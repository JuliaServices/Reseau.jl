# AWS IO Library - Retry Strategies
# Port of aws-c-io/source/retry_strategy.c and exponential_backoff_retry_strategy.c

# Retry error types
@enumx RetryErrorType::UInt8 begin
    TRANSIENT = 0       # Retryable transient error
    THROTTLING = 1      # Rate limiting / throttling
    SERVER_ERROR = 2    # Server-side error
    CLIENT_ERROR = 3    # Client-side error (usually not retryable)
end

# Determine if an error code is retryable
function retry_error_type_from_io_error(error_code::Int)::RetryErrorType.T
    if error_code == ERROR_IO_SOCKET_CONNECTION_REFUSED ||
            error_code == ERROR_IO_SOCKET_TIMEOUT ||
            error_code == ERROR_IO_SOCKET_NO_ROUTE_TO_HOST ||
            error_code == ERROR_IO_SOCKET_NETWORK_DOWN ||
            error_code == ERROR_IO_SOCKET_CLOSED ||
            error_code == ERROR_IO_SOCKET_NOT_CONNECTED ||
            error_code == ERROR_IO_SOCKET_CONNECT_ABORTED ||
            error_code == ERROR_IO_DNS_QUERY_FAILED ||
            error_code == ERROR_IO_DNS_NO_ADDRESS_FOR_HOST ||
            error_code == ERROR_IO_DNS_QUERY_AGAIN ||
            error_code == ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE ||
            error_code == ERROR_IO_TLS_NEGOTIATION_TIMEOUT ||
            error_code == ERROR_IO_TLS_CLOSED_ABORT ||
            error_code == ERROR_IO_BROKEN_PIPE ||
            error_code == ERROR_IO_READ_WOULD_BLOCK
        return RetryErrorType.TRANSIENT
    end

    return RetryErrorType.CLIENT_ERROR
end

# Abstract retry strategy interface
abstract type AbstractRetryStrategy end

# Retry token - represents a single retry attempt
mutable struct RetryToken{S<:AbstractRetryStrategy}
    strategy::S
    error_type::RetryErrorType.T
    original_error::Int
    @atomic retry_count::UInt32
    @atomic last_backoff::UInt64
    last_error::Int
    bound_loop::Union{Nothing, EventLoop}
    lock::ReentrantLock
    retry_scheduled::Bool
end

# =============================================================================
# No Retry Strategy
# =============================================================================

mutable struct NoRetryStrategy <: AbstractRetryStrategy
    shutdown_options::Union{TaskFn, Nothing}
    @atomic shutdown::Bool
end

function NoRetryStrategy(;
        shutdown_options::Union{TaskFn, Nothing} = nothing,
    )
    return NoRetryStrategy(shutdown_options, false)
end

function retry_strategy_acquire_token!(
        strategy::NoRetryStrategy,
        partition_id,
        on_acquired::F,
        timeout_ms::Integer = 0,
    )::Nothing where {F}
    _ = partition_id
    _ = timeout_ms
    _ = on_acquired
    if @atomic strategy.shutdown
        throw_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end
    throw_error(ERROR_IO_RETRY_PERMISSION_DENIED)
end

function retry_strategy_acquire_token!(
        strategy::NoRetryStrategy,
        on_acquired::F,
    )::Nothing where {F}
    return retry_strategy_acquire_token!(strategy, nothing, on_acquired, 0)
end

function retry_strategy_shutdown!(strategy::NoRetryStrategy)
    @atomic strategy.shutdown = true
    if strategy.shutdown_options !== nothing
        strategy.shutdown_options(UInt8(0))
    end
    return nothing
end

# =============================================================================
# Exponential Backoff Retry Strategy
# =============================================================================

# Exponential backoff retry strategy
mutable struct ExponentialBackoffRetryStrategy <: AbstractRetryStrategy
    event_loop_group::EventLoopGroup
    backoff_scale_factor_ms::UInt64
    max_backoff_secs::UInt64
    max_retries::UInt32
    jitter_mode::Symbol
    @atomic shutdown::Bool
end

function ExponentialBackoffRetryStrategy(
        event_loop_group::EventLoopGroup,
        ;
        backoff_scale_factor_ms::Integer = 500,
        max_backoff_secs::Integer = 20,
        max_retries::Integer = 5,
        jitter_mode::Symbol = :default,
    )
    if backoff_scale_factor_ms == 0
        backoff_scale_factor_ms = 500
    end
    if max_backoff_secs == 0
        max_backoff_secs = 20
    end
    if max_retries == 0
        max_retries = 5
    end
    if max_retries > 63
        throw_error(ERROR_INVALID_ARGUMENT)
    end
    if !(jitter_mode in (:default, :none, :full, :decorrelated, :equal))
        throw_error(ERROR_INVALID_ARGUMENT)
    end
    strategy = ExponentialBackoffRetryStrategy(
        event_loop_group,
        UInt64(backoff_scale_factor_ms),
        UInt64(max_backoff_secs),
        UInt32(max_retries),
        jitter_mode,
        false,
    )
    return strategy
end

# Acquire a retry token from the strategy
function retry_strategy_acquire_token!(
        strategy::ExponentialBackoffRetryStrategy,
        partition_id,
        on_acquired::F,
        timeout_ms::Integer = 0,
    )::Nothing where {F}
    _ = partition_id
    _ = timeout_ms
    if @atomic strategy.shutdown
        logf(
            LogLevel.ERROR, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
            "Exponential backoff: acquire token called after shutdown"
        )
        throw_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end

    event_loop = get_next_event_loop(strategy.event_loop_group)
    if event_loop === nothing
        throw_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
    end

    token = RetryToken(
        strategy,
        RetryErrorType.TRANSIENT,
        0,
        UInt32(0),
        UInt64(0),
        0,
        event_loop,
        ReentrantLock(),
        false,
    )

    logf(
        LogLevel.TRACE, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
        "Exponential backoff: token acquired"
    )

    # Schedule callback
    schedule_task_now!(event_loop; type_tag = "retry_token_acquired") do _
        try
            on_acquired(token, OP_SUCCESS)
        catch e
            Core.println("retry_token_acquired task errored")
        end
        return nothing
    end

    return nothing
end

function retry_strategy_acquire_token!(
        strategy::ExponentialBackoffRetryStrategy,
        on_acquired::F,
    )::Nothing where {F}
    return retry_strategy_acquire_token!(strategy, nothing, on_acquired, 0)
end

@inline function _saturating_mul(a::UInt64, b::UInt64)::UInt64
    if a == 0 || b == 0
        return UInt64(0)
    end
    if a > typemax(UInt64) ÷ b
        return typemax(UInt64)
    end
    return a * b
end

@inline function _backoff_scale_factor_ns(strategy::ExponentialBackoffRetryStrategy)::UInt64
    return _saturating_mul(strategy.backoff_scale_factor_ms, UInt64(1_000_000))
end

@inline function _max_backoff_ns(strategy::ExponentialBackoffRetryStrategy)::UInt64
    return _saturating_mul(strategy.max_backoff_secs, UInt64(1_000_000_000))
end

@inline function _random_in_range(from::UInt64, to::UInt64)::UInt64
    maxv = max(from, to)
    minv = min(from, to)
    diff = maxv - minv
    if diff == 0
        return UInt64(0)
    end
    return minv + (rand(UInt64) % diff)
end

function _compute_no_jitter(strategy::ExponentialBackoffRetryStrategy, retry_count::UInt32)::UInt64
    shift = min(Int(retry_count), 63)
    scale_ns = _backoff_scale_factor_ns(strategy)
    backoff = _saturating_mul(UInt64(1) << shift, scale_ns)
    return min(backoff, _max_backoff_ns(strategy))
end

function _compute_full_jitter(strategy::ExponentialBackoffRetryStrategy, retry_count::UInt32)::UInt64
    non_jittered = _compute_no_jitter(strategy, retry_count)
    return _random_in_range(UInt64(0), non_jittered)
end

function _compute_decorrelated_jitter(
        strategy::ExponentialBackoffRetryStrategy,
        retry_count::UInt32,
        last_backoff::UInt64,
    )::UInt64
    if last_backoff == 0
        return _compute_full_jitter(strategy, retry_count)
    end
    max_backoff = _max_backoff_ns(strategy)
    upper = min(max_backoff, _saturating_mul(last_backoff, UInt64(3)))
    scale_ns = _backoff_scale_factor_ns(strategy)
    return _random_in_range(scale_ns, upper)
end

function _compute_backoff_ns(
        strategy::ExponentialBackoffRetryStrategy,
        retry_count::UInt32,
        last_backoff::UInt64,
    )::UInt64
    mode = strategy.jitter_mode
    if mode == :none
        return _compute_no_jitter(strategy, retry_count)
    elseif mode == :full || mode == :default
        return _compute_full_jitter(strategy, retry_count)
    elseif mode == :equal
        non_jittered = _compute_no_jitter(strategy, retry_count)
        half = non_jittered ÷ UInt64(2)
        return half + _random_in_range(UInt64(0), half)
    elseif mode == :decorrelated
        return _compute_decorrelated_jitter(strategy, retry_count, last_backoff)
    else
        return _compute_no_jitter(strategy, retry_count)
    end
end

# Schedule retry for exponential backoff token (default error type)
function retry_token_schedule_retry(
        token::RetryToken{ExponentialBackoffRetryStrategy},
        on_retry_ready::F,
    )::Nothing where {F}
    return retry_token_schedule_retry(token, token.error_type, on_retry_ready)
end

# Schedule retry for exponential backoff token
function retry_token_schedule_retry(
        token::RetryToken{ExponentialBackoffRetryStrategy},
        error_type::RetryErrorType.T,
        on_retry_ready::F,
    )::Nothing where {F}
    strategy = token.strategy
    token.error_type = error_type
    schedule_at = UInt64(0)

    if error_type != RetryErrorType.CLIENT_ERROR
        retry_count = @atomic token.retry_count
        if retry_count >= strategy.max_retries
            logf(
                LogLevel.DEBUG, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
                "Exponential backoff: max retries ($(strategy.max_retries)) exceeded"
            )
            throw_error(ERROR_IO_MAX_RETRIES_EXCEEDED)
        end

        last_backoff = @atomic token.last_backoff
        backoff_ns = _compute_backoff_ns(strategy, retry_count, last_backoff)

        event_loop = token.bound_loop
        if event_loop === nothing
            throw_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
        end

        current_time = clock_now_ns()

        schedule_at = current_time + backoff_ns
        @atomic token.last_backoff = backoff_ns
        @atomic token.retry_count = retry_count + 1
    end

    if @atomic strategy.shutdown
        throw_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end

    already_scheduled = lock(token.lock) do
        if token.retry_scheduled
            true
        else
            token.retry_scheduled = true
            false
        end
    end

    if already_scheduled
        logf(
            LogLevel.ERROR, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
            "Exponential backoff: token already scheduled"
        )
        throw_error(ERROR_INVALID_STATE)
    end

    task = ScheduledTask(
        TaskFn(function (status::UInt8)
            try
                _exponential_backoff_retry_task(token, on_retry_ready, _coerce_task_status(status))
            catch
                Core.println("exponential_backoff_retry task errored")
            end
            return nothing
        end),
        "exponential_backoff_retry",
        UInt64(0),
        false,
    )

    event_loop = token.bound_loop
    event_loop === nothing && throw_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
    schedule_task_future!(event_loop, task, schedule_at)

    return nothing
end

# Retry task callback
function _exponential_backoff_retry_task(
        token::RetryToken{ExponentialBackoffRetryStrategy},
        on_retry_ready::F,
        status::TaskStatus.T,
    ) where {F}
    # Task is executing (or canceled). Clear scheduling state before callbacks.
    lock(token.lock) do
        token.retry_scheduled = false
    end

    logf(
        LogLevel.TRACE, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
        "Exponential backoff: retry task executing"
    )

    if status == TaskStatus.CANCELED
        on_retry_ready(token, ERROR_IO_OPERATION_CANCELLED)
        return nothing
    end

    on_retry_ready(token, OP_SUCCESS)

    return nothing
end

# Record success for exponential backoff token
function retry_token_record_success(token::RetryToken{ExponentialBackoffRetryStrategy})::Nothing
    retries = @atomic token.retry_count
    logf(
        LogLevel.TRACE, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
        "Exponential backoff: success recorded after $(retries) retries"
    )
    return nothing
end

# Release exponential backoff token
function retry_token_release!(token::RetryToken{ExponentialBackoffRetryStrategy})::Nothing
    lock(token.lock) do
        token.retry_scheduled = false
    end
    return nothing
end

# Shutdown strategy
function retry_strategy_shutdown!(strategy::ExponentialBackoffRetryStrategy)
    @atomic strategy.shutdown = true
    logf(
        LogLevel.DEBUG, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
        "Exponential backoff retry strategy: shutdown"
    )
    return nothing
end

# =============================================================================
# Standard Retry Strategy (Token Bucket)
# =============================================================================

const _STANDARD_RETRY_COST = UInt64(5)
const _STANDARD_TRANSIENT_COST = UInt64(10)
const _STANDARD_NO_RETRY_COST = UInt64(1)

mutable struct RetryBucket
    partition_id::String
    current_capacity::UInt64
    lock::ReentrantLock
end

function RetryBucket(partition_id::AbstractString, capacity::UInt64)
    return RetryBucket(String(partition_id), capacity, ReentrantLock())
end

# Standard retry strategy with token bucket rate limiting
mutable struct StandardRetryStrategy <: AbstractRetryStrategy
    event_loop_group::EventLoopGroup
    max_capacity::UInt64
    backoff_scale_factor_ms::UInt64
    max_backoff_secs::UInt64
    max_retries::UInt32
    jitter_mode::Symbol
    buckets::Dict{String, RetryBucket}
    lock::ReentrantLock
    backoff_strategy::ExponentialBackoffRetryStrategy
    @atomic shutdown::Bool
end

function StandardRetryStrategy(
        event_loop_group::EventLoopGroup,
        ;
        initial_bucket_capacity::Integer = 500,
        backoff_scale_factor_ms::Integer = 500,
        max_backoff_secs::Integer = 20,
        max_retries::Integer = 5,
        jitter_mode::Symbol = :default,
    )
    if initial_bucket_capacity == 0
        initial_bucket_capacity = 500
    end
    if backoff_scale_factor_ms == 0
        backoff_scale_factor_ms = 500
    end
    if max_backoff_secs == 0
        max_backoff_secs = 20
    end
    if max_retries == 0
        max_retries = 5
    end
    backoff_strategy = ExponentialBackoffRetryStrategy(
        event_loop_group;
        backoff_scale_factor_ms = backoff_scale_factor_ms,
        max_backoff_secs = max_backoff_secs,
        max_retries = max_retries,
        jitter_mode = jitter_mode,
    )
    strategy = StandardRetryStrategy(
        event_loop_group,
        UInt64(initial_bucket_capacity),
        UInt64(backoff_scale_factor_ms),
        UInt64(max_backoff_secs),
        UInt32(max_retries),
        jitter_mode,
        Dict{String, RetryBucket}(),
        ReentrantLock(),
        backoff_strategy,
        false,
    )
    return strategy
end

mutable struct StandardRetryToken
    strategy::StandardRetryStrategy
    bucket::RetryBucket
    exp_token::Union{Nothing, RetryToken{ExponentialBackoffRetryStrategy}}
    last_retry_cost::UInt64
    lock::ReentrantLock
end

function _standard_partition_key(partition_id)::String
    if partition_id === nothing
        return ""
    end
    if partition_id isa AbstractString
        return lowercase(String(partition_id))
    end
    if partition_id isa AbstractVector{UInt8}
        return lowercase(String(partition_id))
    end
    return lowercase(String(partition_id))
end

function _standard_get_bucket!(strategy::StandardRetryStrategy, partition_id)
    key = _standard_partition_key(partition_id)
    return lock(strategy.lock) do
        return Base.get!(strategy.buckets, key) do
            RetryBucket(key, strategy.max_capacity)
        end
    end
end

# Acquire a retry token from standard strategy
function retry_strategy_acquire_token!(
        strategy::StandardRetryStrategy,
        partition_id,
        on_acquired::F,
        timeout_ms::Integer = 0,
    )::Nothing where {F}
    if @atomic strategy.shutdown
        logf(
            LogLevel.ERROR, LS_IO_STANDARD_RETRY_STRATEGY,
            "Standard retry: acquire token called after shutdown"
        )
        throw_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end

    bucket = _standard_get_bucket!(strategy, partition_id)

    token = StandardRetryToken(
        strategy,
        bucket,
        nothing,
        _STANDARD_NO_RETRY_COST,
        ReentrantLock(),
    )

    on_backoff_acquired = function (exp_token, code)
        if code != OP_SUCCESS || exp_token === nothing
            on_acquired(nothing, code)
            return nothing
        end
        lock(token.lock) do
            token.exp_token = exp_token
        end
        on_acquired(token, OP_SUCCESS)
        return nothing
    end

    retry_strategy_acquire_token!(
        strategy.backoff_strategy,
        partition_id,
        on_backoff_acquired,
        timeout_ms,
    )
    return nothing
end

function retry_strategy_acquire_token!(
        strategy::StandardRetryStrategy,
        on_acquired::F,
    )::Nothing where {F}
    return retry_strategy_acquire_token!(strategy, nothing, on_acquired, 0)
end

# Schedule retry for standard token (default error type)
function retry_token_schedule_retry(
        token::StandardRetryToken,
        on_retry_ready::F,
    ) where {F}
    return retry_token_schedule_retry(token, RetryErrorType.TRANSIENT, on_retry_ready)
end

@inline function _standard_consume_capacity!(
        token::StandardRetryToken,
        error_type::RetryErrorType.T,
    )::UInt64
    bucket = token.bucket
    return lock(bucket.lock) do
        current = bucket.current_capacity
        current == 0 && return UInt64(0)

        consumed = if error_type == RetryErrorType.TRANSIENT
            min(current, _STANDARD_TRANSIENT_COST)
        else
            min(current, _STANDARD_RETRY_COST)
        end

        token.last_retry_cost = consumed
        bucket.current_capacity = current - consumed
        return consumed
    end
end

@inline function _standard_restore_capacity!(
        token::StandardRetryToken,
        capacity_consumed::UInt64,
        previous_cost::UInt64,
    )::Nothing
    bucket = token.bucket
    lock(bucket.lock) do
        token.last_retry_cost = previous_cost
        desired_capacity = bucket.current_capacity + capacity_consumed
        bucket.current_capacity = min(token.strategy.max_capacity, desired_capacity)
    end
    return nothing
end

# Schedule retry for standard token
function retry_token_schedule_retry(
        token::StandardRetryToken,
        error_type::RetryErrorType.T,
        on_retry_ready::F,
    )::Nothing where {F}
    if error_type == RetryErrorType.CLIENT_ERROR
        throw_error(ERROR_IO_RETRY_PERMISSION_DENIED)
    end

    previous_cost = token.last_retry_cost
    capacity_consumed = _standard_consume_capacity!(token, error_type)

    if iszero(capacity_consumed)
        throw_error(ERROR_IO_RETRY_PERMISSION_DENIED)
    end

    exp_token = lock(token.lock) do
        token.exp_token
    end
    if exp_token === nothing
        _standard_restore_capacity!(token, capacity_consumed, previous_cost)
        throw_error(ERROR_INVALID_STATE)
    end

    try
        retry_token_schedule_retry(
            exp_token,
            error_type,
            (_exp_token, code) -> on_retry_ready(token, code),
        )
    catch
        _standard_restore_capacity!(token, capacity_consumed, previous_cost)
        rethrow()
    end

    return nothing
end

# Record success for standard token
function retry_token_record_success(token::StandardRetryToken)::Nothing
    bucket = token.bucket
    lock(bucket.lock) do
        desired_capacity = bucket.current_capacity + token.last_retry_cost
        bucket.current_capacity = min(token.strategy.max_capacity, desired_capacity)
        token.last_retry_cost = 0
    end
    return nothing
end

# Release standard retry token
function retry_token_release!(token::StandardRetryToken)::Nothing
    lock(token.lock) do
        token.exp_token = nothing
    end
    return nothing
end

# Shutdown strategy
function retry_strategy_shutdown!(strategy::StandardRetryStrategy)
    @atomic strategy.shutdown = true
    retry_strategy_shutdown!(strategy.backoff_strategy)
    logf(
        LogLevel.DEBUG, LS_IO_STANDARD_RETRY_STRATEGY,
        "Standard retry strategy: shutdown"
    )
    return nothing
end
