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

# Callback types
const OnRetryTokenAcquiredFn = Function  # (retry_token, error_code, user_data) -> nothing
const OnRetryReadyFn = Function  # (retry_token, error_code, user_data) -> nothing

# Retry token - represents a single retry attempt
# Note: user_data is parameterized as U (typically Any) since it can hold any user-provided value
# and is set dynamically after token creation via retry_token_schedule_retry
mutable struct RetryToken{S, U}
    strategy::S
    error_type::RetryErrorType.T
    original_error::Int
    @atomic retry_count::UInt32
    @atomic last_backoff::UInt64
    last_error::Int
    bound_loop::Union{Nothing, EventLoop}
    lock::ReentrantLock
    # For scheduled retry
    scheduled_retry_task::Union{ScheduledTask, Nothing}  # nullable
    on_retry_ready::Union{OnRetryReadyFn, Nothing}  # nullable
    user_data::U
end

# Abstract retry strategy interface
abstract type AbstractRetryStrategy end

# =============================================================================
# No Retry Strategy
# =============================================================================

mutable struct NoRetryStrategy <: AbstractRetryStrategy
    shutdown_options::shutdown_callback_options
    @atomic shutdown::Bool
end

function NoRetryStrategy(;
        shutdown_options::shutdown_callback_options = shutdown_callback_options(),
    )
    return NoRetryStrategy(shutdown_options, false)
end

function retry_strategy_acquire_token!(
        strategy::NoRetryStrategy,
        on_acquired::OnRetryTokenAcquiredFn,
        user_data,
    )::Union{Nothing, ErrorResult}
    _ = on_acquired
    _ = user_data
    if @atomic strategy.shutdown
        raise_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
        return ErrorResult(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end
    raise_error(ERROR_IO_RETRY_PERMISSION_DENIED)
    return ErrorResult(ERROR_IO_RETRY_PERMISSION_DENIED)
end

function retry_token_schedule_retry(token::RetryToken{NoRetryStrategy, U}, on_retry_ready::OnRetryReadyFn, user_data) where {U}
    _ = token
    _ = on_retry_ready
    _ = user_data
    fatal_assert("schedule_retry must not be called for no-retry strategy", "<unknown>", 0)
    return nothing
end

function retry_token_record_success(token::RetryToken{NoRetryStrategy, U})::Nothing where {U}
    _ = token
    fatal_assert("record_success must not be called for no-retry strategy", "<unknown>", 0)
    return nothing
end

function retry_token_release!(token::RetryToken{NoRetryStrategy, U})::Nothing where {U}
    _ = token
    fatal_assert("release_token must not be called for no-retry strategy", "<unknown>", 0)
    return nothing
end

function retry_strategy_shutdown!(strategy::NoRetryStrategy)
    @atomic strategy.shutdown = true
    if strategy.shutdown_options.shutdown_callback_fn !== nothing
        strategy.shutdown_options.shutdown_callback_fn(strategy.shutdown_options.shutdown_callback_user_data)
    end
    return nothing
end

# Schedule retry callback
function retry_token_schedule_retry(token::RetryToken, on_retry_ready::OnRetryReadyFn, user_data)::Union{Nothing, ErrorResult}
    error("retry_token_schedule_retry must be implemented by concrete retry strategy")
end

# Record success - called when the operation succeeds
function retry_token_record_success(token::RetryToken)::Nothing
    error("retry_token_record_success must be implemented by concrete retry strategy")
end

# Release the retry token
function retry_token_release!(token::RetryToken)::Nothing
    # Default: do nothing
    return nothing
end

# =============================================================================
# Exponential Backoff Retry Strategy
# =============================================================================

# Exponential backoff configuration (matches aws-c-io options)
struct ExponentialBackoffConfig
    backoff_scale_factor_ms::UInt64
    max_backoff_secs::UInt64
    max_retries::UInt32
    jitter_mode::Symbol  # :default, :none, :full, :decorrelated
    generate_random::Union{Nothing, Function}
    generate_random_impl::Union{Nothing, Function}
    generate_random_user_data::Any
end

function _default_generate_random(_user_data)
    return rand(UInt64)
end

function ExponentialBackoffConfig(;
        backoff_scale_factor_ms::Integer = 500,
        max_backoff_secs::Integer = 20,
        max_retries::Integer = 5,
        jitter_mode::Symbol = :default,
        generate_random::Union{Nothing, Function} = nothing,
        generate_random_impl::Union{Nothing, Function} = nothing,
        generate_random_user_data = nothing,
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
    if generate_random === nothing && generate_random_impl === nothing
        generate_random_impl = _default_generate_random
    end
    return ExponentialBackoffConfig(
        UInt64(backoff_scale_factor_ms),
        UInt64(max_backoff_secs),
        UInt32(max_retries),
        jitter_mode,
        generate_random,
        generate_random_impl,
        generate_random_user_data,
    )
end

# Exponential backoff retry strategy
mutable struct ExponentialBackoffRetryStrategy{ELG} <: AbstractRetryStrategy
    event_loop_group::ELG
    config::ExponentialBackoffConfig
    @atomic shutdown::Bool
end

function ExponentialBackoffRetryStrategy(
        event_loop_group::ELG,
        config::ExponentialBackoffConfig = ExponentialBackoffConfig(),
    ) where {ELG}
    if config.max_retries > 63
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end
    if !(config.jitter_mode in (:default, :none, :full, :decorrelated, :equal))
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end
    strategy = ExponentialBackoffRetryStrategy{ELG}(
        event_loop_group,
        config,
        false,
    )
    return strategy
end

# Acquire a retry token from the strategy
function retry_strategy_acquire_token!(
        strategy::ExponentialBackoffRetryStrategy,
        on_acquired::OnRetryTokenAcquiredFn,
        user_data,
    )::Union{Nothing, ErrorResult}
    if @atomic strategy.shutdown
        logf(
            LogLevel.ERROR, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
            "Exponential backoff: acquire token called after shutdown"
        )
        raise_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
        return ErrorResult(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end

    event_loop = event_loop_group_get_next_loop(strategy.event_loop_group)
    if event_loop === nothing
        raise_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
        return ErrorResult(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
    end

    # Create token with Any for user_data to allow dynamic assignment
    token = RetryToken{typeof(strategy), Any}(
        strategy,
        RetryErrorType.TRANSIENT,
        0,
        UInt32(0),
        UInt64(0),
        0,
        event_loop,
        ReentrantLock(),
        nothing,
        nothing,
        nothing,
    )

    logf(
        LogLevel.TRACE, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
        "Exponential backoff: token acquired"
    )

    # Schedule callback
    task = ScheduledTask(
        (t, status) -> on_acquired(token, AWS_OP_SUCCESS, user_data),
        nothing;
        type_tag = "retry_token_acquired"
    )
    event_loop_schedule_task_now!(event_loop, task)

    return nothing
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

@inline function _backoff_scale_factor_ns(config::ExponentialBackoffConfig)::UInt64
    return _saturating_mul(config.backoff_scale_factor_ms, UInt64(1_000_000))
end

@inline function _max_backoff_ns(config::ExponentialBackoffConfig)::UInt64
    return _saturating_mul(config.max_backoff_secs, UInt64(1_000_000_000))
end

@inline function _rand_u64(config::ExponentialBackoffConfig)::UInt64
    if config.generate_random_impl !== nothing
        return UInt64(config.generate_random_impl(config.generate_random_user_data))
    end
    if config.generate_random !== nothing
        return UInt64(config.generate_random())
    end
    return rand(UInt64)
end

@inline function _random_in_range(from::UInt64, to::UInt64, config::ExponentialBackoffConfig)::UInt64
    maxv = max(from, to)
    minv = min(from, to)
    diff = maxv - minv
    if diff == 0
        return UInt64(0)
    end
    return minv + (_rand_u64(config) % diff)
end

function _compute_no_jitter(config::ExponentialBackoffConfig, retry_count::UInt32)::UInt64
    shift = min(Int(retry_count), 63)
    scale_ns = _backoff_scale_factor_ns(config)
    backoff = _saturating_mul(UInt64(1) << shift, scale_ns)
    return min(backoff, _max_backoff_ns(config))
end

function _compute_full_jitter(config::ExponentialBackoffConfig, retry_count::UInt32)::UInt64
    non_jittered = _compute_no_jitter(config, retry_count)
    return _random_in_range(UInt64(0), non_jittered, config)
end

function _compute_decorrelated_jitter(
        config::ExponentialBackoffConfig,
        retry_count::UInt32,
        last_backoff::UInt64,
    )::UInt64
    if last_backoff == 0
        return _compute_full_jitter(config, retry_count)
    end
    max_backoff = _max_backoff_ns(config)
    upper = min(max_backoff, _saturating_mul(last_backoff, UInt64(3)))
    scale_ns = _backoff_scale_factor_ns(config)
    return _random_in_range(scale_ns, upper, config)
end

function _compute_backoff_ns(
        config::ExponentialBackoffConfig,
        retry_count::UInt32,
        last_backoff::UInt64,
    )::UInt64
    mode = config.jitter_mode
    if mode == :none
        return _compute_no_jitter(config, retry_count)
    elseif mode == :full || mode == :default
        return _compute_full_jitter(config, retry_count)
    elseif mode == :equal
        non_jittered = _compute_no_jitter(config, retry_count)
        half = non_jittered ÷ UInt64(2)
        return half + _random_in_range(UInt64(0), half, config)
    elseif mode == :decorrelated
        return _compute_decorrelated_jitter(config, retry_count, last_backoff)
    else
        return _compute_no_jitter(config, retry_count)
    end
end

# Schedule retry for exponential backoff token (default error type)
function retry_token_schedule_retry(
        token::RetryToken{ExponentialBackoffRetryStrategy{ELG}, U},
        on_retry_ready::OnRetryReadyFn,
        user_data,
    ) where {ELG, U}
    return retry_token_schedule_retry(token, token.error_type, on_retry_ready, user_data)
end

# Schedule retry for exponential backoff token
function retry_token_schedule_retry(
        token::RetryToken{ExponentialBackoffRetryStrategy{ELG}, U},
        error_type::RetryErrorType.T,
        on_retry_ready::OnRetryReadyFn,
        user_data,
    ) where {ELG, U}
    strategy = token.strategy
    config = strategy.config
    token.error_type = error_type
    schedule_at = UInt64(0)

    if error_type != RetryErrorType.CLIENT_ERROR
        retry_count = @atomic token.retry_count
        if retry_count >= config.max_retries
            logf(
                LogLevel.DEBUG, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
                "Exponential backoff: max retries ($(config.max_retries)) exceeded"
            )
            raise_error(ERROR_IO_MAX_RETRIES_EXCEEDED)
            return ErrorResult(ERROR_IO_MAX_RETRIES_EXCEEDED)
        end

        last_backoff = @atomic token.last_backoff
        backoff_ns = _compute_backoff_ns(config, retry_count, last_backoff)

        event_loop = token.bound_loop
        if event_loop === nothing
            raise_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
            return ErrorResult(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
        end

        current_time = event_loop_current_clock_time(event_loop)
        if current_time isa ErrorResult
            return current_time
        end

        schedule_at = current_time + backoff_ns
        @atomic token.last_backoff = backoff_ns
        @atomic token.retry_count = retry_count + 1
    end

    if @atomic strategy.shutdown
        raise_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
        return ErrorResult(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end

    task = ScheduledTask(
        _exponential_backoff_retry_task,
        token;
        type_tag = "exponential_backoff_retry"
    )
    already_scheduled = false
    lock(token.lock) do
        if token.scheduled_retry_task !== nothing
            already_scheduled = true
        else
            token.on_retry_ready = on_retry_ready
            token.user_data = user_data
            token.scheduled_retry_task = task
        end
    end

    if already_scheduled
        logf(
            LogLevel.ERROR, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
            "Exponential backoff: token already scheduled"
        )
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end

    event_loop = token.bound_loop
    event_loop === nothing && return ErrorResult(raise_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP))
    event_loop_schedule_task_future!(event_loop, task, schedule_at)

    return nothing
end

# Retry task callback
function _exponential_backoff_retry_task(token::RetryToken, status::TaskStatus.T)
    # Task is executing (or canceled). Clear scheduling state before callbacks.
    local on_retry_ready
    local user_data
    lock(token.lock) do
        token.scheduled_retry_task = nothing
        on_retry_ready = token.on_retry_ready
        user_data = token.user_data
        token.on_retry_ready = nothing
        token.user_data = nothing
    end

    logf(
        LogLevel.TRACE, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
        "Exponential backoff: retry task executing, status=$status"
    )

    if status == TaskStatus.CANCELED
        if on_retry_ready !== nothing
            on_retry_ready(token, ERROR_IO_OPERATION_CANCELLED, user_data)
        end
        return nothing
    end

    if on_retry_ready !== nothing
        on_retry_ready(token, AWS_OP_SUCCESS, user_data)
    end

    return nothing
end

# Record success for exponential backoff token
function retry_token_record_success(token::RetryToken{ExponentialBackoffRetryStrategy{ELG}, U})::Nothing where {ELG, U}
    retries = @atomic token.retry_count
    logf(
        LogLevel.TRACE, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
        "Exponential backoff: success recorded after $(retries) retries"
    )
    return nothing
end

# Release exponential backoff token
function retry_token_release!(token::RetryToken{ExponentialBackoffRetryStrategy{ELG}, U})::Nothing where {ELG, U}
    _ = token
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

# Standard retry configuration
struct StandardRetryConfig
    initial_bucket_capacity::UInt64
    max_capacity::UInt64
    retry_cost::UInt64
    no_retry_increment::UInt64
    retry_timeout_cost::UInt64
    retry_throttling_cost::UInt64
    backoff_config::ExponentialBackoffConfig
end

function StandardRetryConfig(;
        initial_bucket_capacity::Integer = 500,
        max_capacity::Integer = 500,
        retry_cost::Integer = 5,
        no_retry_increment::Integer = 1,
        retry_timeout_cost::Integer = 10,
        retry_throttling_cost::Integer = 10,
        backoff_config::ExponentialBackoffConfig = ExponentialBackoffConfig(),
    )
    return StandardRetryConfig(
        UInt64(initial_bucket_capacity),
        UInt64(max_capacity),
        UInt64(retry_cost),
        UInt64(no_retry_increment),
        UInt64(retry_timeout_cost),
        UInt64(retry_throttling_cost),
        backoff_config,
    )
end

# Standard retry strategy with token bucket rate limiting
mutable struct StandardRetryStrategy{ELG} <: AbstractRetryStrategy
    event_loop_group::ELG
    config::StandardRetryConfig
    @atomic bucket_capacity::Int64  # Current tokens in bucket
    lock::ReentrantLock
    @atomic shutdown::Bool
end

function StandardRetryStrategy(
        event_loop_group::ELG,
        config::StandardRetryConfig = StandardRetryConfig(),
    ) where {ELG}
    strategy = StandardRetryStrategy{ELG}(
        event_loop_group,
        config,
        Int64(config.initial_bucket_capacity),
        ReentrantLock(),
        false,
    )
    return strategy
end

# Acquire a retry token from standard strategy
function retry_strategy_acquire_token!(
        strategy::StandardRetryStrategy,
        on_acquired::OnRetryTokenAcquiredFn,
        user_data,
    )::Union{Nothing, ErrorResult}
    if @atomic strategy.shutdown
        logf(
            LogLevel.ERROR, LS_IO_STANDARD_RETRY_STRATEGY,
            "Standard retry: acquire token called after shutdown"
        )
        raise_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
        return ErrorResult(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end

    event_loop = event_loop_group_get_next_loop(strategy.event_loop_group)
    if event_loop === nothing
        raise_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
        return ErrorResult(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
    end

    token = RetryToken{typeof(strategy), Any}(
        strategy,
        RetryErrorType.TRANSIENT,
        0,
        UInt32(0),
        UInt64(0),
        0,
        event_loop,
        ReentrantLock(),
        nothing,
        nothing,
        nothing,
    )

    logf(
        LogLevel.TRACE, LS_IO_STANDARD_RETRY_STRATEGY,
        "Standard retry: token acquired"
    )

    # Schedule callback
    task = ScheduledTask(
        (t, status) -> on_acquired(token, AWS_OP_SUCCESS, user_data),
        nothing;
        type_tag = "standard_retry_token_acquired"
    )
    event_loop_schedule_task_now!(event_loop, task)

    return nothing
end

# Try to acquire retry permission from token bucket
function _try_acquire_retry_capacity(strategy::StandardRetryStrategy, cost::UInt64)::Bool
    return lock(strategy.lock) do
        current = @atomic strategy.bucket_capacity

        if current >= Int64(cost)
            @atomic strategy.bucket_capacity = current - Int64(cost)
            logf(
                LogLevel.TRACE, LS_IO_STANDARD_RETRY_STRATEGY,
                "Standard retry: acquired $cost capacity, remaining=$(current - Int64(cost))"
            )
            return true
        end

        logf(
            LogLevel.DEBUG, LS_IO_STANDARD_RETRY_STRATEGY,
            "Standard retry: insufficient capacity (need $cost, have $current)"
        )
        return false
    end
end

# Return capacity to bucket (on success)
function _return_retry_capacity(strategy::StandardRetryStrategy, amount::UInt64)
    lock(strategy.lock) do
        current = @atomic strategy.bucket_capacity
        new_capacity = min(Int64(strategy.config.max_capacity), current + Int64(amount))
        @atomic strategy.bucket_capacity = new_capacity
        logf(
            LogLevel.TRACE, LS_IO_STANDARD_RETRY_STRATEGY,
            "Standard retry: returned $amount capacity, now=$new_capacity"
        )
    end
    return nothing
end

# Schedule retry for standard token
# Schedule retry for standard token (default error type)
function retry_token_schedule_retry(
        token::RetryToken{StandardRetryStrategy{ELG}, U},
        on_retry_ready::OnRetryReadyFn,
        user_data,
    ) where {ELG, U}
    return retry_token_schedule_retry(token, token.error_type, on_retry_ready, user_data)
end

# Schedule retry for standard token
function retry_token_schedule_retry(
        token::RetryToken{StandardRetryStrategy{ELG}, U},
        error_type::RetryErrorType.T,
        on_retry_ready::OnRetryReadyFn,
        user_data,
    ) where {ELG, U}
    strategy = token.strategy
    config = strategy.config
    token.error_type = error_type

    if error_type == RetryErrorType.CLIENT_ERROR
        logf(
            LogLevel.DEBUG, LS_IO_STANDARD_RETRY_STRATEGY,
            "Standard retry: client error does not permit retry"
        )
        raise_error(ERROR_IO_RETRY_PERMISSION_DENIED)
        return ErrorResult(ERROR_IO_RETRY_PERMISSION_DENIED)
    end

    retry_count = @atomic token.retry_count
    if retry_count >= config.backoff_config.max_retries
        logf(
            LogLevel.DEBUG, LS_IO_STANDARD_RETRY_STRATEGY,
            "Standard retry: max retries exceeded"
        )
        raise_error(ERROR_IO_MAX_RETRIES_EXCEEDED)
        return ErrorResult(ERROR_IO_MAX_RETRIES_EXCEEDED)
    end

    if @atomic strategy.shutdown
        raise_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
        return ErrorResult(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end

    # Determine cost based on error type
    cost = if token.error_type == RetryErrorType.THROTTLING
        config.retry_throttling_cost
    elseif token.last_error == ERROR_IO_SOCKET_TIMEOUT
        config.retry_timeout_cost
    else
        config.retry_cost
    end

    # Try to acquire capacity
    if !_try_acquire_retry_capacity(strategy, cost)
        logf(
            LogLevel.DEBUG, LS_IO_STANDARD_RETRY_STRATEGY,
            "Standard retry: retry permission denied (quota exhausted)"
        )
        raise_error(ERROR_IO_RETRY_PERMISSION_DENIED)
        return ErrorResult(ERROR_IO_RETRY_PERMISSION_DENIED)
    end

    backoff_config = config.backoff_config
    last_backoff = @atomic token.last_backoff
    backoff_ns = _compute_backoff_ns(backoff_config, retry_count, last_backoff)

    logf(
        LogLevel.DEBUG, LS_IO_STANDARD_RETRY_STRATEGY,
        "Standard retry: scheduling retry $(retry_count + 1) in $(backoff_ns ÷ 1_000_000)ms"
    )

    # Schedule the retry
    event_loop = token.bound_loop
    event_loop === nothing && return ErrorResult(raise_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP))

    current_time = event_loop_current_clock_time(event_loop)
    if current_time isa ErrorResult
        return current_time
    end

    run_at = current_time + backoff_ns

    task = ScheduledTask(
        _standard_retry_task,
        token;
        type_tag = "standard_retry"
    )
    already_scheduled = false
    lock(token.lock) do
        if token.scheduled_retry_task !== nothing
            already_scheduled = true
        else
            token.on_retry_ready = on_retry_ready
            token.user_data = user_data
            token.scheduled_retry_task = task
        end
    end

    if already_scheduled
        logf(
            LogLevel.ERROR, LS_IO_STANDARD_RETRY_STRATEGY,
            "Standard retry: token already scheduled"
        )
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end

    @atomic token.last_backoff = backoff_ns
    @atomic token.retry_count = retry_count + 1

    event_loop_schedule_task_future!(event_loop, task, run_at)

    return nothing
end

# Standard retry task callback
function _standard_retry_task(token::RetryToken, status::TaskStatus.T)
    # Task is executing (or canceled). Clear scheduling state before callbacks.
    local on_retry_ready
    local user_data
    lock(token.lock) do
        token.scheduled_retry_task = nothing
        on_retry_ready = token.on_retry_ready
        user_data = token.user_data
        token.on_retry_ready = nothing
        token.user_data = nothing
    end

    logf(
        LogLevel.TRACE, LS_IO_STANDARD_RETRY_STRATEGY,
        "Standard retry: task executing, status=$status"
    )

    if status == TaskStatus.CANCELED
        if on_retry_ready !== nothing
            on_retry_ready(token, ERROR_IO_OPERATION_CANCELLED, user_data)
        end
        return nothing
    end

    if on_retry_ready !== nothing
        on_retry_ready(token, AWS_OP_SUCCESS, user_data)
    end

    return nothing
end

# Record success for standard token
function retry_token_record_success(token::RetryToken{StandardRetryStrategy{ELG}, U})::Nothing where {ELG, U}
    strategy = token.strategy
    _return_retry_capacity(strategy, strategy.config.no_retry_increment)
    logf(
        LogLevel.TRACE, LS_IO_STANDARD_RETRY_STRATEGY,
        "Standard retry: success recorded"
    )
    return nothing
end

# Release standard retry token
function retry_token_release!(token::RetryToken{StandardRetryStrategy{ELG}, U})::Nothing where {ELG, U}
    _ = token
    return nothing
end

# Shutdown strategy
function retry_strategy_shutdown!(strategy::StandardRetryStrategy)
    @atomic strategy.shutdown = true
    logf(
        LogLevel.DEBUG, LS_IO_STANDARD_RETRY_STRATEGY,
        "Standard retry strategy: shutdown"
    )
    return nothing
end
