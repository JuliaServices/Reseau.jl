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
    retry_count::UInt32
    last_error::Int
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

# Exponential backoff configuration
struct ExponentialBackoffConfig
    initial_delay_ms::UInt64
    max_delay_ms::UInt64
    max_retries::UInt32
    exponential_base::Float64
    jitter_mode::Symbol  # :full, :equal, :decorrelated, :none
    scale_factor::Float64
end

function ExponentialBackoffConfig(;
        initial_delay_ms::Integer = 100,
        max_delay_ms::Integer = 20_000,  # 20 seconds
        max_retries::Integer = 10,
        exponential_base::Real = 2.0,
        jitter_mode::Symbol = :full,
        scale_factor::Real = 25.0,
    )
    return ExponentialBackoffConfig(
        UInt64(initial_delay_ms),
        UInt64(max_delay_ms),
        UInt32(max_retries),
        Float64(exponential_base),
        jitter_mode,
        Float64(scale_factor),
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

    # Create token with Any for user_data to allow dynamic assignment
    token = RetryToken{typeof(strategy), Any}(
        strategy,
        RetryErrorType.TRANSIENT,
        0,
        UInt32(0),
        0,
        nothing,
        nothing,
        nothing,
    )

    logf(
        LogLevel.TRACE, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
        "Exponential backoff: token acquired"
    )

    # Schedule callback
    event_loop = event_loop_group_get_next_loop(strategy.event_loop_group)
    if event_loop !== nothing
        task = ScheduledTask(
            (t, status) -> on_acquired(token, AWS_OP_SUCCESS, user_data),
            nothing;
            type_tag = "retry_token_acquired"
        )
        event_loop_schedule_task_now!(event_loop, task)
    else
        on_acquired(token, AWS_OP_SUCCESS, user_data)
    end

    return nothing
end

# Calculate delay for next retry using exponential backoff with jitter
function _calculate_retry_delay(strategy::ExponentialBackoffRetryStrategy, retry_count::UInt32)::UInt64
    config = strategy.config

    # Base delay calculation: initial_delay * base^retry_count
    base_delay = Float64(config.initial_delay_ms) * (config.exponential_base^retry_count)

    # Apply scale factor
    base_delay *= config.scale_factor

    # Cap at max delay
    base_delay = min(base_delay, Float64(config.max_delay_ms))

    # Apply jitter
    delay = if config.jitter_mode == :full || config.jitter_mode == :default
        # Full jitter: random between 0 and calculated delay
        rand() * base_delay
    elseif config.jitter_mode == :equal
        # Equal jitter: half the base + random half
        (base_delay / 2) + (rand() * base_delay / 2)
    elseif config.jitter_mode == :decorrelated
        # Decorrelated jitter: use previous delay to influence next
        min(Float64(config.max_delay_ms), rand() * base_delay * 3)
    else
        # No jitter
        base_delay
    end

    # Convert to milliseconds and ensure minimum of initial delay
    result = max(UInt64(ceil(delay)), config.initial_delay_ms)

    logf(
        LogLevel.TRACE, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
        "Exponential backoff: retry $retry_count delay = $(result)ms"
    )

    return result
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

    delay_ms = UInt64(0)

    if error_type != RetryErrorType.CLIENT_ERROR
        # Check if max retries exceeded
        if token.retry_count >= config.max_retries
            logf(
                LogLevel.DEBUG, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
                "Exponential backoff: max retries ($(config.max_retries)) exceeded"
            )
            raise_error(ERROR_IO_MAX_RETRIES_EXCEEDED)
            return ErrorResult(ERROR_IO_MAX_RETRIES_EXCEEDED)
        end

        delay_ms = _calculate_retry_delay(strategy, token.retry_count)
        token.retry_count += 1
    end

    if @atomic strategy.shutdown
        raise_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
        return ErrorResult(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end
    token.on_retry_ready = on_retry_ready
    token.user_data = user_data

    logf(
        LogLevel.DEBUG, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
        "Exponential backoff: scheduling retry $(token.retry_count) in $(delay_ms)ms"
    )

    # Schedule the retry
    event_loop = event_loop_group_get_next_loop(strategy.event_loop_group)
    if event_loop === nothing
        raise_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
        return ErrorResult(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
    end

    current_time = event_loop_current_clock_time(event_loop)
    if current_time isa ErrorResult
        return current_time
    end

    run_at = delay_ms == 0 ? current_time : current_time + UInt64(delay_ms * 1_000_000)

    task = ScheduledTask(
        _exponential_backoff_retry_task,
        token;
        type_tag = "exponential_backoff_retry"
    )
    token.scheduled_retry_task = task

    if delay_ms == 0
        event_loop_schedule_task_now!(event_loop, task)
    else
        event_loop_schedule_task_future!(event_loop, task, run_at)
    end

    return nothing
end

# Retry task callback
function _exponential_backoff_retry_task(token::RetryToken, status::TaskStatus.T)
    # Task is executing (or canceled). Clear to avoid canceling a running task.
    token.scheduled_retry_task = nothing

    logf(
        LogLevel.TRACE, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
        "Exponential backoff: retry task executing, status=$status"
    )

    if status == TaskStatus.CANCELED
        if token.on_retry_ready !== nothing
            token.on_retry_ready(token, ERROR_IO_OPERATION_CANCELLED, token.user_data)
        end
        return nothing
    end

    if token.on_retry_ready !== nothing
        token.on_retry_ready(token, AWS_OP_SUCCESS, token.user_data)
    end

    return nothing
end

# Record success for exponential backoff token
function retry_token_record_success(token::RetryToken{ExponentialBackoffRetryStrategy{ELG}, U})::Nothing where {ELG, U}
    logf(
        LogLevel.TRACE, LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
        "Exponential backoff: success recorded after $(token.retry_count) retries"
    )
    return nothing
end

# Release exponential backoff token
function retry_token_release!(token::RetryToken{ExponentialBackoffRetryStrategy{ELG}, U})::Nothing where {ELG, U}
    if token.scheduled_retry_task !== nothing
        strategy = token.strategy
        event_loop = event_loop_group_get_next_loop(strategy.event_loop_group)
        if event_loop !== nothing
            event_loop_cancel_task!(event_loop, token.scheduled_retry_task)
        end
        token.scheduled_retry_task = nothing
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

    token = RetryToken{typeof(strategy), Any}(
        strategy,
        RetryErrorType.TRANSIENT,
        0,
        UInt32(0),
        0,
        nothing,
        nothing,
        nothing,
    )

    logf(
        LogLevel.TRACE, LS_IO_STANDARD_RETRY_STRATEGY,
        "Standard retry: token acquired"
    )

    # Schedule callback
    event_loop = event_loop_group_get_next_loop(strategy.event_loop_group)
    if event_loop !== nothing
        task = ScheduledTask(
            (t, status) -> on_acquired(token, AWS_OP_SUCCESS, user_data),
            nothing;
            type_tag = "standard_retry_token_acquired"
        )
        event_loop_schedule_task_now!(event_loop, task)
    else
        on_acquired(token, AWS_OP_SUCCESS, user_data)
    end

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

    # Check if max retries exceeded
    if token.retry_count >= config.backoff_config.max_retries
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

    token.retry_count += 1
    token.on_retry_ready = on_retry_ready
    token.user_data = user_data

    # Calculate backoff delay
    backoff_config = config.backoff_config
    delay_ms = _calculate_standard_retry_delay(backoff_config, token.retry_count)

    logf(
        LogLevel.DEBUG, LS_IO_STANDARD_RETRY_STRATEGY,
        "Standard retry: scheduling retry $(token.retry_count) in $(delay_ms)ms"
    )

    # Schedule the retry
    event_loop = event_loop_group_get_next_loop(strategy.event_loop_group)
    if event_loop === nothing
        raise_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
        return ErrorResult(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
    end

    current_time = event_loop_current_clock_time(event_loop)
    if current_time isa ErrorResult
        return current_time
    end

    run_at = current_time + UInt64(delay_ms * 1_000_000)

    task = ScheduledTask(
        _standard_retry_task,
        token;
        type_tag = "standard_retry"
    )
    token.scheduled_retry_task = task

    event_loop_schedule_task_future!(event_loop, task, run_at)

    return nothing
end

# Calculate delay for standard retry (same as exponential backoff)
function _calculate_standard_retry_delay(config::ExponentialBackoffConfig, retry_count::UInt32)::UInt64
    base_delay = Float64(config.initial_delay_ms) * (config.exponential_base^retry_count)
    base_delay *= config.scale_factor
    base_delay = min(base_delay, Float64(config.max_delay_ms))

    delay = if config.jitter_mode == :full || config.jitter_mode == :default
        rand() * base_delay
    elseif config.jitter_mode == :equal
        (base_delay / 2) + (rand() * base_delay / 2)
    elseif config.jitter_mode == :decorrelated
        min(Float64(config.max_delay_ms), rand() * base_delay * 3)
    else
        base_delay
    end

    return max(UInt64(ceil(delay)), config.initial_delay_ms)
end

# Standard retry task callback
function _standard_retry_task(token::RetryToken, status::TaskStatus.T)
    # Task is executing (or canceled). Clear to avoid canceling a running task.
    token.scheduled_retry_task = nothing

    logf(
        LogLevel.TRACE, LS_IO_STANDARD_RETRY_STRATEGY,
        "Standard retry: task executing, status=$status"
    )

    if status == TaskStatus.CANCELED
        if token.on_retry_ready !== nothing
            token.on_retry_ready(token, ERROR_IO_OPERATION_CANCELLED, token.user_data)
        end
        return nothing
    end

    if token.on_retry_ready !== nothing
        token.on_retry_ready(token, AWS_OP_SUCCESS, token.user_data)
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
    if token.scheduled_retry_task !== nothing
        strategy = token.strategy
        event_loop = event_loop_group_get_next_loop(strategy.event_loop_group)
        if event_loop !== nothing
            event_loop_cancel_task!(event_loop, token.scheduled_retry_task)
        end
        token.scheduled_retry_task = nothing
    end
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
