# AWS IO Library - Future/Promise Abstraction
# Port of aws-c-io/include/aws/io/future.h

# Future state
@enumx FutureState::UInt8 begin
    PENDING = 0
    COMPLETED = 1
    FAILED = 2
    CANCELLED = 3
end

# Callback type for future completion
const OnFutureCompleteFn = Function  # (future, user_data) -> nothing

# Future waiter - for tracking pending callbacks
mutable struct FutureWaiter
    callback::OnFutureCompleteFn
    user_data::Any
    next::Union{FutureWaiter, Nothing}  # nullable
end

# Generic future for async operations
mutable struct Future{T}
    @atomic state::FutureState.T
    result::Union{T, Nothing}  # nullable
    error_code::Int
    lock::ReentrantLock
    done_event::Base.Threads.Event
    callback::Union{FutureWaiter, Nothing}  # nullable
    owns_result::Bool
end

function Future{T}() where {T}
    return Future{T}(
        FutureState.PENDING,
        nothing,
        0,
        ReentrantLock(),
        Base.Threads.Event(),
        nothing,
        false,
    )
end

# Check if future is complete (success or failure)
function future_is_done(future::Future)::Bool
    state = @atomic future.state
    return state != FutureState.PENDING
end

# Check if future completed successfully
function future_is_success(future::Future)::Bool
    return (@atomic future.state) == FutureState.COMPLETED
end

# Check if future failed
function future_is_failed(future::Future)::Bool
    return (@atomic future.state) == FutureState.FAILED
end

# Check if future was cancelled
function future_is_cancelled(future::Future)::Bool
    return (@atomic future.state) == FutureState.CANCELLED
end

# Get the result (only valid if completed successfully)
function future_get_result(future::Future{T})::Union{T, Nothing} where {T}
    fatal_assert_bool(future_is_done(future), "Cannot get result before future is done", "<unknown>", 0)
    fatal_assert_bool(future_is_success(future), "Cannot get result from future that failed with an error", "<unknown>", 0)
    fatal_assert_bool(future.owns_result, "Result was already moved from future", "<unknown>", 0)
    return future.result
end

# Get the error code (only valid if failed)
function future_get_error(future::Future)::Int
    fatal_assert_bool(future_is_done(future), "Cannot get error before future is done", "<unknown>", 0)
    return future.error_code
end

# Wait for future to complete (blocking)
function future_wait(future::Future; timeout_ms::Integer = -1)::Bool
    future_is_done(future) && return true
    if timeout_ms < 0
        wait(future.done_event)
        return true
    end
    timeout_ns = UInt64(max(timeout_ms, 0)) * UInt64(1_000_000)
    return timedwait_poll_ns(() -> future_is_done(future), timeout_ns) == :ok
end

# Register a callback for when the future completes
function future_on_complete!(future::Future, callback::OnFutureCompleteFn, user_data = nothing)
    invoke_now = false
    lock(future.lock) do
        fatal_assert_bool(future.callback === nothing, "Future done callback must only be set once", "<unknown>", 0)
        if future_is_done(future)
            invoke_now = true
        else
            future.callback = FutureWaiter(callback, user_data, nothing)
        end
    end
    if invoke_now
        Base.invokelatest(callback, future, user_data)
    end
    return nothing
end

# Register a callback only if the future isn't done.
# Returns true if callback was registered, false if already done.
function future_on_complete_if_not_done!(future::Future, callback::OnFutureCompleteFn, user_data = nothing)::Bool
    return lock(future.lock) do
        fatal_assert_bool(future.callback === nothing, "Future done callback must only be set once", "<unknown>", 0)
        if future_is_done(future)
            return false
        end
        future.callback = FutureWaiter(callback, user_data, nothing)
        return true
    end
end

# Integration hooks implemented by the IO stack (see `src/sockets/io/future_integration.jl`).
function future_on_event_loop! end
function future_on_channel! end

# Wait for future to complete (timeout in nanoseconds)
function future_wait_ns(future::Future; timeout_ns::Integer)::Bool
    future_is_done(future) && return true
    if timeout_ns < 0
        wait(future.done_event)
        return true
    end
    return timedwait_poll_ns(() -> future_is_done(future), timeout_ns) == :ok
end

# Complete the future with a result
function future_complete!(future::Future{T}, result::T)::Union{Nothing, ErrorResult} where {T}
    callback = nothing
    ret = lock(future.lock) do
        state = @atomic future.state
        if state != FutureState.PENDING
            raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
            return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
        end

        future.result = result
        future.owns_result = true
        @atomic future.state = FutureState.COMPLETED

        callback = future.callback
        future.callback = nothing
        return nothing
    end
    if ret isa ErrorResult
        return ret
    end
    notify(future.done_event)
    _notify_callback(callback, future)
    return nothing
end

# Fail the future with an error code
function future_fail!(future::Future, error_code::Int)::Union{Nothing, ErrorResult}
    callback = nothing
    ret = lock(future.lock) do
        state = @atomic future.state
        if state != FutureState.PENDING
            raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
            return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
        end

        future.result = nothing
        future.owns_result = false
        future.error_code = error_code
        @atomic future.state = FutureState.FAILED

        callback = future.callback
        future.callback = nothing
        return nothing
    end
    if ret isa ErrorResult
        return ret
    end
    notify(future.done_event)
    _notify_callback(callback, future)
    return nothing
end

# Cancel the future
function future_cancel!(future::Future)::Union{Nothing, ErrorResult}
    callback = nothing
    ret = lock(future.lock) do
        state = @atomic future.state
        if state != FutureState.PENDING
            # Already done, nothing to cancel
            return nothing
        end

        future.result = nothing
        future.owns_result = false
        future.error_code = ERROR_IO_OPERATION_CANCELLED
        @atomic future.state = FutureState.CANCELLED

        callback = future.callback
        future.callback = nothing
        return nothing
    end
    if ret isa ErrorResult
        return ret
    end
    notify(future.done_event)
    _notify_callback(callback, future)
    return nothing
end

# Get result by move (result can be taken only once)
function future_get_result_by_move!(future::Future{T})::Union{T, Nothing} where {T}
    fatal_assert_bool(future_is_done(future), "Cannot get result before future is done", "<unknown>", 0)
    fatal_assert_bool(future_is_success(future), "Cannot get result from future that failed with an error", "<unknown>", 0)
    fatal_assert_bool(future.owns_result, "Result was already moved from future", "<unknown>", 0)

    result = future.result
    future.result = nothing
    future.owns_result = false
    return result
end

# Internal - invoke registered callback
function _notify_callback(callback::Union{FutureWaiter, Nothing}, future::Future)
    if callback !== nothing
        Base.invokelatest(callback.callback, future, callback.user_data)
    end
    return nothing
end

# =============================================================================
# Void Future - future with no result value
# =============================================================================

const VoidFuture = Future{Nothing}

# Complete void future
function void_future_complete!(future::VoidFuture)::Union{Nothing, ErrorResult}
    return future_complete!(future, nothing)
end

# =============================================================================
# Promise - the "producer" side of a future
# =============================================================================

mutable struct Promise{T}
    future::Future{T}
end

function Promise{T}() where {T}
    return Promise{T}(Future{T}())
end

# Get the future from a promise
promise_get_future(promise::Promise) = promise.future

# Complete the promise
function promise_complete!(promise::Promise{T}, result::T) where {T}
    return future_complete!(promise.future, result)
end

# Fail the promise
function promise_fail!(promise::Promise, error_code::Int)
    return future_fail!(promise.future, error_code)
end

# Cancel the promise
function promise_cancel!(promise::Promise)
    return future_cancel!(promise.future)
end

# =============================================================================
# Future combinators
# =============================================================================

# Wait for all futures to complete
function future_all(futures::Vector{<:Future})::Bool
    for future in futures
        if !future_wait(future)
            return false
        end
    end
    return true
end

# Wait for any future to complete, returns index of first completed
function future_any(futures::Vector{<:Future}; timeout_ms::Integer = -1)::Int
    start = monotonic_time_ns()
    timeout_ns = timeout_ms < 0 ? typemax(UInt64) : UInt64(max(timeout_ms, 0)) * 1_000_000
    deadline = add_u64_saturating(start, timeout_ns)

    while true
        for (i, future) in enumerate(futures)
            if future_is_done(future)
                return i
            end
        end

        now = monotonic_time_ns()
        if now >= deadline
            return 0  # Timeout, none completed
        end
        thread_sleep_ns(1_000_000)
    end
    return
end

# Chain futures: when first completes, call continuation
function future_then(
        future::Future{T},
        continuation::Function,  # (result) -> new_future or result
    ) where {T}
    result_future = Future{Any}()

    future_on_complete!(
        future, (f, _) -> begin
            if future_is_success(f)
                try
                    new_result = Base.invokelatest(continuation, future_get_result(f))
                    future_complete!(result_future, new_result)
                catch e
                    future_fail!(result_future, ERROR_UNKNOWN)
                end
            else
                future_fail!(result_future, future_get_error(f))
            end
        end
    )

    return result_future
end
