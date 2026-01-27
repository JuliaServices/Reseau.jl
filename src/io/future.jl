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
mutable struct FutureWaiter{F, U}
    callback::F
    user_data::U
    next::Union{FutureWaiter, Nothing}  # nullable
end

# Generic future for async operations
mutable struct Future{T}
    @atomic state::FutureState.T
    result::Union{T, Nothing}  # nullable
    error_code::Int
    lock::ReentrantLock
    waiters::Union{FutureWaiter, Nothing}  # nullable
end

function Future{T}() where {T}
    return Future{T}(
        FutureState.PENDING,
        nothing,
        0,
        ReentrantLock(),
        nothing,
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
    if future_is_success(future)
        return future.result
    end
    return nothing
end

# Get the error code (only valid if failed)
function future_get_error(future::Future)::Int
    return future.error_code
end

# Wait for future to complete (blocking)
function future_wait(future::Future; timeout_ms::Integer = -1)::Bool
    start_time = high_res_clock()
    timeout_ns = timeout_ms < 0 ? typemax(UInt64) : UInt64(timeout_ms) * 1_000_000

    while !future_is_done(future)
        elapsed = high_res_clock() - start_time
        if elapsed >= timeout_ns
            return false  # Timeout
        end
        yield()  # Let other tasks run
        sleep(0.001)  # Small sleep to avoid busy-waiting
    end

    return true
end

# Register a callback for when the future completes
function future_on_complete!(future::Future, callback::OnFutureCompleteFn, user_data = nothing)
    lock(future.lock) do
        if future_is_done(future)
            # Already complete, call immediately
            Base.invokelatest(callback, future, user_data)
        else
            # Add to waiters list
            waiter = FutureWaiter(callback, user_data, future.waiters)
            future.waiters = waiter
        end
    end
    return nothing
end

# Complete the future with a result
function future_complete!(future::Future{T}, result::T)::Union{Nothing, ErrorResult} where {T}
    return lock(future.lock) do
        state = @atomic future.state
        if state != FutureState.PENDING
            raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
            return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
        end

        future.result = result
        @atomic future.state = FutureState.COMPLETED

        # Notify all waiters
        _notify_waiters(future)
        return nothing
    end
end

# Fail the future with an error code
function future_fail!(future::Future, error_code::Int)::Union{Nothing, ErrorResult}
    return lock(future.lock) do
        state = @atomic future.state
        if state != FutureState.PENDING
            raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
            return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
        end

        future.error_code = error_code
        @atomic future.state = FutureState.FAILED

        # Notify all waiters
        _notify_waiters(future)
        return nothing
    end
end

# Cancel the future
function future_cancel!(future::Future)::Union{Nothing, ErrorResult}
    return lock(future.lock) do
        state = @atomic future.state
        if state != FutureState.PENDING
            # Already done, nothing to cancel
            return nothing
        end

        future.error_code = ERROR_IO_OPERATION_CANCELLED
        @atomic future.state = FutureState.CANCELLED

        # Notify all waiters
        _notify_waiters(future)
        return nothing
    end
end

# Internal - notify all registered waiters
function _notify_waiters(future::Future)
    waiter = future.waiters
    future.waiters = nothing

    while waiter !== nothing
        next = waiter.next
        Base.invokelatest(waiter.callback, future, waiter.user_data)
        waiter = next
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
    start_time = high_res_clock()
    timeout_ns = timeout_ms < 0 ? typemax(UInt64) : UInt64(timeout_ms) * 1_000_000

    while true
        for (i, future) in enumerate(futures)
            if future_is_done(future)
                return i
            end
        end

        elapsed = high_res_clock() - start_time
        if elapsed >= timeout_ns
            return 0  # Timeout, none completed
        end

        yield()
        sleep(0.001)
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
