"""
    pollwait!(waiter)

Park the current Julia task until the waiter is notified.
Concurrent waits on the same `PollWaiter` are forbidden.

Returns the `PollWakeReason` that woke the waiter.

Throws `ArgumentError` if two tasks try to wait on the same waiter
simultaneously, or if the waiter state machine is observed in an invalid state.
"""
function pollwait!(waiter::PollWaiter)::PollWakeReason.T
    task = current_task()
    task.sticky && (task.sticky = false)
    waiter.task = task
    try
        # Fast path: transition directly from EMPTY -> WAITING and park.
        state, ok = @atomicreplace(waiter.state, PollWaiterState.EMPTY => PollWaiterState.WAITING)
        if ok
            wait()
        else
            state == PollWaiterState.NOTIFIED || throw(ArgumentError("concurrent wait on PollWaiter"))
        end
        while true
            # A notifier can win the race before we actually reach `wait()`, so
            # we loop until the NOTIFIED token is consumed or a clean EMPTY
            # state is observed.
            state, ok = @atomicreplace(waiter.state, PollWaiterState.NOTIFIED => PollWaiterState.EMPTY)
            ok && return @atomic :acquire waiter.reason
            state == PollWaiterState.EMPTY && return @atomic :acquire waiter.reason
            state == PollWaiterState.WAITING || throw(ArgumentError("invalid PollWaiter state"))
            wait()
        end
    finally
        waiter.task = nothing
    end
end

@inline function _merge_wake_reason(
        current::PollWakeReason.T,
        incoming::PollWakeReason.T,
    )::PollWakeReason.T
    return current == PollWakeReason.READY ? current : incoming
end

"""
    pollnotify!(waiter, reason=PollWakeReason.READY)

Mark waiter as notified and wake the waiter task if it has already parked.
Returns `true` if a parked waiter was woken and `false` if the waiter was
already notified or had not yet parked. `PollWakeReason.READY` dominates a
pending `PollWakeReason.CANCELED`, which matches Go's "ready beats cancel"
behavior once readiness has already been latched.

Throws `ArgumentError` if the waiter state machine is observed in an invalid
state.
"""
function pollnotify!(waiter::PollWaiter, reason::PollWakeReason.T = PollWakeReason.READY)::Bool
    state = @atomic :acquire waiter.state
    while true
        if state == PollWaiterState.NOTIFIED
            current = @atomic :acquire waiter.reason
            merged = _merge_wake_reason(current, reason)
            merged == current && return false
            @atomic :release waiter.reason = merged
            return false
        end
        state, ok = @atomicreplace(waiter.state, state => PollWaiterState.NOTIFIED)
        ok || continue
        @atomic :release waiter.reason = reason
        if state == PollWaiterState.WAITING
            task = waiter.task
            task isa Task || throw(ArgumentError("invalid PollWaiter task state"))
            # `schedule(task)` is the low-level dual of the `wait()` above.
            schedule(task)
            return true
        end
        state == PollWaiterState.EMPTY || throw(ArgumentError("invalid PollWaiter state"))
        return false
    end
end
