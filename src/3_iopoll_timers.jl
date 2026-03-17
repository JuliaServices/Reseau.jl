@inline function _time_less(a::TimeEntry, b::TimeEntry)::Bool
    if a.deadline_ns != b.deadline_ns
        return a.deadline_ns < b.deadline_ns
    end
    if a.kind != b.kind
        return UInt8(a.kind) < UInt8(b.kind)
    end
    if a.kind == TimeEntryKind.DEADLINE
        apd = a.pollstate::PollState
        bpd = b.pollstate::PollState
        if apd.token != bpd.token
            return apd.token < bpd.token
        end
        return UInt8(a.mode) < UInt8(b.mode)
    end
    return a.primary_seq < b.primary_seq
end

@inline function _heap_parent_index(i::Int)::Int
    return i >>> 1
end

@inline function _heap_left_index(i::Int)::Int
    return i << 1
end

@inline function _heap_right_index(i::Int)::Int
    return (i << 1) + 1
end

function _time_swap!(heap::Vector{TimeEntry}, i::Int, j::Int)
    heap[i], heap[j] = heap[j], heap[i]
    return nothing
end

function _time_sift_up!(heap::Vector{TimeEntry}, i::Int)
    while i > 1
        parent = _heap_parent_index(i)
        _time_less(heap[i], heap[parent]) || break
        _time_swap!(heap, i, parent)
        i = parent
    end
    return nothing
end

function _time_sift_down!(heap::Vector{TimeEntry}, i::Int)
    len = length(heap)
    while true
        left = _heap_left_index(i)
        left > len && break
        smallest = left
        right = _heap_right_index(i)
        if right <= len && _time_less(heap[right], heap[left])
            smallest = right
        end
        _time_less(heap[smallest], heap[i]) || break
        _time_swap!(heap, i, smallest)
        i = smallest
    end
    return nothing
end

function _time_push_locked!(state::Poller, entry::TimeEntry)
    heap = state.time_heap
    push!(heap, entry)
    _time_sift_up!(heap, length(heap))
    return nothing
end

function _time_pop_locked!(state::Poller)::TimeEntry
    heap = state.time_heap
    isempty(heap) && throw(ArgumentError("time heap is empty"))
    entry = heap[1]
    last = pop!(heap)
    if !isempty(heap)
        heap[1] = last
        _time_sift_down!(heap, 1)
    end
    return entry
end

@inline function _registration_active_locked(state::Poller, pd::PollState)::Bool
    current = get(() -> nothing, state.registrations_by_token, pd.token)
    return current !== nothing && current.fd == pd.sysfd && current.pollstate === pd
end

@inline function _entry_live_locked(state::Poller, entry::TimeEntry)::Bool
    if entry.kind == TimeEntryKind.DEADLINE
        pd = entry.pollstate::PollState
        # Descriptors are reused aggressively by the OS, so liveness must check
        # both the fd and the monotonically increasing token.
        return _registration_active_locked(state, pd)
    end
    timer = entry.timer::TimerState
    (@atomic :acquire timer.seq) == entry.primary_seq || return false
    (@atomic :acquire timer.closed) && return false
    return true
end

function _discard_stale_time_entries_locked!(state::Poller)
    while !isempty(state.time_heap)
        entry = state.time_heap[1]
        _entry_live_locked(state, entry) && return nothing
        _ = _time_pop_locked!(state)
    end
    return nothing
end

function _time_peek_locked(state::Poller)
    _discard_stale_time_entries_locked!(state)
    isempty(state.time_heap) && return nothing
    return state.time_heap[1]
end

@inline function _maybe_wake_for_earlier_time!(state::Poller, new_earliest::Int64)
    new_earliest > 0 || return nothing
    poll_until_ns = @atomic :acquire state.poll_until_ns
    if poll_until_ns == 0 || new_earliest < poll_until_ns
        errno = _backend_wake!(state)
        errno == Int32(0) || _throw_errno("iopoll wake", errno)
    end
    return nothing
end

@inline function _deadline_entry(
        deadline_ns::Int64,
        pd::PollState,
        mode::PollMode.T,
        rseq::UInt64,
        wseq::UInt64,
    )::TimeEntry
    return TimeEntry(deadline_ns, TimeEntryKind.DEADLINE, pd, nothing, mode, rseq, wseq)
end

@inline function _timer_entry(deadline_ns::Int64, timer::TimerState, seq::UInt64)::TimeEntry
    return TimeEntry(deadline_ns, TimeEntryKind.TIMER, nothing, timer, PollMode.READ, seq, UInt64(0))
end

function _build_deadline_entries(
        pd::PollState,
        rd_ns::Int64,
        wd_ns::Int64,
        rseq::UInt64,
        wseq::UInt64,
    )::Vector{TimeEntry}
    entries = TimeEntry[]
    # Match Go's combined read/write deadline fast path when both deadlines are
    # identical. Distinct deadlines stay as separate heap entries because they
    # can expire independently.
    if rd_ns > 0 && wd_ns > 0 && rd_ns == wd_ns
        push!(entries, _deadline_entry(rd_ns, pd, PollMode.READWRITE, rseq, wseq))
        return entries
    end
    rd_ns > 0 && push!(entries, _deadline_entry(rd_ns, pd, PollMode.READ, rseq, UInt64(0)))
    wd_ns > 0 && push!(entries, _deadline_entry(wd_ns, pd, PollMode.WRITE, UInt64(0), wseq))
    return entries
end

"""
    schedule_deadlines!(pd, rd_ns, wd_ns, rseq, wseq)

Publish the current deadline snapshot for `pd` into the poller heap.

Arguments are the already-updated read/write deadline words and their sequence
counters. Callers should hold any descriptor-local synchronization needed to
produce a self-consistent snapshot before calling this function; the poller does
not try to reconstruct that relationship after the fact.

Returns `nothing`.

If the newly scheduled entry becomes earlier than the deadline the poller thread
is currently sleeping toward, the backend wake mechanism is triggered so the
poll syscall can be reissued with the shorter timeout.
"""
function schedule_deadlines!(
        pd::PollState,
        rd_ns::Int64,
        wd_ns::Int64,
        rseq::UInt64,
        wseq::UInt64,
    )
    isassigned(POLLER) || return nothing
    state = POLLER[]
    (@atomic :acquire state.running) || return nothing
    new_earliest = Int64(0)
    lock(state.lock)
    try
        _registration_active_locked(state, pd) || return nothing
        for entry in _build_deadline_entries(pd, rd_ns, wd_ns, rseq, wseq)
            _time_push_locked!(state, entry)
            if new_earliest == 0 || entry.deadline_ns < new_earliest
                new_earliest = entry.deadline_ns
            end
        end
    finally
        unlock(state.lock)
    end
    # This is the local equivalent of Go's `netpollBreak()`: once the poller
    # has committed to a sleep horizon, a newly earlier wakeup must actively
    # wake it so the blocking syscall can be retried with a shorter timeout.
    _maybe_wake_for_earlier_time!(state, new_earliest)
    return nothing
end

"""
    schedule_timer!(timer, deadline_ns)

Publish one timer wakeup into the poller heap.

`deadline_ns` is an absolute monotonic `time_ns()`-style timestamp.
Returns `true` if the timer was armed and `false` if the poller was already
stopped.
"""
function schedule_timer!(timer::TimerState, deadline_ns::Int64)::Bool
    state = init!()
    (@atomic :acquire state.running) || return false
    new_earliest = Int64(0)
    entry = nothing
    armed = false
    lock(timer.lock)
    try
        (@atomic :acquire timer.closed) && return false
        @atomic :release timer.deadline_ns = deadline_ns
        seq = @atomic timer.seq += UInt64(1)
        entry = _timer_entry(deadline_ns, timer, seq)
    finally
        unlock(timer.lock)
    end
    lock(state.lock)
    try
        if @atomic :acquire state.running
            _time_push_locked!(state, entry::TimeEntry)
            new_earliest = entry.deadline_ns
            armed = true
        end
    finally
        unlock(state.lock)
    end
    if !armed
        lock(timer.lock)
        try
            if (@atomic :acquire timer.seq) == (entry::TimeEntry).primary_seq && !(@atomic :acquire timer.closed)
                @atomic :release timer.deadline_ns = Int64(0)
            end
        finally
            unlock(timer.lock)
        end
        return false
    end
    _maybe_wake_for_earlier_time!(state, new_earliest)
    return true
end

"""
    _poll_delay_ns(state)

Compute the timeout for the next backend poll call.

Returns:
- `-1` when no time entries are pending and the backend may block indefinitely
- `0` when at least one time entry is already due and the backend should poll
  without blocking
- a positive nanosecond timeout otherwise
"""
function _poll_delay_ns(state::Poller)::Int64
    deadline_ns = Int64(0)
    lock(state.lock)
    try
        entry = _time_peek_locked(state)
        deadline_ns = entry === nothing ? Int64(0) : entry.deadline_ns
        @atomic :release state.poll_until_ns = deadline_ns
    finally
        unlock(state.lock)
    end
    deadline_ns == 0 && return Int64(-1)
    now_ns = Int64(time_ns())
    remaining_ns = deadline_ns - now_ns
    remaining_ns <= 0 && return Int64(0)
    return remaining_ns
end

function _close_timer!(timer::TimerState)
    lock(timer.lock)
    try
        (@atomic :acquire timer.closed) && return nothing
        @atomic :release timer.closed = true
        @atomic :release timer.deadline_ns = Int64(0)
        _ = @atomic timer.seq += UInt64(1)
    finally
        unlock(timer.lock)
    end
    pollnotify!(timer.waiter, PollWakeReason.CANCELED)
    return nothing
end

"""
    waittimer(timer)

Wait for a timer to fire or be canceled.

Returns `true` when the timer reached its scheduled deadline and `false` when it
was closed before firing.
"""
function waittimer(timer::TimerState)::Bool
    while true
        reason = pollwait!(timer.waiter)
        reason == PollWakeReason.READY && return true
        (@atomic :acquire timer.closed) && return false
        (@atomic :acquire timer.deadline_ns) == 0 && return true
    end
end

function _timer_fire!(timer::TimerState, seq::UInt64)
    lock(timer.lock)
    try
        (@atomic :acquire timer.closed) && return nothing
        (@atomic :acquire timer.seq) == seq || return nothing
        @atomic :release timer.deadline_ns = Int64(0)
    finally
        unlock(timer.lock)
    end
    pollnotify!(timer.waiter, PollWakeReason.READY)
    return nothing
end

function deadline_fire! end

@inline function _fire_time_entry!(entry::TimeEntry)
    if entry.kind == TimeEntryKind.DEADLINE
        deadline_fire!(
            entry.pollstate::PollState,
            entry.mode,
            entry.primary_seq,
            entry.secondary_seq,
        )
    else
        _timer_fire!(entry.timer::TimerState, entry.primary_seq)
    end
    return nothing
end

"""
    _drain_expired_time_entries!(state, now_ns)

Remove all expired time entries from the heap and dispatch them to their
deadline or timer fire path.

The heap lock is not held across fire callbacks. That keeps the critical
section small and avoids lock-ordering problems with descriptor-local locks in
`IOPoll`.
"""
function _drain_expired_time_entries!(state::Poller, now_ns::Int64)
    expired = TimeEntry[]
    lock(state.lock)
    try
        while true
            entry = _time_peek_locked(state)
            (entry === nothing || entry.deadline_ns > now_ns) && break
            push!(expired, _time_pop_locked!(state))
        end
    finally
        unlock(state.lock)
    end
    for entry in expired
        _fire_time_entry!(entry)
    end
    return nothing
end

"""
    sleep_until_ns(deadline_ns)

Block the current Julia task until the monotonic `time_ns()` deadline is
reached, or until the poller is shut down.
"""
function sleep_until_ns(deadline_ns::Integer)
    target_ns = Int64(deadline_ns)
    target_ns <= Int64(time_ns()) && return nothing
    state = init!()
    (@atomic :acquire state.running) || return nothing
    timer = TimerState(target_ns, Int64(0))
    schedule_timer!(timer, target_ns) || return nothing
    waittimer(timer)
    return nothing
end

"""
    sleep_ns(delay_ns)

Block the current Julia task for `delay_ns` nanoseconds using the poller-owned
sleep heap.
"""
function sleep_ns(delay_ns::Integer)
    delay = Int64(delay_ns)
    delay <= 0 && return nothing
    return sleep_until_ns(Int64(time_ns()) + delay)
end

"""
    sleep(seconds)

Block the current Julia task for `seconds` wall-clock seconds using the
poller-owned sleep heap.
"""
function sleep(sec::Real)
    sec >= 0 || throw(ArgumentError("cannot sleep for $sec seconds"))
    return sleep_ns(ceil(Int64, sec * 1.0e9))
end

"""
    timedwait(testcb, timeout_s; pollint=0.1)

Poll `testcb()` until it returns `true` or `timeout_s` seconds elapse.
"""
function timedwait(testcb, timeout_s::Real; pollint::Real = 0.1)
    pollint >= 1.0e-3 || throw(ArgumentError("pollint must be ≥ 1 millisecond"))
    start_ns = Int64(time_ns())
    timeout_ns = ceil(Int64, timeout_s * 1.0e9)
    testcb() && return :ok
    step_ns = ceil(Int64, pollint * 1.0e9)
    while true
        elapsed_ns = Int64(time_ns()) - start_ns
        elapsed_ns > timeout_ns && return :timed_out
        remaining_ns = timeout_ns - elapsed_ns
        sleep_ns(min(step_ns, remaining_ns))
        testcb() && return :ok
    end
end
