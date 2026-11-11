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

@inline function _time_set_index!(entry::TimeEntry, index::Int)
    if entry.kind == TimeEntryKind.DEADLINE
        pd = entry.pollstate::PollState
        _mode_has_read(entry.mode) && (pd.read_timer_index = index)
        _mode_has_write(entry.mode) && (pd.write_timer_index = index)
    end
    return nothing
end

function _time_swap!(heap::Vector{TimeEntry}, i::Int, j::Int)
    heap[i], heap[j] = heap[j], heap[i]
    _time_set_index!(heap[i], i)
    _time_set_index!(heap[j], j)
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

# The poller reads `time_min_ns` without `time_lock` to skip the heap while
# nothing is due, as Go's `timers.check` reads `minWhenHeap`. Every heap
# mutation republishes it; the top may be a stale entry, so it is never later
# than the earliest live one. `0` means empty, so an entry at or before `0`
# (always already due) publishes `1`.
@inline function _publish_time_min_locked!(state::Poller)
    heap = state.time_heap
    @atomic state.time_min_ns = isempty(heap) ? Int64(0) : max(heap[1].deadline_ns, Int64(1))
    return nothing
end

function _time_push_locked!(state::Poller, entry::TimeEntry)
    heap = state.time_heap
    length(heap) >= state.compact_at && _compact_time_heap_locked!(state)
    push!(heap, entry)
    _time_set_index!(entry, length(heap))
    _time_sift_up!(heap, length(heap))
    _publish_time_min_locked!(state)
    return nothing
end

function _time_remove_locked!(state::Poller, index::Int)::TimeEntry
    heap = state.time_heap
    entry = heap[index]
    last = pop!(heap)
    _time_set_index!(entry, 0)
    if index <= length(heap)
        heap[index] = last
        _time_set_index!(last, index)
        if index > 1 && _time_less(last, heap[_heap_parent_index(index)])
            _time_sift_up!(heap, index)
        else
            _time_sift_down!(heap, index)
        end
    end
    _publish_time_min_locked!(state)
    return entry
end

# Closed or re-armed timers stay in the heap until they reach its top, which a
# live earlier entry can postpone until their own deadline. Drop them once the
# heap has doubled since the last compaction: amortized O(1) per push, in place.
function _compact_time_heap_locked!(state::Poller)
    heap = state.time_heap
    n = 0
    for i in eachindex(heap)
        entry = heap[i]
        if _entry_live_locked(state, entry)
            n += 1
            heap[n] = entry
        else
            _time_set_index!(entry, 0)
        end
    end
    resize!(heap, n)
    for i in (n >>> 1):-1:1
        _time_sift_down!(heap, i)
    end
    for i in 1:n
        _time_set_index!(heap[i], i)
    end
    state.compact_at = max(_TIME_HEAP_MIN_COMPACT, 2 * n)
    _publish_time_min_locked!(state)
    return nothing
end

function _time_pop_locked!(state::Poller)::TimeEntry
    isempty(state.time_heap) && throw(ArgumentError("time heap is empty"))
    return _time_remove_locked!(state, 1)
end

# Called with `state.lock` held, after clearing `pd.registration`.
function _remove_deadlines!(state::Poller, pd::PollState)
    lock(state.time_lock)
    try
        pd.read_timer_index == 0 || _time_remove_locked!(state, pd.read_timer_index)
        pd.write_timer_index == 0 || _time_remove_locked!(state, pd.write_timer_index)
    finally
        unlock(state.time_lock)
    end
    return nothing
end

# The poller publishes and clears `pd.registration` under `state.lock` together
# with its registration maps, so this needs neither that lock nor a map lookup.
# A `PollState` only ever points at its own registration, so a descriptor whose
# fd number was reused cannot alias it. Removal clears the field before taking
# `time_lock` to drop the descriptor's entries, so an entry pushed after a
# stale read is still removed.
@inline function _registration_active(pd::PollState)::Bool
    return current_registration(pd) !== nothing
end

@inline function _entry_live_locked(state::Poller, entry::TimeEntry)::Bool
    if entry.kind == TimeEntryKind.DEADLINE
        return _registration_active(entry.pollstate::PollState)
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

# Wake coalescing contract. The backend wake latch (`wake_sig`) lets
# concurrent wakers skip redundant backend wakes, and losing the latch CAS is
# only safe because of two invariants:
#
# 1. A set latch implies the backend wake token is still undelivered (the
#    eventfd / EVFILT_USER event / IOCP packet stays readable until consumed),
#    so the poller cannot block again without first consuming it.
# 2. Wakers publish the state they want the poller to observe *before*
#    attempting the wake, and the poller observes it between consuming a wake
#    and sleeping again: `shutdown!` publishes `running = false` under
#    `state.lock`, which the poller re-acquires every cycle in
#    `_poll_delay_ns`, and heap pushes publish `time_min_ns`, which
#    `_poll_delay_ns` re-reads after committing its horizon (below). So state
#    published before a failed CAS is always observed before the next sleep.
#
# Heap pushes run under `time_lock`, which the poller does not take unless an
# entry is due, so the horizon handshake is lock-free: a waker stores
# `time_min_ns` (in `_time_push_locked!`) and then reads `poll_until_ns`
# below; the poller stores `poll_until_ns` and then re-reads `time_min_ns`.
# All four accesses are sequentially consistent, so a waker whose entry the
# poller's re-read missed necessarily reads the horizon the poller committed,
# and wakes if its deadline is earlier. `0` doubles as "no horizon committed"
# and "sleeping without a timeout"; both must wake unconditionally.
@inline function _maybe_wake_for_earlier_time!(state::Poller, new_earliest::Int64)
    new_earliest > 0 || return nothing
    poll_until_ns = @atomic state.poll_until_ns
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

function _reuse_deadline_entry!(entry::Union{Nothing,TimeEntry}, deadline_ns::Int64,
        pd::PollState, mode::PollMode.T, rseq::UInt64, wseq::UInt64)::TimeEntry
    entry === nothing && return _deadline_entry(deadline_ns, pd, mode, rseq, wseq)
    entry.deadline_ns = deadline_ns
    entry.mode = mode
    entry.primary_seq = rseq
    entry.secondary_seq = wseq
    return entry
end

"""
    schedule_deadlines!(pd, rd_ns, wd_ns, rseq, wseq)

Replace `pd`'s heap entries with its current deadline snapshot.

Arguments are the already-updated read/write deadline words and their sequence
counters. Callers should hold any descriptor-local synchronization needed to
produce a self-consistent snapshot before calling this function; the poller does
not try to reconstruct that relationship after the fact. A delayed snapshot with
superseded sequence numbers is ignored. Entries still in the heap are reused;
already-popped callbacks retain their own captured generations.

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
    lock(state.time_lock)
    try
        # `shutdown!` clears `running` under `time_lock`, so this keeps a setter
        # that loaded a retired poller from waking its closed backend.
        (@atomic :acquire state.running) || return nothing
        _registration_active(pd) || return nothing
        (@atomic :acquire pd.rseq) == rseq && (@atomic :acquire pd.wseq) == wseq || return nothing
        first = pd.read_timer_index == 0 ? nothing : _time_remove_locked!(state, pd.read_timer_index)
        second = pd.write_timer_index == 0 ? nothing : _time_remove_locked!(state, pd.write_timer_index)
        if first === nothing
            first = second
            second = nothing
        end
        if rd_ns > 0 && wd_ns > 0 && rd_ns == wd_ns
            entry = _reuse_deadline_entry!(first, rd_ns, pd, PollMode.READWRITE, rseq, wseq)
            _time_push_locked!(state, entry)
            new_earliest = entry.deadline_ns
        else
            if rd_ns > 0
                entry = _reuse_deadline_entry!(first, rd_ns, pd, PollMode.READ, rseq, UInt64(0))
                _time_push_locked!(state, entry)
                new_earliest = entry.deadline_ns
            end
            if wd_ns > 0
                entry = _reuse_deadline_entry!(rd_ns > 0 ? second : first,
                    wd_ns, pd, PollMode.WRITE, UInt64(0), wseq)
                _time_push_locked!(state, entry)
                if new_earliest == 0 || entry.deadline_ns < new_earliest
                    new_earliest = entry.deadline_ns
                end
            end
        end
        # Once the poller has committed to a sleep horizon, a newly earlier
        # wakeup must actively wake it so the blocking syscall can be retried
        # with a shorter timeout. Waking under `time_lock`, with the
        # registration still live, keeps the wake ahead of `shutdown!`
        # closing the backend.
        _maybe_wake_for_earlier_time!(state, new_earliest)
    finally
        unlock(state.time_lock)
    end
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
    lock(state.time_lock)
    try
        if @atomic :acquire state.running
            _time_push_locked!(state, entry::TimeEntry)
            new_earliest = entry.deadline_ns
            armed = true
            # Under `time_lock` with `running` set, `shutdown!` has not closed
            # the backend yet.
            _maybe_wake_for_earlier_time!(state, new_earliest)
        end
    finally
        unlock(state.time_lock)
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

The heap is read through `time_min_ns`, without `time_lock`, so the poller
never waits behind deadline updates (see the wake coalescing contract above).
A stale top entry, such as a closed timer, is dropped by
`_drain_expired_time_entries!` once it comes due, as Go's `timers.check`
leaves zombie timers until they reach the top.
"""
function _poll_delay_ns(state::Poller; now_ns::Int64=Int64(time_ns()))::Int64
    deadline_ns = Int64(0)
    lock(state.lock)
    try
        deadline_ns = @atomic state.time_min_ns
        while true
            @atomic state.poll_until_ns = deadline_ns
            current_ns = @atomic state.time_min_ns
            current_ns == deadline_ns && break
            deadline_ns = current_ns
        end
    finally
        unlock(state.lock)
    end
    deadline_ns == 0 && return Int64(-1)
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

Entries are popped and fired one at a time. The heap lock is still never held
across fire callbacks (avoiding lock-ordering problems with descriptor-local
locks in `IOPoll`), and the loop allocates nothing: it runs on the poller
thread every cycle, and allocating on that thread has crashed under gVisor's
sandbox.
"""
function _drain_expired_time_entries!(state::Poller, now_ns::Int64)
    while true
        # Nothing is due: leave `time_lock` to deadline updates.
        head_ns = @atomic :acquire state.time_min_ns
        (head_ns == 0 || head_ns > now_ns) && return nothing
        local entry::TimeEntry
        lock(state.time_lock)
        try
            head = _time_peek_locked(state)
            (head === nothing || head.deadline_ns > now_ns) && return nothing
            entry = _time_pop_locked!(state)
        finally
            unlock(state.time_lock)
        end
        _fire_time_entry!(entry)
    end
end

@inline function _saturating_add_ns(base_ns::Int64, delta_ns::Int64)::Int64
    sum_ns, overflowed = Base.Checked.add_with_overflow(base_ns, delta_ns)
    overflowed || return sum_ns
    # Signed overflow requires both operands to share a sign, so the delta's
    # sign picks the saturation bound.
    return delta_ns > 0 ? typemax(Int64) : typemin(Int64)
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
    return sleep_until_ns(_saturating_add_ns(Int64(time_ns()), delay))
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
