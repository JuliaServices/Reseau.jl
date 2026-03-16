"""
    EventLoops

Cross-platform event loop abstraction for socket readiness polling.

This module is Reseau's analogue of Go's runtime netpoll layer:
- backends translate OS readiness events into a small uniform `PollEvent`
- one dedicated native poller thread blocks in the platform poll syscall
- Julia tasks never call `epoll_wait`/`kevent`/`GetQueuedCompletionStatusEx`
  directly; they instead park on `PollWaiter`s owned by registrations
- deadlines are treated as part of poller state rather than as independent
  Julia sleeper tasks, which mirrors how Go folds timer wakeups into the
  scheduler-driven `netpoll(delay)` loop

The backends differ substantially, but the exported surface aims to keep the
rest of the runtime working in terms of registrations, waiters, and readiness
notifications instead of backend-specific handles.
"""
module EventLoops

using EnumX
using ..Reseau: @gcsafe_ccall

@enumx PollMode::UInt8 begin
    READ = 0x01
    WRITE = 0x02
    READWRITE = 0x03
end

@enumx TimeEntryKind::UInt8 begin
    DEADLINE = 0x01
    TIMER = 0x02
end

@enumx PollWaiterState::UInt8 begin
    EMPTY = 0x00
    WAITING = 0x01
    NOTIFIED = 0x02
end

@enumx PollWakeReason::UInt8 begin
    READY = 0x01
    CANCELED = 0x02
end

"""
    PollWaiter

Go-style binary wake semaphore for one read waiter and one write waiter per fd.
It uses the low-level `wait()` + `schedule(task)` ownership protocol documented in
Julia's scheduler docs.

The important invariant is that a single `PollWaiter` has at most one active
waiting task. That matches Go's `pollDesc` model, where the runtime keeps one
read waiter slot and one write waiter slot per descriptor.
"""
mutable struct PollWaiter
    @atomic state::PollWaiterState.T
    @atomic reason::PollWakeReason.T
    task::Union{Nothing, Task}
    function PollWaiter()
        return new(PollWaiterState.EMPTY, PollWakeReason.READY, nothing)
    end
end

"""
    TimerState

Poller-managed timer state shared by raw one-shot sleeps and future
resettable/repeating timers.

Unlike fd deadlines, timers do not belong to descriptor registrations. The
state is a latched `PollWaiter` plus timer metadata:
- `deadline_ns`: currently armed monotonic deadline, or `0` when disarmed
- `interval_ns`: repeat interval in nanoseconds, or `0` for one-shot timers
- `seq`: generation counter used to reject stale heap entries after rearm/close
- `closed`: suppresses future fire/rearm after shutdown or explicit close
"""
mutable struct TimerState
    lock::ReentrantLock
    waiter::PollWaiter
    @atomic deadline_ns::Int64
    @atomic interval_ns::Int64
    @atomic seq::UInt64
    @atomic closed::Bool
    function TimerState(deadline_ns::Int64 = Int64(0), interval_ns::Int64 = Int64(0))
        return new(ReentrantLock(), PollWaiter(), deadline_ns, interval_ns, UInt64(0), false)
    end
end

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

"""
    PollEvent

Readiness event decoded from the platform backend.

Fields:
- `fd`: OS descriptor/socket identifier
- `token`: monotonically increasing registration token used to reject stale
  events after descriptor reuse
- `mode`: which readiness direction fired
- `errored`: whether the backend reported an error/hangup condition
"""
struct PollEvent
    fd::Cint
    token::UInt64
    mode::PollMode.T
    errored::Bool
end

"""
    PollState(sysfd=-1, token=0)

Descriptor-local state shared between `EventLoops` and `IOPoll`.

This is intentionally close in spirit to Go's runtime `pollDesc`: it holds
registration identity (`sysfd`, `token`), coarse descriptor state
(`pollable`, `closing`, `event_err`), and the read/write deadline words plus
their sequence numbers. The sequence counters are what let the poller heap
discard stale deadline entries without mutating the heap in place whenever a
deadline changes.
"""
mutable struct PollState
    lock::ReentrantLock
    sysfd::Cint
    token::UInt64
    @atomic pollable::Bool
    @atomic closing::Bool
    @atomic event_err::Bool
    @atomic rd_ns::Int64
    @atomic wd_ns::Int64
    @atomic rseq::UInt64
    @atomic wseq::UInt64
    function PollState(sysfd::Integer = Cint(-1), token::UInt64 = UInt64(0))
        return new(
            ReentrantLock(),
            Cint(sysfd),
            token,
            false,
            false,
            false,
            Int64(0),
            Int64(0),
            UInt64(0),
            UInt64(0),
        )
    end
end

"""
    Registration

Per-fd registration state stored by the poller.

Each active OS descriptor has one `Registration`, which is the home for:
- the current token and interest mask known to the backend
- one read waiter and one write waiter for parked Julia tasks
- any backend-discovered persistent event error
- the `PollState` consumed by higher layers
"""
mutable struct Registration
    fd::Cint
    token::UInt64
    mode::PollMode.T
    read_waiter::PollWaiter
    write_waiter::PollWaiter
    @atomic event_err::Bool
    pollstate::PollState
end

function Registration(
        fd::Cint,
        token::UInt64,
        mode::PollMode.T,
        read_waiter::PollWaiter,
        write_waiter::PollWaiter,
        event_err::Bool,
    )
    return Registration(fd, token, mode, read_waiter, write_waiter, event_err, PollState(fd, token))
end

"""
    TimeEntry

One scheduled time event in the poller min-heap.

`TimeEntryKind.DEADLINE` entries are immutable snapshots of descriptor timeout
state. `mode`, `primary_seq`, and `secondary_seq` capture the read/write
deadline generation at the moment the entry was scheduled, and `pollstate`
points at the descriptor-local state that will eventually consume the timeout.

`TimeEntryKind.TIMER` entries are object-owned timer wakeups. `primary_seq`
stores the timer generation captured when the entry was armed, and `timer`
points at the `TimerState` that will eventually be notified.
"""
struct TimeEntry
    deadline_ns::Int64
    kind::TimeEntryKind.T
    pollstate::Union{Nothing, PollState}
    timer::Union{Nothing, TimerState}
    mode::PollMode.T
    primary_seq::UInt64
    secondary_seq::UInt64
end

"""
    Poller

Global event loop subsystem state. `lock` is a regular mutex because registration
updates can run adjacent to syscalls where spin waiting would be wasteful.

Notable fields:
- `registrations`/`registrations_by_token` let us validate that an event or
  time entry still belongs to the current occupant of an fd slot
- `time_heap` is the min-heap that drives finite backend poll timeouts
- `poll_until_ns` records the deadline currently being slept toward so that a
  newly earlier deadline can call `_backend_wake!`, just like Go uses
  `netpollBreak()` to shorten a blocking poll
"""
mutable struct Poller
    lock::ReentrantLock
    registrations::Dict{Cint, Registration}
    registrations_by_token::Dict{UInt64, Registration}
    time_heap::Vector{TimeEntry}
    shutdown_event::Base.Threads.Event
    kq::Cint
    wake_ident::UInt
    backend_scratch::Any
    @atomic wak_sig::UInt32
    @atomic next_token::UInt64
    @atomic poll_until_ns::Int64
    @atomic running::Bool
end

function Poller()
    return Poller(
        ReentrantLock(),
        Dict{Cint, Registration}(),
        Dict{UInt64, Registration}(),
        TimeEntry[],
        Base.Threads.Event(),
        Cint(-1),
        UInt(1),
        nothing,
        UInt32(0),
        UInt64(0),
        Int64(0),
        false,
    )
end

"""
Global singleton state for the runtime event loop poller.
"""
const POLLER = Ref{Poller}()
const _POLLER_THREAD_ENTRY_C = Ref{Ptr{Cvoid}}(C_NULL)
const _pthread_t = UInt

@inline function _is_generating_output()::Bool
    return ccall(:jl_generating_output, Cint, ()) == 1
end

function _throw_errno(op::AbstractString, errno::Int32)
    throw(SystemError(op, Int(errno)))
end

@inline function _next_token!(state::Poller)::UInt64
    return @atomic state.next_token += UInt64(1)
end

@inline function _mode_has_read(mode::PollMode.T)::Bool
    return (UInt8(mode) & UInt8(PollMode.READ)) != 0
end

@inline function _mode_has_write(mode::PollMode.T)::Bool
    return (UInt8(mode) & UInt8(PollMode.WRITE)) != 0
end

@inline function _mode_is_empty(mode::PollMode.T)::Bool
    return UInt8(mode) == 0x00
end

@inline function _runtime_supported()::Bool
    return Sys.isapple() || Sys.islinux() || Sys.iswindows()
end

function _new_registration(fd::Cint, token::UInt64, mode::PollMode.T)::Registration
    return Registration(fd, token, mode, PollWaiter(), PollWaiter(), false)
end

function deadline_fire! end

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
        errno == Int32(0) || _throw_errno("event loop wake", errno)
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
    current_registration(pd)

Return the active `Registration` corresponding to `pd`, or `nothing` if `pd`
has been deregistered or replaced.

This extra indirection is what lets higher layers validate descriptor identity
without trusting a cached registration reference through close/re-register
races.
"""
function current_registration(pd::PollState)
    isassigned(POLLER) || return nothing
    state = POLLER[]
    lock(state.lock)
    try
        registration = get(() -> nothing, state.registrations_by_token, pd.token)
        if registration === nothing
            return nothing
        end
        registration.fd == pd.sysfd || return nothing
        registration.pollstate === pd || return nothing
        return registration
    finally
        unlock(state.lock)
    end
end

function _notify_registration!(
        registration::Registration,
        mode::PollMode.T,
        reason::PollWakeReason.T = PollWakeReason.READY,
    )
    if _mode_has_read(mode) && _mode_has_read(registration.mode)
        pollnotify!(registration.read_waiter, reason)
    end
    if _mode_has_write(mode) && _mode_has_write(registration.mode)
        pollnotify!(registration.write_waiter, reason)
    end
    return nothing
end

"""
    _spawn_detached_thread(name, thread_fn, arg=nothing)

Start a detached native OS thread that runs `thread_fn(::Ptr{Cvoid})`.
This intentionally does not keep a join handle; shutdown is coordinated via
poller state (`running`) and backend wakeups.
"""
function _spawn_detached_thread(
        name::AbstractString,
        thread_fn::Ref{Ptr{Cvoid}},
        arg = nothing,
    )
    _ = name
    thread_arg = arg === nothing ? C_NULL : pointer_from_objref(arg)
    @static if Sys.iswindows()
        handle = ccall(
            (:CreateThread, "kernel32"), Ptr{Cvoid},
            (Ptr{Cvoid}, Csize_t, Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{UInt32}),
            C_NULL, Csize_t(0), thread_fn[], thread_arg, UInt32(0), C_NULL,
        )
        handle == C_NULL && throw(ArgumentError("error creating event loop thread"))
        _ = ccall((:CloseHandle, "kernel32"), Int32, (Ptr{Cvoid},), handle)
    else
        pthread_ref = Ref{_pthread_t}(0)
        create_ret = ccall(
            :pthread_create, Cint,
            (Ref{_pthread_t}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            pthread_ref, C_NULL, thread_fn[], thread_arg,
        )
        create_ret != 0 && throw(SystemError("pthread_create", Int(create_ret)))
        detach_ret = ccall(:pthread_detach, Cint, (_pthread_t,), pthread_ref[])
        detach_ret != 0 && throw(SystemError("pthread_detach", Int(detach_ret)))
    end
    return nothing
end

"""
    init!()

Initialize the runtime poller state and start the dedicated poller thread.

Returns the live `Poller` singleton.

Throws `ArgumentError` if the current platform is unsupported and `SystemError`
if backend initialization or thread creation fails.
"""
function init!()::Poller
    if isassigned(POLLER)
        state = POLLER[]
        (@atomic state.running) && return state
    end
    _runtime_supported() || throw(ArgumentError("eventloops backend is currently supported on macOS, Linux, and Windows"))
    new_state = Poller()
    errno = _backend_init!(new_state)
    errno == Int32(0) || _throw_errno("eventloops backend init", errno)
    @atomic new_state.running = true
    POLLER[] = new_state
    try
        _spawn_detached_thread(
            "reseau-eventloops-poller",
            _POLLER_THREAD_ENTRY_C,
            new_state,
        )
    catch
        @atomic :release new_state.running = false
        _backend_close!(new_state)
        POLLER[] = Poller()
        rethrow()
    end
    return new_state
end

"""
    shutdown!()

Stop the dedicated poller thread and tear down backend resources.

Returns `nothing`.

Waiting registrations are notified so blocked Julia tasks can observe close or
shutdown on their next state check instead of remaining parked forever.
"""
function shutdown!()
    isassigned(POLLER) || return nothing
    state = POLLER[]
    registrations = Registration[]
    stop_requested = false
    lock(state.lock)
    try
        append!(registrations, values(state.registrations))
        empty!(state.registrations)
        empty!(state.registrations_by_token)
        if @atomic :acquire state.running
            @atomic :release state.running = false
            stop_requested = true
        end
    finally
        unlock(state.lock)
    end
    for registration in registrations
        _notify_registration!(registration, PollMode.READWRITE, PollWakeReason.CANCELED)
    end
    if stop_requested
        wake_errno = _backend_wake!(state)
        wake_errno == Int32(0) || _throw_errno("event loop wake", wake_errno)
        wait(state.shutdown_event)
    end
    _backend_close!(state)
    return nothing
end

"""
    register!(fd; mode=PollMode.READWRITE, pollstate=nothing)

Register an fd with the runtime poller and return its `Registration`.

Keyword arguments:
- `mode`: readiness directions to subscribe to
- `pollstate`: optional pre-existing `PollState` to attach to the registration;
  `IOPoll` uses this so the poller and the descriptor wrapper share one state
  object

Returns the created `Registration`.

Throws `ArgumentError` if `mode` is empty, or `SystemError` if the descriptor is
already registered or the backend registration syscall fails.
"""
function register!(fd::Integer; mode::PollMode.T = PollMode.READWRITE, pollstate::Union{Nothing, PollState} = nothing)::Registration
    _mode_is_empty(mode) && throw(ArgumentError("register! requires READ and/or WRITE mode"))
    state = init!()
    cfd = Cint(fd)
    token = UInt64(0)
    registration = nothing
    errno = Int32(0)
    lock(state.lock)
    try
        (@atomic :acquire state.running) || throw(SystemError("event loop register", Int(Base.Libc.EBADF)))
        existing = get(state.registrations, cfd, nothing)
        existing === nothing || throw(SystemError("event loop register", Int(Base.Libc.EEXIST)))
        token = _next_token!(state)
        errno = _backend_open_fd!(state, cfd, mode, token)
        if errno == Int32(0)
            registration = _new_registration(cfd, token, mode)
            if pollstate !== nothing
                registration.pollstate = pollstate::PollState
            end
            registration.pollstate.sysfd = cfd
            registration.pollstate.token = token
            state.registrations[cfd] = registration
            state.registrations_by_token[token] = registration
        end
    finally
        unlock(state.lock)
    end
    errno == Int32(0) || _throw_errno("event loop register", errno)
    return registration::Registration
end

"""
    deregister!(fd)

Unregister an fd from the runtime poller.

Returns `nothing`.

Any parked waiters are notified so they can re-check descriptor state and see
the close/eviction condition promptly.
"""
function deregister!(fd::Integer)
    isassigned(POLLER) || return nothing
    state = POLLER[]
    (@atomic :acquire state.running) || return nothing
    cfd = Cint(fd)
    registration = nothing
    errno = Int32(0)
    lock(state.lock)
    try
        (@atomic :acquire state.running) || return nothing
        registration = pop!(state.registrations, cfd, nothing)
        registration === nothing || delete!(state.registrations_by_token, registration.token)
        errno = _backend_close_fd!(state, cfd)
    finally
        unlock(state.lock)
    end
    registration === nothing || _notify_registration!(registration::Registration, PollMode.READWRITE, PollWakeReason.CANCELED)
    errno == Int32(0) || _throw_errno("event loop deregister", errno)
    return nothing
end

"""
    arm_waiter!(registration, mode)

Backend hook invoked immediately before waiting so platforms that need explicit
arming (such as IOCP readiness probes) can submit a wait operation.
"""
function arm_waiter!(registration::Registration, mode::PollMode.T)
    _mode_is_empty(mode) && return nothing
    isassigned(POLLER) || return nothing
    state = POLLER[]
    (@atomic :acquire state.running) || return nothing
    errno = Int32(0)
    lock(state.lock)
    try
        (@atomic :acquire state.running) || return nothing
        current = get(state.registrations, registration.fd, nothing)
        current === registration || return nothing
        errno = _backend_arm_waiter!(state, registration, mode)
    finally
        unlock(state.lock)
    end
    errno == Int32(0) || _throw_errno("event loop arm", errno)
    return nothing
end

"""
    _dispatch_ready_event!(state, event)

Route decoded backend events to registered waiter(s).
"""
function _dispatch_ready_event!(state::Poller, event::PollEvent)
    registration = nothing
    lock(state.lock)
    try
        registration = get(state.registrations_by_token, event.token, nothing)
        if registration === nothing
            return nothing
        end
        if event.fd != Cint(-1)
            registration.fd == event.fd || return nothing
        end
        event.errored && (@atomic :release registration.event_err = true)
    finally
        unlock(state.lock)
    end
    _notify_registration!(registration::Registration, event.mode, PollWakeReason.READY)
    return nothing
end

function _notify_all_waiters!(state::Poller)
    registrations = Registration[]
    timers = TimerState[]
    lock(state.lock)
    try
        append!(registrations, values(state.registrations))
        _discard_stale_time_entries_locked!(state)
        for entry in state.time_heap
            entry.kind == TimeEntryKind.TIMER || continue
            push!(timers, entry.timer::TimerState)
        end
    finally
        unlock(state.lock)
    end
    for registration in registrations
        _notify_registration!(registration, PollMode.READWRITE, PollWakeReason.CANCELED)
    end
    for timer in timers
        _close_timer!(timer)
    end
    return nothing
end

function _poller_thread_main!(state::Poller)
    while @atomic state.running
        delay_ns = _poll_delay_ns(state)
        errno = _backend_poll_once!(state, delay_ns)
        @atomic :release state.poll_until_ns = Int64(0)
        _drain_expired_time_entries!(state, Int64(time_ns()))
        errno == Int32(0) && continue
        if errno == Int32(Base.Libc.EINTR)
            continue
        end
        _notify_all_waiters!(state)
        @atomic :release state.running = false
    end
    notify(state.shutdown_event)
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
    while true
        reason = pollwait!(timer.waiter)
        reason == PollWakeReason.READY && return nothing
        (@atomic :acquire timer.closed) && return nothing
        (@atomic :acquire timer.deadline_ns) == 0 && return nothing
    end
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

function _poller_thread_entry(arg::Ptr{Cvoid})::Ptr{Cvoid}
    state = unsafe_pointer_to_objref(arg)::Poller
    try
        _poller_thread_main!(state)
    catch
        _notify_all_waiters!(state)
        notify(state.shutdown_event)
    end
    return C_NULL
end

function __init__()
    _POLLER_THREAD_ENTRY_C[] = @cfunction(_poller_thread_entry, Ptr{Cvoid}, (Ptr{Cvoid},))
    if _is_generating_output()
        POLLER[] = Poller()
    elseif _runtime_supported()
        @static if Sys.iswindows()
            # Avoid eager foreign-thread startup during module load on Windows.
            # Runtime initialization remains lazy via `init!()` at first use.
            POLLER[] = Poller()
        else
            init!()
        end
    else
        POLLER[] = Poller()
    end
    @assert isassigned(POLLER)
    return nothing
end

@static if Sys.isapple()
    include("1_eventloops_kqueue.jl")
elseif Sys.islinux()
    include("1_eventloops_epoll.jl")
elseif Sys.iswindows()
    include("1_eventloops_iocp.jl")
else
    include("1_eventloops_kqueue.jl")
end

end
