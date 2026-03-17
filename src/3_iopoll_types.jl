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

@inline function _mode_has_read(mode::PollMode.T)::Bool
    return (UInt8(mode) & UInt8(PollMode.READ)) != 0
end

@inline function _mode_has_write(mode::PollMode.T)::Bool
    return (UInt8(mode) & UInt8(PollMode.WRITE)) != 0
end

@inline function _mode_is_empty(mode::PollMode.T)::Bool
    return UInt8(mode) == 0x00
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

Descriptor-local state shared between descriptor operations and the runtime
poller.

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

Per-fd registration state stored by the runtime poller.

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

Global runtime poller state. `lock` is a regular mutex because registration
updates can run adjacent to syscalls where spin waiting would be wasteful.

Notable fields:
- `registrations`/`registrations_by_token` let us validate that an event or
  time entry still belongs to the current occupant of an fd slot
- `time_heap` is the min-heap that drives finite backend poll timeouts
- `poll_until_ns` records the deadline currently being slept toward so that a
  newly earlier deadline can call `_backend_wake!`, just like Go uses
  `netpollBreak()` to shorten a blocking poll
"""
abstract type BackendState end

mutable struct Poller
    lock::ReentrantLock
    registrations::Dict{Cint, Registration}
    registrations_by_token::Dict{UInt64, Registration}
    time_heap::Vector{TimeEntry}
    shutdown_event::Base.Threads.Event
    backend_state::Union{Nothing, BackendState}
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
        nothing,
        UInt64(0),
        Int64(0),
        false,
    )
end

function deadline_fire! end
