const SysFD = SocketOps.SocketFD
const INVALID_FD = SocketOps.INVALID_SOCKET

@inline _is_valid_fd(fd::SysFD)::Bool = SocketOps.is_valid_socket(fd)

"""
    PollMode

Bitmask enum used for read, write, and combined read/write readiness and
deadline directions within `IOPoll`.
"""
module PollMode
Base.@enum T::UInt8 begin
    READ = 0x01
    WRITE = 0x02
    READWRITE = 0x03
end
end

module TimeEntryKind
Base.@enum T::UInt8 begin
    DEADLINE = 0x01
    TIMER = 0x02
end
end

module PollWakeReason
Base.@enum T::UInt8 begin
    READY = 0x01
    CANCELED = 0x02
end
end

module IocpOpKind
Base.@enum T::UInt8 begin
    PROBE_READ = 0x01
    PROBE_WRITE = 0x02
    CONNECT = 0x03
    ACCEPT = 0x04
    READ = 0x05
    WRITE = 0x06
end
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

# Wake tokens are identity singletons: `===` on the single atomic word is the
# whole protocol, and reusing two preallocated instances keeps the notify path
# allocation-free on the poller thread.
mutable struct _PollWakeToken
    const reason::PollWakeReason.T
end

const _POLLWAKE_READY = _PollWakeToken(PollWakeReason.READY)
const _POLLWAKE_CANCELED = _PollWakeToken(PollWakeReason.CANCELED)

"""
    PollWaiter

Binary wake primitive used by descriptor registrations and timers.

The whole protocol lives in a single atomic word, mirroring the shape of Go's
`pollDesc.rg`/`wg` netpoll semaphores:

  * `nothing`            — empty: no waiter parked, no wake latched
  * a `Task`             — the parked (or parking) waiter task
  * `_POLLWAKE_READY`    — a latched READY wake
  * `_POLLWAKE_CANCELED` — a latched CANCELED wake

Every transition is one CAS on that word, so a notifier can never observe a
half-published waiter and a waiter can never lose a wake that lands mid-consume
(the two-word state+task variant admitted both). A single `PollWaiter` may
have at most one parked task at a time.
"""
mutable struct PollWaiter
    @atomic state::Union{Nothing, Task, _PollWakeToken}
    function PollWaiter()
        return new(nothing)
    end
end

# Tear-down for a waiter that is leaving `pollwait!` exceptionally
# (`schedule(task, exc; error=true)`); reclaims the slot so the waiter stays
# reusable. If a notifier committed a wake token concurrently with the
# interrupt, the token is consumed here: the interrupting error-schedule either
# stole that notifier's queue slot or the notifier's `schedule` was absorbed by
# `_pollwake_schedule!`'s not-runnable guard.
function _abort_pollwait!(waiter::PollWaiter, task::Task)
    while true
        state = @atomic :acquire waiter.state
        if state === task || state isa _PollWakeToken
            _, cleared = @atomicreplace(waiter.state, state => nothing)
            cleared && return nothing
        elseif state === nothing
            return nothing
        else
            throw(ArgumentError("invalid PollWaiter state"))
        end
    end
end

# `schedule(task)` is the low-level dual of the `wait()` in `pollwait!`.
function _pollwake_schedule!(task::Task)::Bool
    try
        schedule(task)
        return true
    catch err
        err isa ErrorException || rethrow()
        # The parked task was interrupted (`schedule(task, exc; error=true)`)
        # between our token commit and this wake, and the interrupt owns the
        # task's queue slot. The interrupt wake subsumes ours;
        # `_abort_pollwait!` consumes the committed token.
        return false
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
    # Intentionally preserve the caller's task stickiness. The poller wakes this
    # task via `schedule(task)`; for a migratable task that drops it into the
    # global run-queue, waking a cold parked worker whose cost scales with
    # nthreads. Stickiness is the caller's choice (`@async` to pin a hot reader,
    # `Threads.@spawn` to stay migratable) — don't override it here.
    #
    # Consume an already-latched wake without parking, or claim the empty slot
    # by publishing this task in the word. Publishing the task IS the park
    # commitment: from here on any notifier that swaps it for a token owns
    # exactly one `schedule` of this task.
    while true
        state = @atomic :acquire waiter.state
        if state === nothing
            _, claimed = @atomicreplace(waiter.state, nothing => task)
            claimed && break
        elseif state isa _PollWakeToken
            _, consumed = @atomicreplace(waiter.state, state => nothing)
            consumed && return state.reason
        else
            throw(ArgumentError("concurrent wait on PollWaiter"))
        end
    end
    try
        while true
            wait()
            # The token carries its reason in the same atomic word, so consuming
            # it cannot race a separate reason publication. A failed consume can
            # only mean the CANCELED→READY upgrade landed mid-consume: re-read
            # and consume the upgraded token — never re-park, the wake token
            # that got us here has already been spent.
            while true
                state = @atomic :acquire waiter.state
                if state isa _PollWakeToken
                    _, consumed = @atomicreplace(waiter.state, state => nothing)
                    consumed && return state.reason
                elseif state === task
                    # Stale wake with no token committed (an absorbed schedule
                    # from an earlier interrupt race): park again.
                    break
                else
                    throw(ArgumentError("invalid PollWaiter state"))
                end
            end
        end
    catch
        _abort_pollwait!(waiter, task)
        rethrow()
    end
end

"""
    pollnotify!(waiter, reason=PollWakeReason.READY)

Mark waiter as notified and wake the waiter task if it has already parked.
Returns `true` if a parked waiter was woken and `false` if the waiter was
already notified or had not yet parked. `PollWakeReason.READY` dominates a
previously latched `PollWakeReason.CANCELED` so once readiness has been
observed it is preserved.
"""
function pollnotify!(waiter::PollWaiter, reason::PollWakeReason.T = PollWakeReason.READY)::Bool
    token = reason == PollWakeReason.READY ? _POLLWAKE_READY : _POLLWAKE_CANCELED
    while true
        state = @atomic :acquire waiter.state
        if state === _POLLWAKE_READY
            # READY dominates; nothing to add.
            return false
        elseif state === _POLLWAKE_CANCELED
            reason == PollWakeReason.CANCELED && return false
            # Upgrade a latched CANCELED to READY without a wake: whoever the
            # token is destined for either has not parked or already owns the
            # wake that published it.
            _, upgraded = @atomicreplace(waiter.state, _POLLWAKE_CANCELED => _POLLWAKE_READY)
            upgraded && return false
        elseif state === nothing
            _, latched = @atomicreplace(waiter.state, nothing => token)
            latched && return false
        else
            # A parked (or parking) task: committing the token buys exactly one
            # wake of exactly this task.
            waiting = state::Task
            _, committed = @atomicreplace(waiter.state, state => token)
            committed && return _pollwake_schedule!(waiting)
        end
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
    fd::SysFD
    token::UInt64
    mode::PollMode.T
    errored::Bool
end

"""
    PollState(sysfd=-1, token=0)

Descriptor-local state shared between descriptor operations and the runtime
poller.

It holds registration identity (`sysfd`, `token`), coarse descriptor state
(`pollable`, `closing`, `event_err`), and the read/write deadline words plus
their sequence numbers. The sequence counters let the poller heap discard stale
deadline entries after deadline changes without mutating the heap in place.
"""
mutable struct PollState
    lock::ReentrantLock
    sysfd::SysFD
    token::UInt64
    @atomic pollable::Bool
    @atomic closing::Bool
    @atomic event_err::Bool
    @atomic rd_ns::Int64
    @atomic wd_ns::Int64
    @atomic rseq::UInt64
    @atomic wseq::UInt64
    function PollState(sysfd::SysFD = INVALID_FD, token::UInt64 = UInt64(0))
        return new(
            ReentrantLock(),
            sysfd,
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
    fd::SysFD
    token::UInt64
    mode::PollMode.T
    read_waiter::PollWaiter
    write_waiter::PollWaiter
    @atomic event_err::Bool
    pollstate::PollState
end

function Registration(
        fd::SysFD,
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
  newly earlier deadline can call `_backend_wake!` and shorten a blocking poll
"""
abstract type BackendState end

mutable struct Poller
    lock::ReentrantLock
    registrations::Dict{SysFD, Registration}
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
        Dict{SysFD, Registration}(),
        Dict{UInt64, Registration}(),
        TimeEntry[],
        Base.Threads.Event(),
        nothing,
        UInt64(0),
        Int64(0),
        false,
    )
end
