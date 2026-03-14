"""
    IOPoll

Go-style poll descriptor layer built on `EventLoops`.
Provides deadline-aware readiness waiting for network descriptors.

Conceptually this sits where Go's `internal/poll` package sits:
- `EventLoops` is the runtime-facing readiness engine
- `IOPoll` turns readiness and deadlines into descriptor-centric operations
- higher transport layers call `prepare_*`, `wait_*`, and deadline helpers
  instead of talking to the event loop directly
"""
module IOPoll

using EnumX
using ..Reseau.EventLoops
using ..Reseau.SocketOps
import ..Reseau.EventLoops: deadline_fire!

const PollState = EventLoops.PollState

# FDLock state bits packed into one atomic word (close flag, lock flags, refs, waiter counts).
const _MUTEX_CLOSED = UInt64(1) << 0
const _MUTEX_RLOCK = UInt64(1) << 1
const _MUTEX_WLOCK = UInt64(1) << 2
const _MUTEX_REF = UInt64(1) << 3
const _MUTEX_REF_MASK = (UInt64(1) << 20 - UInt64(1)) << 3
const _MUTEX_RWAIT = UInt64(1) << 23
const _MUTEX_RMASK = (UInt64(1) << 20 - UInt64(1)) << 23
const _MUTEX_WWAIT = UInt64(1) << 43
const _MUTEX_WMASK = (UInt64(1) << 20 - UInt64(1)) << 43

const _POLL_NO_ERROR = Int32(0)
const _POLL_ERR_CLOSING = Int32(1)
const _POLL_ERR_TIMEOUT = Int32(2)
const _POLL_ERR_NOT_POLLABLE = Int32(3)

"""
Bitmask of operations used for readiness waits and deadline management.

`READWRITE` is intentionally the bitwise OR of `READ` and `WRITE` so callers can
test or combine directions cheaply.
"""
@enumx PollOp::UInt8 begin
    READ = 0x01
    WRITE = 0x02
    READWRITE = 0x03
end

struct NetClosingError <: Exception end
struct FileClosingError <: Exception end
struct NoDeadlineError <: Exception end
struct DeadlineExceededError <: Exception end
struct NotPollableError <: Exception end

function Base.showerror(io::IO, ::NetClosingError)
    print(io, "use of closed network connection")
    return nothing
end

function Base.showerror(io::IO, ::FileClosingError)
    print(io, "use of closed file")
    return nothing
end

function Base.showerror(io::IO, ::NoDeadlineError)
    print(io, "file type does not support deadline")
    return nothing
end

function Base.showerror(io::IO, ::DeadlineExceededError)
    print(io, "i/o timeout")
    return nothing
end

function Base.showerror(io::IO, ::NotPollableError)
    print(io, "not pollable")
    return nothing
end

@inline function _closing_error(is_file::Bool)::Exception
    is_file && return FileClosingError()
    return NetClosingError()
end

@inline function _mode_has_read(mode::PollOp.T)::Bool
    return (UInt8(mode) & UInt8(PollOp.READ)) != 0
end

@inline function _mode_has_write(mode::PollOp.T)::Bool
    return (UInt8(mode) & UInt8(PollOp.WRITE)) != 0
end

@inline function _is_accept_retry_errno(errno::Int32)::Bool
    return errno == Int32(Base.Libc.EINTR) || errno == Int32(Base.Libc.ECONNABORTED)
end

@inline function _monotonic_ns()::Int64
    return Int64(time_ns())
end

"""
    RuntimeSema

Small counting semaphore used by `FDLock` slow paths.

Unlike `PollWaiter`, this is deliberately unbounded: repeated wakeups must not
be lost while a goroutine-like lock waiter is still making progress through the
`FDLock` state machine.
"""
mutable struct RuntimeSema
    lock::ReentrantLock
    cond::Base.Threads.Condition
    count::Int
    function RuntimeSema()
        lock = ReentrantLock()
        return new(lock, Base.Threads.Condition(lock), 0)
    end
end

"""
    _runtime_sema_acquire!(sema)

Block until one semaphore unit is available, then consume it.

Returns `nothing`.
"""
function _runtime_sema_acquire!(sema::RuntimeSema)
    lock(sema.lock)
    try
        while sema.count == 0
            wait(sema.cond)
        end
        sema.count -= 1
    finally
        unlock(sema.lock)
    end
    return nothing
end

"""
    _runtime_sema_release!(sema)

Add one semaphore unit and notify one blocked waiter.

Returns `nothing`.
"""
function _runtime_sema_release!(sema::RuntimeSema)
    lock(sema.lock)
    try
        sema.count += 1
        notify(sema.cond)
    finally
        unlock(sema.lock)
    end
    return nothing
end

function _new_binary_semaphore0()
    sema = Base.Semaphore(1)
    Base.acquire(sema)
    return sema
end

"""
Atomic lock/reference state for an `FD`, mirroring Go's `internal/poll` approach.

The bitfield tracks:
- whether close has started
- read/write lock ownership
- shared references
- queued waiters for read and write locks
"""
mutable struct FDLock
    @atomic state::UInt64
    const rsema::RuntimeSema
    const wsema::RuntimeSema
    function FDLock()
        return new(UInt64(0), RuntimeSema(), RuntimeSema())
    end
end

"""
    _fdlock_incref!(mu)

Acquire one shared descriptor reference.

Returns `true` on success and `false` if close has already started.

Throws `ArgumentError` if the reference count overflows, which would indicate an
unreasonable number of concurrent operations on one descriptor.
"""
function _fdlock_incref!(mu::FDLock)::Bool
    while true
        old = @atomic :acquire mu.state
        (old & _MUTEX_CLOSED) != 0 && return false
        new = old + _MUTEX_REF
        (new & _MUTEX_REF_MASK) == 0 && throw(ArgumentError("too many concurrent operations on a single fd"))
        _, ok = @atomicreplace(mu.state, old => new)
        ok && return true
    end
end

"""
    _fdlock_incref_and_close!(mu)

Start close, acquire one final shared reference, and wake all queued lock
waiters.

Returns `true` if this call successfully initiated close and `false` if another
task had already done so.
"""
function _fdlock_incref_and_close!(mu::FDLock)::Bool
    while true
        old = @atomic :acquire mu.state
        (old & _MUTEX_CLOSED) != 0 && return false
        new = (old | _MUTEX_CLOSED) + _MUTEX_REF
        (new & _MUTEX_REF_MASK) == 0 && throw(ArgumentError("too many concurrent operations on a single fd"))
        new &= ~(_MUTEX_RMASK | _MUTEX_WMASK)
        _, ok = @atomicreplace(mu.state, old => new)
        ok || continue
        wake = old
        # Close wakes all queued read waiters.
        while (wake & _MUTEX_RMASK) != 0
            wake -= _MUTEX_RWAIT
            _runtime_sema_release!(mu.rsema)
        end
        # Close wakes all queued write waiters.
        while (wake & _MUTEX_WMASK) != 0
            wake -= _MUTEX_WWAIT
            _runtime_sema_release!(mu.wsema)
        end
        return true
    end
end

"""
    _fdlock_decref!(mu)

Release one shared descriptor reference.

Returns `true` exactly when the descriptor has already been marked closed and
this call released the final outstanding reference, meaning the underlying OS
handle may now be destroyed.
"""
function _fdlock_decref!(mu::FDLock)::Bool
    while true
        old = @atomic :acquire mu.state
        (old & _MUTEX_REF_MASK) == 0 && throw(ArgumentError("inconsistent fd mutex state"))
        new = old - _MUTEX_REF
        _, ok = @atomicreplace(mu.state, old => new)
        ok || continue
        return (new & (_MUTEX_CLOSED | _MUTEX_REF_MASK)) == _MUTEX_CLOSED
    end
end

"""
    _fdlock_rwlock!(mu, read_lock, wait_lock)

Acquire the descriptor's read or write operation lock.

Arguments:
- `read_lock`: `true` for the read lock, `false` for the write lock
- `wait_lock`: whether to queue and block if the lock is already held

Returns `true` on success and `false` if the descriptor is closed or if
`wait_lock == false` and the lock is already held.
"""
function _fdlock_rwlock!(mu::FDLock, read_lock::Bool, wait_lock::Bool)::Bool
    mutex_bit = read_lock ? _MUTEX_RLOCK : _MUTEX_WLOCK
    mutex_wait = read_lock ? _MUTEX_RWAIT : _MUTEX_WWAIT
    mutex_mask = read_lock ? _MUTEX_RMASK : _MUTEX_WMASK
    mutex_sema = read_lock ? mu.rsema : mu.wsema
    while true
        old = @atomic :acquire mu.state
        (old & _MUTEX_CLOSED) != 0 && return false
        new = UInt64(0)
        if (old & mutex_bit) == 0
            new = (old | mutex_bit) + _MUTEX_REF
            (new & _MUTEX_REF_MASK) == 0 && throw(ArgumentError("too many concurrent operations on a single fd"))
        else
            wait_lock || return false
            new = old + mutex_wait
            (new & mutex_mask) == 0 && throw(ArgumentError("too many concurrent operations on a single fd"))
        end
        _, ok = @atomicreplace(mu.state, old => new)
        ok || continue
        if (old & mutex_bit) == 0
            return true
        end
        _runtime_sema_acquire!(mutex_sema)
    end
end

"""
    _fdlock_rwunlock!(mu, read_lock)

Release the descriptor's read or write operation lock.

Returns `true` when the descriptor has already been marked closed and this call
released the final reference, so destruction should proceed.
"""
function _fdlock_rwunlock!(mu::FDLock, read_lock::Bool)::Bool
    mutex_bit = read_lock ? _MUTEX_RLOCK : _MUTEX_WLOCK
    mutex_wait = read_lock ? _MUTEX_RWAIT : _MUTEX_WWAIT
    mutex_mask = read_lock ? _MUTEX_RMASK : _MUTEX_WMASK
    mutex_sema = read_lock ? mu.rsema : mu.wsema
    while true
        old = @atomic :acquire mu.state
        ((old & mutex_bit) == 0 || (old & _MUTEX_REF_MASK) == 0) && throw(ArgumentError("inconsistent fd mutex state"))
        new = (old & ~mutex_bit) - _MUTEX_REF
        if (old & mutex_mask) != 0
            new -= mutex_wait
        end
        _, ok = @atomicreplace(mu.state, old => new)
        ok || continue
        if (old & mutex_mask) != 0
            _runtime_sema_release!(mutex_sema)
        end
        return (new & (_MUTEX_CLOSED | _MUTEX_REF_MASK)) == _MUTEX_CLOSED
    end
end

"""
Internal file descriptor wrapper used by the poll layer.

This coordinates descriptor lifetime, read/write serialization, and integration
with `PollState`.

Fields:
- `fdlock`: Go-style reference and read/write lock state
- `pd`: deadline/readiness state shared with `EventLoops`
- `csema`: close semaphore used to wait for non-blocking operations to drain
- `is_blocking`: whether the OS descriptor has been switched back to blocking
"""
mutable struct FD
    fdlock::FDLock
    sysfd::Cint
    pd::PollState
    csema::Base.Semaphore
    @atomic is_blocking::Bool
    is_stream::Bool
    zero_read_is_eof::Bool
    is_file::Bool
    function FD(
            sysfd::Integer;
            is_stream::Bool = true,
            zero_read_is_eof::Bool = true,
            is_file::Bool = false,
        )
        return new(
            FDLock(),
            Cint(sysfd),
            PollState(),
            _new_binary_semaphore0(),
            false,
            is_stream,
            zero_read_is_eof,
            is_file,
        )
    end
end

"""
    _convert_poll_error!(res, is_file)

Map a compact internal poll status code to the public exception surface.

Returns `nothing` when `res` indicates success.

Throws one of `NetClosingError`, `FileClosingError`, `DeadlineExceededError`,
`NotPollableError`, or `ArgumentError` for an invalid status code.
"""
function _convert_poll_error!(res::Int32, is_file::Bool)
    res == _POLL_NO_ERROR && return nothing
    res == _POLL_ERR_CLOSING && throw(_closing_error(is_file))
    res == _POLL_ERR_TIMEOUT && throw(DeadlineExceededError())
    res == _POLL_ERR_NOT_POLLABLE && throw(NotPollableError())
    throw(ArgumentError("invalid poll status"))
end

"""
Map current `PollState` state into a compact poll error code.

This mirrors the shape of Go's `runtime_pollWait` checks: close and deadline
state are consulted before and after parking so callers can distinguish "ready"
from "woken because the descriptor was closed or timed out".
"""
function _check_error(pd::PollState, mode::PollOp.T)::Int32
    (@atomic :acquire pd.closing) && return _POLL_ERR_CLOSING
    if _mode_has_read(mode)
        (@atomic :acquire pd.rd_ns) < 0 && return _POLL_ERR_TIMEOUT
    end
    if _mode_has_write(mode)
        (@atomic :acquire pd.wd_ns) < 0 && return _POLL_ERR_TIMEOUT
    end
    if _mode_has_read(mode)
        _refresh_event_err!(pd)
        (@atomic :acquire pd.event_err) && return _POLL_ERR_NOT_POLLABLE
    end
    return _POLL_NO_ERROR
end

"""
    _refresh_event_err!(pd)

Synchronize the persistent backend error bit from the live registration into
`pd.event_err`.

Backends set `registration.event_err` when the OS reports an error/hangup event
that should permanently make the descriptor non-pollable. Higher layers cache
that on `PollState` because `PollState` outlives any single readiness wait.
"""
function _refresh_event_err!(pd::PollState)
    (@atomic :acquire pd.pollable) || return nothing
    registration = EventLoops.current_registration(pd)
    registration === nothing && return nothing
    has_event_error = @atomic :acquire registration.event_err
    @atomic :release pd.event_err = has_event_error
    return nothing
end

"""
    _wake_waiters!(pd, mode)

Notify the read and/or write waiters associated with `pd`.

Returns `nothing`.
"""
function _wake_waiters!(pd::PollState, mode::PollOp.T)
    (@atomic :acquire pd.pollable) || return nothing
    registration = EventLoops.current_registration(pd)
    registration === nothing && return nothing
    event_mode = EventLoops.PollMode.READWRITE
    if mode == PollOp.READ
        event_mode = EventLoops.PollMode.READ
    elseif mode == PollOp.WRITE
        event_mode = EventLoops.PollMode.WRITE
    end
    EventLoops._notify_registration!(registration, event_mode, EventLoops.PollWakeReason.CANCELED)
    return nothing
end

"""
    deadline_fire!(pd, mode, rseq, wseq)

Consume one expired poller deadline entry.

The poller thread passes in the sequence numbers captured when the deadline was
scheduled. If they still match the current `PollState`, the deadline is live and
the corresponding read/write deadline slot is flipped to `-1`, which is the
local sentinel for "deadline exceeded". If the sequences no longer match, the
entry is stale and ignored.

Returns `nothing`.
"""
function deadline_fire!(
        pd::PollState,
        mode::EventLoops.PollMode.T,
        rseq::UInt64,
        wseq::UInt64,
    )
    wake_read = false
    wake_write = false
    lock(pd.lock)
    try
        (@atomic :acquire pd.closing) && return nothing
        EventLoops.current_registration(pd) === nothing && return nothing
        if (UInt8(mode) & UInt8(EventLoops.PollMode.READ)) != 0
            if (@atomic :acquire pd.rseq) == rseq && (@atomic :acquire pd.rd_ns) > 0
                @atomic :release pd.rd_ns = Int64(-1)
                wake_read = true
            end
        end
        if (UInt8(mode) & UInt8(EventLoops.PollMode.WRITE)) != 0
            if (@atomic :acquire pd.wseq) == wseq && (@atomic :acquire pd.wd_ns) > 0
                @atomic :release pd.wd_ns = Int64(-1)
                wake_write = true
            end
        end
    finally
        unlock(pd.lock)
    end
    if wake_read && wake_write
        _wake_waiters!(pd, PollOp.READWRITE)
    elseif wake_read
        _wake_waiters!(pd, PollOp.READ)
    elseif wake_write
        _wake_waiters!(pd, PollOp.WRITE)
    end
    return nothing
end

"""
Set read/write deadline state on an `FD`.

`deadline_ns == 0` disables deadlines for the selected mode.
`deadline_ns <= time_ns()` triggers immediate timeout.

Returns `nothing`.

Throws:
- `NetClosingError` / `FileClosingError` if close has already started
- `NoDeadlineError` if the descriptor is not managed by the poller
"""
function _set_deadline_impl!(fd::FD, deadline_ns::Integer, mode::PollOp.T)
    deadline = Int64(deadline_ns)
    _fdlock_incref!(fd.fdlock) || throw(_closing_error(fd.is_file))
    try
        pd = fd.pd
        (@atomic :acquire pd.pollable) || throw(NoDeadlineError())
        wake_read = false
        wake_write = false
        registration = nothing
        rd_ns = Int64(0)
        wd_ns = Int64(0)
        rseq = UInt64(0)
        wseq = UInt64(0)
        lock(pd.lock)
        try
            (@atomic :acquire pd.closing) && return nothing
            if _mode_has_read(mode)
                # The new sequence invalidates every previously scheduled read
                # deadline entry for this descriptor.
                @atomic pd.rseq += UInt64(1)
                if deadline == 0
                    @atomic :release pd.rd_ns = Int64(0)
                elseif deadline <= _monotonic_ns()
                    @atomic :release pd.rd_ns = Int64(-1)
                    wake_read = true
                else
                    @atomic :release pd.rd_ns = deadline
                end
            end
            if _mode_has_write(mode)
                @atomic pd.wseq += UInt64(1)
                if deadline == 0
                    @atomic :release pd.wd_ns = Int64(0)
                elseif deadline <= _monotonic_ns()
                    @atomic :release pd.wd_ns = Int64(-1)
                    wake_write = true
                else
                    @atomic :release pd.wd_ns = deadline
                end
            end
            rd_ns = @atomic :acquire pd.rd_ns
            wd_ns = @atomic :acquire pd.wd_ns
            rseq = @atomic :acquire pd.rseq
            wseq = @atomic :acquire pd.wseq
        finally
            unlock(pd.lock)
        end
        # Publish the post-update snapshot to the poller heap. Stale entries are
        # left in the heap and filtered by sequence/token checks when they reach
        # the top, which keeps scheduling cheap and matches Go's timer seq
        # invalidation strategy.
        EventLoops.schedule_deadlines!(pd, rd_ns, wd_ns, rseq, wseq)
        if wake_read && wake_write
            _wake_waiters!(pd, PollOp.READWRITE)
        elseif wake_read
            _wake_waiters!(pd, PollOp.READ)
        elseif wake_write
            _wake_waiters!(pd, PollOp.WRITE)
        end
    finally
        _fd_decref!(fd)
    end
    return nothing
end

"""
Initialize polling state for an `FD`.

When `pollable=true`, the fd is registered with `EventLoops`; otherwise the fd
is treated as blocking and deadline support is disabled.

Keyword arguments:
- `net`: reserved for parity with higher-level callers that track transport kind
- `pollable`: whether the descriptor should be registered with the runtime
  poller

Returns `nothing`.

Throws `SystemError` if event loop registration fails.
"""
function init!(fd::FD; net::Symbol = :tcp, pollable::Bool = true)
    _ = net
    pd = fd.pd
    lock(pd.lock)
    try
        if pollable
            _set_nonblocking!(fd.sysfd)
            registration = EventLoops.register!(fd.sysfd; mode = EventLoops.PollMode.READWRITE, pollstate = pd)
            pd.sysfd = fd.sysfd
            pd.token = registration.token
            @atomic :release pd.pollable = true
            @atomic :release pd.closing = false
            @atomic :release pd.event_err = false
            @atomic :release pd.rd_ns = Int64(0)
            @atomic :release pd.wd_ns = Int64(0)
            @atomic :release pd.rseq = UInt64(1)
            @atomic :release pd.wseq = UInt64(1)
        else
            @atomic :release fd.is_blocking = true
            @atomic :release pd.pollable = false
        end
    finally
        unlock(pd.lock)
    end
    return nothing
end

"""
Tear down polling state for a descriptor and deregister from `EventLoops`.

Returns `nothing`.
"""
function close!(pd::PollState)
    was_pollable = false
    lock(pd.lock)
    try
        was_pollable = @atomic :acquire pd.pollable
        @atomic :release pd.pollable = false
    finally
        unlock(pd.lock)
    end
    was_pollable && pd.sysfd >= 0 && EventLoops.deregister!(pd.sysfd)
    return nothing
end

"""
Mark descriptor as closing and wake all waiters.

This does not itself destroy the OS descriptor; it only forces all future poll
operations to observe closing and all parked waiters to wake up promptly.
"""
function evict!(pd::PollState)
    lock(pd.lock)
    try
        (@atomic :acquire pd.closing) && return nothing
        @atomic :release pd.closing = true
        @atomic pd.rseq += UInt64(1)
        @atomic pd.wseq += UInt64(1)
    finally
        unlock(pd.lock)
    end
    _wake_waiters!(pd, PollOp.READWRITE)
    return nothing
end

"""
Return whether the descriptor is currently managed by the poller.
"""
function pollable(pd::PollState)::Bool
    return @atomic :acquire pd.pollable
end

@inline function _poll_registration(pd::PollState)::EventLoops.Registration
    registration = EventLoops.current_registration(pd)
    registration === nothing && throw(SystemError("event loop wait", Int(Base.Libc.EBADF)))
    return registration
end

"""
Validate read path state before issuing a read syscall.

Returns `nothing`.

Throws the same exceptions as `_convert_poll_error!` if close, timeout, or
backend error state is already visible.
"""
function prepare_read!(pd::PollState, is_file::Bool = false)
    _convert_poll_error!(_check_error(pd, PollOp.READ), is_file)
    return nothing
end

"""
Validate write path state before issuing a write syscall.

Returns `nothing`.
"""
function prepare_write!(pd::PollState, is_file::Bool = false)
    _convert_poll_error!(_check_error(pd, PollOp.WRITE), is_file)
    return nothing
end

"""
Block until read readiness, retrying internally if a canceled wake becomes
stale before the waiter task resumes.

Returns `nothing`.

Throws:
- `ArgumentError` if the descriptor is not pollable
- `NetClosingError` / `FileClosingError` if the descriptor closes while waiting
- `DeadlineExceededError` if the read deadline expires
- `NotPollableError` if the backend reports a permanent readiness error
"""
function wait_read!(pd::PollState, is_file::Bool = false)
    while true
        _convert_poll_error!(_check_error(pd, PollOp.READ), is_file)
        pollable(pd) || throw(ArgumentError("waiting for unsupported file type"))
        registration = _poll_registration(pd)
        EventLoops.arm_waiter!(registration, EventLoops.PollMode.READ)
        reason = EventLoops.pollwait!(registration.read_waiter)
        reason == EventLoops.PollWakeReason.READY && return nothing
        err = _check_error(pd, PollOp.READ)
        err == _POLL_NO_ERROR && continue
        _convert_poll_error!(err, is_file)
    end
end

"""
Block until write readiness, retrying internally if a canceled wake becomes
stale before the waiter task resumes.

Returns `nothing`.
"""
function wait_write!(pd::PollState, is_file::Bool = false)
    while true
        _convert_poll_error!(_check_error(pd, PollOp.WRITE), is_file)
        pollable(pd) || throw(ArgumentError("waiting for unsupported file type"))
        registration = _poll_registration(pd)
        EventLoops.arm_waiter!(registration, EventLoops.PollMode.WRITE)
        reason = EventLoops.pollwait!(registration.write_waiter)
        reason == EventLoops.PollWakeReason.READY && return nothing
        err = _check_error(pd, PollOp.WRITE)
        err == _POLL_NO_ERROR && continue
        _convert_poll_error!(err, is_file)
    end
end

"""
Wait for readiness in a cancellation context (used by close/deadline wake paths).

Returns `nothing`.

Unlike `wait_read!`/`wait_write!`, this helper intentionally does not translate
the wakeup into exceptions; callers use it when they need a best-effort park
that can be interrupted by close/cancel machinery.
"""
function wait_canceled!(pd::PollState, mode::PollOp.T)
    pollable(pd) || return nothing
    registration = EventLoops.current_registration(pd)
    registration === nothing && return nothing
    if mode == PollOp.WRITE
        EventLoops.arm_waiter!(registration, EventLoops.PollMode.WRITE)
        EventLoops.pollwait!(registration.write_waiter)
        return nothing
    end
    EventLoops.arm_waiter!(registration, EventLoops.PollMode.READ)
    EventLoops.pollwait!(registration.read_waiter)
    return nothing
end

"""
Set both read and write deadlines for `fd`.

`deadline_ns` is interpreted as an absolute `time_ns()`-style monotonic
timestamp. Use `0` to clear both deadlines.
"""
function set_deadline!(fd::FD, deadline_ns::Integer)
    _set_deadline_impl!(fd, deadline_ns, PollOp.READWRITE)
    return nothing
end

"""
Set the read deadline for `fd`.
"""
function set_read_deadline!(fd::FD, deadline_ns::Integer)
    _set_deadline_impl!(fd, deadline_ns, PollOp.READ)
    return nothing
end

"""
Set the write deadline for `fd`.
"""
function set_write_deadline!(fd::FD, deadline_ns::Integer)
    _set_deadline_impl!(fd, deadline_ns, PollOp.WRITE)
    return nothing
end

function _set_nonblocking!(fd::Cint)
    SocketOps.set_nonblocking!(fd, true)
    return nothing
end

function _fd_incref!(fd::FD)
    _fdlock_incref!(fd.fdlock) || throw(_closing_error(fd.is_file))
    return nothing
end

function _fd_decref!(fd::FD)
    _fdlock_decref!(fd.fdlock) || return nothing
    _destroy!(fd)
    return nothing
end

function _fd_read_lock!(fd::FD)
    _fdlock_rwlock!(fd.fdlock, true, true) || throw(_closing_error(fd.is_file))
    return nothing
end

function _fd_read_unlock!(fd::FD)
    _fdlock_rwunlock!(fd.fdlock, true) || return nothing
    _destroy!(fd)
    return nothing
end

function _fd_write_lock!(fd::FD)
    _fdlock_rwlock!(fd.fdlock, false, true) || throw(_closing_error(fd.is_file))
    return nothing
end

function _fd_write_unlock!(fd::FD)
    _fdlock_rwunlock!(fd.fdlock, false) || return nothing
    _destroy!(fd)
    return nothing
end

function _destroy!(fd::FD)
    close!(fd.pd)
    if fd.sysfd >= 0
        SocketOps.close_socket_nothrow(fd.sysfd)
        fd.sysfd = Cint(-1)
    end
    Base.release(fd.csema)
    return nothing
end

"""
Close the descriptor and wait for outstanding non-blocking operations to drain.

Returns `nothing`.

Throws `NetClosingError` or `FileClosingError` if close had already started.
"""
function close!(fd::FD)
    _fdlock_incref_and_close!(fd.fdlock) || throw(_closing_error(fd.is_file))
    evict!(fd.pd)
    _fd_decref!(fd)
    if !(@atomic :acquire fd.is_blocking)
        Base.acquire(fd.csema)
    end
    return nothing
end

"""
Switch an `FD` into blocking mode via `ioctl(FIONBIO, 0)`.

Returns `nothing`.
"""
function set_blocking!(fd::FD)
    _fd_incref!(fd)
    try
        @atomic :release fd.is_blocking = true
        SocketOps.set_nonblocking!(fd.sysfd, false)
    finally
        _fd_decref!(fd)
    end
    return nothing
end

"""
Submit a Windows `ConnectEx` operation and wait for completion through IOCP.

The fd must already be initialized as pollable and have any required local bind
applied before calling this helper.
"""
function connect!(fd::FD, addrbuf::Vector{UInt8}, addrlen::Int32)
    _fd_write_lock!(fd)
    try
        prepare_write!(fd.pd, fd.is_file)
        registration = _poll_registration(fd.pd)
        errno = EventLoops._iocp_submit_connect!(registration, addrbuf, addrlen)
        errno == Int32(0) || throw(SystemError("connectex", Int(errno)))
        try
            EventLoops.pollwait!(registration.write_waiter)
            _convert_poll_error!(_check_error(fd.pd, PollOp.WRITE), fd.is_file)
        catch err
            ex = err::Exception
            if EventLoops._iocp_cancel_mode!(registration, EventLoops.PollMode.WRITE)
                EventLoops.pollwait!(registration.write_waiter)
            end
            _ = EventLoops._iocp_finish_connect!(registration)
            rethrow(ex)
        end
        errno = EventLoops._iocp_finish_connect!(registration)
        errno == Int32(0) || throw(SystemError("connectex", Int(errno)))
        SocketOps.update_connect_context!(fd.sysfd)
    finally
        _fd_write_unlock!(fd)
    end
    return nothing
end

"""
Accept one non-blocking child fd from `fd`.

This mirrors Go `internal/poll` accept semantics: read-lock + prepare + retry
on `EINTR`/`ECONNABORTED`, wait on `EAGAIN`.
"""
function accept!(fd::FD, family::Cint, sotype::Cint)::Tuple{Cint, SocketOps.AcceptPeer}
    _fd_read_lock!(fd)
    try
        prepare_read!(fd.pd, fd.is_file)
        while true
            @static if Sys.iswindows()
                registration = _poll_registration(fd.pd)
                child_sysfd = SocketOps.open_socket(family, sotype)
                addrbuf = Vector{UInt8}(undef, Int(2 * SocketOps._ACCEPT_ADDRBUF_LEN))
                errno = EventLoops._iocp_submit_accept!(registration, child_sysfd, addrbuf)
                if errno != Int32(0)
                    SocketOps.close_socket_nothrow(child_sysfd)
                    throw(SystemError("acceptex", Int(errno)))
                end
                try
                    EventLoops.pollwait!(registration.read_waiter)
                    _convert_poll_error!(_check_error(fd.pd, PollOp.READ), fd.is_file)
                catch err
                    ex = err::Exception
                    if EventLoops._iocp_cancel_mode!(registration, EventLoops.PollMode.READ)
                        EventLoops.pollwait!(registration.read_waiter)
                    end
                    _, _, _ = EventLoops._iocp_finish_accept!(registration)
                    SocketOps.close_socket_nothrow(child_sysfd)
                    rethrow(ex)
                end
                accepted_sysfd, accepted_addrbuf, errno = EventLoops._iocp_finish_accept!(registration)
                if errno == Int32(0)
                    peer_addr = SocketOps.finish_accept_ex!(fd.sysfd, accepted_sysfd, accepted_addrbuf)
                    return accepted_sysfd, peer_addr
                end
                SocketOps.close_socket_nothrow(accepted_sysfd)
                if errno == Int32(Base.Libc.ECONNRESET) || _is_accept_retry_errno(errno)
                    continue
                end
                throw(SystemError("acceptex", Int(errno)))
            end
            child_sysfd, peer_addr, errno = SocketOps.try_accept_socket(fd.sysfd)
            if child_sysfd != Cint(-1)
                return child_sysfd, peer_addr
            end
            if errno == Int32(Base.Libc.EAGAIN) && pollable(fd.pd)
                wait_read!(fd.pd, fd.is_file)
                continue
            end
            _is_accept_retry_errno(errno) && continue
            throw(SystemError("accept", Int(errno)))
        end
    finally
        _fd_read_unlock!(fd)
    end
end

"""
Read up to `length(p)` bytes into `p` and return the number of bytes read.

Important behavior notes:
- the return value may be smaller than `length(p)` whenever fewer bytes are
  currently available than the caller requested; this is normal for stream
  sockets and does not imply EOF
- once at least one byte has been read, the call returns immediately instead of
  waiting to fill the rest of `p`
- if no bytes are currently available and the descriptor is pollable, the call
  waits for read readiness and then retries
- a zero-length `p` returns `0` immediately without touching the descriptor

Throws `EOFError` when the peer cleanly closes a stream whose
`zero_read_is_eof` flag is set, `DeadlineExceededError` when the read deadline
expires while waiting, and `SystemError` for OS-level read failures.
"""
function read!(fd::FD, p::Vector{UInt8})::Int
    _fd_read_lock!(fd)
    try
        isempty(p) && return 0
        prepare_read!(fd.pd, fd.is_file)
        while true
            n = GC.@preserve p SocketOps.read_once!(fd.sysfd, pointer(p), Csize_t(length(p)))
            if n >= 0
                if n == 0 && fd.zero_read_is_eof
                    throw(EOFError())
                end
                return Int(n)
            end
            errno = SocketOps.last_error()
            if errno == Int32(Base.Libc.EAGAIN) && pollable(fd.pd)
                wait_read!(fd.pd, fd.is_file)
                continue
            end
            throw(SystemError("read", Int(errno)))
        end
    finally
        _fd_read_unlock!(fd)
    end
end

"""
Write all bytes from `p` and return the number of bytes written.

Unlike `read!`, a successful return means the full buffer was written. In
non-blocking mode this loops on `EAGAIN` by waiting for write readiness and
then resuming from the first unwritten byte.
"""
function write!(fd::FD, p::AbstractVector{UInt8})::Int
    data = if p isa StridedVector{UInt8} && stride(p, 1) == 1
        p
    else
        Vector{UInt8}(p)
    end
    GC.@preserve data begin
        return _write_ptr!(fd, pointer(data), length(data))
    end
end

"""
Write exactly `nbytes` from a `Memory{UInt8}` buffer and return the byte count.

This follows the same blocking/retry behavior as `write!(fd, ::Vector{UInt8})`
and only returns successfully once all requested bytes have been accepted.
"""
function write!(fd::FD, p::Memory{UInt8}, nbytes::Integer)::Int
    n = Int(nbytes)
    n < 0 && throw(ArgumentError("nbytes must be >= 0"))
    n <= length(p) || throw(ArgumentError("nbytes exceeds buffer length"))
    GC.@preserve p begin
        return _write_ptr!(fd, pointer(p), n)
    end
end

function _write_ptr!(fd::FD, p::Ptr{UInt8}, nbytes::Int)::Int
    _fd_write_lock!(fd)
    nn = 0
    try
        prepare_write!(fd.pd, fd.is_file)
        while true
            nn == nbytes && return nn
            n = SocketOps.write_once!(fd.sysfd, p + nn, Csize_t(nbytes - nn))
            if n > 0
                nn += Int(n)
                continue
            end
            n == 0 && throw(EOFError())
            errno = SocketOps.last_error()
            if errno == Int32(Base.Libc.EAGAIN) && pollable(fd.pd)
                wait_write!(fd.pd, fd.is_file)
                continue
            end
            throw(SystemError("write", Int(errno)))
        end
    finally
        _fd_write_unlock!(fd)
    end
end

end
