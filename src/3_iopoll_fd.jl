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
Register an `FD` with the runtime poller.

Returns `nothing`.

Throws `SystemError` if event loop registration fails.
"""
function register!(fd::FD)
    pd = fd.pd
    lock(pd.lock)
    try
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
    finally
        unlock(pd.lock)
    end
    return nothing
end

"""
Tear down polling state for a descriptor and deregister from `EventLoops`.

Returns `nothing`.
"""
function Base.close(pd::PollState)
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
function prepareread(pd::PollState, is_file::Bool = false)
    _convert_poll_error!(_check_error(pd, PollOp.READ), is_file)
    return nothing
end

"""
Validate write path state before issuing a write syscall.

Returns `nothing`.
"""
function preparewrite(pd::PollState, is_file::Bool = false)
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
function waitread(pd::PollState, is_file::Bool = false)
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
function waitwrite(pd::PollState, is_file::Bool = false)
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

Unlike `waitread`/`waitwrite`, this helper intentionally does not translate
the wakeup into exceptions; callers use it when they need a best-effort park
that can be interrupted by close/cancel machinery.
"""
function waitcancelled(pd::PollState, mode::PollOp.T)
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
    close(fd.pd)
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
function Base.close(fd::FD)
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
        preparewrite(fd.pd, fd.is_file)
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
        prepareread(fd.pd, fd.is_file)
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
                waitread(fd.pd, fd.is_file)
                continue
            end
            _is_accept_retry_errno(errno) && continue
            throw(SystemError("accept", Int(errno)))
        end
    finally
        _fd_read_unlock!(fd)
    end
    return nothing
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
        prepareread(fd.pd, fd.is_file)
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
                waitread(fd.pd, fd.is_file)
                continue
            end
            throw(SystemError("read", Int(errno)))
        end
    finally
        _fd_read_unlock!(fd)
    end
    return nothing
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
Write exactly `nbytes` from a contiguous byte buffer and return the byte count.

This follows the same blocking/retry behavior as `write!(fd, ::Vector{UInt8})`
and only returns successfully once all requested bytes have been accepted.
"""
function write!(fd::FD, p::ByteMemory, nbytes::Integer)::Int
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
        preparewrite(fd.pd, fd.is_file)
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
                waitwrite(fd.pd, fd.is_file)
                continue
            end
            throw(SystemError("write", Int(errno)))
        end
    finally
        _fd_write_unlock!(fd)
    end
end
