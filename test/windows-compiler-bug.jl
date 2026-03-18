using Test

module Reseau

export TCP, TLS

module IOPoll

export DeadlineExceededError, FD, TimerState, schedule_timer!, waittimer, _close_timer!, sleep, read!, _read_ptr_some!

struct DeadlineExceededError <: Exception end
struct NoDeadlineError <: Exception end
struct NetClosingError <: Exception end
struct FileClosingError <: Exception end
struct NotPollableError <: Exception end

const _MUTEX_CLOSED = UInt64(1) << 0
const _MUTEX_RLOCK = UInt64(1) << 1
const _MUTEX_WLOCK = UInt64(1) << 2
const _MUTEX_REF = UInt64(1) << 3
const _MUTEX_REF_MASK = (UInt64(1) << 20 - UInt64(1)) << 3
const _MUTEX_RWAIT = UInt64(1) << 23
const _MUTEX_RMASK = (UInt64(1) << 20 - UInt64(1)) << 23
const _MUTEX_WWAIT = UInt64(1) << 43
const _MUTEX_WMASK = (UInt64(1) << 20 - UInt64(1)) << 43

@inline function _closing_error(is_file::Bool)::Exception
    is_file && return FileClosingError()
    return NetClosingError()
end

module PollMode
Base.@enum T::UInt8 begin
    READ = 0x01
    WRITE = 0x02
    READWRITE = 0x03
end
end

module IocpOpKind
Base.@enum T::UInt8 begin
    PROBE_READ = 0x01
    PROBE_WRITE = 0x02
    CONNECT = 0x03
    ACCEPT = 0x04
end
end

module PollWaiterState
Base.@enum T::UInt8 begin
    EMPTY = 0x00
    WAITING = 0x01
    NOTIFIED = 0x02
end
end

module PollWakeReason
Base.@enum T::UInt8 begin
    READY = 0x01
    CANCELED = 0x02
end
end

mutable struct PollWaiter
    @atomic state::PollWaiterState.T
    @atomic reason::PollWakeReason.T
    task::Union{Nothing, Task}
    function PollWaiter()
        return new(PollWaiterState.EMPTY, PollWakeReason.READY, nothing)
    end
end

mutable struct PollState
    lock::ReentrantLock
    sysfd::Int32
    token::UInt64
    @atomic pollable::Bool
    @atomic closing::Bool
    @atomic event_err::Bool
    @atomic rd_ns::Int64
    @atomic wd_ns::Int64
    @atomic rseq::UInt64
    @atomic wseq::UInt64
    function PollState(sysfd::Integer = -1, token::UInt64 = UInt64(0))
        return new(
            ReentrantLock(),
            Int32(sysfd),
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

mutable struct Registration
    fd::Int32
    token::UInt64
    mode::PollMode.T
    read_waiter::PollWaiter
    write_waiter::PollWaiter
    @atomic event_err::Bool
    pollstate::PollState
end

function Registration(
        fd::Int32,
        token::UInt64,
        mode::PollMode.T,
        read_waiter::PollWaiter,
        write_waiter::PollWaiter,
        event_err::Bool,
    )
    return Registration(fd, token, mode, read_waiter, write_waiter, event_err, PollState(fd, token))
end

struct Overlapped end

const _ZERO_OVERLAPPED = Overlapped()
const _SIO_GET_EXTENSION_FUNCTION_POINTER = UInt32(0xC8000006)
const _CONNECTEX_LOCK = ReentrantLock()
const _CONNECTEX_PTR = Ref{Ptr{Cvoid}}(C_NULL)

struct Guid
    data1::UInt32
    data2::UInt16
    data3::UInt16
    data4::NTuple{8, UInt8}
end

const _WSAID_CONNECTEX = Guid(
    0x25a207b9,
    0xddf3,
    0x4660,
    (UInt8(0x8e), UInt8(0xe9), UInt8(0x76), UInt8(0xe5), UInt8(0x8c), UInt8(0x74), UInt8(0x06), UInt8(0x3e)),
)

mutable struct IocpConnectRequest
    addrbuf::Vector{UInt8}
    addrlen::Int32
end

const IocpRequest = Union{Nothing, IocpConnectRequest}

mutable struct IocpOp
    storage::Base.RefValue{Overlapped}
    mode::PollMode.T
    token::UInt64
    kind::IocpOpKind.T
    request::IocpRequest
    owner::Any
    @atomic active::Bool
end

mutable struct IocpRegistration
    fd::Int32
    token::UInt64
    read_op::IocpOp
    write_op::IocpOp
    wait_on_success::Bool
    @atomic closing::Bool
end

mutable struct RuntimeSema
    lock::ReentrantLock
    cond::Base.Threads.Condition
    count::Int
    function RuntimeSema()
        lock = ReentrantLock()
        return new(lock, Base.Threads.Condition(lock), 0)
    end
end

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

mutable struct FDLock
    @atomic state::UInt64
    const rsema::RuntimeSema
    const wsema::RuntimeSema
    function FDLock()
        return new(UInt64(0), RuntimeSema(), RuntimeSema())
    end
end

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
        while (wake & _MUTEX_RMASK) != 0
            wake -= _MUTEX_RWAIT
            _runtime_sema_release!(mu.rsema)
        end
        while (wake & _MUTEX_WMASK) != 0
            wake -= _MUTEX_WWAIT
            _runtime_sema_release!(mu.wsema)
        end
        return true
    end
end

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

mutable struct FD
    fdlock::FDLock
    sysfd::Int32
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
            Int32(sysfd),
            PollState(),
            _new_binary_semaphore0(),
            false,
            is_stream,
            zero_read_is_eof,
            is_file,
        )
    end
end

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

connect!(pfd::FD, addrbuf, addrlen) = nothing
waitwrite(pd::PollState) = nothing
schedule_timer!(timer::TimerState, deadline_ns::Int64) = true
waittimer(timer::TimerState) = false
_close_timer!(timer::TimerState) = nothing
sleep(seconds::Real) = nothing
read!(pfd::FD, buf::Vector{UInt8}) = throw(EOFError())
_read_ptr_some!(pfd::FD, ptr::Ptr{UInt8}, nbytes::Int) = throw(EOFError())

const _POLL_NO_ERROR = Int32(0)
const _POLL_ERR_CLOSING = Int32(1)
const _POLL_ERR_TIMEOUT = Int32(2)
const _POLL_ERR_NOT_POLLABLE = Int32(3)
const _REGISTRATIONS = IdDict{PollState, Registration}()
const _IOCP_BY_KEY = Dict{Tuple{Int32, UInt64}, IocpRegistration}()
const _NEXT_TOKEN = Ref{UInt64}(UInt64(0))

@inline _mode_has_read(mode::PollMode.T)::Bool = mode == PollMode.READ || mode == PollMode.READWRITE
@inline _mode_has_write(mode::PollMode.T)::Bool = mode == PollMode.WRITE || mode == PollMode.READWRITE
@inline _mode_is_empty(mode::PollMode.T)::Bool = mode != PollMode.READ && mode != PollMode.WRITE && mode != PollMode.READWRITE

function schedule_deadlines!(
        pd::PollState,
        rd_ns::Int64,
        wd_ns::Int64,
        rseq::UInt64,
        wseq::UInt64,
    )
    _ = pd
    _ = rd_ns
    _ = wd_ns
    _ = rseq
    _ = wseq
    return nothing
end

@inline function _next_token!()::UInt64
    _NEXT_TOKEN[] += UInt64(1)
    return _NEXT_TOKEN[]
end

function _new_iocp_registration(fd::Int32, token::UInt64)::IocpRegistration
    read_op = IocpOp(Ref(_ZERO_OVERLAPPED), PollMode.READ, token, IocpOpKind.PROBE_READ, nothing, nothing, false)
    write_op = IocpOp(Ref(_ZERO_OVERLAPPED), PollMode.WRITE, token, IocpOpKind.PROBE_WRITE, nothing, nothing, false)
    reg = IocpRegistration(fd, token, read_op, write_op, true, false)
    read_op.owner = reg
    write_op.owner = reg
    return reg
end

@inline function _map_overlapped_errno(err::Int32)::Int32
    err == Int32(0) && return Int32(0)
    err == Int32(Base.Libc.EINPROGRESS) && return Int32(Base.Libc.EINPROGRESS)
    err == Int32(Base.Libc.EAGAIN) && return Int32(Base.Libc.EAGAIN)
    err == Int32(Base.Libc.EALREADY) && return Int32(Base.Libc.EALREADY)
    err == Int32(Base.Libc.EADDRNOTAVAIL) && return Int32(Base.Libc.EADDRNOTAVAIL)
    err == Int32(Base.Libc.ENETUNREACH) && return Int32(Base.Libc.ENETUNREACH)
    err == Int32(Base.Libc.ECONNABORTED) && return Int32(Base.Libc.ECONNABORTED)
    err == Int32(Base.Libc.ECONNRESET) && return Int32(Base.Libc.ECONNRESET)
    err == Int32(Base.Libc.EISCONN) && return Int32(Base.Libc.EISCONN)
    err == Int32(Base.Libc.ENOTCONN) && return Int32(Base.Libc.ENOTCONN)
    err == Int32(Base.Libc.ETIMEDOUT) && return Int32(Base.Libc.ETIMEDOUT)
    err == Int32(Base.Libc.ECONNREFUSED) && return Int32(Base.Libc.ECONNREFUSED)
    err == Int32(Base.Libc.EHOSTUNREACH) && return Int32(Base.Libc.EHOSTUNREACH)
    return Int32(Base.Libc.EIO)
end

@inline function _set_probe_kind!(op::IocpOp)
    op.kind = op.mode == PollMode.READ ? IocpOpKind.PROBE_READ : IocpOpKind.PROBE_WRITE
    op.request = nothing
    return nothing
end

function _load_connectex_ptr(fd::Int32)::Ptr{Cvoid}
    ptr = _CONNECTEX_PTR[]
    ptr != C_NULL && return ptr
    lock(_CONNECTEX_LOCK)
    try
        ptr = _CONNECTEX_PTR[]
        ptr != C_NULL && return ptr
        guid_ref = Ref(_WSAID_CONNECTEX)
        out_ref = Ref{Ptr{Cvoid}}(C_NULL)
        bytes_ref = Ref{UInt32}(UInt32(0))
        _ = fd
        _ = guid_ref
        _ = out_ref
        _ = bytes_ref
        _CONNECTEX_PTR[] = out_ref[]
        return out_ref[]
    finally
        unlock(_CONNECTEX_LOCK)
    end
end

@inline function _wsagetoverlappedresult(fd::Int32, op::IocpOp)::Int32
    bytes_ref = Ref{UInt32}(UInt32(0))
    flags_ref = Ref{UInt32}(UInt32(0))
    _ = fd
    _ = op
    _ = bytes_ref
    _ = flags_ref
    return _map_overlapped_errno(Int32(0))
end

@inline function _clear_iocp_op!(op::IocpOp)
    @atomic :release op.active = false
    _set_probe_kind!(op)
    op.storage[] = _ZERO_OVERLAPPED
    return nothing
end

function _iocp_op_for_mode(reg::IocpRegistration, mode::PollMode.T)::IocpOp
    mode == PollMode.READ && return reg.read_op
    mode == PollMode.WRITE && return reg.write_op
    throw(ArgumentError("invalid IOCP mode"))
end

function _lookup_iocp_registration(registration::Registration)::Union{Nothing, IocpRegistration}
    return get(() -> nothing, _IOCP_BY_KEY, (registration.fd, registration.token))
end

function register!(
        fd::Integer;
        mode::PollMode.T = PollMode.READWRITE,
        pollstate::Union{Nothing, PollState} = nothing,
    )::Registration
    _mode_is_empty(mode) && throw(ArgumentError("register! requires READ and/or WRITE mode"))
    pd = pollstate === nothing ? PollState(fd) : pollstate::PollState
    token = _next_token!()
    registration = Registration(Int32(fd), token, mode, PollWaiter(), PollWaiter(), false)
    registration.pollstate = pd
    pd.sysfd = Int32(fd)
    pd.token = token
    _REGISTRATIONS[pd] = registration
    _IOCP_BY_KEY[(Int32(fd), token)] = _new_iocp_registration(Int32(fd), token)
    return registration
end

function register!(fd::FD)
    pd = fd.pd
    lock(pd.lock)
    try
        registration = register!(fd.sysfd; mode = PollMode.READWRITE, pollstate = pd)
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

function deregister!(pd::PollState)
    registration = pop!(_REGISTRATIONS, pd, nothing)
    registration === nothing || pop!(_IOCP_BY_KEY, (registration.fd, registration.token), nothing)
    return nothing
end

function current_registration(pd::PollState)
    return get(() -> nothing, _REGISTRATIONS, pd)
end

function _poll_registration(pd::PollState)::Registration
    reg = current_registration(pd)
    reg === nothing && throw(SystemError("iopoll wait", Int(Base.Libc.EBADF)))
    return reg
end

function _convert_poll_error!(res::Int32, is_file::Bool)
    res == _POLL_NO_ERROR && return nothing
    res == _POLL_ERR_CLOSING && throw(_closing_error(is_file))
    res == _POLL_ERR_TIMEOUT && throw(DeadlineExceededError())
    res == _POLL_ERR_NOT_POLLABLE && throw(NotPollableError())
    throw(ArgumentError("invalid poll status"))
end

function _refresh_event_err!(pd::PollState)
    (@atomic :acquire pd.pollable) || return nothing
    registration = current_registration(pd)
    registration === nothing && return nothing
    has_event_error = @atomic :acquire registration.event_err
    @atomic :release pd.event_err = has_event_error
    return nothing
end

function _check_error(pd::PollState, mode::PollMode.T)::Int32
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

preparewrite(pd::PollState, is_file::Bool = false) = nothing
function _fd_write_lock!(fd::FD)
    println("[windows-compiler-bug] enter _fd_write_lock!")
    flush(stdout)
    _fdlock_rwlock!(fd.fdlock, false, true) || throw(_closing_error(fd.is_file))
    println("[windows-compiler-bug] acquired _fd_write_lock!")
    flush(stdout)
    return nothing
end

function _fd_write_unlock!(fd::FD)
    _fdlock_rwunlock!(fd.fdlock, false) || return nothing
    return nothing
end
pollable(pd::PollState)::Bool = @atomic :acquire pd.pollable

function _wake_waiters!(pd::PollState, mode::PollMode.T)
    registration = current_registration(pd)
    registration === nothing && return nothing
    if _mode_has_read(mode)
        pollnotify!(registration.read_waiter, PollWakeReason.CANCELED)
    end
    if _mode_has_write(mode)
        pollnotify!(registration.write_waiter, PollWakeReason.CANCELED)
    end
    return nothing
end

function pollwait!(waiter::PollWaiter)::PollWakeReason.T
    task = current_task()
    task.sticky && (task.sticky = false)
    waiter.task = task
    try
        state, ok = @atomicreplace(waiter.state, PollWaiterState.EMPTY => PollWaiterState.WAITING)
        if ok
            wait()
        else
            state == PollWaiterState.NOTIFIED || throw(ArgumentError("concurrent wait on PollWaiter"))
        end
        while true
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

function pollnotify!(waiter::PollWaiter, reason::PollWakeReason.T = PollWakeReason.READY)::Bool
    state = @atomic :acquire waiter.state
    while true
        if state == PollWaiterState.NOTIFIED
            current = @atomic :acquire waiter.reason
            current == PollWakeReason.READY && return false
            @atomic :release waiter.reason = reason
            return false
        end
        state, ok = @atomicreplace(waiter.state, state => PollWaiterState.NOTIFIED)
        ok || continue
        @atomic :release waiter.reason = reason
        if state == PollWaiterState.WAITING
            task = waiter.task
            task isa Task || throw(ArgumentError("invalid PollWaiter task state"))
            schedule(task)
            return true
        end
        state == PollWaiterState.EMPTY || throw(ArgumentError("invalid PollWaiter state"))
        return false
    end
end

function arm_waiter!(registration::Registration, mode::PollMode.T)
    if mode == PollMode.WRITE
        pollnotify!(registration.write_waiter, PollWakeReason.READY)
        return nothing
    end
    pollnotify!(registration.read_waiter, PollWakeReason.READY)
    return nothing
end

function Base.close(pd::PollState)
    was_pollable = false
    lock(pd.lock)
    try
        was_pollable = @atomic :acquire pd.pollable
        @atomic :release pd.pollable = false
    finally
        unlock(pd.lock)
    end
    was_pollable && pd.sysfd >= 0 && deregister!(pd)
    return nothing
end

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
    _wake_waiters!(pd, PollMode.READWRITE)
    return nothing
end

@inline function _monotonic_ns()::Int64
    return Int64(time_ns())
end

function _set_deadline_impl!(fd::FD, deadline_ns::Integer, mode::PollMode.T)
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
        schedule_deadlines!(pd, rd_ns, wd_ns, rseq, wseq)
        if wake_read && wake_write
            _wake_waiters!(pd, PollMode.READWRITE)
        elseif wake_read
            _wake_waiters!(pd, PollMode.READ)
        elseif wake_write
            _wake_waiters!(pd, PollMode.WRITE)
        end
    finally
        _fdlock_decref!(fd.fdlock)
    end
    return nothing
end

function set_write_deadline!(fd::FD, deadline_ns::Integer)
    _set_deadline_impl!(fd, deadline_ns, PollMode.WRITE)
    return nothing
end

function set_deadline!(fd::FD, deadline_ns::Integer)
    _set_deadline_impl!(fd, deadline_ns, PollMode.READWRITE)
    return nothing
end

function set_read_deadline!(fd::FD, deadline_ns::Integer)
    _set_deadline_impl!(fd, deadline_ns, PollMode.READ)
    return nothing
end

function Base.close(fd::FD)
    _fdlock_incref_and_close!(fd.fdlock) || throw(_closing_error(fd.is_file))
    evict!(fd.pd)
    _fdlock_decref!(fd.fdlock)
    close(fd.pd)
    return nothing
end

function _iocp_submit_connect!(registration::Registration, addrbuf::Vector{UInt8}, addrlen::Int32)::Int32
    reg = _lookup_iocp_registration(registration)
    reg === nothing && return Int32(Base.Libc.EBADF)
    op = reg.write_op
    op.kind = IocpOpKind.CONNECT
    op.request = IocpConnectRequest(addrbuf, addrlen)
    errno = _submit_iocp_op!(registration, reg, op)
    errno != Int32(0) && _clear_iocp_op!(op)
    return errno
end

function _iocp_finish_connect!(registration::Registration)::Int32
    return _finish_iocp_mode!(registration, PollMode.WRITE)
end

function _iocp_cancel_mode!(registration::Registration, mode::PollMode.T)::Bool
    reg = _lookup_iocp_registration(registration)
    reg === nothing && return false
    op = _iocp_op_for_mode(reg, mode)
    active = @atomic :acquire op.active
    @atomic :release op.active = false
    return active
end

function _submit_iocp_op!(registration::Registration, reg::IocpRegistration, op::IocpOp)::Int32
    _, ok = @atomicreplace(op.active, false => true)
    ok || return Int32(Base.Libc.EALREADY)
    op.storage[] = _ZERO_OVERLAPPED
    rc = Int32(-1)
    if op.kind == IocpOpKind.PROBE_READ || op.kind == IocpOpKind.PROBE_WRITE
        rc = Int32(0)
    elseif op.kind == IocpOpKind.CONNECT
        request = op.request
        request isa IocpConnectRequest || throw(ArgumentError("missing ConnectEx request"))
        connectex_ptr = _load_connectex_ptr(reg.fd)
        _ = request.addrbuf
        _ = request.addrlen
        _ = connectex_ptr
        rc = Int32(0)
    else
        rc = Int32(Base.Libc.ENOSYS)
    end
    if op.kind == IocpOpKind.PROBE_READ || op.kind == IocpOpKind.PROBE_WRITE
        if rc == 0
            reg.wait_on_success && return Int32(0)
            @atomic :release op.active = false
            pollnotify!(
                op.mode == PollMode.READ ? registration.read_waiter : registration.write_waiter,
                PollWakeReason.READY,
            )
            return Int32(0)
        end
        @atomic :release op.active = false
        return Int32(0)
    end
    if rc == 0
        pollnotify!(registration.write_waiter, PollWakeReason.READY)
        return Int32(0)
    end
    @atomic :release op.active = false
    _clear_iocp_op!(op)
    return Int32(Base.Libc.EIO)
end

function _finish_iocp_mode!(registration::Registration, mode::PollMode.T)::Int32
    reg = _lookup_iocp_registration(registration)
    reg === nothing && return Int32(Base.Libc.EBADF)
    op = _iocp_op_for_mode(reg, mode)
    result = _wsagetoverlappedresult(registration.fd, op)
    _clear_iocp_op!(op)
    return result
end

function connect!(fd::FD, addrbuf::Vector{UInt8}, addrlen::Int32)
    println("[windows-compiler-bug] enter IOPoll.connect!")
    flush(stdout)
    _fd_write_lock!(fd)
    println("[windows-compiler-bug] after _fd_write_lock!")
    flush(stdout)
    try
        preparewrite(fd.pd, fd.is_file)
        println("[windows-compiler-bug] after preparewrite")
        flush(stdout)
        registration = _poll_registration(fd.pd)
        println("[windows-compiler-bug] after _poll_registration")
        flush(stdout)
        errno = _iocp_submit_connect!(registration, addrbuf, addrlen)
        println("[windows-compiler-bug] after _iocp_submit_connect!")
        flush(stdout)
        errno == Int32(0) || throw(SystemError("connectex", Int(errno)))
        try
            println("[windows-compiler-bug] before pollwait! write")
            flush(stdout)
            pollwait!(registration.write_waiter)
            _convert_poll_error!(_check_error(fd.pd, PollMode.WRITE), fd.is_file)
        catch err
            ex = err::Exception
            if _iocp_cancel_mode!(registration, PollMode.WRITE)
                pollwait!(registration.write_waiter)
            end
            _ = _iocp_finish_connect!(registration)
            rethrow(ex)
        end
        errno = _iocp_finish_connect!(registration)
        errno == Int32(0) || throw(SystemError("connectex", Int(errno)))
        Main.Reseau.SocketOps.update_connect_context!(fd.sysfd)
    finally
        _fd_write_unlock!(fd)
    end
    return nothing
end

end

module SocketOps

export AF_INET, AF_INET6, SOCK_STREAM, IPPROTO_TCP, TCP_NODELAY, SOL_SOCKET, SO_KEEPALIVE, SO_ERROR, SockAddrIn, SockAddrIn6, open_socket, bind_socket, connect_socket, set_nonblocking!, set_sockopt_int, get_socket_error, update_connect_context!, sockaddr_in, sockaddr_in_any, sockaddr_in6, sockaddr_in6_any, sockaddr_bytes

const SockLen = Int32
const AF_INET = Int32(2)
const AF_INET6 = Int32(23)
const SOCK_STREAM = Int32(1)
const IPPROTO_TCP = Int32(6)
const TCP_NODELAY = Int32(1)
const SOL_SOCKET = Int32(0xffff)
const SO_KEEPALIVE = Int32(0x0008)
const SO_ERROR = Int32(0x1007)
const SHUT_RD = Int32(0)
const SHUT_WR = Int32(1)

const _WS2_32 = "Ws2_32"
const _KERNEL32 = "Kernel32"
const _INVALID_SOCKET = UInt(typemax(UInt))
const _SOCKET_ERROR = Int32(-1)
const _FIONBIO_BITS = UInt32(0x8004667e)
const _FIONBIO = reinterpret(Int32, _FIONBIO_BITS)
const _WSA_FLAG_OVERLAPPED = UInt32(0x01)
const _WSA_FLAG_NO_HANDLE_INHERIT = UInt32(0x80)
const _HANDLE_FLAG_INHERIT = UInt32(0x00000001)
const _ERROR_IO_PENDING = Int32(997)
const _ERROR_OPERATION_ABORTED = Int32(995)
const _ERROR_NETNAME_DELETED = UInt32(64)
const _ERROR_INVALID_PARAMETER = UInt32(87)
const _ERROR_NOT_ENOUGH_MEMORY = UInt32(8)
const _ERROR_INVALID_HANDLE = UInt32(6)
const _ERROR_NOT_SUPPORTED = UInt32(50)
const _SO_UPDATE_CONNECT_CONTEXT = Int32(0x7010)
const _WSAEINTR = Int32(10004)
const _WSAEBADF = Int32(10009)
const _WSAEACCES = Int32(10013)
const _WSAEFAULT = Int32(10014)
const _WSAEINVAL = Int32(10022)
const _WSAEMFILE = Int32(10024)
const _WSAEWOULDBLOCK = Int32(10035)
const _WSAEINPROGRESS = Int32(10036)
const _WSAEALREADY = Int32(10037)
const _WSAENOTSOCK = Int32(10038)
const _WSAEDESTADDRREQ = Int32(10039)
const _WSAEMSGSIZE = Int32(10040)
const _WSAEPROTOTYPE = Int32(10041)
const _WSAENOPROTOOPT = Int32(10042)
const _WSAEPROTONOSUPPORT = Int32(10043)
const _WSAESOCKTNOSUPPORT = Int32(10044)
const _WSAEOPNOTSUPP = Int32(10045)
const _WSAEPFNOSUPPORT = Int32(10046)
const _WSAEAFNOSUPPORT = Int32(10047)
const _WSAEADDRINUSE = Int32(10048)
const _WSAEADDRNOTAVAIL = Int32(10049)
const _WSAENETDOWN = Int32(10050)
const _WSAENETUNREACH = Int32(10051)
const _WSAENETRESET = Int32(10052)
const _WSAECONNABORTED = Int32(10053)
const _WSAECONNRESET = Int32(10054)
const _WSAENOBUFS = Int32(10055)
const _WSAEISCONN = Int32(10056)
const _WSAENOTCONN = Int32(10057)
const _WSAESHUTDOWN = Int32(10058)
const _WSAETIMEDOUT = Int32(10060)
const _WSAECONNREFUSED = Int32(10061)
const _WSAEHOSTDOWN = Int32(10064)
const _WSAEHOSTUNREACH = Int32(10065)
const _WSADATA_DESC_ZERO = ntuple(_ -> UInt8(0), 257)
const _WSADATA_STATUS_ZERO = ntuple(_ -> UInt8(0), 129)
const _ERRNO_ESOCKTNOSUPPORT = @static isdefined(Base.Libc, :ESOCKTNOSUPPORT) ? Int32(getfield(Base.Libc, :ESOCKTNOSUPPORT)) : Int32(Base.Libc.EPROTONOSUPPORT)
const _ERRNO_ESHUTDOWN = @static isdefined(Base.Libc, :ESHUTDOWN) ? Int32(getfield(Base.Libc, :ESHUTDOWN)) : Int32(Base.Libc.ENOTCONN)
const _ERRNO_EHOSTDOWN = @static isdefined(Base.Libc, :EHOSTDOWN) ? Int32(getfield(Base.Libc, :EHOSTDOWN)) : Int32(Base.Libc.EHOSTUNREACH)
const _ERRNO_ECANCELED = @static isdefined(Base.Libc, :ECANCELED) ? Int32(getfield(Base.Libc, :ECANCELED)) : Int32(Base.Libc.EINTR)

struct SockAddrIn
    sin_family::UInt16
    sin_port::UInt16
    sin_addr::UInt32
    sin_zero::NTuple{8, UInt8}
end

struct SockAddrIn6
    sin6_family::UInt16
    sin6_port::UInt16
    sin6_flowinfo::UInt32
    sin6_addr::NTuple{16, UInt8}
    sin6_scope_id::UInt32
end

struct _WSAData
    wVersion::UInt16
    wHighVersion::UInt16
    szDescription::NTuple{257, UInt8}
    szSystemStatus::NTuple{129, UInt8}
    iMaxSockets::UInt16
    iMaxUdpDg::UInt16
    lpVendorInfo::Ptr{UInt8}
end

@inline function _hton16(v::UInt16)::UInt16
    Base.ENDIAN_BOM == 0x04030201 && return bswap(v)
    return v
end

@inline function _hton32(v::UInt32)::UInt32
    Base.ENDIAN_BOM == 0x04030201 && return bswap(v)
    return v
end

@inline function _port_u16(port::Integer)::UInt16
    (port < 0 || port > 0xffff) && throw(ArgumentError("port must be in [0, 65535]"))
    return UInt16(port)
end

@inline function _byte_u8(v::Integer)::UInt8
    (v < 0 || v > 0xff) && throw(ArgumentError("byte must be in [0, 255]"))
    return UInt8(v)
end

@inline function _ipv4_u32(ip::NTuple{4, UInt8})::UInt32
    return (UInt32(ip[1]) << 24) | (UInt32(ip[2]) << 16) | (UInt32(ip[3]) << 8) | UInt32(ip[4])
end

@inline function _socket_value(fd::Int32)::UInt
    return UInt(reinterpret(UInt32, fd))
end

@inline function _socket_handle(fd::Int32)::Ptr{Cvoid}
    return Ptr{Cvoid}(_socket_value(fd))
end

@inline function _wsa_get_last_error()::Int32
    return Int32(ccall((:WSAGetLastError, _WS2_32), Int32, ()))
end

@inline function _win_get_last_error()::UInt32
    return ccall((:GetLastError, _KERNEL32), UInt32, ())
end

@inline function _map_win32_errno(err::UInt32)::Int32
    err == _ERROR_INVALID_HANDLE && return Int32(Base.Libc.EBADF)
    err == _ERROR_INVALID_PARAMETER && return Int32(Base.Libc.EINVAL)
    err == _ERROR_NOT_ENOUGH_MEMORY && return Int32(Base.Libc.ENOMEM)
    err == _ERROR_NOT_SUPPORTED && return Int32(Base.Libc.ENOSYS)
    err == _ERROR_NETNAME_DELETED && return Int32(Base.Libc.ECONNRESET)
    return Int32(Base.Libc.EIO)
end

@inline function _map_wsa_errno(err::Int32)::Int32
    err == Int32(0) && return Int32(0)
    err == _ERROR_IO_PENDING && return Int32(Base.Libc.EINPROGRESS)
    err == _ERROR_OPERATION_ABORTED && return _ERRNO_ECANCELED
    err == _WSAEINTR && return Int32(Base.Libc.EINTR)
    err == _WSAEBADF && return Int32(Base.Libc.EBADF)
    err == _WSAEACCES && return Int32(Base.Libc.EACCES)
    err == _WSAEFAULT && return Int32(Base.Libc.EFAULT)
    err == _WSAEINVAL && return Int32(Base.Libc.EINVAL)
    err == _WSAEMFILE && return Int32(Base.Libc.EMFILE)
    err == _WSAEWOULDBLOCK && return Int32(Base.Libc.EAGAIN)
    err == _WSAEINPROGRESS && return Int32(Base.Libc.EINPROGRESS)
    err == _WSAEALREADY && return Int32(Base.Libc.EALREADY)
    err == _WSAENOTSOCK && return Int32(Base.Libc.EBADF)
    err == _WSAEDESTADDRREQ && return Int32(Base.Libc.EDESTADDRREQ)
    err == _WSAEMSGSIZE && return Int32(Base.Libc.EMSGSIZE)
    err == _WSAEPROTOTYPE && return Int32(Base.Libc.EPROTOTYPE)
    err == _WSAENOPROTOOPT && return Int32(Base.Libc.ENOPROTOOPT)
    err == _WSAEPROTONOSUPPORT && return Int32(Base.Libc.EPROTONOSUPPORT)
    err == _WSAESOCKTNOSUPPORT && return _ERRNO_ESOCKTNOSUPPORT
    err == _WSAEOPNOTSUPP && return Int32(Base.Libc.EOPNOTSUPP)
    err == _WSAEPFNOSUPPORT && return Int32(Base.Libc.EAFNOSUPPORT)
    err == _WSAEAFNOSUPPORT && return Int32(Base.Libc.EAFNOSUPPORT)
    err == _WSAEADDRINUSE && return Int32(Base.Libc.EADDRINUSE)
    err == _WSAEADDRNOTAVAIL && return Int32(Base.Libc.EADDRNOTAVAIL)
    err == _WSAENETDOWN && return Int32(Base.Libc.ENETDOWN)
    err == _WSAENETUNREACH && return Int32(Base.Libc.ENETUNREACH)
    err == _WSAENETRESET && return Int32(Base.Libc.ENETRESET)
    err == _WSAECONNABORTED && return Int32(Base.Libc.ECONNABORTED)
    err == _WSAECONNRESET && return Int32(Base.Libc.ECONNRESET)
    err == _WSAENOBUFS && return Int32(Base.Libc.ENOBUFS)
    err == _WSAEISCONN && return Int32(Base.Libc.EISCONN)
    err == _WSAENOTCONN && return Int32(Base.Libc.ENOTCONN)
    err == _WSAESHUTDOWN && return _ERRNO_ESHUTDOWN
    err == _WSAETIMEDOUT && return Int32(Base.Libc.ETIMEDOUT)
    err == _WSAECONNREFUSED && return Int32(Base.Libc.ECONNREFUSED)
    err == _WSAEHOSTDOWN && return _ERRNO_EHOSTDOWN
    err == _WSAEHOSTUNREACH && return Int32(Base.Libc.EHOSTUNREACH)
    return Int32(Base.Libc.EIO)
end

function _throw_errno(op::AbstractString, errno::Int32)
    throw(SystemError(op, Int(errno)))
end

const _winsock_lock = ReentrantLock()
const _winsock_initialized = Ref{Bool}(false)
const _winsock_init_pid = Ref{Int}(0)
const _fd_state_lock = ReentrantLock()
const _fd_nonblocking_state = Dict{Int32, Bool}()

function _set_fd_nonblocking_state!(fd::Int32, enabled::Bool)
    lock(_fd_state_lock)
    try
        _fd_nonblocking_state[fd] = enabled
    finally
        unlock(_fd_state_lock)
    end
    return nothing
end

function _clear_fd_state!(fd::Int32)
    lock(_fd_state_lock)
    try
        delete!(_fd_nonblocking_state, fd)
    finally
        unlock(_fd_state_lock)
    end
    return nothing
end

@static if Sys.iswindows()
    function ensure_winsock!()
        pid = Base.getpid()
        if _winsock_initialized[] && _winsock_init_pid[] == pid
            return nothing
        end
        lock(_winsock_lock)
        try
            if _winsock_initialized[] && _winsock_init_pid[] == pid
                return nothing
            end
            wsa_data = Ref(_WSAData(
                UInt16(0),
                UInt16(0),
                _WSADATA_DESC_ZERO,
                _WSADATA_STATUS_ZERO,
                UInt16(0),
                UInt16(0),
                C_NULL,
            ))
            rc = ccall(
                (:WSAStartup, _WS2_32),
                Int32,
                (UInt16, Ref{_WSAData}),
                UInt16(0x0202),
                wsa_data,
            )
            rc == 0 || _throw_errno("WSAStartup", _map_wsa_errno(Int32(rc)))
            _winsock_initialized[] = true
            _winsock_init_pid[] = pid
        finally
            unlock(_winsock_lock)
        end
        return nothing
    end

    function set_close_on_exec!(fd::Int32)
        ok = ccall(
            (:SetHandleInformation, _KERNEL32),
            Int32,
            (Ptr{Cvoid}, UInt32, UInt32),
            _socket_handle(fd),
            _HANDLE_FLAG_INHERIT,
            UInt32(0),
        )
        ok == 0 && _throw_errno("SetHandleInformation", _map_win32_errno(_win_get_last_error()))
        return nothing
    end

    function set_nonblocking!(fd::Int32, enabled::Bool = true)
        ensure_winsock!()
        arg = Ref{UInt32}(enabled ? UInt32(1) : UInt32(0))
        ret = ccall((:ioctlsocket, _WS2_32), Int32, (UInt, Clong, Ref{UInt32}), _socket_value(fd), Clong(_FIONBIO), arg)
        ret == 0 || _throw_errno("ioctlsocket(FIONBIO)", _map_wsa_errno(_wsa_get_last_error()))
        _set_fd_nonblocking_state!(fd, enabled)
        return nothing
    end

    function close_socket_nothrow(fd::Int32)::Int32
        _clear_fd_state!(fd)
        ret = ccall((:closesocket, _WS2_32), Int32, (UInt,), _socket_value(fd))
        ret == 0 && return Int32(0)
        errno = _map_wsa_errno(_wsa_get_last_error())
        errno == Int32(Base.Libc.EBADF) && return errno
        return Int32(0)
    end

    function open_socket(family::Int32, sotype::Int32, proto::Int32 = Int32(0))::Int32
        ensure_winsock!()
        raw_type = Int32(sotype)
        flags = UInt32(_WSA_FLAG_OVERLAPPED | _WSA_FLAG_NO_HANDLE_INHERIT)
        sock = ccall(
            (:WSASocketW, _WS2_32),
            UInt,
            (Int32, Int32, Int32, Ptr{Cvoid}, UInt32, UInt32),
            Int32(family),
            raw_type,
            Int32(proto),
            C_NULL,
            UInt32(0),
            flags,
        )
        if sock == _INVALID_SOCKET
            errno = _wsa_get_last_error()
            if errno == _WSAEINVAL
                sock = ccall(
                    (:WSASocketW, _WS2_32),
                    UInt,
                    (Int32, Int32, Int32, Ptr{Cvoid}, UInt32, UInt32),
                    Int32(family),
                    raw_type,
                    Int32(proto),
                    C_NULL,
                    UInt32(0),
                    _WSA_FLAG_OVERLAPPED,
                )
                sock == _INVALID_SOCKET && _throw_errno("socket", _map_wsa_errno(_wsa_get_last_error()))
                fd_fallback = Int32(UInt32(sock))
                try
                    set_close_on_exec!(fd_fallback)
                    set_nonblocking!(fd_fallback, true)
                catch
                    close_socket_nothrow(fd_fallback)
                    rethrow()
                end
                return fd_fallback
            end
            _throw_errno("socket", _map_wsa_errno(errno))
        end
        fd = Int32(UInt32(sock))
        try
            set_nonblocking!(fd, true)
        catch
            close_socket_nothrow(fd)
            rethrow()
        end
        return fd
    end

    function bind_socket(fd::Int32, addr::SockAddrIn)
        addr_ref = Ref(addr)
        GC.@preserve addr_ref begin
            bind_socket(fd, Base.unsafe_convert(Ptr{Cvoid}, addr_ref), SockLen(sizeof(SockAddrIn)))
        end
        return nothing
    end

    function bind_socket(fd::Int32, addr::SockAddrIn6)
        addr_ref = Ref(addr)
        GC.@preserve addr_ref begin
            bind_socket(fd, Base.unsafe_convert(Ptr{Cvoid}, addr_ref), SockLen(sizeof(SockAddrIn6)))
        end
        return nothing
    end

    function bind_socket(fd::Int32, addr::Ptr{Cvoid}, addrlen::SockLen)
        ret = ccall(
            (:bind, _WS2_32),
            Int32,
            (UInt, Ptr{Cvoid}, Int32),
            _socket_value(fd),
            addr,
            Int32(addrlen),
        )
        ret == 0 && return nothing
        _throw_errno("bind", _map_wsa_errno(_wsa_get_last_error()))
    end

    function set_sockopt_int(fd::Int32, level::Int32, optname::Int32, value::Integer)
        raw = Ref{Int32}(Int32(value))
        ret = GC.@preserve raw begin
            ccall(
                (:setsockopt, _WS2_32),
                Int32,
                (UInt, Int32, Int32, Ptr{UInt8}, Int32),
                _socket_value(fd),
                level,
                optname,
                Ptr{UInt8}(Base.unsafe_convert(Ptr{Int32}, raw)),
                Int32(sizeof(Int32)),
            )
        end
        ret == 0 && return nothing
        _throw_errno("setsockopt", _map_wsa_errno(_wsa_get_last_error()))
    end

    function get_sockopt_int(fd::Int32, level::Int32, optname::Int32)::Int32
        value = Ref{Int32}(0)
        optlen = Ref{Int32}(Int32(sizeof(Int32)))
        ret = GC.@preserve value begin
            ccall(
                (:getsockopt, _WS2_32),
                Int32,
                (UInt, Int32, Int32, Ptr{UInt8}, Ref{Int32}),
                _socket_value(fd),
                level,
                optname,
                Ptr{UInt8}(Base.unsafe_convert(Ptr{Int32}, value)),
                optlen,
            )
        end
        ret == 0 && return Int32(value[])
        _throw_errno("getsockopt", _map_wsa_errno(_wsa_get_last_error()))
    end

    function get_socket_error(fd::Int32)::Int32
        return get_sockopt_int(fd, SOL_SOCKET, SO_ERROR)
    end

    function _set_sockopt_ptr!(fd::Int32, optname::Int32, ptr::Ptr{UInt8}, optlen::Integer)
        ret = ccall(
            (:setsockopt, _WS2_32),
            Int32,
            (UInt, Int32, Int32, Ptr{UInt8}, Int32),
            _socket_value(fd),
            SOL_SOCKET,
            optname,
            ptr,
            Int32(optlen),
        )
        ret == 0 && return nothing
        _throw_errno("setsockopt", _map_wsa_errno(_wsa_get_last_error()))
    end

    function update_connect_context!(fd::Int32)
        handle_ref = Ref{UInt}(_socket_value(fd))
        GC.@preserve handle_ref begin
            _set_sockopt_ptr!(
                fd,
                _SO_UPDATE_CONNECT_CONTEXT,
                Ptr{UInt8}(Base.unsafe_convert(Ptr{UInt}, handle_ref)),
                sizeof(UInt),
            )
        end
        return nothing
    end

    function sockaddr_bytes(addr::SockAddrIn)::Vector{UInt8}
        bytes = Vector{UInt8}(undef, sizeof(SockAddrIn))
        addr_ref = Ref(addr)
        GC.@preserve addr_ref bytes begin
            unsafe_copyto!(
                pointer(bytes),
                Ptr{UInt8}(Base.unsafe_convert(Ptr{SockAddrIn}, addr_ref)),
                sizeof(SockAddrIn),
            )
        end
        return bytes
    end

    function sockaddr_bytes(addr::SockAddrIn6)::Vector{UInt8}
        bytes = Vector{UInt8}(undef, sizeof(SockAddrIn6))
        addr_ref = Ref(addr)
        GC.@preserve addr_ref bytes begin
            unsafe_copyto!(
                pointer(bytes),
                Ptr{UInt8}(Base.unsafe_convert(Ptr{SockAddrIn6}, addr_ref)),
                sizeof(SockAddrIn6),
            )
        end
        return bytes
    end
else
    open_socket(family::Int32, sotype::Int32, proto::Int32 = Int32(0)) = Int32(1)
    bind_socket(sysfd::Int32, sockaddr::Union{SockAddrIn, SockAddrIn6}) = nothing
    bind_socket(sysfd::Int32, addr::Ptr{Cvoid}, addrlen::SockLen) = nothing
    connect_socket(sysfd::Int32, sockaddr::Union{SockAddrIn, SockAddrIn6}) = Int32(0)
    set_nonblocking!(sysfd::Int32, enabled::Bool) = nothing
    set_sockopt_int(fd::Int32, level::Int32, optname::Int32, value::Integer) = nothing
    get_socket_error(fd::Int32)::Int32 = Int32(0)
    update_connect_context!(fd::Int32) = nothing

    function sockaddr_bytes(addr::SockAddrIn)::Vector{UInt8}
        bytes = Vector{UInt8}(undef, sizeof(SockAddrIn))
        GC.@preserve bytes addr unsafe_store!(Ptr{SockAddrIn}(pointer(bytes)), addr)
        return bytes
    end

    function sockaddr_bytes(addr::SockAddrIn6)::Vector{UInt8}
        bytes = Vector{UInt8}(undef, sizeof(SockAddrIn6))
        GC.@preserve bytes addr unsafe_store!(Ptr{SockAddrIn6}(pointer(bytes)), addr)
        return bytes
    end
end

shutdown_socket(fd::Int32, how::Integer) = nothing

function sockaddr_in(ip::NTuple{4, UInt8}, port::Integer)::SockAddrIn
    return SockAddrIn(
        UInt16(AF_INET),
        _hton16(_port_u16(port)),
        _hton32(_ipv4_u32(ip)),
        ntuple(_ -> UInt8(0), 8),
    )
end

function sockaddr_in(ip::NTuple{4, <:Integer}, port::Integer)::SockAddrIn
    return sockaddr_in((_byte_u8(ip[1]), _byte_u8(ip[2]), _byte_u8(ip[3]), _byte_u8(ip[4])), port)
end

function sockaddr_in_any(port::Integer)::SockAddrIn
    return sockaddr_in((UInt8(0), UInt8(0), UInt8(0), UInt8(0)), port)
end

function sockaddr_in6(
        ip::NTuple{16, UInt8},
        port::Integer;
        flowinfo::Integer = 0,
        scope_id::Integer = 0,
    )::SockAddrIn6
    return SockAddrIn6(
        UInt16(AF_INET6),
        _hton16(_port_u16(port)),
        _hton32(UInt32(flowinfo)),
        ip,
        UInt32(scope_id),
    )
end

function sockaddr_in6(
        ip::NTuple{16, <:Integer},
        port::Integer;
        flowinfo::Integer = 0,
        scope_id::Integer = 0,
    )::SockAddrIn6
    return sockaddr_in6((
            _byte_u8(ip[1]), _byte_u8(ip[2]), _byte_u8(ip[3]), _byte_u8(ip[4]),
            _byte_u8(ip[5]), _byte_u8(ip[6]), _byte_u8(ip[7]), _byte_u8(ip[8]),
            _byte_u8(ip[9]), _byte_u8(ip[10]), _byte_u8(ip[11]), _byte_u8(ip[12]),
            _byte_u8(ip[13]), _byte_u8(ip[14]), _byte_u8(ip[15]), _byte_u8(ip[16]),
        ),
        port;
        flowinfo = flowinfo,
        scope_id = scope_id,
    )
end

function sockaddr_in6_any(port::Integer; scope_id::Integer = 0)::SockAddrIn6
    return sockaddr_in6(ntuple(_ -> UInt8(0), 16), port; scope_id = scope_id)
end

@inline function sockaddr_in_ip(addr::SockAddrIn)::NTuple{4, UInt8}
    ip = _hton32(addr.sin_addr)
    return (
        UInt8((ip >> 24) & 0xff),
        UInt8((ip >> 16) & 0xff),
        UInt8((ip >> 8) & 0xff),
        UInt8(ip & 0xff),
    )
end

@inline sockaddr_in6_ip(addr::SockAddrIn6)::NTuple{16, UInt8} = addr.sin6_addr
@inline sockaddr_in6_scopeid(addr::SockAddrIn6)::UInt32 = addr.sin6_scope_id

end

module TCP

using ..IOPoll
using ..SocketOps

export connect, listen, accept, SocketAddr, SocketAddrV4, SocketAddrV6, SocketEndpoint, Conn, Listener, ConnectCanceledError, loopback_addr, any_addr, loopback_addr6, any_addr6, local_addr, remote_addr, addr, _connect_socketaddr_impl

function connect end
function listen end
function accept end

abstract type SocketAddr end

struct SocketAddrV4 <: SocketAddr
    ip::NTuple{4, UInt8}
    port::UInt16
end

struct SocketAddrV6 <: SocketAddr
    ip::NTuple{16, UInt8}
    port::UInt16
    scope_id::UInt32
end

const SocketEndpoint = Union{SocketAddrV4, SocketAddrV6}

mutable struct FD
    pfd::IOPoll.FD
    family::Int32
    sotype::Int32
    net::Symbol
    @atomic is_connected::Bool
    laddr::Union{Nothing, SocketAddr}
    raddr::Union{Nothing, SocketAddr}
end

struct Conn <: IO
    fd::FD
end

struct Listener
    fd::FD
end

struct ConnectCanceledError <: Exception end

@inline function _is_connect_pending_errno(errno::Int32)::Bool
    return errno == Int32(Base.Libc.EINPROGRESS) || errno == Int32(Base.Libc.EALREADY) || errno == Int32(Base.Libc.EINTR)
end

@inline function _is_temporary_unconnected(err::SystemError)::Bool
    return err.errnum == Int(Base.Libc.ENOTCONN) || err.errnum == Int(Base.Libc.EINVAL)
end

function _format_ipv6(ip::NTuple{16, UInt8})::String
    return join(map(x -> string(x, base = 16, pad = 2), ip), ":")
end

function loopback_addr(port::Integer)::SocketAddrV4
    return SocketAddrV4((UInt8(127), UInt8(0), UInt8(0), UInt8(1)), UInt16(port))
end

function any_addr(port::Integer)::SocketAddrV4
    return SocketAddrV4((UInt8(0), UInt8(0), UInt8(0), UInt8(0)), UInt16(port))
end

function loopback_addr6(port::Integer; scope_id::Integer = 0)::SocketAddrV6
    return SocketAddrV6((
            UInt8(0), UInt8(0), UInt8(0), UInt8(0),
            UInt8(0), UInt8(0), UInt8(0), UInt8(0),
            UInt8(0), UInt8(0), UInt8(0), UInt8(0),
            UInt8(0), UInt8(0), UInt8(0), UInt8(1),
        ),
        UInt16(port),
        UInt32(scope_id),
    )
end

function any_addr6(port::Integer; scope_id::Integer = 0)::SocketAddrV6
    return SocketAddrV6(ntuple(_ -> UInt8(0), 16), UInt16(port), UInt32(scope_id))
end

@inline _connect_canceled(::Nothing)::Bool = false
@inline _connect_canceled(::Any)::Bool = false
@inline _connect_wait_register!(::Any, ::FD) = nothing
@inline _connect_wait_unregister!(::Any, ::FD) = nothing
@inline _addr_family(::SocketAddrV4)::Int32 = SocketOps.AF_INET
@inline _addr_family(::SocketAddrV6)::Int32 = SocketOps.AF_INET6
@inline function _to_sockaddr(addr::SocketAddrV4)::SocketOps.SockAddrIn
    return SocketOps.sockaddr_in(addr.ip, Int(addr.port))
end

@inline function _to_sockaddr(addr::SocketAddrV6)::SocketOps.SockAddrIn6
    return SocketOps.sockaddr_in6(addr.ip, Int(addr.port); scope_id = Int(addr.scope_id))
end

function _new_netfd(
        sysfd::Int32;
        family::Int32 = SocketOps.AF_INET,
        sotype::Int32 = SocketOps.SOCK_STREAM,
        net::Symbol = :tcp,
        is_connected::Bool = false,
    )::FD
    return FD(IOPoll.FD(sysfd), family, sotype, net, is_connected, nothing, nothing)
end

function _finalize_connected_addrs!(fd::FD, fallback_remote::SocketAddr)
    fd.raddr = fallback_remote
    @atomic :release fd.is_connected = true
    return nothing
end

function _apply_default_tcp_opts!(fd::FD)
    try
        SocketOps.set_sockopt_int(fd.pfd.sysfd, SocketOps.IPPROTO_TCP, SocketOps.TCP_NODELAY, 1)
    catch
    end
    try
        SocketOps.set_sockopt_int(fd.pfd.sysfd, SocketOps.SOL_SOCKET, SocketOps.SO_KEEPALIVE, 1)
    catch
    end
    return nothing
end

function _wait_connect_complete!(
        fd::FD,
        remote_addr::SocketAddr,
        cancel_state = nothing,
    )
    println("[windows-compiler-bug] enter _wait_connect_complete!")
    flush(stdout)
    _connect_wait_register!(cancel_state, fd)
    try
        @static if Sys.iswindows()
            sockaddr = _to_sockaddr(remote_addr)
            addrbuf = SocketOps.sockaddr_bytes(sockaddr)
            addrlen = Int32(sizeof(typeof(sockaddr)))
            while true
                if _connect_canceled(cancel_state)
                    throw(ConnectCanceledError())
                end
                try
                    IOPoll.connect!(fd.pfd, addrbuf, addrlen)
                catch err
                    ex = err::Exception
                    if ex isa IOPoll.DeadlineExceededError && _connect_canceled(cancel_state)
                        throw(ConnectCanceledError())
                    end
                    rethrow(ex)
                end
                _finalize_connected_addrs!(fd, remote_addr)
                return nothing
            end
        end
        while true
            if _connect_canceled(cancel_state)
                throw(ConnectCanceledError())
            end
            try
                IOPoll.waitwrite(fd.pfd)
            catch err
                ex = err::Exception
                if ex isa IOPoll.DeadlineExceededError && _connect_canceled(cancel_state)
                    throw(ConnectCanceledError())
                end
                rethrow(ex)
            end
            _finalize_connected_addrs!(fd, remote_addr)
            return nothing
        end
    finally
        _connect_wait_unregister!(cancel_state, fd)
    end
end

@inline function _bind_connectex_local!(fd::FD, family::Int32)
    if family == SocketOps.AF_INET6
        SocketOps.bind_socket(fd.pfd.sysfd, SocketOps.sockaddr_in6_any(0))
        return nothing
    end
    SocketOps.bind_socket(fd.pfd.sysfd, SocketOps.sockaddr_in_any(0))
    return nothing
end

function open_tcp_fd!(; family::Int32 = SocketOps.AF_INET)::FD
    sysfd = SocketOps.open_socket(family, SocketOps.SOCK_STREAM)
    return _new_netfd(sysfd; family = family, sotype = SocketOps.SOCK_STREAM, net = :tcp, is_connected = false)
end

function _connect_socketaddr_impl(
        remote_addr::SocketAddr,
        local_addr::Union{Nothing, SocketAddr},
        attempt_deadline::Int64,
        state,
    )::Conn
    println("[windows-compiler-bug] enter _connect_socketaddr_impl")
    flush(stdout)
    family = _addr_family(remote_addr)
    println("[windows-compiler-bug] computed family")
    flush(stdout)
    if local_addr !== nothing && _addr_family(local_addr) != family
        throw(ArgumentError("local and remote address families must match"))
    end
    println("[windows-compiler-bug] local family check done")
    flush(stdout)
    fd = open_tcp_fd!(; family = family)
    println("[windows-compiler-bug] opened tcp fd")
    flush(stdout)
    try
        if local_addr !== nothing
            SocketOps.bind_socket(fd.pfd.sysfd, _to_sockaddr(local_addr))
        elseif Sys.iswindows()
            _bind_connectex_local!(fd, family)
        end
        println("[windows-compiler-bug] local bind step done")
        flush(stdout)
        SocketOps.set_nonblocking!(fd.pfd.sysfd, true)
        println("[windows-compiler-bug] set nonblocking")
        flush(stdout)
        @static if Sys.iswindows()
            IOPoll.register!(fd.pfd)
            println("[windows-compiler-bug] registered with iopoll")
            flush(stdout)
            if attempt_deadline != 0
                IOPoll.set_write_deadline!(fd.pfd, attempt_deadline)
                println("[windows-compiler-bug] set write deadline")
                flush(stdout)
            end
            try
                println("[windows-compiler-bug] before _wait_connect_complete!")
                flush(stdout)
                _wait_connect_complete!(fd, remote_addr, state)
            finally
                if attempt_deadline != 0
                    try
                        IOPoll.set_write_deadline!(fd.pfd, Int64(0))
                    catch
                    end
                end
            end
            _apply_default_tcp_opts!(fd)
            return Conn(fd)
        end
        IOPoll.register!(fd.pfd)
        _wait_connect_complete!(fd, remote_addr, state)
        _apply_default_tcp_opts!(fd)
        return Conn(fd)
    catch
        close(fd)
        rethrow()
    end
end

function connect(remote_addr::SocketAddr)::Conn
    return _connect_socketaddr_impl(remote_addr, nothing, Int64(0), nothing)
end

function connect(remote_addr::SocketAddr, local_addr::Union{Nothing, SocketAddr})::Conn
    return _connect_socketaddr_impl(remote_addr, local_addr, Int64(0), nothing)
end

@inline function _read_some!(conn::Conn, buf::Vector{UInt8})::Int
    return IOPoll.read!(conn.fd.pfd, buf)
end

@inline function _read_some!(conn::Conn, ptr::Ptr{UInt8}, nbytes::Int)::Int
    return IOPoll._read_ptr_some!(conn.fd.pfd, ptr, nbytes)
end

function _grow_readbytes_target!(buf::Vector{UInt8}, current::Int, nb::Int)::Int
    newlen = if current == 0
        min(nb, 1024)
    else
        min(nb, current * 2)
    end
    resize!(buf, newlen)
    return newlen
end

function Base.unsafe_read(conn::Conn, ptr::Ptr{UInt8}, nbytes::UInt)
    remaining = Int(nbytes)
    offset = 0
    while remaining > 0
        n = _read_some!(conn, ptr + offset, remaining)
        offset += n
        remaining -= n
    end
    return nothing
end

function Base.read!(conn::Conn, buf::Vector{UInt8})
    GC.@preserve buf Base.unsafe_read(conn, pointer(buf), UInt(length(buf)))
    return buf
end

function Base.readbytes!(conn::Conn, buf::Vector{UInt8}, nb::Integer = length(buf))::Int
    Base.require_one_based_indexing(buf)
    requested = Int(nb)
    requested < 0 && throw(ArgumentError("nb must be >= 0"))
    requested == 0 && return 0

    original_len = length(buf)
    current_len = original_len
    bytes_read = 0
    while bytes_read < requested
        if current_len == 0 || bytes_read == current_len
            current_len = _grow_readbytes_target!(buf, current_len, requested)
        end
        chunk_capacity = min(current_len - bytes_read, requested - bytes_read)
        n = try
            GC.@preserve buf _read_some!(conn, pointer(buf, bytes_read + 1), chunk_capacity)
        catch err
            ex = err::Exception
            ex isa EOFError || rethrow(ex)
            break
        end
        bytes_read += n
    end
    if current_len > original_len
        resize!(buf, bytes_read)
    end
    return bytes_read
end

function Base.readavailable(conn::Conn)::Vector{UInt8}
    buf = Vector{UInt8}(undef, Base.SZ_UNBUFFERED_IO)
    n = try
        _read_some!(conn, buf)
    catch err
        ex = err::Exception
        ex isa EOFError || rethrow(ex)
        return UInt8[]
    end
    return resize!(buf, n)
end

function Base.read(conn::Conn, ::Type{UInt8})::UInt8
    ref = Ref{UInt8}(0x00)
    Base.unsafe_read(conn, ref, 1)
    return ref[]
end

Base.eof(conn::Conn)::Bool = false
Base.isopen(conn::Conn)::Bool = true
Base.flush(::Conn) = nothing

function Base.unsafe_write(conn::Conn, ptr::Ptr{UInt8}, nbytes::UInt)
    return Int(nbytes)
end

Base.write(conn::Conn, buf::AbstractVector{UInt8}) = Base.unsafe_write(conn, pointer(buf), UInt(length(buf)))

function listen(local_addr::SocketAddr; backlog::Integer = 128, reuseaddr::Bool = true)::Listener
    _ = backlog
    _ = reuseaddr
    family = _addr_family(local_addr)
    fd = open_tcp_fd!(; family = family)
    try
        SocketOps.bind_socket(fd.pfd.sysfd, _to_sockaddr(local_addr))
        IOPoll.register!(fd.pfd)
        fd.laddr = local_addr
        return Listener(fd)
    catch
        close(fd)
        rethrow()
    end
end

function accept(listener::Listener)::Conn
    child = _new_netfd(
        Int32(2);
        family = listener.fd.family,
        sotype = listener.fd.sotype,
        net = listener.fd.net,
        is_connected = true,
    )
    child.laddr = listener.fd.laddr
    child.raddr = loopback_addr(1)
    return Conn(child)
end

function local_addr(conn::Conn)::Union{Nothing, SocketAddr}
    return conn.fd.laddr
end

function remote_addr(conn::Conn)::Union{Nothing, SocketAddr}
    return conn.fd.raddr
end

function addr(listener::Listener)::Union{Nothing, SocketAddr}
    return listener.fd.laddr
end

end

Base.close(fd::TCP.FD) = close(fd.pfd)
Base.close(conn::TCP.Conn) = close(conn.fd)
Base.close(listener::TCP.Listener) = close(listener.fd)
Base.closewrite(conn::TCP.Conn) = Main.Reseau.SocketOps.shutdown_socket(conn.fd.pfd.sysfd, Main.Reseau.SocketOps.SHUT_WR)

function closeread(conn::TCP.Conn)
    Main.Reseau.SocketOps.shutdown_socket(conn.fd.pfd.sysfd, Main.Reseau.SocketOps.SHUT_RD)
    return nothing
end

function set_deadline!(conn::TCP.Conn, deadline_ns::Integer)
    Main.Reseau.IOPoll.set_deadline!(conn.fd.pfd, deadline_ns)
    return nothing
end

function set_read_deadline!(conn::TCP.Conn, deadline_ns::Integer)
    Main.Reseau.IOPoll.set_read_deadline!(conn.fd.pfd, deadline_ns)
    return nothing
end

function set_write_deadline!(conn::TCP.Conn, deadline_ns::Integer)
    Main.Reseau.IOPoll.set_write_deadline!(conn.fd.pfd, deadline_ns)
    return nothing
end

function set_nodelay!(conn::TCP.Conn, enabled::Bool = true)
    Main.Reseau.SocketOps.set_sockopt_int(
        conn.fd.pfd.sysfd,
        Main.Reseau.SocketOps.IPPROTO_TCP,
        Main.Reseau.SocketOps.TCP_NODELAY,
        enabled ? 1 : 0,
    )
    return nothing
end

function set_keepalive!(conn::TCP.Conn, enabled::Bool = true)
    Main.Reseau.SocketOps.set_sockopt_int(
        conn.fd.pfd.sysfd,
        Main.Reseau.SocketOps.SOL_SOCKET,
        Main.Reseau.SocketOps.SO_KEEPALIVE,
        enabled ? 1 : 0,
    )
    return nothing
end

@inline function _show_endpoint(io::IO, endpoint::Union{Nothing, TCP.SocketAddr})
    if endpoint === nothing
        print(io, "?")
    elseif endpoint isa TCP.SocketAddrV4
        addr = endpoint::TCP.SocketAddrV4
        print(io, join(Int.(addr.ip), "."), ":", addr.port)
    else
        addr = endpoint::TCP.SocketAddrV6
        if addr.scope_id != 0
            print(io, "[", TCP._format_ipv6(addr.ip), "%", addr.scope_id, "]:", addr.port)
        else
            print(io, "[", TCP._format_ipv6(addr.ip), "]:", addr.port)
        end
    end
    return nothing
end

@inline _show_state(conn::TCP.Conn) = conn.fd.pfd.sysfd >= 0 ? "open" : "closed"
@inline _show_state(listener::TCP.Listener) = listener.fd.pfd.sysfd >= 0 ? "active" : "closed"

module HostResolvers

using ..IOPoll
using ..SocketOps
using ..TCP
import ..TCP: connect, listen

struct AddressError <: Exception
    err::String
    addr::String
end

struct DNSTimeoutError <: Exception
    address::String
end

struct DNSOpError <: Exception
    op::String
    net::String
    source::Union{Nothing, TCP.SocketEndpoint}
    addr::Union{Nothing, TCP.SocketEndpoint}
    err::Exception
end

struct UnknownNetworkError <: Exception
    network::String
end

abstract type AbstractResolver end

struct SystemResolver <: AbstractResolver end

mutable struct CachingResolver{R <: AbstractResolver} <: AbstractResolver
    parent::R
    ttl_ns::Int64
    stale_ttl_ns::Int64
    negative_ttl_ns::Int64
    max_hosts::Int
    lock::ReentrantLock
    entries::Dict{Tuple{String, String}, Any}
    @atomic cache_hits::Int
    @atomic stale_hits::Int
    @atomic negative_hits::Int
    @atomic misses::Int
end

struct StaticResolver <: AbstractResolver
    hosts::Dict{String, Vector{TCP.SocketEndpoint}}
    services_tcp::Dict{String, Int}
    services_udp::Dict{String, Int}
    fallback::Union{Nothing, AbstractResolver}
end

function CachingResolver(
        parent::R;
        ttl_ns::Integer = Int64(5_000_000_000),
        stale_ttl_ns::Integer = Int64(0),
        negative_ttl_ns::Integer = Int64(0),
        max_hosts::Integer = 1024,
    ) where {R <: AbstractResolver}
    ttl_ns >= 0 || throw(ArgumentError("ttl_ns must be >= 0"))
    stale_ttl_ns >= 0 || throw(ArgumentError("stale_ttl_ns must be >= 0"))
    negative_ttl_ns >= 0 || throw(ArgumentError("negative_ttl_ns must be >= 0"))
    max_hosts > 0 || throw(ArgumentError("max_hosts must be > 0"))
    return CachingResolver{R}(
        parent,
        Int64(ttl_ns),
        Int64(stale_ttl_ns),
        Int64(negative_ttl_ns),
        Int(max_hosts),
        ReentrantLock(),
        Dict{Tuple{String, String}, Any}(),
        0,
        0,
        0,
        0,
    )
end

function CachingResolver(;
        parent::AbstractResolver = SystemResolver(),
        ttl_ns::Integer = Int64(5_000_000_000),
        stale_ttl_ns::Integer = Int64(0),
        negative_ttl_ns::Integer = Int64(0),
        max_hosts::Integer = 1024,
    )
    return CachingResolver(parent; ttl_ns = ttl_ns, stale_ttl_ns = stale_ttl_ns, negative_ttl_ns = negative_ttl_ns, max_hosts = max_hosts)
end

function StaticResolver(;
        hosts::Dict{String, Vector{TCP.SocketEndpoint}} = Dict{String, Vector{TCP.SocketEndpoint}}(),
        services_tcp::Dict{String, Int} = Dict{String, Int}(),
        services_udp::Dict{String, Int} = Dict{String, Int}(),
        fallback::Union{Nothing, AbstractResolver} = nothing,
    )
    return StaticResolver(copy(hosts), copy(services_tcp), copy(services_udp), fallback)
end

mutable struct _LookupFlight
    lock::ReentrantLock
    cond::Threads.Condition
    result::Union{Nothing, Vector{TCP.SocketEndpoint}}
    err::Union{Nothing, Exception}
    @atomic done::Bool
    function _LookupFlight()
        lock = ReentrantLock()
        return new(lock, Threads.Condition(lock), nothing, nothing, false)
    end
end

mutable struct SingleflightResolver{R <: AbstractResolver} <: AbstractResolver
    parent::R
    lock::ReentrantLock
    inflight::Dict{Tuple{String, String}, _LookupFlight}
    @atomic actual_lookups::Int
    @atomic shared_hits::Int
end

function SingleflightResolver(parent::R) where {R <: AbstractResolver}
    return SingleflightResolver{R}(parent, ReentrantLock(), Dict{Tuple{String, String}, _LookupFlight}(), 0, 0)
end

mutable struct _LookupCacheEntry
    result::Union{Nothing, Vector{TCP.SocketEndpoint}}
    err::Union{Nothing, Exception}
    expires_ns::Int64
    stale_expires_ns::Int64
    last_access_ns::Int64
    refreshing::Bool
end

struct ResolverPolicy
    prefer_ipv6::Bool
    allow_ipv4::Bool
    allow_ipv6::Bool
end

function ResolverPolicy(; prefer_ipv6::Bool = false, allow_ipv4::Bool = true, allow_ipv6::Bool = true)
    (!allow_ipv4 && !allow_ipv6) && throw(ArgumentError("resolver policy must allow at least one address family"))
    return ResolverPolicy(prefer_ipv6, allow_ipv4, allow_ipv6)
end

const DEFAULT_RESOLVER = SystemResolver()
const _SERVICE_TCP = Dict{String, Int}("http" => 80, "https" => 443, "ssh" => 22)
const _SERVICE_UDP = Dict{String, Int}("domain" => 53)
const _SERVICE_LOCK = ReentrantLock()
const _SERVICES_LOADED = Ref(false)

function _load_system_services!()
    path = "/etc/services"
    isfile(path) || return nothing
    for raw in eachline(path)
        line = strip(raw)
        isempty(line) && continue
        startswith(line, '#') && continue
        hash_i = findfirst(==('#'), line)
        if hash_i !== nothing
            if hash_i == firstindex(line)
                continue
            end
            line = strip(line[firstindex(line):prevind(line, hash_i)])
            isempty(line) && continue
        end
        fields = split(line)
        length(fields) < 2 && continue
        portnet = fields[2]
        slash_i = findfirst(==('/'), portnet)
        slash_i === nothing && continue
        slash_i == firstindex(portnet) && continue
        slash_i == lastindex(portnet) && continue
        port_str = portnet[firstindex(portnet):prevind(portnet, slash_i)]
        proto = lowercase(portnet[nextind(portnet, slash_i):lastindex(portnet)])
        port = tryparse(Int, port_str)
        port === nothing && continue
        (port <= 0 || port > 65535) && continue
        table = if proto == "tcp"
            _SERVICE_TCP
        elseif proto == "udp"
            _SERVICE_UDP
        else
            nothing
        end
        table === nothing && continue
        for (idx, name) in pairs(fields)
            idx == 2 && continue
            table[lowercase(name)] = port
        end
    end
    return nothing
end

function _ensure_system_services_loaded!()
    _SERVICES_LOADED[] && return nothing
    lock(_SERVICE_LOCK)
    try
        _SERVICES_LOADED[] && return nothing
        _load_system_services!()
        _SERVICES_LOADED[] = true
    finally
        unlock(_SERVICE_LOCK)
    end
    return nothing
end

struct _AddrInfo
    ai_flags::Int32
    ai_family::Int32
    ai_socktype::Int32
    ai_protocol::Int32
    ai_addrlen::UInt32
    ai_canonname::Ptr{UInt8}
    ai_addr::Ptr{Cvoid}
    ai_next::Ptr{_AddrInfo}
end

const _AI_ALL = Int32(0x0010)
const _AI_V4MAPPED = Int32(0x0008)
const _AF_UNSPEC = Int32(0)
const _SOCK_STREAM = Int32(1)
const _HR_AF_INET = SocketOps.AF_INET
const _HR_AF_INET6 = SocketOps.AF_INET6
const _WSAHOST_NOT_FOUND = Int32(11001)
const _WSATRY_AGAIN = Int32(11002)
const _WSATYPE_NOT_FOUND = Int32(10109)
const _DNS_ERROR_RCODE_NAME_ERROR = Int32(9003)
const _DNS_INFO_NO_RECORDS = Int32(9501)

mutable struct DNSRaceState
    @atomic done::Bool
    lock::ReentrantLock
    wait_fds::Vector{IOPoll.FD}
    function DNSRaceState()
        return new(false, ReentrantLock(), IOPoll.FD[])
    end
end

@inline function TCP._connect_canceled(state::DNSRaceState)::Bool
    return @atomic :acquire state.done
end

function TCP._connect_wait_register!(state::DNSRaceState, fd::TCP.FD)
    lock(state.lock)
    try
        if @atomic :acquire state.done
            try
                IOPoll.set_write_deadline!(fd.pfd, Int64(time_ns()) - Int64(1))
            catch
            end
            return nothing
        end
        push!(state.wait_fds, fd.pfd)
    finally
        unlock(state.lock)
    end
    return nothing
end

function TCP._connect_wait_unregister!(state::DNSRaceState, fd::TCP.FD)
    lock(state.lock)
    try
        idx = findfirst(x -> x === fd.pfd, state.wait_fds)
        idx === nothing || deleteat!(state.wait_fds, idx)
    finally
        unlock(state.lock)
    end
    return nothing
end

struct HostResolver{R <: AbstractResolver}
    timeout_ns::Int64
    deadline_ns::Int64
    local_addr::Union{Nothing, TCP.SocketEndpoint}
    fallback_delay_ns::Int64
    resolver::R
    policy::ResolverPolicy
end

function HostResolver(;
        timeout_ns::Integer = Int64(0),
        deadline_ns::Integer = Int64(0),
        local_addr::Union{Nothing, TCP.SocketEndpoint} = nothing,
        fallback_delay_ns::Integer = Int64(300_000_000),
        resolver::AbstractResolver = DEFAULT_RESOLVER,
        policy::ResolverPolicy = ResolverPolicy(),
    )
    wrapped = resolver isa SingleflightResolver ? resolver : SingleflightResolver(resolver)
    return HostResolver{typeof(wrapped)}(
        Int64(timeout_ns),
        Int64(deadline_ns),
        local_addr,
        Int64(fallback_delay_ns),
        wrapped,
        policy,
    )
end

@inline function _min_nonzero(a::Int64, b::Int64)::Int64
    a == 0 && return b
    b == 0 && return a
    return min(a, b)
end

function _connect_deadline_ns(d::HostResolver)::Int64
    now = Int64(time_ns())
    timeout_deadline = d.timeout_ns == 0 ? Int64(0) : now + d.timeout_ns
    return _min_nonzero(timeout_deadline, d.deadline_ns)
end

@inline function _dual_stack_enabled(d::HostResolver)::Bool
    return d.fallback_delay_ns >= 0
end

@inline function _effective_fallback_delay_ns(d::HostResolver)::Int64
    if d.fallback_delay_ns > 0
        return d.fallback_delay_ns
    end
    return Int64(300_000_000)
end

@inline function _use_parallel_race(
        d::HostResolver,
        kind::Symbol,
        fallbacks::Vector{TCP.SocketEndpoint},
    )::Bool
    _dual_stack_enabled(d) || return false
    kind == :tcp || return false
    isempty(fallbacks) && return false
    return true
end

@inline function _is_ipv4(addr::TCP.SocketEndpoint)::Bool
    return addr isa TCP.SocketAddrV4
end

@inline function _is_ipv6(addr::TCP.SocketEndpoint)::Bool
    return addr isa TCP.SocketAddrV6
end

function _parse_ipv4_literal(host::AbstractString)::Union{Nothing, NTuple{4, UInt8}}
    parts = split(String(host), '.')
    length(parts) == 4 || return nothing
    bytes = UInt8[]
    for part in parts
        isempty(part) && return nothing
        v = tryparse(Int, part)
        v === nothing && return nothing
        (0 <= v <= 255) || return nothing
        push!(bytes, UInt8(v))
    end
    return (bytes[1], bytes[2], bytes[3], bytes[4])
end

function _parse_ipv6_literal(host::AbstractString)::Union{Nothing, NTuple{16, UInt8}}
    h = String(host)
    h == "::1" || return nothing
    return (
        UInt8(0), UInt8(0), UInt8(0), UInt8(0),
        UInt8(0), UInt8(0), UInt8(0), UInt8(0),
        UInt8(0), UInt8(0), UInt8(0), UInt8(0),
        UInt8(0), UInt8(0), UInt8(0), UInt8(1),
    )
end

function _split_host_zone(host::AbstractString)::Tuple{String, String}
    s = String(host)
    i = findlast(==('%'), s)
    i === nothing && return s, ""
    i == firstindex(s) && return s, ""
    i == lastindex(s) && throw(AddressError("invalid scoped address zone", s))
    return s[1:prevind(s, i)], s[nextind(s, i):end]
end

function _scope_id_from_zone(zone::AbstractString)::UInt32
    z = String(zone)
    isempty(z) && return UInt32(0)
    numeric = tryparse(Int, z)
    if numeric !== nothing
        (numeric < 0 || numeric > typemax(UInt32)) && throw(AddressError("invalid scope id", z))
        return UInt32(numeric)
    end
    throw(AddressError("unknown interface zone", z))
end

@inline function _utf16_ptr_string(ptr::Ptr{UInt16})::String
    ptr == C_NULL && return ""
    len = 0
    while unsafe_load(ptr, len + 1) != UInt16(0)
        len += 1
    end
    return transcode(String, unsafe_wrap(Vector{UInt16}, ptr, len))
end

@inline function _gai_error_string(code::Int32)::String
    code == _WSAHOST_NOT_FOUND && return "no such host"
    code == _DNS_ERROR_RCODE_NAME_ERROR && return "no such host"
    code == _DNS_INFO_NO_RECORDS && return "no DNS records"
    code == _WSATRY_AGAIN && return "temporary failure in name resolution"
    code == _WSATYPE_NOT_FOUND && return "unknown service"
    return "getaddrinfo error code $code"
end

function _native_getaddrinfo(hostname::AbstractString; flags::Int32 = Int32(0))::Vector{TCP.SocketEndpoint}
    SocketOps.ensure_winsock!()
    addresses = TCP.SocketEndpoint[]
    hostname_s = String(hostname)
    null_service = Ptr{UInt8}(C_NULL)
    hints = Ref{_AddrInfo}()
    hints_ptr = Base.unsafe_convert(Ptr{_AddrInfo}, hints)
    Base.Libc.memset(hints_ptr, 0, sizeof(_AddrInfo))
    hints_bytes = Ptr{UInt8}(hints_ptr)
    GC.@preserve hints begin
        unsafe_store!(Ptr{Int32}(hints_bytes + fieldoffset(_AddrInfo, 1)), flags)
        unsafe_store!(Ptr{Int32}(hints_bytes + fieldoffset(_AddrInfo, 2)), _AF_UNSPEC)
        unsafe_store!(Ptr{Int32}(hints_bytes + fieldoffset(_AddrInfo, 3)), _SOCK_STREAM)
    end
    result_ptr = Ref{Ptr{_AddrInfo}}(C_NULL)
    ret = @static if Sys.iswindows()
        @threadcall((:getaddrinfo, "Ws2_32"), Int32,
            (Cstring, Cstring, Ptr{_AddrInfo}, Ptr{Ptr{_AddrInfo}}),
            hostname_s,
            null_service,
            hints,
            result_ptr,
        )
    else
        @threadcall(:getaddrinfo, Int32,
            (Cstring, Cstring, Ptr{_AddrInfo}, Ptr{Ptr{_AddrInfo}}),
            hostname_s,
            null_service,
            hints,
            result_ptr,
        )
    end
    ret == 0 || _addr_error("lookup failed: $(_gai_error_string(ret))", hostname_s)
    try
        current = result_ptr[]
        while current != C_NULL
            ai = unsafe_load(current)
            if ai.ai_addr != C_NULL
                if ai.ai_family == _HR_AF_INET && Int(ai.ai_addrlen) >= sizeof(SocketOps.SockAddrIn)
                    sa = unsafe_load(Ptr{SocketOps.SockAddrIn}(ai.ai_addr))
                    push!(addresses, TCP.SocketAddrV4(SocketOps.sockaddr_in_ip(sa), 0))
                elseif ai.ai_family == _HR_AF_INET6 && Int(ai.ai_addrlen) >= sizeof(SocketOps.SockAddrIn6)
                    sa = unsafe_load(Ptr{SocketOps.SockAddrIn6}(ai.ai_addr))
                    push!(addresses, TCP.SocketAddrV6(
                        SocketOps.sockaddr_in6_ip(sa),
                        0;
                        scope_id = Int(SocketOps.sockaddr_in6_scopeid(sa)),
                    ))
                end
            end
            current = ai.ai_next
        end
    finally
        if result_ptr[] != C_NULL
            @static if Sys.iswindows()
                ccall((:freeaddrinfo, "Ws2_32"), Cvoid, (Ptr{_AddrInfo},), result_ptr[])
            else
                ccall(:freeaddrinfo, Cvoid, (Ptr{_AddrInfo},), result_ptr[])
            end
        end
    end
    return addresses
end

function _addr_error(err::AbstractString, addr::AbstractString)
    throw(AddressError(String(err), String(addr)))
end

function _literal_host_addr(host::AbstractString)::Union{Nothing, TCP.SocketEndpoint}
    h = String(host)
    isempty(h) && return nothing
    host_only, zone = _split_host_zone(h)
    ip4 = _parse_ipv4_literal(host_only)
    if ip4 !== nothing
        isempty(zone) || throw(AddressError("invalid scoped address", h))
        return TCP.SocketAddrV4(ip4::NTuple{4, UInt8}, 0x0000)
    end
    ip6 = _parse_ipv6_literal(host_only)
    if ip6 !== nothing
        scope_id = _scope_id_from_zone(zone)
        return TCP.SocketAddrV6(ip6::NTuple{16, UInt8}, 0x0000, scope_id)
    end
    return nothing
end

function split_host_port(hostport::AbstractString)::Tuple{String, String}
    s = String(hostport)
    i = findlast(==(':'), s)
    i === nothing && throw(AddressError("missing port in address", s))
    first_i = firstindex(s)
    last_i = lastindex(s)
    j = first_i
    k = first_i
    host = ""
    if !isempty(s) && s[first_i] == '['
        end_idx = findfirst(==(']'), s)
        end_idx === nothing && throw(AddressError("missing ']' in address", s))
        if end_idx == last_i
            throw(AddressError("missing port in address", s))
        end
        next_after_bracket = nextind(s, end_idx)
        if next_after_bracket != i
            if s[next_after_bracket] == ':'
                throw(AddressError("too many colons in address", s))
            end
            throw(AddressError("missing port in address", s))
        end
        host_start = nextind(s, first_i)
        host_end = prevind(s, end_idx)
        host = host_start <= host_end ? String(SubString(s, host_start, host_end)) : ""
        j = host_start
        k = next_after_bracket
    else
        if i != first_i
            host_end = prevind(s, i)
            host = String(SubString(s, first_i, host_end))
            findfirst(==(':'), SubString(s, first_i, host_end)) !== nothing &&
                throw(AddressError("too many colons in address", s))
        else
            host = ""
        end
    end
    findnext(==('['), s, j) !== nothing && throw(AddressError("unexpected '[' in address", s))
    findnext(==(']'), s, k) !== nothing && throw(AddressError("unexpected ']' in address", s))
    if i == last_i
        return host, ""
    end
    port_start = nextind(s, i)
    port = String(SubString(s, port_start, last_i))
    return host, port
end

function join_host_port(host::AbstractString, port::AbstractString)::String
    host_s = String(host)
    port_s = String(port)
    if occursin(':', host_s)
        return "[$host_s]:$port_s"
    end
    return "$host_s:$port_s"
end

function join_host_port(host::AbstractString, port::Integer)::String
    return join_host_port(host, string(port))
end

function lookup_port(resolver::AbstractResolver, network::AbstractString, service::AbstractString)::Int
    _ = resolver
    return lookup_port(DEFAULT_RESOLVER, network, service)
end

function lookup_port(network::AbstractString, service::AbstractString)::Int
    return lookup_port(DEFAULT_RESOLVER, network, service)
end

lookup_port(resolver::SingleflightResolver, network::AbstractString, service::AbstractString)::Int =
    lookup_port((resolver::SingleflightResolver).parent, network, service)

lookup_port(resolver::CachingResolver, network::AbstractString, service::AbstractString)::Int =
    lookup_port((resolver::CachingResolver).parent, network, service)

function _parse_port_table(table::Dict{String, Int}, network::AbstractString, service::AbstractString)::Int
    port = get(() -> nothing, table, lowercase(String(service)))
    port === nothing && throw(AddressError("unknown port", string(network, "/", service)))
    return port::Int
end

function parse_port(service::AbstractString)::Tuple{Int, Bool}
    isempty(service) && return 0, false
    s = String(service)
    neg = false
    if startswith(s, '+')
        s = s[2:end]
    elseif startswith(s, '-')
        neg = true
        s = s[2:end]
    end
    isempty(s) && return 0, false
    max_val = typemax(UInt32)
    cutoff = UInt32(1 << 30)
    n = UInt32(0)
    for ch in s
        ('0' <= ch <= '9') || return 0, true
        d = UInt32(ch - '0')
        if n >= cutoff
            n = max_val
            break
        end
        n *= UInt32(10)
        nn = n + d
        if nn < n || nn > max_val
            n = max_val
            break
        end
        n = nn
    end
    port = if !neg && n >= cutoff
        Int(cutoff - UInt32(1))
    elseif neg && n > cutoff
        Int(cutoff)
    else
        Int(n)
    end
    neg && (port = -port)
    return port, false
end

function lookup_port(::SystemResolver, network::AbstractString, service::AbstractString)::Int
    port, needs_lookup = parse_port(service)
    if needs_lookup
        _ensure_system_services_loaded!()
        n = String(network)
        if n == "ip" || isempty(n)
            try
                port = _parse_port_table(_SERVICE_TCP, "ip", service)
            catch
                port = _parse_port_table(_SERVICE_UDP, "ip", service)
            end
        elseif n == "tcp" || n == "tcp4" || n == "tcp6"
            port = _parse_port_table(_SERVICE_TCP, n, service)
        elseif n == "udp" || n == "udp4" || n == "udp6"
            port = _parse_port_table(_SERVICE_UDP, n, service)
        else
            _addr_error("unknown network", n)
        end
    end
    (port < 0 || port > 65535) && _addr_error("invalid port", service)
    return port
end

function lookup_port(resolver::StaticResolver, network::AbstractString, service::AbstractString)::Int
    port, needs_lookup = parse_port(service)
    if needs_lookup
        n = String(network)
        if n == "tcp" || n == "tcp4" || n == "tcp6" || n == "" || n == "ip"
            p = get(() -> nothing, resolver.services_tcp, lowercase(String(service)))
            if p !== nothing
                port = p::Int
            elseif resolver.fallback !== nothing
                return lookup_port(resolver.fallback::AbstractResolver, network, service)
            else
                port = _parse_port_table(_SERVICE_TCP, n, service)
            end
        elseif n == "udp" || n == "udp4" || n == "udp6"
            p = get(() -> nothing, resolver.services_udp, lowercase(String(service)))
            if p !== nothing
                port = p::Int
            elseif resolver.fallback !== nothing
                return lookup_port(resolver.fallback::AbstractResolver, network, service)
            else
                port = _parse_port_table(_SERVICE_UDP, n, service)
            end
        else
            _addr_error("unknown network", n)
        end
    end
    (port < 0 || port > 65535) && _addr_error("invalid port", service)
    return port
end

function _with_port(addr::TCP.SocketAddrV4, port::Int)::TCP.SocketAddrV4
    return TCP.SocketAddrV4(addr.ip, UInt16(port))
end

function _with_port(addr::TCP.SocketAddrV6, port::Int)::TCP.SocketAddrV6
    return TCP.SocketAddrV6(addr.ip, UInt16(port), addr.scope_id)
end

function _resolve_system_host(host::AbstractString)::Vector{TCP.SocketEndpoint}
    h = String(host)
    literal = _literal_host_addr(h)
    literal === nothing || return TCP.SocketEndpoint[literal]
    flags = _AI_ALL | _AI_V4MAPPED
    ips = _native_getaddrinfo(h; flags = flags)
    out = TCP.SocketEndpoint[]
    seen4 = Set{NTuple{4, UInt8}}()
    seen6 = Set{Tuple{NTuple{16, UInt8}, UInt32}}()
    for endpoint in ips
        if endpoint isa TCP.SocketAddrV4
            ip4 = (endpoint::TCP.SocketAddrV4).ip
            in(ip4, seen4) && continue
            push!(seen4, ip4)
            push!(out, endpoint::TCP.SocketAddrV4)
            continue
        end
        endpoint isa TCP.SocketAddrV6 || continue
        v6 = endpoint::TCP.SocketAddrV6
        key = (v6.ip, v6.scope_id)
        in(key, seen6) && continue
        push!(seen6, key)
        push!(out, v6)
    end
    return out
end

function _resolve_static_host(resolver::StaticResolver, host::AbstractString)::Vector{TCP.SocketEndpoint}
    return _resolve_static_host(resolver, "tcp", host)
end

function _resolve_static_host(
        resolver::StaticResolver,
        network::AbstractString,
        host::AbstractString,
    )::Vector{TCP.SocketEndpoint}
    h = String(host)
    literal = _literal_host_addr(h)
    literal === nothing || return TCP.SocketEndpoint[literal]
    mapped = get(() -> nothing, resolver.hosts, lowercase(h))
    mapped === nothing || return copy(mapped::Vector{TCP.SocketEndpoint})
    resolver.fallback === nothing && _addr_error("no suitable address", h)
    return _resolve_host_ips(resolver.fallback::AbstractResolver, network, h)
end

@inline function _normalize_lookup_host(host::AbstractString)::String
    normalized = lowercase(String(host))
    while !isempty(normalized) && last(normalized) == '.'
        normalized = normalized[1:prevind(normalized, lastindex(normalized))]
    end
    return normalized
end

@inline function _lookup_key(network::AbstractString, host::AbstractString)::Tuple{String, String}
    return lowercase(String(network)), _normalize_lookup_host(host)
end

function _resolve_singleflight_host(
        resolver::SingleflightResolver,
        network::AbstractString,
        host::AbstractString,
    )::Vector{TCP.SocketEndpoint}
    h = String(host)
    literal = _literal_host_addr(h)
    literal === nothing || return TCP.SocketEndpoint[literal]
    key = _lookup_key(network, h)
    flight = nothing
    leader = false
    lock(resolver.lock)
    try
        existing = get(() -> nothing, resolver.inflight, key)
        if existing === nothing
            flight = _LookupFlight()
            resolver.inflight[key] = flight::_LookupFlight
            @atomic :acquire_release resolver.actual_lookups += 1
            leader = true
        else
            flight = existing::_LookupFlight
            @atomic :acquire_release resolver.shared_hits += 1
        end
    finally
        unlock(resolver.lock)
    end
    if leader
        result = nothing
        err = nothing
        try
            result = _resolve_host_ips(resolver.parent, network, h)
        catch ex
            err = ex::Exception
        end
        lock((flight::_LookupFlight).lock)
        try
            flight.result = result === nothing ? nothing : copy(result::Vector{TCP.SocketEndpoint})
            flight.err = err
            @atomic :release flight.done = true
            notify(flight.cond; all = true)
        finally
            unlock(flight.lock)
        end
        lock(resolver.lock)
        try
            current = get(() -> nothing, resolver.inflight, key)
            current === flight && delete!(resolver.inflight, key)
        finally
            unlock(resolver.lock)
        end
        err === nothing || throw(err::Exception)
        return result::Vector{TCP.SocketEndpoint}
    end
    lock((flight::_LookupFlight).lock)
    try
        while !(@atomic :acquire flight.done)
            wait(flight.cond)
        end
        flight.err === nothing || throw(flight.err::Exception)
        return copy(flight.result::Vector{TCP.SocketEndpoint})
    finally
        unlock(flight.lock)
    end
end

function _evict_cache_if_needed_locked!(resolver::CachingResolver)
    length(resolver.entries) <= resolver.max_hosts && return nothing
    oldest_key = nothing
    oldest_access = typemax(Int64)
    for (key, entry) in resolver.entries
        if entry.last_access_ns < oldest_access
            oldest_access = entry.last_access_ns
            oldest_key = key
        end
    end
    oldest_key === nothing || delete!(resolver.entries, oldest_key)
    return nothing
end

function _store_cache_entry_locked!(
        resolver::CachingResolver,
        key::Tuple{String, String},
        result::Union{Nothing, Vector{TCP.SocketEndpoint}},
        err::Union{Nothing, Exception},
        now_ns::Int64,
    )
    expires_ns = now_ns
    stale_expires_ns = now_ns
    if err === nothing
        expires_ns += resolver.ttl_ns
        stale_expires_ns = expires_ns + resolver.stale_ttl_ns
    else
        expires_ns += resolver.negative_ttl_ns
        stale_expires_ns = expires_ns
    end
    resolver.entries[key] = _LookupCacheEntry(
        result === nothing ? nothing : copy(result::Vector{TCP.SocketEndpoint}),
        err,
        expires_ns,
        stale_expires_ns,
        now_ns,
        false,
    )
    _evict_cache_if_needed_locked!(resolver)
    return nothing
end

function _refresh_cached_host!(
        resolver::CachingResolver,
        key::Tuple{String, String},
        network::String,
        host::String,
    )
    result = nothing
    err = nothing
    try
        result = _resolve_host_ips(resolver.parent, network, host)
    catch ex
        err = ex::Exception
    end
    now_ns = Int64(time_ns())
    lock(resolver.lock)
    try
        entry = get(() -> nothing, resolver.entries, key)
        entry === nothing && return nothing
        if err === nothing
            _store_cache_entry_locked!(resolver, key, result::Vector{TCP.SocketEndpoint}, nothing, now_ns)
            return nothing
        end
        entry.refreshing = false
        if err isa AddressError && resolver.negative_ttl_ns > 0
            _store_cache_entry_locked!(resolver, key, nothing, err, now_ns)
        end
    finally
        unlock(resolver.lock)
    end
    return nothing
end

function _resolve_cached_host(
        resolver::CachingResolver,
        network::AbstractString,
        host::AbstractString,
    )::Vector{TCP.SocketEndpoint}
    h = String(host)
    literal = _literal_host_addr(h)
    literal === nothing || return TCP.SocketEndpoint[literal]
    key = _lookup_key(network, h)
    now_ns = Int64(time_ns())
    stale_result = nothing
    refresh_needed = false
    lock(resolver.lock)
    try
        entry = get(() -> nothing, resolver.entries, key)
        if entry !== nothing
            entry.last_access_ns = now_ns
            if now_ns <= entry.expires_ns
                if entry.err === nothing
                    @atomic :acquire_release resolver.cache_hits += 1
                    return copy(entry.result::Vector{TCP.SocketEndpoint})
                end
                @atomic :acquire_release resolver.negative_hits += 1
                throw(entry.err::Exception)
            end
            if entry.err === nothing && now_ns <= entry.stale_expires_ns
                @atomic :acquire_release resolver.stale_hits += 1
                stale_result = copy(entry.result::Vector{TCP.SocketEndpoint})
                if !entry.refreshing
                    entry.refreshing = true
                    refresh_needed = true
                end
            else
                delete!(resolver.entries, key)
            end
        end
        stale_result === nothing && (@atomic :acquire_release resolver.misses += 1)
    finally
        unlock(resolver.lock)
    end
    if stale_result !== nothing
        if refresh_needed
            errormonitor(Threads.@spawn _refresh_cached_host!(resolver, key, String(network), h))
        end
        return stale_result::Vector{TCP.SocketEndpoint}
    end
    result = nothing
    err = nothing
    try
        result = _resolve_host_ips(resolver.parent, network, h)
    catch ex
        err = ex::Exception
    end
    now_ns = Int64(time_ns())
    lock(resolver.lock)
    try
        if err === nothing
            _store_cache_entry_locked!(resolver, key, result::Vector{TCP.SocketEndpoint}, nothing, now_ns)
        elseif err isa AddressError && resolver.negative_ttl_ns > 0
            _store_cache_entry_locked!(resolver, key, nothing, err, now_ns)
        end
    finally
        unlock(resolver.lock)
    end
    err === nothing || throw(err::Exception)
    return result::Vector{TCP.SocketEndpoint}
end

function _resolve_host_ips(
        resolver::AbstractResolver,
        network::AbstractString,
        host::AbstractString,
    )::Vector{TCP.SocketEndpoint}
    if resolver isa SingleflightResolver
        return _resolve_singleflight_host(resolver::SingleflightResolver, network, host)
    end
    if resolver isa CachingResolver
        return _resolve_cached_host(resolver::CachingResolver, network, host)
    end
    if resolver isa SystemResolver
        return _resolve_system_host(host)
    end
    if resolver isa StaticResolver
        return _resolve_static_host(resolver::StaticResolver, network, host)
    end
    resolved = resolve_tcp_addrs(
        resolver,
        network,
        join_host_port(host, 0);
        op = :resolve,
        policy = ResolverPolicy(),
    )
    ips = TCP.SocketEndpoint[]
    for addr in resolved
        if addr isa TCP.SocketAddrV4
            v4 = addr::TCP.SocketAddrV4
            push!(ips, TCP.SocketAddrV4(v4.ip, 0))
        else
            v6 = addr::TCP.SocketAddrV6
            push!(ips, TCP.SocketAddrV6(v6.ip, 0; scope_id = Int(v6.scope_id)))
        end
    end
    return ips
end

function _resolve_host_ips(resolver::AbstractResolver, host::AbstractString)::Vector{TCP.SocketEndpoint}
    return _resolve_host_ips(resolver, "tcp", host)
end

function _apply_policy_and_network(
        ips::Vector{TCP.SocketEndpoint},
        kind::Symbol,
        policy::ResolverPolicy,
    )::Vector{TCP.SocketEndpoint}
    out = TCP.SocketEndpoint[]
    for addr in ips
        if kind == :tcp4 && !(addr isa TCP.SocketAddrV4)
            continue
        end
        if kind == :tcp6 && !(addr isa TCP.SocketAddrV6)
            continue
        end
        _policy_accepts(policy, addr) || continue
        push!(out, addr)
    end
    if policy.prefer_ipv6 && kind == :tcp
        sort!(out; by = a -> a isa TCP.SocketAddrV6 ? 0 : 1)
    end
    return out
end

@inline function _policy_accepts(policy::ResolverPolicy, addr::TCP.SocketEndpoint)::Bool
    if addr isa TCP.SocketAddrV4
        return policy.allow_ipv4
    end
    return policy.allow_ipv6
end

@inline function _wildcard_addrs(kind::Symbol, op::Symbol)::Vector{TCP.SocketEndpoint}
    if kind == :tcp && op == :listen
        return TCP.SocketEndpoint[TCP.any_addr6(0), TCP.any_addr(0)]
    end
    return TCP.SocketEndpoint[TCP.any_addr(0), TCP.any_addr6(0)]
end

function resolve_tcp_addrs(
        resolver::AbstractResolver,
        network::AbstractString,
        address::AbstractString;
        op::Symbol = :connect,
        policy::ResolverPolicy = ResolverPolicy(),
    )::Vector{TCP.SocketEndpoint}
    kind = _network_kind(network)
    addr = String(address)
    op == :connect && isempty(addr) && throw(AddressError("missing address", addr))
    host, service = split_host_port(addr)
    port = lookup_port(resolver, network, service)
    ips = if isempty(host)
        _wildcard_addrs(kind, op)
    else
        _resolve_host_ips(resolver, network, host)
    end
    filtered = _apply_policy_and_network(ips, kind, policy)
    isempty(filtered) && throw(AddressError("no suitable address", host))
    out = TCP.SocketEndpoint[]
    for ipaddr in filtered
        push!(out, _with_port(ipaddr, port))
    end
    return out
end

function resolve_tcp_addrs(network::AbstractString, address::AbstractString)::Vector{TCP.SocketEndpoint}
    return resolve_tcp_addrs(DEFAULT_RESOLVER, network, address)
end

function resolve_tcp_addr(
        resolver::AbstractResolver,
        network::AbstractString,
        address::AbstractString;
        policy::ResolverPolicy = ResolverPolicy(),
    )::TCP.SocketEndpoint
    addrs = resolve_tcp_addrs(resolver, network, address; op = :resolve, policy = policy)
    return addrs[1]
end

function resolve_tcp_addr(network::AbstractString, address::AbstractString)::TCP.SocketEndpoint
    return resolve_tcp_addr(DEFAULT_RESOLVER, network, address)
end

function _spawn_timer_task(f::F, deadline_ns::Int64) where {F}
    timer = IOPoll.TimerState(deadline_ns, Int64(0))
    IOPoll.schedule_timer!(timer, deadline_ns) || return nothing, nothing
    task = errormonitor(Threads.@spawn begin
        IOPoll.waittimer(timer) || return nothing
        f()
        return nothing
    end)
    return timer, task
end

function _close_timer_task!(
        timer::Union{Nothing, IOPoll.TimerState},
        task::Union{Nothing, Task},
    )
    timer === nothing && return nothing
    IOPoll._close_timer!(timer)
    task === nothing && return nothing
    wait(task)
    return nothing
end

function _resolve_with_deadline(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        deadline_ns::Int64,
    )::Vector{TCP.SocketEndpoint}
    deadline_ns == 0 && return resolve_tcp_addrs(d.resolver, network, address; op = :connect, policy = d.policy)
    now_ns = Int64(time_ns())
    now_ns >= deadline_ns && throw(DNSTimeoutError(String(address)))
    mtx = ReentrantLock()
    condition = Threads.Condition(mtx)
    done = Ref(false)
    timed_out = Ref(false)
    result_ref = Ref{Union{Nothing, Vector{TCP.SocketEndpoint}, Exception}}(nothing)
    timer, timer_task = _spawn_timer_task(deadline_ns) do
        lock(mtx)
        try
            done[] && return nothing
            timed_out[] = true
            done[] = true
            notify(condition)
        finally
            unlock(mtx)
        end
        return nothing
    end
    errormonitor(Threads.@spawn begin
        result = try
            resolve_tcp_addrs(d.resolver, network, address; op = :connect, policy = d.policy)
        catch err
            _as_exception(err)
        end
        lock(mtx)
        try
            done[] && return nothing
            result_ref[] = result
            done[] = true
            notify(condition)
        finally
            unlock(mtx)
        end
        return nothing
    end)
    lock(mtx)
    try
        while !done[]
            wait(condition)
        end
    finally
        unlock(mtx)
        _close_timer_task!(timer, timer_task)
    end
    timed_out[] && throw(DNSTimeoutError(String(address)))
    result = result_ref[]
    result === nothing && throw(DNSTimeoutError(String(address)))
    result isa Exception && throw(result)
    return result::Vector{TCP.SocketEndpoint}
end

function _partial_deadline_ns(now_ns::Int64, deadline_ns::Int64, addrs_remaining::Int)::Int64
    deadline_ns == 0 && return Int64(0)
    time_remaining = deadline_ns - now_ns
    time_remaining <= 0 && throw(DNSTimeoutError(""))
    timeout = time_remaining ÷ addrs_remaining
    sane_min = Int64(2_000_000_000)
    if timeout < sane_min
        timeout = time_remaining < sane_min ? time_remaining : sane_min
    end
    return now_ns + timeout
end

function _partition_addrs(addrs::Vector{TCP.SocketEndpoint})::Tuple{Vector{TCP.SocketEndpoint}, Vector{TCP.SocketEndpoint}}
    isempty(addrs) && return TCP.SocketEndpoint[], TCP.SocketEndpoint[]
    primary_is_v4 = _is_ipv4(addrs[1])
    primaries = TCP.SocketEndpoint[]
    fallbacks = TCP.SocketEndpoint[]
    for addr in addrs
        if _is_ipv4(addr) == primary_is_v4
            push!(primaries, addr)
        else
            push!(fallbacks, addr)
        end
    end
    return primaries, fallbacks
end

@inline function _prefer_ipv4_first!(addrs::Vector{TCP.SocketEndpoint}, policy::ResolverPolicy)
    _ = addrs
    _ = policy
    return nothing
end

@inline function _wrap_op_error(
        op::AbstractString,
        net::AbstractString,
        source::Union{Nothing, TCP.SocketEndpoint},
        addr::Union{Nothing, TCP.SocketEndpoint},
        err::Exception,
    )::DNSOpError
    return DNSOpError(String(op), String(net), source, addr, err)
end

@inline function _as_exception(err)::Exception
    return err::Exception
end

@inline _is_self_connect(conn::TCP.Conn)::Bool = false
@inline function _network_kind(network::AbstractString)::Symbol
    n = String(network)
    n == "tcp" && return :tcp
    n == "tcp4" && return :tcp4
    n == "tcp6" && return :tcp6
    throw(UnknownNetworkError(n))
end

function _mark_connect_done!(state::DNSRaceState)
    while true
        current = @atomic :acquire state.done
        current && return false
        _, ok = @atomicreplace(state.done, current => true)
        ok || continue
        waiters = IOPoll.FD[]
        lock(state.lock)
        try
            append!(waiters, state.wait_fds)
            empty!(state.wait_fds)
        finally
            unlock(state.lock)
        end
        for waiter in waiters
            try
                IOPoll.set_write_deadline!(waiter, Int64(time_ns()) - Int64(1))
            catch
            end
        end
        return true
    end
end

struct DNSParallelResult
    primary::Bool
    conn::Union{Nothing, TCP.Conn}
    err::Union{Nothing, Exception}
end

function _resolve_serial(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        addrs::Vector{TCP.SocketEndpoint},
        deadline_ns::Int64,
        state::DNSRaceState,
    )::Tuple{Union{Nothing, TCP.Conn}, Union{Nothing, Exception}}
    println("[windows-compiler-bug] enter _resolve_serial")
    flush(stdout)
    _ = network
    first_err::Union{Nothing, Exception} = nothing
    for (i, remote_addr) in pairs(addrs)
        if @atomic :acquire state.done
            return nothing, first_err
        end
        now_ns = Int64(time_ns())
        if deadline_ns != 0 && now_ns >= deadline_ns
            return nothing, DNSTimeoutError(String(address))
        end
        attempt_deadline = try
            _partial_deadline_ns(now_ns, deadline_ns, length(addrs) - i + 1)
        catch err
            err isa DNSTimeoutError || rethrow(err)
            return nothing, DNSTimeoutError(String(address))
        end
        try
            max_attempts = d.local_addr === nothing ? 3 : 1
            for attempt in 1:max_attempts
                if @atomic :acquire state.done
                    return nothing, first_err
                end
                try
                    println("[windows-compiler-bug] before _connect_socketaddr_impl")
                    flush(stdout)
                    conn = TCP._connect_socketaddr_impl(remote_addr, d.local_addr, attempt_deadline, state)
                    if d.local_addr === nothing && _is_self_connect(conn) && attempt < max_attempts
                        close(conn)
                        continue
                    end
                    if _mark_connect_done!(state)
                        return conn, nothing
                    end
                    close(conn)
                    return nothing, first_err
                catch err
                    ex = _as_exception(err)
                    if ex isa TCP.ConnectCanceledError && (@atomic :acquire state.done)
                        return nothing, first_err
                    end
                    if d.local_addr === nothing &&
                       ex isa SystemError &&
                       (ex::SystemError).errnum == Int(Base.Libc.EADDRNOTAVAIL) &&
                       attempt < max_attempts
                        continue
                    end
                    mapped = ex isa IOPoll.DeadlineExceededError ? DNSTimeoutError(String(address)) : ex
                    first_err === nothing && (first_err = mapped)
                    break
                end
            end
        catch err
            ex = _as_exception(err)
            first_err === nothing && (first_err = ex)
        end
    end
    first_err === nothing && (first_err = AddressError("missing address", String(address)))
    return nothing, first_err::Exception
end

function _resolve_parallel(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        primaries::Vector{TCP.SocketEndpoint},
        fallbacks::Vector{TCP.SocketEndpoint},
        deadline_ns::Int64,
    )::Tuple{Union{Nothing, TCP.Conn}, Union{Nothing, Exception}}
    state = DNSRaceState()
    events = Channel{Union{DNSParallelResult, Symbol}}(4)
    @inline function _emit_event!(event::Union{DNSParallelResult, Symbol})
        try
            put!(events, event)
        catch err
            ex = _as_exception(err)
            ex isa InvalidStateException || rethrow(err)
        end
        return nothing
    end
    function _start_racer(primary::Bool, addrs::Vector{TCP.SocketEndpoint})
        return errormonitor(Threads.@spawn begin
            conn, err = _resolve_serial(d, network, address, addrs, deadline_ns, state)
            _emit_event!(DNSParallelResult(primary, conn, err))
            return nothing
        end)
    end
    _start_racer(true, primaries)
    delay_ns = _effective_fallback_delay_ns(d)
    fallback_timer, fallback_timer_task = _spawn_timer_task(Int64(time_ns()) + delay_ns) do
        _emit_event!(:fallback_timer)
    end
    primary_done = false
    fallback_done = false
    fallback_started = false
    primary_err::Union{Nothing, Exception} = nothing
    fallback_err::Union{Nothing, Exception} = nothing
    try
        while true
            event = take!(events)
            if event === :fallback_timer
                if !fallback_started && !(@atomic :acquire state.done)
                    fallback_started = true
                    _start_racer(false, fallbacks)
                end
                continue
            end
            result = event::DNSParallelResult
            if result.conn !== nothing
                _mark_connect_done!(state)
                return result.conn, nothing
            end
            if result.primary
                primary_done = true
                if primary_err === nothing
                    primary_err = result.err
                end
                if !fallback_started && !(@atomic :acquire state.done)
                    fallback_started = true
                    _close_timer_task!(fallback_timer, fallback_timer_task)
                    _start_racer(false, fallbacks)
                end
            else
                fallback_done = true
                if fallback_err === nothing
                    fallback_err = result.err
                end
            end
            if primary_done && fallback_done
                primary_err === nothing && (primary_err = fallback_err)
                primary_err === nothing && (primary_err = AddressError("missing address", String(address)))
                _mark_connect_done!(state)
                return nothing, primary_err::Exception
            end
        end
    finally
        _close_timer_task!(fallback_timer, fallback_timer_task)
        try
            close(events)
        catch
        end
    end
end

function connect(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
    )::TCP.Conn
    println("[windows-compiler-bug] enter HostResolvers.connect")
    flush(stdout)
    deadline_ns = _connect_deadline_ns(d)
    if deadline_ns != 0 && Int64(time_ns()) >= deadline_ns
        throw(_wrap_op_error("connect", network, d.local_addr, nothing, DNSTimeoutError(String(address))))
    end
    kind = try
        _network_kind(network)
    catch err
        throw(_wrap_op_error("connect", network, d.local_addr, nothing, _as_exception(err)))
    end
    addrs = try
        _resolve_with_deadline(d, network, address, deadline_ns)
    catch err
        throw(_wrap_op_error("connect", network, d.local_addr, nothing, _as_exception(err)))
    end
    println("[windows-compiler-bug] resolved addrs")
    flush(stdout)
    if deadline_ns != 0 && Int64(time_ns()) >= deadline_ns
        throw(_wrap_op_error("connect", network, d.local_addr, nothing, DNSTimeoutError(String(address))))
    end
    _prefer_ipv4_first!(addrs, d.policy)
    primaries, fallbacks = _partition_addrs(addrs)
    conn = nothing
    err = nothing
    if _use_parallel_race(d, kind, fallbacks)
        conn, err = _resolve_parallel(d, network, address, primaries, fallbacks, deadline_ns)
    else
        state = DNSRaceState()
        conn, err = _resolve_serial(d, network, address, addrs, deadline_ns, state)
    end
    conn !== nothing && return conn
    throw(_wrap_op_error(
        "connect",
        network,
        d.local_addr,
        isempty(addrs) ? nothing : addrs[1],
        err === nothing ? AddressError("missing address", String(address)) : err::Exception,
    ))
end

function connect(
        network::AbstractString,
        address::AbstractString;
        kwargs...,
    )::TCP.Conn
    resolver = isempty(kwargs) ? HostResolver() : HostResolver(; kwargs...)
    return connect(resolver, network, address)
end

function connect(
        address::AbstractString;
        kwargs...,
    )::TCP.Conn
    return connect("tcp", address; kwargs...)
end

function listen(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString;
        backlog::Integer = 128,
        reuseaddr::Bool = true,
    )::TCP.Listener
    try
        _network_kind(network)
    catch err
        throw(_wrap_op_error("listen", network, nothing, nothing, _as_exception(err)))
    end
    addrs = try
        resolve_tcp_addrs(d.resolver, network, address; op = :listen, policy = d.policy)
    catch err
        throw(_wrap_op_error("listen", network, nothing, nothing, _as_exception(err)))
    end
    first_err::Union{Nothing, Exception} = nothing
    for local_addr in addrs
        try
            return TCP.listen(local_addr; backlog = backlog, reuseaddr = reuseaddr)
        catch err
            first_err === nothing && (first_err = _as_exception(err))
        end
    end
    throw(_wrap_op_error(
        "listen",
        network,
        nothing,
        isempty(addrs) ? nothing : addrs[1],
        first_err === nothing ? AddressError("missing address", String(address)) : first_err::Exception,
    ))
end

function listen(
        network::AbstractString,
        address::AbstractString;
        backlog::Integer = 128,
        reuseaddr::Bool = true,
    )::TCP.Listener
    return listen(HostResolver(), network, address; backlog = backlog, reuseaddr = reuseaddr)
end

end

module TLS

using ..TCP
using ..HostResolvers

const TLS1_2_VERSION = UInt16(0x0303)
const TLS1_3_VERSION = UInt16(0x0304)

module ClientAuthMode
Base.@enum T::UInt8 begin
    NoClientCert = 0
    RequestClientCert = 1
    RequireAnyClientCert = 2
    VerifyClientCertIfGiven = 3
    RequireAndVerifyClientCert = 4
end
end

struct ConfigError <: Exception
    message::String
end

struct Config
    server_name::Union{Nothing, String}
    verify_peer::Bool
    client_auth::ClientAuthMode.T
    cert_file::Union{Nothing, String}
    key_file::Union{Nothing, String}
    ca_file::Union{Nothing, String}
    client_ca_file::Union{Nothing, String}
    alpn_protocols::Vector{String}
    handshake_timeout_ns::Int64
    min_version::Union{Nothing, UInt16}
    max_version::Union{Nothing, UInt16}
end

function Config(;
        server_name::Union{Nothing, AbstractString} = nothing,
        verify_peer::Bool = true,
        client_auth::ClientAuthMode.T = ClientAuthMode.NoClientCert,
        cert_file::Union{Nothing, AbstractString} = nothing,
        key_file::Union{Nothing, AbstractString} = nothing,
        ca_file::Union{Nothing, AbstractString} = nothing,
        client_ca_file::Union{Nothing, AbstractString} = nothing,
        alpn_protocols::Vector{String} = String[],
        handshake_timeout_ns::Integer = Int64(0),
        min_version::Union{Nothing, UInt16} = TLS1_2_VERSION,
        max_version::Union{Nothing, UInt16} = nothing,
    )
    server_name_s = server_name === nothing ? nothing : String(server_name)
    cert_file_s = cert_file === nothing ? nothing : String(cert_file)
    key_file_s = key_file === nothing ? nothing : String(key_file)
    ca_file_s = ca_file === nothing ? nothing : String(ca_file)
    client_ca_file_s = client_ca_file === nothing ? nothing : String(client_ca_file)
    has_cert = cert_file_s !== nothing
    has_key = key_file_s !== nothing
    has_cert == has_key || throw(ConfigError("both `cert_file` and `key_file` must be set together"))
    handshake_timeout_ns < 0 && throw(ConfigError("handshake_timeout_ns must be >= 0"))
    return Config(
        server_name_s,
        verify_peer,
        client_auth,
        cert_file_s,
        key_file_s,
        ca_file_s,
        client_ca_file_s,
        copy(alpn_protocols),
        Int64(handshake_timeout_ns),
        min_version,
        max_version,
    )
end

struct Conn <: IO
    tcp::TCP.Conn
    config::Config
end

struct Listener
    tcp::TCP.Listener
    config::Config
end

function _connect(
        host_resolver::HostResolvers.HostResolver,
        network::AbstractString,
        address::AbstractString,
        config::Config,
    )::Conn
    tcp = HostResolvers.connect(host_resolver, network, address)
    return Conn(tcp, config)
end

function connect(
        network::AbstractString,
        address::AbstractString;
        timeout_ns::Integer = Int64(0),
        deadline_ns::Integer = Int64(0),
        local_addr::Union{Nothing, TCP.SocketEndpoint} = nothing,
        fallback_delay_ns::Integer = Int64(300_000_000),
        resolver::HostResolvers.AbstractResolver = HostResolvers.DEFAULT_RESOLVER,
        policy::HostResolvers.ResolverPolicy = HostResolvers.ResolverPolicy(),
        kw...
    )::Conn
    host_resolver = HostResolvers.HostResolver(; timeout_ns, deadline_ns, local_addr, fallback_delay_ns, resolver, policy)
    return _connect(host_resolver, network, address, Config(; kw...))
end

function connect(address::AbstractString; kwargs...)::Conn
    return connect("tcp", address; kwargs...)
end

function listen(
        network::AbstractString,
        address::AbstractString,
        config::Config;
        backlog::Integer = 128,
        reuseaddr::Bool = true,
    )::Listener
    listener = TCP.listen(network, address; backlog = backlog, reuseaddr = reuseaddr)
    return Listener(listener, config)
end

Base.isopen(conn::Conn) = true
Base.close(conn::Conn) = close(conn.tcp)
Base.close(listener::Listener) = close(listener.tcp)

end

end # module Reseau

using .Reseau: TCP, TLS

const NC = Reseau.TCP
const TL = Reseau.TLS

function _probe(f, label::AbstractString)
    println("[windows-compiler-bug] probe start: $(label)")
    try
        f()
        println("[windows-compiler-bug] probe done: $(label)")
    catch ex
        println("[windows-compiler-bug] probe error ($(label)): $(typeof(ex))")
    end
    return nothing
end

println("[windows-compiler-bug] julia threads: $(Threads.nthreads())")

@test Reseau.TCP === TCP
@test Reseau.TLS === TLS

_probe("tcp kwcall local_addr v4") do
    NC.connect("tcp", "127.0.0.1:1"; local_addr = NC.loopback_addr(0))
end

_probe("tcp kwcall local_addr v6 mismatch") do
    NC.connect("tcp", "127.0.0.1:1"; local_addr = NC.loopback_addr6(0))
end

@test true
