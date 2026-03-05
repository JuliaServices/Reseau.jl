@static if Sys.iswindows()

const _KERNEL32 = "Kernel32"
const _WS2_32 = "Ws2_32"
const _INVALID_HANDLE_VALUE = Ptr{Cvoid}(typemax(UInt))
const _INFINITE = UInt32(0xffff_ffff)
const _WAIT_TIMEOUT = UInt32(0x00000102)
const _ERROR_IO_PENDING = Int32(997)
const _ERROR_NOT_FOUND = UInt32(1168)
const _ERROR_INVALID_HANDLE = UInt32(6)
const _ERROR_INVALID_PARAMETER = UInt32(87)
const _ERROR_NOT_ENOUGH_MEMORY = UInt32(8)
const _WSAEWOULDBLOCK = Int32(10035)
const _WSAEINPROGRESS = Int32(10036)
const _WSAEALREADY = Int32(10037)
const _WSAENOTCONN = Int32(10057)
const _MAX_IOCP_EVENTS = 128
const _WAKE_KEY = typemax(UInt)

struct Overlapped
    Internal::UInt
    InternalHigh::UInt
    Offset::UInt32
    OffsetHigh::UInt32
    hEvent::Ptr{Cvoid}
end

const _ZERO_OVERLAPPED = Overlapped(UInt(0), UInt(0), UInt32(0), UInt32(0), C_NULL)

struct OverlappedEntry
    key::UInt
    overlapped::Ptr{Cvoid}
    internal::UInt
    qty::UInt32
end

struct WSABUF
    len::UInt32
    buf::Ptr{UInt8}
end

mutable struct IocpOp
    storage::Base.RefValue{Overlapped}
    mode::PollMode.T
    token::UInt64
    owner::Any
    @atomic active::Bool
end

mutable struct IocpRegistration
    fd::Cint
    token::UInt64
    read_op::IocpOp
    write_op::IocpOp
    @atomic closing::Bool
end

mutable struct IocpBackendScratch
    port::Ptr{Cvoid}
    entries::Vector{OverlappedEntry}
    by_fd::Dict{Cint, IocpRegistration}
    by_ptr::Dict{Ptr{Cvoid}, IocpOp}
    zombies::Vector{IocpRegistration}
end

@inline function _socket_value(fd::Cint)::UInt
    return UInt(reinterpret(UInt32, fd))
end

@inline function _socket_handle(fd::Cint)::Ptr{Cvoid}
    return Ptr{Cvoid}(_socket_value(fd))
end

@inline function _op_ptr(op::IocpOp)::Ptr{Cvoid}
    return Ptr{Cvoid}(Base.unsafe_convert(Ptr{Overlapped}, op.storage))
end

@inline function _win_get_last_error()::UInt32
    return ccall((:GetLastError, _KERNEL32), UInt32, ())
end

@inline function _wsa_get_last_error()::Int32
    return Int32(ccall((:WSAGetLastError, _WS2_32), Cint, ()))
end

@inline function _map_win_errno(err::UInt32)::Int32
    err == _ERROR_INVALID_HANDLE && return Int32(Base.Libc.EBADF)
    err == _ERROR_INVALID_PARAMETER && return Int32(Base.Libc.EINVAL)
    err == _ERROR_NOT_ENOUGH_MEMORY && return Int32(Base.Libc.ENOMEM)
    return Int32(Base.Libc.EIO)
end

function _new_iocp_registration(fd::Cint, token::UInt64)::IocpRegistration
    read_op = IocpOp(Ref(_ZERO_OVERLAPPED), PollMode.READ, token, nothing, false)
    write_op = IocpOp(Ref(_ZERO_OVERLAPPED), PollMode.WRITE, token, nothing, false)
    reg = IocpRegistration(fd, token, read_op, write_op, false)
    read_op.owner = reg
    write_op.owner = reg
    return reg
end

@inline function _reset_overlapped!(op::IocpOp)
    op.storage[] = _ZERO_OVERLAPPED
    return nothing
end

@inline function _registration_has_active(reg::IocpRegistration)::Bool
    return (@atomic :acquire reg.read_op.active) || (@atomic :acquire reg.write_op.active)
end

function _cleanup_registration_if_done!(scratch::IocpBackendScratch, reg::IocpRegistration)
    if !(@atomic :acquire reg.closing)
        return nothing
    end
    _registration_has_active(reg) && return nothing
    delete!(scratch.by_ptr, _op_ptr(reg.read_op))
    delete!(scratch.by_ptr, _op_ptr(reg.write_op))
    idx = findfirst(x -> x === reg, scratch.zombies)
    idx === nothing || deleteat!(scratch.zombies, idx)
    return nothing
end

function _cancel_probe!(reg::IocpRegistration, op::IocpOp)
    (@atomic :acquire op.active) || return nothing
    ok = ccall((:CancelIoEx, _KERNEL32), Int32, (Ptr{Cvoid}, Ptr{Cvoid}), _socket_handle(reg.fd), _op_ptr(op))
    if ok == 0
        err = _win_get_last_error()
        if err == _ERROR_NOT_FOUND
            @atomic :release op.active = false
        end
    end
    return nothing
end

function _submit_iocp_probe!(registration::Registration, reg::IocpRegistration, op::IocpOp)::Int32
    _, ok = @atomicreplace(op.active, false => true)
    ok || return Int32(0)
    _reset_overlapped!(op)
    wsabuf = Ref(WSABUF(UInt32(0), Ptr{UInt8}(C_NULL)))
    bytes = Ref{UInt32}(UInt32(0))
    flags = Ref{UInt32}(UInt32(0))
    rc = GC.@preserve op wsabuf bytes flags begin
        if op.mode == PollMode.READ
            @ccall gc_safe = true _WS2_32.WSARecv(
                _socket_value(reg.fd)::UInt,
                wsabuf::Ref{WSABUF},
                UInt32(1)::UInt32,
                bytes::Ref{UInt32},
                flags::Ref{UInt32},
                _op_ptr(op)::Ptr{Cvoid},
                C_NULL::Ptr{Cvoid},
            )::Cint
        else
            @ccall gc_safe = true _WS2_32.WSASend(
                _socket_value(reg.fd)::UInt,
                wsabuf::Ref{WSABUF},
                UInt32(1)::UInt32,
                bytes::Ref{UInt32},
                UInt32(0)::UInt32,
                _op_ptr(op)::Ptr{Cvoid},
                C_NULL::Ptr{Cvoid},
            )::Cint
        end
    end
    if rc == 0
        @atomic :release op.active = false
        _notify_registration!(registration, op.mode)
        return Int32(0)
    end
    err = _wsa_get_last_error()
    if err == _ERROR_IO_PENDING
        return Int32(0)
    end
    @atomic :release op.active = false
    if err == _WSAEWOULDBLOCK || err == _WSAEINPROGRESS || err == _WSAEALREADY || err == _WSAENOTCONN
        return Int32(0)
    end
    @atomic :release registration.event_err = true
    _notify_registration!(registration, op.mode)
    return Int32(0)
end

function _backend_init!(state::Poller)::Int32
    port = ccall(
        (:CreateIoCompletionPort, _KERNEL32),
        Ptr{Cvoid},
        (Ptr{Cvoid}, Ptr{Cvoid}, UInt, UInt32),
        _INVALID_HANDLE_VALUE,
        C_NULL,
        UInt(0),
        UInt32(0),
    )
    port == C_NULL && return _map_win_errno(_win_get_last_error())
    state.backend_scratch = IocpBackendScratch(
        port,
        Vector{OverlappedEntry}(undef, _MAX_IOCP_EVENTS),
        Dict{Cint, IocpRegistration}(),
        Dict{Ptr{Cvoid}, IocpOp}(),
        IocpRegistration[],
    )
    state.wake_ident = UInt(0)
    return Int32(0)
end

function _backend_close!(state::Poller)
    scratch_any = state.backend_scratch
    if scratch_any isa IocpBackendScratch
        scratch = scratch_any::IocpBackendScratch
        if scratch.port != C_NULL
            _ = ccall((:CloseHandle, _KERNEL32), Int32, (Ptr{Cvoid},), scratch.port)
        end
    end
    state.backend_scratch = nothing
    return nothing
end

function _backend_open_fd!(
        state::Poller,
        fd::Cint,
        mode::PollMode.T,
        token::UInt64,
    )::Int32
    _ = mode
    scratch_any = state.backend_scratch
    scratch_any isa IocpBackendScratch || return Int32(Base.Libc.ENOSYS)
    scratch = scratch_any::IocpBackendScratch
    associated = ccall(
        (:CreateIoCompletionPort, _KERNEL32),
        Ptr{Cvoid},
        (Ptr{Cvoid}, Ptr{Cvoid}, UInt, UInt32),
        _socket_handle(fd),
        scratch.port,
        UInt(token),
        UInt32(0),
    )
    associated == C_NULL && return _map_win_errno(_win_get_last_error())
    reg = _new_iocp_registration(fd, token)
    scratch.by_fd[fd] = reg
    scratch.by_ptr[_op_ptr(reg.read_op)] = reg.read_op
    scratch.by_ptr[_op_ptr(reg.write_op)] = reg.write_op
    return Int32(0)
end

function _backend_arm_waiter!(state::Poller, registration::Registration, mode::PollMode.T)::Int32
    scratch_any = state.backend_scratch
    scratch_any isa IocpBackendScratch || return Int32(Base.Libc.ENOSYS)
    scratch = scratch_any::IocpBackendScratch
    reg = get(scratch.by_fd, registration.fd, nothing)
    reg === nothing && return Int32(0)
    reg.token == registration.token || return Int32(0)
    _mode_has_read(mode) && _mode_has_read(registration.mode) && _submit_iocp_probe!(registration, reg, reg.read_op)
    _mode_has_write(mode) && _mode_has_write(registration.mode) && _submit_iocp_probe!(registration, reg, reg.write_op)
    return Int32(0)
end

function _backend_close_fd!(state::Poller, fd::Cint)::Int32
    scratch_any = state.backend_scratch
    scratch_any isa IocpBackendScratch || return Int32(Base.Libc.ENOSYS)
    scratch = scratch_any::IocpBackendScratch
    reg = pop!(scratch.by_fd, fd, nothing)
    reg === nothing && return Int32(0)
    @atomic :release reg.closing = true
    _cancel_probe!(reg, reg.read_op)
    _cancel_probe!(reg, reg.write_op)
    if _registration_has_active(reg)
        idx = findfirst(x -> x === reg, scratch.zombies)
        idx === nothing && push!(scratch.zombies, reg)
    else
        delete!(scratch.by_ptr, _op_ptr(reg.read_op))
        delete!(scratch.by_ptr, _op_ptr(reg.write_op))
    end
    return Int32(0)
end

function _backend_wake!(state::Poller)::Int32
    scratch_any = state.backend_scratch
    scratch_any isa IocpBackendScratch || return Int32(Base.Libc.ENOSYS)
    scratch = scratch_any::IocpBackendScratch
    _, ok = @atomicreplace(state.wak_sig, UInt32(0) => UInt32(1))
    ok || return Int32(0)
    posted = ccall(
        (:PostQueuedCompletionStatus, _KERNEL32),
        Int32,
        (Ptr{Cvoid}, UInt32, UInt, Ptr{Cvoid}),
        scratch.port,
        UInt32(0),
        _WAKE_KEY,
        C_NULL,
    )
    if posted == 0
        @atomic :release state.wak_sig = UInt32(0)
        return _map_win_errno(_win_get_last_error())
    end
    return Int32(0)
end

@inline function _iocp_timeout_ms(delay_ns::Int64)::UInt32
    if delay_ns < 0
        return _INFINITE
    end
    if delay_ns == 0
        return UInt32(0)
    end
    if delay_ns < Int64(1_000_000)
        return UInt32(1)
    end
    if delay_ns < Int64(1_000_000_000_000_000)
        return UInt32(delay_ns ÷ Int64(1_000_000))
    end
    return UInt32(1_000_000_000)
end

function _backend_poll_once!(state::Poller, delay_ns::Int64)::Int32
    scratch_any = state.backend_scratch
    scratch_any isa IocpBackendScratch || return Int32(Base.Libc.ENOSYS)
    scratch = scratch_any::IocpBackendScratch
    entries = scratch.entries
    removed = Ref{UInt32}(UInt32(0))
    wait_ms = _iocp_timeout_ms(delay_ns)
    ok = GC.@preserve entries removed begin
        @ccall gc_safe = true _KERNEL32.GetQueuedCompletionStatusEx(
            scratch.port::Ptr{Cvoid},
            pointer(entries)::Ptr{OverlappedEntry},
            UInt32(length(entries))::UInt32,
            removed::Ref{UInt32},
            wait_ms::UInt32,
            Int32(0)::Int32,
        )::Int32
    end
    if ok == 0
        err = _win_get_last_error()
        err == _WAIT_TIMEOUT && return Int32(0)
        return _map_win_errno(err)
    end
    n = Int(removed[])
    for i in 1:n
        entry = entries[i]
        if entry.key == _WAKE_KEY && entry.overlapped == C_NULL
            delay_ns != 0 && (@atomic :release state.wak_sig = UInt32(0))
            continue
        end
        entry.overlapped == C_NULL && continue
        op = get(scratch.by_ptr, entry.overlapped, nothing)
        op === nothing && continue
        @atomic :release op.active = false
        reg = op.owner
        if reg isa IocpRegistration
            _cleanup_registration_if_done!(scratch, reg)
            (@atomic :acquire reg.closing) && continue
        end
        status = UInt32(entry.internal & UInt(typemax(UInt32)))
        _dispatch_ready_event!(state, PollEvent(Cint(-1), op.token, op.mode, status != UInt32(0)))
    end
    return Int32(0)
end

else

function _backend_init!(state::Poller)::Int32
    _ = state
    return Int32(Base.Libc.ENOSYS)
end

function _backend_close!(state::Poller)
    _ = state
    return nothing
end

function _backend_open_fd!(state::Poller, fd::Cint, mode::PollMode.T, token::UInt64)::Int32
    _ = state
    _ = fd
    _ = mode
    _ = token
    return Int32(Base.Libc.ENOSYS)
end

function _backend_arm_waiter!(state::Poller, registration::Registration, mode::PollMode.T)::Int32
    _ = state
    _ = registration
    _ = mode
    return Int32(Base.Libc.ENOSYS)
end

function _backend_close_fd!(state::Poller, fd::Cint)::Int32
    _ = state
    _ = fd
    return Int32(Base.Libc.ENOSYS)
end

function _backend_wake!(state::Poller)::Int32
    _ = state
    return Int32(Base.Libc.ENOSYS)
end

function _backend_poll_once!(state::Poller, delay_ns::Int64)::Int32
    _ = state
    _ = delay_ns
    return Int32(Base.Libc.ENOSYS)
end

end
