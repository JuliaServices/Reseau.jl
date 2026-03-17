@static if Sys.iswindows()

const _KERNEL32 = "Kernel32"
const _MSWSOCK = "Mswsock"
const _WS2_32 = "Ws2_32"
const _INVALID_HANDLE_VALUE = Ptr{Cvoid}(typemax(UInt))
const _INVALID_SOCKET = UInt(typemax(UInt))
const _INFINITE = UInt32(0xffff_ffff)
const _WAIT_TIMEOUT = UInt32(0x00000102)
const _ERROR_IO_PENDING = Int32(997)
const _ERROR_OPERATION_ABORTED = Int32(995)
const _ERROR_NOT_FOUND = UInt32(1168)
const _ERROR_INVALID_HANDLE = UInt32(6)
const _ERROR_INVALID_PARAMETER = UInt32(87)
const _ERROR_NOT_ENOUGH_MEMORY = UInt32(8)
const _SIO_GET_EXTENSION_FUNCTION_POINTER = UInt32(0xC8000006)
const _SOL_SOCKET = Cint(0xffff)
const _SO_PROTOCOL_INFOW = Cint(0x2005)
const _FILE_SKIP_COMPLETION_PORT_ON_SUCCESS = UInt8(0x01)
const _FILE_SKIP_SET_EVENT_ON_HANDLE = UInt8(0x02)
const _XP1_IFS_HANDLES = UInt32(0x00020000)
const _WSA_FLAG_OVERLAPPED = UInt32(0x01)
const _AF_INET = Cint(2)
const _SOCK_STREAM = Cint(1)
const _IPPROTO_TCP = Cint(6)
const _WSAEWOULDBLOCK = Int32(10035)
const _WSAEINPROGRESS = Int32(10036)
const _WSAEALREADY = Int32(10037)
const _WSAEADDRNOTAVAIL = Int32(10049)
const _WSAENETUNREACH = Int32(10051)
const _WSAECONNABORTED = Int32(10053)
const _WSAECONNRESET = Int32(10054)
const _WSAEISCONN = Int32(10056)
const _WSAENOTCONN = Int32(10057)
const _WSAETIMEDOUT = Int32(10060)
const _WSAECONNREFUSED = Int32(10061)
const _WSAEHOSTUNREACH = Int32(10065)
const _MAX_IOCP_EVENTS = 128
const _WAKE_KEY = typemax(UInt)
const _ERRNO_ECANCELED = @static isdefined(Base.Libc, :ECANCELED) ? Int32(getfield(Base.Libc, :ECANCELED)) : Int32(Base.Libc.EINTR)
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

struct WSAProtocolChain
    chain_len::Int32
    chain_entries::NTuple{7, UInt32}
end

struct WSAProtocolInfo
    service_flags1::UInt32
    service_flags2::UInt32
    service_flags3::UInt32
    service_flags4::UInt32
    provider_flags::UInt32
    provider_id::Guid
    catalog_entry_id::UInt32
    protocol_chain::WSAProtocolChain
    version::Int32
    address_family::Int32
    max_sock_addr::Int32
    min_sock_addr::Int32
    socket_type::Int32
    protocol::Int32
    protocol_max_offset::Int32
    network_byte_order::Int32
    security_scheme::Int32
    message_size::UInt32
    provider_reserved::UInt32
    protocol_name::NTuple{256, UInt16}
end

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

mutable struct IocpConnectRequest
    addrbuf::Vector{UInt8}
    addrlen::Int32
end

mutable struct IocpAcceptRequest
    acceptfd::Cint
    addrbuf::Vector{UInt8}
end

const IocpRequest = Union{Nothing, IocpConnectRequest, IocpAcceptRequest}

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
    fd::Cint
    token::UInt64
    read_op::IocpOp
    write_op::IocpOp
    wait_on_success::Bool
    @atomic closing::Bool
end

mutable struct IocpBackendState <: BackendState
    port::Ptr{Cvoid}
    entries::Vector{OverlappedEntry}
    by_fd::Dict{Cint, IocpRegistration}
    by_ptr::Dict{Ptr{Cvoid}, IocpOp}
    zombies::Vector{IocpRegistration}
    @atomic wake_sig::UInt32
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

@inline function _iocp_backend(state::Poller)
    backend = state.backend_state
    backend isa IocpBackendState || return nothing
    return backend::IocpBackendState
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

@inline function _map_overlapped_errno(err::Int32)::Int32
    err == Int32(0) && return Int32(0)
    err == _ERROR_OPERATION_ABORTED && return _ERRNO_ECANCELED
    err == _ERROR_IO_PENDING && return Int32(Base.Libc.EINPROGRESS)
    err == _WSAEWOULDBLOCK && return Int32(Base.Libc.EAGAIN)
    err == _WSAEINPROGRESS && return Int32(Base.Libc.EINPROGRESS)
    err == _WSAEALREADY && return Int32(Base.Libc.EALREADY)
    err == _WSAEADDRNOTAVAIL && return Int32(Base.Libc.EADDRNOTAVAIL)
    err == _WSAENETUNREACH && return Int32(Base.Libc.ENETUNREACH)
    err == _WSAECONNABORTED && return Int32(Base.Libc.ECONNABORTED)
    err == _WSAECONNRESET && return Int32(Base.Libc.ECONNRESET)
    err == _WSAEISCONN && return Int32(Base.Libc.EISCONN)
    err == _WSAENOTCONN && return Int32(Base.Libc.ENOTCONN)
    err == _WSAETIMEDOUT && return Int32(Base.Libc.ETIMEDOUT)
    err == _WSAECONNREFUSED && return Int32(Base.Libc.ECONNREFUSED)
    err == _WSAEHOSTUNREACH && return Int32(Base.Libc.EHOSTUNREACH)
    return _map_win_errno(UInt32(err))
end

function _new_iocp_registration(fd::Cint, token::UInt64)::IocpRegistration
    read_op = IocpOp(Ref(_ZERO_OVERLAPPED), PollMode.READ, token, IocpOpKind.PROBE_READ, nothing, nothing, false)
    write_op = IocpOp(Ref(_ZERO_OVERLAPPED), PollMode.WRITE, token, IocpOpKind.PROBE_WRITE, nothing, nothing, false)
    reg = IocpRegistration(fd, token, read_op, write_op, true, false)
    read_op.owner = reg
    write_op.owner = reg
    return reg
end

@inline function _reset_overlapped!(op::IocpOp)
    op.storage[] = _ZERO_OVERLAPPED
    return nothing
end

@inline function _set_probe_kind!(op::IocpOp)
    op.kind = op.mode == PollMode.READ ? IocpOpKind.PROBE_READ : IocpOpKind.PROBE_WRITE
    op.request = nothing
    return nothing
end

function _load_connectex_ptr(fd::Cint)::Ptr{Cvoid}
    ptr = _CONNECTEX_PTR[]
    ptr != C_NULL && return ptr
    lock(_CONNECTEX_LOCK)
    try
        ptr = _CONNECTEX_PTR[]
        ptr != C_NULL && return ptr
        guid_ref = Ref(_WSAID_CONNECTEX)
        out_ref = Ref{Ptr{Cvoid}}(C_NULL)
        bytes_ref = Ref{UInt32}(UInt32(0))
        rc = GC.@preserve guid_ref out_ref bytes_ref begin
            @gcsafe_ccall _WS2_32.WSAIoctl(
                _socket_value(fd)::UInt,
                _SIO_GET_EXTENSION_FUNCTION_POINTER::UInt32,
                guid_ref::Ref{Guid},
                UInt32(sizeof(Guid))::UInt32,
                out_ref::Ref{Ptr{Cvoid}},
                UInt32(sizeof(Ptr{Cvoid}))::UInt32,
                bytes_ref::Ref{UInt32},
                C_NULL::Ptr{Cvoid},
                C_NULL::Ptr{Cvoid},
            )::Cint
        end
        rc == 0 || return C_NULL
        _CONNECTEX_PTR[] = out_ref[]
        return out_ref[]
    finally
        unlock(_CONNECTEX_LOCK)
    end
end

@inline function _wsagetoverlappedresult(fd::Cint, op::IocpOp)::Int32
    bytes_ref = Ref{UInt32}(UInt32(0))
    flags_ref = Ref{UInt32}(UInt32(0))
    ok = GC.@preserve op bytes_ref flags_ref begin
        @gcsafe_ccall _WS2_32.WSAGetOverlappedResult(
            _socket_value(fd)::UInt,
            Base.unsafe_convert(Ptr{Overlapped}, op.storage)::Ptr{Overlapped},
            bytes_ref::Ref{UInt32},
            Int32(0)::Int32,
            flags_ref::Ref{UInt32},
        )::Int32
    end
    ok != 0 && return Int32(0)
    return _map_overlapped_errno(_wsa_get_last_error())
end

@inline function _clear_iocp_op!(op::IocpOp)
    @atomic :release op.active = false
    _set_probe_kind!(op)
    _reset_overlapped!(op)
    return nothing
end

function _socket_can_skip_completion_port_on_success(fd::Cint)::Bool
    info_ref = Ref{WSAProtocolInfo}()
    size_ref = Ref{Cint}(Cint(sizeof(WSAProtocolInfo)))
    rc = GC.@preserve info_ref size_ref begin
        ccall(
            (:getsockopt, _WS2_32),
            Cint,
            (UInt, Cint, Cint, Ptr{UInt8}, Ref{Cint}),
            _socket_value(fd),
            _SOL_SOCKET,
            _SO_PROTOCOL_INFOW,
            Ptr{UInt8}(Base.unsafe_convert(Ptr{WSAProtocolInfo}, info_ref)),
            size_ref,
        )
    end
    rc == 0 || return false
    return (info_ref[].service_flags1 & _XP1_IFS_HANDLES) != 0
end

function _maybe_set_completion_modes!(fd::Cint)::Bool
    modes = UInt8(_FILE_SKIP_SET_EVENT_ON_HANDLE)
    if _socket_can_skip_completion_port_on_success(fd)
        modes |= _FILE_SKIP_COMPLETION_PORT_ON_SUCCESS
    end
    ok = @gcsafe_ccall _KERNEL32.SetFileCompletionNotificationModes(
        _socket_handle(fd)::Ptr{Cvoid},
        modes::UInt8,
    )::Int32
    if ok != 0 && (modes & _FILE_SKIP_COMPLETION_PORT_ON_SUCCESS) != 0
        return false
    end
    return true
end

@inline function _registration_has_active(reg::IocpRegistration)::Bool
    return (@atomic :acquire reg.read_op.active) || (@atomic :acquire reg.write_op.active)
end

function _cleanup_registration_if_done!(backend::IocpBackendState, reg::IocpRegistration)
    if !(@atomic :acquire reg.closing)
        return nothing
    end
    _registration_has_active(reg) && return nothing
    delete!(backend.by_ptr, _op_ptr(reg.read_op))
    delete!(backend.by_ptr, _op_ptr(reg.write_op))
    idx = findfirst(x -> x === reg, backend.zombies)
    idx === nothing || deleteat!(backend.zombies, idx)
    return nothing
end

function _cancel_iocp_op!(reg::IocpRegistration, op::IocpOp)::Bool
    (@atomic :acquire op.active) || return false
    ok = @gcsafe_ccall _KERNEL32.CancelIoEx(
        _socket_handle(reg.fd)::Ptr{Cvoid},
        _op_ptr(op)::Ptr{Cvoid},
    )::Int32
    if ok == 0
        err = _win_get_last_error()
        if err == _ERROR_NOT_FOUND
            @atomic :release op.active = false
            return false
        end
    end
    return true
end

function _submit_iocp_op!(registration::Registration, reg::IocpRegistration, op::IocpOp)::Int32
    _, ok = @atomicreplace(op.active, false => true)
    ok || return Int32(Base.Libc.EALREADY)
    _reset_overlapped!(op)
    rc = Cint(-1)
    if op.kind == IocpOpKind.PROBE_READ || op.kind == IocpOpKind.PROBE_WRITE
        wsabuf = Ref(WSABUF(UInt32(0), Ptr{UInt8}(C_NULL)))
        bytes = Ref{UInt32}(UInt32(0))
        flags = Ref{UInt32}(UInt32(0))
        rc = GC.@preserve op wsabuf bytes flags begin
            if op.mode == PollMode.READ
                @gcsafe_ccall _WS2_32.WSARecv(
                    _socket_value(reg.fd)::UInt,
                    wsabuf::Ref{WSABUF},
                    UInt32(1)::UInt32,
                    bytes::Ref{UInt32},
                    flags::Ref{UInt32},
                    _op_ptr(op)::Ptr{Cvoid},
                    C_NULL::Ptr{Cvoid},
                )::Cint
            else
                @gcsafe_ccall _WS2_32.WSASend(
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
    elseif op.kind == IocpOpKind.CONNECT
        request = op.request
        request isa IocpConnectRequest || throw(ArgumentError("missing ConnectEx request"))
        connectex_ptr = _load_connectex_ptr(reg.fd)
        connectex_ptr == C_NULL && return _map_overlapped_errno(_wsa_get_last_error())
        bytes_ref = Ref{UInt32}(UInt32(0))
        addrbuf = request.addrbuf
        rc = GC.@preserve op addrbuf bytes_ref begin
            ccall(
                connectex_ptr,
                Int32,
                (UInt, Ptr{Cvoid}, Cint, Ptr{UInt8}, UInt32, Ref{UInt32}, Ptr{Cvoid}),
                _socket_value(reg.fd),
                pointer(addrbuf),
                request.addrlen,
                C_NULL,
                UInt32(0),
                bytes_ref,
                _op_ptr(op),
            )
        end
    else
        request = op.request
        request isa IocpAcceptRequest || throw(ArgumentError("missing AcceptEx request"))
        bytes_ref = Ref{UInt32}(UInt32(0))
        addrbuf = request.addrbuf
        rc = GC.@preserve op addrbuf bytes_ref begin
            @gcsafe_ccall _MSWSOCK.AcceptEx(
                _socket_value(reg.fd)::UInt,
                _socket_value(request.acceptfd)::UInt,
                pointer(addrbuf)::Ptr{UInt8},
                UInt32(0)::UInt32,
                UInt32(length(addrbuf) ÷ 2)::UInt32,
                UInt32(length(addrbuf) ÷ 2)::UInt32,
                bytes_ref::Ref{UInt32},
                _op_ptr(op)::Ptr{Cvoid},
            )::Int32
        end
    end
    if op.kind == IocpOpKind.PROBE_READ || op.kind == IocpOpKind.PROBE_WRITE
        if rc == 0
            reg.wait_on_success && return Int32(0)
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
    if rc != 0
        reg.wait_on_success && return Int32(0)
        @atomic :release op.active = false
        _notify_registration!(registration, op.mode)
        return Int32(0)
    end
    err = _wsa_get_last_error()
    if err == _ERROR_IO_PENDING
        return Int32(0)
    end
    @atomic :release op.active = false
    _clear_iocp_op!(op)
    return _map_overlapped_errno(err)
end

function _iocp_op_for_mode(reg::IocpRegistration, mode::PollMode.T)::IocpOp
    mode == PollMode.READ && return reg.read_op
    mode == PollMode.WRITE && return reg.write_op
    throw(ArgumentError("invalid IOCP mode"))
end

function _lookup_iocp_registration(registration::Registration)::Union{Nothing, IocpRegistration}
    isassigned(POLLER) || return nothing
    state = POLLER[]
    (@atomic :acquire state.running) || return nothing
    backend = _iocp_backend(state)
    backend === nothing && return nothing
    reg = get(backend.by_fd, registration.fd, nothing)
    reg === nothing && return nothing
    reg.token == registration.token || return nothing
    return reg
end

function _finish_iocp_mode!(registration::Registration, mode::PollMode.T)::Int32
    state = POLLER[]
    reg = nothing
    op = nothing
    lock(state.lock)
    try
        reg = _lookup_iocp_registration(registration)
        reg === nothing && return Int32(Base.Libc.EBADF)
        op = _iocp_op_for_mode(reg, mode)
    finally
        unlock(state.lock)
    end
    result = _wsagetoverlappedresult(registration.fd, op::IocpOp)
    lock(state.lock)
    try
        _clear_iocp_op!(op)
    finally
        unlock(state.lock)
    end
    return result
end

function _iocp_cancel_mode!(registration::Registration, mode::PollMode.T)::Bool
    isassigned(POLLER) || return false
    state = POLLER[]
    (@atomic :acquire state.running) || return false
    canceled = false
    lock(state.lock)
    try
        reg = _lookup_iocp_registration(registration)
        reg === nothing && return false
        canceled = _cancel_iocp_op!(reg, _iocp_op_for_mode(reg, mode))
    finally
        unlock(state.lock)
    end
    return canceled
end

function _iocp_submit_connect!(registration::Registration, addrbuf::Vector{UInt8}, addrlen::Int32)::Int32
    isassigned(POLLER) || return Int32(Base.Libc.ENOSYS)
    state = POLLER[]
    (@atomic :acquire state.running) || return Int32(Base.Libc.EBADF)
    errno = Int32(0)
    lock(state.lock)
    try
        reg = _lookup_iocp_registration(registration)
        reg === nothing && return Int32(Base.Libc.EBADF)
        op = reg.write_op
        op.kind = IocpOpKind.CONNECT
        op.request = IocpConnectRequest(addrbuf, addrlen)
        errno = _submit_iocp_op!(registration, reg, op)
        errno != Int32(0) && _clear_iocp_op!(op)
    finally
        unlock(state.lock)
    end
    return errno
end

function _iocp_finish_connect!(registration::Registration)::Int32
    return _finish_iocp_mode!(registration, PollMode.WRITE)
end

function _iocp_submit_accept!(registration::Registration, acceptfd::Cint, addrbuf::Vector{UInt8})::Int32
    isassigned(POLLER) || return Int32(Base.Libc.ENOSYS)
    state = POLLER[]
    (@atomic :acquire state.running) || return Int32(Base.Libc.EBADF)
    errno = Int32(0)
    lock(state.lock)
    try
        reg = _lookup_iocp_registration(registration)
        reg === nothing && return Int32(Base.Libc.EBADF)
        op = reg.read_op
        op.kind = IocpOpKind.ACCEPT
        op.request = IocpAcceptRequest(acceptfd, addrbuf)
        errno = _submit_iocp_op!(registration, reg, op)
        errno != Int32(0) && _clear_iocp_op!(op)
    finally
        unlock(state.lock)
    end
    return errno
end

function _iocp_finish_accept!(registration::Registration)::Tuple{Cint, Vector{UInt8}, Int32}
    state = POLLER[]
    request = nothing
    lock(state.lock)
    try
        reg = _lookup_iocp_registration(registration)
        reg === nothing && return Cint(-1), UInt8[], Int32(Base.Libc.EBADF)
        request = reg.read_op.request
    finally
        unlock(state.lock)
    end
    request isa IocpAcceptRequest || return Cint(-1), UInt8[], Int32(Base.Libc.EINVAL)
    errno = _finish_iocp_mode!(registration, PollMode.READ)
    return request.acceptfd, request.addrbuf, errno
end

function _backend_init!(state::Poller)::Int32
    port = @gcsafe_ccall _KERNEL32.CreateIoCompletionPort(
        _INVALID_HANDLE_VALUE::Ptr{Cvoid},
        C_NULL::Ptr{Cvoid},
        UInt(0)::UInt,
        UInt32(0)::UInt32,
    )::Ptr{Cvoid}
    port == C_NULL && return _map_win_errno(_win_get_last_error())
    state.backend_state = IocpBackendState(
        port,
        Vector{OverlappedEntry}(undef, _MAX_IOCP_EVENTS),
        Dict{Cint, IocpRegistration}(),
        Dict{Ptr{Cvoid}, IocpOp}(),
        IocpRegistration[],
        UInt32(0),
    )
    return Int32(0)
end

function _backend_close!(state::Poller)
    backend = _iocp_backend(state)
    if backend !== nothing
        if backend.port != C_NULL
            _ = @gcsafe_ccall _KERNEL32.CloseHandle(
                backend.port::Ptr{Cvoid},
            )::Int32
        end
    end
    state.backend_state = nothing
    return nothing
end

function _backend_open_fd!(
        state::Poller,
        fd::Cint,
        mode::PollMode.T,
        token::UInt64,
    )::Int32
    _ = mode
    backend = _iocp_backend(state)
    backend === nothing && return Int32(Base.Libc.ENOSYS)
    associated = @gcsafe_ccall _KERNEL32.CreateIoCompletionPort(
        _socket_handle(fd)::Ptr{Cvoid},
        backend.port::Ptr{Cvoid},
        UInt(token)::UInt,
        UInt32(0)::UInt32,
    )::Ptr{Cvoid}
    associated == C_NULL && return _map_win_errno(_win_get_last_error())
    reg = _new_iocp_registration(fd, token)
    reg.wait_on_success = _maybe_set_completion_modes!(fd)
    backend.by_fd[fd] = reg
    backend.by_ptr[_op_ptr(reg.read_op)] = reg.read_op
    backend.by_ptr[_op_ptr(reg.write_op)] = reg.write_op
    return Int32(0)
end

function _backend_arm_waiter!(state::Poller, registration::Registration, mode::PollMode.T)::Int32
    backend = _iocp_backend(state)
    backend === nothing && return Int32(Base.Libc.ENOSYS)
    reg = get(backend.by_fd, registration.fd, nothing)
    reg === nothing && return Int32(0)
    reg.token == registration.token || return Int32(0)
    if _mode_has_read(mode) && _mode_has_read(registration.mode)
        _set_probe_kind!(reg.read_op)
        _submit_iocp_op!(registration, reg, reg.read_op)
    end
    if _mode_has_write(mode) && _mode_has_write(registration.mode)
        _set_probe_kind!(reg.write_op)
        _submit_iocp_op!(registration, reg, reg.write_op)
    end
    return Int32(0)
end

function _backend_close_fd!(state::Poller, fd::Cint)::Int32
    backend = _iocp_backend(state)
    backend === nothing && return Int32(Base.Libc.ENOSYS)
    reg = pop!(backend.by_fd, fd, nothing)
    reg === nothing && return Int32(0)
    @atomic :release reg.closing = true
    _cancel_iocp_op!(reg, reg.read_op)
    _cancel_iocp_op!(reg, reg.write_op)
    if _registration_has_active(reg)
        idx = findfirst(x -> x === reg, backend.zombies)
        idx === nothing && push!(backend.zombies, reg)
    else
        delete!(backend.by_ptr, _op_ptr(reg.read_op))
        delete!(backend.by_ptr, _op_ptr(reg.write_op))
    end
    return Int32(0)
end

function _backend_wake!(state::Poller)::Int32
    backend = _iocp_backend(state)
    backend === nothing && return Int32(Base.Libc.ENOSYS)
    _, ok = @atomicreplace(backend.wake_sig, UInt32(0) => UInt32(1))
    ok || return Int32(0)
    posted = @gcsafe_ccall _KERNEL32.PostQueuedCompletionStatus(
        backend.port::Ptr{Cvoid},
        UInt32(0)::UInt32,
        _WAKE_KEY::UInt,
        C_NULL::Ptr{Cvoid},
    )::Int32
    if posted == 0
        @atomic :release backend.wake_sig = UInt32(0)
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
    backend = _iocp_backend(state)
    backend === nothing && return Int32(Base.Libc.ENOSYS)
    entries = backend.entries
    removed = Ref{UInt32}(UInt32(0))
    wait_ms = _iocp_timeout_ms(delay_ns)
    ok = GC.@preserve entries removed begin
        @gcsafe_ccall _KERNEL32.GetQueuedCompletionStatusEx(
            backend.port::Ptr{Cvoid},
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
            delay_ns != 0 && (@atomic :release backend.wake_sig = UInt32(0))
            continue
        end
        entry.overlapped == C_NULL && continue
        op = get(backend.by_ptr, entry.overlapped, nothing)
        op === nothing && continue
        @atomic :release op.active = false
        is_probe = op.kind == IocpOpKind.PROBE_READ || op.kind == IocpOpKind.PROBE_WRITE
        reg = op.owner
        if reg isa IocpRegistration
            _cleanup_registration_if_done!(backend, reg)
            (@atomic :acquire reg.closing) && continue
        end
        status = UInt32(entry.internal & UInt(typemax(UInt32)))
        _dispatch_ready_event!(state, PollEvent(Cint(-1), op.token, op.mode, is_probe && status != UInt32(0)))
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

function _iocp_submit_connect!(registration::Registration, addrbuf::Vector{UInt8}, addrlen::Int32)::Int32
    _ = registration
    _ = addrbuf
    _ = addrlen
    return Int32(Base.Libc.ENOSYS)
end

function _iocp_finish_connect!(registration::Registration)::Int32
    _ = registration
    return Int32(Base.Libc.ENOSYS)
end

function _iocp_submit_accept!(registration::Registration, acceptfd::Cint, addrbuf::Vector{UInt8})::Int32
    _ = registration
    _ = acceptfd
    _ = addrbuf
    return Int32(Base.Libc.ENOSYS)
end

function _iocp_finish_accept!(registration::Registration)::Tuple{Cint, Vector{UInt8}, Int32}
    _ = registration
    return Cint(-1), UInt8[], Int32(Base.Libc.ENOSYS)
end

function _iocp_cancel_mode!(registration::Registration, mode::PollMode.T)::Bool
    _ = registration
    _ = mode
    return false
end

end
