# Windows socket syscall bindings used by `SocketOps`.
# Wrappers normalize retry/error behavior and expose POSIX-like errno semantics.

const _WS2_32 = "Ws2_32"
const _MSWSOCK = "Mswsock"
const _KERNEL32 = "Kernel32"
const _INVALID_SOCKET = UInt(typemax(UInt))
const _SOCKET_ERROR = Cint(-1)
# FIONBIO is defined as an unsigned ioctl bit-pattern; preserve bits, then
# reinterpret as signed long for the ioctlsocket `cmd` parameter.
const _FIONBIO_BITS = UInt32(0x8004667e)
const _FIONBIO = reinterpret(Int32, _FIONBIO_BITS)
const _WSA_FLAG_OVERLAPPED = UInt32(0x01)
const _WSA_FLAG_NO_HANDLE_INHERIT = UInt32(0x80)
const _HANDLE_FLAG_INHERIT = UInt32(0x00000001)
const _ACCEPT_ADDRBUF_LEN = 128

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

const _ERROR_IO_PENDING = Int32(997)
const _ERROR_OPERATION_ABORTED = Int32(995)
const _ERROR_NETNAME_DELETED = UInt32(64)
const _ERROR_INVALID_PARAMETER = UInt32(87)
const _ERROR_NOT_ENOUGH_MEMORY = UInt32(8)
const _ERROR_INVALID_HANDLE = UInt32(6)
const _ERROR_NOT_SUPPORTED = UInt32(50)
const _SO_UPDATE_ACCEPT_CONTEXT = Cint(0x700b)
const _SO_UPDATE_CONNECT_CONTEXT = Cint(0x7010)
const _WSADATA_DESC_ZERO = ntuple(_ -> UInt8(0), 257)
const _WSADATA_STATUS_ZERO = ntuple(_ -> UInt8(0), 129)
const _ERRNO_ESOCKTNOSUPPORT = @static isdefined(Base.Libc, :ESOCKTNOSUPPORT) ? Int32(getfield(Base.Libc, :ESOCKTNOSUPPORT)) : Int32(Base.Libc.EPROTONOSUPPORT)
const _ERRNO_ESHUTDOWN = @static isdefined(Base.Libc, :ESHUTDOWN) ? Int32(getfield(Base.Libc, :ESHUTDOWN)) : Int32(Base.Libc.ENOTCONN)
const _ERRNO_EHOSTDOWN = @static isdefined(Base.Libc, :EHOSTDOWN) ? Int32(getfield(Base.Libc, :EHOSTDOWN)) : Int32(Base.Libc.EHOSTUNREACH)
const _ERRNO_ECANCELED = @static isdefined(Base.Libc, :ECANCELED) ? Int32(getfield(Base.Libc, :ECANCELED)) : Int32(Base.Libc.EINTR)

struct _SockAddrHeader
    sa_family::UInt16
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

const _winsock_lock = ReentrantLock()
const _winsock_initialized = Ref{Bool}(false)
const _winsock_init_pid = Ref{Int}(0)
const _fd_state_lock = ReentrantLock()
const _fd_nonblocking_state = Dict{Cint, Bool}()

@inline function _socket_value(fd::Cint)::UInt
    return UInt(reinterpret(UInt32, fd))
end

@inline function _socket_handle(fd::Cint)::Ptr{Cvoid}
    return Ptr{Cvoid}(_socket_value(fd))
end

@inline function _wsa_get_last_error()::Int32
    return Int32(ccall((:WSAGetLastError, _WS2_32), Cint, ()))
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

function _set_fd_nonblocking_state!(fd::Cint, enabled::Bool)
    lock(_fd_state_lock)
    try
        _fd_nonblocking_state[fd] = enabled
    finally
        unlock(_fd_state_lock)
    end
    return nothing
end

function _clear_fd_state!(fd::Cint)
    lock(_fd_state_lock)
    try
        delete!(_fd_nonblocking_state, fd)
    finally
        unlock(_fd_state_lock)
    end
    return nothing
end

function _fd_nonblocking_enabled(fd::Cint)::Bool
    lock(_fd_state_lock)
    try
        return get(() -> false, _fd_nonblocking_state, fd)
    finally
        unlock(_fd_state_lock)
    end
end

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
        rc = @ccall gc_safe = true _WS2_32.WSAStartup(
            UInt16(0x0202)::UInt16,
            wsa_data::Ref{_WSAData},
        )::Cint
        rc == 0 || _throw_errno("WSAStartup", _map_wsa_errno(Int32(rc)))
        _winsock_initialized[] = true
        _winsock_init_pid[] = pid
    finally
        unlock(_winsock_lock)
    end
    return nothing
end

function last_error()::Int32
    return _map_wsa_errno(_wsa_get_last_error())
end

function fd_is_cloexec(fd::Cint)::Bool
    flags = Ref{UInt32}(UInt32(0))
    ok = ccall((:GetHandleInformation, _KERNEL32), Int32, (Ptr{Cvoid}, Ref{UInt32}), _socket_handle(fd), flags)
    if ok == 0
        _throw_errno("GetHandleInformation", _map_win32_errno(_win_get_last_error()))
    end
    return (flags[] & _HANDLE_FLAG_INHERIT) == UInt32(0)
end

function fd_is_nonblocking(fd::Cint)::Bool
    return _fd_nonblocking_enabled(fd)
end

function set_close_on_exec!(fd::Cint)
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

function set_nonblocking!(fd::Cint, enabled::Bool = true)
    ensure_winsock!()
    arg = Ref{UInt32}(enabled ? UInt32(1) : UInt32(0))
    ret = ccall((:ioctlsocket, _WS2_32), Cint, (UInt, Clong, Ref{UInt32}), _socket_value(fd), Clong(_FIONBIO), arg)
    ret == 0 || _throw_errno("ioctlsocket(FIONBIO)", _map_wsa_errno(_wsa_get_last_error()))
    _set_fd_nonblocking_state!(fd, enabled)
    return nothing
end

function open_socket(family::Integer, sotype::Integer, proto::Integer = 0)::Cint
    ensure_winsock!()
    raw_type = Cint(sotype)
    flags = UInt32(_WSA_FLAG_OVERLAPPED | _WSA_FLAG_NO_HANDLE_INHERIT)
    sock = ccall(
        (:WSASocketW, _WS2_32),
        UInt,
        (Cint, Cint, Cint, Ptr{Cvoid}, UInt32, UInt32),
        Cint(family),
        raw_type,
        Cint(proto),
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
                (Cint, Cint, Cint, Ptr{Cvoid}, UInt32, UInt32),
                Cint(family),
                raw_type,
                Cint(proto),
                C_NULL,
                UInt32(0),
                _WSA_FLAG_OVERLAPPED,
            )
            sock == _INVALID_SOCKET && _throw_errno("socket", _map_wsa_errno(_wsa_get_last_error()))
            fd_fallback = Cint(UInt32(sock))
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
    fd = Cint(UInt32(sock))
    try
        set_nonblocking!(fd, true)
    catch
        close_socket_nothrow(fd)
        rethrow()
    end
    return fd
end

function close_socket_nothrow(fd::Cint)::Int32
    _clear_fd_state!(fd)
    ret = @ccall gc_safe = true _WS2_32.closesocket(
        _socket_value(fd)::UInt,
    )::Cint
    ret == 0 && return Int32(0)
    errno = _map_wsa_errno(_wsa_get_last_error())
    errno == Int32(Base.Libc.EBADF) && return errno
    return Int32(0)
end

function close_socket(fd::Cint)
    errno = close_socket_nothrow(fd)
    errno == Int32(0) && return nothing
    _throw_errno("closesocket", errno)
end

function bind_socket(fd::Cint, addr::SockAddrIn)
    addr_ref = Ref(addr)
    GC.@preserve addr_ref begin
        bind_socket(fd, Base.unsafe_convert(Ptr{Cvoid}, addr_ref), SockLen(sizeof(SockAddrIn)))
    end
    return nothing
end

function bind_socket(fd::Cint, addr::SockAddrIn6)
    addr_ref = Ref(addr)
    GC.@preserve addr_ref begin
        bind_socket(fd, Base.unsafe_convert(Ptr{Cvoid}, addr_ref), SockLen(sizeof(SockAddrIn6)))
    end
    return nothing
end

function bind_socket(fd::Cint, addr::Ptr{Cvoid}, addrlen::SockLen)
    ret = @ccall gc_safe = true _WS2_32.bind(
        _socket_value(fd)::UInt,
        addr::Ptr{Cvoid},
        Cint(addrlen)::Cint,
    )::Cint
    ret == 0 && return nothing
    _throw_errno("bind", _map_wsa_errno(_wsa_get_last_error()))
end

function listen_socket(fd::Cint, backlog::Integer)
    ret = @ccall gc_safe = true _WS2_32.listen(
        _socket_value(fd)::UInt,
        Cint(backlog)::Cint,
    )::Cint
    ret == 0 && return nothing
    _throw_errno("listen", _map_wsa_errno(_wsa_get_last_error()))
end

function connect_socket(fd::Cint, addr::SockAddrIn)::Int32
    addr_ref = Ref(addr)
    GC.@preserve addr_ref begin
        return connect_socket(fd, Base.unsafe_convert(Ptr{Cvoid}, addr_ref), SockLen(sizeof(SockAddrIn)))
    end
end

function connect_socket(fd::Cint, addr::SockAddrIn6)::Int32
    addr_ref = Ref(addr)
    GC.@preserve addr_ref begin
        return connect_socket(fd, Base.unsafe_convert(Ptr{Cvoid}, addr_ref), SockLen(sizeof(SockAddrIn6)))
    end
end

function connect_socket(fd::Cint, addr::Ptr{Cvoid}, addrlen::SockLen)::Int32
    ret = @ccall gc_safe = true "Ws2_32".connect(
        _socket_value(fd)::UInt,
        addr::Ptr{Cvoid},
        Cint(addrlen)::Cint,
    )::Cint
    ret == 0 && return Int32(0)
    err = _wsa_get_last_error()
    err == _WSAEWOULDBLOCK && return Int32(Base.Libc.EINPROGRESS)
    return _map_wsa_errno(err)
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

@inline function _decode_accept_peer(addrptr::Ptr{UInt8}, addrlen::SockLen)::AcceptPeer
    Int(addrlen) < sizeof(_SockAddrHeader) && return nothing
    header = unsafe_load(Ptr{_SockAddrHeader}(addrptr))
    family = Cint(header.sa_family)
    if family == AF_INET && Int(addrlen) >= sizeof(SockAddrIn)
        return unsafe_load(Ptr{SockAddrIn}(addrptr))
    end
    if family == AF_INET6 && Int(addrlen) >= sizeof(SockAddrIn6)
        return unsafe_load(Ptr{SockAddrIn6}(addrptr))
    end
    return nothing
end

function try_accept_socket(fd::Cint)::Tuple{Cint, AcceptPeer, Int32}
    addrbuf = Ref{NTuple{_ACCEPT_ADDRBUF_LEN, UInt8}}()
    addrlen = Ref{SockLen}(SockLen(_ACCEPT_ADDRBUF_LEN))
    new_sock = GC.@preserve addrbuf begin
        @ccall gc_safe = true "Ws2_32".accept(
            _socket_value(fd)::UInt,
            Base.unsafe_convert(Ptr{Cvoid}, addrbuf)::Ptr{Cvoid},
            addrlen::Ref{SockLen},
        )::UInt
    end
    if new_sock == _INVALID_SOCKET
        return Cint(-1), nothing, _map_wsa_errno(_wsa_get_last_error())
    end
    newfd = Cint(UInt32(new_sock))
    try
        set_close_on_exec!(newfd)
        set_nonblocking!(newfd, true)
    catch err
        close_socket_nothrow(newfd)
        if err isa SystemError
            return Cint(-1), nothing, Int32(err.errnum)
        end
        rethrow(err)
    end
    peer = GC.@preserve addrbuf begin
        addrptr = Ptr{UInt8}(Base.unsafe_convert(Ptr{NTuple{_ACCEPT_ADDRBUF_LEN, UInt8}}, addrbuf))
        _decode_accept_peer(addrptr, addrlen[])
    end
    return newfd, peer, Int32(0)
end

function accept_socket(fd::Cint)::Cint
    newfd, _, errno = try_accept_socket(fd)
    newfd != Cint(-1) && return newfd
    _throw_errno("accept", errno)
end

function _set_sockopt_ptr!(fd::Cint, optname::Cint, ptr::Ptr{UInt8}, optlen::Integer)
    ret = ccall(
        (:setsockopt, _WS2_32),
        Cint,
        (UInt, Cint, Cint, Ptr{UInt8}, Cint),
        _socket_value(fd),
        SOL_SOCKET,
        optname,
        ptr,
        Cint(optlen),
    )
    ret == 0 && return nothing
    _throw_errno("setsockopt", _map_wsa_errno(_wsa_get_last_error()))
end

function update_connect_context!(fd::Cint)
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

function finish_accept_ex!(listener_fd::Cint, acceptfd::Cint, addrbuf::Vector{UInt8})::AcceptPeer
    listener_ref = Ref{UInt}(_socket_value(listener_fd))
    GC.@preserve listener_ref begin
        _set_sockopt_ptr!(
            acceptfd,
            _SO_UPDATE_ACCEPT_CONTEXT,
            Ptr{UInt8}(Base.unsafe_convert(Ptr{UInt}, listener_ref)),
            sizeof(UInt),
        )
    end
    local_ptr = Ref{Ptr{UInt8}}(C_NULL)
    local_len = Ref{Cint}(0)
    remote_ptr = Ref{Ptr{UInt8}}(C_NULL)
    remote_len = Ref{Cint}(0)
    GC.@preserve addrbuf begin
        @ccall gc_safe = true _MSWSOCK.GetAcceptExSockaddrs(
            pointer(addrbuf)::Ptr{UInt8},
            UInt32(0)::UInt32,
            UInt32(_ACCEPT_ADDRBUF_LEN)::UInt32,
            UInt32(_ACCEPT_ADDRBUF_LEN)::UInt32,
            local_ptr::Ref{Ptr{UInt8}},
            local_len::Ref{Cint},
            remote_ptr::Ref{Ptr{UInt8}},
            remote_len::Ref{Cint},
        )::Cvoid
    end
    remote_ptr[] == C_NULL && return nothing
    return _decode_accept_peer(remote_ptr[], SockLen(remote_len[]))
end

function get_sockopt_int(fd::Cint, level::Cint, optname::Cint)::Int32
    value = Ref{Cint}(0)
    optlen = Ref{Cint}(Cint(sizeof(Cint)))
    ret = GC.@preserve value begin
        ccall(
            (:getsockopt, _WS2_32),
            Cint,
            (UInt, Cint, Cint, Ptr{UInt8}, Ref{Cint}),
            _socket_value(fd),
            level,
            optname,
            Ptr{UInt8}(Base.unsafe_convert(Ptr{Cint}, value)),
            optlen,
        )
    end
    ret == 0 && return Int32(value[])
    _throw_errno("getsockopt", _map_wsa_errno(_wsa_get_last_error()))
end

function set_sockopt_int(fd::Cint, level::Cint, optname::Cint, value::Integer)
    raw = Ref{Cint}(Cint(value))
    ret = GC.@preserve raw begin
        ccall(
            (:setsockopt, _WS2_32),
            Cint,
            (UInt, Cint, Cint, Ptr{UInt8}, Cint),
            _socket_value(fd),
            level,
            optname,
            Ptr{UInt8}(Base.unsafe_convert(Ptr{Cint}, raw)),
            Cint(sizeof(Cint)),
        )
    end
    ret == 0 && return nothing
    _throw_errno("setsockopt", _map_wsa_errno(_wsa_get_last_error()))
end

function get_socket_error(fd::Cint)::Int32
    return get_sockopt_int(fd, SOL_SOCKET, SO_ERROR)
end

function get_socket_name_in(fd::Cint)::SockAddrIn
    addr = Ref{SockAddrIn}()
    addrlen = Ref{SockLen}(SockLen(sizeof(SockAddrIn)))
    ret = ccall(
        (:getsockname, _WS2_32),
        Cint,
        (UInt, Ptr{Cvoid}, Ref{SockLen}),
        _socket_value(fd),
        Base.unsafe_convert(Ptr{Cvoid}, addr),
        addrlen,
    )
    ret == 0 && return addr[]
    _throw_errno("getsockname", _map_wsa_errno(_wsa_get_last_error()))
end

function get_socket_name_in6(fd::Cint)::SockAddrIn6
    addr = Ref{SockAddrIn6}()
    addrlen = Ref{SockLen}(SockLen(sizeof(SockAddrIn6)))
    ret = ccall(
        (:getsockname, _WS2_32),
        Cint,
        (UInt, Ptr{Cvoid}, Ref{SockLen}),
        _socket_value(fd),
        Base.unsafe_convert(Ptr{Cvoid}, addr),
        addrlen,
    )
    ret == 0 && return addr[]
    _throw_errno("getsockname", _map_wsa_errno(_wsa_get_last_error()))
end

function get_peer_name_in(fd::Cint)::SockAddrIn
    addr = Ref{SockAddrIn}()
    addrlen = Ref{SockLen}(SockLen(sizeof(SockAddrIn)))
    ret = ccall(
        (:getpeername, _WS2_32),
        Cint,
        (UInt, Ptr{Cvoid}, Ref{SockLen}),
        _socket_value(fd),
        Base.unsafe_convert(Ptr{Cvoid}, addr),
        addrlen,
    )
    ret == 0 && return addr[]
    _throw_errno("getpeername", _map_wsa_errno(_wsa_get_last_error()))
end

function get_peer_name_in6(fd::Cint)::SockAddrIn6
    addr = Ref{SockAddrIn6}()
    addrlen = Ref{SockLen}(SockLen(sizeof(SockAddrIn6)))
    ret = ccall(
        (:getpeername, _WS2_32),
        Cint,
        (UInt, Ptr{Cvoid}, Ref{SockLen}),
        _socket_value(fd),
        Base.unsafe_convert(Ptr{Cvoid}, addr),
        addrlen,
    )
    ret == 0 && return addr[]
    _throw_errno("getpeername", _map_wsa_errno(_wsa_get_last_error()))
end

function shutdown_socket(fd::Cint, how::Integer)
    ret = @ccall gc_safe = true _WS2_32.shutdown(
        _socket_value(fd)::UInt,
        Cint(how)::Cint,
    )::Cint
    ret == 0 && return nothing
    _throw_errno("shutdown", _map_wsa_errno(_wsa_get_last_error()))
end

function read_once!(fd::Cint, ptr::Ptr{UInt8}, nbytes::Csize_t)::Cssize_t
    n = Int(min(nbytes, Csize_t(typemax(Cint))))
    ret = @ccall gc_safe = true "Ws2_32".recv(
        _socket_value(fd)::UInt,
        ptr::Ptr{UInt8},
        Cint(n)::Cint,
        Cint(0)::Cint,
    )::Cint
    ret >= 0 && return Cssize_t(ret)
    return Cssize_t(-1)
end

function write_once!(fd::Cint, ptr::Ptr{UInt8}, nbytes::Csize_t)::Cssize_t
    n = Int(min(nbytes, Csize_t(typemax(Cint))))
    ret = @ccall gc_safe = true "Ws2_32".send(
        _socket_value(fd)::UInt,
        ptr::Ptr{UInt8},
        Cint(n)::Cint,
        Cint(0)::Cint,
    )::Cint
    ret >= 0 && return Cssize_t(ret)
    return Cssize_t(-1)
end

function recv_from!(
        fd::Cint,
        ptr::Ptr{UInt8},
        nbytes::Csize_t,
        flags::Cint = Cint(0),
        from::Ptr{Cvoid} = Ptr{Cvoid}(C_NULL),
        fromlen::Ptr{SockLen} = Ptr{SockLen}(C_NULL),
    )::Cssize_t
    n = Int(min(nbytes, Csize_t(typemax(Cint))))
    ret = @ccall gc_safe = true "Ws2_32".recvfrom(
        _socket_value(fd)::UInt,
        ptr::Ptr{UInt8},
        Cint(n)::Cint,
        flags::Cint,
        from::Ptr{Cvoid},
        fromlen::Ptr{SockLen},
    )::Cint
    ret >= 0 && return Cssize_t(ret)
    return Cssize_t(-1)
end

function send_to!(
        fd::Cint,
        ptr::Ptr{UInt8},
        nbytes::Csize_t,
        flags::Cint = Cint(0),
        to::Ptr{Cvoid} = C_NULL,
        tolen::SockLen = SockLen(0),
    )::Cssize_t
    n = Int(min(nbytes, Csize_t(typemax(Cint))))
    ret = @ccall gc_safe = true "Ws2_32".sendto(
        _socket_value(fd)::UInt,
        ptr::Ptr{UInt8},
        Cint(n)::Cint,
        flags::Cint,
        to::Ptr{Cvoid},
        Cint(tolen)::Cint,
    )::Cint
    ret >= 0 && return Cssize_t(ret)
    return Cssize_t(-1)
end

function recv_msg!(fd::Cint, msg::Ref{MsgHdr}, flags::Cint = Cint(0))::Cssize_t
    _ = fd
    _ = msg
    _ = flags
    _throw_errno("recvmsg", Int32(Base.Libc.ENOSYS))
end

function send_msg!(fd::Cint, msg::Ref{MsgHdr}, flags::Cint = Cint(0))::Cssize_t
    _ = fd
    _ = msg
    _ = flags
    _throw_errno("sendmsg", Int32(Base.Libc.ENOSYS))
end

function __init__()
    ensure_winsock!()
    return nothing
end
