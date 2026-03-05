# Linux socket syscall bindings used by `SocketOps`.
# Wrappers normalize retry/error behavior and expose consistent errno semantics.
const _F_GETFD = Cint(1)
const _F_SETFD = Cint(2)
const _F_GETFL = Cint(3)
const _F_SETFL = Cint(4)
const _FD_CLOEXEC = Cint(0x0001)
const _O_NONBLOCK = Cint(0x0800)
const _SOCK_CLOEXEC = Cint(0x80000)
const _SOCK_NONBLOCK = Cint(0x0800)
const _ACCEPT_ADDRBUF_LEN = 128
const _ACCEPT4_UNSET = Int32(0)
const _ACCEPT4_ENABLED = Int32(1)
const _ACCEPT4_DISABLED = Int32(2)

struct _SockAddrHeader
    sa_family::UInt16
end

const _accept4_state = Ref{Int32}(_ACCEPT4_UNSET)

@inline function _errno_i32()::Int32
    return Int32(Base.Libc.errno())
end

@inline function ensure_winsock!()
    return nothing
end

@inline function last_error()::Int32
    return _errno_i32()
end

function _throw_errno(op::AbstractString, errno::Int32)
    throw(SystemError(op, Int(errno)))
end

"""
    fd_is_cloexec(fd)

Check whether `fd` has the close-on-exec flag set.
"""
function fd_is_cloexec(fd::Cint)::Bool
    while true
        flags = @ccall fcntl(fd::Cint, _F_GETFD::Cint)::Cint
        if flags != -1
            return (flags & _FD_CLOEXEC) != 0
        end
        errno = _errno_i32()
        errno == Int32(Base.Libc.EINTR) && continue
        _throw_errno("fcntl(F_GETFD)", errno)
    end
end

"""
    fd_is_nonblocking(fd)

Check whether `fd` is in non-blocking mode.
"""
function fd_is_nonblocking(fd::Cint)::Bool
    while true
        flags = @ccall fcntl(fd::Cint, _F_GETFL::Cint)::Cint
        if flags != -1
            return (flags & _O_NONBLOCK) != 0
        end
        errno = _errno_i32()
        errno == Int32(Base.Libc.EINTR) && continue
        _throw_errno("fcntl(F_GETFL)", errno)
    end
end

"""
    set_close_on_exec!(fd)

Set close-on-exec on `fd`.
"""
function set_close_on_exec!(fd::Cint)
    while true
        flags = @ccall fcntl(fd::Cint, _F_GETFD::Cint)::Cint
        if flags != -1
            if (flags & _FD_CLOEXEC) != 0
                return nothing
            end
            ret = @ccall fcntl(fd::Cint, _F_SETFD::Cint, Cint(flags | _FD_CLOEXEC)::Cint)::Cint
            ret == 0 && return nothing
            errno = _errno_i32()
            errno == Int32(Base.Libc.EINTR) && continue
            _throw_errno("fcntl(F_SETFD)", errno)
        end
        errno = _errno_i32()
        errno == Int32(Base.Libc.EINTR) && continue
        _throw_errno("fcntl(F_GETFD)", errno)
    end
end

"""
    set_nonblocking!(fd, enabled=true)

Enable or disable non-blocking mode on `fd`.
"""
function set_nonblocking!(fd::Cint, enabled::Bool = true)
    while true
        flags = @ccall fcntl(fd::Cint, _F_GETFL::Cint)::Cint
        if flags == -1
            errno = _errno_i32()
            errno == Int32(Base.Libc.EINTR) && continue
            _throw_errno("fcntl(F_GETFL)", errno)
        end
        wanted = enabled ? Cint(flags | _O_NONBLOCK) : Cint(flags & ~_O_NONBLOCK)
        wanted == flags && return nothing
        ret = @ccall fcntl(fd::Cint, _F_SETFL::Cint, wanted::Cint)::Cint
        ret == 0 && return nothing
        errno = _errno_i32()
        errno == Int32(Base.Libc.EINTR) && continue
        _throw_errno("fcntl(F_SETFL)", errno)
    end
end

"""
    open_socket(family, sotype, proto=0)

Create a socket and configure it as close-on-exec and non-blocking.
"""
function open_socket(family::Integer, sotype::Integer, proto::Integer = 0)::Cint
    raw_type = Cint(sotype)
    flagged_type = Cint(raw_type | _SOCK_NONBLOCK | _SOCK_CLOEXEC)
    fd = @ccall gc_safe = true socket(Cint(family)::Cint, flagged_type::Cint, Cint(proto)::Cint)::Cint
    if fd == -1
        errno = _errno_i32()
        if errno != Int32(Base.Libc.EINVAL)
            _throw_errno("socket", errno)
        end
        # Older kernels may not support atomic SOCK_NONBLOCK/SOCK_CLOEXEC.
        fd = @ccall gc_safe = true socket(Cint(family)::Cint, raw_type::Cint, Cint(proto)::Cint)::Cint
        fd == -1 && _throw_errno("socket", _errno_i32())
        try
            set_close_on_exec!(fd)
            set_nonblocking!(fd, true)
        catch
            close_socket_nothrow(fd)
            rethrow()
        end
    end
    return fd
end

"""
    close_socket_nothrow(fd)

Best-effort close that returns `0` for success/consumed close errors and
`EBADF` when the descriptor is invalid.
"""
function close_socket_nothrow(fd::Cint)::Int32
    ret = @ccall close(fd::Cint)::Cint
    ret == 0 && return Int32(0)
    errno = _errno_i32()
    # Linux also deallocates the descriptor on most close errors.
    errno == Int32(Base.Libc.EBADF) && return errno
    return Int32(0)
end

"""
    close_socket(fd)

Close a socket descriptor or throw on failure.
"""
function close_socket(fd::Cint)
    errno = close_socket_nothrow(fd)
    errno == Int32(0) && return nothing
    _throw_errno("close", errno)
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
    while true
        ret = @ccall gc_safe = true bind(fd::Cint, addr::Ptr{Cvoid}, addrlen::SockLen)::Cint
        ret == 0 && return nothing
        errno = _errno_i32()
        errno == Int32(Base.Libc.EINTR) && continue
        _throw_errno("bind", errno)
    end
end

function listen_socket(fd::Cint, backlog::Integer)
    while true
        ret = @ccall gc_safe = true listen(fd::Cint, Cint(backlog)::Cint)::Cint
        ret == 0 && return nothing
        errno = _errno_i32()
        errno == Int32(Base.Libc.EINTR) && continue
        _throw_errno("listen", errno)
    end
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
    # Exposes raw errno (e.g. EINPROGRESS) so upper layers can drive connect via poll.
    ret = @ccall gc_safe = true connect(fd::Cint, addr::Ptr{Cvoid}, addrlen::SockLen)::Cint
    ret == 0 && return Int32(0)
    return _errno_i32()
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

function _try_accept_socket_accept4(fd::Cint)::Tuple{Cint, AcceptPeer, Int32}
    addrbuf = Ref{NTuple{_ACCEPT_ADDRBUF_LEN, UInt8}}()
    addrlen = Ref{SockLen}(SockLen(_ACCEPT_ADDRBUF_LEN))
    flags = Cint(_SOCK_NONBLOCK | _SOCK_CLOEXEC)
    newfd = GC.@preserve addrbuf begin
        @ccall gc_safe = true accept4(
            fd::Cint,
            Base.unsafe_convert(Ptr{Cvoid}, addrbuf)::Ptr{Cvoid},
            addrlen::Ref{SockLen},
            flags::Cint,
        )::Cint
    end
    newfd == -1 && return Cint(-1), nothing, _errno_i32()
    peer = GC.@preserve addrbuf begin
        addrptr = Ptr{UInt8}(Base.unsafe_convert(Ptr{NTuple{_ACCEPT_ADDRBUF_LEN, UInt8}}, addrbuf))
        _decode_accept_peer(addrptr, addrlen[])
    end
    return newfd, peer, Int32(0)
end

function _try_accept_socket_fallback(fd::Cint)::Tuple{Cint, AcceptPeer, Int32}
    addrbuf = Ref{NTuple{_ACCEPT_ADDRBUF_LEN, UInt8}}()
    addrlen = Ref{SockLen}(SockLen(_ACCEPT_ADDRBUF_LEN))
    newfd = GC.@preserve addrbuf begin
        @ccall gc_safe = true accept(
            fd::Cint,
            Base.unsafe_convert(Ptr{Cvoid}, addrbuf)::Ptr{Cvoid},
            addrlen::Ref{SockLen},
        )::Cint
    end
    newfd == -1 && return Cint(-1), nothing, _errno_i32()
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

"""
    try_accept_socket(fd)

Perform one non-blocking `accept` attempt and return `(newfd, peer, errno)`.
"""
function try_accept_socket(fd::Cint)::Tuple{Cint, AcceptPeer, Int32}
    state = _accept4_state[]
    if state != _ACCEPT4_DISABLED
        newfd, peer, errno = _try_accept_socket_accept4(fd)
        if newfd != Cint(-1)
            _accept4_state[] = _ACCEPT4_ENABLED
            return newfd, peer, Int32(0)
        end
        if errno != Int32(Base.Libc.ENOSYS) && errno != Int32(Base.Libc.EINVAL)
            _accept4_state[] = _ACCEPT4_ENABLED
            return Cint(-1), nothing, errno
        end
        _accept4_state[] = _ACCEPT4_DISABLED
    end
    return _try_accept_socket_fallback(fd)
end

"""
    accept_socket(fd)

Accept a connection or throw `SystemError` on failure.
"""
function accept_socket(fd::Cint)::Cint
    newfd, _, errno = try_accept_socket(fd)
    newfd != -1 && return newfd
    _throw_errno("accept", errno)
end

function get_sockopt_int(fd::Cint, level::Cint, optname::Cint)::Int32
    value = Ref{Cint}(0)
    optlen = Ref{SockLen}(SockLen(sizeof(Cint)))
    while true
        ret = @ccall getsockopt(
            fd::Cint,
            level::Cint,
            optname::Cint,
            value::Ref{Cint},
            optlen::Ref{SockLen},
        )::Cint
        ret == 0 && return Int32(value[])
        errno = _errno_i32()
        errno == Int32(Base.Libc.EINTR) && continue
        _throw_errno("getsockopt", errno)
    end
end

function set_sockopt_int(fd::Cint, level::Cint, optname::Cint, value::Integer)
    raw = Ref{Cint}(Cint(value))
    while true
        ret = @ccall setsockopt(
            fd::Cint,
            level::Cint,
            optname::Cint,
            raw::Ref{Cint},
            SockLen(sizeof(Cint))::SockLen,
        )::Cint
        ret == 0 && return nothing
        errno = _errno_i32()
        errno == Int32(Base.Libc.EINTR) && continue
        _throw_errno("setsockopt", errno)
    end
end

function get_socket_error(fd::Cint)::Int32
    return get_sockopt_int(fd, SOL_SOCKET, SO_ERROR)
end

function get_socket_name_in(fd::Cint)::SockAddrIn
    addr = Ref{SockAddrIn}()
    addrlen = Ref{SockLen}(SockLen(sizeof(SockAddrIn)))
    while true
        ret = @ccall getsockname(fd::Cint, addr::Ref{SockAddrIn}, addrlen::Ref{SockLen})::Cint
        ret == 0 && return addr[]
        errno = _errno_i32()
        errno == Int32(Base.Libc.EINTR) && continue
        _throw_errno("getsockname", errno)
    end
end

function get_socket_name_in6(fd::Cint)::SockAddrIn6
    addr = Ref{SockAddrIn6}()
    addrlen = Ref{SockLen}(SockLen(sizeof(SockAddrIn6)))
    while true
        ret = @ccall getsockname(fd::Cint, addr::Ref{SockAddrIn6}, addrlen::Ref{SockLen})::Cint
        ret == 0 && return addr[]
        errno = _errno_i32()
        errno == Int32(Base.Libc.EINTR) && continue
        _throw_errno("getsockname", errno)
    end
end

function get_peer_name_in(fd::Cint)::SockAddrIn
    addr = Ref{SockAddrIn}()
    addrlen = Ref{SockLen}(SockLen(sizeof(SockAddrIn)))
    while true
        ret = @ccall getpeername(fd::Cint, addr::Ref{SockAddrIn}, addrlen::Ref{SockLen})::Cint
        ret == 0 && return addr[]
        errno = _errno_i32()
        errno == Int32(Base.Libc.EINTR) && continue
        _throw_errno("getpeername", errno)
    end
end

function get_peer_name_in6(fd::Cint)::SockAddrIn6
    addr = Ref{SockAddrIn6}()
    addrlen = Ref{SockLen}(SockLen(sizeof(SockAddrIn6)))
    while true
        ret = @ccall getpeername(fd::Cint, addr::Ref{SockAddrIn6}, addrlen::Ref{SockLen})::Cint
        ret == 0 && return addr[]
        errno = _errno_i32()
        errno == Int32(Base.Libc.EINTR) && continue
        _throw_errno("getpeername", errno)
    end
end

function shutdown_socket(fd::Cint, how::Integer)
    while true
        ret = @ccall gc_safe = true shutdown(fd::Cint, Cint(how)::Cint)::Cint
        ret == 0 && return nothing
        errno = _errno_i32()
        errno == Int32(Base.Libc.EINTR) && continue
        _throw_errno("shutdown", errno)
    end
end

function read_once!(fd::Cint, ptr::Ptr{UInt8}, nbytes::Csize_t)::Cssize_t
    # Single read syscall with EINTR retry; caller owns EAGAIN and short-read handling.
    while true
        n = @ccall gc_safe = true read(fd::Cint, ptr::Ptr{UInt8}, nbytes::Csize_t)::Cssize_t
        if n == -1
            _errno_i32() == Int32(Base.Libc.EINTR) && continue
        end
        return n
    end
end

function write_once!(fd::Cint, ptr::Ptr{UInt8}, nbytes::Csize_t)::Cssize_t
    # Single write syscall with EINTR retry; caller owns EAGAIN and short-write handling.
    while true
        n = @ccall gc_safe = true write(fd::Cint, ptr::Ptr{UInt8}, nbytes::Csize_t)::Cssize_t
        if n == -1
            _errno_i32() == Int32(Base.Libc.EINTR) && continue
        end
        return n
    end
end

function recv_from!(
        fd::Cint,
        ptr::Ptr{UInt8},
        nbytes::Csize_t,
        flags::Cint = Cint(0),
        from::Ptr{Cvoid} = Ptr{Cvoid}(C_NULL),
        fromlen::Ptr{SockLen} = Ptr{SockLen}(C_NULL),
    )::Cssize_t
    while true
        n = @ccall gc_safe = true recvfrom(
            fd::Cint,
            ptr::Ptr{UInt8},
            nbytes::Csize_t,
            flags::Cint,
            from::Ptr{Cvoid},
            fromlen::Ptr{SockLen},
        )::Cssize_t
        if n == -1
            _errno_i32() == Int32(Base.Libc.EINTR) && continue
        end
        return n
    end
end

function send_to!(
        fd::Cint,
        ptr::Ptr{UInt8},
        nbytes::Csize_t,
        flags::Cint = Cint(0),
        to::Ptr{Cvoid} = C_NULL,
        tolen::SockLen = SockLen(0),
    )::Cssize_t
    while true
        n = @ccall gc_safe = true sendto(
            fd::Cint,
            ptr::Ptr{UInt8},
            nbytes::Csize_t,
            flags::Cint,
            to::Ptr{Cvoid},
            tolen::SockLen,
        )::Cssize_t
        if n == -1
            _errno_i32() == Int32(Base.Libc.EINTR) && continue
        end
        return n
    end
end

function recv_msg!(fd::Cint, msg::Ref{MsgHdr}, flags::Cint = Cint(0))::Cssize_t
    while true
        n = @ccall gc_safe = true recvmsg(fd::Cint, msg::Ref{MsgHdr}, flags::Cint)::Cssize_t
        if n == -1
            _errno_i32() == Int32(Base.Libc.EINTR) && continue
        end
        return n
    end
end

function send_msg!(fd::Cint, msg::Ref{MsgHdr}, flags::Cint = Cint(0))::Cssize_t
    while true
        n = @ccall gc_safe = true sendmsg(fd::Cint, msg::Ref{MsgHdr}, flags::Cint)::Cssize_t
        if n == -1
            _errno_i32() == Int32(Base.Libc.EINTR) && continue
        end
        return n
    end
end
