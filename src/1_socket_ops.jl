"""
    SocketOps

Cross-platform socket syscall facade and sockaddr helpers.

This module is intentionally lower level than `TCP`: it exposes thin wrappers
around the OS socket APIs, normalizes the most important portability differences,
and leaves policy decisions to higher layers.

A few conventions are worth keeping in mind when reading the code:
- successful mutating operations usually return `nothing`
- operations that need to preserve transient errno values often return the raw
  integer error code instead of throwing immediately
- wrappers aim to look POSIX-like even on Windows so the polling and transport
  layers can share most control flow
- address helpers always build or decode structs in network byte order so callers
  can treat the Julia-level tuples as ordinary host-order values
"""
module SocketOps

using ..Reseau: @gcsafe_ccall

const SockLen = @static Sys.iswindows() ? Cint : UInt32

const AF_UNIX = Cint(1)
const AF_INET = Cint(2)
const AF_INET6 = @static Sys.iswindows() ? Cint(23) : Sys.islinux() ? Cint(10) : Cint(30)

const SOCK_STREAM = Cint(1)
const SOCK_DGRAM = Cint(2)

const SHUT_RD = Cint(0)
const SHUT_WR = Cint(1)
const SHUT_RDWR = Cint(2)
const MSG_PEEK = Cint(0x02)

const SOL_SOCKET = @static Sys.islinux() ? Cint(1) : Cint(0xffff)
const IPPROTO_TCP = Cint(6)
const SO_ERROR = @static Sys.islinux() ? Cint(0x0004) : Cint(0x1007)
const SO_REUSEADDR = @static Sys.islinux() ? Cint(0x0002) : Cint(0x0004)
const SO_KEEPALIVE = @static Sys.islinux() ? Cint(0x0009) : Cint(0x0008)
const TCP_NODELAY = Cint(0x01)

@static if Sys.isapple()
    """
    Darwin-compatible `sockaddr_in` for IPv4 operations.
    """
    struct SockAddrIn
        sin_len::UInt8
        sin_family::UInt8
        sin_port::UInt16
        sin_addr::UInt32
        sin_zero::NTuple{8, UInt8}
    end

    """
    Darwin-compatible `sockaddr_in6` for IPv6 operations.
    """
    struct SockAddrIn6
        sin6_len::UInt8
        sin6_family::UInt8
        sin6_port::UInt16
        sin6_flowinfo::UInt32
        sin6_addr::NTuple{16, UInt8}
        sin6_scope_id::UInt32
    end
elseif Sys.islinux()
    """
    Linux-compatible `sockaddr_in` for IPv4 operations.
    """
    struct SockAddrIn
        sin_family::UInt16
        sin_port::UInt16
        sin_addr::UInt32
        sin_zero::NTuple{8, UInt8}
    end

    """
    Linux-compatible `sockaddr_in6` for IPv6 operations.
    """
    struct SockAddrIn6
        sin6_family::UInt16
        sin6_port::UInt16
        sin6_flowinfo::UInt32
        sin6_addr::NTuple{16, UInt8}
        sin6_scope_id::UInt32
    end
else
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
end

"""
Darwin-compatible `struct iovec`.
"""
struct IOVec
    iov_base::Ptr{Cvoid}
    iov_len::Csize_t
end

@static if Sys.islinux()
    """
    Linux-compatible `struct msghdr`.
    """
    struct MsgHdr
        msg_name::Ptr{Cvoid}
        msg_namelen::SockLen
        msg_iov::Ptr{IOVec}
        msg_iovlen::Csize_t
        msg_control::Ptr{Cvoid}
        msg_controllen::Csize_t
        msg_flags::Cint
    end
else
    """
    Darwin-compatible `struct msghdr`.
    """
    struct MsgHdr
        msg_name::Ptr{Cvoid}
        msg_namelen::SockLen
        msg_iov::Ptr{IOVec}
        msg_iovlen::Cint
        msg_control::Ptr{Cvoid}
        msg_controllen::SockLen
        msg_flags::Cint
    end
end

const AcceptPeer = Union{Nothing, SockAddrIn, SockAddrIn6}

@inline function _is_little_endian()::Bool
    return Base.ENDIAN_BOM == 0x04030201
end

@inline function _hton16(v::UInt16)::UInt16
    _is_little_endian() && return bswap(v)
    return v
end

@inline function _ntoh16(v::UInt16)::UInt16
    _is_little_endian() && return bswap(v)
    return v
end

@inline function _hton32(v::UInt32)::UInt32
    _is_little_endian() && return bswap(v)
    return v
end

@inline function _ntoh32(v::UInt32)::UInt32
    _is_little_endian() && return bswap(v)
    return v
end

@inline function _port_u16(port::Integer)::UInt16
    (port < 0 || port > 0xffff) && throw(ArgumentError("port must be in [0, 65535]"))
    return UInt16(port)
end

@inline function _ipv4_u32(ip::NTuple{4, UInt8})::UInt32
    return (UInt32(ip[1]) << 24) | (UInt32(ip[2]) << 16) | (UInt32(ip[3]) << 8) | UInt32(ip[4])
end

@inline function _byte_u8(v::Integer)::UInt8
    (v < 0 || v > 0xff) && throw(ArgumentError("IPv4 octets must be in [0, 255]"))
    return UInt8(v)
end

"""
    sockaddr_in(ip::NTuple{4,UInt8}, port) -> SockAddrIn

Build a platform-compatible `sockaddr_in` from an IPv4 address tuple and port.

`ip` is interpreted in presentation order, for example `(127, 0, 0, 1)`.
`port` is validated to be in `[0, 65535]` and converted to network byte order
inside the returned struct.

Throws `ArgumentError` if the port is out of range.
"""
function sockaddr_in(ip::NTuple{4, UInt8}, port::Integer)::SockAddrIn
    p = _hton16(_port_u16(port))
    @static if Sys.isapple()
        return SockAddrIn(
            UInt8(sizeof(SockAddrIn)),
            UInt8(AF_INET),
            p,
            _hton32(_ipv4_u32(ip)),
            ntuple(_ -> UInt8(0), 8),
        )
    else
        return SockAddrIn(
            UInt16(AF_INET),
            p,
            _hton32(_ipv4_u32(ip)),
            ntuple(_ -> UInt8(0), 8),
        )
    end
end

function sockaddr_in(ip::NTuple{4, <:Integer}, port::Integer)::SockAddrIn
    return sockaddr_in((_byte_u8(ip[1]), _byte_u8(ip[2]), _byte_u8(ip[3]), _byte_u8(ip[4])), port)
end

"""
    sockaddr_in_loopback(port) -> SockAddrIn

Convenience constructor for `127.0.0.1:port`.
"""
function sockaddr_in_loopback(port::Integer)::SockAddrIn
    return sockaddr_in((UInt8(127), UInt8(0), UInt8(0), UInt8(1)), port)
end

"""
    sockaddr_in_any(port) -> SockAddrIn

Convenience constructor for `0.0.0.0:port`, typically used for wildcard binds.
"""
function sockaddr_in_any(port::Integer)::SockAddrIn
    return sockaddr_in((UInt8(0), UInt8(0), UInt8(0), UInt8(0)), port)
end

"""
    sockaddr_in6(ip::NTuple{16,UInt8}, port; flowinfo=0, scope_id=0) -> SockAddrIn6

Build a platform-compatible `sockaddr_in6` from an IPv6 address tuple and port.

`scope_id` is preserved for scoped addresses such as link-local endpoints and
`flowinfo` is exposed for completeness even though higher layers usually leave it
as zero.

Throws `ArgumentError` if the port, `flowinfo`, or `scope_id` is out of range.
"""
function sockaddr_in6(
        ip::NTuple{16, UInt8},
        port::Integer;
        flowinfo::Integer = 0,
        scope_id::Integer = 0,
    )::SockAddrIn6
    (flowinfo < 0 || flowinfo > typemax(UInt32)) && throw(ArgumentError("flowinfo must be in [0, 2^32-1]"))
    (scope_id < 0 || scope_id > typemax(UInt32)) && throw(ArgumentError("scope_id must be in [0, 2^32-1]"))
    p = _hton16(_port_u16(port))
    @static if Sys.isapple()
        return SockAddrIn6(
            UInt8(sizeof(SockAddrIn6)),
            UInt8(AF_INET6),
            p,
            _hton32(UInt32(flowinfo)),
            ip,
            UInt32(scope_id),
        )
    else
        return SockAddrIn6(
            UInt16(AF_INET6),
            p,
            _hton32(UInt32(flowinfo)),
            ip,
            UInt32(scope_id),
        )
    end
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

"""
    sockaddr_in6_loopback(port; scope_id=0) -> SockAddrIn6

Convenience constructor for the IPv6 loopback address `[::1]:port`.
"""
function sockaddr_in6_loopback(port::Integer; scope_id::Integer = 0)::SockAddrIn6
    return sockaddr_in6((
            UInt8(0), UInt8(0), UInt8(0), UInt8(0),
            UInt8(0), UInt8(0), UInt8(0), UInt8(0),
            UInt8(0), UInt8(0), UInt8(0), UInt8(0),
            UInt8(0), UInt8(0), UInt8(0), UInt8(1),
        ),
        port;
        scope_id = scope_id,
    )
end

"""
    sockaddr_in6_any(port; scope_id=0) -> SockAddrIn6

Convenience constructor for the IPv6 wildcard bind address `[::]:port`.
"""
function sockaddr_in6_any(port::Integer; scope_id::Integer = 0)::SockAddrIn6
    return sockaddr_in6(ntuple(_ -> UInt8(0), 16), port; scope_id = scope_id)
end

"""
    sockaddr_in_port(addr) -> UInt16

Decode the IPv4 port from `addr` into host byte order.
"""
@inline function sockaddr_in_port(addr::SockAddrIn)::UInt16
    return _ntoh16(addr.sin_port)
end

"""
    sockaddr_in_ip(addr)

Extract an IPv4 address tuple from a `sockaddr_in`.
"""
@inline function sockaddr_in_ip(addr::SockAddrIn)::NTuple{4, UInt8}
    host_ip = _ntoh32(addr.sin_addr)
    return (
        UInt8((host_ip >> 24) & 0xff),
        UInt8((host_ip >> 16) & 0xff),
        UInt8((host_ip >> 8) & 0xff),
        UInt8(host_ip & 0xff),
    )
end

@inline function sockaddr_in6_port(addr::SockAddrIn6)::UInt16
    return _ntoh16(addr.sin6_port)
end

"""
    sockaddr_in6_ip(addr) -> NTuple{16,UInt8}

Decode the raw IPv6 address bytes from `addr`.
"""
@inline function sockaddr_in6_ip(addr::SockAddrIn6)::NTuple{16, UInt8}
    return addr.sin6_addr
end

"""
    sockaddr_in6_scopeid(addr) -> UInt32

Return the IPv6 scope id stored in `addr`.
"""
@inline function sockaddr_in6_scopeid(addr::SockAddrIn6)::UInt32
    return addr.sin6_scope_id
end

@inline function _throw_enosys(op::AbstractString)
    throw(SystemError(op, Int(Base.Libc.ENOSYS)))
end

@static if Sys.isapple()
include("socket_ops/darwin.jl")
elseif Sys.islinux()
include("socket_ops/linux.jl")
elseif Sys.iswindows()
include("socket_ops/windows.jl")
else

# Unsupported platforms keep the same API surface but fail eagerly with ENOSYS.
# This lets trim/smoke tests and higher-level code compile while still making the
# lack of backend support obvious at runtime.

function fd_is_cloexec(fd::Cint)::Bool
    _ = fd
    _throw_enosys("fcntl(F_GETFD)")
end

function fd_is_nonblocking(fd::Cint)::Bool
    _ = fd
    _throw_enosys("fcntl(F_GETFL)")
end

function set_close_on_exec!(fd::Cint)
    _ = fd
    _throw_enosys("fcntl(F_SETFD)")
end

function set_nonblocking!(fd::Cint, enabled::Bool = true)
    _ = fd
    _ = enabled
    _throw_enosys("ioctl(FIONBIO)")
end

function open_socket(family::Integer, sotype::Integer, proto::Integer = 0)::Cint
    _ = family
    _ = sotype
    _ = proto
    _throw_enosys("socket")
end

function close_socket_nothrow(fd::Cint)::Int32
    _ = fd
    return Int32(Base.Libc.ENOSYS)
end

function close_socket(fd::Cint)
    _ = fd
    _throw_enosys("close")
end

function bind_socket(fd::Cint, addr::SockAddrIn)
    _ = fd
    _ = addr
    _throw_enosys("bind")
end

function bind_socket(fd::Cint, addr::SockAddrIn6)
    _ = fd
    _ = addr
    _throw_enosys("bind")
end

function bind_socket(fd::Cint, addr::Ptr{Cvoid}, addrlen::SockLen)
    _ = fd
    _ = addr
    _ = addrlen
    _throw_enosys("bind")
end

function listen_socket(fd::Cint, backlog::Integer)
    _ = fd
    _ = backlog
    _throw_enosys("listen")
end

function connect_socket(fd::Cint, addr::SockAddrIn)::Int32
    _ = fd
    _ = addr
    return Int32(Base.Libc.ENOSYS)
end

function connect_socket(fd::Cint, addr::SockAddrIn6)::Int32
    _ = fd
    _ = addr
    return Int32(Base.Libc.ENOSYS)
end

function connect_socket(fd::Cint, addr::Ptr{Cvoid}, addrlen::SockLen)::Int32
    _ = fd
    _ = addr
    _ = addrlen
    return Int32(Base.Libc.ENOSYS)
end

function try_accept_socket(fd::Cint)::Tuple{Cint, AcceptPeer, Int32}
    _ = fd
    return Cint(-1), nothing, Int32(Base.Libc.ENOSYS)
end

function accept_socket(fd::Cint)::Cint
    _ = fd
    _throw_enosys("accept")
end

function get_sockopt_int(fd::Cint, level::Cint, optname::Cint)::Int32
    _ = fd
    _ = level
    _ = optname
    _throw_enosys("getsockopt")
end

function set_sockopt_int(fd::Cint, level::Cint, optname::Cint, value::Integer)
    _ = fd
    _ = level
    _ = optname
    _ = value
    _throw_enosys("setsockopt")
end

function get_socket_error(fd::Cint)::Int32
    _ = fd
    _throw_enosys("getsockopt")
end

function get_socket_name_in(fd::Cint)::SockAddrIn
    _ = fd
    _throw_enosys("getsockname")
end

function get_socket_name_in6(fd::Cint)::SockAddrIn6
    _ = fd
    _throw_enosys("getsockname")
end

function get_peer_name_in(fd::Cint)::SockAddrIn
    _ = fd
    _throw_enosys("getpeername")
end

function get_peer_name_in6(fd::Cint)::SockAddrIn6
    _ = fd
    _throw_enosys("getpeername")
end

function shutdown_socket(fd::Cint, how::Integer)
    _ = fd
    _ = how
    _throw_enosys("shutdown")
end

function read_once!(fd::Cint, ptr::Ptr{UInt8}, nbytes::Csize_t)::Cssize_t
    _ = fd
    _ = ptr
    _ = nbytes
    _throw_enosys("read")
end

function write_once!(fd::Cint, ptr::Ptr{UInt8}, nbytes::Csize_t)::Cssize_t
    _ = fd
    _ = ptr
    _ = nbytes
    _throw_enosys("write")
end

function recv_from!(
        fd::Cint,
        ptr::Ptr{UInt8},
        nbytes::Csize_t,
        flags::Cint = Cint(0),
        from::Ptr{Cvoid} = Ptr{Cvoid}(C_NULL),
        fromlen::Ptr{SockLen} = Ptr{SockLen}(C_NULL),
    )::Cssize_t
    _ = fd
    _ = ptr
    _ = nbytes
    _ = flags
    _ = from
    _ = fromlen
    _throw_enosys("recvfrom")
end

function send_to!(
        fd::Cint,
        ptr::Ptr{UInt8},
        nbytes::Csize_t,
        flags::Cint = Cint(0),
        to::Ptr{Cvoid} = C_NULL,
        tolen::SockLen = SockLen(0),
    )::Cssize_t
    _ = fd
    _ = ptr
    _ = nbytes
    _ = flags
    _ = to
    _ = tolen
    _throw_enosys("sendto")
end

function recv_msg!(fd::Cint, msg::Ref{MsgHdr}, flags::Cint = Cint(0))::Cssize_t
    _ = fd
    _ = msg
    _ = flags
    _throw_enosys("recvmsg")
end

function send_msg!(fd::Cint, msg::Ref{MsgHdr}, flags::Cint = Cint(0))::Cssize_t
    _ = fd
    _ = msg
    _ = flags
    _throw_enosys("sendmsg")
end

end

end
