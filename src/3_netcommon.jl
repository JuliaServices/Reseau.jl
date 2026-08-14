"""
    NetCommon

Shared socket-address types and the internal `FD` (netFD) owner used by the
`TCP` and `UDP` transport layers.

This mirrors Go's `net` package structure, where one `netFD` and one set of
sockaddr conversion helpers back every socket type. Public API surfaces live in
`TCP` and `UDP`; those modules re-expose the address types defined here so the
documented names (`TCP.SocketAddrV4`, ...) keep working unchanged.
"""
module NetCommon

using ..Reseau.IOPoll
using ..Reseau.SocketOps

"""
    SocketAddr

Abstract network endpoint type for socket addresses.
"""
abstract type SocketAddr end

"""
    SocketAddrV4

IPv4 endpoint snapshot.

The address bytes are stored in presentation order and the port is stored in
host byte order. Conversion to platform sockaddr structs happens lazily when a
socket operation actually needs one.
"""
struct SocketAddrV4 <: SocketAddr
    ip::NTuple{4, UInt8}
    port::UInt16
    function SocketAddrV4(ip::NTuple{4, UInt8}, port::Integer)
        (port < 0 || port > 0xffff) && throw(ArgumentError("port must be in [0, 65535]"))
        return new(ip, UInt16(port))
    end
end

"""
    SocketAddrV6

IPv6 endpoint snapshot.

`scope_id` is used for scoped link-local addresses and is preserved all the way
down to the platform sockaddr representation so bind/connect can target the same
interface the caller selected.
"""
struct SocketAddrV6 <: SocketAddr
    ip::NTuple{16, UInt8}
    port::UInt16
    scope_id::UInt32
    function SocketAddrV6(ip::NTuple{16, UInt8}, port::Integer; scope_id::Integer = 0)
        (port < 0 || port > 0xffff) && throw(ArgumentError("port must be in [0, 65535]"))
        (scope_id < 0 || scope_id > typemax(UInt32)) && throw(ArgumentError("scope_id must be in [0, 2^32-1]"))
        return new(ip, UInt16(port), UInt32(scope_id))
    end
end

const SocketEndpoint = Union{SocketAddrV4, SocketAddrV6}

function SocketAddrV4(ip::NTuple{4, <:Integer}, port::Integer)
    return SocketAddrV4((UInt8(ip[1]), UInt8(ip[2]), UInt8(ip[3]), UInt8(ip[4])), port)
end

function SocketAddrV6(ip::NTuple{16, <:Integer}, port::Integer; scope_id::Integer = 0)
    return SocketAddrV6((
            UInt8(ip[1]), UInt8(ip[2]), UInt8(ip[3]), UInt8(ip[4]),
            UInt8(ip[5]), UInt8(ip[6]), UInt8(ip[7]), UInt8(ip[8]),
            UInt8(ip[9]), UInt8(ip[10]), UInt8(ip[11]), UInt8(ip[12]),
            UInt8(ip[13]), UInt8(ip[14]), UInt8(ip[15]), UInt8(ip[16]),
        ),
        port;
        scope_id = scope_id,
    )
end

"""
    loopback_addr(port) -> SocketAddrV4

Convenience constructor for `127.0.0.1:port`.
"""
function loopback_addr(port::Integer)::SocketAddrV4
    return SocketAddrV4((UInt8(127), UInt8(0), UInt8(0), UInt8(1)), port)
end

"""
    any_addr(port) -> SocketAddrV4

Convenience constructor for `0.0.0.0:port`, typically used for wildcard binds.
"""
function any_addr(port::Integer)::SocketAddrV4
    return SocketAddrV4((UInt8(0), UInt8(0), UInt8(0), UInt8(0)), port)
end

"""
    loopback_addr6(port; scope_id=0) -> SocketAddrV6

Convenience constructor for `[::1]:port`.
"""
function loopback_addr6(port::Integer; scope_id::Integer = 0)::SocketAddrV6
    return SocketAddrV6((
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
    any_addr6(port; scope_id=0) -> SocketAddrV6

Convenience constructor for the IPv6 wildcard bind address `[::]:port`.
"""
function any_addr6(port::Integer; scope_id::Integer = 0)::SocketAddrV6
    return SocketAddrV6((
            UInt8(0), UInt8(0), UInt8(0), UInt8(0),
            UInt8(0), UInt8(0), UInt8(0), UInt8(0),
            UInt8(0), UInt8(0), UInt8(0), UInt8(0),
            UInt8(0), UInt8(0), UInt8(0), UInt8(0),
        ),
        port;
        scope_id = scope_id,
    )
end

function _format_ipv6(ip::NTuple{16, UInt8})::String
    groups = UInt16[]
    for i in 1:8
        hi = UInt16(ip[(2 * i) - 1])
        lo = UInt16(ip[2 * i])
        push!(groups, (hi << 8) | lo)
    end
    best_start = 0
    best_len = 0
    i = 1
    while i <= length(groups)
        if groups[i] == 0
            j = i
            while j <= length(groups) && groups[j] == 0
                j += 1
            end
            run_len = j - i
            if run_len > best_len && run_len >= 2
                best_start = i
                best_len = run_len
            end
            i = j
        else
            i += 1
        end
    end
    if best_len >= 2
        left = [string(groups[idx], base = 16) for idx in 1:(best_start - 1)]
        right_start = best_start + best_len
        right = [string(groups[idx], base = 16) for idx in right_start:length(groups)]
        if isempty(left) && isempty(right)
            return "::"
        elseif isempty(left)
            return "::" * join(right, ":")
        elseif isempty(right)
            return join(left, ":") * "::"
        else
            return join(left, ":") * "::" * join(right, ":")
        end
    end
    return join((string(group, base = 16) for group in groups), ":")
end

function Base.show(io::IO, addr::SocketAddrV4)
    print(io, string(addr))
    return nothing
end

function Base.show(io::IO, addr::SocketAddrV6)
    print(io, string(addr))
    return nothing
end

function Base.string(addr::SocketAddrV4)
    return "$(addr.ip[1]).$(addr.ip[2]).$(addr.ip[3]).$(addr.ip[4]):$(addr.port)"
end

function Base.string(addr::SocketAddrV6)
    if addr.scope_id != 0
        return "[$(_format_ipv6(addr.ip))%$(addr.scope_id)]:$(addr.port)"
    end
    return "[$(_format_ipv6(addr.ip))]:$(addr.port)"
end

"""
    FD

Internal socket owner built on `IOPoll.FD`.

This is the internal object that owns the actual socket. Public callers usually
interact with the `TCP`/`UDP` connection and listener types, but the transport
implementations keep the extra metadata here so they can cache local/remote
addresses, remember the socket family and type, and share
shutdown/close/deadline behavior with the poll layer.
"""
mutable struct FD
    pfd::IOPoll.FD
    family::Cint
    sotype::Cint
    net::Symbol
    @atomic is_connected::Bool
    laddr::Union{Nothing, SocketAddr}
    raddr::Union{Nothing, SocketAddr}
end

@inline _addr_family(::SocketAddrV4)::Cint = SocketOps.AF_INET
@inline _addr_family(::SocketAddrV6)::Cint = SocketOps.AF_INET6

@inline function _to_sockaddr(addr::SocketAddrV4)::SocketOps.SockAddrIn
    return SocketOps.sockaddr_in(addr.ip, Int(addr.port))
end

@inline function _to_sockaddr(addr::SocketAddrV6)::SocketOps.SockAddrIn6
    return SocketOps.sockaddr_in6(addr.ip, Int(addr.port); scope_id = Int(addr.scope_id))
end

@inline function _from_sockaddr(addr::SocketOps.SockAddrIn)::SocketAddrV4
    return SocketAddrV4(SocketOps.sockaddr_in_ip(addr), Int(SocketOps.sockaddr_in_port(addr)))
end

@inline function _from_sockaddr(addr::SocketOps.SockAddrIn6)::SocketAddrV6
    return SocketAddrV6(
        SocketOps.sockaddr_in6_ip(addr),
        Int(SocketOps.sockaddr_in6_port(addr));
        scope_id = Int(SocketOps.sockaddr_in6_scopeid(addr)),
    )
end

@inline function _is_temporary_unconnected(err::SystemError)::Bool
    return err.errnum == Int(Base.Libc.ENOTCONN) || err.errnum == Int(Base.Libc.EINVAL)
end

function _new_netfd(
        sysfd::SocketOps.SocketFD;
        family::Cint = SocketOps.AF_INET,
        sotype::Cint = SocketOps.SOCK_STREAM,
        net::Symbol = :tcp,
        is_connected::Bool = false,
    )::FD
    # Stream sockets chunk large transfers and treat zero-byte reads as EOF;
    # datagram sockets do neither (an empty datagram is valid data).
    is_stream = sotype == SocketOps.SOCK_STREAM
    pfd = IOPoll.FD(sysfd; is_stream = is_stream, zero_read_is_eof = is_stream, is_file = false)
    return FD(pfd, family, sotype, net, is_connected, nothing, nothing)
end

"""
    open_net_fd!(; family=AF_INET, sotype=SOCK_STREAM, net=:tcp)

Open a non-blocking, close-on-exec socket of the requested family and type and
wrap it in `FD`.

The returned descriptor is not yet registered with `IOPoll`; callers that plan
to issue readiness-driven operations should call `IOPoll.register!` before use.
Throws `SystemError` on socket creation failure.
"""
function open_net_fd!(;
        family::Cint = SocketOps.AF_INET,
        sotype::Cint = SocketOps.SOCK_STREAM,
        net::Symbol = :tcp,
    )::FD
    sysfd = SocketOps.open_socket(family, sotype)
    return _new_netfd(sysfd; family = family, sotype = sotype, net = net, is_connected = false)
end

function _set_local_addr!(fd::FD)
    if fd.family == SocketOps.AF_INET6
        fd.laddr = _from_sockaddr(SocketOps.get_socket_name_in6(fd.pfd.sysfd))
        return nothing
    end
    fd.laddr = _from_sockaddr(SocketOps.get_socket_name_in(fd.pfd.sysfd))
    return nothing
end

function _set_remote_addr!(fd::FD)
    if fd.family == SocketOps.AF_INET6
        fd.raddr = _from_sockaddr(SocketOps.get_peer_name_in6(fd.pfd.sysfd))
        return nothing
    end
    fd.raddr = _from_sockaddr(SocketOps.get_peer_name_in(fd.pfd.sysfd))
    return nothing
end

function _finalize_connected_addrs!(fd::FD, fallback_remote::SocketAddr)
    # `getpeername` can lag slightly behind the moment the kernel considers a
    # non-blocking connect complete. We optimistically refresh both ends, but
    # fall back to the requested remote address when the peer lookup is only
    # temporarily unavailable.
    _set_local_addr!(fd)
    if fd.raddr === nothing
        try
            _set_remote_addr!(fd)
        catch err
            if !(err isa SystemError) || !_is_temporary_unconnected(err)
                rethrow(err)
            end
            fd.raddr = fallback_remote
        end
    end
    @atomic :release fd.is_connected = true
    return nothing
end

@inline function _set_ipv6_only!(fd::FD, enabled::Bool)
    @static if Sys.isopenbsd() || Sys.isdragonfly()
        # These kernels enforce IPv6-only sockets and reject attempts to change
        # IPV6_V6ONLY. This is the same capability exception Go applies.
        return nothing
    else
        try
            SocketOps.set_sockopt_int(
                fd.pfd.sysfd,
                SocketOps.IPPROTO_IPV6,
                SocketOps.IPV6_V6ONLY,
                enabled ? 1 : 0,
            )
        catch err
            ex = err::Exception
            # Go parity: some operating systems never admit this option, so a
            # setsockopt failure is deliberately ignored.
            ex isa SystemError || rethrow(ex)
        end
        return nothing
    end
end

@inline function _show_endpoint(io::IO, endpoint::Union{Nothing, SocketAddr})
    if endpoint === nothing
        print(io, "?")
    else
        show(io, endpoint)
    end
    return nothing
end

end
