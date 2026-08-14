"""
    UDP

Core UDP socket operations and the datagram connection type.

This layer sits directly above `SocketOps`, `IOPoll`, and `NetCommon`, and
mirrors Go's `net.UDPConn`:
- one `Conn` type serves both unconnected (bound) and connected sockets
- `listen` binds a socket for `sendto`/`recvfrom`-style use; `connect` fixes a
  peer so `send`/`recv` apply and ICMP errors surface as `SystemError`s
- a datagram is sent and received whole: there are no partial transfers, a
  zero-byte datagram is valid data rather than EOF, and `Conn` is deliberately
  **not** an `IO` (stream helpers like `readline` would corrupt datagram
  boundaries)
- deadline expiry is surfaced as `UDP.DeadlineExceededError`, with the same
  sticky per-socket deadline model as `TCP`
"""
module UDP

using ..Reseau: ByteMemory, MutableByteBuffer
using ..Reseau.IOPoll
using ..Reseau.SocketOps
using ..Reseau.NetCommon: SocketAddr, SocketAddrV4, SocketAddrV6, SocketEndpoint, FD,
    loopback_addr, any_addr, loopback_addr6, any_addr6,
    _addr_family, _to_sockaddr, _from_sockaddr, _new_netfd, open_net_fd!,
    _set_local_addr!, _finalize_connected_addrs!, _set_ipv6_only!, _show_endpoint

"""
    DeadlineExceededError

Raised when blocking UDP I/O exceeds the active deadline.

Catch `UDP.DeadlineExceededError` when a deadline set by `set_deadline!`,
`set_read_deadline!`, or `set_write_deadline!` expires. This aliases the
underlying poller timeout type so downstream code does not need to depend on
`Reseau.IOPoll` directly.
"""
const DeadlineExceededError = IOPoll.DeadlineExceededError

"""
    TruncatedDatagramError

Raised by `recv!`/`recvfrom!` (and the allocating forms with a small `maxsize`)
when an incoming datagram was longer than the destination buffer and
`allow_truncate=false` (the default). `nread` is the number of bytes that were
delivered; the rest of the datagram is discarded by the kernel. The socket
remains usable.
"""
struct TruncatedDatagramError <: Exception
    nread::Int
end

function Base.showerror(io::IO, err::TruncatedDatagramError)
    print(io, "datagram truncated after $(err.nread) bytes; pass allow_truncate=true to accept truncated reads")
    return nothing
end

"""
    Conn

User-facing UDP socket.

One type serves both modes, mirroring Go's `net.UDPConn`:
- an *unconnected* socket (from [`listen`](@ref)) exchanges datagrams with any
  peer via [`sendto`](@ref) and [`recvfrom`](@ref)/[`recvfrom!`](@ref)
- a *connected* socket (from [`connect`](@ref)) has a fixed peer, uses
  [`send`](@ref) and [`recv`](@ref)/[`recv!`](@ref), and surfaces ICMP
  errors (e.g. `ECONNREFUSED`) on subsequent operations

`recv`-family calls work on both modes; `send` requires a connected socket and
`sendto` an unconnected one. `Conn` is not an `IO`: datagrams are messages,
not a byte stream.
"""
struct Conn
    fd::FD
end

"""
    connect

Create a connected UDP socket from a concrete `SocketAddr` or a string-address
overload added later in the file load order.
"""
function connect end

"""
    listen

Bind an unconnected UDP socket from a concrete `SocketAddr` or a
string-address overload added later in the file load order.
"""
function listen end

@inline _is_wildcard_ip(addr::SocketAddrV4)::Bool = addr.ip == (0x00, 0x00, 0x00, 0x00)
@inline _is_wildcard_ip(addr::SocketAddrV6)::Bool = all(iszero, addr.ip)

# Go internetSocket parity: kernels that reject wildcard dial destinations
# (Windows, FreeBSD, OpenBSD) get them rewritten to the same-family loopback.
# Elsewhere the kernel itself interprets a wildcard destination as localhost.
@inline function _prepare_dial_remote(remote_addr::SocketAddr)::SocketAddr
    @static if Sys.iswindows() || Sys.isfreebsd() || Sys.isopenbsd()
        _is_wildcard_ip(remote_addr) || return remote_addr
        if remote_addr isa SocketAddrV6
            return loopback_addr6(remote_addr.port; scope_id = remote_addr.scope_id)
        end
        return loopback_addr(remote_addr.port)
    else
        return remote_addr
    end
end

const _V4_MAPPED_PREFIX = (
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
)

"""
    _coerce_family(addr, family) -> SocketEndpoint

Convert `addr` to the socket's address family, mirroring Go's `ipToSockaddr`:
an IPv4 address becomes an IPv4-mapped IPv6 address on an `AF_INET6` socket
(the IPv4 wildcard maps to the IPv6 wildcard), and an IPv4-mapped IPv6
address collapses to plain IPv4 on an `AF_INET` socket. Anything else with a
mismatched family throws `ArgumentError`.
"""
@inline function _coerce_family(addr::SocketAddr, family::Cint)::SocketEndpoint
    _addr_family(addr) == family && return addr::SocketEndpoint
    if family == SocketOps.AF_INET6 && addr isa SocketAddrV4
        _is_wildcard_ip(addr) && return any_addr6(addr.port)
        ip = addr.ip
        return SocketAddrV6((_V4_MAPPED_PREFIX..., ip[1], ip[2], ip[3], ip[4]), addr.port)
    end
    if family == SocketOps.AF_INET && addr isa SocketAddrV6
        ip = addr.ip
        if ip[1:12] == _V4_MAPPED_PREFIX && addr.scope_id == 0
            return SocketAddrV4((ip[13], ip[14], ip[15], ip[16]), addr.port)
        end
    end
    throw(ArgumentError("address family does not match the socket family"))
end


@inline function _is_connected(conn::Conn)::Bool
    return @atomic :acquire conn.fd.is_connected
end

function _close_partial!(fd::FD, registered::Bool)
    if registered
        try
            Base.close(fd.pfd)
        catch
        end
    else
        SocketOps.close_socket_nothrow(fd.pfd.sysfd)
    end
    return nothing
end

"""
    listen(local_addr::SocketAddr; reuseaddr=false, reuseport=false) -> Conn

Bind an unconnected UDP socket to `local_addr` and return it.

Port `0` binds an ephemeral port; read it back with [`local_addr`](@ref).
`reuseaddr` sets `SO_REUSEADDR`. `reuseport` sets `SO_REUSEPORT` (kernel
load-balancing of datagrams across sockets bound to the same port on Linux;
BSD port-sharing semantics on Darwin/BSD) and throws `ArgumentError` on
Windows, which has no equivalent option. IPv6 sockets are opened dual-stack
where the platform allows it, matching `TCP`; the string-address entrypoints
pass `v6only=true` and `net` for `"udp6"` binds.
"""
function listen(
        local_addr::SocketAddr;
        reuseaddr::Bool = false,
        reuseport::Bool = false,
        v6only::Bool = false,
        net::Symbol = :udp,
    )::Conn
    @static if Sys.iswindows()
        reuseport && throw(ArgumentError("reuseport is not supported on Windows"))
    end
    family = _addr_family(local_addr)
    fd = open_net_fd!(; family = family, sotype = SocketOps.SOCK_DGRAM, net = net)
    registered = false
    ok = false
    try
        family == SocketOps.AF_INET6 && _set_ipv6_only!(fd, v6only)
        # Go parity (setDefaultSockopts): datagram sockets allow broadcast out
        # of the box. Unlike the v6only option above, a failure is surfaced.
        SocketOps.set_sockopt_int(fd.pfd.sysfd, SocketOps.SOL_SOCKET, SocketOps.SO_BROADCAST, 1)
        if reuseaddr
            SocketOps.set_sockopt_int(fd.pfd.sysfd, SocketOps.SOL_SOCKET, SocketOps.SO_REUSEADDR, 1)
        end
        @static if !Sys.iswindows()
            if reuseport
                SocketOps.set_sockopt_int(fd.pfd.sysfd, SocketOps.SOL_SOCKET, SocketOps.SO_REUSEPORT, 1)
            end
        end
        @static if Sys.iswindows()
            # One dead peer must not poison a shared unconnected socket with
            # spurious WSAECONNRESET failures (see set_udp_connreset!).
            SocketOps.set_udp_connreset!(fd.pfd.sysfd, false)
        end
        SocketOps.bind_socket(fd.pfd.sysfd, _to_sockaddr(local_addr))
        IOPoll.register!(fd.pfd)
        registered = true
        _set_local_addr!(fd)
        ok = true
        return Conn(fd)
    finally
        ok || _close_partial!(fd, registered)
    end
end

"""
    connect(remote_addr::SocketAddr; local_addr=nothing) -> Conn

Create a connected UDP socket with `remote_addr` as its fixed peer.

Connecting a UDP socket is a local operation: no packets are exchanged, the
kernel simply filters inbound datagrams to the peer and lets ICMP errors from
prior sends surface on later operations (Go semantics). `local_addr`, when
given, is bound before connecting; mixed IPv4/IPv6 pairs follow Go's
`favoriteAddrFamily` rule. The string-address entrypoints pass `v6only=true`
and `net` for `"udp6"` dials.
"""
function connect(
        remote_addr::SocketAddr;
        local_addr::Union{Nothing, SocketAddr} = nothing,
        v6only::Bool = false,
        net::Symbol = :udp,
    )::Conn
    remote_addr = _prepare_dial_remote(remote_addr)
    # Go favoriteAddrFamily parity: the socket is AF_INET only when every
    # given address is IPv4; otherwise it is AF_INET6 and IPv4 addresses are
    # carried as IPv4-mapped IPv6.
    family = if local_addr === nothing
        _addr_family(remote_addr)
    elseif _addr_family(local_addr) == SocketOps.AF_INET &&
            _addr_family(remote_addr) == SocketOps.AF_INET
        SocketOps.AF_INET
    else
        SocketOps.AF_INET6
    end
    remote_endpoint = _coerce_family(remote_addr, family)
    local_endpoint = local_addr === nothing ? nothing : _coerce_family(local_addr, family)
    fd = open_net_fd!(; family = family, sotype = SocketOps.SOCK_DGRAM, net = net)
    registered = false
    ok = false
    try
        family == SocketOps.AF_INET6 && _set_ipv6_only!(fd, v6only)
        # Go parity (setDefaultSockopts): datagram sockets allow broadcast out
        # of the box. Unlike the v6only option above, a failure is surfaced.
        SocketOps.set_sockopt_int(fd.pfd.sysfd, SocketOps.SOL_SOCKET, SocketOps.SO_BROADCAST, 1)
        if local_endpoint !== nothing
            SocketOps.bind_socket(fd.pfd.sysfd, _to_sockaddr(local_endpoint))
        end
        errno = SocketOps.connect_socket(fd.pfd.sysfd, _to_sockaddr(remote_endpoint))
        if errno != Int32(0) && errno != Int32(Base.Libc.EISCONN)
            throw(SystemError("connect", Int(errno)))
        end
        IOPoll.register!(fd.pfd)
        registered = true
        _finalize_connected_addrs!(fd, remote_endpoint)
        ok = true
        return Conn(fd)
    finally
        ok || _close_partial!(fd, registered)
    end
end

##########################
# Send paths
##########################

@inline function _send_ptr!(conn::Conn, p::Ptr{UInt8}, nbytes::Int, root, ::Nothing)::Int
    return IOPoll.sendto_ptr!(conn.fd.pfd, p, nbytes, root, nothing, 0)
end

@inline function _send_ptr!(conn::Conn, p::Ptr{UInt8}, nbytes::Int, root, addr::SocketAddrV4)::Int
    dest = Ref(_to_sockaddr(addr))
    return IOPoll.sendto_ptr!(conn.fd.pfd, p, nbytes, root, dest, sizeof(SocketOps.SockAddrIn))
end

@inline function _send_ptr!(conn::Conn, p::Ptr{UInt8}, nbytes::Int, root, addr::SocketAddrV6)::Int
    dest = Ref(_to_sockaddr(addr))
    return IOPoll.sendto_ptr!(conn.fd.pfd, p, nbytes, root, dest, sizeof(SocketOps.SockAddrIn6))
end

function _send_payload!(conn::Conn, data::Union{Vector{UInt8}, ByteMemory}, dest)::Int
    GC.@preserve data begin
        return _send_ptr!(conn, pointer(data), length(data), data, dest)
    end
end

function _send_payload!(conn::Conn, data::Union{String, SubString{String}}, dest)::Int
    GC.@preserve data begin
        return _send_ptr!(conn, pointer(data), ncodeunits(data), data, dest)
    end
end

function _send_payload!(conn::Conn, data::AbstractVector{UInt8}, dest)::Int
    return _send_payload!(conn, Vector{UInt8}(data), dest)
end

"""
    send(conn::Conn, data) -> Nothing

Send `data` as one datagram to the connected peer.

Throws `ArgumentError` if `conn` is unconnected (use [`sendto`](@ref)).
`data` may be a byte vector or a string; an empty payload sends a valid
empty datagram. Payloads are limited to the UDP maximum (65,507 bytes);
oversized sends surface the kernel's `EMSGSIZE` as a `SystemError` and leave
the socket usable.
"""
function send(conn::Conn, data)::Nothing
    _is_connected(conn) || throw(ArgumentError("send requires a connected UDP socket; use sendto(conn, data, addr)"))
    _send_payload!(conn, data, nothing)
    return nothing
end

"""
    sendto(conn::Conn, data, addr::SocketAddr) -> Nothing

Send `data` as one datagram to `addr` on an unconnected socket.

Throws `ArgumentError` if `conn` is connected (Go's `ErrWriteToConnected`
semantics; use [`send`](@ref)) or if `addr`'s family does not match the
socket's.
"""
function sendto(conn::Conn, data, addr::SocketAddr)::Nothing
    _is_connected(conn) && throw(ArgumentError("sendto on a connected UDP socket; use send(conn, data)"))
    dest = _coerce_family(addr, conn.fd.family)
    _send_payload!(conn, data, dest)
    return nothing
end

##########################
# Receive paths
##########################

@inline _peer_endpoint(::Nothing)::Union{Nothing, SocketEndpoint} = nothing
@inline _peer_endpoint(sa::SocketOps.SockAddrIn)::Union{Nothing, SocketEndpoint} = _from_sockaddr(sa)
@inline _peer_endpoint(sa::SocketOps.SockAddrIn6)::Union{Nothing, SocketEndpoint} = _from_sockaddr(sa)

function _recv_datagram!(conn::Conn, buf::MutableByteBuffer, allow_truncate::Bool)
    n, peer, truncated = GC.@preserve buf IOPoll.recvfrom_ptr!(
        conn.fd.pfd,
        Base.unsafe_convert(Ptr{UInt8}, buf),
        length(buf),
        buf,
    )
    if truncated && !allow_truncate
        throw(TruncatedDatagramError(n))
    end
    return n, _peer_endpoint(peer)
end

"""
    recvfrom!(conn::Conn, buf; allow_truncate=false) -> (nread, addr)

Receive one datagram into `buf`, returning the byte count and the sender's
address.

Blocks until a datagram arrives (or the read deadline expires). If the
datagram is longer than `buf`, the excess is discarded by the kernel and, with
`allow_truncate=false` (the default), a [`TruncatedDatagramError`](@ref) is
thrown; with `allow_truncate=true` the truncated prefix is returned silently
(Go semantics). A zero-byte result is a valid empty datagram, never EOF.
"""
function recvfrom!(
        conn::Conn,
        buf::MutableByteBuffer;
        allow_truncate::Bool = false,
    )::Tuple{Int, Union{Nothing, SocketEndpoint}}
    return _recv_datagram!(conn, buf, allow_truncate)
end

"""
    recv!(conn::Conn, buf; allow_truncate=false) -> Int

Receive one datagram into `buf` and return the byte count, discarding the
sender address. Works on connected and unconnected sockets alike; truncation
behaves as in [`recvfrom!`](@ref).
"""
function recv!(conn::Conn, buf::MutableByteBuffer; allow_truncate::Bool = false)::Int
    n, _ = _recv_datagram!(conn, buf, allow_truncate)
    return n
end

"""
    recvfrom(conn::Conn; maxsize=65535) -> (data::Vector{UInt8}, addr)

Receive one datagram, allocating a right-sized result vector.

The default `maxsize` holds any UDP datagram, so the default call never
truncates. A smaller `maxsize` throws [`TruncatedDatagramError`](@ref) for
longer datagrams.
"""
function recvfrom(conn::Conn; maxsize::Integer = 65535)::Tuple{Vector{UInt8}, Union{Nothing, SocketEndpoint}}
    buf = Vector{UInt8}(undef, Int(maxsize))
    n, addr = _recv_datagram!(conn, buf, false)
    resize!(buf, n)
    return buf, addr
end

"""
    recv(conn::Conn; maxsize=65535) -> Vector{UInt8}

Receive one datagram, allocating a right-sized result vector and discarding
the sender address. See [`recvfrom`](@ref) for `maxsize` semantics.
"""
function recv(conn::Conn; maxsize::Integer = 65535)::Vector{UInt8}
    buf = Vector{UInt8}(undef, Int(maxsize))
    n, _ = _recv_datagram!(conn, buf, false)
    resize!(buf, n)
    return buf
end

##########################
# Options
##########################

"""
    set_broadcast!(conn::Conn, enabled=true)

Toggle `SO_BROADCAST`. Broadcast is **enabled by default** on every UDP
socket (Go parity); use `set_broadcast!(conn, false)` to disable it.
"""
function set_broadcast!(conn::Conn, enabled::Bool = true)
    IOPoll.set_sockopt_int!(conn.fd.pfd, SocketOps.SOL_SOCKET, SocketOps.SO_BROADCAST, enabled ? 1 : 0)
    return nothing
end


"""
    set_read_buffer!(conn::Conn, nbytes::Integer)

Set the kernel receive buffer size (`SO_RCVBUF`). Kernels may round the
value (Linux doubles it). Datagrams that arrive while the buffer is full are
dropped, so servers expecting bursts should raise this.
"""
function set_read_buffer!(conn::Conn, nbytes::Integer)
    nbytes > 0 || throw(ArgumentError("buffer size must be positive"))
    IOPoll.set_sockopt_int!(conn.fd.pfd, SocketOps.SOL_SOCKET, SocketOps.SO_RCVBUF, Int(nbytes))
    return nothing
end

"""
    set_write_buffer!(conn::Conn, nbytes::Integer)

Set the kernel send buffer size (`SO_SNDBUF`). Kernels may round the value
(Linux doubles it).
"""
function set_write_buffer!(conn::Conn, nbytes::Integer)
    nbytes > 0 || throw(ArgumentError("buffer size must be positive"))
    IOPoll.set_sockopt_int!(conn.fd.pfd, SocketOps.SOL_SOCKET, SocketOps.SO_SNDBUF, Int(nbytes))
    return nothing
end

"""
    set_ttl!(conn::Conn, ttl::Integer)

Set the unicast time-to-live (IPv4 `IP_TTL`) or hop limit (IPv6
`IPV6_UNICAST_HOPS`) for outgoing datagrams.
"""
function set_ttl!(conn::Conn, ttl::Integer)
    (ttl < 0 || ttl > 255) && throw(ArgumentError("ttl must be in [0, 255]"))
    if conn.fd.family == SocketOps.AF_INET6
        IOPoll.set_sockopt_int!(conn.fd.pfd, SocketOps.IPPROTO_IPV6, SocketOps.IPV6_UNICAST_HOPS, Int(ttl))
    else
        IOPoll.set_sockopt_int!(conn.fd.pfd, SocketOps.IPPROTO_IP, SocketOps.IP_TTL, Int(ttl))
    end
    return nothing
end

##########################
# Deadlines
##########################

"""
    set_deadline!(conn::Conn, deadline_ns::Integer)

Set both the read and write deadline to the absolute monotonic timestamp
`deadline_ns` (the `time_ns()` clock). `0` clears; a value `<= time_ns()`
expires immediately, waking any parked operation with
`UDP.DeadlineExceededError`.
"""
function set_deadline!(conn::Conn, deadline_ns::Integer)
    IOPoll.set_deadline!(conn.fd.pfd, Int64(deadline_ns))
    return nothing
end

"""
    set_read_deadline!(conn::Conn, deadline_ns::Integer)

Set the deadline for `recv`-family operations. See [`set_deadline!`](@ref).
"""
function set_read_deadline!(conn::Conn, deadline_ns::Integer)
    IOPoll.set_read_deadline!(conn.fd.pfd, Int64(deadline_ns))
    return nothing
end

"""
    set_write_deadline!(conn::Conn, deadline_ns::Integer)

Set the deadline for `send`-family operations. See [`set_deadline!`](@ref).
"""
function set_write_deadline!(conn::Conn, deadline_ns::Integer)
    IOPoll.set_write_deadline!(conn.fd.pfd, Int64(deadline_ns))
    return nothing
end

##########################
# Introspection and lifecycle
##########################

"""
    local_addr(conn::Conn) -> Union{Nothing, SocketAddr}

The socket's bound local address, cached at `listen`/`connect` time.
"""
function local_addr(conn::Conn)::Union{Nothing, SocketAddr}
    return conn.fd.laddr
end

"""
    remote_addr(conn::Conn) -> Union{Nothing, SocketAddr}

The connected peer address, or `nothing` for unconnected sockets.
"""
function remote_addr(conn::Conn)::Union{Nothing, SocketAddr}
    return conn.fd.raddr
end

"""
    close(conn::Conn)

Close the socket, waking any parked operations with `NetClosingError`.
Idempotent.
"""
function Base.close(conn::Conn)
    try
        Base.close(conn.fd.pfd)
    catch err
        ex = err::Exception
        ex isa IOPoll.NetClosingError || rethrow(ex)
    end
    return nothing
end

"""
    isopen(conn::Conn) -> Bool

Return `true` while `conn` still owns an open socket.
"""
function Base.isopen(conn::Conn)::Bool
    return !IOPoll._fdlock_closing(conn.fd.pfd.fdlock)
end

@inline _show_state(conn::Conn) = IOPoll._fdlock_closing(conn.fd.pfd.fdlock) ? "closed" : "open"

function Base.show(io::IO, conn::Conn)
    print(io, "UDP.Conn(")
    _show_endpoint(io, local_addr(conn))
    if _is_connected(conn)
        print(io, " => ")
        _show_endpoint(io, remote_addr(conn))
    end
    print(io, ", ", _show_state(conn), ")")
    return nothing
end

end
