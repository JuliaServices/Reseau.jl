"""
    TCP

Core TCP socket operations and connection/listener types.
"""
module TCP

using ..Reseau.IOPoll
using ..Reseau.SocketOps

"""
    SocketAddr

Abstract network endpoint type for TCP socket addresses.
"""
abstract type SocketAddr end

"""
    SocketAddrV4

IPv4 endpoint snapshot.
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

IPv6 endpoint snapshot. `scope_id` is used for scoped link-local addresses.
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

function loopback_addr(port::Integer)::SocketAddrV4
    return SocketAddrV4((UInt8(127), UInt8(0), UInt8(0), UInt8(1)), port)
end

function any_addr(port::Integer)::SocketAddrV4
    return SocketAddrV4((UInt8(0), UInt8(0), UInt8(0), UInt8(0)), port)
end

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
    groups = String[]
    for i in 1:8
        hi = UInt16(ip[(2 * i) - 1])
        lo = UInt16(ip[2 * i])
        push!(groups, string((hi << 8) | lo, base = 16))
    end
    return join(groups, ":")
end

function Base.show(io::IO, addr::SocketAddrV4)
    print(io, "$(addr.ip[1]).$(addr.ip[2]).$(addr.ip[3]).$(addr.ip[4]):$(addr.port)")
    return nothing
end

function Base.show(io::IO, addr::SocketAddrV6)
    if addr.scope_id != 0
        print(io, "[$(_format_ipv6(addr.ip))%$(addr.scope_id)]:$(addr.port)")
    else
        print(io, "[$(_format_ipv6(addr.ip))]:$(addr.port)")
    end
    return nothing
end

"""
    FD

Go-style network descriptor owner built on `IOPoll.FD`.
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

"""
    Conn

User-facing connected TCP stream.
"""
struct Conn
    fd::FD
end

"""
    Listener

User-facing passive TCP listener.
"""
struct Listener
    fd::FD
end

struct ConnectCanceledError <: Exception end

@inline _connect_canceled(::Nothing)::Bool = false
@inline _connect_canceled(::Any)::Bool = false
@inline _connect_wait_register!(::Any, ::FD) = nothing
@inline _connect_wait_unregister!(::Any, ::FD) = nothing

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

@inline function _set_remote_addr_from_accept!(fd::FD, peer_addr::SocketOps.AcceptPeer)
    if peer_addr isa SocketOps.SockAddrIn
        fd.raddr = _from_sockaddr(peer_addr::SocketOps.SockAddrIn)
        return nothing
    end
    if peer_addr isa SocketOps.SockAddrIn6
        fd.raddr = _from_sockaddr(peer_addr::SocketOps.SockAddrIn6)
        return nothing
    end
    _set_remote_addr!(fd)
    return nothing
end

@inline function _is_connect_pending_errno(errno::Int32)::Bool
    return errno == Int32(Base.Libc.EINPROGRESS) || errno == Int32(Base.Libc.EALREADY) || errno == Int32(Base.Libc.EINTR)
end

@inline function _is_accept_retry_errno(errno::Int32)::Bool
    return errno == Int32(Base.Libc.EINTR) || errno == Int32(Base.Libc.ECONNABORTED)
end

@inline function _is_temporary_unconnected(err::SystemError)::Bool
    return err.errnum == Int(Base.Libc.ENOTCONN) || err.errnum == Int(Base.Libc.EINVAL)
end

function _new_netfd(
        sysfd::Cint;
        family::Cint = SocketOps.AF_INET,
        sotype::Cint = SocketOps.SOCK_STREAM,
        net::Symbol = :tcp,
        is_connected::Bool = false,
    )::FD
    pfd = IOPoll.FD(sysfd; is_stream = true, zero_read_is_eof = true, is_file = false)
    return FD(pfd, family, sotype, net, is_connected, nothing, nothing)
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

function _apply_default_tcp_opts!(fd::FD)
    # Match Go's baseline behavior: disable Nagle and enable keepalive by default.
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
        remote_addr::SocketAddr;
        cancel_state = nothing,
    )
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
                IOPoll.wait_write!(fd.pfd.pd)
            catch err
                ex = err::Exception
                if ex isa IOPoll.DeadlineExceededError && _connect_canceled(cancel_state)
                    throw(ConnectCanceledError())
                end
                rethrow(ex)
            end
            so_error = SocketOps.get_socket_error(fd.pfd.sysfd)
            _is_connect_pending_errno(so_error) && continue
            if so_error == Int32(Base.Libc.EISCONN)
                _finalize_connected_addrs!(fd, remote_addr)
                return nothing
            end
            if so_error == Int32(0)
                try
                    _set_remote_addr!(fd)
                    _finalize_connected_addrs!(fd, remote_addr)
                    return nothing
                catch err
                    if err isa SystemError && _is_temporary_unconnected(err)
                        continue
                    end
                    rethrow(err)
                end
            end
            throw(SystemError("connect", Int(so_error)))
        end
    finally
        _connect_wait_unregister!(cancel_state, fd)
    end
end

@inline function _bind_connectex_local!(fd::FD, family::Cint)
    if family == SocketOps.AF_INET6
        SocketOps.bind_socket(fd.pfd.sysfd, SocketOps.sockaddr_in6_any(0))
        return nothing
    end
    SocketOps.bind_socket(fd.pfd.sysfd, SocketOps.sockaddr_in_any(0))
    return nothing
end

"""
    open_tcp_fd!(; family=AF_INET)

Open a non-blocking, cloexec TCP socket and wrap it in `FD`.
"""
function open_tcp_fd!(; family::Cint = SocketOps.AF_INET)::FD
    sysfd = SocketOps.open_socket(family, SocketOps.SOCK_STREAM)
    return _new_netfd(sysfd; family = family, sotype = SocketOps.SOCK_STREAM, net = :tcp, is_connected = false)
end

"""
    connect_tcp_fd!(remote_addr; local_addr=nothing, connect_deadline_ns=0)

Create and connect a non-blocking TCP `FD` using Go-style connect completion:
wait write-ready, then verify with `SO_ERROR`.
"""
function connect_tcp_fd!(
        remote_addr::SocketAddr;
        local_addr::Union{Nothing, SocketAddr} = nothing,
        connect_deadline_ns::Integer = Int64(0),
        cancel_state = nothing,
    )::FD
    family = _addr_family(remote_addr)
    if local_addr !== nothing && _addr_family(local_addr) != family
        throw(ArgumentError("local and remote address families must match"))
    end
    fd = open_tcp_fd!(; family = family)
    try
        if local_addr !== nothing
            SocketOps.bind_socket(fd.pfd.sysfd, _to_sockaddr(local_addr))
        elseif Sys.iswindows()
            _bind_connectex_local!(fd, family)
        end
        # Defensive re-assert: keep connect path non-blocking even if platform state drifts.
        SocketOps.set_nonblocking!(fd.pfd.sysfd, true)
        @static if Sys.iswindows()
            IOPoll.init!(fd.pfd; net = :tcp, pollable = true)
            if connect_deadline_ns != 0
                IOPoll.set_write_deadline!(fd.pfd, connect_deadline_ns)
            end
            try
                _wait_connect_complete!(
                    fd,
                    remote_addr;
                    cancel_state = cancel_state,
                )
            finally
                if connect_deadline_ns != 0
                    try
                        IOPoll.set_write_deadline!(fd.pfd, Int64(0))
                    catch
                    end
                end
            end
            _apply_default_tcp_opts!(fd)
            return fd
        end
        errno = SocketOps.connect_socket(fd.pfd.sysfd, _to_sockaddr(remote_addr))
        if errno == Int32(0) || errno == Int32(Base.Libc.EISCONN)
            IOPoll.init!(fd.pfd; net = :tcp, pollable = true)
            _finalize_connected_addrs!(fd, remote_addr)
            _apply_default_tcp_opts!(fd)
            return fd
        end
        _is_connect_pending_errno(errno) || throw(SystemError("connect", Int(errno)))
        IOPoll.init!(fd.pfd; net = :tcp, pollable = true)
        if connect_deadline_ns != 0
            IOPoll.set_write_deadline!(fd.pfd, connect_deadline_ns)
        end
        try
            _wait_connect_complete!(
                fd,
                remote_addr;
                cancel_state = cancel_state,
            )
        finally
            if connect_deadline_ns != 0
                try
                    IOPoll.set_write_deadline!(fd.pfd, Int64(0))
                catch
                end
            end
        end
        _apply_default_tcp_opts!(fd)
        return fd
    catch
        close!(fd)
        rethrow()
    end
end

"""
    listen_tcp_fd!(local_addr; backlog=128, reuseaddr=true)

Create a listening TCP `FD` bound to `local_addr`.
"""
function listen_tcp_fd!(local_addr::SocketAddr; backlog::Integer = 128, reuseaddr::Bool = true)::FD
    family = _addr_family(local_addr)
    fd = open_tcp_fd!(; family = family)
    try
        reuseaddr && SocketOps.set_sockopt_int(fd.pfd.sysfd, SocketOps.SOL_SOCKET, SocketOps.SO_REUSEADDR, 1)
        SocketOps.bind_socket(fd.pfd.sysfd, _to_sockaddr(local_addr))
        SocketOps.listen_socket(fd.pfd.sysfd, backlog)
        IOPoll.init!(fd.pfd; net = :tcp, pollable = true)
        _set_local_addr!(fd)
        return fd
    catch
        close!(fd)
        rethrow()
    end
end

"""
    accept_tcp_fd!(listener_fd)

Accept a child TCP connection, retrying transient accept errors with Go parity.
"""
function accept_tcp_fd!(listener_fd::FD)::FD
    child_sysfd, peer_addr = IOPoll.accept!(listener_fd.pfd, listener_fd.family, listener_fd.sotype)
    child = _new_netfd(
        child_sysfd;
        family = listener_fd.family,
        sotype = listener_fd.sotype,
        net = listener_fd.net,
        is_connected = true,
    )
    try
        IOPoll.init!(child.pfd; net = listener_fd.net, pollable = true)
        _apply_default_tcp_opts!(child)
        _set_local_addr!(child)
        _set_remote_addr_from_accept!(child, peer_addr)
        @atomic :release child.is_connected = true
        return child
    catch
        close!(child)
        rethrow()
    end
end

"""
    connect(remote_addr; local_addr=nothing)

Connect a TCP connection and return `Conn`.
"""
function connect(remote_addr::SocketAddr; local_addr::Union{Nothing, SocketAddr} = nothing)::Conn
    return Conn(connect_tcp_fd!(remote_addr; local_addr = local_addr))
end

"""
    listen(local_addr; backlog=128, reuseaddr=true)

Create a TCP listener from a bound local address.
"""
function listen(local_addr::SocketAddr; backlog::Integer = 128, reuseaddr::Bool = true)::Listener
    return Listener(listen_tcp_fd!(local_addr; backlog = backlog, reuseaddr = reuseaddr))
end

"""
    accept!(listener)

Accept a new `Conn` from `listener`.
"""
function accept!(listener::Listener)::Conn
    return Conn(accept_tcp_fd!(listener.fd))
end

function Base.read!(conn::Conn, buf::Vector{UInt8})::Int
    return IOPoll.read!(conn.fd.pfd, buf)
end

function Base.write(conn::Conn, buf::Vector{UInt8})::Int
    return IOPoll.write!(conn.fd.pfd, buf)
end

function Base.write(conn::Conn, buf::Memory{UInt8}, nbytes::Integer)::Int
    return IOPoll.write!(conn.fd.pfd, buf, nbytes)
end

function close!(conn::Conn)
    close!(conn.fd)
    return nothing
end

function close!(listener::Listener)
    close!(listener.fd)
    return nothing
end

function close_read!(conn::Conn)
    SocketOps.shutdown_socket(conn.fd.pfd.sysfd, SocketOps.SHUT_RD)
    return nothing
end

function close_write!(conn::Conn)
    SocketOps.shutdown_socket(conn.fd.pfd.sysfd, SocketOps.SHUT_WR)
    return nothing
end

"""
    close!(fd::FD)

Close a net descriptor. Repeated closes are treated as no-op.
"""
function close!(fd::FD)
    IOPoll.close!(fd.pfd)
    return nothing
end

"""
    set_deadline!(conn, deadline_ns)

Set both read and write deadlines on `conn`.

- `deadline_ns` is an absolute monotonic timestamp in nanoseconds, using the
  same clock as `time_ns()`.
- `deadline_ns == 0` disables both deadlines.
- `deadline_ns <= time_ns()` marks both sides as immediately timed out.

After the deadline is reached, blocking `read!`/`write` operations fail with
`IOPoll.DeadlineExceededError` until the deadline is cleared or moved forward.
"""
function set_deadline!(conn::Conn, deadline_ns::Integer)
    IOPoll.set_deadline!(conn.fd.pfd, deadline_ns)
    return nothing
end

"""
    set_read_deadline!(conn, deadline_ns)

Set only the read deadline on `conn`.

- Uses absolute monotonic nanoseconds (`time_ns()` clock).
- `deadline_ns == 0` disables read timeouts.
- `deadline_ns <= time_ns()` causes read waits to time out immediately.

This affects `read!` wait paths only.
"""
function set_read_deadline!(conn::Conn, deadline_ns::Integer)
    IOPoll.set_read_deadline!(conn.fd.pfd, deadline_ns)
    return nothing
end

"""
    set_write_deadline!(conn, deadline_ns)

Set only the write deadline on `conn`.

- Uses absolute monotonic nanoseconds (`time_ns()` clock).
- `deadline_ns == 0` disables write timeouts.
- `deadline_ns <= time_ns()` causes write waits to time out immediately.

This affects `write` wait paths only.
"""
function set_write_deadline!(conn::Conn, deadline_ns::Integer)
    IOPoll.set_write_deadline!(conn.fd.pfd, deadline_ns)
    return nothing
end

function set_nodelay!(conn::Conn, enabled::Bool = true)
    SocketOps.set_sockopt_int(
        conn.fd.pfd.sysfd,
        SocketOps.IPPROTO_TCP,
        SocketOps.TCP_NODELAY,
        enabled ? 1 : 0,
    )
    return nothing
end

function set_keepalive!(conn::Conn, enabled::Bool = true)
    SocketOps.set_sockopt_int(
        conn.fd.pfd.sysfd,
        SocketOps.SOL_SOCKET,
        SocketOps.SO_KEEPALIVE,
        enabled ? 1 : 0,
    )
    return nothing
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
