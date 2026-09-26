"""
    TCP

Core TCP socket operations and connection/listener types.

This layer sits directly above `SocketOps` and `IOPoll`. It is responsible for
turning raw non-blocking sockets into higher-level connection/listener objects,
including:
- sockets are created non-blocking and registered with the poller
- non-blocking connect completes by waiting for write readiness and then reading
  `SO_ERROR`
- accept returns already-initialized child descriptors that are ready for the
  same poll-driven read/write paths as outbound connections
- deadline expiry is surfaced as `TCP.DeadlineExceededError` for transport I/O
"""
module TCP

using ..Reseau: ByteMemory, MutableByteBuffer
using ..Reseau.IOPoll
using ..Reseau.SocketOps
using ..Reseau.NetCommon: SocketAddr, SocketAddrV4, SocketAddrV6, SocketEndpoint, FD,
    loopback_addr, any_addr, loopback_addr6, any_addr6,
    _addr_family, _to_sockaddr, _from_sockaddr, _format_ipv6, _new_netfd, open_net_fd!,
    _set_local_addr!, _set_remote_addr!, _finalize_connected_addrs!,
    _is_temporary_unconnected, _set_ipv6_only!, _show_endpoint
import ..Reseau.NetCommon: _StreamConn, _read_some!, _grow_readbytes_target!,
    _peek_eof, _readbytes_all!, _readbytes_some!, _tryread!, _write_rooted!, _rawfd,
    tryread!, closeread, set_deadline!, set_read_deadline!, set_write_deadline!, rawfd

"""
    DeadlineExceededError

Raised when blocking TCP I/O or `accept(listener)` exceeds the active deadline.

Catch `TCP.DeadlineExceededError` when a deadline set by `set_deadline!`,
`set_read_deadline!`, or `set_write_deadline!` expires. This aliases the
underlying poller timeout type so downstream code does not need to depend on
`Reseau.IOPoll` directly.
"""
const DeadlineExceededError = IOPoll.DeadlineExceededError

"""
    NetClosingError

Raised when a TCP operation encounters a locally closed connection or listener,
including a pending operation woken by `close` from another task.

Catch `TCP.NetClosingError` during deliberate connection or listener shutdown.
This aliases the underlying poller exception without requiring callers to use
`Reseau.IOPoll`. Peer EOF and deadline expiry have separate error behavior.
"""
const NetClosingError = IOPoll.NetClosingError

"""
    connect

Connect a TCP client using either a concrete `SocketAddr` or a string-address
overload added later in the file load order.
"""
function connect end

"""
    listen

Create a TCP listener from either a concrete `SocketAddr` or a string-address
overload added later in the file load order.
"""
function listen end

"""
    accept

Accept one inbound `Conn` from a `TCP.Listener`.
"""
function accept end


"""
    Conn

User-facing connected TCP stream.

Reads and writes are forwarded to `IOPoll`, which means blocking operations are
actually readiness waits against the shared low-level poller rather than
thread-per-socket blocking syscalls. Because `Conn <: IO`, standard Base stream
helpers like `read`, `read!`, `readbytes!`, `eof`, and `write` apply directly.
"""
struct Conn <: _StreamConn
    fd::FD
end

"""
    Listener

User-facing passive TCP listener.

Accepted children are returned as `Conn` values whose underlying sockets are
already non-blocking, poll-registered, and configured with the default TCP
options Reseau wants.
"""
struct Listener
    fd::FD
end

struct ConnectCanceledError <: Exception end

@inline _connect_canceled(::Nothing)::Bool = false
@inline _connect_canceled(::Any)::Bool = false
@inline _connect_wait_register!(::Any, ::FD) = nothing
@inline _connect_wait_unregister!(::Any, ::FD) = nothing

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

function _apply_default_tcp_opts!(fd::FD)
    # Default connected sockets to low-latency sends and kernel keepalive.
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

@static if Sys.iswindows()
    function _wait_connect_complete!(
            fd::FD,
            remote_addr::SocketAddr,
            cancel_state = nothing,
        )
        _connect_wait_register!(cancel_state, fd)
        try
            sockaddr = _to_sockaddr(remote_addr)
            addrbuf = SocketOps.sockaddr_bytes(sockaddr)
            addrlen = Int32(sizeof(typeof(sockaddr)))
            while true
                if _connect_canceled(cancel_state)
                    throw(ConnectCanceledError())
                end
                try
                    # Windows completes the ConnectEx/IOCP path inside `IOPoll.connect!`.
                    # Deadline expiry can still be the signal that the higher-level DNS
                    # race lost, so we translate that case below.
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
        finally
            _connect_wait_unregister!(cancel_state, fd)
        end
    end
else
    function _wait_connect_complete!(
            fd::FD,
            remote_addr::SocketAddr,
            cancel_state = nothing,
        )
        _connect_wait_register!(cancel_state, fd)
        try
            while true
                if _connect_canceled(cancel_state)
                    throw(ConnectCanceledError())
                end
                try
                    # Non-blocking connect completion is detected by waiting for
                    # writability, then inspecting `SO_ERROR` to learn whether the
                    # connection actually succeeded.
                    IOPoll.waitwrite(fd.pfd.pd)
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

Open a non-blocking, close-on-exec TCP socket and wrap it in `FD`.

This is the lowest-level TCP constructor exposed within the package. The
returned descriptor is not yet registered with `IOPoll`; callers that plan to
issue readiness-driven operations should call `IOPoll.register!` before use.

Returns an internal `FD` object and throws `SystemError` on socket creation
failure.
"""
function open_tcp_fd!(;
        family::Cint = SocketOps.AF_INET,
        net::Symbol = :tcp,
    )::FD
    return open_net_fd!(; family = family, sotype = SocketOps.SOCK_STREAM, net = net)
end

@inline function _connect_socketaddr_family(
        remote_addr::SocketAddr,
        local_addr::Union{Nothing, SocketAddr},
    )::Cint
    family = _addr_family(remote_addr)
    if local_addr !== nothing && _addr_family(local_addr) != family
        throw(ArgumentError("local and remote address families must match"))
    end
    return family
end

@inline _is_wildcard_addr(addr::SocketAddrV4)::Bool = addr.ip == (0x00, 0x00, 0x00, 0x00)
@inline _is_wildcard_addr(addr::SocketAddrV6)::Bool = all(iszero, addr.ip)

@inline function _wildcard_remote_to_local(
        remote_addr::SocketAddr,
        network::Symbol,
    )::SocketAddr
    _is_wildcard_addr(remote_addr) || return remote_addr
    if network === :tcp6
        scope_id = remote_addr isa SocketAddrV6 ? remote_addr.scope_id : UInt32(0)
        return loopback_addr6(remote_addr.port; scope_id = scope_id)
    end
    return loopback_addr(remote_addr.port)
end

@inline function _prepare_dial_remote_addr(
        remote_addr::SocketAddr,
        network::Symbol,
    )::SocketAddr
    # Go's internetSocket rewrites wildcard dial destinations on kernels that
    # do not consistently interpret them as the local host. In particular,
    # ConnectEx rejects 0.0.0.0/:: as a remote address on Windows.
    @static if Sys.iswindows() || Sys.isfreebsd() || Sys.isopenbsd()
        return _wildcard_remote_to_local(remote_addr, network)
    else
        return remote_addr
    end
end

@inline function _clear_connect_write_deadline!(fd::FD, connect_deadline_ns::Int64)
    connect_deadline_ns == 0 && return nothing
    try
        IOPoll.set_write_deadline!(fd.pfd, Int64(0))
    catch
    end
    return nothing
end

# Keep platform selection at top level so the active connect methods do not
# lower an internal `@static` control-flow island inside nested exception paths.
@static if Sys.iswindows()
    function _connect_socketaddr_impl(
            remote_addr::SocketAddr,
            local_addr::Union{Nothing, SocketAddr},
            connect_deadline_ns::Int64,
            cancel_state,
            network::Symbol,
        )::Conn
        family = _connect_socketaddr_family(remote_addr, local_addr)
        fd = open_tcp_fd!(; family = family, net = network)
        try
            family == SocketOps.AF_INET6 && _set_ipv6_only!(fd, network === :tcp6)
            if local_addr !== nothing
                SocketOps.bind_socket(fd.pfd.sysfd, _to_sockaddr(local_addr))
            else
                # ConnectEx requires the socket to be bound first, even when the user
                # did not request a specific local address.
                _bind_connectex_local!(fd, family)
            end
            # Defensive re-assert: keep connect path non-blocking even if platform state drifts.
            SocketOps.set_nonblocking!(fd.pfd.sysfd, true)
            IOPoll.register!(fd.pfd)
            if connect_deadline_ns != 0
                IOPoll.set_write_deadline!(fd.pfd, connect_deadline_ns)
            end
            try
                _wait_connect_complete!(
                    fd,
                    remote_addr,
                    cancel_state,
                )
            finally
                _clear_connect_write_deadline!(fd, connect_deadline_ns)
            end
            _apply_default_tcp_opts!(fd)
            return Conn(fd)
        catch
            close(fd)
            rethrow()
        end
    end
else
    function _connect_socketaddr_impl(
            remote_addr::SocketAddr,
            local_addr::Union{Nothing, SocketAddr},
            connect_deadline_ns::Int64,
            cancel_state,
            network::Symbol,
        )::Conn
        family = _connect_socketaddr_family(remote_addr, local_addr)
        fd = open_tcp_fd!(; family = family, net = network)
        try
            family == SocketOps.AF_INET6 && _set_ipv6_only!(fd, network === :tcp6)
            if local_addr !== nothing
                SocketOps.bind_socket(fd.pfd.sysfd, _to_sockaddr(local_addr))
            end
            # Defensive re-assert: keep connect path non-blocking even if platform state drifts.
            SocketOps.set_nonblocking!(fd.pfd.sysfd, true)
            errno = SocketOps.connect_socket(fd.pfd.sysfd, _to_sockaddr(remote_addr))
            if errno == Int32(0) || errno == Int32(Base.Libc.EISCONN)
                IOPoll.register!(fd.pfd)
                _finalize_connected_addrs!(fd, remote_addr)
                _apply_default_tcp_opts!(fd)
                return Conn(fd)
            end
            _is_connect_pending_errno(errno) || throw(SystemError("connect", Int(errno)))
            IOPoll.register!(fd.pfd)
            if connect_deadline_ns != 0
                IOPoll.set_write_deadline!(fd.pfd, connect_deadline_ns)
            end
            try
                _wait_connect_complete!(
                    fd,
                    remote_addr,
                    cancel_state,
                )
            finally
                _clear_connect_write_deadline!(fd, connect_deadline_ns)
            end
            _apply_default_tcp_opts!(fd)
            return Conn(fd)
        catch
            close(fd)
            rethrow()
        end
    end
end

@inline _uses_ephemeral_local_port(::Nothing)::Bool = true
@inline _uses_ephemeral_local_port(addr::SocketAddrV4)::Bool = addr.port == 0
@inline _uses_ephemeral_local_port(addr::SocketAddrV6)::Bool = addr.port == 0

function _is_self_connect(conn::Conn)::Bool
    laddr = conn.fd.laddr
    raddr = conn.fd.raddr
    (laddr === nothing || raddr === nothing) && return true
    if laddr isa SocketAddrV4 && raddr isa SocketAddrV4
        local_v4 = laddr::SocketAddrV4
        remote_v4 = raddr::SocketAddrV4
        return local_v4.port == remote_v4.port && local_v4.ip == remote_v4.ip
    end
    if laddr isa SocketAddrV6 && raddr isa SocketAddrV6
        local_v6 = laddr::SocketAddrV6
        remote_v6 = raddr::SocketAddrV6
        return local_v6.port == remote_v6.port &&
               local_v6.ip == remote_v6.ip &&
               local_v6.scope_id == remote_v6.scope_id
    end
    return false
end

function _dial_socketaddr_with(
        remote_addr::SocketAddr,
        local_addr::Union{Nothing, SocketAddr},
        connect_deadline_ns::Int64,
        cancel_state,
        network::Symbol,
        dial_once::F,
    )::Conn where {F}
    max_attempts = _uses_ephemeral_local_port(local_addr) ? 3 : 1
    for attempt in 1:max_attempts
        conn = try
            dial_once(remote_addr, local_addr, connect_deadline_ns, cancel_state, network)
        catch err
            if err isa SystemError &&
               (err::SystemError).errnum == Int(Base.Libc.EADDRNOTAVAIL) &&
               attempt < max_attempts
                continue
            end
            rethrow(err)
        end
        if attempt < max_attempts && _is_self_connect(conn)
            close(conn)
            continue
        end
        return conn
    end
    error("unreachable TCP dial retry state")
end

function _dial_socketaddr_with(
        dial_once::F,
        remote_addr::SocketAddr,
        local_addr::Union{Nothing, SocketAddr},
        connect_deadline_ns::Int64,
        cancel_state,
        network::Symbol,
    )::Conn where {F}
    return _dial_socketaddr_with(
        remote_addr,
        local_addr,
        connect_deadline_ns,
        cancel_state,
        network,
        dial_once,
    )
end

function _dial_socketaddr_impl(
        remote_addr::SocketAddr,
        local_addr::Union{Nothing, SocketAddr},
        connect_deadline_ns::Int64,
        cancel_state,
        network::Symbol,
    )::Conn
    remote_addr = _prepare_dial_remote_addr(remote_addr, network)
    return _dial_socketaddr_with(
        remote_addr,
        local_addr,
        connect_deadline_ns,
        cancel_state,
        network,
        _connect_socketaddr_impl,
    )
end

"""
    connect(remote_addr)
    connect(remote_addr, local_addr)

Connect a TCP connection and return `Conn`.

This is the direct-address API. The common fast path stays positional so the
socket-connect entrypoint compiles as a simple method call across platforms.
For host/port strings, name resolution, and timeout-aware connect policy, use
the `connect(network, address...)` overloads on the same `TCP.connect` generic.
"""
function connect(remote_addr::SocketAddr)::Conn
    return _dial_socketaddr_impl(remote_addr, nothing, Int64(0), nothing, :tcp)
end

function connect(remote_addr::SocketAddr, local_addr::Union{Nothing, SocketAddr})::Conn
    return _dial_socketaddr_impl(remote_addr, local_addr, Int64(0), nothing, :tcp)
end

"""
    listen(local_addr; backlog=128, reuseaddr=true)

Create a TCP listener from a bound local address.

This is the direct-address equivalent of the `listen(network, address; ...)`
overloads on the same `TCP.listen` generic.

`reuseaddr` sets `SO_REUSEADDR` so a restarting server can rebind a port whose
previous listener is still in TIME_WAIT. On Windows it is a deliberate no-op:
Windows allows the TIME_WAIT rebind without the option, and `SO_REUSEADDR`
there instead permits binding over an *active* listener (silently starving it
of connections). Go and libuv make the same choice.
"""
function _listen_socketaddr_impl(
        local_addr::SocketAddr,
        network::Symbol;
        backlog::Integer,
        reuseaddr::Bool,
    )::Listener
    family = _addr_family(local_addr)
    fd = open_tcp_fd!(; family = family, net = network)
    try
        family == SocketOps.AF_INET6 && _set_ipv6_only!(fd, network === :tcp6)
        @static if !Sys.iswindows()
            # POSIX SO_REUSEADDR permits rebinding a port stuck in TIME_WAIT.
            # Windows gives the same TIME_WAIT rebinding without the option,
            # and setting it there instead means "bind over an active
            # listener" — a hijack that silently starves the original of
            # connections. Go and libuv likewise never set SO_REUSEADDR on
            # Windows TCP listeners, so `reuseaddr` is a deliberate no-op
            # there.
            reuseaddr && SocketOps.set_sockopt_int(fd.pfd.sysfd, SocketOps.SOL_SOCKET, SocketOps.SO_REUSEADDR, 1)
        end
        SocketOps.bind_socket(fd.pfd.sysfd, _to_sockaddr(local_addr))
        SocketOps.listen_socket(fd.pfd.sysfd, backlog)
        IOPoll.register!(fd.pfd)
        _set_local_addr!(fd)
        return Listener(fd)
    catch
        close(fd)
        rethrow()
    end
end

function listen(local_addr::SocketAddr; backlog::Integer = 128, reuseaddr::Bool = true)::Listener
    return _listen_socketaddr_impl(
        local_addr,
        :tcp;
        backlog = backlog,
        reuseaddr = reuseaddr,
    )
end

@inline _with_port(addr::SocketAddrV4, port::Integer)::SocketAddrV4 = SocketAddrV4(addr.ip, port)
@inline function _with_port(addr::SocketAddrV6, port::Integer)::SocketAddrV6
    return SocketAddrV6(addr.ip, port; scope_id = Int(addr.scope_id))
end

@inline function _is_port_taken_errno(errnum::Integer)::Bool
    return errnum == Int(Base.Libc.EADDRINUSE) || errnum == Int(Base.Libc.EACCES)
end

"""
    listenany(hint::Integer; backlog=128, reuseaddr=true) -> (UInt16, Listener)
    listenany(hint::SocketAddr; backlog=128, reuseaddr=true) -> (UInt16, Listener)

Bind a listener on the first available port at or above `hint`'s port,
returning the bound port and the listener (the `Sockets.listenany` idiom).
The integer form binds to the IPv4 loopback address.

Ports that are in use (`EADDRINUSE`) or forbidden (`EACCES`) are skipped by
incrementing the port; running out of ports rethrows the last error. A hint
port of `0` binds an ephemeral port directly.

`reuseaddr` follows [`listen`](@ref) semantics, including its Windows no-op:
exclusive Windows binds are exactly what keeps `EADDRINUSE` (and therefore
this availability probe) reliable there.
"""
function listenany(hint::Integer; backlog::Integer = 128, reuseaddr::Bool = true)::Tuple{UInt16, Listener}
    return listenany(loopback_addr(hint); backlog = backlog, reuseaddr = reuseaddr)
end

function listenany(hint::SocketAddr; backlog::Integer = 128, reuseaddr::Bool = true)::Tuple{UInt16, Listener}
    addr = hint
    while true
        listener = try
            listen(addr; backlog = backlog, reuseaddr = reuseaddr)
        catch err
            ex = err::Exception
            (ex isa SystemError && _is_port_taken_errno(ex.errnum)) || rethrow(ex)
            next_port = Int(addr.port) + 1
            next_port > 0xffff && rethrow(ex)
            addr = _with_port(addr, next_port)
            continue
        end
        bound = local_addr(listener)
        return ((bound::SocketEndpoint).port, listener)
    end
end

"""
    accept(listener)

Accept a new `Conn` from `listener`.

Throws `SystemError`, `DeadlineExceededError`, or other poll/transport errors if
the underlying accept path fails.
"""
function accept(listener::Listener)::Conn
    listener_fd = listener.fd
    child_sysfd, peer_addr = IOPoll.accept!(listener_fd.pfd, listener_fd.family, listener_fd.sotype)
    child = _new_netfd(
        child_sysfd;
        family = listener_fd.family,
        sotype = listener_fd.sotype,
        net = listener_fd.net,
        is_connected = true,
    )
    try
        IOPoll.register!(child.pfd)
        _apply_default_tcp_opts!(child)
        _set_local_addr!(child)
        _set_remote_addr_from_accept!(child, peer_addr)
        @atomic :release child.is_connected = true
        return Conn(child)
    catch
        close(child)
        rethrow()
    end
end

"""
    close(listener)

Close the listening socket. Repeated closes are treated as no-ops.
"""
function Base.close(listener::Listener)
    close(listener.fd)
    return nothing
end

"""
    isopen(listener) -> Bool

Return `true` while `listener` still owns an open listening socket.
"""
function Base.isopen(listener::Listener)::Bool
    return !IOPoll._fdlock_closing(listener.fd.pfd.fdlock)
end

"""
    set_deadline!(listener, deadline_ns)

Set the accept deadline on `listener`.

- `deadline_ns` uses the same absolute monotonic `time_ns()` clock as connection
  deadlines.
- `deadline_ns == 0` disables accept timeouts.
- `deadline_ns <= time_ns()` causes the next blocking `accept` to time out
  immediately.

This affects `accept(listener)` only.
"""
function set_deadline!(listener::Listener, deadline_ns::Integer)
    IOPoll.set_read_deadline!(listener.fd.pfd, deadline_ns)
    return nothing
end

"""
    set_nodelay!(conn, enabled=true)

Enable or disable `TCP_NODELAY` on `conn`.
"""
function set_nodelay!(conn::Conn, enabled::Bool = true)
    IOPoll.set_sockopt_int!(
        conn.fd.pfd,
        SocketOps.IPPROTO_TCP,
        SocketOps.TCP_NODELAY,
        enabled ? 1 : 0,
    )
    return nothing
end

"""
    set_keepalive!(conn, enabled=true; idle_secs=nothing, interval_secs=nothing, count=nothing)

Enable or disable `SO_KEEPALIVE` on `conn`, optionally tuning the probe
schedule (the shape of Go's `KeepAliveConfig`):

- `idle_secs`: idle time before the first probe (`TCP_KEEPIDLE`;
  `TCP_KEEPALIVE` on Darwin)
- `interval_secs`: time between unanswered probes (`TCP_KEEPINTVL`)
- `count`: unanswered probes before the connection is dropped (`TCP_KEEPCNT`)

Tuning values are applied only when provided. Platforms without a given knob
surface the kernel's `SystemError` (notably OpenBSD, and Windows releases
before Server 2016 / Windows 10 1709).
"""
function set_keepalive!(
        conn::Conn,
        enabled::Bool = true;
        idle_secs::Union{Nothing, Integer} = nothing,
        interval_secs::Union{Nothing, Integer} = nothing,
        count::Union{Nothing, Integer} = nothing,
    )
    idle = _positive_sockopt_value("idle_secs", idle_secs)
    interval = _positive_sockopt_value("interval_secs", interval_secs)
    probes = _positive_sockopt_value("count", count)
    IOPoll.set_sockopt_int!(
        conn.fd.pfd,
        SocketOps.SOL_SOCKET,
        SocketOps.SO_KEEPALIVE,
        enabled ? 1 : 0,
    )
    if idle !== nothing
        IOPoll.set_sockopt_int!(conn.fd.pfd, SocketOps.IPPROTO_TCP, SocketOps.TCP_KEEPIDLE, idle)
    end
    if interval !== nothing
        IOPoll.set_sockopt_int!(conn.fd.pfd, SocketOps.IPPROTO_TCP, SocketOps.TCP_KEEPINTVL, interval)
    end
    if probes !== nothing
        IOPoll.set_sockopt_int!(conn.fd.pfd, SocketOps.IPPROTO_TCP, SocketOps.TCP_KEEPCNT, probes)
    end
    return nothing
end

@inline _positive_sockopt_value(::AbstractString, ::Nothing)::Nothing = nothing

function _positive_sockopt_value(name::AbstractString, value::Integer)::Cint
    0 < value <= typemax(Cint) ||
        throw(ArgumentError("$name must be in [1, $(typemax(Cint))]"))
    return Cint(value)
end

"""
    set_quickack!(conn, enabled=true)

Toggle `TCP_QUICKACK` (Linux). On other platforms this is a silent no-op,
matching `Sockets.quickack`, so cross-platform callers can set it
unconditionally. The kernel may clear the flag again after some transfers;
latency-sensitive callers re-assert it as needed.
"""
function set_quickack!(conn::Conn, enabled::Bool = true)
    @static if Sys.islinux()
        IOPoll.set_sockopt_int!(
            conn.fd.pfd,
            SocketOps.IPPROTO_TCP,
            SocketOps.TCP_QUICKACK,
            enabled ? 1 : 0,
        )
    else
        # Match Sockets' no-op while preserving its open-socket check.
        IOPoll._with_fd_ref(conn.fd.pfd) do _
            nothing
        end
    end
    return nothing
end

"""
    set_linger!(conn, timeout_secs)

Configure `SO_LINGER`, following Go's `SetLinger`: a negative timeout disables
lingering (`close` returns immediately and the OS flushes in the background —
the default), `0` discards unsent data on close with a RST, and a positive
timeout asks the OS to keep sending in the background. On some systems,
including Linux, a positive timeout may block `close` until data is sent or
discarded. Remaining data may be discarded after the timeout on some systems.
Nonnegative timeouts must not exceed 65535 seconds.
"""
function set_linger!(conn::Conn, timeout_secs::Integer)
    lg = if timeout_secs < 0
        SocketOps.Linger(0, 0)
    else
        timeout_secs > 0xffff && throw(ArgumentError("linger timeout must be at most 65535 seconds"))
        SocketOps.Linger(1, timeout_secs)
    end
    IOPoll.set_sockopt_bytes!(conn.fd.pfd, SocketOps.SOL_SOCKET, SocketOps.SO_LINGER, Ref(lg))
    return nothing
end

"""
    set_read_buffer!(conn, nbytes)

Set the kernel receive buffer size (`SO_RCVBUF`). The kernel may round the
value, enforce minimums, or (on Linux) double it to leave bookkeeping room.
"""
function set_read_buffer!(conn::Conn, nbytes::Integer)
    size = _positive_sockopt_value("buffer size", nbytes)
    IOPoll.set_sockopt_int!(conn.fd.pfd, SocketOps.SOL_SOCKET, SocketOps.SO_RCVBUF, size)
    return nothing
end

"""
    set_write_buffer!(conn, nbytes)

Set the kernel send buffer size (`SO_SNDBUF`). The kernel may round the
value, enforce minimums, or (on Linux) double it to leave bookkeeping room.
"""
function set_write_buffer!(conn::Conn, nbytes::Integer)
    size = _positive_sockopt_value("buffer size", nbytes)
    IOPoll.set_sockopt_int!(conn.fd.pfd, SocketOps.SOL_SOCKET, SocketOps.SO_SNDBUF, size)
    return nothing
end

"""
    rawfd(listener) -> RawFD or Base.WindowsRawSocket

Listener variant of [`rawfd`](@ref). The same ownership rules apply.
"""
function rawfd(listener::Listener)
    return _rawfd(listener.fd)
end

"""
    local_addr(conn) -> Union{Nothing, SocketAddr}

Return the cached local endpoint for `conn`, if known.
"""
function local_addr(conn::Conn)::Union{Nothing, SocketAddr}
    return conn.fd.laddr
end

"""
    local_addr(listener) -> Union{Nothing, SocketAddr}

Return the listener's bound local endpoint.

This is an alias for `addr(listener)`.
"""
function local_addr(listener::Listener)::Union{Nothing, SocketAddr}
    return addr(listener)
end

"""
    remote_addr(conn) -> Union{Nothing, SocketAddr}

Return the cached remote endpoint for `conn`, if known.
"""
function remote_addr(conn::Conn)::Union{Nothing, SocketAddr}
    return conn.fd.raddr
end

"""
    addr(listener) -> Union{Nothing, SocketAddr}

Return the listener's bound local endpoint, if known.
"""
function addr(listener::Listener)::Union{Nothing, SocketAddr}
    return listener.fd.laddr
end

@inline _show_state(conn::Conn) = IOPoll._fdlock_closing(conn.fd.pfd.fdlock) ? "closed" : "open"
@inline _show_state(listener::Listener) = IOPoll._fdlock_closing(listener.fd.pfd.fdlock) ? "closed" : "active"

function Base.show(io::IO, conn::Conn)
    print(io, "TCP.Conn(")
    _show_endpoint(io, local_addr(conn))
    print(io, " => ")
    _show_endpoint(io, remote_addr(conn))
    print(io, ", ", _show_state(conn), ")")
    return nothing
end

function Base.show(io::IO, listener::Listener)
    print(io, "TCP.Listener(")
    _show_endpoint(io, addr(listener))
    print(io, ", ", _show_state(listener), ")")
    return nothing
end

end
