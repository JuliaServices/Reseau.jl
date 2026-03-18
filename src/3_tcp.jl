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
"""
module TCP

using ..Reseau: ByteMemory
using ..Reseau.IOPoll
using ..Reseau.SocketOps

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
    SocketAddr

Abstract network endpoint type for TCP socket addresses.
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

Internal socket owner built on `IOPoll.FD`.

This is the internal object that owns the actual socket. Public callers usually
interact with `Conn` or `Listener`, but the transport implementation keeps the
extra metadata here so it can cache local/remote addresses, remember the socket
family, and share shutdown/close/deadline behavior with the poll layer.
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

Reads and writes are forwarded to `IOPoll`, which means blocking operations are
actually readiness waits against the shared low-level poller rather than
thread-per-socket blocking syscalls. Because `Conn <: IO`, standard Base stream
helpers like `read`, `read!`, `readbytes!`, `eof`, and `write` apply directly.
"""
struct Conn <: IO
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

function _wait_connect_complete!(
        fd::FD,
        remote_addr::SocketAddr,
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
        end
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
function open_tcp_fd!(; family::Cint = SocketOps.AF_INET)::FD
    sysfd = SocketOps.open_socket(family, SocketOps.SOCK_STREAM)
    return _new_netfd(sysfd; family = family, sotype = SocketOps.SOCK_STREAM, net = :tcp, is_connected = false)
end

function _connect_socketaddr_impl(
        remote_addr::SocketAddr,
        local_addr::Union{Nothing, SocketAddr},
        connect_deadline_ns::Int64,
        cancel_state,
    )::Conn
    family = _addr_family(remote_addr)
    if local_addr !== nothing && _addr_family(local_addr) != family
        throw(ArgumentError("local and remote address families must match"))
    end
    fd = open_tcp_fd!(; family = family)
    try
        if local_addr !== nothing
            SocketOps.bind_socket(fd.pfd.sysfd, _to_sockaddr(local_addr))
        elseif Sys.iswindows()
            # ConnectEx requires the socket to be bound first, even when the user
            # did not request a specific local address.
            _bind_connectex_local!(fd, family)
        end
        # Defensive re-assert: keep connect path non-blocking even if platform state drifts.
        SocketOps.set_nonblocking!(fd.pfd.sysfd, true)
        @static if Sys.iswindows()
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
                if connect_deadline_ns != 0
                    try
                        IOPoll.set_write_deadline!(fd.pfd, Int64(0))
                    catch
                    end
                end
            end
            _apply_default_tcp_opts!(fd)
            return Conn(fd)
        end
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
            if connect_deadline_ns != 0
                try
                    IOPoll.set_write_deadline!(fd.pfd, Int64(0))
                catch
                end
            end
        end
        _apply_default_tcp_opts!(fd)
        return Conn(fd)
    catch
        close(fd)
        rethrow()
    end
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
    return _connect_socketaddr_impl(remote_addr, nothing, Int64(0), nothing)
end

function connect(remote_addr::SocketAddr, local_addr::Union{Nothing, SocketAddr})::Conn
    return _connect_socketaddr_impl(remote_addr, local_addr, Int64(0), nothing)
end

"""
    listen(local_addr; backlog=128, reuseaddr=true)

Create a TCP listener from a bound local address.

This is the direct-address equivalent of the `listen(network, address; ...)`
overloads on the same `TCP.listen` generic.
"""
function listen(local_addr::SocketAddr; backlog::Integer = 128, reuseaddr::Bool = true)::Listener
    family = _addr_family(local_addr)
    fd = open_tcp_fd!(; family = family)
    try
        reuseaddr && SocketOps.set_sockopt_int(fd.pfd.sysfd, SocketOps.SOL_SOCKET, SocketOps.SO_REUSEADDR, 1)
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

"""
    accept(listener)

Accept a new `Conn` from `listener`.

Throws `SystemError`, `IOPoll.DeadlineExceededError`, or other poll/transport
errors if the underlying accept path fails.
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

function _peek_eof(conn::Conn)::Bool
    pfd = conn.fd.pfd
    pref = Ref{UInt8}(0x00)
    while true
        IOPoll.prepareread(pfd.pd, pfd.is_file)
        n = GC.@preserve pref SocketOps.recv_from!(
            pfd.sysfd,
            Base.unsafe_convert(Ptr{UInt8}, pref),
            Csize_t(1),
            SocketOps.MSG_PEEK,
        )
        if n > 0
            return false
        end
        n == 0 && return true
        errno = SocketOps.last_error()
        if errno == Int32(Base.Libc.EAGAIN) && IOPoll.pollable(pfd.pd)
            IOPoll.waitread(pfd.pd, pfd.is_file)
            continue
        end
        throw(SystemError("recv(MSG_PEEK)", Int(errno)))
    end
end

"""
    unsafe_read(conn, ptr, nbytes)

Read exactly `nbytes` into `ptr` or throw `EOFError`.

This is the primitive that powers Julia's standard `read!` behavior once
`TCP.Conn` participates in the `IO` hierarchy.
"""
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

function _readbytes_all!(conn::Conn, buf::Vector{UInt8}, requested::Int)::Int
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
    if current_len > original_len && current_len > bytes_read
        resize!(buf, max(original_len, bytes_read))
    end
    return bytes_read
end

function _readbytes_some!(conn::Conn, buf::Vector{UInt8}, requested::Int)::Int
    original_len = length(buf)
    requested > original_len && resize!(buf, requested)
    bytes_read = try
        GC.@preserve buf _read_some!(conn, pointer(buf), requested)
    catch err
        ex = err::Exception
        ex isa EOFError || rethrow(ex)
        0
    end
    current_len = length(buf)
    if current_len > original_len && current_len > bytes_read
        resize!(buf, max(original_len, bytes_read))
    end
    return bytes_read
end

"""
    read!(conn, buf) -> buf

Read exactly `length(buf)` bytes into `buf` or throw `EOFError`.

Use `readbytes!` or `readavailable` when you want a count-returning read that
may stop early.
"""
Base.read!(conn::Conn, buf::Vector{UInt8})

"""
    readbytes!(conn, buf, nb=length(buf); all::Bool=true) -> Int

Read up to `nb` bytes into `buf`, returning the byte count.

Unlike `read!(conn, buf)`, this API may return after a short read or EOF. It is
the count-returning TCP read entrypoint once `TCP.Conn` follows Julia's `IO`
contract.

If `all` is `true` (the default), the call keeps reading until `nb` bytes have
been transferred, EOF is reached, or an error occurs. If `all` is `false`, at
most one underlying socket read is performed.
"""
function Base.readbytes!(conn::Conn, buf::Vector{UInt8}, nb::Integer = length(buf); all::Bool = true)::Int
    Base.require_one_based_indexing(buf)
    requested = Int(nb)
    requested < 0 && throw(ArgumentError("nb must be >= 0"))
    requested == 0 && return 0
    return all ? _readbytes_all!(conn, buf, requested) : _readbytes_some!(conn, buf, requested)
end

"""
    read(conn, nb::Integer; all::Bool=true) -> Vector{UInt8}

Read and return up to `nb` bytes from `conn`.

If `all` is `true` (the default), the call keeps reading until `nb` bytes have
been transferred, EOF is reached, or an error occurs. If `all` is `false`, at
most one underlying socket read is performed.
"""
function Base.read(conn::Conn, nb::Integer; all::Bool = true)::Vector{UInt8}
    requested = Int(nb)
    requested < 0 && throw(ArgumentError("nb must be >= 0"))
    buf = Vector{UInt8}(undef, all && requested == typemax(Int) ? 1024 : requested)
    n = readbytes!(conn, buf, requested; all = all)
    return resize!(buf, n)
end

"""
    readavailable(conn) -> Vector{UInt8}

Read and return the bytes that are currently ready without requiring a
full-buffer exact read.
"""
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

"""
    eof(conn) -> Bool

Report whether the peer has cleanly closed the read side of the connection.
"""
function Base.eof(conn::Conn)::Bool
    isopen(conn) || return true
    return _peek_eof(conn)
end

function Base.isopen(conn::Conn)::Bool
    return conn.fd.pfd.sysfd >= 0
end

function Base.flush(::Conn)
    return nothing
end

"""
    write(conn, byte::UInt8) -> Int

Write one byte to the connection and return `1`.
"""
function Base.write(conn::Conn, byte::UInt8)::Int
    ref = Ref{UInt8}(byte)
    GC.@preserve ref begin
        return Int(Base.unsafe_write(conn, Base.unsafe_convert(Ptr{UInt8}, ref), UInt(1)))
    end
end

"""
    unsafe_write(conn, ptr, nbytes)

Write exactly `nbytes` from `ptr`, returning the number of bytes written.
"""
function Base.unsafe_write(conn::Conn, ptr::Ptr{UInt8}, nbytes::UInt)
    return IOPoll._write_ptr!(conn.fd.pfd, ptr, Int(nbytes))
end

"""
    write(conn, buf) -> Int

Write all bytes from `buf` and return the number of bytes written.

On success, the return value is always `length(buf)`. If the socket cannot
currently accept data, the call waits for write readiness and resumes until the
entire buffer has been written or an error/deadline interrupts the operation.
"""
Base.write(conn::Conn, buf::AbstractVector{UInt8})

function Base.write(conn::Conn, buf::Vector{UInt8})::Int
    GC.@preserve buf begin
        return Int(Base.unsafe_write(conn, pointer(buf), UInt(length(buf))))
    end
end

function Base.write(conn::Conn, buf::StridedVector{UInt8})::Int
    if stride(buf, 1) == 1
        return GC.@preserve buf Int(Base.unsafe_write(conn, pointer(buf), UInt(length(buf))))
    end
    data = Vector{UInt8}(buf)
    GC.@preserve data begin
        return Int(Base.unsafe_write(conn, pointer(data), UInt(length(data))))
    end
end

function Base.write(conn::Conn, buf::AbstractVector{UInt8})::Int
    data = Vector{UInt8}(buf)
    GC.@preserve data begin
        return Int(Base.unsafe_write(conn, pointer(data), UInt(length(data))))
    end
end

"""
    write(conn, buf, nbytes) -> Int

Write the first `nbytes` bytes from `buf` and return the number of bytes
written.

On success, the return value is always exactly `nbytes`. Like the `Vector`
overload, this may block waiting for write readiness between partial kernel
writes.
"""
function Base.write(conn::Conn, buf::ByteMemory, nbytes::Integer)::Int
    n = Int(nbytes)
    n < 0 && throw(ArgumentError("nbytes must be >= 0"))
    n <= length(buf) || throw(ArgumentError("nbytes exceeds buffer length"))
    GC.@preserve buf begin
        return Int(Base.unsafe_write(conn, pointer(buf), UInt(n)))
    end
end

"""
    close(conn)

Close the connection. Repeated closes are treated as no-ops.
"""
function Base.close(conn::Conn)
    close(conn.fd)
    return nothing
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
    closeread(conn)

Shut down the read side of the TCP connection.
"""
function closeread(conn::Conn)
    SocketOps.shutdown_socket(conn.fd.pfd.sysfd, SocketOps.SHUT_RD)
    return nothing
end

"""
    closewrite(conn)

Shut down the write side of the TCP connection.
"""
function Base.closewrite(conn::Conn)
    SocketOps.shutdown_socket(conn.fd.pfd.sysfd, SocketOps.SHUT_WR)
    return nothing
end

"""
    close(fd)

Close a net descriptor. Repeated closes are treated as no-op.
"""
function Base.close(fd::FD)
    close(fd.pfd)
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

"""
    set_nodelay!(conn, enabled=true)

Enable or disable `TCP_NODELAY` on `conn`.
"""
function set_nodelay!(conn::Conn, enabled::Bool = true)
    SocketOps.set_sockopt_int(
        conn.fd.pfd.sysfd,
        SocketOps.IPPROTO_TCP,
        SocketOps.TCP_NODELAY,
        enabled ? 1 : 0,
    )
    return nothing
end

"""
    set_keepalive!(conn, enabled=true)

Enable or disable `SO_KEEPALIVE` on `conn`.
"""
function set_keepalive!(conn::Conn, enabled::Bool = true)
    SocketOps.set_sockopt_int(
        conn.fd.pfd.sysfd,
        SocketOps.SOL_SOCKET,
        SocketOps.SO_KEEPALIVE,
        enabled ? 1 : 0,
    )
    return nothing
end

"""
    local_addr(conn) -> Union{Nothing, SocketAddr}

Return the cached local endpoint for `conn`, if known.
"""
function local_addr(conn::Conn)::Union{Nothing, SocketAddr}
    return conn.fd.laddr
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

@inline function _show_endpoint(io::IO, endpoint::Union{Nothing, SocketAddr})
    if endpoint === nothing
        print(io, "?")
    else
        show(io, endpoint)
    end
    return nothing
end

@inline _show_state(conn::Conn) = conn.fd.pfd.sysfd >= 0 ? "open" : "closed"
@inline _show_state(listener::Listener) = listener.fd.pfd.sysfd >= 0 ? "active" : "closed"

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
