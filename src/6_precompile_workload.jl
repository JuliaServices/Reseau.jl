# Production precompile workload. Helpers exercise real Reseau code paths so
# precompile artifacts stay aligned with the transport/runtime stack we ship.
using PrecompileTools: @compile_workload, @setup_workload

const IP = IOPoll
const SO = SocketOps
const NC = TCP
const ND = HostResolvers
const TL = TLS

@inline function _pc_trace(event::AbstractString, details::AbstractString = "")::Nothing
    IP._diagnostic_trace("precompile.$(event)", details)
    return nothing
end

@inline function _pc_runtime_supported()::Bool
    return Sys.isapple() || Sys.islinux() || Sys.iswindows()
end

const _PC_EWOULDBLOCK = @static isdefined(Base.Libc, :EWOULDBLOCK) ? Int32(getfield(Base.Libc, :EWOULDBLOCK)) : Int32(Base.Libc.EAGAIN)

function _pc_stream_pair()::Tuple{SO.SocketFD, SO.SocketFD}
    listener = SO.INVALID_SOCKET
    client = SO.INVALID_SOCKET
    accepted = SO.INVALID_SOCKET
    try
        listener = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        SO.set_sockopt_int(listener, SO.SOL_SOCKET, SO.SO_REUSEADDR, 1)
        SO.bind_socket(listener, SO.sockaddr_in_loopback(0))
        SO.listen_socket(listener, 32)
        bound = SO.get_socket_name_in(listener)
        port = Int(SO.sockaddr_in_port(bound))
        client = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        SO.set_nonblocking!(client, false)
        try
            errno = SO.connect_socket(client, SO.sockaddr_in_loopback(port))
            errno == Int32(0) || errno == Int32(Base.Libc.EISCONN) || throw(SystemError("connect", Int(errno)))
        finally
            SO.set_nonblocking!(client, true)
        end
        accepted = _pc_accept_with_retry!(listener)
        stream_client = client
        stream_server = accepted
        client = SO.INVALID_SOCKET
        accepted = SO.INVALID_SOCKET
        return stream_client, stream_server
    finally
        SO.is_valid_socket(accepted) && SO.close_socket_nothrow(accepted)
        SO.is_valid_socket(client) && SO.close_socket_nothrow(client)
        SO.is_valid_socket(listener) && SO.close_socket_nothrow(listener)
    end
end

function _pc_close_fd(fd::SO.SocketFD)
    SO.is_valid_socket(fd) || return nothing
    SO.close_socket_nothrow(fd)
    return nothing
end

function _pc_write_byte(fd::SO.SocketFD, b::UInt8)
    buf = Ref{UInt8}(b)
    for _ in 1:5000
        n = GC.@preserve buf SO.write_once!(fd, Base.unsafe_convert(Ptr{UInt8}, buf), Csize_t(1))
        n == Cssize_t(1) && return nothing
        errno = SO.last_error()
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _PC_EWOULDBLOCK && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("write", Int(errno)))
    end
    throw(ArgumentError("timed out writing byte"))
end

function _pc_write_all!(fd::SO.SocketFD, data::Vector{UInt8})::Nothing
    offset = 0
    while offset < length(data)
        n = GC.@preserve data SO.write_once!(fd, pointer(data, offset + 1), Csize_t(length(data) - offset))
        if n > 0
            offset += Int(n)
            continue
        end
        errno = SO.last_error()
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _PC_EWOULDBLOCK && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("write", Int(errno)))
    end
    return nothing
end

function _pc_read_exact_fd!(fd::SO.SocketFD, data::Vector{UInt8})::Nothing
    offset = 0
    while offset < length(data)
        n = GC.@preserve data SO.read_once!(fd, pointer(data, offset + 1), Csize_t(length(data) - offset))
        if n > 0
            offset += Int(n)
            continue
        end
        n == 0 && throw(EOFError())
        errno = SO.last_error()
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _PC_EWOULDBLOCK && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("read", Int(errno)))
    end
    return nothing
end

function _pc_read_exact!(conn::NC.Conn, buf::Vector{UInt8})::Int
    read!(conn, buf)
    return length(buf)
end

function _pc_wait_connect_ready!(fd::SO.SocketFD)
    registration = IP.register!(fd; mode = IP.PollMode.WRITE)
    try
        IP.arm_waiter!(registration, IP.PollMode.WRITE)
        IP.pollwait!(registration.write_waiter)
    finally
        IP.deregister!(fd)
    end
    return nothing
end

function _pc_accept_with_retry!(listener::SO.SocketFD)::SO.SocketFD
    for _ in 1:5000
        accepted, _, errno = SO.try_accept_socket(listener)
        SO.is_valid_socket(accepted) && return accepted
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _PC_EWOULDBLOCK && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("accept", Int(errno)))
    end
    throw(ArgumentError("timed out waiting for accepted socket"))
end

function _pc_wait_task_done(task::Task, timeout_s::Float64 = 2.0)::Nothing
    status = IP.timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
    status == :timed_out && throw(ArgumentError("precompile helper task timed out"))
    wait(task)
    return nothing
end

function _pc_workload_enabled(name::AbstractString)::Bool
    only = strip(get(ENV, "RESEAU_PRECOMPILE_ONLY", ""))
    isempty(only) && return true
    for part in split(only, ',')
        strip(part) == name && return true
    end
    return false
end

function _pc_run_eventloops_workload!()
    _pc_trace("eventloops.enter")
    IP.__init__()
    _pc_trace("eventloops.iopoll_init.done")
    @assert isassigned(IP.POLLER)
    waiter = IP.PollWaiter()
    IP.pollnotify!(waiter)
    IP.pollwait!(waiter)
    _pc_trace("eventloops.waiter_smoke.done")
    _pc_runtime_supported() || return nothing
    state = IP.Poller()
    fd0 = SO.INVALID_SOCKET
    fd1 = SO.INVALID_SOCKET
    backend_open = false
    try
        _pc_trace("eventloops.backend_init.before")
        errno = IP._backend_init!(state)
        _pc_trace("eventloops.backend_init.after", "errno=$(errno)")
        errno == Int32(0) || throw(SystemError("event loop backend init", Int(errno)))
        backend_open = true
        _pc_trace("eventloops.stream_pair.before")
        fd0, fd1 = _pc_stream_pair()
        _pc_trace("eventloops.stream_pair.after", "fd0=$(fd0) fd1=$(fd1)")
        token = UInt64(1)
        registration = IP.Registration(fd0, token, IP.PollMode.READWRITE, IP.PollWaiter(), IP.PollWaiter(), false)
        state.registrations[fd0] = registration
        state.registrations_by_token[token] = registration
        _pc_trace("eventloops.backend_open_fd.before", "fd=$(fd0)")
        errno = IP._backend_open_fd!(state, fd0, IP.PollMode.READWRITE, token)
        _pc_trace("eventloops.backend_open_fd.after", "errno=$(errno)")
        errno == Int32(0) || throw(SystemError("event loop open fd", Int(errno)))
        _pc_trace("eventloops.arm_read.before")
        errno = IP._backend_arm_waiter!(state, registration, IP.PollMode.READ)
        _pc_trace("eventloops.arm_read.after", "errno=$(errno)")
        errno == Int32(0) || throw(SystemError("event loop arm read waiter", Int(errno)))
        _pc_trace("eventloops.write_byte.before")
        _pc_write_byte(fd1, 0x31)
        _pc_trace("eventloops.write_byte.after")
        ready = false
        for attempt in 1:20
            _pc_trace("eventloops.poll_once.before", "attempt=$(attempt)")
            errno = IP._backend_poll_once!(state, Int64(50_000_000))
            _pc_trace("eventloops.poll_once.after", "attempt=$(attempt) errno=$(errno)")
            errno == Int32(0) || throw(SystemError("event loop poll once", Int(errno)))
            if (@atomic :acquire registration.read_waiter.state) === IP._POLLWAKE_READY
                IP.pollwait!(registration.read_waiter)
                ready = true
                break
            end
        end
        ready || throw(ArgumentError("event loop workload did not observe readability"))
        recv_buf = Vector{UInt8}(undef, 1)
        _pc_trace("eventloops.read_exact.before")
        _pc_read_exact_fd!(fd0, recv_buf)
        _pc_trace("eventloops.read_exact.after")
        _pc_trace("eventloops.backend_close_fd.before")
        errno = IP._backend_close_fd!(state, fd0)
        _pc_trace("eventloops.backend_close_fd.after", "errno=$(errno)")
        errno == Int32(0) || throw(SystemError("event loop close fd", Int(errno)))
    finally
        _pc_trace("eventloops.finally.enter")
        _pc_close_fd(fd0)
        _pc_close_fd(fd1)
        if backend_open
            _pc_trace("eventloops.backend_close.before")
            IP._backend_close!(state)
            _pc_trace("eventloops.backend_close.after")
        end
        _pc_trace("eventloops.shutdown.before")
        IP.shutdown!()
        _pc_trace("eventloops.shutdown.after")
    end
    _pc_trace("eventloops.exit")
    return nothing
end

function _pc_run_internal_poll_workload!()
    _pc_trace("internal_poll.enter")
    _pc_runtime_supported() || return nothing
    _pc_trace("internal_poll.stream_pair.before")
    fd0, fd1 = _pc_stream_pair()
    _pc_trace("internal_poll.stream_pair.after", "fd0=$(fd0) fd1=$(fd1)")
    ipfd = IP.FD(fd0)
    fd0 = SO.INVALID_SOCKET
    try
        IP._set_nonblocking!(ipfd.sysfd)
        _pc_trace("internal_poll.register.before", "fd=$(ipfd.sysfd)")
        IP.register!(ipfd)
        _pc_trace("internal_poll.register.after")
        IP.set_read_deadline!(ipfd, time_ns() + 8_000_000)
        _pc_trace("internal_poll.deadline_read.before")
        try
            IP.read!(ipfd, Vector{UInt8}(undef, 1))
        catch err
            err isa IP.DeadlineExceededError || rethrow(err)
            _pc_trace("internal_poll.deadline_read.expired")
        end
        IP.set_read_deadline!(ipfd, Int64(0))
        _pc_trace("internal_poll.write_byte.before")
        _pc_write_byte(fd1, 0x66)
        _pc_trace("internal_poll.write_byte.after")
        _pc_trace("internal_poll.read.before")
        n = IP.read!(ipfd, Vector{UInt8}(undef, 1))
        _pc_trace("internal_poll.read.after", "n=$(n)")
        n == 1 || error("internal poll workload expected one-byte read")
    finally
        _pc_trace("internal_poll.finally.enter")
        IP._is_valid_fd(ipfd.sysfd) && close(ipfd)
        _pc_close_fd(fd1)
        _pc_trace("internal_poll.shutdown.before")
        IP.shutdown!()
        _pc_trace("internal_poll.shutdown.after")
    end
    _pc_trace("internal_poll.exit")
    return nothing
end

function _pc_run_socket_ops_workload!()
    _pc_trace("socket_ops.enter")
    _pc_runtime_supported() || return nothing
    listener = SO.INVALID_SOCKET
    client = SO.INVALID_SOCKET
    accepted = SO.INVALID_SOCKET
    try
        _pc_trace("socket_ops.listener_open.before")
        listener = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        _pc_trace("socket_ops.listener_open.after", "fd=$(listener)")
        SO.set_sockopt_int(listener, SO.SOL_SOCKET, SO.SO_REUSEADDR, 1)
        SO.bind_socket(listener, SO.sockaddr_in_loopback(0))
        SO.listen_socket(listener, 16)
        bound = SO.get_socket_name_in(listener)
        port = Int(SO.sockaddr_in_port(bound))
        _pc_trace("socket_ops.client_open.before", "port=$(port)")
        client = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        _pc_trace("socket_ops.client_open.after", "fd=$(client)")
        _pc_trace("socket_ops.connect.before", "port=$(port)")
        errno = SO.connect_socket(client, SO.sockaddr_in_loopback(port))
        _pc_trace("socket_ops.connect.after", "errno=$(errno)")
        if errno != Int32(0) && errno != Int32(Base.Libc.EISCONN)
            if errno != Int32(Base.Libc.EINPROGRESS) && errno != Int32(Base.Libc.EALREADY) && errno != Int32(Base.Libc.EINTR)
                throw(SystemError("connect", Int(errno)))
            end
            _pc_trace("socket_ops.connect_wait.before")
            _pc_wait_connect_ready!(client)
            _pc_trace("socket_ops.connect_wait.after")
            so_error = SO.get_socket_error(client)
            so_error == Int32(0) || throw(SystemError("connect(SO_ERROR)", Int(so_error)))
        end
        _pc_trace("socket_ops.accept.before")
        accepted = _pc_accept_with_retry!(listener)
        _pc_trace("socket_ops.accept.after", "fd=$(accepted)")
        payload = UInt8[0x31, 0x32]
        recv_buf = Vector{UInt8}(undef, 2)
        _pc_trace("socket_ops.write.before")
        _pc_write_all!(client, payload)
        _pc_trace("socket_ops.write.after")
        _pc_trace("socket_ops.read.before")
        _pc_read_exact_fd!(accepted, recv_buf)
        _pc_trace("socket_ops.read.after")
    finally
        _pc_trace("socket_ops.finally.enter")
        SO.is_valid_socket(accepted) && SO.close_socket_nothrow(accepted)
        SO.is_valid_socket(client) && SO.close_socket_nothrow(client)
        SO.is_valid_socket(listener) && SO.close_socket_nothrow(listener)
        _pc_trace("socket_ops.shutdown.before")
        IP.shutdown!()
        _pc_trace("socket_ops.shutdown.after")
    end
    _pc_trace("socket_ops.exit")
    return nothing
end

function _pc_run_tcp_workload!()
    _pc_trace("tcp.enter")
    _pc_runtime_supported() || return nothing
    listener = nothing
    client = nothing
    server = nothing
    try
        _pc_trace("tcp.listen.before")
        listener = NC.listen(NC.loopback_addr(0); backlog = 16)
        _pc_trace("tcp.listen.after")
        laddr = NC.addr(listener)
        _pc_trace("tcp.connect.before", "port=$(Int((laddr::NC.SocketAddrV4).port))")
        client = NC.connect(NC.loopback_addr(Int((laddr::NC.SocketAddrV4).port)))
        _pc_trace("tcp.connect.after")
        _pc_trace("tcp.accept.before")
        server = NC.accept(listener)
        _pc_trace("tcp.accept.after")
        payload = UInt8[0x41, 0x42, 0x43]
        _pc_trace("tcp.write.before")
        written = write(client, payload)
        _pc_trace("tcp.write.after", "written=$(written)")
        written == length(payload) || throw(ArgumentError("tcp workload expected 3-byte write"))
        recv_buf = Vector{UInt8}(undef, length(payload))
        _pc_trace("tcp.read.before")
        _pc_read_exact!(server, recv_buf) == length(payload) || throw(EOFError())
        _pc_trace("tcp.read.after")
    finally
        _pc_trace("tcp.finally.enter")
        try
            server === nothing || close(server)
        catch
        end
        try
            client === nothing || close(client)
        catch
        end
        try
            listener === nothing || close(listener)
        catch
        end
        _pc_trace("tcp.shutdown.before")
        IP.shutdown!()
        _pc_trace("tcp.shutdown.after")
    end
    _pc_trace("tcp.exit")
    return nothing
end

function _pc_run_host_resolvers_workload!()
    _pc_trace("host_resolvers.enter")
    _pc_runtime_supported() || return nothing
    listener = nothing
    client = nothing
    server = nothing
    try
        _pc_trace("host_resolvers.listen.before")
        listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 16)
        _pc_trace("host_resolvers.listen.after")
        laddr = NC.addr(listener)
        _pc_trace("host_resolvers.connect.before", "port=$(Int((laddr::NC.SocketAddrV4).port))")
        client = ND.connect("tcp", ND.join_host_port("127.0.0.1", Int((laddr::NC.SocketAddrV4).port)))
        _pc_trace("host_resolvers.connect.after")
        _pc_trace("host_resolvers.accept.before")
        server = NC.accept(listener)
        _pc_trace("host_resolvers.accept.after")
        payload = UInt8[0x51, 0x52]
        _pc_trace("host_resolvers.write.before")
        written = write(client, payload)
        _pc_trace("host_resolvers.write.after", "written=$(written)")
        written == length(payload) || throw(ArgumentError("host resolver workload expected 2-byte write"))
        recv_buf = Vector{UInt8}(undef, length(payload))
        _pc_trace("host_resolvers.read.before")
        _pc_read_exact!(server, recv_buf) == length(payload) || throw(EOFError())
        _pc_trace("host_resolvers.read.after")
    finally
        _pc_trace("host_resolvers.finally.enter")
        try
            server === nothing || close(server)
        catch
        end
        try
            client === nothing || close(client)
        catch
        end
        try
            listener === nothing || close(listener)
        catch
        end
        try
            _pc_trace("host_resolvers.resolver_shutdown.before")
            ND.shutdown!()
            _pc_trace("host_resolvers.resolver_shutdown.after")
        catch
            _pc_trace("host_resolvers.resolver_shutdown.error")
        end
        _pc_trace("host_resolvers.iopoll_shutdown.before")
        IP.shutdown!()
        _pc_trace("host_resolvers.iopoll_shutdown.after")
    end
    _pc_trace("host_resolvers.exit")
    return nothing
end

function _pc_tls_resource_file(name::AbstractString)::Union{Nothing, String}
    pkg_root = normpath(joinpath(@__DIR__, ".."))
    path = joinpath(pkg_root, "test", "resources", name)
    return isfile(path) ? path : nothing
end

function _pc_close_nothrow(resource)
    resource === nothing && return nothing
    try
        close(resource)
    catch
    end
    return nothing
end

"""
    _pc_tls_server_config(cert_path, key_path; ...) -> TL.Config

Build the server-side TLS config used by the package-owned TLS precompile
workload.

The workload intentionally uses the same public `TLS.Config` API that package
users see so precompile artifacts track real supported entrypoints instead of a
special internal harness.
"""
function _pc_tls_server_config(
    cert_path::String,
    key_path::String;
    client_auth::TL.ClientAuthMode.T = TL.ClientAuthMode.NoClientCert,
    client_ca_file::Union{Nothing, String} = nothing,
    session_tickets_disabled::Bool = false,
    curve_preferences::Vector{UInt16} = UInt16[],
    min_version::UInt16 = TL.TLS1_3_VERSION,
    max_version::Union{Nothing, UInt16} = TL.TLS1_3_VERSION,
)::TL.Config
    return TL.Config(
        verify_peer = false,
        cert_file = cert_path,
        key_file = key_path,
        client_auth = client_auth,
        client_ca_file = client_ca_file,
        curve_preferences = copy(curve_preferences),
        handshake_timeout_ns = 1_000_000_000,
        min_version = min_version,
        max_version = max_version,
        session_tickets_disabled = session_tickets_disabled,
    )
end

"""
    _pc_tls_client_config(; ...) -> TL.Config

Build the client-side TLS config used by the package-owned TLS precompile
workload.

Keyword defaults keep the workload deterministic while still covering the
native TLS routing surface the package supports in production.
"""
function _pc_tls_client_config(;
    verify_peer::Bool = false,
    verify_hostname::Bool = verify_peer,
    server_name::Union{Nothing, String} = "localhost",
    ca_file::Union{Nothing, String} = nothing,
    cert_file::Union{Nothing, String} = nothing,
    key_file::Union{Nothing, String} = nothing,
    session_tickets_disabled::Bool = false,
    curve_preferences::Vector{UInt16} = UInt16[],
    min_version::UInt16 = TL.TLS1_3_VERSION,
    max_version::Union{Nothing, UInt16} = TL.TLS1_3_VERSION,
)::TL.Config
    return TL.Config(
        verify_peer = verify_peer,
        verify_hostname = verify_hostname,
        server_name = server_name,
        ca_file = ca_file,
        cert_file = cert_file,
        key_file = key_file,
        handshake_timeout_ns = 1_000_000_000,
        curve_preferences = copy(curve_preferences),
        min_version = min_version,
        max_version = max_version,
        session_tickets_disabled = session_tickets_disabled,
    )
end

struct _PCTLSIdentityPaths
    cert::String
    key::String
end

struct _PCTLSNativeFixturePaths
    ca::String
    server_cert::String
    server_key::String
    client_cert::String
    client_key::String
end

struct _PCTLSRoundtripStates
    client_state::TL.ConnectionState
    server_state::TL.ConnectionState
end

function _pc_tls13_native_paths()::Union{Nothing, _PCTLSNativeFixturePaths}
    ca_path = _pc_tls_resource_file("native_tls_ca.crt")
    server_cert_path = _pc_tls_resource_file("native_tls_server.crt")
    server_key_path = _pc_tls_resource_file("native_tls_server.key")
    client_cert_path = _pc_tls_resource_file("native_tls_client.crt")
    client_key_path = _pc_tls_resource_file("native_tls_client.key")
    if ca_path === nothing ||
       server_cert_path === nothing ||
       server_key_path === nothing ||
       client_cert_path === nothing ||
       client_key_path === nothing
        return nothing
    end
    return _PCTLSNativeFixturePaths(
        ca_path::String,
        server_cert_path::String,
        server_key_path::String,
        client_cert_path::String,
        client_key_path::String,
    )
end

function _pc_tls12_paths()::Union{Nothing, _PCTLSIdentityPaths}
    cert_path = _pc_tls_resource_file("unittests.crt")
    key_path = _pc_tls_resource_file("unittests.key")
    if cert_path === nothing || key_path === nothing
        return nothing
    end
    return _PCTLSIdentityPaths(cert_path::String, key_path::String)
end

function _pc_tls12_ecdsa_paths()::Union{Nothing, _PCTLSIdentityPaths}
    cert_path = _pc_tls_resource_file("native_tls_server_ecdsa.crt")
    key_path = _pc_tls_resource_file("native_tls_server_ecdsa.key")
    if cert_path === nothing || key_path === nothing
        return nothing
    end
    return _PCTLSIdentityPaths(cert_path::String, key_path::String)
end

"""
    _pc_expect_tls_state!(state, expected_version, expect_native_tls13, ...)

Assert the negotiated public `TLS.connection_state` shape emitted by the
precompile workload.

This keeps the workload honest: the compile frontier is not just "a handshake
ran", but "the supported public state surface behaves as expected afterward".
"""
function _pc_expect_tls_state!(
    state::TL.ConnectionState,
    expected_version::String,
    expect_native_tls13::Bool,
    expect_resume::Union{Nothing, Bool} = nothing,
    expect_resumable::Union{Nothing, Bool} = nothing,
    expected_curve::Union{Nothing, String} = nothing,
)::Nothing
    state.handshake_complete || throw(ArgumentError("TLS precompile workload expected a completed handshake"))
    state.version == expected_version || throw(ArgumentError("TLS precompile workload expected $(expected_version)"))
    state.using_native_tls13 == expect_native_tls13 ||
        throw(ArgumentError("TLS precompile workload observed an unexpected native TLS mode"))
    expect_resume === nothing || state.did_resume == expect_resume ||
        throw(ArgumentError("TLS precompile workload observed an unexpected resumed state"))
    expect_resumable === nothing || state.has_resumable_session == expect_resumable ||
        throw(ArgumentError("TLS precompile workload observed an unexpected resumable-session state"))
    if expect_native_tls13
        state.cipher_suite in (
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ) || throw(ArgumentError("TLS precompile workload expected a native TLS 1.3 cipher suite"))
        if expected_curve === nothing
            state.curve in ("X25519", "P-256") ||
                throw(ArgumentError("TLS precompile workload expected a native TLS 1.3 curve"))
        else
            state.curve == expected_curve || throw(ArgumentError("TLS precompile workload observed an unexpected curve"))
        end
    else
        state.cipher_suite in (
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        ) || throw(ArgumentError("TLS precompile workload expected a native TLS 1.2 ECDHE cipher suite"))
        if expected_curve === nothing
            state.curve in ("X25519", "P-256") ||
                throw(ArgumentError("TLS precompile workload expected a native TLS 1.2 curve"))
        else
            state.curve == expected_curve || throw(ArgumentError("TLS precompile workload observed an unexpected curve"))
        end
    end
    return nothing
end

"""
    _pc_run_tls_roundtrip_states!(server_config, client_config) -> _PCTLSRoundtripStates

Drive one public-API TLS roundtrip and return the post-handshake connection
state snapshots observed by both peers.

The helper exercises `TLS.listen`, `TLS.accept`, `TLS.connect`, `TLS.handshake!`,
`read`, `write`, `eof`, and `connection_state` so the canonical workload stays
anchored at the supported public surface.
"""
function _pc_run_tls_roundtrip_states!(
    server_config::TL.Config,
    client_config::TL.Config,
)::_PCTLSRoundtripStates
    _pc_trace("tls.roundtrip_states.enter")
    listener = nothing
    client = nothing
    server_task = nothing
    try
        _pc_trace("tls.listen.before")
        listener = TL.listen(NC.loopback_addr(0), server_config; backlog = 8)
        _pc_trace("tls.listen.after")
        laddr = TL.addr(listener)::NC.SocketAddrV4
        server_task = @async begin
            _pc_trace("tls.server.accept.before")
            conn = TL.accept(listener::TL.Listener)
            _pc_trace("tls.server.accept.after")
            try
                _pc_trace("tls.server.handshake.before")
                TL.handshake!(conn)
                _pc_trace("tls.server.handshake.after")
                state = TL.connection_state(conn)
                _pc_trace("tls.server.write.before")
                write(conn, UInt8[0x41]) == 1 || throw(ArgumentError("TLS precompile workload expected 1-byte server write"))
                _pc_trace("tls.server.write.after")
                _pc_trace("tls.server.read.before")
                read(conn, 1) == UInt8[0x51] || throw(ArgumentError("TLS precompile workload expected 1-byte client ack"))
                _pc_trace("tls.server.read.after")
                return state
            finally
                _pc_trace("tls.server.close.before")
                _pc_close_nothrow(conn)
                _pc_trace("tls.server.close.after")
            end
        end
        _pc_trace("tls.client.connect.before", "port=$(Int(laddr.port))")
        client = TL.connect(NC.loopback_addr(Int(laddr.port)), client_config)
        _pc_trace("tls.client.connect.after")
        _pc_trace("tls.client.read.before")
        read(client, 1) == UInt8[0x41] || throw(ArgumentError("TLS precompile workload expected server byte"))
        _pc_trace("tls.client.read.after")
        _pc_trace("tls.client.write.before")
        write(client, UInt8[0x51]) == 1 || throw(ArgumentError("TLS precompile workload expected client ack write"))
        _pc_trace("tls.client.write.after")
        _pc_trace("tls.client.eof.before")
        eof(client) || throw(ArgumentError("TLS precompile workload expected connection EOF"))
        _pc_trace("tls.client.eof.after")
        client_state = TL.connection_state(client)
        _pc_trace("tls.server_task_wait.before")
        _pc_wait_task_done(server_task::Task, 2.0)
        _pc_trace("tls.server_task_wait.after")
        return _PCTLSRoundtripStates(client_state, fetch(server_task::Task)::TL.ConnectionState)
    finally
        _pc_trace("tls.roundtrip_states.finally.enter")
        _pc_close_nothrow(client)
        _pc_close_nothrow(listener)
        _pc_trace("tls.roundtrip_states.shutdown.before")
        IP.shutdown!()
        _pc_trace("tls.roundtrip_states.shutdown.after")
    end
end

"""
    _pc_run_tls_roundtrip!(server_config, client_config, expected_version, expect_native_tls13, ...)

Run one public TLS roundtrip scenario and validate both peers' public
`ConnectionState`.
"""
function _pc_run_tls_roundtrip!(
    server_config::TL.Config,
    client_config::TL.Config,
    expected_version::String,
    expect_native_tls13::Bool,
    expect_client_resume::Union{Nothing, Bool} = nothing,
    expect_client_resumable::Union{Nothing, Bool} = nothing,
    expect_server_resume::Union{Nothing, Bool} = nothing,
    expected_curve::Union{Nothing, String} = nothing,
)::Nothing
    _pc_trace(
        "tls.roundtrip.enter",
        "version=$(expected_version) native13=$(expect_native_tls13) " *
        "client_resume=$(expect_client_resume) curve=$(expected_curve)",
    )
    roundtrip_states = _pc_run_tls_roundtrip_states!(server_config, client_config)
    _pc_expect_tls_state!(roundtrip_states.client_state, expected_version, expect_native_tls13, expect_client_resume, expect_client_resumable, expected_curve)
    _pc_expect_tls_state!(roundtrip_states.server_state, expected_version, expect_native_tls13, expect_server_resume, false, expected_curve)
    _pc_trace(
        "tls.roundtrip.exit",
        "version=$(expected_version) native13=$(expect_native_tls13) " *
        "client_resume=$(expect_client_resume) curve=$(expected_curve)",
    )
    return nothing
end

"""
    _pc_run_tls_workload!()

Canonical public-API TLS workload shared by package precompile and trim-safe
verification.

The scenarios are intentionally high level:
- mixed TLS 1.2/1.3 negotiation
- exact TLS 1.2 negotiation
- native X25519 routing for TLS 1.2
- mutual TLS and resumption when the richer fixture set is available
- TLS 1.2 ECDSA certificate handling when that fixture is available

Keeping this workload source-owned means trim/precompile coverage evolves with
the actual supported public API rather than drifting into a test-only harness.
"""
function _pc_run_tls_workload!()
    _pc_trace("tls.enter")
    _pc_runtime_supported() || return nothing
    paths = _pc_tls12_paths()
    paths === nothing && return nothing
    # Start with the "normal" modern config that allows both TLS 1.2 and TLS
    # 1.3, then force exact-version and alternate-curve paths underneath it.
    mixed_server_config = _pc_tls_server_config(
        paths.cert,
        paths.key;
        min_version = TL.TLS1_2_VERSION,
        max_version = nothing,
    )
    mixed_client_config = _pc_tls_client_config(
        verify_peer = true,
        server_name = "localhost",
        ca_file = paths.cert,
        min_version = TL.TLS1_2_VERSION,
        max_version = nothing,
    )
    _pc_run_tls_roundtrip!(mixed_server_config, mixed_client_config, "TLSv1.3", true)
    _pc_run_tls_roundtrip!(
        _pc_tls_server_config(
            paths.cert,
            paths.key;
            min_version = TL.TLS1_2_VERSION,
            max_version = TL.TLS1_2_VERSION,
        ),
        mixed_client_config,
        "TLSv1.2",
        false,
    )
    _pc_run_tls_roundtrip!(
        mixed_server_config,
        _pc_tls_client_config(
            verify_peer = true,
            server_name = "localhost",
            ca_file = paths.cert,
            min_version = TL.TLS1_2_VERSION,
            max_version = TL.TLS1_2_VERSION,
        ),
        "TLSv1.2",
        false,
    )
    _pc_run_tls_roundtrip!(
        _pc_tls_server_config(
            paths.cert,
            paths.key;
            curve_preferences = UInt16[TL.X25519],
            min_version = TL.TLS1_2_VERSION,
            max_version = TL.TLS1_2_VERSION,
        ),
        _pc_tls_client_config(
            verify_peer = true,
            server_name = "localhost",
            ca_file = paths.cert,
            curve_preferences = UInt16[TL.X25519],
            min_version = TL.TLS1_2_VERSION,
            max_version = TL.TLS1_2_VERSION,
        ),
        "TLSv1.2",
        false,
        nothing,
        nothing,
        nothing,
        "X25519",
    )
    _pc_run_tls_roundtrip!(
        _pc_tls_server_config(
            paths.cert,
            paths.key;
            curve_preferences = UInt16[TL.X25519],
            min_version = TL.TLS1_2_VERSION,
            max_version = TL.TLS1_2_VERSION,
        ),
        _pc_tls_client_config(
            verify_peer = true,
            server_name = "localhost",
            ca_file = paths.cert,
            curve_preferences = UInt16[TL.X25519],
            min_version = TL.TLS1_2_VERSION,
            max_version = nothing,
        ),
        "TLSv1.2",
        false,
        nothing,
        nothing,
        nothing,
        "X25519",
    )
    native_paths = _pc_tls13_native_paths()
    if native_paths !== nothing
        tls12_mtls_server = _pc_tls_server_config(
            native_paths.server_cert,
            native_paths.server_key;
            client_auth = TL.ClientAuthMode.RequireAndVerifyClientCert,
            client_ca_file = native_paths.ca,
            min_version = TL.TLS1_2_VERSION,
            max_version = TL.TLS1_2_VERSION,
        )
        tls12_mtls_client = _pc_tls_client_config(
            verify_peer = true,
            server_name = "localhost",
            ca_file = native_paths.ca,
            cert_file = native_paths.client_cert,
            key_file = native_paths.client_key,
            min_version = TL.TLS1_2_VERSION,
            max_version = TL.TLS1_2_VERSION,
        )
        _pc_run_tls_roundtrip!(
            tls12_mtls_server,
            tls12_mtls_client,
            "TLSv1.2",
            false,
            false,
            true,
            false,
        )
        _pc_run_tls_roundtrip!(
            tls12_mtls_server,
            tls12_mtls_client,
            "TLSv1.2",
            false,
            true,
            true,
            true,
        )
    end
    ecdsa_paths = _pc_tls12_ecdsa_paths()
    if ecdsa_paths !== nothing
        _pc_run_tls_roundtrip!(
            _pc_tls_server_config(
                ecdsa_paths.cert,
                ecdsa_paths.key;
                min_version = TL.TLS1_2_VERSION,
                max_version = TL.TLS1_2_VERSION,
            ),
            _pc_tls_client_config(
                verify_peer = true,
                verify_hostname = false,
                server_name = "localhost",
                ca_file = ecdsa_paths.cert,
                min_version = TL.TLS1_2_VERSION,
                max_version = TL.TLS1_2_VERSION,
            ),
            "TLSv1.2",
            false,
        )
    end
    _pc_trace("tls.exit")
    return nothing
end

function _pc_run_selected_workloads!()::Nothing
    if _pc_workload_enabled("eventloops")
        _pc_trace("selected.eventloops.before")
        _pc_run_eventloops_workload!()
        _pc_trace("selected.eventloops.after")
    end
    if _pc_workload_enabled("internal_poll")
        _pc_trace("selected.internal_poll.before")
        _pc_run_internal_poll_workload!()
        _pc_trace("selected.internal_poll.after")
    end
    if _pc_workload_enabled("socket_ops")
        _pc_trace("selected.socket_ops.before")
        _pc_run_socket_ops_workload!()
        _pc_trace("selected.socket_ops.after")
    end
    if _pc_workload_enabled("tcp")
        _pc_trace("selected.tcp.before")
        _pc_run_tcp_workload!()
        _pc_trace("selected.tcp.after")
    end
    if _pc_workload_enabled("host_resolvers")
        _pc_trace("selected.host_resolvers.before")
        _pc_run_host_resolvers_workload!()
        _pc_trace("selected.host_resolvers.after")
    end
    if _pc_workload_enabled("tls")
        _pc_trace("selected.tls.before")
        _pc_run_tls_workload!()
        _pc_trace("selected.tls.after")
    end
    return nothing
end

function _pc_run_precompile_workloads!()::Nothing
    _pc_trace(
        "workloads.enter",
        "version=$(VERSION) os=$(Sys.KERNEL) arch=$(Sys.ARCH) threads=$(Threads.nthreads()) only=$(get(ENV, "RESEAU_PRECOMPILE_ONLY", ""))",
    )
    IP.__init__()
    _pc_trace("workloads.iopoll_init.done")
    @assert isassigned(IP.POLLER)
    _pc_run_selected_workloads!()
    _pc_trace("workloads.exit")
    return nothing
end

@setup_workload begin
    @compile_workload begin
        _pc_run_precompile_workloads!()
    end
end
