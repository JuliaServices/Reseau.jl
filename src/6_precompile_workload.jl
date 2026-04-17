# Production precompile workload. Helpers exercise real Reseau code paths so
# precompile artifacts stay aligned with the transport/runtime stack we ship.
using PrecompileTools: @compile_workload, @setup_workload

const IP = IOPoll
const SO = SocketOps
const NC = TCP
const ND = HostResolvers
const TL = TLS

@inline function _pc_runtime_supported()::Bool
    return Sys.isapple() || Sys.islinux() || Sys.iswindows()
end

const _PC_EWOULDBLOCK = @static isdefined(Base.Libc, :EWOULDBLOCK) ? Int32(getfield(Base.Libc, :EWOULDBLOCK)) : Int32(Base.Libc.EAGAIN)

function _pc_stream_pair()::Tuple{Cint, Cint}
    listener = Cint(-1)
    client = Cint(-1)
    accepted = Cint(-1)
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
        client = Cint(-1)
        accepted = Cint(-1)
        return stream_client, stream_server
    finally
        accepted >= 0 && SO.close_socket_nothrow(accepted)
        client >= 0 && SO.close_socket_nothrow(client)
        listener >= 0 && SO.close_socket_nothrow(listener)
    end
end

function _pc_close_fd(fd::Cint)
    fd < 0 && return nothing
    SO.close_socket_nothrow(fd)
    return nothing
end

function _pc_write_byte(fd::Cint, b::UInt8)
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

function _pc_write_all!(fd::Cint, data::Vector{UInt8})::Nothing
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

function _pc_read_exact_fd!(fd::Cint, data::Vector{UInt8})::Nothing
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

function _pc_wait_connect_ready!(fd::Cint)
    registration = IP.register!(fd; mode = IP.PollMode.WRITE)
    try
        IP.arm_waiter!(registration, IP.PollMode.WRITE)
        IP.pollwait!(registration.write_waiter)
    finally
        IP.deregister!(fd)
    end
    return nothing
end

function _pc_accept_with_retry!(listener::Cint)::Cint
    for _ in 1:5000
        accepted, _, errno = SO.try_accept_socket(listener)
        accepted != -1 && return accepted
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
    IP.__init__()
    @assert isassigned(IP.POLLER)
    waiter = IP.PollWaiter()
    IP.pollnotify!(waiter)
    IP.pollwait!(waiter)
    _pc_runtime_supported() || return nothing
    state = IP.Poller()
    fd0 = Cint(-1)
    fd1 = Cint(-1)
    backend_open = false
    try
        errno = IP._backend_init!(state)
        errno == Int32(0) || throw(SystemError("event loop backend init", Int(errno)))
        backend_open = true
        fd0, fd1 = _pc_stream_pair()
        token = UInt64(1)
        registration = IP.Registration(fd0, token, IP.PollMode.READWRITE, IP.PollWaiter(), IP.PollWaiter(), false)
        state.registrations[fd0] = registration
        state.registrations_by_token[token] = registration
        errno = IP._backend_open_fd!(state, fd0, IP.PollMode.READWRITE, token)
        errno == Int32(0) || throw(SystemError("event loop open fd", Int(errno)))
        errno = IP._backend_arm_waiter!(state, registration, IP.PollMode.READ)
        errno == Int32(0) || throw(SystemError("event loop arm read waiter", Int(errno)))
        _pc_write_byte(fd1, 0x31)
        ready = false
        for _ in 1:20
            errno = IP._backend_poll_once!(state, Int64(50_000_000))
            errno == Int32(0) || throw(SystemError("event loop poll once", Int(errno)))
            if (@atomic :acquire registration.read_waiter.state) == IP.PollWaiterState.NOTIFIED
                IP.pollwait!(registration.read_waiter)
                ready = true
                break
            end
        end
        ready || throw(ArgumentError("event loop workload did not observe readability"))
        recv_buf = Vector{UInt8}(undef, 1)
        _pc_read_exact_fd!(fd0, recv_buf)
        errno = IP._backend_close_fd!(state, fd0)
        errno == Int32(0) || throw(SystemError("event loop close fd", Int(errno)))
    finally
        _pc_close_fd(fd0)
        _pc_close_fd(fd1)
        backend_open && IP._backend_close!(state)
        IP.shutdown!()
    end
    return nothing
end

function _pc_run_internal_poll_workload!()
    _pc_runtime_supported() || return nothing
    fd0, fd1 = _pc_stream_pair()
    ipfd = IP.FD(fd0)
    fd0 = Cint(-1)
    try
        IP._set_nonblocking!(ipfd.sysfd)
        IP.register!(ipfd)
        IP.set_read_deadline!(ipfd, time_ns() + 8_000_000)
        try
            IP.read!(ipfd, Vector{UInt8}(undef, 1))
        catch err
            err isa IP.DeadlineExceededError || rethrow(err)
        end
        IP.set_read_deadline!(ipfd, Int64(0))
        _pc_write_byte(fd1, 0x66)
        n = IP.read!(ipfd, Vector{UInt8}(undef, 1))
        n == 1 || error("internal poll workload expected one-byte read")
    finally
        ipfd.sysfd >= 0 && close(ipfd)
        _pc_close_fd(fd1)
        IP.shutdown!()
    end
    return nothing
end

function _pc_run_socket_ops_workload!()
    _pc_runtime_supported() || return nothing
    listener = Cint(-1)
    client = Cint(-1)
    accepted = Cint(-1)
    try
        listener = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        SO.set_sockopt_int(listener, SO.SOL_SOCKET, SO.SO_REUSEADDR, 1)
        SO.bind_socket(listener, SO.sockaddr_in_loopback(0))
        SO.listen_socket(listener, 16)
        bound = SO.get_socket_name_in(listener)
        port = Int(SO.sockaddr_in_port(bound))
        client = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        errno = SO.connect_socket(client, SO.sockaddr_in_loopback(port))
        if errno != Int32(0) && errno != Int32(Base.Libc.EISCONN)
            if errno != Int32(Base.Libc.EINPROGRESS) && errno != Int32(Base.Libc.EALREADY) && errno != Int32(Base.Libc.EINTR)
                throw(SystemError("connect", Int(errno)))
            end
            _pc_wait_connect_ready!(client)
            so_error = SO.get_socket_error(client)
            so_error == Int32(0) || throw(SystemError("connect(SO_ERROR)", Int(so_error)))
        end
        accepted = _pc_accept_with_retry!(listener)
        payload = UInt8[0x31, 0x32]
        recv_buf = Vector{UInt8}(undef, 2)
        _pc_write_all!(client, payload)
        _pc_read_exact_fd!(accepted, recv_buf)
    finally
        accepted >= 0 && SO.close_socket_nothrow(accepted)
        client >= 0 && SO.close_socket_nothrow(client)
        listener >= 0 && SO.close_socket_nothrow(listener)
        IP.shutdown!()
    end
    return nothing
end

function _pc_run_tcp_workload!()
    _pc_runtime_supported() || return nothing
    listener = nothing
    client = nothing
    server = nothing
    try
        listener = NC.listen(NC.loopback_addr(0); backlog = 16)
        laddr = NC.addr(listener)
        client = NC.connect(NC.loopback_addr(Int((laddr::NC.SocketAddrV4).port)))
        server = NC.accept(listener)
        payload = UInt8[0x41, 0x42, 0x43]
        written = write(client, payload)
        written == length(payload) || throw(ArgumentError("tcp workload expected 3-byte write"))
        recv_buf = Vector{UInt8}(undef, length(payload))
        _pc_read_exact!(server, recv_buf) == length(payload) || throw(EOFError())
    finally
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
        IP.shutdown!()
    end
    return nothing
end

function _pc_run_host_resolvers_workload!()
    _pc_runtime_supported() || return nothing
    listener = nothing
    client = nothing
    server = nothing
    try
        listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 16)
        laddr = NC.addr(listener)
        client = ND.connect("tcp", ND.join_host_port("127.0.0.1", Int((laddr::NC.SocketAddrV4).port)))
        server = NC.accept(listener)
        payload = UInt8[0x51, 0x52]
        written = write(client, payload)
        written == length(payload) || throw(ArgumentError("host resolver workload expected 2-byte write"))
        recv_buf = Vector{UInt8}(undef, length(payload))
        _pc_read_exact!(server, recv_buf) == length(payload) || throw(EOFError())
    finally
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
        IP.shutdown!()
    end
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

function _pc_tls_server_config(
    cert_path::String,
    key_path::String;
    client_auth::TL.ClientAuthMode.T = TL.ClientAuthMode.NoClientCert,
    client_ca_file::Union{Nothing, String} = nothing,
    session_tickets_disabled::Bool = false,
    curve_preferences::Vector{UInt16} = UInt16[],
    min_version::UInt16 = TL.TLS1_3_VERSION,
    max_version::UInt16 = TL.TLS1_3_VERSION,
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

function _pc_tls_client_config(;
    verify_peer::Bool = false,
    server_name::Union{Nothing, String} = "localhost",
    ca_file::Union{Nothing, String} = nothing,
    cert_file::Union{Nothing, String} = nothing,
    key_file::Union{Nothing, String} = nothing,
    session_tickets_disabled::Bool = false,
    min_version::UInt16 = TL.TLS1_3_VERSION,
    max_version::UInt16 = TL.TLS1_3_VERSION,
)::TL.Config
    return TL.Config(
        verify_peer = verify_peer,
        server_name = server_name,
        ca_file = ca_file,
        cert_file = cert_file,
        key_file = key_file,
        handshake_timeout_ns = 1_000_000_000,
        min_version = min_version,
        max_version = max_version,
        session_tickets_disabled = session_tickets_disabled,
    )
end

function _pc_tls13_native_paths()::Union{
    Nothing,
    NamedTuple{
        (:ca, :server_cert, :server_key, :client_cert, :client_key),
        Tuple{String, String, String, String, String},
    },
}
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
    return (
        ca = ca_path::String,
        server_cert = server_cert_path::String,
        server_key = server_key_path::String,
        client_cert = client_cert_path::String,
        client_key = client_key_path::String,
    )
end

function _pc_tls12_paths()::Union{
    Nothing,
    NamedTuple{(:cert, :key), Tuple{String, String}},
}
    cert_path = _pc_tls_resource_file("unittests.crt")
    key_path = _pc_tls_resource_file("unittests.key")
    if cert_path === nothing || key_path === nothing
        return nothing
    end
    return (cert = cert_path::String, key = key_path::String)
end

function _pc_run_tls_workload!()
    _pc_runtime_supported() || return nothing
    paths = _pc_tls12_paths()
    paths === nothing && return nothing
    listener = nothing
    client = nothing
    server_task = nothing
    try
        listener = TL.listen(NC.loopback_addr(0), _pc_tls_server_config(
            paths.cert,
            paths.key;
            min_version = TL.TLS1_2_VERSION,
            max_version = TL.TLS1_2_VERSION,
        ); backlog = 8)
        laddr = TL.addr(listener)::NC.SocketAddrV4
        server_task = @async begin
            conn = TL.accept(listener::TL.Listener)
            try
                TL.handshake!(conn)
                state = TL.connection_state(conn)
                write(conn, UInt8[0x41]) == 1 || throw(ArgumentError("TLS precompile workload expected 1-byte server write"))
                read(conn, 1) == UInt8[0x51] || throw(ArgumentError("TLS precompile workload expected 1-byte client ack"))
                return state
            finally
                _pc_close_nothrow(conn)
            end
        end
        client_config = _pc_tls_client_config(
            verify_peer = true,
            server_name = "localhost",
            ca_file = paths.cert,
            min_version = TL.TLS1_2_VERSION,
            max_version = TL.TLS1_2_VERSION,
        )
        client = TL.connect(NC.loopback_addr(Int(laddr.port)), client_config)
        read(client, 1) == UInt8[0x41] || throw(ArgumentError("TLS precompile workload expected server byte"))
        write(client, UInt8[0x51]) == 1 || throw(ArgumentError("TLS precompile workload expected client ack write"))
        eof(client) || throw(ArgumentError("TLS precompile workload expected connection EOF"))
        client_state = TL.connection_state(client)
        client_state.handshake_complete || throw(ArgumentError("TLS precompile workload expected a completed handshake"))
        client_state.version == "TLSv1.2" || throw(ArgumentError("TLS precompile workload expected TLS 1.2"))
        !client_state.using_native_tls13 || throw(ArgumentError("TLS precompile workload did not expect native TLS 1.3 mode"))
        client_state.cipher_suite in (
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        ) || throw(ArgumentError("TLS precompile workload expected a native TLS 1.2 ECDHE-RSA cipher suite"))
        client_state.curve == "P-256" || throw(ArgumentError("TLS precompile workload expected P-256 ECDHE"))
        _pc_wait_task_done(server_task::Task, 2.0)
        server_state = fetch(server_task::Task)::TL.ConnectionState
        server_state.handshake_complete || throw(ArgumentError("TLS precompile workload expected server handshake completion"))
        server_state.version == "TLSv1.2" || throw(ArgumentError("TLS precompile workload expected TLS 1.2 server state"))
        !server_state.using_native_tls13 || throw(ArgumentError("TLS precompile workload did not expect native TLS 1.3 server mode"))
        server_state.cipher_suite in (
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        ) || throw(ArgumentError("TLS precompile workload expected a native TLS 1.2 server cipher suite"))
        server_state.curve == "P-256" || throw(ArgumentError("TLS precompile workload expected a native TLS 1.2 server curve"))
    finally
        _pc_close_nothrow(client)
        _pc_close_nothrow(listener)
        IP.shutdown!()
    end
    return nothing
end

function _pc_run_selected_workloads!()::Nothing
    _pc_workload_enabled("eventloops") && _pc_run_eventloops_workload!()
    _pc_workload_enabled("internal_poll") && _pc_run_internal_poll_workload!()
    _pc_workload_enabled("socket_ops") && _pc_run_socket_ops_workload!()
    _pc_workload_enabled("tcp") && _pc_run_tcp_workload!()
    _pc_workload_enabled("host_resolvers") && _pc_run_host_resolvers_workload!()
    _pc_workload_enabled("tls") && _pc_run_tls_workload!()
    return nothing
end

function _pc_run_precompile_workloads!()::Nothing
    IP.__init__()
    @assert isassigned(IP.POLLER)
    _pc_run_selected_workloads!()
    return nothing
end

@setup_workload begin
    @compile_workload begin
        _pc_run_precompile_workloads!()
    end
end
