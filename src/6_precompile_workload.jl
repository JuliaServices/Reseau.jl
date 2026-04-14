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

function _pc_tls_server_config(cert_path::String, key_path::String)::TL.Config
    return TL.Config(
        verify_peer = false,
        cert_file = cert_path,
        key_file = key_path,
        handshake_timeout_ns = 1_000_000_000,
    )
end

function _pc_tls_client_config()::TL.Config
    return TL.Config(
        verify_peer = false,
        server_name = "localhost",
        handshake_timeout_ns = 1_000_000_000,
    )
end

function _pc_tls_accept_task(listener::TL.Listener)::Task
    return @async begin
        conn = TL.accept(listener)
        TL.handshake!(conn)
        return conn
    end
end

function _pc_tls_connect_client(addr::NC.SocketAddrV4, config::TL.Config)::TL.Conn
    return TL.connect(
        addr;
        server_name = config.server_name,
        verify_peer = config.verify_peer,
        client_auth = config.client_auth,
        cert_file = config.cert_file,
        key_file = config.key_file,
        ca_file = config.ca_file,
        client_ca_file = config.client_ca_file,
        alpn_protocols = copy(config.alpn_protocols),
        handshake_timeout_ns = config.handshake_timeout_ns,
        min_version = config.min_version,
        max_version = config.max_version,
    )
end

function _pc_tls13_client_hello()::TL._ClientHelloMsg
    client_hello = TL._ClientHelloMsg()
    client_hello.vers = TL.TLS1_2_VERSION
    client_hello.random = collect(UInt8(0x00):UInt8(0x1f))
    client_hello.session_id = UInt8[0xaa, 0xbb, 0xcc, 0xdd]
    client_hello.cipher_suites = UInt16[TL._TLS13_AES_128_GCM_SHA256_ID]
    client_hello.compression_methods = UInt8[TL._TLS_COMPRESSION_NONE]
    client_hello.server_name = "localhost"
    client_hello.alpn_protocols = ["h2"]
    client_hello.supported_versions = UInt16[TL.TLS1_3_VERSION]
    client_hello.key_shares = [TL._TLSKeyShare(0x001d, UInt8[0x01, 0x02, 0x03, 0x04])]
    client_hello.psk_modes = UInt8[TL._TLS_PSK_MODE_DHE]
    client_hello.psk_identities = [TL._TLSPSKIdentity(UInt8[0x50, 0x51, 0x52], 0x01020304)]
    client_hello.psk_binders = [zeros(UInt8, 32)]
    return client_hello
end

function _pc_tls13_server_hello(session_id::Vector{UInt8})::TL._ServerHelloMsg
    server_hello = TL._ServerHelloMsg()
    server_hello.vers = TL.TLS1_2_VERSION
    server_hello.random = collect(UInt8(0x80):UInt8(0x9f))
    server_hello.session_id = copy(session_id)
    server_hello.cipher_suite = TL._TLS13_AES_128_GCM_SHA256_ID
    server_hello.compression_method = TL._TLS_COMPRESSION_NONE
    server_hello.supported_version = TL.TLS1_3_VERSION
    server_hello.server_share = TL._TLSKeyShare(0x001d, UInt8[0x05, 0x06, 0x07, 0x08])
    server_hello.selected_identity_present = true
    server_hello.selected_identity = UInt16(0)
    return server_hello
end

function _pc_run_tls13_client_handshake_workload!()::Nothing
    certificate_request = TL._CertificateRequestMsgTLS13()
    certificate_request.ocsp_stapling = true
    certificate_request.scts = true
    certificate_request.supported_signature_algorithms = UInt16[0x0403, 0x0804]
    certificate_request.supported_signature_algorithms_cert = UInt16[0x0403]
    certificate_request.certificate_authorities = [UInt8[0x01, 0x02, 0x03], UInt8[0x04, 0x05]]
    TL._unmarshal_handshake_message(TL._marshal_handshake_message(certificate_request)) == certificate_request ||
        throw(ArgumentError("TLS 1.3 workload certificate request roundtrip mismatch"))

    certificate = TL._CertificateMsgTLS13()
    certificate.certificates = [UInt8[0x10, 0x11, 0x12], UInt8[0x20, 0x21]]
    certificate.ocsp_stapling = true
    certificate.ocsp_staple = UInt8[0x30, 0x31, 0x32]
    certificate.scts = true
    certificate.signed_certificate_timestamps = [UInt8[0x40, 0x41], UInt8[0x50, 0x51, 0x52]]
    TL._unmarshal_handshake_message(TL._marshal_handshake_message(certificate)) == certificate ||
        throw(ArgumentError("TLS 1.3 workload certificate roundtrip mismatch"))

    certificate_verify = TL._CertificateVerifyMsg()
    certificate_verify.signature_algorithm = 0x0804
    certificate_verify.signature = UInt8[0x60, 0x61, 0x62, 0x63]
    TL._unmarshal_handshake_message(TL._marshal_handshake_message(certificate_verify)) == certificate_verify ||
        throw(ArgumentError("TLS 1.3 workload certificate verify roundtrip mismatch"))

    shared_secret = UInt8[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
    psk = UInt8[0x41, 0x42, 0x43, 0x44, 0x45, 0x46]

    expected_client_hello = _pc_tls13_client_hello()
    early_secret = TL._tls13_early_secret(TL._HASH_SHA256, psk)
    binder_key = TL._tls13_resumption_binder_key(early_secret)
    binder_transcript = TL._TranscriptHash(TL._HASH_SHA256; buffer_handshake = false)
    TL._transcript_update!(binder_transcript, TL._marshal_client_hello_without_binders(expected_client_hello))
    binder = TL._tls13_finished_verify_data(TL._HASH_SHA256, binder_key, binder_transcript)
    TL._update_client_hello_binders!(expected_client_hello, [binder])
    client_bytes = TL._marshal_handshake_message(expected_client_hello)

    server_hello = _pc_tls13_server_hello(expected_client_hello.session_id)
    server_hello_bytes = TL._marshal_handshake_message(server_hello)
    transcript = TL._TranscriptHash(TL._HASH_SHA256)
    TL._transcript_update!(transcript, client_bytes)
    TL._transcript_update!(transcript, server_hello_bytes)

    handshake_secret = TL._tls13_handshake_secret(early_secret, shared_secret)
    client_handshake_traffic_secret = TL._tls13_client_handshake_traffic_secret(handshake_secret, transcript)
    server_handshake_traffic_secret = TL._tls13_server_handshake_traffic_secret(handshake_secret, transcript)

    encrypted_extensions = TL._EncryptedExtensionsMsg()
    encrypted_extensions.alpn_protocol = "h2"
    encrypted_extensions_bytes = TL._marshal_handshake_message(encrypted_extensions)
    TL._transcript_update!(transcript, encrypted_extensions_bytes)

    server_finished = TL._FinishedMsg(TL._tls13_finished_verify_data(TL._TLS13_AES_128_GCM_SHA256, server_handshake_traffic_secret, transcript))
    server_finished_bytes = TL._marshal_handshake_message(server_finished)
    TL._transcript_update!(transcript, server_finished_bytes)

    client_finished_bytes = TL._marshal_handshake_message(TL._FinishedMsg(TL._tls13_finished_verify_data(TL._TLS13_AES_128_GCM_SHA256, client_handshake_traffic_secret, transcript)))
    master_secret = TL._tls13_master_secret(handshake_secret)
    client_application_traffic_secret = TL._tls13_client_application_traffic_secret(master_secret, transcript)
    server_application_traffic_secret = TL._tls13_server_application_traffic_secret(master_secret, transcript)
    exporter_master_secret = TL._tls13_exporter_master_secret(master_secret, transcript).secret

    new_session_ticket = TL._NewSessionTicketMsgTLS13()
    new_session_ticket.lifetime = 0x01020304
    new_session_ticket.age_add = 0x05060708
    new_session_ticket.nonce = UInt8[0x90, 0x91]
    new_session_ticket.label = UInt8[0xa0, 0xa1, 0xa2]
    new_session_ticket.max_early_data = 0x0b0c0d0e
    new_session_ticket_bytes = TL._marshal_handshake_message(new_session_ticket)

    state = TL._TLS13ClientHandshakeState(_pc_tls13_client_hello(), TL._TLS13_AES_128_GCM_SHA256_ID, shared_secret, psk)
    io = TL._HandshakeMessageFlightIO([server_hello_bytes, encrypted_extensions_bytes, server_finished_bytes, new_session_ticket_bytes])
    TL._client_handshake_tls13!(state, io)

    state.complete || throw(ArgumentError("TLS 1.3 workload expected complete handshake"))
    state.using_psk || throw(ArgumentError("TLS 1.3 workload expected PSK handshake"))
    state.client_protocol == "h2" || throw(ArgumentError("TLS 1.3 workload expected ALPN selection"))
    io.outbound == [client_bytes, client_finished_bytes] || throw(ArgumentError("TLS 1.3 workload outbound flight mismatch"))
    state.client_handshake_traffic_secret == client_handshake_traffic_secret || throw(ArgumentError("TLS 1.3 workload client handshake secret mismatch"))
    state.server_handshake_traffic_secret == server_handshake_traffic_secret || throw(ArgumentError("TLS 1.3 workload server handshake secret mismatch"))
    state.client_application_traffic_secret == client_application_traffic_secret || throw(ArgumentError("TLS 1.3 workload client application secret mismatch"))
    state.server_application_traffic_secret == server_application_traffic_secret || throw(ArgumentError("TLS 1.3 workload server application secret mismatch"))
    state.exporter_master_secret == exporter_master_secret || throw(ArgumentError("TLS 1.3 workload exporter secret mismatch"))
    state.peer_new_session_tickets == [new_session_ticket] || throw(ArgumentError("TLS 1.3 workload session ticket mismatch"))
    return nothing
end

function _pc_run_tls_workload!()
    _pc_run_tls13_client_handshake_workload!()
    _pc_runtime_supported() || return nothing
    cert_path = _pc_tls_resource_file("unittests.crt")
    key_path = _pc_tls_resource_file("unittests.key")
    (cert_path === nothing || key_path === nothing) && return nothing
    listener = nothing
    client = nothing
    server = nothing
    try
        listener = TL.listen(
            NC.loopback_addr(0),
            _pc_tls_server_config(cert_path::String, key_path::String);
            backlog = 8,
        )
        laddr = TL.addr(listener)::NC.SocketAddrV4
        accept_task = _pc_tls_accept_task(listener::TL.Listener)
        client = _pc_tls_connect_client(NC.loopback_addr(Int(laddr.port)), _pc_tls_client_config())
        _pc_wait_task_done(accept_task, 2.0)
        server = fetch(accept_task)
        payload = UInt8[0x54, 0x4c, 0x53]
        recv_buf = Vector{UInt8}(undef, 3)
        written = write(client, payload)
        written == 3 || throw(ArgumentError("TLS precompile workload expected 3-byte write"))
        read!(server, recv_buf)
    finally
        _pc_close_nothrow(server)
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
