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
    client_hello.random = collect(UInt8(0x20):UInt8(0x3f))
    client_hello.session_id = UInt8[0xba, 0xdb, 0xee, 0xf0]
    client_hello.cipher_suites = UInt16[TL._TLS13_AES_128_GCM_SHA256_ID]
    client_hello.compression_methods = UInt8[TL._TLS_COMPRESSION_NONE]
    client_hello.server_name = "localhost"
    client_hello.alpn_protocols = ["h2"]
    client_hello.supported_versions = UInt16[TL.TLS1_3_VERSION]
    client_hello.supported_curves = UInt16[0x001d, 0x0017]
    client_hello.supported_signature_algorithms = UInt16[0x0804]
    client_hello.supported_signature_algorithms_cert = UInt16[0x0804]
    return client_hello
end

function _pc_tls13_server_hello(session_id::Vector{UInt8}, group::UInt16, server_share::Vector{UInt8})::TL._ServerHelloMsg
    msg = TL._ServerHelloMsg()
    msg.vers = TL.TLS1_2_VERSION
    msg.random = collect(UInt8(0x60):UInt8(0x7f))
    msg.session_id = copy(session_id)
    msg.cipher_suite = TL._TLS13_AES_128_GCM_SHA256_ID
    msg.compression_method = TL._TLS_COMPRESSION_NONE
    msg.supported_version = TL.TLS1_3_VERSION
    msg.server_share = TL._TLSKeyShare(group, copy(server_share))
    return msg
end

function _pc_tls13_hello_retry_request(session_id::Vector{UInt8}, selected_group::UInt16)::TL._ServerHelloMsg
    msg = TL._ServerHelloMsg()
    msg.vers = TL.TLS1_2_VERSION
    msg.random = copy(TL._HELLO_RETRY_REQUEST_RANDOM)
    msg.session_id = copy(session_id)
    msg.cipher_suite = TL._TLS13_AES_128_GCM_SHA256_ID
    msg.compression_method = TL._TLS_COMPRESSION_NONE
    msg.supported_version = TL.TLS1_3_VERSION
    msg.cookie = UInt8[0xa1, 0xa2, 0xa3]
    msg.selected_group = selected_group
    return msg
end

function _pc_tls13_server_certificate_request()::TL._CertificateRequestMsgTLS13
    msg = TL._CertificateRequestMsgTLS13()
    msg.supported_signature_algorithms = UInt16[0x0804]
    msg.supported_signature_algorithms_cert = UInt16[0x0804]
    return msg
end

function _pc_tls13_server_certificate()::TL._CertificateMsgTLS13
    msg = TL._CertificateMsgTLS13()
    msg.certificates = [UInt8[0x30, 0x82, 0x01, 0x01], UInt8[0x30, 0x82, 0x02, 0x02]]
    return msg
end

function _pc_tls13_key_share_provider()::TL._TLS13ScriptedKeyShareProvider
    return TL._TLS13ScriptedKeyShareProvider(
        TL._TLSKeyShare(0x001d, UInt8[0x11, 0x12, 0x13, 0x14]),
        UInt8[0x21, 0x22, 0x23, 0x24],
        UInt8[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38],
        TL._TLSKeyShare(0x0017, UInt8[0x41, 0x42, 0x43, 0x44]),
        UInt8[0x51, 0x52, 0x53, 0x54],
        UInt8[0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68],
    )
end

function _pc_run_tls13_client_handshake_workload!()::Nothing
    client_hello = _pc_tls13_client_hello()
    key_share_provider = _pc_tls13_key_share_provider()
    TL._tls13_prepare_initial_client_hello!(key_share_provider, client_hello)

    initial_client_hello_bytes = TL._marshal_handshake_message(client_hello)
    hrr = _pc_tls13_hello_retry_request(client_hello.session_id, key_share_provider.retry_share.group)
    hrr_bytes = TL._marshal_handshake_message(hrr)

    TL._tls13_process_hello_retry_request!(key_share_provider, client_hello, hrr)
    retry_client_hello_bytes = TL._marshal_handshake_message(client_hello)

    transcript = TL._TranscriptHash(TL._HASH_SHA256)
    TL._transcript_update!(transcript, TL._tls13_message_hash_frame(TL._hash_data(TL._HASH_SHA256, initial_client_hello_bytes)))
    TL._transcript_update!(transcript, hrr_bytes)
    TL._transcript_update!(transcript, retry_client_hello_bytes)

    server_hello = _pc_tls13_server_hello(client_hello.session_id, key_share_provider.retry_share.group, copy(key_share_provider.retry_expected_server_share))
    server_hello_bytes = TL._marshal_handshake_message(server_hello)
    TL._transcript_update!(transcript, server_hello_bytes)

    early_secret = TL._tls13_early_secret(TL._HASH_SHA256, UInt8[])
    handshake_secret = TL._tls13_handshake_secret(early_secret, key_share_provider.retry_shared_secret)
    client_handshake_traffic_secret = TL._tls13_client_handshake_traffic_secret(handshake_secret, transcript)
    server_handshake_traffic_secret = TL._tls13_server_handshake_traffic_secret(handshake_secret, transcript)

    encrypted_extensions = TL._EncryptedExtensionsMsg()
    encrypted_extensions.alpn_protocol = "h2"
    encrypted_extensions_bytes = TL._marshal_handshake_message(encrypted_extensions)
    TL._transcript_update!(transcript, encrypted_extensions_bytes)

    certificate_request = _pc_tls13_server_certificate_request()
    certificate_request_bytes = TL._marshal_handshake_message(certificate_request)
    TL._transcript_update!(transcript, certificate_request_bytes)

    certificate = _pc_tls13_server_certificate()
    certificate_bytes = TL._marshal_handshake_message(certificate)
    TL._transcript_update!(transcript, certificate_bytes)

    signed_message = TL._tls13_signed_message(TL._TLS13_SERVER_SIGNATURE_CONTEXT, transcript)
    certificate_verify = TL._CertificateVerifyMsg(0x0804, UInt8[0xb1, 0xb2, 0xb3, 0xb4, 0xb5])
    certificate_verify_bytes = TL._marshal_handshake_message(certificate_verify)
    TL._transcript_update!(transcript, certificate_verify_bytes)

    server_finished = TL._FinishedMsg(TL._tls13_finished_verify_data(TL._TLS13_AES_128_GCM_SHA256, server_handshake_traffic_secret, transcript))
    server_finished_bytes = TL._marshal_handshake_message(server_finished)
    TL._transcript_update!(transcript, server_finished_bytes)

    transcript_for_client = TL._TranscriptHash(TL._HASH_SHA256)
    transcript_bytes = TL._transcript_buffered_bytes(transcript)::Vector{UInt8}
    TL._transcript_update!(transcript_for_client, transcript_bytes)

    client_certificate = TL._CertificateMsgTLS13()
    client_certificate_bytes = TL._marshal_certificate_tls13(client_certificate)
    TL._transcript_update!(transcript_for_client, client_certificate_bytes)

    client_finished = TL._FinishedMsg(TL._tls13_finished_verify_data(TL._TLS13_AES_128_GCM_SHA256, client_handshake_traffic_secret, transcript_for_client))
    client_finished_bytes = TL._marshal_handshake_message(client_finished)

    master_secret = TL._tls13_master_secret(handshake_secret)
    client_application_traffic_secret = TL._tls13_client_application_traffic_secret(master_secret, transcript)
    server_application_traffic_secret = TL._tls13_server_application_traffic_secret(master_secret, transcript)
    exporter_master_secret = TL._tls13_exporter_secret_for_test(TL._tls13_exporter_master_secret(master_secret, transcript))

    new_session_ticket = TL._NewSessionTicketMsgTLS13()
    new_session_ticket.lifetime = 0x01020304
    new_session_ticket.age_add = 0x05060708
    new_session_ticket.nonce = UInt8[0x90, 0x91]
    new_session_ticket.label = UInt8[0xa0, 0xa1, 0xa2]
    new_session_ticket.max_early_data = 0x0b0c0d0e
    new_session_ticket_bytes = TL._marshal_handshake_message(new_session_ticket)

    verifier = TL._TLS13ScriptedCertificateVerifier(
        certificate.certificates,
        client_hello.server_name,
        certificate_verify.signature_algorithm,
        signed_message,
        certificate_verify.signature,
    )

    inbound = [
        hrr_bytes,
        server_hello_bytes,
        encrypted_extensions_bytes,
        certificate_request_bytes,
        certificate_bytes,
        certificate_verify_bytes,
        server_finished_bytes,
        new_session_ticket_bytes,
    ]
    outbound = [
        initial_client_hello_bytes,
        retry_client_hello_bytes,
        client_certificate_bytes,
        client_finished_bytes,
    ]

    state_client_hello = _pc_tls13_client_hello()
    state_key_share_provider = _pc_tls13_key_share_provider()
    TL._tls13_prepare_initial_client_hello!(state_key_share_provider, state_client_hello)
    state_transcript = TL._TranscriptHash(TL._HASH_SHA256)
    state = TL._new_tls13_client_handshake_state(
        Val{TL._HASH_SHA256}(),
        state_client_hello,
        TL._TLS13_AES_128_GCM_SHA256_ID,
        TL._TLS13_AES_128_GCM_SHA256,
        state_key_share_provider,
        verifier,
        state_transcript,
    )::TL._TLS13ClientHandshakeState{TL._HASH_SHA256}
    io = TL._HandshakeMessageFlightIO(inbound)
    try
        TL._client_handshake_tls13!(state, io)
        state.complete || throw(ArgumentError("TLS 1.3 workload expected complete handshake"))
        !state.using_psk || throw(ArgumentError("TLS 1.3 workload expected certificate handshake"))
        state.client_protocol == "h2" || throw(ArgumentError("TLS 1.3 workload expected ALPN selection"))
        state.have_certificate_request || throw(ArgumentError("TLS 1.3 workload expected CertificateRequest"))
        state.have_server_certificate || throw(ArgumentError("TLS 1.3 workload expected Certificate"))
        state.have_server_certificate_verify || throw(ArgumentError("TLS 1.3 workload expected CertificateVerify"))
        io.outbound == outbound || throw(ArgumentError("TLS 1.3 workload outbound flight mismatch"))
        state.client_handshake_traffic_secret == client_handshake_traffic_secret || throw(ArgumentError("TLS 1.3 workload client handshake secret mismatch"))
        state.server_handshake_traffic_secret == server_handshake_traffic_secret || throw(ArgumentError("TLS 1.3 workload server handshake secret mismatch"))
        state.client_application_traffic_secret == client_application_traffic_secret || throw(ArgumentError("TLS 1.3 workload client application secret mismatch"))
        state.server_application_traffic_secret == server_application_traffic_secret || throw(ArgumentError("TLS 1.3 workload server application secret mismatch"))
        state.exporter_master_secret == exporter_master_secret || throw(ArgumentError("TLS 1.3 workload exporter secret mismatch"))
        state.peer_new_session_tickets == [new_session_ticket] || throw(ArgumentError("TLS 1.3 workload session ticket mismatch"))
    finally
        TL._destroy_tls13_secret!(master_secret)
        TL._destroy_tls13_secret!(handshake_secret)
        TL._destroy_tls13_secret!(early_secret)
        TL._securezero_tls13_client_handshake_state!(state)
    end
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
