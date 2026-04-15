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
    client_hello.supported_curves = UInt16[TL._TLS_GROUP_X25519]
    client_hello.supported_signature_algorithms = UInt16[TL._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256]
    client_hello.supported_signature_algorithms_cert = UInt16[TL._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256]
    return client_hello
end

const _PC_TLS13_CLIENT_X25519_PRIVATE_KEY = UInt8[
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee,
    0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66,
]

const _PC_TLS13_SERVER_X25519_PRIVATE_KEY = UInt8[
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
    0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
    0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
    0x19, 0x0a, 0xfb, 0xec, 0xdd, 0xce, 0xbf, 0xa0,
]

# These bytes mirror the leaf certificate used in `test/resources/unittests.crt`
# so the compile workload and detached TLS 1.3 tests exercise the same cert path.
const _PC_TLS13_CERTIFICATE_DER_HEX =
    "308203ec308202d4a003020102020900898abbbb3fe42f29300d06092a864886f70d01010b050030819a310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310d300b060355040b0c0453444b733112301006035504030c096c6f63616c686f73743130302e06092a864886f70d01090116216177732d73646b2d636f6d6d6f6e2d72756e74696d6540616d617a6f6e2e636f6d301e170d3234303530343137303730345a170d3236303830363137303730345a30819a310b30090603550406130255533113301106035504080c0a57617368696e67746f6e3110300e06035504070c0753656174746c65310f300d060355040a0c06416d617a6f6e310d300b060355040b0c0453444b733112301006035504030c096c6f63616c686f73743130302e06092a864886f70d01090116216177732d73646b2d636f6d6d6f6e2d72756e74696d6540616d617a6f6e2e636f6d30820122300d06092a864886f70d01010105000382010f003082010a0282010100d76a5748f80e44032542d6116f1bb3fce71aa2b6a7dc2d858f28e1bb4bee7121194b0c43269ef94c140431a7d2a5210a0102de0edef1b83443627e76578504e9c17ec535a1b73b1fee684dfe51da0cf72f4760123c0124ce48a5f0a08b6387bab53c52c10f7bb2994db84674f7d1e82584d32c56917887ddd43df3675118712c3cc3e199d92c4451f61448bd821662184a44239e5b09088a42a0680388100f6c85093b72960435f42601836f1dd67f78d71bf63a4fadcb3ec3be012db4442bdc105d05feb94320dcc8e440073b54ce11df5f28ebbe2402b4e8fc359bbec180eac4ec5b6f206ee460d56e3843de22738790ebaaaf20e2b01d4fc22c8f3486ea750203010001a333303130130603551d25040c300a06082b06010505070301301a0603551d110413301182096c6f63616c686f737487047f000001300d06092a864886f70d01010b0500038201010047bb5d3e15e92a4a700a13f7097ae5ad08a72cc848ba9fcb63889cfc5e39b7309e779203e7e2fce8ca56bc1cc8c8a9b8981d64da53e72dabc6235b6565fef8066d66e1d26100c9d8563ce3090849deaa061d108289c6985d847e69bfb3f0dc438f02f041eaf51a696200868b07ee566fecc0c3505a0a9370de343124a87de3b0ff017a79782251d00d5d0c29a0e8a033d20904c8885d71caced8c69153d3791839823e8532cc9321e617d2aa411f6c1c5dc7c1baec5671bebbdfe3b6791caba47fee91b934893a4a14a318358295b9a4ebd87ee02c4f71dcf3eea0b4c1490a7e4ccb31dcf1784ed92f96fee7dccd17769a8612c6b005c44d97486190dee4ce6b"

# This signature is bound to the exact fixed transcript assembled by the
# workload helpers above. If the pinned X25519 keys, ClientHello fields,
# ServerHello fields, ALPN, or certificate bytes change, regenerate it too.
const _PC_TLS13_CERTIFICATE_VERIFY_SIGNATURE_HEX =
    "4e7d1f44b0e7cfc6bcfda98587e26bf214355988f6aed8b5d4f70d453378f0e32cf4d0e23c0a1c1d6281c225132eda9b73deeb391ebb781e0b577fad501a8c03377e90d2aa255bfca1011ae8eebe9286f022fb57354a051c14153317aee1e65a6f669d66aff58c4254e323eab736d677e5bbe8e80d1e5a09c604e5ce996c9b5a033252b00004bf02f07c378b6c4bac4dbab9ded890283b3813840e2eac58328990b4796dd995c11caf01c67acf314d2fbab099de7476dd705f9a0ed3601abd66dd89109fee91c7bf1aa76602a87a1895aa57aa5d423153020d2a79b96de62331003a48861677543a888f50543dd5c65e73855ddac27afbe0b2ffa7eb71094aeb"

@inline _pc_tls13_certificate_der() = Base.hex2bytes(_PC_TLS13_CERTIFICATE_DER_HEX)
@inline _pc_tls13_certificate_verify_signature() = Base.hex2bytes(_PC_TLS13_CERTIFICATE_VERIFY_SIGNATURE_HEX)

function _pc_tls13_server_hello(session_id::Vector{UInt8}, server_share::Vector{UInt8})::TL._ServerHelloMsg
    msg = TL._ServerHelloMsg()
    msg.vers = TL.TLS1_2_VERSION
    msg.random = collect(UInt8(0x60):UInt8(0x7f))
    msg.session_id = copy(session_id)
    msg.cipher_suite = TL._TLS13_AES_128_GCM_SHA256_ID
    msg.compression_method = TL._TLS_COMPRESSION_NONE
    msg.supported_version = TL.TLS1_3_VERSION
    msg.server_share = TL._TLSKeyShare(TL._TLS_GROUP_X25519, copy(server_share))
    return msg
end

function _pc_tls13_server_certificate()::TL._CertificateMsgTLS13
    msg = TL._CertificateMsgTLS13()
    msg.certificates = [_pc_tls13_certificate_der()]
    return msg
end

function _pc_run_tls13_client_handshake_workload!()::Nothing
    client_hello = _pc_tls13_client_hello()
    key_share_provider = TL._TLS13OpenSSLKeyShareProvider(fixed_private_key = _PC_TLS13_CLIENT_X25519_PRIVATE_KEY)
    transcript = TL._TranscriptHash(TL._HASH_SHA256)
    early_secret = TL._TLS13EarlySecret(TL._HASH_SHA256, UInt8[])
    handshake_secret = TL._TLS13HandshakeSecret(TL._HASH_SHA256, UInt8[])
    master_secret = TL._TLS13MasterSecret(TL._HASH_SHA256, UInt8[])
    shared_secret = UInt8[]
    TL._tls13_prepare_initial_client_hello!(key_share_provider, client_hello)
    client_hello_bytes = TL._marshal_handshake_message(client_hello)
    TL._transcript_update!(transcript, client_hello_bytes)

    client_share = client_hello.key_shares[1]::TL._TLSKeyShare
    server_share, shared_secret = TL._tls13_openssl_x25519_server_share_and_secret(client_share.data, _PC_TLS13_SERVER_X25519_PRIVATE_KEY)
    server_hello = _pc_tls13_server_hello(client_hello.session_id, copy(server_share.data))
    server_hello_bytes = TL._marshal_handshake_message(server_hello)
    TL._transcript_update!(transcript, server_hello_bytes)

    early_secret = TL._tls13_early_secret(TL._HASH_SHA256, UInt8[])
    handshake_secret = TL._tls13_handshake_secret(early_secret, shared_secret)
    client_handshake_traffic_secret = TL._tls13_client_handshake_traffic_secret(handshake_secret, transcript)
    server_handshake_traffic_secret = TL._tls13_server_handshake_traffic_secret(handshake_secret, transcript)

    encrypted_extensions = TL._EncryptedExtensionsMsg()
    encrypted_extensions.alpn_protocol = "h2"
    encrypted_extensions_bytes = TL._marshal_handshake_message(encrypted_extensions)
    TL._transcript_update!(transcript, encrypted_extensions_bytes)

    certificate = _pc_tls13_server_certificate()
    certificate_bytes = TL._marshal_handshake_message(certificate)
    TL._transcript_update!(transcript, certificate_bytes)

    certificate_verify = TL._CertificateVerifyMsg(
        TL._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
        _pc_tls13_certificate_verify_signature(),
    )
    certificate_verify_bytes = TL._marshal_handshake_message(certificate_verify)
    TL._transcript_update!(transcript, certificate_verify_bytes)

    server_finished = TL._FinishedMsg(TL._tls13_finished_verify_data(TL._TLS13_AES_128_GCM_SHA256, server_handshake_traffic_secret, transcript))
    server_finished_bytes = TL._marshal_handshake_message(server_finished)
    TL._transcript_update!(transcript, server_finished_bytes)

    transcript_for_client = TL._TranscriptHash(TL._HASH_SHA256)
    transcript_bytes = TL._transcript_buffered_bytes(transcript)::Vector{UInt8}
    TL._transcript_update!(transcript_for_client, transcript_bytes)

    client_finished = TL._FinishedMsg(TL._tls13_finished_verify_data(TL._TLS13_AES_128_GCM_SHA256, client_handshake_traffic_secret, transcript_for_client))
    client_finished_bytes = TL._marshal_handshake_message(client_finished)

    master_secret = TL._tls13_master_secret(handshake_secret)
    client_application_traffic_secret = TL._tls13_client_application_traffic_secret(master_secret, transcript)
    server_application_traffic_secret = TL._tls13_server_application_traffic_secret(master_secret, transcript)
    exporter_master_secret = TL._tls13_exporter_secret_for_test(TL._tls13_exporter_master_secret(master_secret, transcript))

    new_session_ticket = TL._NewSessionTicketMsgTLS13()
    new_session_ticket.lifetime = 0x00015180
    new_session_ticket.age_add = 0x05060708
    new_session_ticket.nonce = UInt8[0x90, 0x91]
    new_session_ticket.label = UInt8[0xa0, 0xa1, 0xa2]
    new_session_ticket.max_early_data = 0x0b0c0d0e
    new_session_ticket_bytes = TL._marshal_handshake_message(new_session_ticket)

    inbound = [
        server_hello_bytes,
        encrypted_extensions_bytes,
        certificate_bytes,
        certificate_verify_bytes,
        server_finished_bytes,
        new_session_ticket_bytes,
    ]
    outbound = [
        client_hello_bytes,
        client_finished_bytes,
    ]

    state_client_hello = _pc_tls13_client_hello()
    state_key_share_provider = TL._TLS13OpenSSLKeyShareProvider(fixed_private_key = _PC_TLS13_CLIENT_X25519_PRIVATE_KEY)
    state = TL._TLS13ClientHandshakeState(
        state_client_hello,
        TL._TLS13_AES_128_GCM_SHA256_ID,
        state_key_share_provider,
        TL._TLS13OpenSSLCertificateVerifier(),
    )::TL._TLS13ClientHandshakeState{TL._HASH_SHA256}
    io = TL._HandshakeMessageFlightIO(inbound)
    try
        TL._client_handshake_tls13!(state, io)
        state.complete || throw(ArgumentError("TLS 1.3 workload expected complete handshake"))
        !state.using_psk || throw(ArgumentError("TLS 1.3 workload expected certificate handshake"))
        state.client_protocol == "h2" || throw(ArgumentError("TLS 1.3 workload expected ALPN selection"))
        !state.have_certificate_request || throw(ArgumentError("TLS 1.3 workload did not expect CertificateRequest"))
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
        TL._destroy_tls13_secret!(early_secret)
        TL._destroy_tls13_secret!(handshake_secret)
        TL._destroy_tls13_secret!(master_secret)
        TL._securezero!(shared_secret)
        TL._securezero_tls13_key_share_provider!(key_share_provider)
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
