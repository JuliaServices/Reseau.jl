
using Test
using Random
using Reseau
include("read_write_test_handler.jl")

const _TLS_RESOURCE_ROOT = joinpath(dirname(@__DIR__), "aws-c-io", "tests", "resources")

function _resource_path(name::AbstractString)
    return joinpath(_TLS_RESOURCE_ROOT, name)
end

const TEST_PEM_CERT = String(read(_resource_path("unittests.crt")))
const TEST_PEM_KEY = String(read(_resource_path("unittests.key")))

function wait_for_flag_tls(flag::Base.RefValue{Bool}; timeout_s::Float64 = 5.0)
    start = Base.time_ns()
    timeout_ns = Int(timeout_s * 1_000_000_000)
    while (Base.time_ns() - start) < timeout_ns
        if flag[]
            return true
        end
        sleep(0.01)
    end
    return false
end

function wait_for_pred_tls(pred::Function; timeout_s::Float64 = 10.0)
    start = Base.time_ns()
    timeout_ns = Int(timeout_s * 1_000_000_000)
    while (Base.time_ns() - start) < timeout_ns
        if pred()
            return true
        end
        sleep(0.01)
    end
    return pred()
end

function wait_for_handshake_status(handler, status; timeout_s::Float64 = 5.0)
    start = Base.time_ns()
    timeout_ns = Int(timeout_s * 1_000_000_000)
    while (Base.time_ns() - start) < timeout_ns
        if handler.stats.handshake_status == status
            return true
        end
        sleep(0.01)
    end
    return false
end

function mark_tls_handler_negotiated!(handler)
    if hasproperty(handler, :state)
        setfield!(handler, :state, Sockets.TlsNegotiationState.SUCCEEDED)
    elseif hasproperty(handler, :negotiation_finished)
        setfield!(handler, :negotiation_finished, true)
    end
    return nothing
end

function mark_tls_handler_failed!(handler)
    if hasproperty(handler, :state)
        setfield!(handler, :state, Sockets.TlsNegotiationState.FAILED)
    elseif hasproperty(handler, :negotiation_finished)
        setfield!(handler, :negotiation_finished, false)
    end
    return nothing
end

mutable struct TlsTestRwArgs
    lock::ReentrantLock
    invocation_happened::Bool
    read_invocations::Int
    received_message::Reseau.ByteBuffer
end

function TlsTestRwArgs(; capacity::Integer = 256)
    return TlsTestRwArgs(ReentrantLock(), false, 0, Reseau.ByteBuffer(capacity))
end

function tls_rw_reset_flag!(args::TlsTestRwArgs)
    lock(args.lock) do
        args.invocation_happened = false
    end
    return nothing
end

function tls_wait_for_read(args::TlsTestRwArgs; timeout_s::Float64 = 5.0)
    start = Base.time_ns()
    timeout_ns = Int(timeout_s * 1_000_000_000)
    while (Base.time_ns() - start) < timeout_ns
        lock(args.lock) do
            if args.invocation_happened
                return true
            end
        end
        sleep(0.01)
    end
    lock(args.lock) do
        return args.invocation_happened
    end
end

function tls_test_handle_read(handler, slot, data_read, user_data)
    _ = handler
    _ = slot
    args = user_data::TlsTestRwArgs
    lock(args.lock) do
        if data_read !== nothing
            buf_ref = Ref(args.received_message)
            Reseau.byte_buf_write_from_whole_buffer(buf_ref, data_read)
            args.received_message = buf_ref[]
        end
        args.read_invocations += 1
        args.invocation_happened = true
    end
    return args.received_message
end

function tls_test_handle_write(handler, slot, data_read, user_data)
    _ = handler
    _ = slot
    _ = data_read
    _ = user_data
    return Reseau.null_buffer()
end

function _buf_to_string(buf::Reseau.ByteBuffer)
    return String(Reseau.byte_cursor_from_buf(buf))
end

function _load_resource_buf(name::AbstractString)
    path = _resource_path(name)
    if !isfile(path)
        return nothing
    end
    bytes = try
        read(path)
    catch
        return nothing
    end
    buf_ref = Ref(Reseau.null_buffer())
    Reseau.byte_buf_init_copy_from_cursor(buf_ref, Reseau.ByteCursor(bytes)) == Reseau.AWS_OP_SUCCESS || return nothing
    return buf_ref[]
end

function _tls_network_connect(
        host::AbstractString,
        port::Integer;
        ctx_options_override::Union{Function, Nothing} = nothing,
    )
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(elg)

    ctx_opts = Sockets.tls_ctx_options_init_default_client()
    if ctx_options_override !== nothing
        ctx_options_override(ctx_opts)
    end
    local ctx
    try
        ctx = Sockets.tls_context_new(ctx_opts)
    catch e
        Sockets.host_resolver_shutdown!(resolver)
        EventLoops.event_loop_group_destroy!(elg)
        return e isa Reseau.ReseauError ? e.code : rethrow()
    end

    setup_err = Ref{Union{Nothing, Int}}(nothing)
    channel_ref = Ref{Any}(nothing)

    tls_conn_opts = Sockets.TlsConnectionOptions(
        ctx;
        server_name = host,
        on_negotiation_result = (handler, slot, err) -> begin
            _ = handler
            _ = slot
            return nothing
        end,
    )

    client_bootstrap = Sockets.ClientBootstrap(Sockets.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    _ = Sockets.client_bootstrap_connect!(
        client_bootstrap,
        host,
        port;
        tls_connection_options = tls_conn_opts,
        on_setup = (bs, err, channel, ud) -> begin
            _ = bs
            _ = ud
            setup_err[] = err
            channel_ref[] = channel
            return nothing
        end,
    )

    wait_for_pred_tls(() -> setup_err[] !== nothing; timeout_s = 20.0)

    if channel_ref[] !== nothing
        Sockets.pipeline_shutdown!(channel_ref[], 0)
    end

    Sockets.host_resolver_shutdown!(resolver)
    EventLoops.event_loop_group_destroy!(elg)

    return setup_err[]
end

function _test_server_ctx()
    cert_path = _resource_path("unittests.crt")
    key_path = _resource_path("unittests.key")
    opts = Sockets.tls_ctx_options_init_default_server_from_path(cert_path, key_path)
    maybe_apply_test_keychain!(opts)
    return Sockets.tls_context_new(opts)
end

function _test_client_ctx(; verify_peer::Bool = true)
    opts = Sockets.tls_ctx_options_init_default_client()
    if verify_peer
        ca_file = _resource_path(Sys.isapple() ? "unittests.crt" : "ca_root.crt")
        Sockets.tls_ctx_options_override_default_trust_store_from_path(opts; ca_file = ca_file)
    else
        Sockets.tls_ctx_options_set_verify_peer(opts, false)
    end
    return Sockets.tls_context_new(opts)
end

@testset "TLS options parity" begin
    opts = Sockets.tls_ctx_options_init_default_client()
    @test !opts.is_server
    @test opts.verify_peer

    Sockets.tls_ctx_options_set_verify_peer(opts, false)
    @test !opts.verify_peer

    Sockets.tls_ctx_options_set_minimum_tls_version(opts, Sockets.TlsVersion.TLSv1_2)
    @test opts.minimum_tls_version == Sockets.TlsVersion.TLSv1_2

    Sockets.tls_ctx_options_set_tls_cipher_preference(
        opts,
        Sockets.TlsCipherPref.TLS_CIPHER_PREF_SYSTEM_DEFAULT,
    )
    @test Sockets.tls_is_cipher_pref_supported(opts.cipher_pref)

    @test Sockets.tls_ctx_options_override_default_trust_store(
        opts,
        Reseau.ByteCursor(TEST_PEM_CERT),
    ) === nothing
    @test _buf_to_string(opts.ca_file) == TEST_PEM_CERT

    temp_dir = mktempdir()
    ca_path = joinpath(temp_dir, "ca.pem")
    write(ca_path, TEST_PEM_CERT)
    @test_throws Reseau.ReseauError Sockets.tls_ctx_options_override_default_trust_store_from_path(
        opts;
        ca_path = "/tmp",
        ca_file = ca_path,
    )

    opts2 = Sockets.tls_ctx_options_init_default_client()
    @test Sockets.tls_ctx_options_override_default_trust_store_from_path(
        opts2;
        ca_path = "/tmp",
        ca_file = ca_path,
    ) === nothing
    @test opts2.ca_path == "/tmp"
    @test _buf_to_string(opts2.ca_file) == TEST_PEM_CERT

    ctx = Sockets.tls_context_new(opts)
    @test ctx isa Sockets.TlsContext

    conn = Sockets.tls_connection_options_init_from_ctx(ctx)
    @test conn.timeout_ms == 0x00002710
    Sockets.tls_connection_options_set_server_name(conn, "example.com")
    Sockets.tls_connection_options_set_alpn_list(conn, "h2")
    Sockets.tls_connection_options_set_timeout_ms(conn, 250)
    Sockets.tls_connection_options_set_advertise_alpn_message(conn, true)

    cb1 = (handler, slot, err) -> nothing
    cb2 = (handler, slot, buf) -> nothing
    cb3 = (handler, slot, err, msg) -> nothing
    Sockets.tls_connection_options_set_callbacks(conn, cb1, cb2, cb3)

    @test conn.server_name == "example.com"
    @test conn.alpn_list == "h2"
    @test conn.timeout_ms == 0x000000fa
    @test conn.advertise_alpn_message
    @test conn.on_negotiation_result isa Reseau.TlsNegotiationResultCallback
    @test conn.on_data_read isa Reseau.TlsDataReadCallback
    @test conn.on_error isa Reseau.TlsErrorCallback

    conn_copy = Sockets.tls_connection_options_copy(conn)
    @test conn_copy.server_name == conn.server_name
    @test conn_copy.alpn_list == conn.alpn_list
    @test conn_copy.timeout_ms == conn.timeout_ms
end

@testset "TLS static state" begin
    Sockets.tls_init_static_state()
    @test !Sockets.is_using_secitem()
    Sockets.tls_clean_up_static_state()
end

@testset "TLS ctx acquire/release" begin
    ctx = _test_client_ctx()
    @test ctx isa Sockets.TlsContext
    @test Sockets.tls_ctx_acquire(ctx) === ctx
    @test Sockets.tls_ctx_release(ctx) === nothing
    @test Sockets.tls_ctx_acquire(nothing) === nothing
    @test Sockets.tls_ctx_release(nothing) === nothing
end

@testset "TLS ctx new helpers" begin
    opts = Sockets.tls_ctx_options_init_default_client()
    @test Sockets.tls_ctx_options_override_default_trust_store(opts, Reseau.ByteCursor(TEST_PEM_CERT)) === nothing
    ctx = Sockets.tls_client_ctx_new(opts)
    @test ctx isa Sockets.TlsContext
    @test !ctx.options.is_server
    @test ctx.options.ca_file.len == opts.ca_file.len
    @test ctx.options.ca_file.mem !== opts.ca_file.mem

    server_ctx = Sockets.tls_server_ctx_new(opts)
    @test server_ctx isa Sockets.TlsContext
    @test server_ctx.options.is_server

    srv_opts = Sockets.tls_ctx_options_init_default_server(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY),
    )
    @test srv_opts isa Sockets.TlsContextOptions
    client_ctx = Sockets.tls_client_ctx_new(srv_opts)
    @test client_ctx isa Sockets.TlsContext
    @test !client_ctx.options.is_server

    bad_opts = Sockets.tls_ctx_options_init_default_client()
    Sockets.tls_ctx_options_set_tls_cipher_preference(
        bad_opts,
        Sockets.TlsCipherPref.TLS_CIPHER_PREF_END_RANGE,
    )
    try
        bad_ctx = Sockets.tls_client_ctx_new(bad_opts)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == EventLoops.ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED
    end
end

@testset "TLS error code predicate - comprehensive" begin
    # All 26 TLS error codes must be recognized by the predicate
    tls_errors = [
        EventLoops.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE,
        EventLoops.ERROR_IO_TLS_ERROR_NOT_NEGOTIATED,
        EventLoops.ERROR_IO_TLS_ERROR_WRITE_FAILURE,
        EventLoops.ERROR_IO_TLS_ERROR_ALERT_RECEIVED,
        EventLoops.ERROR_IO_TLS_CTX_ERROR,
        EventLoops.ERROR_IO_TLS_VERSION_UNSUPPORTED,
        EventLoops.ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED,
        EventLoops.ERROR_IO_TLS_NEGOTIATION_TIMEOUT,
        EventLoops.ERROR_IO_TLS_ALERT_NOT_GRACEFUL,
        EventLoops.ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED,
        EventLoops.ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED,
        EventLoops.ERROR_IO_TLS_ERROR_READ_FAILURE,
        EventLoops.ERROR_IO_TLS_UNKNOWN_ROOT_CERTIFICATE,
        EventLoops.ERROR_IO_TLS_NO_ROOT_CERTIFICATE_FOUND,
        EventLoops.ERROR_IO_TLS_CERTIFICATE_EXPIRED,
        EventLoops.ERROR_IO_TLS_CERTIFICATE_NOT_YET_VALID,
        EventLoops.ERROR_IO_TLS_BAD_CERTIFICATE,
        EventLoops.ERROR_IO_TLS_PEER_CERTIFICATE_EXPIRED,
        EventLoops.ERROR_IO_TLS_BAD_PEER_CERTIFICATE,
        EventLoops.ERROR_IO_TLS_PEER_CERTIFICATE_REVOKED,
        EventLoops.ERROR_IO_TLS_PEER_CERTIFICATE_UNKNOWN,
        EventLoops.ERROR_IO_TLS_INTERNAL_ERROR,
        EventLoops.ERROR_IO_TLS_CLOSED_GRACEFUL,
        EventLoops.ERROR_IO_TLS_CLOSED_ABORT,
        EventLoops.ERROR_IO_TLS_INVALID_CERTIFICATE_CHAIN,
        EventLoops.ERROR_IO_TLS_HOST_NAME_MISMATCH,
    ]
    for code in tls_errors
        @test Sockets.io_error_code_is_tls(code)
    end
    # Non-TLS error codes must not be recognized
    @test !Sockets.io_error_code_is_tls(EventLoops.ERROR_IO_SOCKET_TIMEOUT)
    @test !Sockets.io_error_code_is_tls(EventLoops.ERROR_IO_DNS_QUERY_FAILED)
    @test !Sockets.io_error_code_is_tls(EventLoops.ERROR_IO_EVENT_LOOP_SHUTDOWN)
    @test !Sockets.io_error_code_is_tls(EventLoops.ERROR_IO_BROKEN_PIPE)
    @test !Sockets.io_error_code_is_tls(0)
    # DEFAULT_TRUST_STORE_NOT_FOUND is a config error, not classified as TLS
    # (matches aws-c-io aws_error_code_is_tls predicate)
    @test !Sockets.io_error_code_is_tls(EventLoops.ERROR_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND)
end

@testset "NW socket TLS error translation" begin
    if !Sys.isapple()
        @test true
        return
    end
    # Test that _nw_determine_socket_error maps errSSL* codes to the correct TLS error codes.
    # These mappings match aws-c-io source/darwin/nw_socket.c:s_determine_socket_error()
    errSSL_map = [
        (Int32(-9812), EventLoops.ERROR_IO_TLS_UNKNOWN_ROOT_CERTIFICATE),      # errSSLUnknownRootCert
        (Int32(-9813), EventLoops.ERROR_IO_TLS_NO_ROOT_CERTIFICATE_FOUND),     # errSSLNoRootCert
        (Int32(-9814), EventLoops.ERROR_IO_TLS_CERTIFICATE_EXPIRED),           # errSSLCertExpired
        (Int32(-9815), EventLoops.ERROR_IO_TLS_CERTIFICATE_NOT_YET_VALID),     # errSSLCertNotYetValid
        (Int32(-9824), EventLoops.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE),     # errSSLPeerHandshakeFail
        (Int32(-9808), EventLoops.ERROR_IO_TLS_BAD_CERTIFICATE),              # errSSLBadCert
        (Int32(-9828), EventLoops.ERROR_IO_TLS_PEER_CERTIFICATE_EXPIRED),     # errSSLPeerCertExpired
        (Int32(-9825), EventLoops.ERROR_IO_TLS_BAD_PEER_CERTIFICATE),         # errSSLPeerBadCert
        (Int32(-9827), EventLoops.ERROR_IO_TLS_PEER_CERTIFICATE_REVOKED),     # errSSLPeerCertRevoked
        (Int32(-9829), EventLoops.ERROR_IO_TLS_PEER_CERTIFICATE_UNKNOWN),     # errSSLPeerCertUnknown
        (Int32(-9810), EventLoops.ERROR_IO_TLS_INTERNAL_ERROR),               # errSSLInternal
        (Int32(-9805), EventLoops.ERROR_IO_TLS_CLOSED_GRACEFUL),              # errSSLClosedGraceful
        (Int32(-9806), EventLoops.ERROR_IO_TLS_CLOSED_ABORT),                 # errSSLClosedAbort
        (Int32(-9807), EventLoops.ERROR_IO_TLS_INVALID_CERTIFICATE_CHAIN),    # errSSLXCertChainInvalid
        (Int32(-9843), EventLoops.ERROR_IO_TLS_HOST_NAME_MISMATCH),           # errSSLHostNameMismatch
        (Int32(-67843), EventLoops.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE),   # errSecNotTrusted
        (Int32(-9836), EventLoops.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE),    # errSSLPeerProtocolVersion
    ]
    for (osstatus, expected_error) in errSSL_map
        result = Sockets._nw_determine_socket_error(Int(osstatus))
        @test result == expected_error
    end
end

@testset "TLS ctx options mtls" begin
    opts = Sockets.tls_ctx_options_init_client_mtls(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY),
    )
    @test opts isa Sockets.TlsContextOptions
    @test _buf_to_string(opts.certificate) == TEST_PEM_CERT
    @test _buf_to_string(opts.private_key) == TEST_PEM_KEY

    temp_dir = mktempdir()
    cert_path = joinpath(temp_dir, "cert.pem")
    key_path = joinpath(temp_dir, "key.pem")
    write(cert_path, TEST_PEM_CERT)
    write(key_path, TEST_PEM_KEY)

    opts2 = Sockets.tls_ctx_options_init_client_mtls_from_path(cert_path, key_path)
    @test opts2 isa Sockets.TlsContextOptions
    @test _buf_to_string(opts2.certificate) == TEST_PEM_CERT
    @test _buf_to_string(opts2.private_key) == TEST_PEM_KEY
end

@testset "TLS ctx options pkcs12" begin
    pkcs_bytes = UInt8[0x01, 0x02, 0x03, 0x04]
    pkcs_pwd = "secret"

    if Sys.isapple()
        opts = Sockets.tls_ctx_options_init_client_mtls_pkcs12(pkcs_bytes, pkcs_pwd)
        @test opts isa Sockets.TlsContextOptions
        pkcs_out = Vector{UInt8}(undef, Int(opts.pkcs12.len))
        copyto!(pkcs_out, 1, opts.pkcs12.mem, 1, Int(opts.pkcs12.len))
        @test pkcs_out == pkcs_bytes
        @test _buf_to_string(opts.pkcs12_password) == pkcs_pwd
    else
        @test_throws Reseau.ReseauError Sockets.tls_ctx_options_init_client_mtls_pkcs12(pkcs_bytes, pkcs_pwd)
    end
end

@testset "TLS ctx options server init" begin
    opts = Sockets.tls_ctx_options_init_default_server(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY);
        alpn_list = "h2",
    )
    @test opts isa Sockets.TlsContextOptions
    @test opts.is_server
    @test !opts.verify_peer
    @test opts.alpn_list == "h2"

    temp_dir = mktempdir()
    cert_path = joinpath(temp_dir, "cert.pem")
    key_path = joinpath(temp_dir, "key.pem")
    write(cert_path, TEST_PEM_CERT)
    write(key_path, TEST_PEM_KEY)

    opts2 = Sockets.tls_ctx_options_init_default_server_from_path(
        cert_path,
        key_path;
        alpn_list = "h2",
    )
    @test opts2 isa Sockets.TlsContextOptions
    @test opts2.is_server
    @test !opts2.verify_peer
    @test opts2.alpn_list == "h2"
end

@testset "TLS ctx options platform hooks" begin
    opts = Sockets.tls_ctx_options_init_default_client()
    if Sys.isapple()
        secitem = Sockets.SecItemOptions("cert", "key")
        if Sockets.is_using_secitem()
            @test_throws Reseau.ReseauError Sockets.tls_ctx_options_set_keychain_path(opts, "/tmp")
            @test Sockets.tls_ctx_options_set_secitem_options(opts, secitem) === nothing
        else
            @test Sockets.tls_ctx_options_set_keychain_path(opts, "/tmp") === nothing
            @test_throws Reseau.ReseauError Sockets.tls_ctx_options_set_secitem_options(opts, secitem)
        end
    else
        @test_throws Reseau.ReseauError Sockets.tls_ctx_options_set_keychain_path(opts, "/tmp")
        secitem = Sockets.SecItemOptions("cert", "key")
        @test_throws Reseau.ReseauError Sockets.tls_ctx_options_set_secitem_options(opts, secitem)
    end
end

@testset "TLS minimum version TLSv1_3 unsupported on macOS" begin
    if !Sys.isapple()
        @test true
        return
    end

    opts = Sockets.tls_ctx_options_init_default_client()
    Sockets.tls_ctx_options_set_minimum_tls_version(opts, Sockets.TlsVersion.TLSv1_3)
    ctx = Sockets.tls_context_new(opts)
    @test ctx isa Sockets.TlsContext
    if !(ctx isa Sockets.TlsContext)
        return
    end

    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    ps = Sockets.PipelineState(event_loop)
    socket_opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    socket = Sockets.socket_init(socket_opts)
    conn = Sockets.tls_connection_options_init_from_ctx(ctx)
    try
        res = Sockets.tls_client_handler_new(conn, socket, ps)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == EventLoops.ERROR_IO_TLS_CTX_ERROR
    end

    EventLoops.event_loop_group_destroy!(elg)
end

@testset "TLS ctx options custom key ops" begin
    try
        res = Sockets.tls_ctx_options_init_client_mtls_with_custom_key_operations(
            nothing,
            Reseau.ByteCursor(TEST_PEM_CERT),
        )
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == Reseau.ERROR_INVALID_ARGUMENT
    end
end

@testset "TLS custom key op handler" begin
    op = Sockets.TlsKeyOperation(Reseau.ByteCursor(UInt8[0x01]))
    called = Ref(false)
    handler = Sockets.CustomKeyOpHandler(
        (handler_obj, operation) -> begin
            @test operation === op
            called[] = true
        end,
    )

    @test Sockets.custom_key_op_handler_acquire(handler) === handler
    @test Sockets.custom_key_op_handler_release(handler) === nothing
    Sockets.custom_key_op_handler_perform_operation(handler, op)
    @test called[]
end

@testset "TLS ctx options custom key ops init" begin
    handler = Sockets.CustomKeyOpHandler((handler_obj, operation) -> nothing)
    opts = Sockets.tls_ctx_options_init_client_mtls_with_custom_key_operations(
        handler,
        Reseau.ByteCursor(TEST_PEM_CERT),
    )
    @test opts isa Sockets.TlsContextOptions
    @test opts.custom_key_op_handler === handler
    @test _buf_to_string(opts.certificate) == TEST_PEM_CERT

    try
        bad = Sockets.tls_ctx_options_init_client_mtls_with_custom_key_operations(
            Sockets.CustomKeyOpHandler(nothing),
            Reseau.ByteCursor(TEST_PEM_CERT),
        )
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == Reseau.ERROR_INVALID_ARGUMENT
    end
end

@testset "TLS custom key ops TLSv1_3 unsupported (s2n)" begin
    if !Sys.islinux()
        @test true
        return
    end
    if !Sockets.tls_is_alpn_available()
        @info "Skipping TLS custom key ops TLSv1_3 test (s2n unavailable)"
        return
    end

    handler = Sockets.CustomKeyOpHandler((handler_obj, operation) -> nothing)
    opts = Sockets.tls_ctx_options_init_client_mtls_with_custom_key_operations(
        handler,
        Reseau.ByteCursor(TEST_PEM_CERT),
    )
    @test opts isa Sockets.TlsContextOptions

    Sockets.tls_ctx_options_set_minimum_tls_version(opts, Sockets.TlsVersion.TLSv1_3)
    try
        ctx = Sockets.tls_context_new(opts)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == EventLoops.ERROR_IO_TLS_VERSION_UNSUPPORTED
    end
end

@testset "TLS ctx options pkcs11" begin
    opts = Sockets.TlsCtxPkcs11Options(
        pkcs11_lib = :fake,
        cert_file_path = "cert.pem",
        cert_file_contents = "cert",
    )
    try
        res = Sockets.tls_ctx_options_init_client_mtls_with_pkcs11(opts)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == Reseau.ERROR_INVALID_ARGUMENT
    end

    temp_dir = mktempdir()
    cert_path = joinpath(temp_dir, "cert.pem")
    write(cert_path, TEST_PEM_CERT)

    opts2 = Sockets.TlsCtxPkcs11Options(
        pkcs11_lib = :fake,
        cert_file_path = cert_path,
    )
    try
        res2 = Sockets.tls_ctx_options_init_client_mtls_with_pkcs11(opts2)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == Reseau.ERROR_INVALID_ARGUMENT
    end

    opts3 = Sockets.TlsCtxPkcs11Options(
        pkcs11_lib = :fake,
        cert_file_contents = TEST_PEM_CERT,
    )
    try
        res3 = Sockets.tls_ctx_options_init_client_mtls_with_pkcs11(opts3)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == Reseau.ERROR_INVALID_ARGUMENT
    end
end

@testset "TLS BYO crypto setup" begin
    new_handler = (options, socket, pipeline, ud) -> nothing
    start_negotiation = (handler, ud) -> 0
    client_opts = Sockets.TlsByoCryptoSetupOptions(
        new_handler_fn = new_handler,
        start_negotiation_fn = start_negotiation,
        user_data = 7,
    )
    @test Sockets.tls_byo_crypto_set_client_setup_options(client_opts) === nothing

    server_opts = Sockets.TlsByoCryptoSetupOptions(
        new_handler_fn = new_handler,
        user_data = 9,
    )
    @test Sockets.tls_byo_crypto_set_server_setup_options(server_opts) === nothing

    bad_client = Sockets.TlsByoCryptoSetupOptions(
        new_handler_fn = nothing,
        start_negotiation_fn = nothing,
    )
    try
        res = Sockets.tls_byo_crypto_set_client_setup_options(bad_client)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == Reseau.ERROR_INVALID_ARGUMENT
    end

    Sockets._tls_byo_client_setup[] = nothing
    Sockets._tls_byo_server_setup[] = nothing
end

@testset "TLS timeout task" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Sockets.TlsContext

    opts = Sockets.TlsConnectionOptions(ctx; timeout_ms = 1)
    ps = Sockets.PipelineState(event_loop)
    socket_opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    socket = Sockets.socket_init(socket_opts)
    handler = Sockets.tls_client_handler_new(opts, socket, ps)

    handler.stats.handshake_status = Sockets.TlsNegotiationStatus.ONGOING
    Sockets._tls_timeout_task(handler, Reseau.TaskStatus.RUN_READY)

    @test ps.shutdown_pending
    @test ps.shutdown_error_code == EventLoops.ERROR_IO_TLS_NEGOTIATION_TIMEOUT

    EventLoops.event_loop_group_destroy!(elg)
end

@testset "TLS key operations" begin
    input_bytes = UInt8[0x01, 0x02, 0x03]
    input_cursor = Reseau.ByteCursor(input_bytes)

    cb_called = Ref(false)
    cb_err = Ref(0)
    cb_ud = Ref(0)
    cb_op = Ref{Any}(nothing)
    on_complete = (operation, err, user_data) -> begin
        cb_called[] = true
        cb_err[] = err
        cb_ud[] = user_data
        cb_op[] = operation
    end

    operation = Sockets.TlsKeyOperation(
        input_cursor;
        operation_type = Sockets.TlsKeyOperationType.SIGN,
        signature_algorithm = Sockets.TlsSignatureAlgorithm.RSA,
        digest_algorithm = Sockets.TlsHashAlgorithm.SHA256,
        on_complete = on_complete,
        user_data = 99,
    )

    @test Sockets.tls_key_operation_get_type(operation) == Sockets.TlsKeyOperationType.SIGN
    @test Sockets.tls_key_operation_get_signature_algorithm(operation) == Sockets.TlsSignatureAlgorithm.RSA
    @test Sockets.tls_key_operation_get_digest_algorithm(operation) == Sockets.TlsHashAlgorithm.SHA256
    @test Reseau.byte_cursor_eq(Sockets.tls_key_operation_get_input(operation), input_cursor)

    output_cursor = Reseau.ByteCursor(UInt8[0x0a, 0x0b])
    @test Sockets.tls_key_operation_complete!(operation, output_cursor) === nothing
    @test operation.completed
    @test operation.error_code == Reseau.AWS_OP_SUCCESS
    @test cb_called[]
    @test cb_err[] == Reseau.AWS_OP_SUCCESS
    @test cb_ud[] == 99
    @test cb_op[] === operation
    @test Reseau.byte_cursor_eq(Reseau.byte_cursor_from_buf(operation.output), output_cursor)

    cb_called[] = false
    err_operation = Sockets.TlsKeyOperation(
        input_cursor;
        on_complete = on_complete,
        user_data = 123,
    )
    @test Sockets.tls_key_operation_complete_with_error!(
        err_operation,
        EventLoops.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE,
    ) === nothing
    @test err_operation.completed
    @test err_operation.error_code == EventLoops.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE
    @test cb_called[]
    @test cb_err[] == EventLoops.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE
    @test cb_ud[] == 123

    @test Sockets.tls_hash_algorithm_str(Sockets.TlsHashAlgorithm.SHA384) == "SHA384"
    @test Sockets.tls_hash_algorithm_str(Sockets.TlsHashAlgorithm.UNKNOWN) == "UNKNOWN"
    @test Sockets.tls_signature_algorithm_str(Sockets.TlsSignatureAlgorithm.ECDSA) == "ECDSA"
    @test Sockets.tls_signature_algorithm_str(Sockets.TlsSignatureAlgorithm.UNKNOWN) == "UNKNOWN"
    @test Sockets.tls_key_operation_type_str(Sockets.TlsKeyOperationType.SIGN) == "SIGN"
    @test Sockets.tls_key_operation_type_str(Sockets.TlsKeyOperationType.UNKNOWN) == "UNKNOWN"
end

@testset "TLS handler accessors" begin
    opts = Sockets.tls_ctx_options_init_default_client()
    ctx = Sockets.tls_context_new(opts)
    @test ctx isa Sockets.TlsContext

    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    ps = Sockets.PipelineState(event_loop)
    socket_opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    socket = Sockets.socket_init(socket_opts)
    conn = Sockets.tls_connection_options_init_from_ctx(ctx)
    Sockets.tls_connection_options_set_server_name(conn, "example.com")
    handler = Sockets.tls_client_handler_new(conn, socket, ps)

    @test _buf_to_string(Sockets.tls_handler_server_name(handler)) == "example.com"
    @test Sockets.tls_handler_protocol(handler).len == 0

    handler.protocol = Reseau.byte_buf_from_c_str("h2")
    @test _buf_to_string(Sockets.tls_handler_protocol(handler)) == "h2"

    EventLoops.event_loop_group_destroy!(elg)
end

@testset "TLS BYO crypto integration" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Sockets.TlsContext

    new_called = Ref(false)
    start_called = Ref(false)
    seen_socket = Ref{Any}(nothing)
    seen_pipeline = Ref{Any}(nothing)
    seen_new_ud = Ref{Any}(nothing)
    seen_start_ud = Ref{Any}(nothing)
    seen_handler = Ref{Any}(nothing)
    server_new_called = Ref(false)
    server_seen_socket = Ref{Any}(nothing)
    server_seen_pipeline = Ref{Any}(nothing)
    server_seen_ud = Ref{Any}(nothing)
    server_seen_handler = Ref{Any}(nothing)

    # BYO crypto handler: just a mutable struct to serve as a handler
    byo_handler = (;)

    new_handler = (options, socket, pipeline, ud) -> begin
        new_called[] = true
        seen_socket[] = socket
        seen_pipeline[] = pipeline
        seen_new_ud[] = ud
        return byo_handler
    end
    start_negotiation = (handler, ud) -> begin
        start_called[] = true
        seen_handler[] = handler
        seen_start_ud[] = ud
        return Reseau.AWS_OP_SUCCESS
    end
    server_new_handler = (options, socket, pipeline, ud) -> begin
        server_new_called[] = true
        server_seen_socket[] = socket
        server_seen_pipeline[] = pipeline
        server_seen_ud[] = ud
        h = (;)
        server_seen_handler[] = h
        return h
    end

    client_opts = Sockets.TlsByoCryptoSetupOptions(
        new_handler_fn = new_handler,
        start_negotiation_fn = start_negotiation,
        user_data = 42,
    )
    @test Sockets.tls_byo_crypto_set_client_setup_options(client_opts) === nothing

    server_setup = Sockets.TlsByoCryptoSetupOptions(
        new_handler_fn = server_new_handler,
        user_data = 99,
    )
    @test Sockets.tls_byo_crypto_set_server_setup_options(server_setup) === nothing

    ps = Sockets.PipelineState(event_loop)
    socket_opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    socket = Sockets.socket_init(socket_opts)

    tls_opts = Sockets.TlsConnectionOptions(ctx; server_name = "example.com")
    handler = Sockets.tls_client_handler_new(tls_opts, socket, ps)
    @test new_called[]
    @test start_called[]
    @test seen_socket[] === socket
    @test seen_pipeline[] === ps
    @test seen_new_ud[] == 42
    @test seen_start_ud[] == 42
    @test seen_handler[] === handler

    server_opts = Sockets.tls_ctx_options_init_default_server(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY),
    )
    maybe_apply_test_keychain!(server_opts)
    @test server_opts isa Sockets.TlsContextOptions
    if server_opts isa Sockets.TlsContextOptions
        server_ctx = Sockets.tls_context_new(server_opts)
        @test server_ctx isa Sockets.TlsContext
        if server_ctx isa Sockets.TlsContext
            server_ps = Sockets.PipelineState(event_loop)
            server_socket = Sockets.socket_init(socket_opts)
            server_handler = Sockets.tls_server_handler_new(
                Sockets.TlsConnectionOptions(server_ctx),
                server_socket,
                server_ps,
            )
            @test server_new_called[]
            @test server_seen_socket[] === server_socket
            @test server_seen_pipeline[] === server_ps
            @test server_seen_ud[] == 99
            @test server_seen_handler[] === server_handler
        end
    end

    Sockets._tls_byo_client_setup[] = nothing
    Sockets._tls_byo_server_setup[] = nothing
    EventLoops.event_loop_group_destroy!(elg)
end

@testset "TLS client/server handler API" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    client_ctx = _test_client_ctx()
    @test client_ctx isa Sockets.TlsContext

    ps = Sockets.PipelineState(event_loop)
    socket_opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    socket = Sockets.socket_init(socket_opts)

    client_opts = Sockets.TlsConnectionOptions(client_ctx; server_name = "example.com")
    client_handler = Sockets.tls_client_handler_new(client_opts, socket, ps)
    client_opts.server_name = "changed"
    @test _buf_to_string(Sockets.tls_handler_server_name(client_handler)) == "example.com"
    @test client_handler.stats.handshake_status == Sockets.TlsNegotiationStatus.NONE

    server_opts = Sockets.tls_ctx_options_init_default_server(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY),
    )
    maybe_apply_test_keychain!(server_opts)
    @test server_opts isa Sockets.TlsContextOptions
    if server_opts isa Sockets.TlsContextOptions
        server_ctx = Sockets.tls_context_new(server_opts)
        @test server_ctx isa Sockets.TlsContext
        if server_ctx isa Sockets.TlsContext
            server_ps = Sockets.PipelineState(event_loop)
            server_socket = Sockets.socket_init(socket_opts)

            server_handler = Sockets.tls_server_handler_new(
                Sockets.TlsConnectionOptions(server_ctx),
                server_socket,
                server_ps,
            )
            @test server_handler.stats.handshake_status == Sockets.TlsNegotiationStatus.NONE

            bad_ps = Sockets.PipelineState(event_loop)
            bad_socket = Sockets.socket_init(socket_opts)
            try
                bad_handler = Sockets.tls_client_handler_new(Sockets.TlsConnectionOptions(server_ctx), bad_socket, bad_ps)
                @test false
            catch e
                @test e isa Reseau.ReseauError
                @test e.code == Reseau.ERROR_INVALID_ARGUMENT
            end
        end
    end

    @test Sockets.tls_is_alpn_available()
    EventLoops.event_loop_group_destroy!(elg)
end

@testset "pipeline_setup_client_tls!" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Sockets.TlsContext

    ps = Sockets.PipelineState(event_loop)
    socket_opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    socket = Sockets.socket_init(socket_opts)

    opts = Sockets.TlsConnectionOptions(ctx; timeout_ms = 1)
    handler = Sockets.pipeline_setup_client_tls!(ps, socket, opts)
    @test handler !== nothing

    EventLoops.event_loop_group_destroy!(elg)
end

@testset "TLS concurrent cert import" begin
    temp_dir = mktempdir()
    cert_path = joinpath(temp_dir, "cert.pem")
    key_path = joinpath(temp_dir, "key.pem")
    write(cert_path, TEST_PEM_CERT)
    write(key_path, TEST_PEM_KEY)

    function import_ctx()
        opts = Sockets.tls_ctx_options_init_client_mtls_from_path(cert_path, key_path)
        opts isa Sockets.TlsContextOptions || return opts
        maybe_apply_test_keychain!(opts)
        return Sockets.tls_client_ctx_new(opts)
    end

    tasks = [Threads.@spawn import_ctx() for _ in 1:2]
    ctxs = fetch.(tasks)
    @test all(ctx -> ctx isa Sockets.TlsContext, ctxs)
    for ctx in ctxs
        if ctx isa Sockets.TlsContext
            @test Sockets.tls_ctx_release(ctx) === nothing
        end
    end
end

@testset "TLS duplicate cert import" begin
    opts = Sockets.tls_ctx_options_init_client_mtls(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY),
    )
    @test opts isa Sockets.TlsContextOptions
    if opts isa Sockets.TlsContextOptions
        maybe_apply_test_keychain!(opts)
        ctx1 = Sockets.tls_client_ctx_new(opts)
        @test ctx1 isa Sockets.TlsContext
        if ctx1 isa Sockets.TlsContext
            @test Sockets.tls_ctx_release(ctx1) === nothing
        end

        maybe_apply_test_keychain!(opts)
        ctx2 = Sockets.tls_client_ctx_new(opts)
        @test ctx2 isa Sockets.TlsContext
        if ctx2 isa Sockets.TlsContext
            @test Sockets.tls_ctx_release(ctx2) === nothing
        end
    end
end

@testset "TLS pkcs8 import" begin
    cert_buf = _load_resource_buf("unittests.crt")
    key_buf = _load_resource_buf("unittests.p8")
    if cert_buf === nothing || key_buf === nothing
        @test true
    else
        opts = Sockets.tls_ctx_options_init_client_mtls(
            Reseau.byte_cursor_from_buf(cert_buf),
            Reseau.byte_cursor_from_buf(key_buf),
        )
        @test opts isa Sockets.TlsContextOptions
        if opts isa Sockets.TlsContextOptions
            maybe_apply_test_keychain!(opts)
            ctx = Sockets.tls_client_ctx_new(opts)
            @test ctx isa Sockets.TlsContext
        end
        Reseau.byte_buf_clean_up(Ref(cert_buf))
        Reseau.byte_buf_clean_up(Ref(key_buf))
    end
end

@testset "TLS ecc cert import" begin
    cert_buf = _load_resource_buf("ec_unittests.crt")
    key_name = Sys.isapple() ? "ec_unittests.key" : "ec_unittests.p8"
    key_buf = _load_resource_buf(key_name)
    if cert_buf === nothing || key_buf === nothing
        @test true
    else
        opts = Sockets.tls_ctx_options_init_client_mtls(
            Reseau.byte_cursor_from_buf(cert_buf),
            Reseau.byte_cursor_from_buf(key_buf),
        )
        @test opts isa Sockets.TlsContextOptions
        if opts isa Sockets.TlsContextOptions
            maybe_apply_test_keychain!(opts)
            ctx = Sockets.tls_client_ctx_new(opts)
            @test ctx isa Sockets.TlsContext
        end
        Reseau.byte_buf_clean_up(Ref(cert_buf))
        Reseau.byte_buf_clean_up(Ref(key_buf))
    end
end

@testset "TLS cipher preference" begin
    opts = Sockets.tls_ctx_options_init_default_client()
    Sockets.tls_ctx_options_set_tls_cipher_preference(
        opts,
        Sockets.TlsCipherPref.TLS_CIPHER_PREF_TLSV1_2_2025_07,
    )
    if Sockets.tls_is_cipher_pref_supported(opts.cipher_pref)
        ctx = Sockets.tls_client_ctx_new(opts)
        @test ctx isa Sockets.TlsContext
    else
        try
            ctx = Sockets.tls_client_ctx_new(opts)
            @test false
        catch e
            @test e isa Reseau.ReseauError
            @test e.code == EventLoops.ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED
        end
    end
end

function _tls_local_handshake_with_min_version(min_version::Sockets.TlsVersion.T)
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(elg)

    server_opts = Sockets.tls_ctx_options_init_default_server(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY),
    )
    Sockets.tls_ctx_options_set_minimum_tls_version(server_opts, min_version)
    maybe_apply_test_keychain!(server_opts)
    local server_ctx
    try
        server_ctx = Sockets.tls_context_new(server_opts)
    catch e
        Sockets.host_resolver_shutdown!(resolver)
        EventLoops.event_loop_group_destroy!(elg)
        return
    end
    @test server_ctx isa Sockets.TlsContext

    client_opts = Sockets.tls_ctx_options_init_default_client()
    Sockets.tls_ctx_options_set_minimum_tls_version(client_opts, min_version)
    Sockets.tls_ctx_options_override_default_trust_store_from_path(
        client_opts;
        ca_file = _resource_path("unittests.crt"),
    )
    local client_ctx
    try
        client_ctx = Sockets.tls_context_new(client_opts)
    catch e
        Sockets.host_resolver_shutdown!(resolver)
        EventLoops.event_loop_group_destroy!(elg)
        return
    end
    @test client_ctx isa Sockets.TlsContext

    server_setup_called = Ref(false)
    server_setup_err = Ref(Reseau.AWS_OP_SUCCESS)
    server_shutdown = Ref(false)
    server_channel = Ref{Any}(nothing)
    server_negotiated_called = Ref(false)
    server_negotiated_err = Ref(Reseau.AWS_OP_SUCCESS)
    listener_setup_called = Ref(false)
    listener_setup_err = Ref(Reseau.AWS_OP_SUCCESS)

    server_bootstrap = Sockets.ServerBootstrap(Sockets.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        tls_connection_options = Sockets.TlsConnectionOptions(
            server_ctx;
            on_negotiation_result = (handler, slot, err) -> begin
                server_negotiated_called[] = true
                server_negotiated_err[] = err
                return nothing
            end,
        ),
        on_incoming_channel_setup = (bs, err, channel, ud) -> begin
            server_setup_called[] = true
            server_setup_err[] = err
            server_channel[] = channel
            return nothing
        end,
        on_incoming_channel_shutdown = (bs, err, channel, ud) -> begin
            server_shutdown[] = true
            return nothing
        end,
        on_listener_setup = (bs, err, ud) -> begin
            listener_setup_called[] = true
            listener_setup_err[] = err
            return nothing
        end,
    ))

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    @test wait_for_flag_tls(listener_setup_called)
    @test listener_setup_err[] == Reseau.AWS_OP_SUCCESS
    bound = Sockets.socket_get_bound_address(listener)
    port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_bootstrap = Sockets.ClientBootstrap(Sockets.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    client_setup_called = Ref(false)
    client_setup_err = Ref(Reseau.AWS_OP_SUCCESS)
    client_shutdown = Ref(false)
    client_negotiated_called = Ref(false)
    client_negotiated_err = Ref(Reseau.AWS_OP_SUCCESS)
    client_channel = Ref{Any}(nothing)

    @test Sockets.client_bootstrap_connect!(
        client_bootstrap,
        "127.0.0.1",
        port;
        tls_connection_options = Sockets.TlsConnectionOptions(
            client_ctx;
            server_name = "localhost",
            on_negotiation_result = (handler, slot, err) -> begin
                client_negotiated_called[] = true
                client_negotiated_err[] = err
                return nothing
            end,
        ),
        on_setup = (bs, err, channel, ud) -> begin
            client_setup_called[] = true
            client_setup_err[] = err
            client_channel[] = channel
            return nothing
        end,
        on_shutdown = (bs, err, channel, ud) -> begin
            client_shutdown[] = true
            return nothing
        end,
    ) === nothing

    @test wait_for_flag_tls(server_setup_called)
    @test server_setup_err[] == Reseau.AWS_OP_SUCCESS
    @test wait_for_flag_tls(client_setup_called)
    @test client_setup_err[] == Reseau.AWS_OP_SUCCESS
    @test wait_for_flag_tls(server_negotiated_called)
    @test server_negotiated_err[] == Reseau.AWS_OP_SUCCESS
    @test wait_for_flag_tls(client_negotiated_called)
    @test client_negotiated_err[] == Reseau.AWS_OP_SUCCESS

    if server_channel[] !== nothing
        Sockets.pipeline_shutdown!(server_channel[], Reseau.AWS_OP_SUCCESS)
    end
    if client_channel[] !== nothing
        Sockets.pipeline_shutdown!(client_channel[], Reseau.AWS_OP_SUCCESS)
    end

    @test wait_for_flag_tls(server_shutdown)
    @test wait_for_flag_tls(client_shutdown)

    Sockets.server_bootstrap_shutdown!(server_bootstrap)
    Sockets.host_resolver_shutdown!(resolver)
    EventLoops.event_loop_group_destroy!(elg)
    return nothing
end

@testset "TLS minimum version handshake (TLSv1_2)" begin
    _tls_local_handshake_with_min_version(Sockets.TlsVersion.TLSv1_2)
end

@testset "TLS minimum version handshake (TLSv1_3, linux s2n)" begin
    if !Sys.islinux()
        @test true
        return
    end
    if !Sockets.tls_is_alpn_available()
        @info "Skipping TLSv1_3 handshake test (s2n unavailable)"
        return
    end
    _tls_local_handshake_with_min_version(Sockets.TlsVersion.TLSv1_3)
end

@testset "TLS server multiple connections" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(elg)

    server_opts = Sockets.tls_ctx_options_init_default_server(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY),
    )
    maybe_apply_test_keychain!(server_opts)
    server_ctx = Sockets.tls_context_new(server_opts)
    @test server_ctx isa Sockets.TlsContext

    client_ctx = _test_client_ctx()
    @test client_ctx isa Sockets.TlsContext

    server_setup_called = Ref(false)
    server_setup_err = Ref(Reseau.AWS_OP_SUCCESS)
    server_shutdown = Ref(false)
    server_channel = Ref{Any}(nothing)
    server_negotiated_called = Ref(false)
    server_negotiated_err = Ref(Reseau.AWS_OP_SUCCESS)
    listener_setup_called = Ref(false)
    listener_setup_err = Ref(Reseau.AWS_OP_SUCCESS)

    server_bootstrap = Sockets.ServerBootstrap(Sockets.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        tls_connection_options = Sockets.TlsConnectionOptions(
            server_ctx;
            on_negotiation_result = (handler, slot, err) -> begin
                server_negotiated_called[] = true
                server_negotiated_err[] = err
                return nothing
            end,
        ),
        on_incoming_channel_setup = (bs, err, channel, ud) -> begin
            server_setup_called[] = true
            server_setup_err[] = err
            server_channel[] = channel
            return nothing
        end,
        on_incoming_channel_shutdown = (bs, err, channel, ud) -> begin
            server_shutdown[] = true
            return nothing
        end,
        on_listener_setup = (bs, err, ud) -> begin
            listener_setup_called[] = true
            listener_setup_err[] = err
            return nothing
        end,
    ))

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    @test wait_for_flag_tls(listener_setup_called)
    @test listener_setup_err[] == Reseau.AWS_OP_SUCCESS
    bound = Sockets.socket_get_bound_address(listener)
    port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_bootstrap = Sockets.ClientBootstrap(Sockets.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    function connect_once!()
        server_setup_called[] = false
        server_setup_err[] = Reseau.AWS_OP_SUCCESS
        server_shutdown[] = false
        server_channel[] = nothing
        server_negotiated_called[] = false
        server_negotiated_err[] = Reseau.AWS_OP_SUCCESS

        client_setup_called = Ref(false)
        client_setup_err = Ref(Reseau.AWS_OP_SUCCESS)
        client_shutdown = Ref(false)
        client_negotiated_called = Ref(false)
        client_negotiated_err = Ref(Reseau.AWS_OP_SUCCESS)
        client_channel = Ref{Any}(nothing)

        @test Sockets.client_bootstrap_connect!(
            client_bootstrap,
            "127.0.0.1",
            port;
            tls_connection_options = Sockets.TlsConnectionOptions(
                client_ctx;
                server_name = "localhost",
                on_negotiation_result = (handler, slot, err) -> begin
                    client_negotiated_called[] = true
                    client_negotiated_err[] = err
                    return nothing
                end,
            ),
            on_setup = (bs, err, channel, ud) -> begin
                client_setup_called[] = true
                client_setup_err[] = err
                client_channel[] = channel
                return nothing
            end,
            on_shutdown = (bs, err, channel, ud) -> begin
                client_shutdown[] = true
                return nothing
            end,
        ) === nothing

        @test wait_for_flag_tls(server_setup_called)
        @test server_setup_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag_tls(client_setup_called)
        @test client_setup_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag_tls(server_negotiated_called)
        @test server_negotiated_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag_tls(client_negotiated_called)
        @test client_negotiated_err[] == Reseau.AWS_OP_SUCCESS

        if server_channel[] !== nothing
            Sockets.pipeline_shutdown!(server_channel[], Reseau.AWS_OP_SUCCESS)
        end

        @test wait_for_flag_tls(server_shutdown)
        @test wait_for_flag_tls(client_shutdown)
    end

    connect_once!()
    connect_once!()

    Sockets.server_bootstrap_shutdown!(server_bootstrap)
    Sockets.host_resolver_shutdown!(resolver)
    EventLoops.event_loop_group_destroy!(elg)
end

@testset "TLS server hangup during negotiation" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(elg)

    server_opts = Sockets.tls_ctx_options_init_default_server(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY),
    )
    maybe_apply_test_keychain!(server_opts)
    server_ctx = Sockets.tls_context_new(server_opts)
    @test server_ctx isa Sockets.TlsContext

    listener_destroyed = Ref(false)
    listener_setup_called = Ref(false)
    listener_setup_err = Ref(Reseau.AWS_OP_SUCCESS)
    server_bootstrap = Sockets.ServerBootstrap(Sockets.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        tls_connection_options = Sockets.TlsConnectionOptions(server_ctx),
        on_listener_destroy = (bs, ud) -> begin
            listener_destroyed[] = true
            return nothing
        end,
        on_listener_setup = (bs, err, ud) -> begin
            listener_setup_called[] = true
            listener_setup_err[] = err
            return nothing
        end,
    ))

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    @test wait_for_flag_tls(listener_setup_called)
    @test listener_setup_err[] == Reseau.AWS_OP_SUCCESS
    bound = Sockets.socket_get_bound_address(listener)
    port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    client_socket = Sockets.socket_init(client_opts)
    @test client_socket isa Sockets.Socket

    close_done = Ref(false)
    connect_opts = Sockets.SocketConnectOptions(
        Sockets.SocketEndpoint("127.0.0.1", port);
        event_loop = EventLoops.event_loop_group_get_next_loop(elg),
        on_connection_result = Reseau.EventCallable(err -> begin
            if err != Reseau.AWS_OP_SUCCESS
                close_done[] = true
                return nothing
            end
            loop = client_socket.event_loop
            if loop === nothing
                close_done[] = true
                return nothing
            end
            now = EventLoops.event_loop_current_clock_time(loop)
            task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return nothing
                Sockets.socket_close(client_socket)
                close_done[] = true
                return nothing
            end); type_tag = "close_client_socket")
            EventLoops.event_loop_schedule_task_future!(loop, task, now + UInt64(1_000_000_000))
            return nothing
        end),
    )

    @test Sockets.socket_connect(client_socket, connect_opts) === nothing
    @test wait_for_flag_tls(close_done)

    Sockets.server_bootstrap_shutdown!(server_bootstrap)
    @test wait_for_flag_tls(listener_destroyed)

    Sockets.socket_close(client_socket)
    Sockets.host_resolver_shutdown!(resolver)
    EventLoops.event_loop_group_destroy!(elg)
end

@testset "TLS certificate chain" begin
    cert_buf = _load_resource_buf("server_chain.crt")
    key_buf = _load_resource_buf("server.key")
    if cert_buf === nothing || key_buf === nothing
        @test true
        return
    end

    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(elg)

    server_opts = if Sys.isapple()
        Sockets.tls_ctx_options_init_server_pkcs12_from_path(_resource_path("unittests.p12"), "1234")
    else
        Sockets.tls_ctx_options_init_default_server(
            Reseau.byte_cursor_from_buf(cert_buf),
            Reseau.byte_cursor_from_buf(key_buf),
        )
    end
    maybe_apply_test_keychain!(server_opts)
    server_ctx = Sockets.tls_context_new(server_opts)
    @test server_ctx isa Sockets.TlsContext

    client_ctx = _test_client_ctx()
    @test client_ctx isa Sockets.TlsContext

    server_setup = Ref(false)
    client_setup = Ref(false)
    server_negotiated = Ref(false)
    client_negotiated = Ref(false)
    server_channel = Ref{Any}(nothing)
    client_channel = Ref{Any}(nothing)
    listener_setup_called = Ref(false)
    listener_setup_err = Ref(Reseau.AWS_OP_SUCCESS)

    server_bootstrap = Sockets.ServerBootstrap(Sockets.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        tls_connection_options = Sockets.TlsConnectionOptions(
            server_ctx;
            on_negotiation_result = (handler, slot, err) -> begin
                server_negotiated[] = err == Reseau.AWS_OP_SUCCESS
                return nothing
            end,
        ),
        on_incoming_channel_setup = (bs, err, channel, ud) -> begin
            server_setup[] = err == Reseau.AWS_OP_SUCCESS
            server_channel[] = channel
            return nothing
        end,
        on_listener_setup = (bs, err, ud) -> begin
            listener_setup_called[] = true
            listener_setup_err[] = err
            return nothing
        end,
    ))

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    @test wait_for_flag_tls(listener_setup_called)
    @test listener_setup_err[] == Reseau.AWS_OP_SUCCESS
    bound = Sockets.socket_get_bound_address(listener)
    port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_bootstrap = Sockets.ClientBootstrap(Sockets.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    @test Sockets.client_bootstrap_connect!(
        client_bootstrap,
        "127.0.0.1",
        port;
        tls_connection_options = Sockets.TlsConnectionOptions(
            client_ctx;
            server_name = "localhost",
            on_negotiation_result = (handler, slot, err) -> begin
                client_negotiated[] = err == Reseau.AWS_OP_SUCCESS
                return nothing
            end,
        ),
        on_setup = (bs, err, channel, ud) -> begin
            client_setup[] = err == Reseau.AWS_OP_SUCCESS
            client_channel[] = channel
            return nothing
        end,
    ) === nothing

    @test wait_for_flag_tls(server_setup)
    @test wait_for_flag_tls(client_setup)
    @test wait_for_flag_tls(server_negotiated)
    @test wait_for_flag_tls(client_negotiated)

    if server_channel[] !== nothing
        Sockets.pipeline_shutdown!(server_channel[], Reseau.AWS_OP_SUCCESS)
    end
    if client_channel[] !== nothing
        Sockets.pipeline_shutdown!(client_channel[], Reseau.AWS_OP_SUCCESS)
    end

    Sockets.server_bootstrap_shutdown!(server_bootstrap)
    Sockets.host_resolver_shutdown!(resolver)
    EventLoops.event_loop_group_destroy!(elg)

    Reseau.byte_buf_clean_up(Ref(cert_buf))
    Reseau.byte_buf_clean_up(Ref(key_buf))
end

@testset "TLS echo + backpressure" begin
    if Sys.iswindows() || Threads.nthreads(:interactive) <= 1
        @test true
        return
    end

    prev_max = Sockets.g_aws_channel_max_fragment_size[]
    Sockets.g_aws_channel_max_fragment_size[] = 4096

    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(elg)

    server_ctx = _test_server_ctx()
    client_ctx = Sockets.tls_context_new_client(; verify_peer = false)
    @test server_ctx isa Sockets.TlsContext
    @test client_ctx isa Sockets.TlsContext
    if !(server_ctx isa Sockets.TlsContext) || !(client_ctx isa Sockets.TlsContext)
        Sockets.host_resolver_shutdown!(resolver)
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    write_tag = Reseau.byte_buf_from_c_str("I'm a big teapot")
    read_tag = Reseau.byte_buf_from_c_str("I'm a little teapot.")

    client_rw_args = TlsTestRwArgs(; capacity = 256)
    server_rw_args = TlsTestRwArgs(; capacity = 256)

    client_handler_ref = Ref{Any}(nothing)
    server_handler_ref = Ref{Any}(nothing)

    client_ready = Ref(false)
    server_ready = Ref(false)
    listener_setup_called = Ref(false)
    listener_setup_err = Ref(Reseau.AWS_OP_SUCCESS)

    server_bootstrap = Sockets.ServerBootstrap(Sockets.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        enable_read_back_pressure = true,
        tls_connection_options = Sockets.TlsConnectionOptions(server_ctx),
        on_incoming_channel_setup = (bs, err, channel, ud) -> begin
            if err == Reseau.AWS_OP_SUCCESS
                handler = rw_handler_new(
                    tls_test_handle_read,
                    tls_test_handle_write,
                    true,
                    Int(read_tag.len ÷ 2),
                    server_rw_args,
                )
                server_handler_ref[] = handler
                rw_handler_install!(handler, channel)
            end
            server_ready[] = true
            return nothing
        end,
        on_listener_setup = (bs, err, ud) -> begin
            listener_setup_called[] = true
            listener_setup_err[] = err
            return nothing
        end,
    ))

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    @test wait_for_flag_tls(listener_setup_called)
    @test listener_setup_err[] == Reseau.AWS_OP_SUCCESS
    bound = Sockets.socket_get_bound_address(listener)
    @test bound isa Sockets.SocketEndpoint
    port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_bootstrap = Sockets.ClientBootstrap(Sockets.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    client_tls_opts = Sockets.TlsConnectionOptions(
        client_ctx;
        server_name = "localhost",
    )

    connect_res = Sockets.client_bootstrap_connect!(
        client_bootstrap,
        "127.0.0.1",
        port;
        enable_read_back_pressure = true,
        tls_connection_options = client_tls_opts,
        on_setup = (bs, err, channel, ud) -> begin
            if err == Reseau.AWS_OP_SUCCESS
                handler = rw_handler_new(
                    tls_test_handle_read,
                    tls_test_handle_write,
                    true,
                    Int(write_tag.len ÷ 2),
                    client_rw_args,
                )
                client_handler_ref[] = handler
                rw_handler_install!(handler, channel)
            end
            client_ready[] = true
            return nothing
        end,
    )
    @test connect_res === nothing

    @test wait_for_flag_tls(server_ready)
    @test wait_for_flag_tls(client_ready)

    @test client_handler_ref[] isa ReadWriteTestHandler
    @test server_handler_ref[] isa ReadWriteTestHandler

    rw_handler_write(client_handler_ref[], write_tag)
    rw_handler_write(server_handler_ref[], read_tag)

    @test tls_wait_for_read(client_rw_args)
    @test tls_wait_for_read(server_rw_args)

    tls_rw_reset_flag!(client_rw_args)
    tls_rw_reset_flag!(server_rw_args)

    @test client_rw_args.read_invocations == 1
    @test server_rw_args.read_invocations == 1

    rw_handler_trigger_increment_read_window(server_handler_ref[], 100)
    rw_handler_trigger_increment_read_window(client_handler_ref[], 100)

    @test tls_wait_for_read(client_rw_args)
    @test tls_wait_for_read(server_rw_args)

    @test client_rw_args.read_invocations == 2
    @test server_rw_args.read_invocations == 2
    @test _buf_to_string(server_rw_args.received_message) == _buf_to_string(write_tag)
    @test _buf_to_string(client_rw_args.received_message) == _buf_to_string(read_tag)

    Sockets.server_bootstrap_shutdown!(server_bootstrap)
    Sockets.host_resolver_shutdown!(resolver)
    EventLoops.event_loop_group_destroy!(elg)
    Sockets.g_aws_channel_max_fragment_size[] = prev_max
end

@testset "TLS shutdown with cached data" begin
    if Sys.iswindows() || Threads.nthreads(:interactive) <= 1
        @test true
        return
    end

    for window_update_after_shutdown in (false, true)
        prev_max = Sockets.g_aws_channel_max_fragment_size[]
        Sockets.g_aws_channel_max_fragment_size[] = 4096

        elg = EventLoops.EventLoopGroup(; loop_count = 1)
        resolver = Sockets.HostResolver(elg)

        server_ctx = _test_server_ctx()
        client_ctx = Sockets.tls_context_new_client(; verify_peer = false)
        @test server_ctx isa Sockets.TlsContext
        @test client_ctx isa Sockets.TlsContext
        if !(server_ctx isa Sockets.TlsContext) || !(client_ctx isa Sockets.TlsContext)
            Sockets.host_resolver_shutdown!(resolver)
            EventLoops.event_loop_group_destroy!(elg)
            Sockets.g_aws_channel_max_fragment_size[] = prev_max
            continue
        end

        read_tag = Reseau.byte_buf_from_c_str("I'm a little teapot.")

        client_rw_args = TlsTestRwArgs(; capacity = 256)
        server_rw_args = TlsTestRwArgs(; capacity = 256)

        client_handler_ref = Ref{Any}(nothing)
        server_handler_ref = Ref{Any}(nothing)
        client_channel_ref = Ref{Any}(nothing)
        server_channel_ref = Ref{Any}(nothing)

        server_ready = Ref(false)
        client_ready = Ref(false)
        server_shutdown = Ref(false)
        client_shutdown = Ref(false)
        shutdown_invoked = Ref(false)
        listener_setup_called = Ref(false)
        listener_setup_err = Ref(Reseau.AWS_OP_SUCCESS)

        function client_on_read(handler, slot, data_read, user_data)
            args = user_data::TlsTestRwArgs
            if !shutdown_invoked[]
                shutdown_invoked[] = true
                if !window_update_after_shutdown
                    rw_handler_trigger_increment_read_window(client_handler_ref[], 100)
                end
                if server_channel_ref[] !== nothing
                    Sockets.pipeline_shutdown!(server_channel_ref[], Reseau.AWS_OP_SUCCESS)
                end
            end
            lock(args.lock) do
                if data_read !== nothing
                    buf_ref = Ref(args.received_message)
                    Reseau.byte_buf_write_from_whole_buffer(buf_ref, data_read)
                    args.received_message = buf_ref[]
                end
                args.read_invocations += 1
                args.invocation_happened = true
            end
            return args.received_message
        end

        server_bootstrap = Sockets.ServerBootstrap(Sockets.ServerBootstrapOptions(
            event_loop_group = elg,
            host = "127.0.0.1",
            port = 0,
            enable_read_back_pressure = true,
            tls_connection_options = Sockets.TlsConnectionOptions(server_ctx),
            on_incoming_channel_setup = (bs, err, channel, ud) -> begin
                if err == Reseau.AWS_OP_SUCCESS
                    server_channel_ref[] = channel
                    handler = rw_handler_new(
                        tls_test_handle_read,
                        tls_test_handle_write,
                        true,
                        typemax(Int),
                        server_rw_args,
                    )
                    server_handler_ref[] = handler
                    rw_handler_install!(handler, channel)
                end
                server_ready[] = true
                return nothing
            end,
            on_incoming_channel_shutdown = (bs, err, channel, ud) -> begin
                server_shutdown[] = true
                return nothing
            end,
            on_listener_setup = (bs, err, ud) -> begin
                listener_setup_called[] = true
                listener_setup_err[] = err
                return nothing
            end,
        ))

        listener = server_bootstrap.listener_socket
        @test listener !== nothing
        @test wait_for_flag_tls(listener_setup_called)
        @test listener_setup_err[] == Reseau.AWS_OP_SUCCESS
        bound = Sockets.socket_get_bound_address(listener)
        port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
        @test port != 0

        client_bootstrap = Sockets.ClientBootstrap(Sockets.ClientBootstrapOptions(
            event_loop_group = elg,
            host_resolver = resolver,
        ))

        client_tls_opts = Sockets.TlsConnectionOptions(
            client_ctx;
            server_name = "localhost",
        )

        connect_res = Sockets.client_bootstrap_connect!(
            client_bootstrap,
            "127.0.0.1",
            port;
            enable_read_back_pressure = true,
            tls_connection_options = client_tls_opts,
            on_setup = (bs, err, channel, ud) -> begin
                if err == Reseau.AWS_OP_SUCCESS
                    client_channel_ref[] = channel
                    handler = rw_handler_new(
                        client_on_read,
                        tls_test_handle_write,
                        true,
                        Int(read_tag.len ÷ 2),
                        client_rw_args,
                    )
                    client_handler_ref[] = handler
                    rw_handler_install!(handler, channel)
                end
                client_ready[] = true
                return nothing
            end,
            on_shutdown = (bs, err, channel, ud) -> begin
                client_shutdown[] = true
                return nothing
            end,
        )
        @test connect_res === nothing

        @test wait_for_flag_tls(server_ready)
        @test wait_for_flag_tls(client_ready)

        rw_handler_write(server_handler_ref[], read_tag)
        @test tls_wait_for_read(client_rw_args)

        if window_update_after_shutdown
            rw_handler_trigger_increment_read_window(client_handler_ref[], 100)
        end

        @test wait_for_flag_tls(client_shutdown)
        @test client_rw_args.read_invocations == 2
        @test _buf_to_string(client_rw_args.received_message) == _buf_to_string(read_tag)

        Sockets.server_bootstrap_shutdown!(server_bootstrap)
        Sockets.host_resolver_shutdown!(resolver)
        EventLoops.event_loop_group_destroy!(elg)
        Sockets.g_aws_channel_max_fragment_size[] = prev_max
    end
end

if get(ENV, "RESEAU_RUN_NETWORK_TESTS", "0") == "1"
    @testset "TLS network negotiation (requires network)" begin
        disable_verify_peer = opts -> Sockets.tls_ctx_options_set_verify_peer(opts, false)

        set_tls13 = opts -> Sockets.tls_ctx_options_set_minimum_tls_version(opts, Sockets.TlsVersion.TLSv1_3)

        function override_ca_file(path::AbstractString)
            return opts -> Sockets.tls_ctx_options_override_default_trust_store_from_path(opts; ca_file = path)
        end

        @test _tls_network_connect("www.amazon.com", 443) == Reseau.AWS_OP_SUCCESS
        @test _tls_network_connect("ecc256.badssl.com", 443) == Reseau.AWS_OP_SUCCESS
        @test _tls_network_connect("ecc384.badssl.com", 443) == Reseau.AWS_OP_SUCCESS
        if !Sys.isapple()
            @test _tls_network_connect("sha384.badssl.com", 443) == Reseau.AWS_OP_SUCCESS
            @test _tls_network_connect("sha512.badssl.com", 443) == Reseau.AWS_OP_SUCCESS
            @test _tls_network_connect("rsa8192.badssl.com", 443) == Reseau.AWS_OP_SUCCESS
        end

        @test _tls_network_connect("expired.badssl.com", 443) != Reseau.AWS_OP_SUCCESS
        @test _tls_network_connect("wrong.host.badssl.com", 443) != Reseau.AWS_OP_SUCCESS
        @test _tls_network_connect("self-signed.badssl.com", 443) != Reseau.AWS_OP_SUCCESS
        @test _tls_network_connect("untrusted-root.badssl.com", 443) != Reseau.AWS_OP_SUCCESS
        @test _tls_network_connect("rc4.badssl.com", 443) != Reseau.AWS_OP_SUCCESS
        @test _tls_network_connect("rc4-md5.badssl.com", 443) != Reseau.AWS_OP_SUCCESS

        digicert_path = _resource_path("DigiCertGlobalRootCA.crt.pem")
        @test _tls_network_connect(
            "wrong.host.badssl.com",
            443;
            ctx_options_override = override_ca_file(digicert_path),
        ) != Reseau.AWS_OP_SUCCESS

        ca_override_path = _resource_path("ca_root.crt")
        @test _tls_network_connect(
            "www.amazon.com",
            443;
            ctx_options_override = override_ca_file(ca_override_path),
        ) != Reseau.AWS_OP_SUCCESS

        @test _tls_network_connect(
            "www.amazon.com",
            443;
            ctx_options_override = disable_verify_peer,
        ) == Reseau.AWS_OP_SUCCESS
        @test _tls_network_connect(
            "expired.badssl.com",
            443;
            ctx_options_override = disable_verify_peer,
        ) == Reseau.AWS_OP_SUCCESS
        @test _tls_network_connect(
            "wrong.host.badssl.com",
            443;
            ctx_options_override = disable_verify_peer,
        ) == Reseau.AWS_OP_SUCCESS
        @test _tls_network_connect(
            "self-signed.badssl.com",
            443;
            ctx_options_override = disable_verify_peer,
        ) == Reseau.AWS_OP_SUCCESS
        @test _tls_network_connect(
            "untrusted-root.badssl.com",
            443;
            ctx_options_override = disable_verify_peer,
        ) == Reseau.AWS_OP_SUCCESS

        if Sys.isapple()
            @test _tls_network_connect(
                "ecc256.badssl.com",
                443;
                ctx_options_override = set_tls13,
            ) != Reseau.AWS_OP_SUCCESS
        end
    end
else
    @info "Skipping TLS network tests (set RESEAU_RUN_NETWORK_TESTS=1 to enable)"
end
