
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

function wait_for_handshake_status(handler::Sockets.TlsChannelHandler, status; timeout_s::Float64 = 5.0)
    start = Base.time_ns()
    timeout_ns = Int(timeout_s * 1_000_000_000)
    while (Base.time_ns() - start) < timeout_ns
        if Sockets.handler_gather_statistics(handler).handshake_status == status
            return true
        end
        sleep(0.01)
    end
    return false
end

function mark_tls_handler_negotiated!(handler::Sockets.TlsChannelHandler)
    if hasproperty(handler, :state)
        setfield!(handler, :state, Sockets.TlsNegotiationState.SUCCEEDED)
    elseif hasproperty(handler, :negotiation_finished)
        setfield!(handler, :negotiation_finished, true)
    end
    return nothing
end

function mark_tls_handler_failed!(handler::Sockets.TlsChannelHandler)
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
        Sockets.channel_shutdown!(channel_ref[], 0)
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

    channel = Sockets.Channel(event_loop, nothing)
    slot = Sockets.channel_slot_new!(channel)
    conn = Sockets.tls_connection_options_init_from_ctx(ctx)
    try
        res = Sockets.tls_client_handler_new(conn, slot)
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
    new_handler = (options, slot, ud) -> nothing
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
    channel = Sockets.Channel(event_loop, nothing)
    slot = Sockets.channel_slot_new!(channel)
    handler = Sockets.tls_client_handler_new(opts, slot)
    @test handler isa Sockets.TlsChannelHandler
    Sockets.channel_slot_set_handler!(slot, handler)

    handler.stats.handshake_status = Sockets.TlsNegotiationStatus.ONGOING
    Sockets._tls_timeout_task(handler, Reseau.TaskStatus.RUN_READY)

    @test channel.shutdown_pending
    @test channel.shutdown_error_code == EventLoops.ERROR_IO_TLS_NEGOTIATION_TIMEOUT

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

    channel = Sockets.Channel(event_loop, nothing)
    slot = Sockets.channel_slot_new!(channel)
    conn = Sockets.tls_connection_options_init_from_ctx(ctx)
    Sockets.tls_connection_options_set_server_name(conn, "example.com")
    handler = Sockets.tls_client_handler_new(conn, slot)
    @test handler isa Sockets.TlsChannelHandler
    Sockets.channel_slot_set_handler!(slot, handler)

    @test _buf_to_string(Sockets.tls_handler_server_name(handler)) == "example.com"
    @test Sockets.tls_handler_protocol(handler).len == 0

    handler.protocol = Reseau.byte_buf_from_c_str("h2")
    @test _buf_to_string(Sockets.tls_handler_protocol(handler)) == "h2"

    EventLoops.event_loop_group_destroy!(elg)
end

mutable struct EchoHandler
    slot::Union{Sockets.ChannelSlot, Nothing}
    saw_ping::Base.RefValue{Bool}
end

function EchoHandler(flag::Base.RefValue{Bool})
    return EchoHandler(nothing, flag)
end

function Sockets.handler_process_read_message(handler::EchoHandler, slot::Sockets.ChannelSlot, message::Sockets.IoMessage)
    channel = slot.channel
    buf = message.message_data
    payload = String(Reseau.byte_cursor_from_buf(buf))
    if payload == "ping"
        handler.saw_ping[] = true
        resp = Sockets.IoMessage(4)
        resp_ref = Ref(resp.message_data)
        Reseau.byte_buf_write_from_whole_cursor(resp_ref, Reseau.ByteCursor("pong"))
        resp.message_data = resp_ref[]
        Sockets.channel_slot_send_message(slot, resp, Sockets.ChannelDirection.WRITE)
    end
    if channel !== nothing
        Sockets.channel_release_message_to_pool!(channel, message)
    end
    return nothing
end

function Sockets.handler_process_write_message(handler::EchoHandler, slot::Sockets.ChannelSlot, message::Sockets.IoMessage)
    return Sockets.channel_slot_send_message(slot, message, Sockets.ChannelDirection.WRITE)
end

function Sockets.handler_increment_read_window(handler::EchoHandler, slot::Sockets.ChannelSlot, size::Csize_t)
    return Sockets.channel_slot_increment_read_window!(slot, size)
end

function Sockets.handler_shutdown(
        handler::EchoHandler,
        slot::Sockets.ChannelSlot,
        direction::Sockets.ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )
    Sockets.channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    return nothing
end

function Sockets.handler_initial_window_size(handler::EchoHandler)
    return Reseau.SIZE_MAX
end

function Sockets.handler_message_overhead(handler::EchoHandler)
    return Csize_t(0)
end

function Sockets.handler_destroy(handler::EchoHandler)
    return nothing
end

mutable struct SinkHandler <: Sockets.TlsChannelHandler
    slot::Union{Sockets.ChannelSlot, Nothing}
    writes::Base.RefValue{Int}
end

function SinkHandler()
    return SinkHandler(nothing, Ref(0))
end

function Sockets.handler_process_read_message(handler::SinkHandler, slot::Sockets.ChannelSlot, message::Sockets.IoMessage)
    if slot.channel !== nothing
        Sockets.channel_release_message_to_pool!(slot.channel, message)
    end
    return nothing
end

function Sockets.handler_process_write_message(handler::SinkHandler, slot::Sockets.ChannelSlot, message::Sockets.IoMessage)
    handler.writes[] += 1
    if slot.channel !== nothing
        Sockets.channel_release_message_to_pool!(slot.channel, message)
    end
    return nothing
end

function Sockets.handler_increment_read_window(handler::SinkHandler, slot::Sockets.ChannelSlot, size::Csize_t)
    return Sockets.channel_slot_increment_read_window!(slot, size)
end

function Sockets.handler_shutdown(
        handler::SinkHandler,
        slot::Sockets.ChannelSlot,
        direction::Sockets.ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )
    Sockets.channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    return nothing
end

function Sockets.handler_initial_window_size(handler::SinkHandler)
    return Reseau.SIZE_MAX
end

function Sockets.handler_message_overhead(handler::SinkHandler)
    return Csize_t(0)
end

function Sockets.handler_destroy(handler::SinkHandler)
    return nothing
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
    seen_slot = Ref{Any}(nothing)
    seen_new_ud = Ref{Any}(nothing)
    seen_start_ud = Ref{Any}(nothing)
    seen_handler = Ref{Any}(nothing)
    server_new_called = Ref(false)
    server_seen_slot = Ref{Any}(nothing)
    server_seen_ud = Ref{Any}(nothing)
    server_seen_handler = Ref{Any}(nothing)

    new_handler = (options, slot, ud) -> begin
        new_called[] = true
        seen_slot[] = slot
        seen_new_ud[] = ud
        return SinkHandler()
    end
    start_negotiation = (handler, ud) -> begin
        start_called[] = true
        seen_handler[] = handler
        seen_start_ud[] = ud
        return Reseau.AWS_OP_SUCCESS
    end
    server_new_handler = (options, slot, ud) -> begin
        server_new_called[] = true
        server_seen_slot[] = slot
        server_seen_ud[] = ud
        handler = SinkHandler()
        server_seen_handler[] = handler
        return handler
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

    channel = Sockets.Channel(event_loop, nothing)
    left_slot = Sockets.channel_slot_new!(channel)
    sink = SinkHandler()
    Sockets.channel_slot_set_handler!(left_slot, sink)

    tls_opts = Sockets.TlsConnectionOptions(ctx; server_name = "example.com")
    handler = Sockets.channel_setup_client_tls(left_slot, tls_opts)
    @test handler !== nothing
    @test new_called[]
    @test start_called[]
    @test seen_slot[] === left_slot.adj_right
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
            server_channel = Sockets.Channel(event_loop, nothing)
            server_slot = Sockets.channel_slot_new!(server_channel)
            server_handler = Sockets.tls_server_handler_new(
                Sockets.TlsConnectionOptions(server_ctx),
                server_slot,
            )
            @test server_handler !== nothing
            @test server_new_called[]
            @test server_seen_slot[] === server_slot
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

    channel = Sockets.Channel(event_loop, nothing)
    left_slot = Sockets.channel_slot_new!(channel)
    sink = SinkHandler()
    Sockets.channel_slot_set_handler!(left_slot, sink)
    sink.slot = left_slot
    tls_slot = Sockets.channel_slot_new!(channel)
    Sockets.channel_slot_insert_right!(left_slot, tls_slot)

    client_opts = Sockets.TlsConnectionOptions(client_ctx; server_name = "example.com")
    client_handler = Sockets.tls_client_handler_new(client_opts, tls_slot)
    @test client_handler isa Sockets.TlsChannelHandler
    if client_handler isa Sockets.TlsChannelHandler
        client_opts.server_name = "changed"
        @test _buf_to_string(Sockets.tls_handler_server_name(client_handler)) == "example.com"
        @test Sockets.handler_gather_statistics(client_handler).handshake_status == Sockets.TlsNegotiationStatus.NONE
        @test Sockets.tls_client_handler_start_negotiation(client_handler) === nothing
        @test wait_for_handshake_status(client_handler, Sockets.TlsNegotiationStatus.ONGOING)
    end

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
            server_channel = Sockets.Channel(event_loop, nothing)
            server_left = Sockets.channel_slot_new!(server_channel)
            server_sink = SinkHandler()
            Sockets.channel_slot_set_handler!(server_left, server_sink)
            server_sink.slot = server_left
            server_slot = Sockets.channel_slot_new!(server_channel)
            Sockets.channel_slot_insert_right!(server_left, server_slot)

            server_handler = Sockets.tls_server_handler_new(
                Sockets.TlsConnectionOptions(server_ctx),
                server_slot,
            )
            @test server_handler isa Sockets.TlsChannelHandler
            if server_handler isa Sockets.TlsChannelHandler
                @test Sockets.handler_gather_statistics(server_handler).handshake_status == Sockets.TlsNegotiationStatus.NONE
            end

            bad_channel = Sockets.Channel(event_loop, nothing)
            bad_slot = Sockets.channel_slot_new!(bad_channel)
            try
                bad_handler = Sockets.tls_client_handler_new(Sockets.TlsConnectionOptions(server_ctx), bad_slot)
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

@testset "TLS read shutdown ignores data" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Sockets.TlsContext

    channel = Sockets.Channel(event_loop, nothing)
    slot = Sockets.channel_slot_new!(channel)
    saw_data = Ref(false)
    on_data_read = (handler, slot, buf) -> begin
        saw_data[] = true
        return nothing
    end
    opts = Sockets.TlsConnectionOptions(ctx; on_data_read = on_data_read)
    handler = Sockets.tls_client_handler_new(opts, slot)
    @test handler isa Sockets.TlsChannelHandler
    Sockets.channel_slot_set_handler!(slot, handler)
    if hasproperty(handler, :state)
        setfield!(handler, :state, Sockets.TlsNegotiationState.SUCCEEDED)
    elseif hasproperty(handler, :negotiation_finished)
        setfield!(handler, :negotiation_finished, true)
    end

    Sockets.handler_shutdown(handler, slot, Sockets.ChannelDirection.READ, 0, false)

    msg = Sockets.IoMessage(1)
    msg_ref = Ref(msg.message_data)
    Reseau.byte_buf_write_from_whole_cursor(msg_ref, Reseau.ByteCursor(UInt8[0x00]))
    msg.message_data = msg_ref[]
    Sockets.handler_process_read_message(handler, slot, msg)

    @test !saw_data[]
    EventLoops.event_loop_group_destroy!(elg)
end

@testset "TLS shutdown clears pending writes" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Sockets.TlsContext

    channel = Sockets.Channel(event_loop, nothing)
    slot = Sockets.channel_slot_new!(channel)
    handler = Sockets.tls_client_handler_new(Sockets.TlsConnectionOptions(ctx), slot)
    @test handler isa Sockets.TlsChannelHandler
    Sockets.channel_slot_set_handler!(slot, handler)
    mark_tls_handler_negotiated!(handler)

    Sockets.handler_shutdown(handler, slot, Sockets.ChannelDirection.WRITE, 0, false)
    @test channel.channel_state == Sockets.ChannelState.SHUT_DOWN

    EventLoops.event_loop_group_destroy!(elg)
end

@testset "TLS write after failure" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Sockets.TlsContext

    channel = Sockets.Channel(event_loop, nothing)
    slot = Sockets.channel_slot_new!(channel)
    handler = Sockets.tls_client_handler_new(Sockets.TlsConnectionOptions(ctx), slot)
    @test handler isa Sockets.TlsChannelHandler
    Sockets.channel_slot_set_handler!(slot, handler)
    mark_tls_handler_failed!(handler)

    msg = Sockets.IoMessage(1)
    msg_ref = Ref(msg.message_data)
    Reseau.byte_buf_write_from_whole_cursor(msg_ref, Reseau.ByteCursor(UInt8[0x02]))
    msg.message_data = msg_ref[]
    try
        Sockets.handler_process_write_message(handler, slot, msg)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == EventLoops.ERROR_IO_TLS_ERROR_NOT_NEGOTIATED
    end

    EventLoops.event_loop_group_destroy!(elg)
end

@testset "TLS alert handling" begin
    if Sys.isapple() || Sys.islinux()
        @test true
        return
    end

    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Sockets.TlsContext

    function new_alert_handler()
        channel = Sockets.Channel(event_loop, nothing)
        slot = Sockets.channel_slot_new!(channel)
        handler = Sockets.TlsChannelHandler(Sockets.TlsConnectionOptions(ctx))
        handler.negotiation_completed = true
        handler.state = Sockets.TlsHandshakeState.NEGOTIATED
        handler.slot = slot
        Sockets.channel_slot_set_handler!(slot, handler)
        return channel, slot, handler
    end

    function send_alert!(handler::Sockets.TlsChannelHandler, slot::Sockets.ChannelSlot, level::UInt8, desc::UInt8)
        msg = Sockets.IoMessage(2 + Sockets.TLS_RECORD_HEADER_LEN)
        msg_ref = Ref(msg.message_data)
        Reseau.byte_buf_reserve(msg_ref, 2 + Sockets.TLS_RECORD_HEADER_LEN)
        msg.message_data = msg_ref[]
        buf = msg.message_data
        GC.@preserve buf begin
            ptr = pointer(getfield(buf, :mem))
            unsafe_store!(ptr, Sockets.TLS_RECORD_ALERT)
            unsafe_store!(ptr + 1, UInt8(0))
            unsafe_store!(ptr + 2, UInt8(0))
            unsafe_store!(ptr + 3, UInt8(0))
            unsafe_store!(ptr + 4, UInt8(2))
            unsafe_store!(ptr + 5, level)
            unsafe_store!(ptr + 6, desc)
        end
        setfield!(buf, :len, Csize_t(2 + Sockets.TLS_RECORD_HEADER_LEN))
        Sockets.handler_process_read_message(handler, slot, msg)
    end

    channel, slot, handler = new_alert_handler()
    send_alert!(handler, slot, Sockets.TLS_ALERT_LEVEL_WARNING, Sockets.TLS_ALERT_CLOSE_NOTIFY)
    @test channel.shutdown_error_code == EventLoops.ERROR_IO_TLS_CLOSED_GRACEFUL

    channel, slot, handler = new_alert_handler()
    send_alert!(handler, slot, Sockets.TLS_ALERT_LEVEL_FATAL, UInt8(40))
    @test channel.shutdown_error_code == EventLoops.ERROR_IO_TLS_ALERT_NOT_GRACEFUL

    channel, slot, handler = new_alert_handler()
    msg = Sockets.IoMessage(1 + Sockets.TLS_RECORD_HEADER_LEN)
    msg_ref = Ref(msg.message_data)
    Reseau.byte_buf_reserve(msg_ref, 1 + Sockets.TLS_RECORD_HEADER_LEN)
    msg.message_data = msg_ref[]
    buf = msg.message_data
    GC.@preserve buf begin
        ptr = pointer(getfield(buf, :mem))
        unsafe_store!(ptr, Sockets.TLS_RECORD_ALERT)
        unsafe_store!(ptr + 1, UInt8(0))
        unsafe_store!(ptr + 2, UInt8(0))
        unsafe_store!(ptr + 3, UInt8(0))
        unsafe_store!(ptr + 4, UInt8(1))
        unsafe_store!(ptr + 5, UInt8(0))
    end
    setfield!(buf, :len, Csize_t(1 + Sockets.TLS_RECORD_HEADER_LEN))
    Sockets.handler_process_read_message(handler, slot, msg)
    @test channel.shutdown_error_code == EventLoops.ERROR_IO_TLS_ERROR_ALERT_RECEIVED

    EventLoops.event_loop_group_destroy!(elg)
end

@testset "TLS handshake stats" begin
    if Sys.isapple() || Sys.islinux()
        @test true
        return
    end

    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Sockets.TlsContext

    channel = Sockets.Channel(event_loop, nothing)
    left_slot = Sockets.channel_slot_new!(channel)
    left_sink = SinkHandler()
    Sockets.channel_slot_set_handler!(left_slot, left_sink)

    tls_slot = Sockets.channel_slot_new!(channel)
    Sockets.channel_slot_insert_right!(left_slot, tls_slot)
    right_slot = Sockets.channel_slot_new!(channel)
    Sockets.channel_slot_insert_right!(tls_slot, right_slot)
    right_sink = SinkHandler()
    Sockets.channel_slot_set_handler!(right_slot, right_sink)

    handler = Sockets.tls_client_handler_new(Sockets.TlsConnectionOptions(ctx), tls_slot)
    @test handler isa Sockets.TlsChannelHandler
    if handler isa Sockets.TlsChannelHandler
        @test Sockets.tls_client_handler_start_negotiation(handler) === nothing
        @test wait_for_handshake_status(handler, Sockets.TlsNegotiationStatus.ONGOING)
        @test handler.stats.handshake_start_ns > 0

        payload = Memory{UInt8}(undef, Sockets.TLS_NONCE_LEN)
        rand!(payload)
        msg = Sockets.IoMessage(Sockets.TLS_RECORD_HEADER_LEN + Sockets.TLS_NONCE_LEN)
        msg_ref = Ref(msg.message_data)
        Reseau.byte_buf_reserve(msg_ref, Sockets.TLS_RECORD_HEADER_LEN + Sockets.TLS_NONCE_LEN)
        msg.message_data = msg_ref[]
        buf = msg.message_data
        GC.@preserve buf payload begin
            ptr = pointer(getfield(buf, :mem))
            unsafe_store!(ptr, Sockets.TLS_HANDSHAKE_SERVER_HELLO)
            len = UInt32(Sockets.TLS_NONCE_LEN)
            unsafe_store!(ptr + 1, UInt8((len >> 24) & 0xFF))
            unsafe_store!(ptr + 2, UInt8((len >> 16) & 0xFF))
            unsafe_store!(ptr + 3, UInt8((len >> 8) & 0xFF))
            unsafe_store!(ptr + 4, UInt8(len & 0xFF))
            unsafe_copyto!(ptr + Sockets.TLS_RECORD_HEADER_LEN, pointer(payload), Sockets.TLS_NONCE_LEN)
        end
        setfield!(buf, :len, Csize_t(Sockets.TLS_RECORD_HEADER_LEN + Sockets.TLS_NONCE_LEN))
        Sockets.handler_process_read_message(handler, tls_slot, msg)
        @test wait_for_handshake_status(handler, Sockets.TlsNegotiationStatus.SUCCESS)
        @test handler.stats.handshake_end_ns >= handler.stats.handshake_start_ns
    end

    EventLoops.event_loop_group_destroy!(elg)
end

@testset "TLS mTLS custom key op handshake" begin
    if Sys.isapple() || Sys.islinux()
        @test true
        return
    end

    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    called = Ref(false)
    op_ref = Ref{Any}(nothing)
    key_handler = Sockets.CustomKeyOpHandler(
        (handler_obj, operation) -> begin
            @test handler_obj isa Sockets.CustomKeyOpHandler
            @test Sockets.tls_key_operation_get_type(operation) == Sockets.TlsKeyOperationType.SIGN
            @test Sockets.tls_key_operation_get_digest_algorithm(operation) == Sockets.TlsHashAlgorithm.SHA256
            @test Sockets.tls_key_operation_get_signature_algorithm(operation) == Sockets.TlsSignatureAlgorithm.RSA
            called[] = true
            op_ref[] = operation
        end,
    )

    opts = Sockets.tls_ctx_options_init_client_mtls_with_custom_key_operations(
        key_handler,
        Reseau.ByteCursor(TEST_PEM_CERT),
    )
    @test opts isa Sockets.TlsContextOptions

    ctx = Sockets.tls_context_new(opts)
    @test ctx isa Sockets.TlsContext

    channel = Sockets.Channel(event_loop, nothing)
    left_slot = Sockets.channel_slot_new!(channel)
    left_sink = SinkHandler()
    Sockets.channel_slot_set_handler!(left_slot, left_sink)

    tls_slot = Sockets.channel_slot_new!(channel)
    Sockets.channel_slot_insert_right!(left_slot, tls_slot)
    right_slot = Sockets.channel_slot_new!(channel)
    Sockets.channel_slot_insert_right!(tls_slot, right_slot)
    right_sink = SinkHandler()
    Sockets.channel_slot_set_handler!(right_slot, right_sink)

    tls_handler = Sockets.tls_client_handler_new(Sockets.TlsConnectionOptions(ctx), tls_slot)
    @test tls_handler isa Sockets.TlsChannelHandler
    if tls_handler isa Sockets.TlsChannelHandler
        @test Sockets.tls_client_handler_start_negotiation(tls_handler) === nothing
        @test wait_for_handshake_status(tls_handler, Sockets.TlsNegotiationStatus.ONGOING)

        payload = rand(UInt8, Sockets.TLS_NONCE_LEN)
        msg = Sockets.IoMessage(Sockets.TLS_RECORD_HEADER_LEN + Sockets.TLS_NONCE_LEN)
        msg_ref = Ref(msg.message_data)
        Reseau.byte_buf_reserve(msg_ref, Sockets.TLS_RECORD_HEADER_LEN + Sockets.TLS_NONCE_LEN)
        msg.message_data = msg_ref[]
        buf = msg.message_data
        GC.@preserve buf payload begin
            ptr = pointer(getfield(buf, :mem))
            unsafe_store!(ptr, Sockets.TLS_HANDSHAKE_SERVER_HELLO)
            len = UInt32(Sockets.TLS_NONCE_LEN)
            unsafe_store!(ptr + 1, UInt8((len >> 24) & 0xFF))
            unsafe_store!(ptr + 2, UInt8((len >> 16) & 0xFF))
            unsafe_store!(ptr + 3, UInt8((len >> 8) & 0xFF))
            unsafe_store!(ptr + 4, UInt8(len & 0xFF))
            unsafe_copyto!(ptr + Sockets.TLS_RECORD_HEADER_LEN, pointer(payload), Sockets.TLS_NONCE_LEN)
        end
        setfield!(buf, :len, Csize_t(Sockets.TLS_RECORD_HEADER_LEN + Sockets.TLS_NONCE_LEN))
        Sockets.handler_process_read_message(tls_handler, tls_slot, msg)

        @test wait_for_flag_tls(called)
        @test tls_handler.stats.handshake_status == Sockets.TlsNegotiationStatus.ONGOING

        op = op_ref[]
        @test op isa Sockets.TlsKeyOperation
        if op isa Sockets.TlsKeyOperation
            Sockets.tls_key_operation_complete!(op, Reseau.ByteCursor(UInt8[0x01]))
            @test wait_for_handshake_status(tls_handler, Sockets.TlsNegotiationStatus.SUCCESS)
        end
    end

    EventLoops.event_loop_group_destroy!(elg)
end

@testset "tls handler" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    server_opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    server_sock = Sockets.socket_init(server_opts)
    @test server_sock isa Sockets.Socket

    bind_endpoint = Sockets.SocketEndpoint("127.0.0.1", 0)
    @test Sockets.socket_bind(server_sock, Sockets.SocketBindOptions(bind_endpoint)) === nothing
    @test Sockets.socket_listen(server_sock, 16) === nothing

    server_ready = Ref(false)
    accept_started = Ref(false)
    server_negotiated = Ref(false)
    server_received = Ref(false)

    server_ctx = _test_server_ctx()
    @test server_ctx isa Sockets.TlsContext

    on_server_negotiation = (handler, slot, err) -> begin
        _ = handler
        _ = slot
        _ = err
        server_negotiated[] = true
        return nothing
    end

    on_accept = Reseau.ChannelCallable((err, new_sock) -> begin
        if err != Reseau.AWS_OP_SUCCESS
            return nothing
        end
        Sockets.socket_assign_to_event_loop(new_sock, event_loop)
        channel = Sockets.Channel(event_loop, nothing)
        Sockets.socket_channel_handler_new!(channel, new_sock)

        tls_opts = Sockets.TlsConnectionOptions(server_ctx; on_negotiation_result = on_server_negotiation)
        Sockets.tls_channel_handler_new!(channel, tls_opts)

        echo = EchoHandler(server_received)
        echo_slot = Sockets.channel_slot_new!(channel)
        if Sockets.channel_first_slot(channel) !== echo_slot
            Sockets.channel_slot_insert_end!(channel, echo_slot)
        end
        Sockets.channel_slot_set_handler!(echo_slot, echo)
        echo.slot = echo_slot

        Sockets.channel_setup_complete!(channel)
        server_ready[] = true
        return nothing
    end)

    on_accept_start = Reseau.EventCallable(err -> begin
        if err == Reseau.AWS_OP_SUCCESS
            accept_started[] = true
        end
        return nothing
    end)

    listener_opts = Sockets.SocketListenerOptions(; on_accept_start = on_accept_start, on_accept_result = on_accept)
    @test Sockets.socket_start_accept(server_sock, event_loop, listener_opts) === nothing
    @test wait_for_flag_tls(accept_started)

    bound = Sockets.socket_get_bound_address(server_sock)
    @test bound isa Sockets.SocketEndpoint
    port = bound isa Sockets.SocketEndpoint ? bound.port : 0
    @test port > 0

    client_opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    client_sock = Sockets.socket_init(client_opts)
    @test client_sock isa Sockets.Socket

    negotiated = Ref(false)
    read_done = Ref(false)
    read_payload = Ref("")

    on_data_read = (handler, slot, buf) -> begin
        read_payload[] = String(Reseau.byte_cursor_from_buf(buf))
        read_done[] = true
        return nothing
    end

    on_negotiation = (handler, slot, err) -> begin
        negotiated[] = true
        return nothing
    end

    client_ctx = Sockets.tls_context_new_client(; verify_peer = false)
    @test client_ctx isa Sockets.TlsContext

    client_channel_ref = Ref{Any}(nothing)
    client_tls_ref = Ref{Any}(nothing)

    connect_opts = Sockets.SocketConnectOptions(
        Sockets.SocketEndpoint("127.0.0.1", port);
        event_loop = event_loop,
        on_connection_result = Reseau.EventCallable(err -> begin
            if err != Reseau.AWS_OP_SUCCESS
                negotiated[] = true
                return nothing
            end
            channel = Sockets.Channel(event_loop, nothing)
            Sockets.socket_channel_handler_new!(channel, client_sock)
            tls_opts = Sockets.TlsConnectionOptions(
                client_ctx;
                server_name = "localhost",
                on_negotiation_result = on_negotiation,
                on_data_read = on_data_read,
            )
            tls_handler = Sockets.tls_channel_handler_new!(channel, tls_opts)
            if tls_handler isa Sockets.TlsChannelHandler
                client_channel_ref[] = channel
                client_tls_ref[] = tls_handler
                Sockets.tls_client_handler_start_negotiation(tls_handler)
            end
            Sockets.channel_setup_complete!(channel)
            return nothing
        end),
    )

    @test Sockets.socket_connect(client_sock, connect_opts) === nothing

    @test wait_for_flag_tls(server_ready)
    @test wait_for_flag_tls(negotiated)
    @test wait_for_flag_tls(server_negotiated)

    client_channel = client_channel_ref[]
    client_tls = client_tls_ref[]
    if client_channel isa Sockets.Channel && client_tls isa Sockets.TlsChannelHandler
        msg = Sockets.IoMessage(4)
        msg_ref = Ref(msg.message_data)
        Reseau.byte_buf_write_from_whole_cursor(msg_ref, Reseau.ByteCursor("ping"))
        msg.message_data = msg_ref[]

        ping_task = Sockets.ChannelTask()
        send_args = (handler = client_tls, slot = client_tls.slot, message = msg)
        Sockets.channel_task_init!(ping_task, Reseau.EventCallable(status -> begin
            if Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY
                try
                    Sockets.handler_process_write_message(send_args.handler, send_args.slot, send_args.message)
                catch e
                    if send_args.slot.channel !== nothing
                        Sockets.channel_release_message_to_pool!(send_args.slot.channel, send_args.message)
                    end
                end
            end
            nothing
        end), "tls_test_send_ping")
        Sockets.channel_schedule_task_now!(client_channel, ping_task)
    end

    @test wait_for_flag_tls(read_done)
    @test read_payload[] == "pong"
    @test server_received[] == true

    Sockets.socket_close(server_sock)
    Sockets.socket_close(client_sock)
    EventLoops.event_loop_group_destroy!(elg)
end

@testset "channel_setup_client_tls" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Sockets.TlsContext

    channel = Sockets.Channel(event_loop, nothing)
    left_slot = Sockets.channel_slot_new!(channel)
    sink = SinkHandler()
    Sockets.channel_slot_set_handler!(left_slot, sink)
    sink.slot = left_slot

    opts = Sockets.TlsConnectionOptions(ctx; timeout_ms = 1)
    handler = Sockets.channel_setup_client_tls(left_slot, opts)
    @test handler isa Sockets.TlsChannelHandler
    if handler isa Sockets.TlsChannelHandler
        @test left_slot.adj_right === handler.slot
        @test wait_for_handshake_status(handler, Sockets.TlsNegotiationStatus.ONGOING)
    end

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
        Sockets.channel_shutdown!(server_channel[], Reseau.AWS_OP_SUCCESS)
    end
    if client_channel[] !== nothing
        Sockets.channel_shutdown!(client_channel[], Reseau.AWS_OP_SUCCESS)
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
            Sockets.channel_shutdown!(server_channel[], Reseau.AWS_OP_SUCCESS)
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
        Sockets.channel_shutdown!(server_channel[], Reseau.AWS_OP_SUCCESS)
    end
    if client_channel[] !== nothing
        Sockets.channel_shutdown!(client_channel[], Reseau.AWS_OP_SUCCESS)
    end

    Sockets.server_bootstrap_shutdown!(server_bootstrap)
    Sockets.host_resolver_shutdown!(resolver)
    EventLoops.event_loop_group_destroy!(elg)

    Reseau.byte_buf_clean_up(Ref(cert_buf))
    Reseau.byte_buf_clean_up(Ref(key_buf))
end

@testset "TLS handler overhead + max fragment size" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Sockets.TlsContext

    prev_max = Sockets.g_aws_channel_max_fragment_size[]
    Sockets.g_aws_channel_max_fragment_size[] = Csize_t(4096)

    channel = Sockets.Channel(event_loop, nothing)
    tls_slot = Sockets.channel_slot_new!(channel)
    handler = Sockets.tls_client_handler_new(Sockets.TlsConnectionOptions(ctx), tls_slot)
    @test handler isa Sockets.TlsChannelHandler
    handler isa Sockets.TlsChannelHandler && Sockets.channel_slot_set_handler!(tls_slot, handler)

    app_slot = Sockets.channel_slot_new!(channel)
    Sockets.channel_slot_insert_right!(tls_slot, app_slot)
    app_handler = SinkHandler()
    Sockets.channel_slot_set_handler!(app_slot, app_handler)

    results = Channel{Int}(1)
    task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
        Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return nothing
        msg = Sockets.channel_slot_acquire_max_message_for_write(app_slot)
        if msg isa Sockets.IoMessage
            cap = length(msg.message_data.mem)
            Sockets.channel_release_message_to_pool!(channel, msg)
            put!(results, cap)
        else
            put!(results, -1)
        end
        return nothing
    end); type_tag = "tls_overhead_test")
    EventLoops.event_loop_schedule_task_now!(event_loop, task)

    cap = take!(results)
    expected = Int(Sockets.g_aws_channel_max_fragment_size[] - Csize_t(Sockets.TLS_EST_RECORD_OVERHEAD))
    @test cap == expected

    if handler isa Sockets.TlsChannelHandler
        @test Sockets.handler_message_overhead(handler) == Csize_t(Sockets.TLS_EST_RECORD_OVERHEAD)
        @test Sockets.handler_initial_window_size(handler) == Csize_t(Sockets.TLS_EST_HANDSHAKE_SIZE)
    end

    Sockets.g_aws_channel_max_fragment_size[] = prev_max
    EventLoops.event_loop_group_destroy!(elg)
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
    client_slot_ref = Ref{Any}(nothing)
    server_slot_ref = Ref{Any}(nothing)

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
                slot = Sockets.channel_slot_new!(channel)
                if Sockets.channel_first_slot(channel) !== slot
                    Sockets.channel_slot_insert_end!(channel, slot)
                end
                Sockets.channel_slot_set_handler!(slot, handler)
                server_slot_ref[] = slot
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
                slot = Sockets.channel_slot_new!(channel)
                if Sockets.channel_first_slot(channel) !== slot
                    Sockets.channel_slot_insert_end!(channel, slot)
                end
                Sockets.channel_slot_set_handler!(slot, handler)
                client_slot_ref[] = slot
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

    rw_handler_write(client_handler_ref[], client_slot_ref[], write_tag)
    rw_handler_write(server_handler_ref[], server_slot_ref[], read_tag)

    @test tls_wait_for_read(client_rw_args)
    @test tls_wait_for_read(server_rw_args)

    tls_rw_reset_flag!(client_rw_args)
    tls_rw_reset_flag!(server_rw_args)

    @test client_rw_args.read_invocations == 1
    @test server_rw_args.read_invocations == 1

    rw_handler_trigger_increment_read_window(server_handler_ref[], server_slot_ref[], 100)
    rw_handler_trigger_increment_read_window(client_handler_ref[], client_slot_ref[], 100)

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
        client_slot_ref = Ref{Any}(nothing)
        server_slot_ref = Ref{Any}(nothing)
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
                    rw_handler_trigger_increment_read_window(client_handler_ref[], client_slot_ref[], 100)
                end
                if server_channel_ref[] !== nothing
                    Sockets.channel_shutdown!(server_channel_ref[], Reseau.AWS_OP_SUCCESS)
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
                    slot = Sockets.channel_slot_new!(channel)
                    if Sockets.channel_first_slot(channel) !== slot
                        Sockets.channel_slot_insert_end!(channel, slot)
                    end
                    Sockets.channel_slot_set_handler!(slot, handler)
                    server_slot_ref[] = slot
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
                    slot = Sockets.channel_slot_new!(channel)
                    if Sockets.channel_first_slot(channel) !== slot
                        Sockets.channel_slot_insert_end!(channel, slot)
                    end
                    Sockets.channel_slot_set_handler!(slot, handler)
                    client_slot_ref[] = slot
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

        rw_handler_write(server_handler_ref[], server_slot_ref[], read_tag)
        @test tls_wait_for_read(client_rw_args)

        if window_update_after_shutdown
            rw_handler_trigger_increment_read_window(client_handler_ref[], client_slot_ref[], 100)
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

@testset "TLS statistics handler integration" begin
    if Sys.iswindows() || Threads.nthreads(:interactive) <= 1
        @test true
        return
    end

    mutable struct TestTlsStatisticsHandler <: Sockets.StatisticsHandler
        report_ms::UInt64
        results::Channel{Tuple{Sockets.StatisticsSampleInterval, Vector{Any}}}
    end

    Sockets.report_interval_ms(handler::TestTlsStatisticsHandler) = handler.report_ms
    Sockets.close!(::TestTlsStatisticsHandler) = nothing

    function Sockets.process_statistics(
            handler::TestTlsStatisticsHandler,
            interval::Sockets.StatisticsSampleInterval,
            stats_list::AbstractVector,
        )
        stats = Vector{Any}(undef, length(stats_list))
        for i in 1:length(stats_list)
            entry = stats_list[i]
            if entry isa Sockets.SocketHandlerStatistics
                stats[i] = Sockets.SocketHandlerStatistics(entry.category, entry.bytes_read, entry.bytes_written)
            elseif entry isa Sockets.TlsHandlerStatistics
                stats[i] = Sockets.TlsHandlerStatistics(
                    entry.category,
                    entry.handshake_start_ns,
                    entry.handshake_end_ns,
                    entry.handshake_status,
                )
            else
                stats[i] = entry
            end
        end
        put!(handler.results, (interval, stats))
        return nothing
    end

    function wait_for_stats(ch::Channel; timeout_ns::Int = 5_000_000_000)
        deadline = Base.time_ns() + timeout_ns
        while Base.time_ns() < deadline
            isready(ch) && return true
            sleep(0.01)
        end
        return isready(ch)
    end

    mutable struct FakeSocketStatsHandler
        stats::Sockets.SocketHandlerStatistics
    end

    FakeSocketStatsHandler() = FakeSocketStatsHandler(Sockets.SocketHandlerStatistics())

    Sockets.handler_process_read_message(::FakeSocketStatsHandler, ::Sockets.ChannelSlot, ::Sockets.IoMessage) = nothing
    Sockets.handler_process_write_message(::FakeSocketStatsHandler, ::Sockets.ChannelSlot, ::Sockets.IoMessage) = nothing
    Sockets.handler_increment_read_window(::FakeSocketStatsHandler, ::Sockets.ChannelSlot, ::Csize_t) = nothing
    Sockets.handler_initial_window_size(::FakeSocketStatsHandler) = Csize_t(0)
    Sockets.handler_message_overhead(::FakeSocketStatsHandler) = Csize_t(0)
    Sockets.handler_destroy(::FakeSocketStatsHandler) = nothing

    function Sockets.handler_shutdown(
            ::FakeSocketStatsHandler,
            slot::Sockets.ChannelSlot,
            direction::Sockets.ChannelDirection.T,
            error_code::Int,
            free_scarce_resources_immediately::Bool,
        )
        Sockets.channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
        return nothing
    end

    function Sockets.handler_reset_statistics(handler::FakeSocketStatsHandler)::Nothing
        Sockets.crt_statistics_socket_reset!(handler.stats)
        return nothing
    end

    Sockets.handler_gather_statistics(handler::FakeSocketStatsHandler) = handler.stats

    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    event_loop === nothing && return

    channel = Sockets.Channel(event_loop, nothing)

    socket_handler = FakeSocketStatsHandler()
    socket_slot = Sockets.channel_slot_new!(channel)
    Sockets.channel_slot_set_handler!(socket_slot, socket_handler)

    client_ctx = Sockets.tls_context_new_client(; verify_peer = false)
    @test client_ctx isa Sockets.TlsContext
    client_ctx isa Sockets.TlsContext || return
    tls_slot = Sockets.channel_slot_new!(channel)
    tls_handler = Sockets.tls_client_handler_new(Sockets.TlsConnectionOptions(client_ctx), tls_slot)
    @test tls_handler isa Sockets.TlsChannelHandler
    tls_handler isa Sockets.TlsChannelHandler || return
    Sockets.channel_slot_insert_right!(socket_slot, tls_slot)
    Sockets.channel_slot_set_handler!(tls_slot, tls_handler)

    Sockets.channel_setup_complete!(channel)

    stats_results = Channel{Tuple{Sockets.StatisticsSampleInterval, Vector{Any}}}(1)
    stats_handler = TestTlsStatisticsHandler(UInt64(50), stats_results)

    set_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
        Sockets.channel_set_statistics_handler!(channel, stats_handler)
    end); type_tag = "set_tls_stats")
    EventLoops.event_loop_schedule_task_now!(event_loop, set_task)

    update_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
        socket_handler.stats.bytes_read = 111
        socket_handler.stats.bytes_written = 222
        Sockets.handler_gather_statistics(tls_handler).handshake_status = Sockets.TlsNegotiationStatus.SUCCESS
        return nothing
    end); type_tag = "update_tls_stats")
    EventLoops.event_loop_schedule_task_now!(event_loop, update_task)

    @test wait_for_stats(stats_results)
    interval, stats_vec = take!(stats_results)
    @test interval.end_time_ms >= interval.begin_time_ms

    socket_stats = nothing
    tls_stats = nothing
    for entry in stats_vec
        if entry isa Sockets.SocketHandlerStatistics
            socket_stats = entry
        elseif entry isa Sockets.TlsHandlerStatistics
            tls_stats = entry
        end
    end

    @test socket_stats isa Sockets.SocketHandlerStatistics
    @test tls_stats isa Sockets.TlsHandlerStatistics
    if socket_stats isa Sockets.SocketHandlerStatistics
        @test socket_stats.bytes_read > 0
        @test socket_stats.bytes_written > 0
    end
    if tls_stats isa Sockets.TlsHandlerStatistics
        @test tls_stats.handshake_status == Sockets.TlsNegotiationStatus.SUCCESS
    end

    Sockets.channel_shutdown!(channel, Reseau.AWS_OP_SUCCESS)
    EventLoops.event_loop_group_destroy!(elg)
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
