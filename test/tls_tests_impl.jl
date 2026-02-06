
using Test
using Random
using AwsIO
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

function wait_for_handshake_status(handler::AwsIO.TlsChannelHandler, status; timeout_s::Float64 = 5.0)
    start = Base.time_ns()
    timeout_ns = Int(timeout_s * 1_000_000_000)
    while (Base.time_ns() - start) < timeout_ns
        if AwsIO.handler_gather_statistics(handler).handshake_status == status
            return true
        end
        sleep(0.01)
    end
    return false
end

function mark_tls_handler_negotiated!(handler::AwsIO.TlsChannelHandler)
    if hasproperty(handler, :state)
        setfield!(handler, :state, AwsIO.TlsNegotiationState.SUCCEEDED)
    elseif hasproperty(handler, :negotiation_finished)
        setfield!(handler, :negotiation_finished, true)
    end
    return nothing
end

function mark_tls_handler_failed!(handler::AwsIO.TlsChannelHandler)
    if hasproperty(handler, :state)
        setfield!(handler, :state, AwsIO.TlsNegotiationState.FAILED)
    elseif hasproperty(handler, :negotiation_finished)
        setfield!(handler, :negotiation_finished, false)
    end
    return nothing
end

mutable struct TlsTestRwArgs
    lock::ReentrantLock
    invocation_happened::Bool
    read_invocations::Int
    received_message::AwsIO.ByteBuffer
end

function TlsTestRwArgs(; capacity::Integer = 256)
    return TlsTestRwArgs(ReentrantLock(), false, 0, AwsIO.ByteBuffer(capacity))
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
            AwsIO.byte_buf_write_from_whole_buffer(buf_ref, data_read)
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
    return AwsIO.null_buffer()
end

function _buf_to_string(buf::AwsIO.ByteBuffer)
    return String(AwsIO.byte_cursor_from_buf(buf))
end

function _load_resource_buf(name::AbstractString)
    path = _resource_path(name)
    if !isfile(path)
        return nothing
    end
    buf_ref = Ref(AwsIO.ByteBuffer(0))
    AwsIO.byte_buf_init_from_file(buf_ref, path) == AwsIO.AWS_OP_SUCCESS || return nothing
    return buf_ref[]
end

function _tls_network_connect(
        host::AbstractString,
        port::Integer;
        ctx_options_override::Union{Function, Nothing} = nothing,
    )
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    ctx_opts = AwsIO.tls_ctx_options_init_default_client()
    if ctx_options_override !== nothing
        ctx_options_override(ctx_opts)
    end
    ctx = AwsIO.tls_context_new(ctx_opts)
    if ctx isa AwsIO.ErrorResult
        AwsIO.host_resolver_shutdown!(resolver)
        AwsIO.event_loop_group_destroy!(elg)
        return ctx
    end

    setup_err = Ref{Union{Nothing, Int}}(nothing)
    channel_ref = Ref{Any}(nothing)

    tls_conn_opts = AwsIO.TlsConnectionOptions(
        ctx;
        server_name = host,
        on_negotiation_result = (handler, slot, err, ud) -> begin
            _ = handler
            _ = slot
            _ = ud
            return nothing
        end,
    )

    client_bootstrap = AwsIO.ClientBootstrap(AwsIO.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    _ = AwsIO.client_bootstrap_connect!(
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
        AwsIO.channel_shutdown!(channel_ref[], 0)
    end

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)

    return setup_err[]
end

function _test_server_ctx()
    cert_path = _resource_path("unittests.crt")
    key_path = _resource_path("unittests.key")
    opts = AwsIO.tls_ctx_options_init_default_server_from_path(cert_path, key_path)
    maybe_apply_test_keychain!(opts)
    return opts isa AwsIO.TlsContextOptions ? AwsIO.tls_context_new(opts) : opts
end

function _test_client_ctx(; verify_peer::Bool = true)
    opts = AwsIO.tls_ctx_options_init_default_client()
    if verify_peer
        ca_file = _resource_path(Sys.isapple() ? "unittests.crt" : "ca_root.crt")
        res = AwsIO.tls_ctx_options_override_default_trust_store_from_path(opts; ca_file = ca_file)
        res isa AwsIO.ErrorResult && return res
    else
        AwsIO.tls_ctx_options_set_verify_peer(opts, false)
    end
    return AwsIO.tls_context_new(opts)
end

@testset "TLS options parity" begin
    opts = AwsIO.tls_ctx_options_init_default_client()
    @test !opts.is_server
    @test opts.verify_peer

    AwsIO.tls_ctx_options_set_verify_peer(opts, false)
    @test !opts.verify_peer

    AwsIO.tls_ctx_options_set_minimum_tls_version(opts, AwsIO.TlsVersion.TLSv1_2)
    @test opts.minimum_tls_version == AwsIO.TlsVersion.TLSv1_2

    AwsIO.tls_ctx_options_set_tls_cipher_preference(
        opts,
        AwsIO.TlsCipherPref.TLS_CIPHER_PREF_SYSTEM_DEFAULT,
    )
    @test AwsIO.tls_is_cipher_pref_supported(opts.cipher_pref)

    @test AwsIO.tls_ctx_options_override_default_trust_store(
        opts,
        AwsIO.ByteCursor(TEST_PEM_CERT),
    ) === nothing
    @test _buf_to_string(opts.ca_file) == TEST_PEM_CERT

    temp_dir = mktempdir()
    ca_path = joinpath(temp_dir, "ca.pem")
    write(ca_path, TEST_PEM_CERT)
    @test AwsIO.tls_ctx_options_override_default_trust_store_from_path(
        opts;
        ca_path = "/tmp",
        ca_file = ca_path,
    ) isa AwsIO.ErrorResult

    opts2 = AwsIO.tls_ctx_options_init_default_client()
    @test AwsIO.tls_ctx_options_override_default_trust_store_from_path(
        opts2;
        ca_path = "/tmp",
        ca_file = ca_path,
    ) === nothing
    @test opts2.ca_path == "/tmp"
    @test _buf_to_string(opts2.ca_file) == TEST_PEM_CERT

    ctx = AwsIO.tls_context_new(opts)
    @test ctx isa AwsIO.TlsContext

    conn = AwsIO.tls_connection_options_init_from_ctx(ctx)
    @test conn.timeout_ms == 0x00002710
    AwsIO.tls_connection_options_set_server_name(conn, "example.com")
    AwsIO.tls_connection_options_set_alpn_list(conn, "h2")
    AwsIO.tls_connection_options_set_timeout_ms(conn, 250)
    AwsIO.tls_connection_options_set_advertise_alpn_message(conn, true)

    cb1 = (handler, slot, err, ud) -> nothing
    cb2 = (handler, slot, buf, ud) -> nothing
    cb3 = (handler, slot, err, msg, ud) -> nothing
    AwsIO.tls_connection_options_set_callbacks(conn, cb1, cb2, cb3, 123)

    @test conn.server_name == "example.com"
    @test conn.alpn_list == "h2"
    @test conn.timeout_ms == 0x000000fa
    @test conn.advertise_alpn_message
    @test conn.on_negotiation_result === cb1
    @test conn.on_data_read === cb2
    @test conn.on_error === cb3
    @test conn.user_data == 123

    conn_copy = AwsIO.tls_connection_options_copy(conn)
    @test conn_copy.server_name == conn.server_name
    @test conn_copy.alpn_list == conn.alpn_list
    @test conn_copy.timeout_ms == conn.timeout_ms
end

@testset "TLS static state" begin
    AwsIO.tls_init_static_state()
    @test !AwsIO.is_using_secitem()
    AwsIO.tls_clean_up_static_state()
end

@testset "TLS ctx acquire/release" begin
    ctx = _test_client_ctx()
    @test ctx isa AwsIO.TlsContext
    if ctx isa AwsIO.TlsContext
        @test AwsIO.tls_ctx_acquire(ctx) === ctx
        @test AwsIO.tls_ctx_release(ctx) === nothing
    end
    @test AwsIO.tls_ctx_acquire(nothing) === nothing
    @test AwsIO.tls_ctx_release(nothing) === nothing
end

@testset "TLS ctx new helpers" begin
    opts = AwsIO.tls_ctx_options_init_default_client()
    @test AwsIO.tls_ctx_options_override_default_trust_store(opts, AwsIO.ByteCursor(TEST_PEM_CERT)) === nothing
    ctx = AwsIO.tls_client_ctx_new(opts)
    @test ctx isa AwsIO.TlsContext
    if ctx isa AwsIO.TlsContext
        @test !ctx.options.is_server
        @test ctx.options.ca_file.len == opts.ca_file.len
        @test ctx.options.ca_file.mem !== opts.ca_file.mem
    end

    server_ctx = AwsIO.tls_server_ctx_new(opts)
    @test server_ctx isa AwsIO.TlsContext
    if server_ctx isa AwsIO.TlsContext
        @test server_ctx.options.is_server
    end

    srv_opts = AwsIO.tls_ctx_options_init_default_server(
        AwsIO.ByteCursor(TEST_PEM_CERT),
        AwsIO.ByteCursor(TEST_PEM_KEY),
    )
    @test srv_opts isa AwsIO.TlsContextOptions
    if srv_opts isa AwsIO.TlsContextOptions
        client_ctx = AwsIO.tls_client_ctx_new(srv_opts)
        @test client_ctx isa AwsIO.TlsContext
        if client_ctx isa AwsIO.TlsContext
            @test !client_ctx.options.is_server
        end
    end

    bad_opts = AwsIO.tls_ctx_options_init_default_client()
    AwsIO.tls_ctx_options_set_tls_cipher_preference(
        bad_opts,
        AwsIO.TlsCipherPref.TLS_CIPHER_PREF_END_RANGE,
    )
    bad_ctx = AwsIO.tls_client_ctx_new(bad_opts)
    @test bad_ctx isa AwsIO.ErrorResult
    if bad_ctx isa AwsIO.ErrorResult
        @test bad_ctx.code == AwsIO.ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED
    end
end

@testset "TLS error code predicate - comprehensive" begin
    # All 26 TLS error codes must be recognized by the predicate
    tls_errors = [
        AwsIO.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE,
        AwsIO.ERROR_IO_TLS_ERROR_NOT_NEGOTIATED,
        AwsIO.ERROR_IO_TLS_ERROR_WRITE_FAILURE,
        AwsIO.ERROR_IO_TLS_ERROR_ALERT_RECEIVED,
        AwsIO.ERROR_IO_TLS_CTX_ERROR,
        AwsIO.ERROR_IO_TLS_VERSION_UNSUPPORTED,
        AwsIO.ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED,
        AwsIO.ERROR_IO_TLS_NEGOTIATION_TIMEOUT,
        AwsIO.ERROR_IO_TLS_ALERT_NOT_GRACEFUL,
        AwsIO.ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED,
        AwsIO.ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED,
        AwsIO.ERROR_IO_TLS_ERROR_READ_FAILURE,
        AwsIO.ERROR_IO_TLS_UNKNOWN_ROOT_CERTIFICATE,
        AwsIO.ERROR_IO_TLS_NO_ROOT_CERTIFICATE_FOUND,
        AwsIO.ERROR_IO_TLS_CERTIFICATE_EXPIRED,
        AwsIO.ERROR_IO_TLS_CERTIFICATE_NOT_YET_VALID,
        AwsIO.ERROR_IO_TLS_BAD_CERTIFICATE,
        AwsIO.ERROR_IO_TLS_PEER_CERTIFICATE_EXPIRED,
        AwsIO.ERROR_IO_TLS_BAD_PEER_CERTIFICATE,
        AwsIO.ERROR_IO_TLS_PEER_CERTIFICATE_REVOKED,
        AwsIO.ERROR_IO_TLS_PEER_CERTIFICATE_UNKNOWN,
        AwsIO.ERROR_IO_TLS_INTERNAL_ERROR,
        AwsIO.ERROR_IO_TLS_CLOSED_GRACEFUL,
        AwsIO.ERROR_IO_TLS_CLOSED_ABORT,
        AwsIO.ERROR_IO_TLS_INVALID_CERTIFICATE_CHAIN,
        AwsIO.ERROR_IO_TLS_HOST_NAME_MISMATCH,
    ]
    for code in tls_errors
        @test AwsIO.io_error_code_is_tls(code)
    end
    # Non-TLS error codes must not be recognized
    @test !AwsIO.io_error_code_is_tls(AwsIO.ERROR_IO_SOCKET_TIMEOUT)
    @test !AwsIO.io_error_code_is_tls(AwsIO.ERROR_IO_DNS_QUERY_FAILED)
    @test !AwsIO.io_error_code_is_tls(AwsIO.ERROR_IO_EVENT_LOOP_SHUTDOWN)
    @test !AwsIO.io_error_code_is_tls(AwsIO.ERROR_IO_BROKEN_PIPE)
    @test !AwsIO.io_error_code_is_tls(0)
    # DEFAULT_TRUST_STORE_NOT_FOUND is a config error, not classified as TLS
    # (matches aws-c-io aws_error_code_is_tls predicate)
    @test !AwsIO.io_error_code_is_tls(AwsIO.ERROR_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND)
end

@testset "NW socket TLS error translation" begin
    if !Sys.isapple()
        @test true
        return
    end
    # Test that _nw_determine_socket_error maps errSSL* codes to the correct TLS error codes.
    # These mappings match aws-c-io source/darwin/nw_socket.c:s_determine_socket_error()
    errSSL_map = [
        (Int32(-9812), AwsIO.ERROR_IO_TLS_UNKNOWN_ROOT_CERTIFICATE),      # errSSLUnknownRootCert
        (Int32(-9813), AwsIO.ERROR_IO_TLS_NO_ROOT_CERTIFICATE_FOUND),     # errSSLNoRootCert
        (Int32(-9814), AwsIO.ERROR_IO_TLS_CERTIFICATE_EXPIRED),           # errSSLCertExpired
        (Int32(-9815), AwsIO.ERROR_IO_TLS_CERTIFICATE_NOT_YET_VALID),     # errSSLCertNotYetValid
        (Int32(-9824), AwsIO.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE),     # errSSLPeerHandshakeFail
        (Int32(-9808), AwsIO.ERROR_IO_TLS_BAD_CERTIFICATE),              # errSSLBadCert
        (Int32(-9828), AwsIO.ERROR_IO_TLS_PEER_CERTIFICATE_EXPIRED),     # errSSLPeerCertExpired
        (Int32(-9825), AwsIO.ERROR_IO_TLS_BAD_PEER_CERTIFICATE),         # errSSLPeerBadCert
        (Int32(-9827), AwsIO.ERROR_IO_TLS_PEER_CERTIFICATE_REVOKED),     # errSSLPeerCertRevoked
        (Int32(-9829), AwsIO.ERROR_IO_TLS_PEER_CERTIFICATE_UNKNOWN),     # errSSLPeerCertUnknown
        (Int32(-9810), AwsIO.ERROR_IO_TLS_INTERNAL_ERROR),               # errSSLInternal
        (Int32(-9805), AwsIO.ERROR_IO_TLS_CLOSED_GRACEFUL),              # errSSLClosedGraceful
        (Int32(-9806), AwsIO.ERROR_IO_TLS_CLOSED_ABORT),                 # errSSLClosedAbort
        (Int32(-9807), AwsIO.ERROR_IO_TLS_INVALID_CERTIFICATE_CHAIN),    # errSSLXCertChainInvalid
        (Int32(-9843), AwsIO.ERROR_IO_TLS_HOST_NAME_MISMATCH),           # errSSLHostNameMismatch
        (Int32(-67843), AwsIO.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE),   # errSecNotTrusted
        (Int32(-9836), AwsIO.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE),    # errSSLPeerProtocolVersion
    ]
    for (osstatus, expected_error) in errSSL_map
        result = AwsIO._nw_determine_socket_error(Int(osstatus))
        @test result == expected_error
    end
end

@testset "TLS ctx options mtls" begin
    opts = AwsIO.tls_ctx_options_init_client_mtls(
        AwsIO.ByteCursor(TEST_PEM_CERT),
        AwsIO.ByteCursor(TEST_PEM_KEY),
    )
    @test opts isa AwsIO.TlsContextOptions
    if opts isa AwsIO.TlsContextOptions
        @test _buf_to_string(opts.certificate) == TEST_PEM_CERT
        @test _buf_to_string(opts.private_key) == TEST_PEM_KEY
    end

    temp_dir = mktempdir()
    cert_path = joinpath(temp_dir, "cert.pem")
    key_path = joinpath(temp_dir, "key.pem")
    write(cert_path, TEST_PEM_CERT)
    write(key_path, TEST_PEM_KEY)

    opts2 = AwsIO.tls_ctx_options_init_client_mtls_from_path(cert_path, key_path)
    @test opts2 isa AwsIO.TlsContextOptions
    if opts2 isa AwsIO.TlsContextOptions
        @test _buf_to_string(opts2.certificate) == TEST_PEM_CERT
        @test _buf_to_string(opts2.private_key) == TEST_PEM_KEY
    end
end

@testset "TLS ctx options pkcs12" begin
    pkcs_bytes = UInt8[0x01, 0x02, 0x03, 0x04]
    pkcs_pwd = "secret"

    if Sys.isapple()
        opts = AwsIO.tls_ctx_options_init_client_mtls_pkcs12(pkcs_bytes, pkcs_pwd)
        @test opts isa AwsIO.TlsContextOptions
        if opts isa AwsIO.TlsContextOptions
            pkcs_out = Vector{UInt8}(undef, Int(opts.pkcs12.len))
            copyto!(pkcs_out, 1, opts.pkcs12.mem, 1, Int(opts.pkcs12.len))
            @test pkcs_out == pkcs_bytes
            @test _buf_to_string(opts.pkcs12_password) == pkcs_pwd
        end
    else
        @test AwsIO.tls_ctx_options_init_client_mtls_pkcs12(pkcs_bytes, pkcs_pwd) isa AwsIO.ErrorResult
    end
end

@testset "TLS ctx options server init" begin
    opts = AwsIO.tls_ctx_options_init_default_server(
        AwsIO.ByteCursor(TEST_PEM_CERT),
        AwsIO.ByteCursor(TEST_PEM_KEY);
        alpn_list = "h2",
    )
    @test opts isa AwsIO.TlsContextOptions
    if opts isa AwsIO.TlsContextOptions
        @test opts.is_server
        @test !opts.verify_peer
        @test opts.alpn_list == "h2"
    end

    temp_dir = mktempdir()
    cert_path = joinpath(temp_dir, "cert.pem")
    key_path = joinpath(temp_dir, "key.pem")
    write(cert_path, TEST_PEM_CERT)
    write(key_path, TEST_PEM_KEY)

    opts2 = AwsIO.tls_ctx_options_init_default_server_from_path(
        cert_path,
        key_path;
        alpn_list = "h2",
    )
    @test opts2 isa AwsIO.TlsContextOptions
    if opts2 isa AwsIO.TlsContextOptions
        @test opts2.is_server
        @test !opts2.verify_peer
        @test opts2.alpn_list == "h2"
    end
end

@testset "TLS ctx options platform hooks" begin
    opts = AwsIO.tls_ctx_options_init_default_client()
    if Sys.isapple()
        secitem = AwsIO.SecItemOptions("cert", "key")
        if AwsIO.is_using_secitem()
            @test AwsIO.tls_ctx_options_set_keychain_path(opts, "/tmp") isa AwsIO.ErrorResult
            @test AwsIO.tls_ctx_options_set_secitem_options(opts, secitem) === nothing
        else
            @test AwsIO.tls_ctx_options_set_keychain_path(opts, "/tmp") === nothing
            @test AwsIO.tls_ctx_options_set_secitem_options(opts, secitem) isa AwsIO.ErrorResult
        end
    else
        @test AwsIO.tls_ctx_options_set_keychain_path(opts, "/tmp") isa AwsIO.ErrorResult
        secitem = AwsIO.SecItemOptions("cert", "key")
        @test AwsIO.tls_ctx_options_set_secitem_options(opts, secitem) isa AwsIO.ErrorResult
    end
end

@testset "TLS minimum version TLSv1_3 unsupported on macOS" begin
    if !Sys.isapple()
        @test true
        return
    end

    opts = AwsIO.tls_ctx_options_init_default_client()
    AwsIO.tls_ctx_options_set_minimum_tls_version(opts, AwsIO.TlsVersion.TLSv1_3)
    ctx = AwsIO.tls_context_new(opts)
    @test ctx isa AwsIO.TlsContext
    if !(ctx isa AwsIO.TlsContext)
        return
    end

    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    channel = AwsIO.Channel(event_loop, nothing)
    slot = AwsIO.channel_slot_new!(channel)
    conn = AwsIO.tls_connection_options_init_from_ctx(ctx)
    res = AwsIO.tls_client_handler_new(conn, slot)
    @test res isa AwsIO.ErrorResult
    if res isa AwsIO.ErrorResult
        @test res.code == AwsIO.ERROR_IO_TLS_CTX_ERROR
    end

    AwsIO.event_loop_group_destroy!(elg)
end

@testset "TLS ctx options custom key ops" begin
    res = AwsIO.tls_ctx_options_init_client_mtls_with_custom_key_operations(
        nothing,
        AwsIO.ByteCursor(TEST_PEM_CERT),
    )
    @test res isa AwsIO.ErrorResult
    if res isa AwsIO.ErrorResult
        @test res.code == AwsIO.ERROR_INVALID_ARGUMENT
    end
end

@testset "TLS custom key op handler" begin
    op = AwsIO.TlsKeyOperation(AwsIO.ByteCursor(UInt8[0x01]))
    called = Ref(false)
    handler = AwsIO.CustomKeyOpHandler(
        (handler_obj, operation) -> begin
            @test handler_obj.user_data == 7
            @test operation === op
            called[] = true
        end;
        user_data = 7,
    )

    @test AwsIO.custom_key_op_handler_acquire(handler) === handler
    @test AwsIO.custom_key_op_handler_release(handler) === nothing
    AwsIO.custom_key_op_handler_perform_operation(handler, op)
    @test called[]
end

@testset "TLS ctx options custom key ops init" begin
    handler = AwsIO.CustomKeyOpHandler((handler_obj, operation) -> nothing)
    opts = AwsIO.tls_ctx_options_init_client_mtls_with_custom_key_operations(
        handler,
        AwsIO.ByteCursor(TEST_PEM_CERT),
    )
    @test opts isa AwsIO.TlsContextOptions
    if opts isa AwsIO.TlsContextOptions
        @test opts.custom_key_op_handler === handler
        @test _buf_to_string(opts.certificate) == TEST_PEM_CERT
    end

    bad = AwsIO.tls_ctx_options_init_client_mtls_with_custom_key_operations(
        AwsIO.CustomKeyOpHandler(nothing),
        AwsIO.ByteCursor(TEST_PEM_CERT),
    )
    @test bad isa AwsIO.ErrorResult
    if bad isa AwsIO.ErrorResult
        @test bad.code == AwsIO.ERROR_INVALID_ARGUMENT
    end
end

@testset "TLS custom key ops TLSv1_3 unsupported (s2n)" begin
    if !Sys.islinux()
        @test true
        return
    end
    if !AwsIO.tls_is_alpn_available()
        @info "Skipping TLS custom key ops TLSv1_3 test (s2n unavailable)"
        return
    end

    handler = AwsIO.CustomKeyOpHandler((handler_obj, operation) -> nothing)
    opts = AwsIO.tls_ctx_options_init_client_mtls_with_custom_key_operations(
        handler,
        AwsIO.ByteCursor(TEST_PEM_CERT),
    )
    @test opts isa AwsIO.TlsContextOptions
    opts isa AwsIO.ErrorResult && return

    AwsIO.tls_ctx_options_set_minimum_tls_version(opts, AwsIO.TlsVersion.TLSv1_3)
    ctx = AwsIO.tls_context_new(opts)
    @test ctx isa AwsIO.ErrorResult
    if ctx isa AwsIO.ErrorResult
        @test ctx.code == AwsIO.ERROR_IO_TLS_VERSION_UNSUPPORTED
    end
end

@testset "TLS ctx options pkcs11" begin
    opts = AwsIO.TlsCtxPkcs11Options(
        pkcs11_lib = :fake,
        cert_file_path = "cert.pem",
        cert_file_contents = "cert",
    )
    res = AwsIO.tls_ctx_options_init_client_mtls_with_pkcs11(opts)
    @test res isa AwsIO.ErrorResult
    if res isa AwsIO.ErrorResult
        @test res.code == AwsIO.ERROR_INVALID_ARGUMENT
    end

    temp_dir = mktempdir()
    cert_path = joinpath(temp_dir, "cert.pem")
    write(cert_path, TEST_PEM_CERT)

    opts2 = AwsIO.TlsCtxPkcs11Options(
        pkcs11_lib = :fake,
        cert_file_path = cert_path,
    )
    res2 = AwsIO.tls_ctx_options_init_client_mtls_with_pkcs11(opts2)
    @test res2 isa AwsIO.ErrorResult
    if res2 isa AwsIO.ErrorResult
        @test res2.code == AwsIO.ERROR_INVALID_ARGUMENT
    end

    opts3 = AwsIO.TlsCtxPkcs11Options(
        pkcs11_lib = :fake,
        cert_file_contents = TEST_PEM_CERT,
    )
    res3 = AwsIO.tls_ctx_options_init_client_mtls_with_pkcs11(opts3)
    @test res3 isa AwsIO.ErrorResult
    if res3 isa AwsIO.ErrorResult
        @test res3.code == AwsIO.ERROR_INVALID_ARGUMENT
    end
end

@testset "TLS BYO crypto setup" begin
    new_handler = (options, slot, ud) -> nothing
    start_negotiation = (handler, ud) -> 0
    client_opts = AwsIO.TlsByoCryptoSetupOptions(
        new_handler_fn = new_handler,
        start_negotiation_fn = start_negotiation,
        user_data = 7,
    )
    @test AwsIO.tls_byo_crypto_set_client_setup_options(client_opts) === nothing

    server_opts = AwsIO.TlsByoCryptoSetupOptions(
        new_handler_fn = new_handler,
        user_data = 9,
    )
    @test AwsIO.tls_byo_crypto_set_server_setup_options(server_opts) === nothing

    bad_client = AwsIO.TlsByoCryptoSetupOptions(
        new_handler_fn = nothing,
        start_negotiation_fn = nothing,
    )
    res = AwsIO.tls_byo_crypto_set_client_setup_options(bad_client)
    @test res isa AwsIO.ErrorResult
    if res isa AwsIO.ErrorResult
        @test res.code == AwsIO.ERROR_INVALID_ARGUMENT
    end

    AwsIO._tls_byo_client_setup[] = nothing
    AwsIO._tls_byo_server_setup[] = nothing
end

@testset "TLS timeout task" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa AwsIO.TlsContext
    if ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    opts = AwsIO.TlsConnectionOptions(ctx; timeout_ms = 1)
    channel = AwsIO.Channel(event_loop, nothing)
    slot = AwsIO.channel_slot_new!(channel)
    handler = AwsIO.tls_client_handler_new(opts, slot)
    @test handler isa AwsIO.TlsChannelHandler
    if handler isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end
    AwsIO.channel_slot_set_handler!(slot, handler)

    handler.shared.stats.handshake_status = AwsIO.TlsNegotiationStatus.ONGOING
    AwsIO._tls_timeout_task(handler.shared.timeout_task, handler.shared, AwsIO.TaskStatus.RUN_READY)

    @test channel.shutdown_pending
    @test channel.shutdown_error_code == AwsIO.ERROR_IO_TLS_NEGOTIATION_TIMEOUT

    AwsIO.event_loop_group_destroy!(elg)
end

@testset "TLS key operations" begin
    input_bytes = UInt8[0x01, 0x02, 0x03]
    input_cursor = AwsIO.ByteCursor(input_bytes)

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

    operation = AwsIO.TlsKeyOperation(
        input_cursor;
        operation_type = AwsIO.TlsKeyOperationType.SIGN,
        signature_algorithm = AwsIO.TlsSignatureAlgorithm.RSA,
        digest_algorithm = AwsIO.TlsHashAlgorithm.SHA256,
        on_complete = on_complete,
        user_data = 99,
    )

    @test AwsIO.tls_key_operation_get_type(operation) == AwsIO.TlsKeyOperationType.SIGN
    @test AwsIO.tls_key_operation_get_signature_algorithm(operation) == AwsIO.TlsSignatureAlgorithm.RSA
    @test AwsIO.tls_key_operation_get_digest_algorithm(operation) == AwsIO.TlsHashAlgorithm.SHA256
    @test AwsIO.byte_cursor_eq(AwsIO.tls_key_operation_get_input(operation), input_cursor)

    output_cursor = AwsIO.ByteCursor(UInt8[0x0a, 0x0b])
    @test AwsIO.tls_key_operation_complete!(operation, output_cursor) === nothing
    @test operation.completed
    @test operation.error_code == AwsIO.AWS_OP_SUCCESS
    @test cb_called[]
    @test cb_err[] == AwsIO.AWS_OP_SUCCESS
    @test cb_ud[] == 99
    @test cb_op[] === operation
    @test AwsIO.byte_cursor_eq(AwsIO.byte_cursor_from_buf(operation.output), output_cursor)

    cb_called[] = false
    err_operation = AwsIO.TlsKeyOperation(
        input_cursor;
        on_complete = on_complete,
        user_data = 123,
    )
    @test AwsIO.tls_key_operation_complete_with_error!(
        err_operation,
        AwsIO.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE,
    ) === nothing
    @test err_operation.completed
    @test err_operation.error_code == AwsIO.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE
    @test cb_called[]
    @test cb_err[] == AwsIO.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE
    @test cb_ud[] == 123

    @test AwsIO.tls_hash_algorithm_str(AwsIO.TlsHashAlgorithm.SHA384) == "SHA384"
    @test AwsIO.tls_hash_algorithm_str(AwsIO.TlsHashAlgorithm.UNKNOWN) == "UNKNOWN"
    @test AwsIO.tls_signature_algorithm_str(AwsIO.TlsSignatureAlgorithm.ECDSA) == "ECDSA"
    @test AwsIO.tls_signature_algorithm_str(AwsIO.TlsSignatureAlgorithm.UNKNOWN) == "UNKNOWN"
    @test AwsIO.tls_key_operation_type_str(AwsIO.TlsKeyOperationType.SIGN) == "SIGN"
    @test AwsIO.tls_key_operation_type_str(AwsIO.TlsKeyOperationType.UNKNOWN) == "UNKNOWN"
end

@testset "TLS handler accessors" begin
    opts = AwsIO.tls_ctx_options_init_default_client()
    ctx = AwsIO.tls_context_new(opts)
    @test ctx isa AwsIO.TlsContext
    if ctx isa AwsIO.ErrorResult
        return
    end

    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    channel = AwsIO.Channel(event_loop, nothing)
    slot = AwsIO.channel_slot_new!(channel)
    conn = AwsIO.tls_connection_options_init_from_ctx(ctx)
    AwsIO.tls_connection_options_set_server_name(conn, "example.com")
    handler = AwsIO.tls_client_handler_new(conn, slot)
    @test handler isa AwsIO.TlsChannelHandler
    if handler isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end
    AwsIO.channel_slot_set_handler!(slot, handler)

    @test _buf_to_string(AwsIO.tls_handler_server_name(handler)) == "example.com"
    @test AwsIO.tls_handler_protocol(handler).len == 0

    handler.protocol = AwsIO.byte_buf_from_c_str("h2")
    @test _buf_to_string(AwsIO.tls_handler_protocol(handler)) == "h2"

    AwsIO.event_loop_group_destroy!(elg)
end

mutable struct EchoHandler <: AwsIO.AbstractChannelHandler
    slot::Union{AwsIO.ChannelSlot, Nothing}
    saw_ping::Base.RefValue{Bool}
end

function EchoHandler(flag::Base.RefValue{Bool})
    return EchoHandler(nothing, flag)
end

function AwsIO.handler_process_read_message(handler::EchoHandler, slot::AwsIO.ChannelSlot, message::AwsIO.IoMessage)
    channel = slot.channel
    buf = message.message_data
    payload = String(AwsIO.byte_cursor_from_buf(buf))
    if payload == "ping"
        handler.saw_ping[] = true
        resp = AwsIO.IoMessage(4)
        resp_ref = Ref(resp.message_data)
        AwsIO.byte_buf_write_from_whole_cursor(resp_ref, AwsIO.ByteCursor("pong"))
        resp.message_data = resp_ref[]
        AwsIO.channel_slot_send_message(slot, resp, AwsIO.ChannelDirection.WRITE)
    end
    if channel !== nothing
        AwsIO.channel_release_message_to_pool!(channel, message)
    end
    return nothing
end

function AwsIO.handler_process_write_message(handler::EchoHandler, slot::AwsIO.ChannelSlot, message::AwsIO.IoMessage)
    return AwsIO.channel_slot_send_message(slot, message, AwsIO.ChannelDirection.WRITE)
end

function AwsIO.handler_increment_read_window(handler::EchoHandler, slot::AwsIO.ChannelSlot, size::Csize_t)
    return AwsIO.channel_slot_increment_read_window!(slot, size)
end

function AwsIO.handler_shutdown(
        handler::EchoHandler,
        slot::AwsIO.ChannelSlot,
        direction::AwsIO.ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )
    AwsIO.channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    return nothing
end

function AwsIO.handler_initial_window_size(handler::EchoHandler)
    return AwsIO.SIZE_MAX
end

function AwsIO.handler_message_overhead(handler::EchoHandler)
    return Csize_t(0)
end

function AwsIO.handler_destroy(handler::EchoHandler)
    return nothing
end

mutable struct SinkHandler <: AwsIO.TlsChannelHandler
    slot::Union{AwsIO.ChannelSlot, Nothing}
    writes::Base.RefValue{Int}
end

function SinkHandler()
    return SinkHandler(nothing, Ref(0))
end

function AwsIO.handler_process_read_message(handler::SinkHandler, slot::AwsIO.ChannelSlot, message::AwsIO.IoMessage)
    if slot.channel !== nothing
        AwsIO.channel_release_message_to_pool!(slot.channel, message)
    end
    return nothing
end

function AwsIO.handler_process_write_message(handler::SinkHandler, slot::AwsIO.ChannelSlot, message::AwsIO.IoMessage)
    handler.writes[] += 1
    if slot.channel !== nothing
        AwsIO.channel_release_message_to_pool!(slot.channel, message)
    end
    return nothing
end

function AwsIO.handler_increment_read_window(handler::SinkHandler, slot::AwsIO.ChannelSlot, size::Csize_t)
    return AwsIO.channel_slot_increment_read_window!(slot, size)
end

function AwsIO.handler_shutdown(
        handler::SinkHandler,
        slot::AwsIO.ChannelSlot,
        direction::AwsIO.ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )
    AwsIO.channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    return nothing
end

function AwsIO.handler_initial_window_size(handler::SinkHandler)
    return AwsIO.SIZE_MAX
end

function AwsIO.handler_message_overhead(handler::SinkHandler)
    return Csize_t(0)
end

function AwsIO.handler_destroy(handler::SinkHandler)
    return nothing
end

@testset "TLS BYO crypto integration" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa AwsIO.TlsContext
    if ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

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
        return AwsIO.AWS_OP_SUCCESS
    end
    server_new_handler = (options, slot, ud) -> begin
        server_new_called[] = true
        server_seen_slot[] = slot
        server_seen_ud[] = ud
        handler = SinkHandler()
        server_seen_handler[] = handler
        return handler
    end

    client_opts = AwsIO.TlsByoCryptoSetupOptions(
        new_handler_fn = new_handler,
        start_negotiation_fn = start_negotiation,
        user_data = 42,
    )
    @test AwsIO.tls_byo_crypto_set_client_setup_options(client_opts) === nothing

    server_setup = AwsIO.TlsByoCryptoSetupOptions(
        new_handler_fn = server_new_handler,
        user_data = 99,
    )
    @test AwsIO.tls_byo_crypto_set_server_setup_options(server_setup) === nothing

    channel = AwsIO.Channel(event_loop, nothing)
    left_slot = AwsIO.channel_slot_new!(channel)
    sink = SinkHandler()
    AwsIO.channel_slot_set_handler!(left_slot, sink)

    tls_opts = AwsIO.TlsConnectionOptions(ctx; server_name = "example.com")
    handler = AwsIO.channel_setup_client_tls(left_slot, tls_opts)
    @test handler isa AwsIO.AbstractChannelHandler
    @test new_called[]
    @test start_called[]
    @test seen_slot[] === left_slot.adj_right
    @test seen_new_ud[] == 42
    @test seen_start_ud[] == 42
    @test seen_handler[] === handler

    server_opts = AwsIO.tls_ctx_options_init_default_server(
        AwsIO.ByteCursor(TEST_PEM_CERT),
        AwsIO.ByteCursor(TEST_PEM_KEY),
    )
    maybe_apply_test_keychain!(server_opts)
    @test server_opts isa AwsIO.TlsContextOptions
    if server_opts isa AwsIO.TlsContextOptions
        server_ctx = AwsIO.tls_context_new(server_opts)
        @test server_ctx isa AwsIO.TlsContext
        if server_ctx isa AwsIO.TlsContext
            server_channel = AwsIO.Channel(event_loop, nothing)
            server_slot = AwsIO.channel_slot_new!(server_channel)
            server_handler = AwsIO.tls_server_handler_new(
                AwsIO.TlsConnectionOptions(server_ctx),
                server_slot,
            )
            @test server_handler isa AwsIO.AbstractChannelHandler
            @test server_new_called[]
            @test server_seen_slot[] === server_slot
            @test server_seen_ud[] == 99
            @test server_seen_handler[] === server_handler
        end
    end

    AwsIO._tls_byo_client_setup[] = nothing
    AwsIO._tls_byo_server_setup[] = nothing
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "TLS client/server handler API" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    client_ctx = _test_client_ctx()
    @test client_ctx isa AwsIO.TlsContext
    if client_ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    channel = AwsIO.Channel(event_loop, nothing)
    left_slot = AwsIO.channel_slot_new!(channel)
    sink = SinkHandler()
    AwsIO.channel_slot_set_handler!(left_slot, sink)
    sink.slot = left_slot
    tls_slot = AwsIO.channel_slot_new!(channel)
    AwsIO.channel_slot_insert_right!(left_slot, tls_slot)

    client_opts = AwsIO.TlsConnectionOptions(client_ctx; server_name = "example.com")
    client_handler = AwsIO.tls_client_handler_new(client_opts, tls_slot)
    @test client_handler isa AwsIO.TlsChannelHandler
    if client_handler isa AwsIO.TlsChannelHandler
        client_opts.server_name = "changed"
        @test _buf_to_string(AwsIO.tls_handler_server_name(client_handler)) == "example.com"
        @test AwsIO.handler_gather_statistics(client_handler).handshake_status == AwsIO.TlsNegotiationStatus.NONE
        @test AwsIO.tls_client_handler_start_negotiation(client_handler) === nothing
        @test wait_for_handshake_status(client_handler, AwsIO.TlsNegotiationStatus.ONGOING)
    end

    server_opts = AwsIO.tls_ctx_options_init_default_server(
        AwsIO.ByteCursor(TEST_PEM_CERT),
        AwsIO.ByteCursor(TEST_PEM_KEY),
    )
    maybe_apply_test_keychain!(server_opts)
    @test server_opts isa AwsIO.TlsContextOptions
    if server_opts isa AwsIO.TlsContextOptions
        server_ctx = AwsIO.tls_context_new(server_opts)
        @test server_ctx isa AwsIO.TlsContext
        if server_ctx isa AwsIO.TlsContext
            server_channel = AwsIO.Channel(event_loop, nothing)
            server_left = AwsIO.channel_slot_new!(server_channel)
            server_sink = SinkHandler()
            AwsIO.channel_slot_set_handler!(server_left, server_sink)
            server_sink.slot = server_left
            server_slot = AwsIO.channel_slot_new!(server_channel)
            AwsIO.channel_slot_insert_right!(server_left, server_slot)

            server_handler = AwsIO.tls_server_handler_new(
                AwsIO.TlsConnectionOptions(server_ctx),
                server_slot,
            )
            @test server_handler isa AwsIO.TlsChannelHandler
            if server_handler isa AwsIO.TlsChannelHandler
                @test AwsIO.handler_gather_statistics(server_handler).handshake_status == AwsIO.TlsNegotiationStatus.NONE
            end

            bad_channel = AwsIO.Channel(event_loop, nothing)
            bad_slot = AwsIO.channel_slot_new!(bad_channel)
            bad_handler = AwsIO.tls_client_handler_new(AwsIO.TlsConnectionOptions(server_ctx), bad_slot)
            @test bad_handler isa AwsIO.ErrorResult
            if bad_handler isa AwsIO.ErrorResult
                @test bad_handler.code == AwsIO.ERROR_INVALID_ARGUMENT
            end
        end
    end

    @test AwsIO.tls_is_alpn_available()
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "TLS read shutdown ignores data" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa AwsIO.TlsContext
    if ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    channel = AwsIO.Channel(event_loop, nothing)
    slot = AwsIO.channel_slot_new!(channel)
    saw_data = Ref(false)
    on_data_read = (handler, slot, buf, ud) -> begin
        saw_data[] = true
        return nothing
    end
    opts = AwsIO.TlsConnectionOptions(ctx; on_data_read = on_data_read)
    handler = AwsIO.tls_client_handler_new(opts, slot)
    @test handler isa AwsIO.TlsChannelHandler
    if handler isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end
    AwsIO.channel_slot_set_handler!(slot, handler)
    if hasproperty(handler, :state)
        setfield!(handler, :state, AwsIO.TlsNegotiationState.SUCCEEDED)
    elseif hasproperty(handler, :negotiation_finished)
        setfield!(handler, :negotiation_finished, true)
    end

    AwsIO.handler_shutdown(handler, slot, AwsIO.ChannelDirection.READ, 0, false)

    msg = AwsIO.IoMessage(1)
    msg_ref = Ref(msg.message_data)
    AwsIO.byte_buf_write_from_whole_cursor(msg_ref, AwsIO.ByteCursor(UInt8[0x00]))
    msg.message_data = msg_ref[]
    AwsIO.handler_process_read_message(handler, slot, msg)

    @test !saw_data[]
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "TLS shutdown clears pending writes" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa AwsIO.TlsContext
    if ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    channel = AwsIO.Channel(event_loop, nothing)
    slot = AwsIO.channel_slot_new!(channel)
    handler = AwsIO.tls_client_handler_new(AwsIO.TlsConnectionOptions(ctx), slot)
    @test handler isa AwsIO.TlsChannelHandler
    if handler isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end
    AwsIO.channel_slot_set_handler!(slot, handler)
    mark_tls_handler_negotiated!(handler)

    AwsIO.handler_shutdown(handler, slot, AwsIO.ChannelDirection.WRITE, 0, false)
    @test channel.channel_state == AwsIO.ChannelState.SHUT_DOWN

    AwsIO.event_loop_group_destroy!(elg)
end

@testset "TLS write after failure" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa AwsIO.TlsContext
    if ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    channel = AwsIO.Channel(event_loop, nothing)
    slot = AwsIO.channel_slot_new!(channel)
    handler = AwsIO.tls_client_handler_new(AwsIO.TlsConnectionOptions(ctx), slot)
    @test handler isa AwsIO.TlsChannelHandler
    if handler isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end
    AwsIO.channel_slot_set_handler!(slot, handler)
    mark_tls_handler_failed!(handler)

    msg = AwsIO.IoMessage(1)
    msg_ref = Ref(msg.message_data)
    AwsIO.byte_buf_write_from_whole_cursor(msg_ref, AwsIO.ByteCursor(UInt8[0x02]))
    msg.message_data = msg_ref[]
    res = AwsIO.handler_process_write_message(handler, slot, msg)
    @test res isa AwsIO.ErrorResult
    if res isa AwsIO.ErrorResult
        @test res.code == AwsIO.ERROR_IO_TLS_ERROR_NOT_NEGOTIATED
    end

    AwsIO.event_loop_group_destroy!(elg)
end

@testset "TLS alert handling" begin
    if Sys.isapple() || Sys.islinux()
        @test true
        return
    end

    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa AwsIO.TlsContext
    if ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    function new_alert_handler()
        channel = AwsIO.Channel(event_loop, nothing)
        slot = AwsIO.channel_slot_new!(channel)
        handler = AwsIO.TlsChannelHandler(AwsIO.TlsConnectionOptions(ctx))
        handler.negotiation_completed = true
        handler.state = AwsIO.TlsHandshakeState.NEGOTIATED
        handler.slot = slot
        AwsIO.channel_slot_set_handler!(slot, handler)
        return channel, slot, handler
    end

    function send_alert!(handler::AwsIO.TlsChannelHandler, slot::AwsIO.ChannelSlot, level::UInt8, desc::UInt8)
        msg = AwsIO.IoMessage(2 + AwsIO.TLS_RECORD_HEADER_LEN)
        msg_ref = Ref(msg.message_data)
        AwsIO.byte_buf_reserve(msg_ref, 2 + AwsIO.TLS_RECORD_HEADER_LEN)
        msg.message_data = msg_ref[]
        buf = msg.message_data
        GC.@preserve buf begin
            ptr = pointer(getfield(buf, :mem))
            unsafe_store!(ptr, AwsIO.TLS_RECORD_ALERT)
            unsafe_store!(ptr + 1, UInt8(0))
            unsafe_store!(ptr + 2, UInt8(0))
            unsafe_store!(ptr + 3, UInt8(0))
            unsafe_store!(ptr + 4, UInt8(2))
            unsafe_store!(ptr + 5, level)
            unsafe_store!(ptr + 6, desc)
        end
        setfield!(buf, :len, Csize_t(2 + AwsIO.TLS_RECORD_HEADER_LEN))
        AwsIO.handler_process_read_message(handler, slot, msg)
    end

    channel, slot, handler = new_alert_handler()
    send_alert!(handler, slot, AwsIO.TLS_ALERT_LEVEL_WARNING, AwsIO.TLS_ALERT_CLOSE_NOTIFY)
    @test channel.shutdown_error_code == AwsIO.ERROR_IO_TLS_CLOSED_GRACEFUL

    channel, slot, handler = new_alert_handler()
    send_alert!(handler, slot, AwsIO.TLS_ALERT_LEVEL_FATAL, UInt8(40))
    @test channel.shutdown_error_code == AwsIO.ERROR_IO_TLS_ALERT_NOT_GRACEFUL

    channel, slot, handler = new_alert_handler()
    msg = AwsIO.IoMessage(1 + AwsIO.TLS_RECORD_HEADER_LEN)
    msg_ref = Ref(msg.message_data)
    AwsIO.byte_buf_reserve(msg_ref, 1 + AwsIO.TLS_RECORD_HEADER_LEN)
    msg.message_data = msg_ref[]
    buf = msg.message_data
    GC.@preserve buf begin
        ptr = pointer(getfield(buf, :mem))
        unsafe_store!(ptr, AwsIO.TLS_RECORD_ALERT)
        unsafe_store!(ptr + 1, UInt8(0))
        unsafe_store!(ptr + 2, UInt8(0))
        unsafe_store!(ptr + 3, UInt8(0))
        unsafe_store!(ptr + 4, UInt8(1))
        unsafe_store!(ptr + 5, UInt8(0))
    end
    setfield!(buf, :len, Csize_t(1 + AwsIO.TLS_RECORD_HEADER_LEN))
    AwsIO.handler_process_read_message(handler, slot, msg)
    @test channel.shutdown_error_code == AwsIO.ERROR_IO_TLS_ERROR_ALERT_RECEIVED

    AwsIO.event_loop_group_destroy!(elg)
end

@testset "TLS handshake stats" begin
    if Sys.isapple() || Sys.islinux()
        @test true
        return
    end

    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa AwsIO.TlsContext
    if ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    channel = AwsIO.Channel(event_loop, nothing)
    left_slot = AwsIO.channel_slot_new!(channel)
    left_sink = SinkHandler()
    AwsIO.channel_slot_set_handler!(left_slot, left_sink)

    tls_slot = AwsIO.channel_slot_new!(channel)
    AwsIO.channel_slot_insert_right!(left_slot, tls_slot)
    right_slot = AwsIO.channel_slot_new!(channel)
    AwsIO.channel_slot_insert_right!(tls_slot, right_slot)
    right_sink = SinkHandler()
    AwsIO.channel_slot_set_handler!(right_slot, right_sink)

    handler = AwsIO.tls_client_handler_new(AwsIO.TlsConnectionOptions(ctx), tls_slot)
    @test handler isa AwsIO.TlsChannelHandler
    if handler isa AwsIO.TlsChannelHandler
        @test AwsIO.tls_client_handler_start_negotiation(handler) === nothing
        @test wait_for_handshake_status(handler, AwsIO.TlsNegotiationStatus.ONGOING)
        @test handler.stats.handshake_start_ns > 0

        payload = Memory{UInt8}(undef, AwsIO.TLS_NONCE_LEN)
        rand!(payload)
        msg = AwsIO.IoMessage(AwsIO.TLS_RECORD_HEADER_LEN + AwsIO.TLS_NONCE_LEN)
        msg_ref = Ref(msg.message_data)
        AwsIO.byte_buf_reserve(msg_ref, AwsIO.TLS_RECORD_HEADER_LEN + AwsIO.TLS_NONCE_LEN)
        msg.message_data = msg_ref[]
        buf = msg.message_data
        GC.@preserve buf payload begin
            ptr = pointer(getfield(buf, :mem))
            unsafe_store!(ptr, AwsIO.TLS_HANDSHAKE_SERVER_HELLO)
            len = UInt32(AwsIO.TLS_NONCE_LEN)
            unsafe_store!(ptr + 1, UInt8((len >> 24) & 0xFF))
            unsafe_store!(ptr + 2, UInt8((len >> 16) & 0xFF))
            unsafe_store!(ptr + 3, UInt8((len >> 8) & 0xFF))
            unsafe_store!(ptr + 4, UInt8(len & 0xFF))
            unsafe_copyto!(ptr + AwsIO.TLS_RECORD_HEADER_LEN, pointer(payload), AwsIO.TLS_NONCE_LEN)
        end
        setfield!(buf, :len, Csize_t(AwsIO.TLS_RECORD_HEADER_LEN + AwsIO.TLS_NONCE_LEN))
        AwsIO.handler_process_read_message(handler, tls_slot, msg)
        @test wait_for_handshake_status(handler, AwsIO.TlsNegotiationStatus.SUCCESS)
        @test handler.stats.handshake_end_ns >= handler.stats.handshake_start_ns
    end

    AwsIO.event_loop_group_destroy!(elg)
end

@testset "TLS mTLS custom key op handshake" begin
    if Sys.isapple() || Sys.islinux()
        @test true
        return
    end

    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    called = Ref(false)
    op_ref = Ref{Any}(nothing)
    key_handler = AwsIO.CustomKeyOpHandler(
        (handler_obj, operation) -> begin
            @test handler_obj isa AwsIO.CustomKeyOpHandler
            @test AwsIO.tls_key_operation_get_type(operation) == AwsIO.TlsKeyOperationType.SIGN
            @test AwsIO.tls_key_operation_get_digest_algorithm(operation) == AwsIO.TlsHashAlgorithm.SHA256
            @test AwsIO.tls_key_operation_get_signature_algorithm(operation) == AwsIO.TlsSignatureAlgorithm.RSA
            called[] = true
            op_ref[] = operation
        end,
    )

    opts = AwsIO.tls_ctx_options_init_client_mtls_with_custom_key_operations(
        key_handler,
        AwsIO.ByteCursor(TEST_PEM_CERT),
    )
    @test opts isa AwsIO.TlsContextOptions
    if opts isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    ctx = AwsIO.tls_context_new(opts)
    @test ctx isa AwsIO.TlsContext
    if ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    channel = AwsIO.Channel(event_loop, nothing)
    left_slot = AwsIO.channel_slot_new!(channel)
    left_sink = SinkHandler()
    AwsIO.channel_slot_set_handler!(left_slot, left_sink)

    tls_slot = AwsIO.channel_slot_new!(channel)
    AwsIO.channel_slot_insert_right!(left_slot, tls_slot)
    right_slot = AwsIO.channel_slot_new!(channel)
    AwsIO.channel_slot_insert_right!(tls_slot, right_slot)
    right_sink = SinkHandler()
    AwsIO.channel_slot_set_handler!(right_slot, right_sink)

    tls_handler = AwsIO.tls_client_handler_new(AwsIO.TlsConnectionOptions(ctx), tls_slot)
    @test tls_handler isa AwsIO.TlsChannelHandler
    if tls_handler isa AwsIO.TlsChannelHandler
        @test AwsIO.tls_client_handler_start_negotiation(tls_handler) === nothing
        @test wait_for_handshake_status(tls_handler, AwsIO.TlsNegotiationStatus.ONGOING)

        payload = rand(UInt8, AwsIO.TLS_NONCE_LEN)
        msg = AwsIO.IoMessage(AwsIO.TLS_RECORD_HEADER_LEN + AwsIO.TLS_NONCE_LEN)
        msg_ref = Ref(msg.message_data)
        AwsIO.byte_buf_reserve(msg_ref, AwsIO.TLS_RECORD_HEADER_LEN + AwsIO.TLS_NONCE_LEN)
        msg.message_data = msg_ref[]
        buf = msg.message_data
        GC.@preserve buf payload begin
            ptr = pointer(getfield(buf, :mem))
            unsafe_store!(ptr, AwsIO.TLS_HANDSHAKE_SERVER_HELLO)
            len = UInt32(AwsIO.TLS_NONCE_LEN)
            unsafe_store!(ptr + 1, UInt8((len >> 24) & 0xFF))
            unsafe_store!(ptr + 2, UInt8((len >> 16) & 0xFF))
            unsafe_store!(ptr + 3, UInt8((len >> 8) & 0xFF))
            unsafe_store!(ptr + 4, UInt8(len & 0xFF))
            unsafe_copyto!(ptr + AwsIO.TLS_RECORD_HEADER_LEN, pointer(payload), AwsIO.TLS_NONCE_LEN)
        end
        setfield!(buf, :len, Csize_t(AwsIO.TLS_RECORD_HEADER_LEN + AwsIO.TLS_NONCE_LEN))
        AwsIO.handler_process_read_message(tls_handler, tls_slot, msg)

        @test wait_for_flag_tls(called)
        @test tls_handler.stats.handshake_status == AwsIO.TlsNegotiationStatus.ONGOING

        op = op_ref[]
        @test op isa AwsIO.TlsKeyOperation
        if op isa AwsIO.TlsKeyOperation
            AwsIO.tls_key_operation_complete!(op, AwsIO.ByteCursor(UInt8[0x01]))
            @test wait_for_handshake_status(tls_handler, AwsIO.TlsNegotiationStatus.SUCCESS)
        end
    end

    AwsIO.event_loop_group_destroy!(elg)
end

@testset "tls handler" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    server_opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4)
    server_sock = AwsIO.socket_init(server_opts)
    @test server_sock isa AwsIO.Socket
    if server_sock isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    bind_endpoint = AwsIO.SocketEndpoint("127.0.0.1", 0)
    @test AwsIO.socket_bind(server_sock, AwsIO.SocketBindOptions(bind_endpoint)) === nothing
    @test AwsIO.socket_listen(server_sock, 16) === nothing
    bound = AwsIO.socket_get_bound_address(server_sock)
    @test bound isa AwsIO.SocketEndpoint
    port = bound isa AwsIO.SocketEndpoint ? bound.port : 0
    @test port > 0

    server_ready = Ref(false)
    server_negotiated = Ref(false)
    server_received = Ref(false)

    server_ctx = _test_server_ctx()
    @test server_ctx isa AwsIO.TlsContext
    if server_ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    on_server_negotiation = (handler, slot, err, ud) -> begin
        _ = handler
        _ = slot
        _ = err
        _ = ud
        server_negotiated[] = true
        return nothing
    end

    on_accept = (listener, err, new_sock, ud) -> begin
        if err != AwsIO.AWS_OP_SUCCESS
            return nothing
        end
        AwsIO.socket_assign_to_event_loop(new_sock, event_loop)
        channel = AwsIO.Channel(event_loop, nothing)
        AwsIO.socket_channel_handler_new!(channel, new_sock)

        tls_opts = AwsIO.TlsConnectionOptions(server_ctx; on_negotiation_result = on_server_negotiation)
        AwsIO.tls_channel_handler_new!(channel, tls_opts)

        echo = EchoHandler(server_received)
        echo_slot = AwsIO.channel_slot_new!(channel)
        if AwsIO.channel_first_slot(channel) !== echo_slot
            AwsIO.channel_slot_insert_end!(channel, echo_slot)
        end
        AwsIO.channel_slot_set_handler!(echo_slot, echo)
        echo.slot = echo_slot

        AwsIO.channel_setup_complete!(channel)
        server_ready[] = true
        return nothing
    end

    listener_opts = AwsIO.SocketListenerOptions(; on_accept_result = on_accept)
    @test AwsIO.socket_start_accept(server_sock, event_loop, listener_opts) === nothing

    client_opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4)
    client_sock = AwsIO.socket_init(client_opts)
    @test client_sock isa AwsIO.Socket
    if client_sock isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    negotiated = Ref(false)
    read_done = Ref(false)
    read_payload = Ref("")

    on_data_read = (handler, slot, buf, ud) -> begin
        read_payload[] = String(AwsIO.byte_cursor_from_buf(buf))
        read_done[] = true
        return nothing
    end

    on_negotiation = (handler, slot, err, ud) -> begin
        negotiated[] = true
        return nothing
    end

    client_ctx = AwsIO.tls_context_new_client(; verify_peer = false)
    @test client_ctx isa AwsIO.TlsContext
    if client_ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    client_channel_ref = Ref{Any}(nothing)
    client_tls_ref = Ref{Any}(nothing)

    connect_opts = AwsIO.SocketConnectOptions(
        AwsIO.SocketEndpoint("127.0.0.1", port);
        event_loop = event_loop,
        on_connection_result = (sock_obj, err, ud) -> begin
            if err != AwsIO.AWS_OP_SUCCESS
                negotiated[] = true
                return nothing
            end
            channel = AwsIO.Channel(event_loop, nothing)
            AwsIO.socket_channel_handler_new!(channel, sock_obj)
            tls_opts = AwsIO.TlsConnectionOptions(
                client_ctx;
                server_name = "localhost",
                on_negotiation_result = on_negotiation,
                on_data_read = on_data_read,
            )
            tls_handler = AwsIO.tls_channel_handler_new!(channel, tls_opts)
            if tls_handler isa AwsIO.TlsChannelHandler
                client_channel_ref[] = channel
                client_tls_ref[] = tls_handler
                AwsIO.tls_client_handler_start_negotiation(tls_handler)
            end
            AwsIO.channel_setup_complete!(channel)
            return nothing
        end,
    )

    @test AwsIO.socket_connect(client_sock, connect_opts) === nothing

    @test wait_for_flag_tls(server_ready)
    @test wait_for_flag_tls(negotiated)
    @test wait_for_flag_tls(server_negotiated)

    client_channel = client_channel_ref[]
    client_tls = client_tls_ref[]
    if client_channel isa AwsIO.Channel && client_tls isa AwsIO.TlsChannelHandler
        msg = AwsIO.IoMessage(4)
        msg_ref = Ref(msg.message_data)
        AwsIO.byte_buf_write_from_whole_cursor(msg_ref, AwsIO.ByteCursor("ping"))
        msg.message_data = msg_ref[]

        ping_task = AwsIO.ChannelTask()
        send_args = (handler = client_tls, slot = client_tls.slot, message = msg)
        send_fn = (task, args, status) -> begin
            _ = task
            if status == AwsIO.TaskStatus.RUN_READY
                res = AwsIO.handler_process_write_message(args.handler, args.slot, args.message)
                if res isa AwsIO.ErrorResult && args.slot.channel !== nothing
                    AwsIO.channel_release_message_to_pool!(args.slot.channel, args.message)
                end
            end
            return nothing
        end
        AwsIO.channel_task_init!(ping_task, send_fn, send_args, "tls_test_send_ping")
        AwsIO.channel_schedule_task_now!(client_channel, ping_task)
    end

    @test wait_for_flag_tls(read_done)
    @test read_payload[] == "pong"
    @test server_received[] == true

    AwsIO.socket_close(server_sock)
    AwsIO.socket_close(client_sock)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "channel_setup_client_tls" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa AwsIO.TlsContext
    if ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    channel = AwsIO.Channel(event_loop, nothing)
    left_slot = AwsIO.channel_slot_new!(channel)
    sink = SinkHandler()
    AwsIO.channel_slot_set_handler!(left_slot, sink)
    sink.slot = left_slot

    opts = AwsIO.TlsConnectionOptions(ctx; timeout_ms = 1)
    handler = AwsIO.channel_setup_client_tls(left_slot, opts)
    @test handler isa AwsIO.TlsChannelHandler
    if handler isa AwsIO.TlsChannelHandler
        @test left_slot.adj_right === handler.slot
        @test wait_for_handshake_status(handler, AwsIO.TlsNegotiationStatus.ONGOING)
    end

    AwsIO.event_loop_group_destroy!(elg)
end

@testset "TLS concurrent cert import" begin
    temp_dir = mktempdir()
    cert_path = joinpath(temp_dir, "cert.pem")
    key_path = joinpath(temp_dir, "key.pem")
    write(cert_path, TEST_PEM_CERT)
    write(key_path, TEST_PEM_KEY)

    function import_ctx()
        opts = AwsIO.tls_ctx_options_init_client_mtls_from_path(cert_path, key_path)
        opts isa AwsIO.TlsContextOptions || return opts
        maybe_apply_test_keychain!(opts)
        return AwsIO.tls_client_ctx_new(opts)
    end

    tasks = [Threads.@spawn import_ctx() for _ in 1:2]
    ctxs = fetch.(tasks)
    @test all(ctx -> ctx isa AwsIO.TlsContext, ctxs)
    for ctx in ctxs
        if ctx isa AwsIO.TlsContext
            @test AwsIO.tls_ctx_release(ctx) === nothing
        end
    end
end

@testset "TLS duplicate cert import" begin
    opts = AwsIO.tls_ctx_options_init_client_mtls(
        AwsIO.ByteCursor(TEST_PEM_CERT),
        AwsIO.ByteCursor(TEST_PEM_KEY),
    )
    @test opts isa AwsIO.TlsContextOptions
    if opts isa AwsIO.TlsContextOptions
        maybe_apply_test_keychain!(opts)
        ctx1 = AwsIO.tls_client_ctx_new(opts)
        @test ctx1 isa AwsIO.TlsContext
        if ctx1 isa AwsIO.TlsContext
            @test AwsIO.tls_ctx_release(ctx1) === nothing
        end

        maybe_apply_test_keychain!(opts)
        ctx2 = AwsIO.tls_client_ctx_new(opts)
        @test ctx2 isa AwsIO.TlsContext
        if ctx2 isa AwsIO.TlsContext
            @test AwsIO.tls_ctx_release(ctx2) === nothing
        end
    end
end

@testset "TLS pkcs8 import" begin
    cert_buf = _load_resource_buf("unittests.crt")
    key_buf = _load_resource_buf("unittests.p8")
    if cert_buf === nothing || key_buf === nothing
        @test true
    else
        opts = AwsIO.tls_ctx_options_init_client_mtls(
            AwsIO.byte_cursor_from_buf(cert_buf),
            AwsIO.byte_cursor_from_buf(key_buf),
        )
        @test opts isa AwsIO.TlsContextOptions
        if opts isa AwsIO.TlsContextOptions
            maybe_apply_test_keychain!(opts)
            ctx = AwsIO.tls_client_ctx_new(opts)
            @test ctx isa AwsIO.TlsContext
        end
        AwsIO.byte_buf_clean_up(Ref(cert_buf))
        AwsIO.byte_buf_clean_up(Ref(key_buf))
    end
end

@testset "TLS ecc cert import" begin
    cert_buf = _load_resource_buf("ec_unittests.crt")
    key_name = Sys.isapple() ? "ec_unittests.key" : "ec_unittests.p8"
    key_buf = _load_resource_buf(key_name)
    if cert_buf === nothing || key_buf === nothing
        @test true
    else
        opts = AwsIO.tls_ctx_options_init_client_mtls(
            AwsIO.byte_cursor_from_buf(cert_buf),
            AwsIO.byte_cursor_from_buf(key_buf),
        )
        @test opts isa AwsIO.TlsContextOptions
        if opts isa AwsIO.TlsContextOptions
            maybe_apply_test_keychain!(opts)
            ctx = AwsIO.tls_client_ctx_new(opts)
            @test ctx isa AwsIO.TlsContext
        end
        AwsIO.byte_buf_clean_up(Ref(cert_buf))
        AwsIO.byte_buf_clean_up(Ref(key_buf))
    end
end

@testset "TLS cipher preference" begin
    opts = AwsIO.tls_ctx_options_init_default_client()
    AwsIO.tls_ctx_options_set_tls_cipher_preference(
        opts,
        AwsIO.TlsCipherPref.TLS_CIPHER_PREF_TLSV1_2_2025_07,
    )
    ctx = AwsIO.tls_client_ctx_new(opts)
    if AwsIO.tls_is_cipher_pref_supported(opts.cipher_pref)
        @test ctx isa AwsIO.TlsContext
    else
        @test ctx isa AwsIO.ErrorResult
        ctx isa AwsIO.ErrorResult && @test ctx.code == AwsIO.ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED
    end
end

function _tls_local_handshake_with_min_version(min_version::AwsIO.TlsVersion.T)
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    server_opts = AwsIO.tls_ctx_options_init_default_server(
        AwsIO.ByteCursor(TEST_PEM_CERT),
        AwsIO.ByteCursor(TEST_PEM_KEY),
    )
    server_opts isa AwsIO.ErrorResult && return server_opts
    AwsIO.tls_ctx_options_set_minimum_tls_version(server_opts, min_version)
    maybe_apply_test_keychain!(server_opts)
    server_ctx = AwsIO.tls_context_new(server_opts)
    @test server_ctx isa AwsIO.TlsContext
    if server_ctx isa AwsIO.ErrorResult
        AwsIO.host_resolver_shutdown!(resolver)
        AwsIO.event_loop_group_destroy!(elg)
        return server_ctx
    end

    client_opts = AwsIO.tls_ctx_options_init_default_client()
    AwsIO.tls_ctx_options_set_minimum_tls_version(client_opts, min_version)
    res = AwsIO.tls_ctx_options_override_default_trust_store_from_path(
        client_opts;
        ca_file = _resource_path("unittests.crt"),
    )
    res isa AwsIO.ErrorResult && begin
        AwsIO.host_resolver_shutdown!(resolver)
        AwsIO.event_loop_group_destroy!(elg)
        return res
    end
    client_ctx = AwsIO.tls_context_new(client_opts)
    @test client_ctx isa AwsIO.TlsContext
    if client_ctx isa AwsIO.ErrorResult
        AwsIO.host_resolver_shutdown!(resolver)
        AwsIO.event_loop_group_destroy!(elg)
        return client_ctx
    end

    server_setup_called = Ref(false)
    server_setup_err = Ref(AwsIO.AWS_OP_SUCCESS)
    server_shutdown = Ref(false)
    server_channel = Ref{Any}(nothing)
    server_negotiated_called = Ref(false)
    server_negotiated_err = Ref(AwsIO.AWS_OP_SUCCESS)

    server_bootstrap = AwsIO.ServerBootstrap(AwsIO.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        tls_connection_options = AwsIO.TlsConnectionOptions(
            server_ctx;
            on_negotiation_result = (handler, slot, err, ud) -> begin
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
    ))

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    bound = AwsIO.socket_get_bound_address(listener)
    port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_bootstrap = AwsIO.ClientBootstrap(AwsIO.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    client_setup_called = Ref(false)
    client_setup_err = Ref(AwsIO.AWS_OP_SUCCESS)
    client_shutdown = Ref(false)
    client_negotiated_called = Ref(false)
    client_negotiated_err = Ref(AwsIO.AWS_OP_SUCCESS)
    client_channel = Ref{Any}(nothing)

    @test AwsIO.client_bootstrap_connect!(
        client_bootstrap,
        "127.0.0.1",
        port;
        tls_connection_options = AwsIO.TlsConnectionOptions(
            client_ctx;
            server_name = "localhost",
            on_negotiation_result = (handler, slot, err, ud) -> begin
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
    @test server_setup_err[] == AwsIO.AWS_OP_SUCCESS
    @test wait_for_flag_tls(client_setup_called)
    @test client_setup_err[] == AwsIO.AWS_OP_SUCCESS
    @test wait_for_flag_tls(server_negotiated_called)
    @test server_negotiated_err[] == AwsIO.AWS_OP_SUCCESS
    @test wait_for_flag_tls(client_negotiated_called)
    @test client_negotiated_err[] == AwsIO.AWS_OP_SUCCESS

    if server_channel[] !== nothing
        AwsIO.channel_shutdown!(server_channel[], AwsIO.AWS_OP_SUCCESS)
    end
    if client_channel[] !== nothing
        AwsIO.channel_shutdown!(client_channel[], AwsIO.AWS_OP_SUCCESS)
    end

    @test wait_for_flag_tls(server_shutdown)
    @test wait_for_flag_tls(client_shutdown)

    AwsIO.server_bootstrap_shutdown!(server_bootstrap)
    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
    return nothing
end

@testset "TLS minimum version handshake (TLSv1_2)" begin
    _tls_local_handshake_with_min_version(AwsIO.TlsVersion.TLSv1_2)
end

@testset "TLS minimum version handshake (TLSv1_3, linux s2n)" begin
    if !Sys.islinux()
        @test true
        return
    end
    if !AwsIO.tls_is_alpn_available()
        @info "Skipping TLSv1_3 handshake test (s2n unavailable)"
        return
    end
    _tls_local_handshake_with_min_version(AwsIO.TlsVersion.TLSv1_3)
end

@testset "TLS server multiple connections" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    server_opts = AwsIO.tls_ctx_options_init_default_server(
        AwsIO.ByteCursor(TEST_PEM_CERT),
        AwsIO.ByteCursor(TEST_PEM_KEY),
    )
    maybe_apply_test_keychain!(server_opts)
    server_ctx = AwsIO.tls_context_new(server_opts)
    @test server_ctx isa AwsIO.TlsContext
    if server_ctx isa AwsIO.ErrorResult
        AwsIO.host_resolver_shutdown!(resolver)
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    client_ctx = _test_client_ctx()
    @test client_ctx isa AwsIO.TlsContext
    if client_ctx isa AwsIO.ErrorResult
        AwsIO.host_resolver_shutdown!(resolver)
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    server_setup_called = Ref(false)
    server_setup_err = Ref(AwsIO.AWS_OP_SUCCESS)
    server_shutdown = Ref(false)
    server_channel = Ref{Any}(nothing)
    server_negotiated_called = Ref(false)
    server_negotiated_err = Ref(AwsIO.AWS_OP_SUCCESS)

    server_bootstrap = AwsIO.ServerBootstrap(AwsIO.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        tls_connection_options = AwsIO.TlsConnectionOptions(
            server_ctx;
            on_negotiation_result = (handler, slot, err, ud) -> begin
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
    ))

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    bound = AwsIO.socket_get_bound_address(listener)
    port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_bootstrap = AwsIO.ClientBootstrap(AwsIO.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    function connect_once!()
        server_setup_called[] = false
        server_setup_err[] = AwsIO.AWS_OP_SUCCESS
        server_shutdown[] = false
        server_channel[] = nothing
        server_negotiated_called[] = false
        server_negotiated_err[] = AwsIO.AWS_OP_SUCCESS

        client_setup_called = Ref(false)
        client_setup_err = Ref(AwsIO.AWS_OP_SUCCESS)
        client_shutdown = Ref(false)
        client_negotiated_called = Ref(false)
        client_negotiated_err = Ref(AwsIO.AWS_OP_SUCCESS)
        client_channel = Ref{Any}(nothing)

        @test AwsIO.client_bootstrap_connect!(
            client_bootstrap,
            "127.0.0.1",
            port;
            tls_connection_options = AwsIO.TlsConnectionOptions(
                client_ctx;
                server_name = "localhost",
                on_negotiation_result = (handler, slot, err, ud) -> begin
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
        @test server_setup_err[] == AwsIO.AWS_OP_SUCCESS
        @test wait_for_flag_tls(client_setup_called)
        @test client_setup_err[] == AwsIO.AWS_OP_SUCCESS
        @test wait_for_flag_tls(server_negotiated_called)
        @test server_negotiated_err[] == AwsIO.AWS_OP_SUCCESS
        @test wait_for_flag_tls(client_negotiated_called)
        @test client_negotiated_err[] == AwsIO.AWS_OP_SUCCESS

        if server_channel[] !== nothing
            AwsIO.channel_shutdown!(server_channel[], AwsIO.AWS_OP_SUCCESS)
        end

        @test wait_for_flag_tls(server_shutdown)
        @test wait_for_flag_tls(client_shutdown)
    end

    connect_once!()
    connect_once!()

    AwsIO.server_bootstrap_shutdown!(server_bootstrap)
    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "TLS server hangup during negotiation" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    server_opts = AwsIO.tls_ctx_options_init_default_server(
        AwsIO.ByteCursor(TEST_PEM_CERT),
        AwsIO.ByteCursor(TEST_PEM_KEY),
    )
    maybe_apply_test_keychain!(server_opts)
    server_ctx = AwsIO.tls_context_new(server_opts)
    @test server_ctx isa AwsIO.TlsContext
    if server_ctx isa AwsIO.ErrorResult
        AwsIO.host_resolver_shutdown!(resolver)
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    listener_destroyed = Ref(false)
    server_bootstrap = AwsIO.ServerBootstrap(AwsIO.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        tls_connection_options = AwsIO.TlsConnectionOptions(server_ctx),
        on_listener_destroy = (bs, ud) -> begin
            listener_destroyed[] = true
            return nothing
        end,
    ))

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    bound = AwsIO.socket_get_bound_address(listener)
    port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4)
    client_socket = AwsIO.socket_init(client_opts)
    @test client_socket isa AwsIO.Socket
    if client_socket isa AwsIO.ErrorResult
        AwsIO.server_bootstrap_shutdown!(server_bootstrap)
        AwsIO.host_resolver_shutdown!(resolver)
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    close_done = Ref(false)
    connect_opts = AwsIO.SocketConnectOptions(
        AwsIO.SocketEndpoint("127.0.0.1", port);
        event_loop = AwsIO.event_loop_group_get_next_loop(elg),
        on_connection_result = (sock, err, ud) -> begin
            if err != AwsIO.AWS_OP_SUCCESS
                close_done[] = true
                return nothing
            end
            now = AwsIO.event_loop_current_clock_time(sock.event_loop)
            if now isa AwsIO.ErrorResult
                close_done[] = true
                return nothing
            end
            task = AwsIO.ScheduledTask((ctx, status) -> begin
                status == AwsIO.TaskStatus.RUN_READY || return nothing
                AwsIO.socket_close(ctx)
                close_done[] = true
                return nothing
            end, sock; type_tag = "close_client_socket")
            AwsIO.event_loop_schedule_task_future!(sock.event_loop, task, now + UInt64(1_000_000_000))
            return nothing
        end,
    )

    @test AwsIO.socket_connect(client_socket, connect_opts) === nothing
    @test wait_for_flag_tls(close_done)

    AwsIO.server_bootstrap_shutdown!(server_bootstrap)
    @test wait_for_flag_tls(listener_destroyed)

    AwsIO.socket_close(client_socket)
    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "TLS certificate chain" begin
    cert_buf = _load_resource_buf("server_chain.crt")
    key_buf = _load_resource_buf("server.key")
    if cert_buf === nothing || key_buf === nothing
        @test true
        return
    end

    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    server_opts = if Sys.isapple()
        AwsIO.tls_ctx_options_init_server_pkcs12_from_path(_resource_path("unittests.p12"), "1234")
    else
        AwsIO.tls_ctx_options_init_default_server(
            AwsIO.byte_cursor_from_buf(cert_buf),
            AwsIO.byte_cursor_from_buf(key_buf),
        )
    end
    maybe_apply_test_keychain!(server_opts)
    server_ctx = AwsIO.tls_context_new(server_opts)
    @test server_ctx isa AwsIO.TlsContext
    if server_ctx isa AwsIO.ErrorResult
        AwsIO.host_resolver_shutdown!(resolver)
        AwsIO.event_loop_group_destroy!(elg)
        AwsIO.byte_buf_clean_up(Ref(cert_buf))
        AwsIO.byte_buf_clean_up(Ref(key_buf))
        return
    end

    client_ctx = _test_client_ctx()
    @test client_ctx isa AwsIO.TlsContext
    if client_ctx isa AwsIO.ErrorResult
        AwsIO.host_resolver_shutdown!(resolver)
        AwsIO.event_loop_group_destroy!(elg)
        AwsIO.byte_buf_clean_up(Ref(cert_buf))
        AwsIO.byte_buf_clean_up(Ref(key_buf))
        return
    end

    server_setup = Ref(false)
    client_setup = Ref(false)
    server_negotiated = Ref(false)
    client_negotiated = Ref(false)
    server_channel = Ref{Any}(nothing)
    client_channel = Ref{Any}(nothing)

    server_bootstrap = AwsIO.ServerBootstrap(AwsIO.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        tls_connection_options = AwsIO.TlsConnectionOptions(
            server_ctx;
            on_negotiation_result = (handler, slot, err, ud) -> begin
                server_negotiated[] = err == AwsIO.AWS_OP_SUCCESS
                return nothing
            end,
        ),
        on_incoming_channel_setup = (bs, err, channel, ud) -> begin
            server_setup[] = err == AwsIO.AWS_OP_SUCCESS
            server_channel[] = channel
            return nothing
        end,
    ))

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    bound = AwsIO.socket_get_bound_address(listener)
    port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_bootstrap = AwsIO.ClientBootstrap(AwsIO.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    @test AwsIO.client_bootstrap_connect!(
        client_bootstrap,
        "127.0.0.1",
        port;
        tls_connection_options = AwsIO.TlsConnectionOptions(
            client_ctx;
            server_name = "localhost",
            on_negotiation_result = (handler, slot, err, ud) -> begin
                client_negotiated[] = err == AwsIO.AWS_OP_SUCCESS
                return nothing
            end,
        ),
        on_setup = (bs, err, channel, ud) -> begin
            client_setup[] = err == AwsIO.AWS_OP_SUCCESS
            client_channel[] = channel
            return nothing
        end,
    ) === nothing

    @test wait_for_flag_tls(server_setup)
    @test wait_for_flag_tls(client_setup)
    @test wait_for_flag_tls(server_negotiated)
    @test wait_for_flag_tls(client_negotiated)

    if server_channel[] !== nothing
        AwsIO.channel_shutdown!(server_channel[], AwsIO.AWS_OP_SUCCESS)
    end
    if client_channel[] !== nothing
        AwsIO.channel_shutdown!(client_channel[], AwsIO.AWS_OP_SUCCESS)
    end

    AwsIO.server_bootstrap_shutdown!(server_bootstrap)
    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)

    AwsIO.byte_buf_clean_up(Ref(cert_buf))
    AwsIO.byte_buf_clean_up(Ref(key_buf))
end

@testset "TLS handler overhead + max fragment size" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa AwsIO.TlsContext
    if ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    prev_max = AwsIO.g_aws_channel_max_fragment_size[]
    AwsIO.g_aws_channel_max_fragment_size[] = Csize_t(4096)

    channel = AwsIO.Channel(event_loop, nothing)
    tls_slot = AwsIO.channel_slot_new!(channel)
    handler = AwsIO.tls_client_handler_new(AwsIO.TlsConnectionOptions(ctx), tls_slot)
    @test handler isa AwsIO.TlsChannelHandler
    handler isa AwsIO.TlsChannelHandler && AwsIO.channel_slot_set_handler!(tls_slot, handler)

    app_slot = AwsIO.channel_slot_new!(channel)
    AwsIO.channel_slot_insert_right!(tls_slot, app_slot)
    app_handler = SinkHandler()
    AwsIO.channel_slot_set_handler!(app_slot, app_handler)

    results = Channel{Int}(1)
    task = AwsIO.ScheduledTask(
        (ctx, status) -> begin
            status == AwsIO.TaskStatus.RUN_READY || return nothing
            msg = AwsIO.channel_slot_acquire_max_message_for_write(ctx.slot)
            if msg isa AwsIO.IoMessage
                cap = length(msg.message_data.mem)
                AwsIO.channel_release_message_to_pool!(ctx.channel, msg)
                put!(ctx.results, cap)
            else
                put!(ctx.results, -1)
            end
            return nothing
        end,
        (slot = app_slot, channel = channel, results = results);
        type_tag = "tls_overhead_test",
    )
    AwsIO.event_loop_schedule_task_now!(event_loop, task)

    cap = take!(results)
    expected = Int(AwsIO.g_aws_channel_max_fragment_size[] - Csize_t(AwsIO.TLS_EST_RECORD_OVERHEAD))
    @test cap == expected

    if handler isa AwsIO.TlsChannelHandler
        @test AwsIO.handler_message_overhead(handler) == Csize_t(AwsIO.TLS_EST_RECORD_OVERHEAD)
        @test AwsIO.handler_initial_window_size(handler) == Csize_t(AwsIO.TLS_EST_HANDSHAKE_SIZE)
    end

    AwsIO.g_aws_channel_max_fragment_size[] = prev_max
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "TLS echo + backpressure" begin
    if Sys.iswindows() || Threads.nthreads(:interactive) <= 1
        @test true
        return
    end

    prev_max = AwsIO.g_aws_channel_max_fragment_size[]
    AwsIO.g_aws_channel_max_fragment_size[] = 4096

    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    server_ctx = _test_server_ctx()
    client_ctx = AwsIO.tls_context_new_client(; verify_peer = false)
    @test server_ctx isa AwsIO.TlsContext
    @test client_ctx isa AwsIO.TlsContext
    if !(server_ctx isa AwsIO.TlsContext) || !(client_ctx isa AwsIO.TlsContext)
        AwsIO.host_resolver_shutdown!(resolver)
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    write_tag = AwsIO.byte_buf_from_c_str("I'm a big teapot")
    read_tag = AwsIO.byte_buf_from_c_str("I'm a little teapot.")

    client_rw_args = TlsTestRwArgs(; capacity = 256)
    server_rw_args = TlsTestRwArgs(; capacity = 256)

    client_handler_ref = Ref{Any}(nothing)
    server_handler_ref = Ref{Any}(nothing)
    client_slot_ref = Ref{Any}(nothing)
    server_slot_ref = Ref{Any}(nothing)

    client_ready = Ref(false)
    server_ready = Ref(false)

    server_bootstrap = AwsIO.ServerBootstrap(AwsIO.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        enable_read_back_pressure = true,
        tls_connection_options = AwsIO.TlsConnectionOptions(server_ctx),
        on_incoming_channel_setup = (bs, err, channel, ud) -> begin
            if err == AwsIO.AWS_OP_SUCCESS
                handler = rw_handler_new(
                    tls_test_handle_read,
                    tls_test_handle_write,
                    true,
                    Int(read_tag.len ÷ 2),
                    server_rw_args,
                )
                server_handler_ref[] = handler
                slot = AwsIO.channel_slot_new!(channel)
                if AwsIO.channel_first_slot(channel) !== slot
                    AwsIO.channel_slot_insert_end!(channel, slot)
                end
                AwsIO.channel_slot_set_handler!(slot, handler)
                server_slot_ref[] = slot
            end
            server_ready[] = true
            return nothing
        end,
    ))

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    bound = AwsIO.socket_get_bound_address(listener)
    @test bound isa AwsIO.SocketEndpoint
    port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_bootstrap = AwsIO.ClientBootstrap(AwsIO.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    client_tls_opts = AwsIO.TlsConnectionOptions(
        client_ctx;
        server_name = "localhost",
    )

    connect_res = AwsIO.client_bootstrap_connect!(
        client_bootstrap,
        "127.0.0.1",
        port;
        enable_read_back_pressure = true,
        tls_connection_options = client_tls_opts,
        on_setup = (bs, err, channel, ud) -> begin
            if err == AwsIO.AWS_OP_SUCCESS
                handler = rw_handler_new(
                    tls_test_handle_read,
                    tls_test_handle_write,
                    true,
                    Int(write_tag.len ÷ 2),
                    client_rw_args,
                )
                client_handler_ref[] = handler
                slot = AwsIO.channel_slot_new!(channel)
                if AwsIO.channel_first_slot(channel) !== slot
                    AwsIO.channel_slot_insert_end!(channel, slot)
                end
                AwsIO.channel_slot_set_handler!(slot, handler)
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

    AwsIO.server_bootstrap_shutdown!(server_bootstrap)
    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
    AwsIO.g_aws_channel_max_fragment_size[] = prev_max
end

@testset "TLS shutdown with cached data" begin
    if Sys.iswindows() || Threads.nthreads(:interactive) <= 1
        @test true
        return
    end

    for window_update_after_shutdown in (false, true)
        prev_max = AwsIO.g_aws_channel_max_fragment_size[]
        AwsIO.g_aws_channel_max_fragment_size[] = 4096

        elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
        resolver = AwsIO.DefaultHostResolver(elg)

        server_ctx = _test_server_ctx()
        client_ctx = AwsIO.tls_context_new_client(; verify_peer = false)
        @test server_ctx isa AwsIO.TlsContext
        @test client_ctx isa AwsIO.TlsContext
        if !(server_ctx isa AwsIO.TlsContext) || !(client_ctx isa AwsIO.TlsContext)
            AwsIO.host_resolver_shutdown!(resolver)
            AwsIO.event_loop_group_destroy!(elg)
            AwsIO.g_aws_channel_max_fragment_size[] = prev_max
            continue
        end

        read_tag = AwsIO.byte_buf_from_c_str("I'm a little teapot.")

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

        function client_on_read(handler, slot, data_read, user_data)
            args = user_data::TlsTestRwArgs
            if !shutdown_invoked[]
                shutdown_invoked[] = true
                if !window_update_after_shutdown
                    rw_handler_trigger_increment_read_window(client_handler_ref[], client_slot_ref[], 100)
                end
                if server_channel_ref[] !== nothing
                    AwsIO.channel_shutdown!(server_channel_ref[], AwsIO.AWS_OP_SUCCESS)
                end
            end
            lock(args.lock) do
                if data_read !== nothing
                    buf_ref = Ref(args.received_message)
                    AwsIO.byte_buf_write_from_whole_buffer(buf_ref, data_read)
                    args.received_message = buf_ref[]
                end
                args.read_invocations += 1
                args.invocation_happened = true
            end
            return args.received_message
        end

        server_bootstrap = AwsIO.ServerBootstrap(AwsIO.ServerBootstrapOptions(
            event_loop_group = elg,
            host = "127.0.0.1",
            port = 0,
            enable_read_back_pressure = true,
            tls_connection_options = AwsIO.TlsConnectionOptions(server_ctx),
            on_incoming_channel_setup = (bs, err, channel, ud) -> begin
                if err == AwsIO.AWS_OP_SUCCESS
                    server_channel_ref[] = channel
                    handler = rw_handler_new(
                        tls_test_handle_read,
                        tls_test_handle_write,
                        true,
                        typemax(Int),
                        server_rw_args,
                    )
                    server_handler_ref[] = handler
                    slot = AwsIO.channel_slot_new!(channel)
                    if AwsIO.channel_first_slot(channel) !== slot
                        AwsIO.channel_slot_insert_end!(channel, slot)
                    end
                    AwsIO.channel_slot_set_handler!(slot, handler)
                    server_slot_ref[] = slot
                end
                server_ready[] = true
                return nothing
            end,
            on_incoming_channel_shutdown = (bs, err, channel, ud) -> begin
                server_shutdown[] = true
                return nothing
            end,
        ))

        listener = server_bootstrap.listener_socket
        bound = AwsIO.socket_get_bound_address(listener)
        port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
        @test port != 0

        client_bootstrap = AwsIO.ClientBootstrap(AwsIO.ClientBootstrapOptions(
            event_loop_group = elg,
            host_resolver = resolver,
        ))

        client_tls_opts = AwsIO.TlsConnectionOptions(
            client_ctx;
            server_name = "localhost",
        )

        connect_res = AwsIO.client_bootstrap_connect!(
            client_bootstrap,
            "127.0.0.1",
            port;
            enable_read_back_pressure = true,
            tls_connection_options = client_tls_opts,
            on_setup = (bs, err, channel, ud) -> begin
                if err == AwsIO.AWS_OP_SUCCESS
                    client_channel_ref[] = channel
                    handler = rw_handler_new(
                        client_on_read,
                        tls_test_handle_write,
                        true,
                        Int(read_tag.len ÷ 2),
                        client_rw_args,
                    )
                    client_handler_ref[] = handler
                    slot = AwsIO.channel_slot_new!(channel)
                    if AwsIO.channel_first_slot(channel) !== slot
                        AwsIO.channel_slot_insert_end!(channel, slot)
                    end
                    AwsIO.channel_slot_set_handler!(slot, handler)
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

        AwsIO.server_bootstrap_shutdown!(server_bootstrap)
        AwsIO.host_resolver_shutdown!(resolver)
        AwsIO.event_loop_group_destroy!(elg)
        AwsIO.g_aws_channel_max_fragment_size[] = prev_max
    end
end

@testset "TLS statistics handler integration" begin
    if Sys.iswindows() || Threads.nthreads(:interactive) <= 1
        @test true
        return
    end

    mutable struct TestTlsStatisticsHandler <: AwsIO.StatisticsHandler
        report_ms::UInt64
        results::Channel{Tuple{AwsIO.StatisticsSampleInterval, Vector{Any}}}
    end

    AwsIO.report_interval_ms(handler::TestTlsStatisticsHandler) = handler.report_ms
    AwsIO.close!(::TestTlsStatisticsHandler) = nothing

    function AwsIO.process_statistics(
            handler::TestTlsStatisticsHandler,
            interval::AwsIO.StatisticsSampleInterval,
            stats_list::AbstractVector,
        )
        stats = Vector{Any}(undef, length(stats_list))
        for i in 1:length(stats_list)
            entry = stats_list[i]
            if entry isa AwsIO.SocketHandlerStatistics
                stats[i] = AwsIO.SocketHandlerStatistics(entry.category, entry.bytes_read, entry.bytes_written)
            elseif entry isa AwsIO.TlsHandlerStatistics
                stats[i] = AwsIO.TlsHandlerStatistics(
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

    mutable struct FakeSocketStatsHandler <: AwsIO.AbstractChannelHandler
        stats::AwsIO.SocketHandlerStatistics
    end

    FakeSocketStatsHandler() = FakeSocketStatsHandler(AwsIO.SocketHandlerStatistics())

    AwsIO.handler_process_read_message(::FakeSocketStatsHandler, ::AwsIO.ChannelSlot, ::AwsIO.IoMessage) = nothing
    AwsIO.handler_process_write_message(::FakeSocketStatsHandler, ::AwsIO.ChannelSlot, ::AwsIO.IoMessage) = nothing
    AwsIO.handler_increment_read_window(::FakeSocketStatsHandler, ::AwsIO.ChannelSlot, ::Csize_t) = nothing
    AwsIO.handler_initial_window_size(::FakeSocketStatsHandler) = Csize_t(0)
    AwsIO.handler_message_overhead(::FakeSocketStatsHandler) = Csize_t(0)
    AwsIO.handler_destroy(::FakeSocketStatsHandler) = nothing

    function AwsIO.handler_shutdown(
            ::FakeSocketStatsHandler,
            slot::AwsIO.ChannelSlot,
            direction::AwsIO.ChannelDirection.T,
            error_code::Int,
            free_scarce_resources_immediately::Bool,
        )
        AwsIO.channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
        return nothing
    end

    function AwsIO.handler_reset_statistics(handler::FakeSocketStatsHandler)::Nothing
        AwsIO.crt_statistics_socket_reset!(handler.stats)
        return nothing
    end

    AwsIO.handler_gather_statistics(handler::FakeSocketStatsHandler) = handler.stats

    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    event_loop === nothing && return

    channel = AwsIO.Channel(event_loop, nothing)

    socket_handler = FakeSocketStatsHandler()
    socket_slot = AwsIO.channel_slot_new!(channel)
    AwsIO.channel_slot_set_handler!(socket_slot, socket_handler)

    client_ctx = AwsIO.tls_context_new_client(; verify_peer = false)
    @test client_ctx isa AwsIO.TlsContext
    client_ctx isa AwsIO.TlsContext || return
    tls_slot = AwsIO.channel_slot_new!(channel)
    tls_handler = AwsIO.tls_client_handler_new(AwsIO.TlsConnectionOptions(client_ctx), tls_slot)
    @test tls_handler isa AwsIO.TlsChannelHandler
    tls_handler isa AwsIO.TlsChannelHandler || return
    AwsIO.channel_slot_insert_right!(socket_slot, tls_slot)
    AwsIO.channel_slot_set_handler!(tls_slot, tls_handler)

    AwsIO.channel_setup_complete!(channel)

    stats_results = Channel{Tuple{AwsIO.StatisticsSampleInterval, Vector{Any}}}(1)
    stats_handler = TestTlsStatisticsHandler(UInt64(50), stats_results)

    set_task = AwsIO.ScheduledTask(
        (ch, _status) -> AwsIO.channel_set_statistics_handler!(ch, stats_handler),
        channel;
        type_tag = "set_tls_stats",
    )
    AwsIO.event_loop_schedule_task_now!(event_loop, set_task)

    update_task = AwsIO.ScheduledTask(
        (_ctx, _status) -> begin
            socket_handler.stats.bytes_read = 111
            socket_handler.stats.bytes_written = 222
            AwsIO.handler_gather_statistics(tls_handler).handshake_status = AwsIO.TlsNegotiationStatus.SUCCESS
            return nothing
        end,
        nothing;
        type_tag = "update_tls_stats",
    )
    AwsIO.event_loop_schedule_task_now!(event_loop, update_task)

    @test wait_for_stats(stats_results)
    interval, stats_vec = take!(stats_results)
    @test interval.end_time_ms >= interval.begin_time_ms

    socket_stats = nothing
    tls_stats = nothing
    for entry in stats_vec
        if entry isa AwsIO.SocketHandlerStatistics
            socket_stats = entry
        elseif entry isa AwsIO.TlsHandlerStatistics
            tls_stats = entry
        end
    end

    @test socket_stats isa AwsIO.SocketHandlerStatistics
    @test tls_stats isa AwsIO.TlsHandlerStatistics
    if socket_stats isa AwsIO.SocketHandlerStatistics
        @test socket_stats.bytes_read > 0
        @test socket_stats.bytes_written > 0
    end
    if tls_stats isa AwsIO.TlsHandlerStatistics
        @test tls_stats.handshake_status == AwsIO.TlsNegotiationStatus.SUCCESS
    end

    AwsIO.channel_shutdown!(channel, AwsIO.AWS_OP_SUCCESS)
    AwsIO.event_loop_group_destroy!(elg)
end

if get(ENV, "AWSIO_RUN_NETWORK_TESTS", "0") == "1"
    @testset "TLS network negotiation (requires network)" begin
        disable_verify_peer = opts -> AwsIO.tls_ctx_options_set_verify_peer(opts, false)

        set_tls13 = opts -> AwsIO.tls_ctx_options_set_minimum_tls_version(opts, AwsIO.TlsVersion.TLSv1_3)

        function override_ca_file(path::AbstractString)
            return opts -> AwsIO.tls_ctx_options_override_default_trust_store_from_path(opts; ca_file = path)
        end

        @test _tls_network_connect("www.amazon.com", 443) == AwsIO.AWS_OP_SUCCESS
        @test _tls_network_connect("ecc256.badssl.com", 443) == AwsIO.AWS_OP_SUCCESS
        @test _tls_network_connect("ecc384.badssl.com", 443) == AwsIO.AWS_OP_SUCCESS
        if !Sys.isapple()
            @test _tls_network_connect("sha384.badssl.com", 443) == AwsIO.AWS_OP_SUCCESS
            @test _tls_network_connect("sha512.badssl.com", 443) == AwsIO.AWS_OP_SUCCESS
            @test _tls_network_connect("rsa8192.badssl.com", 443) == AwsIO.AWS_OP_SUCCESS
        end

        @test _tls_network_connect("expired.badssl.com", 443) != AwsIO.AWS_OP_SUCCESS
        @test _tls_network_connect("wrong.host.badssl.com", 443) != AwsIO.AWS_OP_SUCCESS
        @test _tls_network_connect("self-signed.badssl.com", 443) != AwsIO.AWS_OP_SUCCESS
        @test _tls_network_connect("untrusted-root.badssl.com", 443) != AwsIO.AWS_OP_SUCCESS
        @test _tls_network_connect("rc4.badssl.com", 443) != AwsIO.AWS_OP_SUCCESS
        @test _tls_network_connect("rc4-md5.badssl.com", 443) != AwsIO.AWS_OP_SUCCESS

        digicert_path = _resource_path("DigiCertGlobalRootCA.crt.pem")
        @test _tls_network_connect(
            "wrong.host.badssl.com",
            443;
            ctx_options_override = override_ca_file(digicert_path),
        ) != AwsIO.AWS_OP_SUCCESS

        ca_override_path = _resource_path("ca_root.crt")
        @test _tls_network_connect(
            "www.amazon.com",
            443;
            ctx_options_override = override_ca_file(ca_override_path),
        ) != AwsIO.AWS_OP_SUCCESS

        @test _tls_network_connect(
            "www.amazon.com",
            443;
            ctx_options_override = disable_verify_peer,
        ) == AwsIO.AWS_OP_SUCCESS
        @test _tls_network_connect(
            "expired.badssl.com",
            443;
            ctx_options_override = disable_verify_peer,
        ) == AwsIO.AWS_OP_SUCCESS
        @test _tls_network_connect(
            "wrong.host.badssl.com",
            443;
            ctx_options_override = disable_verify_peer,
        ) == AwsIO.AWS_OP_SUCCESS
        @test _tls_network_connect(
            "self-signed.badssl.com",
            443;
            ctx_options_override = disable_verify_peer,
        ) == AwsIO.AWS_OP_SUCCESS
        @test _tls_network_connect(
            "untrusted-root.badssl.com",
            443;
            ctx_options_override = disable_verify_peer,
        ) == AwsIO.AWS_OP_SUCCESS

        if Sys.isapple()
            @test _tls_network_connect(
                "ecc256.badssl.com",
                443;
                ctx_options_override = set_tls13,
            ) != AwsIO.AWS_OP_SUCCESS
        end
    end
else
    @info "Skipping TLS network tests (set AWSIO_RUN_NETWORK_TESTS=1 to enable)"
end

