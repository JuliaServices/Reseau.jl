
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

function wait_for_handshake_status(handler::Reseau.TlsChannelHandler, status; timeout_s::Float64 = 5.0)
    start = Base.time_ns()
    timeout_ns = Int(timeout_s * 1_000_000_000)
    while (Base.time_ns() - start) < timeout_ns
        if Reseau.handler_gather_statistics(handler).handshake_status == status
            return true
        end
        sleep(0.01)
    end
    return false
end

function mark_tls_handler_negotiated!(handler::Reseau.TlsChannelHandler)
    if hasproperty(handler, :state)
        setfield!(handler, :state, Reseau.TlsNegotiationState.SUCCEEDED)
    elseif hasproperty(handler, :negotiation_finished)
        setfield!(handler, :negotiation_finished, true)
    end
    return nothing
end

function mark_tls_handler_failed!(handler::Reseau.TlsChannelHandler)
    if hasproperty(handler, :state)
        setfield!(handler, :state, Reseau.TlsNegotiationState.FAILED)
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
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.HostResolver(elg)

    ctx_opts = Reseau.tls_ctx_options_init_default_client()
    if ctx_options_override !== nothing
        ctx_options_override(ctx_opts)
    end
    ctx = Reseau.tls_context_new(ctx_opts)
    if ctx isa Reseau.ErrorResult
        Reseau.host_resolver_shutdown!(resolver)
        Reseau.event_loop_group_destroy!(elg)
        return ctx
    end

    setup_err = Ref{Union{Nothing, Int}}(nothing)
    channel_ref = Ref{Any}(nothing)

    tls_conn_opts = Reseau.TlsConnectionOptions(
        ctx;
        server_name = host,
        on_negotiation_result = (handler, slot, err, ud) -> begin
            _ = handler
            _ = slot
            _ = ud
            return nothing
        end,
    )

    client_bootstrap = Reseau.ClientBootstrap(Reseau.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    _ = Reseau.client_bootstrap_connect!(
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
        Reseau.channel_shutdown!(channel_ref[], 0)
    end

    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)

    return setup_err[]
end

function _test_server_ctx()
    cert_path = _resource_path("unittests.crt")
    key_path = _resource_path("unittests.key")
    opts = Reseau.tls_ctx_options_init_default_server_from_path(cert_path, key_path)
    maybe_apply_test_keychain!(opts)
    return opts isa Reseau.TlsContextOptions ? Reseau.tls_context_new(opts) : opts
end

function _test_client_ctx(; verify_peer::Bool = true)
    opts = Reseau.tls_ctx_options_init_default_client()
    if verify_peer
        ca_file = _resource_path(Sys.isapple() ? "unittests.crt" : "ca_root.crt")
        res = Reseau.tls_ctx_options_override_default_trust_store_from_path(opts; ca_file = ca_file)
        res isa Reseau.ErrorResult && return res
    else
        Reseau.tls_ctx_options_set_verify_peer(opts, false)
    end
    return Reseau.tls_context_new(opts)
end

@testset "TLS options parity" begin
    opts = Reseau.tls_ctx_options_init_default_client()
    @test !opts.is_server
    @test opts.verify_peer

    Reseau.tls_ctx_options_set_verify_peer(opts, false)
    @test !opts.verify_peer

    Reseau.tls_ctx_options_set_minimum_tls_version(opts, Reseau.TlsVersion.TLSv1_2)
    @test opts.minimum_tls_version == Reseau.TlsVersion.TLSv1_2

    Reseau.tls_ctx_options_set_tls_cipher_preference(
        opts,
        Reseau.TlsCipherPref.TLS_CIPHER_PREF_SYSTEM_DEFAULT,
    )
    @test Reseau.tls_is_cipher_pref_supported(opts.cipher_pref)

    @test Reseau.tls_ctx_options_override_default_trust_store(
        opts,
        Reseau.ByteCursor(TEST_PEM_CERT),
    ) === nothing
    @test _buf_to_string(opts.ca_file) == TEST_PEM_CERT

    temp_dir = mktempdir()
    ca_path = joinpath(temp_dir, "ca.pem")
    write(ca_path, TEST_PEM_CERT)
    @test Reseau.tls_ctx_options_override_default_trust_store_from_path(
        opts;
        ca_path = "/tmp",
        ca_file = ca_path,
    ) isa Reseau.ErrorResult

    opts2 = Reseau.tls_ctx_options_init_default_client()
    @test Reseau.tls_ctx_options_override_default_trust_store_from_path(
        opts2;
        ca_path = "/tmp",
        ca_file = ca_path,
    ) === nothing
    @test opts2.ca_path == "/tmp"
    @test _buf_to_string(opts2.ca_file) == TEST_PEM_CERT

    ctx = Reseau.tls_context_new(opts)
    @test ctx isa Reseau.TlsContext

    conn = Reseau.tls_connection_options_init_from_ctx(ctx)
    @test conn.timeout_ms == 0x00002710
    Reseau.tls_connection_options_set_server_name(conn, "example.com")
    Reseau.tls_connection_options_set_alpn_list(conn, "h2")
    Reseau.tls_connection_options_set_timeout_ms(conn, 250)
    Reseau.tls_connection_options_set_advertise_alpn_message(conn, true)

    cb1 = (handler, slot, err, ud) -> nothing
    cb2 = (handler, slot, buf, ud) -> nothing
    cb3 = (handler, slot, err, msg, ud) -> nothing
    Reseau.tls_connection_options_set_callbacks(conn, cb1, cb2, cb3, 123)

    @test conn.server_name == "example.com"
    @test conn.alpn_list == "h2"
    @test conn.timeout_ms == 0x000000fa
    @test conn.advertise_alpn_message
    @test conn.on_negotiation_result === cb1
    @test conn.on_data_read === cb2
    @test conn.on_error === cb3
    @test conn.user_data == 123

    conn_copy = Reseau.tls_connection_options_copy(conn)
    @test conn_copy.server_name == conn.server_name
    @test conn_copy.alpn_list == conn.alpn_list
    @test conn_copy.timeout_ms == conn.timeout_ms
end

@testset "TLS static state" begin
    Reseau.tls_init_static_state()
    @test !Reseau.is_using_secitem()
    Reseau.tls_clean_up_static_state()
end

@testset "TLS ctx acquire/release" begin
    ctx = _test_client_ctx()
    @test ctx isa Reseau.TlsContext
    if ctx isa Reseau.TlsContext
        @test Reseau.tls_ctx_acquire(ctx) === ctx
        @test Reseau.tls_ctx_release(ctx) === nothing
    end
    @test Reseau.tls_ctx_acquire(nothing) === nothing
    @test Reseau.tls_ctx_release(nothing) === nothing
end

@testset "TLS ctx new helpers" begin
    opts = Reseau.tls_ctx_options_init_default_client()
    @test Reseau.tls_ctx_options_override_default_trust_store(opts, Reseau.ByteCursor(TEST_PEM_CERT)) === nothing
    ctx = Reseau.tls_client_ctx_new(opts)
    @test ctx isa Reseau.TlsContext
    if ctx isa Reseau.TlsContext
        @test !ctx.options.is_server
        @test ctx.options.ca_file.len == opts.ca_file.len
        @test ctx.options.ca_file.mem !== opts.ca_file.mem
    end

    server_ctx = Reseau.tls_server_ctx_new(opts)
    @test server_ctx isa Reseau.TlsContext
    if server_ctx isa Reseau.TlsContext
        @test server_ctx.options.is_server
    end

    srv_opts = Reseau.tls_ctx_options_init_default_server(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY),
    )
    @test srv_opts isa Reseau.TlsContextOptions
    if srv_opts isa Reseau.TlsContextOptions
        client_ctx = Reseau.tls_client_ctx_new(srv_opts)
        @test client_ctx isa Reseau.TlsContext
        if client_ctx isa Reseau.TlsContext
            @test !client_ctx.options.is_server
        end
    end

    bad_opts = Reseau.tls_ctx_options_init_default_client()
    Reseau.tls_ctx_options_set_tls_cipher_preference(
        bad_opts,
        Reseau.TlsCipherPref.TLS_CIPHER_PREF_END_RANGE,
    )
    bad_ctx = Reseau.tls_client_ctx_new(bad_opts)
    @test bad_ctx isa Reseau.ErrorResult
    if bad_ctx isa Reseau.ErrorResult
        @test bad_ctx.code == Reseau.ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED
    end
end

@testset "TLS error code predicate - comprehensive" begin
    # All 26 TLS error codes must be recognized by the predicate
    tls_errors = [
        Reseau.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE,
        Reseau.ERROR_IO_TLS_ERROR_NOT_NEGOTIATED,
        Reseau.ERROR_IO_TLS_ERROR_WRITE_FAILURE,
        Reseau.ERROR_IO_TLS_ERROR_ALERT_RECEIVED,
        Reseau.ERROR_IO_TLS_CTX_ERROR,
        Reseau.ERROR_IO_TLS_VERSION_UNSUPPORTED,
        Reseau.ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED,
        Reseau.ERROR_IO_TLS_NEGOTIATION_TIMEOUT,
        Reseau.ERROR_IO_TLS_ALERT_NOT_GRACEFUL,
        Reseau.ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED,
        Reseau.ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED,
        Reseau.ERROR_IO_TLS_ERROR_READ_FAILURE,
        Reseau.ERROR_IO_TLS_UNKNOWN_ROOT_CERTIFICATE,
        Reseau.ERROR_IO_TLS_NO_ROOT_CERTIFICATE_FOUND,
        Reseau.ERROR_IO_TLS_CERTIFICATE_EXPIRED,
        Reseau.ERROR_IO_TLS_CERTIFICATE_NOT_YET_VALID,
        Reseau.ERROR_IO_TLS_BAD_CERTIFICATE,
        Reseau.ERROR_IO_TLS_PEER_CERTIFICATE_EXPIRED,
        Reseau.ERROR_IO_TLS_BAD_PEER_CERTIFICATE,
        Reseau.ERROR_IO_TLS_PEER_CERTIFICATE_REVOKED,
        Reseau.ERROR_IO_TLS_PEER_CERTIFICATE_UNKNOWN,
        Reseau.ERROR_IO_TLS_INTERNAL_ERROR,
        Reseau.ERROR_IO_TLS_CLOSED_GRACEFUL,
        Reseau.ERROR_IO_TLS_CLOSED_ABORT,
        Reseau.ERROR_IO_TLS_INVALID_CERTIFICATE_CHAIN,
        Reseau.ERROR_IO_TLS_HOST_NAME_MISMATCH,
    ]
    for code in tls_errors
        @test Reseau.io_error_code_is_tls(code)
    end
    # Non-TLS error codes must not be recognized
    @test !Reseau.io_error_code_is_tls(Reseau.ERROR_IO_SOCKET_TIMEOUT)
    @test !Reseau.io_error_code_is_tls(Reseau.ERROR_IO_DNS_QUERY_FAILED)
    @test !Reseau.io_error_code_is_tls(Reseau.ERROR_IO_EVENT_LOOP_SHUTDOWN)
    @test !Reseau.io_error_code_is_tls(Reseau.ERROR_IO_BROKEN_PIPE)
    @test !Reseau.io_error_code_is_tls(0)
    # DEFAULT_TRUST_STORE_NOT_FOUND is a config error, not classified as TLS
    # (matches aws-c-io aws_error_code_is_tls predicate)
    @test !Reseau.io_error_code_is_tls(Reseau.ERROR_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND)
end

@testset "NW socket TLS error translation" begin
    if !Sys.isapple()
        @test true
        return
    end
    # Test that _nw_determine_socket_error maps errSSL* codes to the correct TLS error codes.
    # These mappings match aws-c-io source/darwin/nw_socket.c:s_determine_socket_error()
    errSSL_map = [
        (Int32(-9812), Reseau.ERROR_IO_TLS_UNKNOWN_ROOT_CERTIFICATE),      # errSSLUnknownRootCert
        (Int32(-9813), Reseau.ERROR_IO_TLS_NO_ROOT_CERTIFICATE_FOUND),     # errSSLNoRootCert
        (Int32(-9814), Reseau.ERROR_IO_TLS_CERTIFICATE_EXPIRED),           # errSSLCertExpired
        (Int32(-9815), Reseau.ERROR_IO_TLS_CERTIFICATE_NOT_YET_VALID),     # errSSLCertNotYetValid
        (Int32(-9824), Reseau.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE),     # errSSLPeerHandshakeFail
        (Int32(-9808), Reseau.ERROR_IO_TLS_BAD_CERTIFICATE),              # errSSLBadCert
        (Int32(-9828), Reseau.ERROR_IO_TLS_PEER_CERTIFICATE_EXPIRED),     # errSSLPeerCertExpired
        (Int32(-9825), Reseau.ERROR_IO_TLS_BAD_PEER_CERTIFICATE),         # errSSLPeerBadCert
        (Int32(-9827), Reseau.ERROR_IO_TLS_PEER_CERTIFICATE_REVOKED),     # errSSLPeerCertRevoked
        (Int32(-9829), Reseau.ERROR_IO_TLS_PEER_CERTIFICATE_UNKNOWN),     # errSSLPeerCertUnknown
        (Int32(-9810), Reseau.ERROR_IO_TLS_INTERNAL_ERROR),               # errSSLInternal
        (Int32(-9805), Reseau.ERROR_IO_TLS_CLOSED_GRACEFUL),              # errSSLClosedGraceful
        (Int32(-9806), Reseau.ERROR_IO_TLS_CLOSED_ABORT),                 # errSSLClosedAbort
        (Int32(-9807), Reseau.ERROR_IO_TLS_INVALID_CERTIFICATE_CHAIN),    # errSSLXCertChainInvalid
        (Int32(-9843), Reseau.ERROR_IO_TLS_HOST_NAME_MISMATCH),           # errSSLHostNameMismatch
        (Int32(-67843), Reseau.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE),   # errSecNotTrusted
        (Int32(-9836), Reseau.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE),    # errSSLPeerProtocolVersion
    ]
    for (osstatus, expected_error) in errSSL_map
        result = Reseau._nw_determine_socket_error(Int(osstatus))
        @test result == expected_error
    end
end

@testset "TLS ctx options mtls" begin
    opts = Reseau.tls_ctx_options_init_client_mtls(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY),
    )
    @test opts isa Reseau.TlsContextOptions
    if opts isa Reseau.TlsContextOptions
        @test _buf_to_string(opts.certificate) == TEST_PEM_CERT
        @test _buf_to_string(opts.private_key) == TEST_PEM_KEY
    end

    temp_dir = mktempdir()
    cert_path = joinpath(temp_dir, "cert.pem")
    key_path = joinpath(temp_dir, "key.pem")
    write(cert_path, TEST_PEM_CERT)
    write(key_path, TEST_PEM_KEY)

    opts2 = Reseau.tls_ctx_options_init_client_mtls_from_path(cert_path, key_path)
    @test opts2 isa Reseau.TlsContextOptions
    if opts2 isa Reseau.TlsContextOptions
        @test _buf_to_string(opts2.certificate) == TEST_PEM_CERT
        @test _buf_to_string(opts2.private_key) == TEST_PEM_KEY
    end
end

@testset "TLS ctx options pkcs12" begin
    pkcs_bytes = UInt8[0x01, 0x02, 0x03, 0x04]
    pkcs_pwd = "secret"

    if Sys.isapple()
        opts = Reseau.tls_ctx_options_init_client_mtls_pkcs12(pkcs_bytes, pkcs_pwd)
        @test opts isa Reseau.TlsContextOptions
        if opts isa Reseau.TlsContextOptions
            pkcs_out = Vector{UInt8}(undef, Int(opts.pkcs12.len))
            copyto!(pkcs_out, 1, opts.pkcs12.mem, 1, Int(opts.pkcs12.len))
            @test pkcs_out == pkcs_bytes
            @test _buf_to_string(opts.pkcs12_password) == pkcs_pwd
        end
    else
        @test Reseau.tls_ctx_options_init_client_mtls_pkcs12(pkcs_bytes, pkcs_pwd) isa Reseau.ErrorResult
    end
end

@testset "TLS ctx options server init" begin
    opts = Reseau.tls_ctx_options_init_default_server(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY);
        alpn_list = "h2",
    )
    @test opts isa Reseau.TlsContextOptions
    if opts isa Reseau.TlsContextOptions
        @test opts.is_server
        @test !opts.verify_peer
        @test opts.alpn_list == "h2"
    end

    temp_dir = mktempdir()
    cert_path = joinpath(temp_dir, "cert.pem")
    key_path = joinpath(temp_dir, "key.pem")
    write(cert_path, TEST_PEM_CERT)
    write(key_path, TEST_PEM_KEY)

    opts2 = Reseau.tls_ctx_options_init_default_server_from_path(
        cert_path,
        key_path;
        alpn_list = "h2",
    )
    @test opts2 isa Reseau.TlsContextOptions
    if opts2 isa Reseau.TlsContextOptions
        @test opts2.is_server
        @test !opts2.verify_peer
        @test opts2.alpn_list == "h2"
    end
end

@testset "TLS ctx options platform hooks" begin
    opts = Reseau.tls_ctx_options_init_default_client()
    if Sys.isapple()
        secitem = Reseau.SecItemOptions("cert", "key")
        if Reseau.is_using_secitem()
            @test Reseau.tls_ctx_options_set_keychain_path(opts, "/tmp") isa Reseau.ErrorResult
            @test Reseau.tls_ctx_options_set_secitem_options(opts, secitem) === nothing
        else
            @test Reseau.tls_ctx_options_set_keychain_path(opts, "/tmp") === nothing
            @test Reseau.tls_ctx_options_set_secitem_options(opts, secitem) isa Reseau.ErrorResult
        end
    else
        @test Reseau.tls_ctx_options_set_keychain_path(opts, "/tmp") isa Reseau.ErrorResult
        secitem = Reseau.SecItemOptions("cert", "key")
        @test Reseau.tls_ctx_options_set_secitem_options(opts, secitem) isa Reseau.ErrorResult
    end
end

@testset "TLS minimum version TLSv1_3 unsupported on macOS" begin
    if !Sys.isapple()
        @test true
        return
    end

    opts = Reseau.tls_ctx_options_init_default_client()
    Reseau.tls_ctx_options_set_minimum_tls_version(opts, Reseau.TlsVersion.TLSv1_3)
    ctx = Reseau.tls_context_new(opts)
    @test ctx isa Reseau.TlsContext
    if !(ctx isa Reseau.TlsContext)
        return
    end

    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    channel = Reseau.Channel(event_loop, nothing)
    slot = Reseau.channel_slot_new!(channel)
    conn = Reseau.tls_connection_options_init_from_ctx(ctx)
    res = Reseau.tls_client_handler_new(conn, slot)
    @test res isa Reseau.ErrorResult
    if res isa Reseau.ErrorResult
        @test res.code == Reseau.ERROR_IO_TLS_CTX_ERROR
    end

    Reseau.event_loop_group_destroy!(elg)
end

@testset "TLS ctx options custom key ops" begin
    res = Reseau.tls_ctx_options_init_client_mtls_with_custom_key_operations(
        nothing,
        Reseau.ByteCursor(TEST_PEM_CERT),
    )
    @test res isa Reseau.ErrorResult
    if res isa Reseau.ErrorResult
        @test res.code == Reseau.ERROR_INVALID_ARGUMENT
    end
end

@testset "TLS custom key op handler" begin
    op = Reseau.TlsKeyOperation(Reseau.ByteCursor(UInt8[0x01]))
    called = Ref(false)
    handler = Reseau.CustomKeyOpHandler(
        (handler_obj, operation) -> begin
            @test handler_obj.user_data == 7
            @test operation === op
            called[] = true
        end;
        user_data = 7,
    )

    @test Reseau.custom_key_op_handler_acquire(handler) === handler
    @test Reseau.custom_key_op_handler_release(handler) === nothing
    Reseau.custom_key_op_handler_perform_operation(handler, op)
    @test called[]
end

@testset "TLS ctx options custom key ops init" begin
    handler = Reseau.CustomKeyOpHandler((handler_obj, operation) -> nothing)
    opts = Reseau.tls_ctx_options_init_client_mtls_with_custom_key_operations(
        handler,
        Reseau.ByteCursor(TEST_PEM_CERT),
    )
    @test opts isa Reseau.TlsContextOptions
    if opts isa Reseau.TlsContextOptions
        @test opts.custom_key_op_handler === handler
        @test _buf_to_string(opts.certificate) == TEST_PEM_CERT
    end

    bad = Reseau.tls_ctx_options_init_client_mtls_with_custom_key_operations(
        Reseau.CustomKeyOpHandler(nothing),
        Reseau.ByteCursor(TEST_PEM_CERT),
    )
    @test bad isa Reseau.ErrorResult
    if bad isa Reseau.ErrorResult
        @test bad.code == Reseau.ERROR_INVALID_ARGUMENT
    end
end

@testset "TLS custom key ops TLSv1_3 unsupported (s2n)" begin
    if !Sys.islinux()
        @test true
        return
    end
    if !Reseau.tls_is_alpn_available()
        @info "Skipping TLS custom key ops TLSv1_3 test (s2n unavailable)"
        return
    end

    handler = Reseau.CustomKeyOpHandler((handler_obj, operation) -> nothing)
    opts = Reseau.tls_ctx_options_init_client_mtls_with_custom_key_operations(
        handler,
        Reseau.ByteCursor(TEST_PEM_CERT),
    )
    @test opts isa Reseau.TlsContextOptions
    opts isa Reseau.ErrorResult && return

    Reseau.tls_ctx_options_set_minimum_tls_version(opts, Reseau.TlsVersion.TLSv1_3)
    ctx = Reseau.tls_context_new(opts)
    @test ctx isa Reseau.ErrorResult
    if ctx isa Reseau.ErrorResult
        @test ctx.code == Reseau.ERROR_IO_TLS_VERSION_UNSUPPORTED
    end
end

@testset "TLS ctx options pkcs11" begin
    opts = Reseau.TlsCtxPkcs11Options(
        pkcs11_lib = :fake,
        cert_file_path = "cert.pem",
        cert_file_contents = "cert",
    )
    res = Reseau.tls_ctx_options_init_client_mtls_with_pkcs11(opts)
    @test res isa Reseau.ErrorResult
    if res isa Reseau.ErrorResult
        @test res.code == Reseau.ERROR_INVALID_ARGUMENT
    end

    temp_dir = mktempdir()
    cert_path = joinpath(temp_dir, "cert.pem")
    write(cert_path, TEST_PEM_CERT)

    opts2 = Reseau.TlsCtxPkcs11Options(
        pkcs11_lib = :fake,
        cert_file_path = cert_path,
    )
    res2 = Reseau.tls_ctx_options_init_client_mtls_with_pkcs11(opts2)
    @test res2 isa Reseau.ErrorResult
    if res2 isa Reseau.ErrorResult
        @test res2.code == Reseau.ERROR_INVALID_ARGUMENT
    end

    opts3 = Reseau.TlsCtxPkcs11Options(
        pkcs11_lib = :fake,
        cert_file_contents = TEST_PEM_CERT,
    )
    res3 = Reseau.tls_ctx_options_init_client_mtls_with_pkcs11(opts3)
    @test res3 isa Reseau.ErrorResult
    if res3 isa Reseau.ErrorResult
        @test res3.code == Reseau.ERROR_INVALID_ARGUMENT
    end
end

@testset "TLS BYO crypto setup" begin
    new_handler = (options, slot, ud) -> nothing
    start_negotiation = (handler, ud) -> 0
    client_opts = Reseau.TlsByoCryptoSetupOptions(
        new_handler_fn = new_handler,
        start_negotiation_fn = start_negotiation,
        user_data = 7,
    )
    @test Reseau.tls_byo_crypto_set_client_setup_options(client_opts) === nothing

    server_opts = Reseau.TlsByoCryptoSetupOptions(
        new_handler_fn = new_handler,
        user_data = 9,
    )
    @test Reseau.tls_byo_crypto_set_server_setup_options(server_opts) === nothing

    bad_client = Reseau.TlsByoCryptoSetupOptions(
        new_handler_fn = nothing,
        start_negotiation_fn = nothing,
    )
    res = Reseau.tls_byo_crypto_set_client_setup_options(bad_client)
    @test res isa Reseau.ErrorResult
    if res isa Reseau.ErrorResult
        @test res.code == Reseau.ERROR_INVALID_ARGUMENT
    end

    Reseau._tls_byo_client_setup[] = nothing
    Reseau._tls_byo_server_setup[] = nothing
end

@testset "TLS timeout task" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Reseau.TlsContext
    if ctx isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    opts = Reseau.TlsConnectionOptions(ctx; timeout_ms = 1)
    channel = Reseau.Channel(event_loop, nothing)
    slot = Reseau.channel_slot_new!(channel)
    handler = Reseau.tls_client_handler_new(opts, slot)
    @test handler isa Reseau.TlsChannelHandler
    if handler isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end
    Reseau.channel_slot_set_handler!(slot, handler)

    handler.stats.handshake_status = Reseau.TlsNegotiationStatus.ONGOING
    Reseau._tls_timeout_task(handler.timeout_task, handler, Reseau.TaskStatus.RUN_READY)

    @test channel.shutdown_pending
    @test channel.shutdown_error_code == Reseau.ERROR_IO_TLS_NEGOTIATION_TIMEOUT

    Reseau.event_loop_group_destroy!(elg)
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

    operation = Reseau.TlsKeyOperation(
        input_cursor;
        operation_type = Reseau.TlsKeyOperationType.SIGN,
        signature_algorithm = Reseau.TlsSignatureAlgorithm.RSA,
        digest_algorithm = Reseau.TlsHashAlgorithm.SHA256,
        on_complete = on_complete,
        user_data = 99,
    )

    @test Reseau.tls_key_operation_get_type(operation) == Reseau.TlsKeyOperationType.SIGN
    @test Reseau.tls_key_operation_get_signature_algorithm(operation) == Reseau.TlsSignatureAlgorithm.RSA
    @test Reseau.tls_key_operation_get_digest_algorithm(operation) == Reseau.TlsHashAlgorithm.SHA256
    @test Reseau.byte_cursor_eq(Reseau.tls_key_operation_get_input(operation), input_cursor)

    output_cursor = Reseau.ByteCursor(UInt8[0x0a, 0x0b])
    @test Reseau.tls_key_operation_complete!(operation, output_cursor) === nothing
    @test operation.completed
    @test operation.error_code == Reseau.AWS_OP_SUCCESS
    @test cb_called[]
    @test cb_err[] == Reseau.AWS_OP_SUCCESS
    @test cb_ud[] == 99
    @test cb_op[] === operation
    @test Reseau.byte_cursor_eq(Reseau.byte_cursor_from_buf(operation.output), output_cursor)

    cb_called[] = false
    err_operation = Reseau.TlsKeyOperation(
        input_cursor;
        on_complete = on_complete,
        user_data = 123,
    )
    @test Reseau.tls_key_operation_complete_with_error!(
        err_operation,
        Reseau.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE,
    ) === nothing
    @test err_operation.completed
    @test err_operation.error_code == Reseau.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE
    @test cb_called[]
    @test cb_err[] == Reseau.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE
    @test cb_ud[] == 123

    @test Reseau.tls_hash_algorithm_str(Reseau.TlsHashAlgorithm.SHA384) == "SHA384"
    @test Reseau.tls_hash_algorithm_str(Reseau.TlsHashAlgorithm.UNKNOWN) == "UNKNOWN"
    @test Reseau.tls_signature_algorithm_str(Reseau.TlsSignatureAlgorithm.ECDSA) == "ECDSA"
    @test Reseau.tls_signature_algorithm_str(Reseau.TlsSignatureAlgorithm.UNKNOWN) == "UNKNOWN"
    @test Reseau.tls_key_operation_type_str(Reseau.TlsKeyOperationType.SIGN) == "SIGN"
    @test Reseau.tls_key_operation_type_str(Reseau.TlsKeyOperationType.UNKNOWN) == "UNKNOWN"
end

@testset "TLS handler accessors" begin
    opts = Reseau.tls_ctx_options_init_default_client()
    ctx = Reseau.tls_context_new(opts)
    @test ctx isa Reseau.TlsContext
    if ctx isa Reseau.ErrorResult
        return
    end

    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    channel = Reseau.Channel(event_loop, nothing)
    slot = Reseau.channel_slot_new!(channel)
    conn = Reseau.tls_connection_options_init_from_ctx(ctx)
    Reseau.tls_connection_options_set_server_name(conn, "example.com")
    handler = Reseau.tls_client_handler_new(conn, slot)
    @test handler isa Reseau.TlsChannelHandler
    if handler isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end
    Reseau.channel_slot_set_handler!(slot, handler)

    @test _buf_to_string(Reseau.tls_handler_server_name(handler)) == "example.com"
    @test Reseau.tls_handler_protocol(handler).len == 0

    handler.protocol = Reseau.byte_buf_from_c_str("h2")
    @test _buf_to_string(Reseau.tls_handler_protocol(handler)) == "h2"

    Reseau.event_loop_group_destroy!(elg)
end

mutable struct EchoHandler <: Reseau.AbstractChannelHandler
    slot::Union{Reseau.ChannelSlot, Nothing}
    saw_ping::Base.RefValue{Bool}
end

function EchoHandler(flag::Base.RefValue{Bool})
    return EchoHandler(nothing, flag)
end

function Reseau.handler_process_read_message(handler::EchoHandler, slot::Reseau.ChannelSlot, message::Reseau.IoMessage)
    channel = slot.channel
    buf = message.message_data
    payload = String(Reseau.byte_cursor_from_buf(buf))
    if payload == "ping"
        handler.saw_ping[] = true
        resp = Reseau.IoMessage(4)
        resp_ref = Ref(resp.message_data)
        Reseau.byte_buf_write_from_whole_cursor(resp_ref, Reseau.ByteCursor("pong"))
        resp.message_data = resp_ref[]
        Reseau.channel_slot_send_message(slot, resp, Reseau.ChannelDirection.WRITE)
    end
    if channel !== nothing
        Reseau.channel_release_message_to_pool!(channel, message)
    end
    return nothing
end

function Reseau.handler_process_write_message(handler::EchoHandler, slot::Reseau.ChannelSlot, message::Reseau.IoMessage)
    return Reseau.channel_slot_send_message(slot, message, Reseau.ChannelDirection.WRITE)
end

function Reseau.handler_increment_read_window(handler::EchoHandler, slot::Reseau.ChannelSlot, size::Csize_t)
    return Reseau.channel_slot_increment_read_window!(slot, size)
end

function Reseau.handler_shutdown(
        handler::EchoHandler,
        slot::Reseau.ChannelSlot,
        direction::Reseau.ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )
    Reseau.channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    return nothing
end

function Reseau.handler_initial_window_size(handler::EchoHandler)
    return Reseau.SIZE_MAX
end

function Reseau.handler_message_overhead(handler::EchoHandler)
    return Csize_t(0)
end

function Reseau.handler_destroy(handler::EchoHandler)
    return nothing
end

mutable struct SinkHandler <: Reseau.TlsChannelHandler
    slot::Union{Reseau.ChannelSlot, Nothing}
    writes::Base.RefValue{Int}
end

function SinkHandler()
    return SinkHandler(nothing, Ref(0))
end

function Reseau.handler_process_read_message(handler::SinkHandler, slot::Reseau.ChannelSlot, message::Reseau.IoMessage)
    if slot.channel !== nothing
        Reseau.channel_release_message_to_pool!(slot.channel, message)
    end
    return nothing
end

function Reseau.handler_process_write_message(handler::SinkHandler, slot::Reseau.ChannelSlot, message::Reseau.IoMessage)
    handler.writes[] += 1
    if slot.channel !== nothing
        Reseau.channel_release_message_to_pool!(slot.channel, message)
    end
    return nothing
end

function Reseau.handler_increment_read_window(handler::SinkHandler, slot::Reseau.ChannelSlot, size::Csize_t)
    return Reseau.channel_slot_increment_read_window!(slot, size)
end

function Reseau.handler_shutdown(
        handler::SinkHandler,
        slot::Reseau.ChannelSlot,
        direction::Reseau.ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )
    Reseau.channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    return nothing
end

function Reseau.handler_initial_window_size(handler::SinkHandler)
    return Reseau.SIZE_MAX
end

function Reseau.handler_message_overhead(handler::SinkHandler)
    return Csize_t(0)
end

function Reseau.handler_destroy(handler::SinkHandler)
    return nothing
end

@testset "TLS BYO crypto integration" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Reseau.TlsContext
    if ctx isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
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

    client_opts = Reseau.TlsByoCryptoSetupOptions(
        new_handler_fn = new_handler,
        start_negotiation_fn = start_negotiation,
        user_data = 42,
    )
    @test Reseau.tls_byo_crypto_set_client_setup_options(client_opts) === nothing

    server_setup = Reseau.TlsByoCryptoSetupOptions(
        new_handler_fn = server_new_handler,
        user_data = 99,
    )
    @test Reseau.tls_byo_crypto_set_server_setup_options(server_setup) === nothing

    channel = Reseau.Channel(event_loop, nothing)
    left_slot = Reseau.channel_slot_new!(channel)
    sink = SinkHandler()
    Reseau.channel_slot_set_handler!(left_slot, sink)

    tls_opts = Reseau.TlsConnectionOptions(ctx; server_name = "example.com")
    handler = Reseau.channel_setup_client_tls(left_slot, tls_opts)
    @test handler isa Reseau.AbstractChannelHandler
    @test new_called[]
    @test start_called[]
    @test seen_slot[] === left_slot.adj_right
    @test seen_new_ud[] == 42
    @test seen_start_ud[] == 42
    @test seen_handler[] === handler

    server_opts = Reseau.tls_ctx_options_init_default_server(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY),
    )
    maybe_apply_test_keychain!(server_opts)
    @test server_opts isa Reseau.TlsContextOptions
    if server_opts isa Reseau.TlsContextOptions
        server_ctx = Reseau.tls_context_new(server_opts)
        @test server_ctx isa Reseau.TlsContext
        if server_ctx isa Reseau.TlsContext
            server_channel = Reseau.Channel(event_loop, nothing)
            server_slot = Reseau.channel_slot_new!(server_channel)
            server_handler = Reseau.tls_server_handler_new(
                Reseau.TlsConnectionOptions(server_ctx),
                server_slot,
            )
            @test server_handler isa Reseau.AbstractChannelHandler
            @test server_new_called[]
            @test server_seen_slot[] === server_slot
            @test server_seen_ud[] == 99
            @test server_seen_handler[] === server_handler
        end
    end

    Reseau._tls_byo_client_setup[] = nothing
    Reseau._tls_byo_server_setup[] = nothing
    Reseau.event_loop_group_destroy!(elg)
end

@testset "TLS client/server handler API" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    client_ctx = _test_client_ctx()
    @test client_ctx isa Reseau.TlsContext
    if client_ctx isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    channel = Reseau.Channel(event_loop, nothing)
    left_slot = Reseau.channel_slot_new!(channel)
    sink = SinkHandler()
    Reseau.channel_slot_set_handler!(left_slot, sink)
    sink.slot = left_slot
    tls_slot = Reseau.channel_slot_new!(channel)
    Reseau.channel_slot_insert_right!(left_slot, tls_slot)

    client_opts = Reseau.TlsConnectionOptions(client_ctx; server_name = "example.com")
    client_handler = Reseau.tls_client_handler_new(client_opts, tls_slot)
    @test client_handler isa Reseau.TlsChannelHandler
    if client_handler isa Reseau.TlsChannelHandler
        client_opts.server_name = "changed"
        @test _buf_to_string(Reseau.tls_handler_server_name(client_handler)) == "example.com"
        @test Reseau.handler_gather_statistics(client_handler).handshake_status == Reseau.TlsNegotiationStatus.NONE
        @test Reseau.tls_client_handler_start_negotiation(client_handler) === nothing
        @test wait_for_handshake_status(client_handler, Reseau.TlsNegotiationStatus.ONGOING)
    end

    server_opts = Reseau.tls_ctx_options_init_default_server(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY),
    )
    maybe_apply_test_keychain!(server_opts)
    @test server_opts isa Reseau.TlsContextOptions
    if server_opts isa Reseau.TlsContextOptions
        server_ctx = Reseau.tls_context_new(server_opts)
        @test server_ctx isa Reseau.TlsContext
        if server_ctx isa Reseau.TlsContext
            server_channel = Reseau.Channel(event_loop, nothing)
            server_left = Reseau.channel_slot_new!(server_channel)
            server_sink = SinkHandler()
            Reseau.channel_slot_set_handler!(server_left, server_sink)
            server_sink.slot = server_left
            server_slot = Reseau.channel_slot_new!(server_channel)
            Reseau.channel_slot_insert_right!(server_left, server_slot)

            server_handler = Reseau.tls_server_handler_new(
                Reseau.TlsConnectionOptions(server_ctx),
                server_slot,
            )
            @test server_handler isa Reseau.TlsChannelHandler
            if server_handler isa Reseau.TlsChannelHandler
                @test Reseau.handler_gather_statistics(server_handler).handshake_status == Reseau.TlsNegotiationStatus.NONE
            end

            bad_channel = Reseau.Channel(event_loop, nothing)
            bad_slot = Reseau.channel_slot_new!(bad_channel)
            bad_handler = Reseau.tls_client_handler_new(Reseau.TlsConnectionOptions(server_ctx), bad_slot)
            @test bad_handler isa Reseau.ErrorResult
            if bad_handler isa Reseau.ErrorResult
                @test bad_handler.code == Reseau.ERROR_INVALID_ARGUMENT
            end
        end
    end

    @test Reseau.tls_is_alpn_available()
    Reseau.event_loop_group_destroy!(elg)
end

@testset "TLS read shutdown ignores data" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Reseau.TlsContext
    if ctx isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    channel = Reseau.Channel(event_loop, nothing)
    slot = Reseau.channel_slot_new!(channel)
    saw_data = Ref(false)
    on_data_read = (handler, slot, buf, ud) -> begin
        saw_data[] = true
        return nothing
    end
    opts = Reseau.TlsConnectionOptions(ctx; on_data_read = on_data_read)
    handler = Reseau.tls_client_handler_new(opts, slot)
    @test handler isa Reseau.TlsChannelHandler
    if handler isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end
    Reseau.channel_slot_set_handler!(slot, handler)
    if hasproperty(handler, :state)
        setfield!(handler, :state, Reseau.TlsNegotiationState.SUCCEEDED)
    elseif hasproperty(handler, :negotiation_finished)
        setfield!(handler, :negotiation_finished, true)
    end

    Reseau.handler_shutdown(handler, slot, Reseau.ChannelDirection.READ, 0, false)

    msg = Reseau.IoMessage(1)
    msg_ref = Ref(msg.message_data)
    Reseau.byte_buf_write_from_whole_cursor(msg_ref, Reseau.ByteCursor(UInt8[0x00]))
    msg.message_data = msg_ref[]
    Reseau.handler_process_read_message(handler, slot, msg)

    @test !saw_data[]
    Reseau.event_loop_group_destroy!(elg)
end

@testset "TLS shutdown clears pending writes" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Reseau.TlsContext
    if ctx isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    channel = Reseau.Channel(event_loop, nothing)
    slot = Reseau.channel_slot_new!(channel)
    handler = Reseau.tls_client_handler_new(Reseau.TlsConnectionOptions(ctx), slot)
    @test handler isa Reseau.TlsChannelHandler
    if handler isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end
    Reseau.channel_slot_set_handler!(slot, handler)
    mark_tls_handler_negotiated!(handler)

    Reseau.handler_shutdown(handler, slot, Reseau.ChannelDirection.WRITE, 0, false)
    @test channel.channel_state == Reseau.ChannelState.SHUT_DOWN

    Reseau.event_loop_group_destroy!(elg)
end

@testset "TLS write after failure" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Reseau.TlsContext
    if ctx isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    channel = Reseau.Channel(event_loop, nothing)
    slot = Reseau.channel_slot_new!(channel)
    handler = Reseau.tls_client_handler_new(Reseau.TlsConnectionOptions(ctx), slot)
    @test handler isa Reseau.TlsChannelHandler
    if handler isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end
    Reseau.channel_slot_set_handler!(slot, handler)
    mark_tls_handler_failed!(handler)

    msg = Reseau.IoMessage(1)
    msg_ref = Ref(msg.message_data)
    Reseau.byte_buf_write_from_whole_cursor(msg_ref, Reseau.ByteCursor(UInt8[0x02]))
    msg.message_data = msg_ref[]
    res = Reseau.handler_process_write_message(handler, slot, msg)
    @test res isa Reseau.ErrorResult
    if res isa Reseau.ErrorResult
        @test res.code == Reseau.ERROR_IO_TLS_ERROR_NOT_NEGOTIATED
    end

    Reseau.event_loop_group_destroy!(elg)
end

@testset "TLS alert handling" begin
    if Sys.isapple() || Sys.islinux()
        @test true
        return
    end

    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Reseau.TlsContext
    if ctx isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    function new_alert_handler()
        channel = Reseau.Channel(event_loop, nothing)
        slot = Reseau.channel_slot_new!(channel)
        handler = Reseau.TlsChannelHandler(Reseau.TlsConnectionOptions(ctx))
        handler.negotiation_completed = true
        handler.state = Reseau.TlsHandshakeState.NEGOTIATED
        handler.slot = slot
        Reseau.channel_slot_set_handler!(slot, handler)
        return channel, slot, handler
    end

    function send_alert!(handler::Reseau.TlsChannelHandler, slot::Reseau.ChannelSlot, level::UInt8, desc::UInt8)
        msg = Reseau.IoMessage(2 + Reseau.TLS_RECORD_HEADER_LEN)
        msg_ref = Ref(msg.message_data)
        Reseau.byte_buf_reserve(msg_ref, 2 + Reseau.TLS_RECORD_HEADER_LEN)
        msg.message_data = msg_ref[]
        buf = msg.message_data
        GC.@preserve buf begin
            ptr = pointer(getfield(buf, :mem))
            unsafe_store!(ptr, Reseau.TLS_RECORD_ALERT)
            unsafe_store!(ptr + 1, UInt8(0))
            unsafe_store!(ptr + 2, UInt8(0))
            unsafe_store!(ptr + 3, UInt8(0))
            unsafe_store!(ptr + 4, UInt8(2))
            unsafe_store!(ptr + 5, level)
            unsafe_store!(ptr + 6, desc)
        end
        setfield!(buf, :len, Csize_t(2 + Reseau.TLS_RECORD_HEADER_LEN))
        Reseau.handler_process_read_message(handler, slot, msg)
    end

    channel, slot, handler = new_alert_handler()
    send_alert!(handler, slot, Reseau.TLS_ALERT_LEVEL_WARNING, Reseau.TLS_ALERT_CLOSE_NOTIFY)
    @test channel.shutdown_error_code == Reseau.ERROR_IO_TLS_CLOSED_GRACEFUL

    channel, slot, handler = new_alert_handler()
    send_alert!(handler, slot, Reseau.TLS_ALERT_LEVEL_FATAL, UInt8(40))
    @test channel.shutdown_error_code == Reseau.ERROR_IO_TLS_ALERT_NOT_GRACEFUL

    channel, slot, handler = new_alert_handler()
    msg = Reseau.IoMessage(1 + Reseau.TLS_RECORD_HEADER_LEN)
    msg_ref = Ref(msg.message_data)
    Reseau.byte_buf_reserve(msg_ref, 1 + Reseau.TLS_RECORD_HEADER_LEN)
    msg.message_data = msg_ref[]
    buf = msg.message_data
    GC.@preserve buf begin
        ptr = pointer(getfield(buf, :mem))
        unsafe_store!(ptr, Reseau.TLS_RECORD_ALERT)
        unsafe_store!(ptr + 1, UInt8(0))
        unsafe_store!(ptr + 2, UInt8(0))
        unsafe_store!(ptr + 3, UInt8(0))
        unsafe_store!(ptr + 4, UInt8(1))
        unsafe_store!(ptr + 5, UInt8(0))
    end
    setfield!(buf, :len, Csize_t(1 + Reseau.TLS_RECORD_HEADER_LEN))
    Reseau.handler_process_read_message(handler, slot, msg)
    @test channel.shutdown_error_code == Reseau.ERROR_IO_TLS_ERROR_ALERT_RECEIVED

    Reseau.event_loop_group_destroy!(elg)
end

@testset "TLS handshake stats" begin
    if Sys.isapple() || Sys.islinux()
        @test true
        return
    end

    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Reseau.TlsContext
    if ctx isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    channel = Reseau.Channel(event_loop, nothing)
    left_slot = Reseau.channel_slot_new!(channel)
    left_sink = SinkHandler()
    Reseau.channel_slot_set_handler!(left_slot, left_sink)

    tls_slot = Reseau.channel_slot_new!(channel)
    Reseau.channel_slot_insert_right!(left_slot, tls_slot)
    right_slot = Reseau.channel_slot_new!(channel)
    Reseau.channel_slot_insert_right!(tls_slot, right_slot)
    right_sink = SinkHandler()
    Reseau.channel_slot_set_handler!(right_slot, right_sink)

    handler = Reseau.tls_client_handler_new(Reseau.TlsConnectionOptions(ctx), tls_slot)
    @test handler isa Reseau.TlsChannelHandler
    if handler isa Reseau.TlsChannelHandler
        @test Reseau.tls_client_handler_start_negotiation(handler) === nothing
        @test wait_for_handshake_status(handler, Reseau.TlsNegotiationStatus.ONGOING)
        @test handler.stats.handshake_start_ns > 0

        payload = Memory{UInt8}(undef, Reseau.TLS_NONCE_LEN)
        rand!(payload)
        msg = Reseau.IoMessage(Reseau.TLS_RECORD_HEADER_LEN + Reseau.TLS_NONCE_LEN)
        msg_ref = Ref(msg.message_data)
        Reseau.byte_buf_reserve(msg_ref, Reseau.TLS_RECORD_HEADER_LEN + Reseau.TLS_NONCE_LEN)
        msg.message_data = msg_ref[]
        buf = msg.message_data
        GC.@preserve buf payload begin
            ptr = pointer(getfield(buf, :mem))
            unsafe_store!(ptr, Reseau.TLS_HANDSHAKE_SERVER_HELLO)
            len = UInt32(Reseau.TLS_NONCE_LEN)
            unsafe_store!(ptr + 1, UInt8((len >> 24) & 0xFF))
            unsafe_store!(ptr + 2, UInt8((len >> 16) & 0xFF))
            unsafe_store!(ptr + 3, UInt8((len >> 8) & 0xFF))
            unsafe_store!(ptr + 4, UInt8(len & 0xFF))
            unsafe_copyto!(ptr + Reseau.TLS_RECORD_HEADER_LEN, pointer(payload), Reseau.TLS_NONCE_LEN)
        end
        setfield!(buf, :len, Csize_t(Reseau.TLS_RECORD_HEADER_LEN + Reseau.TLS_NONCE_LEN))
        Reseau.handler_process_read_message(handler, tls_slot, msg)
        @test wait_for_handshake_status(handler, Reseau.TlsNegotiationStatus.SUCCESS)
        @test handler.stats.handshake_end_ns >= handler.stats.handshake_start_ns
    end

    Reseau.event_loop_group_destroy!(elg)
end

@testset "TLS mTLS custom key op handshake" begin
    if Sys.isapple() || Sys.islinux()
        @test true
        return
    end

    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    called = Ref(false)
    op_ref = Ref{Any}(nothing)
    key_handler = Reseau.CustomKeyOpHandler(
        (handler_obj, operation) -> begin
            @test handler_obj isa Reseau.CustomKeyOpHandler
            @test Reseau.tls_key_operation_get_type(operation) == Reseau.TlsKeyOperationType.SIGN
            @test Reseau.tls_key_operation_get_digest_algorithm(operation) == Reseau.TlsHashAlgorithm.SHA256
            @test Reseau.tls_key_operation_get_signature_algorithm(operation) == Reseau.TlsSignatureAlgorithm.RSA
            called[] = true
            op_ref[] = operation
        end,
    )

    opts = Reseau.tls_ctx_options_init_client_mtls_with_custom_key_operations(
        key_handler,
        Reseau.ByteCursor(TEST_PEM_CERT),
    )
    @test opts isa Reseau.TlsContextOptions
    if opts isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    ctx = Reseau.tls_context_new(opts)
    @test ctx isa Reseau.TlsContext
    if ctx isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    channel = Reseau.Channel(event_loop, nothing)
    left_slot = Reseau.channel_slot_new!(channel)
    left_sink = SinkHandler()
    Reseau.channel_slot_set_handler!(left_slot, left_sink)

    tls_slot = Reseau.channel_slot_new!(channel)
    Reseau.channel_slot_insert_right!(left_slot, tls_slot)
    right_slot = Reseau.channel_slot_new!(channel)
    Reseau.channel_slot_insert_right!(tls_slot, right_slot)
    right_sink = SinkHandler()
    Reseau.channel_slot_set_handler!(right_slot, right_sink)

    tls_handler = Reseau.tls_client_handler_new(Reseau.TlsConnectionOptions(ctx), tls_slot)
    @test tls_handler isa Reseau.TlsChannelHandler
    if tls_handler isa Reseau.TlsChannelHandler
        @test Reseau.tls_client_handler_start_negotiation(tls_handler) === nothing
        @test wait_for_handshake_status(tls_handler, Reseau.TlsNegotiationStatus.ONGOING)

        payload = rand(UInt8, Reseau.TLS_NONCE_LEN)
        msg = Reseau.IoMessage(Reseau.TLS_RECORD_HEADER_LEN + Reseau.TLS_NONCE_LEN)
        msg_ref = Ref(msg.message_data)
        Reseau.byte_buf_reserve(msg_ref, Reseau.TLS_RECORD_HEADER_LEN + Reseau.TLS_NONCE_LEN)
        msg.message_data = msg_ref[]
        buf = msg.message_data
        GC.@preserve buf payload begin
            ptr = pointer(getfield(buf, :mem))
            unsafe_store!(ptr, Reseau.TLS_HANDSHAKE_SERVER_HELLO)
            len = UInt32(Reseau.TLS_NONCE_LEN)
            unsafe_store!(ptr + 1, UInt8((len >> 24) & 0xFF))
            unsafe_store!(ptr + 2, UInt8((len >> 16) & 0xFF))
            unsafe_store!(ptr + 3, UInt8((len >> 8) & 0xFF))
            unsafe_store!(ptr + 4, UInt8(len & 0xFF))
            unsafe_copyto!(ptr + Reseau.TLS_RECORD_HEADER_LEN, pointer(payload), Reseau.TLS_NONCE_LEN)
        end
        setfield!(buf, :len, Csize_t(Reseau.TLS_RECORD_HEADER_LEN + Reseau.TLS_NONCE_LEN))
        Reseau.handler_process_read_message(tls_handler, tls_slot, msg)

        @test wait_for_flag_tls(called)
        @test tls_handler.stats.handshake_status == Reseau.TlsNegotiationStatus.ONGOING

        op = op_ref[]
        @test op isa Reseau.TlsKeyOperation
        if op isa Reseau.TlsKeyOperation
            Reseau.tls_key_operation_complete!(op, Reseau.ByteCursor(UInt8[0x01]))
            @test wait_for_handshake_status(tls_handler, Reseau.TlsNegotiationStatus.SUCCESS)
        end
    end

    Reseau.event_loop_group_destroy!(elg)
end

@testset "tls handler" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    server_opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4)
    server_sock = Reseau.socket_init(server_opts)
    @test server_sock isa Reseau.Socket
    if server_sock isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    bind_endpoint = Reseau.SocketEndpoint("127.0.0.1", 0)
    @test Reseau.socket_bind(server_sock, Reseau.SocketBindOptions(bind_endpoint)) === nothing
    @test Reseau.socket_listen(server_sock, 16) === nothing

    server_ready = Ref(false)
    accept_started = Ref(false)
    server_negotiated = Ref(false)
    server_received = Ref(false)

    server_ctx = _test_server_ctx()
    @test server_ctx isa Reseau.TlsContext
    if server_ctx isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
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
        if err != Reseau.AWS_OP_SUCCESS
            return nothing
        end
        Reseau.socket_assign_to_event_loop(new_sock, event_loop)
        channel = Reseau.Channel(event_loop, nothing)
        Reseau.socket_channel_handler_new!(channel, new_sock)

        tls_opts = Reseau.TlsConnectionOptions(server_ctx; on_negotiation_result = on_server_negotiation)
        Reseau.tls_channel_handler_new!(channel, tls_opts)

        echo = EchoHandler(server_received)
        echo_slot = Reseau.channel_slot_new!(channel)
        if Reseau.channel_first_slot(channel) !== echo_slot
            Reseau.channel_slot_insert_end!(channel, echo_slot)
        end
        Reseau.channel_slot_set_handler!(echo_slot, echo)
        echo.slot = echo_slot

        Reseau.channel_setup_complete!(channel)
        server_ready[] = true
        return nothing
    end

    on_accept_start = (socket, err, ud) -> begin
        _ = socket
        _ = ud
        if err == Reseau.AWS_OP_SUCCESS
            accept_started[] = true
        end
        return nothing
    end

    listener_opts = Reseau.SocketListenerOptions(; on_accept_start = on_accept_start, on_accept_result = on_accept)
    @test Reseau.socket_start_accept(server_sock, event_loop, listener_opts) === nothing
    @test wait_for_flag_tls(accept_started)

    bound = Reseau.socket_get_bound_address(server_sock)
    @test bound isa Reseau.SocketEndpoint
    port = bound isa Reseau.SocketEndpoint ? bound.port : 0
    @test port > 0

    client_opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4)
    client_sock = Reseau.socket_init(client_opts)
    @test client_sock isa Reseau.Socket
    if client_sock isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    negotiated = Ref(false)
    read_done = Ref(false)
    read_payload = Ref("")

    on_data_read = (handler, slot, buf, ud) -> begin
        read_payload[] = String(Reseau.byte_cursor_from_buf(buf))
        read_done[] = true
        return nothing
    end

    on_negotiation = (handler, slot, err, ud) -> begin
        negotiated[] = true
        return nothing
    end

    client_ctx = Reseau.tls_context_new_client(; verify_peer = false)
    @test client_ctx isa Reseau.TlsContext
    if client_ctx isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    client_channel_ref = Ref{Any}(nothing)
    client_tls_ref = Ref{Any}(nothing)

    connect_opts = Reseau.SocketConnectOptions(
        Reseau.SocketEndpoint("127.0.0.1", port);
        event_loop = event_loop,
        on_connection_result = (sock_obj, err, ud) -> begin
            if err != Reseau.AWS_OP_SUCCESS
                negotiated[] = true
                return nothing
            end
            channel = Reseau.Channel(event_loop, nothing)
            Reseau.socket_channel_handler_new!(channel, sock_obj)
            tls_opts = Reseau.TlsConnectionOptions(
                client_ctx;
                server_name = "localhost",
                on_negotiation_result = on_negotiation,
                on_data_read = on_data_read,
            )
            tls_handler = Reseau.tls_channel_handler_new!(channel, tls_opts)
            if tls_handler isa Reseau.TlsChannelHandler
                client_channel_ref[] = channel
                client_tls_ref[] = tls_handler
                Reseau.tls_client_handler_start_negotiation(tls_handler)
            end
            Reseau.channel_setup_complete!(channel)
            return nothing
        end,
    )

    @test Reseau.socket_connect(client_sock, connect_opts) === nothing

    @test wait_for_flag_tls(server_ready)
    @test wait_for_flag_tls(negotiated)
    @test wait_for_flag_tls(server_negotiated)

    client_channel = client_channel_ref[]
    client_tls = client_tls_ref[]
    if client_channel isa Reseau.Channel && client_tls isa Reseau.TlsChannelHandler
        msg = Reseau.IoMessage(4)
        msg_ref = Ref(msg.message_data)
        Reseau.byte_buf_write_from_whole_cursor(msg_ref, Reseau.ByteCursor("ping"))
        msg.message_data = msg_ref[]

        ping_task = Reseau.ChannelTask()
        send_args = (handler = client_tls, slot = client_tls.slot, message = msg)
        send_fn = (task, args, status) -> begin
            _ = task
            if status == Reseau.TaskStatus.RUN_READY
                res = Reseau.handler_process_write_message(args.handler, args.slot, args.message)
                if res isa Reseau.ErrorResult && args.slot.channel !== nothing
                    Reseau.channel_release_message_to_pool!(args.slot.channel, args.message)
                end
            end
            return nothing
        end
        Reseau.channel_task_init!(ping_task, send_fn, send_args, "tls_test_send_ping")
        Reseau.channel_schedule_task_now!(client_channel, ping_task)
    end

    @test wait_for_flag_tls(read_done)
    @test read_payload[] == "pong"
    @test server_received[] == true

    Reseau.socket_close(server_sock)
    Reseau.socket_close(client_sock)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "channel_setup_client_tls" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Reseau.TlsContext
    if ctx isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    channel = Reseau.Channel(event_loop, nothing)
    left_slot = Reseau.channel_slot_new!(channel)
    sink = SinkHandler()
    Reseau.channel_slot_set_handler!(left_slot, sink)
    sink.slot = left_slot

    opts = Reseau.TlsConnectionOptions(ctx; timeout_ms = 1)
    handler = Reseau.channel_setup_client_tls(left_slot, opts)
    @test handler isa Reseau.TlsChannelHandler
    if handler isa Reseau.TlsChannelHandler
        @test left_slot.adj_right === handler.slot
        @test wait_for_handshake_status(handler, Reseau.TlsNegotiationStatus.ONGOING)
    end

    Reseau.event_loop_group_destroy!(elg)
end

@testset "TLS concurrent cert import" begin
    temp_dir = mktempdir()
    cert_path = joinpath(temp_dir, "cert.pem")
    key_path = joinpath(temp_dir, "key.pem")
    write(cert_path, TEST_PEM_CERT)
    write(key_path, TEST_PEM_KEY)

    function import_ctx()
        opts = Reseau.tls_ctx_options_init_client_mtls_from_path(cert_path, key_path)
        opts isa Reseau.TlsContextOptions || return opts
        maybe_apply_test_keychain!(opts)
        return Reseau.tls_client_ctx_new(opts)
    end

    tasks = [Threads.@spawn import_ctx() for _ in 1:2]
    ctxs = fetch.(tasks)
    @test all(ctx -> ctx isa Reseau.TlsContext, ctxs)
    for ctx in ctxs
        if ctx isa Reseau.TlsContext
            @test Reseau.tls_ctx_release(ctx) === nothing
        end
    end
end

@testset "TLS duplicate cert import" begin
    opts = Reseau.tls_ctx_options_init_client_mtls(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY),
    )
    @test opts isa Reseau.TlsContextOptions
    if opts isa Reseau.TlsContextOptions
        maybe_apply_test_keychain!(opts)
        ctx1 = Reseau.tls_client_ctx_new(opts)
        @test ctx1 isa Reseau.TlsContext
        if ctx1 isa Reseau.TlsContext
            @test Reseau.tls_ctx_release(ctx1) === nothing
        end

        maybe_apply_test_keychain!(opts)
        ctx2 = Reseau.tls_client_ctx_new(opts)
        @test ctx2 isa Reseau.TlsContext
        if ctx2 isa Reseau.TlsContext
            @test Reseau.tls_ctx_release(ctx2) === nothing
        end
    end
end

@testset "TLS pkcs8 import" begin
    cert_buf = _load_resource_buf("unittests.crt")
    key_buf = _load_resource_buf("unittests.p8")
    if cert_buf === nothing || key_buf === nothing
        @test true
    else
        opts = Reseau.tls_ctx_options_init_client_mtls(
            Reseau.byte_cursor_from_buf(cert_buf),
            Reseau.byte_cursor_from_buf(key_buf),
        )
        @test opts isa Reseau.TlsContextOptions
        if opts isa Reseau.TlsContextOptions
            maybe_apply_test_keychain!(opts)
            ctx = Reseau.tls_client_ctx_new(opts)
            @test ctx isa Reseau.TlsContext
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
        opts = Reseau.tls_ctx_options_init_client_mtls(
            Reseau.byte_cursor_from_buf(cert_buf),
            Reseau.byte_cursor_from_buf(key_buf),
        )
        @test opts isa Reseau.TlsContextOptions
        if opts isa Reseau.TlsContextOptions
            maybe_apply_test_keychain!(opts)
            ctx = Reseau.tls_client_ctx_new(opts)
            @test ctx isa Reseau.TlsContext
        end
        Reseau.byte_buf_clean_up(Ref(cert_buf))
        Reseau.byte_buf_clean_up(Ref(key_buf))
    end
end

@testset "TLS cipher preference" begin
    opts = Reseau.tls_ctx_options_init_default_client()
    Reseau.tls_ctx_options_set_tls_cipher_preference(
        opts,
        Reseau.TlsCipherPref.TLS_CIPHER_PREF_TLSV1_2_2025_07,
    )
    ctx = Reseau.tls_client_ctx_new(opts)
    if Reseau.tls_is_cipher_pref_supported(opts.cipher_pref)
        @test ctx isa Reseau.TlsContext
    else
        @test ctx isa Reseau.ErrorResult
        ctx isa Reseau.ErrorResult && @test ctx.code == Reseau.ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED
    end
end

function _tls_local_handshake_with_min_version(min_version::Reseau.TlsVersion.T)
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.HostResolver(elg)

    server_opts = Reseau.tls_ctx_options_init_default_server(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY),
    )
    server_opts isa Reseau.ErrorResult && return server_opts
    Reseau.tls_ctx_options_set_minimum_tls_version(server_opts, min_version)
    maybe_apply_test_keychain!(server_opts)
    server_ctx = Reseau.tls_context_new(server_opts)
    @test server_ctx isa Reseau.TlsContext
    if server_ctx isa Reseau.ErrorResult
        Reseau.host_resolver_shutdown!(resolver)
        Reseau.event_loop_group_destroy!(elg)
        return server_ctx
    end

    client_opts = Reseau.tls_ctx_options_init_default_client()
    Reseau.tls_ctx_options_set_minimum_tls_version(client_opts, min_version)
    res = Reseau.tls_ctx_options_override_default_trust_store_from_path(
        client_opts;
        ca_file = _resource_path("unittests.crt"),
    )
    res isa Reseau.ErrorResult && begin
        Reseau.host_resolver_shutdown!(resolver)
        Reseau.event_loop_group_destroy!(elg)
        return res
    end
    client_ctx = Reseau.tls_context_new(client_opts)
    @test client_ctx isa Reseau.TlsContext
    if client_ctx isa Reseau.ErrorResult
        Reseau.host_resolver_shutdown!(resolver)
        Reseau.event_loop_group_destroy!(elg)
        return client_ctx
    end

    server_setup_called = Ref(false)
    server_setup_err = Ref(Reseau.AWS_OP_SUCCESS)
    server_shutdown = Ref(false)
    server_channel = Ref{Any}(nothing)
    server_negotiated_called = Ref(false)
    server_negotiated_err = Ref(Reseau.AWS_OP_SUCCESS)
    listener_setup_called = Ref(false)
    listener_setup_err = Ref(Reseau.AWS_OP_SUCCESS)

    server_bootstrap = Reseau.ServerBootstrap(Reseau.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        tls_connection_options = Reseau.TlsConnectionOptions(
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
    bound = Reseau.socket_get_bound_address(listener)
    port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_bootstrap = Reseau.ClientBootstrap(Reseau.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    client_setup_called = Ref(false)
    client_setup_err = Ref(Reseau.AWS_OP_SUCCESS)
    client_shutdown = Ref(false)
    client_negotiated_called = Ref(false)
    client_negotiated_err = Ref(Reseau.AWS_OP_SUCCESS)
    client_channel = Ref{Any}(nothing)

    @test Reseau.client_bootstrap_connect!(
        client_bootstrap,
        "127.0.0.1",
        port;
        tls_connection_options = Reseau.TlsConnectionOptions(
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
    @test server_setup_err[] == Reseau.AWS_OP_SUCCESS
    @test wait_for_flag_tls(client_setup_called)
    @test client_setup_err[] == Reseau.AWS_OP_SUCCESS
    @test wait_for_flag_tls(server_negotiated_called)
    @test server_negotiated_err[] == Reseau.AWS_OP_SUCCESS
    @test wait_for_flag_tls(client_negotiated_called)
    @test client_negotiated_err[] == Reseau.AWS_OP_SUCCESS

    if server_channel[] !== nothing
        Reseau.channel_shutdown!(server_channel[], Reseau.AWS_OP_SUCCESS)
    end
    if client_channel[] !== nothing
        Reseau.channel_shutdown!(client_channel[], Reseau.AWS_OP_SUCCESS)
    end

    @test wait_for_flag_tls(server_shutdown)
    @test wait_for_flag_tls(client_shutdown)

    Reseau.server_bootstrap_shutdown!(server_bootstrap)
    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
    return nothing
end

@testset "TLS minimum version handshake (TLSv1_2)" begin
    _tls_local_handshake_with_min_version(Reseau.TlsVersion.TLSv1_2)
end

@testset "TLS minimum version handshake (TLSv1_3, linux s2n)" begin
    if !Sys.islinux()
        @test true
        return
    end
    if !Reseau.tls_is_alpn_available()
        @info "Skipping TLSv1_3 handshake test (s2n unavailable)"
        return
    end
    _tls_local_handshake_with_min_version(Reseau.TlsVersion.TLSv1_3)
end

@testset "TLS server multiple connections" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.HostResolver(elg)

    server_opts = Reseau.tls_ctx_options_init_default_server(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY),
    )
    maybe_apply_test_keychain!(server_opts)
    server_ctx = Reseau.tls_context_new(server_opts)
    @test server_ctx isa Reseau.TlsContext
    if server_ctx isa Reseau.ErrorResult
        Reseau.host_resolver_shutdown!(resolver)
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    client_ctx = _test_client_ctx()
    @test client_ctx isa Reseau.TlsContext
    if client_ctx isa Reseau.ErrorResult
        Reseau.host_resolver_shutdown!(resolver)
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    server_setup_called = Ref(false)
    server_setup_err = Ref(Reseau.AWS_OP_SUCCESS)
    server_shutdown = Ref(false)
    server_channel = Ref{Any}(nothing)
    server_negotiated_called = Ref(false)
    server_negotiated_err = Ref(Reseau.AWS_OP_SUCCESS)
    listener_setup_called = Ref(false)
    listener_setup_err = Ref(Reseau.AWS_OP_SUCCESS)

    server_bootstrap = Reseau.ServerBootstrap(Reseau.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        tls_connection_options = Reseau.TlsConnectionOptions(
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
    bound = Reseau.socket_get_bound_address(listener)
    port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_bootstrap = Reseau.ClientBootstrap(Reseau.ClientBootstrapOptions(
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

        @test Reseau.client_bootstrap_connect!(
            client_bootstrap,
            "127.0.0.1",
            port;
            tls_connection_options = Reseau.TlsConnectionOptions(
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
        @test server_setup_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag_tls(client_setup_called)
        @test client_setup_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag_tls(server_negotiated_called)
        @test server_negotiated_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag_tls(client_negotiated_called)
        @test client_negotiated_err[] == Reseau.AWS_OP_SUCCESS

        if server_channel[] !== nothing
            Reseau.channel_shutdown!(server_channel[], Reseau.AWS_OP_SUCCESS)
        end

        @test wait_for_flag_tls(server_shutdown)
        @test wait_for_flag_tls(client_shutdown)
    end

    connect_once!()
    connect_once!()

    Reseau.server_bootstrap_shutdown!(server_bootstrap)
    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "TLS server hangup during negotiation" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.HostResolver(elg)

    server_opts = Reseau.tls_ctx_options_init_default_server(
        Reseau.ByteCursor(TEST_PEM_CERT),
        Reseau.ByteCursor(TEST_PEM_KEY),
    )
    maybe_apply_test_keychain!(server_opts)
    server_ctx = Reseau.tls_context_new(server_opts)
    @test server_ctx isa Reseau.TlsContext
    if server_ctx isa Reseau.ErrorResult
        Reseau.host_resolver_shutdown!(resolver)
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    listener_destroyed = Ref(false)
    listener_setup_called = Ref(false)
    listener_setup_err = Ref(Reseau.AWS_OP_SUCCESS)
    server_bootstrap = Reseau.ServerBootstrap(Reseau.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        tls_connection_options = Reseau.TlsConnectionOptions(server_ctx),
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
    bound = Reseau.socket_get_bound_address(listener)
    port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4)
    client_socket = Reseau.socket_init(client_opts)
    @test client_socket isa Reseau.Socket
    if client_socket isa Reseau.ErrorResult
        Reseau.server_bootstrap_shutdown!(server_bootstrap)
        Reseau.host_resolver_shutdown!(resolver)
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    close_done = Ref(false)
    connect_opts = Reseau.SocketConnectOptions(
        Reseau.SocketEndpoint("127.0.0.1", port);
        event_loop = Reseau.event_loop_group_get_next_loop(elg),
        on_connection_result = (sock, err, ud) -> begin
            if err != Reseau.AWS_OP_SUCCESS
                close_done[] = true
                return nothing
            end
            now = Reseau.event_loop_current_clock_time(sock.event_loop)
            if now isa Reseau.ErrorResult
                close_done[] = true
                return nothing
            end
            task = Reseau.ScheduledTask((ctx, status) -> begin
                status == Reseau.TaskStatus.RUN_READY || return nothing
                Reseau.socket_close(ctx)
                close_done[] = true
                return nothing
            end, sock; type_tag = "close_client_socket")
            Reseau.event_loop_schedule_task_future!(sock.event_loop, task, now + UInt64(1_000_000_000))
            return nothing
        end,
    )

    @test Reseau.socket_connect(client_socket, connect_opts) === nothing
    @test wait_for_flag_tls(close_done)

    Reseau.server_bootstrap_shutdown!(server_bootstrap)
    @test wait_for_flag_tls(listener_destroyed)

    Reseau.socket_close(client_socket)
    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "TLS certificate chain" begin
    cert_buf = _load_resource_buf("server_chain.crt")
    key_buf = _load_resource_buf("server.key")
    if cert_buf === nothing || key_buf === nothing
        @test true
        return
    end

    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.HostResolver(elg)

    server_opts = if Sys.isapple()
        Reseau.tls_ctx_options_init_server_pkcs12_from_path(_resource_path("unittests.p12"), "1234")
    else
        Reseau.tls_ctx_options_init_default_server(
            Reseau.byte_cursor_from_buf(cert_buf),
            Reseau.byte_cursor_from_buf(key_buf),
        )
    end
    maybe_apply_test_keychain!(server_opts)
    server_ctx = Reseau.tls_context_new(server_opts)
    @test server_ctx isa Reseau.TlsContext
    if server_ctx isa Reseau.ErrorResult
        Reseau.host_resolver_shutdown!(resolver)
        Reseau.event_loop_group_destroy!(elg)
        Reseau.byte_buf_clean_up(Ref(cert_buf))
        Reseau.byte_buf_clean_up(Ref(key_buf))
        return
    end

    client_ctx = _test_client_ctx()
    @test client_ctx isa Reseau.TlsContext
    if client_ctx isa Reseau.ErrorResult
        Reseau.host_resolver_shutdown!(resolver)
        Reseau.event_loop_group_destroy!(elg)
        Reseau.byte_buf_clean_up(Ref(cert_buf))
        Reseau.byte_buf_clean_up(Ref(key_buf))
        return
    end

    server_setup = Ref(false)
    client_setup = Ref(false)
    server_negotiated = Ref(false)
    client_negotiated = Ref(false)
    server_channel = Ref{Any}(nothing)
    client_channel = Ref{Any}(nothing)
    listener_setup_called = Ref(false)
    listener_setup_err = Ref(Reseau.AWS_OP_SUCCESS)

    server_bootstrap = Reseau.ServerBootstrap(Reseau.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        tls_connection_options = Reseau.TlsConnectionOptions(
            server_ctx;
            on_negotiation_result = (handler, slot, err, ud) -> begin
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
    bound = Reseau.socket_get_bound_address(listener)
    port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_bootstrap = Reseau.ClientBootstrap(Reseau.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    @test Reseau.client_bootstrap_connect!(
        client_bootstrap,
        "127.0.0.1",
        port;
        tls_connection_options = Reseau.TlsConnectionOptions(
            client_ctx;
            server_name = "localhost",
            on_negotiation_result = (handler, slot, err, ud) -> begin
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
        Reseau.channel_shutdown!(server_channel[], Reseau.AWS_OP_SUCCESS)
    end
    if client_channel[] !== nothing
        Reseau.channel_shutdown!(client_channel[], Reseau.AWS_OP_SUCCESS)
    end

    Reseau.server_bootstrap_shutdown!(server_bootstrap)
    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)

    Reseau.byte_buf_clean_up(Ref(cert_buf))
    Reseau.byte_buf_clean_up(Ref(key_buf))
end

@testset "TLS handler overhead + max fragment size" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    ctx = _test_client_ctx()
    @test ctx isa Reseau.TlsContext
    if ctx isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    prev_max = Reseau.g_aws_channel_max_fragment_size[]
    Reseau.g_aws_channel_max_fragment_size[] = Csize_t(4096)

    channel = Reseau.Channel(event_loop, nothing)
    tls_slot = Reseau.channel_slot_new!(channel)
    handler = Reseau.tls_client_handler_new(Reseau.TlsConnectionOptions(ctx), tls_slot)
    @test handler isa Reseau.TlsChannelHandler
    handler isa Reseau.TlsChannelHandler && Reseau.channel_slot_set_handler!(tls_slot, handler)

    app_slot = Reseau.channel_slot_new!(channel)
    Reseau.channel_slot_insert_right!(tls_slot, app_slot)
    app_handler = SinkHandler()
    Reseau.channel_slot_set_handler!(app_slot, app_handler)

    results = Channel{Int}(1)
    task = Reseau.ScheduledTask(
        (ctx, status) -> begin
            status == Reseau.TaskStatus.RUN_READY || return nothing
            msg = Reseau.channel_slot_acquire_max_message_for_write(ctx.slot)
            if msg isa Reseau.IoMessage
                cap = length(msg.message_data.mem)
                Reseau.channel_release_message_to_pool!(ctx.channel, msg)
                put!(ctx.results, cap)
            else
                put!(ctx.results, -1)
            end
            return nothing
        end,
        (slot = app_slot, channel = channel, results = results);
        type_tag = "tls_overhead_test",
    )
    Reseau.event_loop_schedule_task_now!(event_loop, task)

    cap = take!(results)
    expected = Int(Reseau.g_aws_channel_max_fragment_size[] - Csize_t(Reseau.TLS_EST_RECORD_OVERHEAD))
    @test cap == expected

    if handler isa Reseau.TlsChannelHandler
        @test Reseau.handler_message_overhead(handler) == Csize_t(Reseau.TLS_EST_RECORD_OVERHEAD)
        @test Reseau.handler_initial_window_size(handler) == Csize_t(Reseau.TLS_EST_HANDSHAKE_SIZE)
    end

    Reseau.g_aws_channel_max_fragment_size[] = prev_max
    Reseau.event_loop_group_destroy!(elg)
end

@testset "TLS echo + backpressure" begin
    if Sys.iswindows() || Threads.nthreads(:interactive) <= 1
        @test true
        return
    end

    prev_max = Reseau.g_aws_channel_max_fragment_size[]
    Reseau.g_aws_channel_max_fragment_size[] = 4096

    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.HostResolver(elg)

    server_ctx = _test_server_ctx()
    client_ctx = Reseau.tls_context_new_client(; verify_peer = false)
    @test server_ctx isa Reseau.TlsContext
    @test client_ctx isa Reseau.TlsContext
    if !(server_ctx isa Reseau.TlsContext) || !(client_ctx isa Reseau.TlsContext)
        Reseau.host_resolver_shutdown!(resolver)
        Reseau.event_loop_group_destroy!(elg)
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

    server_bootstrap = Reseau.ServerBootstrap(Reseau.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        enable_read_back_pressure = true,
        tls_connection_options = Reseau.TlsConnectionOptions(server_ctx),
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
                slot = Reseau.channel_slot_new!(channel)
                if Reseau.channel_first_slot(channel) !== slot
                    Reseau.channel_slot_insert_end!(channel, slot)
                end
                Reseau.channel_slot_set_handler!(slot, handler)
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
    bound = Reseau.socket_get_bound_address(listener)
    @test bound isa Reseau.SocketEndpoint
    port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_bootstrap = Reseau.ClientBootstrap(Reseau.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    client_tls_opts = Reseau.TlsConnectionOptions(
        client_ctx;
        server_name = "localhost",
    )

    connect_res = Reseau.client_bootstrap_connect!(
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
                slot = Reseau.channel_slot_new!(channel)
                if Reseau.channel_first_slot(channel) !== slot
                    Reseau.channel_slot_insert_end!(channel, slot)
                end
                Reseau.channel_slot_set_handler!(slot, handler)
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

    Reseau.server_bootstrap_shutdown!(server_bootstrap)
    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
    Reseau.g_aws_channel_max_fragment_size[] = prev_max
end

@testset "TLS shutdown with cached data" begin
    if Sys.iswindows() || Threads.nthreads(:interactive) <= 1
        @test true
        return
    end

    for window_update_after_shutdown in (false, true)
        prev_max = Reseau.g_aws_channel_max_fragment_size[]
        Reseau.g_aws_channel_max_fragment_size[] = 4096

        elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
        resolver = Reseau.HostResolver(elg)

        server_ctx = _test_server_ctx()
        client_ctx = Reseau.tls_context_new_client(; verify_peer = false)
        @test server_ctx isa Reseau.TlsContext
        @test client_ctx isa Reseau.TlsContext
        if !(server_ctx isa Reseau.TlsContext) || !(client_ctx isa Reseau.TlsContext)
            Reseau.host_resolver_shutdown!(resolver)
            Reseau.event_loop_group_destroy!(elg)
            Reseau.g_aws_channel_max_fragment_size[] = prev_max
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
                    Reseau.channel_shutdown!(server_channel_ref[], Reseau.AWS_OP_SUCCESS)
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

        server_bootstrap = Reseau.ServerBootstrap(Reseau.ServerBootstrapOptions(
            event_loop_group = elg,
            host = "127.0.0.1",
            port = 0,
            enable_read_back_pressure = true,
            tls_connection_options = Reseau.TlsConnectionOptions(server_ctx),
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
                    slot = Reseau.channel_slot_new!(channel)
                    if Reseau.channel_first_slot(channel) !== slot
                        Reseau.channel_slot_insert_end!(channel, slot)
                    end
                    Reseau.channel_slot_set_handler!(slot, handler)
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
        bound = Reseau.socket_get_bound_address(listener)
        port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
        @test port != 0

        client_bootstrap = Reseau.ClientBootstrap(Reseau.ClientBootstrapOptions(
            event_loop_group = elg,
            host_resolver = resolver,
        ))

        client_tls_opts = Reseau.TlsConnectionOptions(
            client_ctx;
            server_name = "localhost",
        )

        connect_res = Reseau.client_bootstrap_connect!(
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
                    slot = Reseau.channel_slot_new!(channel)
                    if Reseau.channel_first_slot(channel) !== slot
                        Reseau.channel_slot_insert_end!(channel, slot)
                    end
                    Reseau.channel_slot_set_handler!(slot, handler)
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

        Reseau.server_bootstrap_shutdown!(server_bootstrap)
        Reseau.host_resolver_shutdown!(resolver)
        Reseau.event_loop_group_destroy!(elg)
        Reseau.g_aws_channel_max_fragment_size[] = prev_max
    end
end

@testset "TLS statistics handler integration" begin
    if Sys.iswindows() || Threads.nthreads(:interactive) <= 1
        @test true
        return
    end

    mutable struct TestTlsStatisticsHandler <: Reseau.StatisticsHandler
        report_ms::UInt64
        results::Channel{Tuple{Reseau.StatisticsSampleInterval, Vector{Any}}}
    end

    Reseau.report_interval_ms(handler::TestTlsStatisticsHandler) = handler.report_ms
    Reseau.close!(::TestTlsStatisticsHandler) = nothing

    function Reseau.process_statistics(
            handler::TestTlsStatisticsHandler,
            interval::Reseau.StatisticsSampleInterval,
            stats_list::AbstractVector,
        )
        stats = Vector{Any}(undef, length(stats_list))
        for i in 1:length(stats_list)
            entry = stats_list[i]
            if entry isa Reseau.SocketHandlerStatistics
                stats[i] = Reseau.SocketHandlerStatistics(entry.category, entry.bytes_read, entry.bytes_written)
            elseif entry isa Reseau.TlsHandlerStatistics
                stats[i] = Reseau.TlsHandlerStatistics(
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

    mutable struct FakeSocketStatsHandler <: Reseau.AbstractChannelHandler
        stats::Reseau.SocketHandlerStatistics
    end

    FakeSocketStatsHandler() = FakeSocketStatsHandler(Reseau.SocketHandlerStatistics())

    Reseau.handler_process_read_message(::FakeSocketStatsHandler, ::Reseau.ChannelSlot, ::Reseau.IoMessage) = nothing
    Reseau.handler_process_write_message(::FakeSocketStatsHandler, ::Reseau.ChannelSlot, ::Reseau.IoMessage) = nothing
    Reseau.handler_increment_read_window(::FakeSocketStatsHandler, ::Reseau.ChannelSlot, ::Csize_t) = nothing
    Reseau.handler_initial_window_size(::FakeSocketStatsHandler) = Csize_t(0)
    Reseau.handler_message_overhead(::FakeSocketStatsHandler) = Csize_t(0)
    Reseau.handler_destroy(::FakeSocketStatsHandler) = nothing

    function Reseau.handler_shutdown(
            ::FakeSocketStatsHandler,
            slot::Reseau.ChannelSlot,
            direction::Reseau.ChannelDirection.T,
            error_code::Int,
            free_scarce_resources_immediately::Bool,
        )
        Reseau.channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
        return nothing
    end

    function Reseau.handler_reset_statistics(handler::FakeSocketStatsHandler)::Nothing
        Reseau.crt_statistics_socket_reset!(handler.stats)
        return nothing
    end

    Reseau.handler_gather_statistics(handler::FakeSocketStatsHandler) = handler.stats

    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    event_loop === nothing && return

    channel = Reseau.Channel(event_loop, nothing)

    socket_handler = FakeSocketStatsHandler()
    socket_slot = Reseau.channel_slot_new!(channel)
    Reseau.channel_slot_set_handler!(socket_slot, socket_handler)

    client_ctx = Reseau.tls_context_new_client(; verify_peer = false)
    @test client_ctx isa Reseau.TlsContext
    client_ctx isa Reseau.TlsContext || return
    tls_slot = Reseau.channel_slot_new!(channel)
    tls_handler = Reseau.tls_client_handler_new(Reseau.TlsConnectionOptions(client_ctx), tls_slot)
    @test tls_handler isa Reseau.TlsChannelHandler
    tls_handler isa Reseau.TlsChannelHandler || return
    Reseau.channel_slot_insert_right!(socket_slot, tls_slot)
    Reseau.channel_slot_set_handler!(tls_slot, tls_handler)

    Reseau.channel_setup_complete!(channel)

    stats_results = Channel{Tuple{Reseau.StatisticsSampleInterval, Vector{Any}}}(1)
    stats_handler = TestTlsStatisticsHandler(UInt64(50), stats_results)

    set_task = Reseau.ScheduledTask(
        (ch, _status) -> Reseau.channel_set_statistics_handler!(ch, stats_handler),
        channel;
        type_tag = "set_tls_stats",
    )
    Reseau.event_loop_schedule_task_now!(event_loop, set_task)

    update_task = Reseau.ScheduledTask(
        (_ctx, _status) -> begin
            socket_handler.stats.bytes_read = 111
            socket_handler.stats.bytes_written = 222
            Reseau.handler_gather_statistics(tls_handler).handshake_status = Reseau.TlsNegotiationStatus.SUCCESS
            return nothing
        end,
        nothing;
        type_tag = "update_tls_stats",
    )
    Reseau.event_loop_schedule_task_now!(event_loop, update_task)

    @test wait_for_stats(stats_results)
    interval, stats_vec = take!(stats_results)
    @test interval.end_time_ms >= interval.begin_time_ms

    socket_stats = nothing
    tls_stats = nothing
    for entry in stats_vec
        if entry isa Reseau.SocketHandlerStatistics
            socket_stats = entry
        elseif entry isa Reseau.TlsHandlerStatistics
            tls_stats = entry
        end
    end

    @test socket_stats isa Reseau.SocketHandlerStatistics
    @test tls_stats isa Reseau.TlsHandlerStatistics
    if socket_stats isa Reseau.SocketHandlerStatistics
        @test socket_stats.bytes_read > 0
        @test socket_stats.bytes_written > 0
    end
    if tls_stats isa Reseau.TlsHandlerStatistics
        @test tls_stats.handshake_status == Reseau.TlsNegotiationStatus.SUCCESS
    end

    Reseau.channel_shutdown!(channel, Reseau.AWS_OP_SUCCESS)
    Reseau.event_loop_group_destroy!(elg)
end

if get(ENV, "RESEAU_RUN_NETWORK_TESTS", "0") == "1"
    @testset "TLS network negotiation (requires network)" begin
        disable_verify_peer = opts -> Reseau.tls_ctx_options_set_verify_peer(opts, false)

        set_tls13 = opts -> Reseau.tls_ctx_options_set_minimum_tls_version(opts, Reseau.TlsVersion.TLSv1_3)

        function override_ca_file(path::AbstractString)
            return opts -> Reseau.tls_ctx_options_override_default_trust_store_from_path(opts; ca_file = path)
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
