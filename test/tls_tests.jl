using Test
using Random
using AwsIO

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

function wait_for_handshake_status(handler::AwsIO.TlsChannelHandler, status; timeout_s::Float64 = 5.0)
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

const TEST_PEM_CERT = """
-----BEGIN CERTIFICATE-----
dGVzdA==
-----END CERTIFICATE-----
"""

const TEST_PEM_KEY = """
-----BEGIN PRIVATE KEY-----
dGVzdA==
-----END PRIVATE KEY-----
"""

function _buf_to_string(buf::AwsIO.ByteBuffer)
    return String(AwsIO.byte_cursor_from_buf(buf))
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
    ctx = AwsIO.tls_context_new(AwsIO.tls_ctx_options_init_default_client())
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

@testset "TLS error code predicate" begin
    @test AwsIO.io_error_code_is_tls(AwsIO.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
    @test AwsIO.io_error_code_is_tls(AwsIO.ERROR_IO_TLS_HOST_NAME_MISMATCH)
    @test !AwsIO.io_error_code_is_tls(AwsIO.ERROR_IO_SOCKET_TIMEOUT)
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
        @test AwsIO.tls_ctx_options_set_keychain_path(opts, "/tmp") === nothing
        secitem = AwsIO.SecItemOptions("cert", "key")
        @test AwsIO.tls_ctx_options_set_secitem_options(opts, secitem) === nothing
    else
        @test AwsIO.tls_ctx_options_set_keychain_path(opts, "/tmp") isa AwsIO.ErrorResult
        secitem = AwsIO.SecItemOptions("cert", "key")
        @test AwsIO.tls_ctx_options_set_secitem_options(opts, secitem) isa AwsIO.ErrorResult
    end
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

    ctx = AwsIO.tls_context_new(AwsIO.tls_ctx_options_init_default_client())
    @test ctx isa AwsIO.TlsContext
    if ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    opts = AwsIO.TlsConnectionOptions(ctx; timeout_ms = 1)
    handler = AwsIO.TlsChannelHandler(opts)
    channel = AwsIO.Channel(event_loop, nothing)
    slot = AwsIO.channel_slot_new!(channel)
    handler.slot = slot
    AwsIO.channel_slot_set_handler!(slot, handler)

    handler.stats.handshake_status = AwsIO.TlsNegotiationStatus.ONGOING
    AwsIO._tls_timeout_task(handler.timeout_task, handler, AwsIO.TaskStatus.RUN_READY)

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

    conn = AwsIO.tls_connection_options_init_from_ctx(ctx)
    AwsIO.tls_connection_options_set_server_name(conn, "example.com")
    handler = AwsIO.TlsChannelHandler(conn)

    @test _buf_to_string(AwsIO.tls_handler_server_name(handler)) == "example.com"
    @test AwsIO.tls_handler_protocol(handler).len == 0

    handler.protocol = AwsIO.byte_buf_from_c_str("h2")
    @test _buf_to_string(AwsIO.tls_handler_protocol(handler)) == "h2"
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

mutable struct SinkHandler <: AwsIO.AbstractChannelHandler
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

    ctx = AwsIO.tls_context_new(AwsIO.tls_ctx_options_init_default_client())
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

    client_ctx = AwsIO.tls_context_new(AwsIO.tls_ctx_options_init_default_client())
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
        @test client_handler.options.server_name == "example.com"
        @test client_handler.stats.handshake_status == AwsIO.TlsNegotiationStatus.NONE
        @test AwsIO.tls_client_handler_start_negotiation(client_handler) === nothing
        @test wait_for_handshake_status(client_handler, AwsIO.TlsNegotiationStatus.ONGOING)
    end

    server_opts = AwsIO.tls_ctx_options_init_default_server(
        AwsIO.ByteCursor(TEST_PEM_CERT),
        AwsIO.ByteCursor(TEST_PEM_KEY),
    )
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
                @test server_handler.stats.handshake_status == AwsIO.TlsNegotiationStatus.NONE
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

    ctx = AwsIO.tls_context_new(AwsIO.tls_ctx_options_init_default_client())
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
    handler = AwsIO.TlsChannelHandler(opts)
    handler.negotiation_completed = true
    handler.slot = slot
    AwsIO.channel_slot_set_handler!(slot, handler)

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

    ctx = AwsIO.tls_context_new(AwsIO.tls_ctx_options_init_default_client())
    @test ctx isa AwsIO.TlsContext
    if ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    channel = AwsIO.Channel(event_loop, nothing)
    slot = AwsIO.channel_slot_new!(channel)
    handler = AwsIO.TlsChannelHandler(AwsIO.TlsConnectionOptions(ctx))
    handler.slot = slot
    AwsIO.channel_slot_set_handler!(slot, handler)

    msg = AwsIO.IoMessage(1)
    msg_ref = Ref(msg.message_data)
    AwsIO.byte_buf_write_from_whole_cursor(msg_ref, AwsIO.ByteCursor(UInt8[0x01]))
    msg.message_data = msg_ref[]
    AwsIO.handler_process_write_message(handler, slot, msg)
    @test length(handler.pending_writes) == 1

    AwsIO.handler_shutdown(handler, slot, AwsIO.ChannelDirection.WRITE, 0, false)
    @test isempty(handler.pending_writes)

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

    ctx = AwsIO.tls_context_new(AwsIO.tls_ctx_options_init_default_client())
    @test ctx isa AwsIO.TlsContext
    if ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    channel = AwsIO.Channel(event_loop, nothing)
    slot = AwsIO.channel_slot_new!(channel)
    handler = AwsIO.TlsChannelHandler(AwsIO.TlsConnectionOptions(ctx))
    handler.state = AwsIO.TlsHandshakeState.FAILED
    handler.slot = slot
    AwsIO.channel_slot_set_handler!(slot, handler)

    msg = AwsIO.IoMessage(1)
    msg_ref = Ref(msg.message_data)
    AwsIO.byte_buf_write_from_whole_cursor(msg_ref, AwsIO.ByteCursor(UInt8[0x02]))
    msg.message_data = msg_ref[]
    res = AwsIO.handler_process_write_message(handler, slot, msg)
    @test res isa AwsIO.ErrorResult
    if res isa AwsIO.ErrorResult
        @test res.code == AwsIO.ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE
    end
    @test isempty(handler.pending_writes)

    AwsIO.event_loop_group_destroy!(elg)
end

@testset "TLS alert handling" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    ctx = AwsIO.tls_context_new(AwsIO.tls_ctx_options_init_default_client())
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
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    ctx = AwsIO.tls_context_new(AwsIO.tls_ctx_options_init_default_client())
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
    server_received = Ref(false)

    server_ctx = AwsIO.tls_context_new(AwsIO.TlsContextOptions(; is_server = true, verify_peer = false))
    @test server_ctx isa AwsIO.TlsContext
    if server_ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    on_accept = (listener, err, new_sock, ud) -> begin
        if err != AwsIO.AWS_OP_SUCCESS
            return nothing
        end
        AwsIO.socket_assign_to_event_loop(new_sock, event_loop)
        channel = AwsIO.Channel(event_loop, nothing)
        AwsIO.socket_channel_handler_new!(channel, new_sock)

        tls_opts = AwsIO.TlsConnectionOptions(server_ctx)
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
        if err != AwsIO.AWS_OP_SUCCESS
            return nothing
        end
        msg = AwsIO.IoMessage(4)
        msg_ref = Ref(msg.message_data)
        AwsIO.byte_buf_write_from_whole_cursor(msg_ref, AwsIO.ByteCursor("ping"))
        msg.message_data = msg_ref[]
        AwsIO.handler_process_write_message(handler, slot, msg)
        return nothing
    end

    client_ctx = AwsIO.tls_context_new_client(; verify_peer = false)
    @test client_ctx isa AwsIO.TlsContext
    if client_ctx isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

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
            AwsIO.tls_channel_handler_new!(channel, tls_opts)
            AwsIO.channel_setup_complete!(channel)
            return nothing
        end,
    )

    @test AwsIO.socket_connect(client_sock, connect_opts) === nothing

    @test wait_for_flag_tls(server_ready)
    @test wait_for_flag_tls(negotiated)
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

    ctx = AwsIO.tls_context_new(AwsIO.tls_ctx_options_init_default_client())
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
        ctx1 = AwsIO.tls_client_ctx_new(opts)
        @test ctx1 isa AwsIO.TlsContext
        if ctx1 isa AwsIO.TlsContext
            @test AwsIO.tls_ctx_release(ctx1) === nothing
        end

        ctx2 = AwsIO.tls_client_ctx_new(opts)
        @test ctx2 isa AwsIO.TlsContext
        if ctx2 isa AwsIO.TlsContext
            @test AwsIO.tls_ctx_release(ctx2) === nothing
        end
    end
end
