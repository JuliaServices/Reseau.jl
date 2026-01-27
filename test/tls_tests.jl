using Test
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

@testset "TLS options parity" begin
    opts = AwsIO.tls_ctx_options_init_default_client()
    @test !opts.is_server
    @test opts.verify_peer

    AwsIO.tls_ctx_options_set_verify_peer!(opts, false)
    @test !opts.verify_peer

    AwsIO.tls_ctx_options_set_minimum_tls_version!(opts, AwsIO.TlsVersion.TLSv1_2)
    @test opts.minimum_tls_version == AwsIO.TlsVersion.TLSv1_2

    AwsIO.tls_ctx_options_set_tls_cipher_preference!(
        opts,
        AwsIO.TlsCipherPref.TLS_CIPHER_PREF_SYSTEM_DEFAULT,
    )
    @test AwsIO.tls_is_cipher_pref_supported(opts.cipher_pref)

    AwsIO.tls_ctx_options_override_default_trust_store!(
        opts;
        ca_file = "cafile",
        ca_path = "/tmp",
        ca_data = "cadata",
    )
    @test opts.ca_file == "cafile"
    @test opts.ca_path == "/tmp"
    @test opts.ca_data == "cadata"

    ctx = AwsIO.tls_context_new(opts)
    @test ctx isa AwsIO.TlsContext

    conn = AwsIO.tls_connection_options_init_from_ctx(ctx)
    AwsIO.tls_connection_options_set_server_name!(conn, "example.com")
    AwsIO.tls_connection_options_set_alpn_list!(conn, "h2")
    AwsIO.tls_connection_options_set_timeout_ms!(conn, 250)
    AwsIO.tls_connection_options_set_advertise_alpn_message!(conn, true)

    cb1 = (handler, slot, err, ud) -> nothing
    cb2 = (handler, slot, buf, ud) -> nothing
    cb3 = (handler, slot, err, msg, ud) -> nothing
    AwsIO.tls_connection_options_set_callbacks!(conn, cb1, cb2, cb3, 123)

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
