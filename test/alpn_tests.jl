using Test
using Reseau
include("read_write_test_handler.jl")

function wait_for_flag_alpn(flag::Base.RefValue{Bool}; timeout_s::Float64 = 2.0)
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

@testset "alpn handler" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.get_next_event_loop()
    @test event_loop !== nothing
    if event_loop === nothing
        close(elg)
        return
    end

    channel = Sockets.Channel(event_loop, nothing)
    setup_done = Ref(false)
    shutdown_done = Ref(false)

    Sockets.channel_set_setup_callback!(
        channel,
        Reseau.ChannelCallable((err, _channel) -> begin
            setup_done[] = true
            return nothing
        end),
    )

    Sockets.channel_set_shutdown_callback!(
        channel,
        Reseau.EventCallable(err -> begin
            shutdown_done[] = true
            return nothing
        end),
    )

    slot = Sockets.channel_slot_new!(channel)
    if Sockets.channel_first_slot(channel) !== slot
        Sockets.channel_slot_insert_front!(channel, slot)
    end

    handler = Sockets.tls_alpn_handler_new()
    Sockets.channel_slot_set_handler!(slot, handler)
    handler.slot = slot

    Sockets.channel_setup_complete!(channel)
    @test wait_for_flag_alpn(setup_done)

    message = EventLoops.IoMessage(sizeof(Sockets.TlsNegotiatedProtocolMessage))
    message.message_tag = EventLoops.TLS_NEGOTIATED_PROTOCOL_MESSAGE
    message.user_data = Sockets.TlsNegotiatedProtocolMessage(Reseau.byte_buf_from_c_str("h2"))
    message.message_data.len = Csize_t(sizeof(Sockets.TlsNegotiatedProtocolMessage))

    @test Sockets.handler_process_read_message(handler, slot, message) === nothing
    @test Sockets.negotiated_protocol(channel) == "h2"
    @test channel.first === slot
    @test channel.last === slot

    Sockets.channel_shutdown!(channel, Reseau.OP_SUCCESS)
    @test wait_for_flag_alpn(shutdown_done)
    close(elg)
end

@testset "alpn missing protocol message" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.get_next_event_loop()
    @test event_loop !== nothing
    if event_loop === nothing
        close(elg)
        return
    end

    channel = Sockets.Channel(event_loop, nothing)
    slot = Sockets.channel_slot_new!(channel)
    if Sockets.channel_first_slot(channel) !== slot
        Sockets.channel_slot_insert_front!(channel, slot)
    end

    handler = Sockets.tls_alpn_handler_new()
    Sockets.channel_slot_set_handler!(slot, handler)
    handler.slot = slot

    message = EventLoops.IoMessage(0)
    message.message_tag = 0

    try
        Sockets.handler_process_read_message(handler, slot, message)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == EventLoops.ERROR_IO_MISSING_ALPN_MESSAGE
    end

    Sockets.channel_shutdown!(channel, Reseau.OP_SUCCESS)
    close(elg)
end

@testset "alpn empty protocol does not send message" begin
    if !Sys.isapple()
        @test true
        return
    end
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.get_next_event_loop()
    @test event_loop !== nothing
    if event_loop === nothing
        close(elg)
        return
    end
    channel = Sockets.Channel(event_loop, nothing)
    left_slot = Sockets.channel_slot_new!(channel)
    right_slot = Sockets.channel_slot_new!(channel)
    Sockets.channel_slot_insert_right!(left_slot, right_slot)
    message_count = Ref(0)
    handler = ReadWriteTestHandler(
        (_, _, _, _) -> begin
            message_count[] += 1
            return nothing
        end,
        (_, _, _, _) -> nothing;
        event_loop_driven = false,
        window = sizeof(Sockets.TlsNegotiatedProtocolMessage),
    )
    Sockets.channel_slot_set_handler!(right_slot, handler)
    tls_handler = Sockets.SecureTransportTlsHandler(
        left_slot,
        UInt32(0),
        Sockets.TlsHandlerStatistics(),
        Sockets.ChannelTask(),
        C_NULL,
        nothing,
        EventLoops.IoMessage[],
        Reseau.null_buffer(),
        Reseau.null_buffer(),
        nothing,
        nothing,
        C_NULL,
        nothing,
        nothing,
        nothing,
        true,
        false,
        false,
        Sockets.ChannelTask(),
        false,
        Sockets.TlsHandlerReadState.OPEN,
        0,
        Sockets.ChannelTask(),
    )
    Sockets._secure_transport_send_alpn_message(tls_handler)
    @test message_count[] == 0
    tls_handler.protocol = Reseau.byte_buf_from_c_str("h2")
    Sockets._secure_transport_send_alpn_message(tls_handler)
    @test message_count[] == 1
    close(elg)
end

@testset "secure transport ALPN does not fabricate protocol" begin
    if !Sys.isapple()
        @test true
        return
    end
    handler = Sockets.SecureTransportTlsHandler(
        nothing,
        UInt32(0),
        Sockets.TlsHandlerStatistics(),
        Sockets.ChannelTask(),
        C_NULL,
        nothing,
        EventLoops.IoMessage[],
        Reseau.null_buffer(),
        Reseau.null_buffer(),
        "h2",
        nothing,
        C_NULL,
        nothing,
        nothing,
        nothing,
        true,
        false,
        false,
        Sockets.ChannelTask(),
        false,
        Sockets.TlsHandlerReadState.OPEN,
        0,
        Sockets.ChannelTask(),
    )
    protocol = Sockets._secure_transport_get_protocol(handler)
    @test protocol.len == 0
end

@testset "secure transport would-block does not finish negotiation" begin
    if !Sys.isapple()
        @test true
        return
    end
    handler = Sockets.SecureTransportTlsHandler(
        nothing,
        UInt32(0),
        Sockets.TlsHandlerStatistics(),
        Sockets.ChannelTask(),
        C_NULL,
        nothing,
        EventLoops.IoMessage[],
        Reseau.null_buffer(),
        Reseau.null_buffer(),
        nothing,
        nothing,
        C_NULL,
        nothing,
        nothing,
        nothing,
        true,
        false,
        false,
        Sockets.ChannelTask(),
        false,
        Sockets.TlsHandlerReadState.OPEN,
        0,
        Sockets.ChannelTask(),
    )
    Sockets._secure_transport_handle_would_block(handler, false)
    @test handler.negotiation_finished == false
end

@testset "alpn missing protocol payload" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.get_next_event_loop()
    @test event_loop !== nothing
    if event_loop === nothing
        close(elg)
        return
    end

    channel = Sockets.Channel(event_loop, nothing)
    slot = Sockets.channel_slot_new!(channel)
    if Sockets.channel_first_slot(channel) !== slot
        Sockets.channel_slot_insert_front!(channel, slot)
    end

    handler = Sockets.tls_alpn_handler_new()
    Sockets.channel_slot_set_handler!(slot, handler)
    handler.slot = slot

    message = EventLoops.IoMessage(sizeof(Sockets.TlsNegotiatedProtocolMessage))
    message.message_tag = EventLoops.TLS_NEGOTIATED_PROTOCOL_MESSAGE
    message.user_data = nothing
    message.message_data.len = Csize_t(sizeof(Sockets.TlsNegotiatedProtocolMessage))

    try
        Sockets.handler_process_read_message(handler, slot, message)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == EventLoops.ERROR_IO_MISSING_ALPN_MESSAGE
    end

    Sockets.channel_shutdown!(channel, Reseau.OP_SUCCESS)
    close(elg)
end
