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

mutable struct AlpnNegotiationArgs
    new_slot::Union{Reseau.ChannelSlot, Nothing}
    new_handler::Any
    protocol::Union{Reseau.ByteBuffer, Nothing}
end

function AlpnNegotiationArgs()
    return AlpnNegotiationArgs(nothing, nothing, nothing)
end

@testset "alpn handler" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    channel = Reseau.Channel(event_loop, nothing)
    setup_done = Ref(false)
    shutdown_done = Ref(false)

    Reseau.channel_set_setup_callback!(
        channel,
        (ch, err, ud) -> begin
            setup_done[] = true
            return nothing
        end,
        nothing,
    )

    Reseau.channel_set_shutdown_callback!(
        channel,
        (ch, err, ud) -> begin
            shutdown_done[] = true
            return nothing
        end,
        nothing,
    )

    slot = Reseau.channel_slot_new!(channel)
    if Reseau.channel_first_slot(channel) !== slot
        Reseau.channel_slot_insert_front!(channel, slot)
    end

    args = AlpnNegotiationArgs()
    on_protocol = (new_slot, protocol, user_data) -> begin
        user_data.new_slot = new_slot
        user_data.protocol = protocol
        handler = Reseau.PassthroughHandler()
        user_data.new_handler = handler
        return handler
    end

    handler = Reseau.tls_alpn_handler_new(on_protocol, args)
    Reseau.channel_slot_set_handler!(slot, handler)
    handler.slot = slot

    @test !(Reseau.channel_setup_complete!(channel) isa Reseau.ErrorResult)
    @test wait_for_flag_alpn(setup_done)

    message = Reseau.IoMessage(sizeof(Reseau.TlsNegotiatedProtocolMessage))
    message.message_tag = Reseau.TLS_NEGOTIATED_PROTOCOL_MESSAGE
    message.user_data = Reseau.TlsNegotiatedProtocolMessage(Reseau.byte_buf_from_c_str("h2"))
    message.message_data.len = Csize_t(sizeof(Reseau.TlsNegotiatedProtocolMessage))

    res = Reseau.handler_process_read_message(handler, slot, message)
    @test !(res isa Reseau.ErrorResult)
    @test args.protocol !== nothing
    @test String(Reseau.byte_cursor_from_buf(args.protocol)) == "h2"
    @test args.new_slot !== nothing
    @test channel.first === args.new_slot
    @test channel.last === args.new_slot
    @test args.new_handler !== nothing

    Reseau.channel_shutdown!(channel, Reseau.AWS_OP_SUCCESS)
    @test wait_for_flag_alpn(shutdown_done)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "alpn missing protocol message" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    channel = Reseau.Channel(event_loop, nothing)
    slot = Reseau.channel_slot_new!(channel)
    if Reseau.channel_first_slot(channel) !== slot
        Reseau.channel_slot_insert_front!(channel, slot)
    end

    args = AlpnNegotiationArgs()
    handler = Reseau.tls_alpn_handler_new((new_slot, protocol, ud) -> Reseau.PassthroughHandler(), args)
    Reseau.channel_slot_set_handler!(slot, handler)
    handler.slot = slot

    message = Reseau.IoMessage(0)
    message.message_tag = 0

    res = Reseau.handler_process_read_message(handler, slot, message)
    @test res isa Reseau.ErrorResult
    res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_MISSING_ALPN_MESSAGE

    Reseau.channel_shutdown!(channel, Reseau.AWS_OP_SUCCESS)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "alpn empty protocol does not send message" begin
    if !Sys.isapple()
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
    channel = Reseau.Channel(event_loop, nothing)
    left_slot = Reseau.channel_slot_new!(channel)
    right_slot = Reseau.channel_slot_new!(channel)
    Reseau.channel_slot_insert_right!(left_slot, right_slot)
    message_count = Ref(0)
    handler = ReadWriteTestHandler(
        (_, _, _, _) -> begin
            message_count[] += 1
            return nothing
        end,
        (_, _, _, _) -> nothing;
        event_loop_driven = false,
        window = sizeof(Reseau.TlsNegotiatedProtocolMessage),
    )
    Reseau.channel_slot_set_handler!(right_slot, handler)
    tls_handler = Reseau.SecureTransportTlsHandler(
        left_slot,
        UInt32(0),
        Reseau.TlsHandlerStatistics(),
        Reseau.ChannelTask(),
        C_NULL,
        nothing,
        Reseau.IoMessage[],
        Reseau.null_buffer(),
        Reseau.null_buffer(),
        nothing,
        nothing,
        nothing,
        C_NULL,
        nothing,
        nothing,
        nothing,
        nothing,
        true,
        false,
        false,
        Reseau.ChannelTask(),
        false,
        Reseau.TlsHandlerReadState.OPEN,
        0,
        Reseau.ChannelTask(),
    )
    Reseau._secure_transport_send_alpn_message(tls_handler)
    @test message_count[] == 0
    tls_handler.protocol = Reseau.byte_buf_from_c_str("h2")
    Reseau._secure_transport_send_alpn_message(tls_handler)
    @test message_count[] == 1
    Reseau.event_loop_group_destroy!(elg)
end

@testset "secure transport ALPN does not fabricate protocol" begin
    if !Sys.isapple()
        @test true
        return
    end
    handler = Reseau.SecureTransportTlsHandler(
        nothing,
        UInt32(0),
        Reseau.TlsHandlerStatistics(),
        Reseau.ChannelTask(),
        C_NULL,
        nothing,
        Reseau.IoMessage[],
        Reseau.null_buffer(),
        Reseau.null_buffer(),
        "h2",
        nothing,
        nothing,
        C_NULL,
        nothing,
        nothing,
        nothing,
        nothing,
        true,
        false,
        false,
        Reseau.ChannelTask(),
        false,
        Reseau.TlsHandlerReadState.OPEN,
        0,
        Reseau.ChannelTask(),
    )
    protocol = Reseau._secure_transport_get_protocol(handler)
    @test protocol.len == 0
end

@testset "secure transport would-block does not finish negotiation" begin
    if !Sys.isapple()
        @test true
        return
    end
    handler = Reseau.SecureTransportTlsHandler(
        nothing,
        UInt32(0),
        Reseau.TlsHandlerStatistics(),
        Reseau.ChannelTask(),
        C_NULL,
        nothing,
        Reseau.IoMessage[],
        Reseau.null_buffer(),
        Reseau.null_buffer(),
        nothing,
        nothing,
        nothing,
        C_NULL,
        nothing,
        nothing,
        nothing,
        nothing,
        true,
        false,
        false,
        Reseau.ChannelTask(),
        false,
        Reseau.TlsHandlerReadState.OPEN,
        0,
        Reseau.ChannelTask(),
    )
    Reseau._secure_transport_handle_would_block(handler, false)
    @test handler.negotiation_finished == false
end

@testset "alpn error creating handler" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    channel = Reseau.Channel(event_loop, nothing)
    slot = Reseau.channel_slot_new!(channel)
    if Reseau.channel_first_slot(channel) !== slot
        Reseau.channel_slot_insert_front!(channel, slot)
    end

    handler = Reseau.tls_alpn_handler_new((new_slot, protocol, ud) -> nothing, nothing)
    Reseau.channel_slot_set_handler!(slot, handler)
    handler.slot = slot

    message = Reseau.IoMessage(sizeof(Reseau.TlsNegotiatedProtocolMessage))
    message.message_tag = Reseau.TLS_NEGOTIATED_PROTOCOL_MESSAGE
    message.user_data = Reseau.TlsNegotiatedProtocolMessage(Reseau.byte_buf_from_c_str("h2"))
    message.message_data.len = Csize_t(sizeof(Reseau.TlsNegotiatedProtocolMessage))

    res = Reseau.handler_process_read_message(handler, slot, message)
    @test res isa Reseau.ErrorResult
    res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE

    Reseau.channel_shutdown!(channel, Reseau.AWS_OP_SUCCESS)
    Reseau.event_loop_group_destroy!(elg)
end
