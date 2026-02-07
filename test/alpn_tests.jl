using Test
using AwsIO
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
    new_slot::Union{AwsIO.ChannelSlot, Nothing}
    new_handler::Any
    protocol::Union{AwsIO.ByteBuffer, Nothing}
end

function AlpnNegotiationArgs()
    return AlpnNegotiationArgs(nothing, nothing, nothing)
end

@testset "alpn handler" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    channel = AwsIO.Channel(event_loop, nothing)
    setup_done = Ref(false)
    shutdown_done = Ref(false)

    AwsIO.channel_set_setup_callback!(
        channel,
        (ch, err, ud) -> begin
            setup_done[] = true
            return nothing
        end,
        nothing,
    )

    AwsIO.channel_set_shutdown_callback!(
        channel,
        (ch, err, ud) -> begin
            shutdown_done[] = true
            return nothing
        end,
        nothing,
    )

    slot = AwsIO.channel_slot_new!(channel)
    if AwsIO.channel_first_slot(channel) !== slot
        AwsIO.channel_slot_insert_front!(channel, slot)
    end

    args = AlpnNegotiationArgs()
    on_protocol = (new_slot, protocol, user_data) -> begin
        user_data.new_slot = new_slot
        user_data.protocol = protocol
        handler = AwsIO.PassthroughHandler()
        user_data.new_handler = handler
        return handler
    end

    handler = AwsIO.tls_alpn_handler_new(on_protocol, args)
    AwsIO.channel_slot_set_handler!(slot, handler)
    handler.slot = slot

    @test !(AwsIO.channel_setup_complete!(channel) isa AwsIO.ErrorResult)
    @test wait_for_flag_alpn(setup_done)

    message = AwsIO.IoMessage(sizeof(AwsIO.TlsNegotiatedProtocolMessage))
    message.message_tag = AwsIO.TLS_NEGOTIATED_PROTOCOL_MESSAGE
    message.user_data = AwsIO.TlsNegotiatedProtocolMessage(AwsIO.byte_buf_from_c_str("h2"))
    message.message_data.len = Csize_t(sizeof(AwsIO.TlsNegotiatedProtocolMessage))

    res = AwsIO.handler_process_read_message(handler, slot, message)
    @test !(res isa AwsIO.ErrorResult)
    @test args.protocol !== nothing
    @test String(AwsIO.byte_cursor_from_buf(args.protocol)) == "h2"
    @test args.new_slot !== nothing
    @test channel.first === args.new_slot
    @test channel.last === args.new_slot
    @test args.new_handler !== nothing

    AwsIO.channel_shutdown!(channel, AwsIO.AWS_OP_SUCCESS)
    @test wait_for_flag_alpn(shutdown_done)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "alpn missing protocol message" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    channel = AwsIO.Channel(event_loop, nothing)
    slot = AwsIO.channel_slot_new!(channel)
    if AwsIO.channel_first_slot(channel) !== slot
        AwsIO.channel_slot_insert_front!(channel, slot)
    end

    args = AlpnNegotiationArgs()
    handler = AwsIO.tls_alpn_handler_new((new_slot, protocol, ud) -> AwsIO.PassthroughHandler(), args)
    AwsIO.channel_slot_set_handler!(slot, handler)
    handler.slot = slot

    message = AwsIO.IoMessage(0)
    message.message_tag = 0

    res = AwsIO.handler_process_read_message(handler, slot, message)
    @test res isa AwsIO.ErrorResult
    res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_MISSING_ALPN_MESSAGE

    AwsIO.channel_shutdown!(channel, AwsIO.AWS_OP_SUCCESS)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "alpn empty protocol does not send message" begin
    if !Sys.isapple()
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
    channel = AwsIO.Channel(event_loop, nothing)
    left_slot = AwsIO.channel_slot_new!(channel)
    right_slot = AwsIO.channel_slot_new!(channel)
    AwsIO.channel_slot_insert_right!(left_slot, right_slot)
    message_count = Ref(0)
    handler = ReadWriteTestHandler(
        (_, _, _, _) -> begin
            message_count[] += 1
            return nothing
        end,
        (_, _, _, _) -> nothing;
        event_loop_driven = false,
        window = sizeof(AwsIO.TlsNegotiatedProtocolMessage),
    )
    AwsIO.channel_slot_set_handler!(right_slot, handler)
    tls_handler = AwsIO.SecureTransportTlsHandler(
        left_slot,
        UInt32(0),
        AwsIO.TlsHandlerStatistics(),
        AwsIO.ChannelTask(),
        C_NULL,
        nothing,
        AwsIO.Deque{AwsIO.IoMessage}(16),
        AwsIO.null_buffer(),
        AwsIO.null_buffer(),
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
        AwsIO.ChannelTask(),
        false,
        AwsIO.TlsHandlerReadState.OPEN,
        0,
        AwsIO.ChannelTask(),
    )
    AwsIO._secure_transport_send_alpn_message(tls_handler)
    @test message_count[] == 0
    tls_handler.protocol = AwsIO.byte_buf_from_c_str("h2")
    AwsIO._secure_transport_send_alpn_message(tls_handler)
    @test message_count[] == 1
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "secure transport ALPN does not fabricate protocol" begin
    if !Sys.isapple()
        @test true
        return
    end
    handler = AwsIO.SecureTransportTlsHandler(
        nothing,
        UInt32(0),
        AwsIO.TlsHandlerStatistics(),
        AwsIO.ChannelTask(),
        C_NULL,
        nothing,
        AwsIO.Deque{AwsIO.IoMessage}(16),
        AwsIO.null_buffer(),
        AwsIO.null_buffer(),
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
        AwsIO.ChannelTask(),
        false,
        AwsIO.TlsHandlerReadState.OPEN,
        0,
        AwsIO.ChannelTask(),
    )
    protocol = AwsIO._secure_transport_get_protocol(handler)
    @test protocol.len == 0
end

@testset "secure transport would-block does not finish negotiation" begin
    if !Sys.isapple()
        @test true
        return
    end
    handler = AwsIO.SecureTransportTlsHandler(
        nothing,
        UInt32(0),
        AwsIO.TlsHandlerStatistics(),
        AwsIO.ChannelTask(),
        C_NULL,
        nothing,
        AwsIO.Deque{AwsIO.IoMessage}(16),
        AwsIO.null_buffer(),
        AwsIO.null_buffer(),
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
        AwsIO.ChannelTask(),
        false,
        AwsIO.TlsHandlerReadState.OPEN,
        0,
        AwsIO.ChannelTask(),
    )
    AwsIO._secure_transport_handle_would_block(handler, false)
    @test handler.negotiation_finished == false
end

@testset "alpn error creating handler" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    channel = AwsIO.Channel(event_loop, nothing)
    slot = AwsIO.channel_slot_new!(channel)
    if AwsIO.channel_first_slot(channel) !== slot
        AwsIO.channel_slot_insert_front!(channel, slot)
    end

    handler = AwsIO.tls_alpn_handler_new((new_slot, protocol, ud) -> nothing, nothing)
    AwsIO.channel_slot_set_handler!(slot, handler)
    handler.slot = slot

    message = AwsIO.IoMessage(sizeof(AwsIO.TlsNegotiatedProtocolMessage))
    message.message_tag = AwsIO.TLS_NEGOTIATED_PROTOCOL_MESSAGE
    message.user_data = AwsIO.TlsNegotiatedProtocolMessage(AwsIO.byte_buf_from_c_str("h2"))
    message.message_data.len = Csize_t(sizeof(AwsIO.TlsNegotiatedProtocolMessage))

    res = AwsIO.handler_process_read_message(handler, slot, message)
    @test res isa AwsIO.ErrorResult
    res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE

    AwsIO.channel_shutdown!(channel, AwsIO.AWS_OP_SUCCESS)
    AwsIO.event_loop_group_destroy!(elg)
end
