using Test
using AwsIO

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
    AwsIO.channel_slot_insert_front!(channel, slot)

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

    AwsIO.channel_shutdown!(channel, AwsIO.ChannelDirection.READ, AwsIO.AWS_OP_SUCCESS)
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
    AwsIO.channel_slot_insert_front!(channel, slot)

    args = AlpnNegotiationArgs()
    handler = AwsIO.tls_alpn_handler_new((new_slot, protocol, ud) -> AwsIO.PassthroughHandler(), args)
    AwsIO.channel_slot_set_handler!(slot, handler)
    handler.slot = slot

    message = AwsIO.IoMessage(0)
    message.message_tag = 0

    res = AwsIO.handler_process_read_message(handler, slot, message)
    @test res isa AwsIO.ErrorResult
    res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_MISSING_ALPN_MESSAGE

    AwsIO.channel_shutdown!(channel, AwsIO.ChannelDirection.READ, AwsIO.AWS_OP_SUCCESS)
    AwsIO.event_loop_group_destroy!(elg)
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
    AwsIO.channel_slot_insert_front!(channel, slot)

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

    AwsIO.channel_shutdown!(channel, AwsIO.ChannelDirection.READ, AwsIO.AWS_OP_SUCCESS)
    AwsIO.event_loop_group_destroy!(elg)
end
