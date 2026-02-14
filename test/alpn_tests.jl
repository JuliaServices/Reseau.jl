using Test
using Reseau

mutable struct _DummyTlsHandlerProtocol
    protocol::Reseau.ByteBuffer
end

@testset "protocol callback helper emits negotiated protocol" begin
    callback_count = Ref(0)
    callback_protocol = Ref("")
    callback = Sockets.ProtocolNegotiatedCallable((pipeline, protocol) -> begin
        callback_count[] += 1
        @test pipeline === :pipeline
        callback_protocol[] = Reseau.byte_buffer_as_string(protocol)
        return nothing
    end)

    handler = _DummyTlsHandlerProtocol(Reseau.byte_buf_from_c_str("h2"))
    Sockets._install_protocol_handler_from_tls(:pipeline, handler, callback)

    @test callback_count[] == 1
    @test callback_protocol[] == "h2"
end

@testset "protocol callback helper skips empty protocol" begin
    callback_count = Ref(0)
    callback = Sockets.ProtocolNegotiatedCallable((_, _) -> begin
        callback_count[] += 1
        return nothing
    end)

    empty_handler = _DummyTlsHandlerProtocol(Reseau.null_buffer())
    Sockets._install_protocol_handler_from_tls(:pipeline, empty_handler, callback)

    @test callback_count[] == 0
end

@testset "secure transport ALPN does not fabricate protocol" begin
    if !Sys.isapple()
        @test true
        return
    end
    handler = Sockets.SecureTransportTlsState(
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
        nothing,
        nothing,
        nothing,
        nothing,
    )
    protocol = Sockets._secure_transport_get_protocol(handler)
    @test protocol.len == 0
end

@testset "secure transport would-block does not finish negotiation" begin
    if !Sys.isapple()
        @test true
        return
    end
    handler = Sockets.SecureTransportTlsState(
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
        nothing,
        nothing,
        nothing,
        nothing,
    )
    Sockets._secure_transport_handle_would_block(handler, false)
    @test handler.negotiation_finished == false
end
