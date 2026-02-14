using Test
using Reseau

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
