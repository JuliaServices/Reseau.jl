using Test
using Reseau

# A QUIC handshake between a Reseau client and server over loopback UDP, on
# each address family, through the public endpoint API.

const QUD = Reseau.QUIC
const TLU = Reseau.TLS
const UDU = Reseau.UDP

const _QUD_CERT = joinpath(@__DIR__, "resources", "unittests.crt")
const _QUD_KEY = joinpath(@__DIR__, "resources", "unittests.key")

# Reads `f(conn)` for a connection's internal state under its endpoint's lock.
_qud_state(f, c::QUD.Connection) = lock(() -> f(c.slot.conn), c.ep.lock)

@testset "QUIC over UDP" begin
    for loopback in (UDU.loopback_addr(0), UDU.loopback_addr6(0))
        server_config = TLU.Config(verify_peer = false, cert_file = _QUD_CERT, key_file = _QUD_KEY, alpn_protocols = ["h3"])
        listener = try
            QUD.listen(loopback, server_config)
        catch ex
            # Hosts without IPv6 loopback skip that family.
            loopback isa UDU.SocketAddrV6 || rethrow()
            @info "Skipping QUIC over IPv6 loopback" exception = ex
            continue
        end
        client = nothing
        server = nothing
        try
            deadline = Int64(time_ns()) + 20_000_000_000
            addr = QUD.local_addr(listener)
            @test addr isa typeof(loopback)
            server_task = Threads.@spawn QUD.accept(listener; deadline_ns = deadline)
            client = QUD.connect(addr, TLU.Config(verify_peer = false, server_name = "localhost", alpn_protocols = ["h3"]); deadline_ns = deadline)
            server = fetch(server_task)
            @test server isa QUD.Connection
            # The client confirms the handshake once HANDSHAKE_DONE arrives,
            # which may be just after `connect` returns.
            @test timedwait(() -> _qud_state(QUD._handshake_confirmed, client), 20.0; pollint = 0.001) === :ok
            @test _qud_state(QUD._handshake_confirmed, server)
            @test _qud_state(c -> c.error === nothing && c.peer_error === nothing, client)
            @test _qud_state(c -> c.error === nothing && c.peer_error === nothing, server)
            @test QUD.alpn_protocol(client) == "h3"
            @test _qud_state(c -> c.peer_cid, client) == _qud_state(c -> c.local_cid, server)
            @test _qud_state(c -> c.has_rtt_sample, client)
        finally
            client === nothing || close(client)
            server === nothing || close(server)
            close(listener)
        end
    end
end
