using Test
using Reseau

# A QUIC handshake between a Reseau client and server over loopback UDP.

const QUD = Reseau.QUIC
const TLU = Reseau.TLS
const UDU = Reseau.UDP

const _QUD_CERT = joinpath(@__DIR__, "resources", "unittests.crt")
const _QUD_KEY = joinpath(@__DIR__, "resources", "unittests.key")

@testset "QUIC over UDP" begin
    for loopback in (UDU.loopback_addr(0), UDU.loopback_addr6(0))
        server_sock = try
            UDU.listen(loopback)
        catch ex
            # Hosts without IPv6 loopback skip that family.
            loopback isa UDU.SocketAddrV6 || rethrow()
            @info "Skipping QUIC over IPv6 loopback" exception = ex
            continue
        end
        client_sock = nothing
        try
            deadline = Int64(time_ns()) + 20_000_000_000
            server_config = TLU.Config(verify_peer = false, cert_file = _QUD_CERT, key_file = _QUD_KEY, alpn_protocols = ["h3"])
            server_task = Threads.@spawn begin
                accepted = QUD._accept_over_udp(server_config, server_sock; deadline_ns = deadline)
                accepted === nothing && return nothing
                conn, peer = accepted
                QUD._drive_connection!(conn, server_sock, peer, QUD._handshake_confirmed; deadline_ns = deadline)
                return conn
            end
            client_sock = UDU.connect(UDU.local_addr(server_sock))
            client = QUD._client_connection(TLU.Config(verify_peer = false, server_name = "localhost", alpn_protocols = ["h3"]), Int64(time_ns()))
            @test QUD._drive_connection!(client, client_sock, nothing, QUD._handshake_confirmed; deadline_ns = deadline)
            server = fetch(server_task)
            @test server isa QUD._Connection
            @test QUD._handshake_confirmed(client)
            @test QUD._handshake_confirmed(server)
            @test client.error === nothing && server.error === nothing
            @test TLU.connection_state(client.tls).alpn_protocol == "h3"
            @test client.peer_cid == server.local_cid
            @test client.has_rtt_sample
        finally
            close(server_sock)
            client_sock === nothing || close(client_sock)
        end
    end
end
