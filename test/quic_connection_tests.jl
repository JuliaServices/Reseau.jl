using Test
using Reseau

# QUIC connection handshakes (RFC 9000, RFC 9001, RFC 9002 probe timeouts),
# driven in memory: datagrams pass between a client and a server `_Connection`
# under a simulated clock, so loss and reordering are deterministic.

@isdefined(_QcnHarness) || include("quic_harness.jl")

@testset "QUIC connections" begin
    @testset "handshake in memory" begin
        h = _QcnHarness()
        @test _qcn_run!(h)
        client, server = h.client, h.server
        @test QCN._handshake_complete(client) && QCN._handshake_complete(server)
        @test QCN._handshake_confirmed(client) && QCN._handshake_confirmed(server)
        @test client.state == QCN._ConnState.Confirmed
        @test server.state == QCN._ConnState.Confirmed
        @test client.error === nothing && server.error === nothing
        @test TLC.connection_state(client.tls).alpn_protocol == "h3"
        @test TLC.connection_state(server.tls).alpn_protocol == "h3"
        # Initial and Handshake keys are gone (RFC 9001 Section 4.9).
        for conn in (client, server), level in (1, 2)
            @test conn.spaces[level].discarded
        end
        # Each side learned the other's connection IDs and parameters.
        @test client.peer_cid == server.local_cid
        @test server.peer_cid == client.local_cid
        @test client.peer_params.original_destination_connection_id == client.original_dcid
        @test client.peer_params.initial_source_connection_id == server.local_cid
        @test server.peer_params.initial_source_connection_id == client.local_cid
        # Once the delayed ACKs go out, a settled connection has only its idle timer left.
        @test !_qcn_run!(h; done = h -> false, max_time = h.now + 1_000_000_000)
        @test QCN._next_timeout(client) == client.last_activity + client.idle_timeout_ns
        @test QCN._next_timeout(server) == server.last_activity + server.idle_timeout_ns
    end

    @testset "datagram sizes and the amplification limit" begin
        h = _QcnHarness()
        @test _qcn_run!(h)
        # Clients pad every datagram with an Initial packet, and servers every
        # datagram with an ack-eliciting one, to 1200 bytes (RFC 9000 Section 14.1).
        # Handshake datagrams stay at 1200 bytes; only path MTU probes, once
        # the handshake is confirmed, may be larger, up to the ceiling.
        for s in h.log
            handshake = _qcn_has_initial(s.bytes) || _qcn_has_type(s.bytes, QCN._PacketType.Handshake)
            length(s.bytes) <= (handshake ? QCN._MAX_DATAGRAM_SIZE : QCN._PMTU_DEFAULT_CEILING) || @test false
            if _qcn_has_initial(s.bytes) && s.from_client
                @test length(s.bytes) >= 1200
            end
        end
        @test length(first(_qcn_sent(h, false)).bytes) == 1200
        # Before validating the client's address, the server sends at most three
        # times what it received (RFC 9000 Section 8.1).
        received = 0
        sent = 0
        for s in h.log
            if s.from_client
                received += length(s.bytes)
                _qcn_has_type(s.bytes, QCN._PacketType.Handshake) && break
            else
                sent += length(s.bytes)
                @test sent <= 3 * received
            end
        end
    end

    @testset "a silent client holds the server to three times its Initial" begin
        h = _QcnHarness(drop = (from_client, n) -> from_client && n > 1)
        @test !_qcn_run!(h; max_time = _QCN_START + 20_000_000_000)
        server_bytes = sum(length(s.bytes) for s in _qcn_sent(h, false))
        @test server_bytes <= 3 * 1200
        @test server_bytes > 0
    end

    @testset "lost server flight is recovered by probe timeouts" begin
        h = _QcnHarness(drop = (from_client, n) -> !from_client && n <= 2)
        @test _qcn_run!(h)
        @test h.now > _QCN_START  # needed a timer
        @test QCN._handshake_confirmed(h.client)
    end

    @testset "lost client Finished is recovered" begin
        # The client's second datagram carries its Handshake Finished.
        h = _QcnHarness(drop = (from_client, n) -> from_client && n == 2)
        @test _qcn_run!(h)
        @test QCN._handshake_confirmed(h.server)
    end

    @testset "lost HANDSHAKE_DONE is resent" begin
        handshake_done_drops = Ref(0)
        h = _QcnHarness()
        h.drop = (from_client, n) -> begin
            from_client && return false
            dgram = h.log[end].bytes
            if handshake_done_drops[] == 0 && _qcn_has_type(dgram, QCN._PacketType.OneRTT)
                handshake_done_drops[] += 1
                return true
            end
            return false
        end
        @test _qcn_run!(h)
        @test handshake_done_drops[] == 1
    end

    @testset "reordered and duplicated datagrams" begin
        # The server's first two datagrams arrive in reverse order.
        h = _QcnHarness(hold = (from_client, n) -> !from_client && n == 1)
        @test _qcn_run!(h)
        # Every datagram delivered twice.
        h = _QcnHarness(duplicate = (from_client, n) -> true)
        @test _qcn_run!(h)
    end

    @testset "a certificate failure closes both sides with CRYPTO_ERROR" begin
        client_config = TLC.Config(verify_peer = true, server_name = "wrong.example", ca_file = _QCN_CA, alpn_protocols = ["h3"])
        server_config = TLC.Config(verify_peer = false, cert_file = joinpath(@__DIR__, "resources", "native_tls_server.crt"),
            key_file = joinpath(@__DIR__, "resources", "native_tls_server.key"), alpn_protocols = ["h3"])
        h = _QcnHarness(; client_config, server_config)
        @test !_qcn_run!(h; max_time = _QCN_START + 10_000_000_000)
        bad_certificate = QCN._CRYPTO_ERROR_BASE + 42
        @test h.client.error !== nothing && h.client.error.code == bad_certificate
        @test h.server.peer_error !== nothing && h.server.peer_error.code == bad_certificate
        @test h.client.state == QCN._ConnState.Closed
        @test h.server.state == QCN._ConnState.Closed
    end

    @testset "idle timeout closes a quiet connection" begin
        h = _QcnHarness()
        @test _qcn_run!(h)
        @test _qcn_run!(h; done = h -> h.client.state == QCN._ConnState.Closed && h.server.state == QCN._ConnState.Closed,
            max_time = h.now + 2 * h.client.idle_timeout_ns)
        @test h.client.error === nothing  # idle closes are silent
    end

    @testset "duplicate packets are discarded, not acknowledged again" begin
        h = _QcnHarness()
        @test _qcn_run!(h)
        _qcn_exchange!(h)
        # The server's last datagram carried HANDSHAKE_DONE; the client acknowledged it.
        last_server = last(_qcn_sent(h, false)).bytes
        QCN._receive_datagram!(h.client, copy(last_server), h.now)
        @test QCN._next_datagram!(h.client, h.now) === nothing
    end

    @testset "a client with nothing in flight probes until confirmed" begin
        # The server's Initial acknowledges the ClientHello, then everything
        # else is lost, so the client has nothing in flight while the server
        # may be stuck at its amplification limit (RFC 9002 Section 6.2.2.1).
        h = _QcnHarness(drop = (from_client, n) -> n >= 2)
        _qcn_exchange!(h)
        client = h.client
        @test isempty(client.spaces[QCN._HANDSHAKE_SPACE].sent)
        @test client.spaces[QCN._HANDSHAKE_SPACE].write_keys !== nothing
        t = QCN._next_timeout(client)
        @test t < client.last_activity + client.idle_timeout_ns
        QCN._handle_timeout!(client, t)
        probe = QCN._next_datagram!(client, t)
        @test probe !== nothing
        @test _qcn_has_type(probe, QCN._PacketType.Handshake)  # proves its address to the server
    end

    @testset "packets after a fatal one in the same datagram are ignored" begin
        client = QCN._client_connection(_qcn_client_config(), _QCN_START)
        QCN._next_datagram!(client, _QCN_START)
        _, server_keys = QCN._initial_packet_keys(client.original_dcid)
        scid = rand(UInt8, 8)
        dgram = UInt8[]
        packets = Tuple{QCN._PacketLayout, Int, Int64}[]
        for (pn, frames!) in ((0, b -> QCN._append_stream_frame!(b, UInt64(0), UInt64(0), UInt8[0x01])),  # not allowed in Initial
                              (1, b -> QCN._append_connection_close_frame!(b, UInt64(0), UInt64(0), UInt8[])))
            layout = QCN._begin_long_packet!(dgram, QCN._PacketType.Initial, QCN._QUIC_V1, client.local_cid, scid, UInt8[], Int64(pn), 1)
            frames!(dgram)
            push!(packets, (layout, QCN._end_packet!(dgram, layout), Int64(pn)))
        end
        for (layout, payload_last, pn) in packets
            QCN._seal_packet!(server_keys, dgram, layout.first, layout.pn_offset, layout.pn_len, payload_last, pn)
        end
        QCN._receive_datagram!(client, dgram, _QCN_START)
        @test client.state == QCN._ConnState.Closing
        @test client.error.code == QCN._PROTOCOL_VIOLATION
        @test client.peer_error === nothing  # the CONNECTION_CLOSE after it was not processed
    end

    @testset "huge ACK Delay values do not overflow" begin
        client = QCN._client_connection(_qcn_client_config(), _QCN_START)
        client.peer_params = QCN._TransportParameters()  # ack_delay_exponent 3
        # Any varint the peer sends converts to a nonnegative delay.
        for delay in (UInt64(0), UInt64(1000), (UInt64(1) << 51) - 1, UInt64(1) << 51, QCN._MAX_VARINT)
            @test QCN._ack_delay_ns(client, delay) >= 0
        end
        @test QCN._ack_delay_ns(client, UInt64(1000)) == 8_000_000  # 1000 << 3 microseconds
    end

    @testset "servers ignore Initial datagrams under 1200 bytes" begin
        client = QCN._client_connection(_qcn_client_config(), _QCN_START)
        dgram = QCN._next_datagram!(client, _QCN_START)
        header = first(QCN._datagram_packets(dgram, 1, length(dgram), QCN._LOCAL_CID_LEN))
        @test QCN._accept_connection(_qcn_server_config(), dgram[1:1199], header, _QCN_START) === nothing
        @test QCN._accept_connection(_qcn_server_config(), dgram, header, _QCN_START) isa QCN._Connection
    end

    @testset "peer connection IDs are authenticated (RFC 9000 Section 7.3)" begin
        h = _QcnHarness()
        @test _qcn_run!(h)
        client, server = h.client, h.server
        good = client.peer_params
        check(conn, params) = QCN._check_peer_transport_parameters(conn, params)
        @test check(client, good) === nothing
        for bad in (_qcn_with(good; initial_source_connection_id = nothing), _qcn_with(good; initial_source_connection_id = rand(UInt8, 8)),
                    _qcn_with(good; original_destination_connection_id = nothing), _qcn_with(good; original_destination_connection_id = rand(UInt8, 8)),
                    _qcn_with(good; retry_source_connection_id = rand(UInt8, 8)))
            err = check(client, bad)
            @test err isa QCN._TransportError && err.code == QCN._TRANSPORT_PARAMETER_ERROR
        end
        @test check(server, server.peer_params) === nothing
        err = check(server, _qcn_with(server.peer_params; initial_source_connection_id = rand(UInt8, 8)))
        @test err isa QCN._TransportError && err.code == QCN._TRANSPORT_PARAMETER_ERROR
    end

    # Key updates and closing need 1-RTT traffic; streams carry it.
    settle!(h) = _qcn_run!(h; done = h -> false, max_time = h.now + 1_000_000_000)
    function read_into!(received)
        return h -> begin
            id = QCN._accept_stream!(h.server)
            id === nothing || push!(received.ids, id)
            for id in received.ids
                append!(received.data, QCN._stream_read!(h.server, id).data)
            end
        end
    end

    @testset "1-RTT key updates (RFC 9001 Section 6)" begin
        # Not before the handshake is confirmed.
        @test !QCN._initiate_key_update!(QCN._client_connection(_qcn_client_config(), _QCN_START))
        h = _QcnHarness()
        @test _qcn_run!(h)
        client, server = h.client, h.server
        received = (ids = UInt64[], data = UInt8[])
        id = QCN._open_stream!(client)
        QCN._stream_write!(client, id, UInt8[1])
        settle!(h)
        # A packet in this phase is acknowledged, but an endpoint that has not
        # confirmed the handshake still may not update (RFC 9001 Section 6.1).
        client.state = QCN._ConnState.Established
        @test !QCN._initiate_key_update!(client)
        client.state = QCN._ConnState.Confirmed
        @test QCN._initiate_key_update!(client)
        @test client.key_phase
        # No further update until a packet in the new phase is acknowledged.
        @test !QCN._initiate_key_update!(client)
        QCN._stream_write!(client, id, UInt8[2])
        @test _qcn_run!(h; app = read_into!(received), done = h -> length(received.data) == 2)
        @test received.data == [1, 2]
        # The server followed, and answers with the new keys too.
        @test server.key_phase && server.key_updates == 1
        settle!(h)
        @test QCN._initiate_key_update!(client)
        QCN._stream_write!(client, id, UInt8[3])
        @test _qcn_run!(h; app = read_into!(received), done = h -> length(received.data) == 3)
        @test !server.key_phase && server.key_updates == 2
        @test client.key_updates == 2
        @test client.error === nothing && server.error === nothing
    end

    @testset "a packet that fails to open with the next keys does not update them" begin
        h = _QcnHarness()
        @test _qcn_run!(h)
        client, server = h.client, h.server
        # Key phase 1, sealed with the current keys: what an attacker could forge.
        space = client.spaces[QCN._APPLICATION_SPACE]
        buf = UInt8[]
        pn = space.next_pn
        layout = QCN._begin_short_packet!(buf, client.peer_cid, pn, 2; key_phase = true)
        QCN._append_ping_frame!(buf)
        payload_last = QCN._end_packet!(buf, layout)
        space.next_pn += 1
        QCN._seal_packet!(space.write_keys, buf, layout.first, layout.pn_offset, layout.pn_len, payload_last, pn)
        QCN._receive_datagram!(server, buf, h.now)
        @test !server.key_phase && server.key_updates == 0
        # The connection carries on with the old keys.
        received = (ids = UInt64[], data = UInt8[])
        id = QCN._open_stream!(client)
        QCN._stream_write!(client, id, UInt8[7])
        @test _qcn_run!(h; app = read_into!(received), done = h -> received.data == [7])
        @test server.error === nothing
    end

    @testset "packets from the previous key phase still open after an update" begin
        h = _QcnHarness()
        @test _qcn_run!(h)
        client, server = h.client, h.server
        id = QCN._open_stream!(client)
        QCN._stream_write!(client, id, UInt8[0])
        settle!(h)
        QCN._stream_write!(client, id, UInt8[1])
        old_phase = QCN._next_datagram!(client, h.now)
        @test QCN._initiate_key_update!(client)
        QCN._stream_write!(client, id, UInt8[2])
        new_phase = QCN._next_datagram!(client, h.now)
        # The new phase arrives first, then the delayed old one.
        QCN._receive_datagram!(server, new_phase, h.now)
        QCN._receive_datagram!(server, old_phase, h.now)
        @test QCN._accept_stream!(server) == id
        @test QCN._stream_read!(server, id).data == [0, 1, 2]
        @test server.key_updates == 1
    end

    @testset "automatic key updates and the confidentiality limit (RFC 9001 Section 6.6)" begin
        h = _QcnHarness()
        @test _qcn_run!(h)
        client, server = h.client, h.server
        space = client.spaces[QCN._APPLICATION_SPACE]
        send_ping!() = (space.probes += 1; QCN._next_datagram!(client, h.now))
        # The first update follows FirstKeyUpdateInterval packets, unacknowledged.
        client.key_phase_sent = QCN._FIRST_KEY_UPDATE_INTERVAL - 1
        @test !client.key_phase
        send_ping!()
        @test client.key_phase && client.key_updates == 1
        # A later one waits for an acknowledgment in the current phase; if the
        # confidentiality limit nears first, the connection closes instead.
        limit = QCN._aead_confidentiality_limit(space.write_keys.suite)
        client.key_phase_sent = min(limit, typemax(Int64) ÷ 2) - QCN._AEAD_LIMIT_HEADROOM - 1
        send_ping!()
        @test client.key_updates == 1
        if limit == typemax(Int64)  # ChaCha20-Poly1305 has no practical limit.
            @test client.error === nothing
        else
            @test client.error !== nothing && client.error.code == QCN._AEAD_LIMIT_REACHED
        end
        # The peer follows the first update.
        @test server.key_updates == 0
        settle!(h)
        @test server.key_updates == 1 && server.key_phase
    end

    @testset "an application close reaches the peer (RFC 9000 Section 10.2)" begin
        h = _QcnHarness()
        @test _qcn_run!(h)
        QCN._close_connection!(h.client, UInt64(0x42), "bye", h.now)
        @test h.client.state == QCN._ConnState.Closing
        @test_throws ArgumentError QCN._open_stream!(h.client)
        _qcn_exchange!(h)
        err = h.server.peer_error
        @test err !== nothing && err.app && err.code == 0x42 && err.reason == "bye"
        @test h.server.state == QCN._ConnState.Draining
        @test _qcn_run!(h; done = h -> h.client.state == QCN._ConnState.Closed && h.server.state == QCN._ConnState.Closed)
    end

    @testset "a closing endpoint answers more packets with CONNECTION_CLOSE" begin
        h = _QcnHarness()
        @test _qcn_run!(h)
        # The first CONNECTION_CLOSE is lost.
        sent_before = h.sent_count[true]
        h.drop = (from_client, n) -> from_client && n == sent_before + 1
        QCN._close_connection!(h.client, UInt64(1), "", h.now)
        _qcn_exchange!(h)
        @test h.server.peer_error === nothing
        # The server keeps sending, and hears the close in reply.
        id = QCN._open_stream!(h.server)
        QCN._stream_write!(h.server, id, UInt8[1])
        _qcn_exchange!(h)
        @test h.server.peer_error !== nothing && h.server.peer_error.code == 1
    end

    @testset "an application close during the handshake is sent as APPLICATION_ERROR" begin
        # Before 1-RTT keys, the application's code and reason stay private
        # (RFC 9000 Section 10.2.3).
        h = _QcnHarness()
        QCN._close_connection!(h.client, UInt64(0x42), "private reason", h.now)
        _qcn_exchange!(h)
        err = h.server.peer_error
        @test err !== nothing && !err.app && err.code == QCN._APPLICATION_ERROR && isempty(err.reason)
    end
end
