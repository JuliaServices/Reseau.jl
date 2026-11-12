using Test
using Reseau

# QUIC packet protection against the RFC 9001 Appendix A sample packets and the
# RFC 9000 Appendix A packet number examples.

const QPP = Reseau.QUIC

isdefined(@__MODULE__, :_RESEAU_QUIC_TEST_VECTORS_LOADED) || include("quic_test_vectors.jl")

const _AES_128_GCM = UInt16(0x1301)
const _CHACHA20_POLY1305 = UInt16(0x1303)

# Lays out `header || payload` with room for the AEAD tag.
_qpp_packet_buffer(header::Vector{UInt8}, payload::Vector{UInt8}) = vcat(header, payload, zeros(UInt8, 16))

function _qpp_flip(bytes::Vector{UInt8}, i::Int)
    out = copy(bytes)
    out[i] ⊻= 0x01
    return out
end

# Whether sealing throws an ArgumentError whose message mentions `expected`.
function _qpp_seal_error(keys, buf, first, pn_offset, pn_len, payload_last, pn, expected::String)
    try
        QPP._seal_packet!(keys, buf, first, pn_offset, pn_len, payload_last, pn)
    catch ex
        return ex isa ArgumentError && occursin(expected, ex.msg)
    end
    return false
end

@testset "QUIC packet protection" begin
    @testset "Initial secrets and keys (RFC 9001 A.1)" begin
        client_secret, server_secret = QPP._initial_secrets(_RFC9001_DCID)
        @test client_secret == hex2bytes("c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")
        @test server_secret == hex2bytes("3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b")
        client, server = QPP._initial_packet_keys(_RFC9001_DCID)
        @test client.suite == _AES_128_GCM
        @test client.key == hex2bytes("1f369613dd76d5467730efcbe3b1a22d")
        @test client.iv == hex2bytes("fa044b2f42a3fd3b46fb255c")
        @test client.hp.key == hex2bytes("9f50449e04a0e810283a1e9933adedd2")
        @test server.key == hex2bytes("cf3a5331653c364c88f0f379b6067e37")
        @test server.iv == hex2bytes("0ac1493ca1905853b0bba03e")
        @test server.hp.key == hex2bytes("c206b8d9b9f0f37644430b490eeaa314")
    end

    @testset "client Initial (RFC 9001 A.2)" begin
        header = hex2bytes("c300000001088394c8f03e5157080000449e00000002")
        payload = vcat(_RFC9001_CLIENT_CRYPTO_FRAME, zeros(UInt8, 1162 - length(_RFC9001_CLIENT_CRYPTO_FRAME)))
        pn_offset = length(header) - 3
        client, _ = QPP._initial_packet_keys(_RFC9001_DCID)
        buf = _qpp_packet_buffer(header, payload)
        last = QPP._seal_packet!(client, buf, 1, pn_offset, 4, length(header) + length(payload), Int64(2))
        @test last == length(buf) == 1200
        @test buf == _RFC9001_CLIENT_PROTECTED

        # The server derives the same client keys from the DCID and opens it.
        server_view, _ = QPP._initial_packet_keys(_RFC9001_DCID)
        received = copy(_RFC9001_CLIENT_PROTECTED)
        opened = QPP._open_packet!(server_view, received, 1, pn_offset, length(received), Int64(-1))
        @test opened !== nothing
        pn, payload_first, payload_last = opened
        @test pn == 2
        @test received[1:payload_first - 1] == header
        @test received[payload_first:payload_last] == payload
    end

    @testset "server Initial (RFC 9001 A.3)" begin
        header = hex2bytes("c1000000010008f067a5502a4262b50040750001")
        pn_offset = length(header) - 1
        _, server = QPP._initial_packet_keys(_RFC9001_DCID)
        buf = _qpp_packet_buffer(header, _RFC9001_SERVER_PAYLOAD)
        QPP._seal_packet!(server, buf, 1, pn_offset, 2, length(header) + length(_RFC9001_SERVER_PAYLOAD), Int64(1))
        @test buf == _RFC9001_SERVER_PROTECTED

        # Inside a larger datagram buffer, at an offset.
        datagram = vcat(fill(0xaa, 7), _RFC9001_SERVER_PROTECTED, fill(0xbb, 5))
        first = 8
        last = first + length(_RFC9001_SERVER_PROTECTED) - 1
        opened = QPP._open_packet!(server, datagram, first, first + pn_offset - 1, last, Int64(0))
        @test opened !== nothing
        pn, payload_first, payload_last = opened
        @test pn == 1
        @test datagram[first:payload_first - 1] == header
        @test datagram[payload_first:payload_last] == _RFC9001_SERVER_PAYLOAD
        @test datagram[1:7] == fill(0xaa, 7)
        @test datagram[(last + 1):end] == fill(0xbb, 5)
    end

    @testset "Retry integrity tag (RFC 9001 A.4)" begin
        body = _RFC9001_RETRY_PACKET[1:(end - 16)]
        @test QPP._retry_integrity_tag(_RFC9001_DCID, body) == _RFC9001_RETRY_PACKET[(end - 15):end]
        @test QPP._valid_retry_integrity(_RFC9001_DCID, _RFC9001_RETRY_PACKET)
        @test !QPP._valid_retry_integrity(_RFC9001_DCID, _qpp_flip(_RFC9001_RETRY_PACKET, 20))
        @test !QPP._valid_retry_integrity(_RFC9001_DCID, _qpp_flip(_RFC9001_RETRY_PACKET, length(_RFC9001_RETRY_PACKET)))
        @test !QPP._valid_retry_integrity(_qpp_flip(_RFC9001_DCID, 1), _RFC9001_RETRY_PACKET)
        @test !QPP._valid_retry_integrity(_RFC9001_DCID, _RFC9001_RETRY_PACKET[1:15])
    end

    @testset "ChaCha20-Poly1305 short header (RFC 9001 A.5)" begin
        secret = hex2bytes("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
        keys = QPP._PacketKeys(_CHACHA20_POLY1305, secret)
        @test keys.key == hex2bytes("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8")
        @test keys.iv == hex2bytes("e0459b3474bdd0e44a41c144")
        @test keys.hp.key == hex2bytes("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4")
        @test QPP._next_packet_keys(keys).secret == hex2bytes("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")

        pn = Int64(654360564)
        @test QPP._packet_nonce!(keys, pn) == hex2bytes("e0459b3474bdd0e46d417eb0")
        header = hex2bytes("4200bff4")
        buf = _qpp_packet_buffer(header, UInt8[0x01])
        QPP._seal_packet!(keys, buf, 1, 2, 3, 5, pn)
        @test buf == hex2bytes("4cfe4189655e5cd55c41f69080575d7999c25a5bfb")

        opened = QPP._open_packet!(keys, buf, 1, 2, length(buf), pn - 1)
        @test opened !== nothing
        @test opened[1] == pn
        @test buf[opened[2]:opened[3]] == UInt8[0x01]
    end

    @testset "header mask covers 4 low bits in long headers, 5 in short" begin
        # Bit 4 of the mask's first byte is clear in every RFC 9001 vector, so
        # they cannot tell the two widths apart; an all-ones mask can.
        mask = fill(0xff, 16)
        long = UInt8[0xc0, 0x00, 0x00]
        QPP._xor_header_mask!(long, 1, 2, 2, mask)
        @test long == UInt8[0xcf, 0xff, 0xff]
        short = UInt8[0x40, 0x00, 0x00, 0x00]
        QPP._xor_header_mask!(short, 1, 2, 1, mask)
        @test short == UInt8[0x5f, 0xff, 0x00, 0x00]
    end

    @testset "header protection and payload decryption run separately" begin
        # A receiver must unmask the header (with the long-lived hp key) to
        # learn the key phase before it can choose the payload keys.
        _, server = QPP._initial_packet_keys(_RFC9001_DCID)
        buf = copy(_RFC9001_SERVER_PROTECTED)
        pn_offset = 19
        unmasked = QPP._remove_header_protection!(server.hp, buf, 1, pn_offset, length(buf))
        @test unmasked == (2, UInt64(1))
        @test buf[1] == 0xc1
        payload_last = QPP._decrypt_payload!(server, buf, 1, pn_offset, 2, Int64(1), length(buf))
        @test payload_last !== nothing
        @test buf[(pn_offset + 2):payload_last] == _RFC9001_SERVER_PAYLOAD
    end

    @testset "tampered or truncated packets are dropped" begin
        client, _ = QPP._initial_packet_keys(_RFC9001_DCID)
        pn_offset = 19
        n = length(_RFC9001_CLIENT_PROTECTED)
        for i in (1, 10, pn_offset, 40, n)  # header bits, AAD, packet number, payload, tag
            @test QPP._open_packet!(client, _qpp_flip(_RFC9001_CLIENT_PROTECTED, i), 1, pn_offset, n, Int64(-1)) === nothing
        end
        # Too short to hold the 16-byte header protection sample.
        short = _RFC9001_CLIENT_PROTECTED[1:(pn_offset + 18)]
        @test QPP._open_packet!(client, short, 1, pn_offset, length(short), Int64(-1)) === nothing
        @test _qpp_seal_error(client, _qpp_packet_buffer(UInt8[0x40, 0x00], UInt8[0x01]), 1, 2, 1, 3, Int64(0), "too short")
        # Header bits declaring a different packet number length.
        @test _qpp_seal_error(client, _qpp_packet_buffer(UInt8[0x40, 0x00, 0x07], rand(UInt8, 20)), 1, 2, 2, 23, Int64(7), "length bits")
        # No room after the payload for the tag.
        @test _qpp_seal_error(client, vcat(UInt8[0x40, 0x00], zeros(UInt8, 24)), 1, 2, 1, 26, Int64(0), "no room")
    end

    @testset "key update" begin
        secret = rand(UInt8, 32)
        current = QPP._PacketKeys(_AES_128_GCM, secret)
        next = QPP._next_packet_keys(current)
        @test next.key != current.key
        @test next.iv != current.iv
        @test next.hp === current.hp  # RFC 9001 Section 6: header protection keys do not change
        header = UInt8[0x41, 0x00, 0x07]  # short header, 2-byte packet number
        payload = rand(UInt8, 40)
        buf = _qpp_packet_buffer(header, payload)
        last = QPP._seal_packet!(next, buf, 1, 2, 2, length(header) + length(payload), Int64(7))
        @test QPP._open_packet!(current, copy(buf), 1, 2, last, Int64(6)) === nothing
        opened = QPP._open_packet!(next, buf, 1, 2, last, Int64(6))
        @test opened !== nothing
        @test buf[opened[2]:opened[3]] == payload
    end

    @testset "AES-256-GCM round trip" begin
        keys = QPP._PacketKeys(UInt16(0x1302), rand(UInt8, 48))
        @test length(keys.key) == 32
        @test length(keys.hp.key) == 32
        header = UInt8[0x41, 0x12, 0x34]
        payload = rand(UInt8, 64)
        buf = _qpp_packet_buffer(header, payload)
        last = QPP._seal_packet!(keys, buf, 1, 2, 2, length(header) + length(payload), Int64(0x1234))
        opened = QPP._open_packet!(keys, buf, 1, 2, last, Int64(0x1200))
        @test opened !== nothing
        @test opened[1] == 0x1234
        @test buf[opened[2]:opened[3]] == payload
        @test_throws ArgumentError QPP._PacketKeys(UInt16(0xc02f), rand(UInt8, 32))
    end

    @testset "keys from a TLS.QUICConn handshake protect packets end to end" begin
        TLP = Reseau.TLS
        cert = joinpath(@__DIR__, "resources", "unittests.crt")
        key = joinpath(@__DIR__, "resources", "unittests.key")
        client = TLP.quic_client(TLP.Config(verify_peer = false, server_name = "localhost", alpn_protocols = ["h3"]))
        server = TLP.quic_server(TLP.Config(verify_peer = false, cert_file = cert, key_file = key, alpn_protocols = ["h3"]))
        # (is_server, is_write, level) => (suite, secret)
        secrets = Dict{Tuple{Bool, Bool, TLP.QUICEncryptionLevel.T}, Tuple{UInt16, Vector{UInt8}}}()
        try
            for q in (client, server)
                TLP.set_transport_parameters!(q, UInt8[])
                TLP.start!(q)
            end
            a, b = client, server
            idle = 0
            while idle < 2
                e = TLP.next_event!(a)
                if e.kind == TLP.QUICEventKind.NoEvent
                    idle += 1
                    a, b = b, a
                    continue
                end
                idle = 0
                if e.kind == TLP.QUICEventKind.WriteData
                    TLP.handle_data!(b, e.level, e.data)
                elseif e.kind == TLP.QUICEventKind.SetWriteSecret || e.kind == TLP.QUICEventKind.SetReadSecret
                    secrets[(a === server, e.kind == TLP.QUICEventKind.SetWriteSecret, e.level)] = (e.suite, e.data)
                end
            end
        finally
            close(client)
            close(server)
        end
        for level in (TLP.QUICEncryptionLevel.Handshake, TLP.QUICEncryptionLevel.Application), sender_is_server in (false, true)
            suite, write_secret = secrets[(sender_is_server, true, level)]
            peer_suite, read_secret = secrets[(!sender_is_server, false, level)]
            @test suite == peer_suite
            sender = QPP._PacketKeys(suite, write_secret)
            receiver = QPP._PacketKeys(peer_suite, read_secret)
            header = UInt8[0x41, 0x00, 0x05]
            payload = Vector{UInt8}(codeunits("hello from the $(sender_is_server ? "server" : "client")"))
            buf = _qpp_packet_buffer(header, payload)
            last = QPP._seal_packet!(sender, buf, 1, 2, 2, length(header) + length(payload), Int64(5))
            opened = QPP._open_packet!(receiver, buf, 1, 2, last, Int64(4))
            @test opened !== nothing
            opened === nothing || @test buf[opened[2]:opened[3]] == payload
        end
    end

    @testset "packet number encoding and decoding (RFC 9000 A.2, A.3)" begin
        @test QPP._decode_packet_number(Int64(0xa82f30ea), UInt64(0x9b32), 16) == 0xa82f9b32
        @test QPP._packet_number_length(Int64(0xac5c02), Int64(0xabe8b3)) == 2
        @test QPP._packet_number_length(Int64(0xace8fe), Int64(0xabe8b3)) == 3
        @test QPP._packet_number_length(Int64(0), Int64(-1)) == 1
        @test QPP._packet_number_length(Int64(1) << 40, Int64(-1)) == 4
        # Every length chosen for a gap decodes back from the truncated form.
        for (largest_acked, pn) in ((Int64(-1), Int64(0)), (Int64(10), Int64(11)), (Int64(100), Int64(300)),
                (Int64(0xabe8b3), Int64(0xac5c02)), (Int64(0xabe8b3), Int64(0xace8fe)), (Int64(1) << 40, (Int64(1) << 40) + 70_000))
            pn_len = QPP._packet_number_length(pn, largest_acked)
            buf = zeros(UInt8, 4)
            QPP._write_packet_number!(buf, 1, pn, pn_len)
            truncated = UInt64(0)
            for i in 1:pn_len
                truncated = (truncated << 8) | buf[i]
            end
            # The receiver's largest received packet is at least the sender's largest acknowledged.
            @test QPP._decode_packet_number(max(largest_acked, Int64(0)), truncated, 8 * pn_len) == pn
        end
        # Candidates stay below 2^62 near the top of the space.
        top = (Int64(1) << 62) - 1
        @test QPP._decode_packet_number(top - 1, UInt64(top & 0xff), 8) == top
    end
end
