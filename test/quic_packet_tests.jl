using Test
using Reseau

# QUIC wire format: variable-length integers (RFC 9000 Section 16), packet
# headers (Section 17), and coalesced packets in one datagram (Section 12.2).

const QPK = Reseau.QUIC
const QPT = QPK._PacketType

isdefined(@__MODULE__, :_RESEAU_QUIC_TEST_VECTORS_LOADED) || include("quic_test_vectors.jl")

const _QPK_SCID = hex2bytes("f067a5502a4262b5")

_qpk_bytes(buf::Vector{UInt8}, r::UnitRange{Int}) = buf[r]

function _qpk_varint(hex::String)
    buf = hex2bytes(hex)
    return QPK._read_varint(buf, 1, length(buf))
end

function _qpk_encode_varint(v::Integer, len::Union{Nothing, Int} = nothing)
    buf = UInt8[]
    len === nothing ? QPK._append_varint!(buf, UInt64(v)) : QPK._append_varint!(buf, UInt64(v), len)
    return buf
end

_qpk_packets(buf::Vector{UInt8}, short_dcid_len::Int) = collect(QPK._datagram_packets(buf, 1, length(buf), short_dcid_len))

# Builds and seals one packet onto `buf`; returns its layout.
function _qpk_append_sealed!(buf, keys, layout, payload, pn)
    append!(buf, payload)
    payload_last = QPK._end_packet!(buf, layout)
    QPK._seal_packet!(keys, buf, layout.first, layout.pn_offset, layout.pn_len, payload_last, Int64(pn))
    return layout
end

@testset "QUIC packets" begin
    @testset "variable-length integers (RFC 9000 A.1, Section 16)" begin
        @test _qpk_varint("c2197c5eff14e88c") == (UInt64(151288809941952652), 9)
        @test _qpk_varint("9d7f3e7d") == (UInt64(494878333), 5)
        @test _qpk_varint("7bbd") == (UInt64(15293), 3)
        @test _qpk_varint("25") == (UInt64(37), 2)
        @test _qpk_varint("4025") == (UInt64(37), 3)  # non-minimal encodings are valid
        @test _qpk_encode_varint(151288809941952652) == hex2bytes("c2197c5eff14e88c")
        @test _qpk_encode_varint(494878333) == hex2bytes("9d7f3e7d")
        @test _qpk_encode_varint(15293) == hex2bytes("7bbd")
        @test _qpk_encode_varint(37) == hex2bytes("25")
        @test _qpk_encode_varint(37, 2) == hex2bytes("4025")
        for (v, len) in ((0, 1), (63, 1), (64, 2), (16383, 2), (16384, 4), ((1 << 30) - 1, 4), (1 << 30, 8), ((1 << 62) - 1, 8))
            @test QPK._varint_length(UInt64(v)) == len
            encoded = _qpk_encode_varint(v)
            @test length(encoded) == len
            @test QPK._read_varint(encoded, 1, length(encoded)) == (UInt64(v), len + 1)
        end
        @test_throws ArgumentError QPK._varint_length(UInt64(1) << 62)
        @test_throws ArgumentError _qpk_encode_varint(64, 1)
        # Truncated or out of the given range.
        @test _qpk_varint("9d7f3e") === nothing
        @test QPK._read_varint(hex2bytes("7bbd"), 1, 1) === nothing
        @test QPK._read_varint(hex2bytes("25"), 2, 1) === nothing
    end

    @testset "parse the RFC 9001 sample packets" begin
        h = QPK._parse_packet(_RFC9001_CLIENT_PROTECTED, 1, length(_RFC9001_CLIENT_PROTECTED), 8)
        @test h isa QPK._PacketHeader
        @test h.type == QPT.Initial
        @test h.version == QPK._QUIC_V1
        @test _qpk_bytes(_RFC9001_CLIENT_PROTECTED, h.dcid) == _RFC9001_DCID
        @test isempty(h.scid)
        @test isempty(h.token)
        @test h.pn_offset == 19
        @test h.last == 1200

        h = QPK._parse_packet(_RFC9001_SERVER_PROTECTED, 1, length(_RFC9001_SERVER_PROTECTED), 0)
        @test h.type == QPT.Initial
        @test isempty(h.dcid)
        @test _qpk_bytes(_RFC9001_SERVER_PROTECTED, h.scid) == _QPK_SCID
        @test h.pn_offset == 19
        @test h.last == 135

        h = QPK._parse_packet(_RFC9001_RETRY_PACKET, 1, length(_RFC9001_RETRY_PACKET), 0)
        @test h.type == QPT.Retry
        @test isempty(h.dcid)
        @test _qpk_bytes(_RFC9001_RETRY_PACKET, h.scid) == _QPK_SCID
        @test _qpk_bytes(_RFC9001_RETRY_PACKET, h.token) == Vector{UInt8}(codeunits("token"))
        @test h.last == length(_RFC9001_RETRY_PACKET)
    end

    @testset "build the RFC 9001 Initial packets" begin
        client, server = QPK._initial_packet_keys(_RFC9001_DCID)

        buf = UInt8[]
        layout = QPK._begin_long_packet!(buf, QPT.Initial, QPK._QUIC_V1, _RFC9001_DCID, UInt8[], UInt8[], Int64(2), 4)
        append!(buf, _RFC9001_CLIENT_CRYPTO_FRAME)
        # Clients pad Initial datagrams to 1200 bytes (RFC 9000 Section 14.1).
        payload_last = QPK._end_packet!(buf, layout; pad_to = 1200)
        @test length(buf) == 1200
        @test buf[1:22] == hex2bytes("c300000001088394c8f03e5157080000449e00000002")
        QPK._seal_packet!(client, buf, layout.first, layout.pn_offset, layout.pn_len, payload_last, Int64(2))
        @test buf == _RFC9001_CLIENT_PROTECTED

        buf = UInt8[]
        layout = QPK._begin_long_packet!(buf, QPT.Initial, QPK._QUIC_V1, UInt8[], _QPK_SCID, UInt8[], Int64(1), 2)
        _qpk_append_sealed!(buf, server, layout, _RFC9001_SERVER_PAYLOAD, 1)
        @test buf == _RFC9001_SERVER_PROTECTED
    end

    @testset "Retry packets (RFC 9001 A.4)" begin
        token = Vector{UInt8}(codeunits("token"))
        # The RFC sample sets the four unused bits of the first byte.
        retry = QPK._retry_packet(QPK._QUIC_V1, UInt8[], _QPK_SCID, token, _RFC9001_DCID; unused_bits = 0x0f)
        @test retry == _RFC9001_RETRY_PACKET
        retry = QPK._retry_packet(QPK._QUIC_V1, UInt8[0x01, 0x02], _QPK_SCID, token, _RFC9001_DCID)
        @test retry[1] & 0xf0 == 0xf0
        h = QPK._parse_packet(retry, 1, length(retry), 0)
        @test h.type == QPT.Retry
        @test _qpk_bytes(retry, h.dcid) == UInt8[0x01, 0x02]
        @test _qpk_bytes(retry, h.token) == token
        @test QPK._valid_retry_integrity(_RFC9001_DCID, retry)
        # A Retry with no room for a token and tag is dropped.
        @test QPK._parse_packet(retry, 1, h.token.start + 14, 0) === nothing
        # So is a well-formed one with an empty token (RFC 9000 Section 17.2.5.2).
        empty_token = vcat(UInt8[0xf0, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08], _QPK_SCID)
        append!(empty_token, QPK._retry_integrity_tag(_RFC9001_DCID, empty_token))
        @test QPK._valid_retry_integrity(_RFC9001_DCID, empty_token)
        @test QPK._parse_packet(empty_token, 1, length(empty_token), 0) === nothing
    end

    @testset "Version Negotiation packets" begin
        dcid = UInt8[0xaa, 0xbb]
        versions = UInt32[QPK._QUIC_V1, 0x0a0a0a0a]
        vn = QPK._version_negotiation_packet(dcid, _QPK_SCID, versions)
        @test vn[1] & 0xc0 == 0xc0  # long header, with the fixed bit set as RFC 9000 Section 17.2.1 suggests
        h = QPK._parse_packet(vn, 1, length(vn), 0)
        @test h.type == QPT.VersionNegotiation
        @test h.version == 0x00000000
        @test _qpk_bytes(vn, h.dcid) == dcid
        @test _qpk_bytes(vn, h.scid) == _QPK_SCID
        @test QPK._version_negotiation_versions(vn, h) == versions
        # A version list that is not a whole number of versions is malformed.
        @test QPK._parse_packet(vn, 1, length(vn) - 1, 0) === nothing
        @test QPK._parse_packet(vn, 1, h.scid.stop, 0) === nothing  # no versions at all
    end

    @testset "unsupported versions keep the invariant fields" begin
        # RFC 8999: any version may use connection IDs up to 255 bytes.
        dcid = rand(UInt8, 25)
        pkt = vcat(UInt8[0xc0, 0x1a, 0x2b, 0x3c, 0x4d, 25], dcid, UInt8[3, 0x01, 0x02, 0x03], rand(UInt8, 1200))
        h = QPK._parse_packet(pkt, 1, length(pkt), 0)
        @test h.type == QPT.UnsupportedVersion
        @test h.version == 0x1a2b3c4d
        @test _qpk_bytes(pkt, h.dcid) == dcid
        @test _qpk_bytes(pkt, h.scid) == UInt8[0x01, 0x02, 0x03]
        @test h.last == length(pkt)
        # Version 1 caps them at 20 bytes.
        pkt[2:5] = UInt8[0x00, 0x00, 0x00, 0x01]
        @test QPK._parse_packet(pkt, 1, length(pkt), 0) === nothing
    end

    @testset "coalesced packets in one datagram" begin
        dcid = rand(UInt8, 8)
        scid = rand(UInt8, 6)
        token = Vector{UInt8}(codeunits("tok"))
        initial = QPK._PacketKeys(UInt16(0x1301), rand(UInt8, 32))
        handshake = QPK._PacketKeys(UInt16(0x1303), rand(UInt8, 32))
        onertt = QPK._PacketKeys(UInt16(0x1302), rand(UInt8, 48))
        payloads = [rand(UInt8, 30), rand(UInt8, 40), rand(UInt8, 50)]

        buf = UInt8[]
        _qpk_append_sealed!(buf, initial, QPK._begin_long_packet!(buf, QPT.Initial, QPK._QUIC_V1, dcid, scid, token, Int64(0), 1), payloads[1], 0)
        _qpk_append_sealed!(buf, handshake, QPK._begin_long_packet!(buf, QPT.Handshake, QPK._QUIC_V1, dcid, scid, UInt8[], Int64(3), 2), payloads[2], 3)
        _qpk_append_sealed!(buf, onertt, QPK._begin_short_packet!(buf, dcid, Int64(9), 3; key_phase = true), payloads[3], 9)

        headers = _qpk_packets(buf, length(dcid))
        @test [h.type for h in headers] == [QPT.Initial, QPT.Handshake, QPT.OneRTT]
        @test _qpk_bytes(buf, headers[1].token) == token
        @test all(h -> _qpk_bytes(buf, h.dcid) == dcid, headers)
        @test _qpk_bytes(buf, headers[2].scid) == scid
        @test isempty(headers[3].scid)
        @test headers[1].first == 1
        @test headers[2].first == headers[1].last + 1
        @test headers[3].first == headers[2].last + 1
        @test headers[3].last == length(buf)

        for (h, keys, payload, pn) in zip(headers, (initial, handshake, onertt), payloads, (0, 3, 9))
            opened = QPK._open_packet!(keys, buf, h.first, h.pn_offset, h.last, Int64(pn - 1))
            @test opened !== nothing
            opened === nothing && continue
            @test opened[1] == pn
            @test buf[opened[2]:opened[3]] == payload
            @test QPK._reserved_bits_ok(buf[h.first])
        end
        @test buf[headers[3].first] & 0x04 != 0  # key phase, readable once unprotected
    end

    @testset "datagram iteration stops at what it must ignore" begin
        dcid = rand(UInt8, 8)
        keys = QPK._PacketKeys(UInt16(0x1301), rand(UInt8, 32))
        buf = UInt8[]
        _qpk_append_sealed!(buf, keys, QPK._begin_long_packet!(buf, QPT.Handshake, QPK._QUIC_V1, dcid, UInt8[], UInt8[], Int64(1), 1), rand(UInt8, 20), 1)
        one = length(buf)

        # Zero padding after the last packet (a short header with no fixed bit).
        @test length(_qpk_packets(vcat(buf, zeros(UInt8, 30)), 8)) == 1

        # RFC 9000 Section 12.2: later packets for another connection ID are ignored.
        other = copy(buf)
        _qpk_append_sealed!(other, keys, QPK._begin_long_packet!(other, QPT.Handshake, QPK._QUIC_V1, rand(UInt8, 8), UInt8[], UInt8[], Int64(2), 1), rand(UInt8, 20), 2)
        @test length(_qpk_packets(other, 8)) == 1
        same = copy(buf)
        _qpk_append_sealed!(same, keys, QPK._begin_long_packet!(same, QPT.Handshake, QPK._QUIC_V1, dcid, UInt8[], UInt8[], Int64(2), 1), rand(UInt8, 20), 2)
        @test length(_qpk_packets(same, 8)) == 2

        # A Length field running past the datagram drops the packet.
        @test isempty(_qpk_packets(buf[1:(one - 1)], 8))
        # The fixed bit must be set in version 1 packets.
        cleared = copy(buf)
        cleared[1] &= 0xbf
        @test isempty(_qpk_packets(cleared, 8))
        # Headers cut short.
        for n in (1, 3, 6, 10, 15)
            @test QPK._parse_packet(buf, 1, n, 8) === nothing
        end
        # A short header shorter than the local connection ID length.
        @test QPK._parse_packet(UInt8[0x41, 0x01, 0x02], 1, 3, 8) === nothing
    end

    @testset "builders" begin
        # Tiny payloads are padded so the header protection sample fits.
        keys = QPK._PacketKeys(UInt16(0x1301), rand(UInt8, 32))
        buf = UInt8[]
        layout = QPK._begin_short_packet!(buf, UInt8[0x01, 0x02], Int64(5), 1)
        push!(buf, 0x01)  # a PING frame
        payload_last = QPK._end_packet!(buf, layout)
        @test payload_last - layout.pn_offset + 1 >= 4
        @test buf[(layout.pn_offset + 2):payload_last] == zeros(UInt8, payload_last - layout.pn_offset - 1)  # PADDING frames
        QPK._seal_packet!(keys, buf, layout.first, layout.pn_offset, layout.pn_len, payload_last, Int64(5))
        h = QPK._parse_packet(buf, 1, length(buf), 2)
        opened = QPK._open_packet!(keys, buf, h.first, h.pn_offset, h.last, Int64(4))
        @test opened !== nothing
        @test buf[opened[2]] == 0x01

        # The two-byte Length field caps a long header packet's size.
        buf = UInt8[]
        layout = QPK._begin_long_packet!(buf, QPT.Handshake, QPK._QUIC_V1, UInt8[], UInt8[], UInt8[], Int64(0), 1)
        append!(buf, zeros(UInt8, 16_400))
        @test_throws ArgumentError QPK._end_packet!(buf, layout)

        @test_throws ArgumentError QPK._begin_short_packet!(UInt8[], UInt8[], Int64(0), 5)
        @test_throws ArgumentError QPK._begin_long_packet!(UInt8[], QPT.Retry, QPK._QUIC_V1, UInt8[], UInt8[], UInt8[], Int64(0), 1)
        @test_throws ArgumentError QPK._begin_long_packet!(UInt8[], QPT.Handshake, QPK._QUIC_V1, rand(UInt8, 21), UInt8[], UInt8[], Int64(0), 1)
        @test_throws ArgumentError QPK._begin_long_packet!(UInt8[], QPT.Handshake, QPK._QUIC_V1, UInt8[], UInt8[], UInt8[0x01], Int64(0), 1)  # tokens are Initial-only
    end

    @testset "reserved bits after header protection is removed" begin
        @test QPK._reserved_bits_ok(0xc3)
        @test !QPK._reserved_bits_ok(0xcb)  # long header reserved bit 0x08
        @test !QPK._reserved_bits_ok(0xc7)  # long header reserved bit 0x04
        @test QPK._reserved_bits_ok(0x45)   # short header with the key phase bit
        @test !QPK._reserved_bits_ok(0x51)  # short header reserved bit 0x10
        @test !QPK._reserved_bits_ok(0x49)  # short header reserved bit 0x08
    end
end
