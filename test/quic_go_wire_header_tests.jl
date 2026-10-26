using Test
using Reseau

# Ports of quic-go v0.48.2 internal/wire header tests:
#   header_test.go, extended_header_test.go, short_header_test.go,
#   version_negotiation_test.go
# from github.com/quic-go/quic-go@v0.48.2/internal/wire. Testset names are the
# Go test names. quic-go's ParsePacket / ParseConnectionID / ParseShortHeader
# map to `_parse_packet` (which also serves DCID routing); "ParseExtended"
# (reading the packet number once header protection is off) maps to reading
# the bytes at `pn_offset`, with the length from the first byte's low bits as
# `_remove_header_protection!` does. quic-go's ExtendedHeader.Append maps to
# `_begin_long_packet!`/`_end_packet!`, AppendShortHeader to
# `_begin_short_packet!`, ComposeVersionNegotiation to
# `_version_negotiation_packet`. Inputs that Go builds with ExtendedHeader.Append
# are built byte for byte by `_qgwh_long_header` below.
#
# Not ported (N/A):
# - TestIs0RTT, TestParseVersion, TestDistinguishesLongAndShortHeaderPackets:
#   Go-only prefix helpers (Is0RTTPacket, ParseVersion, IsLongHeaderPacket);
#   we have no 0-RTT and only parse whole headers.
# - QUIC v2 cases: the "QUIC v2" subtests of TestParseRetryPacket and
#   TestWritesRetryPacket, TestWritesHandshakePacketVersion2,
#   TestWritesInitialPacketVersion2, TestWrites0RTTPacketVersion2 (no RFC 9369).
# - GetLength()/ParsedLen() assertions without a Julia counterpart.
# - Logging: TestPacketTypeForLogging, TestLogsLongHeaders,
#   TestLogsInitialPacketsWithToken, TestLogsInitialPacketsWithoutToken,
#   TestLogsRetryPacketsWithToken, TestLogShortHeaderWithConnectionID.
# - Benchmarks.
# internal/wire has no varint or packet number encoding tests of its own
# (those live in quicvarint and internal/protocol).

const QGWH = Reseau.QUIC
const QGWHT = QGWH._PacketType

_qgwh_v(v::Integer) = (b = UInt8[]; QGWH._append_varint!(b, UInt64(v)); b)
_qgwh_b(s::AbstractString) = Vector{UInt8}(codeunits(s))
_qgwh_u32(v::Integer) = UInt8[(UInt32(v) >> 24) & 0xff, (UInt32(v) >> 16) & 0xff, (UInt32(v) >> 8) & 0xff, UInt32(v) & 0xff]
_qgwh_parse(buf::Vector{UInt8}, short_dcid_len::Int = 0) =
    isempty(buf) ? QGWH._parse_packet(buf, 1, 0, short_dcid_len) : QGWH._parse_packet(buf, 1, length(buf), short_dcid_len)
_qgwh_contains(haystack::Vector{UInt8}, needle::Vector{UInt8}) =
    any(i -> haystack[i:(i + length(needle) - 1)] == needle, 1:(length(haystack) - length(needle) + 1))

# Long header type bits in version 1.
const _QGWH_INITIAL = 0x0
const _QGWH_0RTT = 0x1
const _QGWH_HANDSHAKE = 0x2
const _QGWH_RETRY = 0x3

# quic-go's ExtendedHeader.Append for a non-Retry long header: Length is always
# a 2-byte varint, then the packet number.
function _qgwh_long_header(type_bits, version, dcid, scid; token = UInt8[], length = 0, pn = 0, pn_len = 1)
    b = UInt8[0xc0 | (UInt8(type_bits) << 4) | UInt8(pn_len - 1)]
    append!(b, _qgwh_u32(version))
    push!(b, UInt8(Base.length(dcid)))
    append!(b, dcid)
    push!(b, UInt8(Base.length(scid)))
    append!(b, scid)
    if type_bits == _QGWH_INITIAL
        append!(b, _qgwh_v(Base.length(token)))
        append!(b, token)
    end
    QGWH._append_varint!(b, UInt64(length), 2)
    for i in (pn_len - 1):-1:0
        push!(b, UInt8((pn >> (8i)) & 0xff))
    end
    return b
end

# The packet number length and (unprotected) packet number of a parsed header.
function _qgwh_pn(buf::Vector{UInt8}, h)
    pn_len = Int(buf[h.first] & 0x03) + 1
    pn = UInt64(0)
    for i in 0:(pn_len - 1)
        pn = (pn << 8) | buf[h.pn_offset + i]
    end
    return pn_len, pn
end

_qgwh_key_phase(buf::Vector{UInt8}, h) = (buf[h.first] & 0x04) != 0  # as connection.jl reads it

@testset "quic-go internal/wire headers" begin
    # header_test.go
    @testset "TestParseConnIDLongHeaderPacket" begin
        b = _qgwh_long_header(_QGWH_HANDSHAKE, QGWH._QUIC_V1, UInt8[0xde, 0xca, 0xfb, 0xad], UInt8[1, 2, 3, 4, 5, 6]; pn_len = 2)
        h = _qgwh_parse(b, 8)
        # Differs from quic-go: it reads the DCID of a long header without
        # looking at Length. We parse the whole header to route a packet, and
        # Length 0 cannot even hold a packet number, so the packet could never
        # be opened; dropping it before routing loses nothing.
        @test h === nothing
        # With a Length that covers the packet number it routes.
        b2 = _qgwh_long_header(_QGWH_HANDSHAKE, QGWH._QUIC_V1, UInt8[0xde, 0xca, 0xfb, 0xad], UInt8[1, 2, 3, 4, 5, 6];
                               pn_len = 2, length = 2)
        h2 = _qgwh_parse(b2, 8)
        @test h2 !== nothing && b2[h2.dcid] == UInt8[0xde, 0xca, 0xfb, 0xad]
    end

    @testset "TestParseConnIDTooLong" begin
        b = vcat(UInt8[0x80], _qgwh_u32(QGWH._QUIC_V1), UInt8[21], zeros(UInt8, 21))
        @test _qgwh_parse(b, 4) === nothing  # ErrInvalidConnectionIDLen
    end

    @testset "TestParseConnIDEOFLongHeader" begin
        b = _qgwh_long_header(_QGWH_HANDSHAKE, QGWH._QUIC_V1, UInt8[0xde, 0xca, 0xfb, 0xad, 0x13, 0x37],
                              UInt8[1, 2, 3, 4, 5, 6, 8, 9]; pn_len = 2)
        data = b[1:(end - 2)]  # cut the packet number
        # Differs from quic-go: as in TestParseConnIDLongHeaderPacket, Length
        # 0 makes us drop the header where quic-go still returns its DCID.
        @test _qgwh_parse(data, 8) === nothing
        for i in 0:(1 + 4 + 1 + 6 - 1)
            @test _qgwh_parse(data[1:i], 8) === nothing
        end
    end

    @testset "TestParseArbitraryLengthConnectionIDs" begin
        for (dlen, slen) in ((rand(1:255), rand(1:255)), (1, 255), (255, 1), (255, 255), (21, 20))
            src = rand(UInt8, slen)
            dest = rand(UInt8, dlen)
            b = vcat(UInt8[0x80, 1, 2, 3, 4], UInt8[dlen], dest, UInt8[slen], src)
            l = length(b)
            append!(b, _qgwh_b("foobar"))  # some payload
            h = _qgwh_parse(b)
            @test h !== nothing
            @test h.type == QGWHT.UnsupportedVersion
            @test h.scid.stop == l
            @test b[h.scid] == src
            @test b[h.dcid] == dest
            @test all(i -> _qgwh_parse(b[1:i]) === nothing, 0:(l - 1))
        end
    end

    @testset "TestIdentifyVersionNegotiationPackets" begin
        # quic-go's IsVersionNegotiationPacket looks only at the first 5 bytes;
        # `_parse_packet` needs whole headers, so each input gets zero-length
        # connection IDs and one listed version appended.
        vn(prefix) = (b = vcat(prefix, UInt8[0, 0], _qgwh_u32(QGWH._QUIC_V1)); h = _qgwh_parse(b); h !== nothing && h.type == QGWHT.VersionNegotiation)
        @test vn(UInt8[0x80 | 0x56, 0, 0, 0, 0])
        @test !vn(UInt8[0x56, 0, 0, 0, 0])
        @test !vn(UInt8[0x80, 1, 0, 0, 0])
        @test !vn(UInt8[0x80, 0, 1, 0, 0])
        @test !vn(UInt8[0x80, 0, 0, 1, 0])
        @test !vn(UInt8[0x80, 0, 0, 0, 1])
    end

    @testset "TestVersionNegotiationPacketEOF" begin
        vnp = UInt8[0x80, 0, 0, 0, 0]
        for i in 0:(length(vnp) - 1)
            h = _qgwh_parse(vnp[1:i])
            @test h === nothing || h.type != QGWHT.VersionNegotiation
        end
    end

    @testset "TestParseLongHeader" begin
        dcid = UInt8[9, 8, 7, 6, 5, 4, 3, 2, 1]
        scid = UInt8[0xde, 0xad, 0xbe, 0xef]
        data = vcat(UInt8[0xc0 ⊻ 0x3], _qgwh_u32(QGWH._QUIC_V1), UInt8[0x9], dcid, UInt8[0x4], scid,
                    _qgwh_v(6), _qgwh_b("foobar"), _qgwh_v(10))
        hdr_len = length(data)
        append!(data, UInt8[0, 0, 0xbe, 0xef])  # packet number
        append!(data, _qgwh_b("foobar"))
        h = _qgwh_parse(data)
        @test h !== nothing
        @test h.type != QGWHT.VersionNegotiation
        @test (h.first, h.last) == (1, length(data))  # the whole packet; nothing left over
        @test data[h.dcid] == dcid
        @test data[h.scid] == scid
        @test h.type == QGWHT.Initial
        @test data[h.token] == _qgwh_b("foobar")
        @test h.last - h.pn_offset + 1 == 10  # Length
        @test h.version == QGWH._QUIC_V1
        @test _qgwh_pn(data, h) == (4, 0xbeef)
        @test h.pn_offset - 1 == hdr_len
    end

    @testset "TestErrorIfReservedBitNotSet" begin
        data = UInt8[0x80 | 0x2 << 4, 0x11, 0xde, 0xca, 0xfb, 0xad, 0xde, 0xad, 0xbe, 0xef]
        @test _qgwh_parse(data) === nothing  # "not a QUIC packet"
    end

    @testset "TestStopParsingWhenEncounteringUnsupportedVersion" begin
        data = UInt8[0xc0, 0xde, 0xad, 0xbe, 0xef, 0x8, 1, 2, 3, 4, 5, 6, 7, 8, 0x8, 8, 7, 6, 5, 4, 3, 2, 1,
                     UInt8('f'), UInt8('o'), UInt8('o'), UInt8('b'), UInt8('a'), UInt8('r')]
        h = _qgwh_parse(data)
        @test h !== nothing
        @test h.type == QGWHT.UnsupportedVersion  # ErrUnsupportedVersion
        @test h.version == 0xdeadbeef
        @test data[h.dcid] == UInt8[1, 2, 3, 4, 5, 6, 7, 8]
        @test data[h.scid] == UInt8[8, 7, 6, 5, 4, 3, 2, 1]
        @test h.last == length(data)
    end

    @testset "TestParseLongHeaderWithoutDestinationConnectionID" begin
        data = vcat(UInt8[0xc0 ⊻ 0x1 << 4], _qgwh_u32(QGWH._QUIC_V1), UInt8[0], UInt8[4], UInt8[0xde, 0xad, 0xbe, 0xef],
                    _qgwh_v(0), UInt8[0xde, 0xca, 0xfb, 0xad])
        # Differs from quic-go: Length is 0, which cannot hold a packet number
        # (see TestParseConnIDLongHeaderPacket); quic-go parses the header, we
        # reject it. With Length 4 we parse it as quic-go does.
        @test _qgwh_parse(data) === nothing
        data[end - 4] = 0x04
        h = _qgwh_parse(data)
        @test h !== nothing
        @test h.type == QGWHT.ZeroRTT
        @test data[h.scid] == UInt8[0xde, 0xad, 0xbe, 0xef]
        @test isempty(h.dcid)
    end

    @testset "TestParseLongHeaderWithoutSourceConnectionID" begin
        data = vcat(UInt8[0xc0 ⊻ 0x2 << 4], _qgwh_u32(QGWH._QUIC_V1), UInt8[10], UInt8.(1:10), UInt8[0],
                    _qgwh_v(0), UInt8[0xde, 0xca, 0xfb, 0xad])
        # Differs from quic-go: Length 0, as in the test above.
        @test _qgwh_parse(data) === nothing
        data[end - 4] = 0x04
        h = _qgwh_parse(data)
        @test h !== nothing
        @test isempty(h.scid)
        @test data[h.dcid] == UInt8.(1:10)
    end

    @testset "TestErrorOnTooLongDestinationConnectionID" begin
        data = vcat(UInt8[0xc0 ⊻ 0x2 << 4], _qgwh_u32(QGWH._QUIC_V1), UInt8[21], UInt8.(1:21), UInt8[0x0],
                    _qgwh_v(0), UInt8[0xde, 0xca, 0xfb, 0xad])
        @test _qgwh_parse(data) === nothing  # ErrInvalidConnectionIDLen
    end

    @testset "TestParseLongHeaderWith2BytePacketNumber" begin
        data = vcat(UInt8[0xc0 ⊻ 0x1], _qgwh_u32(QGWH._QUIC_V1), UInt8[0x0, 0x0], _qgwh_v(0), _qgwh_v(0), UInt8[0x1, 0x23])
        # Differs from quic-go: Length is 0 (the packet number lies past it);
        # quic-go parses the header and the packet number, we reject the
        # header. With a Length covering the packet number we read it.
        @test _qgwh_parse(data) === nothing
        data[end - 2] = 0x02
        h = _qgwh_parse(data)
        @test h !== nothing
        @test _qgwh_pn(data, h) == (2, 0x123)
        @test h.pn_offset + 1 == length(data)
    end

    @testset "TestParseRetryPacket" begin
        @testset "v1" begin
            data = vcat(UInt8[0xc0 | 0b11 << 4 | (10 - 3)], _qgwh_u32(QGWH._QUIC_V1), UInt8[6], UInt8[6, 5, 4, 3, 2, 1],
                        UInt8[10], UInt8.(1:10), _qgwh_b("foobar"), UInt8.(16:-1:1))
            h = _qgwh_parse(data)
            @test h !== nothing
            @test h.type == QGWHT.Retry
            @test h.version == QGWH._QUIC_V1
            @test data[h.dcid] == UInt8[6, 5, 4, 3, 2, 1]
            @test data[h.scid] == UInt8.(1:10)
            @test data[h.token] == _qgwh_b("foobar")
            @test (h.first, h.last) == (1, length(data))
        end
    end

    @testset "TestRetryPacketTooShortForIntegrityTag" begin
        data = vcat(UInt8[0xc0 | 0x3 << 4 | (10 - 3)], _qgwh_u32(QGWH._QUIC_V1), UInt8[0, 0], _qgwh_b("foobar"), UInt8.(1:10))
        @test _qgwh_parse(data) === nothing  # an empty token once the tag is taken off
    end

    @testset "TestTokenLengthTooLarge" begin
        data = vcat(UInt8[0xc0 ⊻ 0x1], _qgwh_u32(QGWH._QUIC_V1), UInt8[0x0], _qgwh_v(4), _qgwh_v(0x42), UInt8[0x12, 0x34])
        @test _qgwh_parse(data) === nothing
    end

    @testset "TestErrorOn5thOr6thBitSet" begin
        data = vcat(UInt8[0xc0 | 0x2 << 4 | 0x8 | 0x1], _qgwh_u32(QGWH._QUIC_V1), UInt8[0x0, 0x0], _qgwh_v(2), UInt8[0x12, 0x34])
        h = _qgwh_parse(data)
        @test h !== nothing
        @test h.type == QGWHT.Handshake
        @test !QGWH._reserved_bits_ok(data[h.first])  # ErrInvalidReservedBits
        @test _qgwh_pn(data, h)[2] == 0x1234
    end

    @testset "TestHeaderEOF" begin
        data = vcat(UInt8[0xc0 ⊻ 0x2 << 4], _qgwh_u32(QGWH._QUIC_V1), UInt8[0x8], UInt8[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37],
                    UInt8[0x8], UInt8[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37])
        for i in 1:(length(data) - 1)
            @test _qgwh_parse(data[1:i]) === nothing
        end
    end

    @testset "TestParseExtendedHeaderEOF" begin
        data = vcat(UInt8[0xc0 | 0x2 << 4 | 0x3], _qgwh_u32(QGWH._QUIC_V1), UInt8[0x0, 0x0], _qgwh_v(0))
        hdr_len = length(data)
        append!(data, UInt8[0xde, 0xad, 0xbe, 0xef])  # packet number
        # quic-go parses each header (NoError) and then fails to read the
        # packet number (io.EOF). Differs from quic-go: we already reject the
        # header for Length 0 (see TestParseConnIDLongHeaderPacket), so the
        # packet number is never read either.
        @test all(i -> _qgwh_parse(data[1:i]) === nothing, hdr_len:(length(data) - 1))
        # With a Length covering the packet number, a truncated one is the
        # EOF quic-go reports.
        data[hdr_len] = 0x04
        @test all(i -> _qgwh_parse(data[1:i]) === nothing, hdr_len:(length(data) - 1))
        @test _qgwh_parse(data) !== nothing
    end

    @testset "TestParseRetryEOF" begin
        data = vcat(UInt8[0xc0 ⊻ 0x3 << 4], _qgwh_u32(QGWH._QUIC_V1), UInt8[0x0, 0x0], UInt8[0xa], UInt8.(1:10))
        hdr_len = length(data)
        # As in Go, hdr_len == length(data), so this loop never runs.
        for i in hdr_len:(length(data) - 1)
            @test _qgwh_parse(data[1:i]) === nothing
        end
    end

    @testset "TestCoalescedPacketParsing" begin
        b = _qgwh_long_header(_QGWH_INITIAL, QGWH._QUIC_V1, UInt8[1, 2, 3, 4], UInt8[]; length = 2 + 6, pn = 0x1337, pn_len = 2)
        hdr_raw = copy(b)
        append!(b, _qgwh_b("foobar"))  # payload of the first packet
        append!(b, _qgwh_b("raboof"))  # second packet
        h = _qgwh_parse(b)
        @test h !== nothing
        @test h.type == QGWHT.Initial
        @test b[h.dcid] == UInt8[1, 2, 3, 4]
        @test b[h.first:h.last] == vcat(hdr_raw, _qgwh_b("foobar"))
        @test b[(h.last + 1):end] == _qgwh_b("raboof")
    end

    @testset "TestCoalescedPacketErrorOnTooSmallPacketNumber" begin
        b = _qgwh_long_header(_QGWH_INITIAL, QGWH._QUIC_V1, UInt8[1, 2, 3, 4], UInt8[]; length = 3, pn = 0x1337, pn_len = 2)
        @test _qgwh_parse(b) === nothing
    end

    @testset "TestCoalescedPacketErrorOnTooSmallPayload" begin
        b = _qgwh_long_header(_QGWH_INITIAL, QGWH._QUIC_V1, UInt8[1, 2, 3, 4], UInt8[]; length = 1000, pn = 0x1337, pn_len = 2)
        append!(b, zeros(UInt8, 500 - 2))
        @test _qgwh_parse(b) === nothing
    end

    # extended_header_test.go
    @testset "TestWritesLongHeaderVersion1" begin
        buf = UInt8[]
        dcid = UInt8[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe]
        scid = UInt8[0xde, 0xca, 0xfb, 0xad, 0x0, 0x0, 0x13, 0x37]
        layout = QGWH._begin_long_packet!(buf, QGWHT.Handshake, UInt32(0x1020304), dcid, scid, UInt8[], Int64(0xdecaf), 3)
        # Length 1234 = 3-byte packet number + payload + 16-byte AEAD tag.
        append!(buf, zeros(UInt8, 1234 - 3 - QGWH._AEAD_TAG_LEN))
        QGWH._end_packet!(buf, layout)
        expected = vcat(UInt8[0xc0 | 0x2 << 4 | 0x2], UInt8[0x1, 0x2, 0x3, 0x4], UInt8[0x6], dcid, UInt8[0x8], scid,
                        _qgwh_v(1234), UInt8[0xd, 0xec, 0xaf])
        @test buf[1:length(expected)] == expected
        @test layout.pn_offset + 2 == length(expected)
    end

    @testset "TestWritesHeaderWith20ByteConnectionID" begin
        # Go uses an out-of-range packet type (0x5); a Handshake header here.
        buf = UInt8[]
        dcid = UInt8.(1:20)
        QGWH._begin_long_packet!(buf, QGWHT.Handshake, UInt32(0x1020304), dcid, UInt8.(1:8), UInt8[], Int64(0xdecafbad), 4)
        @test _qgwh_contains(buf, dcid)
    end

    @testset "TestWritesInitialContainingToken" begin
        token = _qgwh_b("Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.")
        buf = UInt8[]
        QGWH._begin_long_packet!(buf, QGWHT.Initial, UInt32(0x1020304), UInt8[], UInt8[], token, Int64(0xdecafbad), 4)
        @test (buf[1] >> 4) & 0b11 == 0
        @test _qgwh_contains(buf, vcat(_qgwh_v(length(token)), token))
    end

    @testset "TestUses2ByteEncodingForLengthOnInitialPackets" begin
        buf = UInt8[]
        layout = QGWH._begin_long_packet!(buf, QGWHT.Initial, UInt32(0x1020304), UInt8[], UInt8[], UInt8[], Int64(0xdecafbad), 4)
        # Length 37 = 4-byte packet number + 17 payload bytes + 16-byte tag.
        append!(buf, zeros(UInt8, 37 - 4 - QGWH._AEAD_TAG_LEN))
        QGWH._end_packet!(buf, layout)
        length_encoded = (b = UInt8[]; QGWH._append_varint!(b, UInt64(37), 2); b)
        # b[len(b)-6:len(b)-4] of the header: just before the 4-byte packet number.
        @test buf[(layout.pn_offset - 2):(layout.pn_offset - 1)] == length_encoded
    end

    @testset "TestWritesRetryPacket" begin
        token = _qgwh_b("Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.")
        @testset "v1" begin
            b = QGWH._retry_packet(QGWH._QUIC_V1, UInt8[], UInt8[], token, UInt8[1, 2, 3, 4]; unused_bits = 0x00)
            expected = vcat(UInt8[0xc0 | 0b11 << 4], _qgwh_u32(QGWH._QUIC_V1), UInt8[0x0], UInt8[0x0], token)
            # quic-go appends the integrity tag separately.
            @test b[1:(end - QGWH._AEAD_TAG_LEN)] == expected
        end
    end

    # short_header_test.go
    @testset "TestParseShortHeader" begin
        data = UInt8[0b01000110, 0xde, 0xad, 0xbe, 0xef, 0x13, 0x37, 0x99]
        h = _qgwh_parse(data, 4)
        @test h !== nothing
        @test h.type == QGWHT.OneRTT
        @test h.last == length(data)
        @test _qgwh_key_phase(data, h)
        @test _qgwh_pn(data, h) == (3, 0x133799)
        @test h.pn_offset + 3 - 1 == length(data)
        @test QGWH._reserved_bits_ok(data[1])
    end

    @testset "TestParseShortHeaderNoQUICBit" begin
        data = UInt8[0b00000101, 0xde, 0xad, 0xbe, 0xef, 0x13, 0x37]
        @test _qgwh_parse(data, 4) === nothing  # "not a QUIC packet"
    end

    @testset "TestParseShortHeaderReservedBitsSet" begin
        data = UInt8[0b01010101, 0xde, 0xad, 0xbe, 0xef, 0x13, 0x37]
        h = _qgwh_parse(data, 4)
        @test h !== nothing
        @test !QGWH._reserved_bits_ok(data[1])  # ErrInvalidReservedBits
        @test _qgwh_pn(data, h)[2] == 0x1337
    end

    @testset "TestParseShortHeaderErrorsWhenPassedLongHeaderPacket" begin
        h = _qgwh_parse(UInt8[0x80], 4)
        @test h === nothing || h.type != QGWHT.OneRTT  # "not a short header packet"
    end

    @testset "TestParseShortHeaderErrorsOnEOF" begin
        data = UInt8[0b01000110, 0xde, 0xad, 0xbe, 0xef, 0x13, 0x37, 0x99]
        @test _qgwh_parse(data, 4) !== nothing
        # quic-go reads the (unprotected) packet number length and fails when
        # the packet number is cut. The length is header protected, so
        # `_parse_packet` cannot check it; a packet cut inside its packet
        # number is instead too short for the header protection sample, and
        # `_remove_header_protection!` drops it. quic-go's unpacker applies the
        # same sample check before ParseShortHeader.
        keys = QGWH._PacketKeys(UInt16(0x1301), rand(UInt8, 32))
        try
            for i in 0:(length(data) - 1)
                prefix = data[1:i]
                h = _qgwh_parse(prefix, 4)
                @test h === nothing || QGWH._remove_header_protection!(keys.hp, copy(prefix), h.first, h.pn_offset, h.last) === nothing
            end
        finally
            QGWH._destroy_packet_keys!(keys)
        end
    end

    @testset "TestShortHeaderLen" begin
        buf = UInt8[]
        layout = QGWH._begin_short_packet!(buf, UInt8[1, 2, 3, 4], Int64(0), 3)
        @test layout.pn_offset + layout.pn_len - 1 == length(buf) == 8
        buf = UInt8[]
        layout = QGWH._begin_short_packet!(buf, UInt8[], Int64(0), 1)
        @test layout.pn_offset + layout.pn_len - 1 == length(buf) == 2
    end

    @testset "TestWriteShortHeaderPacket" begin
        b = UInt8[]
        QGWH._begin_short_packet!(b, UInt8[1, 2, 3, 4], Int64(1337), 4; key_phase = true)
        h = _qgwh_parse(b, 4)
        @test h !== nothing
        @test h.type == QGWHT.OneRTT
        @test _qgwh_pn(b, h) == (4, 1337)
        @test _qgwh_key_phase(b, h)
        @test h.pn_offset + 4 - 1 == length(b)
    end

    # version_negotiation_test.go
    @testset "TestParseVersionNegotiationPacket" begin
        src = rand(UInt8, rand(1:255))
        dest = rand(UInt8, rand(1:255))
        versions = UInt32[0x22334455, 0x33445566]
        data = vcat(UInt8[0x80, 0, 0, 0, 0], UInt8[length(dest)], dest, UInt8[length(src)], src)
        for v in versions
            append!(data, _qgwh_u32(v))
        end
        h = _qgwh_parse(data)
        @test h !== nothing
        @test h.type == QGWHT.VersionNegotiation
        @test data[h.dcid] == dest
        @test data[h.scid] == src
        @test QGWH._version_negotiation_versions(data, h) == versions
    end

    @testset "TestParseVersionNegotiationPacketWithInvalidLength" begin
        cid = UInt8.(1:8)
        data = QGWH._version_negotiation_packet(cid, cid, UInt32[0x22334455, 0x33445566])
        @test _qgwh_parse(data[1:(end - 2)]) === nothing
    end

    @testset "TestParseVersionNegotiationPacketEmptyVersions" begin
        cid = UInt8.(1:8)
        versions = UInt32[0x22334455]
        data = QGWH._version_negotiation_packet(cid, cid, versions)
        # The listed version and the greased one the composer adds.
        data = data[1:(end - 4 * (length(versions) + 1))]
        @test _qgwh_parse(data) === nothing  # empty version list
    end

    @testset "TestComposeVersionNegotiationWithReservedVersion" begin
        src = UInt8[0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37]
        dest = UInt8.(1:8)
        versions = UInt32[1001, 1003]
        data = QGWH._version_negotiation_packet(dest, src, versions)
        @test data[1] & 0x80 != 0
        @test data[1] & 0x40 != 0
        h = _qgwh_parse(data)
        @test h !== nothing
        @test h.version == 0
        @test data[h.dcid] == dest
        @test data[h.scid] == src
        supported = QGWH._version_negotiation_versions(data, h)
        for v in versions
            @test v in supported
        end
        reserved = filter(v -> !(v in versions), supported)
        # One greased (0x?a?a?a?a) version is added (RFC 9000 Section 6.3).
        @test length(supported) == length(versions) + 1
        @test length(reserved) == 1 && reserved[1] != 0 && reserved[1] & 0x0f0f0f0f == 0x0a0a0a0a
    end
end
