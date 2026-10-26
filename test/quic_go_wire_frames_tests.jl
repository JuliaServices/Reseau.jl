using Test
using Reseau

# Ports of quic-go v0.48.2 internal/wire frame tests:
#   ack_frame_test.go, ack_range_test.go, connection_close_frame_test.go,
#   crypto_frame_test.go, data_blocked_frame_test.go, datagram_frame_test.go,
#   frame_parser_test.go, handshake_done_frame_test.go, max_data_frame_test.go,
#   max_stream_data_frame_test.go, max_streams_frame_test.go,
#   new_connection_id_frame_test.go, new_token_frame_test.go,
#   path_challenge_frame_test.go, path_response_frame_test.go,
#   ping_frame_test.go, pool_test.go, reset_stream_frame_test.go,
#   retire_connection_id_frame_test.go, stop_sending_frame_test.go,
#   stream_data_blocked_frame_test.go, streams_blocked_frame_test.go,
#   stream_frame_test.go
# from github.com/quic-go/quic-go@v0.48.2/internal/wire. Testset names are the
# Go test names. quic-go parses one frame at a time (`parseXxxFrame(b, typ)`);
# here the frame type and body go through `_decode_frames` on a 1-RTT payload,
# so "consumed len(data) bytes" becomes "decoded exactly one frame with no
# error", and io.EOF becomes a FRAME_ENCODING_ERROR naming the frame type.
#
# Not ported (N/A):
# - Length()/GetLength() assertions, MaxDataLen and MaybeSplitOffFrame tests
#   (TestCryptoFrameMaxDataLength, TestCryptoFrameSplitting,
#   TestCryptoFrameNoSplitWhenEnoughSpace, TestCryptoFrameNoSplitWhenSizeTooSmall,
#   TestStreamMaxDataLength, TestStreamMaxDataLengthWithDataLenPresent,
#   TestStreamSplitting*, TestWriteConnectionCloseTransportError,
#   TestWriteConnectionCloseLength): Go-only size/splitting helpers; we size
#   frames inline in the packet builder.
# - TestAckRangeLength, TestAckFrameReset: Go-only helper methods.
# - datagram_frame_test.go (all 8 tests) and TestFrameParsingUnpacksDatagramFrames:
#   no DATAGRAM (RFC 9221) support. TestFrameParsingErrorsWhenDatagramFramesAreNotSupported
#   IS ported, since that is our behavior.
# - pool_test.go (3 tests) and the fromPool/PutBack parts of
#   TestParseStreamUsesBufferForLongFrames / TestParseStreamDoesNotUseBufferForShortFrames:
#   Go buffer pools.
# - BenchmarkParseStreamAndACK, BenchmarkParseOtherFrames: benchmarks.
# - log_test.go (17 tests): Go frame logging.

const QGWF = Reseau.QUIC
const QGWFT = QGWF._PacketType

@isdefined(_QcnHarness) || include("quic_harness.jl")

_qgwf_v(v::Integer) = (b = UInt8[]; QGWF._append_varint!(b, UInt64(v)); b)
_qgwf_b(s::AbstractString) = Vector{UInt8}(codeunits(s))
_qgwf_r(a::Integer, b::Integer) = UInt64(a):UInt64(b)
_qgwf_enc(f) = (b = UInt8[]; f(b); b)

function _qgwf_decode(buf::Vector{UInt8}, packet_type = QGWFT.OneRTT)
    frames = Any[]
    result = QGWF._decode_frames(buf, 1, length(buf), packet_type) do frame
        push!(frames, frame)
        return nothing
    end
    return frames, result
end

# The frame type followed by `payload`, like quic-go's `parseXxxFrame(payload, typ)`.
function _qgwf_parse(type::Integer, payload::Vector{UInt8})
    buf = vcat(_qgwf_v(type), payload)
    frames, result = _qgwf_decode(buf)
    return buf, frames, result
end

# Whether the payload decodes to exactly one frame using every byte.
function _qgwf_one(type::Integer, payload::Vector{UInt8})
    buf, frames, result = _qgwf_parse(type, payload)
    ok = result.error === nothing && length(frames) == 1
    return ok, buf, ok ? frames[1] : nothing
end

# quic-go's io.EOF: a malformed frame of this type.
function _qgwf_malformed(type::Integer, payload::Vector{UInt8})
    _, _, result = _qgwf_parse(type, payload)
    err = result.error
    return err !== nothing && err.code == QGWF._FRAME_ENCODING_ERROR && err.frame_type == UInt64(type)
end

_qgwf_all_prefixes_malformed(type::Integer, data::Vector{UInt8}) =
    all(i -> _qgwf_malformed(type, data[1:i]), 0:(length(data) - 1))

_qgwf_throws(f) = try
    f()
    false
catch
    true
end

_qgwf_ranges(buf, ack) = collect(QGWF._ack_ranges(buf, ack))
_qgwf_acks(buf, ack, pn) = any(r -> UInt64(pn) in r, QGWF._ack_ranges(buf, ack))

# quic-go's default ack_delay_exponent and AckFrame.Append's scaling of a delay.
const _QGWF_ACK_DELAY_EXPONENT = 3
_qgwf_delay_field(ms::Integer) = UInt64(ms * 1000) >> _QGWF_ACK_DELAY_EXPONENT

# ACK Delay in nanoseconds as the connection computes it from the peer's exponent.
function _qgwf_ack_delay_ns(delay::UInt64, exponent::Integer)
    conn = QGWF._client_connection(_qcn_client_config(), Int64(0))
    conn.peer_params = QGWF._TransportParameters(ack_delay_exponent = UInt64(exponent))
    return QGWF._ack_delay_ns(conn, delay)
end

const _QGWF_ACK = 0x02
const _QGWF_ACK_ECN = 0x03

@testset "quic-go internal/wire frames" begin
    # ack_frame_test.go
    @testset "TestParseACKWithoutRanges" begin
        data = vcat(_qgwf_v(100), _qgwf_v(0), _qgwf_v(0), _qgwf_v(10))
        ok, buf, f = _qgwf_one(_QGWF_ACK, data)
        @test ok
        @test f.largest == 100
        @test _qgwf_ranges(buf, f) == [_qgwf_r(90, 100)]
        @test f.range_count == 0
    end

    @testset "TestParseACKSinglePacket" begin
        data = vcat(_qgwf_v(55), _qgwf_v(0), _qgwf_v(0), _qgwf_v(0))
        ok, buf, f = _qgwf_one(_QGWF_ACK, data)
        @test ok
        @test f.largest == 55
        @test _qgwf_ranges(buf, f) == [_qgwf_r(55, 55)]
        @test f.range_count == 0
    end

    @testset "TestParseACKAllPacketsFrom0ToLargest" begin
        data = vcat(_qgwf_v(20), _qgwf_v(0), _qgwf_v(0), _qgwf_v(20))
        ok, buf, f = _qgwf_one(_QGWF_ACK, data)
        @test ok
        @test f.largest == 20
        @test _qgwf_ranges(buf, f) == [_qgwf_r(0, 20)]
        @test f.range_count == 0
    end

    @testset "TestParseACKRejectFirstBlockLargerThanLargestAcked" begin
        data = vcat(_qgwf_v(20), _qgwf_v(0), _qgwf_v(0), _qgwf_v(21))
        @test _qgwf_malformed(_QGWF_ACK, data)  # "invalid first ACK range"
    end

    @testset "TestParseACKWithSingleBlock" begin
        data = vcat(_qgwf_v(1000), _qgwf_v(0), _qgwf_v(1), _qgwf_v(100), _qgwf_v(98), _qgwf_v(50))
        ok, buf, f = _qgwf_one(_QGWF_ACK, data)
        @test ok
        @test f.largest == 1000
        @test f.range_count > 0
        @test _qgwf_ranges(buf, f) == [_qgwf_r(900, 1000), _qgwf_r(750, 800)]
    end

    @testset "TestParseACKWithMultipleBlocks" begin
        data = vcat(_qgwf_v(100), _qgwf_v(0), _qgwf_v(2), _qgwf_v(0), _qgwf_v(0), _qgwf_v(0), _qgwf_v(1), _qgwf_v(1))
        ok, buf, f = _qgwf_one(_QGWF_ACK, data)
        @test ok
        @test f.largest == 100
        @test f.range_count > 0
        @test _qgwf_ranges(buf, f) == [_qgwf_r(100, 100), _qgwf_r(98, 98), _qgwf_r(94, 95)]
    end

    @testset "TestParseACKUseAckDelayExponent" begin
        delay_ms = 1 << 10
        b = _qgwf_enc(buf -> QGWF._append_ack_frame!(buf, [_qgwf_r(1, 1)], _qgwf_delay_field(delay_ms)))
        frames, result = _qgwf_decode(b)
        @test result.error === nothing && length(frames) == 1
        for i in 0:7
            @test _qgwf_ack_delay_ns(frames[1].delay, _QGWF_ACK_DELAY_EXPONENT + i) == Int64(delay_ms) * 1_000_000 * (1 << i)
        end
    end

    @testset "TestParseACKHandleDelayTimeOverflow" begin
        data = vcat(_qgwf_v(100), _qgwf_v(typemax(UInt64) ÷ 5), _qgwf_v(0), _qgwf_v(0))
        ok, _, f = _qgwf_one(_QGWF_ACK, data)
        @test ok
        ns = _qgwf_ack_delay_ns(f.delay, _QGWF_ACK_DELAY_EXPONENT)
        @test ns > 0
        # BUG?: quic-go saturates an overflowing ACK Delay to the largest
        # time.Duration (~292 years); we substitute the peer's max_ack_delay (25 ms).
        @test_broken abs(ns / 3.6e12 - 292 * 365 * 24) <= 365 * 24
    end

    @testset "TestParseACKErrorOnEOF" begin
        data = vcat(_qgwf_v(1000), _qgwf_v(0), _qgwf_v(1), _qgwf_v(100), _qgwf_v(98), _qgwf_v(50))
        @test _qgwf_one(_QGWF_ACK, data)[1]
        @test _qgwf_all_prefixes_malformed(_QGWF_ACK, data)
    end

    @testset "TestParseACKECN" begin
        data = vcat(_qgwf_v(100), _qgwf_v(0), _qgwf_v(0), _qgwf_v(10), _qgwf_v(0x42), _qgwf_v(0x12345), _qgwf_v(0x12345678))
        ok, buf, f = _qgwf_one(_QGWF_ACK_ECN, data)
        @test ok
        @test f.largest == 100
        @test _qgwf_ranges(buf, f) == [_qgwf_r(90, 100)]
        @test f.range_count == 0
        @test f.ecn
        @test f.ect0 == 0x42
        @test f.ect1 == 0x12345
        @test f.ce == 0x12345678
    end

    @testset "TestParseACKECNErrorOnEOF" begin
        data = vcat(_qgwf_v(1000), _qgwf_v(0), _qgwf_v(1), _qgwf_v(100), _qgwf_v(98), _qgwf_v(50),
                    _qgwf_v(0x42), _qgwf_v(0x12345), _qgwf_v(0x12345678))
        @test _qgwf_one(_QGWF_ACK_ECN, data)[1]
        @test _qgwf_all_prefixes_malformed(_QGWF_ACK_ECN, data)
    end

    @testset "TestWriteACKSimpleFrame" begin
        b = _qgwf_enc(buf -> QGWF._append_ack_frame!(buf, [_qgwf_r(100, 1337)], UInt64(0)))
        @test b == vcat(UInt8[_QGWF_ACK], _qgwf_v(1337), UInt8[0], _qgwf_v(0), _qgwf_v(1337 - 100))
    end

    @testset "TestWriteACKECNFrame" begin
        b = _qgwf_enc(buf -> QGWF._append_ack_frame!(buf, [_qgwf_r(10, 2000)], UInt64(0); ecn = (UInt64(13), UInt64(37), UInt64(12345))))
        @test b == vcat(UInt8[_QGWF_ACK_ECN], _qgwf_v(2000), UInt8[0], _qgwf_v(0), _qgwf_v(2000 - 10),
                        _qgwf_v(13), _qgwf_v(37), _qgwf_v(12345))
    end

    # Write, decode, and compare the ranges and delay, as the Go round trips do.
    function _qgwf_ack_roundtrip(ranges, delay = UInt64(0))
        b = _qgwf_enc(buf -> QGWF._append_ack_frame!(buf, ranges, delay))
        frames, result = _qgwf_decode(b)
        ok = result.error === nothing && length(frames) == 1 && frames[1] isa QGWF._AckFrame
        return ok, b, ok ? frames[1] : nothing
    end

    @testset "TestWriteACKSinglePacket" begin
        delay = _qgwf_delay_field(18)
        ok, b, f = _qgwf_ack_roundtrip([_qgwf_r(0x2eadbeef, 0x2eadbeef)], delay)
        @test ok
        @test _qgwf_ranges(b, f) == [_qgwf_r(0x2eadbeef, 0x2eadbeef)]
        @test f.range_count == 0
        @test f.delay == delay
    end

    @testset "TestWriteACKManyPackets" begin
        ok, b, f = _qgwf_ack_roundtrip([_qgwf_r(0x1337, 0x2eadbeef)])
        @test ok
        @test _qgwf_ranges(b, f) == [_qgwf_r(0x1337, 0x2eadbeef)]
        @test f.range_count == 0
    end

    @testset "TestWriteACKSingleGap" begin
        ranges = [_qgwf_r(400, 1000), _qgwf_r(100, 200)]
        ok, b, f = _qgwf_ack_roundtrip(ranges)
        @test ok
        @test _qgwf_ranges(b, f) == ranges
        @test f.range_count > 0
    end

    @testset "TestWriteACKMultipleRanges" begin
        ranges = [_qgwf_r(10, 10), _qgwf_r(8, 8), _qgwf_r(5, 6), _qgwf_r(1, 3)]
        ok, b, f = _qgwf_ack_roundtrip(ranges)
        @test ok
        @test _qgwf_ranges(b, f) == ranges
        @test f.range_count > 0
    end

    @testset "TestWriteACKLimitMaxSize" begin
        # quic-go's AckFrame.Append drops ranges to stay within MaxAckFrameSize
        # (1000 bytes). Our encoder writes what it is given; the connection
        # bounds the ranges it keeps with _keep_largest_ranges!.
        max_ack_frame_size = 1000
        num_ranges = 1000
        received = QGWF._RangeSet()
        for i in 1:num_ranges
            push!(received, Int64(2i):Int64(2i))
        end
        QGWF._keep_largest_ranges!(received, QGWF._MAX_ACK_RANGES)
        ok, b, f = _qgwf_ack_roundtrip(QGWF._descending_ranges(received))
        @test ok
        @test length(b) <= max_ack_frame_size
        # BUG?: quic-go packs the frame up to just under MaxAckFrameSize; we
        # keep at most _MAX_ACK_RANGES (32) ranges, so the frame is far smaller.
        @test_broken length(b) > max_ack_frame_size - 5
        @test f.range_count > 0
        @test f.range_count + 1 < num_ranges
    end

    @testset "TestAckRangeValidator" begin
        cases = [
            ("rejects ACKs without ranges", UnitRange{UInt64}[], false),
            ("accepts an ACK without NACK Ranges", [_qgwf_r(1, 7)], true),
            ("rejects ACK ranges with Smallest greater than Largest", [_qgwf_r(8, 10), _qgwf_r(4, 3)], false),
            ("rejects ACK ranges in the wrong order", [_qgwf_r(2, 2), _qgwf_r(6, 7)], false),
            ("rejects with overlapping ACK ranges", [_qgwf_r(5, 7), _qgwf_r(2, 5)], false),
            ("rejects ACK ranges that are part of a larger ACK range", [_qgwf_r(4, 7), _qgwf_r(5, 6)], false),
            ("rejects with directly adjacent ACK ranges", [_qgwf_r(5, 7), _qgwf_r(2, 4)], false),
            ("accepts an ACK with one lost packet", [_qgwf_r(5, 10), _qgwf_r(1, 3)], true),
            ("accepts an ACK with multiple lost packets", [_qgwf_r(15, 20), _qgwf_r(10, 12), _qgwf_r(1, 3)], true),
        ]
        for (name, ranges, valid) in cases
            @testset "$name" begin
                @test !_qgwf_throws(() -> QGWF._append_ack_frame!(UInt8[], ranges, UInt64(0))) == valid
            end
        end
    end

    @testset "TestAckFrameAcksPacketWithoutRanges" begin
        ok, b, f = _qgwf_ack_roundtrip([_qgwf_r(5, 10)])
        @test ok
        @test !_qgwf_acks(b, f, 1)
        @test !_qgwf_acks(b, f, 4)
        @test _qgwf_acks(b, f, 5)
        @test _qgwf_acks(b, f, 8)
        @test _qgwf_acks(b, f, 10)
        @test !_qgwf_acks(b, f, 11)
        @test !_qgwf_acks(b, f, 20)
    end

    @testset "TestAckFrameAcksPacketWithMultipleRanges" begin
        ok, b, f = _qgwf_ack_roundtrip([_qgwf_r(15, 20), _qgwf_r(5, 8)])
        @test ok
        for (pn, acked) in ((4, false), (5, true), (6, true), (7, true), (8, true), (9, false), (14, false),
                            (15, true), (18, true), (19, true), (20, true), (21, false))
            @test _qgwf_acks(b, f, pn) == acked
        end
    end

    # connection_close_frame_test.go
    @testset "TestParseConnectionCloseTransportError" begin
        reason = "No recent network activity."
        data = vcat(_qgwf_v(0x19), _qgwf_v(0x1337), _qgwf_v(length(reason)), _qgwf_b(reason))
        ok, buf, f = _qgwf_one(0x1c, data)
        @test ok
        @test !f.app
        @test f.error_code == 0x19
        @test f.frame_type == 0x1337
        @test String(buf[f.reason]) == reason
    end

    @testset "TestParseConnectionCloseWithApplicationError" begin
        reason = "The application messed things up."
        data = vcat(_qgwf_v(0xcafe), _qgwf_v(length(reason)), _qgwf_b(reason))
        ok, buf, f = _qgwf_one(0x1d, data)
        @test ok
        @test f.app
        @test f.error_code == 0xcafe
        @test String(buf[f.reason]) == reason
    end

    @testset "TestParseConnectionCloseLongReasonPhrase" begin
        data = vcat(_qgwf_v(0xcafe), _qgwf_v(0x42), _qgwf_v(0xffff))
        @test _qgwf_malformed(0x1c, data)
    end

    @testset "TestParseConnectionCloseErrorsOnEOFs" begin
        reason = "No recent network activity."
        data = vcat(_qgwf_v(0x19), _qgwf_v(0x1337), _qgwf_v(length(reason)), _qgwf_b(reason))
        @test _qgwf_one(0x1c, data)[1]
        @test _qgwf_all_prefixes_malformed(0x1c, data)
    end

    @testset "TestParseConnectionCloseNoReasonPhrase" begin
        data = vcat(_qgwf_v(0xcafe), _qgwf_v(0x42), _qgwf_v(0))
        ok, _, f = _qgwf_one(0x1c, data)
        @test ok
        @test isempty(f.reason)
    end

    @testset "TestWriteConnectionCloseNoReasonPhrase" begin
        b = _qgwf_enc(buf -> QGWF._append_connection_close_frame!(buf, UInt64(0xbeef), UInt64(0x12345), UInt8[]))
        @test b == vcat(UInt8[0x1c], _qgwf_v(0xbeef), _qgwf_v(0x12345), _qgwf_v(0))
    end

    @testset "TestWriteConnectionCloseWithReasonPhrase" begin
        b = _qgwf_enc(buf -> QGWF._append_connection_close_frame!(buf, UInt64(0xdead), UInt64(0), _qgwf_b("foobar")))
        @test b == vcat(UInt8[0x1c], _qgwf_v(0xdead), _qgwf_v(0), _qgwf_v(6), _qgwf_b("foobar"))
    end

    @testset "TestWriteConnectionCloseWithApplicationError" begin
        b = _qgwf_enc(buf -> QGWF._append_connection_close_frame!(buf, UInt64(0xdead), UInt64(0), _qgwf_b("foobar"); app = true))
        @test b == vcat(UInt8[0x1d], _qgwf_v(0xdead), _qgwf_v(6), _qgwf_b("foobar"))
    end

    # crypto_frame_test.go
    @testset "TestParseCryptoFrame" begin
        data = vcat(_qgwf_v(0xdecafbad), _qgwf_v(6), _qgwf_b("foobar"))
        ok, buf, f = _qgwf_one(0x06, data)
        @test ok
        @test f.offset == 0xdecafbad
        @test buf[f.data] == _qgwf_b("foobar")
    end

    @testset "TestParseCryptoFrameErrorsOnEOFs" begin
        data = vcat(_qgwf_v(0xdecafbad), _qgwf_v(6), _qgwf_b("foobar"))
        @test _qgwf_one(0x06, data)[1]
        @test _qgwf_all_prefixes_malformed(0x06, data)
    end

    @testset "TestWriteCryptoFrame" begin
        b = _qgwf_enc(buf -> QGWF._append_crypto_frame!(buf, UInt64(0x123456), _qgwf_b("foobar")))
        @test b == vcat(UInt8[0x06], _qgwf_v(0x123456), _qgwf_v(6), _qgwf_b("foobar"))
    end

    # data_blocked_frame_test.go
    @testset "TestParseDataBlocked" begin
        ok, _, f = _qgwf_one(0x14, _qgwf_v(0x12345678))
        @test ok
        @test f == QGWF._DataBlockedFrame(0x12345678)
    end

    @testset "TestParseDataBlockedErrorsOnEOFs" begin
        data = _qgwf_v(0x12345678)
        @test _qgwf_one(0x14, data)[1]
        @test _qgwf_all_prefixes_malformed(0x14, data)
    end

    @testset "TestWriteDataBlocked" begin
        b = _qgwf_enc(buf -> QGWF._append_data_blocked_frame!(buf, UInt64(0xdeadbeef)))
        @test b == vcat(UInt8[0x14], _qgwf_v(0xdeadbeef))
        @test length(b) == 1 + QGWF._varint_length(UInt64(0xdeadbeef))
    end

    # handshake_done_frame_test.go
    @testset "TestWriteHandshakeDoneSampleFrame" begin
        b = _qgwf_enc(QGWF._append_handshake_done_frame!)
        @test b == UInt8[0x1e]
    end

    # max_data_frame_test.go
    @testset "TestParseMaxDataFrame" begin
        ok, _, f = _qgwf_one(0x10, _qgwf_v(0xdecafbad123456))
        @test ok
        @test f == QGWF._MaxDataFrame(0xdecafbad123456)
    end

    @testset "TestParseMaxDataErrorsOnEOFs" begin
        data = _qgwf_v(0xdecafbad1234567)
        @test _qgwf_one(0x10, data)[1]
        @test _qgwf_all_prefixes_malformed(0x10, data)
    end

    @testset "TestWriteMaxDataFrame" begin
        b = _qgwf_enc(buf -> QGWF._append_max_data_frame!(buf, UInt64(0xdeadbeefcafe)))
        @test b == vcat(UInt8[0x10], _qgwf_v(0xdeadbeefcafe))
    end

    # max_stream_data_frame_test.go
    @testset "TestParseMaxStreamFrame" begin
        ok, _, f = _qgwf_one(0x11, vcat(_qgwf_v(0xdeadbeef), _qgwf_v(0x12345678)))
        @test ok
        @test f == QGWF._MaxStreamDataFrame(0xdeadbeef, 0x12345678)
    end

    @testset "TestParseMaxStreamDataErrorsOnEOFs" begin
        data = vcat(_qgwf_v(0xdeadbeef), _qgwf_v(0x12345678))
        @test _qgwf_one(0x11, data)[1]
        @test _qgwf_all_prefixes_malformed(0x11, data)
    end

    @testset "TestWriteMaxStreamDataFrame" begin
        b = _qgwf_enc(buf -> QGWF._append_max_stream_data_frame!(buf, UInt64(0xdecafbad), UInt64(0xdeadbeefcafe42)))
        @test b == vcat(UInt8[0x11], _qgwf_v(0xdecafbad), _qgwf_v(0xdeadbeefcafe42))
    end

    # max_streams_frame_test.go
    @testset "TestParseMaxStreamsFrameBidirectional" begin
        ok, _, f = _qgwf_one(0x12, _qgwf_v(0xdecaf))
        @test ok
        @test f == QGWF._MaxStreamsFrame(true, 0xdecaf)
    end

    @testset "TestParseMaxStreamsFrameUnidirectional" begin
        ok, _, f = _qgwf_one(0x13, _qgwf_v(0xdecaf))
        @test ok
        @test f == QGWF._MaxStreamsFrame(false, 0xdecaf)
    end

    @testset "TestParseMaxStreamsErrorsOnEOF" begin
        # The Go test passes typ 0x1d, which parseMaxStreamsFrame treats as
        # unidirectional; in a payload 0x1d is CONNECTION_CLOSE, so use 0x13.
        data = _qgwf_v(0xdeadbeefcafe13)
        @test _qgwf_one(0x13, data)[1]
        @test _qgwf_all_prefixes_malformed(0x13, data)
    end

    @testset "TestParseMaxStreamsMaxValue" begin
        for bidi in (false, true)
            @testset "$(bidi ? "bidirectional" : "unidirectional")" begin
                b = _qgwf_enc(buf -> QGWF._append_max_streams_frame!(buf, bidi, QGWF._MAX_STREAMS_LIMIT))
                frames, result = _qgwf_decode(b)
                @test result.error === nothing
                @test frames == [QGWF._MaxStreamsFrame(bidi, QGWF._MAX_STREAMS_LIMIT)]
            end
        end
    end

    @testset "TestParseMaxStreamsErrorsOnTooLargeStreamCount" begin
        # Our encoder refuses 2^60 + 1, so the frame is written by hand.
        for bidi in (false, true)
            @testset "$(bidi ? "bidirectional" : "unidirectional")" begin
                type = bidi ? 0x12 : 0x13
                @test _qgwf_throws(() -> QGWF._append_max_streams_frame!(UInt8[], bidi, QGWF._MAX_STREAMS_LIMIT + 1))
                @test _qgwf_malformed(type, _qgwf_v(QGWF._MAX_STREAMS_LIMIT + 1))
            end
        end
    end

    @testset "TestWriteMaxStreamsBidirectional" begin
        b = _qgwf_enc(buf -> QGWF._append_max_streams_frame!(buf, true, UInt64(0xdeadbeef)))
        @test b == vcat(UInt8[0x12], _qgwf_v(0xdeadbeef))
    end

    @testset "TestWriteMaxStreamsUnidirectional" begin
        b = _qgwf_enc(buf -> QGWF._append_max_streams_frame!(buf, false, UInt64(0xdecafbad)))
        @test b == vcat(UInt8[0x13], _qgwf_v(0xdecafbad))
    end

    # new_connection_id_frame_test.go
    @testset "TestParseNewConnectionIDFrame" begin
        cid = UInt8[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
        data = vcat(_qgwf_v(0xdeadbeef), _qgwf_v(0xcafe), UInt8[10], cid, _qgwf_b("deadbeefdecafbad"))
        ok, buf, f = _qgwf_one(0x18, data)
        @test ok
        @test f.seq == 0xdeadbeef
        @test f.retire_prior_to == 0xcafe
        @test buf[f.cid] == cid
        @test String(buf[f.reset_token]) == "deadbeefdecafbad"
    end

    @testset "TestParseNewConnectionIDRetirePriorToLargerThanSequenceNumber" begin
        data = vcat(_qgwf_v(1000), _qgwf_v(1001), UInt8[3], UInt8[1, 2, 3], _qgwf_b("deadbeefdecafbad"))
        @test _qgwf_malformed(0x18, data)
    end

    @testset "TestParseNewConnectionIDZeroLengthConnID" begin
        data = vcat(_qgwf_v(42), _qgwf_v(12), UInt8[0])
        @test _qgwf_malformed(0x18, data)
    end

    @testset "TestParseNewConnectionIDInvalidConnIDLength" begin
        data = vcat(_qgwf_v(0xdeadbeef), _qgwf_v(0xcafe), UInt8[21], UInt8.(1:21), _qgwf_b("deadbeefdecafbad"))
        @test _qgwf_malformed(0x18, data)
    end

    @testset "TestParseNewConnectionIDErrorsOnEOFs" begin
        data = vcat(_qgwf_v(0xdeadbeef), _qgwf_v(0xcafe1234), UInt8[10], UInt8.(1:10), _qgwf_b("deadbeefdecafbad"))
        @test _qgwf_one(0x18, data)[1]
        @test _qgwf_all_prefixes_malformed(0x18, data)
    end

    @testset "TestWriteNewConnectionIDFrame" begin
        token = UInt8.(0:15)
        cid = UInt8[1, 2, 3, 4, 5, 6]
        b = _qgwf_enc(buf -> QGWF._append_new_connection_id_frame!(buf, UInt64(0x1337), UInt64(0x42), cid, token))
        @test b == vcat(UInt8[0x18], _qgwf_v(0x1337), _qgwf_v(0x42), UInt8[6], cid, token)
    end

    # new_token_frame_test.go
    @testset "TestParseNewTokenFrame" begin
        token = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
        ok, buf, f = _qgwf_one(0x07, vcat(_qgwf_v(length(token)), _qgwf_b(token)))
        @test ok
        @test String(buf[f.token]) == token
    end

    @testset "TestParseNewTokenFrameRejectsEmptyTokens" begin
        @test _qgwf_malformed(0x07, _qgwf_v(0))  # "token must not be empty"
    end

    @testset "TestParseNewTokenFrameErrorsOnEOFs" begin
        token = "Lorem ipsum dolor sit amet, consectetur adipiscing elit"
        data = vcat(_qgwf_v(length(token)), _qgwf_b(token))
        @test _qgwf_one(0x07, data)[1]
        @test _qgwf_all_prefixes_malformed(0x07, data)
    end

    @testset "TestWriteNewTokenFrame" begin
        token = "Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat."
        b = _qgwf_enc(buf -> QGWF._append_new_token_frame!(buf, _qgwf_b(token)))
        @test b == vcat(UInt8[0x07], _qgwf_v(length(token)), _qgwf_b(token))
    end

    # path_challenge_frame_test.go, path_response_frame_test.go
    for (name, type, T, append) in (("PathChallenge", 0x1a, QGWF._PathChallengeFrame, QGWF._append_path_challenge_frame!),
                                    ("PathResponse", 0x1b, QGWF._PathResponseFrame, QGWF._append_path_response_frame!))
        @testset "TestParse$(name)" begin
            ok, _, f = _qgwf_one(type, UInt8[1, 2, 3, 4, 5, 6, 7, 8])
            @test ok
            @test f == T(0x0102030405060708)
        end

        @testset "TestParse$(name)ErrorsOnEOFs" begin
            data = UInt8[1, 2, 3, 4, 5, 6, 7, 8]
            @test _qgwf_one(type, data)[1]
            @test _qgwf_all_prefixes_malformed(type, data)
        end

        @testset "TestWrite$(name)" begin
            b = _qgwf_enc(buf -> append(buf, 0xdeadbeefcafe1337))
            @test b == UInt8[type, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0x13, 0x37]
        end
    end

    # ping_frame_test.go
    @testset "TestWritePingFrame" begin
        @test _qgwf_enc(QGWF._append_ping_frame!) == UInt8[0x01]
    end

    # reset_stream_frame_test.go
    @testset "TestParseResetStream" begin
        ok, _, f = _qgwf_one(0x04, vcat(_qgwf_v(0xdeadbeef), _qgwf_v(0x1337), _qgwf_v(0x987654321)))
        @test ok
        @test f.stream_id == 0xdeadbeef
        @test f.final_size == 0x987654321
        @test f.error_code == 0x1337
    end

    @testset "TestParseResetStreamErrorsOnEOFs" begin
        data = vcat(_qgwf_v(0xdeadbeef), _qgwf_v(0x1337), _qgwf_v(0x987654321))
        @test _qgwf_one(0x04, data)[1]
        @test _qgwf_all_prefixes_malformed(0x04, data)
    end

    @testset "TestWriteResetStream" begin
        b = _qgwf_enc(buf -> QGWF._append_reset_stream_frame!(buf, UInt64(0x1337), UInt64(0xcafe), UInt64(0x11223344decafbad)))
        @test b == vcat(UInt8[0x04], _qgwf_v(0x1337), _qgwf_v(0xcafe), _qgwf_v(0x11223344decafbad))
    end

    # retire_connection_id_frame_test.go
    @testset "TestParseRetireConnectionID" begin
        ok, _, f = _qgwf_one(0x19, _qgwf_v(0xdeadbeef))
        @test ok
        @test f == QGWF._RetireConnectionIdFrame(0xdeadbeef)
    end

    @testset "TestParseRetireConnectionIDErrorsOnEOFs" begin
        data = _qgwf_v(0xdeadbeef)
        @test _qgwf_one(0x19, data)[1]
        @test _qgwf_all_prefixes_malformed(0x19, data)
    end

    @testset "TestWriteRetireConnectionID" begin
        b = _qgwf_enc(buf -> QGWF._append_retire_connection_id_frame!(buf, UInt64(0x1337)))
        @test b == vcat(UInt8[0x19], _qgwf_v(0x1337))
    end

    # stop_sending_frame_test.go
    @testset "TestParseStopSending" begin
        ok, _, f = _qgwf_one(0x05, vcat(_qgwf_v(0xdecafbad), _qgwf_v(0x1337)))
        @test ok
        @test f == QGWF._StopSendingFrame(0xdecafbad, 0x1337)
    end

    @testset "TestParseStopSendingErrorsOnEOFs" begin
        data = vcat(_qgwf_v(0xdecafbad), _qgwf_v(0x123456))
        @test _qgwf_one(0x05, data)[1]
        @test _qgwf_all_prefixes_malformed(0x05, data)
    end

    @testset "TestWriteStopSendingFrame" begin
        b = _qgwf_enc(buf -> QGWF._append_stop_sending_frame!(buf, UInt64(0xdeadbeefcafe), UInt64(0xdecafbad)))
        @test b == vcat(UInt8[0x05], _qgwf_v(0xdeadbeefcafe), _qgwf_v(0xdecafbad))
    end

    # stream_data_blocked_frame_test.go
    @testset "TestParseStreamDataBlocked" begin
        ok, _, f = _qgwf_one(0x15, vcat(_qgwf_v(0xdeadbeef), _qgwf_v(0xdecafbad)))
        @test ok
        @test f == QGWF._StreamDataBlockedFrame(0xdeadbeef, 0xdecafbad)
    end

    @testset "TestParseStreamDataBlockedErrorsOnEOFs" begin
        data = vcat(_qgwf_v(0xdeadbeef), _qgwf_v(0xc0010ff))
        @test _qgwf_one(0x15, data)[1]
        @test _qgwf_all_prefixes_malformed(0x15, data)
    end

    @testset "TestWriteStreamDataBlocked" begin
        b = _qgwf_enc(buf -> QGWF._append_stream_data_blocked_frame!(buf, UInt64(0xdecafbad), UInt64(0x1337)))
        @test b == vcat(UInt8[0x15], _qgwf_v(0xdecafbad), _qgwf_v(0x1337))
    end

    # streams_blocked_frame_test.go
    @testset "TestParseStreamsBlockedFrameBidirectional" begin
        ok, _, f = _qgwf_one(0x16, _qgwf_v(0x1337))
        @test ok
        @test f == QGWF._StreamsBlockedFrame(true, 0x1337)
    end

    @testset "TestParseStreamsBlockedFrameUnidirectional" begin
        ok, _, f = _qgwf_one(0x17, _qgwf_v(0x7331))
        @test ok
        @test f == QGWF._StreamsBlockedFrame(false, 0x7331)
    end

    @testset "TestParseStreamsBlockedFrameErrorsOnEOFs" begin
        data = _qgwf_v(0x12345678)
        @test _qgwf_one(0x16, data)[1]
        @test _qgwf_all_prefixes_malformed(0x16, data)
    end

    @testset "TestParseStreamsBlockedFrameMaxStreamCount" begin
        for bidi in (false, true)
            @testset "$(bidi ? "bidirectional" : "unidirectional")" begin
                b = _qgwf_enc(buf -> QGWF._append_streams_blocked_frame!(buf, bidi, QGWF._MAX_STREAMS_LIMIT))
                frames, result = _qgwf_decode(b)
                @test result.error === nothing
                @test frames == [QGWF._StreamsBlockedFrame(bidi, QGWF._MAX_STREAMS_LIMIT)]
            end
        end
    end

    @testset "TestParseStreamsBlockedFrameErrorOnTooLargeStreamCount" begin
        for bidi in (false, true)
            @testset "$(bidi ? "bidirectional" : "unidirectional")" begin
                type = bidi ? 0x16 : 0x17
                @test _qgwf_throws(() -> QGWF._append_streams_blocked_frame!(UInt8[], bidi, QGWF._MAX_STREAMS_LIMIT + 1))
                @test _qgwf_malformed(type, _qgwf_v(QGWF._MAX_STREAMS_LIMIT + 1))
            end
        end
    end

    @testset "TestWriteStreamsBlockedFrameBidirectional" begin
        b = _qgwf_enc(buf -> QGWF._append_streams_blocked_frame!(buf, true, UInt64(0xdeadbeefcafe)))
        @test b == vcat(UInt8[0x16], _qgwf_v(0xdeadbeefcafe))
    end

    @testset "TestWriteStreamsBlockedFrameUnidirectional" begin
        b = _qgwf_enc(buf -> QGWF._append_streams_blocked_frame!(buf, false, UInt64(0xdeadbeefcafe)))
        @test b == vcat(UInt8[0x17], _qgwf_v(0xdeadbeefcafe))
    end

    # stream_frame_test.go
    @testset "TestParseStreamFrameWithOffBit" begin
        data = vcat(_qgwf_v(0x12345), _qgwf_v(0xdecafbad), _qgwf_b("foobar"))
        ok, buf, f = _qgwf_one(0x08 ⊻ 0x04, data)
        @test ok
        @test f.stream_id == 0x12345
        @test buf[f.data] == _qgwf_b("foobar")
        @test !f.fin
        @test f.offset == 0xdecafbad
    end

    @testset "TestParseStreamFrameRespectsLEN" begin
        data = vcat(_qgwf_v(0x12345), _qgwf_v(4), _qgwf_b("foobar"))
        buf, frames, _ = _qgwf_parse(0x08 ⊻ 0x02, data)
        f = frames[1]
        @test f isa QGWF._StreamFrame
        @test f.stream_id == 0x12345
        @test buf[f.data] == _qgwf_b("foob")
        @test !f.fin
        @test f.offset == 0
        # Consumed len(data) - 2 bytes: the frame alone ends 2 bytes early.
        @test _qgwf_one(0x08 ⊻ 0x02, data[1:(end - 2)])[1]
    end

    @testset "TestParseStreamFrameWithFINBit" begin
        data = vcat(_qgwf_v(9), _qgwf_b("foobar"))
        ok, buf, f = _qgwf_one(0x08 ⊻ 0x01, data)
        @test ok
        @test f.stream_id == 9
        @test buf[f.data] == _qgwf_b("foobar")
        @test f.fin
        @test f.offset == 0
    end

    @testset "TestParseStreamFrameAllowsEmpty" begin
        data = vcat(_qgwf_v(0x1337), _qgwf_v(0x12345))
        ok, _, f = _qgwf_one(0x08 ⊻ 0x04, data)
        @test ok
        @test f.stream_id == 0x1337
        @test f.offset == 0x12345
        @test isempty(f.data)
        @test !f.fin
    end

    @testset "TestParseStreamFrameRejectsOverflow" begin
        data = vcat(_qgwf_v(0x12345), _qgwf_v(QGWF._MAX_VARINT - 5), _qgwf_b("foobar"))
        @test _qgwf_malformed(0x08 ⊻ 0x04, data)  # "stream data overflows maximum offset"
    end

    @testset "TestParseStreamFrameRejectsLongFrames" begin
        max_packet_buffer_size = 1452  # protocol.MaxPacketBufferSize
        data = vcat(_qgwf_v(0x12345), _qgwf_v(max_packet_buffer_size + 1), zeros(UInt8, max_packet_buffer_size + 1))
        # BUG?: quic-go rejects a STREAM frame longer than its 1452-byte pooled
        # buffer even when the data is present; we accept it.
        @test_broken _qgwf_malformed(0x08 ⊻ 0x02, data)
    end

    @testset "TestParseStreamFrameRejectsFramesExceedingRemainingSize" begin
        data = vcat(_qgwf_v(0x12345), _qgwf_v(7), _qgwf_b("foobar"))
        @test _qgwf_malformed(0x08 ⊻ 0x02, data)
    end

    @testset "TestParseStreamFrameErrorsOnEOFs" begin
        type = 0x08 ⊻ 0x04 ⊻ 0x02
        data = vcat(_qgwf_v(0x12345), _qgwf_v(0xdecafbad), _qgwf_v(6), _qgwf_b("foobar"))
        @test _qgwf_one(type, data)[1]
        @test _qgwf_all_prefixes_malformed(type, data)
    end

    min_stream_frame_buffer_size = 128  # protocol.MinStreamFrameBufferSize
    for (name, n) in (("TestParseStreamUsesBufferForLongFrames", min_stream_frame_buffer_size),
                      ("TestParseStreamDoesNotUseBufferForShortFrames", min_stream_frame_buffer_size - 1))
        @testset "$name" begin
            data = vcat(_qgwf_v(0x12345), fill(UInt8('f'), n))
            ok, buf, f = _qgwf_one(0x08, data)
            @test ok
            @test f.stream_id == 0x12345
            @test buf[f.data] == fill(UInt8('f'), n)
            @test length(f.data) == n
            @test !f.fin
        end
    end

    @testset "TestWriteStreamFrameWithoutOffset" begin
        b = _qgwf_enc(buf -> QGWF._append_stream_frame!(buf, UInt64(0x1337), UInt64(0), _qgwf_b("foobar"); explicit_length = false))
        @test b == vcat(UInt8[0x08], _qgwf_v(0x1337), _qgwf_b("foobar"))
    end

    @testset "TestWriteStreamFrameWithOffset" begin
        b = _qgwf_enc(buf -> QGWF._append_stream_frame!(buf, UInt64(0x1337), UInt64(0x123456), _qgwf_b("foobar"); explicit_length = false))
        @test b == vcat(UInt8[0x08 ⊻ 0x04], _qgwf_v(0x1337), _qgwf_v(0x123456), _qgwf_b("foobar"))
    end

    @testset "TestWriteStreamFrameWithFIN" begin
        b = _qgwf_enc(buf -> QGWF._append_stream_frame!(buf, UInt64(0x1337), UInt64(0x123456), UInt8[]; fin = true, explicit_length = false))
        @test b == vcat(UInt8[0x08 ⊻ 0x04 ⊻ 0x01], _qgwf_v(0x1337), _qgwf_v(0x123456))
    end

    @testset "TestWriteStreamFrameWithDataLength" begin
        b = _qgwf_enc(buf -> QGWF._append_stream_frame!(buf, UInt64(0x1337), UInt64(0), _qgwf_b("foobar")))
        @test b == vcat(UInt8[0x08 ⊻ 0x02], _qgwf_v(0x1337), _qgwf_v(6), _qgwf_b("foobar"))
    end

    @testset "TestWriteStreamFrameWithDataLengthAndOffset" begin
        b = _qgwf_enc(buf -> QGWF._append_stream_frame!(buf, UInt64(0x1337), UInt64(0x123456), _qgwf_b("foobar")))
        @test b == vcat(UInt8[0x08 ⊻ 0x04 ⊻ 0x02], _qgwf_v(0x1337), _qgwf_v(0x123456), _qgwf_v(6), _qgwf_b("foobar"))
    end

    @testset "TestWriteStreamFrameEmptyFrameWithoutFIN" begin
        # BUG?: quic-go refuses to write an empty STREAM frame without FIN
        # ("attempting to write empty frame without FIN"); our encoder writes it.
        @test_broken _qgwf_throws(() -> QGWF._append_stream_frame!(UInt8[], UInt64(0x42), UInt64(0x1337), UInt8[]; explicit_length = false))
    end

    # frame_parser_test.go
    @testset "TestFrameParsingReturnsNilWhenNothingToRead" begin
        frames, result = _qgwf_decode(UInt8[])
        @test isempty(frames)
        # quic-go's ParseNext returns no frame and no error; its packet
        # unpacker then rejects the empty payload as a PROTOCOL_VIOLATION,
        # which `_decode_frames` reports itself (RFC 9000 Section 12.4).
        @test result.error !== nothing && result.error.code == QGWF._PROTOCOL_VIOLATION
    end

    @testset "TestFrameParsingSkipsPaddingFrames" begin
        frames, result = _qgwf_decode(vcat(UInt8[0, 0], _qgwf_enc(QGWF._append_ping_frame!)))
        @test result.error === nothing
        # quic-go skips the padding inside ParseNext; we report it as one frame.
        @test frames == Any[QGWF._PaddingFrame(2), QGWF._PingFrame()]
    end

    @testset "TestFrameParsingHandlesPaddingAtEnd" begin
        frames, result = _qgwf_decode(UInt8[0, 0, 0])
        @test result.error === nothing
        @test frames == Any[QGWF._PaddingFrame(3)]
    end

    @testset "TestFrameParsingParsesSingleFrame" begin
        b = UInt8[]
        for _ in 1:10
            QGWF._append_ping_frame!(b)
        end
        frames, result = _qgwf_decode(b)
        @test result.error === nothing
        @test frames[1] isa QGWF._PingFrame
        @test length(frames) == 10  # each PING is one byte
    end

    # Encode with `append`, decode the whole buffer, and expect one frame.
    function _qgwf_unpack(append)
        b = _qgwf_enc(append)
        frames, result = _qgwf_decode(b)
        ok = result.error === nothing && length(frames) == 1
        return ok, b, ok ? frames[1] : nothing
    end

    @testset "TestFrameParsingUnpacksAckFrames" begin
        ok, _, f = _qgwf_unpack(buf -> QGWF._append_ack_frame!(buf, [_qgwf_r(1, 0x13)], UInt64(0)))
        @test ok
        @test f isa QGWF._AckFrame
        @test f.largest == 0x13
    end

    @testset "TestFrameParsingUsesCustomAckDelayExponentFor1RTTPackets" begin
        ok, _, f = _qgwf_unpack(buf -> QGWF._append_ack_frame!(buf, [_qgwf_r(1, 1)], _qgwf_delay_field(1000)))
        @test ok
        @test _qgwf_ack_delay_ns(f.delay, _QGWF_ACK_DELAY_EXPONENT + 2) == 4 * 1_000_000_000
    end

    @testset "TestFrameParsingUsesDefaultAckDelayExponentForNon1RTTPackets" begin
        b = _qgwf_enc(buf -> QGWF._append_ack_frame!(buf, [_qgwf_r(1, 1)], _qgwf_delay_field(1000)))
        frames, result = _qgwf_decode(b, QGWFT.Handshake)
        @test result.error === nothing && length(frames) == 1
        # The frame keeps the raw field; in the default exponent that is 1 s.
        # (Both stacks then leave ACK Delay out of RTT samples outside 1-RTT.)
        @test Int64(frames[1].delay << Int(QGWF._DEFAULT_TRANSPORT_PARAMETERS.ack_delay_exponent)) * 1_000 == 1_000_000_000
    end

    @testset "TestFrameParsingUnpacksResetStreamFrames" begin
        ok, _, f = _qgwf_unpack(buf -> QGWF._append_reset_stream_frame!(buf, UInt64(0xdeadbeef), UInt64(0x1337), UInt64(0xdecafbad1234)))
        @test ok
        @test f == QGWF._ResetStreamFrame(0xdeadbeef, 0x1337, 0xdecafbad1234)
    end

    @testset "TestFrameParsingUnpacksStopSendingFrames" begin
        ok, _, f = _qgwf_unpack(buf -> QGWF._append_stop_sending_frame!(buf, UInt64(0x42), UInt64(0)))
        @test ok
        @test f == QGWF._StopSendingFrame(0x42, 0)
    end

    @testset "TestFrameParsingUnpacksCryptoFrames" begin
        ok, b, f = _qgwf_unpack(buf -> QGWF._append_crypto_frame!(buf, UInt64(0x1337), _qgwf_b("lorem ipsum")))
        @test ok
        @test f.offset == 0x1337
        @test b[f.data] == _qgwf_b("lorem ipsum")
    end

    @testset "TestFrameParsingUnpacksNewTokenFrames" begin
        ok, b, f = _qgwf_unpack(buf -> QGWF._append_new_token_frame!(buf, _qgwf_b("foobar")))
        @test ok
        @test f isa QGWF._NewTokenFrame
        @test b[f.token] == _qgwf_b("foobar")
    end

    @testset "TestFrameParsingUnpacksStreamFrames" begin
        # quic-go's default StreamFrame has no Length field.
        ok, b, f = _qgwf_unpack(buf -> QGWF._append_stream_frame!(buf, UInt64(0x42), UInt64(0x1337), _qgwf_b("foobar"); fin = true, explicit_length = false))
        @test ok
        @test f.stream_id == 0x42
        @test f.offset == 0x1337
        @test f.fin
        @test b[f.data] == _qgwf_b("foobar")
    end

    @testset "TestFrameParsingUnpacksMaxDataFrames" begin
        ok, _, f = _qgwf_unpack(buf -> QGWF._append_max_data_frame!(buf, UInt64(0xcafe)))
        @test ok
        @test f == QGWF._MaxDataFrame(0xcafe)
    end

    @testset "TestFrameParsingUnpacksMaxStreamDataFrames" begin
        ok, _, f = _qgwf_unpack(buf -> QGWF._append_max_stream_data_frame!(buf, UInt64(0xdeadbeef), UInt64(0xdecafbad)))
        @test ok
        @test f == QGWF._MaxStreamDataFrame(0xdeadbeef, 0xdecafbad)
    end

    @testset "TestFrameParsingUnpacksMaxStreamsFrames" begin
        ok, _, f = _qgwf_unpack(buf -> QGWF._append_max_streams_frame!(buf, true, UInt64(0x1337)))
        @test ok
        @test f == QGWF._MaxStreamsFrame(true, 0x1337)
    end

    @testset "TestFrameParsingUnpacksDataBlockedFrames" begin
        ok, _, f = _qgwf_unpack(buf -> QGWF._append_data_blocked_frame!(buf, UInt64(0x1234)))
        @test ok
        @test f == QGWF._DataBlockedFrame(0x1234)
    end

    @testset "TestFrameParsingUnpacksStreamDataBlockedFrames" begin
        ok, _, f = _qgwf_unpack(buf -> QGWF._append_stream_data_blocked_frame!(buf, UInt64(0xdeadbeef), UInt64(0xdead)))
        @test ok
        @test f == QGWF._StreamDataBlockedFrame(0xdeadbeef, 0xdead)
    end

    @testset "TestFrameParsingUnpacksStreamsBlockedFrames" begin
        ok, _, f = _qgwf_unpack(buf -> QGWF._append_streams_blocked_frame!(buf, true, UInt64(0x1234567)))
        @test ok
        @test f == QGWF._StreamsBlockedFrame(true, 0x1234567)
    end

    @testset "TestFrameParsingUnpacksNewConnectionIDFrames" begin
        cid = UInt8[0xde, 0xad, 0xbe, 0xef]
        token = UInt8.(0:15)
        ok, b, f = _qgwf_unpack(buf -> QGWF._append_new_connection_id_frame!(buf, UInt64(0x1337), UInt64(0), cid, token))
        @test ok
        @test f.seq == 0x1337
        @test f.retire_prior_to == 0
        @test b[f.cid] == cid
        @test b[f.reset_token] == token
    end

    @testset "TestFrameParsingUnpacksRetireConnectionIDFrames" begin
        ok, _, f = _qgwf_unpack(buf -> QGWF._append_retire_connection_id_frame!(buf, UInt64(0x1337)))
        @test ok
        @test f == QGWF._RetireConnectionIdFrame(0x1337)
    end

    @testset "TestFrameParsingUnpacksPathChallengeFrames" begin
        ok, _, f = _qgwf_unpack(buf -> QGWF._append_path_challenge_frame!(buf, 0x0102030405060708))
        @test ok
        @test f == QGWF._PathChallengeFrame(0x0102030405060708)
    end

    @testset "TestFrameParsingUnpacksPathResponseFrames" begin
        ok, _, f = _qgwf_unpack(buf -> QGWF._append_path_response_frame!(buf, 0x0102030405060708))
        @test ok
        @test f == QGWF._PathResponseFrame(0x0102030405060708)
    end

    @testset "TestFrameParsingUnpacksConnectionCloseFrames" begin
        ok, b, f = _qgwf_unpack(buf -> QGWF._append_connection_close_frame!(buf, UInt64(0), UInt64(0), _qgwf_b("foobar"); app = true))
        @test ok
        @test f.app
        @test f.error_code == 0
        @test String(b[f.reason]) == "foobar"
    end

    @testset "TestFrameParsingUnpacksHandshakeDoneFrames" begin
        ok, _, f = _qgwf_unpack(QGWF._append_handshake_done_frame!)
        @test ok
        @test f == QGWF._HandshakeDoneFrame()
    end

    @testset "TestFrameParsingErrorsWhenDatagramFramesAreNotSupported" begin
        # DATAGRAM without Length (type 0x30), as quic-go writes it.
        frames, result = _qgwf_decode(vcat(UInt8[0x30], _qgwf_b("foobar")))
        @test isempty(frames)
        err = result.error
        @test err !== nothing
        @test err.code == QGWF._FRAME_ENCODING_ERROR
        @test err.frame_type == 0x30
        @test err.reason == "unknown frame type"
    end

    @testset "TestFrameParsingErrorsOnInvalidType" begin
        frames, result = _qgwf_decode(_qgwf_v(0x42))
        err = result.error
        @test err !== nothing
        @test err.code == QGWF._FRAME_ENCODING_ERROR
        @test err.frame_type == 0x42
        @test err.reason == "unknown frame type"
    end

    @testset "TestFrameParsingErrorsOnInvalidFrames" begin
        b = _qgwf_enc(buf -> QGWF._append_max_stream_data_frame!(buf, UInt64(0x1337), UInt64(0xdeadbeef)))
        frames, result = _qgwf_decode(b[1:(end - 2)])
        @test result.error !== nothing
        @test result.error.code == QGWF._FRAME_ENCODING_ERROR
    end
end
