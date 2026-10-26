using Test
using Reseau

# QUIC frames (RFC 9000 Section 19): encoding, decoding, and the per-packet-type
# rules of Section 12.4.

const QFR = Reseau.QUIC
const QFT = QFR._PacketType

isdefined(@__MODULE__, :_RESEAU_QUIC_TEST_VECTORS_LOADED) || include("quic_test_vectors.jl")

# Decodes `buf[first:last]` and returns the frames and the decode result.
function _qfr_decode(buf::Vector{UInt8}, packet_type = QFT.OneRTT; first::Int = 1, last::Int = length(buf))
    frames = Any[]
    result = QFR._decode_frames(buf, first, last, packet_type) do frame
        push!(frames, frame)
        return nothing
    end
    return frames, result
end

function _qfr_error(buf::Vector{UInt8}, packet_type = QFT.OneRTT)
    _, result = _qfr_decode(buf, packet_type)
    return result.error
end

_qfr_encoding_error(buf, packet_type = QFT.OneRTT) =
    (err = _qfr_error(buf, packet_type); err !== nothing && err.code == QFR._FRAME_ENCODING_ERROR)
_qfr_protocol_violation(buf, packet_type) =
    (err = _qfr_error(buf, packet_type); err !== nothing && err.code == QFR._PROTOCOL_VIOLATION)

_qfr_ranges(buf, ack) = collect(QFR._ack_ranges(buf, ack))

@testset "QUIC frames" begin
    @testset "the RFC 9001 sample payloads" begin
        client_payload = vcat(_RFC9001_CLIENT_CRYPTO_FRAME, zeros(UInt8, 1162 - length(_RFC9001_CLIENT_CRYPTO_FRAME)))
        frames, result = _qfr_decode(client_payload, QFT.Initial)
        @test result.error === nothing
        @test result.ack_eliciting
        @test length(frames) == 2
        crypto = frames[1]
        @test crypto isa QFR._CryptoFrame
        @test crypto.offset == 0
        @test length(crypto.data) == 241
        @test client_payload[crypto.data] == _RFC9001_CLIENT_CRYPTO_FRAME[5:end]  # the ClientHello
        @test frames[2] == QFR._PaddingFrame(917)

        frames, result = _qfr_decode(copy(_RFC9001_SERVER_PAYLOAD), QFT.Initial)
        @test result.error === nothing
        @test length(frames) == 2
        ack = frames[1]
        @test ack isa QFR._AckFrame
        @test ack.largest == 0
        @test ack.delay == 0
        @test !ack.ecn
        @test _qfr_ranges(_RFC9001_SERVER_PAYLOAD, ack) == [UInt64(0):UInt64(0)]
        @test frames[2] isa QFR._CryptoFrame
        @test length(frames[2].data) == 90
    end

    @testset "every frame type round trips" begin
        buf = UInt8[]
        token = rand(UInt8, 12)
        cid = rand(UInt8, 8)
        reset_token = rand(UInt8, 16)
        crypto_data = rand(UInt8, 33)
        stream_data = rand(UInt8, 21)
        reason = Vector{UInt8}(codeunits("bye"))
        QFR._append_padding!(buf, 3)
        QFR._append_ping_frame!(buf)
        QFR._append_ack_frame!(buf, [UInt64(100):UInt64(105), UInt64(90):UInt64(95), UInt64(50):UInt64(50)], UInt64(25))
        QFR._append_ack_frame!(buf, [UInt64(7):UInt64(9)], UInt64(0); ecn = (UInt64(1), UInt64(2), UInt64(3)))
        QFR._append_reset_stream_frame!(buf, UInt64(4), UInt64(0x10c), UInt64(1000))
        QFR._append_stop_sending_frame!(buf, UInt64(8), UInt64(0x101))
        QFR._append_crypto_frame!(buf, UInt64(1234), crypto_data)
        QFR._append_new_token_frame!(buf, token)
        QFR._append_stream_frame!(buf, UInt64(0), UInt64(70000), stream_data; fin = true)
        QFR._append_max_data_frame!(buf, UInt64(1) << 40)
        QFR._append_max_stream_data_frame!(buf, UInt64(4), UInt64(65536))
        QFR._append_max_streams_frame!(buf, true, UInt64(100))
        QFR._append_max_streams_frame!(buf, false, UInt64(3))
        QFR._append_data_blocked_frame!(buf, UInt64(5000))
        QFR._append_stream_data_blocked_frame!(buf, UInt64(12), UInt64(6000))
        QFR._append_streams_blocked_frame!(buf, true, UInt64(9))
        QFR._append_streams_blocked_frame!(buf, false, UInt64(10))
        QFR._append_new_connection_id_frame!(buf, UInt64(3), UInt64(1), cid, reset_token)
        QFR._append_retire_connection_id_frame!(buf, UInt64(2))
        QFR._append_path_challenge_frame!(buf, 0x0102030405060708)
        QFR._append_path_response_frame!(buf, 0x1112131415161718)
        QFR._append_connection_close_frame!(buf, UInt64(QFR._PROTOCOL_VIOLATION), UInt64(0x08), reason)
        QFR._append_connection_close_frame!(buf, UInt64(0x42), UInt64(0), UInt8[]; app = true)
        QFR._append_handshake_done_frame!(buf)

        frames, result = _qfr_decode(buf)
        @test result.error === nothing
        @test result.ack_eliciting
        @test length(frames) == 24
        @test frames[1] == QFR._PaddingFrame(3)
        @test frames[2] == QFR._PingFrame()
        @test frames[3].largest == 105
        @test frames[3].delay == 25
        @test _qfr_ranges(buf, frames[3]) == [UInt64(100):UInt64(105), UInt64(90):UInt64(95), UInt64(50):UInt64(50)]
        @test frames[4].ecn
        @test (frames[4].ect0, frames[4].ect1, frames[4].ce) == (1, 2, 3)
        @test _qfr_ranges(buf, frames[4]) == [UInt64(7):UInt64(9)]
        @test frames[5] == QFR._ResetStreamFrame(4, 0x10c, 1000)
        @test frames[6] == QFR._StopSendingFrame(8, 0x101)
        @test frames[7].offset == 1234
        @test buf[frames[7].data] == crypto_data
        @test buf[frames[8].token] == token
        @test frames[9].stream_id == 0
        @test frames[9].offset == 70000
        @test frames[9].fin
        @test buf[frames[9].data] == stream_data
        @test frames[10] == QFR._MaxDataFrame(UInt64(1) << 40)
        @test frames[11] == QFR._MaxStreamDataFrame(4, 65536)
        @test frames[12] == QFR._MaxStreamsFrame(true, 100)
        @test frames[13] == QFR._MaxStreamsFrame(false, 3)
        @test frames[14] == QFR._DataBlockedFrame(5000)
        @test frames[15] == QFR._StreamDataBlockedFrame(12, 6000)
        @test frames[16] == QFR._StreamsBlockedFrame(true, 9)
        @test frames[17] == QFR._StreamsBlockedFrame(false, 10)
        @test frames[18].seq == 3
        @test frames[18].retire_prior_to == 1
        @test buf[frames[18].cid] == cid
        @test buf[frames[18].reset_token] == reset_token
        @test frames[19] == QFR._RetireConnectionIdFrame(2)
        @test frames[20] == QFR._PathChallengeFrame(0x0102030405060708)
        @test frames[21] == QFR._PathResponseFrame(0x1112131415161718)
        @test !frames[22].app
        @test frames[22].error_code == QFR._PROTOCOL_VIOLATION
        @test frames[22].frame_type == 0x08
        @test buf[frames[22].reason] == reason
        @test frames[23].app
        @test frames[23].error_code == 0x42
        @test isempty(frames[23].reason)
        @test frames[24] == QFR._HandshakeDoneFrame()
    end

    @testset "STREAM frame variants" begin
        data = rand(UInt8, 10)
        for offset in (UInt64(0), UInt64(5)), fin in (false, true), explicit_length in (false, true)
            buf = UInt8[]
            QFR._append_stream_frame!(buf, UInt64(6), offset, data; fin, explicit_length)
            @test buf[1] == 0x08 | (offset > 0 ? 0x04 : 0x00) | (explicit_length ? 0x02 : 0x00) | (fin ? 0x01 : 0x00)
            frames, result = _qfr_decode(buf)
            @test result.error === nothing
            @test frames[1].stream_id == 6
            @test frames[1].offset == offset
            @test frames[1].fin == fin
            @test buf[frames[1].data] == data
        end
        # Without a Length field, the data runs to the end of the packet.
        buf = UInt8[]
        QFR._append_stream_frame!(buf, UInt64(2), UInt64(0), UInt8[0x01, 0x02]; explicit_length = false)
        QFR._append_ping_frame!(buf)
        frames, _ = _qfr_decode(buf)
        @test length(frames) == 1
        @test buf[frames[1].data] == UInt8[0x01, 0x02, 0x01]
        # An empty STREAM frame is how a sender sends just a FIN.
        buf = UInt8[]
        QFR._append_stream_frame!(buf, UInt64(2), UInt64(9), UInt8[]; fin = true)
        frames, result = _qfr_decode(buf)
        @test result.error === nothing
        @test isempty(frames[1].data)
        @test frames[1].fin
    end

    @testset "ACK frames" begin
        # One packet acknowledged, then a gap of exactly one packet.
        buf = UInt8[]
        QFR._append_ack_frame!(buf, [UInt64(10):UInt64(10), UInt64(8):UInt64(8)], UInt64(0))
        frames, _ = _qfr_decode(buf)
        @test _qfr_ranges(buf, frames[1]) == [UInt64(10):UInt64(10), UInt64(8):UInt64(8)]
        # Ranges must be descending and separated by at least one packet.
        @test_throws ArgumentError QFR._append_ack_frame!(UInt8[], [UInt64(8):UInt64(8), UInt64(10):UInt64(10)], UInt64(0))
        @test_throws ArgumentError QFR._append_ack_frame!(UInt8[], [UInt64(10):UInt64(10), UInt64(9):UInt64(9)], UInt64(0))
        @test_throws ArgumentError QFR._append_ack_frame!(UInt8[], UnitRange{UInt64}[], UInt64(0))
        # First ACK Range larger than Largest Acknowledged.
        @test _qfr_encoding_error(UInt8[0x02, 0x05, 0x00, 0x00, 0x06])
        # A gap reaching below packet number 0.
        @test _qfr_encoding_error(UInt8[0x02, 0x05, 0x00, 0x01, 0x02, 0x03, 0x00])
        # ACK frames are not ack-eliciting, and neither is PADDING.
        buf = UInt8[]
        QFR._append_ack_frame!(buf, [UInt64(1):UInt64(3)], UInt64(0))
        QFR._append_padding!(buf, 5)
        _, result = _qfr_decode(buf)
        @test result.error === nothing
        @test !result.ack_eliciting
    end

    @testset "encoding errors (RFC 9000 Section 19)" begin
        # Unknown frame type, reported with that type.
        err = _qfr_error(UInt8[0x21])
        @test err.code == QFR._FRAME_ENCODING_ERROR
        @test err.frame_type == 0x21
        # Every frame type cut short by one byte.
        full = UInt8[]
        QFR._append_crypto_frame!(full, UInt64(0), UInt8[0x01, 0x02])
        @test _qfr_encoding_error(full[1:(end - 1)])
        for make in (
                b -> QFR._append_ack_frame!(b, [UInt64(5):UInt64(9)], UInt64(3)),
                b -> QFR._append_ack_frame!(b, [UInt64(5):UInt64(9)], UInt64(3); ecn = (UInt64(1), UInt64(1), UInt64(1))),
                b -> QFR._append_reset_stream_frame!(b, UInt64(1), UInt64(2), UInt64(3)),
                b -> QFR._append_stop_sending_frame!(b, UInt64(1), UInt64(2)),
                b -> QFR._append_new_token_frame!(b, UInt8[0x01, 0x02]),
                b -> QFR._append_stream_frame!(b, UInt64(1), UInt64(1), UInt8[0x01]),
                b -> QFR._append_max_data_frame!(b, UInt64(70)),
                b -> QFR._append_max_stream_data_frame!(b, UInt64(1), UInt64(70)),
                b -> QFR._append_max_streams_frame!(b, true, UInt64(70)),
                b -> QFR._append_data_blocked_frame!(b, UInt64(70)),
                b -> QFR._append_stream_data_blocked_frame!(b, UInt64(1), UInt64(70)),
                b -> QFR._append_streams_blocked_frame!(b, false, UInt64(70)),
                b -> QFR._append_new_connection_id_frame!(b, UInt64(1), UInt64(0), UInt8[0x01, 0x02], zeros(UInt8, 16)),
                b -> QFR._append_retire_connection_id_frame!(b, UInt64(70)),
                b -> QFR._append_path_challenge_frame!(b, UInt64(1)),
                b -> QFR._append_path_response_frame!(b, UInt64(1)),
                b -> QFR._append_connection_close_frame!(b, UInt64(1), UInt64(0), UInt8[0x61]),
                b -> QFR._append_connection_close_frame!(b, UInt64(1), UInt64(0), UInt8[0x61]; app = true),
            )
            buf = UInt8[]
            make(buf)
            @test _qfr_error(buf) === nothing
            @test _qfr_encoding_error(buf[1:(end - 1)])
        end
        # Offset plus length past 2^62 - 1, for CRYPTO and STREAM.
        too_far = QFR._MAX_VARINT
        buf = UInt8[0x06]
        QFR._append_varint!(buf, too_far)
        QFR._append_varint!(buf, UInt64(1))
        push!(buf, 0x00)
        @test _qfr_encoding_error(buf)
        buf = UInt8[0x0e, 0x00]
        QFR._append_varint!(buf, too_far)
        QFR._append_varint!(buf, UInt64(1))
        push!(buf, 0x00)
        @test _qfr_encoding_error(buf)
        # Stream limits above 2^60 (Sections 19.11 and 19.14).
        for type in (0x12, 0x13, 0x16, 0x17)
            buf = UInt8[type]
            QFR._append_varint!(buf, (UInt64(1) << 60) + 1)
            @test _qfr_encoding_error(buf)
            buf = UInt8[type]
            QFR._append_varint!(buf, UInt64(1) << 60)
            @test _qfr_error(buf) === nothing
        end
        # NEW_TOKEN must carry a token.
        @test _qfr_encoding_error(UInt8[0x07, 0x00])
        # NEW_CONNECTION_ID: lengths 1 to 20, and Retire Prior To at most the sequence number.
        for (cid_len, ok) in ((0, false), (1, true), (20, true), (21, false))
            buf = vcat(UInt8[0x18, 0x01, 0x00, cid_len], zeros(UInt8, cid_len + 16))
            @test (_qfr_error(buf) === nothing) == ok
        end
        @test _qfr_encoding_error(vcat(UInt8[0x18, 0x01, 0x02, 0x04], zeros(UInt8, 20)))
    end

    @testset "frames each packet type may carry (RFC 9000 Section 12.4)" begin
        frame(f) = (b = UInt8[]; f(b); b)
        stream = frame(b -> QFR._append_stream_frame!(b, UInt64(0), UInt64(0), UInt8[0x01]))
        crypto = frame(b -> QFR._append_crypto_frame!(b, UInt64(0), UInt8[0x01]))
        ack = frame(b -> QFR._append_ack_frame!(b, [UInt64(0):UInt64(0)], UInt64(0)))
        done = frame(QFR._append_handshake_done_frame!)
        token = frame(b -> QFR._append_new_token_frame!(b, UInt8[0x01]))
        response = frame(b -> QFR._append_path_response_frame!(b, UInt64(0)))
        retire = frame(b -> QFR._append_retire_connection_id_frame!(b, UInt64(0)))
        transport_close = frame(b -> QFR._append_connection_close_frame!(b, UInt64(0), UInt64(0), UInt8[]))
        app_close = frame(b -> QFR._append_connection_close_frame!(b, UInt64(0), UInt64(0), UInt8[]; app = true))
        for type in (QFT.Initial, QFT.Handshake)
            for allowed in (crypto, ack, transport_close, UInt8[0x00], UInt8[0x01])
                @test _qfr_error(allowed, type) === nothing
            end
            for forbidden in (stream, done, token, response, retire, app_close)
                @test _qfr_protocol_violation(forbidden, type)
            end
        end
        for forbidden in (ack, crypto, done, token, response, retire)
            @test _qfr_protocol_violation(forbidden, QFT.ZeroRTT)
        end
        for allowed in (stream, app_close, transport_close)
            @test _qfr_error(allowed, QFT.ZeroRTT) === nothing
        end
        for allowed in (stream, crypto, ack, done, token, response, retire, transport_close, app_close)
            @test _qfr_error(allowed, QFT.OneRTT) === nothing
        end
        # A packet must contain at least one frame.
        @test _qfr_protocol_violation(UInt8[], QFT.OneRTT)
    end

    @testset "ack-eliciting packets" begin
        frame(f) = (b = UInt8[]; f(b); b)
        close_only = frame(b -> QFR._append_connection_close_frame!(b, UInt64(0), UInt64(0), UInt8[]))
        @test !_qfr_decode(close_only)[2].ack_eliciting
        @test _qfr_decode(UInt8[0x00, 0x01])[2].ack_eliciting  # PING
        @test !_qfr_decode(UInt8[0x00, 0x00])[2].ack_eliciting
    end

    @testset "handlers can stop decoding with their own error" begin
        buf = UInt8[]
        QFR._append_stream_frame!(buf, UInt64(3), UInt64(0), UInt8[0x01])
        QFR._append_ping_frame!(buf)
        seen = Any[]
        result = QFR._decode_frames(buf, 1, length(buf), QFT.OneRTT) do frame
            push!(seen, frame)
            frame isa QFR._StreamFrame && return QFR._TransportError(QFR._STREAM_STATE_ERROR, UInt64(0x08), "send-only stream")
            return nothing
        end
        @test length(seen) == 1
        @test result.error == QFR._TransportError(QFR._STREAM_STATE_ERROR, UInt64(0x08), "send-only stream")
    end

    @testset "decoding a range inside a larger buffer" begin
        buf = UInt8[0xaa, 0xbb]
        QFR._append_ping_frame!(buf)
        QFR._append_max_data_frame!(buf, UInt64(9))
        push!(buf, 0xcc)
        frames, result = _qfr_decode(buf; first = 3, last = length(buf) - 1)
        @test result.error === nothing
        @test frames == Any[QFR._PingFrame(), QFR._MaxDataFrame(9)]
    end
end
