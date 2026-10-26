# Ported from quic-go v0.48.2, internal/ackhandler:
#   received_packet_history_test.go, received_packet_tracker_test.go,
#   received_packet_handler_test.go, sent_packet_history_test.go,
#   sent_packet_handler_test.go, ack_eliciting_test.go,
#   packet_number_generator_test.go (sequential generator only).
#
# quic-go splits loss recovery into a received-packet tracker and a
# sent-packet handler driven through mocks; Reseau keeps all of it in
# `_Connection` (src/quic/connection.jl). The ports map quic-go's pieces onto
# that structure:
#   - received history/tracker: 1-RTT, Handshake, and Initial packets are
#     sealed with the keys the connection reads with and handed to
#     `_receive_datagram!`; the ACK frames the connection then sends with
#     `_next_datagram!` are opened and decoded. "ACK queued" means an ACK is
#     pending and due now; the ACK alarm is `ack_deadline` while not due;
#     `GetAckFrame(false)` (an ACK sent because some other packet goes out) is a
#     PING probe that the pending ACK rides along with.
#   - sent history/handler: `handler.SentPacket` is `_qga_sent!`, which records
#     a `_SentPacket` exactly as `_build_datagram!` does (bytes in flight, time
#     of the last ack-eliciting packet, bytes sent); `ReceivedAck` is
#     `_on_ack!`; `GetLossDetectionTimeout` is `_next_timeout` less the idle
#     timer; `OnLossDetectionTimeout` is `_handle_timeout!` at that time;
#     `SendPTO<space>` is `space.probes > 0`; `SendNone` is an exhausted
#     amplification budget. Each packet carries a one-byte CRYPTO frame at
#     offset pn, so the "lostPackets" quic-go collects from OnLost callbacks are
#     the offsets queued again for sending.
#   - quic-go's LatestRTT is the ack-delay-adjusted sample; Reseau keeps
#     `latest_rtt` raw (RFC 9002 Section 5.3) and uses the adjusted sample for
#     `smoothed_rtt`, so those expectations are checked through `smoothed_rtt`.
#   - quic-go's perspective defaults to the server in sent_packet_handler_test;
#     these tests flip `is_server` on a client connection.
#
# Not applicable (deliberate omissions or Go-only API):
#   ECN: ecn_test.go (16 cases); "sets ECN flags", "queues an ACK if the packet
#     was ECN-CE marked"; the SentPacketHandler "ECN handling" context (7).
#   Packet number skipping: packet_number_generator_test.go "Skipping Packet
#     Number Generator" (5); sent history "saves sent packets, with skipped
#     packet number", "also removes skipped packets before the removed packet",
#     "also iterates over skipped packets"; "rejects ACKs that acknowledge a
#     skipped packet number"; "peeks and pops the initial packet number" and
#     "peeks and pops beyond the initial packet number" (configurable first
#     packet number, skipping).
#   0-RTT: "uses the same packet number space for 0-RTT and 1-RTT packets" (sent
#     handler and received handler), "rejects 0-RTT packets with higher packet
#     numbers than 1-RTT packets", "allows reordered 0-RTT packets", "does
#     nothing when dropping 0-RTT packets", "says if a 1-RTT packet was
#     acknowledged", "doesn't retransmit 0-RTT packets when 0-RTT keys are
#     dropped".
#   Retry (not handled by this client; see `_check_peer_transport_parameters`):
#     the five "for the client" Retry cases.
#   Go API helpers and mocks: send_mode_test.go "has a string representation";
#     received history "appends ACK ranges"; sent history "panics on
#     non-sequential packet number use", "errors when trying to remove a non
#     existing packet", and the "iterating" context except the skipped-packet
#     case (5: Iterate's callback protocol); congestion "returns the pacing
#     delay" (a mock's return value; Reseau has no pacer); "allows sending of
#     ACKs when we're keeping track of MaxOutstandingSentPackets packets"
#     (quic-go's cap on tracked packets, which Reseau does not have).
#
# ACK-range pruning (RFC 9000 Section 13.2.4): quic-go's DeleteBelow and
# IgnoreBelow are `_ignore_below!` on a space's `received`; its
# GetLowestPacketNotConfirmedAcked is the space's `ack_floor`, which the
# connection applies on the next packet received, as quic-go's
# receivedPacketHandler does. Where a Go test raises the threshold by hand,
# the port does too; "doesn't add delayed packets below deleted ranges",
# "deletes packets from the packetHistory when a lower limit is set", and
# "drops old ACK ranges" use the real trigger instead (the peer acknowledging
# a packet that carried an ACK).

using Test
using Random
using Reseau

@isdefined(_QcnHarness) || include("quic_harness.jl")

const QGA = Reseau.QUIC

const _QGA_MS = Int64(1_000_000)
const _QGA_SEC = 1000 * _QGA_MS
const _QGA_MIN = 60 * _QGA_SEC
const _QGA_HOUR = 60 * _QGA_MIN
# Far enough from zero that "an hour ago" is still a positive time.
const _QGA_T0 = 100_000 * _QGA_SEC
const _QGA_SUITE = UInt16(0x1301)  # TLS_AES_128_GCM_SHA256
const _QGA_HS_IN = fill(0x31, 32)
const _QGA_HS_OUT = fill(0x32, 32)
const _QGA_APP_IN = fill(0x41, 32)
const _QGA_APP_OUT = fill(0x42, 32)
const _QGA_PEER_CID = fill(0x77, 8)

# A connection under test, with the keys its simulated peer seals and opens with.
mutable struct _QgaEnd
    conn::QGA._Connection
    seal::Vector{QGA._PacketKeys}
    open::Vector{QGA._PacketKeys}
    largest::Vector{Int64}
end

function _qga_install_handshake_keys!(e::_QgaEnd)
    e.conn.spaces[QGA._HANDSHAKE_SPACE].read_keys = QGA._PacketKeys(_QGA_SUITE, _QGA_HS_IN)
    e.conn.spaces[QGA._HANDSHAKE_SPACE].write_keys = QGA._PacketKeys(_QGA_SUITE, _QGA_HS_OUT)
    return e
end

function _qga_end(; server::Bool = false, handshake_keys::Bool = true)
    conn = QGA._client_connection(_qcn_client_config(), _QGA_T0)
    # quic-go's ackhandler has no idle timers.
    conn.idle_timeout_ns = Int64(10)^18
    conn.handshake_idle_timeout_ns = Int64(10)^18
    # The ClientHello stays out of the way; tests send their own packets. The
    # CRYPTO bytes the tests' packets "carry" exist, so resending them works.
    empty!(conn.spaces[QGA._INITIAL_SPACE].crypto_send.pending)
    for idx in (QGA._HANDSHAKE_SPACE, QGA._APPLICATION_SPACE)
        append!(conn.spaces[idx].crypto_send.data, zeros(UInt8, 4096))
    end
    conn.spaces[QGA._APPLICATION_SPACE].read_keys = QGA._PacketKeys(_QGA_SUITE, _QGA_APP_IN)
    conn.spaces[QGA._APPLICATION_SPACE].write_keys = QGA._PacketKeys(_QGA_SUITE, _QGA_APP_OUT)
    client_keys, server_keys = QGA._initial_packet_keys(conn.original_dcid)
    e = _QgaEnd(
        conn,
        [server_keys, QGA._PacketKeys(_QGA_SUITE, _QGA_HS_IN), QGA._PacketKeys(_QGA_SUITE, _QGA_APP_IN)],
        [client_keys, QGA._PacketKeys(_QGA_SUITE, _QGA_HS_OUT), QGA._PacketKeys(_QGA_SUITE, _QGA_APP_OUT)],
        Int64[-1, -1, -1],
    )
    handshake_keys && _qga_install_handshake_keys!(e)
    conn.is_server = server
    return e
end

# The peer sends packet `pn` in space `idx`: a PING, or PADDING alone when not
# ack-eliciting, or `frames`. Returns whether it was new to the receiver.
function _qga_rx!(e::_QgaEnd, idx::Int, pn::Integer, now::Int64; ack_eliciting::Bool = true, frames = nothing)
    conn = e.conn
    space = conn.spaces[idx]
    was_new = !(pn in space.received)
    buf = UInt8[]
    pn_len = 4
    layout = if idx == QGA._APPLICATION_SPACE
        QGA._begin_short_packet!(buf, conn.local_cid, Int64(pn), pn_len)
    else
        type = idx == QGA._INITIAL_SPACE ? QGA._PacketType.Initial : QGA._PacketType.Handshake
        QGA._begin_long_packet!(buf, type, QGA._QUIC_V1, conn.local_cid, _QGA_PEER_CID, UInt8[], Int64(pn), pn_len)
    end
    if frames !== nothing
        append!(buf, frames)
    else
        push!(buf, ack_eliciting ? 0x01 : 0x00)
    end
    payload_last = QGA._end_packet!(buf, layout)
    QGA._seal_packet!(e.seal[idx], buf, layout.first, layout.pn_offset, pn_len, payload_last, Int64(pn))
    QGA._receive_datagram!(conn, buf, now)
    return was_new
end

_qga_rx!(e::_QgaEnd, pn::Integer, now::Int64; kw...) = _qga_rx!(e, QGA._APPLICATION_SPACE, pn, now; kw...)

struct _QgaAck
    ranges::Vector{UnitRange{Int64}}  # largest first, like quic-go's AckRanges
    delay_ns::Int64
end

_qga_largest(a::_QgaAck) = last(a.ranges[1])
_qga_lowest(a::_QgaAck) = first(a.ranges[end])
_qga_has_missing(a::_QgaAck) = length(a.ranges) > 1

struct _QgaOutPacket
    pn::Int64
    ack::Union{Nothing, _QgaAck}
    ack_eliciting::Bool
    frame_types::Vector{DataType}
end

# Whatever `_next_datagram!` sends now, opened by the peer: packets by space.
function _qga_tx!(e::_QgaEnd, now::Int64)
    conn = e.conn
    dgram = QGA._next_datagram!(conn, now)
    dgram === nothing && return nothing
    len = length(dgram)
    out = Dict{Int, _QgaOutPacket}()
    for hdr in collect(QGA._datagram_packets(dgram, 1, length(dgram), length(conn.peer_cid)))
        idx = hdr.type == QGA._PacketType.Initial ? 1 : hdr.type == QGA._PacketType.Handshake ? 2 : 3
        opened = QGA._open_packet!(e.open[idx], dgram, hdr.first, hdr.pn_offset, hdr.last, e.largest[idx])
        opened === nothing && error("could not open the packet sent in space $idx")
        pn, pf, pl = opened
        e.largest[idx] = max(e.largest[idx], pn)
        ack = Ref{Union{Nothing, _QgaAck}}(nothing)
        types = DataType[]
        res = QGA._decode_frames(dgram, pf, pl, hdr.type) do f
            push!(types, typeof(f))
            if f isa QGA._AckFrame
                ranges = [Int64(first(r)):Int64(last(r)) for r in QGA._ack_ranges(dgram, f)]
                exponent = Int(conn.local_params.ack_delay_exponent)
                ack[] = _QgaAck(ranges, Int64(f.delay << exponent) * 1000)
            end
            nothing
        end
        out[idx] = _QgaOutPacket(pn, ack[], res.ack_eliciting, types)
    end
    return (len = len, packets = out)
end

# The ACK for space `idx` in what the connection sends now, or nothing.
function _qga_ack_out!(e::_QgaEnd, now::Int64, idx::Int = QGA._APPLICATION_SPACE)
    out = _qga_tx!(e, now)
    out === nothing && return nothing
    p = get(out.packets, idx, nothing)
    return p === nothing ? nothing : p.ack
end

# quic-go's GetAckFrame(false): an ACK that goes out because another packet
# does. A PING probe forces a packet; any pending ACK rides along.
function _qga_ack_unqueued!(e::_QgaEnd, now::Int64)
    e.conn.spaces[QGA._APPLICATION_SPACE].probes += 1
    return _qga_ack_out!(e, now)
end

# quic-go's ackQueued and GetAlarmTimeout.
_qga_ack_queued(e::_QgaEnd, now::Int64, idx::Int = 3) =
    (s = e.conn.spaces[idx]; s.ack_pending && s.ack_deadline <= now)
_qga_ack_alarm(e::_QgaEnd, now::Int64, idx::Int = 3) =
    (s = e.conn.spaces[idx]; s.ack_pending && s.ack_deadline > now ? s.ack_deadline : Int64(0))
# quic-go's `tracker.ackQueued = true`.
function _qga_force_queued!(e::_QgaEnd, idx::Int = 3)
    s = e.conn.spaces[idx]
    s.ack_pending = true
    s.ack_deadline = Int64(0)
    return nothing
end

_qga_ranges(e::_QgaEnd, idx::Int = 3) = copy(e.conn.spaces[idx].received.ranges)

# Sending, recorded as `_build_datagram!` records it.
# `ack_largest` is the largest packet number an ACK frame in it acknowledged.
function _qga_sent!(conn::QGA._Connection, idx::Int, pn::Integer; time::Int64, size::Int = 1, ack_eliciting::Bool = true, ack_largest::Integer = -1)
    space = conn.spaces[idx]
    space.next_pn = max(space.next_pn, Int64(pn) + 1)
    conn.bytes_sent += size
    conn.last_send_time = time
    ack_eliciting || return nothing
    frames = [QGA._SentFrame(QGA._SF_CRYPTO, UInt64(0), Int64(pn), Int64(1), false)]
    push!(space.sent, QGA._SentPacket(Int64(pn), time, size, frames, Int64(ack_largest), false))
    space.time_of_last_ack_eliciting = time
    conn.bytes_in_flight += size
    return nothing
end
_qga_sent!(e::_QgaEnd, args...; kw...) = _qga_sent!(e.conn, args...; kw...)

_qga_history(e::_QgaEnd, idx::Int = 3) = [p.pn for p in e.conn.spaces[idx].sent]
# Packets declared lost (or sent again by a probe timeout): their CRYPTO byte
# is queued again.
_qga_lost(e::_QgaEnd, idx::Int = 3) = [x for r in e.conn.spaces[idx].crypto_send.pending.ranges for x in r]
_qga_history_or_lost(e::_QgaEnd, idx::Int = 3) = sort(vcat(_qga_history(e, idx), _qga_lost(e, idx)))

function _qga_set_time!(e::_QgaEnd, idx::Int, pn::Integer, t::Int64)
    sent = e.conn.spaces[idx].sent
    i = findfirst(p -> p.pn == pn, sent)
    p = sent[i]
    sent[i] = QGA._SentPacket(p.pn, t, p.size, p.frames)
    return nothing
end

# The peer's ACK frame for `ranges` (largest first), handed to `_on_ack!`.
function _qga_ack!(e::_QgaEnd, idx::Int, ranges::Vector{<:UnitRange}, now::Int64; delay_ns::Int64 = Int64(0))
    conn = e.conn
    params = conn.peer_params
    exponent = params === nothing ? 3 : Int(params.ack_delay_exponent)
    buf = UInt8[]
    QGA._append_ack_frame!(buf, [UInt64(first(r)):UInt64(last(r)) for r in ranges], UInt64(delay_ns ÷ 1000) >> exponent)
    frame = Ref{Any}(nothing)
    QGA._decode_frames(buf, 1, length(buf), QGA._PacketType.OneRTT) do f
        frame[] = f
        nothing
    end
    return QGA._on_ack!(conn, conn.spaces[idx], idx, buf, frame[]::QGA._AckFrame, now)
end

_qga_update_rtt!(e::_QgaEnd, rtt::Int64) = QGA._update_rtt!(e.conn, rtt, Int64(0))

# quic-go's GetLossDetectionTimeout: the connection's next timer, unless that
# is only the idle timeout.
function _qga_timer(e::_QgaEnd)
    conn = e.conn
    t = QGA._next_timeout(conn)
    (t === nothing || t >= QGA._idle_deadline(conn)) && return nothing
    return t
end

# quic-go's OnLossDetectionTimeout: act on the timer, whenever it is set for.
function _qga_fire!(e::_QgaEnd, now::Int64)
    t = _qga_timer(e)
    QGA._handle_timeout!(e.conn, t === nothing ? now : max(now, t))
    return nothing
end

# quic-go's SendMode: the space with probes to send, or 0 for SendAny.
function _qga_pto_mode(e::_QgaEnd)
    for idx in 1:3
        e.conn.spaces[idx].probes > 0 && return idx
    end
    return 0
end

# setHandshakeConfirmed: drop the Initial and Handshake spaces, then confirm.
function _qga_confirm!(e::_QgaEnd)
    QGA._discard_space!(e.conn, QGA._INITIAL_SPACE)
    QGA._discard_space!(e.conn, QGA._HANDSHAKE_SPACE)
    e.conn.handshake_confirmed = true
    return nothing
end

_qga_set_max_ack_delay!(e::_QgaEnd, ms::Integer) =
    (e.conn.peer_params = QGA._TransportParameters(max_ack_delay_ms = UInt64(ms)); nothing)

# The receiver sends its pending ACK in an ack-eliciting packet and the peer
# acknowledges that packet: the trigger for RFC 9000 Section 13.2.4 pruning.
function _qga_ack_gets_acked!(e::_QgaEnd, now::Int64)
    out = _qga_ack_unqueued!(e, now)
    sent = e.conn.spaces[3].sent
    pn = sent[end].pn
    _qga_ack!(e, 3, [pn:pn], now)
    return out
end

function _qga_frame_bytes(f)
    buf = UInt8[]
    f(buf)
    return buf
end

@testset "quic_go_ackhandler_tests.jl" begin
    T = _QGA_T0

    # ------------------------------------------------------------------
    @testset "ack-eliciting frames" begin
        frames = [
            ("AckFrame", b -> QGA._append_ack_frame!(b, [UInt64(0):UInt64(0)], UInt64(0)), false),
            ("ConnectionCloseFrame", b -> QGA._append_connection_close_frame!(b, UInt64(0), UInt64(0), UInt8[]), false),
            ("DataBlockedFrame", b -> QGA._append_data_blocked_frame!(b, UInt64(0)), true),
            ("PingFrame", b -> QGA._append_ping_frame!(b), true),
            ("ResetStreamFrame", b -> QGA._append_reset_stream_frame!(b, UInt64(0), UInt64(0), UInt64(0)), true),
            ("StreamFrame", b -> QGA._append_stream_frame!(b, UInt64(0), UInt64(0), UInt8[0x13, 0x37]), true),
            ("MaxDataFrame", b -> QGA._append_max_data_frame!(b, UInt64(0)), true),
            ("MaxStreamDataFrame", b -> QGA._append_max_stream_data_frame!(b, UInt64(0), UInt64(0)), true),
        ]
        for (name, f, eliciting) in frames
            @testset "works for $name" begin
                buf = _qga_frame_bytes(f)
                res = QGA._decode_frames((_) -> nothing, buf, 1, length(buf), QGA._PacketType.OneRTT)
                @test res.error === nothing
                @test res.ack_eliciting == eliciting
            end
            @testset "HasAckElicitingFrames works for $name" begin
                # A whole packet payload holding the frame, padded.
                buf = _qga_frame_bytes(f)
                append!(buf, zeros(UInt8, 4))
                res = QGA._decode_frames((_) -> nothing, buf, 1, length(buf), QGA._PacketType.OneRTT)
                @test res.error === nothing
                @test res.ack_eliciting == eliciting
            end
        end
    end

    # ------------------------------------------------------------------
    @testset "Sequential Packet Number Generator" begin
        @testset "generates sequential packet numbers" begin
            e = _qga_end()
            e.conn.spaces[3].next_pn = 100
            pns = Int64[]
            for _ in 1:3
                e.conn.spaces[3].probes = 1
                push!(pns, _qga_tx!(e, T).packets[3].pn)
            end
            @test pns == [100, 101, 102]
        end
    end

    # ------------------------------------------------------------------
    @testset "receivedPacketHistory" begin
        @testset "ranges" begin
            @testset "adds the first packet" begin
                e = _qga_end()
                @test _qga_rx!(e, 4, T)
                @test _qga_ranges(e) == [4:4]
            end
            @testset "doesn't care about duplicate packets" begin
                e = _qga_end()
                @test _qga_rx!(e, 4, T)
                @test !_qga_rx!(e, 4, T)
                @test _qga_ranges(e) == [4:4]
            end
            @testset "adds a few consecutive packets" begin
                e = _qga_end()
                @test _qga_rx!(e, 4, T)
                @test _qga_rx!(e, 5, T)
                @test _qga_rx!(e, 6, T)
                @test _qga_ranges(e) == [4:6]
            end
            @testset "doesn't care about a duplicate packet contained in an existing range" begin
                e = _qga_end()
                @test _qga_rx!(e, 4, T)
                @test _qga_rx!(e, 5, T)
                @test _qga_rx!(e, 6, T)
                @test !_qga_rx!(e, 5, T)
                @test _qga_ranges(e) == [4:6]
            end
            @testset "extends a range at the front" begin
                e = _qga_end()
                @test _qga_rx!(e, 4, T)
                @test _qga_rx!(e, 3, T)
                @test _qga_ranges(e) == [3:4]
            end
            @testset "creates a new range when a packet is lost" begin
                e = _qga_end()
                @test _qga_rx!(e, 4, T)
                @test _qga_rx!(e, 6, T)
                @test _qga_ranges(e) == [4:4, 6:6]
            end
            @testset "creates a new range in between two ranges" begin
                e = _qga_end()
                @test _qga_rx!(e, 4, T)
                @test _qga_rx!(e, 10, T)
                @test length(_qga_ranges(e)) == 2
                @test _qga_rx!(e, 7, T)
                @test _qga_ranges(e) == [4:4, 7:7, 10:10]
            end
            @testset "creates a new range before an existing range for a belated packet" begin
                e = _qga_end()
                @test _qga_rx!(e, 6, T)
                @test _qga_rx!(e, 4, T)
                @test _qga_ranges(e) == [4:4, 6:6]
            end
            @testset "extends a previous range at the end" begin
                e = _qga_end()
                @test _qga_rx!(e, 4, T)
                @test _qga_rx!(e, 7, T)
                @test _qga_rx!(e, 5, T)
                @test _qga_ranges(e) == [4:5, 7:7]
            end
            @testset "extends a range at the front (second range)" begin
                e = _qga_end()
                @test _qga_rx!(e, 4, T)
                @test _qga_rx!(e, 7, T)
                @test _qga_rx!(e, 6, T)
                @test _qga_ranges(e) == [4:4, 6:7]
            end
            @testset "closes a range" begin
                e = _qga_end()
                @test _qga_rx!(e, 6, T)
                @test _qga_rx!(e, 4, T)
                @test length(_qga_ranges(e)) == 2
                @test _qga_rx!(e, 5, T)
                @test _qga_ranges(e) == [4:6]
            end
            @testset "closes a range in the middle" begin
                e = _qga_end()
                @test _qga_rx!(e, 1, T)
                @test _qga_rx!(e, 10, T)
                @test _qga_rx!(e, 4, T)
                @test _qga_rx!(e, 6, T)
                @test length(_qga_ranges(e)) == 4
                @test _qga_rx!(e, 5, T)
                @test _qga_ranges(e) == [1:1, 4:6, 10:10]
            end
        end

        @testset "deleting" begin
            delete_below!(e, pn) = QGA._ignore_below!(e.conn.spaces[3].received, Int64(pn))
            @testset "does nothing when the history is empty" begin
                e = _qga_end()
                delete_below!(e, 5)
                @test isempty(_qga_ranges(e))
            end
            @testset "deletes a range" begin
                e = _qga_end()
                foreach(pn -> @test(_qga_rx!(e, pn, T)), (4, 5, 10))
                delete_below!(e, 6)
                @test _qga_ranges(e) == [10:10]
            end
            @testset "deletes multiple ranges" begin
                e = _qga_end()
                foreach(pn -> @test(_qga_rx!(e, pn, T)), (1, 5, 10))
                delete_below!(e, 8)
                @test _qga_ranges(e) == [10:10]
            end
            @testset "adjusts a range, if packets are delete from an existing range" begin
                e = _qga_end()
                foreach(pn -> @test(_qga_rx!(e, pn, T)), 3:7)
                delete_below!(e, 5)
                @test _qga_ranges(e) == [5:7]
            end
            @testset "adjusts a range, if only one packet remains in the range" begin
                e = _qga_end()
                foreach(pn -> @test(_qga_rx!(e, pn, T)), (4, 5, 10))
                delete_below!(e, 5)
                @test _qga_ranges(e) == [5:5, 10:10]
            end
            @testset "keeps a one-packet range, if deleting up to the packet directly below" begin
                e = _qga_end()
                @test _qga_rx!(e, 4, T)
                delete_below!(e, 4)
                @test _qga_ranges(e) == [4:4]
            end
            @testset "doesn't add delayed packets below deleted ranges" begin
                # DeleteBelow(5) after 4..6: here, an ACK covering 4 is acknowledged.
                e = _qga_end()
                @test _qga_rx!(e, 4, T)
                _qga_ack_gets_acked!(e, T)
                @test _qga_rx!(e, 5, T)
                @test _qga_rx!(e, 6, T)
                @test _qga_ranges(e) == [5:6]
                @test !_qga_rx!(e, 2, T)
                @test _qga_ranges(e) == [5:6]
            end
            @testset "doesn't create more than MaxNumAckRanges ranges" begin
                e = _qga_end()
                @test QGA._MAX_ACK_RANGES == 32
                for i in 0:(QGA._MAX_ACK_RANGES - 1)
                    @test _qga_rx!(e, 2i, T)
                end
                @test length(_qga_ranges(e)) == QGA._MAX_ACK_RANGES
                @test _qga_ranges(e)[1] == 0:0
                _qga_rx!(e, 2 * QGA._MAX_ACK_RANGES + 1000, T)
                # the oldest ACK range was deleted
                @test length(_qga_ranges(e)) == QGA._MAX_ACK_RANGES
                @test _qga_ranges(e)[1] == 2:2
            end
        end

        @testset "ACK range export" begin
            @testset "returns nil if there are no ranges" begin
                e = _qga_end()
                @test _qga_ack_out!(e, T) === nothing
            end
            @testset "gets a single ACK range" begin
                e = _qga_end()
                @test _qga_rx!(e, 4, T)
                @test _qga_rx!(e, 5, T)
                @test _qga_ack_out!(e, T).ranges == [4:5]
            end
            @testset "gets multiple ACK ranges" begin
                e = _qga_end()
                for pn in (4, 5, 6, 1, 11, 10, 2)
                    @test _qga_rx!(e, pn, T)
                end
                @test _qga_ack_out!(e, T).ranges == [10:11, 4:6, 1:2]
            end
        end

        @testset "Getting the highest ACK range" begin
            @testset "returns the zero value if there are no ranges" begin
                e = _qga_end()
                @test isempty(_qga_ranges(e))
                @test _qga_ack_out!(e, T) === nothing
            end
            @testset "gets a single ACK range" begin
                e = _qga_end()
                @test _qga_rx!(e, 4, T)
                @test _qga_rx!(e, 5, T)
                @test _qga_ack_out!(e, T).ranges[1] == 4:5
            end
            @testset "gets the highest of multiple ACK ranges" begin
                e = _qga_end()
                @test _qga_rx!(e, 3, T)
                @test _qga_rx!(e, 6, T)
                @test _qga_rx!(e, 7, T)
                @test _qga_ack_out!(e, T).ranges[1] == 6:7
            end
        end

        @testset "duplicate detection" begin
            isdup(e, pn) = pn in e.conn.spaces[3].received
            @testset "doesn't declare the first packet a duplicate" begin
                e = _qga_end()
                @test !isdup(e, 5)
            end
            @testset "detects a duplicate in a range" begin
                e = _qga_end()
                foreach(pn -> _qga_rx!(e, pn, T), (4, 5, 6))
                @test !isdup(e, 3)
                @test isdup(e, 4)
                @test isdup(e, 5)
                @test isdup(e, 6)
                @test !isdup(e, 7)
            end
            @testset "detects a duplicate in multiple ranges" begin
                e = _qga_end()
                foreach(pn -> _qga_rx!(e, pn, T), (4, 5, 8, 9))
                @test !isdup(e, 3)
                @test isdup(e, 4)
                @test isdup(e, 5)
                @test !isdup(e, 6)
                @test !isdup(e, 7)
                @test isdup(e, 8)
                @test isdup(e, 9)
                @test !isdup(e, 10)
            end
            @testset "says a packet is a potentially duplicate if the ranges were already deleted" begin
                e = _qga_end()
                foreach(pn -> _qga_rx!(e, pn, T), (4, 5, 8, 9, 11))
                QGA._ignore_below!(e.conn.spaces[3].received, Int64(8))
                @test isdup(e, 3)
                @test isdup(e, 4)
                @test isdup(e, 5)
                @test isdup(e, 6)
                @test isdup(e, 7)
                @test isdup(e, 8)
                @test isdup(e, 9)
                @test !isdup(e, 10)
                @test isdup(e, 11)
                @test !isdup(e, 12)
            end
        end

        @testset "randomized receiving" begin
            @testset "receiving packets in a random order, with gaps" begin
                rng = Random.Xoshiro(20241026)
                for _ in 1:5
                    e = _qga_end()
                    num = 2 * QGA._MAX_ACK_RANGES
                    num_lost = rand(rng, 0:(QGA._MAX_ACK_RANGES - 1))
                    lost = sort(Random.shuffle(rng, collect(0:(num - 1)))[1:num_lost])
                    received = setdiff(0:(num - 1), lost)
                    ordered = Random.shuffle(rng, received)
                    for (i, pn) in enumerate(ordered)
                        @test _qga_rx!(e, pn, T)
                        # sometimes receive a duplicate
                        if i > 1 && rand(rng, 0:4) == 0
                            @test !_qga_rx!(e, ordered[rand(rng, 1:(i - 1))], T)
                        end
                    end
                    ack = _qga_ack_out!(e, T)
                    @test length(ack.ranges) <= num_lost + 1
                    acked = [pn for r in ack.ranges for pn in r]
                    @test all(in(received), acked)
                    @test length(acked) == length(received)
                end
            end
        end
    end

    # ------------------------------------------------------------------
    @testset "Received Packet Tracker" begin
        # Initial packets, acknowledged at once.
        I = QGA._INITIAL_SPACE
        @testset "acknowledges packets" begin
            e = _qga_end(handshake_keys = false)
            t = T - 10 * _QGA_SEC
            _qga_rx!(e, I, 3, t)
            ack = _qga_ack_out!(e, t, I)
            @test ack !== nothing
            @test ack.ranges == [3:3]
            @test ack.delay_ns == 0
            # now receive another packet
            _qga_rx!(e, I, 4, t + _QGA_SEC)
            ack = _qga_ack_out!(e, t + _QGA_SEC, I)
            @test ack !== nothing
            @test ack.ranges == [3:4]
            @test ack.delay_ns == 0
        end
        @testset "also acknowledges delayed packets" begin
            e = _qga_end(handshake_keys = false)
            t = T - 10 * _QGA_SEC
            _qga_rx!(e, I, 3, t)
            ack = _qga_ack_out!(e, t, I)
            @test ack !== nothing
            @test _qga_largest(ack) == 3
            @test _qga_lowest(ack) == 3
            @test ack.delay_ns == 0
            # now receive another packet
            _qga_rx!(e, I, 1, t + _QGA_SEC)
            ack = _qga_ack_out!(e, t + _QGA_SEC, I)
            @test ack !== nothing
            @test length(ack.ranges) == 2
            @test 1:1 in ack.ranges
            @test 3:3 in ack.ranges
            @test ack.delay_ns == 0
        end
        @testset "doesn't trigger ACKs for non-ack-eliciting packets" begin
            e = _qga_end(handshake_keys = false)
            t = T - 10 * _QGA_SEC
            _qga_rx!(e, I, 3, t; ack_eliciting = false)
            @test _qga_ack_out!(e, t, I) === nothing
            _qga_rx!(e, I, 4, t + 5 * _QGA_SEC; ack_eliciting = false)
            @test _qga_ack_out!(e, t + 5 * _QGA_SEC, I) === nothing
            _qga_rx!(e, I, 5, t + 10 * _QGA_SEC)
            ack = _qga_ack_out!(e, t + 10 * _QGA_SEC, I)
            @test ack !== nothing
            @test ack.ranges == [3:5]
        end
    end

    # ------------------------------------------------------------------
    @testset "Application Data Received Packet Tracker" begin
        @testset "accepting packets" begin
            @testset "saves the time when each packet arrived" begin
                e = _qga_end()
                _qga_rx!(e, 3, T)
                @test e.conn.spaces[3].largest_received_time == T
            end
            @testset "updates the largestObserved and the largestObservedRcvdTime" begin
                e = _qga_end()
                s = e.conn.spaces[3]
                s.largest_received = 3
                s.largest_received_time = T - _QGA_SEC
                _qga_rx!(e, 5, T)
                @test s.largest_received == 5
                @test s.largest_received_time == T
            end
            @testset "doesn't update the largestObserved and the largestObservedRcvdTime for a belated packet" begin
                e = _qga_end()
                s = e.conn.spaces[3]
                s.largest_received = 5
                s.largest_received_time = T - _QGA_SEC
                _qga_rx!(e, 4, T)
                @test s.largest_received == 5
                @test s.largest_received_time == T - _QGA_SEC
            end
        end

        # receives and gets ACKs for packet numbers 1 to 10 (including)
        function receive_and_ack_10!(e, now)
            for i in 1:10
                _qga_rx!(e, i, now)
            end
            @test _qga_ack_out!(e, now) !== nothing
            @test !_qga_ack_queued(e, now)
        end

        @testset "queueing ACKs" begin
            @testset "always queues an ACK for the first packet" begin
                e = _qga_end()
                _qga_rx!(e, 1, T)
                @test _qga_ack_queued(e, T)
                @test _qga_ack_alarm(e, T) == 0
                @test _qga_ack_out!(e, T).delay_ns < _QGA_SEC
            end
            @testset "works with packet number 0" begin
                e = _qga_end()
                _qga_rx!(e, 0, T)
                @test _qga_ack_queued(e, T)
                @test _qga_ack_alarm(e, T) == 0
                ack = _qga_ack_out!(e, T)
                @test ack !== nothing && ack.delay_ns < _QGA_SEC
            end
            @testset "queues an ACK for every second ack-eliciting packet" begin
                e = _qga_end()
                receive_and_ack_10!(e, T)
                p = 11
                for _ in 0:20
                    _qga_rx!(e, p, T)
                    @test !_qga_ack_queued(e, T)
                    p += 1
                    _qga_rx!(e, p, T)
                    @test _qga_ack_queued(e, T)
                    p += 1
                    # dequeue the ACK frame
                    @test _qga_ack_out!(e, T) !== nothing
                end
            end
            @testset "resets the counter when a non-queued ACK frame is generated" begin
                e = _qga_end()
                receive_and_ack_10!(e, T)
                _qga_rx!(e, 11, T)
                @test _qga_ack_unqueued!(e, T) !== nothing
                _qga_rx!(e, 12, T)
                @test _qga_ack_out!(e, T) === nothing
                _qga_rx!(e, 13, T)
                @test _qga_ack_unqueued!(e, T) !== nothing
            end
            @testset "only sets the timer when receiving a ack-eliciting packets" begin
                e = _qga_end()
                receive_and_ack_10!(e, T)
                _qga_rx!(e, 11, T; ack_eliciting = false)
                @test !_qga_ack_queued(e, T)
                @test _qga_ack_alarm(e, T) == 0
                rcv = T + 10 * _QGA_MS
                _qga_rx!(e, 12, rcv)
                @test !_qga_ack_queued(e, rcv)
                @test _qga_ack_alarm(e, rcv) == rcv + 25 * _QGA_MS
            end
            @testset "queues an ACK if it was reported missing before" begin
                e = _qga_end()
                receive_and_ack_10!(e, T)
                _qga_rx!(e, 11, T)
                _qga_rx!(e, 13, T)
                ack = _qga_ack_out!(e, T)  # ACK: 1-11 and 13, missing: 12
                @test ack !== nothing
                @test _qga_has_missing(ack)
                @test !_qga_ack_queued(e, T)
                _qga_rx!(e, 12, T)
                @test _qga_ack_queued(e, T)
            end
            @testset "doesn't queue an ACK if for non-ack-eliciting packets arriving out-of-order" begin
                e = _qga_end()
                receive_and_ack_10!(e, T)
                _qga_rx!(e, 11, T)
                @test _qga_ack_out!(e, T) === nothing
                _qga_rx!(e, 13, T; ack_eliciting = false)  # receive a non-ack-eliciting packet out-of-order
                @test _qga_ack_out!(e, T) === nothing
            end
            @testset "doesn't queue an ACK if packets arrive out-of-order, but haven't been acknowledged yet" begin
                e = _qga_end()
                receive_and_ack_10!(e, T)
                _qga_rx!(e, 12, T; ack_eliciting = false)
                @test _qga_ack_out!(e, T) === nothing
                # 11 is received out-of-order, but this hasn't been reported in an ACK frame yet
                _qga_rx!(e, 11, T)
                @test _qga_ack_out!(e, T) === nothing
            end
        end

        @testset "raising the threshold" begin
            # quic-go's tracker.IgnoreBelow, as the receivedPacketHandler
            # applies it on the next packet: the space's ack_floor.
            @testset "doesn't recognize in-order packets as out-of-order after raising the threshold" begin
                e = _qga_end()
                receive_and_ack_10!(e, T)
                @test e.conn.spaces[3].last_ack_largest == 10
                @test !_qga_ack_queued(e, T)
                e.conn.spaces[3].ack_floor = 11
                _qga_rx!(e, 11, T)
                @test _qga_ack_out!(e, T) === nothing
            end
            @testset "recognizes out-of-order packets after raising the threshold" begin
                e = _qga_end()
                receive_and_ack_10!(e, T)
                @test e.conn.spaces[3].last_ack_largest == 10
                @test !_qga_ack_queued(e, T)
                e.conn.spaces[3].ack_floor = 11
                _qga_rx!(e, 12, T)
                ack = _qga_ack_out!(e, T)
                @test ack !== nothing
                @test ack.ranges == [12:12]
            end
            @testset "errors when called with an old packet" begin
                # quic-go's error is a duplicate here: dropped, not acknowledged.
                e = _qga_end()
                QGA._ignore_below!(e.conn.spaces[3].received, Int64(7))
                @test 4 in e.conn.spaces[3].received  # IsPotentiallyDuplicate(4)
                @test !_qga_rx!(e, 4, T)
                @test isempty(_qga_ranges(e))
                @test !e.conn.spaces[3].ack_pending
            end
        end

        @testset "ACK generation" begin
            @testset "generates an ACK for an ack-eliciting packet, if no ACK is queued yet" begin
                e = _qga_end()
                _qga_rx!(e, 1, T)
                # The first packet is always acknowledged.
                @test _qga_ack_out!(e, T) !== nothing
            end
            @testset "doesn't generate ACK for a non-ack-eliciting packet, if no ACK is queued yet" begin
                e = _qga_end()
                _qga_rx!(e, 1, T)
                # The first packet is always acknowledged.
                @test _qga_ack_out!(e, T) !== nothing
                _qga_rx!(e, 2, T; ack_eliciting = false)
                @test _qga_ack_unqueued!(e, T) === nothing
                _qga_rx!(e, 3, T)
                ack = _qga_ack_unqueued!(e, T)
                @test ack !== nothing
                @test _qga_lowest(ack) == 1
                @test _qga_largest(ack) == 3
            end

            @testset "for queued ACKs" begin
                @testset "generates a simple ACK frame" begin
                    e = _qga_end()
                    _qga_force_queued!(e)
                    _qga_rx!(e, 1, T)
                    _qga_rx!(e, 2, T)
                    ack = _qga_ack_out!(e, T)
                    @test ack !== nothing
                    @test _qga_largest(ack) == 2
                    @test _qga_lowest(ack) == 1
                    @test !_qga_has_missing(ack)
                end
                @testset "generates an ACK for packet number 0" begin
                    e = _qga_end()
                    _qga_force_queued!(e)
                    _qga_rx!(e, 0, T)
                    ack = _qga_ack_out!(e, T)
                    @test ack !== nothing
                    @test _qga_largest(ack) == 0
                    @test _qga_lowest(ack) == 0
                    @test !_qga_has_missing(ack)
                end
                @testset "sets the delay time" begin
                    e = _qga_end()
                    _qga_force_queued!(e)
                    _qga_rx!(e, 1, T)
                    _qga_rx!(e, 2, T - 1337 * _QGA_MS)
                    ack = _qga_ack_out!(e, T)
                    @test ack !== nothing
                    @test abs(ack.delay_ns - 1337 * _QGA_MS) <= 50 * _QGA_MS
                end
                @testset "uses a 0 delay time if the delay would be negative" begin
                    e = _qga_end()
                    _qga_force_queued!(e)
                    _qga_rx!(e, 0, T + _QGA_HOUR)
                    ack = _qga_ack_out!(e, T)
                    @test ack !== nothing
                    @test ack.delay_ns == 0
                end
                @testset "saves the last sent ACK" begin
                    e = _qga_end()
                    _qga_force_queued!(e)
                    _qga_rx!(e, 1, T)
                    ack = _qga_ack_out!(e, T)
                    @test ack !== nothing
                    @test ack.ranges == [1:1]
                    _qga_rx!(e, 2, T)
                    _qga_force_queued!(e)
                    ack = _qga_ack_out!(e, T)
                    @test ack !== nothing
                    @test ack.ranges == [1:2]
                end
                @testset "generates an ACK frame with missing packets" begin
                    e = _qga_end()
                    _qga_force_queued!(e)
                    _qga_rx!(e, 1, T)
                    _qga_rx!(e, 4, T)
                    ack = _qga_ack_out!(e, T)
                    @test ack !== nothing
                    @test _qga_largest(ack) == 4
                    @test _qga_lowest(ack) == 1
                    @test ack.ranges == [4:4, 1:1]
                end
                @testset "generates an ACK for packet number 0 and other packets" begin
                    e = _qga_end()
                    _qga_force_queued!(e)
                    _qga_rx!(e, 0, T)
                    _qga_rx!(e, 1, T)
                    _qga_rx!(e, 3, T)
                    ack = _qga_ack_out!(e, T)
                    @test ack !== nothing
                    @test _qga_largest(ack) == 3
                    @test _qga_lowest(ack) == 0
                    @test ack.ranges == [3:3, 0:1]
                end
                @testset "deletes packets from the packetHistory when a lower limit is set" begin
                    # IgnoreBelow(7) after 1..12: here, an ACK covering 1..6 is acknowledged first.
                    e = _qga_end()
                    _qga_force_queued!(e)
                    for i in 1:6
                        _qga_rx!(e, i, T)
                    end
                    _qga_ack_gets_acked!(e, T)
                    for i in 7:12
                        _qga_rx!(e, i, T)
                    end
                    _qga_force_queued!(e)
                    ack = _qga_ack_out!(e, T)
                    @test ack !== nothing
                    @test _qga_largest(ack) == 12
                    @test _qga_lowest(ack) == 7
                    @test !_qga_has_missing(ack)
                end
                @testset "resets all counters needed for the ACK queueing decision when sending an ACK" begin
                    e = _qga_end()
                    _qga_force_queued!(e)
                    _qga_rx!(e, 1, T)
                    e.conn.spaces[3].ack_deadline = T - _QGA_MIN
                    @test _qga_ack_out!(e, T) !== nothing
                    @test _qga_ack_alarm(e, T) == 0
                    @test e.conn.spaces[3].ack_eliciting_received == 0
                    @test !_qga_ack_queued(e, T)
                end
                @testset "doesn't generate an ACK when none is queued and the timer is not set" begin
                    e = _qga_end()
                    _qga_force_queued!(e)
                    _qga_rx!(e, 1, T)
                    e.conn.spaces[3].ack_deadline = typemax(Int64)
                    @test _qga_ack_out!(e, T) === nothing
                end
                @testset "doesn't generate an ACK when none is queued and the timer has not yet expired" begin
                    e = _qga_end()
                    _qga_force_queued!(e)
                    _qga_rx!(e, 1, T)
                    e.conn.spaces[3].ack_deadline = T + _QGA_MIN
                    @test _qga_ack_out!(e, T) === nothing
                end
                @testset "generates an ACK when the timer has expired" begin
                    e = _qga_end()
                    _qga_force_queued!(e)
                    _qga_rx!(e, 1, T)
                    e.conn.spaces[3].ack_deadline = T - _QGA_MIN
                    @test _qga_ack_out!(e, T) !== nothing
                end
            end
        end
    end

    # ------------------------------------------------------------------
    @testset "Received Packet Handler" begin
        @testset "generates ACKs for different packet number spaces" begin
            e = _qga_end()
            send_time = T - _QGA_SEC
            _qga_rx!(e, 1, 2, send_time)
            _qga_rx!(e, 2, 1, send_time)
            _qga_rx!(e, 3, 5, send_time)
            _qga_rx!(e, 1, 3, send_time)
            _qga_rx!(e, 2, 2, send_time)
            _qga_rx!(e, 3, 4, send_time)
            out = _qga_tx!(e, T)
            initial_ack = out.packets[1].ack
            @test initial_ack !== nothing
            @test initial_ack.ranges == [2:3]
            @test initial_ack.delay_ns == 0
            handshake_ack = out.packets[2].ack
            @test handshake_ack !== nothing
            @test handshake_ack.ranges == [1:2]
            @test handshake_ack.delay_ns == 0
            one_rtt_ack = out.packets[3].ack
            @test one_rtt_ack !== nothing
            @test one_rtt_ack.ranges == [4:5]
            @test abs(one_rtt_ack.delay_ns - _QGA_SEC) <= 50 * _QGA_MS
        end
        @testset "drops Initial packets" begin
            e = _qga_end()
            send_time = T - _QGA_SEC
            _qga_rx!(e, 1, 2, send_time)
            _qga_rx!(e, 2, 1, send_time)
            # Both ACKs go out together, coalesced.
            out = _qga_tx!(e, T)
            @test out.packets[1].ack !== nothing
            @test out.packets[2].ack !== nothing
            QGA._discard_space!(e.conn, 1)
            _qga_rx!(e, 1, 3, T)
            @test _qga_ack_out!(e, T, 1) === nothing
        end
        @testset "drops Handshake packets" begin
            e = _qga_end()
            send_time = T - _QGA_SEC
            _qga_rx!(e, 2, 1, send_time)
            _qga_rx!(e, 3, 2, send_time)
            out = _qga_tx!(e, T)
            @test out.packets[2].ack !== nothing
            @test out.packets[3].ack !== nothing
            QGA._discard_space!(e.conn, 2)
            _qga_rx!(e, 2, 2, T)
            @test _qga_ack_out!(e, T, 2) === nothing
        end
        @testset "drops old ACK ranges" begin
            # quic-go learns from the sent packet handler that ACKs below 2 were
            # acknowledged; here the peer acknowledges the packet carrying the ACK for 1-2.
            e = _qga_end()
            _qga_rx!(e, 1, T)
            _qga_rx!(e, 2, T)
            out = _qga_ack_gets_acked!(e, T)
            @test out !== nothing
            @test _qga_lowest(out) == 1
            @test _qga_largest(out) == 2
            _qga_rx!(e, 3, T)
            _qga_rx!(e, 4, T)
            ack = _qga_ack_out!(e, T)
            @test ack !== nothing
            @test _qga_lowest(ack) == 3
            @test _qga_largest(ack) == 4
        end
        @testset "says if packets are duplicates" begin
            e = _qga_end()
            isdup(idx, pn) = pn in e.conn.spaces[idx].received
            # Initial
            @test !isdup(1, 3)
            _qga_rx!(e, 1, 3, T)
            @test isdup(1, 3)
            # Handshake
            @test !isdup(2, 3)
            _qga_rx!(e, 2, 3, T)
            @test isdup(2, 3)
            # 1-RTT (quic-go's 0-RTT packet 3 shares this space; 0-RTT is not supported)
            @test !isdup(3, 4)
            _qga_rx!(e, 3, 4, T)
            @test isdup(3, 4)
        end
    end

    # ------------------------------------------------------------------
    @testset "SentPacketHistory" begin
        # Packets are sent for real; an ack-eliciting packet is a PING probe.
        send_eliciting!(e, now) = (e.conn.spaces[3].probes += 1; _qga_tx!(e, now).packets[3].pn)
        function send_ack_only!(e, now)
            s = e.conn.spaces[3]
            _qga_rx!(e, s.largest_received + 2, now)  # a gap: acknowledged at once
            p = _qga_tx!(e, now).packets[3]
            @test !p.ack_eliciting
            return p.pn
        end
        @testset "saves sent packets" begin
            e = _qga_end()
            @test [send_eliciting!(e, T) for _ in 1:3] == [0, 1, 2]
            @test _qga_history(e) == [0, 1, 2]
        end
        @testset "saves non-ack-eliciting packets" begin
            e = _qga_end()
            @test send_ack_only!(e, T) == 0
            @test send_eliciting!(e, T) == 1
            @test send_ack_only!(e, T) == 2
            @test send_eliciting!(e, T) == 3
            @test _qga_history(e) == [1, 3]
        end
        @testset "doesn't save non-ack-eliciting packets" begin
            e = _qga_end()
            e.conn.spaces[3].next_pn = 1
            @test send_eliciting!(e, T) == 1
            e.conn.spaces[3].next_pn = 3  # 2 is never sent
            @test send_ack_only!(e, T) == 3
            @test send_eliciting!(e, T) == 4
            @test _qga_history(e) == [1, 4]
        end
        @testset "gets the length" begin
            e = _qga_end()
            foreach(_ -> send_eliciting!(e, T), 1:3)
            @test length(e.conn.spaces[3].sent) == 3
        end
        @testset "getting the first outstanding packet" begin
            @testset "gets nil, if there are no packets" begin
                e = _qga_end()
                @test isempty(e.conn.spaces[3].sent)
            end
            @testset "gets the first outstanding packet" begin
                e = _qga_end()
                e.conn.spaces[3].next_pn = 2
                send_eliciting!(e, T)
                send_eliciting!(e, T)
                @test first(_qga_history(e)) == 2
                @test _qga_ack!(e, 3, [2:2], T) === nothing
                @test first(_qga_history(e)) == 3
            end
            @testset "doesn't regard path MTU packets as outstanding" begin
                e = _qga_end()
                e.conn.spaces[3].next_pn = 2
                send_eliciting!(e, T)
                e.conn.spaces[3].next_pn = 4  # 3 is never sent
                e.conn.pmtu_probe_size = 1300
                QGA._build_probe_datagram!(e.conn, T)
                @test e.conn.pmtu_probe_pn == 4
                @test first(_qga_history(e)) == 2
                @test _qga_history(e) == [2]
            end
        end
        @testset "removes packets" begin
            e = _qga_end()
            foreach(_ -> send_eliciting!(e, T), 0:3)
            @test _qga_ack!(e, 3, [2:2], T) === nothing
            @test _qga_history(e) == [0, 1, 3]
        end
        @testset "removes and adds packets" begin
            e = _qga_end()
            s = e.conn.spaces[3]
            send_eliciting!(e, T)
            send_eliciting!(e, T)
            s.next_pn = 4  # 2 and 3 are never sent
            send_eliciting!(e, T)
            s.next_pn = 6  # nor 5
            send_eliciting!(e, T)
            @test _qga_ack!(e, 3, [0:1], T) === nothing
            @test send_eliciting!(e, T) == 7
            @test _qga_history(e) == [4, 6, 7]
        end
        @testset "removes the last packet, then adds more" begin
            e = _qga_end()
            send_eliciting!(e, T)
            send_eliciting!(e, T)
            @test _qga_ack!(e, 3, [0:1], T) === nothing
            @test isempty(_qga_history(e))
            @test send_eliciting!(e, T) == 2
            @test _qga_history(e) == [2]
            @test _qga_ack!(e, 3, [2:2], T) === nothing
            @test isempty(_qga_history(e))
        end
        @testset "outstanding packets" begin
            outstanding(e) = !isempty(e.conn.spaces[3].sent)
            @testset "says if it has outstanding packets" begin
                e = _qga_end()
                @test !outstanding(e)
                send_eliciting!(e, T)
                @test outstanding(e)
            end
            @testset "accounts for deleted packets" begin
                e = _qga_end()
                e.conn.spaces[3].next_pn = 10
                send_eliciting!(e, T)
                @test outstanding(e)
                @test _qga_ack!(e, 3, [10:10], T) === nothing
                @test !outstanding(e)
            end
            @testset "counts the number of packets" begin
                e = _qga_end()
                e.conn.spaces[3].next_pn = 10
                send_eliciting!(e, T)
                send_eliciting!(e, T)
                @test _qga_ack!(e, 3, [11:11], T) === nothing
                @test outstanding(e)
                @test _qga_ack!(e, 3, [10:10], T) === nothing
                @test !outstanding(e)
            end
        end
    end

    # ------------------------------------------------------------------
    @testset "SentPacketHandler" begin
        @testset "registering sent packets" begin
            # Registered by real sends, as `handler.SentPacket` is by quic-go's packer.
            send_probe!(e, idx, now) = (e.conn.spaces[idx].probes += 1; _qga_tx!(e, now))
            @testset "accepts two consecutive packets" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                e.conn.spaces[2].next_pn = 1
                l1 = send_probe!(e, 2, T).len
                l2 = send_probe!(e, 2, T).len
                @test e.conn.spaces[2].next_pn - 1 == 2  # largest sent
                @test _qga_history(e, 2) == [1, 2]
                @test e.conn.bytes_in_flight == l1 + l2
            end
            @testset "accepts packet number 0" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                l0 = send_probe!(e, 3, T).len
                @test e.conn.spaces[3].next_pn - 1 == 0
                l1 = send_probe!(e, 3, T).len
                @test e.conn.spaces[3].next_pn - 1 == 1
                @test _qga_history(e) == [0, 1]
                @test e.conn.bytes_in_flight == l0 + l1
            end
            @testset "stores the sent time" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                send_time = T - _QGA_MIN
                send_probe!(e, 3, send_time)
                @test e.conn.spaces[3].time_of_last_ack_eliciting == send_time
            end
            @testset "stores the sent time of Initial packets" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                send_time = T - _QGA_MIN
                send_probe!(e, 1, send_time)
                send_probe!(e, 3, send_time + _QGA_HOUR)
                @test e.conn.spaces[1].time_of_last_ack_eliciting == send_time
            end
        end

        # JustBeforeEach of "ACK processing": packets 0..9, then an RTT of an hour.
        function ack_ctx()
            e = _qga_end(server = true)
            for i in 0:9
                _qga_sent!(e, 3, i; time = T)
            end
            # Increase RTT, because the tests would be flaky otherwise
            _qga_update_rtt!(e, _QGA_HOUR)
            @test e.conn.smoothed_rtt == _QGA_HOUR
            @test e.conn.bytes_in_flight == 10
            return e
        end

        @testset "ACK processing" begin
            @testset "ACK processing" begin
                @testset "accepts ACKs sent in packet 0" begin
                    e = ack_ctx()
                    @test _qga_ack!(e, 3, [0:5], T) === nothing
                    @test e.conn.spaces[3].largest_acked == 5
                end
                @testset "accepts multiple ACKs sent in the same packet" begin
                    e = ack_ctx()
                    @test _qga_ack!(e, 3, [0:3], T) === nothing
                    @test e.conn.spaces[3].largest_acked == 3
                    @test _qga_ack!(e, 3, [0:4], T) === nothing
                    @test e.conn.spaces[3].largest_acked == 4
                end
                @testset "rejects ACKs with a too high LargestAcked packet number" begin
                    e = ack_ctx()
                    err = _qga_ack!(e, 3, [0:9999], T)
                    @test err isa QGA._TransportError
                    @test err.code == QGA._PROTOCOL_VIOLATION
                    @test e.conn.bytes_in_flight == 10
                end
                @testset "ignores repeated ACKs" begin
                    e = ack_ctx()
                    @test _qga_ack!(e, 3, [0:3], T) === nothing
                    @test e.conn.bytes_in_flight == 6
                    @test _qga_ack!(e, 3, [0:3], T) === nothing
                    @test e.conn.spaces[3].largest_acked == 3
                    @test e.conn.bytes_in_flight == 6
                end
            end

            @testset "acks the right packets" begin
                @testset "adjusts the LargestAcked, and adjusts the bytes in flight" begin
                    e = ack_ctx()
                    @test _qga_ack!(e, 3, [0:5], T) === nothing
                    @test e.conn.spaces[3].largest_acked == 5
                    @test _qga_history_or_lost(e) == [6, 7, 8, 9]
                    @test e.conn.bytes_in_flight == 4
                end
                @testset "acks packet 0" begin
                    e = ack_ctx()
                    @test _qga_ack!(e, 3, [0:0], T) === nothing
                    @test !(0 in _qga_history(e))
                    @test _qga_history_or_lost(e) == collect(1:9)
                end
                @testset "calls the OnAcked callback" begin
                    e = ack_ctx()
                    _qga_sent!(e, 3, 10; time = T)
                    @test _qga_ack!(e, 3, [10:10], T) === nothing
                    @test 10 in e.conn.spaces[3].crypto_send.acked
                end
                @testset "handles an ACK frame with one missing packet range" begin
                    e = ack_ctx()
                    @test _qga_ack!(e, 3, [6:9, 1:3], T) === nothing  # lose 4 and 5
                    @test _qga_history_or_lost(e) == [0, 4, 5]
                end
                @testset "does not ack packets below the LowestAcked" begin
                    e = ack_ctx()
                    @test _qga_ack!(e, 3, [3:8], T) === nothing
                    @test _qga_history_or_lost(e) == [0, 1, 2, 9]
                end
                @testset "handles an ACK with multiple missing packet ranges" begin
                    e = ack_ctx()
                    # packets 2, 4 and 5, and 8 were lost
                    @test _qga_ack!(e, 3, [9:9, 6:7, 3:3, 1:1], T) === nothing
                    @test _qga_history_or_lost(e) == [0, 2, 4, 5, 8]
                end
                @testset "processes an ACK frame that would be sent after a late arrival of a packet" begin
                    e = ack_ctx()
                    @test _qga_ack!(e, 3, [6:6, 1:4], T) === nothing  # 5 lost
                    @test _qga_history_or_lost(e) == [0, 5, 7, 8, 9]
                    @test _qga_ack!(e, 3, [1:6], T) === nothing  # now ack 5
                    @test _qga_history_or_lost(e) == [0, 7, 8, 9]
                end
                @testset "processes an ACK that contains old ACK ranges" begin
                    e = ack_ctx()
                    @test _qga_ack!(e, 3, [1:6], T) === nothing
                    @test _qga_history_or_lost(e) == [0, 7, 8, 9]
                    @test _qga_ack!(e, 3, [8:8, 3:3, 1:1], T) === nothing
                    @test _qga_history_or_lost(e) == [0, 7, 9]
                end
            end

            @testset "determining which ACKs we have received an ACK for" begin
                # GetLowestPacketNotConfirmedAcked is the space's ack_floor.
                function more_packets()
                    e = ack_ctx()
                    _qga_sent!(e, 3, 10; time = T, ack_largest = 100)
                    _qga_sent!(e, 3, 11; time = T, ack_largest = 200)
                    _qga_sent!(e, 3, 12; time = T)
                    return e
                end
                @testset "determines which ACK we have received an ACK for" begin
                    e = more_packets()
                    @test _qga_ack!(e, 3, [10:12], T) === nothing
                    @test e.conn.spaces[3].ack_floor == 201
                end
                @testset "doesn't do anything when the acked packet didn't contain an ACK" begin
                    e = more_packets()
                    @test _qga_ack!(e, 3, [10:10], T) === nothing
                    @test e.conn.spaces[3].ack_floor == 101
                    @test _qga_ack!(e, 3, [12:12], T) === nothing
                    @test e.conn.spaces[3].ack_floor == 101
                end
                @testset "doesn't decrease the value" begin
                    e = more_packets()
                    @test _qga_ack!(e, 3, [11:11], T) === nothing
                    @test e.conn.spaces[3].ack_floor == 201
                    @test _qga_ack!(e, 3, [10:10], T) === nothing
                    @test e.conn.spaces[3].ack_floor == 201
                end
            end

            @testset "calculating RTT" begin
                @testset "computes the RTT" begin
                    e = ack_ctx()
                    # First, fake the sent times of the first, second and last packet
                    _qga_set_time!(e, 3, 1, T - 10 * _QGA_MIN)
                    _qga_set_time!(e, 3, 2, T - 5 * _QGA_MIN)
                    _qga_set_time!(e, 3, 6, T - 1 * _QGA_MIN)
                    # Now, check that the proper times are used when calculating the deltas
                    @test _qga_ack!(e, 3, [1:1], T) === nothing
                    @test abs(e.conn.latest_rtt - 10 * _QGA_MIN) <= _QGA_SEC
                    @test _qga_ack!(e, 3, [1:2], T) === nothing
                    @test abs(e.conn.latest_rtt - 5 * _QGA_MIN) <= _QGA_SEC
                    @test _qga_ack!(e, 3, [1:6], T) === nothing
                    @test abs(e.conn.latest_rtt - 1 * _QGA_MIN) <= _QGA_SEC
                end
                @testset "ignores the DelayTime for Initial and Handshake packets" begin
                    e = ack_ctx()
                    _qga_sent!(e, 1, 1; time = T)
                    _qga_set_max_ack_delay!(e, 3_600_000)
                    # make sure the rttStats have a min RTT, so that the delay is used
                    QGA._update_rtt!(e.conn, 5 * _QGA_MIN, Int64(0))
                    _qga_set_time!(e, 1, 1, T - 10 * _QGA_MIN)
                    s0 = e.conn.smoothed_rtt
                    @test _qga_ack!(e, 1, [1:1], T; delay_ns = 5 * _QGA_MIN) === nothing
                    @test abs(e.conn.latest_rtt - 10 * _QGA_MIN) <= _QGA_SEC
                    # the sample was not reduced by the delay
                    @test e.conn.smoothed_rtt == (7 * s0 + 10 * _QGA_MIN) ÷ 8
                end
                @testset "uses the DelayTime in the ACK frame" begin
                    e = ack_ctx()
                    _qga_set_max_ack_delay!(e, 3_600_000)
                    # make sure the rttStats have a min RTT, so that the delay is used
                    QGA._update_rtt!(e.conn, 5 * _QGA_MIN, Int64(0))
                    _qga_set_time!(e, 3, 1, T - 10 * _QGA_MIN)
                    s0 = e.conn.smoothed_rtt
                    @test _qga_ack!(e, 3, [1:1], T; delay_ns = 5 * _QGA_MIN) === nothing
                    # quic-go's (adjusted) LatestRTT is 5 minutes
                    @test e.conn.smoothed_rtt == (7 * s0 + 5 * _QGA_MIN) ÷ 8
                end
                @testset "limits the DelayTime in the ACK frame to max_ack_delay" begin
                    for confirmed in (false, true)
                        e = ack_ctx()
                        e.conn.handshake_confirmed = confirmed
                        _qga_set_max_ack_delay!(e, 60_000)
                        # make sure the rttStats have a min RTT, so that the delay is used
                        QGA._update_rtt!(e.conn, 5 * _QGA_MIN, Int64(0))
                        _qga_set_time!(e, 3, 1, T - 10 * _QGA_MIN)
                        s0 = e.conn.smoothed_rtt
                        @test _qga_ack!(e, 3, [1:1], T; delay_ns = 5 * _QGA_MIN) === nothing
                        # quic-go's (adjusted) LatestRTT is 9 minutes, with or
                        # without handshake confirmation
                        @test e.conn.smoothed_rtt == (7 * s0 + 9 * _QGA_MIN) ÷ 8
                    end
                end
            end
        end

        @testset "congestion" begin
            @testset "should call OnSent" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                e.conn.spaces[3].next_pn = 1
                e.conn.spaces[3].probes = 1
                out = _qga_tx!(e, T)
                @test out.packets[3].pn == 1
                @test e.conn.bytes_in_flight == out.len
            end
            @testset "should call MaybeExitSlowStart and OnPacketAcked" begin
                e = _qga_end(server = true)
                rcv = T - 5 * _QGA_SEC
                cwnd = e.conn.cwnd
                for pn in 1:3
                    _qga_sent!(e, 3, pn; time = T)
                end
                @test _qga_ack!(e, 3, [1:2], rcv) === nothing
                @test e.conn.bytes_in_flight == 1
                @test e.conn.packets_lost == 0
                # not window-limited (RFC 9002 §7.8), so no growth
                @test e.conn.cwnd == cwnd
            end
            @testset "doesn't call OnPacketAcked when a retransmitted packet is acked" begin
                e = _qga_end(server = true)
                cwnd = e.conn.cwnd
                _qga_sent!(e, 3, 1; time = T - _QGA_HOUR)
                _qga_sent!(e, 3, 2; time = T)
                # lose packet 1
                @test _qga_ack!(e, 3, [2:2], T) === nothing
                @test e.conn.packets_lost == 1
                @test _qga_lost(e) == [1]
                reduced = e.conn.cwnd
                @test reduced == round(Int, 0.7 * cwnd)
                @test e.conn.bytes_in_flight == 0
                # no further congestion controller events
                @test _qga_ack!(e, 3, [1:2], T) === nothing
                @test e.conn.cwnd == reduced
                @test e.conn.bytes_in_flight == 0
                @test e.conn.packets_lost == 1
            end
            @testset "doesn't call OnCongestionEvent when a Path MTU probe packet is lost" begin
                e = _qga_end(server = true)
                cwnd = e.conn.cwnd
                e.conn.pmtu_probe_size = 1300
                e.conn.pmtu_probe_pn = 1
                e.conn.pmtu_probe_time = T - _QGA_HOUR
                e.conn.spaces[3].next_pn = 2
                _qga_sent!(e, 3, 2; time = T)
                # lose packet 1, without a congestion event
                @test _qga_ack!(e, 3, [2:2], T) === nothing
                @test e.conn.pmtu_probe_pn == -1  # declared lost
                @test e.conn.pmtu_failures == 1
                @test e.conn.cwnd == cwnd
                @test e.conn.packets_lost == 0
                @test e.conn.bytes_in_flight == 0
            end
            @testset "calls OnPacketAcked and OnCongestionEvent with the right bytes_in_flight value" begin
                e = _qga_end(server = true)
                cwnd = e.conn.cwnd
                _qga_sent!(e, 3, 1; time = T - _QGA_HOUR)
                _qga_sent!(e, 3, 2; time = T - 30 * _QGA_MIN)
                _qga_sent!(e, 3, 3; time = T - 30 * _QGA_MIN)
                _qga_sent!(e, 3, 4; time = T)
                @test e.conn.bytes_in_flight == 4
                # receive the first ACK: 1 is lost, 2 acknowledged
                @test _qga_ack!(e, 3, [2:2], T - 30 * _QGA_MIN) === nothing
                @test _qga_lost(e) == [1]
                @test e.conn.bytes_in_flight == 2
                @test e.conn.cwnd == round(Int, 0.7 * cwnd)
                # receive the second ACK: 3 is lost, 4 acknowledged
                @test _qga_ack!(e, 3, [4:4], T) === nothing
                @test _qga_lost(e) == [1, 3]
                @test e.conn.bytes_in_flight == 0
                # 3 was sent before the recovery period began: no second reduction
                @test e.conn.cwnd == round(Int, 0.7 * cwnd)
            end
            @testset "passes the bytes in flight to the congestion controller" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                _qga_sent!(e, 1, 0; time = T, size = 42)
                @test e.conn.bytes_in_flight == 42
                @test QGA._cwnd_allows(e.conn)
            end
            @testset "allows sending of ACKs when congestion limited" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                @test QGA._cwnd_allows(e.conn)
                @test _qga_pto_mode(e) == 0
                # Fill the window, with data waiting and an ACK due.
                e.conn.bytes_in_flight = e.conn.cwnd
                @test !QGA._cwnd_allows(e.conn)
                QGA._crypto_queue!(e.conn.spaces[3].crypto_send, zeros(UInt8, 10))
                _qga_rx!(e, 1, T)
                out = _qga_tx!(e, T)
                @test out !== nothing
                p = out.packets[3]
                @test p.ack !== nothing
                @test !p.ack_eliciting
                @test QGA._CryptoFrame ∉ p.frame_types
            end
            @testset "allows PTOs, even when congestion limited" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                e.conn.bytes_in_flight = e.conn.cwnd
                e.conn.spaces[2].probes = 1
                @test _qga_pto_mode(e) == 2
                out = _qga_tx!(e, T)
                @test out !== nothing
                @test out.packets[2].ack_eliciting
            end
        end

        @testset "doesn't set an alarm if there are no outstanding packets" begin
            e = _qga_end(server = true)
            e.conn.address_validated = true
            _qga_sent!(e, 3, 10; time = T)
            _qga_sent!(e, 3, 11; time = T)
            @test _qga_ack!(e, 3, [10:11], T) === nothing
            @test _qga_timer(e) === nothing
        end
        @testset "does nothing on OnAlarm if there are no outstanding packets" begin
            e = _qga_end(server = true)
            e.conn.address_validated = true
            _qga_fire!(e, T)
            @test _qga_pto_mode(e) == 0
        end

        @testset "probe packets" begin
            @testset "queues a probe packet" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                _qga_confirm!(e)
                _qga_sent!(e, 3, 10; time = T)
                _qga_sent!(e, 3, 11; time = T)
                _qga_fire!(e, T)
                @test _qga_pto_mode(e) == 3
                # The oldest packet's data goes out again first (Reseau
                # resends two packets' worth for its two probes).
                lost = _qga_lost(e)
                @test !isempty(lost) && first(lost) == 10
                # A timeout is not a loss (RFC 9002 Section 6.2): both stay in flight.
                @test _qga_history(e) == [10, 11]
                @test e.conn.bytes_in_flight == 2
            end
            @testset "says when it can't queue a probe packet" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                _qga_confirm!(e)
                _qga_fire!(e, T)
                @test _qga_pto_mode(e) == 0
                @test isempty(_qga_lost(e))
            end
            @testset "implements exponential backoff" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                _qga_confirm!(e)
                send_time = T - _QGA_HOUR
                _qga_sent!(e, 3, 1; time = send_time)
                timeout = _qga_timer(e) - send_time
                @test _qga_timer(e) - send_time == timeout
                e.conn.pto_count = 1
                @test _qga_timer(e) - send_time == 2 * timeout
                e.conn.pto_count = 2
                @test _qga_timer(e) - send_time == 4 * timeout
                # truncated when the exponential gets too large
                e.conn.pto_count = 20
                @test _qga_timer(e) - send_time == 60 * _QGA_SEC
                # protected from rollover
                e.conn.pto_count = 100
                @test _qga_timer(e) - send_time == 60 * _QGA_SEC
                @test _qga_timer(e) - send_time > 0
            end
            @testset "reset the PTO count when receiving an ACK" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                _qga_confirm!(e)
                _qga_sent!(e, 3, 1; time = T - _QGA_MIN)
                _qga_sent!(e, 3, 2; time = T - _QGA_MIN)
                e.conn.spaces[3].next_pn = 3
                @test abs(_qga_timer(e) - (T - _QGA_MIN)) <= _QGA_SEC
                _qga_fire!(e, T)
                @test _qga_pto_mode(e) == 3
                @test e.conn.pto_count == 1
                @test _qga_ack!(e, 3, [1:1], T) === nothing
                @test e.conn.pto_count == 0
            end
            @testset "resets the PTO mode and PTO count when a packet number space is dropped" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                _qga_update_rtt!(e, _QGA_SEC ÷ 2)
                @test e.conn.smoothed_rtt == _QGA_SEC ÷ 2
                pto_app = QGA._pto_duration(e.conn, 3)
                @test _QGA_SEC < pto_app < 2 * _QGA_SEC
                send_time_handshake = T - 2 * _QGA_MIN
                send_time_app = T - _QGA_MIN
                _qga_sent!(e, 2, 1; time = send_time_handshake)
                _qga_sent!(e, 3, 2; time = send_time_app)
                # PTO timer based on the Handshake packet
                _qga_fire!(e, T)
                @test e.conn.pto_count == 1
                @test _qga_pto_mode(e) == 2
                @test _qga_timer(e) == send_time_handshake + QGA._pto_duration(e.conn, 2)  # already backed off once
                _qga_confirm!(e)
                # PTO timer based on the 1-RTT packet
                @test _qga_timer(e) == send_time_app + QGA._pto_duration(e.conn, 3)  # no backoff. PTO count = 0
                @test _qga_pto_mode(e) != 2
                @test e.conn.pto_count == 0
            end
            @testset "allows two 1-RTT PTOs" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                _qga_confirm!(e)
                _qga_sent!(e, 3, 0; time = T - _QGA_HOUR)
                _qga_fire!(e, T)
                @test _qga_pto_mode(e) == 3
                @test _qga_tx!(e, T).packets[3].ack_eliciting
                @test _qga_pto_mode(e) == 3
                @test _qga_tx!(e, T).packets[3].ack_eliciting
                @test _qga_pto_mode(e) != 3
            end
            @testset "only counts ack-eliciting packets as probe packets" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                _qga_confirm!(e)
                _qga_sent!(e, 3, 0; time = T - _QGA_HOUR)
                _qga_fire!(e, T)
                @test _qga_pto_mode(e) == 3
                @test _qga_tx!(e, T).packets[3].ack_eliciting
                @test _qga_pto_mode(e) == 3
                # An ACK sent while a probe is owed goes out in the probe,
                # which is ack-eliciting: Reseau never sends an ACK-only packet
                # that could use up a probe.
                _qga_rx!(e, 2, T)
                p = _qga_tx!(e, T).packets[3]
                @test p.ack !== nothing
                @test p.ack_eliciting
                @test p.pn in _qga_history(e)
                @test _qga_pto_mode(e) == 0
            end
            @testset "gets two probe packets if PTO expires" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                _qga_confirm!(e)
                _qga_sent!(e, 3, 0; time = T)
                _qga_sent!(e, 3, 1; time = T)
                _qga_update_rtt!(e, _QGA_HOUR)
                @test e.conn.smoothed_rtt == _QGA_HOUR
                # no loss timer, only the PTO
                @test _qga_timer(e) == QGA._pto_deadline(e.conn)[1]

                now = _qga_timer(e)
                _qga_fire!(e, now)  # TLP
                @test e.conn.pto_count == 1
                @test _qga_pto_mode(e) == 3
                @test _qga_tx!(e, now).packets[3].ack_eliciting
                @test _qga_pto_mode(e) == 3
                @test _qga_tx!(e, now).packets[3].ack_eliciting

                now = _qga_timer(e)
                _qga_fire!(e, now)  # PTO
                @test e.conn.pto_count == 2
                @test _qga_pto_mode(e) == 3
                @test _qga_tx!(e, now).packets[3].ack_eliciting
                @test _qga_pto_mode(e) == 3
                @test _qga_tx!(e, now).packets[3].ack_eliciting

                @test _qga_pto_mode(e) == 0
            end
            @testset "gets two probe packets if PTO expires, for Handshake packets" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                _qga_sent!(e, 1, 1; time = T)
                _qga_sent!(e, 1, 2; time = T)
                _qga_update_rtt!(e, _QGA_HOUR)
                @test _qga_timer(e) == QGA._pto_deadline(e.conn)[1]

                now = _qga_timer(e)
                _qga_fire!(e, now)
                @test _qga_pto_mode(e) == 1
                _qga_tx!(e, now)
                @test _qga_pto_mode(e) == 1
                _qga_tx!(e, now)

                @test _qga_pto_mode(e) == 0
            end
            @testset "doesn't send 1-RTT probe packets before the handshake completes" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                _qga_sent!(e, 3, 0; time = T)
                _qga_update_rtt!(e, _QGA_HOUR)
                _qga_fire!(e, T)
                @test _qga_timer(e) === nothing
                @test _qga_pto_mode(e) == 0
                _qga_confirm!(e)
                @test _qga_timer(e) !== nothing
                _qga_fire!(e, T)
                @test _qga_pto_mode(e) == 3
            end
            @testset "resets the send mode when it receives an acknowledgement after queueing probe packets" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                _qga_confirm!(e)
                _qga_sent!(e, 3, 0; time = T - _QGA_HOUR)
                _qga_update_rtt!(e, _QGA_SEC)
                _qga_fire!(e, T)
                @test _qga_pto_mode(e) == 3
                @test _qga_ack!(e, 3, [0:0], T) === nothing
                @test _qga_pto_mode(e) == 0
            end
            @testset "handles ACKs for the original packet" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                _qga_sent!(e, 3, 0; time = T - _QGA_HOUR)
                _qga_update_rtt!(e, _QGA_SEC)
                _qga_fire!(e, T)
                _qga_fire!(e, T)
                @test e.conn.state != QGA._ConnState.Closed
                @test e.conn.error === nothing
            end
            @testset "doesn't set the PTO timer for Path MTU probe packets" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                _qga_confirm!(e)
                _qga_update_rtt!(e, _QGA_SEC)
                e.conn.spaces[3].next_pn = 5
                e.conn.pmtu_probe_size = 1300
                QGA._build_probe_datagram!(e.conn, T)
                @test e.conn.pmtu_probe_pn == 5
                @test QGA._pto_deadline(e.conn) === nothing
            end
        end

        @testset "amplification limit, for the server" begin
            @testset "limits the window to 3x the bytes received, to avoid amplification attacks" begin
                e = _qga_end(server = true)
                # receiving an Initial packet doesn't validate the client's address
                e.conn.bytes_received = 200
                _qga_sent!(e, 1, 1; time = T, size = 599)
                @test QGA._send_budget(e.conn) > 0
                _qga_sent!(e, 1, 2; time = T, size = 1)
                @test QGA._send_budget(e.conn) <= 0
                e.conn.spaces[1].probes = 1
                @test QGA._next_datagram!(e.conn, T) === nothing
            end
            @testset "cancels the loss detection timer when it is amplification limited, and resets it when becoming unblocked" begin
                e = _qga_end(server = true)
                e.conn.bytes_received = 300
                _qga_sent!(e, 1, 1; time = T, size = 900)
                # Amplification limited. We don't need to set a timer now.
                @test _qga_timer(e) === nothing
                # Unblock the server. Now we should fire up the timer.
                e.conn.bytes_received = 301
                @test _qga_timer(e) !== nothing
            end
            @testset "resets the loss detection timer when the client's address is validated" begin
                e = _qga_end(server = true)
                e.conn.bytes_received = 300
                _qga_sent!(e, 2, 1; time = T, size = 900)
                # Amplification limited. We don't need to set a timer now.
                @test _qga_timer(e) === nothing
                e.conn.address_validated = true
                @test _qga_timer(e) !== nothing
            end
            @testset "cancels the loss detection alarm when all Handshake packets are acknowledged" begin
                e = _qga_end(server = true)
                t = T - _QGA_SEC
                e.conn.bytes_received = 99999
                _qga_sent!(e, 3, 2; time = t)
                _qga_sent!(e, 2, 3; time = t)
                _qga_sent!(e, 2, 4; time = t)
                @test _qga_timer(e) !== nothing
                @test _qga_ack!(e, 2, [3:4], T) === nothing
                @test _qga_timer(e) === nothing
            end
        end

        @testset "amplification limit, for the server, with validated address" begin
            @testset "do not limits the window" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                e.conn.bytes_received = 0
                @test QGA._send_budget(e.conn) > 0
                _qga_sent!(e, 1, 1; time = T, size = 900)
                @test QGA._send_budget(e.conn) > 0
            end
        end

        @testset "amplification limit, for the client" begin
            @testset "sends an Initial packet to unblock the server" begin
                e = _qga_end(handshake_keys = false)
                _qga_sent!(e, 1, 1; time = T)
                @test _qga_ack!(e, 1, [1:1], T) === nothing
                # No packets are outstanding at this point.
                # Make sure that a probe packet is sent.
                @test _qga_timer(e) !== nothing
                now = _qga_timer(e)
                _qga_fire!(e, now)
                @test _qga_pto_mode(e) == 1
                # send a single packet to unblock the server
                @test _qga_tx!(e, now).packets[1].ack_eliciting
                @test _qga_pto_mode(e) == 0
                # Now receive an ACK for a Handshake packet.
                # This tells the client that the server completed address validation.
                _qga_install_handshake_keys!(e)
                _qga_sent!(e, 2, 1; time = now)
                QGA._discard_space!(e.conn, 1)  # sending a Handshake packet drops the Initial packet number space
                @test _qga_ack!(e, 2, [1:1], now) === nothing
                # Make sure that no timer is set at this point.
                @test _qga_timer(e) === nothing
            end
            @testset "sends a Handshake packet to unblock the server, if Initial keys were already dropped" begin
                e = _qga_end(handshake_keys = false)
                _qga_sent!(e, 1, 1; time = T)
                @test _qga_ack!(e, 1, [1:1], T) === nothing
                _qga_install_handshake_keys!(e)
                _qga_sent!(e, 2, 1; time = T, ack_eliciting = false)
                QGA._discard_space!(e.conn, 1)  # sending a Handshake packet drops the Initial packet number space
                @test _qga_timer(e) !== nothing
                now = _qga_timer(e)
                _qga_fire!(e, now)
                @test _qga_pto_mode(e) == 2
                # Now receive an ACK for this packet, and send another one.
                @test _qga_ack!(e, 2, [1:1], now) === nothing
                _qga_sent!(e, 2, 2; time = now, ack_eliciting = false)
                @test _qga_timer(e) === nothing
            end
            @testset "doesn't send a packet to unblock the server after handshake confirmation, even if no Handshake ACK was received" begin
                e = _qga_end()
                _qga_sent!(e, 2, 1; time = T)
                QGA._discard_space!(e.conn, 1)  # a client drops Initial keys once it sends a Handshake packet
                @test _qga_timer(e) !== nothing
                _qga_fire!(e, T)
                @test _qga_pto_mode(e) == 2
                # confirm the handshake
                QGA._discard_space!(e.conn, 2)
                e.conn.handshake_confirmed = true
                @test _qga_timer(e) === nothing
            end
            @testset "correctly sets the timer after the Initial packet number space has been dropped" begin
                e = _qga_end(handshake_keys = false)
                _qga_sent!(e, 1, 1; time = T - 19 * _QGA_SEC)
                @test _qga_ack!(e, 1, [1:1], T) === nothing
                _qga_install_handshake_keys!(e)
                _qga_sent!(e, 2, 1; time = T, ack_eliciting = false)
                QGA._discard_space!(e.conn, 1)  # sending a Handshake packet drops the Initial packet number space
                pto = QGA._pto_duration(e.conn, 2)
                @test pto > 0
                @test abs(_qga_timer(e) - (T + pto)) <= 10 * _QGA_MS
            end
            @testset "doesn't reset the PTO count when receiving an ACK" begin
                e = _qga_end(handshake_keys = false)
                _qga_sent!(e, 1, 1; time = T - _QGA_MIN)
                _qga_sent!(e, 1, 2; time = T - _QGA_MIN)
                @test abs(_qga_timer(e) - (T - _QGA_MIN)) <= _QGA_SEC
                _qga_fire!(e, T)
                @test _qga_pto_mode(e) == 1
                @test e.conn.pto_count == 1
                @test _qga_ack!(e, 1, [1:1], T) === nothing
                @test e.conn.pto_count == 1
            end
        end

        @testset "Packet-based loss detection" begin
            @testset "declares packet below the packet loss threshold as lost" begin
                e = _qga_end(server = true)
                for i in 1:6
                    _qga_sent!(e, 3, i; time = T)
                end
                @test _qga_ack!(e, 3, [6:6], T) === nothing
                @test _qga_history(e) == [4, 5]
                @test _qga_lost(e) == [1, 2, 3]
            end
        end

        @testset "Delay-based loss detection" begin
            @testset "immediately detects old packets as lost when receiving an ACK" begin
                e = _qga_end(server = true)
                _qga_sent!(e, 3, 1; time = T - _QGA_HOUR)
                _qga_sent!(e, 3, 2; time = T - _QGA_SEC)
                @test _qga_ack!(e, 3, [2:2], T) === nothing
                # no need to set an alarm, since packet 1 was already declared lost
                @test _qga_lost(e) == [1]
                @test isempty(_qga_history(e))
                @test _qga_timer(e) === nothing
                @test e.conn.bytes_in_flight == 0
            end
            @testset "sets the early retransmit alarm" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                _qga_confirm!(e)
                _qga_sent!(e, 3, 1; time = T - 2 * _QGA_SEC)
                _qga_sent!(e, 3, 2; time = T - 2 * _QGA_SEC)
                _qga_sent!(e, 3, 3; time = T)
                @test _qga_ack!(e, 3, [2:2], T - _QGA_SEC) === nothing
                @test e.conn.smoothed_rtt == _QGA_SEC
                # Packet 1 should be considered lost (1+1/8) RTTs after it was sent.
                loss_time = T - 2 * _QGA_SEC + 9 * _QGA_SEC ÷ 8
                @test _qga_timer(e) == loss_time
                @test _qga_pto_mode(e) == 0
                @test _qga_history(e) == [1, 3]
                QGA._handle_timeout!(e.conn, loss_time)
                @test _qga_history(e) == [3]
                @test _qga_pto_mode(e) == 0
            end
            @testset "sets the early retransmit alarm for crypto packets" begin
                e = _qga_end(server = true)
                e.conn.bytes_received = 1000
                _qga_sent!(e, 1, 1; time = T - 2 * _QGA_SEC)
                _qga_sent!(e, 1, 2; time = T - 2 * _QGA_SEC)
                _qga_sent!(e, 1, 3; time = T)
                @test _qga_ack!(e, 1, [2:2], T - _QGA_SEC) === nothing
                @test e.conn.smoothed_rtt == _QGA_SEC
                # Packet 1 should be considered lost (1+1/8) RTTs after it was sent.
                loss_time = T - 2 * _QGA_SEC + 9 * _QGA_SEC ÷ 8
                @test _qga_timer(e) == loss_time
                @test _qga_pto_mode(e) == 0
                @test _qga_history(e, 1) == [1, 3]
                QGA._handle_timeout!(e.conn, loss_time)
                @test _qga_history(e, 1) == [3]
                @test _qga_pto_mode(e) == 0
            end
            @testset "sets the early retransmit alarm for Path MTU probe packets" begin
                e = _qga_end(server = true)
                e.conn.pmtu_probe_size = 1300
                e.conn.pmtu_probe_pn = 1
                e.conn.pmtu_probe_time = T - 3 * _QGA_SEC
                e.conn.spaces[3].next_pn = 2
                _qga_sent!(e, 3, 2; time = T - 3 * _QGA_SEC)
                @test _qga_ack!(e, 3, [2:2], T - _QGA_SEC) === nothing
                @test e.conn.pmtu_probe_pn == 1  # not yet declared lost
                @test _qga_timer(e) !== nothing
                _qga_fire!(e, T - _QGA_SEC)
                @test e.conn.pmtu_probe_pn == -1  # declared lost
                @test e.conn.pmtu_failures == 1
                @test _qga_timer(e) === nothing
            end
        end

        @testset "crypto packets" begin
            @testset "rejects an ACK that acks packets with a higher encryption level" begin
                e = _qga_end(server = true)
                _qga_sent!(e, 3, 13; time = T)
                err = _qga_ack!(e, 2, [13:13], T)
                @test err isa QGA._TransportError
                @test err.code == QGA._PROTOCOL_VIOLATION
            end
            @testset "deletes Initial packets, as a server" begin
                e = _qga_end(server = true)
                for i in 0:5
                    _qga_sent!(e, 1, i; time = T)
                end
                for i in 0:9
                    _qga_sent!(e, 2, i; time = T)
                end
                @test e.conn.bytes_in_flight == 16
                QGA._discard_space!(e.conn, 1)
                @test isempty(_qga_lost(e, 1))  # frames must not be queued for retransmission
                @test e.conn.bytes_in_flight == 10
                @test e.conn.spaces[1].discarded
                @test isempty(e.conn.spaces[1].sent)
                @test !isempty(e.conn.spaces[2].sent)
            end
            @testset "deletes Handshake packets" begin
                e = _qga_end(server = true)
                for i in 0:5
                    _qga_sent!(e, 2, i; time = T)
                end
                for i in 0:9
                    _qga_sent!(e, 3, i; time = T)
                end
                @test e.conn.bytes_in_flight == 16
                QGA._discard_space!(e.conn, 2)
                @test isempty(_qga_lost(e, 2))  # frames must not be queued for retransmission
                @test e.conn.bytes_in_flight == 10
                @test e.conn.spaces[2].discarded
                @test isempty(e.conn.spaces[2].sent)
            end
            @testset "cancels the PTO when dropping a packet number space" begin
                e = _qga_end(server = true)
                e.conn.address_validated = true
                _qga_sent!(e, 2, 1; time = T - _QGA_MIN)
                _qga_sent!(e, 2, 2; time = T - _QGA_MIN)
                @test abs(_qga_timer(e) - (T - _QGA_MIN)) <= _QGA_SEC
                _qga_fire!(e, T)
                @test _qga_pto_mode(e) == 2
                @test e.conn.pto_count == 1
                QGA._discard_space!(e.conn, 2)
                @test e.conn.pto_count == 0
                @test _qga_pto_mode(e) == 0
            end
        end

        @testset "peeking and popping packet number" begin
            @testset "starts at 0 for handshake and application-data packet number space" begin
                e = _qga_end()
                @test e.conn.spaces[2].next_pn == 0
                @test e.conn.spaces[3].next_pn == 0
            end
        end

        @testset "for the client" begin
            @testset "considers the server's address validated right away" begin
                e = _qga_end()
                @test QGA._send_budget(e.conn) == typemax(Int)
            end
        end
    end
end
