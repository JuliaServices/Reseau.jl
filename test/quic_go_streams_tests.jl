# Ported from quic-go v0.48.2 (github.com/quic-go/quic-go@v0.48.2), the
# stream-level tests of the top-level package:
#   frame_sorter_test.go, receive_stream_test.go, send_stream_test.go,
#   stream_test.go, streams_map_test.go, streams_map_incoming_test.go,
#   streams_map_outgoing_test.go, crypto_stream_test.go,
#   crypto_stream_manager_test.go, retransmission_queue_test.go,
#   framer_test.go, mtu_discoverer_test.go.
#
# quic-go splits these jobs into separate objects tested with mocks. Here each
# `It` is ported to whatever tests the same observable behavior most directly:
# the buffers (`_Reassembly`, `_StreamSendBuffer`, `_CryptoSendBuffer`), a
# `_Connection` driven through the in-memory harness (frames are injected with
# `_qcn_inject!` and what a side sends is decrypted with its peer's keys), or
# the public `Reseau.QUIC.Stream` API over loopback UDP for blocking reads,
# writes, deadlines and accepts. Testset names are quic-go's Describe/Context/It
# text. Where our behavior differs from quic-go's on purpose, a `# Differs
# from quic-go:` note says why and the test asserts ours; otherwise the
# assertion of quic-go's behavior is kept as `@test_broken` with a `# BUG?:`
# note.
#
# Adaptations:
# - Stream IDs: quic-go's unit tests use stream 1337 in isolation; here a
#   receive-only stream is the client's unidirectional stream 2 as seen by the
#   server, and a send-only stream is the client's own unidirectional stream 2.
# - popStreamFrame(size) takes a frame size; quic-go's header length for stream
#   1337 is subtracted to get the data budget (`_qgs_go_data_len`), since our
#   packer reserves a worst-case header (8-byte offset, 2-byte length).
# - Frame-sorter "queues" are compared as byte coverage (data is a function of
#   the offset), since which overlapping frame keeps the bytes is internal.
# - Our CRYPTO buffer limit is `_CRYPTO_BUFFER_LIMIT` past the delivered
#   offset (quic-go: 16 KiB absolute); our PATH_RESPONSE queue holds
#   `_MAX_PATH_RESPONSES` (quic-go: 256); our smallest datagram is 1200 bytes
#   (the MTU tests start there instead of at 1000).
# - Assertions purely about mock call order or Go-only API (Context(),
#   net.Error methods, (n, err) partial-write counts) are skipped.
#
# Not applicable (deliberate omissions or Go API helpers):
# - streams_map: "applies parameters to existing streams (needed for 0-RTT)",
#   "resets for 0-RTT" (no 0-RTT); the four "errors when deleting unknown ...
#   streams" (DeleteStream is an internal Go helper with no equivalent).
# - streams_map_outgoing: "errors when deleting a non-existing stream", "errors
#   when deleting a stream twice" (same), "updates the send window" (0-RTT
#   transport parameter update).
# - streams_map_incoming: "errors when deleting a non-existing stream".
# - send_stream: "cancels the context when Close is called", "cancels the
#   context" (Go context.Context); "returns the number of bytes written, when
#   the deadline expires" (Go's (n, err) partial write).
# - receive_stream: "the deadline error has the right net.Error properties"
#   and stream_test "Deadline Error is a net.Error" (Go error interfaces).
# - framer: "drops *_BLOCKED frames when 0-RTT is rejected", "drops all STREAM
#   frames when 0-RTT is rejected" (no 0-RTT); "detects when too many frames
#   are queued" (our control frames are per-stream flags and a bounded
#   PATH_RESPONSE queue, so there is no unbounded queue to detect).
# - retransmission_queue: the Initial and Handshake "queues and retrieves a
#   control frame", "returns other frames when a CRYPTO frame wouldn't fit",
#   "retrieves both a CRYPTO frame and a control frame" and "retransmits a
#   frame" (they queue MAX_DATA/PING as generic control frames in Initial and
#   Handshake packets; ours carry only CRYPTO, ACK and probe PINGs there).
# - crypto_stream: "rejects new crypto data after finishing" (a level's keys
#   are dropped when it finishes, so its packets can no longer be opened).

using Test
using Reseau
using Random

@isdefined(_QcnHarness) || include("quic_harness.jl")

const QGS = Reseau.QUIC
const UDGS = Reseau.UDP

# quic-go's protocol.MaxByteCount, for "no upper end" in frame-sorter gaps.
const _QGS_MAX = typemax(Int64)
# quic-go's protocol.MinStreamFrameSize and MaxPacketBufferSize.
const _QGS_MIN_STREAM_FRAME = 128
const _QGS_MAX_PACKET_BUFFER = 1452

_qgs_vl(x) = QGS._varint_length(UInt64(x))

# ---------------------------------------------------------------------------
# Frame encoding and decoding.

function _qgs_sf(id, off, data; fin = false)
    b = UInt8[]
    if isempty(data) && !fin
        # quic-go's tests hand such frames to a stream directly; our encoder
        # refuses to write them, so write the bytes here.
        push!(b, off > 0 ? 0x0e : 0x0a)
        QGS._append_varint!(b, UInt64(id))
        off > 0 && QGS._append_varint!(b, UInt64(off))
        push!(b, 0x00)
        return b
    end
    QGS._append_stream_frame!(b, UInt64(id), UInt64(off), data; fin)
    return b
end
_qgs_rst(id, code, final) = (b = UInt8[]; QGS._append_reset_stream_frame!(b, UInt64(id), UInt64(code), UInt64(final)); b)
_qgs_ss(id, code) = (b = UInt8[]; QGS._append_stop_sending_frame!(b, UInt64(id), UInt64(code)); b)
_qgs_msd(id, max) = (b = UInt8[]; QGS._append_max_stream_data_frame!(b, UInt64(id), UInt64(max)); b)
_qgs_ms(bidi, max) = (b = UInt8[]; QGS._append_max_streams_frame!(b, bidi, UInt64(max)); b)
_qgs_pc(data) = (b = UInt8[]; QGS._append_path_frame!(b, 0x1a, UInt64(data)); b)
_qgs_ping() = UInt8[0x01]

_qgs_conv(buf, f::QGS._StreamFrame) = (type = :stream, id = f.stream_id, offset = Int(f.offset), data = buf[f.data], fin = f.fin)
_qgs_conv(buf, f::QGS._ResetStreamFrame) = (type = :reset_stream, id = f.stream_id, code = f.error_code, final_size = Int(f.final_size))
_qgs_conv(buf, f::QGS._StopSendingFrame) = (type = :stop_sending, id = f.stream_id, code = f.error_code)
_qgs_conv(buf, f::QGS._MaxStreamDataFrame) = (type = :max_stream_data, id = f.stream_id, max = Int(f.max))
_qgs_conv(buf, f::QGS._MaxStreamsFrame) = (type = :max_streams, bidi = f.bidi, max = f.max)
_qgs_conv(buf, f::QGS._MaxDataFrame) = (type = :max_data, max = Int(f.max))
_qgs_conv(buf, f::QGS._StreamDataBlockedFrame) = (type = :stream_data_blocked, id = f.stream_id, limit = Int(f.limit))
_qgs_conv(buf, f::QGS._DataBlockedFrame) = (type = :data_blocked, limit = Int(f.limit))
_qgs_conv(buf, f::QGS._StreamsBlockedFrame) = (type = :streams_blocked, bidi = f.bidi, limit = Int(f.limit))
_qgs_conv(buf, f::QGS._PathResponseFrame) = (type = :path_response, data = f.data)
_qgs_conv(buf, f::QGS._PathChallengeFrame) = (type = :path_challenge, data = f.data)
_qgs_conv(buf, f::QGS._CryptoFrame) = (type = :crypto, offset = Int(f.offset), data = buf[f.data])
_qgs_conv(buf, ::QGS._PingFrame) = (type = :ping,)
_qgs_conv(buf, ::QGS._PaddingFrame) = (type = :padding,)
_qgs_conv(buf, ::QGS._AckFrame) = (type = :ack,)
_qgs_conv(buf, f) = (type = :other, frame = f)

# The frames in a raw 1-RTT payload, padding left out.
function _qgs_parse(buf::Vector{UInt8})
    out = Any[]
    isempty(buf) && return out
    QGS._decode_frames(buf, 1, length(buf), QGS._PacketType.OneRTT) do f
        f isa QGS._PaddingFrame || push!(out, _qgs_conv(buf, f))
        nothing
    end
    return out
end

# Whether each STREAM frame in a raw payload of STREAM frames carries a Length field.
function _qgs_stream_length_fields(buf::Vector{UInt8})
    out = Bool[]
    pos = 1
    while pos <= length(buf)
        type = buf[pos]
        0x08 <= type <= 0x0f || break
        pos += 1
        _, pos = QGS._read_varint(buf, pos, length(buf))
        type & 0x04 != 0 && ((_, pos) = QGS._read_varint(buf, pos, length(buf)))
        if type & 0x02 != 0
            len, pos = QGS._read_varint(buf, pos, length(buf))
            pos += Int(len)
            push!(out, true)
        else
            push!(out, false)
            break
        end
    end
    return out
end

# The frames in a datagram one side sent, decrypted (on a copy) with the
# other side's keys. Each has a `space` field: 1 Initial, 2 Handshake, 3 1-RTT.
function _qgs_decode(h, from_client::Bool, dgram::Vector{UInt8})
    receiver = from_client ? h.server : h.client
    out = Any[]
    receiver === nothing && return out
    buf = copy(dgram)
    for header in QGS._datagram_packets(buf, 1, length(buf), QGS._LOCAL_CID_LEN)
        idx = header.type == QGS._PacketType.Initial ? 1 :
              header.type == QGS._PacketType.Handshake ? 2 :
              header.type == QGS._PacketType.OneRTT ? 3 : 0
        idx == 0 && continue
        space = receiver.spaces[idx]
        keys = space.read_keys
        keys === nothing && continue
        opened = QGS._open_packet!(keys, buf, header.first, header.pn_offset, header.last, space.largest_received)
        opened === nothing && continue
        _, pf, pl = opened
        QGS._decode_frames(buf, pf, pl, header.type) do f
            f isa QGS._PaddingFrame || push!(out, merge(_qgs_conv(buf, f), (space = idx,)))
            nothing
        end
    end
    return out
end

# Everything one side sent since `mark` (a length of `h.log`), decoded.
_qgs_mark(h) = length(h.log)
function _qgs_sent(h, from_client::Bool, mark::Int)
    out = Any[]
    for e in h.log[(mark + 1):end]
        e.from_client == from_client && append!(out, _qgs_decode(h, from_client, e.bytes))
    end
    return out
end
_qgs_of(frames, type) = filter(f -> f.type == type, frames)

# Exchanges datagrams and returns what `from_client`'s side sent meanwhile.
function _qgs_flush!(h, from_client::Bool)
    mark = _qgs_mark(h)
    _qcn_exchange!(h)
    return _qgs_sent(h, from_client, mark)
end

# Sends `frames` in a packet of space `idx` (1 Initial, 2 Handshake),
# bypassing the sender's own checks, as `_qcn_inject!` does for 1-RTT.
function _qgs_inject_space!(h, from_client::Bool, idx::Int, frames::Vector{UInt8}; pad_to::Int = 0)
    sender = from_client ? h.client : h.server
    space = sender.spaces[idx]
    buf = UInt8[]
    layout, pn = QGS._begin_packet!(sender, buf, idx)
    append!(buf, frames)
    payload_last = QGS._end_packet!(buf, layout; pad_to)
    space.next_pn += 1
    QGS._seal_packet!(space.write_keys, buf, layout.first, layout.pn_offset, layout.pn_len, payload_last, pn)
    QGS._receive_datagram!(from_client ? h.server : h.client, buf, h.now)
    return nothing
end

function _qgs_handshake(; kwargs...)
    h = _QcnHarness(; kwargs...)
    _qcn_run!(h) || error("handshake failed")
    # Let path MTU discovery and the last ACKs settle.
    _qcn_run!(h; done = h -> false, max_time = h.now + 2_000_000_000)
    return h
end

_qgs_code(conn) = conn.error === nothing ? nothing : conn.error.code

# ---------------------------------------------------------------------------
# Sending on a stream, as quic-go's popStreamFrame.

# quic-go's data budget in a STREAM frame of `size` bytes on stream 1337 at
# `offset`, with a Length field (wire.StreamFrame.MaxDataLen).
function _qgs_go_data_len(size::Integer, offset::Integer)
    header = 1 + 2 + (offset == 0 ? 0 : _qgs_vl(offset)) + 1
    d = size - header
    d > 63 && (d -= 1)
    d > 16383 && (d -= 2)
    return max(d, 0)
end

# Frames stream `id` puts in a packet with `room` bytes for frames: the parsed
# frames and the `_SentFrame`s recorded for acknowledgment and loss.
function _qgs_pop_raw!(conn, id, room::Integer)
    s = conn.streams[UInt64(id)]
    buf = UInt8[]
    sent = QGS._SentFrame[]
    QGS._append_stream_frames!(conn, s, buf, Int(room) + QGS._AEAD_TAG_LEN, sent)
    frames = _qgs_parse(buf)
    return (; frames, sent, buf, stream = _qgs_of(frames, :stream))
end

# quic-go's expectedFrameHeaderLen(offset): a STREAM frame on stream 1337 with a Length field.
_qgs_hdr(offset) = 1 + 2 + (offset == 0 ? 0 : _qgs_vl(offset)) + 1

# The same for at most `data` bytes of new or lost data in one STREAM frame.
_qgs_pop_data!(conn, id, data::Integer) =
    _qgs_pop_raw!(conn, id, data + 1 + _qgs_vl(id) + 8 + 2)

# popStreamFrame(size), with quic-go's frame size.
function _qgs_pop!(conn, id, size::Integer = 1 << 20)
    sb = conn.streams[UInt64(id)].send
    offset = isempty(sb.pending) ? QGS._send_end(sb) : first(first(sb.pending.ranges))
    return _qgs_pop_data!(conn, id, _qgs_go_data_len(size, offset))
end

# hasMoreData: data or a FIN is still waiting to be sent.
_qgs_has_more(conn, id) = QGS._send_has_pending(conn.streams[UInt64(id)].send)
_qgs_can_send(conn, id) = QGS._stream_can_send_now(conn, conn.streams[UInt64(id)])

# getDataAtOffset: byte i of the stream is i mod 256.
_qgs_data_at(offset, len) = UInt8[(offset + i) % 256 for i in 0:(len - 1)]

# ---------------------------------------------------------------------------
# Frame sorter: `_Reassembly`, with the delivered bytes kept until popped.

mutable struct _QgsSorter
    rb::QGS._Reassembly
    out::Vector{UInt8}
    popped::Int
end
_QgsSorter() = _QgsSorter(QGS._Reassembly(), UInt8[], 0)

# Stream data is a function of the offset, so every copy of a byte agrees.
_qgs_bytes(off, len) = UInt8[(o * 7 + 3) % 251 for o in off:(off + len - 1)]
_qgs_push!(s::_QgsSorter, off, len) = QGS._reassemble!(s.out, s.rb, Int64(off), _qgs_bytes(off, len))
_qgs_push!(s::_QgsSorter, off, data::Vector{UInt8}) = QGS._reassemble!(s.out, s.rb, Int64(off), data)

# Pop: the next contiguous bytes and their offset, or (offset, nothing).
function _qgs_pop!(s::_QgsSorter)
    d = Int(s.rb.delivered)
    s.popped < d || return (d, nothing)
    off = s.popped
    data = s.out[(off + 1):d]
    s.popped = d
    return (off, data)
end
_qgs_has_more_data(s::_QgsSorter) = s.popped < s.rb.delivered

# What the sorter holds, popped bytes aside, as offset ranges.
function _qgs_held(s::_QgsSorter)
    set = QGS._RangeSet()
    s.popped < s.rb.delivered && push!(set, Int64(s.popped):Int64(s.rb.delivered - 1))
    for (o, d) in s.rb.fragments
        push!(set, o:(o + length(d) - 1))
    end
    return collect(set)
end

# The gaps above the popped offset, quic-go style: [start, end) with the last
# open-ended.
function _qgs_gaps(s::_QgsSorter)
    gaps = Tuple{Int, Int}[]
    pos = s.popped
    for r in _qgs_held(s)
        first(r) > pos && push!(gaps, (pos, Int(first(r))))
        pos = Int(last(r)) + 1
    end
    push!(gaps, (pos, _QGS_MAX))
    return gaps
end

function _qgs_check_queue(s::_QgsSorter, queue)
    expected = QGS._RangeSet()
    for (o, l) in queue
        push!(expected, Int64(o):Int64(o + l - 1))
    end
    @test _qgs_held(s) == collect(expected)
    @test s.out == _qgs_bytes(0, length(s.out))
    @test all(f -> f[2] == _qgs_bytes(f[1], length(f[2])), s.rb.fragments)
    # Held fragments never overlap.
    @test all(i -> s.rb.fragments[i][1] + length(s.rb.fragments[i][2]) <= s.rb.fragments[i + 1][1], 1:(length(s.rb.fragments) - 1))
end

# (name, pushes as (offset, length), quic-go's queue as (offset, length), quic-go's gaps)
const _QGS_SORTER_CASES = let M = _QGS_MAX, m2 = 64, m3 = 43, m4 = 32, m6 = 22, m9 = 15, m11 = 12, m = 128
    [
        ("case 1", [(3, 3), (6, 5)], [(3, 3), (6, 5)], [(0, 3), (11, M)]),
        ("case 2", [(3, 3), (10, 5)], [(3, 3), (10, 5)], [(0, 3), (6, 10), (15, M)]),
        ("case 3", [(3, 3), (10, 5), (6, 4)], [(3, 3), (6, 4), (10, 5)], [(0, 3), (15, M)]),
        ("case 4", [(3, 4), (5, 4)], [(3, 4), (7, 2)], [(0, 3), (9, M)]),
        ("case 4, for long frames", [(3m2, 4m2), (5m2, 4m2)], [(3m2, 4m2), (7m2, 2m2)], [(0, 3m2), (9m2, M)]),
        ("case 5", [(0, 4), (3, 4)], [(0, 4), (4, 3)], [(7, M)]),
        ("case 5, for long frames", [(0, 4m2), (3m2, 4m2)], [(0, 4m2), (4m2, 3m2)], [(7m2, M)]),
        ("case 6", [(5, 4), (3, 4)], [(3, 2), (5, 4)], [(0, 3), (9, M)]),
        ("case 6, for long frames", [(5m2, 4m2), (3m2, 4m2)], [(3m2, 2m2), (5m2, 4m2)], [(0, 3m2), (9m2, M)]),
        ("case 7", [(3, 3), (10, 5), (6, 2)], [(3, 3), (6, 2), (10, 5)], [(0, 3), (8, 10), (15, M)]),
        ("case 8", [(3, 3), (15, 5), (10, 2)], [(3, 3), (10, 2), (15, 5)], [(0, 3), (6, 10), (12, 15), (20, M)]),
        ("case 9", [(3, 3), (10, 5), (8, 2)], [(3, 3), (8, 2), (10, 5)], [(0, 3), (6, 8), (15, M)]),
        ("case 10", [(3, 3), (10, 5), (5, 6)], [(3, 3), (6, 4), (10, 5)], [(0, 3), (15, M)]),
        ("case 10, for long frames", [(3m4, 3m4), (10m4, 5m4), (5m4, 6m4)], [(3m4, 3m4), (6m4, 4m4), (10m4, 5m4)], [(0, 3m4), (15m4, M)]),
        ("case 11", [(3, 4), (10, 5), (5, 5)], [(3, 4), (7, 3), (10, 5)], [(0, 3), (15, M)]),
        ("case 11, for long frames", [(3m3, 4m3), (10m3, 5m3), (5m3, 5m3)], [(3m3, 4m3), (7m3, 3m3), (10m3, 5m3)], [(0, 3m3), (15m3, M)]),
        ("case 12", [(3, 4), (3, 7)], [(3, 7)], [(0, 3), (10, M)]),
        ("case 13", [(3, 3), (6, 3), (3, 7)], [(3, 7)], [(0, 3), (10, M)]),
        ("case 14", [(3, 3), (6, 4), (3, 5)], [(3, 3), (6, 4)], [(0, 3), (10, M)]),
        ("case 14, for long frames", [(3m3, 3m3), (6m3, 4m3), (3m3, 5m3)], [(3m3, 3m3), (6m3, 4m3)], [(0, 3m3), (10m3, M)]),
        ("case 15", [(3, 3), (6, 3), (3, 6)], [(3, 6)], [(0, 3), (9, M)]),
        ("case 16", [(5, 4), (5, 4)], [(5, 4)], [(0, 5), (9, M)]),
        ("case 17", [(3, 3), (6, 3), (3, 3)], [(3, 3), (6, 3)], [(0, 3), (9, M)]),
        ("case 18", [(5, 4), (5, 2)], [(5, 4)], [(0, 5), (9, M)]),
        ("case 19", [(5, 5), (6, 2)], [(5, 5)], [(0, 5), (10, M)]),
        ("case 20", [(0, 10), (5, 4)], [(0, 10)], [(10, M)]),
        ("case 21", [(5, 5), (7, 3)], [(5, 5)], [(0, 5), (10, M)]),
        ("case 22", [(5, 3), (3, 5)], [(3, 5)], [(0, 3), (8, M)]),
        ("case 23", [(5, 3), (8, 3), (3, 8)], [(3, 8)], [(0, 3), (11, M)]),
        ("case 24", [(3, 3), (9, 3), (6, 6)], [(3, 3), (6, 6)], [(0, 3), (12, M)]),
        ("case 25", [(3, 3), (9, 3), (15, 3), (6, 9)], [(3, 3), (6, 9), (15, 3)], [(0, 3), (18, M)]),
        ("case 26", [(5, 3), (3, 10)], [(3, 10)], [(0, 3), (13, M)]),
        ("case 27", [(3, 3), (6, 4), (2, 4)], [(2, 1), (3, 3), (6, 4)], [(0, 2), (10, M)]),
        ("case 27, for long frames", [(3m, 3m), (6m, 4m), (2m, 4m)], [(2m, m), (3m, 3m), (6m, 4m)], [(0, 2m), (10m, M)]),
        ("case 28", [(3, 3), (6, 4), (2, 6)], [(2, 1), (3, 3), (6, 4)], [(0, 2), (10, M)]),
        ("case 28, for long frames", [(3m, 3m), (6m, 4m), (2m, 6m)], [(2m, m), (3m, 3m), (6m, 4m)], [(0, 2m), (10m, M)]),
        ("case 29", [(3, 3), (6, 3), (6, 5)], [(3, 3), (6, 5)], [(0, 3), (11, M)]),
        ("case 30", [(3, 3), (6, 3), (5, 6)], [(3, 3), (6, 3), (9, 2)], [(0, 3), (11, M)]),
        ("case 30, for long frames", [(3m2, 3m2), (6m2, 3m2), (5m2, 6m2)], [(3m2, 3m2), (6m2, 3m2), (9m2, 2m2)], [(0, 3m2), (11m2, M)]),
        ("case 31", [(3, 3), (9, 3), (5, 10)], [(3, 3), (6, 9)], [(0, 3), (15, M)]),
        ("case 31, for long frames", [(3m9, 3m9), (9m9, 3m9), (5m9, 10m9)], [(3m9, 3m9), (6m9, 9m9)], [(0, 3m9), (15m9, M)]),
        ("case 32", [(3, 3), (9, 3), (3, 9)], [(3, 9)], [(0, 3), (12, M)]),
        # quic-go's comment says f3 is at 12 - 15, but the code pushes it at 9.
        ("case 33", [(3, 3), (9, 3), (9, 3), (5, 12)], [(3, 3), (6, 11)], [(0, 3), (17, M)]),
        ("case 33, for long frames", [(3m11, 3m11), (9m11, 3m11), (9m11, 3m11), (5m11, 12m11)], [(3m11, 3m11), (6m11, 11m11)], [(0, 3m11), (17m11, M)]),
        ("case 34", [(5, 5), (10, 5), (20, 5), (10, 10)], [(5, 5), (10, 10), (20, 5)], [(0, 5), (25, M)]),
        ("case 35", [(3, 3), (9, 4), (3, 8)], [(3, 6), (9, 4)], [(0, 3), (13, M)]),
        ("case 35, for long frames", [(3m6, 3m6), (9m6, 4m6), (3m6, 8m6)], [(3m6, 6m6), (9m6, 4m6)], [(0, 3m6), (13m6, M)]),
    ]
end

# ---------------------------------------------------------------------------
# The public API over loopback.

_qgs_deadline(seconds::Real) = Int64(time_ns()) + round(Int64, seconds * 1e9)
_qgs_err(f) = try
    f()
    nothing
catch ex
    ex
end

function _qgs_api(f; server_kw = (;), client_kw = (;))
    listener = QGS.listen(UDGS.loopback_addr(0), _qcn_server_config(); server_kw...)
    client = server = nothing
    try
        port = QGS.local_addr(listener).port
        accepted = Threads.@spawn QGS.accept(listener; deadline_ns = _qgs_deadline(30))
        client = QGS.connect(UDGS.loopback_addr(port), _qcn_client_config(); deadline_ns = _qgs_deadline(30), client_kw...)
        server = fetch(accepted)
        f(client, server)
    finally
        client === nothing || close(client)
        server === nothing || close(server)
        close(listener)
    end
    return nothing
end

# Whether task `t` finishes within `seconds`.
_qgs_finishes(t::Task, seconds::Real) = timedwait(() -> istaskdone(t), seconds; pollint = 0.005) == :ok

# Runs `f` in a task; returns the task, whose result is `f`'s exception (or
# nothing) and the time_ns() it finished.
_qgs_spawn(f) = Threads.@spawn begin
    err = _qgs_err(f)
    (err, Int64(time_ns()))
end

# Whether a task finished (at `t_ns`) around `deadline_ns`.
_qgs_near(t_ns, deadline_ns) = deadline_ns - 2_000_000 <= t_ns <= deadline_ns + 150_000_000

# A write that blocks: the server allows 1000 bytes on the stream and never
# reads, so writes beyond the send buffer limit wait.
const _QGS_BLOCKING_WRITE = QGS._SEND_BUFFER_LIMIT + 5000
const _QGS_SMALL_WINDOW = (; max_stream_data = 1000)

# Lets the peer see stream `s` by writing a byte, and accepts it there.
function _qgs_accept_peer(s, peer_conn)
    write(s, UInt8[0x2a])
    p = QGS.accept_stream(peer_conn; deadline_ns = _qgs_deadline(10))
    @test read(p, 1) == UInt8[0x2a]
    return p
end

@testset "quic_go_streams_tests.jl" begin
@testset "frame sorter" begin
    @testset "returns nil when empty" begin
        s = _QgsSorter()
        @test _qgs_pop!(s)[2] === nothing
    end

    @testset "inserts and pops a single frame" begin
        s = _QgsSorter()
        _qgs_push!(s, 0, Vector{UInt8}("foobar"))
        @test _qgs_pop!(s) == (0, Vector{UInt8}("foobar"))
        @test _qgs_pop!(s) == (6, nothing)
    end

    @testset "inserts and pops two consecutive frame" begin
        # quic-go pops each frame separately; ours pops the contiguous run.
        s = _QgsSorter()
        _qgs_push!(s, 3, Vector{UInt8}("bar"))
        _qgs_push!(s, 0, Vector{UInt8}("foo"))
        @test _qgs_pop!(s) == (0, Vector{UInt8}("foobar"))
        @test _qgs_pop!(s) == (6, nothing)
    end

    @testset "ignores empty frames" begin
        s = _QgsSorter()
        _qgs_push!(s, 0, UInt8[])
        @test _qgs_pop!(s)[2] === nothing
        @test isempty(s.rb.fragments)
    end

    @testset "says if has more data" begin
        s = _QgsSorter()
        @test !_qgs_has_more_data(s)
        _qgs_push!(s, 0, Vector{UInt8}("foo"))
        @test _qgs_has_more_data(s)
        @test _qgs_pop!(s)[2] == Vector{UInt8}("foo")
        @test !_qgs_has_more_data(s)
    end

    @testset "Gap handling" begin
        for (name, pushes, queue, gaps) in _QGS_SORTER_CASES
            @testset "$name" begin
                s = _QgsSorter()
                for (i, (o, l)) in enumerate(pushes)
                    _qgs_push!(s, o, l)
                    # case 19 also checks the queue after its first frame.
                    name == "case 19" && i == 1 && _qgs_check_queue(s, [(5, 5)])
                end
                _qgs_check_queue(s, queue)
                @test _qgs_gaps(s) == gaps
            end
        end

        @testset "receiving data after reads" begin
            @testset "ignores duplicate frames" begin
                s = _QgsSorter()
                _qgs_push!(s, 0, Vector{UInt8}("foobar"))
                @test _qgs_pop!(s) == (0, Vector{UInt8}("foobar"))
                _qgs_push!(s, 0, Vector{UInt8}("foobar"))
                @test isempty(_qgs_held(s))
                @test _qgs_gaps(s) == [(6, _QGS_MAX)]
            end

            @testset "ignores parts of frames that have already been read" begin
                s = _QgsSorter()
                _qgs_push!(s, 0, Vector{UInt8}("foo"))
                @test _qgs_pop!(s) == (0, Vector{UInt8}("foo"))
                _qgs_push!(s, 0, Vector{UInt8}("foobar"))
                @test _qgs_pop!(s) == (3, Vector{UInt8}("bar"))
                @test isempty(_qgs_held(s))
                @test _qgs_gaps(s) == [(6, _QGS_MAX)]
            end
        end

        @testset "DoS protection" begin
            @testset "errors when too many gaps are created" begin
                # protocol.MaxStreamFrameSorterGaps = 1000. Through a
                # connection: STREAM frames on the client's stream 0 that
                # leave 1000 gaps, then one more.
                h = _qgs_handshake()
                frames = [_qgs_sf(0, i * 7, Vector{UInt8}("foobar")) for i in 0:999]
                for batch in Iterators.partition(frames, 100)
                    _qcn_inject!(h, true, reduce(vcat, batch))
                end
                s = h.server.streams[UInt64(0)]
                # Gaps: one after each frame, the last open-ended.
                @test length(s.recv.reassembly.fragments) + 1 == 1000
                @test h.server.error === nothing
                _qcn_inject!(h, true, _qgs_sf(0, 1000 * 7 + 100, Vector{UInt8}("foobar")))
                # "too many gaps in received data", closed with INTERNAL_ERROR
                # as quic-go does.
                @test h.server.error !== nothing
                @test _qgs_code(h.server) == QGS._INTERNAL_ERROR
            end
        end
    end

    @testset "stress testing" begin
        for long_frames in (true, false)
            name = long_frames ? "long" : "short"
            @testset "using $name frames" begin
                num = 1000
                data_len = long_frames ? 2 * _QGS_MIN_STREAM_FRAME : 25
                data = UInt8[UInt8(i % 256) for i in 0:(num - 1) for _ in 1:data_len]
                total = num * data_len
                random_frames(rng) = shuffle(rng, [(i * data_len, data[(i * data_len + 1):((i + 1) * data_len)]) for i in 0:(num - 1)])
                # Pushes, then pops everything and checks it.
                function check(s)
                    @test _qgs_gaps(s) == [(total, _QGS_MAX)]
                    got = UInt8[]
                    while true
                        off, b = _qgs_pop!(s)
                        b === nothing && break
                        @test off == length(got)
                        append!(got, b)
                    end
                    @test got == data
                    @test isempty(s.rb.fragments)
                end

                @testset "inserting frames in a random order" begin
                    rng = Xoshiro(1)
                    s = _QgsSorter()
                    for (o, d) in random_frames(rng)
                        _qgs_push!(s, o, d)
                    end
                    check(s)
                end

                @testset "inserting frames in a random order, with some duplicates" begin
                    rng = Xoshiro(2)
                    s = _QgsSorter()
                    frames = random_frames(rng)
                    for (o, d) in frames
                        _qgs_push!(s, o, d)
                        if rand(rng, 0:9) < 5
                            (o2, d2) = frames[rand(rng, 1:length(frames))]
                            _qgs_push!(s, o2, d2)
                        end
                    end
                    check(s)
                end

                @testset "inserting frames in a random order, with randomly cut retransmissions" begin
                    rng = Xoshiro(3)
                    s = _QgsSorter()
                    for (o, d) in random_frames(rng)
                        _qgs_push!(s, o, d)
                        if rand(rng, 0:9) < 5
                            len = min(1 + rand(rng, 0:(4 * data_len - 1)), total - 1)
                            off = rand(rng, 0:(total - len - 1))
                            _qgs_push!(s, off, data[(off + 1):(off + len)])
                        end
                    end
                    check(s)
                end
            end
        end
    end
end

@testset "Crypto Stream" begin
    @testset "handling incoming data" begin
        @testset "handles in-order CRYPTO frames" begin
            rb = QGS._Reassembly()
            @test QGS._crypto_receive!(rb, UInt64(0), Vector{UInt8}("foo")) == Vector{UInt8}("foo")
            @test QGS._crypto_receive!(rb, UInt64(3), Vector{UInt8}("bar")) == Vector{UInt8}("bar")
            @test isempty(rb.fragments)
        end

        @testset "errors if the frame exceeds the maximum offset" begin
            rb = QGS._Reassembly()
            err = QGS._crypto_receive!(rb, UInt64(QGS._CRYPTO_BUFFER_LIMIT - 5), Vector{UInt8}("foobar"))
            @test err isa QGS._TransportError
            @test err.code == QGS._CRYPTO_BUFFER_EXCEEDED
        end

        @testset "handles out-of-order CRYPTO frames" begin
            rb = QGS._Reassembly()
            @test isempty(QGS._crypto_receive!(rb, UInt64(3), Vector{UInt8}("bar")))
            @test QGS._crypto_receive!(rb, UInt64(0), Vector{UInt8}("foo")) == Vector{UInt8}("foobar")
            @test isempty(rb.fragments)
        end

        @testset "finishing" begin
            # quic-go's Finish runs when a level's keys are dropped. Through
            # a connection: the server's Initial CRYPTO stream gets data the
            # TLS stack cannot use before the client drops its Initial keys.
            function initial_leftover(offset_after_sh, data)
                h = _QcnHarness()
                _qcn_deliver!(h, true, QGS._next_datagram!(h.client, h.now))
                sh_len = length(h.server.spaces[1].crypto_send.data)
                _qgs_inject_space!(h, false, 1, (b = UInt8[]; QGS._append_crypto_frame!(b, UInt64(sh_len + offset_after_sh), data); b); pad_to = 1200)
                _qcn_run!(h; max_time = h.now + 5_000_000_000)
                return h
            end

            @testset "errors if there's still data to read at the current offset after finishing" begin
                # The bytes reach TLS with the ServerHello and are left
                # unconsumed; the TLS stack refuses the key change
                # (unexpected_message), which also fails the connection.
                h = initial_leftover(0, Vector{UInt8}("foo"))
                @test h.client.error !== nothing
            end

            @testset "errors if there's still data to read at a higher offset after finishing" begin
                h = initial_leftover(10, Vector{UInt8}("foobar"))
                @test h.client.spaces[1].discarded
                @test _qgs_code(h.client) == QGS._PROTOCOL_VIOLATION
                @test h.client.error.reason == "encryption level changed, but crypto stream has more data to read"
            end

            @testset "works with reordered data" begin
                rb = QGS._Reassembly()
                @test isempty(QGS._crypto_receive!(rb, UInt64(3), Vector{UInt8}("bar")))
                @test length(QGS._crypto_receive!(rb, UInt64(0), Vector{UInt8}("foo"))) == 6
                @test isempty(rb.fragments)  # nothing left: finishing is fine
                @test QGS._crypto_receive!(rb, UInt64(3), Vector{UInt8}("bar")) == UInt8[]
            end

            @testset "ignores crypto data below the maximum offset received before finishing" begin
                rb = QGS._Reassembly()
                @test QGS._crypto_receive!(rb, UInt64(0), Vector{UInt8}("foobar")) == Vector{UInt8}("foobar")
                @test QGS._crypto_receive!(rb, UInt64(2), Vector{UInt8}("foo")) == UInt8[]
            end
        end
    end

    @testset "writing data" begin
        @testset "says if it has data" begin
            sb = QGS._CryptoSendBuffer()
            @test !QGS._crypto_has_pending(sb)
            QGS._crypto_queue!(sb, Vector{UInt8}("foobar"))
            @test QGS._crypto_has_pending(sb)
        end

        @testset "pops crypto frames" begin
            sb = QGS._CryptoSendBuffer()
            QGS._crypto_queue!(sb, Vector{UInt8}("foobar"))
            r = QGS._crypto_next_chunk!(sb, 1000)
            @test first(r) == 0
            @test QGS._crypto_bytes(sb, r) == Vector{UInt8}("foobar")
        end

        @testset "coalesces multiple writes" begin
            sb = QGS._CryptoSendBuffer()
            QGS._crypto_queue!(sb, Vector{UInt8}("foo"))
            QGS._crypto_queue!(sb, Vector{UInt8}("bar"))
            r = QGS._crypto_next_chunk!(sb, 1000)
            @test first(r) == 0
            @test QGS._crypto_bytes(sb, r) == Vector{UInt8}("foobar")
        end

        @testset "respects the maximum size" begin
            sb = QGS._CryptoSendBuffer()
            QGS._crypto_queue!(sb, Vector{UInt8}("foobar"))
            r = QGS._crypto_next_chunk!(sb, 3)
            @test first(r) == 0 && QGS._crypto_bytes(sb, r) == Vector{UInt8}("foo")
            r = QGS._crypto_next_chunk!(sb, 3)
            @test first(r) == 3 && QGS._crypto_bytes(sb, r) == Vector{UInt8}("bar")
        end
    end
end

@testset "Crypto Stream Manager" begin
    # Each packet number space has its own CRYPTO stream.
    for (name, idx) in (("passes messages to the initial stream", 1),
                        ("passes messages to the handshake stream", 2),
                        ("passes messages to the 1-RTT stream", 3))
        @testset "$name" begin
            conn = _QcnHarness().client
            @test QGS._crypto_receive!(conn.spaces[idx].crypto_recv, UInt64(0), Vector{UInt8}("foobar")) == Vector{UInt8}("foobar")
            @test all(i -> i == idx || conn.spaces[i].crypto_recv.delivered == 0, 1:3)
        end
    end

    @testset "processes all messages" begin
        conn = _QcnHarness().client
        rb = conn.spaces[2].crypto_recv
        data = UInt8[]
        append!(data, QGS._crypto_receive!(rb, UInt64(3), Vector{UInt8}("bar")))
        append!(data, QGS._crypto_receive!(rb, UInt64(0), Vector{UInt8}("foo")))
        @test data == Vector{UInt8}("foobar")
    end

    @testset "errors for unknown encryption levels" begin
        # CRYPTO frames cannot come in 0-RTT packets.
        @test !QGS._frame_allowed(UInt64(0x06), QGS._PacketType.ZeroRTT)
    end

    @testset "drops Initial" begin
        h = _QcnHarness()
        _qcn_deliver!(h, true, QGS._next_datagram!(h.client, h.now))
        _qgs_inject_space!(h, false, 1, (b = UInt8[]; QGS._append_crypto_frame!(b, UInt64(5000), Vector{UInt8}("foo")); b); pad_to = 1200)
        _qcn_run!(h; max_time = h.now + 5_000_000_000)
        @test h.client.spaces[1].discarded
        # quic-go: "encryption level changed, but crypto stream has more data
        # to read" (RFC 9001 Section 4.1.3).
        @test _qgs_code(h.client) == QGS._PROTOCOL_VIOLATION
    end

    @testset "drops Handshake" begin
        h = _QcnHarness()
        # Client Initial to the server, the server's flight to the client.
        _qcn_deliver!(h, true, QGS._next_datagram!(h.client, h.now))
        while (d = QGS._next_datagram!(h.server, h.now)) !== nothing
            _qcn_deliver!(h, false, d)
        end
        # The client's Finished, held back while the server gets Handshake
        # data it can never use.
        finished = Vector{UInt8}[]
        while (d = QGS._next_datagram!(h.client, h.now)) !== nothing
            push!(finished, d)
        end
        _qgs_inject_space!(h, true, 2, (b = UInt8[]; QGS._append_crypto_frame!(b, UInt64(5000), Vector{UInt8}("foo")); b))
        for d in finished
            _qcn_deliver!(h, true, d)
        end
        _qcn_run!(h; max_time = h.now + 5_000_000_000)
        @test h.server.spaces[2].discarded
        @test _qgs_code(h.server) == QGS._PROTOCOL_VIOLATION
    end
end

@testset "Retransmission queue" begin
    for (level, idx) in (("Initial", 1), ("Handshake", 2))
        @testset "$level data" begin
            @testset "doesn't dequeue anything when it's empty" begin
                sb = QGS._CryptoSendBuffer()
                @test !QGS._crypto_has_pending(sb)
                @test QGS._crypto_next_chunk!(sb, 1 << 20) === nothing
            end

            @testset "queues and retrieves a CRYPTO frame" begin
                sb = QGS._CryptoSendBuffer()
                QGS._crypto_queue!(sb, Vector{UInt8}("foobar"))
                r = QGS._crypto_next_chunk!(sb, 1 << 20)
                QGS._crypto_on_lost!(sb, r)
                @test QGS._crypto_has_pending(sb)
                @test QGS._crypto_next_chunk!(sb, 6) == 0:5
                @test !QGS._crypto_has_pending(sb)
            end

            @testset "returns split CRYPTO frames" begin
                sb = QGS._CryptoSendBuffer()
                QGS._crypto_queue!(sb, vcat(zeros(UInt8, 100), Vector{UInt8}("foobar")))
                QGS._crypto_next_chunk!(sb, 1 << 20)
                QGS._crypto_on_acked!(sb, Int64(0):Int64(99))
                QGS._crypto_on_lost!(sb, Int64(100):Int64(105))
                @test QGS._crypto_has_pending(sb)
                r = QGS._crypto_next_chunk!(sb, 3)
                @test r == 100:102 && QGS._crypto_bytes(sb, r) == Vector{UInt8}("foo")
                @test QGS._crypto_has_pending(sb)
                r = QGS._crypto_next_chunk!(sb, 1 << 20)
                @test r == 103:105 && QGS._crypto_bytes(sb, r) == Vector{UInt8}("bar")
                @test !QGS._crypto_has_pending(sb)
            end

            @testset "drops all $level frames" begin
                # A connection with $level CRYPTO data waiting sends none of it
                # once the space is discarded.
                h = _QcnHarness()
                if idx == 1
                    conn = h.client
                else
                    _qcn_deliver!(h, true, QGS._next_datagram!(h.client, h.now))
                    while (d = QGS._next_datagram!(h.server, h.now)) !== nothing
                        _qcn_deliver!(h, false, d)
                    end
                    conn = h.client
                end
                @test QGS._crypto_has_pending(conn.spaces[idx].crypto_send)
                QGS._discard_space!(conn, idx)
                sent = Any[]
                while (d = QGS._next_datagram!(conn, h.now)) !== nothing
                    push!(sent, d)
                end
                ptype = idx == 1 ? QGS._PacketType.Initial : QGS._PacketType.Handshake
                @test !any(d -> _qcn_has_type(d, ptype), sent)
            end

            @testset "adds a PING" begin
                h = _QcnHarness()
                _qcn_deliver!(h, true, QGS._next_datagram!(h.client, h.now))
                if idx == 1
                    # The server, its first flight sent.
                    while QGS._next_datagram!(h.server, h.now) !== nothing end
                    conn, from_client = h.server, false
                else
                    # The client, its Finished sent.
                    while (d = QGS._next_datagram!(h.server, h.now)) !== nothing
                        _qcn_deliver!(h, false, d)
                    end
                    while QGS._next_datagram!(h.client, h.now) !== nothing end
                    conn, from_client = h.client, true
                end
                conn.spaces[idx].probes = 1
                d = QGS._next_datagram!(conn, h.now)
                @test d !== nothing
                frames = _qgs_decode(h, from_client, d)
                @test any(f -> f.type == :ping && f.space == idx, frames)
            end
        end
    end

    @testset "Application data" begin
        @testset "doesn't dequeue anything when it's empty" begin
            h = _qgs_handshake()
            buf = UInt8[]
            sent = QGS._SentFrame[]
            QGS._append_app_frames!(h.client, buf, 1 << 20, sent)
            @test isempty(buf) && isempty(sent)
        end

        @testset "queues and retrieves a control frame" begin
            h = _qgs_handshake()
            conn = h.client
            @test !QGS._app_wants_to_send(conn)
            conn.max_data_pending = true
            @test QGS._app_wants_to_send(conn)
            # We reserve the largest MAX_DATA frame, 9 bytes (quic-go: the
            # frame's own length).
            buf = UInt8[]
            sent = QGS._SentFrame[]
            QGS._append_app_frames!(conn, buf, 8 + QGS._AEAD_TAG_LEN, sent)
            @test isempty(buf)
            QGS._append_app_frames!(conn, buf, 9 + QGS._AEAD_TAG_LEN, sent)
            @test _qgs_parse(buf) == [(type = :max_data, max = conn.local_max_data)]
            @test !QGS._app_wants_to_send(conn)
        end

        @testset "retransmits a frame" begin
            h = _qgs_handshake()
            conn = h.client
            QGS._on_stream_frame_lost!(conn, QGS._SentFrame(QGS._SF_MAX_DATA))
            @test QGS._app_wants_to_send(conn)
            buf = UInt8[]
            QGS._append_app_frames!(conn, buf, 1 << 20, QGS._SentFrame[])
            @test _qgs_parse(buf) == [(type = :max_data, max = conn.local_max_data)]
        end

        @testset "adds a PING" begin
            h = _qgs_handshake()
            h.client.spaces[3].probes = 1
            d = QGS._next_datagram!(h.client, h.now)
            @test d !== nothing
            @test any(f -> f.type == :ping && f.space == 3, _qgs_decode(h, true, d))
        end
    end
end
@testset "Receive Stream" begin
    # The client's unidirectional stream 2: the server only receives on it.
    rid = UInt64(2)
    recv!(h, frames...) = _qcn_inject!(h, true, reduce(vcat, frames))
    readn(h, n = typemax(Int)) = QGS._stream_read!(h.server, rid, n)
    deadbeef() = UInt8[0xDE, 0xAD, 0xBE, 0xEF]

    @testset "reading" begin
        @testset "reads a single STREAM frame" begin
            h = _qgs_handshake()
            recv!(h, _qgs_sf(rid, 0, deadbeef()))
            r = readn(h, 4)
            @test r.data == deadbeef() && !r.fin
        end

        @testset "reads a single STREAM frame in multiple goes" begin
            h = _qgs_handshake()
            recv!(h, _qgs_sf(rid, 0, deadbeef()))
            @test readn(h, 2).data == UInt8[0xDE, 0xAD]
            @test readn(h, 2).data == UInt8[0xBE, 0xEF]
        end

        @testset "queues a flow control update" begin
            # A 4-byte window: reading 3 bytes uses more than half of it.
            h = _qgs_handshake(server_limits = QGS._StreamLimits(max_stream_data = 4))
            recv!(h, _qgs_sf(rid, 0, deadbeef()))
            @test length(readn(h, 3).data) == 3
            msd = _qgs_of(_qgs_flush!(h, false), :max_stream_data)
            @test length(msd) == 1
            @test msd[1].id == rid && msd[1].max == 3 + 4
        end

        @testset "reads all data available" begin
            h = _qgs_handshake()
            recv!(h, _qgs_sf(rid, 0, UInt8[0xDE, 0xAD]))
            recv!(h, _qgs_sf(rid, 2, UInt8[0xBE, 0xEF]))
            @test readn(h, 6).data == deadbeef()
        end

        @testset "assembles multiple STREAM frames" begin
            h = _qgs_handshake()
            recv!(h, _qgs_sf(rid, 0, UInt8[0xDE, 0xAD]))
            recv!(h, _qgs_sf(rid, 2, UInt8[0xBE, 0xEF]))
            @test readn(h, 4).data == deadbeef()
        end

        @testset "handles STREAM frames in wrong order" begin
            h = _qgs_handshake()
            recv!(h, _qgs_sf(rid, 2, UInt8[0xBE, 0xEF]))
            recv!(h, _qgs_sf(rid, 0, UInt8[0xDE, 0xAD]))
            @test readn(h, 4).data == deadbeef()
        end

        @testset "ignores duplicate STREAM frames" begin
            h = _qgs_handshake()
            recv!(h, _qgs_sf(rid, 0, UInt8[0xDE, 0xAD]))
            recv!(h, _qgs_sf(rid, 0, UInt8[0x13, 0x37]))
            recv!(h, _qgs_sf(rid, 2, UInt8[0xBE, 0xEF]))
            @test readn(h, 4).data == deadbeef()
            @test h.server.error === nothing
        end

        @testset "doesn't rejects a STREAM frames with an overlapping data range" begin
            h = _qgs_handshake()
            recv!(h, _qgs_sf(rid, 0, Vector{UInt8}("foob")))
            recv!(h, _qgs_sf(rid, 2, Vector{UInt8}("obar")))
            @test readn(h, 6).data == Vector{UInt8}("foobar")
            @test h.server.error === nothing
        end

        @testset "closing" begin
            @testset "with FIN bit" begin
                @testset "returns EOFs" begin
                    h = _qgs_handshake()
                    recv!(h, _qgs_sf(rid, 0, deadbeef(); fin = true))
                    r = readn(h, 4)
                    @test r.data == deadbeef() && r.fin
                    @test !haskey(h.server.streams, rid)  # onStreamCompleted
                    r = readn(h, 4)
                    @test isempty(r.data) && r.fin
                end

                @testset "handles out-of-order frames" begin
                    h = _qgs_handshake()
                    recv!(h, _qgs_sf(rid, 2, UInt8[0xBE, 0xEF]; fin = true))
                    recv!(h, _qgs_sf(rid, 0, UInt8[0xDE, 0xAD]))
                    r = readn(h, 4)
                    @test r.data == deadbeef() && r.fin
                    @test !haskey(h.server.streams, rid)
                    r = readn(h, 4)
                    @test isempty(r.data) && r.fin
                end

                @testset "returns EOFs with partial read" begin
                    h = _qgs_handshake()
                    recv!(h, _qgs_sf(rid, 0, UInt8[0xDE, 0xAD]; fin = true))
                    r = readn(h, 4)
                    @test r.data == UInt8[0xDE, 0xAD] && r.fin
                    @test !haskey(h.server.streams, rid)
                end

                @testset "handles immediate FINs" begin
                    h = _qgs_handshake()
                    recv!(h, _qgs_sf(rid, 0, UInt8[]; fin = true))
                    r = readn(h, 4)
                    @test isempty(r.data) && r.fin
                    @test !haskey(h.server.streams, rid)
                end
            end
        end
    end

    @testset "stream cancellations" begin
        @testset "canceling read" begin
            @testset "queues a STOP_SENDING frame" begin
                h = _qgs_handshake()
                recv!(h, _qgs_sf(rid, 0, UInt8[]))
                QGS._stream_stop_sending!(h.server, rid, UInt64(1234))
                ss = _qgs_of(_qgs_flush!(h, false), :stop_sending)
                @test length(ss) == 1
                @test ss[1].id == rid && ss[1].code == 1234
            end

            @testset "doesn't send a STOP_SENDING frame, if the FIN was already read" begin
                h = _qgs_handshake()
                recv!(h, _qgs_sf(rid, 0, Vector{UInt8}("foobar"); fin = true))
                r = readn(h, 100)
                @test length(r.data) == 6 && r.fin
                QGS._stream_stop_sending!(h.server, rid, UInt64(1234))
                @test isempty(_qgs_of(_qgs_flush!(h, false), :stop_sending))
            end

            @testset "doesn't send a STOP_SENDING frame, if the stream was already reset" begin
                h = _qgs_handshake()
                recv!(h, _qgs_rst(rid, 1337, 42))
                QGS._stream_stop_sending!(h.server, rid, UInt64(1234))
                @test isempty(_qgs_of(_qgs_flush!(h, false), :stop_sending))
                # The read reports the peer's reset.
                r = readn(h, 1)
                @test isempty(r.data) && r.fin && r.reset_code == 1337
            end

            @testset "sends a STOP_SENDING after receiving the final offset" begin
                h = _qgs_handshake()
                recv!(h, _qgs_sf(rid, 0, Vector{UInt8}("foobar"); fin = true))
                QGS._stream_stop_sending!(h.server, rid, UInt64(1234))
                @test length(_qgs_of(_qgs_flush!(h, false), :stop_sending)) == 1
                r = readn(h, 1)
                @test isempty(r.data)
                @test !haskey(h.server.streams, rid)
            end

            @testset "completes the stream when receiving the Fin after the stream was canceled" begin
                h = _qgs_handshake()
                recv!(h, _qgs_sf(rid, 0, UInt8[]))
                QGS._stream_stop_sending!(h.server, rid, UInt64(1234))
                recv!(h, _qgs_sf(rid, 1000, UInt8[]; fin = true))
                @test h.server.error === nothing
                # The stream completes (its credit and stream count return to
                # the peer) without the application reading.
                @test !haskey(h.server.streams, rid)
                # The 1000 bytes of final size return to the connection window,
                # though they never arrived (RFC 9000 Section 4.5).
                @test h.server.data_consumed >= 1000
            end

            @testset "handles duplicate FinBits after the stream was canceled" begin
                h = _qgs_handshake()
                recv!(h, _qgs_sf(rid, 0, UInt8[]))
                QGS._stream_stop_sending!(h.server, rid, UInt64(1234))
                recv!(h, _qgs_sf(rid, 1000, UInt8[]; fin = true))
                recv!(h, _qgs_sf(rid, 1000, UInt8[]; fin = true))
                @test h.server.error === nothing
            end
        end

        @testset "receiving RESET_STREAM frames" begin
            rst() = _qgs_rst(rid, 1234, 42)

            @testset "doesn't allow further calls to Read" begin
                h = _qgs_handshake()
                recv!(h, rst())
                r = readn(h, 1)
                @test isempty(r.data) && r.fin && r.reset_code == 1234
                @test !haskey(h.server.streams, rid)  # onStreamCompleted
            end

            @testset "errors when receiving a RESET_STREAM with an inconsistent offset" begin
                h = _qgs_handshake()
                recv!(h, _qgs_sf(rid, 10, UInt8[]; fin = true))
                recv!(h, rst())
                @test _qgs_code(h.server) == QGS._FINAL_SIZE_ERROR
            end

            @testset "ignores duplicate RESET_STREAM frames" begin
                h = _qgs_handshake()
                recv!(h, rst())
                recv!(h, rst())
                @test h.server.error === nothing
                @test h.server.data_received == 42  # counted once
            end

            @testset "doesn't call onStreamCompleted again when the final offset was already received via Fin" begin
                h = _qgs_handshake()
                recv!(h, _qgs_sf(rid, 42, UInt8[]; fin = true))
                recv!(h, rst())
                @test h.server.error === nothing
                r = readn(h, 1)
                @test isempty(r.data) && r.reset_code == 1234
                @test !haskey(h.server.streams, rid)
                @test h.server.peer_closed_uni == 1
            end

            @testset "doesn't do anything when it was closed for shutdown" begin
                h = _qgs_handshake()
                QGS._close_connection!(h.server, UInt64(0x42), "shutdown", h.now)
                recv!(h, rst())
                @test h.server.error.code == 0x42 && h.server.error.app
            end

            @testset "handles RESET_STREAM after CancelRead" begin
                h = _qgs_handshake()
                recv!(h, _qgs_sf(rid, 0, UInt8[]))
                QGS._stream_stop_sending!(h.server, rid, UInt64(1234))
                recv!(h, rst())
                @test h.server.error === nothing
                # The final size is credited to the connection window (Abandon).
                @test h.server.data_consumed == 42
                # The stream completes on the RESET_STREAM, without a read.
                @test !haskey(h.server.streams, rid)
                @test h.server.peer_closed_uni == 1
                r = readn(h, 1)
                @test isempty(r.data) && r.fin
            end
        end
    end

    @testset "errors when a STREAM frame causes a flow control violation" begin
        h = _qgs_handshake(server_limits = QGS._StreamLimits(max_stream_data = 7))
        recv!(h, _qgs_sf(rid, 2, Vector{UInt8}("foobar")))
        @test _qgs_code(h.server) == QGS._FLOW_CONTROL_ERROR
    end
end

@testset "Send Stream" begin
    # The client's own unidirectional stream.
    function sender(; kw...)
        h = _qgs_handshake(; kw...)
        id = QGS._open_stream!(h.client; bidi = false)
        return h, h.client, id
    end
    w!(conn, id, data; fin = false) = QGS._stream_write!(conn, id, data; fin)
    reset!(conn, id, code) = QGS._stream_reset!(conn, id, UInt64(code))
    close!(conn, id) = QGS._stream_write!(conn, id, UInt8[]; fin = true)
    acked!(conn, f) = QGS._on_stream_frame_acked!(conn, f)
    lost!(conn, f) = QGS._on_stream_frame_lost!(conn, f)
    small_window(n) = (; server_limits = QGS._StreamLimits(max_stream_data = n))

    @testset "writing" begin
        @testset "writes and gets all data at once" begin
            h, conn, id = sender()
            w!(conn, id, Vector{UInt8}("foobar"))
            p = _qgs_pop!(conn, id)
            @test length(p.stream) == 1
            f = p.stream[1]
            @test f.data == Vector{UInt8}("foobar") && !f.fin && f.offset == 0
            @test _qgs_stream_length_fields(p.buf) == [true]
            @test conn.streams[id].send.max_sent == 6  # writeOffset
            @test !_qgs_has_more(conn, id)
        end

        @testset "writes and gets data in two turns" begin
            h, conn, id = sender()
            w!(conn, id, Vector{UInt8}("foobar"))
            p = _qgs_pop!(conn, id, _qgs_hdr(0) + 3)
            @test only(p.stream).offset == 0 && !only(p.stream).fin && only(p.stream).data == Vector{UInt8}("foo")
            p = _qgs_pop!(conn, id)
            @test only(p.stream).offset == 3 && !only(p.stream).fin && only(p.stream).data == Vector{UInt8}("bar")
            @test isempty(_qgs_pop!(conn, id, 1000).frames)
        end

        @testset "bundles small writes" begin
            h, conn, id = sender()
            w!(conn, id, Vector{UInt8}("foo"))
            w!(conn, id, Vector{UInt8}("bar"))
            p = _qgs_pop!(conn, id)
            @test only(p.stream).offset == 0 && !only(p.stream).fin && only(p.stream).data == Vector{UInt8}("foobar")
        end

        @testset "writes and gets data in multiple turns, for large writes" begin
            h, conn, id = sender()
            w!(conn, id, _qgs_data_at(0, 5000))
            total = 0
            for i in 0:4
                f = only(_qgs_pop!(conn, id, 1100).stream)
                @test abs(f.offset - 1100 * i) <= 10 * i
                @test !f.fin
                @test f.data == _qgs_data_at(f.offset, length(f.data))
                total += length(f.data)
            end
            @test total == 5000
        end

        # quic-go's Write blocks until its data is dequeued; ours copies it into
        # the send buffer and returns, so only the framing is ported.
        @testset "unblocks Write as soon as a STREAM frame can be buffered" begin
            h, conn, id = sender()
            w!(conn, id, _qgs_data_at(0, _QGS_MAX_PACKET_BUFFER + 3))
            p = _qgs_pop!(conn, id, _qgs_hdr(0) + 2)
            @test length(only(p.stream).data) == 2
            @test _qgs_has_more(conn, id)
            p = _qgs_pop!(conn, id, _qgs_hdr(1) + 1)
            @test length(only(p.stream).data) == 1
            @test _qgs_has_more(conn, id)
        end

        @testset "only unblocks Write once a previously buffered STREAM frame has been fully dequeued" begin
            h, conn, id = sender()
            w!(conn, id, Vector{UInt8}("foobar"))
            w!(conn, id, _qgs_data_at(0, _QGS_MAX_PACKET_BUFFER))
            p = _qgs_pop!(conn, id, _qgs_hdr(0) + 2)
            @test only(p.stream).data == Vector{UInt8}("fo")
            @test _qgs_has_more(conn, id)
            p = _qgs_pop!(conn, id, _qgs_hdr(2) + 4)
            @test only(p.stream).data == Vector{UInt8}("obar")
            @test _qgs_has_more(conn, id)
        end

        @testset "popStreamFrame returns nil if no data is available" begin
            h, conn, id = sender()
            @test isempty(_qgs_pop!(conn, id, 1000).frames)
            @test !_qgs_has_more(conn, id)
        end

        @testset "says if it has more data for writing" begin
            h, conn, id = sender()
            w!(conn, id, zeros(UInt8, 100))
            p = _qgs_pop!(conn, id, 50)
            @test !only(p.stream).fin
            @test _qgs_has_more(conn, id)
            p = _qgs_pop!(conn, id)
            @test !only(p.stream).fin
            @test !_qgs_has_more(conn, id)
            @test isempty(_qgs_pop!(conn, id).frames)
        end

        @testset "copies the slice while writing" begin
            h, conn, id = sender()
            s = Vector{UInt8}("foo")
            w!(conn, id, s)
            p = _qgs_pop!(conn, id, 4 + 1)
            @test only(p.stream).data == Vector{UInt8}("f")
            s[2] = UInt8('e')
            p = _qgs_pop!(conn, id, 100)
            @test only(p.stream).data == Vector{UInt8}("oo")
        end

        @testset "returns when given a nil input" begin
            h, conn, id = sender()
            w!(conn, id, UInt8[])
            @test !_qgs_has_more(conn, id)
            @test isempty(_qgs_pop!(conn, id).frames)
        end

        @testset "returns when given an empty slice" begin
            h, conn, id = sender()
            w!(conn, id, Vector{UInt8}(""))
            @test !_qgs_has_more(conn, id)
        end

        @testset "flow control blocking" begin
            @testset "queues a BLOCKED frame if the stream is flow control blocked" begin
                h, conn, id = sender(; small_window(3)...)
                w!(conn, id, Vector{UInt8}("foobar"))
                p = _qgs_pop!(conn, id, 1000)
                @test length(only(p.stream).data) == 3
                @test _qgs_has_more(conn, id)
                p2 = _qgs_pop!(conn, id, 1000)
                @test isempty(p2.stream)
                @test !_qgs_can_send(conn, id)
                frames = vcat(p2.frames, _qgs_flush!(h, true))
                @test any(f -> f.type == :stream_data_blocked && f.id == id && f.limit == 3, frames)
            end
        end

        @testset "closing" begin
            @testset "doesn't allow writes after it has been closed" begin
                h, conn, id = sender()
                close!(conn, id)
                @test_throws ArgumentError w!(conn, id, Vector{UInt8}("foobar"))
            end

            @testset "allows FIN" begin
                h, conn, id = sender()
                close!(conn, id)
                p = _qgs_pop!(conn, id, 1000)
                f = only(p.stream)
                @test isempty(f.data) && f.fin
                @test _qgs_stream_length_fields(p.buf) == [true]
                @test !_qgs_has_more(conn, id)
            end

            @testset "doesn't send a FIN when there's still data" begin
                h, conn, id = sender()
                w!(conn, id, Vector{UInt8}("foobar"))
                close!(conn, id)
                p = _qgs_pop!(conn, id, 3 + 4)
                @test only(p.stream).data == Vector{UInt8}("foo") && !only(p.stream).fin
                p = _qgs_pop!(conn, id)
                @test only(p.stream).data == Vector{UInt8}("bar") && only(p.stream).fin
            end

            @testset "doesn't send a FIN when there's still data, for long writes" begin
                h, conn, id = sender()
                w!(conn, id, _qgs_data_at(0, 5000))
                close!(conn, id)
                for i in 1:5
                    f = only(_qgs_pop!(conn, id, 1100).stream)
                    @test f.data == _qgs_data_at(f.offset, length(f.data))
                    @test f.fin == (i == 5)
                end
            end

            @testset "doesn't allow FIN after it is closed for shutdown" begin
                h, conn, id = sender()
                QGS._close_connection!(conn, UInt64(0), "test", h.now)
                @test_throws ArgumentError close!(conn, id)
                @test isempty(_qgs_of(_qgs_flush!(h, true), :stream))
            end

            @testset "doesn't allow FIN twice" begin
                h, conn, id = sender()
                close!(conn, id)
                p = _qgs_pop!(conn, id, 1000)
                @test isempty(only(p.stream).data) && only(p.stream).fin
                @test isempty(_qgs_pop!(conn, id, 1000).frames)
                @test !_qgs_has_more(conn, id)
            end
        end

        @testset "closing for shutdown" begin
            @testset "returns errors when the stream is cancelled" begin
                h, conn, id = sender()
                QGS._close_connection!(conn, UInt64(0), "test", h.now)
                @test_throws ArgumentError w!(conn, id, Vector{UInt8}("foo"))
            end

            @testset "doesn't get data for writing if an error occurred" begin
                h, conn, id = sender()
                w!(conn, id, _qgs_data_at(0, 5000))
                p = _qgs_pop!(conn, id, 50)
                @test length(p.stream) == 1
                @test _qgs_has_more(conn, id)
                QGS._close_connection!(conn, UInt64(0), "test", h.now)
                @test isempty(_qgs_of(_qgs_flush!(h, true), :stream))
            end
        end
    end

    @testset "handling MAX_STREAM_DATA frames" begin
        @testset "informs the flow controller" begin
            h, conn, id = sender(; small_window(100)...)
            _qcn_inject!(h, false, _qgs_msd(id, 0x1337))
            @test conn.streams[id].send_max == 0x1337
        end

        @testset "says when it has data for sending" begin
            h, conn, id = sender(; small_window(3)...)
            w!(conn, id, Vector{UInt8}("foobar"))
            _qgs_pop!(conn, id)
            @test !_qgs_can_send(conn, id)
            _qcn_inject!(h, false, _qgs_msd(id, 42))
            @test _qgs_can_send(conn, id)
            @test id in conn.send_queue
        end

        @testset "doesn't say it has data for sending if the MAX_STREAM_DATA frame was reordered" begin
            h, conn, id = sender(; small_window(3)...)
            w!(conn, id, Vector{UInt8}("foobar"))
            _qgs_pop!(conn, id)
            _qcn_inject!(h, false, _qgs_msd(id, 2))
            @test conn.streams[id].send_max == 3
            @test !_qgs_can_send(conn, id)
        end
    end

    @testset "stream cancellations" begin
        @testset "canceling writing" begin
            @testset "queues a RESET_STREAM frame" begin
                h, conn, id = sender()
                w!(conn, id, zeros(UInt8, 1234))
                _qgs_pop!(conn, id)
                reset!(conn, id, 9876)
                p = _qgs_pop!(conn, id)
                @test p.frames == [(type = :reset_stream, id = id, code = UInt64(9876), final_size = 1234)]
            end

            @testset "retransmits a RESET_STREAM frame" begin
                h, conn, id = sender()
                reset!(conn, id, 9876)
                p = _qgs_pop!(conn, id)
                @test only(p.frames).type == :reset_stream
                lost!(conn, only(p.sent))
                p2 = _qgs_pop!(conn, id)
                @test p2.frames == p.frames
            end

            @testset "returns a nil error when the whole slice has been sent out" begin
                h, conn, id = sender()
                @test _qgs_err(() -> w!(conn, id, _qgs_data_at(0, 100))) === nothing
                _qgs_pop!(conn, id)
                reset!(conn, id, 1234)
                @test conn.error === nothing
            end

            for (name, n) in (("doesn't pop STREAM frames after being canceled", 100),
                              ("doesn't pop STREAM frames after being canceled, for large writes", 5000))
                @testset "$name" begin
                    h, conn, id = sender()
                    w!(conn, id, _qgs_data_at(0, n))
                    p = _qgs_pop!(conn, id, 50)
                    @test length(p.stream) == 1
                    @test _qgs_has_more(conn, id)
                    reset!(conn, id, 1234)
                    @test isempty(_qgs_pop!(conn, id, 10).stream)
                    @test !_qgs_has_more(conn, id)
                end
            end

            @testset "ignores acknowledgements for STREAM frames after it was cancelled" begin
                h, conn, id = sender()
                w!(conn, id, _qgs_data_at(0, 100))
                p = _qgs_pop!(conn, id, 50)
                reset!(conn, id, 1234)
                acked!(conn, only(p.sent))
                @test haskey(conn.streams, id)  # the RESET_STREAM is not acknowledged yet
            end

            @testset "only cancels once" begin
                h, conn, id = sender()
                reset!(conn, id, 1234)
                reset!(conn, id, 4321)
                @test _qgs_pop!(conn, id).frames == [(type = :reset_stream, id = id, code = UInt64(1234), final_size = 0)]
                @test isempty(_qgs_pop!(conn, id).frames)
            end

            @testset "queues a RESET_STREAM frame, even if the stream was already closed" begin
                h, conn, id = sender()
                close!(conn, id)
                reset!(conn, id, 123)
                p = _qgs_pop!(conn, id)
                @test length(_qgs_of(p.frames, :reset_stream)) == 1
                @test isempty(p.stream)
                @test !_qgs_has_more(conn, id)
            end
        end

        @testset "receiving STOP_SENDING frames" begin
            @testset "queues a RESET_STREAM frames, and copies the error code from the STOP_SENDING frame" begin
                h, conn, id = sender()
                _qcn_inject!(h, false, _qgs_ss(id, 101))
                rs = _qgs_of(_qgs_flush!(h, true), :reset_stream)
                @test [(f.id, f.code, f.final_size) for f in rs] == [(id, UInt64(101), 0)]
                # Once the RESET_STREAM is acknowledged, quic-go still keeps the
                # stream: "The application needs to learn about the cancellation first."
                _qcn_run!(h; done = h -> false, max_time = h.now + 2_000_000_000)
                @test QGS._stream_stop_code(conn, id) == 101
            end

            @testset "discards the stream when CancelWrite is called after receiving STOP_SENDING" begin
                h, conn, id = sender()
                _qcn_inject!(h, false, _qgs_ss(id, 101))
                reset!(conn, id, 101)
                @test _qgs_pop!(conn, id).frames == [(type = :reset_stream, id = id, code = UInt64(101), final_size = 0)]
            end

            @testset "handles Close after STOP_SENDING" begin
                h, conn, id = sender()
                _qcn_inject!(h, false, _qgs_ss(id, 123))
                @test _qgs_err(() -> close!(conn, id)) === nothing
                p = _qgs_pop!(conn, id)
                @test isempty(p.stream)
                @test length(_qgs_of(p.frames, :reset_stream)) == 1
            end

            @testset "handles STOP_SENDING after sending the FIN" begin
                h, conn, id = sender()
                close!(conn, id)
                @test only(_qgs_pop!(conn, id).stream).fin
                _qcn_inject!(h, false, _qgs_ss(id, 123))
                @test _qgs_pop!(conn, id).frames == [(type = :reset_stream, id = id, code = UInt64(123), final_size = 0)]
            end

            @testset "handles STOP_SENDING after Close, but before sending the FIN" begin
                h, conn, id = sender()
                close!(conn, id)
                _qcn_inject!(h, false, _qgs_ss(id, 123))
                p = _qgs_pop!(conn, id)
                @test isempty(p.stream)
                @test length(_qgs_of(p.frames, :reset_stream)) == 1
            end
        end
    end

    @testset "retransmissions" begin
        # A frame "foobar" at 0x42, lost; everything before it acknowledged.
        function lost_foobar()
            h, conn, id = sender()
            w!(conn, id, _qgs_data_at(0, 0x42 + 6))
            _qgs_pop!(conn, id)
            acked!(conn, QGS._SentFrame(QGS._SF_STREAM, id, Int64(0), Int64(0x42), false))
            lost!(conn, QGS._SentFrame(QGS._SF_STREAM, id, Int64(0x42), Int64(6), false))
            return h, conn, id
        end

        @testset "queues and retrieves frames" begin
            h, conn, id = lost_foobar()
            p = _qgs_pop!(conn, id)
            f = only(p.stream)
            @test f.offset == 0x42 && f.data == _qgs_data_at(0x42, 6)
            @test _qgs_stream_length_fields(p.buf) == [true]
        end

        @testset "splits a retransmission" begin
            h, conn, id = lost_foobar()
            p = _qgs_pop_data!(conn, id, 3)
            @test only(p.stream).offset == 0x42 && only(p.stream).data == _qgs_data_at(0x42, 3)
            @test _qgs_has_more(conn, id)
            p = _qgs_pop!(conn, id)
            @test only(p.stream).offset == 0x45 && only(p.stream).data == _qgs_data_at(0x45, 3)
        end

        @testset "returns nil if the size is too small" begin
            h, conn, id = lost_foobar()
            @test isempty(_qgs_pop_raw!(conn, id, 2).frames)
            @test _qgs_has_more(conn, id)
        end

        @testset "queues lost STREAM frames" begin
            h, conn, id = sender()
            w!(conn, id, Vector{UInt8}("foobar"))
            p = _qgs_pop!(conn, id)
            @test only(p.stream).data == Vector{UInt8}("foobar")
            lost!(conn, only(p.sent))
            @test only(_qgs_pop!(conn, id).stream).data == Vector{UInt8}("foobar")
        end

        @testset "doesn't queue retransmissions for a stream that was canceled" begin
            h, conn, id = sender()
            w!(conn, id, Vector{UInt8}("foobar"))
            p = _qgs_pop!(conn, id, 100)
            reset!(conn, id, 9876)
            lost!(conn, only(p.sent))
            @test isempty(conn.streams[id].send.pending)
        end
    end

    @testset "determining when a stream is completed" begin
        # Pops 20-byte frames until `stop(frame)`.
        function pop_small(conn, id, stop)
            sent = QGS._SentFrame[]
            while true
                p = _qgs_pop!(conn, id, 20)
                isempty(p.sent) && continue
                append!(sent, p.sent)
                stop(only(p.stream)) && return sent
            end
        end

        @testset "says when a stream is completed" begin
            h, conn, id = sender()
            w!(conn, id, zeros(UInt8, 100))
            sent = pop_small(conn, id, f -> !_qgs_has_more(conn, id))
            # All acknowledged, but the FIN is still to be sent.
            foreach(f -> acked!(conn, f), sent)
            @test haskey(conn.streams, id)
            close!(conn, id)
            p = _qgs_pop!(conn, id)
            @test only(p.stream).fin
            acked!(conn, only(p.sent))
            @test !haskey(conn.streams, id)  # onStreamCompleted
        end

        @testset "waits until a RESET_STREAM is acknowledged" begin
            h, conn, id = sender()
            w!(conn, id, Vector{UInt8}("foobar"))
            p = _qgs_pop!(conn, id, 20)
            @test length(only(p.stream).data) == 6
            @test !_qgs_has_more(conn, id)
            reset!(conn, id, 1234)
            cf = _qgs_pop!(conn, id)
            @test only(cf.frames).type == :reset_stream
            acked!(conn, only(p.sent))
            @test haskey(conn.streams, id)
            acked!(conn, only(cf.sent))
            @test !haskey(conn.streams, id)
        end

        @testset "says when a stream is completed, if Close() is called before popping the frame" begin
            h, conn, id = sender()
            w!(conn, id, zeros(UInt8, 100))
            close!(conn, id)
            p = _qgs_pop!(conn, id)
            @test !_qgs_has_more(conn, id)
            @test only(p.stream).fin
            acked!(conn, only(p.sent))
            @test !haskey(conn.streams, id)
        end

        @testset "doesn't say it's completed when there are frames waiting to be retransmitted" begin
            h, conn, id = sender()
            w!(conn, id, _qgs_data_at(0, 100))
            close!(conn, id)
            sent = pop_small(conn, id, f -> f.fin)
            foreach(f -> acked!(conn, f), sent[2:end])
            lost!(conn, sent[1])
            @test haskey(conn.streams, id)
            ret = _qgs_pop!(conn, id)
            @test length(ret.sent) == 1
            acked!(conn, only(ret.sent))
            @test !haskey(conn.streams, id)
        end

        @testset "retransmits data until everything has been acknowledged" begin
            h, conn, id = sender()
            rng = Xoshiro(4)
            data_len = 1 << 22
            data = rand(rng, UInt8, data_len)
            w!(conn, id, data; fin = true)
            conn.peer_max_data = typemax(Int64) ÷ 2
            s = conn.streams[id]
            received = zeros(UInt8, data_len)
            iterations = 0
            while haskey(conn.streams, id) && iterations < 1_000_000
                iterations += 1
                # The send window has 50 to 549 bytes left.
                s.send_max = s.send.max_sent + rand(rng, 50:549)
                p = _qgs_pop!(conn, id, rand(rng, 100:399))
                isempty(p.sent) && continue
                f = only(p.stream)
                if rand(rng, 0:99) < 50
                    received[(f.offset + 1):(f.offset + length(f.data))] = f.data
                    acked!(conn, only(p.sent))
                else
                    lost!(conn, only(p.sent))
                end
            end
            @test !haskey(conn.streams, id)
            @test received == data
        end
    end
end

@testset "Stream" begin
    @testset "completing" begin
        # The client's bidirectional stream 0, on the server.
        function opened()
            h = _qgs_handshake()
            id = QGS._open_stream!(h.client)
            return h, id
        end
        recv_side_done!(h, id) = begin
            QGS._stream_write!(h.client, id, UInt8[0x01]; fin = true)
            _qcn_exchange!(h)
            r = QGS._stream_read!(h.server, id)
            @test r.fin
        end
        send_side_done!(h, id) = begin
            QGS._stream_write!(h.server, id, UInt8[0x02]; fin = true)
            # Until the server's FIN is acknowledged.
            _qcn_run!(h; app = h -> QGS._stream_read!(h.client, id), done = h -> QGS._send_all_acked(h.server.streams[id].send),
                max_time = h.now + 5_000_000_000)
        end

        @testset "is not completed when only the receive side is completed" begin
            h, id = opened()
            recv_side_done!(h, id)
            @test haskey(h.server.streams, id)
        end

        @testset "is not completed when only the send side is completed" begin
            h, id = opened()
            QGS._stream_write!(h.client, id, UInt8[0x01])
            _qcn_exchange!(h)
            send_side_done!(h, id)
            @test QGS._send_all_acked(h.server.streams[id].send)
            @test haskey(h.server.streams, id)
        end

        @testset "is completed when both sides are completed" begin
            h, id = opened()
            recv_side_done!(h, id)
            QGS._stream_write!(h.server, id, UInt8[0x02]; fin = true)
            @test _qcn_run!(h; app = h -> haskey(h.client.streams, id) && QGS._stream_read!(h.client, id),
                done = h -> !haskey(h.server.streams, id), max_time = h.now + 5_000_000_000)
        end
    end
end

@testset "Streams Map" begin
    # One side's streams ("me"), with frames injected by its peer.
    function map_harness(persp; me_limits = QGS._StreamLimits(max_streams_bidi = 111, max_streams_uni = 222),
            peer_limits = QGS._StreamLimits(max_streams_bidi = 1_000_000, max_streams_uni = 1_000_000))
        kw = persp == :server ? (; server_limits = me_limits, client_limits = peer_limits) :
             (; client_limits = me_limits, server_limits = peer_limits)
        h = _qgs_handshake(; kw...)
        mc = persp == :client
        return h, (mc ? h.client : h.server), (mc ? h.server : h.client), mc
    end
    from_peer!(h, mc, frames) = _qcn_inject!(h, !mc, frames)
    # The peer opens a stream and sends a byte on it.
    function peer_open!(h, mc; bidi = true)
        peer = mc ? h.server : h.client
        id = QGS._open_stream!(peer; bidi)
        QGS._stream_write!(peer, id, UInt8[0x01])
        _qcn_exchange!(h)
        return id
    end
    # Finishes both sides of stream `id` until "me" frees it.
    function complete!(h, mc, id)
        me, peer = mc ? (h.client, h.server) : (h.server, h.client)
        step(h) = for c in (me, peer)
            s = get(c.streams, id, nothing)
            s === nothing && continue
            s.send !== nothing && !s.send.fin && QGS._stream_write!(c, id, UInt8[]; fin = true)
            s.recv !== nothing && QGS._stream_read!(c, id)
        end
        @test _qcn_run!(h; app = step, done = h -> !haskey(me.streams, id), max_time = h.now + 10_000_000_000)
    end
    ok(conn, id) = conn.error === nothing && haskey(conn.streams, UInt64(id))
    state_error(conn) = _qgs_code(conn) == QGS._STREAM_STATE_ERROR

    for persp in (:server, :client)
        # firstIncomingBidi, firstOutgoingBidi, firstIncomingUni, firstOutgoingUni
        in_bidi, out_bidi, in_uni, out_uni = persp == :server ? (0, 1, 2, 3) : (1, 0, 3, 2)
        @testset "$persp" begin
            @testset "opening" begin
                @testset "opens bidirectional streams" begin
                    h, me, peer, mc = map_harness(persp)
                    @test QGS._open_stream!(me) == out_bidi
                    @test QGS._open_stream!(me) == out_bidi + 4
                end

                @testset "opens unidirectional streams" begin
                    h, me, peer, mc = map_harness(persp)
                    @test QGS._open_stream!(me; bidi = false) == out_uni
                    @test QGS._open_stream!(me; bidi = false) == out_uni + 4
                end
            end

            @testset "accepting" begin
                @testset "accepts bidirectional streams" begin
                    h, me, peer, mc = map_harness(persp)
                    from_peer!(h, mc, _qgs_sf(in_bidi, 0, UInt8[]))
                    @test QGS._accept_stream!(me) == in_bidi
                    @test QGS._can_send(me, UInt64(in_bidi)) && QGS._can_receive(me, UInt64(in_bidi))
                end

                @testset "accepts unidirectional streams" begin
                    h, me, peer, mc = map_harness(persp)
                    from_peer!(h, mc, _qgs_sf(in_uni, 0, UInt8[]))
                    @test QGS._accept_stream!(me) == in_uni
                    @test !QGS._can_send(me, UInt64(in_uni)) && QGS._can_receive(me, UInt64(in_uni))
                end
            end

            @testset "deleting" begin
                for (what, bidi) in (("bidirectional", true), ("unidirectional", false))
                    @testset "deletes outgoing $what streams" begin
                        h, me, peer, mc = map_harness(persp)
                        id = QGS._open_stream!(me; bidi)
                        @test id == (bidi ? out_bidi : out_uni)
                        complete!(h, mc, id)
                        # A frame for it now finds nothing, without error.
                        from_peer!(h, mc, _qgs_msd(id, 1 << 30))
                        @test me.error === nothing && !haskey(me.streams, id)
                    end

                    @testset "deletes incoming $what streams" begin
                        h, me, peer, mc = map_harness(persp)
                        id = peer_open!(h, mc; bidi)
                        @test id == (bidi ? in_bidi : in_uni)
                        @test haskey(me.streams, id)
                        complete!(h, mc, id)
                        from_peer!(h, mc, _qgs_sf(id, 0, UInt8[0x01]))
                        @test me.error === nothing && !haskey(me.streams, id)
                    end

                    @testset "accepts $(bidi ? "bidirectional" : "unirectional") streams after they have been deleted" begin
                        h, me, peer, mc = map_harness(persp)
                        id = peer_open!(h, mc; bidi)
                        complete!(h, mc, id)
                        @test QGS._accept_stream!(me) == id
                    end
                end
            end

            @testset "getting streams" begin
                @testset "send streams" begin
                    @testset "gets an outgoing bidirectional stream" begin
                        h, me, peer, mc = map_harness(persp)
                        QGS._open_stream!(me)
                        from_peer!(h, mc, _qgs_msd(out_bidi, 1 << 30))
                        @test ok(me, out_bidi)
                    end

                    @testset "errors when the peer tries to open a higher outgoing bidirectional stream" begin
                        h, me, peer, mc = map_harness(persp)
                        from_peer!(h, mc, _qgs_msd(out_bidi + 5 * 4, 1 << 30))
                        @test state_error(me)
                    end

                    @testset "gets an outgoing unidirectional stream" begin
                        h, me, peer, mc = map_harness(persp)
                        QGS._open_stream!(me; bidi = false)
                        from_peer!(h, mc, _qgs_msd(out_uni, 1 << 30))
                        @test ok(me, out_uni)
                    end

                    # (quic-go's name for the unidirectional case.)
                    @testset "errors when the peer tries to open a higher outgoing bidirectional stream" begin
                        h, me, peer, mc = map_harness(persp)
                        from_peer!(h, mc, _qgs_msd(out_uni + 5 * 4, 1 << 30))
                        @test state_error(me)
                    end

                    @testset "gets an incoming bidirectional stream" begin
                        h, me, peer, mc = map_harness(persp)
                        from_peer!(h, mc, _qgs_msd(in_bidi + 4 * 7, 1 << 30))
                        @test ok(me, in_bidi + 4 * 7)
                    end

                    @testset "errors when trying to get an incoming unidirectional stream" begin
                        h, me, peer, mc = map_harness(persp)
                        from_peer!(h, mc, _qgs_msd(in_uni, 1 << 30))
                        @test state_error(me)
                    end
                end

                @testset "receive streams" begin
                    @testset "gets an outgoing bidirectional stream" begin
                        h, me, peer, mc = map_harness(persp)
                        QGS._open_stream!(me)
                        from_peer!(h, mc, _qgs_sf(out_bidi, 0, UInt8[]))
                        @test ok(me, out_bidi)
                    end

                    @testset "errors when the peer tries to open a higher outgoing bidirectional stream" begin
                        h, me, peer, mc = map_harness(persp)
                        from_peer!(h, mc, _qgs_sf(out_bidi + 5 * 4, 0, UInt8[]))
                        @test state_error(me)
                    end

                    @testset "gets an incoming bidirectional stream" begin
                        h, me, peer, mc = map_harness(persp)
                        from_peer!(h, mc, _qgs_sf(in_bidi + 4 * 7, 0, UInt8[]))
                        @test ok(me, in_bidi + 4 * 7)
                    end

                    @testset "gets an incoming unidirectional stream" begin
                        h, me, peer, mc = map_harness(persp)
                        from_peer!(h, mc, _qgs_sf(in_uni + 4 * 10, 0, UInt8[]))
                        @test ok(me, in_uni + 4 * 10)
                    end

                    @testset "errors when trying to get an outgoing unidirectional stream" begin
                        h, me, peer, mc = map_harness(persp)
                        from_peer!(h, mc, _qgs_sf(out_uni, 0, UInt8[]))
                        @test state_error(me)
                    end
                end
            end

            @testset "processes the parameter for outgoing streams" begin
                attempts_blocked = 0
                if persp == :client
                    # Before the server's transport parameters, no streams.
                    # It queues STREAMS_BLOCKED(0), sent once it has 1-RTT keys.
                    client = _QcnHarness().client
                    @test QGS._open_stream!(client) === nothing
                    @test client.streams_blocked_bidi_pending && client.streams_blocked_bidi_at == 0
                    attempts_blocked += 1
                end
                h, me, peer, mc = map_harness(persp; peer_limits = QGS._StreamLimits(max_streams_bidi = 5, max_streams_uni = 8))
                mark = _qgs_mark(h)
                @test [QGS._open_stream!(me) for _ in 1:5] == [out_bidi + 4i for i in 0:4]
                @test QGS._open_stream!(me) === nothing
                @test [QGS._open_stream!(me; bidi = false) for _ in 1:8] == [out_uni + 4i for i in 0:7]
                @test QGS._open_stream!(me; bidi = false) === nothing
                _qcn_exchange!(h)
                blocked = _qgs_of(_qgs_sent(h, mc, mark), :streams_blocked)
                # A STREAMS_BLOCKED frame each time a stream cannot be opened
                # (RFC 9000 Section 4.6): 3 in quic-go's test, which also opens
                # before the limits are known on the server's side.
                @test sort([(f.bidi, f.limit) for f in blocked]) == [(false, 8), (true, 5)]
                @test length(blocked) + attempts_blocked == (persp == :client ? 3 : 2)
            end

            @testset "handling MAX_STREAMS frames" begin
                for (what, bidi, first_id) in (("bidirectional", true, out_bidi), ("unidirectional", false, out_uni))
                    @testset "processes IDs for outgoing $what streams" begin
                        h, me, peer, mc = map_harness(persp; peer_limits = QGS._StreamLimits(max_streams_bidi = 0, max_streams_uni = 0))
                        @test QGS._open_stream!(me; bidi) === nothing
                        from_peer!(h, mc, _qgs_ms(bidi, 1))
                        @test QGS._open_stream!(me; bidi) == first_id
                        @test QGS._open_stream!(me; bidi) === nothing
                    end
                end
            end

            @testset "sending MAX_STREAMS frames" begin
                for (what, bidi, limit) in (("bidirectional", true, 111), ("unidirectional", false, 222))
                    @testset "sends a MAX_STREAMS frame for $what streams" begin
                        h, me, peer, mc = map_harness(persp)
                        id = peer_open!(h, mc; bidi)
                        @test QGS._accept_stream!(me) == id
                        mark = _qgs_mark(h)
                        complete!(h, mc, id)
                        ms = _qgs_of(_qgs_sent(h, mc, mark), :max_streams)
                        @test [(f.bidi, f.max) for f in ms] == [(bidi, UInt64(limit + 1))]
                    end
                end
            end
        end
    end
end

@testset "Streams Map (incoming)" begin
    # The client's unidirectional streams at the server; stream number n is ID 4(n - 1) + 2.
    sid(n) = UInt64(4 * (n - 1) + 2)
    harness(max = 5) = _qgs_handshake(server_limits = QGS._StreamLimits(max_streams_uni = max))
    get_or_open!(h, n) = _qcn_inject!(h, true, _qgs_sf(sid(n), 0, UInt8[]))
    count_streams(h) = count(id -> id % 4 == 2, keys(h.server.streams))
    accept!(h) = QGS._accept_stream!(h.server)
    # The stream ends and the application reads the end.
    function delete_stream!(h, n)
        _qcn_inject!(h, true, _qgs_sf(sid(n), 0, UInt8[]; fin = true))
        @test QGS._stream_read!(h.server, sid(n)).fin
        @test !haskey(h.server.streams, sid(n))
    end
    max_streams_sent!(h) = _qgs_of(_qgs_flush!(h, false), :max_streams)

    @testset "opens all streams up to the id on GetOrOpenStream" begin
        h = harness()
        get_or_open!(h, 4)
        @test count_streams(h) == 4
    end

    @testset "starts opening streams at the right position" begin
        h = harness()
        get_or_open!(h, 2)
        @test count_streams(h) == 2
        get_or_open!(h, 5)
        @test count_streams(h) == 5
    end

    @testset "accepts streams in the right order" begin
        h = harness()
        get_or_open!(h, 2)
        @test accept!(h) == sid(1)
        @test accept!(h) == sid(2)
    end

    @testset "allows opening the maximum stream ID" begin
        h = harness()
        get_or_open!(h, 1)
        @test h.server.error === nothing && haskey(h.server.streams, sid(1))
    end

    @testset "errors when trying to get a stream ID higher than the maximum" begin
        h = harness()
        get_or_open!(h, 6)
        @test _qgs_code(h.server) == QGS._STREAM_LIMIT_ERROR
    end

    @testset "deletes streams" begin
        h = harness()
        get_or_open!(h, 1)
        @test accept!(h) == sid(1)
        delete_stream!(h, 1)
        get_or_open!(h, 1)
        @test h.server.error === nothing && !haskey(h.server.streams, sid(1))
    end

    @testset "waits until a stream is accepted before actually deleting it" begin
        h = harness()
        get_or_open!(h, 2)
        delete_stream!(h, 2)
        @test accept!(h) == sid(1)
        @test accept!(h) == sid(2)
    end

    @testset "doesn't return a stream queued for deleting from GetOrOpenStream" begin
        h = harness()
        get_or_open!(h, 1)
        @test haskey(h.server.streams, sid(1))
        delete_stream!(h, 1)
        get_or_open!(h, 1)
        @test !haskey(h.server.streams, sid(1))
        @test accept!(h) == sid(1)
    end

    @testset "sends MAX_STREAMS frames when streams are deleted" begin
        h = harness()
        get_or_open!(h, 5)
        for n in 1:5
            @test accept!(h) == sid(n)
        end
        @test isempty(max_streams_sent!(h))
        delete_stream!(h, 3)
        @test [(f.bidi, f.max) for f in max_streams_sent!(h)] == [(false, UInt64(5 + 1))]
        delete_stream!(h, 4)
        @test [(f.bidi, f.max) for f in max_streams_sent!(h)] == [(false, UInt64(5 + 2))]
    end

    @testset "using high stream limits" begin
        @testset "doesn't send MAX_STREAMS frames if they would overflow 2^60 (the maximum stream count)" begin
            max_count = Int64(1) << 60  # protocol.MaxStreamCount
            h = harness(max_count - 2)
            get_or_open!(h, 5)
            for n in 1:5
                @test accept!(h) == sid(n)
            end
            @test isempty(max_streams_sent!(h))
            delete_stream!(h, 4)
            @test [f.max for f in max_streams_sent!(h)] == [UInt64(max_count - 1)]
            delete_stream!(h, 3)
            @test [f.max for f in max_streams_sent!(h)] == [UInt64(max_count)]
            delete_stream!(h, 2)
            delete_stream!(h, 1)
            sent = try
                max_streams_sent!(h)
            catch ex
                ex
            end
            # The limit stops at 2^60 (RFC 9000 Section 19.11).
            @test sent isa Vector && isempty(sent)
            @test h.server.local_max_streams_uni == max_count
        end
    end

    @testset "randomized tests" begin
        @testset "opens and accepts streams" begin
            num = 1000
            h = harness(num)
            nums = shuffle(Xoshiro(5), 1:num)
            for batch in Iterators.partition(nums, 100)
                _qcn_inject!(h, true, reduce(vcat, [_qgs_sf(sid(n), 0, UInt8[]) for n in batch]))
            end
            @test h.server.error === nothing
            @test [accept!(h) for _ in 1:num] == [sid(n) for n in 1:num]
        end
    end
end

@testset "Streams Map (outgoing)" begin
    # The client's bidirectional streams; MAX_STREAMS from the server is SetMaxStream.
    harness(max) = _qgs_handshake(server_limits = QGS._StreamLimits(max_streams_bidi = max))
    open!(h) = QGS._open_stream!(h.client)
    set_max!(h, n) = _qcn_inject!(h, false, _qgs_ms(true, n))
    blocked_sent!(h) = _qgs_of(_qgs_flush!(h, true), :streams_blocked)

    @testset "no stream ID limit" begin
        @testset "opens streams" begin
            h = harness(0xffffffff)
            @test open!(h) == 0
            @test open!(h) == 4
        end

        @testset "doesn't open streams after it has been closed" begin
            h = harness(0xffffffff)
            QGS._close_connection!(h.client, UInt64(0), "close", h.now)
            @test_throws ArgumentError open!(h)
        end

        @testset "gets streams" begin
            h = harness(0xffffffff)
            open!(h)
            _qcn_inject!(h, false, _qgs_msd(0, 1 << 30))
            @test h.client.error === nothing && haskey(h.client.streams, UInt64(0))
        end

        @testset "errors when trying to get a stream that has not yet been opened" begin
            h = harness(0xffffffff)
            _qcn_inject!(h, false, _qgs_msd(0, 1 << 30))
            @test _qgs_code(h.client) == QGS._STREAM_STATE_ERROR
        end

        @testset "deletes streams" begin
            h = harness(0xffffffff)
            id = open!(h)
            QGS._stream_write!(h.client, id, UInt8[]; fin = true)
            @test _qcn_run!(h; app = h -> begin
                QGS._accept_stream!(h.server)
                if haskey(h.server.streams, id)
                    QGS._stream_read!(h.server, id)
                    h.server.streams[id].send.fin || QGS._stream_write!(h.server, id, UInt8[]; fin = true)
                end
                haskey(h.client.streams, id) && QGS._stream_read!(h.client, id)
            end, done = h -> !haskey(h.client.streams, id), max_time = h.now + 10_000_000_000)
            _qcn_inject!(h, false, _qgs_msd(id, 1 << 30))
            @test h.client.error === nothing && !haskey(h.client.streams, id)
        end
    end

    @testset "with stream ID limits" begin
        @testset "errors when no stream can be opened immediately" begin
            h = harness(0)
            @test open!(h) === nothing
        end

        @testset "doesn't reduce the stream limit" begin
            h = harness(0)
            set_max!(h, 2)
            set_max!(h, 1)
            @test open!(h) !== nothing
            @test open!(h) == 4
        end

        @testset "queues a STREAMS_BLOCKED frame if no stream can be opened" begin
            h = harness(0)
            set_max!(h, 6)
            @test all(_ -> open!(h) !== nothing, 1:6)
            @test isempty(blocked_sent!(h))
            @test open!(h) === nothing
            # RFC 9000 Section 4.6.
            @test [(f.bidi, f.limit) for f in blocked_sent!(h)] == [(true, 6)]
        end

        @testset "only sends one STREAMS_BLOCKED frame for one stream ID" begin
            h = harness(0)
            set_max!(h, 1)
            @test open!(h) !== nothing
            @test isempty(blocked_sent!(h))
            @test open!(h) === nothing
            @test open!(h) === nothing
            @test [f.limit for f in blocked_sent!(h)] == [1]
        end

        @testset "queues a STREAMS_BLOCKED frame when there more streams waiting for OpenStreamSync than MAX_STREAMS allows" begin
            # Without blocking callers: two attempts at limit 0, then one more
            # than a limit of 1 allows.
            h = harness(0)
            @test open!(h) === nothing
            @test open!(h) === nothing
            first_blocked = blocked_sent!(h)
            set_max!(h, 1)
            @test open!(h) == 0
            @test open!(h) === nothing
            second_blocked = blocked_sent!(h)
            @test [f.limit for f in vcat(first_blocked, second_blocked)] == [0, 1]
        end
    end

    @testset "randomized tests" begin
        # quic-go opens with 100 blocked OpenStreamSync callers; here each
        # raise of the limit is followed by opening as many as it allows.
        function run_limits(rng, n, canceled)
            h = harness(0)
            waiting = [i for i in 1:n if !(i in canceled)]
            ids = UInt64[]
            limits = Int[]
            blocked = Int[]
            limit = 0
            num = length(waiting)
            while limit < num
                push!(limits, limit)
                QGS._open_stream!(h.client) === nothing || error("opened past the limit")
                append!(blocked, [f.limit for f in blocked_sent!(h)])
                limit += rand(rng, 1:(n ÷ 5))
                set_max!(h, limit)
                while length(ids) < min(limit, num)
                    push!(ids, QGS._open_stream!(h.client))
                end
                @test ids == [UInt64(4i) for i in 0:(length(ids) - 1)]
            end
            return ids, limits, blocked, num
        end

        @testset "opens streams" begin
            ids, limits, blocked, num = run_limits(Xoshiro(6), 100, Int[])
            @test length(ids) == num
            # STREAMS_BLOCKED at each limit hit.
            @test blocked == limits
        end

        @testset "opens streams, when some of them are getting canceled" begin
            rng = Xoshiro(7)
            canceled = Set(rand(rng, 1:100, 10))
            ids, limits, blocked, num = run_limits(rng, 100, canceled)
            @test length(ids) == 100 - length(canceled)
            @test blocked == limits
        end
    end
end

@testset "Framer" begin
    # What `_append_app_frames!` puts in a packet with `room` bytes for frames.
    function app_frames!(conn, room; buf = UInt8[])
        sent = QGS._SentFrame[]
        QGS._append_app_frames!(conn, buf, room + QGS._AEAD_TAG_LEN, sent)
        frames = _qgs_parse(buf)
        return (; frames, buf, sent, stream = _qgs_of(frames, :stream))
    end
    # Local bidirectional streams with a MAX_STREAM_DATA frame waiting.
    function with_msd!(conn, n)
        ids = UInt64[]
        for _ in 1:n
            id = QGS._open_stream!(conn)
            s = conn.streams[id]
            s.max_stream_data_pending = true
            QGS._queue_stream!(conn, s)
            push!(ids, id)
        end
        return ids
    end

    @testset "handling control frames" begin
        @testset "adds control frames" begin
            h = _qgs_handshake()
            conn = h.client
            _qcn_inject!(h, false, _qgs_pc(0x0102030406070800))
            conn.max_streams_bidi_pending = true
            p = app_frames!(conn, 1000)
            @test length(p.frames) == 2
            @test (type = :path_response, data = 0x0102030406070800) in p.frames
            @test (type = :max_streams, bidi = true, max = UInt64(conn.local_max_streams_bidi)) in p.frames
            @test length(p.buf) == 9 + 1 + _qgs_vl(conn.local_max_streams_bidi)
        end

        @testset "says if it has data" begin
            h = _qgs_handshake()
            conn = h.client
            @test !QGS._app_wants_to_send(conn)
            conn.max_data_pending = true
            @test QGS._app_wants_to_send(conn)
            @test length(app_frames!(conn, 1000).frames) == 1
            @test !QGS._app_wants_to_send(conn)
        end

        @testset "appends to the slice given" begin
            h = _qgs_handshake()
            conn = h.client
            _qcn_inject!(h, false, _qgs_pc(0x0102030406070800))
            p = app_frames!(conn, 1000; buf = _qgs_ping())
            @test p.frames == [(type = :ping,), (type = :path_response, data = 0x0102030406070800)]
            @test length(p.buf) - 1 == 9
        end

        @testset "adds stream-related control frames" begin
            h = _qgs_handshake()
            conn = h.client
            conn.max_data_pending = true
            ids = with_msd!(conn, 2)
            p = app_frames!(conn, 1 << 20)
            @test length(p.frames) == 3
            @test sort([f.id for f in _qgs_of(p.frames, :max_stream_data)]) == ids
            @test length(_qgs_of(p.frames, :max_data)) == 1
        end

        @testset "doesn't enqueue more stream-related control frames if there are less than 25 bytes left" begin
            h = _qgs_handshake()
            conn = h.client
            with_msd!(conn, 30)
            p = app_frames!(conn, 100)
            @test all(f -> f.type == :max_stream_data, p.frames)
            @test 100 - 25 < length(p.buf) <= 100
        end

        @testset "adds the right number of frames" begin
            # quic-go fills with DATA_BLOCKED frames; ours with MAX_STREAM_DATA.
            h = _qgs_handshake(server_limits = QGS._StreamLimits(max_streams_bidi = 1000))
            conn = h.client
            max_size = 1000
            # Streams 0 to 60 have shorter IDs; leave them out so that all the
            # frames are the same length.
            foreach(_ -> QGS._open_stream!(conn), 1:16)
            frame_len = 1 + _qgs_vl(64) + _qgs_vl(conn.limits.max_stream_data)
            num_frames = max_size ÷ frame_len
            ids = with_msd!(conn, num_frames + 1)
            p = app_frames!(conn, max_size)
            @test length(p.buf) <= max_size
            # We reserve 17 bytes for each MAX_STREAM_DATA frame, so the last
            # few bytes of the packet stay empty.
            @test length(p.buf) > max_size - 17
            # Differs from quic-go: it packs max_size ÷ frame length frames,
            # sizing each frame exactly. We reserve the largest frame's 17
            # bytes, which wastes at most 16 bytes of a packet and saves
            # encoding each frame twice; a frame left out goes in the next.
            @test length(p.frames) == (max_size - 17) ÷ frame_len + 1
            rest = 0
            while QGS._app_wants_to_send(conn)
                rest += length(app_frames!(conn, max_size).frames)
            end
            @test length(p.frames) + rest == num_frames + 1
        end
    end

    @testset "handling PATH_RESPONSE frames" begin
        @testset "packs a single PATH_RESPONSE per packet" begin
            h = _qgs_handshake()
            conn = h.client
            _qcn_inject!(h, false, vcat(_qgs_pc(0x0102030405060708), _qgs_pc(0x0203040506070809)))
            conn.max_data_pending = true
            @test QGS._app_wants_to_send(conn)
            p1 = app_frames!(conn, 1 << 20)
            responses = _qgs_of(p1.frames, :path_response)
            @test responses[1].data == 0x0102030405060708
            @test length(_qgs_of(p1.frames, :max_data)) == 1
            @test length(responses) == 1
            p2 = app_frames!(conn, 1 << 20)
            @test [f.data for f in _qgs_of(p2.frames, :path_response)] == [0x0203040506070809]
            @test !QGS._app_wants_to_send(conn)
        end

        # Not in quic-go's framer tests (its packer pads): RFC 9000 Section
        # 8.2.2.
        @testset "pads a datagram with a PATH_RESPONSE to 1200 bytes" begin
            h = _qgs_handshake()
            conn = h.client
            _qcn_inject!(h, false, _qgs_pc(0x0102030405060708))
            d = QGS._next_datagram!(conn, h.now)
            @test d !== nothing
            @test any(f -> f.type == :path_response, _qgs_decode(h, true, d))
            @test length(d) >= QGS._MAX_DATAGRAM_SIZE
            # Without a PATH_RESPONSE a small packet stays small.
            conn.max_data_pending = true
            d = QGS._next_datagram!(conn, h.now)
            @test d !== nothing && length(d) < 100
        end

        @testset "pads a server's PATH_RESPONSE only as far as the anti-amplification limit allows" begin
            h = _qgs_handshake()
            conn = h.server
            _qcn_inject!(h, true, _qgs_pc(0x0102030405060708))
            # As if the client's address were not yet validated, with room
            # for 300 more bytes.
            conn.address_validated = false
            conn.bytes_sent = 3 * conn.bytes_received - 300
            d = QGS._next_datagram!(conn, h.now)
            @test d !== nothing
            @test any(f -> f.type == :path_response, _qgs_decode(h, false, d))
            @test length(d) == 300
        end

        @testset "limits the number of queued PATH_RESPONSE frames" begin
            h = _qgs_handshake()
            conn = h.client
            n = QGS._MAX_PATH_RESPONSES
            challenges = rand(Xoshiro(8), UInt64, 2n)
            _qcn_inject!(h, false, reduce(vcat, _qgs_pc.(challenges)))
            responses = UInt64[]
            while QGS._app_wants_to_send(conn)
                append!(responses, [f.data for f in _qgs_of(app_frames!(conn, 1 << 20).frames, :path_response)])
            end
            @test responses == challenges[1:n]
            @test isempty(app_frames!(conn, 1 << 20).frames)
        end
    end

    @testset "popping STREAM frames" begin
        function framer(; unlimited = false)
            h = _qgs_handshake()
            conn = h.client
            id1 = QGS._open_stream!(conn; bidi = false)
            id2 = QGS._open_stream!(conn; bidi = false)
            if unlimited
                conn.peer_max_data = typemax(Int64) ÷ 2
                conn.streams[id1].send_max = typemax(Int64) ÷ 2
                conn.streams[id2].send_max = typemax(Int64) ÷ 2
            end
            return h, conn, id1, id2
        end
        w!(conn, id, data) = QGS._stream_write!(conn, id, data)
        # Data that fills one STREAM frame in a packet with `room` bytes.
        one_frame(id, room) = room - (1 + _qgs_vl(id) + 8 + 2)

        @testset "returns nil when popping an empty framer" begin
            h, conn, id1, id2 = framer()
            @test isempty(app_frames!(conn, 1000).frames)
        end

        @testset "returns STREAM frames" begin
            h, conn, id1, id2 = framer()
            w!(conn, id1, zeros(UInt8, 42))
            app_frames!(conn, 1000)
            w!(conn, id1, Vector{UInt8}("foobar"))
            p = app_frames!(conn, 1000)
            @test length(p.stream) == 1
            @test p.stream[1].offset == 42 && p.stream[1].data == Vector{UInt8}("foobar")
            # Differs from quic-go: it drops the Length field of a packet's
            # last STREAM frame. Ours keeps it, which costs one or two bytes
            # but lets frames be appended without rewriting the one before.
            @test _qgs_stream_length_fields(p.buf) == [true]
        end

        @testset "says if it has data" begin
            h, conn, id1, id2 = framer()
            @test !QGS._app_wants_to_send(conn)
            w!(conn, id1, zeros(UInt8, 2 * one_frame(id1, _QGS_MIN_STREAM_FRAME)))
            @test QGS._app_wants_to_send(conn)
            @test length(app_frames!(conn, _QGS_MIN_STREAM_FRAME).stream) == 1
            @test QGS._app_wants_to_send(conn)
            @test length(app_frames!(conn, _QGS_MIN_STREAM_FRAME).stream) == 1
            @test !QGS._app_wants_to_send(conn)
            QGS._stream_reset!(conn, id1, UInt64(0))  # a stream control frame
            @test QGS._app_wants_to_send(conn)
        end

        @testset "appends to a frame slice" begin
            h, conn, id1, id2 = framer()
            w!(conn, id1, Vector{UInt8}("foobar"))
            p = app_frames!(conn, 1000; buf = _qgs_ping())
            @test length(p.frames) == 2
            @test p.frames[1] == (type = :ping,)
            @test p.frames[2].data == Vector{UInt8}("foobar")
        end

        @testset "skips a stream that was reported active, but was completed shortly after" begin
            h, conn, id1, id2 = framer()
            w!(conn, id1, Vector{UInt8}("foobar"))
            w!(conn, id2, Vector{UInt8}("foobar"))
            Base.delete!(conn.streams, id1)  # completed and freed
            p = app_frames!(conn, 1000)
            @test [f.id for f in p.stream] == [id2]
        end

        @testset "skips a stream that was reported active, but doesn't have any data" begin
            h, conn, id1, id2 = framer()
            QGS._queue_stream!(conn, conn.streams[id1])
            w!(conn, id2, Vector{UInt8}("foobar"))
            p = app_frames!(conn, 1000)
            @test [f.id for f in p.stream] == [id2]
        end

        @testset "pops from a stream multiple times, if it has enough data" begin
            h, conn, id1, id2 = framer()
            w!(conn, id1, zeros(UInt8, 2 * one_frame(id1, _QGS_MIN_STREAM_FRAME)))
            @test length(app_frames!(conn, _QGS_MIN_STREAM_FRAME).stream) == 1
            @test length(app_frames!(conn, _QGS_MIN_STREAM_FRAME).stream) == 1
            @test isempty(app_frames!(conn, _QGS_MIN_STREAM_FRAME).frames)
        end

        @testset "re-queues a stream at the end, if it has enough data" begin
            h, conn, id1, id2 = framer()
            w!(conn, id1, zeros(UInt8, 2 * one_frame(id1, _QGS_MIN_STREAM_FRAME)))
            w!(conn, id2, Vector{UInt8}("raboof"))
            # The stream each packet serves first. (quic-go's second packet
            # holds only stream 2's frame, since it starts no STREAM frame
            # with under 128 bytes left; ours fills the rest with stream 1,
            # see "does not pop frames smaller than the minimum size".)
            order = [first(app_frames!(conn, _QGS_MIN_STREAM_FRAME).stream).id for _ in 1:3]
            @test order == [id1, id2, id1]
        end

        @testset "only dequeues data from each stream once per packet" begin
            h, conn, id1, id2 = framer()
            w!(conn, id1, Vector{UInt8}("foobar"))
            w!(conn, id2, Vector{UInt8}("raboof"))
            p = app_frames!(conn, 1000)
            @test [(f.id, f.data) for f in p.stream] == [(id1, Vector{UInt8}("foobar")), (id2, Vector{UInt8}("raboof"))]
        end

        @testset "returns multiple normal frames in the order they were reported active" begin
            h, conn, id1, id2 = framer()
            w!(conn, id2, Vector{UInt8}("foobaz"))
            w!(conn, id1, Vector{UInt8}("foobar"))
            p = app_frames!(conn, 1000)
            @test [f.id for f in p.stream] == [id2, id1]
        end

        @testset "only asks a stream for data once, even if it was reported active multiple times" begin
            h, conn, id1, id2 = framer()
            w!(conn, id1, Vector{UInt8}("foo"))
            w!(conn, id1, Vector{UInt8}("bar"))
            @test count(==(id1), conn.send_queue) == 1
            @test length(app_frames!(conn, 1000).stream) == 1
        end

        @testset "does not pop empty frames" begin
            h, conn, id1, id2 = framer()
            p = app_frames!(conn, 500)
            @test isempty(p.frames) && isempty(p.buf)
        end

        @testset "pops maximum size STREAM frames" begin
            h, conn, id1, id2 = framer(; unlimited = true)
            w!(conn, id1, zeros(UInt8, 3_000_000))
            one = Bool[]
            unused = Int[]
            for i in _QGS_MIN_STREAM_FRAME:1999
                p = app_frames!(conn, i)
                push!(one, length(p.stream) == 1)
                push!(unused, i - length(p.buf))
            end
            @test all(one)
            # Differs from quic-go: it fills the packet exactly. We reserve a
            # worst-case header (an 8-byte offset and a 2-byte length), which
            # leaves at most 9 bytes unused and sizes the frame in one pass.
            @test all(u -> 0 <= u <= 9, unused)
        end

        @testset "pops multiple STREAM frames" begin
            h, conn, id1, id2 = framer(; unlimited = true)
            w!(conn, id2, zeros(UInt8, 3_000_000))
            two = Bool[]
            unused = Int[]
            lengths = Bool[]
            for i in (2 * _QGS_MIN_STREAM_FRAME):1999
                # Stream 1 has a minimum-size frame's worth of data, stream 2 more.
                # Stream 1 reported active first.
                filter!(!=(id2), conn.send_queue)
                conn.streams[id2].queued = false
                w!(conn, id1, zeros(UInt8, one_frame(id1, _QGS_MIN_STREAM_FRAME)))
                QGS._queue_stream!(conn, conn.streams[id2])
                p = app_frames!(conn, i)
                push!(two, [f.id for f in p.stream] == [id1, id2])
                push!(unused, i - length(p.buf))
                push!(lengths, _qgs_stream_length_fields(p.buf) == [true, true])
            end
            @test all(two)
            # Differs from quic-go: as above, the worst-case header leaves at
            # most 9 bytes unused, and the last frame keeps its Length field
            # (see "returns STREAM frames").
            @test all(u -> 0 <= u <= 9, unused)
            @test all(lengths)
        end

        @testset "pops frames that when asked for the the minimum STREAM frame size" begin
            h, conn, id1, id2 = framer()
            w!(conn, id1, Vector{UInt8}("foobar"))
            @test length(app_frames!(conn, _QGS_MIN_STREAM_FRAME).stream) == 1
        end

        @testset "does not pop frames smaller than the minimum size" begin
            h, conn, id1, id2 = framer()
            w!(conn, id1, Vector{UInt8}("foobar"))
            # Differs from quic-go: it does not start a STREAM frame with
            # fewer than 128 bytes left in the packet. We use whatever room
            # is left, so small writes ride along with other frames.
            @test length(app_frames!(conn, _QGS_MIN_STREAM_FRAME - 1).stream) == 1
        end

        @testset "stops iterating when the remaining size is smaller than the minimum STREAM frame size" begin
            h, conn, id1, id2 = framer()
            data = fill(UInt8('f'), 500 - _QGS_MIN_STREAM_FRAME)
            w!(conn, id1, data)
            p = app_frames!(conn, 500)
            @test length(p.stream) == 1 && p.stream[1].data == data
        end
    end
end

@testset "MTU Discoverer" begin
    start_mtu = QGS._MAX_DATAGRAM_SIZE  # quic-go's test starts at 1000
    max_mtu = 2000
    # The client after the handshake, its discovery restarted between
    # `start_mtu` and `ceiling`.
    function restart!(c, ceiling)
        c.max_datagram_size = start_mtu
        c.pmtu_ceiling = ceiling
        c.pmtu_probe_pn = -1
        c.pmtu_failures = 0
        c.pmtu_done = false
        c.pmtu_probe_due = false
        QGS._pmtu_start!(c)
        return c
    end
    function discoverer(ceiling = max_mtu)
        h = _qgs_handshake()
        return h, restart!(h.client, ceiling)
    end
    should_send(c) = !c.pmtu_done && QGS._pmtu_probe_ready(c)
    # GetPing: sends the probe, returns its size.
    function get_ping!(h, c)
        size = c.pmtu_probe_size
        d = QGS._next_datagram!(c, h.now)
        (d !== nothing && length(d) == size && c.pmtu_probe_pn >= 0) || error("no probe of size $size")
        return size
    end
    acked!(c) = QGS._pmtu_probe_acked!(c)
    lost!(c) = QGS._pmtu_probe_lost!(c)

    @testset "only allows a probe 5 RTTs after the handshake completes" begin
        h, c = discoverer()
        # Differs from quic-go: it waits 5 RTTs after the handshake (and
        # between probes). We probe at once, which RFC 8899 allows, so larger
        # datagrams are in use sooner.
        @test should_send(c)
    end

    @testset "doesn't allow a probe if another probe is still in flight" begin
        h, c = discoverer()
        get_ping!(h, c)
        @test !should_send(c)
        lost!(c)
        @test should_send(c)
    end

    @testset "tries a lower size when a probe is lost" begin
        h, c = discoverer()
        size = get_ping!(h, c)
        # Differs from quic-go: it probes the midpoint first (1500 between
        # 1000 and 2000). We probe the ceiling first, which most paths carry,
        # so one probe usually ends the search.
        @test size == max_mtu
        lost!(c)
        size2 = get_ping!(h, c)
        # Differs from quic-go: it tries a lower size after one loss. We
        # retry the same size up to `_PMTU_MAX_PROBES` times first, so one
        # lost packet does not give up a size the path carries (RFC 8899
        # Section 5.1.2's MAX_PROBES).
        @test size2 == size
        for _ in 3:QGS._PMTU_MAX_PROBES
            lost!(c)
            @test get_ping!(h, c) == size
        end
        lost!(c)
        @test should_send(c) && c.pmtu_probe_size < size
    end

    @testset "tries a higher size and calls the callback when a probe is acknowledged" begin
        h, c = discoverer()
        size = get_ping!(h, c)
        acked!(c)
        @test c.max_datagram_size == size
        # Differs from quic-go: its next probe is higher (1750). Our first
        # probe was the ceiling, so discovery is already over.
        @test !should_send(c) && c.pmtu_done
    end

    @testset "stops discovery after getting close enough to the MTU" begin
        h, c = discoverer()
        sizes = Int[]
        while should_send(c)
            push!(sizes, get_ping!(h, c))
            acked!(c)
        end
        # Differs from quic-go: its binary search probes 1500, 1750, 1875,
        # 1937, 1968, 1984 between 1000 and 2000. Ours probes the ceiling
        # first, and the path carries it.
        @test sizes == [max_mtu]
        @test !should_send(c)
        @test 0 <= max_mtu - c.max_datagram_size <= 20  # maxMTUDiff
    end

    @testset "doesn't do discovery before being started" begin
        c = _QcnHarness().client
        @test all(_ -> !should_send(c), 1:5)
    end

    # Runs discovery against a path carrying `real_mtu`, losing fitting
    # probes when `lose()` says so; returns (discovered, probes sent).
    function find!(h, c, rng, max_probes; random_losses = 0)
        ceiling = rand(rng, (start_mtu + 1):3000)
        real_mtu = rand(rng, start_mtu:(ceiling - 1))
        restart!(c, ceiling)
        probes = 0
        losses = 0
        while should_send(c)
            probes > max_probes && return (false, real_mtu, c.max_datagram_size, probes)
            size = get_ping!(h, c)
            probes += 1
            if size <= real_mtu && !(losses < random_losses && rand(rng, 0:(QGS._PMTU_MAX_PROBES - 1)) == 0 && (losses += 1; true))
                acked!(c)
            else
                lost!(c)
            end
        end
        diff = real_mtu - c.max_datagram_size
        return (0 <= diff <= 20, real_mtu, c.max_datagram_size, probes)
    end

    @testset "finds the MTU" begin
        h = _qgs_handshake()
        rng = Xoshiro(9)
        results = [find!(h, h.client, rng, 24) for _ in 1:300]
        @test all(r -> r[1], results)
    end

    max_random_loss = QGS._PMTU_MAX_PROBES - 1
    @testset "finds the MTU, with up to $max_random_loss packets lost" begin
        h = _qgs_handshake()
        rng = Xoshiro(10)
        results = [find!(h, h.client, rng, 32; random_losses = max_random_loss) for _ in 1:500]
        @test all(r -> r[1], results)
    end
end

# Blocking behavior, deadlines, cancellation errors and accepts, through the
# public Stream API over loopback UDP.
@testset "Receive Stream (public API)" begin
    # A stream from the client, accepted and read up to here by the server.
    function accepted(c, srv; bidi = true)
        s = QGS.open_stream(c; bidi)
        return s, _qgs_accept_peer(s, srv)
    end
    wait_available(p, n) = timedwait(() -> bytesavailable(p) >= n, 10; pollint = 0.002) == :ok

    @testset "gets stream id" begin
        _qgs_api() do c, srv
            s, p = accepted(c, srv; bidi = false)
            @test QGS.stream_id(p) == QGS.stream_id(s) == 2
        end
    end

    @testset "reading" begin
        @testset "waits until data is available" begin
            _qgs_api() do c, srv
                s, p = accepted(c, srv)
                reader = Threads.@spawn read(p, 2)
                sleep(0.01)
                @test !istaskdone(reader)
                write(s, UInt8[0xDE, 0xAD])
                @test _qgs_finishes(reader, 10)
                @test fetch(reader) == UInt8[0xDE, 0xAD]
            end
        end

        @testset "deadlines" begin
            @testset "returns an error when Read is called after the deadline" begin
                _qgs_api() do c, srv
                    s, p = accepted(c, srv)
                    write(s, Vector{UInt8}("foobar"))
                    @test wait_available(p, 6)
                    QGS.set_read_deadline!(p, Int64(time_ns()) - 1_000_000_000)
                    err = _qgs_err(() -> read(p, 6))
                    # Even though the data is there.
                    @test err isa UDGS.DeadlineExceededError
                end
            end

            @testset "unblocks when the deadline is changed to the past" begin
                _qgs_api() do c, srv
                    s, p = accepted(c, srv)
                    QGS.set_read_deadline!(p, _qgs_deadline(3600))
                    reader = _qgs_spawn(() -> read(p, 6))
                    @test !_qgs_finishes(reader, 0.1)
                    QGS.set_read_deadline!(p, Int64(time_ns()) - 3_600_000_000_000)
                    @test _qgs_finishes(reader, 1.0) && fetch(reader)[1] isa UDGS.DeadlineExceededError
                end
            end

            @testset "unblocks after the deadline" begin
                _qgs_api() do c, srv
                    s, p = accepted(c, srv)
                    deadline = _qgs_deadline(0.2)
                    QGS.set_read_deadline!(p, deadline)
                    err, t = fetch(_qgs_spawn(() -> read(p, 6)))
                    @test err isa UDGS.DeadlineExceededError
                    @test _qgs_near(t, deadline)
                end
            end

            @testset "doesn't unblock if the deadline is changed before the first one expires" begin
                _qgs_api() do c, srv
                    s, p = accepted(c, srv)
                    deadline1 = _qgs_deadline(0.2)
                    deadline2 = _qgs_deadline(0.4)
                    QGS.set_read_deadline!(p, deadline1)
                    reader = _qgs_spawn(() -> read(p, 10))
                    sleep(0.08)
                    QGS.set_read_deadline!(p, deadline2)
                    @test Int64(time_ns()) < deadline1
                    err, t = fetch(reader)
                    @test err isa UDGS.DeadlineExceededError
                    @test _qgs_near(t, deadline2)
                end
            end

            @testset "unblocks earlier, when a new deadline is set" begin
                _qgs_api() do c, srv
                    s, p = accepted(c, srv)
                    deadline1 = _qgs_deadline(0.8)
                    deadline2 = _qgs_deadline(0.2)
                    QGS.set_read_deadline!(p, deadline1)
                    reader = _qgs_spawn(() -> read(p, 10))
                    sleep(0.04)
                    QGS.set_read_deadline!(p, deadline2)
                    err, t = fetch(reader)
                    @test err isa UDGS.DeadlineExceededError
                    @test _qgs_near(t, deadline2)
                end
            end

            @testset "doesn't unblock if the deadline is removed" begin
                _qgs_api() do c, srv
                    s, p = accepted(c, srv)
                    deadline = _qgs_deadline(0.2)
                    QGS.set_read_deadline!(p, deadline)
                    reader = _qgs_spawn(() -> read(p, 1))
                    sleep(0.08)
                    QGS.set_read_deadline!(p, 0)
                    @test Int64(time_ns()) < deadline
                    @test !_qgs_finishes(reader, 0.4)
                    close(srv)  # closeForShutdown
                    @test _qgs_finishes(reader, 10)
                    @test fetch(reader)[1] isa QGS.ConnectionError
                end
            end
        end

        @testset "closing" begin
            @testset "with FIN bit" begin
                @testset "handles concurrent reads" begin
                    _qgs_api() do c, srv
                        s = QGS.open_stream(c; bidi = false)
                        write(s, Vector{UInt8}("fo"))
                        p = QGS.accept_stream(srv; deadline_ns = _qgs_deadline(10))
                        @test read(p, 2) == Vector{UInt8}("fo")
                        readers = [Threads.@spawn readavailable(p) for _ in 1:3]
                        sleep(0.01)
                        write(s, Vector{UInt8}("obar"))
                        closewrite(s)
                        @test all(t -> _qgs_finishes(t, 10), readers)
                        @test sort(String.(fetch.(readers))) == ["", "", "obar"]
                        # The stream completed once: the client may open one more.
                        @test timedwait(() -> srv.slot.conn.peer_closed_uni == 1, 5) == :ok
                        sleep(0.05)
                        @test srv.slot.conn.peer_closed_uni == 1
                    end
                end
            end
        end

        @testset "closing for shutdown" begin
            @testset "immediately returns all reads" begin
                _qgs_api() do c, srv
                    s, p = accepted(c, srv)
                    reader = _qgs_spawn(() -> read(p, 4))
                    @test !_qgs_finishes(reader, 0.1)
                    close(srv)
                    @test _qgs_finishes(reader, 10)
                    @test fetch(reader)[1] isa QGS.ConnectionError
                end
            end

            @testset "errors for all following reads" begin
                _qgs_api() do c, srv
                    s, p = accepted(c, srv)
                    close(srv)
                    @test _qgs_err(() -> read(p, 1)) isa QGS.ConnectionError
                end
            end
        end
    end

    @testset "stream cancellations" begin
        @testset "canceling read" begin
            stopped(err, s, code) = err isa QGS.StreamStoppedError && err.stream_id == QGS.stream_id(s) && err.code == code && !err.remote

            @testset "unblocks Read" begin
                _qgs_api() do c, srv
                    s, p = accepted(c, srv)
                    reader = _qgs_spawn(() -> read(p, 1))
                    @test !_qgs_finishes(reader, 0.1)
                    QGS.stop_sending!(p, 1234)
                    @test _qgs_finishes(reader, 10)
                    @test stopped(fetch(reader)[1], p, 1234)
                end
            end

            @testset "doesn't allow further calls to Read" begin
                _qgs_api() do c, srv
                    s, p = accepted(c, srv)
                    QGS.stop_sending!(p, 1234)
                    @test stopped(_qgs_err(() -> read(p, 1)), p, 1234)
                end
            end

            @testset "does nothing when CancelRead is called twice" begin
                _qgs_api() do c, srv
                    s, p = accepted(c, srv)
                    QGS.stop_sending!(p, 1234)
                    QGS.stop_sending!(p, 1234)
                    @test stopped(_qgs_err(() -> read(p, 1)), p, 1234)
                end
            end

            @testset "ignores cancellations after closeForShutdown" begin
                _qgs_api() do c, srv
                    s, p = accepted(c, srv)
                    close(srv)
                    @test _qgs_err(() -> read(p, 100)) isa QGS.ConnectionError
                    @test _qgs_err(() -> QGS.stop_sending!(p, 42)) === nothing
                    @test _qgs_err(() -> read(p, 100)) isa QGS.ConnectionError
                end
            end
        end

        @testset "receiving RESET_STREAM frames" begin
            reset_err(err, s, code) = err isa QGS.StreamResetError && err.stream_id == QGS.stream_id(s) && err.code == code && err.remote

            @testset "unblocks Read" begin
                _qgs_api() do c, srv
                    s, p = accepted(c, srv)
                    reader = _qgs_spawn(() -> read(p, 1))
                    @test !_qgs_finishes(reader, 0.1)
                    QGS.reset_stream!(s, 1234)
                    @test _qgs_finishes(reader, 10)
                    @test reset_err(fetch(reader)[1], p, 1234)
                end
            end

            @testset "doesn't allow further calls to Read" begin
                _qgs_api() do c, srv
                    s, p = accepted(c, srv)
                    QGS.reset_stream!(s, 1234)
                    @test reset_err(_qgs_err(() -> read(p, 1)), p, 1234)
                    @test reset_err(_qgs_err(() -> read(p, 1)), p, 1234)
                end
            end

            @testset "handles RESET_STREAM after CancelRead" begin
                # The client answers STOP_SENDING with RESET_STREAM.
                _qgs_api() do c, srv
                    s, p = accepted(c, srv; bidi = false)
                    id = QGS.stream_id(p)
                    QGS.stop_sending!(p, 1234)
                    err = _qgs_err(() -> read(p, 1))
                    # The error indicates a local cancellation.
                    @test err isa QGS.StreamStoppedError && !err.remote && err.code == 1234
                    # The stream completes once the RESET_STREAM arrives, and its
                    # stream count returns to the peer.
                    @test timedwait(() -> lock(() -> !haskey(srv.slot.conn.streams, id), srv.ep.lock), 2) == :ok
                    # Reads still report the local stop.
                    err = _qgs_err(() -> read(p, 1))
                    @test err isa QGS.StreamStoppedError && !err.remote && err.code == 1234
                end
            end
        end
    end
end

@testset "Send Stream (public API)" begin
    accepted(c, srv; bidi = true) = (s = QGS.open_stream(c; bidi); (s, _qgs_accept_peer(s, srv)))
    blocking_write(s) = _qgs_spawn(() -> write(s, zeros(UInt8, _QGS_BLOCKING_WRITE)))

    @testset "gets stream id" begin
        _qgs_api() do c, srv
            @test QGS.stream_id(QGS.open_stream(c; bidi = false)) == 2
        end
    end

    @testset "writing" begin
        @testset "returns when given an empty slice" begin
            _qgs_api() do c, srv
                s = QGS.open_stream(c)
                @test write(s, UInt8[]) == 0
            end
        end

        @testset "deadlines" begin
            @testset "returns an error when Write is called after the deadline" begin
                _qgs_api() do c, srv
                    s = QGS.open_stream(c)
                    QGS.set_write_deadline!(s, Int64(time_ns()) - 1_000_000_000)
                    err = _qgs_err(() -> write(s, Vector{UInt8}("foobar")))
                    # Even though it need not wait.
                    @test err isa UDGS.DeadlineExceededError
                    # The FIN goes out regardless, as quic-go's Close does.
                    @test _qgs_err(() -> closewrite(s)) === nothing
                end
            end

            @testset "unblocks after the deadline" begin
                _qgs_api(server_kw = _QGS_SMALL_WINDOW) do c, srv
                    s = QGS.open_stream(c)
                    deadline = _qgs_deadline(0.3)
                    QGS.set_write_deadline!(s, deadline)
                    err, t = fetch(blocking_write(s))
                    @test err isa UDGS.DeadlineExceededError
                    @test _qgs_near(t, deadline)
                end
            end

            @testset "unblocks when the deadline is changed to the past" begin
                _qgs_api(server_kw = _QGS_SMALL_WINDOW) do c, srv
                    s = QGS.open_stream(c)
                    QGS.set_write_deadline!(s, _qgs_deadline(3600))
                    writer = blocking_write(s)
                    @test !_qgs_finishes(writer, 0.2)
                    QGS.set_write_deadline!(s, Int64(time_ns()) - 3_600_000_000_000)
                    @test _qgs_finishes(writer, 1.0) && fetch(writer)[1] isa UDGS.DeadlineExceededError
                end
            end

            @testset "doesn't pop any data after the deadline expired" begin
                _qgs_api(server_kw = _QGS_SMALL_WINDOW) do c, srv
                    s = QGS.open_stream(c)
                    QGS.set_write_deadline!(s, _qgs_deadline(0.2))
                    err, _ = fetch(blocking_write(s))
                    @test err isa UDGS.DeadlineExceededError
                    # What the write did not get into the send buffer is never sent.
                    taken() = lock(() -> QGS._send_end(c.slot.conn.streams[QGS.stream_id(s)].send), c.ep.lock)
                    before = taken()
                    @test before < _QGS_BLOCKING_WRITE
                    sleep(0.2)
                    @test taken() == before
                end
            end

            @testset "doesn't unblock if the deadline is changed before the first one expires" begin
                _qgs_api(server_kw = _QGS_SMALL_WINDOW) do c, srv
                    s = QGS.open_stream(c)
                    deadline1 = _qgs_deadline(0.2)
                    deadline2 = _qgs_deadline(0.4)
                    QGS.set_write_deadline!(s, deadline1)
                    writer = blocking_write(s)
                    sleep(0.08)
                    QGS.set_write_deadline!(s, deadline2)
                    @test Int64(time_ns()) < deadline1
                    err, t = fetch(writer)
                    @test err isa UDGS.DeadlineExceededError
                    @test _qgs_near(t, deadline2)
                end
            end

            @testset "unblocks earlier, when a new deadline is set" begin
                _qgs_api(server_kw = _QGS_SMALL_WINDOW) do c, srv
                    s = QGS.open_stream(c)
                    deadline1 = _qgs_deadline(0.8)
                    deadline2 = _qgs_deadline(0.2)
                    QGS.set_write_deadline!(s, deadline1)
                    writer = blocking_write(s)
                    sleep(0.04)
                    QGS.set_write_deadline!(s, deadline2)
                    err, t = fetch(writer)
                    @test err isa UDGS.DeadlineExceededError
                    @test _qgs_near(t, deadline2)
                end
            end

            @testset "doesn't unblock if the deadline is removed" begin
                _qgs_api(server_kw = _QGS_SMALL_WINDOW) do c, srv
                    s = QGS.open_stream(c)
                    deadline = _qgs_deadline(0.2)
                    QGS.set_write_deadline!(s, deadline)
                    writer = blocking_write(s)
                    sleep(0.08)
                    QGS.set_write_deadline!(s, 0)
                    @test Int64(time_ns()) < deadline
                    @test !_qgs_finishes(writer, 0.4)
                    close(c)  # closeForShutdown
                    @test _qgs_finishes(writer, 10)
                    @test fetch(writer)[1] isa QGS.ConnectionError
                end
            end
        end

        @testset "closing for shutdown" begin
            @testset "returns errors when the stream is cancelled" begin
                _qgs_api() do c, srv
                    s = QGS.open_stream(c)
                    close(c)
                    @test _qgs_err(() -> write(s, Vector{UInt8}("foo"))) isa QGS.ConnectionError
                end
            end
        end
    end

    @testset "stream cancellations" begin
        @testset "canceling writing" begin
            local_reset(err, s, code) = err isa QGS.StreamResetError && err.stream_id == QGS.stream_id(s) && err.code == code && !err.remote

            @testset "unblocks Write" begin
                _qgs_api(server_kw = _QGS_SMALL_WINDOW) do c, srv
                    s = QGS.open_stream(c)
                    writer = blocking_write(s)
                    @test !_qgs_finishes(writer, 0.2)
                    QGS.reset_stream!(s, 1234)
                    @test _qgs_finishes(writer, 10)
                    @test local_reset(fetch(writer)[1], s, 1234)
                end
            end

            @testset "doesn't allow further calls to Write" begin
                _qgs_api() do c, srv
                    s = QGS.open_stream(c)
                    QGS.reset_stream!(s, 1234)
                    @test local_reset(_qgs_err(() -> write(s, Vector{UInt8}("foobar"))), s, 1234)
                end
            end
        end

        @testset "receiving STOP_SENDING frames" begin
            remote_stop(err, s, code) = err isa QGS.StreamStoppedError && err.stream_id == QGS.stream_id(s) && err.code == code && err.remote
            stop_seen(c, s) = timedwait(() -> lock(() -> QGS._stream_stop_code(c.slot.conn, QGS.stream_id(s)) != QGS._NO_CODE, c.ep.lock), 10) == :ok

            @testset "queues a RESET_STREAM frames, and copies the error code from the STOP_SENDING frame" begin
                # A unidirectional stream: once the RESET_STREAM is acknowledged
                # nothing else keeps it.
                _qgs_api() do c, srv
                    s, p = accepted(c, srv; bidi = false)
                    id = QGS.stream_id(s)
                    QGS.stop_sending!(p, 101)
                    reset_acked() = lock(c.ep.lock) do
                        st = get(c.slot.conn.streams, id, nothing)
                        st !== nothing && st.reset_acked
                    end
                    @test timedwait(reset_acked, 5) == :ok
                    # Kept until the application has seen the cancellation.
                    err = _qgs_err(() -> write(s, Vector{UInt8}("foobar")))
                    @test remote_stop(err, s, 101)
                    @test lock(() -> !haskey(c.slot.conn.streams, id), c.ep.lock)
                end
            end

            @testset "unblocks Write" begin
                _qgs_api(server_kw = _QGS_SMALL_WINDOW) do c, srv
                    s = QGS.open_stream(c)
                    writer = blocking_write(s)
                    p = QGS.accept_stream(srv; deadline_ns = _qgs_deadline(10))
                    @test !istaskdone(writer)
                    QGS.stop_sending!(p, 123)
                    @test _qgs_finishes(writer, 10)
                    @test remote_stop(fetch(writer)[1], s, 123)
                end
            end

            @testset "doesn't allow further calls to Write" begin
                _qgs_api() do c, srv
                    s, p = accepted(c, srv)
                    QGS.stop_sending!(p, 123)
                    @test stop_seen(c, s)
                    @test remote_stop(_qgs_err(() -> write(s, Vector{UInt8}("foobar"))), s, 123)
                end
            end

            @testset "handles Close after STOP_SENDING" begin
                _qgs_api() do c, srv
                    s, p = accepted(c, srv)
                    QGS.stop_sending!(p, 123)
                    @test stop_seen(c, s)
                    @test _qgs_err(() -> close(s)) === nothing
                end
            end

            @testset "ignores cancellations after closeForShutdown" begin
                _qgs_api() do c, srv
                    s = QGS.open_stream(c)
                    close(c)
                    @test _qgs_err(() -> write(s, Vector{UInt8}("hello"))) isa QGS.ConnectionError
                    @test _qgs_err(() -> QGS.reset_stream!(s, 42)) === nothing
                    @test _qgs_err(() -> write(s, Vector{UInt8}("hello"))) isa QGS.ConnectionError
                end
            end
        end
    end
end

@testset "Stream (public API)" begin
    @testset "gets stream id" begin
        _qgs_api() do c, srv
            @test QGS.stream_id(QGS.open_stream(c)) == 0
        end
    end

    @testset "deadlines" begin
        # SetDeadline sets both deadlines.
        set_deadline!(s, t) = (QGS.set_read_deadline!(s, t); QGS.set_write_deadline!(s, t))

        @testset "sets a write deadline, when SetDeadline is called" begin
            _qgs_api() do c, srv
                s = QGS.open_stream(c)
                set_deadline!(s, Int64(time_ns()) - 1_000_000_000)
                @test _qgs_err(() -> write(s, Vector{UInt8}("foobar"))) isa UDGS.DeadlineExceededError
            end
        end

        @testset "sets a read deadline, when SetDeadline is called" begin
            _qgs_api() do c, srv
                s = QGS.open_stream(c)
                p = _qgs_accept_peer(s, srv)
                write(s, Vector{UInt8}("foobar"))
                @test timedwait(() -> bytesavailable(p) >= 6, 10) == :ok
                set_deadline!(p, Int64(time_ns()) - 1_000_000_000)
                @test _qgs_err(() -> read(p, 6)) isa UDGS.DeadlineExceededError
            end
        end
    end
end

@testset "Streams Map (public API)" begin
    @testset "closes" begin
        for persp in (:server, :client)
            @testset "$persp" begin
                _qgs_api() do c, srv
                    conn = persp == :client ? c : srv
                    close(conn)
                    @test _qgs_err(() -> QGS.open_stream(conn)) isa QGS.ConnectionError
                    @test _qgs_err(() -> QGS.open_stream(conn; bidi = false)) isa QGS.ConnectionError
                    @test _qgs_err(() -> QGS.accept_stream(conn)) isa QGS.ConnectionError
                end
            end
        end
    end
end

@testset "Streams Map (incoming, public API)" begin
    @testset "blocks AcceptStream until a new stream is available" begin
        _qgs_api() do c, srv
            acceptor = Threads.@spawn QGS.accept_stream(srv)
            @test !_qgs_finishes(acceptor, 0.1)
            s = QGS.open_stream(c; bidi = false)
            write(s, UInt8[0x01])
            @test _qgs_finishes(acceptor, 10)
            @test QGS.stream_id(fetch(acceptor)) == QGS.stream_id(s)
        end
    end

    @testset "unblocks AcceptStream when the context is canceled" begin
        _qgs_api() do c, srv
            @test _qgs_err(() -> QGS.accept_stream(srv; deadline_ns = _qgs_deadline(0.2))) isa UDGS.DeadlineExceededError
        end
    end

    @testset "unblocks AcceptStream when it is closed" begin
        _qgs_api() do c, srv
            acceptor = _qgs_spawn(() -> QGS.accept_stream(srv))
            @test !_qgs_finishes(acceptor, 0.1)
            close(srv)
            @test _qgs_finishes(acceptor, 10)
            @test fetch(acceptor)[1] isa QGS.ConnectionError
        end
    end

    @testset "errors AcceptStream immediately if it is closed" begin
        _qgs_api() do c, srv
            close(srv)
            @test _qgs_err(() -> QGS.accept_stream(srv)) isa QGS.ConnectionError
        end
    end

    @testset "closes all streams when CloseWithError is called" begin
        _qgs_api() do c, srv
            p1 = _qgs_accept_peer(QGS.open_stream(c; bidi = false), srv)
            p2 = _qgs_accept_peer(QGS.open_stream(c; bidi = false), srv)
            close(srv)
            @test _qgs_err(() -> read(p1, 1)) isa QGS.ConnectionError
            @test _qgs_err(() -> read(p2, 1)) isa QGS.ConnectionError
        end
    end
end

@testset "Streams Map (outgoing, public API)" begin
    # Ends stream `s` both ways, so the server raises the client's stream limit.
    function release!(s, srv)
        closewrite(s)
        p = QGS.accept_stream(srv; deadline_ns = _qgs_deadline(10))
        @test QGS.stream_id(p) == QGS.stream_id(s)
        read(p)
        closewrite(p)
        read(s)
        return nothing
    end
    opener(c; kw...) = Threads.@spawn QGS.open_stream(c; kw...)
    limit(n) = (; server_kw = (; max_streams_bidi = n))

    @testset "no stream ID limit" begin
        @testset "closes all streams when CloseWithError is called" begin
            _qgs_api() do c, srv
                s1 = QGS.open_stream(c)
                s2 = QGS.open_stream(c)
                close(c)
                @test _qgs_err(() -> write(s1, UInt8[0x01])) isa QGS.ConnectionError
                @test _qgs_err(() -> read(s2, 1)) isa QGS.ConnectionError
            end
        end
    end

    @testset "with stream ID limits" begin
        @testset "returns immediately when called with a canceled context" begin
            _qgs_api(; limit(0)...) do c, srv
                @test _qgs_err(() -> QGS.open_stream(c; deadline_ns = Int64(time_ns()) - 1)) isa UDGS.DeadlineExceededError
            end
        end

        @testset "blocks until a stream can be opened synchronously" begin
            _qgs_api(; limit(1)...) do c, srv
                s1 = QGS.open_stream(c)
                t = opener(c)
                @test !_qgs_finishes(t, 0.1)
                release!(s1, srv)
                @test _qgs_finishes(t, 10)
                @test QGS.stream_id(fetch(t)) == 4
            end
        end

        @testset "unblocks when the context is canceled" begin
            _qgs_api(; limit(1)...) do c, srv
                s1 = QGS.open_stream(c)
                @test _qgs_err(() -> QGS.open_stream(c; deadline_ns = _qgs_deadline(0.2))) isa UDGS.DeadlineExceededError
                release!(s1, srv)
                # The next stream opened is still the next number.
                @test QGS.stream_id(QGS.open_stream(c; deadline_ns = _qgs_deadline(10))) == 4
            end
        end

        @testset "opens streams in the right order" begin
            _qgs_api(; limit(1)...) do c, srv
                s1 = QGS.open_stream(c)
                t1 = opener(c)
                sleep(0.05)
                t2 = opener(c)
                sleep(0.05)
                release!(s1, srv)
                @test timedwait(() -> istaskdone(t1) || istaskdone(t2), 10) == :ok
                first_done, other = istaskdone(t1) ? (t1, t2) : (t2, t1)
                @test !_qgs_finishes(other, 0.1)
                release!(fetch(first_done), srv)
                @test _qgs_finishes(other, 10)
                @test QGS.stream_id(fetch(t1)) == 4 && QGS.stream_id(fetch(t2)) == 8
            end
        end

        @testset "opens streams in the right order, when one of the contexts is canceled" begin
            _qgs_api(; limit(1)...) do c, srv
                s1 = QGS.open_stream(c)
                t1 = opener(c)
                sleep(0.05)
                t2 = _qgs_spawn(() -> QGS.open_stream(c; deadline_ns = _qgs_deadline(0.2)))
                sleep(0.05)
                t3 = opener(c)
                @test fetch(t2)[1] isa UDGS.DeadlineExceededError
                release!(s1, srv)
                @test timedwait(() -> istaskdone(t1) || istaskdone(t3), 10) == :ok
                first_done, other = istaskdone(t1) ? (t1, t3) : (t3, t1)
                release!(fetch(first_done), srv)
                @test _qgs_finishes(other, 10)
                @test QGS.stream_id(fetch(t1)) == 4 && QGS.stream_id(fetch(t3)) == 8
            end
        end

        @testset "unblocks multiple OpenStreamSync calls at the same time" begin
            _qgs_api(; limit(2)...) do c, srv
                s1 = QGS.open_stream(c)
                s2 = QGS.open_stream(c)
                # Each task returns its stream or its exception.
                attempt() = Threads.@spawn try
                    QGS.open_stream(c)
                catch ex
                    ex
                end
                t1 = attempt()
                t2 = attempt()
                sleep(0.05)
                t3 = attempt()
                sleep(0.05)
                release!(s1, srv)
                release!(s2, srv)
                tasks = (t1, t2, t3)
                @test timedwait(() -> count(istaskdone, tasks) >= 2, 10) == :ok
                sleep(0.1)
                opened = filter(istaskdone, collect(tasks))
                @test length(opened) == 2
                @test sort([QGS.stream_id(fetch(t)) for t in opened]) == [8, 12]
                @test istaskdone(t1) && istaskdone(t2)
                close(c)
                @test all(t -> _qgs_finishes(t, 10), tasks)
                @test count(t -> fetch(t) isa QGS.ConnectionError, tasks) == 1
            end
        end

        @testset "returns an error for OpenStream while an OpenStreamSync call is blocking" begin
            _qgs_api(; limit(1)...) do c, srv
                s1 = QGS.open_stream(c)
                sync = opener(c)
                @test !_qgs_finishes(sync, 0.05)
                # OpenStream is an attempt that never waits; it fails while the
                # limit allows nothing.
                @test _qgs_err(() -> QGS.open_stream(c; deadline_ns = 1)) isa UDGS.DeadlineExceededError
                # The limit rises by one, as when MAX_STREAMS arrives, and
                # OpenStream is tried before the woken OpenStreamSync runs.
                err = lock(c.ep.lock) do
                    c.slot.conn.peer_max_streams_bidi += 1
                    QGS._wake!(c.slot, false)
                    _qgs_err(() -> QGS.open_stream(c; deadline_ns = 1))
                end
                # OpenStream fails while an OpenStreamSync call is queued, so
                # the new stream goes to the caller that waited.
                @test err isa UDGS.DeadlineExceededError
                @test _qgs_finishes(sync, 10)
                @test QGS.stream_id(fetch(sync)) == 4
            end
        end

        @testset "stops opening synchronously when it is closed" begin
            _qgs_api(; limit(0)...) do c, srv
                t = _qgs_spawn(() -> QGS.open_stream(c))
                @test !_qgs_finishes(t, 0.1)
                close(c)
                @test _qgs_finishes(t, 10)
                @test fetch(t)[1] isa QGS.ConnectionError
            end
        end
    end
end
end
