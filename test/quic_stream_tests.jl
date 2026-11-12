using Test
using Reseau

# QUIC streams (RFC 9000 Sections 2 to 4): stream IDs and limits, flow control,
# resets, loss recovery (RFC 9002), and congestion control, between in-memory
# connections.

@isdefined(_QcnHarness) || include("quic_harness.jl")

const _QST_SECOND = Int64(1_000_000_000)

# Echoes every stream the peer opens: bidirectional data goes back on the same
# stream, finished when the peer finishes. Everything read is kept in
# `received`, by stream.
struct _QstEcho
    open::Vector{UInt64}
    received::Dict{UInt64, Vector{UInt8}}
end

_QstEcho() = _QstEcho(UInt64[], Dict{UInt64, Vector{UInt8}}())

function _qst_echo!(conn, echo::_QstEcho)
    while (id = QCN._accept_stream!(conn)) !== nothing
        push!(echo.open, id)
        echo.received[id] = UInt8[]
    end
    for id in copy(echo.open)
        r = QCN._stream_read!(conn, id)
        append!(echo.received[id], r.data)
        if QCN._is_bidi(id)
            QCN._stream_write!(conn, id, r.data; fin = r.fin)
        end
        r.fin && filter!(!=(id), echo.open)
    end
    return nothing
end

# Reads `id` on `conn` into `into` until FIN; returns whether it finished.
function _qst_read!(conn, id, into::Vector{UInt8})
    r = QCN._stream_read!(conn, id)
    append!(into, r.data)
    return r.fin
end

function _qst_handshake(; kwargs...)
    h = _QcnHarness(; kwargs...)
    _qcn_run!(h) || error("handshake failed")
    return h
end

_qst_stream_frame(id, offset, data; fin = false) =
    (buf = UInt8[]; QCN._append_stream_frame!(buf, UInt64(id), UInt64(offset), data; fin); buf)

# The ACK Delay field of the ACK frame in a server datagram, read with the
# client's keys.
function _qst_ack_delay(h, dgram)
    space = h.client.spaces[QCN._APPLICATION_SPACE]
    header = first(QCN._datagram_packets(dgram, 1, length(dgram), QCN._LOCAL_CID_LEN))
    _, payload_first, payload_last = QCN._open_packet!(space.read_keys, dgram, header.first, header.pn_offset, header.last, space.largest_received)
    delay = Ref{Union{Nothing, UInt64}}(nothing)
    QCN._decode_frames(dgram, payload_first, payload_last, header.type) do frame
        frame isa QCN._AckFrame && (delay[] = frame.delay)
        nothing
    end
    return delay[]
end

function _qst_expect_close(h, code)
    @test h.server.error !== nothing && h.server.error.code == code
    @test h.server.state == QCN._ConnState.Closing
end

@testset "QUIC streams" begin
    @testset "a bidirectional stream echoes data, and both sides free it" begin
        h = _qst_handshake()
        data = rand(UInt8, 100_000)
        id = QCN._open_stream!(h.client)
        @test id == 0
        QCN._stream_write!(h.client, id, data; fin = true)
        echo = _QstEcho()
        got = UInt8[]
        finished = Ref(false)
        @test _qcn_run!(h; app = h -> (_qst_echo!(h.server, echo); finished[] |= _qst_read!(h.client, id, got)), done = h -> finished[])
        @test got == data
        @test echo.received[id] == data
        @test h.client.error === nothing && h.server.error === nothing
        # Once every byte and both FINs are acknowledged, neither side keeps the stream.
        @test _qcn_run!(h; done = h -> isempty(h.client.streams) && isempty(h.server.streams), max_time = h.now + 5 * _QST_SECOND)
        # Reading a finished, freed stream just reports the end.
        r = QCN._stream_read!(h.client, id)
        @test isempty(r.data) && r.fin
    end

    @testset "stream IDs encode the initiator and direction (Section 2.1)" begin
        h = _qst_handshake()
        @test [QCN._open_stream!(h.client) for _ in 1:3] == UInt64[0, 4, 8]
        @test [QCN._open_stream!(h.client; bidi = false) for _ in 1:2] == UInt64[2, 6]
        @test [QCN._open_stream!(h.server) for _ in 1:2] == UInt64[1, 5]
        @test [QCN._open_stream!(h.server; bidi = false) for _ in 1:2] == UInt64[3, 7]
        # Data on stream 8 opens 0 and 4 too, and the peer accepts them in order (Section 3.2).
        QCN._stream_write!(h.client, UInt64(8), UInt8[0x01])
        _qcn_exchange!(h)
        @test [QCN._accept_stream!(h.server) for _ in 1:4] == [UInt64(0), UInt64(4), UInt64(8), nothing]
    end

    @testset "unidirectional streams carry data one way" begin
        h = _qst_handshake()
        id = QCN._open_stream!(h.client; bidi = false)
        QCN._stream_write!(h.client, id, Vector{UInt8}(codeunits("hello")); fin = true)
        _qcn_exchange!(h)
        @test QCN._accept_stream!(h.server) == id
        r = QCN._stream_read!(h.server, id)
        @test r.data == codeunits("hello") && r.fin
        @test_throws ArgumentError QCN._stream_write!(h.server, id, UInt8[0x01])
        @test_throws ArgumentError QCN._stream_read!(h.client, id)
        # Streams that were never opened cannot be used.
        @test_throws ArgumentError QCN._stream_write!(h.client, UInt64(4), UInt8[0x01])
        @test_throws ArgumentError QCN._stream_read!(h.client, UInt64(1))
    end

    @testset "stream limits, raised as streams close (Section 4.6)" begin
        h = _qst_handshake(server_limits = QCN._StreamLimits(max_streams_bidi = 2, max_streams_uni = 1))
        a = QCN._open_stream!(h.client)
        b = QCN._open_stream!(h.client)
        @test QCN._open_stream!(h.client) === nothing
        @test QCN._open_stream!(h.client; bidi = false) !== nothing
        @test QCN._open_stream!(h.client; bidi = false) === nothing
        for id in (a, b)
            QCN._stream_write!(h.client, id, UInt8[0x01]; fin = true)
        end
        echo = _QstEcho()
        got = Dict(a => UInt8[], b => UInt8[])
        third = Ref{Union{Nothing, UInt64}}(nothing)
        @test _qcn_run!(h; app = h -> begin
            _qst_echo!(h.server, echo)
            _qst_read!(h.client, a, got[a])
            _qst_read!(h.client, b, got[b])
            third[] === nothing && (third[] = QCN._open_stream!(h.client))
        end, done = h -> third[] !== nothing)
        @test third[] == 8
    end

    @testset "a peer opening too many streams gets STREAM_LIMIT_ERROR" begin
        h = _qst_handshake(server_limits = QCN._StreamLimits(max_streams_bidi = 2))
        _qcn_inject!(h, true, _qst_stream_frame(8, 0, UInt8[0x01]))
        _qst_expect_close(h, QCN._STREAM_LIMIT_ERROR)
    end

    @testset "frames for streams in the wrong state get STREAM_STATE_ERROR (Section 19)" begin
        # A server-initiated stream the server never opened.
        h = _qst_handshake()
        _qcn_inject!(h, true, _qst_stream_frame(1, 0, UInt8[0x01]))
        _qst_expect_close(h, QCN._STREAM_STATE_ERROR)
        # STREAM on the server's own unidirectional stream.
        h = _qst_handshake()
        QCN._open_stream!(h.server; bidi = false)
        _qcn_inject!(h, true, _qst_stream_frame(3, 0, UInt8[0x01]))
        _qst_expect_close(h, QCN._STREAM_STATE_ERROR)
        # RESET_STREAM on it.
        h = _qst_handshake()
        QCN._open_stream!(h.server; bidi = false)
        buf = UInt8[]
        QCN._append_reset_stream_frame!(buf, UInt64(3), UInt64(0), UInt64(0))
        _qcn_inject!(h, true, buf)
        _qst_expect_close(h, QCN._STREAM_STATE_ERROR)
        # MAX_STREAM_DATA and STOP_SENDING for a stream the server only receives on.
        for frame! in (b -> QCN._append_max_stream_data_frame!(b, UInt64(2), UInt64(10_000)),
                       b -> QCN._append_stop_sending_frame!(b, UInt64(2), UInt64(0)))
            h = _qst_handshake()
            id = QCN._open_stream!(h.client; bidi = false)
            QCN._stream_write!(h.client, id, UInt8[0x01])
            _qcn_exchange!(h)
            buf = UInt8[]
            frame!(buf)
            _qcn_inject!(h, true, buf)
            _qst_expect_close(h, QCN._STREAM_STATE_ERROR)
        end
    end

    @testset "flow control holds the sender to the receiver's limits (Section 4.1)" begin
        h = _qst_handshake(server_limits = QCN._StreamLimits(max_stream_data = 1000, max_data = 1500))
        a = QCN._open_stream!(h.client)
        b = QCN._open_stream!(h.client)
        data = Dict(a => rand(UInt8, 5000), b => rand(UInt8, 5000))
        for id in (a, b)
            QCN._stream_write!(h.client, id, data[id]; fin = true)
        end
        # Nobody reads on the server, so the client stops at the limits.
        @test !_qcn_run!(h; done = h -> false, max_time = h.now + 2 * _QST_SECOND)
        @test h.client.streams[a].send.max_sent <= 1000
        @test h.client.streams[b].send.max_sent <= 1000
        @test h.client.data_sent == 1500
        @test h.client.error === nothing && h.server.error === nothing
        # Reading opens the windows again, and the rest follows.
        echo = _QstEcho()
        @test _qcn_run!(h; app = h -> _qst_echo!(h.server, echo),
            done = h -> length(echo.received) == 2 && isempty(echo.open))
        @test echo.received[a] == data[a]
        @test echo.received[b] == data[b]
    end

    @testset "flow control violations get FLOW_CONTROL_ERROR" begin
        limits = QCN._StreamLimits(max_stream_data = 1000, max_data = 1500)
        # Past the stream's limit.
        h = _qst_handshake(server_limits = limits)
        _qcn_inject!(h, true, _qst_stream_frame(0, 1000, UInt8[0x01]))
        _qst_expect_close(h, QCN._FLOW_CONTROL_ERROR)
        # Past the connection's limit, across two streams.
        h = _qst_handshake(server_limits = limits)
        _qcn_inject!(h, true, vcat(_qst_stream_frame(0, 0, rand(UInt8, 1000)), _qst_stream_frame(4, 0, rand(UInt8, 501))))
        _qst_expect_close(h, QCN._FLOW_CONTROL_ERROR)
        # A RESET_STREAM final size counts too.
        h = _qst_handshake(server_limits = limits)
        buf = UInt8[]
        QCN._append_reset_stream_frame!(buf, UInt64(0), UInt64(0), UInt64(1001))
        _qcn_inject!(h, true, buf)
        _qst_expect_close(h, QCN._FLOW_CONTROL_ERROR)
        # Retransmitted bytes below the limit are fine.
        h = _qst_handshake(server_limits = limits)
        frame = _qst_stream_frame(0, 0, rand(UInt8, 1000))
        _qcn_inject!(h, true, frame)
        _qcn_inject!(h, true, frame)
        @test h.server.error === nothing
    end

    @testset "final size violations get FINAL_SIZE_ERROR (Section 4.5)" begin
        h = _qst_handshake()
        _qcn_inject!(h, true, _qst_stream_frame(0, 0, rand(UInt8, 100)))
        buf = UInt8[]
        QCN._append_reset_stream_frame!(buf, UInt64(0), UInt64(0), UInt64(50))
        _qcn_inject!(h, true, buf)
        _qst_expect_close(h, QCN._FINAL_SIZE_ERROR)
    end

    @testset "RESET_STREAM abandons a stream (Section 3.2)" begin
        h = _qst_handshake()
        id = QCN._open_stream!(h.client)
        QCN._stream_write!(h.client, id, rand(UInt8, 5000))
        _qcn_exchange!(h)
        QCN._stream_reset!(h.client, id, UInt64(7))
        @test_throws ArgumentError QCN._stream_write!(h.client, id, UInt8[0x01])
        got = UInt8[]
        result = Ref{Any}(nothing)
        @test _qcn_run!(h; app = h -> begin
            QCN._accept_stream!(h.server)
            r = QCN._stream_read!(h.server, id)
            append!(got, r.data)
            r.fin && (result[] = r)
        end, done = h -> result[] !== nothing)
        @test result[].reset_code == 7
        # Data already delivered may or may not have been read; none is invented.
        @test length(got) <= 5000
    end

    @testset "STOP_SENDING makes the sender reset the stream (Section 3.5)" begin
        # A small window keeps most of the data unsent when STOP_SENDING arrives.
        h = _qst_handshake(server_limits = QCN._StreamLimits(max_stream_data = 10_000))
        id = QCN._open_stream!(h.client)
        QCN._stream_write!(h.client, id, rand(UInt8, 200_000))
        _qcn_exchange!(h)
        @test QCN._accept_stream!(h.server) == id
        QCN._stream_stop_sending!(h.server, id, UInt64(9))
        result = Ref{Any}(nothing)
        @test _qcn_run!(h; app = h -> begin
            r = QCN._stream_read!(h.server, id)
            r.fin && (result[] = r)
        end, done = h -> result[] !== nothing)
        @test result[].reset_code == 9
        @test QCN._stream_stop_code(h.client, id) == 9
        # The client gave up on the rest of its data.
        @test h.client.data_sent < 200_000
        QCN._stream_write!(h.client, id, UInt8[0x01])  # ignored
        @test h.client.error === nothing && h.server.error === nothing
    end

    @testset "lost stream data is retransmitted" begin
        # Every seventh datagram in each direction is lost.
        h = _qst_handshake()
        h.drop = (from_client, n) -> n % 7 == 0
        data = rand(UInt8, 300_000)
        id = QCN._open_stream!(h.client)
        QCN._stream_write!(h.client, id, data; fin = true)
        echo = _QstEcho()
        got = UInt8[]
        finished = Ref(false)
        @test _qcn_run!(h; app = h -> (_qst_echo!(h.server, echo); finished[] |= _qst_read!(h.client, id, got)), done = h -> finished[])
        @test got == data
    end

    @testset "reordered and duplicated stream data" begin
        h = _qst_handshake()
        h.hold = (from_client, n) -> n % 3 == 0
        h.duplicate = (from_client, n) -> n % 5 == 0
        data = rand(UInt8, 100_000)
        id = QCN._open_stream!(h.client)
        QCN._stream_write!(h.client, id, data; fin = true)
        echo = _QstEcho()
        got = UInt8[]
        finished = Ref(false)
        @test _qcn_run!(h; app = h -> (_qst_echo!(h.server, echo); finished[] |= _qst_read!(h.client, id, got)), done = h -> finished[])
        @test got == data
    end

    @testset "a lone lost STREAM packet is resent on probe timeout" begin
        h = _qst_handshake()
        sent_before = h.sent_count[true]
        h.drop = (from_client, n) -> from_client && n == sent_before + 1
        id = QCN._open_stream!(h.client)
        QCN._stream_write!(h.client, id, UInt8[1, 2, 3]; fin = true)
        _qcn_exchange!(h)
        @test QCN._accept_stream!(h.server) === nothing  # lost
        # The first probe carries the lost data again (RFC 9002 Section 6.2.4).
        t = QCN._next_timeout(h.client)
        QCN._handle_timeout!(h.client, t)
        h.now = t
        QCN._receive_datagram!(h.server, QCN._next_datagram!(h.client, t), t)
        @test QCN._accept_stream!(h.server) == id
        got = UInt8[]
        finished = Ref(false)
        accepted = Ref(true)
        @test _qcn_run!(h; app = h -> begin
            accepted[] |= QCN._accept_stream!(h.server) !== nothing
            accepted[] && (finished[] |= _qst_read!(h.server, id, got))
        end, done = h -> finished[])
        @test got == [1, 2, 3]
        # A packet a probe timeout resends is not counted as lost.
        @test h.client.packets_lost == 0
    end

    @testset "ACKs for 1-RTT packets are delayed up to max_ack_delay (Section 13.2.1)" begin
        h = _qst_handshake()
        _qcn_run!(h; done = h -> false, max_time = h.now + _QST_SECOND)  # settle
        id = QCN._open_stream!(h.client)
        QCN._stream_write!(h.client, id, UInt8[0x01])
        dgram = QCN._next_datagram!(h.client, h.now)
        QCN._receive_datagram!(h.server, dgram, h.now)
        # One ack-eliciting packet: the ACK waits.
        @test QCN._next_datagram!(h.server, h.now) === nothing
        deadline = QCN._next_timeout(h.server)
        @test deadline <= h.now + Int64(h.server.local_params.max_ack_delay_ms) * 1_000_000
        QCN._handle_timeout!(h.server, deadline)
        ack = QCN._next_datagram!(h.server, deadline)
        @test ack !== nothing
        # The ACK reports how long it waited, in units of 2^3 microseconds.
        @test _qst_ack_delay(h, copy(ack)) == UInt64((deadline - h.now) ÷ 1000) >> 3
        # A second ack-eliciting packet gets an ACK right away.
        h.now = deadline
        for _ in 1:2
            QCN._stream_write!(h.client, id, UInt8[0x02])
            QCN._receive_datagram!(h.server, QCN._next_datagram!(h.client, h.now), h.now)
        end
        @test QCN._next_datagram!(h.server, h.now) !== nothing
        # So does a packet that arrives out of order.
        first_dgram = (QCN._stream_write!(h.client, id, UInt8[0x03]); QCN._next_datagram!(h.client, h.now))
        second_dgram = (QCN._stream_write!(h.client, id, UInt8[0x04]); QCN._next_datagram!(h.client, h.now))
        QCN._receive_datagram!(h.server, second_dgram, h.now)
        @test QCN._next_datagram!(h.server, h.now) !== nothing
        QCN._receive_datagram!(h.server, first_dgram, h.now)
    end

    @testset "congestion control limits bytes in flight (RFC 9002 Section 7)" begin
        @test QCN._INITIAL_WINDOW == 10 * QCN._MAX_DATAGRAM_SIZE
        h = _qst_handshake()
        # Acknowledged handshake packets have already grown the window.
        window = h.client.cwnd
        @test window >= QCN._INITIAL_WINDOW
        # The server's datagrams are all lost, so nothing is acknowledged.
        sent_before = h.sent_count[true]
        h.drop = (from_client, n) -> !from_client
        id = QCN._open_stream!(h.client)
        QCN._stream_write!(h.client, id, rand(UInt8, 1_000_000))
        _qcn_exchange!(h)
        sent = sum(length(s.bytes) for s in _qcn_sent(h, true)[(sent_before + 1):end])
        @test sent <= window
        @test h.client.bytes_in_flight <= h.client.cwnd

        # Without loss, slow start grows the window; a loss then halves it.
        h = _qst_handshake()
        echo = _QstEcho()
        id = QCN._open_stream!(h.client)
        QCN._stream_write!(h.client, id, rand(UInt8, 200_000); fin = true)
        overshoot = Ref(0)
        got = UInt8[]
        finished = Ref(false)
        @test _qcn_run!(h; app = h -> begin
            overshoot[] = max(overshoot[], h.client.bytes_in_flight - h.client.cwnd)
            _qst_echo!(h.server, echo)
            finished[] |= _qst_read!(h.client, id, got)
        end, done = h -> finished[])
        @test overshoot[] <= 0
        @test h.client.cwnd > window
        @test h.client.ssthresh == typemax(Int)
        grown = h.client.cwnd
        lost = Ref(false)
        h.drop = (from_client, n) -> from_client && !lost[] && (lost[] = true)
        id = QCN._open_stream!(h.client)
        QCN._stream_write!(h.client, id, rand(UInt8, 50_000); fin = true)
        got = UInt8[]
        finished[] = false
        @test _qcn_run!(h; app = h -> (_qst_echo!(h.server, echo); finished[] |= _qst_read!(h.client, id, got)), done = h -> finished[])
        # The ACK that reveals the loss first grows the window for what it
        # acknowledges (RFC 9002 Section 7.3.2), so halving starts above `grown`.
        @test h.client.ssthresh < grown
        # Loss detection, not a probe timeout, found the one dropped packet.
        @test h.client.packets_lost == 1
    end

    @testset "nothing stays in flight once the handshake settles" begin
        # Packets in discarded Initial and Handshake spaces leave flight with them.
        h = _qst_handshake()
        @test !_qcn_run!(h; done = h -> false, max_time = h.now + _QST_SECOND)
        @test h.client.bytes_in_flight == 0
        @test h.server.bytes_in_flight == 0
    end

    @testset "a recovery period reduces the window once (RFC 9002 Section 7.3.2)" begin
        h = _qst_handshake()
        conn = h.client
        conn.cwnd = 100_000
        QCN._cc_on_congestion!(conn, h.now - 10, h.now)
        @test conn.cwnd == 70_000 && conn.ssthresh == 70_000
        # More losses of packets sent before recovery began change nothing.
        QCN._cc_on_congestion!(conn, h.now - 5, h.now + 1)
        @test conn.cwnd == 70_000
        # Neither do their acknowledgments; packets sent later grow the window.
        conn.bytes_in_flight = 70_000
        QCN._cc_on_acked!(conn, QCN._SentPacket(Int64(0), h.now - 1, 1200, QCN._SentFrame[]), h.now + 2, true)
        @test conn.cwnd == 70_000
        QCN._cc_on_acked!(conn, QCN._SentPacket(Int64(1), h.now + 1, 1200, QCN._SentFrame[]), h.now + 2, true)
        @test conn.cwnd > 70_000
        @test conn.bytes_in_flight == 70_000 - 2400
    end

    @testset "credit for reset and discarded data returns to the connection window" begin
        # The connection window fits one stream's worth: unless the abandoned
        # stream's bytes count as consumed, the second stream can never finish.
        for abandon! in ((h, id) -> QCN._stream_reset!(h.client, id, UInt64(1)),
                         (h, id) -> QCN._stream_stop_sending!(h.server, id, UInt64(1)))
            h = _qst_handshake(server_limits = QCN._StreamLimits(max_data = 3000, max_stream_data = 3000))
            a = QCN._open_stream!(h.client)
            QCN._stream_write!(h.client, a, rand(UInt8, 2000))
            _qcn_exchange!(h)
            abandon!(h, a)
            b = QCN._open_stream!(h.client)
            data = rand(UInt8, 3000)
            QCN._stream_write!(h.client, b, data; fin = true)
            # The server reads only the second stream.
            got = UInt8[]
            finished = Ref(false)
            @test _qcn_run!(h; app = h -> begin
                while QCN._accept_stream!(h.server) !== nothing end
                QCN._stream_opened(h.server, b) && (finished[] |= _qst_read!(h.server, b, got))
            end, done = h -> finished[], max_time = h.now + 10 * _QST_SECOND)
            @test got == data
        end
    end

    @testset "lost RESET_STREAM and MAX_DATA frames are sent again" begin
        h = _qst_handshake()
        id = QCN._open_stream!(h.client)
        QCN._stream_write!(h.client, id, rand(UInt8, 100))
        _qcn_exchange!(h)
        QCN._stream_reset!(h.client, id, UInt64(5))
        sent_before = h.sent_count[true]
        h.drop = (from_client, n) -> from_client && n == sent_before + 1
        result = Ref{Any}(nothing)
        @test _qcn_run!(h; app = h -> begin
            QCN._accept_stream!(h.server)
            r = QCN._stream_read!(h.server, id)
            r.fin && (result[] = r)
        end, done = h -> result[] !== nothing)
        @test result[].reset_code == 5

        # The client is blocked on the connection window; the server's first
        # datagram after reading, carrying MAX_DATA, is lost.
        h = _qst_handshake(server_limits = QCN._StreamLimits(max_data = 1500, max_stream_data = 100_000))
        id = QCN._open_stream!(h.client)
        data = rand(UInt8, 5000)
        QCN._stream_write!(h.client, id, data; fin = true)
        _qcn_exchange!(h)
        @test h.client.data_sent == 1500
        sent_before = h.sent_count[false]
        h.drop = (from_client, n) -> !from_client && n == sent_before + 1
        echo = _QstEcho()
        @test _qcn_run!(h; app = h -> _qst_echo!(h.server, echo),
            done = h -> haskey(echo.received, id) && !(id in echo.open), max_time = h.now + 10 * _QST_SECOND)
        @test echo.received[id] == data
    end
end
