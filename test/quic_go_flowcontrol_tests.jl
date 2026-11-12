using Test
using Reseau

# Ported from quic-go v0.48.2 (github.com/quic-go/quic-go@v0.48.2):
#   internal/flowcontrol/base_flow_controller_test.go
#   internal/flowcontrol/connection_flow_controller_test.go
#   internal/flowcontrol/stream_flow_controller_test.go
#
# Each Go `It` is a @testset named after its Describe/Context/It path. Where
# we behave differently from Go, a `# Differs from quic-go:` note says why.
#
# How quic-go's flow controllers map onto a `_Connection`:
#   - receive side, stream: receiveWindow is `s.recv_max`, receiveWindowSize
#     `conn.limits.max_stream_data`, bytesRead `s.recv.read_offset`,
#     highestReceived `s.recv.max_received`; connection: `conn.local_max_data`,
#     `conn.limits.max_data`, `conn.data_consumed`, `conn.data_received`.
#     A queued window update is `s.max_stream_data_pending` /
#     `conn.max_data_pending`; GetWindowUpdate takes it (clears the flag).
#   - UpdateHighestReceived(offset, final) is an empty STREAM frame ending at
#     `offset` (quic-go calls it with a frame's offset plus length), handled
#     by `_on_frame!`; an error is the `_TransportError` it returns (Go's
#     message text is not compared, only the error code).
#   - AddBytesRead(n) delivers n bytes at the read offset, if not already
#     there, and reads them with `_stream_read!`, which also consumes them at
#     the connection level, as Go's stream controller does.
#   - Abandon() is the application abandoning the stream's receive side
#     (quic-go calls it from CancelRead once the final size is known), i.e.
#     `_stream_stop_sending!`.
#   - send side: sendWindow is `s.send_max` / `conn.peer_max_data`,
#     bytesSent `s.send.max_sent` / `conn.data_sent`, sendWindowSize
#     `_stream_send_limit(conn, s) - s.send.max_sent`; UpdateSendWindow is a
#     MAX_STREAM_DATA / MAX_DATA frame. AddBytesSent(n) writes n bytes and
#     builds a packet: we never send past the window, so where Go adds bytes
#     before any window exists the window is opened just enough first.
#     IsNewlyBlocked is whether the packets built carry a STREAM_DATA_BLOCKED /
#     DATA_BLOCKED frame for that limit.
#   - The base flow controller's tests run on both the stream and the
#     connection level, the two places Go embeds it.
#
# Not applicable (deliberately absent from Reseau.QUIC):
#   base_flow_controller_test.go "receive window size auto-tuning", all 6 Its
#   connection_flow_controller_test.go
#     "auto-tunes the window", "doesn't auto-tune the window if it's not allowed"
#     "setting the minimum window size", all 4 Its (EnsureMinimumWindowSize
#         exists for auto-tuning)
#     "resetting", both Its (Reset is for a rejected 0-RTT; no 0-RTT here)
#     Constructor's maxReceiveWindowSize check (auto-tuning)
#   stream_flow_controller_test.go
#     "tells the connection flow controller when the window was auto-tuned"
#     "doesn't increase the connection flow control window if it's not allowed"

@isdefined(_QcnHarness) || include("quic_harness.jl")

const QGF = Reseau.QUIC
# A bidirectional stream the server opens: the peer's, for a client connection.
const _QGF_PEER_STREAM = UInt64(1)

function _qgf_conn(; max_data::Integer = 1_000_000, max_stream_data::Integer = 1_000_000)
    limits = QGF._StreamLimits(max_data = Int64(max_data), max_stream_data = Int64(max_stream_data))
    return QGF._client_connection(_qcn_client_config(), Int64(0); limits)
end

# A STREAM frame from the peer carrying bytes [offset, offset + len).
function _qgf_frame!(conn, offset::Integer, len::Integer = 0; fin::Bool = false, id::UInt64 = _QGF_PEER_STREAM)
    buf = fill(0x61, len)
    frame = QGF._StreamFrame(id, UInt64(offset), 1:len, fin)
    return QGF._on_frame!(conn, conn.spaces[QGF._APPLICATION_SPACE], QGF._APPLICATION_SPACE, buf, frame, Int64(0))
end

# UpdateHighestReceived(offset, final)
_qgf_highest!(conn, offset::Integer; fin::Bool = false) = _qgf_frame!(conn, offset, 0; fin)

_qgf_stream(conn) = conn.streams[_QGF_PEER_STREAM]

# AddBytesRead(n)
function _qgf_read!(conn, n::Integer)
    s = _qgf_stream(conn)
    rb = s.recv
    QGF._recv_readable(rb) < n && @assert _qgf_frame!(conn, rb.read_offset, n) === nothing
    r = QGF._stream_read!(conn, _QGF_PEER_STREAM, Int(n))
    @assert length(r.data) == n
    return nothing
end

# GetWindowUpdate, for the stream and the connection: the new limit, or 0.
function _qgf_stream_update!(conn)
    s = _qgf_stream(conn)
    s.max_stream_data_pending || return Int64(0)
    s.max_stream_data_pending = false
    return s.recv_max
end
function _qgf_conn_update!(conn)
    conn.max_data_pending || return Int64(0)
    conn.max_data_pending = false
    return conn.local_max_data
end

_qgf_is_flow_control_error(err) = err isa QGF._TransportError && err.code == QGF._FLOW_CONTROL_ERROR
_qgf_is_final_size_error(err) = err isa QGF._TransportError && err.code == QGF._FINAL_SIZE_ERROR

# A stream this endpoint sends on, under the peer's limits.
function _qgf_sender(; stream_max::Integer, conn_max::Integer)
    conn = _qgf_conn()
    conn.peer_max_streams_bidi = 10
    conn.peer_max_data = conn_max
    id = QGF._open_stream!(conn)
    s = conn.streams[id]
    s.send_max = stream_max
    return conn, s
end

# Builds a 1-RTT payload of whatever the connection has to send; returns its frames.
function _qgf_build!(conn)
    buf = UInt8[]
    QGF._append_app_frames!(conn, buf, 65000, QGF._SentFrame[])
    frames = Any[]
    isempty(buf) || QGF._decode_frames(buf, 1, length(buf), QGF._PacketType.OneRTT) do f
        push!(frames, f)
        nothing
    end
    return frames
end

# AddBytesSent(n): write n bytes and send them. Returns the frames built.
function _qgf_send!(conn, s, n::Integer)
    QGF._stream_write!(conn, s.id, zeros(UInt8, n))
    frames = _qgf_build!(conn)
    append!(frames, _qgf_build!(conn))
    return frames
end

_qgf_window(conn, s) = QGF._stream_send_limit(conn, s) - s.send.max_sent
_qgf_bytes_sent(conn, s, level) = level === :stream ? s.send.max_sent : conn.data_sent

# UpdateSendWindow at a level.
function _qgf_update_send_window!(conn, s, level, limit::Integer)
    space = conn.spaces[QGF._APPLICATION_SPACE]
    frame = level === :stream ? QGF._MaxStreamDataFrame(s.id, UInt64(limit)) : QGF._MaxDataFrame(UInt64(limit))
    QGF._on_frame!(conn, space, QGF._APPLICATION_SPACE, UInt8[], frame, Int64(0))
    return nothing
end

# A sender whose window at `level` is `limit`, unlimited at the other level.
_qgf_sender_at(level, limit) =
    level === :stream ? _qgf_sender(; stream_max = limit, conn_max = 1 << 40) : _qgf_sender(; stream_max = 1 << 40, conn_max = limit)

# IsNewlyBlocked at a level: a blocked frame for that limit among `frames`.
function _qgf_blocked_at(frames, level, limit::Integer)
    return any(frames) do f
        level === :stream ? (f isa QGF._StreamDataBlockedFrame && f.limit == limit) :
            (f isa QGF._DataBlockedFrame && f.limit == limit)
    end
end
_qgf_any_blocked(frames, level) =
    any(f -> level === :stream ? f isa QGF._StreamDataBlockedFrame : f isa QGF._DataBlockedFrame, frames)

# A connection whose peer stream, already opened, has receive limit
# `receive_window` with window size `window_size` at the given level.
function _qgf_receiver_at(level, receive_window::Integer, window_size::Integer)
    conn = level === :stream ? _qgf_conn(; max_stream_data = window_size) : _qgf_conn(; max_data = window_size)
    @assert _qgf_highest!(conn, 0) === nothing
    if level === :stream
        _qgf_stream(conn).recv_max = receive_window
    else
        conn.local_max_data = receive_window
    end
    return conn
end

# Sets bytesRead at a level directly, as Go's tests do, and asks for an update.
function _qgf_set_read_and_update!(conn, level, read_position::Integer)
    if level === :stream
        s = _qgf_stream(conn)
        s.recv.read_offset = read_position
        QGF._update_stream_window!(conn, s)
        return _qgf_stream_update!(conn)
    else
        conn.data_consumed = read_position
        QGF._consume!(conn, Int64(0))
        return _qgf_conn_update!(conn)
    end
end
_qgf_receive_window(conn, level) = level === :stream ? _qgf_stream(conn).recv_max : conn.local_max_data

const _QGF_WINDOW_UPDATE_THRESHOLD = 0.25  # protocol.WindowUpdateThreshold

@testset "quic-go flow control" begin
    @testset "Base Flow controller ($level)" for level in (:stream, :connection)
        @testset "send flow control" begin
            @testset "adds bytes sent" begin
                conn, s = _qgf_sender_at(level, 1000)
                _qgf_send!(conn, s, 5)
                _qgf_send!(conn, s, 6)
                @test _qgf_bytes_sent(conn, s, level) == 5 + 6
            end

            @testset "gets the size of the remaining flow control window" begin
                conn, s = _qgf_sender_at(level, 12)
                _qgf_send!(conn, s, 5)
                @test _qgf_window(conn, s) == 12 - 5
            end

            @testset "updates the size of the flow control window" begin
                conn, s = _qgf_sender_at(level, 5)
                _qgf_send!(conn, s, 5)
                _qgf_update_send_window!(conn, s, level, 15)
                @test (level === :stream ? s.send_max : conn.peer_max_data) == 15
                @test _qgf_window(conn, s) == 15 - 5
            end

            @testset "says that the window size is 0 if we sent more than we were allowed to" begin
                conn, s = _qgf_sender_at(level, 15)
                _qgf_send!(conn, s, 15)
                _qgf_update_send_window!(conn, s, level, 10)
                @test _qgf_window(conn, s) == 0
            end

            @testset "does not decrease the flow control window" begin
                conn, s = _qgf_sender_at(level, 0)
                _qgf_update_send_window!(conn, s, level, 20)
                @test _qgf_window(conn, s) == 20
                _qgf_update_send_window!(conn, s, level, 10)
                @test _qgf_window(conn, s) == 20
            end

            @testset "says when it's blocked" begin
                conn, s = _qgf_sender_at(level, 100)
                # Data waits beyond the limit, as when Go's stream asks.
                frames = _qgf_send!(conn, s, 150)
                @test _qgf_bytes_sent(conn, s, level) == 100
                # STREAM_DATA_BLOCKED or DATA_BLOCKED (RFC 9000 Section 4.1).
                @test _qgf_blocked_at(frames, level, 100)
            end

            @testset "doesn't say that it's newly blocked multiple times for the same offset" begin
                conn, s = _qgf_sender_at(level, 100)
                frames = _qgf_send!(conn, s, 150)
                @test _qgf_blocked_at(frames, level, 100)
                @test !_qgf_any_blocked(_qgf_build!(conn), level)
                _qgf_update_send_window!(conn, s, level, 150)
                frames = _qgf_send!(conn, s, 50)
                @test _qgf_bytes_sent(conn, s, level) == 150
                @test _qgf_blocked_at(frames, level, 150)
            end
        end

        @testset "receive flow control" begin
            receive_window = 10000
            window_size = 1000

            @testset "adds bytes read" begin
                conn = _qgf_receiver_at(level, receive_window, window_size)
                _qgf_read!(conn, 5)
                _qgf_read!(conn, 6)
                @test (level === :stream ? _qgf_stream(conn).recv.read_offset : conn.data_consumed) == 5 + 6
            end

            @testset "triggers a window update when necessary" begin
                conn = _qgf_receiver_at(level, receive_window, window_size)
                # Consumed 1 byte more than the threshold.
                consumed = trunc(Int, window_size * _QGF_WINDOW_UPDATE_THRESHOLD + 1)
                remaining = window_size - consumed
                read_position = receive_window - remaining
                offset = _qgf_set_read_and_update!(conn, level, read_position)
                @test offset == read_position + window_size
                @test _qgf_receive_window(conn, level) == read_position + window_size
            end

            @testset "doesn't trigger a window update when not necessary" begin
                conn = _qgf_receiver_at(level, receive_window, window_size)
                # Consumed 1 byte less than the threshold.
                consumed = trunc(Int, window_size * _QGF_WINDOW_UPDATE_THRESHOLD - 1)
                remaining = window_size - consumed
                read_position = receive_window - remaining
                @test _qgf_set_read_and_update!(conn, level, read_position) == 0
            end
        end
    end

    @testset "Connection Flow controller" begin
        @testset "Constructor" begin
            @testset "sets the send and receive windows" begin
                receive_window = 2000
                conn = _qgf_conn(; max_data = receive_window)
                @test conn.local_max_data == receive_window
                @test conn.local_params.initial_max_data == receive_window
            end
        end

        @testset "receive flow control" begin
            @testset "increases the highestReceived by a given window size" begin
                conn = _qgf_conn()
                conn.data_received = 1337
                @test _qgf_frame!(conn, 0, 123) === nothing
                @test conn.data_received == 1337 + 123
            end

            # receiveWindow 100, receiveWindowSize 60, bytesRead 40.
            function setup()
                conn = _qgf_conn(; max_data = 60)
                conn.local_max_data = 100
                @assert _qgf_frame!(conn, 0, 100) === nothing
                QGF._stream_read!(conn, _QGF_PEER_STREAM, 40)
                @assert conn.data_consumed == 100 - 60
                conn.max_data_pending = false
                return conn
            end

            @testset "getting window updates" begin
                @testset "queues window updates" begin
                    conn = setup()
                    _qgf_read!(conn, 1)
                    @test _qgf_conn_update!(conn) == 0
                    _qgf_read!(conn, 29)
                    @test _qgf_conn_update!(conn) != 0
                    _qgf_read!(conn, 1)
                    @test _qgf_conn_update!(conn) == 0
                end

                @testset "gets a window update" begin
                    conn = setup()
                    window_size = conn.limits.max_data
                    old_offset = conn.data_consumed
                    data_read = window_size ÷ 2 - 1  # make sure not to trigger auto-tuning
                    _qgf_read!(conn, data_read)
                    @test _qgf_conn_update!(conn) == old_offset + data_read + 60
                end
            end
        end
    end

    @testset "Stream Flow controller" begin
        @testset "Constructor" begin
            receive_window = 2000
            send_window = 4000

            @testset "sets the send and receive windows" begin
                conn = _qgf_conn(; max_stream_data = receive_window)
                conn.peer_params = QGF._TransportParameters(initial_max_stream_data_bidi_remote = UInt64(send_window))
                conn.peer_max_streams_bidi = 10
                id = QGF._open_stream!(conn)
                s = conn.streams[id]
                @test s.recv_max == receive_window
                @test s.send_max == send_window
            end

            @testset "queues window updates" begin
                conn = _qgf_conn(; max_data = receive_window, max_stream_data = receive_window)
                @test _qgf_highest!(conn, 0) === nothing
                _qgf_read!(conn, receive_window)
                @test _qgf_stream(conn).max_stream_data_pending
            end
        end

        @testset "receiving data" begin
            @testset "registering received offsets" begin
                receive_window = 10000
                window_size = 600
                function setup()
                    conn = _qgf_receiver_at(:stream, receive_window, window_size)
                    return conn, _qgf_stream(conn)
                end

                @testset "updates the highestReceived" begin
                    conn, s = setup()
                    @test _qgf_highest!(conn, 1337) === nothing
                    @test _qgf_highest!(conn, 1338) === nothing
                    @test s.recv.max_received == 1338
                end

                @testset "informs the connection flow controller about received data" begin
                    conn, s = setup()
                    @test _qgf_highest!(conn, 10) === nothing
                    conn.data_received = 100
                    @test _qgf_highest!(conn, 20) === nothing
                    @test conn.data_received == 100 + 10
                end

                @testset "does not decrease the highestReceived" begin
                    conn, s = setup()
                    @test _qgf_highest!(conn, 1337) === nothing
                    @test _qgf_highest!(conn, 1000) === nothing
                    @test s.recv.max_received == 1337
                end

                @testset "does nothing when setting the same byte offset" begin
                    conn, s = setup()
                    @test _qgf_highest!(conn, 1337) === nothing
                    @test _qgf_highest!(conn, 1337) === nothing
                end

                @testset "does not give a flow control violation when using the window completely" begin
                    conn, s = setup()
                    conn.local_max_data = receive_window
                    @test _qgf_highest!(conn, receive_window) === nothing
                end

                @testset "detects a flow control violation" begin
                    conn, s = setup()
                    @test _qgf_is_flow_control_error(_qgf_highest!(conn, receive_window + 1))
                end

                @testset "accepts a final offset higher than the highest received" begin
                    conn, s = setup()
                    @test _qgf_highest!(conn, 100) === nothing
                    @test _qgf_highest!(conn, 101; fin = true) === nothing
                    @test s.recv.max_received == 101
                end

                @testset "errors when receiving a final offset smaller than the highest offset received so far" begin
                    conn, s = setup()
                    _qgf_highest!(conn, 100)
                    @test _qgf_is_final_size_error(_qgf_highest!(conn, 50; fin = true))
                end

                @testset "accepts delayed data after receiving a final offset" begin
                    conn, s = setup()
                    @test _qgf_highest!(conn, 300; fin = true) === nothing
                    @test _qgf_highest!(conn, 250) === nothing
                end

                @testset "errors when receiving a higher offset after receiving a final offset" begin
                    conn, s = setup()
                    @test _qgf_highest!(conn, 200; fin = true) === nothing
                    @test _qgf_is_final_size_error(_qgf_highest!(conn, 250))
                end

                @testset "accepts duplicate final offsets" begin
                    conn, s = setup()
                    @test _qgf_highest!(conn, 200; fin = true) === nothing
                    @test _qgf_highest!(conn, 200; fin = true) === nothing
                    @test s.recv.max_received == 200
                end

                @testset "errors when receiving inconsistent final offsets" begin
                    conn, s = setup()
                    @test _qgf_highest!(conn, 200; fin = true) === nothing
                    @test _qgf_is_final_size_error(_qgf_highest!(conn, 201; fin = true))
                end

                @testset "tells the connection flow controller when a stream is abandoned" begin
                    conn, s = setup()
                    _qgf_read!(conn, 5)
                    @test _qgf_highest!(conn, 100; fin = true) === nothing
                    QGF._stream_stop_sending!(conn, _QGF_PEER_STREAM, UInt64(0))
                    # Up to the final size, including the 95 bytes that never
                    # arrived (RFC 9000 Section 4.5).
                    @test conn.data_consumed == 100
                end

                @testset "tolerates repeated calls to Abandon" begin
                    conn, s = setup()
                    _qgf_read!(conn, 5)
                    @test _qgf_highest!(conn, 100; fin = true) === nothing
                    for _ in 1:3
                        QGF._stream_stop_sending!(conn, _QGF_PEER_STREAM, UInt64(0))
                    end
                    @test conn.data_consumed == 100
                end
            end

            @testset "saves when data is read" begin
                conn = _qgf_conn()
                @test _qgf_highest!(conn, 0) === nothing
                _qgf_read!(conn, 200)
                @test _qgf_stream(conn).recv.read_offset == 200
                @test conn.data_consumed == 200
            end

            @testset "generating window updates" begin
                # Stream: receiveWindow 100, receiveWindowSize 60, bytesRead 40.
                # Connection: receiveWindow 100, receiveWindowSize 120. (Go's
                # connection has read nothing; reading the stream's 40 bytes
                # here reads them at the connection level too.)
                function setup()
                    conn = _qgf_conn(; max_data = 120, max_stream_data = 60)
                    @assert _qgf_highest!(conn, 0) === nothing
                    _qgf_read!(conn, 40)
                    s = _qgf_stream(conn)
                    s.recv_max = 100
                    s.max_stream_data_pending = false
                    conn.local_max_data = 100
                    conn.max_data_pending = false
                    return conn, s
                end

                @testset "queues window updates" begin
                    conn, s = setup()
                    _qgf_read!(conn, 1)
                    @test !s.max_stream_data_pending
                    _qgf_read!(conn, 29)
                    @test s.max_stream_data_pending
                    @test _qgf_stream_update!(conn) != 0
                    _qgf_read!(conn, 1)
                    @test !s.max_stream_data_pending
                end

                @testset "sends a connection-level window update when a large stream is abandoned" begin
                    conn, s = setup()
                    @test _qgf_highest!(conn, 90; fin = true) === nothing
                    @test _qgf_conn_update!(conn) == 0
                    QGF._stream_stop_sending!(conn, _QGF_PEER_STREAM, UInt64(0))
                    # Bytes 40 to 90 never arrived, but count as consumed.
                    @test _qgf_conn_update!(conn) != 0
                end

                @testset "doesn't increase the window after a final offset was already received" begin
                    conn, s = setup()
                    @test _qgf_highest!(conn, 90; fin = true) === nothing
                    _qgf_read!(conn, 30)
                    @test !s.max_stream_data_pending
                    @test _qgf_stream_update!(conn) == 0
                end
            end
        end

        @testset "sending data" begin
            @testset "gets the size of the send window" begin
                conn, s = _qgf_sender(; stream_max = 15, conn_max = 1000)
                _qgf_send!(conn, s, 5)
                @test _qgf_window(conn, s) == 10
            end

            @testset "makes sure that it doesn't overflow the connection-level window" begin
                conn, s = _qgf_sender(; stream_max = 20, conn_max = 12)
                _qgf_send!(conn, s, 10)
                @test _qgf_window(conn, s) == 2
            end

            @testset "doesn't say that it's blocked, if only the connection is blocked" begin
                conn, s = _qgf_sender(; stream_max = 100, conn_max = 50)
                frames = _qgf_send!(conn, s, 60)
                @test conn.data_sent == 50
                @test _qgf_blocked_at(frames, :connection, 50)
                @test !_qgf_any_blocked(frames, :stream)
            end
        end
    end
end
