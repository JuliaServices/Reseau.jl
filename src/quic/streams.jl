# Streams and flow control (RFC 9000 Sections 2 to 4) for a `_Connection`:
# the application's calls to open, read, write, and reset streams, the
# peer's stream frames, building stream frames to send, and what happens when
# those frames are acknowledged or lost.

_is_local(conn::_Connection, id::UInt64)::Bool = _is_client_initiated(id) == !conn.is_server
# Whether this endpoint sends, and receives, on stream `id`.
_can_send(conn::_Connection, id::UInt64)::Bool = _is_bidi(id) || _is_local(conn, id)
_can_receive(conn::_Connection, id::UInt64)::Bool = _is_bidi(id) || !_is_local(conn, id)

function _new_stream(conn::_Connection, id::UInt64)::_Stream
    send_max = Int64(0)
    p = conn.peer_params
    if p !== nothing
        send_max = Int64(if !_is_bidi(id)
            p.initial_max_stream_data_uni
        elseif _is_local(conn, id)
            p.initial_max_stream_data_bidi_remote
        else
            p.initial_max_stream_data_bidi_local
        end)
    end
    send = _can_send(conn, id) ? _StreamSendBuffer() : nothing
    recv = _can_receive(conn, id) ? _StreamReceiveBuffer() : nothing
    s = _Stream(id, send, recv, send_max, conn.limits.max_stream_data)
    conn.streams[id] = s
    return s
end

"Whether stream `id` was ever opened, by either side."
function _stream_opened(conn::_Connection, id::UInt64)::Bool
    idx = _stream_index(id)
    bidi = _is_bidi(id)
    _is_local(conn, id) && return idx < (bidi ? conn.local_opened_bidi : conn.local_opened_uni)
    return idx < (bidi ? conn.peer_opened_bidi : conn.peer_opened_uni)
end

function _queue_stream!(conn::_Connection, s::_Stream)::Nothing
    s.queued && return nothing
    s.queued = true
    push!(conn.send_queue, s.id)
    return nothing
end

"Frees a stream once both its sides are finished, raising the peer's stream limit if it opened it."
function _maybe_free_stream!(conn::_Connection, s::_Stream)::Nothing
    send = s.send
    recv = s.recv
    send_done = send === nothing || _send_all_acked(send) ||
        (s.reset_acked && (s.peer_stop_code == _NO_CODE || s.stop_seen || send.fin))
    recv_done = recv === nothing || s.recv_done
    (send_done && recv_done) || return nothing
    delete!(conn.streams, s.id)
    _is_local(conn, s.id) && return nothing
    if _is_bidi(s.id)
        conn.peer_closed_bidi += 1
        conn.local_max_streams_bidi = conn.peer_closed_bidi + conn.limits.max_streams_bidi
        conn.max_streams_bidi_pending = true
    else
        conn.peer_closed_uni += 1
        conn.local_max_streams_uni = conn.peer_closed_uni + conn.limits.max_streams_uni
        conn.max_streams_uni_pending = true
    end
    return nothing
end

# Flow-control credit returns to the peer once the application has consumed
# half a window (Section 4.2).

function _consume!(conn::_Connection, n::Int64)::Nothing
    conn.data_consumed += n
    window = conn.limits.max_data
    if conn.local_max_data - conn.data_consumed < window ÷ 2
        conn.local_max_data = conn.data_consumed + window
        conn.max_data_pending = true
    end
    return nothing
end

function _update_stream_window!(conn::_Connection, s::_Stream)::Nothing
    rb = s.recv::_StreamReceiveBuffer
    rb.final_size >= 0 && return nothing  # the peer needs no more credit
    window = conn.limits.max_stream_data
    if s.recv_max - rb.read_offset < window ÷ 2
        s.recv_max = rb.read_offset + window
        s.max_stream_data_pending = true
        _queue_stream!(conn, s)
    end
    return nothing
end

# Data the application will not read is dropped as it arrives. After
# STOP_SENDING it counts as consumed; after the peer's reset the whole final
# size already did.
function _discard_unwanted!(conn::_Connection, s::_Stream)::Nothing
    (s.stop_sending_code == _NO_CODE && s.peer_reset_code == _NO_CODE) && return nothing
    rb = s.recv::_StreamReceiveBuffer
    n = _recv_readable(rb)
    n == 0 && return nothing
    _recv_read!(rb, n)
    s.peer_reset_code == _NO_CODE && _consume!(conn, Int64(n))
    return nothing
end

function _reset_send!(conn::_Connection, s::_Stream, code::UInt64)::Nothing
    sb = s.send::_StreamSendBuffer
    (s.reset_code != _NO_CODE || _send_all_acked(sb)) && return nothing
    s.reset_code = code
    s.reset_final_size = sb.max_sent
    s.reset_pending = true
    empty!(sb.pending)
    sb.fin_pending = false
    _queue_stream!(conn, s)
    return nothing
end

# The application's interface.

function _check_open(conn::_Connection)::Nothing
    state = conn.state
    (state == _ConnState.Closing || state == _ConnState.Draining || state == _ConnState.Closed) &&
        throw(ArgumentError("QUIC connection is closed"))
    return nothing
end

# The stream the application named: `nothing` once it is closed and freed.
# Throws for a direction it does not have, or a stream never opened.
function _app_stream(conn::_Connection, id::UInt64, sending::Bool)::Union{Nothing, _Stream}
    if sending
        _can_send(conn, id) || throw(ArgumentError("QUIC stream $(id) is receive-only here"))
    else
        _can_receive(conn, id) || throw(ArgumentError("QUIC stream $(id) is send-only here"))
    end
    s = get(conn.streams, id, nothing)
    s === nothing && !_stream_opened(conn, id) && throw(ArgumentError("QUIC stream $(id) is not open"))
    return s
end

"""
    _open_stream!(conn; bidi = true) -> stream ID or nothing

Open a stream, or return `nothing` while the peer's stream limit allows no
more (RFC 9000 Section 4.6). The peer learns of it when data is sent.
"""
function _open_stream!(conn::_Connection; bidi::Bool = true)::Union{Nothing, UInt64}
    _check_open(conn)
    idx = if bidi
        conn.local_opened_bidi < conn.peer_max_streams_bidi || return nothing
        conn.local_opened_bidi += 1
        conn.local_opened_bidi - 1
    else
        conn.local_opened_uni < conn.peer_max_streams_uni || return nothing
        conn.local_opened_uni += 1
        conn.local_opened_uni - 1
    end
    id = _stream_id(idx, !conn.is_server, bidi)
    _new_stream(conn, id)
    return id
end

"""
    _accept_stream!(conn) -> stream ID or nothing

The next stream the peer opened, in order, or `nothing`.
"""
_accept_stream!(conn::_Connection)::Union{Nothing, UInt64} =
    isempty(conn.accept_queue) ? nothing : popfirst!(conn.accept_queue)

"""
    _stream_write!(conn, id, data; fin = false)

Queue `data` on stream `id`, then finish the stream if `fin`. The connection
buffers all of it; flow and congestion control decide when it is sent. After
the peer's STOP_SENDING (see `_stream_stop_code`) data is dropped.
"""
function _stream_write!(conn::_Connection, id::UInt64, data::AbstractVector{UInt8}; fin::Bool = false)::Nothing
    _check_open(conn)
    s = _app_stream(conn, id, true)
    s === nothing && throw(ArgumentError("QUIC stream $(id) is closed"))
    s.peer_stop_code == _NO_CODE || return nothing
    s.reset_code == _NO_CODE || throw(ArgumentError("QUIC stream $(id) was reset"))
    sb = s.send::_StreamSendBuffer
    _send_write!(sb, data)
    fin && _send_finish!(sb)
    _queue_stream!(conn, s)
    return nothing
end

"""
    _stream_read!(conn, id, max_len = typemax(Int)) -> _ReadResult

Read up to `max_len` bytes from stream `id`. The result's `fin` is set once
the receive side has ended, by FIN or by the peer's reset.
"""
function _stream_read!(conn::_Connection, id::UInt64, max_len::Int = typemax(Int))::_ReadResult
    s = _app_stream(conn, id, false)
    avail = (s === nothing || s.peer_reset_code != _NO_CODE) ? 0 : min(max_len, _recv_readable(s.recv::_StreamReceiveBuffer))
    data = Vector{UInt8}(undef, avail)
    _, fin, code = _stream_read_into!(conn, id, data, 1, avail)
    return _ReadResult(data, fin, code)
end

"""
    _stream_read_into!(conn, id, dst, doff, max_len) -> (n, fin, reset_code)

As `_stream_read!`, but the bytes go to `dst[doff:doff+n-1]`.
"""
function _stream_read_into!(conn::_Connection, id::UInt64, dst::AbstractVector{UInt8}, doff::Int, max_len::Int)::Tuple{Int, Bool, UInt64}
    s = _app_stream(conn, id, false)
    s === nothing && return 0, true, _NO_CODE
    rb = s.recv::_StreamReceiveBuffer
    if s.peer_reset_code != _NO_CODE
        s.recv_done = true
        _maybe_free_stream!(conn, s)
        return 0, true, s.peer_reset_code
    end
    n = _recv_read_into!(rb, dst, doff, max_len)
    if n > 0
        _consume!(conn, Int64(n))
        _update_stream_window!(conn, s)
    end
    fin = _recv_finished(rb)
    if fin
        s.recv_done = true
        _maybe_free_stream!(conn, s)
    end
    return n, fin, _NO_CODE
end

"""
    _stream_reset!(conn, id, code)

Abandon sending on stream `id` with RESET_STREAM (RFC 9000 Section 19.4).
"""
function _stream_reset!(conn::_Connection, id::UInt64, code::UInt64)::Nothing
    _check_open(conn)
    s = _app_stream(conn, id, true)
    s === nothing || _reset_send!(conn, s, code)
    return nothing
end

"""
    _stream_stop_sending!(conn, id, code)

Ask the peer to stop sending on stream `id` (STOP_SENDING, RFC 9000 Section
19.5). Data that still arrives is dropped; keep reading to see the stream end.
"""
function _stream_stop_sending!(conn::_Connection, id::UInt64, code::UInt64)::Nothing
    _check_open(conn)
    s = _app_stream(conn, id, false)
    s === nothing && return nothing
    (s.stop_sending_code != _NO_CODE || s.peer_reset_code != _NO_CODE || s.recv_done) && return nothing
    s.stop_sending_code = code
    s.stop_sending_pending = true
    s.max_stream_data_pending = false
    _queue_stream!(conn, s)
    _discard_unwanted!(conn, s)
    return nothing
end

"The error code of the peer's STOP_SENDING for stream `id`, or `_NO_CODE`."
function _stream_stop_code(conn::_Connection, id::UInt64)::UInt64
    s = get(conn.streams, id, nothing)
    return s === nothing ? _NO_CODE : s.peer_stop_code
end

# The peer's frames.

"""
    _peer_frame_stream!(conn, id, frame_type) -> _Stream, nothing, or _TransportError

The stream a peer's frame names. A frame for a peer-initiated stream not yet
open opens it, and every lower-numbered one of its kind (Section 3.2). Frames
for streams already closed are ignored (`nothing`).
"""
function _peer_frame_stream!(conn::_Connection, id::UInt64, frame_type::UInt64)::Union{Nothing, _Stream, _TransportError}
    s = get(conn.streams, id, nothing)
    s === nothing || return s
    _stream_opened(conn, id) && return nothing
    _is_local(conn, id) && return _TransportError(_STREAM_STATE_ERROR, frame_type, "frame for a stream not yet opened")
    bidi = _is_bidi(id)
    idx = _stream_index(id)
    idx < (bidi ? conn.local_max_streams_bidi : conn.local_max_streams_uni) ||
        return _TransportError(_STREAM_LIMIT_ERROR, frame_type, "peer opened more streams than allowed")
    for i in (bidi ? conn.peer_opened_bidi : conn.peer_opened_uni):idx
        new_id = _stream_id(i, conn.is_server, bidi)
        _new_stream(conn, new_id)
        push!(conn.accept_queue, new_id)
    end
    bidi ? (conn.peer_opened_bidi = idx + 1) : (conn.peer_opened_uni = idx + 1)
    return conn.streams[id]
end

_stream_state_error(frame_type::UInt8, what::String) = _TransportError(_STREAM_STATE_ERROR, UInt64(frame_type), what)

# Data up to `stop` on `s` must fit the stream's limit and, counting only
# bytes beyond those received before, the connection's (Section 4.1).
function _check_receive_credit(conn::_Connection, s::_Stream, stop::Int64, frame_type::UInt8)::Union{Nothing, _TransportError}
    stop > s.recv_max && return _TransportError(_FLOW_CONTROL_ERROR, UInt64(frame_type), "stream flow control limit exceeded")
    rb = s.recv::_StreamReceiveBuffer
    conn.data_received + max(stop - rb.max_received, Int64(0)) > conn.local_max_data &&
        return _TransportError(_FLOW_CONTROL_ERROR, UInt64(frame_type), "connection flow control limit exceeded")
    return nothing
end

function _on_frame!(conn::_Connection, space::_PacketSpace, idx::Int, buf::Vector{UInt8}, frame::_StreamFrame, now::Int64)::Union{Nothing, _TransportError}
    id = frame.stream_id
    _can_receive(conn, id) || return _stream_state_error(0x08, "STREAM on a send-only stream")
    s = _peer_frame_stream!(conn, id, UInt64(0x08))
    s isa _Stream || return s
    rb = s.recv::_StreamReceiveBuffer
    offset = Int64(frame.offset)
    err = _check_receive_credit(conn, s, offset + length(frame.data), 0x08)
    err === nothing || return err
    before = rb.max_received
    code = _recv_insert!(rb, offset, @view(buf[frame.data]), frame.fin)
    code === nothing || return _TransportError(code, UInt64(0x08), "STREAM data contradicts the final size")
    conn.data_received += rb.max_received - before
    _discard_unwanted!(conn, s)
    return nothing
end

function _on_frame!(conn::_Connection, space::_PacketSpace, idx::Int, buf::Vector{UInt8}, frame::_ResetStreamFrame, now::Int64)::Union{Nothing, _TransportError}
    id = frame.stream_id
    _can_receive(conn, id) || return _stream_state_error(0x04, "RESET_STREAM on a send-only stream")
    s = _peer_frame_stream!(conn, id, UInt64(0x04))
    s isa _Stream || return s
    rb = s.recv::_StreamReceiveBuffer
    final_size = Int64(frame.final_size)
    err = _check_receive_credit(conn, s, final_size, 0x04)
    err === nothing || return err
    before = rb.max_received
    code = _recv_set_final_size!(rb, final_size)
    code === nothing || return _TransportError(code, UInt64(0x04), "RESET_STREAM final size contradicts data received")
    conn.data_received += rb.max_received - before
    s.peer_reset_code == _NO_CODE || return nothing
    s.peer_reset_code = frame.error_code
    s.max_stream_data_pending = false
    s.stop_sending_pending = false
    # Nothing more will be read, so the rest of the stream counts as consumed.
    _consume!(conn, final_size - rb.read_offset)
    _discard_unwanted!(conn, s)
    return nothing
end

function _on_frame!(conn::_Connection, space::_PacketSpace, idx::Int, buf::Vector{UInt8}, frame::_StopSendingFrame, now::Int64)::Union{Nothing, _TransportError}
    id = frame.stream_id
    _can_send(conn, id) || return _stream_state_error(0x05, "STOP_SENDING for a receive-only stream")
    s = _peer_frame_stream!(conn, id, UInt64(0x05))
    s isa _Stream || return s
    s.peer_stop_code == _NO_CODE || return nothing
    s.peer_stop_code = frame.error_code
    # The sender answers with RESET_STREAM (Section 3.5).
    _reset_send!(conn, s, frame.error_code)
    return nothing
end

function _on_frame!(conn::_Connection, space::_PacketSpace, idx::Int, buf::Vector{UInt8}, frame::_MaxStreamDataFrame, now::Int64)::Union{Nothing, _TransportError}
    id = frame.stream_id
    _can_send(conn, id) || return _stream_state_error(0x11, "MAX_STREAM_DATA for a receive-only stream")
    s = _peer_frame_stream!(conn, id, UInt64(0x11))
    s isa _Stream || return s
    if Int64(frame.max) > s.send_max
        s.send_max = Int64(frame.max)
        _stream_needs_queue(s) && _queue_stream!(conn, s)
    end
    return nothing
end

function _on_frame!(conn::_Connection, space::_PacketSpace, idx::Int, buf::Vector{UInt8}, frame::_StreamDataBlockedFrame, now::Int64)::Union{Nothing, _TransportError}
    id = frame.stream_id
    _can_receive(conn, id) || return _stream_state_error(0x15, "STREAM_DATA_BLOCKED on a send-only stream")
    s = _peer_frame_stream!(conn, id, UInt64(0x15))
    return s isa _TransportError ? s : nothing
end

function _on_frame!(conn::_Connection, space::_PacketSpace, idx::Int, buf::Vector{UInt8}, frame::_MaxDataFrame, now::Int64)::Nothing
    conn.peer_max_data = max(conn.peer_max_data, Int64(frame.max))
    return nothing
end

function _on_frame!(conn::_Connection, space::_PacketSpace, idx::Int, buf::Vector{UInt8}, frame::_MaxStreamsFrame, now::Int64)::Nothing
    if frame.bidi
        conn.peer_max_streams_bidi = max(conn.peer_max_streams_bidi, Int64(frame.max))
    else
        conn.peer_max_streams_uni = max(conn.peer_max_streams_uni, Int64(frame.max))
    end
    return nothing
end

function _on_frame!(conn::_Connection, space::_PacketSpace, idx::Int, buf::Vector{UInt8}, frame::_PathChallengeFrame, now::Int64)::Nothing
    length(conn.path_responses) < _MAX_PATH_RESPONSES && push!(conn.path_responses, frame.data)
    return nothing
end

# Sending.

_room(buf::Vector{UInt8}, max_size::Int)::Int = max_size - length(buf) - _AEAD_TAG_LEN

_stream_has_control(s::_Stream)::Bool = s.reset_pending || s.stop_sending_pending || s.max_stream_data_pending

# Whether `s` belongs in the send queue: it has control frames, or data or a
# FIN to send, perhaps held back by flow control.
function _stream_needs_queue(s::_Stream)::Bool
    _stream_has_control(s) && return true
    sb = s.send
    return sb !== nothing && s.reset_code == _NO_CODE && _send_has_pending(sb)
end

# The limit on new data for `s`: its own, and what the connection's allows
# beyond what `s` has already sent.
function _stream_send_limit(conn::_Connection, s::_Stream)::Int64
    sb = s.send::_StreamSendBuffer
    return min(s.send_max, sb.max_sent + (conn.peer_max_data - conn.data_sent))
end

function _stream_can_send_now(conn::_Connection, s::_Stream)::Bool
    _stream_has_control(s) && return true
    sb = s.send
    (sb === nothing || s.reset_code != _NO_CODE) && return false
    isempty(sb.pending) || return first(first(sb.pending.ranges)) < _stream_send_limit(conn, s)
    return sb.fin_pending
end

function _app_wants_to_send(conn::_Connection)::Bool
    (!isempty(conn.path_responses) || conn.max_data_pending || conn.max_streams_bidi_pending || conn.max_streams_uni_pending) &&
        return true
    for id in conn.send_queue
        s = get(conn.streams, id, nothing)
        s !== nothing && _stream_can_send_now(conn, s) && return true
    end
    return false
end

# Connection-level frames, then streams' frames round robin, in a 1-RTT packet.
function _append_app_frames!(conn::_Connection, buf::Vector{UInt8}, max_size::Int, frames::Vector{_SentFrame})::Nothing
    while !isempty(conn.path_responses) && _room(buf, max_size) >= 9
        _append_path_frame!(buf, 0x1b, popfirst!(conn.path_responses))
        push!(frames, _SentFrame(_SF_PING))  # ack-eliciting; never resent
    end
    if conn.max_data_pending && _room(buf, max_size) >= 9
        _append_max_data_frame!(buf, UInt64(conn.local_max_data))
        conn.max_data_pending = false
        push!(frames, _SentFrame(_SF_MAX_DATA))
    end
    if conn.max_streams_bidi_pending && _room(buf, max_size) >= 9
        _append_max_streams_frame!(buf, true, UInt64(conn.local_max_streams_bidi))
        conn.max_streams_bidi_pending = false
        push!(frames, _SentFrame(_SF_MAX_STREAMS_BIDI))
    end
    if conn.max_streams_uni_pending && _room(buf, max_size) >= 9
        _append_max_streams_frame!(buf, false, UInt64(conn.local_max_streams_uni))
        conn.max_streams_uni_pending = false
        push!(frames, _SentFrame(_SF_MAX_STREAMS_UNI))
    end
    for _ in 1:length(conn.send_queue)
        isempty(conn.send_queue) && break
        id = popfirst!(conn.send_queue)
        s = get(conn.streams, id, nothing)
        s === nothing && continue
        s.queued = false
        _append_stream_frames!(conn, s, buf, max_size, frames)
        _stream_needs_queue(s) && _queue_stream!(conn, s)
    end
    return nothing
end

function _append_stream_frames!(conn::_Connection, s::_Stream, buf::Vector{UInt8}, max_size::Int, frames::Vector{_SentFrame})::Nothing
    id = s.id
    if s.reset_pending && _room(buf, max_size) >= 25
        _append_reset_stream_frame!(buf, id, s.reset_code, UInt64(s.reset_final_size))
        s.reset_pending = false
        push!(frames, _SentFrame(_SF_RESET_STREAM, id))
    end
    if s.stop_sending_pending && _room(buf, max_size) >= 17
        _append_stop_sending_frame!(buf, id, s.stop_sending_code)
        s.stop_sending_pending = false
        push!(frames, _SentFrame(_SF_STOP_SENDING, id))
    end
    if s.max_stream_data_pending && _room(buf, max_size) >= 17
        _append_max_stream_data_frame!(buf, id, UInt64(s.recv_max))
        s.max_stream_data_pending = false
        push!(frames, _SentFrame(_SF_MAX_STREAM_DATA, id))
    end
    sb = s.send
    (sb === nothing || s.reset_code != _NO_CODE) && return nothing
    # Frame type, stream ID, an offset of up to 8 bytes, and a 2-byte length.
    overhead = 1 + _varint_length(id) + 8 + 2
    while true
        avail = _room(buf, max_size) - overhead
        avail < 0 && break
        before = sb.max_sent
        chunk = _send_next_chunk!(sb, avail, _stream_send_limit(conn, s))
        chunk === nothing && break
        r, fin = chunk
        conn.data_sent += sb.max_sent - before
        _append_stream_frame!(buf, id, UInt64(first(r)), _send_bytes(sb, r); fin)
        push!(frames, _SentFrame(_SF_STREAM, id, first(r), Int64(length(r)), fin))
    end
    return nothing
end

# Acknowledgment and loss of stream and flow-control frames.

function _on_stream_frame_acked!(conn::_Connection, f::_SentFrame)::Nothing
    (f.kind == _SF_STREAM || f.kind == _SF_RESET_STREAM) || return nothing
    s = get(conn.streams, f.stream_id, nothing)
    s === nothing && return nothing
    if f.kind == _SF_STREAM
        _send_on_acked!(s.send::_StreamSendBuffer, _sent_range(f), f.fin)
    else
        s.reset_acked = true
    end
    _maybe_free_stream!(conn, s)
    return nothing
end

# Lost frames are sent again only if they still matter, and then with
# current values.
function _on_stream_frame_lost!(conn::_Connection, f::_SentFrame)::Nothing
    kind = f.kind
    if kind == _SF_MAX_DATA
        conn.max_data_pending = true
        return nothing
    elseif kind == _SF_MAX_STREAMS_BIDI
        conn.max_streams_bidi_pending = true
        return nothing
    elseif kind == _SF_MAX_STREAMS_UNI
        conn.max_streams_uni_pending = true
        return nothing
    end
    s = get(conn.streams, f.stream_id, nothing)
    s === nothing && return nothing
    if kind == _SF_STREAM
        s.reset_code == _NO_CODE || return nothing
        _send_on_lost!(s.send::_StreamSendBuffer, _sent_range(f), f.fin)
    elseif kind == _SF_RESET_STREAM
        s.reset_acked || (s.reset_pending = true)
    elseif kind == _SF_STOP_SENDING
        s.peer_reset_code == _NO_CODE && !s.recv_done && (s.stop_sending_pending = true)
    elseif kind == _SF_MAX_STREAM_DATA
        rb = s.recv::_StreamReceiveBuffer
        rb.final_size < 0 && s.stop_sending_code == _NO_CODE && (s.max_stream_data_pending = true)
    end
    _stream_needs_queue(s) && _queue_stream!(conn, s)
    return nothing
end
