# Per-stream state (RFC 9000 Sections 2 to 4) and the limits an endpoint sets
# for its peer. The connection-level logic that uses them is in streams.jl.

"""
    _StreamLimits

What this endpoint lets its peer do: bytes it may send in total and on each
stream, and how many streams of each kind it may open. Advertised in the
transport parameters, and moved forward as the application reads data and
streams close.
"""
Base.@kwdef struct _StreamLimits
    max_data::Int64 = Int64(4 * 1024 * 1024)
    max_stream_data::Int64 = Int64(1024 * 1024)
    max_streams_bidi::Int64 = Int64(100)
    max_streams_uni::Int64 = Int64(100)
end

# Application error codes are varints, so below 2^62; this marks "none".
const _NO_CODE = typemax(UInt64)

# Stream ID bits (Section 2.1): bit 0 is the initiator (0 for the client),
# bit 1 the direction (0 for bidirectional).
_is_bidi(id::UInt64)::Bool = (id & 0x02) == 0
_is_client_initiated(id::UInt64)::Bool = (id & 0x01) == 0
_stream_index(id::UInt64)::Int64 = Int64(id >> 2)
_stream_id(index::Int64, client::Bool, bidi::Bool)::UInt64 =
    (UInt64(index) << 2) | (client ? 0x00 : 0x01) | (bidi ? 0x00 : 0x02)

"""
    _ReadResult

What `_stream_read!` returns: the bytes read, whether the receive side has
ended (everything up to the final size was read, or the peer reset the
stream), and the peer's RESET_STREAM error code, or `_NO_CODE`.
"""
struct _ReadResult
    data::Vector{UInt8}
    fin::Bool
    reset_code::UInt64
end

"""
    _Stream

One open stream. `send` is `nothing` on a stream only the peer sends on, and
`recv` on one only this endpoint sends on. `send_max` is the peer's
flow-control limit for the stream, `recv_max` the one advertised to it. The
`reset_*` fields track this endpoint abandoning its send side (RESET_STREAM),
`stop_sending_*` its receive side (STOP_SENDING); `peer_*` record what the
peer did. `recv_done` means the application has seen the receive side end.
`queued` means the stream is in the connection's send queue.
"""
mutable struct _Stream
    id::UInt64
    send::Union{Nothing, _StreamSendBuffer}
    recv::Union{Nothing, _StreamReceiveBuffer}
    send_max::Int64
    recv_max::Int64
    max_stream_data_pending::Bool
    reset_code::UInt64
    reset_final_size::Int64
    reset_pending::Bool
    reset_acked::Bool
    stop_sending_code::UInt64
    stop_sending_pending::Bool
    peer_reset_code::UInt64
    peer_stop_code::UInt64
    # Whether the application saw the peer's STOP_SENDING (or can no longer
    # write): until then the stream is kept so writes report it.
    stop_seen::Bool
    recv_done::Bool
    queued::Bool
end

_Stream(id::UInt64, send, recv, send_max::Int64, recv_max::Int64) = _Stream(
    id, send, recv, send_max, recv_max, false,
    _NO_CODE, Int64(0), false, false, _NO_CODE, false, _NO_CODE, _NO_CODE, false, false, false,
)

"""
    _SentFrame

A frame in a packet awaiting acknowledgment, as much of it as is needed to act
when the packet is acknowledged or lost: `kind` is one of the `_SF_*`
constants; CRYPTO and STREAM frames record their byte range as `offset` and
`len`, and STREAM frames whether they carried the FIN.
"""
struct _SentFrame
    kind::UInt8
    stream_id::UInt64
    offset::Int64
    len::Int64
    fin::Bool
end

const _SF_CRYPTO = 0x01
const _SF_STREAM = 0x02
const _SF_HANDSHAKE_DONE = 0x03
const _SF_MAX_DATA = 0x04
const _SF_MAX_STREAM_DATA = 0x05
const _SF_MAX_STREAMS_BIDI = 0x06
const _SF_MAX_STREAMS_UNI = 0x07
const _SF_RESET_STREAM = 0x08
const _SF_STOP_SENDING = 0x09
const _SF_PING = 0x0a

_SentFrame(kind::UInt8, stream_id::UInt64 = UInt64(0)) = _SentFrame(kind, stream_id, Int64(0), Int64(0), false)

_sent_range(f::_SentFrame)::UnitRange{Int64} = f.offset:(f.offset + f.len - 1)
