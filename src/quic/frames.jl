# QUIC frames (RFC 9000 Section 19) and the rules for which packet types may
# carry them (Section 12.4).
#
# Frames have no length prefix, so finding a packet's next frame means decoding
# every frame type. `_decode_frames` walks a decrypted payload and hands each
# frame, as its own concrete struct, to a handler. Data-carrying fields are
# index ranges into the payload buffer, so nothing is copied.

# Transport error codes (RFC 9000 Section 20.1). CRYPTO_ERROR is
# `_CRYPTO_ERROR_BASE + alert`.
const _NO_ERROR = UInt64(0x00)
const _INTERNAL_ERROR = UInt64(0x01)
const _CONNECTION_REFUSED = UInt64(0x02)
const _FLOW_CONTROL_ERROR = UInt64(0x03)
const _STREAM_LIMIT_ERROR = UInt64(0x04)
const _STREAM_STATE_ERROR = UInt64(0x05)
const _FINAL_SIZE_ERROR = UInt64(0x06)
const _FRAME_ENCODING_ERROR = UInt64(0x07)
const _TRANSPORT_PARAMETER_ERROR = UInt64(0x08)
const _CONNECTION_ID_LIMIT_ERROR = UInt64(0x09)
const _PROTOCOL_VIOLATION = UInt64(0x0a)
const _INVALID_TOKEN = UInt64(0x0b)
const _APPLICATION_ERROR = UInt64(0x0c)
const _CRYPTO_BUFFER_EXCEEDED = UInt64(0x0d)
const _KEY_UPDATE_ERROR = UInt64(0x0e)
const _AEAD_LIMIT_REACHED = UInt64(0x0f)
const _NO_VIABLE_PATH = UInt64(0x10)
const _CRYPTO_ERROR_BASE = UInt64(0x0100)

# Stream count limits stop at 2^60 (RFC 9000 Sections 19.11 and 19.14).
const _MAX_STREAMS_LIMIT = UInt64(1) << 60

"""
    _TransportError

A connection error: the error code, the type of the frame that triggered it
(0 if none), and a reason phrase, as a CONNECTION_CLOSE frame carries them.
`app` marks an application error code (CONNECTION_CLOSE type 0x1d) rather
than a transport one.
"""
struct _TransportError
    code::UInt64
    frame_type::UInt64
    reason::String
    app::Bool
end

_TransportError(code::UInt64, frame_type::UInt64, reason::String) = _TransportError(code, frame_type, reason, false)

"""
    _DecodedPayload

Result of `_decode_frames`: the connection error that stopped decoding, if any,
and whether the packet is ack-eliciting (holds a frame other than ACK, PADDING,
or CONNECTION_CLOSE).
"""
struct _DecodedPayload
    error::Union{Nothing, _TransportError}
    ack_eliciting::Bool
end

# One struct per frame type. Fields named after RFC 9000 Section 19.

"A run of consecutive PADDING bytes, reported as one frame."
struct _PaddingFrame
    length::Int
end

struct _PingFrame end

"""
    _AckFrame

ACK or ACK_ECN. `ranges` is where the encoded Gap/ACK Range Length pairs sit
in the payload; walk them with `_ack_ranges`.
"""
struct _AckFrame
    largest::UInt64
    delay::UInt64
    first_range::UInt64
    ranges::UnitRange{Int}
    range_count::Int
    ecn::Bool
    ect0::UInt64
    ect1::UInt64
    ce::UInt64
end

struct _ResetStreamFrame
    stream_id::UInt64
    error_code::UInt64
    final_size::UInt64
end

struct _StopSendingFrame
    stream_id::UInt64
    error_code::UInt64
end

struct _CryptoFrame
    offset::UInt64
    data::UnitRange{Int}
end

struct _NewTokenFrame
    token::UnitRange{Int}
end

struct _StreamFrame
    stream_id::UInt64
    offset::UInt64
    data::UnitRange{Int}
    fin::Bool
end

struct _MaxDataFrame
    max::UInt64
end

struct _MaxStreamDataFrame
    stream_id::UInt64
    max::UInt64
end

struct _MaxStreamsFrame
    bidi::Bool
    max::UInt64
end

struct _DataBlockedFrame
    limit::UInt64
end

struct _StreamDataBlockedFrame
    stream_id::UInt64
    limit::UInt64
end

struct _StreamsBlockedFrame
    bidi::Bool
    limit::UInt64
end

struct _NewConnectionIdFrame
    seq::UInt64
    retire_prior_to::UInt64
    cid::UnitRange{Int}
    reset_token::UnitRange{Int}
end

struct _RetireConnectionIdFrame
    seq::UInt64
end

struct _PathChallengeFrame
    data::UInt64
end

struct _PathResponseFrame
    data::UInt64
end

"""
    _ConnectionCloseFrame

CONNECTION_CLOSE. `app` marks the application variant (type 0x1d), which
carries no frame type.
"""
struct _ConnectionCloseFrame
    app::Bool
    error_code::UInt64
    frame_type::UInt64
    reason::UnitRange{Int}
end

struct _HandshakeDoneFrame end

# Decoding. Each `_decode_*` returns the frame and the position after it, or
# `nothing` if the frame is malformed (a FRAME_ENCODING_ERROR).

const _DecodeResult{T} = Union{Nothing, Tuple{T, Int}}

@inline function _read_bytes(pos::Int, len::UInt64, last::Int)::Union{Nothing, UnitRange{Int}}
    len <= UInt64(last - pos + 1) || return nothing
    return pos:(pos + Int(len) - 1)
end

@inline function _read_u64_be(buf::Vector{UInt8}, pos::Int, last::Int)::Union{Nothing, UInt64}
    pos + 7 <= last || return nothing
    v = UInt64(0)
    for i in 0:7
        v = (v << 8) | buf[pos + i]
    end
    return v
end

function _decode_ack(buf::Vector{UInt8}, pos::Int, last::Int, ecn::Bool)::_DecodeResult{_AckFrame}
    (r = _read_varint(buf, pos, last)) === nothing && return nothing
    largest, pos = r
    (r = _read_varint(buf, pos, last)) === nothing && return nothing
    delay, pos = r
    (r = _read_varint(buf, pos, last)) === nothing && return nothing
    count, pos = r
    (r = _read_varint(buf, pos, last)) === nothing && return nothing
    first_range, pos = r
    # Every packet number the frame implies must be at least 0 (Section 19.3.1).
    first_range <= largest || return nothing
    smallest = largest - first_range
    ranges_first = pos
    for _ in UInt64(1):count
        (r = _read_varint(buf, pos, last)) === nothing && return nothing
        gap, pos = r
        (r = _read_varint(buf, pos, last)) === nothing && return nothing
        len, pos = r
        # Gap counts the unacknowledged packets below the previous range, less one.
        smallest >= UInt64(2) && gap <= smallest - UInt64(2) || return nothing
        next_largest = smallest - gap - UInt64(2)
        len <= next_largest || return nothing
        smallest = next_largest - len
    end
    ranges = ranges_first:(pos - 1)
    ect0 = ect1 = ce = UInt64(0)
    if ecn
        (r = _read_varint(buf, pos, last)) === nothing && return nothing
        ect0, pos = r
        (r = _read_varint(buf, pos, last)) === nothing && return nothing
        ect1, pos = r
        (r = _read_varint(buf, pos, last)) === nothing && return nothing
        ce, pos = r
    end
    return _AckFrame(largest, delay, first_range, ranges, Int(count), ecn, ect0, ect1, ce), pos
end

function _decode_reset_stream(buf::Vector{UInt8}, pos::Int, last::Int)::_DecodeResult{_ResetStreamFrame}
    (r = _read_varint(buf, pos, last)) === nothing && return nothing
    stream_id, pos = r
    (r = _read_varint(buf, pos, last)) === nothing && return nothing
    error_code, pos = r
    (r = _read_varint(buf, pos, last)) === nothing && return nothing
    final_size, pos = r
    return _ResetStreamFrame(stream_id, error_code, final_size), pos
end

function _decode_two_varints(buf::Vector{UInt8}, pos::Int, last::Int)::Union{Nothing, Tuple{UInt64, UInt64, Int}}
    (r = _read_varint(buf, pos, last)) === nothing && return nothing
    a, pos = r
    (r = _read_varint(buf, pos, last)) === nothing && return nothing
    b, pos = r
    return a, b, pos
end

function _decode_crypto(buf::Vector{UInt8}, pos::Int, last::Int)::_DecodeResult{_CryptoFrame}
    (r = _decode_two_varints(buf, pos, last)) === nothing && return nothing
    offset, len, pos = r
    # Offsets past 2^62 - 1 cannot be flow controlled (Section 19.6).
    len <= _MAX_VARINT - offset || return nothing
    (data = _read_bytes(pos, len, last)) === nothing && return nothing
    return _CryptoFrame(offset, data), pos + length(data)
end

function _decode_new_token(buf::Vector{UInt8}, pos::Int, last::Int)::_DecodeResult{_NewTokenFrame}
    (r = _read_varint(buf, pos, last)) === nothing && return nothing
    len, pos = r
    len == 0 && return nothing  # Section 19.7
    (token = _read_bytes(pos, len, last)) === nothing && return nothing
    return _NewTokenFrame(token), pos + length(token)
end

function _decode_stream(buf::Vector{UInt8}, pos::Int, last::Int, type::UInt64)::_DecodeResult{_StreamFrame}
    (r = _read_varint(buf, pos, last)) === nothing && return nothing
    stream_id, pos = r
    offset = UInt64(0)
    if type & 0x04 != 0
        (r = _read_varint(buf, pos, last)) === nothing && return nothing
        offset, pos = r
    end
    data = if type & 0x02 != 0
        (r = _read_varint(buf, pos, last)) === nothing && return nothing
        len, pos = r
        (d = _read_bytes(pos, len, last)) === nothing && return nothing
        d
    else
        pos:last  # no Length: the data runs to the end of the packet
    end
    UInt64(length(data)) <= _MAX_VARINT - offset || return nothing  # Section 19.8
    return _StreamFrame(stream_id, offset, data, type & 0x01 != 0), pos + length(data)
end

function _decode_new_connection_id(buf::Vector{UInt8}, pos::Int, last::Int)::_DecodeResult{_NewConnectionIdFrame}
    (r = _decode_two_varints(buf, pos, last)) === nothing && return nothing
    seq, retire_prior_to, pos = r
    retire_prior_to <= seq || return nothing  # Section 19.15
    pos <= last || return nothing
    cid_len = buf[pos]
    1 <= cid_len <= _MAX_CID_LEN_V1 || return nothing
    (cid = _read_bytes(pos + 1, UInt64(cid_len), last)) === nothing && return nothing
    (reset_token = _read_bytes(cid.stop + 1, UInt64(16), last)) === nothing && return nothing
    return _NewConnectionIdFrame(seq, retire_prior_to, cid, reset_token), reset_token.stop + 1
end

function _decode_connection_close(buf::Vector{UInt8}, pos::Int, last::Int, app::Bool)::_DecodeResult{_ConnectionCloseFrame}
    (r = _read_varint(buf, pos, last)) === nothing && return nothing
    error_code, pos = r
    frame_type = UInt64(0)
    if !app
        (r = _read_varint(buf, pos, last)) === nothing && return nothing
        frame_type, pos = r
    end
    (r = _read_varint(buf, pos, last)) === nothing && return nothing
    len, pos = r
    (reason = _read_bytes(pos, len, last)) === nothing && return nothing
    return _ConnectionCloseFrame(app, error_code, frame_type, reason), pos + length(reason)
end

"""
    _frame_allowed(frame_type, packet_type) -> Bool

Whether a packet of `packet_type` may carry a frame of `frame_type` (RFC 9000
Section 12.4, Table 3). Only for known frame types.
"""
function _frame_allowed(frame_type::UInt64, packet_type::_PacketType.T)::Bool
    if packet_type == _PacketType.Initial || packet_type == _PacketType.Handshake
        # PADDING, PING, ACK, CRYPTO, and the transport CONNECTION_CLOSE.
        return frame_type <= 0x03 || frame_type == 0x06 || frame_type == 0x1c
    elseif packet_type == _PacketType.ZeroRTT
        # ACK, CRYPTO, NEW_TOKEN, RETIRE_CONNECTION_ID, PATH_RESPONSE, and
        # HANDSHAKE_DONE cannot be sent in 0-RTT. Table 3 lists
        # RETIRE_CONNECTION_ID as allowed there, but Section 12.5 includes it
        # with the others a server may reject.
        return !(frame_type == 0x02 || frame_type == 0x03 || frame_type == 0x06 || frame_type == 0x07 ||
                 frame_type == 0x19 || frame_type == 0x1b || frame_type == 0x1e)
    end
    return true
end

@inline _malformed(frame_type::UInt64)::_DecodedPayload =
    _DecodedPayload(_TransportError(_FRAME_ENCODING_ERROR, frame_type, "malformed frame"), false)

"""
    _decode_frames(handler, buf, first, last, packet_type) -> _DecodedPayload

Decode the frames of the decrypted payload `buf[first:last]` from a packet of
`packet_type`, calling `handler(frame)` for each in order. A handler returns
`nothing`, or a `_TransportError` to stop decoding with that error. Decoding
also stops at a malformed or unknown frame (FRAME_ENCODING_ERROR), a frame the
packet type does not permit, or an empty payload (PROTOCOL_VIOLATION). Frames
before the error have already been handled; the connection closes either way.
"""
function _decode_frames(handler::F, buf::Vector{UInt8}, first::Int, last::Int, packet_type::_PacketType.T)::_DecodedPayload where {F}
    first <= last ||
        return _DecodedPayload(_TransportError(_PROTOCOL_VIOLATION, UInt64(0), "packet contains no frames"), false)
    ack_eliciting = false
    pos = first
    while pos <= last
        (r = _read_varint(buf, pos, last)) === nothing && return _malformed(UInt64(0))
        type, pos = r
        type <= 0x1e || return _DecodedPayload(_TransportError(_FRAME_ENCODING_ERROR, type, "unknown frame type"), ack_eliciting)
        _frame_allowed(type, packet_type) ||
            return _DecodedPayload(_TransportError(_PROTOCOL_VIOLATION, type, "frame not permitted in this packet type"), ack_eliciting)
        result = if type == 0x00
            n = 1
            while pos <= last && buf[pos] == 0x00
                n += 1
                pos += 1
            end
            handler(_PaddingFrame(n))
        elseif type == 0x01
            handler(_PingFrame())
        elseif type <= 0x03
            (d = _decode_ack(buf, pos, last, type == 0x03)) === nothing && return _malformed(type)
            frame, pos = d
            handler(frame)
        elseif type == 0x04
            (d = _decode_reset_stream(buf, pos, last)) === nothing && return _malformed(type)
            frame, pos = d
            handler(frame)
        elseif type == 0x05
            (d = _decode_two_varints(buf, pos, last)) === nothing && return _malformed(type)
            stream_id, error_code, pos = d
            handler(_StopSendingFrame(stream_id, error_code))
        elseif type == 0x06
            (d = _decode_crypto(buf, pos, last)) === nothing && return _malformed(type)
            frame, pos = d
            handler(frame)
        elseif type == 0x07
            (d = _decode_new_token(buf, pos, last)) === nothing && return _malformed(type)
            frame, pos = d
            handler(frame)
        elseif type <= 0x0f
            (d = _decode_stream(buf, pos, last, type)) === nothing && return _malformed(type)
            frame, pos = d
            handler(frame)
        elseif type == 0x10 || type == 0x14 || type == 0x19
            (d = _read_varint(buf, pos, last)) === nothing && return _malformed(type)
            value, pos = d
            if type == 0x10
                handler(_MaxDataFrame(value))
            elseif type == 0x14
                handler(_DataBlockedFrame(value))
            else
                handler(_RetireConnectionIdFrame(value))
            end
        elseif type == 0x11 || type == 0x15
            (d = _decode_two_varints(buf, pos, last)) === nothing && return _malformed(type)
            stream_id, value, pos = d
            type == 0x11 ? handler(_MaxStreamDataFrame(stream_id, value)) : handler(_StreamDataBlockedFrame(stream_id, value))
        elseif type <= 0x13 || (0x16 <= type <= 0x17)
            (d = _read_varint(buf, pos, last)) === nothing && return _malformed(type)
            value, pos = d
            value <= _MAX_STREAMS_LIMIT || return _malformed(type)
            bidi = type == 0x12 || type == 0x16
            type <= 0x13 ? handler(_MaxStreamsFrame(bidi, value)) : handler(_StreamsBlockedFrame(bidi, value))
        elseif type == 0x18
            (d = _decode_new_connection_id(buf, pos, last)) === nothing && return _malformed(type)
            frame, pos = d
            handler(frame)
        elseif type == 0x1a || type == 0x1b
            (value = _read_u64_be(buf, pos, last)) === nothing && return _malformed(type)
            pos += 8
            type == 0x1a ? handler(_PathChallengeFrame(value)) : handler(_PathResponseFrame(value))
        elseif type <= 0x1d
            (d = _decode_connection_close(buf, pos, last, type == 0x1d)) === nothing && return _malformed(type)
            frame, pos = d
            handler(frame)
        else
            handler(_HandshakeDoneFrame())
        end
        # ACK, PADDING, and CONNECTION_CLOSE do not elicit an acknowledgment.
        ack_eliciting |= !(type == 0x00 || type == 0x02 || type == 0x03 || type == 0x1c || type == 0x1d)
        result isa _TransportError && return _DecodedPayload(result, ack_eliciting)
    end
    return _DecodedPayload(nothing, ack_eliciting)
end

"""
    _ack_ranges(buf, ack)

Iterate the packet number ranges an ACK frame acknowledges, largest first, as
`UnitRange{UInt64}`s. The frame was validated when decoded.
"""
_ack_ranges(buf::Vector{UInt8}, ack::_AckFrame) = _AckRanges(buf, ack)

struct _AckRanges
    buf::Vector{UInt8}
    ack::_AckFrame
end

Base.IteratorSize(::Type{_AckRanges}) = Base.HasLength()
Base.length(r::_AckRanges) = r.ack.range_count + 1
Base.eltype(::Type{_AckRanges}) = UnitRange{UInt64}

function Base.iterate(r::_AckRanges)
    smallest = r.ack.largest - r.ack.first_range
    return smallest:r.ack.largest, (r.ack.ranges.start, r.ack.range_count, smallest)
end

function Base.iterate(r::_AckRanges, state::Tuple{Int, Int, UInt64})
    pos, remaining, smallest = state
    remaining == 0 && return nothing
    gap, pos = _read_varint(r.buf, pos, r.ack.ranges.stop)::Tuple{UInt64, Int}
    len, pos = _read_varint(r.buf, pos, r.ack.ranges.stop)::Tuple{UInt64, Int}
    largest = smallest - gap - UInt64(2)
    smallest = largest - len
    return smallest:largest, (pos, remaining - 1, smallest)
end

# Encoding. Each `_append_*` appends one frame to `buf`.

_append_padding!(buf::Vector{UInt8}, n::Int)::Nothing = (append!(buf, zeros(UInt8, n)); nothing)

_append_ping_frame!(buf::Vector{UInt8})::Nothing = (push!(buf, 0x01); nothing)

"""
    _append_ack_frame!(buf, ranges, delay; ecn = nothing)

Append an ACK frame acknowledging `ranges`: nonempty packet number ranges,
largest first, with at least one unacknowledged packet between neighbors.
`delay` is already scaled by the ack_delay_exponent. `ecn` holds the ECT(0),
ECT(1), and ECN-CE counts for an ACK_ECN frame.
"""
function _append_ack_frame!(
        buf::Vector{UInt8},
        ranges::AbstractVector{UnitRange{UInt64}},
        delay::UInt64;
        ecn::Union{Nothing, NTuple{3, UInt64}} = nothing,
    )::Nothing
    isempty(ranges) && throw(ArgumentError("an ACK frame acknowledges at least one packet"))
    for i in eachindex(ranges)
        isempty(ranges[i]) && throw(ArgumentError("ACK ranges must be nonempty"))
        i == firstindex(ranges) && continue
        # Adjacent or overlapping ranges must be merged before encoding.
        ranges[i].stop + UInt64(2) <= ranges[i - 1].start ||
            throw(ArgumentError("ACK ranges must be descending and separated by a gap"))
    end
    push!(buf, ecn === nothing ? 0x02 : 0x03)
    top = ranges[firstindex(ranges)]
    _append_varint!(buf, top.stop)
    _append_varint!(buf, delay)
    _append_varint!(buf, UInt64(length(ranges) - 1))
    _append_varint!(buf, top.stop - top.start)
    smallest = top.start
    for i in (firstindex(ranges) + 1):lastindex(ranges)
        r = ranges[i]
        _append_varint!(buf, smallest - r.stop - UInt64(2))
        _append_varint!(buf, r.stop - r.start)
        smallest = r.start
    end
    if ecn !== nothing
        for count in ecn
            _append_varint!(buf, count)
        end
    end
    return nothing
end

function _append_reset_stream_frame!(buf::Vector{UInt8}, stream_id::UInt64, error_code::UInt64, final_size::UInt64)::Nothing
    push!(buf, 0x04)
    _append_varint!(buf, stream_id)
    _append_varint!(buf, error_code)
    _append_varint!(buf, final_size)
    return nothing
end

function _append_stop_sending_frame!(buf::Vector{UInt8}, stream_id::UInt64, error_code::UInt64)::Nothing
    push!(buf, 0x05)
    _append_varint!(buf, stream_id)
    _append_varint!(buf, error_code)
    return nothing
end

function _append_crypto_frame!(buf::Vector{UInt8}, offset::UInt64, data::AbstractVector{UInt8})::Nothing
    push!(buf, 0x06)
    _append_varint!(buf, offset)
    _append_varint!(buf, UInt64(length(data)))
    append!(buf, data)
    return nothing
end

function _append_new_token_frame!(buf::Vector{UInt8}, token::AbstractVector{UInt8})::Nothing
    isempty(token) && throw(ArgumentError("a NEW_TOKEN frame carries a token"))
    push!(buf, 0x07)
    _append_varint!(buf, UInt64(length(token)))
    append!(buf, token)
    return nothing
end

"""
    _append_stream_frame!(buf, stream_id, offset, data; fin = false, explicit_length = true)

Append a STREAM frame. The Offset field is omitted when `offset` is 0. Without
`explicit_length` the frame has no Length field and must end the packet. A
frame without data says nothing unless it carries the FIN, so as in quic-go
writing one throws `ArgumentError`.
"""
function _append_stream_frame!(
        buf::Vector{UInt8},
        stream_id::UInt64,
        offset::UInt64,
        data::AbstractVector{UInt8};
        fin::Bool = false,
        explicit_length::Bool = true,
    )::Nothing
    isempty(data) && !fin && throw(ArgumentError("a QUIC STREAM frame without data must carry the FIN"))
    push!(buf, 0x08 | (offset > 0 ? 0x04 : 0x00) | (explicit_length ? 0x02 : 0x00) | (fin ? 0x01 : 0x00))
    _append_varint!(buf, stream_id)
    offset > 0 && _append_varint!(buf, offset)
    explicit_length && _append_varint!(buf, UInt64(length(data)))
    append!(buf, data)
    return nothing
end

function _append_varint_frame!(buf::Vector{UInt8}, type::UInt8, value::UInt64)::Nothing
    push!(buf, type)
    _append_varint!(buf, value)
    return nothing
end

function _append_two_varint_frame!(buf::Vector{UInt8}, type::UInt8, a::UInt64, b::UInt64)::Nothing
    push!(buf, type)
    _append_varint!(buf, a)
    _append_varint!(buf, b)
    return nothing
end

_append_max_data_frame!(buf::Vector{UInt8}, max::UInt64)::Nothing = _append_varint_frame!(buf, 0x10, max)
_append_max_stream_data_frame!(buf::Vector{UInt8}, stream_id::UInt64, max::UInt64)::Nothing = _append_two_varint_frame!(buf, 0x11, stream_id, max)
_append_data_blocked_frame!(buf::Vector{UInt8}, limit::UInt64)::Nothing = _append_varint_frame!(buf, 0x14, limit)
_append_stream_data_blocked_frame!(buf::Vector{UInt8}, stream_id::UInt64, limit::UInt64)::Nothing = _append_two_varint_frame!(buf, 0x15, stream_id, limit)
_append_retire_connection_id_frame!(buf::Vector{UInt8}, seq::UInt64)::Nothing = _append_varint_frame!(buf, 0x19, seq)

function _append_max_streams_frame!(buf::Vector{UInt8}, bidi::Bool, max::UInt64)::Nothing
    max <= _MAX_STREAMS_LIMIT || throw(ArgumentError("QUIC stream limits stop at 2^60"))
    return _append_varint_frame!(buf, bidi ? 0x12 : 0x13, max)
end

function _append_streams_blocked_frame!(buf::Vector{UInt8}, bidi::Bool, limit::UInt64)::Nothing
    limit <= _MAX_STREAMS_LIMIT || throw(ArgumentError("QUIC stream limits stop at 2^60"))
    return _append_varint_frame!(buf, bidi ? 0x16 : 0x17, limit)
end

function _append_new_connection_id_frame!(
        buf::Vector{UInt8},
        seq::UInt64,
        retire_prior_to::UInt64,
        cid::AbstractVector{UInt8},
        reset_token::AbstractVector{UInt8},
    )::Nothing
    1 <= length(cid) <= _MAX_CID_LEN_V1 || throw(ArgumentError("NEW_CONNECTION_ID carries a 1 to 20 byte connection ID"))
    length(reset_token) == 16 || throw(ArgumentError("a stateless reset token is 16 bytes"))
    retire_prior_to <= seq || throw(ArgumentError("Retire Prior To cannot exceed the sequence number"))
    push!(buf, 0x18)
    _append_varint!(buf, seq)
    _append_varint!(buf, retire_prior_to)
    push!(buf, UInt8(length(cid)))
    append!(buf, cid)
    append!(buf, reset_token)
    return nothing
end

function _append_path_frame!(buf::Vector{UInt8}, type::UInt8, data::UInt64)::Nothing
    push!(buf, type)
    for i in 7:-1:0
        push!(buf, UInt8((data >> (8 * i)) & 0xff))
    end
    return nothing
end

_append_path_challenge_frame!(buf::Vector{UInt8}, data::UInt64)::Nothing = _append_path_frame!(buf, 0x1a, data)
_append_path_response_frame!(buf::Vector{UInt8}, data::UInt64)::Nothing = _append_path_frame!(buf, 0x1b, data)

"""
    _append_connection_close_frame!(buf, error_code, frame_type, reason; app = false)

Append a CONNECTION_CLOSE frame. The transport variant names the frame type
that caused the error; the application variant (`app = true`) has no such field
and `frame_type` is ignored.
"""
function _append_connection_close_frame!(
        buf::Vector{UInt8},
        error_code::UInt64,
        frame_type::UInt64,
        reason::AbstractVector{UInt8};
        app::Bool = false,
    )::Nothing
    push!(buf, app ? 0x1d : 0x1c)
    _append_varint!(buf, error_code)
    app || _append_varint!(buf, frame_type)
    _append_varint!(buf, UInt64(length(reason)))
    append!(buf, reason)
    return nothing
end

_append_handshake_done_frame!(buf::Vector{UInt8})::Nothing = (push!(buf, 0x1e); nothing)
