# QUIC transport parameters (RFC 9000 Section 18), carried in the TLS
# quic_transport_parameters extension.

const _TP_ORIGINAL_DESTINATION_CONNECTION_ID = UInt64(0x00)
const _TP_MAX_IDLE_TIMEOUT = UInt64(0x01)
const _TP_STATELESS_RESET_TOKEN = UInt64(0x02)
const _TP_MAX_UDP_PAYLOAD_SIZE = UInt64(0x03)
const _TP_INITIAL_MAX_DATA = UInt64(0x04)
const _TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL = UInt64(0x05)
const _TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE = UInt64(0x06)
const _TP_INITIAL_MAX_STREAM_DATA_UNI = UInt64(0x07)
const _TP_INITIAL_MAX_STREAMS_BIDI = UInt64(0x08)
const _TP_INITIAL_MAX_STREAMS_UNI = UInt64(0x09)
const _TP_ACK_DELAY_EXPONENT = UInt64(0x0a)
const _TP_MAX_ACK_DELAY = UInt64(0x0b)
const _TP_DISABLE_ACTIVE_MIGRATION = UInt64(0x0c)
const _TP_PREFERRED_ADDRESS = UInt64(0x0d)
const _TP_ACTIVE_CONNECTION_ID_LIMIT = UInt64(0x0e)
const _TP_INITIAL_SOURCE_CONNECTION_ID = UInt64(0x0f)
const _TP_RETRY_SOURCE_CONNECTION_ID = UInt64(0x10)

const _MIN_UDP_PAYLOAD_SIZE = UInt64(1200)

"""
    _TransportParameters

One endpoint's transport parameters. Integer fields hold the RFC 9000 Section
18.2 defaults unless set; connection IDs and tokens are `nothing` when absent.
`preferred_address` is kept as its raw, validated encoding.
"""
Base.@kwdef struct _TransportParameters
    original_destination_connection_id::Union{Nothing, Vector{UInt8}} = nothing
    max_idle_timeout_ms::UInt64 = UInt64(0)
    stateless_reset_token::Union{Nothing, Vector{UInt8}} = nothing
    max_udp_payload_size::UInt64 = UInt64(65527)
    initial_max_data::UInt64 = UInt64(0)
    initial_max_stream_data_bidi_local::UInt64 = UInt64(0)
    initial_max_stream_data_bidi_remote::UInt64 = UInt64(0)
    initial_max_stream_data_uni::UInt64 = UInt64(0)
    initial_max_streams_bidi::UInt64 = UInt64(0)
    initial_max_streams_uni::UInt64 = UInt64(0)
    ack_delay_exponent::UInt64 = UInt64(3)
    max_ack_delay_ms::UInt64 = UInt64(25)
    disable_active_migration::Bool = false
    preferred_address::Union{Nothing, Vector{UInt8}} = nothing
    active_connection_id_limit::UInt64 = UInt64(2)
    initial_source_connection_id::Union{Nothing, Vector{UInt8}} = nothing
    retry_source_connection_id::Union{Nothing, Vector{UInt8}} = nothing
end

function Base.:(==)(a::_TransportParameters, b::_TransportParameters)::Bool
    for name in fieldnames(_TransportParameters)
        getfield(a, name) == getfield(b, name) || return false
    end
    return true
end

const _DEFAULT_TRANSPORT_PARAMETERS = _TransportParameters()

function _append_tp_bytes!(buf::Vector{UInt8}, id::UInt64, value::AbstractVector{UInt8})::Nothing
    _append_varint!(buf, id)
    _append_varint!(buf, UInt64(length(value)))
    append!(buf, value)
    return nothing
end

function _append_tp_varint!(buf::Vector{UInt8}, id::UInt64, value::UInt64, default::UInt64)::Nothing
    value == default && return nothing
    _append_varint!(buf, id)
    _append_varint!(buf, UInt64(_varint_length(value)))
    _append_varint!(buf, value)
    return nothing
end

"""
    _encode_transport_parameters(p) -> Vector{UInt8}

Encode `p`, leaving out integer parameters that hold their default value.
"""
function _encode_transport_parameters(p::_TransportParameters)::Vector{UInt8}
    d = _DEFAULT_TRANSPORT_PARAMETERS
    buf = UInt8[]
    p.original_destination_connection_id === nothing ||
        _append_tp_bytes!(buf, _TP_ORIGINAL_DESTINATION_CONNECTION_ID, p.original_destination_connection_id)
    _append_tp_varint!(buf, _TP_MAX_IDLE_TIMEOUT, p.max_idle_timeout_ms, d.max_idle_timeout_ms)
    p.stateless_reset_token === nothing || _append_tp_bytes!(buf, _TP_STATELESS_RESET_TOKEN, p.stateless_reset_token)
    _append_tp_varint!(buf, _TP_MAX_UDP_PAYLOAD_SIZE, p.max_udp_payload_size, d.max_udp_payload_size)
    _append_tp_varint!(buf, _TP_INITIAL_MAX_DATA, p.initial_max_data, d.initial_max_data)
    _append_tp_varint!(buf, _TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, p.initial_max_stream_data_bidi_local, d.initial_max_stream_data_bidi_local)
    _append_tp_varint!(buf, _TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, p.initial_max_stream_data_bidi_remote, d.initial_max_stream_data_bidi_remote)
    _append_tp_varint!(buf, _TP_INITIAL_MAX_STREAM_DATA_UNI, p.initial_max_stream_data_uni, d.initial_max_stream_data_uni)
    _append_tp_varint!(buf, _TP_INITIAL_MAX_STREAMS_BIDI, p.initial_max_streams_bidi, d.initial_max_streams_bidi)
    _append_tp_varint!(buf, _TP_INITIAL_MAX_STREAMS_UNI, p.initial_max_streams_uni, d.initial_max_streams_uni)
    _append_tp_varint!(buf, _TP_ACK_DELAY_EXPONENT, p.ack_delay_exponent, d.ack_delay_exponent)
    _append_tp_varint!(buf, _TP_MAX_ACK_DELAY, p.max_ack_delay_ms, d.max_ack_delay_ms)
    p.disable_active_migration && _append_tp_bytes!(buf, _TP_DISABLE_ACTIVE_MIGRATION, UInt8[])
    p.preferred_address === nothing || _append_tp_bytes!(buf, _TP_PREFERRED_ADDRESS, p.preferred_address)
    _append_tp_varint!(buf, _TP_ACTIVE_CONNECTION_ID_LIMIT, p.active_connection_id_limit, d.active_connection_id_limit)
    p.initial_source_connection_id === nothing ||
        _append_tp_bytes!(buf, _TP_INITIAL_SOURCE_CONNECTION_ID, p.initial_source_connection_id)
    p.retry_source_connection_id === nothing ||
        _append_tp_bytes!(buf, _TP_RETRY_SOURCE_CONNECTION_ID, p.retry_source_connection_id)
    return buf
end

@inline _tp_error(reason::String)::_TransportError = _TransportError(_TRANSPORT_PARAMETER_ERROR, UInt64(0), reason)

# An integer parameter's value is exactly one variable-length integer.
function _tp_integer(bytes::Vector{UInt8}, value::UnitRange{Int})::Union{Nothing, UInt64}
    isempty(value) && return nothing
    parsed = _read_varint(bytes, value.start, value.stop)
    parsed === nothing && return nothing
    v, next = parsed
    next == value.stop + 1 || return nothing
    return v
end

# Section 18.2: IPv4 address and port, IPv6 address and port, a 1-20 byte
# connection ID with its length, and a stateless reset token.
function _valid_preferred_address(bytes::Vector{UInt8}, value::UnitRange{Int})::Bool
    length(value) >= 25 || return false
    cid_len = Int(bytes[value.start + 24])
    1 <= cid_len <= _MAX_CID_LEN_V1 || return false
    return length(value) == 25 + cid_len + 16
end

"""
    _decode_transport_parameters(bytes; from_server) -> _TransportParameters or _TransportError

Decode and validate the peer's transport parameters. `from_server` says which
side sent them, since some may only come from a server. Unknown parameters are
ignored.
"""
function _decode_transport_parameters(bytes::Vector{UInt8}; from_server::Bool)::Union{_TransportParameters, _TransportError}
    seen = UInt64[]
    odcid = nothing
    max_idle_timeout_ms = UInt64(0)
    reset_token = nothing
    max_udp_payload_size = UInt64(65527)
    initial_max_data = UInt64(0)
    bidi_local = UInt64(0)
    bidi_remote = UInt64(0)
    uni = UInt64(0)
    streams_bidi = UInt64(0)
    streams_uni = UInt64(0)
    ack_delay_exponent = UInt64(3)
    max_ack_delay_ms = UInt64(25)
    disable_active_migration = false
    preferred_address = nothing
    active_connection_id_limit = UInt64(2)
    iscid = nothing
    rscid = nothing
    pos = 1
    last = length(bytes)
    while pos <= last
        (r = _read_varint(bytes, pos, last)) === nothing && return _tp_error("truncated transport parameter ID")
        id, pos = r
        (r = _read_varint(bytes, pos, last)) === nothing && return _tp_error("truncated transport parameter length")
        len, pos = r
        len <= UInt64(last - pos + 1) || return _tp_error("transport parameter runs past the extension")
        value = pos:(pos + Int(len) - 1)
        pos = value.stop + 1
        id > _TP_RETRY_SOURCE_CONNECTION_ID && continue  # unknown, including greased IDs
        id in seen && return _tp_error("duplicate transport parameter")
        push!(seen, id)
        if !from_server && (id == _TP_ORIGINAL_DESTINATION_CONNECTION_ID || id == _TP_STATELESS_RESET_TOKEN ||
                            id == _TP_PREFERRED_ADDRESS || id == _TP_RETRY_SOURCE_CONNECTION_ID)
            return _tp_error("client sent a server-only transport parameter")
        end
        if id == _TP_ORIGINAL_DESTINATION_CONNECTION_ID || id == _TP_INITIAL_SOURCE_CONNECTION_ID || id == _TP_RETRY_SOURCE_CONNECTION_ID
            length(value) <= _MAX_CID_LEN_V1 || return _tp_error("connection ID transport parameter is too long")
            cid = bytes[value]
            if id == _TP_ORIGINAL_DESTINATION_CONNECTION_ID
                odcid = cid
            elseif id == _TP_INITIAL_SOURCE_CONNECTION_ID
                iscid = cid
            else
                rscid = cid
            end
        elseif id == _TP_STATELESS_RESET_TOKEN
            length(value) == 16 || return _tp_error("stateless_reset_token is 16 bytes")
            reset_token = bytes[value]
        elseif id == _TP_DISABLE_ACTIVE_MIGRATION
            isempty(value) || return _tp_error("disable_active_migration carries no value")
            disable_active_migration = true
        elseif id == _TP_PREFERRED_ADDRESS
            _valid_preferred_address(bytes, value) || return _tp_error("malformed preferred_address")
            preferred_address = bytes[value]
        else
            (v = _tp_integer(bytes, value)) === nothing && return _tp_error("malformed integer transport parameter")
            if id == _TP_MAX_IDLE_TIMEOUT
                max_idle_timeout_ms = v
            elseif id == _TP_MAX_UDP_PAYLOAD_SIZE
                v >= _MIN_UDP_PAYLOAD_SIZE || return _tp_error("max_udp_payload_size is below 1200")
                max_udp_payload_size = v
            elseif id == _TP_INITIAL_MAX_DATA
                initial_max_data = v
            elseif id == _TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL
                bidi_local = v
            elseif id == _TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE
                bidi_remote = v
            elseif id == _TP_INITIAL_MAX_STREAM_DATA_UNI
                uni = v
            elseif id == _TP_INITIAL_MAX_STREAMS_BIDI || id == _TP_INITIAL_MAX_STREAMS_UNI
                v <= _MAX_STREAMS_LIMIT || return _tp_error("initial stream limit exceeds 2^60")
                id == _TP_INITIAL_MAX_STREAMS_BIDI ? (streams_bidi = v) : (streams_uni = v)
            elseif id == _TP_ACK_DELAY_EXPONENT
                v <= 20 || return _tp_error("ack_delay_exponent exceeds 20")
                ack_delay_exponent = v
            elseif id == _TP_MAX_ACK_DELAY
                v < (UInt64(1) << 14) || return _tp_error("max_ack_delay is 2^14 or more")
                max_ack_delay_ms = v
            else  # active_connection_id_limit
                v >= 2 || return _tp_error("active_connection_id_limit is below 2")
                active_connection_id_limit = v
            end
        end
    end
    return _TransportParameters(
        odcid, max_idle_timeout_ms, reset_token, max_udp_payload_size, initial_max_data,
        bidi_local, bidi_remote, uni, streams_bidi, streams_uni, ack_delay_exponent,
        max_ack_delay_ms, disable_active_migration, preferred_address,
        active_connection_id_limit, iscid, rscid,
    )
end
