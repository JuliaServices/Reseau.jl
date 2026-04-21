const _TLS13_AEAD_TAG_SIZE = 16
const _TLS13_MAX_PLAINTEXT = 16_384
const _TLS13_MAX_CIPHERTEXT = _TLS13_MAX_PLAINTEXT + 256
const _TLS13_MAX_HANDSHAKE_BUFFER = _MAX_CERTIFICATE_HANDSHAKE_SIZE + _TLS13_MAX_PLAINTEXT
const _TLS13_HANDSHAKE_TYPE_KEY_UPDATE = UInt8(24)
const _TLS13_KEY_UPDATE_NOT_REQUESTED = UInt8(0)
const _TLS13_KEY_UPDATE_REQUESTED = UInt8(1)
const _TLS13_DUMMY_CHANGE_CIPHER_SPEC = UInt8[0x01]

"""
    _TLS13RecordCipherState

Installed TLS 1.3 traffic-secret state for one direction of a connection.

Unlike TLS 1.2, TLS 1.3 derives the AEAD key/IV directly from the traffic
secret, so the state keeps both the current secret and the derived keying
material needed for record protection and KeyUpdate.
"""
mutable struct _TLS13RecordCipherState
    spec::_TLS13CipherSpec
    traffic_secret::Vector{UInt8}
    key::Vector{UInt8}
    iv::Vector{UInt8}
    seq::UInt64
    exhausted::Bool
    aead::_OpenSSLAEADState
    nonce_buf::Vector{UInt8}
    outbuf::Vector{UInt8}
end

function _TLS13RecordCipherState(spec::_TLS13CipherSpec, traffic_secret::AbstractVector{UInt8})
    traffic_key = _tls13_traffic_key(spec, traffic_secret)
    return _TLS13RecordCipherState(
        spec,
        Vector{UInt8}(traffic_secret),
        traffic_key.key,
        traffic_key.iv,
        UInt64(0),
        false,
        _OpenSSLAEADState(_tls13_record_cipher(spec), length(traffic_key.iv)),
        Vector{UInt8}(undef, length(traffic_key.iv)),
        UInt8[],
    )
end

"""
    _TLS13NativeClientState

Connection-owned TLS 1.3 record-layer and post-handshake state.

This is the long-lived state that survives after the TLS 1.3 handshake: record
keys, buffered handshake/plaintext data, shutdown flags, resumable-session
material, and negotiated metadata exposed through `connection_state`.
"""
mutable struct _TLS13NativeClientState
    read_cipher::Union{Nothing, _TLS13RecordCipherState}
    write_cipher::Union{Nothing, _TLS13RecordCipherState}
    record_buffer::Vector{UInt8}
    handshake_buffer::Vector{UInt8}
    handshake_buffer_pos::Int
    plaintext_buffer::Vector{UInt8}
    plaintext_buffer_pos::Int
    useless_record_count::Int
    peer_close_notify::Bool
    sent_close_notify::Bool
    sent_dummy_ccs::Bool
    resumption_secret::Vector{UInt8}
    session_certificates::Vector{Vector{UInt8}}
    session_cipher_suite::UInt16
    session_cache_key::String
    session_alpn::String
    did_resume::Bool
    did_hello_retry_request::Bool
    curve_id::UInt16
end

_TLS13NativeClientState() = _TLS13NativeClientState(
    nothing,
    nothing,
    UInt8[],
    UInt8[],
    1,
    UInt8[],
    1,
    0,
    false,
    false,
    false,
    UInt8[],
    Vector{Vector{UInt8}}(),
    UInt16(0),
    "",
    "",
    false,
    false,
    UInt16(0),
)

"""
    _TLS13HandshakeRecordIO

Thin adapter that exposes TLS 1.3 handshake read/write operations in terms of
the underlying TCP stream plus the connection's TLS 1.3 native record state.
"""
mutable struct _TLS13HandshakeRecordIO
    tcp::TCP.Conn
    state::_TLS13NativeClientState
end

function _securezero_tls13_record_cipher!(cipher::_TLS13RecordCipherState)::Nothing
    _securezero!(cipher.traffic_secret)
    _securezero!(cipher.key)
    _securezero!(cipher.iv)
    _free_openssl_aead_state!(cipher.aead)
    _securezero!(cipher.nonce_buf)
    _securezero!(cipher.outbuf)
    empty!(cipher.outbuf)
    cipher.seq = UInt64(0)
    cipher.exhausted = false
    return nothing
end

function _securezero_tls13_native_client_state!(state::_TLS13NativeClientState)::Nothing
    if state.read_cipher !== nothing
        _securezero_tls13_record_cipher!(state.read_cipher::_TLS13RecordCipherState)
        state.read_cipher = nothing
    end
    if state.write_cipher !== nothing
        _securezero_tls13_record_cipher!(state.write_cipher::_TLS13RecordCipherState)
        state.write_cipher = nothing
    end
    _securezero!(state.record_buffer)
    _securezero!(state.handshake_buffer)
    _securezero!(state.plaintext_buffer)
    _securezero!(state.resumption_secret)
    for cert in state.session_certificates
        _securezero!(cert)
    end
    empty!(state.record_buffer)
    empty!(state.handshake_buffer)
    empty!(state.plaintext_buffer)
    empty!(state.resumption_secret)
    empty!(state.session_certificates)
    state.handshake_buffer_pos = 1
    state.plaintext_buffer_pos = 1
    state.useless_record_count = 0
    state.peer_close_notify = false
    state.sent_close_notify = false
    state.sent_dummy_ccs = false
    state.session_cipher_suite = UInt16(0)
    state.session_cache_key = ""
    state.session_alpn = ""
    state.did_resume = false
    state.did_hello_retry_request = false
    state.curve_id = UInt16(0)
    return nothing
end

function _tls13_set_read_cipher!(state::_TLS13NativeClientState, spec::_TLS13CipherSpec, traffic_secret::AbstractVector{UInt8})::Nothing
    if state.read_cipher !== nothing
        _securezero_tls13_record_cipher!(state.read_cipher::_TLS13RecordCipherState)
    end
    state.read_cipher = _TLS13RecordCipherState(spec, traffic_secret)
    return nothing
end

function _tls13_set_write_cipher!(state::_TLS13NativeClientState, spec::_TLS13CipherSpec, traffic_secret::AbstractVector{UInt8})::Nothing
    if state.write_cipher !== nothing
        _securezero_tls13_record_cipher!(state.write_cipher::_TLS13RecordCipherState)
    end
    state.write_cipher = _TLS13RecordCipherState(spec, traffic_secret)
    return nothing
end

function _tls13_advance_read_cipher!(state::_TLS13NativeClientState)::Nothing
    cipher = state.read_cipher
    cipher === nothing && throw(ArgumentError("tls: missing TLS 1.3 read traffic keys"))
    cipher_state = cipher::_TLS13RecordCipherState
    next_secret = _tls13_next_traffic_secret(cipher_state.spec, cipher_state.traffic_secret)
    try
        _tls13_set_read_cipher!(state, cipher_state.spec, next_secret)
    finally
        _securezero!(next_secret)
    end
    return nothing
end

function _tls13_advance_write_cipher!(state::_TLS13NativeClientState)::Nothing
    cipher = state.write_cipher
    cipher === nothing && throw(ArgumentError("tls: missing TLS 1.3 write traffic keys"))
    cipher_state = cipher::_TLS13RecordCipherState
    next_secret = _tls13_next_traffic_secret(cipher_state.spec, cipher_state.traffic_secret)
    try
        _tls13_set_write_cipher!(state, cipher_state.spec, next_secret)
    finally
        _securezero!(next_secret)
    end
    return nothing
end

function _tls13_fill_nonce!(dest::Vector{UInt8}, iv::Vector{UInt8}, seq::UInt64)::Nothing
    copyto!(dest, 1, iv, 1, length(iv))
    @inbounds for i in 0:7
        dest[end - i] = xor(dest[end - i], UInt8((seq >> (8 * i)) & 0xff))
    end
    return nothing
end

function _tls13_nonce(iv::AbstractVector{UInt8}, seq::UInt64)::Vector{UInt8}
    nonce = iv isa Vector{UInt8} ? copy(iv) : Vector{UInt8}(iv)
    @inbounds for i in 0:7
        nonce[end - i] = xor(nonce[end - i], UInt8((seq >> (8 * i)) & 0xff))
    end
    return nonce
end

@inline function _tls13_fill_record_header!(dest::Vector{UInt8}, content_type::UInt8, payload_len::Int)::Nothing
    payload_len <= 0xffff || throw(ArgumentError("tls: record payload too large"))
    @inbounds begin
        dest[1] = content_type
        dest[2] = UInt8(TLS1_2_VERSION >> 8)
        dest[3] = UInt8(TLS1_2_VERSION & 0xff)
        dest[4] = UInt8(payload_len >> 8)
        dest[5] = UInt8(payload_len & 0xff)
    end
    return nothing
end

# TLS 1.3 record writes emit plaintext only before handshake keys are installed.
# After that they always produce application-data outer records that carry an
# encrypted inner content type, mirroring Go's TLS 1.3 record layer.
function _tls13_write_record!(
    tcp::TCP.Conn,
    cipher::Union{Nothing, _TLS13RecordCipherState},
    inner_type::UInt8,
    payload_ptr::Ptr{UInt8},
    payload_len::Int,
)::Nothing
    payload_len <= _TLS13_MAX_PLAINTEXT || throw(ArgumentError("tls: TLS 1.3 record plaintext exceeds the maximum record size"))
    if cipher === nothing
        payload = unsafe_wrap(Vector{UInt8}, payload_ptr, payload_len; own = false)
        _tls_write_tls_plaintext!(tcp, inner_type, payload)
        return nothing
    end
    cipher_state = cipher::_TLS13RecordCipherState
    cipher_state.exhausted && throw(ArgumentError("tls: TLS 1.3 write traffic secret exhausted"))
    inner_len = payload_len + 1
    record_payload_len = inner_len + _TLS13_AEAD_TAG_SIZE
    total_record_len = 5 + record_payload_len
    resize!(cipher_state.outbuf, total_record_len)
    outbuf = cipher_state.outbuf
    try
        @inbounds begin
            outbuf[1] = _TLS_RECORD_TYPE_APPLICATION_DATA
            outbuf[2] = UInt8(TLS1_2_VERSION >> 8)
            outbuf[3] = UInt8(TLS1_2_VERSION & 0xff)
            outbuf[4] = UInt8(record_payload_len >> 8)
            outbuf[5] = UInt8(record_payload_len & 0xff)
        end
        if payload_len != 0
            GC.@preserve outbuf begin
                unsafe_copyto!(pointer(outbuf, 6), payload_ptr, payload_len)
            end
        end
        outbuf[6 + payload_len] = inner_type
        _tls13_fill_nonce!(cipher_state.nonce_buf, cipher_state.iv, cipher_state.seq)
        ciphertext_len = _tls13_encrypt_record_aead!(
            cipher_state.aead,
            outbuf,
            6,
            inner_len,
            cipher_state.key,
            cipher_state.nonce_buf,
            pointer(outbuf, 1),
            5,
        )
        ciphertext_len == record_payload_len ||
            throw(ArgumentError("tls: TLS 1.3 AEAD produced an unexpected ciphertext length"))
        write(tcp, outbuf)
        if cipher_state.seq == typemax(UInt64)
            cipher_state.exhausted = true
        else
            cipher_state.seq += UInt64(1)
        end
    finally
        _securezero!(cipher_state.nonce_buf)
    end
    return nothing
end

function _tls13_write_record!(
    tcp::TCP.Conn,
    cipher::Union{Nothing, _TLS13RecordCipherState},
    inner_type::UInt8,
    payload::AbstractVector{UInt8},
)::Nothing
    GC.@preserve payload begin
        return _tls13_write_record!(tcp, cipher, inner_type, pointer(payload), length(payload))
    end
end

function _tls13_process_alert!(state::_TLS13NativeClientState, alert::AbstractVector{UInt8})::Nothing
    length(alert) == 2 || _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.3 alert")
    alert_desc = alert[2]
    if alert_desc != _TLS_ALERT_CLOSE_NOTIFY
        alert_level = alert[1]
        level_name = if alert_level == _TLS_ALERT_LEVEL_WARNING
            "warning"
        elseif alert_level == _TLS_ALERT_LEVEL_FATAL
            "fatal"
        else
            "unknown"
        end
        throw(_tls_peer_alert_error(alert_desc, "tls: received $level_name TLS 1.3 alert $(Int(alert_desc))"))
    end
    state.peer_close_notify = true
    return nothing
end

# TLS 1.3 inner plaintext parsing strips padding, recovers the true content
# type, then routes the payload into the handshake/plaintext/post-handshake
# machinery owned by the connection.
function _tls13_process_inner_plaintext!(state::_TLS13NativeClientState, inner::AbstractVector{UInt8})::Bool
    idx = length(inner)
    while idx >= 1 && inner[idx] == 0x00
        idx -= 1
    end
    idx >= 1 || _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: TLS 1.3 record is missing an inner content type")
    content_type = inner[idx]
    payload_len = idx - 1
    if content_type == _TLS_RECORD_TYPE_HANDSHAKE
        if payload_len != 0
            append!(state.handshake_buffer, @view(inner[1:payload_len]))
            length(state.handshake_buffer) <= _TLS13_MAX_HANDSHAKE_BUFFER ||
                _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: received too much buffered TLS 1.3 handshake data")
        end
        return payload_len != 0
    end
    if content_type == _TLS_RECORD_TYPE_APPLICATION_DATA
        payload_len == 0 || append!(state.plaintext_buffer, @view(inner[1:payload_len]))
        return payload_len != 0
    end
    if content_type == _TLS_RECORD_TYPE_ALERT
        _tls13_process_alert!(state, @view(inner[1:payload_len]))
        return false
    end
    _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received unexpected TLS 1.3 inner record type $(Int(content_type))")
end

# Record reads are responsible for parsing/decrypting the outer TLS 1.3 record,
# then feeding any recovered handshake, alert, application, or post-handshake
# bytes into the appropriate connection-owned buffers.
function _tls13_read_record!(tcp::TCP.Conn, state::_TLS13NativeClientState)::Nothing
    payload_len = _tls_read_wire_record!(tcp, state.record_buffer, _TLS13_MAX_CIPHERTEXT)
    record = state.record_buffer
    content_type = record[1]
    payload_start = 6
    payload_end = 5 + payload_len
    payload = @view(record[payload_start:payload_end])
    if content_type == _TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC
        payload_len == 1 && payload[1] == 0x01 || _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed ChangeCipherSpec record")
        _tls_note_useless_record!(state, "tls: too many ignored TLS records")
        return nothing
    end
    if state.read_cipher === nothing
        if content_type == _TLS_RECORD_TYPE_HANDSHAKE
            if payload_len != 0
                append!(state.handshake_buffer, payload)
                length(state.handshake_buffer) <= _TLS13_MAX_HANDSHAKE_BUFFER ||
                    _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: received too much buffered TLS 1.3 handshake data")
                _tls_reset_useless_record_count!(state)
            end
            return nothing
        end
        if content_type == _TLS_RECORD_TYPE_ALERT
            _tls13_process_alert!(state, payload)
            return nothing
        end
        _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received unexpected plaintext TLS 1.3 record type $(Int(content_type))")
    end
    content_type == _TLS_RECORD_TYPE_APPLICATION_DATA ||
        _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received unexpected TLS 1.3 record type $(Int(content_type))")
    cipher = state.read_cipher::_TLS13RecordCipherState
    cipher.exhausted && _tls_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: TLS 1.3 read traffic secret exhausted")
    payload_len >= _TLS13_AEAD_TAG_SIZE ||
        _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.3 AEAD record")
    ciphertext_len = payload_len - _TLS13_AEAD_TAG_SIZE
    _tls13_fill_nonce!(cipher.nonce_buf, cipher.iv, cipher.seq)
    plaintext_len_or_nothing = _tls13_decrypt_record_aead!(
        cipher.aead,
        record,
        payload_start,
        ciphertext_len,
        payload_start + ciphertext_len,
        cipher.key,
        cipher.nonce_buf,
        pointer(record, 1),
        5,
    )
    _securezero!(cipher.nonce_buf)
    plaintext_len_or_nothing === nothing && _tls_fail(_TLS_ALERT_BAD_RECORD_MAC, "tls: invalid TLS 1.3 record authentication tag")
    plaintext = @view(record[payload_start:payload_start + (plaintext_len_or_nothing::Int) - 1])
    advanced = _tls13_process_inner_plaintext!(state, plaintext)
    advanced && _tls_reset_useless_record_count!(state)
    if cipher.seq == typemax(UInt64)
        cipher.exhausted = true
    else
        cipher.seq += UInt64(1)
    end
    return nothing
end

function _tls13_try_take_handshake_message!(state::_TLS13NativeClientState)::Union{Nothing, Vector{UInt8}}
    available = _tls_buffer_available(state.handshake_buffer, state.handshake_buffer_pos)
    available == 0 && return nothing
    available >= 4 || return nothing
    pos = state.handshake_buffer_pos
    msg_len = 4 +
        (Int(state.handshake_buffer[pos + 1]) << 16) +
        (Int(state.handshake_buffer[pos + 2]) << 8) +
        Int(state.handshake_buffer[pos + 3])
    msg_type = state.handshake_buffer[pos]
    msg_len <= _tls_max_handshake_frame_size(msg_type) ||
        _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: received oversized handshake message")
    available >= msg_len || return nothing
    raw = Vector{UInt8}(undef, msg_len)
    copyto!(raw, 1, state.handshake_buffer, pos, msg_len)
    state.handshake_buffer_pos += msg_len
    state.handshake_buffer_pos = _tls_compact_buffer!(state.handshake_buffer, state.handshake_buffer_pos)
    return raw
end

@inline function _tls13_parse_key_update(raw::Vector{UInt8})::Union{Nothing, Bool}
    length(raw) == 5 || return nothing
    raw[1] == _TLS13_HANDSHAKE_TYPE_KEY_UPDATE || return nothing
    raw[2] == 0x00 || return nothing
    raw[3] == 0x00 || return nothing
    raw[4] == 0x01 || return nothing
    request_update = raw[5]
    request_update == _TLS13_KEY_UPDATE_NOT_REQUESTED && return false
    request_update == _TLS13_KEY_UPDATE_REQUESTED && return true
    return nothing
end

@inline function _tls13_key_update_message(request_update::Bool)::Vector{UInt8}
    return UInt8[
        _TLS13_HANDSHAKE_TYPE_KEY_UPDATE,
        0x00,
        0x00,
        0x01,
        request_update ? _TLS13_KEY_UPDATE_REQUESTED : _TLS13_KEY_UPDATE_NOT_REQUESTED,
    ]
end

function _tls13_handle_key_update!(tcp::TCP.Conn, state::_TLS13NativeClientState, request_update::Bool)::Nothing
    if request_update
        raw = _tls13_key_update_message(false)
        try
            _tls13_write_record!(tcp, state.write_cipher, _TLS_RECORD_TYPE_HANDSHAKE, raw)
            _tls13_advance_write_cipher!(state)
        finally
            _securezero!(raw)
        end
    end
    _tls13_advance_read_cipher!(state)
    return nothing
end

function _tls13_store_new_session_ticket!(conn, msg::_NewSessionTicketMsgTLS13)::Nothing
    conn.config.session_tickets_disabled && return nothing
    state = _native_tls13_state(conn)
    isempty(state.resumption_secret) && return nothing
    isempty(state.session_cache_key) && return nothing
    state.session_cipher_suite == UInt16(0) && return nothing
    cipher_spec = _tls13_cipher_spec(state.session_cipher_suite)
    cipher_spec === nothing && _tls_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: cannot store a session ticket for an unsupported cipher suite")
    hash_kind = cipher_spec.hash_kind
    psk = _tls13_expand_label(hash_kind, state.resumption_secret, "resumption", msg.nonce, _hash_len(hash_kind))
    try
        now_s = UInt64(floor(time()))
        session = _owned_tls13_client_session(
            TLS1_3_VERSION,
            state.session_cipher_suite,
            now_s,
            now_s + UInt64(msg.lifetime),
            msg.age_add,
            msg.label,
            psk,
            state.session_certificates,
            state.session_alpn,
        )
        _tls_session_cache_put!(conn.config._client_session_cache, state.session_cache_key, session, _securezero_tls13_client_session!)
        _securezero_tls13_client_session!(session)
    finally
        _securezero!(psk)
    end
    return nothing
end

function _tls13_validate_new_session_ticket(raw::Vector{UInt8})::_NewSessionTicketMsgTLS13
    msg = _unmarshal_new_session_ticket_tls13(raw)
    msg === nothing && _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: unexpected post-handshake TLS 1.3 message")
    msg.lifetime == 0x00000000 && return msg
    msg.lifetime <= _TLS13_MAX_SESSION_TICKET_LIFETIME ||
        _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: received a session ticket with invalid lifetime")
    isempty(msg.label) && _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: received a session ticket with empty opaque ticket label")
    return msg
end

# Post-handshake processing is intentionally owned by the record layer because
# KeyUpdate and NewSessionTicket arrive as ordinary records long after the main
# handshake state machine has finished.
function _tls13_handle_post_handshake_messages!(tcp::TCP.Conn, state::_TLS13NativeClientState)::Nothing
    while true
        raw = _tls13_try_take_handshake_message!(state)
        raw === nothing && return nothing
        handshake_type = raw[1]
        if handshake_type == _HANDSHAKE_TYPE_NEW_SESSION_TICKET
            _tls_note_useless_record!(state, "tls: too many non-advancing TLS 1.3 records")
            _tls_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: NewSessionTicket handling requires TLS.Conn context")
        end
        if handshake_type == _TLS13_HANDSHAKE_TYPE_KEY_UPDATE
            request_update = _tls13_parse_key_update(raw)
            request_update === nothing && _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.3 key update message")
            _tls_note_useless_record!(state, "tls: too many non-advancing TLS 1.3 records")
            _tls13_handle_key_update!(tcp, state, request_update::Bool)
            continue
        end
        _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: unexpected post-handshake TLS 1.3 message")
    end
end

function _tls13_handle_post_handshake_messages!(conn, state::_TLS13NativeClientState)::Nothing
    while true
        raw = _tls13_try_take_handshake_message!(state)
        raw === nothing && return nothing
        handshake_type = raw[1]
        if handshake_type == _HANDSHAKE_TYPE_NEW_SESSION_TICKET
            conn.is_server && _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: unexpected post-handshake TLS 1.3 message")
            msg = _tls13_validate_new_session_ticket(raw)
            msg.lifetime == 0x00000000 && continue
            _tls_note_useless_record!(state, "tls: too many non-advancing TLS 1.3 records")
            _tls13_store_new_session_ticket!(conn, msg)
            continue
        end
        if handshake_type == _TLS13_HANDSHAKE_TYPE_KEY_UPDATE
            request_update = _tls13_parse_key_update(raw)
            request_update === nothing && _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.3 key update message")
            _tls_note_useless_record!(state, "tls: too many non-advancing TLS 1.3 records")
            _tls13_handle_key_update!(conn.tcp, state, request_update::Bool)
            continue
        end
        _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: unexpected post-handshake TLS 1.3 message")
    end
end

@inline function _remaining_handshake_messages(::_TLS13HandshakeRecordIO)::Int
    return 0
end

function _read_handshake_bytes!(io::_TLS13HandshakeRecordIO)::Vector{UInt8}
    while true
        raw = _tls13_try_take_handshake_message!(io.state)
        raw !== nothing && return raw
        io.state.peer_close_notify && throw(EOFError())
        _tls13_read_record!(io.tcp, io.state)
    end
end

function _write_handshake_bytes!(io::_TLS13HandshakeRecordIO, raw::Vector{UInt8})::Nothing
    raw_pos = 1
    raw_len = length(raw)
    while raw_pos <= raw_len
        raw_end = min(raw_pos + _TLS13_MAX_PLAINTEXT - 1, raw_len)
        _tls13_write_record!(io.tcp, io.state.write_cipher, _TLS_RECORD_TYPE_HANDSHAKE, @view(raw[raw_pos:raw_end]))
        raw_pos = raw_end + 1
    end
    return nothing
end

function _tls13_send_dummy_change_cipher_spec!(io::_TLS13HandshakeRecordIO)::Nothing
    io.state.sent_dummy_ccs && return nothing
    _tls_write_tls_plaintext!(io.tcp, _TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC, _TLS13_DUMMY_CHANGE_CIPHER_SPEC, TLS1_2_VERSION)
    io.state.sent_dummy_ccs = true
    return nothing
end

function _tls13_on_handshake_keys!(io::_TLS13HandshakeRecordIO, state::_TLS13ClientHandshakeState)::Nothing
    _tls13_set_read_cipher!(io.state, state.cipher_spec, state.server_handshake_traffic_secret)
    _tls13_set_write_cipher!(io.state, state.cipher_spec, state.client_handshake_traffic_secret)
    return nothing
end

function _tls13_on_server_finished!(io::_TLS13HandshakeRecordIO, state::_TLS13ClientHandshakeState)::Nothing
    _tls13_set_read_cipher!(io.state, state.cipher_spec, state.server_application_traffic_secret)
    return nothing
end

function _tls13_on_client_finished!(io::_TLS13HandshakeRecordIO, state::_TLS13ClientHandshakeState)::Nothing
    _tls13_set_write_cipher!(io.state, state.cipher_spec, state.client_application_traffic_secret)
    return nothing
end
