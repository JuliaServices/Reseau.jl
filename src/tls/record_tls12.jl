const _TLS12_GCM_TAG_SIZE = 16
const _TLS12_MAX_PLAINTEXT = 16_384
const _TLS12_MAX_CIPHERTEXT = _TLS12_MAX_PLAINTEXT + 8 + _TLS12_GCM_TAG_SIZE + 256
const _TLS12_MAX_HANDSHAKE_BUFFER = _MAX_CERTIFICATE_HANDSHAKE_SIZE + _TLS12_MAX_PLAINTEXT
const _TLS12_CHANGE_CIPHER_SPEC_PAYLOAD = UInt8[0x01]

"""
    _TLS12RecordCipherState

Installed TLS 1.2 record protection state for one direction of a connection.

The state is directional because read and write keys evolve independently and
track separate sequence numbers.
"""
mutable struct _TLS12RecordCipherState
    spec::_TLS12CipherSpec
    key::Vector{UInt8}
    iv::Vector{UInt8}
    seq::UInt64
    exhausted::Bool
    aead::_OpenSSLAEADState
    nonce_buf::Vector{UInt8}
    additional_data_buf::Vector{UInt8}
    outbuf::Vector{UInt8}
end

function _TLS12RecordCipherState(
    spec::_TLS12CipherSpec,
    key::Vector{UInt8},
    iv::Vector{UInt8},
    seq::UInt64,
    exhausted::Bool,
)
    return _TLS12RecordCipherState(
        spec,
        key,
        iv,
        seq,
        exhausted,
        _OpenSSLAEADState(_tls12_record_cipher(spec), length(iv) + 8),
        Vector{UInt8}(undef, length(iv) + 8),
        Vector{UInt8}(undef, 13),
        UInt8[],
    )
end

"""
    _TLS12NativeState

Connection-owned TLS 1.2 record-layer state.

This is the long-lived state that `TLS.Conn` keeps after the handshake: current
read/write cipher state, buffered handshake/plaintext bytes, shutdown flags, and
the small amount of negotiated metadata exposed via `connection_state`.
"""
mutable struct _TLS12NativeState
    read_cipher::Union{Nothing, _TLS12RecordCipherState}
    write_cipher::Union{Nothing, _TLS12RecordCipherState}
    record_buffer::Vector{UInt8}
    handshake_buffer::Vector{UInt8}
    handshake_buffer_pos::Int
    plaintext_buffer::Vector{UInt8}
    plaintext_buffer_pos::Int
    useless_record_count::Int
    peer_close_notify::Bool
    sent_close_notify::Bool
    received_change_cipher_spec::Bool
    allow_encrypted_handshake::Bool
    did_resume::Bool
    curve_id::UInt16
    cipher_suite::UInt16
end

_TLS12NativeState() = _TLS12NativeState(
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
    false,
    false,
    UInt16(0),
    UInt16(0),
)

"""
    _TLS12HandshakeRecordIO

Thin adapter that exposes TLS 1.2 handshake read/write operations in terms of
the underlying TCP stream plus the connection's TLS 1.2 native record state.
"""
mutable struct _TLS12HandshakeRecordIO
    tcp::TCP.Conn
    state::_TLS12NativeState
end

function _securezero_tls12_record_cipher!(cipher::_TLS12RecordCipherState)::Nothing
    _securezero!(cipher.key)
    _securezero!(cipher.iv)
    _free_openssl_aead_state!(cipher.aead)
    _securezero!(cipher.nonce_buf)
    _securezero!(cipher.additional_data_buf)
    _securezero!(cipher.outbuf)
    empty!(cipher.outbuf)
    cipher.seq = UInt64(0)
    cipher.exhausted = false
    return nothing
end

function _securezero_tls12_native_state!(state::_TLS12NativeState)::Nothing
    if state.read_cipher !== nothing
        _securezero_tls12_record_cipher!(state.read_cipher::_TLS12RecordCipherState)
        state.read_cipher = nothing
    end
    if state.write_cipher !== nothing
        _securezero_tls12_record_cipher!(state.write_cipher::_TLS12RecordCipherState)
        state.write_cipher = nothing
    end
    _securezero!(state.record_buffer)
    _securezero!(state.handshake_buffer)
    _securezero!(state.plaintext_buffer)
    empty!(state.record_buffer)
    empty!(state.handshake_buffer)
    empty!(state.plaintext_buffer)
    state.handshake_buffer_pos = 1
    state.plaintext_buffer_pos = 1
    state.useless_record_count = 0
    state.peer_close_notify = false
    state.sent_close_notify = false
    state.received_change_cipher_spec = false
    state.allow_encrypted_handshake = false
    state.did_resume = false
    state.curve_id = UInt16(0)
    state.cipher_suite = UInt16(0)
    return nothing
end

function _tls12_set_read_cipher!(state::_TLS12NativeState, spec::_TLS12CipherSpec, key::AbstractVector{UInt8}, iv::AbstractVector{UInt8})::Nothing
    if state.read_cipher !== nothing
        _securezero_tls12_record_cipher!(state.read_cipher::_TLS12RecordCipherState)
    end
    state.read_cipher = _TLS12RecordCipherState(spec, Vector{UInt8}(key), Vector{UInt8}(iv), UInt64(0), false)
    return nothing
end

function _tls12_set_write_cipher!(state::_TLS12NativeState, spec::_TLS12CipherSpec, key::AbstractVector{UInt8}, iv::AbstractVector{UInt8})::Nothing
    if state.write_cipher !== nothing
        _securezero_tls12_record_cipher!(state.write_cipher::_TLS12RecordCipherState)
    end
    state.write_cipher = _TLS12RecordCipherState(spec, Vector{UInt8}(key), Vector{UInt8}(iv), UInt64(0), false)
    return nothing
end

@inline function _tls12_fill_explicit_nonce!(dest::AbstractVector{UInt8}, seq::UInt64)::Nothing
    @inbounds begin
        dest[1] = UInt8((seq >> 56) & 0xff)
        dest[2] = UInt8((seq >> 48) & 0xff)
        dest[3] = UInt8((seq >> 40) & 0xff)
        dest[4] = UInt8((seq >> 32) & 0xff)
        dest[5] = UInt8((seq >> 24) & 0xff)
        dest[6] = UInt8((seq >> 16) & 0xff)
        dest[7] = UInt8((seq >> 8) & 0xff)
        dest[8] = UInt8(seq & 0xff)
    end
    return nothing
end

function _tls12_fill_record_additional_data!(
    dest::AbstractVector{UInt8},
    seq::UInt64,
    content_type::UInt8,
    plaintext_len::Int,
)::Nothing
    plaintext_len >= 0 || throw(ArgumentError("tls12 plaintext length must be >= 0"))
    plaintext_len <= 0xffff || throw(ArgumentError("tls12 plaintext length too large"))
    @inbounds begin
        dest[1] = UInt8((seq >> 56) & 0xff)
        dest[2] = UInt8((seq >> 48) & 0xff)
        dest[3] = UInt8((seq >> 40) & 0xff)
        dest[4] = UInt8((seq >> 32) & 0xff)
        dest[5] = UInt8((seq >> 24) & 0xff)
        dest[6] = UInt8((seq >> 16) & 0xff)
        dest[7] = UInt8((seq >> 8) & 0xff)
        dest[8] = UInt8(seq & 0xff)
        dest[9] = content_type
        dest[10] = UInt8(TLS1_2_VERSION >> 8)
        dest[11] = UInt8(TLS1_2_VERSION & 0xff)
        dest[12] = UInt8(plaintext_len >> 8)
        dest[13] = UInt8(plaintext_len & 0xff)
    end
    return nothing
end

function _tls12_record_additional_data(seq::UInt64, content_type::UInt8, plaintext_len::Int)::Vector{UInt8}
    additional_data = Vector{UInt8}(undef, 13)
    _tls12_fill_record_additional_data!(additional_data, seq, content_type, plaintext_len)
    return additional_data
end

@inline function _tls12_take_received_change_cipher_spec!(state::_TLS12NativeState)::Bool
    seen = state.received_change_cipher_spec
    state.received_change_cipher_spec = false
    return seen
end

# TLS 1.2 record writes emit plaintext until ChangeCipherSpec installs the AEAD
# state, then switch to explicit-nonce AES-GCM framing. Sequence exhaustion is
# treated as a hard protocol error and permanently disables further writes.
function _tls12_write_record!(
    tcp::TCP.Conn,
    cipher::Union{Nothing, _TLS12RecordCipherState},
    content_type::UInt8,
    payload_ptr::Ptr{UInt8},
    payload_len::Int,
)::Nothing
    payload_len <= _TLS12_MAX_PLAINTEXT || throw(ArgumentError("tls: TLS 1.2 record plaintext exceeds the maximum record size"))
    if cipher === nothing
        payload = unsafe_wrap(Vector{UInt8}, payload_ptr, payload_len; own = false)
        _tls_write_tls_plaintext!(tcp, content_type, payload, TLS1_2_VERSION)
        return nothing
    end
    cipher_state = cipher::_TLS12RecordCipherState
    cipher_state.exhausted && throw(ArgumentError("tls: TLS 1.2 write keys exhausted"))
    record_payload_len = 8 + payload_len + _TLS12_GCM_TAG_SIZE
    total_record_len = 5 + record_payload_len
    resize!(cipher_state.outbuf, total_record_len)
    outbuf = cipher_state.outbuf
    explicit_nonce = @view(outbuf[6:13])
    ciphertext_pos = 14
    try
        @inbounds begin
            outbuf[1] = content_type
            outbuf[2] = UInt8(TLS1_2_VERSION >> 8)
            outbuf[3] = UInt8(TLS1_2_VERSION & 0xff)
            outbuf[4] = UInt8(record_payload_len >> 8)
            outbuf[5] = UInt8(record_payload_len & 0xff)
        end
        _tls12_fill_explicit_nonce!(explicit_nonce, cipher_state.seq)
        copyto!(cipher_state.nonce_buf, 1, cipher_state.iv, 1, length(cipher_state.iv))
        copyto!(cipher_state.nonce_buf, length(cipher_state.iv) + 1, explicit_nonce, 1, 8)
        _tls12_fill_record_additional_data!(cipher_state.additional_data_buf, cipher_state.seq, content_type, payload_len)
        if payload_len != 0
            GC.@preserve outbuf begin
                unsafe_copyto!(pointer(outbuf, ciphertext_pos), payload_ptr, payload_len)
            end
        end
        additional_data_buf = cipher_state.additional_data_buf
        ciphertext_len = GC.@preserve additional_data_buf _tls12_encrypt_record_aead!(
            cipher_state.aead,
            outbuf,
            ciphertext_pos,
            payload_len,
            cipher_state.key,
            cipher_state.nonce_buf,
            isempty(additional_data_buf) ? Ptr{UInt8}(C_NULL) : pointer(additional_data_buf),
            length(additional_data_buf),
        )
        ciphertext_len == payload_len + _TLS12_GCM_TAG_SIZE ||
            throw(ArgumentError("tls: TLS 1.2 AEAD produced an unexpected ciphertext length"))
        write(tcp, outbuf)
        if cipher_state.seq == typemax(UInt64)
            cipher_state.exhausted = true
        else
            cipher_state.seq += UInt64(1)
        end
    finally
        _securezero!(cipher_state.nonce_buf)
        _securezero!(cipher_state.additional_data_buf)
    end
    return nothing
end

function _tls12_write_record!(
    tcp::TCP.Conn,
    cipher::Union{Nothing, _TLS12RecordCipherState},
    content_type::UInt8,
    payload::AbstractVector{UInt8},
)::Nothing
    GC.@preserve payload begin
        return _tls12_write_record!(tcp, cipher, content_type, pointer(payload), length(payload))
    end
end

function _tls12_process_alert!(state::_TLS12NativeState, alert::AbstractVector{UInt8})::Nothing
    length(alert) == 2 || _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 alert")
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
        throw(_tls_peer_alert_error(alert_desc, "tls: received $level_name TLS 1.2 alert $(Int(alert_desc))"))
    end
    state.peer_close_notify = true
    return nothing
end

# Record reads are responsible for four protocol-level jobs:
# 1. parse and size-check the wire record,
# 2. decrypt/authenticate if keys are installed,
# 3. route alerts/plaintext/handshake bytes into the right buffers,
# 4. enforce TLS 1.2 invariants like ChangeCipherSpec ordering.
function _tls12_read_record!(tcp::TCP.Conn, state::_TLS12NativeState)::Nothing
    payload_len = _tls_read_wire_record!(tcp, state.record_buffer, _TLS12_MAX_CIPHERTEXT)
    record = state.record_buffer
    content_type = record[1]
    payload_start = 6
    payload_end = 5 + payload_len
    payload = @view(record[payload_start:payload_end])
    if content_type == _TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC
        payload_len == 1 && payload[1] == 0x01 || _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 ChangeCipherSpec record")
        state.read_cipher === nothing || _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received unexpected post-handshake TLS 1.2 ChangeCipherSpec")
        state.received_change_cipher_spec && _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received duplicate TLS 1.2 ChangeCipherSpec")
        state.received_change_cipher_spec = true
        _tls_reset_useless_record_count!(state)
        return nothing
    end
    if state.read_cipher === nothing
        if content_type == _TLS_RECORD_TYPE_HANDSHAKE
            if payload_len != 0
                append!(state.handshake_buffer, payload)
                length(state.handshake_buffer) <= _TLS12_MAX_HANDSHAKE_BUFFER ||
                    _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: received too much buffered TLS 1.2 handshake data")
                _tls_reset_useless_record_count!(state)
            end
            return nothing
        end
        if content_type == _TLS_RECORD_TYPE_ALERT
            _tls12_process_alert!(state, payload)
            return nothing
        end
        if content_type == _TLS_RECORD_TYPE_APPLICATION_DATA
            _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received unexpected plaintext TLS 1.2 application data before ChangeCipherSpec")
        end
        _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received unexpected plaintext TLS 1.2 record type $(Int(content_type))")
    end
    cipher = state.read_cipher::_TLS12RecordCipherState
    cipher.exhausted && _tls_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: TLS 1.2 read keys exhausted")
    payload_len >= cipher.spec.explicit_nonce_length + _TLS12_GCM_TAG_SIZE ||
        _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 AEAD record")
    explicit_nonce_len = cipher.spec.explicit_nonce_length
    plaintext_len = payload_len - explicit_nonce_len - _TLS12_GCM_TAG_SIZE
    ciphertext_pos = payload_start + explicit_nonce_len
    ciphertext_len = payload_len - explicit_nonce_len - _TLS12_GCM_TAG_SIZE
    copyto!(cipher.nonce_buf, 1, cipher.iv, 1, length(cipher.iv))
    copyto!(cipher.nonce_buf, length(cipher.iv) + 1, record, payload_start, explicit_nonce_len)
    _tls12_fill_record_additional_data!(cipher.additional_data_buf, cipher.seq, content_type, plaintext_len)
    try
        additional_data_buf = cipher.additional_data_buf
        plaintext_len_or_nothing = GC.@preserve additional_data_buf _tls12_decrypt_record_aead!(
            cipher.aead,
            record,
            ciphertext_pos,
            ciphertext_len,
            ciphertext_pos + ciphertext_len,
            cipher.key,
            cipher.nonce_buf,
            pointer(additional_data_buf),
            length(additional_data_buf),
        )
        plaintext_len_or_nothing === nothing && _tls_fail(_TLS_ALERT_BAD_RECORD_MAC, "tls: invalid TLS 1.2 record authentication tag")
        plaintext_len = plaintext_len_or_nothing::Int
        plaintext = @view(record[ciphertext_pos:ciphertext_pos + plaintext_len - 1])
        if content_type == _TLS_RECORD_TYPE_HANDSHAKE
            state.allow_encrypted_handshake ||
                _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received unexpected post-handshake TLS 1.2 handshake message")
            append!(state.handshake_buffer, plaintext)
            length(state.handshake_buffer) <= _TLS12_MAX_HANDSHAKE_BUFFER ||
                _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: received too much buffered TLS 1.2 handshake data")
            !isempty(plaintext) && _tls_reset_useless_record_count!(state)
        elseif content_type == _TLS_RECORD_TYPE_APPLICATION_DATA
            if isempty(plaintext)
                _tls_note_useless_record!(state, "tls: too many ignored TLS records")
            else
                append!(state.plaintext_buffer, plaintext)
                _tls_reset_useless_record_count!(state)
            end
        elseif content_type == _TLS_RECORD_TYPE_ALERT
            _tls12_process_alert!(state, plaintext)
        else
            _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received unexpected encrypted TLS 1.2 record type $(Int(content_type))")
        end
    finally
        _securezero!(cipher.nonce_buf)
        _securezero!(cipher.additional_data_buf)
    end
    if cipher.seq == typemax(UInt64)
        cipher.exhausted = true
    else
        cipher.seq += UInt64(1)
    end
    return nothing
end

function _tls12_try_take_handshake_message!(state::_TLS12NativeState)::Union{Nothing, Vector{UInt8}}
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
        _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: received oversized TLS 1.2 handshake message")
    available >= msg_len || return nothing
    raw = Vector{UInt8}(undef, msg_len)
    copyto!(raw, 1, state.handshake_buffer, pos, msg_len)
    state.handshake_buffer_pos += msg_len
    state.handshake_buffer_pos = _tls_compact_buffer!(state.handshake_buffer, state.handshake_buffer_pos)
    return raw
end

@inline function _remaining_handshake_messages(::_TLS12HandshakeRecordIO)::Int
    return 0
end

@inline function _tls12_require_handshake_message(raw::Vector{UInt8}, expected::UInt8, label::AbstractString)::Nothing
    raw[1] == expected || _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: expected TLS 1.2 $(label)")
    return nothing
end

function _read_handshake_bytes!(io::_TLS12HandshakeRecordIO)::Vector{UInt8}
    while true
        raw = _tls12_try_take_handshake_message!(io.state)
        raw !== nothing && return raw
        io.state.peer_close_notify && throw(EOFError())
        _tls12_read_record!(io.tcp, io.state)
    end
end

function _write_handshake_bytes!(io::_TLS12HandshakeRecordIO, raw::Vector{UInt8})::Nothing
    raw_pos = 1
    raw_len = length(raw)
    while raw_pos <= raw_len
        raw_end = min(raw_pos + _TLS12_MAX_PLAINTEXT - 1, raw_len)
        _tls12_write_record!(io.tcp, io.state.write_cipher, _TLS_RECORD_TYPE_HANDSHAKE, @view(raw[raw_pos:raw_end]))
        raw_pos = raw_end + 1
    end
    return nothing
end
