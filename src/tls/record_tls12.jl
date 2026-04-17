const _TLS12_GCM_TAG_SIZE = 16
const _TLS12_MAX_PLAINTEXT = 16_384
const _TLS12_MAX_CIPHERTEXT = _TLS12_MAX_PLAINTEXT + 8 + _TLS12_GCM_TAG_SIZE + 256
const _TLS12_MAX_HANDSHAKE_BUFFER = _MAX_HANDSHAKE_SIZE + _TLS12_MAX_PLAINTEXT
const _TLS12_CHANGE_CIPHER_SPEC_PAYLOAD = UInt8[0x01]

mutable struct _TLS12RecordCipherState
    spec::_TLS12CipherSpec
    key::Vector{UInt8}
    iv::Vector{UInt8}
    seq::UInt64
    exhausted::Bool
end

mutable struct _TLS12NativeClientState
    read_cipher::Union{Nothing, _TLS12RecordCipherState}
    write_cipher::Union{Nothing, _TLS12RecordCipherState}
    handshake_buffer::Vector{UInt8}
    handshake_buffer_pos::Int
    plaintext_buffer::Vector{UInt8}
    plaintext_buffer_pos::Int
    peer_close_notify::Bool
    sent_close_notify::Bool
    received_change_cipher_spec::Bool
    allow_encrypted_handshake::Bool
    did_resume::Bool
    curve_id::UInt16
    cipher_suite::UInt16
end

_TLS12NativeClientState() = _TLS12NativeClientState(
    nothing,
    nothing,
    UInt8[],
    1,
    UInt8[],
    1,
    false,
    false,
    false,
    false,
    false,
    UInt16(0),
    UInt16(0),
)

mutable struct _TLS12HandshakeRecordIO
    tcp::TCP.Conn
    state::_TLS12NativeClientState
end

function _securezero_tls12_record_cipher!(cipher::_TLS12RecordCipherState)::Nothing
    _securezero!(cipher.key)
    _securezero!(cipher.iv)
    cipher.seq = UInt64(0)
    cipher.exhausted = false
    return nothing
end

function _securezero_tls12_native_client_state!(state::_TLS12NativeClientState)::Nothing
    if state.read_cipher !== nothing
        _securezero_tls12_record_cipher!(state.read_cipher::_TLS12RecordCipherState)
        state.read_cipher = nothing
    end
    if state.write_cipher !== nothing
        _securezero_tls12_record_cipher!(state.write_cipher::_TLS12RecordCipherState)
        state.write_cipher = nothing
    end
    _securezero!(state.handshake_buffer)
    _securezero!(state.plaintext_buffer)
    empty!(state.handshake_buffer)
    empty!(state.plaintext_buffer)
    state.handshake_buffer_pos = 1
    state.plaintext_buffer_pos = 1
    state.peer_close_notify = false
    state.sent_close_notify = false
    state.received_change_cipher_spec = false
    state.allow_encrypted_handshake = false
    state.did_resume = false
    state.curve_id = UInt16(0)
    state.cipher_suite = UInt16(0)
    return nothing
end

function _tls12_set_read_cipher!(state::_TLS12NativeClientState, spec::_TLS12CipherSpec, key::AbstractVector{UInt8}, iv::AbstractVector{UInt8})::Nothing
    if state.read_cipher !== nothing
        _securezero_tls12_record_cipher!(state.read_cipher::_TLS12RecordCipherState)
    end
    state.read_cipher = _TLS12RecordCipherState(spec, Vector{UInt8}(key), Vector{UInt8}(iv), UInt64(0), false)
    return nothing
end

function _tls12_set_write_cipher!(state::_TLS12NativeClientState, spec::_TLS12CipherSpec, key::AbstractVector{UInt8}, iv::AbstractVector{UInt8})::Nothing
    if state.write_cipher !== nothing
        _securezero_tls12_record_cipher!(state.write_cipher::_TLS12RecordCipherState)
    end
    state.write_cipher = _TLS12RecordCipherState(spec, Vector{UInt8}(key), Vector{UInt8}(iv), UInt64(0), false)
    return nothing
end

function _tls12_seq_bytes(seq::UInt64)::NTuple{8, UInt8}
    return (
        UInt8((seq >> 56) & 0xff),
        UInt8((seq >> 48) & 0xff),
        UInt8((seq >> 40) & 0xff),
        UInt8((seq >> 32) & 0xff),
        UInt8((seq >> 24) & 0xff),
        UInt8((seq >> 16) & 0xff),
        UInt8((seq >> 8) & 0xff),
        UInt8(seq & 0xff),
    )
end

function _tls12_explicit_nonce(seq::UInt64)::Vector{UInt8}
    bytes = _tls12_seq_bytes(seq)
    return UInt8[bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8]]
end

function _tls12_record_additional_data(seq::UInt64, content_type::UInt8, plaintext_len::Int)::Vector{UInt8}
    plaintext_len >= 0 || throw(ArgumentError("tls12 plaintext length must be >= 0"))
    plaintext_len <= 0xffff || throw(ArgumentError("tls12 plaintext length too large"))
    seq_bytes = _tls12_seq_bytes(seq)
    return UInt8[
        seq_bytes[1], seq_bytes[2], seq_bytes[3], seq_bytes[4],
        seq_bytes[5], seq_bytes[6], seq_bytes[7], seq_bytes[8],
        content_type,
        UInt8(TLS1_2_VERSION >> 8),
        UInt8(TLS1_2_VERSION & 0xff),
        UInt8(plaintext_len >> 8),
        UInt8(plaintext_len & 0xff),
    ]
end

@inline function _tls12_take_received_change_cipher_spec!(state::_TLS12NativeClientState)::Bool
    seen = state.received_change_cipher_spec
    state.received_change_cipher_spec = false
    return seen
end

function _tls12_write_record!(tcp::TCP.Conn, cipher::Union{Nothing, _TLS12RecordCipherState}, content_type::UInt8, payload::AbstractVector{UInt8})::Nothing
    length(payload) <= _TLS12_MAX_PLAINTEXT || throw(ArgumentError("tls: TLS 1.2 record plaintext exceeds the maximum record size"))
    if cipher === nothing
        _tls13_write_tls_plaintext!(tcp, content_type, payload, TLS1_2_VERSION)
        return nothing
    end
    cipher_state = cipher::_TLS12RecordCipherState
    cipher_state.exhausted && throw(ArgumentError("tls: TLS 1.2 write keys exhausted"))
    explicit_nonce = _tls12_explicit_nonce(cipher_state.seq)
    nonce = UInt8[]
    aad = UInt8[]
    ciphertext = UInt8[]
    header = UInt8[]
    try
        nonce = Vector{UInt8}(undef, length(cipher_state.iv) + length(explicit_nonce))
        copyto!(nonce, 1, cipher_state.iv, 1, length(cipher_state.iv))
        copyto!(nonce, length(cipher_state.iv) + 1, explicit_nonce, 1, length(explicit_nonce))
        aad = _tls12_record_additional_data(cipher_state.seq, content_type, length(payload))
        ciphertext = _tls12_encrypt_record_aead(cipher_state.spec, cipher_state.key, nonce, aad, payload)
        record_payload_len = length(explicit_nonce) + length(ciphertext)
        header = UInt8[
            content_type,
            UInt8(TLS1_2_VERSION >> 8),
            UInt8(TLS1_2_VERSION & 0xff),
            UInt8(record_payload_len >> 8),
            UInt8(record_payload_len & 0xff),
        ]
        write(tcp, header)
        write(tcp, explicit_nonce)
        write(tcp, ciphertext)
        if cipher_state.seq == typemax(UInt64)
            cipher_state.exhausted = true
        else
            cipher_state.seq += UInt64(1)
        end
    finally
        _securezero!(explicit_nonce)
        _securezero!(nonce)
        _securezero!(aad)
        _securezero!(ciphertext)
        _securezero!(header)
    end
    return nothing
end

function _tls12_process_alert!(state::_TLS12NativeClientState, alert::AbstractVector{UInt8})::Nothing
    length(alert) == 2 || _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 alert")
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
        throw(_tls13_peer_alert_error(alert_desc, "tls: received $level_name TLS 1.2 alert $(Int(alert_desc))"))
    end
    state.peer_close_notify = true
    return nothing
end

function _tls12_read_record!(tcp::TCP.Conn, state::_TLS12NativeClientState)::Nothing
    header = Vector{UInt8}(undef, 5)
    read!(tcp, header)
    payload_len = (Int(header[4]) << 8) | Int(header[5])
    payload_len <= _TLS12_MAX_CIPHERTEXT || _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: received oversized TLS 1.2 record")
    payload = Vector{UInt8}(undef, payload_len)
    try
        payload_len == 0 || read!(tcp, payload)
        content_type = header[1]
        if content_type == _TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC
            payload_len == 1 && payload[1] == 0x01 || _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 ChangeCipherSpec record")
            state.read_cipher === nothing || _tls13_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received unexpected post-handshake TLS 1.2 ChangeCipherSpec")
            state.received_change_cipher_spec && _tls13_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received duplicate TLS 1.2 ChangeCipherSpec")
            state.received_change_cipher_spec = true
            return nothing
        end
        if state.read_cipher === nothing
            if content_type == _TLS_RECORD_TYPE_HANDSHAKE
                if payload_len != 0
                    append!(state.handshake_buffer, payload)
                    length(state.handshake_buffer) <= _TLS12_MAX_HANDSHAKE_BUFFER ||
                        _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: received too much buffered TLS 1.2 handshake data")
                end
                return nothing
            end
            if content_type == _TLS_RECORD_TYPE_ALERT
                _tls12_process_alert!(state, payload)
                return nothing
            end
            if content_type == _TLS_RECORD_TYPE_APPLICATION_DATA
                _tls13_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received unexpected plaintext TLS 1.2 application data before ChangeCipherSpec")
            end
            _tls13_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received unexpected plaintext TLS 1.2 record type $(Int(content_type))")
        end
        cipher = state.read_cipher::_TLS12RecordCipherState
        cipher.exhausted && _tls13_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: TLS 1.2 read keys exhausted")
        payload_len >= cipher.spec.explicit_nonce_length + _TLS12_GCM_TAG_SIZE ||
            _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 AEAD record")
        explicit_nonce_len = cipher.spec.explicit_nonce_length
        plaintext_len = payload_len - explicit_nonce_len - _TLS12_GCM_TAG_SIZE
        explicit_nonce = Vector{UInt8}(undef, explicit_nonce_len)
        copyto!(explicit_nonce, 1, payload, 1, explicit_nonce_len)
        nonce = UInt8[]
        aad = UInt8[]
        ciphertext = UInt8[]
        plaintext = nothing
        try
            nonce = Vector{UInt8}(undef, length(cipher.iv) + length(explicit_nonce))
            copyto!(nonce, 1, cipher.iv, 1, length(cipher.iv))
            copyto!(nonce, length(cipher.iv) + 1, explicit_nonce, 1, length(explicit_nonce))
            aad = _tls12_record_additional_data(cipher.seq, content_type, plaintext_len)
            ciphertext = Vector{UInt8}(undef, payload_len - explicit_nonce_len)
            copyto!(ciphertext, 1, payload, explicit_nonce_len + 1, length(ciphertext))
            plaintext = _tls12_decrypt_record_aead(cipher.spec, cipher.key, nonce, aad, ciphertext)
            plaintext === nothing && _tls13_fail(_TLS_ALERT_BAD_RECORD_MAC, "tls: invalid TLS 1.2 record authentication tag")
            if content_type == _TLS_RECORD_TYPE_HANDSHAKE
                state.allow_encrypted_handshake ||
                    _tls13_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received unexpected post-handshake TLS 1.2 handshake message")
                append!(state.handshake_buffer, plaintext::Vector{UInt8})
                length(state.handshake_buffer) <= _TLS12_MAX_HANDSHAKE_BUFFER ||
                    _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: received too much buffered TLS 1.2 handshake data")
            elseif content_type == _TLS_RECORD_TYPE_APPLICATION_DATA
                append!(state.plaintext_buffer, plaintext::Vector{UInt8})
            elseif content_type == _TLS_RECORD_TYPE_ALERT
                _tls12_process_alert!(state, plaintext::Vector{UInt8})
            else
                _tls13_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received unexpected encrypted TLS 1.2 record type $(Int(content_type))")
            end
        finally
            _securezero!(explicit_nonce)
            _securezero!(nonce)
            _securezero!(aad)
            _securezero!(ciphertext)
            plaintext isa Vector{UInt8} && _securezero!(plaintext::Vector{UInt8})
        end
        if cipher.seq == typemax(UInt64)
            cipher.exhausted = true
        else
            cipher.seq += UInt64(1)
        end
    finally
        _securezero!(header)
        _securezero!(payload)
    end
    return nothing
end

function _tls12_try_take_handshake_message!(state::_TLS12NativeClientState)::Union{Nothing, Vector{UInt8}}
    available = _tls13_buffer_available(state.handshake_buffer, state.handshake_buffer_pos)
    available == 0 && return nothing
    available >= 4 || return nothing
    pos = state.handshake_buffer_pos
    msg_len = 4 +
        (Int(state.handshake_buffer[pos + 1]) << 16) +
        (Int(state.handshake_buffer[pos + 2]) << 8) +
        Int(state.handshake_buffer[pos + 3])
    msg_len <= _MAX_HANDSHAKE_SIZE || _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: received oversized TLS 1.2 handshake message")
    available >= msg_len || return nothing
    raw = Vector{UInt8}(undef, msg_len)
    copyto!(raw, 1, state.handshake_buffer, pos, msg_len)
    state.handshake_buffer_pos += msg_len
    state.handshake_buffer_pos = _tls13_compact_buffer!(state.handshake_buffer, state.handshake_buffer_pos)
    return raw
end

@inline function _remaining_handshake_messages(::_TLS12HandshakeRecordIO)::Int
    return 0
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
