mutable struct _TLS12ServerHandshakeState
    client_hello::_ClientHelloMsg
    server_hello::_ServerHelloMsg
    certificate_chain::Vector{Vector{UInt8}}
    private_key::Ptr{Cvoid}
    ecdhe_private_key::Ptr{Cvoid}
    cipher_suite::UInt16
    curve_id::UInt16
    selected_signature_algorithm::UInt16
    selected_alpn::String
    send_downgrade_canary::Bool
end

function _TLS12ServerHandshakeState(config)::_TLS12ServerHandshakeState
    cert_file = config.cert_file === nothing ? throw(ArgumentError("tls12 native server requires cert_file")) : (config.cert_file::String)
    key_file = config.key_file === nothing ? throw(ArgumentError("tls12 native server requires key_file")) : (config.key_file::String)
    cert_pem = _read_tls_file_bytes(cert_file)
    key_pem = _read_tls_file_bytes(key_file)
    certificate_chain = _tls13_load_x509_pem_chain(cert_pem)
    private_key = _tls13_load_private_key_pem(key_pem)
    _securezero!(key_pem)
    if !occursin("RSA", _tls13_pkey_type_name(private_key))
        _free_evp_pkey!(private_key)
        throw(ArgumentError("tls: native TLS 1.2 server currently requires an RSA certificate"))
    end
    return _TLS12ServerHandshakeState(
        _ClientHelloMsg(),
        _ServerHelloMsg(),
        certificate_chain,
        private_key,
        C_NULL,
        UInt16(0),
        UInt16(0),
        UInt16(0),
        "",
        false,
    )
end

function _securezero_tls12_server_handshake_state!(state::_TLS12ServerHandshakeState)::Nothing
    for cert in state.certificate_chain
        _securezero!(cert)
    end
    state.private_key == C_NULL || _free_evp_pkey!(state.private_key)
    state.private_key = C_NULL
    state.ecdhe_private_key == C_NULL || _free_evp_pkey!(state.ecdhe_private_key)
    state.ecdhe_private_key = C_NULL
    return nothing
end

@inline function _native_tls12_server_enabled(config)::Bool
    return config.cert_file !== nothing &&
        config.key_file !== nothing &&
        _native_tls12_only(config) &&
        config.client_auth == ClientAuthMode.NoClientCert
end

function _tls12_select_server_cipher_suite(client_hello::_ClientHelloMsg)::UInt16
    for cipher_suite in (
            _TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256_ID,
            _TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384_ID,
        )
        in(cipher_suite, client_hello.cipher_suites) || continue
        return cipher_suite
    end
    _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: client did not offer a supported native TLS 1.2 cipher suite")
end

function _tls12_select_signature_algorithm(pkey::Ptr{Cvoid}, supported_signature_algorithms::AbstractVector{UInt16})::UInt16
    _tls13_pkey_type_name(pkey) == "RSA" ||
        throw(ArgumentError("tls: native TLS 1.2 server currently requires an RSA certificate"))
    for alg in (
            _TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
            _TLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
            _TLS_SIGNATURE_RSA_PSS_RSAE_SHA512,
            _TLS_SIGNATURE_RSA_PKCS1_SHA256,
            _TLS_SIGNATURE_RSA_PKCS1_SHA384,
            _TLS_SIGNATURE_RSA_PKCS1_SHA512,
        )
        in(alg, supported_signature_algorithms) && return alg
    end
    _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: client does not support a usable TLS 1.2 certificate signature algorithm")
end

@inline function _tls12_client_supports_uncompressed_points(client_hello::_ClientHelloMsg)::Bool
    isempty(client_hello.supported_points) && return true
    return in(UInt8(0x00), client_hello.supported_points)
end

function _tls12_set_client_hello!(state::_TLS12ServerHandshakeState, raw::Vector{UInt8})::Nothing
    client_hello = _unmarshal_client_hello(raw)
    client_hello === nothing && _tls13_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls12 server handshake expected ClientHello")
    versions = client_hello.supported_versions
    if isempty(versions)
        client_hello.vers == TLS1_2_VERSION ||
            _tls13_fail(_TLS_ALERT_PROTOCOL_VERSION, "tls: client did not offer TLS 1.2")
    else
        in(TLS1_2_VERSION, versions) || _tls13_fail(_TLS_ALERT_PROTOCOL_VERSION, "tls: client did not offer TLS 1.2")
    end
    in(_TLS_COMPRESSION_NONE, client_hello.compression_methods) ||
        _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: client does not support uncompressed TLS 1.2 connections")
    isempty(client_hello.secure_renegotiation) ||
        _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: initial TLS 1.2 handshake had non-empty renegotiation extension")
    client_hello.extended_master_secret ||
        _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: native TLS 1.2 server requires extended master secret")
    in(_TLS_GROUP_SECP256R1, client_hello.supported_curves) ||
        _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: client did not offer a supported native TLS 1.2 ECDHE curve")
    _tls12_client_supports_uncompressed_points(client_hello) ||
        _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: client did not offer uncompressed TLS 1.2 EC points")
    isempty(client_hello.supported_signature_algorithms) &&
        _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: client did not advertise TLS 1.2 signature algorithms")
    state.client_hello = client_hello
    return nothing
end

function _tls12_read_client_hello!(state::_TLS12ServerHandshakeState, io::_TLS12HandshakeRecordIO)::Vector{UInt8}
    raw = _read_handshake_bytes!(io)
    _tls12_set_client_hello!(state, raw)
    return raw
end

function _tls12_select_server_parameters!(state::_TLS12ServerHandshakeState, config)::Nothing
    state.cipher_suite = _tls12_select_server_cipher_suite(state.client_hello)
    state.curve_id = _TLS_GROUP_SECP256R1
    state.selected_signature_algorithm = _tls12_select_signature_algorithm(
        state.private_key,
        state.client_hello.supported_signature_algorithms,
    )
    state.selected_alpn = _tls_select_server_alpn(config, state.client_hello)
    return nothing
end

function _tls12_send_server_hello!(
    state::_TLS12ServerHandshakeState,
    io::_TLS12HandshakeRecordIO,
    transcript::_TLS12TranscriptState,
    raw_client_hello::Vector{UInt8},
)::Nothing
    rng = Random.RandomDevice()
    server_hello = _ServerHelloMsg()
    server_hello.vers = TLS1_2_VERSION
    if state.send_downgrade_canary
        server_hello.random = rand(rng, UInt8, 24)
        append!(server_hello.random, _TLS13_DOWNGRADE_CANARY_TLS12)
    else
        server_hello.random = rand(rng, UInt8, 32)
    end
    server_hello.session_id = UInt8[]
    server_hello.cipher_suite = state.cipher_suite
    server_hello.compression_method = _TLS_COMPRESSION_NONE
    server_hello.extended_master_secret = true
    server_hello.secure_renegotiation_supported = state.client_hello.secure_renegotiation_supported
    server_hello.server_name_ack = !isempty(state.client_hello.server_name)
    server_hello.alpn_protocol = state.selected_alpn
    if !isempty(state.client_hello.supported_points)
        server_hello.supported_points = UInt8[0x00]
    end
    state.server_hello = server_hello
    raw_server_hello = _marshal_server_hello(server_hello)
    _transcript_update!(transcript, raw_client_hello)
    _transcript_update!(transcript, raw_server_hello)
    _write_handshake_bytes!(io, raw_server_hello)
    return nothing
end

function _tls12_send_server_certificate!(
    state::_TLS12ServerHandshakeState,
    io::_TLS12HandshakeRecordIO,
    transcript::_TLS12TranscriptState,
)::Nothing
    msg = _CertificateMsgTLS12(state.certificate_chain)
    raw = _write_handshake_message(msg, transcript)
    _write_handshake_bytes!(io, raw)
    return nothing
end

function _tls12_server_key_exchange_params(state::_TLS12ServerHandshakeState)::Vector{UInt8}
    state.ecdhe_private_key == C_NULL || _free_evp_pkey!(state.ecdhe_private_key)
    state.ecdhe_private_key = _tls13_p256_generate_private_key()
    public_key = _tls13_p256_public_key(state.ecdhe_private_key)
    params = UInt8[0x03, UInt8(state.curve_id >> 8), UInt8(state.curve_id & 0xff), UInt8(length(public_key))]
    append!(params, public_key)
    _securezero!(public_key)
    return params
end

function _tls12_send_server_key_exchange!(
    state::_TLS12ServerHandshakeState,
    io::_TLS12HandshakeRecordIO,
    transcript::_TLS12TranscriptState,
)::Nothing
    params = UInt8[]
    signed = UInt8[]
    signature = UInt8[]
    try
        params = _tls12_server_key_exchange_params(state)
        sizehint!(signed, length(state.client_hello.random) + length(state.server_hello.random) + length(params))
        append!(signed, state.client_hello.random)
        append!(signed, state.server_hello.random)
        append!(signed, params)
        signature = _tls12_openssl_sign_signature(state.private_key, state.selected_signature_algorithm, signed)
        body = copy(params)
        _append_u16!(body, state.selected_signature_algorithm)
        _append_u16!(body, UInt16(length(signature)))
        append!(body, signature)
        raw = _write_handshake_message(_ServerKeyExchangeMsgTLS12(body), transcript)
        _write_handshake_bytes!(io, raw)
    finally
        _securezero!(params)
        _securezero!(signed)
        _securezero!(signature)
    end
    return nothing
end

function _tls12_send_server_hello_done!(io::_TLS12HandshakeRecordIO, transcript::_TLS12TranscriptState)::Nothing
    raw = _write_handshake_message(_ServerHelloDoneMsgTLS12(), transcript)
    _write_handshake_bytes!(io, raw)
    return nothing
end

function _tls12_read_client_key_exchange!(
    state::_TLS12ServerHandshakeState,
    io::_TLS12HandshakeRecordIO,
    transcript::_TLS12TranscriptState,
)::Vector{UInt8}
    raw = _read_handshake_bytes!(io)
    _tls12_require_handshake_message(raw, _HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE, "ClientKeyExchange")
    msg = _unmarshal_client_key_exchange_tls12(raw)
    msg === nothing && _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 ClientKeyExchange")
    ciphertext = (msg::_ClientKeyExchangeMsgTLS12).ciphertext
    isempty(ciphertext) && _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: empty TLS 1.2 ClientKeyExchange")
    Int(ciphertext[1]) == length(ciphertext) - 1 ||
        _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: malformed TLS 1.2 ClientKeyExchange")
    length(ciphertext) == 66 ||
        _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: malformed TLS 1.2 ClientKeyExchange")
    ciphertext[2] == 0x04 ||
        _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: malformed TLS 1.2 ClientKeyExchange")
    _transcript_update!(transcript, raw)
    return ciphertext
end

function _tls12_server_shared_secret(state::_TLS12ServerHandshakeState, client_key_exchange::AbstractVector{UInt8})::Vector{UInt8}
    state.curve_id == _TLS_GROUP_SECP256R1 ||
        _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: native TLS 1.2 server only supports P-256 ECDHE today")
    state.ecdhe_private_key == C_NULL && throw(ArgumentError("tls: missing TLS 1.2 server ECDHE private key"))
    return _tls13_p256_shared_secret(state.ecdhe_private_key, @view(client_key_exchange[2:end]))
end

function _tls12_read_client_finished!(
    io::_TLS12HandshakeRecordIO,
    transcript::_TLS12TranscriptState,
    master_secret::Vector{UInt8},
    hash_kind::_TLSHashKind,
    cipher_spec::_TLS12CipherSpec,
    client_key::AbstractVector{UInt8},
    client_iv::AbstractVector{UInt8},
)::Nothing
    expected_verify_data = UInt8[]
    io.state.allow_encrypted_handshake = true
    try
        _tls12_read_change_cipher_spec!(io)
        _tls12_set_read_cipher!(io.state, cipher_spec, client_key, client_iv)
        raw = _read_handshake_bytes!(io)
        _tls12_require_handshake_message(raw, _HANDSHAKE_TYPE_FINISHED, "Finished")
        msg = _unmarshal_finished(raw)
        msg === nothing && _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 Finished")
        expected_verify_data = _tls12_client_finished_verify_data(hash_kind, master_secret, transcript)
        _constant_time_equals((msg::_FinishedMsg).verify_data, expected_verify_data) ||
            _tls13_fail(_TLS_ALERT_DECRYPT_ERROR, "tls: invalid TLS 1.2 Finished verify_data")
        _transcript_update!(transcript, raw)
    finally
        io.state.allow_encrypted_handshake = false
        _securezero!(expected_verify_data)
    end
    return nothing
end

function _tls12_send_server_finished!(
    io::_TLS12HandshakeRecordIO,
    transcript::_TLS12TranscriptState,
    master_secret::Vector{UInt8},
    hash_kind::_TLSHashKind,
)::Nothing
    verify_data = _tls12_server_finished_verify_data(hash_kind, master_secret, transcript)
    try
        _tls13_write_tls_plaintext!(io.tcp, _TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC, _TLS12_CHANGE_CIPHER_SPEC_PAYLOAD, TLS1_2_VERSION)
        raw = _write_handshake_message(_FinishedMsg(verify_data), transcript)
        _tls12_write_record!(io.tcp, io.state.write_cipher, _TLS_RECORD_TYPE_HANDSHAKE, raw)
    finally
        _securezero!(verify_data)
    end
    return nothing
end

function _server_handshake_tls12_for_suite!(
    state::_TLS12ServerHandshakeState,
    io::_TLS12HandshakeRecordIO,
    raw_client_hello::Vector{UInt8},
    transcript::_TLS12TranscriptState,
    cipher_spec::_TLS12CipherSpec,
    hash_kind::_TLSHashKind,
)::Nothing
    shared_secret = UInt8[]
    master_secret = UInt8[]
    client_mac = UInt8[]
    server_mac = UInt8[]
    client_key = UInt8[]
    server_key = UInt8[]
    client_iv = UInt8[]
    server_iv = UInt8[]
    try
        _tls12_send_server_hello!(state, io, transcript, raw_client_hello)
        _tls12_send_server_certificate!(state, io, transcript)
        _tls12_send_server_key_exchange!(state, io, transcript)
        _tls12_send_server_hello_done!(io, transcript)
        client_key_exchange = _tls12_read_client_key_exchange!(state, io, transcript)
        shared_secret = _tls12_server_shared_secret(state, client_key_exchange)
        master_secret = _tls12_extended_master_from_pre_master_secret(
            hash_kind,
            shared_secret,
            _transcript_digest(transcript),
        )
        client_mac, server_mac, client_key, server_key, client_iv, server_iv =
            _tls12_keys_from_master_secret(
                hash_kind,
                master_secret,
                state.client_hello.random,
                state.server_hello.random,
                0,
                cipher_spec.key_length,
                cipher_spec.iv_length,
            )
        isempty(client_mac) || _tls13_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: unexpected TLS 1.2 MAC key material for AEAD cipher suite")
        isempty(server_mac) || _tls13_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: unexpected TLS 1.2 MAC key material for AEAD cipher suite")
        _tls12_set_write_cipher!(io.state, cipher_spec, server_key, server_iv)
        _tls12_read_client_finished!(io, transcript, master_secret, hash_kind, cipher_spec, client_key, client_iv)
        _tls12_send_server_finished!(io, transcript, master_secret, hash_kind)
    finally
        _securezero!(shared_secret)
        _securezero!(master_secret)
        _securezero!(client_mac)
        _securezero!(server_mac)
        _securezero!(client_key)
        _securezero!(server_key)
        _securezero!(client_iv)
        _securezero!(server_iv)
    end
    return nothing
end

function _server_handshake_tls12_after_client_hello!(
    state::_TLS12ServerHandshakeState,
    io::_TLS12HandshakeRecordIO,
    config,
    raw_client_hello::Vector{UInt8},
)::Nothing
    _tls12_select_server_parameters!(state, config)
    if state.cipher_suite == _TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256_ID
        transcript = _TranscriptHash(_HASH_SHA256)
        return _server_handshake_tls12_for_suite!(
            state,
            io,
            raw_client_hello,
            transcript,
            _TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            _HASH_SHA256,
        )
    elseif state.cipher_suite == _TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384_ID
        transcript = _TranscriptHash(_HASH_SHA384)
        return _server_handshake_tls12_for_suite!(
            state,
            io,
            raw_client_hello,
            transcript,
            _TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            _HASH_SHA384,
        )
    end
    _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: unsupported native TLS 1.2 cipher suite")
end

function _server_handshake_tls12!(state::_TLS12ServerHandshakeState, io::_TLS12HandshakeRecordIO, config)::Nothing
    raw_client_hello = _tls12_read_client_hello!(state, io)
    return _server_handshake_tls12_after_client_hello!(state, io, config, raw_client_hello)
end

function _native_tls12_server_handshake!(conn)::Nothing
    state = _TLS12ServerHandshakeState(conn.config)
    native_state = _native_tls12_state(conn)
    io = _TLS12HandshakeRecordIO(conn.tcp, native_state)
    try
        _server_handshake_tls12!(state, io, conn.config)
        native_state.did_resume = false
        native_state.curve_id = state.curve_id
        native_state.cipher_suite = state.cipher_suite
        _set_handshake_complete!(conn, "TLSv1.2", isempty(state.selected_alpn) ? nothing : state.selected_alpn)
    finally
        _securezero_tls12_server_handshake_state!(state)
    end
    return nothing
end
