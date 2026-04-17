const _TLS12_SUPPORTED_SIGNATURE_ALGORITHMS = UInt16[
    _TLS_SIGNATURE_RSA_PKCS1_SHA256,
    _TLS_SIGNATURE_RSA_PKCS1_SHA384,
    _TLS_SIGNATURE_RSA_PKCS1_SHA512,
    _TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
    _TLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
    _TLS_SIGNATURE_RSA_PSS_RSAE_SHA512,
    _TLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
    _TLS_SIGNATURE_ECDSA_SECP384R1_SHA384,
    _TLS_SIGNATURE_ECDSA_SECP521R1_SHA512,
]

const _TLS12TranscriptState = Union{
    _TranscriptHash{SHA.SHA2_256_CTX},
    _TranscriptHash{SHA.SHA2_384_CTX},
}

mutable struct _TLS12ClientHandshakeState
    client_hello::_ClientHelloMsg
    server_hello::_ServerHelloMsg
    server_certificate::_CertificateMsgTLS12
    server_key_exchange::_ServerKeyExchangeMsgTLS12
    cipher_suite::UInt16
    client_protocol::String
    curve_id::UInt16
end

function _TLS12ClientHandshakeState(client_hello::_ClientHelloMsg)
    return _TLS12ClientHandshakeState(
        client_hello,
        _ServerHelloMsg(),
        _CertificateMsgTLS12(),
        _ServerKeyExchangeMsgTLS12(),
        UInt16(0),
        "",
        UInt16(0),
    )
end

function _tls12_client_hello(config)::_ClientHelloMsg
    rng = Random.RandomDevice()
    hello = _ClientHelloMsg()
    hello.vers = TLS1_2_VERSION
    hello.random = rand(rng, UInt8, 32)
    hello.session_id = rand(rng, UInt8, 32)
    hello.cipher_suites = UInt16[
        _TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256_ID,
        _TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384_ID,
    ]
    hello.compression_methods = UInt8[_TLS_COMPRESSION_NONE]
    hello.server_name = config.server_name === nothing ? "" : String(config.server_name)
    hello.ocsp_stapling = false
    hello.ticket_supported = false
    hello.alpn_protocols = copy(config.alpn_protocols)
    hello.supported_curves = UInt16[_TLS_GROUP_SECP256R1]
    hello.supported_points = UInt8[0x00]
    hello.supported_signature_algorithms = copy(_TLS12_SUPPORTED_SIGNATURE_ALGORITHMS)
    hello.supported_signature_algorithms_cert = copy(_TLS12_SUPPORTED_SIGNATURE_ALGORITHMS)
    hello.secure_renegotiation_supported = false
    hello.extended_master_secret = true
    hello.scts = true
    return hello
end

function _tls12_select_cipher_spec!(state::_TLS12ClientHandshakeState)::Nothing
    server_hello = state.server_hello
    server_hello.vers == TLS1_2_VERSION || _tls13_fail(_TLS_ALERT_PROTOCOL_VERSION, "tls: server negotiated an unexpected TLS version")
    server_hello.compression_method == _TLS_COMPRESSION_NONE ||
        _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server selected unsupported TLS 1.2 compression")
    server_hello.supported_version == UInt16(0) ||
        _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: TLS 1.2 ServerHello must not include supported_versions")
    server_hello.server_share === nothing ||
        _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: TLS 1.2 ServerHello must not include key_share")
    server_hello.selected_identity_present &&
        _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: TLS 1.2 ServerHello must not include selected PSK identity")
    in(server_hello.cipher_suite, state.client_hello.cipher_suites) ||
        _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: server selected an unconfigured TLS 1.2 cipher suite")
    _tls12_cipher_spec(server_hello.cipher_suite) === nothing &&
        _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: server selected an unsupported native TLS 1.2 cipher suite")
    server_hello.extended_master_secret ||
        _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: native TLS 1.2 client requires extended master secret")
    if !isempty(server_hello.alpn_protocol)
        in(server_hello.alpn_protocol, state.client_hello.alpn_protocols) ||
            _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server selected an unexpected ALPN protocol")
        state.client_protocol = server_hello.alpn_protocol
    end
    state.cipher_suite = server_hello.cipher_suite
    return nothing
end

function _tls12_parse_server_key_exchange(msg::_ServerKeyExchangeMsgTLS12)
    reader = _HandshakeReader(msg.key)
    curve_type = _read_u8!(reader)
    group = _read_u16!(reader)
    public_key = _read_u8_length_prefixed_bytes!(reader)
    signature_algorithm = _read_u16!(reader)
    signature = _read_u16_length_prefixed_bytes!(reader)
    (curve_type === nothing || group === nothing || public_key === nothing || signature_algorithm === nothing || signature === nothing || !_reader_empty(reader)) &&
        _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 ServerKeyExchange")
    curve_type == 0x03 || _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: TLS 1.2 server selected an unsupported ECDHE curve type")
    isempty(public_key) && _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: TLS 1.2 server key share is empty")
    params_len = 4 + length(public_key)
    params = Vector{UInt8}(undef, params_len)
    copyto!(params, 1, msg.key, 1, params_len)
    return (
        group = group::UInt16,
        public_key = public_key::Vector{UInt8},
        signature_algorithm = signature_algorithm::UInt16,
        signature = signature::Vector{UInt8},
        params = params,
    )
end

function _tls12_verify_server_key_exchange!(
    state::_TLS12ClientHandshakeState,
    pubkey::Ptr{Cvoid},
    server_key_exchange::_ServerKeyExchangeMsgTLS12,
)::NamedTuple
    params = _tls12_parse_server_key_exchange(server_key_exchange)
    signed = UInt8[]
    try
        sizehint!(signed, length(state.client_hello.random) + length(state.server_hello.random) + length(params.params))
        append!(signed, state.client_hello.random)
        append!(signed, state.server_hello.random)
        append!(signed, params.params)
        _tls12_openssl_verify_signature(pubkey, params.signature_algorithm, signed, params.signature) ||
            _tls13_fail(_TLS_ALERT_DECRYPT_ERROR, "tls: invalid TLS 1.2 ServerKeyExchange signature")
        return params
    finally
        _securezero!(signed)
        _securezero!(params.params)
    end
end

function _tls12_generate_client_key_exchange(group::UInt16, server_public_key::AbstractVector{UInt8})
    group == _TLS_GROUP_SECP256R1 ||
        _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: native TLS 1.2 client only supports P-256 ECDHE today")
    private_key = _tls13_p256_generate_private_key()
    client_public_key = UInt8[]
    shared_secret = UInt8[]
    try
        client_public_key = _tls13_p256_public_key(private_key)
        shared_secret = _tls13_p256_shared_secret(private_key, server_public_key)
        body = UInt8[UInt8(length(client_public_key))]
        append!(body, client_public_key)
        return _ClientKeyExchangeMsgTLS12(body), shared_secret
    finally
        _free_evp_pkey!(private_key)
        _securezero!(client_public_key)
    end
end

function _tls12_set_server_hello!(state::_TLS12ClientHandshakeState, raw_server_hello::Vector{UInt8})::Nothing
    _tls12_require_handshake_message(raw_server_hello, _HANDSHAKE_TYPE_SERVER_HELLO, "ServerHello")
    server_hello = _unmarshal_handshake_message(raw_server_hello, nothing, TLS1_2_VERSION)
    server_hello isa _ServerHelloMsg || _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 ServerHello")
    state.server_hello = server_hello::_ServerHelloMsg
    _tls12_select_cipher_spec!(state)
    return nothing
end

function _tls12_read_server_hello!(
    state::_TLS12ClientHandshakeState,
    io::_TLS12HandshakeRecordIO,
)::Vector{UInt8}
    raw_server_hello = _read_handshake_bytes!(io)
    _tls12_set_server_hello!(state, raw_server_hello)
    return raw_server_hello
end

function _tls12_read_server_flight!(
    state::_TLS12ClientHandshakeState,
    io::_TLS12HandshakeRecordIO,
    config,
    transcript::_TLS12TranscriptState,
)::Tuple{Ptr{Cvoid}, NamedTuple}
    raw_certificate = _read_handshake_bytes!(io)
    _tls12_require_handshake_message(raw_certificate, _HANDSHAKE_TYPE_CERTIFICATE, "Certificate")
    certificate = _unmarshal_handshake_message(raw_certificate, transcript, TLS1_2_VERSION)
    certificate isa _CertificateMsgTLS12 || _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 Certificate")
    state.server_certificate = certificate::_CertificateMsgTLS12
    pubkey = _tls13_verify_server_certificate_chain(
        state.server_certificate.certificates,
        state.client_hello.server_name;
        verify_peer = config.verify_peer,
        verify_hostname = config.verify_hostname,
        ca_file = config.verify_peer ? _effective_ca_file(config; is_server = false) : nothing,
    )
    occursin("RSA", _tls13_pkey_type_name(pubkey)) ||
        _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: native TLS 1.2 client only supports RSA-authenticated cipher suites today")

    raw_server_key_exchange = _read_handshake_bytes!(io)
    _tls12_require_handshake_message(raw_server_key_exchange, _HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE, "ServerKeyExchange")
    server_key_exchange = _unmarshal_handshake_message(raw_server_key_exchange, transcript, TLS1_2_VERSION)
    server_key_exchange isa _ServerKeyExchangeMsgTLS12 || _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 ServerKeyExchange")
    state.server_key_exchange = server_key_exchange::_ServerKeyExchangeMsgTLS12
    key_exchange = _tls12_verify_server_key_exchange!(state, pubkey, state.server_key_exchange)

    raw_next = _read_handshake_bytes!(io)
    if raw_next[1] == _HANDSHAKE_TYPE_CERTIFICATE_REQUEST
        _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: native TLS 1.2 client certificate authentication is not implemented")
    end
    _tls12_require_handshake_message(raw_next, _HANDSHAKE_TYPE_SERVER_HELLO_DONE, "ServerHelloDone")
    _unmarshal_handshake_message(raw_next, transcript, TLS1_2_VERSION) isa _ServerHelloDoneMsgTLS12 ||
        _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 ServerHelloDone")
    return pubkey, key_exchange
end

function _tls12_read_change_cipher_spec!(io::_TLS12HandshakeRecordIO)::Nothing
    while true
        _tls12_take_received_change_cipher_spec!(io.state) && return nothing
        raw = _tls12_try_take_handshake_message!(io.state)
        raw === nothing || _tls13_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: received unexpected TLS 1.2 handshake message before ChangeCipherSpec")
        io.state.peer_close_notify && throw(EOFError())
        _tls12_read_record!(io.tcp, io.state)
    end
end

function _client_handshake_tls12_for_suite!(
    state::_TLS12ClientHandshakeState,
    io::_TLS12HandshakeRecordIO,
    config,
    transcript::_TLS12TranscriptState,
    raw_client_hello::Vector{UInt8},
    raw_server_hello::Vector{UInt8},
    cipher_spec::_TLS12CipherSpec,
    hash_kind::_TLSHashKind,
)::Nothing
    pubkey = Ptr{Cvoid}(C_NULL)
    shared_secret = UInt8[]
    master_secret = UInt8[]
    client_verify_data = UInt8[]
    expected_server_verify_data = UInt8[]
    client_mac = UInt8[]
    server_mac = UInt8[]
    client_key = UInt8[]
    server_key = UInt8[]
    client_iv = UInt8[]
    server_iv = UInt8[]
    _transcript_update!(transcript, raw_client_hello)
    _transcript_update!(transcript, raw_server_hello)
    try
        pubkey, key_exchange = _tls12_read_server_flight!(state, io, config, transcript)
        state.curve_id = key_exchange.group
        client_key_exchange, generated_shared_secret = _tls12_generate_client_key_exchange(key_exchange.group, key_exchange.public_key)
        shared_secret = generated_shared_secret
        try
            raw_client_key_exchange = _write_handshake_message(client_key_exchange, transcript)
            _write_handshake_bytes!(io, raw_client_key_exchange)
        finally
            _securezero!(client_key_exchange.ciphertext)
        end

        master_secret = _tls12_extended_master_from_pre_master_secret(
            hash_kind,
            shared_secret,
            _transcript_digest(transcript),
        )
        client_mac, server_mac, client_key, server_key, client_iv, server_iv =
            _tls12_keys_from_master_secret(hash_kind, master_secret, state.client_hello.random, state.server_hello.random, 0, cipher_spec.key_length, cipher_spec.iv_length)
        isempty(client_mac) || _tls13_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: unexpected TLS 1.2 MAC key material for AEAD cipher suite")
        isempty(server_mac) || _tls13_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: unexpected TLS 1.2 MAC key material for AEAD cipher suite")
        _tls12_set_write_cipher!(io.state, cipher_spec, client_key, client_iv)
        _tls13_write_tls_plaintext!(io.tcp, _TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC, _TLS12_CHANGE_CIPHER_SPEC_PAYLOAD, TLS1_2_VERSION)
        client_verify_data = _tls12_client_finished_verify_data(hash_kind, master_secret, transcript)
        client_finished = _FinishedMsg(client_verify_data)
        raw_client_finished = _write_handshake_message(client_finished, transcript)
        _tls12_write_record!(io.tcp, io.state.write_cipher, _TLS_RECORD_TYPE_HANDSHAKE, raw_client_finished)

        io.state.allow_encrypted_handshake = true
        try
            _tls12_read_change_cipher_spec!(io)
            _tls12_set_read_cipher!(io.state, cipher_spec, server_key, server_iv)
            raw_server_finished = _read_handshake_bytes!(io)
            _tls12_require_handshake_message(raw_server_finished, _HANDSHAKE_TYPE_FINISHED, "Finished")
            server_finished = _unmarshal_finished(raw_server_finished)
            server_finished === nothing && _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 Finished")
            expected_server_verify_data = _tls12_server_finished_verify_data(hash_kind, master_secret, transcript)
            _constant_time_equals((server_finished::_FinishedMsg).verify_data, expected_server_verify_data) ||
                _tls13_fail(_TLS_ALERT_DECRYPT_ERROR, "tls: invalid TLS 1.2 Finished verify_data")
            _transcript_update!(transcript, raw_server_finished)
        finally
            io.state.allow_encrypted_handshake = false
        end
    finally
        _free_evp_pkey!(pubkey)
        _securezero!(shared_secret)
        _securezero!(master_secret)
        _securezero!(client_verify_data)
        _securezero!(expected_server_verify_data)
        _securezero!(client_mac)
        _securezero!(server_mac)
        _securezero!(client_key)
        _securezero!(server_key)
        _securezero!(client_iv)
        _securezero!(server_iv)
    end
    return nothing
end

function _client_handshake_tls12_after_server_hello!(
    state::_TLS12ClientHandshakeState,
    io::_TLS12HandshakeRecordIO,
    config,
    raw_client_hello::Vector{UInt8},
    raw_server_hello::Vector{UInt8},
)::Nothing
    if state.cipher_suite == _TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256_ID
        transcript = _TranscriptHash(_HASH_SHA256)
        return _client_handshake_tls12_for_suite!(
            state,
            io,
            config,
            transcript,
            raw_client_hello,
            raw_server_hello,
            _TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
            _HASH_SHA256,
        )
    elseif state.cipher_suite == _TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384_ID
        transcript = _TranscriptHash(_HASH_SHA384)
        return _client_handshake_tls12_for_suite!(
            state,
            io,
            config,
            transcript,
            raw_client_hello,
            raw_server_hello,
            _TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
            _HASH_SHA384,
        )
    end
    _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: unsupported native TLS 1.2 cipher suite")
end

function _client_handshake_tls12!(state::_TLS12ClientHandshakeState, io::_TLS12HandshakeRecordIO, config)::Nothing
    raw_client_hello = _marshal_handshake_message(state.client_hello)
    _write_handshake_bytes!(io, raw_client_hello)
    raw_server_hello = _tls12_read_server_hello!(state, io)
    return _client_handshake_tls12_after_server_hello!(state, io, config, raw_client_hello, raw_server_hello)
end
