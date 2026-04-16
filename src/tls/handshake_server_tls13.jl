mutable struct _TLS13ServerHandshakeState
    client_hello::_ClientHelloMsg
    client_hello_raw::Vector{UInt8}
    server_hello::_ServerHelloMsg
    server_hello_raw::Vector{UInt8}
    encrypted_extensions::_EncryptedExtensionsMsg
    certificate::_CertificateMsgTLS13
    certificate_verify::_CertificateVerifyMsg
    client_finished::_FinishedMsg
    cipher_suite::UInt16
    cipher_spec::_TLS13CipherSpec
    transcript::_TLS13TranscriptState
    key_share_provider::_TLS13OpenSSLKeyShareProvider
    private_key::Ptr{Cvoid}
    certificate_chain::Vector{Vector{UInt8}}
    selected_signature_algorithm::UInt16
    selected_alpn::String
    shared_secret::Vector{UInt8}
    handshake_secret::Vector{UInt8}
    master_secret::Vector{UInt8}
    client_handshake_traffic_secret::Vector{UInt8}
    server_handshake_traffic_secret::Vector{UInt8}
    client_application_traffic_secret::Vector{UInt8}
    server_application_traffic_secret::Vector{UInt8}
    exporter_master_secret::Vector{UInt8}
    complete::Bool
end

function _TLS13ServerHandshakeState(config)::_TLS13ServerHandshakeState
    cert_file = config.cert_file === nothing ? throw(ArgumentError("tls13 native server requires cert_file")) : (config.cert_file::String)
    key_file = config.key_file === nothing ? throw(ArgumentError("tls13 native server requires key_file")) : (config.key_file::String)
    cert_pem = read(cert_file)
    key_pem = read(key_file)
    certificate_chain = _tls13_load_x509_pem_chain(cert_pem)
    private_key = _tls13_load_private_key_pem(key_pem)
    _securezero!(key_pem)
    return _TLS13ServerHandshakeState(
        _ClientHelloMsg(),
        UInt8[],
        _ServerHelloMsg(),
        UInt8[],
        _EncryptedExtensionsMsg(),
        _CertificateMsgTLS13(),
        _CertificateVerifyMsg(),
        _FinishedMsg(),
        UInt16(0),
        _TLS13_AES_128_GCM_SHA256,
        _new_tls13_handshake_transcript(_HASH_SHA256),
        _TLS13OpenSSLKeyShareProvider(),
        private_key,
        certificate_chain,
        UInt16(0),
        "",
        UInt8[],
        UInt8[],
        UInt8[],
        UInt8[],
        UInt8[],
        UInt8[],
        UInt8[],
        UInt8[],
        false,
    )
end

function _securezero_tls13_server_handshake_state!(state::_TLS13ServerHandshakeState)::Nothing
    _securezero_tls13_key_share_provider!(state.key_share_provider)
    _free_evp_pkey!(state.private_key)
    state.private_key = C_NULL
    _securezero!(state.client_hello_raw)
    _securezero!(state.server_hello_raw)
    _securezero!(state.shared_secret)
    _securezero!(state.handshake_secret)
    _securezero!(state.master_secret)
    _securezero!(state.client_handshake_traffic_secret)
    _securezero!(state.server_handshake_traffic_secret)
    _securezero!(state.client_application_traffic_secret)
    _securezero!(state.server_application_traffic_secret)
    _securezero!(state.exporter_master_secret)
    return nothing
end

@inline function _native_tls13_server_enabled(config)::Bool
    return config.cert_file !== nothing &&
        config.key_file !== nothing &&
        config.client_auth == ClientAuthMode.NoClientCert &&
        config.min_version == TLS1_3_VERSION &&
        (config.max_version === nothing || config.max_version == TLS1_3_VERSION)
end

function _tls13_select_server_cipher_suite(client_hello::_ClientHelloMsg)::Tuple{UInt16, _TLS13CipherSpec}
    for cipher_suite in (
            _TLS13_AES_128_GCM_SHA256_ID,
            _TLS13_CHACHA20_POLY1305_SHA256_ID,
            _TLS13_AES_256_GCM_SHA384_ID,
        )
        in(cipher_suite, client_hello.cipher_suites) || continue
        return cipher_suite, (_tls13_cipher_spec(cipher_suite)::_TLS13CipherSpec)
    end
    throw(ArgumentError("tls: client did not offer a supported TLS 1.3 cipher suite"))
end

function _tls13_select_server_alpn(config, client_hello::_ClientHelloMsg)::String
    isempty(config.alpn_protocols) && return ""
    isempty(client_hello.alpn_protocols) && return ""
    for proto in config.alpn_protocols
        in(proto, client_hello.alpn_protocols) && return proto
    end
    return ""
end

function _tls13_select_server_signature_algorithm(pkey::Ptr{Cvoid}, client_hello::_ClientHelloMsg)::UInt16
    pkey_type = _tls13_pkey_type_name(pkey)
    if pkey_type == "RSA"
        for alg in (
                _TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
                _TLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
                _TLS_SIGNATURE_RSA_PSS_RSAE_SHA512,
            )
            in(alg, client_hello.supported_signature_algorithms) && return alg
        end
    elseif pkey_type == "EC"
        for alg in (
                _TLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
                _TLS_SIGNATURE_ECDSA_SECP384R1_SHA384,
                _TLS_SIGNATURE_ECDSA_SECP521R1_SHA512,
            )
            in(alg, client_hello.supported_signature_algorithms) && return alg
        end
    elseif pkey_type == "ED25519"
        in(_TLS_SIGNATURE_ED25519, client_hello.supported_signature_algorithms) &&
            return _TLS_SIGNATURE_ED25519
    end
    throw(ArgumentError("tls: client does not support a usable TLS 1.3 certificate signature algorithm"))
end

function _tls13_server_select_key_share!(state::_TLS13ServerHandshakeState)::_TLSKeyShare
    for group in (_TLS_GROUP_X25519, _TLS_GROUP_SECP256R1)
        for client_share in state.client_hello.key_shares
            client_share.group == group || continue
            server_share = _tls13_generate_key_share!(state.key_share_provider, group)
            _securezero!(state.shared_secret)
            state.shared_secret = _tls13_resolve_server_shared_secret(state.key_share_provider, client_share)
            return server_share
        end
    end
    throw(ArgumentError("tls13 native server does not yet support HelloRetryRequest"))
end

function _read_client_hello!(state::_TLS13ServerHandshakeState, io)::Nothing
    raw = _read_handshake_bytes!(io)
    client_hello = _unmarshal_client_hello(raw)
    client_hello === nothing && throw(ArgumentError("tls13 server handshake expected ClientHello"))
    in(TLS1_3_VERSION, client_hello.supported_versions) || throw(ArgumentError("tls: client did not offer TLS 1.3"))
    in(_TLS_COMPRESSION_NONE, client_hello.compression_methods) || throw(ArgumentError("tls: client sent unsupported compression methods"))
    state.client_hello = client_hello
    state.client_hello_raw = raw
    return nothing
end

function _send_server_hello!(state::_TLS13ServerHandshakeState, io, config)::Nothing
    state.cipher_suite, state.cipher_spec = _tls13_select_server_cipher_suite(state.client_hello)
    state.selected_signature_algorithm = _tls13_select_server_signature_algorithm(state.private_key, state.client_hello)
    state.selected_alpn = _tls13_select_server_alpn(config, state.client_hello)
    server_share = _tls13_server_select_key_share!(state)
    transcript = _new_tls13_handshake_transcript(state.cipher_spec.hash_kind)
    _transcript_update!(transcript, state.client_hello_raw)
    state.transcript = transcript

    rng = Random.RandomDevice()
    server_hello = _ServerHelloMsg()
    server_hello.vers = TLS1_2_VERSION
    server_hello.random = rand(rng, UInt8, 32)
    server_hello.session_id = copy(state.client_hello.session_id)
    server_hello.cipher_suite = state.cipher_suite
    server_hello.compression_method = _TLS_COMPRESSION_NONE
    server_hello.supported_version = TLS1_3_VERSION
    server_hello.server_share = server_share
    state.server_hello = server_hello
    raw = _marshal_server_hello(server_hello)
    state.server_hello_raw = raw
    _transcript_update!(state.transcript, raw)
    _write_handshake_bytes!(io, raw)
    return nothing
end

function _establish_server_handshake_keys!(state::_TLS13ServerHandshakeState)::Nothing
    isempty(state.shared_secret) && throw(ArgumentError("tls13 native server requires a shared secret"))
    early_secret = _tls13_early_secret(state.cipher_spec.hash_kind, nothing)
    handshake_secret = _tls13_handshake_secret(early_secret, state.shared_secret)
    master_secret = _tls13_master_secret(handshake_secret)
    try
        _securezero!(state.handshake_secret)
        _securezero!(state.master_secret)
        state.handshake_secret = copy(handshake_secret.secret)
        state.master_secret = copy(master_secret.secret)
        _securezero!(state.client_handshake_traffic_secret)
        _securezero!(state.server_handshake_traffic_secret)
        state.client_handshake_traffic_secret = _tls13_client_handshake_traffic_secret(handshake_secret, state.transcript)
        state.server_handshake_traffic_secret = _tls13_server_handshake_traffic_secret(handshake_secret, state.transcript)
    finally
        _destroy_tls13_secret!(master_secret)
        _destroy_tls13_secret!(handshake_secret)
        _destroy_tls13_secret!(early_secret)
    end
    return nothing
end

function _send_encrypted_extensions!(state::_TLS13ServerHandshakeState, io)::Nothing
    msg = _EncryptedExtensionsMsg()
    msg.alpn_protocol = state.selected_alpn
    msg.server_name_ack = !isempty(state.client_hello.server_name)
    state.encrypted_extensions = msg
    raw = _marshal_encrypted_extensions(msg)
    _transcript_update!(state.transcript, raw)
    _write_handshake_bytes!(io, raw)
    return nothing
end

function _send_server_certificate!(state::_TLS13ServerHandshakeState, io)::Nothing
    msg = _CertificateMsgTLS13()
    msg.certificates = [copy(cert) for cert in state.certificate_chain]
    state.certificate = msg
    raw = _marshal_certificate_tls13(msg)
    _transcript_update!(state.transcript, raw)
    _write_handshake_bytes!(io, raw)
    return nothing
end

function _send_server_certificate_verify!(state::_TLS13ServerHandshakeState, io)::Nothing
    signed = _tls13_signed_message(_TLS13_SERVER_SIGNATURE_CONTEXT, state.transcript)
    signature = _tls13_openssl_sign_signature(state.private_key, state.selected_signature_algorithm, signed)
    try
        msg = _CertificateVerifyMsg(state.selected_signature_algorithm, signature)
        state.certificate_verify = msg
        raw = _marshal_certificate_verify(msg)
        _transcript_update!(state.transcript, raw)
        _write_handshake_bytes!(io, raw)
    finally
        _securezero!(signed)
        _securezero!(signature)
    end
    return nothing
end

function _send_server_finished!(state::_TLS13ServerHandshakeState, io)::Nothing
    verify_data = _tls13_finished_verify_data(state.cipher_spec.hash_kind, state.server_handshake_traffic_secret, state.transcript)
    msg = _FinishedMsg(verify_data)
    raw = _marshal_finished(msg)
    _transcript_update!(state.transcript, raw)
    _write_handshake_bytes!(io, raw)
    _securezero!(state.client_application_traffic_secret)
    _securezero!(state.server_application_traffic_secret)
    _securezero!(state.exporter_master_secret)
    state.client_application_traffic_secret = _tls13_derive_secret(state.cipher_spec.hash_kind, state.master_secret, "c ap traffic", state.transcript)
    state.server_application_traffic_secret = _tls13_derive_secret(state.cipher_spec.hash_kind, state.master_secret, "s ap traffic", state.transcript)
    state.exporter_master_secret = _tls13_derive_secret(state.cipher_spec.hash_kind, state.master_secret, "exp master", state.transcript)
    return nothing
end

function _read_client_finished!(state::_TLS13ServerHandshakeState, io)::Nothing
    raw = _read_handshake_bytes!(io)
    msg = _unmarshal_finished(raw)
    msg === nothing && throw(ArgumentError("tls13 server handshake expected client Finished"))
    expected_verify_data = _tls13_finished_verify_data(state.cipher_spec.hash_kind, state.client_handshake_traffic_secret, state.transcript)
    try
        _constant_time_equals(msg.verify_data, expected_verify_data) || throw(ArgumentError("tls: invalid client finished hash"))
    finally
        _securezero!(expected_verify_data)
    end
    state.client_finished = msg
    _transcript_update!(state.transcript, raw)
    return nothing
end

function _server_handshake_tls13!(state::_TLS13ServerHandshakeState, io, config)::Nothing
    state.complete && throw(ArgumentError("tls13 server handshake already complete"))
    _read_client_hello!(state, io)
    _send_server_hello!(state, io, config)
    _establish_server_handshake_keys!(state)
    _tls13_set_read_cipher!(io.state, state.cipher_spec, state.client_handshake_traffic_secret)
    _tls13_set_write_cipher!(io.state, state.cipher_spec, state.server_handshake_traffic_secret)
    _send_encrypted_extensions!(state, io)
    _send_server_certificate!(state, io)
    _send_server_certificate_verify!(state, io)
    _send_server_finished!(state, io)
    _tls13_set_write_cipher!(io.state, state.cipher_spec, state.server_application_traffic_secret)
    _read_client_finished!(state, io)
    _tls13_set_read_cipher!(io.state, state.cipher_spec, state.client_application_traffic_secret)
    state.complete = true
    return nothing
end

function _native_tls13_server_handshake!(conn)::Nothing
    state = _TLS13ServerHandshakeState(conn.config)
    native_state = _native_tls13_state(conn)
    io = _TLS13HandshakeRecordIO(conn.tcp, native_state)
    try
        _server_handshake_tls13!(state, io, conn.config)
        native_state.session_cipher_suite = state.cipher_suite
        native_state.session_alpn = state.selected_alpn
        native_state.did_resume = false
        native_state.did_hello_retry_request = false
        native_state.curve_id = state.server_hello.server_share === nothing ? UInt16(0) : (state.server_hello.server_share::_TLSKeyShare).group
        _set_handshake_complete!(conn, "TLSv1.3", isempty(state.selected_alpn) ? nothing : state.selected_alpn)
    finally
        _securezero_tls13_server_handshake_state!(state)
    end
    return nothing
end
