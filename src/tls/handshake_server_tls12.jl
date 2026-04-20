# Native TLS 1.2 server handshake state machine.
#
# This file mirrors the server side of Go's `crypto/tls/handshake_server.go`
# for the subset of TLS 1.2 we support natively: ECDHE + AES-GCM, optional
# client certificates, EMS, and session-ticket resumption.

"""
    _TLS12ServerSession

Cached native TLS 1.2 server resumption state.
"""
struct _TLS12ServerSession
    version::UInt16
    cipher_suite::UInt16
    created_at_s::UInt64
    use_by_s::UInt64
    label::Vector{UInt8}
    secret::Vector{UInt8}
    client_certificates::Vector{Vector{UInt8}}
    alpn_protocol::String
    curve_id::UInt16
    ext_master_secret::Bool
end

function _TLS12ServerSession(
    version::UInt16,
    cipher_suite::UInt16,
    created_at_s::UInt64,
    use_by_s::UInt64,
    label::AbstractVector{UInt8},
    secret::AbstractVector{UInt8},
    client_certificates::Vector{Vector{UInt8}},
    alpn_protocol::AbstractString,
    curve_id::UInt16,
    ext_master_secret::Bool,
)
    return _TLS12ServerSession(
        version,
        cipher_suite,
        created_at_s,
        use_by_s,
        Vector{UInt8}(label),
        Vector{UInt8}(secret),
        [copy(cert) for cert in client_certificates],
        String(alpn_protocol),
        curve_id,
        ext_master_secret,
    )
end

function _owned_tls12_server_session(
    version::UInt16,
    cipher_suite::UInt16,
    created_at_s::UInt64,
    use_by_s::UInt64,
    label::AbstractVector{UInt8},
    secret::AbstractVector{UInt8},
    client_certificates::Vector{Vector{UInt8}},
    alpn_protocol::AbstractString,
    curve_id::UInt16,
    ext_master_secret::Bool,
)::_TLS12ServerSession
    return _TLS12ServerSession(
        version,
        cipher_suite,
        created_at_s,
        use_by_s,
        copy(label),
        copy(secret),
        [copy(cert) for cert in client_certificates],
        String(alpn_protocol),
        curve_id,
        ext_master_secret,
    )
end

function Base.copy(session::_TLS12ServerSession)::_TLS12ServerSession
    return _owned_tls12_server_session(
        session.version,
        session.cipher_suite,
        session.created_at_s,
        session.use_by_s,
        session.label,
        session.secret,
        session.client_certificates,
        session.alpn_protocol,
        session.curve_id,
        session.ext_master_secret,
    )
end

function _securezero_tls12_server_session!(session::_TLS12ServerSession)::Nothing
    _securezero!(session.label)
    _securezero!(session.secret)
    for cert in session.client_certificates
        _securezero!(cert)
    end
    return nothing
end

function _serialize_tls12_server_session(session::_TLS12ServerSession)::Vector{UInt8}
    out = UInt8[]
    _append_u16!(out, session.version)
    _append_u16!(out, session.cipher_suite)
    _tls_ticket_append_u64!(out, session.created_at_s)
    _tls_ticket_append_u64!(out, session.use_by_s)
    _tls_ticket_append_u16_length_prefixed_bytes!(out, session.secret)
    _tls_ticket_append_u16_length_prefixed_bytes!(out, codeunits(session.alpn_protocol))
    _append_u16!(out, session.curve_id)
    push!(out, session.ext_master_secret ? 0x01 : 0x00)
    length(session.client_certificates) <= 0xffff ||
        throw(ArgumentError("tls12 server session contains too many certificates"))
    _append_u16!(out, UInt16(length(session.client_certificates)))
    for cert in session.client_certificates
        _tls_ticket_append_u32_length_prefixed_bytes!(out, cert)
    end
    return out
end

function _deserialize_tls12_server_session(
    data::Vector{UInt8},
    ticket::AbstractVector{UInt8},
)::Union{Nothing, _TLS12ServerSession}
    reader = _HandshakeReader(data)
    version = _read_u16!(reader)
    version === nothing && return nothing
    cipher_suite = _read_u16!(reader)
    cipher_suite === nothing && return nothing
    created_at_s = _tls_ticket_read_u64!(reader)
    created_at_s === nothing && return nothing
    use_by_s = _tls_ticket_read_u64!(reader)
    use_by_s === nothing && return nothing
    secret = _read_u16_length_prefixed_bytes!(reader)
    secret === nothing && return nothing
    alpn_bytes = _read_u16_length_prefixed_bytes!(reader)
    if alpn_bytes === nothing
        _securezero!(secret)
        return nothing
    end
    curve_id = _read_u16!(reader)
    if curve_id === nothing
        _securezero!(secret)
        return nothing
    end
    ext_master_secret_byte = _read_u8!(reader)
    if ext_master_secret_byte === nothing
        _securezero!(secret)
        return nothing
    end
    cert_count = _read_u16!(reader)
    if cert_count === nothing
        _securezero!(secret)
        return nothing
    end
    certificates = Vector{Vector{UInt8}}()
    success = false
    try
        for _ in 1:Int(cert_count::UInt16)
            cert = _tls_ticket_read_u32_length_prefixed_bytes!(reader)
            cert === nothing && return nothing
            push!(certificates, cert)
        end
        _reader_empty(reader) || return nothing
        success = true
        return _owned_tls12_server_session(
            version::UInt16,
            cipher_suite::UInt16,
            created_at_s::UInt64,
            use_by_s::UInt64,
            ticket,
            secret::Vector{UInt8},
            certificates,
            String(alpn_bytes::Vector{UInt8}),
            curve_id::UInt16,
            ext_master_secret_byte::UInt8 == 0x01,
        )
    finally
        _securezero!(secret)
        if !success
            for cert in certificates
                _securezero!(cert)
            end
        end
    end
end

"""
    _TLS12ServerHandshakeState

Owned state for one native TLS 1.2 server handshake.

It tracks the parsed ClientHello, locally configured identity, optional client
certificate inputs, and the negotiated outputs needed to install TLS 1.2 record
keys and cache a resumable session.
"""
mutable struct _TLS12ServerHandshakeState
    client_hello::_ClientHelloMsg
    server_hello::_ServerHelloMsg
    certificate_request::_CertificateRequestMsgTLS12
    have_certificate_request::Bool
    client_certificate::_CertificateMsgTLS12
    client_certificate_verify::_CertificateVerifyMsg
    certificate_chain::Vector{Vector{UInt8}}
    private_key::Ptr{Cvoid}
    ecdhe_private_key::Ptr{Cvoid}
    client_leaf_public_key::_TLSPublicKeyState
    peer_certificates::Vector{Vector{UInt8}}
    resumption_session::Union{Nothing, _TLS12ServerSession}
    using_resumption::Bool
    cipher_suite::UInt16
    curve_id::UInt16
    selected_signature_algorithm::UInt16
    selected_alpn::String
    send_downgrade_canary::Bool
end

function _TLS12ServerHandshakeState(config)::_TLS12ServerHandshakeState
    identity = _tls_local_identity(config; is_server = true)
    identity === nothing && throw(ArgumentError("tls12 native server requires cert_file"))
    return _TLS12ServerHandshakeState(
        _ClientHelloMsg(),
        _ServerHelloMsg(),
        _CertificateRequestMsgTLS12(),
        false,
        _CertificateMsgTLS12(),
        _CertificateVerifyMsg(),
        (identity::_TLSLocalIdentity).certificate_chain,
        identity.private_key,
        C_NULL,
        nothing,
        Vector{Vector{UInt8}}(),
        nothing,
        false,
        UInt16(0),
        UInt16(0),
        UInt16(0),
        "",
        false,
    )
end

function _securezero_tls12_server_handshake_state!(state::_TLS12ServerHandshakeState)::Nothing
    for cert in state.peer_certificates
        _securezero!(cert)
    end
    state.private_key == C_NULL || _free_evp_pkey!(state.private_key)
    state.private_key = C_NULL
    state.ecdhe_private_key == C_NULL || _free_evp_pkey!(state.ecdhe_private_key)
    state.ecdhe_private_key = C_NULL
    state.client_leaf_public_key = nothing
    session = state.resumption_session
    session === nothing || _securezero_tls12_server_session!(session::_TLS12ServerSession)
    state.resumption_session = nothing
    return nothing
end

@inline function _native_tls12_server_enabled(config)::Bool
    return config.cert_file !== nothing &&
        config.key_file !== nothing &&
        _native_tls12_only(config)
end

function _tls12_select_server_cipher_suite(client_hello::_ClientHelloMsg, private_key::Ptr{Cvoid})::UInt16
    pkey_type = _tls13_pkey_type_name(private_key)
    if pkey_type == "EC"
        for cipher_suite in (
                _TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_ID,
                _TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_ID,
            )
            in(cipher_suite, client_hello.cipher_suites) && return cipher_suite
        end
    elseif pkey_type == "RSA"
        for cipher_suite in (
                _TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256_ID,
                _TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384_ID,
            )
            in(cipher_suite, client_hello.cipher_suites) && return cipher_suite
        end
    else
        throw(ArgumentError("tls: unsupported TLS 1.2 server certificate key type $(pkey_type)"))
    end
    _tls_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: client did not offer a supported native TLS 1.2 cipher suite")
end

@inline function _tls12_client_supports_uncompressed_points(client_hello::_ClientHelloMsg)::Bool
    isempty(client_hello.supported_points) && return true
    return in(UInt8(0x00), client_hello.supported_points)
end

function _tls12_select_server_curve(client_hello::_ClientHelloMsg, config)::UInt16
    preferred_curves = _tls12_curve_preferences(config)
    for group in preferred_curves
        in(group, client_hello.supported_curves) || continue
        if group == _TLS_GROUP_SECP256R1 && !_tls12_client_supports_uncompressed_points(client_hello)
            continue
        end
        return group
    end
    if in(_TLS_GROUP_SECP256R1, preferred_curves) &&
       in(_TLS_GROUP_SECP256R1, client_hello.supported_curves) &&
       !_tls12_client_supports_uncompressed_points(client_hello)
        _tls_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: client did not offer uncompressed TLS 1.2 EC points")
    end
    _tls_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: client did not offer a supported native TLS 1.2 ECDHE curve")
end

function _tls12_set_client_hello!(state::_TLS12ServerHandshakeState, raw::Vector{UInt8})::Nothing
    client_hello = _unmarshal_client_hello(raw)
    client_hello === nothing && _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls12 server handshake expected ClientHello")
    versions = client_hello.supported_versions
    if isempty(versions)
        client_hello.vers == TLS1_2_VERSION ||
            _tls_fail(_TLS_ALERT_PROTOCOL_VERSION, "tls: client did not offer TLS 1.2")
    else
        in(TLS1_2_VERSION, versions) || _tls_fail(_TLS_ALERT_PROTOCOL_VERSION, "tls: client did not offer TLS 1.2")
    end
    in(_TLS_COMPRESSION_NONE, client_hello.compression_methods) ||
        _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: client does not support uncompressed TLS 1.2 connections")
    isempty(client_hello.secure_renegotiation) ||
        _tls_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: initial TLS 1.2 handshake had non-empty renegotiation extension")
    client_hello.extended_master_secret ||
        _tls_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: native TLS 1.2 server requires extended master secret")
    has_supported_curve = false
    for group in client_hello.supported_curves
        if _native_curve_supported(group)
            has_supported_curve = true
            break
        end
    end
    has_supported_curve || _tls_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: client did not offer a supported native TLS 1.2 ECDHE curve")
    isempty(client_hello.supported_signature_algorithms) &&
        _tls_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: client did not advertise TLS 1.2 signature algorithms")
    state.client_hello = client_hello
    return nothing
end

function _tls12_read_client_hello!(state::_TLS12ServerHandshakeState, io::_TLS12HandshakeRecordIO)::Vector{UInt8}
    raw = _read_handshake_bytes!(io)
    _tls12_set_client_hello!(state, raw)
    return raw
end

function _tls12_select_server_parameters!(state::_TLS12ServerHandshakeState, config)::Nothing
    state.selected_alpn = _tls_select_server_alpn(config, state.client_hello)
    state.resumption_session = nothing
    state.using_resumption = false
    session_ticket = state.client_hello.session_ticket
    if !config.session_tickets_disabled && !isempty(session_ticket)
        keys = _tls_active_session_ticket_keys(config)
        try
            plaintext = _tls_decrypt_server_session_ticket(keys, session_ticket)
            if plaintext !== nothing
                session = _deserialize_tls12_server_session(plaintext, session_ticket)
                _securezero!(plaintext)
                if session !== nothing
                    keep_session = false
                    try
                        now_s = UInt64(floor(time()))
                        if session.version == TLS1_2_VERSION &&
                           now_s <= session.use_by_s &&
                           in(session.cipher_suite, state.client_hello.cipher_suites) &&
                           session.alpn_protocol == state.selected_alpn &&
                           session.ext_master_secret &&
                           _tls12_cipher_spec(session.cipher_suite) !== nothing &&
                           _tls_server_session_client_auth_ok(session.client_certificates, config) do client_certificates
                               _tls13_verify_client_certificate_chain(
                                   client_certificates;
                                   verify_peer = true,
                                   ca_file = _effective_ca_file(config; is_server = true),
                               )
                           end
                            state.resumption_session = session
                            state.using_resumption = true
                            state.cipher_suite = session.cipher_suite
                            state.curve_id = session.curve_id
                            state.peer_certificates = [copy(cert) for cert in session.client_certificates]
                            keep_session = true
                            return nothing
                        end
                    finally
                        keep_session || _securezero_tls12_server_session!(session::_TLS12ServerSession)
                    end
                end
            end
        finally
            _securezero_tls_session_ticket_keys!(keys)
        end
    end
    state.cipher_suite = _tls12_select_server_cipher_suite(state.client_hello, state.private_key)
    state.curve_id = _tls12_select_server_curve(state.client_hello, config)
    signature_algorithm = _tls12_select_signature_algorithm(
        state.private_key,
        state.client_hello.supported_signature_algorithms,
    )
    signature_algorithm === nothing &&
        _tls_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: client does not support a usable TLS 1.2 certificate signature algorithm")
    state.selected_signature_algorithm = signature_algorithm
    return nothing
end

function _tls12_send_server_hello!(
    state::_TLS12ServerHandshakeState,
    io::_TLS12HandshakeRecordIO,
    transcript::_TLS12TranscriptState,
    raw_client_hello::Vector{UInt8},
    config,
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
    server_hello.session_id = state.using_resumption ? copy(state.client_hello.session_id) : UInt8[]
    server_hello.cipher_suite = state.cipher_suite
    server_hello.compression_method = _TLS_COMPRESSION_NONE
    server_hello.extended_master_secret = true
    server_hello.ticket_supported = state.client_hello.ticket_supported && !config.session_tickets_disabled
    server_hello.secure_renegotiation_supported = state.client_hello.secure_renegotiation_supported
    server_hello.server_name_ack = !isempty(state.client_hello.server_name)
    server_hello.alpn_protocol = state.selected_alpn
    if state.curve_id == _TLS_GROUP_SECP256R1 && !isempty(state.client_hello.supported_points)
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
    if state.curve_id == _TLS_GROUP_X25519
        state.ecdhe_private_key = _tls13_x25519_generate_private_key()
        public_key = _tls13_x25519_public_key(state.ecdhe_private_key)
    elseif state.curve_id == _TLS_GROUP_SECP256R1
        state.ecdhe_private_key = _tls13_p256_generate_private_key()
        public_key = _tls13_p256_public_key(state.ecdhe_private_key)
    else
        _tls_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: unsupported native TLS 1.2 ECDHE group")
    end
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

function _tls12_send_certificate_request!(state::_TLS12ServerHandshakeState, io::_TLS12HandshakeRecordIO, transcript::_TLS12TranscriptState)::Nothing
    msg = _CertificateRequestMsgTLS12()
    msg.certificate_types = UInt8[_TLS12_CERT_TYPE_RSA_SIGN, _TLS12_CERT_TYPE_ECDSA_SIGN]
    msg.supported_signature_algorithms = copy(_TLS12_SUPPORTED_SIGNATURE_ALGORITHMS)
    state.certificate_request = msg
    state.have_certificate_request = true
    raw = _write_handshake_message(msg, transcript)
    _write_handshake_bytes!(io, raw)
    return nothing
end

function _tls12_read_client_certificate!(
    state::_TLS12ServerHandshakeState,
    io::_TLS12HandshakeRecordIO,
    transcript::_TLS12TranscriptState,
    config,
)::Nothing
    state.have_certificate_request || return nothing
    raw = _read_handshake_bytes!(io)
    _tls12_require_handshake_message(raw, _HANDSHAKE_TYPE_CERTIFICATE, "Certificate")
    certificate = _unmarshal_handshake_message(raw, transcript, TLS1_2_VERSION)
    certificate isa _CertificateMsgTLS12 || _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 client Certificate")
    state.client_certificate = certificate::_CertificateMsgTLS12
    state.client_leaf_public_key = nothing
    for cert in state.peer_certificates
        _securezero!(cert)
    end
    state.peer_certificates = [copy(cert) for cert in state.client_certificate.certificates]
    has_client_certificates = !isempty(state.client_certificate.certificates)
    if !has_client_certificates
        if config.client_auth == ClientAuthMode.RequireAnyClientCert || config.client_auth == ClientAuthMode.RequireAndVerifyClientCert
            _tls_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: client did not provide a certificate")
        end
        return nothing
    end
    verify_peer = config.client_auth == ClientAuthMode.VerifyClientCertIfGiven || config.client_auth == ClientAuthMode.RequireAndVerifyClientCert
    state.client_leaf_public_key = if verify_peer
        _tls13_verify_client_certificate_chain(
            state.client_certificate.certificates;
            verify_peer,
            ca_file = _effective_ca_file(config; is_server = true),
        )
    else
        _tls_parse_der_certificate_info(state.client_certificate.certificates[1]).public_key
    end
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
    msg === nothing && _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 ClientKeyExchange")
    ciphertext = (msg::_ClientKeyExchangeMsgTLS12).ciphertext
    isempty(ciphertext) && _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: empty TLS 1.2 ClientKeyExchange")
    Int(ciphertext[1]) == length(ciphertext) - 1 ||
        _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: malformed TLS 1.2 ClientKeyExchange")
    if state.curve_id == _TLS_GROUP_X25519
        length(ciphertext) == 33 ||
            _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: malformed TLS 1.2 ClientKeyExchange")
    elseif state.curve_id == _TLS_GROUP_SECP256R1
        length(ciphertext) == 66 ||
            _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: malformed TLS 1.2 ClientKeyExchange")
        ciphertext[2] == 0x04 ||
            _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: malformed TLS 1.2 ClientKeyExchange")
    else
        _tls_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: unsupported native TLS 1.2 ECDHE group")
    end
    _transcript_update!(transcript, raw)
    return ciphertext
end

function _tls12_server_shared_secret(state::_TLS12ServerHandshakeState, client_key_exchange::AbstractVector{UInt8})::Vector{UInt8}
    state.ecdhe_private_key == C_NULL && throw(ArgumentError("tls: missing TLS 1.2 server ECDHE private key"))
    if state.curve_id == _TLS_GROUP_X25519
        return _tls13_x25519_shared_secret(state.ecdhe_private_key, @view(client_key_exchange[2:end]))
    end
    if state.curve_id == _TLS_GROUP_SECP256R1
        return _tls13_p256_shared_secret(state.ecdhe_private_key, @view(client_key_exchange[2:end]))
    end
    _tls_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: unsupported native TLS 1.2 ECDHE group")
end

function _tls12_read_client_certificate_verify!(
    state::_TLS12ServerHandshakeState,
    io::_TLS12HandshakeRecordIO,
    transcript::_TLS12TranscriptState,
)::Nothing
    isempty(state.peer_certificates) && return nothing
    raw = _read_handshake_bytes!(io)
    _tls12_require_handshake_message(raw, _HANDSHAKE_TYPE_CERTIFICATE_VERIFY, "CertificateVerify")
    msg = _unmarshal_certificate_verify(raw)
    msg === nothing && _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 CertificateVerify")
    in((msg::_CertificateVerifyMsg).signature_algorithm, state.certificate_request.supported_signature_algorithms) ||
        _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: client certificate used with invalid TLS 1.2 signature algorithm")
    transcript_bytes = _transcript_buffered_bytes(transcript)
    transcript_bytes === nothing && throw(ArgumentError("tls: TLS 1.2 server client-certificate verification requires a buffered transcript"))
    _tls12_openssl_verify_signature(state.client_leaf_public_key::_TLSPublicKey, msg.signature_algorithm, transcript_bytes, msg.signature) ||
        _tls_fail(_TLS_ALERT_DECRYPT_ERROR, "tls: invalid signature by the TLS 1.2 client certificate")
    state.client_certificate_verify = msg
    _transcript_update!(transcript, raw)
    return nothing
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
        msg === nothing && _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 Finished")
        expected_verify_data = _tls12_client_finished_verify_data(hash_kind, master_secret, transcript)
        _constant_time_equals((msg::_FinishedMsg).verify_data, expected_verify_data) ||
            _tls_fail(_TLS_ALERT_DECRYPT_ERROR, "tls: invalid TLS 1.2 Finished verify_data")
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
        _tls_write_tls_plaintext!(io.tcp, _TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC, _TLS12_CHANGE_CIPHER_SPEC_PAYLOAD, TLS1_2_VERSION)
        raw = _write_handshake_message(_FinishedMsg(verify_data), transcript)
        _tls12_write_record!(io.tcp, io.state.write_cipher, _TLS_RECORD_TYPE_HANDSHAKE, raw)
    finally
        _securezero!(verify_data)
    end
    return nothing
end

function _tls12_send_new_session_ticket!(
    state::_TLS12ServerHandshakeState,
    io::_TLS12HandshakeRecordIO,
    transcript::_TLS12TranscriptState,
    config,
    master_secret::Vector{UInt8},
)::Nothing
    state.server_hello.ticket_supported || return nothing
    label = UInt8[]
    plaintext = UInt8[]
    session = _owned_tls12_server_session(
        TLS1_2_VERSION,
        state.cipher_suite,
        UInt64(floor(time())),
        UInt64(floor(time())) + UInt64(_TLS12_MAX_SESSION_TICKET_LIFETIME),
        UInt8[],
        master_secret,
        state.peer_certificates,
        state.selected_alpn,
        state.curve_id,
        state.server_hello.extended_master_secret,
    )
    keys = _tls_active_session_ticket_keys(config)
    try
        plaintext = _serialize_tls12_server_session(session)
        label = _tls_encrypt_server_session_ticket(keys[1], plaintext)
        raw = _write_handshake_message(_NewSessionTicketMsgTLS12(_TLS12_MAX_SESSION_TICKET_LIFETIME, label), transcript)
        _write_handshake_bytes!(io, raw)
    finally
        _securezero_tls12_server_session!(session)
        _securezero!(plaintext)
        _securezero!(label)
        _securezero_tls_session_ticket_keys!(keys)
    end
    return nothing
end

function _tls12_resumed_server_handshake!(
    state::_TLS12ServerHandshakeState,
    io::_TLS12HandshakeRecordIO,
    raw_client_hello::Vector{UInt8},
    transcript::_TLS12TranscriptState,
    cipher_spec::_TLS12CipherSpec,
    hash_kind::_TLSHashKind,
    config,
)::Nothing
    session = state.resumption_session
    session === nothing && throw(ArgumentError("tls: missing TLS 1.2 resumption session"))
    master_secret = copy(session.secret)
    client_mac = UInt8[]
    server_mac = UInt8[]
    client_key = UInt8[]
    server_key = UInt8[]
    client_iv = UInt8[]
    server_iv = UInt8[]
    try
        _tls12_send_server_hello!(state, io, transcript, raw_client_hello, config)
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
        isempty(client_mac) || _tls_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: unexpected TLS 1.2 MAC key material for AEAD cipher suite")
        isempty(server_mac) || _tls_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: unexpected TLS 1.2 MAC key material for AEAD cipher suite")
        _tls12_send_new_session_ticket!(state, io, transcript, config, master_secret)
        _tls12_set_write_cipher!(io.state, cipher_spec, server_key, server_iv)
        _tls12_send_server_finished!(io, transcript, master_secret, hash_kind)
        _tls12_read_client_finished!(io, transcript, master_secret, hash_kind, cipher_spec, client_key, client_iv)
        state.using_resumption = true
    finally
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

function _server_handshake_tls12_for_suite!(
    state::_TLS12ServerHandshakeState,
    io::_TLS12HandshakeRecordIO,
    raw_client_hello::Vector{UInt8},
    transcript::_TLS12TranscriptState,
    cipher_spec::_TLS12CipherSpec,
    hash_kind::_TLSHashKind,
    config,
)::Nothing
    # The TLS 1.2 server path first decides resumed vs full handshake, then
    # either abbreviates directly to Finished or runs the full cert/key-exchange
    # flight before installing record keys.
    shared_secret = UInt8[]
    master_secret = UInt8[]
    client_mac = UInt8[]
    server_mac = UInt8[]
    client_key = UInt8[]
    server_key = UInt8[]
    client_iv = UInt8[]
    server_iv = UInt8[]
    try
        if state.using_resumption
            return _tls12_resumed_server_handshake!(state, io, raw_client_hello, transcript, cipher_spec, hash_kind, config)
        end
        _tls12_send_server_hello!(state, io, transcript, raw_client_hello, config)
        _tls12_send_server_certificate!(state, io, transcript)
        _tls12_send_server_key_exchange!(state, io, transcript)
        _tls_should_request_client_certificate(config) && _tls12_send_certificate_request!(state, io, transcript)
        _tls12_send_server_hello_done!(io, transcript)
        _tls12_read_client_certificate!(state, io, transcript, config)
        client_key_exchange = _tls12_read_client_key_exchange!(state, io, transcript)
        shared_secret = _tls12_server_shared_secret(state, client_key_exchange)
        master_secret = _tls12_extended_master_from_pre_master_secret(
            hash_kind,
            shared_secret,
            _transcript_digest(transcript),
        )
        _tls12_read_client_certificate_verify!(state, io, transcript)
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
        isempty(client_mac) || _tls_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: unexpected TLS 1.2 MAC key material for AEAD cipher suite")
        isempty(server_mac) || _tls_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: unexpected TLS 1.2 MAC key material for AEAD cipher suite")
        _tls12_read_client_finished!(io, transcript, master_secret, hash_kind, cipher_spec, client_key, client_iv)
        _tls12_send_new_session_ticket!(state, io, transcript, config, master_secret)
        _tls12_set_write_cipher!(io.state, cipher_spec, server_key, server_iv)
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
    if state.cipher_suite == _TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256_ID ||
       state.cipher_suite == _TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_ID
        transcript = _TranscriptHash(_HASH_SHA256)
        return _server_handshake_tls12_for_suite!(
            state,
            io,
            raw_client_hello,
            transcript,
            _tls12_cipher_spec(state.cipher_suite)::_TLS12CipherSpec,
            _HASH_SHA256,
            config,
        )
    elseif state.cipher_suite == _TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384_ID ||
           state.cipher_suite == _TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_ID
        transcript = _TranscriptHash(_HASH_SHA384)
        return _server_handshake_tls12_for_suite!(
            state,
            io,
            raw_client_hello,
            transcript,
            _tls12_cipher_spec(state.cipher_suite)::_TLS12CipherSpec,
            _HASH_SHA384,
            config,
        )
    end
    _tls_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: unsupported native TLS 1.2 cipher suite")
end

function _server_handshake_tls12!(state::_TLS12ServerHandshakeState, io::_TLS12HandshakeRecordIO, config)::Nothing
    raw_client_hello = _tls12_read_client_hello!(state, io)
    return _server_handshake_tls12_after_client_hello!(state, io, config, raw_client_hello)
end

function _native_tls12_server_handshake!(conn)::Nothing
    state = _TLS12ServerHandshakeState(conn.config)
    io = _TLS12HandshakeRecordIO(conn.tcp, _native_tls12_state(conn))
    try
        _server_handshake_tls12!(state, io, conn.config)
        _finish_native_tls12_server_handshake!(conn, state)
    finally
        _securezero_tls12_server_handshake_state!(state)
    end
    return nothing
end
