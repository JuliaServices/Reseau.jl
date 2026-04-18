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

const _TLS12_MAX_SESSION_TICKET_LIFETIME = UInt32(7 * 24 * 60 * 60)
const _TLS12_CERT_TYPE_RSA_SIGN = UInt8(0x01)
const _TLS12_CERT_TYPE_ECDSA_SIGN = UInt8(0x40)

const _TLS12TranscriptState = Union{
    _TranscriptHash{SHA.SHA2_256_CTX},
    _TranscriptHash{SHA.SHA2_384_CTX},
}

struct _TLS12ClientSession
    version::UInt16
    cipher_suite::UInt16
    created_at_s::UInt64
    use_by_s::UInt64
    ticket::Vector{UInt8}
    secret::Vector{UInt8}
    certificates::Vector{Vector{UInt8}}
    alpn_protocol::String
    curve_id::UInt16
    ext_master_secret::Bool
end

function _TLS12ClientSession(
    version::UInt16,
    cipher_suite::UInt16,
    created_at_s::UInt64,
    use_by_s::UInt64,
    ticket::AbstractVector{UInt8},
    secret::AbstractVector{UInt8},
    certificates::Vector{Vector{UInt8}},
    alpn_protocol::AbstractString,
    curve_id::UInt16,
    ext_master_secret::Bool,
)
    return _TLS12ClientSession(
        version,
        cipher_suite,
        created_at_s,
        use_by_s,
        Vector{UInt8}(ticket),
        Vector{UInt8}(secret),
        [copy(cert) for cert in certificates],
        String(alpn_protocol),
        curve_id,
        ext_master_secret,
    )
end

function _owned_tls12_client_session(
    version::UInt16,
    cipher_suite::UInt16,
    created_at_s::UInt64,
    use_by_s::UInt64,
    ticket::AbstractVector{UInt8},
    secret::AbstractVector{UInt8},
    certificates::Vector{Vector{UInt8}},
    alpn_protocol::AbstractString,
    curve_id::UInt16,
    ext_master_secret::Bool,
)::_TLS12ClientSession
    return _TLS12ClientSession(
        version,
        cipher_suite,
        created_at_s,
        use_by_s,
        copy(ticket),
        copy(secret),
        [copy(cert) for cert in certificates],
        String(alpn_protocol),
        curve_id,
        ext_master_secret,
    )
end

function _copy_tls12_client_session(session::_TLS12ClientSession)::_TLS12ClientSession
    return _owned_tls12_client_session(
        session.version,
        session.cipher_suite,
        session.created_at_s,
        session.use_by_s,
        session.ticket,
        session.secret,
        session.certificates,
        session.alpn_protocol,
        session.curve_id,
        session.ext_master_secret,
    )
end

function _securezero_tls12_client_session!(session::_TLS12ClientSession)::Nothing
    _securezero!(session.ticket)
    _securezero!(session.secret)
    for cert in session.certificates
        _securezero!(cert)
    end
    return nothing
end

mutable struct _TLS12ClientSessionCache
    lock::ReentrantLock
    entries::Dict{String, _TLS12ClientSession}
    order::Vector{String}
    capacity::Int
end

function _TLS12ClientSessionCache(capacity::Integer = 64)::_TLS12ClientSessionCache
    Int(capacity) > 0 || throw(ArgumentError("tls12 client session cache capacity must be positive"))
    return _TLS12ClientSessionCache(ReentrantLock(), Dict{String, _TLS12ClientSession}(), String[], Int(capacity))
end

function _tls12_session_cache_get(cache::_TLS12ClientSessionCache, key::AbstractString)::Union{Nothing, _TLS12ClientSession}
    key_s = String(key)
    lock(cache.lock)
    try
        session = get(cache.entries, key_s, nothing)
        session === nothing && return nothing
        deleteat!(cache.order, findall(==(key_s), cache.order))
        pushfirst!(cache.order, key_s)
        return _copy_tls12_client_session(session::_TLS12ClientSession)
    finally
        unlock(cache.lock)
    end
end

function _tls12_session_cache_peek(cache::_TLS12ClientSessionCache, key::AbstractString)::Union{Nothing, _TLS12ClientSession}
    key_s = String(key)
    lock(cache.lock)
    try
        session = get(cache.entries, key_s, nothing)
        session === nothing && return nothing
        return _copy_tls12_client_session(session::_TLS12ClientSession)
    finally
        unlock(cache.lock)
    end
end

function _tls12_session_cache_put!(cache::_TLS12ClientSessionCache, key::AbstractString, session::Union{Nothing, _TLS12ClientSession})::Nothing
    key_s = String(key)
    lock(cache.lock)
    try
        if haskey(cache.entries, key_s)
            existing = pop!(cache.entries, key_s)
            _securezero_tls12_client_session!(existing)
            deleteat!(cache.order, findall(==(key_s), cache.order))
        end
        session === nothing && return nothing
        cache.entries[key_s] = _copy_tls12_client_session(session)
        pushfirst!(cache.order, key_s)
        while length(cache.order) > cache.capacity
            evict_key = pop!(cache.order)
            evicted = pop!(cache.entries, evict_key)
            _securezero_tls12_client_session!(evicted)
        end
    finally
        unlock(cache.lock)
    end
    return nothing
end

mutable struct _TLS12ClientHandshakeState
    client_hello::_ClientHelloMsg
    server_hello::_ServerHelloMsg
    certificate_request::_CertificateRequestMsgTLS12
    have_certificate_request::Bool
    server_certificate::_CertificateMsgTLS12
    server_key_exchange::_ServerKeyExchangeMsgTLS12
    new_session_ticket::_NewSessionTicketMsgTLS12
    have_new_session_ticket::Bool
    client_certificate::_CertificateMsgTLS12
    client_certificate_verify::_CertificateVerifyMsg
    client_certificate_chain::Vector{Vector{UInt8}}
    client_private_key::Ptr{Cvoid}
    client_signature_algorithm::UInt16
    resumption_session::Union{Nothing, _TLS12ClientSession}
    cipher_suite::UInt16
    client_protocol::String
    curve_id::UInt16
    did_resume::Bool
end

function _TLS12ClientHandshakeState(client_hello::_ClientHelloMsg, session::Union{Nothing, _TLS12ClientSession} = nothing)
    return _TLS12ClientHandshakeState(
        client_hello,
        _ServerHelloMsg(),
        _CertificateRequestMsgTLS12(),
        false,
        _CertificateMsgTLS12(),
        _ServerKeyExchangeMsgTLS12(),
        _NewSessionTicketMsgTLS12(),
        false,
        _CertificateMsgTLS12(),
        _CertificateVerifyMsg(),
        Vector{Vector{UInt8}}(),
        C_NULL,
        UInt16(0),
        session,
        UInt16(0),
        "",
        UInt16(0),
        false,
    )
end

function _securezero_tls12_client_handshake_state!(state::_TLS12ClientHandshakeState)::Nothing
    state.client_private_key == C_NULL || _free_evp_pkey!(state.client_private_key)
    state.client_private_key = C_NULL
    state.client_signature_algorithm = UInt16(0)
    for cert in state.client_certificate_chain
        _securezero!(cert)
    end
    empty!(state.client_certificate_chain)
    _securezero!(state.new_session_ticket.ticket)
    state.new_session_ticket = _NewSessionTicketMsgTLS12()
    state.have_new_session_ticket = false
    session = state.resumption_session
    session === nothing || _securezero_tls12_client_session!(session::_TLS12ClientSession)
    state.resumption_session = nothing
    return nothing
end

function _tls12_client_hello(config)::_ClientHelloMsg
    rng = Random.RandomDevice()
    hello = _ClientHelloMsg()
    hello.vers = TLS1_2_VERSION
    hello.random = rand(rng, UInt8, 32)
    hello.session_id = rand(rng, UInt8, 32)
    hello.cipher_suites = UInt16[
        _TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_ID,
        _TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_ID,
        _TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256_ID,
        _TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384_ID,
    ]
    hello.compression_methods = UInt8[_TLS_COMPRESSION_NONE]
    hello.server_name = config.server_name === nothing ? "" : String(config.server_name)
    hello.ocsp_stapling = false
    hello.ticket_supported = !config.session_tickets_disabled
    hello.alpn_protocols = copy(config.alpn_protocols)
    hello.supported_curves = _tls12_curve_preferences(config)
    hello.supported_points = UInt8[0x00]
    hello.supported_signature_algorithms = copy(_TLS12_SUPPORTED_SIGNATURE_ALGORITHMS)
    hello.supported_signature_algorithms_cert = copy(_TLS12_SUPPORTED_SIGNATURE_ALGORITHMS)
    hello.secure_renegotiation_supported = false
    hello.extended_master_secret = true
    hello.scts = true
    return hello
end

function _tls12_select_signature_algorithm(pkey::Ptr{Cvoid}, supported_signature_algorithms::AbstractVector{UInt16})::Union{Nothing, UInt16}
    pkey_type = _tls13_pkey_type_name(pkey)
    if pkey_type == "RSA"
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
        return nothing
    end
    if pkey_type == "EC"
        curve_nid = _tls13_ec_group_curve_nid(pkey)
        if curve_nid == _init_p256_group_nid!()
            in(_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256, supported_signature_algorithms) &&
                return _TLS_SIGNATURE_ECDSA_SECP256R1_SHA256
        elseif curve_nid == _init_p384_group_nid!()
            in(_TLS_SIGNATURE_ECDSA_SECP384R1_SHA384, supported_signature_algorithms) &&
                return _TLS_SIGNATURE_ECDSA_SECP384R1_SHA384
        elseif curve_nid == _init_p521_group_nid!()
            in(_TLS_SIGNATURE_ECDSA_SECP521R1_SHA512, supported_signature_algorithms) &&
                return _TLS_SIGNATURE_ECDSA_SECP521R1_SHA512
        else
            throw(ArgumentError("tls: unsupported EC certificate curve $(curve_nid) for TLS 1.2 signature selection"))
        end
        return nothing
    end
    throw(ArgumentError("tls: unsupported TLS 1.2 certificate key type $(pkey_type)"))
end

function _tls12_certificate_type_for_pkey(pkey::Ptr{Cvoid})::UInt8
    pkey_type = _tls13_pkey_type_name(pkey)
    pkey_type == "RSA" && return _TLS12_CERT_TYPE_RSA_SIGN
    pkey_type == "EC" && return _TLS12_CERT_TYPE_ECDSA_SIGN
    throw(ArgumentError("tls: unsupported TLS 1.2 certificate key type $(pkey_type)"))
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
    server_hello.ticket_supported && !state.client_hello.ticket_supported &&
        _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server announced an unrequested TLS 1.2 session ticket")
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

function _tls12_server_certificate_matches_suite!(cipher_suite::UInt16, pubkey::_TLSRSAPublicKey)::Nothing
    cipher_suite in (
        _TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256_ID,
        _TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384_ID,
    ) || _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: TLS 1.2 server certificate is incompatible with the selected cipher suite")
    return nothing
end

function _tls12_server_certificate_matches_suite!(cipher_suite::UInt16, pubkey::_TLSECPublicKey)::Nothing
    cipher_suite in (
        _TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_ID,
        _TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_ID,
    ) || _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: TLS 1.2 server certificate is incompatible with the selected cipher suite")
    return nothing
end

@inline function _tls12_server_certificate_matches_suite!(cipher_suite::UInt16, pubkey::_TLSEd25519PublicKey)::Nothing
    _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: TLS 1.2 server certificate is incompatible with the selected cipher suite")
end

function _tls12_verify_server_key_exchange!(
    state::_TLS12ClientHandshakeState,
    pubkey::_TLSPublicKey,
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

function _tls12_generate_client_key_exchange(
    advertised_curves::AbstractVector{UInt16},
    group::UInt16,
    server_public_key::AbstractVector{UInt8},
)
    in(group, advertised_curves) ||
        _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server selected an unadvertised TLS 1.2 ECDHE curve")
    if group != _TLS_GROUP_X25519 && group != _TLS_GROUP_SECP256R1
        _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: native TLS 1.2 client does not support ECDHE group $(string(group, base = 16))")
    end
    private_key = group == _TLS_GROUP_X25519 ? _tls13_x25519_generate_private_key() : _tls13_p256_generate_private_key()
    client_public_key = UInt8[]
    shared_secret = UInt8[]
    try
        if group == _TLS_GROUP_X25519
            client_public_key = _tls13_x25519_public_key(private_key)
            shared_secret = _tls13_x25519_shared_secret(private_key, server_public_key)
        else
            client_public_key = _tls13_p256_public_key(private_key)
            shared_secret = _tls13_p256_shared_secret(private_key, server_public_key)
        end
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
)::Tuple{_TLSPublicKey, NamedTuple}
    state.certificate_request = _CertificateRequestMsgTLS12()
    state.have_certificate_request = false
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
    _tls12_server_certificate_matches_suite!(state.cipher_suite, pubkey)

    raw_server_key_exchange = _read_handshake_bytes!(io)
    _tls12_require_handshake_message(raw_server_key_exchange, _HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE, "ServerKeyExchange")
    server_key_exchange = _unmarshal_handshake_message(raw_server_key_exchange, transcript, TLS1_2_VERSION)
    server_key_exchange isa _ServerKeyExchangeMsgTLS12 || _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 ServerKeyExchange")
    state.server_key_exchange = server_key_exchange::_ServerKeyExchangeMsgTLS12
    key_exchange = _tls12_verify_server_key_exchange!(state, pubkey, state.server_key_exchange)

    raw_next = _read_handshake_bytes!(io)
    if raw_next[1] == _HANDSHAKE_TYPE_CERTIFICATE_REQUEST
        certificate_request = _unmarshal_handshake_message(raw_next, transcript, TLS1_2_VERSION)
        certificate_request isa _CertificateRequestMsgTLS12 ||
            _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 CertificateRequest")
        state.certificate_request = certificate_request::_CertificateRequestMsgTLS12
        state.have_certificate_request = true
        raw_next = _read_handshake_bytes!(io)
    end
    _tls12_require_handshake_message(raw_next, _HANDSHAKE_TYPE_SERVER_HELLO_DONE, "ServerHelloDone")
    _unmarshal_handshake_message(raw_next, transcript, TLS1_2_VERSION) isa _ServerHelloDoneMsgTLS12 ||
        _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 ServerHelloDone")
    return pubkey, key_exchange
end

function _tls12_prepare_client_identity!(state::_TLS12ClientHandshakeState, config)::Nothing
    state.client_private_key == C_NULL || _free_evp_pkey!(state.client_private_key)
    state.client_private_key = C_NULL
    state.client_signature_algorithm = UInt16(0)
    for cert in state.client_certificate_chain
        _securezero!(cert)
    end
    empty!(state.client_certificate_chain)
    state.have_certificate_request || return nothing
    config.cert_file === nothing && return nothing
    certificate_chain, private_key = _native_tls13_client_identity(config)
    keep_identity = false
    try
        certificate_type = _tls12_certificate_type_for_pkey(private_key)
        in(certificate_type, state.certificate_request.certificate_types) || return nothing
        signature_algorithm = _tls12_select_signature_algorithm(private_key, state.certificate_request.supported_signature_algorithms)
        signature_algorithm === nothing && return nothing
        state.client_certificate_chain = certificate_chain
        state.client_private_key = private_key
        state.client_signature_algorithm = signature_algorithm
        keep_identity = true
        return nothing
    finally
        if !keep_identity
            _free_evp_pkey!(private_key)
            for cert in certificate_chain
                _securezero!(cert)
            end
        end
    end
end

function _tls12_write_client_certificate!(state::_TLS12ClientHandshakeState, io::_TLS12HandshakeRecordIO, transcript::_TLS12TranscriptState)::Nothing
    state.have_certificate_request || return nothing
    msg = _CertificateMsgTLS12([copy(cert) for cert in state.client_certificate_chain])
    state.client_certificate = msg
    raw = _write_handshake_message(msg, transcript)
    _write_handshake_bytes!(io, raw)
    return nothing
end

function _tls12_write_client_certificate_verify!(state::_TLS12ClientHandshakeState, io::_TLS12HandshakeRecordIO, transcript::_TLS12TranscriptState)::Nothing
    state.client_private_key == C_NULL && return nothing
    transcript_bytes = _transcript_buffered_bytes(transcript)
    transcript_bytes === nothing && throw(ArgumentError("tls: TLS 1.2 client certificate verify requires a buffered transcript"))
    signature = _tls12_openssl_sign_signature(state.client_private_key, state.client_signature_algorithm, transcript_bytes)
    try
        msg = _CertificateVerifyMsg(state.client_signature_algorithm, signature)
        state.client_certificate_verify = msg
        raw = _write_handshake_message(msg, transcript)
        _write_handshake_bytes!(io, raw)
    finally
        _securezero!(signature)
    end
    return nothing
end

function _tls12_read_new_session_ticket!(state::_TLS12ClientHandshakeState, io::_TLS12HandshakeRecordIO, transcript::_TLS12TranscriptState)::Nothing
    raw = _read_handshake_bytes!(io)
    _tls12_require_handshake_message(raw, _HANDSHAKE_TYPE_NEW_SESSION_TICKET, "NewSessionTicket")
    ticket = _unmarshal_handshake_message(raw, transcript, TLS1_2_VERSION)
    ticket isa _NewSessionTicketMsgTLS12 || _tls13_fail(_TLS_ALERT_DECODE_ERROR, "tls: malformed TLS 1.2 NewSessionTicket")
    state.new_session_ticket = ticket::_NewSessionTicketMsgTLS12
    state.have_new_session_ticket = true
    return nothing
end

function _tls12_save_client_session!(
    state::_TLS12ClientHandshakeState,
    config,
    cache_key::AbstractString,
    master_secret::Vector{UInt8},
)::Nothing
    state.have_new_session_ticket || return nothing
    isempty(cache_key) && return nothing
    ticket = state.new_session_ticket.ticket
    isempty(ticket) && return nothing
    lifetime_s = state.new_session_ticket.lifetime_hint == UInt32(0) ?
        _TLS12_MAX_SESSION_TICKET_LIFETIME :
        min(state.new_session_ticket.lifetime_hint, _TLS12_MAX_SESSION_TICKET_LIFETIME)
    now_s = UInt64(floor(time()))
    certificates = if state.did_resume
        session = state.resumption_session
        session === nothing ? state.server_certificate.certificates : (session::_TLS12ClientSession).certificates
    else
        state.server_certificate.certificates
    end
    session = _owned_tls12_client_session(
        TLS1_2_VERSION,
        state.cipher_suite,
        now_s,
        now_s + UInt64(lifetime_s),
        ticket,
        master_secret,
        certificates,
        state.client_protocol,
        state.curve_id,
        state.server_hello.extended_master_secret,
    )
    try
        _tls12_session_cache_put!(config._client_session_cache12, cache_key, session)
    finally
        _securezero_tls12_client_session!(session)
    end
    return nothing
end

function _tls12_resumed_handshake!(
    state::_TLS12ClientHandshakeState,
    io::_TLS12HandshakeRecordIO,
    config,
    transcript::_TLS12TranscriptState,
    raw_client_hello::Vector{UInt8},
    raw_server_hello::Vector{UInt8},
    cipher_spec::_TLS12CipherSpec,
    hash_kind::_TLSHashKind,
    cache_key::AbstractString,
)::Nothing
    session = state.resumption_session
    session === nothing && throw(ArgumentError("tls: missing TLS 1.2 resumption session"))
    session.version == TLS1_2_VERSION ||
        _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: server resumed a TLS 1.2 session with a different version")
    session.cipher_suite == state.cipher_suite ||
        _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: server resumed a TLS 1.2 session with a different cipher suite")
    session.ext_master_secret == state.server_hello.extended_master_secret ||
        _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: server resumed a TLS 1.2 session with a different EMS extension")
    master_secret = copy(session.secret)
    client_verify_data = UInt8[]
    expected_server_verify_data = UInt8[]
    client_mac = UInt8[]
    server_mac = UInt8[]
    client_key = UInt8[]
    server_key = UInt8[]
    client_iv = UInt8[]
    server_iv = UInt8[]
    state.curve_id = session.curve_id
    try
        client_mac, server_mac, client_key, server_key, client_iv, server_iv =
            _tls12_keys_from_master_secret(hash_kind, master_secret, state.client_hello.random, state.server_hello.random, 0, cipher_spec.key_length, cipher_spec.iv_length)
        isempty(client_mac) || _tls13_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: unexpected TLS 1.2 MAC key material for AEAD cipher suite")
        isempty(server_mac) || _tls13_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: unexpected TLS 1.2 MAC key material for AEAD cipher suite")
        state.server_hello.ticket_supported && _tls12_read_new_session_ticket!(state, io, transcript)
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
        _tls12_set_write_cipher!(io.state, cipher_spec, client_key, client_iv)
        _tls13_write_tls_plaintext!(io.tcp, _TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC, _TLS12_CHANGE_CIPHER_SPEC_PAYLOAD, TLS1_2_VERSION)
        client_verify_data = _tls12_client_finished_verify_data(hash_kind, master_secret, transcript)
        raw_client_finished = _write_handshake_message(_FinishedMsg(client_verify_data), transcript)
        _tls12_write_record!(io.tcp, io.state.write_cipher, _TLS_RECORD_TYPE_HANDSHAKE, raw_client_finished)
        state.did_resume = true
        _tls12_save_client_session!(state, config, cache_key, master_secret)
    finally
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
    cache_key::AbstractString,
)::Nothing
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
        session = state.resumption_session
        if session !== nothing && state.server_hello.session_id == state.client_hello.session_id
            return _tls12_resumed_handshake!(state, io, config, transcript, raw_client_hello, raw_server_hello, cipher_spec, hash_kind, cache_key)
        end
        pubkey, key_exchange = _tls12_read_server_flight!(state, io, config, transcript)
        state.curve_id = key_exchange.group
        _tls12_prepare_client_identity!(state, config)
        _tls12_write_client_certificate!(state, io, transcript)
        client_key_exchange, generated_shared_secret = _tls12_generate_client_key_exchange(
            state.client_hello.supported_curves,
            key_exchange.group,
            key_exchange.public_key,
        )
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
        _tls12_write_client_certificate_verify!(state, io, transcript)
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
        state.server_hello.ticket_supported && _tls12_read_new_session_ticket!(state, io, transcript)

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
        _tls12_save_client_session!(state, config, cache_key, master_secret)
    finally
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
    cache_key::AbstractString,
)::Nothing
    if state.cipher_suite == _TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256_ID ||
       state.cipher_suite == _TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_ID
        transcript = _TranscriptHash(_HASH_SHA256)
        return _client_handshake_tls12_for_suite!(
            state,
            io,
            config,
            transcript,
            raw_client_hello,
            raw_server_hello,
            _tls12_cipher_spec(state.cipher_suite)::_TLS12CipherSpec,
            _HASH_SHA256,
            cache_key,
        )
    elseif state.cipher_suite == _TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384_ID ||
           state.cipher_suite == _TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_ID
        transcript = _TranscriptHash(_HASH_SHA384)
        return _client_handshake_tls12_for_suite!(
            state,
            io,
            config,
            transcript,
            raw_client_hello,
            raw_server_hello,
            _tls12_cipher_spec(state.cipher_suite)::_TLS12CipherSpec,
            _HASH_SHA384,
            cache_key,
        )
    end
    _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: unsupported native TLS 1.2 cipher suite")
end

function _client_handshake_tls12!(state::_TLS12ClientHandshakeState, io::_TLS12HandshakeRecordIO, config)::Nothing
    raw_client_hello = _marshal_handshake_message(state.client_hello)
    _write_handshake_bytes!(io, raw_client_hello)
    raw_server_hello = _tls12_read_server_hello!(state, io)
    cache_key = _tls13_client_session_cache_key(config, io.tcp)
    return _client_handshake_tls12_after_server_hello!(state, io, config, raw_client_hello, raw_server_hello, cache_key)
end
