const _HELLO_RETRY_REQUEST_RANDOM = UInt8[
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
]

const _HANDSHAKE_TYPE_MESSAGE_HASH = UInt8(254)
const _TLS13_SERVER_SIGNATURE_CONTEXT = "TLS 1.3, server CertificateVerify\0"
const _TLS13_CLIENT_SIGNATURE_CONTEXT = "TLS 1.3, client CertificateVerify\0"
const _TLS13_SIGNATURE_PADDING = fill(UInt8(0x20), 64)
const _TLS13_MAX_SESSION_TICKET_LIFETIME = UInt32(7 * 24 * 60 * 60)
const _TLS13_DOWNGRADE_CANARY_TLS12 = UInt8[0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x01]
const _TLS13_DOWNGRADE_CANARY_TLS11 = UInt8[0x44, 0x4f, 0x57, 0x4e, 0x47, 0x52, 0x44, 0x00]

struct _TLS13ClientSession
    version::UInt16
    cipher_suite::UInt16
    created_at_s::UInt64
    use_by_s::UInt64
    age_add::UInt32
    ticket::Vector{UInt8}
    secret::Vector{UInt8}
    certificates::Vector{Vector{UInt8}}
    alpn_protocol::String
end

function _TLS13ClientSession(
    version::UInt16,
    cipher_suite::UInt16,
    created_at_s::UInt64,
    use_by_s::UInt64,
    age_add::UInt32,
    ticket::AbstractVector{UInt8},
    secret::AbstractVector{UInt8},
    certificates::Vector{Vector{UInt8}},
    alpn_protocol::AbstractString,
)
    return _TLS13ClientSession(
        version,
        cipher_suite,
        created_at_s,
        use_by_s,
        age_add,
        Vector{UInt8}(ticket),
        Vector{UInt8}(secret),
        [copy(cert) for cert in certificates],
        String(alpn_protocol),
    )
end

function _owned_tls13_client_session(
    version::UInt16,
    cipher_suite::UInt16,
    created_at_s::UInt64,
    use_by_s::UInt64,
    age_add::UInt32,
    ticket::AbstractVector{UInt8},
    secret::AbstractVector{UInt8},
    certificates::Vector{Vector{UInt8}},
    alpn_protocol::AbstractString,
)::_TLS13ClientSession
    return _TLS13ClientSession(
        version,
        cipher_suite,
        created_at_s,
        use_by_s,
        age_add,
        copy(ticket),
        copy(secret),
        [copy(cert) for cert in certificates],
        String(alpn_protocol),
    )
end

function _copy_tls13_client_session(session::_TLS13ClientSession)::_TLS13ClientSession
    return _owned_tls13_client_session(
        session.version,
        session.cipher_suite,
        session.created_at_s,
        session.use_by_s,
        session.age_add,
        session.ticket,
        session.secret,
        session.certificates,
        session.alpn_protocol,
    )
end

function _securezero_tls13_client_session!(session::_TLS13ClientSession)::Nothing
    _securezero!(session.ticket)
    _securezero!(session.secret)
    for cert in session.certificates
        _securezero!(cert)
    end
    return nothing
end

mutable struct _TLS13OpenSSLKeyShareProvider
    fixed_x25519_private_key::Vector{UInt8}
    has_fixed_x25519_private_key::Bool
    fixed_p256_private_key::Vector{UInt8}
    has_fixed_p256_private_key::Bool
    private_key::Ptr{Cvoid}
    private_key_group::UInt16
end

function _TLS13OpenSSLKeyShareProvider(;
    fixed_x25519_private_key::Union{Nothing, AbstractVector{UInt8}} = nothing,
    fixed_p256_private_key::Union{Nothing, AbstractVector{UInt8}} = nothing,
)
    return _TLS13OpenSSLKeyShareProvider(
        fixed_x25519_private_key === nothing ? UInt8[] : Vector{UInt8}(fixed_x25519_private_key),
        fixed_x25519_private_key !== nothing,
        fixed_p256_private_key === nothing ? UInt8[] : Vector{UInt8}(fixed_p256_private_key),
        fixed_p256_private_key !== nothing,
        C_NULL,
        UInt16(0),
    )
end

mutable struct _TLS13OpenSSLCertificateVerifier
    verify_peer::Bool
    verify_hostname::Bool
    ca_file::Union{Nothing, String}
    leaf_public_key::_TLSPublicKeyState
end

function _TLS13OpenSSLCertificateVerifier(;
    verify_peer::Bool = false,
    verify_hostname::Bool = verify_peer,
    ca_file::Union{Nothing, AbstractString} = nothing,
)
    return _TLS13OpenSSLCertificateVerifier(
        verify_peer,
        verify_hostname,
        ca_file === nothing ? nothing : String(ca_file),
        nothing,
    )
end

@inline function _tls13_supports_key_share_group(group::UInt16)::Bool
    return group == _TLS_GROUP_X25519 || group == _TLS_GROUP_SECP256R1
end

function _tls13_generate_key_share!(provider::_TLS13OpenSSLKeyShareProvider, group::UInt16)::_TLSKeyShare
    provider.private_key == C_NULL || _free_evp_pkey!(provider.private_key)
    provider.private_key = C_NULL
    provider.private_key_group = UInt16(0)
    if group == _TLS_GROUP_X25519
        provider.private_key = provider.has_fixed_x25519_private_key ?
            _tls13_x25519_private_key_from_bytes(provider.fixed_x25519_private_key) :
            _tls13_x25519_generate_private_key()
        provider.private_key_group = group
        return _TLSKeyShare(group, _tls13_x25519_public_key(provider.private_key))
    end
    if group == _TLS_GROUP_SECP256R1
        provider.private_key = provider.has_fixed_p256_private_key ?
            _tls13_p256_private_key_from_bytes(provider.fixed_p256_private_key) :
            _tls13_p256_generate_private_key()
        provider.private_key_group = group
        return _TLSKeyShare(group, _tls13_p256_public_key(provider.private_key))
    end
    throw(ArgumentError("tls13 client handshake OpenSSL key share provider does not support group $(string(group, base = 16))"))
end

function _tls13_prepare_initial_client_hello!(provider::_TLS13OpenSSLKeyShareProvider, hello::_ClientHelloMsg)::Nothing
    for group in hello.supported_curves
        _tls13_supports_key_share_group(group) || continue
        hello.key_shares = [_tls13_generate_key_share!(provider, group)]
        return nothing
    end
    throw(ArgumentError("tls13 client handshake requires a supported ECDHE group for the OpenSSL key share provider"))
    return nothing
end

function _tls13_resolve_server_shared_secret(provider::_TLS13OpenSSLKeyShareProvider, server_share::_TLSKeyShare)::Vector{UInt8}
    provider.private_key == C_NULL && throw(ArgumentError("tls13 client handshake is missing an ECDHE private key"))
    server_share.group == provider.private_key_group || throw(ArgumentError("tls13 client handshake received a key share for an unexpected group"))
    if server_share.group == _TLS_GROUP_X25519
        return _tls13_x25519_shared_secret(provider.private_key, server_share.data)
    end
    if server_share.group == _TLS_GROUP_SECP256R1
        return _tls13_p256_shared_secret(provider.private_key, server_share.data)
    end
    throw(ArgumentError("tls13 client handshake OpenSSL key share provider does not support group $(string(server_share.group, base = 16))"))
end

function _tls13_process_hello_retry_request!(
    provider::_TLS13OpenSSLKeyShareProvider,
    hello::_ClientHelloMsg,
    server_hello::_ServerHelloMsg,
)::Nothing
    selected_group = server_hello.selected_group
    if !isempty(server_hello.cookie)
        hello.cookie = copy(server_hello.cookie)
    end
    selected_group == 0x0000 && return nothing
    in(selected_group, hello.supported_curves) || throw(ArgumentError("tls: server selected unsupported group"))
    for key_share in hello.key_shares
        key_share.group == selected_group && throw(ArgumentError("tls: server sent an unnecessary HelloRetryRequest key_share"))
    end
    hello.key_shares = [_tls13_generate_key_share!(provider, selected_group)]
    return nothing
end

function _tls13_verify_server_certificates!(
    verifier::_TLS13OpenSSLCertificateVerifier,
    certificate_msg::_CertificateMsgTLS13,
    server_name::AbstractString,
)::Nothing
    isempty(certificate_msg.certificates) && throw(ArgumentError("tls: received empty certificates message"))
    verifier.leaf_public_key = _tls13_verify_server_certificate_chain(
        certificate_msg.certificates,
        server_name;
        verify_peer = verifier.verify_peer,
        verify_hostname = verifier.verify_hostname,
        ca_file = verifier.ca_file,
    )
    return nothing
end

function _tls13_verify_server_certificate_signature!(verifier::_TLS13OpenSSLCertificateVerifier, transcript::_TranscriptHash, certificate_verify::_CertificateVerifyMsg)::Nothing
    verifier.leaf_public_key === nothing && throw(ArgumentError("tls13 client handshake certificate verifier has no leaf public key"))
    signed = _tls13_signed_message(_TLS13_SERVER_SIGNATURE_CONTEXT, transcript)
    _tls13_openssl_verify_signature(verifier.leaf_public_key::_TLSPublicKey, certificate_verify.signature_algorithm, signed, certificate_verify.signature) ||
        _tls_fail(_TLS_ALERT_DECRYPT_ERROR, "tls13 client handshake received an invalid certificate verify signature")
    return nothing
end

function _tls_select_signature_algorithm(pkey::Ptr{Cvoid}, supported_signature_algorithms::AbstractVector{UInt16})::UInt16
    pkey_type = _tls13_pkey_type_name(pkey)
    if pkey_type == "RSA"
        for alg in (
                _TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
                _TLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
                _TLS_SIGNATURE_RSA_PSS_RSAE_SHA512,
            )
            in(alg, supported_signature_algorithms) && return alg
        end
    elseif pkey_type == "EC"
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
            throw(ArgumentError("tls: unsupported EC certificate curve $(curve_nid) for TLS 1.3 signature selection"))
        end
    elseif pkey_type == "ED25519"
        in(_TLS_SIGNATURE_ED25519, supported_signature_algorithms) && return _TLS_SIGNATURE_ED25519
    end
    throw(ArgumentError("tls: peer does not support a usable TLS 1.3 certificate signature algorithm"))
end

function _securezero_tls13_key_share_provider!(provider::_TLS13OpenSSLKeyShareProvider)::Nothing
    provider.private_key == C_NULL || _free_evp_pkey!(provider.private_key)
    provider.private_key = C_NULL
    provider.private_key_group = UInt16(0)
    provider.has_fixed_x25519_private_key && _securezero!(provider.fixed_x25519_private_key)
    provider.has_fixed_p256_private_key && _securezero!(provider.fixed_p256_private_key)
    return nothing
end

function _securezero_tls13_certificate_verifier!(verifier::_TLS13OpenSSLCertificateVerifier)::Nothing
    verifier.leaf_public_key = nothing
    return nothing
end

const _TLS13TranscriptState = Union{
    _TranscriptHash{SHA.SHA2_256_CTX},
    _TranscriptHash{SHA.SHA2_384_CTX},
}

mutable struct _TLS13ClientHandshakeState
    client_hello::_ClientHelloMsg
    client_hello_raw::Vector{UInt8}
    cipher_suite::UInt16
    cipher_spec::_TLS13CipherSpec
    have_cipher_suite::Bool
    psk_cipher_suite::UInt16
    psk_cipher_spec::Union{Nothing, _TLS13CipherSpec}
    key_share_provider::_TLS13OpenSSLKeyShareProvider
    certificate_verifier::_TLS13OpenSSLCertificateVerifier
    client_certificate_chain::Vector{Vector{UInt8}}
    client_private_key::Ptr{Cvoid}
    client_signature_algorithm::UInt16
    resumption_session::Union{Nothing, _TLS13ClientSession}
    shared_secret::Vector{UInt8}
    psk::Vector{UInt8}
    has_psk::Bool
    transcript::Union{Nothing, _TLS13TranscriptState}
    server_hello_raw::Vector{UInt8}
    server_hello::_ServerHelloMsg
    have_server_hello::Bool
    encrypted_extensions::_EncryptedExtensionsMsg
    have_encrypted_extensions::Bool
    certificate_request::_CertificateRequestMsgTLS13
    have_certificate_request::Bool
    client_certificate::_CertificateMsgTLS13
    have_client_certificate::Bool
    client_certificate_verify::_CertificateVerifyMsg
    have_client_certificate_verify::Bool
    server_certificate::_CertificateMsgTLS13
    have_server_certificate::Bool
    server_certificate_verify::_CertificateVerifyMsg
    have_server_certificate_verify::Bool
    server_finished::_FinishedMsg
    have_server_finished::Bool
    client_finished::_FinishedMsg
    have_client_finished::Bool
    using_psk::Bool
    handshake_secret::Vector{UInt8}
    master_secret::Vector{UInt8}
    client_handshake_traffic_secret::Vector{UInt8}
    server_handshake_traffic_secret::Vector{UInt8}
    client_application_traffic_secret::Vector{UInt8}
    server_application_traffic_secret::Vector{UInt8}
    exporter_master_secret::Vector{UInt8}
    peer_new_session_tickets::Vector{_NewSessionTicketMsgTLS13}
    client_protocol::String
    did_hello_retry_request::Bool
    complete::Bool
end

function _securezero_tls13_client_handshake_state!(state::_TLS13ClientHandshakeState)::Nothing
    _securezero_tls13_key_share_provider!(state.key_share_provider)
    _securezero_tls13_certificate_verifier!(state.certificate_verifier)
    state.client_private_key == C_NULL || _free_evp_pkey!(state.client_private_key)
    state.client_private_key = C_NULL
    _securezero!(state.client_hello_raw)
    _securezero!(state.shared_secret)
    _securezero!(state.psk)
    session = state.resumption_session
    session === nothing || _securezero_tls13_client_session!(session::_TLS13ClientSession)
    _securezero!(state.handshake_secret)
    _securezero!(state.master_secret)
    _securezero!(state.client_handshake_traffic_secret)
    _securezero!(state.server_handshake_traffic_secret)
    _securezero!(state.client_application_traffic_secret)
    _securezero!(state.server_application_traffic_secret)
    _securezero!(state.exporter_master_secret)
    for ticket in state.peer_new_session_tickets
        _securezero!(ticket.nonce)
        _securezero!(ticket.label)
    end
    return nothing
end

function _new_tls13_client_handshake_state(
    client_hello::_ClientHelloMsg,
    key_share_provider::_TLS13OpenSSLKeyShareProvider,
    certificate_verifier::_TLS13OpenSSLCertificateVerifier,
    session::Union{Nothing, _TLS13ClientSession},
)
    psk_cipher_suite = session === nothing ? UInt16(0) : session.cipher_suite
    psk_cipher_spec = session === nothing ? nothing : _tls13_cipher_spec(session.cipher_suite)
    return _TLS13ClientHandshakeState(
        client_hello,
        UInt8[],
        UInt16(0),
        _TLS13_AES_128_GCM_SHA256,
        false,
        psk_cipher_suite,
        psk_cipher_spec,
        key_share_provider,
        certificate_verifier,
        Vector{Vector{UInt8}}(),
        C_NULL,
        UInt16(0),
        session,
        UInt8[],
        session === nothing ? UInt8[] : copy(session.secret),
        session !== nothing,
        nothing,
        UInt8[],
        _ServerHelloMsg(),
        false,
        _EncryptedExtensionsMsg(),
        false,
        _CertificateRequestMsgTLS13(),
        false,
        _CertificateMsgTLS13(),
        false,
        _CertificateVerifyMsg(),
        false,
        _CertificateMsgTLS13(),
        false,
        _CertificateVerifyMsg(),
        false,
        _FinishedMsg(),
        false,
        _FinishedMsg(),
        false,
        false,
        UInt8[],
        UInt8[],
        UInt8[],
        UInt8[],
        UInt8[],
        UInt8[],
        UInt8[],
        _NewSessionTicketMsgTLS13[],
        "",
        false,
        false,
    )
end

function _TLS13ClientHandshakeState(
    client_hello::_ClientHelloMsg,
    key_share_provider::_TLS13OpenSSLKeyShareProvider,
    certificate_verifier::_TLS13OpenSSLCertificateVerifier;
    session::Union{Nothing, _TLS13ClientSession} = nothing,
)
    return _TLS13ClientHandshakeState(client_hello, key_share_provider, certificate_verifier, session)
end

function _TLS13ClientHandshakeState(
    client_hello::_ClientHelloMsg,
    key_share_provider::_TLS13OpenSSLKeyShareProvider,
    certificate_verifier::_TLS13OpenSSLCertificateVerifier,
    session::Union{Nothing, _TLS13ClientSession},
)
    _tls13_prepare_initial_client_hello!(key_share_provider, client_hello)
    session !== nothing && (_tls13_cipher_spec(session.cipher_suite) === nothing) &&
        throw(ArgumentError("unsupported TLS 1.3 session cipher suite: $(string(session.cipher_suite, base = 16))"))
    return _new_tls13_client_handshake_state(client_hello, key_share_provider, certificate_verifier, session)
end

function _TLS13ClientHandshakeState(
    client_hello::_ClientHelloMsg,
    _cipher_suite::UInt16,
    key_share_provider::_TLS13OpenSSLKeyShareProvider,
    certificate_verifier::_TLS13OpenSSLCertificateVerifier,
)
    return _TLS13ClientHandshakeState(client_hello, key_share_provider, certificate_verifier)
end

function _new_tls13_binder_transcript(hash_kind::_TLSHashKind)
    hash_kind == _HASH_SHA256 && return _TranscriptHash(_HASH_SHA256; buffer_handshake = false)
    hash_kind == _HASH_SHA384 && return _TranscriptHash(_HASH_SHA384; buffer_handshake = false)
    throw(ArgumentError("unsupported TLS hash kind: $(hash_kind)"))
end

function _new_tls13_handshake_transcript(hash_kind::_TLSHashKind)::_TLS13TranscriptState
    hash_kind == _HASH_SHA256 && return _TranscriptHash(_HASH_SHA256)
    hash_kind == _HASH_SHA384 && return _TranscriptHash(_HASH_SHA384)
    throw(ArgumentError("unsupported TLS hash kind: $(hash_kind)"))
end

@inline function _tls13_selected_transcript(state::_TLS13ClientHandshakeState)::_TLS13TranscriptState
    transcript = state.transcript
    transcript === nothing && throw(ArgumentError("tls13 client handshake transcript is not initialized"))
    return transcript::_TLS13TranscriptState
end

function _compute_and_update_psk_binders!(
    state::_TLS13ClientHandshakeState,
    prefix_transcript::Union{Nothing, _TranscriptHash} = nothing,
)::Nothing
    state.has_psk || return nothing
    psk_spec = state.psk_cipher_spec
    psk_spec === nothing && throw(ArgumentError("tls13 client handshake is missing a PSK cipher suite"))
    hash_kind = psk_spec.hash_kind
    length(state.client_hello.psk_identities) == 1 || throw(ArgumentError("tls13 client handshake expects exactly one PSK identity"))
    length(state.client_hello.psk_binders) == 1 || throw(ArgumentError("tls13 client handshake expects exactly one PSK binder"))
    in(TLS1_3_VERSION, state.client_hello.supported_versions) || throw(ArgumentError("tls13 client handshake requires supported_versions to include TLS 1.3"))
    in(state.psk_cipher_suite, state.client_hello.cipher_suites) || throw(ArgumentError("tls13 client handshake requires the PSK cipher suite in ClientHello"))
    in(_TLS_PSK_MODE_DHE, state.client_hello.psk_modes) || throw(ArgumentError("tls13 client handshake requires the DHE PSK mode"))

    early_secret = _tls13_early_secret(hash_kind, state.psk)
    binder_key = _tls13_resumption_binder_key(early_secret)
    binder_transcript = _new_tls13_binder_transcript(hash_kind)
    if prefix_transcript !== nothing
        prefix_bytes = _transcript_buffered_bytes(prefix_transcript)
        prefix_bytes === nothing && throw(ArgumentError("tls13 client handshake needs buffered transcript bytes to recompute PSK binders"))
        _transcript_update!(binder_transcript, prefix_bytes)
    end
    _transcript_update!(binder_transcript, _marshal_client_hello_without_binders(state.client_hello))
    try
        binder = _tls13_finished_verify_data(hash_kind, binder_key, binder_transcript)
        _update_client_hello_binders!(state.client_hello, [binder])
    finally
        _securezero!(binder_key)
        _destroy_tls13_secret!(early_secret)
    end
    return nothing
end

function _write_client_hello!(state::_TLS13ClientHandshakeState, io)::Nothing
    in(TLS1_3_VERSION, state.client_hello.supported_versions) || throw(ArgumentError("tls13 client handshake requires supported_versions to include TLS 1.3"))
    isempty(state.client_hello.key_shares) && throw(ArgumentError("tls13 client handshake requires at least one key share"))
    state.has_psk && _compute_and_update_psk_binders!(state)
    raw = _marshal_client_hello(state.client_hello)
    state.client_hello_raw = raw
    _write_handshake_bytes!(io, raw)
    return nothing
end

function _check_server_hello_or_hrr!(state::_TLS13ClientHandshakeState)::Nothing
    server_hello = state.server_hello
    server_hello.supported_version == TLS1_3_VERSION || _tls_fail(_TLS_ALERT_PROTOCOL_VERSION, "tls: server selected TLS 1.3 using an invalid supported_version")
    server_hello.vers == TLS1_2_VERSION || _tls_fail(_TLS_ALERT_PROTOCOL_VERSION, "tls: server sent an incorrect legacy version")
    if server_hello.random != _HELLO_RETRY_REQUEST_RANDOM
        random_tail = @view server_hello.random[25:32]
        (random_tail == _TLS13_DOWNGRADE_CANARY_TLS12 || random_tail == _TLS13_DOWNGRADE_CANARY_TLS11) &&
            _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: downgrade attempt detected")
    end

    (server_hello.ocsp_stapling ||
     server_hello.ticket_supported ||
     server_hello.extended_master_secret ||
     server_hello.secure_renegotiation_supported ||
     !isempty(server_hello.secure_renegotiation) ||
     !isempty(server_hello.alpn_protocol) ||
     !isempty(server_hello.scts)) && _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server sent a ServerHello extension forbidden in TLS 1.3")

    server_hello.session_id == state.client_hello.session_id || _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server did not echo the legacy session ID")
    server_hello.compression_method == _TLS_COMPRESSION_NONE || _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server sent non-zero legacy TLS compression method")
    in(server_hello.cipher_suite, state.client_hello.cipher_suites) || _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server chose an unconfigured cipher suite")
    selected_spec = _tls13_cipher_spec(server_hello.cipher_suite)
    selected_spec === nothing && _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server chose an unsupported TLS 1.3 cipher suite")
    if state.have_cipher_suite
        server_hello.cipher_suite == state.cipher_suite || _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server changed cipher suite after a HelloRetryRequest")
    else
        state.cipher_suite = server_hello.cipher_suite
        state.cipher_spec = selected_spec
        state.have_cipher_suite = true
    end
    return nothing
end

function _tls13_set_server_hello!(state::_TLS13ClientHandshakeState, raw::Vector{UInt8})::Nothing
    msg = _unmarshal_server_hello(raw)
    msg === nothing && _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls13 client handshake expected ServerHello")
    state.server_hello_raw = raw
    state.server_hello = msg
    state.have_server_hello = true
    _check_server_hello_or_hrr!(state)
    return nothing
end

function _read_server_hello!(state::_TLS13ClientHandshakeState, io)::Nothing
    raw = _read_handshake_bytes!(io)
    _tls13_set_server_hello!(state, raw)
    return nothing
end

@inline function _tls13_message_hash_frame(digest::AbstractVector{UInt8})::Vector{UInt8}
    length(digest) <= 0xff || throw(ArgumentError("tls13 message_hash digest too long"))
    out = UInt8[_HANDSHAKE_TYPE_MESSAGE_HASH, 0x00, 0x00, UInt8(length(digest))]
    append!(out, digest)
    return out
end

function _tls13_reset_transcript_for_hrr!(state::_TLS13ClientHandshakeState)::Nothing
    state.have_cipher_suite || throw(ArgumentError("tls13 client handshake must select a cipher suite before HelloRetryRequest transcript reset"))
    ch_hash = _hash_data(state.cipher_spec.hash_kind, state.client_hello_raw)
    new_transcript = _new_tls13_handshake_transcript(state.cipher_spec.hash_kind)
    _transcript_update!(new_transcript, _tls13_message_hash_frame(ch_hash))
    _transcript_update!(new_transcript, state.server_hello_raw)
    state.transcript = new_transcript
    return nothing
end

function _process_hello_retry_request!(state::_TLS13ClientHandshakeState, io)::Nothing
    server_hello = state.server_hello
    (server_hello.selected_group == 0x0000 && isempty(server_hello.cookie)) &&
        _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server sent an unnecessary HelloRetryRequest message")
    server_hello.server_share === nothing || _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: received malformed key_share extension")
    _tls13_process_hello_retry_request!(state.key_share_provider, state.client_hello, server_hello)
    state.client_hello.early_data && (state.client_hello.early_data = false)
    _tls13_reset_transcript_for_hrr!(state)
    if state.has_psk
        psk_spec = state.psk_cipher_spec::_TLS13CipherSpec
        if psk_spec.hash_kind == state.cipher_spec.hash_kind
            session = state.resumption_session
            if session !== nothing && !isempty(state.client_hello.psk_identities)
                ticket_age_ms = floor(UInt64, max(0.0, time() - Float64(session.created_at_s)) * 1000.0)
                state.client_hello.psk_identities[1] = _TLSPSKIdentity(
                    copy(session.ticket),
                    UInt32(mod(ticket_age_ms + UInt64(session.age_add), UInt64(1) << 32)),
                )
                _compute_and_update_psk_binders!(state, _tls13_selected_transcript(state))
            end
        else
            state.client_hello.psk_identities = _TLSPSKIdentity[]
            state.client_hello.psk_binders = Vector{UInt8}[]
            _securezero!(state.psk)
            empty!(state.psk)
            state.has_psk = false
            session = state.resumption_session
            session === nothing || _securezero_tls13_client_session!(session::_TLS13ClientSession)
            state.resumption_session = nothing
        end
    end
    raw = _marshal_client_hello(state.client_hello)
    state.client_hello_raw = raw
    _transcript_update!(_tls13_selected_transcript(state), raw)
    _write_handshake_bytes!(io, raw)
    _read_server_hello!(state, io)
    state.server_hello.random == _HELLO_RETRY_REQUEST_RANDOM && _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: server sent two HelloRetryRequest messages")
    state.did_hello_retry_request = true
    return nothing
end

function _process_server_hello!(state::_TLS13ClientHandshakeState)::Nothing
    server_hello = state.server_hello
    server_hello.random == _HELLO_RETRY_REQUEST_RANDOM && _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls13 client handshake still has a HelloRetryRequest pending")
    isempty(server_hello.cookie) || _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server sent a cookie in a normal ServerHello")
    server_hello.selected_group == 0x0000 || _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: malformed key_share extension")
    server_hello.server_share === nothing && _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server did not send a key share")

    server_share = server_hello.server_share::_TLSKeyShare
    isempty(server_share.data) && _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server sent an empty key share")
    supported_group = false
    for key_share in state.client_hello.key_shares
        if key_share.group == server_share.group
            supported_group = true
            break
        end
    end
    supported_group || _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server selected unsupported group")

    _securezero!(state.shared_secret)
    state.shared_secret = _tls13_resolve_server_shared_secret(state.key_share_provider, server_share)
    state.using_psk = false

    if state.server_hello.selected_identity_present
        state.has_psk || _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server selected a PSK without a client PSK")
        Int(state.server_hello.selected_identity) < length(state.client_hello.psk_identities) ||
            _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server selected an invalid PSK")
        psk_spec = state.psk_cipher_spec
        psk_spec === nothing && throw(ArgumentError("tls13 client handshake is missing a PSK cipher suite"))
        psk_spec.hash_kind == state.cipher_spec.hash_kind ||
            _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server selected an invalid PSK and cipher suite pair")
        state.using_psk = true
    end
    return nothing
end

function _establish_handshake_keys!(state::_TLS13ClientHandshakeState)::Nothing
    isempty(state.shared_secret) && throw(ArgumentError("tls13 client handshake needs a shared secret before establishing handshake keys"))
    transcript = _tls13_selected_transcript(state)
    hash_kind = state.cipher_spec.hash_kind
    early_secret = state.using_psk ? _tls13_early_secret(hash_kind, state.psk) : _tls13_early_secret(hash_kind, nothing)
    handshake_secret = _tls13_handshake_secret(early_secret, state.shared_secret)
    master_secret = _tls13_master_secret(handshake_secret)
    try
        _securezero!(state.handshake_secret)
        _securezero!(state.master_secret)
        state.handshake_secret = copy(handshake_secret.secret)
        state.master_secret = copy(master_secret.secret)
        _securezero!(state.client_handshake_traffic_secret)
        _securezero!(state.server_handshake_traffic_secret)
        state.client_handshake_traffic_secret = _tls13_client_handshake_traffic_secret(handshake_secret, transcript)
        state.server_handshake_traffic_secret = _tls13_server_handshake_traffic_secret(handshake_secret, transcript)
    finally
        _destroy_tls13_secret!(master_secret)
        _destroy_tls13_secret!(handshake_secret)
        _destroy_tls13_secret!(early_secret)
    end
    return nothing
end

function _read_server_parameters!(state::_TLS13ClientHandshakeState, io)::Nothing
    raw = _read_handshake_bytes!(io)
    msg = _unmarshal_encrypted_extensions(raw)
    msg === nothing && _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls13 client handshake expected EncryptedExtensions")
    _transcript_update!(_tls13_selected_transcript(state), raw)
    state.encrypted_extensions = msg
    state.have_encrypted_extensions = true

    server_protocol = msg.alpn_protocol
    if !isempty(server_protocol)
        isempty(state.client_hello.alpn_protocols) && _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server advertised unrequested ALPN extension")
        in(server_protocol, state.client_hello.alpn_protocols) || _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server selected unadvertised ALPN protocol")
    end

    (state.client_hello.quic_transport_parameters === nothing) == (msg.quic_transport_parameters === nothing) ||
        _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: unexpected quic_transport_parameters extension")

    if msg.early_data
        state.client_hello.early_data || _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: server sent an unexpected early_data extension")
        _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls13 client handshake early_data acceptance is not implemented yet")
    end

    state.client_protocol = server_protocol
    return nothing
end

function _tls13_signed_message(context::AbstractString, transcript::_TranscriptHash)::Vector{UInt8}
    transcript_digest = _transcript_digest(transcript)
    out = UInt8[]
    sizehint!(out, length(_TLS13_SIGNATURE_PADDING) + sizeof(context) + length(transcript_digest))
    append!(out, _TLS13_SIGNATURE_PADDING)
    append!(out, codeunits(context))
    append!(out, transcript_digest)
    return out
end

function _read_server_certificate!(state::_TLS13ClientHandshakeState, io)::Nothing
    state.using_psk && return nothing

    raw = _read_handshake_bytes!(io)
    msg = _unmarshal_handshake_message(raw)
    msg === nothing && _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls13 client handshake expected Certificate or CertificateRequest")

    if msg isa _CertificateRequestMsgTLS13
        state.certificate_request = msg
        state.have_certificate_request = true
        _transcript_update!(_tls13_selected_transcript(state), raw)
        raw = _read_handshake_bytes!(io)
        msg = _unmarshal_certificate_tls13(raw)
        msg === nothing && _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls13 client handshake expected Certificate after CertificateRequest")
    end

    certificate = msg isa _CertificateMsgTLS13 ? msg : nothing
    certificate === nothing && _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls13 client handshake expected Certificate")
    isempty(certificate.certificates) && _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: received empty certificates message")

    _transcript_update!(_tls13_selected_transcript(state), raw)
    state.server_certificate = certificate
    state.have_server_certificate = true
    _tls13_verify_server_certificates!(state.certificate_verifier, certificate, state.client_hello.server_name)

    raw = _read_handshake_bytes!(io)
    certificate_verify = _unmarshal_certificate_verify(raw)
    certificate_verify === nothing && _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls13 client handshake expected CertificateVerify")
    in(certificate_verify.signature_algorithm, state.client_hello.supported_signature_algorithms) ||
        _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: certificate used with invalid signature algorithm")
    _tls13_verify_server_certificate_signature!(state.certificate_verifier, _tls13_selected_transcript(state), certificate_verify)
    state.server_certificate_verify = certificate_verify
    state.have_server_certificate_verify = true
    _transcript_update!(_tls13_selected_transcript(state), raw)
    return nothing
end

function _read_server_finished!(state::_TLS13ClientHandshakeState, io)::Nothing
    raw = _read_handshake_bytes!(io)
    msg = _unmarshal_finished(raw)
    msg === nothing && _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls13 client handshake expected Finished")
    transcript = _tls13_selected_transcript(state)
    hash_kind = state.cipher_spec.hash_kind
    expected_verify_data = _tls13_finished_verify_data(hash_kind, state.server_handshake_traffic_secret, transcript)
    try
        _constant_time_equals(msg.verify_data, expected_verify_data) || _tls_fail(_TLS_ALERT_DECRYPT_ERROR, "tls: invalid server finished hash")
    finally
        _securezero!(expected_verify_data)
    end

    state.server_finished = msg
    state.have_server_finished = true
    _transcript_update!(transcript, raw)

    _securezero!(state.client_application_traffic_secret)
    _securezero!(state.server_application_traffic_secret)
    _securezero!(state.exporter_master_secret)
    state.client_application_traffic_secret = _tls13_derive_secret(hash_kind, state.master_secret, "c ap traffic", transcript)
    state.server_application_traffic_secret = _tls13_derive_secret(hash_kind, state.master_secret, "s ap traffic", transcript)
    state.exporter_master_secret = _tls13_derive_secret(hash_kind, state.master_secret, "exp master", transcript)
    return nothing
end

function _send_client_certificate!(state::_TLS13ClientHandshakeState, io)::Nothing
    state.have_certificate_request || return nothing
    msg = if isempty(state.client_certificate_chain)
        _CertificateMsgTLS13()
    else
        out = _CertificateMsgTLS13()
        out.certificates = [copy(cert) for cert in state.client_certificate_chain]
        state.client_signature_algorithm = _tls_select_signature_algorithm(
            state.client_private_key,
            state.certificate_request.supported_signature_algorithms,
        )
        out
    end
    state.client_certificate = msg
    state.have_client_certificate = true
    raw = _marshal_certificate_tls13(msg)
    _transcript_update!(_tls13_selected_transcript(state), raw)
    _write_handshake_bytes!(io, raw)
    if !isempty(msg.certificates)
        signed = _tls13_signed_message(_TLS13_CLIENT_SIGNATURE_CONTEXT, _tls13_selected_transcript(state))
        try
            signature = _tls13_openssl_sign_signature(state.client_private_key, state.client_signature_algorithm, signed)
            try
                verify_msg = _CertificateVerifyMsg(state.client_signature_algorithm, signature)
                state.client_certificate_verify = verify_msg
                state.have_client_certificate_verify = true
                raw = _marshal_certificate_verify(verify_msg)
                _transcript_update!(_tls13_selected_transcript(state), raw)
                _write_handshake_bytes!(io, raw)
            finally
                _securezero!(signature)
            end
        finally
            _securezero!(signed)
        end
    end
    return nothing
end

function _send_client_finished!(state::_TLS13ClientHandshakeState, io)::Nothing
    transcript = _tls13_selected_transcript(state)
    verify_data = _tls13_finished_verify_data(state.cipher_spec.hash_kind, state.client_handshake_traffic_secret, transcript)
    state.client_finished = _FinishedMsg(verify_data)
    state.have_client_finished = true
    raw = _marshal_finished(state.client_finished)
    _transcript_update!(transcript, raw)
    _write_handshake_bytes!(io, raw)
    return nothing
end

function _read_post_handshake_messages!(state::_TLS13ClientHandshakeState, io)::Nothing
    while _remaining_handshake_messages(io) > 0
        raw = _read_handshake_bytes!(io)
        msg = _unmarshal_new_session_ticket_tls13(raw)
        msg === nothing && throw(ArgumentError("tls13 client handshake expected only NewSessionTicket post-handshake messages"))
        msg.lifetime == 0x00000000 && continue
        msg.lifetime <= _TLS13_MAX_SESSION_TICKET_LIFETIME ||
            throw(ArgumentError("tls: received a session ticket with invalid lifetime"))
        isempty(msg.label) && throw(ArgumentError("tls: received a session ticket with empty opaque ticket label"))
        push!(state.peer_new_session_tickets, msg)
    end
    return nothing
end

function _client_handshake_tls13_after_server_hello!(state::_TLS13ClientHandshakeState, io)::Nothing
    if state.server_hello.random == _HELLO_RETRY_REQUEST_RANDOM
        _tls13_send_dummy_change_cipher_spec!(io)
        _process_hello_retry_request!(state, io)
    else
        transcript = _new_tls13_handshake_transcript(state.cipher_spec.hash_kind)
        _transcript_update!(transcript, state.client_hello_raw)
        state.transcript = transcript
    end
    _transcript_update!(_tls13_selected_transcript(state), state.server_hello_raw)
    _process_server_hello!(state)
    _tls13_send_dummy_change_cipher_spec!(io)
    _establish_handshake_keys!(state)
    _tls13_on_handshake_keys!(io, state)
    _read_server_parameters!(state, io)
    _read_server_certificate!(state, io)
    _read_server_finished!(state, io)
    _tls13_on_server_finished!(io, state)
    _send_client_certificate!(state, io)
    _send_client_finished!(state, io)
    _tls13_on_client_finished!(io, state)
    state.complete = true
    _read_post_handshake_messages!(state, io)
    return nothing
end

function _client_handshake_tls13!(state::_TLS13ClientHandshakeState, io)::Nothing
    state.complete && throw(ArgumentError("tls13 client handshake already complete"))
    _write_client_hello!(state, io)
    _read_server_hello!(state, io)
    return _client_handshake_tls13_after_server_hello!(state, io)
end
