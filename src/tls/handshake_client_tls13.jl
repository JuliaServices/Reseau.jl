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

mutable struct _HandshakeMessageFlightIO
    inbound::Vector{Vector{UInt8}}
    inbound_pos::Int
    outbound::Vector{Vector{UInt8}}
end

_HandshakeMessageFlightIO() = _HandshakeMessageFlightIO(Vector{UInt8}[], 1, Vector{UInt8}[])
_HandshakeMessageFlightIO(inbound::Vector{Vector{UInt8}}) = _HandshakeMessageFlightIO(inbound, 1, Vector{UInt8}[])

@inline function _remaining_handshake_messages(io::_HandshakeMessageFlightIO)::Int
    return length(io.inbound) - io.inbound_pos + 1
end

function _read_handshake_bytes!(io::_HandshakeMessageFlightIO)::Vector{UInt8}
    io.inbound_pos <= length(io.inbound) || throw(EOFError("tls13 handshake queue exhausted"))
    raw = io.inbound[io.inbound_pos]
    io.inbound_pos += 1
    return raw
end

struct _TLS13StaticSharedSecretProvider
    shared_secret::Vector{UInt8}
end

_TLS13StaticSharedSecretProvider(shared_secret::AbstractVector{UInt8}) =
    _TLS13StaticSharedSecretProvider(Vector{UInt8}(shared_secret))

struct _TLS13ScriptedKeyShareProvider
    initial_share::_TLSKeyShare
    initial_expected_server_share::Vector{UInt8}
    initial_shared_secret::Vector{UInt8}
    has_retry_share::Bool
    retry_share::_TLSKeyShare
    retry_expected_server_share::Vector{UInt8}
    retry_shared_secret::Vector{UInt8}
end

function _TLS13ScriptedKeyShareProvider(
    initial_share::_TLSKeyShare,
    initial_expected_server_share::AbstractVector{UInt8},
    initial_shared_secret::AbstractVector{UInt8},
)
    return _TLS13ScriptedKeyShareProvider(
        _TLSKeyShare(initial_share.group, copy(initial_share.data)),
        Vector{UInt8}(initial_expected_server_share),
        Vector{UInt8}(initial_shared_secret),
        false,
        _TLSKeyShare(UInt16(0), UInt8[]),
        UInt8[],
        UInt8[],
    )
end

function _TLS13ScriptedKeyShareProvider(
    initial_share::_TLSKeyShare,
    initial_expected_server_share::AbstractVector{UInt8},
    initial_shared_secret::AbstractVector{UInt8},
    retry_share::_TLSKeyShare,
    retry_expected_server_share::AbstractVector{UInt8},
    retry_shared_secret::AbstractVector{UInt8},
)
    return _TLS13ScriptedKeyShareProvider(
        _TLSKeyShare(initial_share.group, copy(initial_share.data)),
        Vector{UInt8}(initial_expected_server_share),
        Vector{UInt8}(initial_shared_secret),
        true,
        _TLSKeyShare(retry_share.group, copy(retry_share.data)),
        Vector{UInt8}(retry_expected_server_share),
        Vector{UInt8}(retry_shared_secret),
    )
end

struct _TLS13NoCertificateVerifier end

struct _TLS13ScriptedCertificateVerifier
    certificates::Vector{Vector{UInt8}}
    server_name::String
    signature_algorithm::UInt16
    signed_message::Vector{UInt8}
    signature::Vector{UInt8}
end

function _TLS13ScriptedCertificateVerifier(
    certificates::Vector{Vector{UInt8}},
    server_name::AbstractString,
    signature_algorithm::UInt16,
    signed_message::AbstractVector{UInt8},
    signature::AbstractVector{UInt8},
)
    return _TLS13ScriptedCertificateVerifier(
        [copy(cert) for cert in certificates],
        String(server_name),
        signature_algorithm,
        Vector{UInt8}(signed_message),
        Vector{UInt8}(signature),
    )
end

mutable struct _TLS13OpenSSLKeyShareProvider
    fixed_private_key::Vector{UInt8}
    has_fixed_private_key::Bool
    private_key::Ptr{Cvoid}
end

function _TLS13OpenSSLKeyShareProvider(; fixed_private_key::Union{Nothing, AbstractVector{UInt8}} = nothing)
    return _TLS13OpenSSLKeyShareProvider(
        fixed_private_key === nothing ? UInt8[] : Vector{UInt8}(fixed_private_key),
        fixed_private_key !== nothing,
        C_NULL,
    )
end

mutable struct _TLS13OpenSSLCertificateVerifier
    leaf_public_key::Ptr{Cvoid}
end

_TLS13OpenSSLCertificateVerifier() = _TLS13OpenSSLCertificateVerifier(C_NULL)

@inline _copy_tls13_key_share(share::_TLSKeyShare) = _TLSKeyShare(share.group, copy(share.data))

function _tls13_prepare_initial_client_hello!(::_TLS13StaticSharedSecretProvider, ::_ClientHelloMsg)::Nothing
    return nothing
end

function _tls13_prepare_initial_client_hello!(provider::_TLS13OpenSSLKeyShareProvider, hello::_ClientHelloMsg)::Nothing
    in(_TLS_GROUP_X25519, hello.supported_curves) || throw(ArgumentError("tls13 client handshake requires X25519 in supported_curves for the OpenSSL key share provider"))
    provider.private_key == C_NULL || _free_evp_pkey!(provider.private_key)
    provider.private_key = provider.has_fixed_private_key ?
        _tls13_x25519_private_key_from_bytes(provider.fixed_private_key) :
        _tls13_x25519_generate_private_key()
    hello.key_shares = [_TLSKeyShare(_TLS_GROUP_X25519, _tls13_x25519_public_key(provider.private_key))]
    return nothing
end

function _tls13_prepare_initial_client_hello!(provider::_TLS13ScriptedKeyShareProvider, hello::_ClientHelloMsg)::Nothing
    hello.key_shares = [_copy_tls13_key_share(provider.initial_share)]
    return nothing
end

function _tls13_resolve_server_shared_secret(provider::_TLS13StaticSharedSecretProvider, ::_TLSKeyShare)::Vector{UInt8}
    return copy(provider.shared_secret)
end

function _tls13_resolve_server_shared_secret(provider::_TLS13OpenSSLKeyShareProvider, server_share::_TLSKeyShare)::Vector{UInt8}
    provider.private_key == C_NULL && throw(ArgumentError("tls13 client handshake is missing an X25519 private key"))
    server_share.group == _TLS_GROUP_X25519 || throw(ArgumentError("tls13 client handshake OpenSSL key share provider only supports X25519 today"))
    return _tls13_x25519_shared_secret(provider.private_key, server_share.data)
end

function _tls13_resolve_server_shared_secret(provider::_TLS13ScriptedKeyShareProvider, server_share::_TLSKeyShare)::Vector{UInt8}
    if server_share.group == provider.initial_share.group &&
       server_share.data == provider.initial_expected_server_share
        return copy(provider.initial_shared_secret)
    end
    if provider.has_retry_share &&
       server_share.group == provider.retry_share.group &&
       server_share.data == provider.retry_expected_server_share
        return copy(provider.retry_shared_secret)
    end
    throw(ArgumentError("tls13 client handshake received an unexpected server key share"))
end

function _tls13_process_hello_retry_request!(
    ::_TLS13StaticSharedSecretProvider,
    ::_ClientHelloMsg,
    ::_ServerHelloMsg,
)::Nothing
    throw(ArgumentError("tls13 client handshake HelloRetryRequest requires a key share provider"))
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
    provider.private_key == C_NULL || _free_evp_pkey!(provider.private_key)
    provider.private_key = C_NULL
    throw(ArgumentError("tls13 client handshake OpenSSL key share provider only supports X25519 today"))
end

function _tls13_process_hello_retry_request!(
    provider::_TLS13ScriptedKeyShareProvider,
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
    provider.has_retry_share || throw(ArgumentError("tls13 client handshake is missing a retry key share"))
    provider.retry_share.group == selected_group || throw(ArgumentError("tls13 client handshake has no retry key share for the selected group"))
    hello.key_shares = [_copy_tls13_key_share(provider.retry_share)]
    return nothing
end

function _tls13_verify_server_certificates!(::_TLS13NoCertificateVerifier, ::_CertificateMsgTLS13, ::AbstractString)::Nothing
    throw(ArgumentError("tls13 client handshake certificate path requires a certificate verifier"))
end

function _tls13_verify_server_certificates!(
    verifier::_TLS13OpenSSLCertificateVerifier,
    certificate_msg::_CertificateMsgTLS13,
    ::AbstractString,
)::Nothing
    isempty(certificate_msg.certificates) && throw(ArgumentError("tls: received empty certificates message"))
    verifier.leaf_public_key == C_NULL || _free_evp_pkey!(verifier.leaf_public_key)
    verifier.leaf_public_key = _tls13_pubkey_from_der_certificate(certificate_msg.certificates[1])
    return nothing
end

function _tls13_verify_server_certificates!(
    verifier::_TLS13ScriptedCertificateVerifier,
    certificate_msg::_CertificateMsgTLS13,
    server_name::AbstractString,
)::Nothing
    certificate_msg.certificates == verifier.certificates || throw(ArgumentError("tls13 client handshake received an unexpected certificate chain"))
    verifier.server_name == server_name || throw(ArgumentError("tls13 client handshake verifier expected a different server name"))
    return nothing
end

function _tls13_verify_server_certificate_signature!(
    ::_TLS13NoCertificateVerifier,
    ::_TranscriptHash,
    ::_CertificateVerifyMsg,
)::Nothing
    throw(ArgumentError("tls13 client handshake certificate path requires a certificate verifier"))
end

function _tls13_verify_server_certificate_signature!(
    verifier::_TLS13OpenSSLCertificateVerifier,
    transcript::_TranscriptHash,
    certificate_verify::_CertificateVerifyMsg,
)::Nothing
    verifier.leaf_public_key == C_NULL && throw(ArgumentError("tls13 client handshake certificate verifier has no leaf public key"))
    signed = _tls13_signed_message(_TLS13_SERVER_SIGNATURE_CONTEXT, transcript)
    _tls13_openssl_verify_signature(verifier.leaf_public_key, certificate_verify.signature_algorithm, signed, certificate_verify.signature) ||
        throw(ArgumentError("tls13 client handshake received an invalid certificate verify signature"))
    return nothing
end

function _tls13_verify_server_certificate_signature!(
    verifier::_TLS13ScriptedCertificateVerifier,
    transcript::_TranscriptHash,
    certificate_verify::_CertificateVerifyMsg,
)::Nothing
    certificate_verify.signature_algorithm == verifier.signature_algorithm ||
        throw(ArgumentError("tls13 client handshake received an unexpected certificate verify signature algorithm"))
    signed = _tls13_signed_message(_TLS13_SERVER_SIGNATURE_CONTEXT, transcript)
    signed == verifier.signed_message || throw(ArgumentError("tls13 client handshake computed an unexpected certificate verify transcript"))
    _constant_time_equals(certificate_verify.signature, verifier.signature) ||
        throw(ArgumentError("tls13 client handshake received an invalid certificate verify signature"))
    return nothing
end

function _securezero_tls13_key_share_provider!(provider::_TLS13StaticSharedSecretProvider)::Nothing
    _securezero!(provider.shared_secret)
    return nothing
end

function _securezero_tls13_key_share_provider!(provider::_TLS13OpenSSLKeyShareProvider)::Nothing
    provider.private_key == C_NULL || _free_evp_pkey!(provider.private_key)
    provider.private_key = C_NULL
    provider.has_fixed_private_key && _securezero!(provider.fixed_private_key)
    return nothing
end

function _securezero_tls13_key_share_provider!(provider::_TLS13ScriptedKeyShareProvider)::Nothing
    _securezero!(provider.initial_shared_secret)
    _securezero!(provider.retry_shared_secret)
    return nothing
end

function _securezero_tls13_certificate_verifier!(::_TLS13NoCertificateVerifier)::Nothing
    return nothing
end

function _securezero_tls13_certificate_verifier!(verifier::_TLS13OpenSSLCertificateVerifier)::Nothing
    verifier.leaf_public_key == C_NULL || _free_evp_pkey!(verifier.leaf_public_key)
    verifier.leaf_public_key = C_NULL
    return nothing
end

function _securezero_tls13_certificate_verifier!(::_TLS13ScriptedCertificateVerifier)::Nothing
    return nothing
end

const _TLS13TranscriptState = Union{
    _TranscriptHash{SHA.SHA2_256_CTX},
    _TranscriptHash{SHA.SHA2_384_CTX},
}

const _TLS13KeyShareProviderState = Union{
    _TLS13StaticSharedSecretProvider,
    _TLS13OpenSSLKeyShareProvider,
    _TLS13ScriptedKeyShareProvider,
}

const _TLS13CertificateVerifierState = Union{
    _TLS13NoCertificateVerifier,
    _TLS13OpenSSLCertificateVerifier,
    _TLS13ScriptedCertificateVerifier,
}

mutable struct _TLS13ClientHandshakeState{HK}
    client_hello::_ClientHelloMsg
    cipher_suite::UInt16
    cipher_spec::_TLS13CipherSpec
    key_share_provider::_TLS13KeyShareProviderState
    certificate_verifier::_TLS13CertificateVerifierState
    shared_secret::Vector{UInt8}
    psk::Vector{UInt8}
    has_psk::Bool
    transcript::_TLS13TranscriptState
    server_hello_raw::Vector{UInt8}
    server_hello::_ServerHelloMsg
    have_server_hello::Bool
    encrypted_extensions::_EncryptedExtensionsMsg
    have_encrypted_extensions::Bool
    certificate_request::_CertificateRequestMsgTLS13
    have_certificate_request::Bool
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
    complete::Bool
end

function _securezero_tls13_client_handshake_state!(state::_TLS13ClientHandshakeState)::Nothing
    _securezero_tls13_key_share_provider!(state.key_share_provider)
    _securezero_tls13_certificate_verifier!(state.certificate_verifier)
    _securezero!(state.shared_secret)
    _securezero!(state.psk)
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
    ::Val{HK},
    client_hello::_ClientHelloMsg,
    cipher_suite::UInt16,
    cipher_spec::_TLS13CipherSpec,
    key_share_provider,
    certificate_verifier,
    transcript::_TLS13TranscriptState,
) where {HK}
    return _TLS13ClientHandshakeState{HK}(
        client_hello,
        cipher_suite,
        cipher_spec,
        key_share_provider,
        certificate_verifier,
        UInt8[],
        UInt8[],
        false,
        transcript,
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
    )
end

function _TLS13ClientHandshakeState(client_hello::_ClientHelloMsg, cipher_suite::UInt16, key_share_provider, certificate_verifier)
    _tls13_prepare_initial_client_hello!(key_share_provider, client_hello)
    if cipher_suite == _TLS13_AES_128_GCM_SHA256_ID
        transcript = _TranscriptHash(_HASH_SHA256)
        return _new_tls13_client_handshake_state(Val{_HASH_SHA256}(), client_hello, cipher_suite, _TLS13_AES_128_GCM_SHA256, key_share_provider, certificate_verifier, transcript)
    elseif cipher_suite == _TLS13_AES_256_GCM_SHA384_ID
        transcript = _TranscriptHash(_HASH_SHA384)
        return _new_tls13_client_handshake_state(Val{_HASH_SHA384}(), client_hello, cipher_suite, _TLS13_AES_256_GCM_SHA384, key_share_provider, certificate_verifier, transcript)
    elseif cipher_suite == _TLS13_CHACHA20_POLY1305_SHA256_ID
        transcript = _TranscriptHash(_HASH_SHA256)
        return _new_tls13_client_handshake_state(Val{_HASH_SHA256}(), client_hello, cipher_suite, _TLS13_CHACHA20_POLY1305_SHA256, key_share_provider, certificate_verifier, transcript)
    end
    throw(ArgumentError("unsupported TLS 1.3 cipher suite: $(string(cipher_suite, base = 16))"))
end

function _TLS13ClientHandshakeState(client_hello::_ClientHelloMsg, cipher_suite::UInt16, shared_secret::AbstractVector{UInt8})
    return _TLS13ClientHandshakeState(
        client_hello,
        cipher_suite,
        _TLS13StaticSharedSecretProvider(shared_secret),
        _TLS13NoCertificateVerifier(),
    )
end

function _TLS13ClientHandshakeState(client_hello::_ClientHelloMsg, cipher_suite::UInt16, shared_secret::AbstractVector{UInt8}, psk::AbstractVector{UInt8})
    state = _TLS13ClientHandshakeState(client_hello, cipher_suite, shared_secret)
    state.psk = Vector{UInt8}(psk)
    state.has_psk = true
    return state
end

function _new_tls13_binder_transcript(hash_kind::_TLSHashKind)
    hash_kind == _HASH_SHA256 && return _TranscriptHash(_HASH_SHA256; buffer_handshake = false)
    hash_kind == _HASH_SHA384 && return _TranscriptHash(_HASH_SHA384; buffer_handshake = false)
    throw(ArgumentError("unsupported TLS hash kind: $(hash_kind)"))
end

function _compute_and_update_psk_binders!(
    state::_TLS13ClientHandshakeState{HK},
    prefix_transcript::Union{Nothing, _TranscriptHash} = nothing,
)::Nothing where {HK}
    state.has_psk || return nothing
    length(state.client_hello.psk_identities) == 1 || throw(ArgumentError("tls13 client handshake expects exactly one PSK identity"))
    length(state.client_hello.psk_binders) == 1 || throw(ArgumentError("tls13 client handshake expects exactly one PSK binder"))
    in(TLS1_3_VERSION, state.client_hello.supported_versions) || throw(ArgumentError("tls13 client handshake requires supported_versions to include TLS 1.3"))
    in(state.cipher_suite, state.client_hello.cipher_suites) || throw(ArgumentError("tls13 client handshake requires the selected cipher suite in ClientHello"))
    in(_TLS_PSK_MODE_DHE, state.client_hello.psk_modes) || throw(ArgumentError("tls13 client handshake requires the DHE PSK mode"))

    early_secret = _tls13_early_secret(HK, state.psk)
    binder_key = _tls13_resumption_binder_key(early_secret)
    binder_transcript = _new_tls13_binder_transcript(HK)
    if prefix_transcript !== nothing
        prefix_bytes = _transcript_buffered_bytes(prefix_transcript)
        prefix_bytes === nothing && throw(ArgumentError("tls13 client handshake needs buffered transcript bytes to recompute PSK binders"))
        _transcript_update!(binder_transcript, prefix_bytes)
    end
    _transcript_update!(binder_transcript, _marshal_client_hello_without_binders(state.client_hello))
    try
        binder = _tls13_finished_verify_data(HK, binder_key, binder_transcript)
        _update_client_hello_binders!(state.client_hello, [binder])
    finally
        _securezero!(binder_key)
        _destroy_tls13_secret!(early_secret)
    end
    return nothing
end

function _write_client_hello!(state::_TLS13ClientHandshakeState, io::_HandshakeMessageFlightIO)::Nothing
    in(TLS1_3_VERSION, state.client_hello.supported_versions) || throw(ArgumentError("tls13 client handshake requires supported_versions to include TLS 1.3"))
    in(state.cipher_suite, state.client_hello.cipher_suites) || throw(ArgumentError("tls13 client handshake requires the selected cipher suite in ClientHello"))
    isempty(state.client_hello.key_shares) && throw(ArgumentError("tls13 client handshake requires at least one key share"))
    state.has_psk && _compute_and_update_psk_binders!(state)
    raw = _marshal_client_hello(state.client_hello)
    _transcript_update!(state.transcript, raw)
    push!(io.outbound, raw)
    return nothing
end

function _check_server_hello_or_hrr!(state::_TLS13ClientHandshakeState)::Nothing
    server_hello = state.server_hello
    server_hello.supported_version == TLS1_3_VERSION || throw(ArgumentError("tls: server selected TLS 1.3 using an invalid supported_version"))
    server_hello.vers == TLS1_2_VERSION || throw(ArgumentError("tls: server sent an incorrect legacy version"))

    (server_hello.ocsp_stapling ||
     server_hello.ticket_supported ||
     server_hello.extended_master_secret ||
     server_hello.secure_renegotiation_supported ||
     !isempty(server_hello.secure_renegotiation) ||
     !isempty(server_hello.alpn_protocol) ||
     !isempty(server_hello.scts)) && throw(ArgumentError("tls: server sent a ServerHello extension forbidden in TLS 1.3"))

    server_hello.session_id == state.client_hello.session_id || throw(ArgumentError("tls: server did not echo the legacy session ID"))
    server_hello.compression_method == _TLS_COMPRESSION_NONE || throw(ArgumentError("tls: server sent non-zero legacy TLS compression method"))
    server_hello.cipher_suite == state.cipher_suite || throw(ArgumentError("tls: server chose an unexpected cipher suite"))
    in(server_hello.cipher_suite, state.client_hello.cipher_suites) || throw(ArgumentError("tls: server chose an unconfigured cipher suite"))
    return nothing
end

function _read_server_hello!(state::_TLS13ClientHandshakeState, io::_HandshakeMessageFlightIO)::Nothing
    raw = _read_handshake_bytes!(io)
    msg = _unmarshal_server_hello(raw)
    msg === nothing && throw(ArgumentError("tls13 client handshake expected ServerHello"))
    state.server_hello_raw = raw
    state.server_hello = msg
    state.have_server_hello = true
    _check_server_hello_or_hrr!(state)
    return nothing
end

@inline function _tls13_message_hash_frame(digest::AbstractVector{UInt8})::Vector{UInt8}
    length(digest) <= 0xff || throw(ArgumentError("tls13 message_hash digest too long"))
    out = UInt8[_HANDSHAKE_TYPE_MESSAGE_HASH, 0x00, 0x00, UInt8(length(digest))]
    append!(out, digest)
    return out
end

function _tls13_reset_transcript_for_hrr!(state::_TLS13ClientHandshakeState{HK})::Nothing where {HK}
    ch_hash = _transcript_digest(state.transcript)
    new_transcript = HK == _HASH_SHA256 ? _TranscriptHash(_HASH_SHA256) : _TranscriptHash(_HASH_SHA384)
    _transcript_update!(new_transcript, _tls13_message_hash_frame(ch_hash))
    _transcript_update!(new_transcript, state.server_hello_raw)
    state.transcript = new_transcript
    return nothing
end

function _process_hello_retry_request!(state::_TLS13ClientHandshakeState{HK}, io::_HandshakeMessageFlightIO)::Nothing where {HK}
    server_hello = state.server_hello
    (server_hello.selected_group == 0x0000 && isempty(server_hello.cookie)) &&
        throw(ArgumentError("tls: server sent an unnecessary HelloRetryRequest message"))
    server_hello.server_share === nothing || throw(ArgumentError("tls: received malformed key_share extension"))
    _tls13_process_hello_retry_request!(state.key_share_provider, state.client_hello, server_hello)
    state.client_hello.early_data && (state.client_hello.early_data = false)
    _tls13_reset_transcript_for_hrr!(state)
    state.has_psk && _compute_and_update_psk_binders!(state, state.transcript)
    raw = _marshal_client_hello(state.client_hello)
    _transcript_update!(state.transcript, raw)
    push!(io.outbound, raw)
    _read_server_hello!(state, io)
    state.server_hello.random == _HELLO_RETRY_REQUEST_RANDOM && throw(ArgumentError("tls: server sent two HelloRetryRequest messages"))
    return nothing
end

function _process_server_hello!(state::_TLS13ClientHandshakeState)::Nothing
    server_hello = state.server_hello
    server_hello.random == _HELLO_RETRY_REQUEST_RANDOM && throw(ArgumentError("tls13 client handshake still has a HelloRetryRequest pending"))
    isempty(server_hello.cookie) || throw(ArgumentError("tls: server sent a cookie in a normal ServerHello"))
    server_hello.selected_group == 0x0000 || throw(ArgumentError("tls: malformed key_share extension"))
    server_hello.server_share === nothing && throw(ArgumentError("tls: server did not send a key share"))

    server_share = server_hello.server_share::_TLSKeyShare
    isempty(server_share.data) && throw(ArgumentError("tls: server sent an empty key share"))
    supported_group = false
    for key_share in state.client_hello.key_shares
        if key_share.group == server_share.group
            supported_group = true
            break
        end
    end
    supported_group || throw(ArgumentError("tls: server selected unsupported group"))

    _securezero!(state.shared_secret)
    state.shared_secret = _tls13_resolve_server_shared_secret(state.key_share_provider, server_share)
    state.using_psk = false

    if state.server_hello.selected_identity_present
        state.has_psk || throw(ArgumentError("tls: server selected a PSK without a client PSK"))
        Int(state.server_hello.selected_identity) < length(state.client_hello.psk_identities) ||
            throw(ArgumentError("tls: server selected an invalid PSK"))
        state.using_psk = true
    end
    return nothing
end

function _establish_handshake_keys!(state::_TLS13ClientHandshakeState{HK})::Nothing where {HK}
    isempty(state.shared_secret) && throw(ArgumentError("tls13 client handshake needs a shared secret before establishing handshake keys"))
    early_secret = state.using_psk ? _tls13_early_secret(HK, state.psk) : _tls13_early_secret(HK, UInt8[])
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

function _read_server_parameters!(state::_TLS13ClientHandshakeState, io::_HandshakeMessageFlightIO)::Nothing
    raw = _read_handshake_bytes!(io)
    msg = _unmarshal_encrypted_extensions(raw)
    msg === nothing && throw(ArgumentError("tls13 client handshake expected EncryptedExtensions"))
    _transcript_update!(state.transcript, raw)
    state.encrypted_extensions = msg
    state.have_encrypted_extensions = true

    server_protocol = msg.alpn_protocol
    if !isempty(server_protocol)
        isempty(state.client_hello.alpn_protocols) && throw(ArgumentError("tls: server advertised unrequested ALPN extension"))
        in(server_protocol, state.client_hello.alpn_protocols) || throw(ArgumentError("tls: server selected unadvertised ALPN protocol"))
    end

    (state.client_hello.quic_transport_parameters === nothing) == (msg.quic_transport_parameters === nothing) ||
        throw(ArgumentError("tls: unexpected quic_transport_parameters extension"))

    if msg.early_data
        state.client_hello.early_data || throw(ArgumentError("tls: server sent an unexpected early_data extension"))
        throw(ArgumentError("tls13 client handshake early_data acceptance is not implemented yet"))
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

function _read_server_certificate!(state::_TLS13ClientHandshakeState, io::_HandshakeMessageFlightIO)::Nothing
    state.using_psk && return nothing

    raw = _read_handshake_bytes!(io)
    msg = _unmarshal_handshake_message(raw)
    msg === nothing && throw(ArgumentError("tls13 client handshake expected Certificate or CertificateRequest"))

    if msg isa _CertificateRequestMsgTLS13
        state.certificate_request = msg
        state.have_certificate_request = true
        _transcript_update!(state.transcript, raw)
        raw = _read_handshake_bytes!(io)
        msg = _unmarshal_certificate_tls13(raw)
        msg === nothing && throw(ArgumentError("tls13 client handshake expected Certificate after CertificateRequest"))
    end

    certificate = msg isa _CertificateMsgTLS13 ? msg : nothing
    certificate === nothing && throw(ArgumentError("tls13 client handshake expected Certificate"))
    isempty(certificate.certificates) && throw(ArgumentError("tls: received empty certificates message"))

    _transcript_update!(state.transcript, raw)
    state.server_certificate = certificate
    state.have_server_certificate = true
    _tls13_verify_server_certificates!(state.certificate_verifier, certificate, state.client_hello.server_name)

    raw = _read_handshake_bytes!(io)
    certificate_verify = _unmarshal_certificate_verify(raw)
    certificate_verify === nothing && throw(ArgumentError("tls13 client handshake expected CertificateVerify"))
    in(certificate_verify.signature_algorithm, state.client_hello.supported_signature_algorithms) ||
        throw(ArgumentError("tls: certificate used with invalid signature algorithm"))
    _tls13_verify_server_certificate_signature!(state.certificate_verifier, state.transcript, certificate_verify)
    state.server_certificate_verify = certificate_verify
    state.have_server_certificate_verify = true
    _transcript_update!(state.transcript, raw)
    return nothing
end

function _read_server_finished!(state::_TLS13ClientHandshakeState{HK}, io::_HandshakeMessageFlightIO)::Nothing where {HK}
    raw = _read_handshake_bytes!(io)
    msg = _unmarshal_finished(raw)
    msg === nothing && throw(ArgumentError("tls13 client handshake expected Finished"))
    expected_verify_data = _tls13_finished_verify_data(HK, state.server_handshake_traffic_secret, state.transcript)
    try
        _constant_time_equals(msg.verify_data, expected_verify_data) || throw(ArgumentError("tls: invalid server finished hash"))
    finally
        _securezero!(expected_verify_data)
    end

    state.server_finished = msg
    state.have_server_finished = true
    _transcript_update!(state.transcript, raw)

    _securezero!(state.client_application_traffic_secret)
    _securezero!(state.server_application_traffic_secret)
    _securezero!(state.exporter_master_secret)
    state.client_application_traffic_secret = _tls13_derive_secret(HK, state.master_secret, "c ap traffic", state.transcript)
    state.server_application_traffic_secret = _tls13_derive_secret(HK, state.master_secret, "s ap traffic", state.transcript)
    state.exporter_master_secret = _tls13_derive_secret(HK, state.master_secret, "exp master", state.transcript)
    return nothing
end

function _send_client_certificate!(state::_TLS13ClientHandshakeState, io::_HandshakeMessageFlightIO)::Nothing
    state.have_certificate_request || return nothing
    raw = _marshal_certificate_tls13(_CertificateMsgTLS13())
    _transcript_update!(state.transcript, raw)
    push!(io.outbound, raw)
    return nothing
end

function _send_client_finished!(state::_TLS13ClientHandshakeState{HK}, io::_HandshakeMessageFlightIO)::Nothing where {HK}
    verify_data = _tls13_finished_verify_data(HK, state.client_handshake_traffic_secret, state.transcript)
    state.client_finished = _FinishedMsg(verify_data)
    state.have_client_finished = true
    raw = _marshal_finished(state.client_finished)
    _transcript_update!(state.transcript, raw)
    push!(io.outbound, raw)
    return nothing
end

function _read_post_handshake_messages!(state::_TLS13ClientHandshakeState, io::_HandshakeMessageFlightIO)::Nothing
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

function _client_handshake_tls13!(state::_TLS13ClientHandshakeState, io::_HandshakeMessageFlightIO)::Nothing
    state.complete && throw(ArgumentError("tls13 client handshake already complete"))
    _write_client_hello!(state, io)
    _read_server_hello!(state, io)
    state.server_hello.random == _HELLO_RETRY_REQUEST_RANDOM && _process_hello_retry_request!(state, io)
    _transcript_update!(state.transcript, state.server_hello_raw)
    _process_server_hello!(state)
    _establish_handshake_keys!(state)
    _read_server_parameters!(state, io)
    _read_server_certificate!(state, io)
    _read_server_finished!(state, io)
    _send_client_certificate!(state, io)
    _send_client_finished!(state, io)
    state.complete = true
    _read_post_handshake_messages!(state, io)
    return nothing
end
