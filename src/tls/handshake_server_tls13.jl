function _read_tls_file_bytes(path::String)::Vector{UInt8}
    file = ccall(:fopen, Ptr{Cvoid}, (Cstring, Cstring), path, "rb")
    file == C_NULL && throw(SystemError("fopen", Base.Libc.errno()))
    bytes = UInt8[]
    chunk = Vector{UInt8}(undef, 8192)
    try
        while true
            n = Int(ccall(:fread, Csize_t, (Ptr{UInt8}, Csize_t, Csize_t, Ptr{Cvoid}), chunk, 1, length(chunk), file))
            if n == 0
                ccall(:feof, Cint, (Ptr{Cvoid},), file) != 0 && return bytes
                ccall(:ferror, Cint, (Ptr{Cvoid},), file) == 0 && throw(SystemError("fread", 0))
                throw(SystemError("fread", Base.Libc.errno()))
            end
            offset = length(bytes)
            resize!(bytes, offset + n)
            copyto!(bytes, offset + 1, chunk, 1, n)
        end
    finally
        ccall(:fclose, Cint, (Ptr{Cvoid},), file)
    end
end

const _TLS13_MAX_CLIENT_PSK_IDENTITIES = 5
const _TLS13_SERVER_SUPPORTED_SIGNATURE_ALGORITHMS = (
    _TLS_SIGNATURE_ED25519,
    _TLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
    _TLS_SIGNATURE_ECDSA_SECP384R1_SHA384,
    _TLS_SIGNATURE_ECDSA_SECP521R1_SHA512,
    _TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
    _TLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
    _TLS_SIGNATURE_RSA_PSS_RSAE_SHA512,
)

struct _TLS13ServerSession
    version::UInt16
    cipher_suite::UInt16
    created_at_s::UInt64
    use_by_s::UInt64
    age_add::UInt32
    label::Vector{UInt8}
    secret::Vector{UInt8}
    client_certificates::Vector{Vector{UInt8}}
    alpn_protocol::String
end

function _TLS13ServerSession(
    version::UInt16,
    cipher_suite::UInt16,
    created_at_s::UInt64,
    use_by_s::UInt64,
    age_add::UInt32,
    label::AbstractVector{UInt8},
    secret::AbstractVector{UInt8},
    client_certificates::Vector{Vector{UInt8}},
    alpn_protocol::AbstractString,
)
    return _TLS13ServerSession(
        version,
        cipher_suite,
        created_at_s,
        use_by_s,
        age_add,
        Vector{UInt8}(label),
        Vector{UInt8}(secret),
        [copy(cert) for cert in client_certificates],
        String(alpn_protocol),
    )
end

function _owned_tls13_server_session(
    version::UInt16,
    cipher_suite::UInt16,
    created_at_s::UInt64,
    use_by_s::UInt64,
    age_add::UInt32,
    label::AbstractVector{UInt8},
    secret::AbstractVector{UInt8},
    client_certificates::Vector{Vector{UInt8}},
    alpn_protocol::AbstractString,
)::_TLS13ServerSession
    return _TLS13ServerSession(
        version,
        cipher_suite,
        created_at_s,
        use_by_s,
        age_add,
        copy(label),
        copy(secret),
        [copy(cert) for cert in client_certificates],
        String(alpn_protocol),
    )
end

function _copy_tls13_server_session(session::_TLS13ServerSession)::_TLS13ServerSession
    return _owned_tls13_server_session(
        session.version,
        session.cipher_suite,
        session.created_at_s,
        session.use_by_s,
        session.age_add,
        session.label,
        session.secret,
        session.client_certificates,
        session.alpn_protocol,
    )
end

function _securezero_tls13_server_session!(session::_TLS13ServerSession)::Nothing
    _securezero!(session.label)
    _securezero!(session.secret)
    for cert in session.client_certificates
        _securezero!(cert)
    end
    return nothing
end

mutable struct _TLS13ServerSessionCache
    lock::ReentrantLock
    entries::Dict{String, _TLS13ServerSession}
    order::Vector{String}
    capacity::Int
end

function _TLS13ServerSessionCache(capacity::Integer = 64)::_TLS13ServerSessionCache
    Int(capacity) > 0 || throw(ArgumentError("tls13 server session cache capacity must be positive"))
    return _TLS13ServerSessionCache(ReentrantLock(), Dict{String, _TLS13ServerSession}(), String[], Int(capacity))
end

@inline _tls13_server_session_cache_key(label::AbstractVector{UInt8}) = bytes2hex(label)

function _tls13_server_session_cache_peek(cache::_TLS13ServerSessionCache, label::AbstractVector{UInt8})::Union{Nothing, _TLS13ServerSession}
    key_s = _tls13_server_session_cache_key(label)
    lock(cache.lock)
    try
        session = get(cache.entries, key_s, nothing)
        session === nothing && return nothing
        return _copy_tls13_server_session(session::_TLS13ServerSession)
    finally
        unlock(cache.lock)
    end
end

function _tls13_server_session_cache_delete!(cache::_TLS13ServerSessionCache, label::AbstractVector{UInt8})::Nothing
    key_s = _tls13_server_session_cache_key(label)
    lock(cache.lock)
    try
        session = pop!(cache.entries, key_s, nothing)
        session === nothing && return nothing
        deleteat!(cache.order, findall(==(key_s), cache.order))
        _securezero_tls13_server_session!(session::_TLS13ServerSession)
    finally
        unlock(cache.lock)
    end
    return nothing
end

function _tls13_server_session_cache_put!(cache::_TLS13ServerSessionCache, session::Union{Nothing, _TLS13ServerSession})::Nothing
    session === nothing && return nothing
    key_s = _tls13_server_session_cache_key(session.label)
    lock(cache.lock)
    try
        if haskey(cache.entries, key_s)
            existing = pop!(cache.entries, key_s)
            _securezero_tls13_server_session!(existing)
            deleteat!(cache.order, findall(==(key_s), cache.order))
        end
        cache.entries[key_s] = _copy_tls13_server_session(session)
        pushfirst!(cache.order, key_s)
        while length(cache.order) > cache.capacity
            evict_key = pop!(cache.order)
            evicted = pop!(cache.entries, evict_key)
            _securezero_tls13_server_session!(evicted)
        end
    finally
        unlock(cache.lock)
    end
    return nothing
end

mutable struct _TLS13ServerHandshakeState
    client_hello::_ClientHelloMsg
    client_hello_raw::Vector{UInt8}
    server_hello::_ServerHelloMsg
    server_hello_raw::Vector{UInt8}
    encrypted_extensions::_EncryptedExtensionsMsg
    certificate_request::_CertificateRequestMsgTLS13
    certificate::_CertificateMsgTLS13
    certificate_verify::_CertificateVerifyMsg
    client_certificate::_CertificateMsgTLS13
    client_certificate_verify::_CertificateVerifyMsg
    client_finished::_FinishedMsg
    cipher_suite::UInt16
    cipher_spec::_TLS13CipherSpec
    transcript::_TLS13TranscriptState
    key_share_provider::_TLS13OpenSSLKeyShareProvider
    private_key::Ptr{Cvoid}
    client_leaf_public_key::Ptr{Cvoid}
    certificate_chain::Vector{Vector{UInt8}}
    peer_certificates::Vector{Vector{UInt8}}
    selected_signature_algorithm::UInt16
    selected_alpn::String
    selected_group::UInt16
    selected_psk_identity::UInt16
    has_selected_psk_identity::Bool
    shared_secret::Vector{UInt8}
    psk::Vector{UInt8}
    using_psk::Bool
    resumption_session::Union{Nothing, _TLS13ServerSession}
    handshake_secret::Vector{UInt8}
    master_secret::Vector{UInt8}
    client_handshake_traffic_secret::Vector{UInt8}
    server_handshake_traffic_secret::Vector{UInt8}
    client_application_traffic_secret::Vector{UInt8}
    server_application_traffic_secret::Vector{UInt8}
    exporter_master_secret::Vector{UInt8}
    did_hello_retry_request::Bool
    complete::Bool
end

function _TLS13ServerHandshakeState(config)::_TLS13ServerHandshakeState
    cert_file = config.cert_file === nothing ? throw(ArgumentError("tls13 native server requires cert_file")) : (config.cert_file::String)
    key_file = config.key_file === nothing ? throw(ArgumentError("tls13 native server requires key_file")) : (config.key_file::String)
    cert_pem = _read_tls_file_bytes(cert_file)
    key_pem = _read_tls_file_bytes(key_file)
    certificate_chain = _tls13_load_x509_pem_chain(cert_pem)
    private_key = _tls13_load_private_key_pem(key_pem)
    _securezero!(key_pem)
    return _TLS13ServerHandshakeState(
        _ClientHelloMsg(),
        UInt8[],
        _ServerHelloMsg(),
        UInt8[],
        _EncryptedExtensionsMsg(),
        _CertificateRequestMsgTLS13(),
        _CertificateMsgTLS13(),
        _CertificateVerifyMsg(),
        _CertificateMsgTLS13(),
        _CertificateVerifyMsg(),
        _FinishedMsg(),
        UInt16(0),
        _TLS13_AES_128_GCM_SHA256,
        _new_tls13_handshake_transcript(_HASH_SHA256),
        _TLS13OpenSSLKeyShareProvider(),
        private_key,
        C_NULL,
        certificate_chain,
        Vector{Vector{UInt8}}(),
        UInt16(0),
        "",
        UInt16(0),
        UInt16(0),
        false,
        UInt8[],
        UInt8[],
        false,
        nothing,
        UInt8[],
        UInt8[],
        UInt8[],
        UInt8[],
        UInt8[],
        UInt8[],
        UInt8[],
        false,
        false,
    )
end

function _securezero_tls13_server_handshake_state!(state::_TLS13ServerHandshakeState)::Nothing
    _securezero_tls13_key_share_provider!(state.key_share_provider)
    state.private_key == C_NULL || _free_evp_pkey!(state.private_key)
    state.private_key = C_NULL
    state.client_leaf_public_key == C_NULL || _free_evp_pkey!(state.client_leaf_public_key)
    state.client_leaf_public_key = C_NULL
    _securezero!(state.client_hello_raw)
    _securezero!(state.server_hello_raw)
    _securezero!(state.shared_secret)
    _securezero!(state.psk)
    session = state.resumption_session
    session === nothing || _securezero_tls13_server_session!(session::_TLS13ServerSession)
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
        _native_tls13_only(config)
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
    _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: client did not offer a supported TLS 1.3 cipher suite")
end

function _tls_select_server_alpn(config, client_hello::_ClientHelloMsg)::String
    isempty(config.alpn_protocols) && return ""
    isempty(client_hello.alpn_protocols) && return ""
    for proto in config.alpn_protocols
        in(proto, client_hello.alpn_protocols) && return proto
    end
    return ""
end

function _tls13_select_server_signature_algorithm(pkey::Ptr{Cvoid}, client_hello::_ClientHelloMsg)::UInt16
    return _tls_select_signature_algorithm(pkey, client_hello.supported_signature_algorithms)
end

function _tls13_find_client_key_share(client_hello::_ClientHelloMsg, group::UInt16)::Union{Nothing, _TLSKeyShare}
    for key_share in client_hello.key_shares
        key_share.group == group && return key_share
    end
    return nothing
end

function _tls13_server_preferred_group(client_hello::_ClientHelloMsg, config)::UInt16
    mutual_groups = UInt16[]
    for group in _tls13_curve_preferences(config)
        in(group, client_hello.supported_curves) && push!(mutual_groups, group)
    end
    isempty(mutual_groups) && _tls13_fail(_TLS_ALERT_HANDSHAKE_FAILURE, "tls: no key exchanges supported by both client and server")
    for group in mutual_groups
        _tls13_find_client_key_share(client_hello, group) === nothing || return group
    end
    return mutual_groups[1]
end

function _tls13_server_key_share!(state::_TLS13ServerHandshakeState, group::UInt16)::_TLSKeyShare
    client_share = _tls13_find_client_key_share(state.client_hello, group)
    client_share === nothing && _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: missing client key share for selected group")
    server_share = _tls13_generate_key_share!(state.key_share_provider, group)
    _securezero!(state.shared_secret)
    state.shared_secret = _tls13_resolve_server_shared_secret(state.key_share_provider, client_share)
    return server_share
end

function _tls13_illegal_client_hello_change(client_hello::_ClientHelloMsg, first_hello::_ClientHelloMsg)::Bool
    return client_hello.vers != first_hello.vers ||
        client_hello.random != first_hello.random ||
        client_hello.session_id != first_hello.session_id ||
        client_hello.cipher_suites != first_hello.cipher_suites ||
        client_hello.compression_methods != first_hello.compression_methods ||
        client_hello.server_name != first_hello.server_name ||
        client_hello.ocsp_stapling != first_hello.ocsp_stapling ||
        client_hello.supported_curves != first_hello.supported_curves ||
        client_hello.supported_points != first_hello.supported_points ||
        client_hello.ticket_supported != first_hello.ticket_supported ||
        client_hello.session_ticket != first_hello.session_ticket ||
        client_hello.supported_signature_algorithms != first_hello.supported_signature_algorithms ||
        client_hello.supported_signature_algorithms_cert != first_hello.supported_signature_algorithms_cert ||
        client_hello.secure_renegotiation_supported != first_hello.secure_renegotiation_supported ||
        client_hello.secure_renegotiation != first_hello.secure_renegotiation ||
        client_hello.extended_master_secret != first_hello.extended_master_secret ||
        client_hello.alpn_protocols != first_hello.alpn_protocols ||
        client_hello.scts != first_hello.scts ||
        client_hello.supported_versions != first_hello.supported_versions ||
        client_hello.psk_modes != first_hello.psk_modes ||
        client_hello.quic_transport_parameters != first_hello.quic_transport_parameters ||
        client_hello.encrypted_client_hello != first_hello.encrypted_client_hello ||
        client_hello.extensions != first_hello.extensions
end

function _tls13_set_client_hello!(state::_TLS13ServerHandshakeState, raw::Vector{UInt8})::Nothing
    client_hello = _unmarshal_client_hello(raw)
    client_hello === nothing && _tls13_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls13 server handshake expected ClientHello")
    in(TLS1_3_VERSION, client_hello.supported_versions) || _tls13_fail(_TLS_ALERT_PROTOCOL_VERSION, "tls: client did not offer TLS 1.3")
    in(_TLS_COMPRESSION_NONE, client_hello.compression_methods) || _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: client sent unsupported compression methods")
    state.client_hello = client_hello
    state.client_hello_raw = raw
    return nothing
end

function _read_client_hello!(state::_TLS13ServerHandshakeState, io)::Nothing
    raw = _read_handshake_bytes!(io)
    _tls13_set_client_hello!(state, raw)
    return nothing
end

function _send_hello_retry_request!(state::_TLS13ServerHandshakeState, io, selected_group::UInt16)::Nothing
    _transcript_update!(state.transcript, state.client_hello_raw)
    ch_hash = _transcript_digest(state.transcript)
    transcript = _new_tls13_handshake_transcript(state.cipher_spec.hash_kind)
    _transcript_update!(transcript, _tls13_message_hash_frame(ch_hash))
    hrr = _ServerHelloMsg()
    hrr.vers = TLS1_2_VERSION
    hrr.random = copy(_HELLO_RETRY_REQUEST_RANDOM)
    hrr.session_id = copy(state.client_hello.session_id)
    hrr.cipher_suite = state.cipher_suite
    hrr.compression_method = _TLS_COMPRESSION_NONE
    hrr.supported_version = TLS1_3_VERSION
    hrr.selected_group = selected_group
    raw = _marshal_server_hello(hrr)
    _transcript_update!(transcript, raw)
    state.transcript = transcript
    _write_handshake_bytes!(io, raw)
    _tls13_send_dummy_change_cipher_spec!(io)
    state.did_hello_retry_request = true
    return nothing
end

function _read_second_client_hello!(state::_TLS13ServerHandshakeState, io, selected_group::UInt16)::Nothing
    first_hello = state.client_hello
    raw = _read_handshake_bytes!(io)
    client_hello = _unmarshal_client_hello(raw)
    client_hello === nothing && _tls13_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls13 server handshake expected second ClientHello")
    length(client_hello.key_shares) == 1 || _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: client did not send one key share in second ClientHello")
    key_share = client_hello.key_shares[1]::_TLSKeyShare
    key_share.group == selected_group || _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: client sent unexpected key share in second ClientHello")
    client_hello.early_data && _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: client indicated early data in second ClientHello")
    _tls13_illegal_client_hello_change(client_hello, first_hello) &&
        _tls13_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: client illegally modified second ClientHello")
    state.client_hello = client_hello
    state.client_hello_raw = raw
    return nothing
end

function _prepare_server_negotiation!(state::_TLS13ServerHandshakeState, io, config)::Nothing
    state.cipher_suite, state.cipher_spec = _tls13_select_server_cipher_suite(state.client_hello)
    state.selected_signature_algorithm = _tls13_select_server_signature_algorithm(state.private_key, state.client_hello)
    state.selected_alpn = _tls_select_server_alpn(config, state.client_hello)
    state.transcript = _new_tls13_handshake_transcript(state.cipher_spec.hash_kind)
    state.selected_group = _tls13_server_preferred_group(state.client_hello, config)
    if _tls13_find_client_key_share(state.client_hello, state.selected_group) === nothing
        _send_hello_retry_request!(state, io, state.selected_group)
        _read_second_client_hello!(state, io, state.selected_group)
    end
    return nothing
end

function _tls13_server_session_client_auth_ok(session::_TLS13ServerSession, config)::Bool
    mode = config.client_auth
    has_client_certificates = !isempty(session.client_certificates)
    if mode == ClientAuthMode.NoClientCert
        return !has_client_certificates
    end
    if mode == ClientAuthMode.RequireAnyClientCert || mode == ClientAuthMode.RequireAndVerifyClientCert
        has_client_certificates || return false
    end
    has_client_certificates || return true
    if mode == ClientAuthMode.VerifyClientCertIfGiven || mode == ClientAuthMode.RequireAndVerifyClientCert
        pkey = Ptr{Cvoid}(C_NULL)
        try
            pkey = _tls13_verify_client_certificate_chain(
                session.client_certificates;
                verify_peer = true,
                ca_file = _effective_ca_file(config; is_server = true),
            )
            return true
        catch
            return false
        finally
            _free_evp_pkey!(pkey)
        end
    end
    return true
end

function _check_for_resumption!(state::_TLS13ServerHandshakeState, config)::Nothing
    state.using_psk = false
    state.has_selected_psk_identity = false
    state.selected_psk_identity = UInt16(0)
    session = state.resumption_session
    session === nothing || _securezero_tls13_server_session!(session::_TLS13ServerSession)
    state.resumption_session = nothing
    _securezero!(state.psk)
    empty!(state.psk)
    config.session_tickets_disabled && return nothing
    in(_TLS_PSK_MODE_DHE, state.client_hello.psk_modes) || return nothing
    length(state.client_hello.psk_identities) == length(state.client_hello.psk_binders) ||
        _tls13_fail(_TLS_ALERT_DECRYPT_ERROR, "tls: invalid or missing PSK binders")
    isempty(state.client_hello.psk_identities) && return nothing
    max_identities = min(length(state.client_hello.psk_identities), _TLS13_MAX_CLIENT_PSK_IDENTITIES)
    for i in 1:max_identities
        identity = state.client_hello.psk_identities[i]
        session = _tls13_server_session_cache_peek(config._server_session_cache, identity.label)
        session === nothing && continue
        early_secret = _TLS13EarlySecret(state.cipher_spec.hash_kind, UInt8[])
        binder_key = UInt8[]
        binder = UInt8[]
        selected = false
        try
            session.version == TLS1_3_VERSION || continue
            now_s = UInt64(floor(time()))
            now_s <= session.use_by_s || continue
            session_spec = _tls13_cipher_spec(session.cipher_suite)
            session_spec === nothing && continue
            session_spec.hash_kind == state.cipher_spec.hash_kind || continue
            session.alpn_protocol == state.selected_alpn || continue
            # Mirror Go here: without 0-RTT support, `obfuscated_ticket_age` does not
            # gate resumption, so binder validation and ticket lifetime remain the
            # relevant checks.
            early_secret = _tls13_early_secret(state.cipher_spec.hash_kind, session.secret)
            binder_key = _tls13_resumption_binder_key(early_secret)
            binder_transcript = _new_tls13_binder_transcript(state.cipher_spec.hash_kind)
            prefix_bytes = _transcript_buffered_bytes(state.transcript)
            if prefix_bytes !== nothing && !isempty(prefix_bytes)
                _transcript_update!(binder_transcript, prefix_bytes)
            end
            _transcript_update!(binder_transcript, _marshal_client_hello_without_binders(state.client_hello))
            binder = _tls13_finished_verify_data(state.cipher_spec.hash_kind, binder_key, binder_transcript)
            _constant_time_equals(state.client_hello.psk_binders[i], binder) || continue
            _tls13_server_session_client_auth_ok(session, config) || continue
            state.psk = copy(session.secret)
            state.using_psk = true
            state.resumption_session = session
            state.selected_psk_identity = UInt16(i - 1)
            state.has_selected_psk_identity = true
            state.peer_certificates = [copy(cert) for cert in session.client_certificates]
            _tls13_server_session_cache_delete!(config._server_session_cache, identity.label)
            selected = true
            return nothing
        finally
            _securezero!(binder)
            _securezero!(binder_key)
            _destroy_tls13_secret!(early_secret)
            selected || _securezero_tls13_server_session!(session)
        end
    end
    return nothing
end

function _send_server_hello!(state::_TLS13ServerHandshakeState, io)::Nothing
    server_share = _tls13_server_key_share!(state, state.selected_group)
    _transcript_update!(state.transcript, state.client_hello_raw)
    rng = Random.RandomDevice()
    server_hello = _ServerHelloMsg()
    server_hello.vers = TLS1_2_VERSION
    server_hello.random = rand(rng, UInt8, 32)
    server_hello.session_id = copy(state.client_hello.session_id)
    server_hello.cipher_suite = state.cipher_suite
    server_hello.compression_method = _TLS_COMPRESSION_NONE
    server_hello.supported_version = TLS1_3_VERSION
    server_hello.server_share = server_share
    if state.has_selected_psk_identity
        server_hello.selected_identity_present = true
        server_hello.selected_identity = state.selected_psk_identity
    end
    state.server_hello = server_hello
    raw = _marshal_server_hello(server_hello)
    state.server_hello_raw = raw
    _transcript_update!(state.transcript, raw)
    _write_handshake_bytes!(io, raw)
    return nothing
end

function _establish_server_handshake_keys!(state::_TLS13ServerHandshakeState)::Nothing
    isempty(state.shared_secret) && throw(ArgumentError("tls13 native server requires a shared secret"))
    early_secret = state.using_psk ? _tls13_early_secret(state.cipher_spec.hash_kind, state.psk) : _tls13_early_secret(state.cipher_spec.hash_kind, nothing)
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

function _request_client_certificate(config)::Bool
    return config.client_auth != ClientAuthMode.NoClientCert
end

function _send_certificate_request!(state::_TLS13ServerHandshakeState, io)::Nothing
    msg = _CertificateRequestMsgTLS13()
    msg.supported_signature_algorithms = UInt16[_TLS13_SERVER_SUPPORTED_SIGNATURE_ALGORITHMS...]
    msg.supported_signature_algorithms_cert = UInt16[_TLS13_SERVER_SUPPORTED_SIGNATURE_ALGORITHMS...]
    state.certificate_request = msg
    raw = _marshal_certificate_request_tls13(msg)
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

function _read_client_certificate!(state::_TLS13ServerHandshakeState, io, config)::Nothing
    if state.using_psk || !_request_client_certificate(config)
        return nothing
    end
    raw = _read_handshake_bytes!(io)
    msg = _unmarshal_certificate_tls13(raw)
    msg === nothing && _tls13_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls13 server handshake expected client Certificate")
    state.client_certificate = msg
    _transcript_update!(state.transcript, raw)
    state.client_leaf_public_key == C_NULL || _free_evp_pkey!(state.client_leaf_public_key)
    state.client_leaf_public_key = C_NULL
    state.peer_certificates = [copy(cert) for cert in msg.certificates]
    has_client_certificates = !isempty(msg.certificates)
    if !has_client_certificates
        if config.client_auth == ClientAuthMode.RequireAnyClientCert || config.client_auth == ClientAuthMode.RequireAndVerifyClientCert
            _tls13_fail(_TLS_ALERT_CERTIFICATE_REQUIRED, "tls: client did not provide a certificate")
        end
        return nothing
    end
    verify_peer = config.client_auth == ClientAuthMode.VerifyClientCertIfGiven || config.client_auth == ClientAuthMode.RequireAndVerifyClientCert
    state.client_leaf_public_key = _tls13_verify_client_certificate_chain(
        msg.certificates;
        verify_peer,
        ca_file = verify_peer ? _effective_ca_file(config; is_server = true) : nothing,
    )
    raw = _read_handshake_bytes!(io)
    certificate_verify = _unmarshal_certificate_verify(raw)
    certificate_verify === nothing && _tls13_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls13 server handshake expected client CertificateVerify")
    in(certificate_verify.signature_algorithm, state.certificate_request.supported_signature_algorithms) ||
        _tls13_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: client certificate used with invalid signature algorithm")
    signed = _tls13_signed_message(_TLS13_CLIENT_SIGNATURE_CONTEXT, state.transcript)
    try
        _tls13_openssl_verify_signature(state.client_leaf_public_key, certificate_verify.signature_algorithm, signed, certificate_verify.signature) ||
            _tls13_fail(_TLS_ALERT_DECRYPT_ERROR, "tls: invalid signature by the client certificate")
    finally
        _securezero!(signed)
    end
    state.client_certificate_verify = certificate_verify
    _transcript_update!(state.transcript, raw)
    return nothing
end

function _read_client_finished!(state::_TLS13ServerHandshakeState, io)::Nothing
    raw = _read_handshake_bytes!(io)
    msg = _unmarshal_finished(raw)
    msg === nothing && _tls13_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls13 server handshake expected client Finished")
    expected_verify_data = _tls13_finished_verify_data(state.cipher_spec.hash_kind, state.client_handshake_traffic_secret, state.transcript)
    try
        _constant_time_equals(msg.verify_data, expected_verify_data) || _tls13_fail(_TLS_ALERT_DECRYPT_ERROR, "tls: invalid client finished hash")
    finally
        _securezero!(expected_verify_data)
    end
    state.client_finished = msg
    _transcript_update!(state.transcript, raw)
    return nothing
end

function _tls13_should_send_session_tickets(state::_TLS13ServerHandshakeState, config)::Bool
    config.session_tickets_disabled && return false
    return in(_TLS_PSK_MODE_DHE, state.client_hello.psk_modes)
end

function _send_new_session_ticket!(state::_TLS13ServerHandshakeState, io, config)::Nothing
    _tls13_should_send_session_tickets(state, config) || return nothing
    hash_kind = state.cipher_spec.hash_kind
    resumption_secret = _tls13_derive_secret(hash_kind, state.master_secret, "res master", state.transcript)
    # We only issue one ticket per connection today, so a zero ticket nonce mirrors
    # Go's current TLS 1.3 server behavior.
    nonce = UInt8[]
    label = rand(Random.RandomDevice(), UInt8, 32)
    psk = UInt8[]
    session = nothing
    try
        psk = _tls13_expand_label(hash_kind, resumption_secret, "resumption", nonce, _hash_len(hash_kind))
        now_s = UInt64(floor(time()))
        age_add_bytes = rand(Random.RandomDevice(), UInt8, 4)
        age_add = (UInt32(age_add_bytes[1]) << 24) |
            (UInt32(age_add_bytes[2]) << 16) |
            (UInt32(age_add_bytes[3]) << 8) |
            UInt32(age_add_bytes[4])
        session = _owned_tls13_server_session(
            TLS1_3_VERSION,
            state.cipher_suite,
            now_s,
            now_s + UInt64(_TLS13_MAX_SESSION_TICKET_LIFETIME),
            age_add,
            label,
            psk,
            state.peer_certificates,
            state.selected_alpn,
        )
        _tls13_server_session_cache_put!(config._server_session_cache, session)
        msg = _NewSessionTicketMsgTLS13()
        msg.lifetime = _TLS13_MAX_SESSION_TICKET_LIFETIME
        msg.age_add = age_add
        msg.nonce = nonce
        msg.label = copy(label)
        raw = _marshal_new_session_ticket_tls13(msg)
        _write_handshake_bytes!(io, raw)
    finally
        session isa _TLS13ServerSession && _securezero_tls13_server_session!(session)
        _securezero!(psk)
        _securezero!(label)
        _securezero!(resumption_secret)
    end
    return nothing
end

function _server_handshake_tls13_after_client_hello!(state::_TLS13ServerHandshakeState, io, config)::Nothing
    _prepare_server_negotiation!(state, io, config)
    _check_for_resumption!(state, config)
    _send_server_hello!(state, io)
    _tls13_send_dummy_change_cipher_spec!(io)
    _establish_server_handshake_keys!(state)
    _tls13_set_read_cipher!(io.state, state.cipher_spec, state.client_handshake_traffic_secret)
    _tls13_set_write_cipher!(io.state, state.cipher_spec, state.server_handshake_traffic_secret)
    _send_encrypted_extensions!(state, io)
    if !state.using_psk
        _request_client_certificate(config) && _send_certificate_request!(state, io)
        _send_server_certificate!(state, io)
        _send_server_certificate_verify!(state, io)
    end
    _send_server_finished!(state, io)
    _tls13_set_write_cipher!(io.state, state.cipher_spec, state.server_application_traffic_secret)
    _read_client_certificate!(state, io, config)
    _read_client_finished!(state, io)
    _tls13_set_read_cipher!(io.state, state.cipher_spec, state.client_application_traffic_secret)
    state.complete = true
    _send_new_session_ticket!(state, io, config)
    return nothing
end

function _server_handshake_tls13!(state::_TLS13ServerHandshakeState, io, config)::Nothing
    state.complete && throw(ArgumentError("tls13 server handshake already complete"))
    _read_client_hello!(state, io)
    return _server_handshake_tls13_after_client_hello!(state, io, config)
end

function _native_tls13_server_handshake!(conn)::Nothing
    state = _TLS13ServerHandshakeState(conn.config)
    native_state = _native_tls13_state(conn)
    io = _TLS13HandshakeRecordIO(conn.tcp, native_state)
    try
        _server_handshake_tls13!(state, io, conn.config)
        native_state.session_cipher_suite = state.cipher_suite
        native_state.session_alpn = state.selected_alpn
        native_state.did_resume = state.using_psk
        native_state.did_hello_retry_request = state.did_hello_retry_request
        native_state.curve_id = state.server_hello.server_share === nothing ? UInt16(0) : (state.server_hello.server_share::_TLSKeyShare).group
        _set_handshake_complete!(conn, "TLSv1.3", isempty(state.selected_alpn) ? nothing : state.selected_alpn)
    finally
        _securezero_tls13_server_handshake_state!(state)
    end
    return nothing
end
