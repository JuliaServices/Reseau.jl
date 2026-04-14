const _HELLO_RETRY_REQUEST_RANDOM = UInt8[
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
    0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
    0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
]

mutable struct _HandshakeMessageFlightIO
    inbound::Vector{Vector{UInt8}}
    inbound_pos::Int
    outbound::Vector{Vector{UInt8}}
end

_HandshakeMessageFlightIO() = _HandshakeMessageFlightIO(Vector{UInt8}[], 1, Vector{UInt8}[])
_HandshakeMessageFlightIO(inbound::Vector{Vector{UInt8}}) = _HandshakeMessageFlightIO(inbound, 1, Vector{UInt8}[])

@inline function _contains_u16(values::Vector{UInt16}, value::UInt16)::Bool
    for candidate in values
        candidate == value && return true
    end
    return false
end

@inline function _contains_u8(values::Vector{UInt8}, value::UInt8)::Bool
    for candidate in values
        candidate == value && return true
    end
    return false
end

@inline function _contains_string(values::Vector{String}, value::String)::Bool
    for candidate in values
        candidate == value && return true
    end
    return false
end

@inline function _remaining_handshake_messages(io::_HandshakeMessageFlightIO)::Int
    return length(io.inbound) - io.inbound_pos + 1
end

function _read_handshake_bytes!(io::_HandshakeMessageFlightIO)::Vector{UInt8}
    io.inbound_pos <= length(io.inbound) || throw(EOFError("tls13 handshake queue exhausted"))
    raw = io.inbound[io.inbound_pos]
    io.inbound_pos += 1
    return raw
end

function _read_handshake_message!(io::_HandshakeMessageFlightIO, transcript::Union{Nothing, _TranscriptHash} = nothing)::_HandshakeMessage
    raw = _read_handshake_bytes!(io)
    msg = _unmarshal_handshake_message(raw, transcript)
    msg === nothing && throw(ArgumentError("tls13 invalid handshake message"))
    return msg
end

function _write_handshake_message!(io::_HandshakeMessageFlightIO, msg::_HandshakeMessage, transcript::Union{Nothing, _TranscriptHash} = nothing)::Vector{UInt8}
    raw = _write_handshake_message(msg, transcript)
    push!(io.outbound, raw)
    return raw
end

mutable struct _TLS13ClientHandshakeState{HK, TR<:_TranscriptHash}
    client_hello::_ClientHelloMsg
    cipher_suite::UInt16
    cipher_spec::_TLS13CipherSpec
    shared_secret::Vector{UInt8}
    psk::Vector{UInt8}
    has_psk::Bool
    transcript::TR
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
    early_secret::Vector{UInt8}
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

function _TLS13ClientHandshakeState(client_hello::_ClientHelloMsg, cipher_suite::UInt16, shared_secret::AbstractVector{UInt8})
    cipher_spec = _tls13_cipher_spec(cipher_suite)
    cipher_spec === nothing && throw(ArgumentError("unsupported TLS 1.3 cipher suite: $(string(cipher_suite, base = 16))"))
    if cipher_spec.hash_kind == _HASH_SHA256
        transcript = _TranscriptHash(_HASH_SHA256)
        return _TLS13ClientHandshakeState{_HASH_SHA256, typeof(transcript)}(
            client_hello,
            cipher_suite,
            cipher_spec,
            Vector{UInt8}(shared_secret),
            UInt8[],
            false,
            transcript,
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
            UInt8[],
            _NewSessionTicketMsgTLS13[],
            "",
            false,
        )
    end

    transcript = _TranscriptHash(_HASH_SHA384)
    return _TLS13ClientHandshakeState{_HASH_SHA384, typeof(transcript)}(
        client_hello,
        cipher_suite,
        cipher_spec,
        Vector{UInt8}(shared_secret),
        UInt8[],
        false,
        transcript,
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
        UInt8[],
        _NewSessionTicketMsgTLS13[],
        "",
        false,
    )
end

function _TLS13ClientHandshakeState(client_hello::_ClientHelloMsg, cipher_suite::UInt16, shared_secret::AbstractVector{UInt8}, psk::AbstractVector{UInt8})
    state = _TLS13ClientHandshakeState(client_hello, cipher_suite, shared_secret)
    state.psk = Vector{UInt8}(psk)
    state.has_psk = true
    return state
end

function _compute_and_update_psk_binders!(state::_TLS13ClientHandshakeState{HK})::Nothing where {HK}
    state.has_psk || return nothing
    length(state.client_hello.psk_identities) == 1 || throw(ArgumentError("tls13 client handshake expects exactly one PSK identity"))
    length(state.client_hello.psk_binders) == 1 || throw(ArgumentError("tls13 client handshake expects exactly one PSK binder"))
    _contains_u16(state.client_hello.supported_versions, TLS1_3_VERSION) || throw(ArgumentError("tls13 client handshake requires supported_versions to include TLS 1.3"))
    _contains_u16(state.client_hello.cipher_suites, state.cipher_suite) || throw(ArgumentError("tls13 client handshake requires the selected cipher suite in ClientHello"))
    _contains_u8(state.client_hello.psk_modes, _TLS_PSK_MODE_DHE) || throw(ArgumentError("tls13 client handshake requires the DHE PSK mode"))

    early_secret = _tls13_early_secret(HK, state.psk)
    binder_key = _tls13_resumption_binder_key(early_secret)
    binder_transcript = HK == _HASH_SHA256 ? _TranscriptHash(_HASH_SHA256; buffer_handshake = false) : _TranscriptHash(_HASH_SHA384; buffer_handshake = false)
    _transcript_update!(binder_transcript, _marshal_client_hello_without_binders(state.client_hello))
    binder = _tls13_finished_verify_data(HK, binder_key, binder_transcript)
    _update_client_hello_binders!(state.client_hello, [binder])
    state.early_secret = early_secret.secret
    return nothing
end

function _write_client_hello!(state::_TLS13ClientHandshakeState, io::_HandshakeMessageFlightIO)::Nothing
    _contains_u16(state.client_hello.supported_versions, TLS1_3_VERSION) || throw(ArgumentError("tls13 client handshake requires supported_versions to include TLS 1.3"))
    _contains_u16(state.client_hello.cipher_suites, state.cipher_suite) || throw(ArgumentError("tls13 client handshake requires the selected cipher suite in ClientHello"))
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
    _contains_u16(state.client_hello.cipher_suites, server_hello.cipher_suite) || throw(ArgumentError("tls: server chose an unconfigured cipher suite"))
    return nothing
end

function _read_server_hello!(state::_TLS13ClientHandshakeState, io::_HandshakeMessageFlightIO)::Nothing
    raw = _copy_valid_handshake_frame(_read_handshake_bytes!(io))
    raw === nothing && throw(ArgumentError("tls13 client handshake expected a valid ServerHello frame"))
    msg = _unmarshal_server_hello(raw)
    msg === nothing && throw(ArgumentError("tls13 client handshake expected ServerHello"))
    _transcript_update!(state.transcript, raw)
    state.server_hello = msg
    state.have_server_hello = true
    _check_server_hello_or_hrr!(state)
    return nothing
end

function _process_server_hello!(state::_TLS13ClientHandshakeState)::Nothing
    server_hello = state.server_hello
    server_hello.random == _HELLO_RETRY_REQUEST_RANDOM && throw(ArgumentError("tls13 client handshake does not yet implement HelloRetryRequest"))
    isempty(server_hello.cookie) || throw(ArgumentError("tls: server sent a cookie in a normal ServerHello"))
    server_hello.selected_group == 0x0000 || throw(ArgumentError("tls: malformed key_share extension"))
    server_hello.server_share === nothing && throw(ArgumentError("tls: server did not send a key share"))

    server_share = server_hello.server_share::_TLSKeyShare
    supported_group = false
    for key_share in state.client_hello.key_shares
        if key_share.group == server_share.group
            supported_group = true
            break
        end
    end
    supported_group || throw(ArgumentError("tls: server selected unsupported group"))

    if !server_hello.selected_identity_present
        throw(ArgumentError("tls13 client handshake certificate path is not implemented yet"))
    end

    state.has_psk || throw(ArgumentError("tls: server selected a PSK without a client PSK"))
    Int(server_hello.selected_identity) < length(state.client_hello.psk_identities) || throw(ArgumentError("tls: server selected an invalid PSK"))
    state.using_psk = true
    return nothing
end

function _establish_handshake_keys!(state::_TLS13ClientHandshakeState{HK})::Nothing where {HK}
    early_secret = state.using_psk ? _tls13_early_secret(HK, state.psk) : _tls13_early_secret(HK, UInt8[])
    handshake_secret = _tls13_handshake_secret(early_secret, state.shared_secret)
    master_secret = _tls13_master_secret(handshake_secret)

    state.early_secret = early_secret.secret
    state.handshake_secret = handshake_secret.secret
    state.master_secret = master_secret.secret
    state.client_handshake_traffic_secret = _tls13_client_handshake_traffic_secret(handshake_secret, state.transcript)
    state.server_handshake_traffic_secret = _tls13_server_handshake_traffic_secret(handshake_secret, state.transcript)
    return nothing
end

function _read_server_parameters!(state::_TLS13ClientHandshakeState, io::_HandshakeMessageFlightIO)::Nothing
    raw = _copy_valid_handshake_frame(_read_handshake_bytes!(io))
    raw === nothing && throw(ArgumentError("tls13 client handshake expected a valid EncryptedExtensions frame"))
    msg = _unmarshal_encrypted_extensions(raw)
    msg === nothing && throw(ArgumentError("tls13 client handshake expected EncryptedExtensions"))
    _transcript_update!(state.transcript, raw)
    state.encrypted_extensions = msg
    state.have_encrypted_extensions = true

    server_protocol = msg.alpn_protocol
    if !isempty(server_protocol)
        isempty(state.client_hello.alpn_protocols) && throw(ArgumentError("tls: server advertised unrequested ALPN extension"))
        _contains_string(state.client_hello.alpn_protocols, server_protocol) || throw(ArgumentError("tls: server selected unadvertised ALPN protocol"))
    end

    (state.client_hello.quic_transport_parameters === nothing) == (msg.quic_transport_parameters === nothing) ||
        throw(ArgumentError("tls: unexpected quic_transport_parameters extension"))

    (!state.client_hello.early_data && msg.early_data) && throw(ArgumentError("tls: server sent an unexpected early_data extension"))

    state.client_protocol = server_protocol
    return nothing
end

function _read_server_finished!(state::_TLS13ClientHandshakeState{HK}, io::_HandshakeMessageFlightIO)::Nothing where {HK}
    raw = _copy_valid_handshake_frame(_read_handshake_bytes!(io))
    raw === nothing && throw(ArgumentError("tls13 client handshake expected a valid Finished frame"))
    msg = _unmarshal_finished(raw)
    msg === nothing && throw(ArgumentError("tls13 client handshake expected Finished"))
    expected_verify_data = _tls13_finished_verify_data(HK, state.server_handshake_traffic_secret, state.transcript)
    msg.verify_data == expected_verify_data || throw(ArgumentError("tls: invalid server finished hash"))

    state.server_finished = msg
    state.have_server_finished = true
    _transcript_update!(state.transcript, raw)

    state.client_application_traffic_secret = _tls13_derive_secret(HK, state.master_secret, "c ap traffic", state.transcript)
    state.server_application_traffic_secret = _tls13_derive_secret(HK, state.master_secret, "s ap traffic", state.transcript)
    state.exporter_master_secret = _tls13_derive_secret(HK, state.master_secret, "exp master", state.transcript)
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
        raw = _copy_valid_handshake_frame(_read_handshake_bytes!(io))
        raw === nothing && throw(ArgumentError("tls13 client handshake expected a valid NewSessionTicket frame"))
        msg = _unmarshal_new_session_ticket_tls13(raw)
        msg === nothing && throw(ArgumentError("tls13 client handshake expected only NewSessionTicket post-handshake messages"))
        push!(state.peer_new_session_tickets, msg)
    end
    return nothing
end

function _client_handshake_tls13!(state::_TLS13ClientHandshakeState, io::_HandshakeMessageFlightIO)::Nothing
    state.complete && throw(ArgumentError("tls13 client handshake already complete"))
    _write_client_hello!(state, io)
    _read_server_hello!(state, io)
    _process_server_hello!(state)
    _establish_handshake_keys!(state)
    _read_server_parameters!(state, io)
    _read_server_finished!(state, io)
    _send_client_finished!(state, io)
    state.complete = true
    _read_post_handshake_messages!(state, io)
    return nothing
end
