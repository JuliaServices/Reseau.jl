using Test
using Reseau

const TLHC = Reseau.TLS
const _TLS_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")
const _TLS13_TEST_CERT_PEM = read(_TLS_CERT_PATH)
const _TLS13_TEST_KEY_PEM = read(_TLS_KEY_PATH)
const _TLS13_TEST_CERT_DER = TLHC._tls13_openssl_certificate_der(_TLS13_TEST_CERT_PEM)
const _TLS13_TEST_CLIENT_X25519_PRIVATE_KEY = UInt8[
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
    0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
    0x55, 0x44, 0x33, 0x22, 0x11, 0x00, 0xff, 0xee,
    0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66,
]
const _TLS13_TEST_SERVER_X25519_PRIVATE_KEY = UInt8[
    0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x07, 0x18,
    0x29, 0x3a, 0x4b, 0x5c, 0x6d, 0x7e, 0x8f, 0x90,
    0x91, 0x82, 0x73, 0x64, 0x55, 0x46, 0x37, 0x28,
    0x19, 0x0a, 0xfb, 0xec, 0xdd, 0xce, 0xbf, 0xa0,
]
const _TLS13_TEST_CLIENT_P256_PRIVATE_KEY = UInt8[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
]
const _TLS13_TEST_SERVER_P256_PRIVATE_KEY = UInt8[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
]

function _tls13_psk_client_hello(; cipher_suite::UInt16 = TLHC._TLS13_AES_128_GCM_SHA256_ID, binder_len::Int = 32)
    msg = TLHC._ClientHelloMsg()
    msg.vers = TLHC.TLS1_2_VERSION
    msg.random = collect(UInt8(0x00):UInt8(0x1f))
    msg.session_id = UInt8[0xaa, 0xbb, 0xcc, 0xdd]
    msg.cipher_suites = UInt16[cipher_suite]
    msg.compression_methods = UInt8[TLHC._TLS_COMPRESSION_NONE]
    msg.server_name = "localhost"
    msg.alpn_protocols = ["h2"]
    msg.supported_versions = UInt16[TLHC.TLS1_3_VERSION]
    msg.key_shares = [TLHC._TLSKeyShare(0x001d, UInt8[0x01, 0x02, 0x03, 0x04])]
    msg.psk_modes = UInt8[TLHC._TLS_PSK_MODE_DHE]
    msg.psk_identities = [TLHC._TLSPSKIdentity(UInt8[0x50, 0x51, 0x52], 0x01020304)]
    msg.psk_binders = [zeros(UInt8, binder_len)]
    return msg
end

function _tls13_psk_server_hello(
    session_id::Vector{UInt8};
    cipher_suite::UInt16 = TLHC._TLS13_AES_128_GCM_SHA256_ID,
    group::UInt16 = 0x001d,
    selected_identity_present::Bool = true,
)
    msg = TLHC._ServerHelloMsg()
    msg.vers = TLHC.TLS1_2_VERSION
    msg.random = collect(UInt8(0x80):UInt8(0x9f))
    msg.session_id = copy(session_id)
    msg.cipher_suite = cipher_suite
    msg.compression_method = TLHC._TLS_COMPRESSION_NONE
    msg.supported_version = TLHC.TLS1_3_VERSION
    msg.server_share = TLHC._TLSKeyShare(group, UInt8[0x05, 0x06, 0x07, 0x08])
    msg.selected_identity_present = selected_identity_present
    msg.selected_identity = UInt16(0)
    return msg
end

function _compute_tls13_psk_server_flight(client_hello::TLHC._ClientHelloMsg, shared_secret::Vector{UInt8}, psk::Vector{UInt8})
    cipher_suite = client_hello.cipher_suites[1]
    cipher_spec = TLHC._tls13_cipher_spec(cipher_suite)::TLHC._TLS13CipherSpec
    hash_kind = cipher_spec.hash_kind

    early_secret = TLHC._tls13_early_secret(hash_kind, psk)
    binder_key = TLHC._tls13_resumption_binder_key(early_secret)
    binder_transcript = TLHC._TranscriptHash(hash_kind; buffer_handshake = false)
    TLHC._transcript_update!(binder_transcript, TLHC._marshal_client_hello_without_binders(client_hello))
    binder = TLHC._tls13_finished_verify_data(hash_kind, binder_key, binder_transcript)
    TLHC._update_client_hello_binders!(client_hello, [binder])

    client_bytes = TLHC._marshal_handshake_message(client_hello)
    server_hello = _tls13_psk_server_hello(client_hello.session_id; cipher_suite)
    server_hello_bytes = TLHC._marshal_handshake_message(server_hello)

    transcript = TLHC._TranscriptHash(hash_kind)
    TLHC._transcript_update!(transcript, client_bytes)
    TLHC._transcript_update!(transcript, server_hello_bytes)

    handshake_secret = TLHC._tls13_handshake_secret(early_secret, shared_secret)
    client_handshake_traffic_secret = TLHC._tls13_client_handshake_traffic_secret(handshake_secret, transcript)
    server_handshake_traffic_secret = TLHC._tls13_server_handshake_traffic_secret(handshake_secret, transcript)

    encrypted_extensions = TLHC._EncryptedExtensionsMsg()
    encrypted_extensions.alpn_protocol = "h2"
    encrypted_extensions_bytes = TLHC._marshal_handshake_message(encrypted_extensions)
    TLHC._transcript_update!(transcript, encrypted_extensions_bytes)

    server_finished = TLHC._FinishedMsg(TLHC._tls13_finished_verify_data(cipher_spec, server_handshake_traffic_secret, transcript))
    server_finished_bytes = TLHC._marshal_handshake_message(server_finished)
    TLHC._transcript_update!(transcript, server_finished_bytes)

    client_finished = TLHC._FinishedMsg(TLHC._tls13_finished_verify_data(cipher_spec, client_handshake_traffic_secret, transcript))
    client_finished_bytes = TLHC._marshal_handshake_message(client_finished)

    master_secret = TLHC._tls13_master_secret(handshake_secret)
    client_application_traffic_secret = TLHC._tls13_client_application_traffic_secret(master_secret, transcript)
    server_application_traffic_secret = TLHC._tls13_server_application_traffic_secret(master_secret, transcript)
    exporter_master_secret = TLHC._tls13_exporter_secret_for_test(TLHC._tls13_exporter_master_secret(master_secret, transcript))

    ticket = TLHC._NewSessionTicketMsgTLS13()
    ticket.lifetime = 0x00015180
    ticket.age_add = 0x05060708
    ticket.nonce = UInt8[0x90, 0x91]
    ticket.label = UInt8[0xa0, 0xa1, 0xa2]
    ticket.max_early_data = 0x0b0c0d0e
    ticket_bytes = TLHC._marshal_handshake_message(ticket)

    return (
        inbound = [server_hello_bytes, encrypted_extensions_bytes, server_finished_bytes, ticket_bytes],
        client_bytes = client_bytes,
        client_finished_bytes = client_finished_bytes,
        client_handshake_traffic_secret = client_handshake_traffic_secret,
        server_handshake_traffic_secret = server_handshake_traffic_secret,
        client_application_traffic_secret = client_application_traffic_secret,
        server_application_traffic_secret = server_application_traffic_secret,
        exporter_master_secret = exporter_master_secret,
        ticket = ticket,
    )
end

function _tls13_cert_client_hello(; supported_curves::Vector{UInt16} = UInt16[0x001d], session_id::Vector{UInt8} = UInt8[0xba, 0xdb, 0xee, 0xf0])
    msg = TLHC._ClientHelloMsg()
    msg.vers = TLHC.TLS1_2_VERSION
    msg.random = collect(UInt8(0x20):UInt8(0x3f))
    msg.session_id = copy(session_id)
    msg.cipher_suites = UInt16[TLHC._TLS13_AES_128_GCM_SHA256_ID]
    msg.compression_methods = UInt8[TLHC._TLS_COMPRESSION_NONE]
    msg.server_name = "localhost"
    msg.alpn_protocols = ["h2"]
    msg.supported_versions = UInt16[TLHC.TLS1_3_VERSION]
    msg.supported_curves = copy(supported_curves)
    msg.supported_signature_algorithms = UInt16[TLHC._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256]
    msg.supported_signature_algorithms_cert = UInt16[TLHC._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256]
    return msg
end

function _tls13_certificate_server_hello(session_id::Vector{UInt8}, group::UInt16, server_share_data::Vector{UInt8})
    msg = TLHC._ServerHelloMsg()
    msg.vers = TLHC.TLS1_2_VERSION
    msg.random = collect(UInt8(0x60):UInt8(0x7f))
    msg.session_id = copy(session_id)
    msg.cipher_suite = TLHC._TLS13_AES_128_GCM_SHA256_ID
    msg.compression_method = TLHC._TLS_COMPRESSION_NONE
    msg.supported_version = TLHC.TLS1_3_VERSION
    msg.server_share = TLHC._TLSKeyShare(group, copy(server_share_data))
    return msg
end

function _tls13_hello_retry_request(session_id::Vector{UInt8}, selected_group::UInt16, cookie::Vector{UInt8})
    msg = TLHC._ServerHelloMsg()
    msg.vers = TLHC.TLS1_2_VERSION
    msg.random = copy(TLHC._HELLO_RETRY_REQUEST_RANDOM)
    msg.session_id = copy(session_id)
    msg.cipher_suite = TLHC._TLS13_AES_128_GCM_SHA256_ID
    msg.compression_method = TLHC._TLS_COMPRESSION_NONE
    msg.supported_version = TLHC.TLS1_3_VERSION
    msg.cookie = copy(cookie)
    msg.selected_group = selected_group
    return msg
end

function _tls13_server_certificate()
    msg = TLHC._CertificateMsgTLS13()
    msg.certificates = [copy(_TLS13_TEST_CERT_DER)]
    return msg
end

function _tls13_server_certificate_request()
    msg = TLHC._CertificateRequestMsgTLS13()
    msg.supported_signature_algorithms = UInt16[TLHC._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256]
    msg.supported_signature_algorithms_cert = UInt16[TLHC._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256]
    return msg
end

_tls13_openssl_key_share_provider() = TLHC._TLS13OpenSSLKeyShareProvider(fixed_x25519_private_key = _TLS13_TEST_CLIENT_X25519_PRIVATE_KEY)

function _tls13_scripted_key_share_provider(; hello_retry::Bool = false)
    initial_share = TLHC._TLSKeyShare(0x001d, UInt8[0x11, 0x12, 0x13, 0x14])
    initial_server_share = UInt8[0x21, 0x22, 0x23, 0x24]
    initial_shared_secret = UInt8[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
    if !hello_retry
        return TLHC._TLS13ScriptedKeyShareProvider(initial_share, initial_server_share, initial_shared_secret)
    end
    retry_share = TLHC._TLSKeyShare(0x0017, UInt8[0x41, 0x42, 0x43, 0x44])
    retry_server_share = UInt8[0x51, 0x52, 0x53, 0x54]
    retry_shared_secret = UInt8[0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68]
    return TLHC._TLS13ScriptedKeyShareProvider(
        initial_share,
        initial_server_share,
        initial_shared_secret,
        retry_share,
        retry_server_share,
        retry_shared_secret,
    )
end

function _compute_tls13_certificate_server_flight(
    client_hello::TLHC._ClientHelloMsg,
    key_share_provider::TLHC._TLS13ScriptedKeyShareProvider;
    hello_retry::Bool = false,
    certificate_request::Bool = false,
)
    TLHC._tls13_prepare_initial_client_hello!(key_share_provider, client_hello)
    client_hello_bytes = TLHC._marshal_handshake_message(client_hello)
    outbound = [client_hello_bytes]
    inbound = Vector{UInt8}[]
    transcript = TLHC._TranscriptHash(TLHC._HASH_SHA256)
    TLHC._transcript_update!(transcript, client_hello_bytes)

    if hello_retry
        hrr = _tls13_hello_retry_request(client_hello.session_id, key_share_provider.retry_share.group, UInt8[0xa1, 0xa2, 0xa3])
        hrr_bytes = TLHC._marshal_handshake_message(hrr)
        push!(inbound, hrr_bytes)
        TLHC._tls13_process_hello_retry_request!(key_share_provider, client_hello, hrr)
        transcript = TLHC._TranscriptHash(TLHC._HASH_SHA256)
        TLHC._transcript_update!(transcript, TLHC._tls13_message_hash_frame(TLHC._hash_data(TLHC._HASH_SHA256, client_hello_bytes)))
        TLHC._transcript_update!(transcript, hrr_bytes)
        retry_client_hello_bytes = TLHC._marshal_handshake_message(client_hello)
        TLHC._transcript_update!(transcript, retry_client_hello_bytes)
        push!(outbound, retry_client_hello_bytes)
        server_hello = _tls13_certificate_server_hello(client_hello.session_id, key_share_provider.retry_share.group, copy(key_share_provider.retry_expected_server_share))
        shared_secret = copy(key_share_provider.retry_shared_secret)
    else
        server_hello = _tls13_certificate_server_hello(client_hello.session_id, key_share_provider.initial_share.group, copy(key_share_provider.initial_expected_server_share))
        shared_secret = copy(key_share_provider.initial_shared_secret)
    end

    server_hello_bytes = TLHC._marshal_handshake_message(server_hello)
    push!(inbound, server_hello_bytes)
    TLHC._transcript_update!(transcript, server_hello_bytes)

    early_secret = TLHC._tls13_early_secret(TLHC._HASH_SHA256, nothing)
    handshake_secret = TLHC._tls13_handshake_secret(early_secret, shared_secret)
    client_handshake_traffic_secret = TLHC._tls13_client_handshake_traffic_secret(handshake_secret, transcript)
    server_handshake_traffic_secret = TLHC._tls13_server_handshake_traffic_secret(handshake_secret, transcript)

    encrypted_extensions = TLHC._EncryptedExtensionsMsg()
    encrypted_extensions.alpn_protocol = "h2"
    encrypted_extensions_bytes = TLHC._marshal_handshake_message(encrypted_extensions)
    push!(inbound, encrypted_extensions_bytes)
    TLHC._transcript_update!(transcript, encrypted_extensions_bytes)

    cert_req = nothing
    if certificate_request
        cert_req = _tls13_server_certificate_request()
        cert_req_bytes = TLHC._marshal_handshake_message(cert_req)
        push!(inbound, cert_req_bytes)
        TLHC._transcript_update!(transcript, cert_req_bytes)
    end

    certificate = _tls13_server_certificate()
    certificate_bytes = TLHC._marshal_handshake_message(certificate)
    push!(inbound, certificate_bytes)
    TLHC._transcript_update!(transcript, certificate_bytes)

    signed_message = TLHC._tls13_signed_message(TLHC._TLS13_SERVER_SIGNATURE_CONTEXT, transcript)
    certificate_verify = TLHC._CertificateVerifyMsg(0x0804, UInt8[0xb1, 0xb2, 0xb3, 0xb4, 0xb5])
    certificate_verify_bytes = TLHC._marshal_handshake_message(certificate_verify)
    push!(inbound, certificate_verify_bytes)
    TLHC._transcript_update!(transcript, certificate_verify_bytes)

    server_finished = TLHC._FinishedMsg(TLHC._tls13_finished_verify_data(TLHC._TLS13_AES_128_GCM_SHA256, server_handshake_traffic_secret, transcript))
    server_finished_bytes = TLHC._marshal_handshake_message(server_finished)
    push!(inbound, server_finished_bytes)
    TLHC._transcript_update!(transcript, server_finished_bytes)

    transcript_for_client = TLHC._TranscriptHash(TLHC._HASH_SHA256)
    transcript_bytes = TLHC._transcript_buffered_bytes(transcript)::Vector{UInt8}
    TLHC._transcript_update!(transcript_for_client, transcript_bytes)

    client_certificate_bytes = nothing
    if certificate_request
        client_certificate_bytes = TLHC._marshal_certificate_tls13(TLHC._CertificateMsgTLS13())
        TLHC._transcript_update!(transcript_for_client, client_certificate_bytes)
        push!(outbound, client_certificate_bytes)
    end

    client_finished = TLHC._FinishedMsg(TLHC._tls13_finished_verify_data(TLHC._TLS13_AES_128_GCM_SHA256, client_handshake_traffic_secret, transcript_for_client))
    client_finished_bytes = TLHC._marshal_handshake_message(client_finished)
    push!(outbound, client_finished_bytes)

    master_secret = TLHC._tls13_master_secret(handshake_secret)
    client_application_traffic_secret = TLHC._tls13_client_application_traffic_secret(master_secret, transcript)
    server_application_traffic_secret = TLHC._tls13_server_application_traffic_secret(master_secret, transcript)
    exporter_master_secret = TLHC._tls13_exporter_secret_for_test(TLHC._tls13_exporter_master_secret(master_secret, transcript))

    ticket = TLHC._NewSessionTicketMsgTLS13()
    ticket.lifetime = 0x00015180
    ticket.age_add = 0x05060708
    ticket.nonce = UInt8[0x90, 0x91]
    ticket.label = UInt8[0xa0, 0xa1, 0xa2]
    ticket.max_early_data = 0x0b0c0d0e
    ticket_bytes = TLHC._marshal_handshake_message(ticket)
    push!(inbound, ticket_bytes)

    verifier = TLHC._TLS13ScriptedCertificateVerifier(
        certificate.certificates,
        client_hello.server_name,
        certificate_verify.signature_algorithm,
        signed_message,
        certificate_verify.signature,
    )

    return (
        inbound = inbound,
        outbound = outbound,
        verifier = verifier,
        client_handshake_traffic_secret = client_handshake_traffic_secret,
        server_handshake_traffic_secret = server_handshake_traffic_secret,
        client_application_traffic_secret = client_application_traffic_secret,
        server_application_traffic_secret = server_application_traffic_secret,
        exporter_master_secret = exporter_master_secret,
        ticket = ticket,
        certificate_request = cert_req,
        certificate = certificate,
        certificate_verify = certificate_verify,
    )
end

function _compute_tls13_real_certificate_server_flight(client_hello::TLHC._ClientHelloMsg; certificate_request::Bool = false)
    key_share_provider = _tls13_openssl_key_share_provider()
    TLHC._tls13_prepare_initial_client_hello!(key_share_provider, client_hello)
    client_hello_bytes = TLHC._marshal_handshake_message(client_hello)
    outbound = [client_hello_bytes]
    transcript = TLHC._TranscriptHash(TLHC._HASH_SHA256)
    TLHC._transcript_update!(transcript, client_hello_bytes)

    client_share = client_hello.key_shares[1]::TLHC._TLSKeyShare
    server_share, shared_secret = TLHC._tls13_openssl_x25519_server_share_and_secret(client_share.data, _TLS13_TEST_SERVER_X25519_PRIVATE_KEY)
    server_hello = _tls13_certificate_server_hello(client_hello.session_id, server_share.group, copy(server_share.data))
    server_hello_bytes = TLHC._marshal_handshake_message(server_hello)
    inbound = [server_hello_bytes]
    TLHC._transcript_update!(transcript, server_hello_bytes)

    early_secret = TLHC._tls13_early_secret(TLHC._HASH_SHA256, nothing)
    handshake_secret = TLHC._tls13_handshake_secret(early_secret, shared_secret)
    client_handshake_traffic_secret = TLHC._tls13_client_handshake_traffic_secret(handshake_secret, transcript)
    server_handshake_traffic_secret = TLHC._tls13_server_handshake_traffic_secret(handshake_secret, transcript)

    encrypted_extensions = TLHC._EncryptedExtensionsMsg()
    encrypted_extensions.alpn_protocol = "h2"
    encrypted_extensions_bytes = TLHC._marshal_handshake_message(encrypted_extensions)
    push!(inbound, encrypted_extensions_bytes)
    TLHC._transcript_update!(transcript, encrypted_extensions_bytes)

    cert_req = nothing
    if certificate_request
        cert_req = _tls13_server_certificate_request()
        cert_req_bytes = TLHC._marshal_handshake_message(cert_req)
        push!(inbound, cert_req_bytes)
        TLHC._transcript_update!(transcript, cert_req_bytes)
    end

    certificate = _tls13_server_certificate()
    certificate_bytes = TLHC._marshal_handshake_message(certificate)
    push!(inbound, certificate_bytes)
    TLHC._transcript_update!(transcript, certificate_bytes)

    signed_message = TLHC._tls13_signed_message(TLHC._TLS13_SERVER_SIGNATURE_CONTEXT, transcript)
    certificate_verify = TLHC._CertificateVerifyMsg(
        TLHC._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
        TLHC._tls13_openssl_sign_from_pem(TLHC._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256, signed_message, _TLS13_TEST_KEY_PEM),
    )
    certificate_verify_bytes = TLHC._marshal_handshake_message(certificate_verify)
    push!(inbound, certificate_verify_bytes)
    TLHC._transcript_update!(transcript, certificate_verify_bytes)

    server_finished = TLHC._FinishedMsg(TLHC._tls13_finished_verify_data(TLHC._TLS13_AES_128_GCM_SHA256, server_handshake_traffic_secret, transcript))
    server_finished_bytes = TLHC._marshal_handshake_message(server_finished)
    push!(inbound, server_finished_bytes)
    TLHC._transcript_update!(transcript, server_finished_bytes)

    transcript_for_client = TLHC._TranscriptHash(TLHC._HASH_SHA256)
    transcript_bytes = TLHC._transcript_buffered_bytes(transcript)::Vector{UInt8}
    TLHC._transcript_update!(transcript_for_client, transcript_bytes)

    if certificate_request
        client_certificate_bytes = TLHC._marshal_certificate_tls13(TLHC._CertificateMsgTLS13())
        TLHC._transcript_update!(transcript_for_client, client_certificate_bytes)
        push!(outbound, client_certificate_bytes)
    end

    client_finished = TLHC._FinishedMsg(TLHC._tls13_finished_verify_data(TLHC._TLS13_AES_128_GCM_SHA256, client_handshake_traffic_secret, transcript_for_client))
    client_finished_bytes = TLHC._marshal_handshake_message(client_finished)
    push!(outbound, client_finished_bytes)

    master_secret = TLHC._tls13_master_secret(handshake_secret)
    client_application_traffic_secret = TLHC._tls13_client_application_traffic_secret(master_secret, transcript)
    server_application_traffic_secret = TLHC._tls13_server_application_traffic_secret(master_secret, transcript)
    exporter_master_secret = TLHC._tls13_exporter_secret_for_test(TLHC._tls13_exporter_master_secret(master_secret, transcript))

    ticket = TLHC._NewSessionTicketMsgTLS13()
    ticket.lifetime = 0x00015180
    ticket.age_add = 0x05060708
    ticket.nonce = UInt8[0x90, 0x91]
    ticket.label = UInt8[0xa0, 0xa1, 0xa2]
    ticket.max_early_data = 0x0b0c0d0e
    ticket_bytes = TLHC._marshal_handshake_message(ticket)
    push!(inbound, ticket_bytes)

    return (
        inbound = inbound,
        outbound = outbound,
        client_handshake_traffic_secret = client_handshake_traffic_secret,
        server_handshake_traffic_secret = server_handshake_traffic_secret,
        client_application_traffic_secret = client_application_traffic_secret,
        server_application_traffic_secret = server_application_traffic_secret,
        exporter_master_secret = exporter_master_secret,
        ticket = ticket,
        certificate_request = cert_req,
        certificate = certificate,
        certificate_verify = certificate_verify,
    )
end

@testset "TLS 1.3 client handshake phases 2-4" begin
    @testset "OpenSSL primitive helpers cover the real provider path" begin
        @test TLHC._x25519_pkey_id() > 0
        @test TLHC._p256_group_nid() > 0
        client_pkey = TLHC._tls13_x25519_private_key_from_bytes(_TLS13_TEST_CLIENT_X25519_PRIVATE_KEY)
        client_secret = UInt8[]
        server_secret = UInt8[]
        client_p256_pkey = Ptr{Cvoid}(C_NULL)
        client_p256_secret = UInt8[]
        server_p256_secret = UInt8[]
        pubkey = Ptr{Cvoid}(C_NULL)
        try
            client_share = TLHC._tls13_x25519_public_key(client_pkey)
            server_share, server_secret = TLHC._tls13_openssl_x25519_server_share_and_secret(client_share, _TLS13_TEST_SERVER_X25519_PRIVATE_KEY)
            client_secret = TLHC._tls13_x25519_shared_secret(client_pkey, server_share.data)
            @test server_share.group == TLHC._TLS_GROUP_X25519
            @test client_secret == server_secret

            client_p256_pkey = TLHC._tls13_p256_private_key_from_bytes(_TLS13_TEST_CLIENT_P256_PRIVATE_KEY)
            client_p256_share = TLHC._tls13_p256_public_key(client_p256_pkey)
            server_p256_share, server_p256_secret = TLHC._tls13_openssl_p256_server_share_and_secret(client_p256_share, _TLS13_TEST_SERVER_P256_PRIVATE_KEY)
            client_p256_secret = TLHC._tls13_p256_shared_secret(client_p256_pkey, server_p256_share.data)
            @test server_p256_share.group == TLHC._TLS_GROUP_SECP256R1
            @test client_p256_secret == server_p256_secret

            signed = collect(UInt8(0x10):UInt8(0x4f))
            signature = TLHC._tls13_openssl_sign_from_pem(TLHC._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256, signed, _TLS13_TEST_KEY_PEM)
            pubkey = TLHC._tls13_pubkey_from_der_certificate(_TLS13_TEST_CERT_DER)
            @test TLHC._tls13_openssl_verify_signature(pubkey, TLHC._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256, signed, signature)

            bad_signature = copy(signature)
            bad_signature[end] = xor(bad_signature[end], 0xff)
            @test !TLHC._tls13_openssl_verify_signature(pubkey, TLHC._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256, signed, bad_signature)
        finally
            TLHC._free_evp_pkey!(client_pkey)
            TLHC._free_evp_pkey!(client_p256_pkey)
            TLHC._free_evp_pkey!(pubkey)
            TLHC._securezero!(client_secret)
            TLHC._securezero!(server_secret)
            TLHC._securezero!(client_p256_secret)
            TLHC._securezero!(server_p256_secret)
        end
    end

    @testset "detached PSK client handshake mirrors Go-style sequencing" begin
        shared_secret = UInt8[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
        psk = UInt8[0x41, 0x42, 0x43, 0x44, 0x45, 0x46]

        expected_client_hello = _tls13_psk_client_hello()
        expected = _compute_tls13_psk_server_flight(expected_client_hello, shared_secret, psk)

        state = TLHC._TLS13ClientHandshakeState(_tls13_psk_client_hello(), TLHC._TLS13_AES_128_GCM_SHA256_ID, shared_secret, psk)
        io = TLHC._HandshakeMessageFlightIO(expected.inbound)
        TLHC._client_handshake_tls13!(state, io)

        @test state.complete
        @test state.using_psk
        @test state.client_protocol == "h2"
        @test state.have_server_hello
        @test state.have_encrypted_extensions
        @test !state.have_server_certificate
        @test !state.have_server_certificate_verify
        @test state.have_server_finished
        @test state.have_client_finished
        @test io.outbound == [expected.client_bytes, expected.client_finished_bytes]
        @test state.client_handshake_traffic_secret == expected.client_handshake_traffic_secret
        @test state.server_handshake_traffic_secret == expected.server_handshake_traffic_secret
        @test state.client_application_traffic_secret == expected.client_application_traffic_secret
        @test state.server_application_traffic_secret == expected.server_application_traffic_secret
        @test state.exporter_master_secret == expected.exporter_master_secret
        @test state.peer_new_session_tickets == [expected.ticket]
    end

    @testset "detached PSK SHA-384 handshake exercises the alternate hash schedule" begin
        shared_secret = collect(UInt8(0x31):UInt8(0x50))
        psk = collect(UInt8(0x41):UInt8(0x70))

        expected_client_hello = _tls13_psk_client_hello(
            cipher_suite = TLHC._TLS13_AES_256_GCM_SHA384_ID,
            binder_len = 48,
        )
        expected = _compute_tls13_psk_server_flight(expected_client_hello, shared_secret, psk)

        state = TLHC._TLS13ClientHandshakeState(
            _tls13_psk_client_hello(
                cipher_suite = TLHC._TLS13_AES_256_GCM_SHA384_ID,
                binder_len = 48,
            ),
            TLHC._TLS13_AES_256_GCM_SHA384_ID,
            shared_secret,
            psk,
        )
        io = TLHC._HandshakeMessageFlightIO(expected.inbound)
        TLHC._client_handshake_tls13!(state, io)

        @test state.complete
        @test state.using_psk
        @test io.outbound == [expected.client_bytes, expected.client_finished_bytes]
        @test state.client_handshake_traffic_secret == expected.client_handshake_traffic_secret
        @test state.server_handshake_traffic_secret == expected.server_handshake_traffic_secret
        @test state.client_application_traffic_secret == expected.client_application_traffic_secret
        @test state.server_application_traffic_secret == expected.server_application_traffic_secret
        @test state.exporter_master_secret == expected.exporter_master_secret
        @test state.peer_new_session_tickets == [expected.ticket]
    end

    @testset "certificate-authenticated client handshake uses real OpenSSL crypto" begin
        client_hello = _tls13_cert_client_hello()
        key_share_provider = _tls13_openssl_key_share_provider()
        expected = _compute_tls13_real_certificate_server_flight(_tls13_cert_client_hello())

        state = TLHC._TLS13ClientHandshakeState(client_hello, TLHC._TLS13_AES_128_GCM_SHA256_ID, key_share_provider, TLHC._TLS13OpenSSLCertificateVerifier())
        io = TLHC._HandshakeMessageFlightIO(expected.inbound)
        TLHC._client_handshake_tls13!(state, io)

        @test state.complete
        @test !state.using_psk
        @test state.client_protocol == "h2"
        @test state.have_server_certificate
        @test state.have_server_certificate_verify
        @test !state.have_certificate_request
        @test state.server_certificate == expected.certificate
        @test state.server_certificate_verify == expected.certificate_verify
        @test io.outbound == expected.outbound
        @test state.client_handshake_traffic_secret == expected.client_handshake_traffic_secret
        @test state.server_handshake_traffic_secret == expected.server_handshake_traffic_secret
        @test state.client_application_traffic_secret == expected.client_application_traffic_secret
        @test state.server_application_traffic_secret == expected.server_application_traffic_secret
        @test state.exporter_master_secret == expected.exporter_master_secret
        @test state.peer_new_session_tickets == [expected.ticket]
    end

    @testset "HelloRetryRequest and CertificateRequest paths are handled detached" begin
        client_hello = _tls13_cert_client_hello(supported_curves = UInt16[0x001d, 0x0017])
        key_share_provider = _tls13_scripted_key_share_provider(; hello_retry = true)
        expected = _compute_tls13_certificate_server_flight(
            _tls13_cert_client_hello(supported_curves = UInt16[0x001d, 0x0017]),
            _tls13_scripted_key_share_provider(; hello_retry = true);
            hello_retry = true,
            certificate_request = true,
        )

        state = TLHC._TLS13ClientHandshakeState(client_hello, TLHC._TLS13_AES_128_GCM_SHA256_ID, key_share_provider, expected.verifier)
        io = TLHC._HandshakeMessageFlightIO(expected.inbound)
        TLHC._client_handshake_tls13!(state, io)

        @test state.complete
        @test !state.using_psk
        @test state.have_certificate_request
        @test state.certificate_request == expected.certificate_request
        @test state.have_server_certificate
        @test state.have_server_certificate_verify
        @test io.outbound == expected.outbound
        @test length(io.outbound) == 4
        @test state.peer_new_session_tickets == [expected.ticket]
    end

    @testset "HelloRetryRequest drops PSK binders when the selected suite hash changes" begin
        client_hello = _tls13_psk_client_hello(
            cipher_suite = TLHC._TLS13_AES_256_GCM_SHA384_ID,
            binder_len = 48,
        )
        client_hello.cipher_suites = UInt16[
            TLHC._TLS13_AES_256_GCM_SHA384_ID,
            TLHC._TLS13_AES_128_GCM_SHA256_ID,
        ]
        client_hello.supported_curves = UInt16[TLHC._TLS_GROUP_X25519, TLHC._TLS_GROUP_SECP256R1]
        key_share_provider = _tls13_scripted_key_share_provider(; hello_retry = true)
        state = TLHC._TLS13ClientHandshakeState(
            client_hello,
            TLHC._TLS13_AES_128_GCM_SHA256_ID,
            key_share_provider,
            TLHC._TLS13NoCertificateVerifier(),
        )
        state.psk = collect(UInt8(0x41):UInt8(0x70))
        state.has_psk = true
        state.psk_cipher_suite = TLHC._TLS13_AES_256_GCM_SHA384_ID
        state.psk_cipher_spec = TLHC._tls13_cipher_spec(TLHC._TLS13_AES_256_GCM_SHA384_ID)

        retry_server_hello = _tls13_certificate_server_hello(
            client_hello.session_id,
            key_share_provider.retry_share.group,
            copy(key_share_provider.retry_expected_server_share),
        )
        io = TLHC._HandshakeMessageFlightIO([
            TLHC._marshal_handshake_message(retry_server_hello),
        ])

        TLHC._write_client_hello!(state, io)
        state.server_hello = _tls13_hello_retry_request(client_hello.session_id, key_share_provider.retry_share.group, UInt8[0xa1, 0xa2])
        state.server_hello_raw = TLHC._marshal_handshake_message(state.server_hello)
        state.have_server_hello = true
        TLHC._check_server_hello_or_hrr!(state)
        TLHC._process_hello_retry_request!(state, io)

        retried_hello = TLHC._unmarshal_client_hello(io.outbound[2])::TLHC._ClientHelloMsg
        @test !state.has_psk
        @test state.did_hello_retry_request
        @test retried_hello.psk_identities == TLHC._TLSPSKIdentity[]
        @test retried_hello.psk_binders == Vector{UInt8}[]
        @test state.cipher_suite == TLHC._TLS13_AES_128_GCM_SHA256_ID
    end

    @testset "certificate verify mismatches are rejected before client finished" begin
        key_share_provider = _tls13_openssl_key_share_provider()
        expected = _compute_tls13_real_certificate_server_flight(_tls13_cert_client_hello())
        bad_certificate_verify = copy(expected.inbound[4])
        bad_certificate_verify[end] = xor(bad_certificate_verify[end], 0xff)
        inbound = copy(expected.inbound)
        inbound[4] = bad_certificate_verify

        state = TLHC._TLS13ClientHandshakeState(_tls13_cert_client_hello(), TLHC._TLS13_AES_128_GCM_SHA256_ID, key_share_provider, TLHC._TLS13OpenSSLCertificateVerifier())
        io = TLHC._HandshakeMessageFlightIO(inbound)

        @test_throws ArgumentError TLHC._client_handshake_tls13!(state, io)
        @test length(io.outbound) == 1
        @test !state.have_client_finished
    end

    @testset "unsupported certificate verify algorithms are rejected" begin
        key_share_provider = _tls13_openssl_key_share_provider()
        expected = _compute_tls13_real_certificate_server_flight(_tls13_cert_client_hello())
        bad_certificate_verify = TLHC._CertificateVerifyMsg(
            TLHC._TLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
            copy(expected.certificate_verify.signature),
        )
        inbound = copy(expected.inbound)
        inbound[4] = TLHC._marshal_handshake_message(bad_certificate_verify)

        state = TLHC._TLS13ClientHandshakeState(_tls13_cert_client_hello(), TLHC._TLS13_AES_128_GCM_SHA256_ID, key_share_provider, TLHC._TLS13OpenSSLCertificateVerifier())
        io = TLHC._HandshakeMessageFlightIO(inbound)

        @test_throws ArgumentError TLHC._client_handshake_tls13!(state, io)
        @test length(io.outbound) == 1
        @test !state.have_client_finished
    end

    @testset "empty certificate chains are rejected before certificate verification" begin
        key_share_provider = _tls13_openssl_key_share_provider()
        expected = _compute_tls13_real_certificate_server_flight(_tls13_cert_client_hello())
        inbound = copy(expected.inbound)
        inbound[3] = TLHC._marshal_handshake_message(TLHC._CertificateMsgTLS13())

        state = TLHC._TLS13ClientHandshakeState(_tls13_cert_client_hello(), TLHC._TLS13_AES_128_GCM_SHA256_ID, key_share_provider, TLHC._TLS13OpenSSLCertificateVerifier())
        io = TLHC._HandshakeMessageFlightIO(inbound)

        @test_throws ArgumentError TLHC._client_handshake_tls13!(state, io)
        @test length(io.outbound) == 1
        @test !state.have_client_finished
    end

    @testset "server finished mismatches are rejected before client finished" begin
        shared_secret = UInt8[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
        psk = UInt8[0x41, 0x42, 0x43, 0x44, 0x45, 0x46]
        expected = _compute_tls13_psk_server_flight(_tls13_psk_client_hello(), shared_secret, psk)
        bad_finished = copy(expected.inbound[3])
        bad_finished[end] = xor(bad_finished[end], 0xff)
        io = TLHC._HandshakeMessageFlightIO([expected.inbound[1], expected.inbound[2], bad_finished])
        state = TLHC._TLS13ClientHandshakeState(_tls13_psk_client_hello(), TLHC._TLS13_AES_128_GCM_SHA256_ID, shared_secret, psk)

        @test_throws ArgumentError TLHC._client_handshake_tls13!(state, io)
        @test length(io.outbound) == 1
    end

    @testset "post-handshake tickets reject invalid lifetimes" begin
        shared_secret = UInt8[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
        psk = UInt8[0x41, 0x42, 0x43, 0x44, 0x45, 0x46]
        expected = _compute_tls13_psk_server_flight(_tls13_psk_client_hello(), shared_secret, psk)
        bad_ticket = TLHC._NewSessionTicketMsgTLS13()
        bad_ticket.lifetime = TLHC._TLS13_MAX_SESSION_TICKET_LIFETIME + UInt32(1)
        bad_ticket.age_add = 0x05060708
        bad_ticket.nonce = UInt8[0x90, 0x91]
        bad_ticket.label = UInt8[0xa0, 0xa1, 0xa2]
        bad_ticket.max_early_data = 0x0b0c0d0e
        inbound = copy(expected.inbound)
        inbound[end] = TLHC._marshal_handshake_message(bad_ticket)

        state = TLHC._TLS13ClientHandshakeState(_tls13_psk_client_hello(), TLHC._TLS13_AES_128_GCM_SHA256_ID, shared_secret, psk)
        io = TLHC._HandshakeMessageFlightIO(inbound)

        @test_throws ArgumentError TLHC._client_handshake_tls13!(state, io)
    end
end
