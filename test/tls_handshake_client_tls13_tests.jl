using Test
using Reseau

const TLHC = Reseau.TLS

function _tls13_psk_client_hello()
    msg = TLHC._ClientHelloMsg()
    msg.vers = TLHC.TLS1_2_VERSION
    msg.random = collect(UInt8(0x00):UInt8(0x1f))
    msg.session_id = UInt8[0xaa, 0xbb, 0xcc, 0xdd]
    msg.cipher_suites = UInt16[TLHC._TLS13_AES_128_GCM_SHA256_ID]
    msg.compression_methods = UInt8[TLHC._TLS_COMPRESSION_NONE]
    msg.server_name = "localhost"
    msg.alpn_protocols = ["h2"]
    msg.supported_versions = UInt16[TLHC.TLS1_3_VERSION]
    msg.key_shares = [TLHC._TLSKeyShare(0x001d, UInt8[0x01, 0x02, 0x03, 0x04])]
    msg.psk_modes = UInt8[TLHC._TLS_PSK_MODE_DHE]
    msg.psk_identities = [TLHC._TLSPSKIdentity(UInt8[0x50, 0x51, 0x52], 0x01020304)]
    msg.psk_binders = [zeros(UInt8, 32)]
    return msg
end

function _tls13_psk_server_hello(session_id::Vector{UInt8}; group::UInt16 = 0x001d, selected_identity_present::Bool = true)
    msg = TLHC._ServerHelloMsg()
    msg.vers = TLHC.TLS1_2_VERSION
    msg.random = collect(UInt8(0x80):UInt8(0x9f))
    msg.session_id = copy(session_id)
    msg.cipher_suite = TLHC._TLS13_AES_128_GCM_SHA256_ID
    msg.compression_method = TLHC._TLS_COMPRESSION_NONE
    msg.supported_version = TLHC.TLS1_3_VERSION
    msg.server_share = TLHC._TLSKeyShare(group, UInt8[0x05, 0x06, 0x07, 0x08])
    msg.selected_identity_present = selected_identity_present
    msg.selected_identity = UInt16(0)
    return msg
end

function _compute_tls13_psk_server_flight(client_hello::TLHC._ClientHelloMsg, shared_secret::Vector{UInt8}, psk::Vector{UInt8})
    early_secret = TLHC._tls13_early_secret(TLHC._HASH_SHA256, psk)
    binder_key = TLHC._tls13_resumption_binder_key(early_secret)
    binder_transcript = TLHC._TranscriptHash(TLHC._HASH_SHA256; buffer_handshake = false)
    TLHC._transcript_update!(binder_transcript, TLHC._marshal_client_hello_without_binders(client_hello))
    binder = TLHC._tls13_finished_verify_data(TLHC._HASH_SHA256, binder_key, binder_transcript)
    TLHC._update_client_hello_binders!(client_hello, [binder])

    client_bytes = TLHC._marshal_handshake_message(client_hello)
    server_hello = _tls13_psk_server_hello(client_hello.session_id)
    server_hello_bytes = TLHC._marshal_handshake_message(server_hello)

    transcript = TLHC._TranscriptHash(TLHC._HASH_SHA256)
    TLHC._transcript_update!(transcript, client_bytes)
    TLHC._transcript_update!(transcript, server_hello_bytes)

    handshake_secret = TLHC._tls13_handshake_secret(early_secret, shared_secret)
    client_handshake_traffic_secret = TLHC._tls13_client_handshake_traffic_secret(handshake_secret, transcript)
    server_handshake_traffic_secret = TLHC._tls13_server_handshake_traffic_secret(handshake_secret, transcript)

    encrypted_extensions = TLHC._EncryptedExtensionsMsg()
    encrypted_extensions.alpn_protocol = "h2"
    encrypted_extensions_bytes = TLHC._marshal_handshake_message(encrypted_extensions)
    TLHC._transcript_update!(transcript, encrypted_extensions_bytes)

    server_finished = TLHC._FinishedMsg(TLHC._tls13_finished_verify_data(TLHC._TLS13_AES_128_GCM_SHA256, server_handshake_traffic_secret, transcript))
    server_finished_bytes = TLHC._marshal_handshake_message(server_finished)
    TLHC._transcript_update!(transcript, server_finished_bytes)

    client_finished = TLHC._FinishedMsg(TLHC._tls13_finished_verify_data(TLHC._TLS13_AES_128_GCM_SHA256, client_handshake_traffic_secret, transcript))
    client_finished_bytes = TLHC._marshal_handshake_message(client_finished)

    master_secret = TLHC._tls13_master_secret(handshake_secret)
    client_application_traffic_secret = TLHC._tls13_client_application_traffic_secret(master_secret, transcript)
    server_application_traffic_secret = TLHC._tls13_server_application_traffic_secret(master_secret, transcript)
    exporter_master_secret = TLHC._tls13_exporter_secret_for_test(TLHC._tls13_exporter_master_secret(master_secret, transcript))

    ticket = TLHC._NewSessionTicketMsgTLS13()
    ticket.lifetime = 0x01020304
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

@testset "TLS 1.3 client handshake phase 2" begin
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

    @testset "certificate path is rejected explicitly for now" begin
        shared_secret = UInt8[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
        psk = UInt8[0x41, 0x42, 0x43, 0x44, 0x45, 0x46]

        expected_client_hello = _tls13_psk_client_hello()
        expected = _compute_tls13_psk_server_flight(expected_client_hello, shared_secret, psk)
        server_hello = _tls13_psk_server_hello(expected_client_hello.session_id; selected_identity_present = false)
        server_hello_bytes = TLHC._marshal_handshake_message(server_hello)

        io = TLHC._HandshakeMessageFlightIO([server_hello_bytes])
        state = TLHC._TLS13ClientHandshakeState(_tls13_psk_client_hello(), TLHC._TLS13_AES_128_GCM_SHA256_ID, shared_secret, psk)

        @test_throws ArgumentError TLHC._client_handshake_tls13!(state, io)
        @test length(io.outbound) == 1
    end

    @testset "HelloRetryRequest is rejected explicitly for now" begin
        shared_secret = UInt8[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
        psk = UInt8[0x41, 0x42, 0x43, 0x44, 0x45, 0x46]
        hello_retry = _tls13_psk_server_hello(UInt8[0xaa, 0xbb, 0xcc, 0xdd])
        hello_retry.random = copy(TLHC._HELLO_RETRY_REQUEST_RANDOM)
        hello_retry.cookie = UInt8[0x01, 0x02, 0x03]
        hello_retry.server_share = nothing
        hello_retry.selected_group = 0x001d
        io = TLHC._HandshakeMessageFlightIO([TLHC._marshal_handshake_message(hello_retry)])
        state = TLHC._TLS13ClientHandshakeState(_tls13_psk_client_hello(), TLHC._TLS13_AES_128_GCM_SHA256_ID, shared_secret, psk)

        @test_throws ArgumentError TLHC._client_handshake_tls13!(state, io)
        @test length(io.outbound) == 1
    end

    @testset "accepted early data is rejected until that path is implemented" begin
        shared_secret = UInt8[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
        psk = UInt8[0x41, 0x42, 0x43, 0x44, 0x45, 0x46]
        client_hello = _tls13_psk_client_hello()
        client_hello.early_data = true
        expected = _compute_tls13_psk_server_flight(client_hello, shared_secret, psk)
        encrypted_extensions = TLHC._EncryptedExtensionsMsg()
        encrypted_extensions.alpn_protocol = "h2"
        encrypted_extensions.early_data = true
        encrypted_extensions_bytes = TLHC._marshal_handshake_message(encrypted_extensions)
        io = TLHC._HandshakeMessageFlightIO([expected.inbound[1], encrypted_extensions_bytes, expected.inbound[3]])
        state = TLHC._TLS13ClientHandshakeState(_tls13_psk_client_hello(), TLHC._TLS13_AES_128_GCM_SHA256_ID, shared_secret, psk)
        state.client_hello.early_data = true

        @test_throws ArgumentError TLHC._client_handshake_tls13!(state, io)
        @test length(io.outbound) == 1
    end

    @testset "unsupported server groups are rejected" begin
        shared_secret = UInt8[0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38]
        psk = UInt8[0x41, 0x42, 0x43, 0x44, 0x45, 0x46]
        bad_server_hello = _tls13_psk_server_hello(UInt8[0xaa, 0xbb, 0xcc, 0xdd]; group = 0x0017)
        io = TLHC._HandshakeMessageFlightIO([TLHC._marshal_handshake_message(bad_server_hello)])
        state = TLHC._TLS13ClientHandshakeState(_tls13_psk_client_hello(), TLHC._TLS13_AES_128_GCM_SHA256_ID, shared_secret, psk)

        @test_throws ArgumentError TLHC._client_handshake_tls13!(state, io)
        @test length(io.outbound) == 1
    end
end
