using Test
using Reseau

const TL12H = Reseau.TLS
const _TLS12_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS12_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")
const _TLS12_CERT_PEM = read(_TLS12_CERT_PATH)
const _TLS12_KEY_PEM = read(_TLS12_KEY_PATH)
const _TLS12_SERVER_P256_PRIVATE_KEY = UInt8[
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
]
const _TLS12_SERVER_X25519_PRIVATE_KEY = UInt8[
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
]

function _tls12_make_server_key_exchange(client_random::Vector{UInt8}, server_random::Vector{UInt8})
    pkey = TL12H._tls13_p256_private_key_from_bytes(_TLS12_SERVER_P256_PRIVATE_KEY)
    try
        public_key = TL12H._tls13_p256_public_key(pkey)
        params = UInt8[0x03, UInt8(TL12H.P256 >> 8), UInt8(TL12H.P256 & 0xff), UInt8(length(public_key))]
        append!(params, public_key)
        signed = vcat(client_random, server_random, params)
        signature = TL12H._tls12_openssl_sign_from_pem(TL12H._TLS_SIGNATURE_RSA_PKCS1_SHA256, signed, _TLS12_KEY_PEM)
        key = copy(params)
        append!(key, UInt8[UInt8(TL12H._TLS_SIGNATURE_RSA_PKCS1_SHA256 >> 8), UInt8(TL12H._TLS_SIGNATURE_RSA_PKCS1_SHA256 & 0xff)])
        append!(key, UInt8[UInt8(length(signature) >> 8), UInt8(length(signature) & 0xff)])
        append!(key, signature)
        return TL12H._ServerKeyExchangeMsgTLS12(key), public_key, signature
    finally
        TL12H._free_evp_pkey!(pkey)
    end
end

@testset "TLS 1.2 native client handshake helpers" begin
    @testset "client hello offers exact TLS 1.2 ECDHE suites" begin
        hello = TL12H._tls12_client_hello(TL12H.Config(
            server_name = "localhost",
            verify_peer = false,
            min_version = TL12H.TLS1_2_VERSION,
            max_version = TL12H.TLS1_2_VERSION,
            alpn_protocols = ["h2"],
        ))
        @test hello.vers == TL12H.TLS1_2_VERSION
        @test hello.cipher_suites == UInt16[
            TL12H._TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_ID,
            TL12H._TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_ID,
            TL12H._TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256_ID,
            TL12H._TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384_ID,
        ]
        @test hello.supported_curves == UInt16[TL12H.P256]
        @test hello.supported_points == UInt8[0x00]
        @test hello.extended_master_secret
        @test !hello.ocsp_stapling
        @test !hello.secure_renegotiation_supported
        @test hello.alpn_protocols == ["h2"]

        reordered = TL12H._tls12_client_hello(TL12H.Config(
            server_name = "localhost",
            verify_peer = false,
            min_version = TL12H.TLS1_2_VERSION,
            max_version = TL12H.TLS1_2_VERSION,
            curve_preferences = UInt16[TL12H.X25519, TL12H.P256],
        ))
        @test reordered.supported_curves == UInt16[TL12H.X25519, TL12H.P256]
    end

    @testset "server key exchange parsing and verification follow TLS 1.2 ECDHE-RSA semantics" begin
        state = TL12H._TLS12ClientHandshakeState(TL12H._ClientHelloMsg())
        state.client_hello.random = collect(UInt8(0x10):UInt8(0x2f))
        state.server_hello.random = collect(UInt8(0x80):UInt8(0x9f))
        msg, public_key, signature = _tls12_make_server_key_exchange(state.client_hello.random, state.server_hello.random)
        parsed = TL12H._tls12_parse_server_key_exchange(msg)
        @test parsed.group == TL12H.P256
        @test parsed.public_key == public_key
        @test parsed.signature_algorithm == TL12H._TLS_SIGNATURE_RSA_PKCS1_SHA256
        @test parsed.signature == signature

        pubkey = TL12H._tls13_pubkey_from_der_certificate(TL12H._tls13_openssl_certificate_der(_TLS12_CERT_PEM))
        try
            verified = TL12H._tls12_verify_server_key_exchange!(state, pubkey, msg)
            @test verified.group == TL12H.P256
            @test verified.public_key == public_key
        finally
            TL12H._free_evp_pkey!(pubkey)
        end
    end

    @testset "client key exchange generation returns an encoded EC point" begin
        pkey = TL12H._tls13_p256_private_key_from_bytes(_TLS12_SERVER_P256_PRIVATE_KEY)
        try
            public_key = TL12H._tls13_p256_public_key(pkey)
            msg, shared_secret = TL12H._tls12_generate_client_key_exchange(UInt16[TL12H.P256], TL12H.P256, public_key)
            @test msg isa TL12H._ClientKeyExchangeMsgTLS12
            @test !isempty(shared_secret)
            @test Int(msg.ciphertext[1]) == length(msg.ciphertext) - 1
            @test msg.ciphertext[2] == 0x04
        finally
            TL12H._free_evp_pkey!(pkey)
        end
    end

    @testset "client key exchange generation supports X25519 for TLS 1.2" begin
        pkey = TL12H._tls13_x25519_private_key_from_bytes(_TLS12_SERVER_X25519_PRIVATE_KEY)
        try
            public_key = TL12H._tls13_x25519_public_key(pkey)
            msg, shared_secret = TL12H._tls12_generate_client_key_exchange(UInt16[TL12H.X25519], TL12H.X25519, public_key)
            @test msg isa TL12H._ClientKeyExchangeMsgTLS12
            @test !isempty(shared_secret)
            @test length(msg.ciphertext) == 33
            @test Int(msg.ciphertext[1]) == length(msg.ciphertext) - 1
        finally
            TL12H._free_evp_pkey!(pkey)
        end
    end

    @testset "client key exchange rejects unadvertised TLS 1.2 curves" begin
        pkey = TL12H._tls13_x25519_private_key_from_bytes(_TLS12_SERVER_X25519_PRIVATE_KEY)
        try
            public_key = TL12H._tls13_x25519_public_key(pkey)
            err = try
                TL12H._tls12_generate_client_key_exchange(UInt16[TL12H.P256], TL12H.X25519, public_key)
                nothing
            catch ex
                ex
            end
            @test err isa TL12H._TLS13AlertError
            if err isa TL12H._TLS13AlertError
                @test (err::TL12H._TLS13AlertError).alert == TL12H._TLS_ALERT_ILLEGAL_PARAMETER
            end
        finally
            TL12H._free_evp_pkey!(pkey)
        end
    end
end
