using Test
using Random
using SHA
using AwsIO
using LibAwsCal

const TEST_RSA_PEM = """
-----BEGIN PRIVATE KEY-----
MIICeQIBADANBgkqhkiG9w0BAQEFAASCAmMwggJfAgEAAoGBALjIiBaQGmLNE+Za
6IzRfKk7PsZlYgdh2wuNIIuTncv9zvw/k8K9ZgkUSLbQsTTzV5z8YvMEwYqQpFtr
Fu7mZ60AnwDYLPSTmWDLPfFbsUB4Q7NCLTMs0b9id0IfwYwxwrPojj1znxxLWheA
txcMJJIRG8K8pIjrNRoZH9rhFvoHAgMBAAECgYEAnLwTmrfOecGjwH+Zw2Apkk4b
eCMknEhniQvC8EFc1lvJxvKSfdszAj5/Uvn/ZX+G8DSwJZwCImt/zb8vK6KpioaV
UE4U9qzaC9u1hKC/fK0BJ7IVgq/rnwZ+Sb4w+wj3rm9xSS3dpqCJ0dIRgCawuYyn
RRNnVN7MjUTn6hhFyBECQQDkV6p9MfJN2+PQeA6gAVHbs9DQzgmwsx6fgOaCiCKv
M18nTq59wDe7tzvm62/1xWzpI/Z0RGg/R/fxdARqpEsfAkEAzyo0hgiWEZ/Fof3e
sEQHlos2LIuvutdnXbg1kEVie4+t4Rg+z3M2C4wGAGmOQ6tUDKaMmAtHlvrTDt3c
FuPcGQJBAKIWXM5b+w0rrs5XusH3zdywCuV9rEFDFNTSkk5MRpqpU706TAC1xpo4
movzylji2MmyHosv1/Q7qRQ7b7snfq8CQQC+YtY0W8220rOpRQuTyGGE29lkpNdS
CcXoHnOza+CvF4M/+601r3b6s6uMU3W4AMtUePd6f9tCCK9Q2Vn7+1p5AkEAxFLB
+BlH2A8w2vVfhVvuFXKrtX0Fa5gfrWnzFQb7Fjr6kWImfhTugOpusAITTLE9Q1er
gDtCFQuI7wHfkAvtlQ==
-----END PRIVATE KEY-----
"""

function _hkdf_ref_sha512(ikm::Vector{UInt8}, salt::Vector{UInt8}, info::Vector{UInt8}, out_len::Int)
    if isempty(salt)
        salt = zeros(UInt8, 64)
    end
    prk = SHA.hmac_sha512(salt, ikm)
    okm = UInt8[]
    t = UInt8[]
    counter = UInt8(1)
    while length(okm) < out_len
        t = SHA.hmac_sha512(prk, vcat(t, info, [counter]))
        append!(okm, t)
        counter = counter + UInt8(1)
    end
    return okm[1:out_len]
end

function _buf_to_vec(buf::AwsIO.ByteBuffer)
    cursor = AwsIO.byte_cursor_from_buf(buf)
    len = Int(cursor.len)
    len == 0 && return UInt8[]
    out = Vector{UInt8}(undef, len)
    AwsIO.byte_cursor_read(Ref(cursor), out, len)
    return out
end

function _pem_private_key_der(pem::String)
    parsed = AwsIO.pem_parse(pem)
    @test !(parsed isa AwsIO.ErrorResult)
    parsed isa Vector || return UInt8[]
    keys = AwsIO.pem_filter_private_keys(parsed)
    @test length(keys) == 1
    length(keys) == 1 || return UInt8[]
    return _buf_to_vec(keys[1].data)
end

@testset "crypto primitives - HKDF SHA512" begin
    ikm = Vector{UInt8}(codeunits("awsio-hkdf-ikm"))
    salt = Vector{UInt8}(codeunits("awsio-hkdf-salt"))
    info = Vector{UInt8}(codeunits("awsio-hkdf-info"))
    expected = _hkdf_ref_sha512(ikm, salt, info, 42)

    derived = AwsIO.hkdf_derive(AwsIO.HkdfHmacType.SHA512, ikm; salt = salt, info = info, length = 42)
    @test !(derived isa AwsIO.ErrorResult)
    if derived isa AwsIO.ByteBuffer
        @test _buf_to_vec(derived) == expected
    end
end

@testset "crypto primitives - AES-GCM roundtrip" begin
    Random.seed!(1234)
    key = rand(UInt8, 32)
    iv = rand(UInt8, 12)
    aad = rand(UInt8, 16)
    plaintext = rand(UInt8, 128)

    enc = AwsIO.aes_gcm_256_encrypt(key, iv, aad, plaintext)
    if enc isa AwsIO.ErrorResult
        unsupported = Int(LibAwsCal.aws_cal_errors.AWS_ERROR_CAL_UNSUPPORTED_ALGORITHM)
        @test enc.code == unsupported
        return
    end

    ciphertext = enc.ciphertext
    tag = enc.tag
    dec = AwsIO.aes_gcm_256_decrypt(key, iv, aad, _buf_to_vec(ciphertext), _buf_to_vec(tag))
    @test dec isa AwsIO.ByteBuffer
    if dec isa AwsIO.ByteBuffer
        @test _buf_to_vec(dec) == plaintext
    end

    bad_tag = _buf_to_vec(tag)
    bad_tag[1] = bad_tag[1] ⊻ 0xFF
    bad_dec = AwsIO.aes_gcm_256_decrypt(key, iv, aad, _buf_to_vec(ciphertext), bad_tag)
    @test bad_dec isa AwsIO.ErrorResult
end

@testset "crypto primitives - ECC sign/verify" begin
    Random.seed!(5678)
    pair = AwsIO.ecc_key_pair_generate(AwsIO.EccCurveName.P256)
    @test pair isa AwsIO.EccKeyPair
    pair isa AwsIO.EccKeyPair || return

    message = rand(UInt8, 128)
    signature = AwsIO.ecc_sign(pair, message)
    @test signature isa AwsIO.ByteBuffer
    signature isa AwsIO.ByteBuffer || return

    verified = AwsIO.ecc_verify(pair, message, signature)
    @test verified === true
end

@testset "crypto primitives - RSA sign/verify + encrypt" begin
    Random.seed!(9012)
    key_der = _pem_private_key_der(TEST_RSA_PEM)
    isempty(key_der) && return

    pair = AwsIO.rsa_key_pair_new_from_private_key_pkcs8(key_der)
    @test pair isa AwsIO.RsaKeyPair
    pair isa AwsIO.RsaKeyPair || return

    public_key = AwsIO.rsa_key_pair_get_public_key(pair)
    if public_key isa AwsIO.ErrorResult
        @test public_key.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED
        pub_pair = pair
    else
        @test public_key isa AwsIO.ByteBuffer
        public_key isa AwsIO.ByteBuffer || return
        pub_pair = AwsIO.rsa_key_pair_new_from_public_key_pkcs1(_buf_to_vec(public_key))
        @test pub_pair isa AwsIO.RsaKeyPair
        pub_pair isa AwsIO.RsaKeyPair || return
    end

    message = rand(UInt8, 64)
    digest = SHA.sha256(message)
    signature = AwsIO.rsa_key_pair_sign_message(
        pair,
        AwsIO.RsaSignatureAlgorithm.PKCS1_5_SHA256,
        digest,
    )
    @test signature isa AwsIO.ByteBuffer
    signature isa AwsIO.ByteBuffer || return

    verified = AwsIO.rsa_key_pair_verify_signature(
        pub_pair,
        AwsIO.RsaSignatureAlgorithm.PKCS1_5_SHA256,
        digest,
        _buf_to_vec(signature),
    )
    @test verified === true

    plaintext = rand(UInt8, 32)
    encrypted = AwsIO.rsa_key_pair_encrypt(
        pub_pair,
        AwsIO.RsaEncryptionAlgorithm.PKCS1_5,
        plaintext,
    )
    @test encrypted isa AwsIO.ByteBuffer
    encrypted isa AwsIO.ByteBuffer || return

    decrypted = AwsIO.rsa_key_pair_decrypt(
        pair,
        AwsIO.RsaEncryptionAlgorithm.PKCS1_5,
        _buf_to_vec(encrypted),
    )
    @test decrypted isa AwsIO.ByteBuffer
    decrypted isa AwsIO.ByteBuffer || return
    @test _buf_to_vec(decrypted) == plaintext
end
