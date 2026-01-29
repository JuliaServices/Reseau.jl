using Test
using Random
using SHA
using AwsIO
using LibAwsCal

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
