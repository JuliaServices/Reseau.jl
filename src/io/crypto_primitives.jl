# AWS IO Library - Crypto Primitives (LibAwsCal-backed)

@enumx HkdfHmacType::UInt8 begin
    SHA512 = 0
end

@enumx EccCurveName::UInt8 begin
    P256 = 0
    P384 = 1
end

@enumx RsaEncryptionAlgorithm::UInt8 begin
    PKCS1_5 = 0
    OAEP_SHA256 = 1
    OAEP_SHA512 = 2
end

@enumx RsaSignatureAlgorithm::UInt8 begin
    PKCS1_5_SHA256 = 0
    PKCS1_5_SHA1 = 1
    PSS_SHA256 = 2
end

mutable struct EccKeyPair
    handle::Ptr{LibAwsCal.aws_ecc_key_pair}
end

mutable struct RsaKeyPair
    handle::Ptr{LibAwsCal.aws_rsa_key_pair}
end

@inline function _crypto_last_error()
    code = Int(LibAwsCommon.aws_last_error())
    if code == 0
        code = Int(last_error())
    end
    raise_error(code)
    return ErrorResult(code)
end

@inline function _ecc_curve_native(curve::EccCurveName.T)
    if curve == EccCurveName.P256
        return LibAwsCal.AWS_CAL_ECDSA_P256
    end
    return LibAwsCal.AWS_CAL_ECDSA_P384
end

@inline function _rsa_encryption_native(alg::RsaEncryptionAlgorithm.T)
    if alg == RsaEncryptionAlgorithm.PKCS1_5
        return LibAwsCal.AWS_CAL_RSA_ENCRYPTION_PKCS1_5
    elseif alg == RsaEncryptionAlgorithm.OAEP_SHA256
        return LibAwsCal.AWS_CAL_RSA_ENCRYPTION_OAEP_SHA256
    end
    return LibAwsCal.AWS_CAL_RSA_ENCRYPTION_OAEP_SHA512
end

@inline function _rsa_signature_native(alg::RsaSignatureAlgorithm.T)
    if alg == RsaSignatureAlgorithm.PKCS1_5_SHA256
        return LibAwsCal.AWS_CAL_RSA_SIGNATURE_PKCS1_5_SHA256
    elseif alg == RsaSignatureAlgorithm.PKCS1_5_SHA1
        return LibAwsCal.AWS_CAL_RSA_SIGNATURE_PKCS1_5_SHA1
    end
    return LibAwsCal.AWS_CAL_RSA_SIGNATURE_PSS_SHA256
end

@inline _aws_byte_cursor_from_key(key::AbstractVector{UInt8}) = _aws_byte_cursor_from_vec(key)
@inline _aws_byte_cursor_from_key(key::ByteBuffer) = _aws_byte_cursor_from_buf(key)

function hkdf_derive(
        hmac_type::HkdfHmacType.T,
        ikm::AbstractVector{UInt8};
        salt::AbstractVector{UInt8} = UInt8[],
        info::AbstractVector{UInt8} = UInt8[],
        length::Integer,
    )::Union{ByteBuffer, ErrorResult}
    _cal_init()
    if hmac_type != HkdfHmacType.SHA512
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end
    allocator = LibAwsCommon.default_aws_allocator()

    ikm_cur = _aws_byte_cursor_from_vec(ikm)
    salt_cur = _aws_byte_cursor_from_vec(salt)
    info_cur = _aws_byte_cursor_from_vec(info)
    out = ByteBuffer(length)
    out_buf_ref = Ref(_aws_byte_buf_from_vec(out.mem))

    cal_hmac = LibAwsCal.HKDF_HMAC_SHA512
    GC.@preserve ikm salt info out begin
        rv = LibAwsCal.aws_hkdf_derive(
            allocator,
            cal_hmac,
            ikm_cur,
            salt_cur,
            info_cur,
            out_buf_ref,
            Csize_t(length),
        )
        rv == 0 || return _crypto_last_error()
    end

    out_buf = out_buf_ref[]
    return ByteBuffer(out.mem, out_buf.len)
end

function ecc_key_pair_generate(curve::EccCurveName.T = EccCurveName.P256)::Union{EccKeyPair, ErrorResult}
    _cal_init()
    allocator = LibAwsCommon.default_aws_allocator()
    handle = LibAwsCal.aws_ecc_key_pair_new_generate_random(allocator, _ecc_curve_native(curve))
    handle == C_NULL && return _crypto_last_error()
    pair = EccKeyPair(handle)
    finalizer(pair) do p
        LibAwsCal.aws_ecc_key_pair_release(p.handle)
    end
    return pair
end

function ecc_sign(
        pair::EccKeyPair,
        message::AbstractVector{UInt8},
    )::Union{ByteBuffer, ErrorResult}
    _cal_init()
    sig_len = LibAwsCal.aws_ecc_key_pair_signature_length(pair.handle)
    sig = Memory{UInt8}(undef, Int(sig_len))
    sig_buf_ref = Ref(_aws_byte_buf_from_vec(sig))
    msg_cur = _aws_byte_cursor_from_vec(message)

    GC.@preserve message sig begin
        if LibAwsCal.aws_ecc_key_pair_sign_message(pair.handle, Ref(msg_cur), sig_buf_ref) != 0
            return _crypto_last_error()
        end
    end

    sig_buf = sig_buf_ref[]
    return ByteBuffer(sig, sig_buf.len)
end

function ecc_verify(
        pair::EccKeyPair,
        message::AbstractVector{UInt8},
        signature::ByteBuffer,
    )::Union{Bool, ErrorResult}
    _cal_init()
    msg_cur = _aws_byte_cursor_from_vec(message)
    sig_cur = _aws_byte_cursor_from_buf(signature)
    GC.@preserve message signature begin
        rv = LibAwsCal.aws_ecc_key_pair_verify_signature(pair.handle, Ref(msg_cur), Ref(sig_cur))
        rv == 0 && return true
    end
    return _crypto_last_error()
end

function rsa_key_pair_new_from_public_key_pkcs1(
        key::Union{AbstractVector{UInt8}, ByteBuffer},
    )::Union{RsaKeyPair, ErrorResult}
    _cal_init()
    allocator = LibAwsCommon.default_aws_allocator()
    key_cur = _aws_byte_cursor_from_key(key)
    handle = LibAwsCal.aws_rsa_key_pair_new_from_public_key_pkcs1(allocator, key_cur)
    handle == C_NULL && return _crypto_last_error()
    pair = RsaKeyPair(handle)
    finalizer(pair) do p
        LibAwsCal.aws_rsa_key_pair_release(p.handle)
    end
    return pair
end

function rsa_key_pair_new_from_private_key_pkcs1(
        key::Union{AbstractVector{UInt8}, ByteBuffer},
    )::Union{RsaKeyPair, ErrorResult}
    _cal_init()
    allocator = LibAwsCommon.default_aws_allocator()
    key_cur = _aws_byte_cursor_from_key(key)
    handle = LibAwsCal.aws_rsa_key_pair_new_from_private_key_pkcs1(allocator, key_cur)
    handle == C_NULL && return _crypto_last_error()
    pair = RsaKeyPair(handle)
    finalizer(pair) do p
        LibAwsCal.aws_rsa_key_pair_release(p.handle)
    end
    return pair
end

function rsa_key_pair_new_from_private_key_pkcs8(
        key::Union{AbstractVector{UInt8}, ByteBuffer},
    )::Union{RsaKeyPair, ErrorResult}
    _cal_init()
    allocator = LibAwsCommon.default_aws_allocator()
    key_cur = _aws_byte_cursor_from_key(key)
    handle = LibAwsCal.aws_rsa_key_pair_new_from_private_key_pkcs8(allocator, key_cur)
    handle == C_NULL && return _crypto_last_error()
    pair = RsaKeyPair(handle)
    finalizer(pair) do p
        LibAwsCal.aws_rsa_key_pair_release(p.handle)
    end
    return pair
end

@inline function rsa_key_pair_block_length(pair::RsaKeyPair)::Csize_t
    return LibAwsCal.aws_rsa_key_pair_block_length(pair.handle)
end

@inline function rsa_key_pair_signature_length(pair::RsaKeyPair)::Csize_t
    return LibAwsCal.aws_rsa_key_pair_signature_length(pair.handle)
end

@inline function rsa_key_pair_max_encrypt_plaintext_size(
        pair::RsaKeyPair,
        algorithm::RsaEncryptionAlgorithm.T,
    )::Csize_t
    return LibAwsCal.aws_rsa_key_pair_max_encrypt_plaintext_size(pair.handle, _rsa_encryption_native(algorithm))
end

function rsa_key_pair_get_public_key(pair::RsaKeyPair)::Union{ByteBuffer, ErrorResult}
    _cal_init()
    allocator = LibAwsCommon.default_aws_allocator()
    buf_ref = Ref{LibAwsCommon.aws_byte_buf}()
    block_len = Int(rsa_key_pair_block_length(pair))
    capacity = max(256, block_len * 4)
    if LibAwsCommon.aws_byte_buf_init(buf_ref, allocator, Csize_t(capacity)) != 0
        return _crypto_last_error()
    end
    rv = LibAwsCal.aws_rsa_key_pair_get_public_key(
        pair.handle,
        LibAwsCal.AWS_CAL_RSA_KEY_EXPORT_PKCS1,
        buf_ref,
    )
    rv == 0 || begin
        LibAwsCommon.aws_byte_buf_clean_up(buf_ref)
        return _crypto_last_error()
    end
    buf = buf_ref[]
    len = Int(buf.len)
    out = ByteBuffer(len)
    if len > 0
        GC.@preserve out begin
            unsafe_copyto!(pointer(out.mem), buf.buffer, len)
        end
    end
    LibAwsCommon.aws_byte_buf_clean_up(buf_ref)
    return ByteBuffer(out.mem, len)
end

function rsa_key_pair_get_private_key(pair::RsaKeyPair)::Union{ByteBuffer, ErrorResult}
    _cal_init()
    allocator = LibAwsCommon.default_aws_allocator()
    buf_ref = Ref{LibAwsCommon.aws_byte_buf}()
    block_len = Int(rsa_key_pair_block_length(pair))
    capacity = max(256, block_len * 4)
    if LibAwsCommon.aws_byte_buf_init(buf_ref, allocator, Csize_t(capacity)) != 0
        return _crypto_last_error()
    end
    rv = LibAwsCal.aws_rsa_key_pair_get_private_key(
        pair.handle,
        LibAwsCal.AWS_CAL_RSA_KEY_EXPORT_PKCS1,
        buf_ref,
    )
    rv == 0 || begin
        LibAwsCommon.aws_byte_buf_clean_up(buf_ref)
        return _crypto_last_error()
    end
    buf = buf_ref[]
    len = Int(buf.len)
    out = ByteBuffer(len)
    if len > 0
        GC.@preserve out begin
            unsafe_copyto!(pointer(out.mem), buf.buffer, len)
        end
    end
    LibAwsCommon.aws_byte_buf_clean_up(buf_ref)
    return ByteBuffer(out.mem, len)
end

function rsa_key_pair_encrypt(
        pair::RsaKeyPair,
        algorithm::RsaEncryptionAlgorithm.T,
        plaintext::AbstractVector{UInt8},
    )::Union{ByteBuffer, ErrorResult}
    _cal_init()
    out = ByteBuffer(Int(rsa_key_pair_block_length(pair)))
    out_buf_ref = Ref(_aws_byte_buf_from_vec(out.mem))
    pt_cur = _aws_byte_cursor_from_vec(plaintext)
    rv = LibAwsCal.aws_rsa_key_pair_encrypt(pair.handle, _rsa_encryption_native(algorithm), pt_cur, out_buf_ref)
    rv == 0 || return _crypto_last_error()
    out_buf = out_buf_ref[]
    return ByteBuffer(out.mem, out_buf.len)
end

function rsa_key_pair_decrypt(
        pair::RsaKeyPair,
        algorithm::RsaEncryptionAlgorithm.T,
        ciphertext::AbstractVector{UInt8},
    )::Union{ByteBuffer, ErrorResult}
    _cal_init()
    out = ByteBuffer(Int(rsa_key_pair_block_length(pair)))
    out_buf_ref = Ref(_aws_byte_buf_from_vec(out.mem))
    ct_cur = _aws_byte_cursor_from_vec(ciphertext)
    rv = LibAwsCal.aws_rsa_key_pair_decrypt(pair.handle, _rsa_encryption_native(algorithm), ct_cur, out_buf_ref)
    rv == 0 || return _crypto_last_error()
    out_buf = out_buf_ref[]
    return ByteBuffer(out.mem, out_buf.len)
end

function rsa_key_pair_sign_message(
        pair::RsaKeyPair,
        algorithm::RsaSignatureAlgorithm.T,
        digest::AbstractVector{UInt8},
    )::Union{ByteBuffer, ErrorResult}
    _cal_init()
    out = ByteBuffer(Int(rsa_key_pair_signature_length(pair)))
    out_buf_ref = Ref(_aws_byte_buf_from_vec(out.mem))
    dig_cur = _aws_byte_cursor_from_vec(digest)
    rv = LibAwsCal.aws_rsa_key_pair_sign_message(pair.handle, _rsa_signature_native(algorithm), dig_cur, out_buf_ref)
    rv == 0 || return _crypto_last_error()
    out_buf = out_buf_ref[]
    return ByteBuffer(out.mem, out_buf.len)
end

function rsa_key_pair_verify_signature(
        pair::RsaKeyPair,
        algorithm::RsaSignatureAlgorithm.T,
        digest::AbstractVector{UInt8},
        signature::AbstractVector{UInt8},
    )::Union{Bool, ErrorResult}
    _cal_init()
    dig_cur = _aws_byte_cursor_from_vec(digest)
    sig_cur = _aws_byte_cursor_from_vec(signature)
    rv = LibAwsCal.aws_rsa_key_pair_verify_signature(pair.handle, _rsa_signature_native(algorithm), dig_cur, sig_cur)
    rv == 0 && return true
    return _crypto_last_error()
end

function aes_gcm_256_encrypt(
        key::AbstractVector{UInt8},
        iv::AbstractVector{UInt8},
        aad::AbstractVector{UInt8},
        plaintext::AbstractVector{UInt8},
    )::Union{NamedTuple{(:ciphertext, :tag), Tuple{ByteBuffer, ByteBuffer}}, ErrorResult}
    _cal_init()
    allocator = LibAwsCommon.default_aws_allocator()
    key_cur = _aws_byte_cursor_from_vec(key)
    iv_cur = _aws_byte_cursor_from_vec(iv)
    aad_cur = _aws_byte_cursor_from_vec(aad)
    cipher = LibAwsCal.aws_aes_gcm_256_new(allocator, Ref(key_cur), Ref(iv_cur), Ref(aad_cur))
    cipher == C_NULL && return _crypto_last_error()

    out = ByteBuffer(length(plaintext) + 16)
    out_buf_ref = Ref(_aws_byte_buf_from_vec(out.mem))
    plain_cur = _aws_byte_cursor_from_vec(plaintext)
    tag_buf = ByteBuffer(16)

    try
        GC.@preserve key iv aad plaintext out begin
            if LibAwsCal.aws_symmetric_cipher_encrypt(cipher, plain_cur, out_buf_ref) != 0
                return _crypto_last_error()
            end
            if LibAwsCal.aws_symmetric_cipher_finalize_encryption(cipher, out_buf_ref) != 0
                return _crypto_last_error()
            end
        end
        tag_cur = LibAwsCal.aws_symmetric_cipher_get_tag(cipher)
        tag_len = Int(tag_cur.len)
        tag_mem = tag_len == 0 ? Memory{UInt8}(undef, 0) :
            unsafe_wrap(Memory{UInt8}, tag_cur.ptr, tag_len; own = false)
        tag_cursor = ByteCursor(tag_mem, tag_len)
        tag_buf_ref = Ref(tag_buf)
        if byte_buf_init_copy_from_cursor(tag_buf_ref, tag_cursor) != OP_SUCCESS
            return _crypto_last_error()
        end
        tag_buf = tag_buf_ref[]
    finally
        LibAwsCal.aws_symmetric_cipher_destroy(cipher)
    end

    out_buf = out_buf_ref[]
    ciphertext = ByteBuffer(out.mem, out_buf.len)
    return (ciphertext = ciphertext, tag = tag_buf)
end

function aes_gcm_256_decrypt(
        key::AbstractVector{UInt8},
        iv::AbstractVector{UInt8},
        aad::AbstractVector{UInt8},
        ciphertext::AbstractVector{UInt8},
        tag::AbstractVector{UInt8},
    )::Union{ByteBuffer, ErrorResult}
    _cal_init()
    allocator = LibAwsCommon.default_aws_allocator()
    key_cur = _aws_byte_cursor_from_vec(key)
    iv_cur = _aws_byte_cursor_from_vec(iv)
    aad_cur = _aws_byte_cursor_from_vec(aad)
    cipher = LibAwsCal.aws_aes_gcm_256_new(allocator, Ref(key_cur), Ref(iv_cur), Ref(aad_cur))
    cipher == C_NULL && return _crypto_last_error()

    out = ByteBuffer(length(ciphertext) + 16)
    out_buf_ref = Ref(_aws_byte_buf_from_vec(out.mem))
    ct_cur = _aws_byte_cursor_from_vec(ciphertext)
    tag_cur = _aws_byte_cursor_from_vec(tag)

    try
        GC.@preserve key iv aad ciphertext out tag begin
            LibAwsCal.aws_symmetric_cipher_set_tag(cipher, tag_cur)
            if LibAwsCal.aws_symmetric_cipher_decrypt(cipher, ct_cur, out_buf_ref) != 0
                return _crypto_last_error()
            end
            if LibAwsCal.aws_symmetric_cipher_finalize_decryption(cipher, out_buf_ref) != 0
                return _crypto_last_error()
            end
        end
    finally
        LibAwsCal.aws_symmetric_cipher_destroy(cipher)
    end

    out_buf = out_buf_ref[]
    return ByteBuffer(out.mem, out_buf.len)
end
