const _TLS_SIGNATURE_ECDSA_SECP256R1_SHA256 = UInt16(0x0403)
const _TLS_SIGNATURE_ECDSA_SECP384R1_SHA384 = UInt16(0x0503)
const _TLS_SIGNATURE_ECDSA_SECP521R1_SHA512 = UInt16(0x0603)
const _TLS_SIGNATURE_RSA_PKCS1_SHA256 = UInt16(0x0401)
const _TLS_SIGNATURE_RSA_PKCS1_SHA384 = UInt16(0x0501)
const _TLS_SIGNATURE_RSA_PKCS1_SHA512 = UInt16(0x0601)
const _TLS_SIGNATURE_RSA_PSS_RSAE_SHA256 = UInt16(0x0804)
const _TLS_SIGNATURE_RSA_PSS_RSAE_SHA384 = UInt16(0x0805)
const _TLS_SIGNATURE_RSA_PSS_RSAE_SHA512 = UInt16(0x0806)
const _TLS_SIGNATURE_ED25519 = UInt16(0x0807)
const _TLS_SIGNATURE_RSA_PSS_PSS_SHA256 = UInt16(0x0809)
const _TLS_SIGNATURE_RSA_PSS_PSS_SHA384 = UInt16(0x080a)
const _TLS_SIGNATURE_RSA_PSS_PSS_SHA512 = UInt16(0x080b)

const _TLS_GROUP_SECP256R1 = UInt16(0x0017)
const _TLS_GROUP_X25519 = UInt16(0x001d)

const _X25519_PKEY_ID = Ref{Cint}(0)
const _ED25519_PKEY_ID = Ref{Cint}(0)
const _P256_GROUP_NID = Ref{Cint}(0)
const _P384_GROUP_NID = Ref{Cint}(0)
const _P521_GROUP_NID = Ref{Cint}(0)

struct _TLSKeyShareSecret
    group::UInt16
    share_data::Vector{UInt8}
    secret::Vector{UInt8}
end

function _init_x25519_pkey_id!()::Cint
    nid = _X25519_PKEY_ID[]
    nid > 0 && return nid
    nid = ccall((:OBJ_sn2nid, _LIBCRYPTO_PATH), Cint, (Cstring,), "X25519")
    nid > 0 || throw(ArgumentError("failed to initialize OpenSSL X25519 provider"))
    _X25519_PKEY_ID[] = nid
    return nid
end

function _init_ed25519_pkey_id!()::Cint
    nid = _ED25519_PKEY_ID[]
    nid > 0 && return nid
    nid = ccall((:OBJ_sn2nid, _LIBCRYPTO_PATH), Cint, (Cstring,), "ED25519")
    nid > 0 || throw(ArgumentError("failed to initialize OpenSSL Ed25519 provider"))
    _ED25519_PKEY_ID[] = nid
    return nid
end

function _init_p256_group_nid!()::Cint
    nid = _P256_GROUP_NID[]
    nid > 0 && return nid
    nid = ccall((:OBJ_sn2nid, _LIBCRYPTO_PATH), Cint, (Cstring,), "prime256v1")
    nid > 0 || throw(ArgumentError("failed to initialize OpenSSL P-256 provider"))
    _P256_GROUP_NID[] = nid
    return nid
end

function _init_p384_group_nid!()::Cint
    nid = _P384_GROUP_NID[]
    nid > 0 && return nid
    nid = ccall((:OBJ_sn2nid, _LIBCRYPTO_PATH), Cint, (Cstring,), "secp384r1")
    nid > 0 || throw(ArgumentError("failed to initialize OpenSSL P-384 provider"))
    _P384_GROUP_NID[] = nid
    return nid
end

function _init_p521_group_nid!()::Cint
    nid = _P521_GROUP_NID[]
    nid > 0 && return nid
    nid = ccall((:OBJ_sn2nid, _LIBCRYPTO_PATH), Cint, (Cstring,), "secp521r1")
    nid > 0 || throw(ArgumentError("failed to initialize OpenSSL P-521 provider"))
    _P521_GROUP_NID[] = nid
    return nid
end

@inline function _openssl_require_nonnull(ptr::Ptr{Cvoid}, op::AbstractString)::Ptr{Cvoid}
    ptr == C_NULL && throw(_make_tls_error(String(op), Int32(0)))
    return ptr
end

@inline function _openssl_require_ok(ok::Integer, op::AbstractString)::Nothing
    ok == 1 || throw(_make_tls_error(String(op), Int32(ok)))
    return nothing
end

@inline function _free_evp_pkey!(pkey::Ptr{Cvoid})::Nothing
    pkey == C_NULL || ccall((:EVP_PKEY_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), pkey)
    return nothing
end

@inline function _up_ref_evp_pkey!(pkey::Ptr{Cvoid})::Ptr{Cvoid}
    pkey == C_NULL && return C_NULL
    _openssl_require_ok(
        ccall((:EVP_PKEY_up_ref, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid},), pkey),
        "EVP_PKEY_up_ref",
    )
    return pkey
end

@inline function _free_evp_pkey_ctx!(ctx::Ptr{Cvoid})::Nothing
    ctx == C_NULL || ccall((:EVP_PKEY_CTX_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), ctx)
    return nothing
end

@inline function _free_evp_md_ctx!(ctx::Ptr{Cvoid})::Nothing
    ctx == C_NULL || ccall((:EVP_MD_CTX_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), ctx)
    return nothing
end

@inline function _free_evp_cipher_ctx!(ctx::Ptr{Cvoid})::Nothing
    ctx == C_NULL || ccall((:EVP_CIPHER_CTX_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), ctx)
    return nothing
end

@inline function _reset_evp_cipher_ctx!(ctx::Ptr{Cvoid})::Nothing
    _openssl_require_ok(
        ccall((:EVP_CIPHER_CTX_reset, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid},), ctx),
        "EVP_CIPHER_CTX_reset",
    )
    return nothing
end

"""
    _OpenSSLAEADState

Persistent AEAD backend state for one record-protection direction.

The native TLS record layer keeps one of these per read/write direction so we can
reuse an `EVP_CIPHER_CTX` across records instead of allocating and freeing a
fresh OpenSSL cipher context for every seal/open operation.
"""
mutable struct _OpenSSLAEADState
    cipher::Ptr{Cvoid}
    ctx::Ptr{Cvoid}
    iv_len::Int
end

function _OpenSSLAEADState(cipher::Ptr{Cvoid}, iv_len::Int)
    ctx = ccall((:EVP_CIPHER_CTX_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
    _openssl_require_nonnull(ctx, "EVP_CIPHER_CTX_new")
    return _OpenSSLAEADState(cipher, ctx, iv_len)
end

function _free_openssl_aead_state!(state::_OpenSSLAEADState)::Nothing
    _free_evp_cipher_ctx!(state.ctx)
    state.ctx = C_NULL
    return nothing
end

@inline function _free_bio!(bio::Ptr{Cvoid})::Nothing
    bio == C_NULL || ccall((:BIO_free, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid},), bio)
    return nothing
end

@inline function _free_x509!(x509::Ptr{Cvoid})::Nothing
    x509 == C_NULL || ccall((:X509_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), x509)
    return nothing
end

@inline function _free_ec_key!(key::Ptr{Cvoid})::Nothing
    key == C_NULL || ccall((:EC_KEY_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), key)
    return nothing
end

@inline function _free_rsa!(rsa::Ptr{Cvoid})::Nothing
    rsa == C_NULL || ccall((:RSA_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), rsa)
    return nothing
end

@inline function _free_ec_point!(point::Ptr{Cvoid})::Nothing
    point == C_NULL || ccall((:EC_POINT_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), point)
    return nothing
end

@inline function _free_bn!(bn::Ptr{Cvoid})::Nothing
    bn == C_NULL || ccall((:BN_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), bn)
    return nothing
end

@inline function _free_bn_ctx!(ctx::Ptr{Cvoid})::Nothing
    ctx == C_NULL || ccall((:BN_CTX_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), ctx)
    return nothing
end

"""
    _TLSSignatureVerifySpec

Backend-neutral description of how a signature should be verified.

The native X.509 and handshake code map certificate or TLS signature schemes to
this struct, then the OpenSSL primitive backend uses it to drive EVP without
having to understand higher-level certificate policy.
"""
struct _TLSSignatureVerifySpec
    digest_bits::UInt16
    direct::Bool
    rsa_pss::Bool
end

struct _OpenSSLParam
    key::Cstring
    data_type::Cuint
    data::Ptr{Cvoid}
    data_size::Csize_t
    return_size::Csize_t
end

struct _TLS13RSAPSSParams
    pad_mode::Vector{UInt8}
    mgf1_digest::Vector{UInt8}
    saltlen::Vector{UInt8}
    params::Vector{_OpenSSLParam}
end

# OpenSSL-backed primitive crypto helpers.
#
# This file is intentionally the backend boundary: EVP/X25519/P-256/AEAD/signing
# primitives, private-key loading, and a small amount of backend object
# lifecycle. Higher-level TLS, X.509 parsing, hostname checks, and trust policy
# live in Julia-owned code outside this file.

const _EVP_CTRL_AEAD_SET_IVLEN = Cint(0x9)
const _EVP_CTRL_AEAD_GET_TAG = Cint(0x10)
const _EVP_CTRL_AEAD_SET_TAG = Cint(0x11)

@inline function _tls13_signature_verify_spec(signature_algorithm::UInt16)::_TLSSignatureVerifySpec
    signature_algorithm == _TLS_SIGNATURE_ECDSA_SECP256R1_SHA256 && return _TLSSignatureVerifySpec(256, false, false)
    signature_algorithm == _TLS_SIGNATURE_ECDSA_SECP384R1_SHA384 && return _TLSSignatureVerifySpec(384, false, false)
    signature_algorithm == _TLS_SIGNATURE_ECDSA_SECP521R1_SHA512 && return _TLSSignatureVerifySpec(512, false, false)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_RSAE_SHA256 && return _TLSSignatureVerifySpec(256, false, true)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_RSAE_SHA384 && return _TLSSignatureVerifySpec(384, false, true)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_RSAE_SHA512 && return _TLSSignatureVerifySpec(512, false, true)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_PSS_SHA256 && return _TLSSignatureVerifySpec(256, false, true)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_PSS_SHA384 && return _TLSSignatureVerifySpec(384, false, true)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_PSS_SHA512 && return _TLSSignatureVerifySpec(512, false, true)
    signature_algorithm == _TLS_SIGNATURE_ED25519 && return _TLSSignatureVerifySpec(0, true, false)
    throw(ArgumentError("unsupported TLS 1.3 signature algorithm: $(string(signature_algorithm, base = 16))"))
end

@inline function _tls12_signature_verify_spec(signature_algorithm::UInt16)::_TLSSignatureVerifySpec
    signature_algorithm == _TLS_SIGNATURE_ECDSA_SECP256R1_SHA256 && return _TLSSignatureVerifySpec(256, false, false)
    signature_algorithm == _TLS_SIGNATURE_ECDSA_SECP384R1_SHA384 && return _TLSSignatureVerifySpec(384, false, false)
    signature_algorithm == _TLS_SIGNATURE_ECDSA_SECP521R1_SHA512 && return _TLSSignatureVerifySpec(512, false, false)
    signature_algorithm == _TLS_SIGNATURE_RSA_PKCS1_SHA256 && return _TLSSignatureVerifySpec(256, false, false)
    signature_algorithm == _TLS_SIGNATURE_RSA_PKCS1_SHA384 && return _TLSSignatureVerifySpec(384, false, false)
    signature_algorithm == _TLS_SIGNATURE_RSA_PKCS1_SHA512 && return _TLSSignatureVerifySpec(512, false, false)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_RSAE_SHA256 && return _TLSSignatureVerifySpec(256, false, true)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_RSAE_SHA384 && return _TLSSignatureVerifySpec(384, false, true)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_RSAE_SHA512 && return _TLSSignatureVerifySpec(512, false, true)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_PSS_SHA256 && return _TLSSignatureVerifySpec(256, false, true)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_PSS_SHA384 && return _TLSSignatureVerifySpec(384, false, true)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_PSS_SHA512 && return _TLSSignatureVerifySpec(512, false, true)
    signature_algorithm == _TLS_SIGNATURE_ED25519 && return _TLSSignatureVerifySpec(0, true, false)
    throw(ArgumentError("unsupported TLS 1.2 signature algorithm: $(string(signature_algorithm, base = 16))"))
end

@inline function _tls_signature_md_name(spec::_TLSSignatureVerifySpec)::Union{Nothing, String}
    spec.direct && return nothing
    spec.digest_bits == 160 && return "SHA1"
    spec.digest_bits == 224 && return "SHA224"
    spec.digest_bits == 256 && return "SHA256"
    spec.digest_bits == 384 && return "SHA384"
    spec.digest_bits == 512 && return "SHA512"
    throw(ArgumentError("unsupported signature digest size: $(spec.digest_bits)"))
end

@inline function _tls_ec_curve_group_nid(curve_id::UInt16)::Cint
    curve_id == _TLS_GROUP_SECP256R1 && return _init_p256_group_nid!()
    curve_id == UInt16(0x0018) && return _init_p384_group_nid!()
    curve_id == UInt16(0x0019) && return _init_p521_group_nid!()
    throw(ArgumentError("unsupported TLS EC curve: $(string(curve_id, base = 16))"))
end

function _openssl_bn_from_bytes(bytes::AbstractVector{UInt8}, op::AbstractString)::Ptr{Cvoid}
    bytes_v = bytes isa Vector{UInt8} ? bytes : Vector{UInt8}(bytes)
    bn = GC.@preserve bytes_v ccall(
        (:BN_bin2bn, _LIBCRYPTO_PATH),
        Ptr{Cvoid},
        (Ptr{UInt8}, Cint, Ptr{Cvoid}),
        pointer(bytes_v),
        Cint(length(bytes_v)),
        C_NULL,
    )
    return _openssl_require_nonnull(bn, op)
end

function _tls_public_key_to_evp_pkey(key::_TLSRSAPublicKey)::Ptr{Cvoid}
    modulus = Ptr{Cvoid}(C_NULL)
    exponent = Ptr{Cvoid}(C_NULL)
    rsa = Ptr{Cvoid}(C_NULL)
    pkey = Ptr{Cvoid}(C_NULL)
    out = Ptr{Cvoid}(C_NULL)
    try
        modulus = _openssl_bn_from_bytes(key.modulus, "BN_bin2bn(RSA modulus)")
        exponent = _openssl_bn_from_bytes(key.exponent, "BN_bin2bn(RSA exponent)")
        rsa = ccall((:RSA_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
        _openssl_require_nonnull(rsa, "RSA_new")
        _openssl_require_ok(
            ccall((:RSA_set0_key, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), rsa, modulus, exponent, C_NULL),
            "RSA_set0_key",
        )
        modulus = C_NULL
        exponent = C_NULL
        pkey = ccall((:EVP_PKEY_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
        _openssl_require_nonnull(pkey, "EVP_PKEY_new")
        _openssl_require_ok(
            ccall((:EVP_PKEY_set1_RSA, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), pkey, rsa),
            "EVP_PKEY_set1_RSA",
        )
        out = pkey
        pkey = C_NULL
        return out
    finally
        _free_bn!(modulus)
        _free_bn!(exponent)
        _free_evp_pkey!(pkey)
        _free_rsa!(rsa)
    end
end

function _tls_public_key_to_evp_pkey(key::_TLSECPublicKey)::Ptr{Cvoid}
    ec_key = Ptr{Cvoid}(C_NULL)
    point = Ptr{Cvoid}(C_NULL)
    pkey = Ptr{Cvoid}(C_NULL)
    point_bytes = key.point
    out = Ptr{Cvoid}(C_NULL)
    try
        ec_key = ccall((:EC_KEY_new_by_curve_name, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Cint,), _tls_ec_curve_group_nid(key.curve_id))
        _openssl_require_nonnull(ec_key, "EC_KEY_new_by_curve_name")
        group = ccall((:EC_KEY_get0_group, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), ec_key)
        _openssl_require_nonnull(group, "EC_KEY_get0_group")
        point = ccall((:EC_POINT_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), group)
        _openssl_require_nonnull(point, "EC_POINT_new")
        point_ok = GC.@preserve point_bytes ccall(
                (:EC_POINT_oct2point, _LIBCRYPTO_PATH),
                Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{Cvoid}),
                group,
                point,
                pointer(point_bytes),
                Csize_t(length(point_bytes)),
                C_NULL,
        )
        _openssl_require_ok(point_ok, "EC_POINT_oct2point")
        _openssl_require_ok(
            ccall((:EC_KEY_set_public_key, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), ec_key, point),
            "EC_KEY_set_public_key",
        )
        pkey = ccall((:EVP_PKEY_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
        _openssl_require_nonnull(pkey, "EVP_PKEY_new")
        _openssl_require_ok(
            ccall((:EVP_PKEY_set1_EC_KEY, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), pkey, ec_key),
            "EVP_PKEY_set1_EC_KEY",
        )
        out = pkey
        pkey = C_NULL
        return out
    finally
        _free_evp_pkey!(pkey)
        _free_ec_point!(point)
        _free_ec_key!(ec_key)
    end
end

function _tls_public_key_to_evp_pkey(key::_TLSEd25519PublicKey)::Ptr{Cvoid}
    key_bytes = key.key
    pkey = GC.@preserve key_bytes ccall(
        (:EVP_PKEY_new_raw_public_key, _LIBCRYPTO_PATH),
        Ptr{Cvoid},
        (Cint, Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
        _init_ed25519_pkey_id!(),
        C_NULL,
        pointer(key_bytes),
        Csize_t(length(key_bytes)),
    )
    return _openssl_require_nonnull(pkey, "EVP_PKEY_new_raw_public_key(Ed25519)")
end

# EVP_PKEY verification for RSA-PSS needs a small parameter block whose backing
# storage must stay alive across the `OSSL_PARAM` call. This wrapper owns that
# storage so higher-level call sites do not have to juggle separate buffers.
function _tls13_rsa_pss_params(md_name::String)::_TLS13RSAPSSParams
    pad_mode = UInt8[b"pss"..., 0x00]
    mgf1_digest = Vector{UInt8}(codeunits(md_name))
    push!(mgf1_digest, 0x00)
    saltlen = UInt8[b"digest"..., 0x00]
    params = Vector{_OpenSSLParam}(undef, 4)
    GC.@preserve pad_mode mgf1_digest saltlen begin
        params[1] = ccall(
            (:OSSL_PARAM_construct_utf8_string, _LIBCRYPTO_PATH),
            _OpenSSLParam,
            (Cstring, Ptr{UInt8}, Csize_t),
            "pad-mode",
            pointer(pad_mode),
            Csize_t(length(pad_mode) - 1),
        )
        params[2] = ccall(
            (:OSSL_PARAM_construct_utf8_string, _LIBCRYPTO_PATH),
            _OpenSSLParam,
            (Cstring, Ptr{UInt8}, Csize_t),
            "mgf1-digest",
            pointer(mgf1_digest),
            Csize_t(length(mgf1_digest) - 1),
        )
        params[3] = ccall(
            (:OSSL_PARAM_construct_utf8_string, _LIBCRYPTO_PATH),
            _OpenSSLParam,
            (Cstring, Ptr{UInt8}, Csize_t),
            "saltlen",
            pointer(saltlen),
            Csize_t(length(saltlen) - 1),
        )
    end
    params[4] = ccall((:OSSL_PARAM_construct_end, _LIBCRYPTO_PATH), _OpenSSLParam, ())
    return _TLS13RSAPSSParams(pad_mode, mgf1_digest, saltlen, params)
end

function _tls13_load_private_key_pem(key_pem::AbstractVector{UInt8})::Ptr{Cvoid}
    key_bytes = Vector{UInt8}(key_pem)
    bio = Ptr{Cvoid}(C_NULL)
    try
        return GC.@preserve key_bytes begin
            bio = ccall(
                (:BIO_new_mem_buf, _LIBCRYPTO_PATH),
                Ptr{Cvoid},
                (Ptr{UInt8}, Cint),
                pointer(key_bytes),
                Cint(length(key_bytes)),
            )
            _openssl_require_nonnull(bio, "BIO_new_mem_buf")
            pkey = ccall(
                (:PEM_read_bio_PrivateKey, _LIBCRYPTO_PATH),
                Ptr{Cvoid},
                (Ptr{Cvoid}, Ptr{Ptr{Cvoid}}, Ptr{Cvoid}, Ptr{Cvoid}),
                bio,
                C_NULL,
                C_NULL,
                C_NULL,
            )
            return _openssl_require_nonnull(pkey, "PEM_read_bio_PrivateKey")
        end
    finally
        _free_bio!(bio)
        _securezero!(key_bytes)
    end
end

function _tls13_pkey_type_name(pkey::Ptr{Cvoid})::String
    name = ccall((:EVP_PKEY_get0_type_name, _LIBCRYPTO_PATH), Cstring, (Ptr{Cvoid},), pkey)
    name == C_NULL && throw(ArgumentError("tls: OpenSSL private key has no type name"))
    return unsafe_string(name)
end

function _tls13_ec_group_curve_nid(pkey::Ptr{Cvoid})::Cint
    ec_key = Ptr{Cvoid}(C_NULL)
    try
        ec_key = ccall((:EVP_PKEY_get1_EC_KEY, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), pkey)
        _openssl_require_nonnull(ec_key, "EVP_PKEY_get1_EC_KEY")
        group = ccall((:EC_KEY_get0_group, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), ec_key)
        _openssl_require_nonnull(group, "EC_KEY_get0_group")
        nid = ccall((:EC_GROUP_get_curve_name, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid},), group)
        nid > 0 || throw(ArgumentError("tls: OpenSSL EC key has no named curve"))
        return nid
    finally
        _free_ec_key!(ec_key)
    end
end

function _tls13_x25519_private_key_from_bytes(private_key::AbstractVector{UInt8})::Ptr{Cvoid}
    length(private_key) == 32 || throw(ArgumentError("tls13 x25519 private key must be 32 bytes"))
    private_bytes = Vector{UInt8}(private_key)
    try
        pkey = GC.@preserve private_bytes ccall(
            (:EVP_PKEY_new_raw_private_key, _LIBCRYPTO_PATH),
            Ptr{Cvoid},
            (Cint, Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
            _init_x25519_pkey_id!(),
            C_NULL,
            pointer(private_bytes),
            Csize_t(length(private_bytes)),
        )
        return _openssl_require_nonnull(pkey, "EVP_PKEY_new_raw_private_key(X25519)")
    finally
        _securezero!(private_bytes)
    end
end

function _tls13_x25519_generate_private_key()::Ptr{Cvoid}
    ctx = ccall((:EVP_PKEY_CTX_new_id, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Cint, Ptr{Cvoid}), _init_x25519_pkey_id!(), C_NULL)
    _openssl_require_nonnull(ctx, "EVP_PKEY_CTX_new_id(X25519)")
    try
        ok = ccall((:EVP_PKEY_keygen_init, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid},), ctx)
        _openssl_require_ok(ok, "EVP_PKEY_keygen_init(X25519)")
        pkey_ref = Ref{Ptr{Cvoid}}(C_NULL)
        ok = ccall((:EVP_PKEY_keygen, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ref{Ptr{Cvoid}}), ctx, pkey_ref)
        _openssl_require_ok(ok, "EVP_PKEY_keygen(X25519)")
        return _openssl_require_nonnull(pkey_ref[], "EVP_PKEY_keygen(X25519)")
    finally
        _free_evp_pkey_ctx!(ctx)
    end
end

function _tls13_x25519_public_key(pkey::Ptr{Cvoid})::Vector{UInt8}
    out_len = Ref{Csize_t}(0)
    ok = ccall(
        (:EVP_PKEY_get_raw_public_key, _LIBCRYPTO_PATH),
        Cint,
        (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}),
        pkey,
        Ptr{UInt8}(C_NULL),
        out_len,
    )
    _openssl_require_ok(ok, "EVP_PKEY_get_raw_public_key")
    out = Vector{UInt8}(undef, Int(out_len[]))
    GC.@preserve out begin
        ok = ccall(
            (:EVP_PKEY_get_raw_public_key, _LIBCRYPTO_PATH),
            Cint,
            (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}),
            pkey,
            pointer(out),
            out_len,
        )
        _openssl_require_ok(ok, "EVP_PKEY_get_raw_public_key")
    end
    resize!(out, Int(out_len[]))
    return out
end

function _tls13_x25519_peer_public_key(peer_public_key::AbstractVector{UInt8})::Ptr{Cvoid}
    length(peer_public_key) == 32 || throw(ArgumentError("tls13 x25519 public key must be 32 bytes"))
    peer_bytes = Vector{UInt8}(peer_public_key)
    peer_pkey = GC.@preserve peer_bytes ccall(
        (:EVP_PKEY_new_raw_public_key, _LIBCRYPTO_PATH),
        Ptr{Cvoid},
        (Cint, Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
        _init_x25519_pkey_id!(),
        C_NULL,
        pointer(peer_bytes),
        Csize_t(length(peer_bytes)),
    )
    return _openssl_require_nonnull(peer_pkey, "EVP_PKEY_new_raw_public_key(X25519)")
end

function _tls13_x25519_shared_secret(private_key::Ptr{Cvoid}, peer_public_key::AbstractVector{UInt8})::Vector{UInt8}
    peer_pkey = _tls13_x25519_peer_public_key(peer_public_key)
    ctx = Ptr{Cvoid}(C_NULL)
    try
        ctx = ccall((:EVP_PKEY_CTX_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Ptr{Cvoid}, Ptr{Cvoid}), private_key, C_NULL)
        _openssl_require_nonnull(ctx, "EVP_PKEY_CTX_new")
        ok = ccall((:EVP_PKEY_derive_init, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid},), ctx)
        _openssl_require_ok(ok, "EVP_PKEY_derive_init")
        ok = ccall((:EVP_PKEY_derive_set_peer, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), ctx, peer_pkey)
        _openssl_require_ok(ok, "EVP_PKEY_derive_set_peer")
        out_len = Ref{Csize_t}(0)
        ok = ccall((:EVP_PKEY_derive, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}), ctx, Ptr{UInt8}(C_NULL), out_len)
        _openssl_require_ok(ok, "EVP_PKEY_derive")
        out = Vector{UInt8}(undef, Int(out_len[]))
        GC.@preserve out begin
            ok = ccall((:EVP_PKEY_derive, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}), ctx, pointer(out), out_len)
            _openssl_require_ok(ok, "EVP_PKEY_derive")
        end
        resize!(out, Int(out_len[]))
        all_zero = UInt8(0)
        @inbounds for byte in out
            all_zero |= byte
        end
        if iszero(all_zero)
            _securezero!(out)
            _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: invalid X25519 shared secret")
        end
        return out
    finally
        _free_evp_pkey_ctx!(ctx)
        _free_evp_pkey!(peer_pkey)
    end
end

function _tls13_openssl_x25519_server_share_and_secret(client_share::AbstractVector{UInt8}, server_private_key::AbstractVector{UInt8})::_TLSKeyShareSecret
    pkey = _tls13_x25519_private_key_from_bytes(server_private_key)
    try
        share_data = _tls13_x25519_public_key(pkey)
        secret = _tls13_x25519_shared_secret(pkey, client_share)
        return _TLSKeyShareSecret(_TLS_GROUP_X25519, share_data, secret)
    finally
        _free_evp_pkey!(pkey)
    end
end

function _tls13_p256_private_key_from_bytes(private_key::AbstractVector{UInt8})::Ptr{Cvoid}
    length(private_key) == 32 || throw(ArgumentError("tls13 P-256 private key must be 32 bytes"))
    private_bytes = Vector{UInt8}(private_key)
    ec_key = Ptr{Cvoid}(C_NULL)
    private_bn = Ptr{Cvoid}(C_NULL)
    point = Ptr{Cvoid}(C_NULL)
    bn_ctx = Ptr{Cvoid}(C_NULL)
    pkey = Ptr{Cvoid}(C_NULL)
    try
        ec_key = ccall((:EC_KEY_new_by_curve_name, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Cint,), _init_p256_group_nid!())
        _openssl_require_nonnull(ec_key, "EC_KEY_new_by_curve_name(P-256)")
        private_bn = GC.@preserve private_bytes ccall(
            (:BN_bin2bn, _LIBCRYPTO_PATH),
            Ptr{Cvoid},
            (Ptr{UInt8}, Cint, Ptr{Cvoid}),
            pointer(private_bytes),
            Cint(length(private_bytes)),
            C_NULL,
        )
        _openssl_require_nonnull(private_bn, "BN_bin2bn")
        _openssl_require_ok(ccall((:EC_KEY_set_private_key, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), ec_key, private_bn), "EC_KEY_set_private_key(P-256)")
        group = ccall((:EC_KEY_get0_group, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), ec_key)
        _openssl_require_nonnull(group, "EC_KEY_get0_group(P-256)")
        point = ccall((:EC_POINT_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), group)
        _openssl_require_nonnull(point, "EC_POINT_new(P-256)")
        bn_ctx = ccall((:BN_CTX_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
        _openssl_require_nonnull(bn_ctx, "BN_CTX_new")
        _openssl_require_ok(ccall((:EC_POINT_mul, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), group, point, private_bn, C_NULL, C_NULL, bn_ctx), "EC_POINT_mul(P-256)")
        _openssl_require_ok(ccall((:EC_KEY_set_public_key, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), ec_key, point), "EC_KEY_set_public_key(P-256)")
        pkey = ccall((:EVP_PKEY_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
        _openssl_require_nonnull(pkey, "EVP_PKEY_new")
        _openssl_require_ok(ccall((:EVP_PKEY_set1_EC_KEY, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), pkey, ec_key), "EVP_PKEY_set1_EC_KEY(P-256)")
        out = pkey
        pkey = C_NULL
        return out
    finally
        _free_evp_pkey!(pkey)
        _free_bn_ctx!(bn_ctx)
        _free_ec_point!(point)
        _free_bn!(private_bn)
        _free_ec_key!(ec_key)
        _securezero!(private_bytes)
    end
end

function _tls13_p256_generate_private_key()::Ptr{Cvoid}
    ec_key = Ptr{Cvoid}(C_NULL)
    pkey = Ptr{Cvoid}(C_NULL)
    try
        ec_key = ccall((:EC_KEY_new_by_curve_name, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Cint,), _init_p256_group_nid!())
        _openssl_require_nonnull(ec_key, "EC_KEY_new_by_curve_name(P-256)")
        _openssl_require_ok(ccall((:EC_KEY_generate_key, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid},), ec_key), "EC_KEY_generate_key(P-256)")
        pkey = ccall((:EVP_PKEY_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
        _openssl_require_nonnull(pkey, "EVP_PKEY_new")
        _openssl_require_ok(ccall((:EVP_PKEY_set1_EC_KEY, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), pkey, ec_key), "EVP_PKEY_set1_EC_KEY(P-256)")
        out = pkey
        pkey = C_NULL
        return out
    finally
        _free_evp_pkey!(pkey)
        _free_ec_key!(ec_key)
    end
end

function _tls13_p256_public_key(pkey::Ptr{Cvoid})::Vector{UInt8}
    ec_key = Ptr{Cvoid}(C_NULL)
    try
        ec_key = ccall((:EVP_PKEY_get1_EC_KEY, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), pkey)
        _openssl_require_nonnull(ec_key, "EVP_PKEY_get1_EC_KEY")
        group = ccall((:EC_KEY_get0_group, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), ec_key)
        _openssl_require_nonnull(group, "EC_KEY_get0_group(P-256)")
        point = ccall((:EC_KEY_get0_public_key, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), ec_key)
        _openssl_require_nonnull(point, "EC_KEY_get0_public_key(P-256)")
        out_len = ccall(
            (:EC_POINT_point2oct, _LIBCRYPTO_PATH),
            Csize_t,
            (Ptr{Cvoid}, Ptr{Cvoid}, Cint, Ptr{UInt8}, Csize_t, Ptr{Cvoid}),
            group,
            point,
            Cint(4),
            Ptr{UInt8}(C_NULL),
            Csize_t(0),
            C_NULL,
        )
        out_len > 0 || throw(_make_tls_error("EC_POINT_point2oct(P-256)", Int32(out_len)))
        out = Vector{UInt8}(undef, Int(out_len))
        GC.@preserve out begin
            wrote = ccall(
                (:EC_POINT_point2oct, _LIBCRYPTO_PATH),
                Csize_t,
                (Ptr{Cvoid}, Ptr{Cvoid}, Cint, Ptr{UInt8}, Csize_t, Ptr{Cvoid}),
                group,
                point,
                Cint(4),
                pointer(out),
                Csize_t(length(out)),
                C_NULL,
            )
            Int(wrote) == length(out) || throw(_make_tls_error("EC_POINT_point2oct(P-256)", Int32(wrote)))
        end
        return out
    finally
        _free_ec_key!(ec_key)
    end
end

function _tls13_p256_peer_public_key(peer_public_key::AbstractVector{UInt8})::Ptr{Cvoid}
    length(peer_public_key) == 65 || throw(ArgumentError("tls13 P-256 public key must be 65 bytes in uncompressed form"))
    peer_public_key[1] == 0x04 || throw(ArgumentError("tls13 P-256 public key must use the uncompressed point format"))
    peer_bytes = Vector{UInt8}(peer_public_key)
    ec_key = Ptr{Cvoid}(C_NULL)
    point = Ptr{Cvoid}(C_NULL)
    pkey = Ptr{Cvoid}(C_NULL)
    try
        ec_key = ccall((:EC_KEY_new_by_curve_name, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Cint,), _init_p256_group_nid!())
        _openssl_require_nonnull(ec_key, "EC_KEY_new_by_curve_name(P-256)")
        group = ccall((:EC_KEY_get0_group, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), ec_key)
        _openssl_require_nonnull(group, "EC_KEY_get0_group(P-256)")
        point = ccall((:EC_POINT_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), group)
        _openssl_require_nonnull(point, "EC_POINT_new(P-256)")
        ok = GC.@preserve peer_bytes ccall(
            (:EC_POINT_oct2point, _LIBCRYPTO_PATH),
            Cint,
            (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{Cvoid}),
            group,
            point,
            pointer(peer_bytes),
            Csize_t(length(peer_bytes)),
            C_NULL,
        )
        _openssl_require_ok(ok, "EC_POINT_oct2point(P-256)")
        _openssl_require_ok(ccall((:EC_KEY_set_public_key, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), ec_key, point), "EC_KEY_set_public_key(P-256)")
        pkey = ccall((:EVP_PKEY_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
        _openssl_require_nonnull(pkey, "EVP_PKEY_new")
        _openssl_require_ok(ccall((:EVP_PKEY_set1_EC_KEY, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), pkey, ec_key), "EVP_PKEY_set1_EC_KEY(P-256)")
        out = pkey
        pkey = C_NULL
        return out
    finally
        _free_evp_pkey!(pkey)
        _free_ec_point!(point)
        _free_ec_key!(ec_key)
    end
end

function _tls13_p256_shared_secret(private_key::Ptr{Cvoid}, peer_public_key::AbstractVector{UInt8})::Vector{UInt8}
    peer_pkey = _tls13_p256_peer_public_key(peer_public_key)
    ctx = Ptr{Cvoid}(C_NULL)
    try
        ctx = ccall((:EVP_PKEY_CTX_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Ptr{Cvoid}, Ptr{Cvoid}), private_key, C_NULL)
        _openssl_require_nonnull(ctx, "EVP_PKEY_CTX_new(P-256)")
        _openssl_require_ok(ccall((:EVP_PKEY_derive_init, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid},), ctx), "EVP_PKEY_derive_init(P-256)")
        _openssl_require_ok(ccall((:EVP_PKEY_derive_set_peer, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), ctx, peer_pkey), "EVP_PKEY_derive_set_peer(P-256)")
        out_len = Ref{Csize_t}(0)
        _openssl_require_ok(ccall((:EVP_PKEY_derive, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}), ctx, Ptr{UInt8}(C_NULL), out_len), "EVP_PKEY_derive(P-256)")
        out = Vector{UInt8}(undef, Int(out_len[]))
        GC.@preserve out begin
            _openssl_require_ok(ccall((:EVP_PKEY_derive, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}), ctx, pointer(out), out_len), "EVP_PKEY_derive(P-256)")
        end
        resize!(out, Int(out_len[]))
        all_zero = UInt8(0)
        @inbounds for byte in out
            all_zero |= byte
        end
        if iszero(all_zero)
            _securezero!(out)
            _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: invalid P-256 shared secret")
        end
        return out
    finally
        _free_evp_pkey_ctx!(ctx)
        _free_evp_pkey!(peer_pkey)
    end
end

function _tls13_openssl_p256_server_share_and_secret(client_share::AbstractVector{UInt8}, server_private_key::AbstractVector{UInt8})::_TLSKeyShareSecret
    pkey = _tls13_p256_private_key_from_bytes(server_private_key)
    try
        share_data = _tls13_p256_public_key(pkey)
        secret = _tls13_p256_shared_secret(pkey, client_share)
        return _TLSKeyShareSecret(_TLS_GROUP_SECP256R1, share_data, secret)
    finally
        _free_evp_pkey!(pkey)
    end
end

function _openssl_verify_signature_with_spec(
    pubkey::Ptr{Cvoid},
    spec::_TLSSignatureVerifySpec,
    signed::AbstractVector{UInt8},
    signature::AbstractVector{UInt8},
)::Bool
    if spec.direct
        signed_bytes = signed isa Vector{UInt8} ? signed : Vector{UInt8}(signed)
        signature_bytes = signature isa Vector{UInt8} ? signature : Vector{UInt8}(signature)
        mdctx = ccall((:EVP_MD_CTX_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
        _openssl_require_nonnull(mdctx, "EVP_MD_CTX_new")
        try
            pctx_ref = Ref{Ptr{Cvoid}}(C_NULL)
            ok = ccall(
                (:EVP_DigestVerifyInit_ex, _LIBCRYPTO_PATH),
                Cint,
                (Ptr{Cvoid}, Ref{Ptr{Cvoid}}, Cstring, Ptr{Cvoid}, Cstring, Ptr{Cvoid}, Ptr{_OpenSSLParam}),
                mdctx,
                pctx_ref,
                C_NULL,
                C_NULL,
                C_NULL,
                pubkey,
                Ptr{_OpenSSLParam}(C_NULL),
            )
            _openssl_require_ok(ok, "EVP_DigestVerifyInit_ex")
            ret = GC.@preserve signed_bytes signature_bytes ccall(
                (:EVP_DigestVerify, _LIBCRYPTO_PATH),
                Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{UInt8}, Csize_t),
                mdctx,
                pointer(signature_bytes),
                Csize_t(length(signature_bytes)),
                pointer(signed_bytes),
                Csize_t(length(signed_bytes)),
            )
            ret == 1 && return true
            ret == 0 && return false
            throw(_make_tls_error("EVP_DigestVerify", Int32(ret)))
        finally
            _free_evp_md_ctx!(mdctx)
        end
    end
    signed_bytes = signed isa Vector{UInt8} ? signed : Vector{UInt8}(signed)
    signature_bytes = signature isa Vector{UInt8} ? signature : Vector{UInt8}(signature)
    mdctx = ccall((:EVP_MD_CTX_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
    _openssl_require_nonnull(mdctx, "EVP_MD_CTX_new")
    try
        pctx_ref = Ref{Ptr{Cvoid}}(C_NULL)
        md_name = _tls_signature_md_name(spec)::String
        if spec.rsa_pss
            pss_params = _tls13_rsa_pss_params(md_name)
            ok = GC.@preserve pss_params ccall(
                (:EVP_DigestVerifyInit_ex, _LIBCRYPTO_PATH),
                Cint,
                (Ptr{Cvoid}, Ref{Ptr{Cvoid}}, Cstring, Ptr{Cvoid}, Cstring, Ptr{Cvoid}, Ptr{_OpenSSLParam}),
                mdctx,
                pctx_ref,
                md_name,
                C_NULL,
                C_NULL,
                pubkey,
                pointer(pss_params.params),
            )
        else
            ok = ccall(
                (:EVP_DigestVerifyInit_ex, _LIBCRYPTO_PATH),
                Cint,
                (Ptr{Cvoid}, Ref{Ptr{Cvoid}}, Cstring, Ptr{Cvoid}, Cstring, Ptr{Cvoid}, Ptr{_OpenSSLParam}),
                mdctx,
                pctx_ref,
                md_name,
                C_NULL,
                C_NULL,
                pubkey,
                Ptr{_OpenSSLParam}(C_NULL),
            )
        end
        _openssl_require_ok(ok, "EVP_DigestVerifyInit_ex")
        ok = GC.@preserve signed_bytes ccall(
            (:EVP_DigestVerifyUpdate, _LIBCRYPTO_PATH),
            Cint,
            (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
            mdctx,
            pointer(signed_bytes),
            Csize_t(length(signed_bytes)),
        )
        _openssl_require_ok(ok, "EVP_DigestVerifyUpdate")
        ret = GC.@preserve signature_bytes ccall(
            (:EVP_DigestVerifyFinal, _LIBCRYPTO_PATH),
            Cint,
            (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
            mdctx,
            pointer(signature_bytes),
            Csize_t(length(signature_bytes)),
        )
        ret == 1 && return true
        ret == 0 && return false
        throw(_make_tls_error("EVP_DigestVerifyFinal", Int32(ret)))
    finally
        _free_evp_md_ctx!(mdctx)
    end
end

function _openssl_verify_signature_with_spec(
    pubkey::_TLSPublicKey,
    spec::_TLSSignatureVerifySpec,
    signed::AbstractVector{UInt8},
    signature::AbstractVector{UInt8},
)::Bool
    pkey = _tls_public_key_to_evp_pkey(pubkey)
    try
        return _openssl_verify_signature_with_spec(pkey, spec, signed, signature)
    finally
        _free_evp_pkey!(pkey)
    end
end

function _tls13_openssl_verify_signature(pubkey::Ptr{Cvoid}, signature_algorithm::UInt16, signed::AbstractVector{UInt8}, signature::AbstractVector{UInt8})::Bool
    return _openssl_verify_signature_with_spec(pubkey, _tls13_signature_verify_spec(signature_algorithm), signed, signature)
end

function _tls13_openssl_verify_signature(pubkey::_TLSPublicKey, signature_algorithm::UInt16, signed::AbstractVector{UInt8}, signature::AbstractVector{UInt8})::Bool
    pkey = _tls_public_key_to_evp_pkey(pubkey)
    try
        return _tls13_openssl_verify_signature(pkey, signature_algorithm, signed, signature)
    finally
        _free_evp_pkey!(pkey)
    end
end

function _tls12_openssl_verify_signature(pubkey::Ptr{Cvoid}, signature_algorithm::UInt16, signed::AbstractVector{UInt8}, signature::AbstractVector{UInt8})::Bool
    return _openssl_verify_signature_with_spec(pubkey, _tls12_signature_verify_spec(signature_algorithm), signed, signature)
end

function _tls12_openssl_verify_signature(pubkey::_TLSPublicKey, signature_algorithm::UInt16, signed::AbstractVector{UInt8}, signature::AbstractVector{UInt8})::Bool
    pkey = _tls_public_key_to_evp_pkey(pubkey)
    try
        return _tls12_openssl_verify_signature(pkey, signature_algorithm, signed, signature)
    finally
        _free_evp_pkey!(pkey)
    end
end

function _openssl_sign_signature_with_spec(
    pkey::Ptr{Cvoid},
    spec::_TLSSignatureVerifySpec,
    signed::AbstractVector{UInt8},
)::Vector{UInt8}
    if spec.direct
        signed_bytes = signed isa Vector{UInt8} ? signed : Vector{UInt8}(signed)
        mdctx = ccall((:EVP_MD_CTX_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
        _openssl_require_nonnull(mdctx, "EVP_MD_CTX_new")
        try
            pctx_ref = Ref{Ptr{Cvoid}}(C_NULL)
            ok = ccall(
                (:EVP_DigestSignInit_ex, _LIBCRYPTO_PATH),
                Cint,
                (Ptr{Cvoid}, Ref{Ptr{Cvoid}}, Cstring, Ptr{Cvoid}, Cstring, Ptr{Cvoid}, Ptr{_OpenSSLParam}),
                mdctx,
                pctx_ref,
                C_NULL,
                C_NULL,
                C_NULL,
                pkey,
                Ptr{_OpenSSLParam}(C_NULL),
            )
            _openssl_require_ok(ok, "EVP_DigestSignInit_ex")
            out_len = Ref{Csize_t}(0)
            ok = GC.@preserve signed_bytes ccall(
                (:EVP_DigestSign, _LIBCRYPTO_PATH),
                Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}, Ptr{UInt8}, Csize_t),
                mdctx,
                Ptr{UInt8}(C_NULL),
                out_len,
                pointer(signed_bytes),
                Csize_t(length(signed_bytes)),
            )
            _openssl_require_ok(ok, "EVP_DigestSign")
            out = Vector{UInt8}(undef, Int(out_len[]))
            GC.@preserve signed_bytes out begin
                ok = ccall(
                    (:EVP_DigestSign, _LIBCRYPTO_PATH),
                    Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}, Ptr{UInt8}, Csize_t),
                    mdctx,
                    pointer(out),
                    out_len,
                    pointer(signed_bytes),
                    Csize_t(length(signed_bytes)),
                )
                _openssl_require_ok(ok, "EVP_DigestSign")
            end
            resize!(out, Int(out_len[]))
            return out
        finally
            _free_evp_md_ctx!(mdctx)
        end
    end
    signed_bytes = signed isa Vector{UInt8} ? signed : Vector{UInt8}(signed)
    mdctx = ccall((:EVP_MD_CTX_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
    _openssl_require_nonnull(mdctx, "EVP_MD_CTX_new")
    try
        pctx_ref = Ref{Ptr{Cvoid}}(C_NULL)
        md_name = _tls_signature_md_name(spec)::String
        if spec.rsa_pss
            pss_params = _tls13_rsa_pss_params(md_name)
            ok = GC.@preserve pss_params ccall(
                (:EVP_DigestSignInit_ex, _LIBCRYPTO_PATH),
                Cint,
                (Ptr{Cvoid}, Ref{Ptr{Cvoid}}, Cstring, Ptr{Cvoid}, Cstring, Ptr{Cvoid}, Ptr{_OpenSSLParam}),
                mdctx,
                pctx_ref,
                md_name,
                C_NULL,
                C_NULL,
                pkey,
                pointer(pss_params.params),
            )
        else
            ok = ccall(
                (:EVP_DigestSignInit_ex, _LIBCRYPTO_PATH),
                Cint,
                (Ptr{Cvoid}, Ref{Ptr{Cvoid}}, Cstring, Ptr{Cvoid}, Cstring, Ptr{Cvoid}, Ptr{_OpenSSLParam}),
                mdctx,
                pctx_ref,
                md_name,
                C_NULL,
                C_NULL,
                pkey,
                Ptr{_OpenSSLParam}(C_NULL),
            )
        end
        _openssl_require_ok(ok, "EVP_DigestSignInit_ex")
        ok = GC.@preserve signed_bytes ccall(
            (:EVP_DigestSignUpdate, _LIBCRYPTO_PATH),
            Cint,
            (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
            mdctx,
            pointer(signed_bytes),
            Csize_t(length(signed_bytes)),
        )
        _openssl_require_ok(ok, "EVP_DigestSignUpdate")
        out_len = Ref{Csize_t}(0)
        ok = ccall((:EVP_DigestSignFinal, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}), mdctx, Ptr{UInt8}(C_NULL), out_len)
        _openssl_require_ok(ok, "EVP_DigestSignFinal")
        out = Vector{UInt8}(undef, Int(out_len[]))
        GC.@preserve out begin
            ok = ccall(
                (:EVP_DigestSignFinal, _LIBCRYPTO_PATH),
                Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Ref{Csize_t}),
                mdctx,
                pointer(out),
                out_len,
            )
            _openssl_require_ok(ok, "EVP_DigestSignFinal")
        end
        resize!(out, Int(out_len[]))
        return out
    finally
        _free_evp_md_ctx!(mdctx)
    end
end

function _tls13_openssl_sign_signature(pkey::Ptr{Cvoid}, signature_algorithm::UInt16, signed::AbstractVector{UInt8})::Vector{UInt8}
    return _openssl_sign_signature_with_spec(pkey, _tls13_signature_verify_spec(signature_algorithm), signed)
end

function _tls12_openssl_sign_signature(pkey::Ptr{Cvoid}, signature_algorithm::UInt16, signed::AbstractVector{UInt8})::Vector{UInt8}
    return _openssl_sign_signature_with_spec(pkey, _tls12_signature_verify_spec(signature_algorithm), signed)
end

function _tls13_openssl_sign_from_pem(signature_algorithm::UInt16, signed::AbstractVector{UInt8}, key_pem::AbstractVector{UInt8})::Vector{UInt8}
    pkey = _tls13_load_private_key_pem(key_pem)
    try
        return _tls13_openssl_sign_signature(pkey, signature_algorithm, signed)
    finally
        _free_evp_pkey!(pkey)
    end
end

function _tls12_openssl_sign_from_pem(signature_algorithm::UInt16, signed::AbstractVector{UInt8}, key_pem::AbstractVector{UInt8})::Vector{UInt8}
    pkey = _tls13_load_private_key_pem(key_pem)
    try
        return _tls12_openssl_sign_signature(pkey, signature_algorithm, signed)
    finally
        _free_evp_pkey!(pkey)
    end
end

@inline function _tls12_record_cipher(spec::_TLS12CipherSpec)::Ptr{Cvoid}
    spec == _TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256 &&
        return ccall((:EVP_aes_128_gcm, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
    spec == _TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384 &&
        return ccall((:EVP_aes_256_gcm, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
    throw(ArgumentError("tls12 native record layer only supports AES-GCM cipher suites"))
end

function _openssl_prepare_encrypt_record_ctx!(
    aead::_OpenSSLAEADState,
    key_bytes::Vector{UInt8},
    iv_bytes::Vector{UInt8},
)::Nothing
    length(iv_bytes) == aead.iv_len || throw(ArgumentError("unexpected AEAD IV length"))
    ctx = aead.ctx
    _reset_evp_cipher_ctx!(ctx)
    ok = ccall((:EVP_EncryptInit_ex, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}), ctx, aead.cipher, C_NULL, Ptr{UInt8}(C_NULL), Ptr{UInt8}(C_NULL))
    _openssl_require_ok(ok, "EVP_EncryptInit_ex")
    ok = ccall((:EVP_CIPHER_CTX_ctrl, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Cint, Cint, Ptr{Cvoid}), ctx, _EVP_CTRL_AEAD_SET_IVLEN, Cint(aead.iv_len), C_NULL)
    _openssl_require_ok(ok, "EVP_CIPHER_CTX_ctrl(SET_IVLEN)")
    GC.@preserve key_bytes iv_bytes begin
        ok = ccall((:EVP_EncryptInit_ex, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}), ctx, C_NULL, C_NULL, pointer(key_bytes), pointer(iv_bytes))
        _openssl_require_ok(ok, "EVP_EncryptInit_ex(key/iv)")
    end
    return nothing
end

function _openssl_prepare_decrypt_record_ctx!(
    aead::_OpenSSLAEADState,
    key_bytes::Vector{UInt8},
    iv_bytes::Vector{UInt8},
)::Nothing
    length(iv_bytes) == aead.iv_len || throw(ArgumentError("unexpected AEAD IV length"))
    ctx = aead.ctx
    _reset_evp_cipher_ctx!(ctx)
    ok = ccall((:EVP_DecryptInit_ex, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}), ctx, aead.cipher, C_NULL, Ptr{UInt8}(C_NULL), Ptr{UInt8}(C_NULL))
    _openssl_require_ok(ok, "EVP_DecryptInit_ex")
    ok = ccall((:EVP_CIPHER_CTX_ctrl, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Cint, Cint, Ptr{Cvoid}), ctx, _EVP_CTRL_AEAD_SET_IVLEN, Cint(aead.iv_len), C_NULL)
    _openssl_require_ok(ok, "EVP_CIPHER_CTX_ctrl(SET_IVLEN)")
    GC.@preserve key_bytes iv_bytes begin
        ok = ccall((:EVP_DecryptInit_ex, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}), ctx, C_NULL, C_NULL, pointer(key_bytes), pointer(iv_bytes))
        _openssl_require_ok(ok, "EVP_DecryptInit_ex(key/iv)")
    end
    return nothing
end

function _openssl_encrypt_record_aead!(
    aead::_OpenSSLAEADState,
    out::Vector{UInt8},
    io_pos::Int,
    plaintext_len::Int,
    key_bytes::Vector{UInt8},
    iv_bytes::Vector{UInt8},
    aad_ptr::Ptr{UInt8},
    aad_len::Int,
)::Int
    _openssl_prepare_encrypt_record_ctx!(aead, key_bytes, iv_bytes)
    ctx = aead.ctx
    out_len = Ref{Cint}(0)
    total = 0
    if aad_len != 0
        ok = ccall((:EVP_EncryptUpdate, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, Cint), ctx, Ptr{UInt8}(C_NULL), out_len, aad_ptr, Cint(aad_len))
        _openssl_require_ok(ok, "EVP_EncryptUpdate(aad)")
    end
    GC.@preserve out begin
        if plaintext_len != 0
            io_ptr = pointer(out, io_pos)
            ok = ccall((:EVP_EncryptUpdate, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, Cint), ctx, io_ptr, out_len, io_ptr, Cint(plaintext_len))
            _openssl_require_ok(ok, "EVP_EncryptUpdate")
            total += Int(out_len[])
        end
        ok = ccall((:EVP_EncryptFinal_ex, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}), ctx, pointer(out, io_pos + total), out_len)
        _openssl_require_ok(ok, "EVP_EncryptFinal_ex")
        total += Int(out_len[])
        ok = ccall((:EVP_CIPHER_CTX_ctrl, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Cint, Cint, Ptr{Cvoid}), ctx, _EVP_CTRL_AEAD_GET_TAG, Cint(16), pointer(out, io_pos + total))
        _openssl_require_ok(ok, "EVP_CIPHER_CTX_ctrl(GET_TAG)")
    end
    return total + 16
end

function _openssl_decrypt_record_aead!(
    aead::_OpenSSLAEADState,
    io::Vector{UInt8},
    io_pos::Int,
    ciphertext_len::Int,
    tag_pos::Int,
    key_bytes::Vector{UInt8},
    iv_bytes::Vector{UInt8},
    aad_ptr::Ptr{UInt8},
    aad_len::Int,
)::Union{Int, Nothing}
    _openssl_prepare_decrypt_record_ctx!(aead, key_bytes, iv_bytes)
    ctx = aead.ctx
    out_len = Ref{Cint}(0)
    total = 0
    if aad_len != 0
        ok = ccall((:EVP_DecryptUpdate, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, Cint), ctx, Ptr{UInt8}(C_NULL), out_len, aad_ptr, Cint(aad_len))
        _openssl_require_ok(ok, "EVP_DecryptUpdate(aad)")
    end
    GC.@preserve io begin
        if ciphertext_len != 0
            io_ptr = pointer(io, io_pos)
            ok = ccall((:EVP_DecryptUpdate, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, Cint), ctx, io_ptr, out_len, io_ptr, Cint(ciphertext_len))
            _openssl_require_ok(ok, "EVP_DecryptUpdate")
            total += Int(out_len[])
        end
        ok = ccall((:EVP_CIPHER_CTX_ctrl, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Cint, Cint, Ptr{Cvoid}), ctx, _EVP_CTRL_AEAD_SET_TAG, Cint(16), pointer(io, tag_pos))
        _openssl_require_ok(ok, "EVP_CIPHER_CTX_ctrl(SET_TAG)")
        final_ok = ccall((:EVP_DecryptFinal_ex, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}), ctx, pointer(io, io_pos + total), out_len)
        final_ok == 1 || return nothing
        total += Int(out_len[])
    end
    return total
end

function _tls12_encrypt_record_aead!(
    aead::_OpenSSLAEADState,
    out::Vector{UInt8},
    io_pos::Int,
    plaintext_len::Int,
    key::Vector{UInt8},
    iv::Vector{UInt8},
    aad_ptr::Ptr{UInt8},
    aad_len::Int,
)::Int
    return _openssl_encrypt_record_aead!(
        aead,
        out,
        io_pos,
        plaintext_len,
        key,
        iv,
        aad_ptr,
        aad_len,
    )
end

function _tls12_encrypt_record_aead(
    spec::_TLS12CipherSpec,
    key::AbstractVector{UInt8},
    iv::AbstractVector{UInt8},
    additional_data::AbstractVector{UInt8},
    plaintext::AbstractVector{UInt8},
)::Vector{UInt8}
    key_bytes = key isa Vector{UInt8} ? key : Vector{UInt8}(key)
    iv_bytes = iv isa Vector{UInt8} ? iv : Vector{UInt8}(iv)
    aad_bytes = additional_data isa Vector{UInt8} ? additional_data : Vector{UInt8}(additional_data)
    plaintext_bytes = plaintext isa Vector{UInt8} ? plaintext : Vector{UInt8}(plaintext)
    ciphertext = Vector{UInt8}(plaintext_bytes)
    resize!(ciphertext, length(plaintext_bytes) + 16)
    aead = _OpenSSLAEADState(_tls12_record_cipher(spec), length(iv_bytes))
    ciphertext_len = try
        GC.@preserve ciphertext aad_bytes _tls12_encrypt_record_aead!(
            aead,
            ciphertext,
            1,
            length(plaintext_bytes),
            key_bytes,
            iv_bytes,
            isempty(aad_bytes) ? Ptr{UInt8}(C_NULL) : pointer(aad_bytes),
            length(aad_bytes),
        )
    finally
        _free_openssl_aead_state!(aead)
    end
    resize!(ciphertext, ciphertext_len)
    return ciphertext
end

function _tls12_decrypt_record_aead!(
    aead::_OpenSSLAEADState,
    io::Vector{UInt8},
    io_pos::Int,
    ciphertext_len::Int,
    tag_pos::Int,
    key::Vector{UInt8},
    iv::Vector{UInt8},
    aad_ptr::Ptr{UInt8},
    aad_len::Int,
)::Union{Int, Nothing}
    return _openssl_decrypt_record_aead!(
        aead,
        io,
        io_pos,
        ciphertext_len,
        tag_pos,
        key,
        iv,
        aad_ptr,
        aad_len,
    )
end

function _tls12_decrypt_record_aead(
    spec::_TLS12CipherSpec,
    key::AbstractVector{UInt8},
    iv::AbstractVector{UInt8},
    additional_data::AbstractVector{UInt8},
    ciphertext_and_tag::AbstractVector{UInt8},
)::Union{Vector{UInt8}, Nothing}
    length(ciphertext_and_tag) >= 16 || _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: TLS 1.2 ciphertext is missing the authentication tag")
    key_bytes = key isa Vector{UInt8} ? key : Vector{UInt8}(key)
    iv_bytes = iv isa Vector{UInt8} ? iv : Vector{UInt8}(iv)
    aad_bytes = additional_data isa Vector{UInt8} ? additional_data : Vector{UInt8}(additional_data)
    ciphertext = Vector{UInt8}(ciphertext_and_tag)
    ciphertext_len = length(ciphertext) - 16
    aead = _OpenSSLAEADState(_tls12_record_cipher(spec), length(iv_bytes))
    try
        plaintext_len = GC.@preserve ciphertext aad_bytes _tls12_decrypt_record_aead!(
            aead,
            ciphertext,
            1,
            ciphertext_len,
            ciphertext_len + 1,
            key_bytes,
            iv_bytes,
            isempty(aad_bytes) ? Ptr{UInt8}(C_NULL) : pointer(aad_bytes),
            length(aad_bytes),
        )
        if plaintext_len === nothing
            _securezero!(ciphertext)
            return nothing
        end
        resize!(ciphertext, plaintext_len::Int)
        return ciphertext
    finally
        _free_openssl_aead_state!(aead)
    end
end

@inline function _tls13_record_cipher(spec::_TLS13CipherSpec)::Ptr{Cvoid}
    spec == _TLS13_AES_128_GCM_SHA256 && return ccall((:EVP_aes_128_gcm, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
    spec == _TLS13_AES_256_GCM_SHA384 && return ccall((:EVP_aes_256_gcm, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
    spec == _TLS13_CHACHA20_POLY1305_SHA256 && return ccall((:EVP_chacha20_poly1305, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
    throw(ArgumentError("tls13 native record layer only supports AES-GCM and ChaCha20-Poly1305 cipher suites"))
end

function _tls13_encrypt_record_aead!(
    aead::_OpenSSLAEADState,
    out::Vector{UInt8},
    io_pos::Int,
    plaintext_len::Int,
    key::Vector{UInt8},
    iv::Vector{UInt8},
    aad_ptr::Ptr{UInt8},
    aad_len::Int,
)::Int
    return _openssl_encrypt_record_aead!(
        aead,
        out,
        io_pos,
        plaintext_len,
        key,
        iv,
        aad_ptr,
        aad_len,
    )
end

function _tls13_encrypt_record_aead(
    spec::_TLS13CipherSpec,
    key::AbstractVector{UInt8},
    iv::AbstractVector{UInt8},
    additional_data::AbstractVector{UInt8},
    plaintext::AbstractVector{UInt8},
)::Vector{UInt8}
    key_bytes = key isa Vector{UInt8} ? key : Vector{UInt8}(key)
    iv_bytes = iv isa Vector{UInt8} ? iv : Vector{UInt8}(iv)
    aad_bytes = additional_data isa Vector{UInt8} ? additional_data : Vector{UInt8}(additional_data)
    plaintext_bytes = plaintext isa Vector{UInt8} ? plaintext : Vector{UInt8}(plaintext)
    ciphertext = Vector{UInt8}(plaintext_bytes)
    resize!(ciphertext, length(plaintext_bytes) + 16)
    aead = _OpenSSLAEADState(_tls13_record_cipher(spec), length(iv_bytes))
    ciphertext_len = try
        GC.@preserve ciphertext aad_bytes _tls13_encrypt_record_aead!(
            aead,
            ciphertext,
            1,
            length(plaintext_bytes),
            key_bytes,
            iv_bytes,
            isempty(aad_bytes) ? Ptr{UInt8}(C_NULL) : pointer(aad_bytes),
            length(aad_bytes),
        )
    finally
        _free_openssl_aead_state!(aead)
    end
    resize!(ciphertext, ciphertext_len)
    return ciphertext
end

function _tls13_decrypt_record_aead!(
    aead::_OpenSSLAEADState,
    io::Vector{UInt8},
    io_pos::Int,
    ciphertext_len::Int,
    tag_pos::Int,
    key::Vector{UInt8},
    iv::Vector{UInt8},
    aad_ptr::Ptr{UInt8},
    aad_len::Int,
)::Union{Int, Nothing}
    return _openssl_decrypt_record_aead!(
        aead,
        io,
        io_pos,
        ciphertext_len,
        tag_pos,
        key,
        iv,
        aad_ptr,
        aad_len,
    )
end

function _tls13_decrypt_record_aead(
    spec::_TLS13CipherSpec,
    key::AbstractVector{UInt8},
    iv::AbstractVector{UInt8},
    additional_data::AbstractVector{UInt8},
    ciphertext_and_tag::AbstractVector{UInt8},
)::Union{Vector{UInt8}, Nothing}
    length(ciphertext_and_tag) >= 16 || _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: TLS 1.3 ciphertext is missing the authentication tag")
    key_bytes = key isa Vector{UInt8} ? key : Vector{UInt8}(key)
    iv_bytes = iv isa Vector{UInt8} ? iv : Vector{UInt8}(iv)
    aad_bytes = additional_data isa Vector{UInt8} ? additional_data : Vector{UInt8}(additional_data)
    ciphertext = Vector{UInt8}(ciphertext_and_tag)
    ciphertext_len = length(ciphertext) - 16
    aead = _OpenSSLAEADState(_tls13_record_cipher(spec), length(iv_bytes))
    try
        plaintext_len = GC.@preserve ciphertext aad_bytes _tls13_decrypt_record_aead!(
            aead,
            ciphertext,
            1,
            ciphertext_len,
            ciphertext_len + 1,
            key_bytes,
            iv_bytes,
            isempty(aad_bytes) ? Ptr{UInt8}(C_NULL) : pointer(aad_bytes),
            length(aad_bytes),
        )
        if plaintext_len === nothing
            _securezero!(ciphertext)
            return nothing
        end
        resize!(ciphertext, plaintext_len::Int)
        return ciphertext
    finally
        _free_openssl_aead_state!(aead)
    end
end
