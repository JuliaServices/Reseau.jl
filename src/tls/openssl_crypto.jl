const _TLS_SIGNATURE_ECDSA_SECP256R1_SHA256 = UInt16(0x0403)
const _TLS_SIGNATURE_ECDSA_SECP384R1_SHA384 = UInt16(0x0503)
const _TLS_SIGNATURE_ECDSA_SECP521R1_SHA512 = UInt16(0x0603)
const _TLS_SIGNATURE_RSA_PSS_RSAE_SHA256 = UInt16(0x0804)
const _TLS_SIGNATURE_RSA_PSS_RSAE_SHA384 = UInt16(0x0805)
const _TLS_SIGNATURE_RSA_PSS_RSAE_SHA512 = UInt16(0x0806)
const _TLS_SIGNATURE_ED25519 = UInt16(0x0807)
const _TLS_SIGNATURE_RSA_PSS_PSS_SHA256 = UInt16(0x0809)
const _TLS_SIGNATURE_RSA_PSS_PSS_SHA384 = UInt16(0x080a)
const _TLS_SIGNATURE_RSA_PSS_PSS_SHA512 = UInt16(0x080b)

const _TLS_GROUP_SECP256R1 = UInt16(0x0017)
const _TLS_GROUP_X25519 = UInt16(0x001d)

const _X25519_PKEY_ID = ccall((:OBJ_sn2nid, _LIBCRYPTO_PATH), Cint, (Cstring,), "X25519")

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

@inline function _free_evp_pkey_ctx!(ctx::Ptr{Cvoid})::Nothing
    ctx == C_NULL || ccall((:EVP_PKEY_CTX_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), ctx)
    return nothing
end

@inline function _free_evp_md_ctx!(ctx::Ptr{Cvoid})::Nothing
    ctx == C_NULL || ccall((:EVP_MD_CTX_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), ctx)
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

struct _TLS13SignatureVerifySpec
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

@inline function _tls13_signature_verify_spec(signature_algorithm::UInt16)::_TLS13SignatureVerifySpec
    signature_algorithm == _TLS_SIGNATURE_ECDSA_SECP256R1_SHA256 && return _TLS13SignatureVerifySpec(256, false, false)
    signature_algorithm == _TLS_SIGNATURE_ECDSA_SECP384R1_SHA384 && return _TLS13SignatureVerifySpec(384, false, false)
    signature_algorithm == _TLS_SIGNATURE_ECDSA_SECP521R1_SHA512 && return _TLS13SignatureVerifySpec(512, false, false)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_RSAE_SHA256 && return _TLS13SignatureVerifySpec(256, false, true)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_RSAE_SHA384 && return _TLS13SignatureVerifySpec(384, false, true)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_RSAE_SHA512 && return _TLS13SignatureVerifySpec(512, false, true)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_PSS_SHA256 && return _TLS13SignatureVerifySpec(256, false, true)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_PSS_SHA384 && return _TLS13SignatureVerifySpec(384, false, true)
    signature_algorithm == _TLS_SIGNATURE_RSA_PSS_PSS_SHA512 && return _TLS13SignatureVerifySpec(512, false, true)
    signature_algorithm == _TLS_SIGNATURE_ED25519 && return _TLS13SignatureVerifySpec(0, true, false)
    throw(ArgumentError("unsupported TLS 1.3 signature algorithm: $(string(signature_algorithm, base = 16))"))
end

@inline function _tls13_signature_md_name(spec::_TLS13SignatureVerifySpec)::Union{Nothing, String}
    spec.direct && return nothing
    spec.digest_bits == 256 && return "SHA256"
    spec.digest_bits == 384 && return "SHA384"
    spec.digest_bits == 512 && return "SHA512"
    throw(ArgumentError("unsupported TLS 1.3 signature digest size: $(spec.digest_bits)"))
end

function _tls13_rsa_pss_params(md_name::String)
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
    return pad_mode, mgf1_digest, saltlen, params
end

function _tls13_load_private_key_pem(key_pem::AbstractVector{UInt8})::Ptr{Cvoid}
    key_bytes = Vector{UInt8}(key_pem)
    bio = Ptr{Cvoid}(C_NULL)
    try
        bio = GC.@preserve key_bytes ccall(
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
    finally
        _free_bio!(bio)
        _securezero!(key_bytes)
    end
end

function _tls13_load_x509_pem(cert_pem::AbstractVector{UInt8})::Ptr{Cvoid}
    cert_bytes = Vector{UInt8}(cert_pem)
    bio = Ptr{Cvoid}(C_NULL)
    try
        bio = GC.@preserve cert_bytes ccall(
            (:BIO_new_mem_buf, _LIBCRYPTO_PATH),
            Ptr{Cvoid},
            (Ptr{UInt8}, Cint),
            pointer(cert_bytes),
            Cint(length(cert_bytes)),
        )
        _openssl_require_nonnull(bio, "BIO_new_mem_buf")
        x509 = ccall(
            (:PEM_read_bio_X509, _LIBCRYPTO_PATH),
            Ptr{Cvoid},
            (Ptr{Cvoid}, Ptr{Ptr{Cvoid}}, Ptr{Cvoid}, Ptr{Cvoid}),
            bio,
            C_NULL,
            C_NULL,
            C_NULL,
        )
        return _openssl_require_nonnull(x509, "PEM_read_bio_X509")
    finally
        _free_bio!(bio)
    end
end

function _tls13_load_x509_der(cert_der::AbstractVector{UInt8})::Ptr{Cvoid}
    cert_bytes = Vector{UInt8}(cert_der)
    x509_ref = Ref{Ptr{Cvoid}}(C_NULL)
    in_ref = Ref{Ptr{UInt8}}()
    GC.@preserve cert_bytes begin
        in_ref[] = pointer(cert_bytes)
        x509 = ccall(
            (:d2i_X509, _LIBCRYPTO_PATH),
            Ptr{Cvoid},
            (Ref{Ptr{Cvoid}}, Ref{Ptr{UInt8}}, Clong),
            x509_ref,
            in_ref,
            Clong(length(cert_bytes)),
        )
        return _openssl_require_nonnull(x509, "d2i_X509")
    end
end

function _tls13_x509_to_der(x509::Ptr{Cvoid})::Vector{UInt8}
    len = ccall((:i2d_X509, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Ptr{UInt8}}), x509, C_NULL)
    len > 0 || throw(_make_tls_error("i2d_X509", Int32(len)))
    out = Vector{UInt8}(undef, len)
    out_ref = Ref{Ptr{UInt8}}()
    GC.@preserve out begin
        out_ref[] = pointer(out)
        wrote = ccall((:i2d_X509, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ref{Ptr{UInt8}}), x509, out_ref)
        wrote == len || throw(_make_tls_error("i2d_X509", Int32(wrote)))
    end
    return out
end

function _tls13_openssl_certificate_der(cert_pem::AbstractVector{UInt8})::Vector{UInt8}
    x509 = _tls13_load_x509_pem(cert_pem)
    try
        return _tls13_x509_to_der(x509)
    finally
        _free_x509!(x509)
    end
end

function _tls13_pubkey_from_der_certificate(cert_der::AbstractVector{UInt8})::Ptr{Cvoid}
    x509 = _tls13_load_x509_der(cert_der)
    try
        pkey = ccall((:X509_get_pubkey, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), x509)
        return _openssl_require_nonnull(pkey, "X509_get_pubkey")
    finally
        _free_x509!(x509)
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
            _X25519_PKEY_ID,
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
    ctx = ccall((:EVP_PKEY_CTX_new_id, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Cint, Ptr{Cvoid}), _X25519_PKEY_ID, C_NULL)
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
        _X25519_PKEY_ID,
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
        return out
    finally
        _free_evp_pkey_ctx!(ctx)
        _free_evp_pkey!(peer_pkey)
    end
end

function _tls13_openssl_x25519_server_share_and_secret(client_share::AbstractVector{UInt8}, server_private_key::AbstractVector{UInt8})
    pkey = _tls13_x25519_private_key_from_bytes(server_private_key)
    try
        share = _TLSKeyShare(_TLS_GROUP_X25519, _tls13_x25519_public_key(pkey))
        secret = _tls13_x25519_shared_secret(pkey, client_share)
        return share, secret
    finally
        _free_evp_pkey!(pkey)
    end
end

function _tls13_openssl_verify_signature(pubkey::Ptr{Cvoid}, signature_algorithm::UInt16, signed::AbstractVector{UInt8}, signature::AbstractVector{UInt8})::Bool
    spec = _tls13_signature_verify_spec(signature_algorithm)
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
        md_name = _tls13_signature_md_name(spec)::String
        if spec.rsa_pss
            pad_mode, mgf1_digest, saltlen, params = _tls13_rsa_pss_params(md_name)
            ok = GC.@preserve pad_mode mgf1_digest saltlen params ccall(
                (:EVP_DigestVerifyInit_ex, _LIBCRYPTO_PATH),
                Cint,
                (Ptr{Cvoid}, Ref{Ptr{Cvoid}}, Cstring, Ptr{Cvoid}, Cstring, Ptr{Cvoid}, Ptr{_OpenSSLParam}),
                mdctx,
                pctx_ref,
                md_name,
                C_NULL,
                C_NULL,
                pubkey,
                pointer(params),
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

function _tls13_openssl_sign_signature(pkey::Ptr{Cvoid}, signature_algorithm::UInt16, signed::AbstractVector{UInt8})::Vector{UInt8}
    spec = _tls13_signature_verify_spec(signature_algorithm)
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
        md_name = _tls13_signature_md_name(spec)::String
        if spec.rsa_pss
            pad_mode, mgf1_digest, saltlen, params = _tls13_rsa_pss_params(md_name)
            ok = GC.@preserve pad_mode mgf1_digest saltlen params ccall(
                (:EVP_DigestSignInit_ex, _LIBCRYPTO_PATH),
                Cint,
                (Ptr{Cvoid}, Ref{Ptr{Cvoid}}, Cstring, Ptr{Cvoid}, Cstring, Ptr{Cvoid}, Ptr{_OpenSSLParam}),
                mdctx,
                pctx_ref,
                md_name,
                C_NULL,
                C_NULL,
                pkey,
                pointer(params),
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

function _tls13_openssl_sign_from_pem(signature_algorithm::UInt16, signed::AbstractVector{UInt8}, key_pem::AbstractVector{UInt8})::Vector{UInt8}
    pkey = _tls13_load_private_key_pem(key_pem)
    try
        return _tls13_openssl_sign_signature(pkey, signature_algorithm, signed)
    finally
        _free_evp_pkey!(pkey)
    end
end
