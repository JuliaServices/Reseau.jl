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
const _P256_GROUP_NID = Ref{Cint}(0)

function _init_x25519_pkey_id!()::Cint
    nid = _X25519_PKEY_ID[]
    nid > 0 && return nid
    nid = ccall((:OBJ_sn2nid, _LIBCRYPTO_PATH), Cint, (Cstring,), "X25519")
    nid > 0 || throw(ArgumentError("failed to initialize OpenSSL X25519 provider"))
    _X25519_PKEY_ID[] = nid
    return nid
end

@inline function _x25519_pkey_id()::Cint
    return _init_x25519_pkey_id!()
end

function _init_p256_group_nid!()::Cint
    nid = _P256_GROUP_NID[]
    nid > 0 && return nid
    nid = ccall((:OBJ_sn2nid, _LIBCRYPTO_PATH), Cint, (Cstring,), "prime256v1")
    nid > 0 || throw(ArgumentError("failed to initialize OpenSSL P-256 provider"))
    _P256_GROUP_NID[] = nid
    return nid
end

@inline function _p256_group_nid()::Cint
    return _init_p256_group_nid!()
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

@inline function _free_bio!(bio::Ptr{Cvoid})::Nothing
    bio == C_NULL || ccall((:BIO_free, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid},), bio)
    return nothing
end

@inline function _free_x509!(x509::Ptr{Cvoid})::Nothing
    x509 == C_NULL || ccall((:X509_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), x509)
    return nothing
end

@inline function _free_x509_store!(store::Ptr{Cvoid})::Nothing
    store == C_NULL || ccall((:X509_STORE_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), store)
    return nothing
end

@inline function _free_x509_store_ctx!(ctx::Ptr{Cvoid})::Nothing
    ctx == C_NULL || ccall((:X509_STORE_CTX_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), ctx)
    return nothing
end

@inline function _free_openssl_stack!(stack::Ptr{Cvoid})::Nothing
    stack == C_NULL || ccall((:OPENSSL_sk_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), stack)
    return nothing
end

@inline function _free_ec_key!(key::Ptr{Cvoid})::Nothing
    key == C_NULL || ccall((:EC_KEY_free, _LIBCRYPTO_PATH), Cvoid, (Ptr{Cvoid},), key)
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

struct _TLS13RSAPSSParams
    pad_mode::Vector{UInt8}
    mgf1_digest::Vector{UInt8}
    saltlen::Vector{UInt8}
    params::Vector{_OpenSSLParam}
end

const _EVP_CTRL_AEAD_SET_IVLEN = Cint(0x9)
const _EVP_CTRL_AEAD_GET_TAG = Cint(0x10)
const _EVP_CTRL_AEAD_SET_TAG = Cint(0x11)

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
        return GC.@preserve cert_bytes begin
            bio = ccall(
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
        end
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

function _tls13_load_verify_locations!(store::Ptr{Cvoid}, ca_path::AbstractString)::Nothing
    ok = if isdir(ca_path)
        ccall(
            (:X509_STORE_load_locations, _LIBCRYPTO_PATH),
            Cint,
            (Ptr{Cvoid}, Cstring, Cstring),
            store,
            C_NULL,
            ca_path,
        )
    else
        ccall(
            (:X509_STORE_load_locations, _LIBCRYPTO_PATH),
            Cint,
            (Ptr{Cvoid}, Cstring, Cstring),
            store,
            ca_path,
            C_NULL,
        )
    end
    _openssl_require_ok(ok, "X509_STORE_load_locations")
    return nothing
end

function _tls13_verify_server_certificate_chain(
    certificates::Vector{Vector{UInt8}},
    server_name::AbstractString;
    verify_peer::Bool,
    ca_file::Union{Nothing, String},
)::Ptr{Cvoid}
    isempty(certificates) && throw(ArgumentError("tls: received empty certificates message"))
    x509s = Ptr{Cvoid}[]
    store = Ptr{Cvoid}(C_NULL)
    store_ctx = Ptr{Cvoid}(C_NULL)
    untrusted = Ptr{Cvoid}(C_NULL)
    try
        for cert in certificates
            push!(x509s, _tls13_load_x509_der(cert))
        end
        leaf = x509s[1]
        if verify_peer
            ca_file === nothing && throw(ArgumentError("tls: certificate verification requires a CA roots path"))
            store = ccall((:X509_STORE_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
            _openssl_require_nonnull(store, "X509_STORE_new")
            _tls13_load_verify_locations!(store, ca_file::String)
            store_ctx = ccall((:X509_STORE_CTX_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
            _openssl_require_nonnull(store_ctx, "X509_STORE_CTX_new")
            if length(x509s) > 1
                untrusted = ccall((:OPENSSL_sk_new_null, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
                _openssl_require_nonnull(untrusted, "OPENSSL_sk_new_null")
                for x509 in @view x509s[2:end]
                    ok = ccall((:OPENSSL_sk_push, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), untrusted, x509)
                    ok > 0 || throw(_make_tls_error("OPENSSL_sk_push", Int32(ok)))
                end
            end
            ok = ccall(
                (:X509_STORE_CTX_init, _LIBCRYPTO_PATH),
                Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                store_ctx,
                store,
                leaf,
                untrusted,
            )
            _openssl_require_ok(ok, "X509_STORE_CTX_init")
            ok = ccall((:X509_STORE_CTX_set_default, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Cstring), store_ctx, "ssl_server")
            _openssl_require_ok(ok, "X509_STORE_CTX_set_default")
            param = ccall((:X509_STORE_CTX_get0_param, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), store_ctx)
            _openssl_require_nonnull(param, "X509_STORE_CTX_get0_param")
            normalized_server_name = String(server_name)
            if !isempty(normalized_server_name)
                if _is_ip_literal_name(normalized_server_name)
                    verify_ip = _verify_ip(normalized_server_name)
                    ok = ccall(
                        (:X509_VERIFY_PARAM_set1_ip_asc, _LIBCRYPTO_PATH),
                        Cint,
                        (Ptr{Cvoid}, Cstring),
                        param,
                        verify_ip,
                    )
                    _openssl_require_ok(ok, "X509_VERIFY_PARAM_set1_ip_asc")
                else
                    verify_name = _verify_name(normalized_server_name)
                    ok = ccall(
                        (:X509_VERIFY_PARAM_set1_host, _LIBCRYPTO_PATH),
                        Cint,
                        (Ptr{Cvoid}, Cstring, Csize_t),
                        param,
                        verify_name,
                        Csize_t(length(verify_name)),
                    )
                    _openssl_require_ok(ok, "X509_VERIFY_PARAM_set1_host")
                end
            end
            ok = ccall((:X509_verify_cert, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid},), store_ctx)
            if ok != 1
                err = ccall((:X509_STORE_CTX_get_error, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid},), store_ctx)
                depth = ccall((:X509_STORE_CTX_get_error_depth, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid},), store_ctx)
                msg_ptr = ccall((:X509_verify_cert_error_string, _LIBCRYPTO_PATH), Cstring, (Clong,), Clong(err))
                msg = msg_ptr == C_NULL ? "unknown certificate verification failure" : unsafe_string(msg_ptr)
                throw(ArgumentError("tls: certificate verification failed at depth $(depth): $(msg)"))
            end
        end
        pkey = ccall((:X509_get_pubkey, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), leaf)
        return _openssl_require_nonnull(pkey, "X509_get_pubkey")
    finally
        _free_x509_store_ctx!(store_ctx)
        _free_openssl_stack!(untrusted)
        _free_x509_store!(store)
        for x509 in x509s
            _free_x509!(x509)
        end
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
            _x25519_pkey_id(),
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
    ctx = ccall((:EVP_PKEY_CTX_new_id, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Cint, Ptr{Cvoid}), _x25519_pkey_id(), C_NULL)
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
        _x25519_pkey_id(),
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

function _tls13_p256_private_key_from_bytes(private_key::AbstractVector{UInt8})::Ptr{Cvoid}
    length(private_key) == 32 || throw(ArgumentError("tls13 P-256 private key must be 32 bytes"))
    private_bytes = Vector{UInt8}(private_key)
    ec_key = Ptr{Cvoid}(C_NULL)
    private_bn = Ptr{Cvoid}(C_NULL)
    point = Ptr{Cvoid}(C_NULL)
    bn_ctx = Ptr{Cvoid}(C_NULL)
    pkey = Ptr{Cvoid}(C_NULL)
    try
        ec_key = ccall((:EC_KEY_new_by_curve_name, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Cint,), _p256_group_nid())
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
        ec_key = ccall((:EC_KEY_new_by_curve_name, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Cint,), _p256_group_nid())
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
    peer_bytes = Vector{UInt8}(peer_public_key)
    ec_key = Ptr{Cvoid}(C_NULL)
    point = Ptr{Cvoid}(C_NULL)
    pkey = Ptr{Cvoid}(C_NULL)
    try
        ec_key = ccall((:EC_KEY_new_by_curve_name, _LIBCRYPTO_PATH), Ptr{Cvoid}, (Cint,), _p256_group_nid())
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
        return out
    finally
        _free_evp_pkey_ctx!(ctx)
        _free_evp_pkey!(peer_pkey)
    end
end

function _tls13_openssl_p256_server_share_and_secret(client_share::AbstractVector{UInt8}, server_private_key::AbstractVector{UInt8})
    pkey = _tls13_p256_private_key_from_bytes(server_private_key)
    try
        share = _TLSKeyShare(_TLS_GROUP_SECP256R1, _tls13_p256_public_key(pkey))
        secret = _tls13_p256_shared_secret(pkey, client_share)
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

function _tls13_openssl_sign_from_pem(signature_algorithm::UInt16, signed::AbstractVector{UInt8}, key_pem::AbstractVector{UInt8})::Vector{UInt8}
    pkey = _tls13_load_private_key_pem(key_pem)
    try
        return _tls13_openssl_sign_signature(pkey, signature_algorithm, signed)
    finally
        _free_evp_pkey!(pkey)
    end
end

@inline function _tls13_record_cipher(spec::_TLS13CipherSpec)::Ptr{Cvoid}
    spec == _TLS13_AES_128_GCM_SHA256 && return ccall((:EVP_aes_128_gcm, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
    spec == _TLS13_AES_256_GCM_SHA384 && return ccall((:EVP_aes_256_gcm, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
    spec == _TLS13_CHACHA20_POLY1305_SHA256 && return ccall((:EVP_chacha20_poly1305, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
    throw(ArgumentError("tls13 native record layer only supports AES-GCM and ChaCha20-Poly1305 cipher suites"))
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
    ctx = ccall((:EVP_CIPHER_CTX_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
    _openssl_require_nonnull(ctx, "EVP_CIPHER_CTX_new")
    ciphertext = Vector{UInt8}(undef, length(plaintext_bytes) + 16)
    tag = Vector{UInt8}(undef, 16)
    out_len = Ref{Cint}(0)
    total = 0
    try
        cipher = _tls13_record_cipher(spec)
        ok = ccall((:EVP_EncryptInit_ex, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}), ctx, cipher, C_NULL, Ptr{UInt8}(C_NULL), Ptr{UInt8}(C_NULL))
        _openssl_require_ok(ok, "EVP_EncryptInit_ex")
        ok = ccall((:EVP_CIPHER_CTX_ctrl, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Cint, Cint, Ptr{Cvoid}), ctx, _EVP_CTRL_AEAD_SET_IVLEN, Cint(length(iv_bytes)), C_NULL)
        _openssl_require_ok(ok, "EVP_CIPHER_CTX_ctrl(SET_IVLEN)")
        GC.@preserve key_bytes iv_bytes begin
            ok = ccall((:EVP_EncryptInit_ex, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}), ctx, C_NULL, C_NULL, pointer(key_bytes), pointer(iv_bytes))
            _openssl_require_ok(ok, "EVP_EncryptInit_ex(key/iv)")
        end
        if !isempty(aad_bytes)
            GC.@preserve aad_bytes begin
                ok = ccall((:EVP_EncryptUpdate, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, Cint), ctx, Ptr{UInt8}(C_NULL), out_len, pointer(aad_bytes), Cint(length(aad_bytes)))
                _openssl_require_ok(ok, "EVP_EncryptUpdate(aad)")
            end
        end
        if !isempty(plaintext_bytes)
            GC.@preserve plaintext_bytes ciphertext begin
                ok = ccall((:EVP_EncryptUpdate, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, Cint), ctx, pointer(ciphertext), out_len, pointer(plaintext_bytes), Cint(length(plaintext_bytes)))
                _openssl_require_ok(ok, "EVP_EncryptUpdate")
            end
            total += Int(out_len[])
        end
        GC.@preserve ciphertext begin
            ok = ccall((:EVP_EncryptFinal_ex, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}), ctx, pointer(ciphertext, total + 1), out_len)
            _openssl_require_ok(ok, "EVP_EncryptFinal_ex")
        end
        total += Int(out_len[])
        GC.@preserve tag begin
            ok = ccall((:EVP_CIPHER_CTX_ctrl, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Cint, Cint, Ptr{Cvoid}), ctx, _EVP_CTRL_AEAD_GET_TAG, Cint(length(tag)), pointer(tag))
            _openssl_require_ok(ok, "EVP_CIPHER_CTX_ctrl(GET_TAG)")
        end
        resize!(ciphertext, total)
        append!(ciphertext, tag)
        return ciphertext
    finally
        _free_evp_cipher_ctx!(ctx)
    end
end

function _tls13_decrypt_record_aead(
    spec::_TLS13CipherSpec,
    key::AbstractVector{UInt8},
    iv::AbstractVector{UInt8},
    additional_data::AbstractVector{UInt8},
    ciphertext_and_tag::AbstractVector{UInt8},
)::Union{Vector{UInt8}, Nothing}
    length(ciphertext_and_tag) >= 16 || throw(ArgumentError("tls: TLS 1.3 ciphertext is missing the authentication tag"))
    key_bytes = key isa Vector{UInt8} ? key : Vector{UInt8}(key)
    iv_bytes = iv isa Vector{UInt8} ? iv : Vector{UInt8}(iv)
    aad_bytes = additional_data isa Vector{UInt8} ? additional_data : Vector{UInt8}(additional_data)
    ciphertext_len = length(ciphertext_and_tag) - 16
    ciphertext = Vector{UInt8}(undef, ciphertext_len)
    copyto!(ciphertext, 1, ciphertext_and_tag, 1, ciphertext_len)
    tag = Vector{UInt8}(undef, 16)
    copyto!(tag, 1, ciphertext_and_tag, ciphertext_len + 1, 16)
    plaintext = Vector{UInt8}(undef, ciphertext_len)
    ctx = ccall((:EVP_CIPHER_CTX_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
    _openssl_require_nonnull(ctx, "EVP_CIPHER_CTX_new")
    out_len = Ref{Cint}(0)
    total = 0
    try
        cipher = _tls13_record_cipher(spec)
        ok = ccall((:EVP_DecryptInit_ex, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}), ctx, cipher, C_NULL, Ptr{UInt8}(C_NULL), Ptr{UInt8}(C_NULL))
        _openssl_require_ok(ok, "EVP_DecryptInit_ex")
        ok = ccall((:EVP_CIPHER_CTX_ctrl, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Cint, Cint, Ptr{Cvoid}), ctx, _EVP_CTRL_AEAD_SET_IVLEN, Cint(length(iv_bytes)), C_NULL)
        _openssl_require_ok(ok, "EVP_CIPHER_CTX_ctrl(SET_IVLEN)")
        GC.@preserve key_bytes iv_bytes begin
            ok = ccall((:EVP_DecryptInit_ex, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}), ctx, C_NULL, C_NULL, pointer(key_bytes), pointer(iv_bytes))
            _openssl_require_ok(ok, "EVP_DecryptInit_ex(key/iv)")
        end
        if !isempty(aad_bytes)
            GC.@preserve aad_bytes begin
                ok = ccall((:EVP_DecryptUpdate, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, Cint), ctx, Ptr{UInt8}(C_NULL), out_len, pointer(aad_bytes), Cint(length(aad_bytes)))
                _openssl_require_ok(ok, "EVP_DecryptUpdate(aad)")
            end
        end
        if !isempty(ciphertext)
            GC.@preserve ciphertext plaintext begin
                ok = ccall((:EVP_DecryptUpdate, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, Cint), ctx, pointer(plaintext), out_len, pointer(ciphertext), Cint(length(ciphertext)))
                _openssl_require_ok(ok, "EVP_DecryptUpdate")
            end
            total += Int(out_len[])
        end
        GC.@preserve tag begin
            ok = ccall((:EVP_CIPHER_CTX_ctrl, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Cint, Cint, Ptr{Cvoid}), ctx, _EVP_CTRL_AEAD_SET_TAG, Cint(length(tag)), pointer(tag))
            _openssl_require_ok(ok, "EVP_CIPHER_CTX_ctrl(SET_TAG)")
        end
        final_ok = GC.@preserve plaintext ccall(
            (:EVP_DecryptFinal_ex, _LIBCRYPTO_PATH),
            Cint,
            (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}),
            ctx,
            pointer(plaintext, total + 1),
            out_len,
        )
        final_ok == 1 || return nothing
        total += Int(out_len[])
        resize!(plaintext, total)
        return plaintext
    finally
        _free_evp_cipher_ctx!(ctx)
    end
end
