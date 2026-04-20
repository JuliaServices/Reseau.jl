"""
    _TLSTrustStore

Native trust-store view used by the certificate chain verifier.

The store holds parsed root certificates only; chain building and policy checks
work against `_TLSCertificateInfo` values and call into the primitive crypto
backend only for raw signature verification.
"""
struct _TLSTrustStore
    roots::Vector{_TLSCertificateInfo}
end

struct _TLSTrustStoreCacheEntry
    mtime::Float64
    size::Int64
    store::_TLSTrustStore
end

struct _TLSTrustStoreFingerprint
    mtime::Float64
    size::Int64
end

const _TLS_TRUST_STORE_CACHE_LOCK = ReentrantLock()
const _TLS_TRUST_STORE_CACHE = Dict{String, _TLSTrustStoreCacheEntry}()

# Native certificate chain verification and trust-store loading.
#
# This layer owns trust-policy decisions (validity windows, issuer linkage,
# basic constraints, EKU/KU checks, trust-anchor selection). It uses parsed
# `_TLSCertificateInfo` values from `x509.jl` and delegates only raw signature
# verification to the OpenSSL primitive backend.

@inline function _tls_verify_purpose_usage_mask(purpose::AbstractString)::UInt8
    purpose == "ssl_server" && return _TLS_EXT_KEY_USAGE_SERVER
    purpose == "ssl_client" && return _TLS_EXT_KEY_USAGE_CLIENT
    throw(ArgumentError("unsupported TLS certificate verification purpose: $(purpose)"))
end

@inline function _tls_verify_purpose_key_usage_mask(purpose::AbstractString)::UInt16
    purpose == "ssl_server" && return _TLS_KEY_USAGE_DIGITAL_SIGNATURE | _TLS_KEY_USAGE_KEY_ENCIPHERMENT
    purpose == "ssl_client" && return _TLS_KEY_USAGE_DIGITAL_SIGNATURE
    throw(ArgumentError("unsupported TLS certificate verification purpose: $(purpose)"))
end

@inline function _tls_certificate_valid_now(cert::_TLSCertificateInfo, now_s::Int64)::Bool
    return cert.not_before_s <= now_s <= cert.not_after_s
end

@inline function _tls_certificate_current_time_message(cert::_TLSCertificateInfo)::String
    return "certificate has expired or is not yet valid (valid unix range $(cert.not_before_s)-$(cert.not_after_s))"
end

@inline function _tls_certificate_usage_permitted(cert::_TLSCertificateInfo, purpose::AbstractString)::Bool
    if cert.has_key_usage && (cert.key_usage & _tls_verify_purpose_key_usage_mask(purpose)) == 0x00
        return false
    end
    cert.extended_key_usage == 0x00 && return true
    (cert.extended_key_usage & _TLS_EXT_KEY_USAGE_ANY) != 0x00 && return true
    return (cert.extended_key_usage & _tls_verify_purpose_usage_mask(purpose)) != 0x00
end

@inline function _tls_issuer_can_sign(cert::_TLSCertificateInfo)::Bool
    cert.is_ca || return false
    cert.has_key_usage || return true
    return (cert.key_usage & _TLS_KEY_USAGE_KEY_CERT_SIGN) != 0x00
end

@inline function _tls_cert_subject_matches_issuer(child::_TLSCertificateInfo, parent::_TLSCertificateInfo)::Bool
    if !isempty(child.authority_key_id) && !isempty(parent.subject_key_id)
        child.authority_key_id == parent.subject_key_id && return true
        return false
    end
    return child.issuer_raw == parent.subject_raw
end

# Trust-store loading stays in native Julia too, including the trim-safe file
# reader, so certificate policy no longer depends on OpenSSL's X509 store APIs.
function _read_tls_file_bytes(path::AbstractString)::Vector{UInt8}
    path_string = String(path)
    file = ccall(:fopen, Ptr{Cvoid}, (Cstring, Cstring), path_string, "rb")
    file == C_NULL && throw(SystemError("fopen", Base.Libc.errno()))
    bytes = Vector{UInt8}(undef, Int(stat(path_string).size))
    chunk = Vector{UInt8}(undef, 8192)
    offset = 0
    completed = false
    try
        while true
            n = Int(ccall(:fread, Csize_t, (Ptr{UInt8}, Csize_t, Csize_t, Ptr{Cvoid}), chunk, 1, length(chunk), file))
            if n == 0
                if ccall(:feof, Cint, (Ptr{Cvoid},), file) != 0
                    resize!(bytes, offset)
                    completed = true
                    return bytes
                end
                ccall(:ferror, Cint, (Ptr{Cvoid},), file) == 0 && throw(SystemError("fread", 0))
                throw(SystemError("fread", Base.Libc.errno()))
            end
            required = offset + n
            required <= length(bytes) || resize!(bytes, max(required, length(bytes) + length(chunk)))
            copyto!(bytes, offset + 1, chunk, 1, n)
            offset = required
        end
    finally
        completed || _securezero!(bytes)
        _securezero!(chunk)
        ccall(:fclose, Cint, (Ptr{Cvoid},), file)
    end
end

function _tls_load_trust_certificates(ca_path::AbstractString)::Vector{Vector{UInt8}}
    if isdir(ca_path)
        certificates = Vector{Vector{UInt8}}()
        for entry in sort(readdir(ca_path; join = true))
            isfile(entry) || continue
            pem_bytes = _read_tls_file_bytes(entry)
            _tls_contains_pem_certificate_header(pem_bytes) || continue
            append!(certificates, _tls_decode_pem_certificates(pem_bytes))
        end
        isempty(certificates) && throw(ArgumentError("tls: CA roots directory does not contain any PEM certificate blocks"))
        return certificates
    end
    return _tls_decode_pem_certificates(_read_tls_file_bytes(ca_path))
end

function _tls_trust_store_fingerprint(ca_path::AbstractString)::_TLSTrustStoreFingerprint
    if isdir(ca_path)
        dir_stat = stat(ca_path)
        latest_mtime = dir_stat.mtime
        total_size = Int64(0)
        for entry in sort(readdir(ca_path; join = true))
            isfile(entry) || continue
            entry_stat = stat(entry)
            latest_mtime = max(latest_mtime, entry_stat.mtime)
            total_size += Int64(entry_stat.size)
        end
        return _TLSTrustStoreFingerprint(latest_mtime, total_size)
    end
    path_stat = stat(ca_path)
    return _TLSTrustStoreFingerprint(path_stat.mtime, Int64(path_stat.size))
end

function _tls_load_trust_store(ca_path::AbstractString)::_TLSTrustStore
    cache_path = abspath(ca_path)
    fingerprint = _tls_trust_store_fingerprint(cache_path)
    lock(_TLS_TRUST_STORE_CACHE_LOCK)
    try
        if haskey(_TLS_TRUST_STORE_CACHE, cache_path)
            entry = _TLS_TRUST_STORE_CACHE[cache_path]
            if entry.mtime == fingerprint.mtime && entry.size == fingerprint.size
                return entry.store
            end
        end
    finally
        unlock(_TLS_TRUST_STORE_CACHE_LOCK)
    end
    certificates = _tls_load_trust_certificates(cache_path)
    roots = _TLSCertificateInfo[]
    for cert_der in certificates
        duplicate = false
        for root in roots
            if root.der == cert_der
                duplicate = true
                break
            end
        end
        duplicate && continue
        push!(roots, _tls_parse_der_certificate_info(cert_der))
    end
    isempty(roots) && throw(ArgumentError("tls: CA roots path does not contain any certificates"))
    store = _TLSTrustStore(roots)
    lock(_TLS_TRUST_STORE_CACHE_LOCK)
    try
        _TLS_TRUST_STORE_CACHE[cache_path] = _TLSTrustStoreCacheEntry(fingerprint.mtime, fingerprint.size, store)
    finally
        unlock(_TLS_TRUST_STORE_CACHE_LOCK)
    end
    return store
end

# Chain verification works top-down from the peer leaf and recursively searches
# intermediates/roots that satisfy issuer linkage, CA constraints, time
# validity, and signature checks until it finds a trust anchor.
function _tls_verify_certificate_signature(child::_TLSCertificateInfo, parent::_TLSCertificateInfo)::Bool
    return _openssl_verify_signature_with_spec(parent.public_key, child.signature_verify_spec, child.tbs_der, child.signature)
end

function _tls_trust_anchor_matches(cert::_TLSCertificateInfo, store::_TLSTrustStore)::Bool
    for root in store.roots
        root.der == cert.der && return true
    end
    return false
end

@inline function _tls_certificate_has_name_constraints(cert::_TLSCertificateInfo)::Bool
    return !isempty(cert.permitted_dns_domains) ||
           !isempty(cert.excluded_dns_domains) ||
           !isempty(cert.permitted_ip_ranges) ||
           !isempty(cert.excluded_ip_ranges)
end

@inline function _tls_dns_constraint_matches(constraint::AbstractString, dns_name::AbstractString)::Bool
    isempty(constraint) && return true
    normalized_constraint = _tls_ascii_lowercase(constraint)
    normalized_name = _tls_ascii_lowercase(dns_name)
    endswith(normalized_name, normalized_constraint) || return false
    startswith(normalized_constraint, ".") && return true
    length(normalized_name) == length(normalized_constraint) && return true
    boundary = ncodeunits(normalized_name) - ncodeunits(normalized_constraint)
    return boundary > 0 && codeunit(normalized_name, boundary) == UInt8('.')
end

@inline function _tls_ip_range_matches(range::_TLSIPRangeConstraint, ip::AbstractVector{UInt8})::Bool
    length(ip) == length(range.network) || return false
    length(ip) == length(range.mask) || return false
    @inbounds for i in eachindex(ip, range.network, range.mask)
        (ip[i] & range.mask[i]) == (range.network[i] & range.mask[i]) || return false
    end
    return true
end

@inline function _tls_constraint_ip_string(ip::AbstractVector{UInt8})::String
    return join(string.(ip), '.')
end

function _tls_verify_certificate_name_constraints!(
    cert::_TLSCertificateInfo,
    issuer::_TLSCertificateInfo,
)::Nothing
    if !isempty(issuer.permitted_dns_domains)
        for dns_name in cert.dns_names
            permitted = false
            for constraint in issuer.permitted_dns_domains
                if _tls_dns_constraint_matches(constraint, dns_name)
                    permitted = true
                    break
                end
            end
            permitted || _tls_fail(
                _TLS_ALERT_BAD_CERTIFICATE,
                "tls: certificate chain violates DNS name constraints for $(repr(dns_name))",
            )
        end
    end
    for dns_name in cert.dns_names
        for constraint in issuer.excluded_dns_domains
            _tls_dns_constraint_matches(constraint, dns_name) || continue
            _tls_fail(
                _TLS_ALERT_BAD_CERTIFICATE,
                "tls: certificate chain violates excluded DNS name constraint for $(repr(dns_name))",
            )
        end
    end
    if !isempty(issuer.permitted_ip_ranges)
        for ip in cert.ip_addresses
            permitted = false
            for constraint in issuer.permitted_ip_ranges
                if _tls_ip_range_matches(constraint, ip)
                    permitted = true
                    break
                end
            end
            permitted || _tls_fail(
                _TLS_ALERT_BAD_CERTIFICATE,
                "tls: certificate chain violates IP name constraints for $(_tls_constraint_ip_string(ip))",
            )
        end
    end
    for ip in cert.ip_addresses
        for constraint in issuer.excluded_ip_ranges
            _tls_ip_range_matches(constraint, ip) || continue
            _tls_fail(
                _TLS_ALERT_BAD_CERTIFICATE,
                "tls: certificate chain violates excluded IP name constraint for $(_tls_constraint_ip_string(ip))",
            )
        end
    end
    return nothing
end

function _tls_verify_chain_name_constraints!(chain::Vector{_TLSCertificateInfo})::Nothing
    for cert_index in eachindex(chain)
        cert = chain[cert_index]
        cert.has_san_extension || continue
        for issuer_index in (cert_index + 1):length(chain)
            issuer = chain[issuer_index]
            _tls_certificate_has_name_constraints(issuer) || continue
            _tls_verify_certificate_name_constraints!(cert, issuer)
        end
    end
    return nothing
end

function _tls_build_chain_to_trust_anchor!(
    child::_TLSCertificateInfo,
    intermediates::Vector{_TLSCertificateInfo},
    store::_TLSTrustStore,
    chain::Vector{_TLSCertificateInfo},
    now_s::Int64,
    remaining_candidates::Base.RefValue{Int},
)::Union{Nothing, Vector{_TLSCertificateInfo}}
    length(chain) > _TLS_MAX_CHAIN_DEPTH && return nothing
    for root in store.roots
        _tls_cert_subject_matches_issuer(child, root) || continue
        remaining_candidates[] -= 1
        remaining_candidates[] >= 0 || return nothing
        _tls_issuer_can_sign(root) || continue
        _tls_certificate_valid_now(root, now_s) || continue
        if root.max_path_len >= 0
            ca_count = 0
            for cert in chain
                cert.is_ca && (ca_count += 1)
            end
            ca_count <= root.max_path_len || continue
        end
        _tls_verify_certificate_signature(child, root) || continue
        verified_chain = copy(chain)
        push!(verified_chain, root)
        return verified_chain
    end
    for (i, parent) in pairs(intermediates)
        _tls_cert_subject_matches_issuer(child, parent) || continue
        remaining_candidates[] -= 1
        remaining_candidates[] >= 0 || return nothing
        _tls_issuer_can_sign(parent) || continue
        _tls_certificate_valid_now(parent, now_s) || continue
        if parent.max_path_len >= 0
            ca_count = 0
            for cert in chain
                cert.is_ca && (ca_count += 1)
            end
            ca_count <= parent.max_path_len || continue
        end
        _tls_verify_certificate_signature(child, parent) || continue
        next_chain = copy(chain)
        push!(next_chain, parent)
        remaining = copy(intermediates)
        deleteat!(remaining, i)
        verified_chain = _tls_build_chain_to_trust_anchor!(parent, remaining, store, next_chain, now_s, remaining_candidates)
        verified_chain === nothing || return verified_chain
    end
    return nothing
end

function _tls_verify_peer_certificate_chain!(
    certificates::Vector{Vector{UInt8}},
    store::_TLSTrustStore,
    purpose::AbstractString,
)::_TLSCertificateInfo
    isempty(certificates) && _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: received empty certificates message")
    parsed = _TLSCertificateInfo[]
    try
        for cert_der in certificates
            push!(parsed, _tls_parse_der_certificate_info(cert_der))
        end
    catch ex
        ex isa _TLSAlertError && rethrow()
        _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: malformed X.509 certificate")
    end
    leaf = parsed[1]
    now_s = Int64(floor(time()))
    _tls_certificate_valid_now(leaf, now_s) ||
        _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: $(_tls_certificate_current_time_message(leaf))")
    _tls_certificate_usage_permitted(leaf, purpose) ||
        _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, purpose == "ssl_server" ?
            "tls: certificate is not authorized for server authentication" :
            "tls: certificate is not authorized for client authentication")
    if _tls_trust_anchor_matches(leaf, store)
        return leaf
    end
    intermediates = length(parsed) > 1 ? parsed[2:end] : _TLSCertificateInfo[]
    remaining_candidates = Ref(_TLS_MAX_CHAIN_CANDIDATES)
    verified_chain = _tls_build_chain_to_trust_anchor!(leaf, intermediates, store, _TLSCertificateInfo[leaf], now_s, remaining_candidates)
    verified_chain === nothing &&
        _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: certificate signed by unknown authority")
    _tls_verify_chain_name_constraints!(verified_chain)
    return leaf
end

# This is the native cert-auth entry point used by TLS 1.2 and TLS 1.3
# handshakes: optionally build to a trust anchor, optionally check hostname/IP,
# then return the parsed leaf public key for later TLS-level signature checks.
function _tls_verify_certificate_chain(
    certificates::Vector{Vector{UInt8}};
    verify_peer::Bool,
    verify_hostname::Bool,
    ca_file::Union{Nothing, String},
    purpose::AbstractString,
    peer_name::AbstractString = "",
)::_TLSPublicKey
    isempty(certificates) && _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: received empty certificates message")
    leaf = if verify_peer
        ca_file === nothing && _tls_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: certificate verification requires a CA roots path")
        store = try
            _tls_load_trust_store(ca_file::String)
        catch ex
            ex isa _TLSAlertError && rethrow()
            _tls_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: failed to load CA roots")
        end
        _tls_verify_peer_certificate_chain!(certificates, store, purpose)
    else
        try
            _tls_parse_der_certificate_info(certificates[1])
        catch ex
            ex isa _TLSAlertError && rethrow()
            _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: malformed X.509 certificate")
        end
    end
    verify_hostname && isempty(peer_name) &&
        _tls_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: hostname verification requires a peer name")
    verify_hostname && _tls_verify_certificate_peer_name!(leaf, peer_name)
    return _tls_copy_public_key(leaf.public_key)
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

function _tls13_load_x509_pem_chain(cert_pem::AbstractVector{UInt8})::Vector{Vector{UInt8}}
    return _tls_decode_pem_certificates(cert_pem)
end

function _tls13_check_x509_peer_name!(cert_der::AbstractVector{UInt8}, peer_name::AbstractString)::Nothing
    cert_info = try
        _tls_parse_der_certificate_info(cert_der)
    catch ex
        ex isa _TLSAlertError && rethrow()
        _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: malformed X.509 certificate")
    end
    _tls_verify_certificate_peer_name!(cert_info, peer_name)
    return nothing
end

function _tls13_check_x509_peer_name!(x509::Ptr{Cvoid}, peer_name::AbstractString)::Nothing
    return _tls13_check_x509_peer_name!(_tls13_x509_to_der(x509), peer_name)
end

function _tls13_verify_certificate_chain(
    certificates::Vector{Vector{UInt8}};
    verify_peer::Bool,
    verify_hostname::Bool,
    ca_file::Union{Nothing, String},
    purpose::AbstractString,
    peer_name::AbstractString = "",
)::_TLSPublicKey
    return _tls_verify_certificate_chain(
        certificates;
        verify_peer,
        verify_hostname,
        ca_file,
        purpose,
        peer_name,
    )
end

function _tls13_verify_server_certificate_chain(
    certificates::Vector{Vector{UInt8}},
    server_name::AbstractString;
    verify_peer::Bool,
    verify_hostname::Bool,
    ca_file::Union{Nothing, String},
)::_TLSPublicKey
    return _tls13_verify_certificate_chain(
        certificates;
        verify_peer,
        verify_hostname,
        ca_file,
        purpose = "ssl_server",
        peer_name = server_name,
    )
end

function _tls13_verify_client_certificate_chain(
    certificates::Vector{Vector{UInt8}};
    verify_peer::Bool,
    ca_file::Union{Nothing, String},
)::_TLSPublicKey
    return _tls13_verify_certificate_chain(
        certificates;
        verify_peer,
        verify_hostname = false,
        ca_file,
        purpose = "ssl_client",
    )
end
