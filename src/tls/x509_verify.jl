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

# eMudhra intermediate CA keys compromised in October 2026. Distrust by key,
# not certificate DER, so the Sectigo cross-signs are covered too. These hashes
# match Go 1.27.3's crypto/x509 denylist and the published incident data:
# https://emudhra.we-have-a-problem.com/impacted-intermediates.json
# https://github.com/golang/go/blob/go1.27.3/src/crypto/x509/verify.go
# Keep this immutable and local: validation must not depend on a network fetch.
const _TLS_DISTRUSTED_SPKI_SHA256 = (
    Tuple(hex2bytes("ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105")), # EM DV TLS CA - G3B
    Tuple(hex2bytes("49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f")), # EM DV TLS CA - G3C
    Tuple(hex2bytes("e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41")), # EM EV TLS CA - G3B
    Tuple(hex2bytes("5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0")), # EM EV TLS CA - G3C
    Tuple(hex2bytes("43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b")), # EM OV TLS CA - G3B
    Tuple(hex2bytes("63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8")), # EM OV TLS CA - G3C
    Tuple(hex2bytes("ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6")), # EM OV CS CA - G3B
    Tuple(hex2bytes("92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30")), # EM OV CS CA - G3C
)

@inline _tls_certificate_distrusted(cert::_TLSCertificateInfo)::Bool =
    cert.spki_sha256 in _TLS_DISTRUSTED_SPKI_SHA256

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
    cert.has_extended_key_usage || return true
    (cert.extended_key_usage & _TLS_EXT_KEY_USAGE_ANY) != 0x00 && return true
    return (cert.extended_key_usage & _tls_verify_purpose_usage_mask(purpose)) != 0x00
end

@inline function _tls_issuer_can_sign(cert::_TLSCertificateInfo)::Bool
    cert.is_ca || return false
    cert.has_key_usage || return true
    return (cert.key_usage & _TLS_KEY_USAGE_KEY_CERT_SIGN) != 0x00
end

@inline function _tls_cert_subject_matches_issuer(child::_TLSCertificateInfo, parent::_TLSCertificateInfo)::Bool
    child.issuer_raw == parent.subject_raw || return false
    if !isempty(child.authority_key_id) && !isempty(parent.subject_key_id)
        return child.authority_key_id == parent.subject_key_id
    end
    return true
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
        try
            push!(roots, _tls_parse_der_certificate_info(cert_der))
        catch err
            err isa ArgumentError || rethrow()
            continue
        end
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

# Cache each source independently. The combined roots vector is owned by this
# store, so adding a directory never changes a cached single-source store.
function _tls_load_trust_store(ca_file::Union{Nothing, String}, ca_dir::Union{Nothing, String})::_TLSTrustStore
    if ca_dir === nothing
        ca_file === nothing && throw(ArgumentError("tls: certificate verification requires a CA roots path"))
        return _tls_load_trust_store(ca_file::String)
    end
    isdir(ca_dir) || throw(ArgumentError("tls: CA roots directory not found"))
    directory_store = _tls_load_trust_store(ca_dir)
    ca_file === nothing && return directory_store
    file_store = _tls_load_trust_store(ca_file)
    roots = copy(file_store.roots)
    for root in directory_store.roots
        any(existing -> existing.der == root.der, roots) || push!(roots, root)
    end
    return _TLSTrustStore(roots)
end

# Chain verification works top-down from the peer leaf and recursively searches
# intermediates/roots that satisfy issuer linkage, CA constraints, time
# validity, and signature checks until it finds a trust anchor.
function _tls_verify_certificate_signature(child::_TLSCertificateInfo, parent::_TLSCertificateInfo)::Bool
    # Reject SHA-1 (digest_bits == 160) for signatures we actually verify in the
    # chain. A self-signed root's own signature is never verified (see
    # `_tls_build_chain_to_trust_anchor!`), so SHA-1 trust anchors stay usable —
    # matching OpenSSL and MbedTLS, which apply the policy only to verified signatures.
    child.signature_verify_spec.digest_bits == 160 && return false
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
           !isempty(cert.excluded_ip_ranges) ||
           !isempty(cert.permitted_uri_domains) ||
           !isempty(cert.excluded_uri_domains) ||
           !isempty(cert.permitted_email_addresses) ||
           !isempty(cert.excluded_email_addresses)
end

@inline function _tls_certificate_has_permitted_name_constraints(cert::_TLSCertificateInfo)::Bool
    return !isempty(cert.permitted_dns_domains) ||
           !isempty(cert.permitted_ip_ranges) ||
           !isempty(cert.permitted_uri_domains) ||
           !isempty(cert.permitted_email_addresses)
end

# Name-constraint matching follows Go 1.27's crypto/x509 (verify.go, constraints.go).

@inline _tls_ascii_lower(b::UInt8)::UInt8 = UInt8('A') <= b <= UInt8('Z') ? b + 0x20 : b

# Go's `domainNameValid`: labels of printable ASCII, none empty, and no trailing
# period. A constraint may use the leading-period form ".example.com". The empty
# string is valid; as a constraint it matches every name.
function _tls_name_constraint_domain_valid(name::AbstractString, constraint::Bool)::Bool
    bytes = codeunits(name)
    n = length(bytes)
    n == 0 && return true
    @inbounds bytes[n] == UInt8('.') && return false
    i = constraint && @inbounds(bytes[1]) == UInt8('.') ? 2 : 1
    label_len = 0
    @inbounds while i <= n
        b = bytes[i]
        (b < 0x21 || b > 0x7e) && return false
        if b == UInt8('.')
            label_len == 0 && return false
            label_len = 0
        else
            label_len += 1
        end
        i += 1
    end
    return label_len > 0
end

# Go's `dnsHasSuffix`: `constraint` matches `name` when it is a case-insensitive
# label suffix of it. A leading-period constraint matches proper subdomains only.
function _tls_dns_constraint_matches(constraint::AbstractString, name::AbstractString)::Bool
    c = codeunits(constraint)
    n = codeunits(name)
    isempty(c) && return true
    length(c) > length(n) && return false
    offset = length(n) - length(c)
    @inbounds for i in eachindex(c)
        _tls_ascii_lower(c[i]) == _tls_ascii_lower(n[offset + i]) || return false
    end
    @inbounds return c[1] == UInt8('.') || offset == 0 || n[offset] == UInt8('.')
end

# A name starting with '*' is also excluded by a subtree whose parent equals the
# name's remaining labels: "*.example.com" could stand for "bar.example.com", so
# excluding "bar.example.com" excludes it (Go's `parentConstraints`, CVE-2025-61727).
function _tls_dns_wildcard_excluded(constraint::AbstractString, name::AbstractString)::Bool
    n = codeunits(name)
    c = codeunits(constraint)
    (isempty(n) || @inbounds(n[1]) != UInt8('*')) && return false
    name_dot = findfirst(==(UInt8('.')), n)
    constraint_dot = findfirst(==(UInt8('.')), c)
    (name_dot === nothing || constraint_dot === nothing) && return false
    length(n) - name_dot == length(c) - constraint_dot || return false
    @inbounds for i in 0:(length(n) - name_dot)
        _tls_ascii_lower(n[name_dot + i]) == _tls_ascii_lower(c[constraint_dot + i]) || return false
    end
    return true
end

function _tls_domain_permitted(constraints::Vector{String}, name::AbstractString)::Bool
    isempty(constraints) && return true
    for constraint in constraints
        _tls_dns_constraint_matches(constraint, name) && return true
    end
    return false
end

function _tls_domain_excluded(constraints::Vector{String}, name::AbstractString)::Bool
    for constraint in constraints
        _tls_dns_constraint_matches(constraint, name) && return true
        _tls_dns_wildcard_excluded(constraint, name) && return true
    end
    return false
end

@inline function _tls_ip_range_matches(range::_TLSIPRangeConstraint, ip::AbstractVector{UInt8})::Bool
    length(ip) == length(range.network) || return false
    length(ip) == length(range.mask) || return false
    @inbounds for i in 1:length(ip)
        (ip[i] & range.mask[i]) == (range.network[i] & range.mask[i]) || return false
    end
    return true
end

@inline function _tls_constraint_ip_string(ip::AbstractVector{UInt8})::String
    return join(string.(ip), '.')
end

struct _TLSParsedMailbox
    local_part::String
    domain::String
end

@inline function _tls_findfirst_ascii_byte(text::String, byte::UInt8, start::Int = 1)::Union{Nothing, Int}
    i = max(start, 1)
    n = ncodeunits(text)
    while i <= n
        codeunit(text, i) == byte && return i
        i += 1
    end
    return nothing
end

@inline function _tls_findlast_ascii_byte(text::String, byte::UInt8)::Union{Nothing, Int}
    i = ncodeunits(text)
    while i >= 1
        codeunit(text, i) == byte && return i
        i -= 1
    end
    return nothing
end

# SAN values are certificate bytes, not necessarily ASCII or valid UTF-8. The
# delimiters searched for are ASCII, so slicing by byte offset is always valid
# where character indexing could land inside a multi-byte character.
@inline _tls_byte_slice(text::String, first::Int, last::Int)::String = String(codeunits(text)[first:last])

# RFC 2822 atext, plus '.' (dot-atom separators are checked afterwards).
@inline function _tls_mailbox_atext(c::UInt8)::Bool
    return (UInt8('0') <= c <= UInt8('9')) || (UInt8('a') <= c <= UInt8('z')) || (UInt8('A') <= c <= UInt8('Z')) ||
           c in codeunits("!#\$%&'*+-/=?^_`{|}~.")
end

# Go's `parseRFC2821Mailbox` (an rfc822Name is an RFC 2821 Mailbox, RFC 5280
# 4.2.1.6). The local part is unquoted and unescaped, so `"admin"@x` and `ad\min@x`
# both name the mailbox `admin@x`; the domain is ASCII-lowercased. Returns
# `nothing` for any value Go rejects, including non-IA5 bytes.
function _tls_parse_rfc2821_mailbox(value::AbstractString)::Union{Nothing, _TLSParsedMailbox}
    bytes = codeunits(String(value))
    n = length(bytes)
    n == 0 && return nothing
    for b in bytes
        b < 0x80 || return nothing
    end
    local_part = UInt8[]
    i = 1
    @inbounds if bytes[1] == UInt8('"')
        i = 2
        while true
            i > n && return nothing
            c = bytes[i]
            i += 1
            if c == UInt8('"')
                break
            elseif c == UInt8('\\')
                # quoted-pair
                i > n && return nothing
                q = bytes[i]
                (q == 0x0b || q == 0x0c || 0x01 <= q <= 0x09 || 0x0e <= q <= 0x7f) || return nothing
                push!(local_part, q)
                i += 1
            elseif c == 0x0b || c == 0x0c || c == 0x20 || c == 0x21 || c == 0x7f ||
                   0x01 <= c <= 0x08 || 0x0e <= c <= 0x1f || 0x23 <= c <= 0x5b || 0x5d <= c <= 0x7e
                # qtext; Go also accepts a space here (RFC 3696 examples use one)
                push!(local_part, c)
            else
                return nothing
            end
        end
    else
        while i <= n
            c = bytes[i]
            if c == UInt8('\\')
                # Go accepts an escaped character outside quotes (RFC 3696 examples).
                i += 1
                i > n && return nothing
                push!(local_part, bytes[i])
                i += 1
            elseif _tls_mailbox_atext(c)
                push!(local_part, c)
                i += 1
            else
                break
            end
        end
        isempty(local_part) && return nothing
        # RFC 3696 section 3: no leading, trailing, or consecutive periods.
        (local_part[1] == UInt8('.') || local_part[end] == UInt8('.')) && return nothing
        for j in 2:length(local_part)
            local_part[j] == UInt8('.') && local_part[j - 1] == UInt8('.') && return nothing
        end
    end
    @inbounds (i > n || bytes[i] != UInt8('@')) && return nothing
    domain = String(bytes[(i + 1):n])
    _tls_name_constraint_domain_valid(domain, false) || return nothing
    _tls_findfirst_ascii_byte(domain, UInt8('@')) === nothing || return nothing
    return _TLSParsedMailbox(String(local_part), _tls_ascii_lowercase(domain))
end

# The lowercased host of a URI SAN for constraint matching, or `nothing` when Go
# refuses to match it: no "//" authority, an empty host, an IP literal, any
# bracketed host, or a percent-escaped host ("Exa%6Dple.com" is example.com).
function _tls_parse_uri_host_domain(uri::AbstractString)::Union{Nothing, String}
    text = String(uri)
    n = ncodeunits(text)
    scheme_end = _tls_findfirst_ascii_byte(text, UInt8(':'))
    scheme_end === nothing && return nothing
    authority_start = scheme_end + 1
    authority_start + 1 <= n || return nothing
    (codeunit(text, authority_start) == UInt8('/') && codeunit(text, authority_start + 1) == UInt8('/')) || return nothing
    authority_start += 2
    authority_end = n
    for idx in authority_start:n
        b = codeunit(text, idx)
        if b == UInt8('/') || b == UInt8('?') || b == UInt8('#')
            authority_end = idx - 1
            break
        end
    end
    authority_end >= authority_start || return nothing
    authority = _tls_byte_slice(text, authority_start, authority_end)
    userinfo_end = _tls_findlast_ascii_byte(authority, UInt8('@'))
    hostport = userinfo_end === nothing ? authority : _tls_byte_slice(authority, userinfo_end + 1, ncodeunits(authority))
    isempty(hostport) && return nothing
    codeunit(hostport, 1) == UInt8('[') && return nothing
    colon = _tls_findlast_ascii_byte(hostport, UInt8(':'))
    host = colon === nothing ? hostport : _tls_byte_slice(hostport, 1, colon - 1)
    isempty(host) && return nothing
    _tls_findfirst_ascii_byte(host, UInt8('%')) === nothing || return nothing
    _tls_findfirst_ascii_byte(host, UInt8(':')) === nothing || return nothing
    _is_ip_literal_name(host) && return nothing
    _tls_name_constraint_domain_valid(host, false) || return nothing
    return _tls_ascii_lowercase(host)
end

# A constraint containing '@' names one mailbox (exact local part, case-insensitive
# domain); any other constraint is a domain subtree for the mailbox's domain.
function _tls_email_constraint_matches(constraint::AbstractString, mailbox::_TLSParsedMailbox, excluded::Bool)::Bool
    if _tls_findfirst_ascii_byte(String(constraint), UInt8('@')) !== nothing
        parsed = _tls_parse_rfc2821_mailbox(constraint)
        return parsed !== nothing && parsed.local_part == mailbox.local_part && parsed.domain == mailbox.domain
    end
    _tls_dns_constraint_matches(constraint, mailbox.domain) && return true
    return excluded && _tls_dns_wildcard_excluded(constraint, mailbox.domain)
end

@inline function _tls_chain_extended_key_usage_permitted(chain::Vector{_TLSCertificateInfo}, purpose::AbstractString)::Bool
    required_usage = _tls_verify_purpose_usage_mask(purpose)
    for cert in chain
        cert.has_extended_key_usage || continue
        (cert.extended_key_usage & _TLS_EXT_KEY_USAGE_ANY) != 0x00 && continue
        (cert.extended_key_usage & required_usage) != 0x00 || return false
    end
    return true
end

function _tls_verify_certificate_name_constraints!(
    cert::_TLSCertificateInfo,
    issuer::_TLSCertificateInfo,
)::Nothing
    if cert.has_unhandled_san_names && _tls_certificate_has_permitted_name_constraints(issuer)
        _tls_fail(
            _TLS_ALERT_BAD_CERTIFICATE,
            "tls: certificate chain contains unsupported subjectAltName forms under a constrained issuer",
        )
    end
    for ip in cert.ip_addresses
        if !isempty(issuer.permitted_ip_ranges)
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
        for constraint in issuer.excluded_ip_ranges
            _tls_ip_range_matches(constraint, ip) || continue
            _tls_fail(
                _TLS_ALERT_BAD_CERTIFICATE,
                "tls: certificate chain violates excluded IP name constraint for $(_tls_constraint_ip_string(ip))",
            )
        end
    end
    for dns_name in cert.dns_names
        _tls_name_constraint_domain_valid(dns_name, false) ||
            _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: cannot apply DNS name constraints to $(repr(dns_name))")
        _tls_domain_permitted(issuer.permitted_dns_domains, dns_name) || _tls_fail(
            _TLS_ALERT_BAD_CERTIFICATE,
            "tls: certificate chain violates DNS name constraints for $(repr(dns_name))",
        )
        _tls_domain_excluded(issuer.excluded_dns_domains, dns_name) && _tls_fail(
            _TLS_ALERT_BAD_CERTIFICATE,
            "tls: certificate chain violates excluded DNS name constraint for $(repr(dns_name))",
        )
    end
    for uri_name in cert.uri_names
        uri_domain = _tls_parse_uri_host_domain(uri_name)
        uri_domain === nothing &&
            _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: cannot apply URI name constraints to $(repr(uri_name))")
        _tls_domain_permitted(issuer.permitted_uri_domains, uri_domain::String) || _tls_fail(
            _TLS_ALERT_BAD_CERTIFICATE,
            "tls: certificate chain violates URI name constraints for $(repr(uri_name))",
        )
        _tls_domain_excluded(issuer.excluded_uri_domains, uri_domain::String) && _tls_fail(
            _TLS_ALERT_BAD_CERTIFICATE,
            "tls: certificate chain violates excluded URI name constraint for $(repr(uri_name))",
        )
    end
    for email in cert.email_addresses
        mailbox = _tls_parse_rfc2821_mailbox(email)
        mailbox === nothing &&
            _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: cannot apply email name constraints to $(repr(email))")
        if !isempty(issuer.permitted_email_addresses)
            permitted = false
            for constraint in issuer.permitted_email_addresses
                if _tls_email_constraint_matches(constraint, mailbox::_TLSParsedMailbox, false)
                    permitted = true
                    break
                end
            end
            permitted || _tls_fail(
                _TLS_ALERT_BAD_CERTIFICATE,
                "tls: certificate chain violates email name constraints for $(repr(email))",
            )
        end
        for constraint in issuer.excluded_email_addresses
            _tls_email_constraint_matches(constraint, mailbox::_TLSParsedMailbox, true) || continue
            _tls_fail(
                _TLS_ALERT_BAD_CERTIFICATE,
                "tls: certificate chain violates excluded email name constraint for $(repr(email))",
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

# A complete chain must also satisfy nested EKUs and every issuer's name
# constraints. Throws `_TLSAlertError` for the first violation.
function _tls_verify_chain_policy!(chain::Vector{_TLSCertificateInfo}, purpose::AbstractString)::Nothing
    _tls_chain_extended_key_usage_permitted(chain, purpose) ||
        _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, purpose == "ssl_server" ?
            "tls: certificate chain is not authorized for server authentication" :
            "tls: certificate chain is not authorized for client authentication")
    _tls_verify_chain_name_constraints!(chain)
    return nothing
end

function _tls_chain_policy_ok!(
    chain::Vector{_TLSCertificateInfo},
    purpose::AbstractString,
    policy_error::Base.RefValue{Union{Nothing, _TLSAlertError}},
)::Bool
    try
        _tls_verify_chain_policy!(chain, purpose)
        return true
    catch err
        err isa _TLSAlertError || rethrow()
        policy_error[] === nothing && (policy_error[] = err::_TLSAlertError)
        return false
    end
end

# Depth-first search from `child` to a trust anchor. A path that reaches an
# anchor but fails the chain policy does not end the search: another path, for
# example through a cross-signed intermediate, may satisfy it (Go keeps every
# candidate chain that passes). `policy_error` keeps the first policy failure.
function _tls_build_chain_to_trust_anchor!(
    child::_TLSCertificateInfo,
    intermediates::Vector{_TLSCertificateInfo},
    store::_TLSTrustStore,
    chain::Vector{_TLSCertificateInfo},
    now_s::Int64,
    remaining_candidates::Base.RefValue{Int},
    purpose::AbstractString,
    policy_error::Base.RefValue{Union{Nothing, _TLSAlertError}},
)::Union{Nothing, Vector{_TLSCertificateInfo}}
    length(chain) > _TLS_MAX_CHAIN_DEPTH && return nothing
    # A pathLenConstraint limits the intermediates below the issuer; the leaf is
    # never one of them, even when it is a CA certificate (RFC 5280 4.2.1.9).
    intermediates_below = length(chain) - 1
    for root in store.roots
        _tls_cert_subject_matches_issuer(child, root) || continue
        _tls_certificate_distrusted(root) && continue
        remaining_candidates[] -= 1
        remaining_candidates[] >= 0 || return nothing
        _tls_issuer_can_sign(root) || continue
        _tls_certificate_valid_now(root, now_s) || continue
        (root.max_path_len < 0 || intermediates_below <= root.max_path_len) || continue
        _tls_verify_certificate_signature(child, root) || continue
        verified_chain = copy(chain)
        push!(verified_chain, root)
        _tls_chain_policy_ok!(verified_chain, purpose, policy_error) && return verified_chain
    end
    for (i, parent) in pairs(intermediates)
        _tls_cert_subject_matches_issuer(child, parent) || continue
        _tls_certificate_distrusted(parent) && continue
        remaining_candidates[] -= 1
        remaining_candidates[] >= 0 || return nothing
        _tls_issuer_can_sign(parent) || continue
        _tls_certificate_valid_now(parent, now_s) || continue
        (parent.max_path_len < 0 || intermediates_below <= parent.max_path_len) || continue
        _tls_verify_certificate_signature(child, parent) || continue
        next_chain = copy(chain)
        push!(next_chain, parent)
        remaining = copy(intermediates)
        deleteat!(remaining, i)
        verified_chain = _tls_build_chain_to_trust_anchor!(
            parent, remaining, store, next_chain, now_s, remaining_candidates, purpose, policy_error,
        )
        verified_chain === nothing || return verified_chain
    end
    return nothing
end

# Trim-safe parse-error detail: surface the X.509 parser's `ArgumentError` message
# directly (it carries a descriptive String) instead of `sprint(showerror, ex)`, whose
# dynamic dispatch over `Exception`/IO defeats `--trim` static analysis. Falls back to a
# static label for any other exception type.
function _tls_parse_error_detail(ex)::String
    if ex isa ArgumentError
        msg = ex.msg
        msg isa String && return msg
    end
    return "unparseable DER"
end

function _tls_verify_peer_certificate_chain!(
    certificates::Vector{Vector{UInt8}},
    store::_TLSTrustStore,
    purpose::AbstractString,
    now_s::Int64 = Int64(floor(time())),
)::_TLSCertificateInfo
    isempty(certificates) && _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: received empty certificates message")
    parsed = _TLSCertificateInfo[]
    try
        for cert_der in certificates
            push!(parsed, _tls_parse_der_certificate_info(cert_der))
        end
    catch ex
        ex isa _TLSAlertError && rethrow()
        _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: malformed X.509 certificate ($(_tls_parse_error_detail(ex)))")
    end
    leaf = parsed[1]
    # Check before the direct-trust shortcut as well as normal path building.
    # Custom CA files/directories must not restore trust in a compromised key.
    _tls_certificate_distrusted(leaf) &&
        _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: certificate uses a distrusted public key")
    _tls_certificate_valid_now(leaf, now_s) ||
        _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: $(_tls_certificate_current_time_message(leaf))")
    _tls_certificate_usage_permitted(leaf, purpose) ||
        _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, purpose == "ssl_server" ?
            "tls: certificate is not authorized for server authentication" :
            "tls: certificate is not authorized for client authentication")
    if _tls_trust_anchor_matches(leaf, store)
        _tls_verify_chain_policy!(_TLSCertificateInfo[leaf], purpose)
        return leaf
    end
    intermediates = length(parsed) > 1 ? parsed[2:end] : _TLSCertificateInfo[]
    remaining_candidates = Ref(_TLS_MAX_CHAIN_CANDIDATES)
    policy_error = Ref{Union{Nothing, _TLSAlertError}}(nothing)
    chain = _tls_build_chain_to_trust_anchor!(
        leaf, intermediates, store, _TLSCertificateInfo[leaf], now_s, remaining_candidates, purpose, policy_error,
    )
    if chain === nothing
        failure = policy_error[]
        failure === nothing || throw(failure::_TLSAlertError)
        _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: certificate signed by unknown authority")
    end
    return leaf
end

# This is the native cert-auth entry point used by TLS 1.2 and TLS 1.3
# handshakes: optionally build to a trust anchor, optionally check hostname/IP,
# then return the parsed leaf public key for later TLS-level signature checks.
# Resolve the optional directory before dispatching with the other optional
# config fields so the verifier remains statically callable under --trim=safe.
@inline function _tls_verify_certificate_chain(
    certificates::Vector{Vector{UInt8}};
    verify_peer::Bool,
    verify_hostname::Bool,
    ca_file::Union{Nothing, String},
    ca_dir::Union{Nothing, String} = nothing,
    verification_time_s::Union{Nothing, Int64} = nothing,
    purpose::AbstractString,
    peer_name::AbstractString = "",
)::_TLSPublicKey
    if ca_dir === nothing
        return _tls_verify_certificate_chain(
            certificates, verify_peer, verify_hostname, ca_file, nothing,
            verification_time_s, purpose, peer_name,
        )
    end
    return _tls_verify_certificate_chain(
        certificates, verify_peer, verify_hostname, ca_file, ca_dir::String,
        verification_time_s, purpose, peer_name,
    )
end

function _tls_verify_certificate_chain(
    certificates::Vector{Vector{UInt8}},
    verify_peer::Bool,
    verify_hostname::Bool,
    ca_file::Union{Nothing, String},
    ca_dir::Union{Nothing, String},
    verification_time_s::Union{Nothing, Int64},
    purpose::AbstractString,
    peer_name::AbstractString,
)::_TLSPublicKey
    isempty(certificates) && _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: received empty certificates message")
    leaf = if verify_peer
        ca_file === nothing && ca_dir === nothing && _tls_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: certificate verification requires a CA roots path")
        store = try
            _tls_load_trust_store(ca_file, ca_dir)
        catch ex
            ex isa _TLSAlertError && rethrow()
            _tls_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: failed to load CA roots")
        end
        _tls_verify_peer_certificate_chain!(
            certificates, store, purpose,
            verification_time_s === nothing ? Int64(floor(time())) : verification_time_s,
        )
    else
        try
            _tls_parse_der_certificate_info(certificates[1])
        catch ex
            ex isa _TLSAlertError && rethrow()
            _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: malformed X.509 certificate ($(_tls_parse_error_detail(ex)))")
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
        _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: malformed X.509 certificate ($(_tls_parse_error_detail(ex)))")
    end
    _tls_verify_certificate_peer_name!(cert_info, peer_name)
    return nothing
end

function _tls13_check_x509_peer_name!(x509::Ptr{Cvoid}, peer_name::AbstractString)::Nothing
    return _tls13_check_x509_peer_name!(_tls13_x509_to_der(x509), peer_name)
end

@inline function _tls13_verify_certificate_chain(
    certificates::Vector{Vector{UInt8}};
    verify_peer::Bool,
    verify_hostname::Bool,
    ca_file::Union{Nothing, String},
    ca_dir::Union{Nothing, String} = nothing,
    verification_time_s::Union{Nothing, Int64} = nothing,
    purpose::AbstractString,
    peer_name::AbstractString = "",
)::_TLSPublicKey
    return _tls_verify_certificate_chain(
        certificates;
        verify_peer,
        verify_hostname,
        ca_file,
        ca_dir,
        verification_time_s,
        purpose,
        peer_name,
    )
end

@inline function _tls13_verify_server_certificate_chain(
    certificates::Vector{Vector{UInt8}},
    server_name::AbstractString;
    verify_peer::Bool,
    verify_hostname::Bool,
    ca_file::Union{Nothing, String},
    ca_dir::Union{Nothing, String} = nothing,
    verification_time_s::Union{Nothing, Int64} = nothing,
)::_TLSPublicKey
    return _tls13_verify_certificate_chain(
        certificates;
        verify_peer,
        verify_hostname,
        ca_file,
        ca_dir,
        verification_time_s,
        purpose = "ssl_server",
        peer_name = server_name,
    )
end

@inline function _tls13_verify_client_certificate_chain(
    certificates::Vector{Vector{UInt8}};
    verify_peer::Bool,
    ca_file::Union{Nothing, String},
    ca_dir::Union{Nothing, String} = nothing,
    verification_time_s::Union{Nothing, Int64} = nothing,
)::_TLSPublicKey
    return _tls13_verify_certificate_chain(
        certificates;
        verify_peer,
        verify_hostname = false,
        ca_file,
        ca_dir,
        verification_time_s,
        purpose = "ssl_client",
    )
end
