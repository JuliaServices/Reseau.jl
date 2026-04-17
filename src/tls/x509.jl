struct _TLSCertificateInfo
    common_name::String
    dns_names::Vector{String}
    ip_addresses::Vector{Vector{UInt8}}
    has_san_extension::Bool
end

const _ASN1_SEQUENCE = UInt8(0x30)
const _ASN1_SET = UInt8(0x31)
const _ASN1_BOOLEAN = UInt8(0x01)
const _ASN1_OCTET_STRING = UInt8(0x04)
const _ASN1_OBJECT_IDENTIFIER = UInt8(0x06)
const _ASN1_UTF8_STRING = UInt8(0x0c)
const _ASN1_PRINTABLE_STRING = UInt8(0x13)
const _ASN1_T61_STRING = UInt8(0x14)
const _ASN1_IA5_STRING = UInt8(0x16)
const _ASN1_UNIVERSAL_STRING = UInt8(0x1c)
const _ASN1_BMP_STRING = UInt8(0x1e)
const _ASN1_CONTEXT_EXPLICIT_VERSION = UInt8(0xa0)
const _ASN1_CONTEXT_EXPLICIT_EXTENSIONS = UInt8(0xa3)
const _ASN1_GENERAL_NAME_DNS = UInt8(0x82)
const _ASN1_GENERAL_NAME_IP = UInt8(0x87)
const _ASN1_OID_COMMON_NAME = (UInt8(0x55), UInt8(0x04), UInt8(0x03))
const _ASN1_OID_SUBJECT_ALT_NAME = (UInt8(0x55), UInt8(0x1d), UInt8(0x11))

@inline function _asn1_range_length(start::Int, stop::Int)::Int
    return stop >= start ? (stop - start + 1) : 0
end

function _asn1_read_length(bytes::AbstractVector{UInt8}, pos::Int)::Tuple{Int, Int}
    pos <= length(bytes) || throw(ArgumentError("tls: truncated DER length"))
    first = bytes[pos]
    pos += 1
    if first < 0x80
        return Int(first), pos
    end
    count = Int(first & 0x7f)
    count > 0 || throw(ArgumentError("tls: indefinite DER lengths are not supported"))
    count <= sizeof(Int) || throw(ArgumentError("tls: oversized DER length"))
    pos + count - 1 <= length(bytes) || throw(ArgumentError("tls: truncated DER length"))
    len = 0
    @inbounds for _ in 1:count
        len <= (typemax(Int) >> 8) || throw(ArgumentError("tls: oversized DER length"))
        len = (len << 8) | Int(bytes[pos])
        pos += 1
    end
    return len, pos
end

function _asn1_read_tlv(bytes::AbstractVector{UInt8}, pos::Int)::NTuple{4, Int}
    pos <= length(bytes) || throw(ArgumentError("tls: truncated DER value"))
    tag = bytes[pos]
    (tag & 0x1f) == 0x1f && throw(ArgumentError("tls: high-tag-number DER values are not supported"))
    pos += 1
    len, value_start = _asn1_read_length(bytes, pos)
    available = length(bytes) - value_start + 1
    len <= available || throw(ArgumentError("tls: truncated DER value"))
    value_end = value_start + len - 1
    return Int(tag), value_start, value_end, value_end + 1
end

function _asn1_expect_tlv(bytes::AbstractVector{UInt8}, pos::Int, expected_tag::UInt8)::NTuple{3, Int}
    tag, value_start, value_end, next_pos = _asn1_read_tlv(bytes, pos)
    tag == expected_tag || throw(ArgumentError("tls: unexpected DER tag $(tag), expected $(expected_tag)"))
    return value_start, value_end, next_pos
end

@inline function _asn1_oid_equals(
    bytes::AbstractVector{UInt8},
    value_start::Int,
    value_end::Int,
    oid::NTuple{N, UInt8},
)::Bool where {N}
    _asn1_range_length(value_start, value_end) == N || return false
    @inbounds for i in 1:N
        bytes[value_start + i - 1] == oid[i] || return false
    end
    return true
end

@inline function _asn1_ascii_string(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::String
    return String(copy(@view bytes[value_start:value_end]))
end

function _asn1_bmp_string(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::String
    len = _asn1_range_length(value_start, value_end)
    iseven(len) || throw(ArgumentError("tls: malformed BMPString value"))
    chars = Char[]
    pos = value_start
    @inbounds while pos <= value_end
        codepoint = (UInt32(bytes[pos]) << 8) | UInt32(bytes[pos + 1])
        push!(chars, Char(codepoint))
        pos += 2
    end
    return String(chars)
end

function _asn1_universal_string(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::String
    len = _asn1_range_length(value_start, value_end)
    len % 4 == 0 || throw(ArgumentError("tls: malformed UniversalString value"))
    chars = Char[]
    pos = value_start
    @inbounds while pos <= value_end
        codepoint = (UInt32(bytes[pos]) << 24) |
                    (UInt32(bytes[pos + 1]) << 16) |
                    (UInt32(bytes[pos + 2]) << 8) |
                    UInt32(bytes[pos + 3])
        push!(chars, Char(codepoint))
        pos += 4
    end
    return String(chars)
end

function _asn1_directory_string(bytes::AbstractVector{UInt8}, tag::UInt8, value_start::Int, value_end::Int)::String
    if tag == _ASN1_UTF8_STRING ||
       tag == _ASN1_PRINTABLE_STRING ||
       tag == _ASN1_T61_STRING ||
       tag == _ASN1_IA5_STRING
        return _asn1_ascii_string(bytes, value_start, value_end)
    elseif tag == _ASN1_BMP_STRING
        return _asn1_bmp_string(bytes, value_start, value_end)
    elseif tag == _ASN1_UNIVERSAL_STRING
        return _asn1_universal_string(bytes, value_start, value_end)
    end
    throw(ArgumentError("tls: unsupported X.509 directory string tag $(tag)"))
end

function _tls_decode_pem_certificates(pem_bytes::AbstractVector{UInt8})::Vector{Vector{UInt8}}
    pem_text = String(copy(pem_bytes))
    certificates = Vector{Vector{UInt8}}()
    for matched in eachmatch(r"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----"s, pem_text)
        body = replace(String(matched.captures[1]), "\r" => "")
        encoded = IOBuffer()
        for line in split(body, '\n')
            stripped = strip(line)
            isempty(stripped) && continue
            occursin(':', stripped) && continue
            print(encoded, stripped)
        end
        encoded = String(take!(encoded))
        isempty(encoded) && continue
        push!(certificates, _tls_pem_base64_decode(encoded))
    end
    isempty(certificates) && throw(ArgumentError("tls: certificate file does not contain any PEM certificate blocks"))
    return certificates
end

@inline function _tls_pem_base64_value(byte::UInt8)::Int
    if byte >= UInt8('A') && byte <= UInt8('Z')
        return Int(byte - UInt8('A'))
    elseif byte >= UInt8('a') && byte <= UInt8('z')
        return Int(byte - UInt8('a')) + 26
    elseif byte >= UInt8('0') && byte <= UInt8('9')
        return Int(byte - UInt8('0')) + 52
    elseif byte == UInt8('+')
        return 62
    elseif byte == UInt8('/')
        return 63
    elseif byte == UInt8('=')
        return -2
    end
    return -1
end

function _tls_pem_base64_decode(encoded::AbstractString)::Vector{UInt8}
    encoded_bytes = codeunits(String(encoded))
    isempty(encoded_bytes) && return UInt8[]
    length(encoded_bytes) % 4 == 0 || throw(ArgumentError("tls: malformed PEM base64 payload"))
    out = Vector{UInt8}(undef, div(length(encoded_bytes), 4) * 3)
    out_len = 0
    pos = firstindex(encoded_bytes)
    last = lastindex(encoded_bytes)
    while pos <= last
        a = _tls_pem_base64_value(encoded_bytes[pos]); pos = nextind(encoded_bytes, pos)
        b = _tls_pem_base64_value(encoded_bytes[pos]); pos = nextind(encoded_bytes, pos)
        c = _tls_pem_base64_value(encoded_bytes[pos]); pos = nextind(encoded_bytes, pos)
        d = _tls_pem_base64_value(encoded_bytes[pos]); pos = nextind(encoded_bytes, pos)
        (a >= 0 && b >= 0) || throw(ArgumentError("tls: malformed PEM base64 payload"))
        if c == -2
            d == -2 || throw(ArgumentError("tls: malformed PEM base64 padding"))
            out_len += 1
            @inbounds out[out_len] = UInt8((a << 2) | (b >> 4))
            pos > last || throw(ArgumentError("tls: malformed PEM base64 padding"))
            break
        end
        c >= 0 || throw(ArgumentError("tls: malformed PEM base64 payload"))
        if d == -2
            out_len += 1
            @inbounds out[out_len] = UInt8((a << 2) | (b >> 4))
            out_len += 1
            @inbounds out[out_len] = UInt8(((b & 0x0f) << 4) | (c >> 2))
            pos > last || throw(ArgumentError("tls: malformed PEM base64 padding"))
            break
        end
        d >= 0 || throw(ArgumentError("tls: malformed PEM base64 payload"))
        out_len += 1
        @inbounds out[out_len] = UInt8((a << 2) | (b >> 4))
        out_len += 1
        @inbounds out[out_len] = UInt8(((b & 0x0f) << 4) | (c >> 2))
        out_len += 1
        @inbounds out[out_len] = UInt8(((c & 0x03) << 6) | d)
    end
    resize!(out, out_len)
    return out
end

function _tls_parse_general_names(
    bytes::AbstractVector{UInt8},
    value_start::Int,
    value_end::Int,
)::Tuple{Vector{String}, Vector{Vector{UInt8}}}
    seq_start, seq_end, seq_next = _asn1_expect_tlv(bytes, value_start, _ASN1_SEQUENCE)
    seq_next == value_end + 1 || throw(ArgumentError("tls: malformed subjectAltName extension"))
    dns_names = String[]
    ip_addresses = Vector{Vector{UInt8}}()
    pos = seq_start
    while pos <= seq_end
        tag, name_start, name_end, pos = _asn1_read_tlv(bytes, pos)
        if tag == _ASN1_GENERAL_NAME_DNS
            push!(dns_names, _asn1_ascii_string(bytes, name_start, name_end))
        elseif tag == _ASN1_GENERAL_NAME_IP
            push!(ip_addresses, copy(@view bytes[name_start:name_end]))
        end
    end
    return dns_names, ip_addresses
end

function _tls_parse_subject_common_name(
    bytes::AbstractVector{UInt8},
    value_start::Int,
    value_end::Int,
)::String
    common_name = ""
    pos = value_start
    while pos <= value_end
        set_start, set_end, pos = _asn1_expect_tlv(bytes, pos, _ASN1_SET)
        set_pos = set_start
        while set_pos <= set_end
            attr_start, attr_end, set_pos = _asn1_expect_tlv(bytes, set_pos, _ASN1_SEQUENCE)
            oid_start, oid_end, attr_pos = _asn1_expect_tlv(bytes, attr_start, _ASN1_OBJECT_IDENTIFIER)
            tag, str_start, str_end, attr_pos = _asn1_read_tlv(bytes, attr_pos)
            attr_pos == attr_end + 1 || throw(ArgumentError("tls: malformed subject name attribute"))
            if _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_COMMON_NAME)
                common_name = _asn1_directory_string(bytes, UInt8(tag), str_start, str_end)
            end
        end
    end
    return common_name
end

function _tls_parse_der_certificate_info(cert_der::AbstractVector{UInt8})::_TLSCertificateInfo
    cert_start, cert_end, cert_next = _asn1_expect_tlv(cert_der, firstindex(cert_der), _ASN1_SEQUENCE)
    cert_next == lastindex(cert_der) + 1 || throw(ArgumentError("tls: malformed certificate container"))
    tbs_start, tbs_end, _ = _asn1_expect_tlv(cert_der, cert_start, _ASN1_SEQUENCE)
    tbs_pos = tbs_start
    if tbs_pos <= tbs_end && cert_der[tbs_pos] == _ASN1_CONTEXT_EXPLICIT_VERSION
        _, _, tbs_pos = _asn1_expect_tlv(cert_der, tbs_pos, _ASN1_CONTEXT_EXPLICIT_VERSION)
    end
    _, _, _, tbs_pos = _asn1_read_tlv(cert_der, tbs_pos) # serial number
    _, _, _, tbs_pos = _asn1_read_tlv(cert_der, tbs_pos) # signature
    _, _, _, tbs_pos = _asn1_read_tlv(cert_der, tbs_pos) # issuer
    _, _, _, tbs_pos = _asn1_read_tlv(cert_der, tbs_pos) # validity
    subject_start, subject_end, tbs_pos = _asn1_expect_tlv(cert_der, tbs_pos, _ASN1_SEQUENCE)
    common_name = _tls_parse_subject_common_name(cert_der, subject_start, subject_end)
    _, _, _, tbs_pos = _asn1_read_tlv(cert_der, tbs_pos) # subjectPublicKeyInfo
    dns_names = String[]
    ip_addresses = Vector{Vector{UInt8}}()
    has_san_extension = false
    while tbs_pos <= tbs_end
        tag, field_start, field_end, tbs_pos = _asn1_read_tlv(cert_der, tbs_pos)
        if tag == _ASN1_CONTEXT_EXPLICIT_EXTENSIONS
            exts_start, exts_end, exts_next = _asn1_expect_tlv(cert_der, field_start, _ASN1_SEQUENCE)
            exts_next == field_end + 1 || throw(ArgumentError("tls: malformed certificate extensions"))
            ext_pos = exts_start
            while ext_pos <= exts_end
                ext_start, ext_end, ext_pos = _asn1_expect_tlv(cert_der, ext_pos, _ASN1_SEQUENCE)
                oid_start, oid_end, value_pos = _asn1_expect_tlv(cert_der, ext_start, _ASN1_OBJECT_IDENTIFIER)
                if value_pos <= ext_end && cert_der[value_pos] == _ASN1_BOOLEAN
                    _, _, value_pos = _asn1_expect_tlv(cert_der, value_pos, _ASN1_BOOLEAN)
                end
                octet_start, octet_end, value_pos = _asn1_expect_tlv(cert_der, value_pos, _ASN1_OCTET_STRING)
                value_pos == ext_end + 1 || throw(ArgumentError("tls: malformed certificate extension value"))
                if _asn1_oid_equals(cert_der, oid_start, oid_end, _ASN1_OID_SUBJECT_ALT_NAME)
                    has_san_extension = true
                    dns_names, ip_addresses = _tls_parse_general_names(cert_der, octet_start, octet_end)
                end
            end
        end
    end
    return _TLSCertificateInfo(common_name, dns_names, ip_addresses, has_san_extension)
end

@inline function _tls_ascii_lowercase(name::AbstractString)::String
    value = String(name)
    bytes = codeunits(value)
    needs_copy = false
    @inbounds for byte in bytes
        if byte >= UInt8('A') && byte <= UInt8('Z')
            needs_copy = true
            break
        end
    end
    needs_copy || return value
    out = Vector{UInt8}(bytes)
    @inbounds for i in eachindex(out)
        byte = out[i]
        if byte >= UInt8('A') && byte <= UInt8('Z')
            out[i] = byte + UInt8(0x20)
        end
    end
    return String(out)
end

@inline _tls_normalized_hostname(host::AbstractString)::String = _tls_ascii_lowercase(_normalize_peer_name(host))
@inline _tls_normalized_hostname_pattern(host::AbstractString)::String = _tls_ascii_lowercase(host)

function _tls_valid_hostname_value(value::AbstractString, is_pattern::Bool)::Bool
    isempty(value) && return false
    value == "*" && return false
    parts = split(value, '.')
    isempty(parts) && return false
    for (i, part) in pairs(parts)
        isempty(part) && return false
        if is_pattern && i == 1 && part == "*"
            continue
        end
        first_idx = firstindex(part)
        for idx in eachindex(part)
            c = part[idx]
            if ('a' <= c <= 'z') || ('A' <= c <= 'Z') || ('0' <= c <= '9')
                continue
            end
            if c == '-' && idx != first_idx
                continue
            end
            c == '_' && continue
            return false
        end
    end
    return true
end

@inline function _tls_valid_hostname(host::AbstractString, is_pattern::Bool)::Bool
    value = is_pattern ? _tls_normalized_hostname_pattern(host) : _tls_normalized_hostname(host)
    return _tls_valid_hostname_value(value, is_pattern)
end

@inline _tls_valid_hostname_input(host::AbstractString)::Bool = _tls_valid_hostname(host, false)
@inline _tls_valid_hostname_pattern(host::AbstractString)::Bool = _tls_valid_hostname(host, true)

@inline function _tls_match_exactly_normalized(a::AbstractString, b::AbstractString)::Bool
    (isempty(a) || a == "." || isempty(b) || b == ".") && return false
    return a == b
end

@inline function _tls_match_exactly(host_a::AbstractString, host_b::AbstractString)::Bool
    return _tls_match_exactly_normalized(_tls_ascii_lowercase(host_a), _tls_ascii_lowercase(host_b))
end

function _tls_match_hostnames_normalized(pattern::AbstractString, host::AbstractString)::Bool
    (isempty(pattern) || isempty(host)) && return false
    pattern_parts = split(pattern, '.')
    host_parts = split(host, '.')
    length(pattern_parts) == length(host_parts) || return false
    for i in eachindex(pattern_parts, host_parts)
        (i == firstindex(pattern_parts) && pattern_parts[i] == "*") && continue
        pattern_parts[i] == host_parts[i] || return false
    end
    return true
end

function _tls_match_hostnames(pattern::AbstractString, host::AbstractString)::Bool
    return _tls_match_hostnames_normalized(_tls_normalized_hostname_pattern(pattern), _tls_normalized_hostname(host))
end

function _tls_literal_host_bytes(host::AbstractString)::Vector{UInt8}
    literal = HostResolvers._literal_host_addr(host)
    literal === nothing && throw(ArgumentError("tls: expected an IP literal host"))
    if literal isa TCP.SocketAddrV4
        return collect((literal::TCP.SocketAddrV4).ip)
    end
    return collect((literal::TCP.SocketAddrV6).ip)
end

@inline function _tls_is_ipv4_mapped(bytes::AbstractVector{UInt8})::Bool
    length(bytes) == 16 || return false
    @inbounds for i in 1:10
        bytes[i] == 0x00 || return false
    end
    return bytes[11] == 0xff && bytes[12] == 0xff
end

@inline function _tls_ip_bytes_equal(a::AbstractVector{UInt8}, b::AbstractVector{UInt8})::Bool
    a == b && return true
    if length(a) == 4 && _tls_is_ipv4_mapped(b)
        @inbounds for i in 1:4
            a[i] == b[i + 12] || return false
        end
        return true
    elseif length(b) == 4 && _tls_is_ipv4_mapped(a)
        @inbounds for i in 1:4
            a[i + 12] == b[i] || return false
        end
        return true
    end
    return false
end

function _tls_certificate_hostname_error(cert::_TLSCertificateInfo, host::AbstractString)::String
    verify_name = _verify_name(host)
    verify_name_lc = _tls_ascii_lowercase(verify_name)
    if !cert.has_san_extension &&
       !isempty(cert.common_name) &&
       _tls_match_hostnames_normalized(_tls_normalized_hostname_pattern(cert.common_name), verify_name_lc)
        return "certificate relies on legacy Common Name field, use SANs instead"
    end
    return "certificate is not valid for host $(verify_name)"
end

function _tls_verify_certificate_peer_name!(cert::_TLSCertificateInfo, peer_name::AbstractString)::Nothing
    normalized = String(peer_name)
    isempty(normalized) && return nothing
    if _is_ip_literal_name(normalized)
        verify_ip = _verify_ip(normalized)
        ip_bytes = _tls_literal_host_bytes(verify_ip)
        for candidate in cert.ip_addresses
            _tls_ip_bytes_equal(candidate, ip_bytes) && return nothing
        end
        _tls13_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: certificate is not valid for IP address $(verify_ip)")
    end
    verify_name = _verify_name(normalized)
    candidate_name = _tls_ascii_lowercase(verify_name)
    valid_candidate_name = _tls_valid_hostname_value(candidate_name, false)
    for match in cert.dns_names
        match_name = _tls_ascii_lowercase(match)
        if valid_candidate_name && _tls_valid_hostname_value(match_name, true)
            _tls_match_hostnames_normalized(match_name, candidate_name) && return nothing
        else
            _tls_match_exactly_normalized(match_name, candidate_name) && return nothing
        end
    end
    _tls13_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: $(_tls_certificate_hostname_error(cert, verify_name))")
end
