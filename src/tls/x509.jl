struct _TLSCertificateInfo
    der::Vector{UInt8}
    subject_raw::Vector{UInt8}
    issuer_raw::Vector{UInt8}
    common_name::String
    dns_names::Vector{String}
    ip_addresses::Vector{Vector{UInt8}}
    has_san_extension::Bool
    not_before_s::Int64
    not_after_s::Int64
    is_ca::Bool
    max_path_len::Int
    has_key_usage::Bool
    key_usage::UInt16
    extended_key_usage::UInt8
    subject_key_id::Vector{UInt8}
    authority_key_id::Vector{UInt8}
end

const _ASN1_INTEGER = UInt8(0x02)
const _ASN1_BIT_STRING = UInt8(0x03)
const _ASN1_SEQUENCE = UInt8(0x30)
const _ASN1_SET = UInt8(0x31)
const _ASN1_BOOLEAN = UInt8(0x01)
const _ASN1_OCTET_STRING = UInt8(0x04)
const _ASN1_OBJECT_IDENTIFIER = UInt8(0x06)
const _ASN1_UTC_TIME = UInt8(0x17)
const _ASN1_GENERALIZED_TIME = UInt8(0x18)
const _ASN1_UTF8_STRING = UInt8(0x0c)
const _ASN1_PRINTABLE_STRING = UInt8(0x13)
const _ASN1_T61_STRING = UInt8(0x14)
const _ASN1_IA5_STRING = UInt8(0x16)
const _ASN1_UNIVERSAL_STRING = UInt8(0x1c)
const _ASN1_BMP_STRING = UInt8(0x1e)
const _ASN1_CONTEXT_EXPLICIT_VERSION = UInt8(0xa0)
const _ASN1_CONTEXT_EXPLICIT_EXTENSIONS = UInt8(0xa3)
const _ASN1_CONTEXT_KEY_IDENTIFIER = UInt8(0x80)
const _ASN1_GENERAL_NAME_DNS = UInt8(0x82)
const _ASN1_GENERAL_NAME_IP = UInt8(0x87)
const _ASN1_OID_COMMON_NAME = (UInt8(0x55), UInt8(0x04), UInt8(0x03))
const _ASN1_OID_KEY_USAGE = (UInt8(0x55), UInt8(0x1d), UInt8(0x0f))
const _ASN1_OID_SUBJECT_KEY_IDENTIFIER = (UInt8(0x55), UInt8(0x1d), UInt8(0x0e))
const _ASN1_OID_SUBJECT_ALT_NAME = (UInt8(0x55), UInt8(0x1d), UInt8(0x11))
const _ASN1_OID_BASIC_CONSTRAINTS = (UInt8(0x55), UInt8(0x1d), UInt8(0x13))
const _ASN1_OID_AUTHORITY_KEY_IDENTIFIER = (UInt8(0x55), UInt8(0x1d), UInt8(0x23))
const _ASN1_OID_EXTENDED_KEY_USAGE = (UInt8(0x55), UInt8(0x1d), UInt8(0x25))
const _ASN1_OID_EKU_ANY = (
    UInt8(0x55), UInt8(0x1d), UInt8(0x25), UInt8(0x00),
)
const _ASN1_OID_EKU_SERVER_AUTH = (
    UInt8(0x2b), UInt8(0x06), UInt8(0x01), UInt8(0x05),
    UInt8(0x05), UInt8(0x07), UInt8(0x03), UInt8(0x01),
)
const _ASN1_OID_EKU_CLIENT_AUTH = (
    UInt8(0x2b), UInt8(0x06), UInt8(0x01), UInt8(0x05),
    UInt8(0x05), UInt8(0x07), UInt8(0x03), UInt8(0x02),
)

const _TLS_KEY_USAGE_DIGITAL_SIGNATURE = UInt16(1) << 0
const _TLS_KEY_USAGE_KEY_ENCIPHERMENT = UInt16(1) << 2
const _TLS_KEY_USAGE_KEY_CERT_SIGN = UInt16(1) << 5

const _TLS_EXT_KEY_USAGE_ANY = UInt8(1) << 0
const _TLS_EXT_KEY_USAGE_SERVER = UInt8(1) << 1
const _TLS_EXT_KEY_USAGE_CLIENT = UInt8(1) << 2
const _TLS_PEM_CERTIFICATE_HEADER = UInt8[codeunits("-----BEGIN CERTIFICATE-----")...]
const _TLS_MAX_CHAIN_DEPTH = 8
const _TLS_MAX_CHAIN_CANDIDATES = 128

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

@inline function _asn1_boolean_value(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::Bool
    value_start == value_end || throw(ArgumentError("tls: malformed ASN.1 BOOLEAN value"))
    return bytes[value_start] != 0x00
end

function _asn1_integer_value(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::Int
    value_start <= value_end || throw(ArgumentError("tls: malformed ASN.1 INTEGER value"))
    bytes[value_start] < 0x80 || throw(ArgumentError("tls: negative ASN.1 INTEGER values are not supported"))
    value = 0
    @inbounds for pos in value_start:value_end
        value <= (typemax(Int) >> 8) || throw(ArgumentError("tls: oversized ASN.1 INTEGER value"))
        value = (value << 8) | Int(bytes[pos])
    end
    return value
end

function _asn1_parse_decimal(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::Int
    value_start <= value_end || throw(ArgumentError("tls: malformed ASN.1 time value"))
    value = 0
    @inbounds for pos in value_start:value_end
        digit = Int(bytes[pos]) - Int(UInt8('0'))
        0 <= digit <= 9 || throw(ArgumentError("tls: malformed ASN.1 time value"))
        value = (value * 10) + digit
    end
    return value
end

@inline _tls_is_leap_year(year::Int)::Bool = (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)

function _tls_days_in_month(year::Int, month::Int)::Int
    month == 2 && return _tls_is_leap_year(year) ? 29 : 28
    month in (4, 6, 9, 11) && return 30
    month in 1:12 || throw(ArgumentError("tls: malformed ASN.1 time value"))
    return 31
end

function _tls_days_from_civil(year::Int, month::Int, day::Int)::Int
    1 <= day <= _tls_days_in_month(year, month) || throw(ArgumentError("tls: malformed ASN.1 time value"))
    adjusted_year = year - (month <= 2 ? 1 : 0)
    era = adjusted_year >= 0 ? (adjusted_year ÷ 400) : ((adjusted_year - 399) ÷ 400)
    year_of_era = adjusted_year - (era * 400)
    shifted_month = month + (month > 2 ? -3 : 9)
    day_of_year = ((153 * shifted_month) + 2) ÷ 5 + day - 1
    day_of_era = year_of_era * 365 + (year_of_era ÷ 4) - (year_of_era ÷ 100) + day_of_year
    return era * 146097 + day_of_era - 719468
end

function _tls_unix_time(year::Int, month::Int, day::Int, hour::Int, minute::Int, second::Int)::Int64
    0 <= hour <= 23 || throw(ArgumentError("tls: malformed ASN.1 time value"))
    0 <= minute <= 59 || throw(ArgumentError("tls: malformed ASN.1 time value"))
    0 <= second <= 59 || throw(ArgumentError("tls: malformed ASN.1 time value"))
    days = _tls_days_from_civil(year, month, day)
    return Int64(days) * 86400 + Int64(hour) * 3600 + Int64(minute) * 60 + Int64(second)
end

function _asn1_parse_x509_time(bytes::AbstractVector{UInt8}, tag::UInt8, value_start::Int, value_end::Int)::Int64
    value_len = _asn1_range_length(value_start, value_end)
    value_len > 0 || throw(ArgumentError("tls: malformed ASN.1 time value"))
    bytes[value_end] == UInt8('Z') || throw(ArgumentError("tls: unsupported ASN.1 time zone"))
    if tag == _ASN1_UTC_TIME
        value_len in (11, 13) || throw(ArgumentError("tls: malformed ASN.1 UTCTime value"))
        year = _asn1_parse_decimal(bytes, value_start, value_start + 1)
        year += year >= 50 ? 1900 : 2000
        month = _asn1_parse_decimal(bytes, value_start + 2, value_start + 3)
        day = _asn1_parse_decimal(bytes, value_start + 4, value_start + 5)
        hour = _asn1_parse_decimal(bytes, value_start + 6, value_start + 7)
        minute = _asn1_parse_decimal(bytes, value_start + 8, value_start + 9)
        second = value_len == 13 ? _asn1_parse_decimal(bytes, value_start + 10, value_start + 11) : 0
        return _tls_unix_time(year, month, day, hour, minute, second)
    elseif tag == _ASN1_GENERALIZED_TIME
        value_len in (13, 15) || throw(ArgumentError("tls: malformed ASN.1 GeneralizedTime value"))
        year = _asn1_parse_decimal(bytes, value_start, value_start + 3)
        month = _asn1_parse_decimal(bytes, value_start + 4, value_start + 5)
        day = _asn1_parse_decimal(bytes, value_start + 6, value_start + 7)
        hour = _asn1_parse_decimal(bytes, value_start + 8, value_start + 9)
        minute = _asn1_parse_decimal(bytes, value_start + 10, value_start + 11)
        second = value_len == 15 ? _asn1_parse_decimal(bytes, value_start + 12, value_start + 13) : 0
        return _tls_unix_time(year, month, day, hour, minute, second)
    end
    throw(ArgumentError("tls: unsupported ASN.1 time tag $(tag)"))
end

function _asn1_parse_key_usage_bits(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::UInt16
    len = _asn1_range_length(value_start, value_end)
    len > 0 || throw(ArgumentError("tls: malformed X.509 key usage extension"))
    unused_bits = Int(bytes[value_start])
    0 <= unused_bits <= 7 || throw(ArgumentError("tls: malformed X.509 key usage extension"))
    bit_index = 0
    bits = UInt16(0)
    pos = value_start + 1
    while pos <= value_end
        byte = bytes[pos]
        limit = pos == value_end ? (8 - unused_bits) : 8
        @inbounds for bit_offset in 0:(limit - 1)
            if (byte & (UInt8(0x80) >> bit_offset)) != 0x00
                bits |= UInt16(1) << bit_index
            end
            bit_index += 1
        end
        pos += 1
    end
    return bits
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

function _tls_contains_pem_certificate_header(bytes::AbstractVector{UInt8})::Bool
    header = _TLS_PEM_CERTIFICATE_HEADER
    last_start = length(bytes) - length(header) + 1
    last_start < 1 && return false
    @inbounds for start in 1:last_start
        matches = true
        for i in eachindex(header)
            if bytes[start + i - 1] != header[i]
                matches = false
                break
            end
        end
        matches && return true
    end
    return false
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

function _tls_parse_basic_constraints(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::Tuple{Bool, Int}
    seq_start, seq_end, seq_next = _asn1_expect_tlv(bytes, value_start, _ASN1_SEQUENCE)
    seq_next == value_end + 1 || throw(ArgumentError("tls: malformed basic constraints extension"))
    is_ca = false
    max_path_len = -1
    pos = seq_start
    if pos <= seq_end && bytes[pos] == _ASN1_BOOLEAN
        bool_start, bool_end, pos = _asn1_expect_tlv(bytes, pos, _ASN1_BOOLEAN)
        is_ca = _asn1_boolean_value(bytes, bool_start, bool_end)
    end
    if pos <= seq_end
        int_start, int_end, pos = _asn1_expect_tlv(bytes, pos, _ASN1_INTEGER)
        max_path_len = _asn1_integer_value(bytes, int_start, int_end)
    end
    pos == seq_end + 1 || throw(ArgumentError("tls: malformed basic constraints extension"))
    return is_ca, max_path_len
end

function _tls_parse_key_usage(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::UInt16
    bit_start, bit_end, bit_next = _asn1_expect_tlv(bytes, value_start, _ASN1_BIT_STRING)
    bit_next == value_end + 1 || throw(ArgumentError("tls: malformed key usage extension"))
    return _asn1_parse_key_usage_bits(bytes, bit_start, bit_end)
end

function _tls_parse_extended_key_usage(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::UInt8
    seq_start, seq_end, seq_next = _asn1_expect_tlv(bytes, value_start, _ASN1_SEQUENCE)
    seq_next == value_end + 1 || throw(ArgumentError("tls: malformed extended key usage extension"))
    mask = UInt8(0)
    pos = seq_start
    while pos <= seq_end
        oid_start, oid_end, pos = _asn1_expect_tlv(bytes, pos, _ASN1_OBJECT_IDENTIFIER)
        if _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_EKU_ANY)
            mask |= _TLS_EXT_KEY_USAGE_ANY
        elseif _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_EKU_SERVER_AUTH)
            mask |= _TLS_EXT_KEY_USAGE_SERVER
        elseif _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_EKU_CLIENT_AUTH)
            mask |= _TLS_EXT_KEY_USAGE_CLIENT
        end
    end
    return mask
end

function _tls_parse_subject_key_identifier(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::Vector{UInt8}
    key_start, key_end, key_next = _asn1_expect_tlv(bytes, value_start, _ASN1_OCTET_STRING)
    key_next == value_end + 1 || throw(ArgumentError("tls: malformed subject key identifier extension"))
    return copy(@view bytes[key_start:key_end])
end

function _tls_parse_authority_key_identifier(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::Vector{UInt8}
    seq_start, seq_end, seq_next = _asn1_expect_tlv(bytes, value_start, _ASN1_SEQUENCE)
    seq_next == value_end + 1 || throw(ArgumentError("tls: malformed authority key identifier extension"))
    pos = seq_start
    while pos <= seq_end
        tag, item_start, item_end, pos = _asn1_read_tlv(bytes, pos)
        if tag == _ASN1_CONTEXT_KEY_IDENTIFIER
            return copy(@view bytes[item_start:item_end])
        end
    end
    return UInt8[]
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
    issuer_start, issuer_end, tbs_pos = _asn1_expect_tlv(cert_der, tbs_pos, _ASN1_SEQUENCE)
    validity_start, validity_end, tbs_pos = _asn1_expect_tlv(cert_der, tbs_pos, _ASN1_SEQUENCE)
    subject_start, subject_end, tbs_pos = _asn1_expect_tlv(cert_der, tbs_pos, _ASN1_SEQUENCE)
    common_name = _tls_parse_subject_common_name(cert_der, subject_start, subject_end)
    _, _, _, tbs_pos = _asn1_read_tlv(cert_der, tbs_pos) # subjectPublicKeyInfo
    dns_names = String[]
    ip_addresses = Vector{Vector{UInt8}}()
    has_san_extension = false
    valid_from_s = Int64(0)
    valid_until_s = Int64(0)
    begin
        time_pos = validity_start
        tag, value_start, value_end, time_pos = _asn1_read_tlv(cert_der, time_pos)
        valid_from_s = _asn1_parse_x509_time(cert_der, UInt8(tag), value_start, value_end)
        tag, value_start, value_end, time_pos = _asn1_read_tlv(cert_der, time_pos)
        valid_until_s = _asn1_parse_x509_time(cert_der, UInt8(tag), value_start, value_end)
        time_pos == validity_end + 1 || throw(ArgumentError("tls: malformed certificate validity"))
    end
    is_ca = false
    max_path_len = -1
    has_key_usage = false
    key_usage = UInt16(0)
    extended_key_usage = UInt8(0)
    subject_key_id = UInt8[]
    authority_key_id = UInt8[]
    while tbs_pos <= tbs_end
        tag, field_start, field_end, tbs_pos = _asn1_read_tlv(cert_der, tbs_pos)
        if tag == _ASN1_CONTEXT_EXPLICIT_EXTENSIONS
            exts_start, exts_end, exts_next = _asn1_expect_tlv(cert_der, field_start, _ASN1_SEQUENCE)
            exts_next == field_end + 1 || throw(ArgumentError("tls: malformed certificate extensions"))
            ext_pos = exts_start
            while ext_pos <= exts_end
                ext_start, ext_end, ext_pos = _asn1_expect_tlv(cert_der, ext_pos, _ASN1_SEQUENCE)
                oid_start, oid_end, value_pos = _asn1_expect_tlv(cert_der, ext_start, _ASN1_OBJECT_IDENTIFIER)
                critical = false
                if value_pos <= ext_end && cert_der[value_pos] == _ASN1_BOOLEAN
                    critical_start, critical_end, value_pos = _asn1_expect_tlv(cert_der, value_pos, _ASN1_BOOLEAN)
                    critical = _asn1_boolean_value(cert_der, critical_start, critical_end)
                end
                octet_start, octet_end, value_pos = _asn1_expect_tlv(cert_der, value_pos, _ASN1_OCTET_STRING)
                value_pos == ext_end + 1 || throw(ArgumentError("tls: malformed certificate extension value"))
                if _asn1_oid_equals(cert_der, oid_start, oid_end, _ASN1_OID_SUBJECT_ALT_NAME)
                    has_san_extension = true
                    dns_names, ip_addresses = _tls_parse_general_names(cert_der, octet_start, octet_end)
                elseif _asn1_oid_equals(cert_der, oid_start, oid_end, _ASN1_OID_BASIC_CONSTRAINTS)
                    is_ca, max_path_len = _tls_parse_basic_constraints(cert_der, octet_start, octet_end)
                elseif _asn1_oid_equals(cert_der, oid_start, oid_end, _ASN1_OID_KEY_USAGE)
                    has_key_usage = true
                    key_usage = _tls_parse_key_usage(cert_der, octet_start, octet_end)
                elseif _asn1_oid_equals(cert_der, oid_start, oid_end, _ASN1_OID_EXTENDED_KEY_USAGE)
                    extended_key_usage = _tls_parse_extended_key_usage(cert_der, octet_start, octet_end)
                elseif _asn1_oid_equals(cert_der, oid_start, oid_end, _ASN1_OID_SUBJECT_KEY_IDENTIFIER)
                    subject_key_id = _tls_parse_subject_key_identifier(cert_der, octet_start, octet_end)
                elseif _asn1_oid_equals(cert_der, oid_start, oid_end, _ASN1_OID_AUTHORITY_KEY_IDENTIFIER)
                    authority_key_id = _tls_parse_authority_key_identifier(cert_der, octet_start, octet_end)
                elseif critical
                    throw(ArgumentError("tls: unsupported critical X.509 extension"))
                end
            end
        end
    end
    return _TLSCertificateInfo(
        Vector{UInt8}(cert_der),
        copy(@view cert_der[subject_start:subject_end]),
        copy(@view cert_der[issuer_start:issuer_end]),
        common_name,
        dns_names,
        ip_addresses,
        has_san_extension,
        valid_from_s,
        valid_until_s,
        is_ca,
        max_path_len,
        has_key_usage,
        key_usage,
        extended_key_usage,
        subject_key_id,
        authority_key_id,
    )
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

struct _TLSTrustStore
    roots::Vector{_TLSCertificateInfo}
end

struct _TLSTrustStoreCacheEntry
    mtime::Float64
    size::Int64
    store::_TLSTrustStore
end

const _TLS_TRUST_STORE_CACHE_LOCK = ReentrantLock()
const _TLS_TRUST_STORE_CACHE = Dict{String, _TLSTrustStoreCacheEntry}()

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

function _tls_trust_store_fingerprint(ca_path::AbstractString)::Tuple{Float64, Int64}
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
        return latest_mtime, total_size
    end
    path_stat = stat(ca_path)
    return path_stat.mtime, Int64(path_stat.size)
end

function _tls_load_trust_store(ca_path::AbstractString)::_TLSTrustStore
    cache_path = abspath(ca_path)
    mtime, size = _tls_trust_store_fingerprint(cache_path)
    lock(_TLS_TRUST_STORE_CACHE_LOCK)
    try
        if haskey(_TLS_TRUST_STORE_CACHE, cache_path)
            entry = _TLS_TRUST_STORE_CACHE[cache_path]
            if entry.mtime == mtime && entry.size == size
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
        _TLS_TRUST_STORE_CACHE[cache_path] = _TLSTrustStoreCacheEntry(mtime, size, store)
    finally
        unlock(_TLS_TRUST_STORE_CACHE_LOCK)
    end
    return store
end

function _tls_verify_certificate_signature(child::_TLSCertificateInfo, parent::_TLSCertificateInfo)::Bool
    pkey = _tls13_pubkey_from_der_certificate(parent.der)
    try
        return _tls13_verify_der_certificate_signature(child.der, pkey)
    finally
        _free_evp_pkey!(pkey)
    end
end

function _tls_trust_anchor_matches(cert::_TLSCertificateInfo, store::_TLSTrustStore)::Bool
    for root in store.roots
        root.der == cert.der && return true
    end
    return false
end

function _tls_build_chain_to_trust_anchor!(
    child::_TLSCertificateInfo,
    intermediates::Vector{_TLSCertificateInfo},
    store::_TLSTrustStore,
    chain::Vector{_TLSCertificateInfo},
    now_s::Int64,
    remaining_candidates::Base.RefValue{Int},
)::Bool
    length(chain) > _TLS_MAX_CHAIN_DEPTH && return false
    for root in store.roots
        _tls_cert_subject_matches_issuer(child, root) || continue
        remaining_candidates[] -= 1
        remaining_candidates[] >= 0 || return false
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
        return true
    end
    for (i, parent) in pairs(intermediates)
        _tls_cert_subject_matches_issuer(child, parent) || continue
        remaining_candidates[] -= 1
        remaining_candidates[] >= 0 || return false
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
        _tls_build_chain_to_trust_anchor!(parent, remaining, store, next_chain, now_s, remaining_candidates) && return true
    end
    return false
end

function _tls_verify_peer_certificate_chain!(
    certificates::Vector{Vector{UInt8}},
    store::_TLSTrustStore,
    purpose::AbstractString,
)::_TLSCertificateInfo
    isempty(certificates) && _tls13_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: received empty certificates message")
    parsed = _TLSCertificateInfo[]
    try
        for cert_der in certificates
            push!(parsed, _tls_parse_der_certificate_info(cert_der))
        end
    catch ex
        ex isa _TLS13AlertError && rethrow()
        _tls13_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: malformed X.509 certificate")
    end
    leaf = parsed[1]
    now_s = Int64(floor(time()))
    _tls_certificate_valid_now(leaf, now_s) ||
        _tls13_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: $(_tls_certificate_current_time_message(leaf))")
    _tls_certificate_usage_permitted(leaf, purpose) ||
        _tls13_fail(_TLS_ALERT_BAD_CERTIFICATE, purpose == "ssl_server" ?
            "tls: certificate is not authorized for server authentication" :
            "tls: certificate is not authorized for client authentication")
    _tls_trust_anchor_matches(leaf, store) && return leaf
    intermediates = length(parsed) > 1 ? parsed[2:end] : _TLSCertificateInfo[]
    remaining_candidates = Ref(_TLS_MAX_CHAIN_CANDIDATES)
    _tls_build_chain_to_trust_anchor!(leaf, intermediates, store, _TLSCertificateInfo[leaf], now_s, remaining_candidates) ||
        _tls13_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: certificate signed by unknown authority")
    return leaf
end

function _tls_verify_certificate_chain(
    certificates::Vector{Vector{UInt8}};
    verify_peer::Bool,
    verify_hostname::Bool,
    ca_file::Union{Nothing, String},
    purpose::AbstractString,
    peer_name::AbstractString = "",
)::Ptr{Cvoid}
    isempty(certificates) && _tls13_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: received empty certificates message")
    leaf = if verify_peer
        ca_file === nothing && _tls13_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: certificate verification requires a CA roots path")
        store = try
            _tls_load_trust_store(ca_file::String)
        catch ex
            ex isa _TLS13AlertError && rethrow()
            _tls13_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: failed to load CA roots")
        end
        _tls_verify_peer_certificate_chain!(certificates, store, purpose)
    else
        try
            _tls_parse_der_certificate_info(certificates[1])
        catch ex
            ex isa _TLS13AlertError && rethrow()
            _tls13_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: malformed X.509 certificate")
        end
    end
    verify_hostname && isempty(peer_name) &&
        _tls13_fail(_TLS_ALERT_INTERNAL_ERROR, "tls: hostname verification requires a peer name")
    verify_hostname && _tls_verify_certificate_peer_name!(leaf, peer_name)
    return _tls13_pubkey_from_der_certificate(leaf.der)
end
