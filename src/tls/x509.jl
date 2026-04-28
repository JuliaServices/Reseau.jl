"""
    _TLSIPRangeConstraint

Parsed RFC 5280 IP NameConstraints entry.
"""
struct _TLSIPRangeConstraint
    network::Vector{UInt8}
    mask::Vector{UInt8}
end

struct _TLSParsedGeneralNames
    dns_names::Vector{String}
    ip_addresses::Vector{Vector{UInt8}}
    email_addresses::Vector{String}
    uri_names::Vector{String}
    has_unhandled_name_types::Bool
end

struct _TLSParsedNameConstraints
    permitted_dns_domains::Vector{String}
    excluded_dns_domains::Vector{String}
    permitted_ip_ranges::Vector{_TLSIPRangeConstraint}
    excluded_ip_ranges::Vector{_TLSIPRangeConstraint}
    permitted_uri_domains::Vector{String}
    excluded_uri_domains::Vector{String}
    permitted_email_addresses::Vector{String}
    excluded_email_addresses::Vector{String}
end

struct _TLSBasicConstraints
    is_ca::Bool
    max_path_len::Int
end

"""
    _TLSCertificateInfo

Parsed X.509 certificate fields retained by the native trust and hostname
verification layers.

This is intentionally narrower than a full generic certificate model: it keeps
the DER slices, subject/issuer identity, SANs, validity window, key-usage
policy, SubjectPublicKeyInfo, signature information, and DNS/IP name
constraints that the native TLS verify path actually needs.
"""
struct _TLSCertificateInfo
    der::Vector{UInt8}
    subject_raw::Vector{UInt8}
    issuer_raw::Vector{UInt8}
    common_name::String
    dns_names::Vector{String}
    ip_addresses::Vector{Vector{UInt8}}
    email_addresses::Vector{String}
    uri_names::Vector{String}
    has_san_extension::Bool
    has_unhandled_san_names::Bool
    not_before_s::Int64
    not_after_s::Int64
    is_ca::Bool
    max_path_len::Int
    has_key_usage::Bool
    key_usage::UInt16
    extended_key_usage::UInt8
    subject_key_id::Vector{UInt8}
    authority_key_id::Vector{UInt8}
    permitted_dns_domains::Vector{String}
    excluded_dns_domains::Vector{String}
    permitted_ip_ranges::Vector{_TLSIPRangeConstraint}
    excluded_ip_ranges::Vector{_TLSIPRangeConstraint}
    permitted_uri_domains::Vector{String}
    excluded_uri_domains::Vector{String}
    permitted_email_addresses::Vector{String}
    excluded_email_addresses::Vector{String}
    tbs_der::Vector{UInt8}
    public_key::_TLSPublicKey
    signature_verify_spec::_TLSSignatureVerifySpec
    signature::Vector{UInt8}
end

# Native DER/PEM/X.509 parsing and hostname/IP verification helpers.
#
# This file owns certificate decoding and extraction of the policy-relevant
# fields used by the native trust layer. It deliberately stops short of raw
# cryptographic verification, which remains delegated to the OpenSSL primitive
# backend through parsed public-key and signature-spec values.

const _ASN1_INTEGER = UInt8(0x02)
const _ASN1_BIT_STRING = UInt8(0x03)
const _ASN1_NULL = UInt8(0x05)
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
const _ASN1_GENERAL_NAME_RFC822 = UInt8(0x81)
const _ASN1_GENERAL_NAME_DNS = UInt8(0x82)
const _ASN1_GENERAL_NAME_URI = UInt8(0x86)
const _ASN1_GENERAL_NAME_IP = UInt8(0x87)
const _ASN1_OID_COMMON_NAME = (UInt8(0x55), UInt8(0x04), UInt8(0x03))
const _ASN1_OID_KEY_USAGE = (UInt8(0x55), UInt8(0x1d), UInt8(0x0f))
const _ASN1_OID_SUBJECT_KEY_IDENTIFIER = (UInt8(0x55), UInt8(0x1d), UInt8(0x0e))
const _ASN1_OID_SUBJECT_ALT_NAME = (UInt8(0x55), UInt8(0x1d), UInt8(0x11))
const _ASN1_OID_BASIC_CONSTRAINTS = (UInt8(0x55), UInt8(0x1d), UInt8(0x13))
const _ASN1_OID_NAME_CONSTRAINTS = (UInt8(0x55), UInt8(0x1d), UInt8(0x1e))
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
const _ASN1_OID_RSA_ENCRYPTION = (
    UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0x86), UInt8(0xf7),
    UInt8(0x0d), UInt8(0x01), UInt8(0x01), UInt8(0x01),
)
const _ASN1_OID_RSASSA_PSS = (
    UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0x86), UInt8(0xf7),
    UInt8(0x0d), UInt8(0x01), UInt8(0x01), UInt8(0x0a),
)
const _ASN1_OID_SHA1_WITH_RSA_ENCRYPTION = (
    UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0x86), UInt8(0xf7),
    UInt8(0x0d), UInt8(0x01), UInt8(0x01), UInt8(0x05),
)
const _ASN1_OID_SHA224_WITH_RSA_ENCRYPTION = (
    UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0x86), UInt8(0xf7),
    UInt8(0x0d), UInt8(0x01), UInt8(0x01), UInt8(0x0e),
)
const _ASN1_OID_SHA256_WITH_RSA_ENCRYPTION = (
    UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0x86), UInt8(0xf7),
    UInt8(0x0d), UInt8(0x01), UInt8(0x01), UInt8(0x0b),
)
const _ASN1_OID_SHA384_WITH_RSA_ENCRYPTION = (
    UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0x86), UInt8(0xf7),
    UInt8(0x0d), UInt8(0x01), UInt8(0x01), UInt8(0x0c),
)
const _ASN1_OID_SHA512_WITH_RSA_ENCRYPTION = (
    UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0x86), UInt8(0xf7),
    UInt8(0x0d), UInt8(0x01), UInt8(0x01), UInt8(0x0d),
)
const _ASN1_OID_ID_EC_PUBLIC_KEY = (
    UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0xce), UInt8(0x3d),
    UInt8(0x02), UInt8(0x01),
)
const _ASN1_OID_ECDSA_WITH_SHA1 = (
    UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0xce), UInt8(0x3d),
    UInt8(0x04), UInt8(0x01),
)
const _ASN1_OID_ECDSA_WITH_SHA224 = (
    UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0xce), UInt8(0x3d),
    UInt8(0x04), UInt8(0x03), UInt8(0x01),
)
const _ASN1_OID_ECDSA_WITH_SHA256 = (
    UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0xce), UInt8(0x3d),
    UInt8(0x04), UInt8(0x03), UInt8(0x02),
)
const _ASN1_OID_ECDSA_WITH_SHA384 = (
    UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0xce), UInt8(0x3d),
    UInt8(0x04), UInt8(0x03), UInt8(0x03),
)
const _ASN1_OID_ECDSA_WITH_SHA512 = (
    UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0xce), UInt8(0x3d),
    UInt8(0x04), UInt8(0x03), UInt8(0x04),
)
const _ASN1_OID_ED25519 = (
    UInt8(0x2b), UInt8(0x65), UInt8(0x70),
)
const _ASN1_OID_MGF1 = (
    UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0x86), UInt8(0xf7),
    UInt8(0x0d), UInt8(0x01), UInt8(0x01), UInt8(0x08),
)
const _ASN1_OID_SHA1 = (
    UInt8(0x2b), UInt8(0x0e), UInt8(0x03), UInt8(0x02), UInt8(0x1a),
)
const _ASN1_OID_SHA224 = (
    UInt8(0x60), UInt8(0x86), UInt8(0x48), UInt8(0x01), UInt8(0x65),
    UInt8(0x03), UInt8(0x04), UInt8(0x02), UInt8(0x04),
)
const _ASN1_OID_SHA256 = (
    UInt8(0x60), UInt8(0x86), UInt8(0x48), UInt8(0x01), UInt8(0x65),
    UInt8(0x03), UInt8(0x04), UInt8(0x02), UInt8(0x01),
)
const _ASN1_OID_SHA384 = (
    UInt8(0x60), UInt8(0x86), UInt8(0x48), UInt8(0x01), UInt8(0x65),
    UInt8(0x03), UInt8(0x04), UInt8(0x02), UInt8(0x02),
)
const _ASN1_OID_SHA512 = (
    UInt8(0x60), UInt8(0x86), UInt8(0x48), UInt8(0x01), UInt8(0x65),
    UInt8(0x03), UInt8(0x04), UInt8(0x02), UInt8(0x03),
)
const _ASN1_OID_CURVE_P256 = (
    UInt8(0x2a), UInt8(0x86), UInt8(0x48), UInt8(0xce), UInt8(0x3d),
    UInt8(0x03), UInt8(0x01), UInt8(0x07),
)
const _ASN1_OID_CURVE_P384 = (
    UInt8(0x2b), UInt8(0x81), UInt8(0x04), UInt8(0x00), UInt8(0x22),
)
const _ASN1_OID_CURVE_P521 = (
    UInt8(0x2b), UInt8(0x81), UInt8(0x04), UInt8(0x00), UInt8(0x23),
)

const _TLS_MAX_RSA_CERT_KEY_BITS = 8192

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

# The low-level ASN.1 helpers stay intentionally strict and allocation-light so
# malformed certificates fail early and higher-level parsing code can remain
# mostly linear over validated TLV slices.
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

function _asn1_integer_bytes(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::Vector{UInt8}
    value_start <= value_end || throw(ArgumentError("tls: malformed ASN.1 INTEGER value"))
    first = bytes[value_start]
    if first >= 0x80
        throw(ArgumentError("tls: negative ASN.1 INTEGER values are not supported"))
    end
    start = value_start
    if first == 0x00 && value_start < value_end
        bytes[value_start + 1] >= 0x80 || throw(ArgumentError("tls: non-minimal ASN.1 INTEGER value"))
        start += 1
    end
    start <= value_end || throw(ArgumentError("tls: malformed ASN.1 INTEGER value"))
    return copy(@view bytes[start:value_end])
end

function _tls_rsa_modulus_bit_length(modulus::AbstractVector{UInt8})::Int
    isempty(modulus) && throw(ArgumentError("tls: malformed RSA public key"))
    first = modulus[1]
    first == 0x00 && throw(ArgumentError("tls: malformed RSA public key"))
    return ((length(modulus) - 1) << 3) + (8 - leading_zeros(first))
end

function _tls_check_rsa_certificate_key_size!(modulus::AbstractVector{UInt8})::Nothing
    bits = _tls_rsa_modulus_bit_length(modulus)
    bits <= _TLS_MAX_RSA_CERT_KEY_BITS ||
        throw(ArgumentError("tls: RSA certificate public key is larger than $(_TLS_MAX_RSA_CERT_KEY_BITS) bits"))
    return nothing
end

function _asn1_bit_string_bytes(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::Vector{UInt8}
    value_start <= value_end || throw(ArgumentError("tls: malformed ASN.1 BIT STRING value"))
    unused_bits = Int(bytes[value_start])
    unused_bits == 0 || throw(ArgumentError("tls: unsupported ASN.1 BIT STRING padding"))
    value_start < value_end || throw(ArgumentError("tls: malformed ASN.1 BIT STRING value"))
    return copy(@view bytes[(value_start + 1):value_end])
end

function _tls_hash_bits_from_oid(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::UInt16
    _asn1_oid_equals(bytes, value_start, value_end, _ASN1_OID_SHA1) && return UInt16(160)
    _asn1_oid_equals(bytes, value_start, value_end, _ASN1_OID_SHA224) && return UInt16(224)
    _asn1_oid_equals(bytes, value_start, value_end, _ASN1_OID_SHA256) && return UInt16(256)
    _asn1_oid_equals(bytes, value_start, value_end, _ASN1_OID_SHA384) && return UInt16(384)
    _asn1_oid_equals(bytes, value_start, value_end, _ASN1_OID_SHA512) && return UInt16(512)
    throw(ArgumentError("tls: unsupported X.509 hash algorithm"))
end

@inline function _tls_digest_len_from_bits(bits::UInt16)::Int
    bits == 160 && return 20
    bits == 224 && return 28
    bits == 256 && return 32
    bits == 384 && return 48
    bits == 512 && return 64
    throw(ArgumentError("tls: unsupported X.509 hash size"))
end

function _tls_require_algorithm_identifier_null_or_absent(bytes::AbstractVector{UInt8}, pos::Int, value_end::Int)::Nothing
    pos > value_end && return nothing
    null_start, null_end, next_pos = _asn1_expect_tlv(bytes, pos, _ASN1_NULL)
    null_start > null_end || throw(ArgumentError("tls: malformed X.509 algorithm parameters"))
    next_pos == value_end + 1 || throw(ArgumentError("tls: malformed X.509 algorithm parameters"))
    return nothing
end

function _tls_parse_pss_hash_algorithm(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::UInt16
    oid_start, oid_end, pos = _asn1_expect_tlv(bytes, value_start, _ASN1_OBJECT_IDENTIFIER)
    hash_bits = _tls_hash_bits_from_oid(bytes, oid_start, oid_end)
    _tls_require_algorithm_identifier_null_or_absent(bytes, pos, value_end)
    return hash_bits
end

function _tls_parse_rsa_pss_signature_spec(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::_TLSSignatureVerifySpec
    seq_start, seq_end, seq_next = _asn1_expect_tlv(bytes, value_start, _ASN1_SEQUENCE)
    seq_next == value_end + 1 || throw(ArgumentError("tls: malformed X.509 RSASSA-PSS parameters"))
    hash_bits = UInt16(160)
    mgf1_hash_bits = UInt16(160)
    salt_len = 20
    trailer_field = 1
    pos = seq_start
    while pos <= seq_end
        tag, item_start, item_end, pos = _asn1_read_tlv(bytes, pos)
        if tag == 0xa0
            alg_start, alg_end, alg_next = _asn1_expect_tlv(bytes, item_start, _ASN1_SEQUENCE)
            alg_next == item_end + 1 || throw(ArgumentError("tls: malformed X.509 RSASSA-PSS hash parameters"))
            hash_bits = _tls_parse_pss_hash_algorithm(bytes, alg_start, alg_end)
        elseif tag == 0xa1
            mgf_start, mgf_end, mgf_next = _asn1_expect_tlv(bytes, item_start, _ASN1_SEQUENCE)
            mgf_next == item_end + 1 || throw(ArgumentError("tls: malformed X.509 RSASSA-PSS mask parameters"))
            oid_start, oid_end, mgf_pos = _asn1_expect_tlv(bytes, mgf_start, _ASN1_OBJECT_IDENTIFIER)
            _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_MGF1) ||
                throw(ArgumentError("tls: unsupported X.509 RSASSA-PSS mask generator"))
            hash_start, hash_end, mgf_pos = _asn1_expect_tlv(bytes, mgf_pos, _ASN1_SEQUENCE)
            mgf_pos == mgf_end + 1 || throw(ArgumentError("tls: malformed X.509 RSASSA-PSS mask parameters"))
            mgf1_hash_bits = _tls_parse_pss_hash_algorithm(bytes, hash_start, hash_end)
        elseif tag == 0xa2
            salt_start, salt_end, salt_next = _asn1_expect_tlv(bytes, item_start, _ASN1_INTEGER)
            salt_next == item_end + 1 || throw(ArgumentError("tls: malformed X.509 RSASSA-PSS salt length"))
            salt_len = _asn1_integer_value(bytes, salt_start, salt_end)
        elseif tag == 0xa3
            trailer_start, trailer_end, trailer_next = _asn1_expect_tlv(bytes, item_start, _ASN1_INTEGER)
            trailer_next == item_end + 1 || throw(ArgumentError("tls: malformed X.509 RSASSA-PSS trailer field"))
            trailer_field = _asn1_integer_value(bytes, trailer_start, trailer_end)
        else
            throw(ArgumentError("tls: unsupported X.509 RSASSA-PSS parameters"))
        end
    end
    mgf1_hash_bits == hash_bits || throw(ArgumentError("tls: unsupported X.509 RSASSA-PSS mask digest"))
    salt_len == _tls_digest_len_from_bits(hash_bits) || throw(ArgumentError("tls: unsupported X.509 RSASSA-PSS salt length"))
    trailer_field == 1 || throw(ArgumentError("tls: unsupported X.509 RSASSA-PSS trailer field"))
    return _TLSSignatureVerifySpec(hash_bits, false, true)
end

function _tls_parse_certificate_signature_spec(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::_TLSSignatureVerifySpec
    oid_start, oid_end, pos = _asn1_expect_tlv(bytes, value_start, _ASN1_OBJECT_IDENTIFIER)
    if _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_SHA1_WITH_RSA_ENCRYPTION)
        throw(ArgumentError("tls: SHA-1 X.509 certificate signatures are not supported"))
    elseif _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_SHA224_WITH_RSA_ENCRYPTION)
        _tls_require_algorithm_identifier_null_or_absent(bytes, pos, value_end)
        return _TLSSignatureVerifySpec(UInt16(224), false, false)
    elseif _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_SHA256_WITH_RSA_ENCRYPTION)
        _tls_require_algorithm_identifier_null_or_absent(bytes, pos, value_end)
        return _TLSSignatureVerifySpec(UInt16(256), false, false)
    elseif _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_SHA384_WITH_RSA_ENCRYPTION)
        _tls_require_algorithm_identifier_null_or_absent(bytes, pos, value_end)
        return _TLSSignatureVerifySpec(UInt16(384), false, false)
    elseif _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_SHA512_WITH_RSA_ENCRYPTION)
        _tls_require_algorithm_identifier_null_or_absent(bytes, pos, value_end)
        return _TLSSignatureVerifySpec(UInt16(512), false, false)
    elseif _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_ECDSA_WITH_SHA1)
        throw(ArgumentError("tls: SHA-1 X.509 certificate signatures are not supported"))
    elseif _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_ECDSA_WITH_SHA224)
        pos > value_end || throw(ArgumentError("tls: malformed X.509 ECDSA signature parameters"))
        return _TLSSignatureVerifySpec(UInt16(224), false, false)
    elseif _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_ECDSA_WITH_SHA256)
        pos > value_end || throw(ArgumentError("tls: malformed X.509 ECDSA signature parameters"))
        return _TLSSignatureVerifySpec(UInt16(256), false, false)
    elseif _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_ECDSA_WITH_SHA384)
        pos > value_end || throw(ArgumentError("tls: malformed X.509 ECDSA signature parameters"))
        return _TLSSignatureVerifySpec(UInt16(384), false, false)
    elseif _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_ECDSA_WITH_SHA512)
        pos > value_end || throw(ArgumentError("tls: malformed X.509 ECDSA signature parameters"))
        return _TLSSignatureVerifySpec(UInt16(512), false, false)
    elseif _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_ED25519)
        pos > value_end || throw(ArgumentError("tls: malformed X.509 Ed25519 signature parameters"))
        return _TLSSignatureVerifySpec(UInt16(0), true, false)
    elseif _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_RSASSA_PSS)
        pos <= value_end || throw(ArgumentError("tls: missing X.509 RSASSA-PSS parameters"))
        return _tls_parse_rsa_pss_signature_spec(bytes, pos, value_end)
    end
    throw(ArgumentError("tls: unsupported X.509 signature algorithm"))
end

function _tls_parse_subject_public_key_info(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::_TLSPublicKey
    alg_start, alg_end, pos = _asn1_expect_tlv(bytes, value_start, _ASN1_SEQUENCE)
    bit_start, bit_end, pos = _asn1_expect_tlv(bytes, pos, _ASN1_BIT_STRING)
    pos == value_end + 1 || throw(ArgumentError("tls: malformed subjectPublicKeyInfo"))
    oid_start, oid_end, alg_pos = _asn1_expect_tlv(bytes, alg_start, _ASN1_OBJECT_IDENTIFIER)
    if _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_RSA_ENCRYPTION) ||
       _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_RSASSA_PSS)
        _tls_require_algorithm_identifier_null_or_absent(bytes, alg_pos, alg_end)
        key_bytes = _asn1_bit_string_bytes(bytes, bit_start, bit_end)
        key_start, key_end, key_next = _asn1_expect_tlv(key_bytes, firstindex(key_bytes), _ASN1_SEQUENCE)
        key_next == lastindex(key_bytes) + 1 || throw(ArgumentError("tls: malformed RSA public key"))
        modulus_start, modulus_end, key_pos = _asn1_expect_tlv(key_bytes, key_start, _ASN1_INTEGER)
        exponent_start, exponent_end, key_pos = _asn1_expect_tlv(key_bytes, key_pos, _ASN1_INTEGER)
        key_pos == key_end + 1 || throw(ArgumentError("tls: malformed RSA public key"))
        modulus = _asn1_integer_bytes(key_bytes, modulus_start, modulus_end)
        _tls_check_rsa_certificate_key_size!(modulus)
        exponent = _asn1_integer_bytes(key_bytes, exponent_start, exponent_end)
        return _TLSRSAPublicKey(modulus, exponent)
    elseif _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_ID_EC_PUBLIC_KEY)
        curve_oid_start, curve_oid_end, alg_pos = _asn1_expect_tlv(bytes, alg_pos, _ASN1_OBJECT_IDENTIFIER)
        alg_pos == alg_end + 1 || throw(ArgumentError("tls: malformed EC public key parameters"))
        curve_id = if _asn1_oid_equals(bytes, curve_oid_start, curve_oid_end, _ASN1_OID_CURVE_P256)
            _TLS_GROUP_SECP256R1
        elseif _asn1_oid_equals(bytes, curve_oid_start, curve_oid_end, _ASN1_OID_CURVE_P384)
            UInt16(0x0018)
        elseif _asn1_oid_equals(bytes, curve_oid_start, curve_oid_end, _ASN1_OID_CURVE_P521)
            UInt16(0x0019)
        else
            throw(ArgumentError("tls: unsupported X.509 EC named curve"))
        end
        return _TLSECPublicKey(curve_id, _asn1_bit_string_bytes(bytes, bit_start, bit_end))
    elseif _asn1_oid_equals(bytes, oid_start, oid_end, _ASN1_OID_ED25519)
        alg_pos > alg_end || throw(ArgumentError("tls: malformed Ed25519 public key parameters"))
        key = _asn1_bit_string_bytes(bytes, bit_start, bit_end)
        length(key) == 32 || throw(ArgumentError("tls: malformed Ed25519 public key"))
        return _TLSEd25519PublicKey(key)
    end
    throw(ArgumentError("tls: unsupported X.509 subject public key algorithm"))
end

@inline function _asn1_ascii_string(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::String
    return String(@view bytes[value_start:value_end])
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
)::_TLSParsedGeneralNames
    seq_start, seq_end, seq_next = _asn1_expect_tlv(bytes, value_start, _ASN1_SEQUENCE)
    seq_next == value_end + 1 || throw(ArgumentError("tls: malformed subjectAltName extension"))
    dns_names = String[]
    ip_addresses = Vector{Vector{UInt8}}()
    email_addresses = String[]
    uri_names = String[]
    has_unhandled_name_types = false
    pos = seq_start
    while pos <= seq_end
        tag, name_start, name_end, pos = _asn1_read_tlv(bytes, pos)
        if tag == _ASN1_GENERAL_NAME_RFC822
            push!(email_addresses, _asn1_ascii_string(bytes, name_start, name_end))
        elseif tag == _ASN1_GENERAL_NAME_DNS
            push!(dns_names, _asn1_ascii_string(bytes, name_start, name_end))
        elseif tag == _ASN1_GENERAL_NAME_URI
            push!(uri_names, _asn1_ascii_string(bytes, name_start, name_end))
        elseif tag == _ASN1_GENERAL_NAME_IP
            push!(ip_addresses, copy(@view bytes[name_start:name_end]))
        else
            has_unhandled_name_types = true
        end
    end
    return _TLSParsedGeneralNames(dns_names, ip_addresses, email_addresses, uri_names, has_unhandled_name_types)
end

@inline function _tls_valid_name_constraint_domain(domain::AbstractString)::Bool
    isempty(domain) && return true
    if startswith(domain, ".")
        length(domain) > 1 || return false
        return _tls_valid_hostname_value(SubString(domain, 2:lastindex(domain)), false)
    end
    return _tls_valid_hostname_value(domain, false)
end

@inline function _tls_valid_email_constraint(value::AbstractString)::Bool
    at = findfirst(==('@'), value)
    at === nothing && return _tls_valid_name_constraint_domain(value)
    local_end = prevind(value, at)
    domain_start = nextind(value, at)
    local_end >= firstindex(value) || return false
    domain_start <= lastindex(value) || return false
    findnext(==('@'), value, domain_start) === nothing || return false
    return _tls_valid_hostname_value(SubString(value, domain_start:lastindex(value)), false)
end

@inline function _tls_valid_ip_mask(mask::AbstractVector{UInt8})::Bool
    seen_zero = false
    @inbounds for byte in mask
        for bit in 7:-1:0
            one = ((byte >> bit) & 0x01) == 0x01
            if seen_zero
                one && return false
            elseif !one
                seen_zero = true
            end
        end
    end
    return true
end

function _tls_parse_ip_range_constraint(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::_TLSIPRangeConstraint
    len = value_end - value_start + 1
    if len == 8
        network = copy(@view bytes[value_start:(value_start + 3)])
        mask = copy(@view bytes[(value_start + 4):value_end])
    elseif len == 32
        network = copy(@view bytes[value_start:(value_start + 15)])
        mask = copy(@view bytes[(value_start + 16):value_end])
    else
        throw(ArgumentError("tls: IP name constraint contained value of length $(len)"))
    end
    _tls_valid_ip_mask(mask) || throw(ArgumentError("tls: IP name constraint contained an invalid mask"))
    return _TLSIPRangeConstraint(network, mask)
end

function _tls_parse_name_constraints_subtrees!(
    bytes::AbstractVector{UInt8},
    value_start::Int,
    value_end::Int,
    dns_out::Vector{String},
    ip_out::Vector{_TLSIPRangeConstraint},
    uri_out::Vector{String},
    email_out::Vector{String},
)::Nothing
    seq_start, seq_end, seq_next = _asn1_expect_tlv(bytes, value_start, _ASN1_SEQUENCE)
    seq_next == value_end + 1 || throw(ArgumentError("tls: malformed NameConstraints extension"))
    pos = seq_start
    while pos <= seq_end
        subtree_start, subtree_end, pos = _asn1_expect_tlv(bytes, pos, _ASN1_SEQUENCE)
        tag, base_start, base_end, subtree_pos = _asn1_read_tlv(bytes, subtree_start)
        if tag == _ASN1_GENERAL_NAME_DNS
            domain = _asn1_ascii_string(bytes, base_start, base_end)
            _tls_valid_name_constraint_domain(domain) ||
                throw(ArgumentError("tls: failed to parse dNSName constraint $(repr(domain))"))
            push!(dns_out, String(domain))
        elseif tag == _ASN1_GENERAL_NAME_RFC822
            mailbox = _asn1_ascii_string(bytes, base_start, base_end)
            _tls_valid_email_constraint(mailbox) ||
                throw(ArgumentError("tls: failed to parse rfc822Name constraint $(repr(mailbox))"))
            push!(email_out, mailbox)
        elseif tag == _ASN1_GENERAL_NAME_URI
            domain = _asn1_ascii_string(bytes, base_start, base_end)
            _tls_valid_name_constraint_domain(domain) ||
                throw(ArgumentError("tls: failed to parse URI name constraint $(repr(domain))"))
            push!(uri_out, String(domain))
        elseif tag == _ASN1_GENERAL_NAME_IP
            push!(ip_out, _tls_parse_ip_range_constraint(bytes, base_start, base_end))
        else
            throw(ArgumentError("tls: unsupported NameConstraints name form"))
        end
        while subtree_pos <= subtree_end
            tag, field_start, field_end, subtree_pos = _asn1_read_tlv(bytes, subtree_pos)
            if tag == 0x80
                minimum = _asn1_integer_value(bytes, field_start, field_end)
                minimum == 0 || throw(ArgumentError("tls: unsupported non-zero NameConstraints minimum"))
            elseif tag == 0x81
                throw(ArgumentError("tls: unsupported NameConstraints maximum"))
            end
        end
    end
    return nothing
end

function _tls_parse_name_constraints(
    bytes::AbstractVector{UInt8},
    value_start::Int,
    value_end::Int,
)::_TLSParsedNameConstraints
    seq_start, seq_end, seq_next = _asn1_expect_tlv(bytes, value_start, _ASN1_SEQUENCE)
    seq_next == value_end + 1 || throw(ArgumentError("tls: malformed NameConstraints extension"))
    permitted_dns = String[]
    excluded_dns = String[]
    permitted_ip = _TLSIPRangeConstraint[]
    excluded_ip = _TLSIPRangeConstraint[]
    permitted_uri = String[]
    excluded_uri = String[]
    permitted_email = String[]
    excluded_email = String[]
    saw_subtrees = false
    pos = seq_start
    while pos <= seq_end
        tag, field_start, field_end, pos = _asn1_read_tlv(bytes, pos)
        if tag == 0xa0
            _tls_parse_name_constraints_subtrees!(bytes, field_start, field_end, permitted_dns, permitted_ip, permitted_uri, permitted_email)
            saw_subtrees = true
        elseif tag == 0xa1
            _tls_parse_name_constraints_subtrees!(bytes, field_start, field_end, excluded_dns, excluded_ip, excluded_uri, excluded_email)
            saw_subtrees = true
        else
            throw(ArgumentError("tls: malformed NameConstraints extension"))
        end
    end
    saw_subtrees || throw(ArgumentError("tls: empty name constraints extension"))
    return _TLSParsedNameConstraints(
        permitted_dns,
        excluded_dns,
        permitted_ip,
        excluded_ip,
        permitted_uri,
        excluded_uri,
        permitted_email,
        excluded_email,
    )
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

function _tls_parse_basic_constraints(bytes::AbstractVector{UInt8}, value_start::Int, value_end::Int)::_TLSBasicConstraints
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
    return _TLSBasicConstraints(is_ca, max_path_len)
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
    tbs_start, tbs_end, tbs_next = _asn1_expect_tlv(cert_der, cert_start, _ASN1_SEQUENCE)
    cert_pos = tbs_next
    outer_sig_alg_start, outer_sig_alg_end, cert_pos = _asn1_expect_tlv(cert_der, cert_pos, _ASN1_SEQUENCE)
    signature_start, signature_end, cert_pos = _asn1_expect_tlv(cert_der, cert_pos, _ASN1_BIT_STRING)
    cert_pos == cert_end + 1 || throw(ArgumentError("tls: malformed certificate container"))
    outer_sig_spec = _tls_parse_certificate_signature_spec(cert_der, outer_sig_alg_start, outer_sig_alg_end)
    signature = _asn1_bit_string_bytes(cert_der, signature_start, signature_end)
    tbs_der = copy(@view cert_der[cert_start:(tbs_next - 1)])
    tbs_pos = tbs_start
    if tbs_pos <= tbs_end && cert_der[tbs_pos] == _ASN1_CONTEXT_EXPLICIT_VERSION
        _, _, tbs_pos = _asn1_expect_tlv(cert_der, tbs_pos, _ASN1_CONTEXT_EXPLICIT_VERSION)
    end
    _, _, _, tbs_pos = _asn1_read_tlv(cert_der, tbs_pos) # serial number
    tbs_sig_alg_start, tbs_sig_alg_end, tbs_pos = _asn1_expect_tlv(cert_der, tbs_pos, _ASN1_SEQUENCE)
    _tls_parse_certificate_signature_spec(cert_der, tbs_sig_alg_start, tbs_sig_alg_end)
    cert_der[tbs_sig_alg_start:tbs_sig_alg_end] == cert_der[outer_sig_alg_start:outer_sig_alg_end] ||
        throw(ArgumentError("tls: mismatched X.509 certificate signature algorithms"))
    issuer_start, issuer_end, tbs_pos = _asn1_expect_tlv(cert_der, tbs_pos, _ASN1_SEQUENCE)
    validity_start, validity_end, tbs_pos = _asn1_expect_tlv(cert_der, tbs_pos, _ASN1_SEQUENCE)
    subject_start, subject_end, tbs_pos = _asn1_expect_tlv(cert_der, tbs_pos, _ASN1_SEQUENCE)
    common_name = _tls_parse_subject_common_name(cert_der, subject_start, subject_end)
    spki_start, spki_end, tbs_pos = _asn1_expect_tlv(cert_der, tbs_pos, _ASN1_SEQUENCE)
    public_key = _tls_parse_subject_public_key_info(cert_der, spki_start, spki_end)
    dns_names = String[]
    ip_addresses = Vector{Vector{UInt8}}()
    email_addresses = String[]
    uri_names = String[]
    has_san_extension = false
    has_unhandled_san_names = false
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
    permitted_dns_domains = String[]
    excluded_dns_domains = String[]
    permitted_ip_ranges = _TLSIPRangeConstraint[]
    excluded_ip_ranges = _TLSIPRangeConstraint[]
    permitted_uri_domains = String[]
    excluded_uri_domains = String[]
    permitted_email_addresses = String[]
    excluded_email_addresses = String[]
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
                    general_names = _tls_parse_general_names(cert_der, octet_start, octet_end)
                    dns_names = general_names.dns_names
                    ip_addresses = general_names.ip_addresses
                    email_addresses = general_names.email_addresses
                    uri_names = general_names.uri_names
                    has_unhandled_san_names = general_names.has_unhandled_name_types
                elseif _asn1_oid_equals(cert_der, oid_start, oid_end, _ASN1_OID_BASIC_CONSTRAINTS)
                    basic_constraints = _tls_parse_basic_constraints(cert_der, octet_start, octet_end)
                    is_ca = basic_constraints.is_ca
                    max_path_len = basic_constraints.max_path_len
                elseif _asn1_oid_equals(cert_der, oid_start, oid_end, _ASN1_OID_KEY_USAGE)
                    has_key_usage = true
                    key_usage = _tls_parse_key_usage(cert_der, octet_start, octet_end)
                elseif _asn1_oid_equals(cert_der, oid_start, oid_end, _ASN1_OID_EXTENDED_KEY_USAGE)
                    extended_key_usage = _tls_parse_extended_key_usage(cert_der, octet_start, octet_end)
                elseif _asn1_oid_equals(cert_der, oid_start, oid_end, _ASN1_OID_SUBJECT_KEY_IDENTIFIER)
                    subject_key_id = _tls_parse_subject_key_identifier(cert_der, octet_start, octet_end)
                elseif _asn1_oid_equals(cert_der, oid_start, oid_end, _ASN1_OID_AUTHORITY_KEY_IDENTIFIER)
                    authority_key_id = _tls_parse_authority_key_identifier(cert_der, octet_start, octet_end)
                elseif _asn1_oid_equals(cert_der, oid_start, oid_end, _ASN1_OID_NAME_CONSTRAINTS)
                    name_constraints = _tls_parse_name_constraints(cert_der, octet_start, octet_end)
                    permitted_dns_domains = name_constraints.permitted_dns_domains
                    excluded_dns_domains = name_constraints.excluded_dns_domains
                    permitted_ip_ranges = name_constraints.permitted_ip_ranges
                    excluded_ip_ranges = name_constraints.excluded_ip_ranges
                    permitted_uri_domains = name_constraints.permitted_uri_domains
                    excluded_uri_domains = name_constraints.excluded_uri_domains
                    permitted_email_addresses = name_constraints.permitted_email_addresses
                    excluded_email_addresses = name_constraints.excluded_email_addresses
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
        email_addresses,
        uri_names,
        has_san_extension,
        has_unhandled_san_names,
        valid_from_s,
        valid_until_s,
        is_ca,
        max_path_len,
        has_key_usage,
        key_usage,
        extended_key_usage,
        subject_key_id,
        authority_key_id,
        permitted_dns_domains,
        excluded_dns_domains,
        permitted_ip_ranges,
        excluded_ip_ranges,
        permitted_uri_domains,
        excluded_uri_domains,
        permitted_email_addresses,
        excluded_email_addresses,
        tbs_der,
        public_key,
        outer_sig_spec,
        signature,
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
    verify_name = _normalize_peer_name(host)
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
        verify_ip = _normalize_peer_name(normalized)
        ip_bytes = _tls_literal_host_bytes(verify_ip)
        for candidate in cert.ip_addresses
            _tls_ip_bytes_equal(candidate, ip_bytes) && return nothing
        end
        _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: certificate is not valid for IP address $(verify_ip)")
    end
    verify_name = _normalize_peer_name(normalized)
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
    _tls_fail(_TLS_ALERT_BAD_CERTIFICATE, "tls: $(_tls_certificate_hostname_error(cert, verify_name))")
end

include("x509_verify.jl")
