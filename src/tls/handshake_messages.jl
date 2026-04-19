const _MAX_HANDSHAKE_SIZE = 65536

const _HANDSHAKE_TYPE_CLIENT_HELLO = UInt8(1)
const _HANDSHAKE_TYPE_SERVER_HELLO = UInt8(2)
const _HANDSHAKE_TYPE_NEW_SESSION_TICKET = UInt8(4)
const _HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = UInt8(8)
const _HANDSHAKE_TYPE_CERTIFICATE = UInt8(11)
const _HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE = UInt8(12)
const _HANDSHAKE_TYPE_CERTIFICATE_REQUEST = UInt8(13)
const _HANDSHAKE_TYPE_SERVER_HELLO_DONE = UInt8(14)
const _HANDSHAKE_TYPE_CERTIFICATE_VERIFY = UInt8(15)
const _HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE = UInt8(16)
const _HANDSHAKE_TYPE_FINISHED = UInt8(20)

const _TLS_COMPRESSION_NONE = UInt8(0)

const _HANDSHAKE_EXTENSION_SERVER_NAME = UInt16(0)
const _HANDSHAKE_EXTENSION_STATUS_REQUEST = UInt16(5)
const _HANDSHAKE_EXTENSION_SUPPORTED_CURVES = UInt16(10)
const _HANDSHAKE_EXTENSION_SUPPORTED_POINTS = UInt16(11)
const _HANDSHAKE_EXTENSION_SIGNATURE_ALGORITHMS = UInt16(13)
const _HANDSHAKE_EXTENSION_ALPN = UInt16(16)
const _HANDSHAKE_EXTENSION_SCT = UInt16(18)
const _HANDSHAKE_EXTENSION_EXTENDED_MASTER_SECRET = UInt16(23)
const _HANDSHAKE_EXTENSION_SESSION_TICKET = UInt16(35)
const _HANDSHAKE_EXTENSION_PRE_SHARED_KEY = UInt16(41)
const _HANDSHAKE_EXTENSION_EARLY_DATA = UInt16(42)
const _HANDSHAKE_EXTENSION_SUPPORTED_VERSIONS = UInt16(43)
const _HANDSHAKE_EXTENSION_COOKIE = UInt16(44)
const _HANDSHAKE_EXTENSION_PSK_MODES = UInt16(45)
const _HANDSHAKE_EXTENSION_CERTIFICATE_AUTHORITIES = UInt16(47)
const _HANDSHAKE_EXTENSION_SIGNATURE_ALGORITHMS_CERT = UInt16(50)
const _HANDSHAKE_EXTENSION_KEY_SHARE = UInt16(51)
const _HANDSHAKE_EXTENSION_QUIC_TRANSPORT_PARAMETERS = UInt16(57)
const _HANDSHAKE_EXTENSION_RENEGOTIATION_INFO = UInt16(0xff01)
const _HANDSHAKE_EXTENSION_ENCRYPTED_CLIENT_HELLO = UInt16(0xfe0d)

const _TLS_SCSV_RENEGOTIATION = UInt16(0x00ff)
const _TLS_PSK_MODE_PLAIN = UInt8(0)
const _TLS_PSK_MODE_DHE = UInt8(1)
const _TLS_STATUS_TYPE_OCSP = UInt8(1)

# TLS handshake wire-message model plus marshal/unmarshal helpers.
#
# These structs intentionally own their byte/vector fields so the rest of the
# handshake code can treat parsed messages as stable protocol snapshots without
# aliasing caller buffers or transient views.

abstract type _HandshakeMessage end

"""
    _TLSKeyShare

One TLS key-share entry from a ClientHello or ServerHello.
"""
struct _TLSKeyShare
    group::UInt16
    data::Vector{UInt8}
end

"""
    _TLSPSKIdentity

TLS 1.3 PSK identity and obfuscated age value as carried on the wire.
"""
struct _TLSPSKIdentity
    label::Vector{UInt8}
    obfuscated_ticket_age::UInt32
end

Base.:(==)(a::_TLSKeyShare, b::_TLSKeyShare) = a.group == b.group && a.data == b.data
Base.:(==)(a::_TLSPSKIdentity, b::_TLSPSKIdentity) = a.label == b.label && a.obfuscated_ticket_age == b.obfuscated_ticket_age

_copy_byte_vectors(byte_vectors::Vector{Vector{UInt8}}) = [copy(bytes) for bytes in byte_vectors]

"""
    _ClientHelloMsg

Julia-owned representation of a TLS ClientHello.

The struct carries both cross-version fields and the version-specific extension
state used by native TLS 1.2, TLS 1.3, and mixed-version negotiation.
`original`, when present, preserves the validated wire frame used for transcript
or retry-sensitive flows.
"""
mutable struct _ClientHelloMsg <: _HandshakeMessage
    original::Union{Nothing, Vector{UInt8}}
    vers::UInt16
    random::Vector{UInt8}
    session_id::Vector{UInt8}
    cipher_suites::Vector{UInt16}
    compression_methods::Vector{UInt8}
    server_name::String
    ocsp_stapling::Bool
    supported_curves::Vector{UInt16}
    supported_points::Vector{UInt8}
    ticket_supported::Bool
    session_ticket::Vector{UInt8}
    supported_signature_algorithms::Vector{UInt16}
    supported_signature_algorithms_cert::Vector{UInt16}
    secure_renegotiation_supported::Bool
    secure_renegotiation::Vector{UInt8}
    extended_master_secret::Bool
    alpn_protocols::Vector{String}
    scts::Bool
    supported_versions::Vector{UInt16}
    cookie::Vector{UInt8}
    key_shares::Vector{_TLSKeyShare}
    early_data::Bool
    psk_modes::Vector{UInt8}
    psk_identities::Vector{_TLSPSKIdentity}
    psk_binders::Vector{Vector{UInt8}}
    quic_transport_parameters::Union{Nothing, Vector{UInt8}}
    encrypted_client_hello::Vector{UInt8}
    extensions::Vector{UInt16}
end

function _ClientHelloMsg(original::Union{Nothing, Vector{UInt8}} = nothing)
    return _ClientHelloMsg(
        original,
        TLS1_2_VERSION,
        zeros(UInt8, 32),
        UInt8[],
        UInt16[],
        UInt8[_TLS_COMPRESSION_NONE],
        "",
        false,
        UInt16[],
        UInt8[],
        false,
        UInt8[],
        UInt16[],
        UInt16[],
        false,
        UInt8[],
        false,
        String[],
        false,
        UInt16[],
        UInt8[],
        _TLSKeyShare[],
        false,
        UInt8[],
        _TLSPSKIdentity[],
        Vector{UInt8}[],
        nothing,
        UInt8[],
        UInt16[],
    )
end

Base.:(==)(a::_ClientHelloMsg, b::_ClientHelloMsg) =
    a.vers == b.vers &&
    a.random == b.random &&
    a.session_id == b.session_id &&
    a.cipher_suites == b.cipher_suites &&
    a.compression_methods == b.compression_methods &&
    a.server_name == b.server_name &&
    a.ocsp_stapling == b.ocsp_stapling &&
    a.supported_curves == b.supported_curves &&
    a.supported_points == b.supported_points &&
    a.ticket_supported == b.ticket_supported &&
    a.session_ticket == b.session_ticket &&
    a.supported_signature_algorithms == b.supported_signature_algorithms &&
    a.supported_signature_algorithms_cert == b.supported_signature_algorithms_cert &&
    a.secure_renegotiation_supported == b.secure_renegotiation_supported &&
    a.secure_renegotiation == b.secure_renegotiation &&
    a.extended_master_secret == b.extended_master_secret &&
    a.alpn_protocols == b.alpn_protocols &&
    a.scts == b.scts &&
    a.supported_versions == b.supported_versions &&
    a.cookie == b.cookie &&
    a.key_shares == b.key_shares &&
    a.early_data == b.early_data &&
    a.psk_modes == b.psk_modes &&
    a.psk_identities == b.psk_identities &&
    a.psk_binders == b.psk_binders &&
    a.quic_transport_parameters == b.quic_transport_parameters &&
    a.encrypted_client_hello == b.encrypted_client_hello

"""
    _ServerHelloMsg

Julia-owned representation of a TLS ServerHello or HelloRetryRequest.

TLS 1.3 reuses the ServerHello wire shape for HelloRetryRequest, so later
handshake code interprets `random`, `selected_group`, and a few extensions to
decide which branch it is looking at.
"""
mutable struct _ServerHelloMsg <: _HandshakeMessage
    original::Union{Nothing, Vector{UInt8}}
    vers::UInt16
    random::Vector{UInt8}
    session_id::Vector{UInt8}
    cipher_suite::UInt16
    compression_method::UInt8
    ocsp_stapling::Bool
    ticket_supported::Bool
    secure_renegotiation_supported::Bool
    secure_renegotiation::Vector{UInt8}
    extended_master_secret::Bool
    alpn_protocol::String
    scts::Vector{Vector{UInt8}}
    supported_version::UInt16
    server_share::Union{Nothing, _TLSKeyShare}
    selected_identity_present::Bool
    selected_identity::UInt16
    supported_points::Vector{UInt8}
    encrypted_client_hello::Vector{UInt8}
    server_name_ack::Bool
    cookie::Vector{UInt8}
    selected_group::UInt16
end

function _ServerHelloMsg(original::Union{Nothing, Vector{UInt8}} = nothing)
    return _ServerHelloMsg(
        original,
        TLS1_2_VERSION,
        zeros(UInt8, 32),
        UInt8[],
        UInt16(0),
        _TLS_COMPRESSION_NONE,
        false,
        false,
        false,
        UInt8[],
        false,
        "",
        Vector{UInt8}[],
        UInt16(0),
        nothing,
        false,
        UInt16(0),
        UInt8[],
        UInt8[],
        false,
        UInt8[],
        UInt16(0),
    )
end

Base.:(==)(a::_ServerHelloMsg, b::_ServerHelloMsg) =
    a.vers == b.vers &&
    a.random == b.random &&
    a.session_id == b.session_id &&
    a.cipher_suite == b.cipher_suite &&
    a.compression_method == b.compression_method &&
    a.ocsp_stapling == b.ocsp_stapling &&
    a.ticket_supported == b.ticket_supported &&
    a.secure_renegotiation_supported == b.secure_renegotiation_supported &&
    a.secure_renegotiation == b.secure_renegotiation &&
    a.extended_master_secret == b.extended_master_secret &&
    a.alpn_protocol == b.alpn_protocol &&
    a.scts == b.scts &&
    a.supported_version == b.supported_version &&
    a.server_share == b.server_share &&
    a.selected_identity_present == b.selected_identity_present &&
    (!a.selected_identity_present || a.selected_identity == b.selected_identity) &&
    a.supported_points == b.supported_points &&
    a.encrypted_client_hello == b.encrypted_client_hello &&
    a.server_name_ack == b.server_name_ack &&
    a.cookie == b.cookie &&
    a.selected_group == b.selected_group

mutable struct _CertificateMsgTLS12 <: _HandshakeMessage
    certificates::Vector{Vector{UInt8}}
end

_CertificateMsgTLS12() = _CertificateMsgTLS12(Vector{UInt8}[])
Base.:(==)(a::_CertificateMsgTLS12, b::_CertificateMsgTLS12) = a.certificates == b.certificates

mutable struct _ServerKeyExchangeMsgTLS12 <: _HandshakeMessage
    key::Vector{UInt8}
end

_ServerKeyExchangeMsgTLS12() = _ServerKeyExchangeMsgTLS12(UInt8[])
_ServerKeyExchangeMsgTLS12(key::AbstractVector{UInt8}) = _ServerKeyExchangeMsgTLS12(Vector{UInt8}(key))
Base.:(==)(a::_ServerKeyExchangeMsgTLS12, b::_ServerKeyExchangeMsgTLS12) = a.key == b.key

mutable struct _EncryptedExtensionsMsg <: _HandshakeMessage
    alpn_protocol::String
    quic_transport_parameters::Union{Nothing, Vector{UInt8}}
    early_data::Bool
    ech_retry_configs::Vector{UInt8}
    server_name_ack::Bool
end

_EncryptedExtensionsMsg() = _EncryptedExtensionsMsg("", nothing, false, UInt8[], false)

Base.:(==)(a::_EncryptedExtensionsMsg, b::_EncryptedExtensionsMsg) =
    a.alpn_protocol == b.alpn_protocol &&
    a.quic_transport_parameters == b.quic_transport_parameters &&
    a.early_data == b.early_data &&
    a.ech_retry_configs == b.ech_retry_configs &&
    a.server_name_ack == b.server_name_ack

mutable struct _CertificateRequestMsgTLS12 <: _HandshakeMessage
    certificate_types::Vector{UInt8}
    supported_signature_algorithms::Vector{UInt16}
    certificate_authorities::Vector{Vector{UInt8}}
end

_CertificateRequestMsgTLS12() = _CertificateRequestMsgTLS12(UInt8[], UInt16[], Vector{UInt8}[])

Base.:(==)(a::_CertificateRequestMsgTLS12, b::_CertificateRequestMsgTLS12) =
    a.certificate_types == b.certificate_types &&
    a.supported_signature_algorithms == b.supported_signature_algorithms &&
    a.certificate_authorities == b.certificate_authorities

mutable struct _CertificateRequestMsgTLS13 <: _HandshakeMessage
    ocsp_stapling::Bool
    scts::Bool
    supported_signature_algorithms::Vector{UInt16}
    supported_signature_algorithms_cert::Vector{UInt16}
    certificate_authorities::Vector{Vector{UInt8}}
end

_CertificateRequestMsgTLS13() = _CertificateRequestMsgTLS13(false, false, UInt16[], UInt16[], Vector{UInt8}[])

Base.:(==)(a::_CertificateRequestMsgTLS13, b::_CertificateRequestMsgTLS13) =
    a.ocsp_stapling == b.ocsp_stapling &&
    a.scts == b.scts &&
    a.supported_signature_algorithms == b.supported_signature_algorithms &&
    a.supported_signature_algorithms_cert == b.supported_signature_algorithms_cert &&
    a.certificate_authorities == b.certificate_authorities

mutable struct _CertificateMsgTLS13 <: _HandshakeMessage
    certificates::Vector{Vector{UInt8}}
    ocsp_stapling::Bool
    ocsp_staple::Union{Nothing, Vector{UInt8}}
    scts::Bool
    signed_certificate_timestamps::Vector{Vector{UInt8}}
end

_CertificateMsgTLS13() = _CertificateMsgTLS13(Vector{UInt8}[], false, nothing, false, Vector{UInt8}[])

Base.:(==)(a::_CertificateMsgTLS13, b::_CertificateMsgTLS13) =
    a.certificates == b.certificates &&
    a.ocsp_stapling == b.ocsp_stapling &&
    a.ocsp_staple == b.ocsp_staple &&
    a.scts == b.scts &&
    a.signed_certificate_timestamps == b.signed_certificate_timestamps

mutable struct _CertificateVerifyMsg <: _HandshakeMessage
    signature_algorithm::UInt16
    signature::Vector{UInt8}
end

_CertificateVerifyMsg() = _CertificateVerifyMsg(UInt16(0), UInt8[])
_CertificateVerifyMsg(signature_algorithm::UInt16, signature::AbstractVector{UInt8}) = _CertificateVerifyMsg(signature_algorithm, Vector{UInt8}(signature))

Base.:(==)(a::_CertificateVerifyMsg, b::_CertificateVerifyMsg) =
    a.signature_algorithm == b.signature_algorithm &&
    a.signature == b.signature

struct _ServerHelloDoneMsgTLS12 <: _HandshakeMessage end

Base.:(==)(::_ServerHelloDoneMsgTLS12, ::_ServerHelloDoneMsgTLS12) = true

mutable struct _ClientKeyExchangeMsgTLS12 <: _HandshakeMessage
    ciphertext::Vector{UInt8}
end

_ClientKeyExchangeMsgTLS12() = _ClientKeyExchangeMsgTLS12(UInt8[])
_ClientKeyExchangeMsgTLS12(ciphertext::AbstractVector{UInt8}) = _ClientKeyExchangeMsgTLS12(Vector{UInt8}(ciphertext))
Base.:(==)(a::_ClientKeyExchangeMsgTLS12, b::_ClientKeyExchangeMsgTLS12) = a.ciphertext == b.ciphertext

mutable struct _NewSessionTicketMsgTLS12 <: _HandshakeMessage
    lifetime_hint::UInt32
    ticket::Vector{UInt8}
end

_NewSessionTicketMsgTLS12() = _NewSessionTicketMsgTLS12(UInt32(0), UInt8[])
_NewSessionTicketMsgTLS12(lifetime_hint::UInt32, ticket::AbstractVector{UInt8}) = _NewSessionTicketMsgTLS12(lifetime_hint, Vector{UInt8}(ticket))

Base.:(==)(a::_NewSessionTicketMsgTLS12, b::_NewSessionTicketMsgTLS12) =
    a.lifetime_hint == b.lifetime_hint &&
    a.ticket == b.ticket

mutable struct _NewSessionTicketMsgTLS13 <: _HandshakeMessage
    lifetime::UInt32
    age_add::UInt32
    nonce::Vector{UInt8}
    label::Vector{UInt8}
    max_early_data::UInt32
end

_NewSessionTicketMsgTLS13() = _NewSessionTicketMsgTLS13(UInt32(0), UInt32(0), UInt8[], UInt8[], UInt32(0))

Base.:(==)(a::_NewSessionTicketMsgTLS13, b::_NewSessionTicketMsgTLS13) =
    a.lifetime == b.lifetime &&
    a.age_add == b.age_add &&
    a.nonce == b.nonce &&
    a.label == b.label &&
    a.max_early_data == b.max_early_data

mutable struct _FinishedMsg <: _HandshakeMessage
    verify_data::Vector{UInt8}
end

_FinishedMsg() = _FinishedMsg(UInt8[])
_FinishedMsg(verify_data::AbstractVector{UInt8}) = _FinishedMsg(Vector{UInt8}(verify_data))
Base.:(==)(a::_FinishedMsg, b::_FinishedMsg) = a.verify_data == b.verify_data

"""
    _HandshakeReader

Small bounds-checked cursor over one owned handshake frame.

The marshal/unmarshal helpers use this rather than raw indexing so malformed
messages fail in one place and the higher-level parsers can stay mostly linear.
"""
mutable struct _HandshakeReader
    data::Vector{UInt8}
    pos::Int
end

_HandshakeReader(data::Vector{UInt8}) = _HandshakeReader(data, 1)
_HandshakeReader(data::AbstractVector{UInt8}) = _HandshakeReader(Vector{UInt8}(data), 1)

@inline function _reader_empty(reader::_HandshakeReader)::Bool
    return reader.pos > length(reader.data)
end

@inline function _reader_remaining(reader::_HandshakeReader)::Int
    return length(reader.data) - reader.pos + 1
end

@inline function _read_u8!(reader::_HandshakeReader)::Union{UInt8, Nothing}
    reader.pos > length(reader.data) && return nothing
    out = reader.data[reader.pos]
    reader.pos += 1
    return out
end

@inline function _read_u16!(reader::_HandshakeReader)::Union{UInt16, Nothing}
    reader.pos + 1 > length(reader.data) && return nothing
    hi = UInt16(reader.data[reader.pos])
    lo = UInt16(reader.data[reader.pos + 1])
    reader.pos += 2
    return (hi << 8) | lo
end

@inline function _read_u24!(reader::_HandshakeReader)::Union{Int, Nothing}
    reader.pos + 2 > length(reader.data) && return nothing
    out = (Int(reader.data[reader.pos]) << 16) | (Int(reader.data[reader.pos + 1]) << 8) | Int(reader.data[reader.pos + 2])
    reader.pos += 3
    return out
end

@inline function _read_u32!(reader::_HandshakeReader)::Union{UInt32, Nothing}
    reader.pos + 3 > length(reader.data) && return nothing
    b1 = UInt32(reader.data[reader.pos])
    b2 = UInt32(reader.data[reader.pos + 1])
    b3 = UInt32(reader.data[reader.pos + 2])
    b4 = UInt32(reader.data[reader.pos + 3])
    reader.pos += 4
    return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4
end

function _read_bytes!(reader::_HandshakeReader, n::Int)::Union{Vector{UInt8}, Nothing}
    n < 0 && return nothing
    n == 0 && return UInt8[]
    reader.pos + n - 1 > length(reader.data) && return nothing
    out = Vector{UInt8}(undef, n)
    copyto!(out, 1, reader.data, reader.pos, n)
    reader.pos += n
    return out
end

@inline function _read_remaining_bytes!(reader::_HandshakeReader)::Vector{UInt8}
    return _read_bytes!(reader, length(reader.data) - reader.pos + 1)::Vector{UInt8}
end

@inline function _skip_remaining!(reader::_HandshakeReader)::Nothing
    reader.pos = length(reader.data) + 1
    return nothing
end

function _read_u8_length_prefixed_bytes!(reader::_HandshakeReader)::Union{Vector{UInt8}, Nothing}
    n = _read_u8!(reader)
    n === nothing && return nothing
    return _read_bytes!(reader, Int(n))
end

function _read_u16_length_prefixed_bytes!(reader::_HandshakeReader)::Union{Vector{UInt8}, Nothing}
    n = _read_u16!(reader)
    n === nothing && return nothing
    return _read_bytes!(reader, Int(n))
end

function _read_u24_length_prefixed_bytes!(reader::_HandshakeReader)::Union{Vector{UInt8}, Nothing}
    n = _read_u24!(reader)
    n === nothing && return nothing
    return _read_bytes!(reader, n)
end

function _read_u16_length_prefixed_reader!(reader::_HandshakeReader)::Union{_HandshakeReader, Nothing}
    bytes = _read_u16_length_prefixed_bytes!(reader)
    bytes === nothing && return nothing
    return _HandshakeReader(bytes)
end

function _read_u24_length_prefixed_reader!(reader::_HandshakeReader)::Union{_HandshakeReader, Nothing}
    bytes = _read_u24_length_prefixed_bytes!(reader)
    bytes === nothing && return nothing
    return _HandshakeReader(bytes)
end

# These append helpers centralize TLS length-prefix framing so the individual
# message marshaling routines can stay readable and mirror the RFC / Go layout.
@inline function _append_u8!(buf::Vector{UInt8}, v::Integer)
    push!(buf, UInt8(v))
    return nothing
end

@inline function _append_u16!(buf::Vector{UInt8}, v::UInt16)
    push!(buf, UInt8(v >> 8), UInt8(v & UInt16(0x00ff)))
    return nothing
end

@inline function _append_u32!(buf::Vector{UInt8}, v::UInt32)
    push!(buf, UInt8(v >> 24), UInt8((v >> 16) & UInt32(0x000000ff)), UInt8((v >> 8) & UInt32(0x000000ff)), UInt8(v & UInt32(0x000000ff)))
    return nothing
end

function _append_u24!(buf::Vector{UInt8}, v::Int)
    0 <= v <= 0x00ff_ffff || throw(ArgumentError("uint24 value out of range: $(v)"))
    push!(buf, UInt8(v >> 16), UInt8((v >> 8) & 0xff), UInt8(v & 0xff))
    return nothing
end

function _append_u8_length_prefixed!(f::F, buf::Vector{UInt8}) where {F}
    prefix_pos = length(buf) + 1
    push!(buf, 0x00)
    body_start = length(buf) + 1
    f(buf)
    len = length(buf) - body_start + 1
    len <= 0xff || throw(ArgumentError("uint8 length prefix overflow: $(len)"))
    buf[prefix_pos] = UInt8(len)
    return nothing
end

function _append_u16_length_prefixed!(f::F, buf::Vector{UInt8}) where {F}
    prefix_pos = length(buf) + 1
    push!(buf, 0x00, 0x00)
    body_start = length(buf) + 1
    f(buf)
    len = length(buf) - body_start + 1
    len <= typemax(UInt16) || throw(ArgumentError("uint16 length prefix overflow: $(len)"))
    value = UInt16(len)
    buf[prefix_pos] = UInt8(value >> 8)
    buf[prefix_pos + 1] = UInt8(value & UInt16(0x00ff))
    return nothing
end

function _append_u24_length_prefixed!(f::F, buf::Vector{UInt8}) where {F}
    prefix_pos = length(buf) + 1
    push!(buf, 0x00, 0x00, 0x00)
    body_start = length(buf) + 1
    f(buf)
    len = length(buf) - body_start + 1
    len <= 0x00ff_ffff || throw(ArgumentError("uint24 length prefix overflow: $(len)"))
    buf[prefix_pos] = UInt8(len >> 16)
    buf[prefix_pos + 1] = UInt8((len >> 8) & 0xff)
    buf[prefix_pos + 2] = UInt8(len & 0xff)
    return nothing
end

function _append_extension!(f::F, buf::Vector{UInt8}, extension::UInt16) where {F}
    _append_u16!(buf, extension)
    _append_u16_length_prefixed!(f, buf)
    return nothing
end

function _append_extension!(buf::Vector{UInt8}, extension::UInt16)
    _append_u16!(buf, extension)
    push!(buf, 0x00, 0x00)
    return nothing
end

function _append_fixed_bytes!(buf::Vector{UInt8}, bytes::AbstractVector{UInt8}, expected_len::Int, label::AbstractString)
    length(bytes) == expected_len || throw(ArgumentError("invalid $(label) length: expected $(expected_len), got $(length(bytes))"))
    append!(buf, bytes)
    return nothing
end

function _copy_valid_handshake_frame(data::AbstractVector{UInt8})::Union{Vector{UInt8}, Nothing}
    length(data) < 4 && return nothing
    body_len = (Int(data[2]) << 16) | (Int(data[3]) << 8) | Int(data[4])
    body_len <= _MAX_HANDSHAKE_SIZE || throw(ArgumentError("tls: handshake message of length $(body_len) bytes exceeds maximum of $(_MAX_HANDSHAKE_SIZE) bytes"))
    length(data) == body_len + 4 || return nothing
    return copy(data)
end

function _marshal_client_hello(msg::_ClientHelloMsg)::Vector{UInt8}
    !isempty(msg.psk_identities) && length(msg.psk_identities) != length(msg.psk_binders) &&
        throw(ArgumentError("client hello psk_identities and psk_binders must have the same length"))

    exts = UInt8[]
    sni_name = isempty(msg.server_name) ? "" : _hostname_in_sni(msg.server_name)
    if !isempty(sni_name)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_SERVER_NAME) do exts_buf
            _append_u16_length_prefixed!(exts_buf) do name_list_buf
                _append_u8!(name_list_buf, 0)
                _append_u16_length_prefixed!(name_list_buf) do server_name_buf
                    append!(server_name_buf, codeunits(sni_name))
                end
            end
        end
    end
    if !isempty(msg.supported_points)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_SUPPORTED_POINTS) do exts_buf
            _append_u8_length_prefixed!(exts_buf) do points_buf
                append!(points_buf, msg.supported_points)
            end
        end
    end
    if msg.ticket_supported
        _append_extension!(exts, _HANDSHAKE_EXTENSION_SESSION_TICKET) do exts_buf
            append!(exts_buf, msg.session_ticket)
        end
    end
    if msg.secure_renegotiation_supported
        _append_extension!(exts, _HANDSHAKE_EXTENSION_RENEGOTIATION_INFO) do exts_buf
            _append_u8_length_prefixed!(exts_buf) do info_buf
                append!(info_buf, msg.secure_renegotiation)
            end
        end
    end
    msg.extended_master_secret && _append_extension!(exts, _HANDSHAKE_EXTENSION_EXTENDED_MASTER_SECRET)
    msg.scts && _append_extension!(exts, _HANDSHAKE_EXTENSION_SCT)
    msg.early_data && _append_extension!(exts, _HANDSHAKE_EXTENSION_EARLY_DATA)
    if msg.quic_transport_parameters !== nothing
        quic_transport_parameters = msg.quic_transport_parameters::Vector{UInt8}
        _append_extension!(exts, _HANDSHAKE_EXTENSION_QUIC_TRANSPORT_PARAMETERS) do exts_buf
            append!(exts_buf, quic_transport_parameters)
        end
    end
    if !isempty(msg.encrypted_client_hello)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_ENCRYPTED_CLIENT_HELLO) do exts_buf
            append!(exts_buf, msg.encrypted_client_hello)
        end
    end
    if msg.ocsp_stapling
        _append_extension!(exts, _HANDSHAKE_EXTENSION_STATUS_REQUEST) do exts_buf
            _append_u8!(exts_buf, _TLS_STATUS_TYPE_OCSP)
            _append_u16!(exts_buf, 0x0000)
            _append_u16!(exts_buf, 0x0000)
        end
    end
    if !isempty(msg.supported_curves)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_SUPPORTED_CURVES) do exts_buf
            _append_u16_length_prefixed!(exts_buf) do curves_buf
                for curve in msg.supported_curves
                    _append_u16!(curves_buf, curve)
                end
            end
        end
    end
    if !isempty(msg.supported_signature_algorithms)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_SIGNATURE_ALGORITHMS) do exts_buf
            _append_u16_length_prefixed!(exts_buf) do sigalgs_buf
                for sigalg in msg.supported_signature_algorithms
                    _append_u16!(sigalgs_buf, sigalg)
                end
            end
        end
    end
    if !isempty(msg.supported_signature_algorithms_cert)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_SIGNATURE_ALGORITHMS_CERT) do exts_buf
            _append_u16_length_prefixed!(exts_buf) do sigalgs_buf
                for sigalg in msg.supported_signature_algorithms_cert
                    _append_u16!(sigalgs_buf, sigalg)
                end
            end
        end
    end
    if !isempty(msg.alpn_protocols)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_ALPN) do exts_buf
            _append_u16_length_prefixed!(exts_buf) do protocol_list_buf
                for protocol in msg.alpn_protocols
                    _append_u8_length_prefixed!(protocol_list_buf) do protocol_buf
                        append!(protocol_buf, codeunits(protocol))
                    end
                end
            end
        end
    end
    if !isempty(msg.supported_versions)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_SUPPORTED_VERSIONS) do exts_buf
            _append_u8_length_prefixed!(exts_buf) do versions_buf
                for version in msg.supported_versions
                    _append_u16!(versions_buf, version)
                end
            end
        end
    end
    if !isempty(msg.cookie)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_COOKIE) do exts_buf
            _append_u16_length_prefixed!(exts_buf) do cookie_buf
                append!(cookie_buf, msg.cookie)
            end
        end
    end
    if !isempty(msg.key_shares)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_KEY_SHARE) do exts_buf
            _append_u16_length_prefixed!(exts_buf) do shares_buf
                for share in msg.key_shares
                    _append_u16!(shares_buf, share.group)
                    _append_u16_length_prefixed!(shares_buf) do share_buf
                        append!(share_buf, share.data)
                    end
                end
            end
        end
    end
    if !isempty(msg.psk_modes)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_PSK_MODES) do exts_buf
            _append_u8_length_prefixed!(exts_buf) do modes_buf
                append!(modes_buf, msg.psk_modes)
            end
        end
    end
    if !isempty(msg.psk_identities)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_PRE_SHARED_KEY) do exts_buf
            _append_u16_length_prefixed!(exts_buf) do identities_buf
                for identity in msg.psk_identities
                    _append_u16_length_prefixed!(identities_buf) do label_buf
                        append!(label_buf, identity.label)
                    end
                    _append_u32!(identities_buf, identity.obfuscated_ticket_age)
                end
            end
            _append_u16_length_prefixed!(exts_buf) do binders_buf
                for binder in msg.psk_binders
                    _append_u8_length_prefixed!(binders_buf) do binder_buf
                        append!(binder_buf, binder)
                    end
                end
            end
        end
    end

    out = UInt8[]
    _append_u8!(out, _HANDSHAKE_TYPE_CLIENT_HELLO)
    _append_u24_length_prefixed!(out) do body_buf
        _append_u16!(body_buf, msg.vers)
        _append_fixed_bytes!(body_buf, msg.random, 32, "client hello random")
        _append_u8_length_prefixed!(body_buf) do session_id_buf
            append!(session_id_buf, msg.session_id)
        end
        _append_u16_length_prefixed!(body_buf) do cipher_suites_buf
            for cipher_suite in msg.cipher_suites
                _append_u16!(cipher_suites_buf, cipher_suite)
            end
        end
        _append_u8_length_prefixed!(body_buf) do compression_methods_buf
            append!(compression_methods_buf, msg.compression_methods)
        end
        !isempty(exts) && _append_u16_length_prefixed!(body_buf) do extensions_buf
            append!(extensions_buf, exts)
        end
    end
    return out
end

function _marshal_client_hello_without_binders(msg::_ClientHelloMsg)
    isempty(msg.psk_identities) && return _handshake_transcript_bytes(msg)

    binders_len = 2
    for binder in msg.psk_binders
        binders_len += 1 + length(binder)
    end

    full_message = _handshake_transcript_bytes(msg)
    binders_len <= length(full_message) || throw(ArgumentError("client hello binders exceed message length"))
    prefix_len = length(full_message) - binders_len
    return @view full_message[1:prefix_len]
end

function _update_client_hello_binders!(msg::_ClientHelloMsg, psk_binders::Vector{Vector{UInt8}})
    length(psk_binders) == length(msg.psk_binders) || throw(ArgumentError("client hello psk binders length mismatch"))
    for i in eachindex(psk_binders, msg.psk_binders)
        length(psk_binders[i]) == length(msg.psk_binders[i]) || throw(ArgumentError("client hello psk binders length mismatch"))
    end
    msg.psk_binders = _copy_byte_vectors(psk_binders)
    msg.original = nothing
    return nothing
end

function _marshal_server_hello(msg::_ServerHelloMsg)::Vector{UInt8}
    msg.server_share !== nothing && msg.selected_group != 0x0000 &&
        throw(ArgumentError("server hello cannot encode both server_share and selected_group"))
    msg.server_share !== nothing && isempty((msg.server_share::_TLSKeyShare).data) &&
        throw(ArgumentError("server hello key share data must be non-empty"))

    exts = UInt8[]
    msg.ocsp_stapling && _append_extension!(exts, _HANDSHAKE_EXTENSION_STATUS_REQUEST)
    msg.ticket_supported && _append_extension!(exts, _HANDSHAKE_EXTENSION_SESSION_TICKET)
    if msg.secure_renegotiation_supported
        _append_extension!(exts, _HANDSHAKE_EXTENSION_RENEGOTIATION_INFO) do exts_buf
            _append_u8_length_prefixed!(exts_buf) do info_buf
                append!(info_buf, msg.secure_renegotiation)
            end
        end
    end
    msg.extended_master_secret && _append_extension!(exts, _HANDSHAKE_EXTENSION_EXTENDED_MASTER_SECRET)
    if !isempty(msg.alpn_protocol)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_ALPN) do exts_buf
            _append_u16_length_prefixed!(exts_buf) do protocol_list_buf
                _append_u8_length_prefixed!(protocol_list_buf) do protocol_buf
                    append!(protocol_buf, codeunits(msg.alpn_protocol))
                end
            end
        end
    end
    if !isempty(msg.scts)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_SCT) do exts_buf
            _append_u16_length_prefixed!(exts_buf) do scts_buf
                for sct in msg.scts
                    _append_u16_length_prefixed!(scts_buf) do sct_buf
                        append!(sct_buf, sct)
                    end
                end
            end
        end
    end
    msg.supported_version != 0x0000 && _append_extension!(exts, _HANDSHAKE_EXTENSION_SUPPORTED_VERSIONS) do exts_buf
        _append_u16!(exts_buf, msg.supported_version)
    end
    if msg.server_share !== nothing
        server_share = msg.server_share::_TLSKeyShare
        _append_extension!(exts, _HANDSHAKE_EXTENSION_KEY_SHARE) do exts_buf
            _append_u16!(exts_buf, server_share.group)
            _append_u16_length_prefixed!(exts_buf) do share_buf
                append!(share_buf, server_share.data)
            end
        end
    end
    if msg.selected_identity_present
        _append_extension!(exts, _HANDSHAKE_EXTENSION_PRE_SHARED_KEY) do exts_buf
            _append_u16!(exts_buf, msg.selected_identity)
        end
    end
    if !isempty(msg.cookie)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_COOKIE) do exts_buf
            _append_u16_length_prefixed!(exts_buf) do cookie_buf
                append!(cookie_buf, msg.cookie)
            end
        end
    end
    if msg.selected_group != 0x0000
        _append_extension!(exts, _HANDSHAKE_EXTENSION_KEY_SHARE) do exts_buf
            _append_u16!(exts_buf, msg.selected_group)
        end
    end
    if !isempty(msg.supported_points)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_SUPPORTED_POINTS) do exts_buf
            _append_u8_length_prefixed!(exts_buf) do points_buf
                append!(points_buf, msg.supported_points)
            end
        end
    end
    if !isempty(msg.encrypted_client_hello)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_ENCRYPTED_CLIENT_HELLO) do exts_buf
            append!(exts_buf, msg.encrypted_client_hello)
        end
    end
    msg.server_name_ack && _append_extension!(exts, _HANDSHAKE_EXTENSION_SERVER_NAME)

    out = UInt8[]
    _append_u8!(out, _HANDSHAKE_TYPE_SERVER_HELLO)
    _append_u24_length_prefixed!(out) do body_buf
        _append_u16!(body_buf, msg.vers)
        _append_fixed_bytes!(body_buf, msg.random, 32, "server hello random")
        _append_u8_length_prefixed!(body_buf) do session_id_buf
            append!(session_id_buf, msg.session_id)
        end
        _append_u16!(body_buf, msg.cipher_suite)
        _append_u8!(body_buf, msg.compression_method)
        !isempty(exts) && _append_u16_length_prefixed!(body_buf) do extensions_buf
            append!(extensions_buf, exts)
        end
    end
    return out
end

function _marshal_certificate_tls12(msg::_CertificateMsgTLS12)::Vector{UInt8}
    out = UInt8[]
    _append_u8!(out, _HANDSHAKE_TYPE_CERTIFICATE)
    _append_u24_length_prefixed!(out) do body_buf
        _append_u24_length_prefixed!(body_buf) do certificates_buf
            for certificate in msg.certificates
                _append_u24_length_prefixed!(certificates_buf) do certificate_buf
                    append!(certificate_buf, certificate)
                end
            end
        end
    end
    return out
end

function _marshal_server_key_exchange_tls12(msg::_ServerKeyExchangeMsgTLS12)::Vector{UInt8}
    out = UInt8[]
    _append_u8!(out, _HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE)
    _append_u24_length_prefixed!(out) do body_buf
        append!(body_buf, msg.key)
    end
    return out
end

function _marshal_encrypted_extensions(msg::_EncryptedExtensionsMsg)::Vector{UInt8}
    out = UInt8[]
    _append_u8!(out, _HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS)
    _append_u24_length_prefixed!(out) do body_buf
        _append_u16_length_prefixed!(body_buf) do extensions_buf
            if !isempty(msg.alpn_protocol)
                _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_ALPN) do exts_buf
                    _append_u16_length_prefixed!(exts_buf) do protocol_list_buf
                        _append_u8_length_prefixed!(protocol_list_buf) do protocol_buf
                            append!(protocol_buf, codeunits(msg.alpn_protocol))
                        end
                    end
                end
            end
            if msg.quic_transport_parameters !== nothing
                quic_transport_parameters = msg.quic_transport_parameters::Vector{UInt8}
                _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_QUIC_TRANSPORT_PARAMETERS) do exts_buf
                    append!(exts_buf, quic_transport_parameters)
                end
            end
            msg.early_data && _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_EARLY_DATA)
            if !isempty(msg.ech_retry_configs)
                _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_ENCRYPTED_CLIENT_HELLO) do exts_buf
                    append!(exts_buf, msg.ech_retry_configs)
                end
            end
            msg.server_name_ack && _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_SERVER_NAME)
        end
    end
    return out
end

function _marshal_certificate_request_tls12(msg::_CertificateRequestMsgTLS12)::Vector{UInt8}
    out = UInt8[]
    _append_u8!(out, _HANDSHAKE_TYPE_CERTIFICATE_REQUEST)
    _append_u24_length_prefixed!(out) do body_buf
        _append_u8_length_prefixed!(body_buf) do types_buf
            append!(types_buf, msg.certificate_types)
        end
        _append_u16_length_prefixed!(body_buf) do sigalgs_buf
            for sigalg in msg.supported_signature_algorithms
                _append_u16!(sigalgs_buf, sigalg)
            end
        end
        _append_u16_length_prefixed!(body_buf) do authorities_buf
            for authority in msg.certificate_authorities
                _append_u16_length_prefixed!(authorities_buf) do authority_buf
                    append!(authority_buf, authority)
                end
            end
        end
    end
    return out
end

function _marshal_certificate_request_tls13(msg::_CertificateRequestMsgTLS13)::Vector{UInt8}
    out = UInt8[]
    _append_u8!(out, _HANDSHAKE_TYPE_CERTIFICATE_REQUEST)
    _append_u24_length_prefixed!(out) do body_buf
        _append_u8!(body_buf, 0)
        _append_u16_length_prefixed!(body_buf) do extensions_buf
            msg.ocsp_stapling && _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_STATUS_REQUEST)
            msg.scts && _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_SCT)
            if !isempty(msg.supported_signature_algorithms)
                _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_SIGNATURE_ALGORITHMS) do exts_buf
                    _append_u16_length_prefixed!(exts_buf) do sigalgs_buf
                        for sigalg in msg.supported_signature_algorithms
                            _append_u16!(sigalgs_buf, sigalg)
                        end
                    end
                end
            end
            if !isempty(msg.supported_signature_algorithms_cert)
                _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_SIGNATURE_ALGORITHMS_CERT) do exts_buf
                    _append_u16_length_prefixed!(exts_buf) do sigalgs_buf
                        for sigalg in msg.supported_signature_algorithms_cert
                            _append_u16!(sigalgs_buf, sigalg)
                        end
                    end
                end
            end
            if !isempty(msg.certificate_authorities)
                _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_CERTIFICATE_AUTHORITIES) do exts_buf
                    _append_u16_length_prefixed!(exts_buf) do authorities_buf
                        for authority in msg.certificate_authorities
                            _append_u16_length_prefixed!(authorities_buf) do authority_buf
                                append!(authority_buf, authority)
                            end
                        end
                    end
                end
            end
        end
    end
    return out
end

function _marshal_certificate_tls13(msg::_CertificateMsgTLS13)::Vector{UInt8}
    msg.ocsp_stapling && (msg.ocsp_staple === nothing || isempty(msg.ocsp_staple::Vector{UInt8})) &&
        throw(ArgumentError("tls13 certificate message requires a non-empty OCSP staple when ocsp_stapling is set"))
    msg.scts && isempty(msg.signed_certificate_timestamps) &&
        throw(ArgumentError("tls13 certificate message requires a non-empty SCT list when scts is set"))

    out = UInt8[]
    _append_u8!(out, _HANDSHAKE_TYPE_CERTIFICATE)
    _append_u24_length_prefixed!(out) do body_buf
        _append_u8!(body_buf, 0)
        _append_u24_length_prefixed!(body_buf) do certificates_buf
            for i in eachindex(msg.certificates)
                certificate = msg.certificates[i]
                _append_u24_length_prefixed!(certificates_buf) do certificate_buf
                    append!(certificate_buf, certificate)
                end
                _append_u16_length_prefixed!(certificates_buf) do extensions_buf
                    i == firstindex(msg.certificates) || return nothing
                    if msg.ocsp_stapling
                        ocsp_staple = msg.ocsp_staple::Vector{UInt8}
                        _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_STATUS_REQUEST) do exts_buf
                            _append_u8!(exts_buf, _TLS_STATUS_TYPE_OCSP)
                            _append_u24_length_prefixed!(exts_buf) do staple_buf
                                append!(staple_buf, ocsp_staple)
                            end
                        end
                    end
                    if msg.scts
                        _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_SCT) do exts_buf
                            _append_u16_length_prefixed!(exts_buf) do scts_buf
                                for sct in msg.signed_certificate_timestamps
                                    _append_u16_length_prefixed!(scts_buf) do sct_buf
                                        append!(sct_buf, sct)
                                    end
                                end
                            end
                        end
                    end
                end
            end
        end
    end
    return out
end

function _marshal_certificate_verify(msg::_CertificateVerifyMsg)::Vector{UInt8}
    out = UInt8[]
    _append_u8!(out, _HANDSHAKE_TYPE_CERTIFICATE_VERIFY)
    _append_u24_length_prefixed!(out) do body_buf
        _append_u16!(body_buf, msg.signature_algorithm)
        _append_u16_length_prefixed!(body_buf) do signature_buf
            append!(signature_buf, msg.signature)
        end
    end
    return out
end

function _marshal_server_hello_done_tls12(::_ServerHelloDoneMsgTLS12)::Vector{UInt8}
    return UInt8[
        _HANDSHAKE_TYPE_SERVER_HELLO_DONE,
        0x00,
        0x00,
        0x00,
    ]
end

function _marshal_client_key_exchange_tls12(msg::_ClientKeyExchangeMsgTLS12)::Vector{UInt8}
    out = UInt8[]
    _append_u8!(out, _HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE)
    _append_u24_length_prefixed!(out) do body_buf
        append!(body_buf, msg.ciphertext)
    end
    return out
end

function _marshal_new_session_ticket_tls12(msg::_NewSessionTicketMsgTLS12)::Vector{UInt8}
    out = UInt8[]
    _append_u8!(out, _HANDSHAKE_TYPE_NEW_SESSION_TICKET)
    _append_u24_length_prefixed!(out) do body_buf
        _append_u32!(body_buf, msg.lifetime_hint)
        _append_u16_length_prefixed!(body_buf) do ticket_buf
            append!(ticket_buf, msg.ticket)
        end
    end
    return out
end

function _marshal_new_session_ticket_tls13(msg::_NewSessionTicketMsgTLS13)::Vector{UInt8}
    out = UInt8[]
    _append_u8!(out, _HANDSHAKE_TYPE_NEW_SESSION_TICKET)
    _append_u24_length_prefixed!(out) do body_buf
        _append_u32!(body_buf, msg.lifetime)
        _append_u32!(body_buf, msg.age_add)
        _append_u8_length_prefixed!(body_buf) do nonce_buf
            append!(nonce_buf, msg.nonce)
        end
        _append_u16_length_prefixed!(body_buf) do label_buf
            append!(label_buf, msg.label)
        end
        _append_u16_length_prefixed!(body_buf) do extensions_buf
            if msg.max_early_data > 0
                _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_EARLY_DATA) do exts_buf
                    _append_u32!(exts_buf, msg.max_early_data)
                end
            end
        end
    end
    return out
end

function _marshal_finished(msg::_FinishedMsg)::Vector{UInt8}
    out = UInt8[]
    _append_u8!(out, _HANDSHAKE_TYPE_FINISHED)
    _append_u24_length_prefixed!(out) do body_buf
        append!(body_buf, msg.verify_data)
    end
    return out
end

function _unmarshal_client_hello(data::Vector{UInt8})::Union{_ClientHelloMsg, Nothing}
    msg = _ClientHelloMsg(data)
    reader = _HandshakeReader(data)
    _read_u8!(reader) == _HANDSHAKE_TYPE_CLIENT_HELLO || return nothing
    _read_u24!(reader) == length(data) - 4 || return nothing

    vers = _read_u16!(reader)
    random = _read_bytes!(reader, 32)
    session_id = _read_u8_length_prefixed_bytes!(reader)
    (vers === nothing || random === nothing || session_id === nothing) && return nothing
    msg.vers = vers
    msg.random = random
    msg.session_id = session_id

    cipher_suites_reader = _read_u16_length_prefixed_reader!(reader)
    cipher_suites_reader === nothing && return nothing
    msg.cipher_suites = UInt16[]
    msg.secure_renegotiation_supported = false
    while !_reader_empty(cipher_suites_reader)
        cipher_suite = _read_u16!(cipher_suites_reader)
        cipher_suite === nothing && return nothing
        cipher_suite == _TLS_SCSV_RENEGOTIATION && (msg.secure_renegotiation_supported = true)
        push!(msg.cipher_suites, cipher_suite)
    end

    compression_methods = _read_u8_length_prefixed_bytes!(reader)
    compression_methods === nothing && return nothing
    msg.compression_methods = compression_methods

    _reader_empty(reader) && return msg

    extensions_reader = _read_u16_length_prefixed_reader!(reader)
    (extensions_reader === nothing || !_reader_empty(reader)) && return nothing

    seen_extensions = Set{UInt16}()
    while !_reader_empty(extensions_reader)
        extension = _read_u16!(extensions_reader)
        ext_reader = _read_u16_length_prefixed_reader!(extensions_reader)
        (extension === nothing || ext_reader === nothing) && return nothing
        in(extension, seen_extensions) && return nothing
        push!(seen_extensions, extension)
        push!(msg.extensions, extension)

        if extension == _HANDSHAKE_EXTENSION_SERVER_NAME
            name_list_reader = _read_u16_length_prefixed_reader!(ext_reader)
            (name_list_reader === nothing || _reader_empty(name_list_reader)) && return nothing
            while !_reader_empty(name_list_reader)
                name_type = _read_u8!(name_list_reader)
                server_name_bytes = _read_u16_length_prefixed_bytes!(name_list_reader)
                (name_type === nothing || server_name_bytes === nothing || isempty(server_name_bytes)) && return nothing
                name_type == 0x00 || continue
                isempty(msg.server_name) || return nothing
                isvalid(String, server_name_bytes) || return nothing
                server_name = String(server_name_bytes)
                endswith(server_name, ".") && return nothing
                msg.server_name = server_name
            end
        elseif extension == _HANDSHAKE_EXTENSION_STATUS_REQUEST
            status_type = _read_u8!(ext_reader)
            responder_ids = _read_u16_length_prefixed_bytes!(ext_reader)
            request_extensions = _read_u16_length_prefixed_bytes!(ext_reader)
            (status_type === nothing || responder_ids === nothing || request_extensions === nothing) && return nothing
            msg.ocsp_stapling = status_type == _TLS_STATUS_TYPE_OCSP
        elseif extension == _HANDSHAKE_EXTENSION_SUPPORTED_CURVES
            curves_reader = _read_u16_length_prefixed_reader!(ext_reader)
            (curves_reader === nothing || _reader_empty(curves_reader)) && return nothing
            msg.supported_curves = UInt16[]
            while !_reader_empty(curves_reader)
                curve = _read_u16!(curves_reader)
                curve === nothing && return nothing
                push!(msg.supported_curves, curve)
            end
        elseif extension == _HANDSHAKE_EXTENSION_SUPPORTED_POINTS
            supported_points = _read_u8_length_prefixed_bytes!(ext_reader)
            (supported_points === nothing || isempty(supported_points)) && return nothing
            msg.supported_points = supported_points
        elseif extension == _HANDSHAKE_EXTENSION_SESSION_TICKET
            msg.ticket_supported = true
            msg.session_ticket = _read_remaining_bytes!(ext_reader)
        elseif extension == _HANDSHAKE_EXTENSION_SIGNATURE_ALGORITHMS
            sigalgs_reader = _read_u16_length_prefixed_reader!(ext_reader)
            (sigalgs_reader === nothing || _reader_empty(sigalgs_reader)) && return nothing
            msg.supported_signature_algorithms = UInt16[]
            while !_reader_empty(sigalgs_reader)
                sigalg = _read_u16!(sigalgs_reader)
                sigalg === nothing && return nothing
                push!(msg.supported_signature_algorithms, sigalg)
            end
        elseif extension == _HANDSHAKE_EXTENSION_SIGNATURE_ALGORITHMS_CERT
            sigalgs_reader = _read_u16_length_prefixed_reader!(ext_reader)
            (sigalgs_reader === nothing || _reader_empty(sigalgs_reader)) && return nothing
            msg.supported_signature_algorithms_cert = UInt16[]
            while !_reader_empty(sigalgs_reader)
                sigalg = _read_u16!(sigalgs_reader)
                sigalg === nothing && return nothing
                push!(msg.supported_signature_algorithms_cert, sigalg)
            end
        elseif extension == _HANDSHAKE_EXTENSION_RENEGOTIATION_INFO
            secure_renegotiation = _read_u8_length_prefixed_bytes!(ext_reader)
            secure_renegotiation === nothing && return nothing
            msg.secure_renegotiation = secure_renegotiation
            msg.secure_renegotiation_supported = true
        elseif extension == _HANDSHAKE_EXTENSION_EXTENDED_MASTER_SECRET
            msg.extended_master_secret = true
        elseif extension == _HANDSHAKE_EXTENSION_ALPN
            protocol_list_reader = _read_u16_length_prefixed_reader!(ext_reader)
            (protocol_list_reader === nothing || _reader_empty(protocol_list_reader)) && return nothing
            msg.alpn_protocols = String[]
            while !_reader_empty(protocol_list_reader)
                protocol_bytes = _read_u8_length_prefixed_bytes!(protocol_list_reader)
                (protocol_bytes === nothing || isempty(protocol_bytes)) && return nothing
                isvalid(String, protocol_bytes) || return nothing
                protocol = String(protocol_bytes)
                push!(msg.alpn_protocols, protocol)
            end
        elseif extension == _HANDSHAKE_EXTENSION_SCT
            msg.scts = true
        elseif extension == _HANDSHAKE_EXTENSION_SUPPORTED_VERSIONS
            versions_reader = _read_u8_length_prefixed_bytes!(ext_reader)
            (versions_reader === nothing || isempty(versions_reader)) && return nothing
            versions_bytes_reader = _HandshakeReader(versions_reader)
            msg.supported_versions = UInt16[]
            while !_reader_empty(versions_bytes_reader)
                version = _read_u16!(versions_bytes_reader)
                version === nothing && return nothing
                push!(msg.supported_versions, version)
            end
        elseif extension == _HANDSHAKE_EXTENSION_COOKIE
            cookie = _read_u16_length_prefixed_bytes!(ext_reader)
            (cookie === nothing || isempty(cookie)) && return nothing
            msg.cookie = cookie
        elseif extension == _HANDSHAKE_EXTENSION_KEY_SHARE
            shares_reader = _read_u16_length_prefixed_reader!(ext_reader)
            shares_reader === nothing && return nothing
            msg.key_shares = _TLSKeyShare[]
            while !_reader_empty(shares_reader)
                group = _read_u16!(shares_reader)
                key_share_data = _read_u16_length_prefixed_bytes!(shares_reader)
                (group === nothing || key_share_data === nothing || isempty(key_share_data)) && return nothing
                push!(msg.key_shares, _TLSKeyShare(group, key_share_data))
            end
        elseif extension == _HANDSHAKE_EXTENSION_EARLY_DATA
            msg.early_data = true
        elseif extension == _HANDSHAKE_EXTENSION_PSK_MODES
            psk_modes = _read_u8_length_prefixed_bytes!(ext_reader)
            psk_modes === nothing && return nothing
            msg.psk_modes = psk_modes
        elseif extension == _HANDSHAKE_EXTENSION_QUIC_TRANSPORT_PARAMETERS
            msg.quic_transport_parameters = _read_remaining_bytes!(ext_reader)
        elseif extension == _HANDSHAKE_EXTENSION_PRE_SHARED_KEY
            _reader_empty(extensions_reader) || return nothing
            identities_reader = _read_u16_length_prefixed_reader!(ext_reader)
            (identities_reader === nothing || _reader_empty(identities_reader)) && return nothing
            msg.psk_identities = _TLSPSKIdentity[]
            while !_reader_empty(identities_reader)
                label = _read_u16_length_prefixed_bytes!(identities_reader)
                obfuscated_ticket_age = _read_u32!(identities_reader)
                (label === nothing || obfuscated_ticket_age === nothing || isempty(label)) && return nothing
                push!(msg.psk_identities, _TLSPSKIdentity(label, obfuscated_ticket_age))
            end
            binders_reader = _read_u16_length_prefixed_reader!(ext_reader)
            (binders_reader === nothing || _reader_empty(binders_reader)) && return nothing
            msg.psk_binders = Vector{UInt8}[]
            while !_reader_empty(binders_reader)
                binder = _read_u8_length_prefixed_bytes!(binders_reader)
                (binder === nothing || isempty(binder)) && return nothing
                push!(msg.psk_binders, binder)
            end
        elseif extension == _HANDSHAKE_EXTENSION_ENCRYPTED_CLIENT_HELLO
            msg.encrypted_client_hello = _read_remaining_bytes!(ext_reader)
        else
            _skip_remaining!(ext_reader)
        end

        _reader_empty(ext_reader) || return nothing
    end

    return msg
end

function _unmarshal_server_hello(data::Vector{UInt8})::Union{_ServerHelloMsg, Nothing}
    msg = _ServerHelloMsg(data)
    reader = _HandshakeReader(data)
    _read_u8!(reader) == _HANDSHAKE_TYPE_SERVER_HELLO || return nothing
    _read_u24!(reader) == length(data) - 4 || return nothing

    vers = _read_u16!(reader)
    random = _read_bytes!(reader, 32)
    session_id = _read_u8_length_prefixed_bytes!(reader)
    cipher_suite = _read_u16!(reader)
    compression_method = _read_u8!(reader)
    (vers === nothing || random === nothing || session_id === nothing || cipher_suite === nothing || compression_method === nothing) && return nothing
    msg.vers = vers
    msg.random = random
    msg.session_id = session_id
    msg.cipher_suite = cipher_suite
    msg.compression_method = compression_method

    _reader_empty(reader) && return msg

    extensions_reader = _read_u16_length_prefixed_reader!(reader)
    (extensions_reader === nothing || !_reader_empty(reader)) && return nothing

    seen_extensions = Set{UInt16}()
    while !_reader_empty(extensions_reader)
        extension = _read_u16!(extensions_reader)
        ext_reader = _read_u16_length_prefixed_reader!(extensions_reader)
        (extension === nothing || ext_reader === nothing) && return nothing
        in(extension, seen_extensions) && return nothing
        push!(seen_extensions, extension)

        if extension == _HANDSHAKE_EXTENSION_STATUS_REQUEST
            msg.ocsp_stapling = true
        elseif extension == _HANDSHAKE_EXTENSION_SESSION_TICKET
            msg.ticket_supported = true
        elseif extension == _HANDSHAKE_EXTENSION_RENEGOTIATION_INFO
            secure_renegotiation = _read_u8_length_prefixed_bytes!(ext_reader)
            secure_renegotiation === nothing && return nothing
            msg.secure_renegotiation = secure_renegotiation
            msg.secure_renegotiation_supported = true
        elseif extension == _HANDSHAKE_EXTENSION_EXTENDED_MASTER_SECRET
            msg.extended_master_secret = true
        elseif extension == _HANDSHAKE_EXTENSION_ALPN
            protocol_list_reader = _read_u16_length_prefixed_reader!(ext_reader)
            (protocol_list_reader === nothing || _reader_empty(protocol_list_reader)) && return nothing
            protocol_bytes = _read_u8_length_prefixed_bytes!(protocol_list_reader)
            (protocol_bytes === nothing || isempty(protocol_bytes) || !_reader_empty(protocol_list_reader)) && return nothing
            isvalid(String, protocol_bytes) || return nothing
            protocol = String(protocol_bytes)
            msg.alpn_protocol = protocol
        elseif extension == _HANDSHAKE_EXTENSION_SCT
            scts_reader = _read_u16_length_prefixed_reader!(ext_reader)
            (scts_reader === nothing || _reader_empty(scts_reader)) && return nothing
            msg.scts = Vector{UInt8}[]
            while !_reader_empty(scts_reader)
                sct = _read_u16_length_prefixed_bytes!(scts_reader)
                (sct === nothing || isempty(sct)) && return nothing
                push!(msg.scts, sct)
            end
        elseif extension == _HANDSHAKE_EXTENSION_SUPPORTED_VERSIONS
            supported_version = _read_u16!(ext_reader)
            supported_version === nothing && return nothing
            msg.supported_version = supported_version
        elseif extension == _HANDSHAKE_EXTENSION_COOKIE
            cookie = _read_u16_length_prefixed_bytes!(ext_reader)
            (cookie === nothing || isempty(cookie)) && return nothing
            msg.cookie = cookie
        elseif extension == _HANDSHAKE_EXTENSION_KEY_SHARE
            if _reader_remaining(ext_reader) == 2
                selected_group = _read_u16!(ext_reader)
                selected_group === nothing && return nothing
                msg.selected_group = selected_group
            else
                group = _read_u16!(ext_reader)
                key_share_data = _read_u16_length_prefixed_bytes!(ext_reader)
                (group === nothing || key_share_data === nothing || isempty(key_share_data)) && return nothing
                msg.server_share = _TLSKeyShare(group, key_share_data)
            end
        elseif extension == _HANDSHAKE_EXTENSION_PRE_SHARED_KEY
            selected_identity = _read_u16!(ext_reader)
            selected_identity === nothing && return nothing
            msg.selected_identity_present = true
            msg.selected_identity = selected_identity
        elseif extension == _HANDSHAKE_EXTENSION_SUPPORTED_POINTS
            supported_points = _read_u8_length_prefixed_bytes!(ext_reader)
            (supported_points === nothing || isempty(supported_points)) && return nothing
            msg.supported_points = supported_points
        elseif extension == _HANDSHAKE_EXTENSION_ENCRYPTED_CLIENT_HELLO
            msg.encrypted_client_hello = _read_remaining_bytes!(ext_reader)
        elseif extension == _HANDSHAKE_EXTENSION_SERVER_NAME
            _reader_empty(ext_reader) || return nothing
            msg.server_name_ack = true
        else
            _skip_remaining!(ext_reader)
        end

        _reader_empty(ext_reader) || return nothing
    end

    return msg
end

function _unmarshal_certificate_tls12(data::Vector{UInt8})::Union{_CertificateMsgTLS12, Nothing}
    msg = _CertificateMsgTLS12()
    reader = _HandshakeReader(data)
    _read_u8!(reader) == _HANDSHAKE_TYPE_CERTIFICATE || return nothing
    _read_u24!(reader) == length(data) - 4 || return nothing

    certificates_reader = _read_u24_length_prefixed_reader!(reader)
    (certificates_reader === nothing || !_reader_empty(reader)) && return nothing

    msg.certificates = Vector{UInt8}[]
    while !_reader_empty(certificates_reader)
        certificate = _read_u24_length_prefixed_bytes!(certificates_reader)
        certificate === nothing && return nothing
        push!(msg.certificates, certificate)
    end

    return msg
end

function _unmarshal_server_key_exchange_tls12(data::Vector{UInt8})::Union{_ServerKeyExchangeMsgTLS12, Nothing}
    reader = _HandshakeReader(data)
    _read_u8!(reader) == _HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE || return nothing
    body_len = _read_u24!(reader)
    body_len === nothing && return nothing
    key = _read_bytes!(reader, body_len)
    (key === nothing || !_reader_empty(reader)) && return nothing
    return _ServerKeyExchangeMsgTLS12(key)
end

function _unmarshal_encrypted_extensions(data::Vector{UInt8})::Union{_EncryptedExtensionsMsg, Nothing}
    msg = _EncryptedExtensionsMsg()
    reader = _HandshakeReader(data)
    _read_u8!(reader) == _HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS || return nothing
    _read_u24!(reader) == length(data) - 4 || return nothing

    extensions_reader = _read_u16_length_prefixed_reader!(reader)
    (extensions_reader === nothing || !_reader_empty(reader)) && return nothing

    seen_extensions = Set{UInt16}()
    while !_reader_empty(extensions_reader)
        extension = _read_u16!(extensions_reader)
        ext_reader = _read_u16_length_prefixed_reader!(extensions_reader)
        (extension === nothing || ext_reader === nothing) && return nothing
        in(extension, seen_extensions) && return nothing
        push!(seen_extensions, extension)

        if extension == _HANDSHAKE_EXTENSION_ALPN
            protocol_list_reader = _read_u16_length_prefixed_reader!(ext_reader)
            (protocol_list_reader === nothing || _reader_empty(protocol_list_reader)) && return nothing
            protocol_bytes = _read_u8_length_prefixed_bytes!(protocol_list_reader)
            (protocol_bytes === nothing || isempty(protocol_bytes) || !_reader_empty(protocol_list_reader)) && return nothing
            isvalid(String, protocol_bytes) || return nothing
            protocol = String(protocol_bytes)
            msg.alpn_protocol = protocol
        elseif extension == _HANDSHAKE_EXTENSION_QUIC_TRANSPORT_PARAMETERS
            msg.quic_transport_parameters = _read_remaining_bytes!(ext_reader)
        elseif extension == _HANDSHAKE_EXTENSION_EARLY_DATA
            msg.early_data = true
        elseif extension == _HANDSHAKE_EXTENSION_ENCRYPTED_CLIENT_HELLO
            msg.ech_retry_configs = _read_remaining_bytes!(ext_reader)
        elseif extension == _HANDSHAKE_EXTENSION_SERVER_NAME
            _reader_empty(ext_reader) || return nothing
            msg.server_name_ack = true
        else
            _skip_remaining!(ext_reader)
        end

        _reader_empty(ext_reader) || return nothing
    end

    return msg
end

function _unmarshal_certificate_request_tls12(data::Vector{UInt8})::Union{_CertificateRequestMsgTLS12, Nothing}
    msg = _CertificateRequestMsgTLS12()
    reader = _HandshakeReader(data)
    _read_u8!(reader) == _HANDSHAKE_TYPE_CERTIFICATE_REQUEST || return nothing
    _read_u24!(reader) == length(data) - 4 || return nothing

    certificate_types = _read_u8_length_prefixed_bytes!(reader)
    sigalgs_reader = _read_u16_length_prefixed_reader!(reader)
    authorities_reader = _read_u16_length_prefixed_reader!(reader)
    (certificate_types === nothing || sigalgs_reader === nothing || authorities_reader === nothing || !_reader_empty(reader)) && return nothing

    msg.certificate_types = certificate_types
    msg.supported_signature_algorithms = UInt16[]
    while !_reader_empty(sigalgs_reader)
        sigalg = _read_u16!(sigalgs_reader)
        sigalg === nothing && return nothing
        push!(msg.supported_signature_algorithms, sigalg)
    end

    msg.certificate_authorities = Vector{UInt8}[]
    while !_reader_empty(authorities_reader)
        authority = _read_u16_length_prefixed_bytes!(authorities_reader)
        authority === nothing && return nothing
        push!(msg.certificate_authorities, authority)
    end

    return msg
end

function _unmarshal_certificate_request_tls13(data::Vector{UInt8})::Union{_CertificateRequestMsgTLS13, Nothing}
    msg = _CertificateRequestMsgTLS13()
    reader = _HandshakeReader(data)
    _read_u8!(reader) == _HANDSHAKE_TYPE_CERTIFICATE_REQUEST || return nothing
    _read_u24!(reader) == length(data) - 4 || return nothing

    context = _read_u8_length_prefixed_bytes!(reader)
    extensions_reader = _read_u16_length_prefixed_reader!(reader)
    (context === nothing || !isempty(context) || extensions_reader === nothing || !_reader_empty(reader)) && return nothing

    seen_extensions = Set{UInt16}()
    while !_reader_empty(extensions_reader)
        extension = _read_u16!(extensions_reader)
        ext_reader = _read_u16_length_prefixed_reader!(extensions_reader)
        (extension === nothing || ext_reader === nothing) && return nothing
        in(extension, seen_extensions) && return nothing
        push!(seen_extensions, extension)

        if extension == _HANDSHAKE_EXTENSION_STATUS_REQUEST
            msg.ocsp_stapling = true
        elseif extension == _HANDSHAKE_EXTENSION_SCT
            msg.scts = true
        elseif extension == _HANDSHAKE_EXTENSION_SIGNATURE_ALGORITHMS
            sigalgs_reader = _read_u16_length_prefixed_reader!(ext_reader)
            (sigalgs_reader === nothing || _reader_empty(sigalgs_reader)) && return nothing
            msg.supported_signature_algorithms = UInt16[]
            while !_reader_empty(sigalgs_reader)
                sigalg = _read_u16!(sigalgs_reader)
                sigalg === nothing && return nothing
                push!(msg.supported_signature_algorithms, sigalg)
            end
        elseif extension == _HANDSHAKE_EXTENSION_SIGNATURE_ALGORITHMS_CERT
            sigalgs_reader = _read_u16_length_prefixed_reader!(ext_reader)
            (sigalgs_reader === nothing || _reader_empty(sigalgs_reader)) && return nothing
            msg.supported_signature_algorithms_cert = UInt16[]
            while !_reader_empty(sigalgs_reader)
                sigalg = _read_u16!(sigalgs_reader)
                sigalg === nothing && return nothing
                push!(msg.supported_signature_algorithms_cert, sigalg)
            end
        elseif extension == _HANDSHAKE_EXTENSION_CERTIFICATE_AUTHORITIES
            authorities_reader = _read_u16_length_prefixed_reader!(ext_reader)
            (authorities_reader === nothing || _reader_empty(authorities_reader)) && return nothing
            msg.certificate_authorities = Vector{UInt8}[]
            while !_reader_empty(authorities_reader)
                authority = _read_u16_length_prefixed_bytes!(authorities_reader)
                (authority === nothing || isempty(authority)) && return nothing
                push!(msg.certificate_authorities, authority)
            end
        else
            _skip_remaining!(ext_reader)
        end

        _reader_empty(ext_reader) || return nothing
    end

    return msg
end

function _unmarshal_certificate_tls13(data::Vector{UInt8})::Union{_CertificateMsgTLS13, Nothing}
    msg = _CertificateMsgTLS13()
    reader = _HandshakeReader(data)
    _read_u8!(reader) == _HANDSHAKE_TYPE_CERTIFICATE || return nothing
    _read_u24!(reader) == length(data) - 4 || return nothing

    context = _read_u8_length_prefixed_bytes!(reader)
    certificates_reader = _read_u24_length_prefixed_reader!(reader)
    (context === nothing || !isempty(context) || certificates_reader === nothing || !_reader_empty(reader)) && return nothing

    msg.certificates = Vector{UInt8}[]
    while !_reader_empty(certificates_reader)
        certificate = _read_u24_length_prefixed_bytes!(certificates_reader)
        extensions_reader = _read_u16_length_prefixed_reader!(certificates_reader)
        (certificate === nothing || extensions_reader === nothing) && return nothing
        push!(msg.certificates, certificate)
        leaf_certificate = length(msg.certificates) == 1

        while !_reader_empty(extensions_reader)
            extension = _read_u16!(extensions_reader)
            ext_reader = _read_u16_length_prefixed_reader!(extensions_reader)
            (extension === nothing || ext_reader === nothing) && return nothing

            if !leaf_certificate
                _skip_remaining!(ext_reader)
            elseif extension == _HANDSHAKE_EXTENSION_STATUS_REQUEST
                status_type = _read_u8!(ext_reader)
                ocsp_staple = _read_u24_length_prefixed_bytes!(ext_reader)
                (status_type === nothing || status_type != _TLS_STATUS_TYPE_OCSP || ocsp_staple === nothing || isempty(ocsp_staple)) && return nothing
                msg.ocsp_stapling = true
                msg.ocsp_staple = ocsp_staple
            elseif extension == _HANDSHAKE_EXTENSION_SCT
                scts_reader = _read_u16_length_prefixed_reader!(ext_reader)
                (scts_reader === nothing || _reader_empty(scts_reader)) && return nothing
                msg.signed_certificate_timestamps = Vector{UInt8}[]
                while !_reader_empty(scts_reader)
                    sct = _read_u16_length_prefixed_bytes!(scts_reader)
                    (sct === nothing || isempty(sct)) && return nothing
                    push!(msg.signed_certificate_timestamps, sct)
                end
                msg.scts = true
            else
                _skip_remaining!(ext_reader)
            end

            _reader_empty(ext_reader) || return nothing
        end
    end

    return msg
end

function _unmarshal_certificate_verify(data::Vector{UInt8})::Union{_CertificateVerifyMsg, Nothing}
    reader = _HandshakeReader(data)
    _read_u8!(reader) == _HANDSHAKE_TYPE_CERTIFICATE_VERIFY || return nothing
    _read_u24!(reader) == length(data) - 4 || return nothing
    signature_algorithm = _read_u16!(reader)
    signature = _read_u16_length_prefixed_bytes!(reader)
    (signature_algorithm === nothing || signature === nothing || isempty(signature) || !_reader_empty(reader)) && return nothing
    return _CertificateVerifyMsg(signature_algorithm, signature)
end

function _unmarshal_server_hello_done_tls12(data::Vector{UInt8})::Union{_ServerHelloDoneMsgTLS12, Nothing}
    length(data) == 4 || return nothing
    data[1] == _HANDSHAKE_TYPE_SERVER_HELLO_DONE || return nothing
    data[2] == 0x00 || return nothing
    data[3] == 0x00 || return nothing
    data[4] == 0x00 || return nothing
    return _ServerHelloDoneMsgTLS12()
end

function _unmarshal_client_key_exchange_tls12(data::Vector{UInt8})::Union{_ClientKeyExchangeMsgTLS12, Nothing}
    reader = _HandshakeReader(data)
    _read_u8!(reader) == _HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE || return nothing
    body_len = _read_u24!(reader)
    body_len === nothing && return nothing
    ciphertext = _read_bytes!(reader, body_len)
    (ciphertext === nothing || !_reader_empty(reader)) && return nothing
    return _ClientKeyExchangeMsgTLS12(ciphertext)
end

function _unmarshal_new_session_ticket_tls12(data::Vector{UInt8})::Union{_NewSessionTicketMsgTLS12, Nothing}
    reader = _HandshakeReader(data)
    _read_u8!(reader) == _HANDSHAKE_TYPE_NEW_SESSION_TICKET || return nothing
    _read_u24!(reader) == length(data) - 4 || return nothing
    lifetime_hint = _read_u32!(reader)
    ticket = _read_u16_length_prefixed_bytes!(reader)
    (lifetime_hint === nothing || ticket === nothing || !_reader_empty(reader)) && return nothing
    return _NewSessionTicketMsgTLS12(lifetime_hint, ticket)
end

function _unmarshal_new_session_ticket_tls13(data::Vector{UInt8})::Union{_NewSessionTicketMsgTLS13, Nothing}
    msg = _NewSessionTicketMsgTLS13()
    reader = _HandshakeReader(data)
    _read_u8!(reader) == _HANDSHAKE_TYPE_NEW_SESSION_TICKET || return nothing
    _read_u24!(reader) == length(data) - 4 || return nothing

    lifetime = _read_u32!(reader)
    age_add = _read_u32!(reader)
    nonce = _read_u8_length_prefixed_bytes!(reader)
    label = _read_u16_length_prefixed_bytes!(reader)
    extensions_reader = _read_u16_length_prefixed_reader!(reader)
    (lifetime === nothing || age_add === nothing || nonce === nothing || label === nothing || extensions_reader === nothing || !_reader_empty(reader)) && return nothing

    msg.lifetime = lifetime
    msg.age_add = age_add
    msg.nonce = nonce
    msg.label = label

    while !_reader_empty(extensions_reader)
        extension = _read_u16!(extensions_reader)
        ext_reader = _read_u16_length_prefixed_reader!(extensions_reader)
        (extension === nothing || ext_reader === nothing) && return nothing

        if extension == _HANDSHAKE_EXTENSION_EARLY_DATA
            max_early_data = _read_u32!(ext_reader)
            max_early_data === nothing && return nothing
            msg.max_early_data = max_early_data
        else
            _skip_remaining!(ext_reader)
        end

        _reader_empty(ext_reader) || return nothing
    end

    return msg
end

function _unmarshal_finished(data::Vector{UInt8})::Union{_FinishedMsg, Nothing}
    reader = _HandshakeReader(data)
    _read_u8!(reader) == _HANDSHAKE_TYPE_FINISHED || return nothing
    body_len = _read_u24!(reader)
    body_len === nothing && return nothing
    verify_data = _read_bytes!(reader, body_len)
    (verify_data === nothing || !_reader_empty(reader)) && return nothing
    return _FinishedMsg(verify_data)
end

function _unmarshal_handshake_message(
    data::AbstractVector{UInt8},
    transcript::Union{Nothing, _TranscriptHash} = nothing,
    tls_version::UInt16 = TLS1_3_VERSION,
)::Union{_HandshakeMessage, Nothing}
    raw = _copy_valid_handshake_frame(data)
    raw === nothing && return nothing

    handshake_type = raw[1]
    msg = if handshake_type == _HANDSHAKE_TYPE_CLIENT_HELLO
        _unmarshal_client_hello(raw)
    elseif handshake_type == _HANDSHAKE_TYPE_SERVER_HELLO
        _unmarshal_server_hello(raw)
    elseif handshake_type == _HANDSHAKE_TYPE_SERVER_KEY_EXCHANGE
        _unmarshal_server_key_exchange_tls12(raw)
    elseif handshake_type == _HANDSHAKE_TYPE_NEW_SESSION_TICKET
        tls_version == TLS1_2_VERSION ? _unmarshal_new_session_ticket_tls12(raw) : _unmarshal_new_session_ticket_tls13(raw)
    elseif handshake_type == _HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS
        _unmarshal_encrypted_extensions(raw)
    elseif handshake_type == _HANDSHAKE_TYPE_CERTIFICATE
        tls_version == TLS1_2_VERSION ? _unmarshal_certificate_tls12(raw) : _unmarshal_certificate_tls13(raw)
    elseif handshake_type == _HANDSHAKE_TYPE_CERTIFICATE_REQUEST
        tls_version == TLS1_2_VERSION ? _unmarshal_certificate_request_tls12(raw) : _unmarshal_certificate_request_tls13(raw)
    elseif handshake_type == _HANDSHAKE_TYPE_SERVER_HELLO_DONE
        _unmarshal_server_hello_done_tls12(raw)
    elseif handshake_type == _HANDSHAKE_TYPE_CERTIFICATE_VERIFY
        _unmarshal_certificate_verify(raw)
    elseif handshake_type == _HANDSHAKE_TYPE_CLIENT_KEY_EXCHANGE
        _unmarshal_client_key_exchange_tls12(raw)
    elseif handshake_type == _HANDSHAKE_TYPE_FINISHED
        _unmarshal_finished(raw)
    else
        nothing
    end

    msg === nothing && return nothing
    transcript === nothing || _transcript_update!(transcript, raw)
    return msg
end

function _marshal_handshake_message(msg::_HandshakeMessage)::Vector{UInt8}
    if msg isa _ClientHelloMsg
        return _marshal_client_hello(msg)
    elseif msg isa _ServerHelloMsg
        return _marshal_server_hello(msg)
    elseif msg isa _CertificateMsgTLS12
        return _marshal_certificate_tls12(msg)
    elseif msg isa _ServerKeyExchangeMsgTLS12
        return _marshal_server_key_exchange_tls12(msg)
    elseif msg isa _NewSessionTicketMsgTLS12
        return _marshal_new_session_ticket_tls12(msg)
    elseif msg isa _NewSessionTicketMsgTLS13
        return _marshal_new_session_ticket_tls13(msg)
    elseif msg isa _EncryptedExtensionsMsg
        return _marshal_encrypted_extensions(msg)
    elseif msg isa _CertificateMsgTLS13
        return _marshal_certificate_tls13(msg)
    elseif msg isa _CertificateRequestMsgTLS12
        return _marshal_certificate_request_tls12(msg)
    elseif msg isa _CertificateRequestMsgTLS13
        return _marshal_certificate_request_tls13(msg)
    elseif msg isa _CertificateVerifyMsg
        return _marshal_certificate_verify(msg)
    elseif msg isa _ServerHelloDoneMsgTLS12
        return _marshal_server_hello_done_tls12(msg)
    elseif msg isa _ClientKeyExchangeMsgTLS12
        return _marshal_client_key_exchange_tls12(msg)
    elseif msg isa _FinishedMsg
        return _marshal_finished(msg)
    end
    error("unsupported handshake message type: $(typeof(msg))")
end

function _handshake_transcript_bytes(msg::_HandshakeMessage)::Vector{UInt8}
    if msg isa _ClientHelloMsg
        original = msg.original
        return original === nothing ? _marshal_client_hello(msg) : copy(original)
    elseif msg isa _ServerHelloMsg
        original = msg.original
        return original === nothing ? _marshal_server_hello(msg) : copy(original)
    elseif msg isa _CertificateMsgTLS12
        return _marshal_certificate_tls12(msg)
    elseif msg isa _ServerKeyExchangeMsgTLS12
        return _marshal_server_key_exchange_tls12(msg)
    elseif msg isa _NewSessionTicketMsgTLS12
        return _marshal_new_session_ticket_tls12(msg)
    elseif msg isa _NewSessionTicketMsgTLS13
        return _marshal_new_session_ticket_tls13(msg)
    elseif msg isa _EncryptedExtensionsMsg
        return _marshal_encrypted_extensions(msg)
    elseif msg isa _CertificateMsgTLS13
        return _marshal_certificate_tls13(msg)
    elseif msg isa _CertificateRequestMsgTLS12
        return _marshal_certificate_request_tls12(msg)
    elseif msg isa _CertificateRequestMsgTLS13
        return _marshal_certificate_request_tls13(msg)
    elseif msg isa _CertificateVerifyMsg
        return _marshal_certificate_verify(msg)
    elseif msg isa _ServerHelloDoneMsgTLS12
        return _marshal_server_hello_done_tls12(msg)
    elseif msg isa _ClientKeyExchangeMsgTLS12
        return _marshal_client_key_exchange_tls12(msg)
    elseif msg isa _FinishedMsg
        return _marshal_finished(msg)
    end
    error("unsupported handshake message type: $(typeof(msg))")
end

function _write_handshake_message(msg::_HandshakeMessage, transcript::Union{Nothing, _TranscriptHash} = nothing)::Vector{UInt8}
    data = _marshal_handshake_message(msg)
    transcript === nothing || _transcript_update!(transcript, data)
    return data
end

function _transcript_update_handshake!(transcript::_TranscriptHash, msg::_HandshakeMessage)::Vector{UInt8}
    data = _handshake_transcript_bytes(msg)
    _transcript_update!(transcript, data)
    return data
end
