const _MAX_HANDSHAKE_SIZE = 65536

const _HANDSHAKE_TYPE_CLIENT_HELLO = UInt8(1)
const _HANDSHAKE_TYPE_SERVER_HELLO = UInt8(2)
const _HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS = UInt8(8)
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
const _HANDSHAKE_EXTENSION_SIGNATURE_ALGORITHMS_CERT = UInt16(50)
const _HANDSHAKE_EXTENSION_KEY_SHARE = UInt16(51)
const _HANDSHAKE_EXTENSION_QUIC_TRANSPORT_PARAMETERS = UInt16(57)
const _HANDSHAKE_EXTENSION_RENEGOTIATION_INFO = UInt16(0xff01)
const _HANDSHAKE_EXTENSION_ENCRYPTED_CLIENT_HELLO = UInt16(0xfe0d)

const _TLS_SCSV_RENEGOTIATION = UInt16(0x00ff)
const _TLS_PSK_MODE_PLAIN = UInt8(0)
const _TLS_PSK_MODE_DHE = UInt8(1)
const _TLS_STATUS_TYPE_OCSP = UInt8(1)

abstract type _HandshakeMessage end

struct _TLSKeyShare
    group::UInt16
    data::Vector{UInt8}
end

struct _TLSPSKIdentity
    label::Vector{UInt8}
    obfuscated_ticket_age::UInt32
end

Base.:(==)(a::_TLSKeyShare, b::_TLSKeyShare) = a.group == b.group && a.data == b.data
Base.:(==)(a::_TLSPSKIdentity, b::_TLSPSKIdentity) = a.label == b.label && a.obfuscated_ticket_age == b.obfuscated_ticket_age

_copy_key_shares(key_shares::Vector{_TLSKeyShare}) = [_TLSKeyShare(share.group, copy(share.data)) for share in key_shares]
_copy_psk_identities(psk_identities::Vector{_TLSPSKIdentity}) = [_TLSPSKIdentity(copy(identity.label), identity.obfuscated_ticket_age) for identity in psk_identities]
_copy_byte_vectors(byte_vectors::Vector{Vector{UInt8}}) = [copy(bytes) for bytes in byte_vectors]

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

function _ClientHelloMsg(;
    original::Union{Nothing, AbstractVector{UInt8}} = nothing,
    vers::UInt16 = TLS1_2_VERSION,
    random::AbstractVector{UInt8} = zeros(UInt8, 32),
    session_id::AbstractVector{UInt8} = UInt8[],
    cipher_suites::Vector{UInt16} = UInt16[],
    compression_methods::AbstractVector{UInt8} = UInt8[_TLS_COMPRESSION_NONE],
    server_name::AbstractString = "",
    ocsp_stapling::Bool = false,
    supported_curves::Vector{UInt16} = UInt16[],
    supported_points::AbstractVector{UInt8} = UInt8[],
    ticket_supported::Bool = false,
    session_ticket::AbstractVector{UInt8} = UInt8[],
    supported_signature_algorithms::Vector{UInt16} = UInt16[],
    supported_signature_algorithms_cert::Vector{UInt16} = UInt16[],
    secure_renegotiation_supported::Bool = false,
    secure_renegotiation::AbstractVector{UInt8} = UInt8[],
    extended_master_secret::Bool = false,
    alpn_protocols::Vector{String} = String[],
    scts::Bool = false,
    supported_versions::Vector{UInt16} = UInt16[],
    cookie::AbstractVector{UInt8} = UInt8[],
    key_shares::Vector{_TLSKeyShare} = _TLSKeyShare[],
    early_data::Bool = false,
    psk_modes::AbstractVector{UInt8} = UInt8[],
    psk_identities::Vector{_TLSPSKIdentity} = _TLSPSKIdentity[],
    psk_binders::Vector{Vector{UInt8}} = Vector{UInt8}[],
    quic_transport_parameters::Union{Nothing, AbstractVector{UInt8}} = nothing,
    encrypted_client_hello::AbstractVector{UInt8} = UInt8[],
    extensions::Vector{UInt16} = UInt16[],
)
    return _ClientHelloMsg(
        original === nothing ? nothing : Vector{UInt8}(original),
        vers,
        Vector{UInt8}(random),
        Vector{UInt8}(session_id),
        copy(cipher_suites),
        Vector{UInt8}(compression_methods),
        String(server_name),
        ocsp_stapling,
        copy(supported_curves),
        Vector{UInt8}(supported_points),
        ticket_supported,
        Vector{UInt8}(session_ticket),
        copy(supported_signature_algorithms),
        copy(supported_signature_algorithms_cert),
        secure_renegotiation_supported,
        Vector{UInt8}(secure_renegotiation),
        extended_master_secret,
        copy(alpn_protocols),
        scts,
        copy(supported_versions),
        Vector{UInt8}(cookie),
        _copy_key_shares(key_shares),
        early_data,
        Vector{UInt8}(psk_modes),
        _copy_psk_identities(psk_identities),
        _copy_byte_vectors(psk_binders),
        quic_transport_parameters === nothing ? nothing : Vector{UInt8}(quic_transport_parameters),
        Vector{UInt8}(encrypted_client_hello),
        copy(extensions),
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

function _ServerHelloMsg(;
    original::Union{Nothing, AbstractVector{UInt8}} = nothing,
    vers::UInt16 = TLS1_2_VERSION,
    random::AbstractVector{UInt8} = zeros(UInt8, 32),
    session_id::AbstractVector{UInt8} = UInt8[],
    cipher_suite::UInt16 = UInt16(0),
    compression_method::UInt8 = _TLS_COMPRESSION_NONE,
    ocsp_stapling::Bool = false,
    ticket_supported::Bool = false,
    secure_renegotiation_supported::Bool = false,
    secure_renegotiation::AbstractVector{UInt8} = UInt8[],
    extended_master_secret::Bool = false,
    alpn_protocol::AbstractString = "",
    scts::Vector{Vector{UInt8}} = Vector{UInt8}[],
    supported_version::UInt16 = UInt16(0),
    server_share::Union{Nothing, _TLSKeyShare} = nothing,
    selected_identity_present::Bool = false,
    selected_identity::UInt16 = UInt16(0),
    supported_points::AbstractVector{UInt8} = UInt8[],
    encrypted_client_hello::AbstractVector{UInt8} = UInt8[],
    server_name_ack::Bool = false,
    cookie::AbstractVector{UInt8} = UInt8[],
    selected_group::UInt16 = UInt16(0),
)
    return _ServerHelloMsg(
        original === nothing ? nothing : Vector{UInt8}(original),
        vers,
        Vector{UInt8}(random),
        Vector{UInt8}(session_id),
        cipher_suite,
        compression_method,
        ocsp_stapling,
        ticket_supported,
        secure_renegotiation_supported,
        Vector{UInt8}(secure_renegotiation),
        extended_master_secret,
        String(alpn_protocol),
        _copy_byte_vectors(scts),
        supported_version,
        server_share === nothing ? nothing : _TLSKeyShare(server_share.group, copy(server_share.data)),
        selected_identity_present,
        selected_identity,
        Vector{UInt8}(supported_points),
        Vector{UInt8}(encrypted_client_hello),
        server_name_ack,
        Vector{UInt8}(cookie),
        selected_group,
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

mutable struct _EncryptedExtensionsMsg <: _HandshakeMessage
    alpn_protocol::String
    quic_transport_parameters::Union{Nothing, Vector{UInt8}}
    early_data::Bool
    ech_retry_configs::Vector{UInt8}
    server_name_ack::Bool
end

function _EncryptedExtensionsMsg(;
    alpn_protocol::AbstractString = "",
    quic_transport_parameters::Union{Nothing, AbstractVector{UInt8}} = nothing,
    early_data::Bool = false,
    ech_retry_configs::AbstractVector{UInt8} = UInt8[],
    server_name_ack::Bool = false,
)
    return _EncryptedExtensionsMsg(
        String(alpn_protocol),
        quic_transport_parameters === nothing ? nothing : Vector{UInt8}(quic_transport_parameters),
        early_data,
        Vector{UInt8}(ech_retry_configs),
        server_name_ack,
    )
end

Base.:(==)(a::_EncryptedExtensionsMsg, b::_EncryptedExtensionsMsg) =
    a.alpn_protocol == b.alpn_protocol &&
    a.quic_transport_parameters == b.quic_transport_parameters &&
    a.early_data == b.early_data &&
    a.ech_retry_configs == b.ech_retry_configs &&
    a.server_name_ack == b.server_name_ack

mutable struct _FinishedMsg <: _HandshakeMessage
    verify_data::Vector{UInt8}
end

_FinishedMsg(; verify_data::AbstractVector{UInt8} = UInt8[]) = _FinishedMsg(Vector{UInt8}(verify_data))
Base.:(==)(a::_FinishedMsg, b::_FinishedMsg) = a.verify_data == b.verify_data

mutable struct _HandshakeReader
    data::Vector{UInt8}
    pos::Int
end

_HandshakeReader(data::AbstractVector{UInt8}) = _HandshakeReader(Vector{UInt8}(data), 1)

@inline function _reader_empty(reader::_HandshakeReader)::Bool
    return reader.pos > length(reader.data)
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

function _read_bytes!(reader::_HandshakeReader, n::Int)::Union{Vector{UInt8}, Nothing}
    n < 0 && return nothing
    n == 0 && return UInt8[]
    reader.pos + n - 1 > length(reader.data) && return nothing
    out = copy(@view(reader.data[reader.pos:(reader.pos + n - 1)]))
    reader.pos += n
    return out
end

@inline function _read_remaining_bytes!(reader::_HandshakeReader)::Vector{UInt8}
    return _read_bytes!(reader, length(reader.data) - reader.pos + 1)::Vector{UInt8}
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

function _read_u16_length_prefixed_reader!(reader::_HandshakeReader)::Union{_HandshakeReader, Nothing}
    bytes = _read_u16_length_prefixed_bytes!(reader)
    bytes === nothing && return nothing
    return _HandshakeReader(bytes)
end

function _bytes_to_string(bytes::AbstractVector{UInt8})::Union{String, Nothing}
    try
        return String(Vector{UInt8}(bytes))
    catch
        return nothing
    end
end

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

@inline function _append_bytes!(buf::Vector{UInt8}, bytes::AbstractVector{UInt8})
    append!(buf, bytes)
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

function _append_fixed_bytes!(buf::Vector{UInt8}, bytes::AbstractVector{UInt8}, expected_len::Int, label::AbstractString)
    length(bytes) == expected_len || throw(ArgumentError("invalid $(label) length: expected $(expected_len), got $(length(bytes))"))
    _append_bytes!(buf, bytes)
    return nothing
end

function _copy_valid_handshake_frame(data::AbstractVector{UInt8})::Union{Vector{UInt8}, Nothing}
    length(data) < 4 && return nothing
    raw = Vector{UInt8}(data)
    body_len = (Int(raw[2]) << 16) | (Int(raw[3]) << 8) | Int(raw[4])
    body_len <= _MAX_HANDSHAKE_SIZE || throw(ArgumentError("tls: handshake message of length $(body_len) bytes exceeds maximum of $(_MAX_HANDSHAKE_SIZE) bytes"))
    length(raw) == body_len + 4 || return nothing
    return raw
end

@inline _handshake_type(::Type{_ClientHelloMsg}) = _HANDSHAKE_TYPE_CLIENT_HELLO
@inline _handshake_type(::Type{_ServerHelloMsg}) = _HANDSHAKE_TYPE_SERVER_HELLO
@inline _handshake_type(::Type{_EncryptedExtensionsMsg}) = _HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS
@inline _handshake_type(::Type{_FinishedMsg}) = _HANDSHAKE_TYPE_FINISHED
@inline _handshake_type(msg::_HandshakeMessage) = _handshake_type(typeof(msg))

function _marshal_handshake_message(msg::_ClientHelloMsg)::Vector{UInt8}
    !isempty(msg.psk_identities) && length(msg.psk_identities) != length(msg.psk_binders) &&
        throw(ArgumentError("client hello psk_identities and psk_binders must have the same length"))

    exts = UInt8[]
    if !isempty(msg.server_name)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_SERVER_NAME) do exts_buf
            _append_u16_length_prefixed!(exts_buf) do name_list_buf
                _append_u8!(name_list_buf, 0)
                _append_u16_length_prefixed!(name_list_buf) do server_name_buf
                    _append_bytes!(server_name_buf, codeunits(msg.server_name))
                end
            end
        end
    end
    if !isempty(msg.supported_points)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_SUPPORTED_POINTS) do exts_buf
            _append_u8_length_prefixed!(exts_buf) do points_buf
                _append_bytes!(points_buf, msg.supported_points)
            end
        end
    end
    if msg.ticket_supported
        _append_extension!(exts, _HANDSHAKE_EXTENSION_SESSION_TICKET) do exts_buf
            _append_bytes!(exts_buf, msg.session_ticket)
        end
    end
    if msg.secure_renegotiation_supported
        _append_extension!(exts, _HANDSHAKE_EXTENSION_RENEGOTIATION_INFO) do exts_buf
            _append_u8_length_prefixed!(exts_buf) do info_buf
                _append_bytes!(info_buf, msg.secure_renegotiation)
            end
        end
    end
    msg.extended_master_secret && _append_extension!(exts, _HANDSHAKE_EXTENSION_EXTENDED_MASTER_SECRET) do _ end
    msg.scts && _append_extension!(exts, _HANDSHAKE_EXTENSION_SCT) do _ end
    msg.early_data && _append_extension!(exts, _HANDSHAKE_EXTENSION_EARLY_DATA) do _ end
    if msg.quic_transport_parameters !== nothing
        quic_transport_parameters = msg.quic_transport_parameters::Vector{UInt8}
        _append_extension!(exts, _HANDSHAKE_EXTENSION_QUIC_TRANSPORT_PARAMETERS) do exts_buf
            _append_bytes!(exts_buf, quic_transport_parameters)
        end
    end
    if !isempty(msg.encrypted_client_hello)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_ENCRYPTED_CLIENT_HELLO) do exts_buf
            _append_bytes!(exts_buf, msg.encrypted_client_hello)
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
                        _append_bytes!(protocol_buf, codeunits(protocol))
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
                _append_bytes!(cookie_buf, msg.cookie)
            end
        end
    end
    if !isempty(msg.key_shares)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_KEY_SHARE) do exts_buf
            _append_u16_length_prefixed!(exts_buf) do shares_buf
                for share in msg.key_shares
                    _append_u16!(shares_buf, share.group)
                    _append_u16_length_prefixed!(shares_buf) do share_buf
                        _append_bytes!(share_buf, share.data)
                    end
                end
            end
        end
    end
    if !isempty(msg.psk_modes)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_PSK_MODES) do exts_buf
            _append_u8_length_prefixed!(exts_buf) do modes_buf
                _append_bytes!(modes_buf, msg.psk_modes)
            end
        end
    end
    if !isempty(msg.psk_identities)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_PRE_SHARED_KEY) do exts_buf
            _append_u16_length_prefixed!(exts_buf) do identities_buf
                for identity in msg.psk_identities
                    _append_u16_length_prefixed!(identities_buf) do label_buf
                        _append_bytes!(label_buf, identity.label)
                    end
                    _append_u32!(identities_buf, identity.obfuscated_ticket_age)
                end
            end
            _append_u16_length_prefixed!(exts_buf) do binders_buf
                for binder in msg.psk_binders
                    _append_u8_length_prefixed!(binders_buf) do binder_buf
                        _append_bytes!(binder_buf, binder)
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
            _append_bytes!(session_id_buf, msg.session_id)
        end
        _append_u16_length_prefixed!(body_buf) do cipher_suites_buf
            for cipher_suite in msg.cipher_suites
                _append_u16!(cipher_suites_buf, cipher_suite)
            end
        end
        _append_u8_length_prefixed!(body_buf) do compression_methods_buf
            _append_bytes!(compression_methods_buf, msg.compression_methods)
        end
        !isempty(exts) && _append_u16_length_prefixed!(body_buf) do extensions_buf
            _append_bytes!(extensions_buf, exts)
        end
    end
    return out
end

function _marshal_client_hello_without_binders(msg::_ClientHelloMsg)::Vector{UInt8}
    isempty(msg.psk_identities) && return _handshake_transcript_bytes(msg)

    binders_len = 2
    for binder in msg.psk_binders
        binders_len += 1 + length(binder)
    end

    full_message = _handshake_transcript_bytes(msg)
    binders_len <= length(full_message) || throw(ArgumentError("client hello binders exceed message length"))
    return full_message[1:(end - binders_len)]
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

function _marshal_handshake_message(msg::_ServerHelloMsg)::Vector{UInt8}
    msg.server_share !== nothing && msg.selected_group != 0x0000 &&
        throw(ArgumentError("server hello cannot encode both server_share and selected_group"))

    exts = UInt8[]
    msg.ocsp_stapling && _append_extension!(exts, _HANDSHAKE_EXTENSION_STATUS_REQUEST) do _ end
    msg.ticket_supported && _append_extension!(exts, _HANDSHAKE_EXTENSION_SESSION_TICKET) do _ end
    if msg.secure_renegotiation_supported
        _append_extension!(exts, _HANDSHAKE_EXTENSION_RENEGOTIATION_INFO) do exts_buf
            _append_u8_length_prefixed!(exts_buf) do info_buf
                _append_bytes!(info_buf, msg.secure_renegotiation)
            end
        end
    end
    msg.extended_master_secret && _append_extension!(exts, _HANDSHAKE_EXTENSION_EXTENDED_MASTER_SECRET) do _ end
    if !isempty(msg.alpn_protocol)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_ALPN) do exts_buf
            _append_u16_length_prefixed!(exts_buf) do protocol_list_buf
                _append_u8_length_prefixed!(protocol_list_buf) do protocol_buf
                    _append_bytes!(protocol_buf, codeunits(msg.alpn_protocol))
                end
            end
        end
    end
    if !isempty(msg.scts)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_SCT) do exts_buf
            _append_u16_length_prefixed!(exts_buf) do scts_buf
                for sct in msg.scts
                    _append_u16_length_prefixed!(scts_buf) do sct_buf
                        _append_bytes!(sct_buf, sct)
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
                _append_bytes!(share_buf, server_share.data)
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
                _append_bytes!(cookie_buf, msg.cookie)
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
                _append_bytes!(points_buf, msg.supported_points)
            end
        end
    end
    if !isempty(msg.encrypted_client_hello)
        _append_extension!(exts, _HANDSHAKE_EXTENSION_ENCRYPTED_CLIENT_HELLO) do exts_buf
            _append_bytes!(exts_buf, msg.encrypted_client_hello)
        end
    end
    msg.server_name_ack && _append_extension!(exts, _HANDSHAKE_EXTENSION_SERVER_NAME) do _ end

    out = UInt8[]
    _append_u8!(out, _HANDSHAKE_TYPE_SERVER_HELLO)
    _append_u24_length_prefixed!(out) do body_buf
        _append_u16!(body_buf, msg.vers)
        _append_fixed_bytes!(body_buf, msg.random, 32, "server hello random")
        _append_u8_length_prefixed!(body_buf) do session_id_buf
            _append_bytes!(session_id_buf, msg.session_id)
        end
        _append_u16!(body_buf, msg.cipher_suite)
        _append_u8!(body_buf, msg.compression_method)
        !isempty(exts) && _append_u16_length_prefixed!(body_buf) do extensions_buf
            _append_bytes!(extensions_buf, exts)
        end
    end
    return out
end

function _marshal_handshake_message(msg::_EncryptedExtensionsMsg)::Vector{UInt8}
    out = UInt8[]
    _append_u8!(out, _HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS)
    _append_u24_length_prefixed!(out) do body_buf
        _append_u16_length_prefixed!(body_buf) do extensions_buf
            if !isempty(msg.alpn_protocol)
                _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_ALPN) do exts_buf
                    _append_u16_length_prefixed!(exts_buf) do protocol_list_buf
                        _append_u8_length_prefixed!(protocol_list_buf) do protocol_buf
                            _append_bytes!(protocol_buf, codeunits(msg.alpn_protocol))
                        end
                    end
                end
            end
            if msg.quic_transport_parameters !== nothing
                quic_transport_parameters = msg.quic_transport_parameters::Vector{UInt8}
                _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_QUIC_TRANSPORT_PARAMETERS) do exts_buf
                    _append_bytes!(exts_buf, quic_transport_parameters)
                end
            end
            msg.early_data && _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_EARLY_DATA) do _ end
            if !isempty(msg.ech_retry_configs)
                _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_ENCRYPTED_CLIENT_HELLO) do exts_buf
                    _append_bytes!(exts_buf, msg.ech_retry_configs)
                end
            end
            msg.server_name_ack && _append_extension!(extensions_buf, _HANDSHAKE_EXTENSION_SERVER_NAME) do _ end
        end
    end
    return out
end

function _marshal_handshake_message(msg::_FinishedMsg)::Vector{UInt8}
    out = UInt8[]
    _append_u8!(out, _HANDSHAKE_TYPE_FINISHED)
    _append_u24_length_prefixed!(out) do body_buf
        _append_bytes!(body_buf, msg.verify_data)
    end
    return out
end

function _unmarshal_client_hello(data::Vector{UInt8})::Union{_ClientHelloMsg, Nothing}
    msg = _ClientHelloMsg(original = data)
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
                server_name = _bytes_to_string(server_name_bytes)
                (server_name === nothing || endswith(server_name, ".")) && return nothing
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
                protocol = _bytes_to_string(protocol_bytes)
                protocol === nothing && return nothing
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
            _read_remaining_bytes!(ext_reader)
        end

        _reader_empty(ext_reader) || return nothing
    end

    return msg
end

function _unmarshal_server_hello(data::Vector{UInt8})::Union{_ServerHelloMsg, Nothing}
    msg = _ServerHelloMsg(original = data)
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
            protocol = _bytes_to_string(protocol_bytes)
            protocol === nothing && return nothing
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
            if length(ext_reader.data) == 2
                selected_group = _read_u16!(ext_reader)
                selected_group === nothing && return nothing
                msg.selected_group = selected_group
            else
                group = _read_u16!(ext_reader)
                key_share_data = _read_u16_length_prefixed_bytes!(ext_reader)
                (group === nothing || key_share_data === nothing) && return nothing
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
            _read_remaining_bytes!(ext_reader)
        end

        _reader_empty(ext_reader) || return nothing
    end

    return msg
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
            protocol = _bytes_to_string(protocol_bytes)
            protocol === nothing && return nothing
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
            _read_remaining_bytes!(ext_reader)
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
    return _FinishedMsg(verify_data = verify_data)
end

function _unmarshal_handshake_message(data::AbstractVector{UInt8}, transcript::Union{Nothing, _TranscriptHash} = nothing)::Union{_HandshakeMessage, Nothing}
    raw = _copy_valid_handshake_frame(data)
    raw === nothing && return nothing

    msg = if raw[1] == _HANDSHAKE_TYPE_CLIENT_HELLO
        _unmarshal_client_hello(raw)
    elseif raw[1] == _HANDSHAKE_TYPE_SERVER_HELLO
        _unmarshal_server_hello(raw)
    elseif raw[1] == _HANDSHAKE_TYPE_ENCRYPTED_EXTENSIONS
        _unmarshal_encrypted_extensions(raw)
    elseif raw[1] == _HANDSHAKE_TYPE_FINISHED
        _unmarshal_finished(raw)
    else
        nothing
    end

    msg === nothing && return nothing
    transcript === nothing || _transcript_update!(transcript, raw)
    return msg
end

function _handshake_transcript_bytes(msg::_ClientHelloMsg)::Vector{UInt8}
    msg.original === nothing && return _marshal_handshake_message(msg)
    return copy(msg.original::Vector{UInt8})
end

function _handshake_transcript_bytes(msg::_ServerHelloMsg)::Vector{UInt8}
    msg.original === nothing && return _marshal_handshake_message(msg)
    return copy(msg.original::Vector{UInt8})
end

@inline _handshake_transcript_bytes(msg::_EncryptedExtensionsMsg)::Vector{UInt8} = _marshal_handshake_message(msg)
@inline _handshake_transcript_bytes(msg::_FinishedMsg)::Vector{UInt8} = _marshal_handshake_message(msg)

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

function _read_u32!(reader::_HandshakeReader)::Union{UInt32, Nothing}
    reader.pos + 3 > length(reader.data) && return nothing
    b1 = UInt32(reader.data[reader.pos])
    b2 = UInt32(reader.data[reader.pos + 1])
    b3 = UInt32(reader.data[reader.pos + 2])
    b4 = UInt32(reader.data[reader.pos + 3])
    reader.pos += 4
    return (b1 << 24) | (b2 << 16) | (b3 << 8) | b4
end
