# QUIC wire format: variable-length integers (RFC 9000 Section 16), packet
# headers (Section 17), and coalesced packets (Section 12.2).
#
# Parsing reads only the header fields that are not header protected, and
# records where each field sits in the datagram buffer rather than copying it.
# Malformed packets parse to `nothing`; receivers drop them without a reply.

const _QUIC_V1 = UInt32(0x00000001)
const _MAX_VARINT = (UInt64(1) << 62) - 1
const _MAX_CID_LEN_V1 = 20
# Builders always write Length as a 2-byte varint so it can be filled in after
# the payload; that caps a long header packet below 16 KiB, well above any
# path MTU.
const _LENGTH_FIELD_LEN = 2

# Kind of a parsed QUIC packet. `UnsupportedVersion` is a long header packet of
# a version other than 1, of which only the version-independent fields (RFC
# 8999) are read, so a server can answer with Version Negotiation.
module _PacketType
Base.@enum T::UInt8 begin
    Initial = 0
    ZeroRTT = 1
    Handshake = 2
    Retry = 3
    VersionNegotiation = 4
    OneRTT = 5
    UnsupportedVersion = 6
end
end

# Long Packet Type bits in version 1, in order.
const _LONG_PACKET_TYPES = (_PacketType.Initial, _PacketType.ZeroRTT, _PacketType.Handshake, _PacketType.Retry)

@inline function _varint_length(v::UInt64)::Int
    v < 0x40 && return 1
    v < 0x4000 && return 2
    v < 0x40000000 && return 4
    v <= _MAX_VARINT && return 8
    throw(ArgumentError("QUIC variable-length integers stop at 2^62 - 1"))
end

@inline function _varint_prefix(len::Int)::UInt8
    len == 1 && return 0x00
    len == 2 && return 0x40
    len == 4 && return 0x80
    len == 8 && return 0xc0
    throw(ArgumentError("QUIC variable-length integers are 1, 2, 4, or 8 bytes"))
end

"""
    _write_varint!(buf, pos, v, len)

Write `v` at `buf[pos]` as a `len`-byte variable-length integer.
"""
function _write_varint!(buf::Vector{UInt8}, pos::Int, v::UInt64, len::Int)::Nothing
    prefix = _varint_prefix(len)
    v < (UInt64(1) << (8 * len - 2)) || throw(ArgumentError("value $(v) does not fit a $(len)-byte QUIC variable-length integer"))
    for i in 1:len
        buf[pos + i - 1] = UInt8((v >> (8 * (len - i))) & 0xff)
    end
    buf[pos] |= prefix
    return nothing
end

"""
    _append_varint!(buf, v, len = _varint_length(v))

Append `v` as a variable-length integer, by default in its shortest form.
"""
function _append_varint!(buf::Vector{UInt8}, v::UInt64, len::Int = _varint_length(v))::Nothing
    pos = length(buf) + 1
    resize!(buf, length(buf) + len)
    _write_varint!(buf, pos, v, len)
    return nothing
end

"""
    _read_varint(buf, pos, last) -> (value, next_pos) or nothing

Read a variable-length integer at `buf[pos]` without reading past `last`.
"""
function _read_varint(buf::Vector{UInt8}, pos::Int, last::Int)::Union{Nothing, Tuple{UInt64, Int}}
    pos <= last || return nothing
    b = buf[pos]
    len = 1 << (b >> 6)
    pos + len - 1 <= last || return nothing
    v = UInt64(b & 0x3f)
    for i in 1:(len - 1)
        v = (v << 8) | buf[pos + i]
    end
    return v, pos + len
end

"""
    _PacketHeader

Where one packet's fields sit in its datagram buffer. `first:last` is the whole
packet. `pn_offset` is where the (still protected) packet number starts, or 0
for Retry, Version Negotiation, and unsupported versions, which carry none.
`token` is an Initial packet's token or a Retry packet's Retry Token. A short
header's `dcid` uses the connection ID length the receiver chose.
"""
struct _PacketHeader
    type::_PacketType.T
    version::UInt32
    first::Int
    dcid::UnitRange{Int}
    scid::UnitRange{Int}
    token::UnitRange{Int}
    pn_offset::Int
    last::Int
end

"""
    _parse_packet(buf, first, datagram_last, short_dcid_len) -> _PacketHeader or nothing

Parse the packet starting at `buf[first]` in a datagram ending at
`datagram_last`. `short_dcid_len` is the length of the connection IDs this
endpoint issued, which short headers do not encode.
"""
function _parse_packet(buf::Vector{UInt8}, first::Int, datagram_last::Int, short_dcid_len::Int)::Union{Nothing, _PacketHeader}
    (1 <= first <= datagram_last <= length(buf)) || return nothing
    b = buf[first]
    no_range = first:(first - 1)
    if b & 0x80 == 0
        # Short header: the fixed bit must be set in version 1.
        b & 0x40 == 0 && return nothing
        pn_offset = first + 1 + short_dcid_len
        pn_offset <= datagram_last || return nothing
        return _PacketHeader(_PacketType.OneRTT, _QUIC_V1, first, (first + 1):(pn_offset - 1), no_range, no_range, pn_offset, datagram_last)
    end
    # Version-independent long header fields (RFC 8999 Section 5.1).
    pos = first + 1
    pos + 4 <= datagram_last || return nothing
    version = (UInt32(buf[pos]) << 24) | (UInt32(buf[pos + 1]) << 16) | (UInt32(buf[pos + 2]) << 8) | UInt32(buf[pos + 3])
    pos += 4
    dcid_len = Int(buf[pos])
    dcid = (pos + 1):(pos + dcid_len)
    pos += 1 + dcid_len
    pos <= datagram_last || return nothing
    scid_len = Int(buf[pos])
    scid = (pos + 1):(pos + scid_len)
    pos += 1 + scid_len
    pos <= datagram_last + 1 || return nothing
    if version == 0x00000000
        # Version Negotiation: the rest of the datagram lists 32-bit versions.
        n = datagram_last - pos + 1
        (n > 0 && n % 4 == 0) || return nothing
        return _PacketHeader(_PacketType.VersionNegotiation, version, first, dcid, scid, no_range, 0, datagram_last)
    end
    version == _QUIC_V1 ||
        return _PacketHeader(_PacketType.UnsupportedVersion, version, first, dcid, scid, no_range, 0, datagram_last)
    (dcid_len <= _MAX_CID_LEN_V1 && scid_len <= _MAX_CID_LEN_V1) || return nothing
    b & 0x40 == 0 && return nothing
    type = _LONG_PACKET_TYPES[((b >> 4) & 0x03) + 1]
    if type == _PacketType.Retry
        # A Retry Token, then the 16-byte integrity tag. Clients discard a Retry
        # with an empty token (RFC 9000 Section 17.2.5.2).
        token = pos:(datagram_last - _AEAD_TAG_LEN)
        isempty(token) && return nothing
        return _PacketHeader(type, version, first, dcid, scid, token, 0, datagram_last)
    end
    token = no_range
    if type == _PacketType.Initial
        parsed = _read_varint(buf, pos, datagram_last)
        parsed === nothing && return nothing
        token_len, pos = parsed
        token_len <= UInt64(datagram_last - pos + 1) || return nothing
        token = pos:(pos + Int(token_len) - 1)
        pos += Int(token_len)
    end
    parsed = _read_varint(buf, pos, datagram_last)
    parsed === nothing && return nothing
    len, pos = parsed
    # Length counts the packet number and the protected payload.
    (len >= 1 && len <= UInt64(datagram_last - pos + 1)) || return nothing
    return _PacketHeader(type, version, first, dcid, scid, token, pos, pos + Int(len) - 1)
end

"""
    _datagram_packets(buf, first, last, short_dcid_len)

Iterate the packets coalesced in the datagram `buf[first:last]` as
`_PacketHeader`s. Iteration stops at the first malformed packet, such as zero
padding after the last packet, and at any packet whose Destination Connection
ID differs from the first packet's (RFC 9000 Section 12.2).
"""
_datagram_packets(buf::Vector{UInt8}, first::Int, last::Int, short_dcid_len::Int) = _DatagramPackets(buf, first, last, short_dcid_len)

struct _DatagramPackets
    buf::Vector{UInt8}
    first::Int
    last::Int
    short_dcid_len::Int
end

Base.IteratorSize(::Type{_DatagramPackets}) = Base.SizeUnknown()
Base.eltype(::Type{_DatagramPackets}) = _PacketHeader

function Base.iterate(d::_DatagramPackets, state::Tuple{Int, UnitRange{Int}} = (d.first, 1:0))
    pos, first_dcid = state
    pos > d.last && return nothing
    header = _parse_packet(d.buf, pos, d.last, d.short_dcid_len)
    header === nothing && return nothing
    if pos == d.first
        first_dcid = header.dcid
    elseif @view(d.buf[header.dcid]) != @view(d.buf[first_dcid])
        return nothing
    end
    return header, (header.last + 1, first_dcid)
end

"""
    _reserved_bits_ok(first_byte) -> Bool

Whether the reserved bits of an unprotected first byte are zero. A nonzero
value after successful decryption is a PROTOCOL_VIOLATION (RFC 9000 Section
17.2 and 17.3.1).
"""
@inline _reserved_bits_ok(first_byte::UInt8)::Bool =
    first_byte & ((first_byte & 0x80) != 0 ? 0x0c : 0x18) == 0x00

"""
    _PacketLayout

Positions of a packet being built: where it starts, where its packet number
sits, and where its Length field is (0 for a short header).
"""
struct _PacketLayout
    first::Int
    pn_offset::Int
    pn_len::Int
    length_pos::Int
end

function _append_u32!(buf::Vector{UInt8}, v::UInt32)::Nothing
    push!(buf, UInt8(v >> 24), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff))
    return nothing
end

function _append_packet_number!(buf::Vector{UInt8}, pn::Int64, pn_len::Int)::Int
    pn_offset = length(buf) + 1
    resize!(buf, length(buf) + pn_len)
    _write_packet_number!(buf, pn_offset, pn, pn_len)
    return pn_offset
end

"""
    _begin_long_packet!(buf, type, version, dcid, scid, token, pn, pn_len) -> _PacketLayout

Append an Initial, 0-RTT, or Handshake header to `buf`. Append the payload's
frames next, then call [`_end_packet!`](@ref). Only Initial packets carry a
token.
"""
function _begin_long_packet!(
        buf::Vector{UInt8},
        type::_PacketType.T,
        version::UInt32,
        dcid::AbstractVector{UInt8},
        scid::AbstractVector{UInt8},
        token::AbstractVector{UInt8},
        pn::Int64,
        pn_len::Int,
    )::_PacketLayout
    1 <= pn_len <= 4 || throw(ArgumentError("QUIC packet number length must be 1 to 4 bytes"))
    type_bits = findfirst(==(type), _LONG_PACKET_TYPES)
    (type_bits === nothing || type == _PacketType.Retry) &&
        throw(ArgumentError("QUIC long header packets with a packet number are Initial, 0-RTT, or Handshake"))
    (length(dcid) <= _MAX_CID_LEN_V1 && length(scid) <= _MAX_CID_LEN_V1) ||
        throw(ArgumentError("QUIC version 1 connection IDs are at most 20 bytes"))
    isempty(token) || type == _PacketType.Initial || throw(ArgumentError("only QUIC Initial packets carry a token"))
    first = length(buf) + 1
    push!(buf, 0xc0 | (UInt8(type_bits - 1) << 4) | UInt8(pn_len - 1))
    _append_u32!(buf, version)
    push!(buf, UInt8(length(dcid)))
    append!(buf, dcid)
    push!(buf, UInt8(length(scid)))
    append!(buf, scid)
    if type == _PacketType.Initial
        _append_varint!(buf, UInt64(length(token)))
        append!(buf, token)
    end
    length_pos = length(buf) + 1
    resize!(buf, length(buf) + _LENGTH_FIELD_LEN)  # filled in by `_end_packet!`
    pn_offset = _append_packet_number!(buf, pn, pn_len)
    return _PacketLayout(first, pn_offset, pn_len, length_pos)
end

"""
    _begin_short_packet!(buf, dcid, pn, pn_len; key_phase = false, spin = false) -> _PacketLayout

Append a 1-RTT (short) header to `buf`. Append the payload's frames next, then
call [`_end_packet!`](@ref).
"""
function _begin_short_packet!(
        buf::Vector{UInt8},
        dcid::AbstractVector{UInt8},
        pn::Int64,
        pn_len::Int;
        key_phase::Bool = false,
        spin::Bool = false,
    )::_PacketLayout
    1 <= pn_len <= 4 || throw(ArgumentError("QUIC packet number length must be 1 to 4 bytes"))
    length(dcid) <= _MAX_CID_LEN_V1 || throw(ArgumentError("QUIC version 1 connection IDs are at most 20 bytes"))
    first = length(buf) + 1
    push!(buf, 0x40 | (UInt8(spin) << 5) | (UInt8(key_phase) << 2) | UInt8(pn_len - 1))
    append!(buf, dcid)
    pn_offset = _append_packet_number!(buf, pn, pn_len)
    return _PacketLayout(first, pn_offset, pn_len, 0)
end

"""
    _end_packet!(buf, layout; pad_to = 0) -> payload_last

Finish the packet at the end of `buf`: add PADDING frames until the header
protection sample fits (RFC 9001 Section 5.4.2) and the packet, tag included,
reaches index `pad_to`; fill in a long header's Length; and append room for the
AEAD tag. The packet is then ready for `_seal_packet!`.
"""
function _end_packet!(buf::Vector{UInt8}, layout::_PacketLayout; pad_to::Int = 0)::Int
    payload_first = layout.pn_offset + layout.pn_len
    length(buf) >= payload_first - 1 || throw(ArgumentError("QUIC packet buffer ends before its packet number"))
    # The sample starts 4 bytes after the packet number, and the tag supplies
    # the last 16 bytes it needs, so the packet number and payload need 4.
    payload_last = max(length(buf), layout.pn_offset + 3, pad_to - _AEAD_TAG_LEN)
    length(buf) < payload_last && _append_zeros!(buf, payload_last - length(buf))  # PADDING frames
    if layout.length_pos != 0
        len = payload_last + _AEAD_TAG_LEN - layout.pn_offset + 1
        len < (1 << (8 * _LENGTH_FIELD_LEN - 2)) ||
            throw(ArgumentError("QUIC long header packet is too large for its 2-byte Length field"))
        _write_varint!(buf, layout.length_pos, UInt64(len), _LENGTH_FIELD_LEN)
    end
    _append_zeros!(buf, _AEAD_TAG_LEN)
    return payload_last
end

# Appends `n` zero bytes without allocating while `buf` has the capacity.
function _append_zeros!(buf::Vector{UInt8}, n::Int)::Nothing
    old = length(buf)
    resize!(buf, old + n)
    fill!(view(buf, (old + 1):(old + n)), 0x00)
    return nothing
end

"""
    _retry_packet(version, dcid, scid, token, odcid; unused_bits = random) -> Vector{UInt8}

A Retry packet carrying `token`, with its integrity tag computed over `odcid`,
the Destination Connection ID of the client's Initial (RFC 9000 Section 17.2.5).
"""
function _retry_packet(
        version::UInt32,
        dcid::AbstractVector{UInt8},
        scid::AbstractVector{UInt8},
        token::AbstractVector{UInt8},
        odcid::AbstractVector{UInt8};
        unused_bits::UInt8 = rand(UInt8),
    )::Vector{UInt8}
    isempty(token) && throw(ArgumentError("a QUIC Retry packet needs a token"))
    (length(dcid) <= _MAX_CID_LEN_V1 && length(scid) <= _MAX_CID_LEN_V1) ||
        throw(ArgumentError("QUIC version 1 connection IDs are at most 20 bytes"))
    buf = UInt8[0xf0 | (unused_bits & 0x0f)]
    _append_u32!(buf, version)
    push!(buf, UInt8(length(dcid)))
    append!(buf, dcid)
    push!(buf, UInt8(length(scid)))
    append!(buf, scid)
    append!(buf, token)
    append!(buf, _retry_integrity_tag(odcid, buf))
    return buf
end

"""
    _version_negotiation_packet(dcid, scid, versions) -> Vector{UInt8}

A Version Negotiation packet listing `versions` (RFC 9000 Section 17.2.1),
and, at a random place among them, one random reserved version of the form
0x?a?a?a?a (Section 15), as quic-go does, so that clients do not come to
depend on the list being exact (Section 6.3). `dcid` and `scid` echo the
client's Source and Destination Connection IDs, and may be up to 255 bytes
since the client's version is unknown.
"""
function _version_negotiation_packet(
        dcid::AbstractVector{UInt8},
        scid::AbstractVector{UInt8},
        versions::AbstractVector{UInt32},
    )::Vector{UInt8}
    isempty(versions) && throw(ArgumentError("a QUIC Version Negotiation packet lists at least one version"))
    (length(dcid) <= 255 && length(scid) <= 255) || throw(ArgumentError("QUIC connection IDs are at most 255 bytes"))
    # The unused bits are random, but the fixed bit is set so the packet looks
    # like other QUIC packets to middleboxes.
    buf = UInt8[0xc0 | (rand(UInt8) & 0x3f)]
    _append_u32!(buf, 0x00000000)
    push!(buf, UInt8(length(dcid)))
    append!(buf, dcid)
    push!(buf, UInt8(length(scid)))
    append!(buf, scid)
    greased = (rand(UInt32) & 0xf0f0f0f0) | 0x0a0a0a0a
    greased_pos = rand(0:length(versions))
    greased_pos == 0 && _append_u32!(buf, greased)
    for (i, v) in enumerate(versions)
        _append_u32!(buf, v)
        i == greased_pos && _append_u32!(buf, greased)
    end
    return buf
end

"""
    _version_negotiation_versions(buf, header) -> Vector{UInt32}

The versions a parsed Version Negotiation packet lists.
"""
function _version_negotiation_versions(buf::Vector{UInt8}, header::_PacketHeader)::Vector{UInt32}
    header.type == _PacketType.VersionNegotiation || throw(ArgumentError("not a QUIC Version Negotiation packet"))
    versions = UInt32[]
    for pos in (header.scid.stop + 1):4:header.last
        push!(versions, (UInt32(buf[pos]) << 24) | (UInt32(buf[pos + 1]) << 16) | (UInt32(buf[pos + 2]) << 8) | UInt32(buf[pos + 3]))
    end
    return versions
end
