# QUIC packet protection (RFC 9001 Section 5), QUIC version 1.
#
# Packets are protected in place inside a caller's buffer, addressed by index
# ranges, so a datagram holding several coalesced packets is never copied. The
# AEAD covers the payload, with the unprotected header as associated data; then
# header protection masks the low bits of the first byte and the packet number
# with bytes derived from a sample of the ciphertext.

const _INITIAL_SALT_V1 = hex2bytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
# RFC 9001 Section 5.8.
const _RETRY_INTEGRITY_KEY_V1 = hex2bytes("be0c690b9f66575a1d766b54e368c84e")
const _RETRY_INTEGRITY_NONCE_V1 = hex2bytes("461599d35d632bf2239825bb")
const _AEAD_TAG_LEN = 16
const _HP_SAMPLE_LEN = 16
const _MAX_PACKET_NUMBER = (Int64(1) << 62) - 1

"""
    _HeaderProtector

Header protection key for one direction (RFC 9001 Section 5.4), with the
OpenSSL context keyed once and reused for every packet. AES suites use AES-ECB;
ChaCha20-Poly1305 uses raw ChaCha20. A key update keeps the same protector.
"""
mutable struct _HeaderProtector
    chacha::Bool
    key::Vector{UInt8}
    ctx::Ptr{Cvoid}
    mask::Vector{UInt8}
end

function _HeaderProtector(suite::UInt16, key::Vector{UInt8})
    chacha = suite == _TLS13_CHACHA20_POLY1305_SHA256_ID
    cipher = if chacha
        ccall((:EVP_chacha20, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
    elseif length(key) == 16
        ccall((:EVP_aes_128_ecb, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
    else
        ccall((:EVP_aes_256_ecb, _LIBCRYPTO_PATH), Ptr{Cvoid}, ())
    end
    ctx = _openssl_require_nonnull(ccall((:EVP_CIPHER_CTX_new, _LIBCRYPTO_PATH), Ptr{Cvoid}, ()), "EVP_CIPHER_CTX_new")
    hp = _HeaderProtector(chacha, key, ctx, zeros(UInt8, _HP_SAMPLE_LEN))
    finalizer(_destroy_header_protector!, hp)
    ok = GC.@preserve key ccall(
        (:EVP_EncryptInit_ex, _LIBCRYPTO_PATH), Cint,
        (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}),
        ctx, cipher, C_NULL, pointer(key), Ptr{UInt8}(C_NULL),
    )
    _openssl_require_ok(ok, "EVP_EncryptInit_ex(hp)")
    if !chacha
        ok = ccall((:EVP_CIPHER_CTX_set_padding, _LIBCRYPTO_PATH), Cint, (Ptr{Cvoid}, Cint), ctx, Cint(0))
        _openssl_require_ok(ok, "EVP_CIPHER_CTX_set_padding")
    end
    return hp
end

function _destroy_header_protector!(hp::_HeaderProtector)::Nothing
    _free_evp_cipher_ctx!(hp.ctx)
    hp.ctx = C_NULL
    _securezero!(hp.key)
    return nothing
end

# Fills `hp.mask[1:5]` from the 16-byte sample at `buf[sample_pos]`.
function _header_protection_mask!(hp::_HeaderProtector, buf::Vector{UInt8}, sample_pos::Int)::Vector{UInt8}
    hp.ctx == C_NULL && throw(ArgumentError("QUIC header protection key was destroyed"))
    out_len = Ref{Cint}(0)
    mask = hp.mask
    GC.@preserve buf mask begin
        sample = pointer(buf, sample_pos)
        if hp.chacha
            # The sample is the 4-byte little-endian block counter followed by
            # the 12-byte nonce, which is exactly OpenSSL's ChaCha20 IV layout.
            # The mask is the keystream, i.e. ChaCha20 applied to zero bytes.
            ok = ccall(
                (:EVP_EncryptInit_ex, _LIBCRYPTO_PATH), Cint,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{UInt8}, Ptr{UInt8}),
                hp.ctx, C_NULL, C_NULL, Ptr{UInt8}(C_NULL), sample,
            )
            _openssl_require_ok(ok, "EVP_EncryptInit_ex(hp sample)")
            fill!(mask, 0x00)
            ok = ccall(
                (:EVP_EncryptUpdate, _LIBCRYPTO_PATH), Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, Cint),
                hp.ctx, pointer(mask), out_len, pointer(mask), Cint(5),
            )
        else
            ok = ccall(
                (:EVP_EncryptUpdate, _LIBCRYPTO_PATH), Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Ref{Cint}, Ptr{UInt8}, Cint),
                hp.ctx, pointer(mask), out_len, sample, Cint(_HP_SAMPLE_LEN),
            )
        end
        _openssl_require_ok(ok, "EVP_EncryptUpdate(hp)")
    end
    return mask
end

# Long headers protect the low 4 bits of the first byte, short headers 5. The
# header form bit itself is never masked.
@inline _first_byte_mask(first_byte::UInt8, mask_byte::UInt8)::UInt8 =
    mask_byte & ((first_byte & 0x80) != 0 ? 0x0f : 0x1f)

# Applies (or, identically, removes) the mask to the first byte and the
# `pn_len` packet number bytes.
@inline function _xor_header_mask!(buf::Vector{UInt8}, first::Int, pn_offset::Int, pn_len::Int, mask::Vector{UInt8})::Nothing
    buf[first] ⊻= _first_byte_mask(buf[first], mask[1])
    for i in 1:pn_len
        buf[pn_offset + i - 1] ⊻= mask[i + 1]
    end
    return nothing
end

"""
    _PacketKeys

Packet protection keys for one direction at one encryption level: the AEAD key
and IV derived from a TLS traffic secret (RFC 9001 Section 5.1), plus the
header protection key, which outlives key updates.
"""
mutable struct _PacketKeys
    suite::UInt16
    spec::_TLS13CipherSpec
    secret::Vector{UInt8}
    key::Vector{UInt8}
    iv::Vector{UInt8}
    nonce::Vector{UInt8}
    aead::_OpenSSLAEADState
    hp::_HeaderProtector
end

function _new_packet_keys(suite::UInt16, spec::_TLS13CipherSpec, secret::Vector{UInt8}, hp::_HeaderProtector)::_PacketKeys
    key = _tls13_expand_label(spec.hash_kind, secret, "quic key", UInt8[], spec.key_length)
    iv = _tls13_expand_label(spec.hash_kind, secret, "quic iv", UInt8[], spec.iv_length)
    keys = _PacketKeys(suite, spec, secret, key, iv, zeros(UInt8, spec.iv_length), _OpenSSLAEADState(_tls13_record_cipher(spec), spec.iv_length), hp)
    finalizer(_destroy_packet_keys!, keys)
    return keys
end

"""
    _PacketKeys(suite::UInt16, secret) -> _PacketKeys

Keys from a traffic secret, such as one carried by a `TLS.QUICConn`
`SetReadSecret` or `SetWriteSecret` event. `suite` is the TLS 1.3 cipher suite.
"""
function _PacketKeys(suite::UInt16, secret::AbstractVector{UInt8})::_PacketKeys
    spec = _tls13_cipher_spec(suite)
    spec === nothing && throw(ArgumentError("QUIC packet protection needs a TLS 1.3 cipher suite, got 0x$(string(suite; base = 16, pad = 4))"))
    owned_secret = Vector{UInt8}(secret)
    hp_key = _tls13_expand_label(spec.hash_kind, owned_secret, "quic hp", UInt8[], spec.key_length)
    return _new_packet_keys(suite, spec, owned_secret, _HeaderProtector(suite, hp_key))
end

"""
    _next_packet_keys(keys) -> _PacketKeys

Keys for the next key phase (RFC 9001 Section 6.1): a new secret from the
"quic ku" label and new AEAD keys, with the same header protection key.
"""
function _next_packet_keys(keys::_PacketKeys)::_PacketKeys
    spec = keys.spec
    secret = _tls13_expand_label(spec.hash_kind, keys.secret, "quic ku", UInt8[], _hash_len(spec.hash_kind))
    return _new_packet_keys(keys.suite, spec, secret, keys.hp)
end

"""
    _destroy_packet_keys!(keys)

Zero the secret and AEAD keys and free the AEAD context. The header protector
may be shared with other key phases, so it is left to its own finalizer.
"""
function _destroy_packet_keys!(keys::_PacketKeys)::Nothing
    _free_openssl_aead_state!(keys.aead)
    _securezero!(keys.secret)
    _securezero!(keys.key)
    _securezero!(keys.iv)
    _securezero!(keys.nonce)
    return nothing
end

"""
    _initial_secrets(dcid) -> (client_secret, server_secret)

Initial secrets (RFC 9001 Section 5.2) from the Destination Connection ID of
the client's first Initial packet.
"""
function _initial_secrets(dcid::AbstractVector{UInt8})::Tuple{Vector{UInt8}, Vector{UInt8}}
    initial_secret = _hkdf_extract(_HASH_SHA256, Vector{UInt8}(dcid), _INITIAL_SALT_V1)
    try
        client = _tls13_expand_label(_HASH_SHA256, initial_secret, "client in", UInt8[], _hash_len(_HASH_SHA256))
        server = _tls13_expand_label(_HASH_SHA256, initial_secret, "server in", UInt8[], _hash_len(_HASH_SHA256))
        return client, server
    finally
        _securezero!(initial_secret)
    end
end

"""
    _initial_packet_keys(dcid) -> (client_keys, server_keys)

Initial packet keys for both directions. Initial packets always use
AEAD_AES_128_GCM.
"""
function _initial_packet_keys(dcid::AbstractVector{UInt8})::Tuple{_PacketKeys, _PacketKeys}
    client_secret, server_secret = _initial_secrets(dcid)
    try
        return _PacketKeys(_TLS13_AES_128_GCM_SHA256_ID, client_secret), _PacketKeys(_TLS13_AES_128_GCM_SHA256_ID, server_secret)
    finally
        _securezero!(client_secret)
        _securezero!(server_secret)
    end
end

"""
    _packet_nonce!(keys, pn) -> Vector{UInt8}

The AEAD nonce for packet number `pn`: the IV with the packet number XORed into
its last 8 bytes (RFC 9001 Section 5.3). Returns `keys.nonce`, reused per call.
"""
function _packet_nonce!(keys::_PacketKeys, pn::Int64)::Vector{UInt8}
    nonce = keys.nonce
    copyto!(nonce, keys.iv)
    n = length(nonce)
    for i in 0:7
        nonce[n - i] ⊻= UInt8((pn >> (8 * i)) & 0xff)
    end
    return nonce
end

"""
    _seal_packet!(keys, buf, first, pn_offset, pn_len, payload_last, pn) -> Int

Protect one packet in place. `buf[first:payload_last]` holds the header, with
the `pn_len`-byte truncated packet number written at `pn_offset`, followed by
the plaintext payload. A long header's Length field must already count the
16-byte tag, which is written to `buf[payload_last+1:payload_last+16]`. Returns
the index of the packet's last byte.
"""
function _seal_packet!(
        keys::_PacketKeys,
        buf::Vector{UInt8},
        first::Int,
        pn_offset::Int,
        pn_len::Int,
        payload_last::Int,
        pn::Int64,
    )::Int
    1 <= pn_len <= 4 || throw(ArgumentError("QUIC packet number length must be 1 to 4 bytes"))
    first <= pn_offset || throw(ArgumentError("QUIC packet number must follow the packet start"))
    # The receiver learns the length from these bits once it unmasks them.
    Int(buf[first] & 0x03) + 1 == pn_len ||
        throw(ArgumentError("QUIC packet header's packet number length bits do not match pn_len"))
    payload_first = pn_offset + pn_len
    last = payload_last + _AEAD_TAG_LEN
    last <= length(buf) || throw(ArgumentError("QUIC packet buffer has no room for the AEAD tag"))
    # RFC 9001 Section 5.4.2: the sample starts 4 bytes after the packet
    # number, as if it were 4 bytes long; senders pad short packets to fit it.
    sample_pos = pn_offset + 4
    sample_pos + _HP_SAMPLE_LEN - 1 <= last ||
        throw(ArgumentError("QUIC packet is too short to sample for header protection; pad the payload"))
    nonce = _packet_nonce!(keys, pn)
    GC.@preserve buf _openssl_encrypt_record_aead!(
        keys.aead,
        buf,
        payload_first,
        payload_last - payload_first + 1,
        keys.key,
        nonce,
        pointer(buf, first),
        payload_first - first,
    )
    _xor_header_mask!(buf, first, pn_offset, pn_len, _header_protection_mask!(keys.hp, buf, sample_pos))
    return last
end

"""
    _remove_header_protection!(hp, buf, first, pn_offset, last) -> (pn_len, truncated_pn) or nothing

Unmask the header of the packet in `buf[first:last]` in place. A receiver does
this before choosing payload keys, since the first byte carries the key phase.
Returns `nothing` when the packet is too short to hold the sample; drop it.
"""
function _remove_header_protection!(
        hp::_HeaderProtector,
        buf::Vector{UInt8},
        first::Int,
        pn_offset::Int,
        last::Int,
    )::Union{Nothing, Tuple{Int, UInt64}}
    sample_pos = pn_offset + 4
    (first <= pn_offset && sample_pos + _HP_SAMPLE_LEN - 1 <= last && last <= length(buf)) || return nothing
    mask = _header_protection_mask!(hp, buf, sample_pos)
    # The packet number length is itself masked, so unmask the first byte alone first.
    buf[first] ⊻= _first_byte_mask(buf[first], mask[1])
    pn_len = Int(buf[first] & 0x03) + 1
    truncated = UInt64(0)
    for i in 1:pn_len
        byte = buf[pn_offset + i - 1] ⊻ mask[i + 1]
        buf[pn_offset + i - 1] = byte
        truncated = (truncated << 8) | byte
    end
    return pn_len, truncated
end

"""
    _decrypt_payload!(keys, buf, first, pn_offset, pn_len, pn, last) -> payload_last or nothing

Decrypt the payload of the packet in `buf[first:last]` in place, after
`_remove_header_protection!`. Returns the index of the last plaintext byte,
or `nothing` when authentication fails; drop the packet.
"""
function _decrypt_payload!(
        keys::_PacketKeys,
        buf::Vector{UInt8},
        first::Int,
        pn_offset::Int,
        pn_len::Int,
        pn::Int64,
        last::Int,
    )::Union{Nothing, Int}
    payload_first = pn_offset + pn_len
    ciphertext_len = last - payload_first + 1 - _AEAD_TAG_LEN
    ciphertext_len >= 0 || return nothing
    nonce = _packet_nonce!(keys, pn)
    plaintext_len = GC.@preserve buf _openssl_decrypt_record_aead!(
        keys.aead,
        buf,
        payload_first,
        ciphertext_len,
        last - _AEAD_TAG_LEN + 1,
        keys.key,
        nonce,
        pointer(buf, first),
        payload_first - first,
    )
    plaintext_len === nothing && return nothing
    return payload_first + plaintext_len - 1
end

"""
    _open_packet!(keys, buf, first, pn_offset, last, largest_pn) -> (pn, payload_first, payload_last) or nothing

Remove header and payload protection from the packet in `buf[first:last]` in
place. `last` comes from a long header's Length field or the datagram end, and
`largest_pn` is the largest packet number received so far in this packet number
space (-1 for none). Returns `nothing` for a packet to drop.
"""
function _open_packet!(
        keys::_PacketKeys,
        buf::Vector{UInt8},
        first::Int,
        pn_offset::Int,
        last::Int,
        largest_pn::Int64,
    )::Union{Nothing, Tuple{Int64, Int, Int}}
    unmasked = _remove_header_protection!(keys.hp, buf, first, pn_offset, last)
    unmasked === nothing && return nothing
    pn_len, truncated = unmasked
    pn = _decode_packet_number(largest_pn, truncated, 8 * pn_len)
    payload_last = _decrypt_payload!(keys, buf, first, pn_offset, pn_len, pn, last)
    payload_last === nothing && return nothing
    return pn, pn_offset + pn_len, payload_last
end

"""
    _decode_packet_number(largest_pn, truncated, pn_nbits) -> Int64

Full packet number from its truncated encoding (RFC 9000 Appendix A.3): the
value closest to `largest_pn + 1` whose low `pn_nbits` bits match.
"""
function _decode_packet_number(largest_pn::Int64, truncated::UInt64, pn_nbits::Int)::Int64
    expected = largest_pn + 1
    win = Int64(1) << pn_nbits
    hwin = win >> 1
    candidate = (expected & ~(win - 1)) | Int64(truncated)
    if candidate <= expected - hwin && candidate < (Int64(1) << 62) - win
        return candidate + win
    elseif candidate > expected + hwin && candidate >= win
        return candidate - win
    end
    return candidate
end

"""
    _packet_number_length(pn, largest_acked) -> Int

Bytes needed to send `pn` so the peer can decode it (RFC 9000 Appendix A.2):
enough bits for twice the packets in flight. `largest_acked` is -1 before any
acknowledgment. This rounds up at exact powers of two, one bit more
conservative than the RFC's real-valued formula.
"""
function _packet_number_length(pn::Int64, largest_acked::Int64)::Int
    0 <= pn <= _MAX_PACKET_NUMBER || throw(ArgumentError("QUIC packet number out of range"))
    num_unacked = largest_acked < 0 ? pn + 1 : pn - largest_acked
    num_unacked > 0 || throw(ArgumentError("QUIC packet number must exceed the largest acknowledged"))
    nbits = (64 - leading_zeros(num_unacked)) + 1
    return min(cld(nbits, 8), 4)
end

"""
    _write_packet_number!(buf, pos, pn, pn_len)

Write the low `pn_len` bytes of `pn`, big endian, at `buf[pos]`.
"""
function _write_packet_number!(buf::Vector{UInt8}, pos::Int, pn::Int64, pn_len::Int)::Nothing
    1 <= pn_len <= 4 || throw(ArgumentError("QUIC packet number length must be 1 to 4 bytes"))
    for i in 1:pn_len
        buf[pos + i - 1] = UInt8((pn >> (8 * (pn_len - i))) & 0xff)
    end
    return nothing
end

"""
    _retry_integrity_tag(odcid, retry_without_tag) -> Vector{UInt8}

Retry Integrity Tag (RFC 9001 Section 5.8): AES-128-GCM with fixed key and
nonce over the Retry pseudo-packet, the original Destination Connection ID
prefixed with its length, then the Retry packet without its tag.
"""
function _retry_integrity_tag(odcid::AbstractVector{UInt8}, retry_without_tag::AbstractVector{UInt8})::Vector{UInt8}
    length(odcid) <= 20 || throw(ArgumentError("QUIC connection IDs are at most 20 bytes"))
    pseudo = Vector{UInt8}(undef, 1 + length(odcid) + length(retry_without_tag))
    pseudo[1] = UInt8(length(odcid))
    copyto!(pseudo, 2, odcid, 1, length(odcid))
    copyto!(pseudo, 2 + length(odcid), retry_without_tag, 1, length(retry_without_tag))
    return _tls13_encrypt_record_aead(_TLS13_AES_128_GCM_SHA256, _RETRY_INTEGRITY_KEY_V1, _RETRY_INTEGRITY_NONCE_V1, pseudo, UInt8[])
end

"""
    _valid_retry_integrity(odcid, retry_packet) -> Bool

Whether the tag ending `retry_packet` matches for the connection ID the client
first sent to.
"""
function _valid_retry_integrity(odcid::AbstractVector{UInt8}, retry_packet::AbstractVector{UInt8})::Bool
    n = length(retry_packet)
    (n > _AEAD_TAG_LEN && length(odcid) <= 20) || return false
    expected = _retry_integrity_tag(odcid, @view(retry_packet[1:(n - _AEAD_TAG_LEN)]))
    return _constant_time_equals(expected, @view(retry_packet[(n - _AEAD_TAG_LEN + 1):n]))
end
