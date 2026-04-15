using SHA

Base.@enum _TLSHashKind::UInt8 begin
    _HASH_SHA256 = 1
    _HASH_SHA384 = 2
end

struct _TLS13CipherSpec
    hash_kind::_TLSHashKind
    key_length::Int
    iv_length::Int
end

const _TLS13_AES_128_GCM_SHA256_ID = UInt16(0x1301)
const _TLS13_AES_256_GCM_SHA384_ID = UInt16(0x1302)
const _TLS13_CHACHA20_POLY1305_SHA256_ID = UInt16(0x1303)

const _TLS13_AES_128_GCM_SHA256 = _TLS13CipherSpec(_HASH_SHA256, 16, 12)
const _TLS13_AES_256_GCM_SHA384 = _TLS13CipherSpec(_HASH_SHA384, 32, 12)
const _TLS13_CHACHA20_POLY1305_SHA256 = _TLS13CipherSpec(_HASH_SHA256, 32, 12)

const _TLS12_MASTER_SECRET_LABEL = "master secret"
const _TLS12_EXTENDED_MASTER_SECRET_LABEL = "extended master secret"
const _TLS12_KEY_EXPANSION_LABEL = "key expansion"
const _TLS12_CLIENT_FINISHED_LABEL = "client finished"
const _TLS12_SERVER_FINISHED_LABEL = "server finished"

mutable struct _TranscriptHash{CTX<:SHA.SHA_CTX}
    hash_kind::_TLSHashKind
    ctx::CTX
    buffer::Union{Nothing, Vector{UInt8}}
end

@inline function _securezero!(bytes::Vector{UInt8})::Nothing
    isempty(bytes) || Base.securezero!(bytes)
    return nothing
end

@inline function _constant_time_equals(a::AbstractVector{UInt8}, b::AbstractVector{UInt8})::Bool
    length(a) == length(b) || return false
    diff = UInt8(0)
    @inbounds for i in eachindex(a, b)
        diff |= xor(a[i], b[i])
    end
    return iszero(diff)
end

function _destroy_tls13_secret!(secret)::Nothing
    _securezero!(getfield(secret, :secret))
    return nothing
end

struct _TLS13EarlySecret
    hash_kind::_TLSHashKind
    secret::Vector{UInt8}
end
_TLS13EarlySecret(hash_kind::_TLSHashKind, secret::AbstractVector{UInt8}) = _TLS13EarlySecret(hash_kind, Vector{UInt8}(secret))

struct _TLS13HandshakeSecret
    hash_kind::_TLSHashKind
    secret::Vector{UInt8}
end
_TLS13HandshakeSecret(hash_kind::_TLSHashKind, secret::AbstractVector{UInt8}) = _TLS13HandshakeSecret(hash_kind, Vector{UInt8}(secret))

struct _TLS13MasterSecret
    hash_kind::_TLSHashKind
    secret::Vector{UInt8}
end
_TLS13MasterSecret(hash_kind::_TLSHashKind, secret::AbstractVector{UInt8}) = _TLS13MasterSecret(hash_kind, Vector{UInt8}(secret))

struct _TLS13ExporterMasterSecret
    hash_kind::_TLSHashKind
    secret::Vector{UInt8}
end
_TLS13ExporterMasterSecret(hash_kind::_TLSHashKind, secret::AbstractVector{UInt8}) = _TLS13ExporterMasterSecret(hash_kind, Vector{UInt8}(secret))

@inline function _tls13_cipher_spec(cipher_suite::UInt16)::Union{_TLS13CipherSpec, Nothing}
    cipher_suite == _TLS13_AES_128_GCM_SHA256_ID && return _TLS13_AES_128_GCM_SHA256
    cipher_suite == _TLS13_AES_256_GCM_SHA384_ID && return _TLS13_AES_256_GCM_SHA384
    cipher_suite == _TLS13_CHACHA20_POLY1305_SHA256_ID && return _TLS13_CHACHA20_POLY1305_SHA256
    return nothing
end

@inline function _hash_len(hash_kind::_TLSHashKind)::Int
    hash_kind == _HASH_SHA256 && return 32
    hash_kind == _HASH_SHA384 && return 48
    throw(ArgumentError("unsupported TLS hash kind: $(hash_kind)"))
end

@inline function _new_hash_context(hash_kind::_TLSHashKind)
    hash_kind == _HASH_SHA256 && return SHA.SHA256_CTX()
    hash_kind == _HASH_SHA384 && return SHA.SHA384_CTX()
    throw(ArgumentError("unsupported TLS hash kind: $(hash_kind)"))
end

@inline function _new_hmac_context(hash_kind::_TLSHashKind, key::AbstractVector{UInt8})
    key_bytes = key isa Vector{UInt8} ? copy(key) : Vector{UInt8}(key)
    try
        hash_kind == _HASH_SHA256 && return SHA.HMAC_CTX(SHA.SHA256_CTX(), key_bytes)
        hash_kind == _HASH_SHA384 && return SHA.HMAC_CTX(SHA.SHA384_CTX(), key_bytes)
        throw(ArgumentError("unsupported TLS hash kind: $(hash_kind)"))
    finally
        _securezero!(key_bytes)
    end
end

@inline function _empty_hash_digest(hash_kind::_TLSHashKind)::Vector{UInt8}
    ctx = _new_hash_context(hash_kind)
    return SHA.digest!(ctx)
end

@inline function _hash_data(hash_kind::_TLSHashKind, data::AbstractVector{UInt8})::Vector{UInt8}
    ctx = _new_hash_context(hash_kind)
    SHA.update!(ctx, data)
    return SHA.digest!(ctx)
end

@inline function _copy_hash_context(ctx::CTX)::CTX where {CTX<:SHA.SHA_CTX}
    @static if VERSION >= v"1.12.0-rc1"
        return CTX(copy(ctx.state), ctx.bytecount, copy(ctx.buffer), ctx.used)
    else
        return deepcopy(ctx)
    end
end

@inline function _hash_context_digest(ctx::CTX)::Vector{UInt8} where {CTX<:SHA.SHA_CTX}
    return SHA.digest!(_copy_hash_context(ctx))
end

@inline function _hmac_data(hash_kind::_TLSHashKind, key::AbstractVector{UInt8}, data::AbstractVector{UInt8})::Vector{UInt8}
    ctx = _new_hmac_context(hash_kind, key)
    SHA.update!(ctx, data)
    return SHA.digest!(ctx)
end

function _TranscriptHash(hash_kind::_TLSHashKind; buffer_handshake::Bool = true)
    ctx = _new_hash_context(hash_kind)
    return _TranscriptHash{typeof(ctx)}(hash_kind, ctx, buffer_handshake ? UInt8[] : nothing)
end

function _transcript_update!(transcript::_TranscriptHash, msg::AbstractVector{UInt8})
    SHA.update!(transcript.ctx, msg)
    transcript.buffer === nothing || append!(transcript.buffer::Vector{UInt8}, msg)
    return nothing
end

@inline function _transcript_digest(transcript::_TranscriptHash)::Vector{UInt8}
    return _hash_context_digest(transcript.ctx)
end

@inline function _transcript_buffered_bytes(transcript::_TranscriptHash)::Union{Nothing, Vector{UInt8}}
    transcript.buffer === nothing && return nothing
    return copy(transcript.buffer::Vector{UInt8})
end

function _discard_transcript_buffer!(transcript::_TranscriptHash)
    transcript.buffer = nothing
    return nothing
end

function _transcript_hash_input(hash_kind::_TLSHashKind, transcript::Nothing)::Vector{UInt8}
    return _empty_hash_digest(hash_kind)
end

function _transcript_hash_input(::_TLSHashKind, transcript_hash::AbstractVector{UInt8})::Vector{UInt8}
    return Vector{UInt8}(transcript_hash)
end

function _transcript_hash_input(::_TLSHashKind, transcript::_TranscriptHash)::Vector{UInt8}
    return _transcript_digest(transcript)
end

function _p_hash(hash_kind::_TLSHashKind, secret::AbstractVector{UInt8}, seed::AbstractVector{UInt8}, out_len::Int)::Vector{UInt8}
    out_len >= 0 || throw(ArgumentError("out_len must be >= 0"))
    out_len == 0 && return UInt8[]
    secret_bytes = Vector{UInt8}(secret)
    seed_bytes = Vector{UInt8}(seed)
    try
        a = _hmac_data(hash_kind, secret_bytes, seed_bytes)
        out = UInt8[]
        sizehint!(out, out_len)
        while length(out) < out_len
            ctx = _new_hmac_context(hash_kind, secret_bytes)
            SHA.update!(ctx, a)
            isempty(seed_bytes) || SHA.update!(ctx, seed_bytes)
            append!(out, SHA.digest!(ctx))
            a = _hmac_data(hash_kind, secret_bytes, a)
        end
        resize!(out, out_len)
        return out
    finally
        _securezero!(secret_bytes)
    end
end

function _tls12_prf(hash_kind::_TLSHashKind, secret::AbstractVector{UInt8}, label::AbstractString, seed::AbstractVector{UInt8}, out_len::Int)::Vector{UInt8}
    label_bytes = codeunits(label)
    seed_bytes = Vector{UInt8}(seed)
    label_seed = UInt8[]
    sizehint!(label_seed, length(label_bytes) + length(seed_bytes))
    append!(label_seed, label_bytes)
    append!(label_seed, seed_bytes)
    return _p_hash(hash_kind, secret, label_seed, out_len)
end

function _tls12_master_from_pre_master_secret(hash_kind::_TLSHashKind, pre_master_secret::AbstractVector{UInt8}, client_random::AbstractVector{UInt8}, server_random::AbstractVector{UInt8})::Vector{UInt8}
    return _tls12_prf(hash_kind, pre_master_secret, _TLS12_MASTER_SECRET_LABEL, vcat(Vector{UInt8}(client_random), Vector{UInt8}(server_random)), 48)
end

function _tls12_extended_master_from_pre_master_secret(hash_kind::_TLSHashKind, pre_master_secret::AbstractVector{UInt8}, transcript_hash::AbstractVector{UInt8})::Vector{UInt8}
    return _tls12_prf(hash_kind, pre_master_secret, _TLS12_EXTENDED_MASTER_SECRET_LABEL, transcript_hash, 48)
end

function _tls12_keys_from_master_secret(hash_kind::_TLSHashKind, master_secret::AbstractVector{UInt8}, client_random::AbstractVector{UInt8}, server_random::AbstractVector{UInt8}, mac_len::Int, key_len::Int, iv_len::Int)
    mac_len >= 0 || throw(ArgumentError("mac_len must be >= 0"))
    key_len >= 0 || throw(ArgumentError("key_len must be >= 0"))
    iv_len >= 0 || throw(ArgumentError("iv_len must be >= 0"))
    seed = vcat(Vector{UInt8}(server_random), Vector{UInt8}(client_random))
    n = 2 * mac_len + 2 * key_len + 2 * iv_len
    key_material = _tls12_prf(hash_kind, master_secret, _TLS12_KEY_EXPANSION_LABEL, seed, n)
    idx = 1
    client_mac = key_material[idx:(idx + mac_len - 1)]
    idx += mac_len
    server_mac = key_material[idx:(idx + mac_len - 1)]
    idx += mac_len
    client_key = key_material[idx:(idx + key_len - 1)]
    idx += key_len
    server_key = key_material[idx:(idx + key_len - 1)]
    idx += key_len
    client_iv = key_material[idx:(idx + iv_len - 1)]
    idx += iv_len
    server_iv = key_material[idx:(idx + iv_len - 1)]
    return client_mac, server_mac, client_key, server_key, client_iv, server_iv
end

function _tls12_export_keying_material(hash_kind::_TLSHashKind, master_secret::AbstractVector{UInt8}, client_random::AbstractVector{UInt8}, server_random::AbstractVector{UInt8}, label::AbstractString, context::Union{Nothing, AbstractVector{UInt8}}, out_len::Int)::Vector{UInt8}
    out_len >= 0 || throw(ArgumentError("length must be >= 0"))
    label == _TLS12_CLIENT_FINISHED_LABEL && throw(ArgumentError("reserved ExportKeyingMaterial label: $(label)"))
    label == _TLS12_SERVER_FINISHED_LABEL && throw(ArgumentError("reserved ExportKeyingMaterial label: $(label)"))
    label == _TLS12_MASTER_SECRET_LABEL && throw(ArgumentError("reserved ExportKeyingMaterial label: $(label)"))
    label == _TLS12_EXTENDED_MASTER_SECRET_LABEL && throw(ArgumentError("reserved ExportKeyingMaterial label: $(label)"))
    label == _TLS12_KEY_EXPANSION_LABEL && throw(ArgumentError("reserved ExportKeyingMaterial label: $(label)"))
    seed = vcat(Vector{UInt8}(client_random), Vector{UInt8}(server_random))
    if context !== nothing
        length(context) < (1 << 16) || throw(ArgumentError("ExportKeyingMaterial context too long"))
        push!(seed, UInt8((length(context) >> 8) & 0xff))
        push!(seed, UInt8(length(context) & 0xff))
        append!(seed, context)
    end
    return _tls12_prf(hash_kind, master_secret, label, seed, out_len)
end

function _tls12_client_finished_verify_data(hash_kind::_TLSHashKind, master_secret::AbstractVector{UInt8}, transcript)::Vector{UInt8}
    return _tls12_prf(hash_kind, master_secret, _TLS12_CLIENT_FINISHED_LABEL, _transcript_hash_input(hash_kind, transcript), 12)
end

function _tls12_server_finished_verify_data(hash_kind::_TLSHashKind, master_secret::AbstractVector{UInt8}, transcript)::Vector{UInt8}
    return _tls12_prf(hash_kind, master_secret, _TLS12_SERVER_FINISHED_LABEL, _transcript_hash_input(hash_kind, transcript), 12)
end

function _hkdf_extract(hash_kind::_TLSHashKind, ikm::Union{Nothing, AbstractVector{UInt8}}, salt::Union{Nothing, AbstractVector{UInt8}})::Vector{UInt8}
    ikm_bytes = ikm === nothing ? zeros(UInt8, _hash_len(hash_kind)) : Vector{UInt8}(ikm)
    salt_bytes = salt === nothing ? zeros(UInt8, _hash_len(hash_kind)) : Vector{UInt8}(salt)
    try
        return _hmac_data(hash_kind, salt_bytes, ikm_bytes)
    finally
        _securezero!(ikm_bytes)
        _securezero!(salt_bytes)
    end
end

function _hkdf_expand(hash_kind::_TLSHashKind, prk::AbstractVector{UInt8}, info::AbstractVector{UInt8}, out_len::Int)::Vector{UInt8}
    out_len >= 0 || throw(ArgumentError("out_len must be >= 0"))
    out_len == 0 && return UInt8[]
    hash_size = _hash_len(hash_kind)
    nblocks = cld(out_len, hash_size)
    nblocks <= 255 || throw(ArgumentError("requested HKDF output too large"))
    out = UInt8[]
    sizehint!(out, out_len)
    prev = UInt8[]
    for counter in 1:nblocks
        ctx = _new_hmac_context(hash_kind, prk)
        isempty(prev) || SHA.update!(ctx, prev)
        isempty(info) || SHA.update!(ctx, info)
        SHA.update!(ctx, UInt8[counter])
        prev = SHA.digest!(ctx)
        append!(out, prev)
    end
    resize!(out, out_len)
    return out
end

function _tls13_expand_label(hash_kind::_TLSHashKind, secret::AbstractVector{UInt8}, label::AbstractString, context::AbstractVector{UInt8}, out_len::Int)::Vector{UInt8}
    out_len >= 0 || throw(ArgumentError("out_len must be >= 0"))
    out_len <= 0xffff || throw(ArgumentError("HKDF-Expand-Label output is too large"))
    label_bytes = Vector{UInt8}(codeunits("tls13 " * label))
    length(label_bytes) <= 0xff || throw(ArgumentError("HKDF-Expand-Label label is too long"))
    length(context) <= 0xff || throw(ArgumentError("HKDF-Expand-Label context is too long"))
    info = UInt8[
        UInt8((out_len >> 8) & 0xff),
        UInt8(out_len & 0xff),
        UInt8(length(label_bytes)),
    ]
    append!(info, label_bytes)
    push!(info, UInt8(length(context)))
    append!(info, context)
    return _hkdf_expand(hash_kind, secret, info, out_len)
end

function _tls13_derive_secret(hash_kind::_TLSHashKind, secret::AbstractVector{UInt8}, label::AbstractString, transcript)::Vector{UInt8}
    context = _transcript_hash_input(hash_kind, transcript)
    return _tls13_expand_label(hash_kind, secret, label, context, _hash_len(hash_kind))
end

function _tls13_early_secret(hash_kind::_TLSHashKind, psk::AbstractVector{UInt8})
    return _TLS13EarlySecret(hash_kind, _hkdf_extract(hash_kind, psk, nothing))
end

@inline function _tls13_resumption_binder_key(secret::_TLS13EarlySecret)::Vector{UInt8}
    return _tls13_derive_secret(secret.hash_kind, secret.secret, "res binder", nothing)
end

@inline function _tls13_client_early_traffic_secret(secret::_TLS13EarlySecret, transcript)::Vector{UInt8}
    return _tls13_derive_secret(secret.hash_kind, secret.secret, "c e traffic", transcript)
end

function _tls13_handshake_secret(secret::_TLS13EarlySecret, shared_secret::AbstractVector{UInt8})
    derived = _tls13_derive_secret(secret.hash_kind, secret.secret, "derived", nothing)
    try
        return _TLS13HandshakeSecret(secret.hash_kind, _hkdf_extract(secret.hash_kind, shared_secret, derived))
    finally
        _securezero!(derived)
    end
end

@inline function _tls13_client_handshake_traffic_secret(secret::_TLS13HandshakeSecret, transcript)::Vector{UInt8}
    return _tls13_derive_secret(secret.hash_kind, secret.secret, "c hs traffic", transcript)
end

@inline function _tls13_server_handshake_traffic_secret(secret::_TLS13HandshakeSecret, transcript)::Vector{UInt8}
    return _tls13_derive_secret(secret.hash_kind, secret.secret, "s hs traffic", transcript)
end

function _tls13_master_secret(secret::_TLS13HandshakeSecret)
    derived = _tls13_derive_secret(secret.hash_kind, secret.secret, "derived", nothing)
    try
        return _TLS13MasterSecret(secret.hash_kind, _hkdf_extract(secret.hash_kind, nothing, derived))
    finally
        _securezero!(derived)
    end
end

@inline function _tls13_client_application_traffic_secret(secret::_TLS13MasterSecret, transcript)::Vector{UInt8}
    return _tls13_derive_secret(secret.hash_kind, secret.secret, "c ap traffic", transcript)
end

@inline function _tls13_server_application_traffic_secret(secret::_TLS13MasterSecret, transcript)::Vector{UInt8}
    return _tls13_derive_secret(secret.hash_kind, secret.secret, "s ap traffic", transcript)
end

@inline function _tls13_resumption_master_secret(secret::_TLS13MasterSecret, transcript)::Vector{UInt8}
    return _tls13_derive_secret(secret.hash_kind, secret.secret, "res master", transcript)
end

function _tls13_exporter_master_secret(secret::_TLS13MasterSecret, transcript)
    return _TLS13ExporterMasterSecret(secret.hash_kind, _tls13_derive_secret(secret.hash_kind, secret.secret, "exp master", transcript))
end

function _tls13_early_exporter_master_secret(secret::_TLS13EarlySecret, transcript)
    return _TLS13ExporterMasterSecret(secret.hash_kind, _tls13_derive_secret(secret.hash_kind, secret.secret, "e exp master", transcript))
end

@inline function _tls13_exporter_secret_for_test(secret::_TLS13ExporterMasterSecret)::Vector{UInt8}
    return copy(secret.secret)
end

function _tls13_exporter(secret::_TLS13ExporterMasterSecret, label::AbstractString, context::AbstractVector{UInt8}, out_len::Int)::Vector{UInt8}
    out_len >= 0 || throw(ArgumentError("out_len must be >= 0"))
    exporter_secret = _tls13_derive_secret(secret.hash_kind, secret.secret, label, nothing)
    context_hash = _hash_data(secret.hash_kind, context)
    try
        return _tls13_expand_label(secret.hash_kind, exporter_secret, "exporter", context_hash, out_len)
    finally
        _securezero!(exporter_secret)
    end
end

@inline function _tls13_next_traffic_secret(hash_kind::_TLSHashKind, traffic_secret::AbstractVector{UInt8})::Vector{UInt8}
    return _tls13_expand_label(hash_kind, traffic_secret, "traffic upd", UInt8[], _hash_len(hash_kind))
end

@inline function _tls13_next_traffic_secret(spec::_TLS13CipherSpec, traffic_secret::AbstractVector{UInt8})::Vector{UInt8}
    return _tls13_next_traffic_secret(spec.hash_kind, traffic_secret)
end

function _tls13_traffic_key(spec::_TLS13CipherSpec, traffic_secret::AbstractVector{UInt8})
    key = _tls13_expand_label(spec.hash_kind, traffic_secret, "key", UInt8[], spec.key_length)
    iv = _tls13_expand_label(spec.hash_kind, traffic_secret, "iv", UInt8[], spec.iv_length)
    return key, iv
end

function _tls13_finished_verify_data(hash_kind::_TLSHashKind, base_key::AbstractVector{UInt8}, transcript)::Vector{UInt8}
    finished_key = _tls13_expand_label(hash_kind, base_key, "finished", UInt8[], _hash_len(hash_kind))
    try
        return _hmac_data(hash_kind, finished_key, _transcript_hash_input(hash_kind, transcript))
    finally
        _securezero!(finished_key)
    end
end

@inline function _tls13_finished_verify_data(spec::_TLS13CipherSpec, base_key::AbstractVector{UInt8}, transcript)::Vector{UInt8}
    return _tls13_finished_verify_data(spec.hash_kind, base_key, transcript)
end
