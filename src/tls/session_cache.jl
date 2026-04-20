"""
    _TLSSessionCache{V}

Small lock-protected LRU-style cache used by native TLS session resumption.

Values are always copied on get/peek/put so cached sessions remain owned by the
cache and callers can securely zero or mutate their working copies without
aliasing shared cache state.
"""
mutable struct _TLSSessionCache{V}
    lock::ReentrantLock
    entries::Dict{String, V}
    order::Vector{String}
    capacity::Int
end

const _TLS_SESSION_TICKET_KEY_NAME_LEN = 16
const _TLS_SESSION_TICKET_KEY_SECRET_LEN = 32
const _TLS_SESSION_TICKET_NONCE_LEN = 12
const _TLS_SESSION_TICKET_KEY_ROTATION_NS = Int64(24 * 60 * 60 * 1_000_000_000)
const _TLS_SESSION_TICKET_KEY_LIFETIME_NS = Int64(7 * 24 * 60 * 60 * 1_000_000_000)

mutable struct _TLSSessionTicketKey
    name::Vector{UInt8}
    secret::Vector{UInt8}
    created_at_ns::Int64
end

function _TLSSessionTicketKey(name::AbstractVector{UInt8}, secret::AbstractVector{UInt8}, created_at_ns::Int64)
    length(name) == _TLS_SESSION_TICKET_KEY_NAME_LEN ||
        throw(ArgumentError("tls session ticket key name must be $(_TLS_SESSION_TICKET_KEY_NAME_LEN) bytes"))
    length(secret) == _TLS_SESSION_TICKET_KEY_SECRET_LEN ||
        throw(ArgumentError("tls session ticket key secret must be $(_TLS_SESSION_TICKET_KEY_SECRET_LEN) bytes"))
    return _TLSSessionTicketKey(Vector{UInt8}(name), Vector{UInt8}(secret), created_at_ns)
end

mutable struct _TLSSessionTicketKeyState
    lock::ReentrantLock
    keys::Vector{_TLSSessionTicketKey}
end

_TLSSessionTicketKeyState() = _TLSSessionTicketKeyState(ReentrantLock(), _TLSSessionTicketKey[])

@inline function _securezero_tls_session_ticket_key!(key::_TLSSessionTicketKey)::Nothing
    _securezero!(key.name)
    _securezero!(key.secret)
    key.created_at_ns = Int64(0)
    return nothing
end

function _tls_generate_session_ticket_key(now_ns::Integer)::_TLSSessionTicketKey
    rng = Random.RandomDevice()
    return _TLSSessionTicketKey(
        rand(rng, UInt8, _TLS_SESSION_TICKET_KEY_NAME_LEN),
        rand(rng, UInt8, _TLS_SESSION_TICKET_KEY_SECRET_LEN),
        Int64(now_ns),
    )
end

function _tls_active_session_ticket_keys(config)::Vector{_TLSSessionTicketKey}
    state = config._session_ticket_keys::_TLSSessionTicketKeyState
    now_ns = Int64(time_ns())
    lock(state.lock)
    try
        if isempty(state.keys) || now_ns - state.keys[1].created_at_ns >= _TLS_SESSION_TICKET_KEY_ROTATION_NS
            pushfirst!(state.keys, _tls_generate_session_ticket_key(now_ns))
        end
        keep = _TLSSessionTicketKey[]
        for key in state.keys
            if now_ns - key.created_at_ns <= _TLS_SESSION_TICKET_KEY_LIFETIME_NS
                push!(keep, key)
            else
                _securezero_tls_session_ticket_key!(key)
            end
        end
        state.keys = keep
        isempty(state.keys) && push!(state.keys, _tls_generate_session_ticket_key(now_ns))
        return [_TLSSessionTicketKey(copy(key.name), copy(key.secret), key.created_at_ns) for key in state.keys]
    finally
        unlock(state.lock)
    end
end

function _securezero_tls_session_ticket_keys!(keys::Vector{_TLSSessionTicketKey})::Nothing
    for key in keys
        _securezero_tls_session_ticket_key!(key)
    end
    empty!(keys)
    return nothing
end

@inline function _tls_ticket_append_u64!(buf::Vector{UInt8}, v::UInt64)::Nothing
    _append_u32!(buf, UInt32(v >> 32))
    _append_u32!(buf, UInt32(v & 0xffffffff))
    return nothing
end

@inline function _tls_ticket_read_u64!(reader)::Union{UInt64, Nothing}
    hi = _read_u32!(reader)
    hi === nothing && return nothing
    lo = _read_u32!(reader)
    lo === nothing && return nothing
    return (UInt64(hi::UInt32) << 32) | UInt64(lo::UInt32)
end

@inline function _tls_ticket_append_u16_length_prefixed_bytes!(buf::Vector{UInt8}, bytes::AbstractVector{UInt8})::Nothing
    length(bytes) <= 0xffff || throw(ArgumentError("tls session ticket field exceeds 65535 bytes"))
    _append_u16!(buf, UInt16(length(bytes)))
    append!(buf, bytes)
    return nothing
end

@inline function _tls_ticket_append_u32_length_prefixed_bytes!(buf::Vector{UInt8}, bytes::AbstractVector{UInt8})::Nothing
    length(bytes) <= typemax(UInt32) || throw(ArgumentError("tls session ticket field exceeds UInt32 length"))
    _append_u32!(buf, UInt32(length(bytes)))
    append!(buf, bytes)
    return nothing
end

@inline function _tls_ticket_read_u32_length_prefixed_bytes!(reader)::Union{Vector{UInt8}, Nothing}
    n = _read_u32!(reader)
    n === nothing && return nothing
    n > typemax(Int) && return nothing
    return _read_bytes!(reader, Int(n::UInt32))
end

function _tls_encrypt_session_ticket(secret::AbstractVector{UInt8}, plaintext::AbstractVector{UInt8})::Vector{UInt8}
    nonce = rand(Random.RandomDevice(), UInt8, _TLS_SESSION_TICKET_NONCE_LEN)
    ciphertext = UInt8[]
    try
        ciphertext = _tls13_encrypt_record_aead(_TLS13_AES_256_GCM_SHA384, secret, nonce, UInt8[], plaintext)
        out = Vector{UInt8}(undef, length(nonce) + length(ciphertext))
        copyto!(out, 1, nonce, 1, length(nonce))
        copyto!(out, length(nonce) + 1, ciphertext, 1, length(ciphertext))
        return out
    finally
        _securezero!(nonce)
        _securezero!(ciphertext)
    end
end

function _tls_decrypt_session_ticket(secret::AbstractVector{UInt8}, encrypted::AbstractVector{UInt8})::Union{Nothing, Vector{UInt8}}
    length(encrypted) >= _TLS_SESSION_TICKET_NONCE_LEN + 16 || return nothing
    return _tls13_decrypt_record_aead(
        _TLS13_AES_256_GCM_SHA384,
        secret,
        @view(encrypted[1:_TLS_SESSION_TICKET_NONCE_LEN]),
        UInt8[],
        @view(encrypted[(_TLS_SESSION_TICKET_NONCE_LEN + 1):lastindex(encrypted)]),
    )
end

function _tls_encrypt_server_session_ticket(key::_TLSSessionTicketKey, plaintext::AbstractVector{UInt8})::Vector{UInt8}
    encrypted = UInt8[]
    try
        encrypted = _tls_encrypt_session_ticket(key.secret, plaintext)
        out = Vector{UInt8}(undef, _TLS_SESSION_TICKET_KEY_NAME_LEN + length(encrypted))
        copyto!(out, 1, key.name, 1, _TLS_SESSION_TICKET_KEY_NAME_LEN)
        copyto!(out, _TLS_SESSION_TICKET_KEY_NAME_LEN + 1, encrypted, 1, length(encrypted))
        return out
    finally
        _securezero!(encrypted)
    end
end

function _tls_decrypt_server_session_ticket(
    keys::Vector{_TLSSessionTicketKey},
    ticket::AbstractVector{UInt8},
)::Union{Nothing, Vector{UInt8}}
    length(ticket) > _TLS_SESSION_TICKET_KEY_NAME_LEN || return nothing
    key_name = @view(ticket[1:_TLS_SESSION_TICKET_KEY_NAME_LEN])
    encrypted = @view(ticket[(_TLS_SESSION_TICKET_KEY_NAME_LEN + 1):lastindex(ticket)])
    for key in keys
        key.name == key_name || continue
        return _tls_decrypt_session_ticket(key.secret, encrypted)
    end
    return nothing
end

function _TLSSessionCache(::Type{V}, capacity::Integer = 64)::_TLSSessionCache{V} where {V}
    Int(capacity) > 0 || throw(ArgumentError("tls session cache capacity must be positive"))
    return _TLSSessionCache{V}(ReentrantLock(), Dict{String, V}(), String[], Int(capacity))
end

# Cache order is maintained explicitly instead of through a heavier container so
# the TLS paths can keep the implementation trim-safe and easy to zero/inspect.
@inline function _tls_session_cache_touch_locked!(cache::_TLSSessionCache, key::String)::Nothing
    deleteat!(cache.order, findall(==(key), cache.order))
    pushfirst!(cache.order, key)
    return nothing
end

function _tls_session_cache_get(cache::_TLSSessionCache{V}, key::AbstractString, copy_value::F)::Union{Nothing, V} where {V, F}
    key_s = String(key)
    lock(cache.lock)
    try
        value = get(cache.entries, key_s, nothing)
        value === nothing && return nothing
        _tls_session_cache_touch_locked!(cache, key_s)
        return copy_value(value::V)
    finally
        unlock(cache.lock)
    end
end

function _tls_session_cache_peek(cache::_TLSSessionCache{V}, key::AbstractString, copy_value::F)::Union{Nothing, V} where {V, F}
    key_s = String(key)
    lock(cache.lock)
    try
        value = get(cache.entries, key_s, nothing)
        value === nothing && return nothing
        return copy_value(value::V)
    finally
        unlock(cache.lock)
    end
end

function _tls_session_cache_delete!(cache::_TLSSessionCache{V}, key::AbstractString, destroy_value!::F)::Nothing where {V, F}
    key_s = String(key)
    lock(cache.lock)
    try
        value = pop!(cache.entries, key_s, nothing)
        value === nothing && return nothing
        deleteat!(cache.order, findall(==(key_s), cache.order))
        destroy_value!(value::V)
    finally
        unlock(cache.lock)
    end
    return nothing
end

function _tls_session_cache_put!(
    cache::_TLSSessionCache{V},
    key::AbstractString,
    value::Union{Nothing, V},
    copy_value::FC,
    destroy_value!::FD,
)::Nothing where {V, FC, FD}
    key_s = String(key)
    lock(cache.lock)
    try
        if haskey(cache.entries, key_s)
            existing = pop!(cache.entries, key_s)
            destroy_value!(existing::V)
            deleteat!(cache.order, findall(==(key_s), cache.order))
        end
        value === nothing && return nothing
        cache.entries[key_s] = copy_value(value::V)
        pushfirst!(cache.order, key_s)
        while length(cache.order) > cache.capacity
            evict_key = pop!(cache.order)
            evicted = pop!(cache.entries, evict_key)
            destroy_value!(evicted::V)
        end
    finally
        unlock(cache.lock)
    end
    return nothing
end
