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
