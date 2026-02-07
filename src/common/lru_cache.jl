mutable struct LRUCache{K, V} <: AbstractCache{K, V}
    data::Dict{K, V}
    order::Vector{K}
    max_items::Int
end

function LRUCache{K, V}(max_items::Integer) where {K, V}
    cap = max(Int(max_items), 2)
    table = Dict{K, V}()
    sizehint!(table, cap)
    order = Vector{K}()
    return LRUCache{K, V}(table, order, Int(max_items))
end

function _order_remove!(order::Vector{K}, key::K, eq) where {K}
    for i in 1:length(order)
        if eq(order[i], key)
            deleteat!(order, i)
            return true
        end
    end
    return false
end

function _touch!(cache::LRUCache{K, V}, key::K) where {K, V}
    _order_remove!(cache.order, key, isequal)
    push!(cache.order, key)
    return nothing
end

function Base.get!(cache::LRUCache{K, V}, key::K, default::V) where {K, V}
    haskey(cache.data, key) || return default
    value = cache.data[key]
    _touch!(cache, key)
    return value
end

function Base.put!(cache::LRUCache{K, V}, key::K, value::V) where {K, V}
    _touch!(cache, key)
    cache.data[key] = value
    if length(cache.order) > cache.max_items
        lru = cache.order[1]
        deleteat!(cache.order, 1)
        delete!(cache.data, lru)
    end
    return nothing
end

function remove!(cache::LRUCache{K, V}, key::K) where {K, V}
    delete!(cache.data, key)
    _order_remove!(cache.order, key, isequal)
    return nothing
end

function clear!(cache::LRUCache)
    empty!(cache.data)
    empty!(cache.order)
    return nothing
end

cache_count(cache::LRUCache) = length(cache.data)

function use_lru!(cache::LRUCache{K, V}) where {K, V}
    isempty(cache.order) && return nothing
    key = cache.order[1]
    deleteat!(cache.order, 1)
    push!(cache.order, key)
    return get(cache.data, key, nothing)
end

function mru(cache::LRUCache{K, V}) where {K, V}
    isempty(cache.order) && return nothing
    return get(cache.data, cache.order[end], nothing)
end

function cache_new_lru(max_items::Integer)
    return LRUCache{Any, Any}(max_items)
end
