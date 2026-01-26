mutable struct LRUCache{K,V,HE} <: AbstractCache{K,V}
    data::HashTable{K,V,HE,NoopDestroy,NoopDestroy}
    order::ArrayList{K}
    max_items::Int
end

function LRUCache{K,V}(max_items::Integer) where {K,V}
    cap = max(Int(max_items), 2)
    table = HashTable{K,V}(hash, isequal; capacity=cap)
    order = ArrayList{K}()
    return LRUCache{K,V,typeof(table.hash_eq)}(table, order, Int(max_items))
end

function _order_remove!(order::ArrayList{K}, key::K, eq) where {K}
    for i in 1:order.length
        if eq(order.data[i], key)
            erase!(order, i)
            return true
        end
    end
    return false
end

function _touch!(cache::LRUCache{K,V}, key::K) where {K,V}
    _order_remove!(cache.order, key, cache.data.hash_eq.eq)
    push_back!(cache.order, key)
    return nothing
end

function get!(cache::LRUCache{K,V}, key::K, default::V) where {K,V}
    found, value = hash_table_get_entry(cache.data, key)
    found || return default
    _touch!(cache, key)
    return value
end

function put!(cache::LRUCache{K,V}, key::K, value::V) where {K,V}
    _touch!(cache, key)
    hash_table_put!(cache.data, key, value)
    if cache.order.length > cache.max_items
        lru = cache.order.data[1]
        erase!(cache.order, 1)
        hash_table_remove!(cache.data, lru)
    end
    return nothing
end

function remove!(cache::LRUCache{K,V}, key::K) where {K,V}
    hash_table_remove!(cache.data, key)
    _order_remove!(cache.order, key, cache.data.hash_eq.eq)
    return nothing
end

function clear!(cache::LRUCache)
    hash_table_clear!(cache.data)
    clear!(cache.order)
    return nothing
end

cache_count(cache::LRUCache) = hash_table_get_entry_count(cache.data)

function use_lru!(cache::LRUCache{K,V}) where {K,V}
    cache.order.length == 0 && return nothing
    key = cache.order.data[1]
    erase!(cache.order, 1)
    push_back!(cache.order, key)
    return hash_table_get(cache.data, key)
end

function mru(cache::LRUCache{K,V}) where {K,V}
    cache.order.length == 0 && return nothing
    return hash_table_get(cache.data, cache.order.data[cache.order.length])
end

function cache_new_lru(max_items::Integer)
    return LRUCache{Any,Any}(max_items)
end
