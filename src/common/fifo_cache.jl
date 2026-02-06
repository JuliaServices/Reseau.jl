mutable struct FIFOCache{K, V} <: AbstractCache{K, V}
    data::HashTable{K, V}
    order::ArrayList{K}
    max_items::Int
end

function FIFOCache{K, V}(max_items::Integer) where {K, V}
    cap = max(Int(max_items), 2)
    table = HashTable{K, V}(hash, isequal; capacity = cap)
    order = ArrayList{K}()
    return FIFOCache{K, V}(table, order, Int(max_items))
end

function get!(cache::FIFOCache{K, V}, key::K, default::V) where {K, V}
    found, value = hash_table_get_entry(cache.data, key)
    return found ? value : default
end

function put!(cache::FIFOCache{K, V}, key::K, value::V) where {K, V}
    found, _ = hash_table_get_entry(cache.data, key)
    found || push_back!(cache.order, key)
    hash_table_put!(cache.data, key, value)
    if cache.order.length > cache.max_items
        oldest = cache.order.data[1]
        erase!(cache.order, 1)
        hash_table_remove!(cache.data, oldest)
    end
    return nothing
end

function remove!(cache::FIFOCache{K, V}, key::K) where {K, V}
    hash_table_remove!(cache.data, key)
    _order_remove!(cache.order, key, cache.data.eq_fn)
    return nothing
end

function clear!(cache::FIFOCache)
    hash_table_clear!(cache.data)
    clear!(cache.order)
    return nothing
end

cache_count(cache::FIFOCache) = hash_table_get_entry_count(cache.data)

function cache_new_fifo(max_items::Integer)
    return FIFOCache{Any, Any}(max_items)
end
