mutable struct LinkedHashTable{K,V}
    keys::ArrayList{K}
    values::ArrayList{V}
end

function LinkedHashTable{K,V}() where {K,V}
    return LinkedHashTable{K,V}(ArrayList{K}(), ArrayList{V}())
end

const linked_hash_table = LinkedHashTable

function linked_hash_table_init(::Type{K}, ::Type{V}; capacity::Integer=0) where {K,V}
    _ = capacity
    return LinkedHashTable{K,V}()
end

function linked_hash_table_put(table::LinkedHashTable{K,V}, key::K, value::V) where {K,V}
    for i in 1:table.keys.length
        if table.keys.data[i] == key
            table.values.data[i] = value
            return OP_SUCCESS
        end
    end
    push_back!(table.keys, key)
    push_back!(table.values, value)
    return OP_SUCCESS
end

function linked_hash_table_find(table::LinkedHashTable{K,V}, key::K) where {K,V}
    for i in 1:table.keys.length
        if table.keys.data[i] == key
            return table.values.data[i]
        end
    end
    return nothing
end

function linked_hash_table_remove(table::LinkedHashTable{K,V}, key::K) where {K,V}
    for i in 1:table.keys.length
        if table.keys.data[i] == key
            erase!(table.keys, i)
            erase!(table.values, i)
            return OP_SUCCESS
        end
    end
    return raise_error(ERROR_HASHTBL_ITEM_NOT_FOUND)
end

linked_hash_table_clear(table::LinkedHashTable) = (clear!(table.keys); clear!(table.values); nothing)
linked_hash_table_get_element_count(table::LinkedHashTable) = table.keys.length
