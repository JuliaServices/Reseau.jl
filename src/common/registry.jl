mutable struct SmallRegistry{K, V}
    keys::Memory{K}
    values::Memory{V}
    length::Int
end

function SmallRegistry{K, V}() where {K, V}
    return SmallRegistry{K, V}(Memory{K}(undef, 0), Memory{V}(undef, 0), 0)
end

@inline function _registry_find(reg::SmallRegistry{K, V}, key::K) where {K, V}
    for i in 1:reg.length
        if reg.keys[i] == key
            return i
        end
    end
    return 0
end

function _registry_grow!(reg::SmallRegistry{K, V}) where {K, V}
    old_cap = length(reg.keys)
    new_cap = old_cap == 0 ? 4 : old_cap * 2
    new_keys = Memory{K}(undef, new_cap)
    new_vals = Memory{V}(undef, new_cap)
    for i in 1:reg.length
        new_keys[i] = reg.keys[i]
        new_vals[i] = reg.values[i]
    end
    reg.keys = new_keys
    reg.values = new_vals
    return nothing
end

function registry_get(reg::SmallRegistry{K, V}, key::K, default) where {K, V}
    idx = _registry_find(reg, key)
    return idx == 0 ? default : reg.values[idx]
end

function registry_get(reg::SmallRegistry{K, V}, key::K) where {K, V}
    return registry_get(reg, key, nothing)
end

function Base.get(f::Function, reg::SmallRegistry{K, V}, key::K) where {K, V}
    idx = _registry_find(reg, key)
    if idx != 0
        return reg.values[idx]
    end
    value = f()
    registry_set!(reg, key, value)
    return value
end

function registry_get!(reg::SmallRegistry{K, V}, key::K, default::V) where {K, V}
    return get(() -> default, reg, key)
end

function registry_set!(reg::SmallRegistry{K, V}, key::K, value::V) where {K, V}
    idx = _registry_find(reg, key)
    if idx == 0
        if reg.length == length(reg.keys)
            _registry_grow!(reg)
        end
        reg.length += 1
        reg.keys[reg.length] = key
        reg.values[reg.length] = value
    else
        reg.values[idx] = value
    end
    return nothing
end

function registry_delete!(reg::SmallRegistry{K, V}, key::K) where {K, V}
    idx = _registry_find(reg, key)
    idx == 0 && return nothing
    last = reg.length
    if idx != last
        reg.keys[idx] = reg.keys[last]
        reg.values[idx] = reg.values[last]
    end
    reg.length -= 1
    return nothing
end

@inline registry_length(reg::SmallRegistry) = reg.length
@inline registry_isempty(reg::SmallRegistry) = reg.length == 0

function registry_foreach(reg::SmallRegistry{K, V}, f::Function) where {K, V}
    for i in 1:reg.length
        f(reg.values[i])
    end
    return nothing
end

function registry_foreach_pair(reg::SmallRegistry{K, V}, f::Function) where {K, V}
    for i in 1:reg.length
        f(reg.keys[i], reg.values[i])
    end
    return nothing
end

mutable struct SmallList{T}
    data::Memory{T}
    length::Int
end

function SmallList{T}() where {T}
    return SmallList{T}(Memory{T}(undef, 0), 0)
end

function _small_list_grow!(list::SmallList{T}) where {T}
    old_cap = length(list.data)
    new_cap = old_cap == 0 ? 4 : old_cap * 2
    new_data = Memory{T}(undef, new_cap)
    for i in 1:list.length
        new_data[i] = list.data[i]
    end
    list.data = new_data
    return nothing
end

function small_list_push!(list::SmallList{T}, value::T) where {T}
    if list.length == length(list.data)
        _small_list_grow!(list)
    end
    list.length += 1
    list.data[list.length] = value
    return nothing
end

@inline small_list_length(list::SmallList) = list.length
@inline small_list_isempty(list::SmallList) = list.length == 0

@inline function small_list_get(list::SmallList{T}, idx::Int) where {T}
    return list.data[idx]
end

function small_list_clear!(list::SmallList)
    list.length = 0
    return nothing
end
