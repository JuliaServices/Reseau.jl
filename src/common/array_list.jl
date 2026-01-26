mutable struct ArrayList{T}
    data::Memory{T}
    length::Int
end

const array_list = ArrayList

const _ARRAY_LIST_STATIC_REGISTRY = WeakKeyDict{Any, Bool}()
const _ARRAY_LIST_BACKING_REGISTRY = WeakKeyDict{Any, Any}()

@inline function array_list_is_static(list::ArrayList)
    return get(_ARRAY_LIST_STATIC_REGISTRY, list, false)
end

function _array_list_mark_static!(list::ArrayList, backing)
    _ARRAY_LIST_STATIC_REGISTRY[list] = true
    backing === nothing || (_ARRAY_LIST_BACKING_REGISTRY[list] = backing)
    return nothing
end

function _array_list_mark_dynamic!(list::ArrayList)
    haskey(_ARRAY_LIST_STATIC_REGISTRY, list) && delete!(_ARRAY_LIST_STATIC_REGISTRY, list)
    haskey(_ARRAY_LIST_BACKING_REGISTRY, list) && delete!(_ARRAY_LIST_BACKING_REGISTRY, list)
    return nothing
end

function ArrayList{T}(capacity::Integer=0) where {T}
    cap = max(Int(capacity), 0)
    return ArrayList{T}(Memory{T}(undef, cap), 0)
end

@inline capacity(list::ArrayList) = length(list.data)
@inline Base.length(list::ArrayList) = list.length
@inline Base.isempty(list::ArrayList) = list.length == 0

function _array_list_grow!(list::ArrayList{T}, min_capacity::Int) where {T}
    cap = capacity(list)
    new_cap = cap == 0 ? 4 : cap * 2
    while new_cap < min_capacity
        new_cap *= 2
    end
    new_data = Memory{T}(undef, new_cap)
    for i in 1:list.length
        new_data[i] = list.data[i]
    end
    list.data = new_data
    return nothing
end

function ensure_capacity!(list::ArrayList, min_capacity::Int)
    if min_capacity > capacity(list)
        _array_list_grow!(list, min_capacity)
    end
    return nothing
end

function array_list_ensure_capacity(list::ArrayList, index::Integer)
    idx = Int(index) + 1
    idx < 1 && return raise_error(ERROR_INVALID_INDEX)
    if array_list_is_static(list)
        return idx > capacity(list) ? raise_error(ERROR_INVALID_INDEX) : OP_SUCCESS
    end
    if idx > capacity(list)
        _array_list_grow!(list, idx)
    end
    return OP_SUCCESS
end

function push_back!(list::ArrayList{T}, value::T) where {T}
    if array_list_ensure_capacity(list, list.length) != OP_SUCCESS
        return OP_ERR
    end
    list.length += 1
    list.data[list.length] = value
    return OP_SUCCESS
end

function push_front!(list::ArrayList{T}, value::T) where {T}
    if array_list_ensure_capacity(list, list.length) != OP_SUCCESS
        return OP_ERR
    end
    for i in list.length:-1:1
        list.data[i + 1] = list.data[i]
    end
    list.length += 1
    list.data[1] = value
    return OP_SUCCESS
end

function pop_back!(list::ArrayList)
    list.length == 0 && return nothing
    val = list.data[list.length]
    list.length -= 1
    return val
end

function pop_front!(list::ArrayList)
    list.length == 0 && return nothing
    val = list.data[1]
    for i in 1:(list.length - 1)
        list.data[i] = list.data[i + 1]
    end
    list.length -= 1
    return val
end

function erase!(list::ArrayList, index::Int)
    index < 1 && return nothing
    index > list.length && return nothing
    for i in index:(list.length - 1)
        list.data[i] = list.data[i + 1]
    end
    list.length -= 1
    return nothing
end

function clear!(list::ArrayList)
    list.length = 0
    return nothing
end

function shrink_to_fit!(list::ArrayList{T}) where {T}
    if list.length == capacity(list)
        return nothing
    end
    new_data = Memory{T}(undef, list.length)
    for i in 1:list.length
        new_data[i] = list.data[i]
    end
    list.data = new_data
    return nothing
end

function swap_contents!(a::ArrayList, b::ArrayList)
    a.data, b.data = b.data, a.data
    a.length, b.length = b.length, a.length
    return nothing
end

function copy_list!(dest::ArrayList{T}, src::ArrayList{T}) where {T}
    ensure_capacity!(dest, src.length)
    for i in 1:src.length
        dest.data[i] = src.data[i]
    end
    dest.length = src.length
    return nothing
end

@inline function Base.getindex(list::ArrayList, index::Int)
    return list.data[index]
end

@inline function Base.setindex!(list::ArrayList{T}, value::T, index::Int) where {T}
    list.data[index] = value
    return nothing
end

function _array_list_partition!(list::ArrayList, lo::Int, hi::Int, lt)
    pivot = list.data[hi]
    i = lo - 1
    for j in lo:(hi - 1)
        if lt(list.data[j], pivot)
            i += 1
            list.data[i], list.data[j] = list.data[j], list.data[i]
        end
    end
    list.data[i + 1], list.data[hi] = list.data[hi], list.data[i + 1]
    return i + 1
end

function _array_list_quicksort!(list::ArrayList, lo::Int, hi::Int, lt)
    if lo < hi
        p = _array_list_partition!(list, lo, hi, lt)
        _array_list_quicksort!(list, lo, p - 1, lt)
        _array_list_quicksort!(list, p + 1, hi, lt)
    end
    return nothing
end

function sort!(list::ArrayList, lt)
    if list.length <= 1
        return nothing
    end
    _array_list_quicksort!(list, 1, list.length, lt)
    return nothing
end

# Back-compat style helpers (0-based indices).
function array_list_init_dynamic(::Type{T}, capacity::Integer) where {T}
    list = ArrayList{T}(capacity)
    _array_list_mark_dynamic!(list)
    return list
end

function array_list_init_dynamic!(list::ArrayList{T}, capacity::Integer) where {T}
    list.data = Memory{T}(undef, max(Int(capacity), 0))
    list.length = 0
    _array_list_mark_dynamic!(list)
    return nothing
end

function array_list_init_static!(list::ArrayList{T}, raw_array::AbstractVector{T}, count::Integer) where {T}
    _array_list_mark_dynamic!(list)
    len = min(Int(count), length(raw_array))
    if len <= 0
        list.data = Memory{T}(undef, 0)
        list.length = 0
        _array_list_mark_static!(list, raw_array)
        return nothing
    end
    data = unsafe_wrap(Memory{T}, pointer(raw_array), len; own=false)
    list.data = data
    list.length = 0
    _array_list_mark_static!(list, raw_array)
    return nothing
end

function array_list_init_static_from_initialized!(
    list::ArrayList{T},
    raw_array::AbstractVector{T},
    count::Integer,
) where {T}
    _array_list_mark_dynamic!(list)
    len = min(Int(count), length(raw_array))
    if len <= 0
        list.data = Memory{T}(undef, 0)
        list.length = 0
        _array_list_mark_static!(list, raw_array)
        return nothing
    end
    data = unsafe_wrap(Memory{T}, pointer(raw_array), len; own=false)
    list.data = data
    list.length = len
    _array_list_mark_static!(list, raw_array)
    return nothing
end

@inline array_list_length(list::ArrayList) = list.length
@inline array_list_capacity(list::ArrayList) = capacity(list)
@inline array_list_clear(list::ArrayList) = clear!(list)
@inline array_list_shrink_to_fit(list::ArrayList) = shrink_to_fit!(list)
@inline array_list_swap_contents(a::ArrayList, b::ArrayList) = swap_contents!(a, b)
@inline array_list_copy(src::ArrayList{T}, dest::ArrayList{T}) where {T} = copy_list!(dest, src)

function array_list_push_back(list::ArrayList{T}, value::T) where {T}
    result = push_back!(list, value)
    if result != OP_SUCCESS && array_list_is_static(list) && last_error() == ERROR_INVALID_INDEX
        return raise_error(ERROR_LIST_EXCEEDS_MAX_SIZE)
    end
    return result
end

function array_list_push_back(list::ArrayList, value::Base.RefValue)
    result = push_back!(list, value[])
    if result != OP_SUCCESS && array_list_is_static(list) && last_error() == ERROR_INVALID_INDEX
        return raise_error(ERROR_LIST_EXCEEDS_MAX_SIZE)
    end
    return result
end

function array_list_push_front(list::ArrayList{T}, value::T) where {T}
    result = push_front!(list, value)
    if result != OP_SUCCESS && array_list_is_static(list) && last_error() == ERROR_INVALID_INDEX
        return raise_error(ERROR_LIST_EXCEEDS_MAX_SIZE)
    end
    return result
end

function array_list_push_front(list::ArrayList, value::Base.RefValue)
    result = push_front!(list, value[])
    if result != OP_SUCCESS && array_list_is_static(list) && last_error() == ERROR_INVALID_INDEX
        return raise_error(ERROR_LIST_EXCEEDS_MAX_SIZE)
    end
    return result
end

function array_list_pop_back(list::ArrayList)
    return pop_back!(list)
end

function array_list_pop_front(list::ArrayList)
    return pop_front!(list)
end

function array_list_pop_front_n(list::ArrayList, n::Integer)
    count = min(Int(n), list.length)
    for _ in 1:count
        pop_front!(list)
    end
    return nothing
end

function array_list_get_at(list::ArrayList, index::Integer)
    idx = Int(index) + 1
    idx < 1 && return nothing
    idx > list.length && return nothing
    return list.data[idx]
end

function array_list_get_at(list::ArrayList, dest::Base.RefValue, index::Integer)
    value = array_list_get_at(list, index)
    value === nothing && return nothing
    dest[] = value
    return nothing
end

function array_list_set_at(list::ArrayList{T}, value::T, index::Integer) where {T}
    idx = Int(index)
    idx < 0 && return raise_error(ERROR_INVALID_INDEX)
    if array_list_ensure_capacity(list, idx) != OP_SUCCESS
        return OP_ERR
    end
    list.data[idx + 1] = value
    if idx + 1 > list.length
        list.length = idx + 1
    end
    return OP_SUCCESS
end

function array_list_set_at(list::ArrayList, value::Base.RefValue, index::Integer)
    return array_list_set_at(list, value[], index)
end

function array_list_erase(list::ArrayList, index::Integer)
    idx = Int(index) + 1
    erase!(list, idx)
    return nothing
end

function array_list_back(list::ArrayList)
    return list.length == 0 ? nothing : list.data[list.length]
end

function array_list_back(list::ArrayList, dest::Base.RefValue)
    value = array_list_back(list)
    value === nothing && return nothing
    dest[] = value
    return nothing
end

function array_list_front(list::ArrayList)
    return list.length == 0 ? nothing : list.data[1]
end

function array_list_front(list::ArrayList, dest::Base.RefValue)
    value = array_list_front(list)
    value === nothing && return nothing
    dest[] = value
    return nothing
end

function array_list_sort(list::ArrayList, lt)
    sort!(list, lt)
    return nothing
end
