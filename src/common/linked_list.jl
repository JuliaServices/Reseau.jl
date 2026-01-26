mutable struct Deque{T}
    data::Memory{T}
    head::Int
    tail::Int
    length::Int
end

function Deque{T}(capacity::Integer=0) where {T}
    cap = max(Int(capacity), 0)
    return Deque{T}(Memory{T}(undef, cap), 1, 1, 0)
end

@inline Base.length(list::Deque) = list.length
@inline Base.isempty(list::Deque) = list.length == 0
@inline capacity(list::Deque) = length(list.data)

function _deque_grow!(list::Deque{T}) where {T}
    old_cap = capacity(list)
    new_cap = old_cap == 0 ? 8 : old_cap * 2
    new_data = Memory{T}(undef, new_cap)
    if list.length > 0
        for i in 1:list.length
            idx = list.head + (i - 1)
            if idx > old_cap
                idx -= old_cap
            end
            new_data[i] = list.data[idx]
        end
    end
    list.data = new_data
    list.head = 1
    list.tail = list.length + 1
    return nothing
end

function push_back!(list::Deque{T}, value::T) where {T}
    if list.length == capacity(list)
        _deque_grow!(list)
    end
    if list.length == 0
        list.head = 1
        list.tail = 2
        list.data[1] = value
        list.length = 1
        return nothing
    end
    list.data[list.tail] = value
    list.tail += 1
    if list.tail > capacity(list)
        list.tail = 1
    end
    list.length += 1
    return nothing
end

function push_front!(list::Deque{T}, value::T) where {T}
    if list.length == capacity(list)
        _deque_grow!(list)
    end
    if list.length == 0
        list.head = 1
        list.tail = 2
        list.data[1] = value
        list.length = 1
        return nothing
    end
    list.head -= 1
    if list.head == 0
        list.head = capacity(list)
    end
    list.data[list.head] = value
    list.length += 1
    return nothing
end

function pop_front!(list::Deque)
    list.length == 0 && return nothing
    value = list.data[list.head]
    list.head += 1
    if list.head > capacity(list)
        list.head = 1
    end
    list.length -= 1
    if list.length == 0
        list.head = 1
        list.tail = 1
    end
    return value
end

function pop_back!(list::Deque)
    list.length == 0 && return nothing
    list.tail -= 1
    if list.tail == 0
        list.tail = capacity(list)
    end
    value = list.data[list.tail]
    list.length -= 1
    if list.length == 0
        list.head = 1
        list.tail = 1
    end
    return value
end

function front(list::Deque)
    return list.length == 0 ? nothing : list.data[list.head]
end

function back(list::Deque)
    if list.length == 0
        return nothing
    end
    idx = list.tail - 1
    if idx == 0
        idx = capacity(list)
    end
    return list.data[idx]
end

function clear!(list::Deque)
    list.length = 0
    list.head = 1
    list.tail = 1
    return nothing
end

function Base.iterate(list::Deque{T}, state::Int=1) where {T}
    state > list.length && return nothing
    idx = list.head + (state - 1)
    if idx > capacity(list)
        idx -= capacity(list)
    end
    return list.data[idx], state + 1
end

function remove!(list::Deque{T}, value; eq=isequal) where {T}
    if list.length == 0
        return false
    end
    new_list = Deque{T}(capacity(list))
    removed = false
    for item in list
        if !removed && eq(item, value)
            removed = true
            continue
        end
        push_back!(new_list, item)
    end
    list.data = new_list.data
    list.head = new_list.head
    list.tail = new_list.tail
    list.length = new_list.length
    return removed
end

const linked_list = Deque
linked_list_init(::Type{T}, capacity::Integer=0) where {T} = Deque{T}(capacity)
linked_list_empty(list::Deque) = isempty(list)
linked_list_push_back(list::Deque{T}, value::T) where {T} = push_back!(list, value)
linked_list_push_front(list::Deque{T}, value::T) where {T} = push_front!(list, value)
linked_list_pop_front(list::Deque) = pop_front!(list)
linked_list_pop_back(list::Deque) = pop_back!(list)
linked_list_front(list::Deque) = front(list)
linked_list_back(list::Deque) = back(list)
linked_list_clear(list::Deque) = clear!(list)
