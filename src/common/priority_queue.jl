mutable struct PriorityQueue{T,Less}
    data::Memory{T}
    length::Int
    less::Less
end

function PriorityQueue{T}(less; capacity::Integer=0) where {T}
    cap = max(Int(capacity), 0)
    return PriorityQueue{T, typeof(less)}(Memory{T}(undef, cap), 0, less)
end

@inline Base.length(queue::PriorityQueue) = queue.length
@inline Base.isempty(queue::PriorityQueue) = queue.length == 0
@inline capacity(queue::PriorityQueue) = length(queue.data)

function _pq_grow!(queue::PriorityQueue{T}, min_capacity::Int) where {T}
    cap = capacity(queue)
    new_cap = cap == 0 ? 8 : cap * 2
    while new_cap < min_capacity
        new_cap *= 2
    end
    new_data = Memory{T}(undef, new_cap)
    for i in 1:queue.length
        new_data[i] = queue.data[i]
    end
    queue.data = new_data
    return nothing
end

function ensure_capacity!(queue::PriorityQueue, min_capacity::Int)
    if min_capacity > capacity(queue)
        _pq_grow!(queue, min_capacity)
    end
    return nothing
end

@inline function _pq_parent(index::Int)
    return index >>> 1
end

@inline function _pq_left(index::Int)
    return index << 1
end

@inline function _pq_right(index::Int)
    return (index << 1) + 1
end

function _pq_swap!(queue::PriorityQueue, a::Int, b::Int)
    queue.data[a], queue.data[b] = queue.data[b], queue.data[a]
    return nothing
end

function _pq_sift_up!(queue::PriorityQueue, index::Int)
    while index > 1
        parent = _pq_parent(index)
        if queue.less(queue.data[index], queue.data[parent])
            _pq_swap!(queue, index, parent)
            index = parent
        else
            break
        end
    end
    return nothing
end

function _pq_sift_down!(queue::PriorityQueue, index::Int)
    while true
        left = _pq_left(index)
        right = _pq_right(index)
        smallest = index

        if left <= queue.length && queue.less(queue.data[left], queue.data[smallest])
            smallest = left
        end
        if right <= queue.length && queue.less(queue.data[right], queue.data[smallest])
            smallest = right
        end
        if smallest == index
            break
        end
        _pq_swap!(queue, index, smallest)
        index = smallest
    end
    return nothing
end

function Base.push!(queue::PriorityQueue{T}, value::T) where {T}
    if queue.length == capacity(queue)
        _pq_grow!(queue, queue.length + 1)
    end
    queue.length += 1
    queue.data[queue.length] = value
    _pq_sift_up!(queue, queue.length)
    return nothing
end

function peek(queue::PriorityQueue)
    return queue.length == 0 ? nothing : queue.data[1]
end

function Base.pop!(queue::PriorityQueue)
    queue.length == 0 && return nothing
    value = queue.data[1]
    if queue.length > 1
        queue.data[1] = queue.data[queue.length]
    end
    queue.length -= 1
    if queue.length > 0
        _pq_sift_down!(queue, 1)
    end
    return value
end

function clear!(queue::PriorityQueue)
    queue.length = 0
    return nothing
end

function remove!(queue::PriorityQueue, value; eq=isequal)
    for i in 1:queue.length
        if eq(queue.data[i], value)
            queue.data[i] = queue.data[queue.length]
            queue.length -= 1
            if i <= queue.length
                _pq_sift_down!(queue, i)
                _pq_sift_up!(queue, i)
            end
            return true
        end
    end
    return false
end

# Convenience names matching prior API shape.
const priority_queue = PriorityQueue
priority_queue_size(queue::PriorityQueue) = length(queue)
priority_queue_capacity(queue::PriorityQueue) = capacity(queue)
priority_queue_clear(queue::PriorityQueue) = clear!(queue)
priority_queue_top(queue::PriorityQueue) = peek(queue)
priority_queue_pop(queue::PriorityQueue) = pop!(queue)
priority_queue_push(queue::PriorityQueue, value) = push!(queue, value)
