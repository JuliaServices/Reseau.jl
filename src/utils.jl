# Platform helpers
const _PLATFORM_WINDOWS = Sys.iswindows()
const _PLATFORM_APPLE = Sys.isapple()

@static if !(_PLATFORM_WINDOWS || _PLATFORM_APPLE || Sys.islinux())
    error("platform not supported")
end

@static if _PLATFORM_APPLE
    const _CLOCK_REALTIME = Cint(0)
    const _CLOCK_MONOTONIC = Cint(6)
    const _CLOCK_MONOTONIC_RAW = Cint(4)
    const _CLOCK_BOOTTIME = Cint(-1)
elseif Sys.islinux()
    const _CLOCK_REALTIME = Cint(0)
    const _CLOCK_MONOTONIC = Cint(1)
    const _CLOCK_MONOTONIC_RAW = Cint(4)
    const _CLOCK_BOOTTIME = Cint(7)
end

@inline function _fcntl(fd::Cint, cmd::Cint, arg::Cint = Cint(0))::Cint
    @static if _PLATFORM_WINDOWS
        return Cint(-1)
    else
        return @ccall fcntl(fd::Cint, cmd::Cint; arg::Cint)::Cint
    end
end

# Math helpers
const SIZE_MAX = typemax(Csize_t)

function mul_u64_saturating(a::UInt64, b::UInt64)
    r, overflow = Base.mul_with_overflow(a, b)
    return overflow ? typemax(UInt64) : r
end

function mul_u64_checked(a::UInt64, b::UInt64, r::Base.RefValue{UInt64})
    val, overflow = Base.mul_with_overflow(a, b)
    if overflow
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    r[] = val
    return OP_SUCCESS
end

function add_u64_saturating(a::UInt64, b::UInt64)
    r, overflow = Base.add_with_overflow(a, b)
    return overflow ? typemax(UInt64) : r
end

function add_u64_checked(a::UInt64, b::UInt64, r::Base.RefValue{UInt64})
    val, overflow = Base.add_with_overflow(a, b)
    if overflow
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    r[] = val
    return OP_SUCCESS
end

function mul_size_saturating(a::Csize_t, b::Csize_t)
    r, overflow = Base.mul_with_overflow(a, b)
    return overflow ? typemax(Csize_t) : r
end

function add_size_saturating(a::Csize_t, b::Csize_t)
    r, overflow = Base.add_with_overflow(a, b)
    return overflow ? typemax(Csize_t) : r
end

function add_size_checked(a::Csize_t, b::Csize_t, r::Base.RefValue{Csize_t})
    val, overflow = Base.add_with_overflow(a, b)
    if overflow
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    r[] = val
    return OP_SUCCESS
end

function sub_size_saturating(a::Csize_t, b::Csize_t)
    r, overflow = Base.sub_with_overflow(a, b)
    return overflow ? Csize_t(0) : r
end

# LRU cache
mutable struct LRUCache{K, V}
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

cache_count(cache::LRUCache) = length(cache.data)

function use_lru!(cache::LRUCache{K, V}) where {K, V}
    isempty(cache.order) && return nothing
    key = cache.order[1]
    deleteat!(cache.order, 1)
    push!(cache.order, key)
    return get(() -> nothing, cache.data, key)
end

# Priority queue
mutable struct PriorityQueue{T, Less}
    data::Memory{T}
    length::Int
    less::Less
end

function PriorityQueue{T}(less; capacity::Integer = 0) where {T}
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

function remove!(queue::PriorityQueue, value; eq = isequal)
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

# Statistics
const StatisticsCategory = UInt32

const STATISTICS_CATEGORY_STRIDE_BITS = 8
const STATISTICS_CATEGORY_STRIDE = UInt32(1) << STATISTICS_CATEGORY_STRIDE_BITS

STATISTICS_CATEGORY_BEGIN_RANGE(x) = StatisticsCategory(x) * STATISTICS_CATEGORY_STRIDE

struct StatisticsSampleInterval
    begin_time_ms::UInt64
    end_time_ms::UInt64
end

abstract type StatisticsHandler end

process_statistics(::StatisticsHandler, ::StatisticsSampleInterval, ::AbstractVector) = nothing
report_interval_ms(::StatisticsHandler) = UInt64(0)
close!(::StatisticsHandler) = nothing
