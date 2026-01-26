# C memory allocation helpers for ring buffer
@inline function _rb_malloc(size::Integer)
    size <= 0 && return Ptr{UInt8}(0)
    mem = Libc.malloc(size)
    mem == C_NULL && error("malloc failed to allocate memory")
    return Ptr{UInt8}(mem)
end

@inline function _rb_free(ptr::Ptr{UInt8})
    ptr == Ptr{UInt8}(0) && return nothing
    Libc.free(ptr)
    return nothing
end

mutable struct ring_buffer
    allocation::Ptr{UInt8}
    @atomic head::UInt  # Stores pointer value as UInt for atomic access
    @atomic tail::UInt  # Stores pointer value as UInt for atomic access
    allocation_end::Ptr{UInt8}
end

@inline function _ring_buffer_load_head_ptr(ring_buf::ring_buffer)
    return Ptr{UInt8}(@atomic :monotonic ring_buf.head)
end

@inline function _ring_buffer_load_tail_ptr(ring_buf::ring_buffer)
    return Ptr{UInt8}(@atomic :acquire ring_buf.tail)
end

@inline function _ring_buffer_store_head_ptr(ring_buf::ring_buffer, ptr::Ptr{UInt8})
    @atomic :monotonic ring_buf.head = UInt(ptr)
    return nothing
end

@inline function _ring_buffer_store_tail_ptr(ring_buf::ring_buffer, ptr::Ptr{UInt8})
    @atomic :release ring_buf.tail = UInt(ptr)
    return nothing
end

@inline function _ptr_diff(a::Ptr{UInt8}, b::Ptr{UInt8})
    return Csize_t(UInt(a) - UInt(b))
end

@inline function _ptr_in_range(ptr::Ptr{UInt8}, start::Ptr{UInt8}, finish::Ptr{UInt8})
    if ptr == C_NULL || start == C_NULL || finish == C_NULL
        return false
    end
    p = UInt(ptr)
    s = UInt(start)
    e = UInt(finish)
    return p >= s && p <= e
end

function ring_buffer_check_atomic_ptr(ring_buf::ring_buffer, atomic_ptr::Ptr{UInt8})
    return _ptr_in_range(atomic_ptr, ring_buf.allocation, ring_buf.allocation_end)
end

function ring_buffer_is_empty(ring_buf::ring_buffer)
    head = _ring_buffer_load_head_ptr(ring_buf)
    tail = _ring_buffer_load_tail_ptr(ring_buf)
    return head == tail
end

function ring_buffer_is_valid(ring_buf::ring_buffer)
    head = _ring_buffer_load_head_ptr(ring_buf)
    tail = _ring_buffer_load_tail_ptr(ring_buf)
    head_in_range = ring_buffer_check_atomic_ptr(ring_buf, head)
    tail_in_range = ring_buffer_check_atomic_ptr(ring_buf, tail)
    valid_head_tail = (head != ring_buf.allocation) || (tail == ring_buf.allocation)
    return (ring_buf.allocation != C_NULL) && head_in_range && tail_in_range && valid_head_tail
end

function ring_buffer_init(ring_buf::ring_buffer, size::Integer)
    precondition(size > 0)

    allocation = _rb_malloc(size)
    if allocation == Ptr{UInt8}(0)
        return OP_ERR
    end

    ring_buf.allocation = allocation
    @atomic ring_buf.head = UInt(allocation)
    @atomic ring_buf.tail = UInt(allocation)
    ring_buf.allocation_end = allocation + Csize_t(size)
    return OP_SUCCESS
end

function ring_buffer_clean_up(ring_buf::ring_buffer)
    precondition(ring_buffer_is_valid(ring_buf))
    if ring_buf.allocation != Ptr{UInt8}(0)
        _rb_free(ring_buf.allocation)
    end
    ring_buf.allocation = Ptr{UInt8}(0)
    ring_buf.allocation_end = Ptr{UInt8}(0)
    @atomic ring_buf.head = UInt(0)
    @atomic ring_buf.tail = UInt(0)
    return nothing
end

function ring_buffer_acquire(ring_buf::ring_buffer, requested_size::Integer, dest)
    dest_ptr = _buf_ptr(dest)
    precondition(ring_buffer_is_valid(ring_buf))
    precondition(byte_buf_is_valid(dest_ptr))
    if requested_size == 0
        return raise_error(ERROR_INVALID_ARGUMENT)
    end

    tail_cpy = _ring_buffer_load_tail_ptr(ring_buf)
    head_cpy = _ring_buffer_load_head_ptr(ring_buf)

    if head_cpy == tail_cpy
        ring_space = ring_buf.allocation_end == Ptr{UInt8}(0) ? Csize_t(0) : _ptr_diff(ring_buf.allocation_end, ring_buf.allocation)
        if Csize_t(requested_size) > ring_space
            return raise_error(ERROR_OOM)
        end
        _ring_buffer_store_head_ptr(ring_buf, ring_buf.allocation + Csize_t(requested_size))
        _ring_buffer_store_tail_ptr(ring_buf, ring_buf.allocation)
        unsafe_store!(dest_ptr, byte_buf_from_empty_array(ring_buf.allocation, requested_size))
        return OP_SUCCESS
    end

    if tail_cpy > head_cpy
        space = _ptr_diff(tail_cpy, head_cpy) - 1
        if space >= Csize_t(requested_size)
            _ring_buffer_store_head_ptr(ring_buf, head_cpy + Csize_t(requested_size))
            unsafe_store!(dest_ptr, byte_buf_from_empty_array(head_cpy, requested_size))
            return OP_SUCCESS
        end
    elseif tail_cpy < head_cpy
        head_space = _ptr_diff(ring_buf.allocation_end, head_cpy)
        if head_space >= Csize_t(requested_size)
            _ring_buffer_store_head_ptr(ring_buf, head_cpy + Csize_t(requested_size))
            unsafe_store!(dest_ptr, byte_buf_from_empty_array(head_cpy, requested_size))
            return OP_SUCCESS
        end
        tail_space = _ptr_diff(tail_cpy, ring_buf.allocation)
        if tail_space > Csize_t(requested_size)
            _ring_buffer_store_head_ptr(ring_buf, ring_buf.allocation + Csize_t(requested_size))
            unsafe_store!(dest_ptr, byte_buf_from_empty_array(ring_buf.allocation, requested_size))
            return OP_SUCCESS
        end
    end

    return raise_error(ERROR_OOM)
end

function ring_buffer_acquire_up_to(
    ring_buf::ring_buffer,
    minimum_size::Integer,
    requested_size::Integer,
    dest,
)
    dest_ptr = _buf_ptr(dest)
    precondition(requested_size >= minimum_size)
    precondition(ring_buffer_is_valid(ring_buf))
    precondition(byte_buf_is_valid(dest_ptr))

    if requested_size == 0 || minimum_size == 0 || dest_ptr == C_NULL
        return raise_error(ERROR_INVALID_ARGUMENT)
    end

    tail_cpy = _ring_buffer_load_tail_ptr(ring_buf)
    head_cpy = _ring_buffer_load_head_ptr(ring_buf)

    if head_cpy == tail_cpy
        ring_space = ring_buf.allocation_end == Ptr{UInt8}(0) ? Csize_t(0) : _ptr_diff(ring_buf.allocation_end, ring_buf.allocation)
        allocation_size = ring_space > Csize_t(requested_size) ? Csize_t(requested_size) : ring_space
        if allocation_size < Csize_t(minimum_size)
            return raise_error(ERROR_OOM)
        end
        _ring_buffer_store_head_ptr(ring_buf, ring_buf.allocation + allocation_size)
        _ring_buffer_store_tail_ptr(ring_buf, ring_buf.allocation)
        unsafe_store!(dest_ptr, byte_buf_from_empty_array(ring_buf.allocation, allocation_size))
        return OP_SUCCESS
    end

    if tail_cpy > head_cpy
        space = _ptr_diff(tail_cpy, head_cpy)
        debug_assert(space != 0)
        space -= 1
        returnable_size = space > Csize_t(requested_size) ? Csize_t(requested_size) : space
        if returnable_size >= Csize_t(minimum_size)
            _ring_buffer_store_head_ptr(ring_buf, head_cpy + returnable_size)
            unsafe_store!(dest_ptr, byte_buf_from_empty_array(head_cpy, returnable_size))
            return OP_SUCCESS
        end
    elseif tail_cpy < head_cpy
        head_space = _ptr_diff(ring_buf.allocation_end, head_cpy)
        tail_space = _ptr_diff(tail_cpy, ring_buf.allocation)

        if head_space >= Csize_t(requested_size)
            _ring_buffer_store_head_ptr(ring_buf, head_cpy + Csize_t(requested_size))
            unsafe_store!(dest_ptr, byte_buf_from_empty_array(head_cpy, requested_size))
            return OP_SUCCESS
        end

        if tail_space > Csize_t(requested_size)
            _ring_buffer_store_head_ptr(ring_buf, ring_buf.allocation + Csize_t(requested_size))
            unsafe_store!(dest_ptr, byte_buf_from_empty_array(ring_buf.allocation, requested_size))
            return OP_SUCCESS
        end

        if head_space >= Csize_t(minimum_size) && head_space >= tail_space
            _ring_buffer_store_head_ptr(ring_buf, head_cpy + head_space)
            unsafe_store!(dest_ptr, byte_buf_from_empty_array(head_cpy, head_space))
            return OP_SUCCESS
        end

        if tail_space > Csize_t(minimum_size)
            _ring_buffer_store_head_ptr(ring_buf, ring_buf.allocation + tail_space - 1)
            unsafe_store!(dest_ptr, byte_buf_from_empty_array(ring_buf.allocation, tail_space - 1))
            return OP_SUCCESS
        end
    end

    return raise_error(ERROR_OOM)
end

@inline function _ring_buffer_buf_belongs_to_pool(ring_buf::ring_buffer, buf::Ptr{ByteBuffer})
    if buf == C_NULL
        return false
    end
    buf_val = unsafe_load(buf)
    if buf_val.buffer == Ptr{UInt8}(0) || ring_buf.allocation == Ptr{UInt8}(0) || ring_buf.allocation_end == Ptr{UInt8}(0)
        return false
    end
    start = UInt(ring_buf.allocation)
    finish = UInt(ring_buf.allocation_end)
    buf_start = UInt(buf_val.buffer)
    buf_end = buf_start + UInt(buf_val.capacity)
    return buf_start >= start && buf_end <= finish
end

function ring_buffer_release(ring_buf::ring_buffer, buf)
    buf_ptr = _buf_ptr(buf)
    precondition(ring_buffer_is_valid(ring_buf))
    precondition(byte_buf_is_valid(buf_ptr))
    precondition(_ring_buffer_buf_belongs_to_pool(ring_buf, buf_ptr))
    buf_val = unsafe_load(buf_ptr)
    _ring_buffer_store_tail_ptr(ring_buf, buf_val.buffer + buf_val.capacity)
    zero_struct!(buf_ptr)
    return nothing
end

function ring_buffer_buf_belongs_to_pool(ring_buf::ring_buffer, buf)
    buf_ptr = _buf_ptr(buf)
    precondition(ring_buffer_is_valid(ring_buf))
    precondition(byte_buf_is_valid(buf_ptr))
    return _ring_buffer_buf_belongs_to_pool(ring_buf, buf_ptr)
end
