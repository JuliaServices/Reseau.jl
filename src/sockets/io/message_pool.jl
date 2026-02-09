# AWS IO Library - Message Pool
# Port of aws-c-io/source/message_pool.c

# Memory pool - stack of fixed-size segments
mutable struct MemoryPool
    stack::Vector{Memory{UInt8}}
    segment_size::Csize_t
    ideal_segment_count::UInt16
end

function MemoryPool(ideal_segment_count::Integer, segment_size::Integer)
    count = UInt16(ideal_segment_count)
    seg_size = Csize_t(segment_size)
    stack = Vector{Memory{UInt8}}()
    sizehint!(stack, Int(count))

    for _ in 1:count
        push!(stack, Memory{UInt8}(undef, Int(seg_size)))
    end

    return MemoryPool(stack, seg_size, count)
end

Base.length(pool::MemoryPool) = length(pool.stack)
Base.isempty(pool::MemoryPool) = isempty(pool.stack)

function memory_pool_clean_up!(pool::MemoryPool)
    empty!(pool.stack)
    return nothing
end

function memory_pool_acquire(pool::MemoryPool)::Memory{UInt8}
    if !isempty(pool.stack)
        return pop!(pool.stack)
    end
    return Memory{UInt8}(undef, Int(pool.segment_size))
end

function memory_pool_release!(pool::MemoryPool, segment::Memory{UInt8})
    if length(pool.stack) >= pool.ideal_segment_count
        return nothing
    end
    push!(pool.stack, segment)
    return nothing
end

# Message pool creation arguments
struct MessagePoolCreationArgs
    application_data_msg_data_size::Csize_t
    application_data_msg_count::UInt8
    small_block_msg_data_size::Csize_t
    small_block_msg_count::UInt8
end

function MessagePoolCreationArgs(;
        application_data_msg_data_size::Integer = 16384,  # 16KB default
        application_data_msg_count::Integer = 4,
        small_block_msg_data_size::Integer = 256,
        small_block_msg_count::Integer = 16,
    )
    return MessagePoolCreationArgs(
        Csize_t(application_data_msg_data_size),
        UInt8(application_data_msg_count),
        Csize_t(small_block_msg_data_size),
        UInt8(small_block_msg_count),
    )
end

# Message pool - manages pools of pre-allocated message buffers
mutable struct MessagePool
    application_data_pool::MemoryPool
    small_block_pool::MemoryPool
    application_data_size::Csize_t
    small_block_size::Csize_t
end

function MessagePool(
        args::MessagePoolCreationArgs = MessagePoolCreationArgs(),
    )::Union{MessagePool, ErrorResult}
    application_data_pool = MemoryPool(args.application_data_msg_count, args.application_data_msg_data_size)
    small_block_pool = MemoryPool(args.small_block_msg_count, args.small_block_msg_data_size)

    pool = MessagePool(
        application_data_pool,
        small_block_pool,
        args.application_data_msg_data_size,
        args.small_block_msg_data_size,
    )

    return pool
end

function message_pool_clean_up!(pool::MessagePool)
    memory_pool_clean_up!(pool.application_data_pool)
    memory_pool_clean_up!(pool.small_block_pool)
    return nothing
end

@inline function _message_pool_view(segment::Memory{UInt8}, capacity::Csize_t)
    cap = Int(capacity)
    if cap <= 0
        return Memory{UInt8}(undef, 0)
    end
    seg_len = length(segment)
    if cap >= seg_len
        return segment
    end
    return unsafe_wrap(Memory{UInt8}, pointer(segment), cap; own = false)
end

# Acquire a message from the pool
function message_pool_acquire(
        pool::MessagePool,
        message_type::IoMessageType.T,
        size_hint::Integer,
    )::Union{IoMessage, Nothing}

    if message_type != IoMessageType.APPLICATION_DATA
        return nothing
    end

    size_hint_val = size_hint < 0 ? 0 : size_hint

    if Csize_t(size_hint_val) > pool.small_block_size
        segment = memory_pool_acquire(pool.application_data_pool)
        max_size = pool.application_data_size
    else
        segment = memory_pool_acquire(pool.small_block_pool)
        max_size = pool.small_block_size
    end

    effective_capacity = Csize_t(size_hint_val) <= max_size ? Csize_t(size_hint_val) : max_size
    view_mem = _message_pool_view(segment, effective_capacity)
    buf = ByteBuffer(view_mem, 0)

    msg = IoMessage(
        buf,
        IoMessageType.APPLICATION_DATA,
        Int32(0),
        Csize_t(0),
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        segment,
    )

    return msg
end

# Release a message back to the pool
function message_pool_release!(pool::MessagePool, message::IoMessage)
    len = message.message_data.len
    if len > 0
        mem = getfield(message.message_data, :mem)
        fill!(view(mem, 1:len), UInt8(0))
    end

    segment = message.pool_segment
    if segment === nothing
        return nothing
    end

    capacity = message.message_data.capacity
    if capacity > pool.small_block_size
        memory_pool_release!(pool.application_data_pool, segment)
    else
        memory_pool_release!(pool.small_block_pool, segment)
    end

    message.pool_segment = nothing
    return nothing
end

# Helper function to resize a ByteBuffer (sets len field)
function Base.resize!(buf::ByteBuffer, new_len::Integer)
    new_len = Csize_t(new_len)
    if new_len > buf.capacity
        error("Cannot resize ByteBuffer beyond capacity")
    end
    setfield!(buf, :len, new_len)
    return buf
end
