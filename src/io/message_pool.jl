# AWS IO Library - Message Pool
# Port of aws-c-io/source/message_pool.c

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

# Message pool - manages pools of pre-allocated IoMessages
# Uses ArrayList as stack-based storage for object pooling
mutable struct MessagePool
    application_data_pool::ArrayList{IoMessage}  # Pool of large messages
    small_block_pool::ArrayList{IoMessage}       # Pool of small messages
    application_data_size::Csize_t
    small_block_size::Csize_t
    ideal_app_data_count::UInt8
    ideal_small_block_count::UInt8
end

function MessagePool(
        args::MessagePoolCreationArgs = MessagePoolCreationArgs(),
    )::Union{MessagePool, ErrorResult}
    pool = MessagePool(
        ArrayList{IoMessage}(Int(args.application_data_msg_count)),
        ArrayList{IoMessage}(Int(args.small_block_msg_count)),
        args.application_data_msg_data_size,
        args.small_block_msg_data_size,
        args.application_data_msg_count,
        args.small_block_msg_count,
    )

    # Pre-allocate large messages
    for i in 1:args.application_data_msg_count
        msg = IoMessage(args.application_data_msg_data_size)
        push_back!(pool.application_data_pool, msg)
    end

    # Pre-allocate small messages
    for i in 1:args.small_block_msg_count
        msg = IoMessage(args.small_block_msg_data_size)
        push_back!(pool.small_block_pool, msg)
    end

    return pool
end

function message_pool_clean_up!(pool::MessagePool)
    clear!(pool.application_data_pool)
    clear!(pool.small_block_pool)
    return nothing
end

# Acquire a message from the pool
function message_pool_acquire(
        pool::MessagePool,
        message_type::IoMessageType.T,
        size_hint::Integer,
    )::Union{IoMessage, Nothing}

    msg::Union{IoMessage, Nothing} = nothing
    max_size::Csize_t = 0

    if message_type == IoMessageType.APPLICATION_DATA
        # Try small pool first if size_hint fits
        if Csize_t(size_hint) <= pool.small_block_size
            if !isempty(pool.small_block_pool)
                msg = pop_back!(pool.small_block_pool)
                max_size = pool.small_block_size
            end
        end

        # Fall back to large pool
        if msg === nothing && !isempty(pool.application_data_pool)
            msg = pop_back!(pool.application_data_pool)
            max_size = pool.application_data_size
        end

        # If still nothing, try small pool again for any size
        if msg === nothing && !isempty(pool.small_block_pool)
            msg = pop_back!(pool.small_block_pool)
            max_size = pool.small_block_size
        end

        # Last resort: allocate new
        if msg === nothing
            actual_size = max(Csize_t(size_hint), pool.application_data_size)
            msg = IoMessage(actual_size)
            max_size = actual_size
        end
    else
        # Unknown message type
        return nothing
    end

    if msg === nothing
        return nothing
    end

    # Reset message state
    msg.message_type = message_type
    msg.message_tag = Int32(0)
    msg.user_data = nothing
    msg.copy_mark = Csize_t(0)
    msg.on_completion = nothing
    msg.owning_channel = nothing
    msg.queueing_handle_next = nothing
    msg.queueing_handle_prev = nothing

    # Reset buffer length to 0, capacity based on the actual capacity
    actual_capacity = msg.message_data.capacity
    resize!(msg.message_data, 0)  # Reset length

    return msg
end

# Release a message back to the pool
function message_pool_release!(pool::MessagePool, message::IoMessage)
    # Clear the buffer data for security
    len = message.message_data.len
    if len > 0
        mem = getfield(message.message_data, :mem)
        fill!(view(mem, 1:len), UInt8(0))
    end

    capacity = message.message_data.capacity

    # Return to appropriate pool based on capacity
    if capacity <= pool.small_block_size
        if length(pool.small_block_pool) < pool.ideal_small_block_count
            push_back!(pool.small_block_pool, message)
            return nothing
        end
    else
        if length(pool.application_data_pool) < pool.ideal_app_data_count
            push_back!(pool.application_data_pool, message)
            return nothing
        end
    end

    # Pool is full, let GC handle it
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
