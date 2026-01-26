# AWS IO Library - Channel Pipeline
# Port of aws-c-io/source/channel.c and include/aws/io/channel.h

# Channel handler task status
@enumx ChannelTaskStatus::UInt8 begin
    RUN_TASK_SUCCESS = 0
    TASK_CANCEL = 1
end

# Channel read/write directions are defined in socket.jl as ChannelDirection

# Callbacks
const ChannelOnSetupCompletedFn = Function  # (channel, error_code, user_data) -> nothing
const ChannelOnShutdownCompletedFn = Function  # (channel, error_code, user_data) -> nothing

# Channel handler options for shutdown behavior
struct ChannelHandlerShutdownOptions
    free_scarce_resources_immediately::Bool
    shutdown_immediately::Bool
end

ChannelHandlerShutdownOptions() = ChannelHandlerShutdownOptions(false, false)

# Channel slot - links handlers in the pipeline
# Each slot can hold a handler and links to adjacent slots
mutable struct ChannelSlot{H <: Union{AbstractChannelHandler, Nothing}, C <: Union{AbstractChannel, Nothing}}
    adj_left::Union{ChannelSlot, Nothing}   # Toward the application (outgoing data flows left)
    adj_right::Union{ChannelSlot, Nothing}  # Toward the socket/network (incoming data flows right)
    handler::H
    channel::C
    current_window_update_batch_size::Csize_t
    upstream_message_overhead::Csize_t
end

function ChannelSlot()
    return ChannelSlot{Nothing, Nothing}(
        nothing,
        nothing,
        nothing,
        nothing,
        Csize_t(0),
        Csize_t(0),
    )
end

function ChannelSlot(handler::H, channel::C) where {H, C}
    return ChannelSlot{H, C}(
        nothing,
        nothing,
        handler,
        channel,
        Csize_t(0),
        Csize_t(0),
    )
end

# Get the slot immediately to the left (application side)
slot_left(slot::ChannelSlot) = slot.adj_left
# Get the slot immediately to the right (socket side)
slot_right(slot::ChannelSlot) = slot.adj_right

# Channel handler base structure
# Concrete handlers should embed this or use similar structure
mutable struct ChannelHandlerBase{V, Impl}
    vtable::V  # ChannelHandlerVTable implementation
    impl::Impl  # Handler-specific implementation data
    slot::Union{ChannelSlot, Nothing}
    message_overhead::Csize_t
    initial_window_size::Csize_t
end

function ChannelHandlerBase(vtable::V, impl::Impl; initial_window_size::Integer = 0) where {V, Impl}
    return ChannelHandlerBase{V, Impl}(
        vtable,
        impl,
        nothing,
        Csize_t(0),
        Csize_t(initial_window_size),
    )
end

# Channel handler vtable interface - methods that all handlers must implement
# These are dispatched via multiple dispatch on the vtable type

# Process an incoming read message (from socket toward application)
function handler_process_read_message(handler::AbstractChannelHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    error("handler_process_read_message must be implemented for $(typeof(handler))")
end

# Process an outgoing write message (from application toward socket)
function handler_process_write_message(handler::AbstractChannelHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    error("handler_process_write_message must be implemented for $(typeof(handler))")
end

# Increment the read window (flow control) - more data can be read
function handler_increment_read_window(handler::AbstractChannelHandler, slot::ChannelSlot, size::Csize_t)::Union{Nothing, ErrorResult}
    error("handler_increment_read_window must be implemented for $(typeof(handler))")
end

# Initiate graceful shutdown of the handler
function handler_shutdown(handler::AbstractChannelHandler, slot::ChannelSlot, direction::ChannelDirection.T, error_code::Int)::Union{Nothing, ErrorResult}
    error("handler_shutdown must be implemented for $(typeof(handler))")
end

# Get the current window size for the handler
function handler_initial_window_size(handler::AbstractChannelHandler)::Csize_t
    error("handler_initial_window_size must be implemented for $(typeof(handler))")
end

# Get the message overhead size for this handler
function handler_message_overhead(handler::AbstractChannelHandler)::Csize_t
    error("handler_message_overhead must be implemented for $(typeof(handler))")
end

# Called when shutdown completes for cleanup
function handler_destroy(handler::AbstractChannelHandler)::Nothing
    # Default implementation does nothing
    return nothing
end

# Reset handler statistics
function handler_reset_statistics(handler::AbstractChannelHandler)::Nothing
    # Default implementation does nothing
    return nothing
end

# Gather handler statistics
function handler_gather_statistics(handler::AbstractChannelHandler)::Any
    # Default implementation returns nothing
    return nothing
end

# Trigger handler to write its pending data
function handler_trigger_write(handler::AbstractChannelHandler)::Nothing
    # Default implementation does nothing
    return nothing
end

# Channel state tracking
@enumx ChannelState::UInt8 begin
    NOT_INITIALIZED = 0
    SETTING_UP = 1
    ACTIVE = 2
    SHUTTING_DOWN_READ = 3
    SHUTTING_DOWN_WRITE = 4
    SHUT_DOWN = 5
end

# Channel - a bidirectional pipeline of handlers
mutable struct Channel{EL <: AbstractEventLoop, FS <: Union{ChannelOnSetupCompletedFn, Nothing}, FD <: Union{ChannelOnShutdownCompletedFn, Nothing}, US, UD}
    event_loop::EL
    first::Union{ChannelSlot, Nothing}  # nullable - Application side (leftmost)
    last::Union{ChannelSlot, Nothing}   # nullable - Socket side (rightmost)
    channel_state::ChannelState.T
    read_back_pressure_enabled::Bool
    channel_id::UInt64
    window::Csize_t
    message_pool::Union{MessagePool, Nothing}  # nullable
    on_setup_completed::FS  # nullable
    on_shutdown_completed::FD  # nullable
    setup_user_data::US
    shutdown_user_data::UD
    shutdown_error_code::Int
    # Statistics tracking
    read_message_count::Csize_t
    write_message_count::Csize_t
    # Shutdown tracking
    shutdown_direction::Union{ChannelDirection.T, Nothing}  # nullable
    shutdown_is_immediate::Bool
    shutdown_pending::Bool
    # Cross-thread task scheduling
    cross_thread_window_increment_pending::Bool
    cross_thread_window_increment_amount::Csize_t
    cross_thread_tasks::Union{Vector{ChannelTask}, Nothing}  # nullable
end

# Global channel counter for unique IDs
const _channel_id_counter = Ref{UInt64}(0)

function _next_channel_id()::UInt64
    id = _channel_id_counter[]
    _channel_id_counter[] = id + 1
    return id
end

function Channel(
        event_loop::EL,
        message_pool::Union{MessagePool, Nothing} = nothing,
    ) where {EL <: AbstractEventLoop}
    channel_id = _next_channel_id()

    return Channel{EL, Nothing, Nothing, Nothing, Nothing}(
        event_loop,
        nothing,  # first
        nothing,  # last
        ChannelState.NOT_INITIALIZED,
        false,    # read_back_pressure_enabled
        channel_id,
        Csize_t(0),  # window
        message_pool,
        nothing,  # on_setup_completed
        nothing,  # on_shutdown_completed
        nothing,  # setup_user_data
        nothing,  # shutdown_user_data
        0,        # shutdown_error_code
        Csize_t(0),  # read_message_count
        Csize_t(0),  # write_message_count
        nothing,  # shutdown_direction
        false,    # shutdown_is_immediate
        false,    # shutdown_pending
        false,    # cross_thread_window_increment_pending
        Csize_t(0),  # cross_thread_window_increment_amount
        nothing,  # cross_thread_tasks
    )
end

# Get the event loop associated with a channel
channel_event_loop(channel::Channel) = channel.event_loop

# Get unique channel ID
channel_id(channel::Channel) = channel.channel_id

# Get the first slot (application side)
channel_first_slot(channel::Channel) = channel.first

# Get the last slot (socket side)
channel_last_slot(channel::Channel) = channel.last

# Check if channel is active
channel_is_active(channel::Channel) = channel.channel_state == ChannelState.ACTIVE

# Set the channel setup callback
function channel_set_setup_callback!(channel::Channel, callback::ChannelOnSetupCompletedFn, user_data)
    channel.on_setup_completed = callback
    channel.setup_user_data = user_data
    return nothing
end

# Set the channel shutdown callback
function channel_set_shutdown_callback!(channel::Channel, callback::ChannelOnShutdownCompletedFn, user_data)
    channel.on_shutdown_completed = callback
    channel.shutdown_user_data = user_data
    return nothing
end

# Slot operations

# Create and insert a new slot into the channel
function channel_slot_new!(channel::Channel)::ChannelSlot
    slot = ChannelSlot()
    slot.channel = channel
    slot.current_window_update_batch_size = Csize_t(0)
    slot.upstream_message_overhead = Csize_t(0)

    logf(
        LogLevel.TRACE, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): created new slot"
    )

    return slot
end

# Insert slot to the right of another slot
function channel_slot_insert_right!(slot::ChannelSlot, right_of::ChannelSlot)
    channel = right_of.channel

    slot.adj_left = right_of
    slot.adj_right = right_of.adj_right
    slot.channel = channel

    if right_of.adj_right !== nothing
        right_of.adj_right.adj_left = slot
    end

    right_of.adj_right = slot

    # Update last pointer if needed
    if channel !== nothing && channel.last === right_of
        channel.last = slot
    end

    return nothing
end

# Insert slot to the left of another slot
function channel_slot_insert_left!(slot::ChannelSlot, left_of::ChannelSlot)
    channel = left_of.channel

    slot.adj_right = left_of
    slot.adj_left = left_of.adj_left
    slot.channel = channel

    if left_of.adj_left !== nothing
        left_of.adj_left.adj_right = slot
    end

    left_of.adj_left = slot

    # Update first pointer if needed
    if channel !== nothing && channel.first === left_of
        channel.first = slot
    end

    return nothing
end

# Insert slot at the end of the channel (socket side)
function channel_slot_insert_end!(channel::Channel, slot::ChannelSlot)
    slot.channel = channel

    if channel.last === nothing
        channel.first = slot
        channel.last = slot
    else
        channel_slot_insert_right!(slot, channel.last)
    end

    return nothing
end

# Insert slot at the front of the channel (application side)
function channel_slot_insert_front!(channel::Channel, slot::ChannelSlot)
    slot.channel = channel

    if channel.first === nothing
        channel.first = slot
        channel.last = slot
    else
        channel_slot_insert_left!(slot, channel.first)
    end

    return nothing
end

# Remove a slot from the channel
function channel_slot_remove!(slot::ChannelSlot)
    channel = slot.channel

    if channel !== nothing
        if channel.first === slot
            channel.first = slot.adj_right
        end
        if channel.last === slot
            channel.last = slot.adj_left
        end
    end

    if slot.adj_left !== nothing
        slot.adj_left.adj_right = slot.adj_right
    end

    if slot.adj_right !== nothing
        slot.adj_right.adj_left = slot.adj_left
    end

    slot.adj_left = nothing
    slot.adj_right = nothing
    slot.channel = nothing

    return nothing
end

# Set the handler for a slot
function channel_slot_set_handler!(slot::ChannelSlot, handler::AbstractChannelHandler)
    slot.handler = handler
    if handler isa ChannelHandlerBase
        handler.slot = slot
    end
    return nothing
end

# Replace handler in a slot
function channel_slot_replace_handler!(slot::ChannelSlot, new_handler::AbstractChannelHandler)::Union{AbstractChannelHandler, Nothing}
    old_handler = slot.handler
    channel_slot_set_handler!(slot, new_handler)
    return old_handler
end

# Message passing functions

# Send a read message to the next slot (toward application)
function channel_slot_send_message(slot::ChannelSlot, message::IoMessage, direction::ChannelDirection.T)::Union{Nothing, ErrorResult}
    channel = slot.channel

    if channel === nothing
        raise_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
        return ErrorResult(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
    end

    if direction == ChannelDirection.READ
        # Send toward application (left)
        next_slot = slot.adj_left
        if next_slot === nothing || next_slot.handler === nothing
            logf(
                LogLevel.WARN, LS_IO_CHANNEL,
                "Channel id=$(channel.channel_id): no handler to process read message"
            )
            raise_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
            return ErrorResult(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
        end

        message.owning_channel = channel
        channel.read_message_count += 1

        return handler_process_read_message(next_slot.handler, next_slot, message)
    else
        # Send toward socket (right)
        next_slot = slot.adj_right
        if next_slot === nothing || next_slot.handler === nothing
            logf(
                LogLevel.WARN, LS_IO_CHANNEL,
                "Channel id=$(channel.channel_id): no handler to process write message"
            )
            raise_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
            return ErrorResult(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
        end

        message.owning_channel = channel
        channel.write_message_count += 1

        return handler_process_write_message(next_slot.handler, next_slot, message)
    end
end

# Increment read window (flow control propagation)
function channel_slot_increment_read_window!(slot::ChannelSlot, size::Csize_t)::Union{Nothing, ErrorResult}
    channel = slot.channel

    if channel === nothing
        return nothing
    end

    # Propagate to the next slot toward the socket
    next_slot = slot.adj_right
    if next_slot === nothing || next_slot.handler === nothing
        return nothing
    end

    # Batch window updates
    next_slot.current_window_update_batch_size += size

    logf(
        LogLevel.TRACE, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): slot window increment of $size, batch now $(next_slot.current_window_update_batch_size)"
    )

    return handler_increment_read_window(next_slot.handler, next_slot, next_slot.current_window_update_batch_size)
end

# Get the upstream message overhead for a slot
function channel_slot_upstream_message_overhead(slot::ChannelSlot)::Csize_t
    return slot.upstream_message_overhead
end

# Calculate and set upstream message overhead for all slots
function _channel_calculate_message_overheads!(channel::Channel)
    overhead = Csize_t(0)
    slot = channel.first

    while slot !== nothing
        slot.upstream_message_overhead = overhead

        if slot.handler !== nothing
            overhead += handler_message_overhead(slot.handler)
        end

        slot = slot.adj_right
    end

    return nothing
end

# Initialize the channel after all handlers are set up
function channel_setup_complete!(channel::Channel)::Union{Nothing, ErrorResult}
    if channel.channel_state != ChannelState.NOT_INITIALIZED && channel.channel_state != ChannelState.SETTING_UP
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL,
            "Channel id=$(channel.channel_id): setup complete called in invalid state"
        )
        raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
        return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
    end

    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): setup complete"
    )

    # Calculate message overheads
    _channel_calculate_message_overheads!(channel)

    # Initialize window to the first handler's initial window size
    if channel.first !== nothing && channel.first.handler !== nothing
        channel.window = handler_initial_window_size(channel.first.handler)
    end

    channel.channel_state = ChannelState.ACTIVE

    # Invoke setup callback
    if channel.on_setup_completed !== nothing
        Base.invokelatest(channel.on_setup_completed, channel, AWS_OP_SUCCESS, channel.setup_user_data)
    end

    return nothing
end

# Shutdown the channel
function channel_shutdown!(channel::Channel, direction::ChannelDirection.T, error_code::Int = 0)::Union{Nothing, ErrorResult}
    if channel.channel_state == ChannelState.SHUT_DOWN
        logf(
            LogLevel.DEBUG, LS_IO_CHANNEL,
            "Channel id=$(channel.channel_id): already shut down"
        )
        return nothing
    end

    if channel.channel_state == ChannelState.SHUTTING_DOWN_READ || channel.channel_state == ChannelState.SHUTTING_DOWN_WRITE
        logf(
            LogLevel.DEBUG, LS_IO_CHANNEL,
            "Channel id=$(channel.channel_id): already shutting down"
        )
        # Only update if error_code is set
        if error_code != 0 && channel.shutdown_error_code == 0
            channel.shutdown_error_code = error_code
        end
        return nothing
    end

    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): shutting down, direction=$direction, error=$error_code"
    )

    channel.shutdown_error_code = error_code
    channel.shutdown_direction = direction

    if direction == ChannelDirection.READ
        channel.channel_state = ChannelState.SHUTTING_DOWN_READ
        # Shutdown starts at socket side and propagates left
        if channel.last !== nothing && channel.last.handler !== nothing
            handler_shutdown(channel.last.handler, channel.last, direction, error_code)
        end
    else
        channel.channel_state = ChannelState.SHUTTING_DOWN_WRITE
        # Shutdown starts at application side and propagates right
        if channel.first !== nothing && channel.first.handler !== nothing
            handler_shutdown(channel.first.handler, channel.first, direction, error_code)
        end
    end

    return nothing
end

# Called when a slot completes its shutdown in a direction
function channel_slot_on_handler_shutdown_complete!(slot::ChannelSlot, direction::ChannelDirection.T, aborted::Bool, propagate_shutdown::Bool)
    channel = slot.channel

    if channel === nothing
        return nothing
    end

    logf(
        LogLevel.TRACE, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): slot handler shutdown complete, direction=$direction"
    )

    if !propagate_shutdown
        return nothing
    end

    if direction == ChannelDirection.READ
        # Propagate left (toward application)
        next_slot = slot.adj_left
        if next_slot !== nothing && next_slot.handler !== nothing
            handler_shutdown(next_slot.handler, next_slot, direction, channel.shutdown_error_code)
        else
            # Reached end of chain, shutdown complete for read direction
            _channel_on_shutdown_direction_complete!(channel, direction)
        end
    else
        # Propagate right (toward socket)
        next_slot = slot.adj_right
        if next_slot !== nothing && next_slot.handler !== nothing
            handler_shutdown(next_slot.handler, next_slot, direction, channel.shutdown_error_code)
        else
            # Reached end of chain, shutdown complete for write direction
            _channel_on_shutdown_direction_complete!(channel, direction)
        end
    end

    return nothing
end

# Internal - called when shutdown completes in a direction
function _channel_on_shutdown_direction_complete!(channel::Channel, direction::ChannelDirection.T)
    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): shutdown complete for direction $direction"
    )

    if channel.channel_state == ChannelState.SHUTTING_DOWN_READ && direction == ChannelDirection.READ
        # Start shutdown in write direction
        channel_shutdown!(channel, ChannelDirection.WRITE, channel.shutdown_error_code)
    elseif channel.channel_state == ChannelState.SHUTTING_DOWN_WRITE && direction == ChannelDirection.WRITE
        # Both directions complete
        _channel_on_shutdown_complete!(channel)
    end

    return nothing
end

# Internal - called when shutdown completes in both directions
function _channel_on_shutdown_complete!(channel::Channel)
    logf(
        LogLevel.INFO, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): shutdown complete, error=$(channel.shutdown_error_code)"
    )

    channel.channel_state = ChannelState.SHUT_DOWN

    # Destroy all handlers
    slot = channel.first
    while slot !== nothing
        next = slot.adj_right
        if slot.handler !== nothing
            handler_destroy(slot.handler)
            slot.handler = nothing
        end
        slot = next
    end

    # Invoke shutdown callback
    if channel.on_shutdown_completed !== nothing
        Base.invokelatest(channel.on_shutdown_completed, channel, channel.shutdown_error_code, channel.shutdown_user_data)
    end

    return nothing
end

# Acquire a message from the channel's message pool
function channel_acquire_message_from_pool(channel::Channel, message_type::IoMessageType.T, size_hint::Integer)::Union{IoMessage, Nothing}
    if channel.message_pool === nothing
        # No pool, create directly
        return IoMessage(size_hint)
    end

    return message_pool_acquire(channel.message_pool, message_type, size_hint)
end

# Release a message back to the channel's message pool
function channel_release_message_to_pool!(channel::Channel, message::IoMessage)
    if channel.message_pool === nothing
        # No pool, just let GC handle it
        return nothing
    end

    return message_pool_release!(channel.message_pool, message)
end

# Helper struct for simple passthrough handler
struct PassthroughHandlerVTable end

mutable struct PassthroughHandler <: AbstractChannelHandler
    slot::Union{ChannelSlot, Nothing}
    initial_window_size::Csize_t
    message_overhead::Csize_t
end

function PassthroughHandler(;
        initial_window_size::Integer = SIZE_MAX,
        message_overhead::Integer = 0,
    )
    return PassthroughHandler(
        nothing,
        Csize_t(initial_window_size),
        Csize_t(message_overhead),
    )
end

function handler_process_read_message(handler::PassthroughHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    return channel_slot_send_message(slot, message, ChannelDirection.READ)
end

function handler_process_write_message(handler::PassthroughHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    return channel_slot_send_message(slot, message, ChannelDirection.WRITE)
end

function handler_increment_read_window(handler::PassthroughHandler, slot::ChannelSlot, size::Csize_t)::Union{Nothing, ErrorResult}
    return channel_slot_increment_read_window!(slot, size)
end

function handler_shutdown(handler::PassthroughHandler, slot::ChannelSlot, direction::ChannelDirection.T, error_code::Int)::Union{Nothing, ErrorResult}
    channel_slot_on_handler_shutdown_complete!(slot, direction, false, true)
    return nothing
end

function handler_initial_window_size(handler::PassthroughHandler)::Csize_t
    return handler.initial_window_size
end

function handler_message_overhead(handler::PassthroughHandler)::Csize_t
    return handler.message_overhead
end
