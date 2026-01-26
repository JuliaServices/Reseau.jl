# AWS IO Library - Socket Channel Handler
# Port of aws-c-io/source/socket_channel_handler.c

# Socket channel handler - bridges socket IO to channel pipeline
# This handler is typically the rightmost handler in a channel (socket side)
# It reads from the socket and pushes messages into the channel (read direction)
# It receives write messages and sends them out the socket (write direction)

# Socket handler statistics
mutable struct SocketHandlerStatistics
    bytes_read::Csize_t
    bytes_written::Csize_t
    read_calls::Csize_t
    write_calls::Csize_t
end

SocketHandlerStatistics() = SocketHandlerStatistics(Csize_t(0), Csize_t(0), Csize_t(0), Csize_t(0))

# Socket handler shutdown state
@enumx SocketHandlerShutdownState::UInt8 begin
    NONE = 0
    SHUTTING_DOWN_READ = 1
    SHUT_DOWN_READ = 2
    SHUTTING_DOWN_WRITE = 3
    SHUT_DOWN_WRITE = 4
    COMPLETE = 5
end

# Socket channel handler structure
mutable struct SocketChannelHandler{S, SlotRef <: Union{ChannelSlot, Nothing}} <: AbstractChannelHandler
    socket::S
    slot::SlotRef
    initial_window_size::Csize_t
    max_read_size::Csize_t
    read_window::Csize_t
    stats::SocketHandlerStatistics
    shutdown_state::SocketHandlerShutdownState.T
    shutdown_in_read_direction::Bool
    shutdown_immediately::Bool
    shutdown_error_code::Int
    # Backpressure tracking
    read_paused::Bool
    reads_in_progress::Int
end

function SocketChannelHandler(
        socket::S;
        initial_window_size::Integer = SIZE_MAX,
        max_read_size::Integer = 16384,  # 16KB default
    ) where {S}
    return SocketChannelHandler{S, Union{ChannelSlot, Nothing}}(
        socket,
        nothing,
        Csize_t(initial_window_size),
        Csize_t(max_read_size),
        Csize_t(initial_window_size),
        SocketHandlerStatistics(),
        SocketHandlerShutdownState.NONE,
        false,
        false,
        0,
        false,
        0,
    )
end

# Handler interface implementations

function handler_initial_window_size(handler::SocketChannelHandler)::Csize_t
    return handler.initial_window_size
end

function handler_message_overhead(handler::SocketChannelHandler)::Csize_t
    return Csize_t(0)  # Socket handler adds no overhead
end

function handler_destroy(handler::SocketChannelHandler)::Nothing
    logf(LogLevel.TRACE, LS_IO_SOCKET_HANDLER, "Socket handler: destroying")
    # Socket cleanup handled separately
    return nothing
end

function handler_reset_statistics(handler::SocketChannelHandler)::Nothing
    handler.stats = SocketHandlerStatistics()
    return nothing
end

function handler_gather_statistics(handler::SocketChannelHandler)::SocketHandlerStatistics
    return handler.stats
end

# Process read message - socket handler is at the socket end, shouldn't receive read messages
function handler_process_read_message(handler::SocketChannelHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    # Socket handler doesn't process read messages - it generates them
    logf(LogLevel.ERROR, LS_IO_SOCKET_HANDLER, "Socket handler: unexpected read message received")
    raise_error(ERROR_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE)
    return ErrorResult(ERROR_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE)
end

# Process write message - send data out the socket
function handler_process_write_message(handler::SocketChannelHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    socket = handler.socket
    channel = slot.channel

    if handler.shutdown_state >= SocketHandlerShutdownState.SHUTTING_DOWN_WRITE
        logf(
            LogLevel.DEBUG, LS_IO_SOCKET_HANDLER,
            "Socket handler: write message received during shutdown"
        )
        # Release message back to pool
        if channel !== nothing
            channel_release_message_to_pool!(channel, message)
        end
        return nothing
    end

    # Get data from message
    buf = message.message_data
    if buf.len == 0
        # Empty message, release and return
        if channel !== nothing
            channel_release_message_to_pool!(channel, message)
        end
        return nothing
    end

    logf(
        LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
        "Socket handler: writing $(buf.len) bytes to socket"
    )

    # Create byte cursor from message data
    cursor = byte_cursor_from_buf(buf)

    # Write to socket
    write_result = socket_write(socket, cursor, _on_socket_write_complete, (handler, message))

    if write_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_SOCKET_HANDLER,
            "Socket handler: failed to write to socket, error=$(write_result.code)"
        )
        if channel !== nothing
            channel_release_message_to_pool!(channel, message)
        end
        return write_result
    end

    handler.stats.write_calls += 1

    return nothing
end

# Socket write completion callback
function _on_socket_write_complete(socket, error_code::Int, bytes_written::Csize_t, user_data)
    handler, message = user_data
    channel = handler.slot !== nothing ? handler.slot.channel : nothing

    if error_code != AWS_OP_SUCCESS
        logf(
            LogLevel.DEBUG, LS_IO_SOCKET_HANDLER,
            "Socket handler: socket write completed with error $error_code, wrote $bytes_written bytes"
        )
    else
        logf(
            LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
            "Socket handler: socket write completed, wrote $bytes_written bytes"
        )
        handler.stats.bytes_written += bytes_written
    end

    # Release the message back to pool
    if channel !== nothing
        channel_release_message_to_pool!(channel, message)
    end

    # If error, trigger shutdown
    if error_code != AWS_OP_SUCCESS && handler.shutdown_state == SocketHandlerShutdownState.NONE
        if handler.slot !== nothing
            channel_shutdown!(handler.slot.channel, ChannelDirection.WRITE, error_code)
        end
    end

    return nothing
end

# Increment read window - handler can now read more data
function handler_increment_read_window(handler::SocketChannelHandler, slot::ChannelSlot, size::Csize_t)::Union{Nothing, ErrorResult}
    handler.read_window += size

    logf(
        LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
        "Socket handler: read window incremented by $size, now $(handler.read_window)"
    )

    # If reads were paused due to backpressure, resume
    if handler.read_paused && handler.read_window > 0
        _socket_handler_trigger_read(handler)
    end

    return nothing
end

# Shutdown handler
function handler_shutdown(handler::SocketChannelHandler, slot::ChannelSlot, direction::ChannelDirection.T, error_code::Int)::Union{Nothing, ErrorResult}
    socket = handler.socket

    logf(
        LogLevel.DEBUG, LS_IO_SOCKET_HANDLER,
        "Socket handler: shutdown requested, direction=$direction, error=$error_code"
    )

    handler.shutdown_error_code = error_code

    if direction == ChannelDirection.READ
        if handler.shutdown_state >= SocketHandlerShutdownState.SHUTTING_DOWN_READ
            return nothing  # Already shutting down
        end

        handler.shutdown_state = SocketHandlerShutdownState.SHUTTING_DOWN_READ
        handler.shutdown_in_read_direction = true

        # Shutdown socket read direction
        socket_shutdown_dir(socket, ChannelDirection.READ)

        # Complete read shutdown
        handler.shutdown_state = SocketHandlerShutdownState.SHUT_DOWN_READ
        channel_slot_on_handler_shutdown_complete!(slot, direction, false, true)

    else  # WRITE
        if handler.shutdown_state >= SocketHandlerShutdownState.SHUTTING_DOWN_WRITE
            return nothing  # Already shutting down
        end

        handler.shutdown_state = SocketHandlerShutdownState.SHUTTING_DOWN_WRITE

        # Shutdown socket write direction
        socket_shutdown_dir(socket, ChannelDirection.WRITE)

        # Complete write shutdown
        handler.shutdown_state = SocketHandlerShutdownState.SHUT_DOWN_WRITE
        channel_slot_on_handler_shutdown_complete!(slot, direction, false, true)

        # If both directions are done, mark complete
        if handler.shutdown_state == SocketHandlerShutdownState.SHUT_DOWN_WRITE
            handler.shutdown_state = SocketHandlerShutdownState.COMPLETE
        end
    end

    return nothing
end

# Trigger handler to process pending writes
function handler_trigger_write(handler::SocketChannelHandler)::Nothing
    # Socket handler doesn't batch writes, so nothing to do
    return nothing
end

# Internal - trigger a socket read
function _socket_handler_trigger_read(handler::SocketChannelHandler)
    if handler.read_paused
        handler.read_paused = false
    end

    if handler.shutdown_state >= SocketHandlerShutdownState.SHUTTING_DOWN_READ
        return nothing
    end

    if handler.slot === nothing
        return nothing
    end

    channel = handler.slot.channel
    if channel === nothing
        return nothing
    end

    # Subscribe to readable events if not already
    _socket_handler_subscribe_to_read(handler)

    sock = handler.socket
    event_loop = sock.event_loop
    if event_loop === nothing
        return nothing
    end

    if event_loop_thread_is_callers_thread(event_loop)
        _socket_handler_do_read(handler)
        return nothing
    end

    task_fn = (ctx, status) -> begin
        status == TaskStatus.RUN_READY || return nothing
        _socket_handler_do_read(ctx)
        return nothing
    end
    task = ScheduledTask(task_fn, handler; type_tag = "socket_read_now")
    event_loop_schedule_task_now!(event_loop, task)

    return nothing
end

# Subscribe to socket readable events
function _socket_handler_subscribe_to_read(handler::SocketChannelHandler)
    socket = handler.socket

    # Set readable callback
    socket_subscribe_to_readable_events(socket, _on_socket_readable, handler)

    return nothing
end

# Socket readable callback - called when socket has data to read
function _on_socket_readable(socket, error_code::Int, user_data)
    handler = user_data

    if error_code != AWS_OP_SUCCESS
        logf(
            LogLevel.DEBUG, LS_IO_SOCKET_HANDLER,
            "Socket handler: readable event with error $error_code"
        )

        if handler.slot !== nothing && handler.slot.channel !== nothing
            channel_shutdown!(handler.slot.channel, ChannelDirection.READ, error_code)
        end
        return nothing
    end

    if handler.shutdown_state >= SocketHandlerShutdownState.SHUTTING_DOWN_READ
        return nothing
    end

    # Read data from socket
    _socket_handler_do_read(handler)

    return nothing
end

# Internal - perform a socket read
function _socket_handler_do_read(handler::SocketChannelHandler)
    if handler.slot === nothing
        return nothing
    end

    channel = handler.slot.channel
    if channel === nothing
        return nothing
    end

    socket = handler.socket
    slot = handler.slot

    handler.reads_in_progress += 1

    # Check flow control
    if handler.read_window == 0
        logf(
            LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
            "Socket handler: read window exhausted, pausing reads"
        )
        handler.read_paused = true
        handler.reads_in_progress -= 1
        return nothing
    end

    # Calculate how much to read
    read_size = min(handler.read_window, handler.max_read_size)

    # Acquire message from pool
    message = channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, read_size)
    if message === nothing
        logf(
            LogLevel.ERROR, LS_IO_SOCKET_HANDLER,
            "Socket handler: failed to acquire message from pool"
        )
        handler.reads_in_progress -= 1
        return nothing
    end

    # Read into message buffer
    read_result = socket_read(socket, message.message_data)

    if read_result isa ErrorResult
        if read_result.code == ERROR_IO_READ_WOULD_BLOCK
            # No data available, release message and wait
            channel_release_message_to_pool!(channel, message)
            handler.reads_in_progress -= 1
            return nothing
        end

        logf(
            LogLevel.DEBUG, LS_IO_SOCKET_HANDLER,
            "Socket handler: socket read failed with error $(read_result.code)"
        )
        channel_release_message_to_pool!(channel, message)
        handler.reads_in_progress -= 1

        # Trigger shutdown on error
        channel_shutdown!(channel, ChannelDirection.READ, read_result.code)
        return nothing
    end

    _, bytes_read = read_result
    handler.stats.read_calls += 1
    handler.stats.bytes_read += bytes_read

    logf(
        LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
        "Socket handler: read $bytes_read bytes from socket"
    )

    if bytes_read == 0
        # EOF - no data read
        channel_release_message_to_pool!(channel, message)
        handler.reads_in_progress -= 1
        return nothing
    end

    # Consume from read window
    handler.read_window -= bytes_read

    # Send message into channel
    send_result = channel_slot_send_message(slot, message, ChannelDirection.READ)

    if send_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_SOCKET_HANDLER,
            "Socket handler: failed to send read message into channel"
        )
        channel_release_message_to_pool!(channel, message)
        handler.reads_in_progress -= 1
        channel_shutdown!(channel, ChannelDirection.READ, send_result.code)
        return nothing
    end

    handler.reads_in_progress -= 1

    # Continue reading if window allows
    if handler.read_window > 0 && handler.shutdown_state < SocketHandlerShutdownState.SHUTTING_DOWN_READ
        _socket_handler_do_read(handler)
    elseif handler.read_window == 0
        handler.read_paused = true
    end

    return nothing
end

# Create and set up a socket channel handler in a channel
function socket_channel_handler_new!(
        channel::Channel,
        socket;
        initial_window_size::Integer = SIZE_MAX,
        max_read_size::Integer = 16384,
    )::Union{SocketChannelHandler, ErrorResult}
    handler = SocketChannelHandler(
        socket;
        initial_window_size = initial_window_size,
        max_read_size = max_read_size,
    )

    # Create slot and add to channel (at the socket end / right side)
    slot = channel_slot_new!(channel)
    channel_slot_insert_end!(channel, slot)
    channel_slot_set_handler!(slot, handler)
    handler.slot = slot

    # Link handler to the socket
    socket.handler = handler

    logf(
        LogLevel.DEBUG, LS_IO_SOCKET_HANDLER,
        "Socket handler: created and added to channel $(channel.channel_id)"
    )

    return handler
end
