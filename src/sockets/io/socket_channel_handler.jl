# AWS IO Library - Socket Channel Handler
# Port of aws-c-io/source/socket_channel_handler.c

# Socket channel handler - bridges socket IO to channel pipeline
# This handler is typically the leftmost handler in a channel (socket side)
# It reads from the socket and pushes messages into the channel (read direction)
# It receives write messages and sends them out the socket (write direction)

# Socket channel handler structure
mutable struct SocketChannelHandler <: AbstractChannelHandler
    socket::Socket
    slot::Union{ChannelSlot, Nothing}
    max_rw_size::Csize_t
    read_task_storage::ChannelTask
    shutdown_task_storage::ChannelTask
    stats::SocketHandlerStatistics
    shutdown_error_code::Int
    shutdown_in_progress::Bool
    pending_read::Bool
end

function SocketChannelHandler(
        socket::Socket;
        max_read_size::Integer = 16384,
    )
    stats = SocketHandlerStatistics()
    crt_statistics_socket_init!(stats)
    return SocketChannelHandler(
        socket,
        nothing,
        Csize_t(max_read_size),
        ChannelTask(),
        ChannelTask(),
        stats,
        0,
        false,
        false,
    )
end

function setchannelslot!(handler::SocketChannelHandler, slot::ChannelSlot)::Nothing
    handler.slot = slot
    return nothing
end

# Handler interface implementations

function handler_initial_window_size(handler::SocketChannelHandler)::Csize_t
    return SIZE_MAX
end

function handler_message_overhead(handler::SocketChannelHandler)::Csize_t
    return Csize_t(0)  # Socket handler adds no overhead
end

function handler_destroy(handler::SocketChannelHandler)::Nothing
    logf(LogLevel.TRACE, LS_IO_SOCKET_HANDLER, "Socket handler: destroying")
    crt_statistics_socket_cleanup!(handler.stats)
    return nothing
end

function handler_reset_statistics(handler::SocketChannelHandler)::Nothing
    crt_statistics_socket_reset!(handler.stats)
    return nothing
end

function handler_gather_statistics(handler::SocketChannelHandler)::SocketHandlerStatistics
    return handler.stats
end

# Process read message - socket handler is at the socket end, shouldn't receive read messages
function handler_process_read_message(handler::SocketChannelHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    _ = handler
    _ = slot
    _ = message
    logf(LogLevel.FATAL, LS_IO_SOCKET_HANDLER, "Socket handler: unexpected read message received")
    fatal_assert("socket handler process_read_message called", "<unknown>", 0)
    raise_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
    return ErrorResult(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
end

# Process write message - send data out the socket
function handler_process_write_message(handler::SocketChannelHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    socket = handler.socket
    _ = slot

    if !socket_is_open(socket)
        raise_error(ERROR_IO_SOCKET_CLOSED)
        return ErrorResult(ERROR_IO_SOCKET_CLOSED)
    end

    logf(
        LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
        "Socket handler: writing $(message.message_data.len) bytes to socket"
    )

    # Create byte cursor from message data
    cursor = byte_cursor_from_buf(message.message_data)

    # Write to socket
    write_result = socket_write(socket, cursor, _on_socket_write_complete, message)

    if write_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_SOCKET_HANDLER,
            "Socket handler: failed to write to socket, error=$(write_result.code)"
        )
        return write_result
    end

    return nothing
end

# Socket write completion callback
function _on_socket_write_complete(socket, error_code::Int, bytes_written::Csize_t, user_data)
    message = user_data
    channel = message isa IoMessage ? message.owning_channel : nothing

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
    end

    if socket !== nothing && socket.handler isa SocketChannelHandler
        socket.handler.stats.bytes_written += UInt64(bytes_written)
    elseif channel isa Channel && channel.first !== nothing && channel.first.handler isa SocketChannelHandler
        channel.first.handler.stats.bytes_written += UInt64(bytes_written)
    end

    if message isa IoMessage && message.on_completion !== nothing
        Base.invokelatest(message.on_completion, channel, message, error_code, message.user_data)
    end

    # Release the message back to pool
    if channel isa Channel && message isa IoMessage
        channel_release_message_to_pool!(channel, message)
    end

    # If error, trigger shutdown
    if error_code != AWS_OP_SUCCESS && channel isa Channel
        channel_shutdown!(channel, error_code)
    end

    return nothing
end

# Increment read window - handler can now read more data
function handler_increment_read_window(handler::SocketChannelHandler, slot::ChannelSlot, size::Csize_t)::Union{Nothing, ErrorResult}
    _ = size

    if handler.shutdown_in_progress
        return nothing
    end
    handler.pending_read && (handler.pending_read = false)
    logf(
        LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
        "Socket handler: increment read window message received, scheduling read"
    )
    _socket_handler_trigger_read(handler)
    return nothing
end

# Shutdown handler
struct SocketHandlerShutdownArgs
    handler::SocketChannelHandler
    channel::Channel
    slot::ChannelSlot
    error_code::Int
    direction::ChannelDirection.T
    free_scarce_resources_immediately::Bool
end

function _socket_handler_close_task(task::ChannelTask, handler::SocketChannelHandler, status::TaskStatus.T)
    _ = task
    _ = status
    slot = handler.slot
    if slot === nothing
        return nothing
    end
    channel_slot_on_handler_shutdown_complete!(slot, ChannelDirection.WRITE, handler.shutdown_error_code, false)
    return nothing
end

function _socket_handler_shutdown_complete_fn(user_data)
    args = user_data
    handler = args.handler
    channel_task_init!(handler.shutdown_task_storage, _socket_handler_close_task, handler, "socket_handler_close")
    handler.shutdown_error_code = args.error_code
    channel_schedule_task_now!(args.channel, handler.shutdown_task_storage)
    return nothing
end

function _socket_handler_shutdown_read_complete_fn(user_data)
    args = user_data
    channel_slot_on_handler_shutdown_complete!(
        args.slot,
        args.direction,
        args.error_code,
        args.free_scarce_resources_immediately,
    )
    return nothing
end

function handler_shutdown(
        handler::SocketChannelHandler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Union{Nothing, ErrorResult}
    socket = handler.socket
    channel = slot.channel

    logf(
        LogLevel.DEBUG, LS_IO_SOCKET_HANDLER,
        "Socket handler: shutdown requested, direction=$direction, error=$error_code"
    )

    handler.shutdown_error_code = error_code
    handler.shutdown_in_progress = true

    if direction == ChannelDirection.READ
        logf(
            LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
            "Socket handler: shutting down read direction with error_code $error_code"
        )
        if free_scarce_resources_immediately && socket_is_open(socket)
            channel === nothing && return nothing
            args = SocketHandlerShutdownArgs(handler, channel, slot, error_code, direction, free_scarce_resources_immediately)
            cb_result = socket_set_close_complete_callback(socket, _socket_handler_shutdown_read_complete_fn, args)
            if cb_result isa ErrorResult
                return cb_result
            end
            return socket_close(socket)
        end

        return channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    end

    logf(
        LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
        "Socket handler: shutting down write direction with error_code $error_code"
    )
    if socket_is_open(socket)
        channel === nothing && return nothing
        args = SocketHandlerShutdownArgs(handler, channel, slot, error_code, direction, free_scarce_resources_immediately)
        cb_result = socket_set_close_complete_callback(socket, _socket_handler_shutdown_complete_fn, args)
        if cb_result isa ErrorResult
            return cb_result
        end
        socket_close(socket)
    else
        channel === nothing && return nothing
        channel_task_init!(handler.shutdown_task_storage, _socket_handler_close_task, handler, "socket_handler_close")
        handler.shutdown_error_code = error_code
        channel_schedule_task_now!(channel, handler.shutdown_task_storage)
    end

    return nothing
end

# Trigger handler to process pending writes
function handler_trigger_write(handler::SocketChannelHandler)::Nothing
    # Socket handler doesn't batch writes, so nothing to do
    return nothing
end

function handler_trigger_read(handler::SocketChannelHandler)::Nothing
    _socket_handler_trigger_read(handler)
    return nothing
end

# Internal - trigger a socket read
function _socket_handler_trigger_read(handler::SocketChannelHandler)
    if handler.shutdown_in_progress
        return nothing
    end

    if handler.slot === nothing
        return nothing
    end

    slot = handler.slot
    if slot.adj_right === nothing || slot.adj_right.handler === nothing
        handler.pending_read = true
        return nothing
    end

    channel = slot.channel
    if channel === nothing
        return nothing
    end

    sock = handler.socket
    event_loop = sock.event_loop
    if event_loop === nothing
        return nothing
    end

    if event_loop_thread_is_callers_thread(event_loop)
        _socket_handler_do_read(handler)
        return nothing
    end

    channel = slot.channel
    if channel === nothing
        return nothing
    end

    if handler.read_task_storage.wrapper_task.scheduled
        return nothing
    end

    channel_task_init!(handler.read_task_storage, _socket_handler_read_task, handler, "socket_handler_read_now")
    channel_schedule_task_now!(channel, handler.read_task_storage)

    return nothing
end

# Subscribe to socket readable events
function _socket_handler_subscribe_to_read(handler::SocketChannelHandler)
    socket = handler.socket

    # Set readable callback
    return socket_subscribe_to_readable_events(socket, _on_socket_readable, handler)
end

# Socket readable callback - called when socket has data to read
function _on_socket_readable(socket, error_code::Int, user_data)
    _ = socket
    handler = user_data

    logf(
        LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
        "Socket handler: readable event with error $error_code"
    )

    _ = error_code
    _socket_handler_trigger_read(handler)

    return nothing
end

function _socket_handler_read_task(task::ChannelTask, handler::SocketChannelHandler, status::TaskStatus.T)
    _ = task
    if status == TaskStatus.RUN_READY
        _socket_handler_do_read(handler)
    end
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

    if handler.shutdown_in_progress
        return nothing
    end

    downstream_window = channel_slot_downstream_read_window(slot)
    max_to_read = downstream_window > handler.max_rw_size ? handler.max_rw_size : downstream_window

    logf(
        LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
        "Socket handler: invoking read. Downstream window $downstream_window, max_to_read $max_to_read"
    )

    if max_to_read == 0
        return nothing
    end

    total_read = Csize_t(0)
    last_error = 0

    while total_read < max_to_read
        iter_max_read = max_to_read - total_read
        message = channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, iter_max_read)
        if message === nothing
            logf(
                LogLevel.ERROR, LS_IO_SOCKET_HANDLER,
                "Socket handler: failed to acquire message from pool"
            )
            last_error = ERROR_OOM
            break
        end

        read_result = socket_read(socket, message.message_data)
        if read_result isa ErrorResult
            last_error = read_result.code
            channel_release_message_to_pool!(channel, message)
            break
        end

        _, bytes_read = read_result
        total_read += bytes_read

        logf(
            LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
            "Socket handler: read $bytes_read bytes from socket"
        )

        send_result = channel_slot_send_message(slot, message, ChannelDirection.READ)
        if send_result isa ErrorResult
            last_error = send_result.code
            channel_release_message_to_pool!(channel, message)
            break
        end
    end

    logf(
        LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
        "Socket handler: total read on this tick $total_read"
    )

    handler.stats.bytes_read += UInt64(total_read)

    if total_read < max_to_read
        if last_error != 0 && last_error != ERROR_IO_READ_WOULD_BLOCK
            channel_shutdown!(channel, last_error)
        end
        return nothing
    end

    if total_read == handler.max_rw_size && !handler.read_task_storage.wrapper_task.scheduled
        channel_task_init!(handler.read_task_storage, _socket_handler_read_task, handler, "socket_handler_re_read")
        channel_schedule_task_now!(channel, handler.read_task_storage)
    end

    return nothing
end

function _socket_handler_wrap_channel_setup!(handler::SocketChannelHandler, channel::Channel)
    original_cb = channel.on_setup_completed
    channel.on_setup_completed = (ch, err, ud) -> begin
        if original_cb !== nothing
            Base.invokelatest(original_cb, ch, err, ud)
        end
        if err == AWS_OP_SUCCESS &&
                ch.channel_state == ChannelState.ACTIVE &&
                handler.pending_read &&
                !handler.shutdown_in_progress
            handler.pending_read = false
            _socket_handler_trigger_read(handler)
        end
        return nothing
    end
    return nothing
end

# Create and set up a socket channel handler in a channel
function socket_channel_handler_new!(
        channel::Channel,
        socket;
        max_read_size::Integer = 16384,
    )::Union{SocketChannelHandler, ErrorResult}
    if socket.event_loop === nothing
        raise_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
        return ErrorResult(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
    end

    handler = SocketChannelHandler(
        socket;
        max_read_size = max_read_size,
    )

    # Create slot and add to channel (socket is left-most)
    slot = channel_slot_new!(channel)
    if channel.first !== slot
        channel_slot_insert_front!(channel, slot)
    end
    channel_slot_set_handler!(slot, handler)

    # Link handler to the socket
    socket.handler = handler

    _socket_handler_wrap_channel_setup!(handler, channel)

    sub_result = _socket_handler_subscribe_to_read(handler)
    if sub_result isa ErrorResult
        return sub_result
    end

    logf(
        LogLevel.DEBUG, LS_IO_SOCKET_HANDLER,
        "Socket handler: created and added to channel $(channel.channel_id)"
    )

    return handler
end

function socket_channel_handler_get_socket(handler::SocketChannelHandler)
    return handler.socket
end
