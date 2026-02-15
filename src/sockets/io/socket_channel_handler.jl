# AWS IO Library - Socket Channel Handler
# Port of aws-c-io/source/socket_channel_handler.c

# Socket channel handler - bridges socket IO to channel pipeline
# This handler is typically the leftmost handler in a channel (socket side)
# It reads from the socket and pushes messages into the channel (read direction)
# It receives write messages and sends them out the socket (write direction)

# Socket channel handler structure
mutable struct SocketChannelHandler
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
    slot = handler.slot
    if slot !== nothing
        channel = slot.channel
        if channel isa Channel && channel.socket === handler.socket
            channel.socket = nothing
        end
    end
    handler.slot = nothing
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
function handler_process_read_message(handler::SocketChannelHandler, slot::ChannelSlot, message::IoMessage)::Nothing
    _ = handler
    _ = slot
    _ = message
    logf(LogLevel.FATAL, LS_IO_SOCKET_HANDLER, "Socket handler: unexpected read message received")
    fatal_assert("socket handler process_read_message called", "<unknown>", 0)
    throw_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
end

# Process write message - send data out the socket
function handler_process_write_message(handler::SocketChannelHandler, slot::ChannelSlot, message::IoMessage)::Nothing
    socket = handler.socket
    _ = slot

    write_complete = WriteCallable((error_code, bytes_written) -> _on_socket_write_complete(handler, message, error_code, bytes_written))

    if !socket_is_open(socket)
        # Preserve async completion semantics: report error via completion path
        # and let channel shutdown cascade there, rather than throwing on loop thread.
        write_complete(ERROR_IO_SOCKET_CLOSED, Csize_t(0))
        return nothing
    end

    logf(
        LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
        "Socket handler: writing $(message.message_data.len) bytes to socket"
    )

    # Create byte cursor from message data
    cursor = byte_cursor_from_buf(message.message_data)

    # Write to socket
    try
        socket_write(socket, cursor, write_complete)
    catch e
        e isa ReseauError || rethrow()
        write_complete(e.code, Csize_t(0))
    end

    return nothing
end

# Socket write completion callback
function _on_socket_write_complete(handler::SocketChannelHandler, message, error_code::Int, bytes_written::Csize_t)
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

    handler.stats.bytes_written += UInt64(bytes_written)

    if message isa IoMessage && message.on_completion !== nothing
        message.on_completion(error_code)
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
function handler_increment_read_window(handler::SocketChannelHandler, slot::ChannelSlot, size::Csize_t)::Nothing
    _ = size

    if handler.shutdown_in_progress
        return nothing
    end
    handler.pending_read && (handler.pending_read = false)
    logf(
        LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
        "Socket handler: increment read window message received, scheduling read"
    )
    _socket_handler_trigger_read(handler)::Nothing
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

function _socket_handler_close_task(handler::SocketChannelHandler)
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
    channel_task_init!(handler.shutdown_task_storage, EventCallable(_ -> _socket_handler_close_task(handler)), "socket_handler_close")
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
    )::Nothing
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
            socket_set_close_complete_callback(socket, TaskFn(_ -> _socket_handler_shutdown_read_complete_fn(args)))
            socket_close(socket)
            return nothing
        end

        channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
        return nothing
    end

    logf(
        LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
        "Socket handler: shutting down write direction with error_code $error_code"
    )
    if socket_is_open(socket)
        channel === nothing && return nothing
        args = SocketHandlerShutdownArgs(handler, channel, slot, error_code, direction, free_scarce_resources_immediately)
        socket_set_close_complete_callback(socket, TaskFn(_ -> _socket_handler_shutdown_complete_fn(args)))
        socket_close(socket)
    else
        channel === nothing && return nothing
        channel_task_init!(handler.shutdown_task_storage, EventCallable(_ -> _socket_handler_close_task(handler)), "socket_handler_close")
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
    _socket_handler_trigger_read(handler)::Nothing
    return nothing
end

# Internal - trigger a socket read
function _socket_handler_trigger_read(handler::SocketChannelHandler)::Nothing
    if handler.shutdown_in_progress
        return nothing
    end

    slot = handler.slot
    if slot === nothing
        return nothing
    end
    if slot.adj_right === nothing || slot.adj_right.handler_read === nothing
        handler.pending_read = true
        return nothing
    end

    channel_any = slot.channel
    if !(channel_any isa Channel)
        return nothing
    end
    channel = channel_any::Channel

    sock = handler.socket
    event_loop = sock.event_loop
    if event_loop === nothing
        return nothing
    end

    if event_loop_thread_is_callers_thread(event_loop)
        _socket_handler_do_read(handler)::Nothing
        return nothing
    end

    if handler.read_task_storage.wrapper_task.scheduled
        return nothing
    end

    channel_task_init!(handler.read_task_storage, EventCallable(s -> _socket_handler_read_task(handler, _coerce_task_status(s))), "socket_handler_read_now")
    channel_schedule_task_now!(channel, handler.read_task_storage)::Nothing

    return nothing
end

# Subscribe to socket readable events
function _socket_handler_subscribe_to_read(handler::SocketChannelHandler)
    socket = handler.socket

    # Set readable callback
    return socket_subscribe_to_readable_events(socket, EventCallable(error_code -> begin
        logf(
            LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
            "Socket handler: readable event with error $error_code"
        )
        _socket_handler_trigger_read(handler)::Nothing
        return nothing
    end))
end

function _socket_handler_read_task(handler::SocketChannelHandler, status::TaskStatus.T)
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

        local bytes_read
        try
            _, bytes_read = socket_read(socket, message.message_data)
        catch e
            if e isa ReseauError
                last_error = e.code
            else
                last_error = ERROR_UNKNOWN
            end
            channel_release_message_to_pool!(channel, message)
            break
        end
        total_read += bytes_read

        logf(
            LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
            "Socket handler: read $bytes_read bytes from socket"
        )

        try
            channel_slot_send_message(slot, message, ChannelDirection.READ)
        catch e
            if e isa ReseauError
                last_error = e.code
            else
                last_error = ERROR_UNKNOWN
            end
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
        channel_task_init!(handler.read_task_storage, EventCallable(s -> _socket_handler_read_task(handler, _coerce_task_status(s))), "socket_handler_re_read")
        channel_schedule_task_now!(channel, handler.read_task_storage)
    end

    return nothing
end

function _socket_handler_wrap_channel_setup!(handler::SocketChannelHandler, channel::Channel)
    original_cb = channel.on_setup_completed
    channel.on_setup_completed = EventCallable(err -> begin
        if original_cb !== nothing
            original_cb(err)
        end
        if err == AWS_OP_SUCCESS &&
                channel.channel_state == ChannelState.ACTIVE &&
                handler.pending_read &&
                !handler.shutdown_in_progress
            handler.pending_read = false
            _socket_handler_trigger_read(handler)::Nothing
        end
        return nothing
    end)
    return nothing
end

# Create and set up a socket channel handler in a channel
function socket_channel_handler_new!(
        channel::Channel,
        socket;
        max_read_size::Integer = 16384,
    )::SocketChannelHandler
    if socket.event_loop === nothing
        throw_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
    end
    if channel.socket !== nothing && channel.socket !== socket
        throw_error(ERROR_INVALID_STATE)
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

    channel.socket = socket

    _socket_handler_wrap_channel_setup!(handler, channel)

    _socket_handler_subscribe_to_read(handler)

    logf(
        LogLevel.DEBUG, LS_IO_SOCKET_HANDLER,
        "Socket handler: created and added to channel $(channel.channel_id)"
    )

    return handler
end

function socket_channel_handler_get_socket(handler::SocketChannelHandler)
    return handler.socket
end
