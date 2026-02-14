# Socket Pipeline Handler
#
# Bridges socket IO to the closure-based middleware pipeline.
# All handler state has been merged into Socket fields (pipeline, read_fn,
# write_fn, stats, etc.) so there is no separate handler struct.
#
# Read path:  OS → socket_read → _socket_dispatch_read → read_fn → (TLS → app)
# Write path: app → pipeline_write! → write_fn → (TLS → _socket_write_message) → socket_write → OS

const SOCKET_DEFAULT_MAX_READ_SIZE = Csize_t(16384)

# Initialize a socket for pipeline use. Sets up pipeline-integration fields,
# subscribes to readable events, and registers shutdown closures.
function socket_pipeline_init!(
        socket::Socket,
        ps::PipelineState;
        max_read_size::Integer = 16384,
    )
    socket.pipeline = ps
    socket.max_rw_size = Csize_t(max_read_size)
    # Socket reads up to downstream_window. Set to SIZE_MAX when no backpressure,
    # or to a handshake-sized value initially when backpressure is enabled
    # (the bootstrap/TLS init will adjust as needed).
    socket.downstream_window = ps.read_back_pressure_enabled ? Csize_t(0) : SIZE_MAX
    stats = SocketHandlerStatistics()
    crt_statistics_socket_init!(stats)
    socket.stats = stats
    socket.read_task = ChannelTask()
    socket.shutdown_task = ChannelTask()
    socket.pending_read = false
    socket.shutdown_in_progress = false

    # Store socket reference on pipeline and set default downstream_read_setter.
    # Set the default write_fn to write directly to the OS socket.
    # TLS middleware overrides this in _wire_tls_pipeline!.
    ps.socket = socket
    socket.write_fn = msg -> _socket_write_message(socket, msg)
    ps.downstream_read_setter = read_fn -> begin
        socket.read_fn = read_fn
    end

    # Subscribe to OS readable events → triggers read loop
    socket_subscribe_to_readable_events(socket, EventCallable(error_code -> begin
        logf(
            LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
            "Socket handler: readable event with error $error_code"
        )
        _socket_handler_trigger_read(socket)::Nothing
        return nothing
    end))

    # Register socket shutdown closures in the pipeline's shutdown chain.
    # Read shutdown is leftmost (socket side, first in read shutdown order).
    # Write shutdown is leftmost (socket side, last in write shutdown order).
    pushfirst!(ps.shutdown_chain.read_shutdown_fns,
        (err, scarce, on_complete) -> _socket_read_shutdown(socket, err, scarce, on_complete))
    push!(ps.shutdown_chain.write_shutdown_fns,
        (err, scarce, on_complete) -> _socket_write_shutdown(socket, err, scarce, on_complete))

    logf(
        LogLevel.DEBUG, LS_IO_SOCKET_HANDLER,
        "Socket handler: initialized for pipeline $(ps.channel_id)"
    )
    return nothing
end

# --- Read path ---

# Trigger a socket read. Called from _socket_trigger_read (channel.jl) and
# from readable event subscriptions.
function _socket_handler_trigger_read(socket::Socket)::Nothing
    if socket.shutdown_in_progress
        return nothing
    end

    ps = socket.pipeline
    if !(ps isa PipelineState)
        socket.pending_read = true
        return nothing
    end

    if socket.read_fn === nothing
        socket.pending_read = true
        return nothing
    end

    event_loop = socket.event_loop
    if event_loop === nothing
        return nothing
    end

    if event_loop_thread_is_callers_thread(event_loop)
        _socket_do_read(socket)::Nothing
        return nothing
    end

    rt = socket.read_task
    if rt === nothing
        return nothing
    end
    read_task = rt::ChannelTask
    if read_task.wrapper_task.scheduled
        return nothing
    end

    channel_task_init!(read_task, EventCallable(s -> _socket_read_task(socket, _coerce_task_status(s))), "socket_read_now")
    pipeline_schedule_task_now!(ps::PipelineState, read_task)::Nothing
    return nothing
end

function _socket_read_task(socket::Socket, status::TaskStatus.T)
    if status == TaskStatus.RUN_READY
        _socket_do_read(socket)
    end
    return nothing
end

# Perform the socket read loop: read from OS socket, dispatch via read_fn.
function _socket_do_read(socket::Socket)
    ps = socket.pipeline
    if !(ps isa PipelineState)
        return nothing
    end

    if socket.shutdown_in_progress
        return nothing
    end

    downstream_window = socket.downstream_window
    max_to_read = downstream_window > socket.max_rw_size ? socket.max_rw_size : downstream_window

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
        message = pipeline_acquire_message_from_pool(ps, IoMessageType.APPLICATION_DATA, iter_max_read)
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
            pipeline_release_message_to_pool!(ps, message)
            break
        end
        total_read += bytes_read

        logf(
            LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
            "Socket handler: read $bytes_read bytes from socket"
        )

        try
            _socket_dispatch_read(socket, message)
        catch e
            if e isa ReseauError
                last_error = e.code
            else
                last_error = ERROR_UNKNOWN
            end
            pipeline_release_message_to_pool!(ps, message)
            break
        end
    end

    logf(
        LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
        "Socket handler: total read on this tick $total_read"
    )

    # Update stats
    stats = socket.stats
    if stats !== nothing
        (stats::SocketHandlerStatistics).bytes_read += UInt64(total_read)
    end

    # Decrement socket downstream window
    if total_read > 0
        socket.downstream_window = socket.downstream_window > total_read ?
            socket.downstream_window - total_read : Csize_t(0)
    end

    if total_read < max_to_read
        if last_error != 0 && last_error != ERROR_IO_READ_WOULD_BLOCK
            pipeline_shutdown!(ps, last_error)
        end
        return nothing
    end

    # If we read a full chunk, schedule another read to drain the socket
    rt = socket.read_task
    if rt !== nothing
        read_task = rt::ChannelTask
        if total_read == socket.max_rw_size && !read_task.wrapper_task.scheduled
            channel_task_init!(read_task, EventCallable(s -> _socket_read_task(socket, _coerce_task_status(s))), "socket_re_read")
            pipeline_schedule_task_now!(ps, read_task)
        end
    end

    return nothing
end

# --- Write path ---

# Write an IoMessage to the OS socket. This is the terminal step of the
# write closure chain (called by write_fn or directly for non-TLS).
function _socket_write_message(socket::Socket, message::IoMessage)
    write_complete = WriteCallable((error_code, bytes_written) ->
        _on_socket_write_complete(socket, message, error_code, bytes_written))

    if !socket_is_open(socket)
        write_complete(ERROR_IO_SOCKET_CLOSED, Csize_t(0))
        return nothing
    end

    logf(
        LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
        "Socket handler: writing $(message.message_data.len) bytes to socket"
    )

    cursor = byte_cursor_from_buf(message.message_data)
    try
        socket_write(socket, cursor, write_complete)
    catch e
        e isa ReseauError || rethrow()
        write_complete(e.code, Csize_t(0))
    end

    return nothing
end

# Socket write completion callback
function _on_socket_write_complete(socket::Socket, message::IoMessage, error_code::Int, bytes_written::Csize_t)
    ps = socket.pipeline

    if error_code != AWS_OP_SUCCESS
        logf(
            LogLevel.DEBUG, LS_IO_SOCKET_HANDLER,
            "Socket handler: write completed with error $error_code, wrote $bytes_written bytes"
        )
    else
        logf(
            LogLevel.TRACE, LS_IO_SOCKET_HANDLER,
            "Socket handler: write completed, wrote $bytes_written bytes"
        )
    end

    # Update stats
    stats = socket.stats
    if stats !== nothing
        (stats::SocketHandlerStatistics).bytes_written += UInt64(bytes_written)
    end

    # Invoke message completion callback
    if message.on_completion !== nothing
        message.on_completion(error_code)
    end

    # Release message to pool
    if ps isa PipelineState
        pipeline_release_message_to_pool!(ps, message)
    end

    # If error, trigger shutdown
    if error_code != AWS_OP_SUCCESS && ps isa PipelineState
        pipeline_shutdown!(ps, error_code)
    end

    return nothing
end

# --- Shutdown ---

# Read direction shutdown closure (registered as first in read_shutdown_fns).
function _socket_read_shutdown(socket::Socket, error_code::Int, free_scarce::Bool, on_complete::Function)
    logf(
        LogLevel.DEBUG, LS_IO_SOCKET_HANDLER,
        "Socket handler: read shutdown, error=$error_code, free_scarce=$free_scarce"
    )
    socket.shutdown_in_progress = true

    if free_scarce && socket_is_open(socket)
        socket_set_close_complete_callback(socket, TaskFn(_ -> begin
            on_complete(error_code, free_scarce)
            return nothing
        end))
        socket_close(socket)
    else
        on_complete(error_code, free_scarce)
    end
    return nothing
end

# Write direction shutdown closure (registered as last in write_shutdown_fns).
function _socket_write_shutdown(socket::Socket, error_code::Int, free_scarce::Bool, on_complete::Function)
    logf(
        LogLevel.DEBUG, LS_IO_SOCKET_HANDLER,
        "Socket handler: write shutdown, error=$error_code"
    )

    if socket_is_open(socket)
        socket_set_close_complete_callback(socket, TaskFn(_ -> begin
            on_complete(error_code, free_scarce)
            return nothing
        end))
        socket_close(socket)
    else
        on_complete(error_code, free_scarce)
    end
    return nothing
end

# --- Statistics ---

function socket_reset_statistics(socket::Socket)::Nothing
    stats = socket.stats
    if stats !== nothing
        crt_statistics_socket_reset!(stats::SocketHandlerStatistics)
    end
    return nothing
end

function socket_gather_statistics(socket::Socket)::Union{SocketHandlerStatistics, Nothing}
    stats = socket.stats
    return stats isa SocketHandlerStatistics ? stats : nothing
end

function socket_cleanup_handler!(socket::Socket)::Nothing
    stats = socket.stats
    if stats !== nothing
        crt_statistics_socket_cleanup!(stats::SocketHandlerStatistics)
    end
    socket.pipeline = nothing
    socket.read_fn = nothing
    socket.write_fn = nothing
    socket.stats = nothing
    socket.read_task = nothing
    socket.shutdown_task = nothing
    return nothing
end
