# AWS IO Library - Pipe Abstraction
# Port of aws-c-io/source/posix/pipe.c

# Callback types for pipe operations (WriteCallable used for trim-safe dispatch)

# Pipe read end
mutable struct PipeReadEnd
    io_handle::IoHandle
    event_loop::Union{EventLoop, Nothing}  # nullable
    on_readable::Union{EventCallable, Nothing}  # nullable
    is_subscribed::Bool
    impl::Any  # platform-specific impl data (e.g. IOCP on Windows)
end

function PipeReadEnd(fd::Integer)
    return PipeReadEnd(
        IoHandle(Int32(fd)),
        nothing,
        nothing,
        false,
        nothing,
    )
end

# Pipe write end
mutable struct PipeWriteEnd
    io_handle::IoHandle
    event_loop::Union{EventLoop, Nothing}
    write_queue::Vector{SocketWriteRequest}  # Reuse socket write request
    is_subscribed::Bool
    impl::Any  # platform-specific impl data (e.g. IOCP on Windows)
end

function PipeWriteEnd(fd::Integer)
    return PipeWriteEnd(
        IoHandle(Int32(fd)),
        nothing,
        SocketWriteRequest[],
        false,
        nothing,
    )
end

# Create a pipe (returns read_end, write_end)
function pipe_create()::Tuple{PipeReadEnd, PipeWriteEnd}
    @static if Sys.iswindows()
        return pipe_create_iocp()
    end

    fds = Memory{Cint}(undef, 2)

    result = ccall(:pipe, Cint, (Ptr{Cint},), fds)

    if result != 0
        errno_val = get_errno()
        logf(LogLevel.ERROR, LS_IO_GENERAL, "Pipe: creation failed with errno=$errno_val")
        throw_error(ERROR_IO_BROKEN_PIPE)
    end

    read_fd = fds[1]
    write_fd = fds[2]

    logf(LogLevel.DEBUG, LS_IO_GENERAL, "Pipe: created read_fd=$read_fd, write_fd=$write_fd")

    # Set non-blocking
    _set_nonblocking(read_fd)
    _set_nonblocking(write_fd)

    read_end = PipeReadEnd(read_fd)
    write_end = PipeWriteEnd(write_fd)

    return (read_end, write_end)
end

# Set fd to non-blocking mode
function _set_nonblocking(fd::Cint)
    flags = _fcntl(fd, F_GETFL)
    flags |= O_NONBLOCK
    _fcntl(fd, F_SETFL, flags)
    fd_flags = _fcntl(fd, F_GETFD)
    fd_flags |= FD_CLOEXEC
    _fcntl(fd, F_SETFD, fd_flags)
    return nothing
end

# Close pipe read end
function pipe_read_end_close!(read_end::PipeReadEnd)::Nothing
    @static if Sys.iswindows()
        return _pipe_read_end_close_iocp!(read_end)
    end

    fd = read_end.io_handle.fd

    if fd >= 0
        logf(LogLevel.DEBUG, LS_IO_GENERAL, "Pipe: closing read end fd=$fd")

        if read_end.is_subscribed && read_end.event_loop !== nothing
            event_loop_unsubscribe_from_io_events!(read_end.event_loop, read_end.io_handle)
            read_end.is_subscribed = false
        end

        ccall(:close, Cint, (Cint,), fd)
        read_end.io_handle.fd = -1
        read_end.on_readable = nothing
        read_end.event_loop = nothing
    end

    return nothing
end

# Close pipe write end
function pipe_write_end_close!(write_end::PipeWriteEnd)::Nothing
    @static if Sys.iswindows()
        return _pipe_write_end_close_iocp!(write_end)
    end

    fd = write_end.io_handle.fd

    if fd >= 0
        logf(LogLevel.DEBUG, LS_IO_GENERAL, "Pipe: closing write end fd=$fd")

        if write_end.is_subscribed && write_end.event_loop !== nothing
            event_loop_unsubscribe_from_io_events!(write_end.event_loop, write_end.io_handle)
            write_end.is_subscribed = false
        end

        # Complete pending writes with error
        while !isempty(write_end.write_queue)
            req = popfirst!(write_end.write_queue)
            if req.written_fn !== nothing
                req.written_fn(ERROR_IO_BROKEN_PIPE, Csize_t(0))
            end
        end

        ccall(:close, Cint, (Cint,), fd)
        write_end.io_handle.fd = -1
        write_end.event_loop = nothing
    end

    return nothing
end

# Subscribe to readable events on read end
function pipe_read_end_subscribe!(
        read_end::PipeReadEnd,
        event_loop::EventLoop,
        on_readable::EventCallable,
    )::Nothing
    @static if Sys.iswindows()
        # event_loop is already stored on the read_end during pipe_init(); keep in sync.
        read_end.event_loop = event_loop
        return _pipe_read_end_subscribe_iocp!(read_end, on_readable)
    end

    if read_end.is_subscribed
        throw_error(ERROR_IO_ALREADY_SUBSCRIBED)
    end

    read_end.on_readable = on_readable
    read_end.event_loop = event_loop

    event_loop_subscribe_to_io_events!(
        event_loop,
        read_end.io_handle,
        Int(IoEventType.READABLE),
        EventCallable(events -> _pipe_read_event_handler(read_end, events)),
    )

    read_end.is_subscribed = true

    logf(
        LogLevel.TRACE, LS_IO_GENERAL,
        "Pipe: read end fd=$(read_end.io_handle.fd) subscribed to events"
    )

    return nothing
end

# Pipe read event handler
function _pipe_read_event_handler(read_end, events::Int)

    if (events & Int(IoEventType.READABLE)) != 0
        if read_end.on_readable !== nothing
            read_end.on_readable(AWS_OP_SUCCESS)
        end
    end

    if (events & Int(IoEventType.ERROR)) != 0 || (events & Int(IoEventType.CLOSED)) != 0
        if read_end.on_readable !== nothing
            read_end.on_readable(ERROR_IO_BROKEN_PIPE)
        end
    end

    return nothing
end

# =============================================================================
# aws-c-io style wrappers (no aws_ prefix)
# =============================================================================

function pipe_init(
        read_end_event_loop::EventLoop,
        write_end_event_loop::EventLoop,
    )::Tuple{PipeReadEnd, PipeWriteEnd}
    read_end, write_end = pipe_create()

    read_end.event_loop = read_end_event_loop
    write_end.event_loop = write_end_event_loop

    @static if Sys.iswindows()
        # Associate handles with each loop's IOCP.
        try
            event_loop_connect_to_io_completion_port!(write_end_event_loop, write_end.io_handle)
            event_loop_connect_to_io_completion_port!(read_end_event_loop, read_end.io_handle)
        catch
            pipe_read_end_close!(read_end)
            pipe_write_end_close!(write_end)
            rethrow()
        end

        # For IOCP, write-end does not require "writable" subscription; IO completion callbacks drive progress.
        write_end.is_subscribed = true
        return (read_end, write_end)
    end

    try
        pipe_write_end_subscribe!(write_end, write_end_event_loop)
    catch
        pipe_read_end_close!(read_end)
        pipe_write_end_close!(write_end)
        rethrow()
    end

    return (read_end, write_end)
end

function pipe_clean_up_read_end(read_end::PipeReadEnd)::Nothing
    if read_end.event_loop === nothing
        throw_error(ERROR_IO_BROKEN_PIPE)
    end
    if !event_loop_thread_is_callers_thread(read_end.event_loop)
        throw_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end
    return pipe_read_end_close!(read_end)
end

function pipe_clean_up_write_end(write_end::PipeWriteEnd)::Nothing
    if write_end.event_loop === nothing
        throw_error(ERROR_IO_BROKEN_PIPE)
    end
    if !event_loop_thread_is_callers_thread(write_end.event_loop)
        throw_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end
    return pipe_write_end_close!(write_end)
end

function pipe_get_read_end_event_loop(read_end::PipeReadEnd)::EventLoop
    if read_end.event_loop === nothing
        throw_error(ERROR_IO_BROKEN_PIPE)
    end
    return read_end.event_loop
end

function pipe_get_write_end_event_loop(write_end::PipeWriteEnd)::EventLoop
    if write_end.event_loop === nothing
        throw_error(ERROR_IO_BROKEN_PIPE)
    end
    return write_end.event_loop
end

function pipe_read(read_end::PipeReadEnd, buffer::ByteBuffer)::Tuple{Nothing, Csize_t}
    if read_end.event_loop !== nothing && !event_loop_thread_is_callers_thread(read_end.event_loop)
        throw_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end
    return pipe_read!(read_end, buffer)
end

function pipe_write(
        write_end::PipeWriteEnd,
        cursor::ByteCursor,
        on_complete::Union{WriteCallable, Nothing} = nothing,
    )::Nothing
    if write_end.event_loop !== nothing && !event_loop_thread_is_callers_thread(write_end.event_loop)
        throw_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end
    return pipe_write!(write_end, cursor, on_complete)
end

function pipe_subscribe_to_readable_events(
        read_end::PipeReadEnd,
        on_readable::EventCallable,
    )::Nothing
    if read_end.event_loop === nothing
        throw_error(ERROR_IO_BROKEN_PIPE)
    end
    if !event_loop_thread_is_callers_thread(read_end.event_loop)
        throw_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end
    return pipe_read_end_subscribe!(read_end, read_end.event_loop, on_readable)
end

function pipe_unsubscribe_from_readable_events(read_end::PipeReadEnd)::Nothing
    @static if Sys.iswindows()
        return _pipe_read_end_unsubscribe_iocp!(read_end)
    end

    if read_end.event_loop === nothing
        throw_error(ERROR_IO_BROKEN_PIPE)
    end
    if !event_loop_thread_is_callers_thread(read_end.event_loop)
        throw_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end
    if !read_end.is_subscribed
        throw_error(ERROR_IO_NOT_SUBSCRIBED)
    end

    event_loop_unsubscribe_from_io_events!(read_end.event_loop, read_end.io_handle)
    read_end.is_subscribed = false
    return nothing
end

# Read from pipe
function pipe_read!(read_end::PipeReadEnd, buffer::ByteBuffer)::Tuple{Nothing, Csize_t}
    @static if Sys.iswindows()
        return _pipe_read_iocp!(read_end, buffer)
    end

    fd = read_end.io_handle.fd

    if fd < 0
        throw_error(ERROR_IO_BROKEN_PIPE)
    end

    remaining = buffer.capacity - buffer.len
    if remaining == 0
        return (nothing, Csize_t(0))
    end

    buf_ptr = pointer(getfield(buffer, :mem)) + buffer.len
    read_val = ccall(:read, Cssize_t, (Cint, Ptr{UInt8}, Csize_t), fd, buf_ptr, remaining)
    errno_val = get_errno()

    if read_val > 0
        amount_read = Csize_t(read_val)
        setfield!(buffer, :len, buffer.len + amount_read)
        return (nothing, amount_read)
    end

    if read_val == 0
        # EOF
        throw_error(ERROR_IO_BROKEN_PIPE)
    end

    # Error
    if errno_val == EAGAIN || errno_val == EWOULDBLOCK
        throw_error(ERROR_IO_READ_WOULD_BLOCK)
    end

    throw_error(ERROR_IO_BROKEN_PIPE)
end

# Subscribe write end to event loop
function pipe_write_end_subscribe!(
        write_end::PipeWriteEnd,
        event_loop::EventLoop,
    )::Nothing
    if write_end.is_subscribed
        throw_error(ERROR_IO_ALREADY_SUBSCRIBED)
    end

    write_end.event_loop = event_loop

    event_loop_subscribe_to_io_events!(
        event_loop,
        write_end.io_handle,
        Int(IoEventType.WRITABLE),
        EventCallable(events -> _pipe_write_event_handler(write_end, events)),
    )

    write_end.is_subscribed = true

    logf(
        LogLevel.TRACE, LS_IO_GENERAL,
        "Pipe: write end fd=$(write_end.io_handle.fd) subscribed to events"
    )

    return nothing
end

# Pipe write event handler
function _pipe_write_event_handler(write_end, events::Int)

    if (events & Int(IoEventType.WRITABLE)) != 0
        _process_pipe_writes(write_end)
    end

    return nothing
end

# Process pending pipe writes
function _process_pipe_writes(write_end::PipeWriteEnd)
    fd = write_end.io_handle.fd

    while !isempty(write_end.write_queue)
        req = first(write_end.write_queue)

        cursor_raw = req.cursor.len > 0 ? pointer(req.cursor.ptr) : Ptr{UInt8}(0)
        written = ccall(
            :write, Cssize_t, (Cint, Ptr{UInt8}, Csize_t),
            fd, cursor_raw, req.cursor.len
        )
        errno_val = get_errno()

        if written < 0
            if errno_val == EAGAIN
                break  # Would block, try later
            end

            # Error - complete all with error
            popfirst!(write_end.write_queue)
            if req.written_fn !== nothing
                req.written_fn(ERROR_IO_BROKEN_PIPE, Csize_t(0))
            end
            continue
        end

        remaining = req.cursor.len
        cursor_ref = Ref(req.cursor)
        _ = byte_cursor_advance(cursor_ref, Csize_t(written))
        req.cursor = cursor_ref[]

        if Csize_t(written) == remaining
            # Write complete
            popfirst!(write_end.write_queue)
            if req.written_fn !== nothing
                req.written_fn(AWS_OP_SUCCESS, req.original_len)
            end
        end
    end

    return nothing
end

# Write to pipe
function pipe_write!(
        write_end::PipeWriteEnd,
        cursor::ByteCursor,
        on_complete::Union{WriteCallable, Nothing} = nothing,
    )::Nothing
    @static if Sys.iswindows()
        return _pipe_write_iocp!(write_end, cursor, on_complete)
    end

    fd = write_end.io_handle.fd

    if fd < 0
        throw_error(ERROR_IO_BROKEN_PIPE)
    end

    # Create write request
    req = SocketWriteRequest(
        cursor,
        cursor.len,
        on_complete,
        0,
        nothing,
        nothing,
    )

    push!(write_end.write_queue, req)

    # Try to write immediately if subscribed
    if write_end.is_subscribed
        _process_pipe_writes(write_end)
    end

    return nothing
end

# Synchronous write to pipe (blocking)
function pipe_write_sync!(write_end::PipeWriteEnd, data::AbstractVector{UInt8})::Csize_t
    fd = write_end.io_handle.fd

    if fd < 0
        throw_error(ERROR_IO_BROKEN_PIPE)
    end

    total_written = Csize_t(0)
    ptr = pointer(data)
    remaining = Csize_t(length(data))

    while remaining > 0
        written = ccall(:write, Cssize_t, (Cint, Ptr{UInt8}, Csize_t), fd, ptr + total_written, remaining)

        if written < 0
            errno_val = get_errno()
            if errno_val == EAGAIN || errno_val == EWOULDBLOCK
                continue  # Retry
            end
            throw_error(ERROR_IO_BROKEN_PIPE)
        end

        total_written += Csize_t(written)
        remaining -= Csize_t(written)
    end

    return total_written
end
