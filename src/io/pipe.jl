# AWS IO Library - Pipe Abstraction
# Port of aws-c-io/source/posix/pipe.c

# Callback types for pipe operations
const OnPipeReadableFn = Function  # (pipe, error_code, user_data) -> nothing
const OnPipeWriteCompleteFn = Function  # (pipe, error_code, bytes_written, user_data) -> nothing

# Pipe read end
# Note: user_data is parameterized as U (typically Any) since it can hold any user-provided value
# and is set dynamically after creation via pipe_read_end_subscribe!
mutable struct PipeReadEnd{U}
    io_handle::IoHandle
    event_loop::Union{EventLoop, Nothing}  # nullable
    on_readable::Union{OnPipeReadableFn, Nothing}  # nullable
    user_data::U
    is_subscribed::Bool
    impl::Any  # platform-specific impl data (e.g. IOCP on Windows)
end

function PipeReadEnd(fd::Integer)
    return PipeReadEnd{Any}(
        IoHandle(Int32(fd)),
        nothing,
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
    write_queue::Deque{SocketWriteRequest}  # Reuse socket write request
    is_subscribed::Bool
    impl::Any  # platform-specific impl data (e.g. IOCP on Windows)
end

function PipeWriteEnd(fd::Integer)
    return PipeWriteEnd(
        IoHandle(Int32(fd)),
        nothing,
        Deque{SocketWriteRequest}(),
        false,
        nothing,
    )
end

# Create a pipe (returns read_end, write_end)
function pipe_create()::Union{Tuple{PipeReadEnd, PipeWriteEnd}, ErrorResult}
    @static if Sys.iswindows()
        return pipe_create_iocp()
    end

    fds = Memory{Cint}(undef, 2)

    result = ccall(:pipe, Cint, (Ptr{Cint},), fds)

    if result != 0
        errno_val = get_errno()
        logf(LogLevel.ERROR, LS_IO_GENERAL, "Pipe: creation failed with errno=$errno_val")
        raise_error(ERROR_IO_BROKEN_PIPE)
        return ErrorResult(ERROR_IO_BROKEN_PIPE)
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
function pipe_read_end_close!(read_end::PipeReadEnd)::Union{Nothing, ErrorResult}
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
        read_end.user_data = nothing
        read_end.event_loop = nothing
    end

    return nothing
end

# Close pipe write end
function pipe_write_end_close!(write_end::PipeWriteEnd)::Union{Nothing, ErrorResult}
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
                Base.invokelatest(req.written_fn, write_end, ERROR_IO_BROKEN_PIPE, Csize_t(0), req.user_data)
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
        on_readable::OnPipeReadableFn,
        user_data,
    )::Union{Nothing, ErrorResult}
    @static if Sys.iswindows()
        # event_loop is already stored on the read_end during pipe_init(); keep in sync.
        read_end.event_loop = event_loop
        return _pipe_read_end_subscribe_iocp!(read_end, on_readable, user_data)
    end

    if read_end.is_subscribed
        raise_error(ERROR_IO_ALREADY_SUBSCRIBED)
        return ErrorResult(ERROR_IO_ALREADY_SUBSCRIBED)
    end

    read_end.on_readable = on_readable
    read_end.user_data = user_data
    read_end.event_loop = event_loop

    result = event_loop_subscribe_to_io_events!(
        event_loop,
        read_end.io_handle,
        Int(IoEventType.READABLE),
        _pipe_read_event_handler,
        read_end,
    )

    if result isa ErrorResult
        return result
    end

    read_end.is_subscribed = true

    logf(
        LogLevel.TRACE, LS_IO_GENERAL,
        "Pipe: read end fd=$(read_end.io_handle.fd) subscribed to events"
    )

    return nothing
end

# Pipe read event handler
function _pipe_read_event_handler(event_loop, handle::IoHandle, events::Int, user_data)
    read_end = user_data

    if (events & Int(IoEventType.READABLE)) != 0
        if read_end.on_readable !== nothing
            Base.invokelatest(read_end.on_readable, read_end, AWS_OP_SUCCESS, read_end.user_data)
        end
    end

    if (events & Int(IoEventType.ERROR)) != 0 || (events & Int(IoEventType.CLOSED)) != 0
        if read_end.on_readable !== nothing
            Base.invokelatest(read_end.on_readable, read_end, ERROR_IO_BROKEN_PIPE, read_end.user_data)
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
    )::Union{Tuple{PipeReadEnd, PipeWriteEnd}, ErrorResult}
    result = pipe_create()
    result isa ErrorResult && return result
    read_end, write_end = result

    read_end.event_loop = read_end_event_loop
    write_end.event_loop = write_end_event_loop

    @static if Sys.iswindows()
        # Associate handles with each loop's IOCP.
        res = event_loop_connect_to_io_completion_port!(write_end_event_loop, write_end.io_handle)
        if res isa ErrorResult
            pipe_read_end_close!(read_end)
            pipe_write_end_close!(write_end)
            return res
        end
        res2 = event_loop_connect_to_io_completion_port!(read_end_event_loop, read_end.io_handle)
        if res2 isa ErrorResult
            pipe_read_end_close!(read_end)
            pipe_write_end_close!(write_end)
            return res2
        end

        # For IOCP, write-end does not require "writable" subscription; IO completion callbacks drive progress.
        write_end.is_subscribed = true
        return (read_end, write_end)
    end

    sub_result = pipe_write_end_subscribe!(write_end, write_end_event_loop)
    if sub_result isa ErrorResult
        pipe_read_end_close!(read_end)
        pipe_write_end_close!(write_end)
        return sub_result
    end

    return (read_end, write_end)
end

function pipe_clean_up_read_end(read_end::PipeReadEnd)::Union{Nothing, ErrorResult}
    if read_end.event_loop === nothing
        raise_error(ERROR_IO_BROKEN_PIPE)
        return ErrorResult(ERROR_IO_BROKEN_PIPE)
    end
    if !event_loop_thread_is_callers_thread(read_end.event_loop)
        raise_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
        return ErrorResult(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end
    return pipe_read_end_close!(read_end)
end

function pipe_clean_up_write_end(write_end::PipeWriteEnd)::Union{Nothing, ErrorResult}
    if write_end.event_loop === nothing
        raise_error(ERROR_IO_BROKEN_PIPE)
        return ErrorResult(ERROR_IO_BROKEN_PIPE)
    end
    if !event_loop_thread_is_callers_thread(write_end.event_loop)
        raise_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
        return ErrorResult(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end
    return pipe_write_end_close!(write_end)
end

function pipe_get_read_end_event_loop(read_end::PipeReadEnd)::Union{EventLoop, ErrorResult}
    if read_end.event_loop === nothing
        raise_error(ERROR_IO_BROKEN_PIPE)
        return ErrorResult(ERROR_IO_BROKEN_PIPE)
    end
    return read_end.event_loop
end

function pipe_get_write_end_event_loop(write_end::PipeWriteEnd)::Union{EventLoop, ErrorResult}
    if write_end.event_loop === nothing
        raise_error(ERROR_IO_BROKEN_PIPE)
        return ErrorResult(ERROR_IO_BROKEN_PIPE)
    end
    return write_end.event_loop
end

function pipe_read(read_end::PipeReadEnd, buffer::ByteBuffer)::Union{Tuple{Nothing, Csize_t}, ErrorResult}
    if read_end.event_loop !== nothing && !event_loop_thread_is_callers_thread(read_end.event_loop)
        raise_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
        return ErrorResult(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end
    return pipe_read!(read_end, buffer)
end

function pipe_write(
        write_end::PipeWriteEnd,
        cursor::ByteCursor,
        on_complete::Union{OnPipeWriteCompleteFn, Nothing} = nothing,
        user_data = nothing,
    )::Union{Nothing, ErrorResult}
    if write_end.event_loop !== nothing && !event_loop_thread_is_callers_thread(write_end.event_loop)
        raise_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
        return ErrorResult(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end
    return pipe_write!(write_end, cursor, on_complete, user_data)
end

function pipe_subscribe_to_readable_events(
        read_end::PipeReadEnd,
        on_readable::OnPipeReadableFn,
        user_data = nothing,
    )::Union{Nothing, ErrorResult}
    if read_end.event_loop === nothing
        raise_error(ERROR_IO_BROKEN_PIPE)
        return ErrorResult(ERROR_IO_BROKEN_PIPE)
    end
    if !event_loop_thread_is_callers_thread(read_end.event_loop)
        raise_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
        return ErrorResult(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end
    return pipe_read_end_subscribe!(read_end, read_end.event_loop, on_readable, user_data)
end

function pipe_unsubscribe_from_readable_events(read_end::PipeReadEnd)::Union{Nothing, ErrorResult}
    @static if Sys.iswindows()
        return _pipe_read_end_unsubscribe_iocp!(read_end)
    end

    if read_end.event_loop === nothing
        raise_error(ERROR_IO_BROKEN_PIPE)
        return ErrorResult(ERROR_IO_BROKEN_PIPE)
    end
    if !event_loop_thread_is_callers_thread(read_end.event_loop)
        raise_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
        return ErrorResult(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end
    if !read_end.is_subscribed
        raise_error(ERROR_IO_NOT_SUBSCRIBED)
        return ErrorResult(ERROR_IO_NOT_SUBSCRIBED)
    end

    result = event_loop_unsubscribe_from_io_events!(read_end.event_loop, read_end.io_handle)
    if result isa ErrorResult
        return result
    end
    read_end.is_subscribed = false
    return nothing
end

# Read from pipe
function pipe_read!(read_end::PipeReadEnd, buffer::ByteBuffer)::Union{Tuple{Nothing, Csize_t}, ErrorResult}
    @static if Sys.iswindows()
        return _pipe_read_iocp!(read_end, buffer)
    end

    fd = read_end.io_handle.fd

    if fd < 0
        raise_error(ERROR_IO_BROKEN_PIPE)
        return ErrorResult(ERROR_IO_BROKEN_PIPE)
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
        raise_error(ERROR_IO_BROKEN_PIPE)
        return ErrorResult(ERROR_IO_BROKEN_PIPE)
    end

    # Error
    if errno_val == EAGAIN || errno_val == EWOULDBLOCK
        raise_error(ERROR_IO_READ_WOULD_BLOCK)
        return ErrorResult(ERROR_IO_READ_WOULD_BLOCK)
    end

    raise_error(ERROR_IO_BROKEN_PIPE)
    return ErrorResult(ERROR_IO_BROKEN_PIPE)
end

# Subscribe write end to event loop
function pipe_write_end_subscribe!(
        write_end::PipeWriteEnd,
        event_loop::EventLoop,
    )::Union{Nothing, ErrorResult}
    if write_end.is_subscribed
        raise_error(ERROR_IO_ALREADY_SUBSCRIBED)
        return ErrorResult(ERROR_IO_ALREADY_SUBSCRIBED)
    end

    write_end.event_loop = event_loop

    result = event_loop_subscribe_to_io_events!(
        event_loop,
        write_end.io_handle,
        Int(IoEventType.WRITABLE),
        _pipe_write_event_handler,
        write_end,
    )

    if result isa ErrorResult
        return result
    end

    write_end.is_subscribed = true

    logf(
        LogLevel.TRACE, LS_IO_GENERAL,
        "Pipe: write end fd=$(write_end.io_handle.fd) subscribed to events"
    )

    return nothing
end

# Pipe write event handler
function _pipe_write_event_handler(event_loop, handle::IoHandle, events::Int, user_data)
    write_end = user_data

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
                Base.invokelatest(req.written_fn, write_end, ERROR_IO_BROKEN_PIPE, Csize_t(0), req.user_data)
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
                Base.invokelatest(req.written_fn, write_end, AWS_OP_SUCCESS, req.original_len, req.user_data)
            end
        end
    end

    return nothing
end

# Write to pipe
function pipe_write!(
        write_end::PipeWriteEnd,
        cursor::ByteCursor,
        on_complete::Union{OnPipeWriteCompleteFn, Nothing} = nothing,
        user_data = nothing,
    )::Union{Nothing, ErrorResult}
    @static if Sys.iswindows()
        return _pipe_write_iocp!(write_end, cursor, on_complete, user_data)
    end

    fd = write_end.io_handle.fd

    if fd < 0
        raise_error(ERROR_IO_BROKEN_PIPE)
        return ErrorResult(ERROR_IO_BROKEN_PIPE)
    end

    # Create write request
    req = SocketWriteRequest(
        cursor,
        cursor.len,
        on_complete,
        user_data,
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
function pipe_write_sync!(write_end::PipeWriteEnd, data::AbstractVector{UInt8})::Union{Csize_t, ErrorResult}
    fd = write_end.io_handle.fd

    if fd < 0
        raise_error(ERROR_IO_BROKEN_PIPE)
        return ErrorResult(ERROR_IO_BROKEN_PIPE)
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
            raise_error(ERROR_IO_BROKEN_PIPE)
            return ErrorResult(ERROR_IO_BROKEN_PIPE)
        end

        total_written += Csize_t(written)
        remaining -= Csize_t(written)
    end

    return total_written
end
