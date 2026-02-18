# AWS IO Library - IOCP pipe backend
# Port of aws-c-io/source/windows/iocp/pipe.c

@static if Sys.iswindows()

    const _KERNEL32 = "Kernel32"
    const INVALID_HANDLE_VALUE = Ptr{Cvoid}(-1)

    const ERROR_IO_PENDING = UInt32(997)
    const ERROR_BROKEN_PIPE = UInt32(109)

    const STATUS_PIPE_BROKEN = UInt32(0xC000014B)
    const STATUS_CANCELLED = UInt32(0xC0000120)

    const PIPE_ACCESS_OUTBOUND = UInt32(0x00000002)
    const FILE_FLAG_OVERLAPPED = UInt32(0x40000000)
    const FILE_FLAG_FIRST_PIPE_INSTANCE = UInt32(0x00080000)

    const PIPE_TYPE_BYTE = UInt32(0x00000000)
    const PIPE_WAIT = UInt32(0x00000000)
    const PIPE_REJECT_REMOTE_CLIENTS = UInt32(0x00000008)

    const OPEN_EXISTING = UInt32(3)
    const GENERIC_READ = UInt32(0x80000000)
    const FILE_ATTRIBUTE_NORMAL = UInt32(0x00000080)

    const PIPE_BUFFER_SIZE = UInt32(4096)

    @enumx IocpPipeReadEndState::UInt8 begin
        OPEN = 0
        SUBSCRIBING = 1
        SUBSCRIBED = 2
        SUBSCRIBE_ERROR = 3
    end

    const MONITORING_BECAUSE_SUBSCRIBING = UInt8(1)
    const MONITORING_BECAUSE_WAITING_FOR_DATA = UInt8(2)
    const MONITORING_BECAUSE_ERROR_SUSPECTED = UInt8(4)

    mutable struct IocpPipeReadEndImpl
        state::IocpPipeReadEndState.T
        monitoring_op::IocpOverlapped
        monitoring_active::Bool
        error_report_task::Union{Nothing, ScheduledTask}
        error_task_active::Bool
        error_code_to_report::Int
        monitoring_request_reasons::UInt8
        cleaned_up::Bool
    end

    function IocpPipeReadEndImpl(read_end::PipeReadEnd)
        impl = IocpPipeReadEndImpl(
            IocpPipeReadEndState.OPEN,
            IocpOverlapped(),
            false,
            nothing,
            false,
            0,
            UInt8(0),
            false,
        )
        iocp_overlapped_init!(impl.monitoring_op, _iocp_pipe_on_zero_byte_read_completion, read_end)
        return impl
    end

    mutable struct IocpPipeWriteRequest
        write_end::PipeWriteEnd
        original_len::Csize_t
        on_complete::Union{WriteCallable, Nothing}
        overlapped::IocpOverlapped
        cleaned_up::Bool
    end

    mutable struct IocpPipeWriteEndImpl
        cleaned_up::Bool
        writes::Vector{IocpPipeWriteRequest}
    end

    function IocpPipeWriteEndImpl()
        return IocpPipeWriteEndImpl(false, [])
    end

    @inline function _iocp_pipe_get_last_error()::UInt32
        return ccall((:GetLastError, _KERNEL32), UInt32, ())
    end

    function _iocp_pipe_translate_windows_error(code::Integer)::Int
        c = UInt32(code)
        if c == ERROR_BROKEN_PIPE || c == STATUS_PIPE_BROKEN || c == STATUS_CANCELLED
            return ERROR_IO_BROKEN_PIPE
        end
        return ERROR_SYS_CALL_FAILURE
    end

    function _iocp_pipe_raise_last_error()
        win_err = _iocp_pipe_get_last_error()
        socket_err = _iocp_pipe_translate_windows_error(win_err)
        throw_error(socket_err)
    end

    function _iocp_pipe_unique_name()::String
        uuid_str = string(UUIDs.uuid4())
        return "\\\\.\\pipe\\reseau_pipe_$(uuid_str)"
    end

    function pipe_create_iocp()::Tuple{PipeReadEnd, PipeWriteEnd}
        pipe_name = _iocp_pipe_unique_name()

        open_mode = PIPE_ACCESS_OUTBOUND | FILE_FLAG_OVERLAPPED | FILE_FLAG_FIRST_PIPE_INSTANCE
        pipe_mode = PIPE_TYPE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS

        write_handle = ccall(
            (:CreateNamedPipeA, _KERNEL32),
            Ptr{Cvoid},
            (Cstring, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, Ptr{Cvoid}),
            pipe_name,
            open_mode,
            pipe_mode,
            UInt32(1), # nMaxInstances
            PIPE_BUFFER_SIZE,
            PIPE_BUFFER_SIZE,
            UInt32(0),
            C_NULL,
        )

        if write_handle == INVALID_HANDLE_VALUE
            _iocp_pipe_raise_last_error()
        end

        read_handle = ccall(
            (:CreateFileA, _KERNEL32),
            Ptr{Cvoid},
            (Cstring, UInt32, UInt32, Ptr{Cvoid}, UInt32, UInt32, Ptr{Cvoid}),
            pipe_name,
            GENERIC_READ,
            UInt32(0), # dwShareMode
            C_NULL,    # lpSecurityAttributes
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            C_NULL,
        )

        if read_handle == INVALID_HANDLE_VALUE
            _ = ccall((:CloseHandle, _KERNEL32), Int32, (Ptr{Cvoid},), write_handle)
            _iocp_pipe_raise_last_error()
        end

        read_end = PipeReadEnd(-1)
        read_end.io_handle.handle = read_handle
        read_end.impl = IocpPipeReadEndImpl(read_end)

        write_end = PipeWriteEnd(-1)
        write_end.io_handle.handle = write_handle
        write_end.impl = IocpPipeWriteEndImpl()

        return (read_end, write_end)
    end

    function _pipe_read_end_close_iocp!(read_end::PipeReadEnd)::Nothing
        impl = read_end.impl::IocpPipeReadEndImpl
        if read_end.io_handle.handle != C_NULL && read_end.io_handle.handle != INVALID_HANDLE_VALUE
            _ = ccall((:CloseHandle, _KERNEL32), Int32, (Ptr{Cvoid},), read_end.io_handle.handle)
        end

        impl.cleaned_up = true

        read_end.io_handle.handle = C_NULL
        read_end.on_readable = nothing
        read_end.event_loop = nothing
        read_end.is_subscribed = false

        return nothing
    end

    function _pipe_write_end_close_iocp!(write_end::PipeWriteEnd)::Nothing
        impl = write_end.impl::IocpPipeWriteEndImpl
        impl.cleaned_up = true

        if write_end.io_handle.handle != C_NULL && write_end.io_handle.handle != INVALID_HANDLE_VALUE
            _ = ccall((:CloseHandle, _KERNEL32), Int32, (Ptr{Cvoid},), write_end.io_handle.handle)
        end

        write_end.io_handle.handle = C_NULL
        write_end.event_loop = nothing
        write_end.is_subscribed = false

        return nothing
    end

    function _pipe_read_end_is_subscribed(read_end::PipeReadEnd)::Bool
        impl = read_end.impl::IocpPipeReadEndImpl
        st = impl.state
        return st == IocpPipeReadEndState.SUBSCRIBING ||
            st == IocpPipeReadEndState.SUBSCRIBED ||
            st == IocpPipeReadEndState.SUBSCRIBE_ERROR
    end

    function _pipe_read_end_request_async_monitoring!(read_end::PipeReadEnd, request_reason::UInt8)
        impl = read_end.impl::IocpPipeReadEndImpl

        async_monitoring_allowed = _pipe_read_end_is_subscribed(read_end) &&
            (impl.state != IocpPipeReadEndState.SUBSCRIBE_ERROR)
        async_monitoring_allowed || return nothing

        if impl.monitoring_active
            impl.monitoring_request_reasons |= request_reason
            return nothing
        end

        impl.monitoring_request_reasons = UInt8(0)
        impl.state = IocpPipeReadEndState.SUBSCRIBED
        impl.error_code_to_report = 0

        iocp_overlapped_reset!(impl.monitoring_op)

        fake_buffer = Ref{UInt32}(0)
        success = ccall(
            (:ReadFile, _KERNEL32),
            Int32,
            (Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{UInt32}, Ptr{Cvoid}),
            read_end.io_handle.handle,
            fake_buffer,
            UInt32(0),
            C_NULL,
            iocp_overlapped_ptr(impl.monitoring_op),
        ) != 0

        if success || _iocp_pipe_get_last_error() == ERROR_IO_PENDING
            impl.monitoring_active = true
            impl.monitoring_op.active = true
            return nothing
        end

        # Could not start monitoring. Report error via task.
        impl.state = IocpPipeReadEndState.SUBSCRIBE_ERROR
        impl.error_code_to_report = _iocp_pipe_translate_windows_error(_iocp_pipe_get_last_error())

        if impl.error_report_task === nothing
            impl.error_report_task = ScheduledTask(; type_tag = "pipe_read_end_report_error") do status
                try
                    _iocp_pipe_read_end_report_error_task(read_end, _coerce_task_status(status))
                catch e
                    Core.println("pipe_read_end_report_error task errored")
                end
                return nothing
            end
        end

        impl.error_task_active = true
        if read_end.event_loop !== nothing
            schedule_task_now!(read_end.event_loop, impl.error_report_task)
        end

        return nothing
    end

    function _iocp_pipe_read_end_report_error_task(read_end::PipeReadEnd, status::TaskStatus.T)
        _ = status
        impl = read_end.impl::IocpPipeReadEndImpl
        impl.error_task_active = false
        impl.error_report_task = nothing

        if impl.cleaned_up
            return nothing
        end

        if impl.state == IocpPipeReadEndState.SUBSCRIBE_ERROR
            if read_end.on_readable !== nothing
                read_end.on_readable(impl.error_code_to_report)
            end
        end

        return nothing
    end

    function _iocp_pipe_on_zero_byte_read_completion(
            event_loop,
            overlapped::IocpOverlapped,
            status_code::Int,
            num_bytes_transferred::Csize_t,
        )
        _ = event_loop
        _ = num_bytes_transferred

        read_end = overlapped.user_data::PipeReadEnd
        impl = read_end.impl::IocpPipeReadEndImpl

        impl.monitoring_active = false
        impl.monitoring_op.active = false

        impl.cleaned_up && return nothing

        if impl.state == IocpPipeReadEndState.SUBSCRIBED
            readable_error_code = if status_code == 0
                impl.monitoring_request_reasons &= ~MONITORING_BECAUSE_WAITING_FOR_DATA
                OP_SUCCESS
            else
                impl.state = IocpPipeReadEndState.SUBSCRIBE_ERROR
                ERROR_IO_BROKEN_PIPE
            end

            if read_end.on_readable !== nothing
                read_end.on_readable(readable_error_code)
            end
        end

        impl.cleaned_up && return nothing

        if impl.monitoring_request_reasons != 0
            _pipe_read_end_request_async_monitoring!(read_end, impl.monitoring_request_reasons)
        end

        return nothing
    end

    function _pipe_read_end_subscribe_iocp!(
            read_end::PipeReadEnd,
            on_readable::EventCallable,
        )::Nothing
        impl = read_end.impl::IocpPipeReadEndImpl

        if impl.state != IocpPipeReadEndState.OPEN
            if _pipe_read_end_is_subscribed(read_end)
                throw_error(ERROR_IO_ALREADY_SUBSCRIBED)
            end
            throw_error(ERROR_UNKNOWN)
        end

        if read_end.event_loop === nothing
            throw_error(ERROR_IO_BROKEN_PIPE)
        end
        if !event_loop_thread_is_callers_thread(read_end.event_loop)
            throw_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
        end

        impl.state = IocpPipeReadEndState.SUBSCRIBING
        read_end.on_readable = on_readable
        read_end.is_subscribed = true

        _pipe_read_end_request_async_monitoring!(read_end, MONITORING_BECAUSE_SUBSCRIBING)
        return nothing
    end

    function _pipe_read_end_unsubscribe_iocp!(read_end::PipeReadEnd)::Nothing
        impl = read_end.impl::IocpPipeReadEndImpl

        if read_end.event_loop === nothing
            throw_error(ERROR_IO_BROKEN_PIPE)
        end
        if !_pipe_read_end_is_subscribed(read_end)
            throw_error(ERROR_IO_NOT_SUBSCRIBED)
        end
        if !event_loop_thread_is_callers_thread(read_end.event_loop)
            throw_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
        end

        impl.state = IocpPipeReadEndState.OPEN
        read_end.on_readable = nothing
        read_end.is_subscribed = false
        impl.monitoring_request_reasons = 0
        impl.error_code_to_report = 0

        if impl.monitoring_active
            _ = ccall((:CancelIo, _KERNEL32), Int32, (Ptr{Cvoid},), read_end.io_handle.handle)
        end

        return nothing
    end

    function _pipe_read_iocp!(read_end::PipeReadEnd, buffer::ByteBuffer)::Tuple{Nothing, Csize_t}
        if read_end.event_loop === nothing
            throw_error(ERROR_IO_BROKEN_PIPE)
        end
        if !event_loop_thread_is_callers_thread(read_end.event_loop)
            throw_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
        end

        remaining = buffer.capacity - buffer.len
        if remaining == 0
            return (nothing, Csize_t(0))
        end

        bytes_available = Ref{UInt32}(0)
        peek_success = ccall(
            (:PeekNamedPipe, _KERNEL32),
            Int32,
            (Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{UInt32}, Ptr{UInt32}, Ptr{UInt32}),
            read_end.io_handle.handle,
            C_NULL,
            UInt32(0),
            C_NULL,
            bytes_available,
            C_NULL,
        ) != 0

        if !peek_success
            _pipe_read_end_request_async_monitoring!(read_end, MONITORING_BECAUSE_ERROR_SUSPECTED)
            _iocp_pipe_raise_last_error()
        end

        if bytes_available[] == 0
            _pipe_read_end_request_async_monitoring!(read_end, MONITORING_BECAUSE_WAITING_FOR_DATA)
            throw_error(ERROR_IO_READ_WOULD_BLOCK)
        end

        bytes_to_read = min(UInt32(remaining), bytes_available[])
        bytes_read = Ref{UInt32}(0)

        buf_ptr = pointer(getfield(buffer, :mem)) + buffer.len
        read_success = ccall(
            (:ReadFile, _KERNEL32),
            Int32,
            (Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{UInt32}, Ptr{Cvoid}),
            read_end.io_handle.handle,
            buf_ptr,
            bytes_to_read,
            bytes_read,
            C_NULL,
        ) != 0

        if !read_success
            _pipe_read_end_request_async_monitoring!(read_end, MONITORING_BECAUSE_ERROR_SUSPECTED)
            _iocp_pipe_raise_last_error()
        end

        amount_read = Csize_t(bytes_read[])
        buffer.len += amount_read

        if bytes_read[] < bytes_to_read
            _pipe_read_end_request_async_monitoring!(read_end, MONITORING_BECAUSE_WAITING_FOR_DATA)
        end

        return (nothing, amount_read)
    end

    function _pipe_write_iocp!(
            write_end::PipeWriteEnd,
            cursor::ByteCursor,
            on_complete::Union{WriteCallable, Nothing},
        )::Nothing
        if write_end.event_loop === nothing
            throw_error(ERROR_IO_BROKEN_PIPE)
        end
        if !event_loop_thread_is_callers_thread(write_end.event_loop)
            throw_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
        end

        if cursor.len > Csize_t(typemax(UInt32))
            throw_error(ERROR_INVALID_BUFFER_SIZE)
        end

        impl = write_end.impl::IocpPipeWriteEndImpl
        impl.cleaned_up && throw_error(ERROR_IO_BROKEN_PIPE)

        req = IocpPipeWriteRequest(
            write_end,
            cursor.len,
            on_complete,
            IocpOverlapped(),
            false,
        )
        iocp_overlapped_init!(req.overlapped, _iocp_pipe_on_write_completion, req)

        push!(impl.writes, req)

        success = ccall(
            (:WriteFile, _KERNEL32),
            Int32,
            (Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{UInt32}, Ptr{Cvoid}),
            write_end.io_handle.handle,
            cursor.ptr,
            UInt32(cursor.len),
            C_NULL,
            iocp_overlapped_ptr(req.overlapped),
        ) != 0

        if !success && _iocp_pipe_get_last_error() != ERROR_IO_PENDING
            # Remove request and report error.
            pop!(impl.writes)
            _iocp_pipe_raise_last_error()
        end

        return nothing
    end

    function _iocp_pipe_on_write_completion(
            event_loop,
            overlapped::IocpOverlapped,
            status_code::Int,
            num_bytes_transferred::Csize_t,
        )
        _ = event_loop

        req = overlapped.user_data::IocpPipeWriteRequest
        write_end = req.write_end
        impl = write_end.impl::IocpPipeWriteEndImpl

        # Remove from active list.
        idx = findfirst(==(req), impl.writes)
        idx !== nothing && deleteat!(impl.writes, idx)

        error_code = status_code == 0 ? OP_SUCCESS : _iocp_pipe_translate_windows_error(status_code)

        if req.on_complete !== nothing
            req.on_complete(error_code, num_bytes_transferred)
        end

        return nothing
    end

end # @static if Sys.iswindows()

# =============================================================================
# Public entrypoint / fallback
# =============================================================================

@static if !Sys.iswindows()
function pipe_create_iocp()::Tuple{PipeReadEnd, PipeWriteEnd}
    throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
end
end
