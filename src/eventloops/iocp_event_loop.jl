# AWS IO Library - IOCP Event Loop Implementation
# Port of aws-c-io/source/windows/iocp/iocp_event_loop.c
# Type definitions are in iocp_event_loop_types.jl

@static if Sys.iswindows()
    using LibAwsCal

    @wrap_thread_fn function _iocp_event_loop_thread_entry(event_loop::EventLoop)
        impl = event_loop.impl
        try
            _iocp_event_loop_thread(event_loop)
        catch e
            Core.println("iocp event loop thread errored")
            # Ensure `run!` can observe startup failure even if the thread exits early.
            @atomic impl.startup_error = e isa ReseauError ? e.code : ERROR_SYS_CALL_FAILURE
        finally
            @atomic impl.running_thread_id = UInt64(0)
            LibAwsCal.aws_cal_thread_clean_up()
            # Always release startup waiters to avoid startup deadlock on early failure.
            notify(impl.startup_event)
            notify(impl.completion_event)
        end
    end

    const _IOCP_THREAD_ENTRY_C = Ref{Ptr{Cvoid}}(C_NULL)

    function _iocp_init_cfunctions!()
        _IOCP_THREAD_ENTRY_C[] = @cfunction(_iocp_event_loop_thread_entry, Ptr{Cvoid}, (Ptr{Cvoid},))
        return nothing
    end

    const _KERNEL32 = "Kernel32"
    const _NTDLL = "ntdll"

    const INVALID_HANDLE_VALUE = Ptr{Cvoid}(-1)

    # SetFileCompletionNotificationModes() flags:
    # - FILE_SKIP_COMPLETION_PORT_ON_SUCCESS = 0x01
    # - FILE_SKIP_SET_EVENT_ON_HANDLE       = 0x02
    # We only want to skip setting the event; we still need completion packets
    # even when an operation completes synchronously.
    const FILE_SKIP_SET_EVENT_ON_HANDLE = UInt8(0x02)

    const ERROR_IO_PENDING = UInt32(997)
    const ERROR_INVALID_PARAMETER = UInt32(87)
    const ERROR_ABANDONED_WAIT_0 = UInt32(735)
    const WAIT_TIMEOUT = UInt32(0x00000102)

    const DEFAULT_TIMEOUT_MS = UInt32(100000)
    const MAX_COMPLETION_PACKETS_PER_LOOP = UInt32(100)

    @inline function _iocp_normalize_status_code(raw::UInt)::Int
        # `OVERLAPPED.Internal` is an NTSTATUS (32-bit). Normalize to low 32 bits so
        # status comparisons are consistent across pointer widths.
        return Int(UInt32(raw & UInt(typemax(UInt32))))
    end

    # Layout-compatible with Windows OVERLAPPED (see aws_win32_OVERLAPPED in aws-c-io)
    struct Win32OVERLAPPED
        Internal::UInt
        InternalHigh::UInt
        Offset::UInt32
        OffsetHigh::UInt32
        hEvent::Ptr{Cvoid}
    end

    const _ZERO_OVERLAPPED = Win32OVERLAPPED(UInt(0), UInt(0), UInt32(0), UInt32(0), C_NULL)

    # Extra header to find the Julia callback object when IO completes.
    # OVERLAPPED must be the first field, so pointer to this struct == pointer to OVERLAPPED.
    struct IocpOverlappedHeader
        overlapped::Win32OVERLAPPED
        objref::Ptr{Cvoid} # pointer_from_objref(IocpOverlapped)
    end

    # OVERLAPPED_ENTRY returned by GetQueuedCompletionStatusEx().
    # Layout per minwinbase.h:
    # ULONG_PTR lpCompletionKey; LPOVERLAPPED lpOverlapped; ULONG_PTR Internal; DWORD dwNumberOfBytesTransferred;
    # Note there is no explicit trailing field; 64-bit ABI alignment pads the struct to 32 bytes.
    struct OverlappedEntry
        lpCompletionKey::UInt
        lpOverlapped::Ptr{Cvoid}
        Internal::UInt
        dwNumberOfBytesTransferred::UInt32
    end

    const _OVERLAPPED_ENTRY_EXPECTED_SIZE = Sys.WORD_SIZE == 64 ? 32 : 16
    const _OVERLAPPED_ENTRY_BYTES_OFFSET = 3 * sizeof(UInt)
    @assert sizeof(OverlappedEntry) == _OVERLAPPED_ENTRY_EXPECTED_SIZE
    @assert fieldoffset(OverlappedEntry, 4) == _OVERLAPPED_ENTRY_BYTES_OFFSET

    const IocpOnCompletionFn = Function

    mutable struct IocpOverlapped
        storage::Base.RefValue{IocpOverlappedHeader}
        on_completion::Union{Nothing, IocpOnCompletionFn}
        user_data::Any
        user_data_aux::Any
        active::Bool
    end

    function IocpOverlapped()
        op = IocpOverlapped(
            Ref(IocpOverlappedHeader(_ZERO_OVERLAPPED, C_NULL)),
            nothing,
            nothing,
            nothing,
            false,
        )
        op.storage[] = IocpOverlappedHeader(_ZERO_OVERLAPPED, pointer_from_objref(op))
        return op
    end

    function iocp_overlapped_init!(
            op::IocpOverlapped,
            on_completion::IocpOnCompletionFn,
            user_data,
        )::IocpOverlapped
        op.on_completion = on_completion
        op.user_data = user_data
        op.user_data_aux = nothing
        op.active = false
        op.storage[] = IocpOverlappedHeader(_ZERO_OVERLAPPED, pointer_from_objref(op))
        return op
    end

    function iocp_overlapped_init!(
            op::IocpOverlapped,
            on_completion::IocpOnCompletionFn,
            user_data,
            user_data_aux,
        )::IocpOverlapped
        op.on_completion = on_completion
        op.user_data = user_data
        op.user_data_aux = user_data_aux
        op.active = false
        op.storage[] = IocpOverlappedHeader(_ZERO_OVERLAPPED, pointer_from_objref(op))
        return op
    end

    function iocp_overlapped_reset!(op::IocpOverlapped)
        op.storage[] = IocpOverlappedHeader(_ZERO_OVERLAPPED, pointer_from_objref(op))
        return nothing
    end

    @inline function iocp_overlapped_ptr(op::IocpOverlapped)::Ptr{Cvoid}
        return Ptr{Cvoid}(Base.unsafe_convert(Ptr{IocpOverlappedHeader}, op.storage))
    end

    @inline function _win_get_last_error()::UInt32
        return ccall((:GetLastError, _KERNEL32), UInt32, ())
    end

    @inline function _win_close_handle(handle::Ptr{Cvoid})::Bool
        return ccall((:CloseHandle, _KERNEL32), Int32, (Ptr{Cvoid},), handle) != 0
    end

    @inline function _win_post_queued_completion_status(
            port::Ptr{Cvoid},
            num_bytes_transferred::UInt32,
            completion_key::UInt,
            overlapped::Ptr{Cvoid},
        )::Bool
        return ccall(
            (:PostQueuedCompletionStatus, _KERNEL32),
            Int32,
            (Ptr{Cvoid}, UInt32, UInt, Ptr{Cvoid}),
            port,
            num_bytes_transferred,
            completion_key,
            overlapped,
        ) != 0
    end

    @inline function _win_create_io_completion_port(
            file_handle::Ptr{Cvoid},
            existing_port::Ptr{Cvoid},
            completion_key::UInt,
            num_concurrent_threads::UInt32,
        )::Ptr{Cvoid}
        return ccall(
            (:CreateIoCompletionPort, _KERNEL32),
            Ptr{Cvoid},
            (Ptr{Cvoid}, Ptr{Cvoid}, UInt, UInt32),
            file_handle,
            existing_port,
            completion_key,
            num_concurrent_threads,
        )
    end

    @inline function _win_set_file_completion_notification_modes(handle::Ptr{Cvoid}, flags::UInt8)::Bool
        return ccall(
            (:SetFileCompletionNotificationModes, _KERNEL32),
            Int32,
            (Ptr{Cvoid}, UInt8),
            handle,
            flags,
        ) != 0
    end

    struct FILE_COMPLETION_INFORMATION
        Port::Ptr{Cvoid}
        Key::Ptr{Cvoid}
    end

    struct IO_STATUS_BLOCK
        status_ptr::UInt
        Information::UInt
    end

    const FileReplaceCompletionInformation = UInt32(0x3D)

    # Removes a handle's IOCP association.
    function _win_unsubscribe_handle_from_iocp(handle::Ptr{Cvoid})::Nothing
        info = Ref(FILE_COMPLETION_INFORMATION(C_NULL, C_NULL))
        status_block = Ref(IO_STATUS_BLOCK(UInt(0), UInt(0)))
        status = ccall(
            (:NtSetInformationFile, _NTDLL),
            Int32,
            (Ptr{Cvoid}, Ptr{IO_STATUS_BLOCK}, Ptr{FILE_COMPLETION_INFORMATION}, UInt32, UInt32),
            handle,
            status_block,
            info,
            UInt32(sizeof(FILE_COMPLETION_INFORMATION)),
            FileReplaceCompletionInformation,
        )
        if status == 0
            return nothing
        end
        throw_error(ERROR_SYS_CALL_FAILURE)
    end

    function _iocp_signal_synced_data_changed(event_loop::EventLoop)::Bool
        impl = event_loop.impl
        completion_key = UInt(impl.iocp_handle)
        ok = _win_post_queued_completion_status(impl.iocp_handle, UInt32(0), completion_key, C_NULL)
        if !ok
            logf(
                LogLevel.ERROR,
                LS_IO_EVENT_LOOP,string("PostQueuedCompletionStatus() failed with error %d", " ", _win_get_last_error(), " ", ))
            return false
        end
        return true
    end

    function event_loop_new_with_iocp()::EventLoop
        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "Initializing IO Completion Port event loop")

        impl = IocpEventLoop()

        # Create IOCP by passing INVALID_HANDLE_VALUE as FileHandle.
        iocp_handle = _win_create_io_completion_port(
            INVALID_HANDLE_VALUE,
            C_NULL,
            UInt(0),
            UInt32(1),
        )
        if iocp_handle == C_NULL
            logf(
                LogLevel.FATAL,
                LS_IO_EVENT_LOOP,string("CreateIoCompletionPort() failed with error %d", " ", _win_get_last_error(), " ", ))
            throw_error(ERROR_SYS_CALL_FAILURE)
        end
        impl.iocp_handle = iocp_handle

        return EventLoop(impl)
    end

    function _iocp_process_tasks_to_schedule(impl::IocpEventLoop, tasks::Vector{ScheduledTask})
        for task in tasks
            if task.timestamp == 0
                task_scheduler_schedule_now!(impl.thread_data.scheduler, task)
            else
                task_scheduler_schedule_future!(impl.thread_data.scheduler, task, task.timestamp)
            end
        end
        empty!(tasks)
        return nothing
    end

    function _iocp_process_synced_data(event_loop::EventLoop)
        impl = event_loop.impl

        tasks_to_schedule = impl.synced_data.tasks_to_schedule_spare
        lock(impl.synced_data.mutex)
        try
            impl.synced_data.thread_signaled = false

            initiate_stop = (impl.synced_data.state == IocpEventThreadState.STOPPING) &&
                (impl.thread_data.state == IocpEventThreadState.RUNNING)
            if initiate_stop
                impl.thread_data.state = IocpEventThreadState.STOPPING
            end

            pending = impl.synced_data.tasks_to_schedule
            spare = impl.synced_data.tasks_to_schedule_spare
            empty!(spare)
            impl.synced_data.tasks_to_schedule = spare
            impl.synced_data.tasks_to_schedule_spare = pending
            tasks_to_schedule = pending
        finally
            unlock(impl.synced_data.mutex)
        end

        _iocp_process_tasks_to_schedule(impl, tasks_to_schedule)
        return nothing
    end

    function _iocp_event_loop_thread(event_loop::EventLoop)
        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "main loop started")
        impl = event_loop.impl

        @atomic impl.running_thread_id = UInt64(Base.Threads.threadid())
        impl.thread_data.state = IocpEventThreadState.RUNNING
        notify(impl.startup_event)

        # Cal cleanup is handled in the thread entry finally block

        timeout_ms = DEFAULT_TIMEOUT_MS
        entries = Memory{OverlappedEntry}(undef, Int(MAX_COMPLETION_PACKETS_PER_LOOP))

        while impl.thread_data.state == IocpEventThreadState.RUNNING
            num_entries = Ref{UInt32}(0)
            should_process_synced_data = false

            ok = @ccall gc_safe = true _KERNEL32.GetQueuedCompletionStatusEx(
                impl.iocp_handle::Ptr{Cvoid},
                entries::Ptr{OverlappedEntry},
                MAX_COMPLETION_PACKETS_PER_LOOP::UInt32,
                num_entries::Ptr{UInt32},
                timeout_ms::UInt32,
                0::Int32, # Alertable = false
            )::Int32

            register_tick_start!(event_loop)

            if ok != 0
                count = Int(num_entries[])
                for i in 1:count
                    entry = entries[i]

                    # Special completion packet signals cross-thread changes.
                    if entry.lpCompletionKey == UInt(impl.iocp_handle)
                        should_process_synced_data = true
                        continue
                    end

                    ov_ptr = entry.lpOverlapped
                    ov_ptr == C_NULL && continue

                    hdr = unsafe_load(Ptr{IocpOverlappedHeader}(ov_ptr))
                    op = unsafe_pointer_to_objref(hdr.objref)::IocpOverlapped
                    cb = op.on_completion
                    cb === nothing && continue

                    # `Internal` carries an NTSTATUS-style status code (0 on success).
                    status_code = _iocp_normalize_status_code(entry.Internal)
                    bytes = Csize_t(entry.dwNumberOfBytesTransferred)
                    try
                        cb(event_loop, op, status_code, bytes)
                    catch e
                        logf(
                            LogLevel.ERROR,
                            LS_IO_EVENT_LOOP,
                            "unhandled IOCP completion callback exception on fd ",
                            Int(impl.iocp_handle),
                            ": ",
                            e,
                            " ",
                        )
                    end
                end
            else
                win_err = _win_get_last_error()
                if win_err == WAIT_TIMEOUT
                    # Timeout is a normal condition.
                elseif win_err == ERROR_ABANDONED_WAIT_0
                    logf(LogLevel.ERROR, LS_IO_EVENT_LOOP, "GetQueuedCompletionStatusEx() abandoned; completion port is closed")
                    impl.thread_data.state = IocpEventThreadState.STOPPING
                    register_tick_end!(event_loop)
                    break
                else
                    logf(
                        LogLevel.ERROR,
                        LS_IO_EVENT_LOOP,string("GetQueuedCompletionStatusEx() failed with error %d", " ", win_err, " ", ))
                end
            end

            if should_process_synced_data
                _iocp_process_synced_data(event_loop)
            end

            if @atomic event_loop.should_stop
                impl.thread_data.state = IocpEventThreadState.STOPPING
                register_tick_end!(event_loop)
                break
            end

            # Run scheduled tasks.
            now_ns = try
                clock_now_ns()
            catch
                UInt64(0)
            end
            task_scheduler_run_all!(impl.thread_data.scheduler, now_ns)

            # Compute next timeout.
            use_default_timeout = false
            now2 = try
                clock_now_ns()
            catch
                use_default_timeout = true
                UInt64(0)
            end

            has_tasks, next_run_time = task_scheduler_has_tasks(impl.thread_data.scheduler)
            if !has_tasks
                use_default_timeout = true
            end

            if use_default_timeout
                timeout_ms = DEFAULT_TIMEOUT_MS
            else
                timeout_ns = next_run_time > now2 ? (next_run_time - now2) : UInt64(0)
                timeout_ms64 = timeout_ns ÷ UInt64(1_000_000)
                timeout_ms = timeout_ms64 > typemax(UInt32) ? typemax(UInt32) : UInt32(timeout_ms64)
            end

            register_tick_end!(event_loop)
        end

        logf(LogLevel.DEBUG, LS_IO_EVENT_LOOP, "exiting main loop")
        return nothing
    end

    function run!(event_loop::EventLoop, impl::IocpEventLoop)::Nothing
        impl = event_loop.impl

        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "starting event-loop thread")

        # Thread startup synchronization (avoid libuv-backed `sleep`/`time_ns` polling).
        impl.startup_event = Base.Threads.Event()
        impl.completion_event = Base.Threads.Event()
        @atomic impl.startup_error = 0
        @atomic impl.running_thread_id = UInt64(0)

        if impl.synced_data.state != IocpEventThreadState.READY_TO_RUN
            throw_error(ERROR_INVALID_STATE)
        end
        if impl.thread_data.state != IocpEventThreadState.READY_TO_RUN
            throw_error(ERROR_INVALID_STATE)
        end

        @atomic event_loop.should_stop = false
        impl.synced_data.state = IocpEventThreadState.RUNNING

        # Launch the event loop thread via ForeignThread
        try
            impl.thread_created_on = ForeignThread(
                "aws-el-iocp",
                _IOCP_THREAD_ENTRY_C,
                event_loop;
                join_strategy = ThreadJoinStrategy.MANUAL,
            )
        catch
            impl.synced_data.state = IocpEventThreadState.READY_TO_RUN
            logf(LogLevel.FATAL, LS_IO_EVENT_LOOP, "thread creation failed")
            throw_error(ERROR_THREAD_NO_SUCH_THREAD_ID)
        end

        event_loop.thread = impl.thread_created_on
        @atomic event_loop.running = true

        wait(impl.startup_event)
        startup_error = @atomic impl.startup_error
        if startup_error != 0 || (@atomic impl.running_thread_id) == 0
            if impl.thread_created_on !== nothing
                wait(impl.completion_event)
            end
            impl.synced_data.state = IocpEventThreadState.READY_TO_RUN
            impl.thread_data.state = IocpEventThreadState.READY_TO_RUN
            @atomic event_loop.running = false
            @atomic event_loop.should_stop = false
            throw_error(startup_error != 0 ? startup_error : ERROR_IO_EVENT_LOOP_SHUTDOWN)
        end

        return nothing
    end

    function stop!(event_loop::EventLoop, impl::IocpEventLoop)::Nothing
        impl = event_loop.impl
        @atomic event_loop.should_stop = true

        if event_loop_thread_is_callers_thread(event_loop)
            impl.thread_data.state = IocpEventThreadState.STOPPING
            return nothing
        end

        signal_thread = false
        lock(impl.synced_data.mutex)
        try
            if impl.synced_data.state == IocpEventThreadState.RUNNING
                impl.synced_data.state = IocpEventThreadState.STOPPING
            end

            if impl.synced_data.state == IocpEventThreadState.STOPPING
                # Always wake the thread so it can observe the stop request.
                impl.synced_data.thread_signaled = true
                signal_thread = true
            end
        finally
            unlock(impl.synced_data.mutex)
        end

        if signal_thread
            signaled = _iocp_signal_synced_data_changed(event_loop)
            if !signaled
                lock(impl.synced_data.mutex)
                try
                    impl.synced_data.thread_signaled = false
                finally
                    unlock(impl.synced_data.mutex)
                end
            end
        end

        return nothing
    end

    function wait_for_stop_completion(event_loop::EventLoop, impl::IocpEventLoop)::Nothing
        impl = event_loop.impl

        if impl.thread_created_on !== nothing
            wait(impl.completion_event)
        end

        impl.synced_data.state = IocpEventThreadState.READY_TO_RUN
        impl.thread_data.state = IocpEventThreadState.READY_TO_RUN
        @atomic event_loop.running = false
        @atomic event_loop.should_stop = false
        return nothing
    end

    function schedule_task_now!(event_loop::EventLoop, impl::IocpEventLoop, task::ScheduledTask)
        _iocp_schedule_task_common(event_loop, task, UInt64(0); serialized = false)
        return nothing
    end

    function schedule_task_now_serialized!(event_loop::EventLoop, impl::IocpEventLoop, task::ScheduledTask)
        _iocp_schedule_task_common(event_loop, task, UInt64(0); serialized = true)
        return nothing
    end

    function schedule_task_future!(event_loop::EventLoop, impl::IocpEventLoop, task::ScheduledTask, run_at_nanos::UInt64)
        _iocp_schedule_task_common(event_loop, task, run_at_nanos; serialized = false)
        return nothing
    end

    function _iocp_schedule_task_common(
            event_loop::EventLoop,
            task::ScheduledTask,
            run_at_nanos::UInt64;
            serialized::Bool,
        )
        impl = event_loop.impl

        if !serialized && event_loop_thread_is_callers_thread(event_loop)
            if run_at_nanos == 0
                task_scheduler_schedule_now!(impl.thread_data.scheduler, task)
            else
                task_scheduler_schedule_future!(impl.thread_data.scheduler, task, run_at_nanos)
            end
            return nothing
        end

        task.timestamp = run_at_nanos
        task.scheduled = true

        should_signal = false
        lock(impl.synced_data.mutex)
        try
            push!(impl.synced_data.tasks_to_schedule, task)
            if !impl.synced_data.thread_signaled
                impl.synced_data.thread_signaled = true
                should_signal = true
            end
        finally
            unlock(impl.synced_data.mutex)
        end

        if should_signal
            signaled = _iocp_signal_synced_data_changed(event_loop)
            if !signaled
                lock(impl.synced_data.mutex)
                try
                    impl.synced_data.thread_signaled = false
                finally
                    unlock(impl.synced_data.mutex)
                end
            end
        end

        return nothing
    end

    function cancel_task!(event_loop::EventLoop, impl::IocpEventLoop, task::ScheduledTask)
        debug_assert(event_loop_thread_is_callers_thread(event_loop))
        impl = event_loop.impl
        if !task.scheduled
            return nothing
        end

        removed = false
        lock(impl.synced_data.mutex)
        try
            if !isempty(impl.synced_data.tasks_to_schedule)
                idx = findfirst(x -> x === task, impl.synced_data.tasks_to_schedule)
                if idx !== nothing
                    deleteat!(impl.synced_data.tasks_to_schedule, idx)
                    removed = true
                end
            end
        finally
            unlock(impl.synced_data.mutex)
        end

        if removed
            task_run!(task, TaskStatus.CANCELED)
            return nothing
        end

        task_scheduler_cancel!(impl.thread_data.scheduler, task)
        return nothing
    end

    function event_loop_thread_is_callers_thread(event_loop::EventLoop, impl::IocpEventLoop)::Bool
        impl = event_loop.impl
        running_id = @atomic impl.running_thread_id
        return running_id != 0 && running_id == UInt64(Base.Threads.threadid())
    end

    function connect_to_io_completion_port(
            event_loop::EventLoop,
            impl::IocpEventLoop,
            handle::IoHandle,
        )::Nothing
        _ = event_loop

        if handle.handle == C_NULL
            throw_error(ERROR_INVALID_ARGUMENT)
        end

        iocp_handle = _win_create_io_completion_port(
            handle.handle,
            impl.iocp_handle,
            UInt(0),
            UInt32(1),
        )

        associated = iocp_handle == impl.iocp_handle

        # On older Windows, associating an already-associated handle may return INVALID_PARAMETER but
        # the association remains valid. Accept this case to match aws-c-io behavior.
        if !associated && _win_get_last_error() == ERROR_INVALID_PARAMETER &&
                handle.handle != INVALID_HANDLE_VALUE && impl.iocp_handle != INVALID_HANDLE_VALUE
            associated = true
        end

        if !associated
            logf(
                LogLevel.ERROR,
                LS_IO_EVENT_LOOP,string("CreateIoCompletionPort() failed with error %d", " ", _win_get_last_error(), " ", ))
            throw_error(ERROR_SYS_CALL_FAILURE)
        end

        _ = _win_set_file_completion_notification_modes(handle.handle, FILE_SKIP_SET_EVENT_ON_HANDLE)

        handle.additional_data = C_NULL
        handle.additional_ref = nothing

        return nothing
    end

    function subscribe_to_io_events!(
            event_loop::EventLoop,
            impl::IocpEventLoop,
            handle::IoHandle,
            events::Int,
            on_event::EventCallable,
        )::Nothing
        _ = event_loop
        _ = handle
        _ = events
        _ = on_event
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    function unsubscribe_from_io_events!(
            event_loop::EventLoop,
            impl::IocpEventLoop,
            handle::IoHandle,
        )::Nothing
        _ = event_loop
        if handle.handle == C_NULL
            throw_error(ERROR_IO_NOT_SUBSCRIBED)
        end
        return _win_unsubscribe_handle_from_iocp(handle.handle)
    end

    function close(event_loop::EventLoop, impl::IocpEventLoop)
        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "destroying event_loop")
        impl = event_loop.impl

        destroy_error = nothing

        try
            stop!(event_loop)
            wait_for_stop_completion(event_loop)

            # Make cancellation callbacks that check `event_loop_thread_is_callers_thread` behave.
            impl.thread_joined_to = UInt64(Base.Threads.threadid())
            @atomic impl.running_thread_id = impl.thread_joined_to

            try
                task_scheduler_clean_up!(impl.thread_data.scheduler)
            catch e
                logf(LogLevel.ERROR, LS_IO_EVENT_LOOP, "task scheduler cleanup errored during destroy: $e")
                destroy_error = destroy_error === nothing ? e : destroy_error
            end

            lock(impl.synced_data.mutex)
            tasks = impl.synced_data.tasks_to_schedule
            impl.synced_data.tasks_to_schedule = ScheduledTask[]
            unlock(impl.synced_data.mutex)

            for task in tasks
                try
                    task_run!(task, TaskStatus.CANCELED)
                catch e
                    logf(LogLevel.ERROR, LS_IO_EVENT_LOOP, "task cancellation callback errored during destroy: $e")
                    destroy_error = destroy_error === nothing ? e : destroy_error
                end
            end
            empty!(tasks)
        catch e
            logf(LogLevel.ERROR, LS_IO_EVENT_LOOP, "iocp event-loop destroy failed: $e")
            destroy_error = destroy_error === nothing ? e : destroy_error
        finally
            if impl.iocp_handle != C_NULL
                _ = _win_close_handle(impl.iocp_handle)
                impl.iocp_handle = C_NULL
            end
        end

        if destroy_error !== nothing
            throw(destroy_error)
        end
        return nothing
    end

end # @static if Sys.iswindows()
