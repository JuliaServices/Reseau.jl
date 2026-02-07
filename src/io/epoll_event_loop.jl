# AWS IO Library - Epoll Event Loop Implementation
# Port of aws-c-io/source/linux/epoll_event_loop.c
# Type definitions are in epoll_event_loop_types.jl

@static if Sys.islinux()
    using LibAwsCal

    # Helper to check if eventfd is available and create one
    function try_create_eventfd()::Union{Int32, Nothing}
        fd = @ccall eventfd(0::Cuint, (EFD_CLOEXEC | EFD_NONBLOCK)::Cint)::Cint
        if fd >= 0
            return Int32(fd)
        end
        return nothing
    end

    # Helper to open a non-blocking pipe
    function open_nonblocking_posix_pipe()::Union{NTuple{2, Int32}, ErrorResult}
        pipe_fds = Ref{NTuple{2, Int32}}((Int32(-1), Int32(-1)))

        ret = @ccall pipe(pipe_fds::Ptr{Int32})::Cint
        if ret != 0
            return ErrorResult(raise_error(ERROR_SYS_CALL_FAILURE))
        end

        read_fd = pipe_fds[][1]
        write_fd = pipe_fds[][2]

        # Set non-blocking on both ends
        for fd in (read_fd, write_fd)
            flags = _fcntl(fd, Cint(3))  # F_GETFL = 3
            if flags == -1
                @ccall close(read_fd::Cint)::Cint
                @ccall close(write_fd::Cint)::Cint
                return ErrorResult(raise_error(ERROR_SYS_CALL_FAILURE))
            end
            ret = _fcntl(fd, Cint(4), (flags | O_NONBLOCK))  # F_SETFL = 4
            if ret == -1
                @ccall close(read_fd::Cint)::Cint
                @ccall close(write_fd::Cint)::Cint
                return ErrorResult(raise_error(ERROR_SYS_CALL_FAILURE))
            end
            fd_flags = _fcntl(fd, Cint(1))  # F_GETFD = 1
            if fd_flags == -1
                @ccall close(read_fd::Cint)::Cint
                @ccall close(write_fd::Cint)::Cint
                return ErrorResult(raise_error(ERROR_SYS_CALL_FAILURE))
            end
            ret = _fcntl(fd, Cint(2), (fd_flags | Cint(1)))  # F_SETFD = 2, FD_CLOEXEC = 1
            if ret == -1
                @ccall close(read_fd::Cint)::Cint
                @ccall close(write_fd::Cint)::Cint
                return ErrorResult(raise_error(ERROR_SYS_CALL_FAILURE))
            end
        end

        return (read_fd, write_fd)
    end

    # Create a new epoll event loop
    function event_loop_new_with_epoll(
            options::EventLoopOptions,
        )::Union{EventLoop, ErrorResult}
        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "Initializing edge-triggered epoll event loop")

        impl = EpollEventLoop()

        if options.thread_options !== nothing
            impl.thread_options = options.thread_options
        end

        # Create epoll instance
        epoll_fd = @ccall epoll_create(100::Cint)::Cint
        if epoll_fd < 0
            logf(LogLevel.FATAL, LS_IO_EVENT_LOOP, "Failed to open epoll handle")
            return ErrorResult(raise_error(ERROR_SYS_CALL_FAILURE))
        end
        impl.epoll_fd = Int32(epoll_fd)

        # Try to use eventfd first, fall back to pipe
        eventfd_result = try_create_eventfd()
        if eventfd_result !== nothing
            logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "Using eventfd for cross-thread notifications")
            impl.use_eventfd = true
            impl.write_task_handle = IoHandle(eventfd_result)
            impl.read_task_handle = IoHandle(eventfd_result)  # Same fd for eventfd
            logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "eventfd descriptor %d", eventfd_result)
        else
            logf(LogLevel.DEBUG, LS_IO_EVENT_LOOP, "Eventfd not available, falling back to pipe")
            impl.use_eventfd = false

            pipe_result = open_nonblocking_posix_pipe()
            if pipe_result isa ErrorResult
                @ccall close(epoll_fd::Cint)::Cint
                logf(LogLevel.FATAL, LS_IO_EVENT_LOOP, "Failed to open pipe handle")
                return pipe_result
            end

            logf(
                LogLevel.TRACE,
                LS_IO_EVENT_LOOP,
                "pipe descriptors read %d, write %d",
                pipe_result[READ_FD],
                pipe_result[WRITE_FD],
            )
            impl.read_task_handle = IoHandle(pipe_result[READ_FD])
            impl.write_task_handle = IoHandle(pipe_result[WRITE_FD])
        end

        impl.should_continue = false

        # Create the event loop
        event_loop = EventLoop(options.clock, impl)
        event_loop.base_elg = options.parent_elg

        return event_loop
    end

    # Stop task callback
    function epoll_stop_task_callback(event_loop::EventLoop, status::TaskStatus.T)
        impl = event_loop.impl_data

        # Now okay to reschedule stop tasks
        @atomic impl.stop_task_scheduled = false

        if status == TaskStatus.RUN_READY
            impl.should_continue = false
        end

        return nothing
    end

    # Run the event loop
    function event_loop_run!(event_loop::EventLoop)::Union{Nothing, ErrorResult}
        impl = event_loop.impl_data

        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "Starting event-loop thread")

        impl.should_continue = true

        # Thread startup synchronization (avoid libuv-backed `sleep`/`time_ns` polling).
        impl.startup_event = Threads.Event()
        @atomic impl.startup_error = 0
        @atomic impl.running_thread_id = UInt64(0)

        # Launch the event loop thread
        thread_fn = el -> epoll_event_loop_thread(el)
        impl.thread_created_on = ThreadHandle()
        thread_options = thread_options_with_defaults(impl.thread_options; name = "aws-el-epoll")

        result = thread_launch(impl.thread_created_on, thread_fn, event_loop, thread_options)
        if result != OP_SUCCESS
            logf(LogLevel.FATAL, LS_IO_EVENT_LOOP, "thread creation failed")
            impl.should_continue = false
            return ErrorResult(last_error())
        end

        event_loop.thread = impl.thread_created_on
        @atomic event_loop.running = true

        wait(impl.startup_event)
        startup_error = @atomic impl.startup_error
        if startup_error != 0 || (@atomic impl.running_thread_id) == 0
            return ErrorResult(raise_error(startup_error != 0 ? startup_error : ERROR_IO_EVENT_LOOP_SHUTDOWN))
        end

        return nothing
    end

    # Stop the event loop
    function event_loop_stop!(event_loop::EventLoop)::Union{Nothing, ErrorResult}
        impl = event_loop.impl_data

        # Use atomic CAS to ensure stop task is only scheduled once
        expected = false
        if !(@atomicreplace impl.stop_task_scheduled expected => true).success
            # Stop task already scheduled
            return nothing
        end

        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "Stopping event-loop thread")

        # Create and schedule stop task
        stop_fn = (ctx, status) -> epoll_stop_task_callback(ctx, status)
        impl.stop_task = ScheduledTask(stop_fn, event_loop; type_tag = "epoll_event_loop_stop")
        event_loop_schedule_task_now!(event_loop, impl.stop_task)

        return nothing
    end

    # Wait for the event loop to stop
    function event_loop_wait_for_stop_completion!(event_loop::EventLoop)::Union{Nothing, ErrorResult}
        impl = event_loop.impl_data

        if impl.thread_created_on !== nothing
            result = thread_join(impl.thread_created_on)
            if result != OP_SUCCESS
                return ErrorResult(last_error())
            end
        end

        @atomic event_loop.running = false

        return nothing
    end

    # Schedule task cross-thread
    function schedule_task_cross_thread(event_loop::EventLoop, task::ScheduledTask, run_at_nanos::UInt64)
        impl = event_loop.impl_data

        logf(
            LogLevel.TRACE,
            LS_IO_EVENT_LOOP,
            "Scheduling %s task cross-thread for timestamp %d",
            task.type_tag,
            run_at_nanos,
        )

        task.timestamp = run_at_nanos
        task.scheduled = true

        lock(impl.task_pre_queue_mutex)

        is_first_task = isempty(impl.task_pre_queue)
        push!(impl.task_pre_queue, task)

        # If the list was not empty, we already have a pending read on the pipe/eventfd
        if is_first_task
            logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "Waking up event-loop thread")
            # Write to signal the event thread
            counter = Ref(UInt64(1))
            @ccall write(impl.write_task_handle.fd::Cint, counter::Ptr{UInt64}, sizeof(UInt64)::Csize_t)::Cssize_t
        end

        unlock(impl.task_pre_queue_mutex)

        return nothing
    end

    # Schedule task common implementation
    function schedule_task_common(event_loop::EventLoop, task::ScheduledTask, run_at_nanos::UInt64)
        impl = event_loop.impl_data

        # If we're on the event thread, schedule directly
        if event_loop_thread_is_callers_thread(event_loop)
            logf(
                LogLevel.TRACE,
                LS_IO_EVENT_LOOP,
                "scheduling %s task in-thread for timestamp %d",
                task.type_tag,
                run_at_nanos,
            )
            if run_at_nanos == 0
                task_scheduler_schedule_now!(impl.scheduler, task)
            else
                task_scheduler_schedule_future!(impl.scheduler, task, run_at_nanos)
            end
            return nothing
        end

        # Otherwise, add to cross-thread queue
        schedule_task_cross_thread(event_loop, task, run_at_nanos)
        return nothing
    end

    # Schedule task now
    function event_loop_schedule_task_now!(event_loop::EventLoop, task::ScheduledTask)
        schedule_task_common(event_loop, task, UInt64(0))
    end

    # Schedule task now (serialized - always goes cross-thread)
    function event_loop_schedule_task_now_serialized!(event_loop::EventLoop, task::ScheduledTask)
        schedule_task_cross_thread(event_loop, task, UInt64(0))
    end

    # Schedule task future
    function event_loop_schedule_task_future!(event_loop::EventLoop, task::ScheduledTask, run_at_nanos::UInt64)
        schedule_task_common(event_loop, task, run_at_nanos)
    end

    # Cancel task
    function event_loop_cancel_task!(event_loop::EventLoop, task::ScheduledTask)
        debug_assert(event_loop_thread_is_callers_thread(event_loop))
        impl = event_loop.impl_data
        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "cancelling %s task", task.type_tag)
        if !task.scheduled
            return nothing
        end

        removed = false
        lock(impl.task_pre_queue_mutex)
        if !isempty(impl.task_pre_queue)
            idx = findfirst(x -> x === task, impl.task_pre_queue)
            if idx !== nothing
                deleteat!(impl.task_pre_queue, idx)
                removed = true
            end
        end
        unlock(impl.task_pre_queue_mutex)

        if removed
            task_run!(task, TaskStatus.CANCELED)
            return nothing
        end

        task_scheduler_cancel!(impl.scheduler, task)
    end

    # Check if on event thread
    function event_loop_thread_is_callers_thread(event_loop::EventLoop)::Bool
        impl = event_loop.impl_data
        running_id = @atomic impl.running_thread_id
        return running_id != 0 && running_id == thread_current_thread_id()
    end

    # Subscribe to IO events
    function event_loop_subscribe_to_io_events!(
            event_loop::EventLoop,
            handle::IoHandle,
            events::Int,
            on_event::OnEventCallback,
            user_data,
        )::Union{Nothing, ErrorResult}
        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "subscribing to events on fd %d", handle.fd)

        epoll_event_data = EpollEventHandleData(handle, on_event, user_data)

        # Store handle data reference
        handle.additional_data = pointer_from_objref(epoll_event_data)
        handle.additional_ref = epoll_event_data

        impl = event_loop.impl_data

        # Build event mask - everyone is always registered for edge-triggered, hang up, remote hang up, errors
        event_mask = EPOLLET | EPOLLHUP | EPOLLRDHUP | EPOLLERR

        if (events & Int(IoEventType.READABLE)) != 0
            event_mask |= EPOLLIN
        end

        if (events & Int(IoEventType.WRITABLE)) != 0
            event_mask |= EPOLLOUT
        end

        # Create epoll_event struct
        epoll_ev = EpollEvent(event_mask, handle.additional_data)
        epoll_ev_ref = Ref(epoll_ev)

        ret = @ccall epoll_ctl(
            impl.epoll_fd::Cint,
            EPOLL_CTL_ADD::Cint,
            handle.fd::Cint,
            epoll_ev_ref::Ptr{EpollEvent},
        )::Cint

        if ret != 0
            logf(LogLevel.ERROR, LS_IO_EVENT_LOOP, "failed to subscribe to events on fd %d", handle.fd)
            handle.additional_data = C_NULL
            handle.additional_ref = nothing
            return ErrorResult(raise_error(ERROR_SYS_CALL_FAILURE))
        end

        return nothing
    end

    # Free IO event resources
    function event_loop_free_io_event_resources!(event_loop::EventLoop, handle::IoHandle)
        return nothing
    end

    # Cleanup task callback
    function epoll_unsubscribe_cleanup_task_callback(event_data::EpollEventHandleData, status::TaskStatus.T)
        return nothing
    end

    # Unsubscribe from IO events
    function event_loop_unsubscribe_from_io_events!(
            event_loop::EventLoop,
            handle::IoHandle,
        )::Union{Nothing, ErrorResult}
        debug_assert(event_loop_thread_is_callers_thread(event_loop))
        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "un-subscribing from events on fd %d", handle.fd)

        impl = event_loop.impl_data

        if handle.additional_data == C_NULL
            return ErrorResult(raise_error(ERROR_IO_NOT_SUBSCRIBED))
        end

        event_data = unsafe_pointer_to_objref(handle.additional_data)::EpollEventHandleData

        # Remove from epoll - use a dummy event (required by older kernels)
        dummy_event = EpollEvent(UInt32(0), C_NULL)
        dummy_ref = Ref(dummy_event)

        ret = @ccall epoll_ctl(
            impl.epoll_fd::Cint,
            EPOLL_CTL_DEL::Cint,
            handle.fd::Cint,
            dummy_ref::Ptr{EpollEvent},
        )::Cint

        if ret != 0
            logf(LogLevel.ERROR, LS_IO_EVENT_LOOP, "failed to un-subscribe from events on fd %d", handle.fd)
            return ErrorResult(raise_error(ERROR_SYS_CALL_FAILURE))
        end

        # Mark as unsubscribed and schedule cleanup task
        event_data.is_subscribed = false

        cleanup_fn = (ctx, status) -> epoll_unsubscribe_cleanup_task_callback(ctx, status)
        event_data.cleanup_task = ScheduledTask(cleanup_fn, event_data; type_tag = "epoll_event_loop_unsubscribe_cleanup")
        event_loop_schedule_task_now!(event_loop, event_data.cleanup_task)

        handle.additional_data = C_NULL
        handle.additional_ref = nothing

        return nothing
    end

    # Callback for cross-thread task pipe/eventfd
    function on_tasks_to_schedule(event_loop::EventLoop, handle::IoHandle, events::Int, user_data)
        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "notified of cross-thread tasks to schedule")
        impl = event_loop.impl_data

        if (events & Int(IoEventType.READABLE)) != 0
            impl.should_process_task_pre_queue = true
        end

        return nothing
    end

    # Process cross-thread task queue
    function process_task_pre_queue(event_loop::EventLoop)
        impl = event_loop.impl_data

        if !impl.should_process_task_pre_queue
            return nothing
        end

        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "processing cross-thread tasks")
        impl.should_process_task_pre_queue = false

        count_ignore = Ref(UInt64(0))

        lock(impl.task_pre_queue_mutex)

        # Drain the eventfd/pipe
        while true
            read_bytes = @ccall read(
                impl.read_task_handle.fd::Cint,
                count_ignore::Ptr{UInt64},
                sizeof(UInt64)::Csize_t,
            )::Cssize_t
            read_bytes < 0 && break
        end

        # Swap pre-queue contents to minimize lock hold time
        tasks_to_schedule = impl.task_pre_queue
        impl.task_pre_queue = ScheduledTask[]

        unlock(impl.task_pre_queue_mutex)

        # Schedule the tasks
        while !isempty(tasks_to_schedule)
            task = popfirst!(tasks_to_schedule)
            task === nothing && break
            logf(
                LogLevel.TRACE,
                LS_IO_EVENT_LOOP,
                "task %s pulled to event-loop, scheduling now",
                task.type_tag,
            )
            if task.timestamp == 0
                task_scheduler_schedule_now!(impl.scheduler, task)
            else
                task_scheduler_schedule_future!(impl.scheduler, task, task.timestamp)
            end
        end

        return nothing
    end

    # Main event loop thread function
    function epoll_event_loop_thread(event_loop::EventLoop)
        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "main loop started")
        impl = event_loop.impl_data

        # Set running thread ID
        @atomic impl.running_thread_id = thread_current_thread_id()

        # Subscribe to events on the read task handle for cross-thread notifications.
        # Signal `startup_event` once subscription is complete.
        err = event_loop_subscribe_to_io_events!(
            event_loop,
            impl.read_task_handle,
            Int(IoEventType.READABLE),
            on_tasks_to_schedule,
            nothing,
        )
        if err isa ErrorResult
            logf(LogLevel.ERROR, LS_IO_EVENT_LOOP, "failed to subscribe to task notification events")
            @atomic impl.startup_error = ERROR_SYS_CALL_FAILURE
            notify(impl.startup_event)
            @atomic impl.running_thread_id = UInt64(0)
            return nothing
        end
        notify(impl.startup_event)

        _ = thread_current_at_exit(() -> LibAwsCal.aws_cal_thread_clean_up())

        timeout = DEFAULT_TIMEOUT_MS
        events = Memory{EpollEvent}(undef, MAX_EVENTS)

        logf(
            LogLevel.INFO,
            LS_IO_EVENT_LOOP,
            "default timeout %d ms, and max events to process per tick %d",
            timeout,
            MAX_EVENTS,
        )

        while impl.should_continue
            logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "waiting for a maximum of %d ms", timeout)

            # Call epoll_wait
            event_count = @ccall gc_safe = true epoll_wait(
                impl.epoll_fd::Cint,
                events::Ptr{EpollEvent},
                MAX_EVENTS::Cint,
                timeout::Cint,
            )::Cint

            event_loop_register_tick_start!(event_loop)

            logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "wake up with %d events to process", event_count)

            # Process events
            if event_count > 0
                tracing_task_begin(tracing_event_loop_events)
            end
            for i in 1:event_count
                tracing_task_begin(tracing_event_loop_event)
                try
                    ev = events[i]
                    event_data_ptr = _epoll_event_data_ptr(ev)

                    if event_data_ptr == C_NULL
                        continue
                    end

                    event_data = unsafe_pointer_to_objref(event_data_ptr)::EpollEventHandleData

                    # Convert epoll events to our event mask
                    event_mask = 0

                    if (ev.events & EPOLLIN) != 0
                        event_mask |= Int(IoEventType.READABLE)
                    end

                    if (ev.events & EPOLLOUT) != 0
                        event_mask |= Int(IoEventType.WRITABLE)
                    end

                    if (ev.events & EPOLLRDHUP) != 0
                        event_mask |= Int(IoEventType.REMOTE_HANG_UP)
                    end

                    if (ev.events & EPOLLHUP) != 0
                        event_mask |= Int(IoEventType.CLOSED)
                    end

                    if (ev.events & EPOLLERR) != 0
                        event_mask |= Int(IoEventType.ERROR)
                    end

                    if event_data.is_subscribed
                        logf(
                            LogLevel.TRACE,
                            LS_IO_EVENT_LOOP,
                            "activity on fd %d, invoking handler",
                            event_data.handle.fd,
                        )
                        Base.invokelatest(
                            event_data.on_event,
                            event_loop,
                            event_data.handle,
                            event_mask,
                            event_data.user_data,
                        )
                    end
                finally
                    tracing_task_end(tracing_event_loop_event)
                end
            end
            if event_count > 0
                tracing_task_end(tracing_event_loop_events)
            end

            # Process cross-thread tasks
            process_task_pre_queue(event_loop)

            # Run scheduled tasks
            now_ns_result = event_loop.clock()
            now_ns = now_ns_result isa ErrorResult ? UInt64(0) : now_ns_result

            logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "running scheduled tasks")
            tracing_task_begin(tracing_event_loop_run_tasks)
            try
                task_scheduler_run_all!(impl.scheduler, now_ns)
            finally
                tracing_task_end(tracing_event_loop_run_tasks)
            end

            # Calculate next timeout
            use_default_timeout = false

            now_ns_result = event_loop.clock()
            if now_ns_result isa ErrorResult
                use_default_timeout = true
            else
                now_ns = now_ns_result
            end

            has_tasks, next_run_time = task_scheduler_has_tasks(impl.scheduler)
            if !has_tasks
                use_default_timeout = true
            end

            if use_default_timeout
                logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "no more scheduled tasks using default timeout")
                timeout = DEFAULT_TIMEOUT_MS
            else
                # Translate timestamp (in nanoseconds) to timeout (in milliseconds)
                timeout_ns = next_run_time > now_ns ? next_run_time - now_ns : UInt64(0)
                timeout_ms = timeout_ns ÷ 1_000_000

                if timeout_ms > typemax(Cint)
                    timeout_ms = typemax(Cint)
                end

                logf(
                    LogLevel.TRACE,
                    LS_IO_EVENT_LOOP,
                    "detected more scheduled tasks with the next occurring at %d ns, using timeout of %d ms",
                    timeout_ns,
                    timeout_ms,
                )
                timeout = Cint(timeout_ms)
            end

            event_loop_register_tick_end!(event_loop)
        end

        logf(LogLevel.DEBUG, LS_IO_EVENT_LOOP, "exiting main loop")

        # Unsubscribe from the task notification events
        event_loop_unsubscribe_from_io_events!(event_loop, impl.read_task_handle)

        # Set thread ID back to NULL
        @atomic impl.running_thread_id = UInt64(0)

        return nothing
    end

    # Destroy epoll event loop
    function event_loop_complete_destroy!(event_loop::EventLoop)
        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "destroying event_loop")
        impl = event_loop.impl_data

        # Stop and wait
        event_loop_stop!(event_loop)
        event_loop_wait_for_stop_completion!(event_loop)

        # Set thread ID for cancellation callbacks
        impl.thread_joined_to = thread_current_thread_id()
        @atomic impl.running_thread_id = impl.thread_joined_to

        # Clean up scheduler (cancels remaining tasks)
        task_scheduler_clean_up!(impl.scheduler)

        # Cancel tasks in pre-queue
        while !isempty(impl.task_pre_queue)
            task = popfirst!(impl.task_pre_queue)
            if task !== nothing
                task_run!(task, TaskStatus.CANCELED)
            end
        end

        # Close file descriptors
        if impl.use_eventfd
            @ccall close(impl.write_task_handle.fd::Cint)::Cint
        else
            @ccall close(impl.read_task_handle.fd::Cint)::Cint
            @ccall close(impl.write_task_handle.fd::Cint)::Cint
        end

        @ccall close(impl.epoll_fd::Cint)::Cint

        # Clean up local data (invokes on_object_removed callbacks)
        for (_, obj) in event_loop.local_data
            _event_loop_local_object_destroy(obj)
        end
        empty!(event_loop.local_data)

        return nothing
    end

end # @static if Sys.islinux()
