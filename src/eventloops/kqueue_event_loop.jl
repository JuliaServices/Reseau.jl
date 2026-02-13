# AWS IO Library - KQueue Event Loop Implementation
# Port of aws-c-io/source/bsd/kqueue_event_loop.c
# Type definitions are in kqueue_event_loop_types.jl

@static if Sys.isapple() || Sys.isbsd()
    using LibAwsCal

    # Channel-based rendezvous for passing EventLoop to the thread function.
    const _KQUEUE_THREAD_STARTUP = Channel{Any}(1)

    # Thread entry point for the kqueue event loop.
    @wrap_thread_fn function _kqueue_event_loop_thread_entry()
        event_loop = take!(_KQUEUE_THREAD_STARTUP)::EventLoop
        try
            kqueue_event_loop_thread(event_loop)
        catch e
            Core.println("kqueue event loop thread errored")
        finally
            impl = event_loop.impl_data
            notify(impl.completion_event)
            managed_thread_finished!()
        end
    end

    const _KQUEUE_THREAD_ENTRY_C = Ref{Ptr{Cvoid}}(C_NULL)

    function _kqueue_init_cfunctions!()
        _KQUEUE_THREAD_ENTRY_C[] = @cfunction(_kqueue_event_loop_thread_entry, Ptr{Cvoid}, (Ptr{Cvoid},))
        return nothing
    end

    # libdispatch helpers for NW socket support (Apple only)
    @static if Sys.isapple()
        const _libdispatch = "libSystem"
        const _dispatch_queue_t = Ptr{Cvoid}
        const _dispatch_queue_attr_t = Ptr{Cvoid}
        const _DISPATCH_QUEUE_SERIAL = _dispatch_queue_attr_t(C_NULL)

        @inline function _kqueue_dispatch_queue_create(label::AbstractString)
            return @ccall _libdispatch.dispatch_queue_create(
                label::Cstring,
                _DISPATCH_QUEUE_SERIAL::_dispatch_queue_attr_t,
            )::_dispatch_queue_t
        end

        @inline function _kqueue_dispatch_release(queue::Ptr{Cvoid})
            @ccall _libdispatch.dispatch_release(queue::Ptr{Cvoid})::Cvoid
        end
    end

    function open_nonblocking_posix_pipe()::NTuple{2, Int32}
        pipe_fds = Ref{NTuple{2, Int32}}((Int32(-1), Int32(-1)))

        ret = @ccall pipe(pipe_fds::Ptr{Int32})::Cint
        if ret != 0
            throw_error(ERROR_SYS_CALL_FAILURE)
        end

        read_fd = pipe_fds[][1]
        write_fd = pipe_fds[][2]

        for fd in (read_fd, write_fd)
            flags = _fcntl(fd, Cint(3))  # F_GETFL = 3
            if flags == -1
                @ccall close(read_fd::Cint)::Cint
                @ccall close(write_fd::Cint)::Cint
                throw_error(ERROR_SYS_CALL_FAILURE)
            end
            ret = _fcntl(fd, Cint(4), (flags | O_NONBLOCK))  # F_SETFL = 4
            if ret == -1
                @ccall close(read_fd::Cint)::Cint
                @ccall close(write_fd::Cint)::Cint
                throw_error(ERROR_SYS_CALL_FAILURE)
            end
            fdflags = _fcntl(fd, Cint(1))  # F_GETFD = 1
            if fdflags == -1
                @ccall close(read_fd::Cint)::Cint
                @ccall close(write_fd::Cint)::Cint
                throw_error(ERROR_SYS_CALL_FAILURE)
            end
            ret = _fcntl(fd, Cint(2), (fdflags | FD_CLOEXEC))  # F_SETFD = 2
            if ret == -1
                @ccall close(read_fd::Cint)::Cint
                @ccall close(write_fd::Cint)::Cint
                throw_error(ERROR_SYS_CALL_FAILURE)
            end
        end

        return (read_fd, write_fd)
    end

    # Create a new kqueue event loop
    function event_loop_new_with_kqueue(
            clock::ClockSource = HighResClock(),
        )::EventLoop
        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "Initializing edge-triggered kqueue event loop")

        impl = KqueueEventLoop()

        # Create kqueue
        kq_fd = @ccall kqueue()::Cint
        if kq_fd == -1
            logf(LogLevel.FATAL, LS_IO_EVENT_LOOP, "Failed to open kqueue handle")
            throw_error(ERROR_SYS_CALL_FAILURE)
        end
        impl.kq_fd = Int32(kq_fd)

        pipe_result = try
            open_nonblocking_posix_pipe()
        catch
            @ccall close(kq_fd::Cint)::Cint
            logf(LogLevel.FATAL, LS_IO_EVENT_LOOP, "failed to open pipe handle")
            rethrow()
        end

        logf(
            LogLevel.TRACE,
            LS_IO_EVENT_LOOP,string("pipe descriptors read %d, write %d", " ", pipe_result[READ_FD], " ", pipe_result[WRITE_FD], " ", ))

        impl.cross_thread_signal_pipe = pipe_result

        # Set up kevent to handle activity on the cross-thread signal pipe
        thread_signal_kevent = Kevent(
            impl.cross_thread_signal_pipe[READ_FD],
            EVFILT_READ,
            EV_ADD | EV_CLEAR,
            UInt32(0),
            0,
            C_NULL,
        )

        changelist = Ref(thread_signal_kevent)
        res = @ccall kevent(
            kq_fd::Cint,
            changelist::Ptr{Kevent},
            1::Cint,
            C_NULL::Ptr{Kevent},
            0::Cint,
            C_NULL::Ptr{Cvoid},
        )::Cint

        if res == -1
            @ccall close(impl.cross_thread_signal_pipe[READ_FD]::Cint)::Cint
            @ccall close(impl.cross_thread_signal_pipe[WRITE_FD]::Cint)::Cint
            @ccall close(kq_fd::Cint)::Cint
            logf(LogLevel.FATAL, LS_IO_EVENT_LOOP, "failed to register kevent for signal pipe")
            throw_error(ERROR_SYS_CALL_FAILURE)
        end

        # Create dispatch queue for NW sockets (Apple only)
        @static if Sys.isapple()
            nw_queue = _kqueue_dispatch_queue_create("com.amazonaws.commonruntime.kqueue-nw")
            if nw_queue != C_NULL
                impl.nw_queue = nw_queue
            end
        end

        # Create the event loop
        event_loop = EventLoop(clock, impl)

        return event_loop
    end

    # Connect an IO handle to the event loop's completion port (for NW sockets)
    @static if Sys.isapple()
        function event_loop_connect_to_io_completion_port!(
                event_loop::EventLoop,
                handle::IoHandle,
            )::Nothing
            if handle.set_queue == C_NULL
                throw_error(ERROR_INVALID_ARGUMENT)
            end
            impl = event_loop.impl_data
            ccall(
                handle.set_queue,
                Cvoid,
                (Ptr{IoHandle}, Ptr{Cvoid}),
                Ref(handle),
                impl.nw_queue,
            )
            return nothing
        end
    end

    # Signal that cross-thread data has changed
    function signal_cross_thread_data_changed(event_loop::EventLoop)
        impl = event_loop.impl_data
        logf(
            LogLevel.TRACE,
            LS_IO_EVENT_LOOP,string("signaling event-loop that cross-thread tasks need to be scheduled", " ", ))
        write_val = Ref{UInt32}(0x00C0FFEE)
        write_size = Csize_t(sizeof(UInt32))
        # Best-effort. Writes may fail if pipe is full (EAGAIN) or interrupted (EINTR).
        while true
            wrote = @ccall gc_safe = true write(
                impl.cross_thread_signal_pipe[WRITE_FD]::Cint,
                write_val::Ptr{UInt32},
                write_size::Csize_t,
            )::Cssize_t
            if wrote == -1
                errno_val = Base.Libc.errno()
                if errno_val == Libc.EINTR
                    continue
                end
                if errno_val != Libc.EAGAIN
                    logf(
                        LogLevel.ERROR,
                        LS_IO_EVENT_LOOP,string("failed to signal event-loop via pipe (errno=%d)", " ", errno_val, " ", ))
                end
            end
            break
        end
        return nothing
    end

    # Run the event loop
    function event_loop_run!(event_loop::EventLoop)::Nothing
        impl = event_loop.impl_data

        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "starting event-loop thread")

        # Thread startup synchronization (avoid libuv-backed `sleep`/`time_ns` polling).
        impl.startup_event = Base.Threads.Event()
        impl.completion_event = Base.Threads.Event()
        @atomic impl.startup_error = 0
        @atomic impl.running_thread_id = UInt64(0)

        # Verify state
        if impl.cross_thread_data.state != EventThreadState.READY_TO_RUN
            throw_error(ERROR_INVALID_STATE)
        end
        if impl.thread_data.state != EventThreadState.READY_TO_RUN
            throw_error(ERROR_INVALID_STATE)
        end

        impl.cross_thread_data.state = EventThreadState.RUNNING

        # Launch the event loop thread via ForeignThread
        put!(_KQUEUE_THREAD_STARTUP, event_loop)
        try
            impl.thread_created_on = ForeignThread("aws-el-kqueue", _KQUEUE_THREAD_ENTRY_C)
        catch
            take!(_KQUEUE_THREAD_STARTUP)  # drain on failure
            impl.cross_thread_data.state = EventThreadState.READY_TO_RUN
            logf(LogLevel.FATAL, LS_IO_EVENT_LOOP, "thread creation failed")
            throw_error(ERROR_THREAD_NO_SUCH_THREAD_ID)
        end

        event_loop.thread = impl.thread_created_on
        @atomic event_loop.running = true

        wait(impl.startup_event)
        startup_error = @atomic impl.startup_error
        if startup_error != 0 || (@atomic impl.running_thread_id) == 0
            throw_error(startup_error != 0 ? startup_error : ERROR_IO_EVENT_LOOP_SHUTDOWN)
        end

        return nothing
    end

    # Stop the event loop
    function event_loop_stop!(event_loop::EventLoop)::Nothing
        impl = event_loop.impl_data
        @atomic event_loop.should_stop = true

        if event_loop_thread_is_callers_thread(event_loop)
            impl.thread_data.state = EventThreadState.STOPPING
            return nothing
        end

        signal_thread = false
        lock(impl.cross_thread_data.mutex)
        try
            if impl.cross_thread_data.state == EventThreadState.RUNNING
                impl.cross_thread_data.state = EventThreadState.STOPPING
                impl.cross_thread_data.thread_signaled = true
                signal_thread = true
            end
        finally
            unlock(impl.cross_thread_data.mutex)
        end
        if signal_thread
            signal_cross_thread_data_changed(event_loop)
        end

        return nothing
    end

    # Wait for the event loop to stop
    function event_loop_wait_for_stop_completion!(event_loop::EventLoop)::Nothing
        impl = event_loop.impl_data

        if impl.thread_created_on !== nothing
            wait(impl.completion_event)
        end

        impl.cross_thread_data.state = EventThreadState.READY_TO_RUN
        impl.thread_data.state = EventThreadState.READY_TO_RUN
        @atomic event_loop.running = false

        return nothing
    end

    # Schedule task cross-thread
    function schedule_task_cross_thread(event_loop::EventLoop, task::ScheduledTask, run_at_nanos::UInt64)
        impl = event_loop.impl_data

        logf(
            LogLevel.TRACE,
            LS_IO_EVENT_LOOP,string("scheduling task cross-thread for timestamp %d", " ", run_at_nanos, " ", ))

        task.timestamp = run_at_nanos
        task.scheduled = true
        should_signal_thread = false

        lock(impl.cross_thread_data.mutex)
        try
            push!(impl.cross_thread_data.tasks_to_schedule, task)

            if !impl.cross_thread_data.thread_signaled
                should_signal_thread = true
                impl.cross_thread_data.thread_signaled = true
            end
        finally
            unlock(impl.cross_thread_data.mutex)
        end

        if should_signal_thread
            signal_cross_thread_data_changed(event_loop)
        end

        return nothing
    end

    # Schedule task common implementation
    function schedule_task_common(event_loop::EventLoop, task::ScheduledTask, run_at_nanos::UInt64)
        impl = event_loop.impl_data

        # If we're on the event thread, schedule directly
        if event_loop_thread_is_callers_thread(event_loop)
            logf(
                LogLevel.TRACE,
                LS_IO_EVENT_LOOP,string("scheduling task in-thread for timestamp %d", " ", run_at_nanos, " ", ))
            if run_at_nanos == 0
                task_scheduler_schedule_now!(impl.thread_data.scheduler, task)
            else
                task_scheduler_schedule_future!(impl.thread_data.scheduler, task, run_at_nanos)
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

    # Schedule task now (serialized)
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
        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP,string("cancelling task %s", " ", task.type_tag))
        if !task.scheduled
            return nothing
        end

        removed = false
        lock(impl.cross_thread_data.mutex)
        try
            if !isempty(impl.cross_thread_data.tasks_to_schedule)
                idx = findfirst(x -> x === task, impl.cross_thread_data.tasks_to_schedule)
                if idx !== nothing
                    deleteat!(impl.cross_thread_data.tasks_to_schedule, idx)
                    removed = true
                end
            end
        finally
            unlock(impl.cross_thread_data.mutex)
        end

        if removed
            task_run!(task, TaskStatus.CANCELED)
            return nothing
        end

        task_scheduler_cancel!(impl.thread_data.scheduler, task)
    end

    # Check if on event thread
    function event_loop_thread_is_callers_thread(event_loop::EventLoop)::Bool
        impl = event_loop.impl_data
        running_id = @atomic impl.running_thread_id
        return running_id != 0 && running_id == UInt64(Base.Threads.threadid())
    end

    # Subscribe task callback
    function kqueue_subscribe_task_callback(task_data::KqueueHandleData{KqueueEventLoop}, status::TaskStatus.T)
        impl = task_data.event_loop

        # If cancelled, nothing to do
        if status == TaskStatus.CANCELED
            return nothing
        end

        # If already unsubscribed, nothing to do
        if task_data.state == HandleState.UNSUBSCRIBED
            return nothing
        end

        if task_data.state == HandleState.SUBSCRIBED
            return nothing
        end

        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP,string("subscribing to events on fd %d", " ", task_data.owner.fd))

        # Build changelist for kevent
        changelist = impl.subscribe_changelist
        eventlist = impl.subscribe_eventlist
        empty!(changelist)
        empty!(eventlist)
        handle_data_ptr = pointer_from_objref(task_data)

        if (task_data.events_subscribed & Int(IoEventType.READABLE)) != 0
            push!(
                changelist, Kevent(
                    task_data.owner.fd,
                    EVFILT_READ,
                    EV_ADD | EV_RECEIPT | EV_CLEAR,
                    handle_data_ptr,
                )
            )
        end
        if (task_data.events_subscribed & Int(IoEventType.WRITABLE)) != 0
            push!(
                changelist, Kevent(
                    task_data.owner.fd,
                    EVFILT_WRITE,
                    EV_ADD | EV_RECEIPT | EV_CLEAR,
                    handle_data_ptr,
                )
            )
        end

        if isempty(changelist)
            task_data.state = HandleState.SUBSCRIBED
            task_data.connected = true
            impl.thread_data.connected_handle_count += 1
            return nothing
        end

        # Call kevent with EV_RECEIPT to get results
        resize!(eventlist, length(changelist))
        timeout_ref = Ref(Timespec(0, 0))
        num_events = @ccall gc_safe = true kevent(
            impl.kq_fd::Cint,
            changelist::Ptr{Kevent},
            length(changelist)::Cint,
            eventlist::Ptr{Kevent},
            length(eventlist)::Cint,
            timeout_ref::Ptr{Timespec},
        )::Cint

        if num_events == -1
            logf(LogLevel.ERROR, LS_IO_EVENT_LOOP,string("failed to subscribe to events on fd %d", " ", task_data.owner.fd))
            task_data.on_event(Int(IoEventType.ERROR))
            return nothing
        end

        # Check for errors in results
        success = true
        for i in 1:num_events
            ev = eventlist[i]
            if ev.data != 0  # Non-zero data indicates error
                success = false
                break
            end
        end

        if !success
            logf(LogLevel.ERROR, LS_IO_EVENT_LOOP,string("failed to subscribe to events on fd %d", " ", task_data.owner.fd))
            # Remove any successful registrations
            for i in 1:num_events
                if eventlist[i].data == 0
                    del_ev = Kevent(eventlist[i].ident, eventlist[i].filter, EV_DELETE)
                    del_ref = Ref(del_ev)
                    @ccall kevent(
                        impl.kq_fd::Cint,
                        del_ref::Ptr{Kevent},
                        1::Cint,
                        C_NULL::Ptr{Kevent},
                        0::Cint,
                        C_NULL::Ptr{Cvoid},
                    )::Cint
                end
            end
            task_data.on_event(Int(IoEventType.ERROR))
            return nothing
        end

        impl.thread_data.connected_handle_count += 1
        task_data.state = HandleState.SUBSCRIBED
        task_data.connected = true
        return nothing
    end

    # Subscribe to IO events
    function event_loop_subscribe_to_io_events!(
            event_loop::EventLoop,
            handle::IoHandle,
            events::Int,
            on_event::EventCallable,
        )::Nothing
        if handle.fd < 0
            throw_error(ERROR_INVALID_ARGUMENT)
        end
        if handle.additional_data != C_NULL
            throw_error(ERROR_IO_ALREADY_SUBSCRIBED)
        end

        impl = event_loop.impl_data::KqueueEventLoop
        handle_data = KqueueHandleData(handle, impl, on_event, events)

        # Store handle data reference
        handle_data_ptr = pointer_from_objref(handle_data)
        handle.additional_data = handle_data_ptr
        handle.additional_ref = handle_data
        handle_data.registry_key = handle_data_ptr
        impl.handle_registry[handle_data_ptr] = handle_data

        # Create subscribe task
        handle_data.subscribe_task = ScheduledTask(
            TaskFn(function(status)
                try
                    kqueue_subscribe_task_callback(handle_data, TaskStatus.T(status))
                catch e
                    Core.println("kqueue_subscribe task errored")
                end
                return nothing
            end);
            type_tag = "kqueue_subscribe",
        )

        event_loop_schedule_task_now!(event_loop, handle_data.subscribe_task)

        return nothing
    end

    # Cleanup task callback
    function kqueue_cleanup_task_callback(handle_data::KqueueHandleData{KqueueEventLoop}, status::TaskStatus.T)
        impl = handle_data.event_loop
        if handle_data.connected
            handle_data.connected = false
            impl.thread_data.connected_handle_count -= 1
        end
        if handle_data.registry_key != C_NULL
            delete!(impl.handle_registry, handle_data.registry_key)
            handle_data.registry_key = C_NULL
        end
        return nothing
    end

    function kqueue_unsubscribe_task_callback(handle_data::KqueueHandleData{KqueueEventLoop}, status::TaskStatus.T)
        if status == TaskStatus.CANCELED
            return nothing
        end

        if handle_data.state == HandleState.UNSUBSCRIBED
            return nothing
        end

        impl = handle_data.event_loop
        if handle_data.state == HandleState.SUBSCRIBED
            changelist = impl.unsubscribe_changelist
            empty!(changelist)

            if (handle_data.events_subscribed & Int(IoEventType.READABLE)) != 0
                push!(changelist, Kevent(handle_data.owner.fd, EVFILT_READ, EV_DELETE))
            end
            if (handle_data.events_subscribed & Int(IoEventType.WRITABLE)) != 0
                push!(changelist, Kevent(handle_data.owner.fd, EVFILT_WRITE, EV_DELETE))
            end

            if !isempty(changelist)
                @ccall kevent(
                    impl.kq_fd::Cint,
                    changelist::Ptr{Kevent},
                    length(changelist)::Cint,
                    C_NULL::Ptr{Kevent},
                    0::Cint,
                    C_NULL::Ptr{Cvoid},
                )::Cint
            end
        end

        kqueue_cleanup_task_callback(handle_data, status)
        return nothing
    end

    # Unsubscribe from IO events
    function event_loop_unsubscribe_from_io_events!(
            event_loop::EventLoop,
            handle::IoHandle,
        )::Nothing
        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP,string("un-subscribing from events on fd %d", " ", handle.fd))

        if handle.additional_data == C_NULL
            throw_error(ERROR_IO_NOT_SUBSCRIBED)
        end

        handle_data = unsafe_pointer_to_objref(handle.additional_data)::KqueueHandleData{KqueueEventLoop}
        impl = event_loop.impl_data::KqueueEventLoop

        if @atomic event_loop.running
            if event_loop_thread_is_callers_thread(event_loop)
                # If called on event-loop thread, delete kqueue registration directly.
                if handle_data.state == HandleState.SUBSCRIBED
                    changelist = impl.unsubscribe_changelist
                    empty!(changelist)

                    if (handle_data.events_subscribed & Int(IoEventType.READABLE)) != 0
                        push!(changelist, Kevent(handle.fd, EVFILT_READ, EV_DELETE))
                    end
                    if (handle_data.events_subscribed & Int(IoEventType.WRITABLE)) != 0
                        push!(changelist, Kevent(handle.fd, EVFILT_WRITE, EV_DELETE))
                    end

                    if !isempty(changelist)
                        @ccall kevent(
                            impl.kq_fd::Cint,
                            changelist::Ptr{Kevent},
                            length(changelist)::Cint,
                            C_NULL::Ptr{Kevent},
                            0::Cint,
                            C_NULL::Ptr{Cvoid},
                        )::Cint
                    end
                end

                # Schedule cleanup task
                handle_data.cleanup_task = ScheduledTask(
                    TaskFn(function(status)
                        try
                            kqueue_cleanup_task_callback(handle_data, TaskStatus.T(status))
                        catch e
                            Core.println("kqueue_cleanup task errored")
                        end
                        return nothing
                    end);
                    type_tag = "kqueue_cleanup",
                )
            else
                # Off-thread unsubscribe must run registration deletion from the event-loop thread.
                handle_data.cleanup_task = ScheduledTask(
                    TaskFn(function(status)
                        try
                            kqueue_unsubscribe_task_callback(handle_data, TaskStatus.T(status))
                        catch e
                            Core.println("kqueue_unsubscribe task errored")
                        end
                        return nothing
                    end);
                    type_tag = "kqueue_unsubscribe",
                )
            end
            event_loop_schedule_task_now!(event_loop, handle_data.cleanup_task)
        else
            # Event loop is no longer running, so task scheduling won't make forward progress.
            # Perform the minimal cleanup synchronously to avoid leaking handle registry entries.
            if handle_data.state == HandleState.SUBSCRIBED
                impl.thread_data.connected_handle_count -= 1
                handle_data.connected = false
            end
            if handle_data.registry_key != C_NULL
                delete!(impl.handle_registry, handle_data.registry_key)
                handle_data.registry_key = C_NULL
            end
            handle_data.cleanup_task = nothing
        end

        handle_data.state = HandleState.UNSUBSCRIBED
        handle.additional_data = C_NULL
        handle.additional_ref = nothing

        return nothing
    end

    # Convert kevent flags to IoEventType
    function event_flags_from_kevent(kevent::Kevent)::Int
        event_flags = 0

        if (kevent.flags & EV_ERROR) != 0
            event_flags |= Int(IoEventType.ERROR)
        elseif kevent.filter == EVFILT_READ
            if kevent.data != 0
                event_flags |= Int(IoEventType.READABLE)
            end
            if (kevent.flags & EV_EOF) != 0
                event_flags |= Int(IoEventType.CLOSED)
            end
        elseif kevent.filter == EVFILT_WRITE
            if kevent.data != 0
                event_flags |= Int(IoEventType.WRITABLE)
            end
            if (kevent.flags & EV_EOF) != 0
                event_flags |= Int(IoEventType.CLOSED)
            end
        end

        return event_flags
    end

    # Process tasks from cross-thread queue
    function process_tasks_to_schedule(event_loop::EventLoop, tasks::Vector{ScheduledTask})
        impl = event_loop.impl_data
        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "processing cross-thread tasks")

        for task in tasks
            logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "task pulled to event-loop, scheduling now")
            if task.timestamp == 0
                task_scheduler_schedule_now!(impl.thread_data.scheduler, task)
            else
                task_scheduler_schedule_future!(impl.thread_data.scheduler, task, task.timestamp)
            end
        end
    end

    # Process cross-thread data
    function process_cross_thread_data(event_loop::EventLoop)
        impl = event_loop.impl_data
        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "notified of cross-thread data to process")

        tasks_to_schedule = impl.cross_thread_data.tasks_to_schedule_spare

        lock(impl.cross_thread_data.mutex)
        try
            impl.cross_thread_data.thread_signaled = false

            initiate_stop = impl.cross_thread_data.state == EventThreadState.STOPPING &&
                impl.thread_data.state == EventThreadState.RUNNING
            if initiate_stop
                impl.thread_data.state = EventThreadState.STOPPING
            end

            empty!(tasks_to_schedule)
            while !isempty(impl.cross_thread_data.tasks_to_schedule)
                push!(tasks_to_schedule, popfirst!(impl.cross_thread_data.tasks_to_schedule))
            end
        finally
            unlock(impl.cross_thread_data.mutex)
        end

        process_tasks_to_schedule(event_loop, tasks_to_schedule)
    end

    # Main event loop thread function
    function kqueue_event_loop_thread(event_loop::EventLoop)
        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "main loop started")
        impl = event_loop.impl_data::KqueueEventLoop

        # Set running thread ID
        @atomic impl.running_thread_id = UInt64(Base.Threads.threadid())
        impl.thread_data.state = EventThreadState.RUNNING
        notify(impl.startup_event)

        kevents = Memory{Kevent}(undef, MAX_EVENTS)
        io_handle_events = Vector{KqueueHandleData{KqueueEventLoop}}()

        timeout = Timespec(DEFAULT_TIMEOUT_SEC, 0)

        logf(
            LogLevel.INFO,
            LS_IO_EVENT_LOOP,string("default timeout %ds, max events per tick %d", " ", DEFAULT_TIMEOUT_SEC, " ", MAX_EVENTS, " ", ))

        while impl.thread_data.state == EventThreadState.RUNNING
            empty!(io_handle_events)
            should_process_cross_thread_data = false

            logf(
                LogLevel.TRACE,
                LS_IO_EVENT_LOOP,string("waiting for a maximum of %ds %dns", " ", timeout.tv_sec, " ", timeout.tv_nsec, " ", ))

            # Call kevent to wait for events
            timeout_ref = Ref(timeout)
            num_kevents = @ccall gc_safe = true kevent(
                impl.kq_fd::Cint,
                C_NULL::Ptr{Kevent},
                0::Cint,
                kevents::Ptr{Kevent},
                MAX_EVENTS::Cint,
                timeout_ref::Ptr{Timespec},
            )::Cint

            event_loop_register_tick_start!(event_loop)

            logf(LogLevel.TRACE, LS_IO_EVENT_LOOP,string("wake up with %d events to process", " ", num_kevents))

            if num_kevents == -1
                raise_error(ERROR_SYS_CALL_FAILURE)
                should_process_cross_thread_data = true
            end

            # Process kevents
            if num_kevents > 0
                tracing_task_begin(tracing_event_loop_events)
            end
            for i in 1:num_kevents
                tracing_task_begin(tracing_event_loop_event)
                try
                    kevent = kevents[i]
                    # Check if this is the cross-thread signal
                        if Int(kevent.ident) == impl.cross_thread_signal_pipe[READ_FD]
                            should_process_cross_thread_data = true
                            read_val = Ref{UInt32}(0)
                            read_size = Csize_t(sizeof(UInt32))
                            while true
                                read_result = @ccall gc_safe = true read(
                                    impl.cross_thread_signal_pipe[READ_FD]::Cint,
                                    read_val::Ptr{UInt32},
                                    read_size::Csize_t,
                                )::Cssize_t
                                if read_result <= 0
                                    if read_result == -1 && Base.Libc.errno() == Libc.EINTR
                                        continue
                                    end
                                    break
                                end
                            end
                            continue
                        end

                    # Process normal event
                    event_flags = event_flags_from_kevent(kevent)
                    if event_flags == 0
                        continue
                    end

                    if kevent.udata != C_NULL
                        handle_data = get(impl.handle_registry, kevent.udata, nothing)
                        handle_data === nothing && continue
                        if handle_data.events_this_loop == 0
                            push!(io_handle_events, handle_data)
                        end
                        handle_data.events_this_loop |= event_flags
                    end
                finally
                    tracing_task_end(tracing_event_loop_event)
                end
            end
            if num_kevents > 0
                tracing_task_end(tracing_event_loop_events)
            end

            # Invoke callbacks for handles with events
            for handle_data in io_handle_events
                if handle_data.state == HandleState.SUBSCRIBED
                    logf(
                        LogLevel.TRACE,
                        LS_IO_EVENT_LOOP,string("activity on fd %d, invoking handler", " ", handle_data.owner.fd, " ", ))
                    handle_data.on_event(handle_data.events_this_loop)
                end
                handle_data.events_this_loop = 0
            end

            # Process cross-thread data.
            if !should_process_cross_thread_data
                pending = false
                lock(impl.cross_thread_data.mutex)
                try
                    pending = impl.cross_thread_data.thread_signaled ||
                        (impl.cross_thread_data.state != EventThreadState.RUNNING)
                    should_process_cross_thread_data = pending
                finally
                    unlock(impl.cross_thread_data.mutex)
                end
            end
            if should_process_cross_thread_data
                process_cross_thread_data(event_loop)
            end

            # Run scheduled tasks
            now_ns = clock_now_ns(event_loop.clock)

            logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "running scheduled tasks")
            tracing_task_begin(tracing_event_loop_run_tasks)
            try
                task_scheduler_run_all!(impl.thread_data.scheduler, now_ns)
            finally
                tracing_task_end(tracing_event_loop_run_tasks)
            end

            # Calculate next timeout
            use_default_timeout = false

            now_ns = clock_now_ns(event_loop.clock)

            has_tasks, next_run_time = task_scheduler_has_tasks(impl.thread_data.scheduler)
            if !has_tasks
                use_default_timeout = true
            end

            if use_default_timeout
                logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "no more scheduled tasks, using default timeout")
                timeout = Timespec(DEFAULT_TIMEOUT_SEC, 0)
            else
                timeout_ns = next_run_time > now_ns ? next_run_time - now_ns : UInt64(0)
                timeout_sec = timeout_ns ÷ 1_000_000_000
                timeout_remainder_ns = timeout_ns % 1_000_000_000

                if timeout_sec > typemax(Clong)
                    timeout_sec = typemax(Clong)
                    timeout_remainder_ns = 0
                end

                logf(
                    LogLevel.TRACE,
                    LS_IO_EVENT_LOOP,string("detected more scheduled tasks, using timeout of %ds %dns", " ", timeout_sec, " ", timeout_remainder_ns, " ", ))
                timeout = Timespec(Clong(timeout_sec), Clong(timeout_remainder_ns))
            end

            event_loop_register_tick_end!(event_loop)
        end

        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "exiting main loop")
        event_loop_thread_exit_s2n_cleanup!(event_loop)
        @atomic impl.running_thread_id = UInt64(0)
        LibAwsCal.aws_cal_thread_clean_up()
        return nothing
    end

    # Destroy kqueue event loop
    function event_loop_complete_destroy!(event_loop::EventLoop)
        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "destroying event_loop")
        impl = event_loop.impl_data

        # Stop and wait
        event_loop_stop!(event_loop)
        event_loop_wait_for_stop_completion!(event_loop)

        # Set thread ID for cancellation callbacks
        impl.thread_joined_to = UInt64(Base.Threads.threadid())
        @atomic impl.running_thread_id = impl.thread_joined_to

        # Clean up scheduler (cancels remaining tasks)
        task_scheduler_clean_up!(impl.thread_data.scheduler)

        # Cancel tasks in cross-thread queue
        while true
            tasks_to_cancel = nothing
            lock(impl.cross_thread_data.mutex)
            try
                isempty(impl.cross_thread_data.tasks_to_schedule) && break
                tasks_to_cancel = impl.cross_thread_data.tasks_to_schedule
                impl.cross_thread_data.tasks_to_schedule = ScheduledTask[]
            finally
                unlock(impl.cross_thread_data.mutex)
            end
            for task in tasks_to_cancel
                task_run!(task, TaskStatus.CANCELED)
            end
        end

        # Remove signal kevent
        del_kevent = Kevent(
            impl.cross_thread_signal_pipe[READ_FD],
            EVFILT_READ,
            EV_DELETE,
            UInt32(0),
            0,
            C_NULL,
        )
        del_ref = Ref(del_kevent)
        @ccall kevent(impl.kq_fd::Cint, del_ref::Ptr{Kevent}, 1::Cint, C_NULL::Ptr{Kevent}, 0::Cint, C_NULL::Ptr{Cvoid})::Cint
        @ccall close(impl.cross_thread_signal_pipe[READ_FD]::Cint)::Cint
        @ccall close(impl.cross_thread_signal_pipe[WRITE_FD]::Cint)::Cint
        @ccall close(impl.kq_fd::Cint)::Cint

        # Release dispatch queue for NW sockets (Apple only)
        @static if Sys.isapple()
            if impl.nw_queue != C_NULL
                _kqueue_dispatch_release(impl.nw_queue)
                impl.nw_queue = C_NULL
            end
        end

        _event_loop_clean_up_shared_resources!(event_loop)

        return nothing
    end

end # @static if Sys.isapple() || Sys.isbsd()
