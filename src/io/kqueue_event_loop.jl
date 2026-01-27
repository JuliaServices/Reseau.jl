# AWS IO Library - KQueue Event Loop Implementation
# Port of aws-c-io/source/bsd/kqueue_event_loop.c

# Only define on BSD/macOS
@static if Sys.isapple() || Sys.isbsd()
    using LibAwsCal

    # Constants from sys/event.h
    const EVFILT_READ = Int16(-1)
    const EVFILT_WRITE = Int16(-2)
    const EV_ADD = UInt16(0x0001)
    const EV_DELETE = UInt16(0x0002)
    const EV_ENABLE = UInt16(0x0004)
    const EV_DISABLE = UInt16(0x0008)
    const EV_ONESHOT = UInt16(0x0010)
    const EV_CLEAR = UInt16(0x0020)
    const EV_RECEIPT = UInt16(0x0040)
    const EV_DISPATCH = UInt16(0x0080)
    const EV_EOF = UInt16(0x8000)
    const EV_ERROR = UInt16(0x4000)
    const READ_FD = 1
    const WRITE_FD = 2
    const O_NONBLOCK = Cint(0x0004)
    const FD_CLOEXEC = Cint(0x0001)

    # kevent structure - must match C struct layout
    # Note: ident is uintptr_t (pointer-sized unsigned), data is intptr_t (pointer-sized signed)
    struct Kevent
        ident::UInt         # identifier for this event (uintptr_t)
        filter::Int16       # filter for event
        flags::UInt16       # action flags for kqueue
        fflags::UInt32      # filter flag value
        data::Int           # filter data value (intptr_t)
        udata::Ptr{Cvoid}   # opaque user data identifier
    end

    function Kevent(fd::Integer, filter::Int16, flags::UInt16, udata::Ptr{Cvoid} = C_NULL)
        return Kevent(UInt(fd), filter, flags, UInt32(0), Int(0), udata)
    end

    function Kevent(
            fd::Integer,
            filter::Int16,
            flags::UInt16,
            fflags::UInt32,
            data::Int,
            udata::Ptr{Cvoid},
        )
        return Kevent(UInt(fd), filter, flags, fflags, data, udata)
    end

    # Event thread state
    @enumx EventThreadState::UInt8 begin
        READY_TO_RUN = 0
        RUNNING = 1
        STOPPING = 2
    end

    # Configuration constants
    const DEFAULT_TIMEOUT_SEC = 100
    const MAX_EVENTS = 100

    # Handle state for subscribed handles
    @enumx HandleState::UInt8 begin
        SUBSCRIBING = 0
        SUBSCRIBED = 1
        UNSUBSCRIBED = 2
    end

    # Handle data attached to IoHandle while subscribed
    # Note: EL is the event loop type (will be KqueueEventLoop), U is user_data type
    mutable struct KqueueHandleData{EL, F <: OnEventCallback, U}
        owner::IoHandle
        event_loop::EL
        on_event::F
        on_event_user_data::U
        events_subscribed::Int  # IoEventType bitmask
        events_this_loop::Int   # Events received during current loop iteration
        state::HandleState.T
        subscribe_task::Union{Nothing, ScheduledTask}  # nullable
        cleanup_task::Union{Nothing, ScheduledTask}  # nullable
        registry_key::Ptr{Cvoid}
    end

    function KqueueHandleData(
            owner::IoHandle,
            event_loop::EL,
            on_event::F,
            user_data::U,
            events::Int,
        ) where {EL, F <: OnEventCallback, U}
        return KqueueHandleData{EL, F, U}(
            owner,
            event_loop,
            on_event,
            user_data,
            events,
            0,
            HandleState.SUBSCRIBING,
            nothing,
            nothing,
            C_NULL,
        )
    end

    # Cross-thread data protected by mutex
    mutable struct KqueueCrossThreadData
        mutex::Mutex
        thread_signaled::Bool
        tasks_to_schedule::Deque{ScheduledTask}
        state::EventThreadState.T
    end

    function KqueueCrossThreadData()
        return KqueueCrossThreadData(
            Mutex(),
            false,
            Deque{ScheduledTask}(16),
            EventThreadState.READY_TO_RUN,
        )
    end

    # Thread-local data
    mutable struct KqueueThreadData
        scheduler::TaskScheduler
        connected_handle_count::Int
        state::EventThreadState.T
    end

    function KqueueThreadData()
        return KqueueThreadData(
            TaskScheduler(),
            0,
            EventThreadState.READY_TO_RUN,
        )
    end

    # KQueue event loop implementation data
    mutable struct KqueueLoopImpl
        thread_created_on::Union{Nothing, ThreadHandle}
        thread_joined_to::UInt64
        @atomic running_thread_id::UInt64
        kq_fd::Int32
        cross_thread_signal_pipe::NTuple{2, Int32}
        cross_thread_data::KqueueCrossThreadData
        thread_data::KqueueThreadData
        thread_options::ThreadOptions
        handle_registry::Dict{Ptr{Cvoid}, Any}
    end

    function KqueueLoopImpl()
        return KqueueLoopImpl(
            nothing,
            UInt64(0),
            UInt64(0),
            Int32(-1),
            (Int32(-1), Int32(-1)),
            KqueueCrossThreadData(),
            KqueueThreadData(),
            ThreadOptions(),
            Dict{Ptr{Cvoid}, Any}(),
        )
    end

    # KQueue event loop concrete type
    const KqueueEventLoop = EventLoop{KqueueLoopImpl, LD, Clock} where {LD, Clock}

    function open_nonblocking_posix_pipe()::Union{NTuple{2, Int32}, ErrorResult}
        pipe_fds = Ref{NTuple{2, Int32}}((Int32(-1), Int32(-1)))

        ret = @ccall pipe(pipe_fds::Ptr{Int32})::Cint
        if ret != 0
            return ErrorResult(raise_error(ERROR_SYS_CALL_FAILURE))
        end

        read_fd = pipe_fds[][1]
        write_fd = pipe_fds[][2]

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
            fdflags = _fcntl(fd, Cint(1))  # F_GETFD = 1
            if fdflags == -1
                @ccall close(read_fd::Cint)::Cint
                @ccall close(write_fd::Cint)::Cint
                return ErrorResult(raise_error(ERROR_SYS_CALL_FAILURE))
            end
            ret = _fcntl(fd, Cint(2), (fdflags | FD_CLOEXEC))  # F_SETFD = 2
            if ret == -1
                @ccall close(read_fd::Cint)::Cint
                @ccall close(write_fd::Cint)::Cint
                return ErrorResult(raise_error(ERROR_SYS_CALL_FAILURE))
            end
        end

        return (read_fd, write_fd)
    end

    # Create a new kqueue event loop
    function event_loop_new_with_kqueue(
            options::EventLoopOptions,
        )::Union{EventLoop, ErrorResult}
        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "Initializing edge-triggered kqueue event loop")

        impl = KqueueLoopImpl()

        if options.thread_options !== nothing
            impl.thread_options = options.thread_options
        end

        # Create kqueue
        kq_fd = @ccall kqueue()::Cint
        if kq_fd == -1
            logf(LogLevel.FATAL, LS_IO_EVENT_LOOP, "Failed to open kqueue handle")
            return ErrorResult(raise_error(ERROR_SYS_CALL_FAILURE))
        end
        impl.kq_fd = Int32(kq_fd)

        pipe_result = open_nonblocking_posix_pipe()
        if pipe_result isa ErrorResult
            @ccall close(kq_fd::Cint)::Cint
            logf(LogLevel.FATAL, LS_IO_EVENT_LOOP, "failed to open pipe handle")
            return pipe_result
        end

        logf(
            LogLevel.TRACE,
            LS_IO_EVENT_LOOP,
            "pipe descriptors read %d, write %d",
            pipe_result[READ_FD],
            pipe_result[WRITE_FD],
        )

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
            return ErrorResult(raise_error(ERROR_SYS_CALL_FAILURE))
        end

        # Mutex is initialized automatically in KqueueCrossThreadData constructor

        # Create the event loop
        event_loop = EventLoop(options.clock, impl)
        event_loop.base_elg = options.parent_elg

        return event_loop
    end

    # Signal that cross-thread data has changed
    function signal_cross_thread_data_changed(event_loop::KqueueEventLoop)
        impl = event_loop.impl_data
        logf(
            LogLevel.TRACE,
            LS_IO_EVENT_LOOP,
            "signaling event-loop that cross-thread tasks need to be scheduled",
        )
        write_val = Ref{UInt32}(0x00C0FFEE)
        write_size = Csize_t(sizeof(UInt32))
        _ = @ccall write(
            impl.cross_thread_signal_pipe[WRITE_FD]::Cint,
            write_val::Ptr{UInt32},
            write_size::Csize_t,
        )::Cssize_t
        return nothing
    end

    # Run the event loop
    function event_loop_run!(event_loop::KqueueEventLoop)::Union{Nothing, ErrorResult}
        impl = event_loop.impl_data

        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "starting event-loop thread")

        # Verify state
        if impl.cross_thread_data.state != EventThreadState.READY_TO_RUN
            return ErrorResult(raise_error(ERROR_INVALID_STATE))
        end
        if impl.thread_data.state != EventThreadState.READY_TO_RUN
            return ErrorResult(raise_error(ERROR_INVALID_STATE))
        end

        impl.cross_thread_data.state = EventThreadState.RUNNING

        # Launch the event loop thread
        thread_fn = el -> kqueue_event_loop_thread(el)
        impl.thread_created_on = ThreadHandle()
        thread_options = thread_options_with_defaults(impl.thread_options; name = "aws-el-kqueue", pool = :interactive)

        result = thread_launch(impl.thread_created_on, thread_fn, event_loop, thread_options)
        if result != OP_SUCCESS
            impl.cross_thread_data.state = EventThreadState.READY_TO_RUN
            logf(LogLevel.FATAL, LS_IO_EVENT_LOOP, "thread creation failed")
            return ErrorResult(last_error())
        end

        event_loop.thread = impl.thread_created_on
        @atomic event_loop.running = true

        wait_start = time_ns()
        while impl.thread_data.state != EventThreadState.RUNNING
            if time_ns() - wait_start > 1_000_000_000
                return ErrorResult(raise_error(ERROR_IO_EVENT_LOOP_SHUTDOWN))
            end
            sleep(0.001)
        end

        return nothing
    end

    # Stop the event loop
    function event_loop_stop!(event_loop::KqueueEventLoop)::Union{Nothing, ErrorResult}
        impl = event_loop.impl_data
        @atomic event_loop.should_stop = true

        if event_loop_thread_is_callers_thread(event_loop)
            impl.thread_data.state = EventThreadState.STOPPING
            return nothing
        end

        signal_thread = false
        mutex_lock(impl.cross_thread_data.mutex)
        if impl.cross_thread_data.state == EventThreadState.RUNNING
            impl.cross_thread_data.state = EventThreadState.STOPPING
            impl.cross_thread_data.thread_signaled = true
            signal_thread = true
        end
        mutex_unlock(impl.cross_thread_data.mutex)
        if signal_thread
            signal_cross_thread_data_changed(event_loop)
        end

        return nothing
    end

    # Wait for the event loop to stop
    function event_loop_wait_for_stop_completion!(event_loop::KqueueEventLoop)::Union{Nothing, ErrorResult}
        impl = event_loop.impl_data

        if impl.thread_created_on !== nothing
            result = thread_join(impl.thread_created_on)
            if result != OP_SUCCESS
                return ErrorResult(last_error())
            end
        end

        impl.cross_thread_data.state = EventThreadState.READY_TO_RUN
        impl.thread_data.state = EventThreadState.READY_TO_RUN
        @atomic event_loop.running = false

        return nothing
    end

    # Schedule task cross-thread
    function schedule_task_cross_thread(event_loop::KqueueEventLoop, task::ScheduledTask, run_at_nanos::UInt64)
        impl = event_loop.impl_data

        logf(
            LogLevel.TRACE,
            LS_IO_EVENT_LOOP,
            "scheduling task cross-thread for timestamp %d",
            run_at_nanos,
        )

        task.timestamp = run_at_nanos
        task.scheduled = true
        should_signal_thread = false

        mutex_lock(impl.cross_thread_data.mutex)
        push_back!(impl.cross_thread_data.tasks_to_schedule, task)

        if !impl.cross_thread_data.thread_signaled
            should_signal_thread = true
            impl.cross_thread_data.thread_signaled = true
        end
        mutex_unlock(impl.cross_thread_data.mutex)

        if should_signal_thread
            signal_cross_thread_data_changed(event_loop)
        end

        return nothing
    end

    # Schedule task common implementation
    function schedule_task_common(event_loop::KqueueEventLoop, task::ScheduledTask, run_at_nanos::UInt64)
        impl = event_loop.impl_data

        # If we're on the event thread, schedule directly
        if event_loop_thread_is_callers_thread(event_loop)
            logf(
                LogLevel.TRACE,
                LS_IO_EVENT_LOOP,
                "scheduling task in-thread for timestamp %d",
                run_at_nanos,
            )
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
    function event_loop_schedule_task_now!(event_loop::KqueueEventLoop, task::ScheduledTask)
        schedule_task_common(event_loop, task, UInt64(0))
    end

    # Schedule task now (serialized)
    function event_loop_schedule_task_now_serialized!(event_loop::KqueueEventLoop, task::ScheduledTask)
        schedule_task_cross_thread(event_loop, task, UInt64(0))
    end

    # Schedule task future
    function event_loop_schedule_task_future!(event_loop::KqueueEventLoop, task::ScheduledTask, run_at_nanos::UInt64)
        schedule_task_common(event_loop, task, run_at_nanos)
    end

    # Cancel task
    function event_loop_cancel_task!(event_loop::KqueueEventLoop, task::ScheduledTask)
        debug_assert(event_loop_thread_is_callers_thread(event_loop))
        impl = event_loop.impl_data
        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "cancelling task %s", task.type_tag)
        if !task.scheduled
            return nothing
        end

        removed = false
        mutex_lock(impl.cross_thread_data.mutex)
        if !isempty(impl.cross_thread_data.tasks_to_schedule)
            removed = remove!(impl.cross_thread_data.tasks_to_schedule, task; eq = (===))
        end
        mutex_unlock(impl.cross_thread_data.mutex)

        if removed
            task_run!(task, TaskStatus.CANCELED)
            return nothing
        end

        task_scheduler_cancel!(impl.thread_data.scheduler, task)
    end

    # Check if on event thread
    function event_loop_thread_is_callers_thread(event_loop::KqueueEventLoop)::Bool
        impl = event_loop.impl_data
        running_id = @atomic impl.running_thread_id
        return running_id != 0 && running_id == thread_current_thread_id()
    end

    # Subscribe task callback
    function kqueue_subscribe_task_callback(task_data::KqueueHandleData, status::TaskStatus.T)
        event_loop = task_data.event_loop
        impl = event_loop.impl_data

        impl.thread_data.connected_handle_count += 1

        # If cancelled, nothing to do
        if status == TaskStatus.CANCELED
            return nothing
        end

        # If already unsubscribed, nothing to do
        if task_data.state == HandleState.UNSUBSCRIBED
            return nothing
        end

        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "subscribing to events on fd %d", task_data.owner.fd)

        # Build changelist for kevent
        changelist = Vector{Kevent}()
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
            return nothing
        end

        # Call kevent with EV_RECEIPT to get results
        eventlist = similar(changelist)
        num_events = @ccall kevent(
            impl.kq_fd::Cint,
            changelist::Ptr{Kevent},
            length(changelist)::Cint,
            eventlist::Ptr{Kevent},
            length(changelist)::Cint,
            C_NULL::Ptr{Cvoid},
        )::Cint

        if num_events == -1
            logf(LogLevel.ERROR, LS_IO_EVENT_LOOP, "failed to subscribe to events on fd %d", task_data.owner.fd)
            task_data.on_event(event_loop, task_data.owner, Int(IoEventType.ERROR), task_data.on_event_user_data)
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
            logf(LogLevel.ERROR, LS_IO_EVENT_LOOP, "failed to subscribe to events on fd %d", task_data.owner.fd)
            # Remove any successful registrations
            for i in 1:num_events
                if eventlist[i].data == 0
                    del_ev = Kevent(eventlist[i].ident, eventlist[i].filter, EV_DELETE)
                    del_ref = Ref(del_ev)
                    @ccall kevent(impl.kq_fd::Cint, del_ref::Ptr{Kevent}, 1::Cint, C_NULL::Ptr{Kevent}, 0::Cint, C_NULL::Ptr{Cvoid})::Cint
                end
            end
            task_data.on_event(event_loop, task_data.owner, Int(IoEventType.ERROR), task_data.on_event_user_data)
            return nothing
        end

        task_data.state = HandleState.SUBSCRIBED
        return nothing
    end

    # Subscribe to IO events
    function event_loop_subscribe_to_io_events!(
            event_loop::KqueueEventLoop,
            handle::IoHandle,
            events::Int,
            on_event::OnEventCallback,
            user_data,
        )::Union{Nothing, ErrorResult}
        if handle.fd < 0
            return ErrorResult(raise_error(ERROR_INVALID_ARGUMENT))
        end
        if handle.additional_data != C_NULL
            return ErrorResult(raise_error(ERROR_IO_ALREADY_SUBSCRIBED))
        end

        handle_data = KqueueHandleData(handle, event_loop, on_event, user_data, events)

        # Store handle data reference
        handle_data_ptr = pointer_from_objref(handle_data)
        handle.additional_data = handle_data_ptr
        handle.additional_ref = handle_data
        handle_data.registry_key = handle_data_ptr
        event_loop.impl_data.handle_registry[handle_data_ptr] = handle_data

        # Create subscribe task
        subscribe_fn = (ctx, status) -> kqueue_subscribe_task_callback(ctx, status)
        handle_data.subscribe_task = ScheduledTask(subscribe_fn, handle_data; type_tag = "kqueue_subscribe")

        event_loop_schedule_task_now!(event_loop, handle_data.subscribe_task)

        return nothing
    end

    # Cleanup task callback
    function kqueue_cleanup_task_callback(handle_data::KqueueHandleData, status::TaskStatus.T)
        impl = handle_data.event_loop.impl_data
        impl.thread_data.connected_handle_count -= 1
        if handle_data.registry_key != C_NULL
            delete!(impl.handle_registry, handle_data.registry_key)
            handle_data.registry_key = C_NULL
        end
        return nothing
    end

    # Unsubscribe from IO events
    function event_loop_unsubscribe_from_io_events!(
            event_loop::KqueueEventLoop,
            handle::IoHandle,
        )::Union{Nothing, ErrorResult}
        debug_assert(event_loop_thread_is_callers_thread(event_loop))
        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "un-subscribing from events on fd %d", handle.fd)

        if handle.additional_data == C_NULL
            return ErrorResult(raise_error(ERROR_IO_NOT_SUBSCRIBED))
        end

        handle_data = unsafe_pointer_to_objref(handle.additional_data)::KqueueHandleData
        impl = event_loop.impl_data

        # If successfully subscribed, remove from kqueue
        if handle_data.state == HandleState.SUBSCRIBED
            changelist = Vector{Kevent}()

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
        cleanup_fn = (ctx, status) -> kqueue_cleanup_task_callback(ctx, status)
        handle_data.cleanup_task = ScheduledTask(cleanup_fn, handle_data; type_tag = "kqueue_cleanup")
        event_loop_schedule_task_now!(event_loop, handle_data.cleanup_task)

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
    function process_tasks_to_schedule(event_loop::KqueueEventLoop, tasks::Vector{ScheduledTask})
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
    function process_cross_thread_data(event_loop::KqueueEventLoop)
        impl = event_loop.impl_data
        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "notified of cross-thread data to process")

        tasks_to_schedule = Vector{ScheduledTask}()

        mutex_lock(impl.cross_thread_data.mutex)
        impl.cross_thread_data.thread_signaled = false

        initiate_stop = impl.cross_thread_data.state == EventThreadState.STOPPING &&
            impl.thread_data.state == EventThreadState.RUNNING
        if initiate_stop
            impl.thread_data.state = EventThreadState.STOPPING
        end

        # Move tasks from cross-thread queue
        while !isempty(impl.cross_thread_data.tasks_to_schedule)
            task = pop_front!(impl.cross_thread_data.tasks_to_schedule)
            if task !== nothing
                push!(tasks_to_schedule, task)
            end
        end

        mutex_unlock(impl.cross_thread_data.mutex)

        process_tasks_to_schedule(event_loop, tasks_to_schedule)
    end

    # timespec structure for kevent timeout
    struct Timespec
        tv_sec::Clong
        tv_nsec::Clong
    end

    # Main event loop thread function
    function kqueue_event_loop_thread(event_loop::KqueueEventLoop)
        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "main loop started")
        impl = event_loop.impl_data

        # Set running thread ID
        @atomic impl.running_thread_id = thread_current_thread_id()
        impl.thread_data.state = EventThreadState.RUNNING

        _ = thread_current_at_exit(() -> LibAwsCal.aws_cal_thread_clean_up())

        kevents = Memory{Kevent}(undef, MAX_EVENTS)
        io_handle_events = Vector{KqueueHandleData}()

        timeout = Timespec(DEFAULT_TIMEOUT_SEC, 0)

        logf(
            LogLevel.INFO,
            LS_IO_EVENT_LOOP,
            "default timeout %ds, max events per tick %d",
            DEFAULT_TIMEOUT_SEC,
            MAX_EVENTS,
        )

        while impl.thread_data.state == EventThreadState.RUNNING
            empty!(io_handle_events)
            should_process_cross_thread_data = false

            logf(
                LogLevel.TRACE,
                LS_IO_EVENT_LOOP,
                "waiting for a maximum of %ds %dns",
                timeout.tv_sec,
                timeout.tv_nsec,
            )

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

            logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "wake up with %d events to process", num_kevents)

            if num_kevents == -1
                raise_error(ERROR_SYS_CALL_FAILURE)
                should_process_cross_thread_data = true
            end

            # Process kevents
            for i in 1:num_kevents
                kevent = kevents[i]
                # Check if this is the cross-thread signal
                if Int(kevent.ident) == impl.cross_thread_signal_pipe[READ_FD]
                    should_process_cross_thread_data = true
                    read_val = Ref{UInt32}(0)
                    read_size = Csize_t(sizeof(UInt32))
                    while true
                        read_result = @ccall read(
                            impl.cross_thread_signal_pipe[READ_FD]::Cint,
                            read_val::Ptr{UInt32},
                            read_size::Csize_t,
                        )::Cssize_t
                        if read_result <= 0
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
            end

            # Invoke callbacks for handles with events
            for handle_data in io_handle_events
                if handle_data.state == HandleState.SUBSCRIBED
                    logf(
                        LogLevel.TRACE,
                        LS_IO_EVENT_LOOP,
                        "activity on fd %d, invoking handler",
                        handle_data.owner.fd,
                    )
                    handle_data.on_event(
                        event_loop,
                        handle_data.owner,
                        handle_data.events_this_loop,
                        handle_data.on_event_user_data,
                    )
                end
                handle_data.events_this_loop = 0
            end

            # Process cross-thread data
            if should_process_cross_thread_data
                process_cross_thread_data(event_loop)
            end

            # Run scheduled tasks
            now_ns_result = event_loop.clock()
            now_ns = now_ns_result isa ErrorResult ? UInt64(0) : now_ns_result

            logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "running scheduled tasks")
            task_scheduler_run_all!(impl.thread_data.scheduler, now_ns)

            # Calculate next timeout
            use_default_timeout = false

            now_ns_result = event_loop.clock()
            if now_ns_result isa ErrorResult
                use_default_timeout = true
            else
                now_ns = now_ns_result
            end

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
                    LS_IO_EVENT_LOOP,
                    "detected more scheduled tasks, using timeout of %ds %dns",
                    timeout_sec,
                    timeout_remainder_ns,
                )
                timeout = Timespec(Clong(timeout_sec), Clong(timeout_remainder_ns))
            end

            event_loop_register_tick_end!(event_loop)
        end

        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "exiting main loop")
        @atomic impl.running_thread_id = UInt64(0)
        return nothing
    end

    # Destroy kqueue event loop
    function event_loop_complete_destroy!(event_loop::KqueueEventLoop)
        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "destroying event_loop")
        impl = event_loop.impl_data

        # Stop and wait
        event_loop_stop!(event_loop)
        event_loop_wait_for_stop_completion!(event_loop)

        # Set thread ID for cancellation callbacks
        impl.thread_joined_to = thread_current_thread_id()
        @atomic impl.running_thread_id = impl.thread_joined_to

        # Clean up scheduler (cancels remaining tasks)
        task_scheduler_clean_up!(impl.thread_data.scheduler)

        # Cancel tasks in cross-thread queue
        while !isempty(impl.cross_thread_data.tasks_to_schedule)
            task = pop_front!(impl.cross_thread_data.tasks_to_schedule)
            if task !== nothing
                task_run!(task, TaskStatus.CANCELED)
            end
        end

        # Mutex doesn't need cleanup in Julia (SpinLock is GC'd)

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

        # Clean up local data (invokes on_object_removed callbacks)
        hash_table_clear!(event_loop.local_data)

        return nothing
    end

end # @static if Sys.isapple() || Sys.isbsd()
