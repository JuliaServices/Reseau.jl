# AWS IO Library - Dispatch Queue Event Loop Implementation
# Port of aws-c-io/source/darwin/dispatch_queue_event_loop.c

@static if Sys.isapple()
    const libdispatch = "libSystem"
    const dispatch_queue_t = Ptr{Cvoid}
    const dispatch_queue_attr_t = Ptr{Cvoid}
    const dispatch_time_t = UInt64
    const dispatch_function_t = Ptr{Cvoid}

    const DISPATCH_QUEUE_SERIAL = dispatch_queue_attr_t(C_NULL)
    const DISPATCH_TIME_NOW = dispatch_time_t(0)
    const DISPATCH_QUEUE_MAX_FUTURE_SERVICE_INTERVAL = UInt64(1_000_000_000)

    @enumx DispatchLoopExecutionState::UInt8 begin
        SUSPENDED = 0
        RUNNING = 1
        SHUTTING_DOWN = 2
        TERMINATED = 3
    end

    mutable struct ScheduledIterationEntry
        timestamp::UInt64
        dispatch_loop::Any
    end

    mutable struct DispatchLoopSyncedData
        synced_data_lock::Mutex
        signal::ConditionVariable
        is_executing::Bool
        current_thread_id::thread_id_t
        execution_state::DispatchLoopExecutionState.T
        cross_thread_tasks::Deque{ScheduledTask}
        scheduled_iterations::Deque{ScheduledIterationEntry}
    end

    function DispatchLoopSyncedData()
        return DispatchLoopSyncedData(
            Mutex(),
            ConditionVariable(),
            false,
            thread_id_t(0),
            DispatchLoopExecutionState.SUSPENDED,
            Deque{ScheduledTask}(16),
            Deque{ScheduledIterationEntry}(16),
        )
    end

    mutable struct DispatchLoop
        dispatch_queue::dispatch_queue_t
        scheduler::TaskScheduler
        base_loop::Union{AbstractEventLoop, Nothing}
        synced_data::DispatchLoopSyncedData
    end

    function DispatchLoop()
        return DispatchLoop(C_NULL, TaskScheduler(), nothing, DispatchLoopSyncedData())
    end

    const DispatchQueueEventLoop = EventLoop{DispatchLoop, LD, Clock} where {LD, Clock}

    @inline function _dispatch_lock(loop::DispatchLoop)
        return mutex_lock(loop.synced_data.synced_data_lock)
    end

    @inline function _dispatch_unlock(loop::DispatchLoop)
        return mutex_unlock(loop.synced_data.synced_data_lock)
    end

    function _dispatch_queue_id()
        uuid_val = Ref{uuid}()
        if uuid_init(uuid_val) != OP_SUCCESS
            fatal_assert("uuid_init failed", "<unknown>", 0)
        end
        buf = ByteBuffer(Memory{UInt8}(undef, UUID_STR_LEN), Csize_t(0))
        if uuid_to_str(uuid_val, Ref(buf)) != OP_SUCCESS
            fatal_assert("uuid_to_str failed", "<unknown>", 0)
        end
        uuid_str = unsafe_string(pointer(buf.mem))
        return "com.amazonaws.commonruntime.eventloop." * uuid_str
    end

    @inline function _dispatch_queue_create(label::AbstractString)
        return @ccall libdispatch.dispatch_queue_create(
            label::Cstring,
            DISPATCH_QUEUE_SERIAL::dispatch_queue_attr_t,
        )::dispatch_queue_t
    end

    @inline _dispatch_suspend(queue::dispatch_queue_t) =
        @ccall libdispatch.dispatch_suspend(queue::dispatch_queue_t)::Cvoid

    @inline _dispatch_resume(queue::dispatch_queue_t) =
        @ccall libdispatch.dispatch_resume(queue::dispatch_queue_t)::Cvoid

    @inline _dispatch_release(queue::dispatch_queue_t) =
        @ccall libdispatch.dispatch_release(queue::dispatch_queue_t)::Cvoid

    @inline function _dispatch_time(delta_nanos::UInt64)
        return @ccall libdispatch.dispatch_time(
            DISPATCH_TIME_NOW::dispatch_time_t,
            Int64(delta_nanos)::Int64,
        )::dispatch_time_t
    end

    @inline function _dispatch_async(queue::dispatch_queue_t, ctx::Ptr{Cvoid}, func::dispatch_function_t)
        @ccall libdispatch.dispatch_async_f(
            queue::dispatch_queue_t,
            ctx::Ptr{Cvoid},
            func::dispatch_function_t,
        )::Cvoid
        return nothing
    end

    @inline function _dispatch_after(queue::dispatch_queue_t, when::dispatch_time_t, ctx::Ptr{Cvoid}, func::dispatch_function_t)
        @ccall libdispatch.dispatch_after_f(
            when::dispatch_time_t,
            queue::dispatch_queue_t,
            ctx::Ptr{Cvoid},
            func::dispatch_function_t,
        )::Cvoid
        return nothing
    end

    function _dispatch_should_schedule_iteration(
            scheduled_iterations::Deque{ScheduledIterationEntry},
            proposed_iteration_time::UInt64,
        )
        isempty(scheduled_iterations) && return true
        entry = front(scheduled_iterations)
        entry === nothing && return true
        return entry.timestamp > proposed_iteration_time
    end

    function _dispatch_try_schedule_new_iteration!(dispatch_loop::DispatchLoop, timestamp::UInt64)
        synced = dispatch_loop.synced_data
        if synced.execution_state != DispatchLoopExecutionState.RUNNING || synced.is_executing
            return nothing
        end

        now_ns = event_loop_current_clock_time(dispatch_loop.base_loop)
        now_ns = now_ns isa ErrorResult ? UInt64(0) : now_ns
        delta = timestamp > now_ns ? timestamp - now_ns : UInt64(0)
        delta = min(delta, DISPATCH_QUEUE_MAX_FUTURE_SERVICE_INTERVAL)
        clamped_timestamp = now_ns + delta

        if !_dispatch_should_schedule_iteration(synced.scheduled_iterations, clamped_timestamp)
            return nothing
        end

        entry = ScheduledIterationEntry(clamped_timestamp, dispatch_loop)
        push_front!(synced.scheduled_iterations, entry)

        entry_ptr = pointer_from_objref(entry)
        run_ptr = _dispatch_run_iteration_ptr()
        if delta == 0
            _dispatch_async(dispatch_loop.dispatch_queue, entry_ptr, run_ptr)
            logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "dispatch queue scheduling run iteration")
        else
            when = _dispatch_time(delta)
            _dispatch_after(dispatch_loop.dispatch_queue, when, entry_ptr, run_ptr)
            logf(
                LogLevel.TRACE,
                LS_IO_EVENT_LOOP,
                "dispatch queue scheduling future iteration in %d ns",
                delta,
            )
        end

        return nothing
    end

    function _dispatch_run_iteration(entry::ScheduledIterationEntry)
        dispatch_loop = entry.dispatch_loop::DispatchLoop
        synced = dispatch_loop.synced_data

        _dispatch_lock(dispatch_loop)
        remove!(synced.scheduled_iterations, entry; eq = (===))

        if synced.execution_state == DispatchLoopExecutionState.SHUTTING_DOWN
            if isempty(synced.scheduled_iterations)
                synced.execution_state = DispatchLoopExecutionState.TERMINATED
                condition_variable_notify_all(synced.signal)
            end
            _dispatch_unlock(dispatch_loop)
            return nothing
        end

        synced.current_thread_id = thread_id_t(Threads.threadid())
        synced.is_executing = true

        local_cross_thread = synced.cross_thread_tasks
        synced.cross_thread_tasks = Deque{ScheduledTask}(16)
        _dispatch_unlock(dispatch_loop)

        while !isempty(local_cross_thread)
            task = pop_front!(local_cross_thread)
            task === nothing && break
            if task.timestamp == 0
                task_scheduler_schedule_now!(dispatch_loop.scheduler, task)
            else
                task_scheduler_schedule_future!(dispatch_loop.scheduler, task, task.timestamp)
            end
        end

        event_loop_register_tick_start!(dispatch_loop.base_loop)
        now_ns = event_loop_current_clock_time(dispatch_loop.base_loop)
        now_ns = now_ns isa ErrorResult ? UInt64(0) : now_ns
        task_scheduler_run_all!(dispatch_loop.scheduler, now_ns)
        event_loop_register_tick_end!(dispatch_loop.base_loop)

        _dispatch_lock(dispatch_loop)
        synced.is_executing = false

        should_schedule = false
        schedule_time = UInt64(0)
        if !isempty(synced.cross_thread_tasks)
            should_schedule = true
        else
            has_tasks, next_time = task_scheduler_has_tasks(dispatch_loop.scheduler)
            if has_tasks
                should_schedule = true
                schedule_time = next_time
            end
        end

        if should_schedule
            _dispatch_try_schedule_new_iteration!(dispatch_loop, schedule_time)
        end

        if synced.execution_state == DispatchLoopExecutionState.SHUTTING_DOWN &&
                isempty(synced.scheduled_iterations)
            synced.execution_state = DispatchLoopExecutionState.TERMINATED
            condition_variable_notify_all(synced.signal)
        end

        _dispatch_unlock(dispatch_loop)
        return nothing
    end

    function _dispatch_run_iteration_c(entry_ptr::Ptr{Cvoid})
        entry = unsafe_pointer_to_objref(entry_ptr)::ScheduledIterationEntry
        _dispatch_run_iteration(entry)
        return nothing
    end

    const DISPATCH_RUN_ITERATION_C = Ref{dispatch_function_t}(C_NULL)

    function _dispatch_run_iteration_ptr()
        ptr = DISPATCH_RUN_ITERATION_C[]
        if ptr == C_NULL
            DISPATCH_RUN_ITERATION_C[] = @cfunction(_dispatch_run_iteration_c, Cvoid, (Ptr{Cvoid},))
            ptr = DISPATCH_RUN_ITERATION_C[]
        end
        return ptr
    end

    function _dispatch_queue_purge_cross_thread_tasks!(dispatch_loop::DispatchLoop)
        synced = dispatch_loop.synced_data
        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "dispatch queue purge cross-thread tasks")

        _dispatch_lock(dispatch_loop)
        synced.current_thread_id = thread_id_t(Threads.threadid())
        synced.is_executing = true
        _dispatch_unlock(dispatch_loop)

        task_scheduler_clean_up!(dispatch_loop.scheduler)

        done = false
        while !done
            _dispatch_lock(dispatch_loop)
            local_cross_thread = synced.cross_thread_tasks
            synced.cross_thread_tasks = Deque{ScheduledTask}(16)
            _dispatch_unlock(dispatch_loop)

            if isempty(local_cross_thread)
                done = true
            end

            while !isempty(local_cross_thread)
                task = pop_front!(local_cross_thread)
                task === nothing && break
                task_run!(task, TaskStatus.CANCELED)
            end
        end

        _dispatch_lock(dispatch_loop)
        synced.is_executing = false
        _dispatch_unlock(dispatch_loop)
        return nothing
    end

    function event_loop_new_with_dispatch_queue(options::EventLoopOptions)::Union{EventLoop, ErrorResult}
        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "Initializing Dispatch Queue Event Loop")

        dispatch_loop = DispatchLoop()
        event_loop = EventLoop(options.clock, dispatch_loop)
        dispatch_loop.base_loop = event_loop
        event_loop.base_elg = options.parent_elg

        thread_increment_unjoined_count()

        queue_id = _dispatch_queue_id()
        queue = _dispatch_queue_create(queue_id)
        if queue == C_NULL
            thread_decrement_unjoined_count()
            return ErrorResult(raise_error(ERROR_SYS_CALL_FAILURE))
        end

        dispatch_loop.dispatch_queue = queue
        _dispatch_suspend(queue)

        logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "dispatch queue created with id: %s", queue_id)

        return event_loop
    end

    function event_loop_start_destroy!(event_loop::DispatchQueueEventLoop)
        dispatch_loop = event_loop.impl_data
        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "dispatch queue start destroy")

        _dispatch_lock(dispatch_loop)
        state = dispatch_loop.synced_data.execution_state
        fatal_assert_bool(
            state == DispatchLoopExecutionState.RUNNING || state == DispatchLoopExecutionState.SUSPENDED,
            "dispatch loop execution_state invalid",
            "<unknown>",
            0,
        )
        if state == DispatchLoopExecutionState.SUSPENDED
            _dispatch_resume(dispatch_loop.dispatch_queue)
        end
        dispatch_loop.synced_data.execution_state = DispatchLoopExecutionState.SHUTTING_DOWN
        _dispatch_unlock(dispatch_loop)
        return nothing
    end

    function _dispatch_wait_for_terminated_state(ctx)
        dispatch_loop = ctx::DispatchLoop
        return dispatch_loop.synced_data.execution_state == DispatchLoopExecutionState.TERMINATED
    end

    function event_loop_complete_destroy!(event_loop::DispatchQueueEventLoop)
        dispatch_loop = event_loop.impl_data
        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "dispatch queue complete destroy")

        fatal_assert_bool(!event_loop_thread_is_callers_thread(event_loop), "destroy on loop thread", "<unknown>", 0)

        _dispatch_lock(dispatch_loop)
        if dispatch_loop.synced_data.execution_state == DispatchLoopExecutionState.SHUTTING_DOWN &&
                isempty(dispatch_loop.synced_data.scheduled_iterations) &&
                !dispatch_loop.synced_data.is_executing
            dispatch_loop.synced_data.execution_state = DispatchLoopExecutionState.TERMINATED
            condition_variable_notify_all(dispatch_loop.synced_data.signal)
        end
        condition_variable_wait_pred(
            dispatch_loop.synced_data.signal,
            dispatch_loop.synced_data.synced_data_lock,
            _dispatch_wait_for_terminated_state,
            dispatch_loop,
        )
        _dispatch_unlock(dispatch_loop)

        _dispatch_queue_purge_cross_thread_tasks!(dispatch_loop)

        _dispatch_release(dispatch_loop.dispatch_queue)
        dispatch_loop.dispatch_queue = C_NULL

        thread_decrement_unjoined_count()
        return nothing
    end

    function event_loop_run!(event_loop::DispatchQueueEventLoop)::Union{Nothing, ErrorResult}
        dispatch_loop = event_loop.impl_data

        _dispatch_lock(dispatch_loop)
        if dispatch_loop.synced_data.execution_state == DispatchLoopExecutionState.SUSPENDED
            logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "starting dispatch queue event loop")
            dispatch_loop.synced_data.execution_state = DispatchLoopExecutionState.RUNNING
            _dispatch_resume(dispatch_loop.dispatch_queue)
            _dispatch_try_schedule_new_iteration!(dispatch_loop, UInt64(0))
        end
        _dispatch_unlock(dispatch_loop)

        @atomic event_loop.running = true
        return nothing
    end

    function event_loop_stop!(event_loop::DispatchQueueEventLoop)::Union{Nothing, ErrorResult}
        dispatch_loop = event_loop.impl_data

        _dispatch_lock(dispatch_loop)
        if dispatch_loop.synced_data.execution_state == DispatchLoopExecutionState.RUNNING
            dispatch_loop.synced_data.execution_state = DispatchLoopExecutionState.SUSPENDED
            logf(LogLevel.INFO, LS_IO_EVENT_LOOP, "suspending dispatch queue event loop")
            _dispatch_suspend(dispatch_loop.dispatch_queue)
        end
        _dispatch_unlock(dispatch_loop)

        @atomic event_loop.should_stop = true
        @atomic event_loop.running = false
        return nothing
    end

    function event_loop_wait_for_stop_completion!(event_loop::DispatchQueueEventLoop)::Union{Nothing, ErrorResult}
        return nothing
    end

    function event_loop_schedule_task_now!(event_loop::DispatchQueueEventLoop, task::ScheduledTask)
        dispatch_loop = event_loop.impl_data
        task.timestamp = UInt64(0)
        task.scheduled = true
        _dispatch_lock(dispatch_loop)
        push_back!(dispatch_loop.synced_data.cross_thread_tasks, task)
        _dispatch_try_schedule_new_iteration!(dispatch_loop, UInt64(0))
        _dispatch_unlock(dispatch_loop)
        return nothing
    end

    function event_loop_schedule_task_now_serialized!(event_loop::DispatchQueueEventLoop, task::ScheduledTask)
        return event_loop_schedule_task_now!(event_loop, task)
    end

    function event_loop_schedule_task_future!(
            event_loop::DispatchQueueEventLoop,
            task::ScheduledTask,
            run_at_nanos::UInt64,
        )
        dispatch_loop = event_loop.impl_data
        task.timestamp = run_at_nanos
        task.scheduled = true
        _dispatch_lock(dispatch_loop)
        push_back!(dispatch_loop.synced_data.cross_thread_tasks, task)
        _dispatch_try_schedule_new_iteration!(dispatch_loop, run_at_nanos)
        _dispatch_unlock(dispatch_loop)
        return nothing
    end

    function event_loop_cancel_task!(event_loop::DispatchQueueEventLoop, task::ScheduledTask)
        dispatch_loop = event_loop.impl_data
        logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "dispatch queue cancelling %s task", task.type_tag)

        if !task.scheduled
            return nothing
        end

        removed = false
        _dispatch_lock(dispatch_loop)
        if !isempty(dispatch_loop.synced_data.cross_thread_tasks)
            removed = remove!(dispatch_loop.synced_data.cross_thread_tasks, task; eq = (===))
        end
        _dispatch_unlock(dispatch_loop)

        if removed
            task_run!(task, TaskStatus.CANCELED)
            return nothing
        end

        task_scheduler_cancel!(dispatch_loop.scheduler, task)
        return nothing
    end

    function event_loop_connect_to_io_completion_port!(
            event_loop::DispatchQueueEventLoop,
            handle::IoHandle,
        )::Union{Nothing, ErrorResult}
        if handle.set_queue == C_NULL
            return ErrorResult(raise_error(ERROR_INVALID_ARGUMENT))
        end
        dispatch_loop = event_loop.impl_data
        ccall(
            handle.set_queue,
            Cvoid,
            (Ptr{IoHandle}, Ptr{Cvoid}),
            Ref(handle),
            dispatch_loop.dispatch_queue,
        )
        return nothing
    end

    function event_loop_subscribe_to_io_events!(
            event_loop::DispatchQueueEventLoop,
            handle::IoHandle,
            events::Int,
            on_event::OnEventCallback,
            user_data,
        )::Union{Nothing, ErrorResult}
        _ = handle
        _ = events
        _ = on_event
        _ = user_data
        logf(
            LogLevel.ERROR,
            LS_IO_EVENT_LOOP,
            "subscribe_to_io_events not supported for dispatch queue event loops",
        )
        return ErrorResult(raise_error(ERROR_PLATFORM_NOT_SUPPORTED))
    end

    function event_loop_unsubscribe_from_io_events!(
            event_loop::DispatchQueueEventLoop,
            handle::IoHandle,
        )::Union{Nothing, ErrorResult}
        _ = handle
        logf(
            LogLevel.ERROR,
            LS_IO_EVENT_LOOP,
            "unsubscribe_from_io_events not supported for dispatch queue event loops",
        )
        return ErrorResult(raise_error(ERROR_PLATFORM_NOT_SUPPORTED))
    end

    function event_loop_free_io_event_resources!(event_loop::DispatchQueueEventLoop, handle::IoHandle)
        _ = event_loop
        _ = handle
        return nothing
    end

    function event_loop_thread_is_callers_thread(event_loop::DispatchQueueEventLoop)::Bool
        dispatch_loop = event_loop.impl_data
        _dispatch_lock(dispatch_loop)
        result = dispatch_loop.synced_data.is_executing &&
            thread_thread_id_equal(
            dispatch_loop.synced_data.current_thread_id,
            thread_id_t(Threads.threadid()),
        )
        _dispatch_unlock(dispatch_loop)
        return result
    end
end
