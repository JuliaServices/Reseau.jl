mutable struct ThreadScheduler
    scheduler::TaskScheduler
    scheduling_queue::Deque{ScheduledTask}
    cancel_queue::Deque{ScheduledTask}
    lock::ReentrantLock
    cond::ConditionVariable
    @atomic should_exit::Bool
    worker::Union{Task, Nothing}
end

function _thread_scheduler_should_wake(ctx)
    ts = ctx
    current = Ref{UInt64}(0)
    if high_res_clock_get_ticks(current) != OP_SUCCESS
        return true
    end
    _, next_time = task_scheduler_has_tasks(ts.scheduler)
    should_exit = @atomic ts.should_exit
    return should_exit || !isempty(ts.scheduling_queue) || !isempty(ts.cancel_queue) || next_time <= current[]
end

function _drain_thread_scheduler_queue!(dest::Deque{ScheduledTask}, src::Deque{ScheduledTask})
    while !isempty(src)
        task = pop_front!(src)
        task === nothing && break
        push_back!(dest, task)
    end
    return nothing
end

function _thread_scheduler_loop(ts::ThreadScheduler)
    while !(@atomic ts.should_exit)
        pending = Deque{ScheduledTask}(16)
        cancel = Deque{ScheduledTask}(16)
        lock(ts.lock)
        _drain_thread_scheduler_queue!(pending, ts.scheduling_queue)
        _drain_thread_scheduler_queue!(cancel, ts.cancel_queue)
        unlock(ts.lock)
        for task in pending
            if task.timestamp != 0
                task_scheduler_schedule_future!(ts.scheduler, task, task.timestamp)
            else
                task_scheduler_schedule_now!(ts.scheduler, task)
            end
        end
        for task in cancel
            task_scheduler_cancel!(ts.scheduler, task)
        end
        current = Ref{UInt64}(0)
        if high_res_clock_get_ticks(current) != OP_SUCCESS
            Base.yield()
            continue
        end
        task_scheduler_run_all!(ts.scheduler, current[])
        _, next_time = task_scheduler_has_tasks(ts.scheduler)
        timeout = Int64(0)
        if next_time == typemax(UInt64)
            timeout = Int64(30) * Int64(TIMESTAMP_NANOS)
        elseif next_time > current[]
            timeout = Int64(next_time - current[])
        end
        if timeout > 0
            lock(ts.lock)
            condition_variable_wait_for_pred(ts.cond, ts.lock, timeout, _thread_scheduler_should_wake, ts)
            unlock(ts.lock)
        end
    end
    return nothing
end

function thread_scheduler_new(options::Union{ThreadOptions, Nothing} = nothing)
    _ = options
    scheduler = TaskScheduler()
    ts = ThreadScheduler(
        scheduler,
        Deque{ScheduledTask}(16),
        Deque{ScheduledTask}(16),
        ReentrantLock(),
        ConditionVariable(),
        false,
        nothing,
    )
    ts.worker = Base.errormonitor(Threads.@spawn _thread_scheduler_loop(ts))
    return ts
end

function thread_scheduler_acquire(::ThreadScheduler)
    return nothing
end

function thread_scheduler_release(scheduler::ThreadScheduler)
    @atomic scheduler.should_exit = true
    condition_variable_notify_all(scheduler.cond)
    scheduler.worker === nothing || wait(scheduler.worker)
    task_scheduler_clean_up!(scheduler.scheduler)
    return nothing
end

function thread_scheduler_schedule_future(scheduler::ThreadScheduler, task::ScheduledTask, time_to_run::UInt64)
    task.timestamp = time_to_run
    task.scheduled = true
    lock(scheduler.lock)
    push_back!(scheduler.scheduling_queue, task)
    unlock(scheduler.lock)
    condition_variable_notify_one(scheduler.cond)
    return nothing
end

function thread_scheduler_schedule_now(scheduler::ThreadScheduler, task::ScheduledTask)
    return thread_scheduler_schedule_future(scheduler, task, UInt64(0))
end

function thread_scheduler_cancel_task(scheduler::ThreadScheduler, task::ScheduledTask)
    lock(scheduler.lock)
    if !isempty(scheduler.scheduling_queue)
        remove!(scheduler.scheduling_queue, task; eq = (===))
    end
    push_back!(scheduler.cancel_queue, task)
    unlock(scheduler.lock)
    condition_variable_notify_one(scheduler.cond)
    return nothing
end
