mutable struct ThreadScheduler
    scheduler::TaskScheduler
    lock::ReentrantLock
    cond::ConditionVariable
    @atomic should_exit::Bool
    worker::Union{Task, Nothing}
end

function _thread_scheduler_loop(ts::ThreadScheduler)
    while !(@atomic ts.should_exit)
        has_tasks, next_time = task_scheduler_has_tasks(ts.scheduler)
        if !has_tasks
            condition_variable_wait_pred(ts.cond, ts.lock, _ -> (@atomic ts.should_exit) || task_scheduler_has_tasks(ts.scheduler)[1], nothing)
        end
        current = Ref{UInt64}(0)
        if high_res_clock_get_ticks(current) != OP_SUCCESS
            Base.yield()
            continue
        end
        task_scheduler_run_all!(ts.scheduler, current[])
        if next_time != typemax(UInt64)
            # yield to avoid busy loop
            Base.yield()
        end
    end
    return nothing
end

function thread_scheduler_new(options::Union{ThreadOptions, Nothing} = nothing)
    _ = options
    scheduler = TaskScheduler()
    ts = ThreadScheduler(scheduler, ReentrantLock(), ConditionVariable(), false, nothing)
    ts.worker = Threads.@spawn _thread_scheduler_loop(ts)
    return ts
end

function thread_scheduler_acquire(::ThreadScheduler)
    return nothing
end

function thread_scheduler_release(scheduler::ThreadScheduler)
    @atomic scheduler.should_exit = true
    condition_variable_notify_all(scheduler.cond)
    scheduler.worker === nothing || wait(scheduler.worker)
    return nothing
end

function thread_scheduler_schedule_future(scheduler::ThreadScheduler, task::ScheduledTask, time_to_run::UInt64)
    lock(scheduler.lock)
    task_scheduler_schedule_future!(scheduler.scheduler, task, time_to_run)
    unlock(scheduler.lock)
    condition_variable_notify_one(scheduler.cond)
    return nothing
end

function thread_scheduler_schedule_now(scheduler::ThreadScheduler, task::ScheduledTask)
    return thread_scheduler_schedule_future(scheduler, task, UInt64(0))
end

function thread_scheduler_cancel_task(scheduler::ThreadScheduler, task::ScheduledTask)
    lock(scheduler.lock)
    task_scheduler_cancel!(scheduler.scheduler, task)
    unlock(scheduler.lock)
    condition_variable_notify_one(scheduler.cond)
    return nothing
end
