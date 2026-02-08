using EnumX

@enumx TaskStatus::UInt8 begin
    RUN_READY = 0
    CANCELED = 1
end

const _TASK_STATUS_STRINGS = (
    "<Running>",  # TaskStatus.RUN_READY == 0
    "<Canceled>", # TaskStatus.CANCELED == 1
)

struct TaskFn
    f::Any
    ctx::Any
end

(task::TaskFn)(status::TaskStatus.T) = Base.invokelatest(task.f, task.ctx, status)

mutable struct ScheduledTask
    fn::TaskFn
    type_tag::String
    timestamp::UInt64
    scheduled::Bool
end

function ScheduledTask(fn, ctx; type_tag::AbstractString = "task")
    return ScheduledTask(TaskFn(fn, ctx), String(type_tag), UInt64(0), false)
end

mutable struct TaskScheduler{Less}
    timed::PriorityQueue{ScheduledTask, Less}
    asap::Vector{ScheduledTask}
end

function TaskScheduler(; capacity::Integer = 8)
    less = (a::ScheduledTask, b::ScheduledTask) -> a.timestamp < b.timestamp
    timed = PriorityQueue{ScheduledTask}(less; capacity = capacity)
    asap = ScheduledTask[]
    return TaskScheduler{typeof(less)}(timed, asap)
end

@inline function task_status_to_string(status::TaskStatus.T)
    idx = Int(status) + 1
    return 1 <= idx <= length(_TASK_STATUS_STRINGS) ? _TASK_STATUS_STRINGS[idx] : "<Unknown>"
end

function task_run!(task::ScheduledTask, status::TaskStatus.T)
    logf(
        LogLevel.TRACE,
        LS_COMMON_TASK_SCHEDULER,
        "id=%s: Running %s task with %s status",
        string(objectid(task)),
        task.type_tag,
        task_status_to_string(status),
    )
    task.scheduled = false
    task.fn(status)
    return nothing
end

function task_scheduler_has_tasks(scheduler::TaskScheduler)
    if !isempty(scheduler.asap)
        return true, UInt64(0)
    end
    next_task = peek(scheduler.timed)
    if next_task === nothing
        return false, typemax(UInt64)
    end
    return true, next_task.timestamp
end

function task_scheduler_schedule_now!(scheduler::TaskScheduler, task::ScheduledTask)
    logf(
        LogLevel.TRACE,
        LS_COMMON_TASK_SCHEDULER,
        "id=%s: Scheduling %s task for immediate execution",
        string(objectid(task)),
        task.type_tag,
    )
    task.timestamp = UInt64(0)
    task.scheduled = true
    push!(scheduler.asap, task)
    return nothing
end

function task_scheduler_schedule_future!(scheduler::TaskScheduler, task::ScheduledTask, time_to_run::UInt64)
    logf(
        LogLevel.TRACE,
        LS_COMMON_TASK_SCHEDULER,
        "id=%s: Scheduling %s task for future execution at time %d",
        string(objectid(task)),
        task.type_tag,
        time_to_run,
    )
    task.timestamp = time_to_run
    task.scheduled = true
    push!(scheduler.timed, task)
    return nothing
end

function task_scheduler_cancel!(scheduler::TaskScheduler, task::ScheduledTask)
    removed = false
    if !isempty(scheduler.asap)
        idx = findfirst(x -> x === task, scheduler.asap)
        if idx !== nothing
            deleteat!(scheduler.asap, idx)
            removed = true
        end
    end
    if !removed
        removed = remove!(scheduler.timed, task; eq = (===))
    end
    task_run!(task, TaskStatus.CANCELED)
    return nothing
end

function _run_due!(scheduler::TaskScheduler, current_time::UInt64, status::TaskStatus.T)
    while !isempty(scheduler.asap)
        task = popfirst!(scheduler.asap)
        task === nothing && break
        task_run!(task, status)
    end

    while true
        next_task = peek(scheduler.timed)
        next_task === nothing && break
        if next_task.timestamp > current_time
            break
        end
        task = pop!(scheduler.timed)
        task === nothing && break
        task_run!(task, status)
    end
    return nothing
end

function task_scheduler_run_all!(scheduler::TaskScheduler, current_time::UInt64)
    _run_due!(scheduler, current_time, TaskStatus.RUN_READY)
    return nothing
end

function task_scheduler_clean_up!(scheduler::TaskScheduler)
    while true
        has_tasks, _ = task_scheduler_has_tasks(scheduler)
        has_tasks || break
        _run_due!(scheduler, typemax(UInt64), TaskStatus.CANCELED)
    end
    empty!(scheduler.asap)
    clear!(scheduler.timed)
    return nothing
end
