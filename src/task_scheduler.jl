using EnumX

@enumx TaskStatus::UInt8 begin
    RUN_READY = 0
    CANCELED = 1
end

const _TASK_STATUS_STRINGS = (
    "<Running>",  # TaskStatus.RUN_READY == 0
    "<Canceled>", # TaskStatus.CANCELED == 1
)

# ── TaskFn: trim-safe type-erased callable for task callbacks ──
# Uses a @generated function to create per-closure-type @cfunction pointers.
# The callable is passed as the first C argument (Ref{F}), so no runtime
# closure trampolines are needed (works on ARM64).

struct _TaskCallWrapper <: Function end

function (::_TaskCallWrapper)(f, status::UInt8)
    f(status)
    return nothing
end

@generated function _task_gen_fptr(::Type{F}) where F
    quote
        @cfunction($(_TaskCallWrapper()), Cvoid, (Ref{$F}, UInt8))
    end
end

struct TaskFn
    ptr::Ptr{Cvoid}       # @cfunction pointer (specialized per callable type F)
    objptr::Ptr{Cvoid}    # pointer to the callable object
    _root::Any            # GC root — prevents collection, never dispatched on
end

function TaskFn(callable::F) where F
    ptr = _task_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return TaskFn(ptr, objptr, objref)
end

@inline function (f::TaskFn)(status::UInt8)::Nothing
    ccall(f.ptr, Cvoid, (Ptr{Cvoid}, UInt8), f.objptr, status)
    return nothing
end

# ── ScheduledTask ──

mutable struct ScheduledTask
    fn::TaskFn
    type_tag::String
    timestamp::UInt64
    scheduled::Bool
end

function ScheduledTask(fn::TaskFn; type_tag::AbstractString = "task")
    return ScheduledTask(fn, String(type_tag), UInt64(0), false)
end

timestamp_less(a, b) = a.timestamp < b.timestamp

mutable struct TaskScheduler
    timed::PriorityQueue{ScheduledTask, typeof(timestamp_less)}
    asap::Vector{ScheduledTask}
    running::Vector{ScheduledTask}
end

function TaskScheduler(; capacity::Integer = 8)
    timed = PriorityQueue{ScheduledTask}(timestamp_less; capacity = capacity)
    asap = ScheduledTask[]
    running = ScheduledTask[]
    return TaskScheduler(timed, asap, running)
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
    task.fn(UInt8(status))
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
    if !removed && !isempty(scheduler.running)
        idx = findfirst(x -> x === task, scheduler.running)
        if idx !== nothing
            # Avoid mutating the running list during execution; `run_all!` will
            # skip unscheduled tasks.
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
    # Move scheduled tasks to `running` before executing.
    # This ensures tasks scheduled by other tasks don't execute until the next tick.
    empty!(scheduler.running)
    scheduler.running, scheduler.asap = scheduler.asap, scheduler.running
    running = scheduler.running

    # Move due timed tasks into `running` (by priority order).
    while true
        next_task = peek(scheduler.timed)
        next_task === nothing && break
        if next_task.timestamp > current_time
            break
        end
        task = pop!(scheduler.timed)
        task === nothing && break
        push!(running, task)
    end

    # Run tasks in FIFO order.
    for task in running
        task.scheduled || continue
        task_run!(task, status)
    end
    empty!(running)
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
