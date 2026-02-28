# Event types for IO event subscriptions (bitmask)
@enumx IoEventType::UInt32 begin
    READABLE = 1
    WRITABLE = 2
    REMOTE_HANG_UP = 4
    CLOSED = 8
    ERROR = 16
end

# Platform-specific event loop implementation type
const PlatformEventLoop = @static if Sys.islinux()
    EpollEventLoop
elseif Sys.isapple() || Sys.isbsd()
    KqueueEventLoop
elseif Sys.iswindows()
    IocpEventLoop
else
    # Fallback — will fail at runtime
    Any
end

# Event loop base structure (impl concrete per platform)
mutable struct EventLoop
    message_pool::Union{MessagePool, Nothing}
    @atomic current_load_factor::Csize_t
    latest_tick_start::UInt64
    current_tick_latency_sum::Csize_t
    @atomic next_flush_time::UInt64
    impl::PlatformEventLoop
    @atomic running::Bool
    @atomic should_stop::Bool
    @atomic semaphore::Csize_t
    cond::Threads.Condition
    thread::Union{Nothing, ForeignThread}
end

EventLoop(impl::PlatformEventLoop) = EventLoop(nothing, Csize_t(0), UInt64(0), Csize_t(0), UInt64(0), impl, false, false, Csize_t(0), Threads.Condition(), nothing)

function EventLoop()
    @static if Sys.islinux()
        return event_loop_new_with_epoll()
    elseif Sys.isapple() || Sys.isbsd()
        return event_loop_new_with_kqueue()
    elseif Sys.iswindows()
        return event_loop_new_with_iocp()
    else
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end
end

Base.acquire(event_loop::EventLoop) = @atomic event_loop.semaphore += 1

function Base.release(event_loop::EventLoop)
    remaining = @atomic event_loop.semaphore -= 1
    if remaining == 0
        lock(event_loop.cond)
        try
            notify(event_loop.cond; all = true)
        finally
            unlock(event_loop.cond)
        end
    end
    return remaining
end

schedule_task_now!(callable::F, event_loop::EventLoop; kw...) where {F} = schedule_task_now!(event_loop, ScheduledTask(callable; kw...))
schedule_task_future!(callable::F, event_loop::EventLoop, run_at_nanos::UInt64; kw...) where {F} = schedule_task_future!(event_loop, ScheduledTask(callable; kw...), run_at_nanos)
run!(event_loop::EventLoop) = run!(event_loop, event_loop.impl)
stop!(event_loop::EventLoop) = stop!(event_loop, event_loop.impl)
wait_for_stop_completion(event_loop::EventLoop) = wait_for_stop_completion(event_loop, event_loop.impl)
schedule_task_now!(event_loop::EventLoop, task::ScheduledTask) = schedule_task_now!(event_loop, event_loop.impl, task)
schedule_task_now_serialized!(event_loop::EventLoop, task::ScheduledTask) = schedule_task_now_serialized!(event_loop, event_loop.impl, task)
schedule_task_future!(event_loop::EventLoop, task::ScheduledTask, run_at_nanos::UInt64) = schedule_task_future!(event_loop, event_loop.impl, task, run_at_nanos)
cancel_task!(event_loop::EventLoop, task::ScheduledTask) = cancel_task!(event_loop, event_loop.impl, task)
subscribe_to_io_events!(event_loop::EventLoop, handle::IoHandle, events::Int, on_event::F) where {F} =
    subscribe_to_io_events!(event_loop, event_loop.impl, handle, events, on_event)
unsubscribe_from_io_events!(event_loop::EventLoop, handle::IoHandle) =
    unsubscribe_from_io_events!(event_loop, event_loop.impl, handle)
event_loop_thread_is_callers_thread(event_loop::EventLoop) =
    event_loop_thread_is_callers_thread(event_loop, event_loop.impl)

connect_to_io_completion_port(event_loop::EventLoop, impl, handle::IoHandle) = nothing
connect_to_io_completion_port(event_loop::EventLoop, handle::IoHandle) =
    connect_to_io_completion_port(event_loop, event_loop.impl, handle)

function Base.close(event_loop::EventLoop)
    event_loop_thread_is_callers_thread(event_loop) && error("close on loop thread")
    lock(event_loop.cond)
    try
        while event_loop.semaphore > 0
            wait(event_loop.cond)
        end
    finally
        unlock(event_loop.cond)
    end
    close(event_loop, event_loop.impl)
    if event_loop.message_pool !== nothing
        try; close(event_loop.message_pool); catch; end
        event_loop.message_pool = nothing
    end
    return nothing
end

close(event_loop::EventLoop, impl) = close(impl)

# Load factor for load balancing
const LOAD_FACTOR_SLIDING_WINDOW_SIZE = 64
const LOAD_FACTOR_FLUSH_INTERVAL_SECS = UInt64(1)
const LOAD_FACTOR_STALE_SECS = UInt64(10)

_clock_nanos_to_secs(nanos::UInt64)::UInt64 = nanos ÷ UInt64(1_000_000_000)

function register_tick_start!(event_loop::EventLoop)
    return event_loop.latest_tick_start = clock_now_ns()
end

function register_tick_end!(event_loop::EventLoop)
    current_time = clock_now_ns()
    latency = current_time - event_loop.latest_tick_start

    # Saturating add into current_tick_latency_sum
    latency_sz = Csize_t(min(latency, UInt64(typemax(Csize_t))))
    if event_loop.current_tick_latency_sum > typemax(Csize_t) - latency_sz
        event_loop.current_tick_latency_sum = typemax(Csize_t)
    else
        event_loop.current_tick_latency_sum += latency_sz
    end

    event_loop.latest_tick_start = UInt64(0)

    next_flush_secs = @atomic event_loop.next_flush_time
    end_tick_secs = _clock_nanos_to_secs(current_time)
    return if end_tick_secs > next_flush_secs
        @atomic event_loop.current_load_factor = event_loop.current_tick_latency_sum
        event_loop.current_tick_latency_sum = 0
        @atomic event_loop.next_flush_time = end_tick_secs + LOAD_FACTOR_FLUSH_INTERVAL_SECS
    end
end

function load_factor(event_loop::EventLoop)::Csize_t
    current_time = clock_now_ns()
    current_time_secs = _clock_nanos_to_secs(current_time)
    next_flush_secs = @atomic event_loop.next_flush_time
    if current_time_secs > next_flush_secs + LOAD_FACTOR_STALE_SECS
        return Csize_t(0)
    end
    return @atomic event_loop.current_load_factor
end

function task_sleep_ns(event_loop::EventLoop, ns::Integer)::Nothing
    ns <= 0 && return nothing

    # Avoid deadlocking the event-loop thread.
    if event_loop_thread_is_callers_thread(event_loop)
        thread_sleep_ns(ns)
        return nothing
    end

    wake = Base.Threads.Event()

    now = clock_now_ns()
    run_at = add_u64_saturating(now, UInt64(ns))
    schedule_task_future!(event_loop, run_at; type_tag = "task_sleep") do _
        try; notify(wake); catch; end
        return nothing
    end
    return wait(wake)
end

function task_sleep_s(event_loop::EventLoop, seconds::Real)::Nothing
    seconds <= 0 && return nothing
    isfinite(seconds) || return (raise_error(ERROR_INVALID_ARGUMENT); nothing)
    ns_f = Float64(seconds) * Float64(TIMESTAMP_NANOS)
    ns_f <= 0 && return nothing
    ns = ns_f >= Float64(typemax(UInt64)) ? typemax(UInt64) : UInt64(round(ns_f))
    task_sleep_ns(event_loop, ns)
    return nothing
end

mutable struct EventLoopGroup
    event_loops::Vector{EventLoop}
    @atomic destroyed::Bool
end

function EventLoopGroup(; loop_count::Integer = 0, cpu_group::Union{Nothing, Integer} = nothing)
    loop_count = loop_count
    if cpu_group !== nothing && loop_count == typemax(UInt16)
        cpu_count = (Int(cpu_group) == 0) ? Sys.CPU_THREADS : 0
        loop_count = UInt16(cpu_count > 0 ? min(cpu_count, typemax(UInt16)) : 1)
    end
    if loop_count == 0
        loop_count = UInt16(max(1, Sys.CPU_THREADS >> 1))
    end
    loops = EventLoop[]
    for _ in 1:loop_count
        loop = EventLoop()
        push!(loops, loop)
    end
    # Start event loops
    for loop in loops
        run!(loop)
    end
    return EventLoopGroup(loops, false)
end

function _close(elg::EventLoopGroup)::Nothing
    foreach(Base.close, elg.event_loops)
    return nothing
end

function Base.close(elg::EventLoopGroup)
    if !(@atomicreplace elg.destroyed false => true).success
        return nothing
    end

    # if called from loop thread, schedule a task to close the event loops
    for loop in elg.event_loops
        if event_loop_thread_is_callers_thread(loop)
            wait(errormonitor(Threads.@spawn _close(elg)))
            return nothing
        end
    end
    _close(elg)
    return nothing
end

const EVENT_LOOP_GROUP = OncePerProcess(() -> EventLoopGroup())
const DEFAULT_EVENT_LOOP_GROUP = ScopedValue{EventLoopGroup}()

function with_event_loop_group(f; kw...)
    return @with DEFAULT_EVENT_LOOP_GROUP => EventLoopGroup(; kw...) f()
end

get_event_loop_group() = isassigned(DEFAULT_EVENT_LOOP_GROUP) ? DEFAULT_EVENT_LOOP_GROUP[] : EVENT_LOOP_GROUP()
loop_count(elg::EventLoopGroup) = length(elg.event_loops)

# Best-of-two load balancing for getting the next event loop
get_next_event_loop() = get_next_event_loop(get_event_loop_group())

function get_next_event_loop(elg::EventLoopGroup)
    loop_count = length(elg.event_loops)
    loop_count == 0 && throw(ArgumentError("Event loop group is empty"))
    loop_count == 1 && return elg.event_loops[1]
    # Best of two random selection
    idx1 = rand(1:loop_count)
    idx2 = rand(1:loop_count)
    el1 = elg.event_loops[idx1]
    el2 = elg.event_loops[idx2]
    load1 = load_factor(el1)
    load2 = load_factor(el2)
    return load1 <= load2 ? el1 : el2
end
