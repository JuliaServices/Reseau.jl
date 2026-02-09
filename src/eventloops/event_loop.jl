# AWS IO Library - Event Loop Abstraction
# Port of aws-c-io/source/event_loop.c and include/aws/io/event_loop.h

# High resolution clock function - returns nanoseconds
function high_res_clock()::UInt64
    ticks = Ref{UInt64}(0)
    high_res_clock_get_ticks(ticks)
    return ticks[]
end

# Event loop options
struct EventLoopOptions
    clock::Function
    thread_options::Union{Nothing, ThreadOptions}
    parent_elg::Any  # EventLoopGroup or nothing
end

function EventLoopOptions(;
        clock = high_res_clock,
        thread_options::Union{Nothing, ThreadOptions} = nothing,
        parent_elg = nothing,
    )
    return EventLoopOptions(clock, thread_options, parent_elg)
end

# Event loop group options
struct EventLoopGroupOptions
    loop_count::UInt16
    shutdown_options::Union{shutdown_callback_options, Nothing}
    cpu_group::Any
    clock_override::Union{Function, Nothing}
end

function EventLoopGroupOptions(;
        loop_count::Integer = 0,
        shutdown_options = nothing,
        cpu_group = nothing,
        clock_override = nothing,
    )
    return EventLoopGroupOptions(
        UInt16(loop_count),
        shutdown_options,
        cpu_group,
        clock_override,
    )
end

function _cpu_group_value(cpu_group)
    if cpu_group === nothing
        return nothing
    end
    if cpu_group isa Base.RefValue
        return cpu_group[]
    end
    return cpu_group
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

# Event loop base structure (non-parametric, concrete per platform)
mutable struct EventLoop
    clock::Function
    local_data::IdDict{Any, EventLoopLocalObject}
    @atomic current_load_factor::Csize_t
    latest_tick_start::UInt64
    current_tick_latency_sum::Csize_t
    @atomic next_flush_time::UInt64
    base_elg::Any  # EventLoopGroup or nothing
    impl_data::PlatformEventLoop
    @atomic running::Bool
    @atomic should_stop::Bool
    thread::Union{Nothing, ThreadHandle}
end

function EventLoop(clock, impl_data::PlatformEventLoop)
    local_data = IdDict{Any, EventLoopLocalObject}()
    return EventLoop(
        clock,
        local_data,
        Csize_t(0),
        UInt64(0),
        Csize_t(0),
        UInt64(0),
        nothing,
        impl_data,
        false,
        false,
        nothing,
    )
end

# Event loop interface - platform backends (kqueue, epoll) implement these methods:
#   event_loop_run!, event_loop_stop!, event_loop_wait_for_stop_completion!,
#   event_loop_complete_destroy!, event_loop_schedule_task_now!,
#   event_loop_schedule_task_now_serialized!, event_loop_schedule_task_future!,
#   event_loop_cancel_task!, event_loop_subscribe_to_io_events!,
#   event_loop_unsubscribe_from_io_events!, event_loop_thread_is_callers_thread

# Start the destruction process (quick, non-blocking)
function event_loop_start_destroy!(event_loop::EventLoop)
    # Default implementation does nothing
    return nothing
end

# Destroy an event loop (blocking)
function event_loop_destroy!(event_loop::EventLoop)
    fatal_assert_bool(!event_loop_thread_is_callers_thread(event_loop), "destroy on loop thread", "<unknown>", 0)
    event_loop_start_destroy!(event_loop)
    event_loop_complete_destroy!(event_loop)
    return nothing
end

# Connect an IO handle to the event loop's completion port / queue (platform-specific)
# On Apple/BSD, the real implementation is in kqueue_event_loop.jl
@static if !(Sys.isapple() || Sys.isbsd() || Sys.iswindows())
function event_loop_connect_to_io_completion_port!(
        event_loop::EventLoop,
        handle::IoHandle,
    )::Union{Nothing, ErrorResult}
    return ErrorResult(raise_error(ERROR_PLATFORM_NOT_SUPPORTED))
end
end

# Free IO event resources for a handle (overridden by epoll on Linux)
@static if !Sys.islinux()
function event_loop_free_io_event_resources!(event_loop::EventLoop, handle::IoHandle)
    # Default implementation does nothing
    return nothing
end
end

# Get current clock time
function event_loop_current_clock_time(event_loop::EventLoop)::Union{UInt64, ErrorResult}
    return event_loop.clock()
end

# Local object management
function event_loop_fetch_local_object(
        event_loop::EventLoop,
        key,
    )::Union{EventLoopLocalObject, ErrorResult}
    debug_assert(event_loop_thread_is_callers_thread(event_loop))
    obj = get(event_loop.local_data, key, nothing)
    if obj === nothing
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end
    return obj::EventLoopLocalObject
end

function event_loop_put_local_object!(
        event_loop::EventLoop,
        obj::EventLoopLocalObject,
    )::Union{Nothing, ErrorResult}
    debug_assert(event_loop_thread_is_callers_thread(event_loop))
    event_loop.local_data[obj.key] = obj
    return nothing
end

function event_loop_remove_local_object!(
        event_loop::EventLoop,
        key,
    )::Union{EventLoopLocalObject, Nothing, ErrorResult}
    debug_assert(event_loop_thread_is_callers_thread(event_loop))
    obj = get(event_loop.local_data, key, nothing)
    if obj === nothing
        return nothing
    end
    removed_copy = EventLoopLocalObject(obj.key, obj.object, obj.on_object_removed)
    delete!(event_loop.local_data, key)
    _event_loop_local_object_destroy(obj)
    return removed_copy
end

# Load factor for load balancing
const LOAD_FACTOR_SLIDING_WINDOW_SIZE = 64
const LOAD_FACTOR_FLUSH_INTERVAL_SECS = UInt64(1)
const LOAD_FACTOR_STALE_SECS = UInt64(10)

@inline function _clock_nanos_to_secs(nanos::UInt64)::UInt64
    return nanos ÷ UInt64(1_000_000_000)
end

function event_loop_register_tick_start!(event_loop::EventLoop)
    current_time = event_loop.clock()
    return event_loop.latest_tick_start = current_time
end

function event_loop_register_tick_end!(event_loop::EventLoop)
    current_time = event_loop.clock()
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

function event_loop_get_load_factor(event_loop::EventLoop)::Csize_t
    current_time = event_loop.clock()
    current_time_secs = _clock_nanos_to_secs(current_time)
    next_flush_secs = @atomic event_loop.next_flush_time

    if current_time_secs > next_flush_secs + LOAD_FACTOR_STALE_SECS
        return Csize_t(0)
    end

    return @atomic event_loop.current_load_factor
end

# Create a new event loop based on platform
function event_loop_new(options::EventLoopOptions)::Union{EventLoop, ErrorResult}
    @static if Sys.islinux()
        return event_loop_new_with_epoll(options)
    elseif Sys.isapple() || Sys.isbsd()
        return event_loop_new_with_kqueue(options)
    elseif Sys.iswindows()
        return event_loop_new_with_iocp(options)
    else
        return ErrorResult(raise_error(ERROR_PLATFORM_NOT_SUPPORTED))
    end
end

# Event Loop Group for managing multiple event loops
mutable struct EventLoopGroup
    event_loops::Vector{EventLoop}
    shutdown_options::Union{shutdown_callback_options, Nothing}
    @atomic ref_count::Int
end

# Julia-idiomatic conveniences:
# - `event_loop_group_get_loop_at(elg, i)` is intentionally 0-based (aws-c-io parity).
# - `elg[i]` uses 1-based indexing like normal Julia collections.
Base.length(elg::EventLoopGroup) = length(elg.event_loops)
Base.getindex(elg::EventLoopGroup, i::Integer) = elg.event_loops[i]

# Create a new event loop group (creates and runs event loops)
function event_loop_group_new(options::EventLoopGroupOptions)
    loop_count = options.loop_count
    cpu_group_val = _cpu_group_value(options.cpu_group)
    if cpu_group_val !== nothing && loop_count == typemax(UInt16)
        cpu_count = (Int(cpu_group_val) == 0) ? Sys.CPU_THREADS : 0
        loop_count = UInt16(cpu_count > 0 ? min(cpu_count, typemax(UInt16)) : 1)
    end
    if loop_count == 0
        loop_count = UInt16(max(1, Sys.CPU_THREADS >> 1))
    end

    clock = options.clock_override === nothing ? high_res_clock : options.clock_override

    # Create first event loop
    first_opts = EventLoopOptions(; clock = clock)
    first_loop = event_loop_new(first_opts)
    if first_loop isa ErrorResult
        return first_loop
    end

    elg = EventLoopGroup(
        Vector{EventLoop}(),
        options.shutdown_options,
        1,
    )

    first_loop.base_elg = elg
    push!(elg.event_loops, first_loop)

    # Create remaining event loops
    for _ in 2:loop_count
        loop_opts = EventLoopOptions(; clock = clock, parent_elg = elg)
        loop = event_loop_new(loop_opts)
        if loop isa ErrorResult
            event_loop_group_destroy!(elg)
            return loop
        end
        push!(elg.event_loops, loop)
    end

    # Start event loops
    for i in 1:length(elg.event_loops)
        loop = elg.event_loops[i]
        result = event_loop_run!(loop)
        if result isa ErrorResult
            event_loop_group_destroy!(elg)
            return result
        end
    end

    return elg
end

function EventLoopGroup(options::EventLoopGroupOptions)
    return event_loop_group_new(options)
end

function event_loop_group_acquire!(elg::EventLoopGroup)
    @atomic elg.ref_count += 1
    return elg
end

function _event_loop_group_called_from_loop_thread(elg::EventLoopGroup)::Bool
    for i in 1:length(elg.event_loops)
        loop = elg.event_loops[i]
        loop === nothing && continue
        if event_loop_thread_is_callers_thread(loop)
            return true
        end
    end
    return false
end

function event_loop_group_release!(elg::EventLoopGroup)
    new_count = @atomic elg.ref_count -= 1
    if new_count > 0
        return nothing
    elseif new_count < 0
        logf(
            LogLevel.ERROR,
            LS_IO_EVENT_LOOP,
            "Event loop group ref_count underflow (ref_count=%d)",
            new_count,
        )
        return nothing
    end

    if _event_loop_group_called_from_loop_thread(elg)
        errormonitor(Threads.@spawn event_loop_group_destroy!(elg))
    else
        event_loop_group_destroy!(elg)
    end
    return nothing
end

function event_loop_group_destroy!(elg::EventLoopGroup)
    logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "Event loop group destroy")
    for i in 1:length(elg.event_loops)
        el = elg.event_loops[i]
        el === nothing && continue
        event_loop_destroy!(el)
    end
    empty!(elg.event_loops)
    if elg.shutdown_options !== nothing
        Base.invokelatest(
            elg.shutdown_options.shutdown_callback_fn,
            elg.shutdown_options.shutdown_callback_user_data,
        )
    end
    return nothing
end

const _DEFAULT_EVENT_LOOP_GROUP_LOCK = ReentrantLock()
const _DEFAULT_EVENT_LOOP_GROUP = Ref{Union{EventLoopGroup, Nothing}}(nothing)

"""
    default_event_loop_group() -> EventLoopGroup

Return a process-wide default `EventLoopGroup`.

This singleton is used by higher-level socket APIs (like `Sockets.TCPSocket`)
when no explicit `EventLoopGroup` is provided.
"""
function default_event_loop_group()::EventLoopGroup
    lock(_DEFAULT_EVENT_LOOP_GROUP_LOCK)
    try
        elg = _DEFAULT_EVENT_LOOP_GROUP[]
        if elg === nothing
            # Keep this single-loop to avoid surprising concurrency in downstream
            # consumers that "just want a default".
            elg = EventLoopGroup(EventLoopGroupOptions(; loop_count = 1))
            elg isa ErrorResult && error("Failed to create default EventLoopGroup: $(elg.code)")
            _DEFAULT_EVENT_LOOP_GROUP[] = elg
        end
        return elg::EventLoopGroup
    finally
        unlock(_DEFAULT_EVENT_LOOP_GROUP_LOCK)
    end
end

function event_loop_group_get_loop_count(elg::EventLoopGroup)::Csize_t
    return Csize_t(length(elg.event_loops))
end

function event_loop_group_get_loop_at(elg::EventLoopGroup, index::Integer)
    idx = Int(index) + 1  # Convert from 0-based to 1-based
    if idx < 1 || idx > length(elg.event_loops)
        return nothing
    end
    return elg.event_loops[idx]
end

# Best-of-two load balancing for getting the next event loop
function event_loop_group_get_next_loop(elg::EventLoopGroup)
    loop_count = length(elg.event_loops)
    if loop_count == 0
        return nothing
    end
    if loop_count == 1
        return elg.event_loops[1]
    end

    # Best of two random selection
    idx1 = rand(1:loop_count)
    idx2 = rand(1:loop_count)

    el1 = elg.event_loops[idx1]
    el2 = elg.event_loops[idx2]

    load1 = event_loop_get_load_factor(el1)
    load2 = event_loop_get_load_factor(el2)

    return load1 <= load2 ? el1 : el2
end

# Get group from event loop
function event_loop_group_acquire_from_event_loop(event_loop::EventLoop)::Union{EventLoopGroup, Nothing}
    if event_loop.base_elg === nothing
        return nothing
    end
    elg = event_loop.base_elg::EventLoopGroup
    return event_loop_group_acquire!(elg)
end

function event_loop_group_release_from_event_loop!(event_loop::EventLoop)
    if event_loop.base_elg !== nothing
        elg = event_loop.base_elg::EventLoopGroup
        event_loop_group_release!(elg)
    end
    return nothing
end

# -----------------------------------------------------------------------------
# Task-friendly sleep without libuv-backed `Timer`
#
# Base `sleep()` uses libuv timers. We implement a task-friendly delay by
# scheduling a wake-up task on an aws event loop and parking the current task.
# -----------------------------------------------------------------------------

function task_sleep_ns(event_loop::EventLoop, ns::Integer)::Nothing
    ns <= 0 && return nothing

    # Avoid deadlocking the event-loop thread.
    if event_loop_thread_is_callers_thread(event_loop)
        thread_sleep_ns(ns)
        return nothing
    end

    wake = Threads.Event()
    ctx = (wake = wake,)
    task = ScheduledTask(
        (ctx, _status) -> (notify(ctx.wake); nothing),
        ctx;
        type_tag = "task_sleep",
    )

    now = event_loop.clock()
    run_at = add_u64_saturating(now isa ErrorResult ? monotonic_time_ns() : now, UInt64(ns))
    event_loop_schedule_task_future!(event_loop, task, run_at)

    wait(wake)
    return nothing
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
