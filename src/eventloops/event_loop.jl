# AWS IO Library - Event Loop Abstraction
# Port of aws-c-io/source/event_loop.c and include/aws/io/event_loop.h

# High resolution clock function - returns nanoseconds
function high_res_clock()::UInt64
    ticks = Ref{UInt64}(0)
    high_res_clock_get_ticks(ticks)
    return ticks[]
end

# Concrete clock source variants used by event loops and host resolver.
struct HighResClock end

struct RefClock
    value::Base.RefValue{UInt64}
end

RefClock(value::Integer) = RefClock(Ref(UInt64(value)))

mutable struct SequenceClock
    values::Vector{UInt64}
    index::Int
end

function SequenceClock(values::AbstractVector{UInt64})
    return SequenceClock(copy(values), 0)
end

function SequenceClock(values::AbstractVector{<:Integer})
    converted = Vector{UInt64}(undef, length(values))
    @inbounds for i in eachindex(values)
        converted[i] = UInt64(values[i])
    end
    return SequenceClock(converted, 0)
end

const ClockSource = Union{HighResClock, RefClock, SequenceClock}

@inline clock_now_ns(::HighResClock)::UInt64 = high_res_clock()
@inline clock_now_ns(clock::RefClock)::UInt64 = clock.value[]

@inline function clock_now_ns(clock::SequenceClock)::UInt64
    values = clock.values
    isempty(values) && return UInt64(0)
    next_index = min(clock.index + 1, length(values))
    clock.index = next_index
    return values[next_index]
end

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

# Event loop base structure (non-parametric, concrete per platform)
mutable struct EventLoop
    clock::ClockSource
    message_pool::Union{MessagePool, Nothing}
    @atomic current_load_factor::Csize_t
    latest_tick_start::UInt64
    current_tick_latency_sum::Csize_t
    @atomic next_flush_time::UInt64
    impl_data::PlatformEventLoop
    @atomic running::Bool
    @atomic should_stop::Bool
    thread::Union{Nothing, ForeignThread}
end

function EventLoop(clock::ClockSource, impl_data::PlatformEventLoop)
    return EventLoop(
        clock,
        nothing,
        Csize_t(0),
        UInt64(0),
        Csize_t(0),
        UInt64(0),
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

function event_loop_subscribe_to_io_events!(
        event_loop::EventLoop,
        handle::IoHandle,
        events::Int,
        on_event::F,
        user_data::Any,
    ) where {F}
    return event_loop_subscribe_to_io_events!(
        event_loop,
        handle,
        events,
        EventCallable((event_bits::Int) -> on_event(event_loop, handle, event_bits, user_data)),
    )
end

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
    )::Nothing
    throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
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
function event_loop_current_clock_time(event_loop::EventLoop)::UInt64
    return clock_now_ns(event_loop.clock)
end

# Shared resource cleanup used by all platform backends.
function _event_loop_clean_up_shared_resources!(event_loop::EventLoop)
    pool = event_loop.message_pool
    pool === nothing && return nothing

    try
        message_pool_clean_up!(pool)
    finally
        event_loop.message_pool = nothing
    end

    return nothing
end

# s2n thread-exit cleanup hook point.
# Backends call this unconditionally on thread exit; default behavior is no-op.
@inline function event_loop_thread_exit_s2n_cleanup!(event_loop::EventLoop)::Nothing
    return event_loop_thread_exit_s2n_cleanup!(event_loop.impl_data)
end

event_loop_thread_exit_s2n_cleanup!(::Any)::Nothing = nothing

# Load factor for load balancing
const LOAD_FACTOR_SLIDING_WINDOW_SIZE = 64
const LOAD_FACTOR_FLUSH_INTERVAL_SECS = UInt64(1)
const LOAD_FACTOR_STALE_SECS = UInt64(10)

@inline function _clock_nanos_to_secs(nanos::UInt64)::UInt64
    return nanos ÷ UInt64(1_000_000_000)
end

function event_loop_register_tick_start!(event_loop::EventLoop)
    current_time = clock_now_ns(event_loop.clock)
    return event_loop.latest_tick_start = current_time
end

function event_loop_register_tick_end!(event_loop::EventLoop)
    current_time = clock_now_ns(event_loop.clock)
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
    current_time = clock_now_ns(event_loop.clock)
    current_time_secs = _clock_nanos_to_secs(current_time)
    next_flush_secs = @atomic event_loop.next_flush_time

    if current_time_secs > next_flush_secs + LOAD_FACTOR_STALE_SECS
        return Csize_t(0)
    end

    return @atomic event_loop.current_load_factor
end

# Create a new event loop based on platform
function event_loop_new(clock::ClockSource = HighResClock())::EventLoop
    @static if Sys.islinux()
        return event_loop_new_with_epoll(clock)
    elseif Sys.isapple() || Sys.isbsd()
        return event_loop_new_with_kqueue(clock)
    elseif Sys.iswindows()
        return event_loop_new_with_iocp(clock)
    else
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end
end

# Event Loop Group for managing multiple event loops
mutable struct EventLoopGroup
    event_loops::Vector{EventLoop}
    lease_lock::ReentrantLock
    active_lease_ids::Set{UInt64}
    next_lease_id::UInt64
    @atomic close_requested::Bool
    @atomic destroying::Bool
    @atomic destroyed::Bool
end

struct EventLoopGroupLease
    group::EventLoopGroup
    lease_id::UInt64
end

# Julia-idiomatic conveniences:
# - `event_loop_group_get_loop_at(elg, i)` is intentionally 0-based (aws-c-io parity).
# - `elg[i]` uses 1-based indexing like normal Julia collections.
Base.length(elg::EventLoopGroup) = length(elg.event_loops)
Base.getindex(elg::EventLoopGroup, i::Integer) = elg.event_loops[i]

# Create a new event loop group (creates and runs event loops)
function EventLoopGroup(;loop_count::Integer = 0, cpu_group::Union{Nothing, Integer} = nothing, clock::ClockSource = HighResClock())
    loop_count = loop_count
    if cpu_group !== nothing && loop_count == typemax(UInt16)
        cpu_count = (Int(cpu_group) == 0) ? Sys.CPU_THREADS : 0
        loop_count = UInt16(cpu_count > 0 ? min(cpu_count, typemax(UInt16)) : 1)
    end
    if loop_count == 0
        loop_count = UInt16(max(1, Sys.CPU_THREADS >> 1))
    end

    elg = EventLoopGroup(
        Vector{EventLoop}(),
        ReentrantLock(),
        Set{UInt64}(),
        UInt64(1),
        false,
        false,
        false,
    )
    try
        # Create event loops
        for _ in 1:loop_count
            loop = event_loop_new(clock)
            push!(elg.event_loops, loop)
        end

        # Start event loops
        for i in 1:length(elg.event_loops)
            loop = elg.event_loops[i]
            event_loop_run!(loop)
        end

        return elg
    catch
        event_loop_group_destroy!(elg)
        rethrow()
    end
end

function event_loop_group_open_lease!(elg::EventLoopGroup)::Union{EventLoopGroupLease, Nothing}
    lock(elg.lease_lock)
    try
        if @atomic elg.close_requested
            return nothing
        end

        lease_id = elg.next_lease_id
        elg.next_lease_id += UInt64(1)
        push!(elg.active_lease_ids, lease_id)
        return EventLoopGroupLease(elg, lease_id)
    finally
        unlock(elg.lease_lock)
    end
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

function _event_loop_group_ready_to_destroy(elg::EventLoopGroup)::Bool
    lock(elg.lease_lock)
    try
        return (@atomic elg.close_requested) && isempty(elg.active_lease_ids)
    finally
        unlock(elg.lease_lock)
    end
end

function _event_loop_group_try_destroy!(elg::EventLoopGroup)::Nothing
    _event_loop_group_ready_to_destroy(elg) || return nothing

    if _event_loop_group_called_from_loop_thread(elg)
        errormonitor(Threads.@spawn event_loop_group_destroy!(elg))
    else
        event_loop_group_destroy!(elg)
    end
    return nothing
end

function event_loop_group_close_lease!(::Nothing)::Nothing
    return nothing
end

function event_loop_group_close_lease!(lease::EventLoopGroupLease)::Nothing
    elg = lease.group
    removed = false
    lock(elg.lease_lock)
    try
        if lease.lease_id in elg.active_lease_ids
            delete!(elg.active_lease_ids, lease.lease_id)
            removed = true
        end
    finally
        unlock(elg.lease_lock)
    end

    removed && _event_loop_group_try_destroy!(elg)
    return nothing
end

function event_loop_group_release!(elg::EventLoopGroup)::Nothing
    @atomic elg.close_requested = true
    _event_loop_group_try_destroy!(elg)
    return nothing
end

function event_loop_group_destroy!(elg::EventLoopGroup)::Nothing
    expected = false
    if !(@atomicreplace elg.destroying expected => true).success
        return nothing
    end

    @atomic elg.close_requested = true
    lock(elg.lease_lock)
    try
        empty!(elg.active_lease_ids)
    finally
        unlock(elg.lease_lock)
    end

    logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "Event loop group destroy")
    try
        for i in 1:length(elg.event_loops)
            el = elg.event_loops[i]
            el === nothing && continue
            event_loop_destroy!(el)
        end
    finally
        empty!(elg.event_loops)
        @atomic elg.destroyed = true
        _event_loop_group_clear_default_if_matches!(elg)
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
        if elg === nothing || (@atomic elg.destroyed)
            elg = EventLoopGroup(; loop_count = 1)
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

function _event_loop_group_clear_default_if_matches!(elg::EventLoopGroup)::Nothing
    lock(_DEFAULT_EVENT_LOOP_GROUP_LOCK)
    try
        if _DEFAULT_EVENT_LOOP_GROUP[] === elg
            _DEFAULT_EVENT_LOOP_GROUP[] = nothing
        end
    finally
        unlock(_DEFAULT_EVENT_LOOP_GROUP_LOCK)
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

    wake = Base.Threads.Event()
    task = ScheduledTask(
        TaskFn(function(status)
            try; notify(wake); catch; end
            return nothing
        end);
        type_tag = "task_sleep",
    )

    now = clock_now_ns(event_loop.clock)
    run_at = add_u64_saturating(now, UInt64(ns))
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
