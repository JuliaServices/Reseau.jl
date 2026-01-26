# AWS IO Library - Event Loop Abstraction
# Port of aws-c-io/source/event_loop.c and include/aws/io/event_loop.h

# Event types for IO event subscriptions (bitmask)
@enumx IoEventType::UInt32 begin
    READABLE = 1
    WRITABLE = 2
    REMOTE_HANG_UP = 4
    CLOSED = 8
    ERROR = 16
end

# Event loop type enum
@enumx EventLoopType::UInt8 begin
    PLATFORM_DEFAULT = 0
    EPOLL = 1
    IOCP = 2
    KQUEUE = 3
    DISPATCH_QUEUE = 4
end

# Get the default event loop type for the current platform
function event_loop_get_default_type()::EventLoopType.T
    @static if Sys.islinux()
        return EventLoopType.EPOLL
    elseif Sys.iswindows()
        return EventLoopType.IOCP
    elseif Sys.isapple()
        # Use kqueue for macOS, dispatch_queue for iOS
        # Since we're typically on macOS, default to kqueue
        return EventLoopType.KQUEUE
    elseif Sys.isbsd()
        return EventLoopType.KQUEUE
    else
        return EventLoopType.PLATFORM_DEFAULT
    end
end

# High resolution clock function - returns nanoseconds
function high_res_clock()::UInt64
    ticks = Ref{UInt64}(0)
    high_res_clock_get_ticks(ticks)
    return ticks[]
end

# Event loop local object for thread-local storage
mutable struct EventLoopLocalObject{T, OnRemoved}
    key::Ptr{Cvoid}  # Address used as key
    object::T
    on_object_removed::OnRemoved
end

function EventLoopLocalObject(key::Ptr{Cvoid}, object::T) where {T}
    return EventLoopLocalObject{T, Nothing}(key, object, nothing)
end

# Event loop options
struct EventLoopOptions{Clock}
    clock::Clock
    thread_options::Union{Nothing, ThreadOptions}
    type::EventLoopType.T
    parent_elg::Ptr{Cvoid}
end

function EventLoopOptions(;
        clock = high_res_clock,
        thread_options::Union{Nothing, ThreadOptions} = nothing,
        type::EventLoopType.T = EventLoopType.PLATFORM_DEFAULT,
        parent_elg::Ptr{Cvoid} = C_NULL,
    )
    return EventLoopOptions(clock, thread_options, type, parent_elg)
end

# Event loop group options
struct EventLoopGroupOptions{S, C, Clock}
    loop_count::UInt16
    type::EventLoopType.T
    shutdown_options::S
    cpu_group::C
    clock_override::Clock
end

function EventLoopGroupOptions(;
        loop_count::Integer = 1,
        type::EventLoopType.T = EventLoopType.PLATFORM_DEFAULT,
        shutdown_options = nothing,
        cpu_group = nothing,
        clock_override = nothing,
    )
    return EventLoopGroupOptions(
        UInt16(loop_count),
        type,
        shutdown_options,
        cpu_group,
        clock_override,
    )
end

# Callback type for IO events
const OnEventCallback = Function  # signature: (event_loop, io_handle, events::Int, user_data) -> Nothing

# Forward declaration - actual EventLoop is defined below
# abstract type AbstractEventLoop already defined in io.jl

# Event loop base structure
mutable struct EventLoop{Impl, LD, Clock} <: AbstractEventLoop
    clock::Clock
    local_data::LD
    @atomic current_load_factor::Csize_t
    latest_tick_start::UInt64
    current_tick_latency_sum::Csize_t
    @atomic next_flush_time::UInt64
    base_elg::Ptr{Cvoid}
    impl_data::Impl
    @atomic running::Bool
    @atomic should_stop::Bool
    thread::Union{Nothing, ThreadHandle}
end

function EventLoop(
        clock::Clock,
        impl_data::Impl,
    ) where {Clock, Impl}
    local_data = HashTable{Ptr{Cvoid}, EventLoopLocalObject{Ptr{Cvoid}, Nothing}}(
        hash_ptr,
        ptr_eq;
        capacity = 20,
    )
    return EventLoop{Impl, typeof(local_data), Clock}(
        clock,
        local_data,
        Csize_t(0),
        UInt64(0),
        Csize_t(0),
        UInt64(0),
        C_NULL,
        impl_data,
        false,
        false,
        nothing,
    )
end

# Event loop vtable interface - these methods must be implemented by concrete event loop types
# Each platform-specific event loop (epoll, kqueue, etc.) implements these

# Start the destruction process (quick, non-blocking)
function event_loop_start_destroy!(event_loop::EventLoop)
    # Default implementation does nothing
    return nothing
end

# Wait for destruction to complete
function event_loop_complete_destroy!(event_loop::EventLoop)
    # Stop the event loop and wait for completion
    event_loop_stop!(event_loop)
    event_loop_wait_for_stop_completion!(event_loop)
    # Clean up local data
    for (key, obj) in event_loop.local_data
        if obj.on_object_removed !== nothing
            obj.on_object_removed(obj)
        end
    end
    hash_table_clear!(event_loop.local_data)
    return nothing
end

# Destroy an event loop (blocking)
function event_loop_destroy!(event_loop::EventLoop)
    event_loop_start_destroy!(event_loop)
    event_loop_complete_destroy!(event_loop)
    return nothing
end

# Run the event loop (non-blocking - starts the loop)
function event_loop_run!(event_loop::EventLoop)::Union{Nothing, ErrorResult}
    error("event_loop_run! must be implemented by concrete event loop type")
end

# Stop the event loop (may be called from any thread)
function event_loop_stop!(event_loop::EventLoop)::Union{Nothing, ErrorResult}
    @atomic event_loop.should_stop = true
    return nothing
end

# Wait for the event loop to stop completely
function event_loop_wait_for_stop_completion!(event_loop::EventLoop)::Union{Nothing, ErrorResult}
    if event_loop.thread !== nothing
        thread_join(event_loop.thread)
    end
    return nothing
end

# Schedule a task for immediate execution
function event_loop_schedule_task_now!(event_loop::EventLoop, task::ScheduledTask)
    error("event_loop_schedule_task_now! must be implemented by concrete event loop type")
end

# Schedule a task for immediate execution (serialized - maintains order)
function event_loop_schedule_task_now_serialized!(event_loop::EventLoop, task::ScheduledTask)
    # Default implementation just calls the regular schedule
    return event_loop_schedule_task_now!(event_loop, task)
end

# Schedule a task for future execution
function event_loop_schedule_task_future!(event_loop::EventLoop, task::ScheduledTask, run_at_nanos::UInt64)
    error("event_loop_schedule_task_future! must be implemented by concrete event loop type")
end

# Cancel a task
function event_loop_cancel_task!(event_loop::EventLoop, task::ScheduledTask)
    error("event_loop_cancel_task! must be implemented by concrete event loop type")
end

# Subscribe to IO events on a handle
function event_loop_subscribe_to_io_events!(
        event_loop::EventLoop,
        handle::IoHandle,
        events::Int,
        on_event::OnEventCallback,
        user_data,
    )::Union{Nothing, ErrorResult}
    error("event_loop_subscribe_to_io_events! must be implemented by concrete event loop type")
end

# Unsubscribe from IO events on a handle
function event_loop_unsubscribe_from_io_events!(
        event_loop::EventLoop,
        handle::IoHandle,
    )::Union{Nothing, ErrorResult}
    error("event_loop_unsubscribe_from_io_events! must be implemented by concrete event loop type")
end

# Free IO event resources for a handle
function event_loop_free_io_event_resources!(event_loop::EventLoop, handle::IoHandle)
    # Default implementation does nothing
    return nothing
end

# Check if running on the event loop's thread
function event_loop_thread_is_callers_thread(event_loop::EventLoop)::Bool
    if event_loop.thread === nothing
        return false
    end
    return thread_current_thread_id() == thread_get_id(event_loop.thread)
end

# Get current clock time
function event_loop_current_clock_time(event_loop::EventLoop)::Union{UInt64, ErrorResult}
    return event_loop.clock()
end

# Local object management
function event_loop_fetch_local_object(
        event_loop::EventLoop,
        key::Ptr{Cvoid},
    )::Union{EventLoopLocalObject, ErrorResult}
    obj = hash_table_get(event_loop.local_data, key)
    if obj === nothing
        raise_error(ERROR_HASHTBL_ITEM_NOT_FOUND)
        return ErrorResult(ERROR_HASHTBL_ITEM_NOT_FOUND)
    end
    return obj
end

function event_loop_put_local_object!(
        event_loop::EventLoop,
        obj::EventLoopLocalObject,
    )::Union{Nothing, ErrorResult}
    old = hash_table_get(event_loop.local_data, obj.key)
    if old !== nothing && old.on_object_removed !== nothing
        old.on_object_removed(old)
    end
    hash_table_put!(event_loop.local_data, obj.key, obj)
    return nothing
end

function event_loop_remove_local_object!(
        event_loop::EventLoop,
        key::Ptr{Cvoid},
    )::Union{EventLoopLocalObject, Nothing, ErrorResult}
    obj = hash_table_get(event_loop.local_data, key)
    if obj === nothing
        return nothing
    end
    hash_table_remove!(event_loop.local_data, key)
    return obj
end

# Load factor for load balancing
const LOAD_FACTOR_SLIDING_WINDOW_SIZE = 64
const LOAD_FACTOR_FLUSH_INTERVAL_NS = UInt64(1_000_000)  # 1ms

function event_loop_register_tick_start!(event_loop::EventLoop)
    current_time = event_loop.clock()
    return event_loop.latest_tick_start = current_time
end

function event_loop_register_tick_end!(event_loop::EventLoop)
    current_time = event_loop.clock()
    latency = current_time - event_loop.latest_tick_start
    event_loop.current_tick_latency_sum += latency

    next_flush = @atomic event_loop.next_flush_time
    return if current_time >= next_flush
        # Calculate new load factor
        new_load = event_loop.current_tick_latency_sum
        @atomic event_loop.current_load_factor = new_load
        event_loop.current_tick_latency_sum = 0
        @atomic event_loop.next_flush_time = current_time + LOAD_FACTOR_FLUSH_INTERVAL_NS
    end
end

function event_loop_get_load_factor(event_loop::EventLoop)::Csize_t
    return @atomic event_loop.current_load_factor
end

# Create a new event loop based on options
function event_loop_new(options::EventLoopOptions)::Union{EventLoop, ErrorResult}
    el_type = options.type
    if el_type == EventLoopType.PLATFORM_DEFAULT
        el_type = event_loop_get_default_type()
    end

    if el_type == EventLoopType.EPOLL
        @static if Sys.islinux()
            return event_loop_new_with_epoll(options)
        else
            return ErrorResult(raise_error(ERROR_UNSUPPORTED_OPERATION))
        end
    elseif el_type == EventLoopType.KQUEUE
        @static if Sys.isapple() || Sys.isbsd()
            return event_loop_new_with_kqueue(options)
        else
            return ErrorResult(raise_error(ERROR_UNSUPPORTED_OPERATION))
        end
    else
        return ErrorResult(raise_error(ERROR_UNSUPPORTED_OPERATION))
    end
end

# Event Loop Group for managing multiple event loops
mutable struct EventLoopGroup{EL, S}
    event_loops::ArrayList{EL}
    shutdown_options::S
    event_loop_type::EventLoopType.T
end

# Create a new event loop group (creates and runs event loops)
function event_loop_group_new(options::EventLoopGroupOptions)
    loop_count = options.loop_count
    if loop_count == 0
        loop_count = UInt16(Sys.CPU_THREADS)
    end

    interactive_threads = Threads.nthreads(:interactive)
    if Int(loop_count) >= interactive_threads
        logf(
            LogLevel.ERROR,
            LS_IO_EVENT_LOOP,
            "Event loop group requires loop_count < interactive thread count (loop_count=%d, interactive=%d)",
            Int(loop_count),
            interactive_threads,
        )
        raise_error(ERROR_THREAD_INVALID_SETTINGS)
        return ErrorResult(ERROR_THREAD_INVALID_SETTINGS)
    end

    el_type = options.type
    if el_type == EventLoopType.PLATFORM_DEFAULT
        el_type = event_loop_get_default_type()
    end

    clock = options.clock_override === nothing ? high_res_clock : options.clock_override

    # Create first event loop to determine concrete type
    first_opts = EventLoopOptions(; clock = clock, type = el_type, parent_elg = C_NULL)
    first_loop = event_loop_new(first_opts)
    if first_loop isa ErrorResult
        return first_loop
    end

    EL = typeof(first_loop)
    elg = EventLoopGroup{EL, typeof(options.shutdown_options)}(
        ArrayList{EL}(Int(loop_count)),
        options.shutdown_options,
        el_type,
    )
    parent_ptr = pointer_from_objref(elg)

    first_loop.base_elg = parent_ptr
    push_back!(elg.event_loops, first_loop)

    # Create remaining event loops
    for _ in 2:loop_count
        loop_opts = EventLoopOptions(; clock = clock, type = el_type, parent_elg = parent_ptr)
        loop = event_loop_new(loop_opts)
        if loop isa ErrorResult
            event_loop_group_destroy!(elg)
            return loop
        end
        push_back!(elg.event_loops, loop)
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
    return elg
end

function event_loop_group_release!(elg::EventLoopGroup)
    return nothing
end

function event_loop_group_destroy!(elg::EventLoopGroup)
    logf(LogLevel.TRACE, LS_IO_EVENT_LOOP, "Event loop group destroy")
    for i in 1:length(elg.event_loops)
        el = elg.event_loops[i]
        el === nothing && continue
        event_loop_destroy!(el)
    end
    clear!(elg.event_loops)
    if elg.shutdown_options !== nothing
        Base.invokelatest(elg.shutdown_options.shutdown_callback_fn)
    end
    return nothing
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

function event_loop_group_get_type(elg::EventLoopGroup)::EventLoopType.T
    return elg.event_loop_type
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
    if event_loop.base_elg == C_NULL
        return nothing
    end
    elg = unsafe_pointer_to_objref(event_loop.base_elg)::EventLoopGroup
    return event_loop_group_acquire!(elg)
end

function event_loop_group_release_from_event_loop!(event_loop::EventLoop)
    if event_loop.base_elg != C_NULL
        elg = unsafe_pointer_to_objref(event_loop.base_elg)::EventLoopGroup
        event_loop_group_release!(elg)
    end
    return nothing
end

# Channel task wrapper for use with channels
mutable struct ChannelTask{F, Ctx}
    wrapper_task::ScheduledTask{F, Ctx}
    task_fn::F
    arg::Ctx
    type_tag::String
    # Intrusive list node
    node_next::Union{ChannelTask{F, Ctx}, Nothing}
    node_prev::Union{ChannelTask{F, Ctx}, Nothing}
end

function ChannelTask(task_fn::F, arg::Ctx, type_tag::AbstractString) where {F, Ctx}
    scheduled_task = ScheduledTask(task_fn, arg; type_tag = type_tag)
    return ChannelTask{F, Ctx}(
        scheduled_task,
        task_fn,
        arg,
        String(type_tag),
        nothing,
        nothing,
    )
end

function channel_task_init!(task::ChannelTask, task_fn, arg, type_tag::AbstractString)
    task.task_fn = task_fn
    task.arg = arg
    task.type_tag = String(type_tag)
    task.node_next = nothing
    task.node_prev = nothing
    return nothing
end
