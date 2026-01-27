# AWS IO Library - Channel Pipeline
# Port of aws-c-io/source/channel.c and include/aws/io/channel.h

# Channel read/write directions are defined in socket.jl as ChannelDirection

# Callbacks
const ChannelOnSetupCompletedFn = Function  # (channel, error_code, user_data) -> nothing
const ChannelOnShutdownCompletedFn = Function  # (channel, error_code, user_data) -> nothing

const DEFAULT_CHANNEL_MAX_FRAGMENT_SIZE = 16 * 1024
const g_aws_channel_max_fragment_size = Ref{Csize_t}(Csize_t(DEFAULT_CHANNEL_MAX_FRAGMENT_SIZE))
const _CHANNEL_MESSAGE_POOL_KEY = Ref{UInt8}(0)
const _CHANNEL_MESSAGE_POOL_KEY_PTR = pointer_from_objref(_CHANNEL_MESSAGE_POOL_KEY)

struct ChannelOptions{EL}
    event_loop::EL
    on_setup_completed::Union{ChannelOnSetupCompletedFn, Nothing}
    on_shutdown_completed::Union{ChannelOnShutdownCompletedFn, Nothing}
    setup_user_data::Any
    shutdown_user_data::Any
    enable_read_back_pressure::Bool
end

function ChannelOptions(;
        event_loop,
        on_setup_completed = nothing,
        on_shutdown_completed = nothing,
        setup_user_data = nothing,
        shutdown_user_data = nothing,
        enable_read_back_pressure::Bool = false,
    )
    return ChannelOptions(
        event_loop,
        on_setup_completed,
        on_shutdown_completed,
        setup_user_data,
        shutdown_user_data,
        enable_read_back_pressure,
    )
end

# Channel task wrapper (aws_channel_task)
mutable struct ChannelTaskContext
    channel::Any
    task::Any
end

mutable struct ChannelTask
    wrapper_task::ScheduledTask
    task_fn::Function
    arg::Any
    type_tag::String
    ctx::ChannelTaskContext
end

function ChannelTask(task_fn, arg, type_tag::AbstractString)
    ctx = ChannelTaskContext(nothing, nothing)
    wrapper_task = ScheduledTask(_channel_task_wrapper, ctx; type_tag = type_tag)
    task = ChannelTask(wrapper_task, task_fn, arg, String(type_tag), ctx)
    ctx.task = task
    return task
end

function ChannelTask()
    return ChannelTask((task, arg, status) -> nothing, nothing, "channel_task")
end

function channel_task_init!(task::ChannelTask, task_fn, arg, type_tag::AbstractString)
    task.task_fn = task_fn
    task.arg = arg
    task.type_tag = String(type_tag)
    task.wrapper_task.type_tag = task.type_tag
    task.wrapper_task.timestamp = UInt64(0)
    task.wrapper_task.scheduled = false
    return nothing
end


# Channel handler options for shutdown behavior
struct ChannelHandlerShutdownOptions
    free_scarce_resources_immediately::Bool
    shutdown_immediately::Bool
end

ChannelHandlerShutdownOptions() = ChannelHandlerShutdownOptions(false, false)

# Channel slot - links handlers in the pipeline
# Each slot can hold a handler and links to adjacent slots.
# Read direction flows left -> right (toward application).
# Write direction flows right -> left (toward socket).
mutable struct ChannelSlot{H <: Union{AbstractChannelHandler, Nothing}, C <: Union{AbstractChannel, Nothing}, SlotRef}
    adj_left::SlotRef   # Toward the socket/network (write direction)
    adj_right::SlotRef  # Toward the application (read direction)
    handler::H
    channel::C
    window_size::Csize_t
    current_window_update_batch_size::Csize_t
    upstream_message_overhead::Csize_t
end

function ChannelSlot()
    return ChannelSlot{Union{AbstractChannelHandler, Nothing}, Union{AbstractChannel, Nothing}, Union{ChannelSlot, Nothing}}(
        nothing,
        nothing,
        nothing,
        nothing,
        Csize_t(0),
        Csize_t(0),
        Csize_t(0),
    )
end

function ChannelSlot(handler::H, channel::C) where {H, C}
    return ChannelSlot{H, C, Union{ChannelSlot, Nothing}}(
        nothing,
        nothing,
        handler,
        channel,
        Csize_t(0),
        Csize_t(0),
        Csize_t(0),
    )
end

# Get the slot immediately to the left (socket side)
slot_left(slot::ChannelSlot) = slot.adj_left
# Get the slot immediately to the right (application side)
slot_right(slot::ChannelSlot) = slot.adj_right

# Channel handler base structure
# Concrete handlers should embed this or use similar structure
mutable struct ChannelHandlerBase{V, Impl, SlotRef <: Union{ChannelSlot, Nothing}}
    vtable::V  # ChannelHandlerVTable implementation
    impl::Impl  # Handler-specific implementation data
    slot::SlotRef
    message_overhead::Csize_t
    initial_window_size::Csize_t
end

function ChannelHandlerBase(vtable::V, impl::Impl; initial_window_size::Integer = 0) where {V, Impl}
    return ChannelHandlerBase{V, Impl, Union{ChannelSlot, Nothing}}(
        vtable,
        impl,
        nothing,
        Csize_t(0),
        Csize_t(initial_window_size),
    )
end

# Channel handler vtable interface - methods that all handlers must implement
# These are dispatched via multiple dispatch on the vtable type

# Process an incoming read message (from socket toward application)
function handler_process_read_message(handler::AbstractChannelHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    error("handler_process_read_message must be implemented for $(typeof(handler))")
end

# Process an outgoing write message (from application toward socket)
function handler_process_write_message(handler::AbstractChannelHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    error("handler_process_write_message must be implemented for $(typeof(handler))")
end

# Increment the read window (flow control) - more data can be read
function handler_increment_read_window(handler::AbstractChannelHandler, slot::ChannelSlot, size::Csize_t)::Union{Nothing, ErrorResult}
    error("handler_increment_read_window must be implemented for $(typeof(handler))")
end

# Initiate graceful shutdown of the handler
function handler_shutdown(
        handler::AbstractChannelHandler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Union{Nothing, ErrorResult}
    error("handler_shutdown must be implemented for $(typeof(handler))")
end

# Get the current window size for the handler
function handler_initial_window_size(handler::AbstractChannelHandler)::Csize_t
    error("handler_initial_window_size must be implemented for $(typeof(handler))")
end

# Get the message overhead size for this handler
function handler_message_overhead(handler::AbstractChannelHandler)::Csize_t
    error("handler_message_overhead must be implemented for $(typeof(handler))")
end

# Called when shutdown completes for cleanup
function handler_destroy(handler::AbstractChannelHandler)::Nothing
    # Default implementation does nothing
    return nothing
end

# Reset handler statistics
function handler_reset_statistics(handler::AbstractChannelHandler)::Nothing
    # Default implementation does nothing
    return nothing
end

# Gather handler statistics
function handler_gather_statistics(handler::AbstractChannelHandler)::Any
    # Default implementation returns nothing
    return nothing
end

# Trigger handler to write its pending data
function handler_trigger_write(handler::AbstractChannelHandler)::Nothing
    # Default implementation does nothing
    return nothing
end

# Trigger handler to read data if it is a data-source handler
function handler_trigger_read(handler::AbstractChannelHandler)::Nothing
    # Default implementation does nothing
    return nothing
end

# Channel state tracking
@enumx ChannelState::UInt8 begin
    NOT_INITIALIZED = 0
    SETTING_UP = 1
    ACTIVE = 2
    SHUTTING_DOWN_READ = 3
    SHUTTING_DOWN_WRITE = 4
    SHUT_DOWN = 5
end

# Channel - a bidirectional pipeline of handlers
mutable struct Channel{EL <: AbstractEventLoop, SlotRef <: Union{ChannelSlot, Nothing}} <: AbstractChannel
    event_loop::EL
    first::SlotRef  # nullable - Application side (leftmost)
    last::SlotRef   # nullable - Socket side (rightmost)
    channel_state::ChannelState.T
    read_back_pressure_enabled::Bool
    channel_id::UInt64
    message_pool::Union{MessagePool, Nothing}  # nullable
    on_setup_completed::Union{ChannelOnSetupCompletedFn, Nothing}  # nullable
    on_shutdown_completed::Union{ChannelOnShutdownCompletedFn, Nothing}  # nullable
    setup_user_data::Any
    shutdown_user_data::Any
    shutdown_error_code::Int
    # Statistics tracking
    read_message_count::Csize_t
    write_message_count::Csize_t
    statistics_handler::Union{StatisticsHandler, Nothing}  # nullable
    statistics_task::Union{ScheduledTask, Nothing}  # nullable
    statistics_interval_start_time_ms::UInt64
    statistics_list::ArrayList{Any}
    # Window/backpressure tracking
    window_update_batch_emit_threshold::Csize_t
    window_update_scheduled::Bool
    window_update_task::ChannelTask
    # Channel task tracking
    pending_tasks::IdDict{Any, Bool}
    pending_tasks_lock::ReentrantLock
    # Shutdown tracking
    shutdown_pending::Bool
    shutdown_immediately::Bool
    shutdown_task::ChannelTask
    shutdown_lock::ReentrantLock
end

# Global channel counter for unique IDs
const _channel_id_counter = Ref{UInt64}(0)

function _next_channel_id()::UInt64
    id = _channel_id_counter[]
    _channel_id_counter[] = id + 1
    return id
end

function Channel(
        event_loop::EL,
        message_pool::Union{MessagePool, Nothing} = nothing;
        enable_read_back_pressure::Bool = false,
    ) where {EL <: AbstractEventLoop}
    channel_id = _next_channel_id()
    window_threshold = enable_read_back_pressure ? Csize_t(g_aws_channel_max_fragment_size[] * 2) : Csize_t(0)

    return Channel{EL, Union{ChannelSlot, Nothing}}(
        event_loop,
        nothing,  # first
        nothing,  # last
        ChannelState.NOT_INITIALIZED,
        enable_read_back_pressure,
        channel_id,
        message_pool,
        nothing,  # on_setup_completed
        nothing,  # on_shutdown_completed
        nothing,  # setup_user_data
        nothing,  # shutdown_user_data
        0,        # shutdown_error_code
        Csize_t(0),  # read_message_count
        Csize_t(0),  # write_message_count
        nothing,  # statistics_handler
        nothing,  # statistics_task
        UInt64(0),  # statistics_interval_start_time_ms
        ArrayList{Any}(16),
        window_threshold,
        false,       # window_update_scheduled
        ChannelTask(),
        IdDict{ChannelTask, Bool}(),
        ReentrantLock(),
        false,    # shutdown_pending
        false,    # shutdown_immediately
        ChannelTask(),
        ReentrantLock(),
    )
end

function _channel_add_pending_task!(channel::Channel, task::ChannelTask)
    lock(channel.pending_tasks_lock) do
        channel.pending_tasks[task] = true
    end
    return nothing
end

function _channel_remove_pending_task!(channel::Channel, task::ChannelTask)
    lock(channel.pending_tasks_lock) do
        delete!(channel.pending_tasks, task)
    end
    return nothing
end

function _channel_task_wrapper(ctx::ChannelTaskContext, status::TaskStatus.T)
    task = ctx.task::ChannelTask
    channel = ctx.channel
    if channel isa Channel
        _channel_remove_pending_task!(channel, task)
        final_status = (status == TaskStatus.CANCELED || channel.channel_state == ChannelState.SHUT_DOWN) ?
            TaskStatus.CANCELED : status
        task.task_fn(task, task.arg, final_status)
        return nothing
    end
    task.task_fn(task, task.arg, status)
    return nothing
end

# Get the event loop associated with a channel
channel_event_loop(channel::Channel) = channel.event_loop

# Check if caller is on channel's event loop thread
channel_thread_is_callers_thread(channel::Channel) = event_loop_thread_is_callers_thread(channel.event_loop)

# Get current clock time from event loop
channel_current_clock_time(channel::Channel) = event_loop_current_clock_time(channel.event_loop)

# Force a read by the data-source handler (socket side)
function channel_trigger_read(channel::Channel)::Union{Nothing, ErrorResult}
    if channel === nothing
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end
    if !channel_thread_is_callers_thread(channel)
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end
    slot = channel.last
    if slot === nothing || slot.handler === nothing
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end
    handler_trigger_read(slot.handler)
    return nothing
end

# Event loop local object wrappers
channel_fetch_local_object(channel::Channel, key::Ptr{Cvoid}) = event_loop_fetch_local_object(channel.event_loop, key)
channel_put_local_object!(channel::Channel, obj::EventLoopLocalObject) = event_loop_put_local_object!(channel.event_loop, obj)
channel_remove_local_object!(channel::Channel, key::Ptr{Cvoid}) = event_loop_remove_local_object!(channel.event_loop, key)

# Channel creation API matching aws_channel_new
mutable struct ChannelSetupArgs
    channel::Channel
end

function _channel_message_pool_on_removed(obj::EventLoopLocalObject)
    pool = obj.object
    if pool isa MessagePool
        message_pool_clean_up!(pool)
    end
    return nothing
end

function _channel_get_or_create_message_pool(channel::Channel)::Union{MessagePool, ErrorResult}
    local_obj = channel_fetch_local_object(channel, _CHANNEL_MESSAGE_POOL_KEY_PTR)
    if !(local_obj isa ErrorResult)
        obj = local_obj::EventLoopLocalObject
        pool = obj.object
        if pool isa MessagePool
            return pool
        end
    end

    creation_args = MessagePoolCreationArgs(;
        application_data_msg_data_size = Int(g_aws_channel_max_fragment_size[]),
        application_data_msg_count = 4,
        small_block_msg_data_size = 128,
        small_block_msg_count = 4,
    )

    pool = MessagePool(creation_args)
    if pool isa ErrorResult
        return pool
    end

    local_object = EventLoopLocalObject(_CHANNEL_MESSAGE_POOL_KEY_PTR, pool, _channel_message_pool_on_removed)
    put_res = channel_put_local_object!(channel, local_object)
    if put_res isa ErrorResult
        return put_res
    end
    return pool
end

function _channel_setup_task(args::ChannelSetupArgs, status::TaskStatus.T)
    channel = args.channel
    if status != TaskStatus.RUN_READY
        if channel.on_setup_completed !== nothing
            Base.invokelatest(channel.on_setup_completed, channel, ERROR_SYS_CALL_FAILURE, channel.setup_user_data)
        end
        return nothing
    end

    pool = _channel_get_or_create_message_pool(channel)
    if pool isa ErrorResult
        if channel.on_setup_completed !== nothing
            Base.invokelatest(channel.on_setup_completed, channel, pool.code, channel.setup_user_data)
        end
        return nothing
    end

    channel.message_pool = pool
    channel.channel_state = ChannelState.ACTIVE

    if channel.on_setup_completed !== nothing
        Base.invokelatest(channel.on_setup_completed, channel, AWS_OP_SUCCESS, channel.setup_user_data)
    end
    return nothing
end

function channel_new(options::ChannelOptions)::Union{Channel, ErrorResult}
    if options.event_loop === nothing
        return ErrorResult(raise_error(ERROR_INVALID_ARGUMENT))
    end

    channel = Channel(
        options.event_loop,
        nothing;
        enable_read_back_pressure = options.enable_read_back_pressure,
    )
    channel.on_setup_completed = options.on_setup_completed
    channel.on_shutdown_completed = options.on_shutdown_completed
    channel.setup_user_data = options.setup_user_data
    channel.shutdown_user_data = options.shutdown_user_data
    channel.channel_state = ChannelState.SETTING_UP

    event_loop_group_acquire_from_event_loop(options.event_loop)

    setup_args = ChannelSetupArgs(channel)
    task = ScheduledTask(_channel_setup_task, setup_args; type_tag = "channel_setup")
    event_loop_schedule_task_now!(options.event_loop, task)
    return channel
end

# Get unique channel ID
channel_id(channel::Channel) = channel.channel_id

# Get the first slot (application side)
channel_first_slot(channel::Channel) = channel.first

# Get the last slot (socket side)
channel_last_slot(channel::Channel) = channel.last

# Channel task scheduling
function _channel_register_task!(
        channel::Channel,
        task::ChannelTask,
        run_at_nanos::UInt64;
        serialized::Bool = false,
    )
    if channel.channel_state == ChannelState.SHUT_DOWN
        task.task_fn(task, task.arg, TaskStatus.CANCELED)
        return nothing
    end

    task.ctx.channel = channel
    _channel_add_pending_task!(channel, task)

    if run_at_nanos == 0
        if serialized
            event_loop_schedule_task_now_serialized!(channel.event_loop, task.wrapper_task)
        else
            event_loop_schedule_task_now!(channel.event_loop, task.wrapper_task)
        end
    else
        event_loop_schedule_task_future!(channel.event_loop, task.wrapper_task, run_at_nanos)
    end

    return nothing
end

function channel_schedule_task_now!(channel::Channel, task::ChannelTask)
    return _channel_register_task!(channel, task, UInt64(0); serialized = false)
end

function channel_schedule_task_now_serialized!(channel::Channel, task::ChannelTask)
    return _channel_register_task!(channel, task, UInt64(0); serialized = true)
end

function channel_schedule_task_future!(channel::Channel, task::ChannelTask, run_at_nanos::UInt64)
    return _channel_register_task!(channel, task, run_at_nanos; serialized = false)
end

# Check if channel is active
channel_is_active(channel::Channel) = channel.channel_state == ChannelState.ACTIVE

# Set the channel setup callback
function channel_set_setup_callback!(channel::Channel, callback::ChannelOnSetupCompletedFn, user_data)
    channel.on_setup_completed = callback
    channel.setup_user_data = user_data
    return nothing
end

# Set the channel shutdown callback
function channel_set_shutdown_callback!(channel::Channel, callback::ChannelOnShutdownCompletedFn, user_data)
    channel.on_shutdown_completed = callback
    channel.shutdown_user_data = user_data
    return nothing
end

function _channel_reset_statistics!(channel::Channel)
    current = channel.first
    while current !== nothing
        handler = current.handler
        handler !== nothing && handler_reset_statistics(handler)
        current = current.adj_right
    end
    return nothing
end

function _channel_gather_statistics_task(channel::Channel, status::TaskStatus.T)
    status == TaskStatus.RUN_READY || return nothing
    channel.statistics_handler === nothing && return nothing

    if channel.channel_state == ChannelState.SHUTTING_DOWN_READ ||
            channel.channel_state == ChannelState.SHUTTING_DOWN_WRITE ||
            channel.channel_state == ChannelState.SHUT_DOWN
        return nothing
    end

    now_ns = event_loop_current_clock_time(channel.event_loop)
    now_ns isa ErrorResult && return nothing
    now_ms = timestamp_convert(now_ns, TIMESTAMP_NANOS, TIMESTAMP_MILLIS, nothing)

    clear!(channel.statistics_list)
    current = channel.first
    while current !== nothing
        handler = current.handler
        if handler !== nothing
            stats = handler_gather_statistics(handler)
            stats !== nothing && push_back!(channel.statistics_list, stats)
        end
        current = current.adj_right
    end

    interval = StatisticsSampleInterval(channel.statistics_interval_start_time_ms, now_ms)
    process_statistics(channel.statistics_handler, interval, channel.statistics_list)
    _channel_reset_statistics!(channel)

    report_ns = timestamp_convert(
        report_interval_ms(channel.statistics_handler),
        TIMESTAMP_MILLIS,
        TIMESTAMP_NANOS,
        nothing,
    )
    if channel.statistics_task !== nothing
        event_loop_schedule_task_future!(channel.event_loop, channel.statistics_task, now_ns + report_ns)
    end
    channel.statistics_interval_start_time_ms = now_ms
    return nothing
end

function channel_set_statistics_handler!(channel::Channel, handler::Union{StatisticsHandler, Nothing})
    if channel.statistics_handler !== nothing
        close!(channel.statistics_handler)
        if channel.statistics_task !== nothing
            event_loop_cancel_task!(channel.event_loop, channel.statistics_task)
        end
        channel.statistics_handler = nothing
        channel.statistics_task = nothing
    end

    if handler !== nothing
        task = ScheduledTask(_channel_gather_statistics_task, channel; type_tag = "gather_statistics")
        now_ns = event_loop_current_clock_time(channel.event_loop)
        if now_ns isa ErrorResult
            return now_ns
        end
        report_ns = timestamp_convert(
            report_interval_ms(handler),
            TIMESTAMP_MILLIS,
            TIMESTAMP_NANOS,
            nothing,
        )
        channel.statistics_interval_start_time_ms =
            timestamp_convert(now_ns, TIMESTAMP_NANOS, TIMESTAMP_MILLIS, nothing)
        _channel_reset_statistics!(channel)
        event_loop_schedule_task_future!(channel.event_loop, task, now_ns + report_ns)
        channel.statistics_task = task
    end

    channel.statistics_handler = handler
    return nothing
end

# Slot operations

# Create and insert a new slot into the channel
function channel_slot_new!(channel::Channel)::ChannelSlot
    slot = ChannelSlot()
    slot.channel = channel
    slot.window_size = Csize_t(0)
    slot.current_window_update_batch_size = Csize_t(0)
    slot.upstream_message_overhead = Csize_t(0)

    if channel.first === nothing
        channel.first = slot
        channel.last = slot
    end

    logf(
        LogLevel.TRACE, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): created new slot"
    )

    return slot
end

# Insert slot to the right of another slot
function channel_slot_insert_right!(slot::ChannelSlot, to_add::ChannelSlot)
    channel = slot.channel

    to_add.adj_right = slot.adj_right
    if slot.adj_right !== nothing
        slot.adj_right.adj_left = to_add
    end
    slot.adj_right = to_add
    to_add.adj_left = slot
    to_add.channel = channel

    if channel !== nothing && channel.last === slot
        channel.last = to_add
    end

    return nothing
end

# Insert slot to the left of another slot
function channel_slot_insert_left!(slot::ChannelSlot, to_add::ChannelSlot)
    channel = slot.channel

    to_add.adj_left = slot.adj_left
    if slot.adj_left !== nothing
        slot.adj_left.adj_right = to_add
    end
    slot.adj_left = to_add
    to_add.adj_right = slot
    to_add.channel = channel

    if channel !== nothing && channel.first === slot
        channel.first = to_add
    end

    return nothing
end

# Insert slot at the end of the channel (socket side)
function channel_slot_insert_end!(channel::Channel, slot::ChannelSlot)
    slot.channel = channel

    if channel.first === nothing || channel.first === slot
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end

    if channel.last === nothing
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end

    channel_slot_insert_right!(channel.last, slot)
    return nothing
end

# Insert slot at the front of the channel (application side)
function channel_slot_insert_front!(channel::Channel, slot::ChannelSlot)
    slot.channel = channel

    if channel.first === slot
        return nothing
    end

    if channel.first === nothing
        channel.first = slot
        channel.last = slot
    else
        channel_slot_insert_left!(channel.first, slot)
    end

    return nothing
end

# Remove a slot from the channel
function channel_slot_remove!(slot::ChannelSlot)
    channel = slot.channel

    if channel !== nothing
        if channel.first === slot
            channel.first = slot.adj_right
        end
        if channel.last === slot
            channel.last = slot.adj_left
        end
    end

    if slot.adj_left !== nothing
        slot.adj_left.adj_right = slot.adj_right
    end

    if slot.adj_right !== nothing
        slot.adj_right.adj_left = slot.adj_left
    end

    slot.adj_left = nothing
    slot.adj_right = nothing
    slot.channel = nothing

    if slot.handler !== nothing
        handler_destroy(slot.handler)
        slot.handler = nothing
    end

    if channel !== nothing
        _channel_calculate_message_overheads!(channel)
    end

    return nothing
end

# Replace a slot in the channel with a new slot
function channel_slot_replace!(remove::ChannelSlot, new_slot::ChannelSlot)
    channel = remove.channel
    new_slot.channel = channel
    new_slot.adj_left = remove.adj_left
    new_slot.adj_right = remove.adj_right

    if remove.adj_left !== nothing
        remove.adj_left.adj_right = new_slot
    end
    if remove.adj_right !== nothing
        remove.adj_right.adj_left = new_slot
    end

    if channel !== nothing && channel.first === remove
        channel.first = new_slot
    end
    if channel !== nothing && channel.last === remove
        channel.last = new_slot
    end

    remove.adj_left = nothing
    remove.adj_right = nothing
    remove.channel = nothing

    if remove.handler !== nothing
        handler_destroy(remove.handler)
        remove.handler = nothing
    end

    if channel !== nothing
        _channel_calculate_message_overheads!(channel)
    end

    return nothing
end

# Set the handler for a slot
function channel_slot_set_handler!(slot::ChannelSlot, handler::AbstractChannelHandler)
    slot.handler = handler
    if hasproperty(handler, :slot)
        try
            setfield!(handler, :slot, slot)
        catch
        end
    end
    if slot.channel !== nothing
        _channel_calculate_message_overheads!(slot.channel)
    end
    return channel_slot_increment_read_window!(slot, handler_initial_window_size(handler))
end

# Replace handler in a slot
function channel_slot_replace_handler!(slot::ChannelSlot, new_handler::AbstractChannelHandler)::Union{AbstractChannelHandler, Nothing}
    old_handler = slot.handler
    channel_slot_set_handler!(slot, new_handler)
    return old_handler
end

# Message passing functions

# Send a read message to the next slot (toward application)
function channel_slot_send_message(slot::ChannelSlot, message::IoMessage, direction::ChannelDirection.T)::Union{Nothing, ErrorResult}
    channel = slot.channel

    if channel === nothing
        raise_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
        return ErrorResult(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
    end

    if direction == ChannelDirection.READ
        # Send toward application (right)
        next_slot = slot.adj_right
        if next_slot === nothing || next_slot.handler === nothing
            logf(
                LogLevel.WARN, LS_IO_CHANNEL,
                "Channel id=$(channel.channel_id): no handler to process read message"
            )
            raise_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
            return ErrorResult(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
        end

        if channel.read_back_pressure_enabled && next_slot.window_size < message.message_data.len
            logf(
                LogLevel.ERROR, LS_IO_CHANNEL,
                "Channel id=$(channel.channel_id): read message exceeds window size"
            )
            raise_error(ERROR_IO_CHANNEL_READ_WOULD_EXCEED_WINDOW)
            return ErrorResult(ERROR_IO_CHANNEL_READ_WOULD_EXCEED_WINDOW)
        end

        message.owning_channel = channel
        channel.read_message_count += 1
        if channel.read_back_pressure_enabled
            next_slot.window_size = sub_size_saturating(next_slot.window_size, message.message_data.len)
        end

        return handler_process_read_message(next_slot.handler, next_slot, message)
    else
        # Send toward socket (left)
        next_slot = slot.adj_left
        if next_slot === nothing || next_slot.handler === nothing
            logf(
                LogLevel.WARN, LS_IO_CHANNEL,
                "Channel id=$(channel.channel_id): no handler to process write message"
            )
            raise_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
            return ErrorResult(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
        end

        message.owning_channel = channel
        channel.write_message_count += 1

        return handler_process_write_message(next_slot.handler, next_slot, message)
    end
end

# Returns downstream read window size for slot
function channel_slot_downstream_read_window(slot::ChannelSlot)::Csize_t
    channel = slot.channel
    if channel === nothing || !channel.read_back_pressure_enabled
        return SIZE_MAX
    end
    next_slot = slot.adj_right
    if next_slot === nothing
        return Csize_t(0)
    end
    return next_slot.window_size
end

# Acquire a message sized to max fragment size minus upstream overhead
function channel_slot_acquire_max_message_for_write(slot::ChannelSlot)
    channel = slot.channel
    if channel === nothing
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end
    if !channel_thread_is_callers_thread(channel)
        raise_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
        return ErrorResult(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end
    overhead = channel_slot_upstream_message_overhead(slot)
    if overhead >= g_aws_channel_max_fragment_size[]
        fatal_assert("Upstream overhead exceeds channel max fragment size", "<unknown>", 0)
    end
    size_hint = g_aws_channel_max_fragment_size[] - overhead
    return channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, size_hint)
end

# Increment read window (flow control propagation)
function channel_slot_increment_read_window!(slot::ChannelSlot, size::Csize_t)::Union{Nothing, ErrorResult}
    channel = slot.channel

    if channel === nothing
        return nothing
    end

    if channel.read_back_pressure_enabled && channel.channel_state != ChannelState.SHUT_DOWN
        slot.current_window_update_batch_size = add_size_saturating(slot.current_window_update_batch_size, size)

        if !channel.window_update_scheduled && slot.window_size <= channel.window_update_batch_emit_threshold
            channel.window_update_scheduled = true
            channel_task_init!(channel.window_update_task, _channel_window_update_task, channel, "window_update_task")
            channel_schedule_task_now!(channel, channel.window_update_task)
        end
    end

    return nothing
end

function _channel_window_update_task(task::ChannelTask, channel::Channel, status::TaskStatus.T)
    _ = task
    channel.window_update_scheduled = false
    status == TaskStatus.RUN_READY || return nothing

    if channel.channel_state == ChannelState.SHUT_DOWN
        return nothing
    end

    slot = channel.last
    while slot !== nothing && slot.adj_left !== nothing
        upstream_slot = slot.adj_left
        if upstream_slot.handler !== nothing
            slot.window_size = add_size_saturating(slot.window_size, slot.current_window_update_batch_size)
            update_size = slot.current_window_update_batch_size
            slot.current_window_update_batch_size = 0
            res = handler_increment_read_window(upstream_slot.handler, upstream_slot, update_size)
            if res isa ErrorResult
                logf(
                    LogLevel.ERROR, LS_IO_CHANNEL,
                    "Channel id=$(channel.channel_id): window update failed with error $(res.code)"
                )
                channel_shutdown!(channel, res.code)
                return nothing
            end
        end
        slot = slot.adj_left
    end

    return nothing
end

# Get the upstream message overhead for a slot
function channel_slot_upstream_message_overhead(slot::ChannelSlot)::Csize_t
    return slot.upstream_message_overhead
end

# Calculate and set upstream message overhead for all slots
function _channel_calculate_message_overheads!(channel::Channel)
    overhead = Csize_t(0)
    slot = channel.first

    while slot !== nothing
        slot.upstream_message_overhead = overhead

        if slot.handler !== nothing
            overhead += handler_message_overhead(slot.handler)
        end

        slot = slot.adj_right
    end

    return nothing
end

# Initialize the channel after all handlers are set up
function channel_setup_complete!(channel::Channel)::Union{Nothing, ErrorResult}
    if channel.channel_state == ChannelState.ACTIVE
        return nothing
    end
    if channel.channel_state != ChannelState.NOT_INITIALIZED && channel.channel_state != ChannelState.SETTING_UP
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL,
            "Channel id=$(channel.channel_id): setup complete called in invalid state"
        )
        raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
        return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
    end

    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): setup complete"
    )

    # Calculate message overheads
    _channel_calculate_message_overheads!(channel)

    channel.channel_state = ChannelState.ACTIVE

    # Invoke setup callback
    if channel.on_setup_completed !== nothing
        Base.invokelatest(channel.on_setup_completed, channel, AWS_OP_SUCCESS, channel.setup_user_data)
    end

    return nothing
end

mutable struct ChannelShutdownWriteArgs
    slot::ChannelSlot
    error_code::Int
    shutdown_immediately::Bool
end

function _channel_shutdown_write_task(args::ChannelShutdownWriteArgs, status::TaskStatus.T)
    slot = args.slot
    if slot.handler === nothing
        return nothing
    end
    handler_shutdown(slot.handler, slot, ChannelDirection.WRITE, args.error_code, args.shutdown_immediately)
    return nothing
end

function _channel_shutdown_completion_task(channel::Channel, status::TaskStatus.T)
    tasks = ChannelTask[]
    lock(channel.pending_tasks_lock) do
        for (task, _) in channel.pending_tasks
            push!(tasks, task)
        end
    end

    for task in tasks
        event_loop_cancel_task!(channel.event_loop, task.wrapper_task)
    end

    if channel.statistics_handler !== nothing
        if channel.statistics_task !== nothing
            event_loop_cancel_task!(channel.event_loop, channel.statistics_task)
        end
        close!(channel.statistics_handler)
        channel.statistics_handler = nothing
        channel.statistics_task = nothing
    end

    if channel.on_shutdown_completed !== nothing
        Base.invokelatest(channel.on_shutdown_completed, channel, channel.shutdown_error_code, channel.shutdown_user_data)
    end

    return nothing
end

function _channel_schedule_shutdown_completion!(channel::Channel)
    logf(
        LogLevel.INFO, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): shutdown complete, error=$(channel.shutdown_error_code)"
    )
    task = ScheduledTask(_channel_shutdown_completion_task, channel; type_tag = "channel_shutdown_complete")
    event_loop_schedule_task_now!(channel.event_loop, task)
    return nothing
end

function _channel_shutdown_task(task::ChannelTask, channel::Channel, status::TaskStatus.T)
    if channel.channel_state == ChannelState.SHUT_DOWN ||
            channel.channel_state == ChannelState.SHUTTING_DOWN_READ ||
            channel.channel_state == ChannelState.SHUTTING_DOWN_WRITE
        return nothing
    end

    channel.channel_state = ChannelState.SHUTTING_DOWN_READ

    slot = channel.first
    if slot !== nothing && slot.handler !== nothing
        channel_slot_shutdown!(slot, ChannelDirection.READ, channel.shutdown_error_code, channel.shutdown_immediately)
        return nothing
    end

    channel.channel_state = ChannelState.SHUT_DOWN
    _channel_schedule_shutdown_completion!(channel)
    return nothing
end

# Shutdown the channel
function channel_shutdown!(channel::Channel, error_code::Int = 0; shutdown_immediately::Bool = false)::Union{Nothing, ErrorResult}
    if channel.channel_state == ChannelState.SHUT_DOWN ||
            channel.channel_state == ChannelState.SHUTTING_DOWN_READ ||
            channel.channel_state == ChannelState.SHUTTING_DOWN_WRITE ||
            channel.shutdown_pending
        return nothing
    end

    channel.shutdown_error_code = error_code
    channel.shutdown_immediately = shutdown_immediately
    channel.shutdown_pending = true

    channel_task_init!(channel.shutdown_task, _channel_shutdown_task, channel, "channel_shutdown")
    channel_schedule_task_now!(channel, channel.shutdown_task)
    return nothing
end

# Shutdown a handler slot
function channel_slot_shutdown!(
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Union{Nothing, ErrorResult}
    if slot.handler === nothing
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end
    return handler_shutdown(slot.handler, slot, direction, error_code, free_scarce_resources_immediately)
end

# Called when a slot completes its shutdown in a direction
function channel_slot_on_handler_shutdown_complete!(
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )
    channel = slot.channel

    if channel === nothing
        return nothing
    end

    logf(
        LogLevel.TRACE, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): slot handler shutdown complete, direction=$direction"
    )

    if channel.channel_state == ChannelState.SHUT_DOWN
        return nothing
    end

    if error_code != 0 && channel.shutdown_error_code == 0
        channel.shutdown_error_code = error_code
    end

    if direction == ChannelDirection.READ
        next_slot = slot.adj_right
        if next_slot !== nothing && next_slot.handler !== nothing
            return handler_shutdown(
                next_slot.handler,
                next_slot,
                direction,
                error_code,
                free_scarce_resources_immediately,
            )
        end

        channel.channel_state = ChannelState.SHUTTING_DOWN_WRITE
        write_args = ChannelShutdownWriteArgs(slot, error_code, free_scarce_resources_immediately)
        write_task = ScheduledTask(_channel_shutdown_write_task, write_args; type_tag = "channel_shutdown_write")
        event_loop_schedule_task_now!(channel.event_loop, write_task)
        return nothing
    end

    next_slot = slot.adj_left
    if next_slot !== nothing && next_slot.handler !== nothing
        return handler_shutdown(
            next_slot.handler,
            next_slot,
            direction,
            error_code,
            free_scarce_resources_immediately,
        )
    end

    if slot === channel.first
        channel.channel_state = ChannelState.SHUT_DOWN
        _channel_schedule_shutdown_completion!(channel)
    end

    return nothing
end

# Acquire a message from the channel's message pool
function channel_acquire_message_from_pool(channel::Channel, message_type::IoMessageType.T, size_hint::Integer)::Union{IoMessage, Nothing}
    if channel.message_pool === nothing
        # No pool, create directly
        message = IoMessage(size_hint)
        message.owning_channel = channel
        return message
    end

    message = message_pool_acquire(channel.message_pool, message_type, size_hint)
    if message !== nothing
        message.owning_channel = channel
    end
    return message
end

# Release a message back to the channel's message pool
function channel_release_message_to_pool!(channel::Channel, message::IoMessage)
    if channel.message_pool === nothing
        # No pool, just let GC handle it
        return nothing
    end

    return message_pool_release!(channel.message_pool, message)
end

function _channel_destroy_impl!(channel::Channel)
    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): destroying channel"
    )

    slot = channel.first
    if slot === nothing || slot.handler === nothing
        channel.channel_state = ChannelState.SHUT_DOWN
    end

    if channel.channel_state != ChannelState.SHUT_DOWN
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL,
            "Channel id=$(channel.channel_id): destroy called before shutdown complete"
        )
        return nothing
    end

    while slot !== nothing
        next = slot.adj_right
        if slot.handler !== nothing
            handler_destroy(slot.handler)
            slot.handler = nothing
        end
        slot.adj_left = nothing
        slot.adj_right = nothing
        slot.channel = nothing
        slot = next
    end

    clear!(channel.statistics_list)
    if channel.statistics_handler !== nothing
        close!(channel.statistics_handler)
        channel.statistics_handler = nothing
        channel.statistics_task = nothing
    end

    event_loop_group_release_from_event_loop!(channel.event_loop)
    channel.first = nothing
    channel.last = nothing
    return nothing
end

function _channel_destroy_task(channel::Channel, status::TaskStatus.T)
    _channel_destroy_impl!(channel)
    return nothing
end

function channel_destroy!(channel::Channel)
    if channel_thread_is_callers_thread(channel)
        return _channel_destroy_impl!(channel)
    end
    task = ScheduledTask(_channel_destroy_task, channel; type_tag = "channel_destroy")
    event_loop_schedule_task_now!(channel.event_loop, task)
    return nothing
end

# Helper struct for simple passthrough handler
struct PassthroughHandlerVTable end

mutable struct PassthroughHandler{SlotRef <: Union{ChannelSlot, Nothing}} <: AbstractChannelHandler
    slot::SlotRef
    initial_window_size::Csize_t
    message_overhead::Csize_t
end

function PassthroughHandler(;
        initial_window_size::Integer = SIZE_MAX,
        message_overhead::Integer = 0,
    )
    return PassthroughHandler{Union{ChannelSlot, Nothing}}(
        nothing,
        Csize_t(initial_window_size),
        Csize_t(message_overhead),
    )
end

function handler_process_read_message(handler::PassthroughHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    return channel_slot_send_message(slot, message, ChannelDirection.READ)
end

function handler_process_write_message(handler::PassthroughHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    return channel_slot_send_message(slot, message, ChannelDirection.WRITE)
end

function handler_increment_read_window(handler::PassthroughHandler, slot::ChannelSlot, size::Csize_t)::Union{Nothing, ErrorResult}
    return channel_slot_increment_read_window!(slot, size)
end

function handler_shutdown(
        handler::PassthroughHandler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Union{Nothing, ErrorResult}
    channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    return nothing
end

function handler_initial_window_size(handler::PassthroughHandler)::Csize_t
    return handler.initial_window_size
end

function handler_message_overhead(handler::PassthroughHandler)::Csize_t
    return handler.message_overhead
end
