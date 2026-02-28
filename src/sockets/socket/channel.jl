# AWS IO Library - Channel Pipeline
# Port of aws-c-io/source/channel.c and include/aws/io/channel.h

# Channel read/write directions are defined in socket.jl as ChannelDirection

const DEFAULT_CHANNEL_MAX_FRAGMENT_SIZE = 16 * 1024
const g_channel_max_fragment_size = Ref{Csize_t}(Csize_t(DEFAULT_CHANNEL_MAX_FRAGMENT_SIZE))

# Channel task wrapper (aws_channel_task)
mutable struct ChannelTask{CH}
    wrapper_task::ScheduledTask
    task_fn::EventCallable
    type_tag::String
    channel::CH

    function ChannelTask{CH}(wrapper_task::ScheduledTask, task_fn::EventCallable, type_tag::String) where {CH}
        return new{CH}(wrapper_task, task_fn, type_tag)
    end
end

const _noop_event_callable = EventCallable((_::Int) -> nothing)

function ChannelTask{CH}(task_fn::EventCallable, type_tag::AbstractString) where {CH}
    local task::ChannelTask{CH}
    wrapper_task = ScheduledTask(; type_tag = type_tag) do status
        try
            _channel_task_wrapper(task, _coerce_task_status(status))
        catch
            Core.println("channel task ($type_tag) errored")
        end
        return nothing
    end
    task = ChannelTask{CH}(wrapper_task, task_fn, String(type_tag))
    return task
end

ChannelTask{CH}() where {CH} = ChannelTask{CH}(_noop_event_callable, "channel_task")

function channel_task_init!(task::ChannelTask, task_fn::EventCallable, type_tag::AbstractString)
    task.task_fn = task_fn
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

include("channel_callables.jl")

const _CHANNEL_SLOT_STATE_DETACHED = UInt8(0)
const _CHANNEL_SLOT_STATE_ATTACHED = UInt8(1)

# Channel slot - links handlers in the pipeline
# Each slot can hold a handler and links to adjacent slots.
# Read direction flows left -> right (toward application).
# Write direction flows right -> left (toward socket).
# Slots are frequently traversed (`adj_left`/`adj_right`) so keep that side
# concretely typed. The backref to the owning channel is parametric so hot paths
# avoid `Any`-typed channel access under trim verification.
mutable struct ChannelSlot{CH}
    adj_left::Union{ChannelSlot{CH}, Nothing}   # Toward the socket/network (write direction)
    adj_right::Union{ChannelSlot{CH}, Nothing}  # Toward the application (read direction)
    handler_read::Union{ChannelHandlerReadCallable, Nothing}
    handler_write::Union{ChannelHandlerWriteCallable, Nothing}
    handler_increment_window::Union{ChannelHandlerIncrementWindowCallable, Nothing}
    handler_shutdown_fn::Union{ChannelHandlerShutdownCallable, Nothing}
    handler_message_overhead_fn::Union{ChannelHandlerMessageOverheadCallable, Nothing}
    handler_destroy_fn::Union{ChannelHandlerDestroyCallable, Nothing}
    handler_trigger_read_fn::Union{ChannelHandlerTriggerReadCallable, Nothing}
    handler_reset_statistics_fn::Union{Function, Nothing}
    handler_gather_statistics_fn::Union{Function, Nothing}
    channel::CH
    @atomic state::UInt8
    window_size::Csize_t
    current_window_update_batch_size::Csize_t
    upstream_message_overhead::Csize_t
end

function ChannelSlot{CH}(channel::CH) where {CH}
    return ChannelSlot{CH}(
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        channel,
        _CHANNEL_SLOT_STATE_DETACHED,
        Csize_t(0),
        Csize_t(0),
        Csize_t(0),
    )
end

@inline function channel_slot_is_attached(slot::ChannelSlot)::Bool
    return (@atomic :acquire slot.state) == _CHANNEL_SLOT_STATE_ATTACHED
end

@inline function _channel_slot_mark_attached!(slot::ChannelSlot)::Nothing
    @atomic :release slot.state = _CHANNEL_SLOT_STATE_ATTACHED
    return nothing
end

@inline function _channel_slot_mark_detached!(slot::ChannelSlot)::Nothing
    @atomic :release slot.state = _CHANNEL_SLOT_STATE_DETACHED
    return nothing
end

@inline function _channel_slot_has_handler(slot::ChannelSlot)::Bool
    return slot.handler_read !== nothing
end

@inline function _channel_slot_clear_handler!(slot::ChannelSlot)::Nothing
    if slot.handler_destroy_fn !== nothing
        (slot.handler_destroy_fn::ChannelHandlerDestroyCallable)()
    end
    slot.handler_read = nothing
    slot.handler_write = nothing
    slot.handler_increment_window = nothing
    slot.handler_shutdown_fn = nothing
    slot.handler_message_overhead_fn = nothing
    slot.handler_destroy_fn = nothing
    slot.handler_trigger_read_fn = nothing
    slot.handler_reset_statistics_fn = nothing
    slot.handler_gather_statistics_fn = nothing
    return nothing
end

# Get the slot immediately to the left (socket side)
slot_left(slot::ChannelSlot) = slot.adj_left
# Get the slot immediately to the right (application side)
slot_right(slot::ChannelSlot) = slot.adj_right

# Channel handler vtable interface - methods that all handlers must implement
# These are dispatched via multiple dispatch on the vtable type

# Process an incoming read message (from socket toward application)
function handler_process_read_message(handler, slot::ChannelSlot, message)::Nothing
    error("handler_process_read_message must be implemented for $(typeof(handler))")
end

# Process an outgoing write message (from application toward socket)
function handler_process_write_message(handler, slot::ChannelSlot, message::IoMessage)::Nothing
    error("handler_process_write_message must be implemented for $(typeof(handler))")
end

# Increment the read window (flow control) - more data can be read
function handler_increment_read_window(handler, slot::ChannelSlot, size::Csize_t)::Nothing
    error("handler_increment_read_window must be implemented for $(typeof(handler))")
end

# Initiate graceful shutdown of the handler
function handler_shutdown(
        handler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Nothing
    error("handler_shutdown must be implemented for $(typeof(handler))")
end

# Get the current window size for the handler
function handler_initial_window_size(handler)::Csize_t
    error("handler_initial_window_size must be implemented for $(typeof(handler))")
end

# Get the message overhead size for this handler
function handler_message_overhead(handler)::Csize_t
    error("handler_message_overhead must be implemented for $(typeof(handler))")
end

# Called when shutdown completes for cleanup
function handler_destroy(handler)::Nothing
    # Default implementation does nothing
    return nothing
end

# Reset handler statistics
function handler_reset_statistics(handler)::Nothing
    # Default implementation does nothing
    return nothing
end

# Gather handler statistics
function handler_gather_statistics(handler)::Any
    # Default implementation returns nothing
    return nothing
end

# Trigger handler to write its pending data
function handler_trigger_write(handler)::Nothing
    # Default implementation does nothing
    return nothing
end

# Trigger handler to read data if it is a data-source handler
function handler_trigger_read(handler)::Nothing
    # Default implementation does nothing
    return nothing
end

function setchannelslot!(handler, slot::ChannelSlot)::Nothing
    _ = handler
    _ = slot
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
mutable struct Channel
    event_loop::EventLoop
    has_event_loop_lease::Bool
    first::Union{ChannelSlot{Channel}, Nothing}  # nullable - Socket side (leftmost)
    last::Union{ChannelSlot{Channel}, Nothing}   # nullable - Application side (rightmost)
    socket::Union{Socket, Nothing}
    channel_state::ChannelState.T
    read_back_pressure_enabled::Bool
    channel_id::UInt64
    setup_pending::Bool
    destroy_pending::Bool
    message_pool::Union{MessagePool, Nothing}  # nullable
    # Setup state
    on_setup_completed::Union{ChannelCallable, Nothing}  # nullable
    negotiated_protocol::Union{String, Nothing}
    setup_future::Future{Nothing}
    # Statistics tracking
    read_message_count::Csize_t
    write_message_count::Csize_t
    statistics_handler::Union{StatisticsHandler, Nothing}  # nullable
    statistics_task::Union{ScheduledTask, Nothing}  # nullable
    statistics_interval_start_time_ms::UInt64
    statistics_list::Vector{Any}
    # Window/backpressure tracking
    window_update_batch_emit_threshold::Csize_t
    window_update_scheduled::Bool
    window_update_task::ChannelTask{Channel}
    # Channel task tracking
    pending_tasks::IdDict{ChannelTask{Channel}, Bool}
    pending_tasks_lock::ReentrantLock
    cross_thread_tasks::Vector{ChannelTask{Channel}}
    cross_thread_tasks_lock::ReentrantLock
    cross_thread_tasks_scheduled::Bool
    cross_thread_task::ScheduledTask
    # Shutdown tracking
    on_shutdown_completed::Union{EventCallable, Nothing}  # nullable
    shutdown_error_code::Int
    shutdown_pending::Bool
    shutdown_immediately::Bool
    shutdown_task::ChannelTask{Channel}
    shutdown_lock::ReentrantLock
end

ChannelSlot(channel::Channel) = ChannelSlot{Channel}(channel)

ChannelTask(task_fn::EventCallable, type_tag::AbstractString) = ChannelTask{Channel}(task_fn, type_tag)
ChannelTask() = ChannelTask{Channel}()

@inline function slot_channel(slot::ChannelSlot)::Channel
    channel_slot_is_attached(slot) || error("ChannelSlot is detached")
    ch = slot.channel
    ch isa Channel || error("ChannelSlot has no owning Channel")
    return ch::Channel
end

# Global channel counter for unique IDs
mutable struct _ChannelIdCounter
    @atomic value::UInt64
end

const _channel_id_counter = _ChannelIdCounter(UInt64(0))

function _next_channel_id()::UInt64
    return @atomic _channel_id_counter.value += 1
end

function _channel_add_pending_task!(channel::Channel, task::ChannelTask{Channel})
    lock(channel.pending_tasks_lock) do
        channel.pending_tasks[task] = true
    end
    return nothing
end

function _channel_remove_pending_task!(channel::Channel, task::ChannelTask{Channel})
    lock(channel.pending_tasks_lock) do
        delete!(channel.pending_tasks, task)
    end
    return nothing
end

@inline function _channel_release_event_loop_lease!(channel::Channel)
    if channel.has_event_loop_lease
        channel.has_event_loop_lease = false
        Base.release(channel.event_loop)
    end
    return nothing
end

function _channel_task_wrapper(task::ChannelTask{Channel}, status::TaskStatus.T)
    @assert isdefined(task, :channel)
    channel = task.channel
    _channel_remove_pending_task!(channel, task)
    final_status = (status == TaskStatus.CANCELED || channel.channel_state == ChannelState.SHUT_DOWN) ?
        TaskStatus.CANCELED : status
    task.task_fn(Int(final_status))
    return nothing
end

function _channel_schedule_cross_thread_tasks(channel::Channel, status::TaskStatus.T)
    tasks = ChannelTask{Channel}[]
    lock(channel.cross_thread_tasks_lock) do
        while !isempty(channel.cross_thread_tasks)
            task = popfirst!(channel.cross_thread_tasks)
            task === nothing && break
            push!(tasks, task)
        end
        channel.cross_thread_tasks_scheduled = false
    end

    final_status = (status == TaskStatus.CANCELED || channel.channel_state == ChannelState.SHUT_DOWN) ?
        TaskStatus.CANCELED : TaskStatus.RUN_READY

    for task in tasks
        if task.wrapper_task.timestamp == 0 || final_status == TaskStatus.CANCELED
            _channel_task_wrapper(task, final_status)
        else
            schedule_task_future!(channel.event_loop, task.wrapper_task, task.wrapper_task.timestamp)
        end
    end
    return nothing
end

function _channel_register_task_cross_thread!(channel::Channel, task::ChannelTask{Channel})
    schedule_now = false
    lock(channel.cross_thread_tasks_lock) do
        if channel.channel_state == ChannelState.SHUT_DOWN
            schedule_now = true
        else
            push!(channel.cross_thread_tasks, task)
            if !channel.cross_thread_tasks_scheduled
                channel.cross_thread_tasks_scheduled = true
                schedule_now = true
            end
        end
    end

    if schedule_now
        if channel.channel_state == ChannelState.SHUT_DOWN
            _channel_task_wrapper(task, TaskStatus.CANCELED)
        else
            schedule_task_now!(channel.event_loop, channel.cross_thread_task)
        end
    end
    return nothing
end

# Get the event loop associated with a channel
channel_event_loop(channel::Channel) = channel.event_loop

# Check if caller is on channel's event loop thread
channel_thread_is_callers_thread(channel::Channel) = event_loop_thread_is_callers_thread(channel.event_loop)

# Get current clock time from event loop
channel_current_clock_time(channel::Channel) = clock_now_ns()

# Force a read by the data-source handler (socket side)
function channel_trigger_read(channel::Channel)::Nothing
    if channel === nothing
        throw_error(ERROR_INVALID_ARGUMENT)
    end
    if !channel_thread_is_callers_thread(channel)
        throw_error(ERROR_INVALID_STATE)
    end
    slot = channel.first
    if slot === nothing || slot.handler_trigger_read_fn === nothing
        throw_error(ERROR_INVALID_STATE)
    end
    (slot.handler_trigger_read_fn::ChannelHandlerTriggerReadCallable)()
    return nothing
end

function _channel_get_or_create_message_pool(channel::Channel)::MessagePool
    pool = channel.event_loop.message_pool
    if pool isa MessagePool
        return pool
    end
    if pool !== nothing
        channel.event_loop.message_pool = nothing
    end

    pool = MessagePool(;
        application_data_msg_data_size = Int(g_channel_max_fragment_size[]),
        application_data_msg_count = 4,
        small_block_msg_data_size = 128,
        small_block_msg_count = 4,
    )
    channel.event_loop.message_pool = pool
    return pool
end

negotiated_protocol(channel::Channel) = channel.negotiated_protocol

@inline function _channel_error_code_from_exception(
        context::AbstractString,
        e,
        bt,
    )::Int
    _ = context
    _ = bt
    return e isa ReseauError ? e.code : ERROR_UNKNOWN
end

function install_last_handler!(channel::Channel, handler)
    new_slot = channel_slot_new!(channel)
    channel_slot_insert_end!(channel, new_slot)
    channel_slot_set_handler!(new_slot, handler)
    return nothing
end

function _complete_setup!(error_code::Int, channel::Channel)::Nothing
    channel.setup_pending = false
    destroy_after_setup = channel.destroy_pending
    channel.destroy_pending = false
    if error_code != OP_SUCCESS
        if channel.on_setup_completed !== nothing
            try
                channel.on_setup_completed(error_code, nothing)
            catch
            end
        end
        channel_shutdown!(channel, error_code)
        if channel.socket !== nothing
            socket_close(channel.socket)
        end
        notify_exception!(channel.setup_future, ReseauError(error_code))
        if destroy_after_setup
            channel_destroy!(channel)
        end
        return nothing
    end
    try
        if channel.on_setup_completed !== nothing
            channel.on_setup_completed(error_code, channel)
        end
        notify(channel.setup_future, nothing)
    catch e
        err = _channel_error_code_from_exception("setup callback", e, catch_backtrace())
        channel_shutdown!(channel, err)
        if channel.socket !== nothing
            socket_close(channel.socket)
        end
        notify_exception!(channel.setup_future, ReseauError(err))
        if destroy_after_setup
            channel_destroy!(channel)
        end
        return nothing
    end
    if destroy_after_setup
        channel_destroy!(channel)
    end
    return nothing
end

@inline function _channel_fail_setup_or_shutdown!(
        channel::Channel,
        socket::Socket,
        error_code::Int,
    )::Nothing
    if channel.setup_pending
        _complete_setup!(error_code, channel)
        return nothing
    end
    channel_shutdown!(channel, error_code)
    socket_close(socket)
    return nothing
end

function Channel(
    event_loop::EventLoop,
    socket::Union{Socket, Nothing} = nothing;
    on_setup_completed::Union{ChannelCallable, Nothing} = nothing,
    on_shutdown_completed::Union{EventCallable, Nothing} = nothing,
    enable_read_back_pressure::Bool = false,
    tls_connection_options::MaybeTlsConnectionOptions = nothing,
    wait_for_setup::Bool = true,
    auto_setup::Bool = socket !== nothing,
)
    channel = Channel(
        event_loop,
        false,    # has_event_loop_lease
        nothing,  # first
        nothing,  # last
        socket,  # socket,
        ChannelState.NOT_INITIALIZED,
        enable_read_back_pressure,
        _next_channel_id(),
        false,  # setup_pending
        false,  # destroy_pending
        nothing,  # message_pool
        on_setup_completed,
        nothing,  # negotiated_protocol
        Future{Nothing}(),
        Csize_t(0),  # read_message_count
        Csize_t(0),  # write_message_count
        nothing,  # statistics_handler
        nothing,  # statistics_task
        UInt64(0),  # statistics_interval_start_time_ms
        Any[],
        enable_read_back_pressure ? Csize_t(g_channel_max_fragment_size[] * 2) : Csize_t(0), # window_threshold
        false,       # window_update_scheduled
        ChannelTask{Channel}(),
        IdDict{ChannelTask{Channel}, Bool}(),
        ReentrantLock(),
        ChannelTask{Channel}[],
        ReentrantLock(),
        false,
        ScheduledTask((_) -> nothing; type_tag = "channel_cross_thread_placeholder"),
        on_shutdown_completed,
        0,        # shutdown_error_code
        false,    # shutdown_pending
        false,    # shutdown_immediately
        ChannelTask{Channel}(),
        ReentrantLock(),
    )
    channel.cross_thread_task = ScheduledTask(; type_tag = "channel_cross_thread_tasks") do status
        try
            _channel_schedule_cross_thread_tasks(channel, _coerce_task_status(status))
        catch e
            Core.println("channel_cross_thread_tasks errored")
        end
        return nothing
    end
    # initial channel setup
    Base.acquire(event_loop)
    acquired = true
    try
        channel.has_event_loop_lease = true
        channel.setup_pending = auto_setup
        channel.destroy_pending = false
        if !auto_setup
            acquired = false
            return channel
        end
        channel.channel_state = ChannelState.SETTING_UP
        setup_fn = function (status::TaskStatus.T)
            try
                if status != TaskStatus.RUN_READY
                    _complete_setup!(ERROR_SYS_CALL_FAILURE, channel)
                    return nothing
                end
                pool = _channel_get_or_create_message_pool(channel)
                channel.message_pool = pool
                channel.channel_state = ChannelState.ACTIVE
                if socket === nothing
                    _complete_setup!(OP_SUCCESS, channel)
                    return nothing
                end
                socket_obj = socket::Socket
                # install socket handler
                local handler_result
                try
                    handler_result = socket_channel_handler_new!(channel, socket_obj)
                catch e
                    err = _channel_error_code_from_exception("socket handler setup", e, catch_backtrace())
                    logf(
                        LogLevel.ERROR,
                        LS_IO_CHANNEL_BOOTSTRAP,
                        "ClientBootstrap: failed to create socket channel handler",
                    )
                    _complete_setup!(err, channel)
                    return nothing
                end
                # install TLS handler (if applicable)
                if tls_connection_options !== nothing &&
                    _socket_uses_network_framework_tls(socket_obj, tls_connection_options)
                    channel.negotiated_protocol = byte_buffer_as_string(socket_get_protocol(socket_obj))
                    _complete_setup!(OP_SUCCESS, channel)
                    _schedule_trigger_read(channel, socket_obj)
                    return nothing
                elseif tls_connection_options !== nothing
                    tls_options = tls_connection_options::TlsConnectionOptions
                    local tls_handler
                    try
                        tls_handler = tls_channel_handler_new!(channel, tls_options)
                    catch e
                        err = _channel_error_code_from_exception("tls handler setup", e, catch_backtrace())
                        _complete_setup!(err, channel)
                        return nothing
                    end
                    if !tls_options.ctx.options.is_server
                        try
                            tls_client_handler_start_negotiation(tls_handler)
                        catch e
                            err = _channel_error_code_from_exception("tls negotiation start", e, catch_backtrace())
                            _complete_setup!(err, channel)
                            return nothing
                        end
                    end
                    _schedule_trigger_read(channel, socket_obj)
                else
                    # non-TLS case
                    _complete_setup!(OP_SUCCESS, channel)
                    _schedule_trigger_read(channel, socket_obj)
                    return nothing
                end
            catch e
                err = _channel_error_code_from_exception("channel setup task", e, catch_backtrace())
                if channel.setup_pending
                    _complete_setup!(err, channel)
                end
            end
            return nothing
        end
        caller_on_event_loop = event_loop_thread_is_callers_thread(event_loop)
        if caller_on_event_loop
            setup_fn(TaskStatus.RUN_READY)
        else
            schedule_task_now!(event_loop; type_tag = "channel_setup") do status
                setup_fn(_coerce_task_status(status))
                return nothing
            end
        end
        acquired = false
        if caller_on_event_loop
            return channel
        end
    finally
        acquired && Base.release(event_loop)
    end
    if wait_for_setup && @atomic event_loop.running
        wait(channel.setup_future)
    end
    return channel
end

function _schedule_trigger_read(channel::Channel, socket::Socket)::Nothing
    if channel_thread_is_callers_thread(channel)
        try
            channel_trigger_read(channel)
        catch e
            err = _channel_error_code_from_exception("trigger_read immediate", e, catch_backtrace())
            _channel_fail_setup_or_shutdown!(channel, socket, err)
        end
        return nothing
    end
    trigger_task = ChannelTask(
        EventCallable(s -> begin
            _coerce_task_status(s) == TaskStatus.RUN_READY || return nothing
            try
                channel_trigger_read(channel)
            catch e
                err = _channel_error_code_from_exception("trigger_read scheduled", e, catch_backtrace())
                _channel_fail_setup_or_shutdown!(channel, socket, err)
                return nothing
            end
            return nothing
        end),
        "channel_trigger_read",
    )
    channel_schedule_task_now!(channel, trigger_task)
    return nothing
end

# Get unique channel ID
channel_id(channel::Channel) = channel.channel_id

# Get the first slot (socket side)
channel_first_slot(channel::Channel) = channel.first

# Get the last slot (application side)
channel_last_slot(channel::Channel) = channel.last

# Channel task scheduling
function _channel_register_task!(
        channel::Channel,
        task::ChannelTask{Channel},
        run_at_nanos::UInt64;
        serialized::Bool = false,
    )
    if channel.channel_state == ChannelState.SHUT_DOWN
        task.task_fn(Int(TaskStatus.CANCELED))
        return nothing
    end

    setfield!(task, :channel, channel)
    task.wrapper_task.timestamp = run_at_nanos
    task.wrapper_task.scheduled = false
    _channel_add_pending_task!(channel, task)

    if serialized
        _channel_register_task_cross_thread!(channel, task)
        return nothing
    end

    if channel_thread_is_callers_thread(channel)
        if run_at_nanos == 0
            schedule_task_now!(channel.event_loop, task.wrapper_task)
        else
            schedule_task_future!(channel.event_loop, task.wrapper_task, run_at_nanos)
        end
    else
        _channel_register_task_cross_thread!(channel, task)
    end

    return nothing
end

function channel_schedule_task_now!(channel::Channel, task::ChannelTask{Channel})
    return _channel_register_task!(channel, task, UInt64(0); serialized = false)
end

function channel_schedule_task_now_serialized!(channel::Channel, task::ChannelTask{Channel})
    return _channel_register_task!(channel, task, UInt64(0); serialized = true)
end

function channel_schedule_task_future!(channel::Channel, task::ChannelTask{Channel}, run_at_nanos::UInt64)
    return _channel_register_task!(channel, task, run_at_nanos; serialized = false)
end

# Check if channel is active
channel_is_active(channel::Channel) = channel.channel_state == ChannelState.ACTIVE

# Set the channel setup callback
function channel_set_setup_callback!(channel::Channel, callback::ChannelCallable)
    channel.on_setup_completed = callback
    return nothing
end

# Set the channel shutdown callback
function channel_set_shutdown_callback!(channel::Channel, callback::EventCallable)
    channel.on_shutdown_completed = callback
    return nothing
end

function _channel_reset_statistics!(channel::Channel)
    current = channel.first
    while current !== nothing
        reset_fn = current.handler_reset_statistics_fn
        reset_fn !== nothing && reset_fn()
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

    now_ns = clock_now_ns()
    now_ms = timestamp_convert(now_ns, TIMESTAMP_NANOS, TIMESTAMP_MILLIS, nothing)

    empty!(channel.statistics_list)
    current = channel.first
    while current !== nothing
        gather_fn = current.handler_gather_statistics_fn
        if gather_fn !== nothing
            stats = gather_fn()
            stats !== nothing && push!(channel.statistics_list, stats)
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
        schedule_task_future!(channel.event_loop, channel.statistics_task, now_ns + report_ns)
    end
    channel.statistics_interval_start_time_ms = now_ms
    return nothing
end

function channel_set_statistics_handler!(channel::Channel, handler::Union{StatisticsHandler, Nothing})
    if channel.statistics_handler !== nothing
        close!(channel.statistics_handler)
        if channel.statistics_task !== nothing
            cancel_task!(channel.event_loop, channel.statistics_task)
        end
        channel.statistics_handler = nothing
        channel.statistics_task = nothing
    end

    if handler !== nothing
        task = ScheduledTask(; type_tag = "gather_statistics") do status
            try
                _channel_gather_statistics_task(channel, _coerce_task_status(status))
            catch e
                Core.println("gather_statistics task errored")
            end
            return nothing
        end
        now_ns = clock_now_ns()
        report_ns = timestamp_convert(
            report_interval_ms(handler),
            TIMESTAMP_MILLIS,
            TIMESTAMP_NANOS,
            nothing,
        )
        channel.statistics_interval_start_time_ms =
            timestamp_convert(now_ns, TIMESTAMP_NANOS, TIMESTAMP_MILLIS, nothing)
        _channel_reset_statistics!(channel)
        schedule_task_future!(channel.event_loop, task, now_ns + report_ns)
        channel.statistics_task = task
    end

    channel.statistics_handler = handler
    return nothing
end

# Slot operations

# Create and insert a new slot into the channel
function channel_slot_new!(channel::Channel)::ChannelSlot
    slot = ChannelSlot(channel)

    if channel.first === nothing
        channel.first = slot
        channel.last = slot
        _channel_slot_mark_attached!(slot)
    end

    logf(
        LogLevel.TRACE, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): created new slot"
    )

    return slot
end

# Insert slot to the right of another slot
function channel_slot_insert_right!(slot::ChannelSlot, to_add::ChannelSlot)
    channel = slot_channel(slot)

    to_add.adj_right = slot.adj_right
    if slot.adj_right !== nothing
        slot.adj_right.adj_left = to_add
    end
    slot.adj_right = to_add
    to_add.adj_left = slot
    to_add.channel = channel
    _channel_slot_mark_attached!(to_add)

    if channel.last === slot
        channel.last = to_add
    end

    return nothing
end

# Insert slot to the left of another slot
function channel_slot_insert_left!(slot::ChannelSlot, to_add::ChannelSlot)
    channel = slot_channel(slot)

    to_add.adj_left = slot.adj_left
    if slot.adj_left !== nothing
        slot.adj_left.adj_right = to_add
    end
    slot.adj_left = to_add
    to_add.adj_right = slot
    to_add.channel = channel
    _channel_slot_mark_attached!(to_add)

    if channel.first === slot
        channel.first = to_add
    end

    return nothing
end

# Insert slot at the end of the channel (application side)
function channel_slot_insert_end!(channel::Channel, slot::ChannelSlot)::Nothing
    slot.channel = channel

    if channel.first === nothing || channel.first === slot
        throw_error(ERROR_INVALID_STATE)
    end

    if channel.last === nothing
        throw_error(ERROR_INVALID_STATE)
    end

    channel_slot_insert_right!(channel.last, slot)
    return nothing
end

# Insert slot at the front of the channel (socket side)
function channel_slot_insert_front!(channel::Channel, slot::ChannelSlot)
    slot.channel = channel

    if channel.first === slot
        return nothing
    end

    if channel.first === nothing
        channel.first = slot
        channel.last = slot
        _channel_slot_mark_attached!(slot)
    else
        channel_slot_insert_left!(channel.first, slot)
    end

    return nothing
end

# Remove a slot from the channel
function channel_slot_remove!(slot::ChannelSlot)
    channel_slot_is_attached(slot) || return nothing
    channel = slot.channel

    if channel.first === slot
        channel.first = slot.adj_right
    end
    if channel.last === slot
        channel.last = slot.adj_left
    end

    if slot.adj_left !== nothing
        slot.adj_left.adj_right = slot.adj_right
    end

    if slot.adj_right !== nothing
        slot.adj_right.adj_left = slot.adj_left
    end

    slot.adj_left = nothing
    slot.adj_right = nothing
    _channel_slot_mark_detached!(slot)

    if _channel_slot_has_handler(slot)
        _channel_slot_clear_handler!(slot)
    end

    _channel_calculate_message_overheads!(channel)

    return nothing
end

# Replace a slot in the channel with a new slot
function channel_slot_replace!(remove::ChannelSlot, new_slot::ChannelSlot)
    channel = slot_channel(remove)
    new_slot.channel = channel
    new_slot.adj_left = remove.adj_left
    new_slot.adj_right = remove.adj_right
    _channel_slot_mark_attached!(new_slot)

    if remove.adj_left !== nothing
        remove.adj_left.adj_right = new_slot
    end
    if remove.adj_right !== nothing
        remove.adj_right.adj_left = new_slot
    end

    if channel.first === remove
        channel.first = new_slot
    end
    if channel.last === remove
        channel.last = new_slot
    end

    remove.adj_left = nothing
    remove.adj_right = nothing
    _channel_slot_mark_detached!(remove)

    if _channel_slot_has_handler(remove)
        _channel_slot_clear_handler!(remove)
    end

    _channel_calculate_message_overheads!(channel)

    return nothing
end

# Set the handler for a slot
function channel_slot_set_handler!(slot::ChannelSlot, handler::H)::Nothing where {H}
    if _channel_slot_has_handler(slot)
        _channel_slot_clear_handler!(slot)
    end
    slot.handler_read = ChannelHandlerReadCallable(handler)
    slot.handler_write = ChannelHandlerWriteCallable(handler)
    slot.handler_increment_window = ChannelHandlerIncrementWindowCallable(handler)
    slot.handler_shutdown_fn = ChannelHandlerShutdownCallable(handler)
    slot.handler_message_overhead_fn = ChannelHandlerMessageOverheadCallable(handler)
    slot.handler_destroy_fn = ChannelHandlerDestroyCallable(handler)
    slot.handler_trigger_read_fn = ChannelHandlerTriggerReadCallable(handler)
    slot.handler_reset_statistics_fn = () -> handler_reset_statistics(handler)
    slot.handler_gather_statistics_fn = () -> handler_gather_statistics(handler)
    setchannelslot!(handler, slot)
    if channel_slot_is_attached(slot)
        _channel_calculate_message_overheads!(slot_channel(slot))
    end
    initial_window = handler_initial_window_size(handler)::Csize_t
    channel_slot_increment_read_window!(slot, initial_window)
    return nothing
end

# Replace handler in a slot
function channel_slot_replace_handler!(slot::ChannelSlot, new_handler)::Nothing
    channel_slot_set_handler!(slot, new_handler)
    return nothing
end

# Message passing functions

# Send a read message to the next slot (toward application)
function channel_slot_send_message(slot::ChannelSlot, message::IoMessage, direction::ChannelDirection.T)::Nothing
    if !channel_slot_is_attached(slot)
        throw_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
    end
    channel = slot.channel

    if direction == ChannelDirection.READ
        # Send toward application (right)
        next_slot = slot.adj_right
        if next_slot === nothing || next_slot.handler_read === nothing
            logf(
                LogLevel.WARN, LS_IO_CHANNEL,
                "Channel id=$(channel.channel_id): no handler to process read message"
            )
            throw_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
        end

        if channel.read_back_pressure_enabled && next_slot.window_size < message.message_data.len
            logf(
                LogLevel.ERROR, LS_IO_CHANNEL,
                "Channel id=$(channel.channel_id): read message exceeds window size"
            )
            throw_error(ERROR_IO_CHANNEL_READ_WOULD_EXCEED_WINDOW)
        end

        message.owning_channel = channel
        channel.read_message_count += 1
        if channel.read_back_pressure_enabled
            next_slot.window_size = sub_size_saturating(next_slot.window_size, message.message_data.len)
        end

        next_slot.handler_read(next_slot, message)
    else
        # Send toward socket (left)
        next_slot = slot.adj_left
        if next_slot === nothing || next_slot.handler_write === nothing
            logf(
                LogLevel.WARN, LS_IO_CHANNEL,
                "Channel id=$(channel.channel_id): no handler to process write message"
            )
            throw_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
        end

        message.owning_channel = channel
        channel.write_message_count += 1

        next_slot.handler_write(next_slot, message)
    end
    return nothing
end

# Returns downstream read window size for slot
function channel_slot_downstream_read_window(slot::ChannelSlot)::Csize_t
    if !channel_slot_is_attached(slot)
        return SIZE_MAX
    end
    channel = slot.channel
    if !channel.read_back_pressure_enabled
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
    if !channel_slot_is_attached(slot)
        throw_error(ERROR_INVALID_ARGUMENT)
    end
    channel = slot.channel
    if !channel_thread_is_callers_thread(channel)
        throw_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end
    overhead = channel_slot_upstream_message_overhead(slot)
    if overhead >= g_channel_max_fragment_size[]
        @assert false "Upstream overhead exceeds channel max fragment size"
    end
    size_hint = g_channel_max_fragment_size[] - overhead
    return channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, size_hint)
end

# Increment read window (flow control propagation)
function channel_slot_increment_read_window!(slot::ChannelSlot, size::Csize_t)::Nothing
    if !channel_slot_is_attached(slot)
        return nothing
    end
    channel = slot.channel
    if channel.read_back_pressure_enabled && channel.channel_state != ChannelState.SHUT_DOWN
        slot.current_window_update_batch_size = add_size_saturating(slot.current_window_update_batch_size, size)
        if !channel.window_update_scheduled && slot.window_size <= channel.window_update_batch_emit_threshold
            channel.window_update_scheduled = true
            channel_task_init!(channel.window_update_task, EventCallable(s -> _channel_window_update_task(channel, _coerce_task_status(s))), "window_update_task")
            channel_schedule_task_now!(channel, channel.window_update_task)
        end
    end
    return nothing
end

function _channel_window_update_task(channel::Channel, status::TaskStatus.T)
    channel.window_update_scheduled = false
    status == TaskStatus.RUN_READY || return nothing

    if channel.channel_state == ChannelState.SHUT_DOWN
        return nothing
    end

    slot = channel.last
    while slot !== nothing && slot.adj_left !== nothing
        upstream_slot = slot.adj_left
        if upstream_slot.handler_increment_window !== nothing
            upstream_handler_increment = upstream_slot.handler_increment_window::ChannelHandlerIncrementWindowCallable
            slot.window_size = add_size_saturating(slot.window_size, slot.current_window_update_batch_size)
            update_size = slot.current_window_update_batch_size
            slot.current_window_update_batch_size = 0
            try
                upstream_handler_increment(upstream_slot, update_size)
            catch e
                e isa ReseauError || rethrow()
                logf(
                    LogLevel.ERROR, LS_IO_CHANNEL,
                    "Channel id=$(channel.channel_id): window update failed with error $(e.code)"
                )
                channel_shutdown!(channel, e.code)
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

        if slot.handler_message_overhead_fn !== nothing
            overhead = add_size_saturating(
                overhead,
                (slot.handler_message_overhead_fn::ChannelHandlerMessageOverheadCallable)(),
            )
        end

        slot = slot.adj_right
    end

    return nothing
end

# Initialize the channel after all handlers are set up
function channel_setup_complete!(channel::Channel)::Nothing
    if channel.channel_state == ChannelState.ACTIVE
        return nothing
    end
    if channel.channel_state != ChannelState.NOT_INITIALIZED && channel.channel_state != ChannelState.SETTING_UP
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL,
            "Channel id=$(channel.channel_id): setup complete called in invalid state"
        )
        throw_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
    end

    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): setup complete"
    )

    # Calculate message overheads
    _channel_calculate_message_overheads!(channel)

    channel.channel_state = ChannelState.ACTIVE

    _complete_setup!(OP_SUCCESS, channel)
    if channel.socket !== nothing
        _schedule_trigger_read(channel, channel.socket)
    end

    return nothing
end

function _channel_shutdown_write_task(
        slot::ChannelSlot,
        error_code::Int,
        shutdown_immediately::Bool,
        status::TaskStatus.T,
    )
    if slot.handler_shutdown_fn === nothing
        return nothing
    end
    (slot.handler_shutdown_fn::ChannelHandlerShutdownCallable)(
        slot,
        ChannelDirection.WRITE,
        error_code,
        shutdown_immediately,
    )
    return nothing
end

function _channel_shutdown_completion_task(channel::Channel, status::TaskStatus.T)
    _ = status
    tasks = ChannelTask{Channel}[]
    lock(channel.pending_tasks_lock) do
        for (task, _) in channel.pending_tasks
            push!(tasks, task)
        end
    end

    for task in tasks
        cancel_task!(channel.event_loop, task.wrapper_task)
    end

    if channel.statistics_handler !== nothing
        if channel.statistics_task !== nothing
            cancel_task!(channel.event_loop, channel.statistics_task)
        end
        close!(channel.statistics_handler)
        channel.statistics_handler = nothing
        channel.statistics_task = nothing
    end

    if channel.on_shutdown_completed !== nothing
        channel.on_shutdown_completed(channel.shutdown_error_code)
    end

    if channel.destroy_pending
        channel.destroy_pending = false
        channel_destroy!(channel)
    end

    return nothing
end

function _channel_schedule_shutdown_completion!(channel::Channel)
    logf(
        LogLevel.INFO, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): shutdown complete, error=$(channel.shutdown_error_code)"
    )
    schedule_task_now!(channel.event_loop; type_tag = "channel_shutdown_complete") do status
        try
            _channel_shutdown_completion_task(channel, _coerce_task_status(status))
        catch
            Core.println("channel_shutdown_complete task errored")
        end
        return nothing
    end
    return nothing
end

function _channel_shutdown_task(channel::Channel, status::TaskStatus.T)
    if channel.channel_state == ChannelState.SHUT_DOWN ||
            channel.channel_state == ChannelState.SHUTTING_DOWN_READ ||
            channel.channel_state == ChannelState.SHUTTING_DOWN_WRITE
        return nothing
    end

    channel.channel_state = ChannelState.SHUTTING_DOWN_READ

    slot = channel.first
    if slot !== nothing && slot.handler_shutdown_fn !== nothing
        channel_slot_shutdown!(slot, ChannelDirection.READ, channel.shutdown_error_code, channel.shutdown_immediately)
        return nothing
    end

    channel.channel_state = ChannelState.SHUT_DOWN
    _channel_release_event_loop_lease!(channel)
    _channel_schedule_shutdown_completion!(channel)
    return nothing
end

# Shutdown the channel
function channel_shutdown!(channel::Channel, error_code::Int = 0; shutdown_immediately::Bool = false)::Nothing
    schedule_task = false
    lock(channel.shutdown_lock) do
        if channel.channel_state == ChannelState.SHUT_DOWN ||
                channel.channel_state == ChannelState.SHUTTING_DOWN_READ ||
                channel.channel_state == ChannelState.SHUTTING_DOWN_WRITE ||
                channel.shutdown_pending
            return nothing
        end

        channel.shutdown_error_code = error_code
        channel.shutdown_immediately = shutdown_immediately
        channel.shutdown_pending = true

        channel_task_init!(channel.shutdown_task, EventCallable(s -> _channel_shutdown_task(channel, _coerce_task_status(s))), "channel_shutdown")
        schedule_task = true
        return nothing
    end

    schedule_task || return nothing
    channel_schedule_task_now!(channel, channel.shutdown_task)
    return nothing
end

# Shutdown a handler slot
function channel_slot_shutdown!(
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Nothing
    if slot.handler_shutdown_fn === nothing
        throw_error(ERROR_INVALID_STATE)
    end
    (slot.handler_shutdown_fn::ChannelHandlerShutdownCallable)(
        slot,
        direction,
        error_code,
        free_scarce_resources_immediately,
    )
    return nothing
end

# Called when a slot completes its shutdown in a direction
function channel_slot_on_handler_shutdown_complete!(
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )
    if !channel_slot_is_attached(slot)
        return nothing
    end
    channel = slot.channel

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
        if next_slot !== nothing && next_slot.handler_shutdown_fn !== nothing
            return (next_slot.handler_shutdown_fn::ChannelHandlerShutdownCallable)(
                next_slot,
                direction,
                error_code,
                free_scarce_resources_immediately,
            )
        end

        channel.channel_state = ChannelState.SHUTTING_DOWN_WRITE
        schedule_task_now!(channel.event_loop; type_tag = "channel_shutdown_write") do status
            try
                _channel_shutdown_write_task(
                    slot,
                    error_code,
                    free_scarce_resources_immediately,
                    _coerce_task_status(status),
                )
            catch e
                Core.println("channel_shutdown_write task errored")
            end
            return nothing
        end
        return nothing
    end

    next_slot = slot.adj_left
    if next_slot !== nothing && next_slot.handler_shutdown_fn !== nothing
        return (next_slot.handler_shutdown_fn::ChannelHandlerShutdownCallable)(
            next_slot,
            direction,
            error_code,
            free_scarce_resources_immediately,
        )
    end

    if slot === channel.first
        channel.channel_state = ChannelState.SHUT_DOWN
        _channel_release_event_loop_lease!(channel)
        _channel_schedule_shutdown_completion!(channel)
    end

    return nothing
end

# Acquire a message from the channel's message pool
function channel_acquire_message_from_pool(channel::Channel, message_type::IoMessageType.T, size_hint::Integer)::Union{IoMessage, Nothing}
    if channel.message_pool === nothing
        # No pool, create directly
        effective_size = size_hint
        if size_hint isa Signed && size_hint < 0
            effective_size = 0
        end
        max_size = Csize_t(g_channel_max_fragment_size[])
        effective_csize = Csize_t(effective_size)
        if effective_csize > max_size
            effective_csize = max_size
        end
        message = IoMessage(Int(effective_csize))
        message.owning_channel = channel
        return message
    end

    message = Base.acquire(channel.message_pool, message_type, size_hint)
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

    return Base.release(channel.message_pool, message)
end

function _channel_destroy_impl!(channel::Channel)
    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): destroying channel"
    )

    slot = channel.first
    if slot === nothing || slot.handler_shutdown_fn === nothing
        channel.channel_state = ChannelState.SHUT_DOWN
    end

    if channel.channel_state != ChannelState.SHUT_DOWN
        channel.destroy_pending = true
        channel_shutdown!(channel, channel.shutdown_error_code)
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL,
            "Channel id=$(channel.channel_id): destroy requested before shutdown complete; deferring"
        )
        return nothing
    end

    while slot !== nothing
        next = slot.adj_right
        if _channel_slot_has_handler(slot)
            _channel_slot_clear_handler!(slot)
        end
        slot.adj_left = nothing
        slot.adj_right = nothing
        _channel_slot_mark_detached!(slot)
        slot = next
    end

    empty!(channel.statistics_list)
    if channel.statistics_handler !== nothing
        close!(channel.statistics_handler)
        channel.statistics_handler = nothing
        channel.statistics_task = nothing
    end

    channel.socket = nothing
    channel.first = nothing
    channel.last = nothing
    _channel_release_event_loop_lease!(channel)
    return nothing
end

function _channel_destroy_task(channel::Channel, status::TaskStatus.T)
    _channel_destroy_impl!(channel)
    return nothing
end

function channel_destroy!(channel::Channel)
    if channel.setup_pending
        channel.destroy_pending = true
        return nothing
    end

    if channel_thread_is_callers_thread(channel)
        return _channel_destroy_impl!(channel)
    end

    destroy_task = ScheduledTask(; type_tag = "channel_destroy") do status
        try
            _channel_destroy_task(channel, _coerce_task_status(status))
        catch e
            Core.println("channel_destroy task errored")
        end
        return nothing
    end
    schedule_task_now!(channel.event_loop, destroy_task)
    return nothing
end

# Helper struct for simple passthrough handler
struct PassthroughHandlerVTable end

mutable struct PassthroughHandler
    slot::Union{ChannelSlot, Nothing}
    initial_window_size::Csize_t
    message_overhead::Csize_t
end

function PassthroughHandler(;
        initial_window_size::Integer = SIZE_MAX,
        message_overhead::Integer = 0,
    )
    return PassthroughHandler(
        nothing,
        Csize_t(initial_window_size),
        Csize_t(message_overhead),
    )
end

function setchannelslot!(handler::PassthroughHandler, slot::ChannelSlot)::Nothing
    handler.slot = slot
    return nothing
end

function handler_process_read_message(handler::PassthroughHandler, slot::ChannelSlot, message::IoMessage)::Nothing
    channel_slot_send_message(slot, message, ChannelDirection.READ)
    return nothing
end

function handler_process_write_message(handler::PassthroughHandler, slot::ChannelSlot, message::IoMessage)::Nothing
    channel_slot_send_message(slot, message, ChannelDirection.WRITE)
    return nothing
end

function handler_increment_read_window(handler::PassthroughHandler, slot::ChannelSlot, size::Csize_t)::Nothing
    channel_slot_increment_read_window!(slot, size)
    return nothing
end

function handler_shutdown(
        handler::PassthroughHandler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Nothing
    channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    return nothing
end

function handler_initial_window_size(handler::PassthroughHandler)::Csize_t
    return handler.initial_window_size
end

function handler_message_overhead(handler::PassthroughHandler)::Csize_t
    return handler.message_overhead
end
