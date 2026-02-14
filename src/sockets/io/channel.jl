# Pipeline State - Closure-based middleware pipeline
#
# Replaces the old Channel → ChannelSlot → AbstractChannelHandler machinery
# with closure-based middleware composed at pipeline construction time.
# See channel-redesign.md for full design rationale.

const DEFAULT_CHANNEL_MAX_FRAGMENT_SIZE = 16 * 1024
const g_aws_channel_max_fragment_size = Ref{Csize_t}(Csize_t(DEFAULT_CHANNEL_MAX_FRAGMENT_SIZE))

# Pipeline lifecycle states (replaces ChannelState)
@enumx PipelineLifecycle::UInt8 begin
    ACTIVE = 0
    SHUTTING_DOWN_READ = 1
    SHUTTING_DOWN_WRITE = 2
    SHUT_DOWN = 3
end

# Shutdown chain - ordered shutdown closures for read and write directions.
# Read shutdown: socket → TLS → app (left to right)
# Write shutdown: app → TLS → socket (right to left)
# Each fn signature: (error_code::Int, free_scarce::Bool, on_complete::Function) -> Nothing
# on_complete signature: (error_code::Int, free_scarce::Bool) -> Nothing
mutable struct ShutdownChain
    read_shutdown_fns::Vector{Any}
    write_shutdown_fns::Vector{Any}
    current_read_idx::Int
    current_write_idx::Int
end

ShutdownChain() = ShutdownChain(Any[], Any[], 1, 1)

# ChannelTask - wraps ScheduledTask with pipeline lifecycle tracking.
# When the task fires, it is removed from the pipeline's pending_tasks
# and canceled if the pipeline is shut down.
mutable struct ChannelTask
    wrapper_task::ScheduledTask
    task_fn::EventCallable
    type_tag::String
    pipeline::Any  # Union{PipelineState, Nothing}
end

const _noop_event_callable = EventCallable((_::Int) -> nothing)

function ChannelTask(task_fn::EventCallable, type_tag::AbstractString)
    task_ref = Ref{Union{ChannelTask, Nothing}}(nothing)
    wrapper_task = ScheduledTask(
        TaskFn(function(status)
            try
                t = task_ref[]
                t !== nothing && _channel_task_wrapper(t, _coerce_task_status(status))
            catch e
                Core.println("channel task ($type_tag) errored")
            end
            return nothing
        end);
        type_tag = type_tag,
    )
    task = ChannelTask(wrapper_task, task_fn, String(type_tag), nothing)
    task_ref[] = task
    return task
end

ChannelTask() = ChannelTask(_noop_event_callable, "channel_task")

function channel_task_init!(task::ChannelTask, task_fn::EventCallable, type_tag::AbstractString)
    task.task_fn = task_fn
    task.type_tag = String(type_tag)
    task.wrapper_task.type_tag = task.type_tag
    task.wrapper_task.timestamp = UInt64(0)
    task.wrapper_task.scheduled = false
    return nothing
end

# Global pipeline counter for unique IDs
mutable struct _ChannelIdCounter
    @atomic value::UInt64
end
const _channel_id_counter = _ChannelIdCounter(UInt64(0))
_next_channel_id()::UInt64 = @atomic _channel_id_counter.value += 1

# PipelineState - shared infrastructure for a middleware pipeline (replaces Channel)
mutable struct PipelineState
    event_loop::EventLoop
    event_loop_group_lease::Union{EventLoopGroupLease, Nothing}
    message_pool::Union{MessagePool, Nothing}
    channel_id::UInt64

    # Lifecycle
    state::PipelineLifecycle.T
    setup_pending::Bool
    destroy_pending::Bool

    # Shutdown
    shutdown_error_code::Int
    shutdown_pending::Bool
    shutdown_immediately::Bool
    on_setup_completed::Union{EventCallable, Nothing}
    on_shutdown_completed::Union{EventCallable, Nothing}
    shutdown_chain::ShutdownChain
    shutdown_task::ChannelTask
    shutdown_lock::ReentrantLock

    # Backpressure
    read_back_pressure_enabled::Bool
    window_update_batch_emit_threshold::Csize_t
    window_update_scheduled::Bool
    window_update_task::ChannelTask
    window_update_fn::Any  # backpressure closure chain (app → H2 → TLS → socket)
    window_update_batch::Csize_t
    downstream_window::Csize_t  # effective app-level window for threshold check

    # Stats
    read_message_count::Csize_t
    write_message_count::Csize_t

    # Task scheduling (cross-thread support)
    pending_tasks::IdDict{ChannelTask, Bool}
    pending_tasks_lock::ReentrantLock
    cross_thread_tasks::Vector{ChannelTask}
    cross_thread_tasks_lock::ReentrantLock
    cross_thread_tasks_scheduled::Bool
    cross_thread_task::ScheduledTask

    # App integration
    socket::Any  # Socket reference, set by socket_pipeline_init!
    downstream_read_setter::Any  # Function(read_fn) — sets the app's read handler
    tls_handler::Any  # TLS handler reference, set by _wire_tls_pipeline!
end

# --- ChannelTask lifecycle ---

function _pipeline_add_pending_task!(ps::PipelineState, task::ChannelTask)
    lock(ps.pending_tasks_lock) do
        ps.pending_tasks[task] = true
    end
    return nothing
end

function _pipeline_remove_pending_task!(ps::PipelineState, task::ChannelTask)
    lock(ps.pending_tasks_lock) do
        delete!(ps.pending_tasks, task)
    end
    return nothing
end

function _channel_task_wrapper(task::ChannelTask, status::TaskStatus.T)
    ps = task.pipeline
    if ps isa PipelineState
        _pipeline_remove_pending_task!(ps, task)
        final_status = (status == TaskStatus.CANCELED || ps.state == PipelineLifecycle.SHUT_DOWN) ?
            TaskStatus.CANCELED : status
        task.task_fn(Int(final_status))
        return nothing
    end
    task.task_fn(Int(status))
    return nothing
end

# --- PipelineState constructor ---

function PipelineState(
        event_loop::EventLoop,
        message_pool::Union{MessagePool, Nothing} = nothing;
        enable_read_back_pressure::Bool = false,
        event_loop_group_lease::Union{EventLoopGroupLease, Nothing} = nothing,
    )
    channel_id = _next_channel_id()
    window_threshold = enable_read_back_pressure ? Csize_t(g_aws_channel_max_fragment_size[] * 2) : Csize_t(0)

    ps = PipelineState(
        event_loop,
        event_loop_group_lease,
        message_pool,
        channel_id,
        PipelineLifecycle.ACTIVE,  # state
        false,  # setup_pending
        false,  # destroy_pending
        0,      # shutdown_error_code
        false,  # shutdown_pending
        false,  # shutdown_immediately
        nothing, # on_setup_completed
        nothing, # on_shutdown_completed
        ShutdownChain(),
        ChannelTask(),  # shutdown_task
        ReentrantLock(), # shutdown_lock
        enable_read_back_pressure,
        window_threshold,
        false,       # window_update_scheduled
        ChannelTask(), # window_update_task
        nothing,     # window_update_fn
        Csize_t(0),  # window_update_batch
        enable_read_back_pressure ? Csize_t(0) : SIZE_MAX,  # downstream_window
        Csize_t(0),  # read_message_count
        Csize_t(0),  # write_message_count
        IdDict{ChannelTask, Bool}(),
        ReentrantLock(),
        ChannelTask[],
        ReentrantLock(),
        false,  # cross_thread_tasks_scheduled
        ScheduledTask(
            TaskFn(function(_status); return nothing; end);
            type_tag = "pipeline_cross_thread_placeholder",
        ),
        nothing, # socket
        nothing, # downstream_read_setter
        nothing, # tls_handler
    )
    ps.cross_thread_task = ScheduledTask(
        TaskFn(function(status)
            try
                _pipeline_schedule_cross_thread_tasks(ps, _coerce_task_status(status))
            catch e
                Core.println("pipeline_cross_thread_tasks errored")
            end
            return nothing
        end);
        type_tag = "pipeline_cross_thread_tasks",
    )
    return ps
end

# --- Pipeline creation API (replaces channel_new) ---

mutable struct _PipelineSetupArgs
    ps::PipelineState
end

function _pipeline_get_or_create_message_pool(ps::PipelineState)::MessagePool
    pool = ps.event_loop.message_pool
    if pool isa MessagePool
        return pool
    end
    if pool !== nothing
        ps.event_loop.message_pool = nothing
    end

    creation_args = MessagePoolCreationArgs(;
        application_data_msg_data_size = Int(g_aws_channel_max_fragment_size[]),
        application_data_msg_count = 4,
        small_block_msg_data_size = 128,
        small_block_msg_count = 4,
    )

    pool = MessagePool(creation_args)
    ps.event_loop.message_pool = pool
    return pool
end

function _pipeline_setup_task(args::_PipelineSetupArgs, status::TaskStatus.T)
    ps = args.ps
    ps.setup_pending = false
    if status != TaskStatus.RUN_READY
        if ps.on_setup_completed !== nothing
            ps.on_setup_completed(ERROR_SYS_CALL_FAILURE)
        end
        if ps.destroy_pending
            ps.destroy_pending = false
            pipeline_destroy!(ps)
        end
        return nothing
    end

    pool = _pipeline_get_or_create_message_pool(ps)
    ps.message_pool = pool

    if ps.on_setup_completed !== nothing
        ps.on_setup_completed(AWS_OP_SUCCESS)
    end
    if ps.destroy_pending
        ps.destroy_pending = false
        pipeline_destroy!(ps)
    end
    return nothing
end

function pipeline_new(
        event_loop::EventLoop;
        event_loop_group::Union{EventLoopGroup, Nothing} = nothing,
        enable_read_back_pressure::Bool = false,
        on_setup_completed::Union{EventCallable, Nothing} = nothing,
        on_shutdown_completed::Union{EventCallable, Nothing} = nothing,
    )::PipelineState
    if event_loop === nothing
        throw_error(ERROR_INVALID_ARGUMENT)
    end

    lease = event_loop_group === nothing ? nothing : event_loop_group_open_lease!(event_loop_group)
    if event_loop_group !== nothing && lease === nothing
        throw_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end

    ps = PipelineState(
        event_loop,
        nothing;
        enable_read_back_pressure = enable_read_back_pressure,
        event_loop_group_lease = lease,
    )
    ps.on_setup_completed = on_setup_completed
    ps.on_shutdown_completed = on_shutdown_completed
    ps.setup_pending = true

    setup_args = _PipelineSetupArgs(ps)
    task = ScheduledTask(
        TaskFn(function(status)
            try
                _pipeline_setup_task(setup_args, _coerce_task_status(status))
            catch e
                Core.println("pipeline_setup task errored")
            end
            return nothing
        end);
        type_tag = "pipeline_setup",
    )
    event_loop_schedule_task_now!(event_loop, task)
    return ps
end

# --- Pipeline queries ---

pipeline_id(ps::PipelineState) = ps.channel_id
pipeline_event_loop(ps::PipelineState) = ps.event_loop
pipeline_is_active(ps::PipelineState) = ps.state == PipelineLifecycle.ACTIVE
pipeline_thread_is_callers_thread(ps::PipelineState) = event_loop_thread_is_callers_thread(ps.event_loop)
pipeline_current_clock_time(ps::PipelineState) = event_loop_current_clock_time(ps.event_loop)

# --- Task scheduling ---

function _pipeline_register_task!(
        ps::PipelineState,
        task::ChannelTask,
        run_at_nanos::UInt64;
        serialized::Bool = false,
    )
    if ps.state == PipelineLifecycle.SHUT_DOWN
        task.task_fn(Int(TaskStatus.CANCELED))
        return nothing
    end

    task.pipeline = ps
    task.wrapper_task.timestamp = run_at_nanos
    task.wrapper_task.scheduled = false
    _pipeline_add_pending_task!(ps, task)

    if serialized
        _pipeline_register_task_cross_thread!(ps, task)
        return nothing
    end

    if pipeline_thread_is_callers_thread(ps)
        if run_at_nanos == 0
            event_loop_schedule_task_now!(ps.event_loop, task.wrapper_task)
        else
            event_loop_schedule_task_future!(ps.event_loop, task.wrapper_task, run_at_nanos)
        end
    else
        _pipeline_register_task_cross_thread!(ps, task)
    end

    return nothing
end

function pipeline_schedule_task_now!(ps::PipelineState, task::ChannelTask)
    return _pipeline_register_task!(ps, task, UInt64(0); serialized = false)
end

function pipeline_schedule_task_now_serialized!(ps::PipelineState, task::ChannelTask)
    return _pipeline_register_task!(ps, task, UInt64(0); serialized = true)
end

function pipeline_schedule_task_future!(ps::PipelineState, task::ChannelTask, run_at_nanos::UInt64)
    return _pipeline_register_task!(ps, task, run_at_nanos; serialized = false)
end

# --- Cross-thread task dispatch ---

function _pipeline_schedule_cross_thread_tasks(ps::PipelineState, status::TaskStatus.T)
    tasks = ChannelTask[]
    lock(ps.cross_thread_tasks_lock) do
        while !isempty(ps.cross_thread_tasks)
            task = popfirst!(ps.cross_thread_tasks)
            task === nothing && break
            push!(tasks, task)
        end
        ps.cross_thread_tasks_scheduled = false
    end

    final_status = (status == TaskStatus.CANCELED || ps.state == PipelineLifecycle.SHUT_DOWN) ?
        TaskStatus.CANCELED : TaskStatus.RUN_READY

    for task in tasks
        if task.wrapper_task.timestamp == 0 || final_status == TaskStatus.CANCELED
            _channel_task_wrapper(task, final_status)
        else
            event_loop_schedule_task_future!(ps.event_loop, task.wrapper_task, task.wrapper_task.timestamp)
        end
    end
    return nothing
end

function _pipeline_register_task_cross_thread!(ps::PipelineState, task::ChannelTask)
    schedule_now = false
    lock(ps.cross_thread_tasks_lock) do
        if ps.state == PipelineLifecycle.SHUT_DOWN
            schedule_now = true
        else
            push!(ps.cross_thread_tasks, task)
            if !ps.cross_thread_tasks_scheduled
                ps.cross_thread_tasks_scheduled = true
                schedule_now = true
            end
        end
    end

    if schedule_now
        if ps.state == PipelineLifecycle.SHUT_DOWN
            _channel_task_wrapper(task, TaskStatus.CANCELED)
        else
            event_loop_schedule_task_now!(ps.event_loop, ps.cross_thread_task)
        end
    end
    return nothing
end

# --- Shutdown cascade ---

function pipeline_shutdown!(ps::PipelineState, error_code::Int = 0; shutdown_immediately::Bool = false)::Nothing
    schedule_task = false
    lock(ps.shutdown_lock) do
        if ps.state != PipelineLifecycle.ACTIVE || ps.shutdown_pending
            return nothing
        end
        ps.shutdown_error_code = error_code
        ps.shutdown_immediately = shutdown_immediately
        ps.shutdown_pending = true

        channel_task_init!(ps.shutdown_task, EventCallable(s -> _pipeline_shutdown_task(ps, _coerce_task_status(s))), "pipeline_shutdown")
        schedule_task = true
        return nothing
    end

    schedule_task || return nothing
    pipeline_schedule_task_now!(ps, ps.shutdown_task)
    return nothing
end

function _pipeline_shutdown_task(ps::PipelineState, status::TaskStatus.T)
    if ps.state != PipelineLifecycle.ACTIVE
        return nothing
    end

    ps.state = PipelineLifecycle.SHUTTING_DOWN_READ

    if isempty(ps.shutdown_chain.read_shutdown_fns)
        # No read shutdown fns → skip to write shutdown
        ps.state = PipelineLifecycle.SHUTTING_DOWN_WRITE
        if isempty(ps.shutdown_chain.write_shutdown_fns)
            # No write shutdown fns either → done
            ps.state = PipelineLifecycle.SHUT_DOWN
            _pipeline_schedule_shutdown_completion!(ps)
        else
            _shutdown_next_write(ps, ps.shutdown_error_code, ps.shutdown_immediately)
        end
        return nothing
    end

    _shutdown_next_read(ps, ps.shutdown_error_code, ps.shutdown_immediately)
    return nothing
end

function _shutdown_next_read(ps::PipelineState, error_code::Int, free_scarce::Bool)
    chain = ps.shutdown_chain
    idx = chain.current_read_idx
    chain.current_read_idx += 1

    if idx > length(chain.read_shutdown_fns)
        # All read shutdowns complete → transition to write shutdown
        ps.state = PipelineLifecycle.SHUTTING_DOWN_WRITE
        if isempty(chain.write_shutdown_fns)
            ps.state = PipelineLifecycle.SHUT_DOWN
            _pipeline_schedule_shutdown_completion!(ps)
            return nothing
        end
        # Schedule write shutdown on next event loop tick
        task = ScheduledTask(
            TaskFn(function(_s)
                _shutdown_next_write(ps, error_code, free_scarce)
                return nothing
            end);
            type_tag = "pipeline_shutdown_write_start",
        )
        event_loop_schedule_task_now!(ps.event_loop, task)
        return nothing
    end

    on_complete = (err, scarce) -> begin
        if err != 0 && ps.shutdown_error_code == 0
            ps.shutdown_error_code = err
        end
        _shutdown_next_read(ps, err, scarce)
    end

    chain.read_shutdown_fns[idx](error_code, free_scarce, on_complete)
end

function _shutdown_next_write(ps::PipelineState, error_code::Int, free_scarce::Bool)
    chain = ps.shutdown_chain
    idx = chain.current_write_idx
    chain.current_write_idx += 1

    if idx > length(chain.write_shutdown_fns)
        # All write shutdowns complete
        ps.state = PipelineLifecycle.SHUT_DOWN
        _pipeline_schedule_shutdown_completion!(ps)
        return nothing
    end

    on_complete = (err, scarce) -> begin
        if err != 0 && ps.shutdown_error_code == 0
            ps.shutdown_error_code = err
        end
        _shutdown_next_write(ps, err, scarce)
    end

    chain.write_shutdown_fns[idx](error_code, free_scarce, on_complete)
end

# --- Shutdown completion ---

function _pipeline_schedule_shutdown_completion!(ps::PipelineState)
    logf(
        LogLevel.INFO, LS_IO_CHANNEL,
        "Pipeline id=$(ps.channel_id): shutdown complete, error=$(ps.shutdown_error_code)"
    )
    task = ScheduledTask(
        TaskFn(function(status)
            try
                _pipeline_shutdown_completion_task(ps, _coerce_task_status(status))
            catch
                Core.println("pipeline_shutdown_complete task errored")
            end
            return nothing
        end);
        type_tag = "pipeline_shutdown_complete",
    )
    event_loop_schedule_task_now!(ps.event_loop, task)
    return nothing
end

function _pipeline_shutdown_completion_task(ps::PipelineState, status::TaskStatus.T)
    # Cancel all pending tasks
    tasks = ChannelTask[]
    lock(ps.pending_tasks_lock) do
        for (task, _) in ps.pending_tasks
            push!(tasks, task)
        end
    end

    for task in tasks
        event_loop_cancel_task!(ps.event_loop, task.wrapper_task)
    end

    # Notify shutdown callback
    if ps.on_shutdown_completed !== nothing
        ps.on_shutdown_completed(ps.shutdown_error_code)
    end

    return nothing
end

# --- Backpressure ---

function pipeline_increment_read_window!(ps::PipelineState, size::Csize_t)::Nothing
    if !ps.read_back_pressure_enabled || ps.state == PipelineLifecycle.SHUT_DOWN
        return nothing
    end

    ps.window_update_batch = add_size_saturating(ps.window_update_batch, size)

    if !ps.window_update_scheduled && ps.downstream_window <= ps.window_update_batch_emit_threshold
        ps.window_update_scheduled = true
        channel_task_init!(ps.window_update_task, EventCallable(s -> _pipeline_window_update_task(ps, _coerce_task_status(s))), "pipeline_window_update")
        pipeline_schedule_task_now!(ps, ps.window_update_task)
    end

    return nothing
end

function _pipeline_window_update_task(ps::PipelineState, status::TaskStatus.T)
    ps.window_update_scheduled = false
    status == TaskStatus.RUN_READY || return nothing
    ps.state == PipelineLifecycle.SHUT_DOWN && return nothing

    batch = ps.window_update_batch
    ps.window_update_batch = Csize_t(0)
    ps.downstream_window = add_size_saturating(ps.downstream_window, batch)

    if ps.window_update_fn !== nothing
        try
            (ps.window_update_fn::Function)(batch)
        catch e
            e isa ReseauError || rethrow()
            logf(
                LogLevel.ERROR, LS_IO_CHANNEL,
                "Pipeline id=$(ps.channel_id): window update failed with error $(e.code)"
            )
            pipeline_shutdown!(ps, e.code)
        end
    end

    return nothing
end

# --- Message pool ---

function pipeline_acquire_message_from_pool(ps::PipelineState, message_type::IoMessageType.T, size_hint::Integer)::Union{IoMessage, Nothing}
    if ps.message_pool === nothing
        effective_size = size_hint
        if size_hint isa Signed && size_hint < 0
            effective_size = 0
        end
        max_size = Csize_t(g_aws_channel_max_fragment_size[])
        effective_csize = Csize_t(effective_size)
        if effective_csize > max_size
            effective_csize = max_size
        end
        message = IoMessage(Int(effective_csize))
        message.owning_channel = ps
        return message
    end

    msg = message_pool_acquire(ps.message_pool, message_type, size_hint)
    if msg !== nothing
        msg.owning_channel = ps
    end
    return msg
end

function pipeline_release_message_to_pool!(ps::PipelineState, message::IoMessage)
    if ps.message_pool === nothing
        return nothing
    end
    return message_pool_release!(ps.message_pool, message)
end

# --- Pipeline destroy ---

function _pipeline_destroy_impl!(ps::PipelineState)
    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL,
        "Pipeline id=$(ps.channel_id): destroying pipeline"
    )

    if ps.state != PipelineLifecycle.SHUT_DOWN
        ps.state = PipelineLifecycle.SHUT_DOWN
    end

    event_loop_group_close_lease!(ps.event_loop_group_lease)
    ps.event_loop_group_lease = nothing
    return nothing
end

function pipeline_destroy!(ps::PipelineState)
    if ps.setup_pending
        ps.destroy_pending = true
        return nothing
    end

    if pipeline_thread_is_callers_thread(ps)
        return _pipeline_destroy_impl!(ps)
    end

    task = ScheduledTask(
        TaskFn(function(status)
            try
                _pipeline_destroy_impl!(ps)
            catch e
                Core.println("pipeline_destroy task errored")
            end
            return nothing
        end);
        type_tag = "pipeline_destroy",
    )
    event_loop_schedule_task_now!(ps.event_loop, task)
    return nothing
end

# --- Socket dispatch (function barriers) ---
# These reference Socket (defined in socket.jl, included before this file)

@inline function _socket_dispatch_read(socket::Socket, msg::IoMessage)
    (socket.read_fn::Function)(msg)
    return nothing
end

@inline function _socket_dispatch_write(socket::Socket, msg::IoMessage)
    (socket.write_fn::Function)(msg)
    return nothing
end

function pipeline_write!(socket::Socket, msg::IoMessage)
    ps = socket.pipeline::PipelineState
    if pipeline_thread_is_callers_thread(ps)
        _socket_dispatch_write(socket, msg)
    else
        task = ChannelTask(EventCallable(_ -> begin
            _socket_dispatch_write(socket, msg)
            return nothing
        end), "pipeline_write_cross_thread")
        pipeline_schedule_task_now!(ps, task)
    end
    return nothing
end

# --- Trigger read on socket ---

function pipeline_trigger_read(socket::Socket)::Nothing
    ps = socket.pipeline
    if !(ps isa PipelineState)
        throw_error(ERROR_INVALID_STATE)
    end
    if !pipeline_thread_is_callers_thread(ps)
        throw_error(ERROR_INVALID_STATE)
    end
    _socket_trigger_read(socket)
    return nothing
end

function _socket_trigger_read(socket::Socket)
    if socket.shutdown_in_progress
        return nothing
    end
    if socket.pending_read
        socket.pending_read = false
    end
    _socket_handler_trigger_read(socket)
    return nothing
end
