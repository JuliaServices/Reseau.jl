# AWS IO Library - Channel Pipeline
# Port of aws-c-io/source/channel.c and include/aws/io/channel.h

# Channel read/write directions are defined in socket.jl as ChannelDirection

const DEFAULT_CHANNEL_MAX_FRAGMENT_SIZE = 16 * 1024
const g_aws_channel_max_fragment_size = Ref{Csize_t}(Csize_t(DEFAULT_CHANNEL_MAX_FRAGMENT_SIZE))

struct ChannelOptions
    event_loop::EventLoop
    event_loop_group::Union{EventLoopGroup, Nothing}
    on_setup_completed::Union{EventCallable, Nothing}
    on_shutdown_completed::Union{EventCallable, Nothing}
    enable_read_back_pressure::Bool
end

function ChannelOptions(;
        event_loop,
        event_loop_group = nothing,
        on_setup_completed = nothing,
        on_shutdown_completed = nothing,
        enable_read_back_pressure::Bool = false,
    )
    return ChannelOptions(
        event_loop,
        event_loop_group,
        on_setup_completed,
        on_shutdown_completed,
        enable_read_back_pressure,
    )
end

# Channel task wrapper (aws_channel_task)
mutable struct ChannelTaskContext{CH, TSK}
    channel::CH
    task::TSK
end

mutable struct ChannelTask
    wrapper_task::ScheduledTask
    task_fn::EventCallable
    type_tag::String
    ctx::ChannelTaskContext
end

const _noop_event_callable = EventCallable((_::Int) -> nothing)

function ChannelTask(task_fn::EventCallable, type_tag::AbstractString)
    ctx = ChannelTaskContext{Any, Union{ChannelTask, Nothing}}(nothing, nothing)
    wrapper_task = ScheduledTask(
        TaskFn(function(status)
            try
                _channel_task_wrapper(ctx, _coerce_task_status(status))
            catch
            end
            return nothing
        end);
        type_tag = type_tag,
    )
    task = ChannelTask(wrapper_task, task_fn, String(type_tag), ctx)
    setfield!(ctx, :task, task)
    return task
end

function ChannelTask()
    return ChannelTask(_noop_event_callable, "channel_task")
end

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

# Trim-safe callable wrappers used by slot-dispatch paths.
struct _ChannelSlotReadCallWrapper <: Function end
@inline function (::_ChannelSlotReadCallWrapper)(
        f::F,
        slot_ptr::Ptr{Cvoid},
        message_ptr::Ptr{Cvoid},
    ) where {F <: Function}
    slot = _callback_ptr_to_obj(slot_ptr)::ChannelSlot
    message = _callback_ptr_to_obj(message_ptr)::IoMessage
    f(slot, message)
    return nothing
end

@generated function _channel_slot_read_gen_fptr(::Type{F}) where {F <: Function}
    quote
        @cfunction($(_ChannelSlotReadCallWrapper()), Cvoid, (Ref{$F}, Ptr{Cvoid}, Ptr{Cvoid}))
    end
end

struct _ChannelSlotWriteCallWrapper <: Function end
@inline function (::_ChannelSlotWriteCallWrapper)(
        f::F,
        slot_ptr::Ptr{Cvoid},
        message_ptr::Ptr{Cvoid},
    ) where {F <: Function}
    slot = _callback_ptr_to_obj(slot_ptr)::ChannelSlot
    message = _callback_ptr_to_obj(message_ptr)::IoMessage
    f(slot, message)
    return nothing
end

@generated function _channel_slot_write_gen_fptr(::Type{F}) where {F <: Function}
    quote
        @cfunction($(_ChannelSlotWriteCallWrapper()), Cvoid, (Ref{$F}, Ptr{Cvoid}, Ptr{Cvoid}))
    end
end

struct ChannelHandlerReadCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelHandlerReadCallable(callable::F) where {F <: Function}
    ptr = _channel_slot_read_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelHandlerReadCallable(ptr, objptr, objref)
end

@inline function (f::ChannelHandlerReadCallable)(slot, message)::Nothing
    slot_ptr, slot_root = _callback_obj_to_ptr_and_root(slot)
    message_ptr, message_root = _callback_obj_to_ptr_and_root(message)
    GC.@preserve slot_root message_root begin
        ccall(f.ptr, Cvoid, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), f.objptr, slot_ptr, message_ptr)
    end
    return nothing
end

struct ChannelHandlerWriteCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelHandlerWriteCallable(callable::F) where {F <: Function}
    ptr = _channel_slot_write_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelHandlerWriteCallable(ptr, objptr, objref)
end

@inline function (f::ChannelHandlerWriteCallable)(slot, message)::Nothing
    slot_ptr, slot_root = _callback_obj_to_ptr_and_root(slot)
    message_ptr, message_root = _callback_obj_to_ptr_and_root(message)
    GC.@preserve slot_root message_root begin
        ccall(f.ptr, Cvoid, (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}), f.objptr, slot_ptr, message_ptr)
    end
    return nothing
end

struct _ChannelSlotIncrementWindowCallWrapper <: Function end
@inline function (::_ChannelSlotIncrementWindowCallWrapper)(
        f::F,
        slot_ptr::Ptr{Cvoid},
        size::Csize_t,
    ) where {F <: Function}
    slot = _callback_ptr_to_obj(slot_ptr)::ChannelSlot
    f(slot, size)
    return nothing
end

@generated function _channel_slot_increment_window_gen_fptr(::Type{F}) where {F <: Function}
    quote
        @cfunction($(_ChannelSlotIncrementWindowCallWrapper()), Cvoid, (Ref{$F}, Ptr{Cvoid}, Csize_t))
    end
end

struct ChannelHandlerIncrementWindowCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelHandlerIncrementWindowCallable(callable::F) where {F <: Function}
    ptr = _channel_slot_increment_window_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelHandlerIncrementWindowCallable(ptr, objptr, objref)
end

@inline function (f::ChannelHandlerIncrementWindowCallable)(slot, size::Csize_t)::Nothing
    slot_ptr, slot_root = _callback_obj_to_ptr_and_root(slot)
    GC.@preserve slot_root begin
        ccall(f.ptr, Cvoid, (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t), f.objptr, slot_ptr, size)
    end
    return nothing
end

struct _ChannelSlotShutdownCallWrapper <: Function end
@inline function (::_ChannelSlotShutdownCallWrapper)(
        f::F,
        slot_ptr::Ptr{Cvoid},
        direction::UInt8,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    ) where {F <: Function}
    slot = _callback_ptr_to_obj(slot_ptr)::ChannelSlot
    f(
        slot,
        ChannelDirection.T(direction),
        error_code,
        free_scarce_resources_immediately,
    )
    return nothing
end

@generated function _channel_slot_shutdown_gen_fptr(::Type{F}) where {F <: Function}
    quote
        @cfunction($(_ChannelSlotShutdownCallWrapper()), Cvoid, (Ref{$F}, Ptr{Cvoid}, UInt8, Int, Bool))
    end
end

struct ChannelHandlerShutdownCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelHandlerShutdownCallable(callable::F) where {F <: Function}
    ptr = _channel_slot_shutdown_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelHandlerShutdownCallable(ptr, objptr, objref)
end

@inline function (f::ChannelHandlerShutdownCallable)(
        slot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Nothing
    slot_ptr, slot_root = _callback_obj_to_ptr_and_root(slot)
    GC.@preserve slot_root begin
        ccall(
            f.ptr,
            Cvoid,
            (Ptr{Cvoid}, Ptr{Cvoid}, UInt8, Int, Bool),
            f.objptr,
            slot_ptr,
            UInt8(direction),
            error_code,
            free_scarce_resources_immediately,
        )
    end
    return nothing
end

struct _ChannelSlotMessageOverheadCallWrapper <: Function end
@inline function (::_ChannelSlotMessageOverheadCallWrapper)(f::F)::Csize_t where {F <: Function}
    return f()
end

@generated function _channel_slot_message_overhead_gen_fptr(::Type{F}) where {F <: Function}
    quote
        @cfunction($(_ChannelSlotMessageOverheadCallWrapper()), Csize_t, (Ref{$F},))
    end
end

struct ChannelHandlerMessageOverheadCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelHandlerMessageOverheadCallable(callable::F) where {F <: Function}
    ptr = _channel_slot_message_overhead_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelHandlerMessageOverheadCallable(ptr, objptr, objref)
end

@inline function (f::ChannelHandlerMessageOverheadCallable)()::Csize_t
    return ccall(f.ptr, Csize_t, (Ptr{Cvoid},), f.objptr)
end

struct _ChannelSlotDestroyCallWrapper <: Function end
@inline function (::_ChannelSlotDestroyCallWrapper)(f::F)::Nothing where {F <: Function}
    f()
    return nothing
end

@generated function _channel_slot_destroy_gen_fptr(::Type{F}) where {F <: Function}
    quote
        @cfunction($(_ChannelSlotDestroyCallWrapper()), Cvoid, (Ref{$F},))
    end
end

struct ChannelHandlerDestroyCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelHandlerDestroyCallable(callable::F) where {F <: Function}
    ptr = _channel_slot_destroy_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelHandlerDestroyCallable(ptr, objptr, objref)
end

@inline function (f::ChannelHandlerDestroyCallable)()::Nothing
    ccall(f.ptr, Cvoid, (Ptr{Cvoid},), f.objptr)
    return nothing
end

struct _ChannelSlotTriggerReadCallWrapper <: Function end
@inline function (::_ChannelSlotTriggerReadCallWrapper)(f::F)::Nothing where {F <: Function}
    f()
    return nothing
end

@generated function _channel_slot_trigger_read_gen_fptr(::Type{F}) where {F <: Function}
    quote
        @cfunction($(_ChannelSlotTriggerReadCallWrapper()), Cvoid, (Ref{$F},))
    end
end

struct ChannelHandlerTriggerReadCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelHandlerTriggerReadCallable(callable::F) where {F <: Function}
    ptr = _channel_slot_trigger_read_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelHandlerTriggerReadCallable(ptr, objptr, objref)
end

@inline function (f::ChannelHandlerTriggerReadCallable)()::Nothing
    ccall(f.ptr, Cvoid, (Ptr{Cvoid},), f.objptr)
    return nothing
end

struct _ChannelSlotResetStatisticsCallWrapper <: Function end
@inline function (::_ChannelSlotResetStatisticsCallWrapper)(f::F)::Nothing where {F <: Function}
    f()
    return nothing
end

@generated function _channel_slot_reset_statistics_gen_fptr(::Type{F}) where {F <: Function}
    quote
        @cfunction($(_ChannelSlotResetStatisticsCallWrapper()), Cvoid, (Ref{$F},))
    end
end

struct ChannelHandlerResetStatisticsCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelHandlerResetStatisticsCallable(callable::F) where {F <: Function}
    ptr = _channel_slot_reset_statistics_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelHandlerResetStatisticsCallable(ptr, objptr, objref)
end

@inline function (f::ChannelHandlerResetStatisticsCallable)()::Nothing
    ccall(f.ptr, Cvoid, (Ptr{Cvoid},), f.objptr)
    return nothing
end

struct _ChannelSlotGatherStatisticsCallWrapper <: Function end
@inline function (::_ChannelSlotGatherStatisticsCallWrapper)(f::F)::Any where {F <: Function}
    return f()
end

@generated function _channel_slot_gather_statistics_gen_fptr(::Type{F}) where {F <: Function}
    quote
        @cfunction($(_ChannelSlotGatherStatisticsCallWrapper()), Any, (Ref{$F},))
    end
end

struct ChannelHandlerGatherStatisticsCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelHandlerGatherStatisticsCallable(callable::F) where {F <: Function}
    ptr = _channel_slot_gather_statistics_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelHandlerGatherStatisticsCallable(ptr, objptr, objref)
end

@inline function (f::ChannelHandlerGatherStatisticsCallable)()::Any
    return ccall(f.ptr, Any, (Ptr{Cvoid},), f.objptr)
end

# Channel lifecycle state tracking
@enumx ChannelLifecycleState::UInt8 begin
    NOT_INITIALIZED = 0
    SETTING_UP = 1
    ACTIVE = 2
    SHUTTING_DOWN_READ = 3
    SHUTTING_DOWN_WRITE = 4
    SHUT_DOWN = 5
end

mutable struct ShutdownChain
    read_shutdown_fns::Vector{Any}
    write_shutdown_fns::Vector{Any}
end

ShutdownChain() = ShutdownChain(Any[], Any[])

# Shared channel runtime state that is threaded through slots and handlers.
mutable struct ChannelState
    event_loop::EventLoop
    event_loop_group_lease::Union{EventLoopGroupLease, Nothing}
    channel_state::ChannelLifecycleState.T
    read_back_pressure_enabled::Bool
    channel_id::UInt64
    setup_pending::Bool
    destroy_pending::Bool
    message_pool::Union{MessagePool, Nothing}
    socket::Union{Socket, Nothing}
    shutdown_chain::ShutdownChain
    on_setup_completed::Union{EventCallable, Nothing}
    on_shutdown_completed::Union{EventCallable, Nothing}
    shutdown_error_code::Int
    # Statistics tracking
    read_message_count::Csize_t
    write_message_count::Csize_t
    statistics_handler::Union{StatisticsHandler, Nothing}
    statistics_task::Union{ScheduledTask, Nothing}
    statistics_interval_start_time_ms::UInt64
    statistics_list::Vector{Any}
    # Window/backpressure tracking
    window_update_batch_emit_threshold::Csize_t
    window_update_scheduled::Bool
    window_update_task::ChannelTask
    # Channel task tracking
    pending_tasks::IdDict{ChannelTask, Bool}
    pending_tasks_lock::ReentrantLock
    cross_thread_tasks::Vector{ChannelTask}
    cross_thread_tasks_lock::ReentrantLock
    cross_thread_tasks_scheduled::Bool
    cross_thread_task::ScheduledTask
    # Shutdown tracking
    shutdown_pending::Bool
    shutdown_immediately::Bool
    shutdown_task::ChannelTask
    shutdown_lock::ReentrantLock
end

# Channel slot - links handlers in the pipeline.
# Read direction flows left -> right (toward application).
# Write direction flows right -> left (toward socket).
mutable struct ChannelSlot
    adj_left::Union{ChannelSlot, Nothing}
    adj_right::Union{ChannelSlot, Nothing}
    handler_read::Union{ChannelHandlerReadCallable, Nothing}
    handler_write::Union{ChannelHandlerWriteCallable, Nothing}
    handler_increment_window::Union{ChannelHandlerIncrementWindowCallable, Nothing}
    handler_shutdown_fn::Union{ChannelHandlerShutdownCallable, Nothing}
    handler_message_overhead_fn::Union{ChannelHandlerMessageOverheadCallable, Nothing}
    handler_destroy_fn::Union{ChannelHandlerDestroyCallable, Nothing}
    handler_trigger_read_fn::Union{ChannelHandlerTriggerReadCallable, Nothing}
    handler_reset_statistics_fn::Union{ChannelHandlerResetStatisticsCallable, Nothing}
    handler_gather_statistics_fn::Union{ChannelHandlerGatherStatisticsCallable, Nothing}
    state::Union{ChannelState, Nothing}
    window_size::Csize_t
    current_window_update_batch_size::Csize_t
    upstream_message_overhead::Csize_t
end

function ChannelSlot()
    return ChannelSlot(
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
        nothing,
        Csize_t(0),
        Csize_t(0),
        Csize_t(0),
    )
end

# Get the slot immediately to the left (socket side)
slot_left(slot::ChannelSlot) = slot.adj_left
# Get the slot immediately to the right (application side)
slot_right(slot::ChannelSlot) = slot.adj_right

# Channel handler interface methods.

function handler_process_read_message(handler, slot::ChannelSlot, message::IoMessage)::Nothing
    error("handler_process_read_message must be implemented for $(typeof(handler))")
end

function handler_process_write_message(handler, slot::ChannelSlot, message::IoMessage)::Nothing
    error("handler_process_write_message must be implemented for $(typeof(handler))")
end

function handler_increment_read_window(handler, slot::ChannelSlot, size::Csize_t)::Nothing
    error("handler_increment_read_window must be implemented for $(typeof(handler))")
end

function handler_shutdown(
        handler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Nothing
    error("handler_shutdown must be implemented for $(typeof(handler))")
end

function handler_initial_window_size(handler)::Csize_t
    error("handler_initial_window_size must be implemented for $(typeof(handler))")
end

function handler_message_overhead(handler)::Csize_t
    error("handler_message_overhead must be implemented for $(typeof(handler))")
end

function handler_destroy(handler)::Nothing
    return nothing
end

function handler_reset_statistics(handler)::Nothing
    return nothing
end

function handler_gather_statistics(handler)::Any
    return nothing
end

function handler_trigger_write(handler)::Nothing
    return nothing
end

function handler_trigger_read(handler)::Nothing
    return nothing
end

function setchannelslot!(handler, slot::ChannelSlot)::Nothing
    _ = handler
    _ = slot
    return nothing
end

mutable struct _PipelineDownstreamReadHandler
    read_fn::Any
    shutdown_chain::ShutdownChain
end

handler_initial_window_size(::_PipelineDownstreamReadHandler)::Csize_t = SIZE_MAX
handler_message_overhead(::_PipelineDownstreamReadHandler)::Csize_t = Csize_t(0)
_pipeline_downstream_increment_read_window(::_PipelineDownstreamReadHandler, _slot, _size)::Nothing = nothing

function _pipeline_downstream_process_write_message(::_PipelineDownstreamReadHandler, _slot, _message)::Nothing
    throw_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
end

function _pipeline_downstream_process_read_message(handler::_PipelineDownstreamReadHandler, slot, message::IoMessage)::Nothing
    read_fn = handler.read_fn
    if read_fn === nothing
        channel = slot_channel_or_nothing(slot)
        channel !== nothing && channel_release_message_to_pool!(channel, message)
        return nothing
    end
    read_fn(message)
    return nothing
end

function handler_destroy(handler::_PipelineDownstreamReadHandler)::Nothing
    handler.read_fn = nothing
    return nothing
end

function _channel_run_shutdown_chain!(
        shutdown_fns::Vector{Any},
        error_code::Int,
        free_scarce_resources_immediately::Bool,
        on_complete::Function,
    )::Nothing
    idx_ref = Ref(1)

    function _step(err::Int, scarce::Bool)::Nothing
        idx = idx_ref[]
        if idx > length(shutdown_fns)
            on_complete(err, scarce)
            return nothing
        end

        idx_ref[] = idx + 1
        shutdown_fn = shutdown_fns[idx]
        try
            shutdown_fn(err, scarce, (next_err, next_scarce) -> _step(next_err, next_scarce))
        catch e
            if e isa ReseauError
                _step(e.code != 0 ? e.code : err, scarce)
                return nothing
            end
            rethrow()
        end
        return nothing
    end

    _step(error_code, free_scarce_resources_immediately)
    return nothing
end

function _pipeline_downstream_handler_shutdown(
        handler::_PipelineDownstreamReadHandler,
        slot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Nothing
    shutdown_fns = direction == ChannelDirection.READ ?
        handler.shutdown_chain.read_shutdown_fns :
        handler.shutdown_chain.write_shutdown_fns

    on_complete = (err, scarce) -> begin
        channel_slot_on_handler_shutdown_complete!(slot, direction, err, scarce)
        return nothing
    end
    _channel_run_shutdown_chain!(
        shutdown_fns,
        error_code,
        free_scarce_resources_immediately,
        on_complete,
    )
    return nothing
end

function handler_process_read_message(
        handler::_PipelineDownstreamReadHandler,
        slot::ChannelSlot,
        message::IoMessage,
    )::Nothing
    _pipeline_downstream_process_read_message(handler, slot, message)
    return nothing
end

function handler_process_write_message(
        handler::_PipelineDownstreamReadHandler,
        slot::ChannelSlot,
        message::IoMessage,
    )::Nothing
    _pipeline_downstream_process_write_message(handler, slot, message)
    return nothing
end

function handler_increment_read_window(
        handler::_PipelineDownstreamReadHandler,
        slot::ChannelSlot,
        size::Csize_t,
    )::Nothing
    _pipeline_downstream_increment_read_window(handler, slot, size)
    return nothing
end

function handler_shutdown(
        handler::_PipelineDownstreamReadHandler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Nothing
    _pipeline_downstream_handler_shutdown(
        handler,
        slot,
        direction,
        error_code,
        free_scarce_resources_immediately,
    )
    return nothing
end

function _channel_ensure_pipeline_downstream_slot!(channel)::_PipelineDownstreamReadHandler
    downstream = channel.downstream
    if downstream isa _PipelineDownstreamState
        return downstream.handler
    end

    slot = channel_slot_new!(channel)
    if channel.last !== slot
        channel_slot_insert_end!(channel, slot)
    end

    handler = _PipelineDownstreamReadHandler(nothing, channel.shutdown_chain)
    channel_slot_set_handler!(slot, handler)
    channel.downstream = _PipelineDownstreamState(slot, handler)
    return handler
end

function _channel_set_pipeline_downstream_read!(channel, read_fn)::Nothing
    handler = _channel_ensure_pipeline_downstream_slot!(channel)
    handler.read_fn = read_fn
    if channel.socket !== nothing
        channel.socket.read_fn = read_fn
    end
    return nothing
end

mutable struct _PipelineDownstreamState
    slot::ChannelSlot
    handler::_PipelineDownstreamReadHandler
end

# Channel - a bidirectional pipeline of slots/handlers.
mutable struct Channel
    first::Union{ChannelSlot, Nothing}
    last::Union{ChannelSlot, Nothing}
    downstream::Union{_PipelineDownstreamState, Nothing}
    tls_handler_ref::Union{WeakRef, Nothing}
    state::ChannelState
end

const _channel_state_registry = IdDict{ChannelState, Channel}()

@inline function Base.getproperty(channel::Channel, name::Symbol)
    if name === :first || name === :last || name === :downstream || name === :tls_handler_ref || name === :state
        return getfield(channel, name)
    end
    if name === :tls_handler
        ref = getfield(channel, :tls_handler_ref)
        return ref === nothing ? nothing : ref.value
    end
    return getproperty(getfield(channel, :state), name)
end

@inline function Base.setproperty!(channel::Channel, name::Symbol, value)
    if name === :first || name === :last || name === :downstream || name === :tls_handler_ref || name === :state
        return setfield!(channel, name, value)
    end
    if name === :tls_handler
        return setfield!(channel, :tls_handler_ref, value === nothing ? nothing : WeakRef(value))
    end
    return setproperty!(getfield(channel, :state), name, value)
end

@inline function slot_state(slot::ChannelSlot)::ChannelState
    st = slot.state
    st isa ChannelState || error("ChannelSlot has no owning ChannelState")
    return st
end

@inline function slot_channel(slot::ChannelSlot)::Channel
    st = slot_state(slot)
    ch = get(_channel_state_registry, st, nothing)
    ch isa Channel || error("ChannelSlot has no owning Channel")
    return ch::Channel
end

@inline function slot_channel_or_nothing(slot::ChannelSlot)::Union{Channel, Nothing}
    st = slot.state
    st isa ChannelState || return nothing
    ch = get(_channel_state_registry, st, nothing)
    ch isa Channel || return nothing
    return ch
end

# Global channel counter for unique IDs
mutable struct _ChannelIdCounter
    @atomic value::UInt64
end
const _channel_id_counter = _ChannelIdCounter(UInt64(0))

function _next_channel_id()::UInt64
    return @atomic _channel_id_counter.value += 1
end

function Channel(
        event_loop::EventLoop,
        message_pool::Union{MessagePool, Nothing} = nothing;
        enable_read_back_pressure::Bool = false,
        event_loop_group_lease::Union{EventLoopGroupLease, Nothing} = nothing,
    )
    channel_id = _next_channel_id()
    window_threshold = enable_read_back_pressure ? Csize_t(g_aws_channel_max_fragment_size[] * 2) : Csize_t(0)

    state = ChannelState(
        event_loop,
        event_loop_group_lease,
        ChannelLifecycleState.NOT_INITIALIZED,
        enable_read_back_pressure,
        channel_id,
        false,  # setup_pending
        false,  # destroy_pending
        message_pool,
        nothing,  # socket
        ShutdownChain(),
        nothing,  # on_setup_completed
        nothing,  # on_shutdown_completed
        0,        # shutdown_error_code
        Csize_t(0),  # read_message_count
        Csize_t(0),  # write_message_count
        nothing,  # statistics_handler
        nothing,  # statistics_task
        UInt64(0),  # statistics_interval_start_time_ms
        Any[],
        window_threshold,
        false,       # window_update_scheduled
        ChannelTask(),
        IdDict{ChannelTask, Bool}(),
        ReentrantLock(),
        ChannelTask[],
        ReentrantLock(),
        false,
        ScheduledTask(
            TaskFn(function(_status); return nothing; end);
            type_tag = "channel_cross_thread_placeholder",
        ),
        false,    # shutdown_pending
        false,    # shutdown_immediately
        ChannelTask(),
        ReentrantLock(),
    )
    channel = Channel(nothing, nothing, nothing, nothing, state)
    _channel_state_registry[state] = channel
    state.cross_thread_task = ScheduledTask(
        TaskFn(function(status)
            try
                _channel_schedule_cross_thread_tasks(channel, _coerce_task_status(status))
            catch e
                Core.println("channel_cross_thread_tasks errored")
            end
            return nothing
        end);
        type_tag = "channel_cross_thread_tasks",
    )
    return channel
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
        final_status = (status == TaskStatus.CANCELED || channel.channel_state == ChannelLifecycleState.SHUT_DOWN) ?
            TaskStatus.CANCELED : status
        task.task_fn(Int(final_status))
        return nothing
    end
    task.task_fn(Int(status))
    return nothing
end

function _channel_schedule_cross_thread_tasks(channel::Channel, status::TaskStatus.T)
    tasks = ChannelTask[]
    lock(channel.cross_thread_tasks_lock) do
        while !isempty(channel.cross_thread_tasks)
            task = popfirst!(channel.cross_thread_tasks)
            task === nothing && break
            push!(tasks, task)
        end
        channel.cross_thread_tasks_scheduled = false
    end

    final_status = (status == TaskStatus.CANCELED || channel.channel_state == ChannelLifecycleState.SHUT_DOWN) ?
        TaskStatus.CANCELED : TaskStatus.RUN_READY

    for task in tasks
        if task.wrapper_task.timestamp == 0 || final_status == TaskStatus.CANCELED
            _channel_task_wrapper(task.ctx, final_status)
        else
            event_loop_schedule_task_future!(channel.event_loop, task.wrapper_task, task.wrapper_task.timestamp)
        end
    end
    return nothing
end

function _channel_register_task_cross_thread!(channel::Channel, task::ChannelTask)
    schedule_now = false
    lock(channel.cross_thread_tasks_lock) do
        if channel.channel_state == ChannelLifecycleState.SHUT_DOWN
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
        if channel.channel_state == ChannelLifecycleState.SHUT_DOWN
            _channel_task_wrapper(task.ctx, TaskStatus.CANCELED)
        else
            event_loop_schedule_task_now!(channel.event_loop, channel.cross_thread_task)
        end
    end
    return nothing
end

# Get the event loop associated with a channel
channel_event_loop(channel::Channel) = channel.event_loop

# Check if caller is on channel's event loop thread
channel_thread_is_callers_thread(channel::Channel) = event_loop_thread_is_callers_thread(channel.event_loop)

# Get current clock time from event loop
channel_current_clock_time(channel::Channel) = event_loop_current_clock_time(channel.event_loop)

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

pipeline_thread_is_callers_thread(channel::Channel) = channel_thread_is_callers_thread(channel)

function pipeline_schedule_task_now!(channel::Channel, task::ChannelTask)::Nothing
    channel_schedule_task_now!(channel, task)
    return nothing
end

function pipeline_shutdown!(channel::Channel, error_code::Int = 0; shutdown_immediately::Bool = false)::Nothing
    channel_shutdown!(channel, error_code; shutdown_immediately = shutdown_immediately)
    return nothing
end

function pipeline_acquire_message_from_pool(
        channel::Channel,
        message_type::IoMessageType.T,
        size_hint::Integer,
    )::Union{IoMessage, Nothing}
    return channel_acquire_message_from_pool(channel, message_type, size_hint)
end

function pipeline_release_message_to_pool!(channel::Channel, message::IoMessage)::Nothing
    channel_release_message_to_pool!(channel, message)
    return nothing
end

function pipeline_increment_read_window!(channel::Channel, size::Integer)::Nothing
    slot = channel.last
    slot === nothing && return nothing
    add = size < 0 ? Csize_t(0) : Csize_t(size)
    channel_slot_increment_read_window!(slot, add)
    return nothing
end

@inline function _pipeline_channel_for_socket(socket::Socket)::Union{Channel, Nothing}
    handler = socket.handler
    if handler !== nothing && hasproperty(handler, :slot)
        slot = getproperty(handler, :slot)
        if slot isa ChannelSlot
            return slot_channel_or_nothing(slot)
        end
    end
    return nothing
end

function pipeline_write!(socket::Socket, msg::IoMessage)::Nothing
    channel = _pipeline_channel_for_socket(socket)
    channel === nothing && throw_error(ERROR_INVALID_STATE)

    if pipeline_thread_is_callers_thread(channel)
        start_slot = channel.last
        start_slot === nothing && throw_error(ERROR_INVALID_STATE)
        channel_slot_send_message(start_slot, msg, ChannelDirection.WRITE)
        return nothing
    end

    task = ChannelTask(
        EventCallable(_ -> begin
            start_slot = channel.last
            start_slot === nothing && throw_error(ERROR_INVALID_STATE)
            channel_slot_send_message(start_slot, msg, ChannelDirection.WRITE)
            return nothing
        end),
        "pipeline_write_cross_thread",
    )
    channel_schedule_task_now!(channel, task)
    return nothing
end

function pipeline_trigger_read(socket::Socket)::Nothing
    channel = _pipeline_channel_for_socket(socket)
    channel === nothing && throw_error(ERROR_INVALID_STATE)
    if !pipeline_thread_is_callers_thread(channel)
        throw_error(ERROR_INVALID_STATE)
    end
    channel_trigger_read(channel)
    return nothing
end

function pipeline_set_downstream_read!(channel::Channel, read_fn)::Nothing
    _channel_set_pipeline_downstream_read!(channel, read_fn)
    return nothing
end

function pipeline_add_read_shutdown_fn!(channel::Channel, shutdown_fn::Function)::Nothing
    push!(channel.shutdown_chain.read_shutdown_fns, shutdown_fn)
    return nothing
end

function pipeline_prepend_write_shutdown_fn!(channel::Channel, shutdown_fn::Function)::Nothing
    pushfirst!(channel.shutdown_chain.write_shutdown_fns, shutdown_fn)
    return nothing
end

function pipeline_tls_handler(channel::Channel)
    return channel.tls_handler
end

# Channel creation API matching aws_channel_new
mutable struct ChannelSetupArgs
    channel::Channel
end

function _channel_get_or_create_message_pool(channel::Channel)::MessagePool
    pool = channel.event_loop.message_pool
    if pool isa MessagePool
        return pool
    end
    if pool !== nothing
        channel.event_loop.message_pool = nothing
    end

    creation_args = MessagePoolCreationArgs(;
        application_data_msg_data_size = Int(g_aws_channel_max_fragment_size[]),
        application_data_msg_count = 4,
        small_block_msg_data_size = 128,
        small_block_msg_count = 4,
    )

    pool = MessagePool(creation_args)
    channel.event_loop.message_pool = pool
    return pool
end

function _channel_setup_task(args::ChannelSetupArgs, status::TaskStatus.T)
    channel = args.channel
    channel.setup_pending = false
    if status != TaskStatus.RUN_READY
        if channel.on_setup_completed !== nothing
            channel.on_setup_completed(ERROR_SYS_CALL_FAILURE)
        end
        if channel.destroy_pending
            channel.destroy_pending = false
            channel_destroy!(channel)
        end
        return nothing
    end

    pool = _channel_get_or_create_message_pool(channel)
    channel.message_pool = pool
    channel.channel_state = ChannelLifecycleState.ACTIVE

    if channel.on_setup_completed !== nothing
        channel.on_setup_completed(AWS_OP_SUCCESS)
    end
    if channel.destroy_pending
        channel.destroy_pending = false
        channel_destroy!(channel)
    end
    return nothing
end

function channel_new(options::ChannelOptions)::Channel
    if options.event_loop === nothing
        throw_error(ERROR_INVALID_ARGUMENT)
    end

    lease = options.event_loop_group === nothing ? nothing : event_loop_group_open_lease!(options.event_loop_group)
    if options.event_loop_group !== nothing && lease === nothing
        throw_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end

    channel = Channel(
        options.event_loop,
        nothing;
        enable_read_back_pressure = options.enable_read_back_pressure,
        event_loop_group_lease = lease,
    )
    channel.on_setup_completed = options.on_setup_completed
    channel.on_shutdown_completed = options.on_shutdown_completed
    channel.channel_state = ChannelLifecycleState.SETTING_UP
    channel.setup_pending = true
    channel.destroy_pending = false

    setup_args = ChannelSetupArgs(channel)
    task = ScheduledTask(
        TaskFn(function(status)
            try
                _channel_setup_task(setup_args, _coerce_task_status(status))
            catch
            end
            return nothing
        end);
        type_tag = "channel_setup",
    )
    event_loop_schedule_task_now!(options.event_loop, task)
    return channel
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
        task::ChannelTask,
        run_at_nanos::UInt64;
        serialized::Bool = false,
    )
    if channel.channel_state == ChannelLifecycleState.SHUT_DOWN
        task.task_fn(Int(TaskStatus.CANCELED))
        return nothing
    end

    setfield!(task.ctx, :channel, channel)
    task.wrapper_task.timestamp = run_at_nanos
    task.wrapper_task.scheduled = false
    _channel_add_pending_task!(channel, task)

    if serialized
        _channel_register_task_cross_thread!(channel, task)
        return nothing
    end

    if channel_thread_is_callers_thread(channel)
        if run_at_nanos == 0
            event_loop_schedule_task_now!(channel.event_loop, task.wrapper_task)
        else
            event_loop_schedule_task_future!(channel.event_loop, task.wrapper_task, run_at_nanos)
        end
    else
        _channel_register_task_cross_thread!(channel, task)
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
channel_is_active(channel::Channel) = channel.channel_state == ChannelLifecycleState.ACTIVE

# Set the channel setup callback
function channel_set_setup_callback!(channel::Channel, callback::EventCallable)
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

    if channel.channel_state == ChannelLifecycleState.SHUTTING_DOWN_READ ||
            channel.channel_state == ChannelLifecycleState.SHUTTING_DOWN_WRITE ||
            channel.channel_state == ChannelLifecycleState.SHUT_DOWN
        return nothing
    end

    now_ns = event_loop_current_clock_time(channel.event_loop)
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
        task = ScheduledTask(
            TaskFn(function(status)
                try
                    _channel_gather_statistics_task(channel, _coerce_task_status(status))
                catch e
                    Core.println("gather_statistics task errored")
                end
                return nothing
            end);
            type_tag = "gather_statistics",
        )
        now_ns = event_loop_current_clock_time(channel.event_loop)
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
    slot.state = channel.state
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
    channel = slot_channel(slot)

    to_add.adj_right = slot.adj_right
    if slot.adj_right !== nothing
        slot.adj_right.adj_left = to_add
    end
    slot.adj_right = to_add
    to_add.adj_left = slot
    to_add.state = channel.state

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
    to_add.state = channel.state

    if channel.first === slot
        channel.first = to_add
    end

    return nothing
end

# Insert slot at the end of the channel (application side)
function channel_slot_insert_end!(channel::Channel, slot::ChannelSlot)::Nothing
    slot.state = channel.state

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
    slot.state = channel.state

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
    channel = slot_channel_or_nothing(slot)

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
    slot.state = nothing

    if slot.handler_destroy_fn !== nothing
        (slot.handler_destroy_fn::ChannelHandlerDestroyCallable)()
    end
    _channel_slot_clear_handler_fns!(slot)

    if channel !== nothing
        _channel_calculate_message_overheads!(channel)
    end

    return nothing
end

# Replace a slot in the channel with a new slot
function channel_slot_replace!(remove::ChannelSlot, new_slot::ChannelSlot)
    channel = slot_channel_or_nothing(remove)
    new_slot.state = remove.state
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
    remove.state = nothing

    if remove.handler_destroy_fn !== nothing
        (remove.handler_destroy_fn::ChannelHandlerDestroyCallable)()
    end
    _channel_slot_clear_handler_fns!(remove)

    if channel !== nothing
        _channel_calculate_message_overheads!(channel)
    end

    return nothing
end

function _channel_slot_clear_handler_fns!(slot::ChannelSlot)::Nothing
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

# Set the handler for a slot
function channel_slot_set_handler!(slot::ChannelSlot, handler)
    slot.handler_read = ChannelHandlerReadCallable((s, message) -> handler_process_read_message(handler, s, message))
    slot.handler_write = ChannelHandlerWriteCallable((s, message) -> handler_process_write_message(handler, s, message))
    slot.handler_increment_window = ChannelHandlerIncrementWindowCallable((s, size) -> handler_increment_read_window(handler, s, size))
    slot.handler_shutdown_fn = ChannelHandlerShutdownCallable((s, direction, error_code, free_scarce_resources_immediately) -> handler_shutdown(handler, s, direction, error_code, free_scarce_resources_immediately))
    slot.handler_message_overhead_fn = ChannelHandlerMessageOverheadCallable(() -> handler_message_overhead(handler))
    slot.handler_destroy_fn = ChannelHandlerDestroyCallable(() -> handler_destroy(handler))
    slot.handler_trigger_read_fn = ChannelHandlerTriggerReadCallable(() -> handler_trigger_read(handler))
    slot.handler_reset_statistics_fn = ChannelHandlerResetStatisticsCallable(() -> handler_reset_statistics(handler))
    slot.handler_gather_statistics_fn = ChannelHandlerGatherStatisticsCallable(() -> handler_gather_statistics(handler))
    setchannelslot!(handler, slot)
    if slot.state !== nothing
        _channel_calculate_message_overheads!(slot_channel(slot))
    end
    channel_slot_increment_read_window!(slot, handler_initial_window_size(handler))
    return nothing
end

# Replace handler in a slot
function channel_slot_replace_handler!(slot::ChannelSlot, new_handler)::Nothing
    if slot.handler_destroy_fn !== nothing
        (slot.handler_destroy_fn::ChannelHandlerDestroyCallable)()
    end
    _channel_slot_clear_handler_fns!(slot)
    channel_slot_set_handler!(slot, new_handler)
    return nothing
end

# Message passing functions

# Send a read message to the next slot (toward application)
function channel_slot_send_message(slot::ChannelSlot, message::IoMessage, direction::ChannelDirection.T)::Nothing
    channel = slot_channel_or_nothing(slot)
    if channel === nothing
        throw_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
    end

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
    channel = slot_channel_or_nothing(slot)
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
    channel = slot_channel_or_nothing(slot)
    if channel === nothing
        throw_error(ERROR_INVALID_ARGUMENT)
    end
    if !channel_thread_is_callers_thread(channel)
        throw_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end
    overhead = channel_slot_upstream_message_overhead(slot)
    if overhead >= g_aws_channel_max_fragment_size[]
        fatal_assert("Upstream overhead exceeds channel max fragment size", "<unknown>", 0)
    end
    size_hint = g_aws_channel_max_fragment_size[] - overhead
    return channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, size_hint)
end

# Increment read window (flow control propagation)
function channel_slot_increment_read_window!(slot::ChannelSlot, size::Csize_t)::Nothing
    channel = slot_channel_or_nothing(slot)

    if channel === nothing
        return nothing
    end

    if channel.read_back_pressure_enabled && channel.channel_state != ChannelLifecycleState.SHUT_DOWN
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

    if channel.channel_state == ChannelLifecycleState.SHUT_DOWN
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
    if channel.channel_state == ChannelLifecycleState.ACTIVE
        return nothing
    end
    if channel.channel_state != ChannelLifecycleState.NOT_INITIALIZED && channel.channel_state != ChannelLifecycleState.SETTING_UP
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

    channel.channel_state = ChannelLifecycleState.ACTIVE

    # Invoke setup callback
    if channel.on_setup_completed !== nothing
        channel.on_setup_completed(AWS_OP_SUCCESS)
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
    if slot.handler_shutdown_fn === nothing
        return nothing
    end
    (slot.handler_shutdown_fn::ChannelHandlerShutdownCallable)(
        slot,
        ChannelDirection.WRITE,
        args.error_code,
        args.shutdown_immediately,
    )
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
        channel.on_shutdown_completed(channel.shutdown_error_code)
    end

    return nothing
end

function _channel_schedule_shutdown_completion!(channel::Channel)
    logf(
        LogLevel.INFO, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): shutdown complete, error=$(channel.shutdown_error_code)"
    )
    task = ScheduledTask(
        TaskFn(function(status)
            try
                _channel_shutdown_completion_task(channel, _coerce_task_status(status))
            catch
                Core.println("channel_shutdown_complete task errored")
            end
            return nothing
        end);
        type_tag = "channel_shutdown_complete",
    )
    event_loop_schedule_task_now!(channel.event_loop, task)
    return nothing
end

function _channel_shutdown_task(channel::Channel, status::TaskStatus.T)
    if channel.channel_state == ChannelLifecycleState.SHUT_DOWN ||
            channel.channel_state == ChannelLifecycleState.SHUTTING_DOWN_READ ||
            channel.channel_state == ChannelLifecycleState.SHUTTING_DOWN_WRITE
        return nothing
    end

    channel.channel_state = ChannelLifecycleState.SHUTTING_DOWN_READ

    slot = channel.first
    if slot !== nothing && slot.handler_shutdown_fn !== nothing
        channel_slot_shutdown!(slot, ChannelDirection.READ, channel.shutdown_error_code, channel.shutdown_immediately)
        return nothing
    end

    channel.channel_state = ChannelLifecycleState.SHUT_DOWN
    _channel_schedule_shutdown_completion!(channel)
    return nothing
end

# Shutdown the channel
function channel_shutdown!(channel::Channel, error_code::Int = 0; shutdown_immediately::Bool = false)::Nothing
    schedule_task = false
    lock(channel.shutdown_lock) do
        if channel.channel_state == ChannelLifecycleState.SHUT_DOWN ||
                channel.channel_state == ChannelLifecycleState.SHUTTING_DOWN_READ ||
                channel.channel_state == ChannelLifecycleState.SHUTTING_DOWN_WRITE ||
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
    channel = slot_channel_or_nothing(slot)

    if channel === nothing
        return nothing
    end

    logf(
        LogLevel.TRACE, LS_IO_CHANNEL,
        "Channel id=$(channel.channel_id): slot handler shutdown complete, direction=$direction"
    )

    if channel.channel_state == ChannelLifecycleState.SHUT_DOWN
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

        channel.channel_state = ChannelLifecycleState.SHUTTING_DOWN_WRITE
        write_args = ChannelShutdownWriteArgs(slot, error_code, free_scarce_resources_immediately)
        write_task = ScheduledTask(
            TaskFn(function(status)
                try
                    _channel_shutdown_write_task(write_args, _coerce_task_status(status))
                catch e
                    Core.println("channel_shutdown_write task errored")
                end
                return nothing
            end);
            type_tag = "channel_shutdown_write",
        )
        event_loop_schedule_task_now!(channel.event_loop, write_task)
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
        channel.channel_state = ChannelLifecycleState.SHUT_DOWN
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
        max_size = Csize_t(g_aws_channel_max_fragment_size[])
        effective_csize = Csize_t(effective_size)
        if effective_csize > max_size
            effective_csize = max_size
        end
        message = IoMessage(Int(effective_csize))
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
    if slot === nothing || slot.handler_shutdown_fn === nothing
        channel.channel_state = ChannelLifecycleState.SHUT_DOWN
    end

    if channel.channel_state != ChannelLifecycleState.SHUT_DOWN
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL,
            "Channel id=$(channel.channel_id): destroy called before shutdown complete"
        )
        return nothing
    end

    while slot !== nothing
        next = slot.adj_right
        if slot.handler_destroy_fn !== nothing
            (slot.handler_destroy_fn::ChannelHandlerDestroyCallable)()
        end
        _channel_slot_clear_handler_fns!(slot)
        slot.adj_left = nothing
        slot.adj_right = nothing
        slot.state = nothing
        slot = next
    end

    empty!(channel.statistics_list)
    if channel.statistics_handler !== nothing
        close!(channel.statistics_handler)
        channel.statistics_handler = nothing
        channel.statistics_task = nothing
    end

    event_loop_group_close_lease!(channel.event_loop_group_lease)
    channel.event_loop_group_lease = nothing
    if channel.socket !== nothing
        channel.socket.read_fn = nothing
    end
    channel.socket = nothing
    channel.tls_handler = nothing
    channel.downstream = nothing
    empty!(channel.shutdown_chain.read_shutdown_fns)
    empty!(channel.shutdown_chain.write_shutdown_fns)
    channel.first = nothing
    channel.last = nothing
    delete!(_channel_state_registry, channel.state)
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

    task = ScheduledTask(
        TaskFn(function(status)
            try
                _channel_destroy_task(channel, _coerce_task_status(status))
            catch e
                Core.println("channel_destroy task errored")
            end
            return nothing
        end);
        type_tag = "channel_destroy",
    )
    event_loop_schedule_task_now!(channel.event_loop, task)
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
