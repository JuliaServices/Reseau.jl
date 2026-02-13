using EnumX

@enumx TaskStatus::UInt8 begin
    RUN_READY = 0
    CANCELED = 1
end

@inline _coerce_task_status(status::TaskStatus.T)::TaskStatus.T = status
@inline _coerce_task_status(status)::TaskStatus.T = TaskStatus.T(status)

@inline function _callback_obj_to_ptr_and_root(obj)
    obj === nothing && return C_NULL, nothing
    if Base.ismutabletype(typeof(obj))
        # Preserve mutable objects explicitly while passing raw object pointers
        # through callback trampolines.
        return pointer_from_objref(obj), obj
    end
    box = Ref{Any}(obj)
    return pointer_from_objref(box), box
end

@inline function _callback_ptr_to_obj(ptr::Ptr{Cvoid})
    ptr == C_NULL && return nothing
    obj = unsafe_pointer_to_objref(ptr)
    return obj isa Base.RefValue ? obj[] : obj
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

function (::_TaskCallWrapper)(f::F, status::UInt8) where {F}
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

# ── EventCallable: trim-safe type-erased callable for (Int) -> Nothing ──
# Covers: on_event (kqueue/epoll), readable_fn, on_readable (pipe),
# on_completion (IoMessage), ChannelTask.task_fn.

struct _EventCallWrapper <: Function end

function (::_EventCallWrapper)(f::F, x::Int) where {F}
    f(x)
    return nothing
end

@generated function _event_gen_fptr(::Type{F}) where F
    quote
        @cfunction($(_EventCallWrapper()), Cvoid, (Ref{$F}, Int))
    end
end

struct EventCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function EventCallable(callable::F) where F
    ptr = _event_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return EventCallable(ptr, objptr, objref)
end


@inline function (f::EventCallable)(x::Int)::Nothing
    ccall(f.ptr, Cvoid, (Ptr{Cvoid}, Int), f.objptr, x)
    return nothing
end

# ── WriteCallable: trim-safe type-erased callable for (Int, Csize_t) -> Nothing ──
# Covers: written_fn (posix/winsock/NW write completion callbacks).

struct _WriteCallWrapper <: Function end

function (::_WriteCallWrapper)(f::F, err::Int, n::Csize_t) where {F}
    f(err, n)
    return nothing
end

@generated function _write_gen_fptr(::Type{F}) where F
    quote
        @cfunction($(_WriteCallWrapper()), Cvoid, (Ref{$F}, Int, Csize_t))
    end
end

struct WriteCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function WriteCallable(callable::F) where F
    ptr = _write_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return WriteCallable(ptr, objptr, objref)
end


@inline function (f::WriteCallable)(err::Int, n::Csize_t)::Nothing
    ccall(f.ptr, Cvoid, (Ptr{Cvoid}, Int, Csize_t), f.objptr, err, n)
    return nothing
end

# ── ChannelCallable: trim-safe type-erased callable for (Int, Any) -> Nothing ──
# Covers: accept_result_fn (error_code, new_socket), on_incoming_channel_setup/shutdown
# (error_code, channel), and similar callbacks needing a runtime object argument.

struct _ChannelCallWrapper <: Function end

function (::_ChannelCallWrapper)(f::F, error_code::Int, objptr::Ptr{Cvoid}) where {F}
    f(error_code, _callback_ptr_to_obj(objptr))
    return nothing
end

@generated function _channel_gen_fptr(::Type{F}) where F
    quote
        @cfunction($(_ChannelCallWrapper()), Cvoid, (Ref{$F}, Int, Ptr{Cvoid}))
    end
end

struct ChannelCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ChannelCallable(callable::F) where F
    ptr = _channel_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ChannelCallable(ptr, objptr, objref)
end


@inline function (f::ChannelCallable)(error_code::Int, obj)::Nothing
    objptr, objroot = _callback_obj_to_ptr_and_root(obj)
    GC.@preserve objroot begin
        ccall(f.ptr, Cvoid, (Ptr{Cvoid}, Int, Ptr{Cvoid}), f.objptr, error_code, objptr)
    end
    return nothing
end

# ── ProtocolNegotiatedCallable: trim-safe (Any, Any) -> Any ──
# Covers: ALPN protocol callback (slot, protocol) -> new_handler_or_nothing.

struct _ProtocolNegotiatedCallWrapper <: Function end

function (::_ProtocolNegotiatedCallWrapper)(f::F, slot, protocol) where {F}
    return f(slot, protocol)
end

@generated function _protocol_negotiated_gen_fptr(::Type{F}) where F
    quote
        @cfunction($(_ProtocolNegotiatedCallWrapper()), Any, (Ref{$F}, Any, Any))
    end
end

struct ProtocolNegotiatedCallable
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function ProtocolNegotiatedCallable(callable::F) where F
    ptr = _protocol_negotiated_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return ProtocolNegotiatedCallable(ptr, objptr, objref)
end

@inline function (f::ProtocolNegotiatedCallable)(slot, protocol)
    return ccall(f.ptr, Any, (Ptr{Cvoid}, Any, Any), f.objptr, slot, protocol)
end

# ── HostResolveCallback: typed resolver callback wrapper ──
# (resolver, host_name, error_code, addresses) -> nothing.

struct HostResolveCallback{F}
    callback::F
end

@inline function (f::HostResolveCallback{F})(resolver, host_name, error_code::Int, addresses)::Nothing where {F}
    f.callback(resolver, host_name, error_code, addresses)
    return nothing
end

# ── HostResolveImpl: typed resolver implementation wrapper ──
# Supports both forms:
#   (host, impl_data) -> result
#   (host, address_type, impl_data) -> result

struct HostResolveImpl{F}
    callable::F
end

@inline function (f::HostResolveImpl{F})(host, impl_data) where {F}
    return f.callable(host, impl_data)
end

@inline function (f::HostResolveImpl{F})(host, address_type, impl_data) where {F}
    return f.callable(host, address_type, impl_data)
end

# ── TLS callback wrappers ──
# Covers callback fields in TlsConnectionOptions + backend handlers.

struct _TlsNegotiationResultCallbackWrapper <: Function end

function (::_TlsNegotiationResultCallbackWrapper)(f::F, handler, slot, error_code::Int) where {F}
    f(handler, slot, error_code)
    return nothing
end

@generated function _tls_negotiation_result_callback_gen_fptr(::Type{F}) where F
    quote
        @cfunction($(_TlsNegotiationResultCallbackWrapper()), Cvoid, (Ref{$F}, Any, Any, Int))
    end
end

struct TlsNegotiationResultCallback
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function TlsNegotiationResultCallback(callable::F) where F
    ptr = _tls_negotiation_result_callback_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return TlsNegotiationResultCallback(ptr, objptr, objref)
end

@inline function (f::TlsNegotiationResultCallback)(handler, slot, error_code::Int)::Nothing
    ccall(f.ptr, Cvoid, (Ptr{Cvoid}, Any, Any, Int), f.objptr, handler, slot, error_code)
    return nothing
end

struct _TlsDataReadCallbackWrapper <: Function end

function (::_TlsDataReadCallbackWrapper)(f::F, handler, slot, buffer) where {F}
    f(handler, slot, buffer)
    return nothing
end

@generated function _tls_data_read_callback_gen_fptr(::Type{F}) where F
    quote
        @cfunction($(_TlsDataReadCallbackWrapper()), Cvoid, (Ref{$F}, Any, Any, Any))
    end
end

struct TlsDataReadCallback
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function TlsDataReadCallback(callable::F) where F
    ptr = _tls_data_read_callback_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return TlsDataReadCallback(ptr, objptr, objref)
end

@inline function (f::TlsDataReadCallback)(handler, slot, buffer)::Nothing
    ccall(f.ptr, Cvoid, (Ptr{Cvoid}, Any, Any, Any), f.objptr, handler, slot, buffer)
    return nothing
end

struct _TlsErrorCallbackWrapper <: Function end

function (::_TlsErrorCallbackWrapper)(f::F, handler, slot, error_code::Int, message) where {F}
    f(handler, slot, error_code, message)
    return nothing
end

@generated function _tls_error_callback_gen_fptr(::Type{F}) where F
    quote
        @cfunction($(_TlsErrorCallbackWrapper()), Cvoid, (Ref{$F}, Any, Any, Int, Any))
    end
end

struct TlsErrorCallback
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function TlsErrorCallback(callable::F) where F
    ptr = _tls_error_callback_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return TlsErrorCallback(ptr, objptr, objref)
end

@inline function (f::TlsErrorCallback)(handler, slot, error_code::Int, message)::Nothing
    ccall(f.ptr, Cvoid, (Ptr{Cvoid}, Any, Any, Int, Any), f.objptr, handler, slot, error_code, message)
    return nothing
end

# ── BootstrapChannelCallback: trim-safe (Any, Int, Any, Any) -> Nothing ──
# Covers channel-bootstrap user callbacks:
#   (bootstrap, error_code, channel, user_data) -> nothing.

struct _BootstrapChannelCallbackWrapper <: Function end

function (::_BootstrapChannelCallbackWrapper)(f::F, bootstrap_ptr::Ptr{Cvoid}, error_code::Int, channel_ptr::Ptr{Cvoid}, user_data_ptr::Ptr{Cvoid}) where {F}
    bootstrap = _callback_ptr_to_obj(bootstrap_ptr)
    channel = _callback_ptr_to_obj(channel_ptr)
    user_data = _callback_ptr_to_obj(user_data_ptr)
    f(bootstrap, error_code, channel, user_data)
    return nothing
end

@generated function _bootstrap_channel_callback_gen_fptr(::Type{F}) where F
    quote
        @cfunction($(_BootstrapChannelCallbackWrapper()), Cvoid, (Ref{$F}, Ptr{Cvoid}, Int, Ptr{Cvoid}, Ptr{Cvoid}))
    end
end

struct BootstrapChannelCallback
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function BootstrapChannelCallback(callable::F) where F
    ptr = _bootstrap_channel_callback_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return BootstrapChannelCallback(ptr, objptr, objref)
end

@inline function (f::BootstrapChannelCallback)(bootstrap, error_code::Int, channel, user_data)::Nothing
    bootstrap_ptr, bootstrap_root = _callback_obj_to_ptr_and_root(bootstrap)
    channel_ptr, channel_root = _callback_obj_to_ptr_and_root(channel)
    user_data_ptr, user_data_root = _callback_obj_to_ptr_and_root(user_data)
    GC.@preserve bootstrap_root channel_root user_data_root begin
        ccall(
            f.ptr,
            Cvoid,
            (Ptr{Cvoid}, Ptr{Cvoid}, Int, Ptr{Cvoid}, Ptr{Cvoid}),
            f.objptr,
            bootstrap_ptr,
            error_code,
            channel_ptr,
            user_data_ptr,
        )
    end
    return nothing
end

# ── BootstrapEventCallback: trim-safe (Any, Int, Any) -> Nothing ──
# Covers server-bootstrap lifecycle callbacks:
#   (bootstrap, error_code, user_data) -> nothing.

struct _BootstrapEventCallbackWrapper <: Function end

function (::_BootstrapEventCallbackWrapper)(f::F, bootstrap_ptr::Ptr{Cvoid}, error_code::Int, user_data_ptr::Ptr{Cvoid}) where {F}
    bootstrap = _callback_ptr_to_obj(bootstrap_ptr)
    user_data = _callback_ptr_to_obj(user_data_ptr)
    f(bootstrap, error_code, user_data)
    return nothing
end

@generated function _bootstrap_event_callback_gen_fptr(::Type{F}) where F
    quote
        @cfunction($(_BootstrapEventCallbackWrapper()), Cvoid, (Ref{$F}, Ptr{Cvoid}, Int, Ptr{Cvoid}))
    end
end

struct BootstrapEventCallback
    ptr::Ptr{Cvoid}
    objptr::Ptr{Cvoid}
    _root::Any
end

function BootstrapEventCallback(callable::F) where F
    ptr = _bootstrap_event_callback_gen_fptr(F)
    objref = Base.cconvert(Ref{F}, callable)
    objptr = Ptr{Cvoid}(Base.unsafe_convert(Ref{F}, objref))
    return BootstrapEventCallback(ptr, objptr, objref)
end

@inline function (f::BootstrapEventCallback)(bootstrap, error_code::Int, user_data)::Nothing
    bootstrap_ptr, bootstrap_root = _callback_obj_to_ptr_and_root(bootstrap)
    user_data_ptr, user_data_root = _callback_obj_to_ptr_and_root(user_data)
    GC.@preserve bootstrap_root user_data_root begin
        ccall(
            f.ptr,
            Cvoid,
            (Ptr{Cvoid}, Ptr{Cvoid}, Int, Ptr{Cvoid}),
            f.objptr,
            bootstrap_ptr,
            error_code,
            user_data_ptr,
        )
    end
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
        LS_COMMON_TASK_SCHEDULER,string("id=%s: Running %s task with %s status", " ", string(objectid(task)), " ", task.type_tag, " ", task_status_to_string(status), " ", ))
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
        LS_COMMON_TASK_SCHEDULER,string("id=%s: Scheduling %s task for immediate execution", " ", string(objectid(task)), " ", task.type_tag, " ", ))
    task.timestamp = UInt64(0)
    task.scheduled = true
    push!(scheduler.asap, task)
    return nothing
end

function task_scheduler_schedule_future!(scheduler::TaskScheduler, task::ScheduledTask, time_to_run::UInt64)
    logf(
        LogLevel.TRACE,
        LS_COMMON_TASK_SCHEDULER,string("id=%s: Scheduling %s task for future execution at time %d", " ", string(objectid(task)), " ", task.type_tag, " ", time_to_run, " ", ))
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
