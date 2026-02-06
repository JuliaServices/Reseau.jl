using EnumX

@enumx ThreadDetachState::UInt8 begin
    NOT_CREATED = 1
    JOINABLE = 2
    JOIN_COMPLETED = 3
    MANAGED = 4
end

@enumx ThreadJoinStrategy::UInt8 begin
    MANUAL = 0
    MANAGED = 1
end

@static if _PLATFORM_WINDOWS
    const thread_id_t = UInt32
else
    const thread_id_t = UInt64
end

const pthread_t = UInt  # pointer-sized: opaque ptr on macOS, unsigned long on Linux

const THREAD_NAME_RECOMMENDED_STRLEN = 15

mutable struct _thread_id_state
    @atomic next_id::UInt64
end

const _thread_id_state = _thread_id_state(UInt64(0))
const _main_thread_id = Ref{thread_id_t}(0)

@inline function _thread_next_id()
    return thread_id_t(@atomic _thread_id_state.next_id += 1)
end

Base.@kwdef struct ThreadOptions
    stack_size::Int = 0
    cpu_id::Int = -1
    join_strategy::ThreadJoinStrategy.T = ThreadJoinStrategy.MANUAL
    name::String = ""
    pool::Symbol = :default
end

mutable struct ThreadHandle{F}
    id::thread_id_t
    detach_state::ThreadDetachState.T
    task::Union{Task, Nothing}  # nullable
    os_thread::pthread_t        # pthread_t (0 if not OS thread)
    name::String
    managed::Bool
    atexit::Vector{F}
    _start_ctx::Any             # temporary (fn, ctx) for OS thread startup
end

function ThreadHandle()
    return ThreadHandle{Any}(thread_id_t(0), ThreadDetachState.NOT_CREATED, nothing, pthread_t(0), "", false, Any[], nothing)
end

const thread = ThreadHandle
const thread_options = ThreadOptions

const _thread_state_registry = SmallRegistry{UInt64, ThreadHandle{Any}}()
const _thread_name_registry = SmallRegistry{UInt64, String}()

mutable struct _interactive_thread_state
    @atomic next_id::Int
end

const _interactive_thread_state = _interactive_thread_state(0)

function _next_interactive_thread_id()
    count = Threads.nthreads(:interactive)
    if count <= 1
        return 1
    end
    next_idx = @atomic _interactive_thread_state.next_id += 1
    return Int(mod(next_idx - 1, count - 1)) + 2
end

# --- OS thread support via pthread_create + @cfunction auto-adoption ---

# @cfunction pointer — NOT valid during precompilation; initialized in __init__
const _os_thread_entry_c = Ref{Ptr{Cvoid}}(C_NULL)

# Thread entry point — @cfunction slow-path auto-adopts the foreign thread
# CRITICAL: must never throw across the C boundary
function _os_thread_entry_impl(arg::Ptr{Cvoid})::Ptr{Cvoid}
    try
        handle = unsafe_pointer_to_objref(arg)::ThreadHandle
        fn, user_ctx = handle._start_ctx::Tuple
        handle._start_ctx = nothing  # release reference
        _thread_task_entry(handle, fn, user_ctx)
    catch ex
        try
            @error "Fatal error in OS thread entry" exception=(ex, catch_backtrace())
        catch; end
    end
    return C_NULL
end

function _init_os_thread_cfunc!()
    _os_thread_entry_c[] = @cfunction(_os_thread_entry_impl, Ptr{Cvoid}, (Ptr{Cvoid},))
    return nothing
end

function _spawn_os_thread(handle::ThreadHandle, fn, ctx)
    handle._start_ctx = (fn, ctx)
    pthread_ref = Ref{pthread_t}(0)
    ret = ccall(:pthread_create, Cint,
        (Ref{pthread_t}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
        pthread_ref, C_NULL, _os_thread_entry_c[], pointer_from_objref(handle))
    if ret != 0
        handle._start_ctx = nothing
        return ret
    end
    handle.os_thread = pthread_ref[]
    return Cint(0)
end

function _spawn_on_interactive_thread(handle::ThreadHandle, fn, ctx, target_tid::Int)
    task = Task(() -> _thread_task_entry(handle, fn, ctx))
    task.sticky = true
    Base.Threads._spawn_set_thrpool(task, :interactive)
    _ = ccall(:jl_set_task_tid, Cint, (Any, Cint), task, target_tid - 1)
    schedule(task)
    return task
end

@inline function _thread_tls_handle()
    return get(Base.task_local_storage(), :thread_handle, nothing)
end

function _thread_set_tls_handle(handle)
    Base.task_local_storage(:thread_handle, handle)
    return nothing
end

function thread_current_thread_id()
    handle = _thread_tls_handle()
    if handle !== nothing
        return handle.id
    end
    if _main_thread_id[] == 0
        _main_thread_id[] = _thread_next_id()
    end
    return _main_thread_id[]
end

@inline thread_thread_id_equal(t1::thread_id_t, t2::thread_id_t) = t1 == t2

function thread_current_sleep(nanos::Integer)
    nanos <= 0 && return nothing
    sleep(nanos / 1_000_000_000)
    return nothing
end

function _run_thread_atexit!(handle::ThreadHandle)
    if isempty(handle.atexit)
        return nothing
    end
    # Run in reverse registration order.
    for idx in length(handle.atexit):-1:1
        entry = handle.atexit[idx]
        entry === nothing && continue
        entry()
    end
    empty!(handle.atexit)
    return nothing
end

function _thread_task_entry(handle::ThreadHandle, fn, ctx)
    _thread_set_tls_handle(handle)
    try
        fn(ctx)
    finally
        _run_thread_atexit!(handle)
        _thread_set_tls_handle(nothing)
        if handle.managed
            thread_pending_join_add(handle)
            thread_decrement_unjoined_count()
        end
    end
    return nothing
end

function default_thread_options()
    return ThreadOptions()
end

function thread_options_with_defaults(opts::ThreadOptions; name::AbstractString = "", pool::Symbol = opts.pool)
    resolved_name = isempty(opts.name) ? String(name) : opts.name
    return ThreadOptions(;
        stack_size = opts.stack_size,
        cpu_id = opts.cpu_id,
        join_strategy = opts.join_strategy,
        name = resolved_name,
        pool = pool,
    )
end

function thread_init(handle::ThreadHandle)
    handle.id = thread_id_t(0)
    handle.detach_state = ThreadDetachState.NOT_CREATED
    handle.task = nothing
    handle.os_thread = pthread_t(0)
    handle.name = ""
    handle.managed = false
    empty!(handle.atexit)
    handle._start_ctx = nothing
    return OP_SUCCESS
end

function thread_init(handle_ref::Base.RefValue{ThreadHandle}, ::Any = nothing)
    handle_ref[] = ThreadHandle()
    return OP_SUCCESS
end

function thread_launch(handle::ThreadHandle, fn, ctx, options::Union{ThreadOptions, Nothing} = nothing)
    opts = options === nothing ? ThreadOptions() : options
    if opts.pool == :interactive
        if Threads.nthreads(:interactive) <= 1
            raise_error(ERROR_THREAD_INVALID_SETTINGS)
            return ERROR_THREAD_INVALID_SETTINGS
        end
    elseif opts.pool != :default && opts.pool != :os
        raise_error(ERROR_INVALID_ARGUMENT)
        return ERROR_INVALID_ARGUMENT
    end
    managed = opts.join_strategy == ThreadJoinStrategy.MANAGED
    handle.detach_state = managed ? ThreadDetachState.MANAGED : ThreadDetachState.JOINABLE
    handle.managed = managed
    handle.name = opts.name
    handle.id = _thread_next_id()
    registry_set!(_thread_state_registry, UInt64(handle.id), handle)
    if !isempty(handle.name)
        registry_set!(_thread_name_registry, UInt64(handle.id), handle.name)
    end
    if managed
        thread_increment_unjoined_count()
    end
    if opts.pool == :os
        ret = _spawn_os_thread(handle, fn, ctx)
        if ret != 0
            registry_delete!(_thread_state_registry, UInt64(handle.id))
            registry_delete!(_thread_name_registry, UInt64(handle.id))
            if managed
                thread_decrement_unjoined_count()
            end
            handle.detach_state = ThreadDetachState.NOT_CREATED
            raise_error(ERROR_THREAD_NO_SUCH_THREAD_ID)
            return ERROR_THREAD_NO_SUCH_THREAD_ID
        end
    elseif opts.pool == :interactive
        target_tid = _next_interactive_thread_id()
        handle.task = Base.errormonitor(_spawn_on_interactive_thread(handle, fn, ctx, target_tid))
    else
        handle.task = Base.errormonitor(Threads.@spawn _thread_task_entry(handle, fn, ctx))
    end
    return OP_SUCCESS
end

function thread_launch(handle_ref::Base.RefValue{ThreadHandle}, fn, ctx, options::Union{ThreadOptions, Nothing} = nothing)
    return thread_launch(handle_ref[], fn, ctx, options)
end

function thread_get_id(handle::ThreadHandle)
    return handle.id
end

function thread_get_id(handle_ref::Base.RefValue{ThreadHandle})
    return thread_get_id(handle_ref[])
end

function thread_get_detach_state(handle::ThreadHandle)
    return handle.detach_state
end

function thread_get_detach_state(handle_ref::Base.RefValue{ThreadHandle})
    return thread_get_detach_state(handle_ref[])
end

function thread_join(handle::ThreadHandle)
    if handle.detach_state == ThreadDetachState.JOINABLE
        if handle.os_thread != 0
            @ccall gc_safe = true pthread_join(handle.os_thread::pthread_t, C_NULL::Ptr{Ptr{Cvoid}})::Cint
        elseif handle.task !== nothing
            wait(handle.task)
        end
        handle.detach_state = ThreadDetachState.JOIN_COMPLETED
        return OP_SUCCESS
    end
    return OP_SUCCESS
end

function thread_join(handle_ref::Base.RefValue{ThreadHandle})
    return thread_join(handle_ref[])
end

function thread_clean_up(handle::ThreadHandle)
    if handle.id != 0
        registry_delete!(_thread_state_registry, UInt64(handle.id))
        registry_delete!(_thread_name_registry, UInt64(handle.id))
    end
    handle.id = thread_id_t(0)
    handle.detach_state = ThreadDetachState.NOT_CREATED
    handle.task = nothing
    handle.os_thread = pthread_t(0)
    handle.name = ""
    handle.managed = false
    empty!(handle.atexit)
    handle._start_ctx = nothing
    return nothing
end

function thread_clean_up(handle_ref::Base.RefValue{ThreadHandle})
    return thread_clean_up(handle_ref[])
end

function thread_current_at_exit(callback)
    handle = _thread_tls_handle()
    handle === nothing && return raise_error(ERROR_INVALID_STATE)
    push!(handle.atexit, callback)
    return OP_SUCCESS
end

function thread_name(thread_id::thread_id_t)
    return registry_get(_thread_name_registry, UInt64(thread_id), nothing)
end

function thread_current_name()
    handle = _thread_tls_handle()
    return handle === nothing ? nothing : handle.name
end
