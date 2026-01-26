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
end

mutable struct ThreadHandle{F}
    id::thread_id_t
    detach_state::ThreadDetachState.T
    task::Union{Task, Nothing}  # nullable
    name::String
    managed::Bool
    atexit::ArrayList{F}
end

function ThreadHandle()
    return ThreadHandle{Any}(thread_id_t(0), ThreadDetachState.NOT_CREATED, nothing, "", false, ArrayList{Any}(0))
end

const thread = ThreadHandle
const thread_options = ThreadOptions

const _thread_state_registry = SmallRegistry{UInt64, ThreadHandle{Any}}()
const _thread_name_registry = SmallRegistry{UInt64, String}()

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
    for idx in handle.atexit.length:-1:1
        entry = handle.atexit.data[idx]
        entry === nothing && continue
        entry()
    end
    clear!(handle.atexit)
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

function thread_init(handle::ThreadHandle)
    handle.id = thread_id_t(0)
    handle.detach_state = ThreadDetachState.NOT_CREATED
    handle.task = nothing
    handle.name = ""
    handle.managed = false
    clear!(handle.atexit)
    return OP_SUCCESS
end

function thread_init(handle_ref::Base.RefValue{ThreadHandle}, ::Any = nothing)
    handle_ref[] = ThreadHandle()
    return OP_SUCCESS
end

function thread_launch(handle::ThreadHandle, fn, ctx, options::Union{ThreadOptions, Nothing} = nothing)
    opts = options === nothing ? ThreadOptions() : options
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
    handle.task = Threads.@spawn _thread_task_entry(handle, fn, ctx)
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
        handle.task === nothing && return OP_SUCCESS
        wait(handle.task)
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
    handle.name = ""
    handle.managed = false
    clear!(handle.atexit)
    return nothing
end

function thread_clean_up(handle_ref::Base.RefValue{ThreadHandle})
    return thread_clean_up(handle_ref[])
end

function thread_current_at_exit(callback)
    handle = _thread_tls_handle()
    handle === nothing && return raise_error(ERROR_INVALID_STATE)
    push_back!(handle.atexit, callback)
    return OP_SUCCESS
end

function thread_name(thread_id::thread_id_t)
    return registry_get(_thread_name_registry, UInt64(thread_id), nothing)
end

function thread_current_name()
    handle = _thread_tls_handle()
    return handle === nothing ? nothing : handle.name
end
