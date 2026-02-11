module EventLoops

# Reseau's libuv-free event loop surface.
#
# This module houses the native event-loop implementations (kqueue/epoll/iocp),
# along with the core IO definitions that the socket stack builds upon.

using EnumX

# Bring parent-module bindings (common utilities, error codes, logging, etc.)
# into this module so moved implementation files can remain largely unchanged.
const _PARENT = parentmodule(@__MODULE__)
for name in names(_PARENT; all = true, imported = false)
    str = String(name)
    startswith(str, "@") && continue
    # Do not shadow stdlib `Threads` inside this module (implementation uses `Base.Threads.*`).
    name === :Threads && continue
    # Do not shadow Base.put!/Base.take! (lru_cache.jl defines Reseau.put! which would mask them).
    name === :put! && continue
    # Avoid self-aliasing.
    name === :EventLoops && continue
    if isdefined(@__MODULE__, name)
        # Allow overwriting Base/Core imports (we want the parent-module bindings),
        # but never clobber bindings defined by this module.
        owner = Base.binding_module(@__MODULE__, name)
        owner === (@__MODULE__) && continue
        (owner === Base || owner === Core) || continue
    end
    val = getfield(_PARENT, name)
    @eval const $(name) = $(_PARENT).$(name)
end

# Pull in thread/runtime primitives from the sibling `Reseau.ForeignThreads` module so
# the implementation can refer to them unqualified.
const _THREADS = getfield(_PARENT, :ForeignThreads)
for name in names(_THREADS; all = true, imported = false)
    str = String(name)
    startswith(str, "@") && continue
    name === :ForeignThreads && continue
    name === :__init__ && continue
    if isdefined(@__MODULE__, name)
        owner = Base.binding_module(@__MODULE__, name)
        owner === (@__MODULE__) && continue
        (owner === Base || owner === Core) || continue
    end
    val = getfield(_THREADS, name)
    @eval const $(name) = $(_THREADS).$(name)
end
# Macros are skipped by the name-loop above; import them explicitly.
using ..ForeignThreads: @wrap_thread_fn

include("tracing.jl")
include("io.jl")
include("message_pool.jl")

include("kqueue_event_loop_types.jl")
include("epoll_event_loop_types.jl")
include("iocp_event_loop_types.jl")

include("event_loop.jl")
include("kqueue_event_loop.jl")
include("epoll_event_loop.jl")
include("iocp_event_loop.jl")

include("future.jl")

function __init__()
    _init_default_clock()
    @static if Sys.isapple() || Sys.isbsd()
        _kqueue_init_cfunctions!()
    elseif Sys.islinux()
        _epoll_init_cfunctions!()
    elseif Sys.iswindows()
        _iocp_init_cfunctions!()
    end
    return nothing
end

export
    EventLoop,
    EventLoopGroup,
    EventLoopGroupOptions,
    IoEventType,
    default_event_loop_group,
    event_loop_group_get_loop_count,
    event_loop_group_get_loop_at,
    event_loop_group_get_next_loop,
    event_loop_group_release!,
    event_loop_schedule_task_now!,
    event_loop_schedule_task_future!,
    event_loop_subscribe_to_io_events!,
    event_loop_unsubscribe_from_io_events!,
    event_loop_thread_is_callers_thread,
    # Futures
    Future,
    cancel!

end # module EventLoops
