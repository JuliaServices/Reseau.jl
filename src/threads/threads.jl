module Threads

# Reseau thread/runtime utilities.
#
# This submodule intentionally shares its name with `Base.Threads`. To avoid
# confusion inside this module, always qualify stdlib thread constructs via
# `Base.Threads`.

using EnumX

# Mirror the most commonly used stdlib thread primitives inside this module.
using Base.Threads
const Condition = Base.Threads.Condition
const Event = Base.Threads.Event

# Make parent-module bindings (common utilities, error codes, logging, etc.)
# available without needing to thread long `..Reseau.` prefixes throughout the
# implementation files moved into this module.
const _PARENT = parentmodule(@__MODULE__)
for name in names(_PARENT; all = true, imported = false)
    # Skip macros and the module's self-binding.
    str = String(name)
    startswith(str, "@") && continue
    name === :Threads && continue
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

include("condition_variable.jl")
include("task_scheduler.jl")
include("thread.jl")
include("thread_shared.jl")
include("future.jl")

export
    ThreadHandle,
    ThreadOptions,
    ThreadJoinStrategy,
    ThreadDetachState,
    thread_current_sleep,
    thread_current_thread_id,
    thread_get_id,
    thread_init,
    thread_launch,
    thread_join,
    thread_pending_join_add,
    ConditionVariable,
    ScheduledTask,
    TaskScheduler,
    Future,
    future_complete!,
    future_fail!,
    future_get_error,
    future_get_result,
    future_on_complete!,
    future_on_complete_if_not_done!

end # module Threads
