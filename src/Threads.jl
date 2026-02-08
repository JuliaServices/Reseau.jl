module Threads

# This submodule intentionally shares its name with `Base.Threads`.
# Inside `Reseau`, many existing call-sites reference `Threads.Event`, `Threads.Condition`, etc.
# Defining `Reseau.Threads` would normally shadow `Base.Threads`, so we import those bindings
# here to preserve existing behavior while also providing Reseau's thread/runtime utilities.

using Base.Threads

# `Base.Threads` does not export `Condition` (it is available as `Threads.Condition`),
# but a lot of existing Reseau code uses `Threads.Condition` explicitly.
const Condition = Base.Threads.Condition

# Similarly, be explicit for `Event` since it is heavily used.
const Event = Base.Threads.Event

# Reseau's OS-thread utilities (foreign thread launching/adoption) and scheduler primitives.
using ..Reseau: ThreadHandle, ThreadOptions, ThreadJoinStrategy, ThreadDetachState
using ..Reseau: thread_current_sleep, thread_current_thread_id, thread_get_id, thread_init
using ..Reseau: thread_launch, thread_join, thread_pending_join_add
using ..Reseau: ConditionVariable
using ..Reseau: ScheduledTask, TaskScheduler
using ..Reseau: Future, future_complete!, future_fail!, future_get_error, future_get_result
using ..Reseau: future_on_complete!, future_on_complete_if_not_done!

export
    # Reseau thread/runtime utilities.
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
