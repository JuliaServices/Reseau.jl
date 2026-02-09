module EventLoops

# Thin module wrapper that groups event-loop functionality under `Reseau.EventLoops`.
# The underlying implementations currently live in `src/sockets/io/*`.

using ..Reseau:
    EventLoop,
    EventLoopGroup,
    EventLoopGroupOptions,
    IoEventType,
    event_loop_group_get_loop_count,
    event_loop_group_get_loop_at,
    event_loop_group_get_next_loop,
    event_loop_group_release!,
    event_loop_schedule_task_now!,
    event_loop_schedule_task_future!,
    event_loop_subscribe_to_io_events!,
    event_loop_unsubscribe_from_io_events!,
    event_loop_thread_is_callers_thread

export
    EventLoop,
    EventLoopGroup,
    EventLoopGroupOptions,
    IoEventType,
    event_loop_group_get_loop_count,
    event_loop_group_get_loop_at,
    event_loop_group_get_next_loop,
    event_loop_group_release!,
    event_loop_schedule_task_now!,
    event_loop_schedule_task_future!,
    event_loop_subscribe_to_io_events!,
    event_loop_unsubscribe_from_io_events!,
    event_loop_thread_is_callers_thread

end # module EventLoops
