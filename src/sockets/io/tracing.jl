# AWS IO Library - Tracing (no-op hooks for parity with aws-c-io)

const _io_tracing_enabled = Ref(false)

const tracing_input_stream_read = :input_stream_read
const tracing_event_loop_run_tasks = :event_loop_run_tasks
const tracing_event_loop_event = :event_loop_event
const tracing_event_loop_events = :event_loop_events

function io_tracing_init()
    _io_tracing_enabled[] = false
    return nothing
end

@inline function tracing_task_begin(_tag)
    return nothing
end

@inline function tracing_task_end(_tag)
    return nothing
end
