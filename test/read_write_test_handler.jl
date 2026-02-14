using Reseau

mutable struct ReadWriteTestHandler
    pipeline::Any  # PipelineState (set when installing)
    on_read::Any
    on_write::Any
    event_loop_driven::Bool
    window::Csize_t
    lock::ReentrantLock
    condition::Base.Threads.Condition
    shutdown_called::Bool
    shutdown_error::Int
    increment_read_window_called::Bool
    destroy_called::Union{Base.RefValue{Bool}, Nothing}
    destroy_condition::Union{Base.Threads.Condition, Nothing}
    ctx::Any
end

function ReadWriteTestHandler(
        on_read,
        on_write;
        event_loop_driven::Bool = true,
        window::Integer = 0,
        ctx = nothing,
    )
    return ReadWriteTestHandler(
        nothing,  # pipeline (set later)
        on_read,
        on_write,
        event_loop_driven,
        Csize_t(window),
        ReentrantLock(),
        Base.Threads.Condition(),
        false,
        Reseau.AWS_OP_SUCCESS,
        false,
        nothing,
        nothing,
        ctx,
    )
end

function rw_handler_new(on_read, on_write, event_loop_driven::Bool, window::Integer, ctx)
    return ReadWriteTestHandler(
        on_read,
        on_write;
        event_loop_driven = event_loop_driven,
        window = window,
        ctx = ctx,
    )
end

function rw_handler_install!(handler::ReadWriteTestHandler, pipeline)
    handler.pipeline = pipeline
    if pipeline.downstream_read_setter !== nothing
        pipeline.downstream_read_setter(function(msg::Sockets.IoMessage)
            data = msg.message_data
            handler.on_read(handler, nothing, data, handler.ctx)
            Sockets.pipeline_release_message_to_pool!(pipeline, msg)
            return nothing
        end)
    end
    return nothing
end

@inline function _rw_task_status(status)
    return status isa Reseau.TaskStatus.T ? status : Reseau.TaskStatus.T(status)
end

function _rw_handler_write_now(
        handler::ReadWriteTestHandler,
        buffer::Reseau.ByteBuffer,
        on_completion,
        user_data,
    )
    ps = handler.pipeline
    socket = ps.socket
    remaining = Int(buffer.len)
    cursor_ref = Ref(Reseau.byte_cursor_from_buf(buffer))
    while remaining > 0
        msg = Sockets.pipeline_acquire_message_from_pool(
            ps,
            EventLoops.IoMessageType.APPLICATION_DATA,
            remaining,
        )
        msg === nothing && return Reseau.ERROR_OOM

        chunk_size = min(remaining, Int(Reseau.capacity(msg.message_data) - msg.message_data.len))
        msg.on_completion = on_completion
        msg.user_data = user_data

        chunk_cursor = Reseau.byte_cursor_advance(cursor_ref, chunk_size)
        msg_ref = Ref(msg.message_data)
        Reseau.byte_buf_write_from_whole_cursor(msg_ref, chunk_cursor)
        msg.message_data = msg_ref[]

        Sockets.pipeline_write!(socket, msg)
        remaining -= chunk_size
    end
    return nothing
end

function rw_handler_write(handler::ReadWriteTestHandler, buffer::Reseau.ByteBuffer)
    return rw_handler_write_with_callback(handler, buffer, nothing, nothing)
end

function rw_handler_write_with_callback(
        handler::ReadWriteTestHandler,
        buffer::Reseau.ByteBuffer,
        on_completion,
        user_data,
    )
    ps = handler.pipeline
    if !handler.event_loop_driven || Sockets.pipeline_thread_is_callers_thread(ps)
        return _rw_handler_write_now(handler, buffer, on_completion, user_data)
    end

    task = Sockets.ChannelTask(Reseau.EventCallable(status -> begin
        if _rw_task_status(status) == Reseau.TaskStatus.RUN_READY
            _rw_handler_write_now(handler, buffer, on_completion, user_data)
        end
        nothing
    end), "rw_handler_write")
    Sockets.pipeline_schedule_task_now!(ps, task)
    return nothing
end

function rw_handler_trigger_increment_read_window(
        handler::ReadWriteTestHandler,
        window_update::Integer,
    )
    update = Csize_t(window_update)
    ps = handler.pipeline
    if !handler.event_loop_driven || Sockets.pipeline_thread_is_callers_thread(ps)
        handler.window = Reseau.add_size_saturating(handler.window, update)
        return Sockets.pipeline_increment_read_window!(ps, update)
    end

    task = Sockets.ChannelTask(Reseau.EventCallable(status -> begin
        if _rw_task_status(status) == Reseau.TaskStatus.RUN_READY
            handler.window = Reseau.add_size_saturating(handler.window, update)
            Sockets.pipeline_increment_read_window!(ps, update)
        end
        nothing
    end), "increment_read_window_task")
    Sockets.pipeline_schedule_task_now!(ps, task)
    return nothing
end

rw_handler_shutdown_called(handler::ReadWriteTestHandler) = handler.shutdown_called

rw_handler_increment_read_window_called(handler::ReadWriteTestHandler) = handler.increment_read_window_called

rw_handler_last_error_code(handler::ReadWriteTestHandler) = handler.shutdown_error
