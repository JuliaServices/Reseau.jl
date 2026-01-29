using AwsIO

mutable struct ReadWriteTestHandler{FRead, FWrite, SlotRef <: Union{AwsIO.ChannelSlot, Nothing}} <: AwsIO.AbstractChannelHandler
    slot::SlotRef
    on_read::FRead
    on_write::FWrite
    event_loop_driven::Bool
    window::Csize_t
    lock::ReentrantLock
    condition::Threads.Condition
    shutdown_called::Bool
    shutdown_error::Int
    increment_read_window_called::Bool
    destroy_called::Union{Base.RefValue{Bool}, Nothing}
    destroy_condition::Union{Threads.Condition, Nothing}
    ctx::Any
end

function ReadWriteTestHandler(
        on_read,
        on_write;
        event_loop_driven::Bool = true,
        window::Integer = 0,
        ctx = nothing,
    )
    return ReadWriteTestHandler{typeof(on_read), typeof(on_write), Union{AwsIO.ChannelSlot, Nothing}}(
        nothing,
        on_read,
        on_write,
        event_loop_driven,
        Csize_t(window),
        ReentrantLock(),
        Threads.Condition(),
        false,
        AwsIO.AWS_OP_SUCCESS,
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

function rw_handler_enable_wait_on_destroy(
        handler::ReadWriteTestHandler,
        destroy_called::Base.RefValue{Bool},
        condition_variable::Threads.Condition,
    )
    handler.destroy_called = destroy_called
    handler.destroy_condition = condition_variable
    return nothing
end

function AwsIO.handler_process_read_message(
        handler::ReadWriteTestHandler,
        slot::AwsIO.ChannelSlot,
        message::AwsIO.IoMessage,
    )::Union{Nothing, AwsIO.ErrorResult}
    next_data = handler.on_read(handler, slot, message.message_data, handler.ctx)

    if slot.channel !== nothing
        AwsIO.channel_release_message_to_pool!(slot.channel, message)
    end

    if slot.adj_right !== nothing && next_data !== nothing
        msg = AwsIO.channel_acquire_message_from_pool(
            slot.channel,
            AwsIO.IoMessageType.APPLICATION_DATA,
            Int(next_data.len),
        )
        if msg === nothing
            return AwsIO.ErrorResult(AwsIO.ERROR_OOM)
        end
        msg_ref = Ref(msg.message_data)
        AwsIO.byte_buf_write_from_whole_buffer(msg_ref, next_data)
        msg.message_data = msg_ref[]
        return AwsIO.channel_slot_send_message(slot, msg, AwsIO.ChannelDirection.READ)
    end

    return nothing
end

function AwsIO.handler_process_write_message(
        handler::ReadWriteTestHandler,
        slot::AwsIO.ChannelSlot,
        message::AwsIO.IoMessage,
    )::Union{Nothing, AwsIO.ErrorResult}
    next_data = handler.on_write(handler, slot, message.message_data, handler.ctx)

    if slot.channel !== nothing
        AwsIO.channel_release_message_to_pool!(slot.channel, message)
    end

    if slot.adj_left !== nothing && next_data !== nothing
        msg = AwsIO.channel_acquire_message_from_pool(
            slot.channel,
            AwsIO.IoMessageType.APPLICATION_DATA,
            Int(next_data.len),
        )
        if msg === nothing
            return AwsIO.ErrorResult(AwsIO.ERROR_OOM)
        end
        msg_ref = Ref(msg.message_data)
        AwsIO.byte_buf_write_from_whole_buffer(msg_ref, next_data)
        msg.message_data = msg_ref[]
        return AwsIO.channel_slot_send_message(slot, msg, AwsIO.ChannelDirection.WRITE)
    end

    return nothing
end

function AwsIO.handler_increment_read_window(
        handler::ReadWriteTestHandler,
        slot::AwsIO.ChannelSlot,
        size::Csize_t,
    )::Union{Nothing, AwsIO.ErrorResult}
    handler.increment_read_window_called = true
    handler.window = AwsIO.add_size_saturating(handler.window, size)
    return AwsIO.channel_slot_increment_read_window!(slot, size)
end

function AwsIO.handler_shutdown(
        handler::ReadWriteTestHandler,
        slot::AwsIO.ChannelSlot,
        direction::AwsIO.ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Union{Nothing, AwsIO.ErrorResult}
    lock(handler.lock) do
        handler.shutdown_called = true
        handler.shutdown_error = error_code
    end
    lock(handler.condition) do
        notify(handler.condition)
    end
    AwsIO.channel_slot_on_handler_shutdown_complete!(
        slot,
        direction,
        error_code,
        free_scarce_resources_immediately,
    )
    return nothing
end

function AwsIO.handler_initial_window_size(handler::ReadWriteTestHandler)::Csize_t
    return handler.window
end

function AwsIO.handler_message_overhead(handler::ReadWriteTestHandler)::Csize_t
    _ = handler
    return Csize_t(0)
end

function AwsIO.handler_destroy(handler::ReadWriteTestHandler)::Nothing
    if handler.destroy_called !== nothing && handler.destroy_condition !== nothing
        handler.destroy_called[] = true
        lock(handler.destroy_condition) do
            notify(handler.destroy_condition)
        end
    end
    return nothing
end

mutable struct RwWriteTaskArgs
    handler::ReadWriteTestHandler
    slot::AwsIO.ChannelSlot
    buffer::AwsIO.ByteBuffer
    on_completion::Any
    user_data::Any
end

function _rw_handler_write_now(
        slot::AwsIO.ChannelSlot,
        buffer::AwsIO.ByteBuffer,
        on_completion,
        user_data,
    )
    remaining = Int(buffer.len)
    cursor_ref = Ref(AwsIO.byte_cursor_from_buf(buffer))
    while remaining > 0
        msg = AwsIO.channel_acquire_message_from_pool(
            slot.channel,
            AwsIO.IoMessageType.APPLICATION_DATA,
            remaining,
        )
        msg === nothing && return AwsIO.ErrorResult(AwsIO.ERROR_OOM)

        chunk_size = min(remaining, Int(AwsIO.capacity(msg.message_data) - msg.message_data.len))
        msg.on_completion = on_completion
        msg.user_data = user_data

        chunk_cursor = AwsIO.byte_cursor_advance(cursor_ref, chunk_size)
        msg_ref = Ref(msg.message_data)
        AwsIO.byte_buf_write_from_whole_cursor(msg_ref, chunk_cursor)
        msg.message_data = msg_ref[]

        send_res = AwsIO.channel_slot_send_message(slot, msg, AwsIO.ChannelDirection.WRITE)
        send_res isa AwsIO.ErrorResult && return send_res
        remaining -= chunk_size
    end
    return nothing
end

function _rw_handler_write_task(task::AwsIO.ChannelTask, args::RwWriteTaskArgs, status::AwsIO.TaskStatus.T)
    _ = task
    if status != AwsIO.TaskStatus.RUN_READY
        return nothing
    end
    _rw_handler_write_now(args.slot, args.buffer, args.on_completion, args.user_data)
    return nothing
end

function rw_handler_write(handler::ReadWriteTestHandler, slot::AwsIO.ChannelSlot, buffer::AwsIO.ByteBuffer)
    return rw_handler_write_with_callback(handler, slot, buffer, nothing, nothing)
end

function rw_handler_write_with_callback(
        handler::ReadWriteTestHandler,
        slot::AwsIO.ChannelSlot,
        buffer::AwsIO.ByteBuffer,
        on_completion,
        user_data,
    )
    if !handler.event_loop_driven || AwsIO.channel_thread_is_callers_thread(slot.channel)
        return _rw_handler_write_now(slot, buffer, on_completion, user_data)
    end

    args = RwWriteTaskArgs(handler, slot, buffer, on_completion, user_data)
    task = AwsIO.ChannelTask()
    AwsIO.channel_task_init!(task, _rw_handler_write_task, args, "rw_handler_write")
    AwsIO.channel_schedule_task_now!(slot.channel, task)
    return nothing
end

function rw_handler_trigger_read(handler::ReadWriteTestHandler, slot::AwsIO.ChannelSlot)
    next_data = handler.on_read(handler, slot, nothing, handler.ctx)
    next_data === nothing && return nothing
    msg = AwsIO.channel_acquire_message_from_pool(
        slot.channel,
        AwsIO.IoMessageType.APPLICATION_DATA,
        Int(next_data.len),
    )
    msg === nothing && return AwsIO.ErrorResult(AwsIO.ERROR_OOM)
    msg_ref = Ref(msg.message_data)
    AwsIO.byte_buf_write_from_whole_buffer(msg_ref, next_data)
    msg.message_data = msg_ref[]
    return AwsIO.channel_slot_send_message(slot, msg, AwsIO.ChannelDirection.READ)
end

mutable struct RwWindowTaskArgs
    handler::ReadWriteTestHandler
    slot::AwsIO.ChannelSlot
    window_update::Csize_t
end

function _rw_handler_window_update_task(task::AwsIO.ChannelTask, args::RwWindowTaskArgs, status::AwsIO.TaskStatus.T)
    _ = task
    status == AwsIO.TaskStatus.RUN_READY || return nothing
    args.handler.window = AwsIO.add_size_saturating(args.handler.window, args.window_update)
    AwsIO.channel_slot_increment_read_window!(args.slot, args.window_update)
    return nothing
end

function rw_handler_trigger_increment_read_window(
        handler::ReadWriteTestHandler,
        slot::AwsIO.ChannelSlot,
        window_update::Integer,
    )
    update = Csize_t(window_update)
    if !handler.event_loop_driven || AwsIO.channel_thread_is_callers_thread(slot.channel)
        handler.window = AwsIO.add_size_saturating(handler.window, update)
        return AwsIO.channel_slot_increment_read_window!(slot, update)
    end

    args = RwWindowTaskArgs(handler, slot, update)
    task = AwsIO.ChannelTask()
    AwsIO.channel_task_init!(task, _rw_handler_window_update_task, args, "increment_read_window_task")
    AwsIO.channel_schedule_task_now!(slot.channel, task)
    return nothing
end

rw_handler_shutdown_called(handler::ReadWriteTestHandler) = handler.shutdown_called

rw_handler_increment_read_window_called(handler::ReadWriteTestHandler) = handler.increment_read_window_called

rw_handler_last_error_code(handler::ReadWriteTestHandler) = handler.shutdown_error
