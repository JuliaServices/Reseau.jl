using Reseau

mutable struct ReadWriteTestHandler{FRead, FWrite, SlotRef <: Union{Reseau.ChannelSlot, Nothing}} <: Reseau.AbstractChannelHandler
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
    return ReadWriteTestHandler{typeof(on_read), typeof(on_write), Union{Reseau.ChannelSlot, Nothing}}(
        nothing,
        on_read,
        on_write,
        event_loop_driven,
        Csize_t(window),
        ReentrantLock(),
        Threads.Condition(),
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

function Reseau.setchannelslot!(handler::ReadWriteTestHandler, slot::Reseau.ChannelSlot)::Nothing
    handler.slot = slot
    return nothing
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

function Reseau.handler_process_read_message(
        handler::ReadWriteTestHandler,
        slot::Reseau.ChannelSlot,
        message::Reseau.IoMessage,
    )::Union{Nothing, Reseau.ErrorResult}
    next_data = handler.on_read(handler, slot, message.message_data, handler.ctx)

    if slot.channel !== nothing
        Reseau.channel_release_message_to_pool!(slot.channel, message)
    end

    if slot.adj_right !== nothing && next_data !== nothing
        msg = Reseau.channel_acquire_message_from_pool(
            slot.channel,
            Reseau.IoMessageType.APPLICATION_DATA,
            Int(next_data.len),
        )
        if msg === nothing
            return Reseau.ErrorResult(Reseau.ERROR_OOM)
        end
        msg_ref = Ref(msg.message_data)
        Reseau.byte_buf_write_from_whole_buffer(msg_ref, next_data)
        msg.message_data = msg_ref[]
        return Reseau.channel_slot_send_message(slot, msg, Reseau.ChannelDirection.READ)
    end

    return nothing
end

function Reseau.handler_process_write_message(
        handler::ReadWriteTestHandler,
        slot::Reseau.ChannelSlot,
        message::Reseau.IoMessage,
    )::Union{Nothing, Reseau.ErrorResult}
    next_data = handler.on_write(handler, slot, message.message_data, handler.ctx)

    if slot.channel !== nothing
        Reseau.channel_release_message_to_pool!(slot.channel, message)
    end

    if slot.adj_left !== nothing && next_data !== nothing
        msg = Reseau.channel_acquire_message_from_pool(
            slot.channel,
            Reseau.IoMessageType.APPLICATION_DATA,
            Int(next_data.len),
        )
        if msg === nothing
            return Reseau.ErrorResult(Reseau.ERROR_OOM)
        end
        msg_ref = Ref(msg.message_data)
        Reseau.byte_buf_write_from_whole_buffer(msg_ref, next_data)
        msg.message_data = msg_ref[]
        return Reseau.channel_slot_send_message(slot, msg, Reseau.ChannelDirection.WRITE)
    end

    return nothing
end

function Reseau.handler_increment_read_window(
        handler::ReadWriteTestHandler,
        slot::Reseau.ChannelSlot,
        size::Csize_t,
    )::Union{Nothing, Reseau.ErrorResult}
    handler.increment_read_window_called = true
    handler.window = Reseau.add_size_saturating(handler.window, size)
    return Reseau.channel_slot_increment_read_window!(slot, size)
end

function Reseau.handler_shutdown(
        handler::ReadWriteTestHandler,
        slot::Reseau.ChannelSlot,
        direction::Reseau.ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Union{Nothing, Reseau.ErrorResult}
    lock(handler.lock) do
        handler.shutdown_called = true
        handler.shutdown_error = error_code
    end
    lock(handler.condition) do
        notify(handler.condition)
    end
    Reseau.channel_slot_on_handler_shutdown_complete!(
        slot,
        direction,
        error_code,
        free_scarce_resources_immediately,
    )
    return nothing
end

function Reseau.handler_initial_window_size(handler::ReadWriteTestHandler)::Csize_t
    return handler.window
end

function Reseau.handler_message_overhead(handler::ReadWriteTestHandler)::Csize_t
    _ = handler
    return Csize_t(0)
end

function Reseau.handler_destroy(handler::ReadWriteTestHandler)::Nothing
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
    slot::Reseau.ChannelSlot
    buffer::Reseau.ByteBuffer
    on_completion::Any
    user_data::Any
end

function _rw_handler_write_now(
        slot::Reseau.ChannelSlot,
        buffer::Reseau.ByteBuffer,
        on_completion,
        user_data,
    )
    remaining = Int(buffer.len)
    cursor_ref = Ref(Reseau.byte_cursor_from_buf(buffer))
    while remaining > 0
        msg = Reseau.channel_acquire_message_from_pool(
            slot.channel,
            Reseau.IoMessageType.APPLICATION_DATA,
            remaining,
        )
        msg === nothing && return Reseau.ErrorResult(Reseau.ERROR_OOM)

        chunk_size = min(remaining, Int(Reseau.capacity(msg.message_data) - msg.message_data.len))
        msg.on_completion = on_completion
        msg.user_data = user_data

        chunk_cursor = Reseau.byte_cursor_advance(cursor_ref, chunk_size)
        msg_ref = Ref(msg.message_data)
        Reseau.byte_buf_write_from_whole_cursor(msg_ref, chunk_cursor)
        msg.message_data = msg_ref[]

        send_res = Reseau.channel_slot_send_message(slot, msg, Reseau.ChannelDirection.WRITE)
        send_res isa Reseau.ErrorResult && return send_res
        remaining -= chunk_size
    end
    return nothing
end

function _rw_handler_write_task(task::Reseau.ChannelTask, args::RwWriteTaskArgs, status::Reseau.TaskStatus.T)
    _ = task
    if status != Reseau.TaskStatus.RUN_READY
        return nothing
    end
    _rw_handler_write_now(args.slot, args.buffer, args.on_completion, args.user_data)
    return nothing
end

function rw_handler_write(handler::ReadWriteTestHandler, slot::Reseau.ChannelSlot, buffer::Reseau.ByteBuffer)
    return rw_handler_write_with_callback(handler, slot, buffer, nothing, nothing)
end

function rw_handler_write_with_callback(
        handler::ReadWriteTestHandler,
        slot::Reseau.ChannelSlot,
        buffer::Reseau.ByteBuffer,
        on_completion,
        user_data,
    )
    if !handler.event_loop_driven || Reseau.channel_thread_is_callers_thread(slot.channel)
        return _rw_handler_write_now(slot, buffer, on_completion, user_data)
    end

    args = RwWriteTaskArgs(handler, slot, buffer, on_completion, user_data)
    task = Reseau.ChannelTask()
    Reseau.channel_task_init!(task, _rw_handler_write_task, args, "rw_handler_write")
    Reseau.channel_schedule_task_now!(slot.channel, task)
    return nothing
end

function rw_handler_trigger_read(handler::ReadWriteTestHandler, slot::Reseau.ChannelSlot)
    next_data = handler.on_read(handler, slot, nothing, handler.ctx)
    next_data === nothing && return nothing
    msg = Reseau.channel_acquire_message_from_pool(
        slot.channel,
        Reseau.IoMessageType.APPLICATION_DATA,
        Int(next_data.len),
    )
    msg === nothing && return Reseau.ErrorResult(Reseau.ERROR_OOM)
    msg_ref = Ref(msg.message_data)
    Reseau.byte_buf_write_from_whole_buffer(msg_ref, next_data)
    msg.message_data = msg_ref[]
    return Reseau.channel_slot_send_message(slot, msg, Reseau.ChannelDirection.READ)
end

mutable struct RwWindowTaskArgs
    handler::ReadWriteTestHandler
    slot::Reseau.ChannelSlot
    window_update::Csize_t
end

function _rw_handler_window_update_task(task::Reseau.ChannelTask, args::RwWindowTaskArgs, status::Reseau.TaskStatus.T)
    _ = task
    status == Reseau.TaskStatus.RUN_READY || return nothing
    args.handler.window = Reseau.add_size_saturating(args.handler.window, args.window_update)
    Reseau.channel_slot_increment_read_window!(args.slot, args.window_update)
    return nothing
end

function rw_handler_trigger_increment_read_window(
        handler::ReadWriteTestHandler,
        slot::Reseau.ChannelSlot,
        window_update::Integer,
    )
    update = Csize_t(window_update)
    if !handler.event_loop_driven || Reseau.channel_thread_is_callers_thread(slot.channel)
        handler.window = Reseau.add_size_saturating(handler.window, update)
        return Reseau.channel_slot_increment_read_window!(slot, update)
    end

    args = RwWindowTaskArgs(handler, slot, update)
    task = Reseau.ChannelTask()
    Reseau.channel_task_init!(task, _rw_handler_window_update_task, args, "increment_read_window_task")
    Reseau.channel_schedule_task_now!(slot.channel, task)
    return nothing
end

rw_handler_shutdown_called(handler::ReadWriteTestHandler) = handler.shutdown_called

rw_handler_increment_read_window_called(handler::ReadWriteTestHandler) = handler.increment_read_window_called

rw_handler_last_error_code(handler::ReadWriteTestHandler) = handler.shutdown_error
