using Test
using Reseau

mutable struct TestingChannelHandler{SlotRef <: Union{Sockets.ChannelSlot, Nothing}}
    slot::SlotRef
    messages::Vector{EventLoops.IoMessage}
    latest_window_update::Csize_t
    initial_window::Csize_t
    complete_write_immediately::Bool
    complete_write_error_code::Int
end

function TestingChannelHandler(initial_window::Integer)
    return TestingChannelHandler{Union{Sockets.ChannelSlot, Nothing}}(
        nothing,
        EventLoops.IoMessage[],
        Csize_t(0),
        Csize_t(initial_window),
        true,
        Reseau.OP_SUCCESS,
    )
end

function Sockets.handler_process_read_message(
        handler::TestingChannelHandler,
        slot::Sockets.ChannelSlot,
        message::EventLoops.IoMessage,
    )
    _ = slot
    push!(handler.messages, message)
    return nothing
end

function Sockets.handler_process_write_message(
        handler::TestingChannelHandler,
        slot::Sockets.ChannelSlot,
        message::EventLoops.IoMessage,
    )
    push!(handler.messages, message)
    if handler.complete_write_immediately && message.on_completion !== nothing && slot.adj_left === nothing
        Base.invokelatest(message.on_completion, handler.complete_write_error_code)
        message.on_completion = nothing
    end
    return nothing
end

function Sockets.handler_increment_read_window(
        handler::TestingChannelHandler,
        slot::Sockets.ChannelSlot,
        size::Csize_t,
    )
    _ = slot
    handler.latest_window_update = size
    return nothing
end

function Sockets.handler_shutdown(
        handler::TestingChannelHandler,
        slot::Sockets.ChannelSlot,
        direction::Sockets.ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )
    _ = handler
    Sockets.channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    return nothing
end

function Sockets.handler_initial_window_size(handler::TestingChannelHandler)::Csize_t
    return handler.initial_window
end

function Sockets.handler_message_overhead(handler::TestingChannelHandler)::Csize_t
    _ = handler
    return Csize_t(0)
end

function Sockets.handler_destroy(handler::TestingChannelHandler)::Nothing
    empty!(handler.messages)
    return nothing
end

function _wait_until(pred; timeout_ns::Int = 2_000_000_000)
    deadline = Base.time_ns() + timeout_ns
    while Base.time_ns() < deadline
        pred() && return true
        yield()
    end
    return pred()
end

function _drain_channel_tasks(channel::Sockets.Channel; timeout_ns::Int = 2_000_000_000)
    done = Ref(false)
    task = Sockets.ChannelTask(Reseau.EventCallable(status -> begin
        Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return nothing
        done[] = true
        return nothing
    end), "drain_channel_tasks")
    Sockets.channel_schedule_task_now!(channel, task)
    return _wait_until(() -> done[]; timeout_ns = timeout_ns)
end

function _wait_ready_channel(ch::Channel; timeout_ns::Int = 2_000_000_000)
    return _wait_until(() -> isready(ch); timeout_ns = timeout_ns)
end

function _setup_channel(; enable_read_back_pressure::Bool = false)
    el = EventLoops.EventLoop()
    EventLoops.run!(el)

    setup_ch = Channel{Int}(1)

    on_setup = Reseau.ChannelCallable((err, _channel) -> begin
        put!(setup_ch, err)
        return nothing
    end)

    channel = Sockets.Channel(
        el,
        nothing;
        on_setup_completed = on_setup,
        enable_read_back_pressure = enable_read_back_pressure,
        auto_setup = true,
    )

    @test _wait_ready_channel(setup_ch)
    if isready(setup_ch)
        @test take!(setup_ch) == Reseau.OP_SUCCESS
    end

    return (el = el, channel = channel)
end

@testset "io_testing_channel" begin
    if Base.Threads.nthreads(:interactive) <= 1
        @test true
    else
        Sockets.io_library_init()

        setup = _setup_channel(enable_read_back_pressure = true)
        el = setup.el
        channel = setup.channel

        left_slot = Sockets.channel_slot_new!(channel)
        left_handler = TestingChannelHandler(16 * 1024)
        @test Sockets.channel_slot_set_handler!(left_slot, left_handler) === nothing

        right_slot = Sockets.channel_slot_new!(channel)
        @test Sockets.channel_slot_insert_end!(channel, right_slot) === nothing
        right_handler = TestingChannelHandler(16 * 1024)
        @test Sockets.channel_slot_set_handler!(right_slot, right_handler) === nothing

        read_msg = Sockets.channel_acquire_message_from_pool(
            channel,
            EventLoops.IoMessageType.APPLICATION_DATA,
            64,
        )
        @test read_msg !== nothing
        @test Sockets.channel_slot_send_message(left_slot, read_msg, Sockets.ChannelDirection.READ) === nothing
        @test length(right_handler.messages) == 1
        @test right_handler.messages[1] === read_msg

        write_msg = Sockets.channel_acquire_message_from_pool(
            channel,
            EventLoops.IoMessageType.APPLICATION_DATA,
            64,
        )
        @test write_msg !== nothing
        @test Sockets.channel_slot_send_message(right_slot, write_msg, Sockets.ChannelDirection.WRITE) === nothing
        @test length(left_handler.messages) == 1
        @test left_handler.messages[1] === write_msg

        @test _drain_channel_tasks(channel)
        @test Sockets.channel_slot_increment_read_window!(right_slot, Csize_t(12345)) === nothing
        @test _wait_until(() -> left_handler.latest_window_update == Csize_t(12345))
        @test left_handler.latest_window_update == Csize_t(12345)

        @test Sockets.channel_shutdown!(channel, Reseau.OP_SUCCESS) === nothing
        @test _wait_until(() -> channel.channel_state == Sockets.ChannelState.SHUT_DOWN)
        Sockets.channel_destroy!(channel)
        close(el)
    end
end
