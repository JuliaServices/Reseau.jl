using Test
using Reseau

mutable struct TestingChannelHandler{SlotRef <: Union{Reseau.ChannelSlot, Nothing}} <: Reseau.AbstractChannelHandler
    slot::SlotRef
    messages::Vector{Reseau.IoMessage}
    latest_window_update::Csize_t
    initial_window::Csize_t
    complete_write_immediately::Bool
    complete_write_error_code::Int
end

function TestingChannelHandler(initial_window::Integer)
    return TestingChannelHandler{Union{Reseau.ChannelSlot, Nothing}}(
        nothing,
        Reseau.IoMessage[],
        Csize_t(0),
        Csize_t(initial_window),
        true,
        Reseau.AWS_OP_SUCCESS,
    )
end

function Reseau.handler_process_read_message(
        handler::TestingChannelHandler,
        slot::Reseau.ChannelSlot,
        message::Reseau.IoMessage,
    )::Union{Nothing, Reseau.ErrorResult}
    _ = slot
    push!(handler.messages, message)
    return nothing
end

function Reseau.handler_process_write_message(
        handler::TestingChannelHandler,
        slot::Reseau.ChannelSlot,
        message::Reseau.IoMessage,
    )::Union{Nothing, Reseau.ErrorResult}
    push!(handler.messages, message)
    if handler.complete_write_immediately && message.on_completion !== nothing && slot.adj_left === nothing
        Base.invokelatest(message.on_completion, slot.channel, message, handler.complete_write_error_code, message.user_data)
        message.on_completion = nothing
    end
    return nothing
end

function Reseau.handler_increment_read_window(
        handler::TestingChannelHandler,
        slot::Reseau.ChannelSlot,
        size::Csize_t,
    )::Union{Nothing, Reseau.ErrorResult}
    _ = slot
    handler.latest_window_update = size
    return nothing
end

function Reseau.handler_shutdown(
        handler::TestingChannelHandler,
        slot::Reseau.ChannelSlot,
        direction::Reseau.ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Union{Nothing, Reseau.ErrorResult}
    _ = handler
    Reseau.channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    return nothing
end

function Reseau.handler_initial_window_size(handler::TestingChannelHandler)::Csize_t
    return handler.initial_window
end

function Reseau.handler_message_overhead(handler::TestingChannelHandler)::Csize_t
    _ = handler
    return Csize_t(0)
end

function Reseau.handler_destroy(handler::TestingChannelHandler)::Nothing
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

function _drain_channel_tasks(channel::Reseau.Channel; timeout_ns::Int = 2_000_000_000)
    done = Ref(false)
    task = Reseau.ChannelTask((_, arg, status) -> begin
        status == Reseau.TaskStatus.RUN_READY || return nothing
        arg[] = true
        return nothing
    end, done, "drain_channel_tasks")
    Reseau.channel_schedule_task_now!(channel, task)
    return _wait_until(() -> done[]; timeout_ns = timeout_ns)
end

function _wait_ready_channel(ch::Channel; timeout_ns::Int = 2_000_000_000)
    return _wait_until(() -> isready(ch); timeout_ns = timeout_ns)
end

function _setup_channel(; enable_read_back_pressure::Bool = false)
    opts = Reseau.EventLoopOptions()
    el = Reseau.event_loop_new(opts)
    el isa Reseau.ErrorResult && return el
    run_res = Reseau.event_loop_run!(el)
    run_res isa Reseau.ErrorResult && return run_res

    setup_ch = Channel{Int}(1)

    on_setup = (ch, err, _ud) -> begin
        put!(setup_ch, err)
        return nothing
    end

    channel_opts = Reseau.ChannelOptions(
        event_loop = el,
        on_setup_completed = on_setup,
        setup_user_data = nothing,
        enable_read_back_pressure = enable_read_back_pressure,
    )

    channel = Reseau.channel_new(channel_opts)
    channel isa Reseau.ErrorResult && return channel

    @test _wait_ready_channel(setup_ch)
    if isready(setup_ch)
        @test take!(setup_ch) == Reseau.AWS_OP_SUCCESS
    end

    return (el = el, channel = channel)
end

@testset "io_testing_channel" begin
    if Threads.nthreads(:interactive) <= 1
        @test true
    else
        Reseau.io_library_init()

        setup = _setup_channel(enable_read_back_pressure = true)
        if setup isa Reseau.ErrorResult
            @test false
        else
            el = setup.el
            channel = setup.channel

            left_slot = Reseau.channel_slot_new!(channel)
            left_handler = TestingChannelHandler(16 * 1024)
            @test Reseau.channel_slot_set_handler!(left_slot, left_handler) === nothing

            right_slot = Reseau.channel_slot_new!(channel)
            @test Reseau.channel_slot_insert_end!(channel, right_slot) === nothing
            right_handler = TestingChannelHandler(16 * 1024)
            @test Reseau.channel_slot_set_handler!(right_slot, right_handler) === nothing

            read_msg = Reseau.channel_acquire_message_from_pool(
                channel,
                Reseau.IoMessageType.APPLICATION_DATA,
                64,
            )
            @test read_msg !== nothing
            @test Reseau.channel_slot_send_message(left_slot, read_msg, Reseau.ChannelDirection.READ) === nothing
            @test length(right_handler.messages) == 1
            @test right_handler.messages[1] === read_msg

            write_msg = Reseau.channel_acquire_message_from_pool(
                channel,
                Reseau.IoMessageType.APPLICATION_DATA,
                64,
            )
            @test write_msg !== nothing
            @test Reseau.channel_slot_send_message(right_slot, write_msg, Reseau.ChannelDirection.WRITE) === nothing
            @test length(left_handler.messages) == 1
            @test left_handler.messages[1] === write_msg

            @test _drain_channel_tasks(channel)
            @test Reseau.channel_slot_increment_read_window!(right_slot, Csize_t(12345)) === nothing
            @test _wait_until(() -> left_handler.latest_window_update == Csize_t(12345))
            @test left_handler.latest_window_update == Csize_t(12345)

            Reseau.channel_destroy!(channel)
            Reseau.event_loop_destroy!(el)
        end
    end
end
