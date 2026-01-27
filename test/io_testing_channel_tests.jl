using Test
using AwsIO

mutable struct TestingChannelHandler{SlotRef <: Union{AwsIO.ChannelSlot, Nothing}} <: AwsIO.AbstractChannelHandler
    slot::SlotRef
    messages::Vector{AwsIO.IoMessage}
    latest_window_update::Csize_t
    initial_window::Csize_t
    complete_write_immediately::Bool
    complete_write_error_code::Int
end

function TestingChannelHandler(initial_window::Integer)
    return TestingChannelHandler{Union{AwsIO.ChannelSlot, Nothing}}(
        nothing,
        AwsIO.IoMessage[],
        Csize_t(0),
        Csize_t(initial_window),
        true,
        AwsIO.AWS_OP_SUCCESS,
    )
end

function AwsIO.handler_process_read_message(
        handler::TestingChannelHandler,
        slot::AwsIO.ChannelSlot,
        message::AwsIO.IoMessage,
    )::Union{Nothing, AwsIO.ErrorResult}
    _ = slot
    push!(handler.messages, message)
    return nothing
end

function AwsIO.handler_process_write_message(
        handler::TestingChannelHandler,
        slot::AwsIO.ChannelSlot,
        message::AwsIO.IoMessage,
    )::Union{Nothing, AwsIO.ErrorResult}
    push!(handler.messages, message)
    if handler.complete_write_immediately && message.on_completion !== nothing && slot.adj_right === nothing
        Base.invokelatest(message.on_completion, slot.channel, message, handler.complete_write_error_code, message.user_data)
        message.on_completion = nothing
    end
    return nothing
end

function AwsIO.handler_increment_read_window(
        handler::TestingChannelHandler,
        slot::AwsIO.ChannelSlot,
        size::Csize_t,
    )::Union{Nothing, AwsIO.ErrorResult}
    _ = slot
    handler.latest_window_update = size
    return nothing
end

function AwsIO.handler_shutdown(
        handler::TestingChannelHandler,
        slot::AwsIO.ChannelSlot,
        direction::AwsIO.ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Union{Nothing, AwsIO.ErrorResult}
    _ = handler
    AwsIO.channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    return nothing
end

function AwsIO.handler_initial_window_size(handler::TestingChannelHandler)::Csize_t
    return handler.initial_window
end

function AwsIO.handler_message_overhead(handler::TestingChannelHandler)::Csize_t
    _ = handler
    return Csize_t(0)
end

function AwsIO.handler_destroy(handler::TestingChannelHandler)::Nothing
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

function _wait_ready_channel(ch::Channel; timeout_ns::Int = 2_000_000_000)
    return _wait_until(() -> isready(ch); timeout_ns = timeout_ns)
end

function _setup_channel(; enable_read_back_pressure::Bool = false)
    opts = AwsIO.EventLoopOptions()
    el = AwsIO.event_loop_new(opts)
    el isa AwsIO.ErrorResult && return el
    run_res = AwsIO.event_loop_run!(el)
    run_res isa AwsIO.ErrorResult && return run_res

    setup_ch = Channel{Int}(1)

    on_setup = (ch, err, _ud) -> begin
        put!(setup_ch, err)
        return nothing
    end

    channel_opts = AwsIO.ChannelOptions(
        event_loop = el,
        on_setup_completed = on_setup,
        setup_user_data = nothing,
        enable_read_back_pressure = enable_read_back_pressure,
    )

    channel = AwsIO.channel_new(channel_opts)
    channel isa AwsIO.ErrorResult && return channel

    @test _wait_ready_channel(setup_ch)
    if isready(setup_ch)
        @test take!(setup_ch) == AwsIO.AWS_OP_SUCCESS
    end

    return (el = el, channel = channel)
end

@testset "io_testing_channel" begin
    if Sys.iswindows() || Threads.nthreads(:interactive) <= 1
        @test true
    else
        AwsIO.io_library_init()

        setup = _setup_channel(enable_read_back_pressure = true)
        if setup isa AwsIO.ErrorResult
            @test false
        else
            el = setup.el
            channel = setup.channel

            app_slot = AwsIO.channel_slot_new!(channel)
            app_handler = TestingChannelHandler(16 * 1024)
            @test AwsIO.channel_slot_set_handler!(app_slot, app_handler) === nothing

            socket_slot = AwsIO.channel_slot_new!(channel)
            @test AwsIO.channel_slot_insert_end!(channel, socket_slot) === nothing
            socket_handler = TestingChannelHandler(16 * 1024)
            @test AwsIO.channel_slot_set_handler!(socket_slot, socket_handler) === nothing

            read_msg = AwsIO.channel_acquire_message_from_pool(
                channel,
                AwsIO.IoMessageType.APPLICATION_DATA,
                64,
            )
            @test read_msg !== nothing
            @test AwsIO.channel_slot_send_message(socket_slot, read_msg, AwsIO.ChannelDirection.READ) === nothing
            @test length(app_handler.messages) == 1
            @test app_handler.messages[1] === read_msg

            write_msg = AwsIO.channel_acquire_message_from_pool(
                channel,
                AwsIO.IoMessageType.APPLICATION_DATA,
                64,
            )
            @test write_msg !== nothing
            @test AwsIO.channel_slot_send_message(app_slot, write_msg, AwsIO.ChannelDirection.WRITE) === nothing
            @test length(socket_handler.messages) == 1
            @test socket_handler.messages[1] === write_msg

            @test AwsIO.channel_slot_increment_read_window!(app_slot, Csize_t(12345)) === nothing
            @test _wait_until(() -> socket_handler.latest_window_update == Csize_t(12345))
            @test socket_handler.latest_window_update == Csize_t(12345)

            AwsIO.channel_destroy!(channel)
            AwsIO.event_loop_destroy!(el)
        end
    end
end
