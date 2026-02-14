using Test
using Reseau

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

@testset "io_testing_pipeline" begin
    if Base.Threads.nthreads(:interactive) <= 1
        @test true
    else
        Sockets.io_library_init()

        el = EventLoops.event_loop_new()
        EventLoops.event_loop_run!(el)

        setup_ch = Channel{Int}(1)
        on_setup = Reseau.EventCallable(err -> begin
            put!(setup_ch, err)
            return nothing
        end)

        ps = Sockets.pipeline_new(el; on_setup_completed = on_setup, enable_read_back_pressure = true)

        @test _wait_ready_channel(setup_ch)
        if isready(setup_ch)
            @test take!(setup_ch) == Reseau.AWS_OP_SUCCESS
        end

        # Test message pool operations
        msg = Sockets.pipeline_acquire_message_from_pool(ps, EventLoops.IoMessageType.APPLICATION_DATA, 64)
        @test msg !== nothing
        @test msg isa EventLoops.IoMessage

        # Release message back to pool
        Sockets.pipeline_release_message_to_pool!(ps, msg)

        # Test window update function
        window_updates = Csize_t[]
        ps.window_update_fn = size -> begin
            push!(window_updates, size)
            return nothing
        end

        Sockets.pipeline_increment_read_window!(ps, Csize_t(12345))
        # Window update is batched via a scheduled task, so wait for it
        @test _wait_until(() -> !isempty(window_updates))
        @test !isempty(window_updates)
        if !isempty(window_updates)
            @test sum(window_updates) >= Csize_t(12345)
        end

        Sockets.pipeline_destroy!(ps)
        EventLoops.event_loop_destroy!(el)
    end
end
