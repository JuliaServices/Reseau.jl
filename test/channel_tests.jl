using Test
using Reseau

function _wait_ready_channel(ch::Channel; timeout_ns::Int = 2_000_000_000)
    deadline = Base.time_ns() + timeout_ns
    while !isready(ch) && Base.time_ns() < deadline
        yield()
    end
    return isready(ch)
end

function _wait_for_pred(pred::Function; timeout_ns::Int = 2_000_000_000)
    deadline = Base.time_ns() + timeout_ns
    while Base.time_ns() < deadline
        pred() && return true
        yield()
    end
    return pred()
end

mutable struct TestDelayedDestroyHandler
    slot::Union{Sockets.ChannelSlot, Nothing}
    destroy_entered::Channel{Bool}
    release_destroy::Channel{Bool}
end

function Sockets.handler_process_read_message(
        ::TestDelayedDestroyHandler,
        ::Sockets.ChannelSlot,
        _message,
    )::Nothing
    return nothing
end

function Sockets.handler_process_write_message(
        ::TestDelayedDestroyHandler,
        ::Sockets.ChannelSlot,
        _message::Sockets.IoMessage,
    )::Nothing
    return nothing
end

function Sockets.handler_increment_read_window(
        ::TestDelayedDestroyHandler,
        ::Sockets.ChannelSlot,
        ::Csize_t,
    )::Nothing
    return nothing
end

function Sockets.handler_shutdown(
        ::TestDelayedDestroyHandler,
        slot::Sockets.ChannelSlot,
        direction::Sockets.ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Nothing
    Sockets.channel_slot_on_handler_shutdown_complete!(
        slot,
        direction,
        error_code,
        free_scarce_resources_immediately,
    )
    return nothing
end

Sockets.handler_initial_window_size(::TestDelayedDestroyHandler)::Csize_t = typemax(Csize_t)
Sockets.handler_message_overhead(::TestDelayedDestroyHandler)::Csize_t = Csize_t(0)

function Sockets.handler_destroy(handler::TestDelayedDestroyHandler)::Nothing
    put!(handler.destroy_entered, true)
    take!(handler.release_destroy)
    return nothing
end

function Sockets.setchannelslot!(handler::TestDelayedDestroyHandler, slot::Sockets.ChannelSlot)::Nothing
    handler.slot = slot
    return nothing
end

function _setup_channel(; with_shutdown_cb::Bool = false)
    el = EventLoops.EventLoop()
    EventLoops.run!(el)

    setup_ch = Channel{Int}(1)
    shutdown_ch = Channel{Int}(1)

    on_setup = Reseau.ChannelCallable((err, _channel) -> begin
        put!(setup_ch, err)
        return nothing
    end)
    on_shutdown = with_shutdown_cb ? (
            Reseau.EventCallable(err -> begin
                put!(shutdown_ch, err)
                return nothing
            end)
        ) : nothing

    channel = Sockets.Channel(
        el,
        nothing;
        on_setup_completed = on_setup,
        on_shutdown_completed = on_shutdown,
        auto_setup = true,
    )

    @test _wait_ready_channel(setup_ch)
    if isready(setup_ch)
        @test take!(setup_ch) == Reseau.OP_SUCCESS
    end

    return (el = el, channel = channel, shutdown_ch = shutdown_ch)
end

@testset "channel" begin
    if Threads.nthreads(:interactive) <= 1
        @test true
    else
        Sockets.io_library_init()

        @testset "slots cleanup" begin
            setup = _setup_channel()
            el = setup.el
            channel = setup.channel

            slot_1 = Sockets.channel_slot_new!(channel)
            slot_2 = Sockets.channel_slot_new!(channel)
            slot_3 = Sockets.channel_slot_new!(channel)
            slot_4 = Sockets.channel_slot_new!(channel)
            slot_5 = Sockets.channel_slot_new!(channel)

            Sockets.channel_slot_insert_right!(slot_1, slot_2)
            Sockets.channel_slot_insert_right!(slot_2, slot_3)
            Sockets.channel_slot_insert_left!(slot_3, slot_4)
            Sockets.channel_slot_remove!(slot_2)

            @test slot_1.adj_left === nothing
            @test slot_1.adj_right === slot_4
            @test slot_4.adj_left === slot_1
            @test slot_4.adj_right === slot_3
            @test slot_3.adj_left === slot_4
            @test slot_3.adj_right === nothing

            Sockets.channel_slot_replace!(slot_4, slot_5)
            @test slot_1.adj_right === slot_5
            @test slot_5.adj_left === slot_1
            @test slot_5.adj_right === slot_3
            @test slot_3.adj_left === slot_5

            Sockets.channel_destroy!(channel)
            close(el)
        end

        @testset "channel delayed destroy cleanup completes once handler is released" begin
            setup = _setup_channel(with_shutdown_cb = true)
            el = setup.el
            channel = setup.channel
            shutdown_ch = setup.shutdown_ch

            destroy_entered = Channel{Bool}(1)
            release_destroy = Channel{Bool}(1)
            handler = TestDelayedDestroyHandler(nothing, destroy_entered, release_destroy)

            slot = Sockets.channel_slot_new!(channel)
            Sockets.channel_slot_set_handler!(slot, handler)

            Sockets.channel_shutdown!(channel, Reseau.OP_SUCCESS)
            @test _wait_ready_channel(shutdown_ch)

            Sockets.channel_destroy!(channel)
            @test _wait_ready_channel(destroy_entered)
            @test channel.first !== nothing

            put!(release_destroy, true)
            @test _wait_for_pred(() -> channel.first === nothing)

            close(el)
        end

        @testset "channel keeps event loop alive until shutdown" begin
            elg = EventLoops.EventLoopGroup(; loop_count = 1)
            loop = elg.event_loops[1]

            setup_ch = Channel{Int}(1)
            shutdown_ch = Channel{Int}(1)
            channel = Sockets.Channel(
                loop,
                nothing;
                on_setup_completed = Reseau.ChannelCallable((err, _channel) -> begin
                    put!(setup_ch, err)
                    return nothing
                end),
                on_shutdown_completed = Reseau.EventCallable(err -> begin
                    put!(shutdown_ch, err)
                    return nothing
                end),
                auto_setup = true,
            )

            @test _wait_ready_channel(setup_ch)
            @test take!(setup_ch) == Reseau.OP_SUCCESS

            close_started = Threads.Atomic{Bool}(false)
            close_finished = Threads.Atomic{Bool}(false)
            close_task = errormonitor(Threads.@spawn begin
                close_started[] = true
                close(elg)
                close_finished[] = true
                return nothing
            end)

            @test _wait_for_pred(() -> close_started[]; timeout_ns = 1_000_000_000)
            sleep(0.05)
            @test !close_finished[]

            Sockets.channel_shutdown!(channel, Reseau.OP_SUCCESS)
            @test _wait_ready_channel(shutdown_ch)
            @test _wait_for_pred(() -> close_finished[]; timeout_ns = 3_000_000_000)

            wait(close_task)
        end

        @testset "destroy before setup completes waits for setup" begin
            el = EventLoops.EventLoop()

            setup_ch = Channel{Int}(1)
            on_setup = Reseau.ChannelCallable((err, _channel) -> begin
                put!(setup_ch, err)
                return nothing
            end)

            channel = Sockets.Channel(
                el,
                nothing;
                on_setup_completed = on_setup,
                on_shutdown_completed = nothing,
                auto_setup = true,
                wait_for_setup = false,
            )

            Sockets.channel_destroy!(channel)
            @test EventLoops.run!(el) === nothing

            @test _wait_ready_channel(setup_ch)
            if isready(setup_ch)
                @test take!(setup_ch) == Reseau.OP_SUCCESS
            end

            deadline = Base.time_ns() + 1_000_000_000
            while channel.channel_state != Sockets.ChannelState.SHUT_DOWN && Base.time_ns() < deadline
                yield()
            end
            @test channel.channel_state == Sockets.ChannelState.SHUT_DOWN

            close(el)
        end

        @testset "setup callback exception does not stall channel setup" begin
            el = EventLoops.EventLoop()

            callback_invocations = Threads.Atomic{Int}(0)
            on_setup = Reseau.ChannelCallable((err, _channel) -> begin
                _ = err
                Threads.atomic_add!(callback_invocations, 1)
                error("setup callback boom")
            end)

            channel = Sockets.Channel(
                el,
                nothing;
                on_setup_completed = on_setup,
                on_shutdown_completed = nothing,
                auto_setup = true,
                wait_for_setup = false,
            )

            @test EventLoops.run!(el) === nothing

            deadline = Base.time_ns() + 1_000_000_000
            while channel.channel_state != Sockets.ChannelState.SHUT_DOWN && Base.time_ns() < deadline
                yield()
            end

            @test channel.channel_state == Sockets.ChannelState.SHUT_DOWN
            @test callback_invocations[] >= 1

            close(el)
        end

        @testset "channel tasks run" begin
            setup = _setup_channel()
            el = setup.el
            channel = setup.channel

            task_count = 4
            status_ch = Channel{Tuple{Int, Reseau.TaskStatus.T}}(task_count)

            tasks = [Sockets.ChannelTask() for _ in 1:task_count]
            for i in 1:task_count
                Sockets.channel_task_init!(tasks[i], Reseau.EventCallable(status -> begin
                    put!(status_ch, (i, Reseau.TaskStatus.T(status)))
                    nothing
                end), "test_channel_task")
            end

            Sockets.channel_schedule_task_now!(channel, tasks[1])
            Sockets.channel_schedule_task_future!(channel, tasks[2], UInt64(1))

            scheduler_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return nothing
                Sockets.channel_schedule_task_now!(channel, tasks[3])
                Sockets.channel_schedule_task_future!(channel, tasks[4], UInt64(1))
                return nothing
            end); type_tag = "schedule_on_thread")
            EventLoops.schedule_task_now!(el, scheduler_task)

            deadline = Base.time_ns() + 2_000_000_000
            results = Dict{Int, Reseau.TaskStatus.T}()
            while length(results) < task_count && Base.time_ns() < deadline
                if isready(status_ch)
                    id, status = take!(status_ch)
                    results[id] = status
                else
                    yield()
                end
            end

            @test length(results) == task_count
            for status in values(results)
                @test status == Reseau.TaskStatus.RUN_READY
            end

            Sockets.channel_destroy!(channel)
            close(el)
        end

        @testset "channel tasks run cross-thread" begin
            setup = _setup_channel()
            el = setup.el
            channel = setup.channel

            task_count = 4
            status_ch = Channel{Tuple{Int, Reseau.TaskStatus.T}}(task_count)

            tasks = [Sockets.ChannelTask() for _ in 1:task_count]
            for i in 1:task_count
                Sockets.channel_task_init!(tasks[i], Reseau.EventCallable(status -> begin
                    put!(status_ch, (i, Reseau.TaskStatus.T(status)))
                    nothing
                end), "test_channel_task_cross_thread")
            end

            t1 = errormonitor(Threads.@spawn begin
                Sockets.channel_schedule_task_now!(channel, tasks[1])
                Sockets.channel_schedule_task_future!(channel, tasks[2], UInt64(1))
            end)
            t2 = errormonitor(Threads.@spawn begin
                Sockets.channel_schedule_task_now!(channel, tasks[3])
                Sockets.channel_schedule_task_future!(channel, tasks[4], UInt64(1))
            end)
            wait(t1)
            wait(t2)

            deadline = Base.time_ns() + 2_000_000_000
            results = Dict{Int, Reseau.TaskStatus.T}()
            while length(results) < task_count && Base.time_ns() < deadline
                if isready(status_ch)
                    id, status = take!(status_ch)
                    results[id] = status
                else
                    yield()
                end
            end

            @test length(results) == task_count
            for status in values(results)
                @test status == Reseau.TaskStatus.RUN_READY
            end

            Sockets.channel_destroy!(channel)
            close(el)
        end

        @testset "channel tasks serialized run" begin
            setup = _setup_channel()
            el = setup.el
            channel = setup.channel

            task_count = 4
            status_ch = Channel{Tuple{Int, Reseau.TaskStatus.T}}(task_count)

            tasks = [Sockets.ChannelTask() for _ in 1:task_count]
            for i in 1:task_count
                Sockets.channel_task_init!(tasks[i], Reseau.EventCallable(status -> begin
                    put!(status_ch, (i, Reseau.TaskStatus.T(status)))
                    nothing
                end), "test_channel_task_serialized")
            end

            Sockets.channel_schedule_task_now_serialized!(channel, tasks[1])
            Sockets.channel_schedule_task_future!(channel, tasks[2], UInt64(1))

            scheduler_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return nothing
                Sockets.channel_schedule_task_now_serialized!(channel, tasks[3])
                Sockets.channel_schedule_task_future!(channel, tasks[4], UInt64(1))
                return nothing
            end); type_tag = "schedule_on_thread_serialized")
            EventLoops.schedule_task_now!(el, scheduler_task)

            deadline = Base.time_ns() + 2_000_000_000
            results = Dict{Int, Reseau.TaskStatus.T}()
            while length(results) < task_count && Base.time_ns() < deadline
                if isready(status_ch)
                    id, status = take!(status_ch)
                    results[id] = status
                else
                    yield()
                end
            end

            @test length(results) == task_count
            for status in values(results)
                @test status == Reseau.TaskStatus.RUN_READY
            end

            Sockets.channel_destroy!(channel)
            close(el)
        end

        @testset "channel serialized tasks queued via cross-thread list" begin
            setup = _setup_channel()
            el = setup.el
            channel = setup.channel

            status_ch = Channel{Reseau.TaskStatus.T}(1)
            task = Sockets.ChannelTask()
            Sockets.channel_task_init!(
                task,
                Reseau.EventCallable(status -> begin
                    put!(status_ch, Reseau.TaskStatus.T(status))
                    nothing
                end),
                "test_channel_task_serialized_queue",
            )

            ready_ch = Channel{Bool}(1)
            block_ch = Channel{Bool}(1)
            released = Ref(false)

            blocker = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return nothing
                Sockets.channel_schedule_task_now_serialized!(channel, task)
                put!(ready_ch, true)
                take!(block_ch)
                return nothing
            end); type_tag = "block_serialized_queue")

            try
                EventLoops.schedule_task_now!(el, blocker)
                @test take!(ready_ch)

                queued = false
                lock(channel.cross_thread_tasks_lock) do
                    queued = !isempty(channel.cross_thread_tasks)
                end
                @test queued

                put!(block_ch, true)
                released[] = true

                deadline = Base.time_ns() + 2_000_000_000
                got_status = false
                while !got_status && Base.time_ns() < deadline
                    if isready(status_ch)
                        status = take!(status_ch)
                        @test status == Reseau.TaskStatus.RUN_READY
                        got_status = true
                    else
                        yield()
                    end
                end
                @test got_status
            finally
                if !released[]
                    try
                        put!(block_ch, true)
                    catch
                    end
                end
                Sockets.channel_destroy!(channel)
                close(el)
            end
        end

        @testset "post shutdown tasks canceled" begin
            setup = _setup_channel(with_shutdown_cb = true)
            el = setup.el
            channel = setup.channel
            shutdown_ch = setup.shutdown_ch

            Sockets.channel_shutdown!(channel, Reseau.OP_SUCCESS)
            @test _wait_ready_channel(shutdown_ch)

            task_status = Ref{Reseau.TaskStatus.T}(Reseau.TaskStatus.RUN_READY)
            task = Sockets.ChannelTask()
            Sockets.channel_task_init!(task, Reseau.EventCallable(status -> begin
                task_status[] = Reseau.TaskStatus.T(status)
                nothing
            end), "post_shutdown")
            Sockets.channel_schedule_task_now!(channel, task)
            @test task_status[] == Reseau.TaskStatus.CANCELED

            Sockets.channel_destroy!(channel)
            close(el)
        end

        @testset "pending tasks canceled on shutdown" begin
            setup = _setup_channel(with_shutdown_cb = true)
            el = setup.el
            channel = setup.channel
            shutdown_ch = setup.shutdown_ch

            task_status = Ref{Int}(100)
            task = Sockets.ChannelTask()
            Sockets.channel_task_init!(task, Reseau.EventCallable(status -> begin
                task_status[] = status
                nothing
            end), "future_task")
            Sockets.channel_schedule_task_future!(channel, task, typemax(UInt64) - 1)
            @test task_status[] == 100

            Sockets.channel_shutdown!(channel, Reseau.OP_SUCCESS)
            @test _wait_ready_channel(shutdown_ch)

            deadline = Base.time_ns() + 2_000_000_000
            while task_status[] == 100 && Base.time_ns() < deadline
                yield()
            end
            @test task_status[] == Int(Reseau.TaskStatus.CANCELED)

            Sockets.channel_destroy!(channel)
            close(el)
        end

        @testset "duplicate shutdown" begin
            setup = _setup_channel(with_shutdown_cb = true)
            el = setup.el
            channel = setup.channel
            shutdown_ch = setup.shutdown_ch

            Sockets.channel_shutdown!(channel, Reseau.OP_SUCCESS)
            @test _wait_ready_channel(shutdown_ch)

            Sockets.channel_shutdown!(channel, Reseau.OP_SUCCESS)

            Sockets.channel_destroy!(channel)
            close(el)
        end

        @testset "concurrent shutdown schedules once" begin
            setup = _setup_channel(with_shutdown_cb = true)
            el = setup.el
            channel = setup.channel
            shutdown_ch = setup.shutdown_ch

            ready = Threads.Atomic{Int}(0)
            go = Threads.Atomic{Bool}(false)

            t1 = errormonitor(Threads.@spawn begin
                Threads.atomic_add!(ready, 1)
                while !go[]
                    yield()
                end
                Sockets.channel_shutdown!(channel, Reseau.OP_SUCCESS)
                return nothing
            end)
            t2 = errormonitor(Threads.@spawn begin
                Threads.atomic_add!(ready, 1)
                while !go[]
                    yield()
                end
                Sockets.channel_shutdown!(channel, Reseau.ERROR_INVALID_STATE)
                return nothing
            end)

            deadline = Base.time_ns() + 1_000_000_000
            while ready[] < 2 && Base.time_ns() < deadline
                yield()
            end
            @test ready[] == 2
            go[] = true
            wait(t1)
            wait(t2)

            @test _wait_ready_channel(shutdown_ch)
            err = take!(shutdown_ch)
            @test err == Reseau.OP_SUCCESS || err == Reseau.ERROR_INVALID_STATE

            extra_deadline = Base.time_ns() + 500_000_000
            while Base.time_ns() < extra_deadline && !isready(shutdown_ch)
                yield()
            end
            @test !isready(shutdown_ch)

            Sockets.channel_destroy!(channel)
            close(el)
        end
    end
end
