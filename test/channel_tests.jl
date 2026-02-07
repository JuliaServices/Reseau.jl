using Test
using Reseau

function _wait_ready_channel(ch::Channel; timeout_ns::Int = 2_000_000_000)
    deadline = Base.time_ns() + timeout_ns
    while !isready(ch) && Base.time_ns() < deadline
        yield()
    end
    return isready(ch)
end

function _setup_channel(; with_shutdown_cb::Bool = false)
    opts = Reseau.EventLoopOptions()
    el = Reseau.event_loop_new(opts)
    el isa Reseau.ErrorResult && return el
    run_res = Reseau.event_loop_run!(el)
    run_res isa Reseau.ErrorResult && return run_res

    setup_ch = Channel{Int}(1)
    shutdown_ch = Channel{Int}(1)

    on_setup = (ch, err, _ud) -> begin
        put!(setup_ch, err)
        return nothing
    end
    on_shutdown = with_shutdown_cb ? (
            (ch, err, _ud) -> begin
                put!(shutdown_ch, err)
                return nothing
            end
        ) : nothing

    channel_opts = Reseau.ChannelOptions(
        event_loop = el,
        on_setup_completed = on_setup,
        on_shutdown_completed = on_shutdown,
        setup_user_data = nothing,
        shutdown_user_data = nothing,
    )

    channel = Reseau.channel_new(channel_opts)
    channel isa Reseau.ErrorResult && return channel

    @test _wait_ready_channel(setup_ch)
    if isready(setup_ch)
        @test take!(setup_ch) == Reseau.AWS_OP_SUCCESS
    end

    return (el = el, channel = channel, shutdown_ch = shutdown_ch)
end

@testset "channel" begin
    if Threads.nthreads(:interactive) <= 1
        @test true
    else
        Reseau.io_library_init()

        @testset "slots cleanup" begin
            setup = _setup_channel()
            if setup isa Reseau.ErrorResult
                @test false
            else
                el = setup.el
                channel = setup.channel

                slot_1 = Reseau.channel_slot_new!(channel)
                slot_2 = Reseau.channel_slot_new!(channel)
                slot_3 = Reseau.channel_slot_new!(channel)
                slot_4 = Reseau.channel_slot_new!(channel)
                slot_5 = Reseau.channel_slot_new!(channel)

                Reseau.channel_slot_insert_right!(slot_1, slot_2)
                Reseau.channel_slot_insert_right!(slot_2, slot_3)
                Reseau.channel_slot_insert_left!(slot_3, slot_4)
                Reseau.channel_slot_remove!(slot_2)

                @test slot_1.adj_left === nothing
                @test slot_1.adj_right === slot_4
                @test slot_4.adj_left === slot_1
                @test slot_4.adj_right === slot_3
                @test slot_3.adj_left === slot_4
                @test slot_3.adj_right === nothing

                Reseau.channel_slot_replace!(slot_4, slot_5)
                @test slot_1.adj_right === slot_5
                @test slot_5.adj_left === slot_1
                @test slot_5.adj_right === slot_3
                @test slot_3.adj_left === slot_5

                Reseau.channel_destroy!(channel)
                Reseau.event_loop_destroy!(el)
            end
        end

        @testset "destroy before setup completes waits for setup" begin
            opts = Reseau.EventLoopOptions()
            el = Reseau.event_loop_new(opts)
            el_val = el isa Reseau.EventLoop ? el : nothing
            @test el_val !== nothing
            if el_val === nothing
                return
            end

            setup_ch = Channel{Int}(1)
            on_setup = (ch, err, _ud) -> begin
                put!(setup_ch, err)
                return nothing
            end

            channel_opts = Reseau.ChannelOptions(
                event_loop = el_val,
                on_setup_completed = on_setup,
                on_shutdown_completed = nothing,
                setup_user_data = nothing,
                shutdown_user_data = nothing,
            )

            channel = Reseau.channel_new(channel_opts)
            if channel isa Reseau.ErrorResult
                @test false
                Reseau.event_loop_destroy!(el_val)
                return
            end

            Reseau.channel_destroy!(channel)
            @test Reseau.event_loop_run!(el_val) === nothing

            @test _wait_ready_channel(setup_ch)
            if isready(setup_ch)
                @test take!(setup_ch) == Reseau.AWS_OP_SUCCESS
            end

            deadline = Base.time_ns() + 1_000_000_000
            while channel.channel_state != Reseau.ChannelState.SHUT_DOWN && Base.time_ns() < deadline
                yield()
            end
            @test channel.channel_state == Reseau.ChannelState.SHUT_DOWN

            Reseau.event_loop_destroy!(el_val)
        end

        @testset "channel tasks run" begin
            setup = _setup_channel()
            if setup isa Reseau.ErrorResult
                @test false
            else
                el = setup.el
                channel = setup.channel

                task_count = 4
                status_ch = Channel{Tuple{Int, Reseau.TaskStatus.T}}(task_count)

                task_fn = (task, arg, status) -> begin
                    put!(status_ch, (Int(arg), status))
                    return nothing
                end

                tasks = [Reseau.ChannelTask() for _ in 1:task_count]
                for i in 1:task_count
                    Reseau.channel_task_init!(tasks[i], task_fn, i, "test_channel_task")
                end

                Reseau.channel_schedule_task_now!(channel, tasks[1])
                Reseau.channel_schedule_task_future!(channel, tasks[2], UInt64(1))

                on_thread = (ctx, status) -> begin
                    status == Reseau.TaskStatus.RUN_READY || return nothing
                    Reseau.channel_schedule_task_now!(ctx.channel, ctx.tasks[3])
                    Reseau.channel_schedule_task_future!(ctx.channel, ctx.tasks[4], UInt64(1))
                    return nothing
                end
                scheduler_task = Reseau.ScheduledTask(on_thread, (channel = channel, tasks = tasks); type_tag = "schedule_on_thread")
                Reseau.event_loop_schedule_task_now!(el, scheduler_task)

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

                Reseau.channel_destroy!(channel)
                Reseau.event_loop_destroy!(el)
            end
        end

        @testset "channel tasks run cross-thread" begin
            setup = _setup_channel()
            if setup isa Reseau.ErrorResult
                @test false
            else
                el = setup.el
                channel = setup.channel

                task_count = 4
                status_ch = Channel{Tuple{Int, Reseau.TaskStatus.T}}(task_count)

                task_fn = (task, arg, status) -> begin
                    put!(status_ch, (Int(arg), status))
                    return nothing
                end

                tasks = [Reseau.ChannelTask() for _ in 1:task_count]
                for i in 1:task_count
                    Reseau.channel_task_init!(tasks[i], task_fn, i, "test_channel_task_cross_thread")
                end

                t1 = errormonitor(Threads.@spawn begin
                    Reseau.channel_schedule_task_now!(channel, tasks[1])
                    Reseau.channel_schedule_task_future!(channel, tasks[2], UInt64(1))
                end)
                t2 = errormonitor(Threads.@spawn begin
                    Reseau.channel_schedule_task_now!(channel, tasks[3])
                    Reseau.channel_schedule_task_future!(channel, tasks[4], UInt64(1))
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

                Reseau.channel_destroy!(channel)
                Reseau.event_loop_destroy!(el)
            end
        end

        @testset "channel tasks serialized run" begin
            setup = _setup_channel()
            if setup isa Reseau.ErrorResult
                @test false
            else
                el = setup.el
                channel = setup.channel

                task_count = 4
                status_ch = Channel{Tuple{Int, Reseau.TaskStatus.T}}(task_count)

                task_fn = (task, arg, status) -> begin
                    put!(status_ch, (Int(arg), status))
                    return nothing
                end

                tasks = [Reseau.ChannelTask() for _ in 1:task_count]
                for i in 1:task_count
                    Reseau.channel_task_init!(tasks[i], task_fn, i, "test_channel_task_serialized")
                end

                Reseau.channel_schedule_task_now_serialized!(channel, tasks[1])
                Reseau.channel_schedule_task_future!(channel, tasks[2], UInt64(1))

                on_thread = (ctx, status) -> begin
                    status == Reseau.TaskStatus.RUN_READY || return nothing
                    Reseau.channel_schedule_task_now_serialized!(ctx.channel, ctx.tasks[3])
                    Reseau.channel_schedule_task_future!(ctx.channel, ctx.tasks[4], UInt64(1))
                    return nothing
                end
                scheduler_task = Reseau.ScheduledTask(on_thread, (channel = channel, tasks = tasks); type_tag = "schedule_on_thread_serialized")
                Reseau.event_loop_schedule_task_now!(el, scheduler_task)

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

                Reseau.channel_destroy!(channel)
                Reseau.event_loop_destroy!(el)
            end
        end

        @testset "channel serialized tasks queued via cross-thread list" begin
            setup = _setup_channel()
            if setup isa Reseau.ErrorResult
                @test false
            else
                el = setup.el
                channel = setup.channel

                status_ch = Channel{Reseau.TaskStatus.T}(1)
                task = Reseau.ChannelTask()
                Reseau.channel_task_init!(
                    task,
                    (task, arg, status) -> begin
                        put!(status_ch, status)
                        return nothing
                    end,
                    nothing,
                    "test_channel_task_serialized_queue",
                )

                ready_ch = Channel{Bool}(1)
                block_ch = Channel{Bool}(1)
                released = Ref(false)

                blocker = Reseau.ScheduledTask(
                    (ctx, status) -> begin
                        status == Reseau.TaskStatus.RUN_READY || return nothing
                        Reseau.channel_schedule_task_now_serialized!(ctx.channel, ctx.task)
                        put!(ctx.ready_ch, true)
                        take!(ctx.block_ch)
                        return nothing
                    end,
                    (channel = channel, task = task, ready_ch = ready_ch, block_ch = block_ch);
                    type_tag = "block_serialized_queue",
                )

                try
                    Reseau.event_loop_schedule_task_now!(el, blocker)
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
                    Reseau.channel_destroy!(channel)
                    Reseau.event_loop_destroy!(el)
                end
            end
        end

        @testset "post shutdown tasks canceled" begin
            setup = _setup_channel(with_shutdown_cb = true)
            if setup isa Reseau.ErrorResult
                @test false
            else
                el = setup.el
                channel = setup.channel
                shutdown_ch = setup.shutdown_ch

                Reseau.channel_shutdown!(channel, Reseau.AWS_OP_SUCCESS)
                @test _wait_ready_channel(shutdown_ch)

                task_status = Ref{Reseau.TaskStatus.T}(Reseau.TaskStatus.RUN_READY)
                task_fn = (task, arg, status) -> begin
                    arg[] = status
                    return nothing
                end
                task = Reseau.ChannelTask()
                Reseau.channel_task_init!(task, task_fn, task_status, "post_shutdown")
                Reseau.channel_schedule_task_now!(channel, task)
                @test task_status[] == Reseau.TaskStatus.CANCELED

                Reseau.channel_destroy!(channel)
                Reseau.event_loop_destroy!(el)
            end
        end

        @testset "pending tasks canceled on shutdown" begin
            setup = _setup_channel(with_shutdown_cb = true)
            if setup isa Reseau.ErrorResult
                @test false
            else
                el = setup.el
                channel = setup.channel
                shutdown_ch = setup.shutdown_ch

                task_status = Ref{Int}(100)
                task_fn = (task, arg, status) -> begin
                    arg[] = Int(status)
                    return nothing
                end
                task = Reseau.ChannelTask()
                Reseau.channel_task_init!(task, task_fn, task_status, "future_task")
                Reseau.channel_schedule_task_future!(channel, task, typemax(UInt64) - 1)
                @test task_status[] == 100

                Reseau.channel_shutdown!(channel, Reseau.AWS_OP_SUCCESS)
                @test _wait_ready_channel(shutdown_ch)

                deadline = Base.time_ns() + 2_000_000_000
                while task_status[] == 100 && Base.time_ns() < deadline
                    yield()
                end
                @test task_status[] == Int(Reseau.TaskStatus.CANCELED)

                Reseau.channel_destroy!(channel)
                Reseau.event_loop_destroy!(el)
            end
        end

        @testset "duplicate shutdown" begin
            setup = _setup_channel(with_shutdown_cb = true)
            if setup isa Reseau.ErrorResult
                @test false
            else
                el = setup.el
                channel = setup.channel
                shutdown_ch = setup.shutdown_ch

                Reseau.channel_shutdown!(channel, Reseau.AWS_OP_SUCCESS)
                @test _wait_ready_channel(shutdown_ch)

                Reseau.channel_shutdown!(channel, Reseau.AWS_OP_SUCCESS)

                Reseau.channel_destroy!(channel)
                Reseau.event_loop_destroy!(el)
            end
        end

        @testset "concurrent shutdown schedules once" begin
            setup = _setup_channel(with_shutdown_cb = true)
            if setup isa Reseau.ErrorResult
                @test false
            else
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
                    Reseau.channel_shutdown!(channel, Reseau.AWS_OP_SUCCESS)
                    return nothing
                end)
                t2 = errormonitor(Threads.@spawn begin
                    Threads.atomic_add!(ready, 1)
                    while !go[]
                        yield()
                    end
                    Reseau.channel_shutdown!(channel, Reseau.ERROR_INVALID_STATE)
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
                @test err == Reseau.AWS_OP_SUCCESS || err == Reseau.ERROR_INVALID_STATE

                extra_deadline = Base.time_ns() + 500_000_000
                while Base.time_ns() < extra_deadline && !isready(shutdown_ch)
                    yield()
                end
                @test !isready(shutdown_ch)

                Reseau.channel_destroy!(channel)
                Reseau.event_loop_destroy!(el)
            end
        end
    end
end
