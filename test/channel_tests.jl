using Test
using AwsIO

function _wait_ready_channel(ch::Channel; timeout_ns::Int = 2_000_000_000)
    deadline = Base.time_ns() + timeout_ns
    while !isready(ch) && Base.time_ns() < deadline
        yield()
    end
    return isready(ch)
end

function _setup_channel(; with_shutdown_cb::Bool = false)
    opts = AwsIO.EventLoopOptions()
    el = AwsIO.event_loop_new(opts)
    el isa AwsIO.ErrorResult && return el
    run_res = AwsIO.event_loop_run!(el)
    run_res isa AwsIO.ErrorResult && return run_res

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

    channel_opts = AwsIO.ChannelOptions(
        event_loop = el,
        on_setup_completed = on_setup,
        on_shutdown_completed = on_shutdown,
        setup_user_data = nothing,
        shutdown_user_data = nothing,
    )

    channel = AwsIO.channel_new(channel_opts)
    channel isa AwsIO.ErrorResult && return channel

    @test _wait_ready_channel(setup_ch)
    if isready(setup_ch)
        @test take!(setup_ch) == AwsIO.AWS_OP_SUCCESS
    end

    return (el = el, channel = channel, shutdown_ch = shutdown_ch)
end

@testset "channel" begin
    if Sys.iswindows() || Threads.nthreads(:interactive) <= 1
        @test true
    else
        AwsIO.io_library_init()

        @testset "slots cleanup" begin
            setup = _setup_channel()
            if setup isa AwsIO.ErrorResult
                @test false
            else
                el = setup.el
                channel = setup.channel

                slot_1 = AwsIO.channel_slot_new!(channel)
                slot_2 = AwsIO.channel_slot_new!(channel)
                slot_3 = AwsIO.channel_slot_new!(channel)
                slot_4 = AwsIO.channel_slot_new!(channel)
                slot_5 = AwsIO.channel_slot_new!(channel)

                AwsIO.channel_slot_insert_right!(slot_1, slot_2)
                AwsIO.channel_slot_insert_right!(slot_2, slot_3)
                AwsIO.channel_slot_insert_left!(slot_3, slot_4)
                AwsIO.channel_slot_remove!(slot_2)

                @test slot_1.adj_left === nothing
                @test slot_1.adj_right === slot_4
                @test slot_4.adj_left === slot_1
                @test slot_4.adj_right === slot_3
                @test slot_3.adj_left === slot_4
                @test slot_3.adj_right === nothing

                AwsIO.channel_slot_replace!(slot_4, slot_5)
                @test slot_1.adj_right === slot_5
                @test slot_5.adj_left === slot_1
                @test slot_5.adj_right === slot_3
                @test slot_3.adj_left === slot_5

                AwsIO.channel_destroy!(channel)
                AwsIO.event_loop_destroy!(el)
            end
        end

        @testset "channel tasks run" begin
            setup = _setup_channel()
            if setup isa AwsIO.ErrorResult
                @test false
            else
                el = setup.el
                channel = setup.channel

                task_count = 4
                status_ch = Channel{Tuple{Int, AwsIO.TaskStatus.T}}(task_count)

                task_fn = (task, arg, status) -> begin
                    put!(status_ch, (Int(arg), status))
                    return nothing
                end

                tasks = [AwsIO.ChannelTask() for _ in 1:task_count]
                for i in 1:task_count
                    AwsIO.channel_task_init!(tasks[i], task_fn, i, "test_channel_task")
                end

                AwsIO.channel_schedule_task_now!(channel, tasks[1])
                AwsIO.channel_schedule_task_future!(channel, tasks[2], UInt64(1))

                on_thread = (ctx, status) -> begin
                    status == AwsIO.TaskStatus.RUN_READY || return nothing
                    AwsIO.channel_schedule_task_now!(ctx.channel, ctx.tasks[3])
                    AwsIO.channel_schedule_task_future!(ctx.channel, ctx.tasks[4], UInt64(1))
                    return nothing
                end
                scheduler_task = AwsIO.ScheduledTask(on_thread, (channel = channel, tasks = tasks); type_tag = "schedule_on_thread")
                AwsIO.event_loop_schedule_task_now!(el, scheduler_task)

                deadline = Base.time_ns() + 2_000_000_000
                results = Dict{Int, AwsIO.TaskStatus.T}()
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
                    @test status == AwsIO.TaskStatus.RUN_READY
                end

                AwsIO.channel_destroy!(channel)
                AwsIO.event_loop_destroy!(el)
            end
        end

        @testset "channel tasks run cross-thread" begin
            setup = _setup_channel()
            if setup isa AwsIO.ErrorResult
                @test false
            else
                el = setup.el
                channel = setup.channel

                task_count = 4
                status_ch = Channel{Tuple{Int, AwsIO.TaskStatus.T}}(task_count)

                task_fn = (task, arg, status) -> begin
                    put!(status_ch, (Int(arg), status))
                    return nothing
                end

                tasks = [AwsIO.ChannelTask() for _ in 1:task_count]
                for i in 1:task_count
                    AwsIO.channel_task_init!(tasks[i], task_fn, i, "test_channel_task_cross_thread")
                end

                t1 = errormonitor(Threads.@spawn begin
                    AwsIO.channel_schedule_task_now!(channel, tasks[1])
                    AwsIO.channel_schedule_task_future!(channel, tasks[2], UInt64(1))
                end)
                t2 = errormonitor(Threads.@spawn begin
                    AwsIO.channel_schedule_task_now!(channel, tasks[3])
                    AwsIO.channel_schedule_task_future!(channel, tasks[4], UInt64(1))
                end)
                wait(t1)
                wait(t2)

                deadline = Base.time_ns() + 2_000_000_000
                results = Dict{Int, AwsIO.TaskStatus.T}()
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
                    @test status == AwsIO.TaskStatus.RUN_READY
                end

                AwsIO.channel_destroy!(channel)
                AwsIO.event_loop_destroy!(el)
            end
        end

        @testset "channel tasks serialized run" begin
            setup = _setup_channel()
            if setup isa AwsIO.ErrorResult
                @test false
            else
                el = setup.el
                channel = setup.channel

                task_count = 4
                status_ch = Channel{Tuple{Int, AwsIO.TaskStatus.T}}(task_count)

                task_fn = (task, arg, status) -> begin
                    put!(status_ch, (Int(arg), status))
                    return nothing
                end

                tasks = [AwsIO.ChannelTask() for _ in 1:task_count]
                for i in 1:task_count
                    AwsIO.channel_task_init!(tasks[i], task_fn, i, "test_channel_task_serialized")
                end

                AwsIO.channel_schedule_task_now_serialized!(channel, tasks[1])
                AwsIO.channel_schedule_task_future!(channel, tasks[2], UInt64(1))

                on_thread = (ctx, status) -> begin
                    status == AwsIO.TaskStatus.RUN_READY || return nothing
                    AwsIO.channel_schedule_task_now_serialized!(ctx.channel, ctx.tasks[3])
                    AwsIO.channel_schedule_task_future!(ctx.channel, ctx.tasks[4], UInt64(1))
                    return nothing
                end
                scheduler_task = AwsIO.ScheduledTask(on_thread, (channel = channel, tasks = tasks); type_tag = "schedule_on_thread_serialized")
                AwsIO.event_loop_schedule_task_now!(el, scheduler_task)

                deadline = Base.time_ns() + 2_000_000_000
                results = Dict{Int, AwsIO.TaskStatus.T}()
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
                    @test status == AwsIO.TaskStatus.RUN_READY
                end

                AwsIO.channel_destroy!(channel)
                AwsIO.event_loop_destroy!(el)
            end
        end

        @testset "channel serialized tasks queued via cross-thread list" begin
            setup = _setup_channel()
            if setup isa AwsIO.ErrorResult
                @test false
            else
                el = setup.el
                channel = setup.channel

                status_ch = Channel{AwsIO.TaskStatus.T}(1)
                task = AwsIO.ChannelTask()
                AwsIO.channel_task_init!(
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

                blocker = AwsIO.ScheduledTask(
                    (ctx, status) -> begin
                        status == AwsIO.TaskStatus.RUN_READY || return nothing
                        AwsIO.channel_schedule_task_now_serialized!(ctx.channel, ctx.task)
                        put!(ctx.ready_ch, true)
                        take!(ctx.block_ch)
                        return nothing
                    end,
                    (channel = channel, task = task, ready_ch = ready_ch, block_ch = block_ch);
                    type_tag = "block_serialized_queue",
                )

                try
                    AwsIO.event_loop_schedule_task_now!(el, blocker)
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
                            @test status == AwsIO.TaskStatus.RUN_READY
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
                    AwsIO.channel_destroy!(channel)
                    AwsIO.event_loop_destroy!(el)
                end
            end
        end

        @testset "post shutdown tasks canceled" begin
            setup = _setup_channel(with_shutdown_cb = true)
            if setup isa AwsIO.ErrorResult
                @test false
            else
                el = setup.el
                channel = setup.channel
                shutdown_ch = setup.shutdown_ch

                AwsIO.channel_shutdown!(channel, AwsIO.AWS_OP_SUCCESS)
                @test _wait_ready_channel(shutdown_ch)

                task_status = Ref{AwsIO.TaskStatus.T}(AwsIO.TaskStatus.RUN_READY)
                task_fn = (task, arg, status) -> begin
                    arg[] = status
                    return nothing
                end
                task = AwsIO.ChannelTask()
                AwsIO.channel_task_init!(task, task_fn, task_status, "post_shutdown")
                AwsIO.channel_schedule_task_now!(channel, task)
                @test task_status[] == AwsIO.TaskStatus.CANCELED

                AwsIO.channel_destroy!(channel)
                AwsIO.event_loop_destroy!(el)
            end
        end

        @testset "pending tasks canceled on shutdown" begin
            setup = _setup_channel(with_shutdown_cb = true)
            if setup isa AwsIO.ErrorResult
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
                task = AwsIO.ChannelTask()
                AwsIO.channel_task_init!(task, task_fn, task_status, "future_task")
                AwsIO.channel_schedule_task_future!(channel, task, typemax(UInt64) - 1)
                @test task_status[] == 100

                AwsIO.channel_shutdown!(channel, AwsIO.AWS_OP_SUCCESS)
                @test _wait_ready_channel(shutdown_ch)

                deadline = Base.time_ns() + 2_000_000_000
                while task_status[] == 100 && Base.time_ns() < deadline
                    yield()
                end
                @test task_status[] == Int(AwsIO.TaskStatus.CANCELED)

                AwsIO.channel_destroy!(channel)
                AwsIO.event_loop_destroy!(el)
            end
        end

        @testset "duplicate shutdown" begin
            setup = _setup_channel(with_shutdown_cb = true)
            if setup isa AwsIO.ErrorResult
                @test false
            else
                el = setup.el
                channel = setup.channel
                shutdown_ch = setup.shutdown_ch

                AwsIO.channel_shutdown!(channel, AwsIO.AWS_OP_SUCCESS)
                @test _wait_ready_channel(shutdown_ch)

                AwsIO.channel_shutdown!(channel, AwsIO.AWS_OP_SUCCESS)

                AwsIO.channel_destroy!(channel)
                AwsIO.event_loop_destroy!(el)
            end
        end
    end
end
