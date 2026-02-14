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
    el = EventLoops.event_loop_new()
    EventLoops.event_loop_run!(el)

    setup_ch = Channel{Int}(1)
    shutdown_ch = Channel{Int}(1)

    on_setup = Reseau.EventCallable(err -> begin
        put!(setup_ch, err)
        return nothing
    end)
    on_shutdown = with_shutdown_cb ? (
            Reseau.EventCallable(err -> begin
                put!(shutdown_ch, err)
                return nothing
            end)
        ) : nothing

    ps = Sockets.pipeline_new(el; on_setup_completed = on_setup, on_shutdown_completed = on_shutdown)

    @test _wait_ready_channel(setup_ch)
    if isready(setup_ch)
        @test take!(setup_ch) == Reseau.AWS_OP_SUCCESS
    end

    return (el = el, ps = ps, shutdown_ch = shutdown_ch)
end

@testset "channel" begin
    if Threads.nthreads(:interactive) <= 1
        @test true
    else
        Sockets.io_library_init()

        @testset "destroy before setup completes waits for setup" begin
            el = EventLoops.event_loop_new()

            setup_ch = Channel{Int}(1)
            on_setup = Reseau.EventCallable(err -> begin
                put!(setup_ch, err)
                return nothing
            end)

            ps = Sockets.pipeline_new(el; on_setup_completed = on_setup, on_shutdown_completed = nothing)

            Sockets.pipeline_destroy!(ps)
            @test EventLoops.event_loop_run!(el) === nothing

            @test _wait_ready_channel(setup_ch)
            if isready(setup_ch)
                @test take!(setup_ch) == Reseau.AWS_OP_SUCCESS
            end

            deadline = Base.time_ns() + 1_000_000_000
            while ps.state != Sockets.PipelineLifecycle.SHUT_DOWN && Base.time_ns() < deadline
                yield()
            end
            @test ps.state == Sockets.PipelineLifecycle.SHUT_DOWN

            EventLoops.event_loop_destroy!(el)
        end

        @testset "channel tasks run" begin
            setup = _setup_channel()
            el = setup.el
            ps = setup.ps

            task_count = 4
            status_ch = Channel{Tuple{Int, Reseau.TaskStatus.T}}(task_count)

            tasks = [Sockets.ChannelTask() for _ in 1:task_count]
            for i in 1:task_count
                Sockets.channel_task_init!(tasks[i], Reseau.EventCallable(status -> begin
                    put!(status_ch, (i, Reseau.TaskStatus.T(status)))
                    nothing
                end), "test_channel_task")
            end

            Sockets.pipeline_schedule_task_now!(ps, tasks[1])
            Sockets.pipeline_schedule_task_future!(ps, tasks[2], UInt64(1))

            scheduler_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return nothing
                Sockets.pipeline_schedule_task_now!(ps, tasks[3])
                Sockets.pipeline_schedule_task_future!(ps, tasks[4], UInt64(1))
                return nothing
            end); type_tag = "schedule_on_thread")
            EventLoops.event_loop_schedule_task_now!(el, scheduler_task)

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

            Sockets.pipeline_destroy!(ps)
            EventLoops.event_loop_destroy!(el)
        end

        @testset "channel tasks run cross-thread" begin
            setup = _setup_channel()
            el = setup.el
            ps = setup.ps

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
                Sockets.pipeline_schedule_task_now!(ps, tasks[1])
                Sockets.pipeline_schedule_task_future!(ps, tasks[2], UInt64(1))
            end)
            t2 = errormonitor(Threads.@spawn begin
                Sockets.pipeline_schedule_task_now!(ps, tasks[3])
                Sockets.pipeline_schedule_task_future!(ps, tasks[4], UInt64(1))
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

            Sockets.pipeline_destroy!(ps)
            EventLoops.event_loop_destroy!(el)
        end

        @testset "channel tasks serialized run" begin
            setup = _setup_channel()
            el = setup.el
            ps = setup.ps

            task_count = 4
            status_ch = Channel{Tuple{Int, Reseau.TaskStatus.T}}(task_count)

            tasks = [Sockets.ChannelTask() for _ in 1:task_count]
            for i in 1:task_count
                Sockets.channel_task_init!(tasks[i], Reseau.EventCallable(status -> begin
                    put!(status_ch, (i, Reseau.TaskStatus.T(status)))
                    nothing
                end), "test_channel_task_serialized")
            end

            Sockets.pipeline_schedule_task_now_serialized!(ps, tasks[1])
            Sockets.pipeline_schedule_task_future!(ps, tasks[2], UInt64(1))

            scheduler_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return nothing
                Sockets.pipeline_schedule_task_now_serialized!(ps, tasks[3])
                Sockets.pipeline_schedule_task_future!(ps, tasks[4], UInt64(1))
                return nothing
            end); type_tag = "schedule_on_thread_serialized")
            EventLoops.event_loop_schedule_task_now!(el, scheduler_task)

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

            Sockets.pipeline_destroy!(ps)
            EventLoops.event_loop_destroy!(el)
        end

        @testset "channel serialized tasks queued via cross-thread list" begin
            setup = _setup_channel()
            el = setup.el
            ps = setup.ps

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
                Sockets.pipeline_schedule_task_now_serialized!(ps, task)
                put!(ready_ch, true)
                take!(block_ch)
                return nothing
            end); type_tag = "block_serialized_queue")

            try
                EventLoops.event_loop_schedule_task_now!(el, blocker)
                @test take!(ready_ch)

                queued = false
                lock(ps.cross_thread_tasks_lock) do
                    queued = !isempty(ps.cross_thread_tasks)
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
                Sockets.pipeline_destroy!(ps)
                EventLoops.event_loop_destroy!(el)
            end
        end

        @testset "post shutdown tasks canceled" begin
            setup = _setup_channel(with_shutdown_cb = true)
            el = setup.el
            ps = setup.ps
            shutdown_ch = setup.shutdown_ch

            Sockets.pipeline_shutdown!(ps, Reseau.AWS_OP_SUCCESS)
            @test _wait_ready_channel(shutdown_ch)

            task_status = Ref{Reseau.TaskStatus.T}(Reseau.TaskStatus.RUN_READY)
            task = Sockets.ChannelTask()
            Sockets.channel_task_init!(task, Reseau.EventCallable(status -> begin
                task_status[] = Reseau.TaskStatus.T(status)
                nothing
            end), "post_shutdown")
            Sockets.pipeline_schedule_task_now!(ps, task)
            @test task_status[] == Reseau.TaskStatus.CANCELED

            Sockets.pipeline_destroy!(ps)
            EventLoops.event_loop_destroy!(el)
        end

        @testset "pending tasks canceled on shutdown" begin
            setup = _setup_channel(with_shutdown_cb = true)
            el = setup.el
            ps = setup.ps
            shutdown_ch = setup.shutdown_ch

            task_status = Ref{Int}(100)
            task = Sockets.ChannelTask()
            Sockets.channel_task_init!(task, Reseau.EventCallable(status -> begin
                task_status[] = status
                nothing
            end), "future_task")
            Sockets.pipeline_schedule_task_future!(ps, task, typemax(UInt64) - 1)
            @test task_status[] == 100

            Sockets.pipeline_shutdown!(ps, Reseau.AWS_OP_SUCCESS)
            @test _wait_ready_channel(shutdown_ch)

            deadline = Base.time_ns() + 2_000_000_000
            while task_status[] == 100 && Base.time_ns() < deadline
                yield()
            end
            @test task_status[] == Int(Reseau.TaskStatus.CANCELED)

            Sockets.pipeline_destroy!(ps)
            EventLoops.event_loop_destroy!(el)
        end

        @testset "duplicate shutdown" begin
            setup = _setup_channel(with_shutdown_cb = true)
            el = setup.el
            ps = setup.ps
            shutdown_ch = setup.shutdown_ch

            Sockets.pipeline_shutdown!(ps, Reseau.AWS_OP_SUCCESS)
            @test _wait_ready_channel(shutdown_ch)

            Sockets.pipeline_shutdown!(ps, Reseau.AWS_OP_SUCCESS)

            Sockets.pipeline_destroy!(ps)
            EventLoops.event_loop_destroy!(el)
        end

        @testset "concurrent shutdown schedules once" begin
            setup = _setup_channel(with_shutdown_cb = true)
            el = setup.el
            ps = setup.ps
            shutdown_ch = setup.shutdown_ch

            ready = Threads.Atomic{Int}(0)
            go = Threads.Atomic{Bool}(false)

            t1 = errormonitor(Threads.@spawn begin
                Threads.atomic_add!(ready, 1)
                while !go[]
                    yield()
                end
                Sockets.pipeline_shutdown!(ps, Reseau.AWS_OP_SUCCESS)
                return nothing
            end)
            t2 = errormonitor(Threads.@spawn begin
                Threads.atomic_add!(ready, 1)
                while !go[]
                    yield()
                end
                Sockets.pipeline_shutdown!(ps, Reseau.ERROR_INVALID_STATE)
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

            Sockets.pipeline_destroy!(ps)
            EventLoops.event_loop_destroy!(el)
        end
    end
end
