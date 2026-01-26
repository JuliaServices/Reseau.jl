using Test
using AwsIO

@testset "Event Loops" begin
    @testset "EventLoopType default" begin
        el_type = AwsIO.event_loop_get_default_type()

        if Sys.islinux()
            @test el_type == AwsIO.EventLoopType.EPOLL
        elseif Sys.isapple() || Sys.isbsd()
            @test el_type == AwsIO.EventLoopType.KQUEUE
        end
    end

    @testset "Event loop scheduling" begin
        if Sys.iswindows()
            @test true
        else
            opts = AwsIO.EventLoopOptions()
            el = AwsIO.event_loop_new(opts)
            @test !(el isa AwsIO.ErrorResult)

            if !(el isa AwsIO.ErrorResult)
                run_res = AwsIO.event_loop_run!(el)
                @test run_res === nothing

                try
                    done = Ref(false)
                    thread_ok = Ref(false)
                    ctx = (el=el, done=done, thread_ok=thread_ok)

                    task_fn = (ctx, status) -> begin
                        ctx.thread_ok[] = AwsIO.event_loop_thread_is_callers_thread(ctx.el)
                        ctx.done[] = true
                        return nothing
                    end

                    task = AwsIO.ScheduledTask(task_fn, ctx; type_tag="event_loop_test_task")
                    AwsIO.event_loop_schedule_task_now!(el, task)

                    deadline = Base.time_ns() + 2_000_000_000
                    while !done[] && Base.time_ns() < deadline
                        yield()
                    end

                    @test done[]
                    @test thread_ok[]
                finally
                    AwsIO.event_loop_destroy!(el)
                end
            end
        end
    end

    @testset "Event loop group" begin
        if Sys.iswindows()
            @test true
        else
            opts = AwsIO.EventLoopGroupOptions(loop_count=1)
            elg = AwsIO.event_loop_group_new(opts)
            @test !(elg isa AwsIO.ErrorResult)

            if !(elg isa AwsIO.ErrorResult)
                try
                    @test AwsIO.event_loop_group_get_loop_count(elg) == 1
                    el = AwsIO.event_loop_group_get_next_loop(elg)
                    @test el !== nothing
                finally
                    AwsIO.event_loop_group_destroy!(elg)
                end
            end
        end
    end
end
