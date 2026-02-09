using Test
using Reseau

@testset "Common containers" begin
    @testset "PriorityQueue" begin
        pq = Reseau.PriorityQueue{Int}((a, b) -> a < b; capacity = 2)
        push!(pq, 3)
        push!(pq, 1)
        push!(pq, 2)
        @test Reseau.peek(pq) == 1
        @test pop!(pq) == 1
        @test pop!(pq) == 2
        @test pop!(pq) == 3
        @test isempty(pq)
    end

end


@testset "Managed thread join" begin
    started = Channel{Nothing}(2)
    stop_flag = Ref(false)
    opts = Threads.ThreadOptions(; join_strategy = Threads.ThreadJoinStrategy.MANAGED)
    handles = Threads.ThreadHandle[]
    for _ in 1:2
        handle = Threads.ThreadHandle()
        push!(handles, handle)
        @test Threads.thread_launch(handle, _ -> begin
            put!(started, nothing)
            while !stop_flag[]
                sleep(0.001)
            end
            return nothing
        end, nothing, opts) == Reseau.OP_SUCCESS
    end
    take!(started)
    take!(started)
    stop_flag[] = true
    @test Threads.thread_join_all_managed() == Reseau.OP_SUCCESS
    @test Threads.thread_get_managed_thread_count() == 0
end

@testset "TaskScheduler cancel" begin
    scheduler = Threads.TaskScheduler()
    status_ch = Channel{Threads.TaskStatus.T}(1)
    task = Threads.ScheduledTask((_, status) -> put!(status_ch, status), nothing; type_tag = "task_cancel")
    Threads.task_scheduler_cancel!(scheduler, task)
    @test Base.timedwait(() -> isready(status_ch), 5.0) == :ok
    @test take!(status_ch) == Threads.TaskStatus.CANCELED
end

@testset "TaskScheduler fairness" begin
    scheduler = Threads.TaskScheduler()
    executed = String[]

    task_a = Threads.ScheduledTask(
        (ctx, status) -> begin
            status == Threads.TaskStatus.RUN_READY || return nothing
            push!(ctx.executed, "a")
            task_b = Threads.ScheduledTask(
                (ctx2, status2) -> begin
                    status2 == Threads.TaskStatus.RUN_READY || return nothing
                    push!(ctx2.executed, "b")
                    return nothing
                end,
                (executed = ctx.executed,);
                type_tag = "task_b",
            )
            Threads.task_scheduler_schedule_now!(ctx.scheduler, task_b)
            return nothing
        end,
        (executed = executed, scheduler = scheduler);
        type_tag = "task_a",
    )

    Threads.task_scheduler_schedule_now!(scheduler, task_a)
    Threads.task_scheduler_run_all!(scheduler, UInt64(0))
    @test executed == ["a"]
    Threads.task_scheduler_run_all!(scheduler, UInt64(0))
    @test executed == ["a", "b"]
end


@testset "Byte buffers" begin
    buf_ref = Ref(Reseau.ByteBuffer(8))
    cur = Reseau.ByteCursor("hi")
    @test Reseau.byte_buf_write_from_whole_cursor(buf_ref, cur) == true
    @test buf_ref[].len == 2
    @test String(unsafe_wrap(Vector{UInt8}, pointer(buf_ref[].mem), Int(buf_ref[].len); own = false)) == "hi"

    bytes = UInt8[0x68, 0x69]  # "hi"
    cur2 = Reseau.byte_cursor_from_array(bytes, 999)
    @test cur2.len == 2
    @test String(cur2) == "hi"

    cur3 = Reseau.ByteCursor(bytes, 999)
    @test cur3.len == 2
    @test String(cur3) == "hi"

    @test_throws ArgumentError Reseau.byte_cursor_from_array(bytes, -1)
    @test_throws ArgumentError Reseau.ByteCursor(bytes, -1)

    # Non-contiguous views are not safe to treat as contiguous pointer+length.
    a = UInt8[0x61, 0x62, 0x63, 0x64, 0x65, 0x66]  # "abcdef"
    rev = @view a[6:-1:1]
    @test_throws ArgumentError Reseau.byte_cursor_from_array(rev)
    @test_throws ArgumentError Reseau.byte_cursor_from_array(rev, 0, 1)
    @test_throws ArgumentError Reseau.byte_buf_from_array(rev)
    @test_throws ArgumentError Reseau.byte_buf_from_empty_array(rev)
end

@testset "Error handling" begin
    Reseau.raise_error(Reseau.ERROR_INVALID_ARGUMENT)
    @test Reseau.last_error() == Reseau.ERROR_INVALID_ARGUMENT
end

@testset "Thread-local last_error is per Julia thread" begin
    if Base.Threads.nthreads() > 1
        barrier = Base.Threads.Atomic{Int}(0)
        tids = Channel{Int}(2)
        errs = Channel{Int}(2)

        t1 = Base.Threads.@spawn begin
            put!(tids, Base.Threads.threadid())
            Reseau.raise_error(Reseau.ERROR_INVALID_ARGUMENT)
            Base.Threads.atomic_add!(barrier, 1)
            while Base.Threads.atomic_load(barrier) < 2
                yield()
            end
            put!(errs, Reseau.last_error())
        end

        t2 = Base.Threads.@spawn begin
            put!(tids, Base.Threads.threadid())
            Reseau.raise_error(Reseau.ERROR_OOM)
            Base.Threads.atomic_add!(barrier, 1)
            while Base.Threads.atomic_load(barrier) < 2
                yield()
            end
            put!(errs, Reseau.last_error())
        end

        wait(t1)
        wait(t2)

        t = [take!(tids), take!(tids)]
        e = [take!(errs), take!(errs)]

        if length(unique(t)) == 1
            # Scheduler happened to run both tasks on the same Julia thread; don't
            # assert cross-thread behavior in that case.
            @test true
        else
            @test sort(e) == sort([Reseau.ERROR_INVALID_ARGUMENT, Reseau.ERROR_OOM])
        end
    else
        @test true
    end
end
