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
    opts = Reseau.ThreadOptions(; join_strategy = Reseau.ThreadJoinStrategy.MANAGED)
    handles = Reseau.ThreadHandle[]
    for _ in 1:2
        handle = Reseau.ThreadHandle()
        push!(handles, handle)
        @test Reseau.thread_launch(handle, _ -> begin
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
    @test Reseau.thread_join_all_managed() == Reseau.OP_SUCCESS
    @test Reseau.thread_get_managed_thread_count() == 0
end

@testset "TaskScheduler cancel" begin
    scheduler = Reseau.TaskScheduler()
    status_ch = Channel{Reseau.TaskStatus.T}(1)
    task = Reseau.ScheduledTask((_, status) -> put!(status_ch, status), nothing; type_tag = "task_cancel")
    Reseau.task_scheduler_cancel!(scheduler, task)
    @test Base.timedwait(() -> isready(status_ch), 5.0) == :ok
    @test take!(status_ch) == Reseau.TaskStatus.CANCELED
end

@testset "TaskScheduler fairness" begin
    scheduler = Reseau.TaskScheduler()
    executed = String[]

    task_a = Reseau.ScheduledTask(
        (ctx, status) -> begin
            status == Reseau.TaskStatus.RUN_READY || return nothing
            push!(ctx.executed, "a")
            task_b = Reseau.ScheduledTask(
                (ctx2, status2) -> begin
                    status2 == Reseau.TaskStatus.RUN_READY || return nothing
                    push!(ctx2.executed, "b")
                    return nothing
                end,
                (executed = ctx.executed,);
                type_tag = "task_b",
            )
            Reseau.task_scheduler_schedule_now!(ctx.scheduler, task_b)
            return nothing
        end,
        (executed = executed, scheduler = scheduler);
        type_tag = "task_a",
    )

    Reseau.task_scheduler_schedule_now!(scheduler, task_a)
    Reseau.task_scheduler_run_all!(scheduler, UInt64(0))
    @test executed == ["a"]
    Reseau.task_scheduler_run_all!(scheduler, UInt64(0))
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
        barrier = Threads.Atomic{Int}(0)
        tids = Channel{Int}(2)
        errs = Channel{Int}(2)

        t1 = Threads.@spawn begin
            put!(tids, Threads.threadid())
            Reseau.raise_error(Reseau.ERROR_INVALID_ARGUMENT)
            Threads.atomic_add!(barrier, 1)
            while Threads.atomic_load(barrier) < 2
                yield()
            end
            put!(errs, Reseau.last_error())
        end

        t2 = Threads.@spawn begin
            put!(tids, Threads.threadid())
            Reseau.raise_error(Reseau.ERROR_OOM)
            Threads.atomic_add!(barrier, 1)
            while Threads.atomic_load(barrier) < 2
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

@testset "Home/temp env fallbacks" begin
    keys = @static if Sys.iswindows()
        ["USERPROFILE", "HOMEDRIVE", "HOMEPATH", "TMP", "TEMP"]
    else
        ["HOME", "TMPDIR", "TMP", "TEMP"]
    end

    old = Dict{String, Union{Nothing, String}}()
    for k in keys
        old[k] = get(ENV, k, nothing)
    end

    try
        for k in keys
            ENV[k] = ""
        end

        Reseau.reset_error()
        home = Reseau.get_home_directory()
        @test Reseau.string_len(home) == 0
        @test Reseau.last_error() == Reseau.ERROR_GET_HOME_DIRECTORY_FAILED

        tmp = Reseau.get_temp_directory()
        @test !isempty(tmp)
        @static if !Sys.iswindows()
            @test tmp == "/tmp"
        end
    finally
        for k in keys
            v = old[k]
            if v === nothing
                pop!(ENV, k, nothing)
            else
                ENV[k] = v
            end
        end
    end
end

@testset "UUID" begin
    u = Ref{Reseau.uuid}()
    @test Reseau.uuid_init(u) == Reseau.OP_SUCCESS
    out = Ref(Reseau.ByteBuffer(Reseau.UUID_STR_LEN))
    @test Reseau.uuid_to_str(u, out) == Reseau.OP_SUCCESS
    @test out[].len == Reseau.UUID_STR_LEN - 1
end

@testset "UUID from string" begin
    s = "123e4567-e89b-12d3-a456-426614174000"
    u = Ref{Reseau.uuid}()
    cursor = Ref(Reseau.ByteCursor(s))
    @test Reseau.uuid_init_from_str(u, cursor) == Reseau.OP_SUCCESS
    out = Ref(Reseau.ByteBuffer(Reseau.UUID_STR_LEN))
    @test Reseau.uuid_to_str(u, out) == Reseau.OP_SUCCESS
    @test String(Reseau.byte_cursor_from_buf(out[])) == s
end

@testset "Date time parsing" begin
    dt = Ref{Reseau.date_time}()

    rfc = "Sun, 06 Nov 1994 08:49:37 GMT"
    rfc_cursor = Ref(Reseau.ByteCursor(rfc))
    @test Reseau.date_time_init_from_str_cursor(dt, rfc_cursor, Reseau.DateFormat.RFC822) == Reseau.OP_SUCCESS
    @test dt[].gmt_time.tm_year + 1900 == 1994
    @test dt[].gmt_time.tm_mon + 1 == 11
    @test dt[].gmt_time.tm_mday == 6
    @test dt[].gmt_time.tm_hour == 8
    @test dt[].gmt_time.tm_min == 49
    @test dt[].gmt_time.tm_sec == 37

    iso = "1994-11-06T08:49:37Z"
    iso_cursor = Ref(Reseau.ByteCursor(iso))
    @test Reseau.date_time_init_from_str_cursor(dt, iso_cursor, Reseau.DateFormat.ISO_8601) == Reseau.OP_SUCCESS
    @test dt[].gmt_time.tm_year + 1900 == 1994
    @test dt[].gmt_time.tm_mon + 1 == 11
    @test dt[].gmt_time.tm_mday == 6
    @test dt[].gmt_time.tm_hour == 8
    @test dt[].gmt_time.tm_min == 49
    @test dt[].gmt_time.tm_sec == 37

    iso_basic = "19941106T084937Z"
    iso_basic_cursor = Ref(Reseau.ByteCursor(iso_basic))
    @test Reseau.date_time_init_from_str_cursor(dt, iso_basic_cursor, Reseau.DateFormat.ISO_8601_BASIC) == Reseau.OP_SUCCESS
    @test dt[].gmt_time.tm_year + 1900 == 1994
    @test dt[].gmt_time.tm_mon + 1 == 11
    @test dt[].gmt_time.tm_mday == 6
    @test dt[].gmt_time.tm_hour == 8
    @test dt[].gmt_time.tm_min == 49
    @test dt[].gmt_time.tm_sec == 37

    bad_cursor = Ref(Reseau.ByteCursor("not a date"))
    @test Reseau.date_time_init_from_str_cursor(dt, bad_cursor, Reseau.DateFormat.AUTO_DETECT) == Reseau.OP_ERR
end

@testset "byte buffer init from file" begin
    mktemp() do path, io
        write(io, "filedata")
        close(io)

        buf_ref = Ref{Reseau.ByteBuffer}()
        @test Reseau.byte_buf_init_from_file(buf_ref, path) == Reseau.AWS_OP_SUCCESS
        buf = buf_ref[]
        @test buf.len == 8
        @test String(Reseau.byte_cursor_from_buf(buf)) == "filedata"
        @test buf.mem[Int(buf.len) + 1] == 0x00
    end
end
