using Test
using AwsIO

@testset "Common containers" begin
    @testset "ArrayList" begin
        list = AwsIO.ArrayList{Int}(2)
        @test AwsIO.push_back!(list, 1) == AwsIO.OP_SUCCESS
        @test AwsIO.push_back!(list, 2) == AwsIO.OP_SUCCESS
        @test length(list) == 2
        @test list[1] == 1
        @test list[2] == 2
        @test AwsIO.pop_back!(list) == 2
        @test AwsIO.pop_front!(list) == 1
        @test isempty(list)
    end

    @testset "Deque" begin
        dq = AwsIO.Deque{Int}(2)
        AwsIO.push_back!(dq, 1)
        AwsIO.push_back!(dq, 2)
        AwsIO.push_front!(dq, 0)
        @test length(dq) == 3
        @test AwsIO.pop_front!(dq) == 0
        @test AwsIO.pop_back!(dq) == 2
        @test AwsIO.pop_back!(dq) == 1
        @test isempty(dq)
    end

    @testset "PriorityQueue" begin
        pq = AwsIO.PriorityQueue{Int}((a, b) -> a < b; capacity = 2)
        push!(pq, 3)
        push!(pq, 1)
        push!(pq, 2)
        @test AwsIO.peek(pq) == 1
        @test pop!(pq) == 1
        @test pop!(pq) == 2
        @test pop!(pq) == 3
        @test isempty(pq)
    end

    @testset "HashTable" begin
        ht = AwsIO.HashTable{Int, String}((x) -> x, (a, b) -> a == b; capacity = 4)
        @test AwsIO.hash_table_put!(ht, 1, "one") == AwsIO.OP_SUCCESS
        @test AwsIO.hash_table_put!(ht, 2, "two") == AwsIO.OP_SUCCESS
        @test AwsIO.hash_table_get(ht, 1) == "one"
        @test AwsIO.hash_table_get(ht, 3) === nothing
        @test AwsIO.hash_table_remove!(ht, 2) == AwsIO.OP_SUCCESS
        @test AwsIO.hash_table_get(ht, 2) === nothing
        AwsIO.hash_table_clear!(ht)
        @test length(ht) == 0
    end
end

@testset "Mutex" begin
    m = Ref{AwsIO.Mutex}()
    @test AwsIO.mutex_init(m) == AwsIO.OP_SUCCESS
    @test AwsIO.mutex_lock(m) == AwsIO.OP_SUCCESS
    @test AwsIO.mutex_try_lock(m) == AwsIO.OP_ERR
    @test AwsIO.last_error() == AwsIO.ERROR_MUTEX_TIMEOUT
    @test AwsIO.mutex_unlock(m) == AwsIO.OP_SUCCESS
    AwsIO.mutex_clean_up(m)
end

@testset "Managed thread join" begin
    started = Channel{Nothing}(2)
    stop_flag = Ref(false)
    opts = AwsIO.ThreadOptions(; join_strategy = AwsIO.ThreadJoinStrategy.MANAGED)
    handles = AwsIO.ThreadHandle[]
    for _ in 1:2
        handle = AwsIO.ThreadHandle()
        push!(handles, handle)
        @test AwsIO.thread_launch(handle, _ -> begin
            put!(started, nothing)
            while !stop_flag[]
                sleep(0.001)
            end
            return nothing
        end, nothing, opts) == AwsIO.OP_SUCCESS
    end
    take!(started)
    take!(started)
    stop_flag[] = true
    @test AwsIO.thread_join_all_managed() == AwsIO.OP_SUCCESS
    @test AwsIO.thread_get_managed_thread_count() == 0
end

@testset "TaskScheduler cancel" begin
    scheduler = AwsIO.TaskScheduler()
    status_ch = Channel{AwsIO.TaskStatus.T}(1)
    task = AwsIO.ScheduledTask((_, status) -> put!(status_ch, status), nothing; type_tag = "task_cancel")
    AwsIO.task_scheduler_cancel!(scheduler, task)
    @test Base.timedwait(() -> isready(status_ch), 5.0) == :ok
    @test take!(status_ch) == AwsIO.TaskStatus.CANCELED
end

@testset "ThreadScheduler" begin
    scheduler = AwsIO.thread_scheduler_new()
    try
        run_status = Channel{AwsIO.TaskStatus.T}(1)
        run_task = AwsIO.ScheduledTask((_, status) -> put!(run_status, status), nothing; type_tag = "thread_scheduler_run")
        AwsIO.thread_scheduler_schedule_now(scheduler, run_task)
        @test Base.timedwait(() -> isready(run_status), 5.0) == :ok
        @test take!(run_status) == AwsIO.TaskStatus.RUN_READY
        cancel_status = Channel{AwsIO.TaskStatus.T}(1)
        cancel_task = AwsIO.ScheduledTask((_, status) -> put!(cancel_status, status), nothing; type_tag = "thread_scheduler_cancel")
        now_ref = Ref{UInt64}(0)
        @test AwsIO.high_res_clock_get_ticks(now_ref) == AwsIO.OP_SUCCESS
        AwsIO.thread_scheduler_schedule_future(scheduler, cancel_task, now_ref[] + UInt64(50_000_000))
        AwsIO.thread_scheduler_cancel_task(scheduler, cancel_task)
        @test Base.timedwait(() -> isready(cancel_status), 5.0) == :ok
        @test take!(cancel_status) == AwsIO.TaskStatus.CANCELED
    finally
        AwsIO.thread_scheduler_release(scheduler)
    end
end

@testset "Byte buffers" begin
    buf_ref = Ref(AwsIO.ByteBuffer(8))
    cur = AwsIO.ByteCursor("hi")
    @test AwsIO.byte_buf_write_from_whole_cursor(buf_ref, cur) == true
    @test buf_ref[].len == 2
    @test String(unsafe_wrap(Vector{UInt8}, pointer(buf_ref[].mem), Int(buf_ref[].len); own = false)) == "hi"
end

@testset "Error handling" begin
    AwsIO._common_init()
    AwsIO.raise_error(AwsIO.ERROR_INVALID_ARGUMENT)
    @test AwsIO.last_error() == AwsIO.ERROR_INVALID_ARGUMENT
end

@testset "UUID" begin
    u = Ref{AwsIO.uuid}()
    @test AwsIO.uuid_init(u) == AwsIO.OP_SUCCESS
    out = Ref(AwsIO.ByteBuffer(AwsIO.UUID_STR_LEN))
    @test AwsIO.uuid_to_str(u, out) == AwsIO.OP_SUCCESS
    @test out[].len == AwsIO.UUID_STR_LEN - 1
end

@testset "byte buffer init from file" begin
    mktemp() do path, io
        write(io, "filedata")
        close(io)

        buf_ref = Ref{AwsIO.ByteBuffer}()
        @test AwsIO.byte_buf_init_from_file(buf_ref, path) == AwsIO.AWS_OP_SUCCESS
        buf = buf_ref[]
        @test buf.len == 8
        @test String(AwsIO.byte_cursor_from_buf(buf)) == "filedata"
        @test buf.mem[Int(buf.len) + 1] == 0x00
    end
end
