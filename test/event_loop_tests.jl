using Test
using AwsIO

const _dispatch_queue_store = Ref{Ptr{Cvoid}}(C_NULL)
function _dispatch_queue_setter(handle::Ptr{AwsIO.IoHandle}, queue::Ptr{Cvoid})
    _dispatch_queue_store[] = queue
    return nothing
end
const _dispatch_queue_setter_c =
    @cfunction(_dispatch_queue_setter, Cvoid, (Ptr{AwsIO.IoHandle}, Ptr{Cvoid}))

const _EVENT_LOOP_TEST_TIMEOUT_NS = 2_000_000_000

function _wait_for_channel(ch::Channel; timeout_ns::Int = _EVENT_LOOP_TEST_TIMEOUT_NS)
    deadline = Base.time_ns() + timeout_ns
    while !isready(ch) && Base.time_ns() < deadline
        yield()
    end
    return isready(ch)
end

function _schedule_event_loop_task(el::AwsIO.EventLoop, fn; type_tag::AbstractString = "event_loop_task")
    done_ch = Channel{Any}(1)
    task_fn = (ctx, status) -> begin
        if status != AwsIO.TaskStatus.RUN_READY
            put!(done_ch, AwsIO.ErrorResult(AwsIO.ERROR_IO_EVENT_LOOP_SHUTDOWN))
            return nothing
        end
        ok = AwsIO.event_loop_thread_is_callers_thread(el)
        result = fn()
        put!(done_ch, (ok, result))
        return nothing
    end
    task = AwsIO.ScheduledTask(task_fn, nothing; type_tag = type_tag)
    AwsIO.event_loop_schedule_task_now!(el, task)
    return done_ch
end

function _payload_abc()
    payload = Memory{UInt8}(undef, 3)
    payload[1] = UInt8('a')
    payload[2] = UInt8('b')
    payload[3] = UInt8('c')
    return payload
end

function _drain_pipe(read_end::AwsIO.PipeReadEnd)
    buf = AwsIO.ByteBuffer(64)
    while true
        res = AwsIO.pipe_read!(read_end, buf)
        if res isa AwsIO.ErrorResult
            return res.code == AwsIO.ERROR_IO_READ_WOULD_BLOCK ? nothing : res
        end
    end
end

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
                interactive_threads = Threads.nthreads(:interactive)
                if interactive_threads <= 1
                    @test true
                    AwsIO.event_loop_destroy!(el)
                else
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    try
                        done = Ref(false)
                        thread_ok = Ref(false)
                        ctx = (el = el, done = done, thread_ok = thread_ok)

                        task_fn = (ctx, status) -> begin
                            ctx.thread_ok[] = AwsIO.event_loop_thread_is_callers_thread(ctx.el)
                            ctx.done[] = true
                            return nothing
                        end

                        task = AwsIO.ScheduledTask(task_fn, ctx; type_tag = "event_loop_test_task")
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
    end

    @testset "Event loop future scheduling timing" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
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
                        actual_time = Ref{UInt64}(0)

                        start_time = AwsIO.event_loop_current_clock_time(el)
                        if start_time isa AwsIO.ErrorResult
                            @test false
                        else
                            target_time = start_time + 50_000_000

                            ctx = (el = el, done = done, actual_time = actual_time)
                            task_fn = (ctx, status) -> begin
                                now = AwsIO.event_loop_current_clock_time(ctx.el)
                                ctx.actual_time[] = now isa AwsIO.ErrorResult ? UInt64(0) : now
                                ctx.done[] = true
                                return nothing
                            end

                            task = AwsIO.ScheduledTask(task_fn, ctx; type_tag = "future_timing")
                            AwsIO.event_loop_schedule_task_future!(el, task, target_time)

                            deadline = Base.time_ns() + 2_000_000_000
                            while !done[] && Base.time_ns() < deadline
                                yield()
                            end

                            @test done[]
                            if done[]
                                @test actual_time[] >= target_time
                                @test actual_time[] - target_time < 1_000_000_000
                            end
                        end
                    finally
                        AwsIO.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop stress scheduling" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                opts = AwsIO.EventLoopOptions()
                el = AwsIO.event_loop_new(opts)
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    try
                        total = 500
                        count = Ref(0)
                        done_ch = Channel{Nothing}(1)
                        count_lock = ReentrantLock()

                        ctx = (count = count, lock = count_lock, done_ch = done_ch, total = total)
                        task_fn = (ctx, status) -> begin
                            local current
                            Base.lock(ctx.lock) do
                                ctx.count[] += 1
                                current = ctx.count[]
                            end
                            if current == ctx.total
                                put!(ctx.done_ch, nothing)
                            end
                            return nothing
                        end

                        for _ in 1:total
                            task = AwsIO.ScheduledTask(task_fn, ctx; type_tag = "stress_now")
                            AwsIO.event_loop_schedule_task_now!(el, task)
                        end

                        deadline = Base.time_ns() + 3_000_000_000
                        while !isready(done_ch) && Base.time_ns() < deadline
                            yield()
                        end

                        @test isready(done_ch)
                        isready(done_ch) && take!(done_ch)
                    finally
                        AwsIO.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop pipe subscribe stress" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                opts = AwsIO.EventLoopOptions()
                el = AwsIO.event_loop_new(opts)
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing

                    try
                        pipe_res = AwsIO.pipe_create()
                        @test !(pipe_res isa AwsIO.ErrorResult)
                        if pipe_res isa AwsIO.ErrorResult
                            return
                        end

                        read_end, write_end = pipe_res

                        payload = Memory{UInt8}(undef, 4)
                        payload[1] = UInt8('p')
                        payload[2] = UInt8('i')
                        payload[3] = UInt8('n')
                        payload[4] = UInt8('g')
                        total_writes = 50
                        expected_bytes = total_writes * length(payload)

                        bytes_read = Ref(0)
                        done = Ref(false)
                        done_ch = Channel{Nothing}(1)
                        read_lock = ReentrantLock()

                        on_readable = (pipe, err, user_data) -> begin
                            if err != AwsIO.AWS_OP_SUCCESS
                                return nothing
                            end

                            buf = AwsIO.ByteBuffer(64)
                            read_res = AwsIO.pipe_read!(pipe, buf)
                            if read_res isa AwsIO.ErrorResult
                                return nothing
                            end

                            _, amount = read_res
                            local total
                            Base.lock(read_lock) do
                                bytes_read[] += Int(amount)
                                total = bytes_read[]
                                if !done[] && total >= expected_bytes
                                    done[] = true
                                    put!(done_ch, nothing)
                                end
                            end

                            return nothing
                        end

                        sub_res = AwsIO.pipe_read_end_subscribe!(read_end, el, on_readable, nothing)
                        @test sub_res === nothing

                        for _ in 1:total_writes
                            write_res = AwsIO.pipe_write_sync!(write_end, payload)
                            @test !(write_res isa AwsIO.ErrorResult)
                        end

                        deadline = Base.time_ns() + 3_000_000_000
                        while !isready(done_ch) && Base.time_ns() < deadline
                            yield()
                        end

                        @test isready(done_ch)
                        isready(done_ch) && take!(done_ch)
                    finally
                        read_end !== nothing && AwsIO.pipe_read_end_close!(read_end)
                        write_end !== nothing && AwsIO.pipe_write_end_close!(write_end)
                        AwsIO.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop subscribe/unsubscribe" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing
                    try
                        pipe_res = AwsIO.pipe_create()
                        @test !(pipe_res isa AwsIO.ErrorResult)
                        if pipe_res isa AwsIO.ErrorResult
                            return
                        end
                        read_end, write_end = pipe_res

                        subscribe_task = _schedule_event_loop_task(el, () -> begin
                            res1 = AwsIO.event_loop_subscribe_to_io_events!(
                                el,
                                read_end.io_handle,
                                Int(AwsIO.IoEventType.READABLE),
                                (loop, handle, events, data) -> nothing,
                                nothing,
                            )
                            res2 = AwsIO.event_loop_subscribe_to_io_events!(
                                el,
                                write_end.io_handle,
                                Int(AwsIO.IoEventType.WRITABLE),
                                (loop, handle, events, data) -> nothing,
                                nothing,
                            )
                            res3 = AwsIO.event_loop_unsubscribe_from_io_events!(el, read_end.io_handle)
                            res4 = AwsIO.event_loop_unsubscribe_from_io_events!(el, write_end.io_handle)
                            return (res1, res2, res3, res4)
                        end; type_tag = "event_loop_subscribe_unsubscribe")

                        @test _wait_for_channel(subscribe_task)
                        ok, results = take!(subscribe_task)
                        @test ok
                        res1, res2, res3, res4 = results
                        @test res1 === nothing
                        @test res2 === nothing
                        @test res3 === nothing
                        @test res4 === nothing
                    finally
                        read_end !== nothing && AwsIO.pipe_read_end_close!(read_end)
                        write_end !== nothing && AwsIO.pipe_write_end_close!(write_end)
                        AwsIO.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop writable event on subscribe" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing
                    try
                        pipe_res = AwsIO.pipe_create()
                        @test !(pipe_res isa AwsIO.ErrorResult)
                        if pipe_res isa AwsIO.ErrorResult
                            return
                        end
                        read_end, write_end = pipe_res

                        writable_count = Ref(0)
                        thread_ok = Ref(true)
                        count_lock = ReentrantLock()
                        writable_ch = Channel{Nothing}(1)

                        on_writable = (loop, handle, events, data) -> begin
                            if !AwsIO.event_loop_thread_is_callers_thread(loop)
                                thread_ok[] = false
                            end
                            if (events & Int(AwsIO.IoEventType.WRITABLE)) == 0
                                return nothing
                            end
                            Base.lock(count_lock) do
                                writable_count[] += 1
                                if writable_count[] == 1 && !isready(writable_ch)
                                    put!(writable_ch, nothing)
                                end
                            end
                            return nothing
                        end

                        sub_task = _schedule_event_loop_task(el, () -> begin
                            return AwsIO.event_loop_subscribe_to_io_events!(
                                el,
                                write_end.io_handle,
                                Int(AwsIO.IoEventType.WRITABLE),
                                on_writable,
                                nothing,
                            )
                        end; type_tag = "event_loop_writable_subscribe")

                        @test _wait_for_channel(sub_task)
                        ok, sub_res = take!(sub_task)
                        @test ok
                        @test sub_res === nothing

                        @test _wait_for_channel(writable_ch; timeout_ns = 3_000_000_000)
                        sleep(1.0)

                        Base.lock(count_lock) do
                            @test writable_count[] == 1
                        end
                        @test thread_ok[]

                        unsub_task = _schedule_event_loop_task(el, () -> begin
                            return AwsIO.event_loop_unsubscribe_from_io_events!(el, write_end.io_handle)
                        end; type_tag = "event_loop_writable_unsubscribe")
                        @test _wait_for_channel(unsub_task)
                        ok2, unsub_res = take!(unsub_task)
                        @test ok2
                        @test unsub_res === nothing
                    finally
                        read_end !== nothing && AwsIO.pipe_read_end_close!(read_end)
                        write_end !== nothing && AwsIO.pipe_write_end_close!(write_end)
                        AwsIO.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop no readable event before write" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing
                    try
                        pipe_res = AwsIO.pipe_create()
                        @test !(pipe_res isa AwsIO.ErrorResult)
                        if pipe_res isa AwsIO.ErrorResult
                            return
                        end
                        read_end, write_end = pipe_res

                        readable_count = Ref(0)
                        count_lock = ReentrantLock()
                        on_readable = (loop, handle, events, data) -> begin
                            if (events & Int(AwsIO.IoEventType.READABLE)) == 0
                                return nothing
                            end
                            Base.lock(count_lock) do
                                readable_count[] += 1
                            end
                            return nothing
                        end

                        sub_task = _schedule_event_loop_task(el, () -> begin
                            return AwsIO.event_loop_subscribe_to_io_events!(
                                el,
                                read_end.io_handle,
                                Int(AwsIO.IoEventType.READABLE),
                                on_readable,
                                nothing,
                            )
                        end; type_tag = "event_loop_readable_subscribe")

                        @test _wait_for_channel(sub_task)
                        ok, sub_res = take!(sub_task)
                        @test ok
                        @test sub_res === nothing

                        sleep(1.0)

                        Base.lock(count_lock) do
                            @test readable_count[] == 0
                        end

                        unsub_task = _schedule_event_loop_task(el, () -> begin
                            return AwsIO.event_loop_unsubscribe_from_io_events!(el, read_end.io_handle)
                        end; type_tag = "event_loop_readable_unsubscribe")
                        @test _wait_for_channel(unsub_task)
                        ok2, unsub_res = take!(unsub_task)
                        @test ok2
                        @test unsub_res === nothing
                    finally
                        read_end !== nothing && AwsIO.pipe_read_end_close!(read_end)
                        write_end !== nothing && AwsIO.pipe_write_end_close!(write_end)
                        AwsIO.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop readable event on subscribe if data present" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing
                    try
                        pipe_res = AwsIO.pipe_create()
                        @test !(pipe_res isa AwsIO.ErrorResult)
                        if pipe_res isa AwsIO.ErrorResult
                            return
                        end
                        read_end, write_end = pipe_res

                        payload = _payload_abc()
                        write_res = AwsIO.pipe_write_sync!(write_end, payload)
                        @test !(write_res isa AwsIO.ErrorResult)

                        readable_count = Ref(0)
                        count_lock = ReentrantLock()
                        readable_ch = Channel{Nothing}(1)

                        on_readable = (loop, handle, events, data) -> begin
                            if (events & Int(AwsIO.IoEventType.READABLE)) == 0
                                return nothing
                            end
                            drain_res = _drain_pipe(read_end)
                            if drain_res isa AwsIO.ErrorResult
                                return nothing
                            end
                            Base.lock(count_lock) do
                                readable_count[] += 1
                                if readable_count[] == 1 && !isready(readable_ch)
                                    put!(readable_ch, nothing)
                                end
                            end
                            return nothing
                        end

                        sub_task = _schedule_event_loop_task(el, () -> begin
                            return AwsIO.event_loop_subscribe_to_io_events!(
                                el,
                                read_end.io_handle,
                                Int(AwsIO.IoEventType.READABLE),
                                on_readable,
                                nothing,
                            )
                        end; type_tag = "event_loop_readable_subscribe_present")

                        @test _wait_for_channel(sub_task)
                        ok, sub_res = take!(sub_task)
                        @test ok
                        @test sub_res === nothing

                        @test _wait_for_channel(readable_ch; timeout_ns = 3_000_000_000)
                        sleep(1.0)

                        Base.lock(count_lock) do
                            @test readable_count[] == 1
                        end

                        unsub_task = _schedule_event_loop_task(el, () -> begin
                            return AwsIO.event_loop_unsubscribe_from_io_events!(el, read_end.io_handle)
                        end; type_tag = "event_loop_readable_unsubscribe_present")
                        @test _wait_for_channel(unsub_task)
                        ok2, unsub_res = take!(unsub_task)
                        @test ok2
                        @test unsub_res === nothing
                    finally
                        read_end !== nothing && AwsIO.pipe_read_end_close!(read_end)
                        write_end !== nothing && AwsIO.pipe_write_end_close!(write_end)
                        AwsIO.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop readable event after write" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing
                    try
                        pipe_res = AwsIO.pipe_create()
                        @test !(pipe_res isa AwsIO.ErrorResult)
                        if pipe_res isa AwsIO.ErrorResult
                            return
                        end
                        read_end, write_end = pipe_res

                        writable_ch = Channel{Nothing}(1)
                        readable_ch = Channel{Nothing}(1)
                        readable_count = Ref(0)
                        count_lock = ReentrantLock()

                        on_writable = (loop, handle, events, data) -> begin
                            if (events & Int(AwsIO.IoEventType.WRITABLE)) == 0
                                return nothing
                            end
                            if !isready(writable_ch)
                                put!(writable_ch, nothing)
                            end
                            return nothing
                        end

                        on_readable = (loop, handle, events, data) -> begin
                            if (events & Int(AwsIO.IoEventType.READABLE)) == 0
                                return nothing
                            end
                            drain_res = _drain_pipe(read_end)
                            if drain_res isa AwsIO.ErrorResult
                                return nothing
                            end
                            Base.lock(count_lock) do
                                readable_count[] += 1
                                if readable_count[] == 1 && !isready(readable_ch)
                                    put!(readable_ch, nothing)
                                end
                            end
                            return nothing
                        end

                        sub_task = _schedule_event_loop_task(el, () -> begin
                            res1 = AwsIO.event_loop_subscribe_to_io_events!(
                                el,
                                write_end.io_handle,
                                Int(AwsIO.IoEventType.WRITABLE),
                                on_writable,
                                nothing,
                            )
                            res2 = AwsIO.event_loop_subscribe_to_io_events!(
                                el,
                                read_end.io_handle,
                                Int(AwsIO.IoEventType.READABLE),
                                on_readable,
                                nothing,
                            )
                            return (res1, res2)
                        end; type_tag = "event_loop_readable_after_write_sub")

                        @test _wait_for_channel(sub_task)
                        ok, results = take!(sub_task)
                        @test ok
                        res1, res2 = results
                        @test res1 === nothing
                        @test res2 === nothing

                        @test _wait_for_channel(writable_ch; timeout_ns = 3_000_000_000)
                        payload = _payload_abc()
                        write_res = AwsIO.pipe_write_sync!(write_end, payload)
                        @test !(write_res isa AwsIO.ErrorResult)

                        @test _wait_for_channel(readable_ch; timeout_ns = 3_000_000_000)
                        sleep(1.0)

                        Base.lock(count_lock) do
                            @test readable_count[] == 1
                        end

                        unsub_task = _schedule_event_loop_task(el, () -> begin
                            res1 = AwsIO.event_loop_unsubscribe_from_io_events!(el, write_end.io_handle)
                            res2 = AwsIO.event_loop_unsubscribe_from_io_events!(el, read_end.io_handle)
                            return (res1, res2)
                        end; type_tag = "event_loop_readable_after_write_unsub")
                        @test _wait_for_channel(unsub_task)
                        ok2, results2 = take!(unsub_task)
                        @test ok2
                        r1, r2 = results2
                        @test r1 === nothing
                        @test r2 === nothing
                    finally
                        read_end !== nothing && AwsIO.pipe_read_end_close!(read_end)
                        write_end !== nothing && AwsIO.pipe_write_end_close!(write_end)
                        AwsIO.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop readable event on 2nd time readable" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing
                    try
                        pipe_res = AwsIO.pipe_create()
                        @test !(pipe_res isa AwsIO.ErrorResult)
                        if pipe_res isa AwsIO.ErrorResult
                            return
                        end
                        read_end, write_end = pipe_res

                        writable_ch = Channel{Nothing}(1)
                        first_readable_ch = Channel{Nothing}(1)
                        second_readable_ch = Channel{Nothing}(1)
                        readable_count = Ref(0)
                        count_lock = ReentrantLock()

                        on_writable = (loop, handle, events, data) -> begin
                            if (events & Int(AwsIO.IoEventType.WRITABLE)) == 0
                                return nothing
                            end
                            if !isready(writable_ch)
                                put!(writable_ch, nothing)
                            end
                            return nothing
                        end

                        on_readable = (loop, handle, events, data) -> begin
                            if (events & Int(AwsIO.IoEventType.READABLE)) == 0
                                return nothing
                            end
                            drain_res = _drain_pipe(read_end)
                            if drain_res isa AwsIO.ErrorResult
                                return nothing
                            end
                            Base.lock(count_lock) do
                                readable_count[] += 1
                                if readable_count[] == 1 && !isready(first_readable_ch)
                                    put!(first_readable_ch, nothing)
                                elseif readable_count[] == 2 && !isready(second_readable_ch)
                                    put!(second_readable_ch, nothing)
                                end
                            end
                            return nothing
                        end

                        sub_task = _schedule_event_loop_task(el, () -> begin
                            res1 = AwsIO.event_loop_subscribe_to_io_events!(
                                el,
                                write_end.io_handle,
                                Int(AwsIO.IoEventType.WRITABLE),
                                on_writable,
                                nothing,
                            )
                            res2 = AwsIO.event_loop_subscribe_to_io_events!(
                                el,
                                read_end.io_handle,
                                Int(AwsIO.IoEventType.READABLE),
                                on_readable,
                                nothing,
                            )
                            return (res1, res2)
                        end; type_tag = "event_loop_readable_second_sub")

                        @test _wait_for_channel(sub_task)
                        ok, results = take!(sub_task)
                        @test ok
                        r1, r2 = results
                        @test r1 === nothing
                        @test r2 === nothing

                        @test _wait_for_channel(writable_ch; timeout_ns = 3_000_000_000)
                        payload = _payload_abc()
                        write_res = AwsIO.pipe_write_sync!(write_end, payload)
                        @test !(write_res isa AwsIO.ErrorResult)

                        @test _wait_for_channel(first_readable_ch; timeout_ns = 3_000_000_000)
                        payload2 = _payload_abc()
                        write_res2 = AwsIO.pipe_write_sync!(write_end, payload2)
                        @test !(write_res2 isa AwsIO.ErrorResult)

                        @test _wait_for_channel(second_readable_ch; timeout_ns = 3_000_000_000)

                        Base.lock(count_lock) do
                            @test readable_count[] == 2
                        end

                        unsub_task = _schedule_event_loop_task(el, () -> begin
                            res1 = AwsIO.event_loop_unsubscribe_from_io_events!(el, write_end.io_handle)
                            res2 = AwsIO.event_loop_unsubscribe_from_io_events!(el, read_end.io_handle)
                            return (res1, res2)
                        end; type_tag = "event_loop_readable_second_unsub")
                        @test _wait_for_channel(unsub_task)
                        ok2, results2 = take!(unsub_task)
                        @test ok2
                        r1b, r2b = results2
                        @test r1b === nothing
                        @test r2b === nothing
                    finally
                        read_end !== nothing && AwsIO.pipe_read_end_close!(read_end)
                        write_end !== nothing && AwsIO.pipe_write_end_close!(write_end)
                        AwsIO.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop no events after unsubscribe" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    read_ends = nothing
                    write_ends = nothing
                    try
                        pipe1 = AwsIO.pipe_create()
                        pipe2 = AwsIO.pipe_create()
                        @test !(pipe1 isa AwsIO.ErrorResult)
                        @test !(pipe2 isa AwsIO.ErrorResult)
                        if pipe1 isa AwsIO.ErrorResult || pipe2 isa AwsIO.ErrorResult
                            return
                        end
                        read_ends = (pipe1[1], pipe2[1])
                        write_ends = (pipe1[2], pipe2[2])

                        done_ch = Channel{Nothing}(1)
                        state_lock = ReentrantLock()
                        writable = Memory{Bool}(undef, 2)
                        writable[1] = false
                        writable[2] = false
                        wrote_both = Ref(false)
                        unsubscribed = Ref(false)
                        error_flag = Ref(false)

                        on_writable = (loop, handle, events, data) -> begin
                            if (events & Int(AwsIO.IoEventType.WRITABLE)) == 0
                                return nothing
                            end
                            Base.lock(state_lock) do
                                if unsubscribed[]
                                    error_flag[] = true
                                    if !isready(done_ch)
                                        put!(done_ch, nothing)
                                    end
                                    return nothing
                                end

                                for i in 1:2
                                    if handle.fd == write_ends[i].io_handle.fd
                                        writable[i] = true
                                    end
                                end

                                if wrote_both[] || !(writable[1] && writable[2])
                                    return nothing
                                end

                                for i in 1:2
                                    payload = _payload_abc()
                                    write_res = AwsIO.pipe_write_sync!(write_ends[i], payload)
                                    if write_res isa AwsIO.ErrorResult
                                        error_flag[] = true
                                        if !isready(done_ch)
                                            put!(done_ch, nothing)
                                        end
                                        return nothing
                                    end
                                end
                                wrote_both[] = true
                            end
                            return nothing
                        end

                        on_readable = (loop, handle, events, data) -> begin
                            if (events & Int(AwsIO.IoEventType.READABLE)) == 0
                                return nothing
                            end
                            Base.lock(state_lock) do
                                if unsubscribed[]
                                    error_flag[] = true
                                    if !isready(done_ch)
                                        put!(done_ch, nothing)
                                    end
                                    return nothing
                                end

                                for i in 1:2
                                    _ = AwsIO.event_loop_unsubscribe_from_io_events!(el, read_ends[i].io_handle)
                                    _ = AwsIO.event_loop_unsubscribe_from_io_events!(el, write_ends[i].io_handle)
                                    AwsIO.pipe_read_end_close!(read_ends[i])
                                    AwsIO.pipe_write_end_close!(write_ends[i])
                                end

                                unsubscribed[] = true
                            end

                            now = AwsIO.event_loop_current_clock_time(el)
                            if !(now isa AwsIO.ErrorResult)
                                run_at = now + 1_000_000_000
                                done_task = AwsIO.ScheduledTask(
                                    (ctx, status) -> begin
                                        if !isready(done_ch)
                                            put!(done_ch, nothing)
                                        end
                                        return nothing
                                    end,
                                    nothing;
                                    type_tag = "unsubrace_done",
                                )
                                AwsIO.event_loop_schedule_task_future!(el, done_task, run_at)
                            else
                                if !isready(done_ch)
                                    put!(done_ch, nothing)
                                end
                            end
                            return nothing
                        end

                        setup_task = _schedule_event_loop_task(el, () -> begin
                            for i in 1:2
                                _ = AwsIO.event_loop_subscribe_to_io_events!(
                                    el,
                                    write_ends[i].io_handle,
                                    Int(AwsIO.IoEventType.WRITABLE),
                                    on_writable,
                                    nothing,
                                )
                                _ = AwsIO.event_loop_subscribe_to_io_events!(
                                    el,
                                    read_ends[i].io_handle,
                                    Int(AwsIO.IoEventType.READABLE),
                                    on_readable,
                                    nothing,
                                )
                            end
                            return nothing
                        end; type_tag = "unsubrace_setup")

                        @test _wait_for_channel(setup_task)
                        _ = take!(setup_task)

                        @test _wait_for_channel(done_ch; timeout_ns = 5_000_000_000)
                        @test !error_flag[]
                    finally
                        if read_ends !== nothing && write_ends !== nothing
                            for i in 1:2
                                AwsIO.pipe_read_end_close!(read_ends[i])
                                AwsIO.pipe_write_end_close!(write_ends[i])
                            end
                        end
                        AwsIO.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop group thread affinity" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 2
                @test true
            else
                opts = AwsIO.EventLoopGroupOptions(loop_count = 2)
                elg = AwsIO.event_loop_group_new(opts)
                @test !(elg isa AwsIO.ErrorResult)

                if !(elg isa AwsIO.ErrorResult)
                    try
                        loop1 = AwsIO.event_loop_group_get_next_loop(elg)
                        loop2 = AwsIO.event_loop_group_get_next_loop(elg)

                        @test loop1 !== loop2

                        ids1 = Int[]
                        ids2 = Int[]
                        lock = ReentrantLock()
                        done_ch = Channel{Nothing}(1)
                        done_count = Ref(0)
                        total = 4

                        task_fn = (ctx, status) -> begin
                            Base.lock(lock) do
                                push!(ctx.ids, Threads.threadid())
                                done_count[] += 1
                                if done_count[] == total
                                    put!(done_ch, nothing)
                                end
                            end
                            return nothing
                        end

                        for _ in 1:2
                            task1 = AwsIO.ScheduledTask(task_fn, (ids = ids1,); type_tag = "elg_affinity")
                            AwsIO.event_loop_schedule_task_now!(loop1, task1)

                            task2 = AwsIO.ScheduledTask(task_fn, (ids = ids2,); type_tag = "elg_affinity")
                            AwsIO.event_loop_schedule_task_now!(loop2, task2)
                        end

                        deadline = Base.time_ns() + 3_000_000_000
                        while !isready(done_ch) && Base.time_ns() < deadline
                            yield()
                        end

                        @test isready(done_ch)
                        isready(done_ch) && take!(done_ch)

                        Base.lock(lock) do
                            @test !isempty(ids1)
                            @test !isempty(ids2)
                            @test all(==(ids1[1]), ids1)
                            @test all(==(ids2[1]), ids2)
                        end
                    finally
                        AwsIO.event_loop_group_destroy!(elg)
                    end
                end
            end
        end
    end

    @testset "IoHandle additional_data parity" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                opts = AwsIO.EventLoopOptions()
                el = AwsIO.event_loop_new(opts)
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing

                    try
                        pipe_res = AwsIO.pipe_create()
                        @test !(pipe_res isa AwsIO.ErrorResult)
                        if pipe_res isa AwsIO.ErrorResult
                            return
                        end

                        read_end, write_end = pipe_res

                        sub_res = AwsIO.event_loop_subscribe_to_io_events!(
                            el,
                            read_end.io_handle,
                            Int(AwsIO.IoEventType.READABLE),
                            (loop, handle, events, data) -> nothing,
                            nothing,
                        )
                        @test sub_res === nothing
                        @test read_end.io_handle.additional_data != C_NULL

                        done_ch = Channel{Nothing}(1)
                        unsub_ctx = (el = el, handle = read_end.io_handle, done_ch = done_ch)
                        unsub_fn = (ctx, status) -> begin
                            AwsIO.event_loop_unsubscribe_from_io_events!(ctx.el, ctx.handle)
                            put!(ctx.done_ch, nothing)
                            return nothing
                        end
                        unsub_task = AwsIO.ScheduledTask(unsub_fn, unsub_ctx; type_tag = "handle_unsubscribe")
                        AwsIO.event_loop_schedule_task_now!(el, unsub_task)

                        deadline = Base.time_ns() + 2_000_000_000
                        while !isready(done_ch) && Base.time_ns() < deadline
                            yield()
                        end

                        @test isready(done_ch)
                        isready(done_ch) && take!(done_ch)
                        @test read_end.io_handle.additional_data == C_NULL
                    finally
                        read_end !== nothing && AwsIO.pipe_read_end_close!(read_end)
                        write_end !== nothing && AwsIO.pipe_write_end_close!(write_end)
                        AwsIO.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop unsubscribe error" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                opts = AwsIO.EventLoopOptions()
                el = AwsIO.event_loop_new(opts)
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    try
                        done_ch = Channel{Int}(1)
                        ctx = (el = el, handle = AwsIO.IoHandle(), done_ch = done_ch)
                        task_fn = (ctx, status) -> begin
                            res = AwsIO.event_loop_unsubscribe_from_io_events!(ctx.el, ctx.handle)
                            code = res isa AwsIO.ErrorResult ? AwsIO.last_error() : 0
                            put!(ctx.done_ch, code)
                            return nothing
                        end
                        task = AwsIO.ScheduledTask(task_fn, ctx; type_tag = "unsubscribe_error")
                        AwsIO.event_loop_schedule_task_now!(el, task)

                        deadline = Base.time_ns() + 2_000_000_000
                        while !isready(done_ch) && Base.time_ns() < deadline
                            yield()
                        end

                        @test isready(done_ch)
                        if isready(done_ch)
                            code = take!(done_ch)
                            @test code == AwsIO.ERROR_IO_NOT_SUBSCRIBED
                        end
                    finally
                        AwsIO.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop syscall error mapping" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                opts = AwsIO.EventLoopOptions()
                el = AwsIO.event_loop_new(opts)
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing

                    try
                        pipe_res = AwsIO.pipe_create()
                        @test !(pipe_res isa AwsIO.ErrorResult)
                        if pipe_res isa AwsIO.ErrorResult
                            return
                        end

                        read_end, write_end = pipe_res
                        bad_fd = read_end.io_handle.fd
                        ccall(:close, Cint, (Cint,), bad_fd)
                        read_end.io_handle.fd = -1
                        bad_handle = AwsIO.IoHandle(bad_fd)

                        if Sys.islinux()
                            res = AwsIO.event_loop_subscribe_to_io_events!(
                                el,
                                bad_handle,
                                Int(AwsIO.IoEventType.READABLE),
                                (loop, handle, events, data) -> nothing,
                                nothing,
                            )
                            @test res isa AwsIO.ErrorResult
                            res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_SYS_CALL_FAILURE
                        elseif Sys.isapple()
                            done_ch = Channel{Int}(1)
                            on_event = (loop, handle, events, data) -> begin
                                _ = AwsIO.event_loop_unsubscribe_from_io_events!(loop, handle)
                                put!(done_ch, events)
                                return nothing
                            end
                            res = AwsIO.event_loop_subscribe_to_io_events!(
                                el,
                                bad_handle,
                                Int(AwsIO.IoEventType.READABLE),
                                on_event,
                                nothing,
                            )
                            @test res === nothing

                            deadline = Base.time_ns() + 2_000_000_000
                            while !isready(done_ch) && Base.time_ns() < deadline
                                yield()
                            end

                            @test isready(done_ch)
                            if isready(done_ch)
                                events = take!(done_ch)
                                @test (events & Int(AwsIO.IoEventType.ERROR)) != 0
                            end
                        else
                            @test true
                        end
                    finally
                        read_end !== nothing && AwsIO.pipe_read_end_close!(read_end)
                        write_end !== nothing && AwsIO.pipe_write_end_close!(write_end)
                        AwsIO.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop serialized ordering" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                opts = AwsIO.EventLoopOptions()
                el = AwsIO.event_loop_new(opts)
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    try
                        order = Int[]
                        order_lock = ReentrantLock()
                        done_ch = Channel{Nothing}(1)
                        total = 5

                        for i in 1:total
                            ctx = (order = order, lock = order_lock, done_ch = done_ch, i = i, total = total)
                            task_fn = (ctx, status) -> begin
                                local count
                                Base.lock(ctx.lock) do
                                    push!(ctx.order, ctx.i)
                                    count = length(ctx.order)
                                end
                                if count == ctx.total
                                    put!(ctx.done_ch, nothing)
                                end
                                return nothing
                            end
                            task = AwsIO.ScheduledTask(task_fn, ctx; type_tag = "serialized_order")
                            AwsIO.event_loop_schedule_task_now_serialized!(el, task)
                        end

                        deadline = Base.time_ns() + 2_000_000_000
                        while !isready(done_ch) && Base.time_ns() < deadline
                            yield()
                        end

                        @test isready(done_ch)
                        isready(done_ch) && take!(done_ch)
                        Base.lock(order_lock) do
                            @test order == collect(1:total)
                        end
                    finally
                        AwsIO.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop cancel task" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                opts = AwsIO.EventLoopOptions()
                el = AwsIO.event_loop_new(opts)
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    try
                        status_ch = Channel{Tuple{AwsIO.TaskStatus.T, Bool}}(1)
                        ctx = (el = el, status_ch = status_ch)
                        future_fn = (ctx, status) -> begin
                            put!(ctx.status_ch, (status, AwsIO.event_loop_thread_is_callers_thread(ctx.el)))
                            return nothing
                        end
                        future_task = AwsIO.ScheduledTask(future_fn, ctx; type_tag = "future_task")

                        now = AwsIO.event_loop_current_clock_time(el)
                        if now isa AwsIO.ErrorResult
                            @test false
                        else
                            AwsIO.event_loop_schedule_task_future!(el, future_task, now + 10_000_000_000)

                            cancel_ctx = (el = el, task = future_task)
                            cancel_fn = (ctx, status) -> begin
                                AwsIO.event_loop_cancel_task!(ctx.el, ctx.task)
                                return nothing
                            end
                            cancel_task = AwsIO.ScheduledTask(cancel_fn, cancel_ctx; type_tag = "cancel_task")
                            AwsIO.event_loop_schedule_task_now!(el, cancel_task)

                            deadline = Base.time_ns() + 2_000_000_000
                            while !isready(status_ch) && Base.time_ns() < deadline
                                yield()
                            end

                            @test isready(status_ch)
                            if isready(status_ch)
                                status, thread_ok = take!(status_ch)
                                @test status == AwsIO.TaskStatus.CANCELED
                                @test thread_ok
                            end
                        end
                    finally
                        AwsIO.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop destroy cancels pending task" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                opts = AwsIO.EventLoopOptions()
                el = AwsIO.event_loop_new(opts)
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    status_ch = Channel{AwsIO.TaskStatus.T}(1)
                    ctx = (status_ch = status_ch,)
                    future_fn = (ctx, status) -> begin
                        put!(ctx.status_ch, status)
                        return nothing
                    end
                    future_task = AwsIO.ScheduledTask(future_fn, ctx; type_tag = "future_task_destroy")

                    now = AwsIO.event_loop_current_clock_time(el)
                    if now isa AwsIO.ErrorResult
                        @test false
                    else
                        AwsIO.event_loop_schedule_task_future!(el, future_task, now + 10_000_000_000)
                        AwsIO.event_loop_destroy!(el)

                        @test isready(status_ch)
                        if isready(status_ch)
                            status = take!(status_ch)
                            @test status == AwsIO.TaskStatus.CANCELED
                        end
                    end
                end
            end
        end
    end

    @testset "Event loop group" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            opts = AwsIO.EventLoopGroupOptions(loop_count = 1)
            elg = AwsIO.event_loop_group_new(opts)
            if interactive_threads <= 1
                @test elg isa AwsIO.ErrorResult
            else
                @test !(elg isa AwsIO.ErrorResult)

                if !(elg isa AwsIO.ErrorResult)
                    try
                        @test AwsIO.event_loop_group_get_loop_count(elg) == 1
                        el = AwsIO.event_loop_group_get_next_loop(elg)
                        @test el !== nothing
                        if el !== nothing
                            acquired = AwsIO.event_loop_group_acquire_from_event_loop(el)
                            @test acquired === elg
                            AwsIO.event_loop_group_release_from_event_loop!(el)
                        end
                    finally
                        AwsIO.event_loop_group_destroy!(elg)
                    end
                end
            end

            if interactive_threads > 1
                bad_opts = AwsIO.EventLoopGroupOptions(loop_count = interactive_threads)
                bad_elg = AwsIO.event_loop_group_new(bad_opts)
                @test bad_elg isa AwsIO.ErrorResult
            end
        end
    end

    @testset "Event loop group async shutdown" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                shutdown_ch = Channel{Bool}(1)
                shutdown_opts = AwsIO.shutdown_callback_options(
                    (ud) -> begin
                        put!(shutdown_ch, true)
                        return nothing
                    end,
                    nothing,
                )

                opts = AwsIO.EventLoopGroupOptions(loop_count = 1, shutdown_options = shutdown_opts)
                elg = AwsIO.event_loop_group_new(opts)
                @test !(elg isa AwsIO.ErrorResult)
                if elg isa AwsIO.ErrorResult
                    return
                end

                done = false
                try
                    el = AwsIO.event_loop_group_get_next_loop(elg)
                    @test el !== nothing
                    if el === nothing
                        return
                    end

                    release_task = AwsIO.ScheduledTask(
                        (ctx, status) -> begin
                            AwsIO.event_loop_group_release!(ctx.elg)
                            return nothing
                        end,
                        (elg = elg,);
                        type_tag = "elg_release_async",
                    )
                    AwsIO.event_loop_schedule_task_now!(el, release_task)
                    done = _wait_for_channel(shutdown_ch)
                    @test done
                finally
                    if !done
                        AwsIO.event_loop_group_destroy!(elg)
                    end
                end
            end
        end
    end

    @testset "Event loop creation types" begin
        if Sys.iswindows()
            @test true
        elseif Sys.islinux()
            el_epoll = AwsIO.event_loop_new(AwsIO.EventLoopOptions(type = AwsIO.EventLoopType.EPOLL))
            @test !(el_epoll isa AwsIO.ErrorResult)
            el_epoll isa AwsIO.ErrorResult || AwsIO.event_loop_destroy!(el_epoll)

            el_kqueue = AwsIO.event_loop_new(AwsIO.EventLoopOptions(type = AwsIO.EventLoopType.KQUEUE))
            @test el_kqueue isa AwsIO.ErrorResult

            el_dispatch = AwsIO.event_loop_new(AwsIO.EventLoopOptions(type = AwsIO.EventLoopType.DISPATCH_QUEUE))
            @test el_dispatch isa AwsIO.ErrorResult
        elseif Sys.isapple() || Sys.isbsd()
            el_kqueue = AwsIO.event_loop_new(AwsIO.EventLoopOptions(type = AwsIO.EventLoopType.KQUEUE))
            @test !(el_kqueue isa AwsIO.ErrorResult)
            el_kqueue isa AwsIO.ErrorResult || AwsIO.event_loop_destroy!(el_kqueue)

            el_dispatch = AwsIO.event_loop_new(AwsIO.EventLoopOptions(type = AwsIO.EventLoopType.DISPATCH_QUEUE))
            if Sys.isapple()
                @test !(el_dispatch isa AwsIO.ErrorResult)
                el_dispatch isa AwsIO.ErrorResult || AwsIO.event_loop_destroy!(el_dispatch)
            else
                @test el_dispatch isa AwsIO.ErrorResult
            end

            el_epoll = AwsIO.event_loop_new(AwsIO.EventLoopOptions(type = AwsIO.EventLoopType.EPOLL))
            @test el_epoll isa AwsIO.ErrorResult
        else
            @test true
        end
    end

    @testset "Event loop stop then restart" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    done1 = Channel{Bool}(1)
                    task1 = AwsIO.ScheduledTask((ctx, status) -> begin
                        if status == AwsIO.TaskStatus.RUN_READY
                            put!(done1, AwsIO.event_loop_thread_is_callers_thread(el))
                        end
                        return nothing
                    end, nothing; type_tag = "event_loop_stop_restart_first")
                    AwsIO.event_loop_schedule_task_now!(el, task1)
                    @test _wait_for_channel(done1)
                    @test take!(done1)

                    @test AwsIO.event_loop_stop!(el) === nothing
                    @test AwsIO.event_loop_wait_for_stop_completion!(el) === nothing
                    @test AwsIO.event_loop_run!(el) === nothing

                    done2 = Channel{Bool}(1)
                    task2 = AwsIO.ScheduledTask((ctx, status) -> begin
                        if status == AwsIO.TaskStatus.RUN_READY
                            put!(done2, AwsIO.event_loop_thread_is_callers_thread(el))
                        end
                        return nothing
                    end, nothing; type_tag = "event_loop_stop_restart_second")
                    AwsIO.event_loop_schedule_task_now!(el, task2)
                    @test _wait_for_channel(done2)
                    @test take!(done2)

                    AwsIO.event_loop_destroy!(el)
                end
            end
        end
    end

    @testset "Event loop multiple stops" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    for _ in 1:8
                        @test AwsIO.event_loop_stop!(el) === nothing
                    end

                    AwsIO.event_loop_destroy!(el)
                end
            end
        end
    end

    @testset "Event loop group setup and shutdown" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            cpu_threads = Sys.CPU_THREADS
            expected = cpu_threads > 1 ? cpu_threads ÷ 2 : cpu_threads

            opts = AwsIO.EventLoopGroupOptions(loop_count = 0)
            elg = AwsIO.event_loop_group_new(opts)

            if interactive_threads <= 1 || expected >= interactive_threads
                @test elg isa AwsIO.ErrorResult
            else
                @test !(elg isa AwsIO.ErrorResult)
                if !(elg isa AwsIO.ErrorResult)
                    try
                        @test AwsIO.event_loop_group_get_loop_count(elg) == expected
                        loop = AwsIO.event_loop_group_get_next_loop(elg)
                        @test loop !== nothing
                    finally
                        AwsIO.event_loop_group_destroy!(elg)
                    end
                end
            end
        end
    end

    @testset "Event loop group shutdown callback" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                shutdown_called = Ref(false)
                shutdown_thread = Ref(0)
                done_ch = Channel{Nothing}(1)

                shutdown_opts = AwsIO.shutdown_callback_options(
                    (user_data) -> begin
                        shutdown_called[] = true
                        shutdown_thread[] = Threads.threadid()
                        if !isready(done_ch)
                            put!(done_ch, nothing)
                        end
                        return nothing
                    end,
                    nothing,
                )

                elg = AwsIO.event_loop_group_new(AwsIO.EventLoopGroupOptions(loop_count = 1, shutdown_options = shutdown_opts))
                @test !(elg isa AwsIO.ErrorResult)

                if !(elg isa AwsIO.ErrorResult)
                    AwsIO.event_loop_group_destroy!(elg)
                    @test _wait_for_channel(done_ch)
                    @test shutdown_called[]
                    @test shutdown_thread[] != 0
                end
            end
        end
    end

    @testset "Event loop local objects" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                opts = AwsIO.EventLoopOptions()
                el = AwsIO.event_loop_new(opts)
                @test !(el isa AwsIO.ErrorResult)

                if !(el isa AwsIO.ErrorResult)
                    run_res = AwsIO.event_loop_run!(el)
                    @test run_res === nothing

                    done = Ref(false)
                    done_cleanup = Ref(false)
                    missing_err1 = Ref(0)
                    missing_err2 = Ref(0)
                    removed_calls = Ref(0)
                    cleanup_calls = Ref(0)
                    fetched_value = Ref{Any}(nothing)
                    removed_value = Ref{Any}(nothing)

                    key_obj = Ref(0)
                    key = pointer_from_objref(key_obj)

                    ctx = (
                        el = el,
                        key = key,
                        missing_err1 = missing_err1,
                        missing_err2 = missing_err2,
                        removed_calls = removed_calls,
                        fetched_value = fetched_value,
                        removed_value = removed_value,
                        done = done,
                    )

                    task_fn = (ctx, status) -> begin
                        res = AwsIO.event_loop_fetch_local_object(ctx.el, ctx.key)
                        if res isa AwsIO.ErrorResult
                            ctx.missing_err1[] = AwsIO.last_error()
                        end

                        on_removed = obj -> (ctx.removed_calls[] += 1)
                        obj1 = AwsIO.EventLoopLocalObject(ctx.key, "one", on_removed)
                        AwsIO.event_loop_put_local_object!(ctx.el, obj1)

                        obj2 = AwsIO.EventLoopLocalObject(ctx.key, "two", on_removed)
                        AwsIO.event_loop_put_local_object!(ctx.el, obj2)

                        fetched = AwsIO.event_loop_fetch_local_object(ctx.el, ctx.key)
                        if !(fetched isa AwsIO.ErrorResult)
                            ctx.fetched_value[] = fetched.object
                        end

                        removed_obj = AwsIO.event_loop_remove_local_object!(ctx.el, ctx.key)
                        if removed_obj !== nothing
                            ctx.removed_value[] = removed_obj.object
                        end

                        res2 = AwsIO.event_loop_fetch_local_object(ctx.el, ctx.key)
                        if res2 isa AwsIO.ErrorResult
                            ctx.missing_err2[] = AwsIO.last_error()
                        end

                        ctx.done[] = true
                        return nothing
                    end

                    task = AwsIO.ScheduledTask(task_fn, ctx; type_tag = "event_loop_local_object_test")
                    AwsIO.event_loop_schedule_task_now!(el, task)

                    deadline = Base.time_ns() + 2_000_000_000
                    while !done[] && Base.time_ns() < deadline
                        yield()
                    end

                    @test done[]
                    @test missing_err1[] == AwsIO.ERROR_INVALID_ARGUMENT
                    @test missing_err2[] == AwsIO.ERROR_INVALID_ARGUMENT
                    @test fetched_value[] == "two"
                    @test removed_value[] == "two"
                    @test removed_calls[] == 1

                    cleanup_ctx = (
                        el = el,
                        key = key,
                        cleanup_calls = cleanup_calls,
                        done_cleanup = done_cleanup,
                    )

                    cleanup_task_fn = (ctx, status) -> begin
                        on_removed = obj -> (ctx.cleanup_calls[] += 1)
                        obj = AwsIO.EventLoopLocalObject(ctx.key, "cleanup", on_removed)
                        AwsIO.event_loop_put_local_object!(ctx.el, obj)
                        ctx.done_cleanup[] = true
                        return nothing
                    end

                    cleanup_task = AwsIO.ScheduledTask(cleanup_task_fn, cleanup_ctx; type_tag = "event_loop_local_object_cleanup")
                    AwsIO.event_loop_schedule_task_now!(el, cleanup_task)

                    deadline = Base.time_ns() + 2_000_000_000
                    while !done_cleanup[] && Base.time_ns() < deadline
                        yield()
                    end

                    @test done_cleanup[]

                    AwsIO.event_loop_destroy!(el)
                    @test cleanup_calls[] == 1
                end
            end
        end
    end

    @testset "Event loop load factor" begin
        times = UInt64[1_000_000_000, 1_000_000_500, 12_000_000_000]
        idx = Ref(0)
        clock = () -> begin
            idx[] += 1
            return idx[] <= length(times) ? times[idx[]] : times[end]
        end

        struct DummyImpl end
        el = AwsIO.EventLoop(clock, DummyImpl())

        AwsIO.event_loop_register_tick_start!(el)
        AwsIO.event_loop_register_tick_end!(el)

        # Force stale state and confirm load factor reports 0
        @atomic el.next_flush_time = UInt64(0)
        @test AwsIO.event_loop_get_load_factor(el) == 0
    end

    @testset "Event loop clock override" begin
        if Sys.iswindows()
            @test true
        else
            clock_calls = Ref(0)
            clock = () -> begin
                clock_calls[] += 1
                return UInt64(42)
            end

            opts = AwsIO.EventLoopOptions(clock = clock)
            el = AwsIO.event_loop_new(opts)
            @test !(el isa AwsIO.ErrorResult)

            if !(el isa AwsIO.ErrorResult)
                @test AwsIO.event_loop_current_clock_time(el) == UInt64(42)
            end

            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads > 1
                group_opts = AwsIO.EventLoopGroupOptions(loop_count = 1, clock_override = clock)
                elg = AwsIO.event_loop_group_new(group_opts)
                @test !(elg isa AwsIO.ErrorResult)

                if !(elg isa AwsIO.ErrorResult)
                    try
                        loop = AwsIO.event_loop_group_get_next_loop(elg)
                        @test loop !== nothing
                        if loop !== nothing
                            @test AwsIO.event_loop_current_clock_time(loop) == UInt64(42)
                        end
                    finally
                        AwsIO.event_loop_group_destroy!(elg)
                    end
                end
            end

            @test clock_calls[] >= 1
        end
    end

    @testset "Event loop group thread constraint" begin
        interactive_threads = Threads.nthreads(:interactive)
        if interactive_threads > 0
            opts = AwsIO.EventLoopGroupOptions(loop_count = UInt16(interactive_threads))
            elg = AwsIO.event_loop_group_new(opts)
            @test elg isa AwsIO.ErrorResult
            if elg isa AwsIO.ErrorResult
                @test elg.code == AwsIO.ERROR_THREAD_INVALID_SETTINGS
            end
        end
    end

    @testset "Epoll task pre-queue drain" begin
        if !Sys.islinux()
            @test true
        else
            opts = AwsIO.EventLoopOptions(type = AwsIO.EventLoopType.EPOLL)
            el = AwsIO.event_loop_new(opts)
            @test !(el isa AwsIO.ErrorResult)

            if !(el isa AwsIO.ErrorResult)
                impl = el.impl_data

                noop_ctx = (nothing = nothing,)
                noop_fn = (ctx, status) -> nothing
                tasks = [
                    AwsIO.ScheduledTask(noop_fn, noop_ctx; type_tag = "pre_queue_task_1"),
                    AwsIO.ScheduledTask(noop_fn, noop_ctx; type_tag = "pre_queue_task_2"),
                ]

                AwsIO.mutex_lock(impl.task_pre_queue_mutex)
                for task in tasks
                    AwsIO.push_back!(impl.task_pre_queue, task)
                end
                AwsIO.mutex_unlock(impl.task_pre_queue_mutex)

                counter = Ref(UInt64(1))
                for _ in 1:3
                    @ccall write(
                        impl.write_task_handle.fd::Cint,
                        counter::Ptr{UInt64},
                        sizeof(UInt64)::Csize_t,
                    )::Cssize_t
                end

                impl.should_process_task_pre_queue = true
                AwsIO.process_task_pre_queue(el)

                @test isempty(impl.task_pre_queue)

                read_buf = Ref(UInt64(0))
                read_res = @ccall read(
                    impl.read_task_handle.fd::Cint,
                    read_buf::Ptr{UInt64},
                    sizeof(UInt64)::Csize_t,
                )::Cssize_t
                @test read_res < 0

                AwsIO.event_loop_destroy!(el)
            end
        end
    end

    @testset "Dispatch queue event loop" begin
        if !Sys.isapple()
            @test true
        else
            opts = AwsIO.EventLoopOptions(type = AwsIO.EventLoopType.DISPATCH_QUEUE)
            el = AwsIO.event_loop_new(opts)
            @test !(el isa AwsIO.ErrorResult)

            if !(el isa AwsIO.ErrorResult)
                run_res = AwsIO.event_loop_run!(el)
                @test run_res === nothing

                try
                    order = Int[]
                    order_lock = ReentrantLock()
                    done_ch = Channel{Nothing}(1)
                    total = 3

                    for i in 1:total
                        ctx = (order = order, lock = order_lock, done_ch = done_ch, i = i, total = total)
                        task_fn = (ctx, status) -> begin
                            local count
                            Base.lock(ctx.lock) do
                                push!(ctx.order, ctx.i)
                                count = length(ctx.order)
                            end
                            if count == ctx.total
                                put!(ctx.done_ch, nothing)
                            end
                            return nothing
                        end
                        task = AwsIO.ScheduledTask(task_fn, ctx; type_tag = "dispatch_queue_order")
                        AwsIO.event_loop_schedule_task_now!(el, task)
                    end

                    deadline = Base.time_ns() + 2_000_000_000
                    while !isready(done_ch) && Base.time_ns() < deadline
                        yield()
                    end

                    @test isready(done_ch)
                    isready(done_ch) && take!(done_ch)
                    Base.lock(order_lock) do
                        @test order == collect(1:total)
                    end

                    elapsed_ch = Channel{UInt64}(1)
                    start_time = AwsIO.event_loop_current_clock_time(el)
                    if start_time isa AwsIO.ErrorResult
                        @test false
                    else
                        timing_ctx = (el = el, start = start_time, elapsed_ch = elapsed_ch)
                        timing_fn = (ctx, status) -> begin
                            now = AwsIO.event_loop_current_clock_time(ctx.el)
                            now = now isa AwsIO.ErrorResult ? UInt64(0) : now
                            put!(ctx.elapsed_ch, now - ctx.start)
                            return nothing
                        end
                        timing_task = AwsIO.ScheduledTask(timing_fn, timing_ctx; type_tag = "dispatch_queue_future")
                        AwsIO.event_loop_schedule_task_future!(el, timing_task, start_time + 50_000_000)

                        deadline = Base.time_ns() + 2_000_000_000
                        while !isready(elapsed_ch) && Base.time_ns() < deadline
                            yield()
                        end

                        @test isready(elapsed_ch)
                        if isready(elapsed_ch)
                            elapsed = take!(elapsed_ch)
                            @test elapsed >= 10_000_000
                        end
                    end

                    status_ch = Channel{AwsIO.TaskStatus.T}(1)
                    cancel_ctx = (el = el, status_ch = status_ch)
                    future_fn = (ctx, status) -> begin
                        put!(ctx.status_ch, status)
                        return nothing
                    end
                    future_task = AwsIO.ScheduledTask(future_fn, cancel_ctx; type_tag = "dispatch_queue_cancelled")
                    now = AwsIO.event_loop_current_clock_time(el)
                    now = now isa AwsIO.ErrorResult ? UInt64(0) : now
                    AwsIO.event_loop_schedule_task_future!(el, future_task, now + 10_000_000_000)

                    cancel_task = AwsIO.ScheduledTask(
                        (ctx, status) -> AwsIO.event_loop_cancel_task!(ctx.el, future_task),
                        cancel_ctx;
                        type_tag = "dispatch_queue_cancel",
                    )
                    AwsIO.event_loop_schedule_task_now!(el, cancel_task)

                    deadline = Base.time_ns() + 2_000_000_000
                    while !isready(status_ch) && Base.time_ns() < deadline
                        yield()
                    end

                    @test isready(status_ch)
                    if isready(status_ch)
                        status = take!(status_ch)
                        @test status == AwsIO.TaskStatus.CANCELED
                    end

                    handle = AwsIO.IoHandle()
                    handle.set_queue = _dispatch_queue_setter_c
                    _dispatch_queue_store[] = C_NULL

                    conn_res = AwsIO.event_loop_connect_to_io_completion_port!(el, handle)
                    @test conn_res === nothing
                    @test _dispatch_queue_store[] == el.impl_data.dispatch_queue

                    sub_res = AwsIO.event_loop_subscribe_to_io_events!(
                        el,
                        handle,
                        Int(AwsIO.IoEventType.READABLE),
                        (loop, h, events, data) -> nothing,
                        nothing,
                    )
                    @test sub_res isa AwsIO.ErrorResult
                    @test AwsIO.last_error() == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED

                    unsub_res = AwsIO.event_loop_unsubscribe_from_io_events!(el, handle)
                    @test unsub_res isa AwsIO.ErrorResult
                    @test AwsIO.last_error() == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED
                finally
                    AwsIO.event_loop_destroy!(el)
                end
            end
        end
    end
end
