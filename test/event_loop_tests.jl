using Test
using Reseau

const _dispatch_queue_store = Ref{Ptr{Cvoid}}(C_NULL)
function _dispatch_queue_setter(handle::Ptr{Reseau.IoHandle}, queue::Ptr{Cvoid})
    _dispatch_queue_store[] = queue
    return nothing
end
const _dispatch_queue_setter_c =
    @cfunction(_dispatch_queue_setter, Cvoid, (Ptr{Reseau.IoHandle}, Ptr{Cvoid}))

const _EVENT_LOOP_TEST_TIMEOUT_NS = 2_000_000_000

function _wait_for_channel(ch::Channel; timeout_ns::Int = _EVENT_LOOP_TEST_TIMEOUT_NS)
    deadline = Base.time_ns() + timeout_ns
    while !isready(ch) && Base.time_ns() < deadline
        yield()
    end
    return isready(ch)
end

function _schedule_event_loop_task(el::Reseau.EventLoop, fn; type_tag::AbstractString = "event_loop_task")
    done_ch = Channel{Any}(1)
    task_fn = (ctx, status) -> begin
        if status != Reseau.TaskStatus.RUN_READY
            put!(done_ch, Reseau.ErrorResult(Reseau.ERROR_IO_EVENT_LOOP_SHUTDOWN))
            return nothing
        end
        ok = Reseau.event_loop_thread_is_callers_thread(el)
        result = fn()
        put!(done_ch, (ok, result))
        return nothing
    end
    task = Reseau.ScheduledTask(task_fn, nothing; type_tag = type_tag)
    Reseau.event_loop_schedule_task_now!(el, task)
    return done_ch
end

function _payload_abc()
    payload = Memory{UInt8}(undef, 3)
    payload[1] = UInt8('a')
    payload[2] = UInt8('b')
    payload[3] = UInt8('c')
    return payload
end

function _drain_pipe(read_end::Reseau.PipeReadEnd)
    buf = Reseau.ByteBuffer(64)
    while true
        res = Reseau.pipe_read!(read_end, buf)
        if res isa Reseau.ErrorResult
            return res.code == Reseau.ERROR_IO_READ_WOULD_BLOCK ? nothing : res
        end
    end
end

@testset "Event Loops" begin
    @testset "EventLoopGroup indexing convenience" begin
        elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
        @test !(elg isa Reseau.ErrorResult)
        elg isa Reseau.ErrorResult && return

        try
            @test length(elg) == 1
            @test elg[1] isa Reseau.EventLoop
            @test elg[1] === Reseau.event_loop_group_get_loop_at(elg, 0)
            @test_throws BoundsError elg[0]
            @test_throws BoundsError elg[2]
        finally
            Reseau.event_loop_group_release!(elg)
        end
    end

    @testset "Epoll pipe cloexec flags" begin
        if Sys.islinux()
            pipe_res = Reseau.open_nonblocking_posix_pipe()
            @test !(pipe_res isa Reseau.ErrorResult)
            if !(pipe_res isa Reseau.ErrorResult)
                read_fd, write_fd = pipe_res
                try
                    for fd in (read_fd, write_fd)
                        fd_flags = Reseau._fcntl(Cint(fd), Reseau.F_GETFD)
                        @test fd_flags != -1
                        @test (fd_flags & Reseau.FD_CLOEXEC) != 0
                        status_flags = Reseau._fcntl(Cint(fd), Reseau.F_GETFL)
                        @test status_flags != -1
                        @test (status_flags & Reseau.O_NONBLOCK) != 0
                    end
                finally
                    @ccall close(read_fd::Cint)::Cint
                    @ccall close(write_fd::Cint)::Cint
                end
            end
        else
            @test true
        end
    end

    @testset "Event loop scheduling" begin
        opts = Reseau.EventLoopOptions()
        el = Reseau.event_loop_new(opts)
        @test !(el isa Reseau.ErrorResult)

        if !(el isa Reseau.ErrorResult)
            interactive_threads = Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
                Reseau.event_loop_destroy!(el)
            else
                run_res = Reseau.event_loop_run!(el)
                @test run_res === nothing

                try
                    done = Ref(false)
                    thread_ok = Ref(false)
                    ctx = (el = el, done = done, thread_ok = thread_ok)

                    task_fn = (ctx, status) -> begin
                        ctx.thread_ok[] = Reseau.event_loop_thread_is_callers_thread(ctx.el)
                        ctx.done[] = true
                        return nothing
                    end

                    task = Reseau.ScheduledTask(task_fn, ctx; type_tag = "event_loop_test_task")
                    Reseau.event_loop_schedule_task_now!(el, task)

                    deadline = Base.time_ns() + 2_000_000_000
                    while !done[] && Base.time_ns() < deadline
                        yield()
                    end

                    @test done[]
                    @test thread_ok[]
                finally
                    Reseau.event_loop_destroy!(el)
                end
            end
        end
    end

    @testset "Event loop future scheduling timing" begin
        interactive_threads = Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            opts = Reseau.EventLoopOptions()
            el = Reseau.event_loop_new(opts)
            @test !(el isa Reseau.ErrorResult)

            if !(el isa Reseau.ErrorResult)
                run_res = Reseau.event_loop_run!(el)
                @test run_res === nothing

                try
                    done = Ref(false)
                    actual_time = Ref{UInt64}(0)

                    start_time = Reseau.event_loop_current_clock_time(el)
                    if start_time isa Reseau.ErrorResult
                        @test false
                    else
                        target_time = start_time + 50_000_000

                        ctx = (el = el, done = done, actual_time = actual_time)
                        task_fn = (ctx, status) -> begin
                            now = Reseau.event_loop_current_clock_time(ctx.el)
                            ctx.actual_time[] = now isa Reseau.ErrorResult ? UInt64(0) : now
                            ctx.done[] = true
                            return nothing
                        end

                        task = Reseau.ScheduledTask(task_fn, ctx; type_tag = "future_timing")
                        Reseau.event_loop_schedule_task_future!(el, task, target_time)

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
                    Reseau.event_loop_destroy!(el)
                end
            end
        end
    end

    @testset "Event loop stress scheduling" begin
        interactive_threads = Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            opts = Reseau.EventLoopOptions()
            el = Reseau.event_loop_new(opts)
            @test !(el isa Reseau.ErrorResult)

            if !(el isa Reseau.ErrorResult)
                run_res = Reseau.event_loop_run!(el)
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
                        task = Reseau.ScheduledTask(task_fn, ctx; type_tag = "stress_now")
                        Reseau.event_loop_schedule_task_now!(el, task)
                    end

                    deadline = Base.time_ns() + 3_000_000_000
                    while !isready(done_ch) && Base.time_ns() < deadline
                        yield()
                    end

                    @test isready(done_ch)
                    isready(done_ch) && take!(done_ch)
                finally
                    Reseau.event_loop_destroy!(el)
                end
            end
        end
    end

    @testset "Event loop pipe subscribe stress" begin
        interactive_threads = Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            opts = Reseau.EventLoopOptions()
            el = Reseau.event_loop_new(opts)
            @test !(el isa Reseau.ErrorResult)

            if !(el isa Reseau.ErrorResult)
                run_res = Reseau.event_loop_run!(el)
                @test run_res === nothing

                read_end = nothing
                write_end = nothing

                try
                    pipe_res = Reseau.pipe_create()
                    @test !(pipe_res isa Reseau.ErrorResult)
                    if pipe_res isa Reseau.ErrorResult
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
                        if err != Reseau.AWS_OP_SUCCESS
                            return nothing
                        end

                        buf = Reseau.ByteBuffer(64)
                        read_res = Reseau.pipe_read!(pipe, buf)
                        if read_res isa Reseau.ErrorResult
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

                    sub_res = Reseau.pipe_read_end_subscribe!(read_end, el, on_readable, nothing)
                    @test sub_res === nothing

                    for _ in 1:total_writes
                        write_res = Reseau.pipe_write_sync!(write_end, payload)
                        @test !(write_res isa Reseau.ErrorResult)
                    end

                    deadline = Base.time_ns() + 3_000_000_000
                    while !isready(done_ch) && Base.time_ns() < deadline
                        yield()
                    end

                    @test isready(done_ch)
                    isready(done_ch) && take!(done_ch)
                finally
                    read_end !== nothing && Reseau.pipe_read_end_close!(read_end)
                    write_end !== nothing && Reseau.pipe_write_end_close!(write_end)
                    Reseau.event_loop_destroy!(el)
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
                el = Reseau.event_loop_new(Reseau.EventLoopOptions())
                @test !(el isa Reseau.ErrorResult)

                if !(el isa Reseau.ErrorResult)
                    run_res = Reseau.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing
                    try
                        pipe_res = Reseau.pipe_create()
                        @test !(pipe_res isa Reseau.ErrorResult)
                        if pipe_res isa Reseau.ErrorResult
                            return
                        end
                        read_end, write_end = pipe_res

                        subscribe_task = _schedule_event_loop_task(el, () -> begin
                            res1 = Reseau.event_loop_subscribe_to_io_events!(
                                el,
                                read_end.io_handle,
                                Int(Reseau.IoEventType.READABLE),
                                (loop, handle, events, data) -> nothing,
                                nothing,
                            )
                            res2 = Reseau.event_loop_subscribe_to_io_events!(
                                el,
                                write_end.io_handle,
                                Int(Reseau.IoEventType.WRITABLE),
                                (loop, handle, events, data) -> nothing,
                                nothing,
                            )
                            res3 = Reseau.event_loop_unsubscribe_from_io_events!(el, read_end.io_handle)
                            res4 = Reseau.event_loop_unsubscribe_from_io_events!(el, write_end.io_handle)
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
                        read_end !== nothing && Reseau.pipe_read_end_close!(read_end)
                        write_end !== nothing && Reseau.pipe_write_end_close!(write_end)
                        Reseau.event_loop_destroy!(el)
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
                el = Reseau.event_loop_new(Reseau.EventLoopOptions())
                @test !(el isa Reseau.ErrorResult)

                if !(el isa Reseau.ErrorResult)
                    run_res = Reseau.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing
                    try
                        pipe_res = Reseau.pipe_create()
                        @test !(pipe_res isa Reseau.ErrorResult)
                        if pipe_res isa Reseau.ErrorResult
                            return
                        end
                        read_end, write_end = pipe_res

                        writable_count = Ref(0)
                        thread_ok = Ref(true)
                        count_lock = ReentrantLock()
                        writable_ch = Channel{Nothing}(1)

                        on_writable = (loop, handle, events, data) -> begin
                            if !Reseau.event_loop_thread_is_callers_thread(loop)
                                thread_ok[] = false
                            end
                            if (events & Int(Reseau.IoEventType.WRITABLE)) == 0
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
                            return Reseau.event_loop_subscribe_to_io_events!(
                                el,
                                write_end.io_handle,
                                Int(Reseau.IoEventType.WRITABLE),
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
                            return Reseau.event_loop_unsubscribe_from_io_events!(el, write_end.io_handle)
                        end; type_tag = "event_loop_writable_unsubscribe")
                        @test _wait_for_channel(unsub_task)
                        ok2, unsub_res = take!(unsub_task)
                        @test ok2
                        @test unsub_res === nothing
                    finally
                        read_end !== nothing && Reseau.pipe_read_end_close!(read_end)
                        write_end !== nothing && Reseau.pipe_write_end_close!(write_end)
                        Reseau.event_loop_destroy!(el)
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
                el = Reseau.event_loop_new(Reseau.EventLoopOptions())
                @test !(el isa Reseau.ErrorResult)

                if !(el isa Reseau.ErrorResult)
                    run_res = Reseau.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing
                    try
                        pipe_res = Reseau.pipe_create()
                        @test !(pipe_res isa Reseau.ErrorResult)
                        if pipe_res isa Reseau.ErrorResult
                            return
                        end
                        read_end, write_end = pipe_res

                        readable_count = Ref(0)
                        count_lock = ReentrantLock()
                        on_readable = (loop, handle, events, data) -> begin
                            if (events & Int(Reseau.IoEventType.READABLE)) == 0
                                return nothing
                            end
                            Base.lock(count_lock) do
                                readable_count[] += 1
                            end
                            return nothing
                        end

                        sub_task = _schedule_event_loop_task(el, () -> begin
                            return Reseau.event_loop_subscribe_to_io_events!(
                                el,
                                read_end.io_handle,
                                Int(Reseau.IoEventType.READABLE),
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
                            return Reseau.event_loop_unsubscribe_from_io_events!(el, read_end.io_handle)
                        end; type_tag = "event_loop_readable_unsubscribe")
                        @test _wait_for_channel(unsub_task)
                        ok2, unsub_res = take!(unsub_task)
                        @test ok2
                        @test unsub_res === nothing
                    finally
                        read_end !== nothing && Reseau.pipe_read_end_close!(read_end)
                        write_end !== nothing && Reseau.pipe_write_end_close!(write_end)
                        Reseau.event_loop_destroy!(el)
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
                el = Reseau.event_loop_new(Reseau.EventLoopOptions())
                @test !(el isa Reseau.ErrorResult)

                if !(el isa Reseau.ErrorResult)
                    run_res = Reseau.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing
                    try
                        pipe_res = Reseau.pipe_create()
                        @test !(pipe_res isa Reseau.ErrorResult)
                        if pipe_res isa Reseau.ErrorResult
                            return
                        end
                        read_end, write_end = pipe_res

                        payload = _payload_abc()
                        write_res = Reseau.pipe_write_sync!(write_end, payload)
                        @test !(write_res isa Reseau.ErrorResult)

                        readable_count = Ref(0)
                        count_lock = ReentrantLock()
                        readable_ch = Channel{Nothing}(1)

                        on_readable = (loop, handle, events, data) -> begin
                            if (events & Int(Reseau.IoEventType.READABLE)) == 0
                                return nothing
                            end
                            drain_res = _drain_pipe(read_end)
                            if drain_res isa Reseau.ErrorResult
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
                            return Reseau.event_loop_subscribe_to_io_events!(
                                el,
                                read_end.io_handle,
                                Int(Reseau.IoEventType.READABLE),
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
                            return Reseau.event_loop_unsubscribe_from_io_events!(el, read_end.io_handle)
                        end; type_tag = "event_loop_readable_unsubscribe_present")
                        @test _wait_for_channel(unsub_task)
                        ok2, unsub_res = take!(unsub_task)
                        @test ok2
                        @test unsub_res === nothing
                    finally
                        read_end !== nothing && Reseau.pipe_read_end_close!(read_end)
                        write_end !== nothing && Reseau.pipe_write_end_close!(write_end)
                        Reseau.event_loop_destroy!(el)
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
                el = Reseau.event_loop_new(Reseau.EventLoopOptions())
                @test !(el isa Reseau.ErrorResult)

                if !(el isa Reseau.ErrorResult)
                    run_res = Reseau.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing
                    try
                        pipe_res = Reseau.pipe_create()
                        @test !(pipe_res isa Reseau.ErrorResult)
                        if pipe_res isa Reseau.ErrorResult
                            return
                        end
                        read_end, write_end = pipe_res

                        writable_ch = Channel{Nothing}(1)
                        readable_ch = Channel{Nothing}(1)
                        readable_count = Ref(0)
                        count_lock = ReentrantLock()

                        on_writable = (loop, handle, events, data) -> begin
                            if (events & Int(Reseau.IoEventType.WRITABLE)) == 0
                                return nothing
                            end
                            if !isready(writable_ch)
                                put!(writable_ch, nothing)
                            end
                            return nothing
                        end

                        on_readable = (loop, handle, events, data) -> begin
                            if (events & Int(Reseau.IoEventType.READABLE)) == 0
                                return nothing
                            end
                            drain_res = _drain_pipe(read_end)
                            if drain_res isa Reseau.ErrorResult
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
                            res1 = Reseau.event_loop_subscribe_to_io_events!(
                                el,
                                write_end.io_handle,
                                Int(Reseau.IoEventType.WRITABLE),
                                on_writable,
                                nothing,
                            )
                            res2 = Reseau.event_loop_subscribe_to_io_events!(
                                el,
                                read_end.io_handle,
                                Int(Reseau.IoEventType.READABLE),
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
                        write_res = Reseau.pipe_write_sync!(write_end, payload)
                        @test !(write_res isa Reseau.ErrorResult)

                        @test _wait_for_channel(readable_ch; timeout_ns = 3_000_000_000)
                        sleep(1.0)

                        Base.lock(count_lock) do
                            @test readable_count[] == 1
                        end

                        unsub_task = _schedule_event_loop_task(el, () -> begin
                            res1 = Reseau.event_loop_unsubscribe_from_io_events!(el, write_end.io_handle)
                            res2 = Reseau.event_loop_unsubscribe_from_io_events!(el, read_end.io_handle)
                            return (res1, res2)
                        end; type_tag = "event_loop_readable_after_write_unsub")
                        @test _wait_for_channel(unsub_task)
                        ok2, results2 = take!(unsub_task)
                        @test ok2
                        r1, r2 = results2
                        @test r1 === nothing
                        @test r2 === nothing
                    finally
                        read_end !== nothing && Reseau.pipe_read_end_close!(read_end)
                        write_end !== nothing && Reseau.pipe_write_end_close!(write_end)
                        Reseau.event_loop_destroy!(el)
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
                el = Reseau.event_loop_new(Reseau.EventLoopOptions())
                @test !(el isa Reseau.ErrorResult)

                if !(el isa Reseau.ErrorResult)
                    run_res = Reseau.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing
                    try
                        pipe_res = Reseau.pipe_create()
                        @test !(pipe_res isa Reseau.ErrorResult)
                        if pipe_res isa Reseau.ErrorResult
                            return
                        end
                        read_end, write_end = pipe_res

                        writable_ch = Channel{Nothing}(1)
                        first_readable_ch = Channel{Nothing}(1)
                        second_readable_ch = Channel{Nothing}(1)
                        readable_count = Ref(0)
                        count_lock = ReentrantLock()

                        on_writable = (loop, handle, events, data) -> begin
                            if (events & Int(Reseau.IoEventType.WRITABLE)) == 0
                                return nothing
                            end
                            if !isready(writable_ch)
                                put!(writable_ch, nothing)
                            end
                            return nothing
                        end

                        on_readable = (loop, handle, events, data) -> begin
                            if (events & Int(Reseau.IoEventType.READABLE)) == 0
                                return nothing
                            end
                            drain_res = _drain_pipe(read_end)
                            if drain_res isa Reseau.ErrorResult
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
                            res1 = Reseau.event_loop_subscribe_to_io_events!(
                                el,
                                write_end.io_handle,
                                Int(Reseau.IoEventType.WRITABLE),
                                on_writable,
                                nothing,
                            )
                            res2 = Reseau.event_loop_subscribe_to_io_events!(
                                el,
                                read_end.io_handle,
                                Int(Reseau.IoEventType.READABLE),
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
                        write_res = Reseau.pipe_write_sync!(write_end, payload)
                        @test !(write_res isa Reseau.ErrorResult)

                        @test _wait_for_channel(first_readable_ch; timeout_ns = 3_000_000_000)
                        payload2 = _payload_abc()
                        write_res2 = Reseau.pipe_write_sync!(write_end, payload2)
                        @test !(write_res2 isa Reseau.ErrorResult)

                        @test _wait_for_channel(second_readable_ch; timeout_ns = 3_000_000_000)

                        Base.lock(count_lock) do
                            @test readable_count[] == 2
                        end

                        unsub_task = _schedule_event_loop_task(el, () -> begin
                            res1 = Reseau.event_loop_unsubscribe_from_io_events!(el, write_end.io_handle)
                            res2 = Reseau.event_loop_unsubscribe_from_io_events!(el, read_end.io_handle)
                            return (res1, res2)
                        end; type_tag = "event_loop_readable_second_unsub")
                        @test _wait_for_channel(unsub_task)
                        ok2, results2 = take!(unsub_task)
                        @test ok2
                        r1b, r2b = results2
                        @test r1b === nothing
                        @test r2b === nothing
                    finally
                        read_end !== nothing && Reseau.pipe_read_end_close!(read_end)
                        write_end !== nothing && Reseau.pipe_write_end_close!(write_end)
                        Reseau.event_loop_destroy!(el)
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
                el = Reseau.event_loop_new(Reseau.EventLoopOptions())
                @test !(el isa Reseau.ErrorResult)

                if !(el isa Reseau.ErrorResult)
                    run_res = Reseau.event_loop_run!(el)
                    @test run_res === nothing

                    read_ends = nothing
                    write_ends = nothing
                    try
                        pipe1 = Reseau.pipe_create()
                        pipe2 = Reseau.pipe_create()
                        @test !(pipe1 isa Reseau.ErrorResult)
                        @test !(pipe2 isa Reseau.ErrorResult)
                        if pipe1 isa Reseau.ErrorResult || pipe2 isa Reseau.ErrorResult
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
                            if (events & Int(Reseau.IoEventType.WRITABLE)) == 0
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
                                    write_res = Reseau.pipe_write_sync!(write_ends[i], payload)
                                    if write_res isa Reseau.ErrorResult
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
                            if (events & Int(Reseau.IoEventType.READABLE)) == 0
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
                                    _ = Reseau.event_loop_unsubscribe_from_io_events!(el, read_ends[i].io_handle)
                                    _ = Reseau.event_loop_unsubscribe_from_io_events!(el, write_ends[i].io_handle)
                                    Reseau.pipe_read_end_close!(read_ends[i])
                                    Reseau.pipe_write_end_close!(write_ends[i])
                                end

                                unsubscribed[] = true
                            end

                            now = Reseau.event_loop_current_clock_time(el)
                            if !(now isa Reseau.ErrorResult)
                                run_at = now + 1_000_000_000
                                done_task = Reseau.ScheduledTask(
                                    (ctx, status) -> begin
                                        if !isready(done_ch)
                                            put!(done_ch, nothing)
                                        end
                                        return nothing
                                    end,
                                    nothing;
                                    type_tag = "unsubrace_done",
                                )
                                Reseau.event_loop_schedule_task_future!(el, done_task, run_at)
                            else
                                if !isready(done_ch)
                                    put!(done_ch, nothing)
                                end
                            end
                            return nothing
                        end

                        setup_task = _schedule_event_loop_task(el, () -> begin
                            for i in 1:2
                                _ = Reseau.event_loop_subscribe_to_io_events!(
                                    el,
                                    write_ends[i].io_handle,
                                    Int(Reseau.IoEventType.WRITABLE),
                                    on_writable,
                                    nothing,
                                )
                                _ = Reseau.event_loop_subscribe_to_io_events!(
                                    el,
                                    read_ends[i].io_handle,
                                    Int(Reseau.IoEventType.READABLE),
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
                                Reseau.pipe_read_end_close!(read_ends[i])
                                Reseau.pipe_write_end_close!(write_ends[i])
                            end
                        end
                        Reseau.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop group thread affinity" begin
        interactive_threads = Threads.nthreads(:interactive)
        if interactive_threads <= 2
            @test true
        else
            opts = Reseau.EventLoopGroupOptions(loop_count = 2)
            elg = Reseau.event_loop_group_new(opts)
            @test !(elg isa Reseau.ErrorResult)

            if !(elg isa Reseau.ErrorResult)
                try
                    loop1 = Reseau.event_loop_group_get_next_loop(elg)
                    loop2 = Reseau.event_loop_group_get_next_loop(elg)

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
                        task1 = Reseau.ScheduledTask(task_fn, (ids = ids1,); type_tag = "elg_affinity")
                        Reseau.event_loop_schedule_task_now!(loop1, task1)

                        task2 = Reseau.ScheduledTask(task_fn, (ids = ids2,); type_tag = "elg_affinity")
                        Reseau.event_loop_schedule_task_now!(loop2, task2)
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
                    Reseau.event_loop_group_destroy!(elg)
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
                opts = Reseau.EventLoopOptions()
                el = Reseau.event_loop_new(opts)
                @test !(el isa Reseau.ErrorResult)

                if !(el isa Reseau.ErrorResult)
                    run_res = Reseau.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing

                    try
                        pipe_res = Reseau.pipe_create()
                        @test !(pipe_res isa Reseau.ErrorResult)
                        if pipe_res isa Reseau.ErrorResult
                            return
                        end

                        read_end, write_end = pipe_res

                        sub_res = Reseau.event_loop_subscribe_to_io_events!(
                            el,
                            read_end.io_handle,
                            Int(Reseau.IoEventType.READABLE),
                            (loop, handle, events, data) -> nothing,
                            nothing,
                        )
                        @test sub_res === nothing
                        @test read_end.io_handle.additional_data != C_NULL

                        done_ch = Channel{Nothing}(1)
                        unsub_ctx = (el = el, handle = read_end.io_handle, done_ch = done_ch)
                        unsub_fn = (ctx, status) -> begin
                            Reseau.event_loop_unsubscribe_from_io_events!(ctx.el, ctx.handle)
                            put!(ctx.done_ch, nothing)
                            return nothing
                        end
                        unsub_task = Reseau.ScheduledTask(unsub_fn, unsub_ctx; type_tag = "handle_unsubscribe")
                        Reseau.event_loop_schedule_task_now!(el, unsub_task)

                        deadline = Base.time_ns() + 2_000_000_000
                        while !isready(done_ch) && Base.time_ns() < deadline
                            yield()
                        end

                        @test isready(done_ch)
                        isready(done_ch) && take!(done_ch)
                        @test read_end.io_handle.additional_data == C_NULL
                    finally
                        read_end !== nothing && Reseau.pipe_read_end_close!(read_end)
                        write_end !== nothing && Reseau.pipe_write_end_close!(write_end)
                        Reseau.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop unsubscribe error" begin
        interactive_threads = Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            opts = Reseau.EventLoopOptions()
            el = Reseau.event_loop_new(opts)
            @test !(el isa Reseau.ErrorResult)

            if !(el isa Reseau.ErrorResult)
                run_res = Reseau.event_loop_run!(el)
                @test run_res === nothing

                try
                    done_ch = Channel{Int}(1)
                    ctx = (el = el, handle = Reseau.IoHandle(), done_ch = done_ch)
                    task_fn = (ctx, status) -> begin
                        res = Reseau.event_loop_unsubscribe_from_io_events!(ctx.el, ctx.handle)
                        code = res isa Reseau.ErrorResult ? Reseau.last_error() : 0
                        put!(ctx.done_ch, code)
                        return nothing
                    end
                    task = Reseau.ScheduledTask(task_fn, ctx; type_tag = "unsubscribe_error")
                    Reseau.event_loop_schedule_task_now!(el, task)

                    deadline = Base.time_ns() + 2_000_000_000
                    while !isready(done_ch) && Base.time_ns() < deadline
                        yield()
                    end

                    @test isready(done_ch)
                    if isready(done_ch)
                        code = take!(done_ch)
                        @test code == Reseau.ERROR_IO_NOT_SUBSCRIBED
                    end
                finally
                    Reseau.event_loop_destroy!(el)
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
                opts = Reseau.EventLoopOptions()
                el = Reseau.event_loop_new(opts)
                @test !(el isa Reseau.ErrorResult)

                if !(el isa Reseau.ErrorResult)
                    run_res = Reseau.event_loop_run!(el)
                    @test run_res === nothing

                    read_end = nothing
                    write_end = nothing

                    try
                        pipe_res = Reseau.pipe_create()
                        @test !(pipe_res isa Reseau.ErrorResult)
                        if pipe_res isa Reseau.ErrorResult
                            return
                        end

                        read_end, write_end = pipe_res
                        bad_fd = read_end.io_handle.fd
                        ccall(:close, Cint, (Cint,), bad_fd)
                        read_end.io_handle.fd = -1
                        bad_handle = Reseau.IoHandle(bad_fd)

                        if Sys.islinux()
                            res = Reseau.event_loop_subscribe_to_io_events!(
                                el,
                                bad_handle,
                                Int(Reseau.IoEventType.READABLE),
                                (loop, handle, events, data) -> nothing,
                                nothing,
                            )
                            @test res isa Reseau.ErrorResult
                            res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_SYS_CALL_FAILURE
                        elseif Sys.isapple()
                            done_ch = Channel{Int}(1)
                            on_event = (loop, handle, events, data) -> begin
                                _ = Reseau.event_loop_unsubscribe_from_io_events!(loop, handle)
                                put!(done_ch, events)
                                return nothing
                            end
                            res = Reseau.event_loop_subscribe_to_io_events!(
                                el,
                                bad_handle,
                                Int(Reseau.IoEventType.READABLE),
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
                                @test (events & Int(Reseau.IoEventType.ERROR)) != 0
                            end
                        else
                            @test true
                        end
                    finally
                        read_end !== nothing && Reseau.pipe_read_end_close!(read_end)
                        write_end !== nothing && Reseau.pipe_write_end_close!(write_end)
                        Reseau.event_loop_destroy!(el)
                    end
                end
            end
        end
    end

    @testset "Event loop serialized ordering" begin
        interactive_threads = Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            opts = Reseau.EventLoopOptions()
            el = Reseau.event_loop_new(opts)
            @test !(el isa Reseau.ErrorResult)

            if !(el isa Reseau.ErrorResult)
                run_res = Reseau.event_loop_run!(el)
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
                        task = Reseau.ScheduledTask(task_fn, ctx; type_tag = "serialized_order")
                        Reseau.event_loop_schedule_task_now_serialized!(el, task)
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
                    Reseau.event_loop_destroy!(el)
                end
            end
        end
    end

    @testset "Event loop cancel task" begin
        interactive_threads = Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            opts = Reseau.EventLoopOptions()
            el = Reseau.event_loop_new(opts)
            @test !(el isa Reseau.ErrorResult)

            if !(el isa Reseau.ErrorResult)
                run_res = Reseau.event_loop_run!(el)
                @test run_res === nothing

                try
                    status_ch = Channel{Tuple{Reseau.TaskStatus.T, Bool}}(1)
                    ctx = (el = el, status_ch = status_ch)
                    future_fn = (ctx, status) -> begin
                        put!(ctx.status_ch, (status, Reseau.event_loop_thread_is_callers_thread(ctx.el)))
                        return nothing
                    end
                    future_task = Reseau.ScheduledTask(future_fn, ctx; type_tag = "future_task")

                    now = Reseau.event_loop_current_clock_time(el)
                    if now isa Reseau.ErrorResult
                        @test false
                    else
                        Reseau.event_loop_schedule_task_future!(el, future_task, now + 10_000_000_000)

                        cancel_ctx = (el = el, task = future_task)
                        cancel_fn = (ctx, status) -> begin
                            Reseau.event_loop_cancel_task!(ctx.el, ctx.task)
                            return nothing
                        end
                        cancel_task = Reseau.ScheduledTask(cancel_fn, cancel_ctx; type_tag = "cancel_task")
                        Reseau.event_loop_schedule_task_now!(el, cancel_task)

                        deadline = Base.time_ns() + 2_000_000_000
                        while !isready(status_ch) && Base.time_ns() < deadline
                            yield()
                        end

                        @test isready(status_ch)
                        if isready(status_ch)
                            status, thread_ok = take!(status_ch)
                            @test status == Reseau.TaskStatus.CANCELED
                            @test thread_ok
                        end
                    end
                finally
                    Reseau.event_loop_destroy!(el)
                end
            end
        end
    end

    @testset "Event loop destroy cancels pending task" begin
        interactive_threads = Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            opts = Reseau.EventLoopOptions()
            el = Reseau.event_loop_new(opts)
            @test !(el isa Reseau.ErrorResult)

            if !(el isa Reseau.ErrorResult)
                run_res = Reseau.event_loop_run!(el)
                @test run_res === nothing

                status_ch = Channel{Reseau.TaskStatus.T}(1)
                ctx = (status_ch = status_ch,)
                future_fn = (ctx, status) -> begin
                    put!(ctx.status_ch, status)
                    return nothing
                end
                future_task = Reseau.ScheduledTask(future_fn, ctx; type_tag = "future_task_destroy")

                now = Reseau.event_loop_current_clock_time(el)
                if now isa Reseau.ErrorResult
                    @test false
                else
                    Reseau.event_loop_schedule_task_future!(el, future_task, now + 10_000_000_000)
                    Reseau.event_loop_destroy!(el)

                    @test isready(status_ch)
                    if isready(status_ch)
                        status = take!(status_ch)
                        @test status == Reseau.TaskStatus.CANCELED
                    end
                end
            end
        end
    end

    @testset "Event loop destroy on loop thread throws" begin
        interactive_threads = Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            opts = Reseau.EventLoopOptions()
            el = Reseau.event_loop_new(opts)
            @test !(el isa Reseau.ErrorResult)
            if !(el isa Reseau.ErrorResult)
                run_res = Reseau.event_loop_run!(el)
                @test run_res === nothing
                destroy_called = Ref(false)
                destroy_threw = Ref(false)
                task = Reseau.ScheduledTask(
                    (ctx, status) -> begin
                        status == Reseau.TaskStatus.RUN_READY || return nothing
                        ctx.destroy_called[] = true
                        try
                            Reseau.event_loop_destroy!(ctx.el)
                        catch err
                            ctx.destroy_threw[] = err isa ErrorException
                        end
                        return nothing
                    end,
                    (el = el, destroy_called = destroy_called, destroy_threw = destroy_threw);
                    type_tag = "destroy_on_loop",
                )
                Reseau.event_loop_schedule_task_now!(el, task)
                deadline = Base.time_ns() + 2_000_000_000
                while !destroy_called[] && Base.time_ns() < deadline
                    sleep(0.01)
                end
                @test destroy_called[]
                @test destroy_threw[]
                Reseau.event_loop_destroy!(el)
            end
        end
    end

    @testset "Event loop group" begin
        opts = Reseau.EventLoopGroupOptions(loop_count = 1)
        elg = Reseau.event_loop_group_new(opts)
        @test !(elg isa Reseau.ErrorResult)

        if !(elg isa Reseau.ErrorResult)
            try
                @test Reseau.event_loop_group_get_loop_count(elg) == 1
                el = Reseau.event_loop_group_get_next_loop(elg)
                @test el !== nothing
                if el !== nothing
                    acquired = Reseau.event_loop_group_acquire_from_event_loop(el)
                    @test acquired === elg
                    Reseau.event_loop_group_release_from_event_loop!(el)
                end
            finally
                Reseau.event_loop_group_destroy!(elg)
            end
        end
    end

    @testset "Event loop group async shutdown" begin
        interactive_threads = Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            shutdown_ch = Channel{Bool}(1)
            shutdown_opts = Reseau.shutdown_callback_options(
                (ud) -> begin
                    put!(shutdown_ch, true)
                    return nothing
                end,
                nothing,
            )

            opts = Reseau.EventLoopGroupOptions(loop_count = 1, shutdown_options = shutdown_opts)
            elg = Reseau.event_loop_group_new(opts)
            @test !(elg isa Reseau.ErrorResult)
            if elg isa Reseau.ErrorResult
                return
            end

            done = false
            try
                el = Reseau.event_loop_group_get_next_loop(elg)
                @test el !== nothing
                if el === nothing
                    return
                end

                release_task = Reseau.ScheduledTask(
                    (ctx, status) -> begin
                        Reseau.event_loop_group_release!(ctx.elg)
                        return nothing
                    end,
                    (elg = elg,);
                    type_tag = "elg_release_async",
                )
                Reseau.event_loop_schedule_task_now!(el, release_task)
                done = _wait_for_channel(shutdown_ch)
                @test done
            finally
                if !done
                    Reseau.event_loop_group_destroy!(elg)
                end
            end
        end
    end

    @testset "Event loop group NUMA setup" begin
        cpu_group = Ref{UInt16}(0)
        cpu_count = Reseau.get_cpu_count_for_group(cpu_group[])
        opts = Reseau.EventLoopGroupOptions(loop_count = typemax(UInt16), cpu_group = cpu_group)
        elg = Reseau.event_loop_group_new(opts)

        @test !(elg isa Reseau.ErrorResult)
        if !(elg isa Reseau.ErrorResult)
            try
                el_count = Reseau.event_loop_group_get_loop_count(elg)
                @test el_count == cpu_count
            finally
                Reseau.event_loop_group_destroy!(elg)
            end
        end
    end

    @testset "Event loop stop then restart" begin
        interactive_threads = Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            el = Reseau.event_loop_new(Reseau.EventLoopOptions())
            @test !(el isa Reseau.ErrorResult)

            if !(el isa Reseau.ErrorResult)
                run_res = Reseau.event_loop_run!(el)
                @test run_res === nothing

                done1 = Channel{Bool}(1)
                task1 = Reseau.ScheduledTask((ctx, status) -> begin
                    if status == Reseau.TaskStatus.RUN_READY
                        put!(done1, Reseau.event_loop_thread_is_callers_thread(el))
                    end
                    return nothing
                end, nothing; type_tag = "event_loop_stop_restart_first")
                Reseau.event_loop_schedule_task_now!(el, task1)
                @test _wait_for_channel(done1)
                @test take!(done1)

                @test Reseau.event_loop_stop!(el) === nothing
                @test Reseau.event_loop_wait_for_stop_completion!(el) === nothing
                @test Reseau.event_loop_run!(el) === nothing

                done2 = Channel{Bool}(1)
                task2 = Reseau.ScheduledTask((ctx, status) -> begin
                    if status == Reseau.TaskStatus.RUN_READY
                        put!(done2, Reseau.event_loop_thread_is_callers_thread(el))
                    end
                    return nothing
                end, nothing; type_tag = "event_loop_stop_restart_second")
                Reseau.event_loop_schedule_task_now!(el, task2)
                @test _wait_for_channel(done2)
                @test take!(done2)

                Reseau.event_loop_destroy!(el)
            end
        end
    end

    @testset "Event loop multiple stops" begin
        interactive_threads = Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            el = Reseau.event_loop_new(Reseau.EventLoopOptions())
            @test !(el isa Reseau.ErrorResult)

            if !(el isa Reseau.ErrorResult)
                run_res = Reseau.event_loop_run!(el)
                @test run_res === nothing

                for _ in 1:8
                    @test Reseau.event_loop_stop!(el) === nothing
                end

                Reseau.event_loop_destroy!(el)
            end
        end
    end

    @testset "Event loop group setup and shutdown" begin
        expected = max(1, Sys.CPU_THREADS >> 1)

        opts = Reseau.EventLoopGroupOptions(loop_count = 0)
        elg = Reseau.event_loop_group_new(opts)

        @test !(elg isa Reseau.ErrorResult)
        if !(elg isa Reseau.ErrorResult)
            try
                @test Reseau.event_loop_group_get_loop_count(elg) == expected
                loop = Reseau.event_loop_group_get_next_loop(elg)
                @test loop !== nothing
            finally
                Reseau.event_loop_group_destroy!(elg)
            end
        end
    end

    @testset "Event loop group shutdown callback" begin
        interactive_threads = Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            shutdown_called = Ref(false)
            shutdown_thread = Ref(0)
            done_ch = Channel{Nothing}(1)

            shutdown_opts = Reseau.shutdown_callback_options(
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

            elg = Reseau.event_loop_group_new(Reseau.EventLoopGroupOptions(loop_count = 1, shutdown_options = shutdown_opts))
            @test !(elg isa Reseau.ErrorResult)

            if !(elg isa Reseau.ErrorResult)
                Reseau.event_loop_group_destroy!(elg)
                @test _wait_for_channel(done_ch)
                @test shutdown_called[]
                @test shutdown_thread[] != 0
            end
        end
    end

    @testset "Event loop local objects" begin
        interactive_threads = Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
                opts = Reseau.EventLoopOptions()
                el = Reseau.event_loop_new(opts)
                @test !(el isa Reseau.ErrorResult)

                if !(el isa Reseau.ErrorResult)
                    run_res = Reseau.event_loop_run!(el)
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
                        res = Reseau.event_loop_fetch_local_object(ctx.el, ctx.key)
                        if res isa Reseau.ErrorResult
                            ctx.missing_err1[] = Reseau.last_error()
                        end

                        on_removed = obj -> (ctx.removed_calls[] += 1)
                        obj1 = Reseau.EventLoopLocalObject(ctx.key, "one", on_removed)
                        Reseau.event_loop_put_local_object!(ctx.el, obj1)

                        obj2 = Reseau.EventLoopLocalObject(ctx.key, "two", on_removed)
                        Reseau.event_loop_put_local_object!(ctx.el, obj2)

                        fetched = Reseau.event_loop_fetch_local_object(ctx.el, ctx.key)
                        if !(fetched isa Reseau.ErrorResult)
                            ctx.fetched_value[] = fetched.object
                        end

                        removed_obj = Reseau.event_loop_remove_local_object!(ctx.el, ctx.key)
                        if removed_obj !== nothing
                            ctx.removed_value[] = removed_obj.object
                        end

                        res2 = Reseau.event_loop_fetch_local_object(ctx.el, ctx.key)
                        if res2 isa Reseau.ErrorResult
                            ctx.missing_err2[] = Reseau.last_error()
                        end

                        ctx.done[] = true
                        return nothing
                    end

                    task = Reseau.ScheduledTask(task_fn, ctx; type_tag = "event_loop_local_object_test")
                    Reseau.event_loop_schedule_task_now!(el, task)

                    deadline = Base.time_ns() + 2_000_000_000
                    while !done[] && Base.time_ns() < deadline
                        yield()
                    end

                    @test done[]
                    @test missing_err1[] == Reseau.ERROR_INVALID_ARGUMENT
                    @test missing_err2[] == Reseau.ERROR_INVALID_ARGUMENT
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
                        obj = Reseau.EventLoopLocalObject(ctx.key, "cleanup", on_removed)
                        Reseau.event_loop_put_local_object!(ctx.el, obj)
                        ctx.done_cleanup[] = true
                        return nothing
                    end

                    cleanup_task = Reseau.ScheduledTask(cleanup_task_fn, cleanup_ctx; type_tag = "event_loop_local_object_cleanup")
                    Reseau.event_loop_schedule_task_now!(el, cleanup_task)

                    deadline = Base.time_ns() + 2_000_000_000
                    while !done_cleanup[] && Base.time_ns() < deadline
                        yield()
                    end

                    @test done_cleanup[]

                    Reseau.event_loop_destroy!(el)
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

        opts = Reseau.EventLoopOptions(clock = clock)
        el = Reseau.event_loop_new(opts)
        @test !(el isa Reseau.ErrorResult)
        if !(el isa Reseau.ErrorResult)
            Reseau.event_loop_register_tick_start!(el)
            Reseau.event_loop_register_tick_end!(el)

            # Force stale state and confirm load factor reports 0
            @atomic el.next_flush_time = UInt64(0)
            @test Reseau.event_loop_get_load_factor(el) == 0
        end
    end

    @testset "Event loop clock override" begin
        clock_calls = Ref(0)
        clock = () -> begin
            clock_calls[] += 1
            return UInt64(42)
        end

        opts = Reseau.EventLoopOptions(clock = clock)
        el = Reseau.event_loop_new(opts)
        @test !(el isa Reseau.ErrorResult)

        if !(el isa Reseau.ErrorResult)
            @test Reseau.event_loop_current_clock_time(el) == UInt64(42)
        end

        interactive_threads = Threads.nthreads(:interactive)
        if interactive_threads > 1
            group_opts = Reseau.EventLoopGroupOptions(loop_count = 1, clock_override = clock)
            elg = Reseau.event_loop_group_new(group_opts)
            @test !(elg isa Reseau.ErrorResult)

            if !(elg isa Reseau.ErrorResult)
                try
                    loop = Reseau.event_loop_group_get_next_loop(elg)
                    @test loop !== nothing
                    if loop !== nothing
                        @test Reseau.event_loop_current_clock_time(loop) == UInt64(42)
                    end
                finally
                    Reseau.event_loop_group_destroy!(elg)
                end
            end
        end

        @test clock_calls[] >= 1
    end

    @testset "Event loop group thread constraint" begin
        # OS threads have no interactive thread pool constraint;
        # verify that creating an ELG with a reasonable count succeeds.
        opts = Reseau.EventLoopGroupOptions(loop_count = UInt16(2))
        elg = Reseau.event_loop_group_new(opts)
        @test !(elg isa Reseau.ErrorResult)
        if !(elg isa Reseau.ErrorResult)
            try
                @test Reseau.event_loop_group_get_loop_count(elg) == 2
            finally
                Reseau.event_loop_group_destroy!(elg)
            end
        end
    end

    @testset "Epoll task pre-queue drain" begin
        if !Sys.islinux()
            @test true
        else
            opts = Reseau.EventLoopOptions()
            el = Reseau.event_loop_new(opts)
            @test !(el isa Reseau.ErrorResult)

            if !(el isa Reseau.ErrorResult)
                impl = el.impl_data

                noop_ctx = (nothing = nothing,)
                noop_fn = (ctx, status) -> nothing
                tasks = [
                    Reseau.ScheduledTask(noop_fn, noop_ctx; type_tag = "pre_queue_task_1"),
                    Reseau.ScheduledTask(noop_fn, noop_ctx; type_tag = "pre_queue_task_2"),
                ]

                lock(impl.task_pre_queue_mutex)
                for task in tasks
                    push!(impl.task_pre_queue, task)
                end
                unlock(impl.task_pre_queue_mutex)

                counter = Ref(UInt64(1))
                for _ in 1:3
                    @ccall write(
                        impl.write_task_handle.fd::Cint,
                        counter::Ptr{UInt64},
                        sizeof(UInt64)::Csize_t,
                    )::Cssize_t
                end

                impl.should_process_task_pre_queue = true
                Reseau.process_task_pre_queue(el)

                @test isempty(impl.task_pre_queue)

                read_buf = Ref(UInt64(0))
                read_res = @ccall read(
                    impl.read_task_handle.fd::Cint,
                    read_buf::Ptr{UInt64},
                    sizeof(UInt64)::Csize_t,
                )::Cssize_t
                @test read_res < 0

                Reseau.event_loop_destroy!(el)
            end
        end
    end

    @testset "Kqueue completion port for NW sockets" begin
        if !Sys.isapple()
            @test true
        else
            opts = Reseau.EventLoopOptions()
            el = Reseau.event_loop_new(opts)
            @test !(el isa Reseau.ErrorResult)

            if !(el isa Reseau.ErrorResult)
                try
                    # Verify nw_queue was created
                    @test el.impl_data.nw_queue != C_NULL

                    # Test connect_to_io_completion_port sets the queue
                    handle = Reseau.IoHandle()
                    handle.set_queue = _dispatch_queue_setter_c
                    _dispatch_queue_store[] = C_NULL

                    conn_res = Reseau.event_loop_connect_to_io_completion_port!(el, handle)
                    @test conn_res === nothing
                    @test _dispatch_queue_store[] == el.impl_data.nw_queue

                    # Test with null set_queue
                    handle2 = Reseau.IoHandle()
                    handle2.set_queue = C_NULL
                    conn_res2 = Reseau.event_loop_connect_to_io_completion_port!(el, handle2)
                    @test conn_res2 isa Reseau.ErrorResult
                finally
                    Reseau.event_loop_destroy!(el)
                end
            end
        end
    end
