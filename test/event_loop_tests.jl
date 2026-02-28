using Test
using Reseau

const _dispatch_queue_store = Ref{Ptr{Cvoid}}(C_NULL)

function _dispatch_queue_setter(handle::Ptr{EventLoops.IoHandle}, queue::Ptr{Cvoid})
    _dispatch_queue_store[] = queue
    return nothing
end
const _dispatch_queue_setter_c =
    @cfunction(_dispatch_queue_setter, Cvoid, (Ptr{EventLoops.IoHandle}, Ptr{Cvoid}))

const _EVENT_LOOP_TEST_TIMEOUT_NS = 2_000_000_000

function _wait_for_channel(ch::Channel; timeout_ns::Int = _EVENT_LOOP_TEST_TIMEOUT_NS)
    deadline = Base.time_ns() + timeout_ns
    while !isready(ch) && Base.time_ns() < deadline
        yield()
    end
    return isready(ch)
end

function _wait_for_loop_stop(el::EventLoops.EventLoop; timeout_ns::Int = 5_000_000_000)
    done_ch = Channel{Any}(1)
    errormonitor(Threads.@spawn begin
        try
            EventLoops.wait_for_stop_completion(el)
            put!(done_ch, nothing)
        catch e
            put!(done_ch, e)
        end
    end)
    _wait_for_channel(done_ch; timeout_ns = timeout_ns) || return false
    result = take!(done_ch)
    result === nothing || throw(result)
    return true
end

function _schedule_event_loop_task(el::EventLoops.EventLoop, fn; type_tag::AbstractString = "event_loop_task")
    done_ch = Channel{Any}(1)
    task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
        if Reseau.TaskStatus.T(status) != Reseau.TaskStatus.RUN_READY
            put!(done_ch, Reseau.ReseauError(EventLoops.ERROR_IO_EVENT_LOOP_SHUTDOWN))
            return nothing
        end
        ok = EventLoops.event_loop_thread_is_callers_thread(el)
        result = fn()
        put!(done_ch, (ok, result))
        return nothing
    end); type_tag = type_tag)
    EventLoops.schedule_task_now!(el, task)
    return done_ch
end

function _payload_abc()
    payload = Memory{UInt8}(undef, 3)
    payload[1] = UInt8('a')
    payload[2] = UInt8('b')
    payload[3] = UInt8('c')
    return payload
end

function _drain_pipe(read_end::Sockets.PipeReadEnd)
    buf = Reseau.ByteBuffer(64)
    while true
        try
            Sockets.pipe_read!(read_end, buf)
        catch e
            e isa Reseau.ReseauError || rethrow()
            return e.code == EventLoops.ERROR_IO_READ_WOULD_BLOCK ? nothing : e
        end
    end
end

@testset "Event Loops" begin
    @testset "Epoll pipe cloexec flags" begin
        if Sys.islinux()
            read_fd, write_fd = EventLoops.open_nonblocking_posix_pipe()
            try
                for fd in (read_fd, write_fd)
                    fd_flags = Reseau._fcntl(Cint(fd), Sockets.F_GETFD)
                    @test fd_flags != -1
                    @test (fd_flags & Sockets.FD_CLOEXEC) != 0
                    status_flags = Reseau._fcntl(Cint(fd), Sockets.F_GETFL)
                    @test status_flags != -1
                    @test (status_flags & Sockets.O_NONBLOCK) != 0
                end
            finally
                @ccall close(read_fd::Cint)::Cint
                @ccall close(write_fd::Cint)::Cint
            end
        else
            @test true
        end
    end

    @testset "Event loop scheduling" begin
        el = EventLoops.EventLoop()

        interactive_threads = Base.Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
            close(el)
        else
            run_res = EventLoops.run!(el)
            @test run_res === nothing

            try
                done = Ref(false)
                thread_ok = Ref(false)

                task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                    thread_ok[] = EventLoops.event_loop_thread_is_callers_thread(el)
                    done[] = true
                    return nothing
                end); type_tag = "event_loop_test_task")
                EventLoops.schedule_task_now!(el, task)

                deadline = Base.time_ns() + 2_000_000_000
                while !done[] && Base.time_ns() < deadline
                    yield()
                end

                @test done[]
                @test thread_ok[]
            finally
                close(el)
            end
        end
    end

    @testset "Event loop future scheduling timing" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()

            run_res = EventLoops.run!(el)
            @test run_res === nothing

            try
                done = Ref(false)
                actual_time = Ref{UInt64}(0)

                start_time = Reseau.clock_now_ns()
                target_time = start_time + 50_000_000

                task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                    actual_time[] = Reseau.clock_now_ns()
                    done[] = true
                    return nothing
                end); type_tag = "future_timing")
                EventLoops.schedule_task_future!(el, task, target_time)

                deadline = Base.time_ns() + 2_000_000_000
                while !done[] && Base.time_ns() < deadline
                    yield()
                end

                @test done[]
                if done[]
                    @test actual_time[] >= target_time
                    @test actual_time[] - target_time < 1_000_000_000
                end
            finally
                close(el)
            end
        end
    end

    @testset "Event loop stress scheduling" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()

            run_res = EventLoops.run!(el)
            @test run_res === nothing

            try
                total = 500
                count = Ref(0)
                done_ch = Channel{Nothing}(1)
                count_lock = ReentrantLock()

                for _ in 1:total
                    task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                        local current
                        Base.lock(count_lock) do
                            count[] += 1
                            current = count[]
                        end
                        if current == total
                            put!(done_ch, nothing)
                        end
                        return nothing
                    end); type_tag = "stress_now")
                    EventLoops.schedule_task_now!(el, task)
                end

                deadline = Base.time_ns() + 3_000_000_000
                while !isready(done_ch) && Base.time_ns() < deadline
                    yield()
                end

                @test isready(done_ch)
                isready(done_ch) && take!(done_ch)
            finally
                close(el)
            end
        end
    end

    @testset "Event loop pipe subscribe stress" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()

            run_res = EventLoops.run!(el)
            @test run_res === nothing

            read_end = nothing
            write_end = nothing

            try
                read_end, write_end = Sockets.pipe_create()

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

                on_readable = Reseau.EventCallable(err -> begin
                    if err != Reseau.OP_SUCCESS
                        return nothing
                    end

                    buf = Reseau.ByteBuffer(64)
                    amount = try
                        _, amt = Sockets.pipe_read!(read_end, buf)
                        amt
                    catch e
                        e isa Reseau.ReseauError || rethrow()
                        return nothing
                    end

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
                end)

                sub_res = Sockets.pipe_read_end_subscribe!(read_end, el, on_readable)
                @test sub_res === nothing

                for _ in 1:total_writes
                    Sockets.pipe_write_sync!(write_end, payload)
                end

                deadline = Base.time_ns() + 3_000_000_000
                while !isready(done_ch) && Base.time_ns() < deadline
                    yield()
                end

                @test isready(done_ch)
                isready(done_ch) && take!(done_ch)
            finally
                read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
                close(el)
            end
        end
    end

    @testset "Event loop subscribe/unsubscribe" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Base.Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = EventLoops.EventLoop()

                run_res = EventLoops.run!(el)
                @test run_res === nothing

                read_end = nothing
                write_end = nothing
                try
                    read_end, write_end = Sockets.pipe_create()

                    subscribe_task = _schedule_event_loop_task(el, () -> begin
                        res1 = EventLoops.subscribe_to_io_events!(
                            el,
                            read_end.io_handle,
                            Int(EventLoops.IoEventType.READABLE),
                            EventLoops.EventCallable((events::Int) -> nothing),
                        )
                        res2 = EventLoops.subscribe_to_io_events!(
                            el,
                            write_end.io_handle,
                            Int(EventLoops.IoEventType.WRITABLE),
                            EventLoops.EventCallable((events::Int) -> nothing),
                        )
                        res3 = EventLoops.unsubscribe_from_io_events!(el, read_end.io_handle)
                        res4 = EventLoops.unsubscribe_from_io_events!(el, write_end.io_handle)
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
                    read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                    write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
                    close(el)
                end
            end
        end
    end

    @testset "Event loop subscription payload is stable and owned by handle refs" begin
        if !Sys.islinux()
            @test true
        else
            interactive_threads = Base.Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = EventLoops.EventLoop()

                run_res = EventLoops.run!(el)
                @test run_res === nothing

                read_end = nothing
                write_end = nothing
                try
                    read_end, write_end = Sockets.pipe_create()

                    subscription_task = _schedule_event_loop_task(
                        el,
                        () -> begin
                            EventLoops.subscribe_to_io_events!(
                                el,
                                read_end.io_handle,
                                Int(EventLoops.IoEventType.READABLE),
                                EventLoops.EventCallable((events::Int) -> nothing),
                            )
                            @test read_end.io_handle.additional_data != C_NULL
                            @test read_end.io_handle.additional_ref isa EventLoops.EpollEventHandleData
                            stored_ptr = read_end.io_handle.additional_data
                            stored_ref = read_end.io_handle.additional_ref
                            @test unsafe_pointer_to_objref(stored_ptr) === stored_ref
                            return nothing
                        end;
                        type_tag = "epoll_subscription_payload_capture",
                    )
                    @test _wait_for_channel(subscription_task)

                    unsubscribe_task = _schedule_event_loop_task(
                        el,
                        () -> begin
                            EventLoops.unsubscribe_from_io_events!(el, read_end.io_handle)
                            return nothing
                        end;
                        type_tag = "epoll_subscription_payload_release",
                    )
                    @test _wait_for_channel(unsubscribe_task)

                    @test read_end.io_handle.additional_data == C_NULL
                    @test read_end.io_handle.additional_ref === nothing
                finally
                    read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                    write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
                    close(el)
                end
            end
        end
    end

    @testset "Event loop writable event on subscribe" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Base.Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = EventLoops.EventLoop()

                run_res = EventLoops.run!(el)
                @test run_res === nothing

                read_end = nothing
                write_end = nothing
                try
                    read_end, write_end = Sockets.pipe_create()

                    writable_count = Ref(0)
                    thread_ok = Ref(true)
                    count_lock = ReentrantLock()
                    writable_ch = Channel{Nothing}(1)

                    on_writable = (loop, handle, events, data) -> begin
                        if !EventLoops.event_loop_thread_is_callers_thread(loop)
                            thread_ok[] = false
                        end
                        if (events & Int(EventLoops.IoEventType.WRITABLE)) == 0
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
                        return EventLoops.subscribe_to_io_events!(
                            el,
                            write_end.io_handle,
                            Int(EventLoops.IoEventType.WRITABLE),
                            EventLoops.EventCallable((events::Int) -> on_writable(el, write_end.io_handle, events, nothing)),
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
                        return EventLoops.unsubscribe_from_io_events!(el, write_end.io_handle)
                    end; type_tag = "event_loop_writable_unsubscribe")
                    @test _wait_for_channel(unsub_task)
                    ok2, unsub_res = take!(unsub_task)
                    @test ok2
                    @test unsub_res === nothing
                finally
                    read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                    write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
                    close(el)
                end
            end
        end
    end

    @testset "Event loop no readable event before write" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Base.Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = EventLoops.EventLoop()

                run_res = EventLoops.run!(el)
                @test run_res === nothing

                read_end = nothing
                write_end = nothing
                try
                    read_end, write_end = Sockets.pipe_create()

                    readable_count = Ref(0)
                    count_lock = ReentrantLock()
                    on_readable = (loop, handle, events, data) -> begin
                        if (events & Int(EventLoops.IoEventType.READABLE)) == 0
                            return nothing
                        end
                        Base.lock(count_lock) do
                            readable_count[] += 1
                        end
                        return nothing
                    end

                    sub_task = _schedule_event_loop_task(el, () -> begin
                        return EventLoops.subscribe_to_io_events!(
                            el,
                            read_end.io_handle,
                            Int(EventLoops.IoEventType.READABLE),
                            EventLoops.EventCallable((events::Int) -> on_readable(el, read_end.io_handle, events, nothing)),
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
                        return EventLoops.unsubscribe_from_io_events!(el, read_end.io_handle)
                    end; type_tag = "event_loop_readable_unsubscribe")
                    @test _wait_for_channel(unsub_task)
                    ok2, unsub_res = take!(unsub_task)
                    @test ok2
                    @test unsub_res === nothing
                finally
                    read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                    write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
                    close(el)
                end
            end
        end
    end

    @testset "Event loop readable event on subscribe if data present" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Base.Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = EventLoops.EventLoop()

                run_res = EventLoops.run!(el)
                @test run_res === nothing

                read_end = nothing
                write_end = nothing
                try
                    read_end, write_end = Sockets.pipe_create()

                    payload = _payload_abc()
                    Sockets.pipe_write_sync!(write_end, payload)

                    readable_count = Ref(0)
                    count_lock = ReentrantLock()
                    readable_ch = Channel{Nothing}(1)

                    on_readable = (loop, handle, events, data) -> begin
                        if (events & Int(EventLoops.IoEventType.READABLE)) == 0
                            return nothing
                        end
                        drain_res = _drain_pipe(read_end)
                        if drain_res isa Reseau.ReseauError
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
                        return EventLoops.subscribe_to_io_events!(
                            el,
                            read_end.io_handle,
                            Int(EventLoops.IoEventType.READABLE),
                            EventLoops.EventCallable((events::Int) -> on_readable(el, read_end.io_handle, events, nothing)),
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
                        return EventLoops.unsubscribe_from_io_events!(el, read_end.io_handle)
                    end; type_tag = "event_loop_readable_unsubscribe_present")
                    @test _wait_for_channel(unsub_task)
                    ok2, unsub_res = take!(unsub_task)
                    @test ok2
                    @test unsub_res === nothing
                finally
                    read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                    write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
                    close(el)
                end
            end
        end
    end

    @testset "Event loop readable event after write" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Base.Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = EventLoops.EventLoop()

                run_res = EventLoops.run!(el)
                @test run_res === nothing

                read_end = nothing
                write_end = nothing
                try
                    read_end, write_end = Sockets.pipe_create()

                    writable_ch = Channel{Nothing}(1)
                    readable_ch = Channel{Nothing}(1)
                    readable_count = Ref(0)
                    count_lock = ReentrantLock()

                    on_writable = (loop, handle, events, data) -> begin
                        if (events & Int(EventLoops.IoEventType.WRITABLE)) == 0
                            return nothing
                        end
                        if !isready(writable_ch)
                            put!(writable_ch, nothing)
                        end
                        return nothing
                    end

                    on_readable = (loop, handle, events, data) -> begin
                        if (events & Int(EventLoops.IoEventType.READABLE)) == 0
                            return nothing
                        end
                        drain_res = _drain_pipe(read_end)
                        if drain_res isa Reseau.ReseauError
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
                        res1 = EventLoops.subscribe_to_io_events!(
                            el,
                            write_end.io_handle,
                            Int(EventLoops.IoEventType.WRITABLE),
                            EventLoops.EventCallable((events::Int) -> on_writable(el, write_end.io_handle, events, nothing)),
                        )
                        res2 = EventLoops.subscribe_to_io_events!(
                            el,
                            read_end.io_handle,
                            Int(EventLoops.IoEventType.READABLE),
                            EventLoops.EventCallable((events::Int) -> on_readable(el, read_end.io_handle, events, nothing)),
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
                    Sockets.pipe_write_sync!(write_end, payload)

                    @test _wait_for_channel(readable_ch; timeout_ns = 3_000_000_000)
                    sleep(1.0)

                    Base.lock(count_lock) do
                        @test readable_count[] == 1
                    end

                    unsub_task = _schedule_event_loop_task(el, () -> begin
                        res1 = EventLoops.unsubscribe_from_io_events!(el, write_end.io_handle)
                        res2 = EventLoops.unsubscribe_from_io_events!(el, read_end.io_handle)
                        return (res1, res2)
                    end; type_tag = "event_loop_readable_after_write_unsub")
                    @test _wait_for_channel(unsub_task)
                    ok2, results2 = take!(unsub_task)
                    @test ok2
                    r1, r2 = results2
                    @test r1 === nothing
                    @test r2 === nothing
                finally
                    read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                    write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
                    close(el)
                end
            end
        end
    end

    @testset "Event loop readable event on 2nd time readable" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Base.Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = EventLoops.EventLoop()

                run_res = EventLoops.run!(el)
                @test run_res === nothing

                read_end = nothing
                write_end = nothing
                try
                    read_end, write_end = Sockets.pipe_create()

                    writable_ch = Channel{Nothing}(1)
                    first_readable_ch = Channel{Nothing}(1)
                    second_readable_ch = Channel{Nothing}(1)
                    readable_count = Ref(0)
                    count_lock = ReentrantLock()

                    on_writable = (loop, handle, events, data) -> begin
                        if (events & Int(EventLoops.IoEventType.WRITABLE)) == 0
                            return nothing
                        end
                        if !isready(writable_ch)
                            put!(writable_ch, nothing)
                        end
                        return nothing
                    end

                    on_readable = (loop, handle, events, data) -> begin
                        if (events & Int(EventLoops.IoEventType.READABLE)) == 0
                            return nothing
                        end
                        drain_res = _drain_pipe(read_end)
                        if drain_res isa Reseau.ReseauError
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
                        res1 = EventLoops.subscribe_to_io_events!(
                            el,
                            write_end.io_handle,
                            Int(EventLoops.IoEventType.WRITABLE),
                            EventLoops.EventCallable((events::Int) -> on_writable(el, write_end.io_handle, events, nothing)),
                        )
                        res2 = EventLoops.subscribe_to_io_events!(
                            el,
                            read_end.io_handle,
                            Int(EventLoops.IoEventType.READABLE),
                            EventLoops.EventCallable((events::Int) -> on_readable(el, read_end.io_handle, events, nothing)),
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
                    Sockets.pipe_write_sync!(write_end, payload)

                    @test _wait_for_channel(first_readable_ch; timeout_ns = 3_000_000_000)
                    payload2 = _payload_abc()
                    Sockets.pipe_write_sync!(write_end, payload2)

                    @test _wait_for_channel(second_readable_ch; timeout_ns = 3_000_000_000)

                    Base.lock(count_lock) do
                        @test readable_count[] == 2
                    end

                    unsub_task = _schedule_event_loop_task(el, () -> begin
                        res1 = EventLoops.unsubscribe_from_io_events!(el, write_end.io_handle)
                        res2 = EventLoops.unsubscribe_from_io_events!(el, read_end.io_handle)
                        return (res1, res2)
                    end; type_tag = "event_loop_readable_second_unsub")
                    @test _wait_for_channel(unsub_task)
                    ok2, results2 = take!(unsub_task)
                    @test ok2
                    r1b, r2b = results2
                    @test r1b === nothing
                    @test r2b === nothing
                finally
                    read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                    write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
                    close(el)
                end
            end
        end
    end

    @testset "Event loop no events after unsubscribe" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Base.Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = EventLoops.EventLoop()

                run_res = EventLoops.run!(el)
                @test run_res === nothing

                read_ends = nothing
                write_ends = nothing
                try
                    pipe1 = Sockets.pipe_create()
                    pipe2 = Sockets.pipe_create()
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
                        if (events & Int(EventLoops.IoEventType.WRITABLE)) == 0
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
                                try
                                    Sockets.pipe_write_sync!(write_ends[i], payload)
                                catch e
                                    e isa Reseau.ReseauError || rethrow()
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
                        if (events & Int(EventLoops.IoEventType.READABLE)) == 0
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
                                _ = EventLoops.unsubscribe_from_io_events!(el, read_ends[i].io_handle)
                                _ = EventLoops.unsubscribe_from_io_events!(el, write_ends[i].io_handle)
                                Sockets.pipe_read_end_close!(read_ends[i])
                                Sockets.pipe_write_end_close!(write_ends[i])
                            end

                            unsubscribed[] = true
                        end

                        now = Reseau.clock_now_ns()
                        run_at = now + 1_000_000_000
                        done_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                                if !isready(done_ch)
                                    put!(done_ch, nothing)
                                end
                                return nothing
                            end); type_tag = "unsubrace_done")
                        EventLoops.schedule_task_future!(el, done_task, run_at)
                        return nothing
                    end

                    setup_task = _schedule_event_loop_task(el, () -> begin
                        for i in 1:2
                            _ = EventLoops.subscribe_to_io_events!(
                                el,
                                write_ends[i].io_handle,
                                Int(EventLoops.IoEventType.WRITABLE),
                                EventLoops.EventCallable((events::Int) -> on_writable(el, write_ends[i].io_handle, events, nothing)),
                            )
                            _ = EventLoops.subscribe_to_io_events!(
                                el,
                                read_ends[i].io_handle,
                                Int(EventLoops.IoEventType.READABLE),
                                EventLoops.EventCallable((events::Int) -> on_readable(el, read_ends[i].io_handle, events, nothing)),
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
                            Sockets.pipe_read_end_close!(read_ends[i])
                            Sockets.pipe_write_end_close!(write_ends[i])
                        end
                    end
                    close(el)
                end
            end
        end
    end

    @testset "Event loop group thread affinity" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if interactive_threads <= 2
            @test true
        else
            elg = EventLoops.EventLoopGroup(; loop_count = 2)

            try
                loop1 = EventLoops.get_next_event_loop()
                loop2 = EventLoops.get_next_event_loop()

                @test loop1 !== loop2

                ids1 = Int[]
                ids2 = Int[]
                lock = ReentrantLock()
                done_ch = Channel{Nothing}(1)
                done_count = Ref(0)
                total = 4

                for _ in 1:2
                    task1 = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                        Base.lock(lock) do
                            push!(ids1, Base.Threads.threadid())
                            done_count[] += 1
                            if done_count[] == total
                                put!(done_ch, nothing)
                            end
                        end
                        return nothing
                    end); type_tag = "elg_affinity")
                    EventLoops.schedule_task_now!(loop1, task1)

                    task2 = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                        Base.lock(lock) do
                            push!(ids2, Base.Threads.threadid())
                            done_count[] += 1
                            if done_count[] == total
                                put!(done_ch, nothing)
                            end
                        end
                        return nothing
                    end); type_tag = "elg_affinity")
                    EventLoops.schedule_task_now!(loop2, task2)
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
                close(elg)
            end
        end
    end

    @testset "IoHandle additional_data parity" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Base.Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = EventLoops.EventLoop()

                run_res = EventLoops.run!(el)
                @test run_res === nothing

                read_end = nothing
                write_end = nothing

                try
                    read_end, write_end = Sockets.pipe_create()

                    sub_res = EventLoops.subscribe_to_io_events!(
                        el,
                        read_end.io_handle,
                        Int(EventLoops.IoEventType.READABLE),
                        EventLoops.EventCallable((events::Int) -> nothing),
                    )
                    @test sub_res === nothing
                    @test read_end.io_handle.additional_data != C_NULL

                    done_ch = Channel{Nothing}(1)
                    handle = read_end.io_handle
                    unsub_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                        EventLoops.unsubscribe_from_io_events!(el, handle)
                        put!(done_ch, nothing)
                        return nothing
                    end); type_tag = "handle_unsubscribe")
                    EventLoops.schedule_task_now!(el, unsub_task)

                    deadline = Base.time_ns() + 2_000_000_000
                    while !isready(done_ch) && Base.time_ns() < deadline
                        yield()
                    end

                    @test isready(done_ch)
                    isready(done_ch) && take!(done_ch)
                    @test read_end.io_handle.additional_data == C_NULL
                finally
                    read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                    write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
                    close(el)
                end
            end
        end
    end

    @testset "Event loop unsubscribe error" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()

            run_res = EventLoops.run!(el)
            @test run_res === nothing

            try
                done_ch = Channel{Int}(1)
                bad_handle = EventLoops.IoHandle()
                task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                    code = try
                        EventLoops.unsubscribe_from_io_events!(el, bad_handle)
                        0
                    catch e
                        e isa Reseau.ReseauError ? e.code : rethrow()
                    end
                    put!(done_ch, code)
                    return nothing
                end); type_tag = "unsubscribe_error")
                EventLoops.schedule_task_now!(el, task)

                deadline = Base.time_ns() + 2_000_000_000
                while !isready(done_ch) && Base.time_ns() < deadline
                    yield()
                end

                @test isready(done_ch)
                if isready(done_ch)
                    code = take!(done_ch)
                    @test code == EventLoops.ERROR_IO_NOT_SUBSCRIBED
                end
            finally
                close(el)
            end
        end
    end

    @testset "Event loop syscall error mapping" begin
        if Sys.iswindows()
            @test true
        else
            interactive_threads = Base.Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = EventLoops.EventLoop()

                run_res = EventLoops.run!(el)
                @test run_res === nothing

                read_end = nothing
                write_end = nothing

                try
                    read_end, write_end = Sockets.pipe_create()
                    bad_fd = read_end.io_handle.fd
                    ccall(:close, Cint, (Cint,), bad_fd)
                    read_end.io_handle.fd = -1
                    bad_handle = EventLoops.IoHandle(bad_fd)

                    if Sys.islinux()
                        err = try
                            EventLoops.subscribe_to_io_events!(
                                el,
                                bad_handle,
                                Int(EventLoops.IoEventType.READABLE),
                                EventLoops.EventCallable((events::Int) -> nothing),
                            )
                            nothing
                        catch e
                            e isa Reseau.ReseauError ? e : rethrow()
                        end
                        @test err isa Reseau.ReseauError
                        err isa Reseau.ReseauError && @test err.code == Reseau.ERROR_SYS_CALL_FAILURE
                    elseif Sys.isapple()
                        done_ch = Channel{Int}(1)
                        on_event = (loop, handle, events, data) -> begin
                            _ = EventLoops.unsubscribe_from_io_events!(loop, handle)
                            put!(done_ch, events)
                            return nothing
                        end
                        res = EventLoops.subscribe_to_io_events!(
                            el,
                            bad_handle,
                            Int(EventLoops.IoEventType.READABLE),
                            EventLoops.EventCallable((events::Int) -> on_event(el, bad_handle, events, nothing)),
                        )
                        @test res === nothing

                        deadline = Base.time_ns() + 2_000_000_000
                        while !isready(done_ch) && Base.time_ns() < deadline
                            yield()
                        end

                        @test isready(done_ch)
                        if isready(done_ch)
                            events = take!(done_ch)
                            @test (events & Int(EventLoops.IoEventType.ERROR)) != 0
                        end
                    else
                        @test true
                    end
                finally
                    read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                    write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
                    close(el)
                end
                end
        end
    end

    @testset "Event loop callback mutates another subscription safely" begin
        if Sys.iswindows() || Sys.isapple()
            @test true
        else
            interactive_threads = Base.Threads.nthreads(:interactive)
            if interactive_threads <= 1
                @test true
            else
                el = EventLoops.EventLoop()
                run_res = EventLoops.run!(el)
                @test run_res === nothing

                read_a = nothing
                write_a = nothing
                read_b = nothing
                write_b = nothing
                events_ch = Channel{Symbol}(2)
                on_a_fired = Threads.Atomic{Bool}(false)
                on_b_fired = Threads.Atomic{Bool}(false)

                try
                    read_a, write_a = Sockets.pipe_create()
                    read_b, write_b = Sockets.pipe_create()

                    on_a = (loop, handle, events, data) -> begin
                        _ = handle
                        _ = events
                        _ = data
                        if on_a_fired[]
                            return nothing
                        end
                        on_a_fired[] = true
                        try
                            EventLoops.unsubscribe_from_io_events!(loop, read_b.io_handle)
                        catch e
                            if !(e isa Reseau.ReseauError && e.code == EventLoops.ERROR_IO_NOT_SUBSCRIBED)
                                rethrow()
                            end
                        end
                        _drain_pipe(read_a)
                        put!(events_ch, :a)
                        return nothing
                    end
                    on_b = (loop, handle, events, data) -> begin
                        _ = loop
                        _ = handle
                        _ = events
                        _ = data
                        if on_b_fired[]
                            return nothing
                        end
                        on_b_fired[] = true
                        _drain_pipe(read_b)
                        put!(events_ch, :b)
                        return nothing
                    end

                    sub_done = _schedule_event_loop_task(el, () -> begin
                        @test EventLoops.subscribe_to_io_events!(
                            el,
                            read_a.io_handle,
                            Int(EventLoops.IoEventType.READABLE),
                            EventLoops.EventCallable((events::Int) -> on_a(el, read_a.io_handle, events, nothing)),
                        ) === nothing
                        @test EventLoops.subscribe_to_io_events!(
                            el,
                            read_b.io_handle,
                            Int(EventLoops.IoEventType.READABLE),
                            EventLoops.EventCallable((events::Int) -> on_b(el, read_b.io_handle, events, nothing)),
                        ) === nothing
                        Sockets.pipe_write!(write_a, _payload_abc())
                        Sockets.pipe_write!(write_b, _payload_abc())
                        return nothing
                    end; type_tag = "subscribe_mutating_cb")
                    @test _wait_for_channel(sub_done)

                    # callback on A should run and may unsubscribe B without breaking the loop.
                    deadline = Base.time_ns() + _EVENT_LOOP_TEST_TIMEOUT_NS
                    while !isready(events_ch) && Base.time_ns() < deadline
                        yield()
                    end
                    @test isready(events_ch)
                    @test take!(events_ch) === :a

                    # Loop continues to accept another task after mutation.
                    continue_ch = _schedule_event_loop_task(el, () -> true; type_tag = "post_mutation_task")
                    @test _wait_for_channel(continue_ch)
                finally
                    read_a !== nothing && Sockets.pipe_read_end_close!(read_a)
                    write_a !== nothing && Sockets.pipe_write_end_close!(write_a)
                    read_b !== nothing && Sockets.pipe_read_end_close!(read_b)
                    write_b !== nothing && Sockets.pipe_write_end_close!(write_b)
                    close(el)
                end
            end
        end
    end

    @testset "Event loop serialized ordering" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()

            run_res = EventLoops.run!(el)
            @test run_res === nothing

            try
                order = Int[]
                order_lock = ReentrantLock()
                done_ch = Channel{Nothing}(1)
                total = 5

                for i in 1:total
                    let i = i
                        task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                            local count
                            Base.lock(order_lock) do
                                push!(order, i)
                                count = length(order)
                            end
                            if count == total
                                put!(done_ch, nothing)
                            end
                            return nothing
                        end); type_tag = "serialized_order")
                        EventLoops.schedule_task_now_serialized!(el, task)
                    end
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
                close(el)
            end
        end
    end

    @testset "Kqueue serialized scheduling stress ordering parity" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if !Sys.isapple() || interactive_threads <= 1 || Base.Threads.nthreads() <= 1
            @test true
        else
            el = EventLoops.EventLoop()
            run_res = EventLoops.run!(el)
            @test run_res === nothing

            try
                total_ids = 10_000
                block_size = 200
                deadline = Base.time_ns() + 30_000_000_000

                sync_lock = ReentrantLock()
                next_id = Ref(1)
                last_processed_id = Ref(0)
                total_processed = Ref(0)
                external_scheduled = Ref(0)
                event_loop_scheduled = Ref(0)
                external_finished = Ref(false)
                event_loop_finished = Ref(false)
                ordering_failed = Ref(false)
                external_error = Ref{Any}(nothing)
                event_loop_thread_ok = Ref(true)
                done_ch = Channel{Nothing}(1)

                function claim_next_id(source::Symbol)
                    return Base.lock(sync_lock) do
                        next_id[] > total_ids && return 0
                        id = next_id[]
                        next_id[] += 1
                        if source == :external
                            external_scheduled[] += 1
                        else
                            event_loop_scheduled[] += 1
                        end
                        return id
                    end
                end

                function schedule_payload(id::Int)
                    task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                        if Reseau.TaskStatus.T(status) != Reseau.TaskStatus.RUN_READY
                            Base.lock(sync_lock) do
                                ordering_failed[] = true
                            end
                            return nothing
                        end
                        signal_done = false
                        Base.lock(sync_lock) do
                            if id != last_processed_id[] + 1
                                ordering_failed[] = true
                            end
                            last_processed_id[] = id
                            total_processed[] += 1
                            if total_processed[] == total_ids && !isready(done_ch)
                                signal_done = true
                            end
                        end
                        signal_done && put!(done_ch, nothing)
                        return nothing
                    end); type_tag = "kqueue_serialized_payload")
                    EventLoops.schedule_task_now_serialized!(el, task)
                    return nothing
                end

                function schedule_event_loop_control()
                    control_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                        if Reseau.TaskStatus.T(status) != Reseau.TaskStatus.RUN_READY
                            Base.lock(sync_lock) do
                                ordering_failed[] = true
                                event_loop_finished[] = true
                            end
                            return nothing
                        end
                        if !EventLoops.event_loop_thread_is_callers_thread(el)
                            Base.lock(sync_lock) do
                                event_loop_thread_ok[] = false
                            end
                        end

                        ids_left = true
                        for _ in 1:block_size
                            id = claim_next_id(:event_loop)
                            if id == 0
                                ids_left = false
                                break
                            end
                            schedule_payload(id)
                            yield()
                        end

                        if ids_left
                            schedule_event_loop_control()
                        else
                            Base.lock(sync_lock) do
                                event_loop_finished[] = true
                            end
                        end
                        return nothing
                    end); type_tag = "kqueue_serialized_control")
                    EventLoops.schedule_task_now_serialized!(el, control_task)
                    return nothing
                end

                external_thread = errormonitor(Threads.@spawn begin
                    try
                        while true
                            id = claim_next_id(:external)
                            id == 0 && break
                            schedule_payload(id)
                            yield()
                        end
                    catch e
                        Base.lock(sync_lock) do
                            external_error[] = e
                        end
                    finally
                        Base.lock(sync_lock) do
                            external_finished[] = true
                        end
                    end
                end)

                schedule_event_loop_control()

                while !isready(done_ch) && Base.time_ns() < deadline
                    yield()
                end

                @test isready(done_ch)
                isready(done_ch) && take!(done_ch)

                producers_done = false
                while !producers_done && Base.time_ns() < deadline
                    producers_done = Base.lock(sync_lock) do
                        return external_finished[] && event_loop_finished[]
                    end
                    producers_done || yield()
                end

                @test producers_done
                @test external_error[] === nothing
                wait(external_thread)

                @test Base.lock(sync_lock) do
                    return total_processed[] == total_ids
                end
                @test Base.lock(sync_lock) do
                    return last_processed_id[] == total_ids
                end
                @test Base.lock(sync_lock) do
                    return !ordering_failed[]
                end
                @test Base.lock(sync_lock) do
                    return external_scheduled[] > 0
                end
                @test Base.lock(sync_lock) do
                    return event_loop_scheduled[] > 0
                end
                @test event_loop_thread_ok[]
            finally
                close(el)
            end
        end
    end

    @testset "Event loop cancel task" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()

            run_res = EventLoops.run!(el)
            @test run_res === nothing

            try
                status_ch = Channel{Tuple{Reseau.TaskStatus.T, Bool}}(1)
                future_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                    put!(status_ch, (Reseau.TaskStatus.T(status), EventLoops.event_loop_thread_is_callers_thread(el)))
                    return nothing
                end); type_tag = "future_task")

                now = Reseau.clock_now_ns()
                EventLoops.schedule_task_future!(el, future_task, now + 10_000_000_000)

                cancel_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                    EventLoops.cancel_task!(el, future_task)
                    return nothing
                end); type_tag = "cancel_task")
                EventLoops.schedule_task_now!(el, cancel_task)

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
            finally
                close(el)
            end
        end
    end

    @testset "Event loop destroy cancels pending task" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()

            run_res = EventLoops.run!(el)
            @test run_res === nothing

            status_ch = Channel{Reseau.TaskStatus.T}(1)
            future_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                put!(status_ch, Reseau.TaskStatus.T(status))
                return nothing
            end); type_tag = "future_task_destroy")

            now = Reseau.clock_now_ns()
            EventLoops.schedule_task_future!(el, future_task, now + 10_000_000_000)
            close(el)

            @test isready(status_ch)
            if isready(status_ch)
                status = take!(status_ch)
                @test status == Reseau.TaskStatus.CANCELED
            end
        end
    end

    @testset "Event loop destroy on loop thread throws" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()
            run_res = EventLoops.run!(el)
            @test run_res === nothing
            destroy_called = Ref(false)
            destroy_threw = Ref(false)
            task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return nothing
                destroy_called[] = true
                try
                    close(el)
                catch err
                    destroy_threw[] = err isa ErrorException || err isa AssertionError
                end
                return nothing
            end); type_tag = "destroy_on_loop")
            EventLoops.schedule_task_now!(el, task)
            deadline = Base.time_ns() + 2_000_000_000
            while !destroy_called[] && Base.time_ns() < deadline
                sleep(0.01)
            end
            @test destroy_called[]
            @test destroy_threw[]
            close(el)
        end
    end

    @testset "Event loop group" begin
        elg = EventLoops.EventLoopGroup(; loop_count = 1)

        try
            @test EventLoops.loop_count(elg) == 1
        finally
            close(elg)
        end
    end

    @testset "Event loop group async shutdown" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            elg = EventLoops.EventLoopGroup(; loop_count = 1)

            done = false
            try
                el = EventLoops.get_next_event_loop()
                @test el !== nothing
                if el === nothing
                    return
                end

                release_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                    close(elg)
                    return nothing
                end); type_tag = "elg_release_async")
                EventLoops.schedule_task_now!(el, release_task)
                deadline = Base.time_ns() + 2_000_000_000
                while any(loop -> (@atomic loop.running), elg.event_loops) && Base.time_ns() < deadline
                    yield()
                end
                done = all(loop -> !(@atomic loop.running), elg.event_loops)
                @test done
            finally
                if !done
                    close(elg)
                end
            end
        end
    end

    @testset "Event loop group NUMA setup" begin
        cpu_count = max(1, min(Sys.CPU_THREADS, Int(typemax(UInt16))))
        elg = EventLoops.EventLoopGroup(; loop_count = typemax(UInt16), cpu_group = 0)

        try
            el_count = EventLoops.loop_count(elg)
            @test el_count == cpu_count
        finally
            close(elg)
        end
    end

    @testset "Event loop stop then restart" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()

            run_res = EventLoops.run!(el)
            @test run_res === nothing

            done1 = Channel{Bool}(1)
            task1 = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                if Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY
                    put!(done1, EventLoops.event_loop_thread_is_callers_thread(el))
                end
                return nothing
            end); type_tag = "event_loop_stop_restart_first")
            EventLoops.schedule_task_now!(el, task1)
            @test _wait_for_channel(done1)
            @test take!(done1)

            @test EventLoops.stop!(el) === nothing
            @test _wait_for_loop_stop(el)
            @test EventLoops.run!(el) === nothing

            done2 = Channel{Bool}(1)
            task2 = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                if Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY
                    put!(done2, EventLoops.event_loop_thread_is_callers_thread(el))
                end
                return nothing
            end); type_tag = "event_loop_stop_restart_second")
            EventLoops.schedule_task_now!(el, task2)
            @test _wait_for_channel(done2)
            @test take!(done2)

            close(el)
        end
    end

    @testset "Event loop multiple stops" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()

            run_res = EventLoops.run!(el)
            @test run_res === nothing

            for _ in 1:8
                @test EventLoops.stop!(el) === nothing
            end

            close(el)
        end
    end

    @testset "Event loop group setup and shutdown" begin
        expected = max(1, Sys.CPU_THREADS >> 1)

        elg = EventLoops.EventLoopGroup(; loop_count = 0)

        try
            @test EventLoops.loop_count(elg) == expected
            loop = EventLoops.get_next_event_loop()
            @test loop !== nothing
        finally
            close(elg)
        end
    end

    @testset "Event loop group destroy idempotent" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            elg = EventLoops.EventLoopGroup(; loop_count = 1)

            close(elg)
            @test all(loop -> !(@atomic loop.running), elg.event_loops)
            @test close(elg) === nothing
        end
    end

    @testset "Event loop message pool sharing" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()

            run_res = EventLoops.run!(el)
            @test run_res === nothing

            setup_ch = Channel{Int}(2)
            on_setup = Reseau.ChannelCallable((err, _channel) -> begin
                put!(setup_ch, err)
                return nothing
            end)

            ch1 = Sockets.Channel(el, nothing; on_setup_completed = on_setup, auto_setup = true)
            ch2 = Sockets.Channel(el, nothing; on_setup_completed = on_setup, auto_setup = true)

            @test _wait_for_channel(setup_ch)
            @test _wait_for_channel(setup_ch)
            if isready(setup_ch)
                @test take!(setup_ch) == Reseau.OP_SUCCESS
            end
            if isready(setup_ch)
                @test take!(setup_ch) == Reseau.OP_SUCCESS
            end

            @test ch1.message_pool isa Sockets.MessagePool
            @test ch2.message_pool isa Sockets.MessagePool
            @test ch1.message_pool === ch2.message_pool
            @test el.message_pool === ch1.message_pool

            Sockets.channel_destroy!(ch1)
            Sockets.channel_destroy!(ch2)

            close(el)
            @test el.message_pool === nothing
        end
    end

    @testset "Event loop load factor" begin
        times = UInt64[1_000_000_000, 1_000_000_500, 12_000_000_000]
        clock = EventLoops.SequenceClock(times)

        el = EventLoops.EventLoop()
        Reseau.with_clock(clock) do
            EventLoops.register_tick_start!(el)
            EventLoops.register_tick_end!(el)

            # Force stale state and confirm load factor reports 0
            @atomic el.next_flush_time = UInt64(0)
            @test EventLoops.load_factor(el) == 0
        end
    end

    @testset "Event loop clock override" begin
        clock = EventLoops.RefClock(UInt64(42))

        el = EventLoops.EventLoop()
        Reseau.with_clock(clock) do
            @test Reseau.clock_now_ns() == UInt64(42)
            elg = EventLoops.EventLoopGroup(; loop_count = 1)
            try
                loop = EventLoops.get_next_event_loop()
                @test loop !== nothing
                if loop !== nothing
                    @test Reseau.clock_now_ns() == UInt64(42)
                end
            finally
                close(elg)
            end
        end
    end

    @testset "Event loop group thread constraint" begin
        # OS threads have no interactive thread pool constraint;
        # verify that creating an ELG with a reasonable count succeeds.
        elg = EventLoops.EventLoopGroup(; loop_count = UInt16(2))

        try
            @test EventLoops.loop_count(elg) == 2
        finally
            close(elg)
        end
    end

    @testset "Epoll task pre-queue drain" begin
        if !Sys.islinux()
            @test true
        else
            el = EventLoops.EventLoop()

            impl = el.impl

            tasks = [
                Reseau.ScheduledTask(Reseau.TaskFn(status -> nothing); type_tag = "pre_queue_task_1"),
                Reseau.ScheduledTask(Reseau.TaskFn(status -> nothing); type_tag = "pre_queue_task_2"),
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
            EventLoops.process_task_pre_queue(el)
            @test isempty(impl.task_pre_queue)

            read_buf = Ref(UInt64(0))
            read_res = @ccall read(
                impl.read_task_handle.fd::Cint,
                read_buf::Ptr{UInt64},
                sizeof(UInt64)::Csize_t,
            )::Cssize_t
            @test read_res < 0

            # Verify queue buffers are reused between drain cycles.
            pre_spare = impl.task_pre_queue_spare

            for i in 1:3
                lock(impl.task_pre_queue_mutex)
                push!(impl.task_pre_queue, Reseau.ScheduledTask(
                    Reseau.TaskFn(status -> nothing),
                    type_tag = "pre_queue_task_repeat_" * string(i),
                ))
                unlock(impl.task_pre_queue_mutex)

                impl.should_process_task_pre_queue = true
                EventLoops.process_task_pre_queue(el)
                @test impl.task_pre_queue_spare === pre_spare
            end

            close(el)
        end
    end

    @testset "Epoll cross-thread burst scheduling remains reliable" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if !Sys.islinux() || interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()
            run_res = EventLoops.run!(el)
            @test run_res === nothing

            try
                task_count = 256
                executed = Base.Threads.Atomic{Int}(0)
                tasks = Vector{Reseau.ScheduledTask}()

                for _ in 1:task_count
                    push!(
                        tasks,
                        Reseau.ScheduledTask(
                            Reseau.TaskFn(status -> begin
                                if Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY
                                    Base.Threads.atomic_add!(executed, 1)
                                end
                                return nothing
                            end),
                            type_tag = "epoll_burst_task",
                        ),
                    )
                end

                Threads.@spawn begin
                    for task in tasks
                        EventLoops.schedule_task_now!(el, task)
                    end
                end

                deadline = Base.time_ns() + 5_000_000_000
                while Base.Threads.atomic_load(executed) < task_count && Base.time_ns() < deadline
                    yield()
                end
                @test Base.Threads.atomic_load(executed) == task_count
            finally
                close(el)
            end
        end
    end

    @testset "Epoll wait buffer grows for large burst readiness" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if !Sys.islinux() || interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()
            run_res = EventLoops.run!(el)
            @test run_res === nothing

            read_ends = Vector{Sockets.PipeReadEnd}()
            write_ends = Vector{Sockets.PipeWriteEnd}()
            events_seen = Base.Threads.Atomic{Int}(0)

            try
                impl = el.impl
                burst_count = 256
                payload_byte = Ref{UInt8}(0x31)

                for _ in 1:burst_count
                    read_end, write_end = Sockets.pipe_create()
                    push!(read_ends, read_end)
                    push!(write_ends, write_end)

                    callback = let fd = read_end.io_handle.fd
                        EventLoops.EventCallable(function(events::Int)
                            if (events & Int(EventLoops.IoEventType.READABLE)) == 0
                                return nothing
                            end
                            read_buf = Ref{UInt8}(0)
                            @ccall read(
                                fd::Cint,
                                read_buf::Ptr{UInt8},
                                sizeof(UInt8)::Csize_t,
                            )::Cssize_t
                            Base.Threads.atomic_add!(events_seen, 1)
                            return nothing
                        end)
                    end

                    EventLoops.subscribe_to_io_events!(
                        el,
                        read_end.io_handle,
                        Int(EventLoops.IoEventType.READABLE),
                        callback,
                    )
                end

                for write_end in write_ends
                    write_res = @ccall write(
                        write_end.io_handle.fd::Cint,
                        payload_byte::Ptr{UInt8},
                        sizeof(UInt8)::Csize_t,
                    )::Cssize_t
                    @test write_res == 1
                end

                deadline = Base.time_ns() + 5_000_000_000
                while Base.Threads.atomic_load(events_seen) < burst_count && Base.time_ns() < deadline
                    yield()
                end

                @test Base.Threads.atomic_load(events_seen) == burst_count
                @test impl.event_wait_capacity >= burst_count
            finally
                close(el)

                for read_end in read_ends
                    Sockets.pipe_read_end_close!(read_end)
                end
                for write_end in write_ends
                    Sockets.pipe_write_end_close!(write_end)
                end
            end
        end
    end

    @testset "Epoll duplicate scheduling preserves explicit future timestamp" begin
        if !Sys.islinux()
            @test true
        else
            el = EventLoops.EventLoop()
            run_res = EventLoops.run!(el)
            @test run_res === nothing

            try
                now = Reseau.clock_now_ns()
                future_deadline = now + 250_000_000

                fired = Channel{UInt64}(1)
                scheduled = Channel{Nothing}(1)

                target_task = Reseau.ScheduledTask(
                    Reseau.TaskFn(status -> begin
                        if Reseau.TaskStatus.T(status) != Reseau.TaskStatus.RUN_READY
                            return nothing
                        end
                        now = Reseau.clock_now_ns()
                        put!(fired, now)
                        return nothing
                    end),
                    type_tag = "epoll_future_dedup_task",
                )

                schedule_future_task = Reseau.ScheduledTask(
                    Reseau.TaskFn(status -> begin
                        if Reseau.TaskStatus.T(status) != Reseau.TaskStatus.RUN_READY
                            return nothing
                        end
                        EventLoops.schedule_task_future!(el, target_task, future_deadline)
                        put!(scheduled, nothing)
                        return nothing
                    end),
                    type_tag = "epoll_future_schedule_task",
                )

                EventLoops.schedule_task_now!(el, schedule_future_task)
                @test _wait_for_channel(scheduled)

                # A concurrent cross-thread schedule for the same task must not rewrite the future timestamp.
                EventLoops.schedule_task_now!(el, target_task)

                if _wait_for_channel(fired)
                    @test take!(fired) >= future_deadline
                else
                    @test false
                end
            finally
                close(el)
            end
        end
    end

    @testset "Epoll cancel-schedule churn stays race-free on same task id" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if !Sys.islinux() || interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()
            run_res = EventLoops.run!(el)
            @test run_res === nothing

            try
                churn_count = 64
                request_ch = Channel{Nothing}(1)
                status_ch = Channel{Reseau.TaskStatus.T}(churn_count)
                canceled_count = Base.Threads.Atomic{Int}(0)
                churn_task = Reseau.ScheduledTask(
                    Reseau.TaskFn(status -> begin
                        put!(status_ch, Reseau.TaskStatus.T(status))
                        return nothing
                    end),
                    type_tag = "epoll_churn_task",
                )

                canceller_task = Reseau.ScheduledTask(
                    Reseau.TaskFn(status -> begin
                        if Reseau.TaskStatus.T(status) != Reseau.TaskStatus.RUN_READY
                            return nothing
                        end

                        if isready(request_ch)
                            take!(request_ch)
                            EventLoops.cancel_task!(el, churn_task)
                            Base.Threads.atomic_add!(canceled_count, 1)
                        end

                        if Base.Threads.atomic_load(canceled_count) < churn_count
                            EventLoops.schedule_task_now!(el, canceller_task)
                        end
                        return nothing
                    end),
                    type_tag = "epoll_churn_canceller",
                )

                EventLoops.schedule_task_now!(el, canceller_task)

                for i in 1:churn_count
                    now = Reseau.clock_now_ns()
                    EventLoops.schedule_task_future!(
                        el,
                        churn_task,
                        now + UInt64(10_000_000_000),
                    )
                    put!(request_ch, nothing)

                    deadline = Base.time_ns() + 2_000_000_000
                    while Base.Threads.atomic_load(canceled_count) < i && Base.time_ns() < deadline
                        yield()
                    end
                    @test Base.Threads.atomic_load(canceled_count) >= i
                end

                for _ in 1:churn_count
                    @test _wait_for_channel(status_ch)
                    @test take!(status_ch) == Reseau.TaskStatus.CANCELED
                end
            finally
                close(el)
            end
        end
    end

    @testset "Epoll exact-capacity wait still dispatches events" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if !Sys.islinux() || interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()
            impl = el.impl
            impl.event_wait_capacity = 1
            run_res = EventLoops.run!(el)
            @test run_res === nothing

            read_end = nothing
            write_end = nothing
            try
                read_end, write_end = Sockets.pipe_create()
                readable_ch = Channel{Int}(1)

                callback = let fd = read_end.io_handle.fd
                    EventLoops.EventCallable(function(events::Int)
                        if (events & Int(EventLoops.IoEventType.READABLE)) == 0
                            return nothing
                        end
                        read_buf = Ref{UInt8}(0)
                        _ = @ccall read(
                            fd::Cint,
                            read_buf::Ptr{UInt8},
                            sizeof(UInt8)::Csize_t,
                        )::Cssize_t
                        if !isready(readable_ch)
                            put!(readable_ch, 1)
                        end
                        return nothing
                    end)
                end

                EventLoops.subscribe_to_io_events!(
                    el,
                    read_end.io_handle,
                    Int(EventLoops.IoEventType.READABLE),
                    callback,
                )

                payload_byte = Ref{UInt8}(0x31)
                write_res = @ccall write(
                    write_end.io_handle.fd::Cint,
                    payload_byte::Ptr{UInt8},
                    sizeof(UInt8)::Csize_t,
                )::Cssize_t
                @test write_res == 1

                @test _wait_for_channel(readable_ch; timeout_ns = 3_000_000_000)
                if isready(readable_ch)
                    @test take!(readable_ch) == 1
                end
                @test impl.event_wait_capacity >= 2
            finally
                close(el)
                read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
            end
        end
    end

    @testset "Epoll close releases remaining subscription payload roots" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if !Sys.islinux() || interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()
            run_res = EventLoops.run!(el)
            @test run_res === nothing

            read_end = nothing
            write_end = nothing
            loop_closed = false
            try
                read_end, write_end = Sockets.pipe_create()

                sub_task = _schedule_event_loop_task(
                    el,
                    () -> begin
                        EventLoops.subscribe_to_io_events!(
                            el,
                            read_end.io_handle,
                            Int(EventLoops.IoEventType.READABLE),
                            EventLoops.EventCallable((events::Int) -> nothing),
                        )
                        return nothing
                    end;
                    type_tag = "epoll_close_releases_subscription_payload",
                )

                @test _wait_for_channel(sub_task)
                ok, sub_res = take!(sub_task)
                @test ok
                @test sub_res === nothing
                @test read_end.io_handle.additional_data != C_NULL
                @test read_end.io_handle.additional_ref isa EventLoops.EpollEventHandleData

                close(el)
                loop_closed = true
                @test read_end.io_handle.additional_data == C_NULL
                @test read_end.io_handle.additional_ref === nothing
            finally
                !loop_closed && close(el)
                read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
            end
        end
    end

    @testset "Epoll subscribe rejects blocking descriptors" begin
        if !Sys.islinux()
            @test true
        else
            el = EventLoops.EventLoop()
            pipe_fds = Ref{NTuple{2, Int32}}((Int32(-1), Int32(-1)))
            pipe_rc = @ccall pipe(pipe_fds::Ptr{Int32})::Cint
            @test pipe_rc == 0
            read_fd = pipe_fds[][1]
            write_fd = pipe_fds[][2]
            handle = EventLoops.IoHandle(read_fd)

            try
                status_flags = Reseau._fcntl(Cint(read_fd), Sockets.F_GETFL)
                @test status_flags != -1
                @test (status_flags & Sockets.O_NONBLOCK) == 0

                err = nothing
                try
                    EventLoops.subscribe_to_io_events!(
                        el,
                        handle,
                        Int(EventLoops.IoEventType.READABLE),
                        EventLoops.EventCallable((events::Int) -> nothing),
                    )
                catch e
                    err = e
                end

                @test err isa Reseau.ReseauError
                if err isa Reseau.ReseauError
                    @test err.code == EventLoops.ERROR_INVALID_ARGUMENT
                end
            finally
                close(el)
                read_fd >= 0 && (@ccall close(read_fd::Cint)::Cint)
                write_fd >= 0 && (@ccall close(write_fd::Cint)::Cint)
            end
        end
    end

    @testset "Kqueue subscribe rejects empty event mask" begin
        if !Sys.isapple()
            @test true
        else
            el = EventLoops.EventLoop()

            read_end = nothing
            write_end = nothing
            try
                read_end, write_end = Sockets.pipe_create()

                err = nothing
                try
                    EventLoops.subscribe_to_io_events!(
                        el,
                        read_end.io_handle,
                        0,
                        EventLoops.EventCallable((events::Int) -> nothing),
                    )
                catch e
                    err = e
                end

                @test err isa Reseau.ReseauError
                if err isa Reseau.ReseauError
                    @test err.code == EventLoops.ERROR_INVALID_ARGUMENT
                end
                @test read_end.io_handle.additional_data == C_NULL
                @test read_end.io_handle.additional_ref === nothing
            finally
                close(el)
                read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
            end
        end
    end

    @testset "Kqueue cleanup task doesn't underflow connected handle count" begin
        if !Sys.isapple()
            @test true
        else
            el = EventLoops.EventLoop()

            read_end = nothing
            write_end = nothing
            try
                read_end, write_end = Sockets.pipe_create()

                impl = el.impl
                handle_data = EventLoops.KqueueHandleData(
                    read_end.io_handle,
                    impl,
                    EventLoops.EventCallable(err -> nothing),
                    Int(EventLoops.IoEventType.READABLE),
                )

                # cleanup should only decrement once for active handles.
                @test impl.thread_data.connected_handle_count == 0
                @test !handle_data.connected
                EventLoops.kqueue_cleanup_task_callback(handle_data, Reseau.TaskStatus.RUN_READY)
                @test impl.thread_data.connected_handle_count == 0

                handle_data.connected = true
                impl.thread_data.connected_handle_count = 1
                EventLoops.kqueue_cleanup_task_callback(handle_data, Reseau.TaskStatus.RUN_READY)
                @test impl.thread_data.connected_handle_count == 0

                @test impl.subscribe_changelist isa Vector{EventLoops.Kevent}
                @test impl.subscribe_eventlist isa Vector{EventLoops.Kevent}
                @test impl.unsubscribe_changelist isa Vector{EventLoops.Kevent}
            finally
                read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
            end
        end
    end

    @testset "Kqueue canceled unsubscribe still runs cleanup" begin
        if !Sys.isapple()
            @test true
        else
            el = EventLoops.EventLoop()

            read_end = nothing
            write_end = nothing
            try
                read_end, write_end = Sockets.pipe_create()

                impl = el.impl
                handle_data = EventLoops.KqueueHandleData(
                    read_end.io_handle,
                    impl,
                    EventLoops.EventCallable(err -> nothing),
                    Int(EventLoops.IoEventType.READABLE),
                )

                key = pointer_from_objref(handle_data)
                handle_data.registry_key = key
                impl.handle_registry[key] = handle_data
                handle_data.connected = true
                impl.thread_data.connected_handle_count = 1

                EventLoops.kqueue_unsubscribe_task_callback(handle_data, Reseau.TaskStatus.CANCELED)

                @test !handle_data.connected
                @test impl.thread_data.connected_handle_count == 0
                @test handle_data.registry_key == C_NULL
                @test !haskey(impl.handle_registry, key)
            finally
                read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
            end
        end
    end

    @testset "Kqueue close cleans up active subscriptions" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if !Sys.isapple() || interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()
            run_res = EventLoops.run!(el)
            @test run_res === nothing

            read_end = nothing
            write_end = nothing
            loop_closed = false
            try
                read_end, write_end = Sockets.pipe_create()
                handle = read_end.io_handle

                sub_res = EventLoops.subscribe_to_io_events!(
                    el,
                    handle,
                    Int(EventLoops.IoEventType.READABLE),
                    EventLoops.EventCallable((events::Int) -> nothing),
                )
                @test sub_res === nothing

                handle_data = nothing
                subscribed = false
                wait_deadline = Base.time_ns() + 2_000_000_000
                while Base.time_ns() < wait_deadline
                    if handle.additional_data != C_NULL
                        handle_data = unsafe_pointer_to_objref(handle.additional_data)::EventLoops.KqueueHandleData{EventLoops.KqueueEventLoop}
                        if handle_data.state == EventLoops.HandleState.SUBSCRIBED && handle_data.connected
                            subscribed = true
                            break
                        end
                    end
                    yield()
                end

                @test subscribed
                if subscribed
                    impl = el.impl
                    registry_key = handle_data.registry_key
                    @test haskey(impl.handle_registry, registry_key)
                    @test impl.thread_data.connected_handle_count == 1

                    close(el)
                    loop_closed = true

                    @test handle.additional_data == C_NULL
                    @test handle.additional_ref === nothing
                    @test handle_data.state == EventLoops.HandleState.UNSUBSCRIBED
                    @test !handle_data.connected
                    @test handle_data.registry_key == C_NULL
                    @test impl.thread_data.connected_handle_count == 0
                    @test isempty(impl.handle_registry)
                end
            finally
                !loop_closed && close(el)
                read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
            end
        end
    end

    @testset "IOCP OVERLAPPED_ENTRY layout" begin
        if !Sys.iswindows()
            @test true
        else
            expected_size = Sys.WORD_SIZE == 64 ? 32 : 16
            @test sizeof(EventLoops.OverlappedEntry) == expected_size
            @test fieldoffset(EventLoops.OverlappedEntry, 4) == 3 * sizeof(UInt)
        end
    end

    @testset "IOCP completion callback arguments" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if !Sys.iswindows() || interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()
            read_end = nothing
            write_end = nothing
            try
                @test EventLoops.run!(el) === nothing
                read_end, write_end = Sockets.pipe_init(el, el)

                completion_ch = Channel{Any}(1)
                payload = Vector{UInt8}("Cherry Pie")
                overlapped = EventLoops.IocpOverlapped()
                EventLoops.iocp_overlapped_init!(
                    overlapped,
                    (loop, completed, status_code, bytes_transferred) -> begin
                        put!(completion_ch, (loop, completed, status_code, bytes_transferred, EventLoops.event_loop_thread_is_callers_thread(loop)))
                        return nothing
                    end,
                    nothing,
                )

                write_ok = GC.@preserve payload overlapped ccall(
                    (:WriteFile, "Kernel32"),
                    Int32,
                    (Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{UInt32}, Ptr{Cvoid}),
                    write_end.io_handle.handle,
                    pointer(payload),
                    UInt32(length(payload)),
                    C_NULL,
                    EventLoops.iocp_overlapped_ptr(overlapped),
                ) != 0
                @test write_ok || EventLoops._win_get_last_error() == UInt32(997)

                @test _wait_for_channel(completion_ch; timeout_ns = 3_000_000_000)
                if isready(completion_ch)
                    cb_loop, cb_overlapped, cb_status, cb_bytes, cb_thread_ok = take!(completion_ch)
                    @test cb_loop === el
                    @test cb_overlapped === overlapped
                    @test cb_status == 0
                    @test cb_bytes == Csize_t(length(payload))
                    @test cb_thread_ok
                end
            finally
                read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
                close(el)
            end
        end
    end

    @testset "IOCP rerun clears stop state" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if !Sys.iswindows() || interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()
            try
                @test EventLoops.run!(el) === nothing

                ran_first = Channel{Bool}(1)
                first_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                    put!(ran_first, Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY)
                    return nothing
                end); type_tag = "iocp_rerun_first")
                EventLoops.schedule_task_now!(el, first_task)
                @test _wait_for_channel(ran_first)
                if isready(ran_first)
                    @test take!(ran_first)
                end

                EventLoops.stop!(el)
                @test _wait_for_loop_stop(el)
                @test !(@atomic el.running)
                @test !(@atomic el.should_stop)
                @test el.impl.synced_data.state == EventLoops.IocpEventThreadState.READY_TO_RUN
                @test el.impl.thread_data.state == EventLoops.IocpEventThreadState.READY_TO_RUN

                @test EventLoops.run!(el) === nothing

                ran_second = Channel{Bool}(1)
                second_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                    put!(ran_second, Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY)
                    return nothing
                end); type_tag = "iocp_rerun_second")
                EventLoops.schedule_task_now!(el, second_task)
                @test _wait_for_channel(ran_second)
                if isready(ran_second)
                    @test take!(ran_second)
                end
            finally
                close(el)
            end
        end
    end

    @testset "IOCP wake failure rolls back stop signal latch" begin
        if !Sys.iswindows()
            @test true
        else
            el = EventLoops.EventLoop()
            impl = el.impl
            original_handle = impl.iocp_handle
            try
                lock(impl.synced_data.mutex)
                try
                    impl.synced_data.state = EventLoops.IocpEventThreadState.RUNNING
                    impl.synced_data.thread_signaled = false
                finally
                    unlock(impl.synced_data.mutex)
                end

                impl.iocp_handle = C_NULL
                EventLoops.stop!(el)

                lock(impl.synced_data.mutex)
                try
                    @test impl.synced_data.state == EventLoops.IocpEventThreadState.STOPPING
                    @test !impl.synced_data.thread_signaled
                finally
                    unlock(impl.synced_data.mutex)
                end
            finally
                impl.iocp_handle = original_handle
                lock(impl.synced_data.mutex)
                try
                    impl.synced_data.state = EventLoops.IocpEventThreadState.READY_TO_RUN
                    impl.synced_data.thread_signaled = false
                finally
                    unlock(impl.synced_data.mutex)
                end
                impl.thread_data.state = EventLoops.IocpEventThreadState.READY_TO_RUN
                @atomic el.should_stop = false
                close(el)
            end
        end
    end

    @testset "IOCP wake failure rolls back schedule signal latch" begin
        if !Sys.iswindows()
            @test true
        else
            el = EventLoops.EventLoop()
            impl = el.impl
            original_handle = impl.iocp_handle
            try
                lock(impl.synced_data.mutex)
                try
                    impl.synced_data.state = EventLoops.IocpEventThreadState.RUNNING
                    impl.synced_data.thread_signaled = false
                finally
                    unlock(impl.synced_data.mutex)
                end

                impl.iocp_handle = C_NULL
                task = Reseau.ScheduledTask(Reseau.TaskFn(_ -> nothing); type_tag = "iocp_failed_signal_schedule")
                EventLoops.schedule_task_now_serialized!(el, task)

                lock(impl.synced_data.mutex)
                try
                    @test !impl.synced_data.thread_signaled
                    @test any(x -> x === task, impl.synced_data.tasks_to_schedule)
                finally
                    unlock(impl.synced_data.mutex)
                end
            finally
                impl.iocp_handle = original_handle
                lock(impl.synced_data.mutex)
                try
                    impl.synced_data.state = EventLoops.IocpEventThreadState.READY_TO_RUN
                    impl.synced_data.thread_signaled = false
                    empty!(impl.synced_data.tasks_to_schedule)
                    empty!(impl.synced_data.tasks_to_schedule_spare)
                finally
                    unlock(impl.synced_data.mutex)
                end
                impl.thread_data.state = EventLoops.IocpEventThreadState.READY_TO_RUN
                close(el)
            end
        end
    end

    @testset "Kqueue completion port for NW sockets" begin
        if !Sys.isapple()
            @test true
        else
            el = EventLoops.EventLoop()

            try
                # Verify nw_queue was created
                @test el.impl.nw_queue != C_NULL

                # Test connect_to_io_completion_port sets the queue
                handle = EventLoops.IoHandle()
                handle.set_queue = _dispatch_queue_setter_c
                _dispatch_queue_store[] = C_NULL

                conn_res = EventLoops.connect_to_io_completion_port(el, handle)
                @test conn_res === nothing
                @test _dispatch_queue_store[] == el.impl.nw_queue

                # If dispatch queue setup failed/was unavailable, the call must fail safely.
                original_queue = el.impl.nw_queue
                el.impl.nw_queue = C_NULL
                @test_throws Reseau.ReseauError EventLoops.connect_to_io_completion_port(el, handle)
                el.impl.nw_queue = original_queue

                # Test with null set_queue
                handle2 = EventLoops.IoHandle()
                handle2.set_queue = C_NULL
                @test_throws Reseau.ReseauError EventLoops.connect_to_io_completion_port(el, handle2)
            finally
                close(el)
            end
        end
    end

    @testset "Kqueue off-thread unsubscribe removes registry entry and decrements count" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if !Sys.isapple() || interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()
            run_res = EventLoops.run!(el)
            @test run_res === nothing

            read_end = nothing
            write_end = nothing
            try
                read_end, write_end = Sockets.pipe_create()
                handle = read_end.io_handle
                sub_res = EventLoops.subscribe_to_io_events!(
                    el,
                    handle,
                    Int(EventLoops.IoEventType.READABLE),
                    EventLoops.EventCallable((events::Int) -> nothing),
                )
                @test sub_res === nothing

                handle_data = nothing
                subscribed = false
                wait_deadline = Base.time_ns() + 2_000_000_000
                while Base.time_ns() < wait_deadline
                    if handle.additional_data != C_NULL
                        handle_data = unsafe_pointer_to_objref(handle.additional_data)::EventLoops.KqueueHandleData{EventLoops.KqueueEventLoop}
                        if handle_data.state == EventLoops.HandleState.SUBSCRIBED && handle_data.connected
                            subscribed = true
                            break
                        end
                    end
                    yield()
                end

                @test subscribed
                if subscribed
                    @test !EventLoops.event_loop_thread_is_callers_thread(el)

                    impl = el.impl
                    registry_key = handle_data.registry_key
                    @test haskey(impl.handle_registry, registry_key)
                    @test impl.thread_data.connected_handle_count == 1

                    EventLoops.unsubscribe_from_io_events!(el, handle)

                    cleaned = false
                    cleanup_deadline = Base.time_ns() + 2_000_000_000
                    while Base.time_ns() < cleanup_deadline
                        if handle.additional_data == C_NULL &&
                                !handle_data.connected &&
                                handle_data.registry_key == C_NULL &&
                                impl.thread_data.connected_handle_count == 0 &&
                                !haskey(impl.handle_registry, registry_key)
                            cleaned = true
                            break
                        end
                        yield()
                    end

                    @test cleaned
                end
            finally
                read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
                close(el)
            end
        end
    end

    @testset "Kqueue unsubscribe cleans up synchronously when loop is stopped" begin
        interactive_threads = Base.Threads.nthreads(:interactive)
        if !Sys.isapple() || interactive_threads <= 1
            @test true
        else
            el = EventLoops.EventLoop()
            run_res = EventLoops.run!(el)
            @test run_res === nothing

            read_end = nothing
            write_end = nothing
            try
                read_end, write_end = Sockets.pipe_create()
                handle = read_end.io_handle

                sub_res = EventLoops.subscribe_to_io_events!(
                    el,
                    handle,
                    Int(EventLoops.IoEventType.READABLE),
                    EventLoops.EventCallable((events::Int) -> nothing),
                )
                @test sub_res === nothing

                handle_data = nothing
                subscribed = false
                wait_deadline = Base.time_ns() + 2_000_000_000
                while Base.time_ns() < wait_deadline
                    if handle.additional_data != C_NULL
                        handle_data = unsafe_pointer_to_objref(handle.additional_data)::EventLoops.KqueueHandleData{EventLoops.KqueueEventLoop}
                        if handle_data.state == EventLoops.HandleState.SUBSCRIBED && handle_data.connected
                            subscribed = true
                            break
                        end
                    end
                    yield()
                end

                @test subscribed
                if subscribed
                    impl = el.impl
                    registry_key = handle_data.registry_key
                    @test haskey(impl.handle_registry, registry_key)
                    @test impl.thread_data.connected_handle_count == 1

                    EventLoops.stop!(el)
                    @test _wait_for_loop_stop(el)
                    @test !(@atomic el.running)

                    EventLoops.unsubscribe_from_io_events!(el, handle)

                    @test handle.additional_data == C_NULL
                    @test !handle_data.connected
                    @test handle_data.registry_key == C_NULL
                    @test impl.thread_data.connected_handle_count == 0
                    @test !haskey(impl.handle_registry, registry_key)
                end
            finally
                read_end !== nothing && Sockets.pipe_read_end_close!(read_end)
                write_end !== nothing && Sockets.pipe_write_end_close!(write_end)
                close(el)
            end
        end
    end
end
