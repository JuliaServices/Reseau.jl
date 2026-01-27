using Test
using AwsIO

const _dispatch_queue_store = Ref{Ptr{Cvoid}}(C_NULL)
function _dispatch_queue_setter(handle::Ptr{AwsIO.IoHandle}, queue::Ptr{Cvoid})
    _dispatch_queue_store[] = queue
    return nothing
end
const _dispatch_queue_setter_c =
    @cfunction(_dispatch_queue_setter, Cvoid, (Ptr{AwsIO.IoHandle}, Ptr{Cvoid}))

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
