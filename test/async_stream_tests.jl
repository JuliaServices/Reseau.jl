using Test
using Reseau

mutable struct AsyncStreamTestState
    data::Vector{UInt8}
    offset::Int
    event_loop::Union{EventLoops.EventLoop, Nothing}
    completion_strategy::Symbol
    max_bytes_per_read::Int
    fail_on_nth_read::Int
    fail_error_code::Int
    read_count::Int
    eof_requires_extra_read::Bool
    pending_eof::Bool
end

function AsyncStreamTestState(;
        data::Vector{UInt8},
        event_loop::Union{EventLoops.EventLoop, Nothing} = nothing,
        completion_strategy::Symbol = :immediate,
        max_bytes_per_read::Int = 0,
        fail_on_nth_read::Int = 0,
        fail_error_code::Int = 0,
        eof_requires_extra_read::Bool = false,
    )
    return AsyncStreamTestState(
        data,
        0,
        event_loop,
        completion_strategy,
        max_bytes_per_read,
        fail_on_nth_read,
        fail_error_code,
        0,
        eof_requires_extra_read,
        false,
    )
end

function _async_test_read(stream::Sockets.AsyncInputStream, dest::Reseau.ByteBuffer)
    state = stream.impl
    future = EventLoops.Future{Bool}()

    function do_read!()
        state.read_count += 1
        if state.fail_on_nth_read > 0 && state.read_count == state.fail_on_nth_read
            EventLoops.future_fail!(future, state.fail_error_code)
            return nothing
        end

        if state.offset >= length(state.data)
            if state.eof_requires_extra_read && !state.pending_eof
                state.pending_eof = true
                EventLoops.future_complete!(future, false)
                return nothing
            end
            state.pending_eof = false
            EventLoops.future_complete!(future, true)
            return nothing
        end

        available = Int(Reseau.capacity(dest) - dest.len)
        remaining = length(state.data) - state.offset
        limit = state.max_bytes_per_read > 0 ? state.max_bytes_per_read : remaining
        to_copy = min(available, remaining, limit)

        if to_copy > 0
            copyto!(dest.mem, Int(dest.len) + 1, state.data, state.offset + 1, to_copy)
            dest.len += Csize_t(to_copy)
            state.offset += to_copy
        end

        eof = state.offset >= length(state.data)
        if eof && state.eof_requires_extra_read
            state.pending_eof = true
            eof = false
        end
        EventLoops.future_complete!(future, eof)
        return nothing
    end

    if state.completion_strategy == :event_loop
        if state.event_loop !== nothing
            task = Reseau.ScheduledTask(Reseau.TaskFn(status -> do_read!());
                type_tag = "async_stream_test_read",
            )
            EventLoops.event_loop_schedule_task_now!(state.event_loop, task)
        else
            do_read!()
        end
    elseif state.completion_strategy == :random
        next_read = state.read_count + 1
        if isodd(next_read) && state.event_loop !== nothing
            task = Reseau.ScheduledTask(Reseau.TaskFn(status -> do_read!());
                type_tag = "async_stream_test_read",
            )
            EventLoops.event_loop_schedule_task_now!(state.event_loop, task)
        else
            do_read!()
        end
    else
        do_read!()
    end

    return future
end

@testset "async input stream read_to_fill sync" begin
    state = AsyncStreamTestState(data = collect(codeunits("hello world")))
    stream = Sockets.AsyncInputStream(_async_test_read, s -> nothing, state)

    dest = Reseau.ByteBuffer(5)
    fut = Sockets.async_input_stream_read_to_fill(stream, dest)
    @test EventLoops.future_wait(fut)
    @test EventLoops.future_is_success(fut)
    @test EventLoops.future_get_result(fut) == false
    @test String(Reseau.byte_cursor_from_buf(dest)) == "hello"

    dest2 = Reseau.ByteBuffer(6)
    fut2 = Sockets.async_input_stream_read_to_fill(stream, dest2)
    @test EventLoops.future_wait(fut2)
    @test EventLoops.future_is_success(fut2)
    @test EventLoops.future_get_result(fut2) == true
    @test String(Reseau.byte_cursor_from_buf(dest2)) == " world"

    dest_full = Reseau.ByteBuffer(0)
    fut3 = Sockets.async_input_stream_read(stream, dest_full)
    @test EventLoops.future_is_failed(fut3)
    @test EventLoops.future_get_error(fut3) == Reseau.ERROR_SHORT_BUFFER
end

@testset "async input stream read_to_fill async" begin
    elg = EventLoops.EventLoopGroup(EventLoops.EventLoopGroupOptions(; loop_count = 1))
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    state = AsyncStreamTestState(data = collect(codeunits("abcd")), event_loop = event_loop, completion_strategy = :event_loop)
    stream = Sockets.AsyncInputStream(_async_test_read, s -> nothing, state)

    dest = Reseau.ByteBuffer(4)
    fut = Sockets.async_input_stream_read_to_fill(stream, dest)
    @test EventLoops.future_wait(fut)
    @test EventLoops.future_is_success(fut)
    @test EventLoops.future_get_result(fut) == true
    @test String(Reseau.byte_cursor_from_buf(dest)) == "abcd"

    EventLoops.event_loop_group_destroy!(elg)
end

@testset "async input stream fill completes on thread" begin
    elg = EventLoops.EventLoopGroup(EventLoops.EventLoopGroupOptions(; loop_count = 1))
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    state = AsyncStreamTestState(
        data = collect(codeunits("123456789")),
        event_loop = event_loop,
        completion_strategy = :event_loop,
        max_bytes_per_read = 1,
    )
    stream = Sockets.AsyncInputStream(_async_test_read, s -> nothing, state)

    buf = Reseau.ByteBuffer(5)
    fut = Sockets.async_input_stream_read_to_fill(stream, buf)
    @test EventLoops.future_wait(fut)
    @test EventLoops.future_is_success(fut)
    @test EventLoops.future_get_result(fut) == false
    @test String(Reseau.byte_cursor_from_buf(buf)) == "12345"

    buf.len = 0
    fut2 = Sockets.async_input_stream_read_to_fill(stream, buf)
    @test EventLoops.future_wait(fut2)
    @test EventLoops.future_is_success(fut2)
    @test EventLoops.future_get_result(fut2) == true
    @test String(Reseau.byte_cursor_from_buf(buf)) == "6789"

    EventLoops.event_loop_group_destroy!(elg)
end

@testset "async input stream fill completes immediately" begin
    state = AsyncStreamTestState(
        data = collect(codeunits("123456789")),
        completion_strategy = :immediate,
        max_bytes_per_read = 1,
    )
    stream = Sockets.AsyncInputStream(_async_test_read, s -> nothing, state)

    buf = Reseau.ByteBuffer(5)
    fut = Sockets.async_input_stream_read_to_fill(stream, buf)
    @test EventLoops.future_wait(fut)
    @test EventLoops.future_is_success(fut)
    @test EventLoops.future_get_result(fut) == false
    @test String(Reseau.byte_cursor_from_buf(buf)) == "12345"

    buf.len = 0
    fut2 = Sockets.async_input_stream_read_to_fill(stream, buf)
    @test EventLoops.future_wait(fut2)
    @test EventLoops.future_is_success(fut2)
    @test EventLoops.future_get_result(fut2) == true
    @test String(Reseau.byte_cursor_from_buf(buf)) == "6789"
end

@testset "async input stream fill completes randomly" begin
    elg = EventLoops.EventLoopGroup(EventLoops.EventLoopGroupOptions(; loop_count = 1))
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    state = AsyncStreamTestState(
        data = collect(codeunits("123456789")),
        event_loop = event_loop,
        completion_strategy = :random,
        max_bytes_per_read = 1,
    )
    stream = Sockets.AsyncInputStream(_async_test_read, s -> nothing, state)

    buf = Reseau.ByteBuffer(5)
    fut = Sockets.async_input_stream_read_to_fill(stream, buf)
    @test EventLoops.future_wait(fut)
    @test EventLoops.future_is_success(fut)
    @test EventLoops.future_get_result(fut) == false
    @test String(Reseau.byte_cursor_from_buf(buf)) == "12345"

    buf.len = 0
    fut2 = Sockets.async_input_stream_read_to_fill(stream, buf)
    @test EventLoops.future_wait(fut2)
    @test EventLoops.future_is_success(fut2)
    @test EventLoops.future_get_result(fut2) == true
    @test String(Reseau.byte_cursor_from_buf(buf)) == "6789"

    EventLoops.event_loop_group_destroy!(elg)
end

@testset "async input stream fill eof requires extra read" begin
    state = AsyncStreamTestState(
        data = collect(codeunits("123456789")),
        completion_strategy = :immediate,
        eof_requires_extra_read = true,
    )
    stream = Sockets.AsyncInputStream(_async_test_read, s -> nothing, state)

    buf = Reseau.ByteBuffer(9)
    fut = Sockets.async_input_stream_read_to_fill(stream, buf)
    @test EventLoops.future_wait(fut)
    @test EventLoops.future_is_success(fut)
    @test EventLoops.future_get_result(fut) == false
    @test String(Reseau.byte_cursor_from_buf(buf)) == "123456789"

    buf.len = 0
    fut2 = Sockets.async_input_stream_read_to_fill(stream, buf)
    @test EventLoops.future_wait(fut2)
    @test EventLoops.future_is_success(fut2)
    @test EventLoops.future_get_result(fut2) == true
    @test buf.len == 0
end

@testset "async input stream fill reports error" begin
    state = AsyncStreamTestState(
        data = collect(codeunits("123456789")),
        completion_strategy = :immediate,
        max_bytes_per_read = 1,
        fail_on_nth_read = 2,
        fail_error_code = 999,
    )
    stream = Sockets.AsyncInputStream(_async_test_read, s -> nothing, state)

    buf = Reseau.ByteBuffer(512)
    fut = Sockets.async_input_stream_read_to_fill(stream, buf)
    @test EventLoops.future_wait(fut)
    @test EventLoops.future_get_error(fut) == 999
end
