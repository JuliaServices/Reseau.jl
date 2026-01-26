using Test
using AwsIO

mutable struct AsyncStreamTestState
    data::Vector{UInt8}
    offset::Int
    event_loop::Union{AwsIO.EventLoop, Nothing}
    complete_async::Bool
end

function _async_test_read(stream::AwsIO.AsyncInputStream, dest::AwsIO.ByteBuffer)
    state = stream.impl
    future = AwsIO.Future{Bool}()

    function do_read!()
        if state.offset >= length(state.data)
            AwsIO.future_complete!(future, true)
            return nothing
        end

        available = Int(AwsIO.capacity(dest) - dest.len)
        remaining = length(state.data) - state.offset
        to_copy = min(available, remaining)

        if to_copy > 0
            copyto!(dest.mem, Int(dest.len) + 1, state.data, state.offset + 1, to_copy)
            dest.len += Csize_t(to_copy)
            state.offset += to_copy
        end

        eof = state.offset >= length(state.data)
        AwsIO.future_complete!(future, eof)
        return nothing
    end

    if state.complete_async && state.event_loop !== nothing
        task = AwsIO.ScheduledTask(
            (t, status) -> do_read!(),
            nothing;
            type_tag = "async_stream_test_read",
        )
        AwsIO.event_loop_schedule_task_now!(state.event_loop, task)
    else
        do_read!()
    end

    return future
end

@testset "async input stream read_to_fill sync" begin
    state = AsyncStreamTestState(collect(codeunits("hello world")), 0, nothing, false)
    stream = AwsIO.AsyncInputStream(_async_test_read, s -> nothing, state)

    dest = AwsIO.ByteBuffer(5)
    fut = AwsIO.async_input_stream_read_to_fill(stream, dest)
    @test AwsIO.future_wait(fut)
    @test AwsIO.future_is_success(fut)
    @test AwsIO.future_get_result(fut) == false
    @test String(AwsIO.byte_cursor_from_buf(dest)) == "hello"

    dest2 = AwsIO.ByteBuffer(6)
    fut2 = AwsIO.async_input_stream_read_to_fill(stream, dest2)
    @test AwsIO.future_wait(fut2)
    @test AwsIO.future_is_success(fut2)
    @test AwsIO.future_get_result(fut2) == true
    @test String(AwsIO.byte_cursor_from_buf(dest2)) == " world"

    dest_full = AwsIO.ByteBuffer(0)
    fut3 = AwsIO.async_input_stream_read(stream, dest_full)
    @test AwsIO.future_is_failed(fut3)
    @test AwsIO.future_get_error(fut3) == AwsIO.ERROR_SHORT_BUFFER
end

@testset "async input stream read_to_fill async" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    state = AsyncStreamTestState(collect(codeunits("abcd")), 0, event_loop, true)
    stream = AwsIO.AsyncInputStream(_async_test_read, s -> nothing, state)

    dest = AwsIO.ByteBuffer(4)
    fut = AwsIO.async_input_stream_read_to_fill(stream, dest)
    @test AwsIO.future_wait(fut)
    @test AwsIO.future_is_success(fut)
    @test AwsIO.future_get_result(fut) == true
    @test String(AwsIO.byte_cursor_from_buf(dest)) == "abcd"

    AwsIO.event_loop_group_destroy!(elg)
end
