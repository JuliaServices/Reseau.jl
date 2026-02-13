using Test
using Random
using Reseau

const SMALL_BUFFER_SIZE = 4
const GIANT_BUFFER_SIZE = 1024 * 1024 * 32

@testset "IOCP pipe stub" begin
    if Sys.iswindows()
        # On Windows, pipe_create_iocp may succeed (returning a Tuple) or throw
        try
            res = Sockets.pipe_create_iocp()
            @test res isa Tuple
        catch e
            @test e isa Reseau.ReseauError
            @test e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
        end
    else
        @test_throws Reseau.ReseauError Sockets.pipe_create_iocp()
        try
            Sockets.pipe_create_iocp()
        catch e
            @test e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
        end
    end
end

@enum PipeLoopSetup::UInt8 begin
    SAME_EVENT_LOOP = 0
    DIFFERENT_EVENT_LOOPS = 1
end

mutable struct PipeResults
    read_end_closed::Bool
    write_end_closed::Bool
    status_code::Int
end

mutable struct PipeBuffers
    src::Reseau.ByteBuffer
    dst::Reseau.ByteBuffer
    num_bytes_written::Csize_t
end

mutable struct PipeReadableEvents
    error_code_to_monitor::Int
    count::Int
    close_read_end_after_n_events::Int
end

mutable struct PipeState
    loop_setup::PipeLoopSetup
    buffer_size::Int
    read_loop::Union{EventLoops.EventLoop, Nothing}
    write_loop::Union{EventLoops.EventLoop, Nothing}
    read_end::Union{Sockets.PipeReadEnd, Nothing}
    write_end::Union{Sockets.PipeWriteEnd, Nothing}
    results::PipeResults
    buffers::PipeBuffers
    readable_events::PipeReadableEvents
    test_data::Any
end

function PipeState(loop_setup::PipeLoopSetup, buffer_size::Integer)
    empty_buf = Reseau.ByteBuffer(0)
    return PipeState(
        loop_setup,
        Int(buffer_size),
        nothing,
        nothing,
        nothing,
        nothing,
        PipeResults(false, false, 0),
        PipeBuffers(empty_buf, empty_buf, Csize_t(0)),
        PipeReadableEvents(Reseau.AWS_OP_SUCCESS, 0, 0),
        nothing,
    )
end

function _signal_error!(state::PipeState)
    state.results.status_code = -1
    return nothing
end

function _signal_done_on_read_end_closed!(state::PipeState)
    state.results.read_end_closed = true
    return nothing
end

function _signal_done_on_write_end_closed!(state::PipeState)
    state.results.write_end_closed = true
    return nothing
end

function _done_pred(state::PipeState)
    if state.results.status_code != 0
        return true
    end
    return state.results.read_end_closed && state.results.write_end_closed
end

function _wait_for_results(state::PipeState; timeout_s::Float64 = 30.0)
    start = Base.time_ns()
    timeout_ns = Int(timeout_s * 1_000_000_000)
    while (Base.time_ns() - start) < timeout_ns
        _done_pred(state) && return state.results.status_code
        sleep(0.01)
    end
    return state.results.status_code == 0 ? -1 : state.results.status_code
end

function _pipe_state_check_copied_data(state::PipeState)
    @test state.buffers.num_bytes_written == Csize_t(state.buffer_size)
    @test Reseau.byte_buf_eq(state.buffers.src, state.buffers.dst)
    return nothing
end

function _schedule_task(state::PipeState, loop::EventLoops.EventLoop, fn; delay_secs::Int = 0, serialized::Bool = false)
    task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
        Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return _signal_error!(state)
        fn(state)
        return nothing
    end); type_tag = "pipe_state_task")

    if delay_secs == 0
        if serialized
            EventLoops.event_loop_schedule_task_now_serialized!(loop, task)
        else
            EventLoops.event_loop_schedule_task_now!(loop, task)
        end
        return nothing
    end

    local now_ns
    try
        now_ns = EventLoops.event_loop_current_clock_time(loop)
    catch
        _signal_error!(state)
        return nothing
    end
    run_at = UInt64(now_ns + UInt64(delay_secs) * 1_000_000_000)
    EventLoops.event_loop_schedule_task_future!(loop, task, run_at)
    return nothing
end

_schedule_read_end_task(state::PipeState, fn; delay_secs::Int = 0, serialized::Bool = false) =
    _schedule_task(state, state.read_loop::EventLoops.EventLoop, fn; delay_secs = delay_secs, serialized = serialized)

_schedule_write_end_task(state::PipeState, fn; delay_secs::Int = 0) =
    _schedule_task(state, state.write_loop::EventLoops.EventLoop, fn; delay_secs = delay_secs)

function _fixture_before!(state::PipeState)
    read_loop = EventLoops.event_loop_new()
    EventLoops.event_loop_run!(read_loop)
    state.read_loop = read_loop

    if state.loop_setup == DIFFERENT_EVENT_LOOPS
        write_loop = EventLoops.event_loop_new()
        EventLoops.event_loop_run!(write_loop)
        state.write_loop = write_loop
    else
        state.write_loop = read_loop
    end

    pipe_result = Sockets.pipe_init(state.read_loop, state.write_loop)
    state.read_end, state.write_end = pipe_result

    if state.buffer_size > 0
        src = Reseau.ByteBuffer(state.buffer_size)
        src.len = Csize_t(state.buffer_size)
        Random.rand!(src.mem)

        dst = Reseau.ByteBuffer(state.buffer_size)
        dst.len = Csize_t(0)
        fill!(dst.mem, 0x00)

        state.buffers = PipeBuffers(src, dst, Csize_t(0))
    end

    return nothing
end

function _fixture_after!(state::PipeState)
    if state.read_loop !== nothing
        EventLoops.event_loop_destroy!(state.read_loop)
    end
    if state.write_loop !== nothing && state.write_loop !== state.read_loop
        EventLoops.event_loop_destroy!(state.write_loop)
    end
    return nothing
end

function _clean_up_read_end_task(state::PipeState)
    try
        Sockets.pipe_clean_up_read_end(state.read_end::Sockets.PipeReadEnd)
        _signal_done_on_read_end_closed!(state)
    catch
        _signal_error!(state)
    end
    return nothing
end

function _clean_up_write_end_task(state::PipeState)
    try
        Sockets.pipe_clean_up_write_end(state.write_end::Sockets.PipeWriteEnd)
        _signal_done_on_write_end_closed!(state)
    catch
        _signal_error!(state)
    end
    return nothing
end

function _clean_up_write_end_on_write_completed(state::PipeState, error_code::Int, bytes_written::Csize_t)
    if error_code == Reseau.AWS_OP_SUCCESS
        state.buffers.num_bytes_written += bytes_written
    end
    try
        Sockets.pipe_clean_up_write_end(state.write_end::Sockets.PipeWriteEnd)
        _signal_done_on_write_end_closed!(state)
    catch
        _signal_error!(state)
    end
    return nothing
end

function _write_once_task(state::PipeState)
    cursor = Reseau.byte_cursor_from_buf(state.buffers.src)
    try
        Sockets.pipe_write(state.write_end::Sockets.PipeWriteEnd, cursor, Reseau.WriteCallable((err, nbytes) -> _clean_up_write_end_on_write_completed(state, err, nbytes)))
    catch
        _signal_error!(state)
    end
    return nothing
end

function _read_everything_task(state::PipeState)
    while state.buffers.dst.len < state.buffers.dst.capacity
        try
            Sockets.pipe_read(state.read_end::Sockets.PipeReadEnd, state.buffers.dst)
        catch e
            if e isa Reseau.ReseauError && e.code == EventLoops.ERROR_IO_READ_WOULD_BLOCK
                break
            end
            _signal_error!(state)
            return nothing
        end
    end

    if state.buffers.dst.len < state.buffers.dst.capacity
        _schedule_read_end_task(state, _read_everything_task; serialized = true)
        return nothing
    end

    try
        Sockets.pipe_clean_up_read_end(state.read_end::Sockets.PipeReadEnd)
        _signal_done_on_read_end_closed!(state)
    catch
        _signal_error!(state)
    end
    return nothing
end

function _on_readable_event(state::PipeState, error_code::Int)
    if error_code == state.readable_events.error_code_to_monitor
        state.readable_events.count += 1
        if state.readable_events.count == state.readable_events.close_read_end_after_n_events
            try
                Sockets.pipe_clean_up_read_end(state.read_end::Sockets.PipeReadEnd)
                _signal_done_on_read_end_closed!(state)
            catch
                _signal_error!(state)
                return nothing
            end
        end
    end
    return nothing
end

function _subscribe_task(state::PipeState)
    try
        Sockets.pipe_subscribe_to_readable_events(state.read_end::Sockets.PipeReadEnd, Reseau.EventCallable(ec -> _on_readable_event(state, ec)))
    catch
        _signal_error!(state)
    end
    return nothing
end

function _sentonce_on_readable_event(state::PipeState, error_code::Int)
    prev_count = state.readable_events.count
    _on_readable_event(state, error_code)
    state.results.status_code != 0 && return nothing
    if state.readable_events.count == 1 && prev_count == 0
        _schedule_read_end_task(state, _clean_up_read_end_task; delay_secs = 1)
    end
    return nothing
end

function _sentonce_subscribe_task(state::PipeState)
    try
        Sockets.pipe_subscribe_to_readable_events(state.read_end::Sockets.PipeReadEnd, Reseau.EventCallable(ec -> _sentonce_on_readable_event(state, ec)))
    catch
        _signal_error!(state)
    end
    return nothing
end

function _subscribe_on_write_completed(state::PipeState, error_code::Int, bytes_written::Csize_t)
    if error_code == Reseau.AWS_OP_SUCCESS
        state.buffers.num_bytes_written += bytes_written
    end
    try
        Sockets.pipe_clean_up_write_end(state.write_end::Sockets.PipeWriteEnd)
    catch
        _signal_error!(state)
        return nothing
    end
    _signal_done_on_write_end_closed!(state)
    _schedule_read_end_task(state, _subscribe_task)
    return nothing
end

function _write_once_then_subscribe_task(state::PipeState)
    cursor = Reseau.byte_cursor_from_buf(state.buffers.src)
    try
        Sockets.pipe_write(state.write_end::Sockets.PipeWriteEnd, cursor, Reseau.WriteCallable((err, nbytes) -> _subscribe_on_write_completed(state, err, nbytes)))
    catch
        _signal_error!(state)
    end
    return nothing
end

function _resubscribe_on_readable_event(state::PipeState, error_code::Int)
    prev_count = state.readable_events.count
    _on_readable_event(state, error_code)
    state.results.status_code != 0 && return nothing

    if state.readable_events.count == 1 && prev_count == 0
        try
            Sockets.pipe_unsubscribe_from_readable_events(state.read_end::Sockets.PipeReadEnd)
        catch
            _signal_error!(state)
            return nothing
        end
        try
            Sockets.pipe_subscribe_to_readable_events(state.read_end::Sockets.PipeReadEnd, Reseau.EventCallable(ec -> _on_readable_event(state, ec)))
        catch
            _signal_error!(state)
        end
    end
    return nothing
end

function _resubscribe_1_task(state::PipeState)
    try
        Sockets.pipe_subscribe_to_readable_events(state.read_end::Sockets.PipeReadEnd, Reseau.EventCallable(ec -> _resubscribe_on_readable_event(state, ec)))
    catch
        _signal_error!(state)
    end
    return nothing
end

function _resubscribe_write_task(state::PipeState)
    cursor = Reseau.byte_cursor_from_buf(state.buffers.src)
    try
        Sockets.pipe_write(state.write_end::Sockets.PipeWriteEnd, cursor, Reseau.WriteCallable((err, nbytes) -> _clean_up_write_end_on_write_completed(state, err, nbytes)))
    catch
        _signal_error!(state)
        return nothing
    end
    _schedule_read_end_task(state, _resubscribe_1_task)
    return nothing
end

function _readall_on_write_completed(state::PipeState, error_code::Int, bytes_written::Csize_t)
    if error_code != Reseau.AWS_OP_SUCCESS
        _signal_error!(state)
        return nothing
    end
    is_second = state.buffers.num_bytes_written > 0
    state.buffers.num_bytes_written += bytes_written
    if is_second
        try
            Sockets.pipe_clean_up_write_end(state.write_end::Sockets.PipeWriteEnd)
            _signal_done_on_write_end_closed!(state)
        catch
            _signal_error!(state)
            return nothing
        end
    end
    return nothing
end

function _readall_write_task(state::PipeState)
    cursor = Reseau.byte_cursor_from_buf(state.buffers.src)
    try
        Sockets.pipe_write(state.write_end::Sockets.PipeWriteEnd, cursor, Reseau.WriteCallable((err, nbytes) -> _readall_on_write_completed(state, err, nbytes)))
    catch
        _signal_error!(state)
    end
    return nothing
end

function _readall_on_readable(state::PipeState, error_code::Int)
    read_end = state.read_end::Sockets.PipeReadEnd
    prev_count = state.readable_events.count
    _on_readable_event(state, error_code)
    state.results.status_code != 0 && return nothing

    if state.readable_events.count == 1 && prev_count == 0
        total_bytes_read = 0
        while true
            state.buffers.dst.len = Csize_t(0)
            try
                Sockets.pipe_read(read_end, state.buffers.dst)
            catch e
                if e isa Reseau.ReseauError && e.code == EventLoops.ERROR_IO_READ_WOULD_BLOCK
                    break
                end
                _signal_error!(state)
                return nothing
            end
            total_bytes_read += Int(state.buffers.dst.len)
        end
        total_bytes_read == 0 && (_signal_error!(state); return nothing)
        _schedule_write_end_task(state, _readall_write_task)
    end
    return nothing
end

function _readall_subscribe_task(state::PipeState)
    try
        Sockets.pipe_subscribe_to_readable_events(state.read_end::Sockets.PipeReadEnd, Reseau.EventCallable(ec -> _readall_on_readable(state, ec)))
    catch
        _signal_error!(state)
    end
    return nothing
end

function _subscribe_and_schedule_write_end_clean_up_task(state::PipeState)
    try
        Sockets.pipe_subscribe_to_readable_events(state.read_end::Sockets.PipeReadEnd, Reseau.EventCallable(ec -> _on_readable_event(state, ec)))
    catch
        _signal_error!(state)
        return nothing
    end
    _schedule_write_end_task(state, _clean_up_write_end_task)
    return nothing
end

function _clean_up_write_end_then_schedule_subscribe_task(state::PipeState)
    try
        Sockets.pipe_clean_up_write_end(state.write_end::Sockets.PipeWriteEnd)
    catch
        _signal_error!(state)
        return nothing
    end
    _signal_done_on_write_end_closed!(state)
    _schedule_read_end_task(state, _subscribe_task)
    return nothing
end

function _close_write_end_after_all_writes_completed(state::PipeState, error_code::Int, bytes_written::Csize_t)
    if error_code != Reseau.AWS_OP_SUCCESS
        _signal_error!(state)
        return nothing
    end
    state.buffers.num_bytes_written += bytes_written
    if state.buffers.num_bytes_written == Csize_t(state.buffer_size)
        try
            Sockets.pipe_clean_up_write_end(state.write_end::Sockets.PipeWriteEnd)
            _signal_done_on_write_end_closed!(state)
        catch
            _signal_error!(state)
            return nothing
        end
    end
    return nothing
end

function _write_in_simultaneous_chunks_task(state::PipeState)
    cursor_ref = Ref(Reseau.byte_cursor_from_buf(state.buffers.src))
    chunk_size = Int(cursor_ref[].len) ÷ 8
    while cursor_ref[].len > 0
        bytes_to_write = chunk_size < Int(cursor_ref[].len) ? chunk_size : Int(cursor_ref[].len)
        chunk_cursor = Reseau.byte_cursor_from_array(cursor_ref[].ptr, bytes_to_write)
        try
            Sockets.pipe_write(state.write_end::Sockets.PipeWriteEnd, chunk_cursor, Reseau.WriteCallable((err, nbytes) -> _close_write_end_after_all_writes_completed(state, err, nbytes)))
        catch
            _signal_error!(state)
            return nothing
        end
        _ = Reseau.byte_cursor_advance(cursor_ref, Csize_t(bytes_to_write))
    end
    return nothing
end

function _cancelled_on_write_completed(state::PipeState, error_code::Int, bytes_written::Csize_t)
    status_ref = state.test_data::Base.RefValue{Int}
    status_ref[] = error_code
    if error_code == Reseau.AWS_OP_SUCCESS
        state.buffers.num_bytes_written += bytes_written
    end
    _schedule_read_end_task(state, _clean_up_read_end_task)
    return nothing
end

function _write_then_clean_up_task(state::PipeState)
    cursor = Reseau.byte_cursor_from_buf(state.buffers.src)
    try
        Sockets.pipe_write(state.write_end::Sockets.PipeWriteEnd, cursor, Reseau.WriteCallable((err, nbytes) -> _cancelled_on_write_completed(state, err, nbytes)))
    catch
        _signal_error!(state)
        return nothing
    end
    try
        Sockets.pipe_clean_up_write_end(state.write_end::Sockets.PipeWriteEnd)
    catch
        _signal_error!(state)
        return nothing
    end
    _signal_done_on_write_end_closed!(state)
    return nothing
end

function _run_pipe_case(test_fn::Function, name::AbstractString, buffer_size::Integer, loop_setup::PipeLoopSetup)
    state = PipeState(loop_setup, buffer_size)
    _fixture_before!(state)

    try
        test_fn(state)
    finally
        _fixture_after!(state)
    end
    return nothing
end

@testset "pipe" begin
    if Base.Threads.nthreads(:interactive) <= 1
        @test true
    else
        Sockets.io_library_init()

        for loop_setup in (SAME_EVENT_LOOP, DIFFERENT_EVENT_LOOPS)
            if loop_setup == DIFFERENT_EVENT_LOOPS && Base.Threads.nthreads(:interactive) <= 2
                @test true
                continue
            end
            @testset "open_close $(loop_setup)" begin
                _run_pipe_case("open_close", SMALL_BUFFER_SIZE, loop_setup) do state
                    _schedule_read_end_task(state, _clean_up_read_end_task)
                    _schedule_write_end_task(state, _clean_up_write_end_task)
                    @test _wait_for_results(state) == 0
                end
            end

            @testset "read_write $(loop_setup)" begin
                _run_pipe_case("read_write", SMALL_BUFFER_SIZE, loop_setup) do state
                    _schedule_read_end_task(state, _read_everything_task)
                    _schedule_write_end_task(state, _write_once_task)
                    @test _wait_for_results(state) == 0
                    _pipe_state_check_copied_data(state)
                end
            end

            @testset "read_write_large $(loop_setup)" begin
                _run_pipe_case("read_write_large", GIANT_BUFFER_SIZE, loop_setup) do state
                    _schedule_read_end_task(state, _read_everything_task)
                    _schedule_write_end_task(state, _write_once_task)
                    @test _wait_for_results(state; timeout_s = 120.0) == 0
                    _pipe_state_check_copied_data(state)
                end
            end

            @testset "readable_event_after_write $(loop_setup)" begin
                _run_pipe_case("readable_after_write", SMALL_BUFFER_SIZE, loop_setup) do state
                    state.readable_events.error_code_to_monitor = Reseau.AWS_OP_SUCCESS
                    state.readable_events.close_read_end_after_n_events = 1
                    _schedule_read_end_task(state, _subscribe_task)
                    _schedule_write_end_task(state, _write_once_task)
                    @test _wait_for_results(state) == 0
                    @test state.readable_events.count == 1
                end
            end

            @testset "readable_event_sent_once $(loop_setup)" begin
                _run_pipe_case("readable_sent_once", SMALL_BUFFER_SIZE, loop_setup) do state
                    state.readable_events.error_code_to_monitor = Reseau.AWS_OP_SUCCESS
                    _schedule_read_end_task(state, _sentonce_subscribe_task)
                    _schedule_write_end_task(state, _write_once_task)
                    @test _wait_for_results(state) == 0
                    @test state.readable_events.count <= 2
                end
            end

            @testset "readable_on_subscribe_if_data_present $(loop_setup)" begin
                _run_pipe_case("readable_on_subscribe", SMALL_BUFFER_SIZE, loop_setup) do state
                    state.readable_events.error_code_to_monitor = Reseau.AWS_OP_SUCCESS
                    state.readable_events.close_read_end_after_n_events = 1
                    _schedule_write_end_task(state, _write_once_then_subscribe_task)
                    @test _wait_for_results(state) == 0
                    @test state.readable_events.count == 1
                end
            end

            @testset "readable_on_resubscribe_if_data_present $(loop_setup)" begin
                _run_pipe_case("readable_on_resubscribe", SMALL_BUFFER_SIZE, loop_setup) do state
                    state.readable_events.error_code_to_monitor = Reseau.AWS_OP_SUCCESS
                    state.readable_events.close_read_end_after_n_events = 2
                    _schedule_write_end_task(state, _resubscribe_write_task)
                    @test _wait_for_results(state) == 0
                    @test state.readable_events.count == 2
                end
            end

            @testset "readable_event_sent_again_after_all_data_read $(loop_setup)" begin
                _run_pipe_case("readable_readall", SMALL_BUFFER_SIZE, loop_setup) do state
                    state.readable_events.error_code_to_monitor = Reseau.AWS_OP_SUCCESS
                    state.readable_events.close_read_end_after_n_events = 2
                    _schedule_read_end_task(state, _readall_subscribe_task)
                    _schedule_write_end_task(state, _readall_write_task)
                    @test _wait_for_results(state) == 0
                    @test state.readable_events.count == 2
                end
            end

            @testset "error_event_after_write_end_closed $(loop_setup)" begin
                _run_pipe_case("error_after_write_closed", SMALL_BUFFER_SIZE, loop_setup) do state
                    state.readable_events.error_code_to_monitor = EventLoops.ERROR_IO_BROKEN_PIPE
                    state.readable_events.close_read_end_after_n_events = 1
                    _schedule_read_end_task(state, _subscribe_and_schedule_write_end_clean_up_task)
                    @test _wait_for_results(state) == 0
                    @test state.readable_events.count == 1
                end
            end

            @testset "error_event_on_subscribe_if_write_closed $(loop_setup)" begin
                _run_pipe_case("error_on_subscribe_if_write_closed", SMALL_BUFFER_SIZE, loop_setup) do state
                    state.readable_events.error_code_to_monitor = EventLoops.ERROR_IO_BROKEN_PIPE
                    state.readable_events.close_read_end_after_n_events = 1
                    _schedule_write_end_task(state, _clean_up_write_end_then_schedule_subscribe_task)
                    @test _wait_for_results(state) == 0
                    @test state.readable_events.count == 1
                end
            end

            @testset "writes_are_fifo $(loop_setup)" begin
                _run_pipe_case("writes_fifo", GIANT_BUFFER_SIZE, loop_setup) do state
                    _schedule_read_end_task(state, _read_everything_task)
                    _schedule_write_end_task(state, _write_in_simultaneous_chunks_task)
                    @test _wait_for_results(state; timeout_s = 120.0) == 0
                    _pipe_state_check_copied_data(state)
                end
            end

            @testset "clean_up_cancels_pending_writes $(loop_setup)" begin
                _run_pipe_case("clean_up_cancels", GIANT_BUFFER_SIZE, loop_setup) do state
                    write_status = Ref{Int}(0)
                    state.test_data = write_status
                    _schedule_write_end_task(state, _write_then_clean_up_task)
                    @test _wait_for_results(state; timeout_s = 120.0) == 0
                    @test write_status[] == EventLoops.ERROR_IO_BROKEN_PIPE
                    @test state.buffers.num_bytes_written < Csize_t(state.buffer_size)
                end
            end
        end
    end
end
