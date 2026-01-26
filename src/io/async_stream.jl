# AWS IO Library - Async Stream
# Port of aws-c-io/source/async_stream.c and include/aws/io/async_stream.h

const AsyncInputStreamReadFn = Function  # (stream, dest::ByteBuffer) -> Future{Bool}
const AsyncInputStreamDestroyFn = Function  # (stream) -> nothing

mutable struct AsyncInputStream{FRead, FDestroy, Impl}
    read_fn::FRead
    destroy_fn::FDestroy
    impl::Impl
    @atomic read_in_progress::Bool
end

function AsyncInputStream(
        read_fn::FRead,
        destroy_fn::FDestroy,
        impl,
    ) where {FRead, FDestroy}
    return AsyncInputStream{FRead, FDestroy, typeof(impl)}(read_fn, destroy_fn, impl, false)
end

function async_input_stream_destroy!(stream::AsyncInputStream)
    stream.destroy_fn(stream)
    return nothing
end

function _async_stream_fail(error_code::Int)::Future{Bool}
    future = Future{Bool}()
    future_fail!(future, error_code)
    return future
end

function async_input_stream_read(stream::AsyncInputStream, dest::ByteBuffer)::Future{Bool}
    # Ensure the buffer has space available
    if dest.len == capacity(dest)
        return _async_stream_fail(ERROR_SHORT_BUFFER)
    end

    if @atomic stream.read_in_progress
        return _async_stream_fail(ERROR_INVALID_STATE)
    end

    @atomic stream.read_in_progress = true
    read_future = stream.read_fn(stream, dest)
    future_on_complete!(
        read_future, (f, ud) -> begin
            @atomic stream.read_in_progress = false
            return nothing
        end
    )
    return read_future
end

mutable struct AsyncStreamFillJob{S}
    stream::S
    dest::ByteBuffer
    read_future::Union{Future{Bool}, Nothing}
    on_complete_future::Future{Bool}
end

function _async_stream_fill_job_complete!(
        job::AsyncStreamFillJob,
        eof::Bool,
        error_code::Int,
    )
    if error_code != 0
        future_fail!(job.on_complete_future, error_code)
    else
        future_complete!(job.on_complete_future, eof)
    end
    return nothing
end

function _async_stream_fill_job_loop(job::AsyncStreamFillJob)
    while true
        if job.read_future !== nothing
            if !future_is_done(job.read_future)
                future_on_complete!(job.read_future, (f, ud) -> _async_stream_fill_job_loop(job))
                return nothing
            end

            error_code = future_get_error(job.read_future)
            eof = error_code == 0 ? (future_get_result(job.read_future) == true) : false
            reached_capacity = job.dest.len == capacity(job.dest)
            job.read_future = nothing

            if error_code != 0 || eof || reached_capacity
                _async_stream_fill_job_complete!(job, eof, error_code)
                return nothing
            end
        end

        job.read_future = async_input_stream_read(job.stream, job.dest)
    end
    return
end

function async_input_stream_read_to_fill(stream::AsyncInputStream, dest::ByteBuffer)::Future{Bool}
    future = Future{Bool}()

    if dest.len == capacity(dest)
        future_fail!(future, ERROR_SHORT_BUFFER)
        return future
    end

    job = AsyncStreamFillJob(stream, dest, nothing, future)
    _async_stream_fill_job_loop(job)
    return future
end
