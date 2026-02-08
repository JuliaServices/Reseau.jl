# Async filesystem operations for `Reseau.Files`.
#
# Design:
# - Operations return `Reseau.Future{T}`.
# - Blocking syscalls run on a `Backend.AbstractFilesBackend` (threadpool in v1).
# - Completion is always scheduled onto the provided `Reseau.EventLoop` to ensure
#   user callbacks run on the event-loop thread.

module Async

export
    AsyncFile,
    open_async,
    stat_async,
    readdir_async,
    mkdir_async,
    rm_async,
    rename_async,
    read_async,
    write_async,
    async_input_stream

using ...Reseau: ErrorResult, raise_error
using ...Reseau: Future, future_complete!, future_fail!, future_cancel!, future_is_done
using ...Reseau: future_on_complete!, future_get_error, future_get_result
using ...Reseau: AsyncInputStream
using ...Reseau: EventLoop, ScheduledTask, TaskStatus
using ...Reseau: event_loop_schedule_task_now!, event_loop_schedule_task_future!, event_loop_current_clock_time
using ...Reseau: monotonic_time_ns
using ...Reseau: ERROR_SHORT_BUFFER, ERROR_INVALID_ARGUMENT, ERROR_IO_OPERATION_CANCELLED, ERROR_SYS_CALL_FAILURE
using ...Reseau: ByteBuffer, capacity

using ..Backend: AbstractFilesBackend, default_backend, submit!
using ..Files: FileHandle, StatStruct, _require_open
using ..Files: open, stat, readdir, mkdir, rm, rename

@inline function _schedule_on_event_loop!(event_loop::EventLoop, fn::Function)::Nothing
    task = ScheduledTask(
        (_ctx, status) -> begin
            status == TaskStatus.RUN_READY || return nothing
            fn()
            return nothing
        end,
        nothing;
        type_tag = "files_async_complete",
    )
    event_loop_schedule_task_now!(event_loop, task)
    return nothing
end

@inline function _deadline_ns(event_loop::EventLoop, timeout_ms::Integer)::Union{Nothing, UInt64}
    timeout_ms < 0 && return nothing
    timeout_ms == 0 && return UInt64(0)
    now = event_loop_current_clock_time(event_loop)
    base = now isa ErrorResult ? monotonic_time_ns() : now
    return base + UInt64(max(timeout_ms, 0)) * UInt64(1_000_000)
end

mutable struct AsyncFile
    handle::FileHandle
    event_loop::EventLoop
    backend::AbstractFilesBackend
    lock::ReentrantLock
    queued::Vector{Function}
    busy::Bool
end

function AsyncFile(handle::FileHandle, event_loop::EventLoop, backend::AbstractFilesBackend)
    return AsyncFile(handle, event_loop, backend, ReentrantLock(), Function[], false)
end

function _start_next_queued!(file::AsyncFile)::Nothing
    job = nothing
    lock(file.lock)
    try
        if file.busy || isempty(file.queued)
            return nothing
        end
        file.busy = true
        job = popfirst!(file.queued)
    finally
        unlock(file.lock)
    end

    # Submit the queued job to the backend. It is responsible for scheduling
    # completion back onto the event loop and then calling `_queued_done!(file)`.
    submit!(file.backend, job)
    return nothing
end

function _queued_done!(file::AsyncFile)::Nothing
    lock(file.lock)
    try
        file.busy = false
    finally
        unlock(file.lock)
    end
    _start_next_queued!(file)
    return nothing
end

function _enqueue!(file::AsyncFile, job::Function)::Nothing
    lock(file.lock)
    try
        push!(file.queued, job)
    finally
        unlock(file.lock)
    end
    _start_next_queued!(file)
    return nothing
end

function open_async(
        event_loop::EventLoop,
        path::AbstractString;
        backend::Union{AbstractFilesBackend, Nothing} = nothing,
        kwargs...,
    )::Future{AsyncFile}
    b = backend === nothing ? default_backend() : backend
    future = Future{AsyncFile}()
    submit!(b, () -> begin
        # Run on worker thread.
        local handle
        try
            handle = open(path; kwargs...)
        catch
            _schedule_on_event_loop!(event_loop, () -> future_fail!(future, ERROR_SYS_CALL_FAILURE))
            return nothing
        end
        _schedule_on_event_loop!(
            event_loop,
            () -> begin
                future_complete!(future, AsyncFile(handle, event_loop, b))
                return nothing
            end,
        )
        return nothing
    end)
    return future
end

function stat_async(
        event_loop::EventLoop,
        path::AbstractString;
        backend::Union{AbstractFilesBackend, Nothing} = nothing,
    )::Future{StatStruct}
    b = backend === nothing ? default_backend() : backend
    future = Future{StatStruct}()
    submit!(b, () -> begin
        local st
        try
            st = stat(path)
        catch
            _schedule_on_event_loop!(event_loop, () -> future_fail!(future, ERROR_SYS_CALL_FAILURE))
            return nothing
        end
        _schedule_on_event_loop!(event_loop, () -> future_complete!(future, st))
        return nothing
    end)
    return future
end

function readdir_async(
        event_loop::EventLoop,
        path::AbstractString;
        backend::Union{AbstractFilesBackend, Nothing} = nothing,
        kwargs...,
    )::Future{Vector{String}}
    b = backend === nothing ? default_backend() : backend
    future = Future{Vector{String}}()
    submit!(b, () -> begin
        local entries
        try
            entries = readdir(path; kwargs...)
        catch
            _schedule_on_event_loop!(event_loop, () -> future_fail!(future, ERROR_SYS_CALL_FAILURE))
            return nothing
        end
        _schedule_on_event_loop!(event_loop, () -> future_complete!(future, entries))
        return nothing
    end)
    return future
end

function mkdir_async(
        event_loop::EventLoop,
        path::AbstractString;
        backend::Union{AbstractFilesBackend, Nothing} = nothing,
        mode::Integer = 0o777,
    )::Future{Nothing}
    b = backend === nothing ? default_backend() : backend
    future = Future{Nothing}()
    submit!(b, () -> begin
        try
            mkdir(path; mode = mode)
        catch
            _schedule_on_event_loop!(event_loop, () -> future_fail!(future, ERROR_SYS_CALL_FAILURE))
            return nothing
        end
        _schedule_on_event_loop!(event_loop, () -> future_complete!(future, nothing))
        return nothing
    end)
    return future
end

function rm_async(
        event_loop::EventLoop,
        path::AbstractString;
        backend::Union{AbstractFilesBackend, Nothing} = nothing,
        force::Bool = false,
        recursive::Bool = false,
    )::Future{Nothing}
    b = backend === nothing ? default_backend() : backend
    future = Future{Nothing}()
    submit!(b, () -> begin
        try
            rm(path; force = force, recursive = recursive)
        catch
            _schedule_on_event_loop!(event_loop, () -> future_fail!(future, ERROR_SYS_CALL_FAILURE))
            return nothing
        end
        _schedule_on_event_loop!(event_loop, () -> future_complete!(future, nothing))
        return nothing
    end)
    return future
end

function rename_async(
        event_loop::EventLoop,
        src::AbstractString,
        dst::AbstractString;
        backend::Union{AbstractFilesBackend, Nothing} = nothing,
    )::Future{Nothing}
    b = backend === nothing ? default_backend() : backend
    future = Future{Nothing}()
    submit!(b, () -> begin
        try
            rename(src, dst)
        catch
            _schedule_on_event_loop!(event_loop, () -> future_fail!(future, ERROR_SYS_CALL_FAILURE))
            return nothing
        end
        _schedule_on_event_loop!(event_loop, () -> future_complete!(future, nothing))
        return nothing
    end)
    return future
end

# --- I/O ---

@static if !Sys.iswindows()
    @inline function _pread_some(f::FileHandle, p::Ptr{UInt8}, n::Csize_t, offset::Int64)::Int
        _ = _require_open(f)
        rc = @ccall gc_safe = true pread(f.fd::Cint, p::Ptr{Cvoid}, n::Csize_t, offset::Int64)::Cssize_t
        if rc < 0
            err = Libc.errno()
            err == Libc.EINTR && return _pread_some(f, p, n, offset)
            throw(SystemError("pread", err))
        end
        return Int(rc)
    end

    @inline function _pwrite_all(f::FileHandle, p::Ptr{UInt8}, n::Csize_t, offset::Int64)::Int
        _ = _require_open(f)
        remaining = Int64(n)
        buf = p
        off = offset
        while remaining > 0
            rc = @ccall gc_safe = true pwrite(f.fd::Cint, buf::Ptr{Cvoid}, Csize_t(remaining)::Csize_t, off::Int64)::Cssize_t
            if rc < 0
                err = Libc.errno()
                err == Libc.EINTR && continue
                throw(SystemError("pwrite", err))
            end
            remaining -= Int64(rc)
            buf += rc
            off += Int64(rc)
        end
        return Int(n)
    end
else
    # Windows offset I/O uses overlapped I/O on the same HANDLE.
    struct _OVERLAPPED
        Internal::UInt
        InternalHigh::UInt
        Offset::UInt32
        OffsetHigh::UInt32
        hEvent::Ptr{Cvoid}
    end

    const _ERROR_HANDLE_EOF = UInt32(38)

    @inline function _win_get_last_error()::UInt32
        return @ccall "kernel32".GetLastError()::UInt32
    end

    @inline function _win_throw(func::AbstractString)
        throw(Base.windowserror(func, _win_get_last_error()))
    end

    @inline function _win_overlapped(offset::Int64)::_OVERLAPPED
        u = UInt64(offset)
        return _OVERLAPPED(0, 0, UInt32(u & 0xFFFFFFFF), UInt32((u >> 32) & 0xFFFFFFFF), C_NULL)
    end

    @inline function _readfile_some(f::FileHandle, p::Ptr{UInt8}, n::UInt32, offset::Union{Nothing, Int64})::Int
        _ = _require_open(f)
        read = Ref{UInt32}(0)
        if offset === nothing
            ok = @ccall gc_safe = true "kernel32".ReadFile(
                f.handle::Ptr{Cvoid},
                p::Ptr{Cvoid},
                n::UInt32,
                read::Ref{UInt32},
                C_NULL::Ptr{_OVERLAPPED},
            )::Int32
            if ok == 0
                err = _win_get_last_error()
                err == _ERROR_HANDLE_EOF && return 0
                _win_throw("ReadFile")
            end
            return Int(read[])
        else
            ov = Ref(_win_overlapped(offset))
            ok = @ccall gc_safe = true "kernel32".ReadFile(
                f.handle::Ptr{Cvoid},
                p::Ptr{Cvoid},
                n::UInt32,
                read::Ref{UInt32},
                ov::Ref{_OVERLAPPED},
            )::Int32
            if ok == 0
                err = _win_get_last_error()
                err == _ERROR_HANDLE_EOF && return 0
                _win_throw("ReadFile")
            end
            return Int(read[])
        end
    end

    @inline function _writefile_all(f::FileHandle, p::Ptr{UInt8}, n::UInt32, offset::Union{Nothing, Int64})::Int
        _ = _require_open(f)
        remaining = UInt32(n)
        buf = p
        off = offset
        while remaining > 0
            written = Ref{UInt32}(0)
            if off === nothing
                ok = @ccall gc_safe = true "kernel32".WriteFile(
                    f.handle::Ptr{Cvoid},
                    buf::Ptr{Cvoid},
                    remaining::UInt32,
                    written::Ref{UInt32},
                    C_NULL::Ptr{_OVERLAPPED},
                )::Int32
                ok != 0 || _win_throw("WriteFile")
            else
                ov = Ref(_win_overlapped(off))
                ok = @ccall gc_safe = true "kernel32".WriteFile(
                    f.handle::Ptr{Cvoid},
                    buf::Ptr{Cvoid},
                    remaining::UInt32,
                    written::Ref{UInt32},
                    ov::Ref{_OVERLAPPED},
                )::Int32
                ok != 0 || _win_throw("WriteFile")
                off += Int64(written[])
            end
            remaining -= written[]
            buf += written[]
        end
        return Int(n)
    end
end

function read_async(
        file::AsyncFile,
        dest::ByteBuffer;
        nbytes::Integer = Int(capacity(dest) - dest.len),
        offset::Union{Nothing, Integer} = nothing,
        timeout_ms::Integer = -1,
    )::Future{Int}
    n = Int(nbytes)
    n < 0 && throw(ArgumentError("nbytes must be >= 0"))
    available = Int(capacity(dest) - dest.len)
    if available <= 0
        future = Future{Int}()
        future_fail!(future, ERROR_SHORT_BUFFER)
        return future
    end
    n = min(n, available)

    future = Future{Int}()
    cancelled = Base.Threads.Atomic{Bool}(false)
    deadline = _deadline_ns(file.event_loop, timeout_ms)
    if deadline !== nothing && deadline != 0
        task = ScheduledTask(
            (ctx, status) -> begin
                status == TaskStatus.RUN_READY || return nothing
                if !future_is_done(ctx.future)
                    ctx.cancelled[] = true
                    future_cancel!(ctx.future)
                end
                return nothing
            end,
            (future = future, cancelled = cancelled);
            type_tag = "files_async_timeout",
        )
        event_loop_schedule_task_future!(file.event_loop, task, deadline)
    elseif deadline == UInt64(0)
        future_cancel!(future)
        return future
    end

    worker_job = () -> begin
        if cancelled[]
            # Ensure queued operations still make progress.
            _schedule_on_event_loop!(
                file.event_loop,
                () -> begin
                    (offset === nothing || Sys.iswindows()) && _queued_done!(file)
                    return nothing
                end,
            )
            return nothing
        end
        bytes_read = 0
        try
            # Read directly into the free tail of `dest`; update `dest.len` on the event loop.
            buf = dest.mem
            off = Int(dest.len) + 1
            GC.@preserve dest buf begin
                p = pointer(buf, off)
                @static if Sys.iswindows()
                    # Windows v1: serialize offset reads via `seek` + normal ReadFile.
                    if offset !== nothing
                        seek(file.handle, offset)
                    end
                    bytes_read = _readfile_some(file.handle, p, UInt32(n), nothing)
                else
                    if offset === nothing
                        while true
                            rc = @ccall gc_safe = true read(file.handle.fd::Cint, p::Ptr{Cvoid}, Csize_t(n)::Csize_t)::Cssize_t
                            if rc < 0
                                err = Libc.errno()
                                err == Libc.EINTR && continue
                                throw(SystemError("read", err))
                            end
                            bytes_read = Int(rc)
                            break
                        end
                    else
                        bytes_read = _pread_some(file.handle, p, Csize_t(n), Int64(offset))
                    end
                end
            end
        catch
            _schedule_on_event_loop!(
                file.event_loop,
                () -> begin
                    future_fail!(future, ERROR_SYS_CALL_FAILURE)
                    (offset === nothing || Sys.iswindows()) && _queued_done!(file)
                    return nothing
                end,
            )
            return nothing
        end

        _schedule_on_event_loop!(
            file.event_loop,
            () -> begin
                if !future_is_done(future)
                    dest.len += Csize_t(bytes_read)
                    future_complete!(future, bytes_read)
                end
                (offset === nothing || Sys.iswindows()) && _queued_done!(file)
                return nothing
            end,
        )
        return nothing
    end

    if offset === nothing || Sys.iswindows()
        _enqueue!(file, worker_job)
    else
        submit!(file.backend, worker_job)
    end

    return future
end

function write_async(
        file::AsyncFile,
        src::AbstractVector{UInt8};
        offset::Union{Nothing, Integer} = nothing,
        timeout_ms::Integer = -1,
    )::Future{Int}
    future = Future{Int}()
    cancelled = Base.Threads.Atomic{Bool}(false)
    deadline = _deadline_ns(file.event_loop, timeout_ms)
    if deadline !== nothing && deadline != 0
        task = ScheduledTask(
            (ctx, status) -> begin
                status == TaskStatus.RUN_READY || return nothing
                if !future_is_done(ctx.future)
                    ctx.cancelled[] = true
                    future_cancel!(ctx.future)
                end
                return nothing
            end,
            (future = future, cancelled = cancelled);
            type_tag = "files_async_timeout",
        )
        event_loop_schedule_task_future!(file.event_loop, task, deadline)
    elseif deadline == UInt64(0)
        future_cancel!(future)
        return future
    end

    worker_job = () -> begin
        if cancelled[]
            _schedule_on_event_loop!(
                file.event_loop,
                () -> begin
                    (offset === nothing || Sys.iswindows()) && _queued_done!(file)
                    return nothing
                end,
            )
            return nothing
        end
        written = 0
        try
            bytes = src
            n = length(bytes)
            GC.@preserve bytes begin
                p = pointer(bytes)
                @static if Sys.iswindows()
                    if offset !== nothing
                        seek(file.handle, offset)
                    end
                    written = _writefile_all(file.handle, p, UInt32(n), nothing)
                else
                    if offset === nothing
                        written = Base.unsafe_write(file.handle, p, UInt(n))
                    else
                        written = _pwrite_all(file.handle, p, Csize_t(n), Int64(offset))
                    end
                end
            end
        catch
            _schedule_on_event_loop!(
                file.event_loop,
                () -> begin
                    future_fail!(future, ERROR_SYS_CALL_FAILURE)
                    (offset === nothing || Sys.iswindows()) && _queued_done!(file)
                    return nothing
                end,
            )
            return nothing
        end

        _schedule_on_event_loop!(
            file.event_loop,
            () -> begin
                if !future_is_done(future)
                    future_complete!(future, written)
                end
                (offset === nothing || Sys.iswindows()) && _queued_done!(file)
                return nothing
            end,
        )
        return nothing
    end

    if offset === nothing || Sys.iswindows()
        _enqueue!(file, worker_job)
    else
        submit!(file.backend, worker_job)
    end

    return future
end

write_async(file::AsyncFile, src::Union{String, SubString{String}}; kwargs...) =
    write_async(file, Vector{UInt8}(codeunits(src)); kwargs...)
write_async(file::AsyncFile, src::AbstractString; kwargs...) =
    write_async(file, Vector{UInt8}(codeunits(src)); kwargs...)

function async_input_stream(
        file::AsyncFile;
        chunk_size::Integer = 64 * 1024,
    )
    read_fn = (stream, dest::ByteBuffer) -> begin
        _ = stream
        # Use as much space as available, but cap to chunk_size.
        n = min(Int(capacity(dest) - dest.len), Int(chunk_size))
        if n <= 0
            f = Future{Bool}()
            future_fail!(f, ERROR_SHORT_BUFFER)
            return f
        end
        fbytes = read_async(file, dest; nbytes = n)
        fout = Future{Bool}()
        future_on_complete!(fbytes, (fb, ud) -> begin
            err = future_get_error(fb)
            if err != 0
                future_fail!(fout, err)
                return nothing
            end
            nread = future_get_result(fb)
            future_complete!(fout, nread == 0)
            return nothing
        end)
        return fout
    end
    destroy_fn = stream -> nothing
    return AsyncInputStream(read_fn, destroy_fn, nothing)
end

end # module Async
