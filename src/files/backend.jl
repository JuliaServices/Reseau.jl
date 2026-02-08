# Backend abstractions for `Reseau.Files`.
#
# v1: a portable threadpool backend which runs blocking filesystem syscalls on
# dedicated OS threads and schedules completion back onto a Reseau event loop.

module Backend

export AbstractFilesBackend, ThreadPoolBackend, default_backend, submit!, shutdown!

using ...Reseau: ThreadHandle, ThreadOptions, ThreadJoinStrategy
using ...Reseau: thread_launch, thread_join, thread_options_with_defaults

abstract type AbstractFilesBackend end

mutable struct ThreadPoolBackend <: AbstractFilesBackend
    lock::ReentrantLock
    cond::Base.Threads.Condition
    queue::Vector{Any}  # eltype = Function
    closed::Bool
    threads::Vector{ThreadHandle}
end

function _worker_main(ctx)
    backend = ctx.backend::ThreadPoolBackend
    while true
        job = nothing
        lock(backend.lock)
        try
            while isempty(backend.queue) && !backend.closed
                wait(backend.cond)
            end
            if backend.closed && isempty(backend.queue)
                return nothing
            end
            job = popfirst!(backend.queue)
        finally
            unlock(backend.lock)
        end

        try
            job()
        catch ex
            # Never throw across the OS-thread boundary; log best-effort.
            try
                @error "Reseau.Files threadpool job failed" exception = (ex, catch_backtrace())
            catch
            end
        end
    end
end

function ThreadPoolBackend(; thread_count::Integer = max(1, min(Sys.CPU_THREADS, 4)))
    n = Int(thread_count)
    n <= 0 && throw(ArgumentError("thread_count must be >= 1"))
    lock = ReentrantLock()
    backend = ThreadPoolBackend(lock, Base.Threads.Condition(lock), Any[], false, ThreadHandle[])

    worker_fn = c -> _worker_main(c)
    for i in 1:n
        handle = ThreadHandle()
        opts = thread_options_with_defaults(
            ThreadOptions(; join_strategy = ThreadJoinStrategy.MANUAL);
            name = "reseau-files-$i",
        )
        rc = thread_launch(handle, worker_fn, (backend = backend,), opts)
        rc == 0 || error("Failed to launch files worker thread ($rc)")
        push!(backend.threads, handle)
    end
    return backend
end

const _DEFAULT_BACKEND_LOCK = ReentrantLock()
const _DEFAULT_BACKEND = Ref{Union{AbstractFilesBackend, Nothing}}(nothing)

function default_backend()::AbstractFilesBackend
    lock(_DEFAULT_BACKEND_LOCK)
    try
        if _DEFAULT_BACKEND[] === nothing
            _DEFAULT_BACKEND[] = ThreadPoolBackend()
        end
        return _DEFAULT_BACKEND[]::AbstractFilesBackend
    finally
        unlock(_DEFAULT_BACKEND_LOCK)
    end
end

function submit!(backend::ThreadPoolBackend, job::Function)::Nothing
    lock(backend.lock)
    try
        backend.closed && throw(ArgumentError("backend is shut down"))
        push!(backend.queue, job)
        notify(backend.cond)
    finally
        unlock(backend.lock)
    end
    return nothing
end

function shutdown!(backend::ThreadPoolBackend)::Nothing
    threads = backend.threads
    lock(backend.lock)
    try
        backend.closed && return nothing
        backend.closed = true
        notify(backend.cond; all = true)
    finally
        unlock(backend.lock)
    end
    for t in threads
        thread_join(t)
    end
    return nothing
end

end # module Backend
