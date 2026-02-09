# Locking + atomic write helpers for `Reseau.Files`.
#
# Scope (v1):
# - pidfile locks (mkpidlock/trymkpidlock)
# - advisory file locks (POSIX flock / Windows LockFileEx)
# - atomic_write helper (temp + rename; optional durability knobs)

module Locking

export
    PidlockedError,
    PidLock,
    mkpidlock,
    trymkpidlock,
    FileLock,
    lock_file,
    unlock_file,
    with_file_lock,
    atomic_write

using ...Reseau: _PLATFORM_WINDOWS
using ...Reseau: ThreadHandle, ThreadOptions, ThreadJoinStrategy
using ...Reseau: thread_launch, thread_join, thread_options_with_defaults
using ...Reseau: thread_current_sleep
using ..Files:
    FileHandle,
    StatStruct,
    JL_O_CREAT,
    JL_O_RDWR,
    JL_O_RDONLY,
    JL_O_EXCL,
    JL_O_CLOEXEC
using ..Files:
    open,
    close,
    flush,
    write,
    stat,
    fstat,
    lstat,
    samefile,
    rename,
    rm,
    mkdir,
    mkpath,
    ispath,
    tempname,
    touch,
    pwd,
    realpath

using ..Watching: watch_file

struct PidlockedError <: Exception
    msg::String
end

Base.show(io::IO, e::PidlockedError) = print(io, e.msg)

mutable struct PidLock
    path::String
    fd::FileHandle
    refresh_thread::Union{Nothing, ThreadHandle}
    refresh_stop::Base.Threads.Atomic{Bool}
    refresh_interval_ns::UInt64
end

@inline function _gethostname()::String
    @static if _PLATFORM_WINDOWS
        # Best-effort: fall back to env var.
        return get(ENV, "COMPUTERNAME", "")
    else
        buf = Vector{UInt8}(undef, 256)
        rc = GC.@preserve buf begin
            @ccall gethostname(pointer(buf)::Ptr{UInt8}, Csize_t(length(buf))::Csize_t)::Cint
        end
        rc == 0 || return ""
        z = findfirst(==(0x00), buf)
        n = z === nothing ? length(buf) : (z - 1)
        return String(copy(buf[1:n]))
    end
end

@inline function _write_pidfile(io::IO, pid::Cint)
    host = _gethostname()
    isempty(host) ? print(io, pid) : print(io, pid, " ", host)
    return nothing
end

function _parse_pidfile(io::IO)
    pid = Cuint(0)
    host = ""
    age = 0.0
    try
        fields = split(read(io, String), ' ', limit = 2)
        p = tryparse(Cuint, fields[1])
        pid = p === nothing ? Cuint(0) : p
        host = (length(fields) == 2) ? fields[2] : ""
    catch
    end
    try
        age = time() - (fstat(io).mtime)
    catch
        age = 0.0
    end
    return (pid, host, age)
end

function _parse_pidfile(path::String)
    try
        io = open(path, JL_O_RDONLY | JL_O_CLOEXEC, 0)
        try
            return _parse_pidfile(io)
        finally
            close(io)
        end
    catch
        return (Cuint(0), "", 0.0)
    end
end

@inline function _isvalidpid(host::AbstractString, pid::Cuint)::Bool
    # Can't inspect remote hosts.
    (host == "" || host == _gethostname()) || return true
    pid == 0 && return false
    @static if _PLATFORM_WINDOWS
        return true
    else
        pid > Cuint(typemax(Cint)) && return false
        rc = @ccall kill(Cint(pid)::Cint, Cint(0)::Cint)::Cint
        if rc == 0
            return true
        end
        err = Libc.errno()
        return err != Libc.ESRCH
    end
end

function _stale_pidfile(path::String, stale_age::Real, refresh::Real)::Bool
    pid, host, age = _parse_pidfile(path)
    age < -Float64(stale_age) && @warn "filesystem time skew detected" path = path
    longer_factor = refresh == 0 ? 25 : 5
    if age > Float64(stale_age)
        if (age > Float64(stale_age) * longer_factor) || !_isvalidpid(host, pid)
            return true
        end
    end
    return false
end

function _tryopen_exclusive(path::String, mode::Integer)
    try
        return open(path, JL_O_RDWR | JL_O_CREAT | JL_O_EXCL | JL_O_CLOEXEC, mode)
    catch ex
        # Only treat "already exists" as a soft failure.
        if ex isa SystemError
            @static if !_PLATFORM_WINDOWS
                ex.errnum == Libc.EEXIST && return nothing
            end
        end
        # Best-effort Windows mapping: if the path exists, treat as locked.
        ispath(path) && return nothing
        rethrow()
    end
end

function _tryrmopenfile(path::String)
    # Deleting open file on Windows is hard if we want to reuse the name quickly.
    if Sys.iswindows()
        try
            rmdir, rmname = splitdir(path)
            sep = Sys.iswindows() ? '\\' : '/'
            rmpath = string(rmdir, isempty(rmdir) ? "" : string(sep), "\$", string(time_ns(); base = 16), rmname, ".deleted")
            rename(path, rmpath)
            path = rmpath
        catch
        end
    end
    try
        rm(path; force = true, recursive = true)
        return true
    catch ex
        return ex
    end
end

function _open_exclusive(path::String;
        mode::Integer = 0o444,
        poll_interval::Real = 10,
        wait::Bool = true,
        stale_age::Real = 0,
        refresh::Real = stale_age / 2,
    )
    file = _tryopen_exclusive(path, mode)
    file === nothing || return file

    if !wait
        if stale_age > 0 && _stale_pidfile(path, stale_age, refresh)
            @warn "attempting to remove probably stale pidfile" path = path
            _tryrmopenfile(path)
            file = _tryopen_exclusive(path, mode)
            file === nothing || return file
        end
        throw(PidlockedError("Failed to get pidfile lock for $(repr(path))."))
    end

    # Wait-loop.
    while true
        if stale_age > 0 && _stale_pidfile(path, stale_age, refresh)
            stale_age = 0
            @warn "attempting to remove probably stale pidfile" path = path
            _tryrmopenfile(path)
        end

        # Retry open.
        file = _tryopen_exclusive(path, mode)
        file === nothing || return file

        # Prefer watcher; fall back to sleep polling.
        try
            _ = watch_file(path, poll_interval)
        catch
            # `thread_current_sleep` is a whole-thread sleep; for this synchronous API that's fine.
            nanos = UInt64(max(poll_interval, 0)) * UInt64(1_000_000_000)
            thread_current_sleep(Int(nanos))
        end
    end
end

function mkpidlock(at::AbstractString, pid::Cint = getpid();
        mode::Integer = 0o444,
        poll_interval::Real = 10,
        stale_age::Real = 0,
        refresh::Real = stale_age / 2,
        wait::Bool = true,
    )
    atdir, atname = splitdir(String(at))
    isempty(atdir) && (atdir = pwd())
    full = realpath(atdir) * string(Base.Filesystem.path_separator) * atname
    fd = _open_exclusive(full; mode = mode, poll_interval = poll_interval, wait = wait, stale_age = stale_age, refresh = refresh)

    lock = PidLock(full, fd, nothing, Base.Threads.Atomic{Bool}(false), UInt64(0))
    try
        _write_pidfile(fd, pid)
        flush(fd)

        if refresh > 0
            lock.refresh_interval_ns = UInt64(round(Int64, Float64(refresh) * 1.0e9))
            handle = ThreadHandle()
            opts = thread_options_with_defaults(
                ThreadOptions(; join_strategy = ThreadJoinStrategy.MANUAL);
                name = "reseau-pidlock-refresh",
            )
            thread_fn = ctx -> begin
                l = ctx.lock::PidLock
                while true
                    l.refresh_stop[] && break
                    thread_current_sleep(Int(l.refresh_interval_ns))
                    l.refresh_stop[] && break
                    try
                        touch(l.path)
                    catch
                    end
                end
                return nothing
            end
            rc = thread_launch(handle, thread_fn, (lock = lock,), opts)
            rc == 0 || error("Failed to launch pidlock refresh thread ($rc)")
            lock.refresh_thread = handle
        end
    catch
        if lock.refresh_thread !== nothing
            lock.refresh_stop[] = true
            thread_join(lock.refresh_thread)
        end
        _tryrmopenfile(full)
        close(fd)
        rethrow()
    end
    finalizer(close, lock)
    return lock
end

function mkpidlock(f::Function, at::AbstractString; kwargs...)
    lock = mkpidlock(at; kwargs...)
    try
        return f()
    finally
        close(lock)
    end
end

function trymkpidlock(args...; kwargs...)
    try
        mkpidlock(args...; kwargs..., wait = false)
    catch ex
        ex isa PidlockedError && return false
        rethrow()
    end
end

function Base.close(lock::PidLock)
    if lock.refresh_thread !== nothing
        lock.refresh_stop[] = true
        thread_join(lock.refresh_thread)
        lock.refresh_thread = nothing
    end
    isopen(lock.fd) || return false
    removed = false
    path = lock.path
    pathstat = try
        stat(path)
    catch
        removed = true
        nothing
    end
    if pathstat !== nothing && samefile(fstat(lock.fd), pathstat)
        removed = _tryrmopenfile(path)
    end
    close(lock.fd)
    return removed === true
end

# -----------------------------------------------------------------------------
# Advisory file locks
# -----------------------------------------------------------------------------

mutable struct FileLock
    path::String
    file::FileHandle
    shared::Bool
end

@static if !_PLATFORM_WINDOWS
    const _LOCK_SH = Cint(1)
    const _LOCK_EX = Cint(2)
    const _LOCK_NB = Cint(4)
    const _LOCK_UN = Cint(8)

    function _flock(fd::Cint, op::Cint)::Nothing
        rc = @ccall flock(fd::Cint, op::Cint)::Cint
        rc == 0 || throw(SystemError("flock", Libc.errno()))
        return nothing
    end
else
    const _LOCKFILE_FAIL_IMMEDIATELY = UInt32(0x00000001)
    const _LOCKFILE_EXCLUSIVE_LOCK = UInt32(0x00000002)

    struct _OVERLAPPED
        Internal::UInt
        InternalHigh::UInt
        Offset::UInt32
        OffsetHigh::UInt32
        hEvent::Ptr{Cvoid}
    end

    @inline function _win_get_last_error()::UInt32
        return @ccall "kernel32".GetLastError()::UInt32
    end

    function _win_throw(func::AbstractString)
        throw(Base.windowserror(func, _win_get_last_error()))
    end

    function _lockfileex(h::Ptr{Cvoid}, flags::UInt32)::Nothing
        ov = Ref(_OVERLAPPED(0, 0, 0, 0, C_NULL))
        ok = @ccall "kernel32".LockFileEx(
            h::Ptr{Cvoid},
            flags::UInt32,
            UInt32(0)::UInt32,
            UInt32(0xFFFFFFFF)::UInt32,
            UInt32(0xFFFFFFFF)::UInt32,
            ov::Ref{_OVERLAPPED},
        )::Int32
        ok != 0 || _win_throw("LockFileEx")
        return nothing
    end

    function _unlockfileex(h::Ptr{Cvoid})::Nothing
        ov = Ref(_OVERLAPPED(0, 0, 0, 0, C_NULL))
        ok = @ccall "kernel32".UnlockFileEx(
            h::Ptr{Cvoid},
            UInt32(0)::UInt32,
            UInt32(0xFFFFFFFF)::UInt32,
            UInt32(0xFFFFFFFF)::UInt32,
            ov::Ref{_OVERLAPPED},
        )::Int32
        ok != 0 || _win_throw("UnlockFileEx")
        return nothing
    end
end

function lock_file(path::AbstractString; shared::Bool = false, blocking::Bool = true, mode::Integer = 0o666)::FileLock
    p = String(path)
    fh = open(p, JL_O_RDWR | JL_O_CREAT | JL_O_CLOEXEC, mode)
    try
        @static if !_PLATFORM_WINDOWS
            op = shared ? _LOCK_SH : _LOCK_EX
            blocking || (op |= _LOCK_NB)
            _flock(fh.fd, op)
        else
            flags = shared ? UInt32(0) : _LOCKFILE_EXCLUSIVE_LOCK
            blocking || (flags |= _LOCKFILE_FAIL_IMMEDIATELY)
            _lockfileex(fh.handle, flags)
        end
    catch
        close(fh)
        rethrow()
    end
    return FileLock(p, fh, shared)
end

function unlock_file(lock::FileLock)::Nothing
    @static if !_PLATFORM_WINDOWS
        _flock(lock.file.fd, _LOCK_UN)
    else
        _unlockfileex(lock.file.handle)
    end
    close(lock.file)
    return nothing
end

with_file_lock(f::Function, path::AbstractString; kwargs...) = begin
    l = lock_file(path; kwargs...)
    try
        return f()
    finally
        unlock_file(l)
    end
end

# -----------------------------------------------------------------------------
# Atomic write
# -----------------------------------------------------------------------------

function atomic_write(
        path::AbstractString,
        data;
        mode = nothing,
        tmpdir::Union{Nothing, AbstractString} = nothing,
        fsync::Bool = false,
        fsync_dir::Bool = false,
        replace::Bool = true,
    )::Nothing
    dst = String(path)
    if !replace && ispath(dst)
        throw(ArgumentError("destination exists: $(repr(dst))"))
    end

    parent = tmpdir === nothing ? dirname(dst) : String(tmpdir)
    isempty(parent) && (parent = pwd())
    mkpath(parent; mode = 0o777)

    tmppath = tempname(parent = parent, prefix = ".atomic_")
    fh = open(tmppath, JL_O_RDWR | JL_O_CREAT | JL_O_EXCL | JL_O_CLOEXEC, mode === nothing ? 0o600 : Int(mode))
    ok = false
    try
        if data isa AbstractVector{UInt8}
            write(fh, data)
        elseif data isa Union{String, SubString{String}, AbstractString}
            write(fh, data)
        elseif data isa Function
            data(fh)
        else
            throw(ArgumentError("unsupported data type for atomic_write: $(typeof(data))"))
        end
        fsync && flush(fh)
        close(fh)
        rename(tmppath, dst)
        if fsync_dir
            # Best-effort: fsync parent directory on POSIX; on Windows flush is a no-op for dirs.
            @static if !_PLATFORM_WINDOWS
                dirfh = open(parent, JL_O_RDONLY | JL_O_CLOEXEC, 0)
                try
                    flush(dirfh)
                finally
                    close(dirfh)
                end
            end
        end
        ok = true
    finally
        if !ok
            try
                close(fh)
            catch
            end
            try
                rm(tmppath; force = true, recursive = true)
            catch
            end
        end
    end
    return nothing
end

end # module Locking
