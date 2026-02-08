# FileHandle - minimal, unbuffered OS file handle.
#
# v1 approach:
# - POSIX uses an `fd::Cint` and syscalls (`open/read/write/lseek/ftruncate/fsync`).
# - Windows uses a Win32 `HANDLE` and kernel32 APIs (`CreateFileW/ReadFile/WriteFile/...`).
#
# This file intentionally does not call Base.Filesystem or FileWatching APIs (libuv-backed).

using ..Reseau: _PLATFORM_WINDOWS, _PLATFORM_LINUX, _PLATFORM_APPLE

mutable struct FileHandle <: IO
    fd::Cint
    handle::Ptr{Cvoid}
    open::Bool
end

FileHandle() = FileHandle(Cint(-1), C_NULL, false)

@inline function _require_open(f::FileHandle)
    f.open || throw(ArgumentError("file is closed"))
    return nothing
end

function Base.isopen(f::FileHandle)::Bool
    return f.open
end

function Base.closewrite(::FileHandle)
    # Disk files do not have half-close semantics.
    return nothing
end

@static if !_PLATFORM_WINDOWS
    # POSIX constants (best-effort).
    const _O_RDONLY = Cint(0)
    const _O_WRONLY = Cint(1)
    const _O_RDWR = Cint(2)

    const _SEEK_SET = Cint(0)
    const _SEEK_CUR = Cint(1)
    const _SEEK_END = Cint(2)

    function _posix_open(path::AbstractString, flags::Integer, mode::Integer)::Cint
        # `open(2)` is variadic and only consumes `mode` when `O_CREAT` is set.
        # On some ABIs, calling variadic functions with a "fixed-args" signature
        # can pass the varargs incorrectly; use the varargs `@ccall` form.
        fd = if (flags & JL_O_CREAT) != 0
            @ccall open(path::Cstring, Cint(flags)::Cint; Cuint(mode)::Cuint)::Cint
        else
            @ccall open(path::Cstring, Cint(flags)::Cint)::Cint
        end
        if fd < 0
            throw(SystemError("open($(repr(path)))", Libc.errno()))
        end
        return fd
    end

    function Base.close(f::FileHandle)::Nothing
        f.open || return nothing
        fd = f.fd
        f.open = false
        f.fd = Cint(-1)
        f.handle = C_NULL
        rc = @ccall gc_safe = true close(fd::Cint)::Cint
        rc == 0 || throw(SystemError("close", Libc.errno()))
        return nothing
    end

    function Base.fd(f::FileHandle)
        _require_open(f)
        return Int(f.fd)
    end

    function Base.flush(f::FileHandle)
        _require_open(f)
        rc = @ccall gc_safe = true fsync(f.fd::Cint)::Cint
        rc == 0 || throw(SystemError("fsync", Libc.errno()))
        return nothing
    end

    function Base.position(f::FileHandle)::Int64
        _require_open(f)
        off = @ccall lseek(f.fd::Cint, Int64(0)::Int64, _SEEK_CUR::Cint)::Int64
        off < 0 && throw(SystemError("lseek", Libc.errno()))
        return off
    end

    function Base.seek(f::FileHandle, pos::Integer)
        _require_open(f)
        off = @ccall lseek(f.fd::Cint, Int64(pos)::Int64, _SEEK_SET::Cint)::Int64
        off < 0 && throw(SystemError("lseek", Libc.errno()))
        return f
    end

    function Base.seekend(f::FileHandle)
        _require_open(f)
        off = @ccall lseek(f.fd::Cint, Int64(0)::Int64, _SEEK_END::Cint)::Int64
        off < 0 && throw(SystemError("lseek", Libc.errno()))
        return f
    end

    function Base.seekstart(f::FileHandle)
        return seek(f, 0)
    end

    function Base.truncate(f::FileHandle, n::Integer)
        _require_open(f)
        rc = @ccall ftruncate(f.fd::Cint, Int64(n)::Int64)::Cint
        rc == 0 || throw(SystemError("ftruncate", Libc.errno()))
        return nothing
    end

    function Base.eof(f::FileHandle)::Bool
        _require_open(f)
        pos = position(f)
        st = fstat(f)
        return pos >= st.size
    end

    function Base.readbytes!(f::FileHandle, b::AbstractVector{UInt8}, nb::Integer = length(b))::Int
        _require_open(f)
        nb < 0 && throw(ArgumentError("nb must be >= 0"))
        nb == 0 && return 0
        n = min(Int(nb), length(b))
        total = 0
        GC.@preserve b begin
            p = pointer(b)
            while total < n
                rc = @ccall gc_safe = true read(
                    f.fd::Cint,
                    (p + total)::Ptr{Cvoid},
                    Csize_t(n - total)::Csize_t,
                )::Cssize_t
                if rc == 0
                    return total
                elseif rc < 0
                    err = Libc.errno()
                    err == Libc.EINTR && continue
                    throw(SystemError("read", err))
                end
                total += Int(rc)
            end
        end
        return total
    end

    function Base.unsafe_read(f::FileHandle, p::Ptr{UInt8}, n::UInt)
        _require_open(f)
        remaining = Int64(n)
        remaining == 0 && return nothing
        buf = Ptr{UInt8}(p)
        while remaining > 0
            rc = @ccall gc_safe = true read(f.fd::Cint, buf::Ptr{Cvoid}, Csize_t(remaining)::Csize_t)::Cssize_t
            if rc == 0
                throw(EOFError())
            elseif rc < 0
                err = Libc.errno()
                err == Libc.EINTR && continue
                throw(SystemError("read", err))
            end
            remaining -= Int64(rc)
            buf += rc
        end
        return nothing
    end

    function Base.unsafe_write(f::FileHandle, p::Ptr{UInt8}, n::UInt)
        _require_open(f)
        remaining = Int64(n)
        remaining == 0 && return 0
        buf = Ptr{UInt8}(p)
        while remaining > 0
            rc = @ccall gc_safe = true write(f.fd::Cint, buf::Ptr{Cvoid}, Csize_t(remaining)::Csize_t)::Cssize_t
            if rc < 0
                err = Libc.errno()
                err == Libc.EINTR && continue
                throw(SystemError("write", err))
            end
            remaining -= Int64(rc)
            buf += rc
        end
        return Int(n)
end
else
    # Windows HANDLE-based file IO.
    const _INVALID_HANDLE_VALUE = Ptr{Cvoid}(-1)

    const _GENERIC_READ = UInt32(0x80000000)
    const _GENERIC_WRITE = UInt32(0x40000000)
    const _FILE_APPEND_DATA = UInt32(0x00000004)

    const _FILE_SHARE_READ = UInt32(0x00000001)
    const _FILE_SHARE_WRITE = UInt32(0x00000002)
    const _FILE_SHARE_DELETE = UInt32(0x00000004)

    const _CREATE_NEW = UInt32(1)
    const _CREATE_ALWAYS = UInt32(2)
    const _OPEN_EXISTING = UInt32(3)
    const _OPEN_ALWAYS = UInt32(4)
    const _TRUNCATE_EXISTING = UInt32(5)

    const _FILE_ATTRIBUTE_NORMAL = UInt32(0x00000080)

    const _FILE_BEGIN = UInt32(0)
    const _FILE_CURRENT = UInt32(1)
    const _FILE_END = UInt32(2)

    const _ERROR_EOF = UInt32(38)

    @inline function _win_get_last_error()::UInt32
        return @ccall "kernel32".GetLastError()::UInt32
    end

    function _win_throw(func::AbstractString)
        throw(Base.windowserror(func, _win_get_last_error()))
    end

    function _win_open(path::AbstractString, flags::Integer, _mode::Integer)::Ptr{Cvoid}
        # Minimal mapping from Base-style JL_O_* flags to CreateFileW parameters.
        #
        # Supported: RDONLY/WRONLY/RDWR, CREAT, TRUNC, EXCL, APPEND.
        access = UInt32(0)
        if (flags & JL_O_RDWR) != 0
            access |= (_GENERIC_READ | _GENERIC_WRITE)
        elseif (flags & JL_O_WRONLY) != 0
            access |= _GENERIC_WRITE
        else
            access |= _GENERIC_READ
        end
        if (flags & JL_O_APPEND) != 0
            # FILE_APPEND_DATA is enough for appends; also allow reading if requested.
            access |= _FILE_APPEND_DATA
        end

        share = _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE

        disposition = _OPEN_EXISTING
        if (flags & JL_O_CREAT) != 0
            if (flags & JL_O_EXCL) != 0
                disposition = _CREATE_NEW
            elseif (flags & JL_O_TRUNC) != 0
                disposition = _CREATE_ALWAYS
            else
                disposition = _OPEN_ALWAYS
            end
        else
            if (flags & JL_O_TRUNC) != 0
                disposition = _TRUNCATE_EXISTING
            end
        end

        attrs = _FILE_ATTRIBUTE_NORMAL

        wpath = Base.cwstring(path)
        h = GC.@preserve wpath begin
            @ccall "kernel32".CreateFileW(
                wpath::Cwstring,
                access::UInt32,
                share::UInt32,
                C_NULL::Ptr{Cvoid},
                disposition::UInt32,
                attrs::UInt32,
                C_NULL::Ptr{Cvoid},
            )::Ptr{Cvoid}
        end
        (h == C_NULL || h == _INVALID_HANDLE_VALUE) && _win_throw("CreateFileW")
        return h
    end

    function Base.close(f::FileHandle)::Nothing
        f.open || return nothing
        h = f.handle
        f.open = false
        f.fd = Cint(-1)
        f.handle = C_NULL
        ok = @ccall gc_safe = true "kernel32".CloseHandle(h::Ptr{Cvoid})::Int32
        ok != 0 || _win_throw("CloseHandle")
        return nothing
    end

    function Base.flush(f::FileHandle)
        _require_open(f)
        ok = @ccall gc_safe = true "kernel32".FlushFileBuffers(f.handle::Ptr{Cvoid})::Int32
        ok != 0 || _win_throw("FlushFileBuffers")
        return nothing
    end

    function Base.position(f::FileHandle)::Int64
        _require_open(f)
        newpos = Ref{Int64}(0)
        ok = @ccall gc_safe = true "kernel32".SetFilePointerEx(
            f.handle::Ptr{Cvoid},
            Int64(0)::Int64,
            newpos::Ref{Int64},
            _FILE_CURRENT::UInt32,
        )::Int32
        ok != 0 || _win_throw("SetFilePointerEx")
        return newpos[]
    end

    function Base.seek(f::FileHandle, pos::Integer)
        _require_open(f)
        newpos = Ref{Int64}(0)
        ok = @ccall gc_safe = true "kernel32".SetFilePointerEx(
            f.handle::Ptr{Cvoid},
            Int64(pos)::Int64,
            newpos::Ref{Int64},
            _FILE_BEGIN::UInt32,
        )::Int32
        ok != 0 || _win_throw("SetFilePointerEx")
        return f
    end

    function Base.eof(f::FileHandle)::Bool
        _require_open(f)
        pos = position(f)
        st = fstat(f)
        return pos >= st.size
    end

    function Base.readbytes!(f::FileHandle, b::AbstractVector{UInt8}, nb::Integer = length(b))::Int
        _require_open(f)
        nb < 0 && throw(ArgumentError("nb must be >= 0"))
        nb == 0 && return 0
        n = min(Int(nb), length(b))
        total = 0
        GC.@preserve b begin
            p = pointer(b)
            while total < n
                read = Ref{UInt32}(0)
                ok = @ccall gc_safe = true "kernel32".ReadFile(
                    f.handle::Ptr{Cvoid},
                    (p + total)::Ptr{Cvoid},
                    UInt32(n - total)::UInt32,
                    read::Ref{UInt32},
                    C_NULL::Ptr{Cvoid},
                )::Int32
                if ok == 0
                    err = _win_get_last_error()
                    err == _ERROR_EOF && return total
                    _win_throw("ReadFile")
                end
                read[] == 0 && return total
                total += Int(read[])
            end
        end
        return total
    end

    function Base.seekend(f::FileHandle)
        _require_open(f)
        newpos = Ref{Int64}(0)
        ok = @ccall gc_safe = true "kernel32".SetFilePointerEx(
            f.handle::Ptr{Cvoid},
            Int64(0)::Int64,
            newpos::Ref{Int64},
            _FILE_END::UInt32,
        )::Int32
        ok != 0 || _win_throw("SetFilePointerEx")
        return f
    end

    function Base.seekstart(f::FileHandle)
        return seek(f, 0)
    end

    function Base.truncate(f::FileHandle, n::Integer)
        _require_open(f)
        seek(f, n)
        ok = @ccall gc_safe = true "kernel32".SetEndOfFile(f.handle::Ptr{Cvoid})::Int32
        ok != 0 || _win_throw("SetEndOfFile")
        return nothing
    end

    function Base.unsafe_read(f::FileHandle, p::Ptr{UInt8}, n::UInt)
        _require_open(f)
        remaining = Int64(n)
        remaining == 0 && return nothing
        buf = Ptr{UInt8}(p)
        readbytes = Ref{UInt32}(0)
        while remaining > 0
            chunk = remaining > typemax(UInt32) ? typemax(UInt32) : UInt32(remaining)
            ok = @ccall gc_safe = true "kernel32".ReadFile(
                f.handle::Ptr{Cvoid},
                buf::Ptr{Cvoid},
                chunk::UInt32,
                readbytes::Ref{UInt32},
                C_NULL::Ptr{Cvoid},
            )::Int32
            if ok == 0
                err = _win_get_last_error()
                err == _ERROR_EOF && throw(EOFError())
                _win_throw("ReadFile")
            end
            got = Int64(readbytes[])
            got == 0 && throw(EOFError())
            remaining -= got
            buf += got
        end
        return nothing
    end

    function Base.unsafe_write(f::FileHandle, p::Ptr{UInt8}, n::UInt)
        _require_open(f)
        remaining = Int64(n)
        remaining == 0 && return 0
        buf = Ptr{UInt8}(p)
        written = Ref{UInt32}(0)
        while remaining > 0
            chunk = remaining > typemax(UInt32) ? typemax(UInt32) : UInt32(remaining)
            ok = @ccall gc_safe = true "kernel32".WriteFile(
                f.handle::Ptr{Cvoid},
                buf::Ptr{Cvoid},
                chunk::UInt32,
                written::Ref{UInt32},
                C_NULL::Ptr{Cvoid},
            )::Int32
            ok != 0 || _win_throw("WriteFile")
            got = Int64(written[])
            remaining -= got
            buf += got
        end
        return Int(n)
    end
end

# -----------------------------------------------------------------------------
# Public open() API (Base-like).
# -----------------------------------------------------------------------------

function open(path::AbstractString, flags::Integer, mode::Integer = 0o666)::FileHandle
    @static if _PLATFORM_WINDOWS
        h = _win_open(path, flags, mode)
        return FileHandle(Cint(-1), h, true)
    else
        fd = _posix_open(path, flags, mode)
        return FileHandle(fd, C_NULL, true)
    end
end

function _flags_from_mode_string(mode::AbstractString)::Tuple{Cint, Bool}
    # Returns (flags, truncate_on_open)
    mode == "r"  && return (JL_O_RDONLY, false)
    mode == "r+" && return (JL_O_RDWR, false)
    mode == "w"  && return (JL_O_WRONLY | JL_O_CREAT | JL_O_TRUNC, true)
    mode == "w+" && return (JL_O_RDWR | JL_O_CREAT | JL_O_TRUNC, true)
    mode == "a"  && return (JL_O_WRONLY | JL_O_CREAT | JL_O_APPEND, false)
    mode == "a+" && return (JL_O_RDWR | JL_O_CREAT | JL_O_APPEND, false)
    throw(ArgumentError("invalid open mode: $(repr(mode))"))
end

function open(path::AbstractString, mode::AbstractString)::FileHandle
    flags, _ = _flags_from_mode_string(mode)
    # Always request CLOEXEC where supported; harmless otherwise.
    flags |= JL_O_CLOEXEC
    return open(path, flags, 0o666)
end

function open(
        path::AbstractString;
        read::Bool = true,
        write::Bool = false,
        create::Bool = false,
        truncate::Bool = false,
        append::Bool = false,
        mode::Integer = 0o666,
    )::FileHandle
    flags = Cint(0)
    if read && write
        flags |= JL_O_RDWR
    elseif write
        flags |= JL_O_WRONLY
    else
        flags |= JL_O_RDONLY
    end
    create && (flags |= JL_O_CREAT)
    truncate && (flags |= JL_O_TRUNC)
    append && (flags |= JL_O_APPEND)
    flags |= JL_O_CLOEXEC
    return open(path, flags, mode)
end

function open(f::Function, path::AbstractString; kwargs...)
    io = open(path; kwargs...)
    try
        return f(io)
    finally
        close(io)
    end
end

function open(f::Function, path::AbstractString, mode::AbstractString)
    io = open(path, mode)
    try
        return f(io)
    finally
        close(io)
    end
end

function open(f::Function, path::AbstractString, flags::Integer, mode::Integer = 0o666)
    io = open(path, flags, mode)
    try
        return f(io)
    finally
        close(io)
    end
end
