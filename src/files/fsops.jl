# Core filesystem operations implemented without libuv.
#
# Notes:
# - Many of these names conflict with Base, so we intentionally do not export them
#   from `Reseau.Files`; use `Reseau.Files.<name>` at call-sites.

using ..Reseau: _PLATFORM_WINDOWS, _PLATFORM_LINUX, _PLATFORM_APPLE

const _PATH_SEP = Sys.iswindows() ? '\\' : '/'

@static if !_PLATFORM_WINDOWS
    # -------------------------------------------------------------------------
    # POSIX
    # -------------------------------------------------------------------------

    function pwd()::String
        p = @ccall getcwd(C_NULL::Ptr{UInt8}, Csize_t(0)::Csize_t)::Ptr{UInt8}
        p == C_NULL && throw(SystemError("getcwd", Libc.errno()))
        try
            return unsafe_string(p)
        finally
            Libc.free(p)
        end
    end

    function cd(dir::AbstractString)::Nothing
        rc = @ccall chdir(dir::Cstring)::Cint
        rc == 0 || throw(SystemError("chdir($(repr(dir)))", Libc.errno()))
        return nothing
    end

    function cd(f::Function, dir::AbstractString)
        old = pwd()
        cd(dir)
        try
            return f()
        finally
            cd(old)
        end
    end

    function mkdir(path::AbstractString; mode::Integer = 0o777)::Nothing
        rc = @ccall mkdir(path::Cstring, Cuint(mode)::Cuint)::Cint
        rc == 0 || throw(SystemError("mkdir($(repr(path)))", Libc.errno()))
        return nothing
    end

    function unlink(path::AbstractString)::Nothing
        rc = @ccall unlink(path::Cstring)::Cint
        rc == 0 || throw(SystemError("unlink($(repr(path)))", Libc.errno()))
        return nothing
    end

    function rmdir(path::AbstractString)::Nothing
        rc = @ccall rmdir(path::Cstring)::Cint
        rc == 0 || throw(SystemError("rmdir($(repr(path)))", Libc.errno()))
        return nothing
    end

    function rename(src::AbstractString, dst::AbstractString)::Nothing
        rc = @ccall rename(src::Cstring, dst::Cstring)::Cint
        rc == 0 || throw(SystemError("rename($(repr(src)) -> $(repr(dst)))", Libc.errno()))
        return nothing
    end
else
    # -------------------------------------------------------------------------
    # Windows
    # -------------------------------------------------------------------------

    const _INVALID_HANDLE_VALUE = Ptr{Cvoid}(-1)

    const _MOVEFILE_REPLACE_EXISTING = UInt32(0x00000001)
    const _MOVEFILE_COPY_ALLOWED = UInt32(0x00000002)
    const _MOVEFILE_WRITE_THROUGH = UInt32(0x00000008)

    @inline function _win_get_last_error()::UInt32
        return @ccall "kernel32".GetLastError()::UInt32
    end

    function _win_throw(func::AbstractString)
        throw(Base.windowserror(func, _win_get_last_error()))
    end

    function pwd()::String
        # Query required length first.
        n = @ccall "kernel32".GetCurrentDirectoryW(UInt32(0)::UInt32, C_NULL::Ptr{UInt16})::UInt32
        n == 0 && _win_throw("GetCurrentDirectoryW")
        buf = Vector{UInt16}(undef, Int(n))
        rc = GC.@preserve buf begin
            @ccall "kernel32".GetCurrentDirectoryW(UInt32(length(buf))::UInt32, pointer(buf)::Ptr{UInt16})::UInt32
        end
        rc == 0 && _win_throw("GetCurrentDirectoryW")
        # rc includes null terminator.
        return String(transcode(UInt8, buf[1:(rc - 1)]))
    end

    function cd(dir::AbstractString)::Nothing
        wdir = Base.cwstring(dir)
        ok = GC.@preserve wdir begin
            @ccall "kernel32".SetCurrentDirectoryW(wdir::Cwstring)::Int32
        end
        ok != 0 || _win_throw("SetCurrentDirectoryW")
        return nothing
    end

    function cd(f::Function, dir::AbstractString)
        old = pwd()
        cd(dir)
        try
            return f()
        finally
            cd(old)
        end
    end

    function mkdir(path::AbstractString; mode::Integer = 0o777)::Nothing
        _ = mode
        wpath = Base.cwstring(path)
        ok = GC.@preserve wpath begin
            @ccall "kernel32".CreateDirectoryW(wpath::Cwstring, C_NULL::Ptr{Cvoid})::Int32
        end
        ok != 0 || _win_throw("CreateDirectoryW")
        return nothing
    end

    function unlink(path::AbstractString)::Nothing
        wpath = Base.cwstring(path)
        ok = GC.@preserve wpath begin
            @ccall "kernel32".DeleteFileW(wpath::Cwstring)::Int32
        end
        ok != 0 || _win_throw("DeleteFileW")
        return nothing
    end

    function rmdir(path::AbstractString)::Nothing
        wpath = Base.cwstring(path)
        ok = GC.@preserve wpath begin
            @ccall "kernel32".RemoveDirectoryW(wpath::Cwstring)::Int32
        end
        ok != 0 || _win_throw("RemoveDirectoryW")
        return nothing
    end

    function rename(src::AbstractString, dst::AbstractString)::Nothing
        wsrc = Base.cwstring(src)
        wdst = Base.cwstring(dst)
        ok = GC.@preserve wsrc wdst begin
            @ccall "kernel32".MoveFileExW(
                wsrc::Cwstring,
                wdst::Cwstring,
                (_MOVEFILE_REPLACE_EXISTING | _MOVEFILE_COPY_ALLOWED)::UInt32,
            )::Int32
        end
        ok != 0 || _win_throw("MoveFileExW")
        return nothing
    end
end

# -----------------------------------------------------------------------------
# Cross-platform helpers (pure Julia).
# -----------------------------------------------------------------------------

function mkpath(path::AbstractString; mode::Integer = 0o777)::Nothing
    # Fast path.
    isempty(path) && return nothing
    # Normalize separators (best-effort); avoid libuv realpath here.
    parts = splitpath(path)
    isempty(parts) && return nothing
    cur = parts[1]
    # On Windows, splitpath("C:\\a\\b") yields ["C:\\", "a", "b"].
    for i in 1:length(parts)
        i == 1 && continue
        cur = joinpath(cur, parts[i])
        try
            mkdir(cur; mode = mode)
        catch ex
            # Ignore EEXIST-like cases.
            if ex isa SystemError
                # On POSIX, EEXIST means already exists.
                @static if !_PLATFORM_WINDOWS
                    ex.errnum == Libc.EEXIST && continue
                end
            end
            # If it already exists and is a directory, continue.
            try
                isdir(cur) && continue
            catch
            end
            rethrow()
        end
    end
    return nothing
end

function rm(path::AbstractString; force::Bool = false, recursive::Bool = false)::Nothing
    try
        st = lstat(path)
        if Base.isdir(st)
            recursive || (throw(ArgumentError("refusing to remove directory without recursive=true: $(repr(path))")))
            for name in readdir(path; join = true)
                rm(name; force = force, recursive = true)
            end
            rmdir(path)
        else
            unlink(path)
        end
        return nothing
    catch ex
        force && return nothing
        rethrow()
    end
end

function mv(src::AbstractString, dst::AbstractString; force::Bool = false)::Nothing
    if force
        try
            rm(dst; force = true, recursive = true)
        catch
        end
    end
    return rename(src, dst)
end

function tempdir()::String
    @static if _PLATFORM_WINDOWS
        # Prefer Win32 API.
        n = @ccall "kernel32".GetTempPathW(UInt32(0)::UInt32, C_NULL::Ptr{UInt16})::UInt32
        if n == 0
            # Fallback to env.
            return something(get(ENV, "TEMP", nothing), get(ENV, "TMP", "C:\\Windows\\Temp"))
        end
        buf = Vector{UInt16}(undef, Int(n + 1))
        rc = GC.@preserve buf begin
            @ccall "kernel32".GetTempPathW(UInt32(length(buf))::UInt32, pointer(buf)::Ptr{UInt16})::UInt32
        end
        rc == 0 && _win_throw("GetTempPathW")
        return String(transcode(UInt8, buf[1:rc]))
    else
        return get(ENV, "TMPDIR", "/tmp")
    end
end

const _temp_counter = Base.Threads.Atomic{UInt64}(0)

function tempname(; parent::AbstractString = tempdir(), prefix::AbstractString = "jl_")::String
    # Base.tempname uses randomness; we use time_ns + counter to keep dependencies minimal.
    base = String(parent)
    c = Base.Threads.atomic_add!(_temp_counter, UInt64(1)) + UInt64(1)
    return joinpath(base, string(prefix, string(time_ns(); base = 16), "_", string(c; base = 16)))
end

function mktemp(; parent::AbstractString = tempdir(), prefix::AbstractString = "jl_", mode::Integer = 0o600)
    while true
        path = tempname(parent = parent, prefix = prefix)
        try
            io = open(path, JL_O_RDWR | JL_O_CREAT | JL_O_EXCL | JL_O_CLOEXEC, mode)
            return (path, io)
        catch ex
            # Retry on EEXIST.
            if ex isa SystemError
                @static if !_PLATFORM_WINDOWS
                    ex.errnum == Libc.EEXIST && continue
                end
            end
            rethrow()
        end
    end
end

function mktemp(f::Function; kwargs...)
    path, io = mktemp(; kwargs...)
    try
        return f(path, io)
    finally
        close(io)
    end
end

function mktempdir(; parent::AbstractString = tempdir(), prefix::AbstractString = "jl_")::String
    while true
        path = tempname(parent = parent, prefix = prefix)
        try
            mkdir(path; mode = 0o700)
            return path
        catch ex
            if ex isa SystemError
                @static if !_PLATFORM_WINDOWS
                    ex.errnum == Libc.EEXIST && continue
                end
            end
            rethrow()
        end
    end
end

function mktempdir(f::Function; kwargs...)
    path = mktempdir(; kwargs...)
    try
        return f(path)
    finally
        rm(path; force = true, recursive = true)
    end
end

# -----------------------------------------------------------------------------
# Directory enumeration (readdir / walkdir)
# -----------------------------------------------------------------------------

@static if !_PLATFORM_WINDOWS
    @static if _PLATFORM_LINUX
        struct _Dirent
            d_ino::UInt64
            d_off::Int64
            d_reclen::UInt16
            d_type::UInt8
            d_name::NTuple{256, UInt8}
        end

        @inline function _dirent_name(de::_Dirent)::String
            # d_name is null-terminated.
            n = 0
            @inbounds for i in 1:length(de.d_name)
                de.d_name[i] == 0x00 && break
                n = i
            end
            return String(UInt8[de.d_name[i] for i in 1:n])
        end
    else
        const _DARWIN_MAXPATHLEN = 1024
        struct _Dirent
            d_ino::UInt64
            d_seekoff::UInt64
            d_reclen::UInt16
            d_namlen::UInt16
            d_type::UInt8
            d_name::NTuple{_DARWIN_MAXPATHLEN, UInt8}
        end

        @inline function _dirent_name(de::_Dirent)::String
            n = Int(de.d_namlen)
            n <= 0 && return ""
            return String(UInt8[de.d_name[i] for i in 1:n])
        end
    end

    function readdir(path::AbstractString = "."; join::Bool = false, sort::Bool = true)::Vector{String}
        dir = @ccall opendir(path::Cstring)::Ptr{Cvoid}
        dir == C_NULL && throw(SystemError("opendir($(repr(path)))", Libc.errno()))
        entries = String[]
        try
            while true
                Libc.errno(0)
                entp = @ccall readdir(dir::Ptr{Cvoid})::Ptr{_Dirent}
                if entp == C_NULL
                    err = Libc.errno()
                    err == 0 && break
                    throw(SystemError("readdir($(repr(path)))", err))
                end
                de = unsafe_load(entp)
                name = _dirent_name(de)
                (name == "." || name == ".." || isempty(name)) && continue
                push!(entries, name)
            end
        finally
            _ = @ccall closedir(dir::Ptr{Cvoid})::Cint
        end
        sort && sort!(entries)
        if join
            return [joinpath(path, e) for e in entries]
        end
        return entries
    end
else
    const _ERROR_FILE_NOT_FOUND = UInt32(2)
    const _ERROR_NO_MORE_FILES = UInt32(18)

    struct _FILETIME
        dwLowDateTime::UInt32
        dwHighDateTime::UInt32
    end

    struct _WIN32_FIND_DATAW
        dwFileAttributes::UInt32
        ftCreationTime::_FILETIME
        ftLastAccessTime::_FILETIME
        ftLastWriteTime::_FILETIME
        nFileSizeHigh::UInt32
        nFileSizeLow::UInt32
        dwReserved0::UInt32
        dwReserved1::UInt32
        cFileName::NTuple{260, UInt16}
        cAlternateFileName::NTuple{14, UInt16}
    end

    @inline function _win_finddata_name(fd::_WIN32_FIND_DATAW)::String
        n = 0
        @inbounds for i in 1:length(fd.cFileName)
            fd.cFileName[i] == 0x0000 && break
            n = i
        end
        n == 0 && return ""
        return String(transcode(UInt8, collect(fd.cFileName[1:n])))
    end

    function readdir(path::AbstractString = "."; join::Bool = false, sort::Bool = true)::Vector{String}
        pattern = joinpath(String(path), "*")
        wpat = Base.cwstring(pattern)
        data = Ref{_WIN32_FIND_DATAW}()
        h = GC.@preserve wpat data begin
            @ccall "kernel32".FindFirstFileW(wpat::Cwstring, data::Ref{_WIN32_FIND_DATAW})::Ptr{Cvoid}
        end
        if h == C_NULL || h == _INVALID_HANDLE_VALUE
            err = _win_get_last_error()
            err == _ERROR_FILE_NOT_FOUND && return String[]
            _win_throw("FindFirstFileW")
        end
        entries = String[]
        try
            while true
                name = _win_finddata_name(data[])
                (name == "." || name == ".." || isempty(name)) || push!(entries, name)
                ok = @ccall "kernel32".FindNextFileW(h::Ptr{Cvoid}, data::Ref{_WIN32_FIND_DATAW})::Int32
                if ok == 0
                    err = _win_get_last_error()
                    err == _ERROR_NO_MORE_FILES && break
                    _win_throw("FindNextFileW")
                end
            end
        finally
            _ = @ccall "kernel32".FindClose(h::Ptr{Cvoid})::Int32
        end
        sort && sort!(entries)
        if join
            return [joinpath(path, e) for e in entries]
        end
        return entries
    end
end

struct WalkDir
    root::String
    topdown::Bool
    follow_symlinks::Bool
    onerror::Function
end

function walkdir(
        dir::AbstractString = ".";
        topdown::Bool = true,
        follow_symlinks::Bool = false,
        onerror::Function = rethrow,
    )::WalkDir
    return WalkDir(String(dir), topdown, follow_symlinks, onerror)
end

function Base.iterate(w::WalkDir, state = nothing)
    stack = state === nothing ? Any[(w.root, false)] : state
    while !isempty(stack)
        root, visited = pop!(stack)
        root = root::String
        visited = visited::Bool

        # Enumerate children.
        names = try
            readdir(root; join = false, sort = true)
        catch ex
            w.onerror(ex)
            continue
        end

        dirs = String[]
        files = String[]
        for name in names
            child = joinpath(root, name)
            is_dir = false
            try
                if w.follow_symlinks
                    is_dir = isdir(child)
                else
                    is_dir = isdir(child) && !islink(child)
                end
            catch ex
                w.onerror(ex)
                continue
            end
            if is_dir
                push!(dirs, name)
            else
                push!(files, name)
            end
        end

        if w.topdown
            # Push child dirs in reverse so iteration is stable.
            for name in reverse(dirs)
                push!(stack, (joinpath(root, name), false))
            end
            return ((root, dirs, files), stack)
        else
            if visited
                return ((root, dirs, files), stack)
            end
            push!(stack, (root, true))
            for name in reverse(dirs)
                push!(stack, (joinpath(root, name), false))
            end
        end
    end
    return nothing
end

# -----------------------------------------------------------------------------
# Path + metadata helpers
# -----------------------------------------------------------------------------

function homedir()::String
    @static if _PLATFORM_WINDOWS
        prof = get(ENV, "USERPROFILE", nothing)
        prof !== nothing && return prof
        drive = get(ENV, "HOMEDRIVE", "C:")
        homepath = get(ENV, "HOMEPATH", "\\Users\\Default")
        return string(drive, homepath)
    else
        return get(ENV, "HOME", pwd())
    end
end

function realpath(path::AbstractString)::String
    @static if _PLATFORM_WINDOWS
        wpath = Base.cwstring(path)
        n = GC.@preserve wpath begin
            @ccall "kernel32".GetFullPathNameW(
                wpath::Cwstring,
                UInt32(0)::UInt32,
                C_NULL::Ptr{UInt16},
                C_NULL::Ptr{Ptr{UInt16}},
            )::UInt32
        end
        n == 0 && _win_throw("GetFullPathNameW")
        buf = Vector{UInt16}(undef, Int(n + 1))
        rc = GC.@preserve wpath buf begin
            @ccall "kernel32".GetFullPathNameW(
                wpath::Cwstring,
                UInt32(length(buf))::UInt32,
                pointer(buf)::Ptr{UInt16},
                C_NULL::Ptr{Ptr{UInt16}},
            )::UInt32
        end
        rc == 0 && _win_throw("GetFullPathNameW")
        return String(transcode(UInt8, buf[1:rc]))
    else
        p = @ccall realpath(path::Cstring, C_NULL::Ptr{UInt8})::Ptr{UInt8}
        p == C_NULL && throw(SystemError("realpath($(repr(path)))", Libc.errno()))
        try
            return unsafe_string(p)
        finally
            Libc.free(p)
        end
    end
end

samefile(a::AbstractString, b::AbstractString) = begin
    sa = stat(a)
    sb = stat(b)
    sa.device == sb.device && sa.inode == sb.inode
end

samefile(a::StatStruct, b::StatStruct) = a.device == b.device && a.inode == b.inode

# -----------------------------------------------------------------------------
# Links
# -----------------------------------------------------------------------------

@static if !_PLATFORM_WINDOWS
    function hardlink(src::AbstractString, dst::AbstractString)::Nothing
        rc = @ccall link(src::Cstring, dst::Cstring)::Cint
        rc == 0 || throw(SystemError("link($(repr(src)) -> $(repr(dst)))", Libc.errno()))
        return nothing
    end

    function symlink(src::AbstractString, dst::AbstractString)::Nothing
        rc = @ccall symlink(src::Cstring, dst::Cstring)::Cint
        rc == 0 || throw(SystemError("symlink($(repr(src)) -> $(repr(dst)))", Libc.errno()))
        return nothing
    end

    function readlink(path::AbstractString)::String
        # Start with a moderate buffer and retry on ENAMETOOLONG.
        buf = Vector{UInt8}(undef, 1024)
        while true
            rc = GC.@preserve buf begin
                @ccall readlink(path::Cstring, pointer(buf)::Ptr{UInt8}, Csize_t(length(buf))::Csize_t)::Cssize_t
            end
            if rc < 0
                err = Libc.errno()
                if err == Libc.ERANGE || err == Libc.ENAMETOOLONG
                    resize!(buf, length(buf) * 2)
                    continue
                end
                throw(SystemError("readlink($(repr(path)))", err))
            end
            n = Int(rc)
            return String(copy(buf[1:n]))
        end
    end
else
    const _SYMBOLIC_LINK_FLAG_DIRECTORY = UInt32(0x00000001)
    const _SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE = UInt32(0x00000002)

    function hardlink(src::AbstractString, dst::AbstractString)::Nothing
        wdst = Base.cwstring(dst)
        wsrc = Base.cwstring(src)
        ok = GC.@preserve wdst wsrc begin
            @ccall "kernel32".CreateHardLinkW(wdst::Cwstring, wsrc::Cwstring, C_NULL::Ptr{Cvoid})::Int32
        end
        ok != 0 || _win_throw("CreateHardLinkW")
        return nothing
    end

    function symlink(src::AbstractString, dst::AbstractString)::Nothing
        wdst = Base.cwstring(dst)
        wsrc = Base.cwstring(src)
        flags = _SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE
        try
            isdir(src) && (flags |= _SYMBOLIC_LINK_FLAG_DIRECTORY)
        catch
        end
        ok = GC.@preserve wdst wsrc begin
            @ccall "kernel32".CreateSymbolicLinkW(wdst::Cwstring, wsrc::Cwstring, flags::UInt32)::Int32
        end
        ok != 0 || _win_throw("CreateSymbolicLinkW")
        return nothing
    end

    function readlink(path::AbstractString)::String
        # Read the reparse-point payload via FSCTL_GET_REPARSE_POINT.
        #
        # Supports:
        # - symlinks (IO_REPARSE_TAG_SYMLINK)
        # - junctions/mount points (IO_REPARSE_TAG_MOUNT_POINT)
        const _FILE_READ_ATTRIBUTES = UInt32(0x00000080)
        const _FILE_SHARE_READ = UInt32(0x00000001)
        const _FILE_SHARE_WRITE = UInt32(0x00000002)
        const _FILE_SHARE_DELETE = UInt32(0x00000004)
        const _OPEN_EXISTING = UInt32(3)
        const _FILE_FLAG_BACKUP_SEMANTICS = UInt32(0x02000000)
        const _FILE_FLAG_OPEN_REPARSE_POINT = UInt32(0x00200000)

        const _FSCTL_GET_REPARSE_POINT = UInt32(0x000900A8)
        const _IO_REPARSE_TAG_SYMLINK = UInt32(0xA000000C)
        const _IO_REPARSE_TAG_MOUNT_POINT = UInt32(0xA0000003)

        wpath = Base.cwstring(path)
        h = GC.@preserve wpath begin
            @ccall "kernel32".CreateFileW(
                wpath::Cwstring,
                _FILE_READ_ATTRIBUTES::UInt32,
                (_FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE)::UInt32,
                C_NULL::Ptr{Cvoid},
                _OPEN_EXISTING::UInt32,
                (_FILE_FLAG_BACKUP_SEMANTICS | _FILE_FLAG_OPEN_REPARSE_POINT)::UInt32,
                C_NULL::Ptr{Cvoid},
            )::Ptr{Cvoid}
        end
        (h == C_NULL || h == _INVALID_HANDLE_VALUE) && _win_throw("CreateFileW")
        try
            buf = Vector{UInt8}(undef, 16 * 1024)
            bytes = Ref{UInt32}(0)
            ok = GC.@preserve buf begin
                @ccall "kernel32".DeviceIoControl(
                    h::Ptr{Cvoid},
                    _FSCTL_GET_REPARSE_POINT::UInt32,
                    C_NULL::Ptr{Cvoid},
                    UInt32(0)::UInt32,
                    pointer(buf)::Ptr{Cvoid},
                    UInt32(length(buf))::UInt32,
                    bytes::Ref{UInt32},
                    C_NULL::Ptr{Cvoid},
                )::Int32
            end
            ok != 0 || _win_throw("DeviceIoControl(FSCTL_GET_REPARSE_POINT)")

            tag = GC.@preserve buf unsafe_load(Ptr{UInt32}(pointer(buf)))
            if tag == _IO_REPARSE_TAG_SYMLINK
                # Header (8 bytes) + symlink fields (12 bytes) => PathBuffer starts at 20 bytes.
                base = 9  # 1-based start of bytes after the 8-byte header
                sub_off = GC.@preserve buf unsafe_load(Ptr{UInt16}(pointer(buf, base)))
                sub_len = GC.@preserve buf unsafe_load(Ptr{UInt16}(pointer(buf, base + 2)))
                pr_off = GC.@preserve buf unsafe_load(Ptr{UInt16}(pointer(buf, base + 4)))
                pr_len = GC.@preserve buf unsafe_load(Ptr{UInt16}(pointer(buf, base + 6)))
                pathbuf = 1 + 8 + 12

                off = pr_len > 0 ? pr_off : sub_off
                len = pr_len > 0 ? pr_len : sub_len
                nchars = Int(len) >>> 1
                start_byte = pathbuf + Int(off) + 1
                u16 = Vector{UInt16}(undef, nchars)
                GC.@preserve buf u16 begin
                    unsafe_copyto!(pointer(u16), Ptr{UInt16}(pointer(buf, start_byte)), nchars)
                end
                s = String(transcode(UInt8, u16))
                startswith(s, "\\\\??\\\\") && (s = s[5:end])
                startswith(s, "\\\\?\\\\") && (s = s[5:end])
                return s
            elseif tag == _IO_REPARSE_TAG_MOUNT_POINT
                # Header (8 bytes) + mount fields (8 bytes) => PathBuffer starts at 16 bytes.
                base = 9
                sub_off = GC.@preserve buf unsafe_load(Ptr{UInt16}(pointer(buf, base)))
                sub_len = GC.@preserve buf unsafe_load(Ptr{UInt16}(pointer(buf, base + 2)))
                pr_off = GC.@preserve buf unsafe_load(Ptr{UInt16}(pointer(buf, base + 4)))
                pr_len = GC.@preserve buf unsafe_load(Ptr{UInt16}(pointer(buf, base + 6)))
                pathbuf = 1 + 8 + 8

                off = pr_len > 0 ? pr_off : sub_off
                len = pr_len > 0 ? pr_len : sub_len
                nchars = Int(len) >>> 1
                start_byte = pathbuf + Int(off) + 1
                u16 = Vector{UInt16}(undef, nchars)
                GC.@preserve buf u16 begin
                    unsafe_copyto!(pointer(u16), Ptr{UInt16}(pointer(buf, start_byte)), nchars)
                end
                s = String(transcode(UInt8, u16))
                startswith(s, "\\\\??\\\\") && (s = s[5:end])
                startswith(s, "\\\\?\\\\") && (s = s[5:end])
                return s
            else
                throw(ErrorException("unsupported reparse tag: $(tag)"))
            end
        finally
            _ = @ccall "kernel32".CloseHandle(h::Ptr{Cvoid})::Int32
        end
    end
end

# -----------------------------------------------------------------------------
# chmod/chown/touch/futime
# -----------------------------------------------------------------------------

@static if !_PLATFORM_WINDOWS
    function chmod(path::AbstractString, mode::Integer)::Nothing
        rc = @ccall chmod(path::Cstring, Cuint(mode)::Cuint)::Cint
        rc == 0 || throw(SystemError("chmod($(repr(path)))", Libc.errno()))
        return nothing
    end

    function chown(path::AbstractString, owner::Integer, group::Integer = -1)::Nothing
        rc = @ccall chown(path::Cstring, Cuint(owner)::Cuint, Cuint(group)::Cuint)::Cint
        rc == 0 || throw(SystemError("chown($(repr(path)))", Libc.errno()))
        return nothing
    end

    @inline function _at_fdcwd()::Cint
        return @static _PLATFORM_APPLE ? Cint(-2) : Cint(-100)
    end

    function touch(path::AbstractString)::Nothing
        # Ensure the file exists.
        try
            open(path, JL_O_WRONLY | JL_O_CREAT | JL_O_CLOEXEC, 0o666) do io
                _ = io
            end
        catch
            # If creation fails, let utimensat throw the real error below.
        end
        rc = @ccall utimensat(_at_fdcwd()::Cint, path::Cstring, C_NULL::Ptr{_Timespec}, Cint(0)::Cint)::Cint
        rc == 0 || throw(SystemError("utimensat($(repr(path)))", Libc.errno()))
        return nothing
    end

    @inline function _seconds_to_timespec(t::Real)::_Timespec
        tf = Float64(t)
        sec = floor(Int64, tf)
        nsec = Int64(round((tf - Float64(sec)) * 1.0e9))
        return _Timespec(Clong(sec), Clong(nsec))
    end

    function futime(path::AbstractString, atime::Real, mtime::Real)::Nothing
        ts = Vector{_Timespec}(undef, 2)
        ts[1] = _seconds_to_timespec(atime)
        ts[2] = _seconds_to_timespec(mtime)
        rc = GC.@preserve ts begin
            @ccall utimensat(_at_fdcwd()::Cint, path::Cstring, pointer(ts)::Ptr{_Timespec}, Cint(0)::Cint)::Cint
        end
        rc == 0 || throw(SystemError("utimensat($(repr(path)))", Libc.errno()))
        return nothing
    end
else
    function chmod(path::AbstractString, mode::Integer)::Nothing
        # Best-effort: map owner write bit to FILE_ATTRIBUTE_READONLY.
        wpath = Base.cwstring(path)
        attrs = GC.@preserve wpath begin
            @ccall "kernel32".GetFileAttributesW(wpath::Cwstring)::UInt32
        end
        attrs == UInt32(0xFFFFFFFF) && _win_throw("GetFileAttributesW")
        readonly = (mode & 0o222) == 0
        if readonly
            attrs |= UInt32(0x00000001)
        else
            attrs &= ~UInt32(0x00000001)
        end
        ok = GC.@preserve wpath begin
            @ccall "kernel32".SetFileAttributesW(wpath::Cwstring, attrs::UInt32)::Int32
        end
        ok != 0 || _win_throw("SetFileAttributesW")
        return nothing
    end

    function chown(path::AbstractString, owner::Integer, group::Integer = -1)::Nothing
        _ = path
        _ = owner
        _ = group
        throw(ErrorException("chown is not supported on Windows"))
    end

    function touch(path::AbstractString)::Nothing
        # Create the file if missing.
        try
            open(path, JL_O_WRONLY | JL_O_CREAT | JL_O_CLOEXEC, 0o666) do io
                _ = io
            end
        catch
        end
        # Update last-write + access times to now.
        const _FILE_WRITE_ATTRIBUTES = UInt32(0x00000100)
        const _OPEN_EXISTING = UInt32(3)
        const _FILE_SHARE_READ = UInt32(0x00000001)
        const _FILE_SHARE_WRITE = UInt32(0x00000002)
        const _FILE_SHARE_DELETE = UInt32(0x00000004)
        const _FILE_ATTRIBUTE_NORMAL = UInt32(0x00000080)

        wpath = Base.cwstring(path)
        h = GC.@preserve wpath begin
            @ccall "kernel32".CreateFileW(
                wpath::Cwstring,
                _FILE_WRITE_ATTRIBUTES::UInt32,
                (_FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE)::UInt32,
                C_NULL::Ptr{Cvoid},
                _OPEN_EXISTING::UInt32,
                _FILE_ATTRIBUTE_NORMAL::UInt32,
                C_NULL::Ptr{Cvoid},
            )::Ptr{Cvoid}
        end
        (h == C_NULL || h == _INVALID_HANDLE_VALUE) && _win_throw("CreateFileW")
        try
            ft = Ref{_FILETIME}()
            @ccall "kernel32".GetSystemTimeAsFileTime(ft::Ref{_FILETIME})::Cvoid
            ok = @ccall "kernel32".SetFileTime(
                h::Ptr{Cvoid},
                C_NULL::Ptr{_FILETIME},
                ft::Ref{_FILETIME},
                ft::Ref{_FILETIME},
            )::Int32
            ok != 0 || _win_throw("SetFileTime")
        finally
            _ = @ccall "kernel32".CloseHandle(h::Ptr{Cvoid})::Int32
        end
        return nothing
    end

    function futime(path::AbstractString, atime::Real, mtime::Real)::Nothing
        const _FILE_WRITE_ATTRIBUTES = UInt32(0x00000100)
        const _OPEN_EXISTING = UInt32(3)
        const _FILE_SHARE_READ = UInt32(0x00000001)
        const _FILE_SHARE_WRITE = UInt32(0x00000002)
        const _FILE_SHARE_DELETE = UInt32(0x00000004)
        const _FILE_ATTRIBUTE_NORMAL = UInt32(0x00000080)
        const _FILE_FLAG_BACKUP_SEMANTICS = UInt32(0x02000000)

        function _unix_seconds_to_filetime(t::Real)::_FILETIME
            tf = Float64(t)
            tf < 0 && (tf = 0.0)
            ticks = UInt64(round(tf * 10_000_000.0)) + UInt64(11644473600) * UInt64(10_000_000)
            return _FILETIME(UInt32(ticks & 0xFFFFFFFF), UInt32((ticks >> 32) & 0xFFFFFFFF))
        end

        wpath = Base.cwstring(path)
        h = GC.@preserve wpath begin
            @ccall "kernel32".CreateFileW(
                wpath::Cwstring,
                _FILE_WRITE_ATTRIBUTES::UInt32,
                (_FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE)::UInt32,
                C_NULL::Ptr{Cvoid},
                _OPEN_EXISTING::UInt32,
                (_FILE_ATTRIBUTE_NORMAL | _FILE_FLAG_BACKUP_SEMANTICS)::UInt32,
                C_NULL::Ptr{Cvoid},
            )::Ptr{Cvoid}
        end
        (h == C_NULL || h == _INVALID_HANDLE_VALUE) && _win_throw("CreateFileW")
        try
            fat = Ref(_unix_seconds_to_filetime(atime))
            fmt = Ref(_unix_seconds_to_filetime(mtime))
            ok = @ccall "kernel32".SetFileTime(
                h::Ptr{Cvoid},
                C_NULL::Ptr{_FILETIME},
                fat::Ref{_FILETIME},
                fmt::Ref{_FILETIME},
            )::Int32
            ok != 0 || _win_throw("SetFileTime")
        finally
            _ = @ccall "kernel32".CloseHandle(h::Ptr{Cvoid})::Int32
        end
        return nothing
    end
end

# -----------------------------------------------------------------------------
# diskstat
# -----------------------------------------------------------------------------

@static if !_PLATFORM_WINDOWS
    @static if _PLATFORM_LINUX
        struct _Statvfs
            f_bsize::Culong
            f_frsize::Culong
            f_blocks::Culong
            f_bfree::Culong
            f_bavail::Culong
            f_files::Culong
            f_ffree::Culong
            f_favail::Culong
            f_fsid::Culong
            f_flag::Culong
            f_namemax::Culong
            __f_spare::NTuple{6, Cint}
        end
    else
        struct _Statvfs
            f_bsize::Culong
            f_frsize::Culong
            f_blocks::UInt32
            f_bfree::UInt32
            f_bavail::UInt32
            f_files::UInt32
            f_ffree::UInt32
            f_favail::UInt32
            f_fsid::Culong
            f_flag::Culong
            f_namemax::Culong
        end
    end

    function diskstat(path::AbstractString)::DiskStat
        buf = Ref{_Statvfs}()
        rc = @ccall statvfs(path::Cstring, buf::Ref{_Statvfs})::Cint
        rc == 0 || throw(SystemError("statvfs($(repr(path)))", Libc.errno()))
        bsize = UInt64(buf[].f_frsize != 0 ? buf[].f_frsize : buf[].f_bsize)
        blocks = UInt64(buf[].f_blocks)
        bfree = UInt64(buf[].f_bfree)
        bavail = UInt64(buf[].f_bavail)
        files = UInt64(buf[].f_files)
        ffree = UInt64(buf[].f_ffree)
        return DiskStat(UInt64(0), bsize, blocks, bfree, bavail, files, ffree, (UInt64(0), UInt64(0), UInt64(0), UInt64(0)))
    end
else
    function diskstat(path::AbstractString)::DiskStat
        wpath = Base.cwstring(path)
        spc = Ref{UInt32}(0)
        bps = Ref{UInt32}(0)
        freec = Ref{UInt32}(0)
        totalc = Ref{UInt32}(0)
        ok = GC.@preserve wpath spc bps freec totalc begin
            @ccall "kernel32".GetDiskFreeSpaceW(
                wpath::Cwstring,
                spc::Ref{UInt32},
                bps::Ref{UInt32},
                freec::Ref{UInt32},
                totalc::Ref{UInt32},
            )::Int32
        end
        ok != 0 || _win_throw("GetDiskFreeSpaceW")
        bsize = UInt64(spc[]) * UInt64(bps[])
        blocks = UInt64(totalc[])
        bfree = UInt64(freec[])
        bavail = bfree
        return DiskStat(UInt64(0), bsize, blocks, bfree, bavail, UInt64(0), UInt64(0), (UInt64(0), UInt64(0), UInt64(0), UInt64(0)))
    end
end

# -----------------------------------------------------------------------------
# Copy helpers (cp / cptree / sendfile fallback)
# -----------------------------------------------------------------------------

function _copy_file(src::AbstractString, dst::AbstractString; mode::Integer = 0o666)::Nothing
    open(src, "r") do r
        open(dst; write = true, create = true, truncate = true, mode = mode) do w
            buf = Vector{UInt8}(undef, 1024 * 1024)
            while true
                # Read up to buf bytes without requiring full buffer.
                n = try
                    Base.readbytes!(r, buf, length(buf))
                catch ex
                    ex isa EOFError ? 0 : rethrow()
                end
                n == 0 && break
                write(w, view(buf, 1:n))
            end
            flush(w)
        end
    end
    return nothing
end

function cp(
        src::AbstractString,
        dst::AbstractString;
        force::Bool = false,
        follow_symlinks::Bool = false,
        preserve::Bool = true,
    )::Nothing
    _ = preserve
    if !force && ispath(dst)
        throw(ArgumentError("destination exists: $(repr(dst))"))
    end
    st = follow_symlinks ? stat(src) : lstat(src)
    if Base.islink(st) && !follow_symlinks
        # Copy symlink as symlink.
        target = readlink(src)
        symlink(target, dst)
        return nothing
    end
    if Base.isdir(st)
        return cptree(src, dst; force = force, follow_symlinks = follow_symlinks, preserve = preserve)
    end
    return _copy_file(src, dst)
end

function cptree(
        src::AbstractString,
        dst::AbstractString;
        force::Bool = false,
        follow_symlinks::Bool = false,
        preserve::Bool = true,
    )::Nothing
    _ = preserve
    if ispath(dst)
        force || throw(ArgumentError("destination exists: $(repr(dst))"))
        rm(dst; force = true, recursive = true)
    end
    mkdir(dst; mode = 0o777)
    for name in readdir(src; join = false, sort = true)
        cp(
            joinpath(src, name),
            joinpath(dst, name);
            force = force,
            follow_symlinks = follow_symlinks,
            preserve = preserve,
        )
    end
    return nothing
end

function sendfile(dst::FileHandle, src::FileHandle, src_offset::Int64, bytes::Integer)
    _require_open(dst)
    _require_open(src)
    seek(src, src_offset)
    remaining = Int64(bytes)
    buf = Vector{UInt8}(undef, min(Int64(1024 * 1024), remaining))
    while remaining > 0
        n = Int(min(remaining, Int64(length(buf))))
        read!(src, view(buf, 1:n))
        write(dst, view(buf, 1:n))
        remaining -= n
    end
    return Int(bytes)
end
