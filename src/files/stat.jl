# stat/lstat/fstat implemented without libuv.
#
# We return `Base.StatStruct` for maximum drop-in compatibility with Base helpers
# like `isfile(::StatStruct)` and `filemode(::StatStruct)`.

using ..Reseau: _PLATFORM_WINDOWS, _PLATFORM_LINUX, _PLATFORM_APPLE

const StatStruct = Base.StatStruct
const DiskStat = Base.Filesystem.DiskStat

struct _Timespec
    tv_sec::Clong
    tv_nsec::Clong
end

@inline function _timespec_to_unix_seconds(ts::_Timespec)::Float64
    return Float64(ts.tv_sec) + (Float64(ts.tv_nsec) / 1.0e9)
end

@static if !_PLATFORM_WINDOWS
    @static if _PLATFORM_LINUX
        # glibc linux 64-bit `struct stat` layout (x86_64/aarch64).
        struct _Stat
            st_dev::UInt64
            st_ino::UInt64
            st_nlink::UInt64
            st_mode::UInt32
            st_uid::UInt32
            st_gid::UInt32
            __pad0::Int32
            st_rdev::UInt64
            st_size::Int64
            st_blksize::Int64
            st_blocks::Int64
            st_atim::_Timespec
            st_mtim::_Timespec
            st_ctim::_Timespec
            __glibc_reserved::NTuple{3, Int64}
        end

        @inline function _stat_to_statstruct(desc, st::_Stat)::StatStruct
            mode = UInt(st.st_mode)
            return StatStruct(
                desc,
                UInt(st.st_dev),
                UInt(st.st_ino),
                mode,
                Int(st.st_nlink),
                UInt(st.st_uid),
                UInt(st.st_gid),
                UInt(st.st_rdev),
                Int64(st.st_size),
                Int64(st.st_blksize),
                Int64(st.st_blocks),
                _timespec_to_unix_seconds(st.st_mtim),
                _timespec_to_unix_seconds(st.st_ctim),
                Int32(0),
            )
        end
    else
        # Darwin/BSD 64-bit inode `struct stat` layout (see sys/stat.h __DARWIN_STRUCT_STAT64).
        struct _Stat
            st_dev::Int32
            st_mode::UInt16
            st_nlink::UInt16
            st_ino::UInt64
            st_uid::UInt32
            st_gid::UInt32
            st_rdev::Int32
            __pad1::Int32
            st_atimespec::_Timespec
            st_mtimespec::_Timespec
            st_ctimespec::_Timespec
            st_birthtimespec::_Timespec
            st_size::Int64
            st_blocks::Int64
            st_blksize::Int32
            st_flags::UInt32
            st_gen::UInt32
            st_lspare::Int32
            st_qspare::NTuple{2, Int64}
        end

        @inline function _stat_to_statstruct(desc, st::_Stat)::StatStruct
            mode = UInt(st.st_mode)
            return StatStruct(
                desc,
                UInt(UInt32(st.st_dev)),
                UInt(st.st_ino),
                mode,
                Int(st.st_nlink),
                UInt(st.st_uid),
                UInt(st.st_gid),
                UInt(UInt32(st.st_rdev)),
                Int64(st.st_size),
                Int64(st.st_blksize),
                Int64(st.st_blocks),
                _timespec_to_unix_seconds(st.st_mtimespec),
                _timespec_to_unix_seconds(st.st_ctimespec),
                Int32(0),
            )
        end
    end

    function stat(path::AbstractString)::StatStruct
        st = Ref{_Stat}()
        rc = @ccall stat(path::Cstring, st::Ref{_Stat})::Cint
        rc == 0 || throw(SystemError("stat($(repr(path)))", Libc.errno()))
        return _stat_to_statstruct(String(path), st[])
    end

    function lstat(path::AbstractString)::StatStruct
        st = Ref{_Stat}()
        rc = @ccall lstat(path::Cstring, st::Ref{_Stat})::Cint
        rc == 0 || throw(SystemError("lstat($(repr(path)))", Libc.errno()))
        return _stat_to_statstruct(String(path), st[])
    end

    function fstat(f::FileHandle)::StatStruct
        _require_open(f)
        st = Ref{_Stat}()
        rc = @ccall fstat(f.fd::Cint, st::Ref{_Stat})::Cint
        rc == 0 || throw(SystemError("fstat", Libc.errno()))
        return _stat_to_statstruct(Base.RawFD(f.fd), st[])
    end
else
    # Windows stat implemented via CreateFileW + GetFileInformationByHandle.
    const _FILE_READ_ATTRIBUTES = UInt32(0x00000080)
    const _FILE_SHARE_READ = UInt32(0x00000001)
    const _FILE_SHARE_WRITE = UInt32(0x00000002)
    const _FILE_SHARE_DELETE = UInt32(0x00000004)
    const _OPEN_EXISTING = UInt32(3)
    const _FILE_FLAG_BACKUP_SEMANTICS = UInt32(0x02000000)
    const _FILE_FLAG_OPEN_REPARSE_POINT = UInt32(0x00200000)
    const _FILE_ATTRIBUTE_DIRECTORY = UInt32(0x00000010)
    const _FILE_ATTRIBUTE_REPARSE_POINT = UInt32(0x00000400)
    const _FILE_ATTRIBUTE_READONLY = UInt32(0x00000001)

    struct _BY_HANDLE_FILE_INFORMATION
        dwFileAttributes::UInt32
        ftCreationTime::_FILETIME
        ftLastAccessTime::_FILETIME
        ftLastWriteTime::_FILETIME
        dwVolumeSerialNumber::UInt32
        nFileSizeHigh::UInt32
        nFileSizeLow::UInt32
        nNumberOfLinks::UInt32
        nFileIndexHigh::UInt32
        nFileIndexLow::UInt32
    end

    @inline function _filetime_to_unix_seconds(ft::_FILETIME)::Float64
        # FILETIME is 100ns intervals since 1601-01-01.
        ticks = (UInt64(ft.dwHighDateTime) << 32) | UInt64(ft.dwLowDateTime)
        # Convert to seconds since Unix epoch.
        unix_100ns = ticks - UInt64(11644473600) * UInt64(10_000_000)
        return Float64(unix_100ns) / 1.0e7
    end

    function _win_open_for_stat(path::AbstractString; follow_symlinks::Bool)::Ptr{Cvoid}
        access = _FILE_READ_ATTRIBUTES
        share = _FILE_SHARE_READ | _FILE_SHARE_WRITE | _FILE_SHARE_DELETE
        flags = _FILE_FLAG_BACKUP_SEMANTICS
        follow_symlinks || (flags |= _FILE_FLAG_OPEN_REPARSE_POINT)
        wpath = Base.cwstring(path)
        h = GC.@preserve wpath begin
            @ccall "kernel32".CreateFileW(
                wpath::Cwstring,
                access::UInt32,
                share::UInt32,
                C_NULL::Ptr{Cvoid},
                _OPEN_EXISTING::UInt32,
                flags::UInt32,
                C_NULL::Ptr{Cvoid},
            )::Ptr{Cvoid}
        end
        (h == C_NULL || h == _INVALID_HANDLE_VALUE) && _win_throw("CreateFileW")
        return h
    end

    function _win_close_handle(h::Ptr{Cvoid})::Nothing
        ok = @ccall gc_safe = true "kernel32".CloseHandle(h::Ptr{Cvoid})::Int32
        ok != 0 || _win_throw("CloseHandle")
        return nothing
    end

    function _win_get_file_info(h::Ptr{Cvoid})::_BY_HANDLE_FILE_INFORMATION
        info = Ref{_BY_HANDLE_FILE_INFORMATION}()
        ok = @ccall "kernel32".GetFileInformationByHandle(
            h::Ptr{Cvoid},
            info::Ref{_BY_HANDLE_FILE_INFORMATION},
        )::Int32
        ok != 0 || _win_throw("GetFileInformationByHandle")
        return info[]
    end

    @inline function _win_mode_from_attrs(attrs::UInt32)::UInt
        # Base exposes POSIX-style mode bits; approximate with file/dir + readonly.
        isdir = (attrs & _FILE_ATTRIBUTE_DIRECTORY) != 0
        readonly = (attrs & _FILE_ATTRIBUTE_READONLY) != 0
        # Default to 0o777 for directories and 0o666 for files; remove write bit if readonly.
        perm = isdir ? UInt(0o777) : UInt(0o666)
        readonly && (perm &= ~UInt(0o222))
        ftype = isdir ? UInt(S_IFDIR) : UInt(S_IFREG)
        # Best-effort: treat reparse points as symlinks for lstat-like calls.
        if (attrs & _FILE_ATTRIBUTE_REPARSE_POINT) != 0
            ftype = UInt(S_IFLNK)
        end
        return ftype | perm
    end

    function _win_info_to_statstruct(desc, info::_BY_HANDLE_FILE_INFORMATION)::StatStruct
        size = (UInt64(info.nFileSizeHigh) << 32) | UInt64(info.nFileSizeLow)
        inode = (UInt64(info.nFileIndexHigh) << 32) | UInt64(info.nFileIndexLow)
        mode = _win_mode_from_attrs(info.dwFileAttributes)
        return StatStruct(
            desc,
            UInt(info.dwVolumeSerialNumber),
            UInt(inode),
            UInt(mode),
            Int(info.nNumberOfLinks),
            UInt(0),
            UInt(0),
            UInt(0),
            Int64(size),
            Int64(0),
            Int64(0),
            _filetime_to_unix_seconds(info.ftLastWriteTime),
            _filetime_to_unix_seconds(info.ftCreationTime),
            Int32(0),
        )
    end

    function stat(path::AbstractString)::StatStruct
        h = _win_open_for_stat(path; follow_symlinks = true)
        try
            info = _win_get_file_info(h)
            return _win_info_to_statstruct(String(path), info)
        finally
            _win_close_handle(h)
        end
    end

    function lstat(path::AbstractString)::StatStruct
        h = _win_open_for_stat(path; follow_symlinks = false)
        try
            info = _win_get_file_info(h)
            return _win_info_to_statstruct(String(path), info)
        finally
            _win_close_handle(h)
        end
    end

    function fstat(f::FileHandle)::StatStruct
        _require_open(f)
        info = _win_get_file_info(f.handle)
        return _win_info_to_statstruct(Base.RawFD(-1), info)
    end
end

# Convenience helpers (namespaced; do not call Base.*(path...) variants).
filesize(path::AbstractString) = stat(path).size
filemode(path::AbstractString) = Base.filemode(stat(path))
mtime(path::AbstractString) = stat(path).mtime
ctime(path::AbstractString) = stat(path).ctime

ispath(path::AbstractString) = try
    stat(path)
    true
catch
    false
end

# mode predicate methods for `StatStruct`
ispath(st::StatStruct) = Base.filemode(st) != 0
isdir(st::StatStruct) = (Base.filemode(st) & S_IFMT) == S_IFDIR
isfile(st::StatStruct) = (Base.filemode(st) & S_IFMT) == S_IFREG
islink(st::StatStruct) = (Base.filemode(st) & S_IFMT) == S_IFLNK
isfifo(st::StatStruct) = (Base.filemode(st) & S_IFMT) == S_IFIFO
issocket(st::StatStruct) = (Base.filemode(st) & S_IFMT) == S_IFSOCK
isblockdev(st::StatStruct) = (Base.filemode(st) & S_IFMT) == S_IFBLK
ischardev(st::StatStruct) = (Base.filemode(st) & S_IFMT) == S_IFCHR

issetuid(st::StatStruct) = (Base.filemode(st) & S_ISUID) != 0
issetgid(st::StatStruct) = (Base.filemode(st) & S_ISGID) != 0
issticky(st::StatStruct) = (Base.filemode(st) & S_ISVTX) != 0

uperm(st::StatStruct) = UInt8((Base.filemode(st) >> 6) & 0x7)
gperm(st::StatStruct) = UInt8((Base.filemode(st) >> 3) & 0x7)
operm(st::StatStruct) = UInt8((Base.filemode(st)) & 0x7)

# mode predicate methods for file names
for f in Symbol[
    :ispath,
    :isfifo,
    :ischardev,
    :isdir,
    :isblockdev,
    :isfile,
    :issocket,
    :issetuid,
    :issetgid,
    :issticky,
    :uperm,
    :gperm,
    :operm,
    :filemode,
    :filesize,
    :mtime,
    :ctime,
]
    @eval ($f)(path...) = ($f)(stat(path...))
end

islink(path...) = islink(lstat(path...))

function ismount(path...)::Bool
    p = joinpath(path...)
    isdir(p) || return false
    s1 = lstat(p)
    islink(s1) && return false
    parent_path = joinpath(p, "..")
    s2 = lstat(parent_path)
    (s1.device != s2.device) && return true
    (s1.inode == s2.inode) && return true
    return false
end
