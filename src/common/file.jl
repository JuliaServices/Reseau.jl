const FILE_TYPE_FILE = 1
const FILE_TYPE_SYM_LINK = 2
const FILE_TYPE_DIRECTORY = 4

const _FILE_READ_MODE = "rb"
const _FILE_WRITE_MODE = "wb"
const _FILE_APPEND_MODE = "ab"
const _MIN_BUFFER_GROWTH_READING_FILES = 32
const _MAX_BUFFER_GROWTH_READING_FILES = 4096

const PATH_DELIM = _PLATFORM_WINDOWS ? UInt8('\\') : UInt8('/')
const PATH_DELIM_STR = _PLATFORM_WINDOWS ? "\\" : "/"

# POSIX fseek/ftell whence values.
const _SEEK_SET = Cint(0)
const _SEEK_END = Cint(2)

@static if _PLATFORM_WINDOWS
    const _WIN_FILE_ATTRIBUTE_DIRECTORY = UInt32(0x10)
    const _WIN_INVALID_FILE_ATTRIBUTES = UInt32(0xffffffff)
    const _WIN_CRT_LIBS = ("ucrtbase", "msvcrt")

    @inline function _win_crt_ccall(sym::Symbol, rettype::Type, argtypes::Tuple, args...)
        # Windows CRT functions may not be imported into the Julia binary. Prefer the CRT dlls
        # explicitly, falling back to the default search if needed.
        for lib in _WIN_CRT_LIBS
            try
                return ccall((sym, lib), rettype, argtypes, args...)
            catch err
                if err isa ErrorException
                    msg = err.msg
                    if occursin("could not load", msg) || occursin("could not find", msg)
                        continue
                    end
                end
                rethrow()
            end
        end
        return ccall(sym, rettype, argtypes, args...)
    end
end

@inline function _c_str_is_empty(c_str::Ptr{UInt8})
    return c_str == C_NULL || unsafe_load(c_str) == 0x00
end

@inline function _getenv_string(name::AbstractString)::Union{Nothing, String}
    ptr = ccall(:getenv, Ptr{UInt8}, (Cstring,), name)
    if ptr == C_NULL || unsafe_load(ptr) == 0x00
        return nothing
    end
    return unsafe_string(ptr)
end

function _fs_file_length(file::Libc.FILE)::Union{Int64, Nothing}
    @static if _PLATFORM_WINDOWS
        try
            pos = _win_crt_ccall(:_ftelli64, Int64, (Ptr{Cvoid},), file.ptr)
            pos < 0 && return nothing
            _win_crt_ccall(:_fseeki64, Cint, (Ptr{Cvoid}, Int64, Cint), file.ptr, 0, _SEEK_END) == 0 || return nothing
            len = _win_crt_ccall(:_ftelli64, Int64, (Ptr{Cvoid},), file.ptr)
            _ = _win_crt_ccall(:_fseeki64, Cint, (Ptr{Cvoid}, Int64, Cint), file.ptr, pos, _SEEK_SET)
            len < 0 && return nothing
            return len
        catch err
            if err isa ErrorException && occursin("could not load", err.msg)
                return nothing
            end
            rethrow()
        end
    else
        pos = ccall(:ftello, Int64, (Ptr{Cvoid},), file.ptr)
        pos < 0 && return nothing
        ccall(:fseeko, Cint, (Ptr{Cvoid}, Int64, Cint), file.ptr, 0, _SEEK_END) == 0 || return nothing
        len = ccall(:ftello, Int64, (Ptr{Cvoid},), file.ptr)
        _ = ccall(:fseeko, Cint, (Ptr{Cvoid}, Int64, Cint), file.ptr, pos, _SEEK_SET)
        len < 0 && return nothing
        return len
    end
end

function byte_buf_init_from_file(out_buf::Base.RefValue{<:ByteBuffer}, filename::Ptr{UInt8})
    if _c_str_is_empty(filename)
        return raise_error(ERROR_FILE_INVALID_PATH)
    end
    name = unsafe_string(filename)
    return byte_buf_init_from_file(out_buf, name)
end

function byte_buf_init_from_file(out_buf::Base.RefValue{<:ByteBuffer}, filename::AbstractString)
    return _byte_buf_init_from_file_impl(out_buf, filename, true, 0)
end

function byte_buf_init_from_file_with_size_hint(
        out_buf::Base.RefValue{<:ByteBuffer},
        filename::Ptr{UInt8},
        _size_hint::Integer,
    )
    return byte_buf_init_from_file(out_buf, filename)
end

function byte_buf_init_from_file_with_size_hint(
        out_buf::Base.RefValue{<:ByteBuffer},
        filename::AbstractString,
        _size_hint::Integer,
    )
    return _byte_buf_init_from_file_impl(out_buf, filename, false, _size_hint)
end

function _byte_buf_init_from_file_impl(
        out_buf::Base.RefValue{<:ByteBuffer},
        filename::AbstractString,
        use_file_size_as_hint::Bool,
        size_hint::Integer,
    )
    if isempty(filename)
        raise_error(ERROR_FILE_INVALID_PATH)
        return OP_ERR
    end

    file_ptr = ccall(:fopen, Ptr{Cvoid}, (Cstring, Cstring), filename, _FILE_READ_MODE)
    if file_ptr == C_NULL
        err = Libc.errno()
        translate_and_raise_io_error_or(err, ERROR_FILE_OPEN_FAILURE)
        return OP_ERR
    end

    file = Libc.FILE(file_ptr)
    try
        if use_file_size_as_hint
            len64 = _fs_file_length(file)
            if len64 !== nothing
                if len64 >= 0 && UInt64(len64) >= UInt64(SIZE_MAX)
                    raise_error(ERROR_OVERFLOW_DETECTED)
                    return OP_ERR
                end
                size_hint = len64 + 1
            end
        end

        if byte_buf_init(out_buf, size_hint) != OP_SUCCESS
            return OP_ERR
        end

        while true
            buf = out_buf[]
            if buf.len == buf.capacity
                additional_capacity = max_size(Csize_t(_MIN_BUFFER_GROWTH_READING_FILES), buf.capacity)
                additional_capacity = min_size(additional_capacity, Csize_t(_MAX_BUFFER_GROWTH_READING_FILES))
                if byte_buf_reserve_relative(out_buf, additional_capacity) != OP_SUCCESS
                    raise_error(ERROR_OOM)
                    return OP_ERR
                end
            end

            buf = out_buf[]
            space_available = buf.capacity - buf.len
            bytes_read = Csize_t(0)
            GC.@preserve buf file begin
                dest_ptr = pointer(buf.mem) + Int(buf.len)
                bytes_read = ccall(
                    :fread,
                    Csize_t,
                    (Ptr{Cvoid}, Csize_t, Csize_t, Ptr{Cvoid}),
                    dest_ptr,
                    1,
                    space_available,
                    file.ptr,
                )
            end

            buf.len += bytes_read

            if ccall(:feof, Cint, (Ptr{Cvoid},), file.ptr) != 0
                break
            end

            if bytes_read == 0
                err = ccall(:ferror, Cint, (Ptr{Cvoid},), file.ptr) != 0 ? Libc.errno() : 0
                translate_and_raise_io_error_or(err, ERROR_FILE_READ_FAILURE)
                return OP_ERR
            end
        end

        buf = out_buf[]
        if buf.len == buf.capacity
            if byte_buf_reserve_relative(out_buf, 1) != OP_SUCCESS
                raise_error(ERROR_OOM)
                return OP_ERR
            end
        end

        buf = out_buf[]
        if length(buf.mem) > 0
            buf.mem[Int(buf.len) + 1] = 0x00
        end
        return OP_SUCCESS
    finally
        try
            close(file)
        catch
        end
    end
end

function get_home_directory()
    home = @static if _PLATFORM_WINDOWS
        something(
            _getenv_string("USERPROFILE"),
            let drive = _getenv_string("HOMEDRIVE"), path = _getenv_string("HOMEPATH")
                (drive !== nothing && path !== nothing) ? string(drive, path) : nothing
            end,
        )
    else
        _getenv_string("HOME")
    end
    if home === nothing || isempty(home)
        raise_error(ERROR_GET_HOME_DIRECTORY_FAILED)
        return string_new_from_array(Ptr{UInt8}(0), 0)
    end
    return string_new_from_c_str(home)
end

function get_temp_directory()::String
    @static if _PLATFORM_WINDOWS
        tmp = something(_getenv_string("TMP"), _getenv_string("TEMP"), nothing)
        if tmp !== nothing && !isempty(tmp)
            return tmp
        end
        # Best-effort fallback.
        return "C:\\\\Windows\\\\Temp"
    else
        tmp = something(_getenv_string("TMPDIR"), _getenv_string("TMP"), _getenv_string("TEMP"), nothing)
        if tmp !== nothing && !isempty(tmp)
            return tmp
        end
        return "/tmp"
    end
end

function tempname(dir::AbstractString = get_temp_directory())::String
    base = isempty(dir) ? "." : dir
    # Avoid a leading '.' in the filename (some tooling treats it as hidden).
    hex = string(rand(UInt128); base = 16)
    return joinpath(base, string("tmp-", hex))
end

function fs_isdir(path::AbstractString)::Bool
    @static if _PLATFORM_WINDOWS
        attrs = ccall((:GetFileAttributesW, "kernel32"), UInt32, (Cwstring,), path)
        attrs == _WIN_INVALID_FILE_ATTRIBUTES && return false
        return (attrs & _WIN_FILE_ATTRIBUTE_DIRECTORY) != 0
    else
        dirp = ccall(:opendir, Ptr{Cvoid}, (Cstring,), path)
        dirp == C_NULL && return false
        _ = ccall(:closedir, Cint, (Ptr{Cvoid},), dirp)
        return true
    end
end

function fs_open_write(path::AbstractString)::Union{Libc.FILE, ErrorResult}
    file_ptr = ccall(:fopen, Ptr{Cvoid}, (Cstring, Cstring), path, _FILE_WRITE_MODE)
    if file_ptr == C_NULL
        err = Libc.errno()
        translate_and_raise_io_error_or(err, ERROR_FILE_OPEN_FAILURE)
        return ErrorResult(last_error())
    end
    return Libc.FILE(file_ptr)
end

function fs_open_append(path::AbstractString)::Union{Libc.FILE, ErrorResult}
    file_ptr = ccall(:fopen, Ptr{Cvoid}, (Cstring, Cstring), path, _FILE_APPEND_MODE)
    if file_ptr == C_NULL
        err = Libc.errno()
        translate_and_raise_io_error_or(err, ERROR_FILE_OPEN_FAILURE)
        return ErrorResult(last_error())
    end
    return Libc.FILE(file_ptr)
end

function fs_write(file::Libc.FILE, data::AbstractVector{UInt8})::Union{Int, ErrorResult}
    len = length(data)
    len == 0 && return 0
    wrote = GC.@preserve data file begin
        ccall(
            :fwrite,
            Csize_t,
            (Ptr{Cvoid}, Csize_t, Csize_t, Ptr{Cvoid}),
            pointer(data),
            1,
            len,
            file.ptr,
        )
    end
    if wrote != len
        err = ccall(:ferror, Cint, (Ptr{Cvoid},), file.ptr) != 0 ? Libc.errno() : 0
        translate_and_raise_io_error_or(err, ERROR_FILE_WRITE_FAILURE)
        return ErrorResult(last_error())
    end
    return Int(wrote)
end

function fs_write(file::Libc.FILE, s::AbstractString)::Union{Int, ErrorResult}
    bytes = codeunits(s)
    GC.@preserve bytes begin
        return fs_write(file, bytes)
    end
end

function fs_flush(file::Libc.FILE)::Union{Nothing, ErrorResult}
    ret = ccall(:fflush, Cint, (Ptr{Cvoid},), file.ptr)
    if ret != 0
        err = Libc.errno()
        translate_and_raise_io_error_or(err, ERROR_FILE_WRITE_FAILURE)
        return ErrorResult(last_error())
    end
    return nothing
end
