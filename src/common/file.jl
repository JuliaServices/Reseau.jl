const FILE_TYPE_FILE = 1
const FILE_TYPE_SYM_LINK = 2
const FILE_TYPE_DIRECTORY = 4

const _FILE_READ_MODE = "rb"
const _MIN_BUFFER_GROWTH_READING_FILES = 32
const _MAX_BUFFER_GROWTH_READING_FILES = 4096

const PATH_DELIM = _PLATFORM_WINDOWS ? UInt8('\\') : UInt8('/')
const PATH_DELIM_STR = _PLATFORM_WINDOWS ? "\\" : "/"

@inline function _c_str_is_empty(c_str::Ptr{UInt8})
    return c_str == C_NULL || unsafe_load(c_str) == 0x00
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
            fd = @static if _PLATFORM_WINDOWS
                ccall(:_fileno, Cint, (Ptr{Cvoid},), file.ptr)
            else
                ccall(:fileno, Cint, (Ptr{Cvoid},), file.ptr)
            end
            if fd == -1
                raise_error(ERROR_INVALID_FILE_HANDLE)
                return OP_ERR
            end

            st = try
                stat(RawFD(fd))
            catch
                err = Libc.errno()
                translate_and_raise_io_error_or(err, ERROR_FILE_READ_FAILURE)
                return OP_ERR
            end

            len64 = filesize(st)
            if len64 >= SIZE_MAX
                raise_error(ERROR_OVERFLOW_DETECTED)
                return OP_ERR
            end
            size_hint = len64 + 1
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
    home = homedir()
    return string_new_from_c_str(home)
end
