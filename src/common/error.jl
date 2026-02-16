const OP_SUCCESS = 0
const OP_ERR = -1

const ERROR_ENUM_STRIDE_BITS = 10
const ERROR_ENUM_STRIDE = 1 << ERROR_ENUM_STRIDE_BITS
ERROR_ENUM_BEGIN_RANGE(x) = x * ERROR_ENUM_STRIDE
ERROR_ENUM_END_RANGE(x) = ((x + 1) * ERROR_ENUM_STRIDE) - 1

const COMMON_PACKAGE_ID = 0

struct ReseauError <: Exception
    code::Int
end

function Base.showerror(io::IO, e::ReseauError)
    info = get(_error_registry, e.code, nothing)
    if info === nothing
        print(io, "ReseauError: unknown error code $(e.code)")
    else
        print(io, "ReseauError: ", info.formatted_name)
    end
end

function throw_error(code::Int)
    raise_error_private(code)
    throw(ReseauError(code))
end

struct ErrorInfo
    literal_name::String
    error_str::String
    lib_name::String
    formatted_name::String
end

const _error_registry = Dict{Int, ErrorInfo}()
const _unknown_error_str = "Unknown Error Code"

function _register_errors!(defs, lib_name::AbstractString)
    for (name, code, msg) in defs
        formatted = string(lib_name, ": ", name, ", ", msg)
        _error_registry[Int(code)] = ErrorInfo(name, msg, lib_name, formatted)
    end
    return nothing
end

const ERROR_SUCCESS = ERROR_ENUM_BEGIN_RANGE(COMMON_PACKAGE_ID)
const ERROR_OOM = ERROR_SUCCESS + 1
const ERROR_NO_SPACE = ERROR_SUCCESS + 2
const ERROR_UNKNOWN = ERROR_SUCCESS + 3
const ERROR_SHORT_BUFFER = ERROR_SUCCESS + 4
const ERROR_OVERFLOW_DETECTED = ERROR_SUCCESS + 5
const ERROR_INVALID_BUFFER_SIZE = ERROR_SUCCESS + 7
const ERROR_THREAD_NO_SUCH_THREAD_ID = ERROR_SUCCESS + 15
const ERROR_COND_VARIABLE_TIMED_OUT = ERROR_SUCCESS + 22
const ERROR_CLOCK_FAILURE = ERROR_SUCCESS + 24
const ERROR_DEST_COPY_TOO_SMALL = ERROR_SUCCESS + 26
const ERROR_INVALID_ARGUMENT = ERROR_SUCCESS + 34
const ERROR_UNIMPLEMENTED = ERROR_SUCCESS + 37
const ERROR_INVALID_STATE = ERROR_SUCCESS + 38
const ERROR_STREAM_UNSEEKABLE = ERROR_SUCCESS + 42
const ERROR_NO_PERMISSION = ERROR_SUCCESS + 43
const ERROR_FILE_INVALID_PATH = ERROR_SUCCESS + 44
const ERROR_MAX_FDS_EXCEEDED = ERROR_SUCCESS + 45
const ERROR_SYS_CALL_FAILURE = ERROR_SUCCESS + 46
const ERROR_STRING_MATCH_NOT_FOUND = ERROR_SUCCESS + 48
const ERROR_INVALID_FILE_HANDLE = ERROR_SUCCESS + 50
const ERROR_DIRECTORY_NOT_EMPTY = ERROR_SUCCESS + 52
const ERROR_PLATFORM_NOT_SUPPORTED = ERROR_SUCCESS + 53
const ERROR_FILE_OPEN_FAILURE = ERROR_SUCCESS + 57
const ERROR_FILE_READ_FAILURE = ERROR_SUCCESS + 58

const _common_error_definitions = (
    ("ERROR_SUCCESS", ERROR_SUCCESS, "Success."),
    ("ERROR_OOM", ERROR_OOM, "Out of memory."),
    ("ERROR_NO_SPACE", ERROR_NO_SPACE, "Out of space on disk."),
    ("ERROR_UNKNOWN", ERROR_UNKNOWN, "Unknown error."),
    ("ERROR_SHORT_BUFFER", ERROR_SHORT_BUFFER, "Buffer is not large enough to hold result."),
    ("ERROR_OVERFLOW_DETECTED", ERROR_OVERFLOW_DETECTED, "Fixed size value overflow was detected."),
    ("ERROR_INVALID_BUFFER_SIZE", ERROR_INVALID_BUFFER_SIZE, "Invalid buffer size."),
    ("ERROR_THREAD_NO_SUCH_THREAD_ID", ERROR_THREAD_NO_SUCH_THREAD_ID, "No such thread ID."),
    ("ERROR_COND_VARIABLE_TIMED_OUT", ERROR_COND_VARIABLE_TIMED_OUT, "Condition variable wait timed out."),
    ("ERROR_CLOCK_FAILURE", ERROR_CLOCK_FAILURE, "Clock operation failed."),
    ("ERROR_DEST_COPY_TOO_SMALL", ERROR_DEST_COPY_TOO_SMALL, "Destination of copy is too small."),
    ("ERROR_INVALID_ARGUMENT", ERROR_INVALID_ARGUMENT, "An invalid argument was passed to a function."),
    ("ERROR_UNIMPLEMENTED", ERROR_UNIMPLEMENTED, "A function was called, but is not implemented."),
    ("ERROR_INVALID_STATE", ERROR_INVALID_STATE, "An invalid state was encountered."),
    ("ERROR_STREAM_UNSEEKABLE", ERROR_STREAM_UNSEEKABLE, "Stream does not support seek operations."),
    ("ERROR_NO_PERMISSION", ERROR_NO_PERMISSION, "User does not have permission to perform the requested action."),
    ("ERROR_FILE_INVALID_PATH", ERROR_FILE_INVALID_PATH, "Invalid file path."),
    ("ERROR_MAX_FDS_EXCEEDED", ERROR_MAX_FDS_EXCEEDED, "The maximum number of fds has been exceeded."),
    ("ERROR_SYS_CALL_FAILURE", ERROR_SYS_CALL_FAILURE, "System call failure."),
    ("ERROR_STRING_MATCH_NOT_FOUND", ERROR_STRING_MATCH_NOT_FOUND, "The specified substring was not present in the input string."),
    ("ERROR_INVALID_FILE_HANDLE", ERROR_INVALID_FILE_HANDLE, "Invalid file handle."),
    ("ERROR_DIRECTORY_NOT_EMPTY", ERROR_DIRECTORY_NOT_EMPTY, "An operation on a directory was attempted which is not allowed when the directory is not empty."),
    ("ERROR_PLATFORM_NOT_SUPPORTED", ERROR_PLATFORM_NOT_SUPPORTED, "Feature not supported on this platform."),
    ("ERROR_FILE_OPEN_FAILURE", ERROR_FILE_OPEN_FAILURE, "Failed opening file."),
    ("ERROR_FILE_READ_FAILURE", ERROR_FILE_READ_FAILURE, "Failed reading from file."),
)

# Register common errors at module load time
_register_errors!(_common_error_definitions, "aws-c-common")

const _error_lock = ReentrantLock()
const _last_error = Dict{UInt64, Int}()

@inline function _error_thread_key()
    return UInt64(Base.Threads.threadid())
end

function last_error()
    key = _error_thread_key()
    lock(_error_lock)
    try
        return get(_last_error, key, 0)
    finally
        unlock(_error_lock)
    end
end

function _set_last_error(err::Int)
    key = _error_thread_key()
    lock(_error_lock)
    try
        if err == 0
            delete!(_last_error, key)
        else
            _last_error[key] = err
        end
    finally
        unlock(_error_lock)
    end
    return nothing
end

function error_str(err::Int)
    info = get(_error_registry, err, nothing)
    return info === nothing ? _unknown_error_str : info.error_str
end

function error_name(err::Int)
    info = get(_error_registry, err, nothing)
    return info === nothing ? _unknown_error_str : info.literal_name
end

function raise_error_private(err::Int)
    _set_last_error(err)
    return nothing
end

function raise_error(err::Int)
    raise_error_private(err)
    return OP_ERR
end

function translate_and_raise_io_error_or(error_no::Integer, fallback_error_code::Integer)
    error_no_i = Int(error_no)
    fallback_i = Int(fallback_error_code)
    if error_no_i == Libc.EINVAL
        if fallback_i != ERROR_SYS_CALL_FAILURE
            return raise_error(fallback_i)
        else
            return raise_error(ERROR_INVALID_ARGUMENT)
        end
    elseif error_no_i == Libc.EPERM || error_no_i == Libc.EACCES
        return raise_error(ERROR_NO_PERMISSION)
    elseif error_no_i == Libc.EISDIR || error_no_i == Libc.ENAMETOOLONG || error_no_i == Libc.ENOENT || error_no_i == Libc.ENOTDIR
        return raise_error(ERROR_FILE_INVALID_PATH)
    elseif error_no_i == Libc.EMFILE || error_no_i == Libc.ENFILE
        return raise_error(ERROR_MAX_FDS_EXCEEDED)
    elseif error_no_i == Libc.ENOMEM
        return raise_error(ERROR_OOM)
    elseif error_no_i == Libc.ENOSPC
        return raise_error(ERROR_NO_SPACE)
    elseif error_no_i == Libc.ENOTEMPTY
        return raise_error(ERROR_DIRECTORY_NOT_EMPTY)
    else
        return raise_error(fallback_i)
    end
end

function translate_and_raise_io_error(error_no::Integer)
    return translate_and_raise_io_error_or(error_no, ERROR_SYS_CALL_FAILURE)
end
