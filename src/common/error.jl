const OP_SUCCESS = 0
const OP_ERR = -1
const AWS_OP_SUCCESS = OP_SUCCESS
const AWS_OP_ERR = OP_ERR

const ERROR_ENUM_STRIDE_BITS = 10
const ERROR_ENUM_STRIDE = 1 << ERROR_ENUM_STRIDE_BITS
ERROR_ENUM_BEGIN_RANGE(x) = x * ERROR_ENUM_STRIDE
ERROR_ENUM_END_RANGE(x) = ((x + 1) * ERROR_ENUM_STRIDE) - 1

const COMMON_PACKAGE_ID = 0

struct ErrorResult
    code::Int
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
const ERROR_UNSUPPORTED_OPERATION = ERROR_SUCCESS + 6
const ERROR_INVALID_BUFFER_SIZE = ERROR_SUCCESS + 7
const ERROR_INVALID_HEX_STR = ERROR_SUCCESS + 8
const ERROR_INVALID_BASE64_STR = ERROR_SUCCESS + 9
const ERROR_INVALID_INDEX = ERROR_SUCCESS + 10
const ERROR_THREAD_INVALID_SETTINGS = ERROR_SUCCESS + 11
const ERROR_THREAD_INSUFFICIENT_RESOURCE = ERROR_SUCCESS + 12
const ERROR_THREAD_NO_PERMISSIONS = ERROR_SUCCESS + 13
const ERROR_THREAD_NOT_JOINABLE = ERROR_SUCCESS + 14
const ERROR_THREAD_NO_SUCH_THREAD_ID = ERROR_SUCCESS + 15
const ERROR_THREAD_DEADLOCK_DETECTED = ERROR_SUCCESS + 16
const ERROR_MUTEX_NOT_INIT = ERROR_SUCCESS + 17
const ERROR_MUTEX_TIMEOUT = ERROR_SUCCESS + 18
const ERROR_MUTEX_CALLER_NOT_OWNER = ERROR_SUCCESS + 19
const ERROR_MUTEX_FAILED = ERROR_SUCCESS + 20
const ERROR_COND_VARIABLE_INIT_FAILED = ERROR_SUCCESS + 21
const ERROR_COND_VARIABLE_TIMED_OUT = ERROR_SUCCESS + 22
const ERROR_COND_VARIABLE_ERROR_UNKNOWN = ERROR_SUCCESS + 23
const ERROR_CLOCK_FAILURE = ERROR_SUCCESS + 24
const ERROR_LIST_EMPTY = ERROR_SUCCESS + 25
const ERROR_DEST_COPY_TOO_SMALL = ERROR_SUCCESS + 26
const ERROR_LIST_EXCEEDS_MAX_SIZE = ERROR_SUCCESS + 27
const ERROR_LIST_STATIC_MODE_CANT_SHRINK = ERROR_SUCCESS + 28
const ERROR_PRIORITY_QUEUE_FULL = ERROR_SUCCESS + 29
const ERROR_PRIORITY_QUEUE_EMPTY = ERROR_SUCCESS + 30
const ERROR_PRIORITY_QUEUE_BAD_NODE = ERROR_SUCCESS + 31
const ERROR_HASHTBL_ITEM_NOT_FOUND = ERROR_SUCCESS + 32
const ERROR_INVALID_DATE_STR = ERROR_SUCCESS + 33
const ERROR_INVALID_ARGUMENT = ERROR_SUCCESS + 34
const ERROR_RANDOM_GEN_FAILED = ERROR_SUCCESS + 35
const ERROR_MALFORMED_INPUT_STRING = ERROR_SUCCESS + 36
const ERROR_UNIMPLEMENTED = ERROR_SUCCESS + 37
const ERROR_INVALID_STATE = ERROR_SUCCESS + 38
const ERROR_ENVIRONMENT_GET = ERROR_SUCCESS + 39
const ERROR_ENVIRONMENT_SET = ERROR_SUCCESS + 40
const ERROR_ENVIRONMENT_UNSET = ERROR_SUCCESS + 41
const ERROR_STREAM_UNSEEKABLE = ERROR_SUCCESS + 42
const ERROR_NO_PERMISSION = ERROR_SUCCESS + 43
const ERROR_FILE_INVALID_PATH = ERROR_SUCCESS + 44
const ERROR_MAX_FDS_EXCEEDED = ERROR_SUCCESS + 45
const ERROR_SYS_CALL_FAILURE = ERROR_SUCCESS + 46
const ERROR_C_STRING_BUFFER_NOT_NULL_TERMINATED = ERROR_SUCCESS + 47
const ERROR_STRING_MATCH_NOT_FOUND = ERROR_SUCCESS + 48
const ERROR_DIVIDE_BY_ZERO = ERROR_SUCCESS + 49
const ERROR_INVALID_FILE_HANDLE = ERROR_SUCCESS + 50
const ERROR_OPERATION_INTERUPTED = ERROR_SUCCESS + 51
const ERROR_DIRECTORY_NOT_EMPTY = ERROR_SUCCESS + 52
const ERROR_PLATFORM_NOT_SUPPORTED = ERROR_SUCCESS + 53
const ERROR_INVALID_UTF8 = ERROR_SUCCESS + 54
const ERROR_GET_HOME_DIRECTORY_FAILED = ERROR_SUCCESS + 55
const ERROR_INVALID_XML = ERROR_SUCCESS + 56
const ERROR_FILE_OPEN_FAILURE = ERROR_SUCCESS + 57
const ERROR_FILE_READ_FAILURE = ERROR_SUCCESS + 58
const ERROR_FILE_WRITE_FAILURE = ERROR_SUCCESS + 59
const ERROR_INVALID_CBOR = ERROR_SUCCESS + 60
const ERROR_CBOR_UNEXPECTED_TYPE = ERROR_SUCCESS + 61
const ERROR_END_COMMON_RANGE = ERROR_ENUM_END_RANGE(COMMON_PACKAGE_ID)

const _last_error = SmallRegistry{UInt64, Int}()

const _thread_handler = SmallRegistry{UInt64, Function}()

const _global_handler = Ref{Union{Nothing, Function}}(nothing)

@inline function _error_thread_key()
    return UInt64(thread_current_thread_id())
end

function last_error()
    return registry_get(_last_error, _error_thread_key(), 0)
end

function _set_last_error(err::Int)
    key = _error_thread_key()
    if err == 0
        registry_delete!(_last_error, key)
    else
        registry_set!(_last_error, key, err)
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

function error_lib_name(err::Int)
    info = get(_error_registry, err, nothing)
    return info === nothing ? _unknown_error_str : info.lib_name
end

function error_debug_str(err::Int)
    info = get(_error_registry, err, nothing)
    return info === nothing ? _unknown_error_str : info.formatted_name
end

function raise_error_private(err::Int)
    _set_last_error(err)
    key = _error_thread_key()
    entry = registry_get(_thread_handler, key, nothing)
    if entry !== nothing
        entry(err)
    elseif _global_handler[] !== nothing
        _global_handler[](err)
    end
    return nothing
end

function raise_error(err::Int)
    raise_error_private(err)
    return OP_ERR
end

function reset_error()
    _set_last_error(0)
    return nothing
end

function restore_error(err::Int)
    _set_last_error(err)
    return nothing
end

function set_global_error_handler(handler)
    old = _global_handler[]
    _global_handler[] = handler
    return old
end

function set_thread_local_error_handler(handler)
    tid = _error_thread_key()
    entry = registry_get(_thread_handler, tid, nothing)
    old = entry === nothing ? nothing : entry
    if handler === nothing
        registry_delete!(_thread_handler, tid)
    else
        registry_set!(_thread_handler, tid, handler)
    end
    return old
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
