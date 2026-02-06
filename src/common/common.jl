const _common_error_definitions = [
    ("ERROR_SUCCESS", ERROR_SUCCESS, "Success."),
    ("ERROR_OOM", ERROR_OOM, "Out of memory."),
    ("ERROR_NO_SPACE", ERROR_NO_SPACE, "Out of space on disk."),
    ("ERROR_UNKNOWN", ERROR_UNKNOWN, "Unknown error."),
    ("ERROR_SHORT_BUFFER", ERROR_SHORT_BUFFER, "Buffer is not large enough to hold result."),
    ("ERROR_OVERFLOW_DETECTED", ERROR_OVERFLOW_DETECTED, "Fixed size value overflow was detected."),
    ("ERROR_UNSUPPORTED_OPERATION", ERROR_UNSUPPORTED_OPERATION, "Unsupported operation."),
    ("ERROR_INVALID_BUFFER_SIZE", ERROR_INVALID_BUFFER_SIZE, "Invalid buffer size."),
    ("ERROR_INVALID_HEX_STR", ERROR_INVALID_HEX_STR, "Invalid hex string."),
    ("ERROR_INVALID_BASE64_STR", ERROR_INVALID_BASE64_STR, "Invalid base64 string."),
    ("ERROR_INVALID_INDEX", ERROR_INVALID_INDEX, "Invalid index for list access."),
    ("ERROR_THREAD_INVALID_SETTINGS", ERROR_THREAD_INVALID_SETTINGS, "Invalid thread settings."),
    ("ERROR_THREAD_INSUFFICIENT_RESOURCE", ERROR_THREAD_INSUFFICIENT_RESOURCE, "Insufficent resources for thread."),
    ("ERROR_THREAD_NO_PERMISSIONS", ERROR_THREAD_NO_PERMISSIONS, "Insufficient permissions for thread operation."),
    ("ERROR_THREAD_NOT_JOINABLE", ERROR_THREAD_NOT_JOINABLE, "Thread not joinable."),
    ("ERROR_THREAD_NO_SUCH_THREAD_ID", ERROR_THREAD_NO_SUCH_THREAD_ID, "No such thread ID."),
    ("ERROR_THREAD_DEADLOCK_DETECTED", ERROR_THREAD_DEADLOCK_DETECTED, "Deadlock detected in thread."),
    ("ERROR_MUTEX_NOT_INIT", ERROR_MUTEX_NOT_INIT, "Mutex not initialized."),
    ("ERROR_MUTEX_TIMEOUT", ERROR_MUTEX_TIMEOUT, "Mutex operation timed out."),
    ("ERROR_MUTEX_CALLER_NOT_OWNER", ERROR_MUTEX_CALLER_NOT_OWNER, "The caller of a mutex operation was not the owner."),
    ("ERROR_MUTEX_FAILED", ERROR_MUTEX_FAILED, "Mutex operation failed."),
    ("ERROR_COND_VARIABLE_INIT_FAILED", ERROR_COND_VARIABLE_INIT_FAILED, "Condition variable initialization failed."),
    ("ERROR_COND_VARIABLE_TIMED_OUT", ERROR_COND_VARIABLE_TIMED_OUT, "Condition variable wait timed out."),
    ("ERROR_COND_VARIABLE_ERROR_UNKNOWN", ERROR_COND_VARIABLE_ERROR_UNKNOWN, "Condition variable unknown error."),
    ("ERROR_CLOCK_FAILURE", ERROR_CLOCK_FAILURE, "Clock operation failed."),
    ("ERROR_LIST_EMPTY", ERROR_LIST_EMPTY, "Empty list."),
    ("ERROR_DEST_COPY_TOO_SMALL", ERROR_DEST_COPY_TOO_SMALL, "Destination of copy is too small."),
    ("ERROR_LIST_EXCEEDS_MAX_SIZE", ERROR_LIST_EXCEEDS_MAX_SIZE, "A requested operation on a list would exceed it's max size."),
    ("ERROR_LIST_STATIC_MODE_CANT_SHRINK", ERROR_LIST_STATIC_MODE_CANT_SHRINK, "Attempt to shrink a list in static mode."),
    ("ERROR_PRIORITY_QUEUE_FULL", ERROR_PRIORITY_QUEUE_FULL, "Attempt to add items to a full preallocated queue in static mode."),
    ("ERROR_PRIORITY_QUEUE_EMPTY", ERROR_PRIORITY_QUEUE_EMPTY, "Attempt to pop an item from an empty queue."),
    ("ERROR_PRIORITY_QUEUE_BAD_NODE", ERROR_PRIORITY_QUEUE_BAD_NODE, "Bad node handle passed to remove."),
    ("ERROR_HASHTBL_ITEM_NOT_FOUND", ERROR_HASHTBL_ITEM_NOT_FOUND, "Item not found in hash table."),
    ("ERROR_INVALID_DATE_STR", ERROR_INVALID_DATE_STR, "Date string is invalid and cannot be parsed."),
    ("ERROR_INVALID_ARGUMENT", ERROR_INVALID_ARGUMENT, "An invalid argument was passed to a function."),
    ("ERROR_RANDOM_GEN_FAILED", ERROR_RANDOM_GEN_FAILED, "A call to the random number generator failed. Retry later."),
    ("ERROR_MALFORMED_INPUT_STRING", ERROR_MALFORMED_INPUT_STRING, "An input string was passed to a parser and the string was incorrectly formatted."),
    ("ERROR_UNIMPLEMENTED", ERROR_UNIMPLEMENTED, "A function was called, but is not implemented."),
    ("ERROR_INVALID_STATE", ERROR_INVALID_STATE, "An invalid state was encountered."),
    ("ERROR_ENVIRONMENT_GET", ERROR_ENVIRONMENT_GET, "System call failure when getting an environment variable."),
    ("ERROR_ENVIRONMENT_SET", ERROR_ENVIRONMENT_SET, "System call failure when setting an environment variable."),
    ("ERROR_ENVIRONMENT_UNSET", ERROR_ENVIRONMENT_UNSET, "System call failure when unsetting an environment variable."),
    ("ERROR_STREAM_UNSEEKABLE", ERROR_STREAM_UNSEEKABLE, "Stream does not support seek operations."),
    ("ERROR_NO_PERMISSION", ERROR_NO_PERMISSION, "User does not have permission to perform the requested action."),
    ("ERROR_FILE_INVALID_PATH", ERROR_FILE_INVALID_PATH, "Invalid file path."),
    ("ERROR_MAX_FDS_EXCEEDED", ERROR_MAX_FDS_EXCEEDED, "The maximum number of fds has been exceeded."),
    ("ERROR_SYS_CALL_FAILURE", ERROR_SYS_CALL_FAILURE, "System call failure."),
    ("ERROR_C_STRING_BUFFER_NOT_NULL_TERMINATED", ERROR_C_STRING_BUFFER_NOT_NULL_TERMINATED, "A c-string like buffer was passed but a null terminator was not found within the bounds of the buffer."),
    ("ERROR_STRING_MATCH_NOT_FOUND", ERROR_STRING_MATCH_NOT_FOUND, "The specified substring was not present in the input string."),
    ("ERROR_DIVIDE_BY_ZERO", ERROR_DIVIDE_BY_ZERO, "Attempt to divide a number by zero."),
    ("ERROR_INVALID_FILE_HANDLE", ERROR_INVALID_FILE_HANDLE, "Invalid file handle."),
    ("ERROR_OPERATION_INTERUPTED", ERROR_OPERATION_INTERUPTED, "The operation was interrupted."),
    ("ERROR_DIRECTORY_NOT_EMPTY", ERROR_DIRECTORY_NOT_EMPTY, "An operation on a directory was attempted which is not allowed when the directory is not empty."),
    ("ERROR_PLATFORM_NOT_SUPPORTED", ERROR_PLATFORM_NOT_SUPPORTED, "Feature not supported on this platform."),
    ("ERROR_INVALID_UTF8", ERROR_INVALID_UTF8, "Invalid UTF-8."),
    ("ERROR_GET_HOME_DIRECTORY_FAILED", ERROR_GET_HOME_DIRECTORY_FAILED, "Failed to get home directory."),
    ("ERROR_INVALID_XML", ERROR_INVALID_XML, "Invalid XML document."),
    ("ERROR_FILE_OPEN_FAILURE", ERROR_FILE_OPEN_FAILURE, "Failed opening file."),
    ("ERROR_FILE_READ_FAILURE", ERROR_FILE_READ_FAILURE, "Failed reading from file."),
    ("ERROR_FILE_WRITE_FAILURE", ERROR_FILE_WRITE_FAILURE, "Failed writing to file."),
    ("ERROR_INVALID_CBOR", ERROR_INVALID_CBOR, "Malformed cbor data."),
    ("ERROR_CBOR_UNEXPECTED_TYPE", ERROR_CBOR_UNEXPECTED_TYPE, "Unexpected cbor type encountered."),
]

# Register common errors at module load time
_register_errors!(_common_error_definitions, "aws-c-common")

const _common_log_subject_infos = (
    LogSubjectInfo(LS_COMMON_GENERAL, "aws-c-common", "Subject for aws-c-common logging that doesn't belong to any particular category"),
    LogSubjectInfo(LS_COMMON_TASK_SCHEDULER, "task-scheduler", "Subject for task scheduler or task specific logging."),
    LogSubjectInfo(LS_COMMON_THREAD, "thread", "Subject for logging thread related functions."),
    LogSubjectInfo(LS_COMMON_MEMTRACE, "memtrace", "Output from the mem_trace_dump function"),
    LogSubjectInfo(LS_COMMON_XML_PARSER, "xml-parser", "Subject for xml parser specific logging."),
    LogSubjectInfo(LS_COMMON_IO, "common-io", "Common IO utilities"),
    LogSubjectInfo(LS_COMMON_BUS, "bus", "Message bus"),
    LogSubjectInfo(LS_COMMON_TEST, "test", "Unit/integration testing"),
    LogSubjectInfo(LS_COMMON_JSON_PARSER, "json-parser", "Subject for json parser specific logging"),
    LogSubjectInfo(LS_COMMON_CBOR, "cbor", "Subject for CBOR encode and decode"),
)

# Register common log subjects at module load time
for info in _common_log_subject_infos
    registry_set!(_log_subject_registry, info.subject_id, info)
end

function _common_init()
    thread_initialize_thread_management()
    return nothing
end

function _common_cleanup()
    thread_join_all_managed()
    return nothing
end
