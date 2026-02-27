# AWS IO Library - Core definitions
# Port of aws-c-io/include/aws/io/io.h

# IO error constants are defined in `src/error.jl` and are bridged into
# `EventLoops` by `src/eventloops/eventloops.jl`.

# Log subjects for IO operations
const LS_IO_GENERAL = LOG_SUBJECT_BEGIN_RANGE(IO_PACKAGE_ID)
const LS_IO_EVENT_LOOP = LS_IO_GENERAL + LogSubject(1)
const LS_IO_SOCKET = LS_IO_EVENT_LOOP + LogSubject(1)
const LS_IO_SOCKET_HANDLER = LS_IO_SOCKET + LogSubject(1)
const LS_IO_TLS = LS_IO_SOCKET_HANDLER + LogSubject(1)
const LS_IO_ALPN = LS_IO_TLS + LogSubject(1)
const LS_IO_DNS = LS_IO_ALPN + LogSubject(1)
const LS_IO_PKI = LS_IO_DNS + LogSubject(1)
const LS_IO_CHANNEL = LS_IO_PKI + LogSubject(1)
const LS_IO_CHANNEL_BOOTSTRAP = LS_IO_CHANNEL + LogSubject(1)
const LS_IO_FILE_UTILS = LS_IO_CHANNEL_BOOTSTRAP + LogSubject(1)
const LS_IO_SHARED_LIBRARY = LS_IO_FILE_UTILS + LogSubject(1)
const LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY = LS_IO_SHARED_LIBRARY + LogSubject(1)
const LS_IO_STANDARD_RETRY_STRATEGY = LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY + LogSubject(1)
const LS_IO_PKCS11 = LS_IO_STANDARD_RETRY_STRATEGY + LogSubject(1)
const LS_IO_PEM = LS_IO_PKCS11 + LogSubject(1)
const LS_IO_LAST = LOG_SUBJECT_END_RANGE(IO_PACKAGE_ID)

# Message type enum
@enumx IoMessageType::UInt8 begin
    APPLICATION_DATA = 0
end

# TLS message tag for negotiated protocol notification (ALPN)
const TLS_NEGOTIATED_PROTOCOL_MESSAGE = Int32(0x01)

# IO Handle - union of fd (POSIX) or handle (Windows/Apple)
mutable struct IoHandle
    fd::Int32  # File descriptor on POSIX
    handle::Ptr{Cvoid}  # Handle on Windows/Apple
    additional_data::Ptr{Cvoid}
    # set_queue callback - for Apple Network Framework
    set_queue::Ptr{Cvoid}
    # Keep Julia-side handle data alive when additional_data stores pointer_from_objref
    additional_ref::Any
end

function IoHandle()
    return IoHandle(-1, C_NULL, C_NULL, C_NULL, nothing)
end

function IoHandle(fd::Integer)
    return IoHandle(Int32(fd), C_NULL, C_NULL, C_NULL, nothing)
end

io_handle_is_valid(handle::IoHandle) = handle.fd >= 0 || handle.handle != C_NULL

# IO Message - data unit flowing through channel pipeline
mutable struct IoMessage
    message_data::ByteBuffer
    message_type::IoMessageType.T
    message_tag::Int32
    copy_mark::Csize_t
    owning_channel::Any  # Channel or nothing
    on_completion::Union{EventCallable, Nothing}
    negotiated_protocol::Union{String, Nothing}
    # Intrusive list node for queueing
    queueing_handle_next::Union{IoMessage, Nothing}  # nullable
    queueing_handle_prev::Union{IoMessage, Nothing}  # nullable
    pool_segment::Union{Memory{UInt8}, Nothing}  # nullable
end

function IoMessage(capacity::Integer)
    buf = ByteBuffer(capacity)
    return IoMessage(
        buf,
        IoMessageType.APPLICATION_DATA,
        Int32(0),
        Csize_t(0),
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
    )
end

const _pkcs11_ckr_names = (
    "CANCEL",
    "HOST_MEMORY",
    "SLOT_ID_INVALID",
    "GENERAL_ERROR",
    "FUNCTION_FAILED",
    "ARGUMENTS_BAD",
    "NO_EVENT",
    "NEED_TO_CREATE_THREADS",
    "CANT_LOCK",
    "ATTRIBUTE_READ_ONLY",
    "ATTRIBUTE_SENSITIVE",
    "ATTRIBUTE_TYPE_INVALID",
    "ATTRIBUTE_VALUE_INVALID",
    "ACTION_PROHIBITED",
    "DATA_INVALID",
    "DATA_LEN_RANGE",
    "DEVICE_ERROR",
    "DEVICE_MEMORY",
    "DEVICE_REMOVED",
    "ENCRYPTED_DATA_INVALID",
    "ENCRYPTED_DATA_LEN_RANGE",
    "FUNCTION_CANCELED",
    "FUNCTION_NOT_PARALLEL",
    "FUNCTION_NOT_SUPPORTED",
    "KEY_HANDLE_INVALID",
    "KEY_SIZE_RANGE",
    "KEY_TYPE_INCONSISTENT",
    "KEY_NOT_NEEDED",
    "KEY_CHANGED",
    "KEY_NEEDED",
    "KEY_INDIGESTIBLE",
    "KEY_FUNCTION_NOT_PERMITTED",
    "KEY_NOT_WRAPPABLE",
    "KEY_UNEXTRACTABLE",
    "MECHANISM_INVALID",
    "MECHANISM_PARAM_INVALID",
    "OBJECT_HANDLE_INVALID",
    "OPERATION_ACTIVE",
    "OPERATION_NOT_INITIALIZED",
    "PIN_INCORRECT",
    "PIN_INVALID",
    "PIN_LEN_RANGE",
    "PIN_EXPIRED",
    "PIN_LOCKED",
    "SESSION_CLOSED",
    "SESSION_COUNT",
    "SESSION_HANDLE_INVALID",
    "SESSION_PARALLEL_NOT_SUPPORTED",
    "SESSION_READ_ONLY",
    "SESSION_EXISTS",
    "SESSION_READ_ONLY_EXISTS",
    "SESSION_READ_WRITE_SO_EXISTS",
    "SIGNATURE_INVALID",
    "SIGNATURE_LEN_RANGE",
    "TEMPLATE_INCOMPLETE",
    "TEMPLATE_INCONSISTENT",
    "TOKEN_NOT_PRESENT",
    "TOKEN_NOT_RECOGNIZED",
    "TOKEN_WRITE_PROTECTED",
    "UNWRAPPING_KEY_HANDLE_INVALID",
    "UNWRAPPING_KEY_SIZE_RANGE",
    "UNWRAPPING_KEY_TYPE_INCONSISTENT",
    "USER_ALREADY_LOGGED_IN",
    "USER_NOT_LOGGED_IN",
    "USER_PIN_NOT_INITIALIZED",
    "USER_TYPE_INVALID",
    "USER_ANOTHER_ALREADY_LOGGED_IN",
    "USER_TOO_MANY_TYPES",
    "WRAPPED_KEY_INVALID",
    "WRAPPED_KEY_LEN_RANGE",
    "WRAPPING_KEY_HANDLE_INVALID",
    "WRAPPING_KEY_SIZE_RANGE",
    "WRAPPING_KEY_TYPE_INCONSISTENT",
    "RANDOM_SEED_NOT_SUPPORTED",
    "RANDOM_NO_RNG",
    "DOMAIN_PARAMS_INVALID",
    "CURVE_NOT_SUPPORTED",
    "BUFFER_TOO_SMALL",
    "SAVED_STATE_INVALID",
    "INFORMATION_SENSITIVE",
    "STATE_UNSAVEABLE",
    "CRYPTOKI_NOT_INITIALIZED",
    "CRYPTOKI_ALREADY_INITIALIZED",
    "MUTEX_BAD",
    "MUTEX_NOT_LOCKED",
    "NEW_PIN_MODE",
    "NEXT_OTP",
    "EXCEEDED_MAX_ITERATIONS",
    "FIPS_SELF_TEST_FAILED",
    "LIBRARY_LOAD_FAILED",
    "PIN_TOO_WEAK",
    "PUBLIC_KEY_INVALID",
    "FUNCTION_REJECTED",
)

function pkcs11_error_code_str(error_code::Integer)::Union{String, Nothing}
    start_code = ERROR_IO_PKCS11_CKR_CANCEL
    idx = Int(error_code - start_code + 1)
    if idx >= 1 && idx <= length(_pkcs11_ckr_names)
        return "CKR_" * _pkcs11_ckr_names[idx]
    end
    return nothing
end

const _io_log_subject_infos = (
    LogSubjectInfo(LS_IO_GENERAL, "aws-c-io", "Subject for IO logging that doesn't belong to any particular category"),
    LogSubjectInfo(LS_IO_EVENT_LOOP, "event-loop", "Subject for Event-loop specific logging."),
    LogSubjectInfo(LS_IO_SOCKET, "socket", "Subject for Socket specific logging."),
    LogSubjectInfo(LS_IO_SOCKET_HANDLER, "socket-handler", "Subject for a socket channel handler."),
    LogSubjectInfo(LS_IO_TLS, "tls-handler", "Subject for TLS-related logging"),
    LogSubjectInfo(LS_IO_ALPN, "alpn", "Subject for ALPN-related logging"),
    LogSubjectInfo(LS_IO_DNS, "dns", "Subject for DNS-related logging"),
    LogSubjectInfo(LS_IO_PKI, "pki-utils", "Subject for Pki utilities."),
    LogSubjectInfo(LS_IO_CHANNEL, "channel", "Subject for Channels"),
    LogSubjectInfo(LS_IO_CHANNEL_BOOTSTRAP, "channel-bootstrap", "Subject for channel bootstrap (client and server modes)"),
    LogSubjectInfo(LS_IO_FILE_UTILS, "file-utils", "Subject for file operations"),
    LogSubjectInfo(LS_IO_SHARED_LIBRARY, "shared-library", "Subject for shared library operations"),
    LogSubjectInfo(LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY, "exp-backoff-strategy", "Subject for exponential backoff retry strategy"),
    LogSubjectInfo(LS_IO_STANDARD_RETRY_STRATEGY, "standard-retry-strategy", "Subject for standard retry strategy"),
    LogSubjectInfo(LS_IO_PKCS11, "pkcs11", "Subject for PKCS#11 library operations"),
    LogSubjectInfo(LS_IO_PEM, "pem", "Subject for pem operations"),
)

# Register IO log subjects at module load time
for info in _io_log_subject_infos
    _log_subject_registry[info.subject_id] = info
end

const _cal_library_initialized = Ref(false)
const _cal_library_init_pid = Ref{Int}(0)

function _cal_init()
    pid = Base.getpid()
    if _cal_library_initialized[] && _cal_library_init_pid[] == pid
        return nothing
    end
    _cal_library_initialized[] = true
    _cal_library_init_pid[] = pid
    return nothing
end

function _cal_cleanup()
    !_cal_library_initialized[] && return nothing
    pid = Base.getpid()
    if _cal_library_init_pid[] != 0 && _cal_library_init_pid[] != pid
        # Serialized precompile state can mark this as initialized from another process.
        _cal_library_initialized[] = false
        _cal_library_init_pid[] = 0
        return nothing
    end
    _cal_library_initialized[] = false
    _cal_library_init_pid[] = 0
    return nothing
end
