# AWS IO Library - Core definitions
# Port of aws-c-io/include/aws/io/io.h

const IO_PACKAGE_ID = 1

# Error codes for IO operations
const ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT = ERROR_ENUM_BEGIN_RANGE(IO_PACKAGE_ID)
const ERROR_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE = ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT + 1
const ERROR_IO_CHANNEL_READ_WOULD_EXCEED_WINDOW = ERROR_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE + 1
const ERROR_IO_EVENT_LOOP_ALREADY_ASSIGNED = ERROR_IO_CHANNEL_READ_WOULD_EXCEED_WINDOW + 1
const ERROR_IO_EVENT_LOOP_SHUTDOWN = ERROR_IO_EVENT_LOOP_ALREADY_ASSIGNED + 1
const ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE = ERROR_IO_EVENT_LOOP_SHUTDOWN + 1
const ERROR_IO_TLS_ERROR_NOT_NEGOTIATED = ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE + 1
const ERROR_IO_TLS_ERROR_WRITE_FAILURE = ERROR_IO_TLS_ERROR_NOT_NEGOTIATED + 1
const ERROR_IO_TLS_ERROR_ALERT_RECEIVED = ERROR_IO_TLS_ERROR_WRITE_FAILURE + 1
const ERROR_IO_TLS_CTX_ERROR = ERROR_IO_TLS_ERROR_ALERT_RECEIVED + 1
const ERROR_IO_TLS_VERSION_UNSUPPORTED = ERROR_IO_TLS_CTX_ERROR + 1
const ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED = ERROR_IO_TLS_VERSION_UNSUPPORTED + 1
const ERROR_IO_MISSING_ALPN_MESSAGE = ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED + 1
const ERROR_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE = ERROR_IO_MISSING_ALPN_MESSAGE + 1
const ERROR_IO_FILE_VALIDATION_FAILURE = ERROR_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE + 1
const ERROR_IO_EVENT_LOOP_THREAD_ONLY = ERROR_IO_FILE_VALIDATION_FAILURE + 1
const ERROR_IO_ALREADY_SUBSCRIBED = ERROR_IO_EVENT_LOOP_THREAD_ONLY + 1
const ERROR_IO_NOT_SUBSCRIBED = ERROR_IO_ALREADY_SUBSCRIBED + 1
const ERROR_IO_OPERATION_CANCELLED = ERROR_IO_NOT_SUBSCRIBED + 1
const ERROR_IO_READ_WOULD_BLOCK = ERROR_IO_OPERATION_CANCELLED + 1
const ERROR_IO_BROKEN_PIPE = ERROR_IO_READ_WOULD_BLOCK + 1
const ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY = ERROR_IO_BROKEN_PIPE + 1
const ERROR_IO_SOCKET_INVALID_OPERATION_FOR_TYPE = ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY + 1
const ERROR_IO_SOCKET_CONNECTION_REFUSED = ERROR_IO_SOCKET_INVALID_OPERATION_FOR_TYPE + 1
const ERROR_IO_SOCKET_TIMEOUT = ERROR_IO_SOCKET_CONNECTION_REFUSED + 1
const ERROR_IO_SOCKET_NO_ROUTE_TO_HOST = ERROR_IO_SOCKET_TIMEOUT + 1
const ERROR_IO_SOCKET_NETWORK_DOWN = ERROR_IO_SOCKET_NO_ROUTE_TO_HOST + 1
const ERROR_IO_SOCKET_CLOSED = ERROR_IO_SOCKET_NETWORK_DOWN + 1
const ERROR_IO_SOCKET_NOT_CONNECTED = ERROR_IO_SOCKET_CLOSED + 1
const ERROR_IO_SOCKET_INVALID_OPTIONS = ERROR_IO_SOCKET_NOT_CONNECTED + 1
const ERROR_IO_SOCKET_ADDRESS_IN_USE = ERROR_IO_SOCKET_INVALID_OPTIONS + 1
const ERROR_IO_SOCKET_INVALID_ADDRESS = ERROR_IO_SOCKET_ADDRESS_IN_USE + 1
const ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE = ERROR_IO_SOCKET_INVALID_ADDRESS + 1
const ERROR_IO_SOCKET_CONNECT_ABORTED = ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE + 1
const ERROR_IO_DNS_QUERY_FAILED = ERROR_IO_SOCKET_CONNECT_ABORTED + 1
const ERROR_IO_DNS_INVALID_NAME = ERROR_IO_DNS_QUERY_FAILED + 1
const ERROR_IO_DNS_NO_ADDRESS_FOR_HOST = ERROR_IO_DNS_INVALID_NAME + 1
const ERROR_IO_DNS_HOST_REMOVED_FROM_CACHE = ERROR_IO_DNS_NO_ADDRESS_FOR_HOST + 1
const ERROR_IO_STREAM_INVALID_SEEK_POSITION = ERROR_IO_DNS_HOST_REMOVED_FROM_CACHE + 1
const ERROR_IO_STREAM_READ_FAILED = ERROR_IO_STREAM_INVALID_SEEK_POSITION + 1
const ERROR_IO_INVALID_FILE_HANDLE_DEPRECATED = ERROR_IO_STREAM_READ_FAILED + 1
const ERROR_IO_SHARED_LIBRARY_LOAD_FAILURE = ERROR_IO_INVALID_FILE_HANDLE_DEPRECATED + 1
const ERROR_IO_SHARED_LIBRARY_FIND_SYMBOL_FAILURE = ERROR_IO_SHARED_LIBRARY_LOAD_FAILURE + 1
const ERROR_IO_TLS_NEGOTIATION_TIMEOUT = ERROR_IO_SHARED_LIBRARY_FIND_SYMBOL_FAILURE + 1
const ERROR_IO_TLS_ALERT_NOT_GRACEFUL = ERROR_IO_TLS_NEGOTIATION_TIMEOUT + 1
const ERROR_IO_MAX_RETRIES_EXCEEDED = ERROR_IO_TLS_ALERT_NOT_GRACEFUL + 1
const ERROR_IO_RETRY_PERMISSION_DENIED = ERROR_IO_MAX_RETRIES_EXCEEDED + 1
const ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED = ERROR_IO_RETRY_PERMISSION_DENIED + 1
const ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED = ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED + 1
const ERROR_IO_PKCS11_VERSION_UNSUPPORTED = ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED + 1
const ERROR_IO_PKCS11_TOKEN_NOT_FOUND = ERROR_IO_PKCS11_VERSION_UNSUPPORTED + 1
const ERROR_IO_PKCS11_KEY_NOT_FOUND = ERROR_IO_PKCS11_TOKEN_NOT_FOUND + 1
const ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED = ERROR_IO_PKCS11_KEY_NOT_FOUND + 1
const ERROR_IO_PKCS11_UNKNOWN_CRYPTOKI_RETURN_VALUE = ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED + 1
# PKCS#11 CKR_* error codes
const ERROR_IO_PKCS11_CKR_CANCEL = ERROR_IO_PKCS11_UNKNOWN_CRYPTOKI_RETURN_VALUE + 1
const ERROR_IO_PKCS11_CKR_HOST_MEMORY = ERROR_IO_PKCS11_CKR_CANCEL + 1
const ERROR_IO_PKCS11_CKR_SLOT_ID_INVALID = ERROR_IO_PKCS11_CKR_HOST_MEMORY + 1
const ERROR_IO_PKCS11_CKR_GENERAL_ERROR = ERROR_IO_PKCS11_CKR_SLOT_ID_INVALID + 1
const ERROR_IO_PKCS11_CKR_FUNCTION_FAILED = ERROR_IO_PKCS11_CKR_GENERAL_ERROR + 1
const ERROR_IO_PKCS11_CKR_ARGUMENTS_BAD = ERROR_IO_PKCS11_CKR_FUNCTION_FAILED + 1
const ERROR_IO_PKCS11_CKR_NO_EVENT = ERROR_IO_PKCS11_CKR_ARGUMENTS_BAD + 1
const ERROR_IO_PKCS11_CKR_NEED_TO_CREATE_THREADS = ERROR_IO_PKCS11_CKR_NO_EVENT + 1
const ERROR_IO_PKCS11_CKR_CANT_LOCK = ERROR_IO_PKCS11_CKR_NEED_TO_CREATE_THREADS + 1
const ERROR_IO_PKCS11_CKR_ATTRIBUTE_READ_ONLY = ERROR_IO_PKCS11_CKR_CANT_LOCK + 1
const ERROR_IO_PKCS11_CKR_ATTRIBUTE_SENSITIVE = ERROR_IO_PKCS11_CKR_ATTRIBUTE_READ_ONLY + 1
const ERROR_IO_PKCS11_CKR_ATTRIBUTE_TYPE_INVALID = ERROR_IO_PKCS11_CKR_ATTRIBUTE_SENSITIVE + 1
const ERROR_IO_PKCS11_CKR_ATTRIBUTE_VALUE_INVALID = ERROR_IO_PKCS11_CKR_ATTRIBUTE_TYPE_INVALID + 1
const ERROR_IO_PKCS11_CKR_ACTION_PROHIBITED = ERROR_IO_PKCS11_CKR_ATTRIBUTE_VALUE_INVALID + 1
const ERROR_IO_PKCS11_CKR_DATA_INVALID = ERROR_IO_PKCS11_CKR_ACTION_PROHIBITED + 1
const ERROR_IO_PKCS11_CKR_DATA_LEN_RANGE = ERROR_IO_PKCS11_CKR_DATA_INVALID + 1
const ERROR_IO_PKCS11_CKR_DEVICE_ERROR = ERROR_IO_PKCS11_CKR_DATA_LEN_RANGE + 1
const ERROR_IO_PKCS11_CKR_DEVICE_MEMORY = ERROR_IO_PKCS11_CKR_DEVICE_ERROR + 1
const ERROR_IO_PKCS11_CKR_DEVICE_REMOVED = ERROR_IO_PKCS11_CKR_DEVICE_MEMORY + 1
const ERROR_IO_PKCS11_CKR_ENCRYPTED_DATA_INVALID = ERROR_IO_PKCS11_CKR_DEVICE_REMOVED + 1
const ERROR_IO_PKCS11_CKR_ENCRYPTED_DATA_LEN_RANGE = ERROR_IO_PKCS11_CKR_ENCRYPTED_DATA_INVALID + 1
const ERROR_IO_PKCS11_CKR_FUNCTION_CANCELED = ERROR_IO_PKCS11_CKR_ENCRYPTED_DATA_LEN_RANGE + 1
const ERROR_IO_PKCS11_CKR_FUNCTION_NOT_PARALLEL = ERROR_IO_PKCS11_CKR_FUNCTION_CANCELED + 1
const ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED = ERROR_IO_PKCS11_CKR_FUNCTION_NOT_PARALLEL + 1
const ERROR_IO_PKCS11_CKR_KEY_HANDLE_INVALID = ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED + 1
const ERROR_IO_PKCS11_CKR_KEY_SIZE_RANGE = ERROR_IO_PKCS11_CKR_KEY_HANDLE_INVALID + 1
const ERROR_IO_PKCS11_CKR_KEY_TYPE_INCONSISTENT = ERROR_IO_PKCS11_CKR_KEY_SIZE_RANGE + 1
const ERROR_IO_PKCS11_CKR_KEY_NOT_NEEDED = ERROR_IO_PKCS11_CKR_KEY_TYPE_INCONSISTENT + 1
const ERROR_IO_PKCS11_CKR_KEY_CHANGED = ERROR_IO_PKCS11_CKR_KEY_NOT_NEEDED + 1
const ERROR_IO_PKCS11_CKR_KEY_NEEDED = ERROR_IO_PKCS11_CKR_KEY_CHANGED + 1
const ERROR_IO_PKCS11_CKR_KEY_INDIGESTIBLE = ERROR_IO_PKCS11_CKR_KEY_NEEDED + 1
const ERROR_IO_PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED = ERROR_IO_PKCS11_CKR_KEY_INDIGESTIBLE + 1
const ERROR_IO_PKCS11_CKR_KEY_NOT_WRAPPABLE = ERROR_IO_PKCS11_CKR_KEY_FUNCTION_NOT_PERMITTED + 1
const ERROR_IO_PKCS11_CKR_KEY_UNEXTRACTABLE = ERROR_IO_PKCS11_CKR_KEY_NOT_WRAPPABLE + 1
const ERROR_IO_PKCS11_CKR_MECHANISM_INVALID = ERROR_IO_PKCS11_CKR_KEY_UNEXTRACTABLE + 1
const ERROR_IO_PKCS11_CKR_MECHANISM_PARAM_INVALID = ERROR_IO_PKCS11_CKR_MECHANISM_INVALID + 1
const ERROR_IO_PKCS11_CKR_OBJECT_HANDLE_INVALID = ERROR_IO_PKCS11_CKR_MECHANISM_PARAM_INVALID + 1
const ERROR_IO_PKCS11_CKR_OPERATION_ACTIVE = ERROR_IO_PKCS11_CKR_OBJECT_HANDLE_INVALID + 1
const ERROR_IO_PKCS11_CKR_OPERATION_NOT_INITIALIZED = ERROR_IO_PKCS11_CKR_OPERATION_ACTIVE + 1
const ERROR_IO_PKCS11_CKR_PIN_INCORRECT = ERROR_IO_PKCS11_CKR_OPERATION_NOT_INITIALIZED + 1
const ERROR_IO_PKCS11_CKR_PIN_INVALID = ERROR_IO_PKCS11_CKR_PIN_INCORRECT + 1
const ERROR_IO_PKCS11_CKR_PIN_LEN_RANGE = ERROR_IO_PKCS11_CKR_PIN_INVALID + 1
const ERROR_IO_PKCS11_CKR_PIN_EXPIRED = ERROR_IO_PKCS11_CKR_PIN_LEN_RANGE + 1
const ERROR_IO_PKCS11_CKR_PIN_LOCKED = ERROR_IO_PKCS11_CKR_PIN_EXPIRED + 1
const ERROR_IO_PKCS11_CKR_SESSION_CLOSED = ERROR_IO_PKCS11_CKR_PIN_LOCKED + 1
const ERROR_IO_PKCS11_CKR_SESSION_COUNT = ERROR_IO_PKCS11_CKR_SESSION_CLOSED + 1
const ERROR_IO_PKCS11_CKR_SESSION_HANDLE_INVALID = ERROR_IO_PKCS11_CKR_SESSION_COUNT + 1
const ERROR_IO_PKCS11_CKR_SESSION_PARALLEL_NOT_SUPPORTED = ERROR_IO_PKCS11_CKR_SESSION_HANDLE_INVALID + 1
const ERROR_IO_PKCS11_CKR_SESSION_READ_ONLY = ERROR_IO_PKCS11_CKR_SESSION_PARALLEL_NOT_SUPPORTED + 1
const ERROR_IO_PKCS11_CKR_SESSION_EXISTS = ERROR_IO_PKCS11_CKR_SESSION_READ_ONLY + 1
const ERROR_IO_PKCS11_CKR_SESSION_READ_ONLY_EXISTS = ERROR_IO_PKCS11_CKR_SESSION_EXISTS + 1
const ERROR_IO_PKCS11_CKR_SESSION_READ_WRITE_SO_EXISTS = ERROR_IO_PKCS11_CKR_SESSION_READ_ONLY_EXISTS + 1
const ERROR_IO_PKCS11_CKR_SIGNATURE_INVALID = ERROR_IO_PKCS11_CKR_SESSION_READ_WRITE_SO_EXISTS + 1
const ERROR_IO_PKCS11_CKR_SIGNATURE_LEN_RANGE = ERROR_IO_PKCS11_CKR_SIGNATURE_INVALID + 1
const ERROR_IO_PKCS11_CKR_TEMPLATE_INCOMPLETE = ERROR_IO_PKCS11_CKR_SIGNATURE_LEN_RANGE + 1
const ERROR_IO_PKCS11_CKR_TEMPLATE_INCONSISTENT = ERROR_IO_PKCS11_CKR_TEMPLATE_INCOMPLETE + 1
const ERROR_IO_PKCS11_CKR_TOKEN_NOT_PRESENT = ERROR_IO_PKCS11_CKR_TEMPLATE_INCONSISTENT + 1
const ERROR_IO_PKCS11_CKR_TOKEN_NOT_RECOGNIZED = ERROR_IO_PKCS11_CKR_TOKEN_NOT_PRESENT + 1
const ERROR_IO_PKCS11_CKR_TOKEN_WRITE_PROTECTED = ERROR_IO_PKCS11_CKR_TOKEN_NOT_RECOGNIZED + 1
const ERROR_IO_PKCS11_CKR_UNWRAPPING_KEY_HANDLE_INVALID = ERROR_IO_PKCS11_CKR_TOKEN_WRITE_PROTECTED + 1
const ERROR_IO_PKCS11_CKR_UNWRAPPING_KEY_SIZE_RANGE = ERROR_IO_PKCS11_CKR_UNWRAPPING_KEY_HANDLE_INVALID + 1
const ERROR_IO_PKCS11_CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT = ERROR_IO_PKCS11_CKR_UNWRAPPING_KEY_SIZE_RANGE + 1
const ERROR_IO_PKCS11_CKR_USER_ALREADY_LOGGED_IN = ERROR_IO_PKCS11_CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT + 1
const ERROR_IO_PKCS11_CKR_USER_NOT_LOGGED_IN = ERROR_IO_PKCS11_CKR_USER_ALREADY_LOGGED_IN + 1
const ERROR_IO_PKCS11_CKR_USER_PIN_NOT_INITIALIZED = ERROR_IO_PKCS11_CKR_USER_NOT_LOGGED_IN + 1
const ERROR_IO_PKCS11_CKR_USER_TYPE_INVALID = ERROR_IO_PKCS11_CKR_USER_PIN_NOT_INITIALIZED + 1
const ERROR_IO_PKCS11_CKR_USER_ANOTHER_ALREADY_LOGGED_IN = ERROR_IO_PKCS11_CKR_USER_TYPE_INVALID + 1
const ERROR_IO_PKCS11_CKR_USER_TOO_MANY_TYPES = ERROR_IO_PKCS11_CKR_USER_ANOTHER_ALREADY_LOGGED_IN + 1
const ERROR_IO_PKCS11_CKR_WRAPPED_KEY_INVALID = ERROR_IO_PKCS11_CKR_USER_TOO_MANY_TYPES + 1
const ERROR_IO_PKCS11_CKR_WRAPPED_KEY_LEN_RANGE = ERROR_IO_PKCS11_CKR_WRAPPED_KEY_INVALID + 1
const ERROR_IO_PKCS11_CKR_WRAPPING_KEY_HANDLE_INVALID = ERROR_IO_PKCS11_CKR_WRAPPED_KEY_LEN_RANGE + 1
const ERROR_IO_PKCS11_CKR_WRAPPING_KEY_SIZE_RANGE = ERROR_IO_PKCS11_CKR_WRAPPING_KEY_HANDLE_INVALID + 1
const ERROR_IO_PKCS11_CKR_WRAPPING_KEY_TYPE_INCONSISTENT = ERROR_IO_PKCS11_CKR_WRAPPING_KEY_SIZE_RANGE + 1
const ERROR_IO_PKCS11_CKR_RANDOM_SEED_NOT_SUPPORTED = ERROR_IO_PKCS11_CKR_WRAPPING_KEY_TYPE_INCONSISTENT + 1
const ERROR_IO_PKCS11_CKR_RANDOM_NO_RNG = ERROR_IO_PKCS11_CKR_RANDOM_SEED_NOT_SUPPORTED + 1
const ERROR_IO_PKCS11_CKR_DOMAIN_PARAMS_INVALID = ERROR_IO_PKCS11_CKR_RANDOM_NO_RNG + 1
const ERROR_IO_PKCS11_CKR_CURVE_NOT_SUPPORTED = ERROR_IO_PKCS11_CKR_DOMAIN_PARAMS_INVALID + 1
const ERROR_IO_PKCS11_CKR_BUFFER_TOO_SMALL = ERROR_IO_PKCS11_CKR_CURVE_NOT_SUPPORTED + 1
const ERROR_IO_PKCS11_CKR_SAVED_STATE_INVALID = ERROR_IO_PKCS11_CKR_BUFFER_TOO_SMALL + 1
const ERROR_IO_PKCS11_CKR_INFORMATION_SENSITIVE = ERROR_IO_PKCS11_CKR_SAVED_STATE_INVALID + 1
const ERROR_IO_PKCS11_CKR_STATE_UNSAVEABLE = ERROR_IO_PKCS11_CKR_INFORMATION_SENSITIVE + 1
const ERROR_IO_PKCS11_CKR_CRYPTOKI_NOT_INITIALIZED = ERROR_IO_PKCS11_CKR_STATE_UNSAVEABLE + 1
const ERROR_IO_PKCS11_CKR_CRYPTOKI_ALREADY_INITIALIZED = ERROR_IO_PKCS11_CKR_CRYPTOKI_NOT_INITIALIZED + 1
const ERROR_IO_PKCS11_CKR_MUTEX_BAD = ERROR_IO_PKCS11_CKR_CRYPTOKI_ALREADY_INITIALIZED + 1
const ERROR_IO_PKCS11_CKR_MUTEX_NOT_LOCKED = ERROR_IO_PKCS11_CKR_MUTEX_BAD + 1
const ERROR_IO_PKCS11_CKR_NEW_PIN_MODE = ERROR_IO_PKCS11_CKR_MUTEX_NOT_LOCKED + 1
const ERROR_IO_PKCS11_CKR_NEXT_OTP = ERROR_IO_PKCS11_CKR_NEW_PIN_MODE + 1
const ERROR_IO_PKCS11_CKR_EXCEEDED_MAX_ITERATIONS = ERROR_IO_PKCS11_CKR_NEXT_OTP + 1
const ERROR_IO_PKCS11_CKR_FIPS_SELF_TEST_FAILED = ERROR_IO_PKCS11_CKR_EXCEEDED_MAX_ITERATIONS + 1
const ERROR_IO_PKCS11_CKR_LIBRARY_LOAD_FAILED = ERROR_IO_PKCS11_CKR_FIPS_SELF_TEST_FAILED + 1
const ERROR_IO_PKCS11_CKR_PIN_TOO_WEAK = ERROR_IO_PKCS11_CKR_LIBRARY_LOAD_FAILED + 1
const ERROR_IO_PKCS11_CKR_PUBLIC_KEY_INVALID = ERROR_IO_PKCS11_CKR_PIN_TOO_WEAK + 1
const ERROR_IO_PKCS11_CKR_FUNCTION_REJECTED = ERROR_IO_PKCS11_CKR_PUBLIC_KEY_INVALID + 1
const ERROR_IO_PINNED_EVENT_LOOP_MISMATCH = ERROR_IO_PKCS11_CKR_FUNCTION_REJECTED + 1
const ERROR_IO_PKCS11_ENCODING_ERROR = ERROR_IO_PINNED_EVENT_LOOP_MISMATCH + 1
const ERROR_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND = ERROR_IO_PKCS11_ENCODING_ERROR + 1
const ERROR_IO_STREAM_SEEK_FAILED = ERROR_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND + 1
const ERROR_IO_STREAM_GET_LENGTH_FAILED = ERROR_IO_STREAM_SEEK_FAILED + 1
const ERROR_IO_STREAM_SEEK_UNSUPPORTED = ERROR_IO_STREAM_GET_LENGTH_FAILED + 1
const ERROR_IO_STREAM_GET_LENGTH_UNSUPPORTED = ERROR_IO_STREAM_SEEK_UNSUPPORTED + 1
const ERROR_IO_TLS_ERROR_READ_FAILURE = ERROR_IO_STREAM_GET_LENGTH_UNSUPPORTED + 1
const ERROR_IO_PEM_MALFORMED = ERROR_IO_TLS_ERROR_READ_FAILURE + 1
const ERROR_IO_SOCKET_MISSING_EVENT_LOOP = ERROR_IO_PEM_MALFORMED + 1
const ERROR_IO_TLS_UNKNOWN_ROOT_CERTIFICATE = ERROR_IO_SOCKET_MISSING_EVENT_LOOP + 1
const ERROR_IO_TLS_NO_ROOT_CERTIFICATE_FOUND = ERROR_IO_TLS_UNKNOWN_ROOT_CERTIFICATE + 1
const ERROR_IO_TLS_CERTIFICATE_EXPIRED = ERROR_IO_TLS_NO_ROOT_CERTIFICATE_FOUND + 1
const ERROR_IO_TLS_CERTIFICATE_NOT_YET_VALID = ERROR_IO_TLS_CERTIFICATE_EXPIRED + 1
const ERROR_IO_TLS_BAD_CERTIFICATE = ERROR_IO_TLS_CERTIFICATE_NOT_YET_VALID + 1
const ERROR_IO_TLS_PEER_CERTIFICATE_EXPIRED = ERROR_IO_TLS_BAD_CERTIFICATE + 1
const ERROR_IO_TLS_BAD_PEER_CERTIFICATE = ERROR_IO_TLS_PEER_CERTIFICATE_EXPIRED + 1
const ERROR_IO_TLS_PEER_CERTIFICATE_REVOKED = ERROR_IO_TLS_BAD_PEER_CERTIFICATE + 1
const ERROR_IO_TLS_PEER_CERTIFICATE_UNKNOWN = ERROR_IO_TLS_PEER_CERTIFICATE_REVOKED + 1
const ERROR_IO_TLS_INTERNAL_ERROR = ERROR_IO_TLS_PEER_CERTIFICATE_UNKNOWN + 1
const ERROR_IO_TLS_CLOSED_GRACEFUL = ERROR_IO_TLS_INTERNAL_ERROR + 1
const ERROR_IO_TLS_CLOSED_ABORT = ERROR_IO_TLS_CLOSED_GRACEFUL + 1
const ERROR_IO_TLS_INVALID_CERTIFICATE_CHAIN = ERROR_IO_TLS_CLOSED_ABORT + 1
const ERROR_IO_TLS_HOST_NAME_MISMATCH = ERROR_IO_TLS_INVALID_CERTIFICATE_CHAIN + 1
const ERROR_IO_DNS_QUERY_AGAIN = ERROR_IO_TLS_HOST_NAME_MISMATCH + 1
const ERROR_IO_END_RANGE = ERROR_ENUM_END_RANGE(IO_PACKAGE_ID)
const ERROR_IO_INVALID_FILE_HANDLE = ERROR_INVALID_FILE_HANDLE

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

# Forward declarations for types defined in other io files
abstract type AbstractChannel end
abstract type AbstractChannelHandler end
abstract type AbstractEventLoop end

# IO Message - data unit flowing through channel pipeline
mutable struct IoMessage
    message_data::ByteBuffer
    message_type::IoMessageType.T
    message_tag::Int32
    copy_mark::Csize_t
    owning_channel::Union{AbstractChannel, Nothing}  # nullable
    on_completion::Any
    user_data::Any
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

# Clock function type for event loops
const IoClock = Function  # signature: () -> UInt64 (nanoseconds)

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

# Error definitions for registration
const _io_error_definitions = let defs = Vector{Tuple{String, Int, String}}()
    append!(
        defs,
        (
            ("ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT", ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT, "Channel cannot accept input"),
            ("ERROR_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE", ERROR_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE, "Channel unknown message type"),
            ("ERROR_IO_CHANNEL_READ_WOULD_EXCEED_WINDOW", ERROR_IO_CHANNEL_READ_WOULD_EXCEED_WINDOW, "A channel handler attempted to propagate a read larger than the upstream window"),
            ("ERROR_IO_EVENT_LOOP_ALREADY_ASSIGNED", ERROR_IO_EVENT_LOOP_ALREADY_ASSIGNED, "An attempt was made to assign an io handle to an event loop, but the handle was already assigned."),
            ("ERROR_IO_EVENT_LOOP_SHUTDOWN", ERROR_IO_EVENT_LOOP_SHUTDOWN, "Event loop has shutdown and a resource was still using it, the resource has been removed from the loop."),
            ("ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE", ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE, "TLS (SSL) negotiation failed"),
            ("ERROR_IO_TLS_ERROR_NOT_NEGOTIATED", ERROR_IO_TLS_ERROR_NOT_NEGOTIATED, "Attempt to read/write, but TLS (SSL) hasn't been negotiated"),
            ("ERROR_IO_TLS_ERROR_WRITE_FAILURE", ERROR_IO_TLS_ERROR_WRITE_FAILURE, "Failed to write to TLS handler"),
            ("ERROR_IO_TLS_ERROR_ALERT_RECEIVED", ERROR_IO_TLS_ERROR_ALERT_RECEIVED, "Fatal TLS Alert was received"),
            ("ERROR_IO_TLS_CTX_ERROR", ERROR_IO_TLS_CTX_ERROR, "Failed to create tls context"),
            ("ERROR_IO_TLS_VERSION_UNSUPPORTED", ERROR_IO_TLS_VERSION_UNSUPPORTED, "A TLS version was specified that is currently not supported. Consider using AWS_IO_TLS_VER_SYS_DEFAULTS,  and when this lib or the operating system is updated, it will automatically be used."),
            ("ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED", ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED, "A TLS Cipher Preference was specified that is currently not supported by the current platform. Consider  using AWS_IO_TLS_CIPHER_SYSTEM_DEFAULT, and when this lib or the operating system is updated, it will automatically be used."),
            ("ERROR_IO_MISSING_ALPN_MESSAGE", ERROR_IO_MISSING_ALPN_MESSAGE, "An ALPN message was expected but not received"),
            ("ERROR_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE", ERROR_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE, "An ALPN message was received but a handler was not created by the user"),
            ("ERROR_IO_FILE_VALIDATION_FAILURE", ERROR_IO_FILE_VALIDATION_FAILURE, "A file was read and the input did not match the expected value"),
            ("ERROR_IO_EVENT_LOOP_THREAD_ONLY", ERROR_IO_EVENT_LOOP_THREAD_ONLY, "Attempt to perform operation that must be run inside the event loop thread"),
            ("ERROR_IO_ALREADY_SUBSCRIBED", ERROR_IO_ALREADY_SUBSCRIBED, "Already subscribed to receive events"),
            ("ERROR_IO_NOT_SUBSCRIBED", ERROR_IO_NOT_SUBSCRIBED, "Not subscribed to receive events"),
            ("ERROR_IO_OPERATION_CANCELLED", ERROR_IO_OPERATION_CANCELLED, "Operation cancelled before it could complete"),
            ("ERROR_IO_READ_WOULD_BLOCK", ERROR_IO_READ_WOULD_BLOCK, "Read operation would block, try again later"),
            ("ERROR_IO_BROKEN_PIPE", ERROR_IO_BROKEN_PIPE, "Attempt to read or write to io handle that has already been closed."),
            ("ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY", ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY, "Socket, unsupported address family."),
            ("ERROR_IO_SOCKET_INVALID_OPERATION_FOR_TYPE", ERROR_IO_SOCKET_INVALID_OPERATION_FOR_TYPE, "Invalid socket operation for socket type."),
            ("ERROR_IO_SOCKET_CONNECTION_REFUSED", ERROR_IO_SOCKET_CONNECTION_REFUSED, "socket connection refused."),
            ("ERROR_IO_SOCKET_TIMEOUT", ERROR_IO_SOCKET_TIMEOUT, "socket operation timed out."),
            ("ERROR_IO_SOCKET_NO_ROUTE_TO_HOST", ERROR_IO_SOCKET_NO_ROUTE_TO_HOST, "socket connect failure, no route to host."),
            ("ERROR_IO_SOCKET_NETWORK_DOWN", ERROR_IO_SOCKET_NETWORK_DOWN, "network is down."),
            ("ERROR_IO_SOCKET_CLOSED", ERROR_IO_SOCKET_CLOSED, "socket is closed."),
            ("ERROR_IO_SOCKET_NOT_CONNECTED", ERROR_IO_SOCKET_NOT_CONNECTED, "socket not connected."),
            ("ERROR_IO_SOCKET_INVALID_OPTIONS", ERROR_IO_SOCKET_INVALID_OPTIONS, "Invalid socket options."),
            ("ERROR_IO_SOCKET_ADDRESS_IN_USE", ERROR_IO_SOCKET_ADDRESS_IN_USE, "Socket address already in use."),
            ("ERROR_IO_SOCKET_INVALID_ADDRESS", ERROR_IO_SOCKET_INVALID_ADDRESS, "Invalid socket address."),
            ("ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE", ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE, "Illegal operation for socket state."),
            ("ERROR_IO_SOCKET_CONNECT_ABORTED", ERROR_IO_SOCKET_CONNECT_ABORTED, "Incoming connection was aborted."),
            ("ERROR_IO_DNS_QUERY_FAILED", ERROR_IO_DNS_QUERY_FAILED, "A nonrecoverable failure when query to dns occurred."),
            ("ERROR_IO_DNS_INVALID_NAME", ERROR_IO_DNS_INVALID_NAME, "Host name was invalid for dns resolution."),
            ("ERROR_IO_DNS_NO_ADDRESS_FOR_HOST", ERROR_IO_DNS_NO_ADDRESS_FOR_HOST, "No address was found for the supplied host name."),
            ("ERROR_IO_DNS_HOST_REMOVED_FROM_CACHE", ERROR_IO_DNS_HOST_REMOVED_FROM_CACHE, "The entries for host name were removed from the local dns cache."),
            ("ERROR_IO_STREAM_INVALID_SEEK_POSITION", ERROR_IO_STREAM_INVALID_SEEK_POSITION, "The seek position was outside of a stream's bounds"),
            ("ERROR_IO_STREAM_READ_FAILED", ERROR_IO_STREAM_READ_FAILED, "Stream failed to read from the underlying io source"),
            ("ERROR_IO_INVALID_FILE_HANDLE_DEPRECATED", ERROR_IO_INVALID_FILE_HANDLE_DEPRECATED, "Operation failed because the file handle was invalid"),
            ("ERROR_IO_SHARED_LIBRARY_LOAD_FAILURE", ERROR_IO_SHARED_LIBRARY_LOAD_FAILURE, "System call error during attempt to load shared library"),
            ("ERROR_IO_SHARED_LIBRARY_FIND_SYMBOL_FAILURE", ERROR_IO_SHARED_LIBRARY_FIND_SYMBOL_FAILURE, "System call error during attempt to find shared library symbol"),
            ("ERROR_IO_TLS_NEGOTIATION_TIMEOUT", ERROR_IO_TLS_NEGOTIATION_TIMEOUT, "Channel shutdown due to tls negotiation timeout"),
            ("ERROR_IO_TLS_ALERT_NOT_GRACEFUL", ERROR_IO_TLS_ALERT_NOT_GRACEFUL, "Channel shutdown due to tls alert. The alert was not for a graceful shutdown."),
            ("ERROR_IO_MAX_RETRIES_EXCEEDED", ERROR_IO_MAX_RETRIES_EXCEEDED, "Retry cannot be attempted because the maximum number of retries has been exceeded."),
            ("ERROR_IO_RETRY_PERMISSION_DENIED", ERROR_IO_RETRY_PERMISSION_DENIED, "Retry cannot be attempted because the retry strategy has prevented the operation."),
            ("ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED", ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED, "TLS digest was created with an unsupported algorithm"),
            ("ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED", ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED, "TLS signature algorithm is currently unsupported."),
            ("ERROR_IO_PKCS11_VERSION_UNSUPPORTED", ERROR_IO_PKCS11_VERSION_UNSUPPORTED, "The PKCS#11 library uses an unsupported API version."),
            ("ERROR_IO_PKCS11_TOKEN_NOT_FOUND", ERROR_IO_PKCS11_TOKEN_NOT_FOUND, "Could not pick PKCS#11 token matching search criteria (none found, or multiple found)"),
            ("ERROR_IO_PKCS11_KEY_NOT_FOUND", ERROR_IO_PKCS11_KEY_NOT_FOUND, "Could not pick PKCS#11 key matching search criteria (none found, or multiple found)"),
            ("ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED", ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED, "PKCS#11 key type not supported"),
            ("ERROR_IO_PKCS11_UNKNOWN_CRYPTOKI_RETURN_VALUE", ERROR_IO_PKCS11_UNKNOWN_CRYPTOKI_RETURN_VALUE, "A PKCS#11 (Cryptoki) library function failed with an unknown return value (CKR_). See log for more details."),
        ),
    )
    for name in _pkcs11_ckr_names
        code = getfield(@__MODULE__, Symbol("ERROR_IO_PKCS11_CKR_", name))
        push!(
            defs,
            (
                "ERROR_IO_PKCS11_CKR_" * name,
                code,
                "A PKCS#11 (Cryptoki) library function failed with return value CKR_" * name,
            ),
        )
    end
    append!(
        defs,
        (
            (
                "ERROR_IO_PINNED_EVENT_LOOP_MISMATCH",
                ERROR_IO_PINNED_EVENT_LOOP_MISMATCH,
                "A connection was requested on an event loop that is not associated with the client bootstrap's event loop group.",
            ),
            (
                "ERROR_IO_PKCS11_ENCODING_ERROR",
                ERROR_IO_PKCS11_ENCODING_ERROR,
                "A PKCS#11 (Cryptoki) library function was unable to ASN.1 (DER) encode a data structure. See log for more details.",
            ),
            (
                "ERROR_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND",
                ERROR_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND,
                "Default TLS trust store not found on this system. Trusted CA certificates must be installed, or \"override default trust store\" must be used while creating the TLS context.",
            ),
            ("ERROR_IO_STREAM_SEEK_FAILED", ERROR_IO_STREAM_SEEK_FAILED, "Stream failed to seek from the underlying I/O source."),
            ("ERROR_IO_STREAM_GET_LENGTH_FAILED", ERROR_IO_STREAM_GET_LENGTH_FAILED, "Stream failed to get length from the underlying I/O source."),
            ("ERROR_IO_STREAM_SEEK_UNSUPPORTED", ERROR_IO_STREAM_SEEK_UNSUPPORTED, "Seek is not supported in the underlying I/O source."),
            ("ERROR_IO_STREAM_GET_LENGTH_UNSUPPORTED", ERROR_IO_STREAM_GET_LENGTH_UNSUPPORTED, "Get length is not supported in the underlying I/O source."),
            ("ERROR_IO_TLS_ERROR_READ_FAILURE", ERROR_IO_TLS_ERROR_READ_FAILURE, "Failure during TLS read."),
            ("ERROR_IO_PEM_MALFORMED", ERROR_IO_PEM_MALFORMED, "Malformed PEM object encountered."),
            ("ERROR_IO_SOCKET_MISSING_EVENT_LOOP", ERROR_IO_SOCKET_MISSING_EVENT_LOOP, "Socket is missing its event loop."),
            ("ERROR_IO_TLS_UNKNOWN_ROOT_CERTIFICATE", ERROR_IO_TLS_UNKNOWN_ROOT_CERTIFICATE, "Channel shutdown due to tls unknown root certificate."),
            ("ERROR_IO_TLS_NO_ROOT_CERTIFICATE_FOUND", ERROR_IO_TLS_NO_ROOT_CERTIFICATE_FOUND, "Channel shutdown due to tls no root certificate found."),
            ("ERROR_IO_TLS_CERTIFICATE_EXPIRED", ERROR_IO_TLS_CERTIFICATE_EXPIRED, "Channel shutdown due to tls certificate expired."),
            ("ERROR_IO_TLS_CERTIFICATE_NOT_YET_VALID", ERROR_IO_TLS_CERTIFICATE_NOT_YET_VALID, "Channel shutdown due to tls certificate not yet valid."),
            ("ERROR_IO_TLS_BAD_CERTIFICATE", ERROR_IO_TLS_BAD_CERTIFICATE, "Channel shutdown due to tls certificate is malformed or not correctly formatted."),
            ("ERROR_IO_TLS_PEER_CERTIFICATE_EXPIRED", ERROR_IO_TLS_PEER_CERTIFICATE_EXPIRED, "Channel shutdown due to peer tls certificate is malformed or not correctly formatted."),
            ("ERROR_IO_TLS_BAD_PEER_CERTIFICATE", ERROR_IO_TLS_BAD_PEER_CERTIFICATE, "Channel shutdown due to peer tls certificate is malformed or not correctly formatted."),
            ("ERROR_IO_TLS_PEER_CERTIFICATE_REVOKED", ERROR_IO_TLS_PEER_CERTIFICATE_REVOKED, "Channel shutdown due to peer tls certificate has been revoked."),
            ("ERROR_IO_TLS_PEER_CERTIFICATE_UNKNOWN", ERROR_IO_TLS_PEER_CERTIFICATE_UNKNOWN, "Channel shutdown due to peer tls certificate is unknown."),
            ("ERROR_IO_TLS_INTERNAL_ERROR", ERROR_IO_TLS_INTERNAL_ERROR, "Channel shutdown due to internal SSL error."),
            ("ERROR_IO_TLS_CLOSED_GRACEFUL", ERROR_IO_TLS_CLOSED_GRACEFUL, "Channel shutdown due to connection closed gracefully."),
            ("ERROR_IO_TLS_CLOSED_ABORT", ERROR_IO_TLS_CLOSED_ABORT, "Channel shutdown due to connection closed due to an error."),
            ("ERROR_IO_TLS_INVALID_CERTIFICATE_CHAIN", ERROR_IO_TLS_INVALID_CERTIFICATE_CHAIN, "Channel shutdown due to invalid certificate chain."),
            ("ERROR_IO_TLS_HOST_NAME_MISMATCH", ERROR_IO_TLS_HOST_NAME_MISMATCH, "Channel shutdown due to certificate's host name does not match the endpoint host name."),
            ("ERROR_IO_DNS_QUERY_AGAIN", ERROR_IO_DNS_QUERY_AGAIN, "A temporary failure in name resolution occurred, please try again."),
        ),
    )
    defs
end

using LibAwsCal
using LibAwsCommon

const _io_error_entries_ref = Ref{Union{Nothing, Memory{error_info}}}(nothing)

const _io_error_list_ref = Ref{error_info_list}()

function _init_io_error_list!()
    entries = _io_error_entries_ref[]
    if entries === nothing
        count = ERROR_IO_DNS_QUERY_AGAIN - ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT + 1
        # Use Memory here for fixed-size storage and stable pointers for the error registry.
        entries = Memory{error_info}(undef, count)
        for (name, code, msg) in _io_error_definitions
            idx = code - ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT + 1
            entries[idx] = _define_error_info(code, name, msg, "aws-c-io")
        end
        _io_error_entries_ref[] = entries
    end
    _io_error_list_ref[] = error_info_list(
        pointer(entries),
        UInt16(length(entries)),
    )
    return nothing
end

const _io_log_subject_infos = let infos = Memory{LogSubjectInfo}(undef, 16)
    infos[1] = LogSubjectInfo(
        LS_IO_GENERAL,
        "aws-c-io",
        "Subject for IO logging that doesn't belong to any particular category",
    )
    infos[2] = LogSubjectInfo(LS_IO_EVENT_LOOP, "event-loop", "Subject for Event-loop specific logging.")
    infos[3] = LogSubjectInfo(LS_IO_SOCKET, "socket", "Subject for Socket specific logging.")
    infos[4] = LogSubjectInfo(LS_IO_SOCKET_HANDLER, "socket-handler", "Subject for a socket channel handler.")
    infos[5] = LogSubjectInfo(LS_IO_TLS, "tls-handler", "Subject for TLS-related logging")
    infos[6] = LogSubjectInfo(LS_IO_ALPN, "alpn", "Subject for ALPN-related logging")
    infos[7] = LogSubjectInfo(LS_IO_DNS, "dns", "Subject for DNS-related logging")
    infos[8] = LogSubjectInfo(LS_IO_PKI, "pki-utils", "Subject for Pki utilities.")
    infos[9] = LogSubjectInfo(LS_IO_CHANNEL, "channel", "Subject for Channels")
    infos[10] = LogSubjectInfo(
        LS_IO_CHANNEL_BOOTSTRAP,
        "channel-bootstrap",
        "Subject for channel bootstrap (client and server modes)",
    )
    infos[11] = LogSubjectInfo(LS_IO_FILE_UTILS, "file-utils", "Subject for file operations")
    infos[12] = LogSubjectInfo(LS_IO_SHARED_LIBRARY, "shared-library", "Subject for shared library operations")
    infos[13] = LogSubjectInfo(
        LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
        "exp-backoff-strategy",
        "Subject for exponential backoff retry strategy",
    )
    infos[14] = LogSubjectInfo(
        LS_IO_STANDARD_RETRY_STRATEGY,
        "standard-retry-strategy",
        "Subject for standard retry strategy",
    )
    infos[15] = LogSubjectInfo(LS_IO_PKCS11, "pkcs11", "Subject for PKCS#11 library operations")
    infos[16] = LogSubjectInfo(LS_IO_PEM, "pem", "Subject for pem operations")
    infos
end

const _io_log_subject_list = LogSubjectInfoList(_io_log_subject_infos)

const _cal_library_initialized = Ref(false)

function _cal_init()
    _cal_library_initialized[] && return nothing
    _cal_library_initialized[] = true
    allocator = LibAwsCommon.default_aws_allocator()
    LibAwsCommon.aws_common_library_init(allocator)
    LibAwsCal.aws_cal_library_init(allocator)
    return nothing
end

function _cal_cleanup()
    !_cal_library_initialized[] && return nothing
    _cal_library_initialized[] = false
    LibAwsCal.aws_cal_library_clean_up()
    LibAwsCommon.aws_common_library_clean_up()
    return nothing
end

const _io_library_initialized = Ref{Bool}(false)

function io_library_init()
    _io_library_initialized[] && return nothing
    _io_library_initialized[] = true
    _common_init()
    _cal_init()
    _init_io_error_list!()
    register_error_info(Base.unsafe_convert(Ptr{error_info_list}, _io_error_list_ref))
    register_log_subject_info_list(_io_log_subject_list)
    io_tracing_init()
    return nothing
end

function io_library_clean_up()
    !_io_library_initialized[] && return nothing
    _io_library_initialized[] = false
    unregister_log_subject_info_list(_io_log_subject_list)
    unregister_error_info(Base.unsafe_convert(Ptr{error_info_list}, _io_error_list_ref))
    _cal_cleanup()
    _common_cleanup()
    return nothing
end

function io_fatal_assert_library_initialized()
    if !_io_library_initialized[]
        logf(
            LogLevel.FATAL,
            LS_IO_GENERAL,
            "aws_io_library_init() must be called before using any functionality in aws-c-io.",
        )
        fatal_assert("io library init must be called first", "<unknown>", 0)
    end
    return nothing
end

# Helper for determining if an error code is retryable
function io_error_code_is_retryable(error_code::Integer)::Bool
    return error_code == ERROR_IO_SOCKET_CLOSED ||
        error_code == ERROR_IO_SOCKET_CONNECT_ABORTED ||
        error_code == ERROR_IO_SOCKET_CONNECTION_REFUSED ||
        error_code == ERROR_IO_SOCKET_NETWORK_DOWN ||
        error_code == ERROR_IO_DNS_QUERY_AGAIN ||
        error_code == ERROR_IO_DNS_NO_ADDRESS_FOR_HOST ||
        error_code == ERROR_IO_SOCKET_TIMEOUT ||
        error_code == ERROR_IO_TLS_NEGOTIATION_TIMEOUT
end

# Include tracing hooks (no-op)
include("tracing.jl")

# Include event loop abstractions and platform-specific implementations
include("event_loop.jl")
include("kqueue_event_loop.jl")
include("epoll_event_loop.jl")
include("dispatch_queue_event_loop.jl")
include("message_pool.jl")
include("socket.jl")
include("posix_socket.jl")
include("channel.jl")
include("statistics.jl")
include("socket_channel_handler.jl")
include("host_resolver.jl")
include("retry_strategy.jl")
include("stream.jl")
include("pem.jl")
include("pipe.jl")
include("shared_library.jl")
include("future.jl")
include("channel_bootstrap.jl")
