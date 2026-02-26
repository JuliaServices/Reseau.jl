module Sockets

# Reseau's libuv-free sockets surface.
#
# This module houses the channel + socket + TLS implementation that used to live
# under `src/io/*` (event-loops have moved to `Reseau.EventLoops`).

using EnumX
using ScopedValues: ScopedValue, @with
import UUIDs
using LibAwsCal
using LibAwsCommon

import ..Reseau:
    ByteBuffer,
    ByteCursor,
    ChannelCallable,
    ClockSource,
    ERROR_COND_VARIABLE_TIMED_OUT,
    ERROR_FILE_INVALID_PATH,
    ERROR_FILE_OPEN_FAILURE,
    ERROR_FILE_READ_FAILURE,
    ERROR_INVALID_ARGUMENT,
    ERROR_INVALID_BUFFER_SIZE,
    ERROR_INVALID_FILE_HANDLE,
    ERROR_INVALID_STATE,
    ERROR_IO_ALREADY_SUBSCRIBED,
    ERROR_IO_BROKEN_PIPE,
    ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT,
    ERROR_IO_CHANNEL_READ_WOULD_EXCEED_WINDOW,
    ERROR_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE,
    ERROR_IO_DNS_NO_ADDRESS_FOR_HOST,
    ERROR_IO_DNS_QUERY_AGAIN,
    ERROR_IO_DNS_QUERY_FAILED,
    ERROR_IO_EVENT_LOOP_ALREADY_ASSIGNED,
    ERROR_IO_EVENT_LOOP_SHUTDOWN,
    ERROR_IO_EVENT_LOOP_THREAD_ONLY,
    ERROR_IO_FILE_VALIDATION_FAILURE,
    ERROR_IO_MAX_RETRIES_EXCEEDED,
    ERROR_IO_MISSING_ALPN_MESSAGE,
    ERROR_IO_NOT_SUBSCRIBED,
    ERROR_IO_OPERATION_CANCELLED,
    ERROR_IO_PEM_MALFORMED,
    ERROR_IO_PKCS11_CKR_CANCEL,
    ERROR_IO_PKCS11_CKR_CRYPTOKI_ALREADY_INITIALIZED,
    ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED,
    ERROR_IO_PKCS11_CKR_FUNCTION_REJECTED,
    ERROR_IO_PKCS11_CKR_USER_ALREADY_LOGGED_IN,
    ERROR_IO_PKCS11_ENCODING_ERROR,
    ERROR_IO_PKCS11_KEY_NOT_FOUND,
    ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED,
    ERROR_IO_PKCS11_TOKEN_NOT_FOUND,
    ERROR_IO_PKCS11_UNKNOWN_CRYPTOKI_RETURN_VALUE,
    ERROR_IO_PKCS11_VERSION_UNSUPPORTED,
    ERROR_IO_READ_WOULD_BLOCK,
    ERROR_IO_RETRY_PERMISSION_DENIED,
    ERROR_IO_SHARED_LIBRARY_FIND_SYMBOL_FAILURE,
    ERROR_IO_SHARED_LIBRARY_LOAD_FAILURE,
    ERROR_IO_SOCKET_ADDRESS_IN_USE,
    ERROR_IO_SOCKET_CLOSED,
    ERROR_IO_SOCKET_CONNECTION_REFUSED,
    ERROR_IO_SOCKET_CONNECT_ABORTED,
    ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE,
    ERROR_IO_SOCKET_INVALID_ADDRESS,
    ERROR_IO_SOCKET_INVALID_OPERATION_FOR_TYPE,
    ERROR_IO_SOCKET_INVALID_OPTIONS,
    ERROR_IO_SOCKET_MISSING_EVENT_LOOP,
    ERROR_IO_SOCKET_NETWORK_DOWN,
    ERROR_IO_SOCKET_NOT_CONNECTED,
    ERROR_IO_SOCKET_NO_ROUTE_TO_HOST,
    ERROR_IO_SOCKET_TIMEOUT,
    ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY,
    ERROR_IO_STREAM_INVALID_SEEK_POSITION,
    ERROR_IO_STREAM_READ_FAILED,
    ERROR_IO_STREAM_SEEK_UNSUPPORTED,
    ERROR_IO_TLS_BAD_CERTIFICATE,
    ERROR_IO_TLS_BAD_PEER_CERTIFICATE,
    ERROR_IO_TLS_CERTIFICATE_EXPIRED,
    ERROR_IO_TLS_CERTIFICATE_NOT_YET_VALID,
    ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED,
    ERROR_IO_TLS_CLOSED_ABORT,
    ERROR_IO_TLS_CLOSED_GRACEFUL,
    ERROR_IO_TLS_CTX_ERROR,
    ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED,
    ERROR_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND,
    ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE,
    ERROR_IO_TLS_ERROR_NOT_NEGOTIATED,
    ERROR_IO_TLS_ERROR_READ_FAILURE,
    ERROR_IO_TLS_ERROR_WRITE_FAILURE,
    ERROR_IO_TLS_HOST_NAME_MISMATCH,
    ERROR_IO_TLS_INTERNAL_ERROR,
    ERROR_IO_TLS_INVALID_CERTIFICATE_CHAIN,
    ERROR_IO_TLS_NEGOTIATION_TIMEOUT,
    ERROR_IO_TLS_NO_ROOT_CERTIFICATE_FOUND,
    ERROR_IO_TLS_PEER_CERTIFICATE_EXPIRED,
    ERROR_IO_TLS_PEER_CERTIFICATE_REVOKED,
    ERROR_IO_TLS_PEER_CERTIFICATE_UNKNOWN,
    ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED,
    ERROR_IO_TLS_UNKNOWN_ROOT_CERTIFICATE,
    ERROR_IO_TLS_VERSION_UNSUPPORTED,
    ERROR_MAX_FDS_EXCEEDED,
    ERROR_NO_PERMISSION,
    ERROR_OOM,
    ERROR_PLATFORM_NOT_SUPPORTED,
    ERROR_SHORT_BUFFER,
    ERROR_STREAM_UNSEEKABLE,
    ERROR_SUCCESS,
    ERROR_SYS_CALL_FAILURE,
    ERROR_UNIMPLEMENTED,
    ERROR_UNKNOWN,
    EventCallable,
    EventLoops,
    HighResClock,
    IO_PACKAGE_ID,
    LRUCache,
    LogLevel,
    OP_SUCCESS,
    ReseauError,
    SIZE_MAX,
    STATISTICS_CATEGORY_BEGIN_RANGE,
    ScheduledTask,
    StatisticsCategory,
    StatisticsHandler,
    StatisticsSampleInterval,
    TIMESTAMP_MILLIS,
    TIMESTAMP_NANOS,
    TaskFn,
    TaskScheduler,
    TaskStatus,
    TlsDataReadCallback,
    WriteCallable,
    _PLATFORM_APPLE,
    _PLATFORM_WINDOWS,
    _SIZE_MAX_HALF,
    _callback_obj_to_ptr_and_root,
    _callback_ptr_to_obj,
    _coerce_task_status,
    _fcntl,
    _last_error,
    _write_gen_fptr,
    add_size_saturating,
    byte_buf_append,
    byte_buf_clean_up,
    byte_buf_clean_up_secure,
    byte_buf_from_c_str,
    byte_buf_from_empty_array,
    byte_buf_init,
    byte_buf_init_copy,
    byte_buf_init_copy_from_cursor,
    byte_buf_remaining_capacity,
    byte_buf_write,
    byte_buf_write_to_capacity,
    byte_buf_write_from_whole_buffer,
    byte_buf_write_from_whole_cursor,
    byte_buf_write_u8,
    byte_buffer_as_string,
    byte_cursor_advance,
    byte_cursor_from_array,
    byte_cursor_from_buf,
    cache_count,
    capacity,
    clock_now_ns,
    close!,
    cursor_getbyte,
    ensure_capacity!,
    error_name,
    fatal_assert,
    fatal_assert_bool,
    high_res_clock,
    high_res_clock_get_ticks,
    io_error_code_is_tls,
    last_error,
    logf,
    memref_advance,
    memref_offset,
    memref_parent,
    mul_size_saturating,
    null_buffer,
    null_cursor,
    process_statistics,
    raise_error,
    remove!,
    report_interval_ms,
    send!,
    sub_size_saturating,
    sys_clock_get_ticks,
    task_run!,
    task_scheduler_cancel!,
    task_scheduler_clean_up!,
    task_scheduler_has_tasks,
    task_scheduler_run_all!,
    task_scheduler_schedule_future!,
    task_scheduler_schedule_now!,
    throw_error,
    timedwait_poll,
    timedwait_poll_ns,
    timestamp_convert,
    translate_and_raise_io_error,
    translate_and_raise_io_error_or,
    use_lru!,
    write!

import ..ForeignThreads:
    ForeignThread,
    _maybe_precompile_park_foreign_thread,
    _maybe_precompile_yield_foreign_thread,
    join_all_managed,
    managed_thread_finished!,
    thread_id_t
using ..ForeignThreads: @wrap_thread_fn

import ..EventLoops:
    EventLoop,
    EventLoopGroup,
    Future,
    IoEventType,
    IoHandle,
    IoMessage,
    IoMessageType,
    LS_IO_ALPN,
    LS_IO_CHANNEL,
    LS_IO_CHANNEL_BOOTSTRAP,
    LS_IO_DNS,
    LS_IO_EVENT_LOOP,
    LS_IO_EXPONENTIAL_BACKOFF_RETRY_STRATEGY,
    LS_IO_GENERAL,
    LS_IO_PEM,
    LS_IO_PKCS11,
    LS_IO_PKI,
    LS_IO_SOCKET,
    LS_IO_SOCKET_HANDLER,
    LS_IO_STANDARD_RETRY_STRATEGY,
    LS_IO_TLS,
    MemoryPool,
    MessagePool,
    TLS_NEGOTIATED_PROTOCOL_MESSAGE,
    _cal_init,
    _close,
    _pkcs11_ckr_names,
    cancel!,
    cancel_task!,
    connect_to_io_completion_port,
    event_loop_thread_is_callers_thread,
    get_event_loop_group,
    get_next_event_loop,
    notify_exception!,
    pkcs11_error_code_str,
    register_tick_end!,
    register_tick_start!,
    run!,
    schedule_task_future!,
    schedule_task_now!,
    schedule_task_now_serialized!,
    stop!,
    subscribe_to_io_events!,
    unsubscribe_from_io_events!,
    wait_for_stop_completion

@static if Sys.iswindows()
    import ..EventLoops:
        IocpOverlapped,
        _win_get_last_error,
        iocp_overlapped_init!,
        iocp_overlapped_ptr,
        iocp_overlapped_reset!
end

const _io_library_initialized = Ref{Bool}(false)
const _io_library_init_pid = Ref{Int}(0)

function io_library_init()
    # Always refresh C callbacks; precompile can serialize C_NULL pointers.
    _host_resolver_init_cfunctions!()
    pid = Base.getpid()
    if _io_library_initialized[] && _io_library_init_pid[] == pid
        return nothing
    end
    _cal_init()
    _io_library_initialized[] = true
    _io_library_init_pid[] = pid
    return nothing
end

function io_library_clean_up()
    !_io_library_initialized[] && return nothing
    pid = Base.getpid()
    if _io_library_init_pid[] != 0 && _io_library_init_pid[] != pid
        _io_library_initialized[] = false
        _io_library_init_pid[] = 0
        return nothing
    end
    _io_library_initialized[] = false
    _io_library_init_pid[] = 0
    tls_clean_up_static_state()
    join_all_managed()
    return nothing
end

# --- IO implementation (moved from `src/io/*`) ---
include("io/tls_types.jl")
include("io/posix_socket_types.jl")
include("io/apple_nw_socket_types.jl")
include("io/winsock_socket_types.jl")
include("io/socket.jl")
include("io/posix_socket_impl.jl")
include("io/winsock_socket.jl")
include("io/winsock_init.jl")
include("io/blocks_abi.jl")
include("io/apple_nw_socket_impl.jl")
include("io/channel.jl")
include("io/statistics.jl")
include("io/socket_channel_handler.jl")
include("io/host_resolver.jl")
include("io/retry_strategy.jl")
include("io/stream.jl")
include("io/pem.jl")
include("io/pkcs11.jl")
include("io/pki_utils.jl")
include("io/pipe.jl")
include("io/iocp_pipe.jl")
include("io/channel_bootstrap_new.jl")

# Previously included directly from src/Reseau.jl
include("io/byte_helpers.jl")
include("io/crypto_primitives.jl")
include("io/tls_channel_handler.jl")
include("io/alpn_handler.jl")

# --- Public surface (stdlib-like TCP + LOCAL subset) ---
include("ipaddr.jl")
include("dns.jl")
include("tcp.jl")

end # module Sockets
