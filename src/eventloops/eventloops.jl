module EventLoops

# Reseau's libuv-free event loop surface.
#
# This module houses the native event-loop implementations (kqueue/epoll/iocp),
# along with the core IO definitions that the socket stack builds upon.

using EnumX

using ..Reseau:
    ByteBuffer,
    ERROR_ENUM_BEGIN_RANGE,
    ERROR_ENUM_END_RANGE,
    ERROR_INVALID_ARGUMENT,
    ERROR_INVALID_FILE_HANDLE,
    ERROR_INVALID_STATE,
    ERROR_PLATFORM_NOT_SUPPORTED,
    ERROR_SYS_CALL_FAILURE,
    ERROR_THREAD_NO_SUCH_THREAD_ID,
    EventCallable,
    LOG_SUBJECT_BEGIN_RANGE,
    LOG_SUBJECT_END_RANGE,
    LogLevel,
    LogSubject,
    LogSubjectInfo,
    ReseauError,
    ScheduledTask,
    TIMESTAMP_NANOS,
    TaskFn,
    TaskScheduler,
    TaskStatus,
    _coerce_task_status,
    _fcntl,
    _log_subject_registry,
    _register_errors!,
    add_u64_saturating,
    capacity,
    debug_assert,
    fatal_assert_bool,
    high_res_clock_get_ticks,
    logf,
    raise_error,
    task_run!,
    task_scheduler_cancel!,
    task_scheduler_clean_up!,
    task_scheduler_has_tasks,
    task_scheduler_run_all!,
    task_scheduler_schedule_future!,
    task_scheduler_schedule_now!,
    thread_sleep_ns,
    throw_error

using ..ForeignThreads: ForeignThread, managed_thread_finished!, @wrap_thread_fn

include("tracing.jl")
include("io.jl")
include("message_pool.jl")

include("kqueue_event_loop_types.jl")
include("epoll_event_loop_types.jl")
include("iocp_event_loop_types.jl")

include("event_loop.jl")
include("kqueue_event_loop.jl")
include("epoll_event_loop.jl")
include("iocp_event_loop.jl")

include("future.jl")

function __init__()
    @static if Sys.isapple() || Sys.isbsd()
        _kqueue_init_cfunctions!()
    elseif Sys.islinux()
        _epoll_init_cfunctions!()
    elseif Sys.iswindows()
        _iocp_init_cfunctions!()
    end
    return nothing
end

export
    EventLoop,
    EventLoopGroup,
    IoEventType,
    default_event_loop_group,
    event_loop_group_get_loop_count,
    event_loop_group_get_loop_at,
    event_loop_group_get_next_loop,
    event_loop_group_release!,
    event_loop_schedule_task_now!,
    event_loop_schedule_task_future!,
    event_loop_subscribe_to_io_events!,
    event_loop_unsubscribe_from_io_events!,
    event_loop_thread_is_callers_thread,
    # Futures
    Future,
    cancel!

end # module EventLoops
