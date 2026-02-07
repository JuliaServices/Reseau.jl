# Epoll event loop type definitions
# Extracted from epoll_event_loop.jl so types exist before EventLoop is defined

@static if Sys.islinux()

    # Constants from sys/epoll.h
    const EPOLLIN = UInt32(0x0001)
    const EPOLLOUT = UInt32(0x0004)
    const EPOLLRDHUP = UInt32(0x2000)
    const EPOLLHUP = UInt32(0x0010)
    const EPOLLERR = UInt32(0x0008)
    const EPOLLET = UInt32(1 << 31)  # Edge-triggered

    const EPOLL_CTL_ADD = Cint(1)
    const EPOLL_CTL_DEL = Cint(2)
    const EPOLL_CTL_MOD = Cint(3)

    # epoll_event ABI is packed in the Linux UAPI headers: u32 events; u64 data; (12 bytes).
    # Use three UInt32 fields to match the packed layout across platforms.
    struct EpollEvent
        events::UInt32
        data_lo::UInt32
        data_hi::UInt32
    end

    @inline function EpollEvent(events::UInt32, ptr::Ptr{Cvoid})
        u = UInt64(UInt(ptr))
        return EpollEvent(events, UInt32(u & 0xffffffff), UInt32(u >> 32))
    end

    @inline function _epoll_event_data_ptr(ev::EpollEvent)::Ptr{Cvoid}
        u = (UInt64(ev.data_hi) << 32) | UInt64(ev.data_lo)
        return Ptr{Cvoid}(u)
    end

    # Constants for eventfd
    const EFD_CLOEXEC = Cint(0o2000000)
    const EFD_NONBLOCK = Cint(0o4000)

    # Configuration constants
    const DEFAULT_TIMEOUT_MS = 100 * 1000  # 100 seconds in milliseconds
    const MAX_EVENTS = 100

    # Pipe fd indices
    const READ_FD = 1
    const WRITE_FD = 2

    # fcntl flags (Linux)
    const O_NONBLOCK = Cint(0x0800)
    const O_CLOEXEC = Cint(0o2000000)

    # Handle data attached to IoHandle while subscribed
    mutable struct EpollEventHandleData{F <: OnEventCallback, U}
        handle::IoHandle
        on_event::F
        user_data::U
        cleanup_task::Union{Nothing, ScheduledTask}  # nullable
        is_subscribed::Bool  # false when handle is unsubscribed but struct not cleaned up yet
    end

    function EpollEventHandleData(
            handle::IoHandle,
            on_event::F,
            user_data::U,
        ) where {F <: OnEventCallback, U}
        return EpollEventHandleData{F, U}(
            handle,
            on_event,
            user_data,
            nothing,
            true,
        )
    end

    # Epoll event loop implementation data
    mutable struct EpollEventLoop
        scheduler::TaskScheduler
        thread_created_on::Union{Nothing, ThreadHandle}
        thread_joined_to::UInt64
        @atomic running_thread_id::UInt64
        read_task_handle::IoHandle
        write_task_handle::IoHandle
        task_pre_queue_mutex::ReentrantLock
        task_pre_queue::Vector{ScheduledTask}
        stop_task::Union{Nothing, ScheduledTask}
        @atomic stop_task_scheduled::Bool
        epoll_fd::Int32
        should_process_task_pre_queue::Bool
        should_continue::Bool
        thread_options::ThreadOptions
        use_eventfd::Bool  # true if using eventfd, false if using pipe
    end

    function EpollEventLoop()
        return EpollEventLoop(
            TaskScheduler(),
            nothing,
            UInt64(0),
            UInt64(0),
            IoHandle(),
            IoHandle(),
            ReentrantLock(),
            ScheduledTask[],
            nothing,
            false,
            Int32(-1),
            false,
            false,
            ThreadOptions(),
            false,
        )
    end

end # @static if Sys.islinux()
