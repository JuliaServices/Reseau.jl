# KQueue event loop type definitions
# Extracted from kqueue_event_loop.jl so types exist before EventLoop is defined

@static if Sys.isapple() || Sys.isbsd()

    # Constants from sys/event.h
    const EVFILT_READ = Int16(-1)
    const EVFILT_WRITE = Int16(-2)
    const EV_ADD = UInt16(0x0001)
    const EV_DELETE = UInt16(0x0002)
    const EV_ENABLE = UInt16(0x0004)
    const EV_DISABLE = UInt16(0x0008)
    const EV_ONESHOT = UInt16(0x0010)
    const EV_CLEAR = UInt16(0x0020)
    const EV_RECEIPT = UInt16(0x0040)
    const EV_DISPATCH = UInt16(0x0080)
    const EV_EOF = UInt16(0x8000)
    const EV_ERROR = UInt16(0x4000)
    const READ_FD = 1
    const WRITE_FD = 2
    const O_NONBLOCK = Cint(0x0004)
    const FD_CLOEXEC = Cint(0x0001)

    # kevent structure - must match C struct layout
    # Note: ident is uintptr_t (pointer-sized unsigned), data is intptr_t (pointer-sized signed)
    struct Kevent
        ident::UInt         # identifier for this event (uintptr_t)
        filter::Int16       # filter for event
        flags::UInt16       # action flags for kqueue
        fflags::UInt32      # filter flag value
        data::Int           # filter data value (intptr_t)
        udata::Ptr{Cvoid}   # opaque user data identifier
    end

    function Kevent(fd::Integer, filter::Int16, flags::UInt16, udata::Ptr{Cvoid} = C_NULL)
        return Kevent(UInt(fd), filter, flags, UInt32(0), Int(0), udata)
    end

    function Kevent(
            fd::Integer,
            filter::Int16,
            flags::UInt16,
            fflags::UInt32,
            data::Int,
            udata::Ptr{Cvoid},
        )
        return Kevent(UInt(fd), filter, flags, fflags, data, udata)
    end

    # timespec structure for kevent timeout (must match `struct timespec`)
    struct Timespec
        tv_sec::Clong
        tv_nsec::Clong
    end

    # Event thread state
    @enumx EventThreadState::UInt8 begin
        READY_TO_RUN = 0
        RUNNING = 1
        STOPPING = 2
    end

    # Configuration constants
    # If we miss a cross-thread wakeup (e.g. signal pipe write fails), we still need to make
    # forward progress in a timely way (especially for STOPPING), so don't sleep for too long.
    const DEFAULT_TIMEOUT_SEC = 1
    const MAX_EVENTS = 100

    # Handle state for subscribed handles
    @enumx HandleState::UInt8 begin
        SUBSCRIBING = 0
        SUBSCRIBED = 1
        UNSUBSCRIBED = 2
    end

    # Handle data attached to IoHandle while subscribed
    mutable struct KqueueHandleData{F <: OnEventCallback, U}
        owner::IoHandle
        event_loop::Any  # EventLoop (not yet defined at include time)
        on_event::F
        on_event_user_data::U
        events_subscribed::Int  # IoEventType bitmask
        events_this_loop::Int   # Events received during current loop iteration
        state::HandleState.T
        subscribe_task::Union{Nothing, ScheduledTask}  # nullable
        cleanup_task::Union{Nothing, ScheduledTask}  # nullable
        registry_key::Ptr{Cvoid}
    end

    function KqueueHandleData(
            owner::IoHandle,
            event_loop,
            on_event::F,
            user_data::U,
            events::Int,
        ) where {F <: OnEventCallback, U}
        return KqueueHandleData{F, U}(
            owner,
            event_loop,
            on_event,
            user_data,
            events,
            0,
            HandleState.SUBSCRIBING,
            nothing,
            nothing,
            C_NULL,
        )
    end

    # Cross-thread data protected by mutex
    mutable struct KqueueCrossThreadData
        mutex::ReentrantLock
        thread_signaled::Bool
        tasks_to_schedule::Vector{ScheduledTask}
        state::EventThreadState.T
    end

    function KqueueCrossThreadData()
        return KqueueCrossThreadData(
            ReentrantLock(),
            false,
            ScheduledTask[],
            EventThreadState.READY_TO_RUN,
        )
    end

    # Thread-local data
    mutable struct KqueueThreadData
        scheduler::TaskScheduler
        connected_handle_count::Int
        state::EventThreadState.T
    end

    function KqueueThreadData()
        return KqueueThreadData(
            TaskScheduler(),
            0,
            EventThreadState.READY_TO_RUN,
        )
    end

    # KQueue event loop implementation data
    mutable struct KqueueEventLoop
        thread_created_on::Union{Nothing, ThreadHandle}
        thread_joined_to::UInt64
        @atomic running_thread_id::UInt64
        startup_event::Threads.Event
        @atomic startup_error::Int
        kq_fd::Int32
        cross_thread_signal_pipe::NTuple{2, Int32}
        cross_thread_data::KqueueCrossThreadData
        thread_data::KqueueThreadData
        thread_options::ThreadOptions
        handle_registry::Dict{Ptr{Cvoid}, Any}
        nw_queue::Ptr{Cvoid}  # dispatch_queue_t for Apple NW sockets
    end

    function KqueueEventLoop()
        return KqueueEventLoop(
            nothing,
            UInt64(0),
            UInt64(0),
            Threads.Event(),
            0,
            Int32(-1),
            (Int32(-1), Int32(-1)),
            KqueueCrossThreadData(),
            KqueueThreadData(),
            ThreadOptions(),
            Dict{Ptr{Cvoid}, Any}(),
            C_NULL,
        )
    end

end # @static if Sys.isapple() || Sys.isbsd()
