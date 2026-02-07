# IOCP event loop type definitions
# Extracted from iocp_event_loop.jl so types exist before EventLoop is defined.

@static if Sys.iswindows()

    # Thread state for event-loop thread.
    @enumx IocpEventThreadState::UInt8 begin
        READY_TO_RUN = 0
        RUNNING = 1
        STOPPING = 2
    end

    mutable struct IocpSyncedData
        mutex::ReentrantLock
        thread_signaled::Bool
        tasks_to_schedule::Vector{ScheduledTask}
        state::IocpEventThreadState.T
    end

    function IocpSyncedData()
        return IocpSyncedData(
            ReentrantLock(),
            false,
            ScheduledTask[],
            IocpEventThreadState.READY_TO_RUN,
        )
    end

    mutable struct IocpThreadData
        scheduler::TaskScheduler
        state::IocpEventThreadState.T
    end

    function IocpThreadData()
        return IocpThreadData(
            TaskScheduler(),
            IocpEventThreadState.READY_TO_RUN,
        )
    end

    mutable struct IocpEventLoop
        iocp_handle::Ptr{Cvoid}
        thread_created_on::Union{Nothing, ThreadHandle}
        thread_joined_to::UInt64
        @atomic running_thread_id::UInt64
        synced_data::IocpSyncedData
        thread_data::IocpThreadData
        thread_options::ThreadOptions
    end

    function IocpEventLoop()
        return IocpEventLoop(
            C_NULL,
            nothing,
            UInt64(0),
            UInt64(0),
            IocpSyncedData(),
            IocpThreadData(),
            ThreadOptions(),
        )
    end

end # @static if Sys.iswindows()

