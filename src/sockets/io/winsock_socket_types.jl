# Winsock Socket type definitions
# Extracted for include-order: types must exist before Socket struct is defined.

@static if Sys.iswindows()
    # Track the one-in-flight overlapped operation used for connect/accept/readable monitoring.
    mutable struct WinsockIoOperationData
        socket::Any # Socket or nothing (Socket not defined yet at include time)
        signal::IocpOverlapped
        in_use::Bool
        sequential_task::Union{Nothing, ScheduledTask}
    end

    function WinsockIoOperationData()
        return WinsockIoOperationData(nothing, IocpOverlapped(), false, nothing)
    end

    # Connection args for stream connect timeout bookkeeping.
    mutable struct WinsockSocketConnectArgs
        socket::Any # Socket or nothing
        timeout_task::Union{Nothing, ScheduledTask}
        io_data::WinsockIoOperationData
    end

    # Pending write request (WriteFile() overlapped).
    mutable struct WinsockSocketWriteRequest
        socket::Any # Socket or nothing
        detached::Bool
        cursor::ByteCursor
        original_len::Csize_t
        written_fn::Union{Function, Nothing}
        user_data::Any
        overlapped::IocpOverlapped
    end

    # Windows socket implementation state (Port of aws-c-io's iocp_socket)
    mutable struct WinsockSocket
        read_io_data::WinsockIoOperationData
        incoming_socket::Any  # Socket or nothing
        accept_buffer::Memory{UInt8}
        connect_args::Union{WinsockSocketConnectArgs, Nothing}
        pending_writes::Vector{WinsockSocketWriteRequest}
        stop_accept::Bool
        waiting_on_readable::Bool
        on_close_complete::Union{Function, Nothing}
        close_user_data::Any
        on_cleanup_complete::Union{Function, Nothing}
        cleanup_user_data::Any
        cleaned_up::Bool
    end

    function WinsockSocket()
        buf = Memory{UInt8}(undef, 288) # 2 * (sizeof(sockaddr_storage)+16) in aws-c-io
        return WinsockSocket(
            WinsockIoOperationData(),
            nothing,
            buf,
            nothing,
            WinsockSocketWriteRequest[],
            false,
            false,
            nothing,
            nothing,
            nothing,
            nothing,
            false,
        )
    end
else
    # Non-Windows builds keep a stub type so dispatch compiles.
    struct WinsockSocket end
end
