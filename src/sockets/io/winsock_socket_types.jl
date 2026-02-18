# Winsock Socket type definitions
# Extracted for include-order: types must exist before Socket struct is defined.

@static if Sys.iswindows()
    # Pending write request (WriteFile() overlapped).
    mutable struct WinsockSocketWriteRequest
        detached::Bool
        cursor::ByteCursor
        original_len::Csize_t
        written_fn::Union{WriteCallable, Nothing}
        overlapped::IocpOverlapped
    end

    # Windows socket implementation state (Port of aws-c-io's iocp_socket)
    mutable struct WinsockSocket
        read_signal::IocpOverlapped
        read_in_use::Bool
        read_sequential_task::Union{Nothing, ScheduledTask}
        connect_timeout_task::Union{Nothing, ScheduledTask}
        connect_generation::UInt64
        connect_active::Bool
        incoming_accept_handle::Ptr{Cvoid}
        accept_buffer::Memory{UInt8}
        pending_writes::Vector{WinsockSocketWriteRequest}
        pending_write_indices::IdDict{WinsockSocketWriteRequest, Int}
        stop_accept::Bool
        waiting_on_readable::Bool
        on_close_complete::Union{TaskFn, Nothing}
        on_cleanup_complete::Union{TaskFn, Nothing}
        cleaned_up::Bool
    end

    function WinsockSocket()
        buf = Memory{UInt8}(undef, 288) # 2 * (sizeof(sockaddr_storage)+16) in aws-c-io
        return WinsockSocket(
            IocpOverlapped(),
            false,
            nothing,
            nothing,
            UInt64(0),
            false,
            C_NULL,
            buf,
            WinsockSocketWriteRequest[],
            IdDict{WinsockSocketWriteRequest, Int}(),
            false,
            false,
            nothing,
            nothing,
            false,
        )
    end
else
    # Non-Windows builds keep a stub type so dispatch compiles.
    struct WinsockSocket end
end
