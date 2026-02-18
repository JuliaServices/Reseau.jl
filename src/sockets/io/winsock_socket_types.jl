# Winsock Socket type definitions
# Extracted for include-order: types must exist before Socket struct is defined.

@static if Sys.iswindows()
    # Track the one-in-flight overlapped operation used for connect/accept/readable monitoring.
    mutable struct WinsockIoOperationData{S}
        socket::Union{Nothing, S}
        signal::IocpOverlapped
        in_use::Bool
        sequential_task::Union{Nothing, ScheduledTask}
    end

    function WinsockIoOperationData{S}() where {S}
        return WinsockIoOperationData{S}(nothing, IocpOverlapped(), false, nothing)
    end

    # Connection args for stream connect timeout bookkeeping.
    mutable struct WinsockSocketConnectArgs{S}
        socket::Union{Nothing, S}
        timeout_task::Union{Nothing, ScheduledTask}
        io_data::WinsockIoOperationData{S}
    end

    # Pending write request (WriteFile() overlapped).
    mutable struct WinsockSocketWriteRequest{S}
        socket::Union{Nothing, S}
        detached::Bool
        cursor::ByteCursor
        original_len::Csize_t
        written_fn::Union{WriteCallable, Nothing}
        overlapped::IocpOverlapped
    end

    # Windows socket implementation state (Port of aws-c-io's iocp_socket)
    mutable struct WinsockSocket{S}
        read_io_data::WinsockIoOperationData{S}
        incoming_socket::Union{Nothing, S}
        accept_buffer::Memory{UInt8}
        connect_args::Union{WinsockSocketConnectArgs{S}, Nothing}
        pending_writes::Vector{WinsockSocketWriteRequest{S}}
        pending_write_indices::IdDict{WinsockSocketWriteRequest{S}, Int}
        stop_accept::Bool
        waiting_on_readable::Bool
        on_close_complete::Union{TaskFn, Nothing}
        on_cleanup_complete::Union{TaskFn, Nothing}
        cleaned_up::Bool
    end

    function WinsockSocket{S}() where {S}
        buf = Memory{UInt8}(undef, 288) # 2 * (sizeof(sockaddr_storage)+16) in aws-c-io
        return WinsockSocket{S}(
            WinsockIoOperationData{S}(),
            nothing,
            buf,
            nothing,
            WinsockSocketWriteRequest{S}[],
            IdDict{WinsockSocketWriteRequest{S}, Int}(),
            false,
            false,
            nothing,
            nothing,
            false,
        )
    end

    WinsockIoOperationData() = WinsockIoOperationData{Any}()
    WinsockSocket() = WinsockSocket{Any}()
else
    # Non-Windows builds keep a stub type so dispatch compiles.
    struct WinsockSocket end
end
