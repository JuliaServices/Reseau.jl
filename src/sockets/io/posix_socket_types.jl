# POSIX Socket type definitions
# Extracted from posix_socket.jl for include-order: types must exist before Socket struct

# Socket write request for queued writes
mutable struct SocketWriteRequest
    cursor::ByteCursor
    original_len::Csize_t
    written_fn::Union{WriteCallable, Nothing}
    error_code::Int
    node_next::Union{SocketWriteRequest, Nothing}  # nullable
    node_prev::Union{SocketWriteRequest, Nothing}  # nullable
end

# POSIX socket connect args
mutable struct PosixSocketConnectArgs{S}
    task::Union{ScheduledTask, Nothing}
    socket::Union{S, Nothing}
end

# POSIX socket implementation data
mutable struct PosixSocket
    write_queue::Vector{SocketWriteRequest}
    written_queue::Vector{SocketWriteRequest}
    written_task::Union{ScheduledTask, Nothing}  # nullable
    connect_args::Union{PosixSocketConnectArgs, Nothing}  # nullable
    written_task_scheduled::Bool
    has_pending_readable_event::Bool
    currently_subscribed::Bool
    continue_accept::Bool
    accept_retry_task::Union{ScheduledTask, Nothing}  # nullable
    close_happened::Union{Ref{Bool}, Nothing}  # nullable
    on_close_complete::Union{TaskFn, Nothing}
    on_cleanup_complete::Union{TaskFn, Nothing}
end

function PosixSocket()
    return PosixSocket(
        SocketWriteRequest[],
        SocketWriteRequest[],
        nothing,
        nothing,
        false,
        false,
        false,
        false,
        nothing,
        nothing,
        nothing,
        nothing,
    )
end
