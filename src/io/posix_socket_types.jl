# POSIX Socket type definitions
# Extracted from posix_socket.jl for include-order: types must exist before Socket struct

# Socket write request for queued writes
mutable struct SocketWriteRequest
    cursor::ByteCursor
    original_len::Csize_t
    written_fn::Union{Function, Nothing}
    user_data::Any
    error_code::Int
    node_next::Union{SocketWriteRequest, Nothing}  # nullable
    node_prev::Union{SocketWriteRequest, Nothing}  # nullable
end

# POSIX socket connect args
mutable struct PosixSocketConnectArgs
    task::Union{ScheduledTask, Nothing}
    socket::Any  # Socket or nothing (Socket not defined yet)
end

# POSIX socket implementation data
mutable struct PosixSocket
    write_queue::Deque{SocketWriteRequest}
    written_queue::Deque{SocketWriteRequest}
    written_task::Union{ScheduledTask, Nothing}  # nullable
    connect_args::Union{PosixSocketConnectArgs, Nothing}  # nullable
    written_task_scheduled::Bool
    currently_subscribed::Bool
    continue_accept::Bool
    close_happened::Union{Ref{Bool}, Nothing}  # nullable
    on_close_complete::Union{Function, Nothing}
    close_user_data::Any
    on_cleanup_complete::Union{Function, Nothing}
    cleanup_user_data::Any
end

function PosixSocket()
    return PosixSocket(
        Deque{SocketWriteRequest}(),
        Deque{SocketWriteRequest}(),
        nothing,
        nothing,
        false,
        false,
        false,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
    )
end
