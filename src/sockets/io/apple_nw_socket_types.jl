# Apple Network Framework Socket type definitions
# Extracted from apple_nw_socket.jl for include-order: types must exist before Socket struct

@static if Sys.isapple()
    const _NW_NETWORK_LIB = "/System/Library/Frameworks/Network.framework/Network"
    const _NW_SECURITY_LIB = "/System/Library/Frameworks/Security.framework/Security"
    const _NW_DISPATCH_LIB = "libSystem"
    const _COREFOUNDATION_LIB = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

    # Backwards-compat feature flag:
    # Downstream packages historically checked `Reseau._NW_SHIM_LIB != ""` to
    # decide whether Apple Network.framework sockets were available. The shim
    # shared library has been removed; keep a non-empty sentinel on macOS.
    const _NW_SHIM_LIB = "<builtin>"

    const nw_connection_t = Ptr{Cvoid}
    const nw_listener_t = Ptr{Cvoid}
    const nw_parameters_t = Ptr{Cvoid}
    const nw_endpoint_t = Ptr{Cvoid}
    const nw_error_t = Ptr{Cvoid}
    const nw_path_t = Ptr{Cvoid}
    const nw_protocol_metadata_t = Ptr{Cvoid}
    const nw_protocol_definition_t = Ptr{Cvoid}
    const nw_protocol_options_t = Ptr{Cvoid}
    const nw_content_context_t = Ptr{Cvoid}
    const sec_protocol_options_t = Ptr{Cvoid}
    const sec_protocol_metadata_t = Ptr{Cvoid}
    const sec_trust_t = Ptr{Cvoid}
    const dispatch_data_t = Ptr{Cvoid}
    const dispatch_queue_t = Ptr{Cvoid}
    const CFErrorRef = Ptr{Cvoid}
    const CFStringRef = Ptr{Cvoid}
    const CFTypeRef = Ptr{Cvoid}
    const CFArrayRef = Ptr{Cvoid}
    const SecTrustRef = Ptr{Cvoid}
    const SecPolicyRef = Ptr{Cvoid}
    const SecIdentityRef = Ptr{Cvoid}
    const OSStatus = Int32

    const KB_16 = Csize_t(16 * 1024)

    @enumx NWSocketState::UInt16 begin
        INVALID = 0x000
        INIT = 0x001
        CONNECTING = 0x002
        CONNECTED_READ = 0x004
        CONNECTED_WRITE = 0x008
        BOUND = 0x010
        LISTENING = 0x020
        STOPPED = 0x040
        ERROR = 0x080
        CLOSING = 0x100
        CLOSED = 0x200
    end

    @enumx NWSocketMode::UInt8 begin
        CONNECTION = 0
        LISTENER = 1
    end

    mutable struct ReadQueueNode
        data::dispatch_data_t
        offset::Csize_t
    end

    mutable struct NWParametersContext
        socket::Any  # Socket (not defined yet at include time)
        options::Any  # SocketOptions (not defined yet at include time)
    end

    mutable struct NWSocket
        last_error::Int
        connection::nw_connection_t
        listener::nw_listener_t
        parameters::nw_parameters_t
        parameters_context::Union{NWParametersContext, Nothing}
        mode::NWSocketMode.T
        read_queue::Vector{ReadQueueNode}
        on_readable::Union{Function, Nothing}
        on_readable_user_data::Any
        on_connection_result::Union{Function, Nothing}
        connect_result_user_data::Any
        on_accept_started::Union{Function, Nothing}
        listen_accept_started_user_data::Any
        on_close_complete::Union{Function, Nothing}
        close_user_data::Any
        on_cleanup_complete::Union{Function, Nothing}
        cleanup_user_data::Any
        cleanup_requested::Bool
        event_loop::Union{EventLoop, Nothing}
        connection_setup::Bool
        timeout_task::Union{ScheduledTask, Nothing}
        host_name::Union{String, Nothing}
        alpn_list::Union{String, Nothing}
        tls_ctx::Union{Any, Nothing}
        protocol_buf::ByteBuffer
        synced_lock::ReentrantLock
        read_scheduled::Bool
        state::UInt16
        base_socket_lock::ReentrantLock
        base_socket::Any  # Socket or nothing (Socket not defined yet)
        pending_writes::Int
        registry_key::Ptr{Cvoid}
    end

    function NWSocket()
        return NWSocket(
            0,
            C_NULL,
            C_NULL,
            C_NULL,
            nothing,
            NWSocketMode.CONNECTION,
            ReadQueueNode[],
            nothing,
            nothing,
            nothing,
            nothing,
            nothing,
            nothing,
            nothing,
            nothing,
            nothing,
            nothing,
            false,
            nothing,
            false,
            nothing,
            nothing,
            nothing,
            nothing,
            null_buffer(),
            ReentrantLock(),
            false,
            UInt16(NWSocketState.INIT),
            ReentrantLock(),
            nothing,
            0,
            C_NULL,
        )
    end

    mutable struct NWSendContext
        socket::NWSocket
        written_fn::Union{Function, Nothing}
        user_data::Any
        registry_key::Ptr{Cvoid}
    end

    NWSendContext(socket::NWSocket, written_fn, user_data) = NWSendContext(socket, written_fn, user_data, C_NULL)
end
