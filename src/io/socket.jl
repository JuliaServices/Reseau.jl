# AWS IO Library - Socket Abstraction
# Port of aws-c-io/include/aws/io/socket.h and source/socket.c

# Socket domain enum
@enumx SocketDomain::UInt8 begin
    IPV4 = 0
    IPV6 = 1
    LOCAL = 2   # Unix domain sockets
    VSOCK = 3   # Inter-VM communication
end

# Socket type enum
@enumx SocketType::UInt8 begin
    STREAM = 0  # TCP when used with IPV4/6, Unix domain sockets with LOCAL
    DGRAM = 1   # UDP when used with IPV4/6
end

# Socket implementation type
@enumx SocketImplType::UInt8 begin
    PLATFORM_DEFAULT = 0
    POSIX = 1
    WINSOCK = 2
    APPLE_NETWORK_FRAMEWORK = 3
end

# Channel direction enum (also used by channel.jl)
@enumx ChannelDirection::UInt8 begin
    READ = 0
    WRITE = 1
end

# Socket state enum
@enumx SocketState::UInt8 begin
    INIT = 0
    CONNECTING = 1
    CONNECTED = 2
    BOUND = 3
    LISTENING = 4
    HALF_CLOSED = 5
    CLOSED = 6
    ERROR = 7
end

# Constants
const NETWORK_INTERFACE_NAME_MAX = 16
# Unix socket path max - typically sizeof(sockaddr_un.sun_path) = 108 on Linux
@static if Sys.iswindows()
    const ADDRESS_MAX_LEN = 256
else
    const ADDRESS_MAX_LEN = 108
end

# Socket endpoint struct
mutable struct SocketEndpoint
    address::NTuple{ADDRESS_MAX_LEN, UInt8}
    port::UInt32
end

function SocketEndpoint()
    return SocketEndpoint(ntuple(_ -> UInt8(0), ADDRESS_MAX_LEN), UInt32(0))
end

function SocketEndpoint(address::AbstractString, port::Integer)
    endpoint = SocketEndpoint()
    set_address!(endpoint, address)
    endpoint.port = UInt32(port)
    return endpoint
end

function set_address!(endpoint::SocketEndpoint, address::AbstractString)
    bytes = codeunits(address)
    len = min(length(bytes), ADDRESS_MAX_LEN - 1)
    # Build new address tuple
    addr = ntuple(ADDRESS_MAX_LEN) do i
        if i <= len
            bytes[i]
        else
            UInt8(0)
        end
    end
    endpoint.address = addr
    return endpoint
end

function get_address(endpoint::SocketEndpoint)::String
    # Find null terminator
    addr = endpoint.address
    len = 0
    for i in 1:ADDRESS_MAX_LEN
        if addr[i] == 0
            break
        end
        len = i
    end
    return String(UInt8[addr[i] for i in 1:len])
end

function Base.copy!(dst::SocketEndpoint, src::SocketEndpoint)
    dst.address = src.address
    dst.port = src.port
    return dst
end

function Base.copy(src::SocketEndpoint)
    return SocketEndpoint(src.address, src.port)
end

# Socket options struct
mutable struct SocketOptions
    type::SocketType.T
    domain::SocketDomain.T
    impl_type::SocketImplType.T
    connect_timeout_ms::UInt32
    keep_alive_interval_sec::UInt16
    keep_alive_timeout_sec::UInt16
    keep_alive_max_failed_probes::UInt16
    keepalive::Bool
    network_interface_name::NTuple{NETWORK_INTERFACE_NAME_MAX, UInt8}
end

function SocketOptions(;
        type::SocketType.T = SocketType.STREAM,
        domain::SocketDomain.T = SocketDomain.IPV4,
        impl_type::SocketImplType.T = SocketImplType.PLATFORM_DEFAULT,
        connect_timeout_ms::Integer = 3000,
        keep_alive_interval_sec::Integer = 0,
        keep_alive_timeout_sec::Integer = 0,
        keep_alive_max_failed_probes::Integer = 0,
        keepalive::Bool = false,
        network_interface_name::AbstractString = "",
    )
    iface = ntuple(i -> i <= length(network_interface_name) ? UInt8(codeunit(network_interface_name, i)) : UInt8(0), NETWORK_INTERFACE_NAME_MAX)
    return SocketOptions(
        type,
        domain,
        impl_type,
        UInt32(connect_timeout_ms),
        UInt16(keep_alive_interval_sec),
        UInt16(keep_alive_timeout_sec),
        UInt16(keep_alive_max_failed_probes),
        keepalive,
        iface,
    )
end

function get_network_interface_name(options::SocketOptions)::String
    iface = options.network_interface_name
    len = 0
    for i in 1:NETWORK_INTERFACE_NAME_MAX
        if iface[i] == 0
            break
        end
        len = i
    end
    return String(UInt8[iface[i] for i in 1:len])
end

# Callback types
const SocketOnShutdownCompleteFn = Function  # (user_data) -> Nothing
const SocketOnConnectionResultFn = Function  # (socket, error_code, user_data) -> Nothing
const SocketOnAcceptStartedFn = Function     # (socket, error_code, user_data) -> Nothing
const SocketOnAcceptResultFn = Function      # (socket, error_code, new_socket, user_data) -> Nothing
const SocketOnWriteCompletedFn = Function    # (socket, error_code, bytes_written, user_data) -> Nothing
const SocketOnReadableFn = Function          # (socket, error_code, user_data) -> Nothing

# Forward declaration
abstract type AbstractSocket end
abstract type AbstractTlsConnectionOptions end

# Socket connect options
struct SocketConnectOptions{E <: Union{AbstractEventLoop, Nothing}, T <: Union{AbstractTlsConnectionOptions, Nothing}, F <: Union{SocketOnConnectionResultFn, Nothing}, U}
    remote_endpoint::SocketEndpoint
    event_loop::E  # nullable
    on_connection_result::F  # nullable
    user_data::U
    tls_connection_options::T  # nullable
end

function SocketConnectOptions(
        remote_endpoint::SocketEndpoint;
        event_loop::Union{AbstractEventLoop, Nothing} = nothing,
        on_connection_result::Union{SocketOnConnectionResultFn, Nothing} = nothing,
        user_data = nothing,
        tls_connection_options = nothing,
    )
    return SocketConnectOptions(
        remote_endpoint,
        event_loop,
        on_connection_result,
        user_data,
        tls_connection_options,
    )
end

# Socket bind options
struct SocketBindOptions{E <: Union{AbstractEventLoop, Nothing}, T <: Union{AbstractTlsConnectionOptions, Nothing}, U}
    local_endpoint::SocketEndpoint
    user_data::U
    event_loop::E  # nullable
    tls_connection_options::T  # nullable
end

function SocketBindOptions(
        local_endpoint::SocketEndpoint;
        user_data = nothing,
        event_loop::Union{AbstractEventLoop, Nothing} = nothing,
        tls_connection_options = nothing,
    )
    return SocketBindOptions(
        local_endpoint,
        user_data,
        event_loop,
        tls_connection_options,
    )
end

# Socket listener options
struct SocketListenerOptions{FR <: Union{SocketOnAcceptResultFn, Nothing}, UR, FS <: Union{SocketOnAcceptStartedFn, Nothing}, US}
    on_accept_result::FR  # nullable
    on_accept_result_user_data::UR
    on_accept_start::FS  # nullable
    on_accept_start_user_data::US
end

function SocketListenerOptions(;
        on_accept_result::Union{SocketOnAcceptResultFn, Nothing} = nothing,
        on_accept_result_user_data = nothing,
        on_accept_start::Union{SocketOnAcceptStartedFn, Nothing} = nothing,
        on_accept_start_user_data = nothing,
    )
    return SocketListenerOptions(
        on_accept_result,
        on_accept_result_user_data,
        on_accept_start,
        on_accept_start_user_data,
    )
end

# Socket vtable - defines the interface for socket implementations
abstract type SocketVTable end

# Socket struct - polymorphic socket with vtable dispatch
mutable struct Socket{V <: SocketVTable, I, H <: Union{AbstractChannelHandler, Nothing}, FR <: Union{SocketOnReadableFn, Nothing}, UR, FC <: Union{SocketOnConnectionResultFn, Nothing}, FA <: Union{SocketOnAcceptResultFn, Nothing}, UA} <: AbstractSocket
    vtable::V
    local_endpoint::SocketEndpoint
    remote_endpoint::SocketEndpoint
    options::SocketOptions
    io_handle::IoHandle
    event_loop::Union{EventLoop, Nothing}  # nullable
    handler::H  # nullable
    state::SocketState.T
    readable_fn::FR  # nullable
    readable_user_data::UR
    connection_result_fn::FC  # nullable
    accept_result_fn::FA  # nullable
    connect_accept_user_data::UA
    impl::I  # Platform-specific implementation data
end

# Vtable interface functions - must be implemented by platform-specific vtables

# Clean up socket resources
function socket_cleanup!(socket::Socket)
    return vtable_socket_cleanup!(socket.vtable, socket)
end

function vtable_socket_cleanup!(vtable::SocketVTable, socket::Socket)
    error("vtable_socket_cleanup! must be implemented by socket vtable")
end

# Connect to a remote endpoint
function socket_connect(socket::Socket, options::SocketConnectOptions)::Union{Nothing, ErrorResult}
    return vtable_socket_connect(socket.vtable, socket, options)
end

function vtable_socket_connect(vtable::SocketVTable, socket::Socket, options::SocketConnectOptions)::Union{Nothing, ErrorResult}
    error("vtable_socket_connect must be implemented by socket vtable")
end

# Bind to a local endpoint
function socket_bind(socket::Socket, options::SocketBindOptions)::Union{Nothing, ErrorResult}
    return vtable_socket_bind(socket.vtable, socket, options)
end

function vtable_socket_bind(vtable::SocketVTable, socket::Socket, options::SocketBindOptions)::Union{Nothing, ErrorResult}
    error("vtable_socket_bind must be implemented by socket vtable")
end

# Start listening for connections
function socket_listen(socket::Socket, backlog_size::Integer)::Union{Nothing, ErrorResult}
    return vtable_socket_listen(socket.vtable, socket, backlog_size)
end

function vtable_socket_listen(vtable::SocketVTable, socket::Socket, backlog_size::Integer)::Union{Nothing, ErrorResult}
    error("vtable_socket_listen must be implemented by socket vtable")
end

# Start accepting connections
function socket_start_accept(socket::Socket, accept_loop::EventLoop, options::SocketListenerOptions)::Union{Nothing, ErrorResult}
    return vtable_socket_start_accept(socket.vtable, socket, accept_loop, options)
end

function vtable_socket_start_accept(vtable::SocketVTable, socket::Socket, accept_loop::EventLoop, options::SocketListenerOptions)::Union{Nothing, ErrorResult}
    error("vtable_socket_start_accept must be implemented by socket vtable")
end

# Stop accepting connections
function socket_stop_accept(socket::Socket)::Union{Nothing, ErrorResult}
    return vtable_socket_stop_accept(socket.vtable, socket)
end

function vtable_socket_stop_accept(vtable::SocketVTable, socket::Socket)::Union{Nothing, ErrorResult}
    error("vtable_socket_stop_accept must be implemented by socket vtable")
end

# Close the socket
function socket_close(socket::Socket)::Union{Nothing, ErrorResult}
    return vtable_socket_close(socket.vtable, socket)
end

function vtable_socket_close(vtable::SocketVTable, socket::Socket)::Union{Nothing, ErrorResult}
    error("vtable_socket_close must be implemented by socket vtable")
end

# Shutdown direction (read or write)
function socket_shutdown_dir(socket::Socket, dir::ChannelDirection.T)::Union{Nothing, ErrorResult}
    return vtable_socket_shutdown_dir(socket.vtable, socket, dir)
end

function vtable_socket_shutdown_dir(vtable::SocketVTable, socket::Socket, dir::ChannelDirection.T)::Union{Nothing, ErrorResult}
    error("vtable_socket_shutdown_dir must be implemented by socket vtable")
end

# Set socket options
function socket_set_options(socket::Socket, options::SocketOptions)::Union{Nothing, ErrorResult}
    return vtable_socket_set_options(socket.vtable, socket, options)
end

function vtable_socket_set_options(vtable::SocketVTable, socket::Socket, options::SocketOptions)::Union{Nothing, ErrorResult}
    error("vtable_socket_set_options must be implemented by socket vtable")
end

# Assign socket to event loop
function socket_assign_to_event_loop(socket::Socket, event_loop::EventLoop)::Union{Nothing, ErrorResult}
    return vtable_socket_assign_to_event_loop(socket.vtable, socket, event_loop)
end

function vtable_socket_assign_to_event_loop(vtable::SocketVTable, socket::Socket, event_loop::EventLoop)::Union{Nothing, ErrorResult}
    error("vtable_socket_assign_to_event_loop must be implemented by socket vtable")
end

# Subscribe to readable events
function socket_subscribe_to_readable_events(socket::Socket, on_readable::SocketOnReadableFn, user_data)::Union{Nothing, ErrorResult}
    return vtable_socket_subscribe_to_readable_events(socket.vtable, socket, on_readable, user_data)
end

function vtable_socket_subscribe_to_readable_events(vtable::SocketVTable, socket::Socket, on_readable::SocketOnReadableFn, user_data)::Union{Nothing, ErrorResult}
    error("vtable_socket_subscribe_to_readable_events must be implemented by socket vtable")
end

# Read from socket
function socket_read(socket::Socket, buffer::ByteBuffer)::Union{Tuple{Nothing, Csize_t}, ErrorResult}
    return vtable_socket_read(socket.vtable, socket, buffer)
end

function vtable_socket_read(vtable::SocketVTable, socket::Socket, buffer::ByteBuffer)::Union{Tuple{Nothing, Csize_t}, ErrorResult}
    error("vtable_socket_read must be implemented by socket vtable")
end

# Write to socket
function socket_write(socket::Socket, cursor::ByteCursor, written_fn::Union{SocketOnWriteCompletedFn, Nothing}, user_data)::Union{Nothing, ErrorResult}
    return vtable_socket_write(socket.vtable, socket, cursor, written_fn, user_data)
end

function vtable_socket_write(vtable::SocketVTable, socket::Socket, cursor::ByteCursor, written_fn::Union{SocketOnWriteCompletedFn, Nothing}, user_data)::Union{Nothing, ErrorResult}
    error("vtable_socket_write must be implemented by socket vtable")
end

# Get socket error
function socket_get_error(socket::Socket)::Int
    return vtable_socket_get_error(socket.vtable, socket)
end

function vtable_socket_get_error(vtable::SocketVTable, socket::Socket)::Int
    error("vtable_socket_get_error must be implemented by socket vtable")
end

# Check if socket is open
function socket_is_open(socket::Socket)::Bool
    return vtable_socket_is_open(socket.vtable, socket)
end

function vtable_socket_is_open(vtable::SocketVTable, socket::Socket)::Bool
    error("vtable_socket_is_open must be implemented by socket vtable")
end

# Set close complete callback (Apple Network Framework only)
function socket_set_close_complete_callback(socket::Socket, fn::SocketOnShutdownCompleteFn, user_data)::Union{Nothing, ErrorResult}
    return vtable_socket_set_close_callback(socket.vtable, socket, fn, user_data)
end

function vtable_socket_set_close_callback(vtable::SocketVTable, socket::Socket, fn::SocketOnShutdownCompleteFn, user_data)::Union{Nothing, ErrorResult}
    # Default implementation - not supported on most platforms
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end

# Set cleanup complete callback (Apple Network Framework only)
function socket_set_cleanup_complete_callback(socket::Socket, fn::SocketOnShutdownCompleteFn, user_data)::Union{Nothing, ErrorResult}
    return vtable_socket_set_cleanup_callback(socket.vtable, socket, fn, user_data)
end

function vtable_socket_set_cleanup_callback(vtable::SocketVTable, socket::Socket, fn::SocketOnShutdownCompleteFn, user_data)::Union{Nothing, ErrorResult}
    # Default implementation - not supported on most platforms
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end

# Non-vtable helper functions

# Get event loop from socket
function socket_get_event_loop(socket::Socket)::Union{EventLoop, Nothing}
    return socket.event_loop
end

# Get bound address
function socket_get_bound_address(socket::Socket)::Union{SocketEndpoint, ErrorResult}
    if socket.local_endpoint.address[1] == 0
        logf(
            LogLevel.ERROR, LS_IO_SOCKET,
            "Socket has no local address. Socket must be bound first. fd=$(socket.io_handle.fd)"
        )
        raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
        return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
    end
    return copy(socket.local_endpoint)
end

# Get default socket implementation type
function socket_get_default_impl_type()::SocketImplType.T
    @static if Sys.islinux() || Sys.isbsd() || Sys.isapple()
        return SocketImplType.POSIX
    elseif Sys.iswindows()
        return SocketImplType.WINSOCK
    else
        return SocketImplType.PLATFORM_DEFAULT
    end
end

# Validate port for connect operation
function socket_validate_port_for_connect(port::Integer, domain::SocketDomain.T)::Union{Nothing, ErrorResult}
    # Local domain doesn't use ports
    if domain == SocketDomain.LOCAL
        return nothing
    end

    # VSOCK domain doesn't use ports in the same way
    if domain == SocketDomain.VSOCK
        return nothing
    end

    # TCP/UDP ports must be 1-65535 for connect
    if port < 1 || port > 65535
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Invalid port $port for connect (must be 1-65535)")
        raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
        return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
    end

    return nothing
end

# Validate port for bind operation
function socket_validate_port_for_bind(port::Integer, domain::SocketDomain.T)::Union{Nothing, ErrorResult}
    # Local domain doesn't use ports
    if domain == SocketDomain.LOCAL
        return nothing
    end

    # VSOCK domain doesn't use ports in the same way
    if domain == SocketDomain.VSOCK
        return nothing
    end

    # TCP/UDP ports must be 0-65535 for bind (0 = ephemeral)
    if port < 0 || port > 65535
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Invalid port $port for bind (must be 0-65535)")
        raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
        return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
    end

    return nothing
end

# Initialize local address for testing (Unix domain sockets)
function socket_endpoint_init_local_address_for_test!(endpoint::SocketEndpoint)
    uuid_result = uuid_init()
    if uuid_result isa ErrorResult
        error("Failed to generate UUID for test socket")
    end
    uuid = uuid_result

    uuid_str = uuid_to_str(uuid)
    if uuid_str isa ErrorResult
        error("Failed to convert UUID to string")
    end

    impl_type = socket_get_default_impl_type()
    if impl_type == SocketImplType.APPLE_NETWORK_FRAMEWORK
        set_address!(endpoint, "testsock$(uuid_str).local")
    elseif impl_type == SocketImplType.POSIX
        set_address!(endpoint, "testsock$(uuid_str).sock")
    elseif impl_type == SocketImplType.WINSOCK
        set_address!(endpoint, "\\\\.\\pipe\\testsock$(uuid_str)")
    end

    return endpoint
end

# Check if network interface name is valid
function is_network_interface_name_valid(interface_name::AbstractString)::Bool
    @static if Sys.iswindows()
        # Network interface binding not supported on Windows
        return false
    else
        # Non-empty name is considered potentially valid
        # Actual validation happens when trying to use it
        return !isempty(interface_name) && length(interface_name) < NETWORK_INTERFACE_NAME_MAX
    end
end

# Parse IPv4 address string to binary representation
function parse_ipv4_address(src::AbstractString)::Union{UInt32, ErrorResult}
    parts = split(src, '.')
    if length(parts) != 4
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Invalid IPv4 address format: $src")
        raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
        return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
    end

    result = UInt32(0)
    for (i, part) in enumerate(parts)
        val = tryparse(UInt8, part)
        if val === nothing
            logf(LogLevel.ERROR, LS_IO_SOCKET, "Invalid IPv4 address component: $part")
            raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
        end
        # Network byte order (big-endian)
        result |= UInt32(val) << (8 * (4 - i))
    end

    return result
end

# Parse IPv6 address string to binary representation
function parse_ipv6_address!(src::AbstractString, dst::ByteBuffer)::Union{Nothing, ErrorResult}
    # Check capacity
    if byte_buf_remaining_capacity(dst) < 16
        raise_error(ERROR_SHORT_BUFFER)
        return ErrorResult(ERROR_SHORT_BUFFER)
    end

    # Handle :: notation
    parts = split(src, "::")
    if length(parts) > 2
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Invalid IPv6 address format: multiple :: in $src")
        raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
        return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
    end

    left_parts = isempty(parts[1]) ? String[] : split(parts[1], ':')
    right_parts = length(parts) == 2 && !isempty(parts[2]) ? split(parts[2], ':') : String[]

    total_parts = length(left_parts) + length(right_parts)
    if total_parts > 8 || (length(parts) == 1 && total_parts != 8)
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Invalid IPv6 address format: wrong number of parts in $src")
        raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
        return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
    end

    zeros_needed = 8 - total_parts

    # Build 16-byte address
    addr = Memory{UInt8}(undef, 16)
    fill!(addr, 0x00)
    byte_idx = 1

    for part in left_parts
        val = tryparse(UInt16, part; base = 16)
        if val === nothing
            logf(LogLevel.ERROR, LS_IO_SOCKET, "Invalid IPv6 address component: $part")
            raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
        end
        addr[byte_idx] = UInt8((val >> 8) & 0xff)
        addr[byte_idx + 1] = UInt8(val & 0xff)
        byte_idx += 2
    end

    # Skip zeros
    byte_idx += zeros_needed * 2

    for part in right_parts
        val = tryparse(UInt16, part; base = 16)
        if val === nothing
            logf(LogLevel.ERROR, LS_IO_SOCKET, "Invalid IPv6 address component: $part")
            raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
        end
        addr[byte_idx] = UInt8((val >> 8) & 0xff)
        addr[byte_idx + 1] = UInt8(val & 0xff)
        byte_idx += 2
    end

    # Append to buffer
    byte_buf_append!(dst, addr)

    return nothing
end
