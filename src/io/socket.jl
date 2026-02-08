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

# Channel direction enum (also used by channel.jl)
@enumx ChannelDirection::UInt8 begin
    READ = 0
    WRITE = 1
end

# Socket state bitmask (matches aws-c-io semantics)
@enumx SocketState::UInt16 begin
    NONE = 0x00
    INIT = 0x01
    CONNECTING = 0x02
    CONNECTED_READ = 0x04
    CONNECTED_WRITE = 0x08
    CONNECTED = 0x0c
    BOUND = 0x10
    LISTENING = 0x20
    CLOSED = 0x40
    ERROR = 0x80
end

@inline socket_state_has(state::SocketState.T, flag::SocketState.T) =
    (UInt16(state) & UInt16(flag)) != 0

@inline function socket_state_set(state::SocketState.T, flag::SocketState.T)::SocketState.T
    return SocketState.T(UInt16(state) | UInt16(flag))
end

@inline function socket_state_clear(state::SocketState.T, flag::SocketState.T)::SocketState.T
    return SocketState.T(UInt16(state) & ~UInt16(flag))
end

@inline function socket_state_mask(flags::SocketState.T...)::SocketState.T
    return SocketState.T(reduce(|, (UInt16(f) for f in flags); init = UInt16(0)))
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

# Socket connect options
struct SocketConnectOptions
    remote_endpoint::SocketEndpoint
    event_loop::Union{EventLoop, Nothing}
    on_connection_result::Union{Function, Nothing}
    user_data::Any
    tls_connection_options::Any  # TlsConnectionOptions or nothing
end

function SocketConnectOptions(
        remote_endpoint::SocketEndpoint;
        event_loop = nothing,
        on_connection_result = nothing,
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
struct SocketBindOptions
    local_endpoint::SocketEndpoint
    user_data::Any
    event_loop::Union{EventLoop, Nothing}
    tls_connection_options::Any  # TlsConnectionOptions or nothing
end

function SocketBindOptions(
        local_endpoint::SocketEndpoint;
        user_data = nothing,
        event_loop = nothing,
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
struct SocketListenerOptions
    on_accept_result::Union{Function, Nothing}
    on_accept_result_user_data::Any
    on_accept_start::Union{Function, Nothing}
    on_accept_start_user_data::Any
end

function SocketListenerOptions(;
        on_accept_result = nothing,
        on_accept_result_user_data = nothing,
        on_accept_start = nothing,
        on_accept_start_user_data = nothing,
    )
    return SocketListenerOptions(
        on_accept_result,
        on_accept_result_user_data,
        on_accept_start,
        on_accept_start_user_data,
    )
end

# Platform-specific socket implementation type
const PlatformSocketImpl = @static if Sys.isapple()
    Union{PosixSocket, NWSocket}
elseif Sys.iswindows()
    WinsockSocket
else
    PosixSocket
end

# Socket struct - non-parametric, dispatches on impl type
mutable struct Socket
    local_endpoint::SocketEndpoint
    remote_endpoint::SocketEndpoint
    options::SocketOptions
    io_handle::IoHandle
    event_loop::Union{EventLoop, Nothing}
    handler::Union{AbstractChannelHandler, Nothing}
    state::SocketState.T
    readable_fn::Union{Function, Nothing}
    readable_user_data::Any
    connection_result_fn::Union{Function, Nothing}
    accept_result_fn::Union{Function, Nothing}
    connect_accept_user_data::Any
    impl::Union{PlatformSocketImpl, Nothing}
end

# Initialize socket based on platform and domain
function socket_init(options::SocketOptions)::Union{Socket, ErrorResult}
    @static if Sys.isapple()
        # macOS: domain-based selection
        if options.domain == SocketDomain.LOCAL || options.domain == SocketDomain.VSOCK
            return socket_init_posix(options)
        else
            return socket_init_apple_nw(options)
        end
    elseif Sys.iswindows()
        return socket_init_winsock(options)
    else
        return socket_init_posix(options)
    end
end

# Socket interface - dispatches to platform-specific implementations via socket_*_impl

function socket_cleanup!(socket::Socket)
    socket.impl === nothing && return nothing
    return socket_cleanup_impl(socket.impl, socket)
end

function socket_connect(socket::Socket, options::SocketConnectOptions)::Union{Nothing, ErrorResult}
    return socket_connect_impl(socket.impl, socket, options)
end

function socket_bind(socket::Socket, options::SocketBindOptions)::Union{Nothing, ErrorResult}
    return socket_bind_impl(socket.impl, socket, options)
end

function socket_listen(socket::Socket, backlog_size::Integer)::Union{Nothing, ErrorResult}
    return socket_listen_impl(socket.impl, socket, backlog_size)
end

function socket_start_accept(socket::Socket, accept_loop::EventLoop, options::SocketListenerOptions)::Union{Nothing, ErrorResult}
    return socket_start_accept_impl(socket.impl, socket, accept_loop, options)
end

function socket_stop_accept(socket::Socket)::Union{Nothing, ErrorResult}
    return socket_stop_accept_impl(socket.impl, socket)
end

function socket_close(socket::Socket)::Union{Nothing, ErrorResult}
    return socket_close_impl(socket.impl, socket)
end

function socket_shutdown_dir(socket::Socket, dir::ChannelDirection.T)::Union{Nothing, ErrorResult}
    return socket_shutdown_dir_impl(socket.impl, socket, dir)
end

function socket_set_options(socket::Socket, options::SocketOptions)::Union{Nothing, ErrorResult}
    return socket_set_options_impl(socket.impl, socket, options)
end

function socket_assign_to_event_loop(socket::Socket, event_loop::EventLoop)::Union{Nothing, ErrorResult}
    return socket_assign_to_event_loop_impl(socket.impl, socket, event_loop)
end

function socket_subscribe_to_readable_events(socket::Socket, on_readable::SocketOnReadableFn, user_data)::Union{Nothing, ErrorResult}
    return socket_subscribe_to_readable_events_impl(socket.impl, socket, on_readable, user_data)
end

function socket_read(socket::Socket, buffer::ByteBuffer)::Union{Tuple{Nothing, Csize_t}, ErrorResult}
    return socket_read_impl(socket.impl, socket, buffer)
end

function socket_write(socket::Socket, cursor::ByteCursor, written_fn::Union{SocketOnWriteCompletedFn, Nothing}, user_data)::Union{Nothing, ErrorResult}
    return socket_write_impl(socket.impl, socket, cursor, written_fn, user_data)
end

function socket_get_error(socket::Socket)::Int
    return socket_get_error_impl(socket.impl, socket)
end

function socket_is_open(socket::Socket)::Bool
    return socket_is_open_impl(socket.impl, socket)
end

function socket_set_close_complete_callback(socket::Socket, fn::SocketOnShutdownCompleteFn, user_data)::Union{Nothing, ErrorResult}
    return socket_set_close_callback_impl(socket.impl, socket, fn, user_data)
end

function socket_set_cleanup_complete_callback(socket::Socket, fn::SocketOnShutdownCompleteFn, user_data)::Union{Nothing, ErrorResult}
    return socket_set_cleanup_callback_impl(socket.impl, socket, fn, user_data)
end

function socket_get_protocol(socket::Socket)::ByteBuffer
    return socket_get_protocol_impl(socket.impl, socket)
end

function socket_get_server_name(socket::Socket)::ByteBuffer
    return socket_get_server_name_impl(socket.impl, socket)
end

# Default implementations for methods only overridden by NW
socket_get_protocol_impl(::PosixSocket, ::Socket) = null_buffer()
socket_get_server_name_impl(::PosixSocket, ::Socket) = null_buffer()

# Non-dispatch helper functions

function socket_get_event_loop(socket::Socket)::Union{EventLoop, Nothing}
    return socket.event_loop
end

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

@inline function _socket_domain_valid(domain::SocketDomain.T)::Bool
    return domain == SocketDomain.IPV4 ||
        domain == SocketDomain.IPV6 ||
        domain == SocketDomain.LOCAL ||
        domain == SocketDomain.VSOCK
end

@inline function _socket_vsock_port_any(port::Integer)::Bool
    return port == -1 || port == typemax(UInt32)
end

# Validate port for connect operation
function socket_validate_port_for_connect(port::Integer, domain::SocketDomain.T)::Union{Nothing, ErrorResult}
    if !_socket_domain_valid(domain)
        raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
        return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
    end

    # Local domain doesn't use ports
    if domain == SocketDomain.LOCAL
        return nothing
    end

    # VSOCK domain doesn't use ports in the same way
    if domain == SocketDomain.VSOCK
        if _socket_vsock_port_any(port) || port < 0 || port > 0x7fffffff
            raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
        end
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
    if !_socket_domain_valid(domain)
        raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
        return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
    end

    # Local domain doesn't use ports
    if domain == SocketDomain.LOCAL
        return nothing
    end

    # VSOCK domain doesn't use ports in the same way
    if domain == SocketDomain.VSOCK
        if _socket_vsock_port_any(port)
            return nothing
        end
        if port < 0 || port > 0x7fffffff
            raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
        end
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
    u = Ref{uuid}()
    if uuid_init(u) != OP_SUCCESS
        error("Failed to generate UUID for test socket")
    end
    buf = Ref(ByteBuffer(UUID_STR_LEN))
    if uuid_to_str(u, buf) != OP_SUCCESS
        error("Failed to convert UUID to string")
    end
    uuid_str = String(byte_cursor_from_buf(buf[]))

    @static if Sys.iswindows()
        set_address!(endpoint, "\\\\.\\pipe\\testsock$(uuid_str)")
    else
        set_address!(endpoint, "testsock$(uuid_str).sock")
    end

    return endpoint
end

# Check if network interface name is valid
function is_network_interface_name_valid(interface_name::AbstractString)::Bool
    @static if Sys.iswindows()
        logf(LogLevel.ERROR, LS_IO_SOCKET, "network_interface_names are not supported on Windows")
        return false
    else
        if isempty(interface_name) || length(interface_name) >= NETWORK_INTERFACE_NAME_MAX
            return false
        end
        iface_index = ccall(:if_nametoindex, Cuint, (Cstring,), interface_name)
        if iface_index == 0
            err = Libc.errno()
            logf(
                LogLevel.ERROR,
                LS_IO_SOCKET,
                "network_interface_name(%s) is invalid with errno: %d",
                interface_name,
                err,
            )
            return false
        end
        return true
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

    if length(left_parts) > 1 && any(part -> occursin('.', part), left_parts[1:end-1])
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Invalid IPv6 address format: invalid IPv4 tail in $src")
        raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
        return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
    end
    if length(right_parts) > 1 && any(part -> occursin('.', part), right_parts[1:end-1])
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Invalid IPv6 address format: invalid IPv4 tail in $src")
        raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
        return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
    end

    ipv4_bytes = nothing
    ipv4_in_left = !isempty(left_parts) && occursin('.', left_parts[end])
    ipv4_in_right = !isempty(right_parts) && occursin('.', right_parts[end])

    if ipv4_in_left && ipv4_in_right
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Invalid IPv6 address format: multiple IPv4 tails in $src")
        raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
        return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
    end

    if ipv4_in_left
        ipv4_res = parse_ipv4_address(left_parts[end])
        if ipv4_res isa ErrorResult
            return ipv4_res
        end
        ipv4_val = ipv4_res
        ipv4_bytes = Memory{UInt8}(undef, 4)
        ipv4_bytes[1] = UInt8((ipv4_val >> 24) & 0xff)
        ipv4_bytes[2] = UInt8((ipv4_val >> 16) & 0xff)
        ipv4_bytes[3] = UInt8((ipv4_val >> 8) & 0xff)
        ipv4_bytes[4] = UInt8(ipv4_val & 0xff)
        left_parts = left_parts[1:end-1]
    elseif ipv4_in_right
        ipv4_res = parse_ipv4_address(right_parts[end])
        if ipv4_res isa ErrorResult
            return ipv4_res
        end
        ipv4_val = ipv4_res
        ipv4_bytes = Memory{UInt8}(undef, 4)
        ipv4_bytes[1] = UInt8((ipv4_val >> 24) & 0xff)
        ipv4_bytes[2] = UInt8((ipv4_val >> 16) & 0xff)
        ipv4_bytes[3] = UInt8((ipv4_val >> 8) & 0xff)
        ipv4_bytes[4] = UInt8(ipv4_val & 0xff)
        right_parts = right_parts[1:end-1]
    end

    ipv4_groups = ipv4_bytes === nothing ? 0 : 2
    total_parts = length(left_parts) + length(right_parts) + ipv4_groups
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

    if ipv4_bytes !== nothing
        addr[byte_idx] = ipv4_bytes[1]
        addr[byte_idx + 1] = ipv4_bytes[2]
        addr[byte_idx + 2] = ipv4_bytes[3]
        addr[byte_idx + 3] = ipv4_bytes[4]
        byte_idx += 4
    end

    # Append to buffer
    start_idx = Int(dst.len) + 1
    copyto!(dst.mem, start_idx, addr, 1, 16)
    dst.len = Csize_t(Int(dst.len) + 16)

    return nothing
end
