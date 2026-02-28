# AWS IO Library - POSIX Socket Implementation
# Port of aws-c-io/source/posix/socket.c

# Platform-specific constants
@static if Sys.isapple()
    # On macOS, suppress SIGPIPE via setsockopt
    const NO_SIGNAL_SOCK_OPT = 0x1022  # SO_NOSIGPIPE
    const NO_SIGNAL_SEND = Cint(0)
    const TCP_KEEPIDLE = 0x10  # TCP_KEEPALIVE on macOS
else
    # On Linux, suppress SIGPIPE via MSG_NOSIGNAL flag to send()
    const NO_SIGNAL_SEND = Cint(0x4000)  # MSG_NOSIGNAL
end

# Socket address family constants
const AF_INET = Cint(2)
const AF_INET6 = @static Sys.isapple() ? Cint(30) : Cint(10)
const AF_UNIX = Cint(1)
@static if Sys.islinux()
    const AF_VSOCK = isdefined(Libc, :AF_VSOCK) ? Cint(Libc.AF_VSOCK) : Cint(40)
    const VMADDR_CID_ANY = UInt32(0xffffffff)
end

# Socket type constants
const SOCK_STREAM = Cint(1)
const SOCK_DGRAM = Cint(2)

# Socket option levels
const SOL_SOCKET = @static Sys.isapple() ? Cint(0xFFFF) : Cint(1)
const IPPROTO_TCP = Cint(6)
const IPPROTO_IP = Cint(0)
const IPPROTO_IPV6 = Cint(41)
const IP_BOUND_IF = @static Sys.isapple() ? (isdefined(Libc, :IP_BOUND_IF) ? Cint(Libc.IP_BOUND_IF) : Cint(25)) : Cint(0)
const IPV6_BOUND_IF = @static Sys.isapple() ? (isdefined(Libc, :IPV6_BOUND_IF) ? Cint(Libc.IPV6_BOUND_IF) : Cint(125)) : Cint(0)

# Socket options
const SO_REUSEADDR = @static Sys.isapple() ? Cint(0x04) : Cint(2)
const SO_KEEPALIVE = @static Sys.isapple() ? Cint(0x08) : Cint(9)
const SO_ERROR = @static Sys.isapple() ? Cint(0x1007) : Cint(4)
const SO_BINDTODEVICE = @static Sys.islinux() ? (isdefined(Libc, :SO_BINDTODEVICE) ? Cint(Libc.SO_BINDTODEVICE) : Cint(25)) : Cint(0)

# TCP keepalive options
@static if Sys.isapple()
    const TCP_KEEPINTVL = Cint(0x0101)  # TCP_KEEPINTVL on macOS
    const TCP_KEEPCNT = Cint(0x0102)    # TCP_KEEPCNT on macOS
else
    const TCP_KEEPIDLE_LINUX = Cint(4)
    const TCP_KEEPINTVL = Cint(5)
    const TCP_KEEPCNT = Cint(6)
end

# File control constants
const F_GETFD = Cint(1)
const F_SETFD = Cint(2)
const F_GETFL = Cint(3)
const F_SETFL = Cint(4)
const FD_CLOEXEC = Cint(1)
const O_NONBLOCK = @static Sys.isapple() ? Cint(0x0004) : Cint(0x0800)
const O_CLOEXEC = @static Sys.isapple() ? Cint(0x01000000) : Cint(0o2000000)

# Connect errno values
const EINPROGRESS = @static Sys.isapple() ? 36 : 115
const EALREADY = @static Sys.isapple() ? 37 : 114
const EINTR = 4
const EAGAIN = @static Sys.isapple() ? 35 : 11
const EWOULDBLOCK = EAGAIN
const ECONNREFUSED = @static Sys.isapple() ? 61 : 111
const ECONNRESET = @static Sys.isapple() ? 54 : 104
const ETIMEDOUT = @static Sys.isapple() ? 60 : 110
const EHOSTUNREACH = @static Sys.isapple() ? 65 : 113
const ENETUNREACH = @static Sys.isapple() ? 51 : 101
const EADDRNOTAVAIL = @static Sys.isapple() ? 49 : 99
const ENETDOWN = @static Sys.isapple() ? 50 : 100
const ECONNABORTED = @static Sys.isapple() ? 53 : 103
const EADDRINUSE = @static Sys.isapple() ? 48 : 98
const ENOBUFS = @static Sys.isapple() ? 55 : 105
const ENOMEM = 12
const EMFILE = 24
const ENFILE = 23
const ENOENT = 2
const EINVAL = 22
const EAFNOSUPPORT = @static Sys.isapple() ? 47 : 97
const EPERM = 1
const EACCES = 13
const ENODEV = 19
const EPIPE = @static Sys.isapple() ? 32 : 32
const _POLLIN = Cshort(0x0001)
const _POLLOUT = Cshort(0x0004)
const _POLLERR = Cshort(0x0008)
const _POLLHUP = Cshort(0x0010)
const _POLLNVAL = Cshort(0x0020)
const MSG_PEEK = Cint(2)

struct PollFd
    fd::Cint
    events::Cshort
    revents::Cshort
end

const NfdsT = @static (Sys.isapple() || Sys.isbsd()) ? Cuint : Culong

# Shutdown directions
const SHUT_RD = Cint(0)
const SHUT_WR = Cint(1)

# VSOCK sockaddr (Linux only)
@static if Sys.islinux()
    struct SockAddrVM
        svm_family::Cushort
        svm_reserved1::Cushort
        svm_port::UInt32
        svm_cid::UInt32
        svm_zero::NTuple{8, UInt8}
    end
    const _VSOCK_ZERO = ntuple(_ -> UInt8(0), 8)
end

@inline _posix_impl(sock::Socket)::PosixSocket = sock.impl::PosixSocket

# Convert domain enum to system constant
function convert_domain(domain::SocketDomain.T)::Cint
    if domain == SocketDomain.IPV4
        return AF_INET
    elseif domain == SocketDomain.IPV6
        return AF_INET6
    elseif domain == SocketDomain.LOCAL
        return AF_UNIX
    elseif domain == SocketDomain.VSOCK
        @static if Sys.islinux()
            return AF_VSOCK
        else
            error("Unsupported socket domain: $domain")
        end
    else
        error("Unsupported socket domain: $domain")
    end
end

# Convert type enum to system constant
function convert_socket_type(type::SocketType.T)::Cint
    if type == SocketType.STREAM
        return SOCK_STREAM
    elseif type == SocketType.DGRAM
        return SOCK_DGRAM
    else
        error("Unsupported socket type: $type")
    end
end

function _set_sockaddr_family!(sockaddr_buf::Memory{UInt8}, family::Cint, len::Integer)
    @static if Sys.isapple() || Sys.isbsd()
        sockaddr_buf[1] = UInt8(len)
        sockaddr_buf[2] = UInt8(family)
    else
        sockaddr_buf[1:2] .= reinterpret(UInt8, [Cshort(family)])
    end
    return nothing
end

# Convert errno to AWS error code
function determine_socket_error(errno_val::Integer)::Int
    if errno_val == ECONNREFUSED
        return ERROR_IO_SOCKET_CONNECTION_REFUSED
    elseif errno_val == ECONNRESET
        return ERROR_IO_SOCKET_CLOSED
    elseif errno_val == ETIMEDOUT
        return ERROR_IO_SOCKET_TIMEOUT
    elseif errno_val == EHOSTUNREACH || errno_val == ENETUNREACH
        return ERROR_IO_SOCKET_NO_ROUTE_TO_HOST
    elseif errno_val == EADDRNOTAVAIL
        return ERROR_IO_SOCKET_INVALID_ADDRESS
    elseif errno_val == ENETDOWN
        return ERROR_IO_SOCKET_NETWORK_DOWN
    elseif errno_val == ECONNABORTED
        return ERROR_IO_SOCKET_CONNECT_ABORTED
    elseif errno_val == EADDRINUSE
        return ERROR_IO_SOCKET_ADDRESS_IN_USE
    elseif errno_val == ENOBUFS || errno_val == ENOMEM
        return ERROR_OOM
    elseif errno_val == EAGAIN || errno_val == EWOULDBLOCK
        return ERROR_IO_READ_WOULD_BLOCK
    elseif errno_val == EMFILE || errno_val == ENFILE
        return ERROR_MAX_FDS_EXCEEDED
    elseif errno_val == ENOENT || errno_val == EINVAL
        return ERROR_FILE_INVALID_PATH
    elseif errno_val == EAFNOSUPPORT
        return ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY
    elseif errno_val == ENODEV
        return ERROR_PLATFORM_NOT_SUPPORTED
    elseif errno_val == EACCES || errno_val == EPERM
        return ERROR_NO_PERMISSION
    else
        return ERROR_IO_SOCKET_NOT_CONNECTED
    end
end

# Parse VSOCK CID from string (Linux only).

const _SOCKET_CONNECT_RETRY_DELAY_NS = UInt64(1_000_000)  # 1ms
const _SOCKET_ACCEPT_RETRY_DELAY_NS = _SOCKET_CONNECT_RETRY_DELAY_NS
const _SOCKET_READABLE_RETRY_DELAY_NS = UInt64(5_000_000) # 5ms
const _SOCKET_READABLE_RETRY_COUNT = 1000
const _SOCKET_WRITE_QUEUE_COMPACT_HEAD_THRESHOLD = 64

@inline function _write_request_queue_isempty(queue::SocketWriteRequestQueue)::Bool
    return queue.head > length(queue.items)
end

@inline function _write_request_queue_length(queue::SocketWriteRequestQueue)::Int
    remaining = length(queue.items) - queue.head + 1
    return remaining > 0 ? remaining : 0
end

@inline function _write_request_queue_front(queue::SocketWriteRequestQueue)::SocketWriteRequest
    return queue.items[queue.head]
end

@inline function _write_request_queue_push_back!(
    queue::SocketWriteRequestQueue,
    write_request::SocketWriteRequest,
)::Nothing
    push!(queue.items, write_request)
    return nothing
end

@inline function _write_request_queue_maybe_compact!(queue::SocketWriteRequestQueue)::Nothing
    if queue.head > length(queue.items)
        empty!(queue.items)
        queue.head = 1
        return nothing
    end

    consumed = queue.head - 1
    if consumed >= _SOCKET_WRITE_QUEUE_COMPACT_HEAD_THRESHOLD && consumed * 2 >= length(queue.items)
        deleteat!(queue.items, 1:consumed)
        queue.head = 1
    end
    return nothing
end

@inline function _write_request_queue_pop_front!(
    queue::SocketWriteRequestQueue,
)::SocketWriteRequest
    write_request = queue.items[queue.head]
    queue.head += 1
    _write_request_queue_maybe_compact!(queue)
    return write_request
end

function _parse_vsock_cid(address::AbstractString)::UInt32
    @static if Sys.islinux()
        if isempty(address)
            throw_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
        end
        if address == "-1"
            return VMADDR_CID_ANY
        end
        cid_val = try
            parse(Int64, address)
        catch
            throw_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
        end
        if cid_val < 0 || cid_val > typemax(UInt32)
            throw_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
        end
        return UInt32(cid_val)
    else
        throw_error(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
    end
end

# Type definitions are in posix_socket_types.jl

function _cancel_accept_retry_task_if_needed!(socket_impl::PosixSocket, event_loop::Union{EventLoop, Nothing})
    if socket_impl.accept_retry_task === nothing
        return nothing
    end

    if event_loop !== nothing
        cancel_task!(event_loop, socket_impl.accept_retry_task)
    end
    socket_impl.accept_retry_task = nothing
    return nothing
end

function _cancel_connect_pending_tasks!(
    sock::Socket,
    connect_args::PosixSocketConnectArgs;
    skip_task::Union{ScheduledTask, Nothing} = nothing,
)::Nothing
    # Canceling scheduled tasks may invoke callbacks synchronously with
    # `TaskStatus.CANCELED`; clear the shared socket pointer first so canceled
    # timeout/poll callbacks become no-ops instead of racing error paths.
    connect_args.socket = nothing

    event_loop = sock.event_loop
    can_cancel = event_loop !== nothing && (@atomic event_loop.running) &&
        event_loop_thread_is_callers_thread(event_loop)

    if can_cancel
        timeout_task = connect_args.task
        if timeout_task !== nothing && timeout_task !== skip_task && timeout_task.scheduled
            cancel_task!(event_loop, timeout_task)
        end

        retry_task = connect_args.poll_retry_task
        if retry_task !== nothing && retry_task !== skip_task && retry_task.scheduled
            cancel_task!(event_loop, retry_task)
        end
    end

    connect_args.task = nothing
    connect_args.poll_retry_task = nothing
    return nothing
end

function _schedule_connect_poll_retry_task!(sock::Socket, connect_args::PosixSocketConnectArgs{S}) where {S}
    if sock.impl === nothing
        return nothing
    end

    socket_impl = _posix_impl(sock)
    if connect_args.socket === nothing || !socket_impl.currently_subscribed
        return nothing
    end

    fd = sock.io_handle.fd
    connect_loop = sock.event_loop
    if connect_loop === nothing
        return nothing
    end

    if connect_args.poll_retry_task !== nothing && connect_args.poll_retry_task.scheduled
        return nothing
    end

    retry_task = ScheduledTask(; type_tag = "posix_connect_poll_retry") do status
        connect_args.poll_retry_task = nothing
        status = _coerce_task_status(status)
        if sock.impl === nothing || status != TaskStatus.RUN_READY
            return nothing
        end

        if connect_args.socket === nothing || !(_posix_impl(sock).currently_subscribed)
            return nothing
        end

        _run_connect_poll(connect_args, status)
        return nothing
    end
    connect_args.poll_retry_task = retry_task
    schedule_task_future!(
        connect_loop,
        retry_task,
        clock_now_ns() + _SOCKET_CONNECT_RETRY_DELAY_NS,
    )

    return nothing
end

function _schedule_accept_retry_task!(sock::Socket)
    @static if !Sys.islinux()
        return nothing
    end

    if sock.impl === nothing
        return nothing
    end

    socket_impl = _posix_impl(sock)
    if socket_impl.accept_retry_task !== nothing || !socket_impl.currently_subscribed || !socket_impl.continue_accept
        return nothing
    end

    accept_loop = sock.event_loop
    if accept_loop === nothing
        return nothing
    end

    retry_task = ScheduledTask(; type_tag = "posix_socket_start_accept_retry") do status
        status = _coerce_task_status(status)
        if sock.impl === nothing || status != TaskStatus.RUN_READY
            if sock.impl !== nothing
                _posix_impl(sock).accept_retry_task = nothing
            end
            return nothing
        end

        impl_now = _posix_impl(sock)
        impl_now.accept_retry_task = nothing

        if sock.event_loop !== accept_loop ||
            !impl_now.continue_accept ||
            !impl_now.currently_subscribed
            return nothing
        end

        _socket_accept_event(sock, Int(IoEventType.READABLE))
        return nothing
    end
    socket_impl.accept_retry_task = retry_task

    schedule_task_future!(
        accept_loop,
        retry_task,
        clock_now_ns() + _SOCKET_ACCEPT_RETRY_DELAY_NS,
    )

    return nothing
end

# Internal socket state as bitmask (matching C implementation)
const POSIX_SOCKET_STATE_INIT = 0x01
const POSIX_SOCKET_STATE_CONNECTING = 0x02
const POSIX_SOCKET_STATE_CONNECTED_READ = 0x04
const POSIX_SOCKET_STATE_CONNECTED_WRITE = 0x08
const POSIX_SOCKET_STATE_BOUND = 0x10
const POSIX_SOCKET_STATE_LISTENING = 0x20
const POSIX_SOCKET_STATE_TIMEDOUT = 0x40
const POSIX_SOCKET_STATE_ERROR = 0x80
const POSIX_SOCKET_STATE_CLOSED = 0x0100

# Internal helper to get errno
function get_errno()::Cint
    return ccall(:jl_errno, Cint, ())
end

# Internal helper to set errno
function set_errno(val::Integer)
    return ccall(:jl_set_errno, Cvoid, (Cint,), Cint(val))
end

# Create the underlying socket file descriptor
function create_posix_socket_fd(options::SocketOptions)::Cint
    if options.domain == SocketDomain.VSOCK
        @static if !Sys.islinux()
            throw_error(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
        end
    end

    domain = convert_domain(options.domain)
    sock_type = convert_socket_type(options.type)

    fd = ccall(:socket, Cint, (Cint, Cint, Cint), domain, sock_type, Cint(0))
    errno_val = get_errno()

    if fd == -1
        socket_error = determine_socket_error(errno_val)
        throw_error(socket_error)
    end

    # Set non-blocking and close-on-exec
    flags = _fcntl(fd, F_GETFL)
    flags |= O_NONBLOCK
    _fcntl(fd, F_SETFL, flags)

    fd_flags = _fcntl(fd, F_GETFD)
    fd_flags |= FD_CLOEXEC
    _fcntl(fd, F_SETFD, fd_flags)

    return fd
end

# Initialize a POSIX socket
function socket_init_posix(
        options::SocketOptions;
        existing_fd::Cint = Cint(-1),
    )::Socket

    socket_impl = PosixSocket()

    io_handle = IoHandle()
    if existing_fd < 0
        io_handle.fd = create_posix_socket_fd(options)
    else
        io_handle.fd = existing_fd
    end

    sock = Socket(
        SocketEndpoint(),
        SocketEndpoint(),
        copy(options),
        io_handle,
        nothing,  # event_loop
        SocketState.INIT,
        nothing,  # readable_fn
        nothing,  # connection_result_fn
        nothing,  # accept_result_fn
        socket_impl,
    )

    # Copy options for new socket
    sock.options = options

    # Set socket options
    try
        set_posix_socket_options!(sock, options)
    catch
        ccall(:close, Cint, (Cint,), io_handle.fd)
        rethrow()
    end

    logf(
        LogLevel.DEBUG, LS_IO_SOCKET,
        "Initializing POSIX socket with domain $(options.domain) and type $(options.type), fd=$(io_handle.fd)"
    )

    return sock
end

# Copy SocketOptions
function Base.copy(options::SocketOptions)
    return SocketOptions(;
        type = options.type,
        domain = options.domain,
        connect_timeout_ms = options.connect_timeout_ms,
        keep_alive_interval_sec = options.keep_alive_interval_sec,
        keep_alive_timeout_sec = options.keep_alive_timeout_sec,
        keep_alive_max_failed_probes = options.keep_alive_max_failed_probes,
        keepalive = options.keepalive,
        network_interface_name = options.network_interface_name,
    )
end

# Set socket options on the underlying fd
function set_posix_socket_options!(sock::Socket, options::SocketOptions)::Nothing
    fd = sock.io_handle.fd

    # Set NOSIGPIPE on macOS
    @static if Sys.isapple()
        opt_val = Ref{Cint}(1)
        ccall(
            :setsockopt, Cint, (Cint, Cint, Cint, Ptr{Cvoid}, Cuint),
            fd, SOL_SOCKET, NO_SIGNAL_SOCK_OPT, opt_val, sizeof(Cint)
        )
    end

    # Set SO_REUSEADDR
    opt_val = Ref{Cint}(1)
    ccall(
        :setsockopt, Cint, (Cint, Cint, Cint, Ptr{Cvoid}, Cuint),
        fd, SOL_SOCKET, SO_REUSEADDR, opt_val, sizeof(Cint)
    )

    # Bind to network interface if requested
    iface_name = get_network_interface_name(options)
    iface_len = ncodeunits(iface_name)

    if iface_len != 0
        if SO_BINDTODEVICE != 0
            ret = GC.@preserve iface_name begin
                ccall(
                    :setsockopt,
                    Cint,
                    (Cint, Cint, Cint, Ptr{Cvoid}, Cuint),
                    fd,
                    SOL_SOCKET,
                    SO_BINDTODEVICE,
                    pointer(iface_name),
                    Cuint(iface_len),
                )
            end
            if ret != 0
                errno_val = get_errno()
                logf(
                    LogLevel.ERROR,
                    LS_IO_SOCKET,
                    "fd=$fd: setsockopt(SO_BINDTODEVICE) for \"$iface_name\" failed with errno $errno_val",
                )
                throw_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
            end
        elseif IP_BOUND_IF != 0
            iface_index = ccall(:if_nametoindex, Cuint, (Cstring,), iface_name)
            if iface_index == 0
                errno_val = get_errno()
                logf(
                    LogLevel.ERROR,
                    LS_IO_SOCKET,
                    "fd=$fd: network_interface_name \"$iface_name\" not found; if_nametoindex() failed with errno $errno_val",
                )
                throw_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
            end

            idx_ref = Ref{Cuint}(iface_index)
            if options.domain == SocketDomain.IPV6
                ret = ccall(
                    :setsockopt,
                    Cint,
                    (Cint, Cint, Cint, Ptr{Cvoid}, Cuint),
                    fd,
                    IPPROTO_IPV6,
                    IPV6_BOUND_IF,
                    idx_ref,
                    sizeof(Cuint),
                )
                if ret != 0
                    errno_val = get_errno()
                    logf(
                        LogLevel.ERROR,
                        LS_IO_SOCKET,
                        "fd=$fd: setsockopt(IPV6_BOUND_IF) for \"$iface_name\" failed with errno $errno_val",
                    )
                    throw_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
                end
            else
                ret = ccall(
                    :setsockopt,
                    Cint,
                    (Cint, Cint, Cint, Ptr{Cvoid}, Cuint),
                    fd,
                    IPPROTO_IP,
                    IP_BOUND_IF,
                    idx_ref,
                    sizeof(Cuint),
                )
                if ret != 0
                    errno_val = get_errno()
                    logf(
                        LogLevel.ERROR,
                        LS_IO_SOCKET,
                        "fd=$fd: setsockopt(IP_BOUND_IF) for \"$iface_name\" failed with errno $errno_val",
                    )
                    throw_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
                end
            end
        else
            logf(
                LogLevel.ERROR,
                LS_IO_SOCKET,
                "fd=$fd: network_interface_name is not supported on this platform",
            )
            throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
        end
    end

    # Set TCP keepalive options if applicable
    if options.type == SocketType.STREAM && options.domain != SocketDomain.LOCAL
        if options.keepalive
            ka_val = Ref{Cint}(1)
            ccall(
                :setsockopt, Cint, (Cint, Cint, Cint, Ptr{Cvoid}, Cuint),
                fd, SOL_SOCKET, SO_KEEPALIVE, ka_val, sizeof(Cint)
            )
        end

        if options.keep_alive_interval_sec > 0 && options.keep_alive_timeout_sec > 0
            @static if Sys.isapple()
                idle_opt = TCP_KEEPIDLE
            else
                idle_opt = TCP_KEEPIDLE_LINUX
            end

            ival = Ref{Cint}(options.keep_alive_interval_sec)
            ccall(
                :setsockopt, Cint, (Cint, Cint, Cint, Ptr{Cvoid}, Cuint),
                fd, IPPROTO_TCP, idle_opt, ival, sizeof(Cint)
            )

            tval = Ref{Cint}(options.keep_alive_timeout_sec)
            ccall(
                :setsockopt, Cint, (Cint, Cint, Cint, Ptr{Cvoid}, Cuint),
                fd, IPPROTO_TCP, TCP_KEEPINTVL, tval, sizeof(Cint)
            )
        end

        if options.keep_alive_max_failed_probes > 0
            cnt_val = Ref{Cint}(options.keep_alive_max_failed_probes)
            ccall(
                :setsockopt, Cint, (Cint, Cint, Cint, Ptr{Cvoid}, Cuint),
                fd, IPPROTO_TCP, TCP_KEEPCNT, cnt_val, sizeof(Cint)
            )
        end
    end

    sock.options = copy(options)
    return nothing
end

# IPv4 sockaddr structure
struct SockaddrIn
    sin_family::Cshort
    sin_port::Cushort
    sin_addr::UInt32
    sin_zero::NTuple{8, UInt8}
end

# IPv6 sockaddr structure
struct SockaddrIn6
    sin6_family::Cushort
    sin6_port::Cushort
    sin6_flowinfo::Cuint
    sin6_addr::NTuple{16, UInt8}
    sin6_scope_id::Cuint
end

# Unix domain sockaddr structure
struct SockaddrUn
    sun_family::Cushort
    sun_path::NTuple{108, UInt8}
end

# Storage for any sockaddr type
struct SockaddrStorage
    data::NTuple{128, UInt8}
end

SockaddrStorage() = SockaddrStorage(ntuple(_ -> UInt8(0), 128))

# Parse IPv4 address using inet_pton
function inet_pton_ipv4(address::AbstractString)::UInt32
    addr_ref = Ref{UInt32}(0)
    result = ccall(:inet_pton, Cint, (Cint, Cstring, Ptr{UInt32}), AF_INET, address, addr_ref)
    if result != 1
        throw_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
    end
    return addr_ref[]
end

# Parse IPv6 address using inet_pton
function inet_pton_ipv6(address::AbstractString)::NTuple{16, UInt8}
    addr = Memory{UInt8}(undef, 16)
    result = GC.@preserve addr ccall(:inet_pton, Cint, (Cint, Cstring, Ptr{UInt8}), AF_INET6, address, pointer(addr))
    if result != 1
        throw_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
    end
    return ntuple(i -> addr[i], Val(16))
end

# Convert IPv4 to string
function inet_ntop_ipv4(addr::UInt32)::String
    buf = Memory{UInt8}(undef, 16)  # INET_ADDRSTRLEN
    addr_ref = Ref(addr)
    result = GC.@preserve buf addr_ref ccall(
        :inet_ntop, Cstring, (Cint, Ptr{UInt32}, Ptr{UInt8}, Cuint),
        AF_INET, addr_ref, pointer(buf), Cuint(16)
    )
    if result == C_NULL
        return ""
    end
    return unsafe_string(result)
end

# Convert IPv6 to string
function inet_ntop_ipv6(addr::NTuple{16, UInt8})::String
    buf = Memory{UInt8}(undef, 46)  # INET6_ADDRSTRLEN
    addr_mem = Memory{UInt8}(undef, length(addr))
    @inbounds for i in eachindex(addr)
        addr_mem[i] = addr[i]
    end
    result = GC.@preserve buf addr_mem ccall(
        :inet_ntop, Cstring, (Cint, Ptr{UInt8}, Ptr{UInt8}, Cuint),
        AF_INET6, pointer(addr_mem), pointer(buf), Cuint(46)
    )
    if result == C_NULL
        return ""
    end
    return unsafe_string(result)
end

# htons/ntohs
htons(x::Integer) = hton(UInt16(x))
ntohs(x::Integer) = ntoh(UInt16(x))

# POSIX impl - cleanup
function socket_cleanup_impl(::PosixSocket, sock::Socket)
    if sock.impl === nothing
        return nothing
    end

    socket_impl = _posix_impl(sock)
    fd_for_logging = sock.io_handle.fd

    if socket_is_open(sock)
        logf(LogLevel.DEBUG, LS_IO_SOCKET, "Socket fd=$fd_for_logging is still open, closing...")
        socket_close(sock)
    end

    on_cleanup_complete = socket_impl.on_cleanup_complete
    socket_impl.on_cleanup_complete = nothing
    socket_impl.on_close_complete = nothing

    sock.readable_fn = nothing
    sock.connection_result_fn = nothing
    sock.accept_result_fn = nothing

    # Reset socket fields
    sock.io_handle = IoHandle()
    sock.impl = nothing

    if on_cleanup_complete !== nothing
        on_cleanup_complete(UInt8(0))
    end

    return nothing
end

# POSIX impl - connect
function socket_connect_impl(
        ::PosixSocket,
        sock::Socket,
        remote_endpoint::SocketEndpoint,
        event_loop::Union{EventLoop, Nothing},
        on_connection_result::Union{EventCallable, Nothing},
        tls_connection_options::MaybeTlsConnectionOptions,
    )::Nothing
    _ = tls_connection_options

    fd = sock.io_handle.fd
    logf(LogLevel.DEBUG, LS_IO_SOCKET, "Socket fd=$fd: beginning connect")

    if sock.event_loop !== nothing
        throw_error(ERROR_IO_EVENT_LOOP_ALREADY_ASSIGNED)
    end

    event_loop === nothing && throw_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)

    if sock.options.type != SocketType.DGRAM
        if sock.state != SocketState.INIT
            throw_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
        end
    else
        # UDP sockets can be in INIT or CONNECTED_READ (if bound first)
        if sock.state != SocketState.INIT && !socket_state_has(sock.state, SocketState.CONNECTED_READ)
            throw_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
        end
    end

    # Validate port
    socket_validate_port_for_connect(remote_endpoint.port, sock.options.domain)

    address = get_address(remote_endpoint)
    port = remote_endpoint.port

    logf(LogLevel.DEBUG, LS_IO_SOCKET, "Socket fd=$fd: connecting to $address:$port")

    # Build sockaddr based on domain
    sockaddr_obj = nothing
    sockaddr_ptr = Ptr{UInt8}(0)
    sockaddr_len::Cuint = 0

    if sock.options.domain == SocketDomain.IPV4
        addr_result = inet_pton_ipv4(address)

        sockaddr_buf = Memory{UInt8}(undef, 128)
        fill!(sockaddr_buf, 0x00)
        _set_sockaddr_family!(sockaddr_buf, AF_INET, 16)
        sockaddr_buf[3:4] .= reinterpret(UInt8, [htons(port)])
        sockaddr_buf[5:8] .= reinterpret(UInt8, [addr_result])
        sockaddr_obj = sockaddr_buf
        sockaddr_ptr = pointer(sockaddr_buf)
        sockaddr_len = Cuint(16)  # sizeof(sockaddr_in)

    elseif sock.options.domain == SocketDomain.IPV6
        addr_result = inet_pton_ipv6(address)

        sockaddr_buf = Memory{UInt8}(undef, 128)
        fill!(sockaddr_buf, 0x00)
        _set_sockaddr_family!(sockaddr_buf, AF_INET6, 28)
        sockaddr_buf[3:4] .= reinterpret(UInt8, [htons(port)])
        @inbounds for i in 5:8
            sockaddr_buf[i] = 0x00
        end
        for i in 1:16
            sockaddr_buf[8 + i] = addr_result[i]
        end
        sockaddr_obj = sockaddr_buf
        sockaddr_ptr = pointer(sockaddr_buf)
        sockaddr_len = Cuint(28)  # sizeof(sockaddr_in6)

    elseif sock.options.domain == SocketDomain.LOCAL
        sockaddr_buf = Memory{UInt8}(undef, 128)
        fill!(sockaddr_buf, 0x00)
        sockaddr_len = @static (Sys.isapple() || Sys.isbsd()) ? Cuint(106) : Cuint(110)  # sizeof(sockaddr_un)
        _set_sockaddr_family!(sockaddr_buf, AF_UNIX, sockaddr_len)
        addr_bytes = Memory{UInt8}(codeunits(address))
        max_path_len = @static (Sys.isapple() || Sys.isbsd()) ? 104 : 108
        copy_len = min(length(addr_bytes), max_path_len)
        for i in 1:copy_len
            sockaddr_buf[2 + i] = addr_bytes[i]
        end
        sockaddr_obj = sockaddr_buf
        sockaddr_ptr = pointer(sockaddr_buf)
        # `sockaddr_len` already set above.
    elseif sock.options.domain == SocketDomain.VSOCK
        cid_result = _parse_vsock_cid(address)
        @static if Sys.islinux()
            vm_addr = SockAddrVM(Cushort(AF_VSOCK), Cushort(0), UInt32(port), cid_result, _VSOCK_ZERO)
            vm_ref = Ref(vm_addr)
            sockaddr_obj = vm_ref
            sockaddr_ptr = Ptr{UInt8}(Base.unsafe_convert(Ptr{SockAddrVM}, vm_ref))
            sockaddr_len = Cuint(sizeof(SockAddrVM))
        else
            throw_error(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
        end
    else
        throw_error(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
    end

    # Set socket state
    sock.state = SocketState.CONNECTING
    copy!(sock.remote_endpoint, remote_endpoint)
    sock.connection_result_fn = on_connection_result

    socket_impl = _posix_impl(sock)

    # Create connect args
    connect_args = PosixSocketConnectArgs(nothing, nothing, sock)
    socket_impl.connect_args = connect_args

    # Attempt to connect
    error_code = GC.@preserve sockaddr_obj ccall(
        :connect, Cint, (Cint, Ptr{UInt8}, Cuint),
        fd, sockaddr_ptr, sockaddr_len
    )
    errno_val = get_errno()

    sock.event_loop = event_loop

    if error_code == 0
        # Connected immediately (common for Unix domain sockets)
        logf(LogLevel.INFO, LS_IO_SOCKET, "Socket fd=$fd: connected immediately")

        # Schedule success callback
        connect_args.task = ScheduledTask(; type_tag = "posix_connect_success") do status
            try
                _run_connect_success(connect_args, _coerce_task_status(status))
            catch e
                Core.println("posix_connect_success task errored")
            end
            return nothing
        end
        schedule_task_now!(event_loop, connect_args.task)
        return nothing
    end

    if errno_val == EINPROGRESS || errno_val == EALREADY || errno_val == EINTR
        logf(LogLevel.TRACE, LS_IO_SOCKET, "Socket fd=$fd: connection pending")

        # Create timeout task
        timeout_task = ScheduledTask(; type_tag = "posix_connect_timeout") do status
            try
                _handle_socket_timeout(connect_args, _coerce_task_status(status))
            catch e
                Core.println("posix_connect_timeout task errored")
            end
            return nothing
        end
        connect_args.task = timeout_task

        # Subscribe to write events (connection completion triggers writable)
        socket_impl.currently_subscribed = true
        try
            subscribe_to_io_events!(
                event_loop,
                sock.io_handle,
                Int(IoEventType.WRITABLE),
                EventCallable(events -> _socket_connect_event(connect_args, events)),
            )
            schedule_task_now!(event_loop; type_tag = "posix_connect_poll") do status
                try
                    _run_connect_poll(connect_args, _coerce_task_status(status))
                catch e
                    Core.println("posix_connect_poll task errored")
                end
                return nothing
            end
        catch
            logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: failed to subscribe to event loop")
            socket_impl.currently_subscribed = false
            sock.event_loop = nothing
            socket_impl.connect_args = nothing
            rethrow()
        end

        # Schedule timeout
        timeout_ns = clock_now_ns()
        timeout_ns += UInt64(sock.options.connect_timeout_ms) * 1_000_000  # ms to ns

        logf(LogLevel.TRACE, LS_IO_SOCKET, "Socket fd=$fd: scheduling timeout at $timeout_ns")
        schedule_task_future!(event_loop, timeout_task, timeout_ns)

        return nothing
    end

    # Connection failed immediately
    logf(LogLevel.DEBUG, LS_IO_SOCKET, "Socket fd=$fd: connect failed with errno=$errno_val")
    socket_error = determine_socket_error(errno_val)
    sock.event_loop = nothing
    socket_impl.connect_args = nothing
    throw_error(socket_error)
end

function _is_socket_connect_ready_for_completion(fd::Integer)::Bool
    pollfd_ref = Ref(PollFd(Cint(fd), _POLLIN | _POLLOUT, Cshort(0)))
    rc = ccall(:poll, Cint, (Ptr{PollFd}, NfdsT, Cint), pollfd_ref, NfdsT(1), Cint(0))
    if rc <= 0
        return false
    end

    revents = pollfd_ref[].revents
    ready = (revents & _POLLOUT) != 0 && (revents & _POLLNVAL) == 0 &&
        (revents & _POLLERR) == 0 &&
        (revents & _POLLHUP) == 0
    if !ready
    end
    return ready
end

function _is_socket_readable_now(fd::Integer)::Bool
    pollfd_ref = Ref(PollFd(Cint(fd), _POLLIN, Cshort(0)))
    rc = ccall(:poll, Cint, (Ptr{PollFd}, NfdsT, Cint), pollfd_ref, NfdsT(1), Cint(0))
    if rc <= 0
        # Some kernels/edge-triggered paths can transiently clear pollable events,
        # so try a non-consuming readability probe before declaring not readable.
        peek_buf = Ref{UInt8}(0)
        peek_rc = ccall(
            :recv,
            Cssize_t,
            (Cint, Ptr{UInt8}, Csize_t, Cint),
            Cint(fd),
            peek_buf,
            Csize_t(1),
            MSG_PEEK,
        )
        if peek_rc > 0
            return true
        end
        if peek_rc == 0
            return true
        end
        if peek_rc < 0
            peek_errno = get_errno()
            if peek_errno != EAGAIN && peek_errno != EWOULDBLOCK
                return false
            end
        end
        return false
    end

    revents = pollfd_ref[].revents
    readable = (revents & _POLLIN) != 0 && (revents & _POLLNVAL) == 0 &&
        (revents & _POLLERR) == 0
    if !readable

        # Some kernels can transiently report no readable poll bits while data is still pending.
        # Fall back to a non-consuming peek read to avoid dropping valid readable callbacks.
        peek_buf = Ref{UInt8}(0)
        peek_rc = ccall(
            :recv,
            Cssize_t,
            (Cint, Ptr{UInt8}, Csize_t, Cint),
            Cint(fd),
            peek_buf,
            Csize_t(1),
            MSG_PEEK,
        )
        if peek_rc > 0
            return true
        end
        if peek_rc == 0
            return true
        end
        if peek_rc < 0
            peek_errno = get_errno()
            if peek_errno != EAGAIN && peek_errno != EWOULDBLOCK
                return false
            end
        end
        return false
    end
    return readable
end

function _schedule_socket_readable_recheck_task(
    sock::Socket,
    fd::Integer,
    retries_left::Int,
    allow_dgram::Bool = false,
)
    if retries_left <= 0 || sock.impl === nothing
        return nothing
    end

    event_loop = sock.event_loop
    if event_loop === nothing
        return nothing
    end

    if sock.readable_fn === nothing
        return nothing
    end

    if !allow_dgram && sock.options.type == SocketType.DGRAM
        return nothing
    end

    schedule_task_future!(
        event_loop,
        clock_now_ns() + _SOCKET_READABLE_RETRY_DELAY_NS;
        type_tag = "posix_socket_readable_retry",
    ) do status
        status = _coerce_task_status(status)
        if status != TaskStatus.RUN_READY
            return nothing
        end

        if sock.readable_fn === nothing || sock.impl === nothing
            return nothing
        end

        if _is_socket_readable_now(fd)
            _on_socket_io_event(sock, Int(IoEventType.READABLE))
            return nothing
        end

        if retries_left > 1
            _schedule_socket_readable_recheck_task(sock, fd, retries_left - 1, allow_dgram)
        end
        return nothing
    end
    return nothing
end

function _is_socket_connect_connected(fd::Integer)::Bool
    peer_addr = Memory{UInt8}(undef, 128)
    fill!(peer_addr, 0x00)
    peer_len = Ref{Cuint}(128)
    rc = GC.@preserve peer_addr ccall(
        :getpeername, Cint, (Cint, Ptr{UInt8}, Ptr{Cuint}),
        fd, pointer(peer_addr), peer_len,
    )
    if rc == 0
        return true
    end

    return false
end

# Connection success callback
function _on_connection_success(sock::Socket)
    event_loop = sock.event_loop
    socket_impl = _posix_impl(sock)
    fd = sock.io_handle.fd

    if socket_impl.currently_subscribed
        unsubscribe_from_io_events!(sock.event_loop, sock.io_handle)
        socket_impl.currently_subscribed = false
    end

    sock.event_loop = nothing

    # Check for connection errors
    connect_result = Ref{Cint}(0)
    result_len = Ref{Cuint}(sizeof(Cint))
    if ccall(
            :getsockopt, Cint, (Cint, Cint, Cint, Ptr{Cint}, Ptr{Cuint}),
            fd, SOL_SOCKET, SO_ERROR, connect_result, result_len
        ) < 0
        errno_val = get_errno()
        socket_error = determine_socket_error(errno_val)
        raise_error(socket_error)
        _on_connection_error(sock, socket_error)
        return
    end

    if connect_result[] != 0
        socket_error = determine_socket_error(connect_result[])
        raise_error(socket_error)
        _on_connection_error(sock, socket_error)
        return
    end

    logf(LogLevel.INFO, LS_IO_SOCKET, "Socket fd=$fd: connection success")

    # Update local endpoint
    try
        _update_local_endpoint!(sock)
    catch
        _on_connection_error(sock, last_error())
        return nothing
    end

    sock.state = socket_state_mask(SocketState.CONNECTED_READ, SocketState.CONNECTED_WRITE)

    # Re-assign to event loop
    try
        socket_assign_to_event_loop(sock, event_loop)
    catch
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: failed to assign to event loop")
        _on_connection_error(sock, last_error())
        return
    end

    # Invoke success callback
    if sock.connection_result_fn !== nothing
        sock.connection_result_fn(OP_SUCCESS)
    end
    return nothing
end

# Connection error callback
function _on_connection_error(sock::Socket, error_code::Integer)
    sock.state = SocketState.ERROR
    fd = sock.io_handle.fd
    socket_impl = _posix_impl(sock)
    logf(LogLevel.DEBUG, LS_IO_SOCKET, "Socket fd=$fd: connection failure, error=$error_code")

    if sock.connection_result_fn !== nothing
        sock.connection_result_fn(Int(error_code))
    elseif sock.accept_result_fn !== nothing
        sock.accept_result_fn(Int(error_code), nothing)
    end
    return nothing
end

# Socket connect event handler
function _socket_connect_event(connect_args::PosixSocketConnectArgs{S}, events::Int) where {S}
    fd = connect_args.socket === nothing ? -1 : (connect_args.socket::Socket).io_handle.fd
    connectable = (events & Int(IoEventType.READABLE) != 0) || (events & Int(IoEventType.WRITABLE) != 0)
    has_error = (events & Int(IoEventType.ERROR) != 0) || (events & Int(IoEventType.CLOSED) != 0)

    logf(LogLevel.TRACE, LS_IO_SOCKET, "Socket fd=$fd: connection activity handler triggered")

    if connect_args.socket !== nothing
        sock = connect_args.socket::Socket
        socket_impl = _posix_impl(sock)

        # On some Linux/epoll paths we can observe writable/readable activity
        # before the connect handshake has fully settled. Reuse the poll-based
        # connect-completion path so readiness/error checks are centralized.
        if connectable && !has_error
            _run_connect_poll(connect_args, TaskStatus.RUN_READY)
            return nothing
        end

        if has_error
            socket_error = socket_get_error(sock)
            if socket_error == ERROR_IO_READ_WOULD_BLOCK
                return nothing  # Spurious event
            end
            if socket_error == ERROR_IO_SOCKET_NOT_CONNECTED
                return nothing
            end
            if socket_impl.currently_subscribed && sock.event_loop !== nothing
                try
                    unsubscribe_from_io_events!(sock.event_loop, sock.io_handle)
                catch e
                end
                socket_impl.currently_subscribed = false
            end
            _cancel_connect_pending_tasks!(sock, connect_args)
            connect_args.socket = nothing
            socket_impl.connect_args = nothing
            raise_error(socket_error)
            _on_connection_error(sock, socket_error)
            return nothing
        end

    end

    return nothing
end

# Handle socket connection timeout
function _handle_socket_timeout(connect_args::PosixSocketConnectArgs{S}, status::TaskStatus.T) where {S}

    logf(LogLevel.TRACE, LS_IO_SOCKET, "Socket timeout task triggered")

    if connect_args.socket !== nothing
        current_task = connect_args.task
        sock = connect_args.socket::Socket
        fd = sock.io_handle.fd
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: timed out, shutting down")

        sock.state = SocketState.ERROR
        error_code = ERROR_IO_SOCKET_TIMEOUT
        socket_impl = _posix_impl(sock)

        if status == TaskStatus.RUN_READY
            if _is_socket_connect_ready_for_completion(fd)
                _cancel_connect_pending_tasks!(sock, connect_args; skip_task = current_task)
                connect_args.socket = nothing
                socket_impl.connect_args = nothing
                sock.state = SocketState.CONNECTING
                _on_connection_success(sock)
                return nothing
            end
            unsubscribe_from_io_events!(sock.event_loop, sock.io_handle)
        else
            error_code = ERROR_IO_EVENT_LOOP_SHUTDOWN
        end

        sock.event_loop = nothing
        socket_impl.currently_subscribed = false

        raise_error(error_code)

        # Close socket and notify error
        _cancel_connect_pending_tasks!(sock, connect_args; skip_task = current_task)
        connect_args.socket = nothing
        socket_impl.connect_args = nothing
        socket_close(sock)
        _on_connection_error(sock, error_code)
    end

    return nothing
end

# Run connect success callback in event loop thread
function _run_connect_success(connect_args::PosixSocketConnectArgs{S}, status::TaskStatus.T) where {S}

    if connect_args.socket !== nothing
        current_task = connect_args.task
        sock = connect_args.socket::Socket
        socket_impl = _posix_impl(sock)

        if status == TaskStatus.RUN_READY
            _cancel_connect_pending_tasks!(sock, connect_args; skip_task = current_task)
            connect_args.socket = nothing
            _on_connection_success(sock)
        else
            raise_error(ERROR_IO_SOCKET_CONNECT_ABORTED)
            _cancel_connect_pending_tasks!(sock, connect_args; skip_task = current_task)
            connect_args.socket = nothing
            sock.event_loop = nothing
            _on_connection_error(sock, ERROR_IO_SOCKET_CONNECT_ABORTED)
        end

        socket_impl.connect_args = nothing
    end

    return nothing
end

# Poll socket for immediate connect completion on the event-loop thread.
function _run_connect_poll(connect_args::PosixSocketConnectArgs{S}, status::TaskStatus.T) where {S}
    if connect_args.socket === nothing || status != TaskStatus.RUN_READY
        return nothing
    end

    sock = connect_args.socket::Socket
    socket_impl = _posix_impl(sock)
    fd = sock.io_handle.fd

    socket_error = socket_get_error(sock)

    if socket_error == OP_SUCCESS
        if _is_socket_connect_ready_for_completion(fd)
            _cancel_connect_pending_tasks!(sock, connect_args)
            connect_args.socket = nothing
            socket_impl.connect_args = nothing
            _on_connection_success(sock)
            return nothing
        end

        _schedule_connect_poll_retry_task!(sock, connect_args)
        return nothing
    end

    if socket_error == ERROR_IO_READ_WOULD_BLOCK || socket_error == ERROR_IO_SOCKET_NOT_CONNECTED
        _schedule_connect_poll_retry_task!(sock, connect_args)
        return nothing
    end

    if socket_impl.currently_subscribed && sock.event_loop !== nothing
        try
            unsubscribe_from_io_events!(sock.event_loop, sock.io_handle)
        catch e
        end
        socket_impl.currently_subscribed = false
    end

    _cancel_connect_pending_tasks!(sock, connect_args)
    connect_args.socket = nothing
    socket_impl.connect_args = nothing
    raise_error(socket_error)
    _on_connection_error(sock, socket_error)

    return nothing
end

# Update local endpoint from socket
function _update_local_endpoint!(sock::Socket)
    fd = sock.io_handle.fd
    address = Memory{UInt8}(undef, 128)
    fill!(address, 0x00)
    address_size = Ref{Cuint}(128)

    result = GC.@preserve address ccall(
        :getsockname, Cint, (Cint, Ptr{UInt8}, Ptr{Cuint}),
        fd, pointer(address), address_size
    )

    if result != 0
        errno_val = get_errno()
        socket_error = determine_socket_error(errno_val)
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: getsockname failed with errno=$errno_val")
        throw_error(socket_error)
    end

    # Parse family (macOS sockaddr has length in first byte)
    family = @static Sys.isapple() ? Cushort(address[2]) : reinterpret(Cushort, address[1:2])[1]

    if family == AF_INET
        port = ntohs(reinterpret(Cushort, address[3:4])[1])
        addr = reinterpret(UInt32, address[5:8])[1]
        addr_str = inet_ntop_ipv4(addr)
        set_address!(sock.local_endpoint, addr_str)
        sock.local_endpoint.port = UInt32(port)
        return nothing
    elseif family == AF_INET6
        port = ntohs(reinterpret(Cushort, address[3:4])[1])
        addr_tuple = ntuple(i -> address[8 + i], Val(16))
        addr_str = inet_ntop_ipv6(addr_tuple)
        set_address!(sock.local_endpoint, addr_str)
        sock.local_endpoint.port = UInt32(port)
        return nothing
    elseif family == AF_UNIX
        # Find null terminator
        path_start = 3
        path_end = path_start - 1
        for i in path_start:min(path_start + 107, length(address))
            if address[i] == 0
                break
            end
            path_end = i
        end
        path = path_end >= path_start ? String(address[path_start:path_end]) : ""
        set_address!(sock.local_endpoint, path)
        sock.local_endpoint.port = UInt32(0)
        return nothing
    end

    @static if Sys.islinux()
        if family == AF_VSOCK
            vm_addr = GC.@preserve address unsafe_load(Ptr{SockAddrVM}(pointer(address)))
            set_address!(sock.local_endpoint, string(vm_addr.svm_cid))
            sock.local_endpoint.port = UInt32(vm_addr.svm_port)
            return nothing
        end
    end

    logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: unsupported address family $family from getsockname")
    throw_error(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
end

# POSIX impl - bind
function socket_bind_impl(
        ::PosixSocket,
        sock::Socket,
        local_endpoint::SocketEndpoint,
        event_loop::Union{EventLoop, Nothing},
        tls_connection_options::MaybeTlsConnectionOptions,
    )::Nothing
    _ = event_loop
    _ = tls_connection_options
    fd = sock.io_handle.fd

    if sock.state != SocketState.INIT
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: invalid state for bind operation")
        throw_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
    end

    # Validate port
    socket_validate_port_for_bind(local_endpoint.port, sock.options.domain)

    address = get_address(local_endpoint)
    port = local_endpoint.port

    logf(LogLevel.INFO, LS_IO_SOCKET, "Socket fd=$fd: binding to $address:$port")

    # Build sockaddr
    sockaddr_obj = nothing
    sockaddr_ptr = Ptr{UInt8}(0)
    sockaddr_len::Cuint = 0

    if sock.options.domain == SocketDomain.IPV4
        addr_result = inet_pton_ipv4(address)

        sockaddr_buf = Memory{UInt8}(undef, 128)
        fill!(sockaddr_buf, 0x00)
        _set_sockaddr_family!(sockaddr_buf, AF_INET, 16)
        sockaddr_buf[3:4] .= reinterpret(UInt8, [htons(port)])
        sockaddr_buf[5:8] .= reinterpret(UInt8, [addr_result])
        sockaddr_obj = sockaddr_buf
        sockaddr_ptr = pointer(sockaddr_buf)
        sockaddr_len = Cuint(16)

    elseif sock.options.domain == SocketDomain.IPV6
        addr_result = inet_pton_ipv6(address)

        sockaddr_buf = Memory{UInt8}(undef, 128)
        fill!(sockaddr_buf, 0x00)
        _set_sockaddr_family!(sockaddr_buf, AF_INET6, 28)
        sockaddr_buf[3:4] .= reinterpret(UInt8, [htons(port)])
        @inbounds for i in 5:8
            sockaddr_buf[i] = 0x00
        end
        for i in 1:16
            sockaddr_buf[8 + i] = addr_result[i]
        end
        sockaddr_obj = sockaddr_buf
        sockaddr_ptr = pointer(sockaddr_buf)
        sockaddr_len = Cuint(28)

    elseif sock.options.domain == SocketDomain.LOCAL
        sockaddr_buf = Memory{UInt8}(undef, 128)
        fill!(sockaddr_buf, 0x00)
        sockaddr_len = @static (Sys.isapple() || Sys.isbsd()) ? Cuint(106) : Cuint(110)  # sizeof(sockaddr_un)
        _set_sockaddr_family!(sockaddr_buf, AF_UNIX, sockaddr_len)
        addr_bytes = Memory{UInt8}(codeunits(address))
        max_path_len = @static (Sys.isapple() || Sys.isbsd()) ? 104 : 108
        copy_len = min(length(addr_bytes), max_path_len)
        for i in 1:copy_len
            sockaddr_buf[2 + i] = addr_bytes[i]
        end
        sockaddr_obj = sockaddr_buf
        sockaddr_ptr = pointer(sockaddr_buf)
        # `sockaddr_len` already set above.
    elseif sock.options.domain == SocketDomain.VSOCK
        cid_result = _parse_vsock_cid(address)
        @static if Sys.islinux()
            vm_addr = SockAddrVM(Cushort(AF_VSOCK), Cushort(0), UInt32(port), cid_result, _VSOCK_ZERO)
            vm_ref = Ref(vm_addr)
            sockaddr_obj = vm_ref
            sockaddr_ptr = Ptr{UInt8}(Base.unsafe_convert(Ptr{SockAddrVM}, vm_ref))
            sockaddr_len = Cuint(sizeof(SockAddrVM))
        else
            throw_error(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
        end
    else
        throw_error(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
    end

    # Bind
    result = GC.@preserve sockaddr_obj ccall(
        :bind, Cint, (Cint, Ptr{UInt8}, Cuint),
        fd, sockaddr_ptr, sockaddr_len
    )

    if result != 0
        errno_val = get_errno()
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: bind failed with errno=$errno_val")
        socket_error = determine_socket_error(errno_val)
        sock.state = SocketState.ERROR
        throw_error(socket_error)
    end

    try
        _update_local_endpoint!(sock)
    catch
        sock.state = SocketState.ERROR
        rethrow()
    end

    if sock.options.type == SocketType.STREAM
        sock.state = SocketState.BOUND
    else
        # UDP is now readable
        sock.state = SocketState.CONNECTED_READ
    end

    logf(
        LogLevel.DEBUG, LS_IO_SOCKET,
        "Socket fd=$fd: successfully bound to $(get_address(sock.local_endpoint)):$(sock.local_endpoint.port)"
    )

    return nothing
end

# POSIX impl - listen
function socket_listen_impl(::PosixSocket, sock::Socket, backlog_size::Integer)::Nothing
    fd = sock.io_handle.fd

    if sock.state != SocketState.BOUND
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: invalid state for listen. Must call bind first.")
        throw_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
    end

    error_code = ccall(:listen, Cint, (Cint, Cint), fd, Cint(backlog_size))

    if error_code == 0
        logf(LogLevel.INFO, LS_IO_SOCKET, "Socket fd=$fd: successfully listening")
        sock.state = SocketState.LISTENING
        return nothing
    end

    errno_val = get_errno()
    logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: listen failed with errno=$errno_val")
    sock.state = SocketState.ERROR
    socket_error = determine_socket_error(errno_val)
    throw_error(socket_error)
end

# POSIX impl - close
function socket_close_impl(socket_impl::PosixSocket, sock::Socket)::Nothing
    fd = sock.io_handle.fd
    logf(LogLevel.DEBUG, LS_IO_SOCKET, "Socket fd=$fd: closing")

    event_loop = sock.event_loop

    if event_loop !== nothing
        # Unsubscribe from events if subscribed
        if socket_impl.currently_subscribed
            _cancel_accept_retry_task_if_needed!(socket_impl, event_loop)
            if sock.state == SocketState.LISTENING
                socket_stop_accept(sock)
            else
                unsubscribe_from_io_events!(event_loop, sock.io_handle)
            end
            socket_impl.currently_subscribed = false
            sock.event_loop = nothing
        end
    end

    close_happened = socket_impl.close_happened
    if close_happened !== nothing
        Base.setfield!(close_happened, :x, true)
    end

    connect_args = socket_impl.connect_args
    if connect_args !== nothing
        connect_args_typed = connect_args::PosixSocketConnectArgs{Socket}
        _cancel_connect_pending_tasks!(sock, connect_args_typed)
        connect_args_typed.socket = nothing
        socket_impl.connect_args = nothing
    end

    # Prevent readable callbacks from firing after close. Connection/accept
    # callbacks may still be needed by in-flight error paths before cleanup.
    sock.readable_fn = nothing

    if socket_is_open(sock)
        ccall(:close, Cint, (Cint,), fd)
        sock.io_handle.fd = -1
        sock.state = SocketState.CLOSED

        # Cancel written task if scheduled
        if socket_impl.written_task_scheduled && event_loop !== nothing
            cancel_task!(event_loop, socket_impl.written_task)
        end

        # Complete pending writes with error
        while !_write_request_queue_isempty(socket_impl.written_queue)
            write_request = _write_request_queue_pop_front!(socket_impl.written_queue)
            bytes_written = write_request.original_len - write_request.cursor.len
            if write_request.written_fn !== nothing
                write_request.written_fn(write_request.error_code, bytes_written)
            end
        end

        while !_write_request_queue_isempty(socket_impl.write_queue)
            write_request = _write_request_queue_pop_front!(socket_impl.write_queue)
            bytes_written = write_request.original_len - write_request.cursor.len
            if write_request.written_fn !== nothing
                write_request.written_fn(ERROR_IO_SOCKET_CLOSED, bytes_written)
            end
        end
    end

    on_close_complete = socket_impl.on_close_complete
    socket_impl.on_close_complete = nothing
    if on_close_complete !== nothing
        on_close_complete(UInt8(0))
    end

    return nothing
end

# POSIX impl - shutdown direction
function socket_shutdown_dir_impl(::PosixSocket, sock::Socket, dir::ChannelDirection.T)::Nothing
    fd = sock.io_handle.fd
    how = dir == ChannelDirection.READ ? SHUT_RD : SHUT_WR

    logf(LogLevel.DEBUG, LS_IO_SOCKET, "Socket fd=$fd: shutting down in direction $dir")

    if ccall(:shutdown, Cint, (Cint, Cint), fd, how) != 0
        errno_val = get_errno()
        socket_error = determine_socket_error(errno_val)
        throw_error(socket_error)
    end

    if dir == ChannelDirection.READ
        sock.state = socket_state_clear(sock.state, SocketState.CONNECTED_READ)
    else
        sock.state = socket_state_clear(sock.state, SocketState.CONNECTED_WRITE)
    end

    return nothing
end

# POSIX impl - set options
function socket_set_options_impl(::PosixSocket, sock::Socket, options::SocketOptions)::Nothing
    if sock.options.domain != options.domain || sock.options.type != options.type
        throw_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
    end
    return set_posix_socket_options!(sock, options)
end

# POSIX impl - assign to event loop
function socket_assign_to_event_loop_impl(::PosixSocket, sock::Socket, event_loop::EventLoop)::Nothing
    fd = sock.io_handle.fd

    if sock.event_loop !== nothing
        throw_error(ERROR_IO_EVENT_LOOP_ALREADY_ASSIGNED)
    end

    logf(LogLevel.DEBUG, LS_IO_SOCKET, "Socket fd=$fd: assigning to event loop")

    sock.event_loop = event_loop
    socket_impl = _posix_impl(sock)
    socket_impl.currently_subscribed = true
    socket_impl.has_pending_readable_event = false

    try
        subscribe_to_io_events!(
            event_loop,
            sock.io_handle,
            Int(IoEventType.WRITABLE) | Int(IoEventType.READABLE),
            EventCallable(events -> _on_socket_io_event(sock, events)),
        )
    catch
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: failed to assign to event loop")
        socket_impl.currently_subscribed = false
        sock.event_loop = nothing
        rethrow()
    end

    # In edge-triggered mode, data can arrive before a readable callback is registered,
    # and epoll may miss that readiness transition.
    schedule_task_now!(event_loop; type_tag = "posix_socket_assign_immediate_io_poll") do status
        try
            status = _coerce_task_status(status)
            status == TaskStatus.CANCELED && return nothing
            sock.impl === nothing && return nothing
            _on_socket_io_event(sock, Int(IoEventType.READABLE) | Int(IoEventType.WRITABLE))
        catch e
            Core.println("socket assign immediate io poll task errored")
        end
        return nothing
    end

    return nothing
end

# Socket IO event handler
function _on_socket_io_event(sock, events::Int)
    sock_impl = sock.impl
    sock_impl === nothing && return nothing

    socket_impl = sock_impl::PosixSocket
    fd = sock.io_handle.fd

    # Handle readable events first
    if socket_impl.currently_subscribed && (events & Int(IoEventType.READABLE)) != 0
        logf(LogLevel.TRACE, LS_IO_SOCKET, "Socket fd=$fd: is readable")
        if sock.readable_fn !== nothing
            if _is_socket_readable_now(fd)
                sock.readable_fn(OP_SUCCESS)
            else
                _schedule_socket_readable_recheck_task(sock, fd, _SOCKET_READABLE_RETRY_COUNT)
            end
        else
            if _is_socket_readable_now(fd)
                socket_impl.has_pending_readable_event = true
            else
            end
        end
    end

    # Handle writable events
    if socket_impl.currently_subscribed && (events & Int(IoEventType.WRITABLE)) != 0
        logf(LogLevel.TRACE, LS_IO_SOCKET, "Socket fd=$fd: is writable")
        _process_socket_write_requests(sock, nothing)
    end

    # Handle hangup/close
    if (events & Int(IoEventType.REMOTE_HANG_UP)) != 0 || (events & Int(IoEventType.CLOSED)) != 0
        raise_error(ERROR_IO_SOCKET_CLOSED)
        logf(LogLevel.TRACE, LS_IO_SOCKET, "Socket fd=$fd: closed remotely")
        if sock.readable_fn !== nothing
            sock.readable_fn(ERROR_IO_SOCKET_CLOSED)
        end
    elseif socket_impl.currently_subscribed && (events & Int(IoEventType.ERROR)) != 0
        socket_error = socket_get_error(sock)
        raise_error(socket_error)
        logf(LogLevel.TRACE, LS_IO_SOCKET, "Socket fd=$fd: error event occurred")
        if sock.readable_fn !== nothing
            sock.readable_fn(socket_error)
        end
    end

    return nothing
end

# POSIX impl - subscribe to readable events
function socket_subscribe_to_readable_events_impl(::PosixSocket, sock::Socket, on_readable::EventCallable)::Nothing
    fd = sock.io_handle.fd
    socket_impl = _posix_impl(sock)
    logf(LogLevel.TRACE, LS_IO_SOCKET, "Socket fd=$fd: subscribing to readable events")

    if !socket_state_has(sock.state, SocketState.CONNECTED_READ)
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: can't subscribe, not connected")
        throw_error(ERROR_IO_SOCKET_NOT_CONNECTED)
    end

    if sock.readable_fn !== nothing
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: already subscribed to readable events")
        throw_error(ERROR_IO_ALREADY_SUBSCRIBED)
    end

    sock.readable_fn = on_readable
    if socket_impl.has_pending_readable_event && sock.event_loop !== nothing
        socket_impl.has_pending_readable_event = false
        event_loop = sock.event_loop
        schedule_task_now!(event_loop; type_tag = "posix_socket_pending_readable_dispatch") do status
            try
                status = _coerce_task_status(status)
                status == TaskStatus.CANCELED && return nothing
                sock.impl === nothing && return nothing
                _on_socket_io_event(sock, Int(IoEventType.READABLE))
            catch e
                Core.println("socket pending readable dispatch task errored")
            end
            return nothing
        end
    elseif sock.options.type == SocketType.DGRAM && sock.event_loop !== nothing
        _schedule_socket_readable_recheck_task(
            sock,
            fd,
            _SOCKET_READABLE_RETRY_COUNT,
            true,
        )
    end

    if sock.event_loop !== nothing
        event_loop = sock.event_loop
        schedule_task_now!(event_loop; type_tag = "posix_socket_subscribe_readable_poll") do status
            try
                status = _coerce_task_status(status)
                status == TaskStatus.CANCELED && return nothing
                sock.impl === nothing && return nothing
                _on_socket_io_event(sock, Int(IoEventType.READABLE))
            catch
                logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket readable subscribe poll task errored")
            end
            return nothing
        end
    end

    return nothing
end

# POSIX impl - read
function socket_read_impl(::PosixSocket, sock::Socket, buffer::ByteBuffer)::Csize_t
    fd = sock.io_handle.fd

    if sock.event_loop !== nothing && !event_loop_thread_is_callers_thread(sock.event_loop)
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: cannot read from different thread")
        throw_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end

    if !socket_state_has(sock.state, SocketState.CONNECTED_READ)
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: cannot read, not connected")
        throw_error(ERROR_IO_SOCKET_NOT_CONNECTED)
    end

    # Calculate remaining capacity
    remaining = buffer.capacity - buffer.len
    if remaining == 0
        return Csize_t(0)
    end

    # Read into buffer
    buf_ptr = pointer(getfield(buffer, :mem)) + buffer.len
    read_val = ccall(:read, Cssize_t, (Cint, Ptr{UInt8}, Csize_t), fd, buf_ptr, remaining)
    errno_val = get_errno()

    logf(LogLevel.TRACE, LS_IO_SOCKET, "Socket fd=$fd: read returned $read_val")

    if read_val > 0
        amount_read = Csize_t(read_val)
        setfield!(buffer, :len, buffer.len + amount_read)
        return amount_read
    end

    # EOF
    if read_val == 0
        logf(LogLevel.INFO, LS_IO_SOCKET, "Socket fd=$fd: zero read, socket closed")
        if remaining > 0
            throw_error(ERROR_IO_SOCKET_CLOSED)
        end
        return Csize_t(0)
    end

    # Error handling
    if errno_val == EAGAIN || errno_val == EWOULDBLOCK || errno_val == EINTR
        logf(LogLevel.TRACE, LS_IO_SOCKET, "Socket fd=$fd: read would block")
        throw_error(ERROR_IO_READ_WOULD_BLOCK)
    end

    if errno_val == EPIPE || errno_val == ECONNRESET
        logf(LogLevel.INFO, LS_IO_SOCKET, "Socket fd=$fd: socket closed")
        throw_error(ERROR_IO_SOCKET_CLOSED)
    end

    if errno_val == ETIMEDOUT
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: socket timed out")
        throw_error(ERROR_IO_SOCKET_TIMEOUT)
    end

    socket_error = determine_socket_error(errno_val)
    logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: read failed with errno=$errno_val")
    throw_error(socket_error)
end

# Process socket write requests
function _process_socket_write_requests(sock::Socket, parent_request::Union{SocketWriteRequest, Nothing})
    socket_impl = _posix_impl(sock)
    fd = sock.io_handle.fd

    purge = false
    socket_error = OP_SUCCESS
    parent_request_failed = false
    pushed_to_written_queue = false

    while !_write_request_queue_isempty(socket_impl.write_queue)
        write_request = _write_request_queue_front(socket_impl.write_queue)

        logf(
            LogLevel.TRACE, LS_IO_SOCKET,
            "Socket fd=$fd: dequeued write request of size $(write_request.original_len)"
        )

        # Send data
        cursor = write_request.cursor
        written = Cssize_t(-1)
        errno_val = Cint(0)
        while true
            written = if cursor.len > 0
                cursor_ptr = cursor.ptr
                GC.@preserve cursor_ptr ccall(
                    :send, Cssize_t, (Cint, Ptr{UInt8}, Csize_t, Cint),
                    fd, Ptr{UInt8}(pointer(cursor_ptr)), cursor.len, NO_SIGNAL_SEND
                )
            else
                ccall(
                    :send, Cssize_t, (Cint, Ptr{UInt8}, Csize_t, Cint),
                    fd, Ptr{UInt8}(0), cursor.len, NO_SIGNAL_SEND
                )
            end

            if written >= 0
                errno_val = Cint(0)
                break
            end

            errno_val = get_errno()
            errno_val == EINTR && continue
            break
        end

        logf(LogLevel.TRACE, LS_IO_SOCKET, "Socket fd=$fd: send returned $written")

        if written < 0
            if errno_val == EAGAIN
                logf(LogLevel.TRACE, LS_IO_SOCKET, "Socket fd=$fd: would block")
                break
            end

            if errno_val == EPIPE
                logf(LogLevel.DEBUG, LS_IO_SOCKET, "Socket fd=$fd: closed before write")
                socket_error = ERROR_IO_SOCKET_CLOSED
                raise_error(socket_error)
                purge = true
                break
            end

            purge = true
            logf(LogLevel.DEBUG, LS_IO_SOCKET, "Socket fd=$fd: write error errno=$errno_val")
            socket_error = determine_socket_error(errno_val)
            raise_error(socket_error)
            break
        end

        remaining = cursor.len

        # Advance cursor (keep remaining bytes)
        cursor_ref = Ref(cursor)
        _ = byte_cursor_advance(cursor_ref, Csize_t(written))
        write_request.cursor = cursor_ref[]

        if Csize_t(written) == remaining
            # Write complete
            logf(LogLevel.TRACE, LS_IO_SOCKET, "Socket fd=$fd: write request completed")
            _write_request_queue_pop_front!(socket_impl.write_queue)
            write_request.error_code = OP_SUCCESS
            _write_request_queue_push_back!(socket_impl.written_queue, write_request)
            pushed_to_written_queue = true
        end
    end

    if purge
        while !_write_request_queue_isempty(socket_impl.write_queue)
            write_request = _write_request_queue_pop_front!(socket_impl.write_queue)
            if write_request === parent_request
                parent_request_failed = true
            else
                write_request.error_code = socket_error
                _write_request_queue_push_back!(socket_impl.written_queue, write_request)
                pushed_to_written_queue = true
            end
        end
    end

    # Schedule written task if needed
    if pushed_to_written_queue && !socket_impl.written_task_scheduled
        socket_impl.written_task_scheduled = true
        socket_impl.written_task = ScheduledTask(; type_tag = "socket_written_task") do status
            try
                _written_task_fn(sock, _coerce_task_status(status))
            catch e
                Core.println("socket_written_task task errored")
            end
            return nothing
        end
        schedule_task_now!(sock.event_loop, socket_impl.written_task)
    end

    return !parent_request_failed
end

# Written task callback
function _written_task_fn(sock::Socket, status::TaskStatus.T)
    socket_impl = _posix_impl(sock)

    socket_impl.written_task_scheduled = false

    # Process completed writes
    if !_write_request_queue_isempty(socket_impl.written_queue)
        # Only process initial contents
        count = _write_request_queue_length(socket_impl.written_queue)
        for _ in 1:count
            if _write_request_queue_isempty(socket_impl.written_queue)
                break
            end
            write_request = _write_request_queue_pop_front!(socket_impl.written_queue)
            bytes_written = write_request.original_len - write_request.cursor.len
            if write_request.written_fn !== nothing
                write_request.written_fn(write_request.error_code, bytes_written)
            end
        end
    end

    return nothing
end

# POSIX impl - write
function socket_write_impl(::PosixSocket, sock::Socket, cursor::ByteCursor, written_fn::Union{WriteCallable, Nothing})::Nothing
    fd = sock.io_handle.fd

    if sock.event_loop !== nothing && !event_loop_thread_is_callers_thread(sock.event_loop)
        throw_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
    end

    if !socket_state_has(sock.state, SocketState.CONNECTED_WRITE)
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: cannot write, not connected")
        throw_error(ERROR_IO_SOCKET_NOT_CONNECTED)
    end

    socket_impl = _posix_impl(sock)

    # Create write request
    write_request = SocketWriteRequest(
        cursor,
        cursor.len,
        written_fn,
        0,
        nothing,
        nothing,
    )

    _write_request_queue_push_back!(socket_impl.write_queue, write_request)

    if !_process_socket_write_requests(sock, write_request)
        throw(ReseauError(last_error()))
    end

    return nothing
end

# POSIX impl - get error
function socket_get_error_impl(::PosixSocket, sock::Socket)::Int
    fd = sock.io_handle.fd
    connect_result = Ref{Cint}(0)
    result_len = Ref{Cuint}(sizeof(Cint))

    if ccall(
            :getsockopt, Cint, (Cint, Cint, Cint, Ptr{Cint}, Ptr{Cuint}),
            fd, SOL_SOCKET, SO_ERROR, connect_result, result_len
        ) < 0
        return determine_socket_error(get_errno())
    end

    if connect_result[] != 0
        return determine_socket_error(connect_result[])
    end

    return OP_SUCCESS
end

# POSIX impl - is open
function socket_is_open_impl(::PosixSocket, sock::Socket)::Bool
    return sock.io_handle.fd >= 0
end

# POSIX impl - start accept
function socket_start_accept_impl(
        ::PosixSocket,
        sock::Socket,
        accept_loop::EventLoop,
        on_accept_result::Union{ChannelCallable, Nothing},
        on_accept_start::Union{EventCallable, Nothing},
        event_loop_group::Union{EventLoopGroup, Nothing},
    )::Nothing
    _ = event_loop_group
    fd = sock.io_handle.fd

    on_accept_result === nothing && throw_error(ERROR_INVALID_ARGUMENT)

    if sock.event_loop !== nothing
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: already assigned to event loop")
        throw_error(ERROR_IO_EVENT_LOOP_ALREADY_ASSIGNED)
    end

    if sock.state != SocketState.LISTENING
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: invalid state for start_accept. Must call listen first.")
        throw_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
    end

    sock.accept_result_fn = on_accept_result
    sock.event_loop = accept_loop

    socket_impl = _posix_impl(sock)
    socket_impl.continue_accept = true
    socket_impl.currently_subscribed = true
    socket_impl.accept_retry_task = nothing

    try
        subscribe_to_io_events!(
            accept_loop,
            sock.io_handle,
            Int(IoEventType.READABLE),
            EventCallable(events -> _socket_accept_event(sock, events)),
        )
        # In edge-triggered epoll mode, adding a subscription can miss an already-ready
        # readiness notification. Schedule an immediate poll on the event loop so an
        # already-pending connection is processed deterministically.
        schedule_task_now!(accept_loop; type_tag = "posix_socket_start_accept_poll") do status
            if _coerce_task_status(status) != TaskStatus.RUN_READY
                return nothing
            end
            _socket_accept_event(sock, Int(IoEventType.READABLE))
            return nothing
        end

    catch
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: failed to subscribe to event loop")
        socket_impl.continue_accept = false
        socket_impl.currently_subscribed = false
        socket_impl.accept_retry_task = nothing
        sock.event_loop = nothing
        rethrow()
    end

    # Invoke on_accept_start callback on the accept loop thread.
    if on_accept_start !== nothing
        schedule_task_now!(accept_loop; type_tag = "posix_socket_on_accept_start") do status
            if _coerce_task_status(status) == TaskStatus.RUN_READY
                on_accept_start(OP_SUCCESS)
            end
            return nothing
        end
    end

    return nothing
end

# Socket accept event handler
function _socket_accept_event(sock, events::Int)
    socket_impl = _posix_impl(sock)
    fd = sock.io_handle.fd

    logf(LogLevel.DEBUG, LS_IO_SOCKET, "Socket fd=$fd: listening event received")

    if socket_impl.continue_accept && (events & Int(IoEventType.READABLE)) != 0
        # Accept loop
        while socket_impl.continue_accept
            in_addr = Memory{UInt8}(undef, 128)
            fill!(in_addr, 0x00)
            in_len = Ref{Cuint}(128)

            in_fd = GC.@preserve in_addr ccall(
                :accept, Cint, (Cint, Ptr{UInt8}, Ptr{Cuint}),
                fd, pointer(in_addr), in_len
            )
            errno_val = get_errno()

            if in_fd == -1
                if errno_val == EAGAIN || errno_val == EWOULDBLOCK
                    _schedule_accept_retry_task!(sock)
                    break
                end
                if errno_val == EINTR
                    continue
                end
                socket_error = socket_get_error(sock)
                raise_error(socket_error)
                _on_connection_error(sock, socket_error)
                break
            end

            logf(LogLevel.DEBUG, LS_IO_SOCKET, "Socket fd=$fd: incoming connection, new fd=$in_fd")

            # Create new socket for the connection. Accepted sockets are already bound to the listener's
            # interface; on Linux, attempting to apply SO_BINDTODEVICE on an already-connected socket
            # can fail, so clear the interface name when cloning options for the accepted socket.
            accept_options = sock.options
            if SO_BINDTODEVICE != 0 && !isempty(get_network_interface_name(accept_options))
                accept_options = copy(accept_options)
                accept_options.network_interface_name = ""
            end
            new_sock = try
                socket_init_posix(accept_options; existing_fd = Cint(in_fd))
            catch
                ccall(:close, Cint, (Cint,), in_fd)
                _on_connection_error(sock, last_error())
                continue
            end
            copy!(new_sock.local_endpoint, sock.local_endpoint)
            new_sock.state = socket_state_mask(SocketState.CONNECTED_READ, SocketState.CONNECTED_WRITE)

            # Parse remote address
            family = @static Sys.isapple() ? Cushort(in_addr[2]) : reinterpret(Cushort, in_addr[1:2])[1]
            port = UInt32(0)

            if family == AF_INET
                port = UInt32(ntohs(reinterpret(Cushort, in_addr[3:4])[1]))
                addr = reinterpret(UInt32, in_addr[5:8])[1]
                addr_str = inet_ntop_ipv4(addr)
                set_address!(new_sock.remote_endpoint, addr_str)
                new_sock.options.domain = SocketDomain.IPV4
            elseif family == AF_INET6
                port = UInt32(ntohs(reinterpret(Cushort, in_addr[3:4])[1]))
                addr_tuple = ntuple(i -> in_addr[8 + i], Val(16))
                addr_str = inet_ntop_ipv6(addr_tuple)
                set_address!(new_sock.remote_endpoint, addr_str)
                new_sock.options.domain = SocketDomain.IPV6
            elseif family == AF_UNIX
                copy!(new_sock.remote_endpoint, sock.local_endpoint)
                new_sock.options.domain = SocketDomain.LOCAL
            end

            @static if Sys.islinux()
                if family == AF_VSOCK
                    vm_addr = GC.@preserve in_addr unsafe_load(Ptr{SockAddrVM}(pointer(in_addr)))
                    port = UInt32(vm_addr.svm_port)
                    set_address!(new_sock.remote_endpoint, string(vm_addr.svm_cid))
                    new_sock.options.domain = SocketDomain.VSOCK
                end
            end

            new_sock.remote_endpoint.port = port

            # Set non-blocking
            flags = _fcntl(in_fd, F_GETFL)
            flags |= O_NONBLOCK
            _fcntl(in_fd, F_SETFL, flags)

            fd_flags = _fcntl(in_fd, F_GETFD)
            fd_flags |= FD_CLOEXEC
            _fcntl(in_fd, F_SETFD, fd_flags)

            logf(
                LogLevel.INFO, LS_IO_SOCKET,
                "Socket fd=$fd: accepted connection from $(get_address(new_sock.remote_endpoint)):$(new_sock.remote_endpoint.port)"
            )

            # Track if close happens during callback
            close_occurred = Ref(false)
            socket_impl.close_happened = close_occurred

            sock.accept_result_fn(OP_SUCCESS, new_sock)

            if close_occurred[]
                return nothing
            end

            socket_impl.close_happened = nothing
        end
    end

    logf(LogLevel.TRACE, LS_IO_SOCKET, "Socket fd=$fd: finished processing incoming connections")
    return nothing
end

# POSIX impl - stop accept
function _socket_stop_accept_on_event_loop!(sock::Socket, socket_impl::PosixSocket)::Nothing
    socket_impl.continue_accept = false

    if !socket_impl.currently_subscribed
        return nothing
    end

    event_loop = sock.event_loop
    _cancel_accept_retry_task_if_needed!(socket_impl, event_loop)
    if event_loop !== nothing
        unsubscribe_from_io_events!(event_loop, sock.io_handle)
    end
    socket_impl.currently_subscribed = false
    sock.event_loop = nothing
    return nothing
end

function socket_stop_accept_impl(::PosixSocket, sock::Socket)::Nothing
    fd = sock.io_handle.fd

    if sock.state != SocketState.LISTENING
        logf(LogLevel.ERROR, LS_IO_SOCKET, "Socket fd=$fd: not in listening state")
        throw_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
    end

    logf(LogLevel.INFO, LS_IO_SOCKET, "Socket fd=$fd: stopping accepting new connections")

    socket_impl = _posix_impl(sock)
    event_loop = sock.event_loop
    if event_loop === nothing || !(@atomic event_loop.running) || event_loop_thread_is_callers_thread(event_loop)
        _socket_stop_accept_on_event_loop!(sock, socket_impl)
        return nothing
    end

    fut = Future{Nothing}()
    schedule_task_now!(event_loop; type_tag = "posix_socket_stop_accept_on_event_loop") do _
        try
            if sock.impl !== nothing
                _socket_stop_accept_on_event_loop!(sock, _posix_impl(sock))
            end
            notify(fut, nothing)
        catch e
            notify(fut, e isa ReseauError ? e : ReseauError(ERROR_UNKNOWN))
        end
        return nothing
    end
    wait(fut)

    return nothing
end

# POSIX impl - set close callback
function socket_set_close_callback_impl(::PosixSocket, sock::Socket, fn::TaskFn)::Nothing
    socket_impl = _posix_impl(sock)
    socket_impl.on_close_complete = fn
    return nothing
end

# POSIX impl - set cleanup callback
function socket_set_cleanup_callback_impl(::PosixSocket, sock::Socket, fn::TaskFn)::Nothing
    socket_impl = _posix_impl(sock)
    socket_impl.on_cleanup_complete = fn
    return nothing
end
