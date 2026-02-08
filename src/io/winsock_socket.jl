# AWS IO Library - Winsock sockets
# Port of aws-c-io/source/windows/iocp/socket.c
#
# Type definitions are in winsock_socket_types.jl

@static if Sys.iswindows()
    const _WS2_32 = "Ws2_32"
    const _WIN_KERNEL32 = "Kernel32"

    # Address families (Windows values)
    const WS_AF_INET = Cint(2)
    const WS_AF_INET6 = Cint(23)

    # Socket types (Windows values)
    const WS_SOCK_STREAM = Cint(1)
    const WS_SOCK_DGRAM = Cint(2)

    # Socket option levels/options (Windows values)
    const WS_SOL_SOCKET = Cint(0xFFFF)
    const WS_IPPROTO_TCP = Cint(6)

    const WS_SO_REUSEADDR = Cint(0x0004)
    const WS_SO_KEEPALIVE = Cint(0x0008)
    const WS_SO_ERROR = Cint(0x1007)
    # In WinSock headers: `#define SO_EXCLUSIVEADDRUSE ((int)(~SO_REUSEADDR))`
    const WS_SO_EXCLUSIVEADDRUSE = ~WS_SO_REUSEADDR

    # mswsock.h values (see docs); used with setsockopt(SOL_SOCKET,...)
    const WS_SO_UPDATE_CONNECT_CONTEXT = Cint(0x7010)

    # Shutdown directions
    const WS_SD_RECEIVE = Cint(0)
    const WS_SD_SEND = Cint(1)
    const WS_SD_BOTH = Cint(2)

    # WSA error codes
    const WSAEWOULDBLOCK = Cint(10035)
    const WSAECONNRESET = Cint(10054)
    const WSAECONNREFUSED = Cint(10061)
    const WSAETIMEDOUT = Cint(10060)
    const WSAEADDRNOTAVAIL = Cint(10049)
    const WSAEADDRINUSE = Cint(10048)
    const WSAENETUNREACH = Cint(10051)
    const WSAEHOSTUNREACH = Cint(10065)
    const WSAENETDOWN = Cint(10050)
    const WSAECONNABORTED = Cint(10053)
    const WSAENOBUFS = Cint(10055)
    const WSAEMFILE = Cint(10024)
    const WSAENAMETOOLONG = Cint(10063)
    const WSAEINVAL = Cint(10022)
    const WSAEAFNOSUPPORT = Cint(10047)
    const WSAEACCES = Cint(10013)

    # Windows error/status codes used by IOCP (see aws-c-io socket.c)
    const IO_OPERATION_CANCELLED = Int(0xC0000120)
    const IO_STATUS_CONNECTION_REFUSED = Int(0xC0000236)
    const IO_STATUS_TIMEOUT = Int(0x00000102)
    const IO_NETWORK_UNREACHABLE = Int(0xC000023C)
    const IO_HOST_UNREACHABLE = Int(0xC000023D)
    const IO_CONNECTION_ABORTED = Int(0xC0000241)
    const IO_PIPE_BROKEN = Int(0xC000014B)
    const IO_STATUS_BUFFER_OVERFLOW = Int(0x80000005)
    const STATUS_INVALID_ADDRESS_COMPONENT = Int(0xC0000207)

    const ERROR_IO_PENDING = Int(997)
    const ERROR_BROKEN_PIPE = Int(109)
    const ERROR_INVALID_PARAMETER = Int(87)
    const SOME_ERROR_CODE_THAT_MEANS_INVALID_PATH = Int(3)

    const ERROR_PIPE_CONNECTED = Int(535)
    const ERROR_OPERATION_ABORTED = Int(995)

    # Keepalive tuning
    const SIO_KEEPALIVE_VALS = UInt32(0x98000004)
    const FIONBIO = UInt32(0x8004667E)
    const FIONREAD = UInt32(0x4004667F)
    struct TcpKeepAlive
        onoff::UInt32
        keepalivetime::UInt32
        keepaliveinterval::UInt32
    end

    # WSARecv/WSASend buffer description
    struct WSABUF
        len::UInt32
        buf::Ptr{UInt8}
    end

    const MSG_PEEK = UInt32(0x2)

    # Named pipe constants (subset)
    const PIPE_BUFFER_SIZE = UInt32(512)
    const PIPE_ACCESS_DUPLEX = UInt32(0x00000003)
    const PIPE_TYPE_BYTE = UInt32(0x00000000)
    const PIPE_READMODE_BYTE = UInt32(0x00000000)
    const PIPE_WAIT = UInt32(0x00000000)
    const PIPE_ACCEPT_REMOTE_CLIENTS = UInt32(0x00000000)
    const PIPE_UNLIMITED_INSTANCES = UInt32(255)
    const FILE_FLAG_OVERLAPPED = UInt32(0x40000000)
    const OPEN_EXISTING = UInt32(3)
    const GENERIC_READ = UInt32(0x80000000)
    const GENERIC_WRITE = UInt32(0x40000000)
    const FILE_ATTRIBUTE_NORMAL = UInt32(0x00000080)

    @inline function _wsa_get_last_error()::Int
        return Int(ccall((:WSAGetLastError, _WS2_32), Cint, ()))
    end

    function _winsock_determine_socket_error(code::Integer)::Int
        c = Int(code)
        if c == Int(WSAECONNREFUSED) || c == IO_STATUS_CONNECTION_REFUSED
            return ERROR_IO_SOCKET_CONNECTION_REFUSED
        elseif c == Int(WSAETIMEDOUT) || c == IO_STATUS_TIMEOUT
            return ERROR_IO_SOCKET_TIMEOUT
        elseif c == IO_PIPE_BROKEN || c == ERROR_BROKEN_PIPE
            return ERROR_IO_SOCKET_CLOSED
        elseif c == STATUS_INVALID_ADDRESS_COMPONENT || c == Int(WSAEADDRNOTAVAIL)
            return ERROR_IO_SOCKET_INVALID_ADDRESS
        elseif c == Int(WSAEADDRINUSE)
            return ERROR_IO_SOCKET_ADDRESS_IN_USE
        elseif c == Int(WSAENETUNREACH) || c == IO_NETWORK_UNREACHABLE || c == IO_HOST_UNREACHABLE ||
                c == Int(WSAEHOSTUNREACH)
            return ERROR_IO_SOCKET_NO_ROUTE_TO_HOST
        elseif c == Int(WSAENETDOWN)
            return ERROR_IO_SOCKET_NETWORK_DOWN
        elseif c == Int(WSAECONNABORTED) || c == IO_CONNECTION_ABORTED
            return ERROR_IO_SOCKET_CONNECT_ABORTED
        elseif c == Int(WSAENOBUFS)
            return ERROR_OOM
        elseif c == Int(WSAEMFILE)
            return ERROR_MAX_FDS_EXCEEDED
        elseif c == Int(WSAENAMETOOLONG) || c == Int(WSAEINVAL) || c == SOME_ERROR_CODE_THAT_MEANS_INVALID_PATH ||
                c == ERROR_INVALID_PARAMETER
            return ERROR_FILE_INVALID_PATH
        elseif c == Int(WSAEAFNOSUPPORT)
            return ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY
        elseif c == Int(WSAEACCES)
            return ERROR_NO_PERMISSION
        else
            return ERROR_IO_SOCKET_NOT_CONNECTED
        end
    end

    @inline function _winsock_socket_handle(sock::Socket)::UInt
        return sock.io_handle.handle == C_NULL ? UInt(0) : UInt(sock.io_handle.handle)
    end

    function _winsock_convert_domain(domain::SocketDomain.T)::Union{Cint, ErrorResult}
        if domain == SocketDomain.IPV4
            return WS_AF_INET
        elseif domain == SocketDomain.IPV6
            return WS_AF_INET6
        elseif domain == SocketDomain.LOCAL
            # Named pipes (not AF_UNIX)
            return WS_AF_INET
        else
            raise_error(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
            return ErrorResult(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
        end
    end

    function _winsock_convert_type(type::SocketType.T)::Union{Cint, ErrorResult}
        if type == SocketType.STREAM
            return WS_SOCK_STREAM
        elseif type == SocketType.DGRAM
            return WS_SOCK_DGRAM
        else
            raise_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_OPTIONS)
        end
    end

    function _winsock_inet_pton_ipv4(address::AbstractString)::Union{UInt32, ErrorResult}
        addr_ref = Ref{UInt32}(0)
        rc = ccall((:inet_pton, _WS2_32), Cint, (Cint, Cstring, Ptr{UInt32}), WS_AF_INET, address, addr_ref)
        if rc != 1
            # rc==0 => invalid address; rc<0 => WSAGetLastError()
            raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
        end
        return addr_ref[]
    end

    function _winsock_inet_pton_ipv6(address::AbstractString)::Union{NTuple{16, UInt8}, ErrorResult}
        mem = Memory{UInt8}(undef, 16)
        rc = GC.@preserve mem ccall((:inet_pton, _WS2_32), Cint, (Cint, Cstring, Ptr{UInt8}), WS_AF_INET6, address, pointer(mem))
        if rc != 1
            raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_ADDRESS)
        end
        return Tuple(mem)
    end

    @inline function _winsock_inet_ntop_ipv4(addr_ptr::Ptr{UInt8})::String
        b1 = unsafe_load(addr_ptr, 1)
        b2 = unsafe_load(addr_ptr, 2)
        b3 = unsafe_load(addr_ptr, 3)
        b4 = unsafe_load(addr_ptr, 4)
        return string(b1, ".", b2, ".", b3, ".", b4)
    end

    function _winsock_inet_ntop_ipv6(addr_ptr::Ptr{UInt8})::String
        # Uncompressed form is fine; parse_ipv6_address! accepts it.
        parts = Vector{String}(undef, 8)
        @inbounds for i in 0:7
            hi = unsafe_load(addr_ptr, 2 * i + 1)
            lo = unsafe_load(addr_ptr, 2 * i + 2)
            val = (UInt16(hi) << 8) | UInt16(lo)
            parts[i + 1] = string(val; base = 16)
        end
        return join(parts, ":")
    end

    function _winsock_update_local_endpoint_ipv4_ipv6!(sock::Socket)::Union{Nothing, ErrorResult}
        handle = _winsock_socket_handle(sock)
        handle == 0 && return ErrorResult(raise_error(ERROR_INVALID_STATE))

        address = Memory{UInt8}(undef, 256)
        fill!(address, 0x00)
        address_size = Ref{Cint}(Cint(length(address)))

        rc = GC.@preserve address ccall(
            (:getsockname, _WS2_32),
            Cint,
            (UInt, Ptr{UInt8}, Ptr{Cint}),
            handle,
            pointer(address),
            address_size,
        )

        if rc != 0
            aws_err = _winsock_determine_socket_error(_wsa_get_last_error())
            raise_error(aws_err)
            return ErrorResult(aws_err)
        end

        family = unsafe_load(Ptr{Cushort}(pointer(address))) |> Cint
        if family == WS_AF_INET
            port = ntohs(unsafe_load(Ptr{Cushort}(pointer(address) + 2)))
            addr_ptr = Ptr{UInt8}(pointer(address) + 4)
            set_address!(sock.local_endpoint, _winsock_inet_ntop_ipv4(addr_ptr))
            sock.local_endpoint.port = UInt32(port)
            return nothing
        elseif family == WS_AF_INET6
            port = ntohs(unsafe_load(Ptr{Cushort}(pointer(address) + 2)))
            addr_ptr = Ptr{UInt8}(pointer(address) + 8)
            set_address!(sock.local_endpoint, _winsock_inet_ntop_ipv6(addr_ptr))
            sock.local_endpoint.port = UInt32(port)
            return nothing
        end

        raise_error(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
        return ErrorResult(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
    end

    function _winsock_socket_set_options!(sock::Socket, options::SocketOptions)::Union{Nothing, ErrorResult}
        if sock.options.domain != options.domain || sock.options.type != options.type
            raise_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_OPTIONS)
        end

        sock.options = copy(options)

        iface = get_network_interface_name(options)
        if !isempty(iface)
            raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
            return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
        end

        if sock.options.domain != SocketDomain.LOCAL && sock.options.type == SocketType.STREAM
            handle = _winsock_socket_handle(sock)
            if sock.options.keepalive && !(sock.options.keep_alive_interval_sec != 0 && sock.options.keep_alive_timeout_sec != 0)
                keep_alive = Ref{Cint}(1)
                _ = ccall(
                    (:setsockopt, _WS2_32),
                    Cint,
                    (UInt, Cint, Cint, Ptr{Cint}, Cint),
                    handle,
                    WS_SOL_SOCKET,
                    WS_SO_KEEPALIVE,
                    keep_alive,
                    Cint(sizeof(Cint)),
                )
            elseif sock.options.keepalive
                keep_alive_timeout_ms = UInt32(sock.options.keep_alive_timeout_sec) * UInt32(1000)
                keep_alive_interval_ms = UInt32(sock.options.keep_alive_interval_sec) * UInt32(1000)
                args = Ref(TcpKeepAlive(UInt32(1), keep_alive_timeout_ms, keep_alive_interval_ms))
                bytes_returned = Ref{UInt32}(0)
                _ = ccall(
                    (:WSAIoctl, _WS2_32),
                    Cint,
                    (UInt, UInt32, Ptr{TcpKeepAlive}, UInt32, Ptr{Cvoid}, UInt32, Ptr{UInt32}, Ptr{Cvoid}, Ptr{Cvoid}),
                    handle,
                    SIO_KEEPALIVE_VALS,
                    args,
                    UInt32(sizeof(TcpKeepAlive)),
                    C_NULL,
                    UInt32(0),
                    bytes_returned,
                    C_NULL,
                    C_NULL,
                )
            end
        end

        return nothing
    end

    function _winsock_create_underlying_socket!(sock::Socket, options::SocketOptions)::Union{Nothing, ErrorResult}
        domain = _winsock_convert_domain(options.domain)
        domain isa ErrorResult && return domain
        stype = _winsock_convert_type(options.type)
        stype isa ErrorResult && return stype

        handle = ccall((:socket, _WS2_32), UInt, (Cint, Cint, Cint), domain, stype, Cint(0))
        if handle == UInt(typemax(UInt))
            wsa_err = _wsa_get_last_error()
            aws_err = _winsock_determine_socket_error(wsa_err)
            logf(LogLevel.ERROR, LS_IO_SOCKET, "socket() failed with WSAError %d", wsa_err)
            raise_error(aws_err)
            return ErrorResult(aws_err)
        end

        # Set non-blocking
        non_blocking = Ref{UInt32}(1)
        if ccall((:ioctlsocket, _WS2_32), Cint, (UInt, UInt32, Ptr{UInt32}), handle, FIONBIO, non_blocking) != 0
            wsa_err = _wsa_get_last_error()
            aws_err = _winsock_determine_socket_error(wsa_err)
            logf(LogLevel.ERROR, LS_IO_SOCKET, "ioctlsocket(FIONBIO) failed with WSAError %d", wsa_err)
            raise_error(aws_err)
            _ = ccall((:closesocket, _WS2_32), Cint, (UInt,), handle)
            return ErrorResult(aws_err)
        end

        sock.io_handle.handle = Ptr{Cvoid}(handle)
        sock.io_handle.additional_data = C_NULL

        set_res = _winsock_socket_set_options!(sock, options)
        set_res isa ErrorResult && return set_res
        return nothing
    end

    # =============================================================================
    # Socket init
    # =============================================================================

    function socket_init_winsock(options::SocketOptions)::Union{Socket, ErrorResult}
        init_res = winsock_check_and_init!()
        init_res isa ErrorResult && return init_res

        impl = WinsockSocket()
        sock = Socket(
            SocketEndpoint(),
            SocketEndpoint(),
            copy(options),
            IoHandle(),
            nothing,
            nothing,
            SocketState.INIT,
            nothing,
            nothing,
            nothing,
            nothing,
            nothing,
            impl,
        )

        impl.read_io_data.socket = sock

        # Local sockets (named pipes) create handles during bind/connect.
        if options.domain != SocketDomain.LOCAL
            create_res = _winsock_create_underlying_socket!(sock, options)
            create_res isa ErrorResult && return create_res
        end

        return sock
    end

    # =============================================================================
    # Dispatch entrypoints
    # =============================================================================

    function socket_cleanup_impl(::WinsockSocket, sock::Socket)
        sock.impl === nothing && return nothing
        impl = sock.impl::WinsockSocket
        impl.cleaned_up && return nothing

        if socket_is_open(sock)
            socket_close(sock)
        end

        on_cleanup_complete = impl.on_cleanup_complete
        cleanup_ud = impl.cleanup_user_data

        impl.cleaned_up = true
        impl.on_cleanup_complete = nothing
        impl.cleanup_user_data = nothing

        # Keep impl alive if there are in-flight IOCP operations.
        pending = impl.read_io_data.in_use || !isempty(impl.pending_writes) || impl.incoming_socket !== nothing
        if !pending
            sock.io_handle = IoHandle()
            sock.impl = nothing
        end

        on_cleanup_complete !== nothing && Base.invokelatest(on_cleanup_complete, cleanup_ud)
        return nothing
    end

    function _winsock_maybe_finish_cleanup!(sock::Socket)
        sock.impl === nothing && return nothing
        impl = sock.impl::WinsockSocket
        impl.cleaned_up || return nothing

        pending = impl.read_io_data.in_use || !isempty(impl.pending_writes) || impl.incoming_socket !== nothing
        pending && return nothing

        sock.io_handle = IoHandle()
        sock.impl = nothing
        return nothing
    end

    function socket_set_close_callback_impl(::WinsockSocket, sock::Socket, fn::SocketOnShutdownCompleteFn, user_data)::Union{Nothing, ErrorResult}
        impl = sock.impl::WinsockSocket
        impl.close_user_data = user_data
        impl.on_close_complete = fn
        return nothing
    end

    function socket_set_cleanup_callback_impl(::WinsockSocket, sock::Socket, fn::SocketOnShutdownCompleteFn, user_data)::Union{Nothing, ErrorResult}
        impl = sock.impl::WinsockSocket
        impl.cleanup_user_data = user_data
        impl.on_cleanup_complete = fn
        return nothing
    end

    # No Apple secitem on Windows.
    socket_get_protocol_impl(::WinsockSocket, ::Socket) = null_buffer()
    socket_get_server_name_impl(::WinsockSocket, ::Socket) = null_buffer()

    # =============================================================================
    # Assign to event loop
    # =============================================================================

    function socket_assign_to_event_loop_impl(::WinsockSocket, sock::Socket, event_loop::EventLoop)::Union{Nothing, ErrorResult}
        if sock.event_loop !== nothing
            raise_error(ERROR_IO_EVENT_LOOP_ALREADY_ASSIGNED)
            return ErrorResult(ERROR_IO_EVENT_LOOP_ALREADY_ASSIGNED)
        end
        if sock.io_handle.handle == C_NULL
            raise_error(ERROR_INVALID_STATE)
            return ErrorResult(ERROR_INVALID_STATE)
        end

        sock.event_loop = event_loop
        res = event_loop_connect_to_io_completion_port!(event_loop, sock.io_handle)
        if res isa ErrorResult
            sock.event_loop = nothing
            return res
        end
        return nothing
    end

    # =============================================================================
    # Connect
    # =============================================================================

    function _winsock_connection_error(sock::Socket, error_code::Int)
        sock.state = SocketState.ERROR
        if sock.connection_result_fn !== nothing
            Base.invokelatest(sock.connection_result_fn, sock, error_code, sock.connect_accept_user_data)
        elseif sock.accept_result_fn !== nothing
            Base.invokelatest(sock.accept_result_fn, sock, error_code, nothing, sock.connect_accept_user_data)
        end
        return nothing
    end

    function _winsock_local_and_udp_connection_success(sock::Socket)
        sock.state = SocketState.CONNECTED
        if sock.connection_result_fn !== nothing
            Base.invokelatest(sock.connection_result_fn, sock, AWS_OP_SUCCESS, sock.connect_accept_user_data)
        end
        return nothing
    end

    function _winsock_stream_connection_success(sock::Socket)::Union{Nothing, ErrorResult}
        handle = _winsock_socket_handle(sock)

        # Apply keepalive, etc.
        _ = _winsock_socket_set_options!(sock, sock.options)

        connect_result = Ref{Cint}(0)
        result_length = Ref{Cint}(Cint(sizeof(Cint)))
        if ccall(
                (:getsockopt, _WS2_32),
                Cint,
                (UInt, Cint, Cint, Ptr{Cint}, Ptr{Cint}),
                handle,
                WS_SOL_SOCKET,
                WS_SO_ERROR,
                connect_result,
                result_length,
            ) != 0
            aws_err = _winsock_determine_socket_error(_wsa_get_last_error())
            raise_error(aws_err)
            return ErrorResult(aws_err)
        end

        if connect_result[] != 0
            aws_err = _winsock_determine_socket_error(connect_result[])
            raise_error(aws_err)
            return ErrorResult(aws_err)
        end

        upd = _winsock_update_local_endpoint_ipv4_ipv6!(sock)
        upd isa ErrorResult && return upd

        # Best-effort update of connect context.
        _ = ccall(
            (:setsockopt, _WS2_32),
            Cint,
            (UInt, Cint, Cint, Ptr{Cvoid}, Cint),
            handle,
            WS_SOL_SOCKET,
            WS_SO_UPDATE_CONNECT_CONTEXT,
            C_NULL,
            Cint(0),
        )

        sock.state = SocketState.CONNECTED
        sock.connection_result_fn !== nothing && Base.invokelatest(sock.connection_result_fn, sock, AWS_OP_SUCCESS, sock.connect_accept_user_data)
        return nothing
    end

    function _winsock_socket_connection_completion(
            event_loop,
            overlapped::IocpOverlapped,
            status_code::Int,
            num_bytes_transferred::Csize_t,
        )
        _ = event_loop
        _ = num_bytes_transferred

        args = overlapped.user_data::WinsockSocketConnectArgs
        io_data = args.io_data

        # Socket was cleaned up before completion.
        io_data.socket === nothing && (io_data.in_use = false; return nothing)

        if status_code == IO_OPERATION_CANCELLED
            io_data.in_use = false
            io_data.socket !== nothing && _winsock_maybe_finish_cleanup!(io_data.socket::Socket)
            return nothing
        end

        sock = args.socket::Union{Socket, Nothing}
        if sock !== nothing
            impl = sock.impl::WinsockSocket
            sock.readable_fn = nothing
            sock.readable_user_data = nothing
            impl.connect_args = nothing
            args.socket = nothing

            if status_code == 0
                res = _winsock_stream_connection_success(sock)
                if res isa ErrorResult
                    _winsock_connection_error(sock, res.code)
                end
            else
                aws_err = _winsock_determine_socket_error(status_code)
                raise_error(aws_err)
                _winsock_connection_error(sock, aws_err)
            end
        end

        io_data.in_use = false
        io_data.socket !== nothing && _winsock_maybe_finish_cleanup!(io_data.socket::Socket)
        return nothing
    end

    function _winsock_handle_socket_timeout(args::WinsockSocketConnectArgs, status::TaskStatus.T)
        if args.socket === nothing
            return nothing
        end

        sock = args.socket::Socket
        sock.state = SocketState.ERROR

        error_code = ERROR_IO_SOCKET_TIMEOUT
        if status == TaskStatus.CANCELED
            # Event loop is gone, the IOCP may never trigger.
            error_code = ERROR_IO_EVENT_LOOP_SHUTDOWN
            impl = sock.impl::WinsockSocket
            impl.read_io_data.in_use = false
        end

        conn_cb = sock.connection_result_fn
        conn_ud = sock.connect_accept_user_data

        raise_error(error_code)
        socket_close(sock)

        conn_cb !== nothing && Base.invokelatest(conn_cb, sock, error_code, conn_ud)
        args.socket = nothing
        return nothing
    end

    function _winsock_tcp_connect(
            sock::Socket,
            remote_endpoint::SocketEndpoint,
            connect_loop::EventLoop,
            bind_addr_ptr::Ptr{Cvoid},
            socket_addr_ptr::Ptr{Cvoid},
            sock_size::Cint,
        )::Union{Nothing, ErrorResult}
        impl = sock.impl::WinsockSocket
        copy!(sock.remote_endpoint, remote_endpoint)

        # Enable SO_REUSEADDR (best-effort)
        reuse = Ref{Cint}(1)
        _ = ccall(
            (:setsockopt, _WS2_32),
            Cint,
            (UInt, Cint, Cint, Ptr{Cint}, Cint),
            _winsock_socket_handle(sock),
            WS_SOL_SOCKET,
            WS_SO_REUSEADDR,
            reuse,
            Cint(sizeof(Cint)),
        )

        if socket_assign_to_event_loop(sock, connect_loop) isa ErrorResult
            sock.state = SocketState.ERROR
            return ErrorResult(last_error())
        end

        sock.state = SocketState.CONNECTING

        connect_fn = winsock_get_connectex_fn()
        connect_fn isa ErrorResult && return connect_fn
        connect_ptr = connect_fn::Ptr{Cvoid}

        # Create connect args and timeout task. Note: ScheduledTask is parametric on ctx type.
        args = WinsockSocketConnectArgs(sock, nothing, impl.read_io_data)
        task = ScheduledTask((ctx, st) -> _winsock_handle_socket_timeout(ctx, st), args; type_tag = "winsock_connect_timeout")
        args.timeout_task = task

        impl.connect_args = args
        impl.read_io_data.in_use = true
        impl.read_io_data.socket = sock

        iocp_overlapped_init!(impl.read_io_data.signal, _winsock_socket_connection_completion, args)

        fake_buffer = Ref{Int32}(0)
        _ = ccall((:bind, _WS2_32), Cint, (UInt, Ptr{Cvoid}, Cint), _winsock_socket_handle(sock), bind_addr_ptr, sock_size)

        connect_res = ccall(
            connect_ptr,
            Int32,
            (UInt, Ptr{Cvoid}, Cint, Ptr{Cvoid}, UInt32, Ptr{UInt32}, Ptr{Cvoid}),
            _winsock_socket_handle(sock),
            socket_addr_ptr,
            sock_size,
            fake_buffer,
            UInt32(0),
            C_NULL,
            iocp_overlapped_ptr(impl.read_io_data.signal),
        ) != 0

        now_ns = event_loop_current_clock_time(connect_loop)
        now_ns = now_ns isa ErrorResult ? UInt64(0) : now_ns
        time_to_run = now_ns

        if !connect_res
            err = _wsa_get_last_error()
            if err != ERROR_IO_PENDING
                impl.connect_args = nothing
                impl.read_io_data.in_use = false
                aws_err = _winsock_determine_socket_error(err)
                raise_error(aws_err)
                return ErrorResult(aws_err)
            end
            time_to_run += UInt64(sock.options.connect_timeout_ms) * UInt64(1_000_000)
        else
            # Immediate completion still triggers IOCP, but run timeout soon to free args.
            time_to_run += UInt64(500) * UInt64(1_000_000)
        end

        event_loop_schedule_task_future!(connect_loop, task, time_to_run)
        return nothing
    end

    function socket_connect_impl(::WinsockSocket, sock::Socket, options::SocketConnectOptions)::Union{Nothing, ErrorResult}
        remote_endpoint = options.remote_endpoint
        connect_loop = options.event_loop
        on_connection_result = options.on_connection_result
        user_data = options.user_data

        if sock.options.type != SocketType.DGRAM
            if sock.state != SocketState.INIT
                sock.state = SocketState.ERROR
                raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
                return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
            end
            on_connection_result === nothing && return ErrorResult(raise_error(ERROR_INVALID_ARGUMENT))
        else
            if sock.state != SocketState.INIT && !socket_state_has(sock.state, SocketState.CONNECTED_READ)
                sock.state = SocketState.ERROR
                raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
                return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
            end
        end

        port_res = socket_validate_port_for_connect(remote_endpoint.port, sock.options.domain)
        port_res isa ErrorResult && return port_res

        sock.connection_result_fn = on_connection_result
        sock.connect_accept_user_data = user_data

        if sock.options.domain == SocketDomain.LOCAL
            connect_loop === nothing && return ErrorResult(raise_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP))

            copy!(sock.remote_endpoint, remote_endpoint)
            handle = ccall(
                (:CreateFileA, _WIN_KERNEL32),
                Ptr{Cvoid},
                (Cstring, UInt32, UInt32, Ptr{Cvoid}, UInt32, UInt32, Ptr{Cvoid}),
                get_address(remote_endpoint),
                GENERIC_READ | GENERIC_WRITE,
                UInt32(0),
                C_NULL,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                C_NULL,
            )
            if handle == INVALID_HANDLE_VALUE
                win_err = _win_get_last_error()
                aws_err = _winsock_determine_socket_error(win_err)
                sock.state = SocketState.ERROR
                raise_error(aws_err)
                return ErrorResult(aws_err)
            end
            sock.io_handle.handle = handle
            if socket_assign_to_event_loop(sock, connect_loop) isa ErrorResult
                sock.state = SocketState.ERROR
                return ErrorResult(last_error())
            end

            # Schedule success on the loop.
            task = ScheduledTask((ctx, st) -> begin
                st == TaskStatus.RUN_READY || return nothing
                _winsock_local_and_udp_connection_success(ctx)
                return nothing
            end, sock; type_tag = "winsock_local_connect_success")
            event_loop_schedule_task_now!(connect_loop, task)
            return nothing
        end

        if sock.options.type == SocketType.DGRAM
            # UDP connect is synchronous.
            connect_loop === nothing && (connect_loop = nothing)
            copy!(sock.remote_endpoint, remote_endpoint)

            address = get_address(remote_endpoint)
            if sock.options.domain == SocketDomain.IPV4
                addr = _winsock_inet_pton_ipv4(address)
                addr isa ErrorResult && return addr
                sin = Ref(SockaddrIn(Cshort(WS_AF_INET), htons(remote_endpoint.port), addr, ntuple(_ -> UInt8(0), 8)))
                rc = GC.@preserve sin ccall(
                    (:connect, _WS2_32),
                    Cint,
                    (UInt, Ptr{Cvoid}, Cint),
                    _winsock_socket_handle(sock),
                    Ptr{Cvoid}(Base.unsafe_convert(Ptr{SockaddrIn}, sin)),
                    Cint(sizeof(SockaddrIn)),
                )
                if rc != 0
                    aws_err = _winsock_determine_socket_error(_wsa_get_last_error())
                    sock.state = SocketState.ERROR
                    raise_error(aws_err)
                    return ErrorResult(aws_err)
                end
            else
                addr6 = _winsock_inet_pton_ipv6(address)
                addr6 isa ErrorResult && return addr6
                sin6 = Ref(SockaddrIn6(Cushort(WS_AF_INET6), htons(remote_endpoint.port), Cuint(0), addr6, Cuint(0)))
                rc = GC.@preserve sin6 ccall(
                    (:connect, _WS2_32),
                    Cint,
                    (UInt, Ptr{Cvoid}, Cint),
                    _winsock_socket_handle(sock),
                    Ptr{Cvoid}(Base.unsafe_convert(Ptr{SockaddrIn6}, sin6)),
                    Cint(sizeof(SockaddrIn6)),
                )
                if rc != 0
                    aws_err = _winsock_determine_socket_error(_wsa_get_last_error())
                    sock.state = SocketState.ERROR
                    raise_error(aws_err)
                    return ErrorResult(aws_err)
                end
            end

            _ = _winsock_update_local_endpoint_ipv4_ipv6!(sock)
            sock.state = SocketState.CONNECTED

            if connect_loop !== nothing
                if socket_assign_to_event_loop(sock, connect_loop) isa ErrorResult
                    sock.state = SocketState.ERROR
                    return ErrorResult(last_error())
                end
                task = ScheduledTask((ctx, st) -> begin
                    st == TaskStatus.RUN_READY || return nothing
                    _winsock_local_and_udp_connection_success(ctx)
                    return nothing
                end, sock; type_tag = "winsock_udp_connect_success")
                event_loop_schedule_task_now!(connect_loop, task)
            end

            return nothing
        end

        # TCP stream connect
        connect_loop === nothing && return ErrorResult(raise_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP))

        address = get_address(remote_endpoint)
        if sock.options.domain == SocketDomain.IPV4
            addr = _winsock_inet_pton_ipv4(address)
            addr isa ErrorResult && return addr
            remote = Ref(SockaddrIn(Cshort(WS_AF_INET), htons(remote_endpoint.port), addr, ntuple(_ -> UInt8(0), 8)))
            bind_addr = Ref(SockaddrIn(Cshort(WS_AF_INET), Cushort(0), UInt32(0), ntuple(_ -> UInt8(0), 8)))
            return GC.@preserve remote bind_addr _winsock_tcp_connect(
                sock,
                remote_endpoint,
                connect_loop,
                Ptr{Cvoid}(Base.unsafe_convert(Ptr{SockaddrIn}, bind_addr)),
                Ptr{Cvoid}(Base.unsafe_convert(Ptr{SockaddrIn}, remote)),
                Cint(sizeof(SockaddrIn)),
            )
        else
            addr6 = _winsock_inet_pton_ipv6(address)
            addr6 isa ErrorResult && return addr6
            remote6 = Ref(SockaddrIn6(Cushort(WS_AF_INET6), htons(remote_endpoint.port), Cuint(0), addr6, Cuint(0)))
            bind6 = Ref(SockaddrIn6(Cushort(WS_AF_INET6), Cushort(0), Cuint(0), ntuple(_ -> UInt8(0), 16), Cuint(0)))
            return GC.@preserve remote6 bind6 _winsock_tcp_connect(
                sock,
                remote_endpoint,
                connect_loop,
                Ptr{Cvoid}(Base.unsafe_convert(Ptr{SockaddrIn6}, bind6)),
                Ptr{Cvoid}(Base.unsafe_convert(Ptr{SockaddrIn6}, remote6)),
                Cint(sizeof(SockaddrIn6)),
            )
        end
    end

    # =============================================================================
    # Bind / Listen
    # =============================================================================

    function _winsock_tcp_bind(sock::Socket, sockaddr_ptr::Ptr{Cvoid}, sock_size::Cint)::Union{Nothing, ErrorResult}
        handle = _winsock_socket_handle(sock)

        # Prevent duplicate binds.
        exclusive = Ref{Cint}(1)
        rc = ccall(
            (:setsockopt, _WS2_32),
            Cint,
            (UInt, Cint, Cint, Ptr{Cint}, Cint),
            handle,
            WS_SOL_SOCKET,
            WS_SO_EXCLUSIVEADDRUSE,
            exclusive,
            Cint(sizeof(Cint)),
        )
        if rc != 0
            aws_err = _winsock_determine_socket_error(_wsa_get_last_error())
            sock.state = SocketState.ERROR
            raise_error(aws_err)
            return ErrorResult(aws_err)
        end

        rc = ccall((:bind, _WS2_32), Cint, (UInt, Ptr{Cvoid}, Cint), handle, sockaddr_ptr, sock_size)
        if rc != 0
            aws_err = _winsock_determine_socket_error(_wsa_get_last_error())
            sock.state = SocketState.ERROR
            raise_error(aws_err)
            return ErrorResult(aws_err)
        end

        upd = _winsock_update_local_endpoint_ipv4_ipv6!(sock)
        upd isa ErrorResult && return upd
        sock.state = SocketState.BOUND
        return nothing
    end

    function _winsock_udp_bind(sock::Socket, sockaddr_ptr::Ptr{Cvoid}, sock_size::Cint)::Union{Nothing, ErrorResult}
        handle = _winsock_socket_handle(sock)
        rc = ccall((:bind, _WS2_32), Cint, (UInt, Ptr{Cvoid}, Cint), handle, sockaddr_ptr, sock_size)
        if rc != 0
            aws_err = _winsock_determine_socket_error(_wsa_get_last_error())
            sock.state = SocketState.ERROR
            raise_error(aws_err)
            return ErrorResult(aws_err)
        end

        upd = _winsock_update_local_endpoint_ipv4_ipv6!(sock)
        upd isa ErrorResult && return upd
        sock.state = SocketState.CONNECTED_READ
        return nothing
    end

    function socket_bind_impl(::WinsockSocket, sock::Socket, options::SocketBindOptions)::Union{Nothing, ErrorResult}
        local_endpoint = options.local_endpoint

        if sock.state != SocketState.INIT
            sock.state = SocketState.ERROR
            raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
            return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
        end

        port_res = socket_validate_port_for_bind(local_endpoint.port, sock.options.domain)
        port_res isa ErrorResult && return port_res

        if sock.options.domain == SocketDomain.LOCAL
            copy!(sock.local_endpoint, local_endpoint)
            pipe_name = get_address(local_endpoint)
            handle = ccall(
                (:CreateNamedPipeA, _WIN_KERNEL32),
                Ptr{Cvoid},
                (Cstring, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, Ptr{Cvoid}),
                pipe_name,
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
                UInt32(0),
                C_NULL,
            )
            if handle == INVALID_HANDLE_VALUE
                win_err = _win_get_last_error()
                aws_err = _winsock_determine_socket_error(win_err)
                sock.state = SocketState.ERROR
                raise_error(aws_err)
                return ErrorResult(aws_err)
            end
            sock.io_handle.handle = handle
            sock.state = SocketState.BOUND
            return nothing
        end

        address = get_address(local_endpoint)
        if sock.options.domain == SocketDomain.IPV4
            addr = _winsock_inet_pton_ipv4(address)
            addr isa ErrorResult && return addr
            sin = Ref(SockaddrIn(Cshort(WS_AF_INET), htons(local_endpoint.port), addr, ntuple(_ -> UInt8(0), 8)))
            return GC.@preserve sin begin
                if sock.options.type == SocketType.STREAM
                    _winsock_tcp_bind(sock, Ptr{Cvoid}(Base.unsafe_convert(Ptr{SockaddrIn}, sin)), Cint(sizeof(SockaddrIn)))
                else
                    _winsock_udp_bind(sock, Ptr{Cvoid}(Base.unsafe_convert(Ptr{SockaddrIn}, sin)), Cint(sizeof(SockaddrIn)))
                end
            end
        else
            addr6 = _winsock_inet_pton_ipv6(address)
            addr6 isa ErrorResult && return addr6
            sin6 = Ref(SockaddrIn6(Cushort(WS_AF_INET6), htons(local_endpoint.port), Cuint(0), addr6, Cuint(0)))
            return GC.@preserve sin6 begin
                if sock.options.type == SocketType.STREAM
                    _winsock_tcp_bind(sock, Ptr{Cvoid}(Base.unsafe_convert(Ptr{SockaddrIn6}, sin6)), Cint(sizeof(SockaddrIn6)))
                else
                    _winsock_udp_bind(sock, Ptr{Cvoid}(Base.unsafe_convert(Ptr{SockaddrIn6}, sin6)), Cint(sizeof(SockaddrIn6)))
                end
            end
        end
    end

    function socket_listen_impl(::WinsockSocket, sock::Socket, backlog_size::Integer)::Union{Nothing, ErrorResult}
        if sock.options.type == SocketType.DGRAM
            raise_error(ERROR_IO_SOCKET_INVALID_OPERATION_FOR_TYPE)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_OPERATION_FOR_TYPE)
        end

        if sock.options.domain == SocketDomain.LOCAL
            if sock.state != SocketState.BOUND
                raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
                return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
            end
            sock.state = SocketState.LISTENING
            return nothing
        end

        rc = ccall((:listen, _WS2_32), Cint, (UInt, Cint), _winsock_socket_handle(sock), Cint(backlog_size))
        if rc == 0
            sock.state = SocketState.LISTENING
            return nothing
        end

        aws_err = _winsock_determine_socket_error(_win_get_last_error())
        raise_error(aws_err)
        return ErrorResult(aws_err)
    end

    # =============================================================================
    # Accept
    # =============================================================================

    function _winsock_tcp_accept_event(event_loop, overlapped::IocpOverlapped, status_code::Int, num_bytes_transferred::Csize_t)
        _ = event_loop
        _ = num_bytes_transferred

        sock = overlapped.user_data::Socket
        impl = sock.impl::WinsockSocket
        io_data = impl.read_io_data

        if io_data.socket === nothing
            io_data.in_use = false
            if impl.incoming_socket !== nothing
                socket_cleanup!(impl.incoming_socket::Socket)
                impl.incoming_socket = nothing
            end
            _winsock_maybe_finish_cleanup!(sock)
            return nothing
        end

        if status_code == IO_OPERATION_CANCELLED || status_code == Int(WSAECONNRESET) || status_code == ERROR_OPERATION_ABORTED
            if impl.incoming_socket !== nothing
                socket_cleanup!(impl.incoming_socket::Socket)
                impl.incoming_socket = nothing
            end
            io_data.in_use = false
            _winsock_maybe_finish_cleanup!(sock)
            return nothing
        end

        if status_code != 0
            aws_err = _winsock_determine_socket_error(status_code)
            raise_error(aws_err)
            sock.state = SocketState.ERROR
            _winsock_connection_error(sock, aws_err)
            if impl.incoming_socket !== nothing
                socket_cleanup!(impl.incoming_socket::Socket)
                impl.incoming_socket = nothing
            end
            io_data.in_use = false
            _winsock_maybe_finish_cleanup!(sock)
            return nothing
        end

        if impl.stop_accept
            if impl.incoming_socket !== nothing
                socket_cleanup!(impl.incoming_socket::Socket)
                impl.incoming_socket = nothing
            end
            io_data.in_use = false
            _winsock_maybe_finish_cleanup!(sock)
            return nothing
        end

        incoming = impl.incoming_socket::Socket
        incoming.state = SocketState.CONNECTED

        # Best-effort parse remote endpoint from accept buffer.
        addr_mem = impl.accept_buffer
        family = unsafe_load(Ptr{Cushort}(pointer(addr_mem))) |> Cint
        port = UInt32(0)
        if family == WS_AF_INET
            port = UInt32(ntohs(unsafe_load(Ptr{Cushort}(pointer(addr_mem) + 2))))
            addr_ptr = Ptr{UInt8}(pointer(addr_mem) + 4)
            set_address!(incoming.remote_endpoint, _winsock_inet_ntop_ipv4(addr_ptr))
            incoming.options.domain = SocketDomain.IPV4
        elseif family == WS_AF_INET6
            port = UInt32(ntohs(unsafe_load(Ptr{Cushort}(pointer(addr_mem) + 2))))
            addr_ptr = Ptr{UInt8}(pointer(addr_mem) + 8)
            set_address!(incoming.remote_endpoint, _winsock_inet_ntop_ipv6(addr_ptr))
            incoming.options.domain = SocketDomain.IPV6
        end
        incoming.remote_endpoint.port = port

        # Make accepted socket non-blocking.
        nb = Ref{UInt32}(1)
        _ = ccall((:ioctlsocket, _WS2_32), Cint, (UInt, UInt32, Ptr{UInt32}), _winsock_socket_handle(incoming), FIONBIO, nb)

        _ = _winsock_socket_set_options!(incoming, sock.options)

        accepted = incoming
        impl.incoming_socket = nothing

        sock.accept_result_fn !== nothing && Base.invokelatest(sock.accept_result_fn, sock, AWS_OP_SUCCESS, accepted, sock.connect_accept_user_data)

        io_data.socket === nothing && return nothing

        # Setup next accept.
        _ = _winsock_socket_setup_accept(sock, nothing)
        return nothing
    end

    function _winsock_socket_setup_accept(sock::Socket, accept_loop::Union{EventLoop, Nothing})::Union{Nothing, ErrorResult}
        impl = sock.impl::WinsockSocket

        # Create incoming socket.
        incoming = socket_init(SocketOptions(; type = sock.options.type, domain = sock.options.domain))
        incoming isa ErrorResult && return incoming
        incoming_sock = incoming::Socket
        copy!(incoming_sock.local_endpoint, sock.local_endpoint)
        incoming_sock.state = SocketState.INIT

        impl.incoming_socket = incoming_sock

        if accept_loop !== nothing
            res = socket_assign_to_event_loop(sock, accept_loop)
            res isa ErrorResult && return res
        end

        iocp_overlapped_init!(impl.read_io_data.signal, _winsock_tcp_accept_event, sock)
        impl.read_io_data.in_use = true

        accept_fn = winsock_get_acceptex_fn()
        accept_fn isa ErrorResult && return accept_fn
        accept_ptr = accept_fn::Ptr{Cvoid}

        while true
            ok = ccall(
                accept_ptr,
                Int32,
                (UInt, UInt, Ptr{UInt8}, UInt32, UInt32, UInt32, Ptr{UInt32}, Ptr{Cvoid}),
                _winsock_socket_handle(sock),
                _winsock_socket_handle(incoming_sock),
                pointer(impl.accept_buffer),
                UInt32(0),
                UInt32(length(impl.accept_buffer) ÷ 2),
                UInt32(length(impl.accept_buffer) ÷ 2),
                C_NULL,
                iocp_overlapped_ptr(impl.read_io_data.signal),
            ) != 0

            if ok
                return nothing
            end

            win_err = _wsa_get_last_error()
            if win_err == ERROR_IO_PENDING
                raise_error(ERROR_IO_READ_WOULD_BLOCK)
                return ErrorResult(ERROR_IO_READ_WOULD_BLOCK)
            elseif win_err == Int(WSAECONNRESET)
                continue
            end

            sock.state = SocketState.ERROR
            impl.read_io_data.in_use = false
            socket_cleanup!(incoming_sock)
            impl.incoming_socket = nothing
            aws_err = _winsock_determine_socket_error(win_err)
            raise_error(aws_err)
            return ErrorResult(aws_err)
        end
    end

    function socket_start_accept_impl(::WinsockSocket, sock::Socket, accept_loop::EventLoop, options::SocketListenerOptions)::Union{Nothing, ErrorResult}
        options.on_accept_result === nothing && return ErrorResult(raise_error(ERROR_INVALID_ARGUMENT))

        if sock.state != SocketState.LISTENING
            raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
            return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
        end

        if sock.event_loop !== nothing && sock.event_loop != accept_loop
            raise_error(ERROR_IO_EVENT_LOOP_ALREADY_ASSIGNED)
            return ErrorResult(ERROR_IO_EVENT_LOOP_ALREADY_ASSIGNED)
        end

        impl = sock.impl::WinsockSocket
        impl.stop_accept = false

        sock.accept_result_fn = options.on_accept_result
        sock.connect_accept_user_data = options.on_accept_result_user_data

        if sock.options.domain == SocketDomain.LOCAL
            return _winsock_local_start_accept(sock, accept_loop, options)
        end

        el_to_use = sock.event_loop === nothing ? accept_loop : nothing
        res = _winsock_socket_setup_accept(sock, el_to_use)
        if res === nothing || (res isa ErrorResult && res.code == ERROR_IO_READ_WOULD_BLOCK)
            if options.on_accept_start !== nothing
                Base.invokelatest(options.on_accept_start, sock, AWS_OP_SUCCESS, options.on_accept_start_user_data)
            end
            return nothing
        end

        sock.state = SocketState.ERROR
        return res
    end

    function socket_stop_accept_impl(::WinsockSocket, sock::Socket)::Union{Nothing, ErrorResult}
        impl = sock.impl::WinsockSocket
        impl.stop_accept = true

        if sock.io_handle.handle != C_NULL
            _ = ccall((:CancelIoEx, _WIN_KERNEL32), Int32, (Ptr{Cvoid}, Ptr{Cvoid}), sock.io_handle.handle, C_NULL)
        end

        return nothing
    end

    # =============================================================================
    # Named pipe accept (LOCAL domain)
    # =============================================================================

    function _winsock_incoming_pipe_connection_event(event_loop, overlapped::IocpOverlapped, status_code::Int, num_bytes_transferred::Csize_t)
        _ = event_loop
        _ = num_bytes_transferred

        sock = overlapped.user_data::Socket
        impl = sock.impl::WinsockSocket
        io_data = impl.read_io_data

        if io_data.socket === nothing
            io_data.in_use = false
            _winsock_maybe_finish_cleanup!(sock)
            return nothing
        end

        if status_code == IO_OPERATION_CANCELLED
            io_data.in_use = false
            _winsock_maybe_finish_cleanup!(sock)
            return nothing
        end

        if status_code != 0
            aws_err = _winsock_determine_socket_error(status_code)
            raise_error(aws_err)
            sock.state = aws_err == ERROR_IO_SOCKET_CLOSED ? SocketState.CLOSED : SocketState.ERROR
            _winsock_connection_error(sock, aws_err)
            io_data.in_use = false
            _winsock_maybe_finish_cleanup!(sock)
            return nothing
        end

        while !impl.stop_accept
            new_sock_any = socket_init(SocketOptions(; type = sock.options.type, domain = sock.options.domain))
            if new_sock_any isa ErrorResult
                sock.state = SocketState.ERROR
                _winsock_connection_error(sock, new_sock_any.code)
                io_data.in_use = false
                _winsock_maybe_finish_cleanup!(sock)
                return nothing
            end
            new_sock = new_sock_any::Socket

            new_sock.state = SocketState.CONNECTED

            # Transfer current handle to the accepted socket. IoHandle is mutable, so don't
            # share the same instance between listener and accepted sockets.
            new_sock.io_handle.fd = sock.io_handle.fd
            new_sock.io_handle.handle = sock.io_handle.handle
            new_sock.io_handle.additional_data = sock.io_handle.additional_data
            new_sock.io_handle.set_queue = sock.io_handle.set_queue
            new_sock.io_handle.additional_ref = sock.io_handle.additional_ref
            if sock.event_loop !== nothing
                _ = event_loop_unsubscribe_from_io_events!(sock.event_loop, new_sock.io_handle)
            end
            new_sock.event_loop = nothing

            # Rebind listening socket with a new pipe instance.
            pipe_name = get_address(sock.local_endpoint)
            handle = ccall(
                (:CreateNamedPipeA, _WIN_KERNEL32),
                Ptr{Cvoid},
                (Cstring, UInt32, UInt32, UInt32, UInt32, UInt32, UInt32, Ptr{Cvoid}),
                pipe_name,
                PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_ACCEPT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUFFER_SIZE,
                PIPE_BUFFER_SIZE,
                UInt32(0),
                C_NULL,
            )
            if handle == INVALID_HANDLE_VALUE
                sock.state = SocketState.ERROR
                aws_err = _winsock_determine_socket_error(_win_get_last_error())
                raise_error(aws_err)
                _winsock_connection_error(sock, aws_err)
                io_data.in_use = false
                _winsock_maybe_finish_cleanup!(sock)
                return nothing
            end

            sock.io_handle.handle = handle
            sock.event_loop = nothing

            iocp_overlapped_init!(impl.read_io_data.signal, _winsock_incoming_pipe_connection_event, sock)
            if socket_assign_to_event_loop(sock, event_loop) isa ErrorResult
                sock.state = SocketState.ERROR
                _winsock_connection_error(sock, last_error())
                io_data.in_use = false
                _winsock_maybe_finish_cleanup!(sock)
                return nothing
            end

            sock.accept_result_fn !== nothing && Base.invokelatest(sock.accept_result_fn, sock, AWS_OP_SUCCESS, new_sock, sock.connect_accept_user_data)

            if io_data.socket === nothing
                io_data.in_use = false
                _winsock_maybe_finish_cleanup!(sock)
                return nothing
            end

            impl.read_io_data.in_use = true
            res = ccall(
                (:ConnectNamedPipe, _WIN_KERNEL32),
                Int32,
                (Ptr{Cvoid}, Ptr{Cvoid}),
                sock.io_handle.handle,
                iocp_overlapped_ptr(impl.read_io_data.signal),
            ) != 0

            if res
                return nothing
            end

            err = _win_get_last_error()
            if err == ERROR_PIPE_CONNECTED
                continue
            elseif err != ERROR_IO_PENDING
                aws_err = _winsock_determine_socket_error(err)
                raise_error(aws_err)
                sock.state = SocketState.ERROR
                impl.read_io_data.in_use = false
                _winsock_connection_error(sock, aws_err)
                _winsock_maybe_finish_cleanup!(sock)
                return nothing
            end

            # IO pending; wait for completion.
            return nothing
        end

        io_data.in_use = false
        _winsock_maybe_finish_cleanup!(sock)
        return nothing
    end

    function _winsock_named_pipe_connected_immediately_task(io_data::WinsockIoOperationData, status::TaskStatus.T)
        if status != TaskStatus.RUN_READY
            io_data.in_use = false
            io_data.socket !== nothing && _winsock_maybe_finish_cleanup!(io_data.socket::Socket)
            return nothing
        end
        sock = io_data.socket::Socket
        _winsock_incoming_pipe_connection_event(sock.event_loop, io_data.signal, AWS_OP_SUCCESS, Csize_t(0))
        return nothing
    end

    function _winsock_local_start_accept(sock::Socket, accept_loop::EventLoop, options::SocketListenerOptions)::Union{Nothing, ErrorResult}
        impl = sock.impl::WinsockSocket
        impl.stop_accept = false

        iocp_overlapped_init!(impl.read_io_data.signal, _winsock_incoming_pipe_connection_event, sock)
        impl.read_io_data.in_use = true

        if sock.event_loop === nothing
            res = socket_assign_to_event_loop(sock, accept_loop)
            res isa ErrorResult && (impl.read_io_data.in_use = false; return res)
        end

        ok = ccall(
            (:ConnectNamedPipe, _WIN_KERNEL32),
            Int32,
            (Ptr{Cvoid}, Ptr{Cvoid}),
            sock.io_handle.handle,
            iocp_overlapped_ptr(impl.read_io_data.signal),
        ) != 0

        if !ok
            err = _win_get_last_error()
            if err != ERROR_IO_PENDING && err != ERROR_PIPE_CONNECTED
                impl.read_io_data.in_use = false
                aws_err = _winsock_determine_socket_error(err)
                raise_error(aws_err)
                return ErrorResult(aws_err)
            elseif err == ERROR_PIPE_CONNECTED
                # No IOCP event will fire; schedule a task to finish the accept.
                task = ScheduledTask((ctx, st) -> _winsock_named_pipe_connected_immediately_task(ctx, st), impl.read_io_data; type_tag = "winsock_pipe_connected_immediately")
                event_loop_schedule_task_now!(sock.event_loop, task)
            end
        end

        if options.on_accept_start !== nothing
            Base.invokelatest(options.on_accept_start, sock, AWS_OP_SUCCESS, options.on_accept_start_user_data)
        end

        return nothing
    end

    # =============================================================================
    # Close / shutdown
    # =============================================================================

    function socket_close_impl(::WinsockSocket, sock::Socket)::Union{Nothing, ErrorResult}
        impl = sock.impl::WinsockSocket

        if sock.event_loop !== nothing && sock.state == SocketState.LISTENING && !impl.stop_accept
            _ = socket_stop_accept(sock)
        end

        if impl.connect_args !== nothing
            impl.connect_args.socket = nothing
            impl.connect_args = nothing
        end

        # Prevent user callbacks firing after close (in case IO completes concurrently).
        sock.readable_fn = nothing
        sock.readable_user_data = nothing
        sock.connection_result_fn = nothing
        sock.accept_result_fn = nothing

        # Detach pending writes for callback purposes, but keep the socket reference
        # so the completion callback can remove them from the pending list.
        for req in impl.pending_writes
            req.detached = true
        end

        if sock.io_handle.handle != C_NULL
            if sock.options.domain == SocketDomain.LOCAL
                _ = ccall((:CloseHandle, _WIN_KERNEL32), Int32, (Ptr{Cvoid},), sock.io_handle.handle)
            else
                _ = ccall((:shutdown, _WS2_32), Cint, (UInt, Cint), _winsock_socket_handle(sock), WS_SD_BOTH)
                _ = ccall((:closesocket, _WS2_32), Cint, (UInt,), _winsock_socket_handle(sock))
            end
            sock.io_handle.handle = C_NULL
        end

        sock.event_loop = nothing
        sock.state = SocketState.CLOSED

        if impl.on_close_complete !== nothing
            cb = impl.on_close_complete
            ud = impl.close_user_data
            cb !== nothing && Base.invokelatest(cb, ud)
        end

        return nothing
    end

    function socket_shutdown_dir_impl(::WinsockSocket, sock::Socket, dir::ChannelDirection.T)::Union{Nothing, ErrorResult}
        how = dir == ChannelDirection.READ ? WS_SD_RECEIVE : WS_SD_SEND
        if ccall((:shutdown, _WS2_32), Cint, (UInt, Cint), _winsock_socket_handle(sock), how) != 0
            aws_err = _winsock_determine_socket_error(_wsa_get_last_error())
            raise_error(aws_err)
            return ErrorResult(aws_err)
        end

        if dir == ChannelDirection.READ
            sock.state = socket_state_clear(sock.state, SocketState.CONNECTED_READ)
        else
            sock.state = socket_state_clear(sock.state, SocketState.CONNECTED_WRITE)
        end

        return nothing
    end

    # =============================================================================
    # Readable subscription
    # =============================================================================

    function _winsock_stream_readable_event(event_loop, overlapped::IocpOverlapped, status_code::Int, num_bytes_transferred::Csize_t)
        _ = event_loop
        _ = num_bytes_transferred

        sock = overlapped.user_data::Socket
        impl = sock.impl::WinsockSocket

        if status_code == ERROR_OPERATION_ABORTED || status_code == IO_OPERATION_CANCELLED
            impl.waiting_on_readable = false
            impl.read_io_data.in_use = false
            _winsock_maybe_finish_cleanup!(sock)
            return nothing
        end

        impl.waiting_on_readable = false

        err_code = AWS_OP_SUCCESS
        if status_code != 0 && status_code != ERROR_IO_PENDING
            err_code = _winsock_determine_socket_error(status_code)
            if err_code == ERROR_IO_SOCKET_CLOSED
                sock.state = SocketState.CLOSED
            else
                sock.state = SocketState.ERROR
            end
        end

        sock.readable_fn !== nothing && Base.invokelatest(sock.readable_fn, sock, err_code, sock.readable_user_data)

        if !impl.waiting_on_readable
            impl.read_io_data.in_use = false
        end

        _winsock_maybe_finish_cleanup!(sock)
        return nothing
    end

    function _winsock_dgram_readable_event(event_loop, overlapped::IocpOverlapped, status_code::Int, num_bytes_transferred::Csize_t)
        _ = event_loop
        _ = num_bytes_transferred

        sock = overlapped.user_data::Socket
        impl = sock.impl::WinsockSocket

        if status_code == ERROR_OPERATION_ABORTED || status_code == IO_OPERATION_CANCELLED
            impl.waiting_on_readable = false
            impl.read_io_data.in_use = false
            _winsock_maybe_finish_cleanup!(sock)
            return nothing
        end

        impl.waiting_on_readable = false

        err_code = AWS_OP_SUCCESS
        if status_code != 0 && status_code != ERROR_IO_PENDING && status_code != IO_STATUS_BUFFER_OVERFLOW
            err_code = _winsock_determine_socket_error(status_code)
            if err_code == ERROR_IO_SOCKET_CLOSED
                sock.state = SocketState.CLOSED
            else
                sock.state = SocketState.ERROR
            end
        end

        sock.readable_fn !== nothing && Base.invokelatest(sock.readable_fn, sock, err_code, sock.readable_user_data)

        if !impl.waiting_on_readable
            impl.read_io_data.in_use = false
        end

        _winsock_maybe_finish_cleanup!(sock)
        return nothing
    end

    function socket_subscribe_to_readable_events_impl(::WinsockSocket, sock::Socket, on_readable::SocketOnReadableFn, user_data)::Union{Nothing, ErrorResult}
        if sock.event_loop === nothing
            raise_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
            return ErrorResult(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
        end
        if sock.readable_fn !== nothing
            raise_error(ERROR_IO_ALREADY_SUBSCRIBED)
            return ErrorResult(ERROR_IO_ALREADY_SUBSCRIBED)
        end
        if !socket_state_has(sock.state, SocketState.CONNECTED_READ)
            raise_error(ERROR_IO_SOCKET_NOT_CONNECTED)
            return ErrorResult(ERROR_IO_SOCKET_NOT_CONNECTED)
        end

        impl = sock.impl::WinsockSocket
        impl.read_io_data.in_use && return ErrorResult(raise_error(ERROR_IO_ALREADY_SUBSCRIBED))

        sock.readable_fn = on_readable
        sock.readable_user_data = user_data

        impl.read_io_data.in_use = true
        impl.waiting_on_readable = true

        if sock.options.type == SocketType.DGRAM
            iocp_overlapped_init!(impl.read_io_data.signal, _winsock_dgram_readable_event, sock)
            buf = Ref(WSABUF(UInt32(0), C_NULL))
            flags = Ref{UInt32}(MSG_PEEK)
            rc = ccall(
                (:WSARecv, _WS2_32),
                Cint,
                (UInt, Ptr{WSABUF}, UInt32, Ptr{UInt32}, Ptr{UInt32}, Ptr{Cvoid}, Ptr{Cvoid}),
                _winsock_socket_handle(sock),
                buf,
                UInt32(1),
                C_NULL,
                flags,
                iocp_overlapped_ptr(impl.read_io_data.signal),
                C_NULL,
            )
            if rc != 0
                err = _wsa_get_last_error()
                if err != ERROR_IO_PENDING
                    impl.read_io_data.in_use = false
                    impl.waiting_on_readable = false
                    aws_err = _winsock_determine_socket_error(err)
                    raise_error(aws_err)
                    return ErrorResult(aws_err)
                end
            end
            return nothing
        end

        iocp_overlapped_init!(impl.read_io_data.signal, _winsock_stream_readable_event, sock)
        fake = Ref{UInt32}(0)
        ok = ccall(
            (:ReadFile, _WIN_KERNEL32),
            Int32,
            (Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{UInt32}, Ptr{Cvoid}),
            sock.io_handle.handle,
            fake,
            UInt32(0),
            C_NULL,
            iocp_overlapped_ptr(impl.read_io_data.signal),
        ) != 0

        if !ok
            err = _win_get_last_error()
            if err != ERROR_IO_PENDING
                impl.read_io_data.in_use = false
                impl.waiting_on_readable = false
                aws_err = _winsock_determine_socket_error(err)
                raise_error(aws_err)
                return ErrorResult(aws_err)
            end
        end

        return nothing
    end

    # =============================================================================
    # Read / Write
    # =============================================================================

    function _winsock_read_would_block(sock::Socket)::ErrorResult
        impl = sock.impl::WinsockSocket
        if !impl.waiting_on_readable
            impl.waiting_on_readable = true
            impl.read_io_data.in_use = true

            if sock.options.type == SocketType.DGRAM
                iocp_overlapped_init!(impl.read_io_data.signal, _winsock_dgram_readable_event, sock)
                buf = Ref(WSABUF(UInt32(0), C_NULL))
                flags = Ref{UInt32}(MSG_PEEK)
                rc = ccall(
                    (:WSARecv, _WS2_32),
                    Cint,
                    (UInt, Ptr{WSABUF}, UInt32, Ptr{UInt32}, Ptr{UInt32}, Ptr{Cvoid}, Ptr{Cvoid}),
                    _winsock_socket_handle(sock),
                    buf,
                    UInt32(1),
                    C_NULL,
                    flags,
                    iocp_overlapped_ptr(impl.read_io_data.signal),
                    C_NULL,
                )
                if rc != 0
                    err = _wsa_get_last_error()
                    if err != ERROR_IO_PENDING
                        impl.waiting_on_readable = false
                        impl.read_io_data.in_use = false
                        aws_err = _winsock_determine_socket_error(err)
                        raise_error(aws_err)
                        return ErrorResult(aws_err)
                    end
                end
            else
                iocp_overlapped_init!(impl.read_io_data.signal, _winsock_stream_readable_event, sock)
                fake = Ref{UInt32}(0)
                ok = ccall(
                    (:ReadFile, _WIN_KERNEL32),
                    Int32,
                    (Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{UInt32}, Ptr{Cvoid}),
                    sock.io_handle.handle,
                    fake,
                    UInt32(0),
                    C_NULL,
                    iocp_overlapped_ptr(impl.read_io_data.signal),
                ) != 0
                if !ok
                    err = _win_get_last_error()
                    if err != ERROR_IO_PENDING
                        impl.waiting_on_readable = false
                        impl.read_io_data.in_use = false
                        aws_err = _winsock_determine_socket_error(err)
                        raise_error(aws_err)
                        return ErrorResult(aws_err)
                    end
                end
            end
        end

        raise_error(ERROR_IO_READ_WOULD_BLOCK)
        return ErrorResult(ERROR_IO_READ_WOULD_BLOCK)
    end

    function socket_read_impl(::WinsockSocket, sock::Socket, buffer::ByteBuffer)::Union{Tuple{Nothing, Csize_t}, ErrorResult}
        if sock.event_loop !== nothing && !event_loop_thread_is_callers_thread(sock.event_loop)
            raise_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
            return ErrorResult(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
        end
        if !socket_state_has(sock.state, SocketState.CONNECTED_READ)
            raise_error(ERROR_IO_SOCKET_NOT_CONNECTED)
            return ErrorResult(ERROR_IO_SOCKET_NOT_CONNECTED)
        end

        remaining = buffer.capacity - buffer.len
        remaining == 0 && return (nothing, Csize_t(0))

        if sock.options.domain == SocketDomain.LOCAL
            # Port of aws-c-io s_local_read(): PeekNamedPipe() then synchronous ReadFile(),
            # and when no bytes are available schedule a 0-byte ReadFile() for IOCP readability.
            bytes_available = Ref{UInt32}(0)
            peek_ok = ccall(
                (:PeekNamedPipe, _WIN_KERNEL32),
                Int32,
                (Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{UInt32}, Ptr{UInt32}, Ptr{UInt32}),
                sock.io_handle.handle,
                C_NULL,
                UInt32(0),
                C_NULL,
                bytes_available,
                C_NULL,
            ) != 0

            if !peek_ok
                win_err = _win_get_last_error()
                aws_err = _winsock_determine_socket_error(win_err)
                raise_error(aws_err)
                return ErrorResult(aws_err)
            end

            if bytes_available[] == 0
                impl = sock.impl::WinsockSocket
                if !impl.waiting_on_readable
                    impl.waiting_on_readable = true
                    impl.read_io_data.in_use = true
                    iocp_overlapped_init!(impl.read_io_data.signal, _winsock_stream_readable_event, sock)
                    fake = Ref{UInt32}(0)
                    ok = ccall(
                        (:ReadFile, _WIN_KERNEL32),
                        Int32,
                        (Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{UInt32}, Ptr{Cvoid}),
                        sock.io_handle.handle,
                        fake,
                        UInt32(0),
                        C_NULL,
                        iocp_overlapped_ptr(impl.read_io_data.signal),
                    ) != 0
                    if !ok
                        err = _win_get_last_error()
                        if err != ERROR_IO_PENDING
                            impl.waiting_on_readable = false
                            impl.read_io_data.in_use = false
                            aws_err = _winsock_determine_socket_error(err)
                            raise_error(aws_err)
                            return ErrorResult(aws_err)
                        end
                    end
                end

                raise_error(ERROR_IO_READ_WOULD_BLOCK)
                return ErrorResult(ERROR_IO_READ_WOULD_BLOCK)
            end

            bytes_to_read = UInt32(min(Int(bytes_available[]), remaining))
            buf_ptr = pointer(getfield(buffer, :mem)) + Int(buffer.len)
            bytes_read = Ref{UInt32}(0)
            ok = ccall(
                (:ReadFile, _WIN_KERNEL32),
                Int32,
                (Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{UInt32}, Ptr{Cvoid}),
                sock.io_handle.handle,
                buf_ptr,
                bytes_to_read,
                bytes_read,
                C_NULL,
            ) != 0

            if !ok
                win_err = _win_get_last_error()
                aws_err = _winsock_determine_socket_error(win_err)
                if aws_err == ERROR_IO_SOCKET_CLOSED
                    sock.state = SocketState.CLOSED
                else
                    sock.state = SocketState.ERROR
                end
                raise_error(aws_err)
                return ErrorResult(aws_err)
            end

            amount = Csize_t(bytes_read[])
            setfield!(buffer, :len, buffer.len + amount)
            return (nothing, amount)
        end

        bytes_to_read = remaining
        if sock.options.type == SocketType.STREAM
            # Be defensive: if the socket ever ends up in blocking mode, a 2nd `recv` on the
            # event-loop thread can deadlock shutdown. Only call `recv` when bytes are ready.
            bytes_available = Ref{UInt32}(0)
            if ccall(
                    (:ioctlsocket, _WS2_32),
                    Cint,
                    (UInt, UInt32, Ptr{UInt32}),
                    _winsock_socket_handle(sock),
                    FIONREAD,
                    bytes_available,
                ) != 0
                aws_err = _winsock_determine_socket_error(_wsa_get_last_error())
                raise_error(aws_err)
                return ErrorResult(aws_err)
            end

            if bytes_available[] == 0
                return _winsock_read_would_block(sock)
            end

            avail = Csize_t(bytes_available[])
            bytes_to_read = avail < bytes_to_read ? avail : bytes_to_read
        end

        buf_ptr = pointer(getfield(buffer, :mem)) + Int(buffer.len)
        max_cint = Csize_t(typemax(Cint))
        bytes_to_read_cint = bytes_to_read > max_cint ? Cint(typemax(Cint)) : Cint(bytes_to_read)
        read_val = ccall(
            (:recv, _WS2_32),
            Cint,
            (UInt, Ptr{UInt8}, Cint, Cint),
            _winsock_socket_handle(sock),
            buf_ptr,
            bytes_to_read_cint,
            Cint(0),
        )

        if read_val > 0
            amount = Csize_t(read_val)
            setfield!(buffer, :len, buffer.len + amount)
            return (nothing, amount)
        end

        if read_val == 0
            sock.state = SocketState.CLOSED
            raise_error(ERROR_IO_SOCKET_CLOSED)
            return ErrorResult(ERROR_IO_SOCKET_CLOSED)
        end

        err = _wsa_get_last_error()
        if err == Int(WSAEWOULDBLOCK)
            return _winsock_read_would_block(sock)
        end

        aws_err = _winsock_determine_socket_error(err)
        raise_error(aws_err)
        return ErrorResult(aws_err)
    end

    function socket_write_impl(::WinsockSocket, sock::Socket, cursor::ByteCursor, written_fn::Union{SocketOnWriteCompletedFn, Nothing}, user_data)::Union{Nothing, ErrorResult}
        if sock.event_loop === nothing || !event_loop_thread_is_callers_thread(sock.event_loop)
            raise_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
            return ErrorResult(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
        end
        if !socket_state_has(sock.state, SocketState.CONNECTED_WRITE)
            raise_error(ERROR_IO_SOCKET_NOT_CONNECTED)
            return ErrorResult(ERROR_IO_SOCKET_NOT_CONNECTED)
        end
        if cursor.len > Csize_t(typemax(UInt32))
            raise_error(ERROR_INVALID_BUFFER_SIZE)
            return ErrorResult(ERROR_INVALID_BUFFER_SIZE)
        end

        impl = sock.impl::WinsockSocket
        req = WinsockSocketWriteRequest(sock, false, cursor, cursor.len, written_fn, user_data, IocpOverlapped())
        iocp_overlapped_init!(req.overlapped, _winsock_socket_written_event, req)
        push!(impl.pending_writes, req)

        ok = ccall(
            (:WriteFile, _WIN_KERNEL32),
            Int32,
            (Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{UInt32}, Ptr{Cvoid}),
            sock.io_handle.handle,
            cursor.ptr,
            UInt32(cursor.len),
            C_NULL,
            iocp_overlapped_ptr(req.overlapped),
        ) != 0

        if !ok
            err = _win_get_last_error()
            if err != ERROR_IO_PENDING
                pop!(impl.pending_writes)
                aws_err = _winsock_determine_socket_error(err)
                raise_error(aws_err)
                return ErrorResult(aws_err)
            end
        end

        return nothing
    end

    function _winsock_socket_written_event(event_loop, overlapped::IocpOverlapped, status_code::Int, num_bytes_transferred::Csize_t)
        _ = event_loop

        req = overlapped.user_data::WinsockSocketWriteRequest
        sock = req.socket::Union{Socket, Nothing}
        aws_err = status_code == 0 ? AWS_OP_SUCCESS : _winsock_determine_socket_error(status_code)

        # Remove from pending list if possible.
        if sock !== nothing
            impl = (sock::Socket).impl::WinsockSocket
            idx = findfirst(==(req), impl.pending_writes)
            idx !== nothing && deleteat!(impl.pending_writes, idx)
        end

        if aws_err != AWS_OP_SUCCESS
            raise_error(aws_err)
        end

        if req.written_fn !== nothing
            cb_sock = req.detached ? nothing : sock
            Base.invokelatest(req.written_fn, cb_sock, aws_err, num_bytes_transferred, req.user_data)
        end

        req.socket = nothing
        sock !== nothing && _winsock_maybe_finish_cleanup!(sock::Socket)
        return nothing
    end

    # =============================================================================
    # Socket misc
    # =============================================================================

    function socket_set_options_impl(::WinsockSocket, sock::Socket, options::SocketOptions)::Union{Nothing, ErrorResult}
        return _winsock_socket_set_options!(sock, options)
    end

    function socket_get_error_impl(::WinsockSocket, sock::Socket)::Int
        if sock.options.domain != SocketDomain.LOCAL
            handle = _winsock_socket_handle(sock)
            connect_result = Ref{Cint}(0)
            result_length = Ref{Cint}(Cint(sizeof(Cint)))
            if ccall(
                    (:getsockopt, _WS2_32),
                    Cint,
                    (UInt, Cint, Cint, Ptr{Cint}, Ptr{Cint}),
                    handle,
                    WS_SOL_SOCKET,
                    WS_SO_ERROR,
                    connect_result,
                    result_length,
                ) != 0
                return _winsock_determine_socket_error(_wsa_get_last_error())
            end
            connect_result[] != 0 && return _winsock_determine_socket_error(connect_result[])
        else
            return _winsock_determine_socket_error(_wsa_get_last_error())
        end
        return AWS_OP_SUCCESS
    end

    function socket_is_open_impl(::WinsockSocket, sock::Socket)::Bool
        return sock.io_handle.handle != C_NULL
    end

else
    # -------------------------------------------------------------------------
    # Non-Windows fallback stubs
    # -------------------------------------------------------------------------
    function socket_init_winsock(options::SocketOptions)::Union{Socket, ErrorResult}
        _ = options
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end
end
