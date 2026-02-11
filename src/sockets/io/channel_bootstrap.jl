# AWS IO Library - Channel Bootstrap
# Port of aws-c-io/source/channel_bootstrap.c

# Callback types for bootstrap operations
const OnBootstrapChannelCreationFn = Function  # (bootstrap, error_code, channel, user_data) -> nothing
const OnBootstrapChannelSetupFn = Function     # (bootstrap, error_code, channel, user_data) -> nothing
const OnBootstrapChannelShutdownFn = Function  # (bootstrap, error_code, channel, user_data) -> nothing
const OnServerListenerSetupFn = Function       # (server_bootstrap, error_code, user_data) -> nothing
const OnIncomingChannelSetupFn = Function      # (server_bootstrap, error_code, channel, user_data) -> nothing
const OnIncomingChannelShutdownFn = Function   # (server_bootstrap, error_code, channel, user_data) -> nothing
const OnServerListenerDestroyFn = Function     # (server_bootstrap, user_data) -> nothing
const ChannelOnProtocolNegotiatedFn = Function # (new_slot, protocol::ByteBuffer, user_data) -> AbstractChannelHandler

# Client bootstrap options
struct ClientBootstrapOptions
    event_loop_group::EventLoopGroup
    host_resolver::HostResolver
    host_resolution_config::Union{HostResolutionConfig, Nothing}
    socket_options::SocketOptions
    tls_connection_options::Any  # TlsConnectionOptions or nothing
    on_protocol_negotiated::Union{Function, Nothing}
    on_creation_callback::Union{Function, Nothing}
    on_setup_callback::Union{Function, Nothing}
    on_shutdown_callback::Union{Function, Nothing}
    user_data::Any
end

function ClientBootstrapOptions(;
        event_loop_group,
        host_resolver,
        host_resolution_config = nothing,
        socket_options::SocketOptions = SocketOptions(),
        tls_connection_options = nothing,
        on_protocol_negotiated = nothing,
        on_creation_callback = nothing,
        on_setup_callback = nothing,
        on_shutdown_callback = nothing,
        user_data = nothing,
    )
    return ClientBootstrapOptions(
        event_loop_group,
        host_resolver,
        host_resolution_config,
        socket_options,
        tls_connection_options,
        on_protocol_negotiated,
        on_creation_callback,
        on_setup_callback,
        on_shutdown_callback,
        user_data,
    )
end

# Client bootstrap - for creating outgoing connections
mutable struct ClientBootstrap
    event_loop_group::EventLoopGroup
    host_resolver::HostResolver
    host_resolution_config::Union{HostResolutionConfig, Nothing}
    socket_options::SocketOptions
    tls_connection_options::Any  # TlsConnectionOptions or nothing
    on_protocol_negotiated::Union{Function, Nothing}
    on_creation_callback::Union{Function, Nothing}
    on_setup_callback::Union{Function, Nothing}
    on_shutdown_callback::Union{Function, Nothing}
    user_data::Any
    @atomic shutdown::Bool
end

function ClientBootstrap(options::ClientBootstrapOptions)
    bootstrap = ClientBootstrap(
        options.event_loop_group,
        options.host_resolver,
        options.host_resolution_config,
        options.socket_options,
        options.tls_connection_options,
        options.on_protocol_negotiated,
        options.on_creation_callback,
        options.on_setup_callback,
        options.on_shutdown_callback,
        options.user_data,
        false,
    )

    logf(LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP, "ClientBootstrap: created")

    return bootstrap
end

@inline function _socket_uses_network_framework_tls(socket::Socket, tls_options)::Bool
    @static if Sys.isapple()
        # Network.framework TLS is only active when SecItem support is enabled.
        # Otherwise, we stack the pure-Julia TLS channel handler on top of the socket.
        return tls_options !== nothing && socket.impl isa NWSocket && is_using_secitem()
    else
        return false
    end
end

function _install_protocol_handler_from_socket(
        channel::Channel,
        socket::Socket,
        on_protocol_negotiated::ChannelOnProtocolNegotiatedFn,
        user_data,
    )::Union{Nothing, ErrorResult}
    protocol = socket_get_protocol(socket)
    new_slot = channel_slot_new!(channel)
    channel_slot_insert_end!(channel, new_slot)
    handler = on_protocol_negotiated(new_slot, protocol, user_data)
    if handler === nothing
        raise_error(ERROR_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE)
        return ErrorResult(ERROR_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE)
    end
    channel_slot_set_handler!(new_slot, handler)
    return nothing
end

# Connection request tracking
mutable struct SocketConnectionRequest
    bootstrap::ClientBootstrap
    host::String
    port::UInt32
    socket_options::SocketOptions
    socket::Union{Socket, Nothing}  # nullable
    channel::Union{Channel, Nothing}  # nullable
    tls_connection_options::Any  # TlsConnectionOptions or nothing
    on_protocol_negotiated::Union{ChannelOnProtocolNegotiatedFn, Nothing}
    on_creation::Union{OnBootstrapChannelCreationFn, Nothing}
    on_setup::Union{OnBootstrapChannelSetupFn, Nothing}  # nullable
    on_shutdown::Union{OnBootstrapChannelShutdownFn, Nothing}  # nullable
    user_data::Any
    enable_read_back_pressure::Bool
    requested_event_loop::Union{EventLoop, Nothing}
    event_loop::Union{EventLoop, Nothing}
    addresses::Vector{HostAddress}
    addresses_count::Int
    failed_count::Int
    connection_chosen::Bool
end

mutable struct SocketConnectionAttempt
    request::SocketConnectionRequest
    host_address::HostAddress
end

# Initiate a connection to a host
function client_bootstrap_connect!(
        bootstrap::ClientBootstrap,
        host::AbstractString,
        port::Integer;
        socket_options::SocketOptions = bootstrap.socket_options,
        tls_connection_options = bootstrap.tls_connection_options,
        on_protocol_negotiated = bootstrap.on_protocol_negotiated,
        on_creation::Union{OnBootstrapChannelCreationFn, Nothing} = bootstrap.on_creation_callback,
        on_setup::Union{OnBootstrapChannelSetupFn, Nothing} = bootstrap.on_setup_callback,
        on_shutdown::Union{OnBootstrapChannelShutdownFn, Nothing} = bootstrap.on_shutdown_callback,
        user_data = bootstrap.user_data,
        enable_read_back_pressure::Bool = false,
        requested_event_loop::Union{EventLoop, Nothing} = nothing,
        host_resolution_config::Union{HostResolutionConfig, Nothing} = bootstrap.host_resolution_config,
    )::Union{Nothing, ErrorResult}
    if @atomic bootstrap.shutdown
        raise_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
        return ErrorResult(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end

    if requested_event_loop !== nothing &&
            !_event_loop_group_contains_loop(bootstrap.event_loop_group, requested_event_loop)
        raise_error(ERROR_IO_PINNED_EVENT_LOOP_MISMATCH)
        return ErrorResult(ERROR_IO_PINNED_EVENT_LOOP_MISMATCH)
    end

    host_str = String(host)

    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,
        "ClientBootstrap: initiating connection to $host_str:$port"
    )

    # Create connection request
    request = SocketConnectionRequest(
        bootstrap,
        host_str,
        UInt32(port),
        socket_options,
        nothing,
        nothing,
        tls_connection_options,
        on_protocol_negotiated,
        on_creation,
        on_setup,
        on_shutdown,
        user_data,
        enable_read_back_pressure,
        requested_event_loop,
        nothing,
        HostAddress[],
        0,
        0,
        false,
    )

    # Resolve host
    resolve_result = host_resolver_resolve!(
        bootstrap.host_resolver,
        host_str,
        (resolver, host, error_code, addresses) -> _on_host_resolved(request, error_code, addresses),
        request,
        resolution_config = host_resolution_config,
    )

    if resolve_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: failed to initiate DNS resolution"
        )
        return resolve_result
    end

    return nothing
end

function _event_loop_group_contains_loop(elg, event_loop::EventLoop)::Bool
    count = Int(event_loop_group_get_loop_count(elg))
    for idx in 0:(count - 1)
        loop = event_loop_group_get_loop_at(elg, idx)
        if loop === event_loop
            return true
        end
    end
    return false
end

function _get_connection_event_loop(request::SocketConnectionRequest)::Union{EventLoop, Nothing}
    request.event_loop !== nothing && return request.event_loop
    request.event_loop = request.requested_event_loop === nothing ?
        event_loop_group_get_next_loop(request.bootstrap.event_loop_group) :
        request.requested_event_loop
    return request.event_loop
end

# Callback when host resolution completes
function _on_host_resolved(request::SocketConnectionRequest, error_code::Int, addresses::Vector{HostAddress})
    if error_code != AWS_OP_SUCCESS
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: DNS resolution failed for $(request.host) with error $error_code"
        )
        _connection_request_complete(request, error_code, nothing)
        return nothing
    end

    if isempty(addresses)
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: no addresses returned for $(request.host)"
        )
        _connection_request_complete(request, ERROR_IO_DNS_NO_ADDRESS_FOR_HOST, nothing)
        return nothing
    end

    event_loop = _get_connection_event_loop(request)
    if event_loop === nothing
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: no event loop available"
        )
        _connection_request_complete(request, ERROR_IO_SOCKET_MISSING_EVENT_LOOP, nothing)
        return nothing
    end

    logf(
        LogLevel.TRACE, LS_IO_CHANNEL_BOOTSTRAP,
        "ClientBootstrap: DNS resolution completed. Kicking off connections on $(length(addresses)) addresses. First one back wins."
    )

    task = ScheduledTask(
        TaskFn(function(status)
            try
                TaskStatus.T(status) == TaskStatus.RUN_READY || return nothing
                _start_connection_attempts(request, addresses, event_loop)
            catch e
                Core.println("client_bootstrap_attempts task errored: $e")
            end
            return nothing
        end);
        type_tag = "client_bootstrap_attempts",
    )
    event_loop_schedule_task_now!(event_loop, task)

    return nothing
end

# Start connection attempts for all resolved addresses
function _start_connection_attempts(
        request::SocketConnectionRequest,
        addresses::Vector{HostAddress},
        event_loop::EventLoop,
    )
    request.event_loop = event_loop
    request.addresses = addresses
    request.addresses_count = length(addresses)
    request.failed_count = 0
    request.connection_chosen = false
    for address in addresses
        _initiate_socket_connect(request, address)
    end
    return nothing
end

function _record_connection_failure(request::SocketConnectionRequest, address::HostAddress)
    resolver = request.bootstrap.host_resolver
    host_resolver_record_connection_failure!(resolver, address)
    return nothing
end

function _note_connection_attempt_failure(request::SocketConnectionRequest, error_code::Int)
    request.connection_chosen && return nothing
    request.failed_count += 1
    if request.failed_count == request.addresses_count
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: last attempt failed with error $error_code"
        )
        request.connection_chosen = true
        _connection_request_complete(request, error_code, nothing)
        return nothing
    end
    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,
        "ClientBootstrap: socket connect attempt $(request.failed_count)/$(request.addresses_count) failed with error $error_code. More attempts ongoing..."
    )
    return nothing
end

# Initiate socket connection
function _initiate_socket_connect(request::SocketConnectionRequest, address::HostAddress)
    event_loop = request.event_loop

    # Create socket
    options = copy(request.socket_options)
    # Only override domain for IP sockets; LOCAL/VSOCK keep their domain
    if options.domain != SocketDomain.LOCAL && options.domain != SocketDomain.VSOCK
        options.domain = address.address_type == HostAddressType.AAAA ? SocketDomain.IPV6 : SocketDomain.IPV4
    end
    sock_result = socket_init(options)

    if sock_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: failed to create socket"
        )
        _note_connection_attempt_failure(request, sock_result.code)
        return nothing
    end

    socket = sock_result

    # Create remote endpoint
    remote_endpoint = SocketEndpoint()
    set_address!(remote_endpoint, address.address)
    remote_endpoint.port = request.port

    # Get event loop
    if event_loop === nothing
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: no event loop available"
        )
        socket_close(socket)
        _connection_request_complete(request, ERROR_IO_SOCKET_MISSING_EVENT_LOOP, nothing)
        return nothing
    end

    attempt = SocketConnectionAttempt(request, address)
    connect_opts = SocketConnectOptions(
        remote_endpoint;
        event_loop = event_loop,
        on_connection_result = (sock, err, ud) -> _on_socket_connect_complete(sock, err, ud),
        user_data = attempt,
        tls_connection_options = request.tls_connection_options,
    )

    # Initiate async connect
    connect_result = socket_connect(socket, connect_opts)

    if connect_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: failed to initiate connection"
        )
        _record_connection_failure(request, address)
        socket_close(socket)
        _note_connection_attempt_failure(request, connect_result.code)
        return nothing
    end

    return nothing
end

# Callback when socket connect completes
function _on_socket_connect_complete(socket::Socket, error_code::Int, attempt::SocketConnectionAttempt)
    request = attempt.request

    if error_code != AWS_OP_SUCCESS
        logf(
            LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: connection failed with error $error_code"
        )
        _record_connection_failure(request, attempt.host_address)
        if _socket_uses_network_framework_tls(socket, request.tls_connection_options) &&
                io_error_code_is_tls(error_code)
            if request.connection_chosen
                socket_close(socket)
                return nothing
            end
            request.connection_chosen = true
            socket_close(socket)
            _connection_request_complete(request, error_code, nothing)
            return nothing
        end
        socket_close(socket)
        _note_connection_attempt_failure(request, error_code)
        return nothing
    end

    if request.connection_chosen
        socket_close(socket)
        return nothing
    end

    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,
        "ClientBootstrap: connection established to $(request.host):$(request.port)"
    )
    request.connection_chosen = true
    request.socket = socket

    # Create channel for this connection
    _setup_client_channel(request)

    return nothing
end

# Set up channel for connected socket
function _setup_client_channel(request::SocketConnectionRequest)
    bootstrap = request.bootstrap
    socket = request.socket
    event_loop = socket.event_loop
    if event_loop === nothing
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: no event loop available for channel setup"
        )
        socket_close(socket)
        _connection_request_complete(request, ERROR_IO_SOCKET_MISSING_EVENT_LOOP, nothing)
        return nothing
    end
    on_shutdown = (ch, err, ud) -> begin
        if request.on_shutdown !== nothing
            Base.invokelatest(request.on_shutdown, bootstrap, err, ch, request.user_data)
        end
        return nothing
    end
    on_setup = (channel, error_code, ud) -> begin
        if error_code != AWS_OP_SUCCESS
            logf(
                LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
                "ClientBootstrap: channel setup failed"
            )
            request.on_shutdown = nothing
            channel_shutdown!(channel, error_code)
            socket_close(socket)
            _connection_request_complete(request, error_code, nothing)
            return nothing
        end
        handler_result = socket_channel_handler_new!(channel, socket)
        if handler_result isa ErrorResult
            logf(
                LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
                "ClientBootstrap: failed to create socket channel handler"
            )
            request.on_shutdown = nothing
            socket_close(socket)
            _connection_request_complete(request, handler_result.code, nothing)
            return nothing
        end
        if request.tls_connection_options !== nothing && _socket_uses_network_framework_tls(socket, request.tls_connection_options)
            tls_options = request.tls_connection_options
            if request.on_protocol_negotiated !== nothing
                proto_res = _install_protocol_handler_from_socket(channel, socket, request.on_protocol_negotiated, request.user_data)
                if proto_res isa ErrorResult
                    request.on_shutdown = nothing
                    channel_shutdown!(channel, proto_res.code)
                    socket_close(socket)
                    _connection_request_complete(request, proto_res.code, nothing)
                    return nothing
                end
            end
            if tls_options.on_negotiation_result !== nothing
                Base.invokelatest(
                    tls_options.on_negotiation_result,
                    handler_result,
                    channel.first,
                    AWS_OP_SUCCESS,
                    tls_options.user_data,
                )
            end
            _connection_request_complete(request, AWS_OP_SUCCESS, channel)
            if channel_thread_is_callers_thread(channel)
                trigger_res = channel_trigger_read(channel)
                if trigger_res isa ErrorResult
                    request.on_shutdown = nothing
                    channel_shutdown!(channel, trigger_res.code)
                    socket_close(socket)
                    _connection_request_complete(request, trigger_res.code, nothing)
                    return nothing
                end
            else
                trigger_task = ChannelTask((task, ctx, status) -> begin
                    _ = task
                    status == TaskStatus.RUN_READY || return nothing
                    trigger_res = channel_trigger_read(ctx.channel)
                    trigger_res isa ErrorResult && channel_shutdown!(ctx.channel, trigger_res.code)
                    return nothing
                end, (channel = channel,), "client_tls_trigger_read")
                channel_schedule_task_now!(channel, trigger_task)
            end
            return nothing
        elseif request.tls_connection_options !== nothing
            tls_options = request.tls_connection_options
            advertise_alpn = request.on_protocol_negotiated !== nothing && tls_is_alpn_available()
            on_negotiation = (handler, slot, err, ud) -> begin
                if tls_options.on_negotiation_result !== nothing
                    Base.invokelatest(tls_options.on_negotiation_result, handler, slot, err, tls_options.user_data)
                end
                if err == AWS_OP_SUCCESS
                    _connection_request_complete(request, AWS_OP_SUCCESS, channel)
                else
                    request.on_shutdown = nothing
                    channel_shutdown!(channel, err)
                    socket_close(socket)
                    _connection_request_complete(request, err, nothing)
                end
                return nothing
            end
            wrapped = TlsConnectionOptions(
                tls_options.ctx;
                server_name = tls_options.server_name,
                alpn_list = tls_options.alpn_list,
                advertise_alpn_message = tls_options.advertise_alpn_message || advertise_alpn,
                on_negotiation_result = on_negotiation,
                on_data_read = tls_options.on_data_read,
                on_error = tls_options.on_error,
                user_data = tls_options.user_data,
                timeout_ms = tls_options.timeout_ms,
            )
            tls_handler = tls_channel_handler_new!(channel, wrapped)
            if tls_handler isa ErrorResult
                request.on_shutdown = nothing
                channel_shutdown!(channel, tls_handler.code)
                socket_close(socket)
                _connection_request_complete(request, tls_handler.code, nothing)
                return nothing
            end
            if advertise_alpn
                alpn_slot = channel_slot_new!(channel)
                channel_slot_insert_right!(tls_handler.slot, alpn_slot)
                alpn_handler = tls_alpn_handler_new(request.on_protocol_negotiated, request.user_data)
                channel_slot_set_handler!(alpn_slot, alpn_handler)
            end
            start_res = tls_client_handler_start_negotiation(tls_handler)
            if start_res isa ErrorResult
                request.on_shutdown = nothing
                channel_shutdown!(channel, start_res.code)
                socket_close(socket)
                _connection_request_complete(request, start_res.code, nothing)
                return nothing
            end
            if channel_thread_is_callers_thread(channel)
                trigger_res = channel_trigger_read(channel)
                if trigger_res isa ErrorResult
                    request.on_shutdown = nothing
                    channel_shutdown!(channel, trigger_res.code)
                    socket_close(socket)
                    _connection_request_complete(request, trigger_res.code, nothing)
                    return nothing
                end
            else
                trigger_task = ChannelTask((task, ctx, status) -> begin
                    _ = task
                    status == TaskStatus.RUN_READY || return nothing
                    trigger_res = channel_trigger_read(ctx.channel)
                    trigger_res isa ErrorResult && channel_shutdown!(ctx.channel, trigger_res.code)
                    return nothing
                end, (channel = channel,), "client_tls_trigger_read")
                channel_schedule_task_now!(channel, trigger_task)
            end
            return nothing
        end
        logf(
            LogLevel.INFO, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: channel $(channel.channel_id) setup complete for $(request.host):$(request.port)"
        )
        _connection_request_complete(request, AWS_OP_SUCCESS, channel)
        return nothing
    end
    options = ChannelOptions(
        event_loop = event_loop,
        on_setup_completed = on_setup,
        on_shutdown_completed = on_shutdown,
        setup_user_data = request,
        shutdown_user_data = request,
        enable_read_back_pressure = request.enable_read_back_pressure,
    )
    channel = channel_new(options)
    if channel isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: failed to create channel"
        )
        socket_close(socket)
        _connection_request_complete(request, channel.code, nothing)
        return nothing
    end
    request.channel = channel
    if request.on_creation !== nothing
        Base.invokelatest(request.on_creation, bootstrap, AWS_OP_SUCCESS, channel, request.user_data)
    end
    return nothing
end

# Complete connection request and invoke callback
function _connection_request_invoke_on_setup(
        request::SocketConnectionRequest,
        error_code::Int,
        channel::Union{Channel, Nothing},
    )
    request.on_setup === nothing && return nothing
    try
        Base.invokelatest(request.on_setup, request.bootstrap, error_code, channel, request.user_data)
    catch err
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: on_setup callback threw: %s",
            sprint(showerror, err, catch_backtrace()),
        )
    end
    return nothing
end

function _connection_request_complete(request::SocketConnectionRequest, error_code::Int, channel::Union{Channel, Nothing})
    if error_code != AWS_OP_SUCCESS
        request.on_shutdown = nothing
    end
    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,
        "ClientBootstrap: connection request complete error=%d on_setup=%s",
        error_code,
        request.on_setup === nothing ? "nothing" : "set",
    )
    if request.on_setup !== nothing
        requested_loop = request.requested_event_loop
        if requested_loop !== nothing && !event_loop_thread_is_callers_thread(requested_loop)
            task = ScheduledTask(
                TaskFn(function(status)
                    try
                        TaskStatus.T(status) == TaskStatus.RUN_READY || return nothing
                        _connection_request_invoke_on_setup(request, error_code, channel)
                    catch e
                        Core.println("client_bootstrap_on_setup task errored: $e")
                    end
                    return nothing
                end);
                type_tag = "client_bootstrap_on_setup",
            )
            event_loop_schedule_task_now!(requested_loop, task)
        else
            _connection_request_invoke_on_setup(request, error_code, channel)
        end
    end
    return nothing
end

# =============================================================================
# Server Bootstrap - for accepting incoming connections
# =============================================================================

# NOTE: On Apple Network.framework (NWSocket backend), listener readiness is asynchronous.
# In particular, when binding to port 0, the effective bound port may remain 0 until the
# accept-start callback fires. Use `on_listener_setup` (wired to `on_accept_start`) to know
# when the listener is ready for `socket_get_bound_address(...)`.

# Server bootstrap options
struct ServerBootstrapOptions
    event_loop_group::EventLoopGroup
    socket_options::SocketOptions
    host::String
    port::UInt32
    backlog::Int
    tls_connection_options::Any  # TlsConnectionOptions or nothing
    on_protocol_negotiated::Union{Function, Nothing}
    on_listener_setup::Union{Function, Nothing}
    on_incoming_channel_setup::Union{Function, Nothing}
    on_incoming_channel_shutdown::Union{Function, Nothing}
    on_listener_destroy::Union{Function, Nothing}
    user_data::Any
    enable_read_back_pressure::Bool
end

function ServerBootstrapOptions(;
        event_loop_group,
        socket_options::SocketOptions = SocketOptions(),
        host::AbstractString = "0.0.0.0",
        port::Integer,
        backlog::Integer = 128,
        tls_connection_options = nothing,
        on_protocol_negotiated = nothing,
        on_listener_setup = nothing,
        on_incoming_channel_setup = nothing,
        on_incoming_channel_shutdown = nothing,
        on_listener_destroy = nothing,
        user_data = nothing,
        enable_read_back_pressure::Bool = false,
    )
    return ServerBootstrapOptions(
        event_loop_group,
        socket_options,
        String(host),
        UInt32(port),
        Int(backlog),
        tls_connection_options,
        on_protocol_negotiated,
        on_listener_setup,
        on_incoming_channel_setup,
        on_incoming_channel_shutdown,
        on_listener_destroy,
        user_data,
        enable_read_back_pressure,
    )
end

# Server bootstrap - for accepting incoming connections
mutable struct ServerBootstrap
    event_loop_group::EventLoopGroup
    socket_options::SocketOptions
    listener_socket::Union{Socket, Nothing}
    listener_event_loop::Union{EventLoop, Nothing}
    tls_connection_options::Any  # TlsConnectionOptions or nothing
    on_protocol_negotiated::Union{Function, Nothing}
    on_listener_setup::Union{Function, Nothing}
    on_incoming_channel_setup::Union{Function, Nothing}
    on_incoming_channel_shutdown::Union{Function, Nothing}
    on_listener_destroy::Union{Function, Nothing}
    user_data::Any
    enable_read_back_pressure::Bool
    @atomic inflight_channels::Int
    @atomic listener_closed::Bool
    @atomic destroy_called::Bool
    @atomic shutdown::Bool
end

function ServerBootstrap(options::ServerBootstrapOptions)
    bootstrap = ServerBootstrap(
        options.event_loop_group,
        options.socket_options,
        nothing,
        nothing,
        options.tls_connection_options,
        options.on_protocol_negotiated,
        options.on_listener_setup,
        options.on_incoming_channel_setup,
        options.on_incoming_channel_shutdown,
        options.on_listener_destroy,
        options.user_data,
        options.enable_read_back_pressure,
        0,
        false,
        false,
        false,
    )

    logf(LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP, "ServerBootstrap: created")

    # Create listener socket
    sock_result = socket_init(options.socket_options)

    if sock_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: failed to create listener socket"
        )
        return sock_result
    end

    listener = sock_result
    bootstrap.listener_socket = listener

    # Bind to address
    local_endpoint = SocketEndpoint()
    set_address!(local_endpoint, options.host)
    local_endpoint.port = options.port

    bind_opts = if _socket_uses_network_framework_tls(listener, options.tls_connection_options)
        SocketBindOptions(local_endpoint; tls_connection_options = options.tls_connection_options)
    else
        SocketBindOptions(local_endpoint)
    end
    bind_result = socket_bind(listener, bind_opts)

    if bind_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: failed to bind to $(options.host):$(options.port)"
        )
        socket_close(listener)
        return bind_result
    end

    # Start listening
    listen_result = socket_listen(listener, options.backlog)

    if listen_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: failed to listen"
        )
        socket_close(listener)
        return listen_result
    end

    # Get event loop and start accepting
    event_loop = event_loop_group_get_next_loop(options.event_loop_group)

    if event_loop === nothing
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: no event loop available"
        )
        socket_close(listener)
        raise_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
        return ErrorResult(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
    end

    bootstrap.listener_event_loop = event_loop

    listener_options = SocketListenerOptions(
        on_accept_result = (sock, err, new_sock, ud) -> _on_incoming_connection(bootstrap, err, new_sock),
        on_accept_result_user_data = bootstrap,
        on_accept_start = (sock, err, ud) -> begin
            if options.on_listener_setup !== nothing
                options.on_listener_setup(bootstrap, err, options.user_data)
            end
        end,
        on_accept_start_user_data = bootstrap,
    )

    accept_result = socket_start_accept(listener, event_loop, listener_options)

    if accept_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: failed to start accepting connections"
        )
        socket_close(listener)
        return accept_result
    end

    logf(
        LogLevel.INFO, LS_IO_CHANNEL_BOOTSTRAP,
        "ServerBootstrap: listening on $(options.host):$(options.port)"
    )

    return bootstrap
end

function _server_bootstrap_incoming_started!(bootstrap::ServerBootstrap)
    @atomic bootstrap.inflight_channels += 1
    return nothing
end

function _server_bootstrap_incoming_finished!(bootstrap::ServerBootstrap)
    @atomic bootstrap.inflight_channels -= 1
    _server_bootstrap_maybe_destroy(bootstrap)
    return nothing
end

function _server_bootstrap_maybe_destroy(bootstrap::ServerBootstrap)
    listener_closed = @atomic bootstrap.listener_closed
    inflight = @atomic bootstrap.inflight_channels
    if !listener_closed || inflight != 0
        return nothing
    end

    expected = false
    if !(@atomicreplace bootstrap.destroy_called expected => true).success
        return nothing
    end

    if bootstrap.on_listener_destroy === nothing
        return nothing
    end

    listener_loop = bootstrap.listener_event_loop
    if listener_loop !== nothing && !event_loop_thread_is_callers_thread(listener_loop)
        task = ScheduledTask(
            TaskFn(function(status)
                try
                    bootstrap.on_listener_destroy === nothing && return nothing
                    Base.invokelatest(bootstrap.on_listener_destroy, bootstrap, bootstrap.user_data)
                catch e
                    Core.println("server_listener_destroy task errored: $e")
                end
                return nothing
            end);
            type_tag = "server_listener_destroy",
        )
        event_loop_schedule_task_now!(listener_loop, task)
    else
        Base.invokelatest(bootstrap.on_listener_destroy, bootstrap, bootstrap.user_data)
    end

    return nothing
end

function _server_bootstrap_listener_destroy_task(ctx, status::TaskStatus.T)
    bootstrap = ctx.bootstrap
    listener = bootstrap.listener_socket
    if listener !== nothing
        socket_stop_accept(listener)
        socket_close(listener)
        bootstrap.listener_socket = nothing
    end
    @atomic bootstrap.listener_closed = true
    _server_bootstrap_maybe_destroy(bootstrap)
    return nothing
end

# Callback for incoming connections
function _on_incoming_connection(bootstrap::ServerBootstrap, error_code::Int, new_socket)
    if error_code != AWS_OP_SUCCESS
        logf(
            LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: incoming connection error $error_code"
        )
        return nothing
    end

    if @atomic bootstrap.shutdown
        socket_close(new_socket)
        return nothing
    end

    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,
        "ServerBootstrap: accepted incoming connection"
    )

    # Set up channel for this connection
    _setup_incoming_channel(bootstrap, new_socket)

    return nothing
end

# Set up channel for incoming connection
function _setup_incoming_channel(bootstrap::ServerBootstrap, socket)
    _server_bootstrap_incoming_started!(bootstrap)
    incoming_called = Ref(false)
    setup_succeeded = Ref(false)
    function invoke_incoming_callback(err, channel)
        if incoming_called[]
            return nothing
        end
        incoming_called[] = true
        if bootstrap.on_incoming_channel_setup !== nothing
            bootstrap.on_incoming_channel_setup(bootstrap, err, channel, bootstrap.user_data)
        end
        return nothing
    end
    event_loop = event_loop_group_get_next_loop(bootstrap.event_loop_group)
    if event_loop === nothing
        logf(
            LogLevel.ERROR,
            LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: no event loop available for incoming channel"
        )
        invoke_incoming_callback(ERROR_IO_SOCKET_MISSING_EVENT_LOOP, nothing)
        socket_close(socket)
        _server_bootstrap_incoming_finished!(bootstrap)
        return nothing
    end
    assign_result = socket_assign_to_event_loop(socket, event_loop)
    if assign_result isa ErrorResult
        logf(
            LogLevel.ERROR,
            LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: failed to assign incoming socket to event loop"
        )
        invoke_incoming_callback(assign_result.code, nothing)
        socket_close(socket)
        _server_bootstrap_incoming_finished!(bootstrap)
        return nothing
    end
    on_shutdown = (ch, err, ud) -> begin
        shutdown_err = err
        if !incoming_called[]
            if shutdown_err == AWS_OP_SUCCESS
                shutdown_err = ERROR_UNKNOWN
            end
            invoke_incoming_callback(shutdown_err, nothing)
        end
        if setup_succeeded[] && bootstrap.on_incoming_channel_shutdown !== nothing
            bootstrap.on_incoming_channel_shutdown(bootstrap, err, ch, bootstrap.user_data)
        end
        _server_bootstrap_incoming_finished!(bootstrap)
        return nothing
    end
    on_setup = (channel, error_code, ud) -> begin
        if error_code != AWS_OP_SUCCESS
            logf(
                LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
                "ServerBootstrap: incoming channel setup failed"
            )
            channel_shutdown!(channel, error_code)
            socket_close(socket)
            return nothing
        end
        handler_result = socket_channel_handler_new!(channel, socket)
        if handler_result isa ErrorResult
            logf(
                LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
                "ServerBootstrap: failed to create socket handler for incoming connection"
            )
            channel_shutdown!(channel, handler_result.code)
            socket_close(socket)
            return nothing
        end
        if bootstrap.tls_connection_options !== nothing && _socket_uses_network_framework_tls(socket, bootstrap.tls_connection_options)
            tls_options = bootstrap.tls_connection_options
            if bootstrap.on_protocol_negotiated !== nothing
                proto_res = _install_protocol_handler_from_socket(channel, socket, bootstrap.on_protocol_negotiated, bootstrap.user_data)
                if proto_res isa ErrorResult
                    channel_shutdown!(channel, proto_res.code)
                    socket_close(socket)
                    return nothing
                end
            end
            if tls_options.on_negotiation_result !== nothing
                Base.invokelatest(
                    tls_options.on_negotiation_result,
                    handler_result,
                    channel.first,
                    AWS_OP_SUCCESS,
                    tls_options.user_data,
                )
            end
            setup_succeeded[] = true
            invoke_incoming_callback(AWS_OP_SUCCESS, channel)
            if channel_thread_is_callers_thread(channel)
                trigger_res = channel_trigger_read(channel)
                if trigger_res isa ErrorResult
                    channel_shutdown!(channel, trigger_res.code)
                    return nothing
                end
            else
                trigger_task = ChannelTask((task, ctx, status) -> begin
                    _ = task
                    status == TaskStatus.RUN_READY || return nothing
                    trigger_res = channel_trigger_read(ctx.channel)
                    trigger_res isa ErrorResult && channel_shutdown!(ctx.channel, trigger_res.code)
                    return nothing
                end, (channel = channel,), "server_tls_trigger_read")
                channel_schedule_task_now!(channel, trigger_task)
            end
            return nothing
        elseif bootstrap.tls_connection_options !== nothing
            tls_options = bootstrap.tls_connection_options
            advertise_alpn = bootstrap.on_protocol_negotiated !== nothing && tls_is_alpn_available()
            on_negotiation = (handler, slot, err, ud) -> begin
                if tls_options.on_negotiation_result !== nothing
                    Base.invokelatest(tls_options.on_negotiation_result, handler, slot, err, tls_options.user_data)
                end
                if err == AWS_OP_SUCCESS
                    setup_succeeded[] = true
                    invoke_incoming_callback(AWS_OP_SUCCESS, channel)
                else
                    channel_shutdown!(channel, err)
                end
                return nothing
            end
            wrapped = TlsConnectionOptions(
                tls_options.ctx;
                server_name = tls_options.server_name,
                alpn_list = tls_options.alpn_list,
                advertise_alpn_message = tls_options.advertise_alpn_message || advertise_alpn,
                on_negotiation_result = on_negotiation,
                on_data_read = tls_options.on_data_read,
                on_error = tls_options.on_error,
                user_data = tls_options.user_data,
                timeout_ms = tls_options.timeout_ms,
            )
            tls_handler = tls_channel_handler_new!(channel, wrapped)
            if tls_handler isa ErrorResult
                channel_shutdown!(channel, tls_handler.code)
                socket_close(socket)
                return nothing
            end
            if advertise_alpn
                alpn_slot = channel_slot_new!(channel)
                channel_slot_insert_right!(tls_handler.slot, alpn_slot)
                alpn_handler = tls_alpn_handler_new(bootstrap.on_protocol_negotiated, bootstrap.user_data)
                channel_slot_set_handler!(alpn_slot, alpn_handler)
            end
            if channel_thread_is_callers_thread(channel)
                trigger_res = channel_trigger_read(channel)
                if trigger_res isa ErrorResult
                    channel_shutdown!(channel, trigger_res.code)
                    return nothing
                end
            else
                trigger_task = ChannelTask((task, ctx, status) -> begin
                    _ = task
                    status == TaskStatus.RUN_READY || return nothing
                    trigger_res = channel_trigger_read(ctx.channel)
                    trigger_res isa ErrorResult && channel_shutdown!(ctx.channel, trigger_res.code)
                    return nothing
                end, (channel = channel,), "server_tls_trigger_read")
                channel_schedule_task_now!(channel, trigger_task)
            end
            return nothing
        end
        setup_succeeded[] = true
        logf(
            LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: incoming channel $(channel.channel_id) setup complete"
        )
        invoke_incoming_callback(AWS_OP_SUCCESS, channel)
        return nothing
    end
    options = ChannelOptions(
        event_loop = event_loop,
        on_setup_completed = on_setup,
        on_shutdown_completed = on_shutdown,
        setup_user_data = nothing,
        shutdown_user_data = nothing,
        enable_read_back_pressure = bootstrap.enable_read_back_pressure,
    )
    channel = channel_new(options)
    if channel isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: failed to create channel for incoming connection"
        )
        invoke_incoming_callback(channel.code, nothing)
        socket_close(socket)
        _server_bootstrap_incoming_finished!(bootstrap)
        return nothing
    end
    return nothing
end

# Shutdown server bootstrap
function server_bootstrap_shutdown!(bootstrap::ServerBootstrap)
    expected = false
    if !(@atomicreplace bootstrap.shutdown expected => true).success
        return nothing
    end

    if bootstrap.listener_socket !== nothing && bootstrap.listener_event_loop !== nothing
        task = ScheduledTask(
            TaskFn(function(status)
                try
                    _server_bootstrap_listener_destroy_task((bootstrap = bootstrap,), TaskStatus.T(status))
                catch e
                    Core.println("server_listener_shutdown task errored: $e")
                end
                return nothing
            end);
            type_tag = "server_listener_shutdown",
        )
        event_loop_schedule_task_now!(bootstrap.listener_event_loop, task)
    else
        _server_bootstrap_listener_destroy_task((bootstrap = bootstrap,), TaskStatus.RUN_READY)
    end

    logf(LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP, "ServerBootstrap: shutdown")

    return nothing
end
