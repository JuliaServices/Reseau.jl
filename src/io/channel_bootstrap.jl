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
struct ClientBootstrapOptions{
    ELG,
    HR,
    SO,
    TO,
    FP <: Union{ChannelOnProtocolNegotiatedFn, Nothing},
    FC <: Union{OnBootstrapChannelCreationFn, Nothing},
    FS <: Union{OnBootstrapChannelSetupFn, Nothing},
    FD <: Union{OnBootstrapChannelShutdownFn, Nothing},
    U,
}
    event_loop_group::ELG
    host_resolver::HR
    host_resolution_config::Union{HostResolutionConfig, Nothing}
    socket_options::SO
    tls_connection_options::TO
    on_protocol_negotiated::FP
    on_creation_callback::FC
    on_setup_callback::FS  # nullable
    on_shutdown_callback::FD  # nullable
    user_data::U
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
mutable struct ClientBootstrap{
    ELG,
    HR,
    TO,
    FP <: Union{ChannelOnProtocolNegotiatedFn, Nothing},
    FC <: Union{OnBootstrapChannelCreationFn, Nothing},
    FS <: Union{OnBootstrapChannelSetupFn, Nothing},
    FD <: Union{OnBootstrapChannelShutdownFn, Nothing},
    U,
}
    event_loop_group::ELG
    host_resolver::HR
    host_resolution_config::Union{HostResolutionConfig, Nothing}
    socket_options::SocketOptions
    tls_connection_options::TO
    on_protocol_negotiated::FP
    on_creation_callback::FC
    on_setup_callback::FS  # nullable
    on_shutdown_callback::FD  # nullable
    user_data::U
    @atomic shutdown::Bool
end

function ClientBootstrap(
        options::ClientBootstrapOptions{ELG, HR, SO, TO, FP, FC, FS, FD, U},
    ) where {ELG, HR, SO, TO, FP, FC, FS, FD, U}
    CBT = ClientBootstrap{ELG, HR, TO, FP, FC, FS, FD, U}
    bootstrap = CBT(
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

# Connection request tracking
mutable struct SocketConnectionRequest{
    CB,
    TO,
    FP <: Union{ChannelOnProtocolNegotiatedFn, Nothing},
    FC <: Union{OnBootstrapChannelCreationFn, Nothing},
    FS <: Union{OnBootstrapChannelSetupFn, Nothing},
    FD <: Union{OnBootstrapChannelShutdownFn, Nothing},
    U,
    EL <: Union{AbstractEventLoop, Nothing},
}
    bootstrap::CB
    host::String
    port::UInt32
    socket::Union{Socket, Nothing}  # nullable
    channel::Union{Channel, Nothing}  # nullable
    tls_connection_options::TO
    on_protocol_negotiated::FP
    on_creation::FC
    on_setup::FS  # nullable
    on_shutdown::FD  # nullable
    user_data::U
    enable_read_back_pressure::Bool
    requested_event_loop::EL
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
        requested_event_loop::Union{AbstractEventLoop, Nothing} = nothing,
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

function _event_loop_group_contains_loop(elg, event_loop::AbstractEventLoop)::Bool
    count = Int(event_loop_group_get_loop_count(elg))
    for idx in 0:(count - 1)
        loop = event_loop_group_get_loop_at(elg, idx)
        if loop === event_loop
            return true
        end
    end
    return false
end

# Callback when host resolution completes
function _on_host_resolved(request::SocketConnectionRequest, error_code::Int, addresses::Vector{HostAddress})
    bootstrap = request.bootstrap

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

    # Use first address
    address = addresses[1]

    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,
        "ClientBootstrap: resolved $(request.host) to $(address.address)"
    )

    # Create socket and connect
    _initiate_socket_connect(request, address.address)

    return nothing
end

# Initiate socket connection
function _initiate_socket_connect(request::SocketConnectionRequest, address::String)
    bootstrap = request.bootstrap

    # Create socket
    sock_result = socket_init_posix(bootstrap.socket_options)

    if sock_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: failed to create socket"
        )
        _connection_request_complete(request, sock_result.code, nothing)
        return nothing
    end

    socket = sock_result
    request.socket = socket

    # Create remote endpoint
    remote_endpoint = SocketEndpoint()
    set_address!(remote_endpoint, address)
    remote_endpoint.port = request.port

    # Get event loop
    event_loop = request.requested_event_loop === nothing ?
        event_loop_group_get_next_loop(bootstrap.event_loop_group) :
        request.requested_event_loop

    if event_loop === nothing
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: no event loop available"
        )
        socket_close(socket)
        _connection_request_complete(request, ERROR_IO_SOCKET_MISSING_EVENT_LOOP, nothing)
        return nothing
    end

    connect_opts = SocketConnectOptions(
        remote_endpoint;
        event_loop = event_loop,
        on_connection_result = (sock, err, ud) -> _on_socket_connect_complete(ud, err),
        user_data = request,
    )

    # Initiate async connect
    connect_result = socket_connect(socket, connect_opts)

    if connect_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: failed to initiate connection"
        )
        socket_close(socket)
        _connection_request_complete(request, connect_result.code, nothing)
        return nothing
    end

    return nothing
end

# Callback when socket connect completes
function _on_socket_connect_complete(request::SocketConnectionRequest, error_code::Int)
    bootstrap = request.bootstrap
    socket = request.socket

    if error_code != AWS_OP_SUCCESS
        logf(
            LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: connection failed with error $error_code"
        )
        socket_close(socket)
        _connection_request_complete(request, error_code, nothing)
        return nothing
    end

    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,
        "ClientBootstrap: connection established to $(request.host):$(request.port)"
    )

    # Create channel for this connection
    _setup_client_channel(request)

    return nothing
end

# Set up channel for connected socket
function _setup_client_channel(request::SocketConnectionRequest)
    bootstrap = request.bootstrap
    socket = request.socket

    # Get event loop from socket
    event_loop = socket.event_loop

    # Create channel
    channel = Channel(event_loop, nothing; enable_read_back_pressure = request.enable_read_back_pressure)
    request.channel = channel

    if request.on_creation !== nothing
        Base.invokelatest(request.on_creation, bootstrap, AWS_OP_SUCCESS, channel, request.user_data)
    end

    # Set shutdown callback
    channel_set_shutdown_callback!(
        channel, (ch, err, ud) -> begin
            if request.on_shutdown !== nothing
                Base.invokelatest(request.on_shutdown, bootstrap, err, ch, request.user_data)
            end
        end, request
    )

    # Add socket handler to channel
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

    # If TLS requested, insert TLS handler and defer setup completion
    if request.tls_connection_options !== nothing
        tls_options = request.tls_connection_options
        advertise_alpn = request.on_protocol_negotiated !== nothing

        on_negotiation = (handler, slot, err, ud) -> begin
            if tls_options.on_negotiation_result !== nothing
                Base.invokelatest(tls_options.on_negotiation_result, handler, slot, err, tls_options.user_data)
            end

            if err == AWS_OP_SUCCESS
                setup_result = channel_setup_complete!(channel)
                if setup_result isa ErrorResult
                    request.on_shutdown = nothing
                    socket_close(socket)
                    _connection_request_complete(request, setup_result.code, nothing)
                    return nothing
                end
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

        if advertise_alpn
            alpn_slot = channel_slot_new!(channel)
            channel_slot_insert_left!(tls_handler.slot, alpn_slot)
            alpn_handler = tls_alpn_handler_new(request.on_protocol_negotiated, request.user_data)
            channel_slot_set_handler!(alpn_slot, alpn_handler)
            alpn_handler.slot = alpn_slot
        end
        return nothing
    end

    # Complete channel setup
    setup_result = channel_setup_complete!(channel)

    if setup_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: channel setup failed"
        )
        request.on_shutdown = nothing
        socket_close(socket)
        _connection_request_complete(request, setup_result.code, nothing)
        return nothing
    end

    logf(
        LogLevel.INFO, LS_IO_CHANNEL_BOOTSTRAP,
        "ClientBootstrap: channel $(channel.channel_id) setup complete for $(request.host):$(request.port)"
    )

    _connection_request_complete(request, AWS_OP_SUCCESS, channel)

    return nothing
end

# Complete connection request and invoke callback
function _connection_request_complete(request::SocketConnectionRequest, error_code::Int, channel::Union{Channel, Nothing})
    if error_code != AWS_OP_SUCCESS
        request.on_shutdown = nothing
    end
    if request.on_setup !== nothing
        Base.invokelatest(request.on_setup, request.bootstrap, error_code, channel, request.user_data)
    end
    return nothing
end

# =============================================================================
# Server Bootstrap - for accepting incoming connections
# =============================================================================

# Server bootstrap options
struct ServerBootstrapOptions{
    ELG,
    SO,
    TO,
    FP <: Union{ChannelOnProtocolNegotiatedFn, Nothing},
    FL <: Union{OnServerListenerSetupFn, Nothing},
    FS <: Union{OnIncomingChannelSetupFn, Nothing},
    FD <: Union{OnIncomingChannelShutdownFn, Nothing},
    FDest <: Union{OnServerListenerDestroyFn, Nothing},
    U,
}
    event_loop_group::ELG
    socket_options::SO
    host::String
    port::UInt32
    tls_connection_options::TO
    on_protocol_negotiated::FP
    on_listener_setup::FL  # nullable
    on_incoming_channel_setup::FS  # nullable
    on_incoming_channel_shutdown::FD  # nullable
    on_listener_destroy::FDest  # nullable
    user_data::U
    enable_read_back_pressure::Bool
end

function ServerBootstrapOptions(;
        event_loop_group,
        socket_options::SocketOptions = SocketOptions(),
        host::AbstractString = "0.0.0.0",
        port::Integer,
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
mutable struct ServerBootstrap{
    ELG,
    TO,
    FP <: Union{ChannelOnProtocolNegotiatedFn, Nothing},
    FL <: Union{OnServerListenerSetupFn, Nothing},
    FS <: Union{OnIncomingChannelSetupFn, Nothing},
    FD <: Union{OnIncomingChannelShutdownFn, Nothing},
    FDest <: Union{OnServerListenerDestroyFn, Nothing},
    U,
}
    event_loop_group::ELG
    socket_options::SocketOptions
    listener_socket::Union{Socket, Nothing}  # nullable
    listener_event_loop::Union{EventLoop, Nothing}  # nullable
    tls_connection_options::TO
    on_protocol_negotiated::FP
    on_listener_setup::FL  # nullable
    on_incoming_channel_setup::FS  # nullable
    on_incoming_channel_shutdown::FD  # nullable
    on_listener_destroy::FDest  # nullable
    user_data::U
    enable_read_back_pressure::Bool
    @atomic inflight_channels::Int
    @atomic listener_closed::Bool
    @atomic destroy_called::Bool
    @atomic shutdown::Bool
end

function ServerBootstrap(
        options::ServerBootstrapOptions{ELG, SO, TO, FP, FL, FS, FD, FDest, U},
    ) where {ELG, SO, TO, FP, FL, FS, FD, FDest, U}
    SBT = ServerBootstrap{ELG, TO, FP, FL, FS, FD, FDest, U}
    bootstrap = SBT(
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
    sock_result = socket_init_posix(options.socket_options)

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

    bind_result = socket_bind(listener, SocketBindOptions(local_endpoint))

    if bind_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: failed to bind to $(options.host):$(options.port)"
        )
        socket_close(listener)
        return bind_result
    end

    # Start listening
    listen_result = socket_listen(listener, 128)

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
            (ctx, status) -> begin
                ctx.bootstrap.on_listener_destroy === nothing && return nothing
                Base.invokelatest(ctx.bootstrap.on_listener_destroy, ctx.bootstrap, ctx.bootstrap.user_data)
                return nothing
            end,
            (bootstrap = bootstrap,);
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

    # Create channel
    channel = Channel(event_loop, nothing; enable_read_back_pressure = bootstrap.enable_read_back_pressure)

    # Set shutdown callback
    channel_set_shutdown_callback!(
        channel, (ch, err, ud) -> begin
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
        end, bootstrap
    )

    # Add socket handler to channel
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

    if bootstrap.tls_connection_options !== nothing
        tls_options = bootstrap.tls_connection_options
        advertise_alpn = bootstrap.on_protocol_negotiated !== nothing

        on_negotiation = (handler, slot, err, ud) -> begin
            if tls_options.on_negotiation_result !== nothing
                Base.invokelatest(tls_options.on_negotiation_result, handler, slot, err, tls_options.user_data)
            end

            if err == AWS_OP_SUCCESS
                setup_result = channel_setup_complete!(channel)
                if setup_result isa ErrorResult
                    channel_shutdown!(channel, setup_result.code)
                    return nothing
                end
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

        if advertise_alpn
            alpn_slot = channel_slot_new!(channel)
            channel_slot_insert_left!(tls_handler.slot, alpn_slot)
            alpn_handler = tls_alpn_handler_new(bootstrap.on_protocol_negotiated, bootstrap.user_data)
            channel_slot_set_handler!(alpn_slot, alpn_handler)
            alpn_handler.slot = alpn_slot
        end

        return nothing
    end

    # Complete channel setup
    setup_result = channel_setup_complete!(channel)

    if setup_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: incoming channel setup failed"
        )
        channel_shutdown!(channel, setup_result.code)
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

# Shutdown server bootstrap
function server_bootstrap_shutdown!(bootstrap::ServerBootstrap)
    expected = false
    if !(@atomicreplace bootstrap.shutdown expected => true).success
        return nothing
    end

    if bootstrap.listener_socket !== nothing && bootstrap.listener_event_loop !== nothing
        task = ScheduledTask(
            _server_bootstrap_listener_destroy_task,
            (bootstrap = bootstrap,);
            type_tag = "server_listener_shutdown",
        )
        event_loop_schedule_task_now!(bootstrap.listener_event_loop, task)
    else
        _server_bootstrap_listener_destroy_task((bootstrap = bootstrap,), TaskStatus.RUN_READY)
    end

    logf(LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP, "ServerBootstrap: shutdown")

    return nothing
end
