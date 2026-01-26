# AWS IO Library - Channel Bootstrap
# Port of aws-c-io/source/channel_bootstrap.c

# Callback types for bootstrap operations
const OnBootstrapChannelSetupFn = Function  # (bootstrap, error_code, channel, user_data) -> nothing
const OnBootstrapChannelShutdownFn = Function  # (bootstrap, error_code, channel, user_data) -> nothing
const OnServerListenerSetupFn = Function  # (server_bootstrap, error_code, socket, user_data) -> nothing
const OnIncomingChannelSetupFn = Function  # (server_bootstrap, error_code, channel, user_data) -> nothing
const OnIncomingChannelShutdownFn = Function  # (server_bootstrap, error_code, channel, user_data) -> nothing

# Client bootstrap options
struct ClientBootstrapOptions{ELG, HR, SO, TO, FS <: Union{OnBootstrapChannelSetupFn, Nothing}, FD <: Union{OnBootstrapChannelShutdownFn, Nothing}, U}
    event_loop_group::ELG
    host_resolver::HR
    socket_options::SO
    tls_connection_options::TO
    on_setup_callback::FS  # nullable
    on_shutdown_callback::FD  # nullable
    user_data::U
end

function ClientBootstrapOptions(;
        event_loop_group,
        host_resolver,
        socket_options::SocketOptions = SocketOptions(),
        tls_connection_options = nothing,
        on_setup_callback = nothing,
        on_shutdown_callback = nothing,
        user_data = nothing,
    )
    return ClientBootstrapOptions(
        event_loop_group,
        host_resolver,
        socket_options,
        tls_connection_options,
        on_setup_callback,
        on_shutdown_callback,
        user_data,
    )
end

# Client bootstrap - for creating outgoing connections
mutable struct ClientBootstrap{ELG, HR, TO, FS <: Union{OnBootstrapChannelSetupFn, Nothing}, FD <: Union{OnBootstrapChannelShutdownFn, Nothing}, U}
    event_loop_group::ELG
    host_resolver::HR
    socket_options::SocketOptions
    tls_connection_options::TO
    on_setup_callback::FS  # nullable
    on_shutdown_callback::FD  # nullable
    user_data::U
    @atomic shutdown::Bool
    ref_count::RefCounted{ClientBootstrap{ELG, HR, TO, FS, FD, U}, Function}
end

function _client_bootstrap_on_zero_ref(bootstrap::ClientBootstrap)
    logf(LogLevel.TRACE, LS_IO_CHANNEL_BOOTSTRAP, "ClientBootstrap: ref count zero")
    return nothing
end

function ClientBootstrap(
        options::ClientBootstrapOptions{ELG, HR, SO, TO, FS, FD, U},
    ) where {ELG, HR, SO, TO, FS, FD, U}
    CBT = ClientBootstrap{ELG, HR, TO, FS, FD, U}
    bootstrap = CBT(
        options.event_loop_group,
        options.host_resolver,
        options.socket_options,
        options.tls_connection_options,
        options.on_setup_callback,
        options.on_shutdown_callback,
        options.user_data,
        false,
        RefCounted{CBT, Function}(1, nothing, _client_bootstrap_on_zero_ref),
    )
    bootstrap.ref_count = RefCounted(bootstrap, _client_bootstrap_on_zero_ref)

    logf(LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP, "ClientBootstrap: created")

    return bootstrap
end

# Acquire reference
function client_bootstrap_acquire!(bootstrap::ClientBootstrap)
    acquire!(bootstrap.ref_count)
    return bootstrap
end

# Release reference
function client_bootstrap_release!(bootstrap::ClientBootstrap)
    release!(bootstrap.ref_count)
    return nothing
end

# Connection request tracking
mutable struct SocketConnectionRequest{CB, TO, FS <: Union{OnBootstrapChannelSetupFn, Nothing}, FD <: Union{OnBootstrapChannelShutdownFn, Nothing}, U}
    bootstrap::CB
    host::String
    port::UInt32
    socket::Union{Socket, Nothing}  # nullable
    channel::Union{Channel, Nothing}  # nullable
    tls_connection_options::TO
    on_setup::FS  # nullable
    on_shutdown::FD  # nullable
    user_data::U
end

# Initiate a connection to a host
function client_bootstrap_connect!(
        bootstrap::ClientBootstrap,
        host::AbstractString,
        port::Integer;
        socket_options::SocketOptions = bootstrap.socket_options,
        tls_connection_options = bootstrap.tls_connection_options,
        on_setup::Union{OnBootstrapChannelSetupFn, Nothing} = bootstrap.on_setup_callback,
        on_shutdown::Union{OnBootstrapChannelShutdownFn, Nothing} = bootstrap.on_shutdown_callback,
        user_data = bootstrap.user_data,
    )::Union{Nothing, ErrorResult}
    if @atomic bootstrap.shutdown
        raise_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
        return ErrorResult(ERROR_IO_EVENT_LOOP_SHUTDOWN)
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
        on_setup,
        on_shutdown,
        user_data,
    )

    # Resolve host
    resolve_result = host_resolver_resolve!(
        bootstrap.host_resolver,
        host_str,
        (resolver, host, error_code, addresses) -> _on_host_resolved(request, error_code, addresses),
        request,
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
    event_loop = event_loop_group_get_next_loop(bootstrap.event_loop_group)

    if event_loop === nothing
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: no event loop available"
        )
        socket_close!(socket)
        _connection_request_complete(request, ERROR_IO_SOCKET_MISSING_EVENT_LOOP, nothing)
        return nothing
    end

    # Initiate async connect
    connect_result = socket_connect(
        socket,
        remote_endpoint,
        event_loop,
        (sock, err, ud) -> _on_socket_connect_complete(ud, err),
        request,
    )

    if connect_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: failed to initiate connection"
        )
        socket_close!(socket)
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
        socket_close!(socket)
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
    channel = Channel(event_loop, nothing)
    request.channel = channel

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
        socket_close!(socket)
        _connection_request_complete(request, handler_result.code, nothing)
        return nothing
    end

    # If TLS requested, insert TLS handler and defer setup completion
    if request.tls_connection_options !== nothing
        tls_options = request.tls_connection_options

        on_negotiation = (handler, slot, err, ud) -> begin
            if tls_options.on_negotiation_result !== nothing
                Base.invokelatest(tls_options.on_negotiation_result, handler, slot, err, tls_options.user_data)
            end

            if err == AWS_OP_SUCCESS
                setup_result = channel_setup_complete!(channel)
                if setup_result isa ErrorResult
                    socket_close!(socket)
                    _connection_request_complete(request, setup_result.code, nothing)
                    return nothing
                end
                _connection_request_complete(request, AWS_OP_SUCCESS, channel)
            else
                channel_shutdown!(channel, ChannelDirection.READ, err)
                socket_close!(socket)
                _connection_request_complete(request, err, nothing)
            end

            return nothing
        end

        wrapped = TlsConnectionOptions(
            tls_options.ctx;
            server_name = tls_options.server_name,
            on_negotiation_result = on_negotiation,
            on_data_read = tls_options.on_data_read,
            on_error = tls_options.on_error,
            user_data = tls_options.user_data,
            timeout_ms = tls_options.timeout_ms,
        )

        tls_channel_handler_new!(channel, wrapped)
        return nothing
    end

    # Complete channel setup
    setup_result = channel_setup_complete!(channel)

    if setup_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: channel setup failed"
        )
        socket_close!(socket)
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
    if request.on_setup !== nothing
        Base.invokelatest(request.on_setup, request.bootstrap, error_code, channel, request.user_data)
    end
    return nothing
end

# =============================================================================
# Server Bootstrap - for accepting incoming connections
# =============================================================================

# Server bootstrap options
struct ServerBootstrapOptions{ELG, SO, FL <: Union{OnServerListenerSetupFn, Nothing}, FS <: Union{OnIncomingChannelSetupFn, Nothing}, FD <: Union{OnIncomingChannelShutdownFn, Nothing}, U}
    event_loop_group::ELG
    socket_options::SO
    host::String
    port::UInt32
    on_listener_setup::FL  # nullable
    on_incoming_channel_setup::FS  # nullable
    on_incoming_channel_shutdown::FD  # nullable
    user_data::U
end

function ServerBootstrapOptions(;
        event_loop_group,
        socket_options::SocketOptions = SocketOptions(),
        host::AbstractString = "0.0.0.0",
        port::Integer,
        on_listener_setup = nothing,
        on_incoming_channel_setup = nothing,
        on_incoming_channel_shutdown = nothing,
        user_data = nothing,
    )
    return ServerBootstrapOptions(
        event_loop_group,
        socket_options,
        String(host),
        UInt32(port),
        on_listener_setup,
        on_incoming_channel_setup,
        on_incoming_channel_shutdown,
        user_data,
    )
end

# Server bootstrap - for accepting incoming connections
mutable struct ServerBootstrap{ELG, FL <: Union{OnServerListenerSetupFn, Nothing}, FS <: Union{OnIncomingChannelSetupFn, Nothing}, FD <: Union{OnIncomingChannelShutdownFn, Nothing}, U}
    event_loop_group::ELG
    socket_options::SocketOptions
    listener_socket::Union{Socket, Nothing}  # nullable
    on_listener_setup::FL  # nullable
    on_incoming_channel_setup::FS  # nullable
    on_incoming_channel_shutdown::FD  # nullable
    user_data::U
    @atomic shutdown::Bool
    ref_count::RefCounted{ServerBootstrap{ELG, FL, FS, FD, U}, Function}
end

function _server_bootstrap_on_zero_ref(bootstrap::ServerBootstrap)
    logf(LogLevel.TRACE, LS_IO_CHANNEL_BOOTSTRAP, "ServerBootstrap: ref count zero")
    if bootstrap.listener_socket !== nothing
        socket_close!(bootstrap.listener_socket)
    end
    return nothing
end

function ServerBootstrap(
        options::ServerBootstrapOptions{ELG, SO, FL, FS, FD, U},
    ) where {ELG, SO, FL, FS, FD, U}
    SBT = ServerBootstrap{ELG, FL, FS, FD, U}
    bootstrap = SBT(
        options.event_loop_group,
        options.socket_options,
        nothing,
        options.on_listener_setup,
        options.on_incoming_channel_setup,
        options.on_incoming_channel_shutdown,
        options.user_data,
        false,
        RefCounted{SBT, Function}(1, nothing, _server_bootstrap_on_zero_ref),
    )
    bootstrap.ref_count = RefCounted(bootstrap, _server_bootstrap_on_zero_ref)

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

    bind_result = socket_bind(listener, local_endpoint)

    if bind_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: failed to bind to $(options.host):$(options.port)"
        )
        socket_close!(listener)
        return bind_result
    end

    # Start listening
    listen_result = socket_listen(listener, 128)

    if listen_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: failed to listen"
        )
        socket_close!(listener)
        return listen_result
    end

    # Get event loop and start accepting
    event_loop = event_loop_group_get_next_loop(options.event_loop_group)

    if event_loop === nothing
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: no event loop available"
        )
        socket_close!(listener)
        raise_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
        return ErrorResult(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
    end

    listener_options = SocketListenerOptions(
        on_accept_result = (sock, err, new_sock, ud) -> _on_incoming_connection(bootstrap, err, new_sock),
        on_accept_result_user_data = bootstrap,
        on_accept_start = (sock, err, ud) -> begin
            if options.on_listener_setup !== nothing
                options.on_listener_setup(bootstrap, err, sock, options.user_data)
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
        socket_close!(listener)
        return accept_result
    end

    logf(
        LogLevel.INFO, LS_IO_CHANNEL_BOOTSTRAP,
        "ServerBootstrap: listening on $(options.host):$(options.port)"
    )

    return bootstrap
end

# Acquire reference
function server_bootstrap_acquire!(bootstrap::ServerBootstrap)
    acquire!(bootstrap.ref_count)
    return bootstrap
end

# Release reference
function server_bootstrap_release!(bootstrap::ServerBootstrap)
    release!(bootstrap.ref_count)
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
    event_loop = socket.event_loop

    # Create channel
    channel = Channel(event_loop, nothing)

    # Set shutdown callback
    channel_set_shutdown_callback!(
        channel, (ch, err, ud) -> begin
            if bootstrap.on_incoming_channel_shutdown !== nothing
                bootstrap.on_incoming_channel_shutdown(bootstrap, err, ch, bootstrap.user_data)
            end
        end, bootstrap
    )

    # Add socket handler to channel
    handler_result = socket_channel_handler_new!(channel, socket)

    if handler_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: failed to create socket handler for incoming connection"
        )
        socket_close!(socket)
        return nothing
    end

    # Complete channel setup
    setup_result = channel_setup_complete!(channel)

    if setup_result isa ErrorResult
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: incoming channel setup failed"
        )
        socket_close!(socket)
        return nothing
    end

    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,
        "ServerBootstrap: incoming channel $(channel.channel_id) setup complete"
    )

    # Invoke setup callback
    if bootstrap.on_incoming_channel_setup !== nothing
        bootstrap.on_incoming_channel_setup(bootstrap, AWS_OP_SUCCESS, channel, bootstrap.user_data)
    end

    return nothing
end

# Shutdown server bootstrap
function server_bootstrap_shutdown!(bootstrap::ServerBootstrap)
    @atomic bootstrap.shutdown = true

    if bootstrap.listener_socket !== nothing
        socket_stop_accept(bootstrap.listener_socket)
        socket_close!(bootstrap.listener_socket)
        bootstrap.listener_socket = nothing
    end

    logf(LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP, "ServerBootstrap: shutdown")

    return nothing
end
