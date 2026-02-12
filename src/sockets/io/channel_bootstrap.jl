# AWS IO Library - Channel Bootstrap
# Port of aws-c-io/source/channel_bootstrap.c

@inline _bootstrap_protocol_negotiated_callback(::Nothing) = nothing
@inline _bootstrap_protocol_negotiated_callback(callback::ProtocolNegotiatedCallable) = callback
@inline _bootstrap_protocol_negotiated_callback(callback) = ProtocolNegotiatedCallable(callback)

@inline _bootstrap_channel_callback(::Nothing) = nothing
@inline _bootstrap_channel_callback(callback::BootstrapChannelCallback) = callback
@inline _bootstrap_channel_callback(callback) = BootstrapChannelCallback(callback)

@inline _bootstrap_event_callback(::Nothing) = nothing
@inline _bootstrap_event_callback(callback::BootstrapEventCallback) = callback
@inline _bootstrap_event_callback(callback) = BootstrapEventCallback(callback)

@inline _bootstrap_listener_destroy_callback(::Nothing) = nothing
@inline _bootstrap_listener_destroy_callback(callback::BootstrapEventCallback) = callback
@inline _bootstrap_listener_destroy_callback(callback) = BootstrapEventCallback((bootstrap, _error_code, user_data) -> callback(bootstrap, user_data))

# Client bootstrap options
struct ClientBootstrapOptions
    event_loop_group::EventLoopGroup
    host_resolver::HostResolver
    host_resolution_config::Union{HostResolutionConfig, Nothing}
    socket_options::SocketOptions
    tls_connection_options::MaybeTlsConnectionOptions
    on_protocol_negotiated::Union{ProtocolNegotiatedCallable, Nothing}
    on_creation_callback::Union{BootstrapChannelCallback, Nothing}
    on_setup_callback::Union{BootstrapChannelCallback, Nothing}
    on_shutdown_callback::Union{BootstrapChannelCallback, Nothing}
    user_data::Any
end

function ClientBootstrapOptions(;
        event_loop_group,
        host_resolver,
        host_resolution_config = nothing,
        socket_options::SocketOptions = SocketOptions(),
        tls_connection_options::MaybeTlsConnectionOptions = nothing,
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
        _bootstrap_protocol_negotiated_callback(on_protocol_negotiated),
        _bootstrap_channel_callback(on_creation_callback),
        _bootstrap_channel_callback(on_setup_callback),
        _bootstrap_channel_callback(on_shutdown_callback),
        user_data,
    )
end

# Client bootstrap - for creating outgoing connections
mutable struct ClientBootstrap
    event_loop_group::EventLoopGroup
    host_resolver::HostResolver
    host_resolution_config::Union{HostResolutionConfig, Nothing}
    socket_options::SocketOptions
    tls_connection_options::MaybeTlsConnectionOptions
    on_protocol_negotiated::Union{ProtocolNegotiatedCallable, Nothing}
    on_creation_callback::Union{BootstrapChannelCallback, Nothing}
    on_setup_callback::Union{BootstrapChannelCallback, Nothing}
    on_shutdown_callback::Union{BootstrapChannelCallback, Nothing}
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

function ClientBootstrap(;
        event_loop_group,
        host_resolver,
        host_resolution_config = nothing,
        socket_options::SocketOptions = SocketOptions(),
        tls_connection_options::MaybeTlsConnectionOptions = nothing,
        on_protocol_negotiated = nothing,
        on_creation_callback = nothing,
        on_setup_callback = nothing,
        on_shutdown_callback = nothing,
        user_data = nothing,
    )
    return ClientBootstrap(
        ClientBootstrapOptions(;
            event_loop_group = event_loop_group,
            host_resolver = host_resolver,
            host_resolution_config = host_resolution_config,
            socket_options = socket_options,
            tls_connection_options = tls_connection_options,
            on_protocol_negotiated = on_protocol_negotiated,
            on_creation_callback = on_creation_callback,
            on_setup_callback = on_setup_callback,
            on_shutdown_callback = on_shutdown_callback,
            user_data = user_data,
        ),
    )
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
        on_protocol_negotiated::ProtocolNegotiatedCallable,
    )::Nothing
    protocol = socket_get_protocol(socket)
    new_slot = channel_slot_new!(channel)
    channel_slot_insert_end!(channel, new_slot)
    handler = on_protocol_negotiated(new_slot, protocol)
    if handler === nothing
        throw_error(ERROR_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE)
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
    tls_connection_options::MaybeTlsConnectionOptions
    on_protocol_negotiated::Union{ProtocolNegotiatedCallable, Nothing}
    on_creation::Union{EventCallable, Nothing}
    on_setup::Union{EventCallable, Nothing}
    on_shutdown::Union{EventCallable, Nothing}
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
        tls_connection_options::MaybeTlsConnectionOptions = bootstrap.tls_connection_options,
        on_protocol_negotiated = bootstrap.on_protocol_negotiated,
        on_creation = bootstrap.on_creation_callback,
        on_setup = bootstrap.on_setup_callback,
        on_shutdown = bootstrap.on_shutdown_callback,
        user_data = bootstrap.user_data,
        enable_read_back_pressure::Bool = false,
        requested_event_loop::Union{EventLoop, Nothing} = nothing,
        host_resolution_config::Union{HostResolutionConfig, Nothing} = bootstrap.host_resolution_config,
    )::Nothing
    if @atomic bootstrap.shutdown
        throw_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end

    if requested_event_loop !== nothing &&
            !_event_loop_group_contains_loop(bootstrap.event_loop_group, requested_event_loop)
        throw_error(ERROR_IO_PINNED_EVENT_LOOP_MISMATCH)
    end

    host_str = String(host)

    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,
        "ClientBootstrap: initiating connection to $host_str:$port"
    )

    protocol_negotiated_cb = _bootstrap_protocol_negotiated_callback(on_protocol_negotiated)
    on_creation_cb = _bootstrap_channel_callback(on_creation)
    on_setup_cb = _bootstrap_channel_callback(on_setup)
    on_shutdown_cb = _bootstrap_channel_callback(on_shutdown)

    # Create connection request — callbacks are wrapped into EventCallables
    # that capture the user_data. The closures also capture `request` (set below)
    # so request.channel is accessible at callback time.
    request = SocketConnectionRequest(
        bootstrap,
        host_str,
        UInt32(port),
        socket_options,
        nothing,
        nothing,
        tls_connection_options,
        protocol_negotiated_cb,
        nothing,  # on_creation (set below)
        nothing,  # on_setup (set below)
        nothing,  # on_shutdown (set below)
        enable_read_back_pressure,
        requested_event_loop,
        nothing,
        HostAddress[],
        0,
        0,
        false,
    )
    # Wrap user callbacks into EventCallables that capture request + user_data
    if on_creation_cb !== nothing
        request.on_creation = EventCallable(error_code -> on_creation_cb(bootstrap, error_code, request.channel, user_data))
    end
    if on_setup_cb !== nothing
        request.on_setup = EventCallable(error_code -> on_setup_cb(bootstrap, error_code, request.channel, user_data))
    end
    if on_shutdown_cb !== nothing
        request.on_shutdown = EventCallable(error_code -> on_shutdown_cb(bootstrap, error_code, request.channel, user_data))
    end

    # Resolve host
    resolve_result = host_resolver_resolve!(
        bootstrap.host_resolver,
        host_str,
        (resolver, host, error_code, addresses) -> _on_host_resolved(request, error_code, addresses);
        resolution_config = host_resolution_config,
    )

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
                _coerce_task_status(status) == TaskStatus.RUN_READY || return nothing
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
    local socket
    try
        socket = socket_init(options)
    catch e
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: failed to create socket"
        )
        _note_connection_attempt_failure(request, e isa ReseauError ? e.code : ERROR_UNKNOWN)
        return nothing
    end

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
        on_connection_result = EventCallable(err -> _on_socket_connect_complete(socket, err, attempt)),
        tls_connection_options = request.tls_connection_options,
    )

    # Initiate async connect
    try
        socket_connect(socket, connect_opts)
    catch e
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: failed to initiate connection"
        )
        _record_connection_failure(request, address)
        socket_close(socket)
        _note_connection_attempt_failure(request, e isa ReseauError ? e.code : ERROR_UNKNOWN)
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
    channel_box = Ref{Any}(nothing)
    on_shutdown = EventCallable(err -> begin
        request.channel = channel_box[]
        if request.on_shutdown !== nothing
            request.on_shutdown(err)
        end
        return nothing
    end)
    on_setup = EventCallable(error_code -> begin
        channel = channel_box[]::Channel
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
        local handler_result
        try
            handler_result = socket_channel_handler_new!(channel, socket)
        catch e
            err = e isa ReseauError ? e.code : ERROR_UNKNOWN
            logf(
                LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
                "ClientBootstrap: failed to create socket channel handler"
            )
            request.on_shutdown = nothing
            socket_close(socket)
            _connection_request_complete(request, err, nothing)
            return nothing
        end
        if request.tls_connection_options !== nothing && _socket_uses_network_framework_tls(socket, request.tls_connection_options)
            tls_options = request.tls_connection_options
            if request.on_protocol_negotiated !== nothing
                try
                    _install_protocol_handler_from_socket(channel, socket, request.on_protocol_negotiated)
                catch e
                    err = e isa ReseauError ? e.code : ERROR_UNKNOWN
                    request.on_shutdown = nothing
                    channel_shutdown!(channel, err)
                    socket_close(socket)
                    _connection_request_complete(request, err, nothing)
                    return nothing
                end
            end
            if tls_options.on_negotiation_result !== nothing
                tls_options.on_negotiation_result(handler_result, channel.first, AWS_OP_SUCCESS)
            end
            _connection_request_complete(request, AWS_OP_SUCCESS, channel)
            if channel_thread_is_callers_thread(channel)
                try
                    channel_trigger_read(channel)
                catch e
                    err = e isa ReseauError ? e.code : ERROR_UNKNOWN
                    request.on_shutdown = nothing
                    channel_shutdown!(channel, err)
                    socket_close(socket)
                    _connection_request_complete(request, err, nothing)
                    return nothing
                end
            else
                trigger_task = ChannelTask(EventCallable(s -> begin
                    _coerce_task_status(s) == TaskStatus.RUN_READY || return nothing
                    try
                        channel_trigger_read(channel)
                    catch e
                        err = e isa ReseauError ? e.code : ERROR_UNKNOWN
                        channel_shutdown!(channel, err)
                    end
                    return nothing
                end), "client_tls_trigger_read")
                channel_schedule_task_now!(channel, trigger_task)
            end
            return nothing
        elseif request.tls_connection_options !== nothing
            tls_options = request.tls_connection_options
            advertise_alpn = request.on_protocol_negotiated !== nothing && tls_is_alpn_available()
            on_negotiation = (handler, slot, err) -> begin
                if tls_options.on_negotiation_result !== nothing
                    tls_options.on_negotiation_result(handler, slot, err)
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
                timeout_ms = tls_options.timeout_ms,
            )
            local tls_handler
            try
                tls_handler = tls_channel_handler_new!(channel, wrapped)
            catch e
                err = e isa ReseauError ? e.code : ERROR_UNKNOWN
                request.on_shutdown = nothing
                channel_shutdown!(channel, err)
                socket_close(socket)
                _connection_request_complete(request, err, nothing)
                return nothing
            end
            if advertise_alpn
                alpn_slot = channel_slot_new!(channel)
                channel_slot_insert_right!(tls_handler.slot, alpn_slot)
                alpn_handler = tls_alpn_handler_new(request.on_protocol_negotiated)
                channel_slot_set_handler!(alpn_slot, alpn_handler)
            end
            try
                tls_client_handler_start_negotiation(tls_handler)
            catch e
                err = e isa ReseauError ? e.code : ERROR_UNKNOWN
                request.on_shutdown = nothing
                channel_shutdown!(channel, err)
                socket_close(socket)
                _connection_request_complete(request, err, nothing)
                return nothing
            end
            if channel_thread_is_callers_thread(channel)
                try
                    channel_trigger_read(channel)
                catch e
                    err = e isa ReseauError ? e.code : ERROR_UNKNOWN
                    request.on_shutdown = nothing
                    channel_shutdown!(channel, err)
                    socket_close(socket)
                    _connection_request_complete(request, err, nothing)
                    return nothing
                end
            else
                trigger_task = ChannelTask(EventCallable(s -> begin
                    _coerce_task_status(s) == TaskStatus.RUN_READY || return nothing
                    try
                        channel_trigger_read(channel)
                    catch e
                        err = e isa ReseauError ? e.code : ERROR_UNKNOWN
                        channel_shutdown!(channel, err)
                    end
                    return nothing
                end), "client_tls_trigger_read")
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
    end)
    options = ChannelOptions(
        event_loop = event_loop,
        on_setup_completed = on_setup,
        on_shutdown_completed = on_shutdown,
        enable_read_back_pressure = request.enable_read_back_pressure,
    )
    local channel
    try
        channel = channel_new(options)
    catch e
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: failed to create channel"
        )
        err = e isa ReseauError ? e.code : ERROR_UNKNOWN
        socket_close(socket)
        _connection_request_complete(request, err, nothing)
        return nothing
    end
    channel_box[] = channel
    request.channel = channel
    if request.on_creation !== nothing
        request.on_creation(AWS_OP_SUCCESS)
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
    request.channel = channel  # ensure closure can see the channel
    try
        request.on_setup(error_code)
    catch err
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,string("ClientBootstrap: on_setup callback threw: %s", " ", string(sprint(showerror, err, catch_backtrace())), " ", ))
    end
    return nothing
end

function _connection_request_complete(request::SocketConnectionRequest, error_code::Int, channel::Union{Channel, Nothing})
    if error_code != AWS_OP_SUCCESS
        request.on_shutdown = nothing
    end
    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,string("ClientBootstrap: connection request complete error=%d on_setup=%s", " ", string(error_code), " ", string(request.on_setup === nothing ? "nothing" : "set"), " ", ))
    if request.on_setup !== nothing
        requested_loop = request.requested_event_loop
        if requested_loop !== nothing && !event_loop_thread_is_callers_thread(requested_loop)
            task = ScheduledTask(
                TaskFn(function(status)
                    try
                        _coerce_task_status(status) == TaskStatus.RUN_READY || return nothing
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
    tls_connection_options::MaybeTlsConnectionOptions
    on_protocol_negotiated::Union{ProtocolNegotiatedCallable, Nothing}
    on_listener_setup::Union{BootstrapEventCallback, Nothing}
    on_incoming_channel_setup::Union{BootstrapChannelCallback, Nothing}
    on_incoming_channel_shutdown::Union{BootstrapChannelCallback, Nothing}
    on_listener_destroy::Union{BootstrapEventCallback, Nothing}
    user_data::Any
    enable_read_back_pressure::Bool
end

function ServerBootstrapOptions(;
        event_loop_group,
        socket_options::SocketOptions = SocketOptions(),
        host::AbstractString = "0.0.0.0",
        port::Integer,
        backlog::Integer = 128,
        tls_connection_options::MaybeTlsConnectionOptions = nothing,
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
        _bootstrap_protocol_negotiated_callback(on_protocol_negotiated),
        _bootstrap_event_callback(on_listener_setup),
        _bootstrap_channel_callback(on_incoming_channel_setup),
        _bootstrap_channel_callback(on_incoming_channel_shutdown),
        _bootstrap_listener_destroy_callback(on_listener_destroy),
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
    tls_connection_options::MaybeTlsConnectionOptions
    on_protocol_negotiated::Union{ProtocolNegotiatedCallable, Nothing}
    on_incoming_channel_setup::Union{ChannelCallable, Nothing}
    on_incoming_channel_shutdown::Union{ChannelCallable, Nothing}
    on_listener_destroy::Union{TaskFn, Nothing}
    user_data::Any
    enable_read_back_pressure::Bool
    @atomic inflight_channels::Int
    @atomic listener_closed::Bool
    @atomic destroy_called::Bool
    @atomic shutdown::Bool
end

function ServerBootstrap(options::ServerBootstrapOptions)
    ud = options.user_data
    bootstrap = ServerBootstrap(
        options.event_loop_group,
        options.socket_options,
        nothing,
        nothing,
        options.tls_connection_options,
        options.on_protocol_negotiated,
        nothing,  # on_incoming_channel_setup (set below)
        nothing,  # on_incoming_channel_shutdown (set below)
        nothing,  # on_listener_destroy (set below)
        ud,
        options.enable_read_back_pressure,
        0,
        false,
        false,
        false,
    )
    # Wrap user callbacks — closures capture bootstrap + user_data
    if options.on_incoming_channel_setup !== nothing
        bootstrap.on_incoming_channel_setup = ChannelCallable((err, ch) -> options.on_incoming_channel_setup(bootstrap, err, ch, ud))
    end
    if options.on_incoming_channel_shutdown !== nothing
        bootstrap.on_incoming_channel_shutdown = ChannelCallable((err, ch) -> options.on_incoming_channel_shutdown(bootstrap, err, ch, ud))
    end
    if options.on_listener_destroy !== nothing
        bootstrap.on_listener_destroy = TaskFn(_ -> options.on_listener_destroy(bootstrap, AWS_OP_SUCCESS, ud))
    end

    logf(LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP, "ServerBootstrap: created")

    listener = nothing
    try
        # Create listener socket
        listener = socket_init(options.socket_options)
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
        socket_bind(listener, bind_opts)

        # Start listening
        socket_listen(listener, options.backlog)

        # Get event loop and start accepting
        event_loop = event_loop_group_get_next_loop(options.event_loop_group)

        if event_loop === nothing
            logf(
                LogLevel.ERROR,
                LS_IO_CHANNEL_BOOTSTRAP,string("ServerBootstrap: no event loop available", " ", ))
            throw_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP)
        end

        bootstrap.listener_event_loop = event_loop

        listener_options = SocketListenerOptions(
            on_accept_result = ChannelCallable((err, new_sock) -> _on_incoming_connection(bootstrap, err, new_sock)),
            on_accept_start = if options.on_listener_setup !== nothing
                EventCallable(err -> options.on_listener_setup(bootstrap, err, ud))
            else
                nothing
            end,
        )

        socket_start_accept(listener, event_loop, listener_options)
    catch e
        err = e isa ReseauError ? e.code : ERROR_UNKNOWN
        logf(
            LogLevel.ERROR,
            LS_IO_CHANNEL_BOOTSTRAP,string("ServerBootstrap: setup failed with error %d", " ", string(err), " ", ))
        if listener !== nothing
            try
                socket_close(listener)
            catch
            end
        end
        bootstrap.listener_socket = nothing
        bootstrap.listener_event_loop = nothing
        rethrow()
    end

    logf(
        LogLevel.INFO, LS_IO_CHANNEL_BOOTSTRAP,
        "ServerBootstrap: listening on $(options.host):$(options.port)"
    )

    return bootstrap
end

function ServerBootstrap(;
        event_loop_group,
        socket_options::SocketOptions = SocketOptions(),
        host::AbstractString = "0.0.0.0",
        port::Integer,
        backlog::Integer = 128,
        tls_connection_options::MaybeTlsConnectionOptions = nothing,
        on_protocol_negotiated = nothing,
        on_listener_setup = nothing,
        on_incoming_channel_setup = nothing,
        on_incoming_channel_shutdown = nothing,
        on_listener_destroy = nothing,
        user_data = nothing,
        enable_read_back_pressure::Bool = false,
    )
    return ServerBootstrap(
        ServerBootstrapOptions(;
            event_loop_group = event_loop_group,
            socket_options = socket_options,
            host = host,
            port = port,
            backlog = backlog,
            tls_connection_options = tls_connection_options,
            on_protocol_negotiated = on_protocol_negotiated,
            on_listener_setup = on_listener_setup,
            on_incoming_channel_setup = on_incoming_channel_setup,
            on_incoming_channel_shutdown = on_incoming_channel_shutdown,
            on_listener_destroy = on_listener_destroy,
            user_data = user_data,
            enable_read_back_pressure = enable_read_back_pressure,
        ),
    )
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
                    bootstrap.on_listener_destroy(UInt8(0))
                catch e
                    Core.println("server_listener_destroy task errored: $e")
                end
                return nothing
            end);
            type_tag = "server_listener_destroy",
        )
        event_loop_schedule_task_now!(listener_loop, task)
    else
        bootstrap.on_listener_destroy(UInt8(0))
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
            bootstrap.on_incoming_channel_setup(err, channel)
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
    try
        socket_assign_to_event_loop(socket, event_loop)
    catch e
        logf(
            LogLevel.ERROR,
            LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: failed to assign incoming socket to event loop"
        )
        err = e isa ReseauError ? e.code : ERROR_UNKNOWN
        invoke_incoming_callback(err, nothing)
        socket_close(socket)
        _server_bootstrap_incoming_finished!(bootstrap)
        return nothing
    end
    channel_box = Ref{Any}(nothing)
    on_shutdown = EventCallable(err -> begin
        ch = channel_box[]
        shutdown_err = err
        if !incoming_called[]
            if shutdown_err == AWS_OP_SUCCESS
                shutdown_err = ERROR_UNKNOWN
            end
            invoke_incoming_callback(shutdown_err, nothing)
        end
        if setup_succeeded[] && bootstrap.on_incoming_channel_shutdown !== nothing
            bootstrap.on_incoming_channel_shutdown(err, ch)
        end
        _server_bootstrap_incoming_finished!(bootstrap)
        return nothing
    end)
    on_setup = EventCallable(error_code -> begin
        channel = channel_box[]::Channel
        if error_code != AWS_OP_SUCCESS
            logf(
                LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
                "ServerBootstrap: incoming channel setup failed"
            )
            channel_shutdown!(channel, error_code)
            socket_close(socket)
            return nothing
        end
        local handler_result
        try
            handler_result = socket_channel_handler_new!(channel, socket)
        catch e
            err = e isa ReseauError ? e.code : ERROR_UNKNOWN
            logf(
                LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
                "ServerBootstrap: failed to create socket handler for incoming connection"
            )
            channel_shutdown!(channel, err)
            socket_close(socket)
            return nothing
        end
        if bootstrap.tls_connection_options !== nothing && _socket_uses_network_framework_tls(socket, bootstrap.tls_connection_options)
            tls_options = bootstrap.tls_connection_options
            if bootstrap.on_protocol_negotiated !== nothing
                try
                    _install_protocol_handler_from_socket(channel, socket, bootstrap.on_protocol_negotiated)
                catch e
                    err = e isa ReseauError ? e.code : ERROR_UNKNOWN
                    channel_shutdown!(channel, err)
                    socket_close(socket)
                    return nothing
                end
            end
            if tls_options.on_negotiation_result !== nothing
                tls_options.on_negotiation_result(handler_result, channel.first, AWS_OP_SUCCESS)
            end
            setup_succeeded[] = true
            invoke_incoming_callback(AWS_OP_SUCCESS, channel)
            if channel_thread_is_callers_thread(channel)
                try
                    channel_trigger_read(channel)
                catch e
                    err = e isa ReseauError ? e.code : ERROR_UNKNOWN
                    channel_shutdown!(channel, err)
                    return nothing
                end
            else
                trigger_task = ChannelTask(EventCallable(s -> begin
                    _coerce_task_status(s) == TaskStatus.RUN_READY || return nothing
                    try
                        channel_trigger_read(channel)
                    catch e
                        err = e isa ReseauError ? e.code : ERROR_UNKNOWN
                        channel_shutdown!(channel, err)
                    end
                    return nothing
                end), "server_tls_trigger_read")
                channel_schedule_task_now!(channel, trigger_task)
            end
            return nothing
        elseif bootstrap.tls_connection_options !== nothing
            tls_options = bootstrap.tls_connection_options
            advertise_alpn = bootstrap.on_protocol_negotiated !== nothing && tls_is_alpn_available()
            on_negotiation = (handler, slot, err) -> begin
                if tls_options.on_negotiation_result !== nothing
                    tls_options.on_negotiation_result(handler, slot, err)
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
                timeout_ms = tls_options.timeout_ms,
            )
            local tls_handler
            try
                tls_handler = tls_channel_handler_new!(channel, wrapped)
            catch e
                err = e isa ReseauError ? e.code : ERROR_UNKNOWN
                channel_shutdown!(channel, err)
                socket_close(socket)
                return nothing
            end
            if advertise_alpn
                alpn_slot = channel_slot_new!(channel)
                channel_slot_insert_right!(tls_handler.slot, alpn_slot)
                alpn_handler = tls_alpn_handler_new(bootstrap.on_protocol_negotiated)
                channel_slot_set_handler!(alpn_slot, alpn_handler)
            end
            if channel_thread_is_callers_thread(channel)
                try
                    channel_trigger_read(channel)
                catch e
                    err = e isa ReseauError ? e.code : ERROR_UNKNOWN
                    channel_shutdown!(channel, err)
                    return nothing
                end
            else
                trigger_task = ChannelTask(EventCallable(s -> begin
                    _coerce_task_status(s) == TaskStatus.RUN_READY || return nothing
                    try
                        channel_trigger_read(channel)
                    catch e
                        err = e isa ReseauError ? e.code : ERROR_UNKNOWN
                        channel_shutdown!(channel, err)
                    end
                    return nothing
                end), "server_tls_trigger_read")
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
    end)
    options = ChannelOptions(
        event_loop = event_loop,
        on_setup_completed = on_setup,
        on_shutdown_completed = on_shutdown,
        enable_read_back_pressure = bootstrap.enable_read_back_pressure,
    )
    local channel
    try
        channel = channel_new(options)
    catch e
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: failed to create channel for incoming connection"
        )
        err = e isa ReseauError ? e.code : ERROR_UNKNOWN
        invoke_incoming_callback(err, nothing)
        socket_close(socket)
        _server_bootstrap_incoming_finished!(bootstrap)
        return nothing
    end
    channel_box[] = channel
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
                    _server_bootstrap_listener_destroy_task((bootstrap = bootstrap,), _coerce_task_status(status))
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
