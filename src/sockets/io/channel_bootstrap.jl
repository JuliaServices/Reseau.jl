# AWS IO Library - Channel Bootstrap
# Port of aws-c-io/source/channel_bootstrap.c

@inline _bootstrap_channel_callback(::Nothing) = nothing
@inline _bootstrap_channel_callback(callback::BootstrapChannelCallback) = callback
@inline _bootstrap_channel_callback(callback::F) where {F} = BootstrapChannelCallback(callback)

@inline _bootstrap_event_callback(::Nothing) = nothing
@inline _bootstrap_event_callback(callback::BootstrapEventCallback) = callback
@inline _bootstrap_event_callback(callback::F) where {F} = BootstrapEventCallback(callback)

struct _BootstrapListenerDestroyAdapter{F}
    callback::F
end

@inline function (adapter::_BootstrapListenerDestroyAdapter)(bootstrap, _error_code::Int, user_data)
    adapter.callback(bootstrap, user_data)
    return nothing
end

@inline _bootstrap_listener_destroy_callback(::Nothing) = nothing
@inline _bootstrap_listener_destroy_callback(callback::BootstrapEventCallback) = callback
@inline _bootstrap_listener_destroy_callback(callback) =
    BootstrapEventCallback(_BootstrapListenerDestroyAdapter(callback))

# Client bootstrap - for creating outgoing connections
mutable struct ClientBootstrap
    event_loop_group::EventLoopGroup
    host_resolver::HostResolver
    host_resolution_config::Union{HostResolutionConfig, Nothing}
    socket_options::SocketOptions
    tls_connection_options::MaybeTlsConnectionOptions
    on_protocol_negotiated::Union{ProtocolNegotiatedCallable, Nothing}
    @atomic shutdown::Bool
end

function ClientBootstrap(;
        event_loop_group,
        host_resolver,
        host_resolution_config = nothing,
        socket_options::SocketOptions = SocketOptions(),
        tls_connection_options::MaybeTlsConnectionOptions = nothing,
        on_protocol_negotiated = nothing,
    )
    on_protocol_negotiated_cb = on_protocol_negotiated === nothing ?
        nothing :
        on_protocol_negotiated isa ProtocolNegotiatedCallable ?
            on_protocol_negotiated :
            ProtocolNegotiatedCallable(on_protocol_negotiated)
    bootstrap = ClientBootstrap(
        event_loop_group,
        host_resolver,
        host_resolution_config,
        socket_options,
        tls_connection_options,
        on_protocol_negotiated_cb,
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
    tls_connection_options::MaybeTlsConnectionOptions
    on_protocol_negotiated::Union{ProtocolNegotiatedCallable, Nothing}
    on_setup::Union{ChannelCallable, Nothing}
    enable_read_back_pressure::Bool
    requested_event_loop::Union{EventLoop, Nothing}
    event_loop::Union{EventLoop, Nothing}
    host_resolution_config::HostResolutionConfig
    addresses::Vector{HostAddress}
    addresses_count::Int
    failed_count::Int
    connection_attempt_tasks::Vector{ScheduledTask}
    connection_chosen::Bool
end

mutable struct SocketConnectionAttempt
    request::SocketConnectionRequest
    host_address::HostAddress
end

function client_bootstrap_connect!(
        bootstrap::ClientBootstrap,
        host::AbstractString,
        port::Integer,
        socket_options::SocketOptions,
        tls_connection_options::MaybeTlsConnectionOptions,
        on_protocol_negotiated::Union{ProtocolNegotiatedCallable, Nothing},
        on_setup::Union{ChannelCallable, Nothing},
        enable_read_back_pressure::Bool,
        requested_event_loop::Union{EventLoop, Nothing},
        host_resolution_config::Union{HostResolutionConfig, Nothing},
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

    protocol_negotiated_cb = on_protocol_negotiated
    on_setup_cb = on_setup
    request_resolution_config = _normalize_resolution_config(
        bootstrap.host_resolver,
        host_resolution_config,
    )

    request = SocketConnectionRequest(
        bootstrap,
        host_str,
        UInt32(port),
        socket_options,
        tls_connection_options,
        protocol_negotiated_cb,
        on_setup_cb,
        enable_read_back_pressure,
        requested_event_loop,
        nothing,
        request_resolution_config,
        HostAddress[],
        0,
        0,
        ScheduledTask[],
        false,
    )

    try
        host_resolver_resolve!(
            addresses -> _on_host_resolved(request, addresses),
            bootstrap.host_resolver,
            host_str,
            request_resolution_config,
        )
    catch e
        _connection_request_complete(
            request,
            e isa ReseauError ? e.code : e isa DNSError ? Int(e.code) : ERROR_UNKNOWN,
            nothing,
        )
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

@inline function _connection_request_has_both_families(addresses::Vector{HostAddress})::Bool
    has_v4 = false
    has_v6 = false
    for addr in addresses
        if addr.address_type == HostAddressType.A
            has_v4 = true
        elseif addr.address_type == HostAddressType.AAAA
            has_v6 = true
        end
        has_v4 && has_v6 && return true
    end
    return false
end

@inline function _attempt_schedule_run_at(
        request::SocketConnectionRequest,
        base_timestamp::UInt64,
        attempt_idx::Int,
    )::UInt64
    delay_ns = attempt_idx == 0 ? request.host_resolution_config.resolution_delay_ns : request.host_resolution_config.connection_attempt_delay_ns
    if !_connection_request_has_both_families(request.addresses)
        delay_ns = 0
    end
    delay = delay_ns + UInt64(attempt_idx) * request.host_resolution_config.connection_attempt_delay_ns
    return delay == 0 ? UInt64(0) : base_timestamp + delay
end

function _cancel_connection_attempts(request::SocketConnectionRequest)
    event_loop = request.event_loop
    event_loop === nothing && return nothing
    for task in request.connection_attempt_tasks
        if task.scheduled
            event_loop_cancel_task!(event_loop, task)
        end
    end
    empty!(request.connection_attempt_tasks)
    return nothing
end

function _start_connection_attempt(
        request::SocketConnectionRequest,
        address::HostAddress,
        run_at_timestamp::UInt64,
        event_loop::EventLoop,
    )
    task = ScheduledTask(; type_tag = "client_bootstrap_attempt") do status
        try
            _coerce_task_status(status) == TaskStatus.RUN_READY || return nothing
            request.connection_chosen && return nothing
            _initiate_socket_connect(request, address)
        catch e
            Core.println("client_bootstrap_attempt task errored")
        end
        return nothing
    end
    push!(request.connection_attempt_tasks, task)

    if run_at_timestamp == 0
        event_loop_schedule_task_now!(event_loop, task)
    else
        event_loop_schedule_task_future!(event_loop, task, run_at_timestamp)
    end
    return nothing
end

# Callback when host resolution completes
function _on_host_resolved(request::SocketConnectionRequest, addresses::Vector{HostAddress})::Nothing
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

    event_loop_schedule_task_now!(event_loop; type_tag = "client_bootstrap_attempts") do status
        try
            _coerce_task_status(status) == TaskStatus.RUN_READY || return nothing
            _start_connection_attempts(request, addresses, event_loop)
        catch e
            Core.println("client_bootstrap_attempts task errored")
        end
        return nothing
    end

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
    if request.connection_attempt_tasks !== nothing
        _cancel_connection_attempts(request)
    end
    if request.addresses_count == 0
        _connection_request_complete(request, ERROR_IO_DNS_NO_ADDRESS_FOR_HOST, nothing)
        return nothing
    end

    request.connection_attempt_tasks = ScheduledTask[]
    now = event_loop_current_clock_time(event_loop)
    for (idx, address) in enumerate(addresses)
        run_at_timestamp = _attempt_schedule_run_at(request, now, idx - 1)
        logf(
            LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,
            string(
                "ClientBootstrap: scheduling connection attempt at ",
                run_at_timestamp,
            ),
        )
        _start_connection_attempt(request, address, run_at_timestamp, event_loop)
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

    # Initiate async connect
    try
        socket_connect(
            socket,
            remote_endpoint;
            event_loop = event_loop,
            event_loop_group = request.bootstrap.event_loop_group,
            on_connection_result = EventCallable(err -> _on_socket_connect_complete(socket, err, attempt)),
            tls_connection_options = request.tls_connection_options,
        )
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
function _on_socket_connect_complete(socket::Socket, error_code::Int, attempt::SocketConnectionAttempt)::Nothing
    request = attempt.request

    if error_code != OP_SUCCESS
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
            _cancel_connection_attempts(request)
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
    _cancel_connection_attempts(request)
    request.connection_chosen = true

    # Create channel for this connection
    _setup_client_channel(request, socket)::Nothing

    return nothing
end

# Set up channel for connected socket
mutable struct _ClientChannelSetupCtx
    request::SocketConnectionRequest
    socket::Socket
    channel::Union{Channel, Nothing}
end

struct _ClientChannelOnSetup{C <: _ClientChannelSetupCtx}
    ctx::C
end

function (cb::_ClientChannelOnSetup)(error_code::Int)::Nothing
    ctx = cb.ctx
    request = ctx.request
    socket = ctx.socket
    channel = ctx.channel::Channel

    if error_code != OP_SUCCESS
        logf(
            LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: channel setup failed"
        )
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
        socket_close(socket)
        _connection_request_complete(request, err, nothing)
        return nothing
    end

    if request.tls_connection_options !== nothing && _socket_uses_network_framework_tls(socket, request.tls_connection_options)
        tls_options = request.tls_connection_options::TlsConnectionOptions
        if request.on_protocol_negotiated !== nothing
            try
                _install_protocol_handler_from_socket(channel, socket, request.on_protocol_negotiated)
            catch e
                err = e isa ReseauError ? e.code : ERROR_UNKNOWN
                channel_shutdown!(channel, err)
                socket_close(socket)
                _connection_request_complete(request, err, nothing)
                return nothing
            end
        end
        if tls_options.on_negotiation_result !== nothing
            tls_options.on_negotiation_result(handler_result, channel.first, OP_SUCCESS)
        end
        _connection_request_complete(request, OP_SUCCESS, channel)
        if channel_thread_is_callers_thread(channel)
            try
                channel_trigger_read(channel)
            catch e
                err = e isa ReseauError ? e.code : ERROR_UNKNOWN
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
        tls_options = request.tls_connection_options::TlsConnectionOptions
        advertise_alpn = request.on_protocol_negotiated !== nothing && tls_is_alpn_available()
        on_negotiation = (handler, slot, err) -> begin
            if tls_options.on_negotiation_result !== nothing
                tls_options.on_negotiation_result(handler, slot, err)
            end
            if err == OP_SUCCESS
                _connection_request_complete(request, OP_SUCCESS, channel)
            else
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
    _connection_request_complete(request, OP_SUCCESS, channel)
    return nothing
end

function _setup_client_channel(request::SocketConnectionRequest, socket::Socket)::Nothing
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

    ctx = _ClientChannelSetupCtx(request, socket, nothing)
    on_setup = EventCallable(_ClientChannelOnSetup(ctx))
    options = ChannelOptions(
        event_loop = event_loop,
        event_loop_group = request.bootstrap.event_loop_group,
        on_setup_completed = on_setup,
        on_shutdown_completed = nothing,
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

    ctx.channel = channel
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
        request.on_setup(error_code, channel)
    catch err
        logf(LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP, "ClientBootstrap: on_setup callback threw")
    end
    return nothing
end

function _connection_request_complete(request::SocketConnectionRequest, error_code::Int, channel::Union{Channel, Nothing})
    _cancel_connection_attempts(request)
    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,string("ClientBootstrap: connection request complete error=%d on_setup=%s", " ", string(error_code), " ", string(request.on_setup === nothing ? "nothing" : "set"), " ", ))
    if request.on_setup !== nothing
        requested_loop = request.requested_event_loop
        if requested_loop !== nothing && !event_loop_thread_is_callers_thread(requested_loop)
            event_loop_schedule_task_now!(requested_loop; type_tag = "client_bootstrap_on_setup") do status
                try
                    _coerce_task_status(status) == TaskStatus.RUN_READY || return nothing
                    _connection_request_invoke_on_setup(request, error_code, channel)
                catch e
                    Core.println("client_bootstrap_on_setup task errored")
                end
                return nothing
            end
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
struct ServerBootstrapOptions{TO, PN, LS, ICS, ICSH, LD, UD}
    event_loop_group::EventLoopGroup
    socket_options::SocketOptions
    host::String
    port::UInt32
    backlog::Int
    tls_connection_options::TO
    on_protocol_negotiated::PN
    on_listener_setup::LS
    on_incoming_channel_setup::ICS
    on_incoming_channel_shutdown::ICSH
    on_listener_destroy::LD
    user_data::UD
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
    on_protocol_negotiated_cb = on_protocol_negotiated === nothing ?
        nothing :
        on_protocol_negotiated isa ProtocolNegotiatedCallable ?
            on_protocol_negotiated :
            ProtocolNegotiatedCallable(on_protocol_negotiated)
    return ServerBootstrapOptions(
        event_loop_group,
        socket_options,
        String(host),
        UInt32(port),
        Int(backlog),
        tls_connection_options,
        on_protocol_negotiated_cb,
        on_listener_setup,
        on_incoming_channel_setup,
        on_incoming_channel_shutdown,
        _bootstrap_listener_destroy_callback(on_listener_destroy),
        user_data,
        enable_read_back_pressure,
    )
end

# Server bootstrap - for accepting incoming connections
mutable struct ServerBootstrap{TO, PN, ICS, ICSH, LD, UD}
    event_loop_group::EventLoopGroup
    socket_options::SocketOptions
    listener_socket::Union{Socket, Nothing}
    listener_event_loop::Union{EventLoop, Nothing}
    tls_connection_options::TO
    on_protocol_negotiated::PN
    on_incoming_channel_setup::ICS
    on_incoming_channel_shutdown::ICSH
    on_listener_destroy::LD
    user_data::UD
    enable_read_back_pressure::Bool
    @atomic inflight_channels::Int
    @atomic listener_closed::Bool
    @atomic destroy_called::Bool
    @atomic shutdown::Bool
end

struct _ServerOnAcceptResult{B <: ServerBootstrap}
    bootstrap::B
end

@inline function (cb::_ServerOnAcceptResult{B})(err::Int, new_sock)::Nothing where {B}
    socket = new_sock::Socket
    _on_incoming_connection(cb.bootstrap, err, socket)
    return nothing
end

struct _ServerOnAcceptStart{B <: ServerBootstrap, CB}
    bootstrap::B
    callback::CB
end

@inline function (cb::_ServerOnAcceptStart{B, CB})(err::Int)::Nothing where {B, CB}
    bs = cb.bootstrap
    cb.callback(bs, err, bs.user_data)
    return nothing
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
        options.on_incoming_channel_setup,
        options.on_incoming_channel_shutdown,
        options.on_listener_destroy,
        ud,
        options.enable_read_back_pressure,
        0,
        false,
        false,
        false,
    )

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

        if _socket_uses_network_framework_tls(listener, options.tls_connection_options)
            socket_bind(listener, local_endpoint; tls_connection_options = options.tls_connection_options)
        else
            socket_bind(listener, local_endpoint)
        end

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

        on_accept_start = if options.on_listener_setup !== nothing
            EventCallable(_ServerOnAcceptStart(bootstrap, options.on_listener_setup))
        else
            nothing
        end

        socket_start_accept(
            listener,
            event_loop;
            on_accept_result = ChannelCallable(_ServerOnAcceptResult(bootstrap)),
            on_accept_start = on_accept_start,
            event_loop_group = bootstrap.event_loop_group,
        )
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
        event_loop_schedule_task_now!(listener_loop; type_tag = "server_listener_destroy") do _
            cb = bootstrap.on_listener_destroy
            cb === nothing && return nothing
            cb(bootstrap, OP_SUCCESS, bootstrap.user_data)
            return nothing
        end
    else
        bootstrap.on_listener_destroy(bootstrap, OP_SUCCESS, bootstrap.user_data)
    end

    return nothing
end

function _server_bootstrap_listener_destroy_task(bootstrap::ServerBootstrap, status::TaskStatus.T)
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
function _on_incoming_connection(bootstrap::ServerBootstrap, error_code::Int, new_socket::Socket)::Nothing
    if error_code != OP_SUCCESS
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
mutable struct _IncomingChannelSetupCtx{B <: ServerBootstrap}
    bootstrap::B
    socket::Socket
    channel::Union{Channel, Nothing}
    incoming_called::Bool
    setup_succeeded::Bool
end

@inline function _incoming_channel_invoke_callback!(
        ctx::_IncomingChannelSetupCtx,
        err::Int,
        channel::Union{Channel, Nothing},
    )::Nothing
    if ctx.incoming_called
        return nothing
    end
    ctx.incoming_called = true
    bootstrap = ctx.bootstrap
    if bootstrap.on_incoming_channel_setup !== nothing
        bootstrap.on_incoming_channel_setup(bootstrap, err, channel, bootstrap.user_data)
    end
    return nothing
end

struct _IncomingChannelOnShutdown{C <: _IncomingChannelSetupCtx}
    ctx::C
end

@inline function (cb::_IncomingChannelOnShutdown)(err::Int)::Nothing
    ctx = cb.ctx
    bootstrap = ctx.bootstrap
    channel = ctx.channel
    shutdown_err = err
    if !ctx.incoming_called
        if shutdown_err == OP_SUCCESS
            shutdown_err = ERROR_UNKNOWN
        end
        _incoming_channel_invoke_callback!(ctx, shutdown_err, nothing)
    end
    if ctx.setup_succeeded && bootstrap.on_incoming_channel_shutdown !== nothing
        bootstrap.on_incoming_channel_shutdown(bootstrap, err, channel, bootstrap.user_data)
    end
    _server_bootstrap_incoming_finished!(bootstrap)
    return nothing
end

struct _IncomingChannelOnSetup{C <: _IncomingChannelSetupCtx}
    ctx::C
end

function _incoming_channel_on_setup!(ctx::_IncomingChannelSetupCtx, error_code::Int)::Nothing
    bootstrap = ctx.bootstrap
    socket = ctx.socket
    channel = ctx.channel::Channel

    if error_code != OP_SUCCESS
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
        tls_options = bootstrap.tls_connection_options::TlsConnectionOptions
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
            tls_options.on_negotiation_result(handler_result, channel.first, OP_SUCCESS)
        end
        ctx.setup_succeeded = true
        _incoming_channel_invoke_callback!(ctx, OP_SUCCESS, channel)
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
        tls_options = bootstrap.tls_connection_options::TlsConnectionOptions
        advertise_alpn = bootstrap.on_protocol_negotiated !== nothing && tls_is_alpn_available()
        on_negotiation = (handler, slot, err) -> begin
            if tls_options.on_negotiation_result !== nothing
                tls_options.on_negotiation_result(handler, slot, err)
            end
            if err == OP_SUCCESS
                ctx.setup_succeeded = true
                _incoming_channel_invoke_callback!(ctx, OP_SUCCESS, channel)
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

    ctx.setup_succeeded = true
    logf(
        LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP,
        "ServerBootstrap: incoming channel $(channel.channel_id) setup complete"
    )
    _incoming_channel_invoke_callback!(ctx, OP_SUCCESS, channel)
    return nothing
end

@inline function (cb::_IncomingChannelOnSetup)(error_code::Int)::Nothing
    return _incoming_channel_on_setup!(cb.ctx, error_code)
end

function _setup_incoming_channel(bootstrap::ServerBootstrap, socket::Socket)::Nothing
    _server_bootstrap_incoming_started!(bootstrap)
    ctx = _IncomingChannelSetupCtx(bootstrap, socket, nothing, false, false)

    event_loop = event_loop_group_get_next_loop(bootstrap.event_loop_group)
    if event_loop === nothing
        logf(
            LogLevel.ERROR,
            LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: no event loop available for incoming channel"
        )
        _incoming_channel_invoke_callback!(ctx, ERROR_IO_SOCKET_MISSING_EVENT_LOOP, nothing)
        socket_close(socket)
        _server_bootstrap_incoming_finished!(bootstrap)
        return nothing
    end

    try
        socket_assign_to_event_loop(socket, event_loop, bootstrap.event_loop_group)
    catch e
        logf(
            LogLevel.ERROR,
            LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: failed to assign incoming socket to event loop"
        )
        err = e isa ReseauError ? e.code : ERROR_UNKNOWN
        _incoming_channel_invoke_callback!(ctx, err, nothing)
        socket_close(socket)
        _server_bootstrap_incoming_finished!(bootstrap)
        return nothing
    end

    on_shutdown = EventCallable(_IncomingChannelOnShutdown(ctx))
    on_setup = EventCallable(_IncomingChannelOnSetup(ctx))
    options = ChannelOptions(
        event_loop = event_loop,
        event_loop_group = bootstrap.event_loop_group,
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
        _incoming_channel_invoke_callback!(ctx, err, nothing)
        socket_close(socket)
        _server_bootstrap_incoming_finished!(bootstrap)
        return nothing
    end

    ctx.channel = channel
    return nothing
end

# Shutdown server bootstrap
function server_bootstrap_shutdown!(bootstrap::ServerBootstrap)
    expected = false
    if !(@atomicreplace bootstrap.shutdown expected => true).success
        return nothing
    end

    if bootstrap.listener_socket !== nothing && bootstrap.listener_event_loop !== nothing
        event_loop_schedule_task_now!(bootstrap.listener_event_loop; type_tag = "server_listener_shutdown") do status
            try
                _server_bootstrap_listener_destroy_task(bootstrap, _coerce_task_status(status))
            catch
                Core.println("server_listener_shutdown task errored")
            end
            return nothing
        end
    else
        _server_bootstrap_listener_destroy_task(bootstrap, TaskStatus.RUN_READY)
    end

    logf(LogLevel.DEBUG, LS_IO_CHANNEL_BOOTSTRAP, "ServerBootstrap: shutdown")

    return nothing
end
