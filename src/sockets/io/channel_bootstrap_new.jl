@inline function _socket_uses_network_framework_tls(socket::Socket, tls_options)::Bool
    @static if Sys.isapple()
        return tls_options !== nothing && socket.impl isa NWSocket && is_using_secitem()
    else
        return false
    end
end

@inline _bootstrap_event_callback(::Nothing) = nothing
@inline _bootstrap_event_callback(callback::EventCallable) = callback
@inline _bootstrap_event_callback(callback::F) where {F} = EventCallable(callback)

@inline _bootstrap_channel_callback(::Nothing) = nothing
@inline _bootstrap_channel_callback(callback::ChannelCallable) = callback
@inline _bootstrap_channel_callback(callback::F) where {F} = ChannelCallable(callback)

mutable struct ConnectionAttempts
    event_loop::EventLoop
    host_resolver::HostResolver
    host_resolution_config::HostResolutionConfig
    socket_options::SocketOptions
    host::String
    port::UInt32
    tls_connection_options::MaybeTlsConnectionOptions
    enable_read_back_pressure::Bool
    connection_attempt_tasks::Vector{ScheduledTask}
    @atomic connection_chosen::Bool
    failed_count::Int
    fut::Future{Socket}
end

function ConnectionAttempts(
        event_loop::EventLoop,
        host_resolver::HostResolver,
        host_resolution_config::HostResolutionConfig,
        socket_options::SocketOptions,
        host::String,
        port::UInt32,
        tls_connection_options::MaybeTlsConnectionOptions,
        enable_read_back_pressure::Bool = false,
    )
    return ConnectionAttempts(
        event_loop,
        host_resolver,
        host_resolution_config,
        socket_options,
        host,
        port,
        tls_connection_options,
        enable_read_back_pressure,
        ScheduledTask[],
        false,
        0,
        Future{Socket}(),
    )
end

function _select_connection_event_loop(
        event_loop_group::EventLoopGroup,
        requested_event_loop::Union{EventLoop, Nothing},
    )::EventLoop
    if requested_event_loop === nothing
        return get_next_event_loop(event_loop_group)
    end
    for loop in event_loop_group.event_loops
        if loop === requested_event_loop
            return requested_event_loop
        end
    end
    throw(ReseauError(ERROR_IO_SOCKET_MISSING_EVENT_LOOP))
end

function client_bootstrap_connect!(
    f::F,
    host::AbstractString,
    port::Integer;
    socket_options::SocketOptions = SocketOptions(),
    tls_connection_options::MaybeTlsConnectionOptions = nothing,
    enable_read_back_pressure::Bool = false,
    requested_event_loop::Union{EventLoop, Nothing} = nothing,
    host_resolution_config::Union{HostResolutionConfig, Nothing} = nothing,
    event_loop_group::EventLoopGroup = EventLoops.get_event_loop_group(),
    host_resolver::HostResolver = get_host_resolver(),
) where {F}
    host = String(host)
    host_resolution_config = _normalize_resolution_config(
        host_resolver,
        host_resolution_config,
    )
    addresses = host_resolver_resolve!(host_resolver, host, host_resolution_config)
    event_loop = _select_connection_event_loop(event_loop_group, requested_event_loop)
    conn_attempts = ConnectionAttempts(
        event_loop,
        host_resolver,
        host_resolution_config,
        socket_options,
        host,
        UInt32(port),
        tls_connection_options,
        enable_read_back_pressure,
    )
    cb = ChannelCallable(f)
    try
        socket = _schedule_connection_attempts(conn_attempts, addresses)
        return Channel(
            event_loop,
            socket;
            on_setup_completed = cb,
            enable_read_back_pressure,
            tls_connection_options,
        )
    catch
        _cancel_connection_attempts(conn_attempts)
        rethrow()
    end
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
        host_resolution_config::HostResolutionConfig,
        has_both_fam::Bool,
        base_timestamp::UInt64,
        attempt_idx::Int,
    )::UInt64
    delay_ns = attempt_idx == 0 ?
        host_resolution_config.resolution_delay_ns :
        host_resolution_config.connection_attempt_delay_ns
    if !has_both_fam
        delay_ns = 0
    end
    delay = delay_ns + UInt64(attempt_idx) * host_resolution_config.connection_attempt_delay_ns
    return delay == 0 ? UInt64(0) : base_timestamp + delay
end

function _schedule_connection_attempts(
    conn_attempts::ConnectionAttempts,
    addresses::Vector{HostAddress}
)
    isempty(addresses) && throw(ReseauError(ERROR_IO_DNS_NO_ADDRESS_FOR_HOST))
    has_both_fam = _connection_request_has_both_families(addresses)
    address_count = length(addresses)
    now = clock_now_ns()
    for (idx, address) in enumerate(addresses)
        run_at_timestamp = _attempt_schedule_run_at(conn_attempts.host_resolution_config, has_both_fam, now, idx - 1)
        task = ScheduledTask(; type_tag = "client_bootstrap_attempt") do status
            try
                _coerce_task_status(status) == TaskStatus.RUN_READY || return nothing
                (@atomic conn_attempts.connection_chosen) && return nothing
                _initiate_socket_connect(conn_attempts, address_count, address)
            catch
                Core.println("client_bootstrap_attempt task errored")
            end
            return nothing
        end
        push!(conn_attempts.connection_attempt_tasks, task)
        if run_at_timestamp == 0
            schedule_task_now!(conn_attempts.event_loop, task)
        else
            schedule_task_future!(conn_attempts.event_loop, task, run_at_timestamp)
        end
    end
    return wait(conn_attempts.fut)
end

function _clear_connection_attempt_tasks!(conn_attempts::ConnectionAttempts)
    for task in conn_attempts.connection_attempt_tasks
        task.scheduled = false
    end
    empty!(conn_attempts.connection_attempt_tasks)
    return nothing
end

function _cancel_connection_attempts_on_event_loop!(conn_attempts::ConnectionAttempts)
    for task in conn_attempts.connection_attempt_tasks
        task.scheduled && cancel_task!(conn_attempts.event_loop, task)
    end
    empty!(conn_attempts.connection_attempt_tasks)
    return nothing
end

function _cancel_connection_attempts(conn_attempts::ConnectionAttempts)
    if !(@atomic conn_attempts.event_loop.running)
        return _clear_connection_attempt_tasks!(conn_attempts)
    end
    if event_loop_thread_is_callers_thread(conn_attempts.event_loop)
        return _cancel_connection_attempts_on_event_loop!(conn_attempts)
    end
    fut = Future{Nothing}()
    schedule_task_now!(conn_attempts.event_loop; type_tag = "client_bootstrap_cancel_attempts") do status
        try
            status = _coerce_task_status(status)
            if status == TaskStatus.RUN_READY
                _cancel_connection_attempts_on_event_loop!(conn_attempts)
            else
                _clear_connection_attempt_tasks!(conn_attempts)
            end
            notify(fut, nothing)
        catch e
            err = e isa ReseauError ? e.code : ERROR_UNKNOWN
            notify_exception!(fut, ReseauError(err))
        end
        return nothing
    end
    wait(fut)
    return nothing
end

function _note_connection_attempt_failure(conn_attempts::ConnectionAttempts, address_count::Int, error_code::Int)
    (@atomic conn_attempts.connection_chosen) && return nothing
    conn_attempts.failed_count += 1
    if conn_attempts.failed_count == address_count
        logf(
            LogLevel.ERROR,
            LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: last attempt failed with error $error_code",
        )
        @atomic conn_attempts.connection_chosen = true
        notify_exception!(conn_attempts.fut, ReseauError(error_code))
        return nothing
    end
    logf(
        LogLevel.DEBUG,
        LS_IO_CHANNEL_BOOTSTRAP,
        "ClientBootstrap: socket connect attempt $(conn_attempts.failed_count)/$address_count failed with error $error_code. More attempts ongoing...",
    )
    return nothing
end

function _on_socket_connect_complete(
        socket::Socket,
        error_code::Int,
        conn_attempts::ConnectionAttempts,
        address_count::Int,
        address::HostAddress,
    )::Nothing
    if error_code != OP_SUCCESS
        logf(
            LogLevel.DEBUG,
            LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: connection failed with error $error_code",
        )
        record_connection_failure!(conn_attempts.host_resolver, address)
        if _socket_uses_network_framework_tls(socket, conn_attempts.tls_connection_options) &&
                io_error_code_is_tls(error_code)
            if @atomic(conn_attempts.connection_chosen)
                socket_close(socket)
                return nothing
            end
            @atomic conn_attempts.connection_chosen = true
            socket_close(socket)
            notify_exception!(conn_attempts.fut, ReseauError(error_code))
            return nothing
        end
        socket_close(socket)
        _note_connection_attempt_failure(conn_attempts, address_count, error_code)
        return nothing
    end
    if @atomic(conn_attempts.connection_chosen)
        socket_close(socket)
        return nothing
    end
    logf(
        LogLevel.DEBUG,
        LS_IO_CHANNEL_BOOTSTRAP,
        "ClientBootstrap: connection established to $(conn_attempts.host):$(conn_attempts.port)",
    )
    @atomic conn_attempts.connection_chosen = true
    notify(conn_attempts.fut, socket)
    return nothing
end

function _initiate_socket_connect(conn_attempts::ConnectionAttempts, address_count::Int, address::HostAddress)
    options = copy(conn_attempts.socket_options)
    if options.domain != SocketDomain.LOCAL && options.domain != SocketDomain.VSOCK
        options.domain = address.address_type == HostAddressType.AAAA ? SocketDomain.IPV6 : SocketDomain.IPV4
    end
    local socket
    try
        socket = socket_init(options)
    catch e
        logf(LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP, "ClientBootstrap: failed to create socket")
        _note_connection_attempt_failure(conn_attempts, address_count, e isa ReseauError ? e.code : ERROR_UNKNOWN)
        return nothing
    end
    remote_endpoint = SocketEndpoint()
    set_address!(remote_endpoint, address.address)
    remote_endpoint.port = conn_attempts.port
    try
        socket_connect(
            socket;
            remote_endpoint,
            event_loop = conn_attempts.event_loop,
            on_connection_result = EventCallable(err -> _on_socket_connect_complete(socket, err, conn_attempts, address_count, address)),
            tls_connection_options = conn_attempts.tls_connection_options,
        )
    catch e
        logf(LogLevel.ERROR, LS_IO_CHANNEL_BOOTSTRAP, "ClientBootstrap: failed to initiate connection")
        record_connection_failure!(conn_attempts.host_resolver, address)
        socket_close(socket)
        _note_connection_attempt_failure(conn_attempts, address_count, e isa ReseauError ? e.code : ERROR_UNKNOWN)
        return nothing
    end
    return nothing
end

# =============================================================================
# Server bootstrap
# =============================================================================

mutable struct ServerBootstrap
    event_loop_group::EventLoopGroup
    socket_options::SocketOptions
    host::String
    port::UInt32
    backlog::Int
    tls_connection_options::MaybeTlsConnectionOptions
    on_listener_setup::Union{EventCallable, Nothing}
    on_incoming_channel_setup::Union{ChannelCallable, Nothing}
    on_incoming_channel_shutdown::Union{ChannelCallable, Nothing}
    on_listener_destroy::Union{EventCallable, Nothing}
    enable_read_back_pressure::Bool
    listener_socket::Union{Socket, Nothing}
    listener_event_loop::Union{EventLoop, Nothing}
    @atomic inflight_channels::Int
    @atomic listener_closed::Bool
    @atomic destroy_called::Bool
    @atomic shutdown::Bool
end

function ServerBootstrap(;
        event_loop_group,
        socket_options::SocketOptions = SocketOptions(),
        host::AbstractString = "0.0.0.0",
        port::Integer,
        backlog::Integer = 128,
        tls_connection_options::MaybeTlsConnectionOptions = nothing,
        on_listener_setup = nothing,
        on_incoming_channel_setup = nothing,
        on_incoming_channel_shutdown = nothing,
        on_listener_destroy = nothing,
        enable_read_back_pressure::Bool = false,
    )
    bootstrap = ServerBootstrap(
        event_loop_group,
        socket_options,
        String(host),
        UInt32(port),
        Int(backlog),
        tls_connection_options,
        _bootstrap_event_callback(on_listener_setup),
        _bootstrap_channel_callback(on_incoming_channel_setup),
        _bootstrap_channel_callback(on_incoming_channel_shutdown),
        _bootstrap_event_callback(on_listener_destroy),
        enable_read_back_pressure,
        nothing,
        nothing,
        0,
        false,
        false,
        false,
    )
    _server_bootstrap_start_listener!(bootstrap)
    return bootstrap
end

struct _ServerOnAcceptResult
    bootstrap::ServerBootstrap
end

@inline function (cb::_ServerOnAcceptResult)(err::Int, new_sock)::Nothing
    if err != OP_SUCCESS || !(new_sock isa Socket)
        _on_incoming_connection(cb.bootstrap, err, nothing)
        return nothing
    end
    _on_incoming_connection(cb.bootstrap, err, new_sock::Socket)
    return nothing
end

function _server_bootstrap_start_listener!(bootstrap::ServerBootstrap)::Nothing
    listener = nothing
    try
        listener = socket_init(bootstrap.socket_options)
        bootstrap.listener_socket = listener

        local_endpoint = SocketEndpoint()
        set_address!(local_endpoint, bootstrap.host)
        local_endpoint.port = bootstrap.port

        if _socket_uses_network_framework_tls(listener, bootstrap.tls_connection_options)
            socket_bind(listener; local_endpoint, tls_connection_options = bootstrap.tls_connection_options)
        else
            socket_bind(listener; local_endpoint)
        end

        socket_listen(listener, bootstrap.backlog)

        event_loop = get_next_event_loop(bootstrap.event_loop_group)
        bootstrap.listener_event_loop = event_loop

        on_accept_start = if bootstrap.on_listener_setup !== nothing
            EventCallable(err -> (bootstrap.on_listener_setup::EventCallable)(err))
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
    catch
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
        LogLevel.INFO,
        LS_IO_CHANNEL_BOOTSTRAP,
        "ServerBootstrap: listening on $(bootstrap.host):$(bootstrap.port)",
    )
    return nothing
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

    if !(@atomicreplace bootstrap.destroy_called false => true).success
        return nothing
    end

    cb = bootstrap.on_listener_destroy
    cb === nothing && return nothing

    listener_loop = bootstrap.listener_event_loop
    if listener_loop !== nothing && !event_loop_thread_is_callers_thread(listener_loop)
        schedule_task_now!(listener_loop; type_tag = "server_listener_destroy") do _
            cb2 = bootstrap.on_listener_destroy
            cb2 === nothing && return nothing
            cb2(OP_SUCCESS)
            return nothing
        end
    else
        cb(OP_SUCCESS)
    end

    return nothing
end

@inline function _server_bootstrap_listener_closed!(bootstrap::ServerBootstrap)::Nothing
    @atomic bootstrap.listener_closed = true
    _server_bootstrap_maybe_destroy(bootstrap)
    return nothing
end

mutable struct _IncomingLifecycle
    @atomic finished::Bool
end

@inline function _finish_incoming_once!(bootstrap::ServerBootstrap, lifecycle::_IncomingLifecycle)::Nothing
    if !(@atomicreplace lifecycle.finished false => true).success
        return nothing
    end
    _server_bootstrap_incoming_finished!(bootstrap)
    return nothing
end

struct _ServerOnListenerClose
    bootstrap::ServerBootstrap
end

@inline function (cb::_ServerOnListenerClose)(_status::UInt8)::Nothing
    _server_bootstrap_listener_closed!(cb.bootstrap)
    return nothing
end

function _server_bootstrap_listener_destroy_task(bootstrap::ServerBootstrap, _status::TaskStatus.T)
    listener = bootstrap.listener_socket
    bootstrap.listener_socket = nothing

    listener === nothing && return _server_bootstrap_listener_closed!(bootstrap)

    close_callback_installed = false
    close_started = false

    try
        socket_set_close_complete_callback(listener, TaskFn(_ServerOnListenerClose(bootstrap)))
        close_callback_installed = true
    catch
    end

    try
        socket_stop_accept(listener)
    catch
    end

    try
        socket_close(listener)
        close_started = true
    catch
    end

    try
        socket_cleanup!(listener)
    catch
    end

    if !(close_callback_installed && close_started)
        _server_bootstrap_listener_closed!(bootstrap)
    end

    return nothing
end

function _on_incoming_connection(
        bootstrap::ServerBootstrap,
        error_code::Int,
        new_socket::Union{Socket, Nothing},
    )::Nothing
    if error_code != OP_SUCCESS || new_socket === nothing
        logf(
            LogLevel.DEBUG,
            LS_IO_CHANNEL_BOOTSTRAP,
            "ServerBootstrap: incoming connection error $error_code",
        )
        return nothing
    end

    if @atomic bootstrap.shutdown
        socket_close(new_socket)
        return nothing
    end

    _setup_incoming_channel(bootstrap, new_socket::Socket)
    return nothing
end

function _setup_incoming_channel(bootstrap::ServerBootstrap, socket::Socket)::Nothing
    _server_bootstrap_incoming_started!(bootstrap)
    lifecycle = _IncomingLifecycle(false)

    event_loop = get_next_event_loop(bootstrap.event_loop_group)

    try
        socket_assign_to_event_loop(socket, event_loop)
    catch e
        err = e isa ReseauError ? e.code : ERROR_UNKNOWN
        if bootstrap.on_incoming_channel_setup !== nothing
            bootstrap.on_incoming_channel_setup(err, nothing)
        end
        socket_close(socket)
        _finish_incoming_once!(bootstrap, lifecycle)
        return nothing
    end

    channel_ref = Ref{Union{Channel, Nothing}}(nothing)

    on_setup = bootstrap.on_incoming_channel_setup
    on_shutdown = EventCallable(err -> begin
        ch = channel_ref[]
        if ch !== nothing && bootstrap.on_incoming_channel_shutdown !== nothing
            (bootstrap.on_incoming_channel_shutdown::ChannelCallable)(err, ch)
        end
        _finish_incoming_once!(bootstrap, lifecycle)
        return nothing
    end)

    try
        channel = Channel(
            event_loop,
            socket;
            on_setup_completed = on_setup,
            on_shutdown_completed = on_shutdown,
            enable_read_back_pressure = bootstrap.enable_read_back_pressure,
            tls_connection_options = bootstrap.tls_connection_options,
        )
        channel_ref[] = channel
    catch e
        err = e isa ReseauError ? e.code : ERROR_UNKNOWN
        if bootstrap.on_incoming_channel_setup !== nothing
            bootstrap.on_incoming_channel_setup(err, nothing)
        end
        socket_close(socket)
        _finish_incoming_once!(bootstrap, lifecycle)
        return nothing
    end

    return nothing
end

function server_bootstrap_shutdown!(bootstrap::ServerBootstrap)
    if !(@atomicreplace bootstrap.shutdown false => true).success
        return nothing
    end

    if bootstrap.listener_socket !== nothing && bootstrap.listener_event_loop !== nothing
        schedule_task_now!(bootstrap.listener_event_loop; type_tag = "server_listener_shutdown") do status
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

    return nothing
end
