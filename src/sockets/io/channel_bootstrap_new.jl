@kwdef mutable struct ConnectionAttempts
    event_loop::EventLoop
    host_resolver::HostResolver
    host_resolution_config::HostResolutionConfig
    socket_options::SocketOptions
    host::String
    port::UInt32
    tls_connection_options::MaybeTlsConnectionOptions
    enable_read_back_pressure::Bool = false
    connection_attempt_tasks::Vector{ScheduledTask} = ScheduledTask[]
    connection_chosen::Bool = false
    failed_count::Int = 0
    fut::Future{Socket} = Future{Socket}()
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
    event_loop = @something(requested_event_loop, get_next_event_loop(event_loop_group))
    conn_attempts = ConnectionAttempts(
        event_loop,
        host_resolver,
        host_resolution_config,
        socket_options,
        host,
        port,
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
                conn_attempts.connection_chosen && return nothing
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
            if e isa ReseauError
                notify_exception!(fut, e)
            else
                notify_exception!(fut, ReseauError(ERROR_UNKNOWN))
            end
        end
        return nothing
    end
    wait(fut)
    return nothing
end

function _note_connection_attempt_failure(conn_attempts::ConnectionAttempts, address_count::Int, error_code::Int)
    conn_attempts.connection_chosen && return nothing
    conn_attempts.failed_count += 1
    if conn_attempts.failed_count == address_count
        logf(
            LogLevel.ERROR,
            LS_IO_CHANNEL_BOOTSTRAP,
            "ClientBootstrap: last attempt failed with error $error_code",
        )
        conn_attempts.connection_chosen = true
        _cancel_connection_attempts(conn_attempts)
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
            if conn_attempts.connection_chosen
                socket_close(socket)
                return nothing
            end
            conn_attempts.connection_chosen = true
            _cancel_connection_attempts(conn_attempts)
            socket_close(socket)
            notify_exception!(conn_attempts.fut, ReseauError(error_code))
            return nothing
        end
        socket_close(socket)
        _note_connection_attempt_failure(conn_attempts, address_count, error_code)
        return nothing
    end
    if conn_attempts.connection_chosen
        socket_close(socket)
        return nothing
    end
    logf(
        LogLevel.DEBUG,
        LS_IO_CHANNEL_BOOTSTRAP,
        "ClientBootstrap: connection established to $(conn_attempts.host):$(conn_attempts.port)",
    )
    _cancel_connection_attempts(conn_attempts)
    conn_attempts.connection_chosen = true
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
