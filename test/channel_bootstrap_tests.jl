using Test
using Reseau

# On macOS, IPV4 → NW sockets which don't expose resolved port synchronously.
# Use LOCAL domain (POSIX sockets) for bootstrap tests that need socket_get_bound_address.
function _bootstrap_test_config()
    @static if Sys.isapple()
        endpoint = Sockets.SocketEndpoint()
        Sockets.socket_endpoint_init_local_address_for_test!(endpoint)
        host = Sockets.get_address(endpoint)
        sock_opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.LOCAL)
        # Custom resolver that returns the local path as an address (DNS doesn't apply to LOCAL domain)
        resolve_fn = (h, impl_data) -> begin
            _ = impl_data
            return [Sockets.HostAddress(host, Sockets.HostAddressType.A, h, UInt64(0))]
        end
        res_config = Sockets.HostResolutionConfig(impl = resolve_fn)
        return (; host, sock_opts, use_port = false, resolution_config = res_config)
    else
        return (; host = "127.0.0.1", sock_opts = Sockets.SocketOptions(), use_port = true, resolution_config = nothing)
    end
end

function wait_for_pred(pred::Function; timeout_s::Float64 = 5.0)
    start = Base.time_ns()
    timeout_ns = Int(timeout_s * 1_000_000_000)
    while (Base.time_ns() - start) < timeout_ns
        if pred()
            return true
        end
        sleep(0.01)
    end
    return false
end

@testset "client/server bootstrap callbacks" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(elg)

    server_setup_called = Ref(false)
    server_setup_error = Ref{Int}(-1)
    server_channel = Ref{Any}(nothing)
    server_setup_has_pool = Ref(false)

    cfg = _bootstrap_test_config()

    server_bootstrap = Sockets.ServerBootstrap(Sockets.ServerBootstrapOptions(
        event_loop_group = elg,
        socket_options = cfg.sock_opts,
        host = cfg.host,
        port = 0,
        on_incoming_channel_setup = (bs, err, channel, ud) -> begin
            server_setup_called[] = true
            server_setup_error[] = err
            server_channel[] = channel
            server_setup_has_pool[] = channel !== nothing && channel.message_pool !== nothing
            return nothing
        end,
    ))

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    if cfg.use_port
        bound = Sockets.socket_get_bound_address(listener)
        @test bound isa Sockets.SocketEndpoint
        port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
        @test port != 0
    else
        port = 0
    end

    client_bootstrap = Sockets.ClientBootstrap(Sockets.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    creation_called = Ref(false)
    creation_error = Ref{Int}(-1)
    setup_called = Ref(false)
    setup_error = Ref{Int}(-1)
    shutdown_called = Ref(false)
    creation_order = Ref(0)
    setup_order = Ref(0)
    order = Ref(0)
    creation_backpressure = Ref(false)
    setup_channel = Ref{Any}(nothing)
    setup_has_pool = Ref(false)

    res = Sockets.client_bootstrap_connect!(
        client_bootstrap,
        cfg.host,
        port;
        socket_options = cfg.sock_opts,
        host_resolution_config = cfg.resolution_config,
        enable_read_back_pressure = true,
        on_creation = (bs, err, channel, ud) -> begin
            order[] += 1
            creation_order[] = order[]
            creation_called[] = true
            creation_error[] = err
            creation_backpressure[] = channel.read_back_pressure_enabled
            return nothing
        end,
        on_setup = (bs, err, channel, ud) -> begin
            order[] += 1
            setup_order[] = order[]
            setup_called[] = true
            setup_error[] = err
            setup_channel[] = channel
            setup_has_pool[] = channel !== nothing && channel.message_pool !== nothing
            return nothing
        end,
        on_shutdown = (bs, err, channel, ud) -> begin
            shutdown_called[] = true
            return nothing
        end,
    )

    @test res === nothing
    @test wait_for_pred(() -> setup_called[])
    @test creation_called[]
    @test creation_error[] == Reseau.AWS_OP_SUCCESS
    @test setup_error[] == Reseau.AWS_OP_SUCCESS
    @test setup_order[] > creation_order[]
    @test creation_backpressure[]
    @test setup_channel[] !== nothing
    @test setup_has_pool[]
    @test setup_channel[].read_back_pressure_enabled

    @test wait_for_pred(() -> server_setup_called[])
    @test server_setup_error[] == Reseau.AWS_OP_SUCCESS
    @test server_setup_has_pool[]

    if setup_channel[] !== nothing
        Sockets.pipeline_shutdown!(setup_channel[], 0)
        @test wait_for_pred(() -> shutdown_called[])
    end

    if server_channel[] !== nothing
        Sockets.pipeline_shutdown!(server_channel[], 0)
    end

    Sockets.server_bootstrap_shutdown!(server_bootstrap)
    Sockets.host_resolver_shutdown!(resolver)
    EventLoops.event_loop_group_destroy!(elg)
end

@testset "client bootstrap attempts multiple resolved addresses" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(elg)
    cfg = _bootstrap_test_config()

    server_setup_called = Ref(false)
    server_channel = Ref{Any}(nothing)

    server_bootstrap = Sockets.ServerBootstrap(Sockets.ServerBootstrapOptions(
        event_loop_group = elg,
        socket_options = cfg.sock_opts,
        host = cfg.host,
        port = 0,
        on_incoming_channel_setup = (bs, err, channel, ud) -> begin
            server_setup_called[] = true
            server_channel[] = channel
            return nothing
        end,
    ))

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    if cfg.use_port
        bound = Sockets.socket_get_bound_address(listener)
        @test bound isa Sockets.SocketEndpoint
        port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
        @test port != 0
    else
        port = 0
    end

    client_bootstrap = Sockets.ClientBootstrap(Sockets.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    setup_called = Ref(false)
    setup_error = Ref{Int}(-1)
    setup_channel = Ref{Any}(nothing)
    shutdown_called = Ref(false)

    @static if Sys.isapple()
        # On macOS LOCAL domain, resolver returns the local path directly
        resolve_impl = (host, impl_data) -> begin
            _ = impl_data
            return [
                Sockets.HostAddress(cfg.host, Sockets.HostAddressType.A, host, UInt64(0)),
            ]
        end
    else
        resolve_impl = (host, impl_data) -> begin
            _ = impl_data
            return [
                Sockets.HostAddress("::1", Sockets.HostAddressType.AAAA, host, UInt64(0)),
                Sockets.HostAddress("127.0.0.1", Sockets.HostAddressType.A, host, UInt64(0)),
            ]
        end
    end
    resolution_config = Sockets.HostResolutionConfig(impl = resolve_impl)

    res = Sockets.client_bootstrap_connect!(
        client_bootstrap,
        "example.com",
        port;
        socket_options = cfg.sock_opts,
        host_resolution_config = resolution_config,
        on_setup = (bs, err, channel, ud) -> begin
            setup_called[] = true
            setup_error[] = err
            setup_channel[] = channel
            return nothing
        end,
        on_shutdown = (bs, err, channel, ud) -> begin
            shutdown_called[] = true
            return nothing
        end,
    )

    @test res === nothing
    @test wait_for_pred(() -> setup_called[])
    @test setup_error[] == Reseau.AWS_OP_SUCCESS
    @test setup_channel[] !== nothing
    @test wait_for_pred(() -> server_setup_called[])

    if setup_channel[] !== nothing
        Sockets.pipeline_shutdown!(setup_channel[], 0)
        @test wait_for_pred(() -> shutdown_called[])
    end

    if server_channel[] !== nothing
        Sockets.pipeline_shutdown!(server_channel[], 0)
    end

    Sockets.server_bootstrap_shutdown!(server_bootstrap)
    Sockets.host_resolver_shutdown!(resolver)
    EventLoops.event_loop_group_destroy!(elg)
end

@testset "client bootstrap requested event loop mismatch" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(elg)
    client_bootstrap = Sockets.ClientBootstrap(Sockets.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    bad_loop = EventLoops.event_loop_new()
    @test_throws Reseau.ReseauError Sockets.client_bootstrap_connect!(
        client_bootstrap,
        "localhost",
        80;
        requested_event_loop = bad_loop,
    )
    EventLoops.event_loop_destroy!(bad_loop)

    Sockets.host_resolver_shutdown!(resolver)
    EventLoops.event_loop_group_destroy!(elg)
end

@testset "client bootstrap on_setup runs on requested event loop" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(elg)
    client_bootstrap = Sockets.ClientBootstrap(Sockets.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))
    requested_loop = EventLoops.event_loop_group_get_loop_at(elg, 0)
    @test requested_loop !== nothing
    setup_called = Ref(false)
    setup_on_loop = Ref(false)
    request = Sockets.SocketConnectionRequest{Nothing, Nothing, Sockets._SocketConnectionEventCallback, Nothing, Nothing}(
        client_bootstrap,
        "example.com",
        UInt32(443),
        client_bootstrap.socket_options,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        Sockets._SocketConnectionEventCallback((bs, err, channel, ud) -> begin
            _ = bs
            _ = channel
            _ = ud
            setup_called[] = true
            setup_on_loop[] = EventLoops.event_loop_thread_is_callers_thread(requested_loop)
            return nothing
        end, nothing),
        nothing,
        false,
        requested_loop,
        nothing,
        Sockets.HostResolutionConfig(),
        Sockets.HostAddress[],
        0,
        0,
        Sockets.ScheduledTask[],
        false,
    )
    Sockets._connection_request_complete(request, EventLoops.ERROR_IO_DNS_NO_ADDRESS_FOR_HOST, nothing)
    @test wait_for_pred(() -> setup_called[])
    @test setup_on_loop[]
    Sockets.host_resolver_shutdown!(resolver)
    EventLoops.event_loop_group_destroy!(elg)
end

@testset "client bootstrap staggered connection scheduling" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(elg)
    client_bootstrap = Sockets.ClientBootstrap(Sockets.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))
    el = EventLoops.event_loop_group_get_loop_at(elg, 0)
    @test el !== nothing
    event_loop = el isa EventLoops.EventLoop ? el : nothing
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    request = Sockets.SocketConnectionRequest{Nothing, Nothing, Sockets._SocketConnectionEventCallback, Nothing, Nothing}(
        client_bootstrap,
        "example.com",
        UInt32(443),
        client_bootstrap.socket_options,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        false,
        nothing,
        nothing,
        Sockets.HostResolutionConfig(;
            connection_attempt_delay_ns = 75_000_000,
            resolution_delay_ns = 25_000_000,
            first_address_family_count = 1,
        ),
        Sockets.HostAddress[],
        0,
        0,
        Sockets.ScheduledTask[],
        false,
    )

    addresses = [
        Sockets.HostAddress("::1", Sockets.HostAddressType.AAAA, "example.com", 0),
        Sockets.HostAddress("127.0.0.1", Sockets.HostAddressType.A, "example.com", 0),
    ]

    Sockets._start_connection_attempts(request, addresses, event_loop)
    @test length(request.connection_attempt_tasks) == 2

    first_task = request.connection_attempt_tasks[1]
    second_task = request.connection_attempt_tasks[2]
    @test first_task.timestamp != UInt64(0)
    @test second_task.timestamp > first_task.timestamp

    scheduled_attempts = copy(request.connection_attempt_tasks)
    Sockets._connection_request_complete(request, Sockets.AWS_OP_SUCCESS, nothing)
    @test isempty(request.connection_attempt_tasks)
    @test all(!task.scheduled for task in scheduled_attempts)

    request = Sockets.SocketConnectionRequest{Nothing, Nothing, Sockets._SocketConnectionEventCallback, Nothing, Nothing}(
        client_bootstrap,
        "example.com",
        UInt32(443),
        client_bootstrap.socket_options,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        false,
        nothing,
        nothing,
        Sockets.HostResolutionConfig(;
            connection_attempt_delay_ns = 30_000_000,
            resolution_delay_ns = 50_000_000,
            first_address_family_count = 1,
        ),
        Sockets.HostAddress[],
        0,
        0,
        Sockets.ScheduledTask[],
        false,
    )
    single_family_addresses = [
        Sockets.HostAddress("127.0.0.1", Sockets.HostAddressType.A, "example.com", 0),
        Sockets.HostAddress("192.0.2.10", Sockets.HostAddressType.A, "example.com", 0),
    ]
    Sockets._start_connection_attempts(request, single_family_addresses, event_loop)
    @test length(request.connection_attempt_tasks) == 2

    first_task = request.connection_attempt_tasks[1]
    second_task = request.connection_attempt_tasks[2]
    @test first_task.timestamp == UInt64(0)
    @test second_task.timestamp > first_task.timestamp
    single_family_attempts = copy(request.connection_attempt_tasks)

    Sockets._connection_request_complete(request, Sockets.AWS_OP_SUCCESS, nothing)
    @test isempty(request.connection_attempt_tasks)
    @test all(!task.scheduled for task in single_family_attempts)

    Sockets.host_resolver_shutdown!(resolver)
    EventLoops.event_loop_group_destroy!(elg)
end

if tls_tests_enabled()
@testset "bootstrap tls negotiation" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(elg)

    cert_path = joinpath(dirname(@__DIR__), "aws-c-io", "tests", "resources", "unittests.crt")
    key_path = joinpath(dirname(@__DIR__), "aws-c-io", "tests", "resources", "unittests.key")
    server_opts = Sockets.tls_ctx_options_init_default_server_from_path(cert_path, key_path)
    maybe_apply_test_keychain!(server_opts)
    @test server_opts isa Sockets.TlsContextOptions
    server_ctx = server_opts isa Sockets.TlsContextOptions ? Sockets.tls_context_new(server_opts) : server_opts
    @test server_ctx isa Sockets.TlsContext
    client_ctx = Sockets.tls_context_new_client(; verify_peer = false)
    @test client_ctx isa Sockets.TlsContext

    server_negotiated = Ref(false)
    client_negotiated = Ref(false)
    server_setup = Ref(false)
    client_setup = Ref(false)
    server_channel = Ref{Any}(nothing)
    client_channel = Ref{Any}(nothing)

    server_tls_opts = Sockets.TlsConnectionOptions(
        server_ctx;
        on_negotiation_result = (handler, slot, err) -> begin
            server_negotiated[] = true
            return nothing
        end,
    )

    cfg = _bootstrap_test_config()

    server_bootstrap = Sockets.ServerBootstrap(Sockets.ServerBootstrapOptions(
        event_loop_group = elg,
        socket_options = cfg.sock_opts,
        host = cfg.host,
        port = 0,
        tls_connection_options = server_tls_opts,
        on_incoming_channel_setup = (bs, err, channel, ud) -> begin
            server_setup[] = err == Reseau.AWS_OP_SUCCESS
            server_channel[] = channel
            return nothing
        end,
    ))

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    if cfg.use_port
        bound = Sockets.socket_get_bound_address(listener)
        @test bound isa Sockets.SocketEndpoint
        port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
        @test port != 0
    else
        port = 0
    end

    client_tls_opts = Sockets.TlsConnectionOptions(
        client_ctx;
        server_name = "localhost",
        on_negotiation_result = (handler, slot, err) -> begin
            client_negotiated[] = true
            return nothing
        end,
    )

    client_bootstrap = Sockets.ClientBootstrap(Sockets.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    @test Sockets.client_bootstrap_connect!(
        client_bootstrap,
        cfg.host,
        port;
        socket_options = cfg.sock_opts,
        host_resolution_config = cfg.resolution_config,
        tls_connection_options = client_tls_opts,
        on_setup = (bs, err, channel, ud) -> begin
            client_setup[] = err == Reseau.AWS_OP_SUCCESS
            client_channel[] = channel
            return nothing
        end,
    ) === nothing

    @test wait_for_pred(() -> server_setup[])
    @test wait_for_pred(() -> client_setup[])
    @test wait_for_pred(() -> server_negotiated[])
    @test wait_for_pred(() -> client_negotiated[])

    if client_channel[] !== nothing
        Sockets.pipeline_shutdown!(client_channel[], 0)
    end
    if server_channel[] !== nothing
        Sockets.pipeline_shutdown!(server_channel[], 0)
    end

    Sockets.server_bootstrap_shutdown!(server_bootstrap)
    Sockets.host_resolver_shutdown!(resolver)
    EventLoops.event_loop_group_destroy!(elg)
end
else
    @info "Skipping bootstrap TLS negotiation (set RESEAU_RUN_TLS_TESTS=1 to enable)"
end

@testset "server bootstrap destroy callback waits for channels" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(elg)
    cfg = _bootstrap_test_config()

    destroy_called = Ref(false)
    server_setup = Ref(false)
    server_shutdown = Ref(false)
    server_channels = Any[]
    client_channel = Ref{Any}(nothing)

    server_bootstrap = Sockets.ServerBootstrap(Sockets.ServerBootstrapOptions(
        event_loop_group = elg,
        socket_options = cfg.sock_opts,
        host = cfg.host,
        port = 0,
        on_incoming_channel_setup = (bs, err, channel, ud) -> begin
            server_setup[] = err == Reseau.AWS_OP_SUCCESS
            if channel !== nothing
                push!(server_channels, channel)
                if @atomic bs.shutdown
                    Sockets.pipeline_shutdown!(channel, 0)
                end
            end
            return nothing
        end,
        on_incoming_channel_shutdown = (bs, err, channel, ud) -> begin
            server_shutdown[] = true
            return nothing
        end,
        on_listener_destroy = (bs, ud) -> begin
            destroy_called[] = true
            return nothing
        end,
    ))

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    if cfg.use_port
        bound = Sockets.socket_get_bound_address(listener)
        @test bound isa Sockets.SocketEndpoint
        port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
        @test port != 0
    else
        port = 0
    end

    client_bootstrap = Sockets.ClientBootstrap(Sockets.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    @test Sockets.client_bootstrap_connect!(
        client_bootstrap,
        cfg.host,
        port;
        socket_options = cfg.sock_opts,
        host_resolution_config = cfg.resolution_config,
        on_setup = (bs, err, channel, ud) -> begin
            if err == Reseau.AWS_OP_SUCCESS
                client_channel[] = channel
            end
            return nothing
        end,
    ) === nothing

    @test wait_for_pred(() -> server_setup[])

    Sockets.server_bootstrap_shutdown!(server_bootstrap)
    sleep(0.05)
    @test !destroy_called[]

    for channel in server_channels
        Sockets.pipeline_shutdown!(channel, 0)
    end
    if client_channel[] !== nothing
        Sockets.pipeline_shutdown!(client_channel[], 0)
    end

    @test wait_for_pred(() -> server_shutdown[])
    @test wait_for_pred(() -> destroy_called[])

    Sockets.host_resolver_shutdown!(resolver)
    EventLoops.event_loop_group_destroy!(elg)
end

@testset "server bootstrap destroy callback without channels" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(elg)
    cfg = _bootstrap_test_config()

    destroy_called = Ref(false)
    server_bootstrap = Sockets.ServerBootstrap(Sockets.ServerBootstrapOptions(
        event_loop_group = elg,
        socket_options = cfg.sock_opts,
        host = cfg.host,
        port = 0,
        on_listener_destroy = (bs, ud) -> begin
            destroy_called[] = true
            return nothing
        end,
    ))

    Sockets.server_bootstrap_shutdown!(server_bootstrap)
    @test wait_for_pred(() -> destroy_called[])

    Sockets.host_resolver_shutdown!(resolver)
    EventLoops.event_loop_group_destroy!(elg)
end
