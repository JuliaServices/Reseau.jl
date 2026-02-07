using Test
using Reseau

# On macOS, IPV4 → NW sockets which don't expose resolved port synchronously.
# Use LOCAL domain (POSIX sockets) for bootstrap tests that need socket_get_bound_address.
function _bootstrap_test_config()
    @static if Sys.isapple()
        endpoint = Reseau.SocketEndpoint()
        Reseau.socket_endpoint_init_local_address_for_test!(endpoint)
        host = Reseau.get_address(endpoint)
        sock_opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.LOCAL)
        # Custom resolver that returns the local path as an address (DNS doesn't apply to LOCAL domain)
        resolve_fn = (h, impl_data) -> begin
            _ = impl_data
            return [Reseau.HostAddress(host, Reseau.HostAddressType.A, h, UInt64(0))]
        end
        res_config = Reseau.HostResolutionConfig(impl = resolve_fn)
        return (; host, sock_opts, use_port = false, resolution_config = res_config)
    else
        return (; host = "127.0.0.1", sock_opts = Reseau.SocketOptions(), use_port = true, resolution_config = nothing)
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
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.DefaultHostResolver(elg)

    server_setup_called = Ref(false)
    server_setup_error = Ref{Int}(-1)
    server_channel = Ref{Any}(nothing)
    server_setup_has_pool = Ref(false)

    cfg = _bootstrap_test_config()

    server_bootstrap = Reseau.ServerBootstrap(Reseau.ServerBootstrapOptions(
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
        bound = Reseau.socket_get_bound_address(listener)
        @test bound isa Reseau.SocketEndpoint
        port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
        @test port != 0
    else
        port = 0
    end

    client_bootstrap = Reseau.ClientBootstrap(Reseau.ClientBootstrapOptions(
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

    res = Reseau.client_bootstrap_connect!(
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
        Reseau.channel_shutdown!(setup_channel[], 0)
        @test wait_for_pred(() -> shutdown_called[])
    end

    if server_channel[] !== nothing
        Reseau.channel_shutdown!(server_channel[], 0)
    end

    Reseau.server_bootstrap_shutdown!(server_bootstrap)
    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "client bootstrap attempts multiple resolved addresses" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.DefaultHostResolver(elg)
    cfg = _bootstrap_test_config()

    server_setup_called = Ref(false)
    server_channel = Ref{Any}(nothing)

    server_bootstrap = Reseau.ServerBootstrap(Reseau.ServerBootstrapOptions(
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
        bound = Reseau.socket_get_bound_address(listener)
        @test bound isa Reseau.SocketEndpoint
        port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
        @test port != 0
    else
        port = 0
    end

    client_bootstrap = Reseau.ClientBootstrap(Reseau.ClientBootstrapOptions(
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
                Reseau.HostAddress(cfg.host, Reseau.HostAddressType.A, host, UInt64(0)),
            ]
        end
    else
        resolve_impl = (host, impl_data) -> begin
            _ = impl_data
            return [
                Reseau.HostAddress("::1", Reseau.HostAddressType.AAAA, host, UInt64(0)),
                Reseau.HostAddress("127.0.0.1", Reseau.HostAddressType.A, host, UInt64(0)),
            ]
        end
    end
    resolution_config = Reseau.HostResolutionConfig(impl = resolve_impl)

    res = Reseau.client_bootstrap_connect!(
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
        Reseau.channel_shutdown!(setup_channel[], 0)
        @test wait_for_pred(() -> shutdown_called[])
    end

    if server_channel[] !== nothing
        Reseau.channel_shutdown!(server_channel[], 0)
    end

    Reseau.server_bootstrap_shutdown!(server_bootstrap)
    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "client bootstrap requested event loop mismatch" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.DefaultHostResolver(elg)
    client_bootstrap = Reseau.ClientBootstrap(Reseau.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    bad_loop = Reseau.event_loop_new(Reseau.EventLoopOptions())
    if bad_loop isa Reseau.ErrorResult
        @test true
    else
        res = Reseau.client_bootstrap_connect!(
            client_bootstrap,
            "localhost",
            80;
            requested_event_loop = bad_loop,
        )
        @test res isa Reseau.ErrorResult
        res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_PINNED_EVENT_LOOP_MISMATCH
        Reseau.event_loop_destroy!(bad_loop)
    end

    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "client bootstrap on_setup runs on requested event loop" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.DefaultHostResolver(elg)
    client_bootstrap = Reseau.ClientBootstrap(Reseau.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))
    requested_loop = Reseau.event_loop_group_get_loop_at(elg, 0)
    @test requested_loop !== nothing
    setup_called = Ref(false)
    setup_on_loop = Ref(false)
    request = Reseau.SocketConnectionRequest(
        client_bootstrap,
        "example.com",
        UInt32(443),
        client_bootstrap.socket_options,
        nothing,
        nothing,
        nothing,
        nothing,
        nothing,
        (bs, err, channel, ud) -> begin
            setup_called[] = true
            setup_on_loop[] = Reseau.event_loop_thread_is_callers_thread(requested_loop)
            return nothing
        end,
        nothing,
        nothing,
        false,
        requested_loop,
        nothing,
        Reseau.HostAddress[],
        0,
        0,
        false,
    )
    Reseau._connection_request_complete(request, Reseau.ERROR_IO_DNS_NO_ADDRESS_FOR_HOST, nothing)
    @test wait_for_pred(() -> setup_called[])
    @test setup_on_loop[]
    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

if tls_tests_enabled()
@testset "bootstrap tls negotiation" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.DefaultHostResolver(elg)

    cert_path = joinpath(dirname(@__DIR__), "aws-c-io", "tests", "resources", "unittests.crt")
    key_path = joinpath(dirname(@__DIR__), "aws-c-io", "tests", "resources", "unittests.key")
    server_opts = Reseau.tls_ctx_options_init_default_server_from_path(cert_path, key_path)
    maybe_apply_test_keychain!(server_opts)
    @test server_opts isa Reseau.TlsContextOptions
    server_ctx = server_opts isa Reseau.TlsContextOptions ? Reseau.tls_context_new(server_opts) : server_opts
    @test server_ctx isa Reseau.TlsContext
    client_ctx = Reseau.tls_context_new_client(; verify_peer = false)
    @test client_ctx isa Reseau.TlsContext

    server_negotiated = Ref(false)
    client_negotiated = Ref(false)
    server_setup = Ref(false)
    client_setup = Ref(false)
    server_channel = Ref{Any}(nothing)
    client_channel = Ref{Any}(nothing)

    server_tls_opts = Reseau.TlsConnectionOptions(
        server_ctx;
        on_negotiation_result = (handler, slot, err, ud) -> begin
            server_negotiated[] = true
            return nothing
        end,
    )

    cfg = _bootstrap_test_config()

    server_bootstrap = Reseau.ServerBootstrap(Reseau.ServerBootstrapOptions(
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
        bound = Reseau.socket_get_bound_address(listener)
        @test bound isa Reseau.SocketEndpoint
        port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
        @test port != 0
    else
        port = 0
    end

    client_tls_opts = Reseau.TlsConnectionOptions(
        client_ctx;
        server_name = "localhost",
        on_negotiation_result = (handler, slot, err, ud) -> begin
            client_negotiated[] = true
            return nothing
        end,
    )

    client_bootstrap = Reseau.ClientBootstrap(Reseau.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    @test Reseau.client_bootstrap_connect!(
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
        Reseau.channel_shutdown!(client_channel[], 0)
    end
    if server_channel[] !== nothing
        Reseau.channel_shutdown!(server_channel[], 0)
    end

    Reseau.server_bootstrap_shutdown!(server_bootstrap)
    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end
else
    @info "Skipping bootstrap TLS negotiation (set RESEAU_RUN_TLS_TESTS=1 to enable)"
end

@testset "server bootstrap destroy callback waits for channels" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.DefaultHostResolver(elg)
    cfg = _bootstrap_test_config()

    destroy_called = Ref(false)
    server_setup = Ref(false)
    server_shutdown = Ref(false)
    server_channels = Any[]
    client_channel = Ref{Any}(nothing)

    server_bootstrap = Reseau.ServerBootstrap(Reseau.ServerBootstrapOptions(
        event_loop_group = elg,
        socket_options = cfg.sock_opts,
        host = cfg.host,
        port = 0,
        on_incoming_channel_setup = (bs, err, channel, ud) -> begin
            server_setup[] = err == Reseau.AWS_OP_SUCCESS
            if channel !== nothing
                push!(server_channels, channel)
                if @atomic bs.shutdown
                    Reseau.channel_shutdown!(channel, 0)
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
        bound = Reseau.socket_get_bound_address(listener)
        @test bound isa Reseau.SocketEndpoint
        port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
        @test port != 0
    else
        port = 0
    end

    client_bootstrap = Reseau.ClientBootstrap(Reseau.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    @test Reseau.client_bootstrap_connect!(
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

    Reseau.server_bootstrap_shutdown!(server_bootstrap)
    sleep(0.05)
    @test !destroy_called[]

    for channel in server_channels
        Reseau.channel_shutdown!(channel, 0)
    end
    if client_channel[] !== nothing
        Reseau.channel_shutdown!(client_channel[], 0)
    end

    @test wait_for_pred(() -> server_shutdown[])
    @test wait_for_pred(() -> destroy_called[])

    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "server bootstrap destroy callback without channels" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.DefaultHostResolver(elg)
    cfg = _bootstrap_test_config()

    destroy_called = Ref(false)
    server_bootstrap = Reseau.ServerBootstrap(Reseau.ServerBootstrapOptions(
        event_loop_group = elg,
        socket_options = cfg.sock_opts,
        host = cfg.host,
        port = 0,
        on_listener_destroy = (bs, ud) -> begin
            destroy_called[] = true
            return nothing
        end,
    ))

    Reseau.server_bootstrap_shutdown!(server_bootstrap)
    @test wait_for_pred(() -> destroy_called[])

    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end
