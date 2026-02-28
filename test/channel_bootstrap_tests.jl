using Test
using Reseau

# On macOS, IPV4 maps to NW sockets which do not expose the resolved port
# synchronously. Use LOCAL sockets for bootstrap tests that need bound-address
# inspection.
function _bootstrap_test_config()
    @static if Sys.isapple()
        endpoint = Sockets.SocketEndpoint()
        Sockets.socket_endpoint_init_local_address_for_test!(endpoint)
        host = Sockets.get_address(endpoint)
        sock_opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.LOCAL)
        res_config = Sockets.HostResolutionConfig(resolve_host_as_address = true)
        return (; host, sock_opts, use_port = false, resolution_config = res_config)
    else
        return (; host = "127.0.0.1", sock_opts = Sockets.SocketOptions(), use_port = true, resolution_config = nothing)
    end
end

function wait_for_pred(pred::Function; timeout_s::Float64 = 5.0)
    start = Base.time_ns()
    timeout_ns = Int(timeout_s * 1_000_000_000)
    while (Base.time_ns() - start) < timeout_ns
        pred() && return true
        sleep(0.01)
    end
    return false
end

function _listener_port(listener, cfg)::Int
    if cfg.use_port
        bound = Sockets.socket_get_bound_address(listener)
        @test bound isa Sockets.SocketEndpoint
        port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
        @test port != 0
        return port
    end
    return 0
end

@testset "client/server bootstrap callbacks" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver()
    cfg = _bootstrap_test_config()

    server_setup_called = Ref(false)
    server_setup_error = Ref{Int}(-1)
    server_channel = Ref{Any}(nothing)
    server_setup_has_pool = Ref(false)

    server_bootstrap = Sockets.ServerBootstrap(;
        event_loop_group = elg,
        socket_options = cfg.sock_opts,
        host = cfg.host,
        port = 0,
        on_incoming_channel_setup = (err, channel) -> begin
            server_setup_called[] = true
            server_setup_error[] = err
            server_channel[] = channel
            server_setup_has_pool[] = channel !== nothing && channel.message_pool !== nothing
            return nothing
        end,
    )

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    port = _listener_port(listener, cfg)

    client_setup_called = Ref(false)
    client_setup_error = Ref{Int}(-1)
    client_setup_channel = Ref{Any}(nothing)

    channel = Sockets.client_bootstrap_connect!(
        (err, ch) -> begin
            client_setup_called[] = true
            client_setup_error[] = err
            client_setup_channel[] = ch
            return nothing
        end,
        cfg.host,
        port;
        socket_options = cfg.sock_opts,
        enable_read_back_pressure = true,
        host_resolution_config = cfg.resolution_config,
        event_loop_group = elg,
        host_resolver = resolver,
    )

    @test client_setup_called[]
    @test client_setup_error[] == Reseau.OP_SUCCESS
    @test client_setup_channel[] === channel
    @test channel.message_pool !== nothing
    @test channel.read_back_pressure_enabled

    @test wait_for_pred(() -> server_setup_called[])
    @test server_setup_error[] == Reseau.OP_SUCCESS
    @test server_setup_has_pool[]

    Sockets.channel_shutdown!(channel, 0)
    if server_channel[] !== nothing
        Sockets.channel_shutdown!(server_channel[], 0)
    end

    Sockets.server_bootstrap_shutdown!(server_bootstrap)
    Sockets.close(resolver)
    close(elg)
end

@testset "client bootstrap attempt scheduling helpers" begin
    cfg = Sockets.HostResolutionConfig(;
        connection_attempt_delay_ns = 75_000_000,
        resolution_delay_ns = 25_000_000,
        first_address_family_count = 1,
    )
    base = UInt64(1_000_000_000)
    mixed_addresses = [
        Sockets.HostAddress("::1", Sockets.HostAddressType.AAAA, "example.com", 0),
        Sockets.HostAddress("127.0.0.1", Sockets.HostAddressType.A, "example.com", 0),
    ]
    @test Sockets._connection_request_has_both_families(mixed_addresses)
    @test Sockets._attempt_schedule_run_at(cfg, true, base, 0) == base + cfg.resolution_delay_ns
    @test Sockets._attempt_schedule_run_at(cfg, true, base, 1) == base + (2 * cfg.connection_attempt_delay_ns)

    single_family_addresses = [
        Sockets.HostAddress("127.0.0.1", Sockets.HostAddressType.A, "example.com", 0),
        Sockets.HostAddress("192.0.2.10", Sockets.HostAddressType.A, "example.com", 0),
    ]
    @test !Sockets._connection_request_has_both_families(single_family_addresses)
    @test Sockets._attempt_schedule_run_at(cfg, false, base, 0) == UInt64(0)
    @test Sockets._attempt_schedule_run_at(cfg, false, base, 1) == base + cfg.connection_attempt_delay_ns
end

@testset "client bootstrap requested event loop mismatch" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver()
    cfg = _bootstrap_test_config()

    bad_loop = EventLoops.EventLoop()
    @test_throws Reseau.ReseauError Sockets.client_bootstrap_connect!(
        (_err, _channel) -> nothing,
        cfg.host,
        cfg.use_port ? 80 : 0;
        socket_options = cfg.sock_opts,
        requested_event_loop = bad_loop,
        host_resolution_config = cfg.resolution_config,
        event_loop_group = elg,
        host_resolver = resolver,
    )
    close(bad_loop)

    Sockets.close(resolver)
    close(elg)
end

if tls_tests_enabled()
    @testset "bootstrap tls negotiation" begin
        cert_path = test_resource_path("unittests.crt")
        key_path = test_resource_path("unittests.key")
        if !(isfile(cert_path) && isfile(key_path))
            @info "Skipping bootstrap tls negotiation (set up test certificate resources to enable)."
            @test true
            return
        end

        elg = EventLoops.EventLoopGroup(; loop_count = 1)
        resolver = Sockets.HostResolver()

        server_opts = Sockets.tls_ctx_options_init_default_server_from_path(cert_path, key_path)
        maybe_apply_test_keychain!(server_opts)
        @test server_opts isa Sockets.TlsContextOptions
        server_ctx = server_opts isa Sockets.TlsContextOptions ? Sockets.tls_context_new(server_opts) : server_opts
        @test server_ctx isa Sockets.TlsContext
        client_ctx = Sockets.tls_context_new_client(; verify_peer = false)
        @test client_ctx isa Sockets.TlsContext

        server_setup = Ref(false)
        client_setup = Ref(false)
        server_channel = Ref{Any}(nothing)
        client_channel = Ref{Any}(nothing)

        server_tls_opts = Sockets.TlsConnectionOptions(server_ctx)

        cfg = _bootstrap_test_config()

        server_bootstrap = Sockets.ServerBootstrap(;
            event_loop_group = elg,
            socket_options = cfg.sock_opts,
            host = cfg.host,
            port = 0,
            tls_connection_options = server_tls_opts,
            on_incoming_channel_setup = (err, channel) -> begin
                server_setup[] = err == Reseau.OP_SUCCESS
                server_channel[] = channel
                return nothing
            end,
        )

        listener = server_bootstrap.listener_socket
        @test listener !== nothing
        port = _listener_port(listener, cfg)

        client_tls_opts = Sockets.TlsConnectionOptions(
            client_ctx;
            server_name = "localhost",
        )

        connect_attempts = Sys.iswindows() ? 3 : 1
        for attempt in 1:connect_attempts
            try
                client_channel[] = Sockets.client_bootstrap_connect!(
                    (err, channel) -> begin
                        client_setup[] = err == Reseau.OP_SUCCESS
                        client_channel[] = channel
                        return nothing
                    end,
                    cfg.host,
                    port;
                    socket_options = cfg.sock_opts,
                    tls_connection_options = client_tls_opts,
                    host_resolution_config = cfg.resolution_config,
                    event_loop_group = elg,
                    host_resolver = resolver,
                )
                break
            catch e
                if e isa Reseau.ReseauError &&
                        e.code == Reseau.ERROR_IO_SOCKET_NOT_CONNECTED &&
                        attempt < connect_attempts
                    @info "Retrying bootstrap TLS connect after transient socket-not-connected error." attempt
                    sleep(0.05 * attempt)
                    continue
                end
                rethrow()
            end
        end

        @test wait_for_pred(() -> server_setup[])
        @test wait_for_pred(() -> client_setup[])
        @test wait(server_tls_opts.tls_negotiation_result) == Reseau.OP_SUCCESS
        @test wait(client_tls_opts.tls_negotiation_result) == Reseau.OP_SUCCESS

        if client_channel[] !== nothing
            Sockets.channel_shutdown!(client_channel[], 0)
        end
        if server_channel[] !== nothing
            Sockets.channel_shutdown!(server_channel[], 0)
        end

        Sockets.server_bootstrap_shutdown!(server_bootstrap)
        Sockets.close(resolver)
        close(elg)
    end
else
    @info "Skipping bootstrap TLS negotiation (set RESEAU_RUN_TLS_TESTS=1 to enable)"
end

@testset "server bootstrap destroy callback waits for channels" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver()
    cfg = _bootstrap_test_config()

    destroy_called = Ref(false)
    server_setup = Ref(false)
    server_shutdown = Ref(false)
    server_channels = []
    client_channel = Ref{Any}(nothing)

    server_bootstrap = Sockets.ServerBootstrap(;
        event_loop_group = elg,
        socket_options = cfg.sock_opts,
        host = cfg.host,
        port = 0,
        on_incoming_channel_setup = (err, channel) -> begin
            server_setup[] = err == Reseau.OP_SUCCESS
            channel !== nothing && push!(server_channels, channel)
            return nothing
        end,
        on_incoming_channel_shutdown = (_err, _channel) -> begin
            server_shutdown[] = true
            return nothing
        end,
        on_listener_destroy = (_err) -> begin
            destroy_called[] = true
            return nothing
        end,
    )

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    port = _listener_port(listener, cfg)

    client_channel[] = Sockets.client_bootstrap_connect!(
        (_err, _channel) -> nothing,
        cfg.host,
        port;
        socket_options = cfg.sock_opts,
        host_resolution_config = cfg.resolution_config,
        event_loop_group = elg,
        host_resolver = resolver,
    )

    @test wait_for_pred(() -> server_setup[])

    Sockets.server_bootstrap_shutdown!(server_bootstrap)
    sleep(0.05)
    @test !destroy_called[]

    for channel in server_channels
        Sockets.channel_shutdown!(channel, 0)
    end
    if client_channel[] !== nothing
        Sockets.channel_shutdown!(client_channel[], 0)
    end

    @test wait_for_pred(() -> server_shutdown[])
    @test wait_for_pred(() -> destroy_called[])

    Sockets.close(resolver)
    close(elg)
end

@testset "server bootstrap destroy callback without channels" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver()
    cfg = _bootstrap_test_config()

    destroy_called = Ref(false)
    server_bootstrap = Sockets.ServerBootstrap(;
        event_loop_group = elg,
        socket_options = cfg.sock_opts,
        host = cfg.host,
        port = 0,
        on_listener_destroy = (_err) -> begin
            destroy_called[] = true
            return nothing
        end,
    )

    Sockets.server_bootstrap_shutdown!(server_bootstrap)
    @test wait_for_pred(() -> destroy_called[])

    Sockets.close(resolver)
    close(elg)
end
