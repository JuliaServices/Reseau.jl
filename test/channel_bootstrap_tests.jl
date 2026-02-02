using Test
using AwsIO

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
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    server_setup_called = Ref(false)
    server_setup_error = Ref{Int}(-1)
    server_channel = Ref{Any}(nothing)
    server_setup_has_pool = Ref(false)

    server_bootstrap = AwsIO.ServerBootstrap(AwsIO.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
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
    bound = AwsIO.socket_get_bound_address(listener)
    @test bound isa AwsIO.SocketEndpoint
    port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_bootstrap = AwsIO.ClientBootstrap(AwsIO.ClientBootstrapOptions(
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

    res = AwsIO.client_bootstrap_connect!(
        client_bootstrap,
        "127.0.0.1",
        port;
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
    @test creation_error[] == AwsIO.AWS_OP_SUCCESS
    @test setup_error[] == AwsIO.AWS_OP_SUCCESS
    @test setup_order[] > creation_order[]
    @test creation_backpressure[]
    @test setup_channel[] !== nothing
    @test setup_has_pool[]
    @test setup_channel[].read_back_pressure_enabled

    @test wait_for_pred(() -> server_setup_called[])
    @test server_setup_error[] == AwsIO.AWS_OP_SUCCESS
    @test server_setup_has_pool[]

    if setup_channel[] !== nothing
        AwsIO.channel_shutdown!(setup_channel[], 0)
        @test wait_for_pred(() -> shutdown_called[])
    end

    if server_channel[] !== nothing
        AwsIO.channel_shutdown!(server_channel[], 0)
    end

    AwsIO.server_bootstrap_shutdown!(server_bootstrap)
    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "client bootstrap requested event loop mismatch" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)
    client_bootstrap = AwsIO.ClientBootstrap(AwsIO.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    bad_loop = AwsIO.event_loop_new(AwsIO.EventLoopOptions(; type = AwsIO.event_loop_get_default_type()))
    if bad_loop isa AwsIO.ErrorResult
        @test true
    else
        res = AwsIO.client_bootstrap_connect!(
            client_bootstrap,
            "localhost",
            80;
            requested_event_loop = bad_loop,
        )
        @test res isa AwsIO.ErrorResult
        res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_PINNED_EVENT_LOOP_MISMATCH
        AwsIO.event_loop_destroy!(bad_loop)
    end

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "client bootstrap on_setup runs on requested event loop" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)
    client_bootstrap = AwsIO.ClientBootstrap(AwsIO.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))
    requested_loop = AwsIO.event_loop_group_get_loop_at(elg, 0)
    @test requested_loop !== nothing
    setup_called = Ref(false)
    setup_on_loop = Ref(false)
    request = AwsIO.SocketConnectionRequest(
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
            setup_on_loop[] = AwsIO.event_loop_thread_is_callers_thread(requested_loop)
            return nothing
        end,
        nothing,
        nothing,
        false,
        requested_loop,
    )
    AwsIO._connection_request_complete(request, AwsIO.ERROR_IO_DNS_NO_ADDRESS_FOR_HOST, nothing)
    @test wait_for_pred(() -> setup_called[])
    @test setup_on_loop[]
    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

if tls_tests_enabled()
@testset "bootstrap tls negotiation" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    cert_path = joinpath(dirname(@__DIR__), "aws-c-io", "tests", "resources", "unittests.crt")
    key_path = joinpath(dirname(@__DIR__), "aws-c-io", "tests", "resources", "unittests.key")
    server_opts = AwsIO.tls_ctx_options_init_default_server_from_path(cert_path, key_path)
    maybe_apply_test_keychain!(server_opts)
    @test server_opts isa AwsIO.TlsContextOptions
    server_ctx = server_opts isa AwsIO.TlsContextOptions ? AwsIO.tls_context_new(server_opts) : server_opts
    @test server_ctx isa AwsIO.TlsContext
    client_ctx = AwsIO.tls_context_new_client(; verify_peer = false)
    @test client_ctx isa AwsIO.TlsContext

    server_negotiated = Ref(false)
    client_negotiated = Ref(false)
    server_setup = Ref(false)
    client_setup = Ref(false)
    server_channel = Ref{Any}(nothing)
    client_channel = Ref{Any}(nothing)

    server_tls_opts = AwsIO.TlsConnectionOptions(
        server_ctx;
        on_negotiation_result = (handler, slot, err, ud) -> begin
            server_negotiated[] = true
            return nothing
        end,
    )

    server_bootstrap = AwsIO.ServerBootstrap(AwsIO.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        tls_connection_options = server_tls_opts,
        on_incoming_channel_setup = (bs, err, channel, ud) -> begin
            server_setup[] = err == AwsIO.AWS_OP_SUCCESS
            server_channel[] = channel
            return nothing
        end,
    ))

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    bound = AwsIO.socket_get_bound_address(listener)
    @test bound isa AwsIO.SocketEndpoint
    port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_tls_opts = AwsIO.TlsConnectionOptions(
        client_ctx;
        server_name = "localhost",
        on_negotiation_result = (handler, slot, err, ud) -> begin
            client_negotiated[] = true
            return nothing
        end,
    )

    client_bootstrap = AwsIO.ClientBootstrap(AwsIO.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    @test AwsIO.client_bootstrap_connect!(
        client_bootstrap,
        "127.0.0.1",
        port;
        tls_connection_options = client_tls_opts,
        on_setup = (bs, err, channel, ud) -> begin
            client_setup[] = err == AwsIO.AWS_OP_SUCCESS
            client_channel[] = channel
            return nothing
        end,
    ) === nothing

    @test wait_for_pred(() -> server_setup[])
    @test wait_for_pred(() -> client_setup[])
    @test wait_for_pred(() -> server_negotiated[])
    @test wait_for_pred(() -> client_negotiated[])

    if client_channel[] !== nothing
        AwsIO.channel_shutdown!(client_channel[], 0)
    end
    if server_channel[] !== nothing
        AwsIO.channel_shutdown!(server_channel[], 0)
    end

    AwsIO.server_bootstrap_shutdown!(server_bootstrap)
    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end
else
    @info "Skipping bootstrap TLS negotiation (set AWSIO_RUN_TLS_TESTS=1 to enable)"
end

@testset "server bootstrap destroy callback waits for channels" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    destroy_called = Ref(false)
    server_setup = Ref(false)
    server_shutdown = Ref(false)
    server_channel = Ref{Any}(nothing)
    client_channel = Ref{Any}(nothing)

    server_bootstrap = AwsIO.ServerBootstrap(AwsIO.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        on_incoming_channel_setup = (bs, err, channel, ud) -> begin
            server_setup[] = err == AwsIO.AWS_OP_SUCCESS
            server_channel[] = channel
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
    bound = AwsIO.socket_get_bound_address(listener)
    @test bound isa AwsIO.SocketEndpoint
    port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_bootstrap = AwsIO.ClientBootstrap(AwsIO.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    @test AwsIO.client_bootstrap_connect!(
        client_bootstrap,
        "127.0.0.1",
        port;
        on_setup = (bs, err, channel, ud) -> begin
            if err == AwsIO.AWS_OP_SUCCESS
                client_channel[] = channel
            end
            return nothing
        end,
    ) === nothing

    @test wait_for_pred(() -> server_setup[])

    AwsIO.server_bootstrap_shutdown!(server_bootstrap)
    sleep(0.05)
    @test !destroy_called[]

    if server_channel[] !== nothing
        AwsIO.channel_shutdown!(server_channel[], 0)
    end
    if client_channel[] !== nothing
        AwsIO.channel_shutdown!(client_channel[], 0)
    end

    @test wait_for_pred(() -> server_shutdown[])
    @test wait_for_pred(() -> destroy_called[])

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "server bootstrap destroy callback without channels" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    destroy_called = Ref(false)
    server_bootstrap = AwsIO.ServerBootstrap(AwsIO.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        on_listener_destroy = (bs, ud) -> begin
            destroy_called[] = true
            return nothing
        end,
    ))

    AwsIO.server_bootstrap_shutdown!(server_bootstrap)
    @test wait_for_pred(() -> destroy_called[])

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end
