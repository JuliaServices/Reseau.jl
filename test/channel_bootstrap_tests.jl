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

    server_bootstrap = AwsIO.ServerBootstrap(AwsIO.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        on_incoming_channel_setup = (bs, err, channel, ud) -> begin
            server_setup_called[] = true
            server_setup_error[] = err
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
    @test setup_channel[].read_back_pressure_enabled

    @test wait_for_pred(() -> server_setup_called[])
    @test server_setup_error[] == AwsIO.AWS_OP_SUCCESS

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
