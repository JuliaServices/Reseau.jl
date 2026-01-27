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

@testset "host resolver cached results" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    resolve_calls = Ref(0)
    impl = (host, data) -> begin
        resolve_calls[] += 1
        return [AwsIO.HostAddress("127.0.0.1", AwsIO.HostAddressType.A, host, 0)]
    end

    config = AwsIO.HostResolutionConfig(
        impl = impl,
        max_ttl_secs = 5,
        resolve_frequency_ns = 5_000_000_000,
    )

    resolved = Ref(false)
    addrs = Ref{Vector{AwsIO.HostAddress}}(AwsIO.HostAddress[])
    cb = (res, host, error_code, addresses) -> begin
        addrs[] = addresses
        resolved[] = true
        return nothing
    end

    @test AwsIO.host_resolver_resolve!(resolver, "example.com", cb; resolution_config = config) === nothing
    @test wait_for_pred(() -> resolved[])
    @test resolve_calls[] == 1
    @test !isempty(addrs[])

    resolved[] = false
    @test AwsIO.host_resolver_resolve!(resolver, "example.com", cb; resolution_config = config) === nothing
    @test wait_for_pred(() -> resolved[])
    @test resolve_calls[] == 1

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "host resolver purge and count" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    resolved = Ref(false)
    addrs = Ref{Vector{AwsIO.HostAddress}}(AwsIO.HostAddress[])

    impl = (host, data) -> begin
        return [AwsIO.HostAddress("127.0.0.1", AwsIO.HostAddressType.A, host, 0)]
    end

    config = AwsIO.HostResolutionConfig(
        impl = impl,
        max_ttl_secs = 5,
        resolve_frequency_ns = 5_000_000_000,
    )

    cb = (res, host, error_code, addresses) -> begin
        addrs[] = addresses
        resolved[] = true
        return nothing
    end

    @test AwsIO.host_resolver_resolve!(resolver, "example.com", cb; resolution_config = config) === nothing
    @test wait_for_pred(() -> resolved[])
    @test !isempty(addrs[])

    count_a = AwsIO.host_resolver_get_host_address_count(
        resolver,
        "example.com";
        flags = AwsIO.GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A,
    )
    @test count_a >= 1

    purge_host_done = Ref(false)
    @test AwsIO.host_resolver_purge_host_cache!(
        resolver,
        "example.com";
        on_host_purge_complete = _ -> (purge_host_done[] = true),
    ) === nothing
    @test wait_for_pred(() -> purge_host_done[])
    @test AwsIO.host_resolver_get_host_address_count(
        resolver,
        "example.com";
        flags = AwsIO.GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A,
    ) == 0

    purge_done = Ref(false)
    @test AwsIO.host_resolver_purge_cache_with_callback!(
        resolver,
        _ -> (purge_done[] = true),
    ) === nothing
    @test wait_for_pred(() -> purge_done[])

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "host resolver record failure moves address" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    resolved = Ref(false)
    addrs = Ref{Vector{AwsIO.HostAddress}}(AwsIO.HostAddress[])

    impl = (host, data) -> begin
        return [AwsIO.HostAddress("127.0.0.1", AwsIO.HostAddressType.A, host, 0)]
    end

    config = AwsIO.HostResolutionConfig(
        impl = impl,
        max_ttl_secs = 5,
        resolve_frequency_ns = 5_000_000_000,
    )

    cb = (res, host, error_code, addresses) -> begin
        addrs[] = addresses
        resolved[] = true
        return nothing
    end

    @test AwsIO.host_resolver_resolve!(resolver, "example.com", cb; resolution_config = config) === nothing
    @test wait_for_pred(() -> resolved[])
    @test !isempty(addrs[])

    addr = addrs[][1]
    AwsIO.host_resolver_record_connection_failure!(resolver, addr)
    count_a = AwsIO.host_resolver_get_host_address_count(
        resolver,
        "example.com";
        flags = AwsIO.GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A,
    )
    @test count_a == 0

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end
