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

@testset "host resolver cache and ttl" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    cfg = AwsIO.HostResolverConfig(;
        max_ttl_secs = 1,
        min_ttl_secs = 1,
        resolve_frequency_ns = 1_000_000_000,
        background_refresh = false,
    )
    resolver = AwsIO.DefaultHostResolver(elg, cfg)

    resolved = Ref(false)
    err = Ref{Int}(0)
    addrs = Ref{Vector{AwsIO.HostAddress}}(AwsIO.HostAddress[])

    cb = (res, host, error_code, addresses) -> begin
        err[] = error_code
        addrs[] = addresses
        resolved[] = true
        return nothing
    end

    @test AwsIO.host_resolver_resolve!(resolver, "localhost", cb) === nothing
    @test wait_for_pred(() -> resolved[])
    @test err[] == AwsIO.AWS_OP_SUCCESS
    @test !isempty(addrs[])

    entry = AwsIO.hash_table_get(resolver.cache, "localhost")
    @test entry !== nothing
    first_resolved = entry.resolved_time

    resolved[] = false
    err[] = 0
    @test AwsIO.host_resolver_resolve!(resolver, "localhost", cb) === nothing
    @test wait_for_pred(() -> resolved[])
    @test err[] == AwsIO.AWS_OP_SUCCESS
    entry_cached = AwsIO.hash_table_get(resolver.cache, "localhost")
    @test entry_cached.resolved_time == first_resolved

    sleep(1.2)
    resolved[] = false
    @test AwsIO.host_resolver_resolve!(resolver, "localhost", cb) === nothing
    @test wait_for_pred(() -> resolved[])
    entry_refreshed = AwsIO.hash_table_get(resolver.cache, "localhost")
    @test entry_refreshed.resolved_time >= first_resolved

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "host resolver background refresh" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    cfg = AwsIO.HostResolverConfig(;
        max_ttl_secs = 5,
        min_ttl_secs = 1,
        resolve_frequency_ns = 10_000_000,
        background_refresh = true,
    )
    resolver = AwsIO.DefaultHostResolver(elg, cfg)

    resolved = Ref(false)
    err = Ref{Int}(0)

    cb = (res, host, error_code, addresses) -> begin
        err[] = error_code
        resolved[] = true
        return nothing
    end

    @test AwsIO.host_resolver_resolve!(resolver, "localhost", cb) === nothing
    @test wait_for_pred(() -> resolved[])
    @test err[] == AwsIO.AWS_OP_SUCCESS
    entry = AwsIO.hash_table_get(resolver.cache, "localhost")
    @test entry !== nothing
    first_resolved = entry.resolved_time

    sleep(0.05)
    resolved[] = false
    err[] = 0
    @test AwsIO.host_resolver_resolve!(resolver, "localhost", cb) === nothing
    @test wait_for_pred(() -> resolved[])
    @test err[] == AwsIO.AWS_OP_SUCCESS
    @test wait_for_pred(
        () -> begin
            entry = AwsIO.hash_table_get(resolver.cache, "localhost")
            entry !== nothing && entry.resolved_time > first_resolved
        end
    )

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end
