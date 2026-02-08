using Test
using Reseau

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

mutable struct MockDnsResolver
    address_lists::Vector{Vector{Reseau.HostAddress}}
    index::Int
    max_resolves::Int
    resolve_count::Int
end

function MockDnsResolver(max_resolves::Integer)
    return MockDnsResolver(Vector{Vector{Reseau.HostAddress}}(), 1, Int(max_resolves), 0)
end

function mock_dns_append!(resolver::MockDnsResolver, addrs::Vector{Reseau.HostAddress})
    push!(resolver.address_lists, [copy(addr) for addr in addrs])
    return nothing
end

function mock_dns_resolve(host::AbstractString, resolver::MockDnsResolver)
    if resolver.resolve_count >= resolver.max_resolves
        return Reseau.HostAddress[], Reseau.ERROR_IO_DNS_QUERY_FAILED
    end
    isempty(resolver.address_lists) && return Reseau.HostAddress[], Reseau.ERROR_IO_DNS_QUERY_FAILED
    list = resolver.address_lists[resolver.index]
    resolver.index = resolver.index % length(resolver.address_lists) + 1
    resolver.resolve_count += 1
    isempty(list) && return Reseau.HostAddress[], Reseau.ERROR_IO_DNS_QUERY_FAILED
    return [copy(addr) for addr in list], Reseau.AWS_OP_SUCCESS
end

function find_address(addrs::Vector{Reseau.HostAddress}, addr_type::Reseau.HostAddressType.T)
    for addr in addrs
        if addr.address_type == addr_type
            return addr
        end
    end
    return nothing
end

function resolve_and_wait(resolver, host; config=nothing, timeout_s::Float64 = 5.0)
    invoked = Ref(false)
    err_ref = Ref{Int}(Reseau.AWS_OP_SUCCESS)
    addrs_ref = Ref{Vector{Reseau.HostAddress}}(Reseau.HostAddress[])
    cb = (res, host_name, err, addresses) -> begin
        err_ref[] = err
        addrs_ref[] = addresses
        invoked[] = true
        return nothing
    end
    result = Reseau.host_resolver_resolve!(resolver, host, cb; resolution_config = config)
    if result isa Reseau.ErrorResult
        return result.code, Reseau.HostAddress[]
    end
    ok = wait_for_pred(() -> invoked[]; timeout_s = timeout_s)
    return ok ? (err_ref[], addrs_ref[]) : :timeout
end

@testset "host resolver ipv6 address variations" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.HostResolver(elg)

    config = Reseau.HostResolutionConfig(max_ttl_secs = 10)

    cases = [
        ("0:0::1", "::1"),
        ("::1", "::1"),
        ("0:0:0:0:0:0:0:1", "::1"),
        ("fd00:ec2:0:0:0:0:0:23", "fd00:ec2::23"),
    ]

    for (input, expected) in cases
        result = resolve_and_wait(resolver, input; config = config)
        @test result !== :timeout
        @test !(result isa Reseau.ErrorResult)
        err, addrs = result
        @test err == Reseau.AWS_OP_SUCCESS
        addr6 = find_address(addrs, Reseau.HostAddressType.AAAA)
        @test addr6 !== nothing
        @test addr6.address == expected
    end

    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "host resolver background refresh stress" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver_config = Reseau.HostResolverConfig(; max_ttl_secs = 2, resolve_frequency_ns = 100_000_000)
    resolver = Reseau.HostResolver(elg, resolver_config)

    host = "refresh.example"
    addr1_ipv4 = Reseau.HostAddress("address1ipv4", Reseau.HostAddressType.A, host, 0)
    addr1_ipv6 = Reseau.HostAddress("address1ipv6", Reseau.HostAddressType.AAAA, host, 0)

    mock = MockDnsResolver(50)
    mock_dns_append!(mock, [addr1_ipv6, addr1_ipv4])

    config = Reseau.HostResolutionConfig(;
        impl = (h, data) -> mock_dns_resolve(h, data),
        impl_data = mock,
        max_ttl_secs = 2,
        resolve_frequency_ns = 100_000_000,
    )

    err, addrs = resolve_and_wait(resolver, host; config = config, timeout_s = 2.0)
    @test err == Reseau.AWS_OP_SUCCESS
    @test !isempty(addrs)

    @test wait_for_pred(() -> mock.resolve_count >= 3; timeout_s = 2.5)

    for _ in 1:10
        result = resolve_and_wait(resolver, host; config = config, timeout_s = 2.0)
        @test result !== :timeout
        if result !== :timeout
            err_code, addresses = result
            @test err_code == Reseau.AWS_OP_SUCCESS
            @test !isempty(addresses)
        end
    end

    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "host resolver literal address lookups" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.HostResolver(elg)
    config = Reseau.HostResolutionConfig(max_ttl_secs = 10)

    result_v4 = resolve_and_wait(resolver, "127.0.0.1"; config = config)
    @test result_v4 !== :timeout
    @test !(result_v4 isa Reseau.ErrorResult)
    err_v4, addrs_v4 = result_v4
    @test err_v4 == Reseau.AWS_OP_SUCCESS
    addr4 = find_address(addrs_v4, Reseau.HostAddressType.A)
    addr6 = find_address(addrs_v4, Reseau.HostAddressType.AAAA)
    @test addr4 !== nothing
    @test addr4.host == "127.0.0.1"
    if addr6 !== nothing
        @test occursin("::ffff:", addr6.address)
    end

    result_v6 = resolve_and_wait(resolver, "::1"; config = config)
    @test result_v6 !== :timeout
    @test !(result_v6 isa Reseau.ErrorResult)
    err_v6, addrs_v6 = result_v6
    @test err_v6 == Reseau.AWS_OP_SUCCESS
    addr4 = find_address(addrs_v6, Reseau.HostAddressType.A)
    addr6 = find_address(addrs_v6, Reseau.HostAddressType.AAAA)
    @test addr4 === nothing
    @test addr6 !== nothing
    @test addr6.host == "::1"

    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

if get(ENV, "RESEAU_RUN_NETWORK_TESTS", "0") == "1"
    @testset "host resolver default dns lookups (network)" begin
        elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
        resolver = Reseau.HostResolver(elg)
        config = Reseau.HostResolutionConfig(max_ttl_secs = 10)

        @testset "ipv6 dualstack lookup" begin
            result = resolve_and_wait(resolver, "s3.dualstack.us-east-1.amazonaws.com"; config = config)
            @test result !== :timeout
            err, addrs = result
            @test err == Reseau.AWS_OP_SUCCESS
            addr4 = find_address(addrs, Reseau.HostAddressType.A)
            addr6 = find_address(addrs, Reseau.HostAddressType.AAAA)
            @test addr4 !== nothing
            @test addr6 !== nothing
        end

        @testset "ipv4 lookup" begin
            result = resolve_and_wait(resolver, "s3.us-east-1.amazonaws.com"; config = config)
            @test result !== :timeout
            err, addrs = result
            @test err == Reseau.AWS_OP_SUCCESS
            addr4 = find_address(addrs, Reseau.HostAddressType.A)
            @test addr4 !== nothing
        end

        Reseau.host_resolver_shutdown!(resolver)
        Reseau.event_loop_group_destroy!(elg)
    end
end

@testset "host resolver ttl cache behavior" begin
    clock_ref = Ref{UInt64}(0)
    clock_fn = () -> clock_ref[]

    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.HostResolver(
        elg,
        Reseau.HostResolverConfig(; max_entries = 10, clock_override = clock_fn),
    )

    host = "host_address"
    addr1_ipv4 = Reseau.HostAddress("address1ipv4", Reseau.HostAddressType.A, host, 0)
    addr1_ipv6 = Reseau.HostAddress("address1ipv6", Reseau.HostAddressType.AAAA, host, 0)
    addr2_ipv4 = Reseau.HostAddress("address2ipv4", Reseau.HostAddressType.A, host, 0)
    addr2_ipv6 = Reseau.HostAddress("address2ipv6", Reseau.HostAddressType.AAAA, host, 0)

    mock = MockDnsResolver(2)
    mock_dns_append!(mock, [addr1_ipv6, addr1_ipv4])
    mock_dns_append!(mock, [addr2_ipv6, addr2_ipv4])

    config = Reseau.HostResolutionConfig(
        impl = (h, data) -> mock_dns_resolve(h, data),
        impl_data = mock,
        max_ttl_secs = 2,
        resolve_frequency_ns = 500_000_000,
    )

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.AWS_OP_SUCCESS
    @test find_address(addrs, Reseau.HostAddressType.AAAA).address == "address1ipv6"
    @test find_address(addrs, Reseau.HostAddressType.A).address == "address1ipv4"

    clock_ref[] = 1_500_000_000
    sleep(1.5)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs1 = result
    @test err == Reseau.AWS_OP_SUCCESS
    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs2 = result
    @test err == Reseau.AWS_OP_SUCCESS
    seen_v6 = Set([
        find_address(addrs1, Reseau.HostAddressType.AAAA).address,
        find_address(addrs2, Reseau.HostAddressType.AAAA).address,
    ])
    seen_v4 = Set([
        find_address(addrs1, Reseau.HostAddressType.A).address,
        find_address(addrs2, Reseau.HostAddressType.A).address,
    ])
    @test seen_v6 == Set(["address1ipv6", "address2ipv6"])
    @test seen_v4 == Set(["address1ipv4", "address2ipv4"])

    clock_ref[] = 2_001_000_000
    sleep(1.5)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.AWS_OP_SUCCESS
    @test find_address(addrs, Reseau.HostAddressType.AAAA).address == "address2ipv6"
    @test find_address(addrs, Reseau.HostAddressType.A).address == "address2ipv4"

    clock_ref[] = 4_000_000_000
    sleep(1.5)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.AWS_OP_SUCCESS
    @test find_address(addrs, Reseau.HostAddressType.AAAA).address == "address2ipv6"
    @test find_address(addrs, Reseau.HostAddressType.A).address == "address2ipv4"

    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "host resolver connection failure handling" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.HostResolver(elg)

    host = "host_address"
    addr1_ipv4 = Reseau.HostAddress("address1ipv4", Reseau.HostAddressType.A, host, 0)
    addr1_ipv6 = Reseau.HostAddress("address1ipv6", Reseau.HostAddressType.AAAA, host, 0)
    addr2_ipv4 = Reseau.HostAddress("address2ipv4", Reseau.HostAddressType.A, host, 0)
    addr2_ipv6 = Reseau.HostAddress("address2ipv6", Reseau.HostAddressType.AAAA, host, 0)

    mock = MockDnsResolver(100)
    mock_dns_append!(mock, [addr1_ipv6, addr2_ipv6, addr1_ipv4, addr2_ipv4])

    config = Reseau.HostResolutionConfig(
        impl = (h, data) -> mock_dns_resolve(h, data),
        impl_data = mock,
        max_ttl_secs = 30,
    )

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.AWS_OP_SUCCESS
    @test find_address(addrs, Reseau.HostAddressType.AAAA).address == "address1ipv6"
    @test find_address(addrs, Reseau.HostAddressType.A).address == "address1ipv4"

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.AWS_OP_SUCCESS
    @test find_address(addrs, Reseau.HostAddressType.AAAA).address == "address2ipv6"
    @test find_address(addrs, Reseau.HostAddressType.A).address == "address2ipv4"

    Reseau.host_resolver_record_connection_failure!(resolver, addr1_ipv6)
    Reseau.host_resolver_record_connection_failure!(resolver, addr1_ipv4)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.AWS_OP_SUCCESS
    @test find_address(addrs, Reseau.HostAddressType.AAAA).address == "address2ipv6"
    @test find_address(addrs, Reseau.HostAddressType.A).address == "address2ipv4"

    Reseau.host_resolver_record_connection_failure!(resolver, addr2_ipv6)
    Reseau.host_resolver_record_connection_failure!(resolver, addr2_ipv4)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.AWS_OP_SUCCESS
    @test find_address(addrs, Reseau.HostAddressType.AAAA).address == "address1ipv6"
    @test find_address(addrs, Reseau.HostAddressType.A).address == "address1ipv4"

    sleep(1.5)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.AWS_OP_SUCCESS
    @test find_address(addrs, Reseau.HostAddressType.AAAA).address == "address1ipv6"
    @test find_address(addrs, Reseau.HostAddressType.A).address == "address1ipv4"

    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "host resolver ttl refreshes on resolve" begin
    clock_ref = Ref{UInt64}(0)
    clock_fn = () -> clock_ref[]

    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.HostResolver(
        elg,
        Reseau.HostResolverConfig(; max_entries = 10, clock_override = clock_fn),
    )

    host = "host_address"
    addr1_ipv4 = Reseau.HostAddress("address1ipv4", Reseau.HostAddressType.A, host, 0)
    addr1_ipv6 = Reseau.HostAddress("address1ipv6", Reseau.HostAddressType.AAAA, host, 0)
    addr2_ipv4 = Reseau.HostAddress("address2ipv4", Reseau.HostAddressType.A, host, 0)
    addr2_ipv6 = Reseau.HostAddress("address2ipv6", Reseau.HostAddressType.AAAA, host, 0)

    mock = MockDnsResolver(100)
    mock_dns_append!(mock, [addr1_ipv6, addr2_ipv6, addr1_ipv4, addr2_ipv4])

    config = Reseau.HostResolutionConfig(
        impl = (h, data) -> mock_dns_resolve(h, data),
        impl_data = mock,
        max_ttl_secs = 30,
    )

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.AWS_OP_SUCCESS
    addr1 = find_address(addrs, Reseau.HostAddressType.AAAA)
    addr1_expiry = addr1.expiry

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.AWS_OP_SUCCESS
    addr2 = find_address(addrs, Reseau.HostAddressType.AAAA)
    addr2_expiry = addr2.expiry

    clock_ref[] = 1_500_000_000
    sleep(1.5)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.AWS_OP_SUCCESS
    addr1_new = find_address(addrs, Reseau.HostAddressType.AAAA)
    @test addr1_expiry < addr1_new.expiry

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.AWS_OP_SUCCESS
    addr2_new = find_address(addrs, Reseau.HostAddressType.AAAA)
    @test addr2_expiry < addr2_new.expiry

    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "host resolver bad list expires eventually" begin
    clock_ref = Ref{UInt64}(0)
    clock_fn = () -> clock_ref[]

    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.HostResolver(
        elg,
        Reseau.HostResolverConfig(; max_entries = 10, clock_override = clock_fn),
    )

    host = "host_address"
    addr1_ipv4 = Reseau.HostAddress("address1ipv4", Reseau.HostAddressType.A, host, 0)
    addr2_ipv4 = Reseau.HostAddress("address2ipv4", Reseau.HostAddressType.A, host, 0)

    mock = MockDnsResolver(1000)
    mock_dns_append!(mock, [addr1_ipv4, addr2_ipv4])

    config = Reseau.HostResolutionConfig(
        impl = (h, data) -> mock_dns_resolve(h, data),
        impl_data = mock,
        max_ttl_secs = 1,
        resolve_frequency_ns = 100_000_000,
    )

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.AWS_OP_SUCCESS
    first_addr = find_address(addrs, Reseau.HostAddressType.A).address
    other_addr = first_addr == "address1ipv4" ? "address2ipv4" : "address1ipv4"

    Reseau.host_resolver_record_connection_failure!(
        resolver,
        Reseau.HostAddress(first_addr, Reseau.HostAddressType.A, host, 0),
    )

    num_addr1 = 0
    num_addr2 = 0
    start_ns = Base.time_ns()
    while num_addr1 == 0
        elapsed_ns = Base.time_ns() - start_ns
        @test elapsed_ns < 10_000_000_000
        clock_ref[] += 200_000_000
        sleep(0.1)
        result = resolve_and_wait(resolver, host; config = config)
        @test result !== :timeout
        err, addrs = result
        @test err == Reseau.AWS_OP_SUCCESS
        addr = find_address(addrs, Reseau.HostAddressType.A)
        if addr.address == first_addr
            num_addr1 += 1
        elseif addr.address == other_addr
            num_addr2 += 1
        else
            @test false
        end
    end

    @test num_addr2 > 3

    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "host resolver low frequency starvation" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.HostResolver(elg)

    host = "host_address"
    addr1_ipv4 = Reseau.HostAddress("address1ipv4", Reseau.HostAddressType.A, host, 0)

    mock = MockDnsResolver(1000)
    mock_dns_append!(mock, [addr1_ipv4])

    config = Reseau.HostResolutionConfig(
        impl = (h, data) -> mock_dns_resolve(h, data),
        impl_data = mock,
        max_ttl_secs = 30,
        resolve_frequency_ns = 120_000_000_000,
    )

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.AWS_OP_SUCCESS
    @test find_address(addrs, Reseau.HostAddressType.A).address == "address1ipv4"

    Reseau.host_resolver_record_connection_failure!(resolver, addr1_ipv4)

    start_ns = Base.time_ns()
    result = resolve_and_wait(resolver, host; config = config, timeout_s = 3.0)
    elapsed_ms = (Base.time_ns() - start_ns) / 1_000_000

    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.AWS_OP_SUCCESS
    @test elapsed_ms > 50
    @test elapsed_ms < 2000
    @test find_address(addrs, Reseau.HostAddressType.A).address == "address1ipv4"

    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "host resolver cached results" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.HostResolver(elg)

    resolve_calls = Ref(0)
    impl = (host, data) -> begin
        resolve_calls[] += 1
        return [Reseau.HostAddress("127.0.0.1", Reseau.HostAddressType.A, host, 0)]
    end

    config = Reseau.HostResolutionConfig(
        impl = impl,
        max_ttl_secs = 5,
        resolve_frequency_ns = 5_000_000_000,
    )

    resolved = Ref(false)
    addrs = Ref{Vector{Reseau.HostAddress}}(Reseau.HostAddress[])
    cb = (res, host, error_code, addresses) -> begin
        addrs[] = addresses
        resolved[] = true
        return nothing
    end

    @test Reseau.host_resolver_resolve!(resolver, "example.com", cb; resolution_config = config) === nothing
    @test wait_for_pred(() -> resolved[])
    @test resolve_calls[] == 1
    @test !isempty(addrs[])

    resolved[] = false
    @test Reseau.host_resolver_resolve!(resolver, "example.com", cb; resolution_config = config) === nothing
    @test wait_for_pred(() -> resolved[])
    @test resolve_calls[] == 1

    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "host resolver purge and count" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.HostResolver(elg)

    resolved = Ref(false)
    addrs = Ref{Vector{Reseau.HostAddress}}(Reseau.HostAddress[])

    impl = (host, data) -> begin
        return [Reseau.HostAddress("127.0.0.1", Reseau.HostAddressType.A, host, 0)]
    end

    config = Reseau.HostResolutionConfig(
        impl = impl,
        max_ttl_secs = 5,
        resolve_frequency_ns = 5_000_000_000,
    )

    cb = (res, host, error_code, addresses) -> begin
        addrs[] = addresses
        resolved[] = true
        return nothing
    end

    @test Reseau.host_resolver_resolve!(resolver, "example.com", cb; resolution_config = config) === nothing
    @test wait_for_pred(() -> resolved[])
    @test !isempty(addrs[])

    count_a = Reseau.host_resolver_get_host_address_count(
        resolver,
        "example.com";
        flags = Reseau.GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A,
    )
    @test count_a >= 1

    purge_host_done = Ref(false)
    @test Reseau.host_resolver_purge_host_cache!(
        resolver,
        "example.com";
        on_host_purge_complete = _ -> (purge_host_done[] = true),
    ) === nothing
    @test wait_for_pred(() -> purge_host_done[])
    @test Reseau.host_resolver_get_host_address_count(
        resolver,
        "example.com";
        flags = Reseau.GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A,
    ) == 0

    purge_host_done[] = false
    @test Reseau.host_resolver_purge_host_cache!(
        resolver,
        "example.com";
        on_host_purge_complete = _ -> (purge_host_done[] = true),
    ) === nothing
    @test wait_for_pred(() -> purge_host_done[])

    resolved[] = false
    @test Reseau.host_resolver_resolve!(resolver, "example.com", cb; resolution_config = config) === nothing
    @test wait_for_pred(() -> resolved[])

    purge_done = Ref(false)
    @test Reseau.host_resolver_purge_cache_with_callback!(
        resolver,
        _ -> (purge_done[] = true),
    ) === nothing
    @test wait_for_pred(() -> purge_done[])

    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "host resolver record failure moves address" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    resolver = Reseau.HostResolver(elg)

    resolved = Ref(false)
    addrs = Ref{Vector{Reseau.HostAddress}}(Reseau.HostAddress[])

    impl = (host, data) -> begin
        return [Reseau.HostAddress("127.0.0.1", Reseau.HostAddressType.A, host, 0)]
    end

    config = Reseau.HostResolutionConfig(
        impl = impl,
        max_ttl_secs = 5,
        resolve_frequency_ns = 5_000_000_000,
    )

    cb = (res, host, error_code, addresses) -> begin
        addrs[] = addresses
        resolved[] = true
        return nothing
    end

    @test Reseau.host_resolver_resolve!(resolver, "example.com", cb; resolution_config = config) === nothing
    @test wait_for_pred(() -> resolved[])
    @test !isempty(addrs[])

    addr = addrs[][1]
    Reseau.host_resolver_record_connection_failure!(resolver, addr)
    count_a = Reseau.host_resolver_get_host_address_count(
        resolver,
        "example.com";
        flags = Reseau.GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A,
    )
    @test count_a == 0

    Reseau.host_resolver_shutdown!(resolver)
    Reseau.event_loop_group_destroy!(elg)
end
