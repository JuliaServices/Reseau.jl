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

mutable struct MockDnsResolver
    address_lists::Vector{Vector{AwsIO.HostAddress}}
    index::Int
    max_resolves::Int
    resolve_count::Int
end

function MockDnsResolver(max_resolves::Integer)
    return MockDnsResolver(Vector{Vector{AwsIO.HostAddress}}(), 1, Int(max_resolves), 0)
end

function mock_dns_append!(resolver::MockDnsResolver, addrs::Vector{AwsIO.HostAddress})
    push!(resolver.address_lists, [copy(addr) for addr in addrs])
    return nothing
end

function mock_dns_resolve(host::AbstractString, resolver::MockDnsResolver)
    if resolver.resolve_count >= resolver.max_resolves
        return AwsIO.HostAddress[], AwsIO.ERROR_IO_DNS_QUERY_FAILED
    end
    isempty(resolver.address_lists) && return AwsIO.HostAddress[], AwsIO.ERROR_IO_DNS_QUERY_FAILED
    list = resolver.address_lists[resolver.index]
    resolver.index = resolver.index % length(resolver.address_lists) + 1
    resolver.resolve_count += 1
    isempty(list) && return AwsIO.HostAddress[], AwsIO.ERROR_IO_DNS_QUERY_FAILED
    return [copy(addr) for addr in list], AwsIO.AWS_OP_SUCCESS
end

function find_address(addrs::Vector{AwsIO.HostAddress}, addr_type::AwsIO.HostAddressType.T)
    for addr in addrs
        if addr.address_type == addr_type
            return addr
        end
    end
    return nothing
end

function resolve_and_wait(resolver, host; config=nothing, timeout_s::Float64 = 5.0)
    invoked = Ref(false)
    err_ref = Ref{Int}(AwsIO.AWS_OP_SUCCESS)
    addrs_ref = Ref{Vector{AwsIO.HostAddress}}(AwsIO.HostAddress[])
    cb = (res, host_name, err, addresses) -> begin
        err_ref[] = err
        addrs_ref[] = addresses
        invoked[] = true
        return nothing
    end
    result = AwsIO.host_resolver_resolve!(resolver, host, cb; resolution_config = config)
    if result isa AwsIO.ErrorResult
        return result.code, AwsIO.HostAddress[]
    end
    ok = wait_for_pred(() -> invoked[]; timeout_s = timeout_s)
    return ok ? (err_ref[], addrs_ref[]) : :timeout
end

@testset "host resolver ipv6 address variations" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    config = AwsIO.HostResolutionConfig(max_ttl_secs = 10)

    cases = [
        ("0:0::1", "::1"),
        ("::1", "::1"),
        ("0:0:0:0:0:0:0:1", "::1"),
        ("fd00:ec2:0:0:0:0:0:23", "fd00:ec2::23"),
    ]

    for (input, expected) in cases
        result = resolve_and_wait(resolver, input; config = config)
        @test result !== :timeout
        @test !(result isa AwsIO.ErrorResult)
        err, addrs = result
        @test err == AwsIO.AWS_OP_SUCCESS
        addr6 = find_address(addrs, AwsIO.HostAddressType.AAAA)
        @test addr6 !== nothing
        @test addr6.address == expected
    end

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "host resolver background refresh stress" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver_config = AwsIO.HostResolverConfig(; max_ttl_secs = 2, resolve_frequency_ns = 100_000_000)
    resolver = AwsIO.DefaultHostResolver(elg, resolver_config)

    host = "refresh.example"
    addr1_ipv4 = AwsIO.HostAddress("address1ipv4", AwsIO.HostAddressType.A, host, 0)
    addr1_ipv6 = AwsIO.HostAddress("address1ipv6", AwsIO.HostAddressType.AAAA, host, 0)

    mock = MockDnsResolver(50)
    mock_dns_append!(mock, [addr1_ipv6, addr1_ipv4])

    config = AwsIO.HostResolutionConfig(;
        impl = (h, data) -> mock_dns_resolve(h, data),
        impl_data = mock,
        max_ttl_secs = 2,
        resolve_frequency_ns = 100_000_000,
    )

    err, addrs = resolve_and_wait(resolver, host; config = config, timeout_s = 2.0)
    @test err == AwsIO.AWS_OP_SUCCESS
    @test !isempty(addrs)

    @test wait_for_pred(() -> mock.resolve_count >= 3; timeout_s = 2.5)

    for _ in 1:10
        result = resolve_and_wait(resolver, host; config = config, timeout_s = 2.0)
        @test result !== :timeout
        if result !== :timeout
            err_code, addresses = result
            @test err_code == AwsIO.AWS_OP_SUCCESS
            @test !isempty(addresses)
        end
    end

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "host resolver literal address lookups" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)
    config = AwsIO.HostResolutionConfig(max_ttl_secs = 10)

    result_v4 = resolve_and_wait(resolver, "127.0.0.1"; config = config)
    @test result_v4 !== :timeout
    @test !(result_v4 isa AwsIO.ErrorResult)
    err_v4, addrs_v4 = result_v4
    @test err_v4 == AwsIO.AWS_OP_SUCCESS
    addr4 = find_address(addrs_v4, AwsIO.HostAddressType.A)
    addr6 = find_address(addrs_v4, AwsIO.HostAddressType.AAAA)
    @test addr4 !== nothing
    @test addr4.host == "127.0.0.1"
    if addr6 !== nothing
        @test occursin("::ffff:", addr6.address)
    end

    result_v6 = resolve_and_wait(resolver, "::1"; config = config)
    @test result_v6 !== :timeout
    @test !(result_v6 isa AwsIO.ErrorResult)
    err_v6, addrs_v6 = result_v6
    @test err_v6 == AwsIO.AWS_OP_SUCCESS
    addr4 = find_address(addrs_v6, AwsIO.HostAddressType.A)
    addr6 = find_address(addrs_v6, AwsIO.HostAddressType.AAAA)
    @test addr4 === nothing
    @test addr6 !== nothing
    @test addr6.host == "::1"

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

if get(ENV, "AWSIO_RUN_NETWORK_TESTS", "0") == "1"
    @testset "host resolver default dns lookups (network)" begin
        elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
        resolver = AwsIO.DefaultHostResolver(elg)
        config = AwsIO.HostResolutionConfig(max_ttl_secs = 10)

        @testset "ipv6 dualstack lookup" begin
            result = resolve_and_wait(resolver, "s3.dualstack.us-east-1.amazonaws.com"; config = config)
            @test result !== :timeout
            err, addrs = result
            @test err == AwsIO.AWS_OP_SUCCESS
            addr4 = find_address(addrs, AwsIO.HostAddressType.A)
            addr6 = find_address(addrs, AwsIO.HostAddressType.AAAA)
            @test addr4 !== nothing
            @test addr6 !== nothing
        end

        @testset "ipv4 lookup" begin
            result = resolve_and_wait(resolver, "s3.us-east-1.amazonaws.com"; config = config)
            @test result !== :timeout
            err, addrs = result
            @test err == AwsIO.AWS_OP_SUCCESS
            addr4 = find_address(addrs, AwsIO.HostAddressType.A)
            @test addr4 !== nothing
        end

        AwsIO.host_resolver_shutdown!(resolver)
        AwsIO.event_loop_group_destroy!(elg)
    end
end

@testset "host resolver ttl cache behavior" begin
    clock_ref = Ref{UInt64}(0)
    clock_fn = () -> clock_ref[]

    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(
        elg,
        AwsIO.HostResolverConfig(; max_entries = 10, clock_override = clock_fn),
    )

    host = "host_address"
    addr1_ipv4 = AwsIO.HostAddress("address1ipv4", AwsIO.HostAddressType.A, host, 0)
    addr1_ipv6 = AwsIO.HostAddress("address1ipv6", AwsIO.HostAddressType.AAAA, host, 0)
    addr2_ipv4 = AwsIO.HostAddress("address2ipv4", AwsIO.HostAddressType.A, host, 0)
    addr2_ipv6 = AwsIO.HostAddress("address2ipv6", AwsIO.HostAddressType.AAAA, host, 0)

    mock = MockDnsResolver(2)
    mock_dns_append!(mock, [addr1_ipv6, addr1_ipv4])
    mock_dns_append!(mock, [addr2_ipv6, addr2_ipv4])

    config = AwsIO.HostResolutionConfig(
        impl = (h, data) -> mock_dns_resolve(h, data),
        impl_data = mock,
        max_ttl_secs = 2,
        resolve_frequency_ns = 500_000_000,
    )

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == AwsIO.AWS_OP_SUCCESS
    @test find_address(addrs, AwsIO.HostAddressType.AAAA).address == "address1ipv6"
    @test find_address(addrs, AwsIO.HostAddressType.A).address == "address1ipv4"

    clock_ref[] = 1_500_000_000
    sleep(1.5)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs1 = result
    @test err == AwsIO.AWS_OP_SUCCESS
    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs2 = result
    @test err == AwsIO.AWS_OP_SUCCESS
    seen_v6 = Set([
        find_address(addrs1, AwsIO.HostAddressType.AAAA).address,
        find_address(addrs2, AwsIO.HostAddressType.AAAA).address,
    ])
    seen_v4 = Set([
        find_address(addrs1, AwsIO.HostAddressType.A).address,
        find_address(addrs2, AwsIO.HostAddressType.A).address,
    ])
    @test seen_v6 == Set(["address1ipv6", "address2ipv6"])
    @test seen_v4 == Set(["address1ipv4", "address2ipv4"])

    clock_ref[] = 2_001_000_000
    sleep(1.5)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == AwsIO.AWS_OP_SUCCESS
    @test find_address(addrs, AwsIO.HostAddressType.AAAA).address == "address2ipv6"
    @test find_address(addrs, AwsIO.HostAddressType.A).address == "address2ipv4"

    clock_ref[] = 4_000_000_000
    sleep(1.5)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == AwsIO.AWS_OP_SUCCESS
    @test find_address(addrs, AwsIO.HostAddressType.AAAA).address == "address2ipv6"
    @test find_address(addrs, AwsIO.HostAddressType.A).address == "address2ipv4"

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "host resolver connection failure handling" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    host = "host_address"
    addr1_ipv4 = AwsIO.HostAddress("address1ipv4", AwsIO.HostAddressType.A, host, 0)
    addr1_ipv6 = AwsIO.HostAddress("address1ipv6", AwsIO.HostAddressType.AAAA, host, 0)
    addr2_ipv4 = AwsIO.HostAddress("address2ipv4", AwsIO.HostAddressType.A, host, 0)
    addr2_ipv6 = AwsIO.HostAddress("address2ipv6", AwsIO.HostAddressType.AAAA, host, 0)

    mock = MockDnsResolver(100)
    mock_dns_append!(mock, [addr1_ipv6, addr2_ipv6, addr1_ipv4, addr2_ipv4])

    config = AwsIO.HostResolutionConfig(
        impl = (h, data) -> mock_dns_resolve(h, data),
        impl_data = mock,
        max_ttl_secs = 30,
    )

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == AwsIO.AWS_OP_SUCCESS
    @test find_address(addrs, AwsIO.HostAddressType.AAAA).address == "address1ipv6"
    @test find_address(addrs, AwsIO.HostAddressType.A).address == "address1ipv4"

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == AwsIO.AWS_OP_SUCCESS
    @test find_address(addrs, AwsIO.HostAddressType.AAAA).address == "address2ipv6"
    @test find_address(addrs, AwsIO.HostAddressType.A).address == "address2ipv4"

    AwsIO.host_resolver_record_connection_failure!(resolver, addr1_ipv6)
    AwsIO.host_resolver_record_connection_failure!(resolver, addr1_ipv4)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == AwsIO.AWS_OP_SUCCESS
    @test find_address(addrs, AwsIO.HostAddressType.AAAA).address == "address2ipv6"
    @test find_address(addrs, AwsIO.HostAddressType.A).address == "address2ipv4"

    AwsIO.host_resolver_record_connection_failure!(resolver, addr2_ipv6)
    AwsIO.host_resolver_record_connection_failure!(resolver, addr2_ipv4)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == AwsIO.AWS_OP_SUCCESS
    @test find_address(addrs, AwsIO.HostAddressType.AAAA).address == "address1ipv6"
    @test find_address(addrs, AwsIO.HostAddressType.A).address == "address1ipv4"

    sleep(1.5)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == AwsIO.AWS_OP_SUCCESS
    @test find_address(addrs, AwsIO.HostAddressType.AAAA).address == "address1ipv6"
    @test find_address(addrs, AwsIO.HostAddressType.A).address == "address1ipv4"

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "host resolver ttl refreshes on resolve" begin
    clock_ref = Ref{UInt64}(0)
    clock_fn = () -> clock_ref[]

    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(
        elg,
        AwsIO.HostResolverConfig(; max_entries = 10, clock_override = clock_fn),
    )

    host = "host_address"
    addr1_ipv4 = AwsIO.HostAddress("address1ipv4", AwsIO.HostAddressType.A, host, 0)
    addr1_ipv6 = AwsIO.HostAddress("address1ipv6", AwsIO.HostAddressType.AAAA, host, 0)
    addr2_ipv4 = AwsIO.HostAddress("address2ipv4", AwsIO.HostAddressType.A, host, 0)
    addr2_ipv6 = AwsIO.HostAddress("address2ipv6", AwsIO.HostAddressType.AAAA, host, 0)

    mock = MockDnsResolver(100)
    mock_dns_append!(mock, [addr1_ipv6, addr2_ipv6, addr1_ipv4, addr2_ipv4])

    config = AwsIO.HostResolutionConfig(
        impl = (h, data) -> mock_dns_resolve(h, data),
        impl_data = mock,
        max_ttl_secs = 30,
    )

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == AwsIO.AWS_OP_SUCCESS
    addr1 = find_address(addrs, AwsIO.HostAddressType.AAAA)
    addr1_expiry = addr1.expiry

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == AwsIO.AWS_OP_SUCCESS
    addr2 = find_address(addrs, AwsIO.HostAddressType.AAAA)
    addr2_expiry = addr2.expiry

    clock_ref[] = 1_500_000_000
    sleep(1.5)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == AwsIO.AWS_OP_SUCCESS
    addr1_new = find_address(addrs, AwsIO.HostAddressType.AAAA)
    @test addr1_expiry < addr1_new.expiry

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == AwsIO.AWS_OP_SUCCESS
    addr2_new = find_address(addrs, AwsIO.HostAddressType.AAAA)
    @test addr2_expiry < addr2_new.expiry

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "host resolver bad list expires eventually" begin
    clock_ref = Ref{UInt64}(0)
    clock_fn = () -> clock_ref[]

    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(
        elg,
        AwsIO.HostResolverConfig(; max_entries = 10, clock_override = clock_fn),
    )

    host = "host_address"
    addr1_ipv4 = AwsIO.HostAddress("address1ipv4", AwsIO.HostAddressType.A, host, 0)
    addr2_ipv4 = AwsIO.HostAddress("address2ipv4", AwsIO.HostAddressType.A, host, 0)

    mock = MockDnsResolver(1000)
    mock_dns_append!(mock, [addr1_ipv4, addr2_ipv4])

    config = AwsIO.HostResolutionConfig(
        impl = (h, data) -> mock_dns_resolve(h, data),
        impl_data = mock,
        max_ttl_secs = 1,
        resolve_frequency_ns = 100_000_000,
    )

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == AwsIO.AWS_OP_SUCCESS
    first_addr = find_address(addrs, AwsIO.HostAddressType.A).address
    other_addr = first_addr == "address1ipv4" ? "address2ipv4" : "address1ipv4"

    AwsIO.host_resolver_record_connection_failure!(
        resolver,
        AwsIO.HostAddress(first_addr, AwsIO.HostAddressType.A, host, 0),
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
        @test err == AwsIO.AWS_OP_SUCCESS
        addr = find_address(addrs, AwsIO.HostAddressType.A)
        if addr.address == first_addr
            num_addr1 += 1
        elseif addr.address == other_addr
            num_addr2 += 1
        else
            @test false
        end
    end

    @test num_addr2 > 3

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "host resolver low frequency starvation" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    host = "host_address"
    addr1_ipv4 = AwsIO.HostAddress("address1ipv4", AwsIO.HostAddressType.A, host, 0)

    mock = MockDnsResolver(1000)
    mock_dns_append!(mock, [addr1_ipv4])

    config = AwsIO.HostResolutionConfig(
        impl = (h, data) -> mock_dns_resolve(h, data),
        impl_data = mock,
        max_ttl_secs = 30,
        resolve_frequency_ns = 120_000_000_000,
    )

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == AwsIO.AWS_OP_SUCCESS
    @test find_address(addrs, AwsIO.HostAddressType.A).address == "address1ipv4"

    AwsIO.host_resolver_record_connection_failure!(resolver, addr1_ipv4)

    start_ns = Base.time_ns()
    result = resolve_and_wait(resolver, host; config = config, timeout_s = 3.0)
    elapsed_ms = (Base.time_ns() - start_ns) / 1_000_000

    @test result !== :timeout
    err, addrs = result
    @test err == AwsIO.AWS_OP_SUCCESS
    @test elapsed_ms > 50
    @test elapsed_ms < 2000
    @test find_address(addrs, AwsIO.HostAddressType.A).address == "address1ipv4"

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
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

    purge_host_done[] = false
    @test AwsIO.host_resolver_purge_host_cache!(
        resolver,
        "example.com";
        on_host_purge_complete = _ -> (purge_host_done[] = true),
    ) === nothing
    @test wait_for_pred(() -> purge_host_done[])

    resolved[] = false
    @test AwsIO.host_resolver_resolve!(resolver, "example.com", cb; resolution_config = config) === nothing
    @test wait_for_pred(() -> resolved[])

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
