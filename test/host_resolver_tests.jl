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

function find_address(addrs::Vector{Sockets.HostAddress}, addr_type::Sockets.HostAddressType.T)
    for addr in addrs
        if addr.address_type == addr_type
            return addr
        end
    end
    return nothing
end

function resolve_and_wait(resolver, host; config=nothing, timeout_s::Float64 = 5.0)
    err_code = Ref{Int}(Reseau.OP_SUCCESS)
    addrs_ref = Ref{Vector{Sockets.HostAddress}}(Sockets.HostAddress[])
    done = Ref(false)

    _task = @async begin
        try
            addrs_ref[] = Sockets.host_resolver_resolve!(resolver, host, config)
        catch e
            if e isa Reseau.ReseauError
                err_code[] = e.code
            elseif e isa DNSError
                err_code[] = Int(e.code)
            else
                rethrow()
            end
        end
        done[] = true
    end
    wait_for_pred(() -> done[]; timeout_s = timeout_s) || return :timeout
    (err_code[], addrs_ref[])
end

@testset "host resolver ipv6 address variations" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver()

    config = Sockets.HostResolutionConfig(max_ttl_secs = 10)

    cases = [
        ("0:0::1", "::1"),
        ("::1", "::1"),
        ("0:0:0:0:0:0:0:1", "::1"),
        ("fd00:ec2:0:0:0:0:0:23", "fd00:ec2::23"),
    ]

    for (input, expected) in cases
        result = resolve_and_wait(resolver, input; config = config)
        @test result !== :timeout
        err, addrs = result
        @test err == Reseau.OP_SUCCESS
        addr6 = find_address(addrs, Sockets.HostAddressType.AAAA)
        @test addr6 !== nothing
        @test addr6.address == expected
    end

    Sockets.close(resolver)
    close(elg)
end

@testset "host resolver happy eyeballs ordering" begin
    host = "2001:db8::1"
    config = Sockets.HostResolutionConfig(
        resolve_host_as_address = true,
        max_ttl_secs = 10,
    )

    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver()

    default_result = resolve_and_wait(resolver, host; config = config)
    @test default_result !== :timeout
    err, default_addresses = default_result
    @test err == Reseau.OP_SUCCESS
    @test default_addresses[1].address == host

    Sockets.close(resolver)
    close(elg)

    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver()

    bias_v6_config = Sockets.HostResolutionConfig(
        resolve_host_as_address = true,
        first_address_family_count = 2,
        max_ttl_secs = 10,
    )
    bias_result = resolve_and_wait(resolver, host; config = bias_v6_config)
    @test bias_result !== :timeout
    err, bias_addresses = bias_result
    @test err == Reseau.OP_SUCCESS
    @test bias_addresses[1].address == host

    Sockets.close(resolver)
    close(elg)
end

@testset "host resolver happy eyeballs config normalization" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver()

    config = Sockets.HostResolutionConfig(
        first_address_family_count = 0,
        connection_attempt_delay_ns = 1,
        min_connection_attempt_delay_ns = 1,
    )
    normalized = Sockets._normalize_resolution_config(resolver, config)

    @test normalized.first_address_family_count == Sockets.HOST_RESOLVER_HAPPY_EYEBALLS_FIRST_ADDRESS_FAMILY_COUNT
    @test normalized.min_connection_attempt_delay_ns == Sockets.HOST_RESOLVER_HAPPY_EYEBALLS_MIN_CONNECTION_ATTEMPT_DELAY_FLOOR_NS
    @test normalized.connection_attempt_delay_ns == Sockets.HOST_RESOLVER_HAPPY_EYEBALLS_MIN_CONNECTION_ATTEMPT_DELAY_FLOOR_NS

    Sockets.close(resolver)
    close(elg)
end

@testset "host resolver background refresh stress" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(1024, 2, 1, 8, 100_000_000)

    host = "::1"
    config = Sockets.HostResolutionConfig(;
        resolve_host_as_address = true,
        max_ttl_secs = 2,
        resolve_frequency_ns = 100_000_000,
    )

    err, addrs = resolve_and_wait(resolver, host; config = config, timeout_s = 2.0)
    @test err == Reseau.OP_SUCCESS
    @test !isempty(addrs)

    for _ in 1:10
        result = resolve_and_wait(resolver, host; config = config, timeout_s = 2.0)
        @test result !== :timeout
        if result !== :timeout
            err_code, addresses = result
            @test err_code == Reseau.OP_SUCCESS
            @test !isempty(addresses)
        end
    end

    Sockets.close(resolver)
    close(elg)
end

@testset "host resolver literal address lookups" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver()
    config = Sockets.HostResolutionConfig(max_ttl_secs = 10)

    result_v4 = resolve_and_wait(resolver, "127.0.0.1"; config = config)
    @test result_v4 !== :timeout
    err_v4, addrs_v4 = result_v4
    @test err_v4 == Reseau.OP_SUCCESS
    addr4 = find_address(addrs_v4, Sockets.HostAddressType.A)
    addr6 = find_address(addrs_v4, Sockets.HostAddressType.AAAA)
    @test addr4 !== nothing
    @test addr4.host == "127.0.0.1"
    if addr6 !== nothing
        @test occursin("::ffff:", addr6.address)
    end

    result_v6 = resolve_and_wait(resolver, "::1"; config = config)
    @test result_v6 !== :timeout
    err_v6, addrs_v6 = result_v6
    @test err_v6 == Reseau.OP_SUCCESS
    addr4 = find_address(addrs_v6, Sockets.HostAddressType.A)
    addr6 = find_address(addrs_v6, Sockets.HostAddressType.AAAA)
    @test addr4 === nothing
    @test addr6 !== nothing
    @test addr6.host == "::1"

    Sockets.close(resolver)
    close(elg)
end

if get(ENV, "RESEAU_RUN_NETWORK_TESTS", "0") == "1"
    @testset "host resolver default dns lookups (network)" begin
        elg = EventLoops.EventLoopGroup(; loop_count = 1)
        resolver = Sockets.HostResolver()
        config = Sockets.HostResolutionConfig(max_ttl_secs = 10)

        @testset "ipv6 dualstack lookup" begin
            result = resolve_and_wait(
                resolver,
                "s3.dualstack.us-east-1.amazonaws.com";
                config = config,
                timeout_s = 15.0,
            )
            @test result !== :timeout
            if result !== :timeout
                err, addrs = result
                @test err == Reseau.OP_SUCCESS
                addr4 = find_address(addrs, Sockets.HostAddressType.A)
                addr6 = find_address(addrs, Sockets.HostAddressType.AAAA)
                @test addr4 !== nothing || addr6 !== nothing
                if addr6 === nothing
                    @info "Dualstack lookup did not return AAAA record; environment/network only returned IPv4" host = "s3.dualstack.us-east-1.amazonaws.com"
                end
                if addr4 === nothing
                    @info "Dualstack lookup missing A record; environment appears IPv6-only" host = "s3.dualstack.us-east-1.amazonaws.com"
                end
            end
        end

        @testset "ipv4 lookup" begin
            result = resolve_and_wait(
                resolver,
                "s3.us-east-1.amazonaws.com";
                config = config,
                timeout_s = 15.0,
            )
            @test result !== :timeout
            if result !== :timeout
                err, addrs = result
                @test err == Reseau.OP_SUCCESS
                addr4 = find_address(addrs, Sockets.HostAddressType.A)
                @test addr4 !== nothing
            end
        end

        Sockets.close(resolver)
        close(elg)
    end
end

@testset "host resolver ttl cache behavior" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(10, 2, 1, 8, 500_000_000)

    host = "127.0.0.1"
    config = Sockets.HostResolutionConfig(
        resolve_host_as_address = true,
        max_ttl_secs = 2,
        resolve_frequency_ns = 500_000_000,
    )

    err, addrs = resolve_and_wait(resolver, host; config = config)
    @test err == Reseau.OP_SUCCESS
    @test !isempty(addrs)
    first_address = addrs[1].address

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.OP_SUCCESS
    @test all(a -> a.address == first_address, addrs)

    sleep(1.5)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs1 = result
    @test err == Reseau.OP_SUCCESS
    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs2 = result
    @test err == Reseau.OP_SUCCESS
    @test all(a -> a.address == first_address, addrs1)
    @test all(a -> a.address == first_address, addrs2)

    sleep(1.5)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.OP_SUCCESS
    @test all(a -> a.address == first_address, addrs)

    sleep(1.5)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.OP_SUCCESS
    @test all(a -> a.address == first_address, addrs)

    Sockets.close(resolver)
    close(elg)
end

@testset "host resolver connection failure handling" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver()

    host = "host_address"
    config = Sockets.HostResolutionConfig(
        resolve_host_as_address = true,
        max_ttl_secs = 30,
    )

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.OP_SUCCESS
    @test !isempty(addrs)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.OP_SUCCESS
    @test !isempty(addrs)

    Sockets.record_connection_failure!(resolver, addrs[1])

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.OP_SUCCESS
    @test !isempty(addrs)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.OP_SUCCESS
    @test !isempty(addrs)

    sleep(1.5)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.OP_SUCCESS
    @test !isempty(addrs)

    Sockets.close(resolver)
    close(elg)
end

@testset "host resolver ttl refreshes on resolve" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(10, 30, 1, 8, 100_000_000)

    host = "127.0.0.1"

    config = Sockets.HostResolutionConfig(
        resolve_host_as_address = true,
        max_ttl_secs = 30,
    )

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.OP_SUCCESS
    addr1_expiry = addrs[1].expiry

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.OP_SUCCESS
    addr2_expiry = addrs[1].expiry

    sleep(1.5)

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.OP_SUCCESS
    addr1_new = addrs[1]
    @test addr1_expiry < addr1_new.expiry

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.OP_SUCCESS
    addr2_new = addrs[1]
    @test addr2_expiry < addr2_new.expiry

    Sockets.close(resolver)
    close(elg)
end

@testset "host resolver bad list expires eventually" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver(10, 1, 1, 8, 100_000_000)

    host = "127.0.0.1"
    config = Sockets.HostResolutionConfig(
        resolve_host_as_address = true,
        max_ttl_secs = 1,
        resolve_frequency_ns = 100_000_000,
    )

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.OP_SUCCESS
    first_addr = addrs[1].address

    Sockets.record_connection_failure!(
        resolver,
        Sockets.HostAddress(first_addr, Sockets.HostAddressType.A, host, 0),
    )

    start_ns = Base.time_ns()
    resolved_host = Ref("")
    @test wait_for_pred(() -> begin
        result = resolve_and_wait(resolver, host; config = config, timeout_s = 1.0)
        result === :timeout && return false
        _, addrs = result
        resolved_host[] = addrs[1].address
        addrs[1].address == first_addr
    end, timeout_s = 2.0)
    @test resolved_host[] == first_addr
    elapsed_ns = Base.time_ns() - start_ns
    @test elapsed_ns < 2_000_000_000

    Sockets.close(resolver)
    close(elg)
end

@testset "host resolver low frequency starvation" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver()

    host = "host_address"
    config = Sockets.HostResolutionConfig(
        resolve_host_as_address = true,
        max_ttl_secs = 30,
        resolve_frequency_ns = 120_000_000_000,
    )

    result = resolve_and_wait(resolver, host; config = config)
    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.OP_SUCCESS
    @test !isempty(addrs)
    addr = addrs[1]

    Sockets.record_connection_failure!(resolver, addr)

    start_ns = Base.time_ns()
    result = resolve_and_wait(resolver, host; config = config, timeout_s = 3.0)
    elapsed_ms = (Base.time_ns() - start_ns) / 1_000_000

    @test result !== :timeout
    err, addrs = result
    @test err == Reseau.OP_SUCCESS
    @test elapsed_ms > 50
    @test elapsed_ms < 2000
    @test !isempty(addrs)

    Sockets.close(resolver)
    close(elg)
end

@testset "host resolver cached results" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver()

    config = Sockets.HostResolutionConfig(
        resolve_host_as_address = true,
        max_ttl_secs = 5,
        resolve_frequency_ns = 5_000_000_000,
    )

    addrs = Sockets.host_resolver_resolve!(resolver, "127.0.0.1", config)
    @test !isempty(addrs)

    addrs = Sockets.host_resolver_resolve!(resolver, "127.0.0.1", config)
    @test addrs[1].address == "127.0.0.1"

    Sockets.close(resolver)
    close(elg)
end

@testset "host resolver count and close" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver()

    config = Sockets.HostResolutionConfig(
        resolve_host_as_address = true,
        max_ttl_secs = 5,
        resolve_frequency_ns = 5_000_000_000,
    )

    addrs = Sockets.host_resolver_resolve!(resolver, "127.0.0.1", config)
    @test !isempty(addrs)

    count_a = Sockets.get_host_address_count(
        resolver,
        "127.0.0.1";
        count_type_a = true,
        count_type_aaaa = false,
    )
    @test count_a >= 1

    @test Sockets.get_host_address_count(
        resolver,
        "example.com";
        count_type_a = true,
        count_type_aaaa = false,
    ) == 0

    Sockets.close(resolver)
    close(elg)
end

@testset "host resolver record failure moves address" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver()

    config = Sockets.HostResolutionConfig(
        resolve_host_as_address = true,
        max_ttl_secs = 5,
        resolve_frequency_ns = 5_000_000_000,
    )

    addrs = Sockets.host_resolver_resolve!(resolver, "127.0.0.1", config)
    @test !isempty(addrs)

    addr = addrs[1]
    Sockets.record_connection_failure!(resolver, addr)
    count_a = Sockets.get_host_address_count(
        resolver,
        "127.0.0.1";
        count_type_a = true,
        count_type_aaaa = false,
    )
    @test count_a == 0

    Sockets.close(resolver)
    close(elg)
end
