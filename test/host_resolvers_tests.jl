using Test
using Reseau

const ND = Reseau.HostResolvers
const NC = Reseau.TCP
const EL = Reseau.EventLoops
const IP = Reseau.IOPoll
const SO = Reseau.SocketOps

struct _SlowResolver <: ND.AbstractResolver
    delay_s::Float64
    addrs::Vector{NC.SocketEndpoint}
end

struct _ThreadcallResolver <: ND.AbstractResolver
    delay_ms::UInt32
    addrs::Vector{NC.SocketEndpoint}
end

function _nd_blocking_sleep_ms(delay_ms::UInt32)
    @static if Sys.iswindows()
        Base.@threadcall((:Sleep, "kernel32"), Cvoid, (UInt32,), delay_ms)
    else
        Base.@threadcall(:usleep, Cint, (Cuint,), Cuint(delay_ms * UInt32(1000)))
    end
    return nothing
end

function ND.resolve_tcp_addrs(
        resolver::_SlowResolver,
        network::AbstractString,
        address::AbstractString;
        op::Symbol = :connect,
        policy::ND.ResolverPolicy = ND.ResolverPolicy(),
    )::Vector{NC.SocketEndpoint}
    _ = network
    _ = address
    _ = op
    _ = policy
    sleep(resolver.delay_s)
    return copy(resolver.addrs)
end

function ND.resolve_tcp_addrs(
        resolver::_ThreadcallResolver,
        network::AbstractString,
        address::AbstractString;
        op::Symbol = :connect,
        policy::ND.ResolverPolicy = ND.ResolverPolicy(),
    )::Vector{NC.SocketEndpoint}
    _ = network
    _ = address
    _ = op
    _ = policy
    _nd_blocking_sleep_ms(resolver.delay_ms)
    return copy(resolver.addrs)
end

mutable struct _CountingResolver <: ND.AbstractResolver
    delay_s::Float64
    addrs::Vector{NC.SocketEndpoint}
    lock::ReentrantLock
    calls::Int
end

function _CountingResolver(delay_s::Float64, addrs::Vector{NC.SocketEndpoint})
    return _CountingResolver(delay_s, addrs, ReentrantLock(), 0)
end

function ND.resolve_tcp_addrs(
        resolver::_CountingResolver,
        network::AbstractString,
        address::AbstractString;
        op::Symbol = :connect,
        policy::ND.ResolverPolicy = ND.ResolverPolicy(),
    )::Vector{NC.SocketEndpoint}
    _ = network
    _ = address
    _ = op
    _ = policy
    lock(resolver.lock)
    try
        resolver.calls += 1
    finally
        unlock(resolver.lock)
    end
    sleep(resolver.delay_s)
    return copy(resolver.addrs)
end

mutable struct _FlappingResolver <: ND.AbstractResolver
    responses::Vector{Vector{NC.SocketEndpoint}}
    delay_s::Float64
    lock::ReentrantLock
    calls::Int
end

function _FlappingResolver(responses::Vector{Vector{NC.SocketEndpoint}}; delay_s::Float64 = 0.0)
    return _FlappingResolver(responses, delay_s, ReentrantLock(), 0)
end

function ND.resolve_tcp_addrs(
        resolver::_FlappingResolver,
        network::AbstractString,
        address::AbstractString;
        op::Symbol = :connect,
        policy::ND.ResolverPolicy = ND.ResolverPolicy(),
    )::Vector{NC.SocketEndpoint}
    _ = network
    _ = address
    _ = op
    _ = policy
    lock(resolver.lock)
    try
        resolver.calls += 1
        idx = min(resolver.calls, length(resolver.responses))
        sleep(resolver.delay_s)
        return copy(resolver.responses[idx])
    finally
        unlock(resolver.lock)
    end
end

mutable struct _ErrorResolver <: ND.AbstractResolver
    delay_s::Float64
    lock::ReentrantLock
    calls::Int
    err::Exception
end

function _ErrorResolver(err::Exception; delay_s::Float64 = 0.0)
    return _ErrorResolver(delay_s, ReentrantLock(), 0, err)
end

function ND.resolve_tcp_addrs(
        resolver::_ErrorResolver,
        network::AbstractString,
        address::AbstractString;
        op::Symbol = :connect,
        policy::ND.ResolverPolicy = ND.ResolverPolicy(),
    )::Vector{NC.SocketEndpoint}
    _ = network
    _ = address
    _ = op
    _ = policy
    lock(resolver.lock)
    try
        resolver.calls += 1
    finally
        unlock(resolver.lock)
    end
    sleep(resolver.delay_s)
    throw(resolver.err)
end

function _nd_wait_task_done(task::Task, timeout_s::Float64 = 2.0)
    return timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
end

function _nd_close_quiet!(x)
    x === nothing && return nothing
    try
        close(x)
    catch
    end
    return nothing
end

function _nd_read_exact!(conn::NC.Conn, buf::Vector{UInt8})::Int
    offset = 0
    while offset < length(buf)
        chunk = Vector{UInt8}(undef, length(buf) - offset)
        n = read!(conn, chunk)
        n > 0 || throw(EOFError())
        copyto!(buf, offset + 1, chunk, 1, n)
        offset += n
    end
    return offset
end

function _nd_ipv6_supported()::Bool
    listener = nothing
    try
        listener = NC.listen("tcp6", "[::1]:0"; backlog = 4)
        return true
    catch
        return false
    finally
        _nd_close_quiet!(listener)
    end
end

function _nd_services_candidate(proto::String)::Union{Nothing, Tuple{String, Int}}
    path = "/etc/services"
    isfile(path) || return nothing
    builtins = if proto == "tcp"
        Set(["ftp", "ftps", "gopher", "http", "https", "imap2", "imap3", "imaps", "pop3", "pop3s", "smtp", "submissions", "ssh", "telnet"])
    else
        Set(["domain"])
    end
    for raw in eachline(path)
        line = strip(raw)
        isempty(line) && continue
        startswith(line, '#') && continue
        hash_i = findfirst(==('#'), line)
        if hash_i !== nothing
            if hash_i == firstindex(line)
                continue
            end
            line = strip(line[firstindex(line):prevind(line, hash_i)])
            isempty(line) && continue
        end
        fields = split(line)
        length(fields) < 2 && continue
        portnet = fields[2]
        slash_i = findfirst(==('/'), portnet)
        slash_i === nothing && continue
        slash_i == firstindex(portnet) && continue
        slash_i == lastindex(portnet) && continue
        port = tryparse(Int, portnet[firstindex(portnet):prevind(portnet, slash_i)])
        port === nothing && continue
        (port <= 0 || port > 65535) && continue
        entry_proto = lowercase(portnet[nextind(portnet, slash_i):lastindex(portnet)])
        entry_proto == proto || continue
        for (idx, svc) in pairs(fields)
            idx == 2 && continue
            svc_l = lowercase(svc)
            in(svc_l, builtins) && continue
            return svc_l, port
        end
    end
    return nothing
end

if !(Sys.isapple() || Sys.islinux())
    @testset "HostResolvers (macOS/Linux only)" begin
        @test true
    end
else
    @testset "HostResolvers phase 5" begin
        @testset "host-port parser and joiner" begin
            host, port = ND.split_host_port("127.0.0.1:8080")
            @test host == "127.0.0.1"
            @test port == "8080"
            host, port = ND.split_host_port("[::1]:443")
            @test host == "::1"
            @test port == "443"
            host, port = ND.split_host_port("[fe80::1%lo0]:443")
            @test host == "fe80::1%lo0"
            @test port == "443"
            host, port = ND.split_host_port("golang.org:")
            @test host == "golang.org"
            @test port == ""
            host, port = ND.split_host_port("[::1]:")
            @test host == "::1"
            @test port == ""
            @test ND.join_host_port("127.0.0.1", 80) == "127.0.0.1:80"
            @test ND.join_host_port("::1", 80) == "[::1]:80"
            @test ND.join_host_port("golang.org", "https%foo") == "golang.org:https%foo"
            @test ND.join_host_port("::1", "") == "[::1]:"
            @test_throws ND.AddressError ND.split_host_port("127.0.0.1")
            @test_throws ND.AddressError ND.split_host_port("::1:443")
            @test_throws ND.AddressError ND.split_host_port("[::1]")
            @test_throws ND.AddressError ND.split_host_port("[::1]:443:80")
            @test_throws ND.AddressError ND.split_host_port("host[bad]:80")
            @test_throws ND.AddressError ND.split_host_port("host]bad:80")
        end
        @testset "literal host and scope parsing helpers" begin
            iface = Sys.isapple() ? "lo0" : "lo"
            @test ND._split_host_zone("fe80::1%$iface") == ("fe80::1", iface)
            @test ND._split_host_zone("%$iface") == ("%$iface", "")
            @test_throws ND.AddressError ND._split_host_zone("fe80::1%")

            @test ND._scope_id_from_zone("") == UInt32(0)
            @test ND._scope_id_from_zone("7") == UInt32(7)
            @test ND._scope_id_from_zone(iface) > UInt32(0)
            @test_throws ND.AddressError ND._scope_id_from_zone("-1")
            @test_throws ND.AddressError ND._scope_id_from_zone(string(UInt64(typemax(UInt32)) + UInt64(1)))
            @test_throws ND.AddressError ND._scope_id_from_zone("reseau-no-such-iface")

            scoped = ND._literal_host_addr("fe80::1%$iface")
            @test scoped isa NC.SocketAddrV6
            if scoped isa NC.SocketAddrV6
                @test scoped.scope_id == Int(ND._scope_id_from_zone(iface))
            end
            @test_throws ND.AddressError ND._literal_host_addr("127.0.0.1%$iface")
        end
        @testset "port parser and service lookup" begin
            @test ND.parse_port("80") == (80, false)
            @test ND.parse_port("+80") == (80, false)
            @test ND.parse_port("-1") == (-1, false)
            @test ND.parse_port("+") == (0, false)
            @test ND.parse_port("999999999999999999999") == (Int((UInt32(1) << 30) - UInt32(1)), false)
            @test ND.parse_port("-999999999999999999999") == (-Int(UInt32(1) << 30), false)
            @test ND.parse_port("service-name") == (0, true)
            @test ND.lookup_port("tcp", "80") == 80
            @test ND.lookup_port("ip", "domain") == 53
            @test ND.lookup_port("ip", "http") == 80
            @test ND.lookup_port("tcp", "http") == 80
            @test ND.lookup_port("udp", "domain") == 53
            tcp_candidate = _nd_services_candidate("tcp")
            if tcp_candidate !== nothing
                svc, port = tcp_candidate::Tuple{String, Int}
                @test ND.lookup_port("tcp", svc) == port
            else
                @test true
            end
            udp_candidate = _nd_services_candidate("udp")
            if udp_candidate !== nothing
                svc, port = udp_candidate::Tuple{String, Int}
                @test ND.lookup_port("udp", svc) == port
            else
                @test true
            end
            @test_throws ND.AddressError ND.lookup_port("tcp", "reseau-unknown-service")
            static_lookup = ND.StaticResolver(
                services_tcp = Dict("smtp-alt" => 2525),
                services_udp = Dict("dns-alt" => 5353),
                fallback = ND.StaticResolver(services_tcp = Dict("fallbacksvc" => 2626)),
            )
            @test ND.lookup_port(static_lookup, "udp", "dns-alt") == 5353
            @test ND.lookup_port(static_lookup, "tcp", "fallbacksvc") == 2626
            udp_fallback = ND.StaticResolver(fallback = ND.StaticResolver(services_udp = Dict("udp-fallback" => 5354)))
            @test ND.lookup_port(udp_fallback, "udp", "udp-fallback") == 5354
            @test_throws ND.AddressError ND.lookup_port("sctp", "domain")
            @test_throws ND.AddressError ND.lookup_port(static_lookup, "sctp", "smtp-alt")
        end
        @testset "resolver policies and static resolver" begin
            v4 = NC.loopback_addr(9000)
            v6 = NC.loopback_addr6(9000)
            resolver = ND.StaticResolver(
                hosts = Dict(
                    "dual.local" => NC.SocketEndpoint[v6, v4],
                    "v4.local" => NC.SocketEndpoint[v4],
                ),
                services_tcp = Dict("echo" => 9000),
            )
            addrs = ND.resolve_tcp_addrs(resolver, "tcp", "dual.local:echo")
            @test length(addrs) == 2
            @test addrs[1] isa NC.SocketAddrV6
            @test addrs[2] isa NC.SocketAddrV4
            addrs_pref = ND.resolve_tcp_addrs(
                resolver,
                "tcp",
                "dual.local:echo";
                policy = ND.ResolverPolicy(; prefer_ipv6 = true, allow_ipv4 = true, allow_ipv6 = true),
            )
            @test addrs_pref[1] isa NC.SocketAddrV6
            addrs_v4_only = ND.resolve_tcp_addrs(
                resolver,
                "tcp",
                "DUAL.LOCAL:echo";
                policy = ND.ResolverPolicy(; allow_ipv4 = true, allow_ipv6 = false),
            )
            @test length(addrs_v4_only) == 1
            @test addrs_v4_only[1] isa NC.SocketAddrV4
            @test_throws ND.AddressError ND.resolve_tcp_addrs(
                resolver,
                "tcp",
                "v4.local:echo";
                policy = ND.ResolverPolicy(; allow_ipv4 = false, allow_ipv6 = true),
            )
            @test ND._resolve_static_host(resolver, "tcp", "DUAL.LOCAL") == NC.SocketEndpoint[v6, v4]
            fallback_only = ND.StaticResolver(fallback = ND.StaticResolver(hosts = Dict("fallback.only" => NC.SocketEndpoint[NC.loopback_addr(9090)])))
            @test ND._resolve_static_host(fallback_only, "tcp", "fallback.only") == NC.SocketEndpoint[NC.loopback_addr(9090)]
            @test_throws ND.AddressError ND._resolve_static_host(ND.StaticResolver(), "tcp", "missing.static.test")
        end
        @testset "wildcard ordering and self-connect helper" begin
            listen_addrs = ND.resolve_tcp_addrs(ND.DEFAULT_RESOLVER, "tcp", ":0"; op = :listen)
            @test length(listen_addrs) == 2
            @test listen_addrs[1] isa NC.SocketAddrV6
            @test listen_addrs[2] isa NC.SocketAddrV4
            connect_addrs = ND.resolve_tcp_addrs(ND.DEFAULT_RESOLVER, "tcp", ":0"; op = :connect)
            @test length(connect_addrs) == 2
            @test connect_addrs[1] isa NC.SocketAddrV4
            @test connect_addrs[2] isa NC.SocketAddrV6
            fake_fd = NC._new_netfd(Cint(-1))
            fake_fd.laddr = NC.loopback_addr(5000)
            fake_fd.raddr = NC.loopback_addr(5000)
            @test ND._is_self_connect(NC.Conn(fake_fd))
            fake_fd.raddr = NC.loopback_addr(5001)
            @test !ND._is_self_connect(NC.Conn(fake_fd))
        end
        @testset "host resolver internal helper utilities" begin
            @test ND._normalize_lookup_host("Example.COM..") == "example.com"
            @test ND._lookup_key("TCP", "Example.COM.") == ("tcp", "example.com")
            @test ND._min_nonzero(Int64(0), Int64(9)) == Int64(9)
            @test ND._min_nonzero(Int64(7), Int64(0)) == Int64(7)
            @test ND._min_nonzero(Int64(7), Int64(9)) == Int64(7)
            @test ND._effective_fallback_delay_ns(ND.HostResolver(fallback_delay_ns = 123)) == Int64(123)
            @test ND._effective_fallback_delay_ns(ND.HostResolver(fallback_delay_ns = 0)) == Int64(300_000_000)
            @test !ND._use_parallel_race(ND.HostResolver(fallback_delay_ns = -1), :tcp, NC.SocketEndpoint[NC.loopback_addr6(80)])
            @test ND._use_parallel_race(ND.HostResolver(fallback_delay_ns = 1), :tcp, NC.SocketEndpoint[NC.loopback_addr6(80)])

            scoped_addr = NC.SocketAddrV6(NC.loopback_addr6(1234).ip, 1234; scope_id = 7)
            scoped_ips = ND._resolve_host_ips(_SlowResolver(0.0, NC.SocketEndpoint[scoped_addr]), "tcp", "ignored.host")
            @test scoped_ips == NC.SocketEndpoint[NC.SocketAddrV6(scoped_addr.ip, 0; scope_id = 7)]
        end
        @testset "system resolver parity guards" begin
            @test ND._HR_AF_INET == SO.AF_INET
            @test ND._HR_AF_INET6 == SO.AF_INET6
            native = ND._native_getaddrinfo("localhost"; flags = ND._AI_ALL | ND._AI_V4MAPPED)
            @test all(x -> x isa NC.SocketEndpoint, native)
            addrs = ND.resolve_tcp_addrs("tcp", "localhost:80")
            @test any(a -> a isa NC.SocketAddrV4, addrs)
            if _nd_ipv6_supported()
                @test any(a -> a isa NC.SocketAddrV6, addrs)
            end
            bad_host_err = try
                ND.resolve_tcp_addrs("tcp", "reseau-invalid-hostname-for-tests.invalid:80")
                nothing
            catch ex
                ex
            end
            @test bad_host_err isa ND.AddressError
            if bad_host_err isa ND.AddressError
                @test occursin("lookup failed", bad_host_err.err)
            end
        end
        @testset "connect/listen by address strings (ipv4)" begin
            EL.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            accept_task = nothing
            try
                listener = NC.listen("tcp", "127.0.0.1:0"; backlog = 16)
                laddr = NC.addr(listener)
                accept_task = errormonitor(Threads.@spawn NC.accept(listener))
                client = NC.connect("tcp", ND.join_host_port("127.0.0.1", Int((laddr::NC.SocketAddrV4).port)); timeout_ns = 1_000_000_000)
                status = _nd_wait_task_done(accept_task, 2.0)
                @test status != :timed_out
                server = fetch(accept_task)
                payload = UInt8[0x41, 0x42, 0x43, 0x44]
                @test write(client, payload) == length(payload)
                recv_buf = Vector{UInt8}(undef, length(payload))
                @test _nd_read_exact!(server, recv_buf) == length(payload)
                @test recv_buf == payload
            finally
                _nd_close_quiet!(server)
                _nd_close_quiet!(client)
                _nd_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "happy-eyeballs fallback launches immediately after primary error" begin
            EL.shutdown!()
            listener = nothing
            connected = nothing
            accepted = nothing
            try
                listener = NC.listen("tcp4", "127.0.0.1:0"; backlog = 16)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                port = Int(laddr.port)
                resolver = ND.StaticResolver(
                    hosts = Dict(
                        "dual.test" => NC.SocketEndpoint[
                            NC.loopback_addr6(port),
                            NC.loopback_addr(port),
                        ],
                    ),
                )
                warm_accept = errormonitor(Threads.@spawn NC.accept(listener))
                warm_client = NC.connect("tcp", "dual.test:$port"; resolver = resolver, fallback_delay_ns = 1_000_000)
                @test _nd_wait_task_done(warm_accept, 2.0) != :timed_out
                warm_server = fetch(warm_accept)
                _nd_close_quiet!(warm_server)
                _nd_close_quiet!(warm_client)
                accept_task = errormonitor(Threads.@spawn NC.accept(listener))
                connect_task = errormonitor(Threads.@spawn NC.connect("tcp", "dual.test:$port"; resolver = resolver, fallback_delay_ns = 5_000_000_000))
                @test _nd_wait_task_done(connect_task, 1.5) != :timed_out
                @test _nd_wait_task_done(accept_task, 1.5) != :timed_out
                connected = fetch(connect_task)
                accepted = fetch(accept_task)
                @test connected isa NC.Conn
                @test accepted isa NC.Conn
            finally
                _nd_close_quiet!(accepted)
                _nd_close_quiet!(connected)
                _nd_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "parallel race returns wrapped error when both families fail" begin
            if !_nd_ipv6_supported()
                @test true
            else
                EL.shutdown!()
                listener = nothing
                try
                    listener = NC.listen("tcp4", "127.0.0.1:0"; backlog = 4)
                    port = Int((NC.addr(listener)::NC.SocketAddrV4).port)
                    close(listener)
                    listener = nothing
                    resolver = ND.StaticResolver(hosts = Dict(
                        "dual-fail.test" => NC.SocketEndpoint[
                            NC.loopback_addr6(port),
                            NC.loopback_addr(port),
                        ],
                    ))
                    err = try
                        NC.connect("tcp", "dual-fail.test:$port"; resolver = resolver, timeout_ns = 500_000_000, fallback_delay_ns = 1_000_000)
                        nothing
                    catch ex
                        ex
                    end
                    @test err isa ND.DNSOpError
                    if err isa ND.DNSOpError
                        @test err.err isa Exception
                        @test err.addr !== nothing
                    end
                finally
                    _nd_close_quiet!(listener)
                    EL.shutdown!()
                end
            end
        end
        @testset "ipv6 connect/listen path" begin
            if !_nd_ipv6_supported()
                @test true
            else
                EL.shutdown!()
                listener = nothing
                client = nothing
                server = nothing
                accept_task = nothing
                try
                    listener = NC.listen("tcp6", "[::1]:0"; backlog = 16)
                    laddr = NC.addr(listener)::NC.SocketAddrV6
                    accept_task = errormonitor(Threads.@spawn NC.accept(listener))
                    client = NC.connect("tcp6", ND.join_host_port("::1", Int(laddr.port)); timeout_ns = 1_000_000_000)
                    @test _nd_wait_task_done(accept_task, 2.0) != :timed_out
                    server = fetch(accept_task)
                    payload = UInt8[0x90, 0x91, 0x92]
                    @test write(client, payload) == length(payload)
                    recv_buf = Vector{UInt8}(undef, length(payload))
                    @test _nd_read_exact!(server, recv_buf) == length(payload)
                    @test recv_buf == payload
                finally
                    _nd_close_quiet!(server)
                    _nd_close_quiet!(client)
                    _nd_close_quiet!(listener)
                    EL.shutdown!()
                end
            end
        end
        @testset "error typing and wrapping (phase 5C)" begin
            slow_resolver = _SlowResolver(0.25, NC.SocketEndpoint[NC.loopback_addr(1)])
            started_ns = time_ns()
            timeout_err = try
                NC.connect("tcp", "slow.local:80"; timeout_ns = 20_000_000, resolver = slow_resolver)
                nothing
            catch ex
                ex
            end
            elapsed_ms = (time_ns() - started_ns) / 1.0e6
            @test timeout_err isa ND.DNSOpError
            if timeout_err isa ND.DNSOpError
                @test timeout_err.err isa ND.DNSTimeoutError
            end
            @test elapsed_ms < 1_000.0
            threadcall_resolver = _ThreadcallResolver(UInt32(250), NC.SocketEndpoint[NC.loopback_addr(1)])
            threadcall_started_ns = time_ns()
            threadcall_timeout_err = try
                NC.connect("tcp", "threadcall.local:80"; timeout_ns = 20_000_000, resolver = threadcall_resolver)
                nothing
            catch ex
                ex
            end
            threadcall_elapsed_ms = (time_ns() - threadcall_started_ns) / 1.0e6
            @test threadcall_timeout_err isa ND.DNSOpError
            if threadcall_timeout_err isa ND.DNSOpError
                @test threadcall_timeout_err.err isa ND.DNSTimeoutError
            end
            @test threadcall_elapsed_ms < 1_000.0
            empty_net_err = try
                ND.resolve_tcp_addrs("", "127.0.0.1:1")
                nothing
            catch ex
                ex
            end
            @test empty_net_err isa ND.UnknownNetworkError
            err_unknown = try
                NC.connect("udp", "127.0.0.1:1")
                nothing
            catch ex
                ex
            end
            @test err_unknown isa ND.DNSOpError
            if err_unknown isa ND.DNSOpError
                @test err_unknown.err isa ND.UnknownNetworkError
            end
            err_bad_addr = try
                NC.listen("tcp", "bad-address")
                nothing
            catch ex
                ex
            end
            @test err_bad_addr isa ND.DNSOpError
            if err_bad_addr isa ND.DNSOpError
                @test err_bad_addr.err isa ND.AddressError
            end
            past_deadline = Int64(time_ns()) - Int64(1)
            err_timeout = try
                NC.connect("tcp", "127.0.0.1:1"; deadline_ns = past_deadline)
                nothing
            catch ex
                ex
            end
            @test err_timeout isa ND.DNSOpError
            if err_timeout isa ND.DNSOpError
                @test err_timeout.err isa ND.DNSTimeoutError
            end
        end
        @testset "singleflight resolver coalesces duplicate concurrent lookups" begin
            EL.shutdown!()
            listener = nothing
            client1 = nothing
            client2 = nothing
            try
                listener = NC.listen("tcp", "127.0.0.1:0"; backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                resolver = _CountingResolver(0.05, NC.SocketEndpoint[NC.loopback_addr(Int(laddr.port))])
                singleflight = ND.SingleflightResolver(resolver)
                accept_task = errormonitor(Threads.@spawn begin
                    conn_a = NC.accept(listener)
                    conn_b = NC.accept(listener)
                    return conn_a, conn_b
                end)
                task1 = errormonitor(Threads.@spawn NC.connect("tcp", "same.test:$(Int(laddr.port))"; resolver = singleflight, timeout_ns = 1_000_000_000, fallback_delay_ns = -1))
                task2 = errormonitor(Threads.@spawn NC.connect("tcp", "same.test:$(Int(laddr.port))"; resolver = singleflight, timeout_ns = 1_000_000_000, fallback_delay_ns = -1))
                @test _nd_wait_task_done(task1, 2.0) != :timed_out
                @test _nd_wait_task_done(task2, 2.0) != :timed_out
                client1 = fetch(task1)
                client2 = fetch(task2)
                server1, server2 = fetch(accept_task)
                _nd_close_quiet!(server2)
                _nd_close_quiet!(server1)
                @test resolver.calls == 1
                @test (@atomic :acquire singleflight.actual_lookups) == 1
                @test (@atomic :acquire singleflight.shared_hits) == 1
            finally
                _nd_close_quiet!(client2)
                _nd_close_quiet!(client1)
                _nd_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "caching resolver fresh/stale/negative behavior" begin
            addr_a = NC.loopback_addr(1111)
            addr_b = NC.loopback_addr(2222)

            fresh_parent = _CountingResolver(0.0, NC.SocketEndpoint[addr_a])
            fresh_cache = ND.CachingResolver(fresh_parent; ttl_ns = 1_000_000_000, stale_ttl_ns = 0, negative_ttl_ns = 0, max_hosts = 8)
            @test ND.resolve_tcp_addrs(fresh_cache, "tcp", "cache.test:80") == NC.SocketEndpoint[NC.SocketAddrV4(addr_a.ip, 80)]
            @test ND.resolve_tcp_addrs(fresh_cache, "tcp", "cache.test:80") == NC.SocketEndpoint[NC.SocketAddrV4(addr_a.ip, 80)]
            @test fresh_parent.calls == 1
            @test (@atomic :acquire fresh_cache.cache_hits) == 1

            stale_parent = _FlappingResolver([NC.SocketEndpoint[addr_a], NC.SocketEndpoint[addr_b]]; delay_s = 0.02)
            stale_cache = ND.CachingResolver(stale_parent; ttl_ns = 10_000_000, stale_ttl_ns = 200_000_000, negative_ttl_ns = 0, max_hosts = 8)
            first = ND.resolve_tcp_addrs(stale_cache, "tcp", "stale.test:80")
            sleep(0.02)
            second = ND.resolve_tcp_addrs(stale_cache, "tcp", "stale.test:80")
            @test first == NC.SocketEndpoint[NC.SocketAddrV4(addr_a.ip, 80)]
            @test second == NC.SocketEndpoint[NC.SocketAddrV4(addr_a.ip, 80)]
            @test (@atomic :acquire stale_cache.stale_hits) == 1
            @test timedwait(() -> stale_parent.calls >= 2, 2.0; pollint = 0.001) != :timed_out
            third = ND.resolve_tcp_addrs(stale_cache, "tcp", "stale.test:80")
            @test third == NC.SocketEndpoint[NC.SocketAddrV4(addr_b.ip, 80)]

            evict_parent = _CountingResolver(0.0, NC.SocketEndpoint[addr_a])
            evict_cache = ND.CachingResolver(evict_parent; ttl_ns = 1_000_000_000, stale_ttl_ns = 0, negative_ttl_ns = 0, max_hosts = 1)
            ND.resolve_tcp_addrs(evict_cache, "tcp", "host-one.test:80")
            ND.resolve_tcp_addrs(evict_cache, "tcp", "host-two.test:80")
            ND.resolve_tcp_addrs(evict_cache, "tcp", "host-one.test:80")
            @test evict_parent.calls == 3

            neg_parent = _ErrorResolver(ND.AddressError("lookup failed", "neg.test"); delay_s = 0.0)
            neg_cache = ND.CachingResolver(neg_parent; ttl_ns = 0, stale_ttl_ns = 0, negative_ttl_ns = 50_000_000, max_hosts = 8)
            err1 = try
                ND.resolve_tcp_addrs(neg_cache, "tcp", "neg.test:80")
                nothing
            catch ex
                ex
            end
            err2 = try
                ND.resolve_tcp_addrs(neg_cache, "tcp", "neg.test:80")
                nothing
            catch ex
                ex
            end
            @test err1 isa ND.AddressError
            @test err2 isa ND.AddressError
            @test neg_parent.calls == 1
            @test (@atomic :acquire neg_cache.negative_hits) == 1
            sleep(0.06)
            err3 = try
                ND.resolve_tcp_addrs(neg_cache, "tcp", "neg.test:80")
                nothing
            catch ex
                ex
            end
            @test err3 isa ND.AddressError
            @test neg_parent.calls == 2
        end
        @testset "singleflight and cache refresh error paths" begin
            err_resolver = _ErrorResolver(ND.AddressError("lookup failed", "singleflight-error.test"); delay_s = 0.02)
            singleflight = ND.SingleflightResolver(err_resolver)
            task1 = errormonitor(Threads.@spawn try
                ND._resolve_host_ips(singleflight, "tcp", "singleflight-error.test")
            catch ex
                ex
            end)
            task2 = errormonitor(Threads.@spawn try
                ND._resolve_host_ips(singleflight, "tcp", "singleflight-error.test")
            catch ex
                ex
            end)
            @test _nd_wait_task_done(task1, 2.0) != :timed_out
            @test _nd_wait_task_done(task2, 2.0) != :timed_out
            @test fetch(task1) isa ND.AddressError
            @test fetch(task2) isa ND.AddressError
            @test err_resolver.calls == 1
            @test (@atomic :acquire singleflight.actual_lookups) == 1
            @test (@atomic :acquire singleflight.shared_hits) == 1

            refresh_parent = _ErrorResolver(ND.AddressError("lookup failed", "refresh.test"); delay_s = 0.0)
            refresh_cache = ND.CachingResolver(refresh_parent; ttl_ns = 1_000_000, stale_ttl_ns = 50_000_000, negative_ttl_ns = 50_000_000, max_hosts = 8)
            key = ND._lookup_key("tcp", "refresh.test")
            old_now_ns = Int64(time_ns()) - Int64(100_000_000)
            lock(refresh_cache.lock)
            try
                ND._store_cache_entry_locked!(refresh_cache, key, NC.SocketEndpoint[NC.loopback_addr(4040)], nothing, old_now_ns)
                refresh_cache.entries[key].refreshing = true
            finally
                unlock(refresh_cache.lock)
            end
            ND._refresh_cached_host!(refresh_cache, key, "tcp", "refresh.test")
            lock(refresh_cache.lock)
            try
                entry = refresh_cache.entries[key]
                @test !entry.refreshing
                @test entry.err isa ND.AddressError
                @test entry.result === nothing
            finally
                unlock(refresh_cache.lock)
            end
        end
        @testset "DNS race wait registration helpers" begin
            fd = nothing
            try
                fd = NC.open_tcp_fd!()
                IP.register!(fd.pfd)
                state = ND.DNSRaceState()
                NC._connect_wait_register!(state, fd)
                @test length(state.wait_fds) == 1
                @test ND._mark_connect_done!(state)
                @test (@atomic :acquire state.done)
                @test isempty(state.wait_fds)
                @test !ND._mark_connect_done!(state)

                state_done = ND.DNSRaceState()
                @atomic :release state_done.done = true
                NC._connect_wait_register!(state_done, fd)
                @test isempty(state_done.wait_fds)

                state_unregister = ND.DNSRaceState()
                NC._connect_wait_register!(state_unregister, fd)
                @test length(state_unregister.wait_fds) == 1
                NC._connect_wait_unregister!(state_unregister, fd)
                @test isempty(state_unregister.wait_fds)
            finally
                if fd !== nothing
                    try
                        close(fd)
                    catch
                    end
                end
                EL.shutdown!()
            end
        end
    end
end
