# Exercise future deadlines and resolver task bodies in compiled executables.

using Reseau

const NC = Reseau.TCP
const IP = Reseau.IOPoll
const ND = Reseau.HostResolvers

const LISTENER = Ref{Union{Nothing, NC.Listener}}(nothing)
const SERVER_ERROR = Ref{Any}(nothing)
const SHUTTING_DOWN = Ref(false)

# echo server task body: named + registered so a trimmed build compiles it
function _echo_server_entry()::Nothing
    conn = nothing
    try
        conn = NC.accept(LISTENER[]::NC.Listener)
        buf = Vector{UInt8}(undef, 1)
        while true
            read!(conn, buf)
            write(conn, buf)
        end
    catch err
        # any error after the client/listener started closing is normal shutdown
        (SHUTTING_DOWN[] || err isa EOFError) || (SERVER_ERROR[] = err)
    finally
        conn === nothing || close(conn)
    end
    return nothing
end

Base.Experimental.entrypoint(_echo_server_entry, ())

function _with_echo_server(f::F)::Nothing where {F}
    listener = NC.listen(NC.loopback_addr(0))
    port = Int((NC.addr(listener)::NC.SocketAddrV4).port)
    LISTENER[] = listener
    SERVER_ERROR[] = nothing
    SHUTTING_DOWN[] = false
    task = Task(_echo_server_entry)
    schedule(task)
    try
        f(port)
    finally
        SHUTTING_DOWN[] = true
        close(listener)
        wait(task)
        LISTENER[] = nothing
    end
    err = SERVER_ERROR[]
    err === nothing || throw(err::Exception)
    return nothing
end

# 1. The dial path with a relative timeout: resolution + connect run under a deadline.
function run_dial_deadline()::Nothing
    _with_echo_server() do port
        conn = NC.connect("127.0.0.1:$port"; timeout_ns = Int64(10_000_000_000))
        try
            write(conn, UInt8[0x2a]) == 1 || error("dial-deadline write failed")
            buf = Vector{UInt8}(undef, 1)
            read!(conn, buf)
            buf[1] == 0x2a || error("dial-deadline echo mismatch")
        finally
            close(conn)
        end
    end
    Core.println("dial-deadline ok")
    return nothing
end

# 2. A read deadline in the future that must FIRE while the task is parked.
function run_read_deadline_fires()::Nothing
    _with_echo_server() do port
        conn = NC.connect(NC.loopback_addr(port))
        try
            NC.set_read_deadline!(conn, Int64(time_ns()) + Int64(300_000_000))
            start = time_ns()
            buf = Vector{UInt8}(undef, 1)
            err = try
                read!(conn, buf)   # the server echoes only after receiving a byte; none sent
                nothing
            catch e
                e
            end
            elapsed_ms = (time_ns() - start) ÷ 1_000_000
            err isa IP.DeadlineExceededError || error("expected DeadlineExceededError, got $(typeof(err))")
            150 <= elapsed_ms || error("read deadline fired too early after $(elapsed_ms)ms")
        finally
            close(conn)
        end
    end
    Core.println("read-deadline ok")
    return nothing
end

# 3. A future read deadline armed while data arrives: readiness must win over the deadline.
function run_read_deadline_wake()::Nothing
    _with_echo_server() do port
        conn = NC.connect(NC.loopback_addr(port))
        try
            NC.set_read_deadline!(conn, Int64(time_ns()) + Int64(10_000_000_000))
            write(conn, UInt8[0x11]) == 1 || error("read-wake write failed")
            buf = Vector{UInt8}(undef, 1)
            read!(conn, buf)   # parks until the echo arrives, deadline armed
            buf[1] == 0x11 || error("read-wake echo mismatch")
            NC.set_read_deadline!(conn, Int64(0))
        finally
            close(conn)
        end
    end
    Core.println("read-wake ok")
    return nothing
end

# 4. The poller's native timer machinery: schedule 200ms out and wait for the firing.
function run_timer()::Nothing
    deadline = Int64(time_ns()) + Int64(200_000_000)
    timer = IP.TimerState(deadline, Int64(0))
    IP.schedule_timer!(timer, deadline) || error("schedule_timer! refused")
    start = time_ns()
    fired = IP.waittimer(timer)
    elapsed_ms = (time_ns() - start) ÷ 1_000_000
    fired || error("timer was cancelled instead of firing")
    100 <= elapsed_ms || error("timer fired too early after $(elapsed_ms)ms")
    Core.println("timer ok")
    return nothing
end

struct _BlockedTrimResolver <: ND.AbstractResolver
    release::Channel{Nothing}
    exited::Channel{Nothing}
end

function ND.resolve_tcp_addrs(resolver::_BlockedTrimResolver, network::AbstractString, address::AbstractString; kwargs...)
    try
        take!(resolver.release)
        return NC.SocketAddrV4[NC.loopback_addr(1)]
    finally
        put!(resolver.exited, nothing)
    end
end

function run_resolver_timeout()::Nothing
    resolver = _BlockedTrimResolver(Channel{Nothing}(1), Channel{Nothing}(1))
    try
        err = try
            NC.connect("blocked.test:1"; resolver, timeout_ns=Int64(100_000_000))
            nothing
        catch ex
            ex
        end
        err isa ND.OpError || error("expected a wrapped resolver timeout")
        err.err isa ND.DialTimeoutError || error("expected DialTimeoutError")
    finally
        put!(resolver.release, nothing)
        take!(resolver.exited)
    end
    Core.println("resolver-timeout ok")
    return nothing
end

function run_parallel_dial()::Nothing
    listener = NC.listen(NC.loopback_addr(0))
    port = Int((NC.addr(listener)::NC.SocketAddrV4).port)
    client = server = nothing
    resolver = ND.StaticResolver(hosts=Dict("dual.test" => NC.SocketEndpoint[NC.loopback_addr6(0), NC.loopback_addr(0)]))
    try
        client = NC.connect("dual.test:$port"; resolver,
            policy=ND.ResolverPolicy(prefer_ipv6=true),
            timeout_ns=Int64(10_000_000_000), fallback_delay_ns=Int64(1_000_000))
        server = NC.accept(listener)
        write(client, UInt8[0x42]) == 1 || error("parallel dial write failed")
        read(server, UInt8) == 0x42 || error("parallel dial payload mismatch")
    finally
        client === nothing || close(client)
        server === nothing || close(server)
        close(listener)
    end
    Core.println("parallel-dial ok")
    return nothing
end

function run_cache_refresh()::Nothing
    parent = ND.StaticResolver(hosts=Dict("refresh.test" => NC.SocketEndpoint[NC.loopback_addr(0)]))
    resolver = ND.CachingResolver(parent; ttl_ns=10_000_000_000, stale_ttl_ns=10_000_000_000)
    expected = ND.resolve_tcp_addrs(resolver, "tcp", "refresh.test:80")
    key = ND._lookup_key("tcp", "refresh.test")
    lock(resolver.lock)
    try
        resolver.entries[key].expires_ns = 0
        resolver.entries[key].stale_expires_ns = typemax(Int64)
    finally
        unlock(resolver.lock)
    end
    ND.resolve_tcp_addrs(resolver, "tcp", "refresh.test:80") == expected || error("stale cache result changed")
    while true
        lock(resolver.lock)
        done = try
            !resolver.entries[key].refreshing
        finally
            unlock(resolver.lock)
        end
        done && break
        yield()
    end
    ND.resolve_tcp_addrs(resolver, "tcp", "refresh.test:80") == expected || error("refreshed cache result changed")
    Core.println("cache-refresh ok")
    return nothing
end

function run_case(case::String)::Nothing
    if case == "dial"
        run_dial_deadline()
    elseif case == "read-deadline"
        run_read_deadline_fires()
    elseif case == "read-wake"
        run_read_deadline_wake()
    elseif case == "timer"
        run_timer()
    elseif case == "resolver-timeout"
        run_resolver_timeout()
    elseif case == "parallel-dial"
        run_parallel_dial()
    elseif case == "cache-refresh"
        run_cache_refresh()
    elseif case == "all"
        run_timer()
        run_read_deadline_wake()
        run_read_deadline_fires()
        run_dial_deadline()
        run_resolver_timeout()
        run_parallel_dial()
        run_cache_refresh()
        Core.println("deadline trim workload passed")
    else
        error("unknown case $case")
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    run_case(isempty(args) ? "all" : args[1])
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
