using Test

module Reseau

module IOPoll

export DeadlineExceededError, FD, TimerState, schedule_timer!, waittimer, _close_timer!, sleep

struct DeadlineExceededError <: Exception end

module PollWaiterState
Base.@enum T::UInt8 begin
    EMPTY = 0x00
    WAITING = 0x01
    NOTIFIED = 0x02
end
end

module PollWakeReason
Base.@enum T::UInt8 begin
    READY = 0x01
    CANCELED = 0x02
end
end

mutable struct PollWaiter
    @atomic state::PollWaiterState.T
    @atomic reason::PollWakeReason.T
    task::Union{Nothing, Task}
    function PollWaiter()
        return new(PollWaiterState.EMPTY, PollWakeReason.READY, nothing)
    end
end

mutable struct PollState
    lock::ReentrantLock
    sysfd::Int32
    token::UInt64
    @atomic pollable::Bool
    @atomic closing::Bool
    @atomic event_err::Bool
    @atomic rd_ns::Int64
    @atomic wd_ns::Int64
    @atomic rseq::UInt64
    @atomic wseq::UInt64
    function PollState(sysfd::Integer = -1, token::UInt64 = UInt64(0))
        return new(
            ReentrantLock(),
            Int32(sysfd),
            token,
            false,
            false,
            false,
            Int64(0),
            Int64(0),
            UInt64(0),
            UInt64(0),
        )
    end
end

mutable struct FD
    sysfd::Int32
    pd::PollState
    csema::Base.Semaphore
    @atomic is_blocking::Bool
    is_stream::Bool
    zero_read_is_eof::Bool
    is_file::Bool
    function FD(
            sysfd::Integer;
            is_stream::Bool = true,
            zero_read_is_eof::Bool = true,
            is_file::Bool = false,
        )
        return new(
            Int32(sysfd),
            PollState(sysfd),
            Base.Semaphore(0),
            false,
            is_stream,
            zero_read_is_eof,
            is_file,
        )
    end
end

mutable struct TimerState
    lock::ReentrantLock
    waiter::PollWaiter
    @atomic deadline_ns::Int64
    @atomic interval_ns::Int64
    @atomic seq::UInt64
    @atomic closed::Bool
    function TimerState(deadline_ns::Int64 = Int64(0), interval_ns::Int64 = Int64(0))
        return new(ReentrantLock(), PollWaiter(), deadline_ns, interval_ns, UInt64(0), false)
    end
end

function register!(pfd::FD)
    @atomic :release pfd.pd.pollable = true
    return nothing
end

function set_write_deadline!(pfd::FD, deadline_ns::Int64)
    @atomic :release pfd.pd.wd_ns = deadline_ns
    return nothing
end

connect!(pfd::FD, addrbuf, addrlen) = nothing
waitwrite(pd::PollState) = nothing
schedule_timer!(timer::TimerState, deadline_ns::Int64) = true
waittimer(timer::TimerState) = false
_close_timer!(timer::TimerState) = nothing
sleep(seconds::Real) = nothing

end

module SocketOps

export AF_INET, AF_INET6, SOCK_STREAM, open_socket, bind_socket, set_nonblocking!, sockaddr_bytes

const AF_INET = Int32(2)
const AF_INET6 = Int32(23)
const SOCK_STREAM = Int32(1)

open_socket(family::Int32, sotype::Int32) = Int32(1)
bind_socket(sysfd::Int32, sockaddr) = nothing
set_nonblocking!(sysfd::Int32, enabled::Bool) = nothing
sockaddr_bytes(sockaddr) = UInt8[0x00]

end

module TCP

using ..IOPoll
using ..SocketOps

export connect, SocketAddr, SocketAddrV4, SocketAddrV6, SocketEndpoint, Conn, ConnectCanceledError, loopback_addr, loopback_addr6, _connect_socketaddr_impl

function connect end

abstract type SocketAddr end

struct SocketAddrV4 <: SocketAddr
    ip::NTuple{4, UInt8}
    port::UInt16
end

struct SocketAddrV6 <: SocketAddr
    ip::NTuple{16, UInt8}
    port::UInt16
    scope_id::UInt32
end

const SocketEndpoint = Union{SocketAddrV4, SocketAddrV6}

mutable struct FD
    pfd::IOPoll.FD
    family::Int32
    sotype::Int32
    net::Symbol
    @atomic is_connected::Bool
    laddr::Union{Nothing, SocketAddr}
    raddr::Union{Nothing, SocketAddr}
end

struct Conn
    fd::FD
end

struct ConnectCanceledError <: Exception end

function loopback_addr(port::Integer)::SocketAddrV4
    return SocketAddrV4((UInt8(127), UInt8(0), UInt8(0), UInt8(1)), UInt16(port))
end

function loopback_addr6(port::Integer; scope_id::Integer = 0)::SocketAddrV6
    return SocketAddrV6((
            UInt8(0), UInt8(0), UInt8(0), UInt8(0),
            UInt8(0), UInt8(0), UInt8(0), UInt8(0),
            UInt8(0), UInt8(0), UInt8(0), UInt8(0),
            UInt8(0), UInt8(0), UInt8(0), UInt8(1),
        ),
        UInt16(port),
        UInt32(scope_id),
    )
end

@inline _connect_canceled(::Nothing)::Bool = false
@inline _connect_canceled(::Any)::Bool = false
@inline _connect_wait_register!(::Any, ::FD) = nothing
@inline _connect_wait_unregister!(::Any, ::FD) = nothing
@inline _addr_family(::SocketAddrV4)::Int32 = SocketOps.AF_INET
@inline _addr_family(::SocketAddrV6)::Int32 = SocketOps.AF_INET6
@inline _to_sockaddr(addr::SocketAddr) = addr

function _new_netfd(
        sysfd::Int32;
        family::Int32 = SocketOps.AF_INET,
        sotype::Int32 = SocketOps.SOCK_STREAM,
        net::Symbol = :tcp,
        is_connected::Bool = false,
    )::FD
    return FD(IOPoll.FD(sysfd), family, sotype, net, is_connected, nothing, nothing)
end

function _finalize_connected_addrs!(fd::FD, fallback_remote::SocketAddr)
    fd.raddr = fallback_remote
    @atomic :release fd.is_connected = true
    return nothing
end

_apply_default_tcp_opts!(fd::FD) = nothing

function _wait_connect_complete!(
        fd::FD,
        remote_addr::SocketAddr,
        cancel_state = nothing,
    )
    _connect_wait_register!(cancel_state, fd)
    try
        @static if Sys.iswindows()
            sockaddr = _to_sockaddr(remote_addr)
            addrbuf = SocketOps.sockaddr_bytes(sockaddr)
            addrlen = Int32(1)
            while true
                if _connect_canceled(cancel_state)
                    throw(ConnectCanceledError())
                end
                try
                    IOPoll.connect!(fd.pfd, addrbuf, addrlen)
                catch err
                    ex = err::Exception
                    if ex isa IOPoll.DeadlineExceededError && _connect_canceled(cancel_state)
                        throw(ConnectCanceledError())
                    end
                    rethrow(ex)
                end
                _finalize_connected_addrs!(fd, remote_addr)
                return nothing
            end
        end
        while true
            if _connect_canceled(cancel_state)
                throw(ConnectCanceledError())
            end
            try
                IOPoll.waitwrite(fd.pfd)
            catch err
                ex = err::Exception
                if ex isa IOPoll.DeadlineExceededError && _connect_canceled(cancel_state)
                    throw(ConnectCanceledError())
                end
                rethrow(ex)
            end
            _finalize_connected_addrs!(fd, remote_addr)
            return nothing
        end
    finally
        _connect_wait_unregister!(cancel_state, fd)
    end
end

@inline function _bind_connectex_local!(fd::FD, family::Int32)
    _ = fd
    _ = family
    return nothing
end

function open_tcp_fd!(; family::Int32 = SocketOps.AF_INET)::FD
    sysfd = SocketOps.open_socket(family, SocketOps.SOCK_STREAM)
    return _new_netfd(sysfd; family = family, sotype = SocketOps.SOCK_STREAM, net = :tcp, is_connected = false)
end

function _connect_socketaddr_impl(
        remote_addr::SocketAddr,
        local_addr::Union{Nothing, SocketAddr},
        attempt_deadline::Int64,
        state,
    )::Conn
    family = _addr_family(remote_addr)
    if local_addr !== nothing && _addr_family(local_addr) != family
        throw(ArgumentError("local and remote address families must match"))
    end
    fd = open_tcp_fd!(; family = family)
    try
        if local_addr !== nothing
            SocketOps.bind_socket(fd.pfd.sysfd, _to_sockaddr(local_addr))
        elseif Sys.iswindows()
            _bind_connectex_local!(fd, family)
        end
        SocketOps.set_nonblocking!(fd.pfd.sysfd, true)
        @static if Sys.iswindows()
            IOPoll.register!(fd.pfd)
            if attempt_deadline != 0
                IOPoll.set_write_deadline!(fd.pfd, attempt_deadline)
            end
            try
                _wait_connect_complete!(fd, remote_addr, state)
            finally
                if attempt_deadline != 0
                    try
                        IOPoll.set_write_deadline!(fd.pfd, Int64(0))
                    catch
                    end
                end
            end
            _apply_default_tcp_opts!(fd)
            return Conn(fd)
        end
        IOPoll.register!(fd.pfd)
        _wait_connect_complete!(fd, remote_addr, state)
        _apply_default_tcp_opts!(fd)
        return Conn(fd)
    catch
        close(fd)
        rethrow()
    end
end

function connect(remote_addr::SocketAddr)::Conn
    return _connect_socketaddr_impl(remote_addr, nothing, Int64(0), nothing)
end

function connect(remote_addr::SocketAddr, local_addr::Union{Nothing, SocketAddr})::Conn
    return _connect_socketaddr_impl(remote_addr, local_addr, Int64(0), nothing)
end

end

Base.close(fd::TCP.FD) = nothing
Base.close(::TCP.Conn) = nothing

module HostResolvers

using ..IOPoll
using ..TCP
import ..TCP: connect

struct AddressError <: Exception
    err::String
    addr::String
end

struct DNSTimeoutError <: Exception
    address::String
end

struct DNSOpError <: Exception
    op::String
    net::String
    source::Union{Nothing, TCP.SocketEndpoint}
    addr::Union{Nothing, TCP.SocketEndpoint}
    err::Exception
end

struct UnknownNetworkError <: Exception
    network::String
end

abstract type AbstractResolver end

struct SystemResolver <: AbstractResolver end

mutable struct CachingResolver{R <: AbstractResolver} <: AbstractResolver
    parent::R
end

struct StaticResolver <: AbstractResolver
    fallback::Union{Nothing, AbstractResolver}
end

mutable struct _LookupFlight
    lock::ReentrantLock
    cond::Threads.Condition
    result::Union{Nothing, Vector{TCP.SocketEndpoint}}
    err::Union{Nothing, Exception}
    @atomic done::Bool
    function _LookupFlight()
        lock = ReentrantLock()
        return new(lock, Threads.Condition(lock), nothing, nothing, false)
    end
end

mutable struct SingleflightResolver{R <: AbstractResolver} <: AbstractResolver
    parent::R
    lock::ReentrantLock
    inflight::Dict{Tuple{String, String}, _LookupFlight}
    @atomic actual_lookups::Int
    @atomic shared_hits::Int
end

function SingleflightResolver(parent::R) where {R <: AbstractResolver}
    return SingleflightResolver{R}(parent, ReentrantLock(), Dict{Tuple{String, String}, _LookupFlight}(), 0, 0)
end

struct ResolverPolicy
    prefer_ipv6::Bool
    allow_ipv4::Bool
    allow_ipv6::Bool
end

function ResolverPolicy(; prefer_ipv6::Bool = false, allow_ipv4::Bool = true, allow_ipv6::Bool = true)
    (!allow_ipv4 && !allow_ipv6) && throw(ArgumentError("resolver policy must allow at least one address family"))
    return ResolverPolicy(prefer_ipv6, allow_ipv4, allow_ipv6)
end

const DEFAULT_RESOLVER = SystemResolver()
const _SERVICE_TCP = Dict{String, Int}("http" => 80, "https" => 443, "ssh" => 22)

mutable struct DNSRaceState
    @atomic done::Bool
    lock::ReentrantLock
    wait_fds::Vector{IOPoll.FD}
    function DNSRaceState()
        return new(false, ReentrantLock(), IOPoll.FD[])
    end
end

@inline function TCP._connect_canceled(state::DNSRaceState)::Bool
    return @atomic :acquire state.done
end

function TCP._connect_wait_register!(state::DNSRaceState, fd::TCP.FD)
    lock(state.lock)
    try
        if @atomic :acquire state.done
            try
                IOPoll.set_write_deadline!(fd.pfd, Int64(time_ns()) - Int64(1))
            catch
            end
            return nothing
        end
        push!(state.wait_fds, fd.pfd)
    finally
        unlock(state.lock)
    end
    return nothing
end

function TCP._connect_wait_unregister!(state::DNSRaceState, fd::TCP.FD)
    lock(state.lock)
    try
        idx = findfirst(x -> x === fd.pfd, state.wait_fds)
        idx === nothing || deleteat!(state.wait_fds, idx)
    finally
        unlock(state.lock)
    end
    return nothing
end

struct HostResolver{R <: AbstractResolver}
    timeout_ns::Int64
    deadline_ns::Int64
    local_addr::Union{Nothing, TCP.SocketEndpoint}
    fallback_delay_ns::Int64
    resolver::R
    policy::ResolverPolicy
end

function HostResolver(;
        timeout_ns::Integer = Int64(0),
        deadline_ns::Integer = Int64(0),
        local_addr::Union{Nothing, TCP.SocketEndpoint} = nothing,
        fallback_delay_ns::Integer = Int64(300_000_000),
        resolver::AbstractResolver = DEFAULT_RESOLVER,
        policy::ResolverPolicy = ResolverPolicy(),
    )
    wrapped = resolver isa SingleflightResolver ? resolver : SingleflightResolver(resolver)
    return HostResolver{typeof(wrapped)}(
        Int64(timeout_ns),
        Int64(deadline_ns),
        local_addr,
        Int64(fallback_delay_ns),
        wrapped,
        policy,
    )
end

@inline function _min_nonzero(a::Int64, b::Int64)::Int64
    a == 0 && return b
    b == 0 && return a
    return min(a, b)
end

function _connect_deadline_ns(d::HostResolver)::Int64
    now = Int64(time_ns())
    timeout_deadline = d.timeout_ns == 0 ? Int64(0) : now + d.timeout_ns
    return _min_nonzero(timeout_deadline, d.deadline_ns)
end

@inline function _dual_stack_enabled(d::HostResolver)::Bool
    return d.fallback_delay_ns >= 0
end

@inline function _effective_fallback_delay_ns(d::HostResolver)::Int64
    if d.fallback_delay_ns > 0
        return d.fallback_delay_ns
    end
    return Int64(300_000_000)
end

@inline function _use_parallel_race(
        d::HostResolver,
        kind::Symbol,
        fallbacks::Vector{TCP.SocketEndpoint},
    )::Bool
    _dual_stack_enabled(d) || return false
    kind == :tcp || return false
    isempty(fallbacks) && return false
    return true
end

@inline function _is_ipv4(addr::TCP.SocketEndpoint)::Bool
    return addr isa TCP.SocketAddrV4
end

@inline function _is_ipv6(addr::TCP.SocketEndpoint)::Bool
    return addr isa TCP.SocketAddrV6
end

function split_host_port(hostport::AbstractString)::Tuple{String, String}
    s = String(hostport)
    i = findlast(==(':'), s)
    i === nothing && throw(AddressError("missing port in address", s))
    first_i = firstindex(s)
    last_i = lastindex(s)
    j = first_i
    k = first_i
    host = ""
    if !isempty(s) && s[first_i] == '['
        end_idx = findfirst(==(']'), s)
        end_idx === nothing && throw(AddressError("missing ']' in address", s))
        if end_idx == last_i
            throw(AddressError("missing port in address", s))
        end
        next_after_bracket = nextind(s, end_idx)
        if next_after_bracket != i
            if s[next_after_bracket] == ':'
                throw(AddressError("too many colons in address", s))
            end
            throw(AddressError("missing port in address", s))
        end
        host_start = nextind(s, first_i)
        host_end = prevind(s, end_idx)
        host = host_start <= host_end ? String(SubString(s, host_start, host_end)) : ""
        j = host_start
        k = next_after_bracket
    else
        if i != first_i
            host_end = prevind(s, i)
            host = String(SubString(s, first_i, host_end))
            findfirst(==(':'), SubString(s, first_i, host_end)) !== nothing &&
                throw(AddressError("too many colons in address", s))
        else
            host = ""
        end
    end
    findnext(==('['), s, j) !== nothing && throw(AddressError("unexpected '[' in address", s))
    findnext(==(']'), s, k) !== nothing && throw(AddressError("unexpected ']' in address", s))
    if i == last_i
        return host, ""
    end
    port_start = nextind(s, i)
    port = String(SubString(s, port_start, last_i))
    return host, port
end

function lookup_port(resolver::AbstractResolver, network::AbstractString, service::AbstractString)::Int
    _ = resolver
    return lookup_port(DEFAULT_RESOLVER, network, service)
end

function lookup_port(network::AbstractString, service::AbstractString)::Int
    return lookup_port(DEFAULT_RESOLVER, network, service)
end

lookup_port(resolver::SingleflightResolver, network::AbstractString, service::AbstractString)::Int =
    lookup_port((resolver::SingleflightResolver).parent, network, service)

lookup_port(resolver::CachingResolver, network::AbstractString, service::AbstractString)::Int =
    lookup_port((resolver::CachingResolver).parent, network, service)

function _parse_port_table(table::Dict{String, Int}, network::AbstractString, service::AbstractString)::Int
    port = get(() -> nothing, table, lowercase(String(service)))
    port === nothing && throw(AddressError("unknown port", string(network, "/", service)))
    return port::Int
end

function parse_port(service::AbstractString)::Tuple{Int, Bool}
    isempty(service) && return 0, false
    s = String(service)
    neg = false
    if startswith(s, '+')
        s = s[2:end]
    elseif startswith(s, '-')
        neg = true
        s = s[2:end]
    end
    isempty(s) && return 0, false
    max_val = typemax(UInt32)
    cutoff = UInt32(1 << 30)
    n = UInt32(0)
    for ch in s
        ('0' <= ch <= '9') || return 0, true
        d = UInt32(ch - '0')
        if n >= cutoff
            n = max_val
            break
        end
        n *= UInt32(10)
        nn = n + d
        if nn < n || nn > max_val
            n = max_val
            break
        end
        n = nn
    end
    port = if !neg && n >= cutoff
        Int(cutoff - UInt32(1))
    elseif neg && n > cutoff
        Int(cutoff)
    else
        Int(n)
    end
    neg && (port = -port)
    return port, false
end

function lookup_port(::SystemResolver, network::AbstractString, service::AbstractString)::Int
    port, needs_lookup = parse_port(service)
    if needs_lookup
        n = String(network)
        if n == "tcp" || n == "tcp4" || n == "tcp6"
            port = _parse_port_table(_SERVICE_TCP, n, service)
        else
            throw(UnknownNetworkError(n))
        end
    end
    (port < 0 || port > 65535) && throw(AddressError("invalid port", String(service)))
    return port
end

function _with_port(addr::TCP.SocketAddrV4, port::Int)::TCP.SocketAddrV4
    return TCP.SocketAddrV4(addr.ip, UInt16(port))
end

function _with_port(addr::TCP.SocketAddrV6, port::Int)::TCP.SocketAddrV6
    return TCP.SocketAddrV6(addr.ip, UInt16(port), addr.scope_id)
end

function _resolve_system_host(host::AbstractString)::Vector{TCP.SocketEndpoint}
    h = String(host)
    if h == "127.0.0.1"
        return TCP.SocketEndpoint[TCP.loopback_addr(0)]
    end
    if h == "::1"
        return TCP.SocketEndpoint[TCP.loopback_addr6(0)]
    end
    throw(AddressError("lookup failed", h))
end

function _resolve_static_host(
        resolver::StaticResolver,
        network::AbstractString,
        host::AbstractString,
    )::Vector{TCP.SocketEndpoint}
    resolver.fallback === nothing && throw(AddressError("lookup failed", String(host)))
    return _resolve_host_ips(resolver.fallback::AbstractResolver, network, host)
end

@inline function _normalize_lookup_host(host::AbstractString)::String
    normalized = lowercase(String(host))
    while !isempty(normalized) && last(normalized) == '.'
        normalized = normalized[1:prevind(normalized, lastindex(normalized))]
    end
    return normalized
end

@inline function _lookup_key(network::AbstractString, host::AbstractString)::Tuple{String, String}
    return lowercase(String(network)), _normalize_lookup_host(host)
end

function _resolve_singleflight_host(
        resolver::SingleflightResolver,
        network::AbstractString,
        host::AbstractString,
    )::Vector{TCP.SocketEndpoint}
    h = String(host)
    key = _lookup_key(network, h)
    flight = nothing
    leader = false
    lock(resolver.lock)
    try
        existing = get(() -> nothing, resolver.inflight, key)
        if existing === nothing
            flight = _LookupFlight()
            resolver.inflight[key] = flight::_LookupFlight
            @atomic :acquire_release resolver.actual_lookups += 1
            leader = true
        else
            flight = existing::_LookupFlight
            @atomic :acquire_release resolver.shared_hits += 1
        end
    finally
        unlock(resolver.lock)
    end
    if leader
        result = nothing
        err = nothing
        try
            result = _resolve_host_ips(resolver.parent, network, h)
        catch ex
            err = ex::Exception
        end
        lock((flight::_LookupFlight).lock)
        try
            flight.result = result === nothing ? nothing : copy(result::Vector{TCP.SocketEndpoint})
            flight.err = err
            @atomic :release flight.done = true
            notify(flight.cond; all = true)
        finally
            unlock(flight.lock)
        end
        lock(resolver.lock)
        try
            current = get(() -> nothing, resolver.inflight, key)
            current === flight && delete!(resolver.inflight, key)
        finally
            unlock(resolver.lock)
        end
        err === nothing || throw(err::Exception)
        return result::Vector{TCP.SocketEndpoint}
    end
    lock((flight::_LookupFlight).lock)
    try
        while !(@atomic :acquire flight.done)
            wait(flight.cond)
        end
        flight.err === nothing || throw(flight.err::Exception)
        return copy(flight.result::Vector{TCP.SocketEndpoint})
    finally
        unlock(flight.lock)
    end
end

function _resolve_host_ips(
        resolver::AbstractResolver,
        network::AbstractString,
        host::AbstractString,
    )::Vector{TCP.SocketEndpoint}
    if resolver isa SingleflightResolver
        return _resolve_singleflight_host(resolver::SingleflightResolver, network, host)
    end
    if resolver isa CachingResolver
        return _resolve_host_ips((resolver::CachingResolver).parent, network, host)
    end
    if resolver isa SystemResolver
        return _resolve_system_host(host)
    end
    if resolver isa StaticResolver
        return _resolve_static_host(resolver::StaticResolver, network, host)
    end
    return _resolve_system_host(host)
end

function _apply_policy_and_network(
        ips::Vector{TCP.SocketEndpoint},
        kind::Symbol,
        policy::ResolverPolicy,
    )::Vector{TCP.SocketEndpoint}
    out = TCP.SocketEndpoint[]
    for addr in ips
        if kind == :tcp4 && !(addr isa TCP.SocketAddrV4)
            continue
        end
        if kind == :tcp6 && !(addr isa TCP.SocketAddrV6)
            continue
        end
        if addr isa TCP.SocketAddrV4
            policy.allow_ipv4 || continue
        else
            policy.allow_ipv6 || continue
        end
        push!(out, addr)
    end
    if policy.prefer_ipv6 && kind == :tcp
        sort!(out; by = a -> a isa TCP.SocketAddrV6 ? 0 : 1)
    end
    return out
end

function resolve_tcp_addrs(
        resolver::AbstractResolver,
        network::AbstractString,
        address::AbstractString;
        op::Symbol = :connect,
        policy::ResolverPolicy = ResolverPolicy(),
    )::Vector{TCP.SocketEndpoint}
    kind = _network_kind(network)
    addr = String(address)
    op == :connect && isempty(addr) && throw(AddressError("missing address", addr))
    host, service = split_host_port(addr)
    port = lookup_port(resolver, network, service)
    ips = _resolve_host_ips(resolver, network, host)
    filtered = _apply_policy_and_network(ips, kind, policy)
    isempty(filtered) && throw(AddressError("no suitable address", host))
    out = TCP.SocketEndpoint[]
    for ipaddr in filtered
        push!(out, _with_port(ipaddr, port))
    end
    return out
end

function _spawn_timer_task(f::F, deadline_ns::Int64) where {F}
    timer = IOPoll.TimerState(deadline_ns, Int64(0))
    IOPoll.schedule_timer!(timer, deadline_ns) || return nothing, nothing
    task = errormonitor(Threads.@spawn begin
        IOPoll.waittimer(timer) || return nothing
        f()
        return nothing
    end)
    return timer, task
end

function _close_timer_task!(
        timer::Union{Nothing, IOPoll.TimerState},
        task::Union{Nothing, Task},
    )
    timer === nothing && return nothing
    IOPoll._close_timer!(timer)
    task === nothing && return nothing
    wait(task)
    return nothing
end

function _resolve_with_deadline(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        deadline_ns::Int64,
    )::Vector{TCP.SocketEndpoint}
    deadline_ns == 0 && return resolve_tcp_addrs(d.resolver, network, address; op = :connect, policy = d.policy)
    now_ns = Int64(time_ns())
    now_ns >= deadline_ns && throw(DNSTimeoutError(String(address)))
    mtx = ReentrantLock()
    condition = Threads.Condition(mtx)
    done = Ref(false)
    timed_out = Ref(false)
    result_ref = Ref{Union{Nothing, Vector{TCP.SocketEndpoint}, Exception}}(nothing)
    timer, timer_task = _spawn_timer_task(deadline_ns) do
        lock(mtx)
        try
            done[] && return nothing
            timed_out[] = true
            done[] = true
            notify(condition)
        finally
            unlock(mtx)
        end
        return nothing
    end
    errormonitor(Threads.@spawn begin
        result = try
            resolve_tcp_addrs(d.resolver, network, address; op = :connect, policy = d.policy)
        catch err
            _as_exception(err)
        end
        lock(mtx)
        try
            done[] && return nothing
            result_ref[] = result
            done[] = true
            notify(condition)
        finally
            unlock(mtx)
        end
        return nothing
    end)
    lock(mtx)
    try
        while !done[]
            wait(condition)
        end
    finally
        unlock(mtx)
        _close_timer_task!(timer, timer_task)
    end
    timed_out[] && throw(DNSTimeoutError(String(address)))
    result = result_ref[]
    result === nothing && throw(DNSTimeoutError(String(address)))
    result isa Exception && throw(result)
    return result::Vector{TCP.SocketEndpoint}
end

function _partial_deadline_ns(now_ns::Int64, deadline_ns::Int64, addrs_remaining::Int)::Int64
    deadline_ns == 0 && return Int64(0)
    time_remaining = deadline_ns - now_ns
    time_remaining <= 0 && throw(DNSTimeoutError(""))
    timeout = time_remaining ÷ addrs_remaining
    sane_min = Int64(2_000_000_000)
    if timeout < sane_min
        timeout = time_remaining < sane_min ? time_remaining : sane_min
    end
    return now_ns + timeout
end

function _partition_addrs(addrs::Vector{TCP.SocketEndpoint})::Tuple{Vector{TCP.SocketEndpoint}, Vector{TCP.SocketEndpoint}}
    isempty(addrs) && return TCP.SocketEndpoint[], TCP.SocketEndpoint[]
    primary_is_v4 = _is_ipv4(addrs[1])
    primaries = TCP.SocketEndpoint[]
    fallbacks = TCP.SocketEndpoint[]
    for addr in addrs
        if _is_ipv4(addr) == primary_is_v4
            push!(primaries, addr)
        else
            push!(fallbacks, addr)
        end
    end
    return primaries, fallbacks
end

@inline function _prefer_ipv4_first!(addrs::Vector{TCP.SocketEndpoint}, policy::ResolverPolicy)
    _ = addrs
    _ = policy
    return nothing
end

@inline function _wrap_op_error(
        op::AbstractString,
        net::AbstractString,
        source::Union{Nothing, TCP.SocketEndpoint},
        addr::Union{Nothing, TCP.SocketEndpoint},
        err::Exception,
    )::DNSOpError
    return DNSOpError(String(op), String(net), source, addr, err)
end

@inline function _as_exception(err)::Exception
    return err::Exception
end

@inline _is_self_connect(conn::TCP.Conn)::Bool = false
@inline function _network_kind(network::AbstractString)::Symbol
    n = String(network)
    n == "tcp" && return :tcp
    n == "tcp4" && return :tcp4
    n == "tcp6" && return :tcp6
    throw(UnknownNetworkError(n))
end

function _mark_connect_done!(state::DNSRaceState)
    while true
        current = @atomic :acquire state.done
        current && return false
        _, ok = @atomicreplace(state.done, current => true)
        ok || continue
        waiters = IOPoll.FD[]
        lock(state.lock)
        try
            append!(waiters, state.wait_fds)
            empty!(state.wait_fds)
        finally
            unlock(state.lock)
        end
        for waiter in waiters
            try
                IOPoll.set_write_deadline!(waiter, Int64(time_ns()) - Int64(1))
            catch
            end
        end
        return true
    end
end

struct DNSParallelResult
    primary::Bool
    conn::Union{Nothing, TCP.Conn}
    err::Union{Nothing, Exception}
end

function _resolve_serial(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        addrs::Vector{TCP.SocketEndpoint},
        deadline_ns::Int64,
        state::DNSRaceState,
    )::Tuple{Union{Nothing, TCP.Conn}, Union{Nothing, Exception}}
    _ = network
    first_err::Union{Nothing, Exception} = nothing
    for (i, remote_addr) in pairs(addrs)
        if @atomic :acquire state.done
            return nothing, first_err
        end
        now_ns = Int64(time_ns())
        if deadline_ns != 0 && now_ns >= deadline_ns
            return nothing, DNSTimeoutError(String(address))
        end
        attempt_deadline = try
            _partial_deadline_ns(now_ns, deadline_ns, length(addrs) - i + 1)
        catch err
            err isa DNSTimeoutError || rethrow(err)
            return nothing, DNSTimeoutError(String(address))
        end
        try
            max_attempts = d.local_addr === nothing ? 3 : 1
            for attempt in 1:max_attempts
                if @atomic :acquire state.done
                    return nothing, first_err
                end
                try
                    conn = TCP._connect_socketaddr_impl(remote_addr, d.local_addr, attempt_deadline, state)
                    if d.local_addr === nothing && _is_self_connect(conn) && attempt < max_attempts
                        close(conn)
                        continue
                    end
                    if _mark_connect_done!(state)
                        return conn, nothing
                    end
                    close(conn)
                    return nothing, first_err
                catch err
                    ex = _as_exception(err)
                    if ex isa TCP.ConnectCanceledError && (@atomic :acquire state.done)
                        return nothing, first_err
                    end
                    if d.local_addr === nothing &&
                       ex isa SystemError &&
                       (ex::SystemError).errnum == Int(Base.Libc.EADDRNOTAVAIL) &&
                       attempt < max_attempts
                        continue
                    end
                    mapped = ex isa IOPoll.DeadlineExceededError ? DNSTimeoutError(String(address)) : ex
                    first_err === nothing && (first_err = mapped)
                    break
                end
            end
        catch err
            ex = _as_exception(err)
            first_err === nothing && (first_err = ex)
        end
    end
    first_err === nothing && (first_err = AddressError("missing address", String(address)))
    return nothing, first_err::Exception
end

function _resolve_parallel(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        primaries::Vector{TCP.SocketEndpoint},
        fallbacks::Vector{TCP.SocketEndpoint},
        deadline_ns::Int64,
    )::Tuple{Union{Nothing, TCP.Conn}, Union{Nothing, Exception}}
    state = DNSRaceState()
    events = Channel{Union{DNSParallelResult, Symbol}}(4)
    @inline function _emit_event!(event::Union{DNSParallelResult, Symbol})
        try
            put!(events, event)
        catch err
            ex = _as_exception(err)
            ex isa InvalidStateException || rethrow(err)
        end
        return nothing
    end
    function _start_racer(primary::Bool, addrs::Vector{TCP.SocketEndpoint})
        return errormonitor(Threads.@spawn begin
            conn, err = _resolve_serial(d, network, address, addrs, deadline_ns, state)
            _emit_event!(DNSParallelResult(primary, conn, err))
            return nothing
        end)
    end
    _start_racer(true, primaries)
    delay_ns = _effective_fallback_delay_ns(d)
    fallback_timer, fallback_timer_task = _spawn_timer_task(Int64(time_ns()) + delay_ns) do
        _emit_event!(:fallback_timer)
    end
    primary_done = false
    fallback_done = false
    fallback_started = false
    primary_err::Union{Nothing, Exception} = nothing
    fallback_err::Union{Nothing, Exception} = nothing
    try
        while true
            event = take!(events)
            if event === :fallback_timer
                if !fallback_started && !(@atomic :acquire state.done)
                    fallback_started = true
                    _start_racer(false, fallbacks)
                end
                continue
            end
            result = event::DNSParallelResult
            if result.conn !== nothing
                _mark_connect_done!(state)
                return result.conn, nothing
            end
            if result.primary
                primary_done = true
                if primary_err === nothing
                    primary_err = result.err
                end
                if !fallback_started && !(@atomic :acquire state.done)
                    fallback_started = true
                    _close_timer_task!(fallback_timer, fallback_timer_task)
                    _start_racer(false, fallbacks)
                end
            else
                fallback_done = true
                if fallback_err === nothing
                    fallback_err = result.err
                end
            end
            if primary_done && fallback_done
                primary_err === nothing && (primary_err = fallback_err)
                primary_err === nothing && (primary_err = AddressError("missing address", String(address)))
                _mark_connect_done!(state)
                return nothing, primary_err::Exception
            end
        end
    finally
        _close_timer_task!(fallback_timer, fallback_timer_task)
        try
            close(events)
        catch
        end
    end
end

function connect(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
    )::TCP.Conn
    deadline_ns = _connect_deadline_ns(d)
    if deadline_ns != 0 && Int64(time_ns()) >= deadline_ns
        throw(_wrap_op_error("connect", network, d.local_addr, nothing, DNSTimeoutError(String(address))))
    end
    kind = try
        _network_kind(network)
    catch err
        throw(_wrap_op_error("connect", network, d.local_addr, nothing, _as_exception(err)))
    end
    addrs = try
        _resolve_with_deadline(d, network, address, deadline_ns)
    catch err
        throw(_wrap_op_error("connect", network, d.local_addr, nothing, _as_exception(err)))
    end
    if deadline_ns != 0 && Int64(time_ns()) >= deadline_ns
        throw(_wrap_op_error("connect", network, d.local_addr, nothing, DNSTimeoutError(String(address))))
    end
    _prefer_ipv4_first!(addrs, d.policy)
    primaries, fallbacks = _partition_addrs(addrs)
    conn = nothing
    err = nothing
    if _use_parallel_race(d, kind, fallbacks)
        conn, err = _resolve_parallel(d, network, address, primaries, fallbacks, deadline_ns)
    else
        state = DNSRaceState()
        conn, err = _resolve_serial(d, network, address, addrs, deadline_ns, state)
    end
    conn !== nothing && return conn
    throw(_wrap_op_error(
        "connect",
        network,
        d.local_addr,
        isempty(addrs) ? nothing : addrs[1],
        err === nothing ? AddressError("missing address", String(address)) : err::Exception,
    ))
end

function connect(
        network::AbstractString,
        address::AbstractString;
        kwargs...,
    )::TCP.Conn
    resolver = isempty(kwargs) ? HostResolver() : HostResolver(; kwargs...)
    return connect(resolver, network, address)
end

function connect(
        address::AbstractString;
        kwargs...,
    )::TCP.Conn
    return connect("tcp", address; kwargs...)
end

end

end # module Reseau

function _probe(f, label::AbstractString)
    println("[windows-compiler-bug] probe start: $(label)")
    try
        f()
        println("[windows-compiler-bug] probe done: $(label)")
    catch ex
        println("[windows-compiler-bug] probe error ($(label)): $(typeof(ex))")
    end
    return nothing
end

println("[windows-compiler-bug] julia threads: $(Threads.nthreads())")

_probe("tcp kwcall local_addr v4") do
    Reseau.TCP.connect("tcp", "127.0.0.1:1"; local_addr = Reseau.TCP.loopback_addr(0))
end

_probe("tcp kwcall local_addr v6 mismatch") do
    Reseau.TCP.connect("tcp", "127.0.0.1:1"; local_addr = Reseau.TCP.loopback_addr6(0))
end

@test true
