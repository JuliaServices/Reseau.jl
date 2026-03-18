using Test

module IOPoll

export DeadlineExceededError

struct DeadlineExceededError <: Exception end

end

module TCP

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

struct Conn end

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

function _connect_socketaddr_impl(
        remote_addr::SocketAddr,
        local_addr::Union{Nothing, SocketAddr},
        attempt_deadline::Int64,
        state,
    )::Conn
    _ = attempt_deadline
    _ = state
    if local_addr isa SocketAddrV6 && remote_addr isa SocketAddrV4
        throw(ArgumentError("address family mismatch"))
    end
    throw(ArgumentError("connect failed"))
end

end

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

abstract type AbstractResolver end

struct SystemResolver <: AbstractResolver end

struct SingleflightResolver{R <: AbstractResolver} <: AbstractResolver
    parent::R
end

SingleflightResolver(parent::R) where {R <: AbstractResolver} = SingleflightResolver{R}(parent)

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

mutable struct DNSRaceState
    @atomic done::Bool
    function DNSRaceState()
        return new(false)
    end
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

@inline function _use_parallel_race(
        d::HostResolver,
        kind::Symbol,
        fallbacks::Vector{TCP.SocketEndpoint},
    )::Bool
    _ = d
    _ = kind
    return !isempty(fallbacks)
end

function _resolve_with_deadline(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        deadline_ns::Int64,
    )::Vector{TCP.SocketEndpoint}
    _ = d
    _ = network
    _ = address
    _ = deadline_ns
    return TCP.SocketEndpoint[TCP.loopback_addr(1)]
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
    return addrs, TCP.SocketEndpoint[]
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
@inline _network_kind(network::AbstractString)::Symbol = Symbol(network)

function _mark_connect_done!(state::DNSRaceState)
    while true
        current = @atomic :acquire state.done
        current && return false
        _, ok = @atomicreplace(state.done, current => true)
        ok || continue
        return true
    end
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
        error("parallel race should not be used in this reproducer")
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
    TCP.connect("tcp", "127.0.0.1:1"; local_addr = TCP.loopback_addr(0))
end

_probe("tcp kwcall local_addr v6 mismatch") do
    TCP.connect("tcp", "127.0.0.1:1"; local_addr = TCP.loopback_addr6(0))
end

@test true
