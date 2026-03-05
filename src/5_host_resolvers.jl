"""
    HostResolvers

Address parsing, name resolution, and connect/listen orchestration APIs.
"""
module HostResolvers

using ..Reseau.SocketOps
using ..Reseau.IOPoll

using ..Reseau.TCP

"""
    AddressError

Address parsing or canonicalization failure.
"""
struct AddressError <: Exception
    err::String
    addr::String
end

"""
    UnknownNetworkError

Raised when a connect/listen network name is unsupported.
"""
struct UnknownNetworkError <: Exception
    network::String
end

"""
    DNSTimeoutError

Raised when connect cannot complete before the configured deadline.
"""
struct DNSTimeoutError <: Exception
    address::String
end

"""
    DNSOpError

High-level connect/listen operation error wrapper, similar to Go's `OpError`.
"""
struct DNSOpError <: Exception
    op::String
    net::String
    source::Union{Nothing, TCP.SocketEndpoint}
    addr::Union{Nothing, TCP.SocketEndpoint}
    err::Exception
end

function Base.showerror(io::IO, err::AddressError)
    print(io, "$(err.err): $(err.addr)")
    return nothing
end

function Base.showerror(io::IO, err::UnknownNetworkError)
    print(io, "unknown network: $(err.network)")
    return nothing
end

function Base.showerror(io::IO, err::DNSTimeoutError)
    print(io, "connect timeout: $(err.address)")
    return nothing
end

function Base.showerror(io::IO, err::DNSOpError)
    print(io, "$(err.op) $(err.net)")
    err.source === nothing || print(io, " ", err.source)
    err.addr === nothing || print(io, " -> ", err.addr)
    print(io, ": ")
    showerror(io, err.err)
    return nothing
end

abstract type AbstractResolver end

"""
    ResolverPolicy

Host-resolution filtering and preference policy.
"""
struct ResolverPolicy
    prefer_ipv6::Bool
    allow_ipv4::Bool
    allow_ipv6::Bool
end

function ResolverPolicy(; prefer_ipv6::Bool = false, allow_ipv4::Bool = true, allow_ipv6::Bool = true)
    (!allow_ipv4 && !allow_ipv6) && throw(ArgumentError("resolver policy must allow at least one address family"))
    return ResolverPolicy(prefer_ipv6, allow_ipv4, allow_ipv6)
end

"""
    SystemResolver

Resolver backed by the platform name service (native `getaddrinfo`).
"""
struct SystemResolver <: AbstractResolver end

"""
    StaticResolver

Resolver with fixed host/service mappings and optional fallback resolver.
"""
struct StaticResolver <: AbstractResolver
    hosts::Dict{String, Vector{TCP.SocketEndpoint}}
    services_tcp::Dict{String, Int}
    services_udp::Dict{String, Int}
    fallback::Union{Nothing, AbstractResolver}
end

function StaticResolver(;
        hosts::Dict{String, Vector{TCP.SocketEndpoint}} = Dict{String, Vector{TCP.SocketEndpoint}}(),
        services_tcp::Dict{String, Int} = Dict{String, Int}(),
        services_udp::Dict{String, Int} = Dict{String, Int}(),
        fallback::Union{Nothing, AbstractResolver} = nothing,
    )
    return StaticResolver(copy(hosts), copy(services_tcp), copy(services_udp), fallback)
end

const DEFAULT_RESOLVER = SystemResolver()

const _SERVICE_TCP = Dict{String, Int}(
    "ftp" => 21,
    "ftps" => 990,
    "gopher" => 70,
    "http" => 80,
    "https" => 443,
    "imap2" => 143,
    "imap3" => 220,
    "imaps" => 993,
    "pop3" => 110,
    "pop3s" => 995,
    "smtp" => 25,
    "submissions" => 465,
    "ssh" => 22,
    "telnet" => 23,
)
const _SERVICE_UDP = Dict{String, Int}(
    "domain" => 53,
)
const _SERVICE_LOCK = ReentrantLock()
const _SERVICES_LOADED = Ref(false)

function _load_system_services!()
    path = "/etc/services"
    isfile(path) || return nothing
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
        port_str = portnet[firstindex(portnet):prevind(portnet, slash_i)]
        proto = lowercase(portnet[nextind(portnet, slash_i):lastindex(portnet)])
        port = tryparse(Int, port_str)
        port === nothing && continue
        (port <= 0 || port > 65535) && continue
        table = if proto == "tcp"
            _SERVICE_TCP
        elseif proto == "udp"
            _SERVICE_UDP
        else
            nothing
        end
        table === nothing && continue
        for (idx, name) in pairs(fields)
            idx == 2 && continue
            table[lowercase(name)] = port
        end
    end
    return nothing
end

function _ensure_system_services_loaded!()
    _SERVICES_LOADED[] && return nothing
    lock(_SERVICE_LOCK)
    try
        _SERVICES_LOADED[] && return nothing
        _load_system_services!()
        _SERVICES_LOADED[] = true
    finally
        unlock(_SERVICE_LOCK)
    end
    return nothing
end

@static if Sys.iswindows()
    struct _AddrInfo
        ai_flags::Cint
        ai_family::Cint
        ai_socktype::Cint
        ai_protocol::Cint
        ai_addrlen::Csize_t
        ai_canonname::Ptr{UInt8}
        ai_addr::Ptr{Cvoid}
        ai_next::Ptr{_AddrInfo}
    end
elseif Sys.isapple() || Sys.isbsd()
    struct _AddrInfo
        ai_flags::Cint
        ai_family::Cint
        ai_socktype::Cint
        ai_protocol::Cint
        ai_addrlen::Cuint
        ai_canonname::Ptr{UInt8}
        ai_addr::Ptr{Cvoid}
        ai_next::Ptr{_AddrInfo}
    end
else
    struct _AddrInfo
        ai_flags::Cint
        ai_family::Cint
        ai_socktype::Cint
        ai_protocol::Cint
        ai_addrlen::Cuint
        ai_addr::Ptr{Cvoid}
        ai_canonname::Ptr{UInt8}
        ai_next::Ptr{_AddrInfo}
    end
end

const _AI_ALL = @static Sys.isapple() ? Cint(0x00000100) : Sys.islinux() ? Cint(0x0010) : Cint(0)
const _AI_V4MAPPED = @static Sys.isapple() ? Cint(0x00000800) : Sys.islinux() ? Cint(0x0008) : Cint(0)
const _AF_UNSPEC = Cint(0)
const _SOCK_STREAM = Cint(1)
const _HR_AF_INET = SocketOps.AF_INET
const _HR_AF_INET6 = SocketOps.AF_INET6

@inline function _gai_error_string(code::Cint)::String
    ptr = @static if Sys.iswindows()
        ccall((:gai_strerrorA, "Ws2_32"), Cstring, (Cint,), code)
    else
        ccall(:gai_strerror, Cstring, (Cint,), code)
    end
    ptr == C_NULL && return "unknown getaddrinfo error code $code"
    return unsafe_string(ptr)
end

function _native_getaddrinfo(hostname::AbstractString; flags::Cint = Cint(0))::Vector{TCP.SocketEndpoint}
    SocketOps.ensure_winsock!()
    addresses = TCP.SocketEndpoint[]
    hints = Ref{_AddrInfo}()
    hints_ptr = Base.unsafe_convert(Ptr{_AddrInfo}, hints)
    Base.Libc.memset(hints_ptr, 0, sizeof(_AddrInfo))
    hints_bytes = Ptr{UInt8}(hints_ptr)
    GC.@preserve hints begin
        unsafe_store!(Ptr{Cint}(hints_bytes + fieldoffset(_AddrInfo, 1)), flags)
        unsafe_store!(Ptr{Cint}(hints_bytes + fieldoffset(_AddrInfo, 2)), _AF_UNSPEC)
        unsafe_store!(Ptr{Cint}(hints_bytes + fieldoffset(_AddrInfo, 3)), _SOCK_STREAM)
    end
    result_ptr = Ref{Ptr{_AddrInfo}}(C_NULL)
    ret = GC.@preserve hints begin
        @static if Sys.iswindows()
            @ccall gc_safe = true "Ws2_32".getaddrinfo(
                String(hostname)::Cstring,
                C_NULL::Cstring,
                hints_ptr::Ptr{_AddrInfo},
                result_ptr::Ptr{Ptr{_AddrInfo}},
            )::Cint
        else
            @ccall gc_safe = true getaddrinfo(
                String(hostname)::Cstring,
                C_NULL::Cstring,
                hints_ptr::Ptr{_AddrInfo},
                result_ptr::Ptr{Ptr{_AddrInfo}},
            )::Cint
        end
    end
    ret == 0 || _addr_error("lookup failed: $(_gai_error_string(ret))", String(hostname))
    try
        current = result_ptr[]
        while current != C_NULL
            ai = unsafe_load(current)
            if ai.ai_addr != C_NULL
                if ai.ai_family == _HR_AF_INET && Int(ai.ai_addrlen) >= sizeof(SocketOps.SockAddrIn)
                    sa = unsafe_load(Ptr{SocketOps.SockAddrIn}(ai.ai_addr))
                    push!(addresses, TCP.SocketAddrV4(SocketOps.sockaddr_in_ip(sa), 0))
                elseif ai.ai_family == _HR_AF_INET6 && Int(ai.ai_addrlen) >= sizeof(SocketOps.SockAddrIn6)
                    sa = unsafe_load(Ptr{SocketOps.SockAddrIn6}(ai.ai_addr))
                    push!(addresses, TCP.SocketAddrV6(
                        SocketOps.sockaddr_in6_ip(sa),
                        0;
                        scope_id = Int(SocketOps.sockaddr_in6_scopeid(sa)),
                    ))
                end
            end
            current = ai.ai_next
        end
    finally
        if result_ptr[] != C_NULL
            @static if Sys.iswindows()
                ccall((:freeaddrinfo, "Ws2_32"), Cvoid, (Ptr{_AddrInfo},), result_ptr[])
            else
                ccall(:freeaddrinfo, Cvoid, (Ptr{_AddrInfo},), result_ptr[])
            end
        end
    end
    return addresses
end

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

struct DNSParallelResult
    primary::Bool
    conn::Union{Nothing, TCP.Conn}
    err::Union{Nothing, Exception}
end

function _addr_error(err::AbstractString, addr::AbstractString)
    throw(AddressError(String(err), String(addr)))
end

@inline function _is_ipv4(addr::TCP.SocketEndpoint)::Bool
    return addr isa TCP.SocketAddrV4
end

@inline function _is_ipv6(addr::TCP.SocketEndpoint)::Bool
    return addr isa TCP.SocketAddrV6
end

function _parse_ipv4_literal(host::AbstractString)::Union{Nothing, NTuple{4, UInt8}}
    h = String(host)
    bytes = Vector{UInt8}(undef, 4)
    rc = GC.@preserve bytes begin
        @ccall gc_safe = true inet_pton(
            SocketOps.AF_INET::Cint,
            h::Cstring,
            pointer(bytes)::Ptr{UInt8},
        )::Cint
    end
    rc == 1 || return nothing
    return (bytes[1], bytes[2], bytes[3], bytes[4])
end

function _parse_ipv6_literal(host::AbstractString)::Union{Nothing, NTuple{16, UInt8}}
    h = String(host)
    bytes = Vector{UInt8}(undef, 16)
    rc = GC.@preserve bytes begin
        @ccall gc_safe = true inet_pton(
            SocketOps.AF_INET6::Cint,
            h::Cstring,
            pointer(bytes)::Ptr{UInt8},
        )::Cint
    end
    rc == 1 || return nothing
    return (
        bytes[1], bytes[2], bytes[3], bytes[4],
        bytes[5], bytes[6], bytes[7], bytes[8],
        bytes[9], bytes[10], bytes[11], bytes[12],
        bytes[13], bytes[14], bytes[15], bytes[16],
    )
end

function _split_host_zone(host::AbstractString)::Tuple{String, String}
    s = String(host)
    i = findlast(==('%'), s)
    i === nothing && return s, ""
    i == firstindex(s) && return s, ""
    i == lastindex(s) && _addr_error("invalid scoped address zone", s)
    return s[1:prevind(s, i)], s[nextind(s, i):end]
end

function _scope_id_from_zone(zone::AbstractString)::UInt32
    z = String(zone)
    isempty(z) && return UInt32(0)
    numeric = tryparse(Int, z)
    if numeric !== nothing
        (numeric < 0 || numeric > typemax(UInt32)) && _addr_error("invalid scope id", z)
        return UInt32(numeric)
    end
    idx = @ccall if_nametoindex(z::Cstring)::UInt32
    idx == 0 && _addr_error("unknown interface zone", z)
    return idx
end

function _literal_host_addr(host::AbstractString)::Union{Nothing, TCP.SocketEndpoint}
    h = String(host)
    isempty(h) && return nothing
    host_only, zone = _split_host_zone(h)
    ip4 = _parse_ipv4_literal(host_only)
    if ip4 !== nothing
        isempty(zone) || _addr_error("invalid scoped address", h)
        return TCP.SocketAddrV4(ip4::NTuple{4, UInt8}, 0)
    end
    ip6 = _parse_ipv6_literal(host_only)
    if ip6 !== nothing
        scope_id = _scope_id_from_zone(zone)
        return TCP.SocketAddrV6(ip6::NTuple{16, UInt8}, 0; scope_id = Int(scope_id))
    end
    return nothing
end

function _parse_port_table(table::Dict{String, Int}, network::AbstractString, service::AbstractString)::Int
    port = get(() -> nothing, table, lowercase(String(service)))
    port === nothing && _addr_error("unknown port", string(network, "/", service))
    return port::Int
end

"""
    join_host_port(host, port)

Join host and port into `host:port`, bracket-quoting IPv6 literals.
`port` may be numeric or an opaque service string.
"""
function join_host_port(host::AbstractString, port::AbstractString)::String
    host_s = String(host)
    port_s = String(port)
    if occursin(':', host_s)
        return "[$host_s]:$port_s"
    end
    return "$host_s:$port_s"
end

function join_host_port(host::AbstractString, port::Integer)::String
    return join_host_port(host, string(port))
end

"""
    split_host_port(hostport)

Split `host:port` or `[host]:port` into `(host, port)`.
"""
function split_host_port(hostport::AbstractString)::Tuple{String, String}
    s = String(hostport)
    i = findlast(==(':'), s)
    i === nothing && _addr_error("missing port in address", s)
    first_i = firstindex(s)
    last_i = lastindex(s)
    j = first_i
    k = first_i
    host = ""
    if !isempty(s) && s[first_i] == '['
        end_idx = findfirst(==(']'), s)
        end_idx === nothing && _addr_error("missing ']' in address", s)
        if end_idx == last_i
            _addr_error("missing port in address", s)
        end
        next_after_bracket = nextind(s, end_idx)
        if next_after_bracket != i
            if s[next_after_bracket] == ':'
                _addr_error("too many colons in address", s)
            end
            _addr_error("missing port in address", s)
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
            findfirst(==(':'), SubString(s, first_i, host_end)) !== nothing && _addr_error("too many colons in address", s)
        else
            host = ""
        end
    end
    findnext(==('['), s, j) !== nothing && _addr_error("unexpected '[' in address", s)
    findnext(==(']'), s, k) !== nothing && _addr_error("unexpected ']' in address", s)
    if i == last_i
        return host, ""
    end
    port_start = nextind(s, i)
    port = String(SubString(s, port_start, last_i))
    return host, port
end

"""
    parse_port(service)

Parse decimal service port; returns `(port, needs_lookup)`.
"""
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

@inline function _network_kind(network::AbstractString)::Symbol
    n = String(network)
    n == "tcp" && return :tcp
    n == "tcp4" && return :tcp4
    n == "tcp6" && return :tcp6
    throw(UnknownNetworkError(n))
end

"""
    lookup_port(network, service)

Resolve numeric or named service into a port number.
"""
function lookup_port(network::AbstractString, service::AbstractString)::Int
    return lookup_port(DEFAULT_RESOLVER, network, service)
end

function lookup_port(::SystemResolver, network::AbstractString, service::AbstractString)::Int
    port, needs_lookup = parse_port(service)
    if needs_lookup
        _ensure_system_services_loaded!()
        n = String(network)
        if n == "ip" || isempty(n)
            try
                port = _parse_port_table(_SERVICE_TCP, "ip", service)
            catch
                port = _parse_port_table(_SERVICE_UDP, "ip", service)
            end
        elseif n == "tcp" || n == "tcp4" || n == "tcp6"
            port = _parse_port_table(_SERVICE_TCP, n, service)
        elseif n == "udp" || n == "udp4" || n == "udp6"
            port = _parse_port_table(_SERVICE_UDP, n, service)
        else
            _addr_error("unknown network", n)
        end
    end
    (port < 0 || port > 65535) && _addr_error("invalid port", service)
    return port
end

function lookup_port(resolver::StaticResolver, network::AbstractString, service::AbstractString)::Int
    port, needs_lookup = parse_port(service)
    if needs_lookup
        n = String(network)
        if n == "tcp" || n == "tcp4" || n == "tcp6" || n == "" || n == "ip"
            p = get(() -> nothing, resolver.services_tcp, lowercase(String(service)))
            if p !== nothing
                port = p::Int
            elseif resolver.fallback !== nothing
                return lookup_port(resolver.fallback::AbstractResolver, network, service)
            else
                port = _parse_port_table(_SERVICE_TCP, n, service)
            end
        elseif n == "udp" || n == "udp4" || n == "udp6"
            p = get(() -> nothing, resolver.services_udp, lowercase(String(service)))
            if p !== nothing
                port = p::Int
            elseif resolver.fallback !== nothing
                return lookup_port(resolver.fallback::AbstractResolver, network, service)
            else
                port = _parse_port_table(_SERVICE_UDP, n, service)
            end
        else
            _addr_error("unknown network", n)
        end
    end
    (port < 0 || port > 65535) && _addr_error("invalid port", service)
    return port
end

@inline function _policy_accepts(policy::ResolverPolicy, addr::TCP.SocketEndpoint)::Bool
    if addr isa TCP.SocketAddrV4
        return policy.allow_ipv4
    end
    return policy.allow_ipv6
end

function _apply_policy_and_network(
        addrs::Vector{TCP.SocketEndpoint},
        kind::Symbol,
        policy::ResolverPolicy,
    )::Vector{TCP.SocketEndpoint}
    out = TCP.SocketEndpoint[]
    for addr in addrs
        if kind == :tcp4 && !(addr isa TCP.SocketAddrV4)
            continue
        end
        if kind == :tcp6 && !(addr isa TCP.SocketAddrV6)
            continue
        end
        _policy_accepts(policy, addr) || continue
        push!(out, addr)
    end
    if policy.prefer_ipv6 && kind == :tcp
        sort!(out; by = a -> a isa TCP.SocketAddrV6 ? 0 : 1)
    end
    return out
end

function _resolve_system_host(host::AbstractString)::Vector{TCP.SocketEndpoint}
    h = String(host)
    literal = _literal_host_addr(h)
    literal === nothing || return TCP.SocketEndpoint[literal]
    flags = @static Sys.isopenbsd() ? Cint(0) : (_AI_ALL | _AI_V4MAPPED)
    ips = _native_getaddrinfo(h; flags = flags)
    out = TCP.SocketEndpoint[]
    seen4 = Set{NTuple{4, UInt8}}()
    seen6 = Set{Tuple{NTuple{16, UInt8}, UInt32}}()
    for endpoint in ips
        if endpoint isa TCP.SocketAddrV4
            ip4 = (endpoint::TCP.SocketAddrV4).ip
            in(ip4, seen4) && continue
            push!(seen4, ip4)
            push!(out, endpoint::TCP.SocketAddrV4)
            continue
        end
        endpoint isa TCP.SocketAddrV6 || continue
        v6 = endpoint::TCP.SocketAddrV6
        key = (v6.ip, v6.scope_id)
        in(key, seen6) && continue
        push!(seen6, key)
        push!(out, v6)
    end
    return out
end

function _resolve_static_host(resolver::StaticResolver, host::AbstractString)::Vector{TCP.SocketEndpoint}
    h = String(host)
    literal = _literal_host_addr(h)
    literal === nothing || return TCP.SocketEndpoint[literal]
    mapped = get(() -> nothing, resolver.hosts, lowercase(h))
    mapped === nothing || return copy(mapped::Vector{TCP.SocketEndpoint})
    resolver.fallback === nothing && _addr_error("no suitable address", h)
    return _resolve_host_ips(resolver.fallback::AbstractResolver, h)
end

function _resolve_host_ips(resolver::AbstractResolver, host::AbstractString)::Vector{TCP.SocketEndpoint}
    if resolver isa SystemResolver
        return _resolve_system_host(host)
    end
    return _resolve_static_host(resolver::StaticResolver, host)
end

@inline function _wildcard_addrs(kind::Symbol, op::Symbol)::Vector{TCP.SocketEndpoint}
    if kind == :tcp && op == :listen
        return TCP.SocketEndpoint[TCP.any_addr6(0), TCP.any_addr(0)]
    end
    return TCP.SocketEndpoint[TCP.any_addr(0), TCP.any_addr6(0)]
end

function _with_port(addr::TCP.SocketAddrV4, port::Int)::TCP.SocketAddrV4
    return TCP.SocketAddrV4(addr.ip, port)
end

function _with_port(addr::TCP.SocketAddrV6, port::Int)::TCP.SocketAddrV6
    return TCP.SocketAddrV6(addr.ip, port; scope_id = Int(addr.scope_id))
end

function _is_self_connect(conn::TCP.Conn)::Bool
    laddr = TCP.local_addr(conn)
    raddr = TCP.remote_addr(conn)
    (laddr === nothing || raddr === nothing) && return true
    if laddr isa TCP.SocketAddrV4 && raddr isa TCP.SocketAddrV4
        lv4 = laddr::TCP.SocketAddrV4
        rv4 = raddr::TCP.SocketAddrV4
        return lv4.port == rv4.port && lv4.ip == rv4.ip
    end
    if laddr isa TCP.SocketAddrV6 && raddr isa TCP.SocketAddrV6
        lv6 = laddr::TCP.SocketAddrV6
        rv6 = raddr::TCP.SocketAddrV6
        return lv6.port == rv6.port && lv6.ip == rv6.ip && lv6.scope_id == rv6.scope_id
    end
    return false
end

"""
    resolve_tcp_addrs(resolver, network, address; op=:connect, policy=ResolverPolicy())

Resolve a TCP `host:port` string into concrete socket addresses.
"""
function resolve_tcp_addrs(
        resolver::AbstractResolver,
        network::AbstractString,
        address::AbstractString;
        op::Symbol = :connect,
        policy::ResolverPolicy = ResolverPolicy(),
    )::Vector{TCP.SocketEndpoint}
    kind = _network_kind(network)
    addr = String(address)
    op == :connect && isempty(addr) && _addr_error("missing address", addr)
    host, service = split_host_port(addr)
    port = lookup_port(resolver, network, service)
    ips = if isempty(host)
        _wildcard_addrs(kind, op)
    else
        _resolve_host_ips(resolver, host)
    end
    filtered = _apply_policy_and_network(ips, kind, policy)
    isempty(filtered) && _addr_error("no suitable address", host)
    out = TCP.SocketEndpoint[]
    for ipaddr in filtered
        push!(out, _with_port(ipaddr, port))
    end
    return out
end

function resolve_tcp_addrs(network::AbstractString, address::AbstractString)::Vector{TCP.SocketEndpoint}
    return resolve_tcp_addrs(DEFAULT_RESOLVER, network, address)
end

"""
    resolve_tcp_addr(resolver, network, address; policy=ResolverPolicy())

Resolve and return the first preferred TCP endpoint.
"""
function resolve_tcp_addr(
        resolver::AbstractResolver,
        network::AbstractString,
        address::AbstractString;
        policy::ResolverPolicy = ResolverPolicy(),
    )::TCP.SocketEndpoint
    addrs = resolve_tcp_addrs(resolver, network, address; op = :resolve, policy = policy)
    return addrs[1]
end

function resolve_tcp_addr(network::AbstractString, address::AbstractString)::TCP.SocketEndpoint
    return resolve_tcp_addr(DEFAULT_RESOLVER, network, address)
end

"""
    HostResolver

Go-like connect configuration for timeout/deadline/local-bind and resolver injection.
"""
struct HostResolver{R<:AbstractResolver}
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
    return HostResolver{typeof(resolver)}(
        Int64(timeout_ns),
        Int64(deadline_ns),
        local_addr,
        Int64(fallback_delay_ns),
        resolver,
        policy,
    )
end

@inline function _min_nonzero(a::Int64, b::Int64)::Int64
    a == 0 && return b
    b == 0 && return a
    return min(a, b)
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

@inline function _use_parallel_race(d::HostResolver, kind::Symbol, fallbacks::Vector{TCP.SocketEndpoint})::Bool
    _dual_stack_enabled(d) || return false
    kind == :tcp || return false
    isempty(fallbacks) && return false
    return true
end

function _connect_deadline_ns(d::HostResolver)::Int64
    now = Int64(time_ns())
    timeout_deadline = d.timeout_ns == 0 ? Int64(0) : now + d.timeout_ns
    return _min_nonzero(timeout_deadline, d.deadline_ns)
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
    timeout_s = (deadline_ns - now_ns) / 1.0e9
    mtx = ReentrantLock()
    condition = Threads.Condition(mtx)
    done = Ref(false)
    timed_out = Ref(false)
    result_ref = Ref{Union{Nothing, Vector{TCP.SocketEndpoint}, Exception}}(nothing)
    timer = Timer(timeout_s) do _
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
        close(timer)
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

function _resolve_serial(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        addrs::Vector{TCP.SocketEndpoint},
        deadline_ns::Int64,
        state::DNSRaceState,
    )::Tuple{Union{Nothing, TCP.Conn}, Union{Nothing, Exception}}
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
                    fd = TCP.connect_tcp_fd!(
                        remote_addr;
                        local_addr = d.local_addr,
                        connect_deadline_ns = attempt_deadline,
                        cancel_state = state,
                    )
                    conn = TCP.Conn(fd)
                    if d.local_addr === nothing && _is_self_connect(conn) && attempt < max_attempts
                        TCP.close!(conn)
                        continue
                    end
                    if _mark_connect_done!(state)
                        return conn, nothing
                    end
                    TCP.close!(conn)
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
    fallback_timer = Timer(delay_ns / 1.0e9) do _
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
                    try
                        close(fallback_timer)
                    catch
                    end
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
        try
            close(fallback_timer)
        catch
        end
        try
            close(events)
        catch
        end
    end
end

"""
    connect(d, network, address)

Connect a TCP connection from a `host:port` string.
"""
function connect(d::HostResolver, network::AbstractString, address::AbstractString)::TCP.Conn
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

function connect(network::AbstractString, address::AbstractString)::TCP.Conn
    return connect(HostResolver(), network, address)
end

function connect(address::AbstractString)::TCP.Conn
    return connect(HostResolver(), "tcp", address)
end

function connect_timeout(network::AbstractString, address::AbstractString, timeout_ns::Integer)::TCP.Conn
    return connect(HostResolver(; timeout_ns = Int64(timeout_ns)), network, address)
end

"""
    listen(d, network, address; backlog=128, reuseaddr=true)

Listen on a resolved local endpoint.
"""
function listen(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString;
        backlog::Integer = 128,
        reuseaddr::Bool = true,
    )::TCP.Listener
    try
        _network_kind(network)
    catch err
        throw(_wrap_op_error("listen", network, nothing, nothing, _as_exception(err)))
    end
    addrs = try
        resolve_tcp_addrs(d.resolver, network, address; op = :listen, policy = d.policy)
    catch err
        throw(_wrap_op_error("listen", network, nothing, nothing, _as_exception(err)))
    end
    first_err::Union{Nothing, Exception} = nothing
    for local_addr in addrs
        try
            return TCP.listen(local_addr; backlog = backlog, reuseaddr = reuseaddr)
        catch err
            first_err === nothing && (first_err = _as_exception(err))
        end
    end
    throw(_wrap_op_error(
        "listen",
        network,
        nothing,
        isempty(addrs) ? nothing : addrs[1],
        first_err === nothing ? AddressError("missing address", String(address)) : first_err::Exception,
    ))
end

function listen(
        network::AbstractString,
        address::AbstractString;
        backlog::Integer = 128,
        reuseaddr::Bool = true,
    )::TCP.Listener
    return listen(HostResolver(), network, address; backlog = backlog, reuseaddr = reuseaddr)
end
end
