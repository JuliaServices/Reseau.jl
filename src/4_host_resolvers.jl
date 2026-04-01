"""
    HostResolvers

Address parsing, name resolution, and TCP string-address helpers.

This layer is the bridge between string-oriented user input like
`"example.com:443"` and the lower-level `TCP` primitives that operate on concrete
socket addresses. It is responsible for:
- parse and canonicalize host/port strings
- resolve hostnames according to a resolver policy
- attempt connections serially or in a Happy Eyeballs-style race
- wrap failures in an operation-specific error that preserves context

The public-facing string overloads for `TCP.connect` and `TCP.listen` are
implemented here so users can stay on the `TCP` surface while the host/service
resolution logic remains factored into its own file.
"""
module HostResolvers

using ..Reseau: @gcsafe_ccall
using ..Reseau.SocketOps
using ..Reseau.IOPoll

using ..Reseau.TCP
import ..Reseau.TCP: connect, listen

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
    LookupError

Host or service lookup failure.
"""
struct LookupError <: Exception
    err::String
    name::String
end

"""
    DialTimeoutError

Raised when dial cannot complete before the configured deadline.
"""
struct DialTimeoutError <: Exception
    address::String
end

"""
    OpError

High-level connect/listen operation error wrapper that preserves operation
context.
"""
struct OpError <: Exception
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

function Base.showerror(io::IO, err::LookupError)
    print(io, "$(err.err): $(err.name)")
    return nothing
end

function Base.showerror(io::IO, err::DialTimeoutError)
    if isempty(err.address)
        print(io, "dial timeout")
    else
        print(io, "dial timeout: $(err.address)")
    end
    return nothing
end

function Base.showerror(io::IO, err::OpError)
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

Fields:
- `prefer_ipv6`: sort mixed-family results so IPv6 candidates come first for the
  generic `tcp` network
- `allow_ipv4`: keep IPv4 candidates in the result set
- `allow_ipv6`: keep IPv6 candidates in the result set

At least one family must remain enabled.
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

Resolver backed by the platform name service (`getaddrinfo`).

This is the default resolver used by the convenience APIs.
"""
struct SystemResolver <: AbstractResolver end

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

"""
    SingleflightResolver(parent)

Resolver wrapper that coalesces concurrent duplicate hostname lookups for the
same `(network, host)` pair while preserving caller-local timeout and connect
behavior outside the raw lookup step.
"""
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

mutable struct _LookupCacheEntry
    result::Union{Nothing, Vector{TCP.SocketEndpoint}}
    err::Union{Nothing, Exception}
    expires_ns::Int64
    stale_expires_ns::Int64
    last_access_ns::Int64
    refreshing::Bool
end

"""
    CachingResolver(; parent=SystemResolver(), ttl_ns, stale_ttl_ns, negative_ttl_ns, max_hosts)
    CachingResolver(parent; ttl_ns, stale_ttl_ns, negative_ttl_ns, max_hosts)

Explicit opt-in hostname cache with policy TTLs.

This caches positive host-IP lookups for `ttl_ns`, may serve stale positives for
up to `stale_ttl_ns` while refreshing in the background, and may cache
`LookupError` failures for `negative_ttl_ns`. `max_hosts` bounds the number of
cached host keys and evicts the least-recently-used entry when full.
"""
mutable struct CachingResolver{R <: AbstractResolver} <: AbstractResolver
    parent::R
    ttl_ns::Int64
    stale_ttl_ns::Int64
    negative_ttl_ns::Int64
    max_hosts::Int
    lock::ReentrantLock
    entries::Dict{Tuple{String, String}, _LookupCacheEntry}
    @atomic cache_hits::Int
    @atomic stale_hits::Int
    @atomic negative_hits::Int
    @atomic misses::Int
end

function CachingResolver(
        parent::R;
        ttl_ns::Integer = Int64(5_000_000_000),
        stale_ttl_ns::Integer = Int64(0),
        negative_ttl_ns::Integer = Int64(0),
        max_hosts::Integer = 1024,
    ) where {R <: AbstractResolver}
    ttl_ns >= 0 || throw(ArgumentError("ttl_ns must be >= 0"))
    stale_ttl_ns >= 0 || throw(ArgumentError("stale_ttl_ns must be >= 0"))
    negative_ttl_ns >= 0 || throw(ArgumentError("negative_ttl_ns must be >= 0"))
    max_hosts > 0 || throw(ArgumentError("max_hosts must be > 0"))
    return CachingResolver{R}(
        parent,
        Int64(ttl_ns),
        Int64(stale_ttl_ns),
        Int64(negative_ttl_ns),
        Int(max_hosts),
        ReentrantLock(),
        Dict{Tuple{String, String}, _LookupCacheEntry}(),
        0,
        0,
        0,
        0,
    )
end

function CachingResolver(;
        parent::AbstractResolver = SystemResolver(),
        ttl_ns::Integer = Int64(5_000_000_000),
        stale_ttl_ns::Integer = Int64(0),
        negative_ttl_ns::Integer = Int64(0),
        max_hosts::Integer = 1024,
    )
    return CachingResolver(parent; ttl_ns = ttl_ns, stale_ttl_ns = stale_ttl_ns, negative_ttl_ns = negative_ttl_ns, max_hosts = max_hosts)
end

"""
    StaticResolver

Resolver with fixed host/service mappings and optional fallback resolver.

This is useful in tests and controlled environments where you want deterministic
name/service lookup without consulting the operating system.
"""
struct StaticResolver{F<:Union{Nothing, AbstractResolver}} <: AbstractResolver
    hosts::Dict{String, Vector{TCP.SocketEndpoint}}
    services_tcp::Dict{String, Int}
    services_udp::Dict{String, Int}
    fallback::F
end

function StaticResolver(;
        hosts::Dict{String, Vector{TCP.SocketEndpoint}} = Dict{String, Vector{TCP.SocketEndpoint}}(),
        services_tcp::Dict{String, Int} = Dict{String, Int}(),
        services_udp::Dict{String, Int} = Dict{String, Int}(),
        fallback::Union{Nothing, AbstractResolver} = nothing,
    )
    return StaticResolver{typeof(fallback)}(copy(hosts), copy(services_tcp), copy(services_udp), fallback)
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
const _WSAHOST_NOT_FOUND = Cint(11001)
const _WSATRY_AGAIN = Cint(11002)
const _WSATYPE_NOT_FOUND = Cint(10109)
const _DNS_ERROR_RCODE_NAME_ERROR = Cint(9003)
const _DNS_INFO_NO_RECORDS = Cint(9501)
const _ADDRINFO_POOL_SIZE = 4
const _ADDRINFO_POOL_CAPACITY = 64
const _ADDRINFO_THREAD_ENTRY_C = Ref{Ptr{Cvoid}}(C_NULL)
const _ADDRINFO_POOL_LOCK = ReentrantLock()
const _ADDRINFO_STARTED_THREADS = Ref{Int}(0)

mutable struct _AddrInfoFuture
    notify::Threads.Condition
    hostname::String
    flags::Cint
    ret::Cint
    done::Bool
    err::Union{Nothing,Exception}
    addr_info_ptr::Ptr{_AddrInfo}
end

function _AddrInfoFuture(hostname::String, flags::Cint)
    return _AddrInfoFuture(Threads.Condition(), hostname, flags, Cint(0), false, nothing, C_NULL)
end

const _ADDRINFO_WORK_QUEUE = Ref{Channel{_AddrInfoFuture}}()

@inline function _addr_info_future_result_ptr(future::_AddrInfoFuture)::Ptr{Ptr{_AddrInfo}}
    base = Ptr{UInt8}(pointer_from_objref(future))
    return Ptr{Ptr{_AddrInfo}}(base + fieldoffset(_AddrInfoFuture, 7))
end

function _prepare_addrinfo_hints!(hints::Ref{_AddrInfo}, flags::Cint)::Nothing
    hints_ptr = Base.unsafe_convert(Ptr{_AddrInfo}, hints)
    Base.Libc.memset(hints_ptr, 0, sizeof(_AddrInfo))
    hints_bytes = Ptr{UInt8}(hints_ptr)
    unsafe_store!(Ptr{Cint}(hints_bytes + fieldoffset(_AddrInfo, 1)), flags)
    unsafe_store!(Ptr{Cint}(hints_bytes + fieldoffset(_AddrInfo, 2)), _AF_UNSPEC)
    unsafe_store!(Ptr{Cint}(hints_bytes + fieldoffset(_AddrInfo, 3)), _SOCK_STREAM)
    return nothing
end

function _ccall_getaddrinfo(hostname::String, hints::Ref{_AddrInfo}, result_ptr::Ptr{Ptr{_AddrInfo}})::Cint
    null_service = Ptr{UInt8}(C_NULL)
    return @static if Sys.iswindows()
        ccall((:getaddrinfo, "Ws2_32"), Cint,
            (Cstring, Cstring, Ptr{_AddrInfo}, Ptr{Ptr{_AddrInfo}}),
            hostname,
            null_service,
            hints,
            result_ptr,
        )
    else
        ccall(:getaddrinfo, Cint,
            (Cstring, Cstring, Ptr{_AddrInfo}, Ptr{Ptr{_AddrInfo}}),
            hostname,
            null_service,
            hints,
            result_ptr,
        )
    end
end

function _run_addrinfo_future!(future::_AddrInfoFuture)::Nothing
    ret = Cint(0)
    err = nothing
    try
        hints = Ref{_AddrInfo}()
        GC.@preserve future hints begin
            _prepare_addrinfo_hints!(hints, future.flags)
            unsafe_store!(_addr_info_future_result_ptr(future), C_NULL)
            ret = _ccall_getaddrinfo(future.hostname, hints, _addr_info_future_result_ptr(future))
        end
    catch ex
        err = ex::Exception
    end
    lock(future.notify)
    try
        future.ret = ret
        if err === nothing
            future.err = nothing
        else
            future.err = err::Exception
        end
        future.done = true
        notify(future.notify)
    finally
        unlock(future.notify)
    end
    return nothing
end

function _addrinfo_worker_entry(arg::Ptr{Cvoid})::Ptr{Cvoid}
    work_queue = unsafe_pointer_to_objref(arg)::Channel{_AddrInfoFuture}
    try
        for future in work_queue
            _run_addrinfo_future!(future)
        end
    catch
    end
    return C_NULL
end

function _ensure_addrinfo_pool!()::Channel{_AddrInfoFuture}
    lock(_ADDRINFO_POOL_LOCK)
    try
        if !isassigned(_ADDRINFO_WORK_QUEUE)
            _ADDRINFO_WORK_QUEUE[] = Channel{_AddrInfoFuture}(_ADDRINFO_POOL_CAPACITY)
            _ADDRINFO_STARTED_THREADS[] = 0
        end
        work_queue = _ADDRINFO_WORK_QUEUE[]
        while _ADDRINFO_STARTED_THREADS[] < _ADDRINFO_POOL_SIZE
            next_idx = _ADDRINFO_STARTED_THREADS[] + 1
            IOPoll._spawn_detached_thread("reseau-getaddrinfo-$next_idx", _ADDRINFO_THREAD_ENTRY_C, work_queue)
            _ADDRINFO_STARTED_THREADS[] = next_idx
        end
        return work_queue
    finally
        unlock(_ADDRINFO_POOL_LOCK)
    end
end

function _wait_addrinfo_future!(future::_AddrInfoFuture)::Cint
    lock(future.notify)
    try
        while !future.done
            wait(future.notify)
        end
        future.err === nothing || throw(future.err::Exception)
        return future.ret
    finally
        unlock(future.notify)
    end
end

function __init__()
    _ADDRINFO_THREAD_ENTRY_C[] = @cfunction(_addrinfo_worker_entry, Ptr{Cvoid}, (Ptr{Cvoid},))
    _ADDRINFO_WORK_QUEUE[] = Channel{_AddrInfoFuture}(_ADDRINFO_POOL_CAPACITY)
    _ADDRINFO_STARTED_THREADS[] = 0
end

@static if Sys.iswindows()
    const _IPHLPAPI = "Iphlpapi"
    const _ERROR_BUFFER_OVERFLOW = UInt32(111)
    const _GAA_FLAG_INCLUDE_PREFIX = UInt32(0x00000010)
    const _GAA_FLAG_INCLUDE_GATEWAYS = UInt32(0x00000080)
    const _ZONE_CACHE_TTL_NS = Int64(60_000_000_000)
    const _WINDOWS_ZONE_CACHE_LOCK = ReentrantLock()
    const _WINDOWS_ZONE_CACHE_LAST_FETCH_NS = Ref{Int64}(Int64(0))
    const _WINDOWS_ZONE_CACHE_TO_INDEX = Ref(Dict{String, UInt32}())

    struct _WindowsSocketAddress
        sockaddr::Ptr{Cvoid}
        sockaddrlength::Int32
    end

    struct _WindowsIpAdapterUnicastAddress
        length::UInt32
        flags::UInt32
        next::Ptr{_WindowsIpAdapterUnicastAddress}
        address::_WindowsSocketAddress
        prefix_origin::Int32
        suffix_origin::Int32
        dad_state::Int32
        valid_lifetime::UInt32
        preferred_lifetime::UInt32
        lease_lifetime::UInt32
        on_link_prefix_length::UInt8
    end

    struct _WindowsIpAdapterAnycastAddress
        length::UInt32
        flags::UInt32
        next::Ptr{_WindowsIpAdapterAnycastAddress}
        address::_WindowsSocketAddress
    end

    struct _WindowsIpAdapterMulticastAddress
        length::UInt32
        flags::UInt32
        next::Ptr{_WindowsIpAdapterMulticastAddress}
        address::_WindowsSocketAddress
    end

    struct _WindowsIpAdapterDnsServerAdapter
        length::UInt32
        reserved::UInt32
        next::Ptr{_WindowsIpAdapterDnsServerAdapter}
        address::_WindowsSocketAddress
    end

    struct _WindowsIpAdapterPrefix
        length::UInt32
        flags::UInt32
        next::Ptr{_WindowsIpAdapterPrefix}
        address::_WindowsSocketAddress
        prefix_length::UInt32
    end

    struct _WindowsIpAdapterWinsServerAddress
        length::UInt32
        reserved::UInt32
        next::Ptr{_WindowsIpAdapterWinsServerAddress}
        address::_WindowsSocketAddress
    end

    struct _WindowsIpAdapterGatewayAddress
        length::UInt32
        reserved::UInt32
        next::Ptr{_WindowsIpAdapterGatewayAddress}
        address::_WindowsSocketAddress
    end

    struct _WindowsIpAdapterAddresses
        length::UInt32
        ifindex::UInt32
        next::Ptr{_WindowsIpAdapterAddresses}
        adapter_name::Ptr{UInt8}
        first_unicast_address::Ptr{_WindowsIpAdapterUnicastAddress}
        first_anycast_address::Ptr{_WindowsIpAdapterAnycastAddress}
        first_multicast_address::Ptr{_WindowsIpAdapterMulticastAddress}
        first_dns_server_address::Ptr{_WindowsIpAdapterDnsServerAdapter}
        dns_suffix::Ptr{UInt16}
        description::Ptr{UInt16}
        friendly_name::Ptr{UInt16}
        physical_address::NTuple{8, UInt8}
        physical_address_length::UInt32
        flags::UInt32
        mtu::UInt32
        iftype::UInt32
        oper_status::UInt32
        ipv6_ifindex::UInt32
        zone_indices::NTuple{16, UInt32}
        first_prefix::Ptr{_WindowsIpAdapterPrefix}
        transmit_link_speed::UInt64
        receive_link_speed::UInt64
        first_wins_server_address::Ptr{_WindowsIpAdapterWinsServerAddress}
        first_gateway_address::Ptr{_WindowsIpAdapterGatewayAddress}
    end
end

@inline function _utf16_ptr_string(ptr::Ptr{UInt16})::String
    ptr == C_NULL && return ""
    len = 0
    while unsafe_load(ptr, len + 1) != UInt16(0)
        len += 1
    end
    return transcode(String, unsafe_wrap(Vector{UInt16}, ptr, len))
end

@static if Sys.iswindows()
    function _windows_zone_entries()::Dict{String, UInt32}
        SocketOps.ensure_winsock!()
        size = UInt32(15_000)
        while true
            size_ref = Ref(size)
            buf = Vector{UInt8}(undef, Int(size_ref[]))
            rc = GC.@preserve buf size_ref begin
                ccall(
                    (:GetAdaptersAddresses, _IPHLPAPI),
                    UInt32,
                    (UInt32, UInt32, Ptr{Cvoid}, Ptr{_WindowsIpAdapterAddresses}, Ref{UInt32}),
                    UInt32(_AF_UNSPEC),
                    (_GAA_FLAG_INCLUDE_PREFIX | _GAA_FLAG_INCLUDE_GATEWAYS),
                    C_NULL,
                    Ptr{_WindowsIpAdapterAddresses}(pointer(buf)),
                    size_ref,
                )
            end
            if rc == UInt32(0)
                out = Dict{String, UInt32}()
                GC.@preserve buf begin
                    current = Ptr{_WindowsIpAdapterAddresses}(pointer(buf))
                    while current != C_NULL
                        adapter = unsafe_load(current)
                        name = _utf16_ptr_string(adapter.friendly_name)
                        if !isempty(name)
                            idx = adapter.ifindex == UInt32(0) ? adapter.ipv6_ifindex : adapter.ifindex
                            idx != UInt32(0) && !haskey(out, name) && (out[name] = idx)
                        end
                        current = adapter.next
                    end
                end
                return out
            end
            rc == _ERROR_BUFFER_OVERFLOW || return Dict{String, UInt32}()
            size = size_ref[]
            size <= UInt32(length(buf)) && return Dict{String, UInt32}()
        end
    end

    function _update_windows_zone_cache!(force::Bool)::Bool
        now_ns = Int64(time_ns())
        lock(_WINDOWS_ZONE_CACHE_LOCK)
        try
            if !force && (_WINDOWS_ZONE_CACHE_LAST_FETCH_NS[] + _ZONE_CACHE_TTL_NS) > now_ns
                return false
            end
            _WINDOWS_ZONE_CACHE_LAST_FETCH_NS[] = now_ns
            _WINDOWS_ZONE_CACHE_TO_INDEX[] = _windows_zone_entries()
            return true
        finally
            unlock(_WINDOWS_ZONE_CACHE_LOCK)
        end
    end

    function _windows_zone_index(name::String)::UInt32
        isempty(name) && return UInt32(0)
        updated = _update_windows_zone_cache!(false)
        lock(_WINDOWS_ZONE_CACHE_LOCK)
        try
            idx = get(() -> UInt32(0), _WINDOWS_ZONE_CACHE_TO_INDEX[], name)
            idx != UInt32(0) && return idx
        finally
            unlock(_WINDOWS_ZONE_CACHE_LOCK)
        end
        if !updated
            _update_windows_zone_cache!(true)
            lock(_WINDOWS_ZONE_CACHE_LOCK)
            try
                return get(() -> UInt32(0), _WINDOWS_ZONE_CACHE_TO_INDEX[], name)
            finally
                unlock(_WINDOWS_ZONE_CACHE_LOCK)
            end
        end
        return UInt32(0)
    end
end

@inline function _gai_error_string(code::Cint)::String
    @static if Sys.iswindows()
        code == _WSAHOST_NOT_FOUND && return "no such host"
        code == _DNS_ERROR_RCODE_NAME_ERROR && return "no such host"
        code == _DNS_INFO_NO_RECORDS && return "no DNS records"
        code == _WSATRY_AGAIN && return "temporary failure in name resolution"
        code == _WSATYPE_NOT_FOUND && return "unknown service"
        return "getaddrinfo error code $code"
    else
        ptr = ccall(:gai_strerror, Cstring, (Cint,), code)
        ptr == C_NULL && return "unknown getaddrinfo error code $code"
        return unsafe_string(ptr)
    end
end

function _native_getaddrinfo(hostname::AbstractString; flags::Cint = Cint(0))::Vector{TCP.SocketEndpoint}
    SocketOps.ensure_winsock!()
    addresses = TCP.SocketEndpoint[]
    hostname_s = String(hostname)
    future = _AddrInfoFuture(hostname_s, flags)
    # `getaddrinfo` can block inside the system resolver stack. Run it on a
    # small dedicated worker pool so hostname resolution does not occupy a Julia
    # scheduler thread while callers wait on timeout/deadline machinery.
    put!(_ensure_addrinfo_pool!(), future)
    ret = _wait_addrinfo_future!(future)
    ret == 0 || _lookup_error("lookup failed: $(_gai_error_string(ret))", hostname_s)
    try
        current = future.addr_info_ptr
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
        if future.addr_info_ptr != C_NULL
            @static if Sys.iswindows()
                ccall((:freeaddrinfo, "Ws2_32"), Cvoid, (Ptr{_AddrInfo},), future.addr_info_ptr)
            else
                ccall(:freeaddrinfo, Cvoid, (Ptr{_AddrInfo},), future.addr_info_ptr)
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

function _lookup_error(err::AbstractString, name::AbstractString)
    throw(LookupError(String(err), String(name)))
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
        @gcsafe_ccall inet_pton(
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
        @gcsafe_ccall inet_pton(
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
    idx = @static if Sys.iswindows()
        _windows_zone_index(z)
    else
        @ccall if_nametoindex(z::Cstring)::UInt32
    end
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
    port === nothing && _lookup_error("unknown port", string(network, "/", service))
    return port::Int
end

"""
    join_host_port(host, port)

Join host and port into `host:port`, bracket-quoting IPv6 literals.
`port` may be numeric or an opaque service string.

Returns the combined string and never performs resolution.
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

Throws `AddressError` if the string is malformed.
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

Parse a decimal service port and return `(port, needs_lookup)`.

If `needs_lookup` is `true`, the caller should treat `service` as a symbolic
service name such as `"https"` and consult the resolver's service tables.
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

This convenience form uses `DEFAULT_RESOLVER`.
"""
function lookup_port(network::AbstractString, service::AbstractString)::Int
    return lookup_port(DEFAULT_RESOLVER, network, service)
end

function lookup_port(resolver::AbstractResolver, network::AbstractString, service::AbstractString)::Int
    _ = resolver
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
            throw(UnknownNetworkError(n))
        end
    end
    (port < 0 || port > 65535) && _addr_error("invalid port", service)
    return port
end

function lookup_port(resolver::StaticResolver, network::AbstractString, service::AbstractString)::Int
    port, needs_lookup = parse_port(service)
    if needs_lookup
        n = String(network)
        fallback = resolver.fallback
        if n == "tcp" || n == "tcp4" || n == "tcp6" || n == "" || n == "ip"
            p = get(() -> nothing, resolver.services_tcp, lowercase(String(service)))
            if p !== nothing
                port = p::Int
            elseif fallback !== nothing
                return lookup_port(fallback, network, service)
            else
                port = _parse_port_table(_SERVICE_TCP, n, service)
            end
        elseif n == "udp" || n == "udp4" || n == "udp6"
            p = get(() -> nothing, resolver.services_udp, lowercase(String(service)))
            if p !== nothing
                port = p::Int
            elseif fallback !== nothing
                return lookup_port(fallback, network, service)
            else
                port = _parse_port_table(_SERVICE_UDP, n, service)
            end
        else
            throw(UnknownNetworkError(n))
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
    )
    out = if kind == :tcp4 || (!policy.allow_ipv6 && policy.allow_ipv4)
        TCP.SocketAddrV4[]
    elseif kind == :tcp6 || (!policy.allow_ipv4 && policy.allow_ipv6)
        TCP.SocketAddrV6[]
    else
        TCP.SocketEndpoint[]
    end
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
    return _resolve_static_host(resolver, "tcp", host)
end

function _resolve_static_host(
        resolver::StaticResolver,
        network::AbstractString,
        host::AbstractString,
    )::Vector{TCP.SocketEndpoint}
    h = String(host)
    literal = _literal_host_addr(h)
    literal === nothing || return TCP.SocketEndpoint[literal]
    mapped = get(() -> nothing, resolver.hosts, lowercase(h))
    mapped === nothing || return copy(mapped::Vector{TCP.SocketEndpoint})
    fallback = resolver.fallback
    fallback === nothing && _lookup_error("no suitable address", h)
    return _resolve_host_ips(fallback, network, h)
end

function _resolve_host_ips(resolver::AbstractResolver, host::AbstractString)::Vector{TCP.SocketEndpoint}
    return _resolve_host_ips(resolver, "tcp", host)
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
    literal = _literal_host_addr(h)
    literal === nothing || return TCP.SocketEndpoint[literal]
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

function _evict_cache_if_needed_locked!(resolver::CachingResolver)
    length(resolver.entries) <= resolver.max_hosts && return nothing
    oldest_key = nothing
    oldest_access = typemax(Int64)
    for (key, entry) in resolver.entries
        if entry.last_access_ns < oldest_access
            oldest_access = entry.last_access_ns
            oldest_key = key
        end
    end
    oldest_key === nothing || delete!(resolver.entries, oldest_key)
    return nothing
end

function _store_cache_entry_locked!(
        resolver::CachingResolver,
        key::Tuple{String, String},
        result::Union{Nothing, Vector{TCP.SocketEndpoint}},
        err::Union{Nothing, Exception},
        now_ns::Int64,
    )
    expires_ns = now_ns
    stale_expires_ns = now_ns
    if err === nothing
        expires_ns += resolver.ttl_ns
        stale_expires_ns = expires_ns + resolver.stale_ttl_ns
    else
        expires_ns += resolver.negative_ttl_ns
        stale_expires_ns = expires_ns
    end
    resolver.entries[key] = _LookupCacheEntry(
        result === nothing ? nothing : copy(result::Vector{TCP.SocketEndpoint}),
        err,
        expires_ns,
        stale_expires_ns,
        now_ns,
        false,
    )
    _evict_cache_if_needed_locked!(resolver)
    return nothing
end

function _refresh_cached_host!(
        resolver::CachingResolver,
        key::Tuple{String, String},
        network::String,
        host::String,
    )
    result = nothing
    err = nothing
    try
        result = _resolve_host_ips(resolver.parent, network, host)
    catch ex
        err = ex::Exception
    end
    now_ns = Int64(time_ns())
    lock(resolver.lock)
    try
        entry = get(() -> nothing, resolver.entries, key)
        entry === nothing && return nothing
        if err === nothing
            _store_cache_entry_locked!(resolver, key, result::Vector{TCP.SocketEndpoint}, nothing, now_ns)
            return nothing
        end
        entry.refreshing = false
        if err isa LookupError && resolver.negative_ttl_ns > 0
            _store_cache_entry_locked!(resolver, key, nothing, err, now_ns)
        end
    finally
        unlock(resolver.lock)
    end
    return nothing
end

function _resolve_cached_host(
        resolver::CachingResolver,
        network::AbstractString,
        host::AbstractString,
    )::Vector{TCP.SocketEndpoint}
    h = String(host)
    literal = _literal_host_addr(h)
    literal === nothing || return TCP.SocketEndpoint[literal]
    key = _lookup_key(network, h)
    now_ns = Int64(time_ns())
    stale_result = nothing
    refresh_needed = false
    lock(resolver.lock)
    try
        entry = get(() -> nothing, resolver.entries, key)
        if entry !== nothing
            entry.last_access_ns = now_ns
            if now_ns <= entry.expires_ns
                if entry.err === nothing
                    @atomic :acquire_release resolver.cache_hits += 1
                    return copy(entry.result::Vector{TCP.SocketEndpoint})
                end
                @atomic :acquire_release resolver.negative_hits += 1
                throw(entry.err::Exception)
            end
            if entry.err === nothing && now_ns <= entry.stale_expires_ns
                @atomic :acquire_release resolver.stale_hits += 1
                stale_result = copy(entry.result::Vector{TCP.SocketEndpoint})
                if !entry.refreshing
                    entry.refreshing = true
                    refresh_needed = true
                end
            else
                delete!(resolver.entries, key)
            end
        end
        stale_result === nothing && (@atomic :acquire_release resolver.misses += 1)
    finally
        unlock(resolver.lock)
    end
    if stale_result !== nothing
        if refresh_needed
            errormonitor(@async _refresh_cached_host!(resolver, key, String(network), h))
        end
        return stale_result::Vector{TCP.SocketEndpoint}
    end
    result = nothing
    err = nothing
    try
        result = _resolve_host_ips(resolver.parent, network, h)
    catch ex
        err = ex::Exception
    end
    now_ns = Int64(time_ns())
    lock(resolver.lock)
    try
        if err === nothing
            _store_cache_entry_locked!(resolver, key, result::Vector{TCP.SocketEndpoint}, nothing, now_ns)
        elseif err isa LookupError && resolver.negative_ttl_ns > 0
            _store_cache_entry_locked!(resolver, key, nothing, err, now_ns)
        end
    finally
        unlock(resolver.lock)
    end
    err === nothing || throw(err::Exception)
    return result::Vector{TCP.SocketEndpoint}
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
        return _resolve_cached_host(resolver::CachingResolver, network, host)
    end
    if resolver isa SystemResolver
        return _resolve_system_host(host)
    end
    if resolver isa StaticResolver
        return _resolve_static_host(resolver::StaticResolver, network, host)
    end
    resolved = resolve_tcp_addrs(
        resolver,
        network,
        join_host_port(host, 0);
        op = :resolve,
        policy = ResolverPolicy(),
    )
    ips = TCP.SocketEndpoint[]
    for addr in resolved
        if addr isa TCP.SocketAddrV4
            v4 = addr::TCP.SocketAddrV4
            push!(ips, TCP.SocketAddrV4(v4.ip, 0))
        else
            v6 = addr::TCP.SocketAddrV6
            push!(ips, TCP.SocketAddrV6(v6.ip, 0; scope_id = Int(v6.scope_id)))
        end
    end
    return ips
end

lookup_port(resolver::SingleflightResolver, network::AbstractString, service::AbstractString)::Int =
    lookup_port((resolver::SingleflightResolver).parent, network, service)

lookup_port(resolver::CachingResolver, network::AbstractString, service::AbstractString)::Int =
    lookup_port((resolver::CachingResolver).parent, network, service)

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

Arguments:
- `resolver`: resolver implementation used for host and service lookup
- `network`: one of `"tcp"`, `"tcp4"`, or `"tcp6"`
- `address`: host/port string

Keyword arguments:
- `op`: context for wildcard handling, typically `:connect`, `:listen`, or
  `:resolve`
- `policy`: address-family filtering and ordering policy

Returns a `Vector{TCP.SocketEndpoint}` in the order that subsequent connection
logic should attempt.

Throws `AddressError`, `LookupError`, or `UnknownNetworkError` when parsing or
resolution fails.
"""
function resolve_tcp_addrs(
        resolver::AbstractResolver,
        network::AbstractString,
        address::AbstractString;
        op::Symbol = :connect,
        policy::ResolverPolicy = ResolverPolicy(),
    )
    kind = _network_kind(network)
    addr = String(address)
    op == :connect && isempty(addr) && _addr_error("missing address", addr)
    host, service = split_host_port(addr)
    port = lookup_port(resolver, network, service)
    ips = if isempty(host)
        _wildcard_addrs(kind, op)
    else
        _resolve_host_ips(resolver, network, host)
    end
    filtered = _apply_policy_and_network(ips, kind, policy)
    isempty(filtered) && _lookup_error("no suitable address", host)
    out = empty(similar(filtered))
    for ipaddr in filtered
        push!(out, _with_port(ipaddr, port))
    end
    return out
end

"""
    resolve_tcp_addrs(network, address) -> Vector{TCP.SocketEndpoint}

Resolve concrete TCP endpoints using `DEFAULT_RESOLVER`.
"""
function resolve_tcp_addrs(network::AbstractString, address::AbstractString)
    return resolve_tcp_addrs(DEFAULT_RESOLVER, network, address)
end

"""
    resolve_tcp_addr(resolver, network, address; policy=ResolverPolicy())

Resolve and return the first preferred TCP endpoint.

This is a convenience wrapper over `resolve_tcp_addrs` that returns only the
first candidate after policy ordering is applied.
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

"""
    resolve_tcp_addr(network, address) -> TCP.SocketEndpoint

Resolve the first preferred endpoint using `DEFAULT_RESOLVER`.
"""
function resolve_tcp_addr(network::AbstractString, address::AbstractString)::TCP.SocketEndpoint
    return resolve_tcp_addr(DEFAULT_RESOLVER, network, address)
end

"""
    HostResolver

Connect configuration for timeout/deadline handling, optional local bind
selection, and resolver/policy injection.

Fields:
- `timeout_ns`: relative timeout budget for the whole resolve+connect operation
- `deadline_ns`: absolute monotonic deadline for the whole operation
- `local_addr`: optional local bind address for outbound connects
- `fallback_delay_ns`: delay before starting the secondary address-family racer;
  negative disables the parallel race
- `resolver`: resolver implementation for host/service lookup
- `policy`: address ordering/filtering policy

The effective deadline is the earlier non-zero value of `now + timeout_ns` and
`deadline_ns`.
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

@inline function _dual_stack_enabled(d::HostResolver)::Bool
    return d.fallback_delay_ns >= 0
end

@inline function _effective_fallback_delay_ns(d::HostResolver)::Int64
    if d.fallback_delay_ns > 0
        return d.fallback_delay_ns
    end
    return Int64(300_000_000)
end

@inline function _use_parallel_race(d::HostResolver, kind::Symbol, fallbacks::AbstractVector{<:TCP.SocketEndpoint})::Bool
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

function _spawn_timer_task(f::F, deadline_ns::Int64) where {F}
    timer = IOPoll.TimerState(deadline_ns, Int64(0))
    IOPoll.schedule_timer!(timer, deadline_ns) || return nothing, nothing
    task = errormonitor(@async begin
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

const _ResolvedConnectAddrs = Union{
    Vector{TCP.SocketAddrV4},
    Vector{TCP.SocketAddrV6},
    Vector{TCP.SocketEndpoint},
}

function _normalize_resolved_connect_addrs(result)::_ResolvedConnectAddrs
    if result isa Vector{TCP.SocketAddrV4}
        return result
    elseif result isa Vector{TCP.SocketAddrV6}
        return result
    elseif result isa Vector{TCP.SocketEndpoint}
        return result
    elseif result isa AbstractVector{<:TCP.SocketEndpoint}
        out = TCP.SocketEndpoint[]
        for addr in result
            push!(out, addr)
        end
        return out
    end
    throw(ArgumentError("resolver returned unsupported address container"))
end

function _resolve_with_deadline(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        deadline_ns::Int64,
    )::_ResolvedConnectAddrs
    deadline_ns == 0 && return resolve_tcp_addrs(d.resolver, network, address; op = :connect, policy = d.policy)
    now_ns = Int64(time_ns())
    now_ns >= deadline_ns && throw(DialTimeoutError(String(address)))
    mtx = ReentrantLock()
    condition = Threads.Condition(mtx)
    done = Ref(false)
    timed_out = Ref(false)
    result_ref = Ref{Union{Nothing, _ResolvedConnectAddrs, Exception}}(nothing)
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
    errormonitor(@async begin
        resolved_or_err = try
            resolve_tcp_addrs(d.resolver, network, address; op = :connect, policy = d.policy)
        catch err
            _as_exception(err)
        end
        stored_result = resolved_or_err isa Exception ? resolved_or_err : _normalize_resolved_connect_addrs(resolved_or_err)
        lock(mtx)
        try
            done[] && return nothing
            result_ref[] = stored_result
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
    timed_out[] && throw(DialTimeoutError(String(address)))
    resolved = result_ref[]
    resolved === nothing && throw(DialTimeoutError(String(address)))
    resolved isa Exception && throw(resolved)
    resolved isa _ResolvedConnectAddrs || throw(ArgumentError("resolver returned unsupported address container"))
    return resolved
end

_coerce_connect_addrs_v4(resolved::Vector{TCP.SocketAddrV4}) = resolved
_coerce_connect_addrs_v4(::Vector{TCP.SocketAddrV6}) = throw(ArgumentError("resolver returned unexpected address family for tcp4"))

function _coerce_connect_addrs_v4(resolved::Vector{TCP.SocketEndpoint})::Vector{TCP.SocketAddrV4}
    out = TCP.SocketAddrV4[]
    for addr in resolved
        push!(out, addr::TCP.SocketAddrV4)
    end
    return out
end

_coerce_connect_addrs_v6(resolved::Vector{TCP.SocketAddrV6}) = resolved
_coerce_connect_addrs_v6(::Vector{TCP.SocketAddrV4}) = throw(ArgumentError("resolver returned unexpected address family for tcp6"))

function _coerce_connect_addrs_v6(resolved::Vector{TCP.SocketEndpoint})::Vector{TCP.SocketAddrV6}
    out = TCP.SocketAddrV6[]
    for addr in resolved
        push!(out, addr::TCP.SocketAddrV6)
    end
    return out
end

_coerce_connect_addrs_any(resolved::Vector{TCP.SocketEndpoint}) = resolved
function _coerce_connect_addrs_any(resolved::Vector{TCP.SocketAddrV4})::Vector{TCP.SocketEndpoint}
    out = TCP.SocketEndpoint[]
    for addr in resolved
        push!(out, addr)
    end
    return out
end

function _coerce_connect_addrs_any(resolved::Vector{TCP.SocketAddrV6})::Vector{TCP.SocketEndpoint}
    out = TCP.SocketEndpoint[]
    for addr in resolved
        push!(out, addr)
    end
    return out
end

function _resolve_connect_addrs(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        deadline_ns::Int64,
        ::Val{:tcp4},
    )::Vector{TCP.SocketAddrV4}
    resolved = _resolve_with_deadline(d, network, address, deadline_ns)
    return _coerce_connect_addrs_v4(resolved)
end

function _resolve_connect_addrs(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        deadline_ns::Int64,
        ::Val{:tcp6},
    )::Vector{TCP.SocketAddrV6}
    resolved = _resolve_with_deadline(d, network, address, deadline_ns)
    return _coerce_connect_addrs_v6(resolved)
end

function _resolve_connect_addrs(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        deadline_ns::Int64,
        ::Val{:tcp},
    )::Vector{TCP.SocketEndpoint}
    resolved = _resolve_with_deadline(d, network, address, deadline_ns)
    return _coerce_connect_addrs_any(resolved)
end

function _partial_deadline_ns(now_ns::Int64, deadline_ns::Int64, addrs_remaining::Int)::Int64
    deadline_ns == 0 && return Int64(0)
    time_remaining = deadline_ns - now_ns
    time_remaining <= 0 && throw(DialTimeoutError(""))
    # Avoid spending the entire remaining budget on the first address candidate
    # when multiple endpoints remain to be tried.
    timeout = time_remaining ÷ addrs_remaining
    sane_min = Int64(2_000_000_000)
    if timeout < sane_min
        timeout = time_remaining < sane_min ? time_remaining : sane_min
    end
    return now_ns + timeout
end

function _partition_addrs(addrs::AbstractVector{A}) where {A<:TCP.SocketEndpoint}
    isempty(addrs) && return A[], A[]
    primary_is_v4 = _is_ipv4(addrs[1])
    primaries = A[]
    fallbacks = A[]
    for addr in addrs
        if _is_ipv4(addr) == primary_is_v4
            push!(primaries, addr)
        else
            push!(fallbacks, addr)
        end
    end
    return primaries, fallbacks
end

@inline function _prefer_ipv4_first!(addrs::AbstractVector{<:TCP.SocketEndpoint}, policy::ResolverPolicy)
    _ = addrs
    _ = policy
    return nothing
end

@inline function _same_addr_family(a::TCP.SocketEndpoint, b::TCP.SocketEndpoint)::Bool
    return (_is_ipv4(a) && _is_ipv4(b)) || (_is_ipv6(a) && _is_ipv6(b))
end

@inline function _wrap_op_error(
        op::AbstractString,
        net::AbstractString,
        source::Union{Nothing, TCP.SocketEndpoint},
        addr::Union{Nothing, TCP.SocketEndpoint},
        err::Exception,
    )::OpError
    return OpError(String(op), String(net), source, addr, err)
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
        addrs::AbstractVector{A},
        deadline_ns::Int64,
        state::DNSRaceState,
    )::Tuple{Union{Nothing, TCP.Conn}, Union{Nothing, Exception}} where {A<:TCP.SocketEndpoint}
    first_err::Union{Nothing, Exception} = nothing
    for (i, remote_addr) in pairs(addrs)
        if @atomic :acquire state.done
            return nothing, first_err
        end
        now_ns = Int64(time_ns())
        if deadline_ns != 0 && now_ns >= deadline_ns
            return nothing, DialTimeoutError(String(address))
        end
        attempt_deadline = try
            _partial_deadline_ns(now_ns, deadline_ns, length(addrs) - i + 1)
        catch err
            err isa DialTimeoutError || rethrow(err)
            return nothing, DialTimeoutError(String(address))
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
                    mapped = ex isa IOPoll.DeadlineExceededError ? DialTimeoutError(String(address)) : ex
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
        primaries::AbstractVector{A},
        fallbacks::AbstractVector{B},
        deadline_ns::Int64,
    )::Tuple{Union{Nothing, TCP.Conn}, Union{Nothing, Exception}} where {A<:TCP.SocketEndpoint, B<:TCP.SocketEndpoint}
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
    function _start_racer(primary::Bool, addrs::AbstractVector{<:TCP.SocketEndpoint})
        return errormonitor(@async begin
            conn, err = _resolve_serial(d, network, address, addrs, deadline_ns, state)
            _emit_event!(DNSParallelResult(primary, conn, err))
            return nothing
        end)
    end
    _start_racer(true, primaries)
    delay_ns = _effective_fallback_delay_ns(d)
    # This is the Happy Eyeballs-style stagger: start one address family first,
    # then launch the fallback family if the primary path has not succeeded
    # quickly enough.
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

function _resolve_serial_families(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        primaries::AbstractVector{A},
        fallbacks::AbstractVector{B},
        deadline_ns::Int64,
    )::Tuple{Union{Nothing, TCP.Conn}, Union{Nothing, Exception}} where {A<:TCP.SocketEndpoint, B<:TCP.SocketEndpoint}
    primary_state = DNSRaceState()
    conn, err = _resolve_serial(d, network, address, primaries, deadline_ns, primary_state)
    conn !== nothing && return conn, nothing
    isempty(fallbacks) && return nothing, err
    fallback_state = DNSRaceState()
    fallback_conn, fallback_err = _resolve_serial(d, network, address, fallbacks, deadline_ns, fallback_state)
    fallback_conn !== nothing && return fallback_conn, nothing
    return nothing, err === nothing ? fallback_err : err
end

function _connect_resolved_addrs_impl(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        kind::Symbol,
        deadline_ns::Int64,
        addrs::Vector{A},
    )::TCP.Conn where {A<:TCP.SocketEndpoint}
    if d.local_addr !== nothing
        local_addr = d.local_addr::TCP.SocketEndpoint
        filtered = A[]
        for addr in addrs
            _same_addr_family(addr, local_addr) && push!(filtered, addr)
        end
        if isempty(filtered)
            throw(_wrap_op_error("connect", network, local_addr, nothing, ArgumentError("local and remote address families must match")))
        end
        addrs = filtered
    end
    if deadline_ns != 0 && Int64(time_ns()) >= deadline_ns
        throw(_wrap_op_error("connect", network, d.local_addr, nothing, DialTimeoutError(String(address))))
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

function _connect_resolved_addrs_impl(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        kind::Symbol,
        deadline_ns::Int64,
        addrs::Vector{TCP.SocketEndpoint},
    )::TCP.Conn
    if d.local_addr !== nothing
        local_addr = d.local_addr::TCP.SocketEndpoint
        if local_addr isa TCP.SocketAddrV4
            filtered = TCP.SocketAddrV4[]
            for addr in addrs
                addr isa TCP.SocketAddrV4 && push!(filtered, addr)
            end
            if isempty(filtered)
                throw(_wrap_op_error("connect", network, local_addr, nothing, ArgumentError("local and remote address families must match")))
            end
            return _connect_resolved_addrs_impl(d, network, address, kind, deadline_ns, filtered)
        else
            filtered = TCP.SocketAddrV6[]
            for addr in addrs
                addr isa TCP.SocketAddrV6 && push!(filtered, addr::TCP.SocketAddrV6)
            end
            if isempty(filtered)
                throw(_wrap_op_error("connect", network, local_addr, nothing, ArgumentError("local and remote address families must match")))
            end
            return _connect_resolved_addrs_impl(d, network, address, kind, deadline_ns, filtered)
        end
    end
    if deadline_ns != 0 && Int64(time_ns()) >= deadline_ns
        throw(_wrap_op_error("connect", network, d.local_addr, nothing, DialTimeoutError(String(address))))
    end
    _prefer_ipv4_first!(addrs, d.policy)
    primary_is_v4 = !isempty(addrs) && addrs[1] isa TCP.SocketAddrV4
    if primary_is_v4
        primaries = TCP.SocketAddrV4[]
        fallbacks = TCP.SocketAddrV6[]
        for addr in addrs
            if addr isa TCP.SocketAddrV4
                push!(primaries, addr)
            else
                push!(fallbacks, addr::TCP.SocketAddrV6)
            end
        end
        conn, err = if _use_parallel_race(d, kind, fallbacks)
            _resolve_parallel(d, network, address, primaries, fallbacks, deadline_ns)
        else
            _resolve_serial_families(d, network, address, primaries, fallbacks, deadline_ns)
        end
        conn !== nothing && return conn
        throw(_wrap_op_error(
            "connect",
            network,
            d.local_addr,
            isempty(primaries) ? (isempty(fallbacks) ? nothing : fallbacks[1]) : primaries[1],
            err === nothing ? AddressError("missing address", String(address)) : err::Exception,
        ))
    end
    primaries = TCP.SocketAddrV6[]
    fallbacks = TCP.SocketAddrV4[]
    for addr in addrs
        if addr isa TCP.SocketAddrV6
            push!(primaries, addr)
        else
            push!(fallbacks, addr::TCP.SocketAddrV4)
        end
    end
    conn, err = if _use_parallel_race(d, kind, fallbacks)
        _resolve_parallel(d, network, address, primaries, fallbacks, deadline_ns)
    else
        _resolve_serial_families(d, network, address, primaries, fallbacks, deadline_ns)
    end
    conn !== nothing && return conn
    throw(_wrap_op_error(
        "connect",
        network,
        d.local_addr,
        isempty(primaries) ? (isempty(fallbacks) ? nothing : fallbacks[1]) : primaries[1],
        err === nothing ? AddressError("missing address", String(address)) : err::Exception,
    ))
end

function _connect_resolved_addrs(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        kind::Symbol,
        deadline_ns::Int64,
        addrs,
    )::TCP.Conn
    if addrs isa Vector{TCP.SocketAddrV4}
        return _connect_resolved_addrs_impl(d, network, address, kind, deadline_ns, addrs)
    elseif addrs isa Vector{TCP.SocketAddrV6}
        return _connect_resolved_addrs_impl(d, network, address, kind, deadline_ns, addrs)
    elseif addrs isa Vector{TCP.SocketEndpoint}
        return _connect_resolved_addrs_impl(d, network, address, kind, deadline_ns, addrs)
    end
    throw(ArgumentError("resolver returned unsupported address container"))
end

function _connect_v4(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        deadline_ns::Int64,
    )::TCP.Conn
    addrs = _resolve_connect_addrs(d, network, address, deadline_ns, Val(:tcp4))
    return _connect_resolved_addrs_impl(d, network, address, :tcp4, deadline_ns, addrs)
end

function _connect_v6(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        deadline_ns::Int64,
    )::TCP.Conn
    addrs = _resolve_connect_addrs(d, network, address, deadline_ns, Val(:tcp6))
    return _connect_resolved_addrs_impl(d, network, address, :tcp6, deadline_ns, addrs)
end

function _connect_dualstack(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
        deadline_ns::Int64,
    )::TCP.Conn
    addrs = _resolve_connect_addrs(d, network, address, deadline_ns, Val(:tcp))
    return _connect_resolved_addrs_impl(d, network, address, :tcp, deadline_ns, addrs)
end

"""
    connect(d, network, address)

Connect a TCP connection from a `host:port` string.

This resolves the address, applies deadline and policy rules, optionally runs a
dual-stack race, and returns a connected `TCP.Conn`.

Throws `OpError` on failure. The wrapped `err` may be an `AddressError`,
`LookupError`, `DialTimeoutError`, `UnknownNetworkError`, `SystemError`, or a
lower-level poll error depending on which phase failed.
"""
function connect(
        d::HostResolver,
        network::AbstractString,
        address::AbstractString,
    )::TCP.Conn
    deadline_ns = _connect_deadline_ns(d)
    if deadline_ns != 0 && Int64(time_ns()) >= deadline_ns
        throw(_wrap_op_error("connect", network, d.local_addr, nothing, DialTimeoutError(String(address))))
    end
    kind = try
        _network_kind(network)
    catch err
        throw(_wrap_op_error("connect", network, d.local_addr, nothing, _as_exception(err)))
    end
    try
        if kind === :tcp4
            return _connect_v4(d, network, address, deadline_ns)
        elseif kind === :tcp6
            return _connect_v6(d, network, address, deadline_ns)
        end
        return _connect_dualstack(d, network, address, deadline_ns)
    catch err
        err isa OpError && rethrow(err)
        throw(_wrap_op_error("connect", network, d.local_addr, nothing, _as_exception(err)))
    end
end

"""
    connect(network, address; kwargs...) -> TCP.Conn

Connect using a default `HostResolver`.

All keyword arguments are forwarded to `HostResolver(; kwargs...)`, so callers
can configure `timeout_ns`, `deadline_ns`, `local_addr`, `fallback_delay_ns`,
`resolver`, and `policy` without explicitly constructing a resolver first.
"""
function connect(
        network::AbstractString,
        address::AbstractString;
        kwargs...,
    )::TCP.Conn
    resolver = isempty(kwargs) ? HostResolver() : HostResolver(; kwargs...)
    return connect(resolver, network, address)
end

"""
    connect(address; kwargs...) -> TCP.Conn

Convenience shorthand for `connect("tcp", address; kwargs...)`.
"""
function connect(
        address::AbstractString;
        kwargs...,
    )::TCP.Conn
    return connect("tcp", address; kwargs...)
end

"""
    listen(d, network, address; backlog=128, reuseaddr=true)

Listen on a resolved local endpoint.

The address string is resolved into one or more concrete local endpoints. Each
candidate is tried in order until one bind/listen succeeds.

Keyword arguments:
- `backlog`: listen backlog passed to the kernel
- `reuseaddr`: whether to enable `SO_REUSEADDR` on the underlying socket

Throws `OpError` if resolution fails or no candidate can be bound.
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

"""
    listen(network, address; backlog=128, reuseaddr=true) -> TCP.Listener

Listen using a default `HostResolver`.
"""
function listen(
        network::AbstractString,
        address::AbstractString;
        backlog::Integer = 128,
        reuseaddr::Bool = true,
    )::TCP.Listener
    return listen(HostResolver(), network, address; backlog = backlog, reuseaddr = reuseaddr)
end
end
