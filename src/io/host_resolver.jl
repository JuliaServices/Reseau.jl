# AWS IO Library - Host Resolver
# Port of aws-c-io/source/host_resolver.c

# Address type for resolved hosts
@enumx HostAddressType::UInt8 begin
    A = 0     # IPv4
    AAAA = 1  # IPv6
end

# Flags for host address count queries
const GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A = UInt32(0x00000001)
const GET_HOST_ADDRESS_COUNT_RECORD_TYPE_AAAA = UInt32(0x00000002)
const GET_HOST_ADDRESS_COUNT_ALL =
    GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A | GET_HOST_ADDRESS_COUNT_RECORD_TYPE_AAAA

# Host address - a single resolved address for a host
mutable struct HostAddress
    address::String  # The IP address as a string
    address_type::HostAddressType.T
    weight::UInt8  # For load balancing / sorting
    connection_failure_count::UInt32
    expiry::UInt64  # Timestamp in nanoseconds when this entry expires
    use_count::UInt32  # How many times this address has been used
    host::String  # The original hostname
end

function HostAddress(address::AbstractString, address_type::HostAddressType.T, host::AbstractString, ttl_nanos::UInt64)
    return HostAddress(
        String(address),
        address_type,
        UInt8(0),
        UInt32(0),
        ttl_nanos,
        UInt32(0),
        String(host),
    )
end

# Copy a host address
function Base.copy(addr::HostAddress)
    return HostAddress(
        addr.address,
        addr.address_type,
        addr.weight,
        addr.connection_failure_count,
        addr.expiry,
        addr.use_count,
        addr.host,
    )
end

# Host resolver callback types
const OnHostResolvedFn = Function  # (resolver, host_name, error_code, addresses::Vector{HostAddress}) -> nothing
const OnHostResolveCompleteFn = Function  # (resolver, user_data) -> nothing

# Resolution request - tracking structure for an outstanding DNS query
mutable struct HostResolverResolutionRequest{F <: Union{OnHostResolvedFn, Nothing}, U}
    host_name::String
    address_type::HostAddressType.T
    on_resolved::F  # nullable
    user_data::U
    # Linked list for queued requests
    next::Union{HostResolverResolutionRequest, Nothing}  # nullable
end

# Host entry - cached data for a resolved host
mutable struct HostEntry
    host_name::String
    addresses_a::Vector{HostAddress}      # IPv4 addresses
    addresses_aaaa::Vector{HostAddress}   # IPv6 addresses
    failed_addresses_a::Vector{HostAddress}
    failed_addresses_aaaa::Vector{HostAddress}
    pending_a::Bool  # A (IPv4) resolution pending
    pending_aaaa::Bool  # AAAA (IPv6) resolution pending
    last_resolve_request_time::UInt64
    resolved_time::UInt64
    resolve_frequency_ns::UInt64
    max_ttl_secs::UInt64
    resolve_impl::Union{Function, Nothing}
    resolve_impl_data::Any
    # Linked list of waiting requests
    pending_requests_a::Union{HostResolverResolutionRequest, Nothing}  # nullable
    pending_requests_aaaa::Union{HostResolverResolutionRequest, Nothing}  # nullable
end

function HostEntry(host_name::AbstractString, config)
    return HostEntry(
        String(host_name),
        Vector{HostAddress}(),
        Vector{HostAddress}(),
        Vector{HostAddress}(),
        Vector{HostAddress}(),
        false,
        false,
        UInt64(0),
        UInt64(0),
        config.resolve_frequency_ns == 0 ? UInt64(1_000_000_000) : config.resolve_frequency_ns,
        config.max_ttl_secs,
        nothing,
        nothing,
        nothing,
        nothing,
    )
end

# Host resolver configuration
struct HostResolverConfig
    max_entries::UInt64
    max_ttl_secs::UInt64
    min_ttl_secs::UInt64
    max_addresses_per_host::UInt64
    resolve_frequency_ns::UInt64  # How often to re-resolve
    background_refresh::Bool  # Whether to refresh in background
end

struct HostResolutionConfig
    impl::Union{Function, Nothing}
    max_ttl_secs::UInt64
    resolve_frequency_ns::UInt64
    impl_data::Any
end

function HostResolutionConfig(;
        impl::Union{Function, Nothing} = nothing,
        max_ttl_secs::Integer = 0,
        resolve_frequency_ns::Integer = 0,
        impl_data = nothing,
    )
    return HostResolutionConfig(
        impl,
        UInt64(max_ttl_secs),
        UInt64(resolve_frequency_ns),
        impl_data,
    )
end

function HostResolverConfig(;
        max_entries::Integer = 1024,
        max_ttl_secs::Integer = 30,  # 30 seconds default
        min_ttl_secs::Integer = 1,
        max_addresses_per_host::Integer = 8,
        resolve_frequency_ns::Integer = 1_000_000_000,  # 1 second
        background_refresh::Bool = true,
    )
    return HostResolverConfig(
        UInt64(max_entries),
        UInt64(max_ttl_secs),
        UInt64(min_ttl_secs),
        UInt64(max_addresses_per_host),
        UInt64(resolve_frequency_ns),
        background_refresh,
    )
end

# Default TTL in nanoseconds (30 seconds)
const HOST_RESOLVER_DEFAULT_TTL_NS = UInt64(30_000_000_000)

# Cache hash helpers
host_string_hash(key::String) = hash(key)
host_string_eq(a::String, b::String) = a == b
const HostResolverCache = HashTable{
    String,
    HostEntry,
    HashEq{typeof(host_string_hash), typeof(host_string_eq)},
    NoopDestroy,
    NoopDestroy,
}

# Abstract resolver interface
abstract type AbstractHostResolver end

# Default host resolver with caching
mutable struct DefaultHostResolver{ELG} <: AbstractHostResolver
    event_loop_group::ELG
    config::HostResolverConfig
    cache::HostResolverCache
    lock::ReentrantLock
    @atomic shutdown::Bool
end

function DefaultHostResolver(
        event_loop_group::ELG,
        config::HostResolverConfig = HostResolverConfig(),
    ) where {ELG}
    cache = HashTable{String, HostEntry}(
        host_string_hash,
        host_string_eq;
        capacity = Int(config.max_entries),
    )
    resolver = DefaultHostResolver{ELG}(
        event_loop_group,
        config,
        cache,
        ReentrantLock(),
        false,
    )
    return resolver
end

function _entry_addresses(entry::HostEntry, address_type::HostAddressType.T)
    return address_type == HostAddressType.A ? entry.addresses_a : entry.addresses_aaaa
end

function _entry_failed_addresses(entry::HostEntry, address_type::HostAddressType.T)
    return address_type == HostAddressType.A ? entry.failed_addresses_a : entry.failed_addresses_aaaa
end

function _entry_pending(entry::HostEntry, address_type::HostAddressType.T)::Bool
    return address_type == HostAddressType.A ? entry.pending_a : entry.pending_aaaa
end

function _set_entry_pending!(entry::HostEntry, address_type::HostAddressType.T, pending::Bool)
    if address_type == HostAddressType.A
        entry.pending_a = pending
    else
        entry.pending_aaaa = pending
    end
    return nothing
end

function _cache_get_or_create!(resolver::DefaultHostResolver, host::String)::HostEntry
    found, entry = hash_table_get_entry(resolver.cache, host)
    if found
        return entry
    end
    entry = HostEntry(host, resolver.config)
    hash_table_put!(resolver.cache, host, entry)
    return entry
end

function _pending_requests(entry::HostEntry, address_type::HostAddressType.T)
    return address_type == HostAddressType.A ? entry.pending_requests_a : entry.pending_requests_aaaa
end

function _set_pending_requests!(
        entry::HostEntry,
        address_type::HostAddressType.T,
        head::Union{HostResolverResolutionRequest, Nothing},
    )
    if address_type == HostAddressType.A
        entry.pending_requests_a = head
    else
        entry.pending_requests_aaaa = head
    end
    return nothing
end

function _enqueue_request!(
        entry::HostEntry,
        host::String,
        address_type::HostAddressType.T,
        on_resolved::OnHostResolvedFn,
        user_data,
    )
    head = _pending_requests(entry, address_type)
    req = HostResolverResolutionRequest(host, address_type, on_resolved, user_data, head)
    _set_pending_requests!(entry, address_type, req)
    return req
end

function _drain_pending_requests!(
        entry::HostEntry,
        address_type::HostAddressType.T,
    )::Union{HostResolverResolutionRequest, Nothing}
    head = _pending_requests(entry, address_type)
    _set_pending_requests!(entry, address_type, nothing)
    return head
end

function _update_entry_cache!(
        entry::HostEntry,
        addresses::Vector{HostAddress},
        address_type::HostAddressType.T,
    )
    if address_type == HostAddressType.A
        entry.addresses_a = addresses
    else
        entry.addresses_aaaa = addresses
    end
    return nothing
end

function _dispatch_resolved_callback(
        resolver::DefaultHostResolver,
        host::String,
        error_code::Int,
        addresses::Vector{HostAddress},
        on_resolved::OnHostResolvedFn,
    )
    event_loop = event_loop_group_get_next_loop(resolver.event_loop_group)
    if event_loop !== nothing
        task = ScheduledTask(
            (t, status) -> on_resolved(resolver, host, error_code, addresses),
            nothing;
            type_tag = "dns_resolve_cached"
        )
        event_loop_schedule_task_now!(event_loop, task)
    else
        on_resolved(resolver, host, error_code, addresses)
    end
    return nothing
end

function _dispatch_simple_callback(
        resolver::DefaultHostResolver,
        callback::Union{Function, Nothing},
        user_data,
    )
    callback === nothing && return nothing
    event_loop = event_loop_group_get_next_loop(resolver.event_loop_group)
    if event_loop !== nothing
        task = ScheduledTask(
            (t, status) -> callback(user_data),
            nothing;
            type_tag = "dns_purge_callback"
        )
        event_loop_schedule_task_now!(event_loop, task)
    else
        callback(user_data)
    end
    return nothing
end

# Resolve a hostname to addresses
function host_resolver_resolve!(
        resolver::DefaultHostResolver,
        host_name::AbstractString,
        on_resolved::OnHostResolvedFn,
        user_data = nothing;
        address_type::HostAddressType.T = HostAddressType.A,
        resolution_config::Union{HostResolutionConfig, Nothing} = nothing,
    )::Union{Nothing, ErrorResult}
    if @atomic resolver.shutdown
        logf(LogLevel.ERROR, LS_IO_DNS, "Host resolver: resolve called after shutdown")
        raise_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
        return ErrorResult(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end

    host = String(host_name)

    logf(LogLevel.DEBUG, LS_IO_DNS, "Host resolver: resolving host '$host'")

    cached_addresses = HostAddress[]
    schedule_resolution = false

    entry = nothing
    lock(resolver.lock) do
        entry = _cache_get_or_create!(resolver, host)
        if resolution_config !== nothing
            if resolution_config.max_ttl_secs != 0
                entry.max_ttl_secs = resolution_config.max_ttl_secs
            end
            if resolution_config.resolve_frequency_ns != 0
                entry.resolve_frequency_ns = resolution_config.resolve_frequency_ns
            end
            entry.resolve_impl = resolution_config.impl
            entry.resolve_impl_data = resolution_config.impl_data
        end
        addresses = _entry_addresses(entry, address_type)
        failed_addresses = _entry_failed_addresses(entry, address_type)
        current_time = high_res_clock()

        valid_addresses = filter(a -> a.expiry > current_time, addresses)
        if !isempty(valid_addresses)
            logf(
                LogLevel.TRACE, LS_IO_DNS,
                "Host resolver: cache hit for '$host', $(length(valid_addresses)) addresses"
            )

            for addr in valid_addresses
                addr.use_count += 1
            end
            cached_addresses = copy.(valid_addresses)

            if resolver.config.background_refresh
                if !_entry_pending(entry, address_type) &&
                        (
                        entry.resolved_time == 0 ||
                            current_time - entry.resolved_time >= entry.resolve_frequency_ns
                    )
                    _set_entry_pending!(entry, address_type, true)
                    entry.last_resolve_request_time = current_time
                    schedule_resolution = true
                end
            end
        else
            valid_failed = filter(a -> a.expiry > current_time, failed_addresses)
            if !isempty(valid_failed)
                cached_addresses = copy.(valid_failed)
            end
            _enqueue_request!(entry, host, address_type, on_resolved, user_data)
            if !_entry_pending(entry, address_type)
                _set_entry_pending!(entry, address_type, true)
                entry.last_resolve_request_time = current_time
                schedule_resolution = true
            end
        end
    end

    if !isempty(cached_addresses)
        _dispatch_resolved_callback(resolver, host, AWS_OP_SUCCESS, cached_addresses, on_resolved)
    end

    if schedule_resolution
        _perform_dns_resolution(resolver, host, address_type, entry)
    end

    return nothing
end

# Perform actual DNS resolution using getaddrinfo (off the event-loop thread)
function _perform_dns_resolution(
        resolver::DefaultHostResolver,
        host::String,
        address_type::HostAddressType.T,
        entry::HostEntry,
    )
    logf(LogLevel.TRACE, LS_IO_DNS, "Host resolver: performing DNS lookup for '$host'")

    event_loop = event_loop_group_get_next_loop(resolver.event_loop_group)
    config = resolver.config
    max_ttl_secs = entry.max_ttl_secs == 0 ? config.max_ttl_secs : entry.max_ttl_secs
    resolve_impl = entry.resolve_impl
    resolve_impl_data = entry.resolve_impl_data

    Threads.@spawn begin
        addresses, error_code = _dns_lookup(
            host,
            address_type,
            max_ttl_secs,
            config.min_ttl_secs,
            config.max_addresses_per_host,
            resolve_impl,
            resolve_impl_data,
        )

        if event_loop !== nothing
            task = ScheduledTask(
                (t, status) -> _dns_resolution_complete(resolver, host, address_type, addresses, error_code),
                nothing;
                type_tag = "dns_resolution_complete"
            )
            event_loop_schedule_task_now!(event_loop, task)
        else
            _dns_resolution_complete(resolver, host, address_type, addresses, error_code)
        end
    end

    return nothing
end

function _dns_lookup(
        host::String,
        address_type::HostAddressType.T,
        max_ttl_secs::UInt64,
        min_ttl_secs::UInt64,
        max_addresses_per_host::UInt64,
        resolve_impl::Union{Function, Nothing},
        resolve_impl_data,
    )::Tuple{Vector{HostAddress}, Int}
    logf(LogLevel.TRACE, LS_IO_DNS, "Host resolver: DNS lookup executing for '$host'")

    addresses = Vector{HostAddress}()
    error_code = AWS_OP_SUCCESS

    ttl_secs = max_ttl_secs == 0 ?
        Int(HOST_RESOLVER_DEFAULT_TTL_NS ÷ 1_000_000_000) :
        Int(max_ttl_secs)
    if min_ttl_secs > 0 && ttl_secs < Int(min_ttl_secs)
        ttl_secs = Int(min_ttl_secs)
    end
    ttl_nanos = high_res_clock() + UInt64(ttl_secs) * 1_000_000_000

    if resolve_impl !== nothing
        try
            result = resolve_impl(host, address_type, resolve_impl_data)
            if result isa Tuple
                addresses, error_code = result
            else
                addresses = result
                error_code = AWS_OP_SUCCESS
            end
        catch e
            logf(LogLevel.ERROR, LS_IO_DNS, "Host resolver: custom resolve failed for '$host': $e")
            error_code = ERROR_IO_DNS_QUERY_FAILED
        end

        if error_code == AWS_OP_SUCCESS
            for addr in addresses
                if addr.expiry == 0
                    addr.expiry = ttl_nanos
                end
            end
        end

        return addresses, error_code
    end

    try
        family = address_type == HostAddressType.A ? AF_INET : AF_INET6
        addrs = _native_getaddrinfo(host, family)

        if !isempty(addrs)
            max_addresses = Int(max_addresses_per_host)

            for addr_str in Iterators.take(addrs, max_addresses)
                push!(addresses, HostAddress(addr_str, address_type, host, ttl_nanos))
            end

            logf(
                LogLevel.DEBUG, LS_IO_DNS,
                "Host resolver: resolved '$host' to $(length(addresses)) addresses"
            )
        else
            logf(LogLevel.DEBUG, LS_IO_DNS, "Host resolver: no addresses found for '$host'")
            error_code = ERROR_IO_DNS_NO_ADDRESS_FOR_HOST
        end

    catch e
        logf(LogLevel.ERROR, LS_IO_DNS, "Host resolver: DNS resolution failed for '$host': $e")
        error_code = ERROR_IO_DNS_QUERY_FAILED
    end

    return addresses, error_code
end

function _dns_resolution_complete(
        resolver::DefaultHostResolver,
        host::String,
        address_type::HostAddressType.T,
        addresses::Vector{HostAddress},
        error_code::Int,
    )
    pending = nothing

    lock(resolver.lock) do
        entry = _cache_get_or_create!(resolver, host)

        if error_code == AWS_OP_SUCCESS && !isempty(addresses)
            _update_entry_cache!(entry, addresses, address_type)
            if address_type == HostAddressType.A
                empty!(entry.failed_addresses_a)
            else
                empty!(entry.failed_addresses_aaaa)
            end
            entry.resolved_time = high_res_clock()
        end

        _set_entry_pending!(entry, address_type, false)
        pending = _drain_pending_requests!(entry, address_type)

        if length(resolver.cache) > resolver.config.max_entries
            _trim_cache!(resolver)
        end
    end

    req = pending
    while req !== nothing
        if req.on_resolved !== nothing
            Base.invokelatest(req.on_resolved, resolver, host, error_code, copy.(addresses))
        end
        req = req.next
    end

    return nothing
end

# Trim cache by removing oldest entries
function _trim_cache!(resolver::DefaultHostResolver)
    # Simple LRU eviction - remove entries that haven't been used recently
    entries_to_remove = String[]
    current_time = high_res_clock()

    for (host, entry) in resolver.cache
        # Check if all addresses are expired (including failed lists)
        all_expired_a = all(a -> a.expiry < current_time, entry.addresses_a) &&
            all(a -> a.expiry < current_time, entry.failed_addresses_a)
        all_expired_aaaa = all(a -> a.expiry < current_time, entry.addresses_aaaa) &&
            all(a -> a.expiry < current_time, entry.failed_addresses_aaaa)

        if (isempty(entry.addresses_a) && isempty(entry.failed_addresses_a) || all_expired_a) &&
                (isempty(entry.addresses_aaaa) && isempty(entry.failed_addresses_aaaa) || all_expired_aaaa)
            push!(entries_to_remove, host)
        end
    end

    for host in entries_to_remove
        hash_table_remove!(resolver.cache, host)
        if length(resolver.cache) <= resolver.config.max_entries
            break
        end
    end

    return nothing
end

# Purge the entire cache
function host_resolver_purge_cache!(resolver::DefaultHostResolver)
    lock(resolver.lock) do
        hash_table_clear!(resolver.cache)
    end
    logf(LogLevel.DEBUG, LS_IO_DNS, "Host resolver: cache purged")
    return nothing
end

function host_resolver_purge_cache_with_callback!(
        resolver::DefaultHostResolver,
        on_purge_cache_complete::Union{Function, Nothing},
        user_data = nothing,
    )::Union{Nothing, ErrorResult}
    host_resolver_purge_cache!(resolver)
    _dispatch_simple_callback(resolver, on_purge_cache_complete, user_data)
    return nothing
end

function host_resolver_purge_host_cache!(
        resolver::DefaultHostResolver,
        host_name::AbstractString;
        on_host_purge_complete::Union{Function, Nothing} = nothing,
        user_data = nothing,
    )::Union{Nothing, ErrorResult}
    host = String(host_name)
    lock(resolver.lock) do
        hash_table_remove!(resolver.cache, host)
    end
    _dispatch_simple_callback(resolver, on_host_purge_complete, user_data)
    return nothing
end

function host_resolver_get_host_address_count(
        resolver::DefaultHostResolver,
        host_name::AbstractString;
        flags::UInt32 = GET_HOST_ADDRESS_COUNT_ALL,
    )::Csize_t
    host = String(host_name)
    return lock(resolver.lock) do
        entry = hash_table_get(resolver.cache, host)
        entry === nothing && return Csize_t(0)

        count = 0
        if (flags & GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A) != 0
            count += length(entry.addresses_a)
        end
        if (flags & GET_HOST_ADDRESS_COUNT_RECORD_TYPE_AAAA) != 0
            count += length(entry.addresses_aaaa)
        end
        return Csize_t(count)
    end
end

# Get a single best address for a host (simplified version)
function host_resolver_get_address!(
        resolver::DefaultHostResolver,
        host_name::AbstractString;
        address_type::HostAddressType.T = HostAddressType.A,
    )::Union{HostAddress, Nothing}
    host = String(host_name)

    return lock(resolver.lock) do
        entry = hash_table_get(resolver.cache, host)

        if entry === nothing
            return nothing
        end

        addresses = _entry_addresses(entry, address_type)
        failed_addresses = _entry_failed_addresses(entry, address_type)
        current_time = high_res_clock()

        # Find a valid address with lowest connection failure count
        best_addr = nothing
        for addr in addresses
            if addr.expiry > current_time
                if best_addr === nothing || addr.connection_failure_count < best_addr.connection_failure_count
                    best_addr = addr
                end
            end
        end

        if best_addr === nothing
            for addr in failed_addresses
                if addr.expiry > current_time
                    if best_addr === nothing || addr.connection_failure_count < best_addr.connection_failure_count
                        best_addr = addr
                    end
                end
            end
        end

        if best_addr !== nothing
            best_addr.use_count += 1
            return copy(best_addr)
        end

        return nothing
    end
end

# Record a connection failure for an address (for load balancing)
function host_resolver_record_connection_failure!(
        resolver::DefaultHostResolver,
        address::HostAddress,
    )
    lock(resolver.lock) do
        entry = hash_table_get(resolver.cache, address.host)
        if entry === nothing
            return nothing
        end

        addresses = _entry_addresses(entry, address.address_type)
        failed_addresses = _entry_failed_addresses(entry, address.address_type)

        for i in eachindex(addresses)
            addr = addresses[i]
            if addr.address == address.address
                addr.connection_failure_count += 1
                push!(failed_addresses, addr)
                deleteat!(addresses, i)
                logf(
                    LogLevel.TRACE, LS_IO_DNS,
                    "Host resolver: recorded failure for $(addr.address), count=$(addr.connection_failure_count)"
                )
                return nothing
            end
        end

        for addr in failed_addresses
            if addr.address == address.address
                addr.connection_failure_count += 1
                logf(
                    LogLevel.TRACE, LS_IO_DNS,
                    "Host resolver: recorded failure for $(addr.address), count=$(addr.connection_failure_count)"
                )
                break
            end
        end
    end

    return nothing
end

# Shutdown the resolver
function host_resolver_shutdown!(resolver::DefaultHostResolver)
    @atomic resolver.shutdown = true
    logf(LogLevel.DEBUG, LS_IO_DNS, "Host resolver: shutdown initiated")
    return nothing
end

# Native getaddrinfo implementation (avoiding Sockets dependency)

# struct addrinfo from C (used by getaddrinfo)
# Note: The layout differs between platforms
@static if Sys.isapple()
    struct addrinfo
        ai_flags::Cint
        ai_family::Cint
        ai_socktype::Cint
        ai_protocol::Cint
        ai_addrlen::Cuint
        ai_canonname::Ptr{UInt8}
        ai_addr::Ptr{Cvoid}
        ai_next::Ptr{addrinfo}
    end
else  # Linux/Unix
    struct addrinfo
        ai_flags::Cint
        ai_family::Cint
        ai_socktype::Cint
        ai_protocol::Cint
        ai_addrlen::Cuint
        ai_addr::Ptr{Cvoid}
        ai_canonname::Ptr{UInt8}
        ai_next::Ptr{addrinfo}
    end
end

# Constants for getaddrinfo hints
const AI_PASSIVE = Cint(0x0001)
const SOCK_STREAM = Cint(1)

"""
Native getaddrinfo wrapper - returns a vector of IP address strings.
"""
function _native_getaddrinfo(hostname::String, family::Cint)::Vector{String}
    addresses = String[]

    # Set up hints
    hints = Ref{addrinfo}()
    # Zero out the struct
    unsafe_store!(Ptr{UInt8}(Base.unsafe_convert(Ptr{addrinfo}, hints)), 0x00, sizeof(addrinfo))

    # Build hints manually by storing fields
    hints_ptr = Base.unsafe_convert(Ptr{addrinfo}, hints)
    GC.@preserve hints begin
        # ai_family
        unsafe_store!(Ptr{Cint}(hints_ptr + fieldoffset(addrinfo, 2)), family)
        # ai_socktype
        unsafe_store!(Ptr{Cint}(hints_ptr + fieldoffset(addrinfo, 3)), SOCK_STREAM)
    end

    # Call getaddrinfo
    result_ptr = Ref{Ptr{addrinfo}}(C_NULL)
    ret = GC.@preserve hints begin
        ccall(
            :getaddrinfo, Cint,
            (Cstring, Ptr{Cvoid}, Ptr{addrinfo}, Ptr{Ptr{addrinfo}}),
            hostname, C_NULL, hints_ptr, result_ptr
        )
    end

    if ret != 0
        # DNS resolution failed
        return addresses
    end

    # Walk the linked list of results
    current = result_ptr[]
    while current != C_NULL
        ai = unsafe_load(current)

        # Extract address based on family
        if ai.ai_family == AF_INET && ai.ai_addr != C_NULL
            # IPv4 - address is at offset 4 in sockaddr_in (after sin_family and sin_port)
            addr_ptr = Ptr{UInt32}(ai.ai_addr + 4)
            addr_val = unsafe_load(addr_ptr)

            # Convert to dotted decimal string
            buf = Memory{UInt8}(undef, 16)
            ret = GC.@preserve buf begin
                ccall(
                    :inet_ntop, Ptr{UInt8},
                    (Cint, Ptr{UInt32}, Ptr{UInt8}, Cuint),
                    AF_INET, addr_ptr, pointer(buf), Cuint(16)
                )
            end
            if ret != C_NULL
                push!(addresses, unsafe_string(pointer(buf)))
            end
        elseif ai.ai_family == AF_INET6 && ai.ai_addr != C_NULL
            # IPv6 - address is at offset 8 in sockaddr_in6 (after sin6_family, sin6_port, sin6_flowinfo)
            addr_ptr = Ptr{UInt8}(ai.ai_addr + 8)

            # Convert to string
            buf = Memory{UInt8}(undef, 46)
            ret = GC.@preserve buf begin
                ccall(
                    :inet_ntop, Ptr{UInt8},
                    (Cint, Ptr{UInt8}, Ptr{UInt8}, Cuint),
                    AF_INET6, addr_ptr, pointer(buf), Cuint(46)
                )
            end
            if ret != C_NULL
                push!(addresses, unsafe_string(pointer(buf)))
            end
        end

        current = ai.ai_next
    end

    # Free the results
    if result_ptr[] != C_NULL
        ccall(:freeaddrinfo, Cvoid, (Ptr{addrinfo},), result_ptr[])
    end

    return addresses
end
