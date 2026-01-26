# AWS IO Library - Host Resolver
# Port of aws-c-io/source/host_resolver.c

# Address type for resolved hosts
@enumx HostAddressType::UInt8 begin
    A = 0     # IPv4
    AAAA = 1  # IPv6
end

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
    pending_a::Bool  # A (IPv4) resolution pending
    pending_aaaa::Bool  # AAAA (IPv6) resolution pending
    last_resolve_request_time::UInt64
    resolved_time::UInt64
    # Linked list of waiting requests
    pending_requests::Union{HostResolverResolutionRequest, Nothing}  # nullable
end

function HostEntry(host_name::AbstractString)
    return HostEntry(
        String(host_name),
        Vector{HostAddress}(),
        Vector{HostAddress}(),
        false,
        false,
        UInt64(0),
        UInt64(0),
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

function HostResolverConfig(;
        max_entries::Integer = 1024,
        max_ttl_secs::Integer = 300,  # 5 minutes default
        min_ttl_secs::Integer = 10,
        max_addresses_per_host::Integer = 8,
        resolve_frequency_ns::Integer = 5_000_000_000,  # 5 seconds
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

# Default TTL in nanoseconds (5 minutes)
const HOST_RESOLVER_DEFAULT_TTL_NS = UInt64(300_000_000_000)

# Abstract resolver interface
abstract type AbstractHostResolver end

# Default host resolver with caching
mutable struct DefaultHostResolver{ELG} <: AbstractHostResolver
    event_loop_group::ELG
    config::HostResolverConfig
    cache::Dict{String, HostEntry}
    lock::ReentrantLock
    @atomic shutdown::Bool
    ref_count::RefCounted{DefaultHostResolver{ELG}, Function}
end

function _resolver_on_zero_ref(resolver::DefaultHostResolver)
    logf(LogLevel.TRACE, LS_IO_DNS, "Host resolver: ref count zero, cleaning up")
    empty!(resolver.cache)
    return nothing
end

function DefaultHostResolver(
        event_loop_group::ELG,
        config::HostResolverConfig = HostResolverConfig(),
    ) where {ELG}
    resolver = DefaultHostResolver{ELG}(
        event_loop_group,
        config,
        Dict{String, HostEntry}(),
        ReentrantLock(),
        false,
        RefCounted{DefaultHostResolver{ELG}, Function}(1, nothing, _resolver_on_zero_ref),  # placeholder
    )
    resolver.ref_count = RefCounted(resolver, _resolver_on_zero_ref)
    return resolver
end

# Acquire reference to resolver
function host_resolver_acquire!(resolver::DefaultHostResolver)
    acquire!(resolver.ref_count)
    return resolver
end

# Release reference to resolver
function host_resolver_release!(resolver::DefaultHostResolver)
    release!(resolver.ref_count)
    return nothing
end

# Resolve a hostname to addresses
function host_resolver_resolve!(
        resolver::DefaultHostResolver,
        host_name::AbstractString,
        on_resolved::OnHostResolvedFn,
        user_data = nothing;
        address_type::HostAddressType.T = HostAddressType.A,
    )::Union{Nothing, ErrorResult}
    if @atomic resolver.shutdown
        logf(LogLevel.ERROR, LS_IO_DNS, "Host resolver: resolve called after shutdown")
        raise_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
        return ErrorResult(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end

    host = String(host_name)

    logf(LogLevel.DEBUG, LS_IO_DNS, "Host resolver: resolving host '$host'")

    # Check cache first
    lock(resolver.lock) do
        entry = get(resolver.cache, host, nothing)

        if entry !== nothing
            # Check if we have valid cached addresses
            addresses = address_type == HostAddressType.A ? entry.addresses_a : entry.addresses_aaaa
            current_time = high_res_clock()

            # Filter to non-expired addresses
            valid_addresses = filter(a -> a.expiry > current_time, addresses)

            if !isempty(valid_addresses)
                logf(
                    LogLevel.TRACE, LS_IO_DNS,
                    "Host resolver: cache hit for '$host', $(length(valid_addresses)) addresses"
                )

                # Update use counts
                for addr in valid_addresses
                    addr.use_count += 1
                end

                # Schedule callback
                event_loop = event_loop_group_get_next_loop(resolver.event_loop_group)
                if event_loop !== nothing
                    task = ScheduledTask(
                        (t, status) -> on_resolved(resolver, host, AWS_OP_SUCCESS, copy.(valid_addresses)),
                        nothing;
                        type_tag = "dns_resolve_cached"
                    )
                    event_loop_schedule_task_now!(event_loop, task)
                else
                    # No event loop, call directly
                    on_resolved(resolver, host, AWS_OP_SUCCESS, copy.(valid_addresses))
                end

                return nothing
            end
        end
    end

    # Need to resolve - perform getaddrinfo
    _perform_dns_resolution(resolver, host, address_type, on_resolved, user_data)

    return nothing
end

# Perform actual DNS resolution using getaddrinfo
function _perform_dns_resolution(
        resolver::DefaultHostResolver,
        host::String,
        address_type::HostAddressType.T,
        on_resolved::OnHostResolvedFn,
        user_data,
    )
    logf(LogLevel.TRACE, LS_IO_DNS, "Host resolver: performing DNS lookup for '$host'")

    # Get an event loop to schedule the async work
    event_loop = event_loop_group_get_next_loop(resolver.event_loop_group)

    # Schedule DNS resolution as a task
    # In a real implementation, this would be done in a thread pool to avoid blocking
    task = ScheduledTask(
        (t, status) -> _dns_resolution_task(resolver, host, address_type, on_resolved, user_data),
        nothing;
        type_tag = "dns_resolution"
    )

    if event_loop !== nothing
        event_loop_schedule_task_now!(event_loop, task)
    else
        # No event loop, execute directly
        _dns_resolution_task(resolver, host, address_type, on_resolved, user_data)
    end

    return nothing
end

# DNS resolution task - called on event loop
function _dns_resolution_task(
        resolver::DefaultHostResolver,
        host::String,
        address_type::HostAddressType.T,
        on_resolved::OnHostResolvedFn,
        user_data,
    )
    logf(LogLevel.TRACE, LS_IO_DNS, "Host resolver: DNS task executing for '$host'")

    addresses = Vector{HostAddress}()
    error_code = AWS_OP_SUCCESS

    try
        # Use native getaddrinfo
        family = address_type == HostAddressType.A ? AF_INET : AF_INET6
        addrs = _native_getaddrinfo(host, family)

        current_time = high_res_clock()
        ttl_nanos = current_time + HOST_RESOLVER_DEFAULT_TTL_NS

        if !isempty(addrs)
            for addr_str in addrs
                push!(addresses, HostAddress(addr_str, address_type, host, ttl_nanos))
            end

            logf(
                LogLevel.DEBUG, LS_IO_DNS,
                "Host resolver: resolved '$host' to $(length(addresses)) addresses"
            )

            # Update cache
            _update_cache!(resolver, host, addresses, address_type)
        else
            logf(LogLevel.DEBUG, LS_IO_DNS, "Host resolver: no addresses found for '$host'")
            error_code = ERROR_IO_DNS_NO_ADDRESS_FOR_HOST
        end

    catch e
        logf(LogLevel.ERROR, LS_IO_DNS, "Host resolver: DNS resolution failed for '$host': $e")
        error_code = ERROR_IO_DNS_QUERY_FAILED
    end

    # Invoke callback
    on_resolved(resolver, host, error_code, addresses)

    return nothing
end

# Update the cache with resolved addresses
function _update_cache!(resolver::DefaultHostResolver, host::String, addresses::Vector{HostAddress}, address_type::HostAddressType.T)
    lock(resolver.lock) do
        entry = get!(resolver.cache, host) do
            HostEntry(host)
        end

        if address_type == HostAddressType.A
            entry.addresses_a = addresses
            entry.pending_a = false
        else
            entry.addresses_aaaa = addresses
            entry.pending_aaaa = false
        end

        entry.resolved_time = high_res_clock()

        # Trim cache if too large
        if length(resolver.cache) > resolver.config.max_entries
            _trim_cache!(resolver)
        end
    end

    return nothing
end

# Trim cache by removing oldest entries
function _trim_cache!(resolver::DefaultHostResolver)
    # Simple LRU eviction - remove entries that haven't been used recently
    entries_to_remove = String[]
    current_time = high_res_clock()

    for (host, entry) in resolver.cache
        # Check if all addresses are expired
        all_expired_a = all(a -> a.expiry < current_time, entry.addresses_a)
        all_expired_aaaa = all(a -> a.expiry < current_time, entry.addresses_aaaa)

        if (isempty(entry.addresses_a) || all_expired_a) &&
                (isempty(entry.addresses_aaaa) || all_expired_aaaa)
            push!(entries_to_remove, host)
        end
    end

    for host in entries_to_remove
        delete!(resolver.cache, host)
        if length(resolver.cache) <= resolver.config.max_entries
            break
        end
    end

    return nothing
end

# Purge the entire cache
function host_resolver_purge_cache!(resolver::DefaultHostResolver)
    lock(resolver.lock) do
        empty!(resolver.cache)
    end
    logf(LogLevel.DEBUG, LS_IO_DNS, "Host resolver: cache purged")
    return nothing
end

# Get a single best address for a host (simplified version)
function host_resolver_get_address!(
        resolver::DefaultHostResolver,
        host_name::AbstractString;
        address_type::HostAddressType.T = HostAddressType.A,
    )::Union{HostAddress, Nothing}
    host = String(host_name)

    return lock(resolver.lock) do
        entry = get(resolver.cache, host, nothing)

        if entry === nothing
            return nothing
        end

        addresses = address_type == HostAddressType.A ? entry.addresses_a : entry.addresses_aaaa
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
        entry = get(resolver.cache, address.host, nothing)
        if entry === nothing
            return nothing
        end

        addresses = address.address_type == HostAddressType.A ? entry.addresses_a : entry.addresses_aaaa

        for addr in addresses
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
            buf = Vector{UInt8}(undef, 16)
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
            buf = Vector{UInt8}(undef, 46)
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
