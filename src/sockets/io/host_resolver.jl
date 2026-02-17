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

function HostAddress(address::AbstractString, address_type::HostAddressType.T, host::AbstractString, ttl_nanos::Integer)
    return HostAddress(address, address_type, host, UInt64(ttl_nanos))
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

@enumx DefaultResolverState::UInt8 begin
    ACTIVE = 0
    SHUTTING_DOWN = 1
end

struct HostResolverConfig
    max_entries::UInt64
    max_ttl_secs::UInt64
    min_ttl_secs::UInt64
    max_addresses_per_host::UInt64
    resolve_frequency_ns::UInt64  # How often to re-resolve
    background_refresh::Bool  # retained for compatibility
    clock_override::Union{ClockSource, Nothing}
end

struct HostResolutionConfig
    max_ttl_secs::UInt64
    resolve_frequency_ns::UInt64
    resolution_delay_ns::UInt64
    first_address_family_count::UInt64
    connection_attempt_delay_ns::UInt64
    min_connection_attempt_delay_ns::UInt64
    resolve_host_as_address::Bool
end

function HostResolutionConfig(;
        max_ttl_secs::Integer = 0,
        resolve_frequency_ns::Integer = 0,
        resolution_delay_ns::Integer = HOST_RESOLVER_HAPPY_EYEBALLS_RESOLUTION_DELAY_NS,
        first_address_family_count::Integer = Int(HOST_RESOLVER_HAPPY_EYEBALLS_FIRST_ADDRESS_FAMILY_COUNT),
        connection_attempt_delay_ns::Integer = HOST_RESOLVER_HAPPY_EYEBALLS_CONNECTION_ATTEMPT_DELAY_NS,
        min_connection_attempt_delay_ns::Integer = HOST_RESOLVER_HAPPY_EYEBALLS_MIN_CONNECTION_ATTEMPT_DELAY_NS,
        resolve_host_as_address::Bool = false,
    )
    return HostResolutionConfig(
        UInt64(max_ttl_secs),
        UInt64(resolve_frequency_ns),
        UInt64(resolution_delay_ns),
        UInt64(first_address_family_count),
        UInt64(connection_attempt_delay_ns),
        UInt64(min_connection_attempt_delay_ns),
        resolve_host_as_address,
    )
end

function HostResolverConfig(;
        max_entries::Integer = 1024,
        max_ttl_secs::Integer = 30,  # 30 seconds default
        min_ttl_secs::Integer = 1,
        max_addresses_per_host::Integer = 8,
        resolve_frequency_ns::Integer = 1_000_000_000,  # 1 second
        background_refresh::Bool = true,
        clock_override::Union{ClockSource, Nothing} = nothing,
    )
    return HostResolverConfig(
        UInt64(max_entries),
        UInt64(max_ttl_secs),
        UInt64(min_ttl_secs),
        UInt64(max_addresses_per_host),
        UInt64(resolve_frequency_ns),
        background_refresh,
        clock_override,
    )
end

const HOST_RESOLVER_DEFAULT_RESOLVE_FREQUENCY_NS = UInt64(1_000_000_000)
const HOST_RESOLVER_MIN_WAIT_BETWEEN_RESOLVE_NS = UInt64(100_000_000) # 100ms
const HOST_RESOLVER_HAPPY_EYEBALLS_RESOLUTION_DELAY_NS = UInt64(50_000_000) # 50ms
const HOST_RESOLVER_HAPPY_EYEBALLS_FIRST_ADDRESS_FAMILY_COUNT = UInt64(1)
const HOST_RESOLVER_HAPPY_EYEBALLS_CONNECTION_ATTEMPT_DELAY_NS = UInt64(250_000_000) # 250ms
const HOST_RESOLVER_HAPPY_EYEBALLS_MIN_CONNECTION_ATTEMPT_DELAY_NS = UInt64(100_000_000) # 100ms
const HOST_RESOLVER_HAPPY_EYEBALLS_MIN_CONNECTION_ATTEMPT_DELAY_FLOOR_NS = UInt64(10_000_000) # 10ms

@inline function _normalize_first_address_family_count(count::UInt64)::UInt64
    return count == 0 ? HOST_RESOLVER_HAPPY_EYEBALLS_FIRST_ADDRESS_FAMILY_COUNT : count
end

@inline function _normalize_connection_attempt_min_delay(min_delay::UInt64)::UInt64
    return max(min_delay, HOST_RESOLVER_HAPPY_EYEBALLS_MIN_CONNECTION_ATTEMPT_DELAY_FLOOR_NS)
end

@inline function _normalize_connection_attempt_delay(
    delay_ns::UInt64,
    min_delay_ns::UInt64,
)::UInt64
    return max(delay_ns, min_delay_ns)
end

mutable struct HostEntry{T}
    resolver::T
    host_name::String
    resolution_config::HostResolutionConfig
    resolve_frequency_ns::UInt64
    entry_lock::ReentrantLock
    entry_signal::ConditionVariable
    a_records::LRUCache{String, HostAddress}
    aaaa_records::LRUCache{String, HostAddress}
    failed_a_records::LRUCache{String, HostAddress}
    failed_aaaa_records::LRUCache{String, HostAddress}
    pending_resolve_futures::Vector{Future{Vector{HostAddress}}}
    last_resolve_request_time::UInt64
    resolves_since_last_request::UInt32
    @atomic state::DefaultResolverState.T
    new_addresses::Vector{HostAddress}
    expired_addresses::Vector{HostAddress}
    on_host_purge_complete::Union{TaskFn, Nothing}  # late-init: nothing → TaskFn
    resolver_thread::Union{ForeignThread, Nothing}
end

# Host resolver with caching
mutable struct HostResolver
    event_loop_group::EventLoopGroup
    config::HostResolverConfig
    cache::Dict{String, HostEntry{HostResolver}}
    resolver_lock::ReentrantLock
    @atomic shutdown::Bool
end

@inline function _resolver_clock(resolver::HostResolver)::UInt64
    override_clock = resolver.config.clock_override
    return override_clock === nothing ? clock_now_ns() : clock_now_ns(override_clock)
end

function HostResolver(
        event_loop_group::EventLoopGroup,
        config::HostResolverConfig = HostResolverConfig(),
    )
    cache = Dict{String, HostEntry{HostResolver}}()
    sizehint!(cache, Int(config.max_entries))
    resolver = HostResolver(
        event_loop_group,
        config,
        cache,
        ReentrantLock(),
        false,
    )
    return resolver
end

const _DEFAULT_HOST_RESOLVER_LOCK = ReentrantLock()
const _DEFAULT_HOST_RESOLVER = Ref{Union{HostResolver, Nothing}}(nothing)

"""
    default_host_resolver() -> HostResolver

Return a process-wide default `HostResolver`, bound to
`EventLoops.get_event_loop_group()`.
"""
function default_host_resolver()::HostResolver
    lock(_DEFAULT_HOST_RESOLVER_LOCK)
    try
        resolver = _DEFAULT_HOST_RESOLVER[]
        if resolver === nothing
            resolver = HostResolver(EventLoops.get_event_loop_group())
            _DEFAULT_HOST_RESOLVER[] = resolver
        end
        return resolver::HostResolver
    finally
        unlock(_DEFAULT_HOST_RESOLVER_LOCK)
    end
end

"""Type alias for HostResolver.cache; values are always `HostEntry{HostResolver}`."""
const HostResolverCache = Dict{String, HostEntry{HostResolver}}

function _entry_cache_capacity(resolver::HostResolver, config::HostResolutionConfig)
    ttl = config.max_ttl_secs != 0 ? config.max_ttl_secs : resolver.config.max_ttl_secs
    return max(Int(ttl), 1)
end

function HostEntry(
        resolver::HostResolver,
        host_name::AbstractString,
        config::Union{HostResolutionConfig, Nothing},
        timestamp::UInt64,
    )
    normalized = _normalize_resolution_config(resolver, config)
    capacity = _entry_cache_capacity(resolver, normalized)
    a_records = LRUCache{String, HostAddress}(capacity)
    aaaa_records = LRUCache{String, HostAddress}(capacity)
    failed_a_records = LRUCache{String, HostAddress}(capacity)
    failed_aaaa_records = LRUCache{String, HostAddress}(capacity)
    return HostEntry(
        resolver,
        String(host_name),
        normalized,
        normalized.resolve_frequency_ns == 0 ? HOST_RESOLVER_DEFAULT_RESOLVE_FREQUENCY_NS : normalized.resolve_frequency_ns,
        ReentrantLock(),
        ConditionVariable(),
        a_records,
        aaaa_records,
        failed_a_records,
        failed_aaaa_records,
        Future{Vector{HostAddress}}[],
        timestamp,
        UInt32(0),
        DefaultResolverState.ACTIVE,
        HostAddress[],
        HostAddress[],
        nothing,
        nothing,
    )
end

function _normalize_resolution_config(
        resolver::HostResolver,
        config::Union{HostResolutionConfig, Nothing},
    )
    base_max_ttl = resolver.config.max_ttl_secs
    base_resolve_freq = resolver.config.resolve_frequency_ns == 0 ?
        HOST_RESOLVER_DEFAULT_RESOLVE_FREQUENCY_NS :
        resolver.config.resolve_frequency_ns

    if config === nothing
        return HostResolutionConfig(
            base_max_ttl,
            base_resolve_freq,
            HOST_RESOLVER_HAPPY_EYEBALLS_RESOLUTION_DELAY_NS,
            HOST_RESOLVER_HAPPY_EYEBALLS_FIRST_ADDRESS_FAMILY_COUNT,
            HOST_RESOLVER_HAPPY_EYEBALLS_CONNECTION_ATTEMPT_DELAY_NS,
            HOST_RESOLVER_HAPPY_EYEBALLS_MIN_CONNECTION_ATTEMPT_DELAY_NS,
            false,
        )
    end

    max_ttl = config.max_ttl_secs != 0 ? config.max_ttl_secs : base_max_ttl
    resolve_freq = config.resolve_frequency_ns != 0 ? config.resolve_frequency_ns : base_resolve_freq

    resolution_delay_ns = config.resolution_delay_ns == 0 ?
        HOST_RESOLVER_HAPPY_EYEBALLS_RESOLUTION_DELAY_NS : config.resolution_delay_ns
    first_address_family_count = _normalize_first_address_family_count(config.first_address_family_count)
    min_connection_attempt_delay_ns = _normalize_connection_attempt_min_delay(
        config.min_connection_attempt_delay_ns == 0 ?
        HOST_RESOLVER_HAPPY_EYEBALLS_MIN_CONNECTION_ATTEMPT_DELAY_NS :
        config.min_connection_attempt_delay_ns,
    )
    connection_attempt_delay_ns = _normalize_connection_attempt_delay(
        config.connection_attempt_delay_ns == 0 ?
        HOST_RESOLVER_HAPPY_EYEBALLS_CONNECTION_ATTEMPT_DELAY_NS :
        config.connection_attempt_delay_ns,
        min_connection_attempt_delay_ns,
    )

    return HostResolutionConfig(
        max_ttl,
        resolve_freq,
        resolution_delay_ns,
        first_address_family_count,
        connection_attempt_delay_ns,
        min_connection_attempt_delay_ns,
        config.resolve_host_as_address,
    )
end

function _dispatch_simple_callback(
        resolver::HostResolver,
        callback::Union{TaskFn, Nothing},
    )
    callback === nothing && return nothing
    event_loop = get_next_event_loop(resolver.event_loop_group)
    if event_loop !== nothing
        schedule_task_now!(callback, event_loop; type_tag = "dns_purge_callback")
    else
        callback(UInt8(0))
    end
    return nothing
end

function _cache_find(cache::LRUCache{String, HostAddress}, key::String)
    return get(cache.data, key, nothing)
end

function _cache_remove_good!(entry::HostEntry, cache::LRUCache{String, HostAddress}, key::String)
    addr = _cache_find(cache, key)
    addr === nothing && return false
    push!(entry.expired_addresses, copy(addr))
    remove!(cache, key)
    return true
end

function _cache_remove_failed!(cache::LRUCache{String, HostAddress}, key::String)
    remove!(cache, key)
    return nothing
end

function _update_address_cache!(
        entry::HostEntry,
        addresses::Vector{HostAddress},
        new_expiry::UInt64,
    )
    for addr in addresses
        addr.host = entry.host_name
        if addr.address_type == HostAddressType.A
            primary = entry.a_records
            fallback = entry.failed_a_records
        else
            primary = entry.aaaa_records
            fallback = entry.failed_aaaa_records
        end

        existing = _cache_find(primary, addr.address)
        if existing !== nothing
            existing.expiry = new_expiry
            continue
        end

        failed = _cache_find(fallback, addr.address)
        if failed !== nothing
            continue
        end

        addr_copy = copy(addr)
        addr_copy.expiry = new_expiry
        _PARENT.put!(primary, addr_copy.address, addr_copy)
        push!(entry.new_addresses, copy(addr_copy))
    end
    return nothing
end

function _process_records!(
        entry::HostEntry,
        records::LRUCache{String, HostAddress},
        failed_records::LRUCache{String, HostAddress},
        timestamp::UInt64,
    )
    record_count = cache_count(records)
    expired_records = 0

    for _ in 1:record_count
        if expired_records >= record_count - 1
            break
        end
        addr = use_lru!(records)
        addr === nothing && break
        if addr.expiry < timestamp
            _cache_remove_good!(entry, records, addr.address)
            expired_records += 1
        end
    end

    should_promote = cache_count(records) == 0
    failed_count = cache_count(failed_records)
    for _ in 1:failed_count
        addr = use_lru!(failed_records)
        addr === nothing && break
        if timestamp >= addr.expiry
            _cache_remove_failed!(failed_records, addr.address)
        elseif should_promote
            addr_copy = copy(addr)
            _PARENT.put!(records, addr_copy.address, addr_copy)
            push!(entry.new_addresses, copy(addr_copy))
            _cache_remove_failed!(failed_records, addr.address)
            should_promote = false
        end
    end
    return nothing
end

function _collect_family_records(cache::LRUCache{String, HostAddress})
    addrs = HostAddress[]
    count = cache_count(cache)
    for _ in 1:count
        addr = use_lru!(cache)
        addr === nothing && break
        push!(addrs, copy(addr))
    end
    return addrs
end

function _interleave_family_addresses(
        primary_family::HostAddressType.T,
        primary_family_count::Int,
        aaaa_records::Vector{HostAddress},
        a_records::Vector{HostAddress},
    )
    primary_count = max(primary_family_count, 1)

    primary = primary_family == HostAddressType.AAAA ? aaaa_records : a_records
    secondary = primary_family == HostAddressType.AAAA ? a_records : aaaa_records
    primary_len = length(primary)
    secondary_len = length(secondary)

    addresses = HostAddress[]
    sizehint!(addresses, primary_len + secondary_len)

    if primary_len == 0
        append!(addresses, secondary)
        return addresses
    end
    if secondary_len == 0
        append!(addresses, primary)
        return addresses
    end

    primary_idx = 1
    secondary_idx = 1
    while primary_idx <= primary_len || secondary_idx <= secondary_len
        for _ in 1:primary_count
            primary_idx <= primary_len || continue
            push!(addresses, primary[primary_idx])
            primary_idx += 1
        end
        if secondary_idx <= secondary_len
            push!(addresses, secondary[secondary_idx])
            secondary_idx += 1
        end
    end
    return addresses
end

function _collect_callback_addresses(entry::HostEntry)
    aaaa_records = _collect_family_records(entry.aaaa_records)
    a_records = _collect_family_records(entry.a_records)
    isempty(aaaa_records) && return a_records
    isempty(a_records) && return aaaa_records

    return _interleave_family_addresses(
        HostAddressType.AAAA,
        Int(entry.resolution_config.first_address_family_count),
        aaaa_records,
        a_records,
    )
end

function _host_entry_finished_pred(entry::HostEntry)
    return (@atomic entry.state) == DefaultResolverState.SHUTTING_DOWN
end

function _host_entry_finished_or_pending_pred(entry::HostEntry)
    return ((@atomic entry.state) == DefaultResolverState.SHUTTING_DOWN) || !isempty(entry.pending_resolve_futures)
end

@inline function _is_ipv4_literal(host::AbstractString)::Bool
    parts = split(host, '.')
    length(parts) == 4 || return false
    for part in parts
        isempty(part) && return false
        all(c -> '0' <= c <= '9', part) || return false
        val = tryparse(Int, part)
        val === nothing && return false
        0 <= val <= 255 || return false
    end
    return true
end

function _default_dns_resolve(host::String, max_addresses::Int)

    # Fast path: for numeric IP literals, skip getaddrinfo() entirely.
    if _is_ipv4_literal(host)
        return [HostAddress(host, HostAddressType.A, host, UInt64(0))], OP_SUCCESS
    end

    # Preserve `getaddrinfo()` result ordering (aws-c-io parity).
    error_code = OP_SUCCESS
    flags = @static Sys.isopenbsd() ? Cint(0) : (AI_ALL | AI_V4MAPPED)
    raw_addresses = _native_getaddrinfo(host; flags = flags)
    addresses = HostAddress[]
    for (addr, family) in raw_addresses
        if family == _HR_AF_INET6
            push!(addresses, HostAddress(addr, HostAddressType.AAAA, host, UInt64(0)))
        elseif family == _HR_AF_INET
            push!(addresses, HostAddress(addr, HostAddressType.A, host, UInt64(0)))
        end
        if max_addresses > 0 && length(addresses) >= max_addresses
            break
        end
    end

    if isempty(addresses)
        error_code = ERROR_IO_DNS_NO_ADDRESS_FOR_HOST
    end

    return addresses, error_code
end

function _resolve_addresses(entry::HostEntry)::Tuple{Vector{HostAddress}, Int}
    host_name = entry.host_name
    if entry.resolution_config.resolve_host_as_address
        return [HostAddress(host_name, HostAddressType.A, host_name, UInt64(0))], OP_SUCCESS
    end

    addresses::Vector{HostAddress} = HostAddress[]
    error_code::Int = ERROR_IO_DNS_QUERY_FAILED

    try
        max_addresses = Int(entry.resolver.config.max_addresses_per_host)
        resolved, err = _default_dns_resolve(host_name, max_addresses)
        addresses = resolved
        error_code = Int(err)
    catch
        logf(LogLevel.ERROR, LS_IO_DNS, "Host resolver: resolve failed for '$host_name'")
        return HostAddress[], ERROR_IO_DNS_QUERY_FAILED
    end

    error_code == OP_SUCCESS || return HostAddress[], error_code

    normalized = HostAddress[]
    sizehint!(normalized, length(addresses))
    for addr in addresses
        addr_copy = copy(addr)
        addr_copy.host = host_name
        push!(normalized, addr_copy)
    end

    return normalized, OP_SUCCESS
end

@wrap_thread_fn function _resolver_thread_entry(entry::HostEntry{HostResolver})
    try
        _host_resolver_thread(entry)
    catch e
        Core.println("host resolver thread errored")
    finally
        managed_thread_finished!()
    end
end

const _RESOLVER_THREAD_ENTRY_C = Ref{Ptr{Cvoid}}(C_NULL)
const _RESOLVER_THREAD_ENTRY_LOCK = ReentrantLock()

function _host_resolver_init_cfunctions!()
    _RESOLVER_THREAD_ENTRY_C[] = @cfunction(_resolver_thread_entry, Ptr{Cvoid}, (Ptr{Cvoid},))
    return nothing
end

function _host_resolver_ensure_thread_entry!()::Nothing
    _RESOLVER_THREAD_ENTRY_C[] != C_NULL && return nothing
    lock(_RESOLVER_THREAD_ENTRY_LOCK)
    try
        _RESOLVER_THREAD_ENTRY_C[] == C_NULL && _host_resolver_init_cfunctions!()
    finally
        unlock(_RESOLVER_THREAD_ENTRY_LOCK)
    end
    return nothing
end

function _host_resolver_thread(entry::HostEntry)
    try
        max_no_solicitation_interval = max(UInt64(1), entry.resolution_config.max_ttl_secs) * UInt64(1_000_000_000)
        wait_between_resolves = min(max_no_solicitation_interval, entry.resolve_frequency_ns)
        shutdown_only_wait_time = HOST_RESOLVER_MIN_WAIT_BETWEEN_RESOLVE_NS
        request_interruptible_wait_time = wait_between_resolves > shutdown_only_wait_time ?
            wait_between_resolves - shutdown_only_wait_time :
            UInt64(0)

        while (@atomic entry.state) == DefaultResolverState.ACTIVE
            keep_going = true
            addresses, err_code = _resolve_addresses(entry)
            timestamp = _resolver_clock(entry.resolver)
            new_expiry = timestamp + entry.resolution_config.max_ttl_secs * UInt64(1_000_000_000)

            pending = Future{Vector{HostAddress}}[]
            lock(entry.entry_lock)
            try
                if err_code == OP_SUCCESS
                    _update_address_cache!(entry, addresses, new_expiry)
                end
                _process_records!(entry, entry.aaaa_records, entry.failed_aaaa_records, timestamp)
                _process_records!(entry, entry.a_records, entry.failed_a_records, timestamp)

                pending = entry.pending_resolve_futures
                entry.pending_resolve_futures = Future{Vector{HostAddress}}[]
            finally
                unlock(entry.entry_lock)
            end

            while !isempty(pending)
                pending_future = popfirst!(pending)
                callback_addresses = HostAddress[]
                lock(entry.entry_lock)
                try
                    callback_addresses = _collect_callback_addresses(entry)
                finally
                    unlock(entry.entry_lock)
                end

                error_code = if isempty(callback_addresses)
                    err_code == OP_SUCCESS ? ERROR_IO_DNS_NO_ADDRESS_FOR_HOST : err_code
                else
                    OP_SUCCESS
                end
                addrs = isempty(callback_addresses) ? HostAddress[] : callback_addresses
                if error_code == OP_SUCCESS
                    if isempty(addrs)
                        notify(
                            pending_future,
                            DNSError(entry.host_name, Int32(ERROR_IO_DNS_NO_ADDRESS_FOR_HOST)),
                        )
                    else
                        notify(pending_future, addrs)
                    end
                else
                    notify(pending_future, DNSError(entry.host_name, Int32(error_code)))
                end
            end

            empty!(entry.new_addresses)
            empty!(entry.expired_addresses)

            lock(entry.entry_lock)
            try
                entry.resolves_since_last_request += 1

                condition_variable_wait_for_pred(
                    entry.entry_signal,
                    entry.entry_lock,
                    shutdown_only_wait_time,
                    _host_entry_finished_pred,
                    entry,
                )

                if request_interruptible_wait_time > 0
                    condition_variable_wait_for_pred(
                        entry.entry_signal,
                        entry.entry_lock,
                        request_interruptible_wait_time,
                        _host_entry_finished_or_pending_pred,
                        entry,
                    )
                end
            finally
                unlock(entry.entry_lock)
            end

            resolver = entry.resolver
            lock(resolver.resolver_lock)
            try
                lock(entry.entry_lock)
                try
                    now = clock_now_ns()
                    if resolver.shutdown || (
                            isempty(entry.pending_resolve_futures) &&
                            entry.last_resolve_request_time + max_no_solicitation_interval < now
                        )
                        @atomic entry.state = DefaultResolverState.SHUTTING_DOWN
                        delete!(resolver.cache, entry.host_name)
                    end

                    keep_going = (@atomic entry.state) == DefaultResolverState.ACTIVE
                finally
                    unlock(entry.entry_lock)
                end
            finally
                unlock(resolver.resolver_lock)
            end

            keep_going || break
        end

        if entry.on_host_purge_complete !== nothing
            entry.on_host_purge_complete(UInt8(0))
        end
    catch err
        _ = err
        logf(LogLevel.ERROR, LS_IO_DNS, "Host resolver: thread failed for '$(entry.host_name)'")
    end

    return nothing
end

function _host_entry_shutdown!(entry::HostEntry)
    pending = Future{Vector{HostAddress}}[]
    lock(entry.entry_lock)
    pending = entry.pending_resolve_futures
    entry.pending_resolve_futures = Future{Vector{HostAddress}}[]
    @atomic entry.state = DefaultResolverState.SHUTTING_DOWN
    condition_variable_notify_all(entry.entry_signal)
    unlock(entry.entry_lock)
    for resolve_future in pending
        notify(resolve_future, DNSError(entry.host_name, Int32(ERROR_IO_EVENT_LOOP_SHUTDOWN)))
    end
    return nothing
end

# Resolve a hostname to addresses.
# Returns a future that will be completed with either:
# - Vector{HostAddress} on success
# - Exception (typically DNSError/ReseauError) on failure
function host_resolver_resolve!(
        resolver::HostResolver,
        host_name::AbstractString,
        resolution_config::Union{HostResolutionConfig, Nothing} = nothing,
)::Future{Vector{HostAddress}}
    result = Future{Vector{HostAddress}}()
    if @atomic resolver.shutdown
        logf(LogLevel.ERROR, LS_IO_DNS, "Host resolver: resolve called after shutdown")
        notify(result, DNSError(String(host_name), Int32(ERROR_IO_EVENT_LOOP_SHUTDOWN)))
        return result
    end

    host = String(host_name)
    timestamp = clock_now_ns()
    normalized_config = _normalize_resolution_config(resolver, resolution_config)

    lock(resolver.resolver_lock)
    try
        entry_any = get(() -> nothing, resolver.cache, host)
        if entry_any === nothing
            _host_resolver_ensure_thread_entry!()
            new_entry = HostEntry(resolver, host, normalized_config, timestamp)
            push!(new_entry.pending_resolve_futures, result)
            resolver.cache[host] = new_entry
            try
                new_entry.resolver_thread = ForeignThread(
                    "ReseauHostResolver",
                    _RESOLVER_THREAD_ENTRY_C,
                    new_entry,
                )
            catch e
                delete!(resolver.cache, host)
                notify(result, e isa Exception ? e : ReseauError(ERROR_UNKNOWN))
            end
            return result
        end

        entry = entry_any::HostEntry
        lock(entry.entry_lock)
        try
            entry.last_resolve_request_time = timestamp
            entry.resolves_since_last_request = 0
            cached_addresses = _collect_callback_addresses(entry)

            if !isempty(cached_addresses)
                notify(result, cached_addresses)
                return result
            end

            push!(entry.pending_resolve_futures, result)
            condition_variable_notify_all(entry.entry_signal)
            return result
        finally
            unlock(entry.entry_lock)
        end
    finally
        unlock(resolver.resolver_lock)
    end
end

# Purge the entire cache
function host_resolver_purge_cache!(resolver::HostResolver)
    lock(resolver.resolver_lock)
    for (_, entry_any) in resolver.cache
        entry = entry_any::HostEntry
        _host_entry_shutdown!(entry)
    end
    empty!(resolver.cache)
    unlock(resolver.resolver_lock)

    logf(LogLevel.DEBUG, LS_IO_DNS, "Host resolver: cache purged")
    return nothing
end

function host_resolver_purge_cache_with_callback!(
        resolver::HostResolver,
        on_purge_cache_complete::Union{TaskFn, Nothing} = nothing,
    )::Nothing
    host_resolver_purge_cache!(resolver)
    _dispatch_simple_callback(resolver, on_purge_cache_complete)
    return nothing
end

function host_resolver_purge_host_cache!(
        resolver::HostResolver,
        host_name::AbstractString;
        on_host_purge_complete::Union{TaskFn, Nothing} = nothing,
    )::Nothing
    host = String(host_name)

    lock(resolver.resolver_lock)
    entry_any = get(resolver.cache, host, nothing)
    if entry_any === nothing
        unlock(resolver.resolver_lock)
        _dispatch_simple_callback(resolver, on_host_purge_complete)
        return nothing
    end
    entry = entry_any::HostEntry

    lock(entry.entry_lock)
    entry.on_host_purge_complete = on_host_purge_complete
    unlock(entry.entry_lock)

    delete!(resolver.cache, host)
    unlock(resolver.resolver_lock)

    _host_entry_shutdown!(entry)

    return nothing
end

function host_resolver_get_host_address_count(
        resolver::HostResolver,
        host_name::AbstractString;
        flags::UInt32 = GET_HOST_ADDRESS_COUNT_ALL,
    )::Csize_t
    host = String(host_name)
    count = 0

    lock(resolver.resolver_lock)
    entry_any = get(resolver.cache, host, nothing)
    if entry_any !== nothing
        entry = entry_any::HostEntry
        lock(entry.entry_lock)
        if (flags & GET_HOST_ADDRESS_COUNT_RECORD_TYPE_A) != 0
            count += cache_count(entry.a_records)
        end
        if (flags & GET_HOST_ADDRESS_COUNT_RECORD_TYPE_AAAA) != 0
            count += cache_count(entry.aaaa_records)
        end
        unlock(entry.entry_lock)
    end
    unlock(resolver.resolver_lock)

    return Csize_t(count)
end

# Get a single best address for a host (simplified version)
function host_resolver_get_address!(
        resolver::HostResolver,
        host_name::AbstractString;
        address_type::HostAddressType.T = HostAddressType.A,
    )::Union{HostAddress, Nothing}
    host = String(host_name)

    lock(resolver.resolver_lock)
    entry_any = get(resolver.cache, host, nothing)
    if entry_any === nothing
        unlock(resolver.resolver_lock)
        return nothing
    end
    entry = entry_any::HostEntry
    lock(entry.entry_lock)
    unlock(resolver.resolver_lock)

    cache = address_type == HostAddressType.A ? entry.a_records : entry.aaaa_records
    addr = use_lru!(cache)
    result = addr === nothing ? nothing : copy(addr)

    unlock(entry.entry_lock)
    return result
end

# Record a connection failure for an address (for load balancing)
function host_resolver_record_connection_failure!(
        resolver::HostResolver,
        address::HostAddress,
    )
    lock(resolver.resolver_lock)
    entry_any = get(resolver.cache, address.host, nothing)
    if entry_any === nothing
        unlock(resolver.resolver_lock)
        return nothing
    end
    entry = entry_any::HostEntry

    lock(entry.entry_lock)
    unlock(resolver.resolver_lock)

    if address.address_type == HostAddressType.A
        primary = entry.a_records
        failed = entry.failed_a_records
    else
        primary = entry.aaaa_records
        failed = entry.failed_aaaa_records
    end

    cached = _cache_find(primary, address.address)
    if cached !== nothing
        _cache_remove_good!(entry, primary, address.address)
        addr_copy = copy(cached)
        addr_copy.connection_failure_count += 1
        _PARENT.put!(failed, addr_copy.address, addr_copy)
    else
        cached_failed = _cache_find(failed, address.address)
        if cached_failed !== nothing
            cached_failed.connection_failure_count += 1
        end
    end

    unlock(entry.entry_lock)
    return nothing
end

# Shutdown the resolver
function host_resolver_shutdown!(resolver::HostResolver)
    @atomic resolver.shutdown = true
    entries = HostEntry{HostResolver}[]
    lock(resolver.resolver_lock)
    for (_, entry_any) in resolver.cache
        entry = entry_any::HostEntry
        push!(entries, entry)
    end
    empty!(resolver.cache)
    unlock(resolver.resolver_lock)

    for entry in entries
        _host_entry_shutdown!(entry)
    end

    logf(LogLevel.DEBUG, LS_IO_DNS, "Host resolver: shutdown initiated")
    return nothing
end

# Native getaddrinfo implementation (avoiding Sockets dependency)

# struct addrinfo from C (used by getaddrinfo)
# Note: The layout differs between platforms
@static if Sys.iswindows()
    struct addrinfo
        ai_flags::Cint
        ai_family::Cint
        ai_socktype::Cint
        ai_protocol::Cint
        ai_addrlen::Csize_t
        ai_canonname::Ptr{UInt8}
        ai_addr::Ptr{Cvoid}
        ai_next::Ptr{addrinfo}
    end
elseif Sys.isapple() || Sys.isbsd()
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
const AI_ALL = @static Sys.isapple() ? Cint(0x00000100) : Sys.islinux() ? Cint(0x0010) : Cint(0)
const AI_V4MAPPED = @static Sys.isapple() ? Cint(0x00000800) : Sys.islinux() ? Cint(0x0008) : Cint(0)
const AF_UNSPEC = Cint(0)
const SOCK_STREAM = Cint(1)
# Address family constants as returned by the OS getaddrinfo()/getnameinfo() stack.
# Note: On Windows, AF_INET6 is 23 (not POSIX's 10).
const _HR_AF_INET = Cint(2)
const _HR_AF_INET6 = @static Sys.iswindows() ? Cint(23) : AF_INET6

# NI_NUMERICHOST is platform-specific (Linux uses 1, Apple/BSD/Windows use 2).
const NI_NUMERICHOST = @static Sys.islinux() ? Cint(0x00000001) : Cint(0x00000002)

"""
Native getaddrinfo wrapper - returns a vector of address/family pairs.
"""
function _native_getaddrinfo(hostname::String; flags::Cint = Cint(0))::Vector{Tuple{String, Cint}}
    addresses = Tuple{String, Cint}[]
    hints = Ref{addrinfo}()
    hints_ptr = Base.unsafe_convert(Ptr{addrinfo}, hints)
    Base.Libc.memset(hints_ptr, 0, sizeof(addrinfo))
    hints_bytes = Ptr{UInt8}(hints_ptr)
    GC.@preserve hints begin
        # ai_flags
        unsafe_store!(Ptr{Cint}(hints_bytes + fieldoffset(addrinfo, 1)), flags)
        # ai_family
        unsafe_store!(Ptr{Cint}(hints_bytes + fieldoffset(addrinfo, 2)), AF_UNSPEC)
        # ai_socktype
        unsafe_store!(Ptr{Cint}(hints_bytes + fieldoffset(addrinfo, 3)), SOCK_STREAM)
    end
    result_ptr = Ref{Ptr{addrinfo}}(C_NULL)
    ret = GC.@preserve hints begin
        @ccall gc_safe = true getaddrinfo(
            hostname::Cstring,
            C_NULL::Cstring,
            hints_ptr::Ptr{addrinfo},
            result_ptr::Ptr{Ptr{addrinfo}},
        )::Cint
    end
    ret != 0 && return addresses
    current = result_ptr[]
    while current != C_NULL
        ai = unsafe_load(current)
        if ai.ai_addr != C_NULL
            buf = Memory{UInt8}(undef, 46)
            gi = GC.@preserve buf begin
                ccall(
                    :getnameinfo, Cint,
                    (Ptr{Cvoid}, Cuint, Ptr{UInt8}, Cuint, Ptr{UInt8}, Cuint, Cint),
                    ai.ai_addr, ai.ai_addrlen, pointer(buf), Cuint(length(buf)), C_NULL, 0, NI_NUMERICHOST
                )
            end
            if gi == 0
                addr = unsafe_string(pointer(buf))
                if ai.ai_family == _HR_AF_INET || ai.ai_family == _HR_AF_INET6
                    push!(addresses, (addr, ai.ai_family))
                end
            end
        end
        current = ai.ai_next
    end
    if result_ptr[] != C_NULL
        ccall(:freeaddrinfo, Cvoid, (Ptr{addrinfo},), result_ptr[])
    end
    return addresses
end

"""
    getalladdrinfo_raw(hostname; flags=0) -> Vector{Tuple{String, Cint}}

Public wrapper for the libuv-free `getaddrinfo()` implementation used by the
host resolver. This exists primarily so downstream packages can avoid `Sockets`.
"""
function getalladdrinfo_raw(hostname::AbstractString; flags::Cint = Cint(0))::Vector{Tuple{String, Cint}}
    return _native_getaddrinfo(String(hostname); flags = flags)
end
