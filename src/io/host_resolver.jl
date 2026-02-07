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

# Host resolver callback types
const OnHostResolvedFn = Function  # (resolver, host_name, error_code, addresses::Vector{HostAddress}) -> nothing
const OnHostResolveCompleteFn = Function  # (resolver, user_data) -> nothing

@enumx DefaultResolverState::UInt8 begin
    ACTIVE = 0
    SHUTTING_DOWN = 1
end

mutable struct PendingCallback
    callback::OnHostResolvedFn
    user_data::Any
end

# Host resolver configuration
struct HostResolverConfig
    max_entries::UInt64
    max_ttl_secs::UInt64
    min_ttl_secs::UInt64
    max_addresses_per_host::UInt64
    resolve_frequency_ns::UInt64  # How often to re-resolve
    background_refresh::Bool  # retained for compatibility
    clock_override::Union{Function, Nothing}
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
        clock_override::Union{Function, Nothing} = nothing,
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

const HostResolverCache = Dict{String, Any}

# Abstract resolver interface
abstract type AbstractHostResolver end

# Default host resolver with caching
mutable struct DefaultHostResolver <: AbstractHostResolver
    event_loop_group::EventLoopGroup
    config::HostResolverConfig
    cache::HostResolverCache
    resolver_lock::ReentrantLock
    @atomic shutdown::Bool
end

@inline function _resolver_clock(resolver::DefaultHostResolver)::UInt64
    clock_override = resolver.config.clock_override
    return clock_override === nothing ? high_res_clock() : clock_override()
end

function DefaultHostResolver(
        event_loop_group::EventLoopGroup,
        config::HostResolverConfig = HostResolverConfig(),
    )
    cache = Dict{String, Any}()
    sizehint!(cache, Int(config.max_entries))
    resolver = DefaultHostResolver(
        event_loop_group,
        config,
        cache,
        ReentrantLock(),
        false,
    )
    return resolver
end

mutable struct HostEntry
    resolver::DefaultHostResolver
    host_name::String
    resolution_config::HostResolutionConfig
    resolve_frequency_ns::UInt64
    entry_lock::ReentrantLock
    entry_signal::ConditionVariable
    a_records::LRUCache{String, HostAddress}
    aaaa_records::LRUCache{String, HostAddress}
    failed_a_records::LRUCache{String, HostAddress}
    failed_aaaa_records::LRUCache{String, HostAddress}
    pending_callbacks::Deque{PendingCallback}
    last_resolve_request_time::UInt64
    resolves_since_last_request::UInt32
    @atomic state::DefaultResolverState.T
    new_addresses::Vector{HostAddress}
    expired_addresses::Vector{HostAddress}
    on_host_purge_complete::Union{Function, Nothing}  # late-init: nothing → Function
    on_host_purge_complete_user_data::Any              # late-init
    resolver_thread::ThreadHandle
end

function _entry_cache_capacity(resolver::DefaultHostResolver, config::HostResolutionConfig)
    ttl = config.max_ttl_secs != 0 ? config.max_ttl_secs : resolver.config.max_ttl_secs
    return max(Int(ttl), 1)
end

function HostEntry(
        resolver::DefaultHostResolver,
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
        Deque{PendingCallback}(0),
        timestamp,
        UInt32(0),
        DefaultResolverState.ACTIVE,
        HostAddress[],
        HostAddress[],
        nothing,
        nothing,
        ThreadHandle(),
    )
end

function _normalize_resolution_config(
        resolver::DefaultHostResolver,
        config::Union{HostResolutionConfig, Nothing},
    )
    base_max_ttl = resolver.config.max_ttl_secs
    base_resolve_freq = resolver.config.resolve_frequency_ns == 0 ?
        HOST_RESOLVER_DEFAULT_RESOLVE_FREQUENCY_NS :
        resolver.config.resolve_frequency_ns

    if config === nothing
        return HostResolutionConfig(
            _default_dns_resolve,
            base_max_ttl,
            base_resolve_freq,
            resolver.config.max_addresses_per_host,
        )
    end

    impl = config.impl === nothing ? _default_dns_resolve : config.impl
    max_ttl = config.max_ttl_secs != 0 ? config.max_ttl_secs : base_max_ttl
    resolve_freq = config.resolve_frequency_ns != 0 ? config.resolve_frequency_ns : base_resolve_freq
    impl_data = config.impl_data === nothing && impl === _default_dns_resolve ?
        resolver.config.max_addresses_per_host :
        config.impl_data

    return HostResolutionConfig(impl, max_ttl, resolve_freq, impl_data)
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
            (t, status) -> Base.invokelatest(callback, user_data),
            nothing;
            type_tag = "dns_purge_callback"
        )
        event_loop_schedule_task_now!(event_loop, task)
    else
        Base.invokelatest(callback, user_data)
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
        put!(primary, addr_copy.address, addr_copy)
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
            put!(records, addr_copy.address, addr_copy)
            push!(entry.new_addresses, copy(addr_copy))
            _cache_remove_failed!(failed_records, addr.address)
            should_promote = false
        end
    end
    return nothing
end

function _collect_callback_addresses(entry::HostEntry)
    addresses = HostAddress[]
    aaaa = use_lru!(entry.aaaa_records)
    a = use_lru!(entry.a_records)
    aaaa !== nothing && push!(addresses, copy(aaaa))
    a !== nothing && push!(addresses, copy(a))
    return addresses
end

function _host_entry_finished_pred(entry::HostEntry)
    return (@atomic entry.state) == DefaultResolverState.SHUTTING_DOWN
end

function _host_entry_finished_or_pending_pred(entry::HostEntry)
    return ((@atomic entry.state) == DefaultResolverState.SHUTTING_DOWN) || !isempty(entry.pending_callbacks)
end

function _invoke_resolver_impl(impl::Function, host::String, impl_data)
    result = impl(host, impl_data)
    if result isa Tuple
        return result
    end
    return result, AWS_OP_SUCCESS
end

function _default_dns_resolve(host::String, impl_data)
    max_addresses = impl_data isa Integer ? Int(impl_data) : 0
    # We want a stable mix of A/AAAA results. `getaddrinfo()` ordering is platform-dependent and can
    # yield long runs of one family (e.g. AAAA first). If we hard-cap by "first N" we may end up
    # with only one family even when both exist (e.g. dualstack endpoints).
    ipv6 = HostAddress[]
    ipv4 = HostAddress[]
    error_code = AWS_OP_SUCCESS
    flags = @static Sys.isopenbsd() ? Cint(0) : (AI_ALL | AI_V4MAPPED)
    raw_addresses = _native_getaddrinfo(host; flags = flags)
    for (addr, family) in raw_addresses
        if family == AF_INET6
            push!(ipv6, HostAddress(addr, HostAddressType.AAAA, host, UInt64(0)))
        elseif family == AF_INET
            push!(ipv4, HostAddress(addr, HostAddressType.A, host, UInt64(0)))
        end
    end

    addresses = HostAddress[]
    if max_addresses > 0
        # Interleave IPv6/IPv4 to keep both families represented when possible.
        i6 = 1
        i4 = 1
        while length(addresses) < max_addresses && (i6 <= length(ipv6) || i4 <= length(ipv4))
            if i6 <= length(ipv6)
                push!(addresses, ipv6[i6])
                i6 += 1
                length(addresses) >= max_addresses && break
            end
            if i4 <= length(ipv4)
                push!(addresses, ipv4[i4])
                i4 += 1
            end
        end
    else
        append!(addresses, ipv6)
        append!(addresses, ipv4)
    end

    if isempty(addresses)
        error_code = ERROR_IO_DNS_NO_ADDRESS_FOR_HOST
    end

    return addresses, error_code
end

function _resolve_addresses(entry::HostEntry)
    addresses = HostAddress[]
    error_code = AWS_OP_SUCCESS

    impl = entry.resolution_config.impl === nothing ? _default_dns_resolve : entry.resolution_config.impl
    impl_data = entry.resolution_config.impl_data
    try
        addresses, error_code = _invoke_resolver_impl(impl, entry.host_name, impl_data)
    catch e
        if e isa MethodError && impl !== _default_dns_resolve
            try
                addresses = impl(entry.host_name, HostAddressType.A, impl_data)
                error_code = AWS_OP_SUCCESS
            catch err
                logf(LogLevel.ERROR, LS_IO_DNS, "Host resolver: custom resolve failed for '$(entry.host_name)': $err")
                addresses = HostAddress[]
                error_code = ERROR_IO_DNS_QUERY_FAILED
            end
        else
            logf(LogLevel.ERROR, LS_IO_DNS, "Host resolver: resolve failed for '$(entry.host_name)': $e")
            error_code = ERROR_IO_DNS_QUERY_FAILED
        end
    end

    if error_code == AWS_OP_SUCCESS
        if addresses isa AbstractVector{HostAddress}
            addresses = collect(addresses)
            for addr in addresses
                addr.host = entry.host_name
            end
        else
            addresses = HostAddress[]
            error_code = ERROR_IO_DNS_QUERY_FAILED
        end
    end

    return addresses, error_code
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

            pending = Deque{PendingCallback}(0)
            lock(entry.entry_lock)
            try
                if err_code == AWS_OP_SUCCESS
                    _update_address_cache!(entry, addresses, new_expiry)
                end
                _process_records!(entry, entry.aaaa_records, entry.failed_aaaa_records, timestamp)
                _process_records!(entry, entry.a_records, entry.failed_a_records, timestamp)

                pending = entry.pending_callbacks
                entry.pending_callbacks = Deque{PendingCallback}(0)
            finally
                unlock(entry.entry_lock)
            end

            while !isempty(pending)
                pending_callback = pop_front!(pending)
                callback_addresses = HostAddress[]
                lock(entry.entry_lock)
                try
                    callback_addresses = _collect_callback_addresses(entry)
                finally
                    unlock(entry.entry_lock)
                end

                if isempty(callback_addresses)
                    error_code = err_code == AWS_OP_SUCCESS ? ERROR_IO_DNS_QUERY_FAILED : err_code
                    try
                        Base.invokelatest(
                            pending_callback.callback,
                            entry.resolver,
                            entry.host_name,
                            error_code,
                            HostAddress[],
                        )
                    catch err
                        logf(
                            LogLevel.ERROR,
                            LS_IO_DNS,
                            "Host resolver: callback failed for '$(entry.host_name)': $err",
                        )
                    end
                else
                    try
                        Base.invokelatest(
                            pending_callback.callback,
                            entry.resolver,
                            entry.host_name,
                            AWS_OP_SUCCESS,
                            callback_addresses,
                        )
                    catch err
                        logf(
                            LogLevel.ERROR,
                            LS_IO_DNS,
                            "Host resolver: callback failed for '$(entry.host_name)': $err",
                        )
                    end
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
                    now = _resolver_clock(resolver)
                    if resolver.shutdown || (
                            isempty(entry.pending_callbacks) &&
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
            Base.invokelatest(entry.on_host_purge_complete, entry.on_host_purge_complete_user_data)
        end
    catch err
        logf(LogLevel.ERROR, LS_IO_DNS, "Host resolver: thread failed for '$(entry.host_name)': $err")
        bt = catch_backtrace()
        logf(LogLevel.ERROR, LS_IO_DNS, "%s", sprint(showerror, err, bt))
    end

    return nothing
end

function _host_entry_shutdown!(entry::HostEntry)
    lock(entry.entry_lock)
    @atomic entry.state = DefaultResolverState.SHUTTING_DOWN
    condition_variable_notify_all(entry.entry_signal)
    unlock(entry.entry_lock)
    return nothing
end

# Resolve a hostname to addresses
function host_resolver_resolve!(
        resolver::DefaultHostResolver,
        host_name::AbstractString,
        on_resolved::OnHostResolvedFn,
        user_data = nothing;
        resolution_config::Union{HostResolutionConfig, Nothing} = nothing,
    )::Union{Nothing, ErrorResult}
    if @atomic resolver.shutdown
        logf(LogLevel.ERROR, LS_IO_DNS, "Host resolver: resolve called after shutdown")
        raise_error(ERROR_IO_EVENT_LOOP_SHUTDOWN)
        return ErrorResult(ERROR_IO_EVENT_LOOP_SHUTDOWN)
    end

    host = String(host_name)
    timestamp = _resolver_clock(resolver)

    lock(resolver.resolver_lock)
    entry = get(resolver.cache, host, nothing)
    if entry === nothing
        new_entry = HostEntry(resolver, host, resolution_config, timestamp)
        push_back!(
            new_entry.pending_callbacks,
            PendingCallback(on_resolved, user_data),
        )
        resolver.cache[host] = new_entry
        thread_options = ThreadOptions(;
            join_strategy = ThreadJoinStrategy.MANAGED,
            name = "AwsHostResolver",
        )
        launch_result = thread_launch(new_entry.resolver_thread, _host_resolver_thread, new_entry, thread_options)
        if launch_result != OP_SUCCESS
            delete!(resolver.cache, host)
            unlock(resolver.resolver_lock)
            return ErrorResult(last_error())
        end
        unlock(resolver.resolver_lock)
        return nothing
    end

    lock(entry.entry_lock)
    unlock(resolver.resolver_lock)

    entry.last_resolve_request_time = timestamp
    entry.resolves_since_last_request = 0
    cached_addresses = _collect_callback_addresses(entry)

    if !isempty(cached_addresses)
        unlock(entry.entry_lock)
        Base.invokelatest(on_resolved, resolver, host, AWS_OP_SUCCESS, cached_addresses)
        return nothing
    end

    push_back!(
        entry.pending_callbacks,
        PendingCallback(on_resolved, user_data),
    )
    condition_variable_notify_all(entry.entry_signal)
    unlock(entry.entry_lock)

    return nothing
end

# Purge the entire cache
function host_resolver_purge_cache!(resolver::DefaultHostResolver)
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

    lock(resolver.resolver_lock)
    entry = get(resolver.cache, host, nothing)
    if entry === nothing
        unlock(resolver.resolver_lock)
        _dispatch_simple_callback(resolver, on_host_purge_complete, user_data)
        return nothing
    end

    lock(entry.entry_lock)
    entry.on_host_purge_complete = on_host_purge_complete
    entry.on_host_purge_complete_user_data = user_data
    unlock(entry.entry_lock)

    delete!(resolver.cache, host)
    unlock(resolver.resolver_lock)

    _host_entry_shutdown!(entry)

    return nothing
end

function host_resolver_get_host_address_count(
        resolver::DefaultHostResolver,
        host_name::AbstractString;
        flags::UInt32 = GET_HOST_ADDRESS_COUNT_ALL,
    )::Csize_t
    host = String(host_name)
    count = 0

    lock(resolver.resolver_lock)
    entry = get(resolver.cache, host, nothing)
    if entry !== nothing
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
        resolver::DefaultHostResolver,
        host_name::AbstractString;
        address_type::HostAddressType.T = HostAddressType.A,
    )::Union{HostAddress, Nothing}
    host = String(host_name)

    lock(resolver.resolver_lock)
    entry = get(resolver.cache, host, nothing)
    if entry === nothing
        unlock(resolver.resolver_lock)
        return nothing
    end
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
        resolver::DefaultHostResolver,
        address::HostAddress,
    )
    lock(resolver.resolver_lock)
    entry = get(resolver.cache, address.host, nothing)
    if entry === nothing
        unlock(resolver.resolver_lock)
        return nothing
    end

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
        put!(failed, addr_copy.address, addr_copy)
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
function host_resolver_shutdown!(resolver::DefaultHostResolver)
    @atomic resolver.shutdown = true
    entries = HostEntry[]
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
@static if Sys.isapple() || Sys.isbsd()
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
const NI_NUMERICHOST = Cint(0x00000002)

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
                if ai.ai_family == AF_INET || ai.ai_family == AF_INET6
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
