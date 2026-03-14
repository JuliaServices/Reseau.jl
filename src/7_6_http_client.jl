# HTTP client transport, redirect, cookie-jar, and high-level convenience APIs.
export Transport
export ClientConn
export ManagedBody
export RetryBucket
export roundtrip!
export close_idle_connections!
export idle_connection_count

using Base64
using CodecZlib
using ..Reseau.TCP
using ..Reseau.HostResolvers
using ..Reseau.TLS

const _CONN_READER_DEFAULT_BUFFER_BYTES = 16 * 1024

mutable struct _ConnReader{C} <: IO
    conn::C
    buf::Vector{UInt8}
    next::Int
    stop::Int
end

"""
    _ConnReader(conn; buffer_bytes=16*1024)

Buffered `IO` adapter layered over `TCP.Conn` or `TLS.Conn`.

HTTP/1 parsing wants a byte-oriented reader with a small amount of lookahead so
it can parse lines and then continue reading bodies from the same transport.
This type provides that without forcing the transport types themselves to own
HTTP-specific buffering policy.
"""
function _ConnReader(conn::C; buffer_bytes::Integer = _CONN_READER_DEFAULT_BUFFER_BYTES) where {C}
    buffer_bytes > 0 || throw(ArgumentError("buffer_bytes must be > 0"))
    return _ConnReader{C}(conn, Vector{UInt8}(undef, Int(buffer_bytes)), 1, 0)
end

@inline function _conn_reader_available(reader::_ConnReader)::Int
    reader.next > reader.stop && return 0
    return reader.stop - reader.next + 1
end

@inline function _fill_conn_reader!(reader::_ConnReader)::Int
    n = read!(reader.conn, reader.buf)
    reader.next = 1
    reader.stop = n
    return n
end

function _upcoming_header_keys(reader::_ConnReader)::Int
    _conn_reader_available(reader) == 0 && return 0
    nkeys = 0
    line_start = reader.next
    i = reader.next
    while i <= reader.stop && nkeys < 1000
        if @inbounds(reader.buf[i]) == 0x0a
            line_len = i - line_start + 1
            if line_len == 1
                break
            end
            first = @inbounds(reader.buf[line_start])
            if first == 0x0d && line_len == 2
                break
            end
            if first != 0x20 && first != 0x09
                nkeys += 1
            end
            line_start = i + 1
        end
        i += 1
    end
    return nkeys
end

const _ClientConnReader = Union{_ConnReader{TCP.Conn}, _ConnReader{TLS.Conn}}

"""
    ClientConn

Internal pooled HTTP/1 connection record. It bundles the underlying transport,
the parser's `_ConnReader`, a reusable request serialization buffer, and a few
small pieces of pooling metadata such as `reused` and `last_used_ns`.
"""
mutable struct ClientConn
    key::String
    address::String
    secure::Bool
    tcp::Union{Nothing, TCP.Conn}
    tls::Union{Nothing, TLS.Conn}
    reader::_ClientConnReader
    request_buf::IOBuffer
    reused::Bool
    @atomic closed::Bool
    last_used_ns::Int64
end

const _CONN_WAITER_WAITING = UInt8(0)
const _CONN_WAITER_CONN = UInt8(1)
const _CONN_WAITER_DIAL = UInt8(2)
const _CONN_WAITER_ERROR = UInt8(3)
const _CONN_WAITER_CANCELED = UInt8(4)

mutable struct _ConnWaiter
    key::String
    signal::Channel{Nothing}
    conn::Union{Nothing, ClientConn}
    err::Union{Nothing, Exception}
    @atomic state::UInt8
end

function _ConnWaiter(key::String)
    return _ConnWaiter(key, Channel{Nothing}(1), nothing, nothing, _CONN_WAITER_WAITING)
end

"""
    Transport(; ...)

Connection-pooling transport for HTTP/1 requests.

This is the closest analogue to Go's `http.Transport` in the current codebase.
It owns dial/TLS policy and decides when an idle connection can be reused versus
closed.

`max_conns_per_host = 0` leaves per-host concurrency unlimited. Positive values
bound the total live HTTP/1 connections (idle, in-flight, and dialing) for one
pool key and cause additional acquires to wait for direct handoff or a freed
dial slot.
"""
mutable struct Transport
    host_resolver::HostResolvers.HostResolver
    tls_config::Union{Nothing, TLS.Config}
    proxy::ProxyConfig
    retry_bucket::Union{Nothing, RetryBucket}
    max_idle_per_host::Int
    max_idle_total::Int
    max_conns_per_host::Int
    idle_timeout_ns::Int64
    lock::ReentrantLock
    idle::Dict{String, Vector{ClientConn}}
    waiters::Dict{String, Vector{_ConnWaiter}}
    conns_per_host::Dict{String, Int}
    @atomic idle_total::Int
    @atomic closed::Bool
end

"""
    ManagedBody

Response body wrapper that returns/tears down pooled connections once the body
is fully consumed or closed.

If the caller drains the body to EOF, `ManagedBody` returns the underlying
connection to the idle pool when it is safe to do so. If the body is abandoned
early or an error occurs, the connection is closed instead so the next request
does not observe leftover bytes.
"""
mutable struct ManagedBody{B <: AbstractBody} <: AbstractBody
    inner::B
    transport::Transport
    conn::ClientConn
    reusable::Bool
    @atomic saw_eof::Bool
    @atomic released::Bool
end

function Transport(;
        host_resolver::HostResolvers.HostResolver = HostResolvers.HostResolver(),
        tls_config::Union{Nothing, TLS.Config} = nothing,
        proxy = nothing,
        retry_bucket::Union{Nothing, RetryBucket} = RetryBucket(),
        max_idle_per_host::Integer = 2,
        max_idle_total::Integer = 64,
        max_conns_per_host::Integer = 0,
        idle_timeout_ns::Integer = Int64(90_000_000_000),
    )
    max_idle_per_host > 0 || throw(ArgumentError("max_idle_per_host must be > 0"))
    max_idle_total > 0 || throw(ArgumentError("max_idle_total must be > 0"))
    max_conns_per_host >= 0 || throw(ArgumentError("max_conns_per_host must be >= 0"))
    idle_timeout_ns >= 0 || throw(ArgumentError("idle_timeout_ns must be >= 0"))
    return Transport(
        host_resolver,
        tls_config,
        _normalize_proxy_config(proxy),
        retry_bucket,
        Int(max_idle_per_host),
        Int(max_idle_total),
        Int(max_conns_per_host),
        Int64(idle_timeout_ns),
        ReentrantLock(),
        Dict{String, Vector{ClientConn}}(),
        Dict{String, Vector{_ConnWaiter}}(),
        Dict{String, Int}(),
        0,
        false,
    )
end

@inline function _transport_closed(transport::Transport)::Bool
    return @atomic :acquire transport.closed
end

@inline function _conn_closed(conn::ClientConn)::Bool
    return @atomic :acquire conn.closed
end

function _conn_stream(conn::ClientConn)
    if conn.secure
        conn.tls === nothing && throw(ProtocolError("transport connection missing TLS stream"))
        return conn.tls::TLS.Conn
    end
    conn.tcp === nothing && throw(ProtocolError("transport connection missing TCP stream"))
    return conn.tcp::TCP.Conn
end

function _close_conn!(conn::ClientConn)::Bool
    if _conn_closed(conn)
        return false
    end
    @atomic :release conn.closed = true
    if conn.secure
        if conn.tls !== nothing
            try
                TLS.close!(conn.tls::TLS.Conn)
            catch
            end
        end
    else
        if conn.tcp !== nothing
            try
                TCP.close!(conn.tcp::TCP.Conn)
            catch
            end
        end
    end
    return true
end

@inline function _notify_waiter!(waiter::_ConnWaiter)
    isready(waiter.signal) || put!(waiter.signal, nothing)
    return nothing
end

@inline function _waiter_waiting(waiter::_ConnWaiter)::Bool
    return (@atomic :acquire waiter.state) == _CONN_WAITER_WAITING
end

function _enqueue_waiter_locked!(transport::Transport, waiter::_ConnWaiter)
    queue = get(() -> _ConnWaiter[], transport.waiters, waiter.key)
    push!(queue, waiter)
    transport.waiters[waiter.key] = queue
    return waiter
end

function _remove_waiter_locked!(transport::Transport, key::String, waiter::_ConnWaiter)
    queue = get(() -> nothing, transport.waiters, key)
    queue === nothing && return nothing
    idx = findfirst(isequal(waiter), queue::Vector{_ConnWaiter})
    idx === nothing || deleteat!(queue::Vector{_ConnWaiter}, idx)
    isempty(queue::Vector{_ConnWaiter}) && delete!(transport.waiters, key)
    return nothing
end

function _next_waiter_locked!(transport::Transport, key::String)::Union{Nothing, _ConnWaiter}
    queue = get(() -> nothing, transport.waiters, key)
    queue === nothing && return nothing
    while !isempty(queue::Vector{_ConnWaiter})
        waiter = popfirst!(queue::Vector{_ConnWaiter})
        if _waiter_waiting(waiter)
            isempty(queue::Vector{_ConnWaiter}) && delete!(transport.waiters, key)
            return waiter
        end
    end
    delete!(transport.waiters, key)
    return nothing
end

@inline function _conn_slots_locked(transport::Transport, key::String)::Int
    return get(() -> 0, transport.conns_per_host, key)
end

function _reserve_conn_slot_locked!(transport::Transport, key::String)::Bool
    current = _conn_slots_locked(transport, key)
    max_per_host = transport.max_conns_per_host
    if max_per_host != 0 && current >= max_per_host
        return false
    end
    transport.conns_per_host[key] = current + 1
    return true
end

function _decrement_conn_slot_locked!(transport::Transport, key::String)
    current = _conn_slots_locked(transport, key)
    current <= 1 ? delete!(transport.conns_per_host, key) : (transport.conns_per_host[key] = current - 1)
    return nothing
end

function _promote_waiter_to_dial_locked!(transport::Transport, key::String)::Union{Nothing, _ConnWaiter}
    transport.max_conns_per_host == 0 && return nothing
    _reserve_conn_slot_locked!(transport, key) || return nothing
    waiter = _next_waiter_locked!(transport, key)
    if waiter === nothing
        _decrement_conn_slot_locked!(transport, key)
        return nothing
    end
    waiter.conn = nothing
    waiter.err = nothing
    @atomic :release waiter.state = _CONN_WAITER_DIAL
    return waiter
end

function _release_conn_slot_locked!(transport::Transport, key::String)::Union{Nothing, _ConnWaiter}
    _decrement_conn_slot_locked!(transport, key)
    _transport_closed(transport) && return nothing
    return _promote_waiter_to_dial_locked!(transport, key)
end

function _close_owned_conn!(transport::Transport, conn::ClientConn)
    _close_conn!(conn) || return nothing
    waiter = nothing
    lock(transport.lock)
    try
        waiter = _release_conn_slot_locked!(transport, conn.key)
    finally
        unlock(transport.lock)
    end
    waiter === nothing || _notify_waiter!(waiter)
    return nothing
end

function _close_owned_conns!(transport::Transport, conns::Vector{ClientConn})
    for conn in conns
        _close_owned_conn!(transport, conn)
    end
    return nothing
end

function _deliver_waiter_conn_locked!(waiter::_ConnWaiter, conn::ClientConn)::Bool
    _waiter_waiting(waiter) || return false
    waiter.conn = conn
    waiter.err = nothing
    @atomic :release waiter.state = _CONN_WAITER_CONN
    return true
end

function _deliver_waiter_error_locked!(waiter::_ConnWaiter, err::Exception)::Bool
    _waiter_waiting(waiter) || return false
    waiter.conn = nothing
    waiter.err = err
    @atomic :release waiter.state = _CONN_WAITER_ERROR
    return true
end

function _wait_for_conn!(transport::Transport, waiter::_ConnWaiter, deadline_ns::Int64)
    while true
        state = @atomic :acquire waiter.state
        if state == _CONN_WAITER_CONN
            return waiter.conn::ClientConn
        elseif state == _CONN_WAITER_DIAL
            return :dial
        elseif state == _CONN_WAITER_ERROR
            throw(waiter.err::Exception)
        elseif state == _CONN_WAITER_CANCELED
            throw(IOPoll.DeadlineExceededError())
        end
        if deadline_ns == 0
            take!(waiter.signal)
            continue
        end
        now_ns = Int64(time_ns())
        if now_ns >= deadline_ns
            lock(transport.lock)
            try
                if _waiter_waiting(waiter)
                    _remove_waiter_locked!(transport, waiter.key, waiter)
                    @atomic :release waiter.state = _CONN_WAITER_CANCELED
                    throw(IOPoll.DeadlineExceededError())
                end
            finally
                unlock(transport.lock)
            end
            continue
        end
        timeout_s = min((deadline_ns - now_ns) / 1.0e9, 0.05)
        timedwait(() -> isready(waiter.signal), timeout_s; pollint = 0.001)
        isready(waiter.signal) && take!(waiter.signal)
    end
end

function _prepare_conn_for_reuse!(conn::ClientConn)
    if conn.secure
        conn.tls === nothing || TLS.set_deadline!(conn.tls::TLS.Conn, Int64(0))
    else
        conn.tcp === nothing || TCP.set_deadline!(conn.tcp::TCP.Conn, Int64(0))
    end
    conn.last_used_ns = time_ns()
    return nothing
end

function _host_for_sni(address::AbstractString)::String
    host, _ = HostResolvers.split_host_port(address)
    return host
end

function _effective_tls_config(transport::Transport, address::String, server_name::Union{Nothing, String})::TLS.Config
    sni = server_name === nothing ? _host_for_sni(address) : server_name
    cfg = transport.tls_config
    if cfg === nothing
        return TLS.Config(server_name = sni)
    end
    if cfg.server_name !== nothing
        return cfg
    end
    return TLS.Config(
        server_name = sni,
        verify_peer = cfg.verify_peer,
        client_auth = cfg.client_auth,
        cert_file = cfg.cert_file,
        key_file = cfg.key_file,
        ca_file = cfg.ca_file,
        client_ca_file = cfg.client_ca_file,
        alpn_protocols = copy(cfg.alpn_protocols),
        handshake_timeout_ns = cfg.handshake_timeout_ns,
        min_version = cfg.min_version,
        max_version = cfg.max_version,
    )
end

function _write_request_bytes!(stream, request_io::IOBuffer)
    data = take!(request_io)
    request_bytes = length(data)
    request_bytes == 0 && return nothing
    n = write(stream, data)
    n == request_bytes || throw(ProtocolError("transport short write"))
    return nothing
end

function _write_request_streaming!(
        request_io::IOBuffer,
        stream,
        request::Request;
        wire_target::Union{Nothing, AbstractString} = nothing,
        proxy_authorization::Union{Nothing, AbstractString} = nothing,
    )
    if request.content_length >= 0 && request.body isa BytesBody && !headercontains(request.headers, "Transfer-Encoding", "chunked")
        _write_request_head!(request_io, request; wire_target = wire_target, proxy_authorization = proxy_authorization)
        _write_request_bytes!(stream, request_io)
        _write_exact_bytes_body!(stream, request.body::BytesBody, request.content_length)
        return nothing
    end
    write_request!(request_io, request; wire_target = wire_target, proxy_authorization = proxy_authorization)
    _write_request_bytes!(stream, request_io)
    return nothing
end

function _perform_http_connect_tunnel!(
        tcp::TCP.Conn,
        proxy::_ProxyTarget,
        target_address::String,
        deadline_ns::Int64,
    )::Nothing
    deadline_ns == 0 || TCP.set_deadline!(tcp, deadline_ns)
    headers = Headers()
    setheader(headers, "Host", target_address)
    proxy.authorization === nothing || setheader(headers, "Proxy-Authorization", proxy.authorization::String)
    request = Request(
        "CONNECT",
        target_address;
        headers = headers,
        host = target_address,
        content_length = 0,
    )
    request_io = IOBuffer()
    write_request!(request_io, request)
    _write_request_bytes!(tcp, request_io)
    response = _read_incoming_response(_ConnReader(tcp), request)
    try
        body_close!(response.rawbody)
    catch
    end
    response.head.status_code == 200 || throw(ProtocolError("proxy CONNECT failed with status $(response.head.status_code)"))
    return nothing
end

function _new_conn!(
        transport::Transport,
        plan::_ProxyPlan,
        address::String;
        secure::Bool,
        server_name::Union{Nothing, String},
        deadline_ns::Int64 = Int64(0),
    )::ClientConn
    tcp = TCP.connect(transport.host_resolver, "tcp", plan.first_hop_address)
    if plan.mode == _ProxyPlanMode.HTTP_TUNNEL
        proxy = plan.proxy
        proxy === nothing && throw(ProtocolError("proxy CONNECT tunnel is missing proxy config"))
        _perform_http_connect_tunnel!(tcp, proxy::_ProxyTarget, address, deadline_ns)
    end
    if secure
        cfg = _effective_tls_config(transport, address, server_name)
        tls = TLS.client(tcp, cfg)
        TLS.handshake!(tls)
        return ClientConn(plan.pool_key, plan.first_hop_address, true, tcp, tls, _ConnReader(tls), IOBuffer(), false, false, time_ns())
    end
    return ClientConn(plan.pool_key, plan.first_hop_address, false, tcp, nothing, _ConnReader(tcp), IOBuffer(), false, false, time_ns())
end

function _evict_expired_idle_locked!(transport::Transport, key::String, now_ns::Int64)::Vector{ClientConn}
    idle_list = get(() -> nothing, transport.idle, key)
    idle_list === nothing && return ClientConn[]
    kept = ClientConn[]
    stale = ClientConn[]
    for conn in idle_list::Vector{ClientConn}
        expired = transport.idle_timeout_ns > 0 && (now_ns - conn.last_used_ns) > transport.idle_timeout_ns
        if _conn_closed(conn) || expired
            @atomic :acquire_release transport.idle_total -= 1
            push!(stale, conn)
            continue
        end
        push!(kept, conn)
    end
    if isempty(kept)
        delete!(transport.idle, key)
    else
        transport.idle[key] = kept
    end
    return stale
end

function _acquire_conn!(
        transport::Transport,
        plan::_ProxyPlan,
        address::String;
        secure::Bool,
        server_name::Union{Nothing, String},
        deadline_ns::Int64 = Int64(0),
    )::ClientConn
    _transport_closed(transport) && throw(ProtocolError("transport is closed"))
    waiter = nothing
    while true
        stale = ClientConn[]
        conn = nothing
        should_dial = false
        lock(transport.lock)
        try
            _transport_closed(transport) && throw(ProtocolError("transport is closed"))
            now_ns = Int64(time_ns())
            append!(stale, _evict_expired_idle_locked!(transport, plan.pool_key, now_ns))
            idle_list = get(() -> nothing, transport.idle, plan.pool_key)
            while idle_list !== nothing && !isempty(idle_list::Vector{ClientConn})
                conn = pop!(idle_list::Vector{ClientConn})
                @atomic :acquire_release transport.idle_total -= 1
                isempty(idle_list::Vector{ClientConn}) && delete!(transport.idle, plan.pool_key)
                if !_conn_closed(conn::ClientConn)
                    (conn::ClientConn).reused = true
                    break
                end
                push!(stale, conn::ClientConn)
                conn = nothing
                idle_list = get(() -> nothing, transport.idle, plan.pool_key)
            end
            if conn === nothing && isempty(stale)
                if _reserve_conn_slot_locked!(transport, plan.pool_key)
                    should_dial = true
                else
                    waiter = _ConnWaiter(plan.pool_key)
                    _enqueue_waiter_locked!(transport, waiter)
                end
            end
        finally
            unlock(transport.lock)
        end
        isempty(stale) || (_close_owned_conns!(transport, stale); continue)
        if conn !== nothing
            return conn::ClientConn
        end
        if should_dial
            try
                return _new_conn!(transport, plan, address; secure = secure, server_name = server_name, deadline_ns = deadline_ns)
            catch err
                waiter_to_notify = nothing
                lock(transport.lock)
                try
                    waiter_to_notify = _release_conn_slot_locked!(transport, plan.pool_key)
                finally
                    unlock(transport.lock)
                end
                waiter_to_notify === nothing || _notify_waiter!(waiter_to_notify)
                rethrow(err)
            end
        end
        result = _wait_for_conn!(transport, waiter::_ConnWaiter, deadline_ns)
        if result === :dial
            try
                return _new_conn!(transport, plan, address; secure = secure, server_name = server_name, deadline_ns = deadline_ns)
            catch err
                waiter_to_notify = nothing
                lock(transport.lock)
                try
                    waiter_to_notify = _release_conn_slot_locked!(transport, plan.pool_key)
                finally
                    unlock(transport.lock)
                end
                waiter_to_notify === nothing || _notify_waiter!(waiter_to_notify)
                rethrow(err)
            end
        end
        conn = result::ClientConn
        conn.reused = true
        return conn
    end
end

function _put_idle_conn!(transport::Transport, conn::ClientConn)
    if _transport_closed(transport) || _conn_closed(conn)
        _close_owned_conn!(transport, conn)
        return nothing
    end
    try
        _prepare_conn_for_reuse!(conn)
    catch
        _close_owned_conn!(transport, conn)
        return nothing
    end
    waiter_to_notify = nothing
    should_close = false
    lock(transport.lock)
    try
        if _transport_closed(transport)
            should_close = true
        else
            waiter = _next_waiter_locked!(transport, conn.key)
            if waiter !== nothing && _deliver_waiter_conn_locked!(waiter, conn)
                waiter_to_notify = waiter
            else
                idle_list = get(() -> ClientConn[], transport.idle, conn.key)
                if length(idle_list) >= transport.max_idle_per_host || (@atomic :acquire transport.idle_total) >= transport.max_idle_total
                    should_close = true
                else
                    push!(idle_list, conn)
                    transport.idle[conn.key] = idle_list
                    @atomic :acquire_release transport.idle_total += 1
                end
            end
        end
    finally
        unlock(transport.lock)
    end
    waiter_to_notify === nothing || (_notify_waiter!(waiter_to_notify); return nothing)
    should_close && _close_owned_conn!(transport, conn)
    return nothing
end

"""
    close_idle_connections!(transport)

Close and discard all currently idle pooled connections. Active in-flight
requests are unaffected. Returns `nothing`.
"""
function close_idle_connections!(transport::Transport)
    to_close = ClientConn[]
    lock(transport.lock)
    try
        for (_, idle_list) in transport.idle
            for conn in idle_list
                push!(to_close, conn)
            end
        end
        empty!(transport.idle)
        @atomic :release transport.idle_total = 0
    finally
        unlock(transport.lock)
    end
    _close_owned_conns!(transport, to_close)
    return nothing
end

"""
    close(transport)

Close `transport` and eagerly drop every idle connection it owns. In-flight
requests are allowed to finish on the connections they already hold.
"""
function Base.close(transport::Transport)
    _transport_closed(transport) && return nothing
    to_close = ClientConn[]
    waiters_to_notify = _ConnWaiter[]
    err = ProtocolError("transport is closed")
    lock(transport.lock)
    try
        _transport_closed(transport) && return nothing
        @atomic :release transport.closed = true
        for (_, idle_list) in transport.idle
            append!(to_close, idle_list)
        end
        empty!(transport.idle)
        @atomic :release transport.idle_total = 0
        for (_, queue) in transport.waiters
            for waiter in queue
                _deliver_waiter_error_locked!(waiter, err) && push!(waiters_to_notify, waiter)
            end
        end
        empty!(transport.waiters)
    finally
        unlock(transport.lock)
    end
    _close_owned_conns!(transport, to_close)
    foreach(_notify_waiter!, waiters_to_notify)
    return nothing
end

"""
    idle_connection_count(transport; key=nothing)

Return idle pooled connection count globally or for one host key.

When `key === nothing`, returns the transport-wide count. Otherwise `key`
should match the transport's internal pool key such as `https://example.com:443`.
"""
function idle_connection_count(transport::Transport; key::Union{Nothing, AbstractString} = nothing)::Int
    lock(transport.lock)
    try
        if key === nothing
            return @atomic :acquire transport.idle_total
        end
        idle_list = get(() -> nothing, transport.idle, String(key))
        idle_list === nothing && return 0
        return length(idle_list::Vector{ClientConn})
    finally
        unlock(transport.lock)
    end
end

function Base.read(reader::_ConnReader{C}, ::Type{UInt8}) where {C}
    if _conn_reader_available(reader) > 0
        b = @inbounds reader.buf[reader.next]
        reader.next += 1
        return b
    end
    n = _fill_conn_reader!(reader)
    n == 0 && throw(EOFError())
    reader.next = 2
    return @inbounds reader.buf[1]
end

function Base.readbytes!(reader::_ConnReader{C}, dst::Vector{UInt8}, nb::Integer = length(dst)) where {C}
    target = min(Int(nb), length(dst))
    target <= 0 && return 0
    total = 0
    available = _conn_reader_available(reader)
    if available > 0
        copied = min(available, target)
        copyto!(dst, 1, reader.buf, reader.next, copied)
        reader.next += copied
        total = copied
        total == target && return total
    end
    while total < target
        n = _fill_conn_reader!(reader)
        n == 0 && break
        copied = min(n, target - total)
        copyto!(dst, total + 1, reader.buf, 1, copied)
        reader.next = copied + 1
        reader.stop = n
        total += copied
    end
    return total
end

@inline function _read_u8(reader::_ConnReader{C})::UInt8 where {C}
    if _conn_reader_available(reader) > 0
        b = @inbounds reader.buf[reader.next]
        reader.next += 1
        return b
    end
    n = _fill_conn_reader!(reader)
    n == 0 && throw(ParseError("unexpected EOF while reading HTTP/1 data"))
    reader.next = 2
    return @inbounds reader.buf[1]
end

function _readline_crlf(reader::_ConnReader{C}, max_line_bytes::Integer)::String where {C}
    max_line_bytes <= 0 && throw(ArgumentError("max_line_bytes must be > 0"))
    bytes = UInt8[]
    while true
        if _conn_reader_available(reader) == 0
            n = _fill_conn_reader!(reader)
            n > 0 || throw(ParseError("unexpected EOF while reading HTTP/1 data"))
        end
        start = reader.next
        stop = reader.stop
        nl_idx = 0
        @inbounds for i in start:stop
            if reader.buf[i] == 0x0a
                nl_idx = i
                break
            end
        end
        if nl_idx == 0
            segment_len = stop - start + 1
            length(bytes) + segment_len > max_line_bytes && throw(ProtocolError("HTTP/1 line exceeds configured max_line_bytes"))
            append!(bytes, @view(reader.buf[start:stop]))
            reader.next = stop + 1
            continue
        end
        segment_len = nl_idx - start + 1
        length(bytes) + segment_len > max_line_bytes && throw(ProtocolError("HTTP/1 line exceeds configured max_line_bytes"))
        append!(bytes, @view(reader.buf[start:nl_idx]))
        reader.next = nl_idx + 1
        nbytes = length(bytes)
        if nbytes >= 2 && bytes[nbytes - 1] == 0x0d && bytes[nbytes] == 0x0a
            resize!(bytes, nbytes - 2)
            return String(bytes)
        end
    end
end

@inline function _reset_request_buffer!(conn::ClientConn)::IOBuffer
    request_buf = conn.request_buf
    truncate(request_buf, 0)
    seekstart(request_buf)
    return request_buf
end

@inline function _response_reusable(response::_IncomingResponse, request::Request)::Bool
    response.head.close && return false
    request.close && return false
    headercontains(response.head.headers, "Connection", "close") && return false
    response.rawbody isa EOFBody && return false
    return true
end

@inline function _retryable_method(method::String)::Bool
    return method == "GET" || method == "HEAD" || method == "OPTIONS" || method == "TRACE"
end

@inline function _retryable_request(request::Request)::Bool
    _retryable_method(request.method) || return false
    request.content_length == 0 && return true
    request.body isa EmptyBody && return true
    request.body isa BytesBody && return true
    return false
end

@inline function _retryable_reused_conn_error(err)::Bool
    err isa EOFError && return true
    err isa SystemError && return true
    err isa ParseError && return true
    err isa IOPoll.NetClosingError && return true
    err isa IOPoll.NotPollableError && return true
    err isa IOPoll.DeadlineExceededError && return false
    return false
end

function _release_managed!(body::ManagedBody)
    was_released = @atomic :acquire body.released
    was_released && return nothing
    @atomic :release body.released = true
    if body.reusable
        _put_idle_conn!(body.transport, body.conn)
    else
        _close_owned_conn!(body.transport, body.conn)
    end
    return nothing
end

function body_closed(body::ManagedBody)::Bool
    return @atomic :acquire body.released
end

function body_close!(body::ManagedBody)
    if !(@atomic :acquire body.saw_eof)
        body.reusable = false
    end
    body_close!(body.inner)
    _release_managed!(body)
    return nothing
end

function body_read!(body::ManagedBody, dst::Vector{UInt8})::Int
    try
        n = body_read!(body.inner, dst)
        if n == 0
            @atomic :release body.saw_eof = true
            _release_managed!(body)
        end
        return n
    catch
        body.reusable = false
        _release_managed!(body)
        rethrow()
    end
end

"""
    roundtrip!(transport, address, request; secure=false, server_name=nothing)

Execute one HTTP/1 request/response exchange through `transport`.

This is the low-level HTTP/1 path used by the higher-level client APIs. It
returns a `Response`, potentially wrapping the body in `ManagedBody` so the
connection can be recycled when the caller finishes consuming it.

Throws parser, protocol, transport, TLS, and timeout exceptions depending on
where the exchange fails.
"""
function _roundtrip_incoming!(
        transport::Transport,
        address::AbstractString,
        request::Request;
        secure::Bool = false,
        server_name::Union{Nothing, AbstractString} = nothing,
        proxy_config::ProxyConfig = transport.proxy,
    )
    request_deadline = _request_deadline_ns(request)
    retry_template = _retryable_request(request) ? _copy_request(request) : nothing
    attempt = 1
    current_request = request
    while true
        plan = _proxy_plan(proxy_config, secure, String(address))
        conn = _acquire_conn!(
            transport,
            plan,
            String(address);
            secure = secure,
            server_name = server_name === nothing ? nothing : String(server_name),
            deadline_ns = request_deadline,
        )
        was_reused = conn.reused
        try
            _apply_conn_deadline!(conn, request_deadline)
            request_io = _reset_request_buffer!(conn)
            stream = _conn_stream(conn)
            try
                wire_target = plan.mode == _ProxyPlanMode.HTTP_FORWARD ? _request_url(false, String(address), current_request.target) : nothing
                proxy_auth = plan.mode == _ProxyPlanMode.HTTP_FORWARD && plan.proxy !== nothing ? (plan.proxy::_ProxyTarget).authorization : nothing
                _write_request_streaming!(request_io, stream, current_request; wire_target = wire_target, proxy_authorization = proxy_auth)
            finally
                try
                    body_close!(current_request.body)
                catch
                end
            end
            reader = conn.reader
            raw_response = _read_incoming_response(reader, current_request)
            # HTTP/1 informational responses are consumed internally so callers
            # observe the final non-1xx response, matching the behavior of Go's
            # client transport.
            while (raw_response.head.status_code >= 100 && raw_response.head.status_code < 200) && raw_response.head.status_code != 101
                try
                    body_close!(raw_response.rawbody)
                catch
                end
                raw_response = _read_incoming_response(reader, current_request)
            end
            reusable = _response_reusable(raw_response, current_request)
            if raw_response.rawbody isa EmptyBody
                if reusable
                    _put_idle_conn!(transport, conn)
                else
                    _close_owned_conn!(transport, conn)
                end
                return raw_response
            end
            managed = ManagedBody(raw_response.rawbody, transport, conn, reusable, false, false)
            return _IncomingResponse(
                raw_response.head,
                managed,
            )
        catch err
            _close_owned_conn!(transport, conn)
            if attempt == 1 && was_reused && retry_template !== nothing && _retryable_reused_conn_error(err)
                current_request = _copy_request(retry_template::Request)
                attempt = 2
                continue
            end
            rethrow(err)
        end
    end
end

function roundtrip!(
        transport::Transport,
        address::AbstractString,
        request::Request;
        secure::Bool = false,
        server_name::Union{Nothing, AbstractString} = nothing,
    )
    return _streaming_response(_roundtrip_incoming!(transport, address, request; secure = secure, server_name = server_name))
end

export Client
export ClientTrace
export Cookie
export CookieJar
export do!
export get!
export StatusError
export TooManyRedirectsError
export request
export get
export head
export post
export put
export patch
export delete
export options

"""
    ClientTrace(; ...)

Optional callback hooks for client request lifecycle events.

Each field may be `nothing` or a callback function. Callbacks are invoked
synchronously from the request path, so they should stay lightweight and may
throw to abort a request.
"""
struct ClientTrace
    on_get_conn::Union{Nothing, Function}
    on_got_conn::Union{Nothing, Function}
    on_wrote_request::Union{Nothing, Function}
    on_got_first_response_byte::Union{Nothing, Function}
end

"""
    Client(; ...)

High-level HTTP client with transport pooling, redirect policy, cookies, and
optional HTTP/2.

Keyword arguments:
- `transport`: lower-level HTTP/1 transport/pool implementation
- `check_redirect`: optional callback deciding whether a redirect should be
  followed
- `cookiejar`: cookie jar implementation, or `nothing` to disable cookies
- `max_redirects`: maximum redirect hops before failing
- `trace`: optional lifecycle callback bundle
- `prefer_http2`: whether secure requests should try HTTP/2 when available
"""
mutable struct Client
    transport::Transport
    check_redirect::Union{Nothing, Function}
    cookiejar::Union{Nothing, CookieJar}
    max_redirects::Int
    trace::Union{Nothing, ClientTrace}
    prefer_http2::Bool
    h2_lock::ReentrantLock
    h2_conns::Dict{String, H2Connection}
end

function ClientTrace(;
        on_get_conn::Union{Nothing, Function} = nothing,
        on_got_conn::Union{Nothing, Function} = nothing,
        on_wrote_request::Union{Nothing, Function} = nothing,
        on_got_first_response_byte::Union{Nothing, Function} = nothing,
    )
    return ClientTrace(on_get_conn, on_got_conn, on_wrote_request, on_got_first_response_byte)
end

function Client(;
        transport::Transport = Transport(proxy = ProxyFromEnvironment()),
        check_redirect::Union{Nothing, Function} = nothing,
        cookiejar::Union{Nothing, CookieJar} = CookieJar(),
        max_redirects::Integer = 10,
        trace::Union{Nothing, ClientTrace} = nothing,
        prefer_http2::Bool = true,
    )
    max_redirects >= 0 || throw(ArgumentError("max_redirects must be >= 0"))
    return Client(transport, check_redirect, cookiejar, Int(max_redirects), trace, prefer_http2, ReentrantLock(), Dict{String, H2Connection}())
end

struct _UseTransportProxy end

const _USE_TRANSPORT_PROXY = _UseTransportProxy()

struct _RedirectPolicy
    check_redirect::Union{Nothing, Function}
    max_redirects::Int
    redirect_method::Union{Nothing, String}
    preserve_method::Bool
    forward_headers::Bool
end

function _normalize_redirect_method_override(redirect_method)::Tuple{Union{Nothing, String}, Bool}
    redirect_method === nothing && return nothing, false
    redirect_method == :same && return nothing, true
    redirect_method isa AbstractString || redirect_method isa Symbol || throw(ArgumentError("redirect_method must be nothing, :same, or an HTTP method String/Symbol"))
    method = uppercase(String(redirect_method))
    method in ("GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH") || throw(ArgumentError("redirect_method must be one of GET, POST, PUT, DELETE, HEAD, OPTIONS, PATCH, or :same"))
    return method, false
end

function _redirect_policy(
        client::Client;
        redirect_limit::Union{Nothing, Integer} = nothing,
        redirect_method = nothing,
        forwardheaders::Bool = true,
    )::_RedirectPolicy
    max_redirects = redirect_limit === nothing ? client.max_redirects : Int(redirect_limit)
    max_redirects >= 0 || throw(ArgumentError("redirect_limit must be >= 0"))
    callback = client.check_redirect
    method_override, preserve_method = _normalize_redirect_method_override(redirect_method)
    return _RedirectPolicy(callback, max_redirects, method_override, preserve_method, forwardheaders)
end

function _proxy_config_for_request(client::Client, proxy)::ProxyConfig
    proxy === _USE_TRANSPORT_PROXY && return client.transport.proxy
    return _normalize_proxy_config(proxy)
end

function Base.close(client::Client)
    close(client.transport)
    lock(client.h2_lock)
    try
        for (_, conn) in client.h2_conns
            try
                close(conn)
            catch
            end
        end
        empty!(client.h2_conns)
    finally
        unlock(client.h2_lock)
    end
    return nothing
end

@inline function _h2_key(plan::_ProxyPlan)::String
    return string("h2|", plan.pool_key)
end

function _acquire_h2_conn!(
        client::Client,
        plan::_ProxyPlan,
        address::String,
        secure::Bool;
        server_name::Union{Nothing, String} = nothing,
    )::H2Connection
    key = _h2_key(plan)
    lock(client.h2_lock)
    try
        existing = get(() -> nothing, client.h2_conns, key)
        if existing !== nothing
            is_closed = @atomic :acquire (existing::H2Connection).closed
            if !is_closed
                return existing::H2Connection
            end
            delete!(client.h2_conns, key)
        end
        tls_cfg = if secure
            base_cfg = client.transport.tls_config
            if base_cfg === nothing
                TLS.Config(server_name = server_name)
            else
                TLS.Config(
                    server_name = server_name === nothing ? base_cfg.server_name : server_name,
                    verify_peer = base_cfg.verify_peer,
                    client_auth = base_cfg.client_auth,
                    cert_file = base_cfg.cert_file,
                    key_file = base_cfg.key_file,
                    ca_file = base_cfg.ca_file,
                    client_ca_file = base_cfg.client_ca_file,
                    alpn_protocols = copy(base_cfg.alpn_protocols),
                    handshake_timeout_ns = base_cfg.handshake_timeout_ns,
                    min_version = base_cfg.min_version,
                    max_version = base_cfg.max_version,
                )
            end
        else
            nothing
        end
        conn = if plan.mode == _ProxyPlanMode.DIRECT
            connect_h2!(
                address;
                secure = secure,
                host_resolver = client.transport.host_resolver,
                tls_config = tls_cfg,
            )
        elseif plan.mode == _ProxyPlanMode.HTTP_TUNNEL
            proxy = plan.proxy
            proxy === nothing && throw(ProtocolError("proxy CONNECT tunnel is missing proxy config"))
            tcp = TCP.connect(client.transport.host_resolver, "tcp", plan.first_hop_address)
            try
                _perform_http_connect_tunnel!(tcp, proxy::_ProxyTarget, address, Int64(0))
                connect_h2!(tcp, address; secure = secure, tls_config = tls_cfg)
            catch
                try
                    TCP.close!(tcp)
                catch
                end
                rethrow()
            end
        else
            throw(ArgumentError("HTTP/2 is not supported for proxy plan mode $(plan.mode)"))
        end
        client.h2_conns[key] = conn
        return conn
    finally
        unlock(client.h2_lock)
    end
end

@inline function _should_fallback_h2_to_h1(err)::Bool
    return err isa H2NegotiationError
end

function _drop_h2_conn!(client::Client, plan::_ProxyPlan)
    key = _h2_key(plan)
    lock(client.h2_lock)
    try
        conn = get(() -> nothing, client.h2_conns, key)
        if conn !== nothing
            delete!(client.h2_conns, key)
            try
                close(conn::H2Connection)
            catch
            end
        end
    finally
        unlock(client.h2_lock)
    end
    return nothing
end

function _use_h2(client::Client, secure::Bool, protocol::Symbol)::Bool
    protocol == :h1 && return false
    protocol == :h2 && return true
    protocol == :auto || throw(ArgumentError("protocol must be :auto, :h1, or :h2"))
    secure || return false
    return client.prefer_http2
end

function _host_path_from_request(address::String, request::Request)::Tuple{String, String}
    host, _ = HostResolvers.split_host_port(address)
    target = request.target
    if isempty(target)
        return host, "/"
    end
    startswith(target, "/") && return host, target
    return host, "/$target"
end

function _normalize_cookies_input(cookies)
    if cookies isa Bool
        return cookies
    end
    cookies isa AbstractDict || throw(ArgumentError("cookies must be true, false, or an AbstractDict of cookie name/value pairs"))
    normalized = Cookie[]
    for (name, value) in pairs(cookies)
        push!(normalized, Cookie(name, value))
    end
    return normalized
end

function _effective_cookiejar(client::Union{Nothing, Client}, cookiejar::Union{Nothing, CookieJar})::Union{Nothing, CookieJar}
    cookiejar !== nothing && return cookiejar
    client === nothing && return COOKIEJAR
    return (client::Client).cookiejar
end

function _cookie_header(
        cookiejar::Union{Nothing, CookieJar},
        cookies::Union{Bool, Vector{Cookie}},
        secure::Bool,
        host::String,
        path::String,
    )::Union{Nothing, String}
    cookies === false && return nothing
    merged = Cookie[]
    if cookiejar !== nothing
        scheme = secure ? "https" : "http"
        append!(merged, getcookies!(cookiejar, scheme, host, path))
    end
    if cookies !== true
        append!(merged, cookies::Vector{Cookie})
    end
    isempty(merged) && return nothing
    return stringify("", merged)
end

function _store_set_cookies!(
        cookiejar::Union{Nothing, CookieJar},
        cookies::Union{Bool, Vector{Cookie}},
        secure::Bool,
        host::String,
        path::String,
        headers::Headers,
    )
    cookies === false && return nothing
    cookiejar === nothing && return nothing
    scheme = secure ? "https" : "http"
    setcookies!(cookiejar::CookieJar, scheme, host, path, headers)
    return nothing
end

function _trace_call(trace::Union{Nothing, ClientTrace}, field::Symbol, args...)
    trace === nothing && return nothing
    callback = getfield(trace::ClientTrace, field)
    callback === nothing && return nothing
    callback(args...)
    return nothing
end

function _clone_bytes_body(body::BytesBody)::BytesBody
    remaining = (length(body.data) - body.next_index) + 1
    remaining <= 0 && return BytesBody(UInt8[])
    copied = Vector{UInt8}(undef, remaining)
    copyto!(copied, 1, body.data, body.next_index, remaining)
    return BytesBody(copied)
end

function _clone_body(body::AbstractBody)::AbstractBody
    body isa EmptyBody && return EmptyBody()
    body isa BytesBody && return _clone_bytes_body(body::BytesBody)
    throw(ProtocolError("request body is not replayable for redirect"))
end

function _copy_request(request::Request)
    return _request_nocopy(
        request.method,
        request.target,
        copy(request.headers),
        copy(request.trailers),
        _clone_body(request.body),
        request.host,
        request.content_length,
        request.proto_major,
        request.proto_minor,
        request.close,
        request.context,
    )
end

function _copy_request_shallow_body(request::Request)
    return _request_nocopy(
        request.method,
        request.target,
        copy(request.headers),
        copy(request.trailers),
        request.body,
        request.host,
        request.content_length,
        request.proto_major,
        request.proto_minor,
        request.close,
        request.context,
    )
end

@inline function _is_nonreplayable_body_error(err)::Bool
    err isa ProtocolError || return false
    return occursin("request body is not replayable for redirect", (err::ProtocolError).message)
end

function _copy_request_for_send(request::Request; allow_nonreplayable::Bool = false)::Request
    if allow_nonreplayable
        try
            return _copy_request(request)
        catch err
            _is_nonreplayable_body_error(err) || rethrow(err)
            return _copy_request_shallow_body(request)
        end
    end
    return _copy_request(request)
end

function _is_redirect_status(status_code::Int)::Bool
    return status_code == 301 || status_code == 302 || status_code == 303 || status_code == 307 || status_code == 308
end

function _split_request_target(target::String)::Tuple{String, String}
    current = isempty(target) ? "/" : target
    hash_idx = findfirst('#', current)
    hash_idx === nothing || (current = String(SubString(current, firstindex(current), prevind(current, hash_idx))))
    query_idx = findfirst('?', current)
    if query_idx === nothing
        return isempty(current) ? "/" : current, ""
    end
    path = query_idx == firstindex(current) ? "/" : String(SubString(current, firstindex(current), prevind(current, query_idx)))
    query = query_idx == lastindex(current) ? "" : String(SubString(current, nextind(current, query_idx), lastindex(current)))
    return isempty(path) ? "/" : path, query
end

function _join_request_target(path::String, query::String)::String
    final_path = isempty(path) ? "/" : path
    isempty(query) && return final_path
    return string(final_path, "?", query)
end

function _merge_redirect_base_path(base_path::String, relative_path::String)::String
    isempty(relative_path) && return base_path
    slash = findlast('/', base_path)
    slash === nothing && return "/" * relative_path
    return string(SubString(base_path, firstindex(base_path), slash), relative_path)
end

function _remove_dot_segments(path::String)::String
    absolute = startswith(path, "/")
    trailing_slash = endswith(path, "/") || endswith(path, "/.") || endswith(path, "/..")
    segments = split(path, '/'; keepempty = false)
    stack = String[]
    for segment in segments
        if segment == "."
            continue
        elseif segment == ".."
            isempty(stack) || pop!(stack)
        else
            push!(stack, segment)
        end
    end
    normalized = absolute ? "/" : ""
    normalized *= join(stack, "/")
    isempty(normalized) && return absolute ? "/" : "."
    if trailing_slash && normalized != "/"
        normalized *= "/"
    end
    return normalized
end

function _resolve_relative_redirect_request_target(current_target::String, location::String)::String
    base_path, base_query = _split_request_target(current_target)
    startswith(location, "#") && return _join_request_target(base_path, base_query)
    startswith(location, "?") && return _join_request_target(base_path, String(SubString(location, nextind(location, firstindex(location)), lastindex(location))))
    reference = location
    hash_idx = findfirst('#', reference)
    hash_idx === nothing || (reference = String(SubString(reference, firstindex(reference), prevind(reference, hash_idx))))
    query = ""
    query_idx = findfirst('?', reference)
    if query_idx !== nothing
        query = query_idx == lastindex(reference) ? "" : String(SubString(reference, nextind(reference, query_idx), lastindex(reference)))
        reference = query_idx == firstindex(reference) ? "" : String(SubString(reference, firstindex(reference), prevind(reference, query_idx)))
    end
    if isempty(reference)
        return _join_request_target(base_path, query_idx === nothing ? base_query : query)
    end
    path = if startswith(reference, "/")
        _remove_dot_segments(reference)
    else
        _remove_dot_segments(_merge_redirect_base_path(base_path, reference))
    end
    return _join_request_target(path, query)
end

@inline function _normalize_redirect_host(host::String)::String
    normalized = lowercase(host)
    while !isempty(normalized) && last(normalized) == '.'
        normalized = normalized[1:prevind(normalized, lastindex(normalized))]
    end
    return normalized
end

function _is_domain_or_subdomain(sub::String, parent::String)::Bool
    sub == parent && return true
    (occursin(':', sub) || occursin('%', sub)) && return false
    return endswith(sub, "." * parent)
end

function _should_copy_sensitive_headers_on_redirect(initial_address::String, redirect_address::String)::Bool
    initial_host = try
        HostResolvers.split_host_port(initial_address)[1]
    catch
        initial_address
    end
    redirect_host = try
        HostResolvers.split_host_port(redirect_address)[1]
    catch
        redirect_address
    end
    initial_norm = _normalize_redirect_host(initial_host)
    redirect_norm = _normalize_redirect_host(redirect_host)
    isempty(initial_norm) && return false
    isempty(redirect_norm) && return false
    return _is_domain_or_subdomain(redirect_norm, initial_norm)
end

function _strip_sensitive_redirect_headers!(headers::Headers)
    removeheader(headers, "Authorization")
    removeheader(headers, "Www-Authenticate")
    removeheader(headers, "Cookie")
    removeheader(headers, "Cookie2")
    removeheader(headers, "Proxy-Authorization")
    removeheader(headers, "Proxy-Authenticate")
    return nothing
end

function _normalize_redirect_authority(authority::String, secure::Bool)::String
    at_idx = findlast('@', authority)
    if at_idx !== nothing
        authority = String(SubString(authority, nextind(authority, at_idx), lastindex(authority)))
    end
    isempty(authority) && throw(ProtocolError("redirect location is missing host"))
    if startswith(authority, "[")
        if occursin("]:", authority)
            return authority
        end
        close_idx = findfirst(']', authority)
        close_idx === nothing && throw(ProtocolError("invalid IPv6 host authority in redirect location: $authority"))
        host = String(SubString(authority, nextind(authority, firstindex(authority)), prevind(authority, close_idx)))
        return HostResolvers.join_host_port(host, secure ? 443 : 80)
    end
    colon_count = count(==(':'), authority)
    if colon_count == 0
        return HostResolvers.join_host_port(authority, secure ? 443 : 80)
    end
    if colon_count == 1
        return authority
    end
    return HostResolvers.join_host_port(authority, secure ? 443 : 80)
end

function _resolve_redirect_target(current_address::String, current_secure::Bool, location::String, current_target::String)
    scheme_match = match(r"^([A-Za-z][A-Za-z0-9+\\.-]*):", location)
    if scheme_match !== nothing
        scheme = lowercase(String(scheme_match.captures[1]))
        (scheme == "http" || scheme == "https") || throw(ProtocolError("unsupported redirect location scheme '$scheme'"))
        parsed = _parse_http_url(location)
        return parsed.address, parsed.secure, parsed.target
    end
    if startswith(location, "//")
        parsed = _parse_http_url(string(current_secure ? "https:" : "http:", location))
        return parsed.address, parsed.secure, parsed.target
    end
    return current_address, current_secure, _resolve_relative_redirect_request_target(current_target, location)
end

function _rewrite_method_for_redirect(method::String, status_code::Int, policy::_RedirectPolicy)::String
    if status_code == 307 || status_code == 308
        return method
    end
    if status_code == 303
        return "GET"
    end
    if policy.preserve_method
        return method
    end
    if policy.redirect_method !== nothing
        return policy.redirect_method::String
    end
    method == "HEAD" && return method
    return "GET"
end

@inline function _redirect_body_replayable(request::Request)::Bool
    request.content_length == 0 && return true
    request.body isa EmptyBody && return true
    request.body isa BytesBody && return true
    return false
end

@inline function _redirect_reuses_request_body(method::String)::Bool
    return !(method == "GET" || method == "HEAD")
end

function _redirect_referer(
        last_secure::Bool,
        last_address::String,
        last_target::String,
        new_secure::Bool,
        explicit_ref::Union{Nothing, String},
    )::Union{Nothing, String}
    if last_secure && !new_secure
        return nothing
    end
    if explicit_ref !== nothing && !isempty(explicit_ref::String)
        return explicit_ref::String
    end
    target = isempty(last_target) ? "/" : last_target
    startswith(target, "/") || (target = "/" * target)
    return string(last_secure ? "https://" : "http://", last_address, target)
end

function _prepare_request_for_redirect(request::Request, status_code::Int, new_target::String, policy::_RedirectPolicy)::Request
    method = _rewrite_method_for_redirect(request.method, status_code, policy)
    if method == request.method
        copied = _copy_request(request)
        copied.target = new_target
        if !policy.forward_headers
            copied.headers = Headers()
            copied.trailers = Headers()
        end
        removeheader(copied.headers, "Host")
        return copied
    end
    redirected = if _redirect_reuses_request_body(method)
        copied = _copy_request(request)
        copied.method = method
        copied.target = new_target
        if !policy.forward_headers
            copied.headers = Headers()
            copied.trailers = Headers()
        end
        copied
    else
        _request_nocopy(
            method,
            new_target,
            policy.forward_headers ? copy(request.headers) : Headers(),
            Headers(),
            EmptyBody(),
            request.host,
            Int64(0),
            request.proto_major,
            request.proto_minor,
            request.close,
            request.context,
        )
    end
    removeheader(redirected.headers, "Host")
    if !_redirect_reuses_request_body(method)
        # Per Go/HTTP behavior: when method is rewritten to GET/HEAD, entity headers
        # tied to an old request body must be removed.
        removeheader(redirected.headers, "Content-Length")
        removeheader(redirected.headers, "Transfer-Encoding")
        removeheader(redirected.headers, "Content-Type")
        removeheader(redirected.headers, "Content-Encoding")
        removeheader(redirected.headers, "Content-Language")
        removeheader(redirected.headers, "Content-Location")
    end
    return redirected
end

"""
    do!(client, address, request; secure=false, server_name=nothing, protocol=:auto)

Send `request` with redirect handling and return the final low-level `Response`.

This method preserves streaming bodies, so callers are responsible for draining
or closing `response.body`.

`protocol` accepts `:auto`, `:h1`, or `:h2`. In `:auto` mode the client may try
HTTP/2 first for secure requests and fall back to HTTP/1 when negotiation says
that h2 is unavailable.

Per-call redirect behavior can be overridden with `redirect_limit`,
`redirect_method`, and `forwardheaders`.
"""
function _do_incoming!(
        client::Client,
        address::AbstractString,
        request::Request;
        secure::Bool = false,
        server_name::Union{Nothing, AbstractString} = nothing,
        protocol::Symbol = :auto,
        redirect_policy::_RedirectPolicy = _redirect_policy(client),
        retry_controller = nothing,
        proxy_config::ProxyConfig = client.transport.proxy,
        cookies::Union{Bool, Vector{Cookie}} = true,
        cookiejar::Union{Nothing, CookieJar} = client.cookiejar,
    )
    current_address = String(address)
    initial_address = current_address
    current_secure = secure
    explicit_server_name = server_name !== nothing
    current_server_name = explicit_server_name ? String(server_name::AbstractString) : _host_for_sni(current_address)
    current_request = _copy_request_shallow_body(request)
    controller = retry_controller
    previous_response = nothing
    retry_attempt = 1
    retry_token = nothing
    for redirect_count in 0:redirect_policy.max_redirects
        while true
            send_request = _copy_request_for_send(current_request; allow_nonreplayable = retry_attempt == 1)
            proxy_plan = _proxy_plan(proxy_config, current_secure, current_address)
            host, path = _host_path_from_request(current_address, current_request)
            cookie_value = _cookie_header(cookiejar, cookies, current_secure, host, path)
            cookie_value === nothing || setheader(send_request.headers, "Cookie", cookie_value)
            _trace_call(client.trace, :on_get_conn, current_address, current_secure)
            response = try
                if _use_h2(client, current_secure, protocol) && proxy_plan.mode != _ProxyPlanMode.HTTP_FORWARD
                    try
                        conn = _acquire_h2_conn!(client, proxy_plan, current_address, current_secure; server_name = current_server_name)
                        _h2_roundtrip_incoming!(conn, send_request)
                    catch err
                        _drop_h2_conn!(client, proxy_plan)
                        if protocol == :auto && _should_fallback_h2_to_h1(err)
                            _roundtrip_incoming!(
                                client.transport,
                                current_address,
                                send_request;
                                secure = current_secure,
                                server_name = current_server_name,
                                proxy_config = proxy_config,
                            )
                        else
                            rethrow(err)
                        end
                    end
                else
                    _roundtrip_incoming!(
                        client.transport,
                        current_address,
                        send_request;
                        secure = current_secure,
                        server_name = current_server_name,
                        proxy_config = proxy_config,
                    )
                end
            catch err
                if controller !== nothing
                    ctrl = controller::_RetryController
                    _release_retry_token!(ctrl, retry_token, err)
                end
                retry_token = nothing
                if controller !== nothing
                    ctrl = controller::_RetryController
                    if _should_retry_request_attempt(ctrl, retry_attempt, current_request, err, nothing)
                        scheduled, next_token = _arm_request_retry!(ctrl, current_address, current_request, retry_attempt, nothing)
                        if scheduled
                            retry_attempt += 1
                            retry_token = next_token
                            continue
                        end
                    end
                end
                rethrow(err)
            end
            response = _annotate_incoming_response(
                response,
                _request_url(current_secure, current_address, current_request.target),
                previous_response,
                redirect_count,
            )
            _trace_call(client.trace, :on_got_conn, current_address, current_secure)
            _trace_call(client.trace, :on_wrote_request, send_request.method, send_request.target)
            _trace_call(client.trace, :on_got_first_response_byte, response.head.status_code)
            _store_set_cookies!(cookiejar, cookies, current_secure, host, path, response.head.headers)
            status_response = _retry_policy_response(response, current_request)
            if controller !== nothing
                ctrl = controller::_RetryController
                if _retryable_status_code(status_response.status_code)
                    _release_retry_token!(ctrl, retry_token, status_response)
                else
                    _release_retry_token!(ctrl, retry_token)
                end
            end
            retry_token = nothing
            if controller !== nothing
                ctrl = controller::_RetryController
                should_retry = try
                    _should_retry_request_attempt(ctrl, retry_attempt, current_request, nothing, status_response)
                catch
                    try
                        body_close!(response.rawbody)
                    catch
                    end
                    rethrow()
                end
                if should_retry
                    scheduled, next_token = _arm_request_retry!(ctrl, current_address, current_request, retry_attempt, status_response)
                    if scheduled
                        retry_attempt += 1
                        retry_token = next_token
                        try
                            body_close!(response.rawbody)
                        catch
                        end
                        continue
                    end
                end
            end
            if !_is_redirect_status(response.head.status_code)
                return response
            end
            location = header(response.head.headers, "Location", nothing)
            (location === nothing || isempty(location::String)) && return response
            redirect_policy.max_redirects == 0 && return response
            redirect_count == redirect_policy.max_redirects && throw(TooManyRedirectsError(redirect_policy.max_redirects, _streaming_response(response)))
            if redirect_policy.check_redirect !== nothing
                proceed = (redirect_policy.check_redirect::Function)(_streaming_response(response), current_request, location)
                proceed isa Bool || throw(ProtocolError("check_redirect callback must return Bool"))
                proceed || return response
            end
            next_method = _rewrite_method_for_redirect(current_request.method, response.head.status_code, redirect_policy)
            if _redirect_reuses_request_body(next_method) && !_redirect_body_replayable(current_request)
                return response
            end
            previous_response = _streaming_response(response)
            body_close!(response.rawbody)
            previous_secure = current_secure
            previous_address = current_address
            previous_target = current_request.target
            current_address, current_secure, next_target = _resolve_redirect_target(current_address, current_secure, location, current_request.target)
            if !explicit_server_name
                current_server_name = _host_for_sni(current_address)
            end
            current_request = _prepare_request_for_redirect(current_request, response.head.status_code, next_target, redirect_policy)
            existing_ref = header(current_request.headers, "Referer", nothing)
            next_ref = _redirect_referer(previous_secure, previous_address, previous_target, current_secure, existing_ref)
            if next_ref === nothing
                removeheader(current_request.headers, "Referer")
            else
                setheader(current_request.headers, "Referer", next_ref::String)
            end
            if !_should_copy_sensitive_headers_on_redirect(initial_address, current_address)
                _strip_sensitive_redirect_headers!(current_request.headers)
            end
            current_request.host = current_address
            break
        end
    end
    throw(ProtocolError("unexpected redirect loop termination"))
end

function do!(
        client::Client,
        address::AbstractString,
        request::Request;
        secure::Bool = false,
        server_name::Union{Nothing, AbstractString} = nothing,
        protocol::Symbol = :auto,
        proxy = _USE_TRANSPORT_PROXY,
        redirect_limit::Union{Nothing, Integer} = nothing,
        redirect_method = nothing,
        forwardheaders::Bool = true,
        cookies = true,
        cookiejar::Union{Nothing, CookieJar} = nothing,
    )
    normalized_cookies = _normalize_cookies_input(cookies)
    policy = _redirect_policy(
        client;
        redirect_limit = redirect_limit,
        redirect_method = redirect_method,
        forwardheaders = forwardheaders,
    )
    proxy_config = _proxy_config_for_request(client, proxy)
    effective_cookiejar = _effective_cookiejar(client, cookiejar)
    return _streaming_response(_do_incoming!(
        client,
        address,
        request;
        secure = secure,
        server_name = server_name,
        protocol = protocol,
        redirect_policy = policy,
        proxy_config = proxy_config,
        cookies = normalized_cookies,
        cookiejar = effective_cookiejar,
    ))
end

"""
    get!(client, address, target; secure=false, protocol=:auto)

Convenience GET request using an existing `Client`.

Returns the same low-level `Response` shape as `do!`.
"""
function get!(client::Client, address::AbstractString, target::AbstractString; secure::Bool = false, protocol::Symbol = :auto, kwargs...)
    request = Request("GET", target; host = String(address), body = EmptyBody(), content_length = 0)
    return do!(client, address, request; secure = secure, protocol = protocol, kwargs...)
end

import Base: get

"""
    StatusError

Raised when `status_exception=true` and the response status indicates failure.
"""
struct StatusError <: Exception
    response::Response
end

function Base.showerror(io::IO, err::StatusError)
    resp = err.response
    print(io, "http status error: ", resp.status, " for ", resp.request.method, " ", resp.url)
    return nothing
end

"""
    TooManyRedirectsError

Raised when redirect following is enabled and the client exceeds the configured
redirect limit. The final redirect response is attached for inspection.
"""
struct TooManyRedirectsError <: Exception
    limit::Int
    response::Response
end

function Base.showerror(io::IO, err::TooManyRedirectsError)
    resp = err.response
    print(io, "http too many redirects after ", err.limit, " hops for ", resp.request.method, " ", resp.url)
    return nothing
end

struct _TextRange
    first::Int
    last::Int
end

const _EMPTY_TEXT_RANGE = _TextRange(0, 0)

@inline function _text_range(lo::Int, hi::Int)::_TextRange
    return lo <= hi ? _TextRange(lo, hi) : _EMPTY_TEXT_RANGE
end

@inline function _text_range_empty(r::_TextRange)::Bool
    return r.first == 0
end

@inline function _text_range_string(source::String, r::_TextRange)::String
    _text_range_empty(r) && return ""
    return String(SubString(source, r.first, r.last))
end

@inline function _find_url_byte(
        bytes::Base.CodeUnits{UInt8, String},
        lo::Int,
        hi::Int,
        byte::UInt8,
    )::Union{Nothing, Int}
    lo > hi && return nothing
    @inbounds for i in lo:hi
        bytes[i] == byte && return i
    end
    return nothing
end

@inline function _find_last_url_byte(
        bytes::Base.CodeUnits{UInt8, String},
        lo::Int,
        hi::Int,
        byte::UInt8,
    )::Union{Nothing, Int}
    lo > hi && return nothing
    @inbounds for i in hi:-1:lo
        bytes[i] == byte && return i
    end
    return nothing
end

@inline function _find_first_url_sep(
        bytes::Base.CodeUnits{UInt8, String},
        lo::Int,
        hi::Int,
    )::Union{Nothing, Int}
    lo > hi && return nothing
    @inbounds for i in lo:hi
        b = bytes[i]
        (b == UInt8('/') || b == UInt8('?')) && return i
    end
    return nothing
end

@inline function _ascii_equal_fold_literal(
        bytes::Base.CodeUnits{UInt8, String},
        lo::Int,
        hi::Int,
        literal::String,
    )::Bool
    n = hi >= lo ? (hi - lo + 1) : 0
    n == ncodeunits(literal) || return false
    @inbounds for j in 1:n
        _to_ascii_lower(bytes[lo + j - 1]) == _to_ascii_lower(codeunit(literal, j)) || return false
    end
    return true
end

mutable struct _URLParts
    source::String
    secure::Bool
    default_port::UInt16
    authority_range::_TextRange
    host_range::_TextRange
    userinfo_range::_TextRange
    target_range::_TextRange
    query_suffix::String
    has_explicit_port::Bool
    target_starts_with_query::Bool
    has_userinfo::Bool
    address_cache::String
    target_cache::String
    server_name_cache::String
    url_cache::String
    authorization_cache::String
end

function _urlparts_address!(parts::_URLParts)::String
    cached = getfield(parts, :address_cache)
    isempty(cached) || return cached
    source = getfield(parts, :source)
    address = if getfield(parts, :has_explicit_port)
        _text_range_string(source, getfield(parts, :authority_range))
    else
        host = _text_range_string(source, getfield(parts, :host_range))
        HostResolvers.join_host_port(host, Int(getfield(parts, :default_port)))
    end
    setfield!(parts, :address_cache, address)
    return address
end

function _urlparts_target!(parts::_URLParts)::String
    cached = getfield(parts, :target_cache)
    isempty(cached) || return cached
    source = getfield(parts, :source)
    query_suffix = getfield(parts, :query_suffix)
    target_range = getfield(parts, :target_range)
    target = if _text_range_empty(target_range)
        isempty(query_suffix) ? "/" : string("/?", query_suffix)
    else
        base = if getfield(parts, :target_starts_with_query)
            string("/", SubString(source, target_range.first, target_range.last))
        else
            String(SubString(source, target_range.first, target_range.last))
        end
        isempty(query_suffix) ? base : _append_query(base, query_suffix)
    end
    setfield!(parts, :target_cache, target)
    return target
end

function _urlparts_server_name!(parts::_URLParts)::String
    cached = getfield(parts, :server_name_cache)
    isempty(cached) || return cached
    source = getfield(parts, :source)
    server_name = if getfield(parts, :has_explicit_port)
        host, _ = HostResolvers.split_host_port(_urlparts_address!(parts))
        host
    else
        _text_range_string(source, getfield(parts, :host_range))
    end
    setfield!(parts, :server_name_cache, server_name)
    return server_name
end

function _urlparts_url!(parts::_URLParts)::String
    cached = getfield(parts, :url_cache)
    isempty(cached) || return cached
    url = _request_url(getfield(parts, :secure), _urlparts_address!(parts), _urlparts_target!(parts))
    setfield!(parts, :url_cache, url)
    return url
end

function _urlparts_authorization!(parts::_URLParts)::Union{Nothing, String}
    getfield(parts, :has_userinfo) || return nothing
    cached = getfield(parts, :authorization_cache)
    isempty(cached) || return cached
    userinfo = _text_range_string(getfield(parts, :source), getfield(parts, :userinfo_range))
    parts_split = split(userinfo, ':'; limit = 2)
    username = parts_split[1]
    password = length(parts_split) == 2 ? parts_split[2] : ""
    authorization = "Basic " * base64encode(string(username, ":", password))
    setfield!(parts, :authorization_cache, authorization)
    return authorization
end

function Base.getproperty(parts::_URLParts, sym::Symbol)
    if sym === :secure
        return getfield(parts, :secure)
    elseif sym === :address
        return _urlparts_address!(parts)
    elseif sym === :target
        return _urlparts_target!(parts)
    elseif sym === :server_name
        return _urlparts_server_name!(parts)
    elseif sym === :url
        return _urlparts_url!(parts)
    elseif sym === :authorization
        return _urlparts_authorization!(parts)
    end
    return getfield(parts, sym)
end

function Base.propertynames(::_URLParts, private::Bool = false)
    return private ? fieldnames(_URLParts) : (:secure, :address, :target, :server_name, :url, :authorization)
end

@inline function _request_url(secure::Bool, address::String, target::String)::String
    return string(secure ? "https://" : "http://", address, target)
end

function _annotate_incoming_response(
        incoming::_IncomingResponse{B},
        request_url::String,
        previous::Union{Nothing, Response},
        redirect_count::Int,
    )::_IncomingResponse{B} where {B <: AbstractBody}
    head = incoming.head
    return _IncomingResponse(
        _IncomingResponseHead(
            head.status_code,
            head.reason,
            head.headers,
            head.trailers,
            head.content_length,
            head.proto_major,
            head.proto_minor,
            head.close,
            head.request,
            request_url,
            previous,
            redirect_count,
        ),
        incoming.rawbody,
    )
end

const _DEFAULT_CLIENT_LOCK = ReentrantLock()
const _DEFAULT_CLIENT = Ref{Union{Nothing, Client}}(nothing)
const COOKIEJAR = CookieJar()

function _default_client!()::Client
    lock(_DEFAULT_CLIENT_LOCK)
    try
        existing = _DEFAULT_CLIENT[]
        existing === nothing || return existing::Client
        created = Client()
        _DEFAULT_CLIENT[] = created
        return created
    finally
        unlock(_DEFAULT_CLIENT_LOCK)
    end
end

function _status_throws(resp::Response)::Bool
    return resp.status_code >= 300 && !_is_redirect_status(resp.status_code)
end

function _read_all_response_bytes(io::IO)::Vector{UInt8}
    out = UInt8[]
    buf = Vector{UInt8}(undef, 8192)
    while true
        n = readbytes!(io, buf, length(buf))
        n == 0 && return out
        append!(out, @view(buf[1:n]))
    end
end

const _MAX_EAGER_RESPONSE_PREALLOC = Int64(1 << 20)

function _read_all_response_bytes(body::AbstractBody; content_length_hint::Int64 = Int64(-1))::Vector{UInt8}
    if 0 <= content_length_hint <= _MAX_EAGER_RESPONSE_PREALLOC
        out = Vector{UInt8}(undef, Int(content_length_hint))
        n = _copy_response_bytes!(out, body)
        n == content_length_hint || resize!(out, Int(n))
        return out
    end
    out = UInt8[]
    content_length_hint > 0 && sizehint!(out, Int(min(content_length_hint, _MAX_EAGER_RESPONSE_PREALLOC)))
    buf = Vector{UInt8}(undef, 8192)
    while true
        n = body_read!(body, buf)
        n == 0 && return out
        append!(out, @view(buf[1:n]))
    end
end

function _copy_response_bytes!(dest::IO, io::IO)::Int64
    buf = Vector{UInt8}(undef, 8192)
    total = Int64(0)
    while true
        n = readbytes!(io, buf, length(buf))
        n == 0 && return total
        total += n
        write(dest, view(buf, 1:n))
    end
end

function _copy_response_bytes!(dest::AbstractVector{UInt8}, io::IO)::Int64
    buf = Vector{UInt8}(undef, 8192)
    total = 0
    capacity = length(dest)
    while true
        n = readbytes!(io, buf, length(buf))
        n == 0 && break
        needed = total + n
        needed <= capacity || throw(ArgumentError("Unable to grow response stream IOBuffer $(capacity) large enough for response body size: $(needed)"))
        copyto!(dest, total + 1, buf, 1, n)
        total = needed
    end
    dest isa Vector{UInt8} && resize!(dest::Vector{UInt8}, total)
    return Int64(total)
end

function _copy_response_bytes!(dest::IO, body::AbstractBody)::Int64
    buf = Vector{UInt8}(undef, 8192)
    total = Int64(0)
    while true
        n = body_read!(body, buf)
        n == 0 && return total
        total += n
        write(dest, view(buf, 1:n))
    end
end

function _copy_response_bytes!(dest::AbstractVector{UInt8}, body::AbstractBody)::Int64
    buf = Vector{UInt8}(undef, 8192)
    total = 0
    capacity = length(dest)
    while true
        n = body_read!(body, buf)
        n == 0 && break
        needed = total + n
        needed <= capacity || throw(ArgumentError("Unable to grow response stream IOBuffer $(capacity) large enough for response body size: $(needed)"))
        copyto!(dest, total + 1, buf, 1, n)
        total = needed
    end
    dest isa Vector{UInt8} && resize!(dest::Vector{UInt8}, total)
    return Int64(total)
end

function _should_decompress_response(headers::Headers, decompress::Union{Nothing, Bool})::Bool
    decompress === false && return false
    encoding = header(headers, "Content-Encoding", nothing)
    encoding === nothing && return false
    normalized = lowercase(strip(encoding))
    return normalized == "gzip" || normalized == "x-gzip"
end

@inline function _closed_bufferstream_error(err)::Bool
    return err isa Base.IOError && occursin("stream is closed or unusable", sprint(showerror, err))
end

function _pump_response_body!(stream::Base.BufferStream, body::AbstractBody)::Nothing
    buf = Vector{UInt8}(undef, 8192)
    try
        while true
            n = body_read!(body, buf)
            n == 0 && break
            try
                write(stream, view(buf, 1:n))
            catch err
                _closed_bufferstream_error(err) && break
                rethrow()
            end
        end
    finally
        try
            body_close!(body)
        catch
        end
        try
            close(stream)
        catch
        end
    end
    return nothing
end

mutable struct _BodyIO{B <: AbstractBody} <: IO
    body::B
    buf::Vector{UInt8}
    next_index::Int
    filled::Int
    @atomic saw_eof::Bool
    @atomic closed::Bool
end

function _BodyIO(body::B; buffer_bytes::Integer = 8192) where {B <: AbstractBody}
    n = Int(buffer_bytes)
    n > 0 || throw(ArgumentError("buffer_bytes must be > 0"))
    return _BodyIO{B}(body, Vector{UInt8}(undef, n), 1, 0, false, false)
end

@inline function _buffered_bytes(io::_BodyIO)::Int
    return max(io.filled - io.next_index + 1, 0)
end

function _fill_bodyio!(io::_BodyIO)::Int
    (@atomic :acquire io.closed) && return 0
    (@atomic :acquire io.saw_eof) && return 0
    io.next_index = 1
    n = body_read!(io.body, io.buf)
    io.filled = n
    if n == 0
        @atomic :release io.saw_eof = true
    end
    return n
end

function Base.isopen(io::_BodyIO)::Bool
    return !(@atomic :acquire io.closed)
end

function Base.bytesavailable(io::_BodyIO)::Int
    return _buffered_bytes(io)
end

function Base.eof(io::_BodyIO)::Bool
    _buffered_bytes(io) > 0 && return false
    (@atomic :acquire io.closed) && return true
    (@atomic :acquire io.saw_eof) && return true
    return _fill_bodyio!(io) == 0
end

function Base.read(io::_BodyIO, ::Type{UInt8})::UInt8
    eof(io) && throw(EOFError())
    b = io.buf[io.next_index]
    io.next_index += 1
    return b
end

function Base.readbytes!(io::_BodyIO, dst::Vector{UInt8}, nb::Integer = length(dst))::Int
    target = Int(nb)
    target < 0 && throw(ArgumentError("nb must be >= 0"))
    target = min(target, length(dst))
    total = 0
    while total < target
        available = _buffered_bytes(io)
        if available == 0
            _fill_bodyio!(io) == 0 && break
            available = _buffered_bytes(io)
        end
        chunk = min(available, target - total)
        copyto!(dst, total + 1, io.buf, io.next_index, chunk)
        io.next_index += chunk
        total += chunk
    end
    return total
end

function Base.unsafe_read(io::_BodyIO, ptr::Ptr{UInt8}, nbytes::UInt)
    remaining = Int(nbytes)
    offset = 0
    buf = io.buf
    while remaining > 0
        available = _buffered_bytes(io)
        if available == 0
            _fill_bodyio!(io) == 0 && throw(EOFError())
            available = _buffered_bytes(io)
        end
        chunk = min(available, remaining)
        GC.@preserve buf begin
            unsafe_copyto!(ptr + offset, pointer(buf, io.next_index), chunk)
        end
        io.next_index += chunk
        offset += chunk
        remaining -= chunk
    end
    return nothing
end

function Base.close(io::_BodyIO)
    if !(@atomic :acquire io.closed)
        @atomic :release io.closed = true
        @atomic :release io.saw_eof = true
        io.next_index = 1
        io.filled = 0
        body_close!(io.body)
    end
    return nothing
end

function _response_body_reader(incoming::_IncomingResponse; decompress::Union{Nothing, Bool})::Tuple{IO, Union{Nothing, Task}}
    raw_stream = _BodyIO(incoming.rawbody)
    if _should_decompress_response(incoming.head.headers, decompress)
        return CodecZlib.GzipDecompressorStream(raw_stream), nothing
    end
    return raw_stream, nothing
end

function _with_response_reader(f::F, incoming::_IncomingResponse; decompress::Union{Nothing, Bool}) where {F}
    reader, _ = _response_body_reader(incoming; decompress = decompress)
    try
        return f(reader)
    finally
        try
            close(reader)
        catch
        end
    end
end

function _resolve_response_sink(response_stream, response_body)
    if response_stream !== nothing && response_body !== response_stream
        throw(ArgumentError("response_stream and response_body must reference the same sink"))
    end
    if response_body === nothing || response_body isa IO || response_body isa AbstractVector{UInt8}
        return response_body
    end
    throw(ArgumentError("unsupported response body sink $(typeof(response_body)); expected nothing, IO, or AbstractVector{UInt8}"))
end

function _consume_incoming_response!(
        incoming::_IncomingResponse,
        sink;
        decompress::Union{Nothing, Bool},
    )::Tuple{Any, Int64}
    if !_should_decompress_response(incoming.head.headers, decompress)
        try
            if sink === nothing
                body = _read_all_response_bytes(incoming.rawbody; content_length_hint = incoming.head.content_length)
                return body, Int64(length(body))
            end
            if sink isa IO
                n = _copy_response_bytes!(sink::IO, incoming.rawbody)
                return nothing, n
            end
            n = _copy_response_bytes!(sink::AbstractVector{UInt8}, incoming.rawbody)
            if sink isa Vector{UInt8}
                return sink::Vector{UInt8}, n
            end
            return view(sink::AbstractVector{UInt8}, 1:Int(n)), n
        catch
            try
                body_close!(incoming.rawbody)
            catch
            end
            rethrow()
        end
    end
    return _with_response_reader(incoming; decompress = decompress) do reader
        if sink === nothing
            body = _read_all_response_bytes(reader)
            return body, Int64(length(body))
        end
        if sink isa IO
            n = _copy_response_bytes!(sink::IO, reader)
            return nothing, n
        end
        n = _copy_response_bytes!(sink::AbstractVector{UInt8}, reader)
        if sink isa Vector{UInt8}
            return sink::Vector{UInt8}, n
        end
        return view(sink::AbstractVector{UInt8}, 1:Int(n)), n
    end
end

function _add_header_value!(headers::Headers, key, value)
    key_s = String(key)
    if value isa AbstractVector && !(value isa AbstractString)
        for item in value
            appendheader(headers, key_s, String(item))
        end
        return nothing
    end
    appendheader(headers, key_s, String(value))
    return nothing
end

function _is_header_list_entry(x)::Bool
    x isa Pair && return true
    (x isa Tuple && length(x) == 2) && return true
    return false
end

function _is_headers_input(x)::Bool
    x === nothing && return true
    x isa Headers && return true
    x isa AbstractDict && return true
    if x isa AbstractVector
        for item in x
            _is_header_list_entry(item) || return false
        end
        return true
    end
    return false
end

function _normalize_headers_input(headers_input)::Headers
    headers_input === nothing && return Headers()
    headers_input isa Headers && return copy(headers_input)
    headers = Headers()
    if headers_input isa AbstractDict
        for (k, v) in pairs(headers_input)
            _add_header_value!(headers, k, v)
        end
        return headers
    end
    if headers_input isa AbstractVector
        for item in headers_input
            if item isa Pair
                pair = item::Pair
                _add_header_value!(headers, pair.first, pair.second)
                continue
            end
            if item isa Tuple && length(item) == 2
                tup = item::Tuple
                _add_header_value!(headers, tup[1], tup[2])
                continue
            end
            throw(ArgumentError("unsupported header entry type $(typeof(item)); expected Pair or 2-tuple"))
        end
        return headers
    end
    throw(ArgumentError("unsupported headers input type $(typeof(headers_input))"))
end

function _apply_default_accept_encoding!(headers::Headers, decompress::Union{Nothing, Bool})::Nothing
    decompress === false && return nothing
    hasheader(headers, "Accept-Encoding") && return nothing
    setheader(headers, "Accept-Encoding", "gzip")
    return nothing
end

function _query_string(query)::String
    query === nothing && return ""
    query isa AbstractString && return String(query)
    _is_unreserved_query_byte(b::UInt8) = (
        (b >= UInt8('A') && b <= UInt8('Z')) ||
        (b >= UInt8('a') && b <= UInt8('z')) ||
        (b >= UInt8('0') && b <= UInt8('9')) ||
        b == UInt8('-') ||
        b == UInt8('.') ||
        b == UInt8('_') ||
        b == UInt8('~')
    )
    function _percent_encode_query_component(value)::String
        text = string(value)
        encoded = IOBuffer()
        for b in codeunits(text)
            if _is_unreserved_query_byte(b)
                write(encoded, b)
            else
                print(encoded, '%')
                print(encoded, uppercase(string(b, base = 16, pad = 2)))
            end
        end
        return String(take!(encoded))
    end
    _pair_string(k, v) = string(_percent_encode_query_component(k), "=", _percent_encode_query_component(v))
    parts = String[]
    if query isa AbstractDict
        query_pairs = collect(pairs(query))
        sort!(query_pairs; by = x -> String(x.first))
        for (k, v) in query_pairs
            push!(parts, _pair_string(k, v))
        end
        return join(parts, "&")
    end
    if query isa AbstractVector
        for item in query
            if item isa Pair
                pair = item::Pair
                push!(parts, _pair_string(pair.first, pair.second))
                continue
            end
            if item isa Tuple && length(item) == 2
                tup = item::Tuple
                push!(parts, _pair_string(tup[1], tup[2]))
                continue
            end
            throw(ArgumentError("unsupported query entry type $(typeof(item)); expected Pair or 2-tuple"))
        end
        return join(parts, "&")
    end
    throw(ArgumentError("unsupported query type $(typeof(query)); expected String, Dict, or vector of Pair/tuples"))
end

function _append_query(target::String, query)::String
    query_s = _query_string(query)
    isempty(query_s) && return target
    occursin('?', target) && return string(target, "&", query_s)
    return string(target, "?", query_s)
end

function _parse_http_url(url::AbstractString; query = nothing)::_URLParts
    s = url isa String ? url : String(url)
    bytes = codeunits(s)
    scheme_idx = findfirst("://", s)
    scheme_idx === nothing && throw(ArgumentError("URL must include http:// or https:// scheme: $s"))
    scheme_start = first(scheme_idx)
    scheme_end = last(scheme_idx)
    scheme_last = prevind(s, scheme_start)
    secure = if _ascii_equal_fold_literal(bytes, firstindex(s), scheme_last, "http")
        false
    elseif _ascii_equal_fold_literal(bytes, firstindex(s), scheme_last, "https")
        true
    else
        scheme = String(SubString(s, firstindex(s), scheme_last))
        throw(ArgumentError("unsupported URL scheme '$scheme'; expected http or https"))
    end
    rest_start = nextind(s, scheme_end)
    rest_start > lastindex(s) && throw(ArgumentError("URL missing authority: $s"))
    fragment_idx = _find_url_byte(bytes, rest_start, lastindex(s), UInt8('#'))
    rest_last = fragment_idx === nothing ? lastindex(s) : prevind(s, fragment_idx)
    sep = _find_first_url_sep(bytes, rest_start, rest_last)
    authority_range = sep === nothing ? _text_range(rest_start, rest_last) : _text_range(rest_start, prevind(s, sep))
    target_range = sep === nothing ? _EMPTY_TEXT_RANGE : _text_range(sep, rest_last)
    target_starts_with_query = sep !== nothing && @inbounds bytes[sep] == UInt8('?')

    userinfo_range = _EMPTY_TEXT_RANGE
    has_userinfo = false
    at_idx = _text_range_empty(authority_range) ? nothing : _find_last_url_byte(bytes, authority_range.first, authority_range.last, UInt8('@'))
    if at_idx !== nothing
        userinfo_range = _text_range(authority_range.first, prevind(s, at_idx))
        has_userinfo = !_text_range_empty(userinfo_range)
        authority_range = _text_range(nextind(s, at_idx), authority_range.last)
    end

    _text_range_empty(authority_range) && throw(ArgumentError("URL missing host: $s"))

    host_range = authority_range
    has_explicit_port = false
    if @inbounds bytes[authority_range.first] == UInt8('[')
        close_idx = _find_url_byte(bytes, authority_range.first, authority_range.last, UInt8(']'))
        close_idx === nothing && throw(ArgumentError("invalid IPv6 host authority: $(_text_range_string(s, authority_range))"))
        host_range = _text_range(nextind(s, authority_range.first), prevind(s, close_idx))
        if close_idx < authority_range.last
            next_after_close = nextind(s, close_idx)
            has_explicit_port = next_after_close <= authority_range.last && @inbounds(bytes[next_after_close] == UInt8(':'))
        end
    else
        has_explicit_port = _find_last_url_byte(bytes, authority_range.first, authority_range.last, UInt8(':')) !== nothing
        has_explicit_port || (host_range = authority_range)
    end

    query_suffix = query === nothing ? "" : _query_string(query)
    default_port = secure ? UInt16(443) : UInt16(80)
    return _URLParts(
        s,
        secure,
        default_port,
        authority_range,
        host_range,
        userinfo_range,
        target_range,
        query_suffix,
        has_explicit_port,
        target_starts_with_query,
        has_userinfo,
        "",
        "",
        "",
        "",
        "",
    )
end

function _method_upper(method::Union{AbstractString, Symbol})::String
    return uppercase(String(method))
end

@inline function _basic_auth_header(username::AbstractString, password::AbstractString)::String
    return "Basic " * base64encode(string(username, ":", password))
end

function _basic_auth_header(basicauth)::String
    if basicauth isa Tuple && length(basicauth) == 2
        return _basic_auth_header(String(basicauth[1]), String(basicauth[2]))
    end
    if basicauth isa Pair
        return _basic_auth_header(String(basicauth.first), String(basicauth.second))
    end
    throw(ArgumentError("basicauth must be `nothing`, `(username, password)`, or `username => password`"))
end

function _apply_request_authorization!(
        headers::Headers,
        basicauth,
        url_authorization::Union{Nothing, String},
    )::Nothing
    hasheader(headers, "Authorization") && return nothing
    if basicauth !== nothing
        setheader(headers, "Authorization", _basic_auth_header(basicauth))
        return nothing
    end
    url_authorization === nothing || setheader(headers, "Authorization", url_authorization::String)
    return nothing
end

function _client_for_request(
        client::Union{Nothing, Client};
        connect_timeout::Real,
        require_ssl_verification::Bool,
    )::Tuple{Client, Bool}
    connect_timeout >= 0 || throw(ArgumentError("connect_timeout must be >= 0"))
    if client !== nothing
        if connect_timeout > 0 || !require_ssl_verification
            throw(ArgumentError("connect_timeout/require_ssl_verification overrides are not supported when passing an explicit Client"))
        end
        return client::Client, false
    end
    if connect_timeout == 0 && require_ssl_verification
        return _default_client!(), false
    end
    timeout_ns = connect_timeout == 0 ? Int64(0) : Int64(round(connect_timeout * 1.0e9))
    resolver = HostResolvers.HostResolver(timeout_ns = timeout_ns)
    tls_config = require_ssl_verification ? nothing : TLS.Config(verify_peer = false)
    transport = Transport(
        host_resolver = resolver,
        tls_config = tls_config,
        proxy = ProxyFromEnvironment(),
        max_idle_per_host = 1,
        max_idle_total = 1,
        idle_timeout_ns = Int64(0),
    )
    return Client(transport = transport), true
end

function _validate_request_extra_kwargs(kwargs)
    for (k, v) in kwargs
        if k == :verbose || k == :canonicalize_headers || k == :logerrors || k == :observelayers
            continue
        end
        throw(ArgumentError("unsupported keyword argument: $k"))
    end
    return nothing
end

@inline function _request_deadline_ns(request::Request)::Int64
    ctx = request.context
    ctx === nothing && return Int64(0)
    return (ctx::RequestContext).deadline_ns
end

function _apply_conn_deadline!(conn::ClientConn, deadline_ns::Int64)
    deadline_ns == 0 && return nothing
    if conn.secure
        conn.tls === nothing || TLS.set_deadline!(conn.tls::TLS.Conn, deadline_ns)
    else
        conn.tcp === nothing || TCP.set_deadline!(conn.tcp::TCP.Conn, deadline_ns)
    end
    return nothing
end

mutable struct _RetryController{F}
    enabled::Bool
    remaining::Int
    retry_non_idempotent::Bool
    retry_if::F
    respect_retry_after::Bool
    bucket::Union{Nothing, RetryBucket}
end

@inline function _retryable_status_code(status::Int)::Bool
    return status == 408 || status == 429 || status == 500 || status == 502 || status == 503 || status == 504
end

@inline function _retryable_request_method(method::String)::Bool
    return method == "GET" || method == "HEAD" || method == "OPTIONS" || method == "TRACE" || method == "PUT" || method == "DELETE"
end

@inline function _retryable_request_headers(request::Request)::Bool
    key = header(request.headers, "Idempotency-Key", nothing)
    key !== nothing && !isempty(key::String) && return true
    legacy = header(request.headers, "X-Idempotency-Key", nothing)
    return legacy !== nothing && !isempty(legacy::String)
end

@inline function _retryable_request_body(request::Request)::Bool
    return request.content_length == 0 || request.body isa EmptyBody || request.body isa BytesBody
end

@inline function _retryable_policy_request(request::Request, retry_non_idempotent::Bool)::Bool
    _retryable_request_body(request) || return false
    retry_non_idempotent && return true
    return _retryable_request_method(request.method) || _retryable_request_headers(request)
end

function _retryable_request_error(err)::Bool
    err isa EOFError && return true
    err isa SystemError && return true
    err isa ParseError && return true
    err isa HostResolvers.DNSTimeoutError && return true
    err isa HostResolvers.DNSOpError && return _retryable_request_error((err::HostResolvers.DNSOpError).err)
    err isa IOPoll.NetClosingError && return true
    err isa IOPoll.NotPollableError && return true
    err isa IOPoll.DeadlineExceededError && return false
    err isa TLS.TLSHandshakeTimeoutError && return true
    if err isa TLS.TLSError
        cause = (err::TLS.TLSError).cause
        cause === nothing && return false
        return _retryable_request_error(cause::Exception)
    end
    return false
end

function _retry_hook_decision(controller::_RetryController, attempt::Int, err, req::Request, resp)
    hook = controller.retry_if
    hook === nothing && return nothing
    decision = hook(attempt, err, req, resp)
    (decision === nothing || decision isa Bool) || throw(ArgumentError("retry_if must return Bool or nothing"))
    return decision
end

function _should_retry_request_attempt(controller::_RetryController, attempt::Int, req::Request, err, resp)::Bool
    controller.enabled || return false
    controller.remaining > 0 || return false
    _retryable_request_body(req) || return false
    built_in = false
    if err !== nothing
        built_in = _retryable_policy_request(req, controller.retry_non_idempotent) && _retryable_request_error(err)
    elseif resp !== nothing
        built_in = _retryable_policy_request(req, controller.retry_non_idempotent) && _retryable_status_code((resp::Response).status_code)
    end
    decision = _retry_hook_decision(controller, attempt, err, req, resp)
    decision === nothing && return built_in
    return decision::Bool
end

@inline function _retry_bucket_for_request(client::Client, retry_bucket::Bool)
    retry_bucket || return nothing
    return client.transport.retry_bucket
end

@inline function _retry_bucket_for_request(client::Client, retry_bucket::RetryBucket)
    _ = client
    return retry_bucket
end

@inline function _retry_partition_for_address(address::AbstractString)::String
    host, _ = HostResolvers.split_host_port(address)
    return lowercase(host)
end

function _retry_delay_ns(
        controller::_RetryController,
        attempt::Int,
        response::Union{Nothing, Response},
    )::Int64
    retry_after_ns = nothing
    if controller.respect_retry_after && response !== nothing
        status = (response::Response).status_code
        if status == 429 || status == 503
            retry_after_ns = _retry_after_delay_ns((response::Response).headers)
        end
    end
    return _retry_delay_ns(controller.bucket, attempt; retry_after_ns = retry_after_ns)
end

function _sleep_retry_delay!(request::Request, delay_ns::Int64)::Bool
    delay_ns < 0 && return false
    deadline_ns = _request_deadline_ns(request)
    if deadline_ns != 0
        now_ns = Int64(time_ns())
        now_ns >= deadline_ns && return false
        now_ns > typemax(Int64) - delay_ns && return false
        now_ns + delay_ns <= deadline_ns || return false
    end
    delay_ns == 0 && return true
    sleep(delay_ns / 1.0e9)
    return true
end

function _release_retry_token!(controller::_RetryController, token)
    token === nothing && return nothing
    bucket = controller.bucket
    bucket === nothing && return nothing
    Base.release(bucket::RetryBucket, token)
    return nothing
end

function _release_retry_token!(controller::_RetryController, token, err)
    token === nothing && return nothing
    bucket = controller.bucket
    bucket === nothing && return nothing
    Base.release(bucket::RetryBucket, token, err)
    return nothing
end

function _arm_request_retry!(
        controller::_RetryController,
        address::AbstractString,
        request::Request,
        attempt::Int,
        response::Union{Nothing, Response},
    )
    delay_ns = _retry_delay_ns(controller, attempt, response)
    token = nothing
    bucket = controller.bucket
    if bucket !== nothing
        try
            token = Base.acquire(bucket::RetryBucket, _retry_partition_for_address(address))
        catch err
            err isa RetryDeniedError || rethrow(err)
            return false, nothing
        end
    end
    ok = false
    try
        _sleep_retry_delay!(request, delay_ns) || return false, nothing
        ok = true
    finally
        ok || _release_retry_token!(controller, token)
    end
    controller.remaining -= 1
    return true, token
end

function _retry_controller(
        client::Client;
        retry::Bool,
        retries::Integer,
        retry_non_idempotent::Bool,
        retry_if,
        respect_retry_after::Bool,
        retry_bucket::Union{Bool, RetryBucket},
    )::_RetryController
    retries isa Bool && throw(ArgumentError("retries must be >= 0"))
    retries >= 0 || throw(ArgumentError("retries must be >= 0"))
    return _RetryController(
        retry && retries > 0,
        Int(retries),
        retry_non_idempotent,
        retry_if,
        respect_retry_after,
        _retry_bucket_for_request(client, retry_bucket),
    )
end

function _retry_policy_response(incoming::_IncomingResponse, fallback_request::Request)::Response
    head = incoming.head
    return _response_nocopy_public(
        head.status_code,
        head.reason,
        head.headers,
        head.trailers,
        nothing,
        head.content_length,
        head.proto_major,
        head.proto_minor,
        head.close,
        head.request === nothing ? fallback_request : (head.request::Request),
        head.request_url,
        head.previous,
        head.redirect_count,
    )
end

"""
    request(method, url, headers=Pair{String,String}[], body=nothing; kwargs...)

High-level one-shot HTTP request API (similar shape to HTTP.jl convenience
methods).

Keyword arguments:
- `basicauth`: optional basic-auth credentials supplied as
  `(username, password)` or `username => password`; explicit
  `Authorization` headers take precedence, and URL `userinfo` is only used as a
  fallback when neither is provided
- `retry`: overall toggle for high-level request retries; lower-level reused-connection transport retries still happen independently
- `retries`: maximum number of retry attempts after the initial request attempt
- `retry_non_idempotent`: allow automatic retries for methods like `POST`/`PATCH`; `PUT` and `DELETE` are already treated as idempotent
- `retry_if`: optional callback `(attempt, err, req, resp) -> Bool | nothing`; `true` forces a retry when the request body is replayable, `false` suppresses retry, and `nothing` defers to built-in retry rules
- `respect_retry_after`: honor server `Retry-After` on retryable `429`/`503` responses
- `retry_bucket`: `true` uses the request transport's default `RetryBucket`, `false` disables bucket coordination, and a custom `RetryBucket` overrides the transport default
- automatic retries only occur for replayable request bodies; built-in policy retries idempotent methods (`GET`, `HEAD`, `OPTIONS`, `TRACE`, `PUT`, `DELETE`) plus requests carrying `Idempotency-Key`/`X-Idempotency-Key`
- `status_exception`: throw `StatusError` for non-success responses
- `redirect`: follow redirects through `do!`
- `redirect_limit`: maximum number of redirects to follow for this call;
  `0` disables redirect following while still returning the redirect response
- `redirect_method`: override the method used for `301`/`302` redirects; pass
  `:same` to preserve the original method
- `forwardheaders`: whether original request headers are copied onto redirect
  follow-up requests
- request bodies may be passed positionally or, for convenience helpers like
  `post(url; body=...)`, via the `body` keyword; supported inputs include
  strings, byte vectors, `IO`, `Dict`/`NamedTuple` form fields, `HTTP.Form`,
  iterable chunks, and existing `HTTP.AbstractBody` values
- `proxy`: explicit proxy override for this call; pass a proxy URL string, a
  `ProxyConfig`, or `nothing` to force direct connections
- `cookies`: `true` to use the effective cookie jar, `false` to disable cookie
  send/store for this call, or a dictionary of extra cookie name/value pairs to
  append to jar-derived cookies
- `cookiejar`: optional cookie jar override for this call; explicit clients
  default to `client.cookiejar`, while implicit convenience calls default to the
  shared `HTTP.COOKIEJAR`
- `query`: optional query string or key/value collection appended to the URL
- `response_stream`: optional sink `IO` or byte buffer written with the final response body
- `response_body`: alias for `response_stream`
- `decompress`: `nothing`/`true` auto-decompress gzip responses, `false` leaves wire bytes untouched
- `sse_callback`: callback receiving `(event)` or `(stream, event)` for
  successful SSE responses
- `client`: optional explicit `Client`; otherwise a default or ephemeral client
  is created
- `connect_timeout`: connection timeout in seconds for implicit clients
- `readtimeout`: overall request deadline in seconds
- `require_ssl_verification`: disable certificate verification only for testing
- `protocol`: `:auto`, `:h1`, or `:h2`

The built-in retry policy is intentionally conservative: it retries transient
transport errors plus retryable `408`/`429`/`5xx` responses for replayable
requests, but does not automatically retry request read-timeout/deadline
failures.

Returns a high-level `Response`. When no response sink is provided,
`response.body` is a fully materialized `Vector{UInt8}`. When `response_stream`
or `response_body` is provided, the final `Response` contains either the filled
buffer/view or `nothing` for `IO` sinks.

Throws `ArgumentError` for unsupported inputs or invalid sink combinations,
`StatusError` when `status_exception=true` and the response status is considered
failing, plus any lower-level transport or protocol exception raised during the
request. Automatic retries only occur for replayable request bodies.
"""
function request(
        method::Union{AbstractString, Symbol},
        url::AbstractString,
        h = Pair{String, String}[],
        b = nothing;
        headers = h,
        body = b,
        basicauth = nothing,
        retry::Bool = true,
        retries::Integer = 4,
        retry_non_idempotent::Bool = false,
        retry_if = nothing,
        respect_retry_after::Bool = true,
        retry_bucket::Union{Bool, RetryBucket} = true,
        status_exception::Bool = true,
        redirect::Bool = true,
        redirect_limit::Union{Nothing, Integer} = nothing,
        redirect_method = nothing,
        forwardheaders::Bool = true,
        proxy = _USE_TRANSPORT_PROXY,
        cookies = true,
        cookiejar::Union{Nothing, CookieJar} = nothing,
        query = nothing,
        response_stream = nothing,
        response_body = response_stream,
        decompress::Union{Nothing, Bool} = nothing,
        sse_callback = nothing,
        client::Union{Nothing, Client} = nothing,
        connect_timeout::Real = 0,
        readtimeout::Real = 0,
        require_ssl_verification::Bool = true,
        protocol::Symbol = :auto,
        kwargs...,
    )
    _validate_request_extra_kwargs(kwargs)
    readtimeout >= 0 || throw(ArgumentError("readtimeout must be >= 0"))
    parsed = _parse_http_url(url; query = query)
    req_headers = _normalize_headers_input(headers)
    normalized_cookies = _normalize_cookies_input(cookies)
    sink = _resolve_response_sink(response_stream, response_body)
    sse_callback === nothing || sink === nothing || throw(ArgumentError("sse_callback cannot be combined with response_stream or response_body"))
    _apply_default_accept_encoding!(req_headers, decompress)
    _apply_request_authorization!(req_headers, basicauth, parsed.authorization)
    normalized_body = _normalize_body_input(body)
    if normalized_body.default_content_type !== nothing && !hasheader(req_headers, "Content-Type")
        setheader(req_headers, "Content-Type", normalized_body.default_content_type::String)
    end
    req = Request(
        _method_upper(method),
        parsed.target;
        headers = req_headers,
        body = normalized_body.body,
        host = parsed.address,
        content_length = normalized_body.content_length,
    )
    if readtimeout > 0
        timeout_ns = Int64(round(readtimeout * 1.0e9))
        set_deadline!(req.context, Int64(time_ns()) + timeout_ns)
    end
    req_client, owns_client = _client_for_request(client; connect_timeout = connect_timeout, require_ssl_verification = require_ssl_verification)
    retry_controller = _retry_controller(
        req_client;
        retry = retry,
        retries = retries,
        retry_non_idempotent = retry_non_idempotent,
        retry_if = retry_if,
        respect_retry_after = respect_retry_after,
        retry_bucket = retry_bucket,
    )
    client === nothing || proxy === _USE_TRANSPORT_PROXY || throw(ArgumentError("proxy override is not supported when passing an explicit Client"))
    proxy_config = _proxy_config_for_request(req_client, proxy)
    effective_cookiejar = _effective_cookiejar(client, cookiejar)
    incoming_response = nothing
    try
        incoming_response = _do_incoming!(
            req_client,
            parsed.address,
            req;
            secure = parsed.secure,
            server_name = parsed.server_name,
            protocol = protocol,
            redirect_policy = _redirect_policy(
                req_client;
                redirect_limit = redirect ? redirect_limit : 0,
                redirect_method = redirect_method,
                forwardheaders = forwardheaders,
            ),
            retry_controller = retry_controller,
            proxy_config = proxy_config,
            cookies = normalized_cookies,
            cookiejar = effective_cookiejar,
        )
        incoming = incoming_response::_IncomingResponse
        resolved_request = incoming.head.request === nothing ? req : incoming.head.request::Request
        if sse_callback !== nothing
            sse_response = _finalize_request_response(incoming, nobody, Int64(0), resolved_request, parsed.url)
            if !_status_throws(sse_response)
                _consume_incoming_sse!(incoming, sse_response, sse_callback::Function; decompress = decompress)
                return sse_response
            end
        end
        final_body, final_length = _consume_incoming_response!(incoming, sink; decompress = decompress)
        response = _finalize_request_response(incoming, final_body, final_length, resolved_request, parsed.url)
        status_exception && _status_throws(response) && throw(StatusError(response))
        return response
    finally
        owns_client && close(req_client)
    end
end

function _finalize_request_response(
        incoming::_IncomingResponse,
        body,
        body_length::Int64,
        resolved_request::Request,
        request_url::String,
    )::Response
    return _response_nocopy_public(
        incoming.head.status_code,
        incoming.head.reason,
        incoming.head.headers,
        incoming.head.trailers,
        body,
        body_length,
        incoming.head.proto_major,
        incoming.head.proto_minor,
        incoming.head.close,
        resolved_request,
        incoming.head.request_url === nothing ? request_url : (incoming.head.request_url::String),
        incoming.head.previous,
        incoming.head.redirect_count,
    )
end

function _split_headers_body_args(args::Tuple)
    if isempty(args)
        return Pair{String, String}[], nothing
    end
    if length(args) == 1
        arg = args[1]
        if _is_headers_input(arg)
            return arg, nothing
        end
        return Pair{String, String}[], arg
    end
    if length(args) == 2
        return args[1], args[2]
    end
    throw(ArgumentError("expected at most two positional arguments after URL: headers and body"))
end

"""`GET` convenience wrapper around `request`."""
function get(url::AbstractString, headers = Pair{String, String}[]; kwargs...)
    return request("GET", url, headers, nothing; kwargs...)
end

"""`HEAD` convenience wrapper around `request`."""
function head(url::AbstractString, headers = Pair{String, String}[]; kwargs...)
    return request("HEAD", url, headers, nothing; kwargs...)
end

"""`POST` convenience wrapper around `request`."""
function post(url::AbstractString, args...; kwargs...)
    headers, body = _split_headers_body_args(args)
    return request("POST", url, headers, body; kwargs...)
end

"""`PUT` convenience wrapper around `request`."""
function put(url::AbstractString, args...; kwargs...)
    headers, body = _split_headers_body_args(args)
    return request("PUT", url, headers, body; kwargs...)
end

"""`PATCH` convenience wrapper around `request`."""
function patch(url::AbstractString, args...; kwargs...)
    headers, body = _split_headers_body_args(args)
    return request("PATCH", url, headers, body; kwargs...)
end

"""`DELETE` convenience wrapper around `request`."""
function delete(url::AbstractString, args...; kwargs...)
    headers, body = _split_headers_body_args(args)
    return request("DELETE", url, headers, body; kwargs...)
end

"""`OPTIONS` convenience wrapper around `request`."""
function options(url::AbstractString, headers = Pair{String, String}[]; kwargs...)
    return request("OPTIONS", url, headers, nothing; kwargs...)
end
