# HTTP client transport, redirect, cookie-jar, and high-level convenience APIs.
export Transport
export ClientConn
export ManagedBody
export roundtrip!
export close_idle_connections!
export idle_connection_count

using Base64
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

"""
    Transport(; ...)

Connection-pooling transport for HTTP/1 requests.
"""
mutable struct Transport
    host_resolver::HostResolvers.HostResolver
    tls_config::Union{Nothing, TLS.Config}
    max_idle_per_host::Int
    max_idle_total::Int
    idle_timeout_ns::Int64
    lock::ReentrantLock
    idle::Dict{String, Vector{ClientConn}}
    @atomic idle_total::Int
    @atomic closed::Bool
end

"""
    ManagedBody

Response body wrapper that returns/tears down pooled connections once the body
is fully consumed or closed.
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
        max_idle_per_host::Integer = 2,
        max_idle_total::Integer = 64,
        idle_timeout_ns::Integer = Int64(90_000_000_000),
    )
    max_idle_per_host > 0 || throw(ArgumentError("max_idle_per_host must be > 0"))
    max_idle_total > 0 || throw(ArgumentError("max_idle_total must be > 0"))
    idle_timeout_ns >= 0 || throw(ArgumentError("idle_timeout_ns must be >= 0"))
    return Transport(
        host_resolver,
        tls_config,
        Int(max_idle_per_host),
        Int(max_idle_total),
        Int64(idle_timeout_ns),
        ReentrantLock(),
        Dict{String, Vector{ClientConn}}(),
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

function _close_conn!(conn::ClientConn)
    if _conn_closed(conn)
        return nothing
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

function _new_conn!(transport::Transport, key::String, address::String; secure::Bool, server_name::Union{Nothing, String})::ClientConn
    tcp = HostResolvers.connect(transport.host_resolver, "tcp", address)
    if secure
        cfg = _effective_tls_config(transport, address, server_name)
        tls = TLS.client(tcp, cfg)
        TLS.handshake!(tls)
        return ClientConn(key, address, true, tcp, tls, _ConnReader(tls), IOBuffer(), false, false, time_ns())
    end
    return ClientConn(key, address, false, tcp, nothing, _ConnReader(tcp), IOBuffer(), false, false, time_ns())
end

function _evict_expired_idle_locked!(transport::Transport, key::String, now_ns::Int64)
    idle_list = get(() -> nothing, transport.idle, key)
    idle_list === nothing && return nothing
    kept = ClientConn[]
    for conn in idle_list::Vector{ClientConn}
        expired = transport.idle_timeout_ns > 0 && (now_ns - conn.last_used_ns) > transport.idle_timeout_ns
        if _conn_closed(conn) || expired
            _close_conn!(conn)
            @atomic :acquire_release transport.idle_total -= 1
            continue
        end
        push!(kept, conn)
    end
    if isempty(kept)
        delete!(transport.idle, key)
    else
        transport.idle[key] = kept
    end
    return nothing
end

function _acquire_conn!(transport::Transport, key::String, address::String; secure::Bool, server_name::Union{Nothing, String})::ClientConn
    _transport_closed(transport) && throw(ProtocolError("transport is closed"))
    lock(transport.lock)
    try
        now_ns = Int64(time_ns())
        _evict_expired_idle_locked!(transport, key, now_ns)
        idle_list = get(() -> nothing, transport.idle, key)
        if idle_list !== nothing && !isempty(idle_list::Vector{ClientConn})
            conn = pop!(idle_list::Vector{ClientConn})
            @atomic :acquire_release transport.idle_total -= 1
            isempty(idle_list::Vector{ClientConn}) && delete!(transport.idle, key)
            if !_conn_closed(conn)
                conn.reused = true
                return conn
            end
            _close_conn!(conn)
        end
    finally
        unlock(transport.lock)
    end
    return _new_conn!(transport, key, address; secure = secure, server_name = server_name)
end

function _put_idle_conn!(transport::Transport, conn::ClientConn)
    if _transport_closed(transport) || _conn_closed(conn)
        _close_conn!(conn)
        return nothing
    end
    lock(transport.lock)
    try
        if _transport_closed(transport)
            _close_conn!(conn)
            return nothing
        end
        idle_list = get(() -> ClientConn[], transport.idle, conn.key)
        if length(idle_list) >= transport.max_idle_per_host || (@atomic :acquire transport.idle_total) >= transport.max_idle_total
            _close_conn!(conn)
            return nothing
        end
        if conn.secure
            conn.tls === nothing || TLS.set_deadline!(conn.tls::TLS.Conn, Int64(0))
        else
            conn.tcp === nothing || TCP.set_deadline!(conn.tcp::TCP.Conn, Int64(0))
        end
        conn.last_used_ns = time_ns()
        push!(idle_list, conn)
        transport.idle[conn.key] = idle_list
        @atomic :acquire_release transport.idle_total += 1
    finally
        unlock(transport.lock)
    end
    return nothing
end

function close_idle_connections!(transport::Transport)
    lock(transport.lock)
    try
        for (_, idle_list) in transport.idle
            for conn in idle_list
                _close_conn!(conn)
            end
        end
        empty!(transport.idle)
        @atomic :release transport.idle_total = 0
    finally
        unlock(transport.lock)
    end
    return nothing
end

function Base.close(transport::Transport)
    _transport_closed(transport) && return nothing
    @atomic :release transport.closed = true
    close_idle_connections!(transport)
    return nothing
end

"""
    idle_connection_count(transport; key=nothing)

Return idle pooled connection count globally or for one host key.
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

@inline function _response_reusable(response::Response, request::Request)::Bool
    response.close && return false
    request.close && return false
    has_header_token(response.headers, "Connection", "close") && return false
    response.body isa EOFBody && return false
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
        _close_conn!(body.conn)
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
        _close_conn!(body.conn)
        _release_managed!(body)
        rethrow()
    end
end

"""
    roundtrip!(transport, address, request; secure=false, server_name=nothing)

Execute one HTTP/1 request/response exchange through `transport`.
"""
function roundtrip!(
        transport::Transport,
        address::AbstractString,
        request::Request;
        secure::Bool = false,
        server_name::Union{Nothing, AbstractString} = nothing,
    )
    key = string(secure ? "https://" : "http://", address)
    request_deadline = _request_deadline_ns(request)
    retry_template = _retryable_request(request) ? _copy_request(request) : nothing
    attempt = 1
    current_request = request
    while true
        conn = _acquire_conn!(transport, key, String(address); secure = secure, server_name = server_name === nothing ? nothing : String(server_name))
        was_reused = conn.reused
        try
            _apply_conn_deadline!(conn, request_deadline)
            request_io = _reset_request_buffer!(conn)
            try
                write_request!(request_io, current_request)
            finally
                try
                    body_close!(current_request.body)
                catch
                end
            end
            stream = _conn_stream(conn)
            request_bytes = request_io.size
            n = write(stream, request_io.data, request_bytes)
            n == request_bytes || throw(ProtocolError("transport short write"))
            reader = conn.reader
            raw_response = read_response(reader, current_request)
            while (raw_response.status_code >= 100 && raw_response.status_code < 200) && raw_response.status_code != 101
                try
                    body_close!(raw_response.body)
                catch
                end
                raw_response = read_response(reader, current_request)
            end
            reusable = _response_reusable(raw_response, current_request)
            if raw_response.body isa EmptyBody
                if reusable
                    _put_idle_conn!(transport, conn)
                else
                    _close_conn!(conn)
                end
                return raw_response
            end
            managed = ManagedBody(raw_response.body, transport, conn, reusable, false, false)
            return Response{typeof(managed)}(
                raw_response.status_code,
                raw_response.reason,
                raw_response.headers,
                raw_response.trailers,
                managed,
                raw_response.content_length,
                raw_response.proto_major,
                raw_response.proto_minor,
                raw_response.close,
                raw_response.request,
            )
        catch err
            _close_conn!(conn)
            if attempt == 1 && was_reused && retry_template !== nothing && _retryable_reused_conn_error(err)
                current_request = _copy_request(retry_template::Request)
                attempt = 2
                continue
            end
            rethrow(err)
        end
    end
end

export Client
export ClientTrace
export AbstractCookieJar
export MemoryCookieJar
export Cookie
export do!
export get!
export ClientResponse
export StatusError
export request
export get
export head
export post
export put
export patch
export delete
export options

abstract type AbstractCookieJar end

"""
    Cookie

Minimal in-memory cookie representation used by `MemoryCookieJar`.
"""
struct Cookie
    name::String
    value::String
    path::String
    secure::Bool
end

"""
    MemoryCookieJar()

Simple host-keyed cookie jar for client redirect/session flows.
"""
mutable struct MemoryCookieJar <: AbstractCookieJar
    lock::ReentrantLock
    by_host::Dict{String, Dict{String, Cookie}}
end

"""
    ClientTrace(; ...)

Optional callback hooks for client request lifecycle events.
"""
struct ClientTrace
    on_get_conn::Union{Nothing, Function}
    on_got_conn::Union{Nothing, Function}
    on_wrote_request::Union{Nothing, Function}
    on_got_first_response_byte::Union{Nothing, Function}
end

"""
    Client(; ...)

High-level HTTP client with transport pooling, redirect policy, cookies, and optional HTTP/2.
"""
mutable struct Client
    transport::Transport
    check_redirect::Union{Nothing, Function}
    jar::Union{Nothing, AbstractCookieJar}
    max_redirects::Int
    trace::Union{Nothing, ClientTrace}
    prefer_http2::Bool
    h2_lock::ReentrantLock
    h2_conns::Dict{String, H2Connection}
end

function MemoryCookieJar()
    return MemoryCookieJar(ReentrantLock(), Dict{String, Dict{String, Cookie}}())
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
        transport::Transport = Transport(),
        check_redirect::Union{Nothing, Function} = nothing,
        jar::Union{Nothing, AbstractCookieJar} = MemoryCookieJar(),
        max_redirects::Integer = 10,
        trace::Union{Nothing, ClientTrace} = nothing,
        prefer_http2::Bool = true,
    )
    max_redirects >= 0 || throw(ArgumentError("max_redirects must be >= 0"))
    return Client(transport, check_redirect, jar, Int(max_redirects), trace, prefer_http2, ReentrantLock(), Dict{String, H2Connection}())
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

@inline function _h2_key(address::String, secure::Bool)::String
    return string(secure ? "https://" : "http://", address)
end

function _acquire_h2_conn!(
        client::Client,
        address::String,
        secure::Bool;
        server_name::Union{Nothing, String} = nothing,
    )::H2Connection
    key = _h2_key(address, secure)
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
        conn = connect_h2!(
            address;
            secure = secure,
            host_resolver = client.transport.host_resolver,
            tls_config = tls_cfg,
        )
        client.h2_conns[key] = conn
        return conn
    finally
        unlock(client.h2_lock)
    end
end

@inline function _should_fallback_h2_to_h1(err)::Bool
    return err isa H2NegotiationError
end

function _drop_h2_conn!(client::Client, address::String, secure::Bool)
    key = _h2_key(address, secure)
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

function _cookie_header(jar::MemoryCookieJar, host::String, path::String, secure::Bool)::Union{Nothing, String}
    lock(jar.lock)
    try
        host_map = get(() -> nothing, jar.by_host, host)
        host_map === nothing && return nothing
        parts = String[]
        for (_, cookie) in host_map::Dict{String, Cookie}
            cookie.secure && !secure && continue
            startswith(path, cookie.path) || continue
            push!(parts, "$(cookie.name)=$(cookie.value)")
        end
        isempty(parts) && return nothing
        return join(parts, "; ")
    finally
        unlock(jar.lock)
    end
end

function _store_set_cookies!(jar::MemoryCookieJar, host::String, set_cookie_values::Vector{String})
    lock(jar.lock)
    try
        host_map = get(() -> Dict{String, Cookie}(), jar.by_host, host)
        for value in set_cookie_values
            parts = split(value, ';')
            isempty(parts) && continue
            name_value = split(_trim_http_ows(parts[1]), '='; limit = 2)
            length(name_value) == 2 || continue
            name = _trim_http_ows(name_value[1])
            cookie_value = _trim_http_ows(name_value[2])
            isempty(name) && continue
            cookie_path = "/"
            secure = false
            for attr_raw in parts[2:end]
                attr = _trim_http_ows(attr_raw)
                isempty(attr) && continue
                kv = split(attr, '='; limit = 2)
                attr_name = lowercase(_trim_http_ows(kv[1]))
                if attr_name == "path" && length(kv) == 2
                    parsed_path = _trim_http_ows(kv[2])
                    !isempty(parsed_path) && (cookie_path = parsed_path)
                elseif attr_name == "secure"
                    secure = true
                end
            end
            host_map[name] = Cookie(name, cookie_value, cookie_path, secure)
        end
        jar.by_host[host] = host_map
    finally
        unlock(jar.lock)
    end
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
    return Request(
        request.method,
        request.target;
        headers = request.headers,
        trailers = request.trailers,
        body = _clone_body(request.body),
        host = request.host,
        content_length = request.content_length,
        proto_major = request.proto_major,
        proto_minor = request.proto_minor,
        close = request.close,
        context = request.context,
    )
end

function _copy_request_shallow_body(request::Request)
    return Request(
        request.method,
        request.target;
        headers = request.headers,
        trailers = request.trailers,
        body = request.body,
        host = request.host,
        content_length = request.content_length,
        proto_major = request.proto_major,
        proto_minor = request.proto_minor,
        close = request.close,
        context = request.context,
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
    delete_header!(headers, "Authorization")
    delete_header!(headers, "Www-Authenticate")
    delete_header!(headers, "Cookie")
    delete_header!(headers, "Cookie2")
    delete_header!(headers, "Proxy-Authorization")
    delete_header!(headers, "Proxy-Authenticate")
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
    startswith(location, "http://") && begin
        host_path = String(SubString(location, 8))
        slash = findfirst('/', host_path)
        if slash === nothing
            address = _normalize_redirect_authority(host_path, false)
            return address, false, "/"
        end
        authority = String(SubString(host_path, firstindex(host_path), prevind(host_path, slash)))
        address = _normalize_redirect_authority(authority, false)
        path = String(SubString(host_path, slash, lastindex(host_path)))
        return address, false, path
    end
    startswith(location, "https://") && begin
        host_path = String(SubString(location, 9))
        slash = findfirst('/', host_path)
        if slash === nothing
            address = _normalize_redirect_authority(host_path, true)
            return address, true, "/"
        end
        authority = String(SubString(host_path, firstindex(host_path), prevind(host_path, slash)))
        address = _normalize_redirect_authority(authority, true)
        path = String(SubString(host_path, slash, lastindex(host_path)))
        return address, true, path
    end
    startswith(location, "//") && begin
        host_path = String(SubString(location, 3))
        slash = findfirst('/', host_path)
        if slash === nothing
            address = _normalize_redirect_authority(host_path, current_secure)
            return address, current_secure, "/"
        end
        authority = String(SubString(host_path, firstindex(host_path), prevind(host_path, slash)))
        address = _normalize_redirect_authority(authority, current_secure)
        path = String(SubString(host_path, slash, lastindex(host_path)))
        return address, current_secure, path
    end
    startswith(location, "/") && return current_address, current_secure, location
    base_prefix = current_target
    slash = findlast('/', base_prefix)
    if slash === nothing
        return current_address, current_secure, "/$location"
    end
    base = String(SubString(base_prefix, firstindex(base_prefix), slash))
    return current_address, current_secure, string(base, location)
end

function _rewrite_method_for_redirect(method::String, status_code::Int)::String
    if status_code == 301 || status_code == 302 || status_code == 303
        if method == "GET" || method == "HEAD"
            return method
        end
        return "GET"
    end
    return method
end

@inline function _redirect_body_replayable(request::Request)::Bool
    request.content_length == 0 && return true
    request.body isa EmptyBody && return true
    request.body isa BytesBody && return true
    return false
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

function _prepare_request_for_redirect(request::Request, status_code::Int, new_target::String)::Request
    method = _rewrite_method_for_redirect(request.method, status_code)
    if method == request.method
        copied = _copy_request(request)
        copied.target = new_target
        return copied
    end
    redirected = Request(
        method,
        new_target;
        headers = request.headers,
        host = request.host,
        body = EmptyBody(),
        content_length = 0,
        proto_major = request.proto_major,
        proto_minor = request.proto_minor,
        close = request.close,
        context = request.context,
    )
    # Per Go/HTTP behavior: when method is rewritten to GET/HEAD, entity headers
    # tied to an old request body must be removed.
    delete_header!(redirected.headers, "Content-Length")
    delete_header!(redirected.headers, "Transfer-Encoding")
    delete_header!(redirected.headers, "Content-Type")
    delete_header!(redirected.headers, "Content-Encoding")
    delete_header!(redirected.headers, "Content-Language")
    delete_header!(redirected.headers, "Content-Location")
    return redirected
end

"""
    do!(client, address, request; secure=false, server_name=nothing, protocol=:auto)

Send a request with redirect handling and return the final response.
"""
function do!(
        client::Client,
        address::AbstractString,
        request::Request;
        secure::Bool = false,
        server_name::Union{Nothing, AbstractString} = nothing,
        protocol::Symbol = :auto,
    )
    current_address = String(address)
    initial_address = current_address
    current_secure = secure
    explicit_server_name = server_name !== nothing
    current_server_name = explicit_server_name ? String(server_name::AbstractString) : _host_for_sni(current_address)
    current_request = _copy_request_for_send(request; allow_nonreplayable = true)
    for redirect_count in 0:client.max_redirects
        send_request = _copy_request_for_send(current_request; allow_nonreplayable = redirect_count == 0)
        host, path = _host_path_from_request(current_address, current_request)
        if client.jar isa MemoryCookieJar
            cookie_value = _cookie_header(client.jar::MemoryCookieJar, host, path, current_secure)
            cookie_value === nothing || set_header!(send_request.headers, "Cookie", cookie_value)
        end
        _trace_call(client.trace, :on_get_conn, current_address, current_secure)
        response = if _use_h2(client, current_secure, protocol)
            try
                conn = _acquire_h2_conn!(client, current_address, current_secure; server_name = current_server_name)
                h2_roundtrip!(conn, send_request)
            catch err
                _drop_h2_conn!(client, current_address, current_secure)
                if protocol == :auto && _should_fallback_h2_to_h1(err)
                    roundtrip!(
                        client.transport,
                        current_address,
                        send_request;
                        secure = current_secure,
                        server_name = current_server_name,
                    )
                else
                    rethrow(err)
                end
            end
        else
            roundtrip!(
                client.transport,
                current_address,
                send_request;
                secure = current_secure,
                server_name = current_server_name,
            )
        end
        _trace_call(client.trace, :on_got_conn, current_address, current_secure)
        _trace_call(client.trace, :on_wrote_request, send_request.method, send_request.target)
        _trace_call(client.trace, :on_got_first_response_byte, response.status_code)
        if client.jar isa MemoryCookieJar
            set_cookie_values = get_headers(response.headers, "Set-Cookie")
            isempty(set_cookie_values) || _store_set_cookies!(client.jar::MemoryCookieJar, host, set_cookie_values)
        end
        if !_is_redirect_status(response.status_code)
            return response
        end
        location = get_header(response.headers, "Location")
        location === nothing && return response
        redirect_count == client.max_redirects && throw(ProtocolError("stopped after maximum redirect count ($(client.max_redirects))"))
        if client.check_redirect !== nothing
            proceed = (client.check_redirect::Function)(response, current_request, location)
            proceed isa Bool || throw(ProtocolError("check_redirect callback must return Bool"))
            proceed || return response
        end
        if (response.status_code == 307 || response.status_code == 308) && !_redirect_body_replayable(current_request)
            return response
        end
        body_close!(response.body)
        previous_secure = current_secure
        previous_address = current_address
        previous_target = current_request.target
        current_address, current_secure, next_target = _resolve_redirect_target(current_address, current_secure, location, current_request.target)
        if !explicit_server_name
            current_server_name = _host_for_sni(current_address)
        end
        current_request = _prepare_request_for_redirect(current_request, response.status_code, next_target)
        existing_ref = get_header(current_request.headers, "Referer")
        next_ref = _redirect_referer(previous_secure, previous_address, previous_target, current_secure, existing_ref)
        if next_ref === nothing
            delete_header!(current_request.headers, "Referer")
        else
            set_header!(current_request.headers, "Referer", next_ref::String)
        end
        if !_should_copy_sensitive_headers_on_redirect(initial_address, current_address)
            _strip_sensitive_redirect_headers!(current_request.headers)
        end
        current_request.host = current_address
    end
    throw(ProtocolError("unexpected redirect loop termination"))
end

"""
    get!(client, address, target; secure=false, protocol=:auto)

Convenience GET request using an existing `Client`.
"""
function get!(client::Client, address::AbstractString, target::AbstractString; secure::Bool = false, protocol::Symbol = :auto)
    request = Request("GET", target; host = String(address), body = EmptyBody(), content_length = 0)
    return do!(client, address, request; secure = secure, protocol = protocol)
end

import Base: get

"""
    ClientResponse

Materialized high-level response returned by `request/get/post/...` helpers.
"""
struct ClientResponse
    status::Int
    headers::Vector{Pair{String, String}}
    body::Vector{UInt8}
    request::Request
    url::String
end

"""
    StatusError

Raised when `status_exception=true` and the response status indicates failure.
"""
struct StatusError <: Exception
    response::ClientResponse
end

function Base.showerror(io::IO, err::StatusError)
    resp = err.response
    print(io, "http status error: ", resp.status, " for ", resp.request.method, " ", resp.url)
    return nothing
end

struct _URLParts
    secure::Bool
    address::String
    target::String
    server_name::String
    url::String
    authorization::Union{Nothing, String}
end

const _DEFAULT_CLIENT_LOCK = ReentrantLock()
const _DEFAULT_CLIENT = Ref{Union{Nothing, Client}}(nothing)

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

function _status_throws(resp::ClientResponse)::Bool
    return resp.status >= 300
end

function _header_pairs(headers::Headers)::Vector{Pair{String, String}}
    out = Pair{String, String}[]
    for key in header_keys(headers)
        values = get_headers(headers, key)
        for value in values
            push!(out, key => value)
        end
    end
    return out
end

function _read_response_body_bytes!(body::AbstractBody)::Vector{UInt8}
    out = UInt8[]
    buf = Vector{UInt8}(undef, 8192)
    try
        while true
            n = body_read!(body, buf)
            n == 0 && break
            append!(out, @view(buf[1:n]))
        end
    finally
        try
            body_close!(body)
        catch
        end
    end
    return out
end

function _add_header_value!(headers::Headers, key, value)
    key_s = String(key)
    if value isa AbstractVector && !(value isa AbstractString)
        for item in value
            add_header!(headers, key_s, String(item))
        end
        return nothing
    end
    add_header!(headers, key_s, String(value))
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

function _normalize_body_input(body_input)::Tuple{AbstractBody, Int64}
    body_input === nothing && return EmptyBody(), Int64(0)
    body_input isa EmptyBody && return EmptyBody(), Int64(0)
    if body_input isa BytesBody
        cloned = _clone_bytes_body(body_input::BytesBody)
        remaining = (length(cloned.data) - cloned.next_index) + 1
        return cloned, Int64(max(0, remaining))
    end
    if body_input isa AbstractString
        bytes = collect(codeunits(String(body_input)))
        return BytesBody(bytes), Int64(length(bytes))
    end
    if body_input isa AbstractVector{UInt8}
        bytes = Vector{UInt8}(body_input)
        return BytesBody(bytes), Int64(length(bytes))
    end
    if body_input isa IO
        bytes = read(body_input)
        return BytesBody(bytes), Int64(length(bytes))
    end
    throw(ArgumentError("unsupported request body type $(typeof(body_input)); expected nothing, String, Vector{UInt8}, IO, or HTTP.AbstractBody"))
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
    s = String(url)
    scheme_idx = findfirst("://", s)
    scheme_idx === nothing && throw(ArgumentError("URL must include http:// or https:// scheme: $s"))
    scheme_start = first(scheme_idx)
    scheme_end = last(scheme_idx)
    scheme = lowercase(String(SubString(s, firstindex(s), prevind(s, scheme_start))))
    secure = if scheme == "http"
        false
    elseif scheme == "https"
        true
    else
        throw(ArgumentError("unsupported URL scheme '$scheme'; expected http or https"))
    end
    rest_start = nextind(s, scheme_end)
    rest_start > lastindex(s) && throw(ArgumentError("URL missing authority: $s"))
    rest = String(SubString(s, rest_start, lastindex(s)))
    fragment_idx = findfirst('#', rest)
    fragment_idx === nothing || (rest = String(SubString(rest, firstindex(rest), prevind(rest, fragment_idx))))
    sep = findfirst(c -> c == '/' || c == '?', rest)
    authority = ""
    target = "/"
    if sep === nothing
        authority = rest
    else
        authority = String(SubString(rest, firstindex(rest), prevind(rest, sep)))
        raw_target = String(SubString(rest, sep, lastindex(rest)))
        if startswith(raw_target, "?")
            target = string("/", raw_target)
        else
            target = raw_target
        end
    end
    authorization = nothing
    at_idx = findlast('@', authority)
    if at_idx !== nothing
        user_info = String(SubString(authority, firstindex(authority), prevind(authority, at_idx)))
        authority = String(SubString(authority, nextind(authority, at_idx), lastindex(authority)))
        if !isempty(user_info)
            parts = split(user_info, ':'; limit = 2)
            username = parts[1]
            password = length(parts) == 2 ? parts[2] : ""
            authorization = "Basic " * base64encode(string(username, ":", password))
        end
    end
    isempty(authority) && throw(ArgumentError("URL missing host: $s"))
    address = ""
    if startswith(authority, "[")
        if occursin("]:", authority)
            address = authority
        else
            close_idx = findfirst(']', authority)
            close_idx === nothing && throw(ArgumentError("invalid IPv6 host authority: $authority"))
            host = String(SubString(authority, nextind(authority, firstindex(authority)), prevind(authority, close_idx)))
            address = HostResolvers.join_host_port(host, secure ? 443 : 80)
        end
    else
        address = occursin(':', authority) ? authority : HostResolvers.join_host_port(authority, secure ? 443 : 80)
    end
    target = _append_query(target, query)
    host, _ = HostResolvers.split_host_port(address)
    full_url = string(scheme, "://", address, target)
    return _URLParts(secure, address, target, host, full_url, authorization)
end

function _method_upper(method::AbstractString)::String
    return uppercase(String(method))
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
        max_idle_per_host = 1,
        max_idle_total = 1,
        idle_timeout_ns = Int64(0),
    )
    return Client(transport = transport), true
end

function _validate_request_extra_kwargs(kwargs)
    for (k, v) in kwargs
        if k == :retry
            if v isa Bool && !v
                continue
            end
            throw(ArgumentError("retry keyword is not implemented yet; pass retry=false"))
        end
        if k == :verbose || k == :decompress || k == :canonicalize_headers || k == :logerrors || k == :observelayers
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

"""
    request(method, url, headers=Pair{String,String}[], body=nothing; kwargs...)

High-level one-shot HTTP request API (similar shape to HTTP.jl convenience methods).
"""
function request(
        method::AbstractString,
        url::AbstractString,
        headers = Pair{String, String}[],
        body = nothing;
        status_exception::Bool = true,
        redirect::Bool = true,
        query = nothing,
        client::Union{Nothing, Client} = nothing,
        connect_timeout::Real = 0,
        readtimeout::Real = 0,
        require_ssl_verification::Bool = true,
        protocol::Symbol = :auto,
        kwargs...,
    )::ClientResponse
    _validate_request_extra_kwargs(kwargs)
    readtimeout >= 0 || throw(ArgumentError("readtimeout must be >= 0"))
    parsed = _parse_http_url(url; query = query)
    req_headers = _normalize_headers_input(headers)
    if parsed.authorization !== nothing && !has_header(req_headers, "Authorization")
        set_header!(req_headers, "Authorization", parsed.authorization::String)
    end
    req_body, content_length = _normalize_body_input(body)
    req = Request(
        _method_upper(method),
        parsed.target;
        headers = req_headers,
        body = req_body,
        host = parsed.address,
        content_length = content_length,
    )
    if readtimeout > 0
        timeout_ns = Int64(round(readtimeout * 1.0e9))
        set_deadline!(req.context, Int64(time_ns()) + timeout_ns)
    end
    req_client, owns_client = _client_for_request(client; connect_timeout = connect_timeout, require_ssl_verification = require_ssl_verification)
    low_level_response = nothing
    try
        if redirect
            low_level_response = do!(
                req_client,
                parsed.address,
                req;
                secure = parsed.secure,
                server_name = parsed.server_name,
                protocol = protocol,
            )
        else
            low_level_response = roundtrip!(
                req_client.transport,
                parsed.address,
                req;
                secure = parsed.secure,
                server_name = parsed.server_name,
            )
        end
        response_body = _read_response_body_bytes!((low_level_response::Response).body)
        resolved_request = low_level_response.request === nothing ? req : low_level_response.request::Request
        response = ClientResponse(
            low_level_response.status_code,
            _header_pairs(low_level_response.headers),
            response_body,
            resolved_request,
            parsed.url,
        )
        status_exception && _status_throws(response) && throw(StatusError(response))
        return response
    finally
        owns_client && close(req_client)
    end
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
