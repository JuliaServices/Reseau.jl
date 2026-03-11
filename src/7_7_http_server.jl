# Shared HTTP server kernel for HTTP/1, TLS, and HTTP/2.
export Server
export Stream
export listen
export listen!
export serve
export serve!
export forceclose
export port

using EnumX: @enumx
using ..Reseau.TCP
using ..Reseau.TLS
using ..Reseau.HostResolvers
using ..Reseau.IOPoll

@enumx _ServerState::UInt8 begin
    INITIAL = 0
    RUNNING = 1
    CLOSING = 2
    CLOSED = 3
end

@enumx _ConnState::UInt8 begin
    NEW = 0
    ACTIVE = 1
    IDLE = 2
    HIJACKED = 3
    CLOSED = 4
end

@enumx _StreamType::UInt8 begin
    CLIENT = 0
    SERVER = 1
end

@enumx _ServerStreamWriteMode::UInt8 begin
    UNDECIDED = 0
    NONE = 1
    FIXED = 2
    CHUNKED = 3
    IDENTITY = 4
end

mutable struct _ServerConn
    conn::Union{TCP.Conn, TLS.Conn}
    @atomic state::_ConnState.T
    @atomic state_unix_sec::Int64
end

Base.hash(conn::_ServerConn, h::UInt) = hash(objectid(conn), h)
Base.:(==)(a::_ServerConn, b::_ServerConn) = a === b

mutable struct Server{F}
    network::String
    address::String
    handler::F
    stream::Bool
    read_timeout_ns::Int64
    read_header_timeout_ns::Int64
    write_timeout_ns::Int64
    idle_timeout_ns::Int64
    max_header_bytes::Int
    listenany::Bool
    reuseaddr::Bool
    backlog::Int
    lock::ReentrantLock
    listener::Union{Nothing, TCP.Listener, TLS.Listener}
    serve_task::Union{Nothing, Task}
    active_conns::Set{_ServerConn}
    bound_address::Union{Nothing, String}
    bound_port::Int
    @atomic state::_ServerState.T
end

function Server(;
        network::AbstractString = "tcp",
        address::AbstractString = "127.0.0.1:0",
        handler::F,
        stream::Bool = false,
        read_timeout_ns::Integer = Int64(0),
        read_header_timeout_ns::Integer = Int64(0),
        write_timeout_ns::Integer = Int64(0),
        idle_timeout_ns::Integer = Int64(0),
        max_header_bytes::Integer = 1 * 1024 * 1024,
        listenany::Bool = false,
        reuseaddr::Bool = true,
        backlog::Integer = 128,
    ) where {F}
    read_timeout_ns >= 0 || throw(ArgumentError("read_timeout_ns must be >= 0"))
    read_header_timeout_ns >= 0 || throw(ArgumentError("read_header_timeout_ns must be >= 0"))
    write_timeout_ns >= 0 || throw(ArgumentError("write_timeout_ns must be >= 0"))
    idle_timeout_ns >= 0 || throw(ArgumentError("idle_timeout_ns must be >= 0"))
    max_header_bytes > 0 || throw(ArgumentError("max_header_bytes must be > 0"))
    backlog > 0 || throw(ArgumentError("backlog must be > 0"))
    return Server{F}(
        String(network),
        String(address),
        handler,
        stream,
        Int64(read_timeout_ns),
        Int64(read_header_timeout_ns),
        Int64(write_timeout_ns),
        Int64(idle_timeout_ns),
        Int(max_header_bytes),
        listenany,
        reuseaddr,
        Int(backlog),
        ReentrantLock(),
        nothing,
        nothing,
        Set{_ServerConn}(),
        nothing,
        0,
        _ServerState.INITIAL,
    )
end

mutable struct Stream <: IO
    side::_StreamType.T
    method::Union{Nothing, String}
    parsed::Union{Nothing, _URLParts}
    headers::Union{Nothing, Headers}
    client::Union{Nothing, Client}
    owns_client::Bool
    proxy_config::ProxyConfig
    cookies::Union{Bool, Vector{Cookie}}
    cookiejar::Union{Nothing, CookieJar}
    redirect::Bool
    redirect_policy::Union{Nothing, _RedirectPolicy}
    protocol::Symbol
    decompress::Union{Nothing, Bool}
    readtimeout::Float64
    request_buffer::IOBuffer
    response::Union{Nothing, Response}
    reader::Union{Nothing, IO}
    producer::Union{Nothing, Task}
    server::Union{Nothing, Server}
    tracked::Union{Nothing, _ServerConn}
    request::Union{Nothing, Request}
    @atomic started::Bool
    @atomic write_closed::Bool
    @atomic read_closed::Bool
    @atomic response_started::Bool
    @atomic continue_sent::Bool
    ignore_writes::Bool
    write_mode::_ServerStreamWriteMode.T
    written_bytes::Int64
end

function Stream(server::Server, tracked::_ServerConn, request::Request)
    response = Response(
        200;
        proto_major = Int(request.proto_major),
        proto_minor = Int(request.proto_minor),
        request = request,
    )
    return Stream(
        _StreamType.SERVER,
        nothing,
        nothing,
        nothing,
        nothing,
        false,
        ProxyConfig(),
        true,
        nothing,
        false,
        nothing,
        :auto,
        nothing,
        0.0,
        IOBuffer(),
        response,
        nothing,
        nothing,
        server,
        tracked,
        request,
        false,
        false,
        false,
        false,
        false,
        false,
        _ServerStreamWriteMode.UNDECIDED,
        Int64(0),
    )
end

@inline function _server_state(server::Server)::_ServerState.T
    return @atomic :acquire server.state
end

@inline function _set_server_state!(server::Server, state::_ServerState.T)::Nothing
    @atomic :release server.state = state
    return nothing
end

@inline function _conn_state(conn::_ServerConn)::_ConnState.T
    return @atomic :acquire conn.state
end

@inline function _set_conn_state!(conn::_ServerConn, state::_ConnState.T)::Nothing
    @atomic :release conn.state = state
    @atomic :release conn.state_unix_sec = floor(Int64, time())
    return nothing
end

@inline function _server_shutting_down(server::Server)::Bool
    state = _server_state(server)
    return state == _ServerState.CLOSING || state == _ServerState.CLOSED
end

function _require_server_stream(stream::Stream)::Nothing
    stream.side == _StreamType.SERVER && return nothing
    throw(ArgumentError("operation is only valid for server-side HTTP streams"))
end

"""
    server_addr(server) -> String

Return the bound `host:port` address for a listening server.
"""
function server_addr(server::Server)::String
    lock(server.lock)
    try
        server.bound_address === nothing && throw(ProtocolError("server is not listening"))
        return server.bound_address::String
    finally
        unlock(server.lock)
    end
end

"""
    port(server) -> Int

Return the bound port for `server`, or the configured port if it has not started
listening yet.
"""
function port(server::Server)::Int
    lock(server.lock)
    try
        if server.bound_port != 0
            return server.bound_port
        end
        try
            _, port_num = HostResolvers.split_host_port(server.address)
            return port_num
        catch
            return 0
        end
    finally
        unlock(server.lock)
    end
end

"""
    isopen(server) -> Bool

Return `true` while `server` can still accept or finish serving connections.
"""
function Base.isopen(server::Server)::Bool
    state = _server_state(server)
    state == _ServerState.CLOSED && return false
    lock(server.lock)
    try
        listener = server.listener
        listener === nothing && return state == _ServerState.INITIAL
        return state == _ServerState.RUNNING
    finally
        unlock(server.lock)
    end
end

"""
    wait(server)

Block until the server task exits.
"""
function Base.wait(server::Server)::Nothing
    task = nothing
    lock(server.lock)
    try
        task = server.serve_task
    finally
        unlock(server.lock)
    end
    task === nothing && return nothing
    wait(task::Task)
    return nothing
end

function _listener_addr(listener::Union{TCP.Listener, TLS.Listener})
    if listener isa TLS.Listener
        return TLS.addr(listener::TLS.Listener)
    end
    return TCP.addr(listener::TCP.Listener)
end

function _listener_bound_address(listener::Union{TCP.Listener, TLS.Listener})::Tuple{String, Int}
    laddr = _listener_addr(listener)
    laddr === nothing && return ("", 0)
    return (sprint(show, laddr), Int(laddr.port))
end

function _accept_server_conn!(listener::Union{TCP.Listener, TLS.Listener})
    if listener isa TLS.Listener
        return TLS.accept!(listener::TLS.Listener)
    end
    return TCP.accept!(listener::TCP.Listener)
end

function _close_server_transport!(conn::Union{TCP.Conn, TLS.Conn})::Nothing
    if conn isa TLS.Conn
        TLS.close!(conn::TLS.Conn)
    else
        TCP.close!(conn::TCP.Conn)
    end
    return nothing
end

function _close_server_write!(conn::Union{TCP.Conn, TLS.Conn})::Nothing
    if conn isa TLS.Conn
        TLS.close_write!(conn::TLS.Conn)
    else
        TCP.close_write!(conn::TCP.Conn)
    end
    return nothing
end

function _close_server_listener!(listener::Union{TCP.Listener, TLS.Listener})::Nothing
    if listener isa TLS.Listener
        TLS.close!(listener::TLS.Listener)
    else
        TCP.close!(listener::TCP.Listener)
    end
    return nothing
end

function _set_read_deadline!(conn::Union{TCP.Conn, TLS.Conn}, deadline_ns::Int64)::Nothing
    if conn isa TLS.Conn
        TLS.set_read_deadline!(conn::TLS.Conn, deadline_ns)
    else
        TCP.set_read_deadline!(conn::TCP.Conn, deadline_ns)
    end
    return nothing
end

function _set_write_deadline!(conn::Union{TCP.Conn, TLS.Conn}, deadline_ns::Int64)::Nothing
    if conn isa TLS.Conn
        TLS.set_write_deadline!(conn::TLS.Conn, deadline_ns)
    else
        TCP.set_write_deadline!(conn::TCP.Conn, deadline_ns)
    end
    return nothing
end

function _set_deadline!(conn::Union{TCP.Conn, TLS.Conn}, deadline_ns::Int64)::Nothing
    if conn isa TLS.Conn
        TLS.set_deadline!(conn::TLS.Conn, deadline_ns)
    else
        TCP.set_deadline!(conn::TCP.Conn, deadline_ns)
    end
    return nothing
end

function _listen_address(server::Server)::String
    !server.listenany && return server.address
    host, _ = HostResolvers.split_host_port(server.address)
    return HostResolvers.join_host_port(host, 0)
end

function _track_conn!(server::Server, tracked::_ServerConn)::Nothing
    lock(server.lock)
    try
        push!(server.active_conns, tracked)
    finally
        unlock(server.lock)
    end
    return nothing
end

function _untrack_conn!(server::Server, tracked::_ServerConn)::Nothing
    lock(server.lock)
    try
        delete!(server.active_conns, tracked)
    finally
        unlock(server.lock)
    end
    return nothing
end

function _server_conns(server::Server)::Vector{_ServerConn}
    tracked = _ServerConn[]
    lock(server.lock)
    try
        append!(tracked, server.active_conns)
    finally
        unlock(server.lock)
    end
    return tracked
end

function _close_server_conn!(tracked::_ServerConn)::Nothing
    _set_conn_state!(tracked, _ConnState.CLOSED)
    try
        _close_server_transport!(tracked.conn)
    catch
    end
    return nothing
end

function _close_listener!(server::Server)::Nothing
    listener = nothing
    lock(server.lock)
    try
        listener = server.listener
        server.listener = nothing
    finally
        unlock(server.lock)
    end
    listener === nothing && return nothing
    try
        _close_server_listener!(listener::Union{TCP.Listener, TLS.Listener})
    catch
    end
    return nothing
end

function _close_idle_conns!(server::Server)::Bool
    tracked_conns = _server_conns(server)
    isempty(tracked_conns) && return true
    now_sec = floor(Int64, time())
    for tracked in tracked_conns
        state = _conn_state(tracked)
        if state == _ConnState.IDLE
            _close_server_conn!(tracked)
            continue
        end
        if state == _ConnState.NEW
            state_sec = @atomic :acquire tracked.state_unix_sec
            if state_sec != 0 && state_sec < now_sec - 5
                _close_server_conn!(tracked)
            end
        end
    end
    return isempty(_server_conns(server))
end

function _begin_shutdown!(server::Server)::Bool
    lock(server.lock)
    try
        state = _server_state(server)
        if state == _ServerState.CLOSING || state == _ServerState.CLOSED
            return false
        end
        _set_server_state!(server, _ServerState.CLOSING)
        return true
    finally
        unlock(server.lock)
    end
end

"""
    forceclose(server)

Immediately stop accepting new connections and close all tracked connections.
"""
function forceclose(server::Server)::Nothing
    initiated = _begin_shutdown!(server)
    _close_listener!(server)
    for tracked in _server_conns(server)
        _close_server_conn!(tracked)
    end
    wait(server)
    _set_server_state!(server, _ServerState.CLOSED)
    return nothing
end

"""
    close(server)

Gracefully stop accepting new connections, wait for active work to quiesce, and
then close the remaining tracked connections.
"""
function Base.close(server::Server)::Nothing
    state = _server_state(server)
    state == _ServerState.CLOSED && return nothing
    initiated = _begin_shutdown!(server)
    _close_listener!(server)
    wait(server)
    poll_s = 0.001
    while true
        _close_idle_conns!(server) && break
        sleep(poll_s)
        poll_s < 0.5 && (poll_s = min(poll_s * 2, 0.5))
    end
    _set_server_state!(server, _ServerState.CLOSED)
    return nothing
end

function _set_read_deadline_for_header!(server::Server, conn::Union{TCP.Conn, TLS.Conn})::Nothing
    timeout = server.read_header_timeout_ns > 0 ? server.read_header_timeout_ns : server.read_timeout_ns
    timeout <= 0 && return nothing
    _set_read_deadline!(conn, Int64(time_ns()) + timeout)
    return nothing
end

function _set_read_deadline_for_body!(server::Server, conn::Union{TCP.Conn, TLS.Conn})::Nothing
    timeout = server.read_timeout_ns
    timeout <= 0 && return nothing
    _set_read_deadline!(conn, Int64(time_ns()) + timeout)
    return nothing
end

function _set_idle_deadline!(server::Server, conn::Union{TCP.Conn, TLS.Conn})::Nothing
    timeout = server.idle_timeout_ns > 0 ? server.idle_timeout_ns : server.read_timeout_ns
    timeout <= 0 && return nothing
    _set_read_deadline!(conn, Int64(time_ns()) + timeout)
    return nothing
end

function _set_write_deadline!(server::Server, conn::Union{TCP.Conn, TLS.Conn})::Nothing
    timeout = server.write_timeout_ns
    timeout <= 0 && return nothing
    _set_write_deadline!(conn, Int64(time_ns()) + timeout)
    return nothing
end

function _clear_deadlines!(conn::Union{TCP.Conn, TLS.Conn})::Nothing
    try
        _set_deadline!(conn, Int64(0))
    catch
    end
    return nothing
end

@inline function _request_wants_close(request::Request)::Bool
    request.close && return true
    return has_header_token(request.headers, "Connection", "close")
end

@inline function _response_wants_close(response::Response)::Bool
    response.close && return true
    return has_header_token(response.headers, "Connection", "close")
end

@inline function _request_body_fully_consumed(request::Request)::Bool
    body = request.body
    body isa EmptyBody && return true
    if body isa FixedLengthBody
        return (body::FixedLengthBody).remaining == 0
    end
    if body isa ChunkedBody
        return (body::ChunkedBody).done
    end
    body isa EOFBody && return false
    return false
end

function _write_all_response!(conn::Union{TCP.Conn, TLS.Conn}, response::Response)::Nothing
    io = IOBuffer()
    write_response!(io, response)
    bytes = take!(io)
    total = 0
    while total < length(bytes)
        n = write(conn, bytes[(total + 1):end])
        n > 0 || throw(ProtocolError("server write made no progress"))
        total += n
    end
    return nothing
end

function _server_error_status(err::Exception)::Union{Nothing, Int}
    if err isa ParseError
        return 400
    end
    if err isa ProtocolError
        message = sprint(showerror, err)
        if occursin("max_header_bytes", message) || occursin("max_line_bytes", message)
            return 431
        end
        return 400
    end
    if err isa IOPoll.DeadlineExceededError
        return 408
    end
    return nothing
end

function _try_write_server_error!(conn::Union{TCP.Conn, TLS.Conn}, request::Union{Nothing, Request}, status_code::Int)::Nothing
    response = Response(
        status_code;
        close = true,
        content_length = 0,
        request = request,
    )
    try
        _write_all_response!(conn, response)
    catch
    end
    try
        _close_server_write!(conn)
    catch
    end
    return nothing
end

function _server_stream_allows_body(stream::Stream)::Bool
    _require_server_stream(stream)
    _body_allowed_for_status(stream.response.status_code) || return false
    stream.request.method == "HEAD" && return false
    return true
end

function _server_stream_write_mode(stream::Stream)::_ServerStreamWriteMode.T
    # Framing is chosen late so explicit response headers win, while unread
    # request bodies still force connection close independently of write mode.
    allows_body = _server_stream_allows_body(stream)
    allows_body || return _ServerStreamWriteMode.NONE
    has_header_token(stream.response.headers, "Transfer-Encoding", "chunked") && return _ServerStreamWriteMode.CHUNKED
    if has_header(stream.response.headers, "Content-Length") || stream.response.content_length >= 0
        return _ServerStreamWriteMode.FIXED
    end
    if stream.response.proto_major == UInt8(1) && stream.response.proto_minor == UInt8(0)
        stream.response.close = true
        return _ServerStreamWriteMode.IDENTITY
    end
    return _ServerStreamWriteMode.CHUNKED
end

function _write_server_stream_bytes!(stream::Stream, bytes::AbstractVector{UInt8})::Nothing
    isempty(bytes) && return nothing
    data = bytes isa Vector{UInt8} ? bytes : Vector{UInt8}(bytes)
    _set_write_deadline!(stream.server, stream.tracked.conn)
    total = 0
    while total < length(data)
        chunk = total == 0 ? data : data[(total + 1):end]
        n = write(stream.tracked.conn, chunk)
        n > 0 || throw(ProtocolError("server stream write made no progress"))
        total += n
    end
    return nothing
end

function _write_server_stream_head!(stream::Stream)::Nothing
    headers = copy(stream.response.headers)
    response_close = stream.response.close || _should_close_connection(headers, stream.response.proto_major, stream.response.proto_minor)
    response_close && set_header!(headers, "Connection", "close")
    mode = _server_stream_write_mode(stream)
    stream.write_mode = mode
    if mode == _ServerStreamWriteMode.NONE
        delete_header!(headers, "Content-Length")
        delete_header!(headers, "Transfer-Encoding")
    elseif mode == _ServerStreamWriteMode.FIXED
        if stream.response.content_length >= 0
            set_header!(headers, "Content-Length", string(stream.response.content_length))
        end
    elseif mode == _ServerStreamWriteMode.CHUNKED
        delete_header!(headers, "Content-Length")
        set_header!(headers, "Transfer-Encoding", "chunked")
        _prepare_trailer_header!(headers, stream.response.trailers)
    else
        delete_header!(headers, "Content-Length")
        delete_header!(headers, "Transfer-Encoding")
    end
    io = IOBuffer()
    _write_status_line!(io, stream.response)
    _write_headers!(io, headers)
    write(io, "\r\n")
    _write_server_stream_bytes!(stream, take!(io))
    @atomic :release stream.response_started = true
    return nothing
end

function _server_startread(stream::Stream)::Request
    _require_server_stream(stream)
    return stream.request
end

function _maybe_write_continue!(stream::Stream)::Nothing
    _require_server_stream(stream)
    already_sent = @atomic :acquire stream.continue_sent
    already_sent && return nothing
    # We only acknowledge `Expect: 100-continue` once the handler actually tries
    # to consume the request body.
    has_header_token(stream.request.headers, "Expect", "100-continue") || return nothing
    _request_body_fully_consumed(stream.request) && return nothing
    response = Response(
        100;
        proto_major = Int(stream.request.proto_major),
        proto_minor = Int(stream.request.proto_minor),
        content_length = 0,
        request = stream.request,
    )
    _write_all_response!(stream.tracked.conn, response)
    @atomic :release stream.continue_sent = true
    return nothing
end

function _server_isopen(stream::Stream)::Bool
    _require_server_stream(stream)
    return !(@atomic :acquire stream.read_closed) || !(@atomic :acquire stream.write_closed)
end

function _server_eof(stream::Stream)::Bool
    _require_server_stream(stream)
    return _request_body_fully_consumed(stream.request)
end

function _server_readbytes!(stream::Stream, dest::AbstractVector{UInt8}, nb::Integer = length(dest))
    _require_server_stream(stream)
    nb >= 0 || throw(ArgumentError("nb must be >= 0"))
    nb == 0 && return 0
    nb <= length(dest) || throw(ArgumentError("nb must be <= length(dest)"))
    _maybe_write_continue!(stream)
    buf = Vector{UInt8}(undef, nb)
    n = body_read!(stream.request.body, buf)
    n == 0 && (@atomic :release stream.read_closed = true)
    n > 0 && copyto!(dest, 1, buf, 1, n)
    _request_body_fully_consumed(stream.request) && (@atomic :release stream.read_closed = true)
    return n
end

function _server_read(stream::Stream)::Vector{UInt8}
    _require_server_stream(stream)
    _maybe_write_continue!(stream)
    out = UInt8[]
    buf = Vector{UInt8}(undef, 16 * 1024)
    while true
        n = body_read!(stream.request.body, buf)
        n == 0 && break
        append!(out, @view(buf[1:n]))
    end
    @atomic :release stream.read_closed = true
    return out
end

function setstatus(stream::Stream, status::Integer)::Nothing
    _require_server_stream(stream)
    (@atomic :acquire stream.response_started) && throw(ArgumentError("cannot change status after response writing has started"))
    stream.response.status_code = Int(status)
    return nothing
end

function setheader(stream::Stream, key::AbstractString, value::AbstractString)::Nothing
    _require_server_stream(stream)
    (@atomic :acquire stream.response_started) && throw(ArgumentError("cannot change headers after response writing has started"))
    set_header!(stream.response.headers, key, value)
    return nothing
end

function setheader(stream::Stream, header::Pair{<:AbstractString, <:AbstractString})::Nothing
    return setheader(stream, header.first, header.second)
end

function addtrailer(stream::Stream, trailers::Headers)::Nothing
    _require_server_stream(stream)
    for key in header_keys(trailers)
        values = get_headers(trailers, key)
        for value in values
            add_header!(stream.response.trailers, key, value)
        end
    end
    return nothing
end

function addtrailer(stream::Stream, header::Pair{<:AbstractString, <:AbstractString})::Nothing
    _require_server_stream(stream)
    add_header!(stream.response.trailers, header.first, header.second)
    return nothing
end

function addtrailer(stream::Stream, headers::AbstractVector{<:Pair})::Nothing
    for header in headers
        addtrailer(stream, header)
    end
    return nothing
end

function startwrite(stream::Stream)::Response
    _require_server_stream(stream)
    started = @atomic :acquire stream.response_started
    started && return stream.response
    !_request_body_fully_consumed(stream.request) && (stream.response.close = true)
    !_server_stream_allows_body(stream) && (stream.ignore_writes = true)
    _write_server_stream_head!(stream)
    return stream.response
end

function _server_write(stream::Stream, data::AbstractVector{UInt8})::Int
    _require_server_stream(stream)
    (@atomic :acquire stream.write_closed) && throw(ArgumentError("response writes are closed"))
    startwrite(stream)
    stream.ignore_writes && return length(data)
    if stream.write_mode == _ServerStreamWriteMode.CHUNKED
        io = IOBuffer()
        print(io, string(length(data), base = 16), "\r\n")
        write(io, data)
        write(io, "\r\n")
        _write_server_stream_bytes!(stream, take!(io))
    else
        _write_server_stream_bytes!(stream, data)
    end
    stream.written_bytes += length(data)
    return length(data)
end

function _server_write(stream::Stream, data::Union{String, SubString{String}})::Int
    return _server_write(stream, Vector{UInt8}(codeunits(String(data))))
end

function _server_closewrite(stream::Stream)::Nothing
    _require_server_stream(stream)
    was_closed = @atomic :acquire stream.write_closed
    was_closed && return nothing
    startwrite(stream)
    if stream.write_mode == _ServerStreamWriteMode.CHUNKED
        io = IOBuffer()
        write(io, "0\r\n")
        _write_headers!(io, stream.response.trailers)
        write(io, "\r\n")
        _write_server_stream_bytes!(stream, take!(io))
    elseif stream.write_mode == _ServerStreamWriteMode.FIXED
        if stream.response.content_length >= 0 && stream.written_bytes != stream.response.content_length
            throw(ProtocolError("response body bytes did not match Content-Length"))
        end
    end
    @atomic :release stream.write_closed = true
    return nothing
end

function _server_closeread(stream::Stream)::Response
    _require_server_stream(stream)
    already_closed = @atomic :acquire stream.read_closed
    already_closed && return stream.response
    if !_request_body_fully_consumed(stream.request)
        stream.response.close = true
        try
            body_close!(stream.request.body)
        catch
        end
    end
    @atomic :release stream.read_closed = true
    return stream.response
end

function _server_close(stream::Stream)::Nothing
    _require_server_stream(stream)
    try
        _server_closewrite(stream)
    catch
    end
    try
        _server_closeread(stream)
    catch
    end
    return nothing
end

function _write_response_body_to_stream!(stream::Stream, body)::Nothing
    body === nothing && return nothing
    if body isa EmptyBody
        return nothing
    end
    if body isa AbstractString
        write(stream, body::AbstractString)
        return nothing
    end
    if body isa AbstractVector{UInt8}
        write(stream, body::AbstractVector{UInt8})
        return nothing
    end
    if body isa AbstractBody
        buf = Vector{UInt8}(undef, 16 * 1024)
        try
            while true
                n = body_read!(body::AbstractBody, buf)
                n == 0 && break
                write(stream, @view(buf[1:n]))
            end
        finally
            try
                body_close!(body::AbstractBody)
            catch
            end
        end
        return nothing
    end
    throw(ProtocolError("unsupported stream response body type $(typeof(body))"))
end

const _H2_SERVER_MAX_DATA_FRAME_SIZE = 16_384

mutable struct _ServerPrefaceConn{C} <: IO
    prefix::Vector{UInt8}
    next::Int
    conn::C
end

function _ServerPrefaceConn(prefix::Vector{UInt8}, conn::C) where {C}
    return _ServerPrefaceConn{C}(prefix, 1, conn)
end

function Base.read!(conn::_ServerPrefaceConn, dst::Vector{UInt8})::Int
    isempty(dst) && return 0
    available = (length(conn.prefix) - conn.next) + 1
    if available > 0
        n = min(length(dst), available)
        copyto!(dst, 1, conn.prefix, conn.next, n)
        conn.next += n
        return n
    end
    return read!(conn.conn, dst)
end

function _h2_preface_prefix_matches(prefix::Vector{UInt8})::Bool
    @inbounds for i in 1:length(prefix)
        prefix[i] == _H2_PREFACE[i] || return false
    end
    return true
end

function _probe_h2_preface!(server::Server, conn::TCP.Conn)::Tuple{Bool, _ServerPrefaceConn{TCP.Conn}}
    # Cleartext HTTP/2 has no ALPN, so we sniff enough of the connection preface
    # to choose h2 and replay the same bytes into the h1 parser otherwise.
    _set_read_deadline_for_header!(server, conn)
    prefix = UInt8[]
    while length(prefix) < length(_H2_PREFACE)
        chunk = Vector{UInt8}(undef, length(_H2_PREFACE) - length(prefix))
        n = read!(conn, chunk)
        n > 0 || break
        append!(prefix, @view(chunk[1:n]))
        _h2_preface_prefix_matches(prefix) || return false, _ServerPrefaceConn(prefix, conn)
        length(prefix) == length(_H2_PREFACE) && return true, _ServerPrefaceConn(prefix, conn)
    end
    return false, _ServerPrefaceConn(prefix, conn)
end

function _write_all_h2_server!(conn::Union{TCP.Conn, TLS.Conn}, bytes::Vector{UInt8})::Nothing
    total = 0
    while total < length(bytes)
        chunk = total == 0 ? bytes : bytes[(total + 1):end]
        n = write(conn, chunk)
        n > 0 || throw(ProtocolError("h2 server write made no progress"))
        total += n
    end
    return nothing
end

function _write_frame_h2_server!(conn::Union{TCP.Conn, TLS.Conn}, frame::AbstractFrame)::Nothing
    io = IOBuffer()
    framer = Framer(io)
    write_frame!(framer, frame)
    _write_all_h2_server!(conn, take!(io))
    return nothing
end

function _write_data_frames_h2_server!(conn::Union{TCP.Conn, TLS.Conn}, stream_id::UInt32, data::Vector{UInt8}; end_stream::Bool)::Nothing
    isempty(data) && return nothing
    offset = 1
    total_len = length(data)
    while offset <= total_len
        remaining = total_len - offset + 1
        chunk_len = min(_H2_SERVER_MAX_DATA_FRAME_SIZE, remaining)
        chunk = Vector{UInt8}(undef, chunk_len)
        copyto!(chunk, 1, data, offset, chunk_len)
        final_chunk = (offset + chunk_len - 1) == total_len
        _write_frame_h2_server!(conn, DataFrame(stream_id, end_stream && final_chunk, chunk))
        offset += chunk_len
    end
    return nothing
end

function _read_exact_h2_server!(io, n::Int)::Vector{UInt8}
    out = Vector{UInt8}(undef, n)
    offset = 0
    while offset < n
        chunk = Vector{UInt8}(undef, n - offset)
        nr = read!(io, chunk)
        nr > 0 || throw(EOFError())
        copyto!(out, offset + 1, chunk, 1, nr)
        offset += nr
    end
    return out
end

function _decode_h2_request(headers::Vector{HeaderField}, body::Vector{UInt8})::Request
    method = "GET"
    path = "/"
    host = nothing
    out_headers = Headers()
    for header in headers
        if header.name == ":method"
            method = header.value
            continue
        end
        if header.name == ":path"
            path = header.value
            continue
        end
        if header.name == ":authority"
            host = header.value
            continue
        end
        add_header!(out_headers, header.name, header.value)
    end
    return Request(
        method,
        path;
        headers = out_headers,
        body = BytesBody(body),
        host = host,
        content_length = length(body),
        proto_major = 2,
        proto_minor = 0,
    )
end

function _encode_h2_response_headers(response::Response)::Vector{UInt8}
    header_fields = HeaderField[HeaderField(":status", string(response.status_code), false)]
    for key in header_keys(response.headers)
        values = get_headers(response.headers, key)
        for value in values
            push!(header_fields, HeaderField(lowercase(key), value, false))
        end
    end
    encoder = Encoder()
    return encode_header_block(encoder, header_fields)
end

function _write_response_body_h2_server!(conn::Union{TCP.Conn, TLS.Conn}, stream_id::UInt32, response::Response)::Nothing
    response.body isa EmptyBody && return nothing
    buf = Vector{UInt8}(undef, 16 * 1024)
    pending = UInt8[]
    have_pending = false
    try
        while true
            n = body_read!(response.body, buf)
            if n == 0
                if have_pending
                    _write_data_frames_h2_server!(conn, stream_id, pending; end_stream = true)
                else
                    _write_frame_h2_server!(conn, DataFrame(stream_id, true, UInt8[]))
                end
                return nothing
            end
            current = Vector{UInt8}(undef, n)
            copyto!(current, 1, buf, 1, n)
            if have_pending
                _write_data_frames_h2_server!(conn, stream_id, pending; end_stream = false)
            end
            pending = current
            have_pending = true
        end
    finally
        try
            body_close!(response.body)
        catch
        end
    end
end

function _handle_h2_stream!(server::Server, conn::Union{TCP.Conn, TLS.Conn}, stream_id::UInt32, header_block::Vector{UInt8}, body::Vector{UInt8}, decoder::Decoder)::Nothing
    decoded_headers = decode_header_block(decoder, header_block)
    request = _decode_h2_request(decoded_headers, body)
    response = server.handler(request)
    response isa Response || throw(ProtocolError("h2 server handler must return HTTP.Response"))
    response_obj = response::Response
    response_obj.request = request
    response_header_block = _encode_h2_response_headers(response_obj)
    end_stream = response_obj.body isa EmptyBody
    _write_frame_h2_server!(conn, HeadersFrame(stream_id, end_stream, true, response_header_block))
    end_stream || _write_response_body_h2_server!(conn, stream_id, response_obj)
    return nothing
end

function _serve_h2_conn!(server::Server, tracked::_ServerConn, reader_source)::Nothing
    conn = tracked.conn
    reader = Framer(_ConnReader(reader_source))
    decoder = Decoder()
    try
        preface = _read_exact_h2_server!(reader_source, length(_H2_PREFACE))
        preface == _H2_PREFACE || throw(ProtocolError("invalid h2 client preface"))
        client_settings = read_frame!(reader)
        client_settings isa SettingsFrame || throw(ProtocolError("expected initial h2 SETTINGS frame"))
        _write_frame_h2_server!(conn, SettingsFrame(false, Pair{UInt16, UInt32}[]))
        _write_frame_h2_server!(conn, SettingsFrame(true, Pair{UInt16, UInt32}[]))
        headers_block = Dict{UInt32, Vector{UInt8}}()
        body_block = Dict{UInt32, Vector{UInt8}}()
        headers_done = Dict{UInt32, Bool}()
        body_done = Dict{UInt32, Bool}()
        continuation_stream = UInt32(0)
        max_stream_id = UInt32(0)
        while !_server_shutting_down(server)
            frame = try
                read_frame!(reader)
            catch err
                if err isa EOFError || err isa IOPoll.NetClosingError || err isa ParseError || err isa TLS.TLSError
                    return nothing
                end
                rethrow(err)
            end
            if continuation_stream != UInt32(0)
                if !(frame isa ContinuationFrame && (frame::ContinuationFrame).stream_id == continuation_stream)
                    throw(ProtocolError("expected CONTINUATION for stream $(continuation_stream)"))
                end
            elseif frame isa ContinuationFrame
                throw(ProtocolError("unexpected CONTINUATION frame"))
            end
            if frame isa SettingsFrame
                sf = frame::SettingsFrame
                sf.ack || _write_frame_h2_server!(conn, SettingsFrame(true, Pair{UInt16, UInt32}[]))
                continue
            end
            if frame isa PingFrame
                ping = frame::PingFrame
                ping.ack || _write_frame_h2_server!(conn, PingFrame(true, ping.opaque_data))
                continue
            end
            if frame isa HeadersFrame
                hf = frame::HeadersFrame
                hf.stream_id == UInt32(0) && throw(ProtocolError("HEADERS stream id must be non-zero"))
                iseven(hf.stream_id) && throw(ProtocolError("HEADERS stream id must be odd for client-initiated streams"))
                if hf.stream_id < max_stream_id && !haskey(headers_block, hf.stream_id)
                    throw(ProtocolError("HEADERS stream id must increase monotonically"))
                end
                hf.stream_id > max_stream_id && (max_stream_id = hf.stream_id)
                headers_block[hf.stream_id] = get(() -> UInt8[], headers_block, hf.stream_id)
                append!(headers_block[hf.stream_id], hf.header_block_fragment)
                headers_done[hf.stream_id] = hf.end_headers
                !hf.end_headers && (continuation_stream = hf.stream_id)
                body_done[hf.stream_id] = hf.end_stream
                if get(() -> false, headers_done, hf.stream_id) && get(() -> false, body_done, hf.stream_id)
                    _handle_h2_stream!(server, conn, hf.stream_id, headers_block[hf.stream_id], get(() -> UInt8[], body_block, hf.stream_id), decoder)
                    delete!(headers_block, hf.stream_id)
                    delete!(headers_done, hf.stream_id)
                    haskey(body_block, hf.stream_id) && delete!(body_block, hf.stream_id)
                    haskey(body_done, hf.stream_id) && delete!(body_done, hf.stream_id)
                end
                continue
            end
            if frame isa ContinuationFrame
                cf = frame::ContinuationFrame
                cf.stream_id == UInt32(0) && throw(ProtocolError("CONTINUATION stream id must be non-zero"))
                existing = get(() -> UInt8[], headers_block, cf.stream_id)
                append!(existing, cf.header_block_fragment)
                headers_block[cf.stream_id] = existing
                headers_done[cf.stream_id] = cf.end_headers
                continuation_stream = cf.end_headers ? UInt32(0) : cf.stream_id
                if get(() -> false, headers_done, cf.stream_id) && get(() -> false, body_done, cf.stream_id)
                    _handle_h2_stream!(server, conn, cf.stream_id, headers_block[cf.stream_id], get(() -> UInt8[], body_block, cf.stream_id), decoder)
                    delete!(headers_block, cf.stream_id)
                    delete!(headers_done, cf.stream_id)
                    haskey(body_block, cf.stream_id) && delete!(body_block, cf.stream_id)
                    haskey(body_done, cf.stream_id) && delete!(body_done, cf.stream_id)
                end
                continue
            end
            if frame isa DataFrame
                df = frame::DataFrame
                df.stream_id == UInt32(0) && throw(ProtocolError("DATA stream id must be non-zero"))
                iseven(df.stream_id) && throw(ProtocolError("DATA stream id must be odd for client-initiated streams"))
                haskey(headers_block, df.stream_id) || throw(ProtocolError("DATA frame received before HEADERS"))
                existing = get(() -> UInt8[], body_block, df.stream_id)
                append!(existing, df.data)
                body_block[df.stream_id] = existing
                _write_frame_h2_server!(conn, WindowUpdateFrame(UInt32(0), UInt32(length(df.data))))
                _write_frame_h2_server!(conn, WindowUpdateFrame(df.stream_id, UInt32(length(df.data))))
                body_done[df.stream_id] = df.end_stream
                if get(() -> false, headers_done, df.stream_id) && get(() -> false, body_done, df.stream_id)
                    _handle_h2_stream!(server, conn, df.stream_id, headers_block[df.stream_id], body_block[df.stream_id], decoder)
                    delete!(headers_block, df.stream_id)
                    delete!(headers_done, df.stream_id)
                    delete!(body_block, df.stream_id)
                    delete!(body_done, df.stream_id)
                end
                continue
            end
        end
    catch err
        if err isa ProtocolError || err isa ParseError || err isa EOFError || err isa IOPoll.NetClosingError || err isa TLS.TLSError
            return nothing
        end
        rethrow(err)
    finally
        _clear_deadlines!(conn)
        _close_server_conn!(tracked)
        _untrack_conn!(server, tracked)
    end
    return nothing
end

function _serve_conn!(server::Server, tracked::_ServerConn)::Nothing
    entered_helper = false
    try
        conn = tracked.conn
        if conn isa TLS.Conn
            _set_read_deadline_for_header!(server, conn::TLS.Conn)
            # TLS needs an explicit handshake here so ALPN can pick h2 vs h1
            # before any HTTP parser commits to a protocol.
            TLS.handshake!(conn::TLS.Conn)
            proto = TLS.connection_state(conn::TLS.Conn).alpn_protocol
            entered_helper = true
            if proto == "h2"
                return _serve_h2_conn!(server, tracked, conn::TLS.Conn)
            end
            return _serve_h1_conn!(server, tracked, conn::TLS.Conn)
        end
        use_h2, reader_source = _probe_h2_preface!(server, conn::TCP.Conn)
        entered_helper = true
        if use_h2
            return _serve_h2_conn!(server, tracked, reader_source)
        end
        return _serve_h1_conn!(server, tracked, reader_source)
    catch err
        if err isa IOPoll.DeadlineExceededError
            _try_write_server_error!(tracked.conn, nothing, 408)
            return nothing
        end
        if err isa ParseError || err isa ProtocolError || err isa EOFError || err isa IOPoll.DeadlineExceededError || err isa IOPoll.NetClosingError || err isa TLS.TLSError || err isa TLS.TLSHandshakeTimeoutError
            return nothing
        end
        rethrow(err)
    finally
        if !entered_helper
            _clear_deadlines!(tracked.conn)
            _close_server_conn!(tracked)
            _untrack_conn!(server, tracked)
        end
    end
end

function _serve_h1_conn!(server::Server, tracked::_ServerConn, reader_source)::Nothing
    reader = _ConnReader(reader_source)
    try
        while true
            _server_shutting_down(server) && return nothing
            _set_read_deadline_for_header!(server, tracked.conn)
            request = try
                read_request(reader; max_header_bytes = server.max_header_bytes)
            catch err
                status_code = _server_error_status(err::Exception)
                status_code === nothing || _try_write_server_error!(tracked.conn, nothing, status_code::Int)
                if err isa ParseError || err isa ProtocolError || err isa EOFError || err isa IOPoll.DeadlineExceededError || err isa IOPoll.NetClosingError || err isa TLS.TLSError || err isa TLS.TLSHandshakeTimeoutError
                    return nothing
                end
                rethrow(err)
            end
            _set_conn_state!(tracked, _ConnState.ACTIVE)
            _set_read_deadline_for_body!(server, tracked.conn)
            if server.stream
                stream = Stream(server, tracked, request)
                try
                    server.handler(stream)
                    if !(@atomic :acquire stream.write_closed)
                        closewrite(stream)
                    end
                    closeread(stream)
                    _clear_deadlines!(tracked.conn)
                    _server_shutting_down(server) && return nothing
                    if _request_wants_close(request) || _response_wants_close(stream.response)
                        return nothing
                    end
                catch err
                    status_code = _server_error_status(err::Exception)
                    if !(@atomic :acquire stream.response_started)
                        try
                            setstatus(stream, status_code === nothing ? 500 : status_code::Int)
                            stream.response.close = true
                            startwrite(stream)
                            closewrite(stream)
                        catch
                        end
                    end
                    try
                        stream.response.close = true
                        close(stream)
                    catch
                    end
                    return nothing
                end
            else
                response = try
                    server.handler(request)
                catch err
                    status_code = _server_error_status(err::Exception)
                    _try_write_server_error!(tracked.conn, request, status_code === nothing ? 500 : status_code::Int)
                    return nothing
                end
                response isa Response || throw(ProtocolError("server handler must return HTTP.Response"))
                response_obj = response::Response
                response_obj.request = request
                if !_request_body_fully_consumed(request)
                    response_obj.close = true
                    try
                        body_close!(request.body)
                    catch
                    end
                end
                _set_write_deadline!(server, tracked.conn)
                _write_all_response!(tracked.conn, response_obj)
                _clear_deadlines!(tracked.conn)
                _server_shutting_down(server) && return nothing
                if _request_wants_close(request) || _response_wants_close(response_obj)
                    return nothing
                end
            end
            _set_conn_state!(tracked, _ConnState.IDLE)
            _set_idle_deadline!(server, tracked.conn)
        end
    finally
        _clear_deadlines!(tracked.conn)
        _close_server_conn!(tracked)
        _untrack_conn!(server, tracked)
    end
    return nothing
end

function _serve_listener!(server::Server, listener::Union{TCP.Listener, TLS.Listener})
    _server_shutting_down(server) && throw(ProtocolError("server is shutting down"))
    lock(server.lock)
    try
        server.listener = listener
        server.bound_address, server.bound_port = _listener_bound_address(listener)
    finally
        unlock(server.lock)
    end
    _set_server_state!(server, _ServerState.RUNNING)
    while true
        _server_shutting_down(server) && return nothing
        conn = try
            _accept_server_conn!(listener)
        catch err
            if _server_shutting_down(server)
                return nothing
            end
            if err isa IOPoll.NetClosingError || err isa EOFError
                return nothing
            end
            rethrow(err)
        end
        tracked = _ServerConn(conn, _ConnState.NEW, floor(Int64, time()))
        _track_conn!(server, tracked)
        errormonitor(Threads.@spawn _serve_conn!(server, tracked))
    end
    return nothing
end

function _run_server!(server::Server)
    listener = TCP.listen(
        server.network, _listen_address(server); backlog = server.backlog, reuseaddr = server.reuseaddr,
    )
    try
        _serve_listener!(server, listener)
    finally
        try
            TCP.close!(listener)
        catch
        end
    end
    return nothing
end

"""
    listen!(server) -> Server

Start a configured `Server` asynchronously and return it.
"""
function listen!(server::Server)::Server
    state = _server_state(server)
    state == _ServerState.CLOSED && throw(ProtocolError("closed servers cannot be restarted"))
    state == _ServerState.RUNNING && throw(ProtocolError("server is already running"))
    task = errormonitor(Threads.@spawn _run_server!(server))
    lock(server.lock)
    try
        server.serve_task = task
    finally
        unlock(server.lock)
    end
    return server
end

"""
    listen!(handler, host="127.0.0.1", port=8080; listenany=false, reuseaddr=true, backlog=128) -> Server
    listen!(handler, port; kwargs...) -> Server
    listen!(handler, listener; kwargs...) -> Server

Start a streaming HTTP server and return the running `Server`.

`handler` is called with an `HTTP.Stream` and is responsible for reading the
request and writing the response.
"""
function listen!(
    handler::F, host::AbstractString = "127.0.0.1", port_num::Integer = 8080;
    listenany::Bool = false, reuseaddr::Bool = true, backlog::Integer = 128,
) where {F}
    return listen!(Server(
        network = "tcp",
        address = HostResolvers.join_host_port(host, Int(port_num)),
        handler = handler,
        stream = true,
        listenany = listenany,
        reuseaddr = reuseaddr,
        backlog = backlog,
    ))
end

function listen!(
    handler::F, port_num::Integer; listenany::Bool = false, reuseaddr::Bool = true, backlog::Integer = 128,
) where {F}
    return listen!(handler, "127.0.0.1", port_num; listenany = listenany, reuseaddr = reuseaddr, backlog = backlog)
end

function listen!(
    handler::F, listener::Union{TCP.Listener, TLS.Listener};
    listenany::Bool = false, reuseaddr::Bool = true, backlog::Integer = 128,
) where {F}
    listenany && throw(ArgumentError("listenany is not valid when passing an existing listener"))
    _ = reuseaddr
    _ = backlog
    bound_address, bound_port = _listener_bound_address(listener)
    server = Server(
        network = "tcp",
        address = bound_address,
        handler = handler,
        stream = true,
        listenany = false,
        reuseaddr = reuseaddr,
        backlog = backlog,
    )
    server.bound_address = bound_address
    server.bound_port = bound_port
    task = errormonitor(Threads.@spawn _serve_listener!(server, listener))
    lock(server.lock)
    try
        server.serve_task = task
    finally
        unlock(server.lock)
    end
    return server
end

"""
    listen(handler, args...; kwargs...)

Run `listen!` in the foreground, blocking until the server is closed.
"""
function listen(handler::F, args...; kwargs...) where {F}
    server = listen!(handler, args...; kwargs...)
    try
        wait(server)
    finally
        try
            close(server)
        catch
        end
    end
    return server
end

"""
    serve!(handler, host="127.0.0.1", port=8080; stream=false, listenany=false, reuseaddr=true, backlog=128) -> Server
    serve!(handler, port; kwargs...) -> Server
    serve!(handler, listener; kwargs...) -> Server

Start an HTTP server and return the running `Server`.

By default `handler` is called with an `HTTP.Request` and must return an
`HTTP.Response`. Pass `stream=true` to use the lower-level `HTTP.Stream`
handler path instead.
"""
function serve!(
    handler::F, args...; stream::Bool = false, listenany::Bool = false, reuseaddr::Bool = true, backlog::Integer = 128,
) where {F}
    if stream
        return listen!(handler, args...; listenany = listenany, reuseaddr = reuseaddr, backlog = backlog)
    end
    if length(args) == 1 && args[1] isa Union{TCP.Listener, TLS.Listener}
        listener = args[1]::Union{TCP.Listener, TLS.Listener}
        bound_address, bound_port = _listener_bound_address(listener)
        server = Server(
            network = "tcp",
            address = bound_address,
            handler = handler,
            stream = false,
            listenany = false,
            reuseaddr = reuseaddr,
            backlog = backlog,
        )
        server.bound_address = bound_address
        server.bound_port = bound_port
        task = errormonitor(Threads.@spawn _serve_listener!(server, listener))
        lock(server.lock)
        try
            server.serve_task = task
        finally
            unlock(server.lock)
        end
        return server
    end
    host, port_num = if length(args) == 1 && args[1] isa Integer
        ("127.0.0.1", Int(args[1]::Integer))
    elseif length(args) == 2 && args[1] isa AbstractString && args[2] isa Integer
        (args[1]::AbstractString, Int(args[2]::Integer))
    else
        throw(ArgumentError("serve! expects host/port, port, or existing listener"))
    end
    return listen!(Server(
        network = "tcp",
        address = HostResolvers.join_host_port(host, port_num),
        handler = handler,
        stream = false,
        listenany = listenany,
        reuseaddr = reuseaddr,
        backlog = backlog,
    ))
end

"""
    serve(handler, args...; kwargs...)

Run `serve!` in the foreground, blocking until the server is closed.
"""
function serve(handler::F, args...; stream::Bool = false, listenany::Bool = false, reuseaddr::Bool = true, backlog::Integer = 128) where {F}
    server = serve!(handler, args...; stream = stream, listenany = listenany, reuseaddr = reuseaddr, backlog = backlog)
    try
        wait(server)
    finally
        try
            close(server)
        catch
        end
    end
    return server
end
