# HTTP/1 server implementation built on `TCP`.
export Server
export Stream
export listen
export listen!
export serve
export serve!
export streamhandler
export forceclose
export port

using EnumX: @enumx
using ..Reseau.TCP
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

@enumx _ServerStreamWriteMode::UInt8 begin
    UNDECIDED = 0
    NONE = 1
    FIXED = 2
    CHUNKED = 3
    IDENTITY = 4
end

mutable struct _ServerConn
    conn::TCP.Conn
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
    listener::Union{Nothing, TCP.Listener}
    serve_task::Union{Nothing, Task}
    active_conns::Set{_ServerConn}
    shutdown_hooks::Vector{Function}
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
        Function[],
        nothing,
        0,
        _ServerState.INITIAL,
    )
end

mutable struct Stream <: IO
    server::Server
    tracked::_ServerConn
    request::Request
    response::Response
    @atomic read_closed::Bool
    @atomic response_started::Bool
    @atomic write_closed::Bool
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
        server,
        tracked,
        request,
        response,
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

function _configured_port(address::AbstractString)::Int
    try
        _, port = HostResolvers.split_host_port(address)
        return port
    catch
        return 0
    end
end

function server_addr(server::Server)::String
    lock(server.lock)
    try
        server.bound_address === nothing && throw(ProtocolError("server is not listening"))
        return server.bound_address::String
    finally
        unlock(server.lock)
    end
end

function port(server::Server)::Int
    lock(server.lock)
    try
        if server.bound_port != 0
            return server.bound_port
        end
        return _configured_port(server.address)
    finally
        unlock(server.lock)
    end
end

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

function _listener_bound_address(listener::TCP.Listener)::Tuple{String, Int}
    laddr = TCP.addr(listener)
    laddr === nothing && return ("", 0)
    return (sprint(show, laddr), Int(laddr.port))
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
        TCP.close!(tracked.conn)
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
        TCP.close!(listener::TCP.Listener)
    catch
    end
    return nothing
end

function _wait_serve_task!(server::Server)::Nothing
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

function _register_on_shutdown!(server::Server, fn::Function)::Nothing
    lock(server.lock)
    try
        push!(server.shutdown_hooks, fn)
    finally
        unlock(server.lock)
    end
    return nothing
end

function _run_shutdown_hooks!(server::Server)::Nothing
    hooks = Function[]
    lock(server.lock)
    try
        append!(hooks, server.shutdown_hooks)
        empty!(server.shutdown_hooks)
    finally
        unlock(server.lock)
    end
    for hook in hooks
        try
            hook()
        catch
        end
    end
    return nothing
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

function forceclose(server::Server)::Nothing
    initiated = _begin_shutdown!(server)
    _close_listener!(server)
    initiated && _run_shutdown_hooks!(server)
    for tracked in _server_conns(server)
        _close_server_conn!(tracked)
    end
    _wait_serve_task!(server)
    _set_server_state!(server, _ServerState.CLOSED)
    return nothing
end

function Base.close(server::Server)::Nothing
    state = _server_state(server)
    state == _ServerState.CLOSED && return nothing
    initiated = _begin_shutdown!(server)
    _close_listener!(server)
    initiated && _run_shutdown_hooks!(server)
    _wait_serve_task!(server)
    poll_s = 0.001
    while true
        _close_idle_conns!(server) && break
        sleep(poll_s)
        poll_s < 0.5 && (poll_s = min(poll_s * 2, 0.5))
    end
    _set_server_state!(server, _ServerState.CLOSED)
    return nothing
end

function _set_read_deadline_for_header!(server::Server, conn::TCP.Conn)::Nothing
    timeout = server.read_header_timeout_ns > 0 ? server.read_header_timeout_ns : server.read_timeout_ns
    timeout <= 0 && return nothing
    TCP.set_read_deadline!(conn, Int64(time_ns()) + timeout)
    return nothing
end

function _set_read_deadline_for_body!(server::Server, conn::TCP.Conn)::Nothing
    timeout = server.read_timeout_ns
    timeout <= 0 && return nothing
    TCP.set_read_deadline!(conn, Int64(time_ns()) + timeout)
    return nothing
end

function _set_idle_deadline!(server::Server, conn::TCP.Conn)::Nothing
    timeout = server.idle_timeout_ns > 0 ? server.idle_timeout_ns : server.read_timeout_ns
    timeout <= 0 && return nothing
    TCP.set_read_deadline!(conn, Int64(time_ns()) + timeout)
    return nothing
end

function _set_write_deadline!(server::Server, conn::TCP.Conn)::Nothing
    timeout = server.write_timeout_ns
    timeout <= 0 && return nothing
    TCP.set_write_deadline!(conn, Int64(time_ns()) + timeout)
    return nothing
end

function _clear_deadlines!(conn::TCP.Conn)::Nothing
    try
        TCP.set_deadline!(conn, Int64(0))
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

function _write_all_response!(conn::TCP.Conn, response::Response)::Nothing
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

function _try_write_server_error!(conn::TCP.Conn, request::Union{Nothing, Request}, status_code::Int)::Nothing
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
    return nothing
end

function _server_stream_allows_body(stream::Stream)::Bool
    _body_allowed_for_status(stream.response.status_code) || return false
    stream.request.method == "HEAD" && return false
    return true
end

function _server_stream_write_mode(stream::Stream)::_ServerStreamWriteMode.T
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
    _set_write_deadline!(stream.server, stream.tracked.conn)
    total = 0
    while total < length(bytes)
        n = write(stream.tracked.conn, bytes[(total + 1):end])
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

function startread(stream::Stream)::Request
    return stream.request
end

function _maybe_write_continue!(stream::Stream)::Nothing
    already_sent = @atomic :acquire stream.continue_sent
    already_sent && return nothing
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

function Base.isopen(stream::Stream)::Bool
    return !(@atomic :acquire stream.read_closed) || !(@atomic :acquire stream.write_closed)
end

function Base.eof(stream::Stream)::Bool
    return _request_body_fully_consumed(stream.request)
end

function Base.readbytes!(stream::Stream, dest::AbstractVector{UInt8}, nb::Integer = length(dest))
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

function Base.read(stream::Stream)::Vector{UInt8}
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

function Base.read(stream::Stream, ::Type{String})::String
    return String(read(stream))
end

function setstatus(stream::Stream, status::Integer)::Nothing
    (@atomic :acquire stream.response_started) && throw(ArgumentError("cannot change status after response writing has started"))
    stream.response.status_code = Int(status)
    return nothing
end

function setheader(stream::Stream, key::AbstractString, value::AbstractString)::Nothing
    (@atomic :acquire stream.response_started) && throw(ArgumentError("cannot change headers after response writing has started"))
    set_header!(stream.response.headers, key, value)
    return nothing
end

function setheader(stream::Stream, header::Pair{<:AbstractString, <:AbstractString})::Nothing
    return setheader(stream, header.first, header.second)
end

function addtrailer(stream::Stream, trailers::Headers)::Nothing
    for key in header_keys(trailers)
        values = get_headers(trailers, key)
        for value in values
            add_header!(stream.response.trailers, key, value)
        end
    end
    return nothing
end

function addtrailer(stream::Stream, header::Pair{<:AbstractString, <:AbstractString})::Nothing
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
    started = @atomic :acquire stream.response_started
    started && return stream.response
    !_request_body_fully_consumed(stream.request) && (stream.response.close = true)
    !_server_stream_allows_body(stream) && (stream.ignore_writes = true)
    _write_server_stream_head!(stream)
    return stream.response
end

function _write_server_stream_data!(stream::Stream, data::AbstractVector{UInt8})::Int
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

function Base.write(stream::Stream, data::Vector{UInt8})::Int
    return _write_server_stream_data!(stream, data)
end

function Base.write(stream::Stream, data::StridedVector{UInt8})::Int
    return _write_server_stream_data!(stream, data)
end

function Base.write(stream::Stream, data::AbstractVector{UInt8})::Int
    return _write_server_stream_data!(stream, Vector{UInt8}(data))
end

function Base.write(stream::Stream, data::Union{String, SubString{String}})::Int
    return write(stream, Vector{UInt8}(codeunits(String(data))))
end

function closewrite(stream::Stream)::Nothing
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

function closeread(stream::Stream)::Response
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

function Base.close(stream::Stream)::Nothing
    try
        closewrite(stream)
    catch
    end
    try
        closeread(stream)
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

function streamhandler(handler::F) where {F}
    return function(stream::Stream)
        request = startread(stream)
        body = read(stream)
        materialized = Request(
            request.method,
            request.target;
            headers = request.headers,
            trailers = request.trailers,
            body = BytesBody(body),
            host = request.host,
            content_length = length(body),
            proto_major = Int(request.proto_major),
            proto_minor = Int(request.proto_minor),
            close = request.close,
            context = request.context,
        )
        response = handler(materialized)
        response isa Response || throw(ProtocolError("server handler must return HTTP.Response"))
        response_obj = response::Response
        response_obj.request = materialized
        stream.response.status_code = response_obj.status_code
        stream.response.reason = response_obj.reason
        stream.response.headers = copy(response_obj.headers)
        stream.response.content_length = response_obj.content_length
        stream.response.close = response_obj.close
        startwrite(stream)
        _write_response_body_to_stream!(stream, response_obj.body)
        addtrailer(stream, response_obj.trailers)
        closewrite(stream)
        closeread(stream)
        return nothing
    end
end

function _serve_conn!(server::Server, tracked::_ServerConn)::Nothing
    reader = _ConnReader(tracked.conn)
    try
        while true
            _server_shutting_down(server) && return nothing
            _set_read_deadline_for_header!(server, tracked.conn)
            request = try
                read_request(reader; max_header_bytes = server.max_header_bytes)
            catch err
                status_code = _server_error_status(err::Exception)
                status_code === nothing || _try_write_server_error!(tracked.conn, nothing, status_code::Int)
                if err isa ParseError || err isa ProtocolError || err isa EOFError || err isa IOPoll.DeadlineExceededError || err isa IOPoll.NetClosingError
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

function serve!(server::Server, listener::TCP.Listener)
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
            TCP.accept!(listener)
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

function listen_and_serve!(server::Server)
    listener = TCP.listen(
        server.network,
        _listen_address(server);
        backlog = server.backlog,
        reuseaddr = server.reuseaddr,
    )
    try
        serve!(server, listener)
    finally
        try
            TCP.close!(listener)
        catch
        end
    end
    return nothing
end

function start!(server::Server)::Task
    state = _server_state(server)
    state == _ServerState.CLOSED && throw(ProtocolError("closed servers cannot be restarted"))
    state == _ServerState.RUNNING && throw(ProtocolError("server is already running"))
    task = errormonitor(Threads.@spawn listen_and_serve!(server))
    lock(server.lock)
    try
        server.serve_task = task
    finally
        unlock(server.lock)
    end
    return task
end

function _build_server(
        handler::F,
        host::AbstractString,
        port_num::Integer;
        stream::Bool,
        listenany::Bool,
        reuseaddr::Bool,
        backlog::Integer,
    ) where {F}
    return Server(
        network = "tcp",
        address = HostResolvers.join_host_port(host, Int(port_num)),
        handler = handler,
        stream = stream,
        listenany = listenany,
        reuseaddr = reuseaddr,
        backlog = backlog,
    )
end

function listen!(
        handler::F,
        host::AbstractString = "127.0.0.1",
        port_num::Integer = 8080;
        listenany::Bool = false,
        reuseaddr::Bool = true,
        backlog::Integer = 128,
    ) where {F}
    server = _build_server(
        handler,
        host,
        port_num;
        stream = true,
        listenany = listenany,
        reuseaddr = reuseaddr,
        backlog = backlog,
    )
    start!(server)
    return server
end

function listen!(
        handler::F,
        port_num::Integer;
        listenany::Bool = false,
        reuseaddr::Bool = true,
        backlog::Integer = 128,
    ) where {F}
    return listen!(
        handler,
        "127.0.0.1",
        port_num;
        listenany = listenany,
        reuseaddr = reuseaddr,
        backlog = backlog,
    )
end

function listen!(
        handler::F,
        listener::TCP.Listener;
        listenany::Bool = false,
        reuseaddr::Bool = true,
        backlog::Integer = 128,
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
    task = errormonitor(Threads.@spawn serve!(server, listener))
    lock(server.lock)
    try
        server.serve_task = task
    finally
        unlock(server.lock)
    end
    return server
end

function listen(
        handler::F,
        args...;
        kwargs...,
    ) where {F}
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

function serve!(
        handler::F,
        args...;
        stream::Bool = false,
        listenany::Bool = false,
        reuseaddr::Bool = true,
        backlog::Integer = 128,
    ) where {F}
    stream && return listen!(
        handler,
        args...;
        listenany = listenany,
        reuseaddr = reuseaddr,
        backlog = backlog,
    )
    return listen!(
        streamhandler(handler),
        args...;
        listenany = listenany,
        reuseaddr = reuseaddr,
        backlog = backlog,
    )
end

function serve(
        handler::F,
        args...;
        stream::Bool = false,
        listenany::Bool = false,
        reuseaddr::Bool = true,
        backlog::Integer = 128,
    ) where {F}
    server = serve!(
        handler,
        args...;
        stream = stream,
        listenany = listenany,
        reuseaddr = reuseaddr,
        backlog = backlog,
    )
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
