# HTTP/1 server implementation built on `TCP`.
export Server
export server_addr
export serve!
export listen_and_serve!
export start!
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
    bound_address::Union{Nothing, String}
    bound_port::Int
    @atomic state::_ServerState.T
end

function Server(;
        network::AbstractString = "tcp",
        address::AbstractString = "127.0.0.1:0",
        handler::F,
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

function forceclose(server::Server)::Nothing
    _set_server_state!(server, _ServerState.CLOSING)
    _close_listener!(server)
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
    _set_server_state!(server, _ServerState.CLOSING)
    _close_listener!(server)
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

function _serve_conn!(server::Server, tracked::_ServerConn)::Nothing
    reader = _ConnReader(tracked.conn)
    try
        while true
            _server_shutting_down(server) && return nothing
            _set_read_deadline_for_header!(server, tracked.conn)
            request = try
                read_request(reader; max_header_bytes = server.max_header_bytes)
            catch err
                if err isa ParseError || err isa ProtocolError || err isa EOFError || err isa IOPoll.DeadlineExceededError || err isa IOPoll.NetClosingError
                    return nothing
                end
                rethrow(err)
            end
            _set_conn_state!(tracked, _ConnState.ACTIVE)
            _set_read_deadline_for_body!(server, tracked.conn)
            response = server.handler(request)
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
