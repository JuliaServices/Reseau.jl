# HTTP/1 server implementation built on `TCP`.
export Server
export server_addr
export serve!
export listen_and_serve!
export start!
export shutdown!

using ..Reseau.TCP
using ..Reseau.HostResolvers
using ..Reseau.IOPoll

mutable struct Server
    network::String
    address::String
    handler::Function
    read_timeout_ns::Int64
    read_header_timeout_ns::Int64
    write_timeout_ns::Int64
    idle_timeout_ns::Int64
    max_header_bytes::Int
    lock::ReentrantLock
    listener::Union{Nothing, TCP.Listener}
    serve_task::Union{Nothing, Task}
    active_conns::Set{TCP.Conn}
    active_tasks::Set{Task}
    bound_address::Union{Nothing, String}
    @atomic shutting_down::Bool
end

"""
    Server(; network="tcp", address="127.0.0.1:0", handler, ...)

Create an HTTP server with timeouts and parser limits.
"""
function Server(;
        network::AbstractString = "tcp",
        address::AbstractString = "127.0.0.1:0",
        handler::Function,
        read_timeout_ns::Integer = Int64(0),
        read_header_timeout_ns::Integer = Int64(0),
        write_timeout_ns::Integer = Int64(0),
        idle_timeout_ns::Integer = Int64(0),
        max_header_bytes::Integer = 1 * 1024 * 1024,
    )
    read_timeout_ns >= 0 || throw(ArgumentError("read_timeout_ns must be >= 0"))
    read_header_timeout_ns >= 0 || throw(ArgumentError("read_header_timeout_ns must be >= 0"))
    write_timeout_ns >= 0 || throw(ArgumentError("write_timeout_ns must be >= 0"))
    idle_timeout_ns >= 0 || throw(ArgumentError("idle_timeout_ns must be >= 0"))
    max_header_bytes > 0 || throw(ArgumentError("max_header_bytes must be > 0"))
    return Server(
        String(network),
        String(address),
        handler,
        Int64(read_timeout_ns),
        Int64(read_header_timeout_ns),
        Int64(write_timeout_ns),
        Int64(idle_timeout_ns),
        Int(max_header_bytes),
        ReentrantLock(),
        nothing,
        nothing,
        Set{TCP.Conn}(),
        Set{Task}(),
        nothing,
        false,
    )
end

@inline function _server_shutting_down(server::Server)::Bool
    return @atomic :acquire server.shutting_down
end

"""
    server_addr(server)

Return the effective bound `host:port` once listening starts.
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

function _track_conn!(server::Server, conn::TCP.Conn, task::Task)
    lock(server.lock)
    try
        push!(server.active_conns, conn)
        push!(server.active_tasks, task)
    finally
        unlock(server.lock)
    end
    return nothing
end

function _untrack_conn!(server::Server, conn::TCP.Conn, task::Task)
    lock(server.lock)
    try
        delete!(server.active_conns, conn)
        delete!(server.active_tasks, task)
    finally
        unlock(server.lock)
    end
    return nothing
end

function _set_read_deadline_for_header!(server::Server, conn::TCP.Conn)
    timeout = server.read_header_timeout_ns > 0 ? server.read_header_timeout_ns : server.read_timeout_ns
    timeout <= 0 && return nothing
    TCP.set_read_deadline!(conn, Int64(time_ns()) + timeout)
    return nothing
end

function _set_idle_deadline!(server::Server, conn::TCP.Conn)
    timeout = server.idle_timeout_ns
    timeout <= 0 && return nothing
    TCP.set_read_deadline!(conn, Int64(time_ns()) + timeout)
    return nothing
end

function _set_write_deadline!(server::Server, conn::TCP.Conn)
    timeout = server.write_timeout_ns
    timeout <= 0 && return nothing
    TCP.set_write_deadline!(conn, Int64(time_ns()) + timeout)
    return nothing
end

function _clear_deadlines!(conn::TCP.Conn)
    try
        TCP.set_deadline!(conn, Int64(0))
    catch
    end
    return nothing
end

function _write_all_response!(conn::TCP.Conn, response::Response)
    io = IOBuffer()
    write_response!(io, response)
    payload = take!(io)
    total = 0
    while total < length(payload)
        n = write(conn, payload[(total + 1):end])
        n > 0 || throw(ProtocolError("server write made no progress"))
        total += n
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

function _serve_conn!(server::Server, conn::TCP.Conn)
    task = current_task()
    _track_conn!(server, conn, task)
    reader = _ConnReader(conn)
    try
        while true
            _server_shutting_down(server) && return nothing
            _set_read_deadline_for_header!(server, conn)
            request = try
                read_request(reader; max_header_bytes = server.max_header_bytes)
            catch err
                if err isa ParseError || err isa ProtocolError || err isa EOFError || err isa IOPoll.DeadlineExceededError || err isa IOPoll.NetClosingError
                    return nothing
                end
                rethrow(err)
            end
            _clear_deadlines!(conn)
            response = server.handler(request)
            response isa Response || throw(ProtocolError("server handler must return HTTP.Response"))
            response_obj = response::Response
            response_obj.request = request
            # Preserve HTTP/1 safety: unread request bodies disable keep-alive reuse.
            if !_request_body_fully_consumed(request)
                response_obj.close = true
                try
                    body_close!(request.body)
                catch
                end
            end
            _set_write_deadline!(server, conn)
            _write_all_response!(conn, response_obj)
            _clear_deadlines!(conn)
            if _request_wants_close(request) || _response_wants_close(response_obj)
                return nothing
            end
            _set_idle_deadline!(server, conn)
        end
    finally
        _clear_deadlines!(conn)
        try
            TCP.close!(conn)
        catch
        end
        _untrack_conn!(server, conn, task)
    end
    return nothing
end

"""
    serve!(server, listener)

Serve requests from an existing listener until shutdown.
"""
function serve!(server::Server, listener::TCP.Listener)
    _server_shutting_down(server) && throw(ProtocolError("server is shutting down"))
    lock(server.lock)
    try
        server.listener = listener
        laddr = TCP.addr(listener)
        if laddr isa TCP.SocketAddrV4
            server.bound_address = HostResolvers.join_host_port("127.0.0.1", Int((laddr::TCP.SocketAddrV4).port))
        elseif laddr isa TCP.SocketAddrV6
            server.bound_address = HostResolvers.join_host_port("::1", Int((laddr::TCP.SocketAddrV6).port))
        end
    finally
        unlock(server.lock)
    end
    while true
        if _server_shutting_down(server)
            return nothing
        end
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
        conn_task = errormonitor(Threads.@spawn _serve_conn!(server, conn))
        lock(server.lock)
        try
            push!(server.active_tasks, conn_task)
        finally
            unlock(server.lock)
        end
    end
    return nothing
end

"""
    listen_and_serve!(server)

Listen then serve using `server.network` and `server.address`.
"""
function listen_and_serve!(server::Server)
    listener = HostResolvers.listen(server.network, server.address; backlog = 128)
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

"""
    start!(server)

Start `listen_and_serve!` on a background task.
"""
function start!(server::Server)::Task
    task = errormonitor(Threads.@spawn listen_and_serve!(server))
    lock(server.lock)
    try
        server.serve_task = task
    finally
        unlock(server.lock)
    end
    return task
end

function _close_listener!(server::Server)
    listener = nothing
    lock(server.lock)
    try
        listener = server.listener
        server.listener = nothing
    finally
        unlock(server.lock)
    end
    if listener !== nothing
        _close_listener_with_timeout!(listener::TCP.Listener)
    end
    return nothing
end

function _close_listener_with_timeout!(listener::TCP.Listener; timeout_s::Float64 = 1.0)
    task = errormonitor(Threads.@spawn begin
        try
            TCP.close!(listener)
        catch
        end
        return nothing
    end)
    _ = timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
    return nothing
end

function _force_close_conn_with_timeout!(conn::TCP.Conn; timeout_s::Float64 = 1.0)
    task = errormonitor(Threads.@spawn begin
        try
            TCP.close!(conn)
        catch
        end
        return nothing
    end)
    _ = timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
    return nothing
end

"""
    shutdown!(server; force=false, timeout_s=5.0)

Request graceful shutdown, optionally force-closing active connections.
"""
function shutdown!(server::Server; force::Bool = false, timeout_s::Float64 = 5.0)
    @atomic :release server.shutting_down = true
    _close_listener!(server)
    task = nothing
    lock(server.lock)
    try
        task = server.serve_task
    finally
        unlock(server.lock)
    end
    if task !== nothing
        _ = timedwait(() -> istaskdone(task::Task), timeout_s; pollint = 0.001)
    end
    conns = TCP.Conn[]
    tasks = Task[]
    lock(server.lock)
    try
        append!(conns, server.active_conns)
        append!(tasks, server.active_tasks)
    finally
        unlock(server.lock)
    end
    if force
        close_deadline = time() + timeout_s
        for conn in conns
            remaining = close_deadline - time()
            remaining <= 0 && break
            _force_close_conn_with_timeout!(conn; timeout_s = min(remaining, 1.0))
        end
    end
    deadline = time() + timeout_s
    for task_item in tasks
        remaining = deadline - time()
        remaining <= 0 && break
        _ = timedwait(() -> istaskdone(task_item), remaining; pollint = 0.001)
    end
    return nothing
end
