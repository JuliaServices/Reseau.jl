# Runs a `_Connection` over a UDP socket: a minimal driver for one connection
# per socket, until there is an endpoint that demultiplexes many.

@inline _monotonic_ns()::Int64 = Int64(time_ns())

function _flush_datagrams!(conn::_Connection, sock::UDP.Conn, peer::Union{Nothing, UDP.SocketEndpoint}, now::Int64)::Nothing
    while (dgram = _next_datagram!(conn, now)) !== nothing
        peer === nothing ? UDP.send(sock, dgram) : UDP.sendto(sock, dgram, peer::UDP.SocketEndpoint)
    end
    return nothing
end

# Waits for one datagram until `wake_ns`; returns its bytes and sender, or
# `nothing` once the deadline passes.
function _receive_until(sock::UDP.Conn, buf::Vector{UInt8}, wake_ns::Int64)::Union{Nothing, Tuple{Vector{UInt8}, Union{Nothing, UDP.SocketEndpoint}}}
    UDP.set_read_deadline!(sock, max(wake_ns, Int64(1)))
    try
        n, from = UDP.recvfrom!(sock, buf)
        return buf[1:n], from
    catch ex
        ex isa UDP.DeadlineExceededError && return nothing
        rethrow()
    end
end

"""
    _drive_connection!(conn, sock, peer, step; deadline_ns) -> Bool

Run `conn` over `sock` until `step(conn)` returns `true`, the connection
closes, or `deadline_ns` passes; returns whether `step` finished. `step` runs
before each round of sending, so it can read and write streams; whatever it
queues goes out before this returns. `peer` is the destination for an
unconnected socket, or `nothing` for a connected one.
"""
function _drive_connection!(
        conn::_Connection,
        sock::UDP.Conn,
        peer::Union{Nothing, UDP.SocketEndpoint},
        step::F;
        deadline_ns::Int64,
    )::Bool where {F}
    buf = Vector{UInt8}(undef, 65535)
    while true
        finished = step(conn)
        now = _monotonic_ns()
        _flush_datagrams!(conn, sock, peer, now)
        finished && return true
        (conn.state == _ConnState.Closed || now >= deadline_ns) && return false
        timeout = _next_timeout(conn)
        received = _receive_until(sock, buf, timeout === nothing ? deadline_ns : min(timeout, deadline_ns))
        now = _monotonic_ns()
        received === nothing || _receive_datagram!(conn, received[1], now)
        timeout = _next_timeout(conn)
        timeout !== nothing && now >= timeout && _handle_timeout!(conn, now)
    end
end

"""
    _accept_over_udp(config, sock; deadline_ns) -> (conn, peer) or nothing

Wait on an unconnected socket for a client's first Initial and start a server
connection for it, having processed that datagram.
"""
function _accept_over_udp(config::TLS.Config, sock::UDP.Conn; deadline_ns::Int64)::Union{Nothing, Tuple{_Connection, UDP.SocketEndpoint}}
    buf = Vector{UInt8}(undef, 65535)
    while _monotonic_ns() < deadline_ns
        received = _receive_until(sock, buf, deadline_ns)
        received === nothing && return nothing
        dgram, from = received
        from === nothing && continue
        header = nothing
        for h in _datagram_packets(dgram, 1, length(dgram), _LOCAL_CID_LEN)
            header = h
            break
        end
        header === nothing && continue
        conn = _accept_connection(config, dgram, header::_PacketHeader, _monotonic_ns())
        conn === nothing && continue
        _receive_datagram!(conn, dgram, _monotonic_ns())
        return conn, from::UDP.SocketEndpoint
    end
    return nothing
end
