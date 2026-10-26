# The public interface: connections and listeners over UDP sockets, with
# streams that any task can read and write as `IO`.
#
# Each UDP socket belongs to an endpoint: one connection for a client, every
# connection a listener accepted for a server. A task per endpoint receives
# datagrams and runs the connections' timers. All of an endpoint's state is
# guarded by its one lock, and tasks waiting on a connection wait on a
# condition of that lock. Whichever task changes a connection sends what the
# change allows at once, and pulls the receive task's next wakeup earlier
# when the connection now has an earlier timer, by lowering the socket's read
# deadline. A task waiting with a deadline registers it the same way, and the
# receive task wakes every waiter each time round. Changing a stream's
# deadline wakes the tasks waiting on it, which wait again with the new one.

"""
    ConnectionError

Why a QUIC connection ended: the error `code` and `reason` from its
CONNECTION_CLOSE, an application error code when `app` is set and a transport
error code (RFC 9000 Section 20.1) otherwise, and whether the peer closed it
(`remote`). A connection that went idle, or whose socket failed, ends with a
local transport error with code 0 and a reason saying which.
"""
struct ConnectionError <: Exception
    code::UInt64
    reason::String
    app::Bool
    remote::Bool
end

function Base.showerror(io::IO, err::ConnectionError)
    print(io, "QUIC connection closed ", err.remote ? "by the peer" : "locally", " with ",
        err.app ? "application" : "transport", " error 0x", string(err.code; base = 16))
    isempty(err.reason) || print(io, ": ", err.reason)
    return nothing
end

"""
    StreamResetError

Stream `stream_id` was reset (RESET_STREAM) with application error `code`.
Reads fail with this when the peer reset it (`remote`), and writes when
this endpoint did, with [`reset_stream!`](@ref).
"""
struct StreamResetError <: Exception
    stream_id::UInt64
    code::UInt64
    remote::Bool
end

function Base.showerror(io::IO, err::StreamResetError)
    print(io, "QUIC stream ", err.stream_id, " was reset ", err.remote ? "by the peer" : "locally",
        " with error 0x", string(err.code; base = 16))
    return nothing
end

"""
    StreamStoppedError

Sending on stream `stream_id` was stopped (STOP_SENDING) with application
error `code`. Writes fail with this when the peer stopped it (`remote`),
and reads when this endpoint did, with [`stop_sending!`](@ref).
"""
struct StreamStoppedError <: Exception
    stream_id::UInt64
    code::UInt64
    remote::Bool
end

function Base.showerror(io::IO, err::StreamStoppedError)
    print(io, "QUIC stream ", err.stream_id, " was stopped ", err.remote ? "by the peer" : "locally",
        " with error 0x", string(err.code; base = 16))
    return nothing
end

const _StreamEnd = Union{Nothing, StreamResetError, StreamStoppedError}

# One connection on an endpoint. `cond` belongs to the endpoint's lock.
# `failure` says why the socket failed under it; `routes` are the
# Destination Connection IDs that reach it.
mutable struct _ConnSlot
    conn::_Connection
    # Tasks wait for the handshake or stream credit on `cond`, for the peer's
    # streams on `accept_cond`, and to read and write streams on `read_cond`
    # and `write_cond`, registering those streams in `read_waiting` and
    # `write_waiting`. Each is woken only when it has reason to look again,
    # since waking a task on another thread is costly.
    cond::Threads.Condition
    accept_cond::Threads.Condition
    read_cond::Threads.Condition
    write_cond::Threads.Condition
    read_waiting::Vector{UInt64}
    write_waiting::Vector{UInt64}
    # Tickets of the tasks waiting in `open_stream`, in the order they began
    # to wait, for each kind of stream; `tickets` numbers them.
    open_waiting_bidi::Vector{Int}
    open_waiting_uni::Vector{Int}
    tickets::Int
    handshake_seen::Bool
    peer::Union{Nothing, UDP.SocketEndpoint}
    failure::Union{Nothing, String}
    routes::Vector{Vector{UInt8}}
    announced::Bool
end

mutable struct _Endpoint
    sock::UDP.Conn
    lock::ReentrantLock
    is_server::Bool
    config::Union{Nothing, TLS.Config}
    limits::_StreamLimits
    slots::Vector{_ConnSlot}
    routes::Dict{Vector{UInt8}, _ConnSlot}
    # The socket's read deadline, `typemax(Int64)` for none.
    armed::Int64
    # Deadlines of tasks waiting on this endpoint's conditions.
    waiters::Vector{Int64}
    accept_queue::Vector{_ConnSlot}
    accept_cond::Threads.Condition
    accepting::Bool
    done::Bool
    # Whether datagrams go out in batches through UDP segmentation offload,
    # and the buffer they are gathered in.
    gso::Bool
    send_buf::Vector{UInt8}
    # The largest datagram its connections may probe for.
    pmtu_ceiling::Int
end

function _Endpoint(sock::UDP.Conn, is_server::Bool, config::Union{Nothing, TLS.Config}, limits::_StreamLimits)
    lk = ReentrantLock()
    return _Endpoint(
        sock, lk, is_server, config, limits, _ConnSlot[], Dict{Vector{UInt8}, _ConnSlot}(),
        typemax(Int64), Int64[], _ConnSlot[], Threads.Condition(lk), is_server, false,
        IOPoll._UDP_OFFLOAD, Vector{UInt8}(undef, _GSO_MAX_BYTES), _MAX_DATAGRAM_SIZE,
    )
end

"""
    Connection

A QUIC connection, from [`connect`](@ref) or [`accept`](@ref). Open streams
with [`open_stream`](@ref), take the peer's with [`accept_stream`](@ref), and
end it with `close`. Safe to use from any task.
"""
struct Connection
    ep::_Endpoint
    slot::_ConnSlot
end

"""
    Listener

Accepts QUIC connections on a UDP socket; see [`listen`](@ref).
"""
struct Listener
    ep::_Endpoint
end

"""
    Stream

One QUIC stream, as an `IO`. Reads block until data arrives, the stream
ends (`eof`), the peer resets it ([`StreamResetError`](@ref)), or the
connection closes ([`ConnectionError`](@ref)). Writes are buffered and block
while too much is unacknowledged; after the peer's STOP_SENDING they throw
[`StreamStoppedError`](@ref). `closewrite` sends the FIN. `close` only
finishes the sending side, as in quic-go; abandon a stream with
[`reset_stream!`](@ref) and [`stop_sending!`](@ref).
"""
mutable struct Stream <: IO
    conn::Connection
    id::UInt64
    read_deadline_ns::Int64
    write_deadline_ns::Int64
    # Why reads, and writes, can no longer succeed, kept once seen: the
    # connection forgets a stream when both its sides are done.
    read_end::_StreamEnd
    write_end::_StreamEnd
end

Stream(conn::Connection, id::UInt64) = Stream(conn, id, Int64(0), Int64(0), nothing, nothing)

# A connected socket's peer can have an unsent buffer this large on each
# stream before writes wait for acknowledgments.
const _SEND_BUFFER_LIMIT = 1024 * 1024

# Timers and waiting.

function _set_socket_deadline!(ep::_Endpoint, t::Int64)::Nothing
    ep.armed = t
    try
        UDP.set_read_deadline!(ep.sock, t == typemax(Int64) ? 0 : t)
    catch
        # The socket closed under the receive task, which is exiting.
    end
    return nothing
end

# Make the receive task wake by `t`.
function _arm!(ep::_Endpoint, t::Int64)::Nothing
    t < ep.armed && _set_socket_deadline!(ep, t)
    return nothing
end

# The receive task's next wakeup. Waiters whose deadline has passed were just
# woken and remove their deadline when they run, so they are left out.
function _endpoint_deadline(ep::_Endpoint, now::Int64)::Int64
    t = typemax(Int64)
    for slot in ep.slots
        timeout = _next_timeout(slot.conn)
        timeout === nothing || (t = min(t, timeout))
    end
    for w in ep.waiters
        w > now && (t = min(t, w))
    end
    return t
end

# Waits on `cond`, whose lock is held, until notified or until `deadline_ns`
# (0 for none) passes. Returns `false`, without waiting, once it has.
function _wait!(ep::_Endpoint, cond::Threads.Condition, deadline_ns::Int64)::Bool
    if deadline_ns == 0
        wait(cond)
        return true
    end
    _monotonic_ns() >= deadline_ns && return false
    push!(ep.waiters, deadline_ns)
    _arm!(ep, deadline_ns)
    try
        wait(cond)
    finally
        i = findfirst(==(deadline_ns), ep.waiters)
        i === nothing || deleteat!(ep.waiters, i)
    end
    return true
end

# Sending, receiving, and the receive task.

function _failure_reason(@nospecialize(ex))::String
    ex isa String && return ex
    ex isa SystemError && return string(ex.prefix, ": ", Libc.strerror(ex.errnum))
    return "socket failure"
end

function _fail_slot!(slot::_ConnSlot, @nospecialize(ex))::Nothing
    slot.failure === nothing && (slot.failure = _failure_reason(ex))
    slot.conn.state = _ConnState.Closed
    return nothing
end

# At most this many handshaken connections wait to be accepted (quic-go's
# MaxAcceptQueueSize); later ones are refused.
const _MAX_ACCEPT_QUEUE = 32

# At most this many datagrams, and bytes, go out in one segmented send.
const _GSO_MAX_SEGMENTS = 64
const _GSO_MAX_BYTES = 65000

# errno values meaning the kernel or device cannot segment UDP (Linux): EIO
# when the device lacks checksum offload, as in quic-go, or no support at all.
const _GSO_UNSUPPORTED = (Int32(Base.Libc.EIO), Int32(Base.Libc.ENOSYS), Int32(92), Int32(95))

# errno values that lose a datagram but leave the socket usable: ICMP errors,
# which a connected socket reports on a later call (an unconnected one, as
# quic-go uses, never sees them), and transient shortages.
const _TRANSIENT_SOCKET_ERRORS = (
    Int32(Base.Libc.ECONNREFUSED), Int32(Base.Libc.EHOSTUNREACH), Int32(Base.Libc.ENETUNREACH),
    Int32(Base.Libc.EHOSTDOWN), Int32(Base.Libc.ECONNRESET), Int32(Base.Libc.ENOBUFS),
    Int32(Base.Libc.ENOMEM), Int32(Base.Libc.EINTR),
)

_transient_socket_error(@nospecialize(ex))::Bool = ex isa SystemError && Int32((ex::SystemError).errnum) in _TRANSIENT_SOCKET_ERRORS

# Sends `nbytes` of `ep.send_buf`, datagrams of `segment` bytes with a shorter
# last one, to the slot's peer. Where segmentation turns out to be
# unavailable, the endpoint stops using it and sends them one by one. Returns
# whether the slot is still usable.
function _send_gathered!(ep::_Endpoint, slot::_ConnSlot, nbytes::Int, segment::Int)::Bool
    buf = ep.send_buf
    try
        UDP._send_segments!(ep.sock, buf, nbytes, segment, slot.peer)
        return true
    catch ex
        if ex isa SystemError && ex.errnum == Base.Libc.EMSGSIZE
            # The local route no longer carries datagrams this large; loss
            # recovery resends them at the minimum size.
            _pmtu_black_hole!(slot.conn)
            return true
        end
        _transient_socket_error(ex) && return true  # lost, as on the network
        errno = ex isa SystemError ? Int32(ex.errnum) : Int32(0)
        if errno in _GSO_UNSUPPORTED
            ep.gso = false
        elseif errno != Int32(Base.Libc.EINVAL)
            _fail_slot!(slot, ex)
            return false
        end
        # EINVAL: the segments are larger than the route now takes. Sent one
        # by one, they get EMSGSIZE, which shrinks the datagram size.
    end
    off = 0
    while off < nbytes
        len = min(segment, nbytes - off)
        _send_one!(ep, slot, buf[(off + 1):(off + len)]) || return false
        off += len
    end
    return true
end

function _send_one!(ep::_Endpoint, slot::_ConnSlot, dgram::Vector{UInt8})::Bool
    peer = slot.peer
    try
        peer === nothing ? UDP.send(ep.sock, dgram) : UDP.sendto(ep.sock, dgram, peer::UDP.SocketEndpoint)
        return true
    catch ex
        if ex isa SystemError && ex.errnum == Base.Libc.EMSGSIZE
            # Too large for the local route: a probe's size is given up at once;
            # otherwise the route shrank, and loss recovery resends the data
            # at the minimum size.
            conn = slot.conn
            length(dgram) > conn.max_datagram_size ? _pmtu_refused!(conn) : _pmtu_black_hole!(conn)
            return true
        end
        _transient_socket_error(ex) && return true  # lost, as on the network
        _fail_slot!(slot, ex)
        return false
    end
end

# Sends whatever the connection has to send. With segmentation offload, runs
# of equal-sized datagrams (a shorter one ends a run) go out in one system
# call each.
function _flush!(ep::_Endpoint, slot::_ConnSlot, now::Int64)::Nothing
    ep.gso || return _flush_each!(ep, slot, now)
    buf = ep.send_buf
    nbytes = 0
    segment = 0
    count = 0
    while (dgram = _build_datagram!(slot.conn, now)) !== nothing
        len = length(dgram)
        if len > slot.conn.max_datagram_size
            # A path MTU probe goes out on its own.
            if count > 0
                _send_gathered!(ep, slot, nbytes, segment) || return nothing
                nbytes = 0
                count = 0
            end
            _send_one!(ep, slot, dgram) || return nothing
            continue
        end
        if count > 0 && (len > segment || count == _GSO_MAX_SEGMENTS || nbytes + len > length(buf))
            _send_gathered!(ep, slot, nbytes, segment) || return nothing
            nbytes = 0
            count = 0
        end
        count == 0 && (segment = len)
        copyto!(buf, nbytes + 1, dgram, 1, len)
        nbytes += len
        count += 1
        if len < segment
            _send_gathered!(ep, slot, nbytes, segment) || return nothing
            nbytes = 0
            count = 0
        end
        ep.gso || return _flush_each!(ep, slot, now)
    end
    count > 0 && _send_gathered!(ep, slot, nbytes, segment)
    return nothing
end

function _flush_each!(ep::_Endpoint, slot::_ConnSlot, now::Int64)::Nothing
    while (dgram = _build_datagram!(slot.conn, now)) !== nothing
        _send_one!(ep, slot, dgram) || return nothing
    end
    return nothing
end

function _remove_slot!(ep::_Endpoint, slot::_ConnSlot)::Nothing
    i = findfirst(x -> x === slot, ep.slots)
    i === nothing && return nothing
    deleteat!(ep.slots, i)
    for cid in slot.routes
        get(ep.routes, cid, nothing) === slot && delete!(ep.routes, cid)
    end
    # Ends a handshake still in progress and drops its secrets.
    close(slot.conn.tls)
    return nothing
end

# Whether a task waiting to read stream `id` has something new to see.
function _read_ready(conn::_Connection, id::UInt64)::Bool
    st = get(conn.streams, id, nothing)
    (st === nothing || st.recv === nothing) && return true
    (st.peer_reset_code != _NO_CODE || st.stop_sending_code != _NO_CODE) && return true
    rb = st.recv::_StreamReceiveBuffer
    return _recv_readable(rb) > 0 || _recv_finished(rb)
end

# Whether a task waiting to write stream `id` should look again: the stream
# ended, or its unacknowledged bytes fell to half the limit, so that each
# wakeup has a large write to make.
function _write_ready(conn::_Connection, id::UInt64)::Bool
    st = get(conn.streams, id, nothing)
    (st === nothing || st.send === nothing) && return true
    (st.peer_stop_code != _NO_CODE || st.reset_code != _NO_CODE) && return true
    sb = st.send::_StreamSendBuffer
    return _send_end(sb) - sb.base < _SEND_BUFFER_LIMIT ÷ 2
end

# Wakes the tasks waiting on `slot` that have reason to look again: all of
# them when `force` is set (a deadline passed) or the connection has ended.
function _wake!(slot::_ConnSlot, force::Bool)::Nothing
    conn = slot.conn
    force = force || !_conn_open(conn) || slot.failure !== nothing
    if force || !slot.handshake_seen && _handshake_complete(conn) ||
       conn.local_opened_bidi < conn.peer_max_streams_bidi || conn.local_opened_uni < conn.peer_max_streams_uni
        slot.handshake_seen |= _handshake_complete(conn)
        notify(slot.cond; all = true)
    end
    (force || !isempty(conn.accept_queue)) && notify(slot.accept_cond; all = true)
    if !isempty(slot.read_waiting) && (force || any(id -> _read_ready(conn, id), slot.read_waiting))
        notify(slot.read_cond; all = true)
    end
    if !isempty(slot.write_waiting) && (force || any(id -> _write_ready(conn, id), slot.write_waiting))
        notify(slot.write_cond; all = true)
    end
    return nothing
end

# `_wait!` on behalf of a task reading or writing stream `id`, registered in
# `waiting` so `_wake!` knows to check that stream.
function _wait_stream!(ep::_Endpoint, cond::Threads.Condition, waiting::Vector{UInt64}, id::UInt64, deadline_ns::Int64)::Bool
    push!(waiting, id)
    try
        return _wait!(ep, cond, deadline_ns)
    finally
        i = findfirst(==(id), waiting)
        i === nothing || deleteat!(waiting, i)
    end
end

# Runs `slot`'s due timers, sends what it can, hands a server connection to
# `accept` once its handshake completes, and wakes its waiters.
function _service!(ep::_Endpoint, slot::_ConnSlot, now::Int64, force::Bool = false)::Nothing
    conn = slot.conn
    timeout = _next_timeout(conn)
    timeout !== nothing && now >= timeout && _handle_timeout!(conn, now)
    _flush!(ep, slot, now)
    if ep.is_server && !slot.announced && _handshake_complete(conn) && _conn_open(conn)
        slot.announced = true
        if ep.accepting && length(ep.accept_queue) < _MAX_ACCEPT_QUEUE
            push!(ep.accept_queue, slot)
            notify(ep.accept_cond; all = true)
        else
            # Closed, or too many waiting to be accepted: CONNECTION_REFUSED,
            # as quic-go does.
            _close_connection!(conn, ep.accepting ? _CONNECTION_REFUSED : UInt64(0), "", now; app = false)
            _flush!(ep, slot, now)
        end
    end
    _wake!(slot, force)
    conn.state == _ConnState.Closed && _remove_slot!(ep, slot)
    return nothing
end

# After the application changes a connection: send, and wake the receive
# task earlier if a timer moved up.
function _after_op!(ep::_Endpoint, slot::_ConnSlot)::Nothing
    _flush!(ep, slot, _monotonic_ns())
    timeout = _next_timeout(slot.conn)
    timeout === nothing || _arm!(ep, timeout)
    _wake!(slot, false)
    return nothing
end

function _new_slot!(ep::_Endpoint, conn::_Connection, peer::Union{Nothing, UDP.SocketEndpoint})::_ConnSlot
    conn.pmtu_ceiling = ep.pmtu_ceiling
    lk = ep.lock
    slot = _ConnSlot(
        conn, Threads.Condition(lk), Threads.Condition(lk), Threads.Condition(lk), Threads.Condition(lk),
        UInt64[], UInt64[], Int[], Int[], 0, false, peer, nothing, Vector{UInt8}[], false,
    )
    push!(ep.slots, slot)
    _add_route!(ep, slot, conn.local_cid)
    return slot
end

function _add_route!(ep::_Endpoint, slot::_ConnSlot, cid::Vector{UInt8})::Nothing
    ep.routes[cid] = slot
    push!(slot.routes, cid)
    return nothing
end

# Hands a datagram to the connection its Destination Connection ID names, or
# to a new server connection for a client's first Initial. The caller services
# the connection afterwards, once per batch of datagrams.
function _route_datagram!(ep::_Endpoint, buf::Vector{UInt8}, first::Int, last::Int, from::Union{Nothing, UDP.SocketEndpoint}, now::Int64)::Nothing
    header = _parse_packet(buf, first, last, _LOCAL_CID_LEN)
    header === nothing && return nothing
    slot = get(ep.routes, view(buf, header.dcid), nothing)
    if slot === nothing
        (ep.is_server && ep.accepting && from !== nothing) || return nothing
        dgram = buf[first:last]
        header = _parse_packet(dgram, 1, length(dgram), _LOCAL_CID_LEN)::_PacketHeader
        conn = _accept_connection(ep.config::TLS.Config, dgram, header, now; limits = ep.limits)
        conn === nothing && return nothing
        slot = _new_slot!(ep, conn, from)
        # The client keeps using the Destination Connection ID it chose
        # until the server's first packet reaches it.
        _add_route!(ep, slot, dgram[header.dcid])
        _receive_datagram!(slot.conn, dgram, now)
        return nothing
    end
    _receive_datagram!(slot.conn, buf, first, last, now)
    return nothing
end

# The most datagrams taken from the socket before connections are serviced.
const _RECV_BATCH = 64

# Routes the datagrams in `buf[1:n]`: one, or a run of `segment`-byte ones
# the kernel coalesced (UDP generic receive offload).
function _route_received!(ep::_Endpoint, buf::Vector{UInt8}, n::Int, segment::Int, from::Union{Nothing, UDP.SocketEndpoint}, now::Int64)::Nothing
    segment = segment == 0 ? n : segment
    off = 0
    while off < n
        len = min(segment, n - off)
        _route_datagram!(ep, buf, off + 1, off + len, from, now)
        off += len
    end
    return nothing
end

function _fail_all!(ep::_Endpoint, @nospecialize(ex))::Nothing
    lock(ep.lock)
    try
        for slot in ep.slots
            _fail_slot!(slot, ex)
        end
    finally
        unlock(ep.lock)
    end
    return nothing
end

_endpoint_finished(ep::_Endpoint)::Bool = !ep.accepting && isempty(ep.slots)

function _run_endpoint!(ep::_Endpoint)::Nothing
    buf = Vector{UInt8}(undef, 65535)
    try
        while true
            lock(ep.lock)
            try
                now = _monotonic_ns()
                # Waiters whose deadline passed must run to see it.
                force = any(w -> w <= now, ep.waiters)
                for slot in copy(ep.slots)
                    _service!(ep, slot, now, force)
                end
                (force || !ep.accepting || !isempty(ep.accept_queue)) && notify(ep.accept_cond; all = true)
                _endpoint_finished(ep) && return nothing
                # A timer still due after servicing would wake this task at
                # once forever; check it again a little later instead.
                _set_socket_deadline!(ep, max(_endpoint_deadline(ep, now), now + _GRANULARITY_NS))
            finally
                unlock(ep.lock)
            end
            n = 0
            from = nothing
            segment = 0
            try
                n, from, segment = UDP._recv_segments!(ep.sock, buf, true)
            catch ex
                if ex isa UDP.DeadlineExceededError
                    # Let woken waiters run before the next round.
                    yield()
                    continue
                end
                # A truncated datagram is not QUIC, and transient errors lose
                # a datagram at most; anything else ends the endpoint.
                (ex isa UDP.TruncatedDatagramError || _transient_socket_error(ex)) && continue
                _fail_all!(ep, ex)
                break
            end
            # Take whatever else has already arrived, so connections are
            # serviced (and send, and wake their waiters) once per batch
            # rather than once per datagram.
            failure = nothing
            lock(ep.lock)
            try
                now = _monotonic_ns()
                _route_received!(ep, buf, n, segment, from, now)
                for _ in 2:_RECV_BATCH
                    n, from, segment = try
                        UDP._recv_segments!(ep.sock, buf, false)
                    catch ex
                        (ex isa UDP.TruncatedDatagramError || _transient_socket_error(ex)) && continue
                        failure = ex
                        break
                    end
                    n < 0 && break
                    _route_received!(ep, buf, n, segment, from, now)
                end
            finally
                unlock(ep.lock)
            end
            if failure !== nothing
                _fail_all!(ep, failure)
                break
            end
        end
    finally
        lock(ep.lock)
        try
            ep.done = true
            ep.accepting = false
            for slot in ep.slots
                _fail_slot!(slot, "endpoint closed")
                _wake!(slot, true)
                close(slot.conn.tls)
            end
            empty!(ep.slots)
            notify(ep.accept_cond; all = true)
        finally
            unlock(ep.lock)
        end
        close(ep.sock)
    end
    return nothing
end

# Waits until the endpoint's receive task has exited and closed the socket,
# which happens once its connections have closed (and, for a listener, it
# was closed). Returns `false` if `deadline_ns` passes first.
function _wait_endpoint_done(ep::_Endpoint, deadline_ns::Int64)::Bool
    lock(ep.lock)
    try
        while !ep.done
            _wait!(ep, ep.accept_cond, deadline_ns) || return false
        end
        return true
    finally
        unlock(ep.lock)
    end
end

# Socket buffers this large keep a burst of datagrams from overflowing them;
# the kernel caps the request (net.core.rmem_max and wmem_max on Linux).
const _SOCKET_BUFFER_BYTES = 7 * 1024 * 1024

# Sets the socket up and returns the ceiling for path MTU discovery: the
# minimum where Don't Fragment cannot be set (larger datagrams would be
# fragmented); `max_datagram_size` when given; else the route's MTU less IP
# and UDP headers when the socket knows it, up to jumbo frames, or the
# default.
function _configure_socket!(sock::UDP.Conn, max_datagram_size::Integer)::Int
    for set! in (UDP.set_read_buffer!, UDP.set_write_buffer!)
        try
            set!(sock, _SOCKET_BUFFER_BYTES)
        catch
        end
    end
    UDP._enable_gro!(sock)
    UDP._set_dont_fragment!(sock) || return _MAX_DATAGRAM_SIZE
    max_datagram_size > 0 && return clamp(Int(max_datagram_size), _MAX_DATAGRAM_SIZE, 65527)
    mtu = UDP._path_mtu(sock)
    mtu <= 0 && return _PMTU_DEFAULT_CEILING
    headers = sock.fd.family == UDP.SocketOps.AF_INET6 ? 48 : 28
    return clamp(mtu - headers, _MAX_DATAGRAM_SIZE, _PMTU_MAX_CEILING)
end

function _start!(ep::_Endpoint)::Nothing
    Threads.@spawn _run_endpoint!(ep)
    return nothing
end

# Connection state for the application.

function _conn_open(conn::_Connection)::Bool
    state = conn.state
    return state == _ConnState.Handshaking || state == _ConnState.Established || state == _ConnState.Confirmed
end

function _conn_error(slot::_ConnSlot)::ConnectionError
    conn = slot.conn
    e = conn.peer_error
    e === nothing || return ConnectionError(e.code, e.reason, e.app, true)
    e = conn.error
    e === nothing || return ConnectionError(e.code, e.reason, e.app, false)
    f = slot.failure
    f === nothing || return ConnectionError(UInt64(0), f, false, false)
    return ConnectionError(UInt64(0), "idle timeout", false, false)
end

function _check_conn!(slot::_ConnSlot)::Nothing
    (_conn_open(slot.conn) && slot.failure === nothing) || throw(_conn_error(slot))
    return nothing
end

function _stream_limits(max_data, max_stream_data, max_streams_bidi, max_streams_uni)::_StreamLimits
    return _StreamLimits(;
        max_data = Int64(max_data), max_stream_data = Int64(max_stream_data),
        max_streams_bidi = Int64(max_streams_bidi), max_streams_uni = Int64(max_streams_uni),
    )
end

const _DEFAULT_LIMITS = _StreamLimits()

"""
    connect(remote_addr, config; deadline_ns = 0, local_addr = nothing,
            max_data, max_stream_data, max_streams_bidi, max_streams_uni,
            max_datagram_size = 0) -> Connection

Open a QUIC connection to `remote_addr` (a `UDP.SocketAddr`) over a new
connected UDP socket, and return once the handshake completes. `config` is
the client `TLS.Config`; QUIC requires its `alpn_protocols`. The limits are
what the server may send (in bytes, overall and per stream) and how many
streams of each kind it may open at once. Datagrams start at 1200 bytes and
grow as path MTU discovery finds the path carries more, up to
`max_datagram_size`, or by default the route's MTU (up to 9000 bytes) where
the kernel reports it and 1452 bytes otherwise. Throws
`UDP.DeadlineExceededError` when `deadline_ns` passes first, or
[`ConnectionError`](@ref) when the handshake fails.
"""
function connect(
        remote_addr::UDP.SocketAddr,
        config::TLS.Config;
        deadline_ns::Integer = 0,
        local_addr::Union{Nothing, UDP.SocketAddr} = nothing,
        max_data::Integer = _DEFAULT_LIMITS.max_data,
        max_stream_data::Integer = _DEFAULT_LIMITS.max_stream_data,
        max_streams_bidi::Integer = _DEFAULT_LIMITS.max_streams_bidi,
        max_streams_uni::Integer = _DEFAULT_LIMITS.max_streams_uni,
        max_datagram_size::Integer = 0,
    )::Connection
    limits = _stream_limits(max_data, max_stream_data, max_streams_bidi, max_streams_uni)
    deadline = Int64(deadline_ns)
    sock = UDP.connect(remote_addr; local_addr)
    ceiling = _configure_socket!(sock, max_datagram_size)
    ep = _Endpoint(sock, false, nothing, limits)
    ep.pmtu_ceiling = ceiling
    started = false
    slot = nothing
    ok = false
    try
        conn = _client_connection(config, _monotonic_ns(); limits)
        slot = _new_slot!(ep, conn, nothing)
        _start!(ep)
        started = true
        lock(ep.lock)
        try
            while !_handshake_complete(conn)
                _check_conn!(slot)
                _wait!(ep, slot.cond, deadline) || throw(UDP.DeadlineExceededError())
            end
            _check_conn!(slot)
        finally
            unlock(ep.lock)
        end
        ok = true
        return Connection(ep, slot)
    finally
        if !ok
            if started
                # Abandon the handshake silently; the receive task then exits
                # and closes the socket.
                lock(ep.lock)
                try
                    slot === nothing || ((slot::_ConnSlot).conn.state = _ConnState.Closed)
                    _set_socket_deadline!(ep, Int64(1))
                finally
                    unlock(ep.lock)
                end
            else
                close(sock)
            end
        end
    end
end

"""
    listen(local_addr, config; max_data, max_stream_data, max_streams_bidi, max_streams_uni,
           max_datagram_size = 0) -> Listener

Accept QUIC connections on a UDP socket bound to `local_addr` (port 0 for an
ephemeral port; see [`local_addr`](@ref)). `config` is the server
`TLS.Config`, with its certificate and `alpn_protocols`. The limits apply
to each connection's client, as for [`connect`](@ref). An unconnected socket
cannot ask the kernel for a route's MTU, so datagrams grow to at most 1452
bytes unless `max_datagram_size` allows more, as on a jumbo-frame network.
"""
function listen(
        local_addr::UDP.SocketAddr,
        config::TLS.Config;
        max_data::Integer = _DEFAULT_LIMITS.max_data,
        max_stream_data::Integer = _DEFAULT_LIMITS.max_stream_data,
        max_streams_bidi::Integer = _DEFAULT_LIMITS.max_streams_bidi,
        max_streams_uni::Integer = _DEFAULT_LIMITS.max_streams_uni,
        max_datagram_size::Integer = 0,
    )::Listener
    limits = _stream_limits(max_data, max_stream_data, max_streams_bidi, max_streams_uni)
    sock = UDP.listen(local_addr)
    ceiling = _configure_socket!(sock, max_datagram_size)
    ep = _Endpoint(sock, true, config, limits)
    ep.pmtu_ceiling = ceiling
    _start!(ep)
    return Listener(ep)
end

"""
    accept(listener; deadline_ns = 0) -> Connection

The next connection whose handshake completed. Throws `ArgumentError` once
the listener is closed, and `UDP.DeadlineExceededError` when `deadline_ns`
passes first.
"""
function accept(listener::Listener; deadline_ns::Integer = 0)::Connection
    ep = listener.ep
    deadline = Int64(deadline_ns)
    lock(ep.lock)
    try
        while true
            if !isempty(ep.accept_queue)
                slot = popfirst!(ep.accept_queue)
                return Connection(ep, slot)
            end
            ep.accepting || throw(ArgumentError("QUIC listener is closed"))
            _wait!(ep, ep.accept_cond, deadline) || throw(UDP.DeadlineExceededError())
        end
    finally
        unlock(ep.lock)
    end
end

"""
    close(listener)

Stop accepting connections. Connections already accepted go on; the socket
closes once they have all ended.
"""
function Base.close(listener::Listener)::Nothing
    ep = listener.ep
    lock(ep.lock)
    try
        ep.accepting || return nothing
        ep.accepting = false
        now = _monotonic_ns()
        for slot in ep.accept_queue
            _close_connection!(slot.conn, UInt64(0), "", now; app = false)
            _after_op!(ep, slot)
        end
        empty!(ep.accept_queue)
        notify(ep.accept_cond; all = true)
        _set_socket_deadline!(ep, Int64(1))
    finally
        unlock(ep.lock)
    end
    return nothing
end

Base.isopen(listener::Listener)::Bool = lock(() -> listener.ep.accepting, listener.ep.lock)

"""
    local_addr(listener_or_connection) -> UDP.SocketAddr

The local address of the UDP socket.
"""
local_addr(listener::Listener) = UDP.local_addr(listener.ep.sock)
local_addr(c::Connection) = UDP.local_addr(c.ep.sock)

"""
    remote_addr(connection) -> UDP.SocketAddr

The peer's address.
"""
function remote_addr(c::Connection)
    peer = c.slot.peer
    return peer === nothing ? UDP.remote_addr(c.ep.sock) : peer
end

"""
    close(connection; code = 0, reason = "")

Close the connection with application error `code` (RFC 9000 Section
10.2). Blocked operations on it, and later ones, throw
[`ConnectionError`](@ref).
"""
function Base.close(c::Connection; code::Integer = 0, reason::AbstractString = "")::Nothing
    ep = c.ep
    lock(ep.lock)
    try
        _conn_open(c.slot.conn) || return nothing
        _close_connection!(c.slot.conn, UInt64(code), String(reason), _monotonic_ns())
        _after_op!(ep, c.slot)
    finally
        unlock(ep.lock)
    end
    return nothing
end

function Base.isopen(c::Connection)::Bool
    lock(c.ep.lock)
    try
        return _conn_open(c.slot.conn) && c.slot.failure === nothing
    finally
        unlock(c.ep.lock)
    end
end

"""
    alpn_protocol(connection) -> String or nothing

The application protocol the handshake negotiated.
"""
function alpn_protocol(c::Connection)::Union{Nothing, String}
    lock(c.ep.lock)
    try
        return TLS.connection_state(c.slot.conn.tls).alpn_protocol
    finally
        unlock(c.ep.lock)
    end
end

"""
    open_stream(connection; bidi = true, deadline_ns = 0) -> Stream

Open a bidirectional stream, or a unidirectional one this endpoint sends
on. Waits while the peer's stream limit allows no more; throws
`UDP.DeadlineExceededError` when `deadline_ns` passes first. Callers that
wait get streams in the order they began to wait, before any later caller,
as in quic-go: a deadline already past opens a stream only if one is free
and no other caller is waiting for it.
"""
function open_stream(c::Connection; bidi::Bool = true, deadline_ns::Integer = 0)::Stream
    ep = c.ep
    slot = c.slot
    deadline = Int64(deadline_ns)
    queue = bidi ? slot.open_waiting_bidi : slot.open_waiting_uni
    ticket = 0
    lock(ep.lock)
    try
        while true
            _check_conn!(slot)
            # Only the longest waiting caller, or anyone while none waits.
            if isempty(queue) || first(queue) == ticket
                id = _open_stream!(slot.conn; bidi)
                id === nothing || return Stream(c, id::UInt64)
            end
            if ticket == 0
                slot.tickets += 1
                ticket = slot.tickets
                push!(queue, ticket)
            end
            _wait!(ep, slot.cond, deadline) || throw(UDP.DeadlineExceededError())
        end
    finally
        if ticket != 0
            i = findfirst(==(ticket), queue)
            i === nothing || deleteat!(queue, i)
            # The next caller in line may find a stream free now.
            isempty(queue) || notify(slot.cond; all = true)
        end
        unlock(ep.lock)
    end
end

"""
    accept_stream(connection; deadline_ns = 0) -> Stream

The next stream the peer opened, waiting for one.
"""
function accept_stream(c::Connection; deadline_ns::Integer = 0)::Stream
    ep = c.ep
    slot = c.slot
    deadline = Int64(deadline_ns)
    lock(ep.lock)
    try
        while true
            id = _accept_stream!(slot.conn)
            id === nothing || return Stream(c, id::UInt64)
            _check_conn!(slot)
            _wait!(ep, slot.accept_cond, deadline) || throw(UDP.DeadlineExceededError())
        end
    finally
        unlock(ep.lock)
    end
end

# Streams.

"The stream's ID (RFC 9000 Section 2.1)."
stream_id(s::Stream)::UInt64 = s.id

"Whether the stream is bidirectional."
isbidi(s::Stream)::Bool = _is_bidi(s.id)

"""
    set_read_deadline!(stream, deadline_ns)

Make reads throw `UDP.DeadlineExceededError` once the monotonic clock
(`time_ns()`) reaches `deadline_ns`, as for TCP connections: a read after
then fails even when data is waiting, and a read already waiting fails when
the deadline passes. The new deadline applies to reads already waiting too,
waking them at once if it has passed. 0 clears it. The end of the stream,
its reset, and a closed connection are reported first.
"""
function set_read_deadline!(s::Stream, deadline_ns::Integer)::Nothing
    ep = s.conn.ep
    slot = s.conn.slot
    lock(ep.lock)
    try
        s.read_deadline_ns = Int64(deadline_ns)
        # Tasks waiting to read the stream wait again with the new deadline.
        s.id in slot.read_waiting && notify(slot.read_cond; all = true)
    finally
        unlock(ep.lock)
    end
    return nothing
end

"""
    set_write_deadline!(stream, deadline_ns)

As [`set_read_deadline!`](@ref), for writes, including those waiting for
buffer space. `closewrite` (and `close`) send the FIN regardless.
"""
function set_write_deadline!(s::Stream, deadline_ns::Integer)::Nothing
    ep = s.conn.ep
    slot = s.conn.slot
    lock(ep.lock)
    try
        s.write_deadline_ns = Int64(deadline_ns)
        s.id in slot.write_waiting && notify(slot.write_cond; all = true)
    finally
        unlock(ep.lock)
    end
    return nothing
end

# Whether a stream deadline (0 for none) has passed.
_deadline_passed(deadline_ns::Int64)::Bool = deadline_ns != 0 && _monotonic_ns() >= deadline_ns

function _end_reads(s::Stream, err::Union{StreamResetError, StreamStoppedError})
    s.read_end = err
    throw(err)
end

# The application knows the stream's sending side is over, so it can be freed.
function _stop_seen!(conn::_Connection, st::_Stream)::Nothing
    st.stop_seen = true
    _maybe_free_stream!(conn, st)
    return nothing
end

function _end_writes(s::Stream, err::Union{StreamResetError, StreamStoppedError})
    s.write_end = err
    throw(err)
end

# Throws if the stream's receiving side was reset by the peer or stopped
# here. A reset is acknowledged by reading it, which lets the stream be freed.
function _check_read_end!(s::Stream, ep::_Endpoint, slot::_ConnSlot, st::_Stream)::Nothing
    if st.stop_sending_code != _NO_CODE
        _end_reads(s, StreamStoppedError(s.id, st.stop_sending_code, false))
    elseif st.peer_reset_code != _NO_CODE
        _stream_read!(slot.conn, s.id, 0)
        _after_op!(ep, slot)
        _end_reads(s, StreamResetError(s.id, st.peer_reset_code, true))
    end
    return nothing
end

# Throws once the stream's read or write deadline (`deadline_ns`) has passed,
# reporting a closed connection first.
function _check_deadline!(slot::_ConnSlot, deadline_ns::Int64)::Nothing
    _deadline_passed(deadline_ns) || return nothing
    _check_conn!(slot)
    throw(UDP.DeadlineExceededError())
end

# With `ep.lock` held, waits until the stream has bytes to read (`true`) or
# has ended (`false`), throwing for resets, closed connections, and deadlines.
# Each time round the deadline is read again, since `set_read_deadline!`
# wakes waiting readers when it changes.
function _wait_readable!(s::Stream, ep::_Endpoint, slot::_ConnSlot)::Bool
    while true
        # Another task may have stopped the stream meanwhile.
        err = s.read_end
        err === nothing || throw(err)
        conn = slot.conn
        _can_receive(conn, s.id) || throw(ArgumentError("QUIC stream $(s.id) is send-only here"))
        st = get(conn.streams, s.id, nothing)
        st === nothing && return false
        _check_read_end!(s, ep, slot, st)
        rb = st.recv::_StreamReceiveBuffer
        if _recv_finished(rb)
            # Reading nothing at the end lets the stream be freed.
            _stream_read!(conn, s.id, 0)
            _after_op!(ep, slot)
            return false
        end
        _check_deadline!(slot, s.read_deadline_ns)
        _recv_readable(rb) > 0 && return true
        _check_conn!(slot)
        _wait_stream!(ep, slot.read_cond, slot.read_waiting, s.id, s.read_deadline_ns) || throw(UDP.DeadlineExceededError())
    end
end

# Reads up to `max_len` bytes, waiting for at least one; empty at the end of
# the stream.
function _read_some!(s::Stream, max_len::Int)::Vector{UInt8}
    err = s.read_end
    err === nothing || throw(err)
    ep = s.conn.ep
    slot = s.conn.slot
    lock(ep.lock)
    try
        _wait_readable!(s, ep, slot) || return UInt8[]
        r = _stream_read!(slot.conn, s.id, max_len)
        _after_op!(ep, slot)
        return r.data
    finally
        unlock(ep.lock)
    end
end

# As `_read_some!`, into `dst[doff:...]`: returns the count, 0 at the end.
function _read_into!(s::Stream, dst::AbstractVector{UInt8}, doff::Int, max_len::Int)::Int
    err = s.read_end
    err === nothing || throw(err)
    ep = s.conn.ep
    slot = s.conn.slot
    lock(ep.lock)
    try
        _wait_readable!(s, ep, slot) || return 0
        n, _, _ = _stream_read_into!(slot.conn, s.id, dst, doff, max_len)
        _after_op!(ep, slot)
        return n
    finally
        unlock(ep.lock)
    end
end

# Data already waiting is no end, whatever the deadline, as for TCP
# connections; waiting for more respects it.
function Base.eof(s::Stream)::Bool
    ep = s.conn.ep
    slot = s.conn.slot
    lock(ep.lock)
    try
        while true
            err = s.read_end
            err === nothing || throw(err)
            conn = slot.conn
            st = get(conn.streams, s.id, nothing)
            st === nothing && return true
            st.recv === nothing && return true
            _check_read_end!(s, ep, slot, st)
            rb = st.recv::_StreamReceiveBuffer
            _recv_readable(rb) > 0 && return false
            if _recv_finished(rb)
                # Reading nothing at the end lets the stream be freed.
                _stream_read!(conn, s.id, 0)
                _after_op!(ep, slot)
                return true
            end
            _check_conn!(slot)
            _wait_stream!(ep, slot.read_cond, slot.read_waiting, s.id, s.read_deadline_ns) || throw(UDP.DeadlineExceededError())
        end
    finally
        unlock(ep.lock)
    end
end

function Base.bytesavailable(s::Stream)::Int
    lock(s.conn.ep.lock)
    try
        st = get(s.conn.slot.conn.streams, s.id, nothing)
        (st === nothing || st.recv === nothing) && return 0
        return _recv_readable(st.recv::_StreamReceiveBuffer)
    finally
        unlock(s.conn.ep.lock)
    end
end

Base.readavailable(s::Stream)::Vector{UInt8} = _read_some!(s, typemax(Int))

function Base.unsafe_read(s::Stream, p::Ptr{UInt8}, n::UInt)::Nothing
    dst = unsafe_wrap(Array, p, Int(n))
    done = 0
    while done < n
        k = _read_into!(s, dst, done + 1, Int(n) - done)
        k == 0 && throw(EOFError())
        done += k
    end
    return nothing
end

function Base.read(s::Stream, ::Type{UInt8})::UInt8
    b = Vector{UInt8}(undef, 1)
    _read_into!(s, b, 1, 1) == 0 && throw(EOFError())
    return b[1]
end

"""
    readbytes!(stream, b, nb = length(b); all = true) -> Int

Read up to `nb` bytes into `b`, growing it if needed. With `all = true`,
wait until `nb` bytes or the end of the stream; with `all = false`, return
once any bytes have arrived (0 at the end of the stream).
"""
function Base.readbytes!(s::Stream, b::AbstractVector{UInt8}, nb::Integer = length(b); all::Bool = true)::Int
    nb <= 0 && return 0
    # As Base does, `b` grows to take `nb` bytes and is cut back to its old
    # length, or to what was read if that is longer.
    old_len = length(b)
    nb > old_len && resize!(b, Int(nb))
    n = 0
    while n < nb
        k = _read_into!(s, b, n + 1, Int(nb) - n)
        n += k
        (k == 0 || !all) && break
    end
    length(b) > old_len && resize!(b, max(old_len, n))
    return n
end

function Base.read(s::Stream, nb::Integer)::Vector{UInt8}
    out = UInt8[]
    while length(out) < nb
        data = _read_some!(s, Int(nb - length(out)))
        isempty(data) && break
        append!(out, data)
    end
    return out
end

function Base.read(s::Stream)::Vector{UInt8}
    out = UInt8[]
    while true
        data = _read_some!(s, typemax(Int))
        isempty(data) && return out
        append!(out, data)
    end
end

# Writes `data`, then the FIN if `fin`, waiting while the stream has
# `_SEND_BUFFER_LIMIT` bytes unacknowledged.
function _write_bytes!(s::Stream, data::AbstractVector{UInt8}, fin::Bool)::Nothing
    ep = s.conn.ep
    slot = s.conn.slot
    lock(ep.lock)
    try
        pos = 1
        n = length(data)
        while true
            conn = slot.conn
            _check_conn!(slot)
            _can_send(conn, s.id) || throw(ArgumentError("QUIC stream $(s.id) is receive-only here"))
            ended = s.write_end
            ended === nothing || throw(ended)
            st = get(conn.streams, s.id, nothing)
            st === nothing && throw(ArgumentError("QUIC stream $(s.id) is closed"))
            # The peer's STOP_SENDING also resets the stream, so it comes first.
            if st.peer_stop_code != _NO_CODE
                _stop_seen!(conn, st)
                _after_op!(ep, slot)
                _end_writes(s, StreamStoppedError(s.id, st.peer_stop_code, true))
            end
            st.reset_code == _NO_CODE || _end_writes(s, StreamResetError(s.id, st.reset_code, false))
            # A FIN alone goes out whatever the deadline.
            (n > 0 || !fin) && _check_deadline!(slot, s.write_deadline_ns)
            sb = st.send::_StreamSendBuffer
            room = _SEND_BUFFER_LIMIT - Int(_send_end(sb) - sb.base)
            if room > 0 || pos > n
                stop = pos + min(max(room, 0), n - pos + 1) - 1
                last_chunk = stop >= n
                _stream_write!(conn, s.id, view(data, pos:stop); fin = fin && last_chunk)
                pos = stop + 1
                _after_op!(ep, slot)
                last_chunk && return nothing
                continue
            end
            _wait_stream!(ep, slot.write_cond, slot.write_waiting, s.id, s.write_deadline_ns) || throw(UDP.DeadlineExceededError())
        end
    finally
        unlock(ep.lock)
    end
end

function Base.unsafe_write(s::Stream, p::Ptr{UInt8}, n::UInt)::Int
    _write_bytes!(s, unsafe_wrap(Array, p, Int(n)), false)
    return Int(n)
end

function Base.write(s::Stream, data::Union{Vector{UInt8}, SubArray{UInt8, 1}})::Int
    _write_bytes!(s, data, false)
    return length(data)
end

Base.write(s::Stream, b::UInt8)::Int = write(s, UInt8[b])

"Send the stream's FIN: this side has nothing more to write."
Base.closewrite(s::Stream)::Nothing = _write_bytes!(s, UInt8[], true)

function Base.close(s::Stream)::Nothing
    lock(s.conn.ep.lock)
    try
        conn = s.conn.slot.conn
        _conn_open(conn) || return nothing
        st = get(conn.streams, s.id, nothing)
        st === nothing && return nothing
        if st.peer_stop_code != _NO_CODE
            _stop_seen!(conn, st)
            _after_op!(s.conn.ep, s.conn.slot)
            return nothing
        end
        (st.send === nothing || st.reset_code != _NO_CODE || (st.send::_StreamSendBuffer).fin) && return nothing
    finally
        unlock(s.conn.ep.lock)
    end
    closewrite(s)
    return nothing
end

function Base.isopen(s::Stream)::Bool
    lock(s.conn.ep.lock)
    try
        return _conn_open(s.conn.slot.conn) && haskey(s.conn.slot.conn.streams, s.id)
    finally
        unlock(s.conn.ep.lock)
    end
end

"""
    reset_stream!(stream, code)

Abandon the sending side with RESET_STREAM and application error `code`.
Does nothing once the connection has closed.
"""
function reset_stream!(s::Stream, code::Integer)::Nothing
    ep = s.conn.ep
    lock(ep.lock)
    try
        conn = s.conn.slot.conn
        _conn_open(conn) || return nothing
        st = get(conn.streams, s.id, nothing)
        st === nothing || st.peer_stop_code == _NO_CODE || _stop_seen!(conn, st)
        _stream_reset!(conn, s.id, UInt64(code))
        _after_op!(ep, s.conn.slot)
    finally
        unlock(ep.lock)
    end
    return nothing
end

"""
    stop_sending!(stream, code)

Ask the peer to stop sending (STOP_SENDING with application error `code`)
and drop whatever it still sends. Reads then throw
[`StreamStoppedError`](@ref); the receiving side is over, without reading,
once the peer's FIN or RESET_STREAM arrives. Does nothing once the
connection has closed, or after the peer reset the stream or the stream
ended.
"""
function stop_sending!(s::Stream, code::Integer)::Nothing
    ep = s.conn.ep
    lock(ep.lock)
    try
        conn = s.conn.slot.conn
        _conn_open(conn) || return nothing
        st = get(conn.streams, s.id, nothing)
        _stream_stop_sending!(conn, s.id, UInt64(code))
        # The stream may be freed already, so reads remember the stop.
        if st !== nothing && st.stop_sending_code != _NO_CODE && s.read_end === nothing
            s.read_end = StreamStoppedError(s.id, st.stop_sending_code, false)
        end
        _after_op!(ep, s.conn.slot)
    finally
        unlock(ep.lock)
    end
    return nothing
end

function Base.show(io::IO, c::Connection)
    print(io, "QUIC.Connection(", c.slot.conn.is_server ? "server" : "client", ", ", c.slot.conn.state, ")")
    return nothing
end

Base.show(io::IO, ::Listener) = print(io, "QUIC.Listener()")
Base.show(io::IO, s::Stream) = print(io, "QUIC.Stream(", s.id, ")")
