using Reseau

const IP = Reseau.IOPoll
const SO = Reseau.SocketOps
const _SO_EWOULDBLOCK = @static isdefined(Base.Libc, :EWOULDBLOCK) ? Int32(getfield(Base.Libc, :EWOULDBLOCK)) : Int32(Base.Libc.EAGAIN)

function _accept_with_retry(listener::Cint)::Cint
    for _ in 1:5000
        accepted, _, errno = SO.try_accept_socket(listener)
        accepted != -1 && return accepted
        if errno == Int32(Base.Libc.EAGAIN)
            yield()
            continue
        end
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("accept", Int(errno)))
    end
    throw(ArgumentError("timed out waiting for accepted socket"))
end

function _write_all!(fd::Cint, data::Vector{UInt8})::Nothing
    offset = 0
    while offset < length(data)
        n = GC.@preserve data SO.write_once!(fd, pointer(data, offset + 1), Csize_t(length(data) - offset))
        if n > 0
            offset += Int(n)
            continue
        end
        n == 0 && error("expected non-zero write progress")
        errno = Int32(Base.Libc.errno())
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _SO_EWOULDBLOCK && (yield(); continue)
        throw(SystemError("write", Int(errno)))
    end
    return nothing
end

function _read_exact!(fd::Cint, data::Vector{UInt8})::Nothing
    offset = 0
    while offset < length(data)
        n = GC.@preserve data SO.read_once!(fd, pointer(data, offset + 1), Csize_t(length(data) - offset))
        if n > 0
            offset += Int(n)
            continue
        end
        n == 0 && error("unexpected EOF")
        errno = Int32(Base.Libc.errno())
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _SO_EWOULDBLOCK && (yield(); continue)
        throw(SystemError("read", Int(errno)))
    end
    return nothing
end

function run_socket_ops_trim_sample()::Nothing
    listener = Cint(-1)
    client = Cint(-1)
    accepted = Cint(-1)
    try
        listener = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        SO.set_sockopt_int(listener, SO.SOL_SOCKET, SO.SO_REUSEADDR, 1)
        SO.bind_socket(listener, SO.sockaddr_in_loopback(0))
        SO.listen_socket(listener, 16)
        bound = SO.get_socket_name_in(listener)
        port = Int(SO.sockaddr_in_port(bound))
        client = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        SO.set_nonblocking!(client, false)
        try
            errno = SO.connect_socket(client, SO.sockaddr_in_loopback(port))
            errno == Int32(0) || errno == Int32(Base.Libc.EISCONN) || throw(SystemError("connect", Int(errno)))
        finally
            SO.set_nonblocking!(client, true)
        end
        accepted = _accept_with_retry(listener)
        payload = UInt8[0x71, 0x72, 0x73]
        recv_buf = Vector{UInt8}(undef, length(payload))
        _write_all!(client, payload)
        _read_exact!(accepted, recv_buf)
        recv_buf == payload || error("payload mismatch")
    finally
        accepted >= 0 && SO.close_socket_nothrow(accepted)
        client >= 0 && SO.close_socket_nothrow(client)
        listener >= 0 && SO.close_socket_nothrow(listener)
        IP.shutdown!()
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_socket_ops_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
