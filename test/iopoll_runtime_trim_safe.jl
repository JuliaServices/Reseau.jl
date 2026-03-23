using Reseau

const NP = Reseau.IOPoll
const IP = Reseau.IOPoll
const SO = Reseau.SocketOps
const _TRIM_EWOULDBLOCK = @static isdefined(Base.Libc, :EWOULDBLOCK) ? Int32(getfield(Base.Libc, :EWOULDBLOCK)) : Int32(Base.Libc.EAGAIN)

function _accept_with_retry(listener::Cint)::Cint
    for _ in 1:5000
        accepted, _, errno = SO.try_accept_socket(listener)
        accepted != -1 && return accepted
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _TRIM_EWOULDBLOCK && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("accept", Int(errno)))
    end
    throw(ArgumentError("timed out waiting for accepted socket"))
end

function _stream_pair()::Tuple{Cint, Cint}
    listener = Cint(-1)
    client = Cint(-1)
    accepted = Cint(-1)
    try
        listener = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        SO.set_sockopt_int(listener, SO.SOL_SOCKET, SO.SO_REUSEADDR, 1)
        SO.bind_socket(listener, SO.sockaddr_in_loopback(0))
        SO.listen_socket(listener, 32)
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
        stream_client = client
        stream_server = accepted
        client = Cint(-1)
        accepted = Cint(-1)
        return stream_client, stream_server
    finally
        accepted >= 0 && SO.close_socket_nothrow(accepted)
        client >= 0 && SO.close_socket_nothrow(client)
        listener >= 0 && SO.close_socket_nothrow(listener)
    end
end

function _close_fd(fd::Cint)::Nothing
    fd < 0 && return nothing
    SO.close_socket_nothrow(fd)
    return nothing
end

function _write_byte(fd::Cint, b::UInt8)::Nothing
    buf = Ref{UInt8}(b)
    for _ in 1:5000
        n = GC.@preserve buf SO.write_once!(fd, Base.unsafe_convert(Ptr{UInt8}, buf), Csize_t(1))
        n == Cssize_t(1) && return nothing
        errno = SO.last_error()
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _TRIM_EWOULDBLOCK && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("write", Int(errno)))
    end
    throw(ArgumentError("timed out writing byte"))
end

function _read_byte(fd::Cint)::UInt8
    buf = Ref{UInt8}(0x00)
    for _ in 1:5000
        n = GC.@preserve buf SO.read_once!(fd, Base.unsafe_convert(Ptr{UInt8}, buf), Csize_t(1))
        n == Cssize_t(1) && return buf[]
        errno = SO.last_error()
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _TRIM_EWOULDBLOCK && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("read", Int(errno)))
    end
    throw(ArgumentError("timed out reading byte"))
end

@inline function _expect_errno_zero(errno::Int32, op::AbstractString)::Nothing
    errno == Int32(0) || throw(SystemError(op, Int(errno)))
    return nothing
end

function run_iopoll_runtime_trim_sample()::Nothing
    fd0 = Cint(-1)
    fd1 = Cint(-1)
    try
        NP.init!()
        fd0, fd1 = _stream_pair()
        registration = NP.register!(fd0; mode = NP.PollMode.READWRITE)
        NP.arm_waiter!(registration, NP.PollMode.READ)
        _write_byte(fd1, 0x44)
        NP.pollwait!(registration.read_waiter) == NP.PollWakeReason.READY || error("expected READY wake reason")
        _read_byte(fd0) == 0x44 || error("unexpected read byte")
        NP.deregister!(fd0)
    finally
        _close_fd(fd0)
        _close_fd(fd1)
        NP.shutdown!()
    end
    return nothing
end

function run_internal_poll_trim_sample()::Nothing
    fd0, fd1 = _stream_pair()
    ipfd = IP.FD(fd0)
    fd0 = Cint(-1)
    try
        IP._set_nonblocking!(ipfd.sysfd)
        IP.register!(ipfd)
        _write_byte(fd1, 0x65)
        read_buf = Vector{UInt8}(undef, 1)
        n = IP.read!(ipfd, read_buf)
        n == 1 || error("expected one byte read")
        read_buf[1] == 0x65 || error("unexpected read byte")
        n = IP.write!(ipfd, UInt8[0x66])
        n == 1 || error("expected one byte written")
        _read_byte(fd1) == 0x66 || error("unexpected peer byte")
    finally
        ipfd.sysfd >= 0 && close(ipfd)
        _close_fd(fd1)
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    try
        run_iopoll_runtime_trim_sample()
        run_internal_poll_trim_sample()
    finally
        NP.shutdown!()
    end
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
