using Reseau

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

function _wait_task_done(task::Task, timeout_s::Float64 = 2.0)::Bool
    start_ns = Int64(time_ns())
    timeout_ns = Int64(timeout_s * 1.0e9)
    while !istaskdone(task)
        Int64(time_ns()) - start_ns > timeout_ns && return false
        yield()
    end
    return true
end

function run_iopoll_runtime_trim_sample()::Nothing
    fd0, fd1 = _stream_pair()
    waiter_task = nothing
    try
        registration = IP.register!(fd0; mode = IP.PollMode.READWRITE)
        waiter_task = errormonitor(@async begin
            IP.arm_waiter!(registration, IP.PollMode.READ)
            reason = IP.pollwait!(registration.read_waiter)
            reason == IP.PollWakeReason.READY || error("unexpected wake reason")
            return nothing
        end)
        _write_byte(fd1, 0x44)
        _wait_task_done(waiter_task, 2.0) || error("timed out waiting for iopoll readiness")
        _read_byte(fd0) == 0x44 || error("unexpected iopoll read byte")
        combined = IP._build_deadline_entries(registration.pollstate, Int64(10), Int64(10), UInt64(3), UInt64(5))
        length(combined) == 1 || error("expected one combined deadline entry")
        combined[1].mode == IP.PollMode.READWRITE || error("expected combined read/write entry")
    finally
        waiter_task isa Task && !istaskdone(waiter_task) && wait(waiter_task)
        fd0 >= 0 && IP.deregister!(fd0)
        _close_fd(fd0)
        _close_fd(fd1)
        IP.shutdown!()
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_iopoll_runtime_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
