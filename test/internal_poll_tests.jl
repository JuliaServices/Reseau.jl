using Test
using Reseau

const IP = Reseau.IOPoll
const SO = Reseau.SocketOps
const _IP_EWOULDBLOCK = @static isdefined(Base.Libc, :EWOULDBLOCK) ? Int32(getfield(Base.Libc, :EWOULDBLOCK)) : Int32(Base.Libc.EAGAIN)

function _ip_socketpair_stream()
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
        if Sys.iswindows()
            SO.set_nonblocking!(client, false)
            try
                err = SO.connect_socket(client, SO.sockaddr_in_loopback(port))
                err == Int32(0) || err == Int32(Base.Libc.EISCONN) || throw(SystemError("connect", Int(err)))
            finally
                SO.set_nonblocking!(client, true)
            end
        else
            err = SO.connect_socket(client, SO.sockaddr_in_loopback(port))
            if err != Int32(0) && err != Int32(Base.Libc.EISCONN)
                err == Int32(Base.Libc.EINPROGRESS) || err == Int32(Base.Libc.EALREADY) || err == Int32(Base.Libc.EINTR) || throw(SystemError("connect", Int(err)))
                _ip_wait_connect_ready!(client)
                so_error = SO.get_socket_error(client)
                so_error == Int32(0) || throw(SystemError("connect(SO_ERROR)", Int(so_error)))
            end
        end
        accepted, _ = _ip_accept_with_retry(listener)
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

function _ip_close_fd(fd::Cint)
    fd < 0 && return nothing
    SO.close_socket_nothrow(fd)
    return nothing
end

function _ip_write_byte(fd::Cint, b::UInt8)
    buf = Ref{UInt8}(b)
    for _ in 1:5000
        n = GC.@preserve buf SO.write_once!(fd, Base.unsafe_convert(Ptr{UInt8}, buf), Csize_t(1))
        n == Cssize_t(1) && return nothing
        errno = SO.last_error()
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _IP_EWOULDBLOCK && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("write", Int(errno)))
    end
    throw(ArgumentError("timed out writing byte"))
end

function _ip_accept_with_retry(listener::Cint)::Tuple{Cint, SO.AcceptPeer}
    for _ in 1:5000
        accepted, peer, errno = SO.try_accept_socket(listener)
        accepted != -1 && return accepted, peer
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _IP_EWOULDBLOCK && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("accept", Int(errno)))
    end
    throw(ArgumentError("timed out waiting for accepted socket"))
end

function _ip_wait_connect_ready!(fd::Cint)
    registration = IP.register!(fd; mode = IP.PollMode.WRITE)
    try
        IP.arm_waiter!(registration, IP.PollMode.WRITE)
        IP.pollwait!(registration.write_waiter)
    finally
        IP.deregister!(fd)
    end
    return nothing
end

@testset "IOPoll phase 2" begin
        IP.shutdown!()
        @testset "read waits then wakes on readability" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            read_task = nothing
            fd0 = Cint(-1)
            try
                IP._set_nonblocking!(ipfd.sysfd)
                IP.register!(ipfd)
                read_task = errormonitor(Threads.@spawn begin
                    buf = Vector{UInt8}(undef, 1)
                    n = IP.read!(ipfd, buf)
                    return n, buf[1]
                end)
                pre = IP.timedwait(() -> istaskdone(read_task), 0.05; pollint = 0.001)
                @test pre == :timed_out
                _ip_write_byte(fd1, 0x61)
                status = IP.timedwait(() -> istaskdone(read_task), 2.0; pollint = 0.001)
                @test status != :timed_out
                if status != :timed_out
                    n, b = fetch(read_task)
                    @test n == 1
                    @test b == 0x61
                end
            finally
                if read_task isa Task && !istaskdone(read_task)
                    close(ipfd)
                end
                if ipfd.sysfd >= 0
                    close(ipfd)
                end
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "read deadline timeout" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            fd0 = Cint(-1)
            try
                IP._set_nonblocking!(ipfd.sysfd)
                IP.register!(ipfd)
                IP.set_read_deadline!(ipfd, time_ns() + 40_000_000)
                @test_throws IP.DeadlineExceededError IP.read!(ipfd, Vector{UInt8}(undef, 1))
                IP.set_read_deadline!(ipfd, Int64(0))
                _ip_write_byte(fd1, 0x62)
                n = IP.read!(ipfd, Vector{UInt8}(undef, 1))
                @test n == 1
            finally
                ipfd.sysfd >= 0 && close(ipfd)
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "stale deadline timer does not poison future waits" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            fd0 = Cint(-1)
            try
                IP._set_nonblocking!(ipfd.sysfd)
                IP.register!(ipfd)
                IP.set_read_deadline!(ipfd, time_ns() + 20_000_000)
                IP.set_read_deadline!(ipfd, time_ns() + 5_000_000_000)
                IP.sleep(0.06)
                _ip_write_byte(fd1, 0x63)
                buf = Vector{UInt8}(undef, 1)
                n = IP.read!(ipfd, buf)
                @test n == 1
                @test buf[1] == 0x63
            finally
                ipfd.sysfd >= 0 && close(ipfd)
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "wait_read retries stale canceled wake internally" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            wait_task = nothing
            fd0 = Cint(-1)
            try
                IP._set_nonblocking!(ipfd.sysfd)
                IP.register!(ipfd)
                IP.set_read_deadline!(ipfd, time_ns() + 100_000_000)
                wait_task = errormonitor(Threads.@spawn begin
                    IP.waitread(ipfd.pd, ipfd.is_file)
                    return :ok
                end)
                pre = IP.timedwait(() -> istaskdone(wait_task), 0.05; pollint = 0.001)
                @test pre == :timed_out
                IP.set_read_deadline!(ipfd, time_ns() + 5_000_000_000)
                IP.sleep(0.12)
                stale = IP.timedwait(() -> istaskdone(wait_task), 0.02; pollint = 0.001)
                @test stale == :timed_out
                _ip_write_byte(fd1, 0x64)
                status = IP.timedwait(() -> istaskdone(wait_task), 2.0; pollint = 0.001)
                @test status != :timed_out
                status == :timed_out || @test fetch(wait_task) == :ok
            finally
                if wait_task isa Task && !istaskdone(wait_task)
                    close(ipfd)
                end
                ipfd.sysfd >= 0 && close(ipfd)
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "combined deadline entry normalization" begin
            registration = IP.Registration(Cint(7), UInt64(11), IP.PollMode.READWRITE, IP.PollWaiter(), IP.PollWaiter(), false)
            combined = IP._build_deadline_entries(registration.pollstate, Int64(10), Int64(10), UInt64(3), UInt64(5))
            @test length(combined) == 1
            @test combined[1].mode == IP.PollMode.READWRITE
            @test combined[1].primary_seq == UInt64(3)
            @test combined[1].secondary_seq == UInt64(5)
            split = IP._build_deadline_entries(registration.pollstate, Int64(10), Int64(11), UInt64(3), UInt64(5))
            @test length(split) == 2
            @test split[1].mode == IP.PollMode.READ
            @test split[2].mode == IP.PollMode.WRITE
        end
        @testset "set_deadline uses one combined heap entry and expires both sides" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            fd0 = Cint(-1)
            try
                IP._set_nonblocking!(ipfd.sysfd)
                IP.register!(ipfd)
                state = IP.POLLER[]
                future_deadline = Int64(time_ns()) + Int64(5_000_000_000)
                IP.set_deadline!(ipfd, future_deadline)
                lock(state.lock)
                try
                    entries = filter(x -> x.kind == IP.TimeEntryKind.DEADLINE && (x.pollstate::IP.PollState).token == ipfd.pd.token, state.time_heap)
                    @test length(entries) == 1
                    @test entries[1].mode == IP.PollMode.READWRITE
                finally
                    unlock(state.lock)
                end
                IP.set_deadline!(ipfd, Int64(time_ns()) + Int64(30_000_000))
                IP.sleep(0.06)
                @test IP._check_error(ipfd.pd, IP.PollMode.READ) == Int32(2)
                @test IP._check_error(ipfd.pd, IP.PollMode.WRITE) == Int32(2)
                IP.set_deadline!(ipfd, Int64(0))
                @test IP._check_error(ipfd.pd, IP.PollMode.READ) == Int32(0)
                @test IP._check_error(ipfd.pd, IP.PollMode.WRITE) == Int32(0)
            finally
                ipfd.sysfd >= 0 && close(ipfd)
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "close evicts blocked waiters" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            read_task = nothing
            fd0 = Cint(-1)
            try
                IP._set_nonblocking!(ipfd.sysfd)
                IP.register!(ipfd)
                read_task = errormonitor(Threads.@spawn begin
                    try
                        IP.read!(ipfd, Vector{UInt8}(undef, 1))
                        return :ok
                    catch err
                        return err
                    end
                end)
                pre = IP.timedwait(() -> istaskdone(read_task), 0.05; pollint = 0.001)
                @test pre == :timed_out
                close(ipfd)
                status = IP.timedwait(() -> istaskdone(read_task), 2.0; pollint = 0.001)
                @test status != :timed_out
                if status != :timed_out
                    err = fetch(read_task)
                    @test err isa IP.NetClosingError
                end
            finally
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "event error maps to not pollable" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            fd0 = Cint(-1)
            try
                IP._set_nonblocking!(ipfd.sysfd)
                IP.register!(ipfd)
                state = IP.POLLER[]
                event = IP.PollEvent(ipfd.sysfd, ipfd.pd.token, IP.PollMode.READ, true)
                IP._dispatch_ready_event!(state, event)
                @test_throws IP.NotPollableError IP.prepareread(ipfd.pd)
            finally
                ipfd.sysfd >= 0 && close(ipfd)
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "wait_canceled wakes on readiness" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            wait_task = nothing
            fd0 = Cint(-1)
            try
                IP._set_nonblocking!(ipfd.sysfd)
                IP.register!(ipfd)
                wait_task = errormonitor(Threads.@spawn begin
                    IP.waitcancelled(ipfd.pd, IP.PollMode.READ)
                    return :ok
                end)
                pre = IP.timedwait(() -> istaskdone(wait_task), 0.05; pollint = 0.001)
                @test pre == :timed_out
                _ip_write_byte(fd1, 0x71)
                status = IP.timedwait(() -> istaskdone(wait_task), 2.0; pollint = 0.001)
                @test status != :timed_out
                if status != :timed_out
                    @test fetch(wait_task) == :ok
                end
            finally
                if wait_task isa Task && !istaskdone(wait_task)
                    close(ipfd)
                end
                ipfd.sysfd >= 0 && close(ipfd)
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "fdlock close wakes queued waiters" begin
            mu = IP.FDLock()
            @test IP._fdlock_rwlock!(mu, true, true)
            waiters = [errormonitor(Threads.@spawn IP._fdlock_rwlock!(mu, true, true)) for _ in 1:32]
            pre = IP.timedwait(() -> all(istaskdone, waiters), 0.05; pollint = 0.001)
            @test pre == :timed_out
            @test IP._fdlock_incref_and_close!(mu)
            _ = IP._fdlock_rwunlock!(mu, true)
            for waiter in waiters
                status = IP.timedwait(() -> istaskdone(waiter), 2.0; pollint = 0.001)
                @test status != :timed_out
                if status != :timed_out
                    @test fetch(waiter) == false
                end
            end
        end
    end
end
