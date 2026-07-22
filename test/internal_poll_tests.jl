using Test
using Reseau

const IP = Reseau.IOPoll
const SO = Reseau.SocketOps
const _IP_EWOULDBLOCK = @static isdefined(Base.Libc, :EWOULDBLOCK) ? Int32(getfield(Base.Libc, :EWOULDBLOCK)) : Int32(Base.Libc.EAGAIN)

function _ip_socketpair_stream()
    listener = SO.INVALID_SOCKET
    client = SO.INVALID_SOCKET
    accepted = SO.INVALID_SOCKET
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
            err = SO.connect_socket(client, SO.sockaddr_in_loopback(port))
            err == Int32(0) || err == Int32(Base.Libc.EISCONN) || throw(SystemError("connect", Int(err)))
        finally
            SO.set_nonblocking!(client, true)
        end
        accepted, _ = _ip_accept_with_retry(listener)
        stream_client = client
        stream_server = accepted
        client = SO.INVALID_SOCKET
        accepted = SO.INVALID_SOCKET
        return stream_client, stream_server
    finally
        SO.is_valid_socket(accepted) && SO.close_socket_nothrow(accepted)
        SO.is_valid_socket(client) && SO.close_socket_nothrow(client)
        SO.is_valid_socket(listener) && SO.close_socket_nothrow(listener)
    end
end

function _ip_close_fd(fd::SO.SocketFD)
    SO.is_valid_socket(fd) || return nothing
    SO.close_socket_nothrow(fd)
    return nothing
end

function _ip_write_byte(fd::SO.SocketFD, b::UInt8)
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

function _ip_accept_with_retry(listener::SO.SocketFD)::Tuple{SO.SocketFD, SO.AcceptPeer}
    for _ in 1:5000
        accepted, peer, errno = SO.try_accept_socket(listener)
        SO.is_valid_socket(accepted) && return accepted, peer
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _IP_EWOULDBLOCK && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("accept", Int(errno)))
    end
    throw(ArgumentError("timed out waiting for accepted socket"))
end

function _ip_wait_connect_ready!(fd::SO.SocketFD)
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
        @testset "stream syscall chunk bounds" begin
            maxrw = 1 << 30
            @test IP._MAX_RW == maxrw
            @test IP._max_rw_chunk(0) == 0
            @test IP._max_rw_chunk(maxrw - 1) == maxrw - 1
            @test IP._max_rw_chunk(maxrw) == maxrw
            @test IP._max_rw_chunk(maxrw + 1) == maxrw
            @test IP._max_rw_chunk(typemax(Int)) == maxrw
            @test IP._checked_write_advance(3, 4, 4) == 7
            err = try
                IP._checked_write_advance(3, 5, 4)
                nothing
            catch ex
                ex
            end
            @test err isa ErrorException
            @test occursin("got 5 from a write of 4", sprint(showerror, err))
        end
        @testset "read waits then wakes on readability" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            read_task = nothing
            fd0 = SO.INVALID_SOCKET
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
                if IP._is_valid_fd(ipfd.sysfd)
                    close(ipfd)
                end
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "read accepts contiguous byte views" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            fd0 = SO.INVALID_SOCKET
            try
                IP._set_nonblocking!(ipfd.sysfd)
                IP.register!(ipfd)
                _ip_write_byte(fd1, 0x6a)
                backing = fill(UInt8(0x00), 3)
                buf = @view backing[2:2]
                n = IP.read!(ipfd, buf)
                @test n == 1
                @test backing == UInt8[0x00, 0x6a, 0x00]
            finally
                IP._is_valid_fd(ipfd.sysfd) && close(ipfd)
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "read deadline timeout" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            fd0 = SO.INVALID_SOCKET
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
                IP._is_valid_fd(ipfd.sysfd) && close(ipfd)
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "absolute deadline semantics" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            fd0 = SO.INVALID_SOCKET
            try
                IP._set_nonblocking!(ipfd.sysfd)
                IP.register!(ipfd)
                # The API accepts absolute monotonic timestamps. Negative
                # values are therefore already expired; overflow prevention
                # belongs where relative durations are added to the clock.
                IP.set_deadline!(ipfd, Int64(-1))
                @test (@atomic :acquire ipfd.pd.rd_ns) == Int64(-1)
                @test (@atomic :acquire ipfd.pd.wd_ns) == Int64(-1)
                @test IP._check_error(ipfd.pd, IP.PollMode.READ) == Int32(2)
                @test IP._check_error(ipfd.pd, IP.PollMode.WRITE) == Int32(2)
                near_max = typemax(Int64) - Int64(1)
                IP.set_read_deadline!(ipfd, near_max)
                @test (@atomic :acquire ipfd.pd.rd_ns) == near_max
                @test IP._check_error(ipfd.pd, IP.PollMode.READ) == Int32(0)
                IP.set_deadline!(ipfd, Int64(0))
                @test (@atomic :acquire ipfd.pd.rd_ns) == Int64(0)
                @test (@atomic :acquire ipfd.pd.wd_ns) == Int64(0)
            finally
                IP._is_valid_fd(ipfd.sysfd) && close(ipfd)
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "stale deadline timer does not poison future waits" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            fd0 = SO.INVALID_SOCKET
            try
                IP._set_nonblocking!(ipfd.sysfd)
                IP.register!(ipfd)
                IP.set_read_deadline!(ipfd, time_ns() + 20_000_000)
                stale_rseq = @atomic :acquire ipfd.pd.rseq
                IP.set_read_deadline!(ipfd, time_ns() + 5_000_000_000)
                IP.deadline_fire!(ipfd.pd, IP.PollMode.READ, stale_rseq, UInt64(0))
                @test IP._check_error(ipfd.pd, IP.PollMode.READ) == Int32(0)
                _ip_write_byte(fd1, 0x63)
                buf = Vector{UInt8}(undef, 1)
                n = IP.read!(ipfd, buf)
                @test n == 1
                @test buf[1] == 0x63
            finally
                IP._is_valid_fd(ipfd.sysfd) && close(ipfd)
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "wait_read retries stale canceled wake internally" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            wait_task = nothing
            fd0 = SO.INVALID_SOCKET
            try
                IP._set_nonblocking!(ipfd.sysfd)
                IP.register!(ipfd)
                # Far-future deadline: it only exists so a live rseq can be
                # captured and later fired stale. A short deadline races the
                # test's own setup and can legitimately expire the waiter.
                IP.set_read_deadline!(ipfd, time_ns() + 5_000_000_000)
                stale_rseq = @atomic :acquire ipfd.pd.rseq
                wait_started = Channel{Nothing}(1)
                wait_task = errormonitor(Threads.@spawn begin
                    put!(wait_started, nothing)
                    IP.waitread(ipfd.pd, ipfd.is_file)
                    return :ok
                end)
                started = IP.timedwait(() -> isready(wait_started), 2.0; pollint = 0.001)
                @test started != :timed_out
                started == :timed_out || take!(wait_started)
                pre = IP.timedwait(() -> istaskdone(wait_task), 0.05; pollint = 0.001)
                @test pre == :timed_out
                IP.set_read_deadline!(ipfd, time_ns() + 5_000_000_000)
                IP.deadline_fire!(ipfd.pd, IP.PollMode.READ, stale_rseq, UInt64(0))
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
                IP._is_valid_fd(ipfd.sysfd) && close(ipfd)
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "combined deadline entry normalization" begin
            registration = IP.Registration(IP.SysFD(7), UInt64(11), IP.PollMode.READWRITE, IP.PollWaiter(), IP.PollWaiter(), false)
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
            fd0 = SO.INVALID_SOCKET
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
                rseq = @atomic :acquire ipfd.pd.rseq
                wseq = @atomic :acquire ipfd.pd.wseq
                IP.deadline_fire!(ipfd.pd, IP.PollMode.READWRITE, rseq, wseq)
                @test IP._check_error(ipfd.pd, IP.PollMode.READ) == Int32(2)
                @test IP._check_error(ipfd.pd, IP.PollMode.WRITE) == Int32(2)
                IP.set_deadline!(ipfd, Int64(0))
                @test IP._check_error(ipfd.pd, IP.PollMode.READ) == Int32(0)
                @test IP._check_error(ipfd.pd, IP.PollMode.WRITE) == Int32(0)
            finally
                IP._is_valid_fd(ipfd.sysfd) && close(ipfd)
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "close evicts blocked waiters" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            read_task = nothing
            fd0 = SO.INVALID_SOCKET
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
        @testset "shutdown closes blocked descriptor waiters" begin
            IP.shutdown!()
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            read_task = nothing
            fd0 = SO.INVALID_SOCKET
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
                @test IP.timedwait(() -> istaskdone(read_task), 0.05; pollint = 0.001) == :timed_out
                IP.shutdown!()
                @test IP.timedwait(() -> istaskdone(read_task), 2.0; pollint = 0.001) != :timed_out
                result = fetch(read_task)
                @test result isa IP.NetClosingError
                @test (@atomic :acquire ipfd.pd.closing)
                @test !(@atomic :acquire ipfd.pd.pollable)
            finally
                if read_task isa Task && istaskdone(read_task)
                    wait(read_task)
                end
                IP._is_valid_fd(ipfd.sysfd) && close(ipfd)
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @static if Sys.iswindows()
            @testset "shutdown drains pending IOCP before releasing raw buffers" begin
                IP.shutdown!()
                fd0, fd1 = _ip_socketpair_stream()
                ipfd = IP.FD(fd0)
                read_task = nothing
                shutdown_task = nothing
                fd0 = SO.INVALID_SOCKET
                try
                    IP._set_nonblocking!(ipfd.sysfd)
                    IP.register!(ipfd)
                    # Exercise the raw-pointer path used by TCP/TLS: the IOCP op
                    # has no object in its buffer root slot, so the task's
                    # GC.@preserve scope must remain parked until shutdown has
                    # observed the terminal completion.
                    read_task = errormonitor(Threads.@spawn begin
                        buf = Vector{UInt8}(undef, 1)
                        return GC.@preserve buf begin
                            try
                                IP._read_ptr_some!(ipfd, pointer(buf), 1)
                                :ok
                            catch err
                                err
                            end
                        end
                    end)
                    state = IP.POLLER[]
                    active = IP.timedwait(2.0; pollint = 0.001) do
                        lock(state.lock)
                        try
                            backend = IP._iocp_backend(state)
                            backend === nothing && return false
                            reg = get(backend.by_fd, ipfd.sysfd, nothing)
                            reg === nothing && return false
                            return (@atomic :acquire reg.read_op.active) && reg.read_op.buffer === nothing
                        finally
                            unlock(state.lock)
                        end
                    end
                    @test active != :timed_out
                    @test !istaskdone(read_task)

                    shutdown_task = errormonitor(Threads.@spawn IP.shutdown!())
                    @test IP.timedwait(() -> istaskdone(shutdown_task), 5.0; pollint = 0.001) != :timed_out
                    wait(shutdown_task)
                    @test IP.timedwait(() -> istaskdone(read_task), 2.0; pollint = 0.001) != :timed_out
                    result = fetch(read_task)
                    @test result isa IP.NetClosingError
                    @test (@atomic :acquire ipfd.pd.closing)
                    @test !(@atomic :acquire ipfd.pd.pollable)
                finally
                    if read_task isa Task && istaskdone(read_task)
                        wait(read_task)
                    end
                    if shutdown_task isa Task && istaskdone(shutdown_task)
                        wait(shutdown_task)
                    end
                    IP._is_valid_fd(ipfd.sysfd) && close(ipfd)
                    _ip_close_fd(fd1)
                    IP.shutdown!()
                end
            end
        end
        @testset "control references delay descriptor destruction" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            control_task = nothing
            close_task = nothing
            release_control = Channel{Nothing}(1)
            fd0 = SO.INVALID_SOCKET
            try
                held_fd = Channel{IP.SysFD}(1)
                control_task = errormonitor(Threads.@spawn begin
                    IP._with_fd_ref(ipfd) do sysfd
                        put!(held_fd, sysfd)
                        take!(release_control)
                        return sysfd
                    end
                end)
                sysfd = take!(held_fd)
                @test sysfd == ipfd.sysfd

                close_task = errormonitor(Threads.@spawn close(ipfd))
                @test IP.timedwait(() -> istaskdone(close_task), 0.05; pollint = 0.001) == :timed_out
                @test ipfd.sysfd == sysfd
                @test SO.get_sockopt_int(sysfd, SO.SOL_SOCKET, SO.SO_KEEPALIVE) >= 0

                put!(release_control, nothing)
                @test IP.timedwait(() -> istaskdone(control_task), 2.0; pollint = 0.001) != :timed_out
                @test fetch(control_task) == sysfd
                @test IP.timedwait(() -> istaskdone(close_task), 2.0; pollint = 0.001) != :timed_out
                @test fetch(close_task) === nothing
                @test ipfd.sysfd == IP.INVALID_FD

                @test_throws IP.NetClosingError IP.shutdown_socket!(ipfd, SO.SHUT_RD)
                @test_throws IP.NetClosingError IP.set_sockopt_int!(ipfd, SO.SOL_SOCKET, SO.SO_KEEPALIVE, 1)
            finally
                if control_task isa Task && !istaskdone(control_task)
                    isready(release_control) || put!(release_control, nothing)
                    wait(control_task)
                end
                if close_task isa Task && !istaskdone(close_task)
                    wait(close_task)
                end
                IP._is_valid_fd(ipfd.sysfd) && close(ipfd)
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "event error maps to not pollable" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            fd0 = SO.INVALID_SOCKET
            try
                IP._set_nonblocking!(ipfd.sysfd)
                IP.register!(ipfd)
                state = IP.POLLER[]
                event = IP.PollEvent(ipfd.sysfd, ipfd.pd.token, IP.PollMode.READ, true)
                IP._dispatch_ready_event!(state, event)
                @test_throws IP.NotPollableError IP.prepareread(ipfd.pd)
            finally
                IP._is_valid_fd(ipfd.sysfd) && close(ipfd)
                _ip_close_fd(fd1)
                IP.shutdown!()
            end
        end
        @testset "wait_canceled wakes on readiness" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            wait_task = nothing
            fd0 = SO.INVALID_SOCKET
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
                IP._is_valid_fd(ipfd.sysfd) && close(ipfd)
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
