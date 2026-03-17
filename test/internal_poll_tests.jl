using Test
using Reseau

const EL = Reseau.EventLoops
const IP = Reseau.IOPoll

function _ip_socketpair_stream()
    fds = Vector{Cint}(undef, 2)
    ret = ccall(:socketpair, Cint, (Cint, Cint, Cint, Ptr{Cint}), Cint(1), Cint(1), Cint(0), pointer(fds))
    ret == 0 || throw(SystemError("socketpair", Int(Base.Libc.errno())))
    return fds[1], fds[2]
end

function _ip_close_fd(fd::Cint)
    fd < 0 && return nothing
    @ccall close(fd::Cint)::Cint
    return nothing
end

function _ip_write_byte(fd::Cint, b::UInt8)
    buf = Ref{UInt8}(b)
    n = @ccall write(fd::Cint, buf::Ref{UInt8}, Csize_t(1)::Csize_t)::Cssize_t
    n == Cssize_t(1) || throw(SystemError("write", Int(Base.Libc.errno())))
    return nothing
end

if !(Sys.isapple() || Sys.islinux())
    @testset "IOPoll (macOS/Linux only)" begin
        @test true
    end
else
    @testset "IOPoll phase 2" begin
        EL.shutdown!()
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
                pre = EL.timedwait(() -> istaskdone(read_task), 0.05; pollint = 0.001)
                @test pre == :timed_out
                _ip_write_byte(fd1, 0x61)
                status = EL.timedwait(() -> istaskdone(read_task), 2.0; pollint = 0.001)
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
                EL.shutdown!()
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
                EL.shutdown!()
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
                EL.sleep(0.06)
                _ip_write_byte(fd1, 0x63)
                buf = Vector{UInt8}(undef, 1)
                n = IP.read!(ipfd, buf)
                @test n == 1
                @test buf[1] == 0x63
            finally
                ipfd.sysfd >= 0 && close(ipfd)
                _ip_close_fd(fd1)
                EL.shutdown!()
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
                pre = EL.timedwait(() -> istaskdone(wait_task), 0.05; pollint = 0.001)
                @test pre == :timed_out
                IP.set_read_deadline!(ipfd, time_ns() + 5_000_000_000)
                EL.sleep(0.12)
                stale = EL.timedwait(() -> istaskdone(wait_task), 0.02; pollint = 0.001)
                @test stale == :timed_out
                _ip_write_byte(fd1, 0x64)
                status = EL.timedwait(() -> istaskdone(wait_task), 2.0; pollint = 0.001)
                @test status != :timed_out
                status == :timed_out || @test fetch(wait_task) == :ok
            finally
                if wait_task isa Task && !istaskdone(wait_task)
                    close(ipfd)
                end
                ipfd.sysfd >= 0 && close(ipfd)
                _ip_close_fd(fd1)
                EL.shutdown!()
            end
        end
        @testset "combined deadline entry normalization" begin
            registration = EL.Registration(Cint(7), UInt64(11), EL.PollMode.READWRITE, EL.PollWaiter(), EL.PollWaiter(), false)
            combined = EL._build_deadline_entries(registration.pollstate, Int64(10), Int64(10), UInt64(3), UInt64(5))
            @test length(combined) == 1
            @test combined[1].mode == EL.PollMode.READWRITE
            @test combined[1].primary_seq == UInt64(3)
            @test combined[1].secondary_seq == UInt64(5)
            split = EL._build_deadline_entries(registration.pollstate, Int64(10), Int64(11), UInt64(3), UInt64(5))
            @test length(split) == 2
            @test split[1].mode == EL.PollMode.READ
            @test split[2].mode == EL.PollMode.WRITE
        end
        @testset "set_deadline uses one combined heap entry and expires both sides" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            fd0 = Cint(-1)
            try
                IP._set_nonblocking!(ipfd.sysfd)
                IP.register!(ipfd)
                state = EL.POLLER[]
                future_deadline = Int64(time_ns()) + Int64(5_000_000_000)
                IP.set_deadline!(ipfd, future_deadline)
                lock(state.lock)
                try
                    entries = filter(x -> x.kind == EL.TimeEntryKind.DEADLINE && (x.pollstate::EL.PollState).token == ipfd.pd.token, state.time_heap)
                    @test length(entries) == 1
                    @test entries[1].mode == EL.PollMode.READWRITE
                finally
                    unlock(state.lock)
                end
                IP.set_deadline!(ipfd, Int64(time_ns()) + Int64(30_000_000))
                EL.sleep(0.06)
                @test IP._check_error(ipfd.pd, IP.PollOp.READ) == Int32(2)
                @test IP._check_error(ipfd.pd, IP.PollOp.WRITE) == Int32(2)
                IP.set_deadline!(ipfd, Int64(0))
                @test IP._check_error(ipfd.pd, IP.PollOp.READ) == Int32(0)
                @test IP._check_error(ipfd.pd, IP.PollOp.WRITE) == Int32(0)
            finally
                ipfd.sysfd >= 0 && close(ipfd)
                _ip_close_fd(fd1)
                EL.shutdown!()
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
                pre = EL.timedwait(() -> istaskdone(read_task), 0.05; pollint = 0.001)
                @test pre == :timed_out
                close(ipfd)
                status = EL.timedwait(() -> istaskdone(read_task), 2.0; pollint = 0.001)
                @test status != :timed_out
                if status != :timed_out
                    err = fetch(read_task)
                    @test err isa IP.NetClosingError
                end
            finally
                _ip_close_fd(fd1)
                EL.shutdown!()
            end
        end
        @testset "event error maps to not pollable" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            fd0 = Cint(-1)
            try
                IP._set_nonblocking!(ipfd.sysfd)
                IP.register!(ipfd)
                state = EL.POLLER[]
                event = EL.PollEvent(ipfd.sysfd, ipfd.pd.token, EL.PollMode.READ, true)
                EL._dispatch_ready_event!(state, event)
                @test_throws IP.NotPollableError IP.prepareread(ipfd.pd)
            finally
                ipfd.sysfd >= 0 && close(ipfd)
                _ip_close_fd(fd1)
                EL.shutdown!()
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
                    IP.waitcancelled(ipfd.pd, IP.PollOp.READ)
                    return :ok
                end)
                pre = EL.timedwait(() -> istaskdone(wait_task), 0.05; pollint = 0.001)
                @test pre == :timed_out
                _ip_write_byte(fd1, 0x71)
                status = EL.timedwait(() -> istaskdone(wait_task), 2.0; pollint = 0.001)
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
                EL.shutdown!()
            end
        end
        @testset "fdlock close wakes queued waiters" begin
            mu = IP.FDLock()
            @test IP._fdlock_rwlock!(mu, true, true)
            waiters = [errormonitor(Threads.@spawn IP._fdlock_rwlock!(mu, true, true)) for _ in 1:32]
            pre = EL.timedwait(() -> all(istaskdone, waiters), 0.05; pollint = 0.001)
            @test pre == :timed_out
            @test IP._fdlock_incref_and_close!(mu)
            _ = IP._fdlock_rwunlock!(mu, true)
            for waiter in waiters
                status = EL.timedwait(() -> istaskdone(waiter), 2.0; pollint = 0.001)
                @test status != :timed_out
                if status != :timed_out
                    @test fetch(waiter) == false
                end
            end
        end
    end
end
