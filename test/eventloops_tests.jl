using Test
using Reseau

const NP = Reseau.EventLoops

function _el_socketpair_stream()
    fds = Vector{Cint}(undef, 2)
    ret = ccall(:socketpair, Cint, (Cint, Cint, Cint, Ptr{Cint}), Cint(1), Cint(1), Cint(0), pointer(fds))
    ret == 0 || throw(SystemError("socketpair", Int(Base.Libc.errno())))
    return fds[1], fds[2]
end

function _el_close_fd(fd::Cint)
    fd < 0 && return nothing
    ccall(:close, Cint, (Cint,), fd)
    return nothing
end

function _el_write_byte(fd::Cint, b::UInt8)
    buf = Ref{UInt8}(b)
    n = ccall(:write, Cssize_t, (Cint, Ptr{UInt8}, Csize_t), fd, buf, Csize_t(1))
    n == Cssize_t(1) || throw(SystemError("write", Int(Base.Libc.errno())))
    return nothing
end

function _el_read_byte(fd::Cint)
    buf = Ref{UInt8}(0x00)
    n = ccall(:read, Cssize_t, (Cint, Ptr{UInt8}, Csize_t), fd, buf, Csize_t(1))
    n == Cssize_t(1) || throw(SystemError("read", Int(Base.Libc.errno())))
    return buf[]
end

function _el_wait_task_done(task::Task, timeout_s::Float64 = 2.0)
    status = timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
    return status
end

if !(Sys.isapple() || Sys.islinux())
    @testset "EventLoops (macOS/Linux only)" begin
        @test true
    end
else
    @testset "EventLoops kqueue phase 1" begin
        NP.shutdown!()
        @testset "backend delay semantics" begin
            state = NP.Poller()
            errno = NP._backend_init!(state)
            @test errno == Int32(0)
            poll_task = nothing
            try
                t0 = time_ns()
                errno = NP._backend_poll_once!(state, Int64(0))
                elapsed_ns = time_ns() - t0
                @test errno == Int32(0)
                @test elapsed_ns < 50_000_000
                t0 = time_ns()
                errno = NP._backend_poll_once!(state, Int64(30_000_000))
                elapsed_ns = time_ns() - t0
                @test errno == Int32(0)
                @test elapsed_ns >= 15_000_000
                wake_ch = Channel{Nothing}(1)
                poll_task = errormonitor(Threads.@spawn begin
                    err = NP._backend_poll_once!(state, Int64(-1))
                    err == Int32(0) || throw(SystemError("kevent", Int(err)))
                    put!(wake_ch, nothing)
                    return nothing
                end)
                sleep(0.03)
                @test NP._backend_wake!(state) == Int32(0)
                status = timedwait(() -> isready(wake_ch), 2.0; pollint = 0.001)
                @test status != :timed_out
                if status != :timed_out
                    take!(wake_ch)
                    wait(poll_task)
                end
            finally
                if poll_task isa Task && !istaskdone(poll_task)
                    NP._backend_wake!(state)
                    @test _el_wait_task_done(poll_task, 1.0) != :timed_out
                end
                poll_task isa Task && istaskdone(poll_task) && wait(poll_task)
                NP._backend_close!(state)
            end
        end
        @testset "runtime register/pollwait/deregister" begin
            NP.init!()
            fd0, fd1 = _el_socketpair_stream()
            waiter_task = nothing
            try
                registration = NP.register!(fd0; mode = NP.PollMode.READWRITE)
                @test registration.token > 0
                wait_ch = Channel{Nothing}(1)
                waiter_task = errormonitor(Threads.@spawn begin
                    NP.pollwait!(registration.read_waiter)
                    put!(wait_ch, nothing)
                    return nothing
                end)
                pre = timedwait(() -> isready(wait_ch), 0.05; pollint = 0.001)
                @test pre == :timed_out
                _el_write_byte(fd1, 0x33)
                status = timedwait(() -> isready(wait_ch), 2.0; pollint = 0.001)
                @test status != :timed_out
                if status != :timed_out
                    take!(wait_ch)
                    wait(waiter_task)
                    @test _el_read_byte(fd0) == 0x33
                end
                NP.deregister!(fd0)
            finally
                if waiter_task !== nothing && !istaskdone(waiter_task)
                    try
                        NP.deregister!(fd0)
                    catch
                    end
                    @test _el_wait_task_done(waiter_task, 1.0) != :timed_out
                end
                waiter_task isa Task && istaskdone(waiter_task) && wait(waiter_task)
                _el_close_fd(fd0)
                _el_close_fd(fd1)
                NP.shutdown!()
            end
        end
        @testset "stale token suppression" begin
            state = NP.init!()
            fd0, fd1 = _el_socketpair_stream()
            waiter_task = nothing
            try
                registration1 = NP.register!(fd0; mode = NP.PollMode.READ)
                token1 = registration1.token
                NP.deregister!(fd0)
                registration2 = NP.register!(fd0; mode = NP.PollMode.READ)
                token2 = registration2.token
                @test token2 != token1
                wait_ch = Channel{Nothing}(1)
                waiter_task = errormonitor(Threads.@spawn begin
                    NP.pollwait!(registration2.read_waiter)
                    put!(wait_ch, nothing)
                    return nothing
                end)
                sleep(0.02)
                stale = NP.PollEvent(fd0, token1, NP.PollMode.READ, false)
                NP._dispatch_ready_event!(state, stale)
                stale_status = timedwait(() -> isready(wait_ch), 0.05; pollint = 0.001)
                @test stale_status == :timed_out
                _el_write_byte(fd1, 0x44)
                status = timedwait(() -> isready(wait_ch), 2.0; pollint = 0.001)
                @test status != :timed_out
                if status != :timed_out
                    take!(wait_ch)
                    wait(waiter_task)
                    @test _el_read_byte(fd0) == 0x44
                end
                NP.deregister!(fd0)
            finally
                if waiter_task !== nothing && !istaskdone(waiter_task)
                    try
                        NP.deregister!(fd0)
                    catch
                    end
                    @test _el_wait_task_done(waiter_task, 1.0) != :timed_out
                end
                waiter_task isa Task && istaskdone(waiter_task) && wait(waiter_task)
                _el_close_fd(fd0)
                _el_close_fd(fd1)
                NP.shutdown!()
            end
        end
        @testset "shutdown-safe control paths" begin
            NP.init!()
            NP.shutdown!()
            fd0, fd1 = _el_socketpair_stream()
            try
                dereg_task = errormonitor(Threads.@spawn NP.deregister!(fd0))
                @test _el_wait_task_done(dereg_task, 0.5) != :timed_out
                wait(dereg_task)
            finally
                _el_close_fd(fd0)
                _el_close_fd(fd1)
            end
        end
    end
end
