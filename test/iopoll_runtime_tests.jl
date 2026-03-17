using Test
using Reseau

const NP = Reseau.IOPoll
const EL = Reseau.IOPoll

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

# These backend helpers block an OS thread inside the raw poll syscall. When
# the Julia scheduler only has one worker thread, using `Threads.@spawn` around
# them would starve the companion task that is supposed to drive the wakeup.
_el_can_block_julia_worker() = Threads.nthreads() > 1

if !(Sys.isapple() || Sys.islinux())
    @testset "IOPoll Runtime (macOS/Linux only)" begin
        @test true
    end
else
    @testset "IOPoll runtime phase 1" begin
        NP.shutdown!()
        @testset "poller-backed sleep/timedwait" begin
            t0 = time_ns()
            EL.sleep(0.03)
            elapsed_ns = time_ns() - t0
            @test elapsed_ns >= 15_000_000
            @test EL.timedwait(() -> false, 0.05; pollint = 0.001) == :timed_out
            wake_ch = Channel{Nothing}(1)
            wake_task = errormonitor(Threads.@spawn begin
                EL.sleep(0.03)
                put!(wake_ch, nothing)
                return nothing
            end)
            status = EL.timedwait(() -> isready(wake_ch), 2.0; pollint = 0.001)
            @test status != :timed_out
            status == :timed_out || take!(wake_ch)
            wait(wake_task)
        end
        @testset "pollwait wake reason precedence" begin
            waiter = NP.PollWaiter()
            @test !NP.pollnotify!(waiter, NP.PollWakeReason.CANCELED)
            @test !NP.pollnotify!(waiter, NP.PollWakeReason.READY)
            @test NP.pollwait!(waiter) == NP.PollWakeReason.READY

            waiter = NP.PollWaiter()
            @test !NP.pollnotify!(waiter, NP.PollWakeReason.READY)
            @test !NP.pollnotify!(waiter, NP.PollWakeReason.CANCELED)
            @test NP.pollwait!(waiter) == NP.PollWakeReason.READY
        end
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
                if _el_can_block_julia_worker()
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
                else
                    @test NP._backend_wake!(state) == Int32(0)
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
        @testset "earlier scheduled deadline wakes poll early" begin
            old_poller = NP.POLLER[]
            state = NP.Poller()
            poll_task = nothing
            fd0 = Cint(-1)
            fd1 = Cint(-1)
            try
                errno = NP._backend_init!(state)
                @test errno == Int32(0)
                @atomic :release state.running = true
                NP.POLLER[] = state
                fd0, fd1 = _el_socketpair_stream()
                token = UInt64(41)
                registration = NP.Registration(fd0, token, NP.PollMode.READWRITE, NP.PollWaiter(), NP.PollWaiter(), false)
                state.registrations[fd0] = registration
                state.registrations_by_token[token] = registration
                @atomic :release state.poll_until_ns = Int64(time_ns()) + Int64(5_000_000_000)
                if _el_can_block_julia_worker()
                    poll_task = errormonitor(Threads.@spawn begin
                        t0 = time_ns()
                        err = NP._backend_poll_once!(state, Int64(5_000_000_000))
                        return err, time_ns() - t0
                    end)
                    sleep(0.03)
                    NP.schedule_deadlines!(registration.pollstate, Int64(time_ns()) + Int64(20_000_000), Int64(0), UInt64(1), UInt64(0))
                    err, elapsed_ns = fetch(poll_task)
                    @test err == Int32(0)
                    @test elapsed_ns < 500_000_000
                else
                    NP.schedule_deadlines!(registration.pollstate, Int64(time_ns()) + Int64(20_000_000), Int64(0), UInt64(1), UInt64(0))
                    delay_ns = NP._poll_delay_ns(state)
                    @test delay_ns >= 0
                    @test delay_ns < 500_000_000
                end
            finally
                if poll_task isa Task && !istaskdone(poll_task)
                    NP._backend_wake!(state)
                    @test _el_wait_task_done(poll_task, 1.0) != :timed_out
                end
                poll_task isa Task && istaskdone(poll_task) && wait(poll_task)
                NP.POLLER[] = old_poller
                _el_close_fd(fd0)
                _el_close_fd(fd1)
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
        @testset "shutdown cancels active waiters and timers" begin
            fd0, fd1 = _el_socketpair_stream()
            reg_task = nothing
            timer_task = nothing
            reg_reason = Ref{Union{Nothing, NP.PollWakeReason.T}}(nothing)
            timer_reason = Ref{Union{Nothing, NP.PollWakeReason.T}}(nothing)
            try
                state = NP.init!()
                registration = NP.register!(fd0; mode = NP.PollMode.READ)
                timer = NP.TimerState()
                @test NP.schedule_timer!(timer, Int64(time_ns()) + Int64(5_000_000_000))
                reg_task = errormonitor(Threads.@spawn begin
                    reg_reason[] = NP.pollwait!(registration.read_waiter)
                    return nothing
                end)
                timer_task = errormonitor(Threads.@spawn begin
                    timer_reason[] = NP.pollwait!(timer.waiter)
                    return nothing
                end)
                sleep(0.05)
                NP._notify_all_waiters!(state)
                @test _el_wait_task_done(reg_task, 2.0) != :timed_out
                @test _el_wait_task_done(timer_task, 2.0) != :timed_out
                wait(reg_task)
                wait(timer_task)
                @test reg_reason[] == NP.PollWakeReason.CANCELED
                @test timer_reason[] == NP.PollWakeReason.CANCELED
                @test (@atomic :acquire timer.closed)
                @test (@atomic :acquire timer.deadline_ns) == Int64(0)
                NP.deregister!(fd0)
            finally
                reg_task isa Task && istaskdone(reg_task) && wait(reg_task)
                timer_task isa Task && istaskdone(timer_task) && wait(timer_task)
                _el_close_fd(fd0)
                _el_close_fd(fd1)
                NP.shutdown!()
            end
        end
    end
end
