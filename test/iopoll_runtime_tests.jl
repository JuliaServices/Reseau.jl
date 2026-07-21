using Test
using Reseau

const NP = Reseau.IOPoll
const IP = Reseau.IOPoll
const SO = Reseau.SocketOps
const _EL_EWOULDBLOCK = @static isdefined(Base.Libc, :EWOULDBLOCK) ? Int32(getfield(Base.Libc, :EWOULDBLOCK)) : Int32(Base.Libc.EAGAIN)

function _el_socketpair_stream()
    listener = Cint(-1)
    client = Cint(-1)
    accepted = Cint(-1)
    try
        _el_log_test_progress("_el_socketpair_stream: listener")
        listener = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        SO.set_sockopt_int(listener, SO.SOL_SOCKET, SO.SO_REUSEADDR, 1)
        SO.bind_socket(listener, SO.sockaddr_in_loopback(0))
        SO.listen_socket(listener, 32)
        bound = SO.get_socket_name_in(listener)
        port = Int(SO.sockaddr_in_port(bound))
        _el_log_test_progress("_el_socketpair_stream: connect")
        client = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        SO.set_nonblocking!(client, false)
        try
            err = SO.connect_socket(client, SO.sockaddr_in_loopback(port))
            err == Int32(0) || err == Int32(Base.Libc.EISCONN) || throw(SystemError("connect", Int(err)))
        finally
            SO.set_nonblocking!(client, true)
        end
        _el_log_test_progress("_el_socketpair_stream: accept")
        accepted, _ = _el_accept_with_retry(listener)
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

function _el_open_stream_fd()::Cint
    return SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
end

function _el_close_fd(fd::Cint)
    fd < 0 && return nothing
    SO.close_socket_nothrow(fd)
    return nothing
end

function _el_write_byte(fd::Cint, b::UInt8)
    buf = Ref{UInt8}(b)
    for _ in 1:5000
        n = GC.@preserve buf SO.write_once!(fd, Base.unsafe_convert(Ptr{UInt8}, buf), Csize_t(1))
        n == Cssize_t(1) && return nothing
        errno = SO.last_error()
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _EL_EWOULDBLOCK && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("write", Int(errno)))
    end
    throw(ArgumentError("timed out writing byte"))
end

function _el_read_byte(fd::Cint)
    buf = Ref{UInt8}(0x00)
    for _ in 1:5000
        n = GC.@preserve buf SO.read_once!(fd, Base.unsafe_convert(Ptr{UInt8}, buf), Csize_t(1))
        n == Cssize_t(1) && return buf[]
        errno = SO.last_error()
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _EL_EWOULDBLOCK && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("read", Int(errno)))
    end
    throw(ArgumentError("timed out reading byte"))
end

function _el_wait_task_done(task::Task, timeout_s::Float64 = 2.0)
    status = timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
    return status
end

function _el_wait_channel_ready(ch::Channel{Nothing}, timeout_s::Float64 = 2.0)
    status = timedwait(() -> isready(ch), timeout_s; pollint = 0.001)
    status == :timed_out || take!(ch)
    return status
end

function _el_log_test_progress(msg::AbstractString)
    println("[iopoll_runtime_tests] ", msg)
    flush(stdout)
    return nothing
end

# These backend helpers block an OS thread inside the raw poll syscall. When
# the Julia scheduler only has one worker thread, using `Threads.@spawn` around
# them would starve the companion task that is supposed to drive the wakeup.
_el_can_block_julia_worker() = Threads.nthreads() > 1

function _el_accept_with_retry(listener::Cint)::Tuple{Cint, SO.AcceptPeer}
    for _ in 1:5000
        accepted, peer, errno = SO.try_accept_socket(listener)
        accepted != -1 && return accepted, peer
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _EL_EWOULDBLOCK && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("accept", Int(errno)))
    end
    throw(ArgumentError("timed out waiting for accepted socket"))
end

function _el_wait_connect_ready!(fd::Cint)
    registration = IP.register!(fd; mode = IP.PollMode.WRITE)
    try
        # Unix backends observe writability directly from the registration, but
        # IOCP requires an explicit probe submission before a waiter can block.
        IP.arm_waiter!(registration, IP.PollMode.WRITE)
        IP.pollwait!(registration.write_waiter)
    finally
        IP.deregister!(fd)
    end
    return nothing
end

@testset "IOPoll runtime phase 1" begin
        NP.shutdown!()
        _el_log_test_progress("START: poller-backed sleep/timedwait")
        @testset "poller-backed sleep/timedwait" begin
            _el_log_test_progress("poller-backed sleep/timedwait: sleep")
            t0 = time_ns()
            IP.sleep(0.03)
            elapsed_ns = time_ns() - t0
            @test elapsed_ns >= 15_000_000
            _el_log_test_progress("poller-backed sleep/timedwait: timedwait false")
            @test IP.timedwait(() -> false, 0.05; pollint = 0.001) == :timed_out
            wake_ch = Channel{Nothing}(1)
            _el_log_test_progress("poller-backed sleep/timedwait: spawn wake task")
            wake_task = errormonitor(@async begin
                IP.sleep(0.03)
                put!(wake_ch, nothing)
                return nothing
            end)
            _el_log_test_progress("poller-backed sleep/timedwait: wait for wake")
            status = IP.timedwait(() -> isready(wake_ch), 2.0; pollint = 0.001)
            @test status != :timed_out
            status == :timed_out || take!(wake_ch)
            wait(wake_task)
        end
        _el_log_test_progress("DONE: poller-backed sleep/timedwait")
        _el_log_test_progress("START: pollwait wake reason precedence")
        @testset "pollwait wake reason precedence" begin
            waiter = NP.PollWaiter()
            @test !NP.pollnotify!(waiter, NP.PollWakeReason.CANCELED)
            @test (@atomic :acquire waiter.state) == NP.PollWaiterState.CANCELED
            @test !NP.pollnotify!(waiter, NP.PollWakeReason.READY)
            @test (@atomic :acquire waiter.state) == NP.PollWaiterState.NOTIFIED
            @test NP.pollwait!(waiter) == NP.PollWakeReason.READY
            @test (@atomic :acquire waiter.state) == NP.PollWaiterState.EMPTY

            waiter = NP.PollWaiter()
            @test !NP.pollnotify!(waiter, NP.PollWakeReason.READY)
            @test !NP.pollnotify!(waiter, NP.PollWakeReason.CANCELED)
            @test (@atomic :acquire waiter.state) == NP.PollWaiterState.NOTIFIED
            @test NP.pollwait!(waiter) == NP.PollWakeReason.READY

            waiter = NP.PollWaiter()
            @test !NP.pollnotify!(waiter, NP.PollWakeReason.CANCELED)
            @test NP.pollwait!(waiter) == NP.PollWakeReason.CANCELED
            @test (@atomic :acquire waiter.state) == NP.PollWaiterState.EMPTY

            for i in 1:128
                waiter = NP.PollWaiter()
                expected = isodd(i) ? NP.PollWakeReason.READY : NP.PollWakeReason.CANCELED
                waiter_task = errormonitor(Threads.@spawn NP.pollwait!(waiter))
                deadline = time_ns() + 2_000_000_000
                while (@atomic :acquire waiter.state) != NP.PollWaiterState.WAITING && !istaskdone(waiter_task)
                    time_ns() < deadline || error("timed out waiting for PollWaiter to park")
                    yield()
                end
                @test NP.pollnotify!(waiter, expected)
                @test fetch(waiter_task) == expected
                @test (@atomic :acquire waiter.state) == NP.PollWaiterState.EMPTY
            end
        end
        _el_log_test_progress("DONE: pollwait wake reason precedence")
        _el_log_test_progress("START: backend delay semantics")
        @testset "backend delay semantics" begin
            state = NP.Poller()
            errno = NP._backend_init!(state)
            @test errno == Int32(0)
            poll_task = nothing
            try
                _el_log_test_progress("backend delay semantics: zero timeout")
                t0 = time_ns()
                errno = NP._backend_poll_once!(state, Int64(0))
                elapsed_ns = time_ns() - t0
                @test errno == Int32(0)
                @test elapsed_ns < 50_000_000
                _el_log_test_progress("backend delay semantics: finite timeout")
                t0 = time_ns()
                errno = NP._backend_poll_once!(state, Int64(30_000_000))
                elapsed_ns = time_ns() - t0
                @test errno == Int32(0)
                @test elapsed_ns >= 15_000_000
                if _el_can_block_julia_worker()
                    _el_log_test_progress("backend delay semantics: blocking wake")
                    wake_ch = Channel{Nothing}(1)
                    poll_task = errormonitor(Threads.@spawn begin
                        err = NP._backend_poll_once!(state, Int64(-1))
                        err == Int32(0) || throw(SystemError("backend poll", Int(err)))
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
        _el_log_test_progress("DONE: backend delay semantics")
        _el_log_test_progress("START: earlier scheduled deadline wakes poll early")
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
                fd0 = _el_open_stream_fd()
                fd1 = Cint(-1)
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
        _el_log_test_progress("DONE: earlier scheduled deadline wakes poll early")
        _el_log_test_progress("START: runtime register/pollwait/deregister")
        @testset "runtime register/pollwait/deregister" begin
            _el_log_test_progress("runtime register/pollwait/deregister: init")
            NP.init!()
            _el_log_test_progress("runtime register/pollwait/deregister: socketpair")
            fd0, fd1 = _el_socketpair_stream()
            waiter_task = nothing
            try
                _el_log_test_progress("runtime register/pollwait/deregister: register")
                registration = NP.register!(fd0; mode = NP.PollMode.READWRITE)
                @test registration.token > 0
                wait_ch = Channel{Nothing}(1)
                wait_started = Channel{Nothing}(1)
                waiter_task = errormonitor(@async begin
                    NP.arm_waiter!(registration, NP.PollMode.READ)
                    put!(wait_started, nothing)
                    NP.pollwait!(registration.read_waiter)
                    put!(wait_ch, nothing)
                    return nothing
                end)
                @test _el_wait_channel_ready(wait_started, 2.0) != :timed_out
                pre = timedwait(() -> isready(wait_ch), 0.05; pollint = 0.001)
                @test pre == :timed_out
                _el_log_test_progress("runtime register/pollwait/deregister: trigger read ready")
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
        _el_log_test_progress("DONE: runtime register/pollwait/deregister")
        _el_log_test_progress("START: stale token suppression")
        @testset "stale token suppression" begin
            state = NP.init!()
            fd0, fd1 = _el_socketpair_stream()
            waiter_task = nothing
            try
                registration1 = NP.register!(fd0; mode = NP.PollMode.READ)
                token1 = registration1.token
                NP.deregister!(fd0)
                _el_close_fd(fd0)
                _el_close_fd(fd1)
                fd0 = Cint(-1)
                fd1 = Cint(-1)
                fd0, fd1 = _el_socketpair_stream()
                registration2 = NP.register!(fd0; mode = NP.PollMode.READ)
                token2 = registration2.token
                @test token2 != token1
                wait_ch = Channel{Nothing}(1)
                wait_started = Channel{Nothing}(1)
                waiter_task = errormonitor(@async begin
                    NP.arm_waiter!(registration2, NP.PollMode.READ)
                    put!(wait_started, nothing)
                    NP.pollwait!(registration2.read_waiter)
                    put!(wait_ch, nothing)
                    return nothing
                end)
                @test _el_wait_channel_ready(wait_started, 2.0) != :timed_out
                stale = NP.PollEvent(Cint(-1), token1, NP.PollMode.READ, false)
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
        _el_log_test_progress("DONE: stale token suppression")
        _el_log_test_progress("START: stale pollstate close preserves active registration")
        @testset "stale pollstate close preserves active registration" begin
            fd0, fd1 = _el_socketpair_stream()
            waiter_task = nothing
            try
                registration = NP.register!(fd0; mode = NP.PollMode.READ)
                stale_pd = NP.PollState(fd0, registration.token - UInt64(1))
                @atomic :release stale_pd.pollable = true
                close(stale_pd)
                @test NP.current_registration(registration.pollstate) === registration
                wait_ch = Channel{Nothing}(1)
                wait_started = Channel{Nothing}(1)
                waiter_task = errormonitor(@async begin
                    NP.arm_waiter!(registration, NP.PollMode.READ)
                    put!(wait_started, nothing)
                    NP.pollwait!(registration.read_waiter)
                    put!(wait_ch, nothing)
                    return nothing
                end)
                @test _el_wait_channel_ready(wait_started, 2.0) != :timed_out
                _el_write_byte(fd1, 0x55)
                status = timedwait(() -> isready(wait_ch), 2.0; pollint = 0.001)
                @test status != :timed_out
                if status != :timed_out
                    take!(wait_ch)
                    wait(waiter_task)
                    @test _el_read_byte(fd0) == 0x55
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
        _el_log_test_progress("DONE: stale pollstate close preserves active registration")
        _el_log_test_progress("START: shutdown-safe control paths")
        @testset "shutdown-safe control paths" begin
            NP.init!()
            NP.shutdown!()
            fd0, fd1 = _el_socketpair_stream()
            try
                dereg_task = errormonitor(@async NP.deregister!(fd0))
                @test _el_wait_task_done(dereg_task, 0.5) != :timed_out
                wait(dereg_task)
            finally
                _el_close_fd(fd0)
                _el_close_fd(fd1)
            end
        end
        _el_log_test_progress("DONE: shutdown-safe control paths")
        _el_log_test_progress("START: shutdown wakes timer waiters")
        @testset "shutdown wakes timer waiters" begin
            NP.shutdown!()
            timer = NP.TimerState()
            @test NP.schedule_timer!(timer, Int64(time_ns()) + Int64(60_000_000_000))
            timer_task = errormonitor(@async NP.waittimer(timer))
            try
                NP.shutdown!()
                @test _el_wait_task_done(timer_task, 1.0) != :timed_out
                @test fetch(timer_task) === false
                @test (@atomic :acquire timer.closed)
                @test (@atomic :acquire timer.deadline_ns) == Int64(0)
            finally
                timer_task isa Task && istaskdone(timer_task) && wait(timer_task)
                NP.shutdown!()
            end
        end
        _el_log_test_progress("DONE: shutdown wakes timer waiters")
        _el_log_test_progress("START: shutdown cancels active waiters and timers")
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
                reg_started = Channel{Nothing}(1)
                timer_started = Channel{Nothing}(1)
                reg_task = errormonitor(@async begin
                    put!(reg_started, nothing)
                    reg_reason[] = NP.pollwait!(registration.read_waiter)
                    return nothing
                end)
                timer_task = errormonitor(@async begin
                    put!(timer_started, nothing)
                    timer_reason[] = NP.pollwait!(timer.waiter)
                    return nothing
                end)
                @test _el_wait_channel_ready(reg_started, 2.0) != :timed_out
                @test _el_wait_channel_ready(timer_started, 2.0) != :timed_out
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
        _el_log_test_progress("DONE: shutdown cancels active waiters and timers")
        _el_log_test_progress("START: expired-entry drain fires without allocating")
        @testset "expired-entry drain fires without allocating" begin
            state = NP.Poller()
            t1 = NP.TimerState()
            t2 = NP.TimerState()
            now = Int64(time_ns())
            for (timer, offset) in ((t1, Int64(-2_000_000)), (t2, Int64(-1_000_000)))
                @atomic :release timer.deadline_ns = now + offset
                seq = @atomic timer.seq += UInt64(1)
                entry = NP._timer_entry(now + offset, timer, seq)
                lock(state.lock)
                try
                    NP._time_push_locked!(state, entry)
                finally
                    unlock(state.lock)
                end
            end
            NP._drain_expired_time_entries!(state, now)
            @test isempty(state.time_heap)
            @test (@atomic :acquire t1.deadline_ns) == Int64(0)
            @test (@atomic :acquire t2.deadline_ns) == Int64(0)
            # Fired-but-unparked waiters latch NOTIFIED; check the latch
            # directly so a drain regression fails instead of parking forever.
            @test (@atomic :acquire t1.waiter.state) == NP.PollWaiterState.NOTIFIED
            @test (@atomic :acquire t2.waiter.state) == NP.PollWaiterState.NOTIFIED
            # The drain runs on the detached poller thread every cycle, and
            # allocating there has crashed under gVisor's sandbox. Coverage
            # instrumentation adds allocations, so only assert without it.
            drained = NP._drain_expired_time_entries!(state, Int64(time_ns()))
            @test drained === nothing
            if Base.JLOptions().code_coverage == 0
                allocs = @allocated NP._drain_expired_time_entries!(state, Int64(time_ns()))
                @test allocs == 0
            end
        end
        _el_log_test_progress("DONE: expired-entry drain fires without allocating")
        _el_log_test_progress("START: shutdown wakes an idle poller promptly")
        @testset "shutdown wakes an idle poller promptly" begin
            NP.shutdown!()
            state = NP.init!()
            @test @atomic state.running
            # Let the poller thread commit to its uncapped backend wait: with
            # no registrations and no timers there is no poll timeout at all,
            # so shutdown completing is exactly the backend wake working.
            sleep(0.1)
            shutdown_task = errormonitor(Threads.@spawn begin
                NP.shutdown!()
                return nothing
            end)
            @test _el_wait_task_done(shutdown_task, 10.0) != :timed_out
            if istaskdone(shutdown_task)
                wait(shutdown_task)
                @test !(@atomic state.running)
            end
        end
        _el_log_test_progress("DONE: shutdown wakes an idle poller promptly")
    end
