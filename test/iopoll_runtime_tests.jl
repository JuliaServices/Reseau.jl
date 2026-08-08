using Test
using Reseau

const NP = Reseau.IOPoll
const IP = Reseau.IOPoll
const SO = Reseau.SocketOps
const _EL_EWOULDBLOCK = @static isdefined(Base.Libc, :EWOULDBLOCK) ? Int32(getfield(Base.Libc, :EWOULDBLOCK)) : Int32(Base.Libc.EAGAIN)

function _el_socketpair_stream()
    listener = SO.INVALID_SOCKET
    client = SO.INVALID_SOCKET
    accepted = SO.INVALID_SOCKET
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
        client = SO.INVALID_SOCKET
        accepted = SO.INVALID_SOCKET
        return stream_client, stream_server
    finally
        SO.is_valid_socket(accepted) && SO.close_socket_nothrow(accepted)
        SO.is_valid_socket(client) && SO.close_socket_nothrow(client)
        SO.is_valid_socket(listener) && SO.close_socket_nothrow(listener)
    end
end

function _el_open_stream_fd()::SO.SocketFD
    return SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
end

function _el_close_fd(fd::SO.SocketFD)
    SO.is_valid_socket(fd) || return nothing
    SO.close_socket_nothrow(fd)
    return nothing
end

function _el_write_byte(fd::SO.SocketFD, b::UInt8)
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

function _el_read_byte(fd::SO.SocketFD)
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

# Deadlocks surface as a suite hang; the CI job timeout is the final guard.
function _el_wait_task_done(task::Task)
    # Status-only wait: a task that failed is still "done" here, matching the
    # polling helper this replaced; callers inspect results via fetch.
    try
        wait(task)
    catch
    end
    return nothing
end

function _el_wait_channel_ready(ch::Channel{Nothing})
    take!(ch)
    return nothing
end

# Far-future monotonic deadline: pending forever from the test's perspective,
# but far from typemax so saturating arithmetic never wraps it.
const _EL_FAR_FUTURE_NS = typemax(Int64) ÷ 2

function _el_log_test_progress(msg::AbstractString)
    println("[iopoll_runtime_tests] ", msg)
    flush(stdout)
    return nothing
end

# These backend helpers block an OS thread inside the raw poll syscall. When
# the Julia scheduler only has one worker thread, using `Threads.@spawn` around
# them would starve the companion task that is supposed to drive the wakeup.
_el_can_block_julia_worker() = Threads.nthreads() > 1

function _el_accept_with_retry(listener::SO.SocketFD)::Tuple{SO.SocketFD, SO.AcceptPeer}
    for _ in 1:5000
        accepted, peer, errno = SO.try_accept_socket(listener)
        SO.is_valid_socket(accepted) && return accepted, peer
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _EL_EWOULDBLOCK && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("accept", Int(errno)))
    end
    throw(ArgumentError("timed out waiting for accepted socket"))
end

function _el_wait_connect_ready!(fd::SO.SocketFD)
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
            @test IP._saturating_add_ns(Int64(20), Int64(22)) == Int64(42)
            @test IP._saturating_add_ns(typemax(Int64) - Int64(2), Int64(3)) == typemax(Int64)
            @test IP._saturating_add_ns(typemin(Int64) + Int64(2), Int64(-3)) == typemin(Int64)
            # Latency semantics (sleep waits at least its delay, a future
            # timedwait deadline expires) live in timing_semantics_tests.jl;
            # here cover only the deterministic branches.
            _el_log_test_progress("poller-backed sleep/timedwait: sleep zero delay")
            IP.sleep(0.0)
            _el_log_test_progress("poller-backed sleep/timedwait: timedwait expired deadline")
            @test IP.timedwait(() -> false, 0.0) == :timed_out
            _el_log_test_progress("poller-backed sleep/timedwait: timedwait ready predicate")
            wake_ch = Channel{Nothing}(1)
            put!(wake_ch, nothing)
            @test IP.timedwait(() -> isready(wake_ch), 60.0) == :ok
            take!(wake_ch)
        end
        _el_log_test_progress("DONE: poller-backed sleep/timedwait")
        _el_log_test_progress("START: pollwait wake reason precedence")
        @testset "pollwait wake reason precedence" begin
            waiter = NP.PollWaiter()
            @test !NP.pollnotify!(waiter, NP.PollWakeReason.CANCELED)
            @test (@atomic :acquire waiter.state) === NP._POLLWAKE_CANCELED
            @test !NP.pollnotify!(waiter, NP.PollWakeReason.READY)
            @test (@atomic :acquire waiter.state) === NP._POLLWAKE_READY
            @test NP.pollwait!(waiter) == NP.PollWakeReason.READY
            @test (@atomic :acquire waiter.state) === nothing

            waiter = NP.PollWaiter()
            @test !NP.pollnotify!(waiter, NP.PollWakeReason.READY)
            @test !NP.pollnotify!(waiter, NP.PollWakeReason.CANCELED)
            @test (@atomic :acquire waiter.state) === NP._POLLWAKE_READY
            @test NP.pollwait!(waiter) == NP.PollWakeReason.READY

            waiter = NP.PollWaiter()
            @test !NP.pollnotify!(waiter, NP.PollWakeReason.CANCELED)
            @test NP.pollwait!(waiter) == NP.PollWakeReason.CANCELED
            @test (@atomic :acquire waiter.state) === nothing

            waiter = NP.PollWaiter()
            owner_task = Threads.@spawn NP.pollwait!(waiter)
            while !((@atomic :acquire waiter.state) isa Task) && !istaskdone(owner_task)
                yield()
            end
            published_owner = @atomic :acquire waiter.state
            @test published_owner === owner_task
            concurrent_err = try
                NP.pollwait!(waiter)
                nothing
            catch err
                err
            end
            @test concurrent_err isa ArgumentError
            @test (@atomic :acquire waiter.state) === published_owner
            @test NP.pollnotify!(waiter, NP.PollWakeReason.READY)
            @test fetch(owner_task) == NP.PollWakeReason.READY
            @test (@atomic :acquire waiter.state) === nothing

            interrupted_waiter = NP.PollWaiter()
            interrupted_task = Threads.@spawn NP.pollwait!(interrupted_waiter)
            while !((@atomic :acquire interrupted_waiter.state) isa Task) && !istaskdone(interrupted_task)
                yield()
            end
            schedule(interrupted_task, InterruptException(); error = true)
            @test_throws TaskFailedException fetch(interrupted_task)
            @test (@atomic :acquire interrupted_waiter.state) === nothing
            @test !NP.pollnotify!(interrupted_waiter, NP.PollWakeReason.READY)
            @test NP.pollwait!(interrupted_waiter) == NP.PollWakeReason.READY

            for reason in (NP.PollWakeReason.READY, NP.PollWakeReason.CANCELED)
                for _ in 1:128
                    waiter = NP.PollWaiter()
                    @test !NP.pollnotify!(waiter, reason)
                    @test NP.pollwait!(waiter) == reason
                    @test (@atomic :acquire waiter.state) === nothing
                end
            end

            for i in 1:128
                waiter = NP.PollWaiter()
                expected = isodd(i) ? NP.PollWakeReason.READY : NP.PollWakeReason.CANCELED
                waiter_task = errormonitor(Threads.@spawn NP.pollwait!(waiter))
                while !((@atomic :acquire waiter.state) isa Task) && !istaskdone(waiter_task)
                    yield()
                end
                @test NP.pollnotify!(waiter, expected)
                @test fetch(waiter_task) == expected
                @test (@atomic :acquire waiter.state) === nothing
            end

            # Regression for the two-word protocol's lost-wakeup deadlock: a
            # parked waiter woken CANCELED while a concurrent READY upgrade
            # lands mid-consume must return a reason — never re-park with its
            # wake token already spent.
            for _ in 1:256
                waiter = NP.PollWaiter()
                waiter_task = Threads.@spawn NP.pollwait!(waiter)
                while !((@atomic :acquire waiter.state) isa Task) && !istaskdone(waiter_task)
                    yield()
                end
                cancel_task = Threads.@spawn NP.pollnotify!(waiter, NP.PollWakeReason.CANCELED)
                ready_task = Threads.@spawn NP.pollnotify!(waiter, NP.PollWakeReason.READY)
                # A lost-wakeup regression parks this fetch forever; the CI job
                # timeout is the deadlock guard.
                @test fetch(waiter_task) isa NP.PollWakeReason.T
                wait(cancel_task)
                wait(ready_task)
                # A notify that landed after the consume latches a fresh token;
                # drain it so the waiter ends the iteration clean.
                if (@atomic :acquire waiter.state) isa NP._PollWakeToken
                    NP.pollwait!(waiter)
                end
                @test (@atomic :acquire waiter.state) === nothing
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
                # Finite-timeout latency semantics live in
                # timing_semantics_tests.jl; here cover the zero-timeout path
                # and the wake path, which need no clock.
                errno = NP._backend_poll_once!(state, Int64(0))
                @test errno == Int32(0)
                if _el_can_block_julia_worker()
                    _el_log_test_progress("backend delay semantics: blocking wake")
                    wake_ch = Channel{Nothing}(1)
                    poll_task = errormonitor(Threads.@spawn begin
                        err = NP._backend_poll_once!(state, Int64(-1))
                        err == Int32(0) || throw(SystemError("backend poll", Int(err)))
                        put!(wake_ch, nothing)
                        return nothing
                    end)
                    # The backend wake is sticky: a wake posted before the
                    # poller enters the syscall still terminates the next
                    # poll, so both sides of the race pass without settling.
                    @test NP._backend_wake!(state) == Int32(0)
                    take!(wake_ch)
                    wait(poll_task)
                else
                    @test NP._backend_wake!(state) == Int32(0)
                end
            finally
                if poll_task isa Task && !istaskdone(poll_task)
                    NP._backend_wake!(state)
                    _el_wait_task_done(poll_task)
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
            fd0 = SO.INVALID_SOCKET
            fd1 = SO.INVALID_SOCKET
            try
                errno = NP._backend_init!(state)
                @test errno == Int32(0)
                @atomic :release state.running = true
                NP.POLLER[] = state
                fd0 = _el_open_stream_fd()
                fd1 = SO.INVALID_SOCKET
                token = UInt64(41)
                registration = NP.Registration(fd0, token, NP.PollMode.READWRITE, NP.PollWaiter(), NP.PollWaiter(), false)
                state.registrations[fd0] = registration
                state.registrations_by_token[token] = registration
                @atomic :release state.poll_until_ns = _EL_FAR_FUTURE_NS
                deadline_ns = _EL_FAR_FUTURE_NS - Int64(20_000_000)
                if _el_can_block_julia_worker()
                    # Poll with no timeout at all: the fetch below completing
                    # is exactly the earlier-deadline wake working. A wake that
                    # lands before the poll enters the syscall stays pending,
                    # so both sides of the race pass.
                    poll_task = errormonitor(Threads.@spawn begin
                        return NP._backend_poll_once!(state, Int64(-1))
                    end)
                    NP.schedule_deadlines!(registration.pollstate, deadline_ns, Int64(0), UInt64(1), UInt64(0))
                    @test fetch(poll_task) == Int32(0)
                else
                    NP.schedule_deadlines!(registration.pollstate, deadline_ns, Int64(0), UInt64(1), UInt64(0))
                    # With an injected clock the next-delay computation is
                    # exact: 20ms before the deadline, and zero once expired.
                    @test NP._poll_delay_ns(state; now_ns = deadline_ns - Int64(20_000_000)) == Int64(20_000_000)
                    @test NP._poll_delay_ns(state; now_ns = deadline_ns) == Int64(0)
                end
            finally
                if poll_task isa Task && !istaskdone(poll_task)
                    NP._backend_wake!(state)
                    _el_wait_task_done(poll_task)
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
                _el_wait_channel_ready(wait_started)
                # Nothing has been written yet, so a completed wait here means
                # a spurious wake already happened.
                @test !isready(wait_ch)
                _el_log_test_progress("runtime register/pollwait/deregister: trigger read ready")
                _el_write_byte(fd1, 0x33)
                take!(wait_ch)
                wait(waiter_task)
                @test _el_read_byte(fd0) == 0x33
                NP.deregister!(fd0)
            finally
                if waiter_task !== nothing && !istaskdone(waiter_task)
                    try
                        NP.deregister!(fd0)
                    catch
                    end
                    _el_wait_task_done(waiter_task)
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
                fd0 = SO.INVALID_SOCKET
                fd1 = SO.INVALID_SOCKET
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
                _el_wait_channel_ready(wait_started)
                # Wait for the waiter to park so the stale dispatch below has a
                # parked task to (wrongly) wake if suppression regresses.
                while !((@atomic :acquire registration2.read_waiter.state) isa Task) && !istaskdone(waiter_task)
                    yield()
                end
                stale = NP.PollEvent(NP.INVALID_FD, token1, NP.PollMode.READ, false)
                NP._dispatch_ready_event!(state, stale)
                # Dispatch is synchronous: a suppression regression would have
                # replaced the parked task with a wake token already.
                @test (@atomic :acquire registration2.read_waiter.state) isa Task
                @test !isready(wait_ch)
                _el_write_byte(fd1, 0x44)
                take!(wait_ch)
                wait(waiter_task)
                @test _el_read_byte(fd0) == 0x44
                NP.deregister!(fd0)
            finally
                if waiter_task !== nothing && !istaskdone(waiter_task)
                    try
                        NP.deregister!(fd0)
                    catch
                    end
                    _el_wait_task_done(waiter_task)
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
                _el_wait_channel_ready(wait_started)
                _el_write_byte(fd1, 0x55)
                take!(wait_ch)
                wait(waiter_task)
                @test _el_read_byte(fd0) == 0x55
                NP.deregister!(fd0)
            finally
                if waiter_task !== nothing && !istaskdone(waiter_task)
                    try
                        NP.deregister!(fd0)
                    catch
                    end
                    _el_wait_task_done(waiter_task)
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
                _el_wait_task_done(dereg_task)
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
            @test NP.schedule_timer!(timer, _EL_FAR_FUTURE_NS)
            timer_task = errormonitor(@async NP.waittimer(timer))
            try
                NP.shutdown!()
                _el_wait_task_done(timer_task)
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
                @test NP.schedule_timer!(timer, _EL_FAR_FUTURE_NS)
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
                _el_wait_channel_ready(reg_started)
                _el_wait_channel_ready(timer_started)
                NP._notify_all_waiters!(state)
                _el_wait_task_done(reg_task)
                _el_wait_task_done(timer_task)
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
            # The drain compares entry deadlines against a caller-supplied
            # cutoff, so a fixed clock keeps this fully deterministic.
            now = Int64(1_000_000_000)
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
            # Fired-but-unparked waiters latch a READY wake; check the latch
            # directly so a drain regression fails instead of parking forever.
            @test (@atomic :acquire t1.waiter.state) === NP._POLLWAKE_READY
            @test (@atomic :acquire t2.waiter.state) === NP._POLLWAKE_READY
            # The drain runs on the detached poller thread every cycle, and
            # allocating there has crashed under gVisor's sandbox. Coverage
            # instrumentation adds allocations, so only assert without it.
            drained = NP._drain_expired_time_entries!(state, now)
            @test drained === nothing
            if Base.JLOptions().code_coverage == 0
                allocs = @allocated NP._drain_expired_time_entries!(state, now)
                @test allocs == 0
            end
        end
        _el_log_test_progress("DONE: expired-entry drain fires without allocating")
        _el_log_test_progress("START: shutdown wakes an idle poller promptly")
        @testset "shutdown wakes an idle poller promptly" begin
            NP.shutdown!()
            state = NP.init!()
            @test @atomic state.running
            # With no registrations and no timers the poller's backend wait is
            # uncapped, so shutdown completing is exactly the backend wake
            # working. The wake is sticky: posted before the poller commits to
            # the syscall, it still terminates the next wait, so no settling
            # delay is needed for either side of the race.
            shutdown_task = errormonitor(Threads.@spawn begin
                NP.shutdown!()
                return nothing
            end)
            _el_wait_task_done(shutdown_task)
            if istaskdone(shutdown_task)
                wait(shutdown_task)
                @test !(@atomic state.running)
            end
        end
        _el_log_test_progress("DONE: shutdown wakes an idle poller promptly")
    end
