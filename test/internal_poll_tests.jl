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

function _ip_read_byte(fd::SO.SocketFD)::UInt8
    buf = Ref{UInt8}(0)
    while true
        n = GC.@preserve buf SO.read_once!(fd, Base.unsafe_convert(Ptr{UInt8}, buf), Csize_t(1))
        n == Cssize_t(1) && return buf[]
        n == Cssize_t(0) && throw(EOFError())
        errno = SO.last_error()
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _IP_EWOULDBLOCK && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("read", Int(errno)))
    end
end

# Wait without touching the IOPoll runtime. `IP.timedwait` sleeps through
# `sleep_until_ns`, whose `init!()` retires a stopped poller generation; tests
# that deliberately stop the poller must not let their waiting primitive
# trigger that re-init (or its shutdown side effects) before they assert on
# the stopped generation's state. A regression spins forever here; the CI job
# timeout is the deadlock guard.
function _ip_spin_until(f)::Bool
    while !f()
        yield()
    end
    return true
end

# Far-future monotonic deadline: pending forever from the test's perspective,
# but far from typemax so saturating arithmetic never wraps it.
const _IP_FAR_FUTURE_NS = typemax(Int64) ÷ 2

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
                # Nothing has been written yet, so a completed read here means
                # a spurious wake already happened.
                @test !istaskdone(read_task)
                _ip_write_byte(fd1, 0x61)
                n, b = fetch(read_task)
                @test n == 1
                @test b == 0x61
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
                # An already-expired deadline enters the timeout branch without
                # waiting on the wall clock; the fires-while-blocked path is
                # covered in timing_semantics_tests.jl.
                IP.set_read_deadline!(ipfd, Int64(1))
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
        @testset "identical deadlines do not invalidate timer state" begin
            fd0, fd1 = _ip_socketpair_stream()
            ipfd = IP.FD(fd0)
            fd0 = SO.INVALID_SOCKET
            try
                IP._set_nonblocking!(ipfd.sysfd)
                IP.register!(ipfd)
                initial_rseq = @atomic :acquire ipfd.pd.rseq
                initial_wseq = @atomic :acquire ipfd.pd.wseq
                IP.set_deadline!(ipfd, Int64(0))
                @test (@atomic :acquire ipfd.pd.rseq) == initial_rseq
                @test (@atomic :acquire ipfd.pd.wseq) == initial_wseq

                future_deadline = _IP_FAR_FUTURE_NS
                IP.set_read_deadline!(ipfd, future_deadline)
                updated_rseq = @atomic :acquire ipfd.pd.rseq
                IP.set_read_deadline!(ipfd, future_deadline)
                @test (@atomic :acquire ipfd.pd.rseq) == updated_rseq
                @test (@atomic :acquire ipfd.pd.rd_ns) == future_deadline
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
                # Two distinct far-future deadlines: the first exists only so a
                # live rseq can be captured and later fired stale.
                IP.set_read_deadline!(ipfd, _IP_FAR_FUTURE_NS - Int64(1))
                stale_rseq = @atomic :acquire ipfd.pd.rseq
                IP.set_read_deadline!(ipfd, _IP_FAR_FUTURE_NS)
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
                # captured and later fired stale. A nearer deadline races the
                # test's own setup and can legitimately expire the waiter.
                IP.set_read_deadline!(ipfd, _IP_FAR_FUTURE_NS - Int64(1))
                stale_rseq = @atomic :acquire ipfd.pd.rseq
                wait_started = Channel{Nothing}(1)
                wait_task = errormonitor(Threads.@spawn begin
                    put!(wait_started, nothing)
                    IP.waitread(ipfd.pd, ipfd.is_file)
                    return :ok
                end)
                take!(wait_started)
                waiter = IP._poll_registration(ipfd.pd).read_waiter
                # Wait for the reader to park so the stale fire below has a
                # parked task to (wrongly) complete if the retry regresses.
                while !((@atomic :acquire waiter.state) isa Task) && !istaskdone(wait_task)
                    yield()
                end
                @test !istaskdone(wait_task)
                IP.set_read_deadline!(ipfd, _IP_FAR_FUTURE_NS)
                IP.deadline_fire!(ipfd.pd, IP.PollMode.READ, stale_rseq, UInt64(0))
                # `deadline_fire!` is synchronous and the stale sequence must
                # be suppressed at the source: the deadline is not poisoned
                # and the parked waiter is untouched.
                @test (@atomic :acquire ipfd.pd.rd_ns) == _IP_FAR_FUTURE_NS
                @test (@atomic :acquire waiter.state) isa Task
                @test !istaskdone(wait_task)
                _ip_write_byte(fd1, 0x64)
                @test fetch(wait_task) == :ok
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
                future_deadline = _IP_FAR_FUTURE_NS
                IP.set_deadline!(ipfd, future_deadline)
                lock(state.lock)
                try
                    entries = filter(x -> x.kind == IP.TimeEntryKind.DEADLINE && (x.pollstate::IP.PollState).token == ipfd.pd.token, state.time_heap)
                    @test length(entries) == 1
                    @test entries[1].mode == IP.PollMode.READWRITE
                finally
                    unlock(state.lock)
                end
                IP.set_deadline!(ipfd, _IP_FAR_FUTURE_NS - Int64(1))
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
                # Wait for the reader to park so the close below evicts a
                # genuinely blocked waiter.
                waiter = IP._poll_registration(ipfd.pd).read_waiter
                while !((@atomic :acquire waiter.state) isa Task) && !istaskdone(read_task)
                    yield()
                end
                @test !istaskdone(read_task)
                close(ipfd)
                err = fetch(read_task)
                @test err isa IP.NetClosingError
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
                # Wait for the reader to park so shutdown evicts a genuinely
                # blocked waiter.
                waiter = IP._poll_registration(ipfd.pd).read_waiter
                while !((@atomic :acquire waiter.state) isa Task) && !istaskdone(read_task)
                    yield()
                end
                @test !istaskdone(read_task)
                IP.shutdown!()
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
            @testset "pointer-only IOCP uses rooted bounce buffers" begin
                IP.shutdown!()
                fd0, fd1 = _ip_socketpair_stream()
                ipfd = IP.FD(fd0)
                read_task = nothing
                shutdown_task = nothing
                raw_ptr = Channel{Ptr{UInt8}}(1)
                fd0 = SO.INVALID_SOCKET
                try
                    IP._set_nonblocking!(ipfd.sysfd)
                    IP.register!(ipfd)
                    # A pointer-only operation must target an op-rooted bounce
                    # buffer rather than the caller's unowned pointer.
                    read_task = errormonitor(Threads.@spawn begin
                        buf = Vector{UInt8}(undef, 1)
                        return GC.@preserve buf begin
                            put!(raw_ptr, pointer(buf))
                            try
                                n = IP._read_ptr_some!(ipfd, pointer(buf), 1)
                                (n, buf[1])
                            catch err
                                err
                            end
                        end
                    end)
                    caller_ptr = take!(raw_ptr)
                    state = IP.POLLER[]
                    @test _ip_spin_until() do
                        lock(state.lock)
                        try
                            backend = IP._iocp_backend(state)
                            backend === nothing && return false
                            reg = get(backend.by_fd, ipfd.sysfd, nothing)
                            reg === nothing && return false
                            op_buffer = reg.read_op.buffer
                            return (@atomic :acquire reg.read_op.active) &&
                                op_buffer isa Vector{UInt8} &&
                                pointer(op_buffer::Vector{UInt8}) != caller_ptr
                        finally
                            unlock(state.lock)
                        end
                    end
                    @test !istaskdone(read_task)

                    _ip_write_byte(fd1, 0x6a)
                    @test fetch(read_task) == (1, 0x6a)

                    source = Ref{UInt8}(0x6c)
                    written = GC.@preserve source IP._write_ptr!(
                        ipfd,
                        Base.unsafe_convert(Ptr{UInt8}, source),
                        1,
                    )
                    @test written == 1
                    @test _ip_read_byte(fd1) == 0x6c

                    # Leave another raw read pending and verify normal runtime
                    # shutdown retires the rooted bounce buffer before waking
                    # the caller out of its preserve scope.
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
                    @test _ip_spin_until() do
                        lock(state.lock)
                        try
                            backend = IP._iocp_backend(state)
                            backend === nothing && return false
                            reg = get(backend.by_fd, ipfd.sysfd, nothing)
                            reg === nothing && return false
                            return (@atomic :acquire reg.read_op.active) &&
                                reg.read_op.buffer isa Vector{UInt8}
                        finally
                            unlock(state.lock)
                        end
                    end

                    shutdown_started = Channel{Nothing}(1)
                    shutdown_task = errormonitor(Threads.@spawn begin
                        put!(shutdown_started, nothing)
                        IP.shutdown!()
                    end)
                    take!(shutdown_started)
                    # Runtime-free waits: once shutdown has begun, an
                    # `IP.timedwait` here would spin up a fresh poller
                    # generation via `init!()` mid-assertion.
                    @test _ip_spin_until(() -> istaskdone(shutdown_task))
                    wait(shutdown_task)
                    @test _ip_spin_until(() -> istaskdone(read_task))
                    @test fetch(read_task) isa IP.NetClosingError
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
            @testset "CancelIoEx ERROR_NOT_FOUND preserves the queued-completion fence" begin
                IP.shutdown!()
                fd0, fd1 = _ip_socketpair_stream()
                state = IP.Poller()
                op = nothing
                packet_posted = false
                try
                    @test IP._backend_init!(state) == Int32(0)
                    backend = IP._iocp_backend(state)
                    @test backend !== nothing
                    token = UInt64(0x51)
                    @test IP._backend_open_fd!(state, fd0, IP.PollMode.READWRITE, token) == Int32(0)
                    reg = (backend::IP.IocpBackendState).by_fd[fd0]
                    op = reg.read_op
                    registration = IP.Registration(
                        fd0,
                        token,
                        IP.PollMode.READ,
                        IP.PollWaiter(),
                        IP.PollWaiter(),
                        false,
                    )
                    @test IP._submit_iocp_op!(
                        registration,
                        reg,
                        op;
                        ptr = Ptr{UInt8}(C_NULL),
                        nbytes = UInt32(1),
                        kind = IP.IocpOpKind.READ,
                    ) == Int32(Base.Libc.EINVAL)
                    @test !(@atomic :acquire op.active)
                    @atomic :release op.active = true
                    impostor = IP.Registration(
                        fd0,
                        token,
                        IP.PollMode.READ,
                        IP.PollWaiter(),
                        IP.PollWaiter(),
                        false,
                    )
                    lock(state.lock)
                    try
                        state.registrations[fd0] = registration
                        state.registrations_by_token[token] = registration
                        @atomic :release state.running = true
                        @test IP._lookup_iocp_registration(state, registration) === reg
                        @test IP._lookup_iocp_registration(state, impostor) === nothing
                    finally
                        unlock(state.lock)
                    end

                    posted = ccall(
                        (:PostQueuedCompletionStatus, "Kernel32"),
                        Int32,
                        (Ptr{Cvoid}, UInt32, UInt, Ptr{Cvoid}),
                        backend.port,
                        UInt32(0),
                        UInt(token),
                        IP._op_ptr(op),
                    )
                    posted != 0 || error(
                        "PostQueuedCompletionStatus failed: $(IP._win_get_last_error())",
                    )
                    packet_posted = posted != 0

                    # There is deliberately no matching OS request, so
                    # CancelIoEx returns ERROR_NOT_FOUND even though a packet
                    # for this OVERLAPPED is queued.
                    raw_cancel = ccall(
                        (:CancelIoEx, "Kernel32"),
                        Int32,
                        (Ptr{Cvoid}, Ptr{Cvoid}),
                        IP._socket_handle(fd0),
                        IP._op_ptr(op),
                    )
                    raw_cancel_error = raw_cancel == 0 ? IP._win_get_last_error() : UInt32(0)
                    @test raw_cancel == 0
                    @test raw_cancel_error == IP._ERROR_NOT_FOUND
                    @test IP._cancel_iocp_op!(reg, op)
                    @test (@atomic :acquire op.active)

                    @test IP._submit_iocp_op!(
                        registration,
                        reg,
                        op;
                        kind = IP.IocpOpKind.PROBE_READ,
                    ) == Int32(Base.Libc.EALREADY)

                    IP._drain_pending_ops_on_close!(backend)
                    @test !(@atomic :acquire op.active)

                    bytes_ref = Ref{UInt32}(UInt32(0))
                    key_ref = Ref{UInt}(UInt(0))
                    ov_ref = Ref{Ptr{Cvoid}}(C_NULL)
                    empty_result = GC.@preserve bytes_ref key_ref ov_ref begin
                        ccall(
                            (:GetQueuedCompletionStatus, "Kernel32"),
                            Int32,
                            (Ptr{Cvoid}, Ref{UInt32}, Ref{UInt}, Ref{Ptr{Cvoid}}, UInt32),
                            backend.port,
                            bytes_ref,
                            key_ref,
                            ov_ref,
                            UInt32(0),
                        )
                    end
                    empty_error = empty_result == 0 ? IP._win_get_last_error() : UInt32(0)
                    @test empty_result == 0
                    @test ov_ref[] == C_NULL
                    @test empty_error == IP._WAIT_TIMEOUT
                finally
                    @atomic :release state.running = false
                    if op isa IP.IocpOp && !packet_posted
                        active_op = op::IP.IocpOp
                        @atomic :release active_op.active = false
                    end
                    state.backend_state === nothing || IP._backend_close!(state)
                    _ip_close_fd(fd0)
                    _ip_close_fd(fd1)
                    IP.shutdown!()
                end
            end
            @testset "active IOCP storage cannot be finished or reused before dispatch" begin
                IP.shutdown!()
                fd0, fd1 = _ip_socketpair_stream()
                ipfd = IP.FD(fd0)
                read_task = nothing
                fd0 = SO.INVALID_SOCKET
                try
                    IP._set_nonblocking!(ipfd.sysfd)
                    IP.register!(ipfd)
                    read_task = errormonitor(Threads.@spawn begin
                        buf = Vector{UInt8}(undef, 1)
                        try
                            n = IP.read!(ipfd, buf)
                            return n, buf[1]
                        catch err
                            return err
                        end
                    end)
                    state = IP.POLLER[]
                    @test _ip_spin_until() do
                        lock(state.lock)
                        try
                            backend = IP._iocp_backend(state)
                            backend === nothing && return false
                            reg = get(backend.by_fd, ipfd.sysfd, nothing)
                            reg === nothing && return false
                            return @atomic :acquire reg.read_op.active
                        finally
                            unlock(state.lock)
                        end
                    end

                    lock(state.lock)
                    try
                        backend = IP._iocp_backend(state)::IP.IocpBackendState
                        reg = backend.by_fd[ipfd.sysfd]
                        op = reg.read_op
                        registration = state.registrations[ipfd.sysfd]
                        _ip_write_byte(fd1, 0x6b)

                        # For IOCP-associated handles, WSAGetOverlappedResult
                        # becomes terminal after GQCSEx dequeues the packet. The
                        # poller cannot publish active=false yet because this
                        # task deliberately holds state.lock.
                        observed = Ref((UInt32(0), Int32(Base.Libc.EAGAIN)))
                        while true
                            observed[] = IP._wsagetoverlappedresult_bytes(ipfd.sysfd, op)
                            observed[][2] != Int32(Base.Libc.EAGAIN) && break
                            yield()
                        end
                        @test observed[][2] == Int32(0)

                        @test IP._cancel_iocp_op!(reg, op)
                        still_active = @atomic :acquire op.active
                        @test still_active
                        if still_active
                            @test IP._iocp_finish_read!(registration) ==
                                (UInt32(0), Int32(Base.Libc.EAGAIN))
                            second = Vector{UInt8}(undef, 1)
                            rootless_errno = GC.@preserve second begin
                                IP._iocp_submit_read!(
                                    registration,
                                    pointer(second),
                                    UInt32(1),
                                )
                            end
                            @test rootless_errno == Int32(Base.Libc.EALREADY)
                            @test (@atomic :acquire op.active)
                            rooted_errno = GC.@preserve second begin
                                IP._iocp_submit_read!(
                                    registration,
                                    pointer(second),
                                    UInt32(1),
                                    second,
                                )
                            end
                            @test rooted_errno == Int32(Base.Libc.EALREADY)
                        end
                    finally
                        unlock(state.lock)
                    end

                    @test fetch(read_task) == (1, 0x6b)
                finally
                    IP._is_valid_fd(ipfd.sysfd) && close(ipfd)
                    _ip_close_fd(fd1)
                    IP.shutdown!()
                end
            end
            @testset "re-init retires a stopped IOCP generation after a raw read unwinds" begin
                IP.shutdown!()
                fd0, fd1 = _ip_socketpair_stream()
                ipfd = IP.FD(fd0)
                read_task = nothing
                fd0 = SO.INVALID_SOCKET
                try
                    IP._set_nonblocking!(ipfd.sysfd)
                    IP.register!(ipfd)
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
                    old_state = IP.POLLER[]
                    old_op = Ref{Any}(nothing)
                    @test _ip_spin_until() do
                        lock(old_state.lock)
                        try
                            backend = IP._iocp_backend(old_state)
                            backend === nothing && return false
                            reg = get(backend.by_fd, ipfd.sysfd, nothing)
                            reg === nothing && return false
                            old_op[] = reg.read_op
                            return @atomic :acquire reg.read_op.active
                        finally
                            unlock(old_state.lock)
                        end
                    end

                    lock(old_state.lock)
                    try
                        @atomic :release old_state.running = false
                    finally
                        unlock(old_state.lock)
                    end
                    wake_errno = IP._backend_wake!(old_state)
                    if wake_errno != Int32(0)
                        # Restore a serviceable poll loop before failing the
                        # test so cleanup cannot strand the native thread.
                        @atomic :release old_state.running = true
                        _ip_write_byte(fd1, 0x7e)
                        error("IOCP backend wake failed: $(wake_errno)")
                    end
                    # Positive but long past on the monotonic clock: already expired.
                    IP.set_read_deadline!(ipfd, Int64(1))

                    # `_ip_spin_until`, not `IP.timedwait`: the runtime-backed
                    # wait would call `init!()` and retire the stopped
                    # generation before the assertions below observe it.
                    @test _ip_spin_until(() -> istaskdone(read_task))
                    @test fetch(read_task) isa IP.DeadlineExceededError
                    op = old_op[]::IP.IocpOp
                    @test old_state.backend_state !== nothing
                    @test (@atomic :acquire op.active)
                    @test op.buffer isa Vector{UInt8}

                    new_state = IP.init!()
                    @test new_state !== old_state
                    @test (@atomic :acquire new_state.running)
                    @test old_state.backend_state === nothing
                    @test !(@atomic :acquire op.active)
                    @test !(@atomic :acquire ipfd.pd.pollable)
                finally
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
                # `close` must block while the control reference is held: the
                # descriptor stays valid and usable, and close only completes
                # after the release below.
                @test !istaskdone(close_task)
                @test ipfd.sysfd == sysfd
                @test SO.get_sockopt_int(sysfd, SO.SOL_SOCKET, SO.SO_KEEPALIVE) >= 0

                put!(release_control, nothing)
                @test fetch(control_task) == sysfd
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
                # Nothing has been written yet, so a completed wait here
                # means a spurious wake already happened.
                @test !istaskdone(wait_task)
                _ip_write_byte(fd1, 0x71)
                @test fetch(wait_task) == :ok
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
            # The write lock is held, so no waiter can have acquired it; a
            # completed waiter here means the lock was wrongly granted.
            @test !any(istaskdone, waiters)
            @test IP._fdlock_incref_and_close!(mu)
            _ = IP._fdlock_rwunlock!(mu, true)
            for waiter in waiters
                @test fetch(waiter) == false
            end
        end
    end
