using Test
using Reseau

# The one test file allowed to read the wall clock (see test/README.md).
#
# Reseau owns the timer heap and poller deadline machinery, so a small set of
# tests must let a real future deadline expire to prove timers actually fire.
# Every elapsed-time assertion here is a LOWER bound: a preempted or paused
# runner only ever makes the measured elapsed time larger, so none of these
# can fail because CI is slow. Upper-bound latency assertions are forbidden
# everywhere, including here.

const _TS_IP = Reseau.IOPoll
const _TS_NP = Reseau.IOPoll

@testset "IOPoll.sleep waits at least the requested delay" begin
    t0 = time_ns()
    _TS_IP.sleep(0.03)
    @test time_ns() - t0 >= 15_000_000
end

@testset "IOPoll.timedwait expires a future deadline" begin
    t0 = time_ns()
    @test _TS_IP.timedwait(() -> false, 0.03) == :timed_out
    @test time_ns() - t0 >= 15_000_000
end

@testset "IOPoll.timedwait observes a predicate flipped mid-wait" begin
    wake_ch = Channel{Nothing}(1)
    wake_task = errormonitor(@async begin
        _TS_IP.sleep(0.03)
        put!(wake_ch, nothing)
        return nothing
    end)
    @test _TS_IP.timedwait(() -> isready(wake_ch), 60.0) == :ok
    take!(wake_ch)
    wait(wake_task)
end

@testset "read deadline fires while a reader is blocked" begin
    # A near-future deadline set before the read: whether the read blocks
    # first (timer fires and wakes it) or a runner pause expires the deadline
    # before entry (fast path), the observable result is the same error, so
    # this cannot false-fail on a slow runner.
    _TS_NC = Reseau.TCP
    listener = nothing
    client = nothing
    server = nothing
    try
        listener = _TS_NC.listen(_TS_NC.loopback_addr(0); backlog = 1)
        laddr = _TS_NC.addr(listener)::_TS_NC.SocketAddrV4
        accept_task = errormonitor(@async _TS_NC.accept(listener))
        client = _TS_NC.connect(_TS_NC.loopback_addr(Int(laddr.port)))
        server = fetch(accept_task)
        _TS_NC.set_read_deadline!(server, Int64(time_ns()) + Int64(30_000_000))
        @test_throws _TS_IP.DeadlineExceededError read!(server, Vector{UInt8}(undef, 1))
    finally
        for x in (client, server, listener)
            x === nothing && continue
            try
                close(x)
            catch
            end
        end
    end
end

@testset "backend finite poll timeout waits at least the delay" begin
    state = _TS_NP.Poller()
    errno = _TS_NP._backend_init!(state)
    @test errno == Int32(0)
    try
        # Warm up so the timed call below measures the poll, not JIT.
        _TS_NP._backend_poll_once!(state, Int64(0))
        t0 = time_ns()
        errno = _TS_NP._backend_poll_once!(state, Int64(30_000_000))
        elapsed_ns = time_ns() - t0
        @test errno == Int32(0)
        @test elapsed_ns >= 15_000_000
    finally
        _TS_NP._backend_close!(state)
    end
end
