module DeadlineHeapTests

using Test, Random, Reseau
const TCP = Reseau.TCP
const IP = Reseau.IOPoll
const FUTURE = typemax(Int64) ÷ 2

function with_connections(f, n=1)
    IP.shutdown!()
    listener = TCP.listen(TCP.loopback_addr(0))
    clients, peers = TCP.Conn[], TCP.Conn[]
    try
        for _ in 1:n
            push!(clients, TCP.connect(TCP.addr(listener)))
            push!(peers, TCP.accept(listener))
        end
        f(clients, peers, IP.POLLER[])
    finally
        foreach(close, clients)
        foreach(close, peers)
        close(listener)
        IP.shutdown!()
    end
end

entries(state, pd) = lock(state.time_lock) do
    filter(e -> e.kind == IP.TimeEntryKind.DEADLINE && e.pollstate === pd, state.time_heap)
end

# Check both directions of the index map as well as the ordinary heap order.
function valid_heap(state, descriptors)
    return lock(state.time_lock) do
        heap = state.time_heap
        for (i, entry) in enumerate(heap)
            i > 1 && IP._time_less(entry, heap[i >>> 1]) && return false
            entry.kind == IP.TimeEntryKind.DEADLINE || continue
            pd = entry.pollstate
            IP._mode_has_read(entry.mode) && pd.read_timer_index != i && return false
            IP._mode_has_write(entry.mode) && pd.write_timer_index != i && return false
        end
        for pd in descriptors
            for (index, mode, deadline) in ((pd.read_timer_index, IP.PollMode.READ, @atomic(pd.rd_ns)),
                                           (pd.write_timer_index, IP.PollMode.WRITE, @atomic(pd.wd_ns)))
                (index == 0) == (deadline <= 0) || return false
                index == 0 && continue
                1 <= index <= length(heap) || return false
                entry = heap[index]
                entry.pollstate === pd && entry.deadline_ns == deadline || return false
                (mode == IP.PollMode.READ ? IP._mode_has_read(entry.mode) : IP._mode_has_write(entry.mode)) || return false
            end
        end
        return true
    end
end

@testset "bounded descriptor deadline heap" begin
    with_connections() do clients, peers, state
        client, pd = only(clients), only(clients).fd.pfd.pd
        TCP.set_write_deadline!(client, FUTURE)
        TCP.set_read_deadline!(client, FUTURE + 1)
        owned = entries(state, pd)
        for i in 2:10_001
            TCP.set_read_deadline!(client, FUTURE + i)
        end
        current = entries(state, pd)
        @test length(current) == 2
        @test all(e -> any(x -> x === e, owned), current)
        @test valid_heap(state, [pd])
        TCP.set_deadline!(client, 0)
        @test isempty(entries(state, pd))
        @test (pd.read_timer_index, pd.write_timer_index) == (0, 0)
        @test write(client, UInt8[0x61]) == 1
        @test read(only(peers), 1) == UInt8[0x61]

        # Combined, split and single-direction transitions all use the real setter.
        for (read_ns, write_ns) in ((FUTURE, FUTURE), (FUTURE, FUTURE + 1),
                (0, FUTURE), (FUTURE, 0), (FUTURE + 2, FUTURE + 2), (0, 0))
            TCP.set_read_deadline!(client, read_ns)
            TCP.set_write_deadline!(client, write_ns)
            expected = read_ns == write_ns ? Int(read_ns > 0) : Int(read_ns > 0) + Int(write_ns > 0)
            @test length(entries(state, pd)) == expected
            @test valid_heap(state, [pd])
        end
        TCP.set_deadline!(client, FUTURE)
        close(client)
        @test isempty(entries(state, pd))
        @test (pd.read_timer_index, pd.write_timer_index) == (0, 0)
    end

    @testset "heap indices survive unrelated deadlines and timers" begin
        with_connections(32) do clients, peers, state
            descriptors = [c.fd.pfd.pd for c in clients]
            timer = IP.TimerState()
            @test IP.schedule_timer!(timer, FUTURE - 1)
            rng = MersenneTwister(0xdea1)
            for _ in 1:1000
                client = rand(rng, clients)
                read_ns, write_ns = rand(rng, (0, FUTURE, FUTURE + 1), 2)
                TCP.set_read_deadline!(client, read_ns)
                TCP.set_write_deadline!(client, write_ns)
                @test valid_heap(state, descriptors)
            end
            @test IP._poll_delay_ns(state; now_ns=FUTURE - 2) == 1
            IP._close_timer!(timer)
            for client in clients
                TCP.set_deadline!(client, 0)
            end
            # The poller drops a stale top entry once it comes due.
            IP._drain_expired_time_entries!(state, FUTURE)
            @test IP._poll_delay_ns(state; now_ns=FUTURE) == -1
            @test isempty(state.time_heap)
            foreach(c -> TCP.set_deadline!(c, FUTURE), clients)
            IP.shutdown!()
            @test isempty(state.time_heap)
            @test all(pd -> pd.read_timer_index == pd.write_timer_index == 0, descriptors)
        end
    end

    @testset "delayed publication and already-popped callbacks" begin
        with_connections() do clients, peers, state
            client, pd = only(clients), only(clients).fd.pfd.pd
            TCP.set_deadline!(client, FUTURE)
            old_rseq, old_wseq = @atomic(pd.rseq), @atomic(pd.wseq)
            TCP.set_deadline!(client, FUTURE + 1)
            current = only(entries(state, pd))
            IP.schedule_deadlines!(pd, FUTURE, FUTURE, old_rseq, old_wseq)
            @test only(entries(state, pd)) === current
            @test current.deadline_ns == FUTURE + 1

            popped = lock(state.time_lock) do
                IP._time_remove_locked!(state, pd.read_timer_index)
            end
            captured = (popped.deadline_ns, popped.mode, popped.primary_seq, popped.secondary_seq)
            @test (pd.read_timer_index, pd.write_timer_index) == (0, 0)
            TCP.set_deadline!(client, FUTURE + 2)
            @test only(entries(state, pd)) !== popped
            @test (popped.deadline_ns, popped.mode, popped.primary_seq, popped.secondary_seq) == captured
            IP._fire_time_entry!(popped)
            @test (@atomic pd.rd_ns) == (@atomic pd.wd_ns) == FUTURE + 2
            @test valid_heap(state, [pd])

            # An old combined callback may still expire an unchanged direction.
            popped = lock(state.time_lock) do
                IP._time_remove_locked!(state, pd.read_timer_index)
            end
            TCP.set_read_deadline!(client, FUTURE + 3)
            IP._fire_time_entry!(popped)
            @test (@atomic pd.rd_ns) == FUTURE + 3
            @test (@atomic pd.wd_ns) == -1
            TCP.set_deadline!(client, 0)
            @test isempty(entries(state, pd))
        end
    end

    @testset "concurrent setters retain the latest generations" begin
        with_connections() do clients, peers, state
            client, pd = only(clients), only(clients).fd.pfd.pd
            @sync for worker in 1:4
                Threads.@spawn for i in 1:1000
                    deadline = FUTURE + worker * 1000 + i
                    if isodd(worker)
                        TCP.set_read_deadline!(client, deadline)
                    else
                        TCP.set_write_deadline!(client, deadline)
                    end
                end
            end
            @test length(entries(state, pd)) == 2
            @test valid_heap(state, [pd])
            for entry in entries(state, pd)
                if IP._mode_has_read(entry.mode)
                    @test entry.primary_seq == (@atomic pd.rseq)
                end
                if IP._mode_has_write(entry.mode)
                    @test entry.secondary_seq == (@atomic pd.wseq)
                end
            end
            TCP.set_deadline!(client, 0)
            @test isempty(entries(state, pd))
        end
    end
end

@testset "closed timers behind a live earlier entry are dropped from the heap" begin
    IP.shutdown!()
    state = IP.init!()
    heap_length() = (lock(state.time_lock); try length(state.time_heap) finally unlock(state.time_lock) end)
    now_ns = Int64(time_ns())
    # The live timer stays at the top, so stale entries never reach it.
    live = IP.TimerState()
    IP.schedule_timer!(live, now_ns + 3600 * 1_000_000_000)
    try
        for _ in 1:10_000
            timer = IP.TimerState()
            IP.schedule_timer!(timer, now_ns + 7200 * 1_000_000_000)
            IP._close_timer!(timer)
        end
        @test heap_length() <= 2 * IP._TIME_HEAP_MIN_COMPACT
        lock(state.time_lock)
        try
            # Compaction kept the heap order and the live entry.
            heap = state.time_heap
            @test any(entry -> entry.timer === live, heap)
            @test all(i -> !IP._time_less(heap[i], heap[i >>> 1]), 2:length(heap))
        finally
            unlock(state.time_lock)
        end
    finally
        IP._close_timer!(live)
        IP.shutdown!()
    end
end

# The poller takes `state.lock` for every readiness event, so deadline and
# timer updates must not wait for it: a contended update stalled every socket.
@testset "deadline and timer updates do not take the poller lock" begin
    with_connections() do clients, peers, state
        client, pd = only(clients), only(clients).fd.pfd.pd
        timer = IP.TimerState()
        updater = nothing
        lock(state.lock)
        try
            # Pinned to this thread, so it runs only while this task yields. It
            # has no blocking point, so it finishes on its first run; the loop
            # only bounds how long a regression keeps it parked on the lock.
            updater = @async begin
                TCP.set_read_deadline!(client, FUTURE)
                TCP.set_read_deadline!(client, FUTURE - 1)
                IP.schedule_timer!(timer, FUTURE)
                TCP.set_read_deadline!(client, 0)
                return true
            end
            for _ in 1:1000
                istaskdone(updater) && break
                yield()
            end
            @test istaskdone(updater)
        finally
            unlock(state.lock)
        end
        @test fetch(updater)
        @test isempty(entries(state, pd))
        IP._close_timer!(timer)
    end

    # The other side: the poller leaves `time_lock` alone while nothing is due.
    state = IP.Poller()
    timer = IP.TimerState()
    seq = @atomic timer.seq += UInt64(1)
    lock(state.time_lock) do
        IP._time_push_locked!(state, IP._timer_entry(FUTURE, timer, seq))
    end
    poller = nothing
    lock(state.time_lock)
    try
        poller = @async begin
            delay = IP._poll_delay_ns(state; now_ns = FUTURE - 2)
            IP._drain_expired_time_entries!(state, FUTURE - 1)
            return delay
        end
        for _ in 1:1000
            istaskdone(poller) && break
            yield()
        end
        @test istaskdone(poller)
    finally
        unlock(state.time_lock)
    end
    @test fetch(poller) == 2
    @test length(state.time_heap) == 1
    @test (@atomic state.poll_until_ns) == FUTURE
    IP._close_timer!(timer)
end

end # module
