using Test
using Reseau

# Datagram packetization layer path MTU discovery (RFC 9000 Section 14.3,
# RFC 8899): after the handshake, probes find the largest datagram the path
# carries, up to the local ceiling and the peer's max_udp_payload_size.

@isdefined(_QcnHarness) || include("quic_harness.jl")

const QPM = Reseau.QUIC

# Sends `nbytes` from client to server on a new stream; returns whether all of
# it arrived.
function _qpm_transfer!(h, nbytes)
    id = QPM._open_stream!(h.client)
    QPM._stream_write!(h.client, id, zeros(UInt8, nbytes); fin = true)
    got = Ref(0)
    sid = Ref{Union{Nothing, UInt64}}(nothing)
    finished = Ref(false)
    _qcn_run!(h; app = h -> begin
        sid[] === nothing && (sid[] = QPM._accept_stream!(h.server))
        if sid[] !== nothing
            r = QPM._stream_read!(h.server, sid[]::UInt64)
            got[] += length(r.data)
            r.fin && (finished[] = true)
        end
    end, done = h -> finished[])
    return finished[] && got[] == nbytes
end

# Lets discovery finish, on probe timers alone if the transfer did not last long enough.
_qpm_settle!(h) = @test _qcn_run!(h; done = h -> h.client.pmtu_done, max_time = h.now + 600_000_000_000)

function _qpm_handshake(; kwargs...)
    h = _QcnHarness(; kwargs...)
    @test _qcn_run!(h)
    return h
end

# The largest datagram the client sent after time `since`, probes aside.
function _qpm_largest_data(h, since)
    sizes = [length(s.bytes) for s in h.log if s.from_client && s.time >= since && length(s.bytes) <= h.client.max_datagram_size]
    return maximum(sizes)
end

@testset "QUIC path MTU discovery" begin
    @testset "datagrams grow to the local ceiling when the path carries them" begin
        h = _qpm_handshake()
        @test h.client.max_datagram_size == QPM._MAX_DATAGRAM_SIZE
        start = h.now
        @test _qpm_transfer!(h, 300_000)
        @test h.client.max_datagram_size == QPM._PMTU_DEFAULT_CEILING
        @test _qpm_largest_data(h, start) == QPM._PMTU_DEFAULT_CEILING
        @test h.client.packets_lost == 0
    end

    @testset "discovery stops at what the path carries, and lost probes are not congestion" begin
        h = _qpm_handshake(path_mtu = 1350)
        @test _qpm_transfer!(h, 300_000)
        _qpm_settle!(h)
        @test 1350 - QPM._PMTU_PRECISION <= h.client.max_datagram_size <= 1350
        # Probes lost to the path neither count as losses nor shrink the window.
        @test h.client.packets_lost == 0
        @test h.client.ssthresh == typemax(Int)
    end

    @testset "the peer's max_udp_payload_size caps datagrams" begin
        h = _qpm_handshake(server_max_udp_payload = 1300)
        @test _qpm_transfer!(h, 300_000)
        _qpm_settle!(h)
        @test h.client.max_datagram_size == 1300
    end

    @testset "a path that stops carrying large datagrams falls back to the minimum" begin
        h = _qpm_handshake()
        @test _qpm_transfer!(h, 200_000)
        @test h.client.max_datagram_size > QPM._MAX_DATAGRAM_SIZE
        h.path_mtu = QPM._MAX_DATAGRAM_SIZE
        @test _qpm_transfer!(h, 200_000)
        @test h.client.max_datagram_size == QPM._MAX_DATAGRAM_SIZE
    end

    @testset "a ceiling at the minimum means no probes" begin
        h = _QcnHarness()
        h.client.pmtu_ceiling = QPM._MAX_DATAGRAM_SIZE
        @test _qcn_run!(h)
        start = h.now
        @test _qpm_transfer!(h, 100_000)
        @test all(s -> length(s.bytes) <= QPM._MAX_DATAGRAM_SIZE, filter(s -> s.from_client && s.time >= start, h.log))
    end
end
