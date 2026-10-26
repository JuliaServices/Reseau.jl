using Test
using Reseau

# Congestion control (RFC 9002 Section 7) with CUBIC (RFC 9438): how the
# window shrinks on loss and grows back, driven directly with acknowledgments
# on a connection whose RTT is fixed.

@isdefined(_QcnHarness) || include("quic_harness.jl")

const QCC = Reseau.QUIC
const _QCC_MSS = QCC._MAX_DATAGRAM_SIZE

function _qcc_conn(rtt_ns::Int64)
    conn = QCC._client_connection(_qcn_client_config(), Int64(0))
    conn.has_rtt_sample = true
    conn.smoothed_rtt = rtt_ns
    conn.latest_rtt = rtt_ns
    conn.min_rtt = rtt_ns
    return conn
end

_qcc_packet(pn, time_sent) = QCC._SentPacket(Int64(pn), Int64(time_sent), _QCC_MSS, QCC._SentFrame[])

# A sender limited only by the congestion window: each RTT a window's worth
# of packets, all sent after the loss, is acknowledged. Returns the time
# reached.
function _qcc_drive!(conn, from::Int64, to::Int64, rtt::Int64)
    t = from
    pn = 1_000_000
    while t < to
        for _ in 1:(conn.cwnd ÷ _QCC_MSS)
            conn.bytes_in_flight = conn.cwnd
            QCC._cc_on_acked!(conn, _qcc_packet(pn, t - 1), t, true)
            pn += 1
        end
        t += rtt
    end
    return t
end

@testset "QUIC congestion control" begin
    @testset "a loss shrinks the window by CUBIC's β of 0.7" begin
        conn = _qcc_conn(Int64(10_000_000))
        conn.cwnd = 100_000
        QCC._cc_on_congestion!(conn, Int64(10), Int64(100))
        @test conn.cwnd == 70_000
        @test conn.ssthresh == 70_000
        # Another loss of a packet sent before the recovery began changes nothing.
        QCC._cc_on_congestion!(conn, Int64(50), Int64(200))
        @test conn.cwnd == 70_000
    end

    @testset "a loss below the last maximum converges fast (RFC 9438 Section 4.7)" begin
        conn = _qcc_conn(Int64(10_000_000))
        conn.cwnd = 100_000
        QCC._cc_on_congestion!(conn, Int64(10), Int64(100))
        @test conn.cubic_w_max == 100_000
        QCC._cc_on_congestion!(conn, Int64(150), Int64(200))
        # The window was still below its last maximum, so that maximum is
        # lowered to leave room for other flows.
        @test conn.cubic_w_max ≈ 70_000 * (1 + 0.7) / 2
        @test conn.cwnd == 49_000
    end

    @testset "the window grows back along a cubic curve, reaching W_max at time K" begin
        rtt = Int64(100_000_000)
        conn = _qcc_conn(rtt)
        w_max = 1000 * _QCC_MSS
        conn.cwnd = w_max
        loss = Int64(1_000_000_000)
        QCC._cc_on_congestion!(conn, loss - 1, loss)
        reduced = conn.cwnd
        @test reduced == round(Int, 0.7 * w_max)
        k = cbrt((w_max - reduced) / _QCC_MSS / 0.4)  # seconds
        @test conn.cubic_k ≈ k
        half = _qcc_drive!(conn, loss + 1, loss + round(Int64, k / 2 * 1e9), rtt)
        # Concave: by K/2 most of the way back, though still below W_max.
        @test reduced + 0.75 * (w_max - reduced) < conn.cwnd < w_max
        _qcc_drive!(conn, half, loss + round(Int64, k * 1e9), rtt)
        @test 0.97 * w_max < conn.cwnd < 1.05 * w_max
    end

    @testset "on short round trips the window grows as fast as Reno's would" begin
        rtt = Int64(10_000_000)
        conn = _qcc_conn(rtt)
        conn.cwnd = 100_000
        loss = Int64(1_000_000_000)
        QCC._cc_on_congestion!(conn, loss - 1, loss)
        k = cbrt((100_000 - conn.cwnd) / _QCC_MSS / 0.4)
        _qcc_drive!(conn, loss + 1, loss + round(Int64, k / 2 * 1e9), rtt)
        # The cubic curve alone would still be below W_max here.
        @test conn.cwnd > 100_000
    end

    @testset "the window grows only while it is in use (RFC 9002 Section 7.8)" begin
        conn = _qcc_conn(Int64(10_000_000))
        start = conn.cwnd
        @test conn.cwnd < conn.ssthresh  # slow start
        conn.bytes_in_flight = 2 * _QCC_MSS
        @test !QCC._cwnd_limited(conn)
        QCC._cc_on_acked!(conn, _qcc_packet(1, 10), Int64(20), false)
        @test conn.cwnd == start
        conn.bytes_in_flight = conn.cwnd
        @test QCC._cwnd_limited(conn)
        QCC._cc_on_acked!(conn, _qcc_packet(2, 10), Int64(20), true)
        @test conn.cwnd == start + _QCC_MSS
        @test conn.bytes_in_flight == start - _QCC_MSS
        # In congestion avoidance too.
        conn.cwnd = 100_000
        QCC._cc_on_congestion!(conn, Int64(30), Int64(40))
        avoid = conn.cwnd
        conn.bytes_in_flight = 3 * _QCC_MSS
        for pn in 3:50
            QCC._cc_on_acked!(conn, _qcc_packet(pn, 1_000_000), Int64(1_000_000_000), false)
        end
        @test conn.cwnd == avoid
    end
end
