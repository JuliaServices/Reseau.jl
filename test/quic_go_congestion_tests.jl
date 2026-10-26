using Test
using Reseau

# Ported from quic-go v0.48.2 (github.com/quic-go/quic-go@v0.48.2):
#   internal/congestion/cubic_test.go         (itself ported from Chromium)
#   internal/congestion/cubic_sender_test.go  (itself ported from Chromium)
#   internal/utils/rtt_stats_test.go
# and, all not applicable here (see below), internal/congestion/
# hybrid_slow_start_test.go, pacer_test.go and bandwidth_test.go.
#
# Each Go `It` (or `func Test...`) is a @testset named after it. Units are
# translated to ours (bytes, nanoseconds) and quic-go's maxDatagramSize (1280)
# to ours, `_MAX_DATAGRAM_SIZE` (1200). Where we deliberately behave
# differently from Go, a `# Differs from quic-go:` note says why, and what we
# do instead is tested.
#
# How the Go APIs map onto ours:
#   - Cubic.CongestionWindowAfterAck(acked, cwnd, minRTT, t): set `conn.cwnd`
#     and the RTT, call `_cubic_on_acked!(conn, acked, t)`, read `conn.cwnd`.
#     Ours uses the smoothed RTT where Chromium uses min RTT; both are set to
#     the test's RTT.
#   - Cubic.CongestionWindowAfterPacketLoss(cwnd): set `conn.cwnd`, call
#     `_cc_on_congestion!` with a packet sent after the last recovery began.
#   - Cubic.lastMaxCongestionWindow: `conn.cubic_w_max`.
#   - cubic_test.go emulates 2 connections (Cubic.SetNumConnections(2)); ours
#     is always one, so β, the extra "last max" backoff and the Reno-friendly α
#     are those for N = 1 (0.7, 0.85, 3(1-β)/(1+β)), which are RFC 9438's.
#     The one magic number (in "works below origin") was produced by running
#     Chromium's algorithm; `_QgcGoCubic` re-implements that algorithm so the
#     number can be recomputed for N = 1 and our datagram size, and is checked
#     to reproduce Go's number for N = 2 and 1280 bytes.
#   - cubicSender: a `_QgcSender` drives a connection's congestion controller
#     directly. CanSend(bytesInFlight) is `_cwnd_allows(conn)`;
#     OnPacketAcked/OnCongestionEvent are `_cc_on_acked!`/`_cc_on_congestion!`;
#     AckNPackets judges `_cwnd_limited` once beforehand, as Go passes the same
#     priorInFlight for every packet of the ACK. Go tells a packet sent after a
#     reduction by its packet number; ours by its send time, so the simulated
#     clock moves 1 ns per packet sent.
#   - RTTStats.UpdateRTT(sample, ackDelay, _): `_update_rtt!(conn, sample, ackDelay)`;
#     PTO(false)/PTO(true): `_pto_duration` for the Handshake and application
#     spaces (only the latter adds the peer's max_ack_delay).
#
# Not applicable (deliberately absent from Reseau.QUIC):
#   hybrid_slow_start_test.go  "works in a simple case", "works with delay"
#                              (no hybrid slow start)
#   pacer_test.go              all 13 Its (no pacing)
#   bandwidth_test.go          "converts from time delta" (Go API, used for pacing)
#   cubic_sender_test.go
#     "paces"                                  (pacing)
#     "slow start packet loss PRR"             (PRR)
#     "slow start burst packet loss PRR"       (PRR)
#     "RTO congestion window",
#     "RTO congestion window no retransmission" (OnRetransmissionTimeout is a TCP
#         RTO hook with no callers in quic-go v0.48.2; RFC 9002 has no RTO and
#         Sections 6.2 and 7 keep PTO from touching the window)
#     "doesn't allow reductions of the maximum packet size" (Go API: a panic;
#         our PMTUD lowers it on purpose after a black hole, RFC 8899 Section 4.3)
#     Parts of other Its are skipped and marked inline: Reno-mode congestion
#     avoidance (one MSS per window of ACKs), hybrid slow start state,
#     TimeUntilSend/BandwidthEstimate (pacing), and OnConnectionMigration (no
#     connection migration; we send disable_active_migration).
#   rtt_stats_test.go
#     TestRTTStatsMaxAckDelay (Go API: a setter/getter; max_ack_delay's use is
#         covered by TestRTTStatsComputePTO)
#     TestRTTStatsRestore, TestRTTMeasurementAfterRestore (SetInitialRTT: no
#         RTT restored from a previous connection here)

@isdefined(_QcnHarness) || include("quic_harness.jl")

const QGC = Reseau.QUIC
const _QGC_MSS = QGC._MAX_DATAGRAM_SIZE
const _QGC_MS = Int64(1_000_000)
const _QGC_US = Int64(1_000)

function _qgc_conn()
    return QGC._client_connection(_qcn_client_config(), Int64(0))
end

function _qgc_set_rtt!(conn, rtt::Int64)
    conn.has_rtt_sample = true
    conn.smoothed_rtt = rtt
    conn.latest_rtt = rtt
    conn.min_rtt = rtt
    return nothing
end

# Chromium's CUBIC (quic-go internal/congestion/cubic.go), integer and float32
# arithmetic included, for N emulated connections and a datagram size.
mutable struct _QgcGoCubic
    n::Int
    mss::Int
    epoch::Int64
    last_max::Int
    acked::Int
    est::Int
    origin::Int
    time_to_origin::UInt32
end
_QgcGoCubic(n, mss) = _QgcGoCubic(n, mss, typemin(Int64), 0, 0, 0, 0, UInt32(0))
_qgc_go_beta(c) = (Float32(c.n) - 1 + Float32(0.7)) / Float32(c.n)
_qgc_go_beta_last_max(c) = (Float32(c.n) - 1 + Float32(0.85)) / Float32(c.n)
function _qgc_go_alpha(c)
    b = _qgc_go_beta(c)
    return 3 * Float32(c.n) * Float32(c.n) * (1 - b) / (1 + b)
end
function _qgc_go_after_loss!(c::_QgcGoCubic, cwnd::Int)
    if cwnd + c.mss < c.last_max
        c.last_max = trunc(Int, _qgc_go_beta_last_max(c) * Float32(cwnd))
    else
        c.last_max = cwnd
    end
    c.epoch = typemin(Int64)
    return trunc(Int, Float32(cwnd) * _qgc_go_beta(c))
end
function _qgc_go_after_ack!(c::_QgcGoCubic, acked::Int, cwnd::Int, delay_min::Int64, t::Int64)
    c.acked += acked
    if c.epoch == typemin(Int64)
        c.epoch = t
        c.acked = acked
        c.est = cwnd
        if c.last_max <= cwnd
            c.time_to_origin = UInt32(0)
            c.origin = cwnd
        else
            cube_factor = (Int64(1) << 40) ÷ 410 ÷ c.mss
            c.time_to_origin = UInt32(trunc(cbrt(Float64(cube_factor * (c.last_max - cwnd)))))
            c.origin = c.last_max
        end
    end
    elapsed = (((t + delay_min - c.epoch) ÷ 1000) << 10) ÷ 1_000_000
    offset = abs(Int64(c.time_to_origin) - elapsed)
    delta = (410 * offset * offset * offset * c.mss) >> 40
    target = elapsed > Int64(c.time_to_origin) ? c.origin + delta : c.origin - delta
    target = min(target, cwnd + c.acked ÷ 2)
    c.est += trunc(Int, Float32(c.acked) * _qgc_go_alpha(c) * Float32(c.mss) / Float32(c.est))
    c.acked = 0
    return max(target, c.est)
end

# cubic_test.go's parameters: emulated connections, datagram size, β, the
# extra backoff for a loss before the last maximum was regained, and the
# Reno-friendly α. `ours` says whether the suite runs on our controller,
# where Go's expectations that we deliberately miss are replaced by checks of
# what we do; otherwise it runs on `_QgcGoCubic` with Go's own parameters,
# which checks the port itself.
struct _QgcCubicParams
    n::Int
    mss::Int
    beta::Float32
    beta_last_max::Float32
    alpha::Float32
    ours::Bool
end

function _QgcCubicParams(n::Int, mss::Int, ours::Bool)
    beta = (Float32(n) - 1 + Float32(0.7)) / Float32(n)
    beta_last_max = (Float32(n) - 1 + Float32(0.85)) / Float32(n)
    alpha = 3 * Float32(n) * Float32(n) * (1 - beta) / (1 + beta)
    return _QgcCubicParams(n, mss, beta, beta_last_max, alpha, ours)
end

const _QGC_MAX_CUBIC_TIME_INTERVAL = 30 * _QGC_MS

_qgc_reno_cwnd(p::_QgcCubicParams, cwnd::Int) =
    cwnd + trunc(Int, Float32(p.mss) * p.alpha * Float32(p.mss) / Float32(cwnd))

function _qgc_cubic_convex_cwnd(p::_QgcCubicParams, initial::Int, rtt::Int64, elapsed::Int64)
    offset = (((elapsed + rtt) ÷ _QGC_US) << 10) ÷ 1_000_000
    return initial + ((410 * offset * offset * offset * p.mss) >> 40)
end

# Our congestion controller standing in for quic-go's Cubic.
mutable struct _QgcCubic
    conn::QGC._Connection
end

_qgc_new_cubic(p::_QgcCubicParams) = p.ours ? _QgcCubic(_qgc_conn()) : _QgcGoCubic(p.n, p.mss)

function _qgc_ack!(c::_QgcCubic, acked::Int, cwnd::Int, rtt::Int64, t::Int64)
    conn = c.conn
    conn.cwnd = cwnd
    _qgc_set_rtt!(conn, rtt)
    QGC._cubic_on_acked!(conn, acked, t)
    return conn.cwnd
end
_qgc_ack!(c::_QgcGoCubic, acked::Int, cwnd::Int, rtt::Int64, t::Int64) = _qgc_go_after_ack!(c, acked, cwnd, rtt, t)

function _qgc_loss!(c::_QgcCubic, cwnd::Int, now::Int64)
    conn = c.conn
    conn.cwnd = cwnd
    # A packet sent after the last recovery began, so that this is a new loss event.
    t = max(now, conn.recovery_start + 1)
    QGC._cc_on_congestion!(conn, t, t)
    return conn.cwnd
end
_qgc_loss!(c::_QgcGoCubic, cwnd::Int, now::Int64) = _qgc_go_after_loss!(c, cwnd)

_qgc_last_max(c::_QgcCubic) = c.conn.cubic_w_max
_qgc_last_max(c::_QgcGoCubic) = c.last_max

function _qgc_cubic_suite(p::_QgcCubicParams)
    mss = p.mss
    @testset "works above origin (with tighter bounds)" begin
        cubic = _qgc_new_cubic(p)
        # Convex growth.
        rtt_min = 100 * _QGC_MS
        rtt_min_s = Float32(0.1)
        current = 10 * mss
        initial = current

        now = _QGC_MS
        initial_time = now
        expected_first = _qgc_reno_cwnd(p, current)
        current = _qgc_ack!(cubic, mss, current, rtt_min, initial_time)
        @test current == expected_first

        # Normal TCP phase. The maximum number of expected Reno RTTs is
        # where the cubic and Reno curves meet.
        max_reno_rtts = trunc(Int, sqrt(Float64(p.alpha / (Float32(0.4) * rtt_min_s * rtt_min_s * rtt_min_s))) - 2)
        reno_mismatches = 0
        reno_max_miss = 0
        epoch_changes = Int[]
        for _ in 1:max_reno_rtts
            # The window grows by about one MSS every current_cwnd/Alpha acks.
            num_acks = trunc(Int, Float32(current ÷ mss) / p.alpha)
            initial_this_epoch = current
            for _ in 1:num_acks
                expected_next = _qgc_reno_cwnd(p, current)
                current = _qgc_ack!(cubic, mss, current, rtt_min, now)
                reno_mismatches += current != expected_next
                reno_max_miss = max(reno_max_miss, abs(current - expected_next))
            end
            # Byte-wise Reno is an estimate: within half a packet of one MSS.
            push!(epoch_changes, current - initial_this_epoch)
            now += 100 * _QGC_MS
        end
        if p.ours
            # Differs from quic-go: Chromium truncates every Reno-friendly
            # increment (and divides by W_est rather than cwnd); ours keeps
            # W_est as a float and carries sub-byte growth to the next ACK
            # (RFC 9438 Section 4.3), so it is never more than a couple of
            # bytes off.
            @test reno_max_miss <= 2
        else
            @test reno_mismatches == 0
        end
        @test all(d -> abs(d - mss) <= mss ÷ 2, epoch_changes)

        convex_mismatches = 0
        for _ in 1:54
            max_acks = current ÷ mss
            interval = (100 * 1000 ÷ max_acks) * _QGC_US
            for _ in 1:max_acks
                now += interval
                current = _qgc_ack!(cubic, mss, current, rtt_min, now)
                expected = _qgc_cubic_convex_cwnd(p, initial, rtt_min, now - initial_time)
                # If we allow per-ack updates, every update is a small cubic update.
                convex_mismatches += current != expected
            end
        end
        expected = _qgc_cubic_convex_cwnd(p, initial, rtt_min, now - initial_time)
        current = _qgc_ack!(cubic, mss, current, rtt_min, now)
        if p.ours
            # Differs from quic-go: Chromium sets cwnd to W_cubic(t + min_rtt)
            # on every ACK; ours moves (target - cwnd)/cwnd per ACK (RFC 9438
            # Section 4.4), so it trails the curve and ends about 3% below
            # it. (With N = 1, Chromium's own algorithm also leaves this
            # closed form on 436 ACKs.)
            @test 0.95 * expected < current < expected
        else
            @test convex_mismatches == 0
            @test current == expected
        end
    end

    @testset "works above the origin with fine grained cubing" begin
        cubic = _qgc_new_cubic(p)
        # An artificially large cwnd keeps Reno from overtaking cubic.
        current = 1000 * mss
        initial = current
        rtt_min = 100 * _QGC_MS
        now = _QGC_MS
        initial_time = now

        current = _qgc_ack!(cubic, mss, current, rtt_min, now)
        now += 600 * _QGC_MS
        current = _qgc_ack!(cubic, mss, current, rtt_min, now)

        # Only non-zero, fine-grained cubic increases on every ack.
        not_expected = 0
        not_increasing = 0
        decreasing = 0
        too_large = 0
        start = current
        for _ in 1:100
            now += 10 * _QGC_MS
            expected = _qgc_cubic_convex_cwnd(p, initial, rtt_min, now - initial_time)
            next = _qgc_ack!(cubic, mss, current, rtt_min, now)
            # Cubic increases...
            not_expected += next != expected
            # ...that are non-zero and less than a tenth of a packet.
            not_increasing += !(next > current)
            decreasing += next < current
            too_large += !(mss ÷ 10 > next - current)
            current = next
        end
        if p.ours
            # Differs from quic-go: one ACK per 10 ms on a 1000-packet window.
            # Chromium jumps to the curve; ours adds (target - cwnd)/cwnd per
            # ACK (RFC 9438 Section 4.4), under a byte on some of these ACKs,
            # carried over to the next, so the window never shrinks and still
            # grows over the run.
            @test decreasing == 0
            @test current > start
        else
            @test not_expected == 0
            @test not_increasing == 0
        end
        @test too_large == 0
    end

    @testset "handles per ack updates" begin
        cubic = _qgc_new_cubic(p)
        # A large cwnd and RTT force the first increase to be a cubic increase.
        initial_packets = 150
        current = initial_packets * mss
        rtt_min = 350 * _QGC_MS

        # Initialize the epoch, tracking the Reno-equivalent window.
        now = _QGC_MS
        r_cwnd = _qgc_reno_cwnd(p, current)
        current = _qgc_ack!(cubic, mss, current, rtt_min, now)
        initial = current

        # The return of cwnd packets in less than MaxCubicInterval().
        max_acks = trunc(Int, Float32(initial_packets) / p.alpha)
        interval = _QGC_MAX_CUBIC_TIME_INTERVAL ÷ (max_acks + 1)

        # The first increase is dictated by the cubic equation, but it is
        # less than one byte, so the cwnd doesn't change.
        now += interval
        r_cwnd = _qgc_reno_cwnd(p, r_cwnd)
        next = _qgc_ack!(cubic, mss, current, rtt_min, now)
        if p.ours
            # Differs from quic-go: Chromium's first ACK left cwnd on the cubic
            # curve shifted by min_rtt, so this one adds under a byte; ours
            # left it on the Reno-friendly estimate (RFC 9438 Section 4.3),
            # which this ACK grows again, by a few bytes.
            @test 0 < next - current < mss ÷ 100
        else
            @test next == current
        end
        not_increasing = 0
        not_reno = 0
        reno_max_miss = 0
        for _ in 1:(max_acks - 1)
            now += interval
            next = _qgc_ack!(cubic, mss, current, rtt_min, now)
            r_cwnd = _qgc_reno_cwnd(p, r_cwnd)
            # The window should increase on every ack...
            not_increasing += !(next > current)
            # ...exactly as the Reno estimate does.
            not_reno += next != r_cwnd
            reno_max_miss = max(reno_max_miss, abs(next - r_cwnd))
            current = next
        end
        @test not_increasing == 0
        if p.ours
            # Differs from quic-go: the Reno estimate is not byte-exact (see
            # "works above origin"): ours stays within one Reno increment,
            # under a tenth of a datagram, of Chromium's. With N = 1
            # Chromium's own algorithm also misses it on 2 ACKs.
            @test reno_max_miss < mss ÷ 10
        else
            @test not_reno == 0
        end

        # After a window of acks, the cwnd has grown by nearly one packet.
        minimum_expected_increase = mss * 9 ÷ 10
        @test current > initial + minimum_expected_increase
    end

    @testset "handles loss events" begin
        cubic = _qgc_new_cubic(p)
        rtt_min = 100 * _QGC_MS
        current = 422 * mss
        expected = _qgc_reno_cwnd(p, current)
        # Initialize the state.
        now = _QGC_MS
        @test _qgc_ack!(cubic, mss, current, rtt_min, now) == expected

        # On the first loss, the last max congestion window is set to the
        # congestion window before the loss.
        pre_loss = current
        if p.ours
            # Differs from quic-go: Go's last max stays 0 until a loss; ours
            # keeps the curve's origin in W_max, so it is already the window
            # from the start of the epoch (RFC 9438 Section 4.2 sets W_max to
            # cwnd when there was no loss). The next checks show the first
            # loss still records the window before it.
            @test _qgc_last_max(cubic) == pre_loss
        else
            @test _qgc_last_max(cubic) == 0
        end
        expected = trunc(Int, Float32(current) * p.beta)
        @test _qgc_loss!(cubic, current, now) == expected
        @test _qgc_last_max(cubic) == pre_loss
        current = expected

        # On the second loss the window has not yet regained the last max,
        # which is reduced by an additional backoff factor to allow for
        # competition.
        pre_loss = current
        expected = trunc(Int, Float32(current) * p.beta)
        @test _qgc_loss!(cubic, current, now) == expected
        current = expected
        @test pre_loss > _qgc_last_max(cubic)
        expected_last_max = trunc(Int, Float32(pre_loss) * p.beta_last_max)
        @test _qgc_last_max(cubic) == expected_last_max
        @test expected < _qgc_last_max(cubic)
        # An increase stays below the origin.
        current = _qgc_ack!(cubic, mss, current, rtt_min, now)
        @test _qgc_last_max(cubic) > current

        # On the final loss the window had nearly regained the last max.
        current = trunc(Int, _qgc_last_max(cubic)) - 1
        pre_loss = current
        expected = trunc(Int, Float32(current) * p.beta)
        reduced = _qgc_loss!(cubic, current, now)
        if p.ours
            # Differs from quic-go: Chromium truncates β·cwnd (210914); ours
            # rounds it (210915). RFC 9438 Section 4.6 leaves this open.
            @test reduced == round(Int, current * 0.7)
            # Differs from quic-go: Chromium applies the extra backoff only
            # when cwnd + MSS < W_max, so W_max stays the window before the
            # loss; ours whenever cwnd < W_max, as RFC 9438 Section 4.7 says,
            # so a window one byte short of W_max lowers W_max to
            # cwnd·(1 + β)/2.
            @test _qgc_last_max(cubic) ≈ pre_loss * (1 + 0.7) / 2
        else
            @test reduced == expected
            @test _qgc_last_max(cubic) == pre_loss
        end
    end

    @testset "works below origin" begin
        cubic = _qgc_new_cubic(p)
        # Concave growth.
        rtt_min = 100 * _QGC_MS
        current = 422 * mss
        expected = _qgc_reno_cwnd(p, current)
        # Initialize the state.
        now = _QGC_MS
        @test _qgc_ack!(cubic, mss, current, rtt_min, now) == expected

        expected = trunc(Int, Float32(current) * p.beta)
        @test _qgc_loss!(cubic, current, now) == expected
        current = expected
        after_loss = current
        # First update after loss to initialize the epoch.
        current = _qgc_ack!(cubic, mss, current, rtt_min, now)
        # Cubic phase.
        for _ in 1:40
            now += 100 * _QGC_MS
            current = _qgc_ack!(cubic, mss, current, rtt_min, now)
        end
        expected = if p.n == 2 && p.mss == 1280
            553632 * mss ÷ 1460
        else
            # Go's number, recomputed for these parameters.
            go = _QgcGoCubic(p.n, mss)
            t = _QGC_MS
            w = 422 * mss
            _qgc_go_after_ack!(go, mss, w, rtt_min, t)
            w = _qgc_go_after_loss!(go, w)
            w = _qgc_go_after_ack!(go, mss, w, rtt_min, t)
            for _ in 1:40
                t += 100 * _QGC_MS
                w = _qgc_go_after_ack!(go, mss, w, rtt_min, t)
            end
            w
        end
        if p.ours
            # Differs from quic-go: one ACK per RTT. Chromium grows by its
            # cap of half the acked bytes per ACK toward the curve; ours by
            # (target - cwnd)/cwnd per ACK (RFC 9438 Section 4.4): 11951
            # bytes over the 41 ACKs against Chromium's 24600.
            @test after_loss < current < expected
        else
            @test current == expected
        end
    end
    return nothing
end

# A sender as cubic_sender_test.go drives one: packets in flight, oldest first.
mutable struct _QgcSender
    conn::QGC._Connection
    now::Int64
    next_pn::Int64
    queue::Vector{QGC._SentPacket}
    last_acked_sent::Int64
end
_QgcSender() = _QgcSender(_qgc_conn(), Int64(0), Int64(1), QGC._SentPacket[], typemin(Int64))

function _qgc_send_one!(s::_QgcSender, len::Int)
    s.now += 1
    push!(s.queue, QGC._SentPacket(s.next_pn, s.now, len, QGC._SentFrame[]))
    s.conn.bytes_in_flight += len
    s.next_pn += 1
    return nothing
end

# SendAvailableSendWindowLen
function _qgc_send_window!(s::_QgcSender, len::Int = _QGC_MSS)
    sent = 0
    while QGC._cwnd_allows(s.conn)
        _qgc_send_one!(s, len)
        sent += 1
    end
    return sent
end

# AckNPackets: an RTT sample of 60 ms, then n packets acknowledged.
function _qgc_ack!(s::_QgcSender, n::Int)
    conn = s.conn
    QGC._update_rtt!(conn, 60 * _QGC_MS, Int64(0))
    limited = QGC._cwnd_limited(conn)
    for _ in 1:n
        # Go acknowledges packet numbers it may not have sent; there is
        # nothing here to acknowledge then.
        isempty(s.queue) && break
        p = popfirst!(s.queue)
        s.last_acked_sent = p.time_sent
        QGC._cc_on_acked!(conn, p, s.now, limited)
    end
    s.now += _QGC_MS
    return nothing
end

# LoseNPacketsLen
function _qgc_lose!(s::_QgcSender, n::Int)
    for _ in 1:n
        p = popfirst!(s.queue)
        s.conn.bytes_in_flight -= p.size
        QGC._cc_on_congestion!(s.conn, p.time_sent, s.now)
    end
    return nothing
end

# LosePacket(number), which does not count as acknowledged progress. A
# packet number not yet sent is sent first, after everything else.
function _qgc_lose_packet!(s::_QgcSender, pn::Int64)
    i = findfirst(p -> p.pn == pn, s.queue)
    if i === nothing
        while s.next_pn <= pn
            _qgc_send_one!(s, _QGC_MSS)
        end
        i = findfirst(p -> p.pn == pn, s.queue)
    end
    p = s.queue[i]
    deleteat!(s.queue, i)
    s.conn.bytes_in_flight -= p.size
    QGC._cc_on_congestion!(s.conn, p.time_sent, s.now)
    return nothing
end

# InRecovery: the last packet acknowledged was sent before the recovery began.
_qgc_in_recovery(s::_QgcSender) = s.last_acked_sent != typemin(Int64) && s.last_acked_sent <= s.conn.recovery_start

const _QGC_DEFAULT_WINDOW_TCP = 10 * _QGC_MSS
const _QGC_RENO_BETA = 0.7

@testset "quic-go congestion control" begin
    @testset "Cubic" begin
        # The port run on Chromium's algorithm with Go's parameters: every
        # expectation must hold, or the port is wrong.
        @testset "reference (Chromium's algorithm, 2 connections, 1280 bytes)" begin
            _qgc_cubic_suite(_QgcCubicParams(2, 1280, false))
        end
        @testset "ours (1 connection, $(_QGC_MSS) bytes)" begin
            _qgc_cubic_suite(_QgcCubicParams(1, _QGC_MSS, true))
        end
    end

    @testset "Cubic Sender" begin
        @testset "has the right values at startup" begin
            s = _QgcSender()
            # At startup make sure we are at the default.
            @test s.conn.cwnd == _QGC_DEFAULT_WINDOW_TCP
            # Make sure we can send. (TimeUntilSend: pacing, N/A.)
            @test QGC._cwnd_allows(s.conn)
            # And that window is un-affected.
            @test s.conn.cwnd == _QGC_DEFAULT_WINDOW_TCP
            # Fill the send window with data, then verify that we can't send.
            _qgc_send_window!(s)
            @test !QGC._cwnd_allows(s.conn)
        end

        @testset "application limited slow start" begin
            s = _QgcSender()
            # Send exactly 10 packets and ensure the CWND ends at 14 packets.
            number_of_acks = 5
            @test QGC._cwnd_allows(s.conn)
            _qgc_send_window!(s)
            for _ in 1:number_of_acks
                _qgc_ack!(s, 2)
            end
            # 2 acks arrive while bytes in flight exceed half the window.
            @test s.conn.cwnd == _QGC_DEFAULT_WINDOW_TCP + _QGC_MSS * 2 * 2
        end

        @testset "exponential slow start" begin
            s = _QgcSender()
            number_of_acks = 20
            @test QGC._cwnd_allows(s.conn)
            for _ in 1:number_of_acks
                # Send our full send window.
                _qgc_send_window!(s)
                _qgc_ack!(s, 2)
            end
            # (BandwidthEstimate: Go API for pacing, N/A.)
            @test s.conn.cwnd == _QGC_DEFAULT_WINDOW_TCP + _QGC_MSS * 2 * number_of_acks
        end

        @testset "slow start packet loss" begin
            s = _QgcSender()
            number_of_acks = 10
            for _ in 1:number_of_acks
                _qgc_send_window!(s)
                _qgc_ack!(s, 2)
            end
            _qgc_send_window!(s)
            expected = _QGC_DEFAULT_WINDOW_TCP + _QGC_MSS * 2 * number_of_acks
            @test s.conn.cwnd == expected

            # Lose a packet to exit slow start.
            _qgc_lose!(s, 1)
            packets_in_recovery_window = expected ÷ _QGC_MSS

            # Out of slow start with a reduced window.
            expected = trunc(Int, Float32(expected) * Float32(_QGC_RENO_BETA))
            @test s.conn.cwnd == expected

            # Recovery phase: every packet in the recovery window is acked
            # before recovery ends.
            _qgc_ack!(s, packets_in_recovery_window)
            _qgc_send_window!(s)
            @test s.conn.cwnd == expected
            # The rest (an entire window acked before cwnd grows by one MSS,
            # then hybrid slow start reset by an RTO) is Reno mode and hybrid
            # slow start: N/A.
        end

        @testset "tcp cubic reset epoch on quiescence" begin
            s = _QgcSender()
            max_cwnd_bytes = 50 * _QGC_MSS
            num_sent = _qgc_send_window!(s)

            # Make sure we fall out of slow start.
            saved = s.conn.cwnd
            _qgc_lose!(s, 1)
            @test saved > s.conn.cwnd

            # Ack the rest of the outstanding packets to get out of recovery.
            for _ in 2:num_sent
                _qgc_ack!(s, 1)
            end
            @test s.conn.bytes_in_flight == 0

            # Send a new window of data and ack all; cubic growth should occur.
            saved = s.conn.cwnd
            num_sent = _qgc_send_window!(s)
            for _ in 1:num_sent
                _qgc_ack!(s, 1)
            end
            @test saved < s.conn.cwnd
            @test max_cwnd_bytes > s.conn.cwnd
            @test s.conn.bytes_in_flight == 0

            # Quiescent time of 100 seconds.
            s.now += 100_000 * _QGC_MS

            # Send new window of data and ack one packet. Cubic epoch should
            # have been reset; ensure cwnd increase is not dramatic.
            saved = s.conn.cwnd
            _qgc_send_window!(s)
            _qgc_ack!(s, 1)
            @test abs(saved - s.conn.cwnd) <= _QGC_MSS
            @test max_cwnd_bytes > s.conn.cwnd
        end

        @testset "multiple losses in one window" begin
            s = _QgcSender()
            _qgc_send_window!(s)
            initial_window = s.conn.cwnd
            acked_pn = Int64(0)
            _qgc_lose_packet!(s, acked_pn + 1)
            post_loss_window = s.conn.cwnd
            @test initial_window > post_loss_window
            _qgc_lose_packet!(s, acked_pn + 3)
            @test s.conn.cwnd == post_loss_window
            _qgc_lose_packet!(s, s.next_pn - 1)
            @test s.conn.cwnd == post_loss_window

            # Lose a later packet and ensure the window decreases.
            _qgc_lose_packet!(s, s.next_pn)
            @test post_loss_window > s.conn.cwnd
        end

        @testset "1 connection congestion avoidance at end of recovery" begin
            s = _QgcSender()
            # Ack 10 packets in 5 acks to raise the CWND to 20.
            number_of_acks = 5
            for _ in 1:number_of_acks
                _qgc_send_window!(s)
                _qgc_ack!(s, 2)
            end
            _qgc_send_window!(s)
            expected = _QGC_DEFAULT_WINDOW_TCP + _QGC_MSS * 2 * number_of_acks
            @test s.conn.cwnd == expected

            _qgc_lose!(s, 1)

            # Out of slow start with a reduced window.
            expected = trunc(Int, Float32(expected) * Float32(_QGC_RENO_BETA))
            @test s.conn.cwnd == expected

            # No growth in the recovery phase, until the 20 outstanding
            # packets are acked.
            in_recovery = Bool[]
            unchanged = Bool[]
            for _ in 1:10
                _qgc_send_window!(s)
                push!(in_recovery, _qgc_in_recovery(s))
                _qgc_ack!(s, 2)
                push!(unchanged, s.conn.cwnd == expected)
            end
            @test all(in_recovery)
            @test all(unchanged[1:(end - 1)])
            # Differs from quic-go: Go expects no growth on the last ACK too,
            # in Reno mode, which waits for a whole window of ACKs. That ACK
            # is for a packet sent after recovery began, which ends recovery
            # (RFC 9002 Section 7.3.2), and our CUBIC grows by its
            # Reno-friendly estimate, a fraction of a datagram.
            @test expected < s.conn.cwnd < expected + _QGC_MSS
            @test !_qgc_in_recovery(s)
            # The rest (no growth for the next window of ACKs, then exactly
            # one MSS) is Reno mode: N/A.
        end

        @testset "no PRR" begin
            s = _QgcSender()
            _qgc_send_window!(s)
            _qgc_lose!(s, 9)
            _qgc_ack!(s, 1)

            @test s.conn.cwnd == trunc(Int, Float32(_QGC_RENO_BETA) * Float32(_QGC_DEFAULT_WINDOW_TCP))
            window_in_packets = Float32(_QGC_RENO_BETA) * Float32(_QGC_DEFAULT_WINDOW_TCP) / Float32(_QGC_MSS)
            num_sent = _qgc_send_window!(s)
            @test num_sent == trunc(Int, window_in_packets)
        end

        @testset "reset after connection migration" begin
            s = _QgcSender()
            @test s.conn.cwnd == _QGC_DEFAULT_WINDOW_TCP
            @test s.conn.ssthresh == typemax(Int)

            # Starts with slow start.
            number_of_acks = 10
            for _ in 1:number_of_acks
                _qgc_send_window!(s)
                _qgc_ack!(s, 2)
            end
            _qgc_send_window!(s)
            expected = _QGC_DEFAULT_WINDOW_TCP + _QGC_MSS * 2 * number_of_acks
            @test s.conn.cwnd == expected

            # Loses a packet to exit slow start.
            _qgc_lose!(s, 1)

            # Out of slow start with a reduced window; the slow start
            # threshold is updated too.
            expected = trunc(Int, Float32(expected) * Float32(_QGC_RENO_BETA))
            @test s.conn.cwnd == expected
            @test s.conn.ssthresh == expected
            # The reset on OnConnectionMigration is N/A (no migration).
        end

        @testset "slow starts up to the maximum congestion window" begin
            # quic-go caps the window at MaxCongestionWindowPackets (10000) datagrams.
            conn = _qgc_conn()
            initial_max_cwnd = 10000 * _QGC_MSS
            for i in 1:(10000 - 1)
                conn.bytes_in_flight = conn.cwnd
                QGC._cc_on_acked!(conn, QGC._SentPacket(i, Int64(i), 1350, QGC._SentFrame[]), Int64(i + 1), true)
            end
            # Differs from quic-go: Go caps the window at initial_max_cwnd.
            # RFC 9002 has no maximum window, and its slow start adds the
            # bytes acknowledged (Section 7.3.1) where Go adds one datagram
            # per packet, so ours grows by every 1350-byte packet.
            @test conn.cwnd > initial_max_cwnd
            @test conn.cwnd == QGC._INITIAL_WINDOW + (10000 - 1) * 1350
        end

        @testset "slow starts up to maximum congestion window, if larger packets are sent" begin
            conn = _qgc_conn()
            packet_size = 1280 + 100
            conn.max_datagram_size = packet_size
            for i in 1:(10000 - 1)
                conn.bytes_in_flight = conn.cwnd
                QGC._cc_on_acked!(conn, QGC._SentPacket(i, Int64(i), packet_size, QGC._SentFrame[]), Int64(i + 1), true)
            end
            max_cwnd = 10000 * packet_size
            @test conn.cwnd > max_cwnd
            # Differs from quic-go: Go caps the window at max_cwnd plus a
            # packet; RFC 9002 has no maximum window (see above).
            @test conn.cwnd == QGC._INITIAL_WINDOW + (10000 - 1) * packet_size
        end

        @testset "limit cwnd increase in congestion avoidance" begin
            # Cubic.
            s = _QgcSender()
            num_sent = _qgc_send_window!(s)

            # Make sure we fall out of slow start.
            saved = s.conn.cwnd
            _qgc_lose!(s, 1)
            @test saved > s.conn.cwnd

            # Ack the rest of the outstanding packets to get out of recovery.
            for _ in 2:num_sent
                _qgc_ack!(s, 1)
            end
            @test s.conn.bytes_in_flight == 0

            saved = s.conn.cwnd
            _qgc_send_window!(s)

            # Ack packets until the CWND increases.
            while s.conn.cwnd == saved
                _qgc_ack!(s, 1)
                _qgc_send_window!(s)
            end
            # Bytes in flight may be larger than the CWND if the CWND isn't an
            # exact multiple of the packet sizes being sent.
            # Differs from quic-go: Go expects bytes in flight >= cwnd, since
            # its CanSend only needs bytes in flight below the window and so
            # overshoots it. RFC 9002 Section 7 says bytes in flight MUST NOT
            # exceed the window, and ours never sends past it.
            @test s.conn.bytes_in_flight <= s.conn.cwnd
            saved = s.conn.cwnd

            # Advance time 2 seconds waiting for an ack.
            s.now += 2000 * _QGC_MS

            # Ack two packets. The CWND should increase by only one packet.
            _qgc_ack!(s, 2)
            # Differs from quic-go: Chromium jumps to the curve, capped at half
            # the acked bytes per ACK, so grows by exactly one MSS for two
            # ACKs; ours moves (target - cwnd)/cwnd per ACK (RFC 9438 Section
            # 4.4), 899 bytes here, so the limit holds but not the exact value.
            @test saved < s.conn.cwnd <= saved + _QGC_MSS
        end
    end

    @testset "RTTStats" begin
        @testset "TestRTTStatsDefaults" begin
            conn = _qgc_conn()
            @test conn.min_rtt == 0
            @test conn.smoothed_rtt == 0
        end

        @testset "TestRTTStatsSmoothedRTT" begin
            conn = _qgc_conn()
            # ack_delay is ignored in the first measurement.
            QGC._update_rtt!(conn, 300 * _QGC_MS, 100 * _QGC_MS)
            @test conn.latest_rtt == 300 * _QGC_MS
            @test conn.smoothed_rtt == 300 * _QGC_MS
            # Smoothed RTT includes max ack delay if it's reasonable.
            QGC._update_rtt!(conn, 350 * _QGC_MS, 50 * _QGC_MS)
            # Differs from quic-go: Go's LatestRTT (300 ms) is the sample less
            # the ack delay; our latest_rtt is the raw sample, as RFC 9002
            # Section 5.3 defines it (the adjusted value only feeds smoothed_rtt).
            @test conn.latest_rtt == 350 * _QGC_MS
            @test conn.smoothed_rtt == 300 * _QGC_MS
            # A large erroneous ack_delay does not change Smoothed RTT.
            QGC._update_rtt!(conn, 200 * _QGC_MS, 300 * _QGC_MS)
            @test conn.latest_rtt == 200 * _QGC_MS
            @test conn.smoothed_rtt == 287_500 * _QGC_US
        end

        @testset "TestRTTStatsMinRTT" begin
            conn = _qgc_conn()
            QGC._update_rtt!(conn, 200 * _QGC_MS, Int64(0))
            @test conn.min_rtt == 200 * _QGC_MS
            QGC._update_rtt!(conn, 10 * _QGC_MS, Int64(0))
            @test conn.min_rtt == 10 * _QGC_MS
            for _ in 1:3
                QGC._update_rtt!(conn, 50 * _QGC_MS, Int64(0))
                @test conn.min_rtt == 10 * _QGC_MS
            end
            # ack_delay does not go into recording of MinRTT.
            QGC._update_rtt!(conn, 7 * _QGC_MS, 2 * _QGC_MS)
            @test conn.min_rtt == 7 * _QGC_MS
        end

        @testset "TestRTTStatsComputePTO" begin
            max_ack_delay_ms = 42 * 60 * 1000
            rtt = 1000 * _QGC_MS
            conn = _qgc_conn()
            conn.peer_params = QGC._TransportParameters(max_ack_delay_ms = UInt64(max_ack_delay_ms))
            QGC._update_rtt!(conn, rtt, Int64(0))
            @test conn.smoothed_rtt == rtt
            @test conn.rttvar == rtt ÷ 2
            @test QGC._pto_duration(conn, QGC._HANDSHAKE_SPACE) == rtt + 4 * (rtt ÷ 2)
            @test QGC._pto_duration(conn, QGC._APPLICATION_SPACE) == rtt + 4 * (rtt ÷ 2) + max_ack_delay_ms * _QGC_MS
        end

        @testset "TestRTTStatsPTOWithShortRTT" begin
            rtt = _QGC_US
            conn = _qgc_conn()
            QGC._update_rtt!(conn, rtt, Int64(0))
            @test QGC._pto_duration(conn, QGC._APPLICATION_SPACE) == rtt + QGC._GRANULARITY_NS
        end

        @testset "TestRTTStatsUpdateWithBadSendDeltas" begin
            conn = _qgc_conn()
            initial_rtt = 10 * _QGC_MS
            QGC._update_rtt!(conn, initial_rtt, Int64(0))
            @test conn.min_rtt == initial_rtt
            @test conn.smoothed_rtt == initial_rtt

            min_kept = Bool[]
            smoothed_kept = Bool[]
            for bad in (Int64(0), -1000 * _QGC_US)
                QGC._update_rtt!(conn, bad, Int64(0))
                push!(min_kept, conn.min_rtt == initial_rtt)
                push!(smoothed_kept, conn.smoothed_rtt == initial_rtt)
            end
            @test all(min_kept)
            @test all(smoothed_kept)
        end
    end
end
