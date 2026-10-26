# QUIC connections (RFC 9000).
#
# A `_Connection` is a sans-I/O state machine: the caller hands it datagrams
# with `_receive_datagram!`, sends whatever `_next_datagram!` returns, and calls
# `_handle_timeout!` once `_next_timeout` passes. Times are monotonic
# nanoseconds supplied by the caller. The TLS handshake runs in a
# `TLS.QUICConn`; this layer carries its CRYPTO data, installs its keys, and
# discards them as RFC 9001 Section 4.9 requires. It acknowledges packets,
# detects loss and retransmits what was lost (RFC 9002 Section 6), and limits
# bytes in flight with NewReno congestion control (RFC 9002 Section 7). Streams
# and flow control are in streams.jl.

const _MAX_DATAGRAM_SIZE = 1200
# Path MTU discovery (RFC 8899): the largest datagram probed for unless the
# socket knows better (Ethernet's 1500-byte MTU less IPv6 and UDP headers);
# the search stops within this many bytes; a size is given up on after this
# many lost probes; and this many consecutive probe timeouts with datagrams
# above the minimum mean the path no longer carries them.
const _PMTU_DEFAULT_CEILING = 1452
# The most a socket's own MTU may raise the ceiling to: jumbo frames.
const _PMTU_MAX_CEILING = 9000
const _PMTU_PRECISION = 20
const _PMTU_MAX_PROBES = 3
const _PMTU_BLACK_HOLE_PTOS = 3
const _LOCAL_CID_LEN = 8
const _INITIAL_RTT_NS = Int64(333_000_000)  # RFC 9002 Section 6.2.2
const _GRANULARITY_NS = Int64(1_000_000)
const _PACKET_THRESHOLD = 3                 # RFC 9002 Section 6.1.1
const _MAX_ACK_RANGES = 32
# Backoff stops lengthening the probe timeout here (quic-go's maxPTODuration).
const _MAX_PTO_NS = Int64(60_000_000_000)
const _DEFAULT_IDLE_TIMEOUT_MS = UInt64(30_000)
# Until the handshake completes, a connection quiet this long is dropped, and
# one not done by twice this from its creation (quic-go's
# DefaultHandshakeIdleTimeout and handshakeTimeout).
const _HANDSHAKE_IDLE_TIMEOUT_NS = Int64(5_000_000_000)
# Congestion windows (RFC 9002 Section 7.2).
const _INITIAL_WINDOW = 10 * _MAX_DATAGRAM_SIZE
const _MINIMUM_WINDOW = 2 * _MAX_DATAGRAM_SIZE
# 1-RTT packets are acknowledged after this many ack-eliciting ones arrive, or
# after max_ack_delay (RFC 9000 Section 13.2.2).
const _ACK_ELICITING_THRESHOLD = 2
# Bound on PATH_RESPONSE frames waiting to be sent.
const _MAX_PATH_RESPONSES = 8
# Automatic 1-RTT key updates, as quic-go makes them: the first soon after the
# handshake, to exercise the mechanism, then after this many packets sent or
# received with one key (RFC 9001 Section 6).
const _FIRST_KEY_UPDATE_INTERVAL = Int64(100)
const _KEY_UPDATE_INTERVAL = Int64(100_000)
# Packets kept in hand below the confidentiality limit for CONNECTION_CLOSE,
# when no key update is allowed before it is reached.
const _AEAD_LIMIT_HEADROOM = Int64(1_000)

const _INITIAL_SPACE = 1
const _HANDSHAKE_SPACE = 2
const _APPLICATION_SPACE = 3

# Connection states. `Established` means the TLS handshake completed;
# `Confirmed` means it is confirmed (RFC 9001 Section 4.1.2). `Closing` sends
# CONNECTION_CLOSE after a local error, `Draining` follows the peer's, and both
# end in `Closed`.
module _ConnState
Base.@enum T::UInt8 begin
    Handshaking = 0
    Established = 1
    Confirmed = 2
    Closing = 3
    Draining = 4
    Closed = 5
end
end

"""
An ack-eliciting packet awaiting acknowledgment: its size, counted in flight,
and its frames; the largest packet number an ACK frame in it acknowledged (-1
for none); and whether a probe timeout already queued its frames again.
"""
struct _SentPacket
    pn::Int64
    time_sent::Int64
    size::Int
    frames::Vector{_SentFrame}
    ack_largest::Int64
    resent::Bool
end

_SentPacket(pn::Integer, time_sent::Integer, size::Integer, frames::Vector{_SentFrame}) =
    _SentPacket(Int64(pn), Int64(time_sent), Int(size), frames, Int64(-1), false)

"""
    _PacketSpace

State for one packet number space: its keys, packet numbers sent and received,
the CRYPTO stream at its encryption level, and packets in flight.
`ack_pending` means an ack-eliciting packet arrived since the last ACK, which
is due at `ack_deadline`. `last_ack_largest` is the largest packet number the
last ACK sent reported (-1 before the first), and `ack_floor` the lowest the
peer has not seen acknowledged. `loss_time` is when the time threshold will
declare the earliest unacknowledged packet lost (RFC 9002 Section 6.1.2).
"""
mutable struct _PacketSpace
    read_keys::Union{Nothing, _PacketKeys}
    write_keys::Union{Nothing, _PacketKeys}
    discarded::Bool
    next_pn::Int64
    largest_acked::Int64
    largest_received::Int64
    largest_received_time::Int64
    received::_ReceivedPackets
    ack_pending::Bool
    ack_eliciting_received::Int
    ack_deadline::Int64
    last_ack_largest::Int64
    ack_floor::Int64
    crypto_send::_CryptoSendBuffer
    crypto_recv::_Reassembly
    sent::Vector{_SentPacket}
    time_of_last_ack_eliciting::Int64
    loss_time::Int64
    probes::Int
end

_PacketSpace() = _PacketSpace(
    nothing, nothing, false, Int64(0), Int64(-1), Int64(-1), Int64(0), _ReceivedPackets(), false, 0, typemax(Int64),
    Int64(-1), Int64(0), _CryptoSendBuffer(), _Reassembly(), _SentPacket[], Int64(0), typemax(Int64), 0,
)

_ack_due(space::_PacketSpace, now::Int64)::Bool = space.ack_pending && now >= space.ack_deadline

"""
    _Connection

One QUIC connection, client or server. See the file header for how to drive it.
"""
Base.@kwdef mutable struct _Connection
    is_server::Bool
    tls::TLS.QUICConn
    state::_ConnState.T = _ConnState.Handshaking
    spaces::NTuple{3, _PacketSpace} = (_PacketSpace(), _PacketSpace(), _PacketSpace())
    local_cid::Vector{UInt8}
    peer_cid::Vector{UInt8}
    # The Destination Connection ID of the client's first Initial.
    original_dcid::Vector{UInt8}
    peer_cid_set::Bool
    local_params::_TransportParameters
    peer_params::Union{Nothing, _TransportParameters} = nothing
    handshake_complete::Bool = false
    handshake_confirmed::Bool = false
    handshake_done_pending::Bool = false
    # Servers send at most three times what they received until the client's
    # address is validated (RFC 9000 Section 8.1).
    address_validated::Bool = false
    # A client knows the server validated its address once the server
    # acknowledges a Handshake or 1-RTT packet (RFC 9002 Appendix A.8).
    peer_validated_address::Bool = false
    bytes_received::Int = 0
    bytes_sent::Int = 0
    smoothed_rtt::Int64 = Int64(0)
    rttvar::Int64 = Int64(0)
    min_rtt::Int64 = Int64(0)
    latest_rtt::Int64 = Int64(0)
    has_rtt_sample::Bool = false
    pto_count::Int = 0
    # NewReno (RFC 9002 Section 7): packets sent at or before
    # `recovery_start` do not grow the window or cause another reduction.
    cwnd::Int = _INITIAL_WINDOW
    ssthresh::Int = typemax(Int)
    bytes_in_flight::Int = 0
    # Packets loss detection declared lost, less those whose frames a probe
    # timeout had already queued again.
    packets_lost::Int = 0
    # CUBIC (RFC 9438): the window before the last reduction, the time from
    # the start of an epoch until the window regains it (seconds), when the
    # current congestion avoidance epoch began (-1 before it), the window
    # Reno would have, and growth not yet a whole byte.
    cubic_w_max::Float64 = 0.0
    cubic_k::Float64 = 0.0
    cubic_epoch::Int64 = Int64(-1)
    cubic_w_est::Float64 = 0.0
    cubic_growth::Float64 = 0.0
    # Path MTU discovery: the datagram size in use; the most the local socket
    # may send; the search's upper bound (0 before it starts); whether a
    # probe should go out, and of what size; the outstanding probe's packet
    # number (-1 for none) and when it was sent; lost probes at that size;
    # and whether the search is over.
    max_datagram_size::Int = _MAX_DATAGRAM_SIZE
    pmtu_ceiling::Int = _PMTU_DEFAULT_CEILING
    pmtu_high::Int = 0
    pmtu_probe_due::Bool = false
    pmtu_probe_size::Int = 0
    pmtu_probe_pn::Int64 = Int64(-1)
    pmtu_probe_time::Int64 = Int64(0)
    pmtu_failures::Int = 0
    pmtu_done::Bool = false
    recovery_start::Int64 = typemin(Int64)
    last_send_time::Int64
    last_activity::Int64
    idle_timeout_ns::Int64 = Int64(_DEFAULT_IDLE_TIMEOUT_MS) * 1_000_000
    handshake_idle_timeout_ns::Int64 = _HANDSHAKE_IDLE_TIMEOUT_NS
    created::Int64 = Int64(0)
    close_pending::Bool = false
    close_deadline::Int64 = Int64(0)
    # Datagrams received while closing, each answered at falling rate.
    close_received::Int = 0
    # 1-RTT key updates (RFC 9001 Section 6). The application space's keys are
    # the current phase's; `prev_read_keys` open packets from the phase before,
    # until `prev_read_keys_expiry`, and `next_read_keys` (derived on demand)
    # those from the next. The first packet numbers sent and received in the
    # current phase tell which phase an incoming packet belongs to, and when
    # another update may start; the packets sent and received in it, when one
    # is due. The update intervals are fields so tests can lower them.
    key_phase::Bool = false
    prev_read_keys::Union{Nothing, _PacketKeys} = nothing
    prev_read_keys_expiry::Int64 = typemax(Int64)
    next_read_keys::Union{Nothing, _PacketKeys} = nothing
    key_phase_first_sent::Int64 = Int64(-1)
    key_phase_first_received::Int64 = typemax(Int64)
    key_phase_sent::Int64 = Int64(0)
    key_phase_received::Int64 = Int64(0)
    key_updates::Int = 0
    first_key_update_interval::Int64 = _FIRST_KEY_UPDATE_INTERVAL
    key_update_interval::Int64 = _KEY_UPDATE_INTERVAL
    # 1-RTT packets that failed authentication, and how many end the
    # connection (RFC 9001 Section 6.6), set with the 1-RTT keys.
    invalid_packets::Int64 = Int64(0)
    invalid_packet_limit::Int64 = typemax(Int64)
    error::Union{Nothing, _TransportError} = nothing
    peer_error::Union{Nothing, _TransportError} = nothing
    # Streams. `local_opened_*` and `peer_opened_*` count the streams each side
    # has opened; `peer_max_streams_*` limit this endpoint and
    # `local_max_streams_*` limit the peer, which closing its streams raises.
    limits::_StreamLimits
    streams::Dict{UInt64, _Stream} = Dict{UInt64, _Stream}()
    local_opened_bidi::Int64 = Int64(0)
    local_opened_uni::Int64 = Int64(0)
    peer_max_streams_bidi::Int64 = Int64(0)
    peer_max_streams_uni::Int64 = Int64(0)
    peer_opened_bidi::Int64 = Int64(0)
    peer_opened_uni::Int64 = Int64(0)
    local_max_streams_bidi::Int64
    local_max_streams_uni::Int64
    peer_closed_bidi::Int64 = Int64(0)
    peer_closed_uni::Int64 = Int64(0)
    max_streams_bidi_pending::Bool = false
    max_streams_uni_pending::Bool = false
    # The peer's stream limits last reported with STREAMS_BLOCKED (-1 for
    # none), and whether that frame is still to be sent.
    streams_blocked_bidi_at::Int64 = Int64(-1)
    streams_blocked_uni_at::Int64 = Int64(-1)
    streams_blocked_bidi_pending::Bool = false
    streams_blocked_uni_pending::Bool = false
    accept_queue::Vector{UInt64} = UInt64[]
    # Streams with frames to send, served round robin.
    send_queue::Vector{UInt64} = UInt64[]
    # STOP_SENDING frames (stream ID, error code) of streams freed before
    # they went out.
    stop_sending_queue::Vector{Tuple{UInt64, UInt64}} = Tuple{UInt64, UInt64}[]
    # Connection flow control (RFC 9000 Section 4.1): what this endpoint may
    # send and has sent, and the limit it set for the peer, what the peer has
    # sent against it, and what the application has consumed.
    peer_max_data::Int64 = Int64(0)
    data_sent::Int64 = Int64(0)
    local_max_data::Int64
    data_received::Int64 = Int64(0)
    data_consumed::Int64 = Int64(0)
    max_data_pending::Bool = false
    # The peer's limit last reported with DATA_BLOCKED (-1 for none), and
    # whether that frame is still to be sent.
    data_blocked_at::Int64 = Int64(-1)
    data_blocked_pending::Bool = false
    path_responses::Vector{UInt64} = UInt64[]
    # Where datagrams are built; see `_build_datagram!`.
    tx_buf::Vector{UInt8} = sizehint!(UInt8[], _MAX_DATAGRAM_SIZE)
end

_handshake_complete(conn::_Connection)::Bool = conn.handshake_complete
_handshake_confirmed(conn::_Connection)::Bool = conn.handshake_confirmed

# PeerCompletedAddressValidation (RFC 9002 Appendix A.8): a server takes the
# client's address as given; a client knows once a Handshake or 1-RTT packet
# is acknowledged, or the handshake is confirmed.
_peer_completed_address_validation(conn::_Connection)::Bool =
    conn.is_server || conn.peer_validated_address || conn.handshake_confirmed

@inline function _space_index(level::TLS.QUICEncryptionLevel.T)::Int
    level == TLS.QUICEncryptionLevel.Initial && return _INITIAL_SPACE
    level == TLS.QUICEncryptionLevel.Handshake && return _HANDSHAKE_SPACE
    level == TLS.QUICEncryptionLevel.Application && return _APPLICATION_SPACE
    throw(ArgumentError("QUIC 0-RTT is not supported"))
end

@inline function _space_level(idx::Int)::TLS.QUICEncryptionLevel.T
    idx == _INITIAL_SPACE && return TLS.QUICEncryptionLevel.Initial
    idx == _HANDSHAKE_SPACE && return TLS.QUICEncryptionLevel.Handshake
    return TLS.QUICEncryptionLevel.Application
end

_random_cid()::Vector{UInt8} = rand(Random.RandomDevice(), UInt8, _LOCAL_CID_LEN)

function _new_connection(
        is_server::Bool,
        tls::TLS.QUICConn,
        local_cid::Vector{UInt8},
        peer_cid::Vector{UInt8},
        original_dcid::Vector{UInt8},
        now::Int64,
        limits::_StreamLimits,
        max_udp_payload_size::Int = 65527,
    )::_Connection
    client_keys, server_keys = _initial_packet_keys(original_dcid)
    params = _TransportParameters(
        max_udp_payload_size = UInt64(max_udp_payload_size),
        original_destination_connection_id = is_server ? copy(original_dcid) : nothing,
        max_idle_timeout_ms = _DEFAULT_IDLE_TIMEOUT_MS,
        initial_max_data = UInt64(limits.max_data),
        initial_max_stream_data_bidi_local = UInt64(limits.max_stream_data),
        initial_max_stream_data_bidi_remote = UInt64(limits.max_stream_data),
        initial_max_stream_data_uni = UInt64(limits.max_stream_data),
        initial_max_streams_bidi = UInt64(limits.max_streams_bidi),
        initial_max_streams_uni = UInt64(limits.max_streams_uni),
        disable_active_migration = true,
        initial_source_connection_id = copy(local_cid),
    )
    conn = _Connection(;
        is_server, tls, local_cid, peer_cid, original_dcid, peer_cid_set = is_server,
        local_params = params, last_send_time = now, last_activity = now, created = now, limits,
        local_max_streams_bidi = limits.max_streams_bidi, local_max_streams_uni = limits.max_streams_uni,
        local_max_data = limits.max_data,
    )
    conn.spaces[_INITIAL_SPACE].read_keys = is_server ? client_keys : server_keys
    conn.spaces[_INITIAL_SPACE].write_keys = is_server ? server_keys : client_keys
    TLS.set_transport_parameters!(tls, _encode_transport_parameters(params))
    TLS.start!(tls)
    _process_tls_events!(conn, now)
    return conn
end

"""
    _client_connection(config, now; limits = _StreamLimits()) -> _Connection

Start a client connection. Its first `_next_datagram!` is the padded Initial.
`limits` are what the server may send and open.
"""
function _client_connection(config::TLS.Config, now::Int64; limits::_StreamLimits = _StreamLimits(), max_udp_payload_size::Int = 65527)::_Connection
    original_dcid = _random_cid()
    return _new_connection(false, TLS.quic_client(config), _random_cid(), copy(original_dcid), original_dcid, now, limits, max_udp_payload_size)
end

"""
    _accept_connection(config, datagram, header, now; limits = _StreamLimits()) -> _Connection or nothing

Start a server connection for a client's first Initial packet, parsed from
`datagram` as `header`. Pass the same datagram to `_receive_datagram!` next.
Returns `nothing` for an Initial a server must not answer: one in a datagram
under 1200 bytes (RFC 9000 Section 14.1) or with a Destination Connection ID
under 8 bytes (Section 7.2). `limits` are what the client may send and open.
"""
function _accept_connection(
        config::TLS.Config,
        datagram::Vector{UInt8},
        header::_PacketHeader,
        now::Int64;
        limits::_StreamLimits = _StreamLimits(),
        max_udp_payload_size::Int = 65527,
    )::Union{Nothing, _Connection}
    header.type == _PacketType.Initial || return nothing
    length(datagram) >= _MAX_DATAGRAM_SIZE || return nothing
    length(header.dcid) >= 8 || return nothing
    return _new_connection(true, TLS.quic_server(config), _random_cid(), datagram[header.scid], datagram[header.dcid], now, limits, max_udp_payload_size)
end

"""
    _check_peer_transport_parameters(conn, params) -> nothing or _TransportError

Authenticate the connection IDs the peer used (RFC 9000 Section 7.3): its
initial_source_connection_id must match the Source Connection ID it sent, and a
server must echo the client's original Destination Connection ID.
"""
function _check_peer_transport_parameters(conn::_Connection, params::_TransportParameters)::Union{Nothing, _TransportError}
    params.initial_source_connection_id === nothing && return _tp_error("peer did not send initial_source_connection_id")
    params.initial_source_connection_id == conn.peer_cid ||
        return _tp_error("initial_source_connection_id does not match the peer's connection ID")
    if !conn.is_server
        params.original_destination_connection_id === nothing &&
            return _tp_error("server did not send original_destination_connection_id")
        params.original_destination_connection_id == conn.original_dcid ||
            return _tp_error("original_destination_connection_id does not match")
        # This client never follows a Retry.
        params.retry_source_connection_id === nothing || return _tp_error("unexpected retry_source_connection_id")
    end
    return nothing
end

function _process_tls_events!(conn::_Connection, now::Int64)::Nothing
    while true
        e = TLS.next_event!(conn.tls)
        kind = e.kind
        kind == TLS.QUICEventKind.NoEvent && return nothing
        if kind == TLS.QUICEventKind.WriteData
            _crypto_queue!(conn.spaces[_space_index(e.level)].crypto_send, e.data)
        elseif kind == TLS.QUICEventKind.SetReadSecret
            conn.spaces[_space_index(e.level)].read_keys = _PacketKeys(e.suite, e.data)
            e.level == TLS.QUICEncryptionLevel.Application && (conn.invalid_packet_limit = _aead_integrity_limit(e.suite))
        elseif kind == TLS.QUICEventKind.SetWriteSecret
            conn.spaces[_space_index(e.level)].write_keys = _PacketKeys(e.suite, e.data)
        elseif kind == TLS.QUICEventKind.TransportParameters
            params = _decode_transport_parameters(e.data; from_server = !conn.is_server)
            if params isa _TransportError
                _close!(conn, params, now)
                return nothing
            end
            err = _check_peer_transport_parameters(conn, params)
            if err !== nothing
                _close!(conn, err, now)
                return nothing
            end
            conn.peer_params = params
            conn.peer_max_data = Int64(params.initial_max_data)
            conn.peer_max_streams_bidi = Int64(params.initial_max_streams_bidi)
            conn.peer_max_streams_uni = Int64(params.initial_max_streams_uni)
            conn.idle_timeout_ns = _negotiated_idle_timeout_ns(conn.idle_timeout_ns, params.max_idle_timeout_ms)
        elseif kind == TLS.QUICEventKind.HandshakeDone
            conn.handshake_complete = true
            conn.state == _ConnState.Handshaking && (conn.state = _ConnState.Established)
            # A server's handshake is confirmed once complete; it tells the
            # client with HANDSHAKE_DONE (RFC 9001 Section 4.1.2).
            if conn.is_server
                _confirm_handshake!(conn, now)
                conn.handshake_done_pending = true
            end
        elseif kind == TLS.QUICEventKind.Error
            err = e.err::TLS.TLSError
            _close!(conn, _TransportError(_CRYPTO_ERROR_BASE + TLS.alert_code(err), UInt64(0x06), err.message), now)
            return nothing
        end
    end
end

function _confirm_handshake!(conn::_Connection, now::Int64)::Nothing
    conn.handshake_confirmed = true
    conn.state == _ConnState.Established && (conn.state = _ConnState.Confirmed)
    _drop_encryption_level!(conn, _HANDSHAKE_SPACE, now)
    _pmtu_start!(conn)
    return nothing
end

# Path MTU discovery (RFC 9000 Section 14.3, RFC 8899): once the handshake is
# confirmed, probe first at the ceiling, which most paths carry, then search
# between the size in use and the largest size not yet given up on.
function _pmtu_start!(conn::_Connection)::Nothing
    peer = conn.peer_params
    peer_max = peer === nothing ? 65527 : Int(min(peer.max_udp_payload_size, UInt64(65527)))
    conn.pmtu_high = min(conn.pmtu_ceiling, peer_max)
    conn.pmtu_high > conn.max_datagram_size ? _pmtu_next!(conn, conn.pmtu_high) : _pmtu_stop!(conn)
    return nothing
end

function _pmtu_next!(conn::_Connection, size::Int)::Nothing
    conn.pmtu_probe_size = size
    conn.pmtu_probe_due = true
    return nothing
end

function _pmtu_stop!(conn::_Connection)::Nothing
    conn.pmtu_done = true
    conn.pmtu_probe_due = false
    conn.pmtu_probe_pn = Int64(-1)
    return nothing
end

# Probe halfway to the upper bound, unless the search is close enough.
function _pmtu_search!(conn::_Connection)::Nothing
    if conn.pmtu_high - conn.max_datagram_size < _PMTU_PRECISION
        _pmtu_stop!(conn)
    else
        _pmtu_next!(conn, (conn.max_datagram_size + conn.pmtu_high + 1) ÷ 2)
    end
    return nothing
end

function _pmtu_probe_acked!(conn::_Connection)::Nothing
    conn.max_datagram_size = conn.pmtu_probe_size
    conn.pmtu_probe_pn = Int64(-1)
    conn.pmtu_failures = 0
    _pmtu_search!(conn)
    return nothing
end

function _pmtu_probe_lost!(conn::_Connection)::Nothing
    conn.pmtu_probe_pn = Int64(-1)
    conn.pmtu_failures += 1
    if conn.pmtu_failures < _PMTU_MAX_PROBES
        _pmtu_next!(conn, conn.pmtu_probe_size)
    else
        conn.pmtu_failures = 0
        conn.pmtu_high = conn.pmtu_probe_size - 1
        _pmtu_search!(conn)
    end
    return nothing
end

# A probe is lost once three later packets are acknowledged, or after three
# probe timeouts' worth of time; probes are kept out of loss recovery and
# congestion control.
function _pmtu_check_probe!(conn::_Connection, now::Int64)::Nothing
    pn = conn.pmtu_probe_pn
    pn < 0 && return nothing
    space = conn.spaces[_APPLICATION_SPACE]
    if space.largest_acked - pn >= _PACKET_THRESHOLD || now >= _pmtu_probe_deadline(conn)
        _pmtu_probe_lost!(conn)
    end
    return nothing
end

_pmtu_probe_deadline(conn::_Connection)::Int64 = conn.pmtu_probe_time + 3 * _pto_duration(conn, _APPLICATION_SPACE)

# The path stopped carrying datagrams above the minimum (RFC 8899 Section 4.3).
# The local stack refused the probe as too large (EMSGSIZE): give up its size
# at once.
function _pmtu_refused!(conn::_Connection)::Nothing
    conn.pmtu_failures = _PMTU_MAX_PROBES - 1
    _pmtu_probe_lost!(conn)
    return nothing
end

function _pmtu_black_hole!(conn::_Connection)::Nothing
    conn.max_datagram_size = _MAX_DATAGRAM_SIZE
    _pmtu_stop!(conn)
    return nothing
end

# A probe: a 1-RTT packet of a PING and PADDING, alone in a datagram of the
# size being tested, outside loss recovery and congestion control.
function _build_probe_datagram!(conn::_Connection, now::Int64)::Vector{UInt8}
    buf = empty!(conn.tx_buf)
    space = conn.spaces[_APPLICATION_SPACE]
    layout, pn = _begin_packet!(conn, buf, _APPLICATION_SPACE)
    _append_ping_frame!(buf)
    payload_last = _end_packet!(buf, layout; pad_to = conn.pmtu_probe_size)
    space.next_pn += 1
    conn.key_phase_first_sent < 0 && (conn.key_phase_first_sent = pn)
    _seal_datagram!(conn, buf, [_PendingPacket(_APPLICATION_SPACE, layout, payload_last, pn, true, _SentFrame[], Int64(-1))], now)
    conn.pmtu_probe_due = false
    conn.pmtu_probe_pn = pn
    conn.pmtu_probe_time = now
    return buf
end

# Whether a probe may go out now: one at a time, with room in the window.
function _pmtu_probe_ready(conn::_Connection)::Bool
    return conn.pmtu_probe_due && conn.pmtu_probe_pn < 0 && conn.state == _ConnState.Confirmed &&
        conn.bytes_in_flight + conn.pmtu_probe_size <= conn.cwnd
end

"Stop using a packet number space and drop its keys (RFC 9001 Section 4.9)."
function _discard_space!(conn::_Connection, idx::Int)::Nothing
    space = conn.spaces[idx]
    space.discarded && return nothing
    space.discarded = true
    space.read_keys === nothing || _destroy_packet_keys!(space.read_keys)
    space.write_keys === nothing || _destroy_packet_keys!(space.write_keys)
    space.read_keys = nothing
    space.write_keys = nothing
    for p in space.sent
        conn.bytes_in_flight -= p.size
    end
    empty!(space.sent)
    space.ack_pending = false
    space.loss_time = typemax(Int64)
    space.probes = 0
    # Discarding keys is progress, so the probe backoff restarts (RFC 9002 Section 6.4).
    conn.pto_count = 0
    return nothing
end

# An encryption level ends: its packet number space goes. CRYPTO data still
# held there past what TLS was given can never be read, which is a
# PROTOCOL_VIOLATION (RFC 9001 Section 4.1.3), as quic-go treats it.
function _drop_encryption_level!(conn::_Connection, idx::Int, now::Int64)::Nothing
    space = conn.spaces[idx]
    leftover = !space.discarded && !isempty(space.crypto_recv.fragments)
    _discard_space!(conn, idx)
    leftover && _close!(conn, _TransportError(_PROTOCOL_VIOLATION, UInt64(0), "encryption level changed, but crypto stream has more data to read"), now)
    return nothing
end

function _close!(conn::_Connection, err::_TransportError, now::Int64)::Nothing
    state = conn.state
    (state == _ConnState.Closing || state == _ConnState.Draining || state == _ConnState.Closed) && return nothing
    conn.error = err
    conn.state = _ConnState.Closing
    conn.close_pending = true
    conn.close_deadline = now + 3 * _pto_duration(conn, _INITIAL_SPACE)
    return nothing
end

"""
    _close_connection!(conn, code, reason, now; app = true)

Close the connection now (RFC 9000 Section 10.2), sending CONNECTION_CLOSE
with `code` and `reason`: an application error code, or a transport error
code when `app = false`.
"""
function _close_connection!(conn::_Connection, code::UInt64, reason::String, now::Int64; app::Bool = true)::Nothing
    _close!(conn, _TransportError(code, UInt64(0), reason, app), now)
    return nothing
end

function _enter_draining!(conn::_Connection, peer_error::_TransportError, now::Int64)::Nothing
    conn.peer_error = peer_error
    (conn.state == _ConnState.Draining || conn.state == _ConnState.Closed) && return nothing
    conn.state = _ConnState.Draining
    conn.close_pending = false
    conn.close_deadline = now + 3 * _pto_duration(conn, _INITIAL_SPACE)
    return nothing
end

# Receiving.

"""
    _receive_datagram!(conn, buf, [first, last,] now)

Process one UDP datagram from the peer: `buf`, or `buf[first:last]`.
Packets are decrypted in place.
"""
_receive_datagram!(conn::_Connection, buf::Vector{UInt8}, now::Int64)::Nothing =
    _receive_datagram!(conn, buf, 1, length(buf), now)

function _receive_datagram!(conn::_Connection, buf::Vector{UInt8}, first::Int, last::Int, now::Int64)::Nothing
    if conn.state == _ConnState.Closing
        # The peer has not seen CONNECTION_CLOSE yet: send it again, for the
        # 1st, 2nd, 4th, 8th... datagram, so this cannot be used to amplify
        # (RFC 9000 Section 10.2.1).
        conn.close_received += 1
        ispow2(conn.close_received) && (conn.close_pending = true)
        # It still raises the anti-amplification budget (RFC 9000 Section
        # 8.1), which a close over that budget is waiting for.
        conn.bytes_received += last - first + 1
        return nothing
    end
    conn.state == _ConnState.Handshaking || conn.state == _ConnState.Established || conn.state == _ConnState.Confirmed ||
        return nothing
    processed = false
    for header in _datagram_packets(buf, first, last, _LOCAL_CID_LEN)
        idx = header.type == _PacketType.Initial ? _INITIAL_SPACE :
              header.type == _PacketType.Handshake ? _HANDSHAKE_SPACE :
              header.type == _PacketType.OneRTT ? _APPLICATION_SPACE : 0
        # Version Negotiation, Retry, and 0-RTT are not handled yet.
        idx == 0 && continue
        _receive_packet!(conn, buf, header, idx, now) && (processed = true)
        (conn.state == _ConnState.Closing || conn.state == _ConnState.Draining) && break
    end
    processed && (conn.bytes_received += last - first + 1)
    return nothing
end

function _receive_packet!(conn::_Connection, buf::Vector{UInt8}, header::_PacketHeader, idx::Int, now::Int64)::Bool
    space = conn.spaces[idx]
    keys = space.read_keys
    (space.discarded || keys === nothing) && return false
    opened = if idx == _APPLICATION_SPACE
        _open_1rtt_packet!(conn, space, keys, buf, header, now)
    else
        _open_packet!(keys, buf, header.first, header.pn_offset, header.last, space.largest_received)
    end
    opened === nothing && return false
    pn, payload_first, payload_last = opened
    if !_reserved_bits_ok(buf[header.first])
        _close!(conn, _TransportError(_PROTOCOL_VIOLATION, UInt64(0), "nonzero reserved bits"), now)
        return true
    end
    pn in space.received && return true
    # Below the largest packet number the last ACK reported, so reported missing there.
    was_missing = pn < space.last_ack_largest
    # A client switches to the connection ID the server chose in its first
    # Initial (RFC 9000 Section 7.2).
    if !conn.peer_cid_set && idx == _INITIAL_SPACE
        conn.peer_cid = buf[header.scid]
        conn.peer_cid_set = true
    end
    conn.last_activity = now
    result = _decode_frames(buf, payload_first, payload_last, header.type) do frame
        _on_frame!(conn, space, idx, buf, frame, now)
    end
    push!(space.received, pn:pn)
    _keep_largest_ranges!(space.received, _MAX_ACK_RANGES)
    _ignore_below!(space.received, space.ack_floor)
    if pn > space.largest_received
        space.largest_received = pn
        space.largest_received_time = now
    end
    # A packet below the floor was just dropped from the ranges: nothing to report.
    result.ack_eliciting && pn >= space.ack_floor && _schedule_ack!(conn, space, idx, was_missing, now)
    if result.error !== nothing
        _close!(conn, result.error, now)
        return true
    end
    if conn.is_server && idx == _HANDSHAKE_SPACE
        # A Handshake packet proves the client owns its address, and lets the
        # server drop its Initial keys (RFC 9001 Section 4.9.1).
        conn.address_validated = true
        _drop_encryption_level!(conn, _INITIAL_SPACE, now)
    end
    _process_tls_events!(conn, now)
    return true
end

# Opens a 1-RTT packet with the keys its Key Phase bit selects (RFC 9001
# Section 6.3). A packet that opens with the next phase's keys means the peer
# updated them, and this endpoint follows; one that does not is dropped, so a
# forged Key Phase bit changes nothing. Packets that fail authentication count
# toward the integrity limit, which closes the connection with
# AEAD_LIMIT_REACHED (Section 6.6).
function _open_1rtt_packet!(
        conn::_Connection,
        space::_PacketSpace,
        keys::_PacketKeys,
        buf::Vector{UInt8},
        header::_PacketHeader,
        now::Int64,
    )::Union{Nothing, Tuple{Int64, Int, Int}}
    unmasked = _remove_header_protection!(keys.hp, buf, header.first, header.pn_offset, header.last)
    unmasked === nothing && return nothing
    pn_len, truncated = unmasked
    pn = _decode_packet_number(space.largest_received, truncated, 8 * pn_len)
    phase = (buf[header.first] & 0x04) != 0
    prev = conn.prev_read_keys
    if prev !== nothing && now > conn.prev_read_keys_expiry
        # The previous phase's keys outlive the update by 3 PTO (Section 6.5).
        _destroy_packet_keys!(prev)
        conn.prev_read_keys = prev = nothing
        conn.prev_read_keys_expiry = typemax(Int64)
    end
    first_received = conn.key_phase_first_received
    if phase == conn.key_phase
        payload_last = _decrypt_payload!(keys, buf, header.first, header.pn_offset, pn_len, pn, header.last)
        payload_last === nothing && return _authentication_failed!(conn, now)
        # The peer's first packet in a phase this endpoint started shows it
        # has the new keys, so the old ones may go.
        first_received == typemax(Int64) && conn.key_updates > 0 && _start_key_drop_timer!(conn, now)
        conn.key_phase_first_received = min(first_received, pn)
        conn.key_phase_received += 1
        _maybe_update_keys!(conn, now)
    elseif pn < first_received && (first_received != typemax(Int64) || conn.key_updates > 0)
        # Sent before the current phase began, and delayed; dropped once the
        # previous phase's keys are gone.
        prev === nothing && return nothing
        payload_last = _decrypt_payload!(prev, buf, header.first, header.pn_offset, pn_len, pn, header.last)
        payload_last === nothing && return _authentication_failed!(conn, now)
    else
        next = conn.next_read_keys
        if next === nothing
            next = _next_packet_keys(keys)
            conn.next_read_keys = next
        end
        payload_last = _decrypt_payload!(next, buf, header.first, header.pn_offset, pn_len, pn, header.last)
        payload_last === nothing && return _authentication_failed!(conn, now)
        # The peer may update again only after this endpoint answered its last
        # update with the new keys (Section 6.2).
        if conn.key_updates > 0 && conn.key_phase_first_sent < 0
            _close!(conn, _TransportError(_KEY_UPDATE_ERROR, UInt64(0), "keys updated too quickly"), now)
            return nothing
        end
        _rotate_keys!(conn, space)
        conn.key_phase_first_received = pn
        _start_key_drop_timer!(conn, now)
    end
    return pn, header.pn_offset + pn_len, payload_last
end

function _authentication_failed!(conn::_Connection, now::Int64)::Nothing
    conn.invalid_packets += 1
    conn.invalid_packets >= conn.invalid_packet_limit &&
        _close!(conn, _TransportError(_AEAD_LIMIT_REACHED, UInt64(0), "AEAD integrity limit reached"), now)
    return nothing
end

function _start_key_drop_timer!(conn::_Connection, now::Int64)::Nothing
    conn.prev_read_keys_expiry = now + 3 * _pto_duration(conn, _APPLICATION_SPACE)
    return nothing
end

# Moves both directions to the next key phase; the current read keys become
# the previous phase's, and those before them, if still kept, are dropped.
function _rotate_keys!(conn::_Connection, space::_PacketSpace)::Nothing
    read = space.read_keys::_PacketKeys
    write = space.write_keys::_PacketKeys
    next_read = conn.next_read_keys
    space.read_keys = next_read === nothing ? _next_packet_keys(read) : next_read
    space.write_keys = _next_packet_keys(write)
    _destroy_packet_keys!(write)
    old = conn.prev_read_keys
    old === nothing || _destroy_packet_keys!(old)
    conn.prev_read_keys = read
    conn.prev_read_keys_expiry = typemax(Int64)
    conn.next_read_keys = nothing
    conn.key_phase = !conn.key_phase
    conn.key_phase_first_sent = Int64(-1)
    conn.key_phase_first_received = typemax(Int64)
    conn.key_phase_sent = Int64(0)
    conn.key_phase_received = Int64(0)
    conn.key_updates += 1
    return nothing
end

# Whether this endpoint may start a key update (RFC 9001 Section 6.1): once the
# handshake is confirmed, the first at once, and later ones after a packet sent
# with the current keys is acknowledged.
function _key_update_allowed(conn::_Connection)::Bool
    conn.state == _ConnState.Confirmed || return false
    conn.key_updates == 0 && return true
    first_sent = conn.key_phase_first_sent
    return first_sent >= 0 && conn.spaces[_APPLICATION_SPACE].largest_acked >= first_sent
end

"""
    _initiate_key_update!(conn) -> Bool

Switch to the next 1-RTT keys (RFC 9001 Section 6.1). Returns `false`, and
changes nothing, before the handshake is confirmed or, after an earlier
update, while no packet sent with the current keys has been acknowledged.
"""
function _initiate_key_update!(conn::_Connection)::Bool
    _key_update_allowed(conn) || return false
    _rotate_keys!(conn, conn.spaces[_APPLICATION_SPACE])
    return true
end

# Starts a key update once enough packets were sent or received with the
# current keys, as soon as one is allowed. Updates come well before the
# confidentiality limit (RFC 9001 Section 6.6); if none is allowed by the time
# it nears, the connection closes with AEAD_LIMIT_REACHED instead.
function _maybe_update_keys!(conn::_Connection, now::Int64)::Nothing
    interval = conn.key_update_interval
    conn.key_updates == 0 && (interval = min(interval, conn.first_key_update_interval))
    sent = conn.key_phase_sent
    (sent >= interval || conn.key_phase_received >= interval) || return nothing
    _initiate_key_update!(conn) && return nothing
    write = conn.spaces[_APPLICATION_SPACE].write_keys
    write === nothing && return nothing
    sent >= _aead_confidentiality_limit(write.suite) - _AEAD_LIMIT_HEADROOM &&
        _close!(conn, _TransportError(_AEAD_LIMIT_REACHED, UInt64(0), "AEAD confidentiality limit reached"), now)
    return nothing
end

# An acknowledgment of a packet sent with the current keys, before any packet
# protected with them arrived, came in a packet protected with older keys
# (RFC 9001 Section 6.2).
function _check_ack_key_phase(conn::_Connection, largest::Int64)::Union{Nothing, _TransportError}
    first_sent = conn.key_phase_first_sent
    (first_sent >= 0 && largest >= first_sent && conn.key_phase_first_received == typemax(Int64)) || return nothing
    return _TransportError(_KEY_UPDATE_ERROR, UInt64(0x02), "received ACK for key phase $(conn.key_updates), but peer didn't update keys")
end

# Initial and Handshake packets are acknowledged at once, and so is the first
# 1-RTT packet. Later 1-RTT packets wait for a second ack-eliciting packet or
# max_ack_delay, unless the last ACK reported this one missing, or it starts a
# new gap above what that ACK reported (RFC 9000 Section 13.2.1), as in
# quic-go's receivedPacketTracker.
function _schedule_ack!(conn::_Connection, space::_PacketSpace, idx::Int, was_missing::Bool, now::Int64)::Nothing
    space.ack_pending = true
    if idx != _APPLICATION_SPACE || space.last_ack_largest < 0
        space.ack_deadline = min(space.ack_deadline, now)
        return nothing
    end
    space.ack_deadline <= now && return nothing  # already due
    space.ack_eliciting_received += 1
    highest = space.received.ranges[end]
    new_gap = first(highest) > space.last_ack_largest + 1 && length(highest) == 1
    if was_missing || new_gap || space.ack_eliciting_received >= _ACK_ELICITING_THRESHOLD
        space.ack_deadline = now
    else
        space.ack_deadline = min(space.ack_deadline, now + Int64(conn.local_params.max_ack_delay_ms) * 1_000_000)
    end
    return nothing
end

# Frames nothing acts on (PADDING, PING, PATH_RESPONSE, the *_BLOCKED frames,
# connection ID management) are accepted and ignored.
_on_frame!(conn::_Connection, space::_PacketSpace, idx::Int, buf::Vector{UInt8}, frame, now::Int64) = nothing

function _on_frame!(conn::_Connection, space::_PacketSpace, idx::Int, buf::Vector{UInt8}, frame::_CryptoFrame, now::Int64)::Union{Nothing, _TransportError}
    bytes = _crypto_receive!(space.crypto_recv, frame.offset, @view(buf[frame.data]))
    bytes isa _TransportError && return bytes
    isempty(bytes) && return nothing
    try
        TLS.handle_data!(conn.tls, _space_level(idx), bytes)
    catch ex
        ex isa TLS.TLSError || rethrow()
        err = ex::TLS.TLSError
        return _TransportError(_CRYPTO_ERROR_BASE + TLS.alert_code(err), UInt64(0x06), err.message)
    end
    return nothing
end

function _on_frame!(conn::_Connection, space::_PacketSpace, idx::Int, buf::Vector{UInt8}, frame::_AckFrame, now::Int64)::Union{Nothing, _TransportError}
    if idx == _APPLICATION_SPACE
        err = _check_ack_key_phase(conn, Int64(frame.largest))
        err === nothing || return err
    end
    err = _on_ack!(conn, space, idx, buf, frame, now)
    # An acknowledgment may allow a key update that is due.
    idx == _APPLICATION_SPACE && err === nothing && _maybe_update_keys!(conn, now)
    return err
end

function _on_frame!(conn::_Connection, space::_PacketSpace, idx::Int, buf::Vector{UInt8}, frame::_ConnectionCloseFrame, now::Int64)::Nothing
    _enter_draining!(conn, _TransportError(frame.error_code, frame.frame_type, String(buf[frame.reason]), frame.app), now)
    return nothing
end

function _on_frame!(conn::_Connection, space::_PacketSpace, idx::Int, buf::Vector{UInt8}, ::_HandshakeDoneFrame, now::Int64)::Union{Nothing, _TransportError}
    conn.is_server && return _TransportError(_PROTOCOL_VIOLATION, UInt64(0x1e), "client sent HANDSHAKE_DONE")
    conn.handshake_confirmed || _confirm_handshake!(conn, now)
    return nothing
end

function _on_frame!(conn::_Connection, space::_PacketSpace, idx::Int, buf::Vector{UInt8}, ::_NewTokenFrame, now::Int64)::Union{Nothing, _TransportError}
    conn.is_server && return _TransportError(_PROTOCOL_VIOLATION, UInt64(0x07), "client sent NEW_TOKEN")
    return nothing
end

function _on_ack!(conn::_Connection, space::_PacketSpace, idx::Int, buf::Vector{UInt8}, frame::_AckFrame, now::Int64)::Union{Nothing, _TransportError}
    largest = Int64(frame.largest)
    largest < space.next_pn || return _TransportError(_PROTOCOL_VIOLATION, UInt64(0x02), "ACK for a packet never sent")
    # Any acknowledgment beyond the Initial space shows the server validated
    # this client's address, even one acknowledging nothing new.
    idx != _INITIAL_SPACE && (conn.peer_validated_address = true)
    ranges = UnitRange{UInt64}[]
    for r in _ack_ranges(buf, frame)
        push!(ranges, r)
    end
    # The frame lists ranges from the largest down, and `space.sent` is in
    # packet number order, so one pass over both finds the acknowledged ones.
    reverse!(ranges)
    newly_acked = _SentPacket[]
    kept = 0
    j = 1
    for p in space.sent
        while j <= length(ranges) && Int64(last(ranges[j])) < p.pn
            j += 1
        end
        if j <= length(ranges) && Int64(first(ranges[j])) <= p.pn
            push!(newly_acked, p)
        else
            kept += 1
            space.sent[kept] = p
        end
    end
    resize!(space.sent, kept)
    space.largest_acked = max(space.largest_acked, largest)
    if idx == _APPLICATION_SPACE && conn.pmtu_probe_pn >= 0
        probe = conn.pmtu_probe_pn
        if any(r -> Int64(first(r)) <= probe <= Int64(last(r)), ranges)
            _pmtu_probe_acked!(conn)
        else
            _pmtu_check_probe!(conn, now)
        end
    end
    isempty(newly_acked) && return nothing
    for p in newly_acked
        p.pn == largest || continue
        # Only ack-eliciting packets are tracked, so this one qualifies (RFC 9002 Section 5.1).
        ack_delay = idx == _APPLICATION_SPACE ? _trusted_ack_delay_ns(conn, frame.delay) : Int64(0)
        _update_rtt!(conn, now - p.time_sent, ack_delay)
    end
    # Whether the window was in use is judged once, before this ACK empties it.
    limited = _cwnd_limited(conn)
    for p in newly_acked
        _cc_on_acked!(conn, p, now, limited)
        for f in p.frames
            _on_frame_acked!(conn, space, f)
        end
        # The peer has seen the ACK this packet carried, so need not hear
        # about those packets again (RFC 9000 Section 13.2.4).
        p.ack_largest >= 0 && (space.ack_floor = max(space.ack_floor, p.ack_largest + 1))
    end
    # A client keeps backing off until it knows the server validated its
    # address, which an Initial acknowledgment does not show (RFC 9002 Section 6.2.1).
    _peer_completed_address_validation(conn) && (conn.pto_count = 0)
    # The path delivers again: probes still owed are no longer needed.
    for s in conn.spaces
        s.probes = 0
    end
    _detect_lost_packets!(conn, space, now)
    return nothing
end

# The ACK Delay field in nanoseconds.
function _ack_delay_ns(conn::_Connection, delay::UInt64)::Int64
    params = conn.peer_params
    params === nothing && return Int64(0)
    exponent = Int(params.ack_delay_exponent)
    # Microseconds become nanoseconds below, so keep `delay << exponent` under
    # 2^53, where multiplying by 1000 still fits an Int64.
    delay > (UInt64(typemax(Int64)) >> (exponent + 10)) && return Int64(params.max_ack_delay_ms) * 1_000_000
    return Int64(delay << exponent) * 1_000
end

# The ACK delay an RTT sample is adjusted by. Delays beyond the peer's
# max_ack_delay are not trusted: RFC 9002 Section 5.3 lets them count before
# the handshake is confirmed, but like quic-go this never does, so a peer
# cannot shrink RTT samples by claiming long delays.
function _trusted_ack_delay_ns(conn::_Connection, delay::UInt64)::Int64
    params = conn.peer_params
    params === nothing && return Int64(0)
    return min(_ack_delay_ns(conn, delay), Int64(params.max_ack_delay_ms) * 1_000_000)
end

"RTT estimation (RFC 9002 Section 5.3)."
function _update_rtt!(conn::_Connection, latest::Int64, ack_delay::Int64)::Nothing
    # A sample that is not positive (a coarse or stepped clock) says nothing
    # about the path; as in quic-go, it is ignored rather than pinning min_rtt at 0.
    latest <= 0 && return nothing
    conn.latest_rtt = latest
    if !conn.has_rtt_sample
        conn.has_rtt_sample = true
        conn.min_rtt = latest
        conn.smoothed_rtt = latest
        conn.rttvar = latest ÷ 2
        return nothing
    end
    conn.min_rtt = min(conn.min_rtt, latest)
    adjusted = latest >= conn.min_rtt + ack_delay ? latest - ack_delay : latest
    conn.rttvar = (3 * conn.rttvar + abs(conn.smoothed_rtt - adjusted)) ÷ 4
    conn.smoothed_rtt = (7 * conn.smoothed_rtt + adjusted) ÷ 8
    return nothing
end

"""
Declare packets lost by packet or time threshold (RFC 9002 Section 6.1), and
set the space's loss time for the earliest packet below the largest
acknowledged that is not lost yet (Appendix A.10).
"""
function _detect_lost_packets!(conn::_Connection, space::_PacketSpace, now::Int64)::Nothing
    rtt = conn.has_rtt_sample ? max(conn.smoothed_rtt, conn.latest_rtt) : _INITIAL_RTT_NS
    loss_delay = max(9 * rtt ÷ 8, _GRANULARITY_NS)
    lost_before = now - loss_delay
    space.loss_time = typemax(Int64)
    latest_lost_sent = typemin(Int64)
    kept = 0
    for p in space.sent
        if p.pn < space.largest_acked && (space.largest_acked - p.pn >= _PACKET_THRESHOLD || p.time_sent <= lost_before)
            _requeue_lost!(conn, space, p)
            p.resent || (conn.packets_lost += 1)
            latest_lost_sent = max(latest_lost_sent, p.time_sent)
        else
            p.pn < space.largest_acked && (space.loss_time = min(space.loss_time, p.time_sent + loss_delay))
            kept += 1
            space.sent[kept] = p
        end
    end
    resize!(space.sent, kept)
    latest_lost_sent == typemin(Int64) || _cc_on_congestion!(conn, latest_lost_sent, now)
    return nothing
end

# Takes a lost packet out of flight and queues whatever it carried that still
# needs delivering, unless a probe timeout queued that already.
function _requeue_lost!(conn::_Connection, space::_PacketSpace, p::_SentPacket)::Nothing
    conn.bytes_in_flight -= p.size
    p.resent && return nothing
    for f in p.frames
        _on_frame_lost!(conn, space, f)
    end
    return nothing
end

function _on_frame_acked!(conn::_Connection, space::_PacketSpace, f::_SentFrame)::Nothing
    if f.kind == _SF_CRYPTO
        _crypto_on_acked!(space.crypto_send, _sent_range(f))
    else
        _on_stream_frame_acked!(conn, f)
    end
    return nothing
end

function _on_frame_lost!(conn::_Connection, space::_PacketSpace, f::_SentFrame)::Nothing
    kind = f.kind
    if kind == _SF_CRYPTO
        _crypto_on_lost!(space.crypto_send, _sent_range(f))
    elseif kind == _SF_HANDSHAKE_DONE
        conn.handshake_done_pending = true
    elseif kind == _SF_PING
        # Nothing to resend.
    else
        _on_stream_frame_lost!(conn, f)
    end
    return nothing
end

# Congestion control (RFC 9002 Section 7.3). Growth while the application
# leaves the window unused, and persistent congestion, are not handled yet.

const _CUBIC_BETA = 0.7
const _CUBIC_C = 0.4
# Reno's growth per RTT, in segments, that keeps CUBIC fair to it (RFC 9438 Section 4.3).
const _CUBIC_ALPHA = 3 * (1 - _CUBIC_BETA) / (1 + _CUBIC_BETA)

# Whether the sender is using its window, so that acknowledgments may grow it
# (RFC 9002 Section 7.8): nearly full, or in slow start more than half full.
function _cwnd_limited(conn::_Connection)::Bool
    conn.bytes_in_flight >= conn.cwnd - 3 * conn.max_datagram_size && return true
    return conn.cwnd < conn.ssthresh && conn.bytes_in_flight > conn.cwnd ÷ 2
end

# An acknowledged packet leaves flight and, unless it was sent before the
# current recovery period or the window was not in use, grows the window:
# by its size in slow start, along CUBIC's curve after.
function _cc_on_acked!(conn::_Connection, p::_SentPacket, now::Int64, cwnd_limited::Bool)::Nothing
    conn.bytes_in_flight -= p.size
    p.time_sent <= conn.recovery_start && return nothing
    cwnd_limited || return nothing
    if conn.cwnd < conn.ssthresh
        conn.cwnd += p.size
        return nothing
    end
    _cubic_on_acked!(conn, p.size, now)
    return nothing
end

_cubic_window(conn::_Connection, t::Float64)::Float64 =
    _CUBIC_C * (t - conn.cubic_k)^3 * conn.max_datagram_size + conn.cubic_w_max

# Congestion avoidance (RFC 9438 Section 4): aim for where the cubic curve will
# be an RTT from now, or follow Reno where it would be ahead.
function _cubic_on_acked!(conn::_Connection, acked::Int, now::Int64)::Nothing
    cwnd = Float64(conn.cwnd)
    if conn.cubic_epoch < 0
        conn.cubic_epoch = now
        if conn.cubic_w_max < cwnd
            # No loss yet, or the last maximum is behind: grow from here.
            conn.cubic_w_max = cwnd
            conn.cubic_k = 0.0
        end
        conn.cubic_w_est = cwnd
    end
    t = (now - conn.cubic_epoch) / 1e9
    rtt = (conn.has_rtt_sample ? conn.smoothed_rtt : _INITIAL_RTT_NS) / 1e9
    conn.cubic_w_est += _CUBIC_ALPHA * conn.max_datagram_size * acked / cwnd
    new = if conn.cubic_w_est > _cubic_window(conn, t)
        max(cwnd, conn.cubic_w_est)
    else
        target = clamp(_cubic_window(conn, t + rtt), cwnd, 1.5 * cwnd)
        cwnd + (target - cwnd) * acked / cwnd
    end
    growth = conn.cubic_growth + (new - cwnd)
    whole = floor(Int, growth)
    conn.cubic_growth = growth - whole
    conn.cwnd += whole
    return nothing
end

# A loss of a packet sent at `time_sent` starts a recovery period, unless one
# started after it was sent: the window shrinks by β, and the cubic curve
# restarts from it toward the window before the loss (RFC 9438 Section 4.6),
# or below that window when it had not been regained (Section 4.7).
function _cc_on_congestion!(conn::_Connection, time_sent::Int64, now::Int64)::Nothing
    time_sent <= conn.recovery_start && return nothing
    conn.recovery_start = now
    cwnd = Float64(conn.cwnd)
    conn.cubic_w_max = cwnd < conn.cubic_w_max ? cwnd * (1 + _CUBIC_BETA) / 2 : cwnd
    conn.ssthresh = max(round(Int, cwnd * _CUBIC_BETA), _MINIMUM_WINDOW)
    conn.cwnd = conn.ssthresh
    conn.cubic_k = cbrt(max(0.0, conn.cubic_w_max - conn.cwnd) / conn.max_datagram_size / _CUBIC_C)
    conn.cubic_epoch = Int64(-1)
    conn.cubic_growth = 0.0
    return nothing
end

_cwnd_allows(conn::_Connection)::Bool = conn.bytes_in_flight + conn.max_datagram_size <= conn.cwnd

# Sending.

# ACKs go out regardless of the congestion window; anything ack-eliciting
# waits for room in it, except probes (RFC 9002 Section 7).
function _space_wants_to_send(conn::_Connection, idx::Int, now::Int64, cwnd_ok::Bool)::Bool
    space = conn.spaces[idx]
    (space.discarded || space.write_keys === nothing) && return false
    _ack_due(space, now) && return true
    space.probes > 0 && return true
    cwnd_ok || return false
    _crypto_has_pending(space.crypto_send) && return true
    idx == _APPLICATION_SPACE || return false
    return conn.handshake_done_pending || _app_wants_to_send(conn)
end

function _send_budget(conn::_Connection)::Int
    (!conn.is_server || conn.address_validated) && return typemax(Int)
    return 3 * conn.bytes_received - conn.bytes_sent
end

# A packet built into the datagram, sealed once the datagram is complete.
struct _PendingPacket
    space::Int
    layout::_PacketLayout
    payload_last::Int
    pn::Int64
    ack_eliciting::Bool
    frames::Vector{_SentFrame}
    # The largest packet number its ACK frame acknowledges, or -1.
    ack_largest::Int64
end

_PendingPacket(space::Int, layout::_PacketLayout, payload_last::Int, pn::Int64) =
    _PendingPacket(space, layout, payload_last, pn, false, _SentFrame[], Int64(-1))

function _begin_packet!(conn::_Connection, buf::Vector{UInt8}, idx::Int)::Tuple{_PacketLayout, Int64}
    space = conn.spaces[idx]
    pn = space.next_pn
    pn_len = _packet_number_length(pn, space.largest_acked)
    layout = if idx == _APPLICATION_SPACE
        _begin_short_packet!(buf, conn.peer_cid, pn, pn_len; key_phase = conn.key_phase)
    else
        type = idx == _INITIAL_SPACE ? _PacketType.Initial : _PacketType.Handshake
        _begin_long_packet!(buf, type, _QUIC_V1, conn.peer_cid, conn.local_cid, UInt8[], pn, pn_len)
    end
    return layout, pn
end

# Pads the datagram's last packet so the datagram reaches `target` bytes. The
# bytes after a built packet's payload are its zeroed tag placeholder, so
# appending zeros extends the payload with PADDING frames.
function _pad_last_packet!(buf::Vector{UInt8}, packets::Vector{_PendingPacket}, target::Int)::Nothing
    extra = target - length(buf)
    extra <= 0 && return nothing
    last = packets[end]
    _append_zeros!(buf, extra)
    payload_last = last.payload_last + extra
    if last.layout.length_pos != 0
        len = payload_last + _AEAD_TAG_LEN - last.layout.pn_offset + 1
        _write_varint!(buf, last.layout.length_pos, UInt64(len), _LENGTH_FIELD_LEN)
    end
    packets[end] = _PendingPacket(last.space, last.layout, payload_last, last.pn, last.ack_eliciting, last.frames, last.ack_largest)
    return nothing
end

function _seal_datagram!(conn::_Connection, buf::Vector{UInt8}, packets::Vector{_PendingPacket}, now::Int64)::Vector{UInt8}
    one_rtt = false
    for p in packets
        keys = conn.spaces[p.space].write_keys::_PacketKeys
        _seal_packet!(keys, buf, p.layout.first, p.layout.pn_offset, p.layout.pn_len, p.payload_last, p.pn)
        p.space == _APPLICATION_SPACE && (one_rtt = true)
    end
    if one_rtt
        conn.key_phase_sent += 1
        _maybe_update_keys!(conn, now)
    end
    conn.bytes_sent += length(buf)
    conn.last_send_time = now
    return buf
end

"""
    _next_datagram!(conn, now) -> Vector{UInt8} or nothing

The next datagram to send, or `nothing` when there is nothing to send now.
Call repeatedly until it returns `nothing`.
"""
function _next_datagram!(conn::_Connection, now::Int64)::Union{Nothing, Vector{UInt8}}
    dgram = _build_datagram!(conn, now)
    return dgram === nothing ? nothing : copy(dgram)
end

"""
    _build_datagram!(conn, now) -> Vector{UInt8} or nothing

As `_next_datagram!`, but the datagram may be the connection's own buffer,
which the next call overwrites: send or copy it first.
"""
function _build_datagram!(conn::_Connection, now::Int64)::Union{Nothing, Vector{UInt8}}
    state = conn.state
    (state == _ConnState.Closed || state == _ConnState.Draining) && return nothing
    state == _ConnState.Closing && return _close_datagram!(conn, now)
    _pmtu_probe_ready(conn) && return _build_probe_datagram!(conn, now)
    cwnd_ok = _cwnd_allows(conn)
    wants = (
        _space_wants_to_send(conn, 1, now, cwnd_ok),
        _space_wants_to_send(conn, 2, now, cwnd_ok),
        _space_wants_to_send(conn, 3, now, cwnd_ok),
    )
    any(wants) || return nothing
    max_size = min(conn.max_datagram_size, _send_budget(conn))
    # Clients pad every datagram with an Initial packet, and servers those with
    # an ack-eliciting one, to 1200 bytes (RFC 9000 Section 14.1).
    initial = conn.spaces[_INITIAL_SPACE]
    may_pad = wants[_INITIAL_SPACE] &&
        (!conn.is_server || _crypto_has_pending(initial.crypto_send) || initial.probes > 0)
    may_pad && max_size < _MAX_DATAGRAM_SIZE && return nothing
    max_size <= 0 && return nothing
    buf = empty!(conn.tx_buf)
    packets = _PendingPacket[]
    padded = false
    path_padded = false
    for idx in 1:3
        wants[idx] || continue
        space = conn.spaces[idx]
        layout, pn = _begin_packet!(conn, buf, idx)
        payload_first = layout.pn_offset + layout.pn_len
        if max_size - length(buf) - _AEAD_TAG_LEN < 4
            resize!(buf, layout.first - 1)
            break
        end
        frames = _SentFrame[]
        ack_largest = Int64(-1)
        if space.ack_pending && !isempty(space.received)
            ack = UInt8[]
            _append_ack_frame!(ack, _descending_ranges(space.received), _local_ack_delay(conn, space, idx, now))
            if length(ack) <= max_size - length(buf) - _AEAD_TAG_LEN
                append!(buf, ack)
                space.ack_pending = false
                space.ack_eliciting_received = 0
                space.ack_deadline = typemax(Int64)
                ack_largest = last(space.received.ranges[end])
                space.last_ack_largest = ack_largest
            end
        end
        # Probes may exceed the congestion window.
        if cwnd_ok || space.probes > 0
            if idx == _APPLICATION_SPACE && conn.handshake_done_pending && max_size - length(buf) - _AEAD_TAG_LEN >= 1
                _append_handshake_done_frame!(buf)
                conn.handshake_done_pending = false
                push!(frames, _SentFrame(_SF_HANDSHAKE_DONE))
            end
            while _crypto_has_pending(space.crypto_send)
                offset = first(first(space.crypto_send.pending.ranges))
                # Frame type, offset, and a length of up to two bytes.
                room = max_size - length(buf) - _AEAD_TAG_LEN - 1 - _varint_length(UInt64(offset)) - 2
                room <= 0 && break
                chunk = _crypto_next_chunk!(space.crypto_send, min(room, 16383))::UnitRange{Int64}
                _append_crypto_frame!(buf, UInt64(first(chunk)), _crypto_bytes(space.crypto_send, chunk))
                push!(frames, _SentFrame(_SF_CRYPTO, UInt64(0), first(chunk), length(chunk), false))
            end
            idx == _APPLICATION_SPACE && _append_app_frames!(conn, buf, max_size, frames)
        end
        if space.probes > 0
            if isempty(frames) && max_size - length(buf) - _AEAD_TAG_LEN >= 1
                _append_ping_frame!(buf)
                push!(frames, _SentFrame(_SF_PING))
            end
            space.probes -= 1
        end
        if length(buf) < payload_first
            resize!(buf, layout.first - 1)  # nothing fit
            continue
        end
        ack_eliciting = !isempty(frames)
        payload_last = _end_packet!(buf, layout)
        push!(packets, _PendingPacket(idx, layout, payload_last, pn, ack_eliciting, frames, ack_largest))
        space.next_pn += 1
        idx == _APPLICATION_SPACE && conn.key_phase_first_sent < 0 && (conn.key_phase_first_sent = pn)
        ack_eliciting && idx == _INITIAL_SPACE && (padded = true)
        idx == _INITIAL_SPACE && !conn.is_server && (padded = true)
        # Datagrams with a PATH_RESPONSE are padded to 1200 bytes too, as far
        # as the anti-amplification limit allows (RFC 9000 Section 8.2.2).
        idx == _APPLICATION_SPACE && any(f -> f.kind == _SF_PATH_RESPONSE, frames) && (path_padded = true)
    end
    isempty(packets) && return nothing
    padded && _pad_last_packet!(buf, packets, _MAX_DATAGRAM_SIZE)
    path_padded && _pad_last_packet!(buf, packets, min(_MAX_DATAGRAM_SIZE, max_size))
    _seal_datagram!(conn, buf, packets, now)
    for (i, p) in enumerate(packets)
        p.ack_eliciting || continue
        size = (i < length(packets) ? packets[i + 1].layout.first : length(buf) + 1) - p.layout.first
        space = conn.spaces[p.space]
        push!(space.sent, _SentPacket(p.pn, now, size, p.frames, p.ack_largest, false))
        space.time_of_last_ack_eliciting = now
        conn.bytes_in_flight += size
    end
    # A client drops its Initial keys once it sends a Handshake packet (RFC 9001 Section 4.9.1).
    if !conn.is_server && any(p -> p.space == _HANDSHAKE_SPACE, packets)
        _drop_encryption_level!(conn, _INITIAL_SPACE, now)
    end
    return buf
end

# The ACK Delay field (RFC 9000 Section 19.3): how long the largest packet
# waited, in units of 2^ack_delay_exponent microseconds; 0 outside 1-RTT.
function _local_ack_delay(conn::_Connection, space::_PacketSpace, idx::Int, now::Int64)::UInt64
    idx == _APPLICATION_SPACE || return UInt64(0)
    waited = max(now - space.largest_received_time, Int64(0))
    return UInt64(waited ÷ 1_000) >> Int(conn.local_params.ack_delay_exponent)
end

# One CONNECTION_CLOSE in each packet number space the peer may be reading.
function _close_datagram!(conn::_Connection, now::Int64)::Union{Nothing, Vector{UInt8}}
    conn.close_pending || return nothing
    err = conn.error::_TransportError
    reason = Vector{UInt8}(codeunits(err.reason))
    length(reason) > 256 && resize!(reason, 256)
    buf = UInt8[]
    packets = _PendingPacket[]
    has_initial = false
    for idx in 1:3
        space = conn.spaces[idx]
        (space.discarded || space.write_keys === nothing) && continue
        layout, pn = _begin_packet!(conn, buf, idx)
        if err.app && idx != _APPLICATION_SPACE
            # An application's code and reason stay private until 1-RTT
            # (RFC 9000 Section 10.2.3).
            _append_connection_close_frame!(buf, _APPLICATION_ERROR, UInt64(0), UInt8[])
        else
            _append_connection_close_frame!(buf, err.code, err.frame_type, reason; app = err.app)
        end
        push!(packets, _PendingPacket(idx, layout, _end_packet!(buf, layout), pn))
        space.next_pn += 1
        idx == _INITIAL_SPACE && (has_initial = true)
    end
    isempty(packets) && return nothing
    has_initial && !conn.is_server && _pad_last_packet!(buf, packets, _MAX_DATAGRAM_SIZE)
    if length(buf) > _send_budget(conn)
        # Over the anti-amplification limit: try again once the peer sends
        # more, without using up packet numbers.
        for p in packets
            conn.spaces[p.space].next_pn -= 1
        end
        return nothing
    end
    conn.close_pending = false
    return _seal_datagram!(conn, buf, packets, now)
end

# Timers.

"""
Probe timeout for a packet number space (RFC 9002 Section 6.2.1), with backoff
that stops at 60 s (`_MAX_PTO_NS`), as in quic-go.
"""
function _pto_duration(conn::_Connection, idx::Int)::Int64
    srtt = conn.has_rtt_sample ? conn.smoothed_rtt : _INITIAL_RTT_NS
    rttvar = conn.has_rtt_sample ? conn.rttvar : _INITIAL_RTT_NS ÷ 2
    duration = srtt + max(4 * rttvar, _GRANULARITY_NS)
    params = conn.peer_params
    idx == _APPLICATION_SPACE && params !== nothing && (duration += Int64(params.max_ack_delay_ms) * 1_000_000)
    # Shifting no further than the cap allows also keeps this from overflowing.
    cap = max(duration, _MAX_PTO_NS)
    shift = min(conn.pto_count, 62)
    return duration > (cap >> shift) ? cap : duration << shift
end

# The earliest probe timeout and its space, or nothing.
function _pto_deadline(conn::_Connection)::Union{Nothing, Tuple{Int64, Int}}
    # A server that may not send must not arm the timer; a datagram from the
    # client re-arms it (RFC 9002 Section 6.2.2.1).
    conn.is_server && _send_budget(conn) <= 0 && return nothing
    best = nothing
    for idx in 1:3
        space = conn.spaces[idx]
        (space.discarded || isempty(space.sent)) && continue
        # Application data probes wait for handshake confirmation (RFC 9002 Section 6.2.1).
        idx == _APPLICATION_SPACE && !conn.handshake_confirmed && continue
        t = space.time_of_last_ack_eliciting + _pto_duration(conn, idx)
        (best === nothing || t < best[1]) && (best = (t, idx))
    end
    # A client with nothing in flight still probes until it knows the server
    # validated its address, in case the server is blocked by its
    # amplification limit (RFC 9002 Section 6.2.2.1).
    if best === nothing && !_peer_completed_address_validation(conn)
        idx = conn.spaces[_HANDSHAKE_SPACE].write_keys !== nothing && !conn.spaces[_HANDSHAKE_SPACE].discarded ?
            _HANDSHAKE_SPACE : _INITIAL_SPACE
        conn.spaces[idx].discarded || (best = (conn.last_send_time + _pto_duration(conn, idx), idx))
    end
    return best
end

# The earliest time-threshold loss time and its space, or nothing.
function _loss_time_deadline(conn::_Connection)::Union{Nothing, Tuple{Int64, Int}}
    best = nothing
    for idx in 1:3
        space = conn.spaces[idx]
        (space.discarded || space.loss_time == typemax(Int64)) && continue
        (best === nothing || space.loss_time < best[1]) && (best = (space.loss_time, idx))
    end
    return best
end

# The idle timeout is the smaller of the two nonzero values (RFC 9000 Section
# 10.1). The peer's can be up to 2^62 - 1 ms, which overflows in nanoseconds;
# anything above the local value cannot lower it.
function _negotiated_idle_timeout_ns(local_ns::Int64, peer_ms::UInt64)::Int64
    (peer_ms == 0 || peer_ms >= UInt64(local_ns ÷ 1_000_000) + 1) && return local_ns
    return min(local_ns, Int64(peer_ms) * 1_000_000)
end

# When inactivity ends the connection: until the handshake completes, after
# the handshake idle timeout, or at twice that from its creation, as in
# quic-go; afterwards after the idle timeout.
function _idle_deadline(conn::_Connection)::Int64
    conn.handshake_complete && return conn.last_activity + conn.idle_timeout_ns
    return min(conn.last_activity + conn.handshake_idle_timeout_ns, conn.created + 2 * conn.handshake_idle_timeout_ns)
end

"""
    _next_timeout(conn) -> Int64 or nothing

When `_handle_timeout!` should next run, or `nothing` once closed.
"""
function _next_timeout(conn::_Connection)::Union{Nothing, Int64}
    state = conn.state
    state == _ConnState.Closed && return nothing
    (state == _ConnState.Closing || state == _ConnState.Draining) && return conn.close_deadline
    t = _idle_deadline(conn)
    # A pending loss time stands in for the probe timeout (RFC 9002 Appendix A.8).
    loss = _loss_time_deadline(conn)
    recovery = loss === nothing ? _pto_deadline(conn) : loss
    recovery === nothing || (t = min(t, recovery[1]))
    for space in conn.spaces
        space.ack_pending && !space.discarded && (t = min(t, space.ack_deadline))
    end
    conn.pmtu_probe_pn >= 0 && (t = min(t, _pmtu_probe_deadline(conn)))
    return t
end

"""
    _handle_timeout!(conn, now)

Act on whichever timers have expired: closing or draining ends, the idle
timeout closes the connection silently, a loss time declares packets lost,
and a probe timeout sends probes. A due ACK needs nothing here;
`_next_datagram!` sends it.
"""
function _handle_timeout!(conn::_Connection, now::Int64)::Nothing
    state = conn.state
    state == _ConnState.Closed && return nothing
    if state == _ConnState.Closing || state == _ConnState.Draining
        now >= conn.close_deadline && (conn.state = _ConnState.Closed)
        return nothing
    end
    if now >= _idle_deadline(conn)
        conn.state = _ConnState.Closed
        return nothing
    end
    _pmtu_check_probe!(conn, now)
    loss = _loss_time_deadline(conn)
    if loss !== nothing
        now >= loss[1] && _detect_lost_packets!(conn, conn.spaces[loss[2]], now)
        return nothing
    end
    pto = _pto_deadline(conn)
    if pto !== nothing && now >= pto[1]
        idx = pto[2]
        space = conn.spaces[idx]
        conn.pto_count += 1
        conn.pto_count >= _PMTU_BLACK_HOLE_PTOS && conn.max_datagram_size > _MAX_DATAGRAM_SIZE && _pmtu_black_hole!(conn)
        # Probes carry the oldest unacknowledged data again: all of it during
        # the handshake, and up to two packets' worth in 1-RTT (RFC 9002
        # Section 6.2.4). A timeout is not a loss (Section 6.2), so those
        # packets stay in flight, and an ACK for them still counts.
        n = idx == _APPLICATION_SPACE ? 2 : typemax(Int)
        for i in eachindex(space.sent)
            n == 0 && break
            p = space.sent[i]
            p.resent && continue
            for f in p.frames
                _on_frame_lost!(conn, space, f)
            end
            space.sent[i] = _SentPacket(p.pn, p.time_sent, p.size, p.frames, p.ack_largest, true)
            n -= 1
        end
        # Two probes, as quic-go sends; one when nothing is in flight, where
        # the probe only unblocks a server at its amplification limit.
        space.probes = isempty(space.sent) ? 1 : 2
    end
    return nothing
end
