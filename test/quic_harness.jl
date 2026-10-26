# In-memory harness for QUIC connection tests: datagrams pass between a client
# and a server `_Connection` under a simulated clock, so loss and reordering
# are deterministic. Included by quic_connection_tests.jl and
# quic_stream_tests.jl.

const QCN = Reseau.QUIC
const TLC = Reseau.TLS

const _QCN_CERT = joinpath(@__DIR__, "resources", "unittests.crt")
const _QCN_KEY = joinpath(@__DIR__, "resources", "unittests.key")
const _QCN_CA = joinpath(@__DIR__, "resources", "native_tls_ca.crt")
const _QCN_START = Int64(1_000_000_000)

_qcn_client_config(; kwargs...) = TLC.Config(; verify_peer = false, server_name = "localhost", alpn_protocols = ["h3"], kwargs...)
_qcn_server_config(; kwargs...) = TLC.Config(; verify_peer = false, cert_file = _QCN_CERT, key_file = _QCN_KEY, alpn_protocols = ["h3"], kwargs...)

# Every datagram sent, for checks on sizes and the amplification limit.
struct _QcnSent
    from_client::Bool
    bytes::Vector{UInt8}
    time::Int64
end

mutable struct _QcnHarness
    client::QCN._Connection
    server::Union{Nothing, QCN._Connection}
    server_config::TLC.Config
    server_limits::QCN._StreamLimits
    now::Int64
    log::Vector{_QcnSent}
    # `drop(from_client, n)` drops the n-th datagram (1-based) in that direction.
    drop::Function
    sent_count::Dict{Bool, Int}
    # Datagrams held back to deliver later, for reordering.
    held::Vector{Tuple{Bool, Vector{UInt8}}}
    hold::Function
    # `duplicate(from_client, n)` delivers the n-th datagram twice.
    duplicate::Function
    # Datagrams longer than this are lost, as on a path with that MTU.
    path_mtu::Int
    server_max_udp_payload::Int
end

function _QcnHarness(;
        client_config = _qcn_client_config(),
        server_config = _qcn_server_config(),
        client_limits = QCN._StreamLimits(),
        server_limits = QCN._StreamLimits(),
        drop = (from_client, n) -> false,
        hold = (from_client, n) -> false,
        duplicate = (from_client, n) -> false,
        path_mtu = typemax(Int),
        server_max_udp_payload = 65527,
    )
    client = QCN._client_connection(client_config, _QCN_START; limits = client_limits)
    return _QcnHarness(client, nothing, server_config, server_limits, _QCN_START, _QcnSent[], drop, Dict(true => 0, false => 0), Tuple{Bool, Vector{UInt8}}[], hold, duplicate, path_mtu, server_max_udp_payload)
end

function _qcn_deliver!(h::_QcnHarness, from_client::Bool, dgram::Vector{UInt8})
    if from_client
        if h.server === nothing
            header = first(QCN._datagram_packets(dgram, 1, length(dgram), QCN._LOCAL_CID_LEN))
            h.server = QCN._accept_connection(h.server_config, dgram, header, h.now; limits = h.server_limits,
                max_udp_payload_size = h.server_max_udp_payload)
            h.server === nothing && return
        end
        QCN._receive_datagram!(h.server, dgram, h.now)
    else
        QCN._receive_datagram!(h.client, dgram, h.now)
    end
    return nothing
end

# Moves datagrams until neither side has anything to send. Returns how many moved.
function _qcn_exchange!(h::_QcnHarness)
    moved = 0
    while true
        progressed = false
        for from_client in (true, false)
            conn = from_client ? h.client : h.server
            conn === nothing && continue
            while (dgram = QCN._next_datagram!(conn, h.now)) !== nothing
                progressed = true
                moved += 1
                push!(h.log, _QcnSent(from_client, copy(dgram), h.now))
                n = (h.sent_count[from_client] += 1)
                h.drop(from_client, n) && continue
                length(dgram) > h.path_mtu && continue
                if h.hold(from_client, n)
                    push!(h.held, (from_client, dgram))
                    continue
                end
                h.duplicate(from_client, n) && _qcn_deliver!(h, from_client, copy(dgram))
                _qcn_deliver!(h, from_client, dgram)
            end
        end
        if !progressed && !isempty(h.held)
            for (from_client, dgram) in h.held
                _qcn_deliver!(h, from_client, dgram)
            end
            empty!(h.held)
            progressed = true
        end
        progressed || return moved
    end
end

function _qcn_next_timeout(h::_QcnHarness)
    times = Int64[]
    for conn in (h.client, h.server)
        conn === nothing && continue
        t = QCN._next_timeout(conn)
        t === nothing || push!(times, t)
    end
    return isempty(times) ? nothing : minimum(times)
end

# Runs the exchange, advancing the clock to the next timer whenever both sides
# go quiet, until `done(h)` or `max_time` passes. `app(h)` runs before every
# exchange, to read and write streams.
function _qcn_run!(h::_QcnHarness;
        app = h -> nothing,
        done = h -> QCN._handshake_confirmed(h.client) && h.server !== nothing && QCN._handshake_confirmed(h.server),
        max_time = h.now + 60_000_000_000)
    while true
        app(h)
        moved = _qcn_exchange!(h)
        done(h) && return true
        moved > 0 && continue  # the application may have more to do
        t = _qcn_next_timeout(h)
        (t === nothing || t > max_time) && return false
        h.now = max(h.now, t)
        for conn in (h.client, h.server)
            conn === nothing && continue
            nt = QCN._next_timeout(conn)
            nt !== nothing && nt <= h.now && QCN._handle_timeout!(conn, h.now)
        end
    end
end

_qcn_sent(h, from_client) = [s for s in h.log if s.from_client == from_client]

_qcn_has_type(dgram::Vector{UInt8}, type) =
    any(hdr -> hdr.type == type, QCN._datagram_packets(dgram, 1, length(dgram), QCN._LOCAL_CID_LEN))
_qcn_has_initial(dgram) = _qcn_has_type(dgram, QCN._PacketType.Initial)

# A copy of `p` with some fields replaced.
function _qcn_with(p::QCN._TransportParameters; kw...)
    fields = Dict{Symbol, Any}(f => getfield(p, f) for f in fieldnames(QCN._TransportParameters))
    merge!(fields, Dict{Symbol, Any}(kw))
    return QCN._TransportParameters(; fields...)
end

# Sends `frames` from one side to the other in a 1-RTT packet, bypassing the
# sender's own checks, to show how the receiver handles a misbehaving peer.
function _qcn_inject!(h::_QcnHarness, from_client::Bool, frames::Vector{UInt8})
    sender = from_client ? h.client : h.server
    space = sender.spaces[QCN._APPLICATION_SPACE]
    buf = UInt8[]
    layout, pn = QCN._begin_packet!(sender, buf, QCN._APPLICATION_SPACE)
    append!(buf, frames)
    payload_last = QCN._end_packet!(buf, layout)
    space.next_pn += 1
    QCN._seal_packet!(space.write_keys, buf, layout.first, layout.pn_offset, layout.pn_len, payload_last, pn)
    QCN._receive_datagram!(from_client ? h.server : h.client, buf, h.now)
    return nothing
end

_qcn_frames(append!, args...) = (buf = UInt8[]; append!(buf, args...); buf)
