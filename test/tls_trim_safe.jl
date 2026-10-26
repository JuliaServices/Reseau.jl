using Reseau

const TL = Reseau.TLS
const NC = Reseau.TCP
const IP = Reseau.IOPoll

const _TLS_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")
const _TLS_NATIVE_CA_PATH = joinpath(@__DIR__, "resources", "native_tls_ca.crt")
const _TLS_NATIVE_SERVER_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server.crt")
const _TLS_NATIVE_SERVER_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_server.key")
const _TLS_NATIVE_CLIENT_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_client.crt")
const _TLS_NATIVE_CLIENT_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_client.key")
const _TLS_NATIVE_ECDSA_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server_ecdsa.crt")
const _TLS_NATIVE_ECDSA_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_server_ecdsa.key")
const _TLS_MIXED_SERVER_CONFIG = TL.Config(
    verify_peer = false,
    cert_file = _TLS_CERT_PATH,
    key_file = _TLS_KEY_PATH,
    handshake_timeout_ns = 10_000_000_000,
    min_version = TL.TLS1_2_VERSION,
)
const _TLS_EXACT_TLS12_SERVER_CONFIG = TL.Config(
    verify_peer = false,
    cert_file = _TLS_CERT_PATH,
    key_file = _TLS_KEY_PATH,
    handshake_timeout_ns = 10_000_000_000,
    min_version = TL.TLS1_2_VERSION,
    max_version = TL.TLS1_2_VERSION,
)
const _TLS_SERVER_LISTENER = Ref{Union{Nothing, TL.Listener}}(nothing)

struct _TLSRoundtripStates
    client_state::TL.ConnectionState
    server_state::TL.ConnectionState
end

function _close_quiet!(x)
    x === nothing && return nothing
    try
        close(x)
    catch
    end
    return nothing
end

function _tls_server_config(;
    cert_file::String = _TLS_CERT_PATH,
    key_file::String = _TLS_KEY_PATH,
    client_auth::TL.ClientAuthMode.T = TL.ClientAuthMode.NoClientCert,
    client_ca_file::Union{Nothing, String} = nothing,
    min_version::UInt16 = TL.TLS1_2_VERSION,
    max_version::Union{Nothing, UInt16} = nothing,
    curve_preferences::Vector{UInt16} = UInt16[],
)::TL.Config
    return TL.Config(
        verify_peer = false,
        cert_file = cert_file,
        key_file = key_file,
        client_auth = client_auth,
        client_ca_file = client_ca_file,
        handshake_timeout_ns = 10_000_000_000,
        min_version = min_version,
        max_version = max_version,
        curve_preferences = copy(curve_preferences),
    )
end

function _tls_client_config(;
    ca_file::String = _TLS_CERT_PATH,
    cert_file::Union{Nothing, String} = nothing,
    key_file::Union{Nothing, String} = nothing,
    verify_hostname::Bool = true,
    max_version::Union{Nothing, UInt16} = nothing,
    curve_preferences::Vector{UInt16} = UInt16[],
)::TL.Config
    return TL.Config(
        server_name = "localhost",
        verify_peer = true,
        verify_hostname = verify_hostname,
        ca_file = ca_file,
        cert_file = cert_file,
        key_file = key_file,
        handshake_timeout_ns = 10_000_000_000,
        min_version = TL.TLS1_2_VERSION,
        max_version = max_version,
        curve_preferences = copy(curve_preferences),
    )
end

function _tls_server_task_entry()::TL.ConnectionState
    listener = _TLS_SERVER_LISTENER[]::TL.Listener
    conn = TL.accept(listener)
    try
        TL.handshake!(conn)
        state = TL.connection_state(conn)
        write(conn, UInt8[0x11])
        read(conn, 1) == UInt8[0x21] || error("unexpected TLS trim client ack")
        return state
    finally
        _close_quiet!(conn)
    end
end

Base.Experimental.entrypoint(_tls_server_task_entry, ())

# After the handshake, sends an application-data record that cannot
# authenticate, then drains the raw socket until the client closes.
function _tls_forged_record_server_entry()::Nothing
    listener = _TLS_SERVER_LISTENER[]::TL.Listener
    conn = TL.accept(listener)
    try
        TL.handshake!(conn)
        record = fill(0x42, 37)
        record[1] = 0x17
        record[2] = 0x03
        record[3] = 0x03
        record[4] = 0x00
        record[5] = 0x20
        write(conn.tcp, record)
        buf = Vector{UInt8}(undef, 64)
        while true
            n = try
                readbytes!(conn.tcp, buf; all = false)
            catch
                0
            end
            n == 0 && break
        end
    finally
        _close_quiet!(conn)
    end
    return nothing
end

Base.Experimental.entrypoint(_tls_forged_record_server_entry, ())

# A failed read must throw `TLSError` in the trimmed executable too, however
# precisely inference knows the error the read caught.
function _run_tls_forged_record_trim!()::Nothing
    listener::Union{Nothing, TL.Listener} = nothing
    client::Union{Nothing, TL.Conn} = nothing
    try
        listener = TL.listen(NC.loopback_addr(0), _TLS_MIXED_SERVER_CONFIG; backlog = 8)
        _TLS_SERVER_LISTENER[] = listener
        laddr = TL.addr(listener)::NC.SocketAddrV4
        server_task = Task(_tls_forged_record_server_entry)
        schedule(server_task)
        client = TL.connect(NC.loopback_addr(Int(laddr.port)), _tls_client_config())
        failed = false
        try
            readbytes!(client, Vector{UInt8}(undef, 16); all = false)
        catch err
            err isa TL.TLSError || rethrow()
            failed = true
        end
        failed || error("expected a TLS read error for a forged record")
        _close_quiet!(client)
        client = nothing
        wait(server_task)
    finally
        _TLS_SERVER_LISTENER[] = nothing
        _close_quiet!(client)
        _close_quiet!(listener)
    end
    return nothing
end

function _tls_expect_state(
    state::TL.ConnectionState,
    expected_version::String,
    expect_native_tls13::Bool,
    expect_resume::Union{Nothing, Bool} = nothing,
    expect_resumable::Union{Nothing, Bool} = nothing,
    expected_curve::Union{Nothing, String} = nothing,
)::Nothing
    state.handshake_complete || error("handshake incomplete")
    state.version == expected_version || error("unexpected TLS version")
    state.using_native_tls13 == expect_native_tls13 || error("unexpected native TLS mode")
    expect_resume === nothing || state.did_resume == expect_resume || error("unexpected TLS resumed state")
    expect_resumable === nothing || state.has_resumable_session == expect_resumable || error("unexpected TLS resumable-session state")
    if expect_native_tls13
        state.cipher_suite in (
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ) || error("unexpected TLS 1.3 cipher suite")
        if expected_curve === nothing
            state.curve in ("X25519", "P-256") || error("unexpected TLS 1.3 curve")
        else
            state.curve == expected_curve || error("unexpected TLS curve")
        end
    else
        state.cipher_suite in (
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        ) || error("unexpected TLS 1.2 cipher suite")
        if expected_curve === nothing
            state.curve in ("X25519", "P-256") || error("unexpected TLS 1.2 curve")
        else
            state.curve == expected_curve || error("unexpected TLS curve")
        end
    end
    return nothing
end

function _run_tls_roundtrip_states!(
    server_config::TL.Config,
    client_config::TL.Config,
)::_TLSRoundtripStates
    listener::Union{Nothing, TL.Listener} = nothing
    client::Union{Nothing, TL.Conn} = nothing
    server_task::Union{Nothing, Task} = nothing
    try
        listener = TL.listen(NC.loopback_addr(0), server_config; backlog = 8)
        _TLS_SERVER_LISTENER[] = listener
        laddr = TL.addr(listener)::NC.SocketAddrV4
        server_task = Task(_tls_server_task_entry)
        schedule(server_task)
        client = TL.connect(NC.loopback_addr(Int(laddr.port)), client_config)
        read(client, 1) == UInt8[0x11] || error("expected TLS server byte")
        TL.tryread!(client, Vector{UInt8}(undef, 1)) === nothing || error("expected no pending TLS input before the ack")
        write(client, UInt8[0x21]) == 1 || error("expected TLS client ack write")
        eof(client) || error("expected TLS EOF")
        TL.tryread!(client, Vector{UInt8}(undef, 1)) === 0 || error("expected tryread! to report TLS EOF")
        client_state = TL.connection_state(client)
        wait(server_task::Task)
        return _TLSRoundtripStates(client_state, fetch(server_task::Task)::TL.ConnectionState)
    finally
        _TLS_SERVER_LISTENER[] = nothing
        _close_quiet!(client)
        _close_quiet!(listener)
    end
end

function _run_tls_roundtrip!(
    server_config::TL.Config,
    client_config::TL.Config,
    expected_version::String,
    expect_native_tls13::Bool,
    expect_client_resume::Union{Nothing, Bool} = nothing,
    expect_client_resumable::Union{Nothing, Bool} = nothing,
    expect_server_resume::Union{Nothing, Bool} = nothing,
    expected_curve::Union{Nothing, String} = nothing,
)::Nothing
    roundtrip_states = _run_tls_roundtrip_states!(server_config, client_config)
    _tls_expect_state(roundtrip_states.client_state, expected_version, expect_native_tls13, expect_client_resume, expect_client_resumable, expected_curve)
    _tls_expect_state(roundtrip_states.server_state, expected_version, expect_native_tls13, expect_server_resume, false, expected_curve)
    return nothing
end

function _run_combined_ca_trim!(version::UInt16)::Nothing
    root = joinpath(@__DIR__, "resources", "combined_ca")
    key = joinpath(root, "leaf.key")
    ca_file = joinpath(root, "ca_a.crt")
    ca_dir = joinpath(root, "ca_b")
    server_config = TL.Config(
        cert_file=joinpath(root, "leaf_b.crt"), key_file=key, verify_peer=false,
        client_auth=TL.ClientAuthMode.RequireAndVerifyClientCert,
        client_ca_file=ca_file, client_ca_dir=ca_dir,
        min_version=version, max_version=version,
        handshake_timeout_ns=10_000_000_000, _verification_time_s=Int64(1790121600),
    )
    client_config = TL.Config(
        server_name="localhost", cert_file=joinpath(root, "leaf_a.crt"), key_file=key,
        ca_file=ca_file, ca_dir=ca_dir, min_version=version, max_version=version,
        handshake_timeout_ns=10_000_000_000, _verification_time_s=Int64(1790121600),
    )
    states = _run_tls_roundtrip_states!(TL.Config(server_config), TL.Config(client_config))
    states.client_state.handshake_complete || error("combined CA client handshake failed")
    states.server_state.handshake_complete || error("combined CA server handshake failed")
    return nothing
end

function _run_distrusted_ca_trim!()::Nothing
    fixtures = joinpath(@__DIR__, "resources", "emudhra")
    certs = TL._tls_decode_pem_certificates(TL._read_tls_file_bytes(
        joinpath(fixtures, "dv-g3b-aaa-emudhra.we-have-a-problem.com.pem"),
    ))
    rejected = false
    try
        TL._tls13_verify_server_certificate_chain(
            certs, "dv-g3b-aaa-emudhra.we-have-a-problem.com";
            verify_peer = true, verify_hostname = true,
            ca_file = joinpath(fixtures, "roots.pem"),
            verification_time_s = Int64(1792497600),
        )
    catch err
        err isa TL._TLSAlertError || rethrow()
        rejected = true
    end
    rejected || error("compromised CA accepted in trim executable")
    return nothing
end

function run_tls_trim_sample()::Nothing
    _run_distrusted_ca_trim!()
    _run_tls_forged_record_trim!()
    _run_combined_ca_trim!(TL.TLS1_2_VERSION)
    _run_combined_ca_trim!(TL.TLS1_3_VERSION)
    _run_tls_roundtrip!(_TLS_MIXED_SERVER_CONFIG, _tls_client_config(), "TLSv1.3", true)
    _run_tls_roundtrip!(_TLS_EXACT_TLS12_SERVER_CONFIG, _tls_client_config(), "TLSv1.2", false)
    _run_tls_roundtrip!(_TLS_MIXED_SERVER_CONFIG, _tls_client_config(max_version = TL.TLS1_2_VERSION), "TLSv1.2", false)
    _run_tls_roundtrip!(
        _tls_server_config(
            max_version = TL.TLS1_2_VERSION,
            curve_preferences = UInt16[TL.X25519],
        ),
        _tls_client_config(
            max_version = TL.TLS1_2_VERSION,
            curve_preferences = UInt16[TL.X25519],
        ),
        "TLSv1.2",
        false,
        nothing,
        nothing,
        nothing,
        "X25519",
    )
    _run_tls_roundtrip!(
        _tls_server_config(
            max_version = TL.TLS1_2_VERSION,
            curve_preferences = UInt16[TL.X25519],
        ),
        _tls_client_config(
            curve_preferences = UInt16[TL.X25519],
        ),
        "TLSv1.2",
        false,
        nothing,
        nothing,
        nothing,
        "X25519",
    )
    tls12_mtls_server = _tls_server_config(
        cert_file = _TLS_NATIVE_SERVER_CERT_PATH,
        key_file = _TLS_NATIVE_SERVER_KEY_PATH,
        client_auth = TL.ClientAuthMode.RequireAndVerifyClientCert,
        client_ca_file = _TLS_NATIVE_CA_PATH,
        max_version = TL.TLS1_2_VERSION,
    )
    tls12_mtls_client = _tls_client_config(
        ca_file = _TLS_NATIVE_CA_PATH,
        cert_file = _TLS_NATIVE_CLIENT_CERT_PATH,
        key_file = _TLS_NATIVE_CLIENT_KEY_PATH,
        max_version = TL.TLS1_2_VERSION,
    )
    _run_tls_roundtrip!(tls12_mtls_server, tls12_mtls_client, "TLSv1.2", false, false, true, false)
    _run_tls_roundtrip!(tls12_mtls_server, tls12_mtls_client, "TLSv1.2", false, true, true, true)
    _run_tls_roundtrip!(
        _tls_server_config(
            cert_file = _TLS_NATIVE_ECDSA_CERT_PATH,
            key_file = _TLS_NATIVE_ECDSA_KEY_PATH,
            max_version = TL.TLS1_2_VERSION,
        ),
        _tls_client_config(
            ca_file = _TLS_NATIVE_ECDSA_CERT_PATH,
            verify_hostname = false,
            max_version = TL.TLS1_2_VERSION,
        ),
        "TLSv1.2",
        false,
    )
    return nothing
end

# Pumps events between two QUICConns until both handshakes finish, so the
# handshake task, turn handoff, and post-handshake ticket path are compiled.
function _run_quic_handshake_trim!(client::TL.QUICConn, server::TL.QUICConn)::Nothing
    TL.set_transport_parameters!(client, UInt8[0x01])
    TL.set_transport_parameters!(server, UInt8[0x02])
    TL.start!(client)
    TL.start!(server)
    a, b = client, server
    idle = 0
    done = 0
    while idle < 2
        event = TL.next_event!(a)
        if event.kind == TL.QUICEventKind.NoEvent
            idle += 1
            a, b = b, a
            continue
        end
        idle = 0
        if event.kind == TL.QUICEventKind.WriteData
            TL.handle_data!(b, event.level, event.data)
        elseif event.kind == TL.QUICEventKind.HandshakeDone
            done += 1
            a === server && TL.send_session_ticket!(server)
        elseif event.kind == TL.QUICEventKind.Error
            throw(event.err::TL.TLSError)
        end
    end
    done == 2 || error("QUIC trim handshake did not complete")
    return nothing
end

function _run_quic_trim!()::Nothing
    client_config = TL.Config(verify_peer = false, server_name = "localhost", alpn_protocols = ["h3"])
    server_config = TL.Config(verify_peer = false, cert_file = _TLS_CERT_PATH, key_file = _TLS_KEY_PATH, alpn_protocols = ["h3"])
    for resumed in (false, true)
        client = TL.quic_client(client_config)
        server = TL.quic_server(server_config)
        try
            _run_quic_handshake_trim!(client, server)
            state = TL.connection_state(client)
            state.alpn_protocol == "h3" || error("unexpected QUIC trim ALPN")
            state.did_resume == resumed || error("unexpected QUIC trim resumption state")
        finally
            close(client)
            close(server)
        end
    end
    return nothing
end

function _quic_trim_seal!(keys, buf::Vector{UInt8}, layout, payload::Vector{UInt8})::Nothing
    append!(buf, payload)
    payload_last = Reseau.QUIC._end_packet!(buf, layout)
    Reseau.QUIC._seal_packet!(keys, buf, layout.first, layout.pn_offset, layout.pn_len, payload_last, Int64(2))
    return nothing
end

# Builds a datagram of an Initial and a 1-RTT packet, seals both, then parses
# the datagram back and opens each packet.
function _quic_trim_datagram!(initial_keys, onertt_keys)::Nothing
    QP = Reseau.QUIC
    dcid = UInt8[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
    payload = fill(0x01, 24)
    buf = UInt8[]
    layout = QP._begin_long_packet!(buf, QP._PacketType.Initial, QP._QUIC_V1, dcid, UInt8[0x01], UInt8[0x02], Int64(2), 4)
    _quic_trim_seal!(initial_keys, buf, layout, payload)
    layout = QP._begin_short_packet!(buf, dcid, Int64(2), 2; key_phase = true)
    _quic_trim_seal!(onertt_keys, buf, layout, payload)
    count = 0
    for (keys, header) in zip((initial_keys, onertt_keys), QP._datagram_packets(buf, 1, length(buf), length(dcid)))
        opened = QP._open_packet!(keys, buf, header.first, header.pn_offset, header.last, Int64(1))
        opened === nothing && error("QUIC trim packet failed to open")
        buf[opened[2]:opened[3]] == payload || error("QUIC trim packet payload mismatch")
        count += 1
    end
    count == 2 || error("QUIC trim datagram did not parse into two packets")
    return nothing
end

# Encodes one of every frame type and decodes them back, so the decoder's
# handler call is compiled for each frame struct.
function _quic_trim_frames!()::Nothing
    QP = Reseau.QUIC
    buf = UInt8[]
    data = UInt8[0x01, 0x02, 0x03]
    QP._append_padding!(buf, 2)
    QP._append_ping_frame!(buf)
    QP._append_ack_frame!(buf, [UInt64(9):UInt64(10), UInt64(1):UInt64(5)], UInt64(3))
    QP._append_ack_frame!(buf, [UInt64(4):UInt64(4)], UInt64(0); ecn = (UInt64(1), UInt64(0), UInt64(2)))
    QP._append_reset_stream_frame!(buf, UInt64(0), UInt64(1), UInt64(2))
    QP._append_stop_sending_frame!(buf, UInt64(0), UInt64(1))
    QP._append_crypto_frame!(buf, UInt64(0), data)
    QP._append_new_token_frame!(buf, data)
    QP._append_stream_frame!(buf, UInt64(4), UInt64(7), data; fin = true)
    QP._append_max_data_frame!(buf, UInt64(100))
    QP._append_max_stream_data_frame!(buf, UInt64(4), UInt64(100))
    QP._append_max_streams_frame!(buf, true, UInt64(10))
    QP._append_data_blocked_frame!(buf, UInt64(100))
    QP._append_stream_data_blocked_frame!(buf, UInt64(4), UInt64(100))
    QP._append_streams_blocked_frame!(buf, false, UInt64(10))
    QP._append_new_connection_id_frame!(buf, UInt64(1), UInt64(0), data, zeros(UInt8, 16))
    QP._append_retire_connection_id_frame!(buf, UInt64(0))
    QP._append_path_challenge_frame!(buf, UInt64(7))
    QP._append_path_response_frame!(buf, UInt64(7))
    QP._append_connection_close_frame!(buf, UInt64(0), UInt64(0), data)
    QP._append_handshake_done_frame!(buf)
    QP._append_stream_frame!(buf, UInt64(8), UInt64(0), data; explicit_length = false)
    count = Ref(0)
    acked = Ref(UInt64(0))
    # The handler names `Reseau.QUIC` directly: a captured module variable would
    # make every lookup inside the closure dynamic.
    result = QP._decode_frames(buf, 1, length(buf), QP._PacketType.OneRTT) do frame
        count[] += 1
        if frame isa Reseau.QUIC._AckFrame
            for r in Reseau.QUIC._ack_ranges(buf, frame)
                acked[] += UInt64(length(r))
            end
        end
        return nothing
    end
    result.error === nothing || error("QUIC trim frames failed to decode")
    count[] == 22 || error("QUIC trim decoded the wrong number of frames")
    acked[] == 8 || error("QUIC trim ACK ranges mismatch")
    return nothing
end

# Callable structs rather than closures drive the UDP connections, so nothing
# captured gets boxed.

# Sends `data` on a bidirectional stream and reads back the echo.
mutable struct _QuicTrimEchoClient
    data::Vector{UInt8}
    got::Vector{UInt8}
    id::UInt64
    started::Bool
end

function (c::_QuicTrimEchoClient)(conn::Reseau.QUIC._Connection)::Bool
    QP = Reseau.QUIC
    QP._handshake_complete(conn) || return false
    if !c.started
        c.started = true
        c.id = QP._open_stream!(conn)::UInt64
        QP._stream_write!(conn, c.id, c.data; fin = true)
    end
    r = QP._stream_read!(conn, c.id)
    append!(c.got, r.data)
    return r.fin
end

# Echoes every stream until the peer closes the connection.
struct _QuicTrimEchoServer
    open::Vector{UInt64}
end

function (e::_QuicTrimEchoServer)(conn::Reseau.QUIC._Connection)::Bool
    QP = Reseau.QUIC
    while true
        id = QP._accept_stream!(conn)
        id === nothing && break
        push!(e.open, id)
    end
    for id in copy(e.open)
        r = QP._stream_read!(conn, id)
        QP._stream_write!(conn, id, r.data; fin = r.fin)
        r.fin && filter!(!=(id), e.open)
    end
    return conn.peer_error !== nothing
end

_quic_trim_closed(conn::Reseau.QUIC._Connection)::Bool =
    conn.state == Reseau.QUIC._ConnState.Closed || conn.state == Reseau.QUIC._ConnState.Draining

function _quic_trim_server_entry(config::TL.Config, sock::Reseau.UDP.Conn, deadline::Int64)::Bool
    accepted = Reseau.QUIC._accept_over_udp(config, sock; deadline_ns = deadline)
    accepted === nothing && return false
    conn, peer = accepted
    return Reseau.QUIC._drive_connection!(conn, sock, peer, _QuicTrimEchoServer(UInt64[]); deadline_ns = deadline)
end

# Moves datagrams both ways until neither side sends, then fires timers due
# within 100 ms, until the next is further off. Returns the advanced clock.
function _quic_trim_settle!(client::Reseau.QUIC._Connection, server::Reseau.QUIC._Connection, now::Int64)::Int64
    QP = Reseau.QUIC
    for _ in 1:10_000
        moved = false
        while (d = QP._next_datagram!(client, now)) !== nothing
            QP._receive_datagram!(server, d, now)
            moved = true
        end
        while (d = QP._next_datagram!(server, now)) !== nothing
            QP._receive_datagram!(client, d, now)
            moved = true
        end
        moved && continue
        t = typemax(Int64)
        for conn in (client, server)
            nt = QP._next_timeout(conn)
            nt === nothing || (t = min(t, nt))
        end
        t - now > 100_000_000 && return now
        now = max(now, t)
        for conn in (client, server)
            nt = QP._next_timeout(conn)
            nt !== nothing && nt <= now && QP._handle_timeout!(conn, now)
        end
    end
    error("QUIC trim connections did not settle")
end

# Streams in both directions, STOP_SENDING and RESET_STREAM, a key update,
# and an application close, between in-memory connections.
function _quic_trim_streams!(client::Reseau.QUIC._Connection, server::Reseau.QUIC._Connection, now::Int64)::Nothing
    QP = Reseau.QUIC
    data = rand(UInt8, 50_000)
    bidi = QP._open_stream!(client)::UInt64
    uni = QP._open_stream!(client; bidi = false)::UInt64
    QP._stream_write!(client, bidi, data; fin = true)
    QP._stream_write!(client, uni, data; fin = true)
    now = _quic_trim_settle!(client, server, now)
    QP._accept_stream!(server) == bidi || error("QUIC trim server did not accept the bidirectional stream")
    QP._accept_stream!(server) == uni || error("QUIC trim server did not accept the unidirectional stream")
    for id in (bidi, uni)
        r = QP._stream_read!(server, id)
        (r.data == data && r.fin) || error("QUIC trim server read the wrong data")
    end
    QP._stream_write!(server, bidi, data; fin = true)
    now = _quic_trim_settle!(client, server, now)
    r = QP._stream_read!(client, bidi)
    (r.data == data && r.fin) || error("QUIC trim client read the wrong echo")

    stopped = QP._open_stream!(client)::UInt64
    reset = QP._open_stream!(client)::UInt64
    for id in (stopped, reset)
        QP._stream_write!(client, id, data)
    end
    now = _quic_trim_settle!(client, server, now)
    QP._stream_stop_sending!(server, stopped, UInt64(1))
    QP._stream_reset!(client, reset, UInt64(2))
    now = _quic_trim_settle!(client, server, now)
    QP._stream_stop_code(client, stopped) == 1 || error("QUIC trim STOP_SENDING was not received")
    for (id, code) in ((stopped, UInt64(1)), (reset, UInt64(2)))
        QP._accept_stream!(server)
        r = QP._stream_read!(server, id)
        while !r.fin
            r = QP._stream_read!(server, id)
        end
        r.reset_code == code || error("QUIC trim reset code mismatch")
    end

    QP._initiate_key_update!(client) || error("QUIC trim key update was refused")
    last_id = QP._open_stream!(client)::UInt64
    QP._stream_write!(client, last_id, UInt8[0x2a]; fin = true)
    now = _quic_trim_settle!(client, server, now)
    QP._accept_stream!(server) == last_id || error("QUIC trim stream after the key update was not accepted")
    QP._stream_read!(server, last_id).data == UInt8[0x2a] || error("QUIC trim data after the key update mismatch")
    server.key_updates == 1 || error("QUIC trim server did not follow the key update")

    QP._close_connection!(client, UInt64(0), "done", now)
    now = _quic_trim_settle!(client, server, now)
    err = server.peer_error
    (err !== nothing && err.app) || error("QUIC trim application close was not received")
    return nothing
end

# A QUIC connection in memory, through streams and closing, then an echo over
# loopback UDP.
function _quic_trim_connection!()::Nothing
    QP = Reseau.QUIC
    client_config = TL.Config(verify_peer = false, server_name = "localhost", alpn_protocols = ["h3"])
    server_config = TL.Config(verify_peer = false, cert_file = _TLS_CERT_PATH, key_file = _TLS_KEY_PATH, alpn_protocols = ["h3"])
    now = Int64(time_ns())
    client = QP._client_connection(client_config, now)
    first_dgram = QP._next_datagram!(client, now)::Vector{UInt8}
    header = QP._parse_packet(first_dgram, 1, length(first_dgram), QP._LOCAL_CID_LEN)::QP._PacketHeader
    server = QP._accept_connection(server_config, first_dgram, header, now)::QP._Connection
    QP._receive_datagram!(server, first_dgram, now)
    for _ in 1:50
        moved = false
        while (d = QP._next_datagram!(server, now)) !== nothing
            QP._receive_datagram!(client, d, now)
            moved = true
        end
        while (d = QP._next_datagram!(client, now)) !== nothing
            QP._receive_datagram!(server, d, now)
            moved = true
        end
        moved || break
    end
    (QP._handshake_confirmed(client) && QP._handshake_confirmed(server)) || error("QUIC trim in-memory handshake did not confirm")
    _quic_trim_streams!(client, server, _quic_trim_settle!(client, server, now))

    server_sock = Reseau.UDP.listen(Reseau.UDP.loopback_addr(0))
    client_sock = Reseau.UDP.connect(Reseau.UDP.local_addr(server_sock)::Reseau.UDP.SocketAddrV4)
    try
        deadline = Int64(time_ns()) + 20_000_000_000
        server_task = Threads.@spawn _quic_trim_server_entry(server_config, server_sock, deadline)
        udp_client = QP._client_connection(client_config, Int64(time_ns()))
        echo = _QuicTrimEchoClient(rand(UInt8, 200_000), UInt8[], UInt64(0), false)
        QP._drive_connection!(udp_client, client_sock, nothing, echo; deadline_ns = deadline) ||
            error("QUIC trim UDP echo did not finish")
        echo.got == echo.data || error("QUIC trim UDP echo mismatch")
        QP._close_connection!(udp_client, UInt64(0), "done", Int64(time_ns()))
        QP._drive_connection!(udp_client, client_sock, nothing, _quic_trim_closed; deadline_ns = deadline)
        fetch(server_task)::Bool || error("QUIC trim UDP server did not see the close")
    finally
        close(client_sock)
        close(server_sock)
    end
    return nothing
end

# The public QUIC API: a listener and a connection driven by their receive
# tasks, with streams used as IO from another task.
function _quic_trim_api_server(listener::Reseau.QUIC.Listener)::Int
    QP = Reseau.QUIC
    conn = QP.accept(listener; deadline_ns = Int64(time_ns()) + 20_000_000_000)
    echoed = 0
    try
        s = QP.accept_stream(conn)
        data = read(s)
        write(s, data)
        closewrite(s)
        echoed += length(data)
        u = QP.accept_stream(conn)
        QP.isbidi(u) && error("QUIC trim API expected a unidirectional stream")
        echoed += length(read(u))
        r = QP.accept_stream(conn)
        QP.reset_stream!(r, 0x10c)
        QP.accept_stream(conn)
    catch err
        err isa QP.ConnectionError || rethrow()
    end
    return echoed
end

function _quic_trim_public_api!()::Nothing
    QP = Reseau.QUIC
    server_config = TL.Config(verify_peer = false, cert_file = _TLS_CERT_PATH, key_file = _TLS_KEY_PATH, alpn_protocols = ["h3"])
    listener = QP.listen(Reseau.UDP.loopback_addr(0), server_config; max_streams_bidi = 4)
    try
        server_task = Threads.@spawn _quic_trim_api_server(listener)
        addr = QP.local_addr(listener)::Reseau.UDP.SocketAddrV4
        client_config = TL.Config(verify_peer = false, server_name = "localhost", alpn_protocols = ["h3"])
        conn = QP.connect(addr, client_config; deadline_ns = Int64(time_ns()) + 20_000_000_000)
        QP.alpn_protocol(conn) == "h3" || error("QUIC trim API ALPN mismatch")
        s = QP.open_stream(conn)
        payload = rand(UInt8, 50_000)
        write(s, payload)
        closewrite(s)
        QP.set_read_deadline!(s, Int64(time_ns()) + 20_000_000_000)
        buf = Vector{UInt8}(undef, 1024)
        got = UInt8[]
        while (n = readbytes!(s, buf, length(buf); all = false)) > 0
            append!(got, view(buf, 1:n))
        end
        got == payload || error("QUIC trim API echo mismatch")
        eof(s) || error("QUIC trim API expected the end of the stream")
        u = QP.open_stream(conn; bidi = false)
        write(u, "one way")
        closewrite(u)
        r = QP.open_stream(conn)
        write(r, UInt8[0x01])
        reset_seen = try
            read(r)
            false
        catch err
            err isa QP.StreamResetError || rethrow()
            (err::QP.StreamResetError).code == 0x10c
        end
        reset_seen || error("QUIC trim API expected a reset")
        QP.stop_sending!(r, 0x10c)
        close(conn; code = 0x100, reason = "done")
        fetch(server_task)::Int == length(payload) + 7 || error("QUIC trim API server mismatch")
    finally
        close(listener)
    end
    return nothing
end

# Compiles every packet protection and wire format path: AES-128-GCM Initial
# keys on a long header, ChaCha20-Poly1305 keys after a key update on a short
# header, and building and parsing Retry and Version Negotiation packets.
function _run_quic_packet_protection_trim!()::Nothing
    QP = Reseau.QUIC
    dcid = UInt8[0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08]
    secret = fill(0x11, 32)
    _quic_trim_datagram!(QP._initial_packet_keys(dcid)[1], QP._next_packet_keys(QP._PacketKeys(UInt16(0x1303), secret)))
    retry = QP._retry_packet(QP._QUIC_V1, UInt8[0x01], UInt8[0x02], UInt8[0x03], dcid)
    QP._valid_retry_integrity(dcid, retry) || error("QUIC trim Retry tag mismatch")
    header = QP._parse_packet(retry, 1, length(retry), 0)
    (header !== nothing && header.type == QP._PacketType.Retry) || error("QUIC trim Retry did not parse")
    vn = QP._version_negotiation_packet(UInt8[0x01], UInt8[0x02], UInt32[QP._QUIC_V1])
    header = QP._parse_packet(vn, 1, length(vn), 0)
    header === nothing && error("QUIC trim Version Negotiation did not parse")
    QP._version_negotiation_versions(vn, header) == UInt32[QP._QUIC_V1] || error("QUIC trim Version Negotiation versions mismatch")
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_tls_trim_sample()
    _run_quic_trim!()
    _run_quic_packet_protection_trim!()
    _quic_trim_frames!()
    _quic_trim_connection!()
    _quic_trim_public_api!()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
