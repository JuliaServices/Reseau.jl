using Test
using Reseau

const TLN = Reseau.TLS
const NCN = Reseau.TCP
const IPN = Reseau.IOPoll

const _TLS_NATIVE_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS_NATIVE_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")
const _TLS_NATIVE_MTLS_CA_PATH = joinpath(@__DIR__, "resources", "native_tls_ca.crt")
const _TLS_NATIVE_MTLS_SERVER_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server.crt")
const _TLS_NATIVE_MTLS_SERVER_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_server.key")
const _TLS_NATIVE_MTLS_CLIENT_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_client.crt")
const _TLS_NATIVE_MTLS_CLIENT_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_client.key")

function _tls_native_close_quiet!(x)
    x === nothing && return nothing
    try
        close(x)
    catch
    end
    return nothing
end

function _tls_native_wait_task(task::Task, timeout_s::Float64 = 5.0)
    return IPN.timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
end

function _open_tcp_pair()
    listener = NCN.listen(NCN.loopback_addr(0); backlog = 1)
    addr = NCN.addr(listener)::NCN.SocketAddrV4
    accept_task = errormonitor(Threads.@spawn NCN.accept(listener))
    client = NCN.connect(addr)
    status = _tls_native_wait_task(accept_task, 5.0)
    status == :timed_out && error("timed out waiting for TCP accept")
    server = fetch(accept_task)
    return listener, client, server
end

function _read_tls_record(conn::NCN.Conn)
    header = Vector{UInt8}(undef, 5)
    read!(conn, header)
    payload_len = (Int(header[4]) << 8) | Int(header[5])
    payload = Vector{UInt8}(undef, payload_len)
    payload_len == 0 || read!(conn, payload)
    return header, payload
end

function _tls13_unexpected_message_error(f)
    err = try
        f()
        nothing
    catch ex
        ex
    end
    @test err isa TLN._TLSAlertError
    if err isa TLN._TLSAlertError
        @test err.alert == TLN._TLS_ALERT_UNEXPECTED_MESSAGE
        @test !err.from_peer
    end
    return err
end

function _assert_no_pending_tcp_bytes(conn::NCN.Conn)
    NCN.set_read_deadline!(conn, time_ns() + 50_000_000)
    try
        @test_throws NCN.DeadlineExceededError read!(conn, Vector{UInt8}(undef, 1))
    finally
        NCN.set_read_deadline!(conn, Int64(0))
    end
    return nothing
end

function _tls13_record_state_pair()
    client_state = TLN._TLS13NativeClientState()
    server_state = TLN._TLS13NativeClientState()
    server_to_client_secret = UInt8[UInt8(0x10 + i) for i in 0:31]
    client_to_server_secret = UInt8[UInt8(0x80 + i) for i in 0:31]
    TLN._tls13_set_read_cipher!(client_state, TLN._TLS13_AES_128_GCM_SHA256, server_to_client_secret)
    TLN._tls13_set_write_cipher!(client_state, TLN._TLS13_AES_128_GCM_SHA256, client_to_server_secret)
    TLN._tls13_set_write_cipher!(server_state, TLN._TLS13_AES_128_GCM_SHA256, server_to_client_secret)
    TLN._tls13_set_read_cipher!(server_state, TLN._TLS13_AES_128_GCM_SHA256, client_to_server_secret)
    # These pairs model an established (post-handshake) connection, so the
    # record layer must accept application data.
    client_state.handshake_complete = true
    server_state.handshake_complete = true
    return client_state, server_state, server_to_client_secret, client_to_server_secret
end

# Minimal duck-typed stand-in for TLS.Conn exposing just the fields the
# conn-aware KeyUpdate handler touches, so the write-lock serialization can be
# exercised without a full handshake.
mutable struct _MockKeyUpdateConn
    tcp::Any
    write_lock::ReentrantLock
    write_permanent_error::Any
end

function _tls13_native_client_config(;
    verify_peer::Bool = false,
    verify_hostname::Bool = verify_peer,
    server_name::Union{Nothing, String} = "localhost",
    ca_file::Union{Nothing, String} = nothing,
    alpn_protocols::Vector{String} = String[],
    cert_file::Union{Nothing, String} = nothing,
    key_file::Union{Nothing, String} = nothing,
    session_tickets_disabled::Bool = false,
    curve_preferences::Vector{UInt16} = UInt16[],
)
    return TLN.Config(
        server_name = server_name,
        verify_peer = verify_peer,
        verify_hostname = verify_hostname,
        ca_file = ca_file,
        cert_file = cert_file,
        key_file = key_file,
        alpn_protocols = copy(alpn_protocols),
        curve_preferences = copy(curve_preferences),
        min_version = TLN.TLS1_3_VERSION,
        max_version = TLN.TLS1_3_VERSION,
        handshake_timeout_ns = 10_000_000_000,
        session_tickets_disabled = session_tickets_disabled,
    )
end

function _tls13_native_server_config(;
    alpn_protocols::Vector{String} = String[],
    client_auth::TLN.ClientAuthMode.T = TLN.ClientAuthMode.NoClientCert,
    client_ca_file::Union{Nothing, String} = nothing,
    session_tickets_disabled::Bool = false,
    cert_file::String = _TLS_NATIVE_CERT_PATH,
    key_file::String = _TLS_NATIVE_KEY_PATH,
    curve_preferences::Vector{UInt16} = UInt16[],
)
    return TLN.Config(
        verify_peer = false,
        cert_file = cert_file,
        key_file = key_file,
        client_auth = client_auth,
        client_ca_file = client_ca_file,
        alpn_protocols = copy(alpn_protocols),
        curve_preferences = copy(curve_preferences),
        handshake_timeout_ns = 10_000_000_000,
        min_version = TLN.TLS1_3_VERSION,
        max_version = TLN.TLS1_3_VERSION,
        session_tickets_disabled = session_tickets_disabled,
    )
end

function _start_tls13_native_server(config::TLN.Config; configure = nothing)
    listener = TLN.listen(NCN.loopback_addr(0), config; backlog = 8)
    addr = TLN.addr(listener)::NCN.SocketAddrV4
    server_ref = Ref{Union{Nothing, TLN.Conn}}(nothing)
    task = Threads.@spawn begin
        conn = TLN.accept(listener)
        server_ref[] = conn
        configure === nothing || configure(conn)
        TLN.handshake!(conn)
        return conn
    end
    return listener, addr, task, server_ref
end

function _finish_tls13_native_server!(task::Task)
    status = _tls_native_wait_task(task, 5.0)
    status == :timed_out && error("timed out waiting for TLS native server task")
    try
        wait(task)
    catch
    end
    return nothing
end

# Minimal handshake-message source for driving server-side flight readers
# detached from a wire record layer.
mutable struct _TLS13ServerFlightIO
    inbound::Vector{Vector{UInt8}}
    inbound_pos::Int
end

_TLS13ServerFlightIO(inbound::Vector{Vector{UInt8}}) = _TLS13ServerFlightIO(inbound, 1)

function TLN._read_handshake_bytes!(io::_TLS13ServerFlightIO)::Vector{UInt8}
    io.inbound_pos <= length(io.inbound) || throw(EOFError())
    raw = io.inbound[io.inbound_pos]
    io.inbound_pos += 1
    return raw
end

@testset "TLS native TLS1.3 client" begin
    @test TLN._native_tls13_only(_tls13_native_client_config())
    @test !TLN._native_tls13_only(TLN.Config(server_name = "localhost", verify_peer = false))
    @test TLN._native_tls13_only(TLN.Config(
        server_name = "localhost",
        verify_peer = false,
        cert_file = _TLS_NATIVE_CERT_PATH,
        key_file = _TLS_NATIVE_KEY_PATH,
        min_version = TLN.TLS1_3_VERSION,
        max_version = TLN.TLS1_3_VERSION,
    ))
    @test TLN._native_tls13_server_enabled(_tls13_native_server_config())

    @testset "server enforces TLS 1.3 ClientHello invariants" begin
        server_config = _tls13_native_server_config()
        client_config = _tls13_native_client_config()

        valid_state = TLN._TLS13ServerHandshakeState(server_config)
        try
            valid_hello = TLN._tls13_client_hello(client_config)
            @test TLN._tls13_set_client_hello!(valid_state, TLN._marshal_client_hello(valid_hello)) === nothing
        finally
            TLN._securezero_tls13_server_handshake_state!(valid_state)
        end

        cases = (
            (
                "legacy version negotiation",
                TLN._TLS_ALERT_ILLEGAL_PARAMETER,
                hello -> (hello.supported_versions = UInt16[]),
            ),
            (
                "extra compression method",
                TLN._TLS_ALERT_ILLEGAL_PARAMETER,
                hello -> (hello.compression_methods = UInt8[TLN._TLS_COMPRESSION_NONE, 0x01]),
            ),
            (
                "non-empty renegotiation info",
                TLN._TLS_ALERT_HANDSHAKE_FAILURE,
                hello -> (hello.secure_renegotiation = UInt8[0x01]),
            ),
            (
                "TCP early data",
                TLN._TLS_ALERT_UNSUPPORTED_EXTENSION,
                hello -> (hello.early_data = true),
            ),
            (
                "QUIC parameters on TCP",
                TLN._TLS_ALERT_UNSUPPORTED_EXTENSION,
                hello -> (hello.quic_transport_parameters = UInt8[]),
            ),
        )
        for (label, expected_alert, configure!) in cases
            @testset "$label" begin
                state = TLN._TLS13ServerHandshakeState(server_config)
                try
                    hello = TLN._tls13_client_hello(client_config)
                    configure!(hello)
                    err = try
                        TLN._tls13_set_client_hello!(state, TLN._marshal_client_hello(hello))
                        nothing
                    catch ex
                        ex
                    end
                    @test err isa TLN._TLSAlertError
                    if err isa TLN._TLSAlertError
                        @test err.alert == expected_alert
                        @test !err.from_peer
                    end
                finally
                    TLN._securezero_tls13_server_handshake_state!(state)
                end
            end
        end
    end

    @testset "native client sends the selected fatal alert on the wire" begin
        IPN.shutdown!()
        listener = nothing
        server_tcp = nothing
        accept_task = nothing
        client_task = nothing
        try
            listener = NCN.listen(NCN.loopback_addr(0); backlog = 1)
            addr = NCN.addr(listener)::NCN.SocketAddrV4
            accept_task = errormonitor(Threads.@spawn NCN.accept(listener))
            client_task = Threads.@spawn begin
                try
                    TLN.connect(addr, _tls13_native_client_config())
                    nothing
                catch ex
                    ex
                end
            end

            @test _tls_native_wait_task(accept_task, 5.0) != :timed_out
            server_tcp = fetch(accept_task)
            client_header, client_payload = _read_tls_record(server_tcp)
            @test client_header[1] == TLN._TLS_RECORD_TYPE_HANDSHAKE
            client_hello = TLN._unmarshal_client_hello(client_payload)
            @test client_hello isa TLN._ClientHelloMsg

            server_hello = TLN._ServerHelloMsg()
            server_hello.vers = TLN.TLS1_2_VERSION
            server_hello.random = collect(UInt8(0x40):UInt8(0x5f))
            server_hello.session_id = copy((client_hello::TLN._ClientHelloMsg).session_id)
            server_hello.cipher_suite = TLN._TLS13_AES_128_GCM_SHA256_ID
            server_hello.compression_method = TLN._TLS_COMPRESSION_NONE
            # Omit supported_versions: this must be missing_extension, not the
            # former protocol_version/internal-error classification.
            raw_server_hello = TLN._marshal_server_hello(server_hello)
            TLN._tls_write_tls_plaintext!(
                server_tcp,
                TLN._TLS_RECORD_TYPE_HANDSHAKE,
                raw_server_hello,
                TLN.TLS1_2_VERSION,
            )

            alert_header, alert_payload = _read_tls_record(server_tcp)
            @test alert_header[1] == TLN._TLS_RECORD_TYPE_ALERT
            @test alert_payload == UInt8[
                TLN._TLS_ALERT_LEVEL_FATAL,
                TLN._TLS_ALERT_MISSING_EXTENSION,
            ]

            @test _tls_native_wait_task(client_task::Task, 5.0) != :timed_out
            client_err = fetch(client_task::Task)
            @test client_err isa TLN.TLSError
            if client_err isa TLN.TLSError
                @test client_err.cause isa TLN._TLSAlertError
                if client_err.cause isa TLN._TLSAlertError
                    @test (client_err.cause::TLN._TLSAlertError).alert == TLN._TLS_ALERT_MISSING_EXTENSION
                end
            end
        finally
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(listener)
            client_task isa Task && !istaskdone(client_task) && wait(client_task)
            IPN.shutdown!()
        end
    end

    @testset "native client sends decode_error for a malformed ServerHello" begin
        IPN.shutdown!()
        listener = nothing
        server_tcp = nothing
        accept_task = nothing
        client_task = nothing
        try
            listener = NCN.listen(NCN.loopback_addr(0); backlog = 1)
            addr = NCN.addr(listener)::NCN.SocketAddrV4
            accept_task = errormonitor(Threads.@spawn NCN.accept(listener))
            client_task = Threads.@spawn begin
                try
                    TLN.connect(addr, _tls13_native_client_config())
                    nothing
                catch ex
                    ex
                end
            end
            @test _tls_native_wait_task(accept_task, 5.0) != :timed_out
            server_tcp = fetch(accept_task)
            client_header, _ = _read_tls_record(server_tcp)
            @test client_header[1] == TLN._TLS_RECORD_TYPE_HANDSHAKE

            malformed_server_hello = UInt8[
                TLN._HANDSHAKE_TYPE_SERVER_HELLO,
                0x00,
                0x00,
                0x01,
                0x00,
            ]
            TLN._tls_write_tls_plaintext!(
                server_tcp,
                TLN._TLS_RECORD_TYPE_HANDSHAKE,
                malformed_server_hello,
                TLN.TLS1_2_VERSION,
            )
            alert_header, alert_payload = _read_tls_record(server_tcp)
            @test alert_header[1] == TLN._TLS_RECORD_TYPE_ALERT
            @test alert_payload == UInt8[TLN._TLS_ALERT_LEVEL_FATAL, TLN._TLS_ALERT_DECODE_ERROR]

            @test _tls_native_wait_task(client_task::Task, 5.0) != :timed_out
            client_err = fetch(client_task::Task)
            @test client_err isa TLN.TLSError
            if client_err isa TLN.TLSError
                @test client_err.cause isa TLN._TLSAlertError
                if client_err.cause isa TLN._TLSAlertError
                    @test (client_err.cause::TLN._TLSAlertError).alert == TLN._TLS_ALERT_DECODE_ERROR
                end
            end
        finally
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(listener)
            client_task isa Task && !istaskdone(client_task) && wait(client_task)
            IPN.shutdown!()
        end
    end

    @testset "record EOF distinguishes boundaries from truncation" begin
        cases = (
            ("record boundary", UInt8[], EOFError),
            ("partial header", UInt8[TLN._TLS_RECORD_TYPE_HANDSHAKE, 0x03], TLN._TLSUnexpectedEOFError),
            (
                "partial payload",
                UInt8[TLN._TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x03, 0x00, 0x04, 0xaa, 0xbb],
                TLN._TLSUnexpectedEOFError,
            ),
        )
        for (label, wire, expected_error) in cases
            @testset "$label" begin
                IPN.shutdown!()
                listener = nothing
                client_tcp = nothing
                server_tcp = nothing
                try
                    listener, client_tcp, server_tcp = _open_tcp_pair()
                    isempty(wire) || write(client_tcp, wire)
                    close(client_tcp)
                    client_tcp = nothing
                    err = try
                        TLN._tls_read_wire_record!(server_tcp, UInt8[], TLN._TLS13_MAX_CIPHERTEXT, UInt16(0))
                        nothing
                    catch ex
                        ex
                    end
                    @test typeof(err) === expected_error
                finally
                    _tls_native_close_quiet!(server_tcp)
                    _tls_native_close_quiet!(client_tcp)
                    _tls_native_close_quiet!(listener)
                    IPN.shutdown!()
                end
            end
        end

        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        try
            listener, client_tcp, server_tcp = _open_tcp_pair()
            write(client_tcp, UInt8[TLN._TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x03, 0x00, 0x00])
            close(client_tcp)
            client_tcp = nothing
            record_buffer = UInt8[]
            @test TLN._tls_read_wire_record!(server_tcp, record_buffer, TLN._TLS13_MAX_CIPHERTEXT, UInt16(0)) == 0
            @test_throws EOFError TLN._tls_read_wire_record!(server_tcp, record_buffer, TLN._TLS13_MAX_CIPHERTEXT, UInt16(0))
        finally
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(client_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "record versions follow negotiation state" begin
        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        try
            listener, client_tcp, server_tcp = _open_tcp_pair()
            state = TLN._TLS13NativeClientState()
            io = TLN._TLS13HandshakeRecordIO(client_tcp, state)
            raw = UInt8[TLN._HANDSHAKE_TYPE_CLIENT_HELLO, 0x00, 0x00, 0x00]

            TLN._write_handshake_bytes!(io, raw)
            initial_header, initial_payload = _read_tls_record(server_tcp)
            @test (UInt16(initial_header[2]) << 8) | UInt16(initial_header[3]) == TLN._TLS_LEGACY_RECORD_VERSION
            @test initial_payload == raw

            state.version = TLN.TLS1_3_VERSION
            TLN._write_handshake_bytes!(io, raw)
            negotiated_header, negotiated_payload = _read_tls_record(server_tcp)
            @test (UInt16(negotiated_header[2]) << 8) | UInt16(negotiated_header[3]) == TLN.TLS1_2_VERSION
            @test negotiated_payload == raw
        finally
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(client_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end

        cases = (
            (
                "pre-negotiation handshake",
                UInt8[TLN._TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x01, 0x00, 0x00],
                UInt16(0),
                nothing,
            ),
            (
                "negotiated TLS 1.3 legacy version",
                UInt8[TLN._TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x03, 0x00, 0x00],
                TLN.TLS1_3_VERSION,
                nothing,
            ),
            (
                # RFC 8446 §5.1: the legacy record version MUST be ignored once
                # TLS 1.3 is negotiated (Go only enforces it for pre-1.3).
                "ignored legacy version on negotiated TLS 1.3",
                UInt8[TLN._TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x01, 0x00, 0x00],
                TLN.TLS1_3_VERSION,
                nothing,
            ),
            (
                "wrong negotiated version on TLS 1.2",
                UInt8[TLN._TLS_RECORD_TYPE_HANDSHAKE, 0x03, 0x01, 0x00, 0x00],
                TLN.TLS1_2_VERSION,
                TLN._TLSAlertError,
            ),
            (
                "non-handshake first record",
                UInt8[TLN._TLS_RECORD_TYPE_APPLICATION_DATA, 0x03, 0x03, 0x00, 0x00],
                UInt16(0),
                TLN._TLSRecordHeaderError,
            ),
            (
                "implausible first version",
                UInt8[TLN._TLS_RECORD_TYPE_HANDSHAKE, 0x11, 0x11, 0x00, 0x00],
                UInt16(0),
                TLN._TLSRecordHeaderError,
            ),
            (
                "SSLv2 header",
                UInt8[0x80, 0x00, 0x01, 0x00, 0x00],
                UInt16(0),
                TLN._TLSAlertError,
            ),
            (
                "oversized record",
                UInt8[
                    TLN._TLS_RECORD_TYPE_HANDSHAKE,
                    0x03,
                    0x03,
                    UInt8((TLN._TLS13_MAX_CIPHERTEXT + 1) >> 8),
                    UInt8((TLN._TLS13_MAX_CIPHERTEXT + 1) & 0xff),
                ],
                TLN.TLS1_3_VERSION,
                TLN._TLSAlertError,
            ),
        )
        for (label, header, negotiated_version, expected_error) in cases
            @testset "$label" begin
                IPN.shutdown!()
                listener = nothing
                client_tcp = nothing
                server_tcp = nothing
                try
                    listener, client_tcp, server_tcp = _open_tcp_pair()
                    write(client_tcp, header)
                    result = try
                        TLN._tls_read_wire_record!(
                            server_tcp,
                            UInt8[],
                            TLN._TLS13_MAX_CIPHERTEXT,
                            negotiated_version,
                        )
                    catch ex
                        ex
                    end
                    if expected_error === nothing
                        @test result == 0
                    else
                        @test result isa expected_error
                    end
                    if label == "wrong negotiated version on TLS 1.2" && result isa TLN._TLSAlertError
                        @test result.alert == TLN._TLS_ALERT_PROTOCOL_VERSION
                    elseif label == "SSLv2 header" && result isa TLN._TLSAlertError
                        @test result.alert == TLN._TLS_ALERT_PROTOCOL_VERSION
                    elseif label == "oversized record" && result isa TLN._TLSAlertError
                        @test result.alert == TLN._TLS_ALERT_RECORD_OVERFLOW
                    end
                finally
                    _tls_native_close_quiet!(server_tcp)
                    _tls_native_close_quiet!(client_tcp)
                    _tls_native_close_quiet!(listener)
                    IPN.shutdown!()
                end
            end
        end
    end

    @testset "fragmented handshake records reject TLS 1.3 interleaving" begin
        partial = UInt8[TLN._HANDSHAKE_TYPE_FINISHED, 0x00, 0x00]
        tail = UInt8[0x01, 0xaa]
        interrupts = (
            (
                "ChangeCipherSpec",
                TLN._TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC,
                UInt8[0x01],
            ),
            (
                "alert",
                TLN._TLS_RECORD_TYPE_ALERT,
                UInt8[TLN._TLS_ALERT_LEVEL_FATAL, TLN._TLS_ALERT_HANDSHAKE_FAILURE],
            ),
            (
                "application data",
                TLN._TLS_RECORD_TYPE_APPLICATION_DATA,
                UInt8[0x42],
            ),
        )
        for (label, content_type, payload) in interrupts
            @testset "plaintext $label" begin
                IPN.shutdown!()
                listener = nothing
                client_tcp = nothing
                server_tcp = nothing
                try
                    listener, client_tcp, server_tcp = _open_tcp_pair()
                    state = TLN._TLS13NativeClientState()
                    state.version = TLN.TLS1_3_VERSION
                    TLN._tls_write_tls_plaintext!(
                        client_tcp,
                        TLN._TLS_RECORD_TYPE_HANDSHAKE,
                        partial,
                        TLN.TLS1_2_VERSION,
                    )
                    TLN._tls13_read_record!(server_tcp, state)
                    TLN._tls_write_tls_plaintext!(client_tcp, content_type, payload, TLN.TLS1_2_VERSION)
                    err = _tls13_unexpected_message_error(() -> TLN._tls13_read_record!(server_tcp, state))
                    err isa TLN._TLSAlertError && @test occursin("interrupted", err.message)
                finally
                    _tls_native_close_quiet!(server_tcp)
                    _tls_native_close_quiet!(client_tcp)
                    _tls_native_close_quiet!(listener)
                    IPN.shutdown!()
                end
            end
        end

        for (label, content_type, payload) in interrupts[2:3]
            @testset "encrypted $label" begin
                IPN.shutdown!()
                listener = nothing
                client_tcp = nothing
                server_tcp = nothing
                client_state = nothing
                server_state = nothing
                try
                    listener, client_tcp, server_tcp = _open_tcp_pair()
                    client_state, server_state, _, _ = _tls13_record_state_pair()
                    TLN._tls13_write_record!(client_tcp, client_state, TLN._TLS_RECORD_TYPE_HANDSHAKE, partial)
                    TLN._tls13_read_record!(server_tcp, server_state)
                    TLN._tls13_write_record!(client_tcp, client_state, content_type, payload)
                    err = _tls13_unexpected_message_error(() -> TLN._tls13_read_record!(server_tcp, server_state))
                    err isa TLN._TLSAlertError && @test occursin("interrupted", err.message)
                finally
                    client_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(client_state)
                    server_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(server_state)
                    _tls_native_close_quiet!(server_tcp)
                    _tls_native_close_quiet!(client_tcp)
                    _tls_native_close_quiet!(listener)
                    IPN.shutdown!()
                end
            end
        end

        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        try
            listener, client_tcp, server_tcp = _open_tcp_pair()
            state = TLN._TLS13NativeClientState()
            state.version = TLN.TLS1_3_VERSION
            TLN._tls_write_tls_plaintext!(client_tcp, TLN._TLS_RECORD_TYPE_HANDSHAKE, partial, TLN.TLS1_2_VERSION)
            TLN._tls_write_tls_plaintext!(client_tcp, TLN._TLS_RECORD_TYPE_HANDSHAKE, tail, TLN.TLS1_2_VERSION)
            TLN._tls13_read_record!(server_tcp, state)
            TLN._tls13_read_record!(server_tcp, state)
            @test TLN._tls13_try_take_handshake_message!(state) == vcat(partial, tail)

            TLN._tls_write_tls_plaintext!(client_tcp, TLN._TLS_RECORD_TYPE_HANDSHAKE, UInt8[], TLN.TLS1_2_VERSION)
            _tls13_unexpected_message_error(() -> TLN._tls13_read_record!(server_tcp, state))
        finally
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(client_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "fragmented handshake messages span encrypted records" begin
        # Encrypted records all share the application_data outer type, so a
        # handshake message continuing in the next record must reassemble via
        # the decrypted inner type instead of tripping the interleave check.
        partial = UInt8[TLN._HANDSHAKE_TYPE_FINISHED, 0x00, 0x00]
        tail = UInt8[0x01, 0xaa]
        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        client_state = nothing
        server_state = nothing
        try
            listener, client_tcp, server_tcp = _open_tcp_pair()
            client_state, server_state, _, _ = _tls13_record_state_pair()
            TLN._tls13_write_record!(client_tcp, client_state, TLN._TLS_RECORD_TYPE_HANDSHAKE, partial)
            TLN._tls13_write_record!(client_tcp, client_state, TLN._TLS_RECORD_TYPE_HANDSHAKE, tail)
            TLN._tls13_read_record!(server_tcp, server_state)
            TLN._tls13_read_record!(server_tcp, server_state)
            @test TLN._tls13_try_take_handshake_message!(server_state) == vcat(partial, tail)
        finally
            client_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(client_state)
            server_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(server_state)
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(client_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "record layer rejects padding-only inner plaintext" begin
        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        client_state = nothing
        server_state = nothing
        try
            listener, client_tcp, server_tcp = _open_tcp_pair()
            client_state, server_state, _, _ = _tls13_record_state_pair()
            write_cipher = client_state.write_cipher::TLN._TLS13RecordCipherState
            # Inner plaintext of a single zero byte: all padding, no content type.
            inner_len = 1
            record_payload_len = inner_len + TLN._TLS13_AEAD_TAG_SIZE
            outbuf = Vector{UInt8}(undef, 5 + record_payload_len)
            TLN._tls13_fill_record_header!(outbuf, TLN._TLS_RECORD_TYPE_APPLICATION_DATA, record_payload_len)
            outbuf[6] = 0x00
            TLN._tls13_fill_nonce!(write_cipher.nonce_buf, write_cipher.iv, write_cipher.seq)
            ciphertext_len = TLN._tls13_encrypt_record_aead!(
                write_cipher.aead,
                outbuf,
                6,
                inner_len,
                write_cipher.key,
                write_cipher.nonce_buf,
                pointer(outbuf, 1),
                5,
            )
            @test ciphertext_len == record_payload_len
            write(client_tcp, outbuf)
            err = try
                TLN._tls13_read_record!(server_tcp, server_state)
                nothing
            catch ex
                ex
            end
            @test err isa TLN._TLSAlertError
            if err isa TLN._TLSAlertError
                @test err.alert == TLN._TLS_ALERT_UNEXPECTED_MESSAGE
            end
        finally
            client_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(client_state)
            server_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(server_state)
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(client_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "TLS 1.3 user_canceled alerts are ignored with a bound" begin
        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        try
            listener, client_tcp, server_tcp = _open_tcp_pair()
            state = TLN._TLS13NativeClientState()
            state.version = TLN.TLS1_3_VERSION
            user_canceled = UInt8[TLN._TLS_ALERT_LEVEL_FATAL, TLN._TLS_ALERT_USER_CANCELED]
            handshake = UInt8[TLN._HANDSHAKE_TYPE_FINISHED, 0x00, 0x00, 0x01, 0xaa]
            TLN._tls_write_tls_plaintext!(client_tcp, TLN._TLS_RECORD_TYPE_ALERT, user_canceled, TLN.TLS1_2_VERSION)
            TLN._tls_write_tls_plaintext!(client_tcp, TLN._TLS_RECORD_TYPE_HANDSHAKE, handshake, TLN.TLS1_2_VERSION)
            TLN._tls13_read_record!(server_tcp, state)
            @test state.useless_record_count == 1
            TLN._tls13_read_record!(server_tcp, state)
            @test state.useless_record_count == 0
            @test TLN._tls13_try_take_handshake_message!(state) == handshake
        finally
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(client_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end

        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        try
            listener, client_tcp, server_tcp = _open_tcp_pair()
            state = TLN._TLS13NativeClientState()
            state.version = TLN.TLS1_3_VERSION
            user_canceled = UInt8[TLN._TLS_ALERT_LEVEL_WARNING, TLN._TLS_ALERT_USER_CANCELED]
            for _ in 1:(TLN._TLS_MAX_USELESS_RECORDS + 1)
                TLN._tls_write_tls_plaintext!(client_tcp, TLN._TLS_RECORD_TYPE_ALERT, user_canceled, TLN.TLS1_2_VERSION)
            end
            for _ in 1:TLN._TLS_MAX_USELESS_RECORDS
                TLN._tls13_read_record!(server_tcp, state)
            end
            _tls13_unexpected_message_error(() -> TLN._tls13_read_record!(server_tcp, state))
        finally
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(client_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end

        for level in (TLN._TLS_ALERT_LEVEL_WARNING, TLN._TLS_ALERT_LEVEL_FATAL)
            IPN.shutdown!()
            listener = nothing
            client_tcp = nothing
            server_tcp = nothing
            try
                listener, client_tcp, server_tcp = _open_tcp_pair()
                state = TLN._TLS13NativeClientState()
                state.version = TLN.TLS1_3_VERSION
                TLN._tls_write_tls_plaintext!(
                    client_tcp,
                    TLN._TLS_RECORD_TYPE_ALERT,
                    UInt8[level, TLN._TLS_ALERT_HANDSHAKE_FAILURE],
                    TLN.TLS1_2_VERSION,
                )
                err = try
                    TLN._tls13_read_record!(server_tcp, state)
                    nothing
                catch ex
                    ex
                end
                @test err isa TLN._TLSAlertError
                if err isa TLN._TLSAlertError
                    @test err.from_peer
                    @test err.alert == TLN._TLS_ALERT_HANDSHAKE_FAILURE
                end
            finally
                _tls_native_close_quiet!(server_tcp)
                _tls_native_close_quiet!(client_tcp)
                _tls_native_close_quiet!(listener)
                IPN.shutdown!()
            end
        end
    end

    @testset "record layer fragments oversized handshake payloads" begin
        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        try
            listener, client_tcp, server_tcp = _open_tcp_pair()
            io = TLN._TLS13HandshakeRecordIO(client_tcp, TLN._TLS13NativeClientState())
            body_len = TLN._TLS13_MAX_PLAINTEXT + 32
            raw = UInt8[
                TLN._HANDSHAKE_TYPE_CERTIFICATE,
                UInt8(body_len >> 16),
                UInt8((body_len >> 8) & 0xff),
                UInt8(body_len & 0xff),
            ]
            append!(raw, fill(UInt8(0x42), body_len))
            TLN._write_handshake_bytes!(io, raw)
            header1, payload1 = _read_tls_record(server_tcp)
            header2, payload2 = _read_tls_record(server_tcp)
            @test header1[1] == TLN._TLS_RECORD_TYPE_HANDSHAKE
            @test header2[1] == TLN._TLS_RECORD_TYPE_HANDSHAKE
            @test length(payload1) == TLN._TLS13_MAX_PLAINTEXT
            @test length(payload2) == length(raw) - TLN._TLS13_MAX_PLAINTEXT
            @test vcat(payload1, payload2) == raw
            _assert_no_pending_tcp_bytes(server_tcp)
        finally
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(client_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "dummy change cipher spec is sent once" begin
        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        try
            listener, client_tcp, server_tcp = _open_tcp_pair()
            state = TLN._TLS13NativeClientState()
            io = TLN._TLS13HandshakeRecordIO(client_tcp, state)
            TLN._tls13_send_dummy_change_cipher_spec!(io)
            TLN._tls13_send_dummy_change_cipher_spec!(io)
            header, payload = _read_tls_record(server_tcp)
            @test header[1] == TLN._TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC
            @test UInt16(header[2]) << 8 | UInt16(header[3]) == TLN.TLS1_2_VERSION
            @test payload == UInt8[0x01]
            @test state.sent_dummy_ccs
            _assert_no_pending_tcp_bytes(server_tcp)
        finally
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(client_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "record-layer session tickets preserve Go validation alerts" begin
        function ticket_raw(; lifetime = UInt32(60), label = UInt8[0xa0])
            ticket = TLN._NewSessionTicketMsgTLS13()
            ticket.lifetime = lifetime
            ticket.age_add = UInt32(1)
            ticket.nonce = UInt8[0x01]
            ticket.label = copy(label)
            return TLN._marshal_handshake_message(ticket)
        end

        cases = (
            (
                ticket_raw(lifetime = TLN._TLS13_MAX_SESSION_TICKET_LIFETIME + UInt32(1)),
                TLN._TLS_ALERT_ILLEGAL_PARAMETER,
            ),
            (ticket_raw(label = UInt8[]), TLN._TLS_ALERT_DECODE_ERROR),
            (
                UInt8[TLN._HANDSHAKE_TYPE_NEW_SESSION_TICKET, 0x00, 0x00, 0x01, 0x00],
                TLN._TLS_ALERT_DECODE_ERROR,
            ),
        )
        for (raw, expected_alert) in cases
            err = try
                TLN._tls13_validate_new_session_ticket(raw)
                nothing
            catch ex
                ex
            end
            @test err isa TLN._TLSAlertError
            err isa TLN._TLSAlertError && @test err.alert == expected_alert
        end
    end

    @testset "post-handshake key update rotates read and write traffic secrets" begin
        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        client_state = nothing
        server_state = nothing
        try
            listener, client_tcp, server_tcp = _open_tcp_pair()
            client_state, server_state, server_to_client_secret, client_to_server_secret = _tls13_record_state_pair()
            request_key_update = UInt8[
                UInt8(24),
                0x00,
                0x00,
                0x01,
                0x01,
            ]
            expected_response = UInt8[
                UInt8(24),
                0x00,
                0x00,
                0x01,
                0x00,
            ]
            expected_next_read = TLN._tls13_next_traffic_secret(TLN._TLS13_AES_128_GCM_SHA256, server_to_client_secret)
            expected_next_write = TLN._tls13_next_traffic_secret(TLN._TLS13_AES_128_GCM_SHA256, client_to_server_secret)
            try
                TLN._tls13_write_record!(server_tcp, server_state, TLN._TLS_RECORD_TYPE_HANDSHAKE, request_key_update)
                TLN._tls13_advance_write_cipher!(server_state)
                TLN._tls13_read_record!(client_tcp, client_state)
                TLN._tls13_handle_post_handshake_messages!(client_tcp, client_state)
                @test client_state.read_cipher !== nothing
                @test client_state.write_cipher !== nothing
                @test (client_state.read_cipher::TLN._TLS13RecordCipherState).traffic_secret == expected_next_read
                @test (client_state.write_cipher::TLN._TLS13RecordCipherState).traffic_secret == expected_next_write
                TLN._tls13_read_record!(server_tcp, server_state)
                @test server_state.handshake_buffer == expected_response
                TLN._tls13_handle_post_handshake_messages!(server_tcp, server_state)
                @test (server_state.read_cipher::TLN._TLS13RecordCipherState).traffic_secret == expected_next_write
                @test (server_state.write_cipher::TLN._TLS13RecordCipherState).traffic_secret == expected_next_read
            finally
                TLN._securezero!(expected_next_read)
                TLN._securezero!(expected_next_write)
            end
        finally
            client_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(client_state)
            server_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(server_state)
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(client_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "write-side key updates refresh long-lived TLS 1.3 traffic secrets" begin
        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        client_state = nothing
        server_state = nothing
        try
            listener, client_tcp, server_tcp = _open_tcp_pair()
            client_state, server_state, _, client_to_server_secret = _tls13_record_state_pair()
            write_cipher = client_state.write_cipher::TLN._TLS13RecordCipherState
            read_cipher = server_state.read_cipher::TLN._TLS13RecordCipherState
            write_cipher.seq = TLN._TLS13_WRITE_KEY_UPDATE_INTERVAL
            read_cipher.seq = TLN._TLS13_WRITE_KEY_UPDATE_INTERVAL
            expected_next_write = TLN._tls13_next_traffic_secret(TLN._TLS13_AES_128_GCM_SHA256, client_to_server_secret)
            try
                TLN._tls13_maybe_rekey_write!(client_tcp, client_state)
                TLN._tls13_read_record!(server_tcp, server_state)
                TLN._tls13_handle_post_handshake_messages!(server_tcp, server_state)
                @test (client_state.write_cipher::TLN._TLS13RecordCipherState).traffic_secret == expected_next_write
                @test (server_state.read_cipher::TLN._TLS13RecordCipherState).traffic_secret == expected_next_write
            finally
                TLN._securezero!(expected_next_write)
            end
        finally
            client_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(client_state)
            server_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(server_state)
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(client_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "empty TLS 1.3 application records are bounded" begin
        state = TLN._TLS13NativeClientState()
        # Post-handshake connection: empty application records are legal but
        # counted as useless so they stay bounded.
        state.handshake_complete = true
        try
            for _ in 1:TLN._TLS_MAX_USELESS_RECORDS
                @test !TLN._tls13_process_inner_plaintext!(state, UInt8[TLN._TLS_RECORD_TYPE_APPLICATION_DATA])
            end
            err = try
                TLN._tls13_process_inner_plaintext!(state, UInt8[TLN._TLS_RECORD_TYPE_APPLICATION_DATA])
                nothing
            catch ex
                ex
            end
            @test err isa TLN._TLSAlertError
            if err isa TLN._TLSAlertError
                @test err.alert == TLN._TLS_ALERT_UNEXPECTED_MESSAGE
                @test occursin("too many ignored TLS records", err.message)
            end
        finally
            TLN._securezero_tls13_native_client_state!(state)
        end
    end

    @testset "TLS 1.3 application data before handshake completion is rejected" begin
        # Unauthenticated peers must not be able to grow plaintext_buffer during
        # the handshake; pre-Finished application data is unexpected_message and
        # does not accumulate.
        for payload in (UInt8[TLN._TLS_RECORD_TYPE_APPLICATION_DATA], UInt8[0x42, TLN._TLS_RECORD_TYPE_APPLICATION_DATA])
            state = TLN._TLS13NativeClientState()
            @test !state.handshake_complete
            try
                err = try
                    TLN._tls13_process_inner_plaintext!(state, payload)
                    nothing
                catch ex
                    ex
                end
                @test err isa TLN._TLSAlertError
                if err isa TLN._TLSAlertError
                    @test err.alert == TLN._TLS_ALERT_UNEXPECTED_MESSAGE
                    @test occursin("application data before handshake", err.message)
                end
                @test isempty(state.plaintext_buffer)
            finally
                TLN._securezero_tls13_native_client_state!(state)
            end
        end
    end

    @testset "peer KeyUpdate response serializes under the write lock" begin
        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        client_state = nothing
        server_state = nothing
        try
            listener, client_tcp, server_tcp = _open_tcp_pair()
            client_state, server_state, _, client_to_server_secret = _tls13_record_state_pair()
            conn = _MockKeyUpdateConn(client_tcp, ReentrantLock(), nothing)
            expected_next_write = TLN._tls13_next_traffic_secret(TLN._TLS13_AES_128_GCM_SHA256, client_to_server_secret)
            before_secret = copy((client_state.write_cipher::TLN._TLS13RecordCipherState).traffic_secret)
            try
                # Hold the write lock: the response write and write-cipher
                # rotation share write state with an application writer, so the
                # handler must block here rather than race.
                lock(conn.write_lock)
                handler = errormonitor(Threads.@spawn TLN._tls13_handle_key_update!(conn, client_state, true))
                @test timedwait(() -> istaskdone(handler), 0.3) == :timed_out
                @test (client_state.write_cipher::TLN._TLS13RecordCipherState).traffic_secret == before_secret
                unlock(conn.write_lock)
                @test timedwait(() -> istaskdone(handler), 2.0) == :ok
                fetch(handler)
                @test (client_state.write_cipher::TLN._TLS13RecordCipherState).traffic_secret == expected_next_write
                @test conn.write_permanent_error === nothing
                # The peer receives exactly the responding KeyUpdate record.
                TLN._tls13_read_record!(server_tcp, server_state)
                raw = TLN._tls13_try_take_handshake_message!(server_state)
                @test raw !== nothing
                @test TLN._tls13_parse_key_update(raw::Vector{UInt8}) === false
            finally
                TLN._securezero!(expected_next_write)
                TLN._securezero!(before_secret)
            end
        finally
            client_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(client_state)
            server_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(server_state)
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(client_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "peer KeyUpdate response failure becomes the permanent write error" begin
        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        client_state = nothing
        server_state = nothing
        try
            listener, client_tcp, server_tcp = _open_tcp_pair()
            client_state, server_state, _, _ = _tls13_record_state_pair()
            conn = _MockKeyUpdateConn(client_tcp, ReentrantLock(), nothing)
            read_secret_before = copy((client_state.read_cipher::TLN._TLS13RecordCipherState).traffic_secret)
            try
                # Break the transport so writing the response fails.
                close(client_tcp)
                # The handler must not propagate the failure into the read path;
                # it records it as the permanent write-side error instead.
                TLN._tls13_handle_key_update!(conn, client_state, true)
                @test conn.write_permanent_error isa TLN.TLSError
                # The read cipher still advances (it is owned by the read path
                # and independent of the write failure).
                @test (client_state.read_cipher::TLN._TLS13RecordCipherState).traffic_secret != read_secret_before
            finally
                TLN._securezero!(read_secret_before)
            end
        finally
            client_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(client_state)
            server_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(server_state)
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(client_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "record layer rejects oversized plaintext and exhausted write sequence numbers" begin
        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        client_state = nothing
        server_state = nothing
        try
            listener, client_tcp, server_tcp = _open_tcp_pair()
            client_state, server_state, _, _ = _tls13_record_state_pair()
            @test_throws ArgumentError TLN._tls13_write_record!(
                client_tcp,
                client_state,
                TLN._TLS_RECORD_TYPE_APPLICATION_DATA,
                fill(UInt8(0x00), TLN._TLS13_MAX_PLAINTEXT + 1),
            )
            write_cipher = client_state.write_cipher::TLN._TLS13RecordCipherState
            write_cipher.seq = typemax(UInt64)
            TLN._tls13_write_record!(client_tcp, client_state, TLN._TLS_RECORD_TYPE_APPLICATION_DATA, UInt8[0xaa])
            @test write_cipher.exhausted
            @test_throws ArgumentError TLN._tls13_write_record!(
                client_tcp,
                client_state,
                TLN._TLS_RECORD_TYPE_APPLICATION_DATA,
                UInt8[0xbb],
            )
        finally
            client_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(client_state)
            server_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(server_state)
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(client_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "record layer rejects authenticated oversized inner plaintext" begin
        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        client_state = nothing
        server_state = nothing
        try
            listener, client_tcp, server_tcp = _open_tcp_pair()
            client_state, server_state, _, _ = _tls13_record_state_pair()
            write_cipher = client_state.write_cipher::TLN._TLS13RecordCipherState
            content_len = TLN._TLS13_MAX_PLAINTEXT + 1
            inner_len = content_len + 1
            record_payload_len = inner_len + TLN._TLS13_AEAD_TAG_SIZE
            outbuf = Vector{UInt8}(undef, 5 + record_payload_len)
            TLN._tls13_fill_record_header!(outbuf, TLN._TLS_RECORD_TYPE_APPLICATION_DATA, record_payload_len)
            fill!(@view(outbuf[6:5 + content_len]), 0x42)
            outbuf[6 + content_len] = TLN._TLS_RECORD_TYPE_APPLICATION_DATA
            TLN._tls13_fill_nonce!(write_cipher.nonce_buf, write_cipher.iv, write_cipher.seq)
            ciphertext_len = TLN._tls13_encrypt_record_aead!(
                write_cipher.aead,
                outbuf,
                6,
                inner_len,
                write_cipher.key,
                write_cipher.nonce_buf,
                pointer(outbuf, 1),
                5,
            )
            @test ciphertext_len == record_payload_len
            write(client_tcp, outbuf)
            err = try
                TLN._tls13_read_record!(server_tcp, server_state)
                nothing
            catch ex
                ex
            end
            @test err isa TLN._TLSAlertError
            if err isa TLN._TLSAlertError
                @test err.alert == TLN._TLS_ALERT_RECORD_OVERFLOW
            end
        finally
            client_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(client_state)
            server_state isa TLN._TLS13NativeClientState && TLN._securezero_tls13_native_client_state!(server_state)
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(client_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "server aborts resumption when a valid ticket has an invalid binder" begin
        config = _tls13_native_server_config()
        state = TLN._TLS13ServerHandshakeState(config)
        keys = TLN._tls_active_session_ticket_keys(config)
        plaintext = UInt8[]
        label = UInt8[]
        try
            now_s = UInt64(floor(time()))
            session = TLN._TLS13ServerSession(
                TLN.TLS1_3_VERSION,
                TLN._TLS13_AES_128_GCM_SHA256_ID,
                now_s,
                now_s + UInt64(60),
                UInt32(0),
                UInt8[],
                fill(UInt8(0x42), 32),
                Vector{Vector{UInt8}}(),
                "",
            )
            plaintext = TLN._serialize_tls13_server_session(session)
            label = TLN._tls_encrypt_server_session_ticket(keys[1], plaintext)
            hello = TLN._ClientHelloMsg()
            hello.psk_modes = UInt8[TLN._TLS_PSK_MODE_DHE]
            hello.psk_identities = [TLN._TLSPSKIdentity(copy(label), UInt32(0))]
            hello.psk_binders = [fill(UInt8(0xa5), TLN._hash_len(TLN._HASH_SHA256))]
            state.client_hello = hello
            state.cipher_suite = TLN._TLS13_AES_128_GCM_SHA256_ID
            state.cipher_spec = TLN._TLS13_AES_128_GCM_SHA256
            state.selected_alpn = ""
            state.transcript = TLN._new_tls13_handshake_transcript(TLN._HASH_SHA256)

            err = try
                TLN._check_for_resumption!(state, config)
                nothing
            catch ex
                ex
            end
            @test err isa TLN._TLSAlertError
            if err isa TLN._TLSAlertError
                @test err.alert == TLN._TLS_ALERT_DECRYPT_ERROR
                @test occursin("invalid PSK binder", err.message)
            end
            @test !state.using_psk
        finally
            TLN._securezero_tls13_server_handshake_state!(state)
            TLN._securezero_tls_session_ticket_keys!(keys)
            TLN._securezero!(plaintext)
            TLN._securezero!(label)
        end
    end

    @testset "server distinguishes malformed PSK binder counts from bad MACs" begin
        config = _tls13_native_server_config()
        state = TLN._TLS13ServerHandshakeState(config)
        try
            hello = TLN._ClientHelloMsg()
            hello.psk_modes = UInt8[TLN._TLS_PSK_MODE_DHE]
            hello.psk_identities = [
                TLN._TLSPSKIdentity(UInt8[0x01], UInt32(0)),
                TLN._TLSPSKIdentity(UInt8[0x02], UInt32(0)),
            ]
            hello.psk_binders = [fill(UInt8(0xa5), TLN._hash_len(TLN._HASH_SHA256))]
            state.client_hello = hello

            err = try
                TLN._check_for_resumption!(state, config)
                nothing
            catch ex
                ex
            end
            @test err isa TLN._TLSAlertError
            if err isa TLN._TLSAlertError
                @test err.alert == TLN._TLS_ALERT_ILLEGAL_PARAMETER
                @test occursin("invalid or missing PSK binders", err.message)
            end
            @test !state.using_psk
        finally
            TLN._securezero_tls13_server_handshake_state!(state)
        end
    end

    @testset "server rejects client certificate verify scheme that mismatches the certified key" begin
        config = _tls13_native_server_config(client_auth = TLN.ClientAuthMode.RequireAnyClientCert)
        state = TLN._TLS13ServerHandshakeState(config)
        try
            state.client_certificate_request_algorithms = UInt16[TLN._TLS13_SERVER_SUPPORTED_SIGNATURE_ALGORITHMS...]
            certificate = TLN._CertificateMsgTLS13()
            certificate.certificates = TLN._tls13_load_x509_pem_chain(read(_TLS_NATIVE_MTLS_CLIENT_CERT_PATH))
            # The client certificate carries an RSA key; ECDSA P-256 is offered
            # in the CertificateRequest but cannot belong to the certified key.
            # Go reports this through verifyHandshakeSignature as decrypt_error.
            certificate_verify = TLN._CertificateVerifyMsg(
                TLN._TLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
                fill(UInt8(0x5a), 64),
            )
            io = _TLS13ServerFlightIO([
                TLN._marshal_certificate_tls13(certificate),
                TLN._marshal_certificate_verify(certificate_verify),
            ])
            err = try
                TLN._read_client_certificate!(state, io, config)
                nothing
            catch ex
                ex
            end
            @test err isa TLN._TLSAlertError
            if err isa TLN._TLSAlertError
                @test err.alert == TLN._TLS_ALERT_DECRYPT_ERROR
                @test occursin("invalid signature by the client certificate", err.message)
                @test !err.from_peer
            end
        finally
            TLN._securezero_tls13_server_handshake_state!(state)
        end
    end

    @testset "native client roundtrip with ALPN" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config(alpn_protocols = ["h2", "http/1.1"]))
            client = TLN.connect(
                addr;
                server_name = "localhost",
                verify_peer = false,
                alpn_protocols = ["h2", "http/1.1"],
                min_version = TLN.TLS1_3_VERSION,
                max_version = TLN.TLS1_3_VERSION,
                handshake_timeout_ns = 10_000_000_000,
            )
            _finish_tls13_native_server!(server_task::Task)
            server = fetch(server_task::Task)
            @test client.policy == TLN._TLS_POLICY_TLS13
            @test server.policy == TLN._TLS_POLICY_TLS13
            client_state = TLN.connection_state(client)
            server_state = TLN.connection_state(server)
            @test client_state.handshake_complete
            @test client_state.version == "TLSv1.3"
            @test client_state.alpn_protocol == "h2"
            @test client_state.using_native_tls13
            @test server_state.handshake_complete
            @test server_state.using_native_tls13
            @test server_state.alpn_protocol == "h2"
            payload = UInt8[0x01, 0x02, 0x03, 0x04]
            @test write(client, payload) == length(payload)
            @test read(server, length(payload)) == payload
            reply = UInt8[0xa0, 0xa1, 0xa2]
            @test write(server, reply) == length(reply)
            @test read(client, length(reply)) == reply
        finally
            _tls_native_close_quiet!(server)
            _tls_native_close_quiet!(client)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native client accepts h2/http1.1 ALPN fallback with an empty negotiated protocol" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config(alpn_protocols = ["h2"]))
            client = TLN.connect(
                addr;
                server_name = "localhost",
                verify_peer = false,
                alpn_protocols = ["http/1.1"],
                min_version = TLN.TLS1_3_VERSION,
                max_version = TLN.TLS1_3_VERSION,
                handshake_timeout_ns = 10_000_000_000,
            )
            server = fetch(server_task::Task)
            @test TLN.connection_state(client).alpn_protocol == ""
            @test TLN.connection_state(server).alpn_protocol == ""
            status = _tls_native_wait_task(server_task::Task, 5.0)
            @test status != :timed_out
        finally
            _tls_native_close_quiet!(server)
            _tls_native_close_quiet!(client)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native client rejects ALPN no-overlap with no_application_protocol" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config(alpn_protocols = ["h2"]))
            err = try
                TLN.connect(
                    addr;
                    server_name = "localhost",
                    verify_peer = false,
                    alpn_protocols = ["spdy/3"],
                    min_version = TLN.TLS1_3_VERSION,
                    max_version = TLN.TLS1_3_VERSION,
                    handshake_timeout_ns = 10_000_000_000,
                )
                nothing
            catch ex
                ex
            end
            @test err isa TLN.TLSError
            if err isa TLN.TLSError
                @test occursin("alert 120", err.message)
            end
            status = _tls_native_wait_task(server_task::Task, 5.0)
            @test status != :timed_out
        finally
            _tls_native_close_quiet!(server)
            _tls_native_close_quiet!(client)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "TLS 1.3 rejects too many ignored ChangeCipherSpec records" begin
        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        try
            listener, client_tcp, server_tcp = _open_tcp_pair()
            state = TLN._TLS13NativeClientState()
            state.version = TLN.TLS1_3_VERSION
            for _ in 1:(TLN._TLS_MAX_USELESS_RECORDS + 1)
                TLN._tls_write_tls_plaintext!(
                    client_tcp,
                    TLN._TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC,
                    UInt8[0x01],
                    TLN.TLS1_2_VERSION,
                )
            end
            for _ in 1:TLN._TLS_MAX_USELESS_RECORDS
                TLN._tls13_read_record!(server_tcp, state)
            end
            err = try
                TLN._tls13_read_record!(server_tcp, state)
                nothing
            catch ex
                ex
            end
            @test err isa TLN._TLSAlertError
            if err isa TLN._TLSAlertError
                @test err.alert == TLN._TLS_ALERT_UNEXPECTED_MESSAGE
            end
        finally
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(client_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native server handles HelloRetryRequest with P-256 through public APIs" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config(
                curve_preferences = UInt16[TLN.P256],
            ))
            client = TLN.connect(addr, _tls13_native_client_config(server_name = "localhost", verify_peer = false))
            _finish_tls13_native_server!(server_task::Task)
            server = fetch(server_task::Task)
            client_state = TLN.connection_state(client)
            server_state = TLN.connection_state(server)
            @test client_state.using_native_tls13
            @test server_state.using_native_tls13
            @test client_state.did_hello_retry_request
            @test server_state.did_hello_retry_request
            @test client_state.curve == "P-256"
            @test server_state.curve == "P-256"
            payload = UInt8[0x31, 0x32, 0x33]
            @test write(client, payload) == length(payload)
            @test read(server, length(payload)) == payload
        finally
            _tls_native_close_quiet!(server)
            _tls_native_close_quiet!(client)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "live native TLS fragments large application payloads" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config(
                curve_preferences = UInt16[TLN.P256],
            ))
            client = TLN.connect(addr, _tls13_native_client_config(server_name = "localhost", verify_peer = false))
            _finish_tls13_native_server!(server_task::Task)
            server = fetch(server_task::Task)
            payload = [UInt8(mod(i, 251)) for i in 0:(3 * TLN._TLS13_MAX_PLAINTEXT + 17)]
            reply = [UInt8(mod(2 * i, 253)) for i in 0:(2 * TLN._TLS13_MAX_PLAINTEXT + 29)]
            @test write(client, payload) == length(payload)
            @test read(server, length(payload)) == payload
            @test write(server, reply) == length(reply)
            @test read(client, length(reply)) == reply
        finally
            _tls_native_close_quiet!(server)
            _tls_native_close_quiet!(client)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native client resumes TLS 1.3 sessions on a reused Config" begin
        IPN.shutdown!()
        listener = nothing
        client1 = nothing
        client2 = nothing
        client3 = nothing
        server_task = nothing
        try
            listener = TLN.listen(NCN.loopback_addr(0), _tls13_native_server_config(
                curve_preferences = UInt16[TLN.P256],
            ); backlog = 8)
            addr = TLN.addr(listener)::NCN.SocketAddrV4
            server_task = Threads.@spawn begin
                conns = TLN.Conn[]
                for i in 1:3
                    conn = TLN.accept(listener)
                    TLN.handshake!(conn)
                    push!(conns, conn)
                    write(conn, UInt8[UInt8(i)])
                    close(conn)
                end
                return conns
            end
            client_config = _tls13_native_client_config(
                server_name = "localhost",
                verify_peer = true,
                ca_file = _TLS_NATIVE_CERT_PATH,
            )
            client1 = TLN.connect(addr, client_config)
            @test read(client1, 1) == UInt8[0x01]
            @test eof(client1)
            @test !TLN.connection_state(client1).did_resume
            @test TLN.connection_state(client1).did_hello_retry_request
            @test TLN.connection_state(client1).has_resumable_session

            client2 = TLN.connect(addr, client_config)
            @test read(client2, 1) == UInt8[0x02]
            @test eof(client2)
            @test TLN.connection_state(client2).did_resume
            @test TLN.connection_state(client2).did_hello_retry_request

            client3 = TLN.connect(addr, client_config)
            @test read(client3, 1) == UInt8[0x03]
            @test eof(client3)
            @test TLN.connection_state(client3).did_resume
            @test TLN.connection_state(client3).did_hello_retry_request

            status = _tls_native_wait_task(server_task::Task, 5.0)
            status == :timed_out && error("timed out waiting for TLS session resumption server")
            wait(server_task::Task)
        finally
            _tls_native_close_quiet!(client3)
            _tls_native_close_quiet!(client2)
            _tls_native_close_quiet!(client1)
            if server_task isa Task && _tls_native_wait_task(server_task::Task, 1.0) != :timed_out
                wait(server_task::Task)
            end
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native server RequestClientCert accepts clients without certificates" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config(
                cert_file = _TLS_NATIVE_MTLS_SERVER_CERT_PATH,
                key_file = _TLS_NATIVE_MTLS_SERVER_KEY_PATH,
                client_auth = TLN.ClientAuthMode.RequestClientCert,
                client_ca_file = _TLS_NATIVE_MTLS_CA_PATH,
            ))
            client = TLN.connect(addr, _tls13_native_client_config(
                server_name = "localhost",
                verify_peer = true,
                ca_file = _TLS_NATIVE_MTLS_CA_PATH,
            ))
            _finish_tls13_native_server!(server_task::Task)
            server = fetch(server_task::Task)
            @test TLN.connection_state(client).handshake_complete
            @test TLN.connection_state(server).handshake_complete
            payload = UInt8[0x31, 0x32]
            @test write(client, payload) == length(payload)
            @test read(server, length(payload)) == payload
        finally
            _tls_native_close_quiet!(server)
            _tls_native_close_quiet!(client)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native server VerifyClientCertIfGiven accepts clients without certificates" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config(
                cert_file = _TLS_NATIVE_MTLS_SERVER_CERT_PATH,
                key_file = _TLS_NATIVE_MTLS_SERVER_KEY_PATH,
                client_auth = TLN.ClientAuthMode.VerifyClientCertIfGiven,
                client_ca_file = _TLS_NATIVE_MTLS_CA_PATH,
            ))
            client = TLN.connect(addr, _tls13_native_client_config(
                server_name = "localhost",
                verify_peer = true,
                ca_file = _TLS_NATIVE_MTLS_CA_PATH,
            ))
            _finish_tls13_native_server!(server_task::Task)
            server = fetch(server_task::Task)
            @test TLN.connection_state(client).handshake_complete
            @test TLN.connection_state(server).handshake_complete
            payload = UInt8[0x41, 0x42]
            @test write(client, payload) == length(payload)
            @test read(server, length(payload)) == payload
        finally
            _tls_native_close_quiet!(server)
            _tls_native_close_quiet!(client)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native server VerifyClientCertIfGiven verifies provided client certificates" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config(
                cert_file = _TLS_NATIVE_MTLS_SERVER_CERT_PATH,
                key_file = _TLS_NATIVE_MTLS_SERVER_KEY_PATH,
                client_auth = TLN.ClientAuthMode.VerifyClientCertIfGiven,
                client_ca_file = _TLS_NATIVE_MTLS_CA_PATH,
            ))
            client = TLN.connect(addr, _tls13_native_client_config(
                server_name = "localhost",
                verify_peer = true,
                ca_file = _TLS_NATIVE_MTLS_CA_PATH,
                cert_file = _TLS_NATIVE_MTLS_CLIENT_CERT_PATH,
                key_file = _TLS_NATIVE_MTLS_CLIENT_KEY_PATH,
            ))
            _finish_tls13_native_server!(server_task::Task)
            server = fetch(server_task::Task)
            @test TLN.connection_state(client).handshake_complete
            @test TLN.connection_state(server).handshake_complete
            payload = UInt8[0x51, 0x52]
            @test write(client, payload) == length(payload)
            @test read(server, length(payload)) == payload
        finally
            _tls_native_close_quiet!(server)
            _tls_native_close_quiet!(client)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native server RequireAnyClientCert accepts provided client certificates" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config(
                cert_file = _TLS_NATIVE_MTLS_SERVER_CERT_PATH,
                key_file = _TLS_NATIVE_MTLS_SERVER_KEY_PATH,
                client_auth = TLN.ClientAuthMode.RequireAnyClientCert,
                client_ca_file = _TLS_NATIVE_MTLS_CA_PATH,
            ))
            client = TLN.connect(addr, _tls13_native_client_config(
                server_name = "localhost",
                verify_peer = true,
                ca_file = _TLS_NATIVE_MTLS_CA_PATH,
                cert_file = _TLS_NATIVE_MTLS_CLIENT_CERT_PATH,
                key_file = _TLS_NATIVE_MTLS_CLIENT_KEY_PATH,
            ))
            _finish_tls13_native_server!(server_task::Task)
            server = fetch(server_task::Task)
            @test TLN.connection_state(client).handshake_complete
            @test TLN.connection_state(server).handshake_complete
            payload = UInt8[0x61, 0x62]
            @test write(client, payload) == length(payload)
            @test read(server, length(payload)) == payload
        finally
            _tls_native_close_quiet!(server)
            _tls_native_close_quiet!(client)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native server rejects missing client certificate when any certificate is required" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server_task = nothing
        try
            listener = TLN.listen(
                NCN.loopback_addr(0),
                _tls13_native_server_config(
                    cert_file = _TLS_NATIVE_MTLS_SERVER_CERT_PATH,
                    key_file = _TLS_NATIVE_MTLS_SERVER_KEY_PATH,
                    client_auth = TLN.ClientAuthMode.RequireAnyClientCert,
                    client_ca_file = _TLS_NATIVE_MTLS_CA_PATH,
                );
                backlog = 8,
            )
            addr = TLN.addr(listener)::NCN.SocketAddrV4
            server_task = Threads.@spawn begin
                conn = TLN.accept(listener)
                try
                    TLN.handshake!(conn)
                    return :ok
                catch err
                    return err
                finally
                    _tls_native_close_quiet!(conn)
                end
            end
            try
                client = TLN.connect(
                    addr,
                    _tls13_native_client_config(
                        server_name = "localhost",
                        verify_peer = true,
                        ca_file = _TLS_NATIVE_MTLS_CA_PATH,
                    ),
                )
                @test_throws TLN.TLSError read(client, 1)
            catch err
                @test err isa TLN.TLSError
            end
            status = _tls_native_wait_task(server_task::Task, 5.0)
            status == :timed_out && error("timed out waiting for require-any-client-cert failure server")
            @test fetch(server_task::Task) isa TLN.TLSError
        finally
            _tls_native_close_quiet!(client)
            if server_task isa Task && _tls_native_wait_task(server_task::Task, 1.0) != :timed_out
                wait(server_task::Task)
            end
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native mutual TLS roundtrip and resumption" begin
        IPN.shutdown!()
        listener = nothing
        client1 = nothing
        client2 = nothing
        server_task = nothing
        try
            server_config = _tls13_native_server_config(
                cert_file = _TLS_NATIVE_MTLS_SERVER_CERT_PATH,
                key_file = _TLS_NATIVE_MTLS_SERVER_KEY_PATH,
                client_auth = TLN.ClientAuthMode.RequireAndVerifyClientCert,
                client_ca_file = _TLS_NATIVE_MTLS_CA_PATH,
            )
            listener = TLN.listen(NCN.loopback_addr(0), server_config; backlog = 8)
            addr = TLN.addr(listener)::NCN.SocketAddrV4
            server_task = Threads.@spawn begin
                conns = TLN.Conn[]
                for i in 1:2
                    conn = TLN.accept(listener)
                    TLN.handshake!(conn)
                    push!(conns, conn)
                    write(conn, UInt8[UInt8(0x10 + i)])
                    close(conn)
                end
                return conns
            end
            client_config = _tls13_native_client_config(
                server_name = "localhost",
                verify_peer = true,
                ca_file = _TLS_NATIVE_MTLS_CA_PATH,
                cert_file = _TLS_NATIVE_MTLS_CLIENT_CERT_PATH,
                key_file = _TLS_NATIVE_MTLS_CLIENT_KEY_PATH,
            )
            client1 = TLN.connect(addr, client_config)
            @test read(client1, 1) == UInt8[0x11]
            @test eof(client1)
            @test !TLN.connection_state(client1).did_resume
            @test TLN.connection_state(client1).has_resumable_session

            client2 = TLN.connect(addr, client_config)
            @test read(client2, 1) == UInt8[0x12]
            @test eof(client2)
            @test TLN.connection_state(client2).did_resume

            status = _tls_native_wait_task(server_task::Task, 5.0)
            status == :timed_out && error("timed out waiting for mutual TLS resumption server")
            wait(server_task::Task)
        finally
            _tls_native_close_quiet!(client2)
            _tls_native_close_quiet!(client1)
            if server_task isa Task && _tls_native_wait_task(server_task::Task, 1.0) != :timed_out
                wait(server_task::Task)
            end
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native server rejects missing client certificate when required" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server_task = nothing
        try
            listener = TLN.listen(
                NCN.loopback_addr(0),
                _tls13_native_server_config(
                    cert_file = _TLS_NATIVE_MTLS_SERVER_CERT_PATH,
                    key_file = _TLS_NATIVE_MTLS_SERVER_KEY_PATH,
                    client_auth = TLN.ClientAuthMode.RequireAndVerifyClientCert,
                    client_ca_file = _TLS_NATIVE_MTLS_CA_PATH,
                );
                backlog = 8,
            )
            addr = TLN.addr(listener)::NCN.SocketAddrV4
            server_task = Threads.@spawn begin
                conn = TLN.accept(listener)
                try
                    TLN.handshake!(conn)
                    return :ok
                catch err
                    return err
                finally
                    _tls_native_close_quiet!(conn)
                end
            end
            try
                client = TLN.connect(
                    addr,
                    _tls13_native_client_config(
                        server_name = "localhost",
                        verify_peer = true,
                        ca_file = _TLS_NATIVE_MTLS_CA_PATH,
                    ),
                )
                @test_throws TLN.TLSError read(client, 1)
            catch err
                @test err isa TLN.TLSError
            end
            status = _tls_native_wait_task(server_task::Task, 5.0)
            status == :timed_out && error("timed out waiting for client-auth failure server")
            @test fetch(server_task::Task) isa TLN.TLSError
        finally
            _tls_native_close_quiet!(client)
            if server_task isa Task && _tls_native_wait_task(server_task::Task, 1.0) != :timed_out
                wait(server_task::Task)
            end
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native client verifies self-signed localhost certificate" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config())
            client = TLN.connect(
                addr;
                server_name = "localhost",
                verify_peer = true,
                ca_file = _TLS_NATIVE_CERT_PATH,
                min_version = TLN.TLS1_3_VERSION,
                max_version = TLN.TLS1_3_VERSION,
                handshake_timeout_ns = 10_000_000_000,
            )
            _finish_tls13_native_server!(server_task::Task)
            @test TLN.connection_state(client).handshake_complete
        finally
            _tls_native_close_quiet!(client)
            server_task isa Task && _finish_tls13_native_server!(server_task)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native client can verify hostname without chain verification" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config())
            client = TLN.connect(addr, _tls13_native_client_config(
                server_name = "localhost",
                verify_peer = false,
                verify_hostname = true,
            ))
            _finish_tls13_native_server!(server_task::Task)
            @test TLN.connection_state(client).handshake_complete
        finally
            _tls_native_close_quiet!(client)
            server_task isa Task && _finish_tls13_native_server!(server_task)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native client rejects wrong hostname" begin
        IPN.shutdown!()
        listener = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config())
            @test_throws TLN.TLSError TLN.connect(
                addr;
                server_name = "example.com",
                verify_peer = true,
                ca_file = _TLS_NATIVE_CERT_PATH,
                min_version = TLN.TLS1_3_VERSION,
                max_version = TLN.TLS1_3_VERSION,
                handshake_timeout_ns = 10_000_000_000,
            )
        finally
            server_task isa Task && _finish_tls13_native_server!(server_task)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "handshake failures are sticky" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config())
            tcp = NCN.connect(addr)
            client = TLN.client(tcp, _tls13_native_client_config(
                server_name = "example.com",
                verify_peer = true,
                ca_file = _TLS_NATIVE_CERT_PATH,
            ))
            first_err = try
                TLN.handshake!(client)
                nothing
            catch ex
                ex
            end
            second_err = try
                TLN.handshake!(client)
                nothing
            catch ex
                ex
            end
            @test first_err isa TLN.TLSError
            @test second_err === first_err
            if first_err isa TLN.TLSError
                @test occursin("certificate is not valid for host example.com", first_err.message)
            end
        finally
            _tls_native_close_quiet!(client)
            server_task isa Task && _finish_tls13_native_server!(server_task)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native client rejects wrong hostname without chain verification" begin
        IPN.shutdown!()
        listener = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config())
            err = try
                TLN.connect(addr, _tls13_native_client_config(
                    server_name = "example.com",
                    verify_peer = false,
                    verify_hostname = true,
                ))
                nothing
            catch ex
                ex
            end
            @test err isa TLN.TLSError
            if err isa TLN.TLSError
                @test occursin("certificate is not valid for host", err.message)
            end
        finally
            server_task isa Task && _finish_tls13_native_server!(server_task)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native server sends fatal alert on unexpected first handshake message" begin
        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config())
            client_tcp = NCN.connect(addr)
            payload = UInt8[TLN._HANDSHAKE_TYPE_FINISHED, 0x00, 0x00, 0x00]
            header = UInt8[
                TLN._TLS_RECORD_TYPE_HANDSHAKE,
                UInt8(TLN.TLS1_2_VERSION >> 8),
                UInt8(TLN.TLS1_2_VERSION & 0xff),
                UInt8(length(payload) >> 8),
                UInt8(length(payload) & 0xff),
            ]
            write(client_tcp, header)
            write(client_tcp, payload)
            alert_header, alert_payload = _read_tls_record(client_tcp)
            @test alert_header[1] == TLN._TLS_RECORD_TYPE_ALERT
            @test alert_payload == UInt8[TLN._TLS_ALERT_LEVEL_FATAL, TLN._TLS_ALERT_UNEXPECTED_MESSAGE]
        finally
            _tls_native_close_quiet!(client_tcp)
            server_task isa Task && _finish_tls13_native_server!(server_task)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native server sends decode_error for a malformed ClientHello" begin
        IPN.shutdown!()
        listener = nothing
        client_tcp = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config())
            client_tcp = NCN.connect(addr)
            malformed_client_hello = UInt8[
                TLN._HANDSHAKE_TYPE_CLIENT_HELLO,
                0x00,
                0x00,
                0x01,
                0x00,
            ]
            TLN._tls_write_tls_plaintext!(
                client_tcp,
                TLN._TLS_RECORD_TYPE_HANDSHAKE,
                malformed_client_hello,
                TLN._TLS_LEGACY_RECORD_VERSION,
            )
            alert_header, alert_payload = _read_tls_record(client_tcp)
            @test alert_header[1] == TLN._TLS_RECORD_TYPE_ALERT
            @test alert_payload == UInt8[TLN._TLS_ALERT_LEVEL_FATAL, TLN._TLS_ALERT_DECODE_ERROR]
        finally
            _tls_native_close_quiet!(client_tcp)
            server_task isa Task && _finish_tls13_native_server!(server_task)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native client does not send a fatal alert in response to a peer fatal alert" begin
        IPN.shutdown!()
        listener = nothing
        server_tcp = nothing
        accept_task = nothing
        client_task = nothing
        try
            listener = NCN.listen(NCN.loopback_addr(0); backlog = 1)
            addr = NCN.addr(listener)::NCN.SocketAddrV4
            accept_task = errormonitor(Threads.@spawn NCN.accept(listener))
            client_task = Threads.@spawn begin
                try
                    TLN.connect(addr, _tls13_native_client_config(server_name = "localhost", verify_peer = false))
                    nothing
                catch ex
                    ex
                end
            end
            @test _tls_native_wait_task(accept_task, 5.0) != :timed_out
            server_tcp = fetch(accept_task)
            header, _ = _read_tls_record(server_tcp)
            if header[1] == TLN._TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC
                header, _ = _read_tls_record(server_tcp)
            end
            @test header[1] == TLN._TLS_RECORD_TYPE_HANDSHAKE

            alert_header = UInt8[
                TLN._TLS_RECORD_TYPE_ALERT,
                UInt8(TLN.TLS1_2_VERSION >> 8),
                UInt8(TLN.TLS1_2_VERSION & 0xff),
                0x00,
                0x02,
            ]
            alert_payload = UInt8[TLN._TLS_ALERT_LEVEL_FATAL, TLN._TLS_ALERT_HANDSHAKE_FAILURE]
            write(server_tcp, alert_header)
            write(server_tcp, alert_payload)

            @test _tls_native_wait_task(client_task::Task, 5.0) != :timed_out
            client_err = fetch(client_task::Task)
            @test client_err isa TLN.TLSError
            if client_err isa TLN.TLSError
                @test occursin("received fatal TLS 1.3 alert", client_err.message)
            end

            NCN.set_read_deadline!(server_tcp, time_ns() + 100_000_000)
            extra = try
                read!(server_tcp, Vector{UInt8}(undef, 1))
                :bytes
            catch ex
                ex
            finally
                NCN.set_read_deadline!(server_tcp, Int64(0))
            end
            @test extra isa EOFError || extra isa NCN.DeadlineExceededError
        finally
            _tls_native_close_quiet!(server_tcp)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native client rejects invalid CA roots path contents" begin
        IPN.shutdown!()
        listener = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(_tls13_native_server_config())
            @test_throws TLN.TLSError TLN.connect(
                addr;
                server_name = "localhost",
                verify_peer = true,
                ca_file = _TLS_NATIVE_KEY_PATH,
                min_version = TLN.TLS1_3_VERSION,
                max_version = TLN.TLS1_3_VERSION,
                handshake_timeout_ns = 10_000_000_000,
            )
        finally
            server_task isa Task && _finish_tls13_native_server!(server_task)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native client observes close_notify as EOF" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server_task = nothing
        writer_task = nothing
        try
            listener, addr, server_task, server_ref = _start_tls13_native_server(_tls13_native_server_config())
            client = TLN.connect(
                addr;
                server_name = "localhost",
                verify_peer = false,
                min_version = TLN.TLS1_3_VERSION,
                max_version = TLN.TLS1_3_VERSION,
                handshake_timeout_ns = 10_000_000_000,
            )
            _finish_tls13_native_server!(server_task::Task)
            writer_task = Threads.@spawn begin
                server = server_ref[]::TLN.Conn
                payload = UInt8[0xde, 0xad, 0xbe, 0xef]
                write(server, payload)
                close(server)
            end
            status = _tls_native_wait_task(writer_task::Task, 5.0)
            status == :timed_out && error("timed out waiting for TLS native close_notify writer")
            wait(writer_task::Task)
            @test read(client, 4) == UInt8[0xde, 0xad, 0xbe, 0xef]
            @test eof(client)
        finally
            _tls_native_close_quiet!(client)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end
end
