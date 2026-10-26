using Test
using Reseau

# Mirrors Go's crypto/tls quic_test.go: two QUICConns pass CRYPTO-frame bytes
# to each other through their events, with no QUIC transport underneath.

const TLQ = Reseau.TLS
const QEL = TLQ.QUICEncryptionLevel
const QEK = TLQ.QUICEventKind

const _QUIC_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _QUIC_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")
const _QUIC_CA_PATH = joinpath(@__DIR__, "resources", "native_tls_ca.crt")
const _QUIC_SERVER_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server.crt")
const _QUIC_SERVER_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_server.key")

function _quic_client_config(;
    server_name::Union{Nothing, String} = "localhost",
    verify_peer::Bool = false,
    ca_file::Union{Nothing, String} = nothing,
    alpn_protocols::Vector{String} = String[],
    min_version::Union{Nothing, UInt16} = TLQ.TLS1_3_VERSION,
    max_version::Union{Nothing, UInt16} = nothing,
    session_tickets_disabled::Bool = false,
    curve_preferences::Vector{UInt16} = UInt16[],
)
    return TLQ.Config(;
        server_name,
        verify_peer,
        ca_file,
        alpn_protocols = copy(alpn_protocols),
        min_version,
        max_version,
        session_tickets_disabled,
        curve_preferences = copy(curve_preferences),
    )
end

function _quic_server_config(;
    cert_file::String = _QUIC_CERT_PATH,
    key_file::String = _QUIC_KEY_PATH,
    alpn_protocols::Vector{String} = String[],
    min_version::Union{Nothing, UInt16} = TLQ.TLS1_3_VERSION,
    max_version::Union{Nothing, UInt16} = nothing,
    curve_preferences::Vector{UInt16} = UInt16[],
)
    return TLQ.Config(;
        verify_peer = false,
        cert_file,
        key_file,
        alpn_protocols = copy(alpn_protocols),
        min_version,
        max_version,
        curve_preferences = copy(curve_preferences),
    )
end

mutable struct _QUICTestPeer
    conn::TLQ.QUICConn
    is_server::Bool
    read_secret::Dict{QEL.T, Tuple{UInt16, Vector{UInt8}}}
    write_secret::Dict{QEL.T, Tuple{UInt16, Vector{UInt8}}}
    got_params::Union{Nothing, Vector{UInt8}}
    got_error::Union{Nothing, TLQ.TLSError}
    complete::Bool
end

function _QUICTestPeer(conn::TLQ.QUICConn, is_server::Bool)
    return _QUICTestPeer(
        conn,
        is_server,
        Dict{QEL.T, Tuple{UInt16, Vector{UInt8}}}(),
        Dict{QEL.T, Tuple{UInt16, Vector{UInt8}}}(),
        nothing,
        nothing,
        false,
    )
end

function _quic_test_client(config::TLQ.Config; transport_parameters = UInt8[])
    conn = TLQ.quic_client(config)
    transport_parameters === nothing || TLQ.set_transport_parameters!(conn, transport_parameters)
    return _QUICTestPeer(conn, false)
end

function _quic_test_server(config::TLQ.Config; transport_parameters = UInt8[])
    conn = TLQ.quic_server(config)
    transport_parameters === nothing || TLQ.set_transport_parameters!(conn, transport_parameters)
    return _QUICTestPeer(conn, true)
end

function _quic_set_read_secret!(peer::_QUICTestPeer, level::QEL.T, suite::UInt16, secret::Vector{UInt8})
    @test level == QEL.Handshake || level == QEL.Application
    @test haskey(peer.write_secret, level)
    level == QEL.Application && @test peer.complete
    @test !haskey(peer.read_secret, level)
    peer.read_secret[level] = (suite, secret)
    return nothing
end

function _quic_set_write_secret!(peer::_QUICTestPeer, level::QEL.T, suite::UInt16, secret::Vector{UInt8})
    @test level == QEL.Handshake || level == QEL.Application
    @test !haskey(peer.write_secret, level)
    peer.write_secret[level] = (suite, secret)
    return nothing
end

# Drives both sides until neither has events left. Returns `nothing` once both
# handshakes complete, `:transport_parameters_required` when a side asks for
# parameters, or the `TLSError` that stopped the exchange.
function _run_quic_connection(cli::_QUICTestPeer, srv::_QUICTestPeer; on_event = nothing, send_ticket::Bool = true)
    try
        for peer in (cli, srv)
            peer.conn.started || TLQ.start!(peer.conn)
        end
        a, b = cli, srv
        idle = 0
        while true
            e = TLQ.next_event!(a.conn)
            on_event !== nothing && on_event(e, a, b) && continue
            if a.got_error !== nothing && e.kind != QEK.NoEvent
                error("unexpected event $(e.kind) after an Error event")
            end
            if e.kind == QEK.NoEvent
                idle += 1
                if idle == 2
                    (a.complete && b.complete) || error("handshake incomplete")
                    return nothing
                end
                a, b = b, a
                continue
            elseif e.kind == QEK.SetReadSecret
                _quic_set_read_secret!(a, e.level, e.suite, e.data)
            elseif e.kind == QEK.SetWriteSecret
                _quic_set_write_secret!(a, e.level, e.suite, e.data)
            elseif e.kind == QEK.WriteData
                TLQ.handle_data!(b.conn, e.level, e.data)
            elseif e.kind == QEK.TransportParameters
                a.got_params = e.data
            elseif e.kind == QEK.TransportParametersRequired
                return :transport_parameters_required
            elseif e.kind == QEK.HandshakeDone
                a.complete = true
                a.is_server && send_ticket && TLQ.send_session_ticket!(a.conn)
            elseif e.kind == QEK.Error
                e.err === nothing && error("Error event without an error")
                a.got_error = e.err
            end
            idle = 0
        end
    catch ex
        ex isa TLQ.TLSError && return ex
        rethrow()
    end
end

function _quic_handshake!(cli::_QUICTestPeer, srv::_QUICTestPeer; kwargs...)
    result = _run_quic_connection(cli, srv; kwargs...)
    @test result === nothing
    return result
end

function _quic_close_all!(peers::_QUICTestPeer...)
    for peer in peers
        close(peer.conn)
    end
    return nothing
end

@testset "TLS QUIC" begin
    @testset "a handshake failure with a non-String message is still reported" begin
        # ArgumentError's message is any AbstractString.
        err = Reseau.TLS._quic_error("handshake", ArgumentError(SubString("bad argument!", 1, 12)))
        @test err isa Reseau.TLS.TLSError
        @test occursin("bad argument", sprint(showerror, err))
    end

    @testset "handshake installs matching secrets at each level" begin
        cli = _quic_test_client(_quic_client_config())
        srv = _quic_test_server(_quic_server_config())
        try
            _quic_handshake!(cli, srv)
            for level in (QEL.Handshake, QEL.Application)
                @test haskey(cli.read_secret, level)
                @test haskey(srv.read_secret, level)
                @test cli.read_secret[level] == srv.write_secret[level]
                @test cli.write_secret[level] == srv.read_secret[level]
                @test !isempty(cli.read_secret[level][2])
            end
            @test cli.read_secret[QEL.Handshake][2] != cli.read_secret[QEL.Application][2]
            cli_state = TLQ.connection_state(cli.conn)
            srv_state = TLQ.connection_state(srv.conn)
            @test cli_state.handshake_complete
            @test srv_state.handshake_complete
            @test cli_state.version == "TLSv1.3"
            @test cli_state.cipher_suite == srv_state.cipher_suite
            @test cli_state.cipher_suite !== nothing
        finally
            _quic_close_all!(cli, srv)
        end
    end

    @testset "QUIC always negotiates TLS 1.3" begin
        for (client_kw, server_kw) in (
                ((;), (;)),
                ((; min_version = TLQ.TLS1_2_VERSION), (; min_version = TLQ.TLS1_2_VERSION)),
                ((; min_version = nothing), (; min_version = nothing)),
            )
            cli = _quic_test_client(_quic_client_config(; client_kw...))
            srv = _quic_test_server(_quic_server_config(; server_kw...))
            try
                _quic_handshake!(cli, srv)
                @test TLQ.connection_state(cli.conn).version == "TLSv1.3"
            finally
                _quic_close_all!(cli, srv)
            end
        end
        @test_throws TLQ.ConfigError TLQ.quic_client(_quic_client_config(min_version = TLQ.TLS1_2_VERSION, max_version = TLQ.TLS1_2_VERSION))
        @test_throws TLQ.ConfigError TLQ.quic_server(_quic_server_config(min_version = TLQ.TLS1_2_VERSION, max_version = TLQ.TLS1_2_VERSION))
    end

    @testset "ClientHello carries transport parameters and no compatibility session ID" begin
        params = Vector{UInt8}(codeunits("client params"))
        cli = _quic_test_client(_quic_client_config(); transport_parameters = params)
        try
            TLQ.start!(cli.conn)
            e = TLQ.next_event!(cli.conn)
            @test e.kind == QEK.WriteData
            @test e.level == QEL.Initial
            hello = TLQ._unmarshal_handshake_message_or_fail(e.data)
            @test hello isa TLQ._ClientHelloMsg
            @test isempty(hello.session_id)
            @test hello.quic_transport_parameters == params
            @test hello.supported_versions == [TLQ.TLS1_3_VERSION]
            @test TLQ.next_event!(cli.conn).kind == QEK.NoEvent
        finally
            close(cli.conn)
        end
    end

    @testset "HelloRetryRequest stays at the Initial level" begin
        # The client's single key share is X25519; the server insists on P-256.
        cli = _quic_test_client(_quic_client_config(curve_preferences = [TLQ.X25519, TLQ.P256]))
        srv = _quic_test_server(_quic_server_config(curve_preferences = [TLQ.P256]))
        try
            _quic_handshake!(cli, srv)
            @test TLQ.connection_state(cli.conn).did_hello_retry_request
            @test TLQ.connection_state(srv.conn).did_hello_retry_request
            @test TLQ.connection_state(cli.conn).curve == TLQ.connection_state(srv.conn).curve
        finally
            _quic_close_all!(cli, srv)
        end
    end

    @testset "session resumption through send_session_ticket!" begin
        client_config = _quic_client_config()
        server_config = _quic_server_config()
        cli = _quic_test_client(client_config)
        srv = _quic_test_server(server_config)
        try
            _quic_handshake!(cli, srv)
            @test !TLQ.connection_state(cli.conn).did_resume
            @test TLQ.connection_state(cli.conn).has_resumable_session
        finally
            _quic_close_all!(cli, srv)
        end

        cli2 = _quic_test_client(client_config)
        srv2 = _quic_test_server(server_config)
        try
            _quic_handshake!(cli2, srv2)
            @test TLQ.connection_state(cli2.conn).did_resume
            @test TLQ.connection_state(srv2.conn).did_resume
        finally
            _quic_close_all!(cli2, srv2)
        end

        cli3 = _quic_test_client(TLQ.Config(client_config; session_tickets_disabled = true))
        srv3 = _quic_test_server(server_config)
        try
            _quic_handshake!(cli3, srv3)
            @test !TLQ.connection_state(cli3.conn).did_resume
        finally
            _quic_close_all!(cli3, srv3)
        end
    end

    @testset "servers send no ticket unless asked" begin
        client_config = _quic_client_config()
        server_config = _quic_server_config()
        cli = _quic_test_client(client_config)
        srv = _quic_test_server(server_config)
        try
            _quic_handshake!(cli, srv; send_ticket = false)
            @test !TLQ.connection_state(cli.conn).has_resumable_session
        finally
            _quic_close_all!(cli, srv)
        end
    end

    @testset "send_session_ticket! misuse" begin
        cli = _quic_test_client(_quic_client_config())
        srv = _quic_test_server(_quic_server_config())
        try
            TLQ.start!(srv.conn)
            @test_throws TLQ.TLSError TLQ.send_session_ticket!(srv.conn)
            _quic_handshake!(cli, srv; send_ticket = false)
            @test_throws TLQ.TLSError TLQ.send_session_ticket!(cli.conn)
            TLQ.send_session_ticket!(srv.conn)
            @test_throws TLQ.TLSError TLQ.send_session_ticket!(srv.conn)
        finally
            _quic_close_all!(cli, srv)
        end
    end

    @testset "handshake data delivered one byte at a time" begin
        cli = _quic_test_client(_quic_client_config())
        srv = _quic_test_server(_quic_server_config())
        on_event = (e, a, b) -> begin
            e.kind == QEK.WriteData || return false
            for i in eachindex(e.data)
                TLQ.handle_data!(b.conn, e.level, e.data[i:i])
            end
            return true
        end
        try
            _quic_handshake!(cli, srv; on_event)
            @test TLQ.connection_state(cli.conn).has_resumable_session
        finally
            _quic_close_all!(cli, srv)
        end
    end

    @testset "handshake data at the wrong level is rejected" begin
        cli = _quic_test_client(_quic_client_config())
        srv = _quic_test_server(_quic_server_config())
        try
            TLQ.start!(cli.conn)
            TLQ.start!(srv.conn)
            e = TLQ.next_event!(cli.conn)
            @test e.kind == QEK.WriteData
            err = try
                TLQ.handle_data!(srv.conn, QEL.Handshake, e.data)
                nothing
            catch ex
                ex
            end
            @test err isa TLQ.TLSError
            @test occursin("wrong level", sprint(showerror, err))
        finally
            _quic_close_all!(cli, srv)
        end
    end

    @testset "post-handshake messages QUIC forbids" begin
        cert_request = TLQ._CertificateRequestMsgTLS13()
        cert_request.supported_signature_algorithms = UInt16[TLQ._TLS_SIGNATURE_ECDSA_SECP256R1_SHA256]
        forbidden = (
            ("certificate request", TLQ._marshal_certificate_request_tls13(cert_request), "unexpected"),
            ("key update", TLQ._tls13_key_update_message(false), "unexpected key update message"),
        )
        for (name, raw, expected) in forbidden
            cli = _quic_test_client(_quic_client_config())
            srv = _quic_test_server(_quic_server_config())
            try
                _quic_handshake!(cli, srv)
                err = try
                    TLQ.handle_data!(cli.conn, QEL.Application, raw)
                    nothing
                catch ex
                    ex
                end
                @test err isa TLQ.TLSError
                err isa TLQ.TLSError && @test occursin(expected, sprint(showerror, err))
                err isa TLQ.TLSError && @test TLQ.alert_code(err) == TLQ._TLS_ALERT_UNEXPECTED_MESSAGE
            finally
                _quic_close_all!(cli, srv)
            end
        end
    end

    @testset "servers accept no post-handshake messages" begin
        cli = _quic_test_client(_quic_client_config())
        srv = _quic_test_server(_quic_server_config())
        try
            _quic_handshake!(cli, srv)
            ticket = TLQ._NewSessionTicketMsgTLS13()
            ticket.lifetime = UInt32(60)
            ticket.label = UInt8[0x01]
            err = try
                TLQ.handle_data!(srv.conn, QEL.Application, TLQ._marshal_new_session_ticket_tls13(ticket))
                nothing
            catch ex
                ex
            end
            @test err isa TLQ.TLSError
            err isa TLQ.TLSError && @test TLQ.alert_code(err) == TLQ._TLS_ALERT_UNEXPECTED_MESSAGE
            # The failure is final: it comes back as an Error event too.
            e = TLQ.next_event!(srv.conn)
            @test e.kind == QEK.Error
            @test e.err === err
        finally
            _quic_close_all!(cli, srv)
        end
    end

    @testset "oversized post-handshake message" begin
        cli = _quic_test_client(_quic_client_config())
        srv = _quic_test_server(_quic_server_config())
        try
            _quic_handshake!(cli, srv)
            size = TLQ._tls_max_handshake_frame_size(TLQ._HANDSHAKE_TYPE_NEW_SESSION_TICKET) + 1
            header = UInt8[TLQ._HANDSHAKE_TYPE_NEW_SESSION_TICKET, UInt8((size >> 16) & 0xff), UInt8((size >> 8) & 0xff), UInt8(size & 0xff)]
            @test_throws TLQ.TLSError TLQ.handle_data!(cli.conn, QEL.Application, header)
        finally
            _quic_close_all!(cli, srv)
        end
    end

    @testset "certificate failure surfaces as an alert-carrying error" begin
        cli = _quic_test_client(_quic_client_config(server_name = "name", verify_peer = true, ca_file = _QUIC_CA_PATH))
        srv = _quic_test_server(_quic_server_config(cert_file = _QUIC_SERVER_CERT_PATH, key_file = _QUIC_SERVER_KEY_PATH))
        try
            err = _run_quic_connection(cli, srv)
            @test err isa TLQ.TLSError
            if err isa TLQ.TLSError
                @test TLQ.alert_code(err) == TLQ._TLS_ALERT_BAD_CERTIFICATE
                e = TLQ.next_event!(cli.conn)
                @test e.kind == QEK.Error
                @test e.err === err
                @test TLQ.next_event!(cli.conn).kind == QEK.NoEvent
            end
            @test !TLQ.connection_state(cli.conn).handshake_complete
        finally
            _quic_close_all!(cli, srv)
        end
    end

    @testset "ALPN is negotiated and required" begin
        cli = _quic_test_client(_quic_client_config(alpn_protocols = ["h3"]))
        srv = _quic_test_server(_quic_server_config(alpn_protocols = ["h3"]))
        server_alpn_seen = Ref(false)
        on_event = (e, a, b) -> begin
            if a === srv && e.kind == QEK.SetReadSecret && e.level == QEL.Handshake
                server_alpn_seen[] = TLQ.connection_state(srv.conn).alpn_protocol == "h3"
            end
            return false
        end
        try
            _quic_handshake!(cli, srv; on_event)
            @test server_alpn_seen[]
            @test TLQ.connection_state(cli.conn).alpn_protocol == "h3"
            @test TLQ.connection_state(srv.conn).alpn_protocol == "h3"
        finally
            _quic_close_all!(cli, srv)
        end

        # RFC 9001 Section 8.1: a server with ALPN configured refuses a client
        # that offers none, and a client refuses a server that selects none.
        for (client_alpn, server_alpn) in ((String[], ["h3"]), (["h3"], String[]))
            cli = _quic_test_client(_quic_client_config(alpn_protocols = client_alpn))
            srv = _quic_test_server(_quic_server_config(alpn_protocols = server_alpn))
            try
                err = _run_quic_connection(cli, srv)
                @test err isa TLQ.TLSError
                err isa TLQ.TLSError && @test TLQ.alert_code(err) == TLQ._TLS_ALERT_NO_APPLICATION_PROTOCOL
            finally
                _quic_close_all!(cli, srv)
            end
        end
    end

    @testset "transport parameters can be supplied late" begin
        cli = _quic_test_client(_quic_client_config(); transport_parameters = nothing)
        srv = _quic_test_server(_quic_server_config(); transport_parameters = nothing)
        try
            @test _run_quic_connection(cli, srv) === :transport_parameters_required
            TLQ.set_transport_parameters!(cli.conn, codeunits("client params"))
            @test _run_quic_connection(cli, srv) === :transport_parameters_required
            TLQ.set_transport_parameters!(srv.conn, codeunits("server params"))
            _quic_handshake!(cli, srv)
            @test cli.got_params == codeunits("server params")
            @test srv.got_params == codeunits("client params")
        finally
            _quic_close_all!(cli, srv)
        end
    end

    @testset "empty transport parameters are still delivered" begin
        cli = _quic_test_client(_quic_client_config())
        srv = _quic_test_server(_quic_server_config())
        try
            _quic_handshake!(cli, srv)
            @test cli.got_params == UInt8[]
            @test srv.got_params == UInt8[]
        finally
            _quic_close_all!(cli, srv)
        end
    end

    @testset "servers reject a ClientHello without transport parameters" begin
        srv = _quic_test_server(_quic_server_config())
        try
            TLQ.start!(srv.conn)
            hello = TLQ._tls13_client_hello(_quic_client_config())
            TLQ._tls13_prepare_initial_client_hello!(TLQ._TLS13OpenSSLKeyShareProvider(), hello)
            err = try
                TLQ.handle_data!(srv.conn, QEL.Initial, TLQ._marshal_client_hello(hello))
                nothing
            catch ex
                ex
            end
            @test err isa TLQ.TLSError
            err isa TLQ.TLSError && @test TLQ.alert_code(err) == TLQ._TLS_ALERT_MISSING_EXTENSION
        finally
            close(srv.conn)
        end
    end

    @testset "close stops a blocked handshake" begin
        # Waiting for handshake bytes.
        cli = _quic_test_client(_quic_client_config())
        TLQ.start!(cli.conn)
        while TLQ.next_event!(cli.conn).kind != QEK.NoEvent
        end
        close(cli.conn)
        @test !TLQ.connection_state(cli.conn).handshake_complete
        @test_throws TLQ.TLSError TLQ.handle_data!(cli.conn, QEL.Initial, UInt8[0x02, 0x00, 0x00, 0x00])
        close(cli.conn)

        # Waiting for transport parameters.
        cli = _quic_test_client(_quic_client_config(); transport_parameters = nothing)
        TLQ.start!(cli.conn)
        @test TLQ.next_event!(cli.conn).kind == QEK.TransportParametersRequired
        close(cli.conn)
        @test !TLQ.connection_state(cli.conn).handshake_complete

        # Never started.
        cli = _quic_test_client(_quic_client_config())
        close(cli.conn)
        @test_throws TLQ.TLSError TLQ.start!(cli.conn)
    end

    @testset "start! runs once" begin
        cli = _quic_test_client(_quic_client_config())
        try
            TLQ.start!(cli.conn)
            @test_throws TLQ.TLSError TLQ.start!(cli.conn)
        finally
            close(cli.conn)
        end
    end
end
