using Test
using Reseau

const TL12N = Reseau.TLS
const NC12N = Reseau.TCP
const IP12N = Reseau.IOPoll

const _TLS12_NATIVE_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS12_NATIVE_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")
const _TLS12_NATIVE_CA_PATH = joinpath(@__DIR__, "resources", "native_tls_ca.crt")
const _TLS12_NATIVE_SERVER_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server.crt")
const _TLS12_NATIVE_SERVER_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_server.key")
const _TLS12_NATIVE_CLIENT_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_client.crt")
const _TLS12_NATIVE_CLIENT_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_client.key")
const _TLS12_NATIVE_ECDSA_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server_ecdsa.crt")
const _TLS12_NATIVE_ECDSA_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_server_ecdsa.key")

function _tls12_native_close_quiet!(x)
    x === nothing && return nothing
    try
        close(x)
    catch
    end
    return nothing
end

function _tls12_native_wait_task(task::Task, timeout_s::Float64 = 5.0)
    return IP12N.timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
end

function _tls12_native_client_config(;
    verify_peer::Bool = false,
    verify_hostname::Bool = verify_peer,
    server_name::Union{Nothing, String} = "localhost",
    ca_file::Union{Nothing, String} = nothing,
    cert_file::Union{Nothing, String} = nothing,
    key_file::Union{Nothing, String} = nothing,
    alpn_protocols::Vector{String} = String[],
    curve_preferences::Vector{UInt16} = UInt16[],
)
    return TL12N.Config(
        server_name = server_name,
        verify_peer = verify_peer,
        verify_hostname = verify_hostname,
        ca_file = ca_file,
        cert_file = cert_file,
        key_file = key_file,
        alpn_protocols = copy(alpn_protocols),
        curve_preferences = copy(curve_preferences),
        min_version = TL12N.TLS1_2_VERSION,
        max_version = TL12N.TLS1_2_VERSION,
        handshake_timeout_ns = 10_000_000_000,
    )
end

function _tls12_server_config(;
    alpn_protocols::Vector{String} = String[],
    cert_file::String = _TLS12_NATIVE_CERT_PATH,
    key_file::String = _TLS12_NATIVE_KEY_PATH,
    client_auth::TL12N.ClientAuthMode.T = TL12N.ClientAuthMode.NoClientCert,
    client_ca_file::Union{Nothing, String} = nothing,
    curve_preferences::Vector{UInt16} = UInt16[],
)
    return TL12N.Config(
        verify_peer = false,
        cert_file = cert_file,
        key_file = key_file,
        client_auth = client_auth,
        client_ca_file = client_ca_file,
        alpn_protocols = copy(alpn_protocols),
        curve_preferences = copy(curve_preferences),
        min_version = TL12N.TLS1_2_VERSION,
        max_version = TL12N.TLS1_2_VERSION,
        handshake_timeout_ns = 10_000_000_000,
    )
end

function _tls12_run_public_roundtrip(server_config::TL12N.Config, client_config::TL12N.Config)
    listener = nothing
    client = nothing
    task = nothing
    try
        listener, addr, task = _start_tls12_server(server_config; handler = conn -> begin
            write(conn, UInt8[0x6f, 0x6b])
            read(conn, 2) == UInt8[0x61, 0x63] || error("unexpected TLS 1.2 client ack")
            return TL12N.connection_state(conn)
        end)
        client = TL12N.connect(addr, client_config)
        client_state = TL12N.connection_state(client)
        read(client, 2) == UInt8[0x6f, 0x6b] || error("unexpected TLS 1.2 server bytes")
        write(client, UInt8[0x61, 0x63]) == 2 || error("unexpected TLS 1.2 client ack write")
        _tls12_native_wait_task(task, 5.0) != :timed_out || error("timed out waiting for TLS 1.2 server task")
        return client_state, fetch(task)::TL12N.ConnectionState
    finally
        _tls12_native_close_quiet!(client)
        if task !== nothing
            try
                wait(task)
            catch
            end
        end
        _tls12_native_close_quiet!(listener)
    end
end

function _start_tls12_server(config::TL12N.Config; handler)
    listener = TL12N.listen(NC12N.loopback_addr(0), config; backlog = 8)
    addr = TL12N.addr(listener)::NC12N.SocketAddrV4
    task = Threads.@spawn begin
        conn = TL12N.accept(listener)
        try
            TL12N.handshake!(conn)
            return handler(conn)
        catch
            rethrow()
        finally
            _tls12_native_close_quiet!(conn)
        end
    end
    return listener, addr, task
end

function _tls12_open_tcp_pair()
    listener = NC12N.listen(NC12N.loopback_addr(0); backlog = 1)
    addr = NC12N.addr(listener)::NC12N.SocketAddrV4
    accept_task = errormonitor(Threads.@spawn NC12N.accept(listener))
    client = NC12N.connect(addr)
    status = _tls12_native_wait_task(accept_task, 5.0)
    status == :timed_out && error("timed out waiting for TCP accept")
    server = fetch(accept_task)
    return listener, client, server
end

function _tls12_unexpected_message_error(f)
    err = try
        f()
        nothing
    catch err
        err
    end
    @test err isa TL12N._TLSAlertError
    tls_err = err::TL12N._TLSAlertError
    @test tls_err.alert == TL12N._TLS_ALERT_UNEXPECTED_MESSAGE
    return tls_err
end

@testset "TLS native TLS1.2 client" begin
    @test TL12N._native_tls12_only(_tls12_native_client_config())
    @test !TL12N._native_tls12_only(TL12N.Config(server_name = "localhost", verify_peer = false))
    @test TL12N._native_tls12_server_enabled(_tls12_server_config())
    @test TL12N._native_tls12_server_enabled(TL12N.Config(
        cert_file = _TLS12_NATIVE_CERT_PATH,
        key_file = _TLS12_NATIVE_KEY_PATH,
        client_auth = TL12N.ClientAuthMode.RequireAnyClientCert,
        min_version = TL12N.TLS1_2_VERSION,
        max_version = TL12N.TLS1_2_VERSION,
    ))

    @testset "record layer roundtrip encrypts and decrypts application data" begin
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        try
            listener, client_tcp, server_tcp = _tls12_open_tcp_pair()
            client_state = TL12N._TLS12NativeState()
            server_state = TL12N._TLS12NativeState()
            write_key = UInt8[UInt8(0x10 + i) for i in 0:15]
            write_iv = UInt8[0xa0, 0xa1, 0xa2, 0xa3]
            TL12N._tls12_set_write_cipher!(client_state, TL12N._TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256, write_key, write_iv)
            TL12N._tls12_set_read_cipher!(server_state, TL12N._TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256, write_key, write_iv)
            TL12N._tls12_write_record!(client_tcp, client_state.write_cipher, TL12N._TLS_RECORD_TYPE_APPLICATION_DATA, UInt8[0x61, 0x62, 0x63])
            TL12N._tls12_read_record!(server_tcp, server_state)
            @test server_state.plaintext_buffer == UInt8[0x61, 0x62, 0x63]
        finally
            _tls12_native_close_quiet!(server_tcp)
            _tls12_native_close_quiet!(client_tcp)
            _tls12_native_close_quiet!(listener)
        end
    end

    @testset "plaintext application data before ChangeCipherSpec is rejected" begin
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        try
            listener, client_tcp, server_tcp = _tls12_open_tcp_pair()
            state = TL12N._TLS12NativeState()
            TL12N._tls_write_tls_plaintext!(client_tcp, TL12N._TLS_RECORD_TYPE_APPLICATION_DATA, UInt8[0x61], TL12N.TLS1_2_VERSION)
            tls_err = _tls12_unexpected_message_error(() -> TL12N._tls12_read_record!(server_tcp, state))
            @test !tls_err.from_peer
        finally
            _tls12_native_close_quiet!(server_tcp)
            _tls12_native_close_quiet!(client_tcp)
            _tls12_native_close_quiet!(listener)
        end
    end

    @testset "post-handshake ChangeCipherSpec is rejected" begin
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        try
            listener, client_tcp, server_tcp = _tls12_open_tcp_pair()
            state = TL12N._TLS12NativeState()
            read_key = UInt8[UInt8(0x20 + i) for i in 0:15]
            read_iv = UInt8[0xb0, 0xb1, 0xb2, 0xb3]
            TL12N._tls12_set_read_cipher!(state, TL12N._TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256, read_key, read_iv)
            TL12N._tls_write_tls_plaintext!(client_tcp, TL12N._TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC, UInt8[0x01], TL12N.TLS1_2_VERSION)
            tls_err = _tls12_unexpected_message_error(() -> TL12N._tls12_read_record!(server_tcp, state))
            @test !tls_err.from_peer
        finally
            _tls12_native_close_quiet!(server_tcp)
            _tls12_native_close_quiet!(client_tcp)
            _tls12_native_close_quiet!(listener)
        end
    end

    @testset "post-handshake handshake records are rejected" begin
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        try
            listener, client_tcp, server_tcp = _tls12_open_tcp_pair()
            write_key = UInt8[UInt8(0x40 + i) for i in 0:15]
            write_iv = UInt8[0xc0, 0xc1, 0xc2, 0xc3]
            client_state = TL12N._TLS12NativeState()
            server_state = TL12N._TLS12NativeState()
            TL12N._tls12_set_write_cipher!(client_state, TL12N._TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256, write_key, write_iv)
            TL12N._tls12_set_read_cipher!(server_state, TL12N._TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256, write_key, write_iv)
            hello_request = UInt8[0x00, 0x00, 0x00, 0x00]
            TL12N._tls12_write_record!(client_tcp, client_state.write_cipher, TL12N._TLS_RECORD_TYPE_HANDSHAKE, hello_request)
            tls_err = _tls12_unexpected_message_error(() -> TL12N._tls12_read_record!(server_tcp, server_state))
            @test !tls_err.from_peer
        finally
            _tls12_native_close_quiet!(server_tcp)
            _tls12_native_close_quiet!(client_tcp)
            _tls12_native_close_quiet!(listener)
        end
    end

    @testset "server hello does not echo the client session id without resumption" begin
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        state = nothing
        try
            listener, client_tcp, server_tcp = _tls12_open_tcp_pair()
            state = TL12N._TLS12ServerHandshakeState(_tls12_server_config())
            hello = TL12N._tls12_client_hello(_tls12_native_client_config(alpn_protocols = ["h2"]))
            state.client_hello = hello
            state.cipher_suite = TL12N._TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256_ID
            state.selected_alpn = "h2"
            io = TL12N._TLS12HandshakeRecordIO(server_tcp, TL12N._TLS12NativeState())
            transcript = TL12N._TranscriptHash(TL12N._HASH_SHA256)
            TL12N._tls12_send_server_hello!(state, io, transcript, TL12N._marshal_handshake_message(hello), _tls12_server_config())
            @test !isempty(hello.session_id)
            @test isempty(state.server_hello.session_id)
        finally
            state === nothing || TL12N._securezero_tls12_server_handshake_state!(state)
            _tls12_native_close_quiet!(server_tcp)
            _tls12_native_close_quiet!(client_tcp)
            _tls12_native_close_quiet!(listener)
        end
    end

    @testset "malformed TLS 1.2 ClientKeyExchange reports illegal_parameter" begin
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        state = nothing
        try
            listener, client_tcp, server_tcp = _tls12_open_tcp_pair()
            state = TL12N._TLS12ServerHandshakeState(_tls12_server_config())
            state.curve_id = TL12N.P256
            client_io = TL12N._TLS12HandshakeRecordIO(client_tcp, TL12N._TLS12NativeState())
            server_io = TL12N._TLS12HandshakeRecordIO(server_tcp, TL12N._TLS12NativeState())
            malformed = TL12N._ClientKeyExchangeMsgTLS12(vcat(UInt8[0x41, 0x02], zeros(UInt8, 64)))
            TL12N._write_handshake_bytes!(client_io, TL12N._marshal_handshake_message(malformed))
            err = try
                TL12N._tls12_read_client_key_exchange!(state, server_io, TL12N._TranscriptHash(TL12N._HASH_SHA256))
                nothing
            catch ex
                ex
            end
            @test err isa TL12N._TLSAlertError
            if err isa TL12N._TLSAlertError
                @test (err::TL12N._TLSAlertError).alert == TL12N._TLS_ALERT_ILLEGAL_PARAMETER
            end
        finally
            state === nothing || TL12N._securezero_tls12_server_handshake_state!(state)
            _tls12_native_close_quiet!(server_tcp)
            _tls12_native_close_quiet!(client_tcp)
            _tls12_native_close_quiet!(listener)
        end
    end

    @testset "exact TLS 1.2 native client and server handshake through public APIs" begin
        listener = nothing
        client = nothing
        task = nothing
        try
            listener, addr, task = _start_tls12_server(_tls12_server_config(alpn_protocols = ["h2"]); handler = conn -> begin
                state = TL12N.connection_state(conn)
                @test state.handshake_complete
                @test state.version == "TLSv1.2"
                @test state.alpn_protocol == "h2"
                @test state.cipher_suite in (
                    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
                )
                @test !state.using_native_tls13
                @test state.curve == "P-256"
                @test read(conn, 4) == UInt8[0x70, 0x69, 0x6e, 0x67]
                write(conn, UInt8[0x70, 0x6f, 0x6e, 0x67])
                nothing
            end)

            client = TL12N.connect(addr, _tls12_native_client_config(alpn_protocols = ["h2"]))
            TL12N.handshake!(client)
            state = TL12N.connection_state(client)
            @test state.handshake_complete
            @test state.version == "TLSv1.2"
            @test state.alpn_protocol == "h2"
            @test state.cipher_suite in (
                "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
                "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            )
            @test !state.using_native_tls13
            @test state.curve == "P-256"

            write(client, UInt8[0x70, 0x69, 0x6e, 0x67])
            @test read(client, 4) == UInt8[0x70, 0x6f, 0x6e, 0x67]

            @test _tls12_native_wait_task(task, 5.0) != :timed_out
            wait(task)
        finally
            _tls12_native_close_quiet!(client)
            if task !== nothing
                try
                    wait(task)
                catch
                end
            end
            _tls12_native_close_quiet!(listener)
        end
    end

    @testset "exact TLS 1.2 curve preferences can negotiate X25519 natively" begin
        server_cfg = _tls12_server_config(curve_preferences = UInt16[TL12N.X25519])
        client_cfg = _tls12_native_client_config(curve_preferences = UInt16[TL12N.X25519])
        client_state, server_state = _tls12_run_public_roundtrip(server_cfg, client_cfg)
        @test client_state.handshake_complete
        @test server_state.handshake_complete
        @test client_state.version == "TLSv1.2"
        @test server_state.version == "TLSv1.2"
        @test client_state.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        @test server_state.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        @test client_state.curve == "X25519"
        @test server_state.curve == "X25519"
    end

    @testset "exact TLS 1.2 client verifies the server certificate" begin
        listener = nothing
        client = nothing
        task = nothing
        try
            listener, addr, task = _start_tls12_server(_tls12_server_config(); handler = conn -> begin
                write(conn, UInt8[0x6f, 0x6b])
                nothing
            end)

            client = TL12N.connect(addr, _tls12_native_client_config(
                verify_peer = true,
                verify_hostname = true,
                ca_file = _TLS12_NATIVE_CERT_PATH,
            ))
            TL12N.handshake!(client)
            @test TL12N.connection_state(client).version == "TLSv1.2"
            @test read(client, 2) == UInt8[0x6f, 0x6b]
            @test _tls12_native_wait_task(task, 5.0) != :timed_out
            wait(task)
        finally
            _tls12_native_close_quiet!(client)
            if task !== nothing
                try
                    wait(task)
                catch
                end
            end
            _tls12_native_close_quiet!(listener)
        end
    end

    @testset "native TLS 1.2 server interoperates with OpenSSL client path" begin
        listener = nothing
        client = nothing
        task = nothing
        try
            listener, addr, task = _start_tls12_server(_tls12_server_config(alpn_protocols = ["h2"]); handler = conn -> begin
                @test read(conn, 5) == UInt8[0x68, 0x65, 0x6c, 0x6c, 0x6f]
                write(conn, UInt8[0x77, 0x6f, 0x72, 0x6c, 0x64])
                nothing
            end)

            client = TL12N.connect(addr, TL12N.Config(
                verify_peer = true,
                verify_hostname = true,
                server_name = "localhost",
                ca_file = _TLS12_NATIVE_CERT_PATH,
                alpn_protocols = ["h2"],
                handshake_timeout_ns = 10_000_000_000,
                min_version = nothing,
                max_version = TL12N.TLS1_2_VERSION,
            ))
            TL12N.handshake!(client)
            state = TL12N.connection_state(client)
            @test state.handshake_complete
            @test state.version == "TLSv1.2"
            @test state.alpn_protocol == "h2"
            @test !state.using_native_tls13

            write(client, UInt8[0x68, 0x65, 0x6c, 0x6c, 0x6f])
            @test read(client, 5) == UInt8[0x77, 0x6f, 0x72, 0x6c, 0x64]

            @test _tls12_native_wait_task(task, 5.0) != :timed_out
            wait(task)
        finally
            _tls12_native_close_quiet!(client)
            if task !== nothing
                try
                    wait(task)
                catch
                end
            end
            _tls12_native_close_quiet!(listener)
        end
    end

    @testset "exact TLS 1.2 mTLS resumes through public APIs" begin
        server_cfg = _tls12_server_config(
            cert_file = _TLS12_NATIVE_SERVER_CERT_PATH,
            key_file = _TLS12_NATIVE_SERVER_KEY_PATH,
            client_auth = TL12N.ClientAuthMode.RequireAndVerifyClientCert,
            client_ca_file = _TLS12_NATIVE_CA_PATH,
        )
        client_cfg = _tls12_native_client_config(
            verify_peer = true,
            verify_hostname = true,
            ca_file = _TLS12_NATIVE_CA_PATH,
            cert_file = _TLS12_NATIVE_CLIENT_CERT_PATH,
            key_file = _TLS12_NATIVE_CLIENT_KEY_PATH,
        )

        client_state1, server_state1 = _tls12_run_public_roundtrip(server_cfg, client_cfg)
        @test client_state1.handshake_complete
        @test server_state1.handshake_complete
        @test client_state1.version == "TLSv1.2"
        @test server_state1.version == "TLSv1.2"
        @test client_state1.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        @test server_state1.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        @test !client_state1.did_resume
        @test !server_state1.did_resume
        @test client_state1.has_resumable_session
        @test client_state1.curve == "P-256"
        @test server_state1.curve == "P-256"

        client_state2, server_state2 = _tls12_run_public_roundtrip(server_cfg, client_cfg)
        @test client_state2.handshake_complete
        @test server_state2.handshake_complete
        @test client_state2.version == "TLSv1.2"
        @test server_state2.version == "TLSv1.2"
        @test client_state2.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        @test server_state2.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        @test client_state2.did_resume
        @test server_state2.did_resume
        @test client_state2.has_resumable_session
        @test client_state2.curve == "P-256"
        @test server_state2.curve == "P-256"
    end

    @testset "exact TLS 1.2 ECDSA server certificates negotiate ECDHE-ECDSA" begin
        server_cfg = _tls12_server_config(
            cert_file = _TLS12_NATIVE_ECDSA_CERT_PATH,
            key_file = _TLS12_NATIVE_ECDSA_KEY_PATH,
        )
        client_cfg = _tls12_native_client_config(
            verify_peer = true,
            verify_hostname = false,
            ca_file = _TLS12_NATIVE_ECDSA_CERT_PATH,
        )
        client_state, server_state = _tls12_run_public_roundtrip(server_cfg, client_cfg)
        @test client_state.handshake_complete
        @test server_state.handshake_complete
        @test client_state.version == "TLSv1.2"
        @test server_state.version == "TLSv1.2"
        @test client_state.cipher_suite == "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        @test server_state.cipher_suite == "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
        @test client_state.curve == "P-256"
        @test server_state.curve == "P-256"
    end

    @testset "exact TLS 1.2 ECDSA CN-only certificates are rejected by hostname verification" begin
        server_cfg = _tls12_server_config(
            cert_file = _TLS12_NATIVE_ECDSA_CERT_PATH,
            key_file = _TLS12_NATIVE_ECDSA_KEY_PATH,
        )
        client_cfg = _tls12_native_client_config(
            verify_peer = true,
            verify_hostname = true,
            ca_file = _TLS12_NATIVE_ECDSA_CERT_PATH,
        )
        handler_ran = Ref(false)
        listener = nothing
        server_task = nothing
        try
            listener, addr, server_task = _start_tls12_server(server_cfg; handler = conn -> begin
                handler_ran[] = true
                write(conn, UInt8[0x6f, 0x6b])
                read(conn, 2) == UInt8[0x61, 0x63] || error("unexpected TLS 1.2 client ack")
                return TL12N.connection_state(conn)
            end)
            err = try
                TL12N.connect(addr, client_cfg)
                nothing
            catch ex
                ex
            end
            @test err isa TL12N.TLSError
            if err isa TL12N.TLSError
                @test occursin("legacy Common Name", err.message)
            end
            _tls12_native_wait_task(server_task, 5.0) != :timed_out || error("timed out waiting for TLS 1.2 server task")
            server_err = try
                wait(server_task)
                nothing
            catch ex
                ex
            end
            @test !handler_ran[]
            @test server_err !== nothing
        finally
            _tls12_native_close_quiet!(listener)
            IP12N.shutdown!()
        end
    end
end
