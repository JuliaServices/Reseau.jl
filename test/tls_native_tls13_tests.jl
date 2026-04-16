using Test
using Reseau

const TLN = Reseau.TLS
const NCN = Reseau.TCP
const IPN = Reseau.IOPoll

const _TLS_NATIVE_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS_NATIVE_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")

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
    return client_state, server_state, server_to_client_secret, client_to_server_secret
end

function _tls13_native_client_config(;
    verify_peer::Bool = false,
    server_name::Union{Nothing, String} = "localhost",
    ca_file::Union{Nothing, String} = nothing,
    alpn_protocols::Vector{String} = String[],
)
    return TLN.Config(
        server_name = server_name,
        verify_peer = verify_peer,
        ca_file = ca_file,
        alpn_protocols = copy(alpn_protocols),
        min_version = TLN.TLS1_3_VERSION,
        max_version = TLN.TLS1_3_VERSION,
        handshake_timeout_ns = 10_000_000_000,
    )
end

function _tls13_native_server_config(; alpn_protocols::Vector{String} = String[])
    return TLN.Config(
        verify_peer = false,
        cert_file = _TLS_NATIVE_CERT_PATH,
        key_file = _TLS_NATIVE_KEY_PATH,
        alpn_protocols = copy(alpn_protocols),
        handshake_timeout_ns = 10_000_000_000,
        min_version = TLN.TLS1_3_VERSION,
        max_version = TLN.TLS1_3_VERSION,
    )
end

function _tls13_openssl_server_config(; alpn_protocols::Vector{String} = String[])
    return TLN.Config(
        verify_peer = false,
        cert_file = _TLS_NATIVE_CERT_PATH,
        key_file = _TLS_NATIVE_KEY_PATH,
        alpn_protocols = copy(alpn_protocols),
        handshake_timeout_ns = 10_000_000_000,
    )
end

function _tls_native_set_server_ciphersuites!(conn::TLN.Conn, suites::AbstractString)::Nothing
    ok = ccall((:SSL_set_ciphersuites, TLN._LIBSSL_PATH), Cint, (Ptr{Cvoid}, Cstring), conn.ssl, suites)
    ok == 1 || throw(TLN._make_tls_error("SSL_set_ciphersuites", Int32(ok)))
    return nothing
end

function _tls_native_set_server_groups_list!(conn::TLN.Conn, groups::AbstractString)::Nothing
    # This OpenSSL build does not export `SSL_set1_groups_list`, so mirror the
    # macro expansion through `SSL_ctrl` instead.
    ok = ccall((:SSL_ctrl, TLN._LIBSSL_PATH), Clong, (Ptr{Cvoid}, Cint, Clong, Cstring), conn.ssl, Cint(92), Clong(0), groups)
    ok == 1 || throw(TLN._make_tls_error("SSL_set1_groups_list", Int32(ok)))
    return nothing
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

@testset "TLS native TLS1.3 client" begin
    @test TLN._native_tls13_client_enabled(_tls13_native_client_config())
    @test !TLN._native_tls13_client_enabled(TLN.Config(server_name = "localhost", verify_peer = false))
    @test !TLN._native_tls13_client_enabled(TLN.Config(
        server_name = "localhost",
        verify_peer = false,
        cert_file = _TLS_NATIVE_CERT_PATH,
        key_file = _TLS_NATIVE_KEY_PATH,
        min_version = TLN.TLS1_3_VERSION,
        max_version = TLN.TLS1_3_VERSION,
    ))
    @test TLN._native_tls13_server_enabled(_tls13_native_server_config())

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
                TLN._tls13_write_record!(server_tcp, server_state.write_cipher, TLN._TLS_RECORD_TYPE_HANDSHAKE, request_key_update)
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
                nothing,
                TLN._TLS_RECORD_TYPE_APPLICATION_DATA,
                fill(UInt8(0x00), TLN._TLS13_MAX_PLAINTEXT + 1),
            )
            write_cipher = client_state.write_cipher::TLN._TLS13RecordCipherState
            write_cipher.seq = typemax(UInt64)
            TLN._tls13_write_record!(client_tcp, client_state.write_cipher, TLN._TLS_RECORD_TYPE_APPLICATION_DATA, UInt8[0xaa])
            @test write_cipher.exhausted
            @test_throws ArgumentError TLN._tls13_write_record!(
                client_tcp,
                client_state.write_cipher,
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
            @test client.mode == TLN._TLS_CONN_MODE_NATIVE_TLS13_CLIENT
            @test server.mode == TLN._TLS_CONN_MODE_NATIVE_TLS13_SERVER
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

    @testset "native client negotiates AES_256_GCM_SHA384" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(
                _tls13_openssl_server_config();
                configure = conn -> _tls_native_set_server_ciphersuites!(conn, "TLS_AES_256_GCM_SHA384"),
            )
            client = TLN.connect(addr, _tls13_native_client_config(server_name = "localhost", verify_peer = false))
            _finish_tls13_native_server!(server_task::Task)
            server = fetch(server_task::Task)
            client_native_state = client.native_state::TLN._TLS13NativeClientState
            @test client_native_state.read_cipher !== nothing
            @test client_native_state.write_cipher !== nothing
            @test (client_native_state.read_cipher::TLN._TLS13RecordCipherState).spec == TLN._TLS13_AES_256_GCM_SHA384
            @test TLN.connection_state(client).cipher_suite == "TLS_AES_256_GCM_SHA384"
            server_reply = UInt8[0x93]
            @test write(server, server_reply) == length(server_reply)
            @test read(client, length(server_reply)) == server_reply
            payload = UInt8[0x26, 0x56]
            @test write(client, payload) == length(payload)
            @test read(server, length(payload)) == payload
        finally
            _tls_native_close_quiet!(server)
            _tls_native_close_quiet!(client)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native client negotiates CHACHA20_POLY1305_SHA256" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(
                _tls13_openssl_server_config();
                configure = conn -> _tls_native_set_server_ciphersuites!(conn, "TLS_CHACHA20_POLY1305_SHA256"),
            )
            client = TLN.connect(addr, _tls13_native_client_config(server_name = "localhost", verify_peer = false))
            _finish_tls13_native_server!(server_task::Task)
            server = fetch(server_task::Task)
            client_native_state = client.native_state::TLN._TLS13NativeClientState
            @test client_native_state.read_cipher !== nothing
            @test client_native_state.write_cipher !== nothing
            @test (client_native_state.read_cipher::TLN._TLS13RecordCipherState).spec == TLN._TLS13_CHACHA20_POLY1305_SHA256
            @test TLN.connection_state(client).cipher_suite == "TLS_CHACHA20_POLY1305_SHA256"
            payload = UInt8[0xca, 0xfe, 0x13]
            @test write(client, payload) == length(payload)
            @test read(server, length(payload)) == payload
        finally
            _tls_native_close_quiet!(server)
            _tls_native_close_quiet!(client)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native client handles HelloRetryRequest with P-256" begin
        IPN.shutdown!()
        listener = nothing
        client = nothing
        server_task = nothing
        try
            listener, addr, server_task, _ = _start_tls13_native_server(
                _tls13_openssl_server_config();
                configure = conn -> _tls_native_set_server_groups_list!(conn, "P-256"),
            )
            client = TLN.connect(addr, _tls13_native_client_config(server_name = "localhost", verify_peer = false))
            _finish_tls13_native_server!(server_task::Task)
            client_state = TLN.connection_state(client)
            @test client_state.did_hello_retry_request
            @test client_state.curve == "P-256"
        finally
            _tls_native_close_quiet!(client)
            server_task isa Task && _finish_tls13_native_server!(server_task)
            _tls_native_close_quiet!(listener)
            IPN.shutdown!()
        end
    end

    @testset "native client resumes TLS 1.3 sessions on a reused Config" begin
        IPN.shutdown!()
        listener = nothing
        client1 = nothing
        client2 = nothing
        server_task = nothing
        try
            listener = TLN.listen(NCN.loopback_addr(0), _tls13_openssl_server_config(); backlog = 8)
            addr = TLN.addr(listener)::NCN.SocketAddrV4
            server_task = Threads.@spawn begin
                conns = TLN.Conn[]
                for i in 1:2
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
            @test TLN.connection_state(client1).has_resumable_session

            client2 = TLN.connect(addr, client_config)
            @test read(client2, 1) == UInt8[0x02]
            @test eof(client2)
            @test TLN.connection_state(client2).did_resume

            status = _tls_native_wait_task(server_task::Task, 5.0)
            status == :timed_out && error("timed out waiting for TLS session resumption server")
            wait(server_task::Task)
        finally
            _tls_native_close_quiet!(client2)
            _tls_native_close_quiet!(client1)
            server_task isa Task && wait(server_task)
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
