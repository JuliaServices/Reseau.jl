using Test
using Reseau

const TL12N = Reseau.TLS
const NC12N = Reseau.TCP
const IP12N = Reseau.IOPoll

const _TLS12_NATIVE_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS12_NATIVE_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")

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
    alpn_protocols::Vector{String} = String[],
)
    return TL12N.Config(
        server_name = server_name,
        verify_peer = verify_peer,
        verify_hostname = verify_hostname,
        ca_file = ca_file,
        alpn_protocols = copy(alpn_protocols),
        min_version = TL12N.TLS1_2_VERSION,
        max_version = TL12N.TLS1_2_VERSION,
        handshake_timeout_ns = 10_000_000_000,
    )
end

function _tls12_openssl_server_config(; alpn_protocols::Vector{String} = String[])
    return TL12N.Config(
        verify_peer = false,
        cert_file = _TLS12_NATIVE_CERT_PATH,
        key_file = _TLS12_NATIVE_KEY_PATH,
        alpn_protocols = copy(alpn_protocols),
        min_version = TL12N.TLS1_2_VERSION,
        max_version = TL12N.TLS1_2_VERSION,
        handshake_timeout_ns = 10_000_000_000,
    )
end

function _start_tls12_server(config::TL12N.Config; handler)
    listener = TL12N.listen(NC12N.loopback_addr(0), config; backlog = 8)
    addr = TL12N.addr(listener)::NC12N.SocketAddrV4
    task = Threads.@spawn begin
        conn = TL12N.accept(listener)
        try
            TL12N.handshake!(conn)
            handler(conn)
            return conn
        catch
            _tls12_native_close_quiet!(conn)
            rethrow()
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
    @test err isa TL12N._TLS13AlertError
    tls_err = err::TL12N._TLS13AlertError
    @test tls_err.alert == TL12N._TLS_ALERT_UNEXPECTED_MESSAGE
    return tls_err
end

@testset "TLS native TLS1.2 client" begin
    @test TL12N._native_tls12_only(_tls12_native_client_config())
    @test !TL12N._native_tls12_only(TL12N.Config(server_name = "localhost", verify_peer = false))

    @testset "record layer roundtrip encrypts and decrypts application data" begin
        listener = nothing
        client_tcp = nothing
        server_tcp = nothing
        try
            listener, client_tcp, server_tcp = _tls12_open_tcp_pair()
            client_state = TL12N._TLS12NativeClientState()
            server_state = TL12N._TLS12NativeClientState()
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
            state = TL12N._TLS12NativeClientState()
            TL12N._tls13_write_tls_plaintext!(client_tcp, TL12N._TLS_RECORD_TYPE_APPLICATION_DATA, UInt8[0x61], TL12N.TLS1_2_VERSION)
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
            state = TL12N._TLS12NativeClientState()
            read_key = UInt8[UInt8(0x20 + i) for i in 0:15]
            read_iv = UInt8[0xb0, 0xb1, 0xb2, 0xb3]
            TL12N._tls12_set_read_cipher!(state, TL12N._TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256, read_key, read_iv)
            TL12N._tls13_write_tls_plaintext!(client_tcp, TL12N._TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC, UInt8[0x01], TL12N.TLS1_2_VERSION)
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
            client_state = TL12N._TLS12NativeClientState()
            server_state = TL12N._TLS12NativeClientState()
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

    @testset "exact TLS 1.2 client handshakes through public APIs" begin
        listener = nothing
        client = nothing
        task = nothing
        try
            listener, addr, task = _start_tls12_server(_tls12_openssl_server_config(alpn_protocols = ["h2"]); handler = conn -> begin
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

    @testset "exact TLS 1.2 client verifies the server certificate" begin
        listener = nothing
        client = nothing
        task = nothing
        try
            listener, addr, task = _start_tls12_server(_tls12_openssl_server_config(); handler = conn -> begin
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
end
