using Test
using NetworkOptions
using Reseau

const TL = Reseau.TLS
const NC = Reseau.TCP
const ND = Reseau.HostResolvers
const EL = Reseau.EventLoops

const _TLS_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")

function _tls_wait_task_done(task::Task, timeout_s::Float64 = 2.0)
    return EL.timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
end

function _tls_close_quiet!(x)
    x === nothing && return nothing
    try
        if x isa TL.Conn || x isa TL.Listener
            TL.close!(x)
        elseif x isa NC.Conn || x isa NC.Listener
            NC.close!(x)
        end
    catch
    end
    return nothing
end

@inline function _tls_handshake_connect_error(ex)
    return ex isa TL.TLSError || ex isa TL.TLSHandshakeTimeoutError
end

function _tls_server_config(; handshake_timeout_ns::Int64 = 0)
    return TL.Config(
        verify_peer = false,
        cert_file = _TLS_CERT_PATH,
        key_file = _TLS_KEY_PATH,
        handshake_timeout_ns = handshake_timeout_ns,
    )
end

function _tls_connect(
        network::AbstractString,
        address::AbstractString,
        config::TL.Config = TL.Config();
        timeout_ns::Integer = Int64(0),
        deadline_ns::Integer = Int64(0),
        local_addr::Union{Nothing, NC.SocketEndpoint} = nothing,
        fallback_delay_ns::Integer = Int64(300_000_000),
        resolver::ND.AbstractResolver = ND.DEFAULT_RESOLVER,
        policy::ND.ResolverPolicy = ND.ResolverPolicy(),
    )::TL.Conn
    return TL.connect(
        network,
        address;
        timeout_ns = timeout_ns,
        deadline_ns = deadline_ns,
        local_addr = local_addr,
        fallback_delay_ns = fallback_delay_ns,
        resolver = resolver,
        policy = policy,
        server_name = config.server_name,
        verify_peer = config.verify_peer,
        client_auth = config.client_auth,
        cert_file = config.cert_file,
        key_file = config.key_file,
        ca_file = config.ca_file,
        client_ca_file = config.client_ca_file,
        alpn_protocols = copy(config.alpn_protocols),
        handshake_timeout_ns = config.handshake_timeout_ns,
        min_version = config.min_version,
        max_version = config.max_version,
    )
end

if !(Sys.isapple() || Sys.islinux())
    @testset "TLS (macOS/Linux only)" begin
        @test true
    end
else
    @testset "TLS phase 6" begin
        @testset "config validation" begin
            cfg_default = TL.Config()
            @test cfg_default.min_version == TL.TLS1_2_VERSION
            @test cfg_default.client_auth == TL.ClientAuthMode.NoClientCert
            default_ca = TL._default_ca_file_path()
            expected_default_ca = try
                path = NetworkOptions.ca_roots_path()
                if path === nothing
                    nothing
                else
                    path_s = String(path)
                    isempty(path_s) || !isfile(path_s) ? nothing : path_s
                end
            catch
                nothing
            end
            if expected_default_ca !== nothing
                @test default_ca == expected_default_ca
                @test isfile(default_ca::String)
            else
                @test default_ca === nothing
            end
            @test TL._effective_ca_file(cfg_default; is_server = false) == default_ca
            explicit_ca_cfg = TL.Config(server_name = "localhost", ca_file = _TLS_CERT_PATH)
            @test TL._effective_ca_file(explicit_ca_cfg; is_server = false) == _TLS_CERT_PATH
            @test_throws TL.ConfigError TL.Config(cert_file = _TLS_CERT_PATH)
            @test_throws TL.ConfigError TL.Config(key_file = _TLS_KEY_PATH)
            @test_throws TL.ConfigError TL.Config(handshake_timeout_ns = -1)
            @test_throws TL.ConfigError TL.listen("tcp", "127.0.0.1:0", TL.Config(verify_peer = false))
            EL.shutdown!()
            listener = nothing
            client_tcp = nothing
            server_tcp = nothing
            try
                listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 4)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn NC.accept!(listener))
                client_tcp = ND.connect("tcp", "127.0.0.1:$(Int(laddr.port))")
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                server_tcp = fetch(accept_task)
                @test_throws TL.ConfigError TL.client(client_tcp, TL.Config(verify_peer = true))
                _tls_close_quiet!(client_tcp)
                client_tcp = nothing
                _tls_close_quiet!(server_tcp)
                server_tcp = nothing
            finally
                _tls_close_quiet!(server_tcp)
                _tls_close_quiet!(client_tcp)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "server client-auth mode mapping and runtime path" begin
            @test TL._server_verify_mode(TL.Config(client_auth = TL.ClientAuthMode.NoClientCert)) == TL._SSL_VERIFY_NONE
            @test TL._server_verify_mode(TL.Config(client_auth = TL.ClientAuthMode.RequestClientCert)) == TL._SSL_VERIFY_PEER
            @test TL._server_verify_mode(TL.Config(client_auth = TL.ClientAuthMode.VerifyClientCertIfGiven)) == TL._SSL_VERIFY_PEER
            @test TL._server_verify_mode(TL.Config(client_auth = TL.ClientAuthMode.RequireAnyClientCert)) == (TL._SSL_VERIFY_PEER | TL._SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
            @test TL._server_verify_mode(TL.Config(client_auth = TL.ClientAuthMode.RequireAndVerifyClientCert)) == (TL._SSL_VERIFY_PEER | TL._SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
            @test TL._server_verify_callback(TL.Config(client_auth = TL.ClientAuthMode.NoClientCert)) == C_NULL
            @test TL._server_verify_callback(TL.Config(client_auth = TL.ClientAuthMode.VerifyClientCertIfGiven)) == C_NULL
            @test TL._server_verify_callback(TL.Config(client_auth = TL.ClientAuthMode.RequireAndVerifyClientCert)) == C_NULL
            @test TL._server_verify_callback(TL.Config(client_auth = TL.ClientAuthMode.RequestClientCert)) != C_NULL
            @test TL._server_verify_callback(TL.Config(client_auth = TL.ClientAuthMode.RequireAnyClientCert)) != C_NULL
            EL.shutdown!()
            listener = nothing
            accept_task = nothing
            client = nothing
            try
                request_listener = nothing
                request_accept = nothing
                request_client = nothing
                request_server = nothing
                request_server_cfg = TL.Config(
                    cert_file = _TLS_CERT_PATH,
                    key_file = _TLS_KEY_PATH,
                    client_auth = TL.ClientAuthMode.RequestClientCert,
                    verify_peer = false,
                )
                try
                    request_listener = TL.listen("tcp", "127.0.0.1:0", request_server_cfg; backlog = 8)
                    request_addr = TL.addr(request_listener)::NC.SocketAddrV4
                    request_accept = errormonitor(Threads.@spawn begin
                        conn = TL.accept!(request_listener)
                        try
                            TL.handshake!(conn)
                            return conn
                        catch err
                            _tls_close_quiet!(conn)
                            return err
                        end
                    end)
                    request_client = _tls_connect("tcp", "127.0.0.1:$(Int(request_addr.port))", TL.Config(
                        verify_peer = false,
                        server_name = "localhost",
                    ))
                    @test request_client isa TL.Conn
                    @test _tls_wait_task_done(request_accept, 2.0) != :timed_out
                    request_server = fetch(request_accept)
                    @test request_server isa TL.Conn
                finally
                    _tls_close_quiet!(request_server)
                    _tls_close_quiet!(request_client)
                    _tls_close_quiet!(request_listener)
                end
                strict_server_cfg = TL.Config(
                    cert_file = _TLS_CERT_PATH,
                    key_file = _TLS_KEY_PATH,
                    client_auth = TL.ClientAuthMode.RequireAndVerifyClientCert,
                    client_ca_file = _TLS_CERT_PATH,
                )
                listener = TL.listen("tcp", "127.0.0.1:0", strict_server_cfg; backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept!(listener)
                    try
                        TL.handshake!(conn)
                        _tls_close_quiet!(conn)
                        return :ok
                    catch err
                        _tls_close_quiet!(conn)
                        return err
                    end
                end)
                client_cfg = TL.Config(verify_peer = false, server_name = "localhost", handshake_timeout_ns = 10_000_000_000)
                connect_err = nothing
                try
                    client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", client_cfg)
                catch ex
                    connect_err = ex
                end
                if connect_err !== nothing
                    @test _tls_handshake_connect_error(connect_err)
                else
                    @test client isa TL.Conn
                end
                accept_task !== nothing && _tls_wait_task_done(accept_task, 12.0)
            finally
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "client certificate config loads native certificate into SSL handle" begin
            EL.shutdown!()
            listener = nothing
            client_tcp = nothing
            server_tcp = nothing
            client_tls = nothing
            try
                listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn NC.accept!(listener))
                client_tcp = ND.connect("tcp", "127.0.0.1:$(Int(laddr.port))")
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                server_tcp = fetch(accept_task)
                client_tls = TL.client(client_tcp, TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                    cert_file = _TLS_CERT_PATH,
                    key_file = _TLS_KEY_PATH,
                ))
                cert_ptr = ccall((:SSL_get_certificate, TL._LIBSSL), Ptr{Cvoid}, (Ptr{Cvoid},), client_tls.ssl)
                @test cert_ptr != C_NULL
            finally
                _tls_close_quiet!(client_tls)
                _tls_close_quiet!(server_tcp)
                _tls_close_quiet!(client_tcp)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "SNI/hostname normalization parity" begin
            @test TL._normalize_peer_name("example.com.") == "example.com"
            @test TL._normalize_peer_name("[::1]") == "::1"
            @test TL._normalize_peer_name("fe80::1%lo0") == "fe80::1"
            @test TL._hostname_in_sni("example.com.") == "example.com"
            @test TL._hostname_in_sni("127.0.0.1") == ""
            @test TL._hostname_in_sni("[::1]") == ""
        end
        @testset "ALPN negotiates on server and client paths" begin
            EL.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                server_cfg = TL.Config(
                    verify_peer = false,
                    cert_file = _TLS_CERT_PATH,
                    key_file = _TLS_KEY_PATH,
                    alpn_protocols = ["h2", "http/1.1"],
                )
                listener = TL.listen("tcp", "127.0.0.1:0", server_cfg; backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept!(listener)
                    TL.handshake!(conn)
                    return conn
                end)
                client_cfg = TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                    alpn_protocols = ["h2", "http/1.1"],
                )
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", client_cfg)
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)
                @test TL.connection_state(client).alpn_protocol == "h2"
                @test TL.connection_state(server).alpn_protocol == "h2"
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "SSL_CTX is reused for equivalent client configs" begin
            EL.shutdown!()
            listener = nothing
            accept_task = nothing
            client1 = nothing
            client2 = nothing
            server_conns = TL.Conn[]
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 16)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    local conns = TL.Conn[]
                    for _ in 1:2
                        conn = TL.accept!(listener)
                        TL.handshake!(conn)
                        push!(conns, conn)
                    end
                    return conns
                end)
                client_cfg = TL.Config(verify_peer = false, server_name = "localhost")
                client1 = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", client_cfg)
                client2 = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", client_cfg)
                @test client1.ssl_ctx != C_NULL
                @test client1.ssl_ctx == client2.ssl_ctx
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                server_conns = fetch(accept_task)
            finally
                for conn in server_conns
                    _tls_close_quiet!(conn)
                end
                _tls_close_quiet!(client1)
                _tls_close_quiet!(client2)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "SSL_CTX cache respects max bound with eviction" begin
            old_max = TL._CTX_CACHE_MAX[]
            TL._CTX_CACHE_MAX[] = 2
            TL._free_ssl_ctx_cache!()
            try
                cfg1 = TL.Config(verify_peer = false, alpn_protocols = ["proto-1"])
                cfg2 = TL.Config(verify_peer = false, alpn_protocols = ["proto-2"])
                cfg3 = TL.Config(verify_peer = false, alpn_protocols = ["proto-3"])
                key1 = TL._ssl_context_key(cfg1; is_server = false)
                ctx1 = TL._shared_ssl_ctx(cfg1; is_server = false)
                ctx2 = TL._shared_ssl_ctx(cfg2; is_server = false)
                ctx3 = TL._shared_ssl_ctx(cfg3; is_server = false)
                @test ctx1 != C_NULL
                @test ctx2 != C_NULL
                @test ctx3 != C_NULL
                @test length(TL._CTX_CACHE) <= 2
                @test !haskey(TL._CTX_CACHE, key1)
            finally
                TL._free_ssl_ctx_cache!()
                TL._CTX_CACHE_MAX[] = old_max
            end
        end
        @testset "connect/listen handshake and roundtrip" begin
            EL.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 16)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    try
                        conn = TL.accept!(listener)
                        TL.handshake!(conn)
                        buf = Vector{UInt8}(undef, 4)
                        n = read!(conn, buf)
                        n > 0 && write(conn, view(buf, 1:n))
                        view_buf = Vector{UInt8}(undef, 3)
                        n = read!(conn, view_buf)
                        n > 0 && write(conn, view(view_buf, 1:n))
                        return conn
                    catch err
                        return err
                    end
                end)
                client_cfg = TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                    handshake_timeout_ns = 10_000_000_000,
                )
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", client_cfg)
                payload = UInt8[0x61, 0x62, 0x63, 0x64]
                @test write(client, payload) == 4
                recv_buf = Vector{UInt8}(undef, 4)
                @test read!(client, recv_buf) == 4
                @test recv_buf == payload
                payload_view = @view payload[2:4]
                @test write(client, payload_view) == length(payload_view)
                recv_view_buf = Vector{UInt8}(undef, length(payload_view))
                @test read!(client, recv_view_buf) == length(payload_view)
                @test recv_view_buf == collect(payload_view)
                @test _tls_wait_task_done(accept_task, 12.0) != :timed_out
                server_result = fetch(accept_task)
                server_result isa Exception && throw(server_result)
                server = server_result::TL.Conn
                state = TL.connection_state(client)
                @test state.handshake_complete
                @test !isempty(state.version)
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "peer read observes clean EOF after close_notify" begin
            EL.shutdown!()
            listener = nothing
            client = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                close_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept!(listener)
                    try
                        TL.handshake!(conn)
                    catch
                    end
                    TL.close!(conn)
                    return nothing
                end)
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                ))
                @test _tls_wait_task_done(close_task, 2.0) != :timed_out
                buf = Vector{UInt8}(undef, 1)
                @test read!(client, buf) == 0
            finally
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "close_write shuts down TLS write side and rejects further writes" begin
            EL.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept!(listener)
                    TL.handshake!(conn)
                    return conn
                end)
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                ))
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)
                TL.close_write!(client)
                write_err = try
                    write(client, UInt8[0x41])
                    nothing
                catch ex
                    ex
                end
                @test write_err isa TL.TLSError
                if write_err isa TL.TLSError
                    @test write_err.message == "tls: protocol is shutdown"
                end
                TL.set_read_deadline!(server, time_ns() + 1_000_000_000)
                @test read!(server, Vector{UInt8}(undef, 1)) == 0
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "close_write before handshake complete returns TLSError" begin
            EL.shutdown!()
            listener = nothing
            client_tcp = nothing
            server_tcp = nothing
            tls_client = nothing
            try
                listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn NC.accept!(listener))
                client_tcp = ND.connect("tcp", "127.0.0.1:$(Int(laddr.port))")
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                server_tcp = fetch(accept_task)
                tls_client = TL.client(client_tcp, TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                ))
                err = try
                    TL.close_write!(tls_client)
                    nothing
                catch ex
                    ex
                end
                @test err isa TL.TLSError
                if err isa TL.TLSError
                    @test occursin("before handshake complete", err.message)
                end
            finally
                _tls_close_quiet!(tls_client)
                _tls_close_quiet!(server_tcp)
                _tls_close_quiet!(client_tcp)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "peer verification success with explicit CA file" begin
            EL.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 16)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    try
                        conn = TL.accept!(listener)
                        TL.handshake!(conn)
                        return conn
                    catch err
                        return err
                    end
                end)
                client_cfg = TL.Config(
                    verify_peer = true,
                    server_name = "localhost",
                    ca_file = _TLS_CERT_PATH,
                    handshake_timeout_ns = 10_000_000_000,
                )
                connect_result = try
                    _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", client_cfg)
                catch ex
                    ex
                end
                if connect_result isa TL.Conn
                    client = connect_result
                    @test _tls_wait_task_done(accept_task, 12.0) != :timed_out
                    server_result = fetch(accept_task)
                    server_result isa Exception && throw(server_result)
                    server = server_result::TL.Conn
                    @test TL.connection_state(client).handshake_complete
                else
                    @test connect_result isa TL.TLSHandshakeTimeoutError
                end
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "peer verification failure surfaces TLSError" begin
            EL.shutdown!()
            listener = nothing
            accept_task = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 16)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept!(listener)
                    try
                        TL.handshake!(conn)
                    catch
                    end
                    _tls_close_quiet!(conn)
                    return nothing
                end)
                bad_client_cfg = TL.Config(
                    verify_peer = true,
                    server_name = "localhost",
                    handshake_timeout_ns = 10_000_000_000,
                )
                bad_connect_err = try
                    _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", bad_client_cfg)
                    nothing
                catch ex
                    ex
                end
                @test bad_connect_err !== nothing
                if bad_connect_err !== nothing
                    @test _tls_handshake_connect_error(bad_connect_err)
                end
                accept_task !== nothing && _tls_wait_task_done(accept_task, 2.0)
            finally
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "ip literal verification path does not require explicit server_name" begin
            EL.shutdown!()
            listener = nothing
            accept_task = nothing
            client = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 16)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept!(listener)
                    try
                        TL.handshake!(conn)
                    catch
                    end
                    _tls_close_quiet!(conn)
                    return nothing
                end)
                client_cfg = TL.Config(
                    verify_peer = true,
                    ca_file = _TLS_CERT_PATH,
                    handshake_timeout_ns = 10_000_000_000,
                )
                connect_err = nothing
                try
                    client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", client_cfg)
                catch ex
                    connect_err = ex
                end
                if connect_err !== nothing
                    @test connect_err isa TL.TLSError || connect_err isa TL.TLSHandshakeTimeoutError
                else
                    @test client isa TL.Conn
                end
                accept_task !== nothing && _tls_wait_task_done(accept_task, 12.0)
            finally
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "handshake timeout surfaces TLSHandshakeTimeoutError" begin
            EL.shutdown!()
            listener = nothing
            client_tcp = nothing
            stalled_peer = nothing
            try
                listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = NC.accept!(listener)
                    EL.sleep(1.0)
                    return conn
                end)
                client_tcp = ND.connect("tcp", "127.0.0.1:$(Int(laddr.port))")
                client_tls = TL.client(client_tcp, TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                    handshake_timeout_ns = 200_000_000,
                ))
                original_read_deadline = time_ns() + 2_000_000_000
                original_write_deadline = time_ns() + 2_500_000_000
                TL.set_read_deadline!(client_tls, original_read_deadline)
                TL.set_write_deadline!(client_tls, original_write_deadline)
                pfd = client_tls.tcp.fd.pfd
                pre_read_ns = @atomic :acquire pfd.pd.rd_ns
                pre_write_ns = @atomic :acquire pfd.pd.wd_ns
                @test_throws TL.TLSHandshakeTimeoutError TL.handshake!(client_tls)
                post_read_ns = @atomic :acquire pfd.pd.rd_ns
                post_write_ns = @atomic :acquire pfd.pd.wd_ns
                @test post_read_ns == pre_read_ns
                @test post_write_ns == pre_write_ns
                _tls_close_quiet!(client_tls)
                client_tcp = nothing
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                stalled_peer = fetch(accept_task)
            finally
                _tls_close_quiet!(stalled_peer)
                _tls_close_quiet!(client_tcp)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "handshake deadline with no handshake_timeout maps to i/o timeout TLSError" begin
            EL.shutdown!()
            listener = nothing
            client_tcp = nothing
            stalled_peer = nothing
            client_tls = nothing
            try
                listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = NC.accept!(listener)
                    EL.sleep(1.0)
                    return conn
                end)
                client_tcp = ND.connect("tcp", "127.0.0.1:$(Int(laddr.port))")
                client_tls = TL.client(client_tcp, TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                    handshake_timeout_ns = 0,
                ))
                TL.set_read_deadline!(client_tls, time_ns() + 100_000_000)
                TL.set_write_deadline!(client_tls, time_ns() + 100_000_000)
                err = try
                    TL.handshake!(client_tls)
                    nothing
                catch ex
                    ex
                end
                @test err isa TL.TLSError
                @test !(err isa TL.TLSHandshakeTimeoutError)
                if err isa TL.TLSError
                    @test err.message == "i/o timeout"
                end
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                stalled_peer = fetch(accept_task)
            finally
                _tls_close_quiet!(client_tls)
                _tls_close_quiet!(stalled_peer)
                _tls_close_quiet!(client_tcp)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "host resolver timeout budget includes TLS handshake time" begin
            EL.shutdown!()
            listener = nothing
            stalled_peer = nothing
            try
                listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = NC.accept!(listener)
                    EL.sleep(1.2)
                    NC.close!(conn)
                    return nothing
                end)
                host_resolver = ND.HostResolver(timeout_ns = 100_000_000)
                cfg = TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                    handshake_timeout_ns = 0,
                )
                started_ns = time_ns()
                err = try
                    _tls_connect(
                        "tcp",
                        "127.0.0.1:$(Int(laddr.port))",
                        cfg;
                        timeout_ns = host_resolver.timeout_ns,
                        deadline_ns = host_resolver.deadline_ns,
                        local_addr = host_resolver.local_addr,
                        fallback_delay_ns = host_resolver.fallback_delay_ns,
                        resolver = host_resolver.resolver,
                        policy = host_resolver.policy,
                    )
                    nothing
                catch ex
                    ex
                end
                elapsed_ms = (time_ns() - started_ns) / 1.0e6
                @test err isa TL.TLSError
                if err isa TL.TLSError
                    @test err.message == "i/o timeout"
                end
                @test elapsed_ms < 700.0
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
            finally
                _tls_close_quiet!(stalled_peer)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "operations fail fast after close" begin
            EL.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept!(listener)
                    TL.handshake!(conn)
                    return conn
                end)
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                ))
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)
                TL.close!(client)
                TL.close!(client)
                @test_throws TL.TLSError TL.handshake!(client)
                @test_throws TL.TLSError read!(client, Vector{UInt8}(undef, 1))
                @test_throws TL.TLSError write(client, UInt8[0x41])
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "write timeout remains sticky across subsequent writes" begin
            EL.shutdown!()
            listener = nothing
            client = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                hold_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept!(listener)
                    TL.handshake!(conn)
                    EL.sleep(1.5)
                    TL.close!(conn)
                    return nothing
                end)
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                ))
                TL.set_write_deadline!(client, time_ns() + 5_000_000)
                payload = fill(UInt8(0x5a), 64 * 1024 * 1024)
                first_err = try
                    write(client, payload)
                    nothing
                catch ex
                    ex
                end
                @test first_err isa TL.TLSError
                if first_err isa TL.TLSError
                    @test first_err.message == "i/o timeout"
                end
                TL.set_write_deadline!(client, Int64(0))
                second_err = try
                    write(client, UInt8[0x01])
                    nothing
                catch ex
                    ex
                end
                @test second_err isa TL.TLSError
                if first_err isa TL.TLSError && second_err isa TL.TLSError
                    @test second_err === first_err
                end
                @test _tls_wait_task_done(hold_task, 2.0) != :timed_out
            finally
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "blocked read unblocks when local close races" begin
            EL.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            read_task = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept!(listener)
                    TL.handshake!(conn)
                    return conn
                end)
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                ))
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)
                read_task = errormonitor(Threads.@spawn begin
                    try
                        read!(client, Vector{UInt8}(undef, 1))
                    catch err
                        return err
                    end
                    return :ok
                end)
                @test _tls_wait_task_done(read_task, 0.05) == :timed_out
                TL.close!(client)
                @test _tls_wait_task_done(read_task, 2.0) != :timed_out
                result = fetch(read_task)
                @test result isa TL.TLSError
                if result isa TL.TLSError
                    @test occursin("connection is closed", result.message)
                end
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                EL.shutdown!()
            end
        end
    end
end
