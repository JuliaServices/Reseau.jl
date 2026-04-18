using Test
using NetworkOptions
using Reseau

const TL = Reseau.TLS
const NC = Reseau.TCP
const ND = Reseau.HostResolvers
const IP = Reseau.IOPoll

const _TLS_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")
const _TLS_NATIVE_CA_PATH = joinpath(@__DIR__, "resources", "native_tls_ca.crt")
const _TLS_NATIVE_SERVER_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server.crt")
const _TLS_NATIVE_SERVER_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_server.key")
const _TLS_NATIVE_CLIENT_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_client.crt")
const _TLS_NATIVE_CLIENT_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_client.key")

function _tls_wait_task_done(task::Task, timeout_s::Float64 = 2.0)
    return IP.timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
end

function _tls_close_quiet!(x)
    x === nothing && return nothing
    try
        if x isa TL.Conn || x isa TL.Listener
            close(x)
        elseif x isa NC.Conn || x isa NC.Listener
            close(x)
        end
    catch
    end
    return nothing
end

function _tls_trace(label::AbstractString)
    println("[tls_tests] ", label)
    flush(stdout)
    return nothing
end

@inline function _tls_handshake_connect_error(ex)
    return ex isa TL.TLSError || ex isa TL.TLSHandshakeTimeoutError
end

function _tls_server_config(;
    handshake_timeout_ns::Int64 = 0,
    cert_file::String = _TLS_CERT_PATH,
    key_file::String = _TLS_KEY_PATH,
    client_auth::TL.ClientAuthMode.T = TL.ClientAuthMode.NoClientCert,
    client_ca_file::Union{Nothing, String} = nothing,
    min_version::Union{Nothing, UInt16} = TL.TLS1_2_VERSION,
    max_version::Union{Nothing, UInt16} = nothing,
    curve_preferences::Vector{UInt16} = UInt16[],
)
    return TL.Config(
        verify_peer = false,
        cert_file = cert_file,
        key_file = key_file,
        client_auth = client_auth,
        client_ca_file = client_ca_file,
        handshake_timeout_ns = handshake_timeout_ns,
        min_version = min_version,
        max_version = max_version,
        curve_preferences = copy(curve_preferences),
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
        address,
        config;
        timeout_ns = timeout_ns,
        deadline_ns = deadline_ns,
        local_addr = local_addr,
        fallback_delay_ns = fallback_delay_ns,
        resolver = resolver,
        policy = policy,
    )
end

function _tls_raw_config_for_test(base::TL.Config; min_version = base.min_version, max_version = base.max_version)
    return TL.Config(
        base.server_name,
        base.verify_peer,
        base.verify_hostname,
        base.client_auth,
        base.cert_file,
        base.key_file,
        base.ca_file,
        base.client_ca_file,
        copy(base.alpn_protocols),
        copy(base.curve_preferences),
        base.handshake_timeout_ns,
        min_version,
        max_version,
        base.session_tickets_disabled,
        base._client_session_cache,
        base._server_session_cache,
        base._client_session_cache12,
        base._server_session_cache12,
    )
end

@testset "TLS phase 6" begin
        @test TL.Conn <: IO
        @test TL.DeadlineExceededError === NC.DeadlineExceededError
        @test TL.DeadlineExceededError === IP.DeadlineExceededError
        _tls_trace("START: config validation")
        @testset "config validation" begin
            cfg_default = TL.Config()
            @test cfg_default.min_version == TL.TLS1_2_VERSION
            @test cfg_default.client_auth == TL.ClientAuthMode.NoClientCert
            @test cfg_default.verify_hostname
            @test !isdefined(TL, :TLS1_0_VERSION)
            @test !isdefined(TL, :TLS1_1_VERSION)
            @test TL._native_curve_preferences(cfg_default) == UInt16[TL.X25519, TL.P256]
            @test TL._tls12_curve_preferences(cfg_default) == UInt16[TL.P256]
            @test TL._native_curve_preferences(TL.Config(
                min_version = TL.TLS1_3_VERSION,
                max_version = TL.TLS1_3_VERSION,
                curve_preferences = UInt16[TL.P256, TL.X25519],
            )) == UInt16[TL.P256, TL.X25519]
            default_ca = TL._default_ca_file_path()
            expected_default_ca = try
                path = NetworkOptions.ca_roots_path()
                if path === nothing
                    nothing
                else
                    path_s = String(path)
                    isempty(path_s) || !ispath(path_s) ? nothing : path_s
                end
            catch
                nothing
            end
            if expected_default_ca !== nothing
                @test default_ca == expected_default_ca
                @test ispath(default_ca::String)
            else
                @test default_ca === nothing
            end
            @test TL._effective_ca_file(cfg_default; is_server = false) == default_ca
            explicit_ca_cfg = TL.Config(server_name = "localhost", ca_file = _TLS_CERT_PATH)
            @test TL._effective_ca_file(explicit_ca_cfg; is_server = false) == _TLS_CERT_PATH
            @test TL._effective_ca_file(TL.Config(verify_peer = false, client_auth = TL.ClientAuthMode.RequestClientCert); is_server = true) === nothing
            verified_client_auth_cfg = TL.Config(
                verify_peer = false,
                client_auth = TL.ClientAuthMode.VerifyClientCertIfGiven,
                client_ca_file = _TLS_CERT_PATH,
            )
            @test TL._effective_ca_file(verified_client_auth_cfg; is_server = true) == _TLS_CERT_PATH
            @test TL._native_tls_auto_client_enabled(TL.Config(server_name = "localhost", verify_peer = false))
            @test TL._tls_client_policy(TL.Config(server_name = "localhost", verify_peer = false)) == TL._TLS_POLICY_AUTO
            @test TL._native_tls12_only(TL.Config(server_name = "localhost", verify_peer = false, max_version = TL.TLS1_2_VERSION))
            @test TL._tls_client_policy(TL.Config(server_name = "localhost", verify_peer = false, max_version = TL.TLS1_2_VERSION)) == TL._TLS_POLICY_TLS12
            @test TL._native_tls_auto_server_enabled(TL.Config(
                verify_peer = false,
                cert_file = _TLS_CERT_PATH,
                key_file = _TLS_KEY_PATH,
            ))
            @test TL._tls_server_policy(TL.Config(
                verify_peer = false,
                cert_file = _TLS_CERT_PATH,
                key_file = _TLS_KEY_PATH,
            )) == TL._TLS_POLICY_AUTO
            @test TL._tls_server_policy(TL.Config(
                verify_peer = false,
                cert_file = _TLS_CERT_PATH,
                key_file = _TLS_KEY_PATH,
                max_version = TL.TLS1_2_VERSION,
            )) == TL._TLS_POLICY_TLS12
            @test TL._native_tls_auto_client_enabled(TL.Config(
                server_name = "localhost",
                verify_peer = false,
                cert_file = _TLS_CERT_PATH,
                key_file = _TLS_KEY_PATH,
            ))
            @test TL._native_tls_auto_server_enabled(TL.Config(
                verify_peer = false,
                cert_file = _TLS_CERT_PATH,
                key_file = _TLS_KEY_PATH,
                client_auth = TL.ClientAuthMode.RequireAnyClientCert,
            ))
            disabled_ticket_cfg = TL.Config(
                server_name = "localhost",
                verify_peer = false,
                session_tickets_disabled = true,
            )
            @test !TL._tls13_client_hello(disabled_ticket_cfg).ticket_supported
            @test !TL._tls_auto_client_hello(disabled_ticket_cfg).ticket_supported
            @test_throws TL.ConfigError TL.Config(cert_file = _TLS_CERT_PATH)
            @test_throws TL.ConfigError TL.Config(key_file = _TLS_KEY_PATH)
            @test_throws TL.ConfigError TL.Config(handshake_timeout_ns = -1)
            @test_throws TL.ConfigError TL.Config(server_name = "localhost", verify_peer = false, min_version = UInt16(0x0301))
            @test_throws TL.ConfigError TL.Config(server_name = "localhost", verify_peer = false, max_version = UInt16(0x0302))
            @test_throws TL.ConfigError TL._validate_config(TL.Config(verify_peer = false, curve_preferences = UInt16[0x9999]); is_server = false)
            @test TL._validate_config(TL.Config(verify_peer = false, curve_preferences = UInt16[TL.P256]); is_server = false) === nothing
            @test TL._validate_config(TL.Config(
                verify_peer = false,
                min_version = TL.TLS1_2_VERSION,
                max_version = TL.TLS1_2_VERSION,
                curve_preferences = UInt16[TL.X25519],
            ); is_server = false) === nothing
            @test_throws TL.ConfigError TL.Config(min_version = TL.TLS1_3_VERSION, max_version = TL.TLS1_2_VERSION)
            raw_cfg = _tls_raw_config_for_test(TL.Config(server_name = "localhost", verify_peer = false); min_version = UInt16(0x0301))
            @test_throws TL.ConfigError TL._validate_config(raw_cfg; is_server = false)
            raw_reversed = _tls_raw_config_for_test(TL.Config(server_name = "localhost", verify_peer = false); min_version = TL.TLS1_3_VERSION, max_version = TL.TLS1_2_VERSION)
            @test_throws TL.ConfigError TL._validate_config(raw_reversed; is_server = false)
            @test_throws TL.ConfigError TL._validate_config(TL.Config(verify_peer = false, ca_file = joinpath(@__DIR__, "missing-ca.pem")); is_server = false)
            @test_throws TL.ConfigError TL._validate_config(TL.Config(verify_peer = false, client_ca_file = joinpath(@__DIR__, "missing-client-ca.pem")); is_server = true)
            @test_throws TL.ConfigError TL._validate_config(TL.Config(
                cert_file = _TLS_CERT_PATH,
                key_file = _TLS_KEY_PATH,
                verify_peer = false,
                client_auth = TL.ClientAuthMode.VerifyClientCertIfGiven,
            ); is_server = true)
            @test_throws TL.ConfigError TL.listen("tcp", "127.0.0.1:0", TL.Config(verify_peer = false))
            IP.shutdown!()
            listener = nothing
            client_tcp = nothing
            server_tcp = nothing
            try
                listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 4)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn NC.accept(listener))
                client_tcp = ND.connect("tcp", "127.0.0.1:$(Int(laddr.port))")
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                server_tcp = fetch(accept_task)
                @test_throws TL.ConfigError TL.client(client_tcp, TL.Config(verify_peer = true))
                @test_throws TL.ConfigError TL.client(client_tcp, TL.Config(verify_peer = false, verify_hostname = true))
                _tls_close_quiet!(client_tcp)
                client_tcp = nothing
                _tls_close_quiet!(server_tcp)
                server_tcp = nothing
            finally
                _tls_close_quiet!(server_tcp)
                _tls_close_quiet!(client_tcp)
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "version helpers and connect config inference" begin
            payload = UInt8[0x61, 0x62, 0x63]
            copied = TL._write_buffer(@view(payload[1:2:3]), 2)
            @test copied == UInt8[0x61, 0x63]
            @test copied isa Vector{UInt8}

            inferred = TL._prepare_connect_config(TL.Config(verify_peer = false), "Example.com.:443")
            @test inferred.server_name == "Example.com"
            inferred_ip = TL._prepare_connect_config(TL.Config(verify_peer = false), "[::1]:443")
            @test inferred_ip.server_name == "::1"
            inferred_addr = TL._prepare_connect_config(TL.Config(verify_peer = false), NC.loopback_addr(443))
            @test inferred_addr.server_name == "127.0.0.1"
            explicit = TL.Config(server_name = "manual.example", verify_peer = false)
            @test TL._prepare_connect_config(explicit, "example.com:443") === explicit
            @test TL._prepare_connect_config(explicit, NC.loopback_addr(443)) === explicit
            unchanged = TL._prepare_connect_config(TL.Config(verify_peer = false), "bad-address")
            @test unchanged.server_name === nothing
        end
        @testset "direct socket-address connect/listen passthroughs" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen(NC.loopback_addr(0), _tls_server_config(); backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept(listener)
                    TL.handshake!(conn)
                    return conn
                end)
                client = TL.connect(
                    NC.loopback_addr(Int(laddr.port)),
                    NC.loopback_addr(0);
                    verify_peer = false,
                    server_name = "localhost",
                    handshake_timeout_ns = 1_000_000_000,
                )
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)
                client_local = TL.local_addr(client)::NC.SocketAddrV4
                @test client_local.ip == NC.loopback_addr(0).ip
                payload = UInt8[0x64, 0x69, 0x72]
                recv_buf = Vector{UInt8}(undef, length(payload))
                @test write(client, payload) == length(payload)
                @test read!(server, recv_buf) === recv_buf
                @test recv_buf == payload
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "server client-auth runtime path" begin
            IP.shutdown!()
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
                        conn = TL.accept(request_listener)
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
                    conn = TL.accept(listener)
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
                IP.shutdown!()
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
            IP.shutdown!()
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
                    conn = TL.accept(listener)
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
                IP.shutdown!()
            end
        end
        _tls_trace("DONE: config validation")
        _tls_trace("START: show methods summarize TLS endpoints and handshake state")
        @testset "show methods summarize TLS endpoints and handshake state" begin
            IP.shutdown!()
            tls_listener = nothing
            tcp_listener = nothing
            client_tcp = nothing
            server_tcp = nothing
            client_tls = nothing
            server_tls = nothing
            try
                listener_cfg = _tls_server_config()
                tls_listener = TL.listen("tcp", "127.0.0.1:0", listener_cfg; backlog = 8)
                tls_laddr = TL.addr(tls_listener)
                @test repr(tls_listener) == "TLS.Listener($(repr(tls_laddr)), active)"
                close(tls_listener)
                @test repr(tls_listener) == "TLS.Listener($(repr(tls_laddr)), closed)"
                tls_listener = nothing

                tcp_listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
                tcp_laddr = NC.addr(tcp_listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn NC.accept(tcp_listener))
                client_tcp = ND.connect("tcp", "127.0.0.1:$(Int(tcp_laddr.port))")
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                server_tcp = fetch(accept_task)

                server_cfg = TL.Config(
                    verify_peer = false,
                    cert_file = _TLS_CERT_PATH,
                    key_file = _TLS_KEY_PATH,
                    alpn_protocols = ["h2", "http/1.1"],
                )
                client_cfg = TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                    alpn_protocols = ["h2", "http/1.1"],
                )
                client_tls = TL.client(client_tcp, client_cfg)
                server_tls = TL.server(server_tcp, server_cfg)

                client_local = TL.local_addr(client_tls)
                client_remote = TL.remote_addr(client_tls)
                server_local = TL.local_addr(server_tls)
                server_remote = TL.remote_addr(server_tls)

                @test repr(client_tls) == "TLS.Conn($(repr(client_local)) => $(repr(client_remote)), client, handshake pending)"
                @test repr(server_tls) == "TLS.Conn($(repr(server_local)) => $(repr(server_remote)), server, handshake pending)"

                server_task = errormonitor(Threads.@spawn TL.handshake!(server_tls))
                TL.handshake!(client_tls)
                @test _tls_wait_task_done(server_task, 2.0) != :timed_out
                fetch(server_task)

                client_state = TL.connection_state(client_tls)
                server_state = TL.connection_state(server_tls)
                @test client_state.alpn_protocol == "h2"
                @test server_state.alpn_protocol == "h2"
                @test repr(client_tls) == "TLS.Conn($(repr(client_local)) => $(repr(client_remote)), client, $(client_state.version), $(client_state.alpn_protocol))"
                @test repr(server_tls) == "TLS.Conn($(repr(server_local)) => $(repr(server_remote)), server, $(server_state.version), $(server_state.alpn_protocol))"

                close(client_tls)
                close(server_tls)

                @test repr(client_tls) == "TLS.Conn($(repr(client_local)) => $(repr(client_remote)), client, closed)"
                @test repr(server_tls) == "TLS.Conn($(repr(server_local)) => $(repr(server_remote)), server, closed)"
            finally
                _tls_close_quiet!(server_tls)
                _tls_close_quiet!(client_tls)
                _tls_close_quiet!(server_tcp)
                _tls_close_quiet!(client_tcp)
                _tls_close_quiet!(tcp_listener)
                _tls_close_quiet!(tls_listener)
                IP.shutdown!()
            end
        end
        @testset "listener deadline, open state, and local_addr alias" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                @test isopen(listener)
                @test TL.local_addr(listener) == laddr

                TL.set_deadline!(listener, Int64(time_ns()) - Int64(1))
                @test_throws TL.DeadlineExceededError TL.accept(listener)

                TL.set_deadline!(listener, Int64(0))
                accept_task = errormonitor(Threads.@spawn TL.accept(listener))
                client = NC.connect(NC.loopback_addr(Int(laddr.port)))
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)
                @test server isa TL.Conn

                @test close(listener) === nothing
                @test !isopen(listener)
                @test close(listener) === nothing
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        _tls_trace("DONE: show methods summarize TLS endpoints and handshake state")
        _tls_trace("START: connect/listen handshake and roundtrip")
        @testset "connect/listen handshake and roundtrip" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 16)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    try
                        conn = TL.accept(listener)
                        TL.handshake!(conn)
                        buf = Vector{UInt8}(undef, 4)
                        read!(conn, buf)
                        write(conn, buf)
                        view_backing = fill(UInt8(0x00), 5)
                        view_buf = @view view_backing[2:4]
                        read!(conn, view_buf)
                        write(conn, view_buf)
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
                @test read!(client, recv_buf) === recv_buf
                @test recv_buf == payload
                payload_view = @view payload[2:4]
                @test write(client, payload_view) == length(payload_view)
                recv_view_buf = Vector{UInt8}(undef, length(payload_view))
                @test read!(client, recv_view_buf) === recv_view_buf
                @test recv_view_buf == collect(payload_view)
                @test _tls_wait_task_done(accept_task, 12.0) != :timed_out
                server_result = fetch(accept_task)
                server_result isa Exception && throw(server_result)
                server = server_result::TL.Conn
                state = TL.connection_state(client)
                @test state.handshake_complete
                @test state.version == "TLSv1.3"
                @test state.using_native_tls13
                server_state = TL.connection_state(server)
                @test server_state.handshake_complete
                @test server_state.version == "TLSv1.3"
                @test server_state.using_native_tls13
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "mixed-version native client negotiates TLS 1.2 with an exact TLS 1.2 server" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", TL.Config(
                    verify_peer = false,
                    cert_file = _TLS_CERT_PATH,
                    key_file = _TLS_KEY_PATH,
                    handshake_timeout_ns = 10_000_000_000,
                    min_version = TL.TLS1_2_VERSION,
                    max_version = TL.TLS1_2_VERSION,
                ); backlog = 16)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    try
                        conn = TL.accept(listener)
                        TL.handshake!(conn)
                        write(conn, UInt8[0x31])
                        return conn
                    catch err
                        return err
                    end
                end)
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                    handshake_timeout_ns = 10_000_000_000,
                ))
                @test read(client, 1) == UInt8[0x31]
                @test _tls_wait_task_done(accept_task, 12.0) != :timed_out
                server_result = fetch(accept_task)
                server_result isa Exception && throw(server_result)
                server = server_result::TL.Conn
                client_state = TL.connection_state(client)
                server_state = TL.connection_state(server)
                @test client_state.handshake_complete
                @test server_state.handshake_complete
                @test client_state.version == "TLSv1.2"
                @test server_state.version == "TLSv1.2"
                @test !client_state.using_native_tls13
                @test !server_state.using_native_tls13
                @test client_state.curve == "P-256"
                @test server_state.curve == "P-256"
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "mixed-version native server negotiates TLS 1.2 with an exact TLS 1.2 client" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(handshake_timeout_ns = 10_000_000_000); backlog = 16)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    try
                        conn = TL.accept(listener)
                        TL.handshake!(conn)
                        write(conn, UInt8[0x41])
                        return conn
                    catch err
                        return err
                    end
                end)
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                    handshake_timeout_ns = 10_000_000_000,
                    max_version = TL.TLS1_2_VERSION,
                ))
                @test read(client, 1) == UInt8[0x41]
                @test _tls_wait_task_done(accept_task, 12.0) != :timed_out
                server_result = fetch(accept_task)
                server_result isa Exception && throw(server_result)
                server = server_result::TL.Conn
                client_state = TL.connection_state(client)
                server_state = TL.connection_state(server)
                @test client_state.handshake_complete
                @test server_state.handshake_complete
                @test client_state.version == "TLSv1.2"
                @test server_state.version == "TLSv1.2"
                @test !client_state.using_native_tls13
                @test !server_state.using_native_tls13
                @test client_state.curve == "P-256"
                @test server_state.curve == "P-256"
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "mixed-version native TLS can negotiate TLS 1.2 with X25519 when configured" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(
                    handshake_timeout_ns = 10_000_000_000,
                    curve_preferences = UInt16[TL.X25519],
                ); backlog = 16)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    try
                        conn = TL.accept(listener)
                        TL.handshake!(conn)
                        write(conn, UInt8[0x58])
                        return conn
                    catch err
                        return err
                    end
                end)
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                    handshake_timeout_ns = 10_000_000_000,
                    max_version = TL.TLS1_2_VERSION,
                    curve_preferences = UInt16[TL.X25519],
                ))
                @test read(client, 1) == UInt8[0x58]
                @test _tls_wait_task_done(accept_task, 12.0) != :timed_out
                server_result = fetch(accept_task)
                server_result isa Exception && throw(server_result)
                server = server_result::TL.Conn
                client_state = TL.connection_state(client)
                server_state = TL.connection_state(server)
                @test client_state.version == "TLSv1.2"
                @test server_state.version == "TLSv1.2"
                @test !client_state.using_native_tls13
                @test !server_state.using_native_tls13
                @test client_state.curve == "X25519"
                @test server_state.curve == "X25519"
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "mixed-version native client supports TLS 1.2 mTLS and resumption against an exact TLS 1.2 server" begin
            function run_once(server_cfg::TL.Config, client_cfg::TL.Config)
                listener = nothing
                client = nothing
                accept_task = nothing
                try
                    listener = TL.listen("tcp", "127.0.0.1:0", server_cfg; backlog = 16)
                    laddr = TL.addr(listener)::NC.SocketAddrV4
                    accept_task = errormonitor(Threads.@spawn begin
                        conn = TL.accept(listener)
                        try
                            TL.handshake!(conn)
                            write(conn, UInt8[0x51])
                            read(conn, 1) == UInt8[0x61] || error("unexpected TLS client ack")
                            return TL.connection_state(conn)
                        finally
                            _tls_close_quiet!(conn)
                        end
                    end)
                    client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", client_cfg)
                    read(client, 1) == UInt8[0x51] || error("unexpected TLS server byte")
                    write(client, UInt8[0x61]) == 1 || error("unexpected TLS client ack write")
                    @test _tls_wait_task_done(accept_task, 12.0) != :timed_out
                    return TL.connection_state(client), fetch(accept_task)::TL.ConnectionState
                finally
                    _tls_close_quiet!(client)
                    _tls_close_quiet!(listener)
                    IP.shutdown!()
                end
            end

            server_cfg = _tls_server_config(
                handshake_timeout_ns = 10_000_000_000,
                cert_file = _TLS_NATIVE_SERVER_CERT_PATH,
                key_file = _TLS_NATIVE_SERVER_KEY_PATH,
                client_auth = TL.ClientAuthMode.RequireAndVerifyClientCert,
                client_ca_file = _TLS_NATIVE_CA_PATH,
                min_version = TL.TLS1_2_VERSION,
                max_version = TL.TLS1_2_VERSION,
            )
            client_cfg = TL.Config(
                verify_peer = true,
                verify_hostname = true,
                server_name = "localhost",
                ca_file = _TLS_NATIVE_CA_PATH,
                cert_file = _TLS_NATIVE_CLIENT_CERT_PATH,
                key_file = _TLS_NATIVE_CLIENT_KEY_PATH,
                handshake_timeout_ns = 10_000_000_000,
            )

            client_state1, server_state1 = run_once(server_cfg, client_cfg)
            @test client_state1.version == "TLSv1.2"
            @test server_state1.version == "TLSv1.2"
            @test !client_state1.using_native_tls13
            @test !server_state1.using_native_tls13
            @test client_state1.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            @test server_state1.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            @test !client_state1.did_resume
            @test !server_state1.did_resume
            @test client_state1.has_resumable_session
            @test client_state1.curve == "P-256"
            @test server_state1.curve == "P-256"

            client_state2, server_state2 = run_once(server_cfg, client_cfg)
            @test client_state2.version == "TLSv1.2"
            @test server_state2.version == "TLSv1.2"
            @test !client_state2.using_native_tls13
            @test !server_state2.using_native_tls13
            @test client_state2.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            @test server_state2.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            @test client_state2.did_resume
            @test server_state2.did_resume
            @test client_state2.has_resumable_session
            @test client_state2.curve == "P-256"
            @test server_state2.curve == "P-256"
        end
        @testset "mixed-version native server supports TLS 1.2 mTLS and resumption against an exact TLS 1.2 client" begin
            function run_once(server_cfg::TL.Config, client_cfg::TL.Config)
                listener = nothing
                client = nothing
                accept_task = nothing
                try
                    listener = TL.listen("tcp", "127.0.0.1:0", server_cfg; backlog = 16)
                    laddr = TL.addr(listener)::NC.SocketAddrV4
                    accept_task = errormonitor(Threads.@spawn begin
                        conn = TL.accept(listener)
                        try
                            TL.handshake!(conn)
                            write(conn, UInt8[0x52])
                            read(conn, 1) == UInt8[0x62] || error("unexpected TLS client ack")
                            return TL.connection_state(conn)
                        finally
                            _tls_close_quiet!(conn)
                        end
                    end)
                    client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", client_cfg)
                    read(client, 1) == UInt8[0x52] || error("unexpected TLS server byte")
                    write(client, UInt8[0x62]) == 1 || error("unexpected TLS client ack write")
                    @test _tls_wait_task_done(accept_task, 12.0) != :timed_out
                    return TL.connection_state(client), fetch(accept_task)::TL.ConnectionState
                finally
                    _tls_close_quiet!(client)
                    _tls_close_quiet!(listener)
                    IP.shutdown!()
                end
            end

            server_cfg = _tls_server_config(
                handshake_timeout_ns = 10_000_000_000,
                cert_file = _TLS_NATIVE_SERVER_CERT_PATH,
                key_file = _TLS_NATIVE_SERVER_KEY_PATH,
                client_auth = TL.ClientAuthMode.RequireAndVerifyClientCert,
                client_ca_file = _TLS_NATIVE_CA_PATH,
            )
            client_cfg = TL.Config(
                verify_peer = true,
                verify_hostname = true,
                server_name = "localhost",
                ca_file = _TLS_NATIVE_CA_PATH,
                cert_file = _TLS_NATIVE_CLIENT_CERT_PATH,
                key_file = _TLS_NATIVE_CLIENT_KEY_PATH,
                handshake_timeout_ns = 10_000_000_000,
                min_version = TL.TLS1_2_VERSION,
                max_version = TL.TLS1_2_VERSION,
            )

            client_state1, server_state1 = run_once(server_cfg, client_cfg)
            @test client_state1.version == "TLSv1.2"
            @test server_state1.version == "TLSv1.2"
            @test !client_state1.using_native_tls13
            @test !server_state1.using_native_tls13
            @test client_state1.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            @test server_state1.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            @test !client_state1.did_resume
            @test !server_state1.did_resume
            @test client_state1.has_resumable_session
            @test client_state1.curve == "P-256"
            @test server_state1.curve == "P-256"

            client_state2, server_state2 = run_once(server_cfg, client_cfg)
            @test client_state2.version == "TLSv1.2"
            @test server_state2.version == "TLSv1.2"
            @test !client_state2.using_native_tls13
            @test !server_state2.using_native_tls13
            @test client_state2.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            @test server_state2.cipher_suite == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
            @test client_state2.did_resume
            @test server_state2.did_resume
            @test client_state2.has_resumable_session
            @test client_state2.curve == "P-256"
            @test server_state2.curve == "P-256"
        end
        @testset "mixed-version native client still offers TLS 1.2 resumption when a TLS 1.3 session is cached" begin
            function run_once(server_cfg::TL.Config, client_cfg::TL.Config)::TL.ConnectionState
                listener = nothing
                client = nothing
                accept_task = nothing
                try
                    listener = TL.listen("tcp", "127.0.0.1:0", server_cfg; backlog = 16)
                    laddr = TL.addr(listener)::NC.SocketAddrV4
                    accept_task = errormonitor(Threads.@spawn begin
                        conn = TL.accept(listener)
                        try
                            TL.handshake!(conn)
                            write(conn, UInt8[0x53])
                            read(conn, 1) == UInt8[0x63] || error("unexpected TLS client ack")
                            return nothing
                        finally
                            _tls_close_quiet!(conn)
                        end
                    end)
                    client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", client_cfg)
                    read(client, 1) == UInt8[0x53] || error("unexpected TLS server byte")
                    write(client, UInt8[0x63]) == 1 || error("unexpected TLS client ack write")
                    @test _tls_wait_task_done(accept_task, 12.0) != :timed_out
                    fetch(accept_task)
                    return TL.connection_state(client)
                finally
                    _tls_close_quiet!(client)
                    _tls_close_quiet!(listener)
                    IP.shutdown!()
                end
            end

            client_cfg = TL.Config(
                verify_peer = false,
                server_name = "localhost",
                handshake_timeout_ns = 10_000_000_000,
            )
            mixed_server_cfg = _tls_server_config(handshake_timeout_ns = 10_000_000_000)
            exact_tls12_server_cfg = _tls_server_config(
                handshake_timeout_ns = 10_000_000_000,
                min_version = TL.TLS1_2_VERSION,
                max_version = TL.TLS1_2_VERSION,
            )

            tls13_state = run_once(mixed_server_cfg, client_cfg)
            @test tls13_state.version == "TLSv1.3"
            @test tls13_state.using_native_tls13
            @test tls13_state.has_resumable_session

            tls12_state1 = run_once(exact_tls12_server_cfg, client_cfg)
            @test tls12_state1.version == "TLSv1.2"
            @test !tls12_state1.using_native_tls13
            @test !tls12_state1.did_resume
            @test tls12_state1.has_resumable_session

            tls12_state2 = run_once(exact_tls12_server_cfg, client_cfg)
            @test tls12_state2.version == "TLSv1.2"
            @test !tls12_state2.using_native_tls13
            @test tls12_state2.did_resume
            @test tls12_state2.has_resumable_session
        end
        _tls_trace("DONE: connect/listen handshake and roundtrip")
        @testset "effective TLS 1.2 client routing stays native with client certs" begin
            IP.shutdown!()
            listener = nothing
            client_tls = nothing
            server_tls = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", TL.Config(
                    verify_peer = true,
                    verify_hostname = false,
                    cert_file = _TLS_NATIVE_SERVER_CERT_PATH,
                    key_file = _TLS_NATIVE_SERVER_KEY_PATH,
                    client_auth = TL.ClientAuthMode.RequireAndVerifyClientCert,
                    client_ca_file = _TLS_NATIVE_CA_PATH,
                    min_version = TL.TLS1_2_VERSION,
                    max_version = TL.TLS1_2_VERSION,
                ); backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept(listener)
                    TL.handshake!(conn)
                    return conn
                end)
                client_tls = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", TL.Config(
                    verify_peer = true,
                    verify_hostname = true,
                    server_name = "localhost",
                    ca_file = _TLS_NATIVE_CA_PATH,
                    cert_file = _TLS_NATIVE_CLIENT_CERT_PATH,
                    key_file = _TLS_NATIVE_CLIENT_KEY_PATH,
                    min_version = nothing,
                    max_version = TL.TLS1_2_VERSION,
                ))
                @test client_tls.policy == TL._TLS_POLICY_TLS12
                @test _tls_wait_task_done(accept_task, 12.0) != :timed_out
                server_tls = fetch(accept_task)
                client_state = TL.connection_state(client_tls)
                server_state = TL.connection_state(server_tls)
                @test client_state.version == "TLSv1.2"
                @test server_state.version == "TLSv1.2"
                @test !client_state.using_native_tls13
                @test !server_state.using_native_tls13
            finally
                _tls_close_quiet!(server_tls)
                _tls_close_quiet!(client_tls)
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        _tls_trace("START: write accepts string codeunits buffers")
        @testset "write accepts string codeunits buffers" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept(listener)
                    TL.handshake!(conn)
                    TL.set_read_deadline!(conn, time_ns() + 5_000_000_000)
                    server_codeunits_buf = Vector{UInt8}(undef, 2)
                    read!(conn, server_codeunits_buf)
                    write(conn, server_codeunits_buf)
                    return conn
                end)
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                    handshake_timeout_ns = 10_000_000_000,
                ))
                TL.set_read_deadline!(client, time_ns() + 5_000_000_000)
                @test write(client, codeunits("hi")) == 2
                client_codeunits_buf = Vector{UInt8}(undef, 2)
                @test read!(client, client_codeunits_buf) === client_codeunits_buf
                @test String(client_codeunits_buf) == "hi"
                @test _tls_wait_task_done(accept_task, 12.0) != :timed_out
                server = fetch(accept_task)
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        _tls_trace("DONE: write accepts string codeunits buffers")
        _tls_trace("START: peer read observes clean EOF after close_notify")
        @testset "peer read observes clean EOF after close_notify" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                close_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept(listener)
                    try
                        TL.handshake!(conn)
                    catch
                    end
                    close(conn)
                    return nothing
                end)
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                ))
                @test _tls_wait_task_done(close_task, 2.0) != :timed_out
                buf = Vector{UInt8}(undef, 1)
                @test eof(client)
                @test_throws EOFError read!(client, buf)
            finally
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "close_write shuts down TLS write side and rejects further writes" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept(listener)
                    TL.handshake!(conn)
                    return conn
                end)
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                ))
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)
                closewrite(client)
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
                @test eof(server)
                @test_throws EOFError read!(server, Vector{UInt8}(undef, 1))
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "close_write before handshake complete returns TLSError" begin
            IP.shutdown!()
            listener = nothing
            client_tcp = nothing
            server_tcp = nothing
            tls_client = nothing
            try
                listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn NC.accept(listener))
                client_tcp = ND.connect("tcp", "127.0.0.1:$(Int(laddr.port))")
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                server_tcp = fetch(accept_task)
                tls_client = TL.client(client_tcp, TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                ))
                err = try
                    closewrite(tls_client)
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
                IP.shutdown!()
            end
        end
        @testset "peer verification success with explicit CA file" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 16)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    try
                        conn = TL.accept(listener)
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
                IP.shutdown!()
            end
        end
        @testset "hostname verification can be enabled without chain verification" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 16)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    try
                        conn = TL.accept(listener)
                        TL.handshake!(conn)
                        return conn
                    catch err
                        return err
                    end
                end)
                client_cfg = TL.Config(
                    verify_peer = false,
                    verify_hostname = true,
                    server_name = "localhost",
                    handshake_timeout_ns = 10_000_000_000,
                    max_version = TL.TLS1_2_VERSION,
                )
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", client_cfg)
                @test _tls_wait_task_done(accept_task, 12.0) != :timed_out
                server_result = fetch(accept_task)
                server_result isa Exception && throw(server_result)
                server = server_result::TL.Conn
                @test TL.connection_state(client).handshake_complete
                @test !TL.connection_state(client).using_native_tls13
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "hostname verification failure surfaces TLSError without CA verification" begin
            IP.shutdown!()
            listener = nothing
            accept_task = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 16)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept(listener)
                    try
                        TL.handshake!(conn)
                    catch
                    end
                    _tls_close_quiet!(conn)
                    return nothing
                end)
                client_cfg = TL.Config(
                    verify_peer = false,
                    verify_hostname = true,
                    server_name = "example.com",
                    handshake_timeout_ns = 10_000_000_000,
                    max_version = TL.TLS1_2_VERSION,
                )
                connect_err = try
                    _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", client_cfg)
                    nothing
                catch ex
                    ex
                end
                @test connect_err isa TL.TLSError
                if connect_err isa TL.TLSError
                    @test occursin("certificate is not valid for host", connect_err.message)
                end
                accept_task !== nothing && _tls_wait_task_done(accept_task, 2.0)
            finally
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "peer verification failure surfaces TLSError" begin
            IP.shutdown!()
            listener = nothing
            accept_task = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 16)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept(listener)
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
                IP.shutdown!()
            end
        end
        @testset "ip literal verification path infers server_name and succeeds" begin
            IP.shutdown!()
            listener = nothing
            accept_task = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 16)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept(listener)
                    try
                        TL.handshake!(conn)
                        return conn
                    catch
                        _tls_close_quiet!(conn)
                        rethrow()
                    end
                end)
                client_cfg = TL.Config(
                    verify_peer = true,
                    ca_file = _TLS_CERT_PATH,
                    handshake_timeout_ns = 10_000_000_000,
                )
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", client_cfg)
                @test _tls_wait_task_done(accept_task, 12.0) != :timed_out
                server = fetch(accept_task)
                client_state = TL.connection_state(client)
                server_state = TL.connection_state(server)
                @test client_state.handshake_complete
                @test server_state.handshake_complete
                @test client_state.version == "TLSv1.3"
                @test server_state.version == "TLSv1.3"
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "handshake timeout surfaces TLSHandshakeTimeoutError" begin
            IP.shutdown!()
            listener = nothing
            client_tcp = nothing
            stalled_peer = nothing
            try
                listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = NC.accept(listener)
                    IP.sleep(1.0)
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
                IP.shutdown!()
            end
        end
        @testset "handshake deadline with no handshake_timeout maps to i/o timeout TLSError" begin
            IP.shutdown!()
            listener = nothing
            client_tcp = nothing
            stalled_peer = nothing
            client_tls = nothing
            try
                listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = NC.accept(listener)
                    IP.sleep(1.0)
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
                IP.shutdown!()
            end
        end
        @testset "host resolver timeout budget includes TLS handshake time" begin
            IP.shutdown!()
            listener = nothing
            stalled_peer = nothing
            try
                listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = NC.accept(listener)
                    IP.sleep(1.2)
                    close(conn)
                    return nothing
                end)
                host_resolver = ND.HostResolver(timeout_ns = 250_000_000)
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
                IP.shutdown!()
            end
        end
        @testset "operations fail fast after close" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept(listener)
                    TL.handshake!(conn)
                    return conn
                end)
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                ))
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)
                close(client)
                close(client)
                @test_throws TL.TLSError TL.handshake!(client)
                @test_throws TL.TLSError read!(client, Vector{UInt8}(undef, 1))
                @test_throws TL.TLSError write(client, UInt8[0x41])
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "readbytes! and read support single-read mode" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept(listener)
                    TL.handshake!(conn)
                    return conn
                end)
                client = _tls_connect("tcp", "127.0.0.1:$(Int(laddr.port))", TL.Config(
                    verify_peer = false,
                    server_name = "localhost",
                ))
                @test _tls_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)

                first_payload = UInt8[0x41, 0x42]
                @test write(client, first_payload) == length(first_payload)
                TL.set_read_deadline!(server, time_ns() + 250_000_000)
                first_buf = Vector{UInt8}(undef, 4)
                @test readbytes!(server, first_buf, 4; all = false) == length(first_payload)
                @test first_buf[1:2] == first_payload
                TL.set_read_deadline!(server, Int64(0))

                second_payload = UInt8[0x43, 0x44]
                @test write(client, second_payload) == length(second_payload)
                TL.set_read_deadline!(server, time_ns() + 250_000_000)
                @test read(server, 4; all = false) == second_payload
                TL.set_read_deadline!(server, Int64(0))

                third_payload = UInt8[0x45, 0x46]
                @test write(client, third_payload) == length(third_payload)
                TL.set_read_deadline!(server, time_ns() + 250_000_000)
                grown_buf = fill(UInt8(0x00), 3)
                @test readbytes!(server, grown_buf, 5; all = false) == length(third_payload)
                @test grown_buf[1:2] == third_payload
                @test length(grown_buf) == 3
                TL.set_read_deadline!(server, Int64(0))

                fourth_payload = UInt8[0x47, 0x48]
                @test write(client, fourth_payload) == length(fourth_payload)
                TL.set_read_deadline!(server, time_ns() + 250_000_000)
                view_backing = fill(UInt8(0x00), 5)
                view_buf = @view view_backing[2:4]
                @test readbytes!(server, view_buf, 3; all = false) == length(fourth_payload)
                @test view_backing == UInt8[0x00, 0x47, 0x48, 0x00, 0x00]
                TL.set_read_deadline!(server, Int64(0))
            finally
                _tls_close_quiet!(server)
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "write timeout remains sticky across subsequent writes" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                hold_task = errormonitor(@async begin
                    conn = TL.accept(listener)
                    TL.handshake!(conn)
                    IP.sleep(1.5)
                    close(conn)
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
                fetch(hold_task)
            finally
                _tls_close_quiet!(client)
                _tls_close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "blocked read unblocks when local close races" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            read_task = nothing
            try
                listener = TL.listen("tcp", "127.0.0.1:0", _tls_server_config(); backlog = 8)
                laddr = TL.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn begin
                    conn = TL.accept(listener)
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
                close(client)
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
                IP.shutdown!()
            end
        end
    end
