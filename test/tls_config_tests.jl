using Test
using NetworkOptions
using Reseau

isdefined(@__MODULE__, :_RESEAU_TLS_TEST_UTILS_LOADED) || include("tls_test_utils.jl")

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
        base._session_ticket_keys,
        base._client_session_cache,
        base._server_session_cache,
        base._client_session_cache12,
        base._server_session_cache12,
        base._client_identity,
        base._server_identity,
    )
end

@testset "TLS config and helpers" begin
    @test TL.Conn <: IO
    @test TL.DeadlineExceededError === NC.DeadlineExceededError
    @test TL.DeadlineExceededError === IP.DeadlineExceededError

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
        @test TL._tls13_client_hello(disabled_ticket_cfg).ocsp_stapling
        @test TL._tls13_client_hello(disabled_ticket_cfg).scts
        @test !TL._tls_auto_client_hello(disabled_ticket_cfg).ocsp_stapling
        @test !TL._tls_auto_client_hello(disabled_ticket_cfg).scts
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

    @testset "SNI/hostname normalization parity" begin
        @test TL._normalize_peer_name("example.com.") == "example.com"
        @test TL._normalize_peer_name("[::1]") == "::1"
        @test TL._normalize_peer_name("fe80::1%lo0") == "fe80::1"
        @test TL._hostname_in_sni("example.com.") == "example.com"
        @test TL._hostname_in_sni("127.0.0.1") == ""
        @test TL._hostname_in_sni("[::1]") == ""
    end
end
