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
        base._verification_time_s,
    )
end

@testset "TLS config and helpers" begin
    @test TL.Conn <: IO
    @test TL.DeadlineExceededError === NC.DeadlineExceededError
    @test TL.DeadlineExceededError === IP.DeadlineExceededError

    @testset "config copy and legacy positional form" begin
        base = TL.Config(
            server_name = "base.example",
            ca_dir = SubString(dirname(_TLS_CERT_PATH), 1),
            client_ca_dir = dirname(_TLS_NATIVE_CA_PATH),
            verify_peer = false,
            verify_hostname = false,
            cert_file = _TLS_CERT_PATH,
            key_file = _TLS_KEY_PATH,
            alpn_protocols = ["h2", "http/1.1"],
            curve_preferences = UInt16[TL.P256],
            handshake_timeout_ns = Int64(1_000),
            max_version = TL.TLS1_3_VERSION,
            session_tickets_disabled = true,
        )
        copied = TL.Config(
            base;
            server_name = "copy.example",
            alpn_protocols = ["http/1.1"],
            handshake_timeout_ns = Int64(2_000),
        )
        @test copied.server_name == "copy.example"
        @test copied.alpn_protocols == ["http/1.1"]
        @test copied.handshake_timeout_ns == Int64(2_000)
        @test copied.curve_preferences == base.curve_preferences
        # Vectors are owned by the copy, as with a fresh config.
        @test copied.curve_preferences !== base.curve_preferences
        @test copied.alpn_protocols !== base.alpn_protocols
        @test copied.verify_peer == base.verify_peer
        @test copied.verify_hostname == base.verify_hostname
        @test copied.client_auth == base.client_auth
        @test copied.cert_file == base.cert_file
        @test copied.key_file == base.key_file
        @test copied.ca_file === base.ca_file
        @test copied.client_ca_file === base.client_ca_file
        @test copied.ca_dir === base.ca_dir
        @test copied.client_ca_dir === base.client_ca_dir
        @test copied.ca_dir isa String
        @test copied.min_version == base.min_version
        @test copied.max_version == base.max_version
        @test copied.session_tickets_disabled == base.session_tickets_disabled
        # Private state is shared, so resumption and the loaded identity carry over.
        @test copied._session_ticket_keys === base._session_ticket_keys
        @test copied._client_session_cache === base._client_session_cache
        @test copied._server_session_cache === base._server_session_cache
        @test copied._client_session_cache12 === base._client_session_cache12
        @test copied._server_session_cache12 === base._server_session_cache12
        @test copied._client_identity === base._client_identity
        @test copied._server_identity === base._server_identity
        @test copied._verification_time_s === base._verification_time_s

        renamed = TL._config_with_server_name(base, "renamed.example")
        @test renamed.server_name == "renamed.example"
        @test renamed._client_session_cache === base._client_session_cache
        @test renamed._client_identity === base._client_identity

        # Different credentials must not inherit an identity that may already be loaded.
        recredentialed = TL.Config(
            base;
            cert_file = _TLS_NATIVE_SERVER_CERT_PATH,
            key_file = _TLS_NATIVE_SERVER_KEY_PATH,
        )
        @test recredentialed.cert_file == abspath(_TLS_NATIVE_SERVER_CERT_PATH)
        @test recredentialed.key_file == abspath(_TLS_NATIVE_SERVER_KEY_PATH)
        @test recredentialed._client_identity !== base._client_identity
        @test recredentialed._server_identity !== base._server_identity
        @test recredentialed._client_session_cache === base._client_session_cache
        @test recredentialed._session_ticket_keys === base._session_ticket_keys

        # Copies go through the same validation as fresh configs.
        @test_throws TL.ConfigError TL.Config(base; handshake_timeout_ns = Int64(-1))
        @test_throws TL.ConfigError TL.Config(base; key_file = nothing)
        @test_throws TL.ConfigError TL.Config(base; min_version = TL.TLS1_3_VERSION, max_version = TL.TLS1_2_VERSION)
        @test_throws TL.ConfigError TL.Config(TL.Config(); cert_file = _TLS_CERT_PATH)

        # HTTP.jl 2.6.x builds configs positionally from the field list that predates
        # `_verification_time_s`. That arity must keep working and select the wall clock.
        fixture = TL.Config(
            server_name = "fixture.example",
            verify_peer = false,
            _verification_time_s = Int64(1_700_000_000),
        )
        legacy = TL.Config(
            "legacy.example",
            fixture.verify_peer,
            fixture.verify_hostname,
            fixture.client_auth,
            fixture.cert_file,
            fixture.key_file,
            fixture.ca_file,
            fixture.client_ca_file,
            copy(fixture.alpn_protocols),
            copy(fixture.curve_preferences),
            fixture.handshake_timeout_ns,
            fixture.min_version,
            fixture.max_version,
            fixture.session_tickets_disabled,
            fixture._session_ticket_keys,
            fixture._client_session_cache,
            fixture._server_session_cache,
            fixture._client_session_cache12,
            fixture._server_session_cache12,
            fixture._client_identity,
            fixture._server_identity,
        )
        @test legacy.server_name == "legacy.example"
        @test legacy.verify_peer == fixture.verify_peer
        @test legacy._verification_time_s === nothing
        @test legacy._client_session_cache === fixture._client_session_cache
        @test legacy._client_identity === fixture._client_identity
        # Adding a field means revisiting the 21-argument compatibility method above.
        @test fieldcount(TL.Config) == 24
        @test legacy.ca_dir === legacy.client_ca_dir === nothing
        raw = _tls_raw_config_for_test(fixture)
        @test raw._verification_time_s == fixture._verification_time_s
        @test raw.ca_dir === raw.client_ca_dir === nothing
    end

    @testset "config validation" begin
        cfg_default = TL.Config()
        @test cfg_default.ca_dir === nothing
        @test cfg_default.client_ca_dir === nothing
        @test cfg_default.min_version == TL.TLS1_2_VERSION
        @test cfg_default.client_auth == TL.ClientAuthMode.NoClientCert
        @test cfg_default.verify_hostname
        @test !isdefined(TL, :TLS1_0_VERSION)
        @test !isdefined(TL, :TLS1_1_VERSION)
        @test TL._native_curve_preferences(cfg_default) == UInt16[TL.X25519, TL.P256, TL.P384, TL.P521]
        @test TL._tls12_curve_preferences(cfg_default) == UInt16[TL.X25519, TL.P256, TL.P384, TL.P521]
        @test TL._native_curve_preferences(TL.Config(
            min_version = TL.TLS1_3_VERSION,
            max_version = TL.TLS1_3_VERSION,
            curve_preferences = UInt16[TL.P521, TL.P384, TL.P256, TL.X25519],
        )) == UInt16[TL.P521, TL.P384, TL.P256, TL.X25519]
        alpn = ["h2"]
        curves = UInt16[TL.P256]
        positional_cfg = TL.Config(
            "example.com",
            false,
            false,
            TL.ClientAuthMode.NoClientCert,
            nothing,
            nothing,
            nothing,
            nothing,
            alpn,
            curves,
            Int64(123),
            TL.TLS1_2_VERSION,
            TL.TLS1_3_VERSION,
            true,
        )
        @test positional_cfg.server_name == "example.com"
        @test !positional_cfg.verify_peer
        @test !positional_cfg.verify_hostname
        @test positional_cfg.client_auth == TL.ClientAuthMode.NoClientCert
        @test positional_cfg.alpn_protocols == ["h2"]
        @test positional_cfg.curve_preferences == UInt16[TL.P256]
        @test positional_cfg.handshake_timeout_ns == 123
        @test positional_cfg.min_version == TL.TLS1_2_VERSION
        @test positional_cfg.max_version == TL.TLS1_3_VERSION
        @test positional_cfg.session_tickets_disabled
        push!(alpn, "http/1.1")
        push!(curves, TL.X25519)
        @test positional_cfg.alpn_protocols == ["h2"]
        @test positional_cfg.curve_preferences == UInt16[TL.P256]
        @test_throws TL.ConfigError TL.Config(
            nothing,
            true,
            true,
            TL.ClientAuthMode.NoClientCert,
            _TLS_CERT_PATH,
            nothing,
            nothing,
            nothing,
            String[],
            UInt16[],
            Int64(0),
            TL.TLS1_2_VERSION,
            nothing,
            false,
        )
        @test_throws TL.ConfigError TL.Config(
            nothing,
            true,
            true,
            TL.ClientAuthMode.NoClientCert,
            nothing,
            nothing,
            nothing,
            nothing,
            String[],
            UInt16[],
            Int64(-1),
            TL.TLS1_2_VERSION,
            nothing,
            false,
        )
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
        @test TL._validate_config(TL.Config(verify_peer = false, curve_preferences = UInt16[TL.P384]); is_server = false) === nothing
        @test TL._validate_config(TL.Config(verify_peer = false, curve_preferences = UInt16[TL.P521]); is_server = false) === nothing
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
            _tls_wait_task_done(accept_task)
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
