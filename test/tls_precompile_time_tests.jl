using Test
using Reseau

@testset "TLS precompile certificate time" begin
    tls = Reseau.TLS
    resources = joinpath(@__DIR__, "resources")
    expired = joinpath(resources, "expired_precompile.crt")
    key = joinpath(resources, "unittests.key")
    certs = tls._tls_decode_pem_certificates(read(expired))
    cert = tls._tls_parse_der_certificate_info(only(certs))
    verify_at(t) = tls._tls13_verify_server_certificate_chain(
        certs, "localhost"; verify_peer = true, verify_hostname = true,
        ca_file = expired, verification_time_s = t,
    )
    # This is the original, signed fixture from v1.3.1, expired August 6, 2026.
    @test_throws tls._TLSAlertError verify_at(nothing)
    @test_throws tls._TLSAlertError verify_at(cert.not_before_s - 1)
    @test_throws tls._TLSAlertError verify_at(cert.not_after_s + 1)
    @test verify_at(cert.not_before_s) isa tls._TLSPublicKey
    @test verify_at(cert.not_after_s) isa tls._TLSPublicKey
    @test verify_at(Reseau._PC_TLS_VERIFICATION_TIME_S) isa tls._TLSPublicKey
    @test tls.Config()._verification_time_s === nothing
    @test_throws tls._TLSAlertError tls._tls13_verify_server_certificate_chain(
        certs, "wrong.example"; verify_peer = true, verify_hostname = true,
        ca_file = expired, verification_time_s = Reseau._PC_TLS_VERIFICATION_TIME_S,
    )
    @test_throws tls._TLSAlertError tls._tls13_verify_server_certificate_chain(
        certs, "localhost"; verify_peer = true, verify_hostname = true,
        ca_file = joinpath(resources, "native_tls_ca.crt"),
        verification_time_s = Reseau._PC_TLS_VERIFICATION_TIME_S,
    )

    # All fixtures, including the mTLS CA/client and ECDSA certificate, must
    # contain the chosen instant. Check both certificate purposes explicitly.
    for name in ("unittests.crt", "native_tls_ca.crt", "native_tls_server.crt",
                 "native_tls_client.crt", "native_tls_server_ecdsa.crt")
        path = joinpath(resources, name)
        info = tls._tls_parse_der_certificate_info(only(tls._tls_decode_pem_certificates(read(path))))
        @test info.not_before_s <= Reseau._PC_TLS_VERIFICATION_TIME_S <= info.not_after_s
    end
    client_certs = tls._tls_decode_pem_certificates(read(joinpath(resources, "native_tls_client.crt")))
    for t in (Int64(0), Int64(2_208_988_800)) # 1970 and 2040
        @test_throws tls._TLSAlertError tls._tls13_verify_client_certificate_chain(
            client_certs; verify_peer = true, ca_file = joinpath(resources, "native_tls_ca.crt"),
            verification_time_s = t,
        )
    end
    @test tls._tls13_verify_client_certificate_chain(
        client_certs; verify_peer = true, ca_file = joinpath(resources, "native_tls_ca.crt"),
        verification_time_s = Reseau._PC_TLS_VERIFICATION_TIME_S,
    ) isa tls._TLSPublicKey

    # Real handshakes with the expired certificate must work in the canonical
    # precompile configurations, with peer and hostname verification enabled.
    for version in (tls.TLS1_2_VERSION, tls.TLS1_3_VERSION)
        server = Reseau._pc_tls_server_config(expired, key; min_version = version, max_version = version)
        client = Reseau._pc_tls_client_config(;
            verify_peer = true, ca_file = expired, min_version = version, max_version = version,
        )
        renamed = tls._config_with_server_name(client, "localhost")
        @test renamed._verification_time_s == Reseau._PC_TLS_VERIFICATION_TIME_S
        states = Reseau._pc_run_tls_roundtrip_states!(server, renamed)
        @test states.client_state.version == (version == tls.TLS1_2_VERSION ? "TLSv1.2" : "TLSv1.3")
        @test !states.client_state.did_resume
        resumed = Reseau._pc_run_tls_roundtrip_states!(server, renamed)
        @test resumed.client_state.did_resume
        @test resumed.server_state.did_resume
        normal = tls.Config(; verify_peer = true, server_name = "localhost", ca_file = expired,
                            min_version = version, max_version = version)
        @test_throws tls.TLSError Reseau._pc_run_tls_roundtrip_states!(server, normal)
    end
    # Verify that both peers consume the override in real TLS 1.2/1.3 mTLS.
    # A future time on just the server must reject the client certificate;
    # a future time on just the client must reject the server certificate.
    for version in (tls.TLS1_2_VERSION, tls.TLS1_3_VERSION)
        server_at(t) = tls.Config(;
            cert_file = joinpath(resources, "native_tls_server.crt"),
            key_file = joinpath(resources, "native_tls_server.key"),
            client_auth = tls.ClientAuthMode.RequireAndVerifyClientCert,
            client_ca_file = joinpath(resources, "native_tls_ca.crt"),
            min_version = version, max_version = version, _verification_time_s = t,
        )
        client_at(t) = tls.Config(;
            server_name = "localhost", ca_file = joinpath(resources, "native_tls_ca.crt"),
            cert_file = joinpath(resources, "native_tls_client.crt"),
            key_file = joinpath(resources, "native_tls_client.key"),
            min_version = version, max_version = version, _verification_time_s = t,
        )
        valid = Reseau._PC_TLS_VERIFICATION_TIME_S
        future = Int64(2_208_988_800)
        @test_throws tls.TLSError Reseau._pc_run_tls_roundtrip_states!(server_at(future), client_at(valid))
        @test_throws tls.TLSError Reseau._pc_run_tls_roundtrip_states!(server_at(valid), client_at(future))
    end
    # Exercise mTLS and session resumption through the shared production workload.
    @test Reseau._pc_run_tls_workload!() === nothing
end
