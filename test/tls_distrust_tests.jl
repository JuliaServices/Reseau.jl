module TLSKeyDistrustTests

using Test
using Reseau

const T = Reseau.TLS
const FIXTURES = joinpath(@__DIR__, "resources", "emudhra")
const ROOTS = joinpath(FIXTURES, "roots.pem")
const VERIFY_TIME = Int64(1792497600) # 2026-10-20 12:00:00 UTC

certificates(path) = T._tls_decode_pem_certificates(read(path))

function verification_error(certs, store, purpose = "ssl_server")
    try
        T._tls_verify_peer_certificate_chain!(certs, store, purpose, VERIFY_TIME)
        return nothing
    catch err
        return err
    end
end

@testset "compromised CA public keys" begin
    affected = certificates(joinpath(FIXTURES, "intermediates.pem"))
    expected_hashes = readlines(joinpath(FIXTURES, "spki-sha256.txt"))
    @test length(affected) == length(expected_hashes) == 16
    @test length(unique(expected_hashes)) == 8

    @testset "all keys and cross-signs, including direct trust" begin
        for (der, expected_hash) in zip(affected, expected_hashes)
            cert = T._tls_parse_der_certificate_info(der)
            @test bytes2hex(collect(cert.spki_sha256)) == expected_hash
            @test T._tls_certificate_distrusted(cert)
            # Supplying the compromised certificate as a trust anchor must not
            # bypass distrust, even when it is also the peer's leaf certificate.
            store = T._TLSTrustStore([cert])
            for purpose in ("ssl_server", "ssl_client")
                err = verification_error([der], store, purpose)
                @test err isa T._TLSAlertError
                @test occursin("distrusted public key", sprint(showerror, err))
            end
        end
    end

    @testset "real chains and directly trusted compromised issuers" begin
        store = T._tls_load_trust_store(ROOTS)
        chain_files = filter(f -> endswith(f, ".we-have-a-problem.com.pem"), readdir(FIXTURES))
        @test length(chain_files) == 12
        for file in chain_files
            certs = certificates(joinpath(FIXTURES, file))
            parsed = T._tls_parse_der_certificate_info.(certs)
            @test all(cert -> T._tls_certificate_valid_now(cert, VERIFY_TIME), parsed)
            # The leaf really is signed by the affected key; this must fail
            # because of distrust, not a malformed fixture or an invalid signature.
            @test T._tls_verify_certificate_signature(parsed[1], parsed[2])
            @test !T._tls_certificate_distrusted(parsed[1])
            @test T._tls_certificate_distrusted(parsed[2])
            err = verification_error(certs, store)
            @test err isa T._TLSAlertError
            @test occursin("unknown authority", sprint(showerror, err))
            # Exercise the root-candidate loop with the intermediate in the
            # trust store, and the peer sending only its leaf.
            @test verification_error(certs[1:1], T._TLSTrustStore([parsed[2]])) isa T._TLSAlertError
        end
    end

    @testset "unrelated valid paths remain usable" begin
        good = certificates(joinpath(@__DIR__, "resources", "native_tls_server.crt"))
        good_root = T._tls_load_trust_store(joinpath(@__DIR__, "resources", "native_tls_ca.crt"))
        mixed = T._TLSTrustStore(vcat(T._tls_parse_der_certificate_info.(affected), good_root.roots))
        @test verification_error(good, mixed) === nothing
        # An unused certificate sent by the peer is not part of the chosen path.
        @test verification_error(vcat(good, affected), mixed) === nothing
        @test !T._tls_certificate_distrusted(T._tls_parse_der_certificate_info(good[1]))
    end

    @testset "custom CA files and directories" begin
        certs = certificates(joinpath(FIXTURES, "dv-g3b-aaa-emudhra.we-have-a-problem.com.pem"))
        mktempdir() do dir
            cp(ROOTS, joinpath(dir, "roots.pem"))
            for (ca_file, ca_dir) in ((ROOTS, nothing), (nothing, dir), (ROOTS, dir))
                @test_throws T._TLSAlertError T._tls13_verify_server_certificate_chain(
                    certs, "dv-g3b-aaa-emudhra.we-have-a-problem.com";
                    verify_peer = true, verify_hostname = true,
                    ca_file, ca_dir, verification_time_s = VERIFY_TIME,
                )
            end
        end
    end

    @testset "TLS 1.2 and TLS 1.3 session caches recheck distrust" begin
        good_path = joinpath(@__DIR__, "resources", "native_tls_server.crt")
        good_ca = joinpath(@__DIR__, "resources", "native_tls_ca.crt")
        bad_path = joinpath(FIXTURES, "dv-g3b-aaa-emudhra.we-have-a-problem.com.pem")
        for (path, ca_file, server_name, allowed) in (
            (good_path, good_ca, "localhost", true),
            (bad_path, ROOTS, "dv-g3b-aaa-emudhra.we-have-a-problem.com", false),
        )
            config = T.Config(; server_name, ca_file, _verification_time_s = VERIFY_TIME)
            certs = certificates(path)
            # Artificial tickets need no clock reads or network I/O: their
            # lifetime is unbounded so only certificate policy decides reuse.
            session12 = T._TLS12ClientSession(
                T.TLS1_2_VERSION, T._TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256_ID,
                UInt64(VERIFY_TIME), typemax(UInt64), UInt8[1], zeros(UInt8, 48),
                certs, "", T.X25519, true,
            )
            T._tls_session_cache_put!(config._client_session_cache12, server_name, session12, T._securezero_tls12_client_session!)
            loaded12 = T._tls12_try_load_client_session(config, server_name, T._tls12_client_hello(config))
            @test (loaded12 !== nothing) == allowed
            @test (T._tls_session_cache_get(config._client_session_cache12, server_name) !== nothing) == allowed

            session13 = T._TLS13ClientSession(
                T.TLS1_3_VERSION, T._TLS13_AES_128_GCM_SHA256_ID,
                UInt64(VERIFY_TIME), typemax(UInt64), UInt32(0), UInt8[1],
                zeros(UInt8, 32), certs, "",
            )
            T._tls_session_cache_put!(config._client_session_cache, server_name, session13, T._securezero_tls13_client_session!)
            loaded13 = T._tls13_try_load_client_session(config, server_name, T._tls13_client_hello(config))
            @test (loaded13 !== nothing) == allowed
            @test (T._tls_session_cache_get(config._client_session_cache, server_name) !== nothing) == allowed
        end
    end
end

end # module
