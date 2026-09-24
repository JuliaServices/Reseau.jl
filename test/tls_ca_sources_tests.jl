module TLSCASourceTests
using Test, Reseau
const TLS = Reseau.TLS
const TCP = Reseau.TCP
const FIXTURES = joinpath(@__DIR__, "resources", "combined_ca")
const CA_A = joinpath(FIXTURES, "ca_a.crt")
const CA_B = joinpath(FIXTURES, "ca_b", "ca_b.crt")
const KEY = joinpath(FIXTURES, "leaf.key")
# Fixed fixture time; transport deadlines and ticket lifetimes still use live clocks.
const VERIFY_TIME = Int64(1790121600) # 2026-09-23 UTC

function roundtrip(listener, client_config, server_config=listener.config)
    release_server = Channel{Nothing}(1)
    server_task = Threads.@spawn begin
        server_conn = nothing
        try
            server_conn = TLS.server(TCP.accept(listener.listener), server_config)
            TLS.set_deadline!(server_conn, time_ns() + 10_000_000_000)
            TLS.handshake!(server_conn)
            write(server_conn, UInt8[0x11])
            read(server_conn, 1) == UInt8[0x21] || error("missing client acknowledgement")
            state = TLS.connection_state(server_conn)
            take!(release_server)
            state
        catch err
            err
        finally
            server_conn === nothing || close(server_conn)
        end
    end
    conn = nothing
    client_result = try
        conn = TLS.connect(TLS.addr(listener), client_config)
        TLS.set_deadline!(conn, time_ns() + 10_000_000_000)
        read(conn, 1) == UInt8[0x11] || error("missing server byte")
        write(conn, UInt8[0x21])
        TLS.connection_state(conn)
    catch err
        err
    finally
        put!(release_server, nothing)
        conn === nothing || close(conn)
    end
    return client_result, fetch(server_task)
end

function successful(result; resumed=false)
    client, server = result
    @test client isa TLS.ConnectionState
    @test server isa TLS.ConnectionState
    if client isa TLS.ConnectionState && server isa TLS.ConnectionState
        @test client.handshake_complete && server.handshake_complete
        @test client.did_resume == resumed
        @test server.did_resume == resumed
    end
end

@testset "Combined CA sources" begin
    mktempdir() do dir
        roots = joinpath(dir, "roots")
        mkdir(roots)
        cp(CA_B, joinpath(roots, "root.pem"))
        for version in (TLS.TLS1_2_VERSION, TLS.TLS1_3_VERSION), issuer in ("a", "b")
            leaf = joinpath(FIXTURES, "leaf_$issuer.crt")
            client_issuer = issuer == "a" ? "b" : "a"
            client_leaf = joinpath(FIXTURES, "leaf_$client_issuer.crt")
            server_config = TLS.Config(
                cert_file=leaf, key_file=KEY, verify_peer=false,
                client_auth=TLS.ClientAuthMode.RequireAndVerifyClientCert,
                client_ca_file=CA_A, client_ca_dir=roots,
                min_version=version, max_version=version,
                handshake_timeout_ns=10_000_000_000, _verification_time_s=VERIFY_TIME,
            )
            client_config = TLS.Config(
                server_name="localhost", cert_file=client_leaf, key_file=KEY,
                ca_file=CA_A, ca_dir=roots, min_version=version, max_version=version,
                handshake_timeout_ns=10_000_000_000, _verification_time_s=VERIFY_TIME,
            )
            listener = TLS.listen("tcp", "127.0.0.1:0", server_config)
            try
                successful(roundtrip(listener, client_config))
                successful(roundtrip(listener, TLS.Config(client_config; handshake_timeout_ns=Int64(10_000_000_000))); resumed=true)
                # Removing the required source must invalidate the cached peer chain.
                wrong_client = issuer == "a" ? TLS.Config(client_config; ca_file=nothing) : TLS.Config(client_config; ca_dir=nothing)
                @test first(roundtrip(listener, wrong_client)) isa TLS.TLSError
                successful(roundtrip(listener, client_config))
                wrong_server = client_issuer == "a" ? TLS.Config(server_config; client_ca_file=nothing) : TLS.Config(server_config; client_ca_dir=nothing)
                @test last(roundtrip(listener, client_config, wrong_server)) isa TLS.TLSError
                # Each source also works independently for its own issuer.
                only_client = issuer == "a" ? TLS.Config(client_config; ca_dir=nothing) : TLS.Config(client_config; ca_file=nothing)
                only_server = client_issuer == "a" ? TLS.Config(server_config; client_ca_dir=nothing) : TLS.Config(server_config; client_ca_file=nothing)
                only_client = TLS.Config(only_client; session_tickets_disabled=true)
                successful(roundtrip(listener, only_client, only_server))
                if issuer == "b"
                    @test TLS._effective_ca_file(only_client; is_server=false) === nothing
                    legacy = TLS.Config(only_client; ca_file=roots, ca_dir=nothing, session_tickets_disabled=true)
                    successful(roundtrip(listener, legacy, only_server))
                end
            finally
                close(listener)
            end
        end

        @testset "Cache isolation and source invalidation" begin
            file_store = TLS._tls_load_trust_store(CA_A)
            dir_store = TLS._tls_load_trust_store(roots)
            @test length(file_store.roots) == length(dir_store.roots) == 1
            combined = TLS._tls_load_trust_store(CA_A, roots)
            @test length(combined.roots) == 2
            @test TLS._tls_load_trust_store(CA_A) === file_store
            @test TLS._tls_load_trust_store(roots) === dir_store
            @test length(file_store.roots) == length(dir_store.roots) == 1
            write(joinpath(roots, "root.pem"), read(CA_A), repeat("\n", 64))
            @test length(TLS._tls_load_trust_store(CA_A, roots).roots) == 1
            @test length(combined.roots) == 2
            bundle = joinpath(dir, "bundle.pem")
            cp(CA_A, bundle)
            @test length(TLS._tls_load_trust_store(bundle, roots).roots) == 1
            write(bundle, read(CA_B), repeat("\n", 128))
            @test length(TLS._tls_load_trust_store(bundle, roots).roots) == 2
        end

        @testset "Invalid sources are not ignored" begin
            for bad_dir in (joinpath(dir, "missing"), CA_A)
                cfg = TLS.Config(server_name="localhost", ca_file=CA_A, ca_dir=bad_dir)
                @test_throws TLS.ConfigError TLS.connect("tcp", "invalid-address", cfg)
                @test_throws TLS.ConfigError TLS.connect(TCP.loopback_addr(0), cfg)
                @test_throws TLS.ConfigError TLS._validate_config(TLS.Config(cfg; ca_dir=nothing, client_ca_dir=bad_dir); is_server=false)
            end
            empty_dir = joinpath(dir, "empty")
            mkdir(empty_dir)
            certs = TLS._tls_decode_pem_certificates(read(joinpath(FIXTURES, "leaf_a.crt")))
            for invalid_dir in (empty_dir, joinpath(dir, "missing"), CA_A)
                @test_throws TLS._TLSAlertError TLS._tls13_verify_server_certificate_chain(
                    certs, "localhost"; verify_peer=true, verify_hostname=true,
                    ca_file=CA_A, ca_dir=invalid_dir, verification_time_s=VERIFY_TIME,
                )
            end
            malformed = joinpath(dir, "malformed.pem")
            write(malformed, "not a certificate")
            @test_throws TLS._TLSAlertError TLS._tls13_verify_server_certificate_chain(
                certs, "localhost"; verify_peer=true, verify_hostname=true,
                ca_file=malformed, ca_dir=roots, verification_time_s=VERIFY_TIME,
            )
            untrusted = TLS._tls_decode_pem_certificates(read(joinpath(@__DIR__, "resources", "native_tls_server.crt")))
            @test_throws TLS._TLSAlertError TLS._tls13_verify_server_certificate_chain(
                untrusted, "localhost"; verify_peer=true, verify_hostname=true,
                ca_file=CA_A, ca_dir=roots, verification_time_s=VERIFY_TIME,
            )
        end
    end
end
end
