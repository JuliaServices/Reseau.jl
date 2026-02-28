using Test
using Reseau
import Reseau: EventLoops, Sockets

function _find_pki_resource_root()
    root = dirname(@__DIR__)
    candidates = (
        joinpath(root, "test", "resources"),
        joinpath(root, "aws-c-io", "tests", "resources"),
    )
    for candidate in candidates
        if isdir(candidate)
            return candidate
        end
    end
    error("PKI test resources not found. Expected one of: $(join(candidates, ", "))")
end

const _PKI_RESOURCE_ROOT = _find_pki_resource_root()
const _CF_LIB = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

function _cf_array_count(array_ref::Ptr{Cvoid})::Int
    return Int(ccall((:CFArrayGetCount, _CF_LIB), Clong, (Ptr{Cvoid},), array_ref))
end

function _pki_resource_path(name::AbstractString)
    return joinpath(_PKI_RESOURCE_ROOT, name)
end

function _pki_load_cursor(name::AbstractString)
    path = _pki_resource_path(name)
    return Reseau.ByteCursor(read(path))
end

@testset "PKI utils default path selection" begin
    seen = Set{String}()
    push!(seen, "/etc/ssl/certs")
    push!(seen, "/etc/ssl/certs/ca-certificates.crt")

    exists_fn = path -> path in seen

    @test Sockets.determine_default_pki_dir(; path_exists = exists_fn) == "/etc/ssl/certs"
    @test Sockets.determine_default_pki_ca_file(; path_exists = exists_fn) ==
          "/etc/ssl/certs/ca-certificates.crt"

    empty_fn = _ -> false
    @test Sockets.determine_default_pki_dir(; path_exists = empty_fn) === nothing
    @test Sockets.determine_default_pki_ca_file(; path_exists = empty_fn) === nothing
end

@testset "PKI utils platform stubs" begin
    if Sys.isapple()
        if !tls_tests_enabled()
            @info "Skipping Apple PKI tests (set RESEAU_RUN_TLS_TESTS=1 to enable)"
            return
        end

        cert = _pki_load_cursor("unittests.crt")
        key = _pki_load_cursor("unittests.key")
        pkcs12 = _pki_load_cursor("unittests.p12")
        pwd = Reseau.ByteCursor("1234")

        res = Sockets.import_public_and_private_keys_to_identity(cert, key; keychain_path = test_keychain_path())
        if res isa Ptr{Cvoid}
            @test _cf_array_count(res) == 1
            Sockets._cf_release(res)
        end

        res = Sockets.import_public_and_private_keys_to_identity(cert, key; keychain_path = test_keychain_path())
        if res isa Ptr{Cvoid}
            @test _cf_array_count(res) == 1
            Sockets._cf_release(res)
        end

        res = Sockets.import_pkcs12_to_identity(pkcs12, pwd)
        if res isa Ptr{Cvoid}
            @test _cf_array_count(res) == 1
            Sockets._cf_release(res)
        end

        bad_pwd = Reseau.ByteCursor("wrong-password")
        @test_throws Reseau.ReseauError Sockets.import_pkcs12_to_identity(pkcs12, bad_pwd)

        mktempdir() do tmp
            bad_keychain_path = joinpath(tmp, "missing.keychain-db")
            @test_throws Reseau.ReseauError Sockets.import_public_and_private_keys_to_identity(
                cert,
                key;
                keychain_path = bad_keychain_path,
            )
        end

        ca = _pki_load_cursor("server_chain.crt")
        pem_objs = Sockets.pem_parse(read(_pki_resource_path("server_chain.crt")))
        res = Sockets.import_trusted_certificates(ca)
        if res isa Ptr{Cvoid}
            @test _cf_array_count(res) == length(pem_objs)
            Sockets._cf_release(res)
        end

        if Sockets.is_using_secitem()
            res = Sockets.secitem_import_cert_and_key(cert, key; cert_label = "reseau-cert", key_label = "reseau-key")
            if res isa Ptr{Cvoid}
                Sockets._cf_release(res)
            end

            res = Sockets.secitem_import_pkcs12(pkcs12, pwd; cert_label = "reseau-cert", key_label = "reseau-key")
            if res isa Ptr{Cvoid}
                Sockets._cf_release(res)
            end

            @test_throws Reseau.ReseauError Sockets.secitem_import_pkcs12(
                pkcs12,
                bad_pwd;
                cert_label = "reseau-cert-bad",
                key_label = "reseau-key-bad",
            )
        else
            @info "Skipping SecItem PKI tests (SecItem disabled)."
        end
    elseif Sys.iswindows()
        cert = Reseau.ByteCursor("cert")
        key = Reseau.ByteCursor("key")
        pkcs12 = Reseau.ByteCursor("pkcs12")
        pwd = Reseau.ByteCursor("pwd")

        @test_throws Reseau.ReseauError Sockets.import_public_and_private_keys_to_identity(cert, key)
        @test_throws Reseau.ReseauError Sockets.import_pkcs12_to_identity(pkcs12, pwd)
        @test_throws Reseau.ReseauError Sockets.import_trusted_certificates(cert)
        @test_throws Reseau.ReseauError Sockets.secitem_import_cert_and_key(cert, key; cert_label = "cert", key_label = "key")
        @test_throws Reseau.ReseauError Sockets.secitem_import_pkcs12(pkcs12, pwd; cert_label = "cert", key_label = "key")

        cert_reg_path = "CurrentUser/My/reseau-test-cert"
        client_opts = Sockets.tls_ctx_options_init_client_mtls_from_system_path(cert_reg_path)
        @test client_opts isa Sockets.TlsContextOptions
        @test !client_opts.is_server
        @test client_opts.verify_peer
        @test client_opts.system_certificate_path == cert_reg_path

        server_opts = Sockets.tls_ctx_options_init_default_server_from_system_path(cert_reg_path)
        @test server_opts isa Sockets.TlsContextOptions
        @test server_opts.is_server
        @test !server_opts.verify_peer
        @test server_opts.system_certificate_path == cert_reg_path

        @test_throws Reseau.ReseauError Sockets.load_cert_from_system_cert_store(cert_reg_path)
        @test_throws Reseau.ReseauError Sockets.import_key_pair_to_cert_context(cert, key; is_client_mode = true)
        @test Sockets.close_cert_store(C_NULL) === nothing
    else
        cert = Reseau.ByteCursor("cert")
        key = Reseau.ByteCursor("key")
        pkcs12 = Reseau.ByteCursor("pkcs12")
        pwd = Reseau.ByteCursor("pwd")

        @test_throws Reseau.ReseauError Sockets.import_public_and_private_keys_to_identity(cert, key)

        @test_throws Reseau.ReseauError Sockets.import_pkcs12_to_identity(pkcs12, pwd)

        @test_throws Reseau.ReseauError Sockets.import_trusted_certificates(cert)

        @test_throws Reseau.ReseauError Sockets.secitem_import_cert_and_key(cert, key; cert_label = "cert", key_label = "key")

        @test_throws Reseau.ReseauError Sockets.secitem_import_pkcs12(pkcs12, pwd; cert_label = "cert", key_label = "key")

        @test_throws Reseau.ReseauError Sockets.load_cert_from_system_cert_store("cert")

        @test_throws Reseau.ReseauError Sockets.import_key_pair_to_cert_context(cert, key; is_client_mode = true)

        Sockets.close_cert_store(C_NULL)
    end
end
