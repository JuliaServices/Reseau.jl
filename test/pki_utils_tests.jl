using Test
using Reseau
import Reseau: EventLoops, Sockets

const _PKI_RESOURCE_ROOT = joinpath(dirname(@__DIR__), "aws-c-io", "tests", "resources")
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
        else
            @info "Skipping SecItem PKI tests (SecItem disabled)."
        end
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

@testset "X509 helpers (aws-lc)" begin
    if !Sockets.aws_lc_available()
        @info "Skipping X509 helper tests (aws_lc_jll not available)"
        return
    end

    chain_pem = Reseau.ByteCursor(read(_pki_resource_path("server_chain.crt")))
    ca_pem = Reseau.ByteCursor(read(_pki_resource_path("ca_root.crt")))

    Sockets.x509_verify_chain(chain_pem; trust_store_cursor = ca_pem, host = "localhost")

    try
        Sockets.x509_verify_chain(chain_pem; trust_store_cursor = ca_pem, host = "example.com")
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == EventLoops.ERROR_IO_TLS_HOST_NAME_MISMATCH
    end

    wrong_ca = Reseau.ByteCursor(read(_pki_resource_path("DigiCertGlobalRootCA.crt.pem")))
    try
        Sockets.x509_verify_chain(chain_pem; trust_store_cursor = wrong_ca)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code in (EventLoops.ERROR_IO_TLS_UNKNOWN_ROOT_CERTIFICATE, EventLoops.ERROR_IO_TLS_INVALID_CERTIFICATE_CHAIN)
    end

    chain = Sockets.x509_parse_pem_chain(chain_pem)
    @test chain isa Vector
    chain isa Vector && @test length(chain) == 2

    pem_objs = Sockets.pem_parse(read(_pki_resource_path("unittests.crt")))
    if pem_objs isa Vector && !isempty(pem_objs)
        der_cursor = Reseau.byte_cursor_from_buf(pem_objs[1].data)
        x509 = Sockets.x509_load_der(der_cursor)
        @test x509 isa Sockets.X509Ref
    end
end
