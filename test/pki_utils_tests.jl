using Test
using AwsIO

const _PKI_RESOURCE_ROOT = joinpath(dirname(@__DIR__), "aws-c-io", "tests", "resources")

function _pki_resource_path(name::AbstractString)
    return joinpath(_PKI_RESOURCE_ROOT, name)
end

function _pki_load_cursor(name::AbstractString)
    path = _pki_resource_path(name)
    return AwsIO.ByteCursor(read(path))
end

@testset "PKI utils default path selection" begin
    seen = Set{String}()
    push!(seen, "/etc/ssl/certs")
    push!(seen, "/etc/ssl/certs/ca-certificates.crt")

    exists_fn = path -> path in seen

    @test AwsIO.determine_default_pki_dir(; path_exists = exists_fn) == "/etc/ssl/certs"
    @test AwsIO.determine_default_pki_ca_file(; path_exists = exists_fn) ==
          "/etc/ssl/certs/ca-certificates.crt"

    empty_fn = _ -> false
    @test AwsIO.determine_default_pki_dir(; path_exists = empty_fn) === nothing
    @test AwsIO.determine_default_pki_ca_file(; path_exists = empty_fn) === nothing
end

@testset "PKI utils platform stubs" begin
    if Sys.isapple()
        if !tls_tests_enabled()
            @info "Skipping Apple PKI tests (set AWSIO_RUN_TLS_TESTS=1 to enable)"
            return
        end

        cert = _pki_load_cursor("unittests.crt")
        key = _pki_load_cursor("unittests.key")
        pkcs12 = _pki_load_cursor("unittests.p12")
        pwd = AwsIO.ByteCursor("1234")

        res = AwsIO.import_public_and_private_keys_to_identity(cert, key; keychain_path = test_keychain_path())
        @test !(res isa AwsIO.ErrorResult)
        if res isa Ptr{Cvoid}
            AwsIO._cf_release(res)
        end

        res = AwsIO.import_pkcs12_to_identity(pkcs12, pwd)
        @test !(res isa AwsIO.ErrorResult)
        if res isa Ptr{Cvoid}
            AwsIO._cf_release(res)
        end

        ca = _pki_load_cursor("ca_root.crt")
        res = AwsIO.import_trusted_certificates(ca)
        @test !(res isa AwsIO.ErrorResult)
        if res isa Ptr{Cvoid}
            AwsIO._cf_release(res)
        end

        if AwsIO.is_using_secitem()
            res = AwsIO.secitem_import_cert_and_key(cert, key; cert_label = "awsio-cert", key_label = "awsio-key")
            @test !(res isa AwsIO.ErrorResult)
            if res isa Ptr{Cvoid}
                AwsIO._cf_release(res)
            end

            res = AwsIO.secitem_import_pkcs12(pkcs12, pwd; cert_label = "awsio-cert", key_label = "awsio-key")
            @test !(res isa AwsIO.ErrorResult)
            if res isa Ptr{Cvoid}
                AwsIO._cf_release(res)
            end
        else
            @info "Skipping SecItem PKI tests (SecItem disabled)."
        end
    else
        cert = AwsIO.ByteCursor("cert")
        key = AwsIO.ByteCursor("key")
        pkcs12 = AwsIO.ByteCursor("pkcs12")
        pwd = AwsIO.ByteCursor("pwd")

        res = AwsIO.import_public_and_private_keys_to_identity(cert, key)
        @test res isa AwsIO.ErrorResult
        res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED

        res = AwsIO.import_pkcs12_to_identity(pkcs12, pwd)
        @test res isa AwsIO.ErrorResult
        res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED

        res = AwsIO.import_trusted_certificates(cert)
        @test res isa AwsIO.ErrorResult
        res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED

        res = AwsIO.secitem_import_cert_and_key(cert, key; cert_label = "cert", key_label = "key")
        @test res isa AwsIO.ErrorResult
        res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED

        res = AwsIO.secitem_import_pkcs12(pkcs12, pwd; cert_label = "cert", key_label = "key")
        @test res isa AwsIO.ErrorResult
        res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED

        res = AwsIO.load_cert_from_system_cert_store("cert")
        @test res isa AwsIO.ErrorResult
        res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED

        res = AwsIO.import_key_pair_to_cert_context(cert, key; is_client_mode = true)
        @test res isa AwsIO.ErrorResult
        res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED

        AwsIO.close_cert_store(C_NULL)
    end
end

@testset "X509 helpers (aws-lc)" begin
    if !AwsIO.aws_lc_available()
        @info "Skipping X509 helper tests (aws_lc_jll not available)"
        return
    end

    chain_pem = AwsIO.ByteCursor(read(_pki_resource_path("server_chain.crt")))
    ca_pem = AwsIO.ByteCursor(read(_pki_resource_path("ca_root.crt")))

    @test AwsIO.x509_verify_chain(chain_pem; trust_store_cursor = ca_pem, host = "localhost") === nothing

    res = AwsIO.x509_verify_chain(chain_pem; trust_store_cursor = ca_pem, host = "example.com")
    @test res isa AwsIO.ErrorResult
    if res isa AwsIO.ErrorResult
        @test res.code == AwsIO.ERROR_IO_TLS_HOST_NAME_MISMATCH
    end

    wrong_ca = AwsIO.ByteCursor(read(_pki_resource_path("DigiCertGlobalRootCA.crt.pem")))
    res = AwsIO.x509_verify_chain(chain_pem; trust_store_cursor = wrong_ca)
    @test res isa AwsIO.ErrorResult
    if res isa AwsIO.ErrorResult
        @test res.code in (AwsIO.ERROR_IO_TLS_UNKNOWN_ROOT_CERTIFICATE, AwsIO.ERROR_IO_TLS_INVALID_CERTIFICATE_CHAIN)
    end

    chain = AwsIO.x509_parse_pem_chain(chain_pem)
    @test chain isa Vector
    chain isa Vector && @test length(chain) == 2

    pem_objs = AwsIO.pem_parse(read(_pki_resource_path("unittests.crt")))
    @test !(pem_objs isa AwsIO.ErrorResult)
    if pem_objs isa Vector && !isempty(pem_objs)
        der_cursor = AwsIO.byte_cursor_from_buf(pem_objs[1].data)
        x509 = AwsIO.x509_load_der(der_cursor)
        @test x509 isa AwsIO.X509Ref
    end
end
