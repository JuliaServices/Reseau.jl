using Test
using AwsIO

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
