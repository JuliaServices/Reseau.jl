using Test
using AwsIO

@testset "PEM parse and filters" begin
    root = dirname(@__DIR__)
    pem_path = joinpath(root, "aws-c-io", "tests", "resources", "testcert0.pem")
    if !isfile(pem_path)
        @test true
    else
        pem_text = read(pem_path, String)
        objs = AwsIO.pem_parse(pem_text)
        @test !(objs isa AwsIO.ErrorResult)
        objs isa AwsIO.ErrorResult && return

        @test length(objs) == 1
        obj = objs[1]
        @test obj.object_type == AwsIO.PemObjectType.X509
        @test obj.type_string == "CERTIFICATE"
        @test AwsIO.pem_is_certificate(obj)
        @test !AwsIO.pem_is_private_key(obj)

        certs = AwsIO.pem_filter_certificates(objs)
        @test length(certs) == 1
        @test certs[1].object_type == AwsIO.PemObjectType.X509
        @test isempty(AwsIO.pem_filter_private_keys(objs))

        from_file = AwsIO.pem_parse_from_file(pem_path)
        @test !(from_file isa AwsIO.ErrorResult)
        from_file isa AwsIO.ErrorResult && return
        @test length(from_file) == 1
    end
end

@testset "PEM encode roundtrip" begin
    data = Vector{UInt8}("pemdata")
    pem = AwsIO.pem_encode(data, AwsIO.PemObjectType.PUBLIC_KEY)
    parsed = AwsIO.pem_parse(pem)
    @test !(parsed isa AwsIO.ErrorResult)
    parsed isa AwsIO.ErrorResult && return

    @test length(parsed) == 1
    @test parsed[1].object_type == AwsIO.PemObjectType.PUBLIC_KEY
    @test String(AwsIO.byte_cursor_from_buf(parsed[1].data)) == "pemdata"
end

@testset "PEM malformed" begin
    bad = "-----BEGIN CERTIFICATE-----\nnot-base64!!\n-----END CERTIFICATE-----"
    res = AwsIO.pem_parse(bad)
    @test res isa AwsIO.ErrorResult
    @test res.code == AwsIO.ERROR_IO_PEM_MALFORMED
end

@testset "PEM CRLF and multiple objects" begin
    data1 = Vector{UInt8}("one")
    data2 = Vector{UInt8}("two")
    pem1 = AwsIO.pem_encode(data1, AwsIO.PemObjectType.PUBLIC_KEY)
    pem2 = AwsIO.pem_encode(data2, AwsIO.PemObjectType.PUBLIC_KEY)

    pem_combo = "junk line\n" * pem1 * "\nextra\n" * pem2
    parsed = AwsIO.pem_parse(pem_combo)
    @test !(parsed isa AwsIO.ErrorResult)
    parsed isa AwsIO.ErrorResult && return
    @test length(parsed) == 2
    @test String(AwsIO.byte_cursor_from_buf(parsed[1].data)) == "one"
    @test String(AwsIO.byte_cursor_from_buf(parsed[2].data)) == "two"

    pem_crlf = replace(pem1, "\n" => "\r\n")
    parsed_crlf = AwsIO.pem_parse(pem_crlf)
    @test !(parsed_crlf isa AwsIO.ErrorResult)
    parsed_crlf isa AwsIO.ErrorResult && return
    @test length(parsed_crlf) == 1
end
