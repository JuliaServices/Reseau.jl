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
