module TLSChainBuildingTests

using Test
using Reseau

const T = Reseau.TLS
# ECDSA P-256 chains made with Go's crypto/x509, valid 2026-01-01 to 2036-01-01.
# `roots.pem` holds root A (EKU clientAuth only), root A' (excludes example.com),
# and root B (unconstrained). In the *_alternative files the leaf's intermediate
# is cross-signed: first by A or A', then by B. Go 1.27 agrees with every verdict.
const FIXTURES = joinpath(@__DIR__, "resources", "alternate_paths")
const VERIFY_TIME = Int64(1793275200) # 2026-10-29 12:00:00 UTC

function verification_error(file)
    certs = T._tls_decode_pem_certificates(read(joinpath(FIXTURES, file)))
    try
        T._tls_verify_certificate_chain(
            certs;
            verify_peer = true,
            verify_hostname = true,
            ca_file = joinpath(FIXTURES, "roots.pem"),
            verification_time_s = VERIFY_TIME,
            purpose = "ssl_server",
            peer_name = "www.example.com",
        )
        return ""
    catch err
        return sprint(showerror, err)
    end
end

@testset "a path failing EKU or name constraints falls back to another path" begin
    @test verification_error("eku_alternative.pem") == ""
    @test verification_error("nc_alternative.pem") == ""
    # With only the constrained path available, its failure is reported.
    @test occursin("not authorized for server authentication", verification_error("eku_only.pem"))
    @test occursin("excluded DNS name constraint", verification_error("nc_only.pem"))
end

@testset "pathLenConstraint counts intermediates, not the leaf" begin
    # pathlen:0 issuing a CA-flagged leaf is valid; issuing another CA is not.
    @test verification_error("ca_leaf_pathlen0.pem") == ""
    @test occursin("unknown authority", verification_error("pathlen0_exceeded.pem"))
end

end
