module TLSNameConstraintsTests

using Test
using Reseau

const T = Reseau.TLS
# ECDSA P-256 chains made with Go's crypto/x509, valid 2026-01-01 to 2036-01-01.
# Each chain file holds a leaf and its intermediate. `root.pem` issues every
# intermediate; `constrained_root.pem` carries name constraints itself and issues
# its leaves directly. Go 1.27 accepts exactly the chains these tests accept.
const FIXTURES = joinpath(@__DIR__, "resources", "name_constraints")
const VERIFY_TIME = Int64(1793275200) # 2026-10-29 12:00:00 UTC

function verification_error(file, host; root = "root.pem")
    certs = T._tls_decode_pem_certificates(read(joinpath(FIXTURES, file)))
    try
        T._tls_verify_certificate_chain(
            certs;
            verify_peer = true,
            verify_hostname = true,
            ca_file = joinpath(FIXTURES, root),
            verification_time_s = VERIFY_TIME,
            purpose = "ssl_server",
            peer_name = host,
        )
        return ""
    catch err
        return sprint(showerror, err)
    end
end

@testset "name constraints parsed from certificate DER" begin
    # Permitted: DNS example.com and .example.org, IP 10.0.0.0/8.
    @test verification_error("permitted.pem", "www.example.com") == ""
    @test verification_error("permitted.pem", "api.example.org") == ""
    @test verification_error("permitted.pem", "10.1.2.3") == ""
    @test occursin("violates DNS name constraints", verification_error("not_permitted.pem", "www.example.net"))
    # Excluded: DNS bar.example.com, email admin@example.com, IP 10.0.0.0/8.
    @test verification_error("allowed_under_exclusions.pem", "www.example.com") == ""
    # A constrained trust anchor loads and constrains its leaves.
    @test verification_error("under_constrained_root.pem", "www.example.com"; root = "constrained_root.pem") == ""
    @test occursin(
        "violates DNS name constraints",
        verification_error("outside_constrained_root.pem", "www.example.net"; root = "constrained_root.pem"),
    )
end

@testset "names that could stand for a constrained name" begin
    # "*.example.com" would match the excluded "bar.example.com".
    for file in ("excluded_wildcard.pem", "excluded_wildcard_case.pem"), host in ("bar.example.com", "foo.example.com")
        @test occursin("excluded DNS name constraint", verification_error(file, host))
    end
    @test T._tls_dns_wildcard_excluded("bar.example.com", "*.example.com")
    @test T._tls_dns_wildcard_excluded("example.com", "*.COM")
    @test !T._tls_dns_wildcard_excluded("a.bar.example.com", "*.example.com")
    # A SAN with an empty label is rejected instead of suffix-matched.
    @test occursin("cannot apply DNS name constraints", verification_error("leading_period_san.pem", "www.example.com"))
    # `ad\min@example.com` and `"admin"@example.com` name the excluded mailbox.
    @test occursin("excluded email name constraint", verification_error("excluded_escaped_email.pem", "www.example.com"))
    @test occursin("excluded email name constraint", verification_error("excluded_quoted_email.pem", "www.example.com"))
    @test T._tls_parse_rfc2821_mailbox("\"a@b\"@Example.COM") == T._TLSParsedMailbox("a@b", "example.com")
    # SAN ::ffff:10.0.0.1 would match peer 10.0.0.1 while escaping the 10.0.0.0/8 exclusion.
    @test occursin("IPv4-mapped", verification_error("mapped_ip_san.pem", "10.0.0.1"))
end

end
