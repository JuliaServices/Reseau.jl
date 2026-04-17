using Test
using Reseau

const TLX = Reseau.TLS

const _TLS_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server.crt")
const _TLS_CA_PATH = joinpath(@__DIR__, "resources", "native_tls_ca.crt")
const _TLS_ECDSA_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server_ecdsa.crt")

_read_bytes(path::AbstractString) = read(path)

function _tls_cert_info(path::AbstractString)
    certs = TLX._tls_decode_pem_certificates(_read_bytes(path))
    @test length(certs) == 1
    return TLX._tls_parse_der_certificate_info(certs[1])
end

@testset "TLS x509 helpers" begin
    @testset "native PEM certificate decoding preserves block boundaries" begin
        combined = vcat(_read_bytes(_TLS_CERT_PATH), UInt8('\n'), _read_bytes(_TLS_CA_PATH))
        certificates = TLX._tls_decode_pem_certificates(combined)
        @test length(certificates) == 2
        leaf_info = TLX._tls_parse_der_certificate_info(certificates[1])
        ca_info = TLX._tls_parse_der_certificate_info(certificates[2])
        @test leaf_info.common_name == "localhost"
        @test ca_info.common_name == "Reseau Native TLS Test CA"

        with_headers = replace(
            String(_read_bytes(_TLS_CERT_PATH)),
            "-----BEGIN CERTIFICATE-----\n" =>
                "-----BEGIN CERTIFICATE-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-256-CBC,0000000000000000\n\n",
        )
        header_certificates = TLX._tls_decode_pem_certificates(Vector{UInt8}(codeunits(with_headers)))
        @test length(header_certificates) == 1
        @test header_certificates[1] == certificates[1]
    end

    @testset "parsed certificate info includes SAN DNS and IP data" begin
        cert = _tls_cert_info(_TLS_CERT_PATH)
        @test cert.common_name == "localhost"
        @test cert.has_san_extension
        @test cert.dns_names == ["localhost"]
        @test UInt8[0x7f, 0x00, 0x00, 0x01] in cert.ip_addresses
        @test UInt8[
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ] in cert.ip_addresses
    end

    @testset "Go-style hostname matching helpers" begin
        @test TLX._tls_valid_hostname_input("localhost.")
        @test TLX._tls_valid_hostname_pattern("*.example.com")
        @test !TLX._tls_valid_hostname_pattern("*")
        @test TLX._tls_match_hostnames("*.example.com", "api.example.com")
        @test !TLX._tls_match_hostnames("*.example.com", "example.com")
        @test TLX._tls_match_exactly("LOCALHOST", "localhost")
    end

    @testset "certificate peer-name verification uses SANs and rejects legacy CN fallback" begin
        san_cert = _tls_cert_info(_TLS_CERT_PATH)
        @test TLX._tls_verify_certificate_peer_name!(san_cert, "localhost") === nothing
        @test TLX._tls_verify_certificate_peer_name!(san_cert, "LOCALHOST.") === nothing
        @test TLX._tls_verify_certificate_peer_name!(san_cert, "127.0.0.1") === nothing
        @test TLX._tls_verify_certificate_peer_name!(san_cert, "[::1]") === nothing
        @test TLX._tls_verify_certificate_peer_name!(san_cert, "[::ffff:127.0.0.1]") === nothing

        host_err = try
            TLX._tls_verify_certificate_peer_name!(san_cert, "example.com")
            nothing
        catch ex
            ex
        end
        @test host_err isa TLX._TLS13AlertError
        if host_err isa TLX._TLS13AlertError
            @test occursin("certificate is not valid for host example.com", host_err.message)
        end

        legacy_cert = _tls_cert_info(_TLS_ECDSA_CERT_PATH)
        @test !legacy_cert.has_san_extension
        legacy_err = try
            TLX._tls_verify_certificate_peer_name!(legacy_cert, "localhost")
            nothing
        catch ex
            ex
        end
        @test legacy_err isa TLX._TLS13AlertError
        if legacy_err isa TLX._TLS13AlertError
            @test occursin("legacy Common Name", legacy_err.message)
        end
    end

    @testset "malformed DER peer-name verification fails with bad_certificate alert" begin
        err = try
            TLX._tls13_check_x509_peer_name!(UInt8[0x30, 0x89, 0x01], "localhost")
            nothing
        catch ex
            ex
        end
        @test err isa TLX._TLS13AlertError
        if err isa TLX._TLS13AlertError
            @test err.alert == TLX._TLS_ALERT_BAD_CERTIFICATE
            @test occursin("malformed X.509 certificate", err.message)
        end
    end
end
