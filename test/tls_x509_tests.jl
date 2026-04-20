using Test
using Reseau

const TLX = Reseau.TLS

const _TLS_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server.crt")
const _TLS_CA_PATH = joinpath(@__DIR__, "resources", "native_tls_ca.crt")
const _TLS_CLIENT_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_client.crt")
const _TLS_ECDSA_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server_ecdsa.crt")
const _TLS_UNITTEST_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")

_read_bytes(path::AbstractString) = read(path)

function _find_subsequence_x509(haystack::AbstractVector{UInt8}, needle::AbstractVector{UInt8})
    last_start = length(haystack) - length(needle) + 1
    last_start < 1 && return nothing
    for start in 1:last_start
        haystack[start:(start + length(needle) - 1)] == needle && return start
    end
    return nothing
end

function _tls_cert_info(path::AbstractString)
    certs = TLX._tls_decode_pem_certificates(_read_bytes(path))
    @test length(certs) == 1
    return TLX._tls_parse_der_certificate_info(certs[1])
end

function _tls_copy_cert(
    cert::TLX._TLSCertificateInfo;
    der = cert.der,
    subject_raw = cert.subject_raw,
    issuer_raw = cert.issuer_raw,
    common_name = cert.common_name,
    dns_names = cert.dns_names,
    ip_addresses = cert.ip_addresses,
    has_san_extension = cert.has_san_extension,
    not_before_s = cert.not_before_s,
    not_after_s = cert.not_after_s,
    is_ca = cert.is_ca,
    max_path_len = cert.max_path_len,
    has_key_usage = cert.has_key_usage,
    key_usage = cert.key_usage,
    extended_key_usage = cert.extended_key_usage,
    subject_key_id = cert.subject_key_id,
    authority_key_id = cert.authority_key_id,
    permitted_dns_domains = cert.permitted_dns_domains,
    excluded_dns_domains = cert.excluded_dns_domains,
    permitted_ip_ranges = cert.permitted_ip_ranges,
    excluded_ip_ranges = cert.excluded_ip_ranges,
    tbs_der = cert.tbs_der,
    public_key = cert.public_key,
    signature_verify_spec = cert.signature_verify_spec,
    signature = cert.signature,
)
    return TLX._TLSCertificateInfo(
        copy(der),
        copy(subject_raw),
        copy(issuer_raw),
        common_name,
        copy(dns_names),
        [copy(ip) for ip in ip_addresses],
        has_san_extension,
        not_before_s,
        not_after_s,
        is_ca,
        max_path_len,
        has_key_usage,
        key_usage,
        extended_key_usage,
        copy(subject_key_id),
        copy(authority_key_id),
        copy(permitted_dns_domains),
        copy(excluded_dns_domains),
        [TLX._TLSIPRangeConstraint(copy(range.network), copy(range.mask)) for range in permitted_ip_ranges],
        [TLX._TLSIPRangeConstraint(copy(range.network), copy(range.mask)) for range in excluded_ip_ranges],
        copy(tbs_der),
        TLX._tls_copy_public_key(public_key),
        signature_verify_spec,
        copy(signature),
    )
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
        @test cert.subject_raw != cert.issuer_raw
        @test cert.not_before_s < cert.not_after_s
        @test !cert.is_ca
        @test cert.has_key_usage
        @test (cert.key_usage & TLX._TLS_KEY_USAGE_DIGITAL_SIGNATURE) != 0x00
        @test (cert.key_usage & TLX._TLS_KEY_USAGE_KEY_ENCIPHERMENT) != 0x00
        @test (cert.extended_key_usage & TLX._TLS_EXT_KEY_USAGE_SERVER) != 0x00
        @test isempty(cert.authority_key_id) == false
        @test isempty(cert.subject_key_id) == false
        @test cert.public_key isa TLX._TLSRSAPublicKey
        @test cert.signature_verify_spec.digest_bits == 256
        @test !cert.signature_verify_spec.direct
        @test !cert.signature_verify_spec.rsa_pss
        @test !isempty(cert.tbs_der)
        @test !isempty(cert.signature)
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

    @testset "purpose usage checks enforce TLS key usage and prefer AKI/SKI issuer links" begin
        server_cert = _tls_cert_info(_TLS_CERT_PATH)
        key_encipherment_only = _tls_copy_cert(
            server_cert;
            key_usage = TLX._TLS_KEY_USAGE_KEY_ENCIPHERMENT,
            has_key_usage = true,
        )
        no_key_usage = _tls_copy_cert(
            server_cert;
            key_usage = UInt16(0),
            has_key_usage = true,
        )
        @test TLX._tls_certificate_usage_permitted(key_encipherment_only, "ssl_server")
        @test !TLX._tls_certificate_usage_permitted(key_encipherment_only, "ssl_client")
        @test !TLX._tls_certificate_usage_permitted(no_key_usage, "ssl_server")

        ca_cert = _tls_cert_info(_TLS_CA_PATH)
        mismatched_parent = _tls_copy_cert(ca_cert; subject_raw = UInt8[0x30, 0x00])
        @test TLX._tls_cert_subject_matches_issuer(server_cert, mismatched_parent)
        missing_ski_parent = _tls_copy_cert(ca_cert; subject_raw = UInt8[0x30, 0x00], subject_key_id = UInt8[])
        @test !TLX._tls_cert_subject_matches_issuer(server_cert, missing_ski_parent)
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
        @test host_err isa TLX._TLSAlertError
        if host_err isa TLX._TLSAlertError
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
        @test legacy_err isa TLX._TLSAlertError
        if legacy_err isa TLX._TLSAlertError
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
        @test err isa TLX._TLSAlertError
        if err isa TLX._TLSAlertError
            @test err.alert == TLX._TLS_ALERT_BAD_CERTIFICATE
            @test occursin("malformed X.509 certificate", err.message)
        end
    end

    @testset "subject public key info and certificate signatures are parsed natively" begin
        rsa_cert = _tls_cert_info(_TLS_CERT_PATH)
        rsa_ca = _tls_cert_info(_TLS_CA_PATH)
        ecdsa_cert = _tls_cert_info(_TLS_ECDSA_CERT_PATH)

        @test rsa_cert.public_key isa TLX._TLSRSAPublicKey
        if rsa_cert.public_key isa TLX._TLSRSAPublicKey
            @test rsa_cert.public_key.exponent == UInt8[0x01, 0x00, 0x01]
            @test !isempty(rsa_cert.public_key.modulus)
        end

        @test ecdsa_cert.public_key isa TLX._TLSECPublicKey
        if ecdsa_cert.public_key isa TLX._TLSECPublicKey
            @test ecdsa_cert.public_key.curve_id == TLX._TLS_GROUP_SECP256R1
            @test length(ecdsa_cert.public_key.point) == 65
            @test first(ecdsa_cert.public_key.point) == 0x04
        end

        @test TLX._tls_verify_certificate_signature(rsa_cert, rsa_ca)
        @test TLX._tls_verify_certificate_signature(ecdsa_cert, ecdsa_cert)
        @test TLX._tls_verify_certificate_signature(rsa_ca, rsa_ca)
    end

    @testset "native trust verifier accepts valid server and client chains" begin
        server_certs = TLX._tls_decode_pem_certificates(_read_bytes(_TLS_CERT_PATH))
        client_certs = TLX._tls_decode_pem_certificates(_read_bytes(_TLS_CLIENT_CERT_PATH))
        server_key = TLX._tls13_verify_server_certificate_chain(
            server_certs,
            "localhost";
            verify_peer = true,
            verify_hostname = true,
            ca_file = _TLS_CA_PATH,
        )
        client_key = TLX._tls13_verify_client_certificate_chain(
            client_certs;
            verify_peer = true,
            ca_file = _TLS_CA_PATH,
        )
        @test server_key isa TLX._TLSRSAPublicKey
        @test client_key isa TLX._TLSRSAPublicKey
    end

    @testset "native trust store cache reuses unchanged CA roots" begin
        store1 = TLX._tls_load_trust_store(_TLS_CA_PATH)
        store2 = TLX._tls_load_trust_store(_TLS_CA_PATH)
        @test store1 === store2

        mktempdir() do dir
            write(joinpath(dir, "root.pem"), _read_bytes(_TLS_CA_PATH))
            dir_store1 = TLX._tls_load_trust_store(dir)
            dir_store2 = TLX._tls_load_trust_store(dir)
            @test dir_store1 === dir_store2
        end
    end

    @testset "native trust verifier accepts peer chains that include the trust anchor" begin
        server_certs = vcat(
            TLX._tls_decode_pem_certificates(_read_bytes(_TLS_CERT_PATH)),
            TLX._tls_decode_pem_certificates(_read_bytes(_TLS_CA_PATH)),
        )
        pkey = TLX._tls13_verify_server_certificate_chain(
            server_certs,
            "localhost";
            verify_peer = true,
            verify_hostname = true,
            ca_file = _TLS_CA_PATH,
        )
        @test pkey isa TLX._TLSRSAPublicKey
    end

    @testset "native trust verifier supports CA directories" begin
        certs = TLX._tls_decode_pem_certificates(_read_bytes(_TLS_CERT_PATH))
        mktempdir() do dir
            root_path = joinpath(dir, "root.pem")
            junk_path = joinpath(dir, "junk.bin")
            write(root_path, _read_bytes(_TLS_CA_PATH))
            write(junk_path, UInt8[0xff, 0xfe, 0xfd, 0xfc])
            pkey = TLX._tls13_verify_server_certificate_chain(
                certs,
                "localhost";
                verify_peer = true,
                verify_hostname = true,
                ca_file = dir,
            )
            @test pkey isa TLX._TLSRSAPublicKey
        end
    end

    @testset "unknown critical X.509 extensions are rejected" begin
        cert_der = only(TLX._tls_decode_pem_certificates(_read_bytes(_TLS_CA_PATH)))
        mutated = copy(cert_der)
        basic_constraints_oid = UInt8[0x06, 0x03, 0x55, 0x1d, 0x13]
        oid_pos = _find_subsequence_x509(mutated, basic_constraints_oid)
        @test oid_pos !== nothing
        if oid_pos !== nothing
            mutated[oid_pos + 4] = 0x7f
            err = try
                TLX._tls_parse_der_certificate_info(mutated)
                nothing
            catch ex
                ex
            end
            @test err isa ArgumentError
            if err isa ArgumentError
                @test occursin("unsupported critical X.509 extension", err.msg)
            end
        end
    end

    @testset "native trust verifier enforces DNS and IP name constraints" begin
        server_certs = TLX._tls_decode_pem_certificates(_read_bytes(_TLS_CERT_PATH))
        root = _tls_cert_info(_TLS_CA_PATH)

        dns_permitted_store = TLX._TLSTrustStore([
            _tls_copy_cert(root; permitted_dns_domains = ["localhost"]),
        ])
        @test TLX._tls_verify_peer_certificate_chain!(server_certs, dns_permitted_store, "ssl_server") isa TLX._TLSCertificateInfo

        dns_excluded_store = TLX._TLSTrustStore([
            _tls_copy_cert(root; excluded_dns_domains = ["localhost"]),
        ])
        dns_err = try
            TLX._tls_verify_peer_certificate_chain!(server_certs, dns_excluded_store, "ssl_server")
            nothing
        catch ex
            ex
        end
        @test dns_err isa TLX._TLSAlertError
        if dns_err isa TLX._TLSAlertError
            @test dns_err.alert == TLX._TLS_ALERT_BAD_CERTIFICATE
            @test occursin("excluded DNS name constraint", dns_err.message)
        end

        ip_permitted_store = TLX._TLSTrustStore([
            _tls_copy_cert(root; permitted_ip_ranges = [
                TLX._TLSIPRangeConstraint(UInt8[0x7f, 0x00, 0x00, 0x00], UInt8[0xff, 0xff, 0xff, 0x00]),
                TLX._TLSIPRangeConstraint(
                    UInt8[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
                    UInt8[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                ),
            ]),
        ])
        @test TLX._tls_verify_peer_certificate_chain!(server_certs, ip_permitted_store, "ssl_server") isa TLX._TLSCertificateInfo

        ip_excluded_store = TLX._TLSTrustStore([
            _tls_copy_cert(root; excluded_ip_ranges = [
                TLX._TLSIPRangeConstraint(UInt8[0x7f, 0x00, 0x00, 0x00], UInt8[0xff, 0xff, 0xff, 0x00]),
            ]),
        ])
        ip_err = try
            TLX._tls_verify_peer_certificate_chain!(server_certs, ip_excluded_store, "ssl_server")
            nothing
        catch ex
            ex
        end
        @test ip_err isa TLX._TLSAlertError
        if ip_err isa TLX._TLSAlertError
            @test ip_err.alert == TLX._TLS_ALERT_BAD_CERTIFICATE
            @test occursin("excluded IP name constraint", ip_err.message)
        end
    end

    @testset "native trust verifier rejects unknown authorities and incompatible EKUs" begin
        server_certs = TLX._tls_decode_pem_certificates(_read_bytes(_TLS_CERT_PATH))
        client_certs = TLX._tls_decode_pem_certificates(_read_bytes(_TLS_CLIENT_CERT_PATH))

        unknown_err = try
            TLX._tls13_verify_server_certificate_chain(
                server_certs,
                "localhost";
                verify_peer = true,
                verify_hostname = true,
                ca_file = _TLS_UNITTEST_CERT_PATH,
            )
            nothing
        catch ex
            ex
        end
        @test unknown_err isa TLX._TLSAlertError
        if unknown_err isa TLX._TLSAlertError
            @test unknown_err.alert == TLX._TLS_ALERT_BAD_CERTIFICATE
            @test occursin("unknown authority", unknown_err.message)
        end

        ca_load_err = mktemp() do path, io
            write(io, UInt8[0xff, 0xfe, 0xfd, 0xfc])
            close(io)
            try
                TLX._tls13_verify_server_certificate_chain(
                    server_certs,
                    "localhost";
                    verify_peer = true,
                    verify_hostname = true,
                    ca_file = path,
                )
                nothing
            catch ex
                ex
            end
        end
        @test ca_load_err isa TLX._TLSAlertError
        if ca_load_err isa TLX._TLSAlertError
            @test ca_load_err.alert == TLX._TLS_ALERT_INTERNAL_ERROR
            @test occursin("failed to load CA roots", ca_load_err.message)
        end

        malformed_err = try
            TLX._tls13_verify_server_certificate_chain(
                [UInt8[0x30, 0x89, 0x01]],
                "localhost";
                verify_peer = true,
                verify_hostname = false,
                ca_file = _TLS_CA_PATH,
            )
            nothing
        catch ex
            ex
        end
        @test malformed_err isa TLX._TLSAlertError
        if malformed_err isa TLX._TLSAlertError
            @test malformed_err.alert == TLX._TLS_ALERT_BAD_CERTIFICATE
            @test occursin("malformed X.509 certificate", malformed_err.message)
        end

        wrong_server_usage = try
            TLX._tls13_verify_server_certificate_chain(
                client_certs,
                "localhost";
                verify_peer = true,
                verify_hostname = false,
                ca_file = _TLS_CA_PATH,
            )
            nothing
        catch ex
            ex
        end
        @test wrong_server_usage isa TLX._TLSAlertError
        if wrong_server_usage isa TLX._TLSAlertError
            @test occursin("server authentication", wrong_server_usage.message)
        end

        wrong_client_usage = try
            TLX._tls13_verify_client_certificate_chain(
                server_certs;
                verify_peer = true,
                ca_file = _TLS_CA_PATH,
            )
            nothing
        catch ex
            ex
        end
        @test wrong_client_usage isa TLX._TLSAlertError
        if wrong_client_usage isa TLX._TLSAlertError
            @test occursin("client authentication", wrong_client_usage.message)
        end
    end

    @testset "hostname verification requires a peer name" begin
        certs = TLX._tls_decode_pem_certificates(_read_bytes(_TLS_CERT_PATH))
        err = try
            TLX._tls13_verify_server_certificate_chain(
                certs,
                "";
                verify_peer = false,
                verify_hostname = true,
                ca_file = nothing,
            )
            nothing
        catch ex
            ex
        end
        @test err isa TLX._TLSAlertError
        if err isa TLX._TLSAlertError
            @test err.alert == TLX._TLS_ALERT_INTERNAL_ERROR
            @test occursin("requires a peer name", err.message)
        end
    end
end
