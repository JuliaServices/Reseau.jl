using Test
using Reseau

const TLX = Reseau.TLS

const _TLS_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server.crt")
const _TLS_CA_PATH = joinpath(@__DIR__, "resources", "native_tls_ca.crt")
const _TLS_CLIENT_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_client.crt")
const _TLS_ECDSA_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server_ecdsa.crt")
const _TLS_UNITTEST_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")

_read_bytes(path::AbstractString) = read(path)

function _der_length_bytes(len::Int)
    len < 0 && throw(ArgumentError("negative DER length"))
    len < 0x80 && return UInt8[UInt8(len)]
    bytes = UInt8[]
    value = len
    while value > 0
        pushfirst!(bytes, UInt8(value & 0xff))
        value >>= 8
    end
    return vcat(UInt8[0x80 | UInt8(length(bytes))], bytes)
end

function _der_tlv(tag::UInt8, value::AbstractVector{UInt8})
    out = UInt8[tag]
    append!(out, _der_length_bytes(length(value)))
    append!(out, value)
    return out
end

function _der_integer(value::AbstractVector{UInt8})
    bytes = Vector{UInt8}(value)
    isempty(bytes) && throw(ArgumentError("empty DER integer"))
    if bytes[1] >= 0x80
        pushfirst!(bytes, 0x00)
    end
    return _der_tlv(TLX._ASN1_INTEGER, bytes)
end

function _rsa_spki_der(modulus::AbstractVector{UInt8}, exponent::AbstractVector{UInt8} = UInt8[0x01, 0x00, 0x01])
    alg = _der_tlv(
        TLX._ASN1_SEQUENCE,
        vcat(_der_tlv(TLX._ASN1_OBJECT_IDENTIFIER, collect(TLX._ASN1_OID_RSA_ENCRYPTION)), _der_tlv(TLX._ASN1_NULL, UInt8[])),
    )
    rsa_key = _der_tlv(TLX._ASN1_SEQUENCE, vcat(_der_integer(modulus), _der_integer(exponent)))
    bit_string = _der_tlv(TLX._ASN1_BIT_STRING, vcat(UInt8[0x00], rsa_key))
    return _der_tlv(TLX._ASN1_SEQUENCE, vcat(alg, bit_string))
end

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
    email_addresses = cert.email_addresses,
    uri_names = cert.uri_names,
    has_san_extension = cert.has_san_extension,
    has_unhandled_san_names = cert.has_unhandled_san_names,
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
    permitted_uri_domains = cert.permitted_uri_domains,
    excluded_uri_domains = cert.excluded_uri_domains,
    permitted_email_addresses = cert.permitted_email_addresses,
    excluded_email_addresses = cert.excluded_email_addresses,
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
        copy(email_addresses),
        copy(uri_names),
        has_san_extension,
        has_unhandled_san_names,
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
        copy(permitted_uri_domains),
        copy(excluded_uri_domains),
        copy(permitted_email_addresses),
        copy(excluded_email_addresses),
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
        @test !cert.has_unhandled_san_names
        @test cert.dns_names == ["localhost"]
        @test isempty(cert.email_addresses)
        @test isempty(cert.uri_names)
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

    @testset "SHA-1 X.509 certificate signatures are rejected during parsing" begin
        sha1_rsa = UInt8[
            0x06, 0x09,
            0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05,
            0x05, 0x00,
        ]
        sha1_ecdsa = UInt8[
            0x06, 0x07,
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x01,
        ]
        @test_throws ArgumentError TLX._tls_parse_certificate_signature_spec(sha1_rsa, 1, length(sha1_rsa))
        @test_throws ArgumentError TLX._tls_parse_certificate_signature_spec(sha1_ecdsa, 1, length(sha1_ecdsa))
    end

    @testset "Go-style hostname matching helpers" begin
        @test TLX._tls_valid_hostname_input("localhost.")
        @test TLX._tls_valid_hostname_pattern("*.example.com")
        @test !TLX._tls_valid_hostname_pattern("*")
        @test TLX._tls_match_hostnames("*.example.com", "api.example.com")
        @test !TLX._tls_match_hostnames("*.example.com", "example.com")
        @test TLX._tls_match_exactly("LOCALHOST", "localhost")
    end

    @testset "purpose usage checks enforce TLS key usage and Go-style issuer links" begin
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
        @test TLX._tls_cert_subject_matches_issuer(server_cert, ca_cert)
        mismatched_parent = _tls_copy_cert(ca_cert; subject_raw = UInt8[0x30, 0x00])
        @test !TLX._tls_cert_subject_matches_issuer(server_cert, mismatched_parent)
        missing_ski_parent = _tls_copy_cert(ca_cert; subject_key_id = UInt8[])
        @test TLX._tls_cert_subject_matches_issuer(server_cert, missing_ski_parent)
        wrong_ski_parent = _tls_copy_cert(ca_cert; subject_key_id = UInt8[0xff])
        @test !TLX._tls_cert_subject_matches_issuer(server_cert, wrong_ski_parent)
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

        max_modulus = vcat(UInt8[0x80], zeros(UInt8, 1023))
        oversized_modulus = vcat(UInt8[0x01], zeros(UInt8, 1024))
        @test TLX._tls_rsa_modulus_bit_length(max_modulus) == TLX._TLS_MAX_RSA_CERT_KEY_BITS
        @test TLX._tls_rsa_modulus_bit_length(oversized_modulus) == TLX._TLS_MAX_RSA_CERT_KEY_BITS + 1
        oversized_spki = _rsa_spki_der(oversized_modulus)
        @test_throws ArgumentError TLX._tls_parse_subject_public_key_info(oversized_spki, 1, length(oversized_spki))
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

    @testset "native trust store skips unsupported root entries" begin
        mktempdir() do dir
            write(joinpath(dir, "bad.pem"), """
-----BEGIN CERTIFICATE-----
////
-----END CERTIFICATE-----
""")
            write(joinpath(dir, "root.pem"), _read_bytes(_TLS_CA_PATH))
            store = TLX._tls_load_trust_store(dir)
            @test !isempty(store.roots)
        end
    end

    @testset "local identity cache replacement keeps owner references valid" begin
        mktempdir() do dir
            cert_path = joinpath(dir, "identity.crt")
            key_path = joinpath(dir, "identity.key")
            write(cert_path, _read_bytes(_TLS_UNITTEST_CERT_PATH))
            write(key_path, _read_bytes(joinpath(@__DIR__, "resources", "unittests.key")))
            config = TLX.Config(cert_file = cert_path, key_file = key_path)
            signed = UInt8[0x72, 0x65, 0x73, 0x65, 0x61, 0x75]
            first_cert = _tls_cert_info(_TLS_UNITTEST_CERT_PATH)
            second_cert = _tls_cert_info(_TLS_CERT_PATH)
            first_identity = nothing
            second_entry = nothing
            second_identity = nothing
            try
                first_identity = TLX._tls_local_identity(config; is_server = true)
                first_signature = TLX._tls13_openssl_sign_signature(
                    (first_identity::TLX._TLSLocalIdentity).private_key,
                    TLX._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
                    signed,
                )
                @test TLX._tls13_openssl_verify_signature(first_cert.public_key, TLX._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256, signed, first_signature)
                TLX._free_evp_pkey!((first_identity::TLX._TLSLocalIdentity).private_key)
                first_identity = nothing

                write(cert_path, _read_bytes(_TLS_CERT_PATH))
                write(key_path, _read_bytes(joinpath(@__DIR__, "resources", "native_tls_server.key")))
                second_entry = TLX._tls_cached_local_identity(cert_path, key_path)

                second_identity = TLX._tls_local_identity(config; is_server = true)
                old_signature = TLX._tls13_openssl_sign_signature(
                    (second_identity::TLX._TLSLocalIdentity).private_key,
                    TLX._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
                    signed,
                )
                @test TLX._tls13_openssl_verify_signature(first_cert.public_key, TLX._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256, signed, old_signature)

                new_signature = TLX._tls13_openssl_sign_signature(
                    (second_entry::TLX._TLSLocalIdentityCacheEntry).private_key,
                    TLX._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
                    signed,
                )
                @test TLX._tls13_openssl_verify_signature(second_cert.public_key, TLX._TLS_SIGNATURE_RSA_PSS_RSAE_SHA256, signed, new_signature)
            finally
                first_identity isa TLX._TLSLocalIdentity && TLX._free_evp_pkey!(first_identity.private_key)
                second_identity isa TLX._TLSLocalIdentity && TLX._free_evp_pkey!(second_identity.private_key)
                second_entry isa TLX._TLSLocalIdentityCacheEntry && TLX._free_evp_pkey!(second_entry.private_key)
                TLX._finalize_tls_local_identity_state!(config._server_identity)
            end
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

    @testset "native trust verifier enforces nested EKU and broader name constraints" begin
        server_leaf = _tls_cert_info(_TLS_CERT_PATH)
        client_leaf = _tls_cert_info(_TLS_CLIENT_CERT_PATH)
        root = _tls_cert_info(_TLS_CA_PATH)

        client_only_root = _tls_copy_cert(root; extended_key_usage = TLX._TLS_EXT_KEY_USAGE_CLIENT)
        server_only_root = _tls_copy_cert(root; extended_key_usage = TLX._TLS_EXT_KEY_USAGE_SERVER)

        server_chain_err = try
            TLX._tls_verify_peer_certificate_chain!(
                TLX._tls_decode_pem_certificates(_read_bytes(_TLS_CERT_PATH)),
                TLX._TLSTrustStore([client_only_root]),
                "ssl_server",
            )
            nothing
        catch ex
            ex
        end
        @test server_chain_err isa TLX._TLSAlertError
        if server_chain_err isa TLX._TLSAlertError
            @test occursin("certificate chain is not authorized for server authentication", server_chain_err.message)
        end

        client_chain_err = try
            TLX._tls_verify_peer_certificate_chain!(
                TLX._tls_decode_pem_certificates(_read_bytes(_TLS_CLIENT_CERT_PATH)),
                TLX._TLSTrustStore([server_only_root]),
                "ssl_client",
            )
            nothing
        catch ex
            ex
        end
        @test client_chain_err isa TLX._TLSAlertError
        if client_chain_err isa TLX._TLSAlertError
            @test occursin("certificate chain is not authorized for client authentication", client_chain_err.message)
        end

        email_leaf = _tls_copy_cert(server_leaf; email_addresses = ["ops@localhost"])
        email_ok_chain = TLX._TLSCertificateInfo[email_leaf, _tls_copy_cert(root; permitted_email_addresses = ["localhost"])]
        @test TLX._tls_verify_chain_name_constraints!(email_ok_chain) === nothing

        email_err = try
            TLX._tls_verify_chain_name_constraints!(
                TLX._TLSCertificateInfo[email_leaf, _tls_copy_cert(root; excluded_email_addresses = ["ops@localhost"])],
            )
            nothing
        catch ex
            ex
        end
        @test email_err isa TLX._TLSAlertError
        if email_err isa TLX._TLSAlertError
            @test occursin("excluded email name constraint", email_err.message)
        end

        uri_leaf = _tls_copy_cert(server_leaf; uri_names = ["spiffe://service.local/ns/default"])
        uri_ok_chain = TLX._TLSCertificateInfo[uri_leaf, _tls_copy_cert(root; permitted_uri_domains = ["service.local"])]
        @test TLX._tls_verify_chain_name_constraints!(uri_ok_chain) === nothing

        uri_err = try
            TLX._tls_verify_chain_name_constraints!(
                TLX._TLSCertificateInfo[uri_leaf, _tls_copy_cert(root; excluded_uri_domains = ["service.local"])],
            )
            nothing
        catch ex
            ex
        end
        @test uri_err isa TLX._TLSAlertError
        if uri_err isa TLX._TLSAlertError
            @test occursin("excluded URI name constraint", uri_err.message)
        end

        unsupported_name_err = try
            TLX._tls_verify_chain_name_constraints!(
                TLX._TLSCertificateInfo[
                    _tls_copy_cert(server_leaf; has_unhandled_san_names = true),
                    _tls_copy_cert(root; permitted_dns_domains = ["localhost"]),
                ],
            )
            nothing
        catch ex
            ex
        end
        @test unsupported_name_err isa TLX._TLSAlertError
        if unsupported_name_err isa TLX._TLSAlertError
            @test occursin("unsupported subjectAltName forms", unsupported_name_err.message)
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
