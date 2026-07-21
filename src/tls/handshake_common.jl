# Small helpers shared by multiple handshake state machines.
#
# The version-specific files own the handshake flights and transcript logic;
# this file only holds policy decisions that are identical across those flows.

function _tls_select_server_alpn(config, client_hello::_ClientHelloMsg)::String
    isempty(config.alpn_protocols) && return ""
    isempty(client_hello.alpn_protocols) && return ""
    http11_fallback = false
    for proto in config.alpn_protocols
        for client_proto in client_hello.alpn_protocols
            proto == client_proto && return proto
            proto == "h2" && client_proto == "http/1.1" && (http11_fallback = true)
        end
    end
    http11_fallback && return ""
    _tls_fail(_TLS_ALERT_NO_APPLICATION_PROTOCOL, "tls: client and server do not support a common ALPN protocol")
end

@inline _tls_should_request_client_certificate(config)::Bool =
    config.client_auth != ClientAuthMode.NoClientCert

@inline function _tls13_signature_scheme_matches_public_key(
    signature_algorithm::UInt16,
    public_key::_TLSPublicKey,
)::Bool
    if public_key isa _TLSRSAPublicKey
        return signature_algorithm == _TLS_SIGNATURE_RSA_PSS_RSAE_SHA256 ||
            signature_algorithm == _TLS_SIGNATURE_RSA_PSS_RSAE_SHA384 ||
            signature_algorithm == _TLS_SIGNATURE_RSA_PSS_RSAE_SHA512 ||
            signature_algorithm == _TLS_SIGNATURE_RSA_PSS_PSS_SHA256 ||
            signature_algorithm == _TLS_SIGNATURE_RSA_PSS_PSS_SHA384 ||
            signature_algorithm == _TLS_SIGNATURE_RSA_PSS_PSS_SHA512
    end
    if public_key isa _TLSECPublicKey
        curve_id = (public_key::_TLSECPublicKey).curve_id
        return (curve_id == _TLS_GROUP_SECP256R1 && signature_algorithm == _TLS_SIGNATURE_ECDSA_SECP256R1_SHA256) ||
            (curve_id == UInt16(0x0018) && signature_algorithm == _TLS_SIGNATURE_ECDSA_SECP384R1_SHA384) ||
            (curve_id == UInt16(0x0019) && signature_algorithm == _TLS_SIGNATURE_ECDSA_SECP521R1_SHA512)
    end
    return public_key isa _TLSEd25519PublicKey && signature_algorithm == _TLS_SIGNATURE_ED25519
end

# Used when deciding whether a cached resumption session is still valid for the
# current server-side client-auth policy. Resumption should not bypass a stricter
# certificate requirement than the original session satisfied.
function _tls_server_session_client_auth_ok(
    verify_chain!::F,
    client_certificates::Vector{Vector{UInt8}},
    config,
)::Bool where {F}
    mode = config.client_auth
    has_client_certificates = !isempty(client_certificates)
    if mode == ClientAuthMode.NoClientCert
        return !has_client_certificates
    end
    if mode == ClientAuthMode.RequireAnyClientCert || mode == ClientAuthMode.RequireAndVerifyClientCert
        has_client_certificates || return false
    end
    has_client_certificates || return true
    if mode == ClientAuthMode.VerifyClientCertIfGiven || mode == ClientAuthMode.RequireAndVerifyClientCert
        try
            verify_chain!(client_certificates)
            return true
        catch
            return false
        end
    end
    return true
end
