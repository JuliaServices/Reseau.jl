function _tls_select_server_alpn(config, client_hello::_ClientHelloMsg)::String
    isempty(config.alpn_protocols) && return ""
    isempty(client_hello.alpn_protocols) && return ""
    for proto in config.alpn_protocols
        in(proto, client_hello.alpn_protocols) && return proto
    end
    return ""
end

@inline _tls_should_request_client_certificate(config)::Bool =
    config.client_auth != ClientAuthMode.NoClientCert

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
