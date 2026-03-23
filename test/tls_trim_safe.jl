using Reseau

const TL = Reseau.TLS

const _TLS_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")

function run_tls_trim_sample()::Nothing
    isfile(_TLS_CERT_PATH) || error("missing trim TLS certificate")
    isfile(_TLS_KEY_PATH) || error("missing trim TLS private key")

    client_cfg = TL.Config(
        verify_peer = false,
        server_name = "localhost",
        alpn_protocols = ["h2"],
        handshake_timeout_ns = 10_000_000_000,
    )
    server_cfg = TL.Config(
        verify_peer = false,
        cert_file = _TLS_CERT_PATH,
        key_file = _TLS_KEY_PATH,
        handshake_timeout_ns = 10_000_000_000,
    )

    client_cfg.server_name == "localhost" || error("client server_name mismatch")
    client_cfg.alpn_protocols == ["h2"] || error("client ALPN mismatch")
    server_cfg.cert_file == _TLS_CERT_PATH || error("server cert path mismatch")
    server_cfg.key_file == _TLS_KEY_PATH || error("server key path mismatch")
    server_cfg.handshake_timeout_ns == 10_000_000_000 || error("server handshake timeout mismatch")
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_tls_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
