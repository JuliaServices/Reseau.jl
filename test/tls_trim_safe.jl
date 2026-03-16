using Reseau

const TL = Reseau.TLS
const NC = Reseau.TCP
const EL = Reseau.EventLoops

const _TLS_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")

function run_tls_trim_sample()::Nothing
    (Sys.isapple() || Sys.islinux()) || return nothing
    listener::Union{Nothing, NC.Listener} = nothing
    client_tcp::Union{Nothing, NC.Conn} = nothing
    server_tcp::Union{Nothing, NC.Conn} = nothing
    client_tls::Union{Nothing, TL.Conn} = nothing
    server_tls::Union{Nothing, TL.Conn} = nothing
    try
        listener = NC.listen(NC.loopback_addr(0); backlog = 8)
        laddr = NC.addr(listener)::NC.SocketAddrV4
        client_tcp = NC.connect(NC.loopback_addr(Int(laddr.port)))
        server_tcp = NC.accept(listener)
        client_cfg = TL.Config(verify_peer = false, server_name = "localhost", handshake_timeout_ns = 1_000_000_000)
        server_cfg = TL.Config(
            verify_peer = false,
            cert_file = _TLS_CERT_PATH,
            key_file = _TLS_KEY_PATH,
            handshake_timeout_ns = 1_000_000_000,
        )
        client_tls = TL.client(client_tcp, client_cfg)
        server_tls = TL.server(server_tcp, server_cfg)
        _ = TL.connection_state(client_tls)
        _ = TL.connection_state(server_tls)
    finally
        if server_tls !== nothing
            try
                close(server_tls::TL.Conn)
            catch
            end
        elseif server_tcp !== nothing
            try
                close(server_tcp::NC.Conn)
            catch
            end
        end
        if client_tls !== nothing
            try
                close(client_tls::TL.Conn)
            catch
            end
        elseif client_tcp !== nothing
            try
                close(client_tcp::NC.Conn)
            catch
            end
        end
        if listener !== nothing
            try
                close(listener::NC.Listener)
            catch
            end
        end
        EL.shutdown!()
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_tls_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
