using Reseau

const TL = Reseau.TLS
const NC = Reseau.TCP
const IP = Reseau.IOPoll

const _TLS_CA_PATH = joinpath(@__DIR__, "resources", "native_tls_ca.crt")
const _TLS_SERVER_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server.crt")
const _TLS_SERVER_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_server.key")
const _TLS_CLIENT_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_client.crt")
const _TLS_CLIENT_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_client.key")
const _TLS_SERVER_CONFIG = TL.Config(
    verify_peer = false,
    cert_file = _TLS_SERVER_CERT_PATH,
    key_file = _TLS_SERVER_KEY_PATH,
    client_auth = TL.ClientAuthMode.RequireAndVerifyClientCert,
    client_ca_file = _TLS_CA_PATH,
    handshake_timeout_ns = 10_000_000_000,
    min_version = TL.TLS1_3_VERSION,
    max_version = TL.TLS1_3_VERSION,
)
const _TLS_SERVER_LISTENER = Ref{Union{Nothing, TL.Listener}}(nothing)

function _close_quiet!(x)
    x === nothing && return nothing
    try
        close(x)
    catch
    end
    return nothing
end

function _tls_client_config()::TL.Config
    return TL.Config(
        server_name = "localhost",
        verify_peer = true,
        ca_file = _TLS_CA_PATH,
        cert_file = _TLS_CLIENT_CERT_PATH,
        key_file = _TLS_CLIENT_KEY_PATH,
        handshake_timeout_ns = 10_000_000_000,
        min_version = TL.TLS1_3_VERSION,
        max_version = TL.TLS1_3_VERSION,
    )
end

function _tls_server_task_entry()::Vector{TL.ConnectionState}
    listener = _TLS_SERVER_LISTENER[]::TL.Listener
    states = TL.ConnectionState[]
    for i in 1:2
        conn = TL.accept(listener)
        try
            TL.handshake!(conn)
            push!(states, TL.connection_state(conn))
            write(conn, UInt8[UInt8(0x10 + i)])
            read(conn, 1) == UInt8[UInt8(0x20 + i)] || error("unexpected TLS trim client ack")
        finally
            _close_quiet!(conn)
        end
    end
    return states
end

Base.Experimental.entrypoint(_tls_server_task_entry, ())

function run_tls_trim_sample()::Nothing
    listener::Union{Nothing, TL.Listener} = nothing
    client1::Union{Nothing, TL.Conn} = nothing
    client2::Union{Nothing, TL.Conn} = nothing
    server_task::Union{Nothing, Task} = nothing
    try
        listener = TL.listen(NC.loopback_addr(0), _TLS_SERVER_CONFIG; backlog = 8)
        _TLS_SERVER_LISTENER[] = listener
        laddr = TL.addr(listener)::NC.SocketAddrV4
        server_task = Task(_tls_server_task_entry)
        schedule(server_task)
        client_config = _tls_client_config()
        client1 = TL.connect(NC.loopback_addr(Int(laddr.port)), client_config)
        read(client1, 1) == UInt8[0x11] || error("expected first TLS byte")
        write(client1, UInt8[0x21]) == 1 || error("expected first TLS client ack write")
        eof(client1) || error("expected first TLS EOF")
        client1_state = TL.connection_state(client1)
        client1_state.did_resume &&
            error("did not expect first native TLS connection to resume")
        client1_state.has_resumable_session ||
            error("expected first native TLS connection to cache a resumable session")
        client2 = TL.connect(NC.loopback_addr(Int(laddr.port)), client_config)
        read(client2, 1) == UInt8[0x12] || error("expected resumed TLS byte")
        write(client2, UInt8[0x22]) == 1 || error("expected resumed TLS client ack write")
        eof(client2) || error("expected resumed TLS EOF")
        client2_state = TL.connection_state(client2)
        client2_state.did_resume ||
            error("expected native TLS trim sample to resume")
        status = IP.timedwait(() -> istaskdone(server_task::Task), 10.0; pollint = 0.001)
        status == :timed_out && error("timed out waiting for TLS server task")
        server_states = fetch(server_task::Task)::Vector{TL.ConnectionState}
        length(server_states) == 2 || error("expected two TLS server connections")
        server_states[2].did_resume || error("expected native TLS trim server to resume")
        client2_state.handshake_complete || error("client handshake incomplete")
    finally
        _TLS_SERVER_LISTENER[] = nothing
        _close_quiet!(client2)
        _close_quiet!(client1)
        _close_quiet!(listener)
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_tls_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
