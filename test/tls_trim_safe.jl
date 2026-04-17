using Reseau

const TL = Reseau.TLS
const NC = Reseau.TCP
const IP = Reseau.IOPoll

const _TLS_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")
const _TLS_SERVER_CONFIG = TL.Config(
    verify_peer = false,
    cert_file = _TLS_CERT_PATH,
    key_file = _TLS_KEY_PATH,
    handshake_timeout_ns = 10_000_000_000,
    min_version = TL.TLS1_2_VERSION,
    max_version = TL.TLS1_2_VERSION,
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
        ca_file = _TLS_CERT_PATH,
        handshake_timeout_ns = 10_000_000_000,
        min_version = TL.TLS1_2_VERSION,
        max_version = TL.TLS1_2_VERSION,
    )
end

function _tls_server_task_entry()::TL.ConnectionState
    listener = _TLS_SERVER_LISTENER[]::TL.Listener
    conn = TL.accept(listener)
    try
        TL.handshake!(conn)
        state = TL.connection_state(conn)
        write(conn, UInt8[0x11])
        read(conn, 1) == UInt8[0x21] || error("unexpected TLS trim client ack")
        return state
    finally
        _close_quiet!(conn)
    end
end

Base.Experimental.entrypoint(_tls_server_task_entry, ())

function run_tls_trim_sample()::Nothing
    listener::Union{Nothing, TL.Listener} = nothing
    client::Union{Nothing, TL.Conn} = nothing
    server_task::Union{Nothing, Task} = nothing
    try
        listener = TL.listen(NC.loopback_addr(0), _TLS_SERVER_CONFIG; backlog = 8)
        _TLS_SERVER_LISTENER[] = listener
        laddr = TL.addr(listener)::NC.SocketAddrV4
        server_task = Task(_tls_server_task_entry)
        schedule(server_task)
        client = TL.connect(NC.loopback_addr(Int(laddr.port)), _tls_client_config())
        read(client, 1) == UInt8[0x11] || error("expected TLS server byte")
        write(client, UInt8[0x21]) == 1 || error("expected TLS client ack write")
        eof(client) || error("expected TLS EOF")
        client_state = TL.connection_state(client)
        client_state.handshake_complete || error("client handshake incomplete")
        client_state.version == "TLSv1.2" || error("expected TLS 1.2 connection state")
        !client_state.using_native_tls13 || error("did not expect TLS 1.3 native mode")
        client_state.cipher_suite in (
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
        ) || error("expected TLS 1.2 ECDHE-RSA cipher suite")
        client_state.curve == "P-256" || error("expected P-256 ECDHE")
        status = IP.timedwait(() -> istaskdone(server_task::Task), 10.0; pollint = 0.001)
        status == :timed_out && error("timed out waiting for TLS server task")
        server_state = fetch(server_task::Task)::TL.ConnectionState
        server_state.handshake_complete || error("server handshake incomplete")
        server_state.version == "TLSv1.2" || error("expected TLS 1.2 server state")
    finally
        _TLS_SERVER_LISTENER[] = nothing
        _close_quiet!(client)
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
