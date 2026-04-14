using Reseau

const TL = Reseau.TLS
const NC = Reseau.TCP
const IP = Reseau.IOPoll

const _TLS_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")
const _TLS_SERVER_LISTENER = Ref{Union{Nothing, TL.Listener}}(nothing)
const _TLS_SERVER_CONN = Ref{Union{Nothing, TL.Conn}}(nothing)

function _close_quiet!(x)
    x === nothing && return nothing
    try
        close(x)
    catch
    end
    return nothing
end

function _read_exact!(conn::TL.Conn, buf::Vector{UInt8})::Nothing
    read!(conn, buf)
    return nothing
end

function _tls_client_connect(addr::NC.SocketAddrV4)::TL.Conn
    return TL.connect(
        addr;
        server_name = "localhost",
        verify_peer = false,
        handshake_timeout_ns = 10_000_000_000,
    )
end

function _tls_server_task_entry()::Nothing
    listener = _TLS_SERVER_LISTENER[]::TL.Listener
    conn = TL.accept(listener)
    TL.handshake!(conn)
    _TLS_SERVER_CONN[] = conn
    return nothing
end

Base.Experimental.entrypoint(_tls_server_task_entry, ())

function run_tls_trim_sample()::Nothing
    listener::Union{Nothing, TL.Listener} = nothing
    client::Union{Nothing, TL.Conn} = nothing
    server::Union{Nothing, TL.Conn} = nothing
    server_task::Union{Nothing, Task} = nothing
    try
        Reseau._pc_run_tls13_client_handshake_workload!()
        listener = TL.listen(
            NC.loopback_addr(0),
            TL.Config(
                verify_peer = false,
                cert_file = _TLS_CERT_PATH,
                key_file = _TLS_KEY_PATH,
                handshake_timeout_ns = 10_000_000_000,
            );
            backlog = 8,
        )
        _TLS_SERVER_LISTENER[] = listener
        _TLS_SERVER_CONN[] = nothing
        laddr = TL.addr(listener)::NC.SocketAddrV4
        server_task = Task(_tls_server_task_entry)
        schedule(server_task)
        client = _tls_client_connect(NC.loopback_addr(Int(laddr.port)))
        status = IP.timedwait(() -> istaskdone(server_task::Task), 10.0; pollint = 0.001)
        status == :timed_out && error("timed out waiting for TLS server task")
        wait(server_task)
        server = _TLS_SERVER_CONN[]::TL.Conn
        TL.connection_state(client).handshake_complete || error("client handshake incomplete")
        TL.connection_state(server).handshake_complete || error("server handshake incomplete")
        payload = UInt8[0x54, 0x4c, 0x53]
        write(client, payload) == length(payload) || error("expected TLS payload write")
        recv_buf = Vector{UInt8}(undef, length(payload))
        _read_exact!(server, recv_buf)
        recv_buf == payload || error("TLS payload mismatch")
    finally
        _TLS_SERVER_LISTENER[] = nothing
        _TLS_SERVER_CONN[] = nothing
        _close_quiet!(server)
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
