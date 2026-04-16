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

function _tls_client_config()::TL.Config
    return TL.Config(
        server_name = "localhost",
        verify_peer = false,
        handshake_timeout_ns = 10_000_000_000,
        min_version = TL.TLS1_3_VERSION,
        max_version = TL.TLS1_3_VERSION,
    )
end

function _tls_server_task_entry()::Nothing
    listener = _TLS_SERVER_LISTENER[]::TL.Listener
    conns = TL.Conn[]
    for i in 1:2
        conn = TL.accept(listener)
        TL.handshake!(conn)
        push!(conns, conn)
        write(conn, UInt8[UInt8(i)])
        close(conn)
    end
    _TLS_SERVER_CONN[] = conns[end]
    return nothing
end

Base.Experimental.entrypoint(_tls_server_task_entry, ())

function run_tls_trim_sample()::Nothing
    listener::Union{Nothing, TL.Listener} = nothing
    client1::Union{Nothing, TL.Conn} = nothing
    client2::Union{Nothing, TL.Conn} = nothing
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
        client_config = _tls_client_config()
        client1 = TL.connect(NC.loopback_addr(Int(laddr.port)), client_config)
        read(client1, 1) == UInt8[0x01] || error("expected first TLS byte")
        eof(client1) || error("expected first TLS EOF")
        client1_state = TL.connection_state(client1)
        client1_state.did_resume &&
            error("did not expect first native TLS connection to resume")
        client1_state.has_resumable_session ||
            error("expected first native TLS connection to cache a resumable session")
        client2 = TL.connect(NC.loopback_addr(Int(laddr.port)), client_config)
        read(client2, 1) == UInt8[0x02] || error("expected resumed TLS byte")
        eof(client2) || error("expected resumed TLS EOF")
        client2_state = TL.connection_state(client2)
        client2_state.did_resume ||
            error("expected native TLS trim sample to resume")
        status = IP.timedwait(() -> istaskdone(server_task::Task), 10.0; pollint = 0.001)
        status == :timed_out && error("timed out waiting for TLS server task")
        wait(server_task)
        client2_state.handshake_complete || error("client handshake incomplete")
    finally
        _TLS_SERVER_LISTENER[] = nothing
        _TLS_SERVER_CONN[] = nothing
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
