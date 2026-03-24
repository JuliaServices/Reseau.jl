using Reseau

const NC = Reseau.TCP
const IP = Reseau.IOPoll

function _read_exact!(conn::NC.Conn, buf::Vector{UInt8})::Nothing
    read!(conn, buf)
    return nothing
end

function _close_quiet!(x)
    x === nothing && return nothing
    try
        close(x)
    catch
    end
    return nothing
end

function run_tcp_trim_sample()::Nothing
    listener::Union{Nothing, NC.Listener} = nothing
    client::Union{Nothing, NC.Conn} = nothing
    server::Union{Nothing, NC.Conn} = nothing
    try
        listener = NC.listen(NC.loopback_addr(0); backlog = 16)
        laddr = NC.addr(listener)::NC.SocketAddrV4
        client = NC.connect(NC.loopback_addr(Int(laddr.port)))
        server = NC.accept(listener)
        client_local = NC.local_addr(client)::NC.SocketAddrV4
        client_remote = NC.remote_addr(client)::NC.SocketAddrV4
        server_local = NC.local_addr(server)::NC.SocketAddrV4
        server_remote = NC.remote_addr(server)::NC.SocketAddrV4
        client_remote.port == laddr.port || error("client remote port mismatch")
        server_local.port == laddr.port || error("server local port mismatch")
        server_remote.port == client_local.port || error("server remote port mismatch")
        payload = UInt8[0x61, 0x62, 0x63]
        write(client, payload) == length(payload) || error("expected TCP payload write")
        recv_buf = Vector{UInt8}(undef, length(payload))
        _read_exact!(server, recv_buf)
        recv_buf == payload || error("TCP payload mismatch")
    finally
        _close_quiet!(server)
        _close_quiet!(client)
        _close_quiet!(listener)
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_tcp_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
