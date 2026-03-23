using Reseau

const NC = Reseau.TCP
const IP = Reseau.IOPoll

function run_tcp_trim_sample()::Nothing
    listener::Union{Nothing, NC.Listener} = nothing
    client::Union{Nothing, NC.Conn} = nothing
    server::Union{Nothing, NC.Conn} = nothing
    try
        listener = NC.listen(NC.loopback_addr(0); backlog = 16)
        laddr = NC.addr(listener)::NC.SocketAddrV4
        client = NC.connect(NC.loopback_addr(Int((laddr::NC.SocketAddrV4).port)))
        IP.set_read_deadline!(listener.fd.pfd, time_ns() + 5_000_000_000)
        try
            server = NC.accept(listener)
        finally
            IP.set_read_deadline!(listener.fd.pfd, Int64(0))
        end
        client_local = NC.local_addr(client)::NC.SocketAddrV4
        client_remote = NC.remote_addr(client)::NC.SocketAddrV4
        server_local = NC.local_addr(server)::NC.SocketAddrV4
        server_remote = NC.remote_addr(server)::NC.SocketAddrV4
        client_remote.port == laddr.port || error("client remote port mismatch")
        server_local.port == laddr.port || error("server local port mismatch")
        server_remote.port == client_local.port || error("server remote port mismatch")
    finally
        if server !== nothing
            try
                close(server::NC.Conn)
            catch
            end
        end
        if client !== nothing
            try
                close(client::NC.Conn)
            catch
            end
        end
        if listener !== nothing
            try
                close(listener::NC.Listener)
            catch
            end
        end
        IP.shutdown!()
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_tcp_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
