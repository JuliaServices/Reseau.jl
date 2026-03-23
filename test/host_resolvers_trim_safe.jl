using Reseau

const ND = Reseau.HostResolvers
const NC = Reseau.TCP
const IP = Reseau.IOPoll

struct _TrimResolver <: ND.AbstractResolver
    addr::NC.SocketEndpoint
end

function ND.lookup_port(::_TrimResolver, network::AbstractString, service::AbstractString)::Int
    _ = network
    return parse(Int, service)
end

function ND._resolve_host_ips(resolver::_TrimResolver, network::AbstractString, host::AbstractString)::Vector{NC.SocketEndpoint}
    _ = network
    host == "trim.local" || throw(ND.AddressError("unknown host", String(host)))
    addr = resolver.addr
    if addr isa NC.SocketAddrV4
        v4 = addr::NC.SocketAddrV4
        return NC.SocketEndpoint[NC.SocketAddrV4(v4.ip, 0)]
    end
    v6 = addr::NC.SocketAddrV6
    return NC.SocketEndpoint[NC.SocketAddrV6(v6.ip, 0; scope_id = Int(v6.scope_id))]
end

function run_host_resolvers_trim_sample()::Nothing
    listener::Union{Nothing, NC.Listener} = nothing
    client::Union{Nothing, NC.Conn} = nothing
    server::Union{Nothing, NC.Conn} = nothing
    try
        listener = NC.listen(NC.loopback_addr(0); backlog = 16)
        laddr = NC.addr(listener)::NC.SocketAddrV4
        resolver = _TrimResolver(NC.loopback_addr(Int(laddr.port)))
        client = ND.connect("tcp", "trim.local:$(Int(laddr.port))"; resolver = resolver, fallback_delay_ns = -1)
        IP.set_read_deadline!(listener.fd.pfd, time_ns() + 5_000_000_000)
        try
            server = NC.accept(listener)
        finally
            IP.set_read_deadline!(listener.fd.pfd, Int64(0))
        end
        client_remote = NC.remote_addr(client)::NC.SocketAddrV4
        server_local = NC.local_addr(server)::NC.SocketAddrV4
        client_remote.port == laddr.port || error("client remote port mismatch")
        server_local.port == laddr.port || error("server local port mismatch")
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
    run_host_resolvers_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
