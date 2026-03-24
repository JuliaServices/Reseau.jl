using Reseau

const ND = Reseau.HostResolvers
const NC = Reseau.TCP
const IP = Reseau.IOPoll

struct _TrimResolver <: ND.AbstractResolver
    addr::NC.SocketAddrV4
end

function ND.lookup_port(::_TrimResolver, network::AbstractString, service::AbstractString)::Int
    _ = network
    return parse(Int, service)
end

function ND._resolve_host_ips(resolver::_TrimResolver, network::AbstractString, host::AbstractString)::Vector{NC.SocketEndpoint}
    _ = network
    host == "trim.local" || throw(ND.AddressError("unknown host", String(host)))
    v4 = resolver.addr
    result = Vector{NC.SocketEndpoint}(undef, 1)
    result[1] = NC.SocketAddrV4(v4.ip, 0)
    return result
end

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

function run_host_resolvers_trim_sample()::Nothing
    listener::Union{Nothing, NC.Listener} = nothing
    client::Union{Nothing, NC.Conn} = nothing
    server::Union{Nothing, NC.Conn} = nothing
    trim_resolver = _TrimResolver(NC.loopback_addr(0))
    resolver = ND.HostResolver(resolver = trim_resolver)
    try
        listener = ND.listen(resolver, "tcp4", "trim.local:0"; backlog = 16)
        laddr = NC.addr(listener)::NC.SocketAddrV4
        addrstr = ND.join_host_port("trim.local", Int(laddr.port))
        ND.resolve_tcp_addr(trim_resolver, "tcp4", addrstr) isa NC.SocketAddrV4 || error("expected IPv4 resolution")
        client = ND.connect(resolver, "tcp4", addrstr)
        server = NC.accept(listener)
        payload = UInt8[0x71, 0x72, 0x73]
        write(client, payload) == length(payload) || error("expected HostResolvers payload write")
        recv_buf = Vector{UInt8}(undef, length(payload))
        _read_exact!(server, recv_buf)
        recv_buf == payload || error("HostResolvers payload mismatch")
    finally
        _close_quiet!(server)
        _close_quiet!(client)
        _close_quiet!(listener)
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_host_resolvers_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
