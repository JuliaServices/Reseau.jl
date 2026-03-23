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
    resolver = _TrimResolver(NC.loopback_addr(4040))
    addrs = ND.resolve_tcp_addrs(resolver, "tcp", "trim.local:4040"; op = :connect)
    length(addrs) == 1 || error("expected one resolved address")
    addr = addrs[1]::NC.SocketAddrV4
    addr.port == 4040 || error("resolved port mismatch")
    addr.ip == NC.loopback_addr(0).ip || error("resolved ip mismatch")
    single = ND.resolve_tcp_addr(resolver, "tcp", "trim.local:4040")
    single == addr || error("resolved single address mismatch")
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_host_resolvers_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
