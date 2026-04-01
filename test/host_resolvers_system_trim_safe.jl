using Reseau

const ND = Reseau.HostResolvers
const NC = Reseau.TCP

function run_host_resolvers_system_trim_sample()::Nothing
    native = ND._native_getaddrinfo("localhost"; flags = ND._AI_ALL | ND._AI_V4MAPPED)
    isempty(native) && error("expected native localhost resolution")
    all(x -> x isa NC.SocketEndpoint, native) || error("expected native socket endpoints")
    resolved = ND.resolve_tcp_addrs("tcp", "localhost:80")
    isempty(resolved) && error("expected resolved localhost addresses")
    all(x -> x isa NC.SocketEndpoint, resolved) || error("expected resolved socket endpoints")
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_host_resolvers_system_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
