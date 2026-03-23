using Reseau

const NC = Reseau.TCP

function run_tcp_trim_sample()::Nothing
    listener::Union{Nothing, NC.Listener} = nothing
    try
        listener = NC.listen(NC.loopback_addr(0); backlog = 16)
        laddr = NC.addr(listener)::NC.SocketAddrV4
        Int(laddr.port) > 0 || error("expected bound loopback port")
        laddr.ip == NC.loopback_addr(0).ip || error("expected loopback listener address")
    finally
        if listener !== nothing
            try
                close(listener::NC.Listener)
            catch
            end
        end
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_tcp_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
