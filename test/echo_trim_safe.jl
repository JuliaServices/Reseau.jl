using Reseau

const RS = Reseau.Sockets

function run_echo()::Nothing
    server::Union{RS.TCPServer, Nothing} = nothing
    client::Union{RS.TCPSocket, Nothing} = nothing
    peer::Union{RS.TCPSocket, Nothing} = nothing
    try
        RS.io_library_init()

        port_u16, server = RS.listenany(0)
        client = RS.connect(Int(port_u16))

        write(client, "hello")
        flush(client)

        peer = RS.accept(server)
        req = String(read(peer, 5))
        req == "hello" || error("server expected \"hello\", got $(repr(req))")

        write(peer, "hello")
        flush(peer)
        close(peer)
        peer = nothing

        resp = String(read(client, 5))
        resp == "hello" || error("client expected \"hello\", got $(repr(resp))")

        close(client)
        client = nothing
        close(server)
        server = nothing
    finally
        peer !== nothing && close(peer)
        client !== nothing && close(client)
        server !== nothing && close(server)
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_echo()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
