using Reseau

const ND = Reseau.HostResolvers
const NC = Reseau.TCP
const EL = Reseau.EventLoops

function _trim_read_exact!(conn::NC.Conn, buf::Vector{UInt8})::Int
    offset = 0
    while offset < length(buf)
        chunk = Vector{UInt8}(undef, length(buf) - offset)
        n = read!(conn, chunk)
        n > 0 || throw(EOFError())
        copyto!(buf, offset + 1, chunk, 1, n)
        offset += n
    end
    return offset
end

function run_host_resolvers_trim_sample()::Nothing
    (Sys.isapple() || Sys.islinux()) || return nothing
    listener::Union{Nothing, NC.Listener} = nothing
    client::Union{Nothing, NC.Conn} = nothing
    server::Union{Nothing, NC.Conn} = nothing
    try
        listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 16)
        laddr = NC.addr(listener)
        client = ND.connect("tcp", "127.0.0.1:$(Int((laddr::NC.SocketAddrV4).port))")
        server = NC.accept!(listener)
        payload = UInt8[0x66, 0x67, 0x68]
        recv_buf = Vector{UInt8}(undef, length(payload))
        write(client, payload) == length(payload) || error("expected full write")
        _trim_read_exact!(server, recv_buf) == length(payload) || error("expected full read")
        recv_buf == payload || error("payload mismatch")
    finally
        if server !== nothing
            try
                NC.close!(server::NC.Conn)
            catch
            end
        end
        if client !== nothing
            try
                NC.close!(client::NC.Conn)
            catch
            end
        end
        if listener !== nothing
            try
                NC.close!(listener::NC.Listener)
            catch
            end
        end
        EL.shutdown!()
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_host_resolvers_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
