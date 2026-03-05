using Reseau

const NC = Reseau.TCP
const EL = Reseau.EventLoops

function _write_all!(conn::NC.Conn, data::Vector{UInt8})::Nothing
    n = write(conn, data)
    n == length(data) || error("expected full write")
    return nothing
end

function _read_exact!(conn::NC.Conn, data::Vector{UInt8})::Nothing
    offset = 0
    while offset < length(data)
        chunk = Vector{UInt8}(undef, length(data) - offset)
        n = read!(conn, chunk)
        n > 0 || error("expected positive read progress")
        copyto!(data, offset + 1, chunk, 1, n)
        offset += n
    end
    return nothing
end

function run_tcp_trim_sample()::Nothing
    (Sys.isapple() || Sys.islinux()) || return nothing
    listener::Union{Nothing, NC.Listener} = nothing
    client::Union{Nothing, NC.Conn} = nothing
    server::Union{Nothing, NC.Conn} = nothing
    try
        listener = NC.listen(NC.loopback_addr(0); backlog = 16)
        laddr = NC.addr(listener)
        client = NC.connect(NC.loopback_addr(Int((laddr::NC.SocketAddrV4).port)))
        server = NC.accept!(listener)
        payload = UInt8[0x30, 0x31, 0x32, 0x33]
        recv_buf = Vector{UInt8}(undef, length(payload))
        _write_all!(client, payload)
        _read_exact!(server, recv_buf)
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
    run_tcp_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
