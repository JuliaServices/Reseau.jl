using Reseau

const NU = Reseau.UDP

function _close_quiet!(x)
    x === nothing && return nothing
    try
        close(x)
    catch
    end
    return nothing
end

function run_udp_trim_sample()::Nothing
    receiver::Union{Nothing, NU.Conn} = nothing
    sender::Union{Nothing, NU.Conn} = nothing
    try
        receiver = NU.listen(NU.loopback_addr(0))
        raddr = NU.local_addr(receiver)::NU.SocketAddrV4
        raddr.port == 0 && error("expected an ephemeral UDP port")
        sender = NU.connect(raddr)
        NU.remote_addr(sender)::NU.SocketAddrV4 == raddr || error("sender remote mismatch")
        payload = UInt8[0x61, 0x62, 0x63]
        NU.send(sender, payload)
        buf = Vector{UInt8}(undef, 8)
        n, from = NU.recvfrom!(receiver, buf)
        n == length(payload) || error("expected a 3-byte datagram")
        buf[1:n] == payload || error("UDP payload mismatch")
        from::NU.SocketAddrV4 == NU.local_addr(sender)::NU.SocketAddrV4 || error("peer mismatch")
        NU.sendto(receiver, payload, from)
        reply = NU.recv(sender)
        reply == payload || error("UDP reply mismatch")
    finally
        _close_quiet!(sender)
        _close_quiet!(receiver)
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_udp_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
