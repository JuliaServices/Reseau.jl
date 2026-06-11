using Reseau

const NC = Reseau.TCP
const SK = Reseau.SOCKS

function _close_quiet!(x)
    x === nothing && return nothing
    try
        close(x)
    catch
    end
    return nothing
end

function run_socks_trim_sample()::Nothing
    listener::Union{Nothing, NC.Listener} = nothing
    client::Union{Nothing, NC.Conn} = nothing
    server::Union{Nothing, NC.Conn} = nothing
    try
        listener = NC.listen(NC.loopback_addr(0); backlog = 16)
        laddr = NC.addr(listener)::NC.SocketAddrV4
        client = NC.connect(NC.loopback_addr(Int(laddr.port)))
        server = NC.accept(listener)
        # Pre-buffer the scripted proxy replies (no-auth method selection plus
        # a successful CONNECT reply with a 0.0.0.0:0 IPv4 bound address) so
        # the handshake completes without a second task.
        replies = UInt8[0x05, 0x00, 0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        write(server, replies) == length(replies) || error("expected proxy reply write")
        bound = SK.connect!(client, "example.com:443")
        string(bound) == "0.0.0.0:0" || error("unexpected SOCKS bound address")
        expected = UInt8[
            0x05, 0x01, 0x00,
            0x05, 0x01, 0x00, 0x03, UInt8(length("example.com")),
            codeunits("example.com")...,
            0x01, 0xbb,
        ]
        request = Vector{UInt8}(undef, length(expected))
        read!(server, request)
        request == expected || error("unexpected SOCKS handshake bytes")
        err = try
            SK.connect!(client, "missing-port")
            nothing
        catch ex
            ex
        end
        err isa SK.TargetAddressError || error("expected SOCKS target validation error")
        isempty(sprint(showerror, err::SK.TargetAddressError)) && error("expected SOCKS error message")
    finally
        _close_quiet!(server)
        _close_quiet!(client)
        _close_quiet!(listener)
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_socks_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
