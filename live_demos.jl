# Live demo A: TCP echo + deadline
using Reseau

listener = TCP.listen(TCP.loopback_addr(0))
release_server = Channel{Nothing}(1)

server_task = errormonitor(@async begin
    conn = TCP.accept(listener)
    try
        request = String(read(conn, 5))
        write(conn, "echo:" * request)
        take!(release_server) # Stay silent while the client tests its deadline.
    finally
        close(conn)
    end
end)

client = TCP.connect(TCP.addr(listener))
try
    write(client, "hello")
    println("TCP echo: ", String(read(client, 10)))

    TCP.set_read_deadline!(client, time_ns() + 500_000_000)
    try
        read(client, UInt8)
    catch err
        err isa TCP.DeadlineExceededError || rethrow()
        println(
            "TCP deadline: ",
            nameof(typeof(err)),
            " (",
            sprint(showerror, err),
            ")",
        )
    finally
        TCP.set_read_deadline!(client, 0)
    end
finally
    put!(release_server, nothing)
    close(client)
    close(listener)
    wait(server_task)
end

# Expected output:
# TCP echo: echo:hello
# TCP deadline: DeadlineExceededError (i/o timeout)


# Live demo B: TLS ALPN loopback
cert_file = joinpath(pkgdir(Reseau), "test", "resources", "native_tls_server.crt")
key_file = joinpath(pkgdir(Reseau), "test", "resources", "native_tls_server.key")
ca_file = joinpath(pkgdir(Reseau), "test", "resources", "native_tls_ca.crt")
protocols = ["h2", "http/1.1"]

server_config = TLS.Config(
    cert_file = cert_file,
    key_file = key_file,
    verify_peer = false,
    alpn_protocols = protocols,
    handshake_timeout_ns = 5_000_000_000,
)
listener = TLS.listen(TCP.loopback_addr(0), server_config)

server_task = errormonitor(@async begin
    conn = TLS.accept(listener)
    try
        TLS.handshake!(conn)
        request = String(read(conn, 5))
        write(conn, "secure:" * request)
        return TLS.connection_state(conn)
    finally
        close(conn)
    end
end)

client_config = TLS.Config(
    server_name = "localhost",
    ca_file = ca_file,
    alpn_protocols = protocols,
    handshake_timeout_ns = 5_000_000_000,
)
client = TLS.connect(TLS.addr(listener), client_config)

try
    write(client, "hello")
    reply = String(read(client, 12))
    client_state = TLS.connection_state(client)
    server_state = fetch(server_task)

    println("TLS echo: ", reply)
    println("TLS version: ", client_state.version)
    println("Client ALPN: ", client_state.alpn_protocol)
    println("Server ALPN: ", server_state.alpn_protocol)
finally
    close(client)
    close(listener)
end

# Expected output:
# TLS echo: secure:hello
# TLS version: TLSv1.3
# Client ALPN: h2
# Server ALPN: h2
