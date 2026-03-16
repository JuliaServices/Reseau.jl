# Reseau.jl

`Reseau.jl` is a pure-Julia networking transport stack organized around the
same broad layers as Go's `runtime`, `internal/poll`, `net`, and `crypto/tls`
packages.

Reseau owns:

- event-loop backends and timer-driven readiness polling
- non-blocking socket operations and deadline handling
- TCP connections and listeners
- hostname-aware dialing and listening through the `TCP` entrypoints
- TLS clients and listeners

## Installation

```julia
using Pkg
Pkg.add("Reseau")
```

## Main Entry Points

The user-facing API is centered on the exported `TCP` and `TLS` modules:

- `TCP` for plain TCP connections, listeners, deadlines, and string-address dialing
- `TLS` for TLS connections, listeners, and handshake/configuration control

## Quick Start

### TCP

```julia
using Reseau

listener = TCP.listen(TCP.loopback_addr(0); backlog = 128)
addr = TCP.addr(listener)

server_task = errormonitor(Threads.@spawn begin
    conn = TCP.accept(listener)
    try
        buf = Vector{UInt8}(undef, 5)
        read!(conn, buf)
        write(conn, buf)
    finally
        close(conn)
    end
end)

client = TCP.connect(addr)
write(client, collect(codeunits("hello")))
reply = Vector{UInt8}(undef, 5)
read!(client, reply)

close(client)
close(listener)
wait(server_task)
```

### Hostname-Based Dialing

```julia
using Reseau

conn = TCP.connect("example.com:80")
close(conn)

listener = TCP.listen("127.0.0.1:0"; backlog = 64)
println(TCP.addr(listener))
close(listener)
```

### TLS

```julia
using Reseau

conn = TLS.connect(
    "www.google.com:443";
    alpn_protocols = ["h2", "http/1.1"],
)

state = TLS.connection_state(conn)
println((state.handshake_complete, state.alpn_protocol))
close(conn)
```

## Why Use Reseau

- Deadlines and readiness behavior are part of the transport instead of bolted on outside it.
- Concrete-address and hostname-based dialing use the same `TCP` and `TLS` entrypoints.
- TLS lives in the same stack as plain TCP, so timeout and lifecycle behavior stay aligned.

## Reading Guide

- Read [TCP](tcp.md) for plain connections, listeners, deadlines, and string-address dialing.
- Read [TLS](tls.md) for client/server TLS configuration and handshake behavior.
- Read [Sockets Migration Guide](migrate-sockets.md) if you are porting from Julia's stdlib `Sockets`.
- Read [API Reference](reference.md) for the exported surface area.
