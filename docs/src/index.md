```@meta
Description = "Documentation for Reseau.jl's pure-Julia TCP and TLS transport stack."
```

# [Reseau.jl](@id home-page)

`Reseau.jl` is a pure-Julia networking transport stack with deadline-aware TCP,
hostname-aware dialing, and TLS in one package. The public surface is
deliberately small: plain TCP lives under [`Reseau.TCP`](@ref) and TLS lives
under [`Reseau.TLS`](@ref). String-address dialing uses the same entrypoints,
while the advanced resolver types behind that behavior are documented
separately in [Name Resolution](@ref name-resolution-manual).

```@contents
Pages = [
    "index.md",
    "tcp.md",
    "tls.md",
    "resolution.md",
    "migrate-sockets.md",
    "reference.md",
]
Depth = 2
```

## Installation

```julia
using Pkg
Pkg.add("Reseau")
```

## Module Entry Points

The package exports only `TCP` and `TLS`, which keeps the public API module-scoped
instead of namespace-flat:

```@docs; canonical=false
Reseau.TCP
Reseau.TLS
```

Read [API Reference](@ref api-reference-manual) for the canonical public docstrings and [Name
Resolution](@ref name-resolution-manual) for the advanced `resolver`,
`policy`, and `"host:port"` dialing layer.

## Why Reseau

- Deadline and readiness behavior live inside the transport instead of in ad hoc timeout wrappers.
- Concrete-address and hostname-based dialing use the same [`TCP.connect`](@ref Reseau.TCP.connect) and [`TLS.connect`](@ref Reseau.TLS.connect) entrypoints.
- TLS keeps the same lifecycle and deadline model as TCP, including lazy handshakes and transport-backed I/O.
- Because `TCP.Conn` and `TLS.Conn` are `IO` subtypes, standard helpers like
  `read`, `read!`, `readbytes!`, `eof`, and `write` work directly on live
  connections.

## Quick Start

This example stays entirely local: it opens a loopback listener, echoes one
payload, and shows the reply that came back over the socket.

```@example home-echo
using Reseau

listener = TCP.listen(TCP.loopback_addr(0); backlog = 16)
server = @async begin
    conn = TCP.accept(listener)
    try
        write(conn, "echo:" * String(read(conn)))
    finally
        close(conn)
        close(listener)
    end
end

client = TCP.connect(TCP.addr(listener))
reply = ""
try
    write(client, "hello")
    closewrite(client)
    reply = String(read(client))
finally
    close(client)
end

wait(server)
reply
```

## Documentation Map

- Read [TCP](@ref tcp-manual) for plain connections, address constructors, deadlines, I/O semantics, and socket options.
- Read [TLS](@ref tls-manual) for `TLS.Config`, client/server wrappers, lazy handshakes, and connection-state inspection.
- Read [Name Resolution](@ref name-resolution-manual) for advanced resolver controls behind the string-address entrypoints.
- Read [Migrating from `Sockets` to Reseau](@ref sockets-migration-manual) if you are porting code from Julia's stdlib `Sockets`.
- Read [API Reference](@ref api-reference-manual) for canonical docstrings and a generated docstring index.
