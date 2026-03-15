# Reseau.jl

Reseau.jl is the lower-level networking stack that now sits under the extracted
HTTP.jl 2.0 package.

After the split, Reseau owns:

- event loop and poller behavior
- non-blocking socket operations
- TCP connection and listener types
- host parsing and resolution
- TLS connections and listeners

If you want HTTP, WebSockets, SSE, or HTTP/2, use HTTP.jl on top of Reseau.

## Installation

```julia
using Pkg
Pkg.add("Reseau")
```

For development from a local checkout:

```julia
using Pkg
Pkg.develop(path="/path/to/Reseau.jl")
```

## Package Shape

The public surface is intentionally module-qualified:

- `Reseau.TCP` for concrete-address TCP work
- `Reseau.HostResolvers` for string-address resolution and dialing
- `Reseau.TLS` for TLS clients and listeners

This makes it clearer which layer owns what, and mirrors the way Go splits
transport, name resolution, and TLS responsibilities.

## Quick Start

### Direct-address TCP

```julia
using Reseau

listener = Reseau.TCP.listen(Reseau.TCP.loopback_addr(9000))
conn = Reseau.TCP.accept!(listener)
```

### String-address TCP

```julia
using Reseau

conn = Reseau.HostResolvers.connect("tcp", "example.com:443")
```

### TLS

```julia
using Reseau

conn = Reseau.TLS.connect(
    "tcp",
    "example.com:443";
    alpn_protocols=["h2", "http/1.1"],
)
```

## Why Use Reseau

- Deadlines and blocking behavior are explicit and testable.
- String-address dialing and concrete-address dialing are both first-class.
- TLS is part of the same stack instead of an afterthought layered over a
  different transport abstraction.
- HTTP.jl 2.0 now uses this exact stack, so transport semantics stay aligned
  across the ecosystem.

## Reading Guide

- Read [TCP and Resolution](tcp.md) for the main connection/listener APIs.
- Read [TLS](tls.md) for client/server TLS configuration.
- Read [Sockets Migration Guide](migrate-sockets.md) if you are porting from
  Julia's stdlib `Sockets`.
