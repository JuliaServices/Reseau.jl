# Migrating from `Sockets` to Reseau

If you are using Julia's stdlib `Sockets`, the main conceptual change is that
Reseau makes transport layers explicit instead of forcing everything through one
untyped socket surface.

The payoff is better deadlines, clearer address handling, integrated TLS, and a
stack that matches what HTTP.jl 2.0 now uses underneath.

## Quick Mapping

| `Sockets` | Reseau |
| --- | --- |
| `listen(ip"127.0.0.1", port)` | `Reseau.TCP.listen(Reseau.TCP.loopback_addr(port))` |
| `connect(ip"127.0.0.1", port)` | `Reseau.TCP.connect(Reseau.TCP.loopback_addr(port))` |
| `connect("example.com", port)` | `Reseau.HostResolvers.connect("tcp", "example.com:$port")` |
| `accept(server)` | `Reseau.TCP.accept!(listener)` |
| `close(sock)` | `Reseau.TCP.close!(conn)` |
| `getsockname(sock)` | `Reseau.TCP.local_addr(conn)` |
| `getpeername(sock)` | `Reseau.TCP.remote_addr(conn)` |
| external TLS wrapper | `Reseau.TLS.connect`, `Reseau.TLS.listen`, `Reseau.TLS.client`, `Reseau.TLS.server` |

## The Two Most Common Ports

## 1. Simple TCP server

### `Sockets`

```julia
using Sockets

server = listen(ip"127.0.0.1", 9000)
sock = accept(server)
```

### `Reseau`

```julia
using Reseau

listener = Reseau.TCP.listen(Reseau.TCP.loopback_addr(9000))
conn = Reseau.TCP.accept!(listener)
```

## 2. Hostname-based client dial

### `Sockets`

```julia
using Sockets

sock = connect("example.com", 443)
```

### `Reseau`

```julia
using Reseau

conn = Reseau.HostResolvers.connect("tcp", "example.com:443")
```

## Deadlines Are First-Class

This is one of the biggest quality-of-life improvements over `Sockets`.

```julia
using Reseau

conn = Reseau.HostResolvers.connect("tcp", "example.com:443")
Reseau.TCP.set_read_deadline!(conn, time_ns() + 5_000_000_000)
```

Instead of managing ad hoc task timeouts around blocking socket calls, the
deadline is attached to the connection itself.

## Shutdown Is Explicit

Half-closing is exposed directly:

```julia
Reseau.TCP.close_write!(conn)
Reseau.TCP.close_read!(conn)
```

That is a better migration target than reaching for low-level shutdown syscalls.

## TLS No Longer Lives Somewhere Else

With `Sockets`, TLS usually meant another package layered on top. With Reseau,
TLS is part of the same stack:

```julia
using Reseau

tls = Reseau.TLS.connect(
    "tcp",
    "example.com:443";
    verify_peer=true,
    alpn_protocols=["h2", "http/1.1"],
)
```

For servers:

```julia
cfg = Reseau.TLS.Config(cert_file="server.crt", key_file="server.key")
listener = Reseau.TLS.listen("tcp", "127.0.0.1:8443", cfg)
```

## What to Change in Real Code

1. Replace direct `Sockets.connect(host, port)` calls with
   `HostResolvers.connect("tcp", "host:port")`.
2. Replace direct listen/accept loops with `TCP.listen` + `TCP.accept!`.
3. Replace manual timeout wrappers with connection deadlines.
4. Move TLS setup onto `Reseau.TLS.Config` and `Reseau.TLS.connect/listen`.
5. Update any code that expected raw `Sockets.TCPSocket` internals; Reseau uses
   its own `TCP.Conn` and `TLS.Conn` types.

## Benefits of Porting

- Better deadline and readiness behavior
- Clearer address and hostname handling
- TLS integrated into the same stack
- The same transport semantics used by HTTP.jl 2.0
- A package boundary that makes plain TCP, resolved TCP, and TLS easier to test
  in isolation
