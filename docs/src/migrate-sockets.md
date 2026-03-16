```@meta
Description = "How to migrate TCP and TLS code from Julia's stdlib Sockets to Reseau.jl."
```

# [Migrating from `Sockets` to Reseau](@id sockets-migration-manual)

If you are porting code from Julia's stdlib `Sockets`, the easiest mental model
is:

- keep the familiar `connect`, `listen`, `accept`, `read!`, `write`, and `close` flow
- move plain transport work onto [`Reseau.TCP`](@ref)
- move TLS work onto [`Reseau.TLS`](@ref)
- replace timeout wrappers with connection deadlines

```@contents
Pages = ["migrate-sockets.md"]
Depth = 2:3
```

## Quick Mapping

| `Sockets` | Reseau |
| --- | --- |
| `listen(ip"127.0.0.1", port)` | `TCP.listen(TCP.loopback_addr(port))` |
| `connect(ip"127.0.0.1", port)` | `TCP.connect(TCP.loopback_addr(port))` |
| `connect("example.com", port)` | `TCP.connect("example.com:$port")` |
| `accept(server)` | `TCP.accept(listener)` |
| `read!(sock, buf)` | `read!(conn, buf)` |
| `write(sock, buf)` | `write(conn, buf)` |
| `close(sock)` | `close(conn)` / `close(listener)` |
| `getsockname(sock)` | `TCP.local_addr(conn)` |
| `getpeername(sock)` | `TCP.remote_addr(conn)` |
| external TLS wrapper | `TLS.connect`, `TLS.listen`, `TLS.client`, `TLS.server` |

## TCP Server Shape

### `Sockets`

```julia
using Sockets

server = listen(ip"127.0.0.1", 9000)
sock = accept(server)
close(sock)
close(server)
```

### `Reseau`

```julia
using Reseau

listener = TCP.listen(TCP.loopback_addr(9000))
conn = TCP.accept(listener)
close(conn)
close(listener)
```

Read [TCP](@ref tcp-manual) for the full connection and deadline model.

## Hostname-Based Dialing

If your old code used separate host and port arguments, the most direct Reseau
translation is the `"host:port"` string-address surface:

```julia
using Reseau

conn = TCP.connect("example.com:443")
close(conn)
```

If you need to control family preference, timeout budget, or custom resolution,
read [Name Resolution](@ref name-resolution-manual).

## Standard I/O Still Applies

One nice migration property is that the connection still behaves like a Julia
stream:

- `read!(conn, buf)`
- `write(conn, buf)`
- `close(conn)`

The difference is in the transport semantics: deadlines and readiness are now
part of the connection itself, and partial reads/writes are documented
explicitly on the `TCP.Conn` and `TLS.Conn` APIs in [API Reference](@ref api-reference-manual).

## Deadlines Become First-Class

Instead of wrapping operations in ad hoc timeout tasks, set deadlines directly
on the live connection:

```julia
using Reseau

conn = TCP.connect("example.com:443")
TCP.set_read_deadline!(conn, time_ns() + 5_000_000_000)
close(conn)
```

This deadline model carries through to TLS as well.

## TLS Lives In The Same Stack

With `Sockets`, TLS is usually another package layered on top. With Reseau, TCP
and TLS are sibling surfaces in one transport stack:

```julia
using Reseau

tls = TLS.connect(
    "example.com:443";
    verify_peer = true,
    alpn_protocols = ["h2", "http/1.1"],
)

close(tls)
```

For servers:

```julia
using Reseau

cfg = TLS.Config(cert_file = "server.crt", key_file = "server.key")
listener = TLS.listen("tcp", "127.0.0.1:8443", cfg)
close(listener)
```

Read [TLS](@ref tls-manual) for handshake behavior, config options, and lifecycle details.

## One Naming Difference To Keep

Full teardown follows Base conventions: use `close(conn)` and `close(listener)`.

Half-close remains explicit:

- `closewrite(conn)`
- `TCP.closeread(conn)`

## Porting Checklist

1. Replace `Sockets.connect(host, port)` with `TCP.connect("host:port")` when you want hostname resolution.
2. Replace listen/accept loops with `TCP.listen(...)` and `TCP.accept(listener)`.
3. Replace timeout wrappers with `TCP.set_deadline!`, `TCP.set_read_deadline!`, or `TCP.set_write_deadline!`.
4. Move TLS setup onto `TLS.Config`, `TLS.connect`, `TLS.listen`, `TLS.client`, and `TLS.server`.
5. Update any code that expected `Sockets.TCPSocket` internals; Reseau exposes `TCP.Conn` and `TLS.Conn` instead.
