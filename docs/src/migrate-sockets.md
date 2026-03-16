# Migrating from `Sockets` to Reseau

If you are using Julia's stdlib `Sockets`, the easiest mental model is:

- keep `connect`, `listen`, `accept`, and `close`
- move plain TCP work onto `TCP`
- move TLS work onto `TLS`
- replace ad hoc timeout wrappers with connection deadlines

## Quick Mapping

| `Sockets` | Reseau |
| --- | --- |
| `listen(ip"127.0.0.1", port)` | `TCP.listen(TCP.loopback_addr(port))` |
| `connect(ip"127.0.0.1", port)` | `TCP.connect(TCP.loopback_addr(port))` |
| `connect("example.com", port)` | `TCP.connect("example.com:$port")` |
| `accept(server)` | `TCP.accept(listener)` |
| `close(sock)` | `close(conn)` / `close(listener)` |
| `getsockname(sock)` | `TCP.local_addr(conn)` |
| `getpeername(sock)` | `TCP.remote_addr(conn)` |
| external TLS wrapper | `TLS.connect`, `TLS.listen`, `TLS.client`, `TLS.server` |

## 1. Simple TCP Server

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

## 2. Hostname-Based Client Dial

### `Sockets`

```julia
using Sockets

sock = connect("example.com", 443)
close(sock)
```

### `Reseau`

```julia
using Reseau

conn = TCP.connect("example.com:443")
close(conn)
```

## Deadlines Are First-Class

One of the biggest quality-of-life improvements over `Sockets` is that the
deadline lives on the connection itself:

```julia
using Reseau

conn = TCP.connect("example.com:443")
TCP.set_read_deadline!(conn, time_ns() + 5_000_000_000)
close(conn)
```

Instead of managing task-local timeout wrappers around blocking socket calls,
the transport itself owns the timeout.

## TLS Lives in the Same Package

With `Sockets`, TLS usually means adding another layer elsewhere. With Reseau,
plain TCP and TLS share one stack:

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

## One Naming Difference To Know

Full connection teardown now matches Base: use `close(conn)` and
`close(listener)`.

Half-close is still spelled with explicit transport helpers:

- `closewrite(conn)`
- `TCP.closeread(conn)`

## What To Change In Real Code

1. Replace `Sockets.connect(host, port)` with `TCP.connect("host:port")` when you want hostname resolution.
2. Replace listen/accept loops with `TCP.listen(...)` and `TCP.accept(listener)`.
3. Replace timeout wrappers with `TCP.set_deadline!`, `TCP.set_read_deadline!`, or `TCP.set_write_deadline!`.
4. Move TLS setup onto `TLS.Config`, `TLS.connect`, and `TLS.listen`.
5. Update any code that expected `Sockets.TCPSocket` internals; Reseau uses `TCP.Conn` and `TLS.Conn`.

## Benefits Of Porting

- Better deadline and readiness behavior
- One TCP surface for both concrete addresses and `"host:port"` dialing
- TLS integrated into the same transport stack
- Clearer listener/connection types than raw `Sockets` handles
