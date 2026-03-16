# TCP

`TCP` is the main plain-transport entrypoint in Reseau. The same `TCP.connect`
and `TCP.listen` surface supports both concrete socket addresses and
hostname-based string addresses.

## Address Constructors

Use concrete addresses when you already know the exact family and endpoint you
want:

- `TCP.SocketAddrV4`
- `TCP.SocketAddrV6`
- `TCP.loopback_addr`
- `TCP.any_addr`
- `TCP.loopback_addr6`
- `TCP.any_addr6`

```julia
using Reseau

addr = TCP.loopback_addr(9000)
listener = TCP.listen(addr; backlog = 128, reuseaddr = true)
conn = TCP.accept(listener)

close(conn)
close(listener)
```

## String-Address Dialing and Listening

If you prefer the `Sockets`-style `"host:port"` surface, use the same
`TCP.connect` and `TCP.listen` entrypoints directly:

```julia
using Reseau

conn = TCP.connect("example.com:443")
close(conn)

listener = TCP.listen("127.0.0.1:9000"; backlog = 64)
close(listener)
```

If you need to tune connect behavior, the string-address overloads accept:

- `timeout_ns`
- `deadline_ns`
- `local_addr`
- `fallback_delay_ns`
- `resolver`
- `policy`

```julia
using Reseau

conn = TCP.connect(
    "example.com:443";
    timeout_ns = 2_000_000_000,
    fallback_delay_ns = 100_000_000,
)

close(conn)
```

## Deadlines and Shutdown

Deadlines live on the connection itself:

- `TCP.set_deadline!(conn, deadline_ns)`
- `TCP.set_read_deadline!(conn, deadline_ns)`
- `TCP.set_write_deadline!(conn, deadline_ns)`

Full close uses Julia's standard `close(conn)` / `close(listener)` surface.

Half-close remains explicit today:

- `closewrite(conn)`
- `TCP.closeread(conn)`

```julia
using Reseau

conn = TCP.connect("example.com:80")
TCP.set_read_deadline!(conn, time_ns() + 5_000_000_000)
close(conn)
```

## Address Inspection

Use these helpers to inspect the bound or connected endpoints:

- `TCP.local_addr(conn)`
- `TCP.remote_addr(conn)`
- `TCP.addr(listener)`
