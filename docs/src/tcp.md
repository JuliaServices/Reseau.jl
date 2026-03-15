# TCP and Resolution

Reseau splits TCP work into two layers:

- `Reseau.TCP` for concrete socket addresses
- `Reseau.HostResolvers` for string-address parsing, host resolution, and
  timeout-aware dialing

## `Reseau.TCP`

Use `Reseau.TCP` when you already know the exact address family and endpoint you
want.

### Address Types

- `Reseau.TCP.SocketAddrV4`
- `Reseau.TCP.SocketAddrV6`
- `Reseau.TCP.loopback_addr`
- `Reseau.TCP.any_addr`
- `Reseau.TCP.loopback_addr6`
- `Reseau.TCP.any_addr6`

### Connections and Listeners

```julia
using Reseau

addr = Reseau.TCP.loopback_addr(9000)
listener = Reseau.TCP.listen(addr; backlog=128, reuseaddr=true)
conn = Reseau.TCP.accept!(listener)
```

Client connections are just as direct:

```julia
using Reseau

conn = Reseau.TCP.connect(Reseau.TCP.loopback_addr(9000))
write(conn, collect(codeunits("hello")))
buf = Vector{UInt8}(undef, 5)
read!(conn, buf)
```

### Deadlines and Shutdown

These are important differences from `Sockets`:

- `Reseau.TCP.set_deadline!(conn, deadline_ns)`
- `Reseau.TCP.set_read_deadline!(conn, deadline_ns)`
- `Reseau.TCP.set_write_deadline!(conn, deadline_ns)`
- `Reseau.TCP.close_read!(conn)`
- `Reseau.TCP.close_write!(conn)`

### Address Inspection

- `Reseau.TCP.local_addr(conn)`
- `Reseau.TCP.remote_addr(conn)`
- `Reseau.TCP.addr(listener)`

## `Reseau.HostResolvers`

Use `HostResolvers` when you want the package to handle host parsing and
resolution for you.

### Common Entry Points

- `Reseau.HostResolvers.connect("tcp", "example.com:443")`
- `Reseau.HostResolvers.connect("example.com:443")`
- `Reseau.HostResolvers.listen("tcp", "127.0.0.1:9000")`
- `Reseau.HostResolvers.resolve_tcp_addr`
- `Reseau.HostResolvers.resolve_tcp_addrs`
- `Reseau.HostResolvers.lookup_port`
- `Reseau.HostResolvers.join_host_port`
- `Reseau.HostResolvers.split_host_port`

### Example

```julia
using Reseau

listener = Reseau.HostResolvers.listen("tcp", "127.0.0.1:9000")
conn = Reseau.HostResolvers.connect("tcp", "127.0.0.1:9000")
peer = Reseau.TCP.accept!(listener)
```

### Resolution Policies

`HostResolvers` also owns the higher-level resolution helpers:

- `ResolverPolicy`
- `SystemResolver`
- `StaticResolver`
- `CachingResolver`
- `SingleflightResolver`
- `HostResolver`

These are the right tools when you want to tune IPv4/IPv6 preference,
cache lookups, or control resolution behavior explicitly.
