# API Reference

Reseau keeps its public surface module-qualified. That is intentional: it makes
the layer boundaries obvious.

## `Reseau.TCP`

### Address constructors

- `Reseau.TCP.SocketAddrV4`
- `Reseau.TCP.SocketAddrV6`
- `Reseau.TCP.loopback_addr`
- `Reseau.TCP.any_addr`
- `Reseau.TCP.loopback_addr6`
- `Reseau.TCP.any_addr6`

### Connections and listeners

- `Reseau.TCP.connect`
- `Reseau.TCP.listen`
- `Reseau.TCP.accept!`
- `Reseau.TCP.close!`
- `Reseau.TCP.close_read!`
- `Reseau.TCP.close_write!`

### Deadlines and socket options

- `Reseau.TCP.set_deadline!`
- `Reseau.TCP.set_read_deadline!`
- `Reseau.TCP.set_write_deadline!`
- `Reseau.TCP.set_nodelay!`
- `Reseau.TCP.set_keepalive!`

### Address inspection

- `Reseau.TCP.local_addr`
- `Reseau.TCP.remote_addr`
- `Reseau.TCP.addr`

## `Reseau.HostResolvers`

### Address parsing and lookup

- `Reseau.HostResolvers.join_host_port`
- `Reseau.HostResolvers.split_host_port`
- `Reseau.HostResolvers.parse_port`
- `Reseau.HostResolvers.lookup_port`
- `Reseau.HostResolvers.resolve_tcp_addr`
- `Reseau.HostResolvers.resolve_tcp_addrs`

### Dial/listen helpers

- `Reseau.HostResolvers.connect`
- `Reseau.HostResolvers.listen`
- `Reseau.HostResolvers.HostResolver`

### Resolver helpers

- `Reseau.HostResolvers.ResolverPolicy`
- `Reseau.HostResolvers.SystemResolver`
- `Reseau.HostResolvers.StaticResolver`
- `Reseau.HostResolvers.CachingResolver`
- `Reseau.HostResolvers.SingleflightResolver`

## `Reseau.TLS`

### Main types

- `Reseau.TLS.Config`
- `Reseau.TLS.Conn`
- `Reseau.TLS.Listener`
- `Reseau.TLS.ClientAuthMode`

### Client and server setup

- `Reseau.TLS.connect`
- `Reseau.TLS.listen`
- `Reseau.TLS.client`
- `Reseau.TLS.server`
- `Reseau.TLS.accept!`
- `Reseau.TLS.handshake!`

### Lifecycle and inspection

- `Reseau.TLS.close!`
- `Reseau.TLS.addr`

### Errors

- `Reseau.TLS.ConfigError`
- `Reseau.TLS.TLSError`
- `Reseau.TLS.TLSHandshakeTimeoutError`

## Package Boundary Note

HTTP-related APIs are intentionally no longer part of Reseau. Use HTTP.jl for:

- request/response handling
- HTTP clients and servers
- WebSockets
- HPACK and HTTP/2
