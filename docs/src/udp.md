```@meta
CurrentModule = Reseau
Description = "UDP datagram sockets in Reseau.jl: connected and unconnected use, deadlines, and truncation policy."
```

# [UDP](@id udp-manual)

`Reseau.UDP` provides datagram sockets with the same readiness, deadline, and
close machinery as [`Reseau.TCP`](@ref), mirroring Go's `net.UDPConn`: one
[`UDP.Conn`](@ref UDP.Conn) type serves both unconnected and connected use.

```@contents
Pages = ["udp.md"]
Depth = 2:3
```

## Unconnected sockets

[`UDP.listen`](@ref UDP.listen) binds a socket that can exchange datagrams
with any peer:

```julia
using Reseau

a = UDP.listen(UDP.loopback_addr(0))
b = UDP.listen(UDP.loopback_addr(0))

UDP.sendto(a, "ping", UDP.local_addr(b))
data, from = UDP.recvfrom(b)
UDP.sendto(b, "pong", from)

close(a); close(b)
```

Despite the name, no `listen(2)` syscall is involved; the name matches Go's
`ListenUDP` and marks the socket as the passive, bound side.

## Connected sockets

[`UDP.connect`](@ref UDP.connect) fixes a peer. Connecting a UDP socket is a
local operation — no packets are exchanged — but the kernel then filters
inbound datagrams to that peer and surfaces ICMP errors (such as
`ECONNREFUSED`) on later operations:

```julia
using Reseau

server = UDP.listen(UDP.loopback_addr(0))
client = UDP.connect(UDP.local_addr(server))

UDP.send(client, "hello")
data, from = UDP.recvfrom(server)
UDP.sendto(server, "reply", from)
reply = UDP.recv(client)

close(client); close(server)
```

`send` requires a connected socket and `sendto` an unconnected one (Go's
`ErrWriteToConnected` semantics); the `recv` family works on both.

## Datagram semantics

- A datagram is sent and received whole. There are no partial transfers.
- A zero-byte datagram is valid data, never EOF. `UDP.Conn` has no EOF
  concept at all and is deliberately **not** an `IO` — stream helpers like
  `readline` would corrupt message boundaries.
- Sends larger than the UDP maximum payload (65,507 bytes) fail with the
  kernel's `EMSGSIZE` and leave the socket usable.

### Truncation

If an incoming datagram is longer than the receive buffer, the kernel
delivers a prefix and discards the rest. Reseau makes this explicit and
uniform across platforms: with the default `allow_truncate=false`,
[`UDP.recv!`](@ref UDP.recv!) and [`UDP.recvfrom!`](@ref UDP.recvfrom!) throw
[`UDP.TruncatedDatagramError`](@ref UDP.TruncatedDatagramError); with
`allow_truncate=true` the truncated prefix is returned silently (Go
semantics). The allocating [`UDP.recv`](@ref UDP.recv) and
[`UDP.recvfrom`](@ref UDP.recvfrom) default to a `maxsize` that holds any
datagram, so they never truncate unless a smaller `maxsize` is requested.

## Socket options and dual-stack behavior

Broadcast (`SO_BROADCAST`) is **enabled by default** on every UDP socket,
matching Go's `setDefaultSockopts`; disable it with
`UDP.set_broadcast!(conn, false)`. Kernel buffer sizes are set with
`UDP.set_read_buffer!`/`UDP.set_write_buffer!` (datagrams that arrive while
the receive buffer is full are dropped), and `UDP.set_ttl!` sets the IPv4 TTL
or IPv6 hop limit.

AF_INET6 sockets are dual-stack by default (except with the `"udp6"` network
name), and addresses convert the way Go's `ipToSockaddr` converts them: an
IPv4 destination on an IPv6 socket is carried as an IPv4-mapped IPv6 address,
an IPv4-mapped destination on an IPv4 socket collapses to plain IPv4, and
`connect` picks `AF_INET` only when every given address is IPv4 (Go's
`favoriteAddrFamily`). A wildcard dial destination means "this host": the
kernel interprets it directly where supported, and Reseau rewrites it to the
loopback address on Windows, FreeBSD, and OpenBSD exactly as Go's
`internetSocket` does.

## Deadlines

The deadline model is identical to TCP: absolute monotonic timestamps on the
`time_ns()` clock, sticky per socket, surfaced as
[`UDP.DeadlineExceededError`](@ref UDP.DeadlineExceededError).

```julia
conn = UDP.listen(UDP.loopback_addr(0))
UDP.set_read_deadline!(conn, time_ns() + 5_000_000_000)
```

## String addresses

The resolver-backed entrypoints accept `"host:port"` strings and the network
names `"udp"`, `"udp4"`, and `"udp6"` (`"udp6"` binds IPv6-only). There is no
Happy-Eyeballs race and no dial timeout: connecting a UDP socket is
immediate, so only name resolution can block. Failures are wrapped in
`HostResolvers.OpError` like TCP dialing.

```julia
conn = UDP.connect("localhost:9000")
wild = UDP.listen(":9000")
four = UDP.listen("udp4", "127.0.0.1:9000")
```

## Not yet implemented

Multicast group management (`join_multicast_group`-style APIs), control-message
(`recvmsg` ancillary data) access, and batched datagram I/O are planned
follow-ups; the socket-ops layer already carries most of the required
plumbing.
