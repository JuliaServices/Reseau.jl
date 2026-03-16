```@meta
CurrentModule = Reseau.TCP
Description = "TCP connections, listeners, deadlines, socket options, and address helpers in Reseau.jl."
```

# [TCP](@id tcp-manual)

`TCP` is the plain-transport entrypoint in Reseau. The same [`connect`](@ref)
and [`listen`](@ref) surface supports both concrete socket addresses and
hostname-based string addresses. Read [Name Resolution](@ref name-resolution-manual) for the resolver
and policy objects behind the string-address overloads.

```@contents
Pages = ["tcp.md"]
Depth = 2:3
```

## Address Model

Use concrete addresses when you already know the exact family and endpoint you
want to target. Reseau exposes both IPv4 and IPv6 address snapshots:

```@docs; canonical=false
SocketAddr
SocketAddrV4
SocketAddrV6
loopback_addr
any_addr
loopback_addr6
any_addr6
```

Concrete addresses are especially useful when you want to bind explicitly to a
family or pass a preselected local address to outbound dialing.

## Connections and Listeners

The core connection surface is small and intentionally transport-focused:

```@docs; canonical=false
Conn
Listener
connect
listen
accept
```

For `"host:port"` dialing, the string-address overloads accept:

- `timeout_ns`
- `deadline_ns`
- `local_addr`
- `fallback_delay_ns`
- `resolver`
- `policy`

Those knobs feed the resolver layer described in [Name Resolution](@ref name-resolution-manual), while
the actual socket lifecycle still lands in the same `TCP.Conn` and
`TCP.Listener` types.

## Stream I/O and Lifecycle

`TCP.Conn` follows Julia's standard stream conventions for `read!`, `write`,
and `close`, while still exposing explicit half-close helpers when you need
them:

```@docs; canonical=false
Base.read!(::Conn, ::Vector{UInt8})
Base.write(::Conn, ::AbstractVector{UInt8})
Base.close(::Conn)
Base.close(::Listener)
closeread
Base.closewrite(::Conn)
```

The important behavioral detail is that partial reads and writes are normal:
reads return as soon as at least one byte is available, and writes retry
through readiness waits until the requested payload has been written or an
error/deadline interrupts the operation.

## Deadlines, Socket Options, and Address Inspection

Deadline management lives on the live connection, not in helper tasks or
external timeout wrappers:

```@docs; canonical=false
set_deadline!
set_read_deadline!
set_write_deadline!
set_nodelay!
set_keepalive!
local_addr
remote_addr
addr
```

Use absolute monotonic nanoseconds from `time_ns()` for deadline APIs. Setting
a deadline to `0` clears it, while setting it to a time in the past makes the
next blocking wait time out immediately.

## Where To Go Next

- Read [TLS](@ref tls-manual) for the TLS wrapper layer that reuses the same transport and deadline model.
- Read [Name Resolution](@ref name-resolution-manual) for `ResolverPolicy`, `HostResolver`, and explicit resolution helpers.
- Read [API Reference](@ref api-reference-manual) for the canonical docstrings for the entire TCP surface.
