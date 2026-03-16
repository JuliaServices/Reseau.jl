```@meta
CollapsedDocStrings = true
Description = "Canonical API reference for Reseau.jl's TCP, TLS, and name-resolution surfaces."
```

# [API Reference](@id api-reference-manual)

This page is the canonical home for the package and module docstrings used
throughout the rest of the manual.

```@contents
Pages = ["reference.md"]
Depth = 2:2
```

## Package Modules

```@docs
Reseau
Reseau.TCP
Reseau.TLS
```

### Internal Layers

These modules are not the primary end-user entrypoints, but they explain the
package layering and are part of the documented rewrite architecture:

```@docs
Reseau.EventLoops
Reseau.SocketOps
Reseau.IOPoll
Reseau.IOPoll.PollOp
Reseau.HostResolvers
```

## TCP

```@meta
CurrentModule = Reseau.TCP
```

### Address Types and Constructors

```@docs
SocketAddr
SocketAddrV4
SocketAddrV6
loopback_addr
any_addr
loopback_addr6
any_addr6
```

### Connections and I/O

```@docs
Conn
Listener
connect
listen
accept
Base.read!(::Conn, ::Vector{UInt8})
Base.write(::Conn, ::AbstractVector{UInt8})
Base.close(::Conn)
Base.close(::Listener)
closeread
Base.closewrite(::Conn)
```

### Deadlines, Socket Options, and Address Inspection

```@docs
set_deadline!
set_read_deadline!
set_write_deadline!
set_nodelay!
set_keepalive!
local_addr
remote_addr
addr
```

## Name Resolution

```@meta
CurrentModule = Reseau.HostResolvers
```

### Policy and Resolver Types

```@docs
ResolverPolicy
SystemResolver
SingleflightResolver
CachingResolver
StaticResolver
HostResolver
```

### Explicit Resolution Helpers

```@docs
resolve_tcp_addrs
resolve_tcp_addr
```

## TLS

```@meta
CurrentModule = Reseau.TLS
```

### Configuration, State, and Errors

```@docs
Config
ConnectionState
Conn
Listener
ConfigError
TLSError
TLSHandshakeTimeoutError
```

### Client and Server Construction

```@docs
client
server
connect
listen
accept
handshake!
```

### I/O, Lifecycle, Deadlines, and Inspection

```@docs
Base.read!(::Conn, ::Vector{UInt8})
Base.write(::Conn, ::AbstractVector{UInt8})
Base.close(::Conn)
Base.close(::Listener)
Base.closewrite(::Conn)
set_deadline!
set_read_deadline!
set_write_deadline!
local_addr
remote_addr
net_conn
connection_state
addr
```

## Docstring Index

```@meta
CurrentModule = Main
```

```@index
Pages = ["reference.md"]
Modules = [Reseau, Reseau.TCP, Reseau.HostResolvers, Reseau.TLS]
Order = [:module, :type, :function]
```
