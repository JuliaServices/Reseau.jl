```@meta
CollapsedDocStrings = true
Description = "Canonical API reference for Reseau.jl's public TCP and TLS surfaces."
```

# [API Reference](@id api-reference-manual)

This page is the canonical home for Reseau's public package, TCP, and TLS
docstrings.

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
Base.readbytes!(::Conn, ::Vector{UInt8}, ::Integer)
Base.readavailable(::Conn)
Base.eof(::Conn)
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
Base.readbytes!(::Conn, ::Vector{UInt8}, ::Integer)
Base.readavailable(::Conn)
Base.eof(::Conn)
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

## Internal Support Layers

These modules power the public transport surface and are documented here for
completeness, but they are not the primary 1.0 entrypoints.

```@meta
CurrentModule = Main
```

```@docs
Reseau.SocketOps
Reseau.IOPoll
Reseau.IOPoll.PollMode
Reseau.HostResolvers
```

## Docstring Index

```@meta
CurrentModule = Main
```

```@index
Pages = ["reference.md"]
Modules = [Reseau, Reseau.TCP, Reseau.TLS]
Order = [:module, :type, :function]
```
