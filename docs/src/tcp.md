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
Base.readbytes!(::Conn, ::Vector{UInt8}, ::Integer)
Base.readavailable(::Conn)
Base.eof(::Conn)
Base.isopen(::Conn)
Base.isopen(::Listener)
Base.write(::Conn, ::AbstractVector{UInt8})
Base.close(::Conn)
Base.close(::Listener)
closeread
Base.closewrite(::Conn)
```

The key contract is:

- `read!(conn, buf)` fills `buf` or throws `EOFError`, just like other Julia `IO` types.
- `readbytes!(conn, buf, nb)` and `readavailable(conn)` are the count-returning entrypoints when you want short-read behavior.
- `write(conn, buf)` writes the full payload unless an error or deadline interrupts the operation.
- `close(conn)` and `close(listener)` are idempotent, which keeps cleanup paths safe in `finally` blocks.
- `isopen(conn)` and `isopen(listener)` report whether the underlying socket is still live.

## Closing Connections and Listeners

Close the objects your application owns. Calling `close(listener)` from another
task wakes a pending `accept`; `close(conn)` wakes pending connection I/O,
including reads with an active deadline. Catch [`TCP.NetClosingError`](@ref)
in these tasks when local closure is expected. Do not treat unrelated errors as
normal shutdown. Peer EOF and deadline expiry are separate conditions.

```@docs; canonical=false
NetClosingError
```

Socket closure stops pending I/O; it does not finish application requests.
If requests must drain, stop accepting first and let their handlers finish
before closing their connections. Set an application policy for handlers that
do not finish. Close only your application's objects, rather than stopping the
shared internal poller or resolver runtime.

Stop and join your accept task before taking the final snapshot of accepted
connections to close. Otherwise a connection accepted during shutdown can
escape cleanup. Synchronize connection tracking if handlers also modify it,
and close each handler's connection in `finally`.

For HTTP servers, use the server's own lifecycle API instead of tracking its
transport objects: `close(server)` drains active work, while
`HTTP.forceclose(server)` closes tracked connections immediately. Servo's
`serve!` and `run!` return an HTTP server handle that uses the same lifecycle.

`TCP.NetClosingError` identifies local closure; it does not configure process
signal handling or guarantee delivery of `InterruptException`. See the
[signal-handling discussion](https://github.com/JuliaServices/Reseau.jl/issues/126)
for application-level SIGINT considerations and Julia runtime limitations.

## Deadlines, Socket Options, and Address Inspection

Deadline management lives on the live connection, not in helper tasks or
external timeout wrappers:

```@docs; canonical=false
set_deadline!
set_read_deadline!
set_write_deadline!
DeadlineExceededError
set_nodelay!
set_keepalive!
local_addr
remote_addr
addr
```

Use absolute monotonic nanoseconds from `time_ns()` for deadline APIs. Setting
a deadline to `0` clears it, while setting it to a time in the past makes the
next blocking wait time out immediately.

Deadline expiry is surfaced as [`TCP.DeadlineExceededError`](@ref). Catch that
alias instead of reaching into `Reseau.IOPoll` directly:

```julia
try
    TCP.set_read_deadline!(conn, time_ns() + 100_000_000)
    read!(conn, buf)
catch err
    if err isa TCP.DeadlineExceededError
        TCP.set_read_deadline!(conn, 0) # clear or move the deadline before retrying
    else
        rethrow()
    end
end
```

Listeners use the same `set_deadline!` name for `accept` deadlines. That
deadline applies only to `accept(listener)`; established connections still use
their own per-connection deadline state. `local_addr(listener)` is also
available as a discoverable alias for `addr(listener)`.

## Where To Go Next

- Read [TLS](@ref tls-manual) for the TLS wrapper layer that reuses the same transport and deadline model.
- Read [Name Resolution](@ref name-resolution-manual) for the advanced resolver controls that sit behind string-address dialing.
- Read [API Reference](@ref api-reference-manual) for the canonical docstrings for the entire TCP surface.
