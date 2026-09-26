```@meta
CurrentModule = Reseau.Unix
Description = "Connect to local filesystem Unix sockets with Reseau's stream IO and deadlines."
```

# [Unix Socket Clients](@id unix-manual)

Use `Reseau.Unix.connect` when a local service listens on a filesystem socket,
such as `/tmp/service.sock`. This client transport is available on Linux,
macOS and FreeBSD. It uses the same polling, stream IO and deadline behavior as
TCP. Call it through the package namespace; `Unix` is not exported.

With the service already listening:

```julia
using Reseau

conn = Reseau.Unix.connect("/tmp/service.sock"; timeout_ns = 5_000_000_000)
try
    write(conn, "request\n")
    Reseau.Unix.set_read_deadline!(conn, time_ns() + 5_000_000_000)
    reply = readline(conn)
finally
    close(conn)
end
```

`read!` fills the requested buffer or throws `EOFError`. By default,
`readbytes!(conn, buf, nb)` waits for `nb` bytes or EOF. With `all=false`, it
stops after one socket read, which can return fewer bytes. `readavailable`
also permits a short read. Both can wait for input; `Reseau.Unix.tryread!`
returns `nothing` immediately if no bytes are ready. Writes send the complete payload
unless a deadline, close or transport error interrupts them. Byte vectors and
mutable views follow the same rules as [TCP stream IO](@ref tcp-manual).

## Paths and errors

Paths are used as supplied. Relative paths are relative to the current working
directory, and a leading `@` is an ordinary filename. The path must be nonempty,
contain no NUL, and fit in 107 bytes on Linux or 103 bytes on macOS and FreeBSD.
These are byte limits for the complete path, so a non-ASCII name can use more
than one byte per character.

Invalid paths raise `ArgumentError` before a socket is opened. A missing file,
refused connection, or other OS failure raises `SystemError` with the native
error code. Unsupported platforms raise `ArgumentError` before opening a
descriptor.

This API connects to filesystem stream sockets. It does not provide a listener,
Linux abstract socket names, datagrams, descriptor passing or Windows named
pipes. TLS wrappers continue to accept TCP connections.

## Deadlines and ownership

`timeout_ns` limits the connect operation relative to its start. `deadline_ns`
is an absolute timestamp on the `time_ns()` clock. Zero disables each limit;
when both are supplied, the earlier deadline applies. A successful connect
clears its temporary deadline. Set subsequent read/write limits with
`Reseau.Unix.set_read_deadline!`, `set_write_deadline!`, or `set_deadline!`.
Clear a limit by setting it to zero. An expired limit raises
[`DeadlineExceededError`](@ref).

`close(conn)` wakes pending operations, closes the owned descriptor and can be
called repeatedly. It never deletes the server's socket file. A task interrupted
by local close receives [`NetClosingError`](@ref).
`closewrite(conn)` and `Reseau.Unix.closeread(conn)` shut down one direction.

`Reseau.Unix.rawfd(conn)` returns a borrowed descriptor for native interoperation.
Keep the connection reachable and prevent concurrent close while using it. Do
not close that descriptor yourself or change its nonblocking flags.

```@docs; canonical=false
Conn
connect
```
