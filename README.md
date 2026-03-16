# Reseau.jl

`Reseau.jl` is a pure-Julia networking transport stack organized in roughly the
same layers as Go's `runtime`, `internal/poll`, `net`, and `crypto/tls`
packages.

Reseau owns:

- cross-platform event-loop backends for macOS (`kqueue`), Linux (`epoll`),
  and Windows (`IOCP`)
- low-level socket operations and internal poll/runtime plumbing
- TCP connections and listeners
- host parsing, resolution, and timeout-aware dialing
- TLS clients and listeners
- precompile and `--trim=safe` validation in the test suite

HTTP.jl 2.0 is built on top of this transport stack. If you want HTTP clients,
servers, WebSockets, or HTTP/2, use HTTP.jl on top of Reseau.

## Installation

```julia
using Pkg
Pkg.add("Reseau")
```

## Main Entry Points

The public API is intentionally module-qualified:

- `Reseau.TCP` for concrete-address TCP work
- `Reseau.HostResolvers` for string-address resolution and dialing
- `Reseau.TLS` for TLS clients and listeners

## Quick Start

### Direct-address TCP

```julia
using Reseau

listener = Reseau.TCP.listen(Reseau.TCP.loopback_addr(0); backlog = 128)
addr = Reseau.TCP.addr(listener)

server_task = errormonitor(Threads.@spawn begin
    conn = Reseau.TCP.accept!(listener)
    try
        buf = Vector{UInt8}(undef, 5)
        read!(conn, buf)
        write(conn, buf)
    finally
        Reseau.TCP.close!(conn)
    end
end)

client = Reseau.TCP.connect(addr)
write(client, collect(codeunits("hello")))
reply = Vector{UInt8}(undef, 5)
read!(client, reply)

Reseau.TCP.close!(client)
Reseau.TCP.close!(listener)
wait(server_task)
```

### String-address dialing

```julia
using Reseau

conn = Reseau.HostResolvers.connect("tcp", "example.com:80")
Reseau.TCP.close!(conn)

listener = Reseau.HostResolvers.listen("tcp", "127.0.0.1:0"; backlog = 64)
println(Reseau.TCP.addr(listener))
Reseau.TCP.close!(listener)
```

You can also take control of timeout, deadline, and resolver policy explicitly:

```julia
using Reseau

resolver = Reseau.HostResolvers.HostResolver(
    timeout_ns = 2_000_000_000,
    fallback_delay_ns = 300_000_000,
)

conn = Reseau.HostResolvers.connect(resolver, "tcp", "example.com:80")
Reseau.TCP.close!(conn)
```

### TLS client

```julia
using Reseau

conn = Reseau.TLS.connect(
    "tcp",
    "www.google.com:443";
    alpn_protocols = ["h2", "http/1.1"],
)

state = Reseau.TLS.connection_state(conn)
println((state.handshake_complete, state.alpn_protocol))
Reseau.TLS.close!(conn)
```

By default, outbound TLS verification uses `NetworkOptions.ca_roots_path()` when
`ca_file` is omitted.

### TLS listener

```julia
using Reseau

config = Reseau.TLS.Config(
    cert_file = "server.crt",
    key_file = "server.key",
)

listener = Reseau.TLS.listen("tcp", "127.0.0.1:8443", config)
conn = Reseau.TLS.accept!(listener)

Reseau.TLS.close!(conn)
Reseau.TLS.close!(listener)
```

For verified client-certificate auth, provide `client_ca_file` explicitly:

```julia
using Reseau

config = Reseau.TLS.Config(
    cert_file = "server.crt",
    key_file = "server.key",
    client_auth = Reseau.TLS.ClientAuthMode.RequireAndVerifyClientCert,
    client_ca_file = "client-ca.pem",
)
```

## Why Use Reseau

- Deadlines and readiness behavior are first-class instead of layered on later.
- Concrete-address and string-address dialing are both supported cleanly.
- TLS lives in the same transport stack instead of hanging off a different socket
  abstraction.
- HTTP.jl 2.0 uses this exact transport layer, so networking semantics stay
  aligned across the stack.

## Package Layout

- `Reseau.EventLoops`: backend-specific pollers and timer scheduling
- `Reseau.SocketOps`: raw socket syscalls, sockaddr helpers, and platform quirks
- `Reseau.IOPoll`: internal poll-descriptor, deadline, and readiness machinery
- `Reseau.TCP`: TCP endpoints, listeners, deadlines, and lifecycle operations
- `Reseau.HostResolvers`: host/service parsing, resolution, and Happy
  Eyeballs-style dialing
- `Reseau.TLS`: TLS configuration, clients, listeners, and handshake behavior

## Documentation

- [TCP and Resolution](docs/src/tcp.md)
- [TLS](docs/src/tls.md)
- [Sockets Migration Guide](docs/src/migrate-sockets.md)
- [API Reference](docs/src/reference.md)

## Development

From a local checkout:

```sh
julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate()'
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false)'
```

The test suite also exercises:

- precompile workloads
- `--trim=safe` compile workloads
- platform-specific event-loop and socket paths

## Windows Compiled-Binary Note

On Windows, fully compiled or `--trim=safe` executables should bundle dependent
artifacts and JLLs so runtime libraries like OpenSSL are available next to the
built executable. The trim-compile tests in `test/trim_compile_tests.jl`
exercise that path directly.
