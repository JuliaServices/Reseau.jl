# Reseau.jl

`Reseau.jl` is a pure-Julia networking transport stack with deadline-aware TCP,
hostname-aware dialing, and TLS in one package.

[![](https://img.shields.io/badge/docs-stable-blue.svg)](https://juliaservices.github.io/Reseau.jl/stable)
[![](https://img.shields.io/badge/docs-dev-blue.svg)](https://juliaservices.github.io/Reseau.jl/dev)

Reseau provides:

- TCP connections and listeners
- hostname-aware dialing and listening through the `TCP` and `TLS` entrypoints
- TLS clients and listeners
- integrated readiness, deadline, and timer handling across macOS, Linux, and Windows
- precompile and `--trim=safe` validation in the test suite

## Installation

```julia
using Pkg
Pkg.add("Reseau")
```

## Main Entry Points

The supported 1.0-facing entry points are the exported `TCP` and `TLS` modules:

- `TCP` for TCP connections, listeners, deadlines, and string-address dialing
- `TLS` for TLS clients and listeners

## Quick Start

### TCP

```julia
using Reseau

listener = TCP.listen(TCP.loopback_addr(0); backlog = 128)
addr = TCP.addr(listener)

server_task = errormonitor(@async begin
    conn = TCP.accept(listener)
    try
        write(conn, "echo:" * String(read(conn)))
    finally
        close(conn)
    end
end)

client = TCP.connect(addr)
write(client, "hello")
closewrite(client)
reply = String(read(client))

close(client)
close(listener)
wait(server_task)

reply == "echo:hello"
```

### String-address dialing

```julia
using Reseau

conn = TCP.connect("example.com:80")
close(conn)

listener = TCP.listen("127.0.0.1:0"; backlog = 64)
println(TCP.addr(listener))
close(listener)
```

The hostname/address-string behavior is available directly on `TCP.connect`,
`TCP.listen`, and `TLS.connect`; most code never needs to reach into the
resolver support layer directly.

You can also set deadlines directly on live connections:

```julia
using Reseau

conn = TCP.connect("example.com:80")
TCP.set_read_deadline!(conn, time_ns() + 5_000_000_000)
close(conn)
```

### TLS client

```julia
using Reseau

conn = TLS.connect(
    "www.google.com:443";
    alpn_protocols = ["h2", "http/1.1"],
)

state = TLS.connection_state(conn)
println((state.handshake_complete, state.alpn_protocol))
close(conn)
```

By default, outbound TLS verification uses `NetworkOptions.ca_roots_path()` when
`ca_file` is omitted.

### TLS listener

```julia
using Reseau

config = TLS.Config(
    cert_file = "server.crt",
    key_file = "server.key",
)

listener = TLS.listen("tcp", "127.0.0.1:8443", config)
conn = TLS.accept(listener)

close(conn)
close(listener)
```

For verified client-certificate auth, provide `client_ca_file` explicitly:

```julia
using Reseau

config = TLS.Config(
    cert_file = "server.crt",
    key_file = "server.key",
    client_auth = TLS.ClientAuthMode.RequireAndVerifyClientCert,
    client_ca_file = "client-ca.pem",
)
```

## Why Use Reseau

- Deadlines and readiness behavior are first-class instead of layered on later.
- Concrete-address and hostname-based dialing both work through the same `TCP`
  and `TLS` entrypoints.
- TLS lives in the same transport stack instead of hanging off a different socket
  abstraction.

## Internal Architecture

`TCP` and `TLS` are the intended public surfaces. Reseau also contains internal
support layers such as `Reseau.SocketOps`, `Reseau.IOPoll`, and
`Reseau.HostResolvers` that power the transport stack but are not the primary
1.0 API entrypoints.

## Documentation

- [Stable docs](https://juliaservices.github.io/Reseau.jl/stable)
- [Dev docs](https://juliaservices.github.io/Reseau.jl/dev)
- [TCP](https://juliaservices.github.io/Reseau.jl/stable/tcp/)
- [TLS](https://juliaservices.github.io/Reseau.jl/stable/tls/)
- [Name Resolution](https://juliaservices.github.io/Reseau.jl/stable/resolution/)
- [Sockets Migration Guide](https://juliaservices.github.io/Reseau.jl/stable/migrate-sockets/)
- [API Reference](https://juliaservices.github.io/Reseau.jl/stable/reference/)

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
