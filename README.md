# Reseau.jl

`Reseau.jl` is a pure-Julia networking stack organized in roughly the same layers as Go's `net`, `crypto/tls`, and `net/http` implementations.

Today the package includes:
- cross-platform event-loop backends for macOS (`kqueue`), Linux (`epoll`), and Windows (`IOCP`)
- low-level socket operations and internal poll/runtime plumbing
- TCP connections and listeners
- host resolution + dialing/listening helpers
- TLS client/server support
- HTTP/1.1 and HTTP/2 client/server support
- precompile and `--trim=safe` compile workloads in the test suite

The public API is intentionally layered. Most users will spend their time in:
- `Reseau.TCP`
- `Reseau.HostResolvers`
- `Reseau.TLS`
- `Reseau.HTTP`

## Installation

```julia
using Pkg
Pkg.add("Reseau")
```

For development:

```julia
julia --project=. -e 'using Pkg; Pkg.instantiate()'
julia --project=. -e 'using Pkg; Pkg.test()'
```

## Package Layout

- `Reseau.EventLoops`: platform event-loop backends (`kqueue` / `epoll` / `IOCP`)
- `Reseau.SocketOps`: raw socket syscalls, sockaddr helpers, and platform quirks
- `Reseau.IOPoll`: internal poll-descriptor and deadline layer
- `Reseau.TCP`: TCP endpoints, `Conn`, `Listener`, deadlines, close semantics
- `Reseau.HostResolvers`: `host:port` parsing, `getaddrinfo`, Happy Eyeballs-style connect orchestration
- `Reseau.TLS`: TLS connections/listeners built on top of `TCP`
- `Reseau.HTTP`: HTTP core types, HTTP/1.1, HPACK, HTTP/2, high-level client/server APIs

## Quick Start

### TCP

```julia
using Reseau
const TCP = Reseau.TCP

listener = TCP.listen(TCP.loopback_addr(0); backlog = 128)
addr = TCP.addr(listener)

server_task = errormonitor(Threads.@spawn begin
    conn = TCP.accept!(listener)
    buf = Vector{UInt8}(undef, 5)
    read!(conn, buf)
    write(conn, buf)
    TCP.close!(conn)
end)

client = TCP.connect(addr)
write(client, collect(codeunits("hello")))
reply = Vector{UInt8}(undef, 5)
read!(client, reply)

TCP.close!(client)
TCP.close!(listener)
wait(server_task)
```

### Host Resolution + Connect/Listen by Address String

```julia
using Reseau
const ND = Reseau.HostResolvers
const TCP = Reseau.TCP

conn = ND.connect("tcp", "example.com:80")
TCP.close!(conn)

listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 64)
println(TCP.addr(listener))
TCP.close!(listener)
```

If you want custom resolution behavior, timeouts, or a static resolver:

```julia
using Reseau
const ND = Reseau.HostResolvers

resolver = ND.HostResolver(; timeout_ns = 2_000_000_000)
conn = ND.connect(resolver, "tcp", "example.com:80")
Reseau.TCP.close!(conn)
```

### TLS

```julia
using Reseau
const TLS = Reseau.TLS

conn = TLS.connect("tcp", "www.google.com:443")
state = TLS.connection_state(conn)
println((state.handshake_complete, state.negotiated_protocol))
TLS.close!(conn)
```

Server-side TLS listeners are built on top of `TCP` listeners:

```julia
using Reseau
const TLS = Reseau.TLS

config = TLS.Config(
    cert_file = "server.crt",
    key_file = "server.key",
)
listener = TLS.listen("tcp", "127.0.0.1:8443", config)
conn = TLS.accept!(listener)
TLS.close!(conn)
TLS.close!(listener)
```

### HTTP Client

```julia
using Reseau
const HTTP = Reseau.HTTP

resp = HTTP.get("https://www.google.com")
println(resp.status)
println(length(resp.body))

resp = HTTP.post(
    "https://httpbin.org/post",
    ["Content-Type" => "application/json"],
    collect(codeunits("{\"hello\":true}"));
    status_exception = false,
)
println(resp.status)
```

You can also create a reusable client explicitly:

```julia
using Reseau
const HTTP = Reseau.HTTP

client = HTTP.Client(; prefer_http2 = true)
resp = HTTP.get("https://www.google.com"; client = client)
close(client)
```

### HTTP Server

```julia
using Reseau
const HTTP = Reseau.HTTP

server = HTTP.Server(; address = "127.0.0.1:8080", handler = req -> begin
    body = HTTP.BytesBody(collect(codeunits("hello from reseau")))
    return HTTP.Response(200; reason = "OK", body = body, content_length = 17)
end)

task = HTTP.start!(server)
println(HTTP.server_addr(server))

# ... run requests ...

HTTP.shutdown!(server)
wait(task)
```

## Notes on Lower Layers

`Reseau.EventLoops`, `Reseau.SocketOps`, and `Reseau.IOPoll` are real implementations, not stubs, and they are heavily tested. They exist primarily to support the higher-level TCP/TLS/HTTP stack, but they are also useful when you want to reason about readiness, deadlines, or platform-specific event-loop behavior.

## Testing and Benchmarks

Useful commands during development:

```julia
julia --project=. test/runtests.jl
julia --project=. benchmarks/benchmarks.jl
```

The test suite also exercises:
- precompile workloads
- `--trim=safe` compile workloads
- platform-specific event-loop/socket paths

## Windows Compiled-Binary Note

On Windows, fully compiled or `--trim=safe` executables should bundle dependent artifacts/JLLs so runtime libraries like OpenSSL are present next to the built executable.

In practice, that means preferring a bundled build flow such as JuliaC's `--bundle` mode for Windows executables. The repository's trim-compile tests exercise this path directly in [`test/trim_compile_tests.jl`](/Users/jacob.quinn/.julia/dev/Reseau/test/trim_compile_tests.jl).

## Status

Reseau is a serious rewrite with production-oriented goals:
- direct OS syscalls instead of libuv-mediated sockets
- Go-inspired layering and semantics
- broad test coverage, including trim-compile validation
- cross-platform event-loop backends for macOS, Linux, and Windows

The implementation is still evolving, but the intended direction is clear: a full networking stack in Julia with predictable semantics from raw sockets up through HTTP.
