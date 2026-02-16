# Reseau.jl

Pure-Julia implementation of aws-c-io style primitives (macOS + Linux).
The API mirrors aws-c-io naming and behavior, but drops the `aws_` prefix.
Event loops, sockets, channels, TLS, host resolver, and async input streams
use direct OS syscalls and Julia-managed threads (no libuv).

GitHub Actions : [![Build Status](https://github.com/JuliaServices/Reseau.jl/workflows/CI/badge.svg)](https://github.com/JuliaServices/Reseau.jl/actions?query=workflow%3ACI+branch%3Amaster)

[![codecov.io](http://codecov.io/github/JuliaServices/Reseau.jl/coverage.svg?branch=master)](http://codecov.io/github/JuliaServices/Reseau.jl?branch=master)

## Installation

```julia
using Pkg
Pkg.add("Reseau")
```

## Usage

### Event loop group + resolver
```julia
using Reseau

elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
resolver = Reseau.HostResolver(elg)

Reseau.host_resolver_resolve!(resolver, "localhost") do addresses
    @show addresses
end
```

### Socket + channel (plain)
```julia
using Reseau

elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
el = Reseau.event_loop_group_get_next_loop(elg)
sock = Reseau.socket_init_posix(Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4))

Reseau.socket_connect(
    sock,
    Reseau.SocketEndpoint("127.0.0.1", 8080);
    event_loop = el,
    on_connection_result = (sock_obj, err, ud) -> @show err,
)
```

### TLS channel handler
```julia
using Reseau

# Assumes an established socket and event loop (see socket example).
channel = Reseau.Channel(el, nothing)
Reseau.socket_channel_handler_new!(channel, sock)

ctx = Reseau.tls_context_new_client(; verify_peer = false)
tls_opts = Reseau.TlsConnectionOptions(ctx; server_name = "localhost")
Reseau.tls_channel_handler_new!(channel, tls_opts)

Reseau.channel_setup_complete!(channel)
```

### Async input stream
```julia
using Reseau

data = Reseau.ByteBuffer(5)
stream = Reseau.AsyncInputStream((s, dest) -> begin
    fut = Reseau.Future{Bool}()
    dest.len += 5
    Reseau.future_complete!(fut, true)
    fut
end, s -> nothing, nothing)

future = Reseau.async_input_stream_read_to_fill(stream, data)
Reseau.future_wait(future)
```

## Threading model

Reseau runs event loops on OS threads (via `pthread_create` / `CreateThread`) and auto-adopts them into Julia.
There are no enforced `JULIA_NUM_THREADS` requirements; configure Julia threads based on your application needs.
Note: `Reseau.Threads` is a Reseau submodule and intentionally shares its name with `Base.Threads`. Use `Base.Threads` when you mean the stdlib module.

## Debug assertions

Some internal invariants (including certain thread-affinity checks) are guarded by `Reseau.DEBUG_BUILD[]` and are disabled by default.
For local development you can enable them early in your process:

```julia
using Reseau
Reseau.DEBUG_BUILD[] = true
```
