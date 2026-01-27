# AwsIO.jl

Pure-Julia implementation of aws-c-io style primitives (macOS + Linux).
The API mirrors aws-c-io naming and behavior, but drops the `aws_` prefix.
Event loops, sockets, channels, TLS, host resolver, and async input streams
use direct OS syscalls and Julia-managed threads (no libuv).

GitHub Actions : [![Build Status](https://github.com/JuliaServices/AwsIO.jl/workflows/CI/badge.svg)](https://github.com/JuliaServices/AwsIO.jl/actions?query=workflow%3ACI+branch%3Amaster)

[![codecov.io](http://codecov.io/github/JuliaServices/AwsIO.jl/coverage.svg?branch=master)](http://codecov.io/github/JuliaServices/AwsIO.jl?branch=master)

## Installation

```julia
using Pkg
Pkg.add("AwsIO")
```

## Usage

### Event loop group + resolver
```julia
using AwsIO

elg = EventLoopGroup(EventLoopGroupOptions(; loop_count = 1))
resolver = DefaultHostResolver(elg)

host_resolver_resolve!(resolver, "localhost") do res, host, err, addrs
    @show err addrs
end
```

### Socket + channel (plain)
```julia
using AwsIO

elg = EventLoopGroup(EventLoopGroupOptions(; loop_count = 1))
el = event_loop_group_get_next_loop(elg)
sock = socket_init_posix(SocketOptions(; type = SocketType.STREAM, domain = SocketDomain.IPV4))

connect_opts = SocketConnectOptions(
    SocketEndpoint("127.0.0.1", 8080);
    event_loop = el,
    on_connection_result = (sock_obj, err, ud) -> @show err,
)

socket_connect(sock, connect_opts)
```

### TLS channel handler
```julia
using AwsIO

# Assumes an established socket and event loop (see socket example).
channel = Channel(el, nothing)
socket_channel_handler_new!(channel, sock)

ctx = tls_context_new_client(; verify_peer = false)
tls_opts = TlsConnectionOptions(ctx; server_name = "localhost")
tls_channel_handler_new!(channel, tls_opts)

channel_setup_complete!(channel)
```

### Async input stream
```julia
using AwsIO

data = ByteBuffer(5)
stream = AsyncInputStream((s, dest) -> begin
    fut = Future{Bool}()
    dest.len += 5
    future_complete!(fut, true)
    fut
end, s -> nothing, nothing)

future = async_input_stream_read_to_fill(stream, data)
future_wait(future)
```

## Threading requirements

AwsIO runs event loops on Julia-managed threads and intentionally avoids the libuv global IO lock.
For correctness and to keep the main interactive thread available, the event-loop group requires:

- `Threads.nthreads(:interactive) > 1`
- `loop_count < Threads.nthreads(:interactive)`

If these constraints are not met, `event_loop_group_new` returns an error. Recommended settings
for local development are `JULIA_NUM_THREADS=auto,2` (or higher interactive count when using
multiple event loops).
