```@meta
CurrentModule = Reseau
Description = "QUIC connections and streams in Reseau.jl: connecting, listening, streams as IO, errors, and deadlines."
```

# [QUIC](@id quic-manual)

`Reseau.QUIC` runs QUIC (RFC 9000, 9001, and 9002) over [`Reseau.UDP`](@ref),
with the TLS 1.3 handshake from [`Reseau.TLS`](@ref). It is the transport for
HTTP/3. The module is not exported: use it as `Reseau.QUIC`.

```@contents
Pages = ["quic.md"]
Depth = 2:3
```

## Connecting and listening

[`QUIC.connect`](@ref QUIC.connect) opens a connection over a new connected UDP
socket and returns once the handshake completes. QUIC requires ALPN, so the
client `TLS.Config` names its application protocols:

```julia
using Reseau
const QUIC = Reseau.QUIC

addr = first(Reseau.HostResolvers.resolve_tcp_addrs("udp", "cloudflare-quic.com:443"))
config = TLS.Config(server_name = "cloudflare-quic.com", alpn_protocols = ["h3"])
conn = QUIC.connect(addr, config; deadline_ns = Int64(time_ns()) + 5_000_000_000)
QUIC.alpn_protocol(conn)  # "h3"
close(conn)
```

A server binds with [`QUIC.listen`](@ref QUIC.listen) and takes connections
whose handshake completed with [`QUIC.accept`](@ref QUIC.accept). One UDP
socket carries every connection the listener accepts. Closing the listener
stops new connections; accepted ones go on.

Each UDP socket has a task that receives datagrams and runs the connections'
timers. Connections, streams, and listeners can be used from any task.

## Streams

[`QUIC.open_stream`](@ref QUIC.open_stream) opens a bidirectional stream, or
with `bidi = false` a unidirectional one, and
[`QUIC.accept_stream`](@ref QUIC.accept_stream) takes the next stream the
peer opened. A [`QUIC.Stream`](@ref QUIC.Stream) is an `IO`:

```julia
s = QUIC.open_stream(conn)
write(s, "request")
closewrite(s)          # send the FIN
response = read(s)     # until the peer's FIN
```

Reads wait for data. `readbytes!(s, buf, n; all = false)` returns as soon as
some data has arrived. Writes are buffered, up to 1 MiB unacknowledged per
stream, and then wait; flow control and congestion control decide when data
is sent. `open_stream` waits while the peer's stream limit allows no more.

[`QUIC.reset_stream!`](@ref QUIC.reset_stream!) abandons the sending side and
[`QUIC.stop_sending!`](@ref QUIC.stop_sending!) asks the peer to abandon its
side, each with an application error code. `close(stream)` only sends the
FIN.

## Errors and deadlines

- [`QUIC.StreamResetError`](@ref QUIC.StreamResetError): reads after the
  peer's RESET_STREAM, and writes after this endpoint's `reset_stream!`.
- [`QUIC.StreamStoppedError`](@ref QUIC.StreamStoppedError): writes after the
  peer's STOP_SENDING, and reads after this endpoint's `stop_sending!`.
- [`QUIC.ConnectionError`](@ref QUIC.ConnectionError): any operation once the
  connection has closed, saying who closed it and with what code. An idle
  connection closes after 30 seconds, or the peer's shorter idle timeout.

`connect`, `accept`, `open_stream`, and `accept_stream` take a `deadline_ns`
keyword, and [`QUIC.set_read_deadline!`](@ref QUIC.set_read_deadline!) and
[`QUIC.set_write_deadline!`](@ref QUIC.set_write_deadline!) set them for a
stream's reads and writes. A deadline is a `time_ns()` value; waiting past it
throws `UDP.DeadlineExceededError`.

## Performance

On Linux, datagrams leave in batches through UDP segmentation offload and
arrive in batches through receive offload; elsewhere they go one per system
call. Congestion control is CUBIC. Datagrams start at 1200 bytes, and path
MTU discovery raises them to what the path carries: by default up to the
route's MTU where the kernel reports it (connected client sockets on Linux,
up to 9000 bytes) and up to 1452 bytes otherwise. Pass `max_datagram_size` to
`connect` or `listen` to set that ceiling, for example on a jumbo-frame
network. Sockets ask for 7 MiB buffers; raise `net.core.rmem_max` and
`net.core.wmem_max` on Linux to let the kernel grant them.

## Limitations

Packets are not paced. There is no 0-RTT, no connection migration, and no
handling of Retry or Version Negotiation.

Without Retry, a listener cannot make clients prove their address before it
sets up a connection, so spoofed Initial packets each cost it a connection
until they time out. As in quic-go, a handshake is dropped after 5 seconds
without activity or 10 seconds in all, and at most 32 handshaken connections
wait to be accepted; further ones are refused with CONNECTION_REFUSED.
