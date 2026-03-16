# API Reference

The public surface is centered on the exported `TCP` and `TLS` modules.

## `TCP`

### Address Constructors

- `TCP.SocketAddrV4`
- `TCP.SocketAddrV6`
- `TCP.loopback_addr`
- `TCP.any_addr`
- `TCP.loopback_addr6`
- `TCP.any_addr6`

### Connections and Listeners

- `TCP.connect`
- `TCP.listen`
- `TCP.accept`
- `close(::TCP.Conn)`
- `close(::TCP.Listener)`

The string-address overloads on `TCP.connect` accept:

- `timeout_ns`
- `deadline_ns`
- `local_addr`
- `fallback_delay_ns`
- `resolver`
- `policy`

### Deadlines, Shutdown, and Socket Options

- `TCP.set_deadline!`
- `TCP.set_read_deadline!`
- `TCP.set_write_deadline!`
- `TCP.closeread`
- `closewrite(::TCP.Conn)`
- `TCP.set_nodelay!`
- `TCP.set_keepalive!`

### Address Inspection

- `TCP.local_addr`
- `TCP.remote_addr`
- `TCP.addr`

## `TLS`

### Main Types

- `TLS.Config`
- `TLS.Conn`
- `TLS.Listener`
- `TLS.ClientAuthMode`

### Client and Server Setup

- `TLS.connect`
- `TLS.listen`
- `TLS.client`
- `TLS.server`
- `TLS.accept`
- `TLS.handshake!`

The string-address overloads on `TLS.connect` accept the same resolution and
connect-policy keywords as `TCP.connect`, along with all `TLS.Config` keywords.

### Lifecycle and Inspection

- `close(::TLS.Conn)`
- `close(::TLS.Listener)`
- `TLS.addr`
- `TLS.net_conn`
- `TLS.connection_state`
- `closewrite(::TLS.Conn)`

### Errors

- `TLS.ConfigError`
- `TLS.TLSError`
- `TLS.TLSHandshakeTimeoutError`
