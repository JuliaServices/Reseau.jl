# TLS

`TLS` wraps `TCP` connections and listeners with OpenSSL-backed TLS state while
keeping deadlines and socket lifecycle aligned with the underlying transport.

## Core Types

- `TLS.Config`
- `TLS.Conn`
- `TLS.Listener`
- `TLS.ClientAuthMode`

Important error types:

- `TLS.ConfigError`
- `TLS.TLSError`
- `TLS.TLSHandshakeTimeoutError`

## Client Connections

The simplest path is `TLS.connect("host:port"; kwargs...)`:

```julia
using Reseau

conn = TLS.connect(
    "www.google.com:443";
    verify_peer = true,
    alpn_protocols = ["h2", "http/1.1"],
)

state = TLS.connection_state(conn)
println((state.handshake_complete, state.alpn_protocol))
close(conn)
```

If you already have a plain `TCP.Conn`, wrap it explicitly:

```julia
using Reseau

tcp = TCP.connect("example.com:443")
cfg = TLS.Config(alpn_protocols = ["h2", "http/1.1"])
tls = TLS.client(tcp, cfg)
TLS.handshake!(tls)

close(tls)
```

## Server Listeners

Construct a reusable `TLS.Config`, then build a TLS listener on top of a TCP
listener:

```julia
using Reseau

cfg = TLS.Config(
    cert_file = "server.crt",
    key_file = "server.key",
    alpn_protocols = ["h2", "http/1.1"],
)

listener = TLS.listen("tcp", "127.0.0.1:8443", cfg)
conn = TLS.accept(listener)

close(conn)
close(listener)
```

Accepted connections are returned in lazy-handshake form, just like Go's
`crypto/tls`.

## Configuration Highlights

Useful `TLS.Config` keywords include:

- `server_name`
- `verify_peer`
- `client_auth`
- `cert_file`
- `key_file`
- `ca_file`
- `client_ca_file`
- `alpn_protocols`
- `handshake_timeout_ns`
- `min_version`
- `max_version`

For server-side verified client-certificate auth, provide `client_ca_file`
explicitly.

## Connection Helpers

- `TLS.handshake!(conn)` to complete the handshake eagerly
- `close(conn)` / `close(listener)` for lifecycle management
- `TLS.addr(listener)` for the local listener address
- `TLS.net_conn(conn)` to reach the wrapped `TCP.Conn`
- `TLS.connection_state(conn)` for a negotiated-state snapshot
