# TLS

`Reseau.TLS` is the TLS layer that wraps `Reseau.TCP` connections and listeners.
It uses a Go-style split between reusable configuration and per-connection state.

## Core Types

- `Reseau.TLS.Config`
- `Reseau.TLS.Conn`
- `Reseau.TLS.Listener`
- `Reseau.TLS.ClientAuthMode`

Important error types:

- `Reseau.TLS.ConfigError`
- `Reseau.TLS.TLSError`
- `Reseau.TLS.TLSHandshakeTimeoutError`

## Client Connections

The easiest path is `Reseau.TLS.connect`:

```julia
using Reseau

conn = Reseau.TLS.connect(
    "tcp",
    "example.com:443";
    verify_peer=true,
    alpn_protocols=["h2", "http/1.1"],
)
```

If you already have a `Reseau.TCP.Conn`, wrap it with `Reseau.TLS.client`:

```julia
using Reseau

tcp = Reseau.HostResolvers.connect("tcp", "example.com:443")
cfg = Reseau.TLS.Config(alpn_protocols=["h2", "http/1.1"])
tls = Reseau.TLS.client(tcp, cfg)
Reseau.TLS.handshake!(tls)
```

## Server Listeners

Construct a reusable `Config`, then build a TLS listener:

```julia
using Reseau

cfg = Reseau.TLS.Config(
    cert_file="server.crt",
    key_file="server.key",
    alpn_protocols=["h2", "http/1.1"],
)

listener = Reseau.TLS.listen("tcp", "127.0.0.1:8443", cfg)
conn = Reseau.TLS.accept!(listener)
```

Accepted connections are returned in lazy-handshake form, just like Go's
`crypto/tls`.

## Configuration Highlights

Useful `Config` keywords include:

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

## Operational Notes

- Deadline handling stays aligned with the underlying transport.
- `server_name` is inferred from dial targets when possible.
- ALPN is the key bridge between Reseau and HTTP.jl's HTTP/2 behavior.
- This is the layer to configure certificates and peer verification; HTTP.jl
  should receive an already-prepared listener or connection policy.
