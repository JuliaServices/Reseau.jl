```@meta
CurrentModule = Reseau.TLS
Description = "TLS clients, listeners, configuration, and handshake behavior in Reseau.jl."
```

# [TLS](@id tls-manual)

`TLS` wraps `TCP` connections and listeners with OpenSSL-backed TLS state while
keeping deadlines and socket lifecycle aligned with the underlying transport.
String-address client dialing uses the same resolver/policy layer as
[`Reseau.TCP.connect`](@ref Reseau.TCP.connect); see [Name Resolution](@ref name-resolution-manual)
for that part of the stack.

```@contents
Pages = ["tls.md"]
Depth = 2:3
```

## Configuration, Types, and Errors

The main TLS building blocks are:

```@docs; canonical=false
Config
ConnectionState
Conn
Listener
ConfigError
TLSError
TLSHandshakeTimeoutError
```

`ClientAuthMode` is an enum-like policy surface with the following cases:

- `TLS.ClientAuthMode.NoClientCert`
- `TLS.ClientAuthMode.RequestClientCert`
- `TLS.ClientAuthMode.RequireAnyClientCert`
- `TLS.ClientAuthMode.VerifyClientCertIfGiven`
- `TLS.ClientAuthMode.RequireAndVerifyClientCert`

For server-side verified client-certificate auth, provide `client_ca_file`
explicitly in [`Config`](@ref).

## Client and Server Construction

You can either dial and handshake a client in one step, or wrap an existing
`TCP.Conn` manually:

```@docs; canonical=false
client
server
connect
listen
accept
handshake!
```

Important behaviors to keep in mind:

- [`connect`](@ref) returns a fully handshaken client connection.
- [`listen`](@ref) returns a TLS listener whose accepted connections are
  lazy-handshake wrappers.
- [`client`](@ref) and [`server`](@ref) are the direct wrapping APIs when you
  already control the underlying `TCP.Conn`.
- [`handshake!`](@ref) is idempotent, so eager and lazy handshake styles can coexist safely.

## I/O, Lifecycle, Deadlines, and Inspection

TLS connections still behave like Julia streams, but now read and write operate
on plaintext application data while OpenSSL handles record framing underneath:

```@docs; canonical=false
Base.read!(::Conn, ::Vector{UInt8})
Base.write(::Conn, ::AbstractVector{UInt8})
Base.close(::Conn)
Base.close(::Listener)
Base.closewrite(::Conn)
set_deadline!
set_read_deadline!
set_write_deadline!
local_addr
remote_addr
net_conn
connection_state
addr
```

Two details matter in practice:

- TLS deadlines are delegated to the wrapped TCP transport, so the timeout
  model matches [TCP](@ref tcp-manual) exactly.
- A timed-out TLS write is treated as a permanent write failure, mirroring Go's
  `crypto/tls` behavior where partial record emission leaves future writes
  unsafe.

## Practical Usage Notes

- If `server_name` is omitted, [`connect`](@ref) derives it from the dial target when possible so SNI and certificate verification behave like Go's defaults.
- If `ca_file` is omitted for outbound verification, Reseau falls back to `NetworkOptions.ca_roots_path()` when that path is available.
- [`connection_state`](@ref) does not force the handshake to run; it reports the current negotiated state as-is.

## Where To Go Next

- Read [TCP](@ref tcp-manual) for the underlying transport model and socket lifecycle.
- Read [Name Resolution](@ref name-resolution-manual) for resolver and address-family policy controls shared by `TCP.connect` and `TLS.connect`.
- Read [API Reference](@ref api-reference-manual) for the canonical TLS docstrings.
