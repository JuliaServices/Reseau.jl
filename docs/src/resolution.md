```@meta
CurrentModule = Reseau.HostResolvers
Description = "Host resolution, address-family policy, and resolver configuration for Reseau.jl."
```

# [Name Resolution](@id name-resolution-manual)

`TCP.connect("host:port")`, `TCP.listen("host:port")`, and `TLS.connect("host:port")`
all flow through a resolver layer that turns host/port strings into concrete
`TCP.SocketEndpoint` values. Most users can ignore that layer and stay on the
`TCP` or `TLS` entrypoints directly. The types documented here are advanced
controls for custom resolution, caching, and explicit address-family policy.

```@contents
Pages = ["resolution.md"]
Depth = 2:3
```

## When This Layer Matters

Most users can call [`Reseau.TCP.connect`](@ref Reseau.TCP.connect) or
[`Reseau.TLS.connect`](@ref Reseau.TLS.connect) directly and never touch these
types. Reach for this layer when you need any of the following:

- explicit IPv4/IPv6 preference or filtering
- a custom resolver backend
- cached or deduplicated hostname lookups
- pre-resolved address lists before dialing
- deadline and fallback-race control packaged into one reusable dial policy

## Resolver Policy

`ResolverPolicy` controls how mixed-family results are filtered and ordered:

```@docs; canonical=false
ResolverPolicy
```

This is the right tool when you want a `"tcp"` dial to prefer IPv6 first,
disable one family entirely, or otherwise steer the order of candidate
endpoints before connect attempts begin.

## Resolver Implementations

Reseau ships a small stack of resolver building blocks for advanced dialing
control:

```@docs; canonical=false
SystemResolver
SingleflightResolver
CachingResolver
StaticResolver
HostResolver
```

The usual default path is:

1. `SystemResolver` performs platform DNS and service lookups.
2. `SingleflightResolver` coalesces concurrent duplicate lookups.
3. `HostResolver` packages timeout, deadline, local bind, fallback delay, and policy for a whole resolve+connect operation.

Add `CachingResolver` or `StaticResolver` when you want explicit control over
lookup reuse or deterministic test-time address mapping.

## Resolving Explicitly

If you want the concrete address list before dialing, use the explicit helper
functions:

```@docs; canonical=false
resolve_tcp_addrs
resolve_tcp_addr
```

These helpers are useful when:

- you want to inspect or log the resolved candidate set
- you want to dial multiple endpoints yourself
- you are building higher-level connection policy on top of Reseau

## Relationship To TCP And TLS

- [`Reseau.TCP.connect`](@ref Reseau.TCP.connect) uses this layer for string-address dialing.
- [`Reseau.TCP.listen`](@ref Reseau.TCP.listen) uses it for `"host:port"` listener setup.
- [`Reseau.TLS.connect`](@ref Reseau.TLS.connect) forwards the same resolver and policy keywords before wrapping the resulting TCP transport in TLS.

Read [TCP](@ref tcp-manual) and [TLS](@ref tls-manual) for the transport and handshake layers that sit on top of these resolved endpoints.
