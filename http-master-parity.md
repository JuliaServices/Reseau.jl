# HTTP.jl Master Parity

## Goal

Track the biggest user-facing gaps between `Reseau.HTTP` and current
`HTTP.jl` `master`, so we can close them deliberately without losing context as
we work towards parity item by item.

This document is about public API and user interface parity, not internal
implementation parity. `Reseau` can keep its own architecture as long as users
can accomplish the same things with a comparably ergonomic surface.

## Comparison Target

- Compared against the local `HTTP.jl` checkout after `git fetch origin`.
- Comparison target was `origin/master` at commit `a380230`.
- Comparison date: 2026-03-06.

## Progress Since Initial Review

The original review below captured the gap set before the current parity work
started. Since then, `Reseau.HTTP` has closed several of the biggest client-side
gaps:

- high-level request helpers now return `Response`
- `response_stream` / `response_body` sink support landed for `IO` and
  byte-buffer destinations
- gzip `decompress` handling is implemented in the high-level request pipeline
- `HTTP.open` landed as a streaming client API (currently using `Symbol`
  methods to avoid colliding with Base file-opening overloads)
- client-side SSE consumption via `sse_callback` landed

The server-side picture also improved substantially during the current rewrite
pass:

- function-style server entry points now exist: `serve`, `serve!`, `listen`,
  `listen!`, `forceclose`, and `port`
- server-side HTTP/2 now supports request handlers and stream handlers, bounded
  request-body streaming, concurrent streams, stricter frame/header validation,
  and graceful `close(server)` drain via `GOAWAY`
- HTTP/1 server semantics were tightened around unsupported `Expect`, no-body
  responses, fixed `Content-Length` mismatches, and timeout coverage
- server-side SSE helpers landed
- `HTTP.WebSockets` now has a meaningful public surface for open/listen/send/
  receive/ping/pong/close flows

The remaining sections are still useful as a backlog, but some of the original
server/SSE/WebSocket sections now overstate the current gaps and should be read
in that light.

Important note:

- `HTTP.jl` exposes much more than its top-level `export` list suggests.
- A lot of its public surface is "public by qualification" through names pulled
  in from submodules and then accessed as `HTTP.Foo`, `HTTP.Router`,
  `HTTP.Cookie`, `HTTP.WebSockets.open`, etc.
- Any parity review that only looks at explicit `export` lines will
  underestimate what `HTTP.jl` actually exposes to users.

## Current Shared Surface

These areas already overlap meaningfully:

- High-level request helpers: `request`, `get`, `head`, `post`, `put`, `patch`,
  `delete`.
- Core request/response/header/body concepts.
- Redirect following of some kind.
- Cookie handling of some kind.
- Basic server lifecycle of some kind.
- Explicit HTTP/1 parse/write APIs.

`Reseau.HTTP` is also already ahead in one notable area:

- Explicit public HPACK and HTTP/2 framing/client/server APIs.

## Biggest Gaps To Address

### 1. Client Request Surface

This is the single biggest parity gap.

`HTTP.jl` exposes a very wide request surface through `HTTP.request(...)`:

- `response_stream`
- `sse_callback`
- `connect_timeout`
- `pool`
- `readtimeout`
- `status_exception`
- `basicauth`
- `canonicalize_headers`
- `proxy`
- `detect_content_type`
- `logerrors`
- `logtag`
- `observelayers`
- `retry`
- `retries`
- `retry_non_idempotent`
- `retry_delays`
- `retry_check`
- `require_ssl_verification`
- `sslconfig`
- `socket_type_tls`
- `cookies`
- `cookiejar`

`Reseau.HTTP.request(...)` currently supports only a narrower subset:

- `status_exception`
- `redirect`
- `query`
- `client`
- `connect_timeout`
- `readtimeout`
- `require_ssl_verification`
- `protocol`

There are also compatibility shims that are currently accepted but not really
implemented:

- `verbose`
- `decompress`
- `canonicalize_headers`
- `logerrors`
- `observelayers`

`retry` is also only tolerated in the very narrow `retry=false` form, not
implemented as a real retry API.

### 2. Return-Type and Streaming Mismatch

`HTTP.jl`'s top-level request family returns `HTTP.Response`, and supports:

- buffered bodies
- `response_stream`
- `HTTP.open(...)`
- `HTTP.openraw(...)`

`Reseau.HTTP` currently splits the world differently:

- `request(...)` returns a fully materialized `ClientResponse`
- `do!(...)` and `roundtrip!(...)` return lower-level streaming `Response`

That split is coherent, but it is not HTTP.jl parity. If parity is the goal,
we likely need to move closer to:

- top-level request helpers returning `Response`
- `response_stream` support
- an `open(...)`-style API

`openraw(...)` is lower priority than `open(...)`, but still part of the
current `HTTP.jl` surface.

### 3. Request Body Input Parity

`HTTP.jl` supports many request body shapes:

- `AbstractDict` / `NamedTuple` as
  `application/x-www-form-urlencoded`
- strings
- bytes
- `IO`
- iterable/chunked request bodies
- multipart `Form`

`Reseau.HTTP` currently handles:

- `nothing`
- `String`
- `Vector{UInt8}`
- `IO`
- `AbstractBody`

Missing parity items:

- automatic form-urlencoded encoding from `Dict` / `NamedTuple`
- iterable/chunked request bodies
- multipart/form-data helpers

### 4. Server Entry Point Shape

`HTTP.jl`'s primary server story is function-oriented:

- `HTTP.serve`
- `HTTP.serve!`
- `HTTP.listen`
- `HTTP.listen!`

It also supports:

- request handlers
- stream handlers
- `HTTP.Server`
- `HTTP.forceclose`
- `HTTP.port`

`Reseau.HTTP` now exposes the same top-level function-style entry points users
expect:

- `serve`
- `serve!`
- `listen`
- `listen!`
- `Server`
- `forceclose`
- `port`

This is no longer a top-tier parity gap. The remaining server-side parity work
is more about higher-level ergonomics and middleware/router features than basic
entry-point shape.

### 5. Router / Middleware / Handler Framework

This gap is now largely closed.

`Reseau.HTTP` now exposes the same core surface users expect from `HTTP.jl`:

- `Handler`
- `Middleware`
- `streamhandler`
- `Router`
- `register!`
- `getroute`
- `getparams`
- `getparam`
- `getcookies`
- `HTTP.Handlers.cookie_middleware`

The router now supports the same matching shapes we called out above:

- exact routes
- `*` segment wildcards
- named params like `{id}`
- regex params like `{id:[0-9]+}`
- trailing `/**`

It also works through both the request-handler and stream-handler server entry
points, with dedicated HTTP/1 and HTTP/2 coverage in `Reseau`'s test suite.

The remaining parity work in this area is mostly about higher-level polish and
future middleware conveniences, not the core router/handler framework itself.

### 6. Cookies

`Reseau.HTTP` currently has a simple `MemoryCookieJar` and lightweight
`Cookie` type oriented around redirect/session handling.

`HTTP.jl` exposes a richer cookie surface:

- `Cookie`
- `CookieJar`
- `cookies`
- `stringify`
- `getcookies!`
- `setcookies!`
- `addcookie!`

The `HTTP.jl` cookie model includes:

- domain
- path
- expires
- max-age
- secure
- httponly
- hostonly
- samesite

So cookie parity is not just "store cookies in a jar"; it is a broader public
API and richer data model.

### 7. Multipart / Form APIs

`HTTP.jl` has user-facing multipart/form helpers:

- `Form`
- `Multipart`
- `content_type`
- `parse_multipart_form`

`Reseau.HTTP` currently has no comparable public multipart/form layer.

This is a meaningful parity gap because multipart upload support is part of the
normal HTTP client surface for many users.

### 8. SSE

`HTTP.jl` supports both:

- server-side SSE emission with `SSEEvent`, `SSEStream`, and `sse_stream`
- client-side SSE consumption via `sse_callback`

`Reseau.HTTP` now supports both:

- server-side SSE emission with `SSEEvent`, `SSEStream`, and `sse_stream`
- client-side SSE consumption via `sse_callback`

This is no longer a meaningful parity gap.

### 9. WebSockets

`HTTP.jl` exposes a substantial WebSocket API through `HTTP.WebSockets`,
including:

- `open`
- `listen`
- `listen!`
- `upgrade`
- `WebSocket`
- `send`
- `receive`
- `ping`
- `pong`
- `close`
- `isclosed`
- `isok`

`Reseau.HTTP` now has a substantial `HTTP.WebSockets` surface by qualification,
including `open`, `listen`, `listen!`, `WebSocket`, `send`, `receive`, `ping`,
`pong`, `close`, `isclosed`, and `isok`.

The main remaining parity questions here are completeness and exact API shape,
especially around upgrade helpers and any long-tail convenience APIs, not the
absence of a websocket subsystem.

### 10. Client Customization Model

`HTTP.jl` has a full client layer stack:

- `Layer`
- `pushlayer!`
- `pushfirstlayer!`
- `poplayer!`
- `popfirstlayer!`
- `@client`

This is a real public customization story for request pipelines.

`Reseau.HTTP` currently uses explicit `Client` / `Transport` objects instead.

We should decide explicitly whether parity here means:

- match the exact layer API
- or expose equivalent power through the existing `Client` / `Transport` model

This is an important design choice, not just a missing helper.

### 11. Lower-Level Utilities and Long Tail

`HTTP.jl` also exposes a longer tail of public or public-ish utilities:

- `download`
- `openraw`
- access log formatting helpers
- `sniff`, `isjson`
- `statustext`
- string helpers like `tocameldash`, `escapehtml`, etc.
- low-level parser/message utilities

These are real parity gaps, but they are lower-value than the client/server
surface gaps above.

## Likely Non-Goals or Explicit Deferrals

These are the most obvious items to skip or defer:

- `HTTP.download`
- access-log DSL helpers like `@logfmt_str`, `common_logfmt`, `combined_logfmt`
- low-level parser utility exports unless another package truly needs them
- exact reproduction of the client layer stack if `Client` / `Transport` can
  cover the same real-world use cases cleanly

## Recommended Parity Phases

### Phase 1: High-Value Client Parity

Focus on the top-level request family first:

- return-type strategy review for `request`
- `response_stream`
- actual `decompress`
- real retry knobs
- richer redirect knobs
- proxy support
- cookie kwargs
- richer body inputs
- form-urlencoded bodies

This is the biggest practical parity win for ordinary users.

### Phase 2: Streaming Client Surface

Add:

- `open(...)`
- possibly `openraw(...)`

This unlocks a lot of advanced workflows and is more foundational than
`download`.

### Phase 3: Router / Middleware

Add:

- `Router`
- `register!`
- path params helpers
- a lightweight middleware story

This is likely the biggest missing server-side UX feature.

### Phase 4: Cookies and Multipart/Form APIs

Add richer cookie and multipart/form support:

- public cookie helpers
- richer cookie model if needed
- `Form` / multipart helpers
- multipart parsing

### Phase 5: WebSockets

Treat WebSockets as a dedicated track.

This is clearly part of `HTTP.jl`'s public surface, but it is large enough that
it should likely be scoped and reviewed separately.

## Design Guidance

We should aim for behavioral parity, not implementation imitation.

Concretely:

- it is okay if `Reseau.HTTP` keeps its own `Client` / `Transport` internals
- it is okay if HTTP/2 stays more explicit in `Reseau` than in `HTTP.jl`
- it is okay if some long-tail convenience helpers are skipped intentionally

What matters is that a user coming from `HTTP.jl` can find equivalent ways to:

- make requests with the same major knobs
- stream request and response bodies
- run servers in a familiar way
- route requests
- use cookies, multipart, SSE, and WebSockets where desired

## Current Working Assumption

The highest-value parity work is:

1. client request surface
2. streaming APIs
3. router/middleware
4. richer cookie + multipart/form support

The most obvious explicit non-goal right now is:

1. `HTTP.download`

This document should be updated as parity work lands so it remains the source of
truth for what is still missing and what we have intentionally chosen not to
match.
