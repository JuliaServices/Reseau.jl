# Sockets Submodule PRD (Reseau.Sockets)

Goal: provide a *drop-in* replacement for Julia stdlib `Sockets` (TCP + named pipes first) implemented on top of Reseau's socket + channel + TLS stack (not libuv).

Primary motivation:
- Many downstream packages want "Sockets-like" APIs (`connect`, `listen`, `accept`, `read`, `write`) but do not want to be coupled to libuv streams.
- Reseau already implements most of the hard parts (cross-platform socket backends, event loops, DNS resolver, TLS, ALPN, backpressure windows); what's missing is the user-facing, `Sockets`-shaped surface.

Non-goals (at least for v1):
- Perfect type identity with stdlib `Sockets.TCPSocket` / `LibuvStream` (we can be API-compatible without being `LibuvStream`-compatible).
- Full coverage of every libuv-specific behavior or error type (`_UVError`, etc).
- UDP/multicast parity (explicitly punted until TCP+LOCAL parity is solid).

Status (2026-02-08):
- Julia version in this workspace: `1.12.3`.
- Reseau `Project.toml` compat: `julia = "1.11"`.
- `Reseau.Sockets` now exists as a public submodule with:
  - stdlib-derived address types: `IPAddr`, `IPv4`, `IPv6`, `InetAddr`, `@ip_str`
  - libuv-free DNS + interface utilities: `getalladdrinfo`, `getaddrinfo`, `getnameinfo`, `getipaddrs`, `getipaddr`, `islinklocaladdr`
  - `TCPSocket <: IO` and `TCPServer` with `connect`/`listen`/`listenany`/`accept` and `getsockname`/`getpeername`
  - first-class TLS integration via keywords on `connect`/`listen` plus `tlsupgrade!(sock)` for explicit upgrades
- The legacy channel-to-`IO` adapters (`src/io/channel_buffer.jl`, `src/io/bufferio.jl`) have been deleted and their useful behavior folded into `Reseau.Sockets.TCPSocket`. The `BufferIO` dependency was removed from `Project.toml`.
- Tests added:
  - `test/sockets_compat_tests.jl` (TCP + LOCAL + addr/DNS utils, plus TLS echo behind `RESEAU_RUN_TLS_TESTS=1`)

This doc has 4 parts:
0. Repo/module organization notes (how `Sockets` fits into the larger refactor).
1. Inventory/deep-dive: what stdlib `Sockets` exports and how it behaves.
2. Inventory/deep-dive: what Reseau already has (and what's missing for parity).
3. PRD/TODO: proposed `Reseau.Sockets` API, implementation strategy (no `BufferIOChannel` adapter), TLS extension knobs, and phased rollout.

---

## 0) Repo Organization Notes (Proposed)

High-level direction: organize the public surface of Reseau into a small number of domain modules, with "common/runtime" utilities remaining internal.

Proposed public modules:
- `Reseau.EventLoops`: event loop types, scheduling, event loop groups, IO-event subscription, timers/delays (libuv-free).
- `Reseau.Files`: file handles/streams, async IO strategy (threadpool/overlapped/uring later), file watching, and any Base-like filesystem surface.
- `Reseau.Sockets`: TCP + LOCAL (named pipes / unix domain sockets), DNS helpers, and TLS integration that makes `connect(...; tls=true)` / `listen(...; tls=true)` work.

What about threads/concurrency?
- There is a real "runtime/concurrency" layer in this repo today: `src/common/thread.jl`, `src/common/thread_shared.jl`, `src/common/condition_variable.jl`, `src/common/task_scheduler.jl`, `src/io/future.jl`, plus libuv-free sleep/clock utilities.
- This layer is used by both EventLoops (each loop runs on an OS thread) and Sockets/DNS (host resolver runs an OS thread).

Recommendation:
- Add a `Reseau.Threads` module to hold:
  - OS thread lifecycle (`ThreadHandle`, `thread_launch`, managed-join, `thread_current_sleep`)
  - condition variables / synchronization helpers
  - `ScheduledTask`/`TaskScheduler` and `Future`
- Status: implemented as a public submodule (`src/Threads.jl`). It intentionally re-exports `Base.Threads` bindings (`Event`, `Condition`, etc) while also exposing Reseau's OS-thread/runtime utilities. This keeps existing call-sites that use `Threads.Event` working while giving us a natural home for Reseau runtime pieces.

---

## 1) Inventory: Julia stdlib `Sockets` (Julia 1.12.x)

Reference sources in this environment:
- `~/.julia/juliaup/julia-1.12.3+0.aarch64.apple.darwin14/share/julia/stdlib/v1.12/Sockets/src/Sockets.jl`
- `.../Sockets/src/IPAddr.jl`
- `.../Sockets/src/addrinfo.jl`
- `.../Sockets/src/PipeServer.jl`

### A. Exported surface

`Sockets` exports:
- TCP: `connect`, `listen`, `listenany`, `accept`, `getsockname`, `getpeername`, `bind`
- UDP: `UDPSocket`, `recv`, `recvfrom`, `send`, `join_multicast_group`, `leave_multicast_group`
- DNS/name utils: `getaddrinfo`, `getalladdrinfo`, `getnameinfo`
- Local IP utils: `getipaddr`, `getipaddrs`, `islinklocaladdr`
- Address types: `IPAddr`, `IPv4`, `IPv6`, `@ip_str`
- Stream types: `TCPSocket`, `UDPSocket`

Notably *not* exported (but part of the "shape"):
- `TCPServer` type (returned by `listen`).
- Domain socket types (`PipeServer`, `PipeEndpoint`), though `listen(path::AbstractString)` and `connect(path::AbstractString)` are exported and return those.

### B. Core types and semantics

TCP:
- `TCPSocket <: Base.LibuvStream`
- `TCPServer <: Base.LibuvServer`
- `connect(host, port)` is blocking, and returns a connected `TCPSocket`.
- `listen(host, port)` returns `TCPServer`; `accept(server)` blocks until connection.
- `getsockname(sock)` / `getpeername(sock)` return `(IPAddr, UInt16)`.

UDP:
- `UDPSocket <: Base.LibuvStream`
- `recv(sock)` blocks and returns a datagram payload as `Vector{UInt8}`.
- `recvfrom(sock)` blocks and returns `(InetAddr{IPv4/IPv6}, Vector{UInt8})`.
- `send(sock, ipaddr, port, msg)` sends a datagram to an explicit remote; socket does not need to be "connected".

Domain sockets / named pipes:
- `listen(path::AbstractString)` returns a `PipeServer` (UNIX domain socket on unix; named pipe on Windows).
- `connect(path::AbstractString)` returns a `PipeEndpoint`.

DNS + interface enumeration:
- `getaddrinfo` and friends run via libuv-backed async requests.
- `getipaddrs` enumerates interfaces via `jl_uv_interface_addresses` (libuv).

### C. Important behavioral details that matter for "drop-in"

- `bind(sock, host, port; ipv6only=false, reuseaddr=false, ...)` returns `Bool` and uses "false indicates bind failed due to address-in-use / access denied / addr-not-available" semantics (as opposed to always throwing).
- `listen()` defaults to binding `localhost` only, not all interfaces.
- `listenany(host, port_hint)` loops over ports until a bind+listen succeeds and returns `(actual_port, server)`.
- `accept(callback, server)` exists and spawns an async accept-loop task that calls `callback(client)` repeatedly.

---

## 2) Inventory: What Reseau Already Has

### A. Low-level sockets (already implemented)

Key files:
- `src/io/socket.jl` (public socket abstraction + options + endpoints)
- `src/io/posix_socket_impl.jl`, `src/io/apple_nw_socket_impl.jl`, `src/io/winsock_socket.jl` (platform backends)

Reseau provides:
- `SocketDomain`: `IPV4`, `IPV6`, `LOCAL`, `VSOCK`
- `SocketType`: `STREAM`, `DGRAM`
- `SocketEndpoint` (string address + port)
- `SocketOptions` (type/domain/connect timeout/keepalive/interface name, etc)
- `socket_init`, `socket_bind`, `socket_listen`, `socket_connect`, `socket_close`, `socket_read`, `socket_write`, ...

Important nuance:
- On macOS, `socket_init` chooses Apple Network.framework (`NWSocket`) for IP sockets, and POSIX sockets for `LOCAL` / `VSOCK`.

### B. Channel pipeline + bootstraps (already implemented)

Key files:
- `src/io/channel.jl`
- `src/io/socket_channel_handler.jl`
- `src/io/channel_bootstrap.jl`

Reseau provides:
- `ClientBootstrap` and `client_bootstrap_connect!` that do: DNS resolve -> connect attempts -> channel construction -> install socket handler -> optionally install TLS handler -> trigger reads.
- `ServerBootstrap` and `server_bootstrap_shutdown!` that do: bind -> listen -> accept loop -> per-connection channel setup -> optional TLS.
- Backpressure windows (read window) in channel slots.

### C. DNS resolver (already implemented, libuv-free)

Key file:
- `src/io/host_resolver.jl`

Reseau provides:
- `HostResolver` with caching and address-family balancing logic.
- A libuv-free native resolver:
  - `Reseau.getalladdrinfo(hostname; flags=0) -> Vector{Tuple{String, Cint}}`
  - This is explicitly documented as "exists primarily so downstream packages can avoid `Sockets`".

### D. TLS (already implemented)

Key file:
- `src/io/tls_channel_handler.jl`

Reseau provides:
- `TlsContextOptions`, `TlsContext`, `TlsConnectionOptions`
- Client + server TLS setup in `client_bootstrap_connect!` / `ServerBootstrap` (TLS handler stacked in the channel pipeline).
- Optional ALPN handler insertion.
- On macOS with SecItem enabled and `NWSocket`, TLS can be "native" via Network.framework (rather than the pure channel TLS handler).

### E. Channel -> IO adapters (removed)

Previously:
- `src/io/channel_buffer.jl`: `ChannelBuffer <: IO`
- `src/io/bufferio.jl`: `BufferIOChannel <: IO`

Observation:
- These two files were largely duplicative: both installed a channel handler, buffered inbound bytes, and wrote by chunking into `IoMessage`s.

Direction:
- Done: both adapters were deleted and their behavior moved directly into `Reseau.Sockets.TCPSocket`. This lets us:
  - stop exposing "random extra" IO types at the top level
  - avoid maintaining multiple buffering implementations
  - drop the `BufferIO` dependency entirely

---

## 3) PRD: A `Sockets`-Compatible Surface in Reseau

### A. Proposed module layout

Implement a submodule:
- `Reseau.Sockets`

Rationale:
- Lets users change a single line (`using Sockets` -> `using Reseau.Sockets`) and keep most code identical.
- Avoids name conflicts with stdlib in typical usage; can still do `const Sockets = Reseau.Sockets` at call sites.

### B. Compatibility target: "API drop-in", not "LibuvStream drop-in"

Assumption: most downstream packages only require:
- A blocking `connect` that returns an `IO`
- `read`/`write`/`eof`/`close`/`isopen`
- `listen` + `accept` for servers
- `getpeername`/`getsockname` for logging and proxying

We should explicitly document that `Reseau.Sockets.TCPSocket` is *not* a `Base.LibuvStream`, and will not work with internal Base libuv helpers that dispatch on `LibuvStream`.

### C. Implementation strategy: TCPSocket is the adapter (delete `channel_buffer.jl` + `bufferio.jl`)

Core decision: `Reseau.Sockets.TCPSocket` should *be* the blocking `IO` facade over a channel, using the proven logic currently living in:
- `src/io/channel_buffer.jl` (contiguous buffer + `unsafe_read` / `write`)
- `src/io/bufferio.jl` (extra Base IO coverage; segment buffering; write buffering)

Recommendation:
- Base the new `TCPSocket` implementation on the **contiguous buffer** approach from `ChannelBuffer`:
  - simpler invariants (`read_pos`, `write_pos`)
  - easy `unsafe_read` implementation
  - backpressure window increments are straightforward
- Then selectively port a few "nice-to-have" Base IO methods that BufferIO gave us:
  - `readbytes!`, `readavailable`, `peek(UInt8)`, `read(String)` (these are convenience/perf polish, not blockers)
- Keep `tlsupgrade!` as an explicit API, but make the primary path be one-shot TLS at `connect(...; tls=true)` / `listen(...; tls=true)`.

Implementation note:
- Even though this is called `TCPSocket`, it is really "a stream socket or local named pipe endpoint" from Reseau's point of view. The type should track the underlying `Reseau.Socket` (from the `SocketChannelHandler`) so `getsockname`/`getpeername` can work.

### D. Proposed user-facing types

#### 1. `Reseau.Sockets.TCPSocket <: IO`

Fields (likely):
- `channel::Union{Channel,Nothing}` / `slot::Union{ChannelSlot,Nothing}` / `socket::Union{Socket,Nothing}` (same pattern as the current adapters)
- `host`, `port` for the `connect(host, port)` constructors (not for `connect(ip, port)` variants)
- `buffer::Vector{UInt8}`, `read_pos::Int`, `write_pos::Int` (contiguous buffering)
- `cond::Threads.Condition`, `closed::Bool`, `shutdown_error::Int`
- write tracking: `pending_writes`, `write_error`
- config: `enable_read_back_pressure`, `initial_window_size`
- connect synchronization: `connect_event`, `connect_error`

Implements:
- `Base.read*`, `Base.write*`, `Base.unsafe_read`, `Base.unsafe_write`, `Base.flush`, `Base.eof`
  - implemented directly on `TCPSocket` using the extracted buffering + channel-handler logic.
- `Base.isopen`, `Base.close`.
- Optional: `Base.bytesavailable`, `Base.closewrite` (map to `socket_shutdown_dir(..., WRITE)`).

#### 2. `Reseau.Sockets.TCPServer`

Backed by:
- `Reseau.ServerBootstrap` + an accept queue of *channels or sockets* to turn into `TCPSocket`s.

Implements:
- `accept(server)::TCPSocket` that blocks until a connection arrives.
- `Base.close(server)` to stop accept loop and close listener.
- `Base.isopen(server)` or a `status` field.

Implementation detail:
- `ServerBootstrap` currently uses a hardcoded backlog (`socket_listen(listener, 128)`), while stdlib `listen(...; backlog=511)` is configurable.
  - For parity, either:
    - extend `ServerBootstrapOptions` to include `backlog`, or
    - implement `Sockets.listen` directly using the low-level socket API (bind/listen/start_accept) and bypass `ServerBootstrap`.

#### 3. UDP (explicitly out of scope for now)

We can revisit UDP once TCP + LOCAL (named pipes/unix sockets) + TLS are stable and API-compatible.

### E. Proposed function coverage and signatures

Targeting stdlib-compatible signatures (plus TLS extensions):

TCP connect:
- `connect(port::Integer; kws...)`
- `connect(host::AbstractString, port::Integer; kws...)`
- `connect(addr::IPAddr, port::Integer; kws...)`
- `connect(addr::InetAddr; kws...)`

TCP listen:
- `listen(port::Integer; backlog::Integer=511, kws...)`
- `listen(host::IPAddr, port::Integer; backlog::Integer=511, kws...)`
- `listen(addr::InetAddr; backlog::Integer=511, kws...)`

Accept:
- `accept(server::TCPServer) -> TCPSocket`
- `accept(callback, server::TCPServer) -> Task` (spawn loop)

Sockname/peername:
- `getsockname(sock::TCPSocket) -> (IPAddr, UInt16)`
- `getpeername(sock::TCPSocket) -> (IPAddr, UInt16)`

Domain socket / named pipe parity:
- `listen(path::AbstractString; kws...) -> TCPServer`
- `connect(path::AbstractString; kws...) -> TCPSocket`
  - Internally uses `SocketDomain.LOCAL` and treats `path` as either:
    - unix domain socket path on unix, or
    - `\\.\pipe\name` on Windows (matching the existing Reseau LOCAL implementation).

DNS/name:
- `getalladdrinfo(host::AbstractString) -> Vector{IPAddr}`
  - implement via `Reseau.getalladdrinfo(host)` + IPAddr parsing.
- `getaddrinfo(host::AbstractString[, ::Type{IPv4/IPv6}]) -> IPAddr`
- `getnameinfo(ip::IPAddr) -> String`
  - implement via native `getnameinfo()` in libc / winsock.

Local interface enumeration:
- `getipaddrs([::Type{IPv4/IPv6/IPAddr}]; loopback=false) -> Vector{IPAddr}`
  - implement via `getifaddrs` on unix, `GetAdaptersAddresses` on Windows.

### F. TLS extension design

Design goals:
- Preserve the stdlib signature surface (no keywords required) while enabling TLS via keywords.
- Make TLS easy for common cases, but allow passing a prebuilt `TlsConnectionOptions` for advanced users.

Client TLS knobs (proposed):
- `connect(...; tls::Bool=false, tls_options::Union{TlsConnectionOptions,Nothing}=nothing, server_name=nothing, ssl_cacert=nothing, ssl_capath=nothing, ssl_cert=nothing, ssl_key=nothing, ssl_insecure::Bool=false, alpn_list=nothing, timeout_ms=TLS_DEFAULT_TIMEOUT_MS, ...)`

Server TLS knobs (proposed):
- `listen(...; tls::Bool=false, tls_options::Union{TlsConnectionOptions,Nothing}=nothing, ssl_cert, ssl_key, ssl_insecure::Bool=false, alpn_list=nothing, ...)`

Implementation recommendation:
- Prefer configuring TLS in `client_bootstrap_connect!` / `ServerBootstrap` via `tls_connection_options`.
  - This ensures TLS negotiation is part of the connection setup, and on macOS can use Network.framework TLS where applicable.
  - `tlsupgrade!(sock)` remains useful as an explicit "upgrade" API, but for `Sockets` parity a single-step `connect(...; tls=true)` is nicer.

### G. Error mapping and semantics

Stdlib `Sockets` uses `IOError` / `_UVError` and sometimes returns `Bool` (e.g. `bind`).

For a "drop-in" surface we should:
- Throw exceptions on most failures (Base-like).
- Preserve `bind` returning `Bool` with `false` for expected bind failures (address in use, access denied, addr not available).
- Map Reseau error codes (e.g. `ERROR_IO_SOCKET_ADDRESS_IN_USE`) into:
  - `false` for `bind`
  - `ArgumentError` for invalid ports/addresses
  - `IOError`/`EOFError` for read/write on closed sockets
  - a `DNSError` analogue for DNS failures (optional; could reuse Reseau error codes instead)

### H. Testing plan (Reseau test suite)

Add `test/sockets_compat_tests.jl` with:
- TCP: echo server and client, `connect`/`listen`/`accept`, `read`/`write`, close semantics.
- LOCAL: same echo tests over `connect(path)` / `listen(path)` (important on macOS where IP sockets use `NWSocket`).
- TLS (behind `RESEAU_RUN_TLS_TESTS=1`): local TLS server and client with self-signed cert from `aws-c-io/tests/resources`.
- Ensure `Base`-style IO behaviors are covered: `unsafe_read`, `read!`, `read(UInt8)`, `skip`, `flush`, `close`.

Also run downstream tests after implementation:
- `~/.julia/dev/HTTP`
- `~/.julia/dev/AwsHTTP`

---

## Phased TODO

### Phase 0: Module Refactor Skeleton (done)
- `Reseau.EventLoops`, `Reseau.Files`, `Reseau.Sockets`, `Reseau.Threads` are now public submodules.

### Phase 1: TCP client parity (done)
- `TCPSocket <: IO` is implemented in `src/sockets/tcp.jl` with the buffering + handler logic folded in.
- `connect` overloads exist (`connect(port)`, `connect(host, port)`, `connect(IPAddr, port)`, `connect(InetAddr)`).
- `getpeername`/`getsockname` are implemented.
- Legacy IO adapters deleted.
- Basic echo tests exist in `test/sockets_compat_tests.jl`.

### Phase 2: TCP server parity (done)
- `TCPServer` + `listen`/`listenany`/`accept` are implemented (including LOCAL path support).
- Tests cover TCP + LOCAL echo and basic `listenany` behavior.

### Phase 3: TLS on connect/listen (done)
- TLS keywords are supported for both client and server.
- `tlsupgrade!(sock)` exists for explicit upgrades.
- TLS echo tests exist (gated behind `RESEAU_RUN_TLS_TESTS=1`).

### Phase 4: IPAddr + DNS + interface utils (done)
- `IPAddr`/`IPv4`/`IPv6` + `@ip_str` are implemented in `src/sockets/ipaddr.jl` (adapted from stdlib).
- `getalladdrinfo`, `getaddrinfo`, `getnameinfo`, `getipaddrs`, `getipaddr`, `islinklocaladdr` are implemented in `src/sockets/dns.jl`.
- Minimal tests exist in `test/sockets_compat_tests.jl`.

### Future: UDP (explicitly deferred)
- Only revisit after TCP + LOCAL + TLS parity is stable.

---

## Open Questions / Follow-ups (Non-blocking)

1. Scope: confirm TCP + LOCAL + TLS first, with UDP/multicast deferred.
2. Type compatibility: do we want `Reseau.Sockets.IPAddr` to match stdlib's printed form/ordering exactly (it is currently adapted from stdlib, but not identical in module identity)?
3. Error types: should `DNSError` carry libc/winsock `EAI_*` codes (current behavior) or Reseau-native error codes?
5. macOS: do we want to force POSIX sockets for IP traffic initially (for more predictable `fd`/`getsockname`), or embrace Network.framework and accept small behavioral differences?
5. Future modules: if we want more public organization, candidates are `Reseau.TLS` and `Reseau.PKI` (today those live under `Reseau` directly).
