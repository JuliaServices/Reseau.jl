# HTTP Extraction Inventory

## Scope
- Source of truth for the new HTTP 2.0 implementation: `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_http.jl` and its included files.
- Target package shell to replace: `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree` based on `HTTP/master`.
- Lower-level networking substrate that remains in `Reseau`: `EventLoops`, `IOPoll`, `SocketOps`, `TCP`, `HostResolvers`, and `TLS`.

## Move From Reseau To HTTP

### Source modules
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_http.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_0_http_core.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_1_http1.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_2_hpack.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_3_http2.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_4_http2_client.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_6_http_client.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_6_http_cookies.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_6_http_forms.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_6_http_proxy.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_6_http_request_bodies.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_6_http_retry.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_6_http_sniff.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_6_http_sse.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_6_http_stream.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_6_http_websocket_codec.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_6_http_websockets.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_7_http_handlers.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_7_http_server.jl`

### Test modules and fixtures
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/hpack_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http1_wire_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http2_client_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http2_frame_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http2_server_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_client_proxy_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_client_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_client_transport_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_cookie_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_core_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_forms_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_handlers_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_integration_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_parity_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_retry_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_server_http1_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_trim_safe.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_websocket_autobahn.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_websocket_client_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_websocket_codec_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_websocket_integration_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http_websocket_server_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/trim_compile_tests.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/resources/unittests.crt`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/resources/unittests.key`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/websockets/config/fuzzingclient.json`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/websockets/config/fuzzingserver.json`

### Precompile and mixed-ownership notes
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/8_precompile_workload.jl` is mixed.
- Keep in `Reseau`: event loop, internal poll, socket ops, TCP, host resolver, and TLS workloads.
- Move or recreate in `HTTP`: the portions that exercise `HT = HTTP`, including `_PCHTTPChunkConn`, `_pc_wait_http_server_addr`, HTTP request/response parsing, client/server paths, websocket paths, and any HTTP/2 or cookie/form workloads.
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/trim_compile_tests.jl` is mixed.
- Keep in `Reseau`: non-HTTP trim cases for event loops, socket ops, TCP, host resolvers, and TLS.
- Move or recreate in `HTTP`: only the `http_trim_safe.jl` compile/trim workload.
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/resources/unittests.crt` and `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/resources/unittests.key` are shared fixtures.
- Re-home copies into `HTTP` instead of moving the originals, because `Reseau` TLS tests still use them.

## Keep In Reseau
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/1_eventloops.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/2_socket_ops.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/3_internal_poll.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/4_tcp.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/5_host_resolvers.jl`
- `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/6_tls.jl`
- Non-HTTP tests under `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/`:
  - `eventloops_tests.jl`
  - `internal_poll_tests.jl`
  - `socket_ops_tests.jl`
  - `tcp_tests.jl`
  - `host_resolvers_tests.jl`
  - `tls_tests.jl`
  - trim-safe variants for the remaining non-HTTP layers

## HTTP Package Boundary After Extraction
- `HTTP` should depend on `Reseau` for lower-level transport and TLS behavior instead of duplicating those layers.
- Direct `Reseau` dependencies visible in the extracted source:
  - `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_4_http2_client.jl` uses `Reseau.TCP`, `Reseau.HostResolvers`, `Reseau.TLS`, and `Reseau.IOPoll`.
  - `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_6_http_client.jl` uses `Reseau.TCP`, `Reseau.HostResolvers`, and `Reseau.TLS`.
  - `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_6_http_proxy.jl` uses `Reseau.HostResolvers`.
  - `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_7_http_server.jl` uses `Reseau.TCP`, `Reseau.TLS`, `Reseau.HostResolvers`, and `Reseau.IOPoll`.
  - `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_6_http_websockets.jl` imports transport-facing names that should remain reachable through the package boundary after the move.
- Private helper leak to resolve during extraction:
  - `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_6_http_proxy.jl` currently reaches into `HostResolvers._parse_ipv4_literal` and `HostResolvers._parse_ipv6_literal`.
  - The split should replace that with either a public `Reseau` helper or an HTTP-local implementation.
- Non-`Reseau` package deps used by the extracted stack and likely needed in `HTTP` 2.0:
  - `Base64`
  - `CodecZlib`
  - `Dates`
  - `EnumX`
  - `JSON`
  - `PrecompileTools`
  - `Random`
  - `SHA`
  - `URIs`
  - `UUIDs`

## Replace In HTTP Master

### Replace-all source tree
- Treat the current 1.x source tree under `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/` as replace-all.
- Legacy implementation files to delete or overwrite include:
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/HTTP.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/Conditions.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/Connections.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/Exceptions.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/Handlers.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/IOExtras.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/Messages.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/Pairs.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/Parsers.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/SSE.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/Servers.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/StatusCodes.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/Streams.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/Strings.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/WebSockets.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/clientlayers/**`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/cookiejar.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/cookies.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/download.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/multipart.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/parsemultipart.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/parseutils.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/precompile.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/sniff.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/status_messages.jl`

### Replace-all test tree
- Treat the current 1.x test tree under `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/` as replace-all.
- Replace:
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/runtests.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/*.jl`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/resources/**`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/websockets/**`
- One likely keep/recompare area: the Autobahn config files under `test/websockets/config/`, but only if they match the extracted `Reseau` versions.

### Replace-all docs content
- Keep only the Documenter shell under `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/`.
- Rewrite:
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/src/index.md`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/src/client.md`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/src/server.md`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/src/websockets.md`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/src/reference.md`
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/examples/**`
- Replace the old docs generation logic in `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/make.jl` with a 2.0-specific page tree and doctest/deploy configuration.

## Keep As Scaffolding In HTTP Master
- `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/Project.toml`
  - Keep package identity: `name`, `uuid`, `authors`.
  - Replace `version`, deps, compat, extras, and targets for 2.0.
- `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/.github/workflows/TagBot.yml`
- `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/.github/workflows/previews-cleanup.yml`
- `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/.github/workflows/ci.yml`
  - Keep only as workflow scaffolding; rewrite matrix/test/docs commands for 2.0.
- `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/Project.toml`
- `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/make.jl`
  - Keep only the core `Documenter`/`deploydocs` pattern.

## Immediate Implementation Implications
- `HTTP/master` can be safely treated as a generated-style shell plus repo metadata; `src/`, `test/`, and `docs/` should be replaced wholesale in the execution worktree.
- The extraction should preserve a clean package boundary: `HTTP` owns the HTTP implementation and tests; `Reseau` owns the transport/runtime/TLS layers.
- The extraction is not a no-dependency split. `HTTP` 2.0 should continue to call into `Reseau` for transport and TLS behavior through explicit package dependencies.
- The extraction has at least one private cross-package hotspot to fix: the proxy layer's use of `HostResolvers._parse_ipv4_literal` and `HostResolvers._parse_ipv6_literal`.
