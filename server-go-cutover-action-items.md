# Action Items: Go-Inspired HTTP Server Cut-Over

## Context
- Repo: Reseau
- Worktree: /Users/jacob.quinn/.julia/dev/Reseau
- Branch: codex/server-go-cutover

## Items

### [x] ITEM-001 (P0) Build the new Go-inspired server kernel
- Description: Replace the existing ad hoc HTTP server lifecycle in `src/7_7_http_server.jl` with a fresh server kernel modeled on Go's `net/http` machinery. The new kernel should own listener tracking, active connection tracking, connection-state transitions, graceful shutdown vs force-close semantics, actual bound-address tracking, and accept-loop behavior. This item should intentionally retire the old `Server` implementation instead of layering on top of it.
- Desired outcome: A new internal server core exists that is shaped around Go-like `Serve`, `Close`, `Shutdown`, tracked listeners, tracked connections, and explicit connection state, with no dependency on the old HTTP/1 server implementation. The public server object should support `close(server)`, `forceclose(server)`, `wait(server)`, `isopen(server)`, and `port(server)` semantics that will later back `listen`/`serve`.
- Affected files: `src/7_7_http_server.jl`, `src/7_http.jl`, `test/http_server_http1_tests.jl`, `test/runtests.jl`, `src/8_precompile_workload.jl`
- Implementation notes:
  - Design a new concrete server type with Go-like lifecycle fields: listener(s), active connection set, serve task, state atomics, shutdown bookkeeping, and bound address/port.
  - Introduce connection-state tracking and internal state transitions for new/active/idle/closed, with room for future upgraded or hijacked states.
  - Implement graceful `Base.close(server)` and immediate `forceclose(server)` separately, following Go's model rather than the current single `shutdown!` behavior.
  - Preserve only the intended public surface; remove obsolete helpers and dead state from the current server implementation.
  - Update or replace existing HTTP/1 server tests to validate the new lifecycle semantics.
- Verification:
  - `julia --project=. --startup-file=no --history-file=no test/http_server_http1_tests.jl`
  - `julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - It is acceptable to do a hard cut-over and delete the current server internals without compatibility shims.
  - HTTP/1 over TCP is the initial target for the new kernel; later items can layer richer protocol behavior on top.
- Completion criteria:
  - The old server lifecycle code is removed or completely superseded.
  - The new server object supports close/forceclose/wait/isopen/port with deterministic tests.
  - Full local tests still pass.
- Verification evidence:
  - `julia --project=. --startup-file=no --history-file=no test/http_server_http1_tests.jl`
  - `julia --project=. --startup-file=no --history-file=no test/runtests.jl`

### [x] ITEM-002 (P0) Add the new server-side stream machinery
- Description: Implement a fresh server-side `HTTP.Stream`-style abstraction that allows incremental request-body reads and incremental response writes on top of the new server kernel. This is required to support HTTP.jl-style `listen`/`listen!` semantics and request-handler adaptation via `streamhandler`.
- Desired outcome: There is a server stream type and related helpers for `startread`, `closeread`, `startwrite`, `closewrite`, `setstatus`, `setheader`, chunked response writes, and trailer emission, all implemented natively on Reseau's HTTP/1 parser/serializer/body abstractions.
- Affected files: `src/7_7_http_server.jl`, `src/7_1_http1.jl`, `src/7_0_http_core.jl`, `test/http_server_http1_tests.jl`, `test/http_integration_tests.jl`
- Implementation notes:
  - Keep client-side `src/7_6_http_stream.jl` separate; do not overload it with server behavior.
  - Build a dedicated server stream type or set of helpers integrated with the new server kernel.
  - Ensure request bodies can be read progressively and response bodies can be streamed progressively.
  - Support chunked responses and response trailers in a way compatible with future stream-mode handlers and router/middleware work.
  - Remove any dead code paths from the old server implementation that are made obsolete by the new stream layer.
- Verification:
  - `RESEAU_TEST_ONLY=http_server_http1_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - It is acceptable to model the public stream behavior after HTTP.jl while implementing it from scratch on top of Reseau internals.
- Completion criteria:
  - Stream-mode request/response exchange works end-to-end in tests.
  - Chunked writes and trailer support have regression coverage.
  - No old dead stream/server helpers remain referenced.
- Verification evidence:
  - `RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `julia --project=. --startup-file=no --history-file=no test/http_server_http1_tests.jl`
  - `julia --project=. --startup-file=no --history-file=no test/runtests.jl`

### [x] ITEM-003 (P0) Expose HTTP.jl-style `listen` / `listen!` / `serve` / `serve!` APIs
- Description: Add the top-level user-facing server APIs modeled on `HTTP.jl origin/master`, while wiring them into the new Go-inspired server kernel rather than copying HTTP.jl internals.
- Desired outcome: `listen`, `listen!`, `serve`, and `serve!` exist with the intended split: `listen*` for stream handlers and `serve*` for request handlers, with `streamhandler` bridging request handlers onto the stream layer. The supported initial keyword surface should be exactly `listenany`, `reuseaddr`, `backlog`, and `stream`.
- Affected files: `src/7_7_http_server.jl`, `src/7_http.jl`, `test/http_server_http1_tests.jl`, `test/http_integration_tests.jl`, `src/8_precompile_workload.jl`
- Implementation notes:
  - Support overloads for `host, port`, `port`, and existing listener objects as appropriate for Reseau's listener types.
  - Implement `serve!(f; stream=false)` as the request-handler wrapper over `listen!`.
  - Add a `streamhandler` helper modeled on HTTP.jl's surface, but implemented on top of the new server stream type.
  - Keep the public keyword surface intentionally narrow for now: `listenany`, `reuseaddr`, `backlog`, `stream`.
  - Ensure the new APIs return the new server object with the expected `close`/`forceclose`/`wait` behavior.
- Verification:
  - `RESEAU_TEST_ONLY=http_server_http1_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - Existing lower-level `Server(...)` construction can be retired or significantly changed as part of the cut-over.
- Completion criteria:
  - The new top-level server APIs exist and are covered by tests.
  - The request-handler and stream-handler split matches the intended `HTTP.jl` semantics.
  - The supported keywords behave correctly.
- Verification evidence:
  - `julia --project=. --startup-file=no --history-file=no test/http_server_http1_tests.jl`
  - `RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `julia --project=. --startup-file=no --history-file=no test/runtests.jl`

### [ ] ITEM-004 (P0) Match core HTTP/1 server correctness behavior
- Description: Add the HTTP/1 correctness behavior that `HTTP.jl` and Go both expect from a production server loop: malformed-request handling, header-size enforcement responses, `Expect: 100-continue`, timeouts, keep-alive decisions, unread-request-body handling, HEAD behavior, and proper response framing.
- Desired outcome: The new server loop returns `400`, `431`, and `408` when appropriate, sends `100 Continue` when required, handles keep-alive vs close correctly, closes or avoids reusing connections when request bodies are unread, and frames responses correctly for fixed-length and chunked bodies.
- Affected files: `src/7_7_http_server.jl`, `src/7_1_http1.jl`, `src/7_0_http_core.jl`, `test/http_server_http1_tests.jl`, `test/http_integration_tests.jl`
- Implementation notes:
  - Use Go's per-connection serve-loop model and timeout/reset behavior as the guide for body/header timing semantics.
  - Ensure `read_timeout_ns` and `read_header_timeout_ns` semantics are actually enforced correctly instead of only partially applied to header reads.
  - Add or expand raw-socket regression tests for malformed requests, header overflows, `Expect: 100-continue`, keep-alive shutdown, unread bodies, and trailer emission.
  - Aggressively remove dead or obsolete error paths from the old server implementation.
- Verification:
  - `RESEAU_TEST_ONLY=http_server_http1_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - For now, HTTP/1 correctness is the required parity target; HTTP/2 server integration can remain separate until the new kernel is stable.
- Completion criteria:
  - Raw protocol behavior matches the intended status codes and connection semantics.
  - Timeout, keep-alive, and unread-body regressions are covered in tests.
  - Full suite stays green.

### [ ] ITEM-005 (P1) Integrate future-proof Go-style lifecycle hooks and prune dead code
- Description: Shape the new server internals so they are ready for later router/middleware, upgraded connections, and richer server functionality, while also pruning the now-obsolete old server code and stale tests. This item should add internal hook points and state plumbing without exposing extra public API yet.
- Desired outcome: The server kernel includes internal support for connection state tracking, graceful-shutdown hooks for future upgraded connections, and clean listener/connection bookkeeping suitable for later HTTP/2 and websocket shutdown integration. Any dead code left over from the old server or the old separate H2 server path should be deleted or isolated.
- Affected files: `src/7_7_http_server.jl`, `src/7_5_http2_server.jl`, `src/7_6_http_websockets.jl`, `test/http2_server_tests.jl`, `test/http_websocket_server_tests.jl`, `src/8_precompile_workload.jl`
- Implementation notes:
  - Add internal-only hook registration or state handling for future upgraded/hijacked connections.
  - Review `src/7_5_http2_server.jl` and decide whether it should be retired, isolated, or partially adapted to the new kernel shape.
  - Review websocket server shutdown interaction and keep it coherent with the new server lifecycle model.
  - Delete or simplify dead helpers and unused test scaffolding that no longer fit the new server design.
- Verification:
  - `RESEAU_TEST_ONLY=http2_server_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `RESEAU_TEST_ONLY=http_websocket_server_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - It is acceptable to reduce or delete obsolete standalone server code paths in preparation for later HTTP/2 unification work.
- Completion criteria:
  - The new kernel has the internal lifecycle shape we want for future work.
  - Dead code from the old server implementation is removed.
  - All affected tests still pass.

### [ ] ITEM-006 (P1) Final polish, docs/precompile updates, PR, and green CI
- Description: Do the final full-suite verification, update any needed docs or precompile workload references for the new server APIs, open the PR, and babysit CI until all checks are green.
- Desired outcome: The branch is reviewable, the action-item file is fully checked off, the full local suite passes, the PR is open with a clear description, and Ubuntu/macOS/Windows CI are all green.
- Affected files: `server-go-cutover-action-items.md`, `src/8_precompile_workload.jl`, `README.md`, `docs/` if needed, `.github` metadata only if strictly required
- Implementation notes:
  - Update the action-item file with completion notes as each item lands.
  - Run the full local test suite after the final item.
  - Open a PR summarizing the hard cut-over and the new server surface.
  - Monitor Actions and fix any platform-specific issues until CI is green.
- Verification:
  - `julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `julia --project=. -e 'using Pkg; Pkg.test()'`
  - CI checks on the opened PR
- Assumptions:
  - No compatibility notes or deprecation shims are needed because this is a hard cut-over.
- Completion criteria:
  - All items are checked off in this file.
  - The PR is open and all CI checks are green.
  - The branch is in a clean, reviewable state.

## Continuity

```text
* Take investigation/review findings and make a detailed, prioritized action item .md file; ensure each action item has enough detail (description, affected files, etc.) that a fresh context/engineer "taking on" the item would understand what needs to be done and where to go to get started and ideally how to verify that it's done
* Start working on the action-item list, for each item:
  * Thoroughly investigate the action item and work involved, state assumptions, do the work, including verification step
  * Work until verification succeeds (i.e. tests pass)
  * Mark the item done in the action item list
  * Commit the work involved for this action item
  * Continue with the same steps on the next action item
* When compacting, the itemizer instructions should be preserved *exactly* to ensure continuity
* The action-item document should very clearly state the repo/worktree where the work should be done
* Post-compaction, if there are unstaged edits in files relating to the current action item, you should assume they were your own edits and should continue directly w/ work without pausing to confirm
* No shortcuts or cutting corners while doing the action item work; each item should be done thoughtfully, carefully, with production-quality effort/work put into it; we're not trying to rush the work here at all and prefer quality, robustness, and thoroughness over "quick wins".
* No backwards compat or unnecessary shims should be included unless specifically requested
```
