# Action Items: HTTP Server Production Readiness

## Context
- Repo: Reseau
- Worktree: /Users/jacob.quinn/.julia/dev/Reseau
- Branch: codex/server-go-cutover

## Items

### [x] ITEM-001 (P0) Fix HTTP/2 handler dispatch and no-body response correctness
- Description: The unified server currently routes all HTTP/2 requests through the request-handler path, even when `server.stream == true`, so `listen! do stream ... end` is broken for h2. The h2 response path also treats only `EmptyBody` as bodyless, which incorrectly sends DATA on `HEAD` and other no-body responses.
- Desired outcome: HTTP/2 request dispatch honors the `serve!` vs `listen!` split, stream-mode handlers work over h2, request-mode handlers keep working, and h2 responses obey no-body rules for `HEAD`, `1xx`, `204`, and `304`.
- Affected files: `src/7_7_http_server.jl`, `test/http2_server_tests.jl`, `test/http_integration_tests.jl`, `test/http_server_http1_tests.jl`
- Implementation notes:
  - Investigate how much of the existing server-side `Stream` API can be reused for h2 without speculative abstraction.
  - Thread `server.stream` through the h2 request lifecycle so stream handlers receive a `Stream` and request handlers continue to receive a `Request`.
  - Decide and implement the minimal correct h2 server-side streaming semantics for request reads and response writes needed for production use now.
  - Enforce no-body response rules in the h2 response writer.
  - Add regression tests for:
    - h2 stream-mode serving
    - h2 `HEAD` responses
    - `204` or `304` body suppression
- Verification:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http2_server_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `julia --project=. --startup-file=no --history-file=no -e 'using Reseau; HT = Reseau.HTTP; server = HT.listen!("127.0.0.1", 0; listenany=true) do stream; HT.startread(stream); HT.setstatus(stream, 200); HT.startwrite(stream); write(stream, "ok"); nothing; end; addr = nothing; deadline = time() + 5; while addr === nothing && time() < deadline; try addr = HT.server_addr(server); catch; sleep(0.01); end; end; conn = HT.connect_h2!(addr; secure=false); try req = HT.Request("GET", "/"; host=addr, body=HT.EmptyBody(), content_length=0, proto_major=2, proto_minor=0); resp = HT.h2_roundtrip!(conn, req); buf = Vector{UInt8}(undef, 16); n = HT.body_read!(resp.body, buf); println((resp.status_code, String(buf[1:n]))); finally try close(conn) catch end; try HT.forceclose(server) catch end; try wait(server) catch end; end'`
- Assumptions:
  - It is acceptable to implement the first h2 stream-handler fix as a buffered server-stream path in the current kernel, with true concurrent/streaming h2 request-body execution deferred to ITEM-002.
  - The current public API shape should be preserved; this item is about making the shipped surface actually work.
- Risks:
  - h2 stream support may expose deeper issues in the h2 frame/state machine that need to be addressed immediately in ITEM-002.
- Completion criteria:
  - `listen!` stream handlers work over h2.
  - h2 no-body responses do not emit DATA frames.
  - The new regression tests pass.
- Verification evidence:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http2_server_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_server_http1_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `julia --project=. --startup-file=no --history-file=no -e 'using Reseau; ...'` direct h2 stream roundtrip returned `(200, "ok")`

### [x] ITEM-002 (P0) Make HTTP/2 stream handling concurrent and connection-safe
- Description: The current h2 path still runs handlers inline on the connection task, so one slow request stalls unrelated streams. That breaks the core multiplexing benefit of h2 even after ITEM-001 fixed stream-handler dispatch.
- Desired outcome: The h2 server can execute multiple request handlers concurrently on one connection, and shared connection writes remain safe when those handlers emit responses at the same time.
- Affected files: `src/7_7_http_server.jl`, `test/http2_server_tests.jl`, `test/http_integration_tests.jl`
- Implementation notes:
  - Decouple frame-read progression from handler execution so one slow stream does not stall unrelated streams.
  - Add or adapt synchronization for response writes once handlers run concurrently.
  - Keep the design direct; do not introduce a speculative scheduler.
  - Add regression tests for concurrent h2 streams on one connection.
- Verification:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http2_server_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - Add a targeted concurrency regression test and run it through `test/runtests.jl`
- Assumptions:
  - Full request-body streaming and receive-side buffering improvements are allowed to land in the next item rather than being forced into the same commit.
- Risks:
  - Once streams run concurrently, response write ordering and shared connection state become much easier to get wrong.
- Completion criteria:
  - Two concurrent h2 requests on one connection no longer serialize behind one another.
  - Tests cover the new concurrency behavior.
- Verification evidence:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http2_server_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - Added `HTTP/2 server handles concurrent streams on one connection` regression coverage in `test/http2_server_tests.jl`

### [x] ITEM-003 (P0) Replace full HTTP/2 request buffering with bounded streaming request-body handling
- Description: The current h2 path still accumulates full request bodies in memory before handler execution. That is both a DoS risk and a major parity miss against Go’s body/flow-control behavior.
- Desired outcome: h2 request bodies are consumed through a bounded streaming body reader, and read-side `WINDOW_UPDATE` credits are tied to actual body consumption instead of unconditional frame receipt.
- Affected files: `src/7_7_http_server.jl`, `test/http2_server_tests.jl`, `test/http_integration_tests.jl`
- Implementation notes:
  - Study the current h2 client body/stream abstractions and Go’s server-side body flow to choose the most direct reusable model.
  - Replace the `body_block` accumulation model with a bounded buffer and a server-side streaming body implementation.
  - Ensure the frame loop does not block the whole connection waiting on one application body read.
  - Add regression tests for:
    - large uploads without pre-buffering the whole request
    - slow request-body consumption without unbounded growth
- Verification:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http2_server_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - We do not need to implement full HTTP/2 priority or push support to fix the request-body path responsibly.
  - Bounding the server-side request-body buffer and returning `WINDOW_UPDATE` on application reads is an acceptable production step even before ITEM-004 tightens the rest of the frame/state machine.
- Risks:
  - Flow-control mistakes here can cause deadlocks or stalls that only show up under stressed tests.
- Completion criteria:
  - Request bodies are not fully materialized before the handler starts.
  - Read-side buffering is bounded and covered by tests.
- Verification evidence:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http2_server_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_server_http1_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - Added `HTTP/2 server starts handling request bodies before upload completion` regression coverage in `test/http2_server_tests.jl`

### [x] ITEM-004 (P0) Implement missing HTTP/2 frame/state validation and flow-control behavior
- Description: The server currently only type-checks the initial `SETTINGS`, ACKs later `SETTINGS`, ignores `WINDOW_UPDATE`, `RST_STREAM`, and `GOAWAY`, and accepts malformed header sets too permissively. That is a correctness and hardening gap against Go.
- Desired outcome: The h2 server validates pseudo-headers and forbidden headers, applies relevant peer settings, processes frame types needed for stable interop, and maintains flow-control state closely enough to behave correctly against stricter peers.
- Affected files: `src/7_7_http_server.jl`, `test/http2_server_tests.jl`, `test/http_integration_tests.jl`
- Implementation notes:
  - Audit the frame loop against Go’s `processSettings`, `processWindowUpdate`, `processResetStream`, `processGoAway`, and request validation paths.
  - Implement only the frame/state machinery needed for production-safe serving now; avoid speculative support for priority or push unless required.
  - Reject invalid pseudo-header shapes and connection-specific headers on requests.
  - Ensure response encoding does not emit illegal h2 headers.
  - Add regression tests for:
    - invalid pseudo-headers
    - forbidden connection-specific headers
    - peer `SETTINGS` and `WINDOW_UPDATE`
    - `RST_STREAM` / `GOAWAY` behavior as appropriate
- Verification:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http2_server_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - It is acceptable to leave HTTP/2 server push unsupported for now unless a dependency emerges while tightening correctness.
- Risks:
  - Tightening validation may expose client-side assumptions in existing tests that were accidentally depending on lax behavior.
- Completion criteria:
  - The server handles the required frame/state transitions without obvious protocol violations.
  - Illegal request/response header patterns are rejected or stripped correctly.
  - Tests cover the new validation behavior.
- Verification evidence:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http2_server_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_server_http1_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - Added raw h2 regression coverage for invalid request headers, `GOAWAY` on protocol errors, response-header filtering, peer `SETTINGS_INITIAL_WINDOW_SIZE`, connection-level `WINDOW_UPDATE`, and `RST_STREAM` continuation of later streams

### [x] ITEM-005 (P1) Restore Go-style shutdown and upgraded-connection lifecycle behavior
- Description: Shutdown behavior is not yet production-ready for h2 or future upgraded/hijacked connections. The current lifecycle does not send `GOAWAY`, h2 connections do not participate in conn-state transitions the same way as h1, and the internal upgraded-connection shutdown path needs to be coherent.
- Desired outcome: `close(server)` behaves as a real graceful shutdown for both h1 and h2, `forceclose(server)` remains the immediate path, h2 connections participate in state tracking, and upgraded/future hijacked connections have a clear shutdown notification path.
- Affected files: `src/7_7_http_server.jl`, `src/7_6_http_websockets.jl`, `test/http2_server_tests.jl`, `test/http_server_http1_tests.jl`, `test/http_websocket_server_tests.jl`, `test/http_websocket_integration_tests.jl`
- Implementation notes:
  - Reconcile the current server lifecycle with Go’s `Shutdown`, `Close`, `closeIdleConns`, and `RegisterOnShutdown` model.
  - Ensure h2 connections transition between `NEW`, `ACTIVE`, `IDLE`, and shutdown states coherently.
  - If upgraded connection shutdown hooks are missing or incomplete, add the minimal internal mechanism needed now.
  - Add tests for graceful shutdown with active vs idle connections and for any upgraded-connection shutdown notification path in use.
- Verification:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_server_http1_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http2_server_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_websocket_server_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_websocket_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - We can keep the public `close(server)` / `forceclose(server)` API while bringing the underlying behavior much closer to Go.
- Risks:
  - Shutdown and upgraded-connection work often exposes races that only show up under repeated test runs.
- Completion criteria:
  - Graceful shutdown no longer relies on h1-only assumptions.
  - h2 shutdown sends the right connection-level signal and drains correctly.
  - Relevant websocket/upgraded connection tests remain green.
- Verification evidence:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_server_http1_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http2_server_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_websocket_server_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_websocket_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - Added graceful-drain coverage for active h1 requests, h2 `GOAWAY` + active-stream drain, and websocket server close notification / handler cleanup

### [x] ITEM-006 (P1) Harden remaining HTTP/1 server edge cases and fill coverage gaps
- Description: HTTP/1 coverage is solid on several paths, but important production edges remain untested or under-implemented, including unsupported `Expect`, no-body response rules, fixed-length response mismatches, and timeout coverage beyond the current happy-path checks.
- Desired outcome: The HTTP/1 server correctly handles the remaining core edge cases expected from a production loop, and the test suite exercises those paths directly.
- Affected files: `src/7_7_http_server.jl`, `test/http_server_http1_tests.jl`, `test/http_integration_tests.jl`
- Implementation notes:
  - Compare the current h1 behavior with Go’s request/response rules around `Expect`, no-body responses, and connection reuse.
  - Prevent malformed fixed-length responses from being emitted silently.
  - Add tests for:
    - unsupported `Expect` behavior
    - `HEAD`/`204`/`304` no-body semantics
    - fixed-length overflow/undershoot handling
    - write timeout and idle timeout behavior if still missing
- Verification:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_server_http1_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - If Go and HTTP.jl differ slightly on a niche h1 edge, prefer the behavior that is safer and more standards-correct unless the public HTTP.jl surface requires otherwise.
- Risks:
  - Tightening fixed-length or timeout handling can uncover existing client-side assumptions.
- Completion criteria:
  - Remaining core h1 edge cases are explicitly tested.
  - Invalid fixed-length writes are caught before corrupting responses on the wire.
- Verification evidence:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_server_http1_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http2_server_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - Added explicit regressions for unsupported `Expect`, `HEAD` / `204` / `304` no-body stream responses, idle timeout, write timeout, and fixed `Content-Length` overflow / underflow handling

### [x] ITEM-007 (P2) Expand platform and parity verification to production-ready confidence
- Description: Even after the server fixes land, the branch still needs broader confidence: key server suites are skipped on Windows, h2 TLS+ALPN servering is not covered, and the parity docs should reflect the actual remaining gap set.
- Desired outcome: The server-focused suites are credible across supported environments, TLS+ALPN h2 serving has regression coverage, and the parity/action-item docs reflect the post-hardening state honestly.
- Affected files: `test/runtests.jl`, `test/http2_server_tests.jl`, `test/http_integration_tests.jl`, `.github/workflows/ci.yml`, `server-production-readiness-action-items.md`, `http-master-parity.md`
- Implementation notes:
  - Add missing TLS+ALPN h2 server tests once the server kernel is ready.
  - Reassess whether Windows skips are still needed for the server-focused suites.
  - Update the parity/action-item documentation once the production-hardening items are complete.
- Verification:
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false)'`
  - Re-run the server-focused suites explicitly if Windows skips remain in place while investigating CI behavior
- Assumptions:
  - Platform-specific issues should be fixed where reasonable, but temporary skips can remain only if clearly justified and documented after the server kernel itself is solid.
- Risks:
  - Some CI issues may turn out to be Julia/compiler problems rather than package bugs; that still needs to be distinguished carefully.
- Completion criteria:
  - The remaining parity gaps are documented accurately.
  - The production-readiness story includes meaningful platform and TLS coverage, not just local happy paths.
- Verification evidence:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_server_http1_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http2_server_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - Updated `http-master-parity.md` to reflect the current server, SSE, and websocket parity state instead of the stale pre-hardening gap list
  - Documented that the remaining Windows server-suite skips in `test/runtests.jl` are a separate compiler issue, not an unresolved server regression
  - GitHub Actions run `22934318567` on PR `#71` completed green on `ubuntu-latest`, `macOS-latest`, and `windows-latest`

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
