# Action Items: HTTP Response Parity

## Context
- Repo: Reseau
- Worktree: /Users/jacob.quinn/.julia/dev/Reseau
- Branch: jq-http-response-parity

## Items

### [x] ITEM-001 (P0) Introduce the internal client response seam
- Description: The current client stack exposes the transport/body representation too directly inside the high-level request path. `roundtrip!`/`do!` produce `Response{<:AbstractBody}`, and `request(...)` immediately drains that into `ClientResponse`. Before changing public behavior, we need an internal seam that separates wire-level response metadata and raw streaming bodies from high-level response materialization. This should reduce follow-on churn and make `response_stream`, `open`, SSE, and decompression share one implementation path.
- Desired outcome: A new internal representation exists for client-side incoming responses, low-level HTTP/1 and HTTP/2 client execution can produce it, and the high-level request path can consume it without changing external request semantics yet.
- Affected files: `src/70_http_core.jl`, `src/74_http2_client.jl`, `src/76_http_client.jl`, `test/http_client_transport_tests.jl`, `test/http2_client_tests.jl`, `test/http_trim_safe.jl`, `src/8_precompile_workload.jl`
- Implementation notes:
  - Introduce an internal immutable response-head/incoming-response representation for the client path only.
  - Add an adapter from existing low-level parsed/client-managed responses into the new incoming representation so the first item can land without rewriting every transport path at once.
  - Keep `AbstractBody` and existing wire parser/body types internal to the low-level stack.
  - Preserve current connection reuse semantics driven by `ManagedBody` and existing H2 body handling.
  - Keep current high-level request behavior unchanged for this item so later items can refactor from a stable seam.
- Verification:
  - `julia --startup-file=no --project=/Users/jacob.quinn/.julia/dev/Reseau -e 'include("/Users/jacob.quinn/.julia/dev/Reseau/test/http_client_transport_tests.jl")'`
  - `julia --startup-file=no --project=/Users/jacob.quinn/.julia/dev/Reseau -e 'include("/Users/jacob.quinn/.julia/dev/Reseau/test/http2_client_tests.jl")'`
  - `julia --startup-file=no --project=/Users/jacob.quinn/.julia/dev/Reseau -e 'include("/Users/jacob.quinn/.julia/dev/Reseau/test/http_trim_safe.jl")'`
- Assumptions:
  - It is acceptable for the first item to introduce new internal types without changing public request/open APIs yet.
  - Low-level `do!`/`roundtrip!`/`h2_roundtrip!` can continue to use `AbstractBody`-based internals for now.
- Risks:
  - Accidentally changing connection-release behavior on EOF or early close would cause subtle pooling regressions.
  - Introducing the internal seam in the wrong module could make later `open` work harder instead of easier.
- Completion criteria:
  - The client stack has a clear internal incoming-response seam in place.
  - Targeted HTTP/1, HTTP/2, and trim-safe tests pass unchanged.
- Verification evidence:
  - 2026-03-07: `test/http_client_transport_tests.jl` passed locally.
  - 2026-03-07: `test/http2_client_tests.jl` passed locally.
  - 2026-03-07: `test/http_trim_safe.jl` loaded and completed successfully under the package test environment.

### [ ] ITEM-002 (P0) Replace `ClientResponse` with the public high-level response type
- Description: The current public request API returns `ClientResponse`, which duplicates response metadata and diverges from both the existing low-level `Response` model and the desired HTTP parity direction. We want the high-level API to return a single public response type whose `body` field contains the final, user-facing body representation.
- Desired outcome: `request/get/post/...` return the new public `Response{B}` type, `ClientResponse` is removed, and high-level buffered requests return `Response{Vector{UInt8}}` while preserving current semantics around redirects, status exceptions, cookies, and request metadata.
- Affected files: `src/70_http_core.jl`, `src/76_http_client.jl`, `src/7_http.jl`, `test/http_client_tests.jl`, `test/http_parity_tests.jl`, `test/http_integration_tests.jl`, `src/8_precompile_workload.jl`
- Implementation notes:
  - Define the new public response type and any lightweight request-info metadata needed by high-level results.
  - Delete `ClientResponse` and migrate `StatusError` to wrap the new public response type.
  - Update the buffered request path to materialize response bytes through the internal incoming-response seam from ITEM-001.
  - Keep low-level streaming APIs (`do!`, `roundtrip!`, `h2_roundtrip!`) on their existing internal return shape until later items unify around `open`.
  - Update tests and any precompile workload that explicitly expects `ClientResponse`.
- Verification:
  - `julia --startup-file=no --project=/Users/jacob.quinn/.julia/dev/Reseau -e 'include("/Users/jacob.quinn/.julia/dev/Reseau/test/http_client_tests.jl")'`
  - `julia --startup-file=no --project=/Users/jacob.quinn/.julia/dev/Reseau -e 'include("/Users/jacob.quinn/.julia/dev/Reseau/test/http_parity_tests.jl"); include("/Users/jacob.quinn/.julia/dev/Reseau/test/http_integration_tests.jl")'`
- Assumptions:
  - It is acceptable to update the public request return type in one scoped item without keeping a compatibility alias for `ClientResponse`.
- Risks:
  - Tests or downstream helper code may have implicit assumptions about `ClientResponse.body::Vector{UInt8}` or field names.
  - The new public response type should not accidentally become coupled to low-level `AbstractBody` internals.
- Completion criteria:
  - `ClientResponse` no longer exists.
  - High-level request helpers return the new public response type and targeted request tests pass.

### [ ] ITEM-003 (P1) Add `response_stream` and centralize decompression on the consumer pipeline
- Description: `response_stream` and `decompress` should not be special cases bolted onto `request(...)`. They should be different consumers of one shared response reader built over the internal incoming-response/raw-body path. This item adds high-level response streaming, keeps default buffered reads working, and makes decompression apply uniformly to both modes.
- Desired outcome: `request(...; response_stream=...)` streams into caller-owned destinations, default requests still buffer into `Vector{UInt8}`, and `decompress=nothing|true|false` works consistently for buffered and streamed responses.
- Affected files: `src/76_http_client.jl`, `src/70_http_core.jl`, `test/http_client_tests.jl`, `test/http_parity_tests.jl`
- Implementation notes:
  - Introduce a shared internal `IO`-like wrapper over incoming raw response bodies.
  - Normalize response destinations for `nothing`, writable `IO`, and caller-provided byte buffers.
  - Decide and document the returned public response shape for streamed responses (`Response{Nothing}` is the working assumption).
  - Ensure success drains preserve HTTP/1 keep-alive reuse and error paths still close correctly.
  - Keep `decompress` off by explicit request only when `false`; default behavior should auto-decompress gzip.
- Verification:
  - `julia --startup-file=no --project=/Users/jacob.quinn/.julia/dev/Reseau -e 'include("/Users/jacob.quinn/.julia/dev/Reseau/test/http_client_tests.jl"); include("/Users/jacob.quinn/.julia/dev/Reseau/test/http_parity_tests.jl")'`
- Assumptions:
  - Supporting `IO` and mutable byte-buffer destinations is enough for the first parity pass; file-path-string convenience is intentionally out of scope.
  - Returning `Response{Nothing}` for streamed responses is acceptable because the body bytes live in caller-owned destinations.
- Risks:
  - Too-small user buffers need a clear and stable error behavior.
  - Decompression and streaming interactions can easily double-close or partially drain if the IO wrapper ownership is muddled.
- Completion criteria:
  - Response streaming works for IO and byte-buffer sinks.
  - Decompression behavior is shared across buffered and streamed request modes.
  - Targeted request/parity tests pass with new regression coverage.

### [ ] ITEM-004 (P1) Add `HTTP.open` on the shared client stream model
- Description: `HTTP.open` should be the one public API that exposes a live request/response stream object. It should sit on top of the same underlying execution and response-reader pipeline as `request(...)`, not duplicate it.
- Desired outcome: A public `Stream <: IO` exists for request/response streaming, `startread`/read/write/close semantics are defined and tested, and `request(...)` and `open(...)` share the same response reader/decompression machinery where appropriate.
- Affected files: `src/76_http_client.jl`, `src/7_http.jl`, `test/http_client_tests.jl`, `test/http_integration_tests.jl`, `src/8_precompile_workload.jl`
- Implementation notes:
  - Design the public stream object so request writes and response reads have clear lifecycle boundaries.
  - Return header/status metadata as a public response object from the read-start step without buffering the body.
  - Reuse the internal incoming-response seam and response-IO wrapper from earlier items.
  - Keep redirect behavior aligned with the intended `open` semantics; do-block usage should be the primary API.
- Verification:
  - `julia --startup-file=no --project=/Users/jacob.quinn/.julia/dev/Reseau -e 'include("/Users/jacob.quinn/.julia/dev/Reseau/test/http_client_tests.jl"); include("/Users/jacob.quinn/.julia/dev/Reseau/test/http_integration_tests.jl")'`
- Assumptions:
  - We can add `open` without yet supporting every HTTP.jl streaming nuance like upgrades or raw-socket escape hatches.
- Risks:
  - Read/write lifecycle mistakes can leak connections or deadlock response completion.
  - `open` should not fork the client stack into a second implementation of request execution.
- Completion criteria:
  - `HTTP.open` exists, can stream reads and request writes, and shares implementation with the request path.
  - Targeted streaming tests pass.

### [ ] ITEM-005 (P1) Add `sse_callback` on top of the shared response reader
- Description: SSE should be a consumption mode layered on the shared response reader, not a transport-specific special path. The callback API should incrementally parse `text/event-stream` responses, respect decompression, and leave error responses on the regular request path.
- Desired outcome: `request(...; sse_callback=...)` parses SSE events incrementally, rejects incompatible option combinations like `response_stream`, and returns a normal public response with `body === nothing`.
- Affected files: `src/76_http_client.jl`, `src/7_http.jl`, `test/http_client_tests.jl`, `test/http_parity_tests.jl`
- Implementation notes:
  - Add an internal SSE parser/consumer over generic `IO`.
  - Support callback signatures compatible with HTTP.jl-style `f(event)` and `f(stream, event)` if practical.
  - Apply `decompress` before SSE parsing.
  - For non-success responses, bypass SSE parsing and preserve normal `status_exception` behavior.
- Verification:
  - `julia --startup-file=no --project=/Users/jacob.quinn/.julia/dev/Reseau -e 'include("/Users/jacob.quinn/.julia/dev/Reseau/test/http_client_tests.jl"); include("/Users/jacob.quinn/.julia/dev/Reseau/test/http_parity_tests.jl")'`
- Assumptions:
  - Server-side SSE support is out of scope for this item; this item is strictly client parity.
- Risks:
  - UTF-8 and partial-chunk parsing edge cases are easy to get subtly wrong.
  - SSE should not consume error responses incorrectly or interfere with redirect/status logic.
- Completion criteria:
  - `sse_callback` works for valid SSE responses, respects decompression, and has dedicated regression tests.

### [ ] ITEM-006 (P1) Final cleanup, docs, and full-suite verification
- Description: After the client redesign lands, we need to remove dead code, tighten docs, update parity tracking, and run the broader suite so the final state is clean and supportable.
- Desired outcome: The action document and parity notes reflect the new implementation, dead code like old helper paths is gone, and the relevant full test coverage is green.
- Affected files: `http-response-parity.md`, `http-master-parity.md`, `src/76_http_client.jl`, `src/7_http.jl`, `README.md`, `test/`, `docs/` (if present and needed)
- Implementation notes:
  - Remove dead `ClientResponse` references, obsolete helpers, and stale docstrings.
  - Update docs for `request`, `response_stream`, `decompress`, `open`, and `sse_callback`.
  - Record verification evidence in this action file as items finish.
  - Run a broader/full test pass before declaring the series complete.
- Verification:
  - `julia --startup-file=no --project=/Users/jacob.quinn/.julia/dev/Reseau -e 'using Pkg; Pkg.test()'`
- Assumptions:
  - The earlier items will have already added enough targeted regression coverage that the full suite is primarily a final integration check.
- Risks:
  - Dead-code cleanup can accidentally remove helper paths still used by precompile or trim-safe tests.
- Completion criteria:
  - The action list is fully checked off with brief verification notes.
  - Full package tests pass.

## Compaction Continuity Block

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
