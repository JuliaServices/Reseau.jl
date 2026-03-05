# Action Items: Windows parity follow-up and README rewrite

## Context
- Repo: Reseau.jl
- Worktree: /Users/jacob.quinn/.julia/dev/Reseau
- Branch: windows-iocp-socketops-support

## Items

### [ ] ITEM-001 (P0) Implement Windows ConnectEx/AcceptEx parity
- Description: Replace the remaining plain Winsock connect/accept paths with Go-style extension-function based ConnectEx/AcceptEx flows so Windows uses real overlapped completion-driven operations instead of readiness/backoff emulation.
- Desired outcome: Windows TCP connect/accept logic uses ConnectEx/AcceptEx where appropriate, integrates with IOCP cleanly, and eliminates the current listener backoff workaround.
- Affected files: `src/2_socket_ops_windows.jl`, `src/3_internal_poll.jl`, `src/4_tcp.jl`, `src/1_eventloops_iocp.jl`, relevant tests
- Implementation notes:
  - Investigate current SocketOps/TCP/InternalPoll flow and identify insertion points for extension-function based connect/accept helpers.
  - Mirror Go's logical flow for socket creation, pre-bind requirements, address update calls, and completion handling while keeping Julia-specific exception semantics.
  - Remove the Windows accept polling/backoff path once AcceptEx-backed readiness is in place.
- Verification:
  - `julia --project=. test/runtests.jl`
  - Targeted Windows CI run for the full suite
- Assumptions:
  - Existing IOCP poller structure can support the extension-function completions without redesigning the whole backend.
  - ITEM-001 will land the real `ConnectEx`/`AcceptEx` flow first; IOCP completion-mode optimization stays in ITEM-002 so the behavior change is easier to validate incrementally.
- Completion criteria:
  - Windows no longer relies on the current accept backoff path and the suite passes on Windows.

### [ ] ITEM-002 (P1) Align Windows completion behavior and resolver parity
- Description: Close the remaining Windows-specific parity gaps, including any justified completion-mode optimization and the single-thread resolver race disable.
- Desired outcome: Windows behavior matches the Go reference more closely for completion delivery and host resolution semantics without retaining temporary platform-specific restrictions.
- Affected files: `src/2_socket_ops_windows.jl`, `src/5_host_resolvers.jl`, related tests/docs
- Implementation notes:
  - Add any safe completion notification mode configuration analogous to Go if it fits the Julia design.
  - Revisit and remove the single-thread Windows Happy Eyeballs disable if the stabilized stack no longer needs it.
  - Extend or adjust tests to cover the corrected behavior.
- Verification:
  - `julia --project=. test/runtests.jl`
  - Targeted Windows CI run for resolver/integration paths
- Assumptions:
  - The remaining resolver restriction is compensating for earlier Windows instability and can be removed after the socket/poller changes land.
- Completion criteria:
  - Windows-specific behavior drift is either removed or explicitly justified in code comments/tests.

### [ ] ITEM-003 (P1) Remove leftover artifacts and document the current package
- Description: Clean up residual no-op debug helpers from the Windows investigation cycle and rewrite the README so it accurately reflects the current package layout, major entry points, examples, and Windows compiled-binary guidance.
- Desired outcome: Source is free of stale debug scaffolding and README.md provides an accurate, polished overview of the current Reseau stack.
- Affected files: `src/4_tcp.jl`, `src/5_host_resolvers.jl`, `src/76_http_client.jl`, `README.md`, any other touched docs/tests
- Implementation notes:
  - Remove or inline any leftover no-op debug helpers that no longer serve a purpose.
  - Rewrite README.md around the modern package structure: TCP, TLS, HTTP/1, HTTP/2, event loops, host resolution, benchmarks/tests, and trim/bundle note for Windows.
  - Include example entry points for common client/server usage.
- Verification:
  - `julia --project=. test/runtests.jl`
  - Manual README spot-check for example accuracy against exported APIs
- Assumptions:
  - README examples can stay concise and should prefer currently exported/public entry points over internal modules.
- Completion criteria:
  - README is current and readable, and artifact/debug cleanup leaves no dead helper remnants behind.

## Itemizer continuity block

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
