# Action Items: POSIX Socket Hardening and Parity Follow-Through

## Context
- Repo: Reseau
- Worktree: /Users/jacob.quinn/.julia/dev/Reseau-posix-socket-review
- Branch: codex/posix-socket-review

## Items

### [x] ITEM-001 (P0) Enforce required POSIX connect/accept inputs and remove crash path
- Description: POSIX `socket_connect_impl` can be called with `event_loop = nothing` and then fail at task scheduling time; POSIX `socket_start_accept_impl` can be called with `on_accept_result = nothing` and then crash at callback invocation.
- Desired outcome: POSIX socket path rejects invalid inputs up-front with deterministic errors and never dereferences nullable callbacks in accept flow.
- Affected files: `src/sockets/linux/posix_socket_impl.jl`, `test/socket_tests.jl`
- Implementation notes:
  - Add explicit `event_loop === nothing` check in POSIX connect implementation.
  - Add explicit `on_accept_result === nothing` check in POSIX start-accept implementation.
  - Add focused regression tests for both invalid-input cases.
- Verification:
  - `julia --project=. test/socket_tests.jl`
- Assumptions:
  - Existing cross-platform API allows nullable values, but POSIX/Winsock implementations are allowed to reject missing required runtime inputs for connect/accept.
- Risks:
  - Some existing callers may have been relying on undefined behavior instead of deterministic errors.
- Completion criteria:
  - Missing-event-loop and missing-accept-callback cases throw expected Reseau errors.
  - `test/socket_tests.jl` passes.
- Verification evidence:
  - `julia --project=. -e 'using Test; using Reseau; import Reseau: Threads, EventLoops, Sockets; include("test/test_utils.jl"); cleanup_test_sockets!(); atexit(cleanup_test_sockets!); include("test/socket_tests.jl")'` passed.

### [x] ITEM-002 (P0) Fix platform portability for path length and poll nfds type
- Description: Endpoint address validation currently uses a fixed non-Windows max of 108 bytes; on Apple/BSD local socket path max is 104. Poll `nfds_t` is currently hard-coded as `Culong`, which is not portable.
- Desired outcome: Platform-sensitive constants/types are used so POSIX path behaves correctly on Linux and Apple/BSD.
- Affected files: `src/sockets/socket/socket.jl`, `src/sockets/linux/posix_socket_impl.jl`, `test/socket_tests.jl`
- Implementation notes:
  - Make `ADDRESS_MAX_LEN` platform-aware for Unix domain sockets (Apple/BSD vs Linux).
  - Introduce an `nfds_t` alias used by `poll` ccall signatures and arguments.
  - Add/update tests for local endpoint max path validation behavior.
- Verification:
  - `julia --project=. test/socket_tests.jl`
- Assumptions:
  - Using `Cuint` for `nfds_t` on Apple/BSD and Linux is safe for supported targets.
- Risks:
  - Over-tightening path validation could break tests using long local socket names.
- Completion criteria:
  - Platform-specific max path checks are deterministic in validation and no silent truncation is possible.
  - Poll calls use a dedicated `nfds_t` alias and tests pass.
- Verification evidence:
  - `julia --project=. -e 'using Test; using Reseau; import Reseau: Threads, EventLoops, Sockets; include("test/test_utils.jl"); cleanup_test_sockets!(); atexit(cleanup_test_sockets!); include("test/socket_tests.jl")'` passed.

### [x] ITEM-003 (P1) Propagate local-endpoint update failures consistently
- Description: `_update_local_endpoint!` currently returns silently on `getsockname()` failure; reference C path treats this as a surfaced error in key flows.
- Desired outcome: Local-endpoint update failure is observable where endpoint updates are semantically required.
- Affected files: `src/sockets/linux/posix_socket_impl.jl`, `test/socket_tests.jl`
- Implementation notes:
  - Return a success/failure indicator from `_update_local_endpoint!` or throw in failure cases.
  - Ensure connect/bind success paths handle failure deterministically (error propagation/logging).
  - Add regression test with controlled failure injection if practical; otherwise add behavior test around expected endpoint availability after bind/connect.
- Verification:
  - `julia --project=. test/socket_tests.jl`
- Assumptions:
  - Existing successful bind/connect tests can be extended to verify endpoint population post-operation.
- Risks:
  - Strict propagation may surface previously hidden transient system failures.
- Completion criteria:
  - Endpoint-update failure path is explicit and tested.
  - `test/socket_tests.jl` passes.
- Verification evidence:
  - `julia --project=. -e 'using Test; using Reseau; import Reseau: Threads, EventLoops, Sockets; include("test/test_utils.jl"); cleanup_test_sockets!(); atexit(cleanup_test_sockets!); include("test/socket_tests.jl")'` passed.

### [ ] ITEM-004 (P1) Add socket-handler EOF and close-propagation regressions
- Description: Reseau lacks direct equivalents of aws-c-io socket-handler EOF-after-peer-hangup and close-propagation tests.
- Desired outcome: EOF and close behavior is directly tested for LOCAL/IPv4/IPv6 socket handler paths.
- Affected files: `test/socket_handler_tests.jl`, `test/test_utils.jl`
- Implementation notes:
  - Add LOCAL/IPv4/IPv6 cases where peer hangup still permits draining buffered data then EOF.
  - Add a close-propagation test verifying expected shutdown/error behavior.
- Verification:
  - `julia --project=. test/socket_handler_tests.jl`
- Assumptions:
  - Existing socket handler harness is sufficient to add these scenarios without large helper refactors.
- Risks:
  - Timing-sensitive tests may be flaky; include robust wait predicates and bounded timeouts.
- Completion criteria:
  - New EOF/close regression tests are present and passing reliably.

### [ ] ITEM-005 (P1) Add large multi-frame socket-handler backpressure regression
- Description: aws-c-io tests large multi-frame payload behavior; Reseau currently has smaller payload/backpressure cases only.
- Desired outcome: Large fragmented payload read/write + backpressure behavior is covered in socket handler tests.
- Affected files: `test/socket_handler_tests.jl`
- Implementation notes:
  - Add a large payload scenario split across multiple frames.
  - Verify read-window increments and final payload integrity.
- Verification:
  - `julia --project=. test/socket_handler_tests.jl`
- Assumptions:
  - Existing read-window controls in tests can support larger payload without helper redesign.
- Risks:
  - Resource-heavy test may increase runtime; keep payload large enough for regression value but not excessive.
- Completion criteria:
  - Multi-frame large payload path is tested and passing.

### [ ] ITEM-006 (P1) Add pinned event-loop callback-affinity regressions
- Description: aws-c-io includes pinned event-loop and DNS-failure callback-thread regressions; Reseau only has partial bootstrap mismatch checks.
- Desired outcome: Callback affinity and failure-path behavior are explicitly covered when event loops are pinned.
- Affected files: `test/channel_bootstrap_tests.jl`, `test/socket_handler_tests.jl` (if needed)
- Implementation notes:
  - Add tests that assert callback execution on expected event-loop thread in success and DNS failure flows.
  - Reuse existing event-loop group helpers and thread-id checks.
- Verification:
  - `julia --project=. test/channel_bootstrap_tests.jl`
- Assumptions:
  - Current test harness can expose event-loop thread identity or equivalent loop-handle identity for assertions.
- Risks:
  - Thread scheduling races can create nondeterminism; use synchronization primitives and explicit waits.
- Completion criteria:
  - Pinned-loop success/failure regressions are present and passing.

### [ ] ITEM-007 (P1) Add channel lifecycle parity regressions (hold/liveness/multi-host timeout)
- Description: aws-c-io has channel lifecycle regression coverage (refcount-delayed cleanup, ELG liveness, multi-host timeout/fallback) that is missing/partial in Reseau.
- Desired outcome: Reseau channel/bootstrap tests cover these lifecycle scenarios explicitly.
- Affected files: `test/channel_tests.jl`, `test/channel_bootstrap_tests.jl`
- Implementation notes:
  - Add regression cases for delayed cleanup semantics.
  - Add ELG liveness behavior test.
  - Add multi-host timeout/fallback integration-style test.
- Verification:
  - `julia --project=. test/channel_tests.jl`
  - `julia --project=. test/channel_bootstrap_tests.jl`
- Assumptions:
  - Existing channel/ELG helpers can model these cases without major refactoring.
- Risks:
  - Potential test flakiness due async timing; prefer deterministic wait predicates.
- Completion criteria:
  - New lifecycle regressions pass and reduce parity gaps against aws-c-io suite.

### [ ] ITEM-008 (P0) Full validation, PR creation, and CI-green confirmation
- Description: After all code/test work, full project validation and PR workflow must complete successfully.
- Desired outcome: Full local tests pass, PR is opened against Reseau, and all CI platform checks are green.
- Affected files: repo-wide (verification and PR metadata)
- Implementation notes:
  - Run full Reseau test suite.
  - Address any failures discovered by full-suite execution.
  - Push branch and open PR with summary of parity improvements and added regressions.
  - Monitor CI to completion; fix issues until all required checks pass.
- Verification:
  - `julia --project=. -e 'using Pkg; Pkg.test()'`
  - `gh pr checks <pr-number> --watch`
- Assumptions:
  - GitHub CLI auth and repo push permissions are available in this environment.
- Risks:
  - Cross-platform CI failures may require additional follow-up commits.
- Completion criteria:
  - Local full suite passes.
  - PR exists and all required CI checks are passing.

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
