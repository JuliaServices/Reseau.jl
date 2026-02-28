# Action Items: kqueue parity hardening from deep review

## Context
- Repo: Reseau
- Worktree: /Users/jacob.quinn/.julia/dev/Reseau-kqueue-review
- Branch: codex/kqueue-parity-review

## Items

### [x] ITEM-001 (P0) Ensure kqueue unsubscribe cleanup always runs
- Description: Off-thread kqueue unsubscribe cleanup can be skipped when the scheduled unsubscribe task is canceled during shutdown, leaving registry/count state stale.
- Desired outcome: Cleanup logic runs regardless of cancellation status (or equivalent guaranteed path), so registry entries and connection counts are never leaked.
- Affected files: `src/eventloops/apple/kqueue_event_loop.jl`, `test/event_loop_tests.jl`
- Implementation notes:
  - Rework `kqueue_unsubscribe_task_callback` so cancellation skips only kernel `EV_DELETE`, not cleanup.
  - Add regression test that forces pending off-thread unsubscribe cleanup task cancellation during close and asserts cleanup invariants.
  - Keep logic aligned with aws-c-io's cleanup invariants (cleanup task semantics should not depend on status).
- Verification:
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false, test_args=["event_loop_tests"])'`
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'include("test/event_loop_tests.jl")'`
- Assumptions:
  - The test can deterministically trigger cancellation via event-loop shutdown timing without nondeterministic flakes.
  - No additional API surface is required; fix remains internal.
  - Investigation note: direct invocation of `kqueue_unsubscribe_task_callback(..., CANCELED)` is sufficient to validate cleanup semantics without flaky timing races.
- Risks:
  - Race-sensitive behavior may need careful synchronization in tests.
- Completion criteria:
  - New regression test passes.
  - kqueue cleanup invariants hold after forced cancellation path.
- Verification evidence:
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Test; using Reseau; import Reseau: Threads, EventLoops, Sockets; include(\"test/event_loop_tests.jl\")'` (pass: `Event Loops | 66/66`).
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false, test_args=[\"event_loop_tests\"])'` (pass: `Testing Reseau tests passed`).

### [x] ITEM-002 (P0) Validate kqueue subscribe event masks
- Description: kqueue subscribe path currently accepts empty/invalid event masks; aws-c-io expects read/write bits to be present.
- Desired outcome: kqueue subscribe rejects invalid masks with a deterministic error and has test coverage.
- Affected files: `src/eventloops/apple/kqueue_event_loop.jl`, `test/event_loop_tests.jl`
- Implementation notes:
  - Add explicit event-mask guard in `subscribe_to_io_events!` for `READABLE|WRITABLE`.
  - Add kqueue-specific test for invalid mask (`0`) and ensure expected error code.
  - Keep behavior consistent with epoll/iocp argument-validation style where applicable.
- Verification:
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false, test_args=["event_loop_tests"])'`
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'include("test/event_loop_tests.jl")'`
- Assumptions:
  - `ERROR_INVALID_ARGUMENT` is the correct error code for invalid subscription mask in this package.
- Risks:
  - Cross-platform tests may need per-platform gating to avoid false failures.
- Completion criteria:
  - Invalid mask is rejected on kqueue path.
  - New test passes and no regressions in event loop tests.
- Verification evidence:
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Test; using Reseau; import Reseau: Threads, EventLoops, Sockets; include(\"test/event_loop_tests.jl\")'` (pass: `Event Loops | 70/70`).
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false, test_args=[\"event_loop_tests\"])'` (pass: `Testing Reseau tests passed`).

### [x] ITEM-003 (P1) Harden kqueue close invariants and add regression tests
- Description: kqueue close path does not explicitly enforce/sweep active subscription invariants; leaks could be silent if callers close with active subscriptions.
- Desired outcome: close is robust when handles remain subscribed, and tests cover that state.
- Affected files: `src/eventloops/apple/kqueue_event_loop.jl`, `test/event_loop_tests.jl`
- Implementation notes:
  - Add explicit registry/handle cleanup sweep in `close` for any residual `handle_registry` entries.
  - Ensure `connected_handle_count` and per-handle refs (`additional_data`, `additional_ref`, registry key) are normalized.
  - Add regression test closing loop with active subscription and asserting post-close cleanup state.
- Verification:
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false, test_args=["event_loop_tests"])'`
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'include("test/event_loop_tests.jl")'`
- Assumptions:
  - Explicit cleanup-on-close is preferred to introducing strict asserts that could break existing callers.
- Risks:
  - Close-path changes can impact shutdown ordering and cancellation behavior.
- Completion criteria:
  - Active-subscription close test passes.
  - No stale handle registry entries remain after close.
- Verification evidence:
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Test; using Reseau; import Reseau: Threads, EventLoops, Sockets; include(\"test/event_loop_tests.jl\")'` (pass: `Event Loops | 71/71`).
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false, test_args=[\"event_loop_tests\"])'` (pass: `Testing Reseau tests passed`).

### [x] ITEM-004 (P1) Add serialized scheduling stress parity coverage for kqueue
- Description: Reseau lacks a kqueue-focused high-volume serialized cross-thread scheduling parity test equivalent in spirit to aws-c-io's stress case.
- Desired outcome: kqueue path has a robust ordering test under concurrent scheduling pressure.
- Affected files: `test/event_loop_tests.jl`
- Implementation notes:
  - Add macOS-gated stress test combining external-thread and event-loop scheduling.
  - Verify submission order equals execution order for serialized tasks.
  - Keep runtime bounded for CI stability.
- Verification:
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false, test_args=["event_loop_tests"])'`
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'include("test/event_loop_tests.jl")'`
- Assumptions:
  - Existing serialized APIs are intended to preserve global ordering across concurrent producers.
- Risks:
  - Overly aggressive stress size may create flaky runtime behavior.
- Completion criteria:
  - New kqueue serialized stress test passes consistently.
- Verification evidence:
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Test; using Reseau; import Reseau: Threads, EventLoops, Sockets; include(\"test/event_loop_tests.jl\")'` (pass: `Event Loops | 72/72`).
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false, test_args=[\"event_loop_tests\"])'` (pass: `Testing Reseau tests passed`).

### [x] ITEM-005 (P1) Run full test matrix locally and stabilize failures
- Description: All Reseau tests must pass before PR.
- Desired outcome: Full local test matrix passes for this worktree.
- Affected files: `test/` (as needed), source files from prior items
- Implementation notes:
  - Run default suite.
  - Run network-only, TLS-only, and TLS+network variants.
  - Fix/iterate until all combinations pass.
- Verification:
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'`
  - `RESEAU_RUN_NETWORK_TESTS=1 JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false)'`
  - `RESEAU_RUN_TLS_TESTS=1 JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false)'`
  - `RESEAU_RUN_TLS_TESTS=1 RESEAU_RUN_NETWORK_TESTS=1 JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false)'`
- Assumptions:
  - Environment has outbound network and TLS test prerequisites available.
- Risks:
  - Network/TLS flakiness may require reruns and targeted hardening.
- Completion criteria:
  - All four matrix commands pass.
- Verification evidence:
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'` (pass: `Testing Reseau tests passed`).
  - `RESEAU_RUN_NETWORK_TESTS=1 JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false)'` (pass: `host resolver default dns lookups (network)` and `Testing Reseau tests passed`).
  - `RESEAU_RUN_TLS_TESTS=1 JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false)'` (pass: `TLS network tests skipped`, TLS suites pass, `Testing Reseau tests passed`).
  - `RESEAU_RUN_TLS_TESTS=1 RESEAU_RUN_NETWORK_TESTS=1 JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false)'` (pass: `TLS network negotiation (requires network)` and `Testing Reseau tests passed`).

### [x] ITEM-006 (P1) Open PR and ensure CI passes on all platforms
- Description: User requested PR creation and confirmation that all CI platform checks pass.
- Desired outcome: PR is open against `main`, all required checks complete successfully, and status/report is provided.
- Affected files: `.github/workflows/*` (only if CI fix required), PR metadata
- Implementation notes:
  - Push branch.
  - Create PR with summary, testing, and parity context.
  - Monitor GitHub Actions runs (macOS/Linux/Windows) and fix any failures until green.
- Verification:
  - `gh auth status --hostname github.com`
  - `git push -u origin codex/kqueue-parity-review`
  - `gh pr create --base main --head codex/kqueue-parity-review --title "..." --body-file ...`
  - `gh pr checks <pr-number> --watch`
  - `gh run list --branch codex/kqueue-parity-review`
- Assumptions:
  - GitHub authentication and push permissions are available from this environment.
- Risks:
  - CI may surface pre-existing unrelated failures; must distinguish and handle.
- Completion criteria:
  - PR exists with correct description.
  - CI checks are passing across configured platforms.
- Verification evidence:
  - `gh auth status --hostname github.com` (pass: authenticated as `quinnj`).
  - `git push -u origin codex/kqueue-parity-review` (pass: branch pushed).
  - `gh pr create --base main --head codex/kqueue-parity-review --title \"Harden kqueue parity and coverage\" --body-file /tmp/reseau-kqueue-pr.md` (pass: PR opened: `https://github.com/JuliaServices/Reseau.jl/pull/49`).
  - `gh pr checks 49 --watch --interval 30` (pass: `Julia 1.12 - macOS-latest - aarch64 - pull_request`, `Julia 1.12 - ubuntu-latest - x64 - pull_request`, `Julia 1.12 - windows-latest - x64 - pull_request`).

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
