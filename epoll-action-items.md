# Action Items: Reseau Epoll Parity Hardening

## Context
- Repo: Reseau
- Worktree: /Users/jacob.quinn/.julia/dev/Reseau-epoll-review
- Branch: codex/epoll-review

## Items

### [x] ITEM-001 (P0) Modernize epoll/pipe FD creation and close-on-exec handling
- Description: The epoll loop currently uses `epoll_create()` and pipe fallback via `pipe()` + `fcntl()`. This works, but leaves known hardening gaps versus modern Linux recommendations (`epoll_create1(EPOLL_CLOEXEC)` and atomic `pipe2(O_NONBLOCK|O_CLOEXEC)`).
- Desired outcome: Prefer atomic CLOEXEC/NONBLOCK creation paths while preserving fallback behavior; keep existing semantics intact.
- Affected files: `src/eventloops/linux/epoll_event_loop.jl`, `src/eventloops/linux/epoll_event_loop_types.jl`, `test/event_loop_tests.jl`
- Implementation notes:
  - Add constants and `ccall` usage for `epoll_create1`, `EPOLL_CLOEXEC`, `pipe2` flags.
  - Prefer `epoll_create1(EPOLL_CLOEXEC)` with fallback to existing path when unavailable/failing in expected ways.
  - Prefer `pipe2(O_NONBLOCK|O_CLOEXEC)` with fallback to current `pipe()+fcntl` path.
  - Keep existing behavior and logging around eventfd preference/fallback.
  - Update/add tests validating the descriptor setup expectations where testable.
- Verification:
  - `cd /Users/jacob.quinn/.julia/dev/Reseau-epoll-review && JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - On non-Linux hosts, Linux/epoll-specific assertions may be conditionally skipped.
  - Preserving current fallback behavior is preferred over strict fail-fast changes.
- Risks:
  - Incorrect errno handling on fallback branches could break startup on older kernels/libcs.
- Completion criteria:
  - FD creation path prefers modern atomic APIs and tests pass.
- Verification evidence:
  - 2026-02-28: `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no test/runtests.jl` passed (exit code 0).

### [x] ITEM-002 (P0) Harden event-loop lifecycle safety semantics
- Description: Findings identified lifecycle risk areas: no explicit self-thread guard in `wait_for_stop_completion`, and potential unsafe teardown sequencing if stop/wait errors occur.
- Desired outcome: Lifecycle operations should be robust, explicit, and safe under error/shutdown races, with behavior documented in code paths.
- Affected files: `src/eventloops/linux/epoll_event_loop.jl`, `test/event_loop_tests.jl`
- Implementation notes:
  - Add explicit guard(s) preventing invalid wait-from-loop-thread usage.
  - Audit and harden `close(event_loop, impl)` sequencing so FD teardown remains safe under exceptional paths.
  - Keep behavior aligned with existing public contract and aws-c-io parity intent.
  - Add/adjust tests for lifecycle edge-cases.
- Verification:
  - `cd /Users/jacob.quinn/.julia/dev/Reseau-epoll-review && JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - It is acceptable to return/throw `ERROR_INVALID_STATE` style errors for invalid wait usage.
- Risks:
  - Lifecycle changes can introduce deadlocks or shutdown flakiness if lock/thread ordering is wrong.
- Completion criteria:
  - Lifecycle edge-case tests pass and code explicitly guards unsafe usage.
- Verification evidence:
  - 2026-02-28: `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no test/runtests.jl` passed (exit code 0).

### [x] ITEM-003 (P1) Close test parity gaps identified in epoll review
- Description: Review found parity gaps versus aws-c-io coverage depth (e.g., destroy-path cancellation thread affinity, high-contention serialized scheduling, explicit epoll-specific contracts).
- Desired outcome: Add targeted regression tests in Reseau covering missing parity scenarios.
- Affected files: `test/event_loop_tests.jl` (and helpers if needed)
- Implementation notes:
  - Add a test that verifies canceled task callbacks run on the event-loop thread in destroy/stop lifecycle paths.
  - Add a higher-contention serialized scheduling test (multi-producer ordering guarantees).
  - Add at least one explicit epoll-only contract test from findings (backend/registration behavior that is currently under-asserted).
  - Keep tests deterministic and CI-friendly.
- Verification:
  - `cd /Users/jacob.quinn/.julia/dev/Reseau-epoll-review && JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - Some tests will be gated to Linux/epoll where platform behavior differs.
- Risks:
  - Overly timing-sensitive tests can create CI flakiness.
- Completion criteria:
  - New parity tests are merged, stable, and passing locally/CI.
- Verification evidence:
  - 2026-02-28: `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no test/runtests.jl` passed (exit code 0).

### [ ] ITEM-004 (P0) Full validation, PR, and CI completion
- Description: After implementation items land, we need end-to-end validation and delivery.
- Desired outcome: Full Reseau test suite passes, PR opened, and all required CI platform checks pass.
- Affected files: repository-wide (no specific code target), `.github/workflows/*` (read-only for CI mapping), `epoll-action-items.md` status updates
- Implementation notes:
  - Run full package tests from repo root.
  - Push branch and open PR with clear summary and test evidence.
  - Monitor CI checks and fix any regressions until all required checks pass.
  - Update this action-item file with final verification evidence.
- Verification:
  - `cd /Users/jacob.quinn/.julia/dev/Reseau-epoll-review && JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'`
  - `gh pr checks <pr-number> --watch`
- Assumptions:
  - GitHub CLI auth and remote push permissions are available in this environment.
- Risks:
  - CI-only platform regressions may require additional iterations.
- Completion criteria:
  - PR is open and all required checks are green.

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
