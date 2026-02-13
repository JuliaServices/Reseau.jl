# Happy Eyeballs v2 Work Plan

Status legend: [ ] pending, [x] done, [~] blocked/needs-more-info

## Design
- Implement RFC 8305 Happy Eyeballs v2 behavior end-to-end for client connection setup in Reseau:
  - Sort resolved destination addresses to follow family preference + interleaving behavior.
  - Stagger connection attempts with a configurable default delay between families.
  - Cancel pending attempts after first successful connection.
- Keep behavior consistent with existing resolver cache/failure accounting where possible.

## Step 1 — Baseline and spec-backed design
- [x] Confirm RFC 8305 interpretation for code paths in `src/sockets/io/host_resolver.jl` and `src/sockets/io/channel_bootstrap.jl` (sections 3, 4, 5).
- [x] Download RFC 8305 locally for reference while working (`rfc8305.txt`).
- [x] Document target changes, boundaries, and acceptance criteria in this file.

## Step 2 — Resolver replacement for address ordering
- [x] Implement Happy Eyeballs-aware address ordering at the source (`src/sockets/io/host_resolver.jl`).
- [x] Replace callback address selection with an order that interleaves families (prefers IPv6 first, then alternates per RFC 8305 configurable first-address-family count).
- [x] Preserve existing cache/failure tracking behavior so existing resolver semantics remain stable.

## Step 3 — Connection attempt orchestration update
- [x] Replace immediate “fire all attempts” behavior in `src/sockets/io/channel_bootstrap.jl` with scheduled staggered attempts.
- [x] Add per-request tracking for pending attempt tasks.
- [x] Cancel pending attempt tasks when a connection succeeds.
- [x] Add explicit scheduling logs and task cancellation hooks to avoid orphaned scheduled connection attempts.
- [x] Emit/maintain logging at TRACE/DEBUG for scheduling and cancellation behavior.

## Step 4 — Test expansion
- [x] Add unit coverage for resolver family ordering and config normalization.
- [x] Add integration-style coverage proving delayed staggered attempts and cancellation behavior in bootstrap scheduling.
- [x] Keep all tests executable on non-networked CI-safe runners.

## Step 5 — Validation
- [x] Run full Reseau tests on local worktree and confirm green.
- [x] Run AwsHTTP local tests (`/Users/jacob.quinn/.julia/dev/AwsHTTP`).
- [x] Run HTTP local tests (`/Users/jacob.quinn/.julia/dev/HTTP`).

## Step 6 — Merge readiness
- [ ] Update changelog/docs if needed.
- [x] Open PR (https://github.com/JuliaServices/Reseau.jl/pull/25)
- [ ] Ensure CI green across the 3 platforms.
