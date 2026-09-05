# Reseau Agent Notes

Reseau implements a native networking transport stack in Julia. The public
entrypoints are the `TCP`, `UDP`, and `TLS` modules. Keep that surface small;
internal pollers, socket operations, and resolver machinery stay internal.

## Architecture and contracts

- Implementation lives in `src/`; tests start at `test/runtests.jl`.
- Use Go's networking stack as the reference for ownership, call ordering,
  wait/unblock behavior, deadlines, and poller wakeups. A local Go checkout may
  be available at `~/golang`; the relevant source paths are `src/runtime`,
  `src/internal/poll`, `src/net`, and `src/crypto/tls`. Check the reference version
  when investigating a semantic difference.
- Use Base/stdlib `IO` behavior and Sockets signatures as public API references.
  Implement socket and name-resolution operations with native calls; keep the
  package independent of the `Sockets` stdlib internally.
- Preserve supported public contracts. Resolve lifecycle and ownership problems
  at their source instead of adding legacy API shims or wrapper layers.
- Prefer direct arguments and keywords over thin option structs. Keep hot-path
  fields concrete and avoid `Any` or unnecessary dynamic dispatch. Use `@atomic`
  fields on mutable structs instead of introducing `Threads.Atomic`.
- Support `AbstractVector{UInt8}` and views in buffer APIs where the contract
  permits. Keep comments about current behavior and the reasons behind it.

## Validation

CI in `.github/workflows/CI.yml` defines the current Julia versions, thread
counts, platform matrix, and test switches. It covers Linux, macOS, Windows,
and FreeBSD. Platform work follows the change's scope; there is no macOS-first
migration gate.

Run the package tests from the repository root:

```sh
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```

For a focused test file, set `RESEAU_TEST_ONLY` to an exact filename listed in
`test/runtests.jl`. Confirm the selected test actually runs. Use the CI thread
and platform configurations when changes affect scheduling or native calls.

- Exercise real transport behavior, close/wait/deadline interactions, and the
  public entrypoints affected by a change. Precompile and `--trim=safe` checks
  must reach those paths too.
- Investigate tests that stop making progress. Use bounded diagnostics to find
  the blocked operation; avoid fake waits, permanent skips, or production stubs
  that merely suppress a test or compiler failure.
- Keep platform semantics consistent. Document any Julia/compiler limitation and
  the coverage it prevents. Validate affected downstream packages when shared
  behavior changes.
- Report local results and CI results separately, including skipped checks and
  platform coverage that remains unverified.

## Checkout hygiene

Keep `Manifest.toml` out of commits. Preserve user-owned untracked files, local
probes, and working plans. Commit action-item markdown only when requested.
