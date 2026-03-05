# Reseau Agent Notes (Go Rewrite)

This repository is in a full rewrite state.

- Current active code lives in `src/`.
- Archived pre-rewrite code lives in `src_old/`.
- Current active tests live in `test/`.
- Archived pre-rewrite tests live in `test_old/`.

## Rewrite Mandate

Reseau is being rewritten to mirror Go's networking stack architecture and semantics.

Required reference source:

- `~/golang/src/runtime`
- `~/golang/src/internal/poll`
- `~/golang/src/net`
- `~/golang/src/crypto/tls`

All implementation work must directly reference Go's logical flow of:

- data structures and ownership
- function boundaries and call ordering
- wait/unblock/deadline semantics
- event loop behavior and wake mechanisms

## Hard Rules

- No backwards compatibility layers.
- No API shims for legacy Reseau interfaces.
- No partial migration tricks that preserve old behavior.
- Prefer semantic parity with Go over preserving old package behavior.
- Do not add or rely on `Sockets` stdlib dependency; use native socket/name-resolution calls directly.
- Never use `Threads.Atomic` in new code.
- Use `@atomic` fields on `mutable struct` types instead.

## Phase Order

See `golang-rewrite.md` for the authoritative roadmap.

- Phases 1-8: macOS-only implementation (kqueue/POSIX/TLS)
- Phase 9: Linux + Windows expansion (epoll + IOCP)

Do not start Linux/Windows implementation work before macOS phase gates are complete.

## Current Test Entry Point

`test/runtests.jl` is intentionally minimal while the rewrite bootstraps.

Run from repo root:

```sh
cd "$(git rev-parse --show-toplevel)"
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```
