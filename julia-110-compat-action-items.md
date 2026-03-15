# Action Items: Julia 1.10 Compatibility Push

## Context
- Repo: Reseau + HTTP
- Worktree: `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree`
- Worktree: `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree`
- Branch: `codex/reseau-http-split`
- Branch: `codex/http-2.0-extraction`

## Items

### [x] ITEM-001 (P0) Land syntax and byte-buffer compat groundwork
- Description: The current 1.10 bring-up work is sitting as unstaged edits in both split worktrees. We need to preserve Julia 1.12 behavior while adding the minimal parsing/runtime compat needed for older Julia versions, specifically the `@ccall gc_safe = true` sites and `Memory{UInt8}` byte-buffer construction sites.
- Desired outcome: Both worktrees load and pass the touched 1.12 smoke tests with a shared compat approach in place, and the 1.10 bring-up is no longer blocked by raw `gc_safe` or raw `Memory` syntax.
- Affected files: `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/0_gcsafe_ccall_compat.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/0_memory_compat.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/Reseau.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/1_eventloops.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/1_eventloops_epoll.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/1_eventloops_iocp.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/1_eventloops_kqueue.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/2_socket_ops.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/2_socket_ops_darwin.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/2_socket_ops_linux.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/2_socket_ops_windows.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/3_internal_poll.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/4_tcp.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/5_host_resolvers.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/6_tls.jl`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/7_6_http_proxy.jl`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/7_6_http_websocket_codec.jl`
- Implementation notes:
  - Keep the existing 1.12 pthread path unchanged.
  - Mirror the JSON-style `VERSION < v"1.11"` byte-buffer gating instead of sprinkling local aliases everywhere.
  - Reuse the `@gcsafe_ccall` macro for all older-Julia `gc_safe` callsites.
- Verification:
  - `julia --project=. --startup-file=no --history-file=no -e 'using Reseau; println("reseau-112-ok")'`
  - `julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.develop(path="/Users/jacob.quinn/.julia/dev/Reseau-split-worktree"); using HTTP; println("http-112-ok")'`
  - `RESEAU_TEST_ONLY=tcp_tests.jl JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `RESEAU_TEST_ONLY=tls_tests.jl JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `HTTP_TEST_ONLY=http_websocket_codec_tests.jl JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `HTTP_TEST_ONLY=http_websocket_client_tests.jl JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - The current unstaged edits belong to this task and should be kept.
  - HTTP can continue importing small compat helpers from Reseau during the extraction branch state.
- Completion criteria:
  - The compat files are in place, the supported 1.12 path still passes the targeted verification, and 1.10 no longer fails first on raw `gc_safe` or `Memory` syntax.
- Verification evidence:
  - `using Reseau` and `using HTTP` both succeed on Julia 1.12 after the compat refactor.
  - `tcp_tests.jl`, `tls_tests.jl`, `http_websocket_codec_tests.jl`, and `http_websocket_client_tests.jl` all pass on Julia 1.12.
  - Julia 1.10 smoke loads now move past raw `@ccall gc_safe = true` and raw `Memory{UInt8}` parsing/runtime failures; the next blocker is package resolution/loading work.

### [x] ITEM-002 (P0) Make both packages resolvable and loadable on Julia 1.10
- Description: After removing the parsing blockers, the next gap is package compatibility and dependency resolution. Both packages still declare `julia = "1.12"`, and the 1.10 smoke currently dies during dependency loading rather than inside package code.
- Desired outcome: Fresh Julia 1.10 environments can `Pkg.develop` the split worktrees, resolve/install dependencies, and `using Reseau` / `using HTTP` succeeds.
- Affected files: `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/Project.toml`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/Project.toml`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/Manifest.toml`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/Manifest.toml` (only if regeneration is required), any source files revealed by 1.10 load failures.
- Implementation notes:
  - Use temporary environments for 1.10 bring-up where possible to avoid unnecessary manifest churn in the repos.
  - Investigate dependency support boundaries before lowering compat bounds.
  - If 1.10 load reveals additional Base API gaps, fix them minimally and keep 1.12 semantics intact.
- Verification:
  - `julia +1.10 --startup-file=no --history-file=no -e 'using Pkg; Pkg.activate(temp=true); Pkg.develop(path="/Users/jacob.quinn/.julia/dev/Reseau-split-worktree"); Pkg.instantiate(); using Reseau; println("reseau-110-ok")'`
  - `julia +1.10 --startup-file=no --history-file=no -e 'using Pkg; Pkg.activate(temp=true); Pkg.develop(path="/Users/jacob.quinn/.julia/dev/Reseau-split-worktree"); Pkg.develop(path="/Users/jacob.quinn/.julia/dev/HTTP-split-worktree"); Pkg.instantiate(); using HTTP; println("http-110-ok")'`
- Assumptions:
  - The needed dependency set has Julia 1.10-compatible releases available.
- Completion criteria:
  - Both packages can be installed and loaded on Julia 1.10 from fresh temporary environments.
- Verification evidence:
  - A fresh Julia 1.10 temp environment can `Pkg.develop` the Reseau split worktree, instantiate dependencies, and `using Reseau` succeeds.
  - A fresh Julia 1.10 temp environment can `Pkg.develop` both split worktrees, instantiate dependencies, and `using HTTP` succeeds.

### [x] ITEM-003 (P0) Get Reseau’s 1.10 test suite green
- Description: Once Reseau loads on 1.10, the full runtime and trim-safe suites need to pass. This will likely expose differences in task scheduling, detached thread startup, libuv/runtime helpers, TLS/OpenSSL behavior, or atomic semantics between 1.10 and 1.12.
- Desired outcome: Reseau’s supported macOS-phase tests pass on Julia 1.10 with the same package semantics we keep on 1.12.
- Affected files: `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/**`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/**`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/Project.toml`
- Implementation notes:
  - Triage failures starting with event loop bootstrap, internal poll, TCP, host resolvers, TLS, and trim-safe verification.
  - Preserve the restored Reseau-specific precompile workload and trim-safe coverage while adapting code for 1.10.
  - Prefer direct compatibility fixes over test-only masking.
- Verification:
  - `JULIA_NUM_THREADS=1 julia +1.10 --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `RESEAU_TEST_ONLY=trim_compile_tests.jl JULIA_NUM_THREADS=1 julia +1.10 --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - Linux/Windows phase-9 code only needs to remain parseable; macOS is the active gating platform in this rewrite state.
  - JuliaC trim compilation is unavailable on Julia 1.10, so the trim-safe suite should skip there rather than pretend verifier coverage exists below the toolchain floor.
- Completion criteria:
  - The Reseau Julia 1.10 test suite passes locally, with trim-safe tests explicitly skipped because JuliaC trim support is unavailable below Julia 1.12.
- Verification evidence:
  - `Pkg.test("Reseau")` from a fresh Julia 1.10 temp environment passes end to end.
  - Event loops, internal poll, socket ops, TCP, host resolvers, and TLS all pass on Julia 1.10.
  - `trim_compile_tests.jl` now skips with an explicit JuliaC/toolchain message on Julia 1.10 instead of failing on a missing CLI entrypoint.

### [ ] ITEM-004 (P0) Get HTTP’s 1.10 test suite green
- Description: HTTP depends on the extracted Reseau transport stack and likely has its own 1.10 issues beyond the websocket `Memory` sites. The full suite needs to pass once HTTP can load on 1.10.
- Desired outcome: HTTP’s Julia 1.10 suite passes end to end against the 1.10-compatible Reseau worktree.
- Affected files: `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/**`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/**`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/Project.toml`
- Implementation notes:
  - Work from targeted failing suites toward the full `test/runtests.jl` aggregate.
  - Keep the extracted HTTP 2.0 behavior intact rather than special-casing 1.10 semantics unless required by Base/runtime differences.
- Verification:
  - `JULIA_NUM_THREADS=1 julia +1.10 --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `HTTP_TEST_ONLY=trim_compile_tests.jl JULIA_NUM_THREADS=1 julia +1.10 --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - Once Reseau is stable on 1.10, HTTP failures will mostly be package-local rather than transport-core regressions.
- Completion criteria:
  - The HTTP Julia 1.10 test suite passes locally, including trim-safe verification.

### [ ] ITEM-005 (P1) Update CI/package metadata for Julia 1.10 support
- Description: Local compatibility is not enough; the package metadata and CI need to reflect the new supported floor so hosted checks can exercise it.
- Desired outcome: Both repos advertise the right Julia floor and run CI on 1.10 without regressing 1.12.
- Affected files: `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/Project.toml`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/.github/workflows/**`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/Project.toml`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/.github/workflows/**`
- Implementation notes:
  - Only lower the declared Julia compat once local verification supports it.
  - Keep the current 1.12-specific pthread behavior intact even if 1.10 uses a compat path.
- Verification:
  - `rg -n '1\.10|1\.12|julia-version|matrix' .github/workflows Project.toml -g'*.yml' -g'*.yaml' -g'Project.toml'`
  - Re-run the key local 1.10 and 1.12 smoke/tests after metadata changes.
- Assumptions:
  - CI changes are only worth landing if Items 1-4 are solid locally.
- Completion criteria:
  - Both packages declare and test the final Julia support floor needed for 1.10.
