# Action Items: HTTP + Reseau Coverage and Julia 1.10 Follow-Up

## Context
- Primary repo: Reseau
- Primary worktree: /Users/jacob.quinn/.julia/dev/Reseau
- Primary branch: jq-reseau-http-perf-pass
- Execution worktree (Reseau): /Users/jacob.quinn/.julia/dev/Reseau-split-worktree
- Execution branch (Reseau): codex/reseau-http-split
- Execution worktree (HTTP): /Users/jacob.quinn/.julia/dev/HTTP-split-worktree
- Execution branch (HTTP): codex/http-2.0-extraction
- Goal: raise both packages above 90% source coverage while recording the Julia floor investigation result: keep the minimum supported Julia version at 1.12 for now.

## Items

### [x] ITEM-001 (P0) Establish fresh Julia 1.10 and coverage baselines
- Description: Both repositories currently target Julia 1.12 in `Project.toml`, both active manifests were generated on Julia 1.12, and the trim-safe tests rely on `Base.Experimental.entrypoint`, which does not exist on Julia 1.10. Before implementation work begins, we need hard baseline evidence for the real runtime blockers and current coverage gaps.
- Desired outcome: We have concrete Julia 1.10 failure modes and fresh source-coverage baselines for both repos, so the next items can target real blockers instead of guessing.
- Affected files: `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/Project.toml`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/**`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/Project.toml`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/**`
- Implementation notes:
  - Reconfirm actual Julia 1.10 blockers by running `instantiate`, `using`, and at least targeted tests under `julia +1.10`.
  - Lower package compat only if the codebase and dependency set genuinely support 1.10.
  - Regenerate manifests under Julia 1.10 or adopt per-version manifest handling so both repos instantiate cleanly on 1.10 and 1.12.
  - Patch trim-safe test entrypoints to avoid calling APIs that are absent on 1.10.
  - Keep test behavior meaningful on 1.10 rather than papering over real failures.
- Verification:
  - `cd /Users/jacob.quinn/.julia/dev/HTTP-split-worktree && julia +1.10 --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); using HTTP; println(HTTP.VERSION)'`
  - `cd /Users/jacob.quinn/.julia/dev/Reseau-split-worktree && julia +1.10 --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); using Reseau'`
  - `cd /Users/jacob.quinn/.julia/dev/HTTP-split-worktree && JULIA_NUM_THREADS=1 julia +1.10 --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false)'`
  - `cd /Users/jacob.quinn/.julia/dev/Reseau-split-worktree && JULIA_NUM_THREADS=1 julia +1.10 --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false)'`
- Assumptions:
  - `Base.Experimental.entrypoint` is a test-only blocker and can be version-gated without changing package runtime semantics.
  - If a dependency or compiler path proves truly incompatible with 1.10, 1.11 is the acceptable fallback only after concrete evidence is captured.
- Risks:
  - Julia 1.10 may expose scheduler or compiler differences in concurrency-heavy tests that did not show up on 1.12.
  - Regenerating manifests may shift package versions and reveal latent compat issues.
- Completion criteria:
  - Both repositories have concrete Julia 1.10 failure evidence and fresh source-coverage baselines recorded in this tracker.
- Verification evidence:
  - Julia `1.10.10` resolution is possible for both repos after re-resolve, so the floor is not blocked purely by package-manager metadata.
  - `Reseau` currently fails on Julia `1.10.10` during precompile/load at [`src/1_eventloops_kqueue.jl:220`](/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/1_eventloops_kqueue.jl#L220) because `@ccall gc_safe = true ...` is 1.12-only syntax.
  - `Reseau` contains 69 `@ccall gc_safe = true` callsites across event loop, socket, resolver, and TLS code.
  - `HTTP` currently fails on Julia `1.10.10` through the same `Reseau` blocker and also has 2 direct `@ccall gc_safe = true` callsites in [`src/7_6_http_proxy.jl`](/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/7_6_http_proxy.jl).
  - `Base.Experimental.entrypoint` is absent on Julia `1.10.10`, and both repos use it in trim-safe test scripts.
  - Fresh Julia `1.12.3` source-coverage baselines are:
    - `Reseau`: `2431/2827 = 85.99%`
    - `HTTP`: `6346/7280 = 87.17%`
  - Lowest-coverage active files from the fresh baselines:
    - `Reseau`: `2_socket_ops_darwin.jl`, `4_tcp.jl`, `1_eventloops_kqueue.jl`, `1_eventloops.jl`, `6_tls.jl`, `5_host_resolvers.jl`
    - `HTTP`: `7_6_http_cookies.jl`, `7_6_http_stream.jl`, `7_6_http_websocket_codec.jl`, `7_6_http_websockets.jl`, `7_3_http2.jl`, `7_6_http_sse.jl`, `7_6_http_proxy.jl`, `7_6_http_request_bodies.jl`, `7_4_http2_client.jl`, `7_7_http_server.jl`, `7_6_http_client.jl`

### [x] ITEM-002 (P0) Close the Julia floor investigation and retain Julia 1.12
- Description: The compatibility investigation needs a definitive outcome so the rest of the work can focus on coverage instead of carrying a speculative older-Julia branch. The question is whether Julia 1.10 or 1.11 can be supported without a larger architectural rewrite of the poller/runtime thread model.
- Desired outcome: We have an evidence-backed decision on the Julia floor, and the code remains aligned with the chosen floor instead of carrying unused compatibility scaffolding.
- Affected files: `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/coverage-julia110-action-items.md`
- Implementation notes:
  - Investigate both syntax-level and runtime-level blockers on Julia 1.10 and 1.11.
  - Confirm whether the dedicated poller thread model can safely block in backend syscalls on pre-1.12 runtimes that lack `@ccall gc_safe = true`.
  - If the investigation shows the floor cannot be lowered cleanly, keep the codebase on Julia 1.12 and remove the exploratory compatibility edits.
- Verification:
  - `julia +1.10 --startup-file=no --history-file=no -e 'println(VERSION)'`
  - `julia +1.11 --startup-file=no --history-file=no -e 'println(VERSION)'`
  - `sample <julia test pid> 1 1`
- Assumptions:
  - Retaining a 1.12 floor is acceptable if older runtimes require a deeper redesign than a compatibility pass.
- Risks:
  - The blocker is architectural enough that partial fixes could leave the codebase with unsupported, misleading compat shims.
- Completion criteria:
  - The tracker records the floor decision and the evidence behind it.
- Verification evidence:
  - Julia `1.10.10` and `1.11.9` both lack `@ccall gc_safe = true`, so blocking backend syscalls cannot use the same GC-safe path as Julia `1.12`.
  - Experimental compatibility branches could make direct targeted probes work, but full package test runs on Julia `1.10.10` and `1.11.9` still deadlocked with the main thread in `jl_gc_wait_for_the_world` while the poller thread sat blocked in `kevent`.
  - A direct sample of the Julia `1.11.9` `Pkg.test` child showed exactly that state: main thread waiting for GC world stop, poller thread blocked in `_backend_poll_once!` at `1_eventloops_kqueue.jl:220`.
  - The user explicitly chose to keep the Julia floor at `1.12` for now after reviewing the investigation.

### [x] ITEM-003 (P0) Keep HTTP aligned with the retained Julia 1.12 floor
- Description: HTTP now follows the Reseau floor decision. No older-Julia compatibility work should be carried in HTTP while Reseau remains 1.12-only.
- Desired outcome: HTTP stays on the same supported Julia floor as Reseau, and the remaining work focuses on coverage and CI on that floor.
- Affected files: `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/coverage-julia110-action-items.md`
- Implementation notes:
  - Record that the HTTP floor stays at Julia 1.12 because it depends directly on Reseau.
  - Do not add compatibility shims in HTTP while the lower-level runtime remains intentionally 1.12-only.
- Verification:
  - `cd /Users/jacob.quinn/.julia/dev/HTTP-split-worktree && sed -n '1,80p' Project.toml`
- Assumptions:
  - HTTP should not claim support for a lower Julia version than Reseau.
- Risks:
  - Diverging floors between HTTP and Reseau would create confusing unsupported combinations.
- Completion criteria:
  - The tracker records that HTTP remains aligned to the retained Julia 1.12 floor.

### [x] ITEM-004 (P1) Drive HTTP source coverage above 90% with targeted regression tests
- Description: HTTP already has a broad suite, but the current source coverage artifacts still leave material gaps in cookies, streaming, proxy, SSE, HTTP/2, and related client/server edge paths. The new target is >90% source coverage, so the remaining uncovered logic needs focused tests, not generic extra traffic.
- Desired outcome: HTTP source coverage exceeds 90% in a fresh local run, and the added tests cover real protocol/control-flow branches that matter for the 2.0 line.
- Affected files: `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/**`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/**`
- Implementation notes:
  - Start from a fresh coverage run to identify current low-coverage files and dead branches after the 1.10 work settles.
  - Add targeted tests for the most weakly covered, high-value paths first.
  - Prefer deterministic unit/integration harnesses over flaky live-network coverage padding.
  - Re-run coverage after each meaningful batch until the package is above 90%.
- Verification:
  - `cd /Users/jacob.quinn/.julia/dev/HTTP-split-worktree && rm -f src/*.cov test/*.cov && JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.develop(path=\"/Users/jacob.quinn/.julia/dev/Reseau-split-worktree\"); Pkg.test(; coverage=true)'`
  - `cd /Users/jacob.quinn/.julia/dev/HTTP-split-worktree && awk 'BEGIN{covered=0; total=0} /^[ \t]*-/ {next} {total++; if ($1+0>0) covered++} END{printf \"HTTP src coverage %d/%d %.2f%%\\n\", covered, total, (total?100*covered/total:0)}' src/*.cov`
- Assumptions:
  - The >90% target is on source files in `src/`, not test files or docs-generated artifacts.
  - The highest-leverage remaining HTTP gaps are the cookie helper/jar utilities plus the stream and SSE helper branches that are still deterministic enough to exercise directly from tests.
  - Direct tests against internal HTTP helper functions are acceptable here when the alternative would be brittle network orchestration solely to hit the same branch.
- Risks:
  - Some remaining branches may be trim/compiler-only or platform-conditional and need version/platform-aware expectations.
- Completion criteria:
  - A fresh local HTTP coverage run on the target Julia version reports source coverage above 90%.
- Verification evidence:
  - Added targeted regression coverage in `test/http_forms_tests.jl`, `test/http_client_proxy_tests.jl`, `test/http2_frame_tests.jl`, `test/http_websocket_codec_tests.jl`, `test/http_cookie_tests.jl`, and `test/http_client_tests.jl`.
  - Verified the expanded targeted suites locally with direct `julia --project=. --startup-file=no --history-file=no test/<file>.jl` runs, including the newly expanded cookie and client coverage files.
  - Fresh full coverage verification passed with:
    - `cd /Users/jacob.quinn/.julia/dev/HTTP-split-worktree && rm -f src/*.cov test/*.cov && JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.develop(path="/Users/jacob.quinn/.julia/dev/Reseau-split-worktree"); Pkg.test(; coverage=true)'`
    - `cd /Users/jacob.quinn/.julia/dev/HTTP-split-worktree && awk 'BEGIN{covered=0; total=0} /^[ \t]*-/ {next} {total++; if ($1+0>0) covered++} END{printf "HTTP src coverage %d/%d %.2f%%\n", covered, total, (total?100*covered/total:0)}' src/*.cov`
  - Final HTTP source coverage after the coverage pass is `6583/7304 = 90.13%`.

### [x] ITEM-005 (P1) Drive Reseau source coverage above 90% with targeted regression tests
- Description: Reseau’s current source coverage is materially below the desired bar, with especially visible room in event loops, Darwin socket ops, TCP, TLS, and host resolver edge paths. The package needs more direct behavioral tests around the Go-style poller/runtime semantics and transport/TLS branches it owns.
- Desired outcome: Reseau source coverage exceeds 90% in a fresh local run while preserving the rewrite mandate and maintaining deterministic test behavior.
- Affected files: `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/**`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/**`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/codecov.yml` if exclusions need auditing
- Implementation notes:
  - Start from a fresh coverage run after the 1.10 compatibility work.
  - Add targeted tests for low-coverage macOS-active source, especially deadline/wake edge cases, sockaddr conversions, resolver parsing, and TLS config/error branches.
  - Keep Linux/Windows phase-9 exclusions honest; do not hide active macOS gaps behind coverage config.
  - Re-run coverage after each meaningful batch until the package is above 90%.
- Verification:
  - `cd /Users/jacob.quinn/.julia/dev/Reseau-split-worktree && rm -f src/*.cov test/*.cov && JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=true)'`
  - `cd /Users/jacob.quinn/.julia/dev/Reseau-split-worktree && awk 'BEGIN{covered=0; total=0} /^[ \t]*-/ {next} {total++; if ($1+0>0) covered++} END{printf \"Reseau src coverage %d/%d %.2f%%\\n\", covered, total, (total?100*covered/total:0)}' src/*.cov`
- Assumptions:
  - The >90% target is for the active `src/` surface that ships today, not archived or intentionally excluded future-phase files.
  - The highest-leverage remaining Reseau gaps are the HostResolvers parser/cache branches, TLS config/version helpers, and a smaller set of event-loop shutdown/timer control paths; the raw Darwin syscall retry branches are less productive for deterministic coverage work.
  - Direct tests of internal helper functions are acceptable for these runtime utilities when the public API does not expose the branch without manufacturing brittle OS-level failure modes.
- Risks:
  - Some event-loop timing branches may need careful harnessing to avoid reintroducing flakiness.
- Completion criteria:
  - A fresh local Reseau coverage run on the target Julia version reports source coverage above 90%.
- Verification evidence:
  - Added targeted regression coverage in `test/eventloops_tests.jl`, `test/tcp_tests.jl`, `test/host_resolvers_tests.jl`, and `test/tls_tests.jl`.
  - Verified the expanded targeted suites locally with direct `julia --project=. --startup-file=no --history-file=no test/<file>.jl` runs for the touched files.
  - Fresh full coverage verification passed with:
    - `cd /Users/jacob.quinn/.julia/dev/Reseau-split-worktree && rm -f src/*.cov test/*.cov && JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=true)'`
    - `cd /Users/jacob.quinn/.julia/dev/Reseau-split-worktree && awk 'BEGIN{covered=0; total=0} /^[ \t]*-/ {next} {total++; if ($1+0>0) covered++} END{printf "Reseau src coverage %d/%d %.2f%%\n", covered, total, (total?100*covered/total:0)}' src/*.cov`
  - Final Reseau source coverage after the coverage pass is `2553/2836 = 90.02%`.

### [ ] ITEM-006 (P1) Keep CI/workflow coverage green on the retained Julia 1.12 floor
- Description: With the Julia floor retained at 1.12, the CI work is now about preserving green 1.12 workflows while the new coverage tests land, not lowering the version matrix.
- Desired outcome: Both repositories keep their main CI test jobs on Julia 1.12 across the intended platforms, with updated coverage-focused test additions remaining green.
- Affected files: `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/.github/workflows/*.yml`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/.github/workflows/*.yml`, possibly docs/test harness files if version-gated behavior is needed
- Implementation notes:
  - Keep the workflow matrices on Julia 1.12.
  - Preserve the branch/dependency bootstrap logic for the split.
  - Ensure any new coverage-focused tests remain stable in CI.
  - Keep docs jobs aligned with the retained Julia floor.
- Verification:
  - `ruby -e 'require \"yaml\"; Dir[\"/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/.github/workflows/*.yml\", \"/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/.github/workflows/*.yml\"].sort.each { |path| YAML.safe_load(File.read(path), permitted_classes: [], aliases: true); puts path }'`
  - Local Julia 1.12 test/docs commands from the other items
- Assumptions:
  - GitHub-hosted runners continue to execute Julia 1.12 on all three primary platforms.
- Risks:
  - Coverage-focused additions may expose platform-specific timing differences even without changing the Julia version matrix.
- Completion criteria:
  - Workflow files remain syntactically valid and continue targeting Julia 1.12.

### [ ] ITEM-007 (P1) Run exhaustive local verification and prepare the follow-up pushes
- Description: After compatibility, coverage, and CI edits land, both repos need a final clean verification pass so the follow-up can be pushed confidently without leaving coverage/math ambiguity or version-specific regressions unresolved.
- Desired outcome: Both repos pass full local tests and docs builds on the chosen Julia floor, fresh coverage is above 90%, and the tracker records the evidence for handoff/review.
- Affected files: `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/**`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/**`, this tracker
- Implementation notes:
  - Re-run full tests and docs with fresh coverage artifacts.
  - Capture final coverage numbers in the tracker.
  - If CI workflows were changed, sanity-check them locally and then push branches.
  - Check hosted CI until both repos are green.
- Verification:
  - `cd /Users/jacob.quinn/.julia/dev/HTTP-split-worktree && JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.develop(path=\"/Users/jacob.quinn/.julia/dev/Reseau-split-worktree\"); Pkg.test(; coverage=true)'`
  - `cd /Users/jacob.quinn/.julia/dev/HTTP-split-worktree && julia --project=docs --startup-file=no --history-file=no docs/make.jl`
  - `cd /Users/jacob.quinn/.julia/dev/Reseau-split-worktree && JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=true)'`
  - `cd /Users/jacob.quinn/.julia/dev/Reseau-split-worktree && julia --project=docs --startup-file=no --history-file=no docs/make.jl`
- Assumptions:
  - Docs toolchains and doctests remain compatible with the selected Julia floor.
- Risks:
  - Coverage-driven additions can expose docs drift or latent platform assumptions late in the cycle.
- Completion criteria:
  - Both repos are locally verified on the target Julia version with source coverage above 90%, and the work is ready to push/check in hosted CI.

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
