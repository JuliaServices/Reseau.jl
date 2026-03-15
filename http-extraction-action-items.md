# Action Items: Reseau HTTP Extraction Split

## Context
- Primary repo: Reseau
- Primary worktree: /Users/jacob.quinn/.julia/dev/Reseau
- Primary branch: jq-reseau-http-perf-pass
- Secondary repo: HTTP
- Secondary worktree: /Users/jacob.quinn/.julia/dev/HTTP
- Secondary branch: merge-awhttp-internals
- Execution worktree (Reseau): /Users/jacob.quinn/.julia/dev/Reseau-split-worktree
- Execution branch (Reseau): codex/reseau-http-split
- Execution worktree (HTTP): /Users/jacob.quinn/.julia/dev/HTTP-split-worktree
- Execution branch (HTTP): codex/http-2.0-extraction
- Execution note: perform destructive package resets and extraction work in fresh linked worktrees created from `Reseau/jq-reseau-http-perf-pass` and `HTTP/master` so the current dirty checkouts remain untouched.

## Items

### [x] ITEM-001 (P0) Establish clean execution worktrees and branches
- Description: Create dedicated linked worktrees for the split so the in-place `Reseau` and `HTTP` checkouts are preserved. Capture the exact branch points and ensure the new worktrees start clean before any file deletion, extraction, or forceful package reshaping begins.
- Desired outcome: Two clean, isolated worktrees exist for implementation and PR prep: one for `Reseau` based on the current HTTP-containing branch, and one for `HTTP` based on `master`.
- Affected files: `.git/worktrees/*` in both repositories, plus this action-item file for recorded paths/branch names.
- Implementation notes:
  - Create a new `HTTP` worktree from local `master`.
  - Create a new `Reseau` worktree from local `jq-reseau-http-perf-pass`.
  - Create dedicated topic branches in each worktree for the split/PR work.
  - Record the new worktree paths and branch names back into this document.
  - Verify both new worktrees are clean and that no untracked files from the current checkouts were copied into the new execution trees.
- Verification:
  - `git -C /Users/jacob.quinn/.julia/dev/HTTP worktree list`
  - `git -C /Users/jacob.quinn/.julia/dev/HTTP-split-worktree status --short --branch`
  - `git -C /Users/jacob.quinn/.julia/dev/Reseau worktree list`
  - `git -C /Users/jacob.quinn/.julia/dev/Reseau-split-worktree status --short --branch`
- Assumptions:
  - Local `HTTP/master` is the intended base for the package reset.
  - Local `Reseau/jq-reseau-http-perf-pass` is the intended source branch for the extracted HTTP implementation.
  - Using fresh worktrees is acceptable because it avoids removing or resetting existing uncommitted files.
- Risks:
  - Branch naming collisions if similarly named worktrees or branches already exist.
  - Local `master` may be stale relative to upstream and need a later explicit refresh.
- Completion criteria:
  - Clean execution worktrees exist for both repositories.
  - The action-item file reflects the actual worktree paths and branch names to use for all later items.

### [x] ITEM-002 (P0) Produce the extraction inventory and ownership map
- Description: Inventory every HTTP-owned source file, test, fixture, and doc responsibility currently living in `Reseau`, and contrast that against what still exists on `HTTP/master`. This is the map that prevents orphaned code, missing exports, or silently dropped tests during the split.
- Desired outcome: A concrete migration inventory exists that identifies exactly what moves to `HTTP`, what stays in `Reseau`, what is deleted from `HTTP/master`, and what shared assumptions need to be untangled.
- Affected files: `src/Reseau.jl`, `src/7_*.jl`, `src/8_precompile_workload.jl`, `test/http*.jl`, `test/hpack_tests.jl`, `test/websockets/**`, `/Users/jacob.quinn/.julia/dev/HTTP/src/**`, `/Users/jacob.quinn/.julia/dev/HTTP/test/**`, `/Users/jacob.quinn/.julia/dev/HTTP/docs/**`, and this action-item file.
- Implementation notes:
  - Enumerate all `Reseau.HTTP` source modules, helper modules, precompile hooks, and exported APIs.
  - Enumerate all HTTP-facing tests, fixtures, optional integration suites, and coverage-sensitive paths in `Reseau`.
  - Enumerate all legacy HTTP.jl source/test/docs material on `HTTP/master` that must be replaced or consciously retained.
  - Record any behavior gaps between `Reseau.HTTP` and `HTTP/master`, especially around dependencies, public API names, docs structure, and CI assumptions.
- Verification:
  - `rg -n 'include\\("7_|include\\("8_precompile_workload' /Users/jacob.quinn/.julia/dev/Reseau/src`
  - `find /Users/jacob.quinn/.julia/dev/Reseau/test -maxdepth 2 -type f | sort | rg '/http|/hpack|/websocket|trim_compile'`
  - `find /Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src /Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test /Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs -maxdepth 3 -type f | sort`
- Assumptions:
  - `Reseau.HTTP` is the source of truth for the new HTTP 2.0 implementation.
  - `HTTP/master` should be treated as a package shell plus metadata/CI/docs hosting baseline, not as implementation to merge feature-by-feature.
- Risks:
  - Hidden helpers in `Reseau` that are used by both HTTP and non-HTTP layers could be accidentally moved instead of re-homed.
  - Test fixtures or generated reports may be large enough that they should be regenerated rather than copied.
- Completion criteria:
  - The inventory is recorded in this document or a linked companion note with clear keep/move/delete decisions.

### [x] ITEM-003 (P0) Reset the HTTP package on `master` to a clean 2.0 extraction baseline
- Description: Replace the current `HTTP/master` package layout with a clean generated-style baseline so the extracted code lands in a deliberate structure instead of incrementally patching the legacy tree. The reset should preserve package identity, CI/doc entrypoints that remain useful, and package metadata that still applies.
- Desired outcome: The `HTTP` execution worktree contains a minimal package skeleton ready to receive the extracted implementation, with `src/`, `test/`, and `docs/` aligned to the new 2.0 package architecture instead of the old 1.x layout.
- Affected files: `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/**`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/**`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/**`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/Project.toml`.
- Implementation notes:
  - Remove or replace legacy `HTTP/master` source, tests, and docs content in the execution worktree only.
  - Preserve package name, UUID, authorship, and release identity.
  - Set `version = "2.0.0"` on the master-based branch if it is not already there.
  - Keep the reset buildable with a minimal module and smoke test before the full extraction lands.
- Verification:
  - `git -C /Users/jacob.quinn/.julia/dev/HTTP-split-worktree status --short`
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); using HTTP; println(HTTP)'`
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.test()'`
- Assumptions:
  - It is acceptable for `HTTP` to pass only skeletal smoke tests immediately after the reset commit, before the extracted functionality is moved over in later items.
- Risks:
  - Deleting the legacy tree may also remove useful workflow, doc, or release scaffolding unless reintroduced deliberately.
- Completion criteria:
  - The `HTTP` execution worktree resembles a clean package baseline and passes its minimal smoke verification.

### [x] ITEM-004 (P0) Port the HTTP 2.0 source implementation from Reseau into HTTP
- Description: Move the actual HTTP client/server/websocket/HTTP2 implementation out of `Reseau` and into `HTTP`, preserving behavior while untangling package boundaries, module names, dependencies, includes, exports, and precompile flow.
- Desired outcome: `HTTP` becomes the authoritative home of the extracted implementation while depending on `Reseau` as the lower-level transport/TCP/TLS substrate where appropriate.
- Affected files: `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_*.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/8_precompile_workload.jl`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/**`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/Project.toml`.
- Implementation notes:
  - Re-root the `Reseau.HTTP` module tree into `HTTP`.
  - Translate `include` order and internal module references cleanly.
  - Replace `Reseau.HTTP`-specific naming and module nesting with package-local `HTTP` equivalents.
  - Keep explicit `Reseau` package dependencies where the HTTP stack should continue to call into the extracted transport/TCP/TLS layers.
  - Reconcile dependency lists, compat bounds, and precompile workload ownership.
  - Ensure the resulting source layout stays readable and reviewable instead of mirroring temporary extraction mechanics.
- Verification:
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); using HTTP'`
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using HTTP; println(HTTP.VERSION)'`
- Assumptions:
  - Non-HTTP networking primitives remain in `Reseau`, and `HTTP` 2.0 will depend on `Reseau` directly rather than duplicating those layers.
- Risks:
  - Subtle namespace, initialization-order, or dependency-cycle bugs during the module split.
  - Platform-specific behavior tied to `Reseau` internals may need a cleaner abstraction boundary instead of a straight move.
- Completion criteria:
  - `HTTP` loads successfully from the extracted source tree and owns the implementation directly.

### [x] ITEM-005 (P0) Port the HTTP test suite, fixtures, and specialized harnesses into HTTP
- Description: Move the HTTP-focused tests out of `Reseau` into `HTTP`, including fixtures, websocket harnesses, trim tests, and any optional external suites that remain valuable for release confidence.
- Desired outcome: `HTTP` contains the full authoritative test suite for the extracted implementation, and `Reseau` no longer owns HTTP behavior tests.
- Affected files: `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/http*.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/hpack_tests.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/websockets/**`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/**`.
- Implementation notes:
  - Re-home all HTTP-owned tests into a coherent `HTTP/test` layout.
  - Preserve optional gates for long-running or environment-dependent suites.
  - Bring over only fixtures that are necessary; do not blindly copy generated websocket reports if they can be regenerated.
  - Update test helpers/imports so the suite targets `HTTP`, not `Reseau.HTTP`.
- Verification:
  - `JULIA_NUM_THREADS=1 julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'`
  - `JULIA_NUM_THREADS=1 julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test --startup-file=no --history-file=no -e 'using HTTP, Test'`
- Assumptions:
  - `hpack_tests.jl` belongs with `HTTP` because HPACK is part of the HTTP/2 implementation, not a standalone `Reseau` transport primitive.
- Risks:
  - Long-running integration suites could become flaky when moved unless their setup/teardown logic also moves cleanly.
- Completion criteria:
  - The extracted `HTTP` test suite runs from the `HTTP` worktree and no longer imports `Reseau.HTTP`.

### [x] ITEM-006 (P0) Remove the extracted HTTP stack from Reseau and restore package boundaries
- Description: Strip the HTTP implementation out of `Reseau`, leaving behind the Go-inspired transport/runtime/TLS stack that should remain after the split. Update entrypoints, deps, tests, and any package metadata that still imply bundled HTTP ownership.
- Desired outcome: `Reseau` contains only the non-HTTP networking stack and remains internally consistent after the removal.
- Affected files: `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/Reseau.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_*.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/8_precompile_workload.jl`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/Project.toml`.
- Implementation notes:
  - Remove HTTP includes and exports from the root module.
  - Revisit dependency and compat lists after the HTTP modules leave.
  - Keep transport/TCP/TLS layering aligned with the Go rewrite mandate after the split.
  - Preserve or replace any precompile work that still matters for the remaining package.
- Verification:
  - `julia --project=/Users/jacob.quinn/.julia/dev/Reseau-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); using Reseau'`
  - `JULIA_NUM_THREADS=1 julia --project=/Users/jacob.quinn/.julia/dev/Reseau-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false)'`
- Assumptions:
  - The remaining package should not preserve a compatibility `HTTP` shim or re-export layer.
- Risks:
  - Hidden references from transport/TLS tests or precompile workloads back into the extracted HTTP modules.
- Completion criteria:
  - `Reseau` loads and tests cleanly without bundling the HTTP stack.

### [x] ITEM-007 (P1) Reconcile API surface, dependency policy, and release metadata for HTTP 2.0
- Description: Normalize `HTTP` package metadata and public API around the extracted implementation so the 2.0 branch is intentional and reviewable, not just a copied internal tree. This includes versioning, deps, compat, exports, and release-facing package identity decisions.
- Desired outcome: `HTTP` clearly presents itself as the extracted 2.0 package line with accurate dependency/compat metadata and an auditable public surface.
- Affected files: `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/Project.toml`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/HTTP.jl`, relevant source files that define exports/version constants.
- Implementation notes:
  - Confirm `version = "2.0.0"` on the execution branch.
  - Remove stale 1.x dependencies that no longer apply.
  - Add missing deps required by the extracted code.
  - Audit exports/public constants for names that changed under `Reseau.HTTP`.
  - Record breaking changes and intended benefits as implementation notes for later docs.
- Verification:
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); using HTTP; println(HTTP.VERSION)'`
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.status()'`
- Assumptions:
  - Julia compat may legitimately move forward to match the extracted implementation if required.
- Risks:
  - Tightening compat bounds for the rewrite may be a breaking change beyond API behavior alone.
- Completion criteria:
  - HTTP metadata, exports, and deps match the extracted implementation and release intent.

### [x] ITEM-008 (P1) Close HTTP functional gaps and add missing regression tests
- Description: After the raw extraction, compare the resulting `HTTP` package against both the new `Reseau.HTTP` behavior and the old `HTTP/master` expectations to identify missing coverage, behavior regressions, or undocumented breaks. Add tests for uncovered branches and fix defects before release.
- Desired outcome: The new `HTTP` package has strong confidence across core client/server/websocket/HTTP2 flows, with targeted tests for newly discovered edge cases.
- Affected files: `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/**`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/**`.
- Implementation notes:
  - Run coverage and inspect low-coverage or unexecuted paths.
  - Add focused tests for redirect behavior, proxy behavior, streaming, decompression, cookies, websocket negotiation, HTTP/2 framing, and trim/compile surfaces as needed.
  - Fix any extraction regressions found while running the full suite or comparing to 1.x behavior.
- Verification:
  - `JULIA_NUM_THREADS=1 julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=true)'`
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using Coverage; cov = process_folder(); println(length(cov))'`
- Assumptions:
  - Coverage quality matters more than hitting an arbitrary percentage, but low-signal gaps should still be investigated.
- Risks:
  - Some deep branches may only be reachable via flaky network-dependent tests and need deterministic local harnesses.
- Completion criteria:
  - No known untested critical paths remain in `HTTP`, and added tests cover discovered regressions/breaking behavior.

### [x] ITEM-009 (P1) Rebuild HTTP documentation for the 2.0 package line
- Description: Rewrite the `HTTP` docs around the extracted implementation, including high-level guides, API reference, and a detailed migration guide for 1.x users. The docs should build locally and be ready for deploy previews and release publication.
- Desired outcome: `HTTP/docs` is a complete Documenter setup with guides that explain the 2.0 architecture, main entrypoints, breaking changes, migration steps, and benefits of upgrading.
- Affected files: `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/**`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/**` docstrings as needed.
- Implementation notes:
  - Provide traditional docs structure: home/overview, client guide, server guide, websocket/HTTP2 or advanced guides, API reference, and migration guide from 1.x to 2.0.
  - Document breaking changes explicitly, including dependency/runtime assumptions that changed with the extraction.
  - Highlight benefits such as performance, architecture clarity, and improved protocol/test behavior.
  - Ensure doctests and examples are realistic and maintainable.
- Verification:
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate()'`
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs --startup-file=no --history-file=no -e 'using Documenter: doctest; using HTTP; doctest(HTTP)'`
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs --startup-file=no --history-file=no docs/make.jl`
- Assumptions:
  - Existing 1.x docs can be discarded or selectively mined rather than preserved wholesale.
- Risks:
  - Migration guidance may require careful cross-checking against 1.x semantics to avoid underselling breakage.
- Completion criteria:
  - `HTTP` docs build successfully and include a substantive 1.x -> 2.0 migration guide.

### [x] ITEM-010 (P1) Build full Reseau documentation for the post-split package
- Description: Create a proper `Reseau/docs` setup and write documentation for the package that remains after HTTP extraction. This should explain the main entrypoints, package purpose, API reference, and a strong migration guide for `Sockets` stdlib users moving to `Reseau`.
- Desired outcome: `Reseau` has a conventional Documenter site with architecture-aware guides and a practical porting guide for `Sockets` users.
- Affected files: `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/docs/**`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/**` docstrings as needed, possibly `.github/workflows/ci.yml`.
- Implementation notes:
  - Create `docs/Project.toml`, `docs/make.jl`, `docs/src/index.md`, guide pages, API reference, and the `Sockets` migration guide.
  - Explain the transport/TCP/TLS layering, supported platforms/phase status, and core entrypoints.
  - Show idiomatic porting examples from `Sockets` to `Reseau`.
  - Clearly call out benefits and semantic differences.
- Verification:
  - `julia --project=/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/docs --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate()'`
  - `julia --project=/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/docs --startup-file=no --history-file=no -e 'using Documenter: doctest; using Reseau; doctest(Reseau)'`
  - `julia --project=/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/docs --startup-file=no --history-file=no docs/make.jl`
- Assumptions:
  - `Reseau` currently has no active docs tree, so a fresh setup is expected rather than a migration.
- Risks:
  - The package API may still be evolving after the split, which can force doc churn if written too early.
- Completion criteria:
  - `Reseau` docs build successfully and include a solid `Sockets` migration guide.

### [x] ITEM-011 (P1) Update CI, coverage, and docs deployment workflows for both repos
- Description: Align both repositories’ CI with the new ownership split so tests, coverage, and docs builds run where they belong and publish correctly on branch pushes/tags.
- Desired outcome: `HTTP` and `Reseau` each have CI workflows that run their own tests, collect coverage, and build/deploy docs on the intended branches with preview support where appropriate.
- Affected files: `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/.github/workflows/*.yml`, `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/.github/workflows/*.yml`, docs deploy config in `docs/make.jl`.
- Implementation notes:
  - Point `HTTP` CI and docs builds at the `codex/reseau-http-split` branch until the sibling `Reseau` PR merges, since `HTTP` 2.0 now depends on the extracted lower-level transport package.
  - Add missing docs job or preview-cleanup workflow to `Reseau` if needed.
  - Add or preserve coverage upload for both repos.
  - Validate branch filters against the intended PR base branches.
  - Keep environment-gated long-running tests opt-in if they are too heavy for default CI.
- Verification:
  - `ruby -e 'require "yaml"; Dir["/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/.github/workflows/*.yml", "/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/.github/workflows/*.yml"].sort.each { |path| YAML.safe_load(File.read(path), permitted_classes: [], aliases: true); puts path }'`
  - Local docs build commands from ITEM-009 and ITEM-010.
  - Local test commands from ITEM-008 and ITEM-012.
- Assumptions:
  - Existing repo secrets for Documenter/Codecov/TagBot can be reused once the workflow wiring is correct.
  - The `codex/reseau-http-split` branch will be pushed before relying on the updated `HTTP` workflow in hosted CI.
- Risks:
  - Branch filters may need to reflect whichever default branch the repos actually use at PR time.
- Completion criteria:
  - Both repos have valid workflow files and successful local equivalents of their test/docs jobs.

### [ ] ITEM-012 (P1) Run exhaustive local verification for both repositories
- Description: Execute the full practical local verification pass after the split so the repos are ready for PR review and hosted CI. This is the consolidation item for ensuring the end state is actually stable.
- Desired outcome: Both `HTTP` and `Reseau` pass their full local test/docs/coverage verification commands with no known red flags left unaddressed.
- Affected files: No intentional source changes unless failures require fixes; verification evidence should be recorded in this action-item file.
- Implementation notes:
  - Run the canonical package tests for both repos from their execution worktrees.
  - Run docs builds for both repos.
  - Run coverage-producing test passes where feasible.
  - If failures appear, fix them under the relevant repo and rerun until green.
- Verification:
  - `cd /Users/jacob.quinn/.julia/dev/HTTP-split-worktree && JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=true)'`
  - `cd /Users/jacob.quinn/.julia/dev/HTTP-split-worktree && julia --project=docs --startup-file=no --history-file=no docs/make.jl`
  - `cd /Users/jacob.quinn/.julia/dev/Reseau-split-worktree && JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=true)'`
  - `cd /Users/jacob.quinn/.julia/dev/Reseau-split-worktree && julia --project=docs --startup-file=no --history-file=no docs/make.jl`
- Assumptions:
  - Some platform-specific coverage or optional network suites may still rely on hosted CI for full cross-platform validation.
- Risks:
  - Exhaustive local verification can be slow and may expose flakiness that needs deterministic harness improvements.
- Completion criteria:
  - All defined local verification commands complete successfully and their results are recorded.

### [ ] ITEM-013 (P2) Prepare PR branches, push them, open PRs, and drive hosted CI to green
- Description: Finish the split end-to-end by ensuring each completed item has its own commit history, pushing both branches, opening PRs, and iterating on any hosted CI failures until both PRs are green with acceptable coverage.
- Desired outcome: Two reviewable PRs exist, one for `HTTP` and one for `Reseau`, each with passing CI and clear release/migration framing.
- Affected files: No predetermined file set; includes git branch state, commit history, PR descriptions, and any follow-up fixes required by hosted CI.
- Implementation notes:
  - Review commit history to ensure each completed item was committed cleanly.
  - Push both execution branches to their remotes.
  - Open PRs with summaries that explain the split, migration implications, and docs coverage.
  - Monitor hosted CI and fix failures in follow-up commits until all required checks are green.
  - Record final coverage numbers and any residual risks in the PR descriptions.
- Verification:
  - `git -C /Users/jacob.quinn/.julia/dev/HTTP-split-worktree log --oneline --decorate --max-count=20`
  - `git -C /Users/jacob.quinn/.julia/dev/Reseau-split-worktree log --oneline --decorate --max-count=20`
  - `gh pr status`
  - `gh run list --limit 20`
- Assumptions:
  - `gh` authentication and remote push permissions are already available in this environment.
- Risks:
  - Hosted CI may reveal platform-only issues not reproducible locally.
- Completion criteria:
  - PRs exist for both repos, all required hosted checks are green, and final coverage/migration notes are captured.

## Verification Log
- ITEM-001:
  - `git -C /Users/jacob.quinn/.julia/dev/HTTP worktree list` shows `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree` on `codex/http-2.0-extraction` and preserves the existing dirty checkout plus the separate `master` worktree.
  - `git -C /Users/jacob.quinn/.julia/dev/HTTP-split-worktree status --short --branch` returned a clean `## codex/http-2.0-extraction`.
  - `git -C /Users/jacob.quinn/.julia/dev/Reseau worktree list` shows `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree` on `codex/reseau-http-split` alongside the original checkout.
  - `git -C /Users/jacob.quinn/.julia/dev/Reseau-split-worktree status --short --branch` returned a clean `## codex/reseau-http-split`.
- ITEM-002:
  - Companion inventory note recorded at `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/http-extraction-inventory.md`.
  - `rg -n 'include\\(\"7_|include\\(\"8_precompile_workload' /Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src` confirmed the HTTP include graph rooted at `src/7_http.jl` plus mixed ownership in `src/8_precompile_workload.jl`.
  - `find /Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test -maxdepth 2 -type f | sort | rg '/http|/hpack|/websocket|trim_compile'` identified the HTTP-owned test tree and mixed `trim_compile_tests.jl` ownership.
  - `find /Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src /Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test /Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs -maxdepth 3 -type f | sort` plus a targeted `Project.toml`/workflow/docs read confirmed that `HTTP/master` is largely replace-all in `src/`, `test/`, and `docs/`, with only package identity and workflow/documenter scaffolding worth preserving.
- ITEM-003:
  - `git -C /Users/jacob.quinn/.julia/dev/HTTP-split-worktree rm -r src test docs` cleared the legacy 1.x package trees in the clean execution worktree.
  - Minimal 2.0 shell files were recreated at `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/HTTP.jl`, `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/runtests.jl`, and `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/**`.
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); using HTTP; println(HTTP); println(HTTP.VERSION)'` loaded the package and printed `HTTP` then `2.0.0`.
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.test()'` passed the new `HTTP 2.0 skeleton` testset.
- ITEM-004:
  - Source files from `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_*.jl` were copied into `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/`, excluding the nested-module wrapper `7_http.jl`.
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/HTTP.jl` now owns the extracted include graph directly, preserving the `Reseau.HTTP` include ordering inside the top-level `HTTP` package.
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/Project.toml` now declares the extracted source dependencies, including `Reseau` plus the stdlib/package deps used by the moved modules.
  - `rg -n '\\.\\.Reseau' /Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src` returned no matches after rewriting the package-boundary imports.
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.develop(path=\"/Users/jacob.quinn/.julia/dev/Reseau-split-worktree\"); Pkg.instantiate(); using HTTP; println(HTTP.VERSION)'` loaded the extracted package and printed `2.0.0`.
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.develop(path=\"/Users/jacob.quinn/.julia/dev/Reseau-split-worktree\"); using HTTP; println(isdefined(HTTP, :Request)); println(isdefined(HTTP, :Transport)); println(isdefined(HTTP, :WebSockets))'` printed `true`, `true`, `true`.
  - Temporary note: `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/HTTP.jl` currently sets `__precompile__(false)` so `HTTP` can coexist with the still-embedded `Reseau.HTTP` code during the extraction phase; this should be removed after `Reseau` drops the bundled HTTP implementation.
- ITEM-005:
  - HTTP-owned tests, copied fixtures, and websocket harness assets now live under `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/**`, including copied TLS fixtures and the Autobahn client config.
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/runtests.jl` now runs the HTTP-only suite with `HTTP_TEST_ONLY` and `HTTP_RUN_WEBSOCKET_AUTOBAHN` controls instead of the old `Reseau`-specific entrypoint.
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/trim_compile_tests.jl` was reduced to the HTTP-only trim workload, and `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/Project.toml` now supports direct `test/` activation plus local `Pkg.develop` wiring.
  - `rg -n 'Reseau\\.HTTP' /Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test` returned no matches after rewriting the moved tests to target `HTTP`/`HTTP.WebSockets`.
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test --startup-file=no --history-file=no -e 'using Pkg; Pkg.develop(path=pwd()); Pkg.develop(path=\"/Users/jacob.quinn/.julia/dev/Reseau-split-worktree\"); Pkg.instantiate(); using HTTP, Test; println(\"test env ok\")'` succeeded.
  - `HTTP_TEST_ONLY=http_websocket_codec_tests.jl julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.develop(path=\"/Users/jacob.quinn/.julia/dev/Reseau-split-worktree\"); Pkg.test(; coverage=false)'` passed the moved websocket codec suite from the `HTTP` worktree.
  - Full-suite stabilization remains a dedicated follow-up in ITEM-008 and ITEM-012; this item establishes ownership and executable test wiring in `HTTP`.
- ITEM-006:
  - `git rm` removed the embedded HTTP source tree from `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/7_*.jl`, removed the mixed precompile file `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/8_precompile_workload.jl`, and deleted the HTTP-owned tests/harness assets from `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/**`.
  - `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/src/Reseau.jl` now only includes the event loop, socket ops, internal poll, TCP, host resolver, and TLS layers.
  - `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/runtests.jl` and `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/test/trim_compile_tests.jl` now run only the non-HTTP test/trim workloads.
  - `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/Project.toml` no longer declares the HTTP-only package deps (`Base64`, `CodecZlib`, `Dates`, `PrecompileTools`, `Random`, `SHA`, `UUIDs`).
  - `julia --project=/Users/jacob.quinn/.julia/dev/Reseau-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); using Reseau; println(Reseau)'` succeeded and printed `Reseau`.
  - Residual verification note: `RESEAU_TEST_ONLY=eventloops_tests.jl JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; coverage=false)'` hangs after `[runtests] include START: eventloops_tests.jl` in both `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree` and the untouched source branch `/Users/jacob.quinn/.julia/dev/Reseau`, so this appears to be a pre-existing non-HTTP issue rather than a regression introduced by the HTTP split.
- ITEM-007:
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/HTTP.jl` no longer needs the temporary `__precompile__(false)` escape hatch now that `Reseau` no longer bundles the same HTTP methods.
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src/7_6_http_proxy.jl` now uses local IPv4/IPv6 literal parsers backed by `inet_pton` instead of private `HostResolvers._parse_ipv4_literal` / `_parse_ipv6_literal` calls.
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/Project.toml` now reflects the slimmer test target after the direct `Base64`/`Dates` test imports were removed.
  - `rg -n 'HostResolvers\\._parse_ipv|__precompile__\\(false\\)' /Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src` returned no matches.
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.develop(path=\"/Users/jacob.quinn/.julia/dev/Reseau-split-worktree\"); Pkg.instantiate(); using HTTP; println(HTTP.VERSION)'` precompiled and loaded `HTTP`, printing `2.0.0`.
  - `HTTP_TEST_ONLY=http_client_proxy_tests.jl julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.develop(path=\"/Users/jacob.quinn/.julia/dev/Reseau-split-worktree\"); Pkg.test(; coverage=false)'` passed the proxy suite with the localized parser implementation.
- ITEM-008:
  - Full extracted HTTP suites now pass from `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree`, including the client, server, websocket, HTTP/2, integration, parity, proxy, and trim-compile paths. The work here fixed all moved-test dependency/import issues uncovered while driving the extracted suite and added extra sniff/multipart coverage.
  - Added targeted branch coverage in `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/test/http_forms_tests.jl` for MIME sniffing signatures, multiple JSON shapes, richer multipart parsing, and lower-cased multipart header ordering.
  - `JULIA_NUM_THREADS=1 julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree --startup-file=no --history-file=no -e 'using Pkg; Pkg.develop(path=\"/Users/jacob.quinn/.julia/dev/Reseau-split-worktree\"); Pkg.test(; coverage=true)'` completed successfully.
  - `julia --startup-file=no --history-file=no -e 'using Pkg; Pkg.activate(temp=true); Pkg.add(\"Coverage\"); using Coverage; cov = process_folder(\"/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/src\"); covered,total = get_summary(cov); println((covered,total))'` reported `6346/7630` covered source lines, or `83.17%` for `src/`.
  - Lowest remaining file-level coverage after the added tests is concentrated in helper-heavy modules rather than missing core protocol flows: `7_6_http_stream.jl` (`68.03%`), `7_6_http_cookies.jl` (`73.91%`), `7_6_http_forms.jl` (`76.41%`), `7_6_http_websockets.jl` (`77.61%`), and `7_6_http_request_bodies.jl` (`80.0%`).
- ITEM-009:
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/` now has a conventional Documenter layout with a home page, client guide, server guide, protocols guide, migration guide, and API reference.
  - The guides document the extracted 2.0 package around the real `Client`/`Transport`, `serve!`/`listen!`, `WebSockets`, and explicit HTTP/2 entrypoints, and the migration guide now calls out the Julia `1.11` requirement plus the `Reseau` transport boundary explicitly.
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs --startup-file=no --history-file=no -e 'using Pkg; Pkg.develop(PackageSpec(path=pwd())); Pkg.develop(PackageSpec(path=\"/Users/jacob.quinn/.julia/dev/Reseau-split-worktree\")); Pkg.instantiate()'` succeeded.
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs --startup-file=no --history-file=no -e 'using Documenter: doctest; using HTTP; doctest(HTTP)'` succeeded.
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs --startup-file=no --history-file=no docs/make.jl` succeeded.
- ITEM-010:
  - `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/docs/` now exists with a conventional Documenter structure: home, TCP/resolution guide, TLS guide, `Sockets` migration guide, and API reference.
  - The docs explicitly position Reseau as the post-split transport/runtime/TLS layer and point HTTP users at HTTP.jl for the extracted HTTP stack.
  - `julia --project=/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/docs --startup-file=no --history-file=no -e 'using Pkg; Pkg.develop(PackageSpec(path=pwd())); Pkg.instantiate()'` succeeded.
  - `julia --project=/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/docs --startup-file=no --history-file=no -e 'using Documenter: doctest; using Reseau; doctest(Reseau)'` succeeded.
  - `julia --project=/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/docs --startup-file=no --history-file=no docs/make.jl` succeeded.
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/` now contains a real 2.0 docs tree: a rewritten home page, client/server/protocol guides, a migration guide from 1.x, and a grouped manual API reference.
  - The migration guide explicitly frames 2.0 as the extracted Reseau-backed HTTP line, calls out the main compatibility expectations, and points users toward the stable top-level surfaces instead of 1.x internals.
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/make.jl` now builds the multi-page site and uses `checkdocs = :none` so the authored manual reference can build cleanly without a full `@docs` inclusion pass yet.
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs --startup-file=no --history-file=no -e 'using Pkg; Pkg.develop(PackageSpec(path=pwd())); Pkg.develop(PackageSpec(path=\"/Users/jacob.quinn/.julia/dev/Reseau-split-worktree\")); Pkg.instantiate()'` succeeded.
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs --startup-file=no --history-file=no -e 'using Documenter: doctest; using HTTP; doctest(HTTP)'` passed.
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs --startup-file=no --history-file=no docs/make.jl` completed successfully.
- ITEM-011:
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/.github/workflows/ci.yml` now runs a focused Julia `1.11`/`1.12`/`nightly` matrix, uploads coverage from the Ubuntu `1.12` job only, and explicitly `Pkg.develop`s `https://github.com/JuliaServices/Reseau.jl` at `codex/reseau-http-split` before build/test/docs so the extracted dependency boundary works in hosted CI.
  - `/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs/make.jl` now calls `deploydocs(...)` unconditionally, relying on Documenter to no-op outside CI and to publish previews/releases from the workflow environment.
  - `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/.github/workflows/ci.yml` now adds cache, coverage upload, and a dedicated docs job, and `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/.github/workflows/previews-cleanup.yml` now provides preview cleanup parity with `HTTP`.
  - `/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/docs/make.jl` now calls `deploydocs(...)` unconditionally against `github.com/JuliaServices/Reseau.jl.git`.
  - `ruby -e 'require "yaml"; Dir["/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/.github/workflows/*.yml", "/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/.github/workflows/*.yml"].sort.each { |path| YAML.safe_load(File.read(path), permitted_classes: [], aliases: true); puts path }'` parsed every workflow file successfully.
  - `julia --project=/Users/jacob.quinn/.julia/dev/HTTP-split-worktree/docs --startup-file=no --history-file=no docs/make.jl` succeeded and reported `Documenter could not auto-detect the building environment. Skipping deployment.`
  - `julia --project=/Users/jacob.quinn/.julia/dev/Reseau-split-worktree/docs --startup-file=no --history-file=no docs/make.jl` succeeded and reported `Documenter could not auto-detect the building environment. Skipping deployment.`

## Continuity

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
