# Action Items: HTTP redirect follow-up parity and policy

## Context
- Repo: Reseau
- Worktree: /Users/jacob.quinn/.julia/dev/Reseau
- Branch: codex/http-redirect-parity

## Items

### [x] ITEM-001 (P0) Implement redirect policy overrides and RFC-style target resolution
- Description: Reseau's redirect loop currently hardcodes most redirect policy on `Client` and resolves `Location` values manually. That leaves per-request parity gaps (`redirect_limit`, `redirect_method`, `forwardheaders`) and incorrect behavior for relative references like `../next`, `?q=1`, and `#frag`.
- Desired outcome: High-level request/open flows can override redirect policy per call, and redirect resolution follows RFC-style URI reference semantics while rejecting unsupported redirect targets.
- Affected files: `src/7_6_http_client.jl`, `src/7_6_http_stream.jl`, `test/http_client_tests.jl`
- Implementation notes:
  - Introduce an internal redirect policy/config type passed into `_do_incoming!` instead of relying solely on `Client.max_redirects` and `Client.check_redirect`.
  - Add per-request keyword support for `redirect_limit`, `redirect_method`, `forwardheaders`, and per-call `check_redirect` while preserving existing client defaults when the new keywords are omitted.
  - Replace `_resolve_redirect_target`'s manual path concatenation with correct reference resolution for absolute, scheme-relative, path-relative, query-only, and fragment-only redirect targets.
  - Reject redirect targets with unsupported schemes or missing hosts after resolution.
  - Ensure redirected requests do not carry stale `Host` headers when authority changes.
- Verification:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_client_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_parity_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - Introducing an internal redirect policy helper is acceptable as long as there is no public backwards-compatibility shim layer.
  - A focused internal redirect-reference resolver is preferable to adding a new URL dependency if it keeps the semantics correct.
- Completion criteria:
  - High-level request/open flows accept per-call redirect overrides.
  - Redirect target resolution matches expected results for relative, query-only, and fragment-only `Location` values.
  - Existing redirect tests still pass and new target-resolution coverage passes.
 - Verification evidence:
  - `2026-03-08`: `RESEAU_TEST_ONLY=http_client_tests.jl` passed with new request/open redirect override coverage.
  - `2026-03-08`: `RESEAU_TEST_ONLY=http_parity_tests.jl` passed after redirect policy/ref-resolution changes.

### [ ] ITEM-002 (P0) Keep redirect-limit exhaustion as an error and expose redirect metadata
- Description: We want auto-follow redirect exhaustion to throw instead of silently returning the last `3xx`, while still returning redirects when redirect following is disabled. At the same time, callers need enough metadata to inspect the final URL/redirect chain.
- Desired outcome: Redirect-following requests throw a dedicated redirect-limit error path by default, `redirect=false` still returns the original redirect response, and responses expose the final redirected URL plus useful redirect history/count metadata.
- Affected files: `src/7_0_http_core.jl`, `src/7_6_http_client.jl`, `src/7_6_http_stream.jl`, `test/http_client_tests.jl`, `test/http_parity_tests.jl`
- Implementation notes:
  - Keep redirect-limit exhaustion as a thrown error from the redirect loop when following is enabled.
  - Adjust high-level status-exception behavior so returned `3xx` responses from `redirect=false` do not trigger `StatusError`.
  - Add response/request metadata for final URL and redirect count, and add redirect parent/history links if needed for a useful inspection story.
  - Make sure streamed/open requests surface the same redirect metadata as buffered requests.
- Verification:
  - `julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test(; test_args=["http_client","http_parity"])'`
  - `julia --project=. --startup-file=no --history-file=no -e 'using Reseau; using Test; const HT = Reseau.HTTP; @test !HT._status_throws(HT.Response(302))'`
- Assumptions:
  - A small new exception type or richer `ProtocolError` message is acceptable if it keeps the API direct and testable.
  - Redirect metadata can be added directly to the request/response model without preserving `HTTP.jl`'s exact ancestry shape.
- Completion criteria:
  - Redirect exhaustion throws during auto-following.
  - `redirect=false` returns a `3xx` response without `StatusError`.
  - Redirect metadata is observable on final responses and covered by tests.

### [ ] ITEM-003 (P1) Finish verification, docs, and PR handoff
- Description: After the behavior changes land, we need stable regression coverage, any necessary API docs updates, and a clean PR with green CI.
- Desired outcome: Redirect behavior is documented where needed, the relevant test suite passes locally, commits are scoped by item, and the PR is opened and monitored until all GitHub checks are green.
- Affected files: `test/http_client_tests.jl`, `test/http_parity_tests.jl`, `src/7_6_http_client.jl`, `src/7_6_http_stream.jl`, `README.md` or docs only if needed
- Implementation notes:
  - Add targeted regression coverage for `redirect_limit`, `redirect_method`, `forwardheaders=false`, `Host` stripping, disabled redirect behavior, and redirect metadata.
  - Update any docstrings or public API docs if the new per-request redirect keywords need to be discoverable.
  - Run broader verification before push, then push the branch, open a PR with `gh`, and monitor Actions/logs until green.
- Verification:
  - `julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.test()'`
  - `git diff --stat origin/main...HEAD`
  - `gh run list --branch codex/http-redirect-parity --limit 10`
- Assumptions:
  - Existing docs only need focused updates if the new redirect keywords are public API.
  - CI is available through GitHub Actions on the repository.
- Completion criteria:
  - Relevant local tests pass.
  - Branch is pushed and a PR exists.
  - GitHub Actions for the PR are green, or any failures have been fixed and re-run to green.
