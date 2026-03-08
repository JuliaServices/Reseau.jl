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

### [x] ITEM-002 (P0) Keep redirect-limit exhaustion as an error and expose redirect metadata
- Description: We want auto-follow redirect exhaustion to throw instead of silently returning the last `3xx`, while still returning redirects when redirect following is disabled. At the same time, callers need enough metadata to inspect the final URL/redirect chain.
- Desired outcome: Redirect-following requests throw a dedicated redirect-limit error path by default, `redirect=false` still returns the original redirect response, and responses expose the final redirected URL plus useful redirect history/count metadata.
- Affected files: `src/7_0_http_core.jl`, `src/7_6_http_client.jl`, `src/7_6_http_stream.jl`, `test/http_client_tests.jl`, `test/http_parity_tests.jl`
- Implementation notes:
  - Keep redirect-limit exhaustion as a thrown error from the redirect loop when following is enabled.
  - Adjust high-level status-exception behavior so returned `3xx` responses from `redirect=false` do not trigger `StatusError`.
  - Add response/request metadata for final URL and redirect count, and add redirect parent/history links if needed for a useful inspection story.
  - Make sure streamed/open requests surface the same redirect metadata as buffered requests.
- Verification:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_client_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_parity_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_core_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - A small new exception type or richer `ProtocolError` message is acceptable if it keeps the API direct and testable.
  - Redirect metadata can be added directly to the request/response model without preserving `HTTP.jl`'s exact ancestry shape.
- Completion criteria:
  - Redirect exhaustion throws during auto-following.
  - `redirect=false` returns a `3xx` response without `StatusError`.
  - Redirect metadata is observable on final responses and covered by tests.
 - Verification evidence:
  - `2026-03-08`: `RESEAU_TEST_ONLY=http_client_tests.jl` passed with redirect-disabled, limit-zero, metadata, and `TooManyRedirectsError` coverage.
  - `2026-03-08`: `RESEAU_TEST_ONLY=http_parity_tests.jl` passed after the redirect error/metadata changes.
  - `2026-03-08`: `RESEAU_TEST_ONLY=http_core_tests.jl` passed after extending `Response` metadata fields.

### [x] ITEM-003 (P1) Finish docs and local verification
- Description: After the behavior changes land, we need stable regression coverage, trim-compile compatibility, and any necessary public API docstring updates before we hand the branch to CI.
- Desired outcome: Redirect behavior is documented where needed, the relevant local suite passes, and the final code/docs delta is committed cleanly for review.
- Affected files: `test/http_client_tests.jl`, `test/http_parity_tests.jl`, `test/http_trim_safe.jl`, `src/7_6_http_client.jl`, `src/7_6_http_stream.jl`
- Implementation notes:
  - Add targeted regression coverage for `redirect_limit`, `redirect_method`, `forwardheaders=false`, `Host` stripping, disabled redirect behavior, and redirect metadata.
  - Update any docstrings or public API docs if the new per-request redirect keywords need to be discoverable.
  - Run the full local suite, including trim compile coverage, before pushing.
- Verification:
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `git diff --stat origin/main...HEAD`
- Assumptions:
  - Existing docs only need focused docstring updates for the new redirect keywords.
- Completion criteria:
  - Relevant local tests pass, including trim compile coverage.
  - Public redirect knobs are documented where callers will discover them.
 - Verification evidence:
  - `2026-03-08`: `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no test/runtests.jl` passed end-to-end.
  - `2026-03-08`: `RESEAU_TEST_ONLY=trim_compile_tests.jl` passed after updating `test/http_trim_safe.jl` for the extended `Response` metadata fields.
  - `2026-03-08`: request/open docstrings were updated to describe `redirect_limit`, `redirect_method`, `forwardheaders`, and `check_redirect`.

### [ ] ITEM-004 (P1) Push branch, open PR, and babysit CI
- Description: With the code and local verification complete, we still need to land the branch in GitHub, open a reviewable PR, and stay on it until CI reports green.
- Desired outcome: The branch is pushed, the PR clearly describes the redirect changes, and all GitHub Actions checks are green.
- Affected files: none locally unless CI failures require follow-up fixes
- Implementation notes:
  - Push `codex/http-redirect-parity` to `origin`.
  - Open a PR with `gh pr create` against `main`, summarizing redirect policy overrides, redirect metadata, and the new `TooManyRedirectsError`.
  - Monitor GitHub Actions with `gh run list` / `gh run view --log-failed`, fix any failures, and re-run until green.
- Verification:
  - `gh pr view --json number,title,state,url`
  - `gh run list --branch codex/http-redirect-parity --limit 10`
- Assumptions:
  - GitHub Actions is the authoritative CI surface for this repository.
- Completion criteria:
  - Branch is pushed and a PR exists.
  - GitHub Actions for the PR are green, or any failures have been fixed and re-run to green.
