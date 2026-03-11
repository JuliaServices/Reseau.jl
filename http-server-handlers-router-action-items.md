# Action Items: HTTP Server Handlers and Router Parity

## Context
- Repo: Reseau
- Worktree: /Users/jacob.quinn/.julia/dev/Reseau
- Branch: http-server-handlers-router-parity

## Items

### [x] ITEM-001 (P0) Add request-context metadata plumbing and upstream handlers surface
- Description: `Reseau.HTTP` currently lacks the upstream `HTTP.Handlers` surface entirely, and `RequestContext` does not yet support the lightweight per-request metadata storage the upstream router/middleware layer expects for matched routes, params, and parsed cookies.
- Desired outcome: `Reseau.HTTP` has a dedicated `Handlers` module wired into `src/7_http.jl`, `RequestContext` can store/retrieve route metadata lazily without disturbing existing cancellation/deadline behavior, and the public names `Handler`, `Middleware`, `Router`, `register!`, `getroute`, `getparams`, `getparam`, `getcookies`, and `streamhandler` are available from `Reseau.HTTP`.
- Affected files: `src/7_0_http_core.jl`, `src/7_http.jl`, `src/7_7_http_handlers.jl`
- Implementation notes:
  - Extend `RequestContext` with lazy metadata storage plus the minimal `Base.get`, `Base.getindex`, `Base.setindex!`, and `Base.haskey` support needed by the ported handlers layer.
  - Add a new `Reseau.HTTP.Handlers` module based on `HTTP.jl` `origin/master` router/handlers behavior, adapting imports and stream plumbing to `Reseau`’s current `Request`, `Response`, `Stream`, and cookie APIs.
  - Keep the port direct where behavior matches upstream, but avoid adding any compatibility shim for older Reseau server APIs.
  - Preserve request-context metadata for matched route strings, named params, and cookie middleware results.
- Verification:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_core_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_server_http1_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - Request route/param/cookie metadata should live in `RequestContext`, not as new top-level `Request` fields, because that matches the upstream `origin/master` public behavior more closely while keeping core request structure focused.
  - A dedicated `src/7_7_http_handlers.jl` file is the cleanest include point because the module depends on server/stream APIs that already exist in `Reseau.HTTP`.
- Verification evidence:
  - `RESEAU_TEST_ONLY=http_core_tests.jl` passed after adding lazy metadata storage and dict-like `RequestContext` accessors.
  - `RESEAU_TEST_ONLY=http_server_http1_tests.jl` passed with the new `Handlers` module included in `Reseau.HTTP`.
- Completion criteria:
  - `using Reseau; Reseau.HTTP.Router` and related handler symbols load successfully.
  - Router metadata storage works without regressing request-context deadline/cancel behavior.

### [x] ITEM-002 (P0) Finish router, middleware, streamhandler, and cookie semantics against server behavior
- Description: Even with the module in place, the port still needs careful integration against `Reseau`’s server pipeline so request handlers, stream handlers, wildcard/regex routing, 404/405 handling, and cookie middleware all behave like HTTP.jl instead of just compiling.
- Desired outcome: Router matching covers exact, `*`, `{name}`, `{name:regex}`, and trailing `/**` patterns; request handlers and stream handlers both work; and cookie middleware plus parameter helpers behave correctly for real requests.
- Affected files: `src/7_7_http_handlers.jl`, `src/7_6_http_stream.jl`, `src/7_7_http_server.jl`
- Implementation notes:
  - Audit the ported `streamhandler` carefully against `Reseau`’s `startread`, `read`, `setstatus`, `setheader`, `addtrailer`, `closewrite`, and `closeread` semantics rather than assuming the upstream implementation drops in unchanged.
  - Ensure route matching extracts the path portion from `Request.target` correctly for origin-form requests while preserving query strings for normal request handling.
  - Confirm 404 vs 405 behavior remains distinguishable, and only matched routes run middleware.
  - Review hot-path allocations in route matching and metadata assignment so the port stays direct and predictable.
- Verification:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_handlers_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_server_http1_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_integration_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - Route matching should operate on the request path only, ignoring the query string exactly as `HTTP.jl` does.
  - No separate legacy compatibility layer is needed for older server helper names; the current `serve`/`serve!`/`listen`/`listen!` surface is the integration target.
- Verification evidence:
  - `RESEAU_TEST_ONLY=http_handlers_tests.jl` passed with live request-handler and stream-handler router coverage, including 404/405 and query-string-insensitive matching.
  - `RESEAU_TEST_ONLY=http_server_http1_tests.jl` passed after the adapter review.
  - `RESEAU_TEST_ONLY=http2_server_tests.jl` passed after adding router coverage to the shared HTTP/2 server path.
- Completion criteria:
  - Live server requests can pass through `streamhandler` and `Router` successfully.
  - Query strings do not break route matching, and 404/405 behavior is covered.

### [x] ITEM-003 (P0) Port and adapt upstream handlers/router tests into Reseau’s test suite
- Description: `Reseau` currently has no dedicated router/middleware test coverage, so the upstream `HTTP.jl` handlers tests and relevant server-side handler coverage need to be ported and adapted to current request/response/body APIs.
- Desired outcome: `Reseau` has a focused `http_handlers_tests.jl` suite plus any necessary integration assertions for `streamhandler` and router behavior, and the suite is wired into `test/runtests.jl`.
- Affected files: `test/http_handlers_tests.jl`, `test/http_server_http1_tests.jl`, `test/http_integration_tests.jl`, `test/runtests.jl`
- Implementation notes:
  - Start from `HTTP.jl` `test/handlers.jl` and the `HTTP.streamhandler` coverage in `test/server.jl`, then adapt assertions to `Reseau.HTTP.Response`, `BytesBody`, and current helper patterns.
  - Add explicit coverage for route params, regex params, double-star routes, middleware invocation boundaries, cookie middleware, and query-string-insensitive matching.
  - Keep tests small, deterministic, and runnable via `RESEAU_TEST_ONLY`.
- Verification:
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_handlers_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_server_http1_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - A standalone `test/http_handlers_tests.jl` file is the clearest home for the direct upstream router coverage.
  - Existing server tests may still need a few additions where handler behavior only makes sense over a live socket.
- Verification evidence:
  - `RESEAU_TEST_ONLY=http_core_tests.jl` passed after adding request-context metadata coverage.
  - `RESEAU_TEST_ONLY=http_handlers_tests.jl` passed with direct router, middleware, streamhandler, and live HTTP/1 server coverage.
  - `RESEAU_TEST_ONLY=trim_compile_tests.jl` passed after leaving the trim workload on static-friendly coverage.
- Completion criteria:
  - The new handlers test file passes on its own and from the full runner.
  - The test runner includes the new suite in the normal HTTP path.

### [x] ITEM-004 (P1) Update documentation and parity tracking for the new server surface
- Description: The README currently documents outdated server APIs, and the parity notes still list router/middleware as missing. The public docs need to match the shipped behavior after the port.
- Desired outcome: README examples use the current `serve!`/`listen!` lifecycle, the new router/middleware surface is documented accurately, and `http-master-parity.md` reflects the reduced gap.
- Affected files: `README.md`, `http-master-parity.md`, `src/7_7_http_handlers.jl`, `src/7_7_http_server.jl`
- Implementation notes:
  - Replace the stale README server example that still references `start!`, `server_addr`, and `shutdown!`.
  - Add concise handler/router usage examples that match the final ported API, including route params and middleware usage where helpful.
  - Update docstrings in the new handlers module and any touched server entrypoints so help-mode output stays accurate.
- Verification:
  - `rg -n "start!\\(|shutdown!\\(|server_addr\\(" README.md src`
  - `JULIA_NUM_THREADS=1 RESEAU_TEST_ONLY=http_handlers_tests.jl julia --project=. --startup-file=no --history-file=no test/runtests.jl`
- Assumptions:
  - Repo documentation for this work is primarily README plus in-source docstrings and parity notes; there is no separate Documenter site to update in this repo.
- Verification evidence:
  - README now uses `serve!`/`close`/`wait` instead of the stale `start!`/`shutdown!` flow.
  - `RESEAU_TEST_ONLY=http_handlers_tests.jl` passed after the documentation pass.
  - The router/middleware parity section in `http-master-parity.md` was updated without disturbing unrelated edits elsewhere in that file.
- Completion criteria:
  - README examples match real public APIs in the current tree.
  - `http-master-parity.md` no longer describes router/middleware as missing.

### [ ] ITEM-005 (P0) Run the full verification matrix, push the branch, open the PR, and drive CI green
- Description: The feature is not done until the full local suite is clean, the branch is pushed, the PR exists, and GitHub Actions are green. Any regressions uncovered by the full suite or CI need to be fixed before reporting back.
- Desired outcome: All relevant local verification passes, the feature branch is pushed, a PR is open against `main`, and GitHub Actions checks for that PR complete successfully.
- Affected files: `test/runtests.jl`, `.github/workflows/` (only if CI fixes are required), plus any source/test/docs files needing follow-up fixes
- Implementation notes:
  - Run the targeted HTTP suites first, then the full package test command from the repo instructions.
  - Commit each completed item separately before moving on, then push the branch and open the PR with a concise parity-focused description.
  - Use `gh run list` / `gh run view --log-failed` to inspect failures and iterate until CI is green.
  - Do not disturb unrelated existing worktree changes while preparing commits or the PR.
- Verification:
  - `JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'`
  - `git status --short`
  - `gh pr create --base main --head http-server-handlers-router-parity --title "<fill after implementation>" --body "<fill after implementation>"`
  - `gh run list --branch http-server-handlers-router-parity --limit 20`
- Assumptions:
  - GitHub auth and push permissions remain available for this repo during the final PR/CI step.
  - Any CI-only regressions should be fixed on the same feature branch before the task is considered complete.
- Completion criteria:
  - Local full test command passes.
  - PR is open and its CI checks are green.
