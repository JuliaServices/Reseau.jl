# Action Items: Secure Transport Parity Hardening

## Context
- Repo: Reseau
- Worktree: /Users/jacob.quinn/.julia/dev/Reseau-secure-transport-review
- Branch: codex/secure-transport-review

## Items

### [x] ITEM-001 (P0) Harden SecureTransport setup calls and protocol minimum mapping
- Description: The SecureTransport handler currently maps `TLSv1_1` to the TLS 1.2 constant and ignores critical `OSStatus` results during handler setup/shutdown.
- Desired outcome: SecureTransport setup uses the correct TLS enum mapping and fails fast with deterministic errors when setup APIs fail.
- Affected files: `src/sockets/apple/secure_transport_tls_handler.jl`, `test/alpn_tests.jl`
- Implementation notes:
  - Add a small helper to assert successful `OSStatus` from SecureTransport setup calls.
  - Fix TLS minimum version mapping for `TLSv1_1`.
  - Check `SSLSetProtocolVersionMin`, `SSLSetSessionOption`, `SSLSetCertificate`, `SSLSetPeerDomainName`, and shutdown `SSLClose` status handling.
  - Add an Apple-focused regression test for TLS min-version mapping behavior.
- Verification:
  - `julia --project=. test/alpn_tests.jl`
- Assumptions:
  - Existing `ERROR_IO_TLS_CTX_ERROR` is the correct setup-failure error surface for these setup call failures.
  - Regression test can validate mapping through helper-level behavior without mocking C APIs.
- Execution notes (2026-02-28):
  - Add small helper functions in SecureTransport implementation and validate helper behavior in `test/alpn_tests.jl` to avoid dependence on TLS env-gated suites for this item's verification.
- Risks:
  - Tightening status checks can surface latent failures on some macOS versions that were previously silent.
- Completion criteria:
  - Correct TLS enum mapping exists for `TLSv1_1`.
  - All targeted setup calls are status-checked.
  - Regression test passes.
- Verification evidence:
  - 2026-02-28: `julia --project=. -e 'using Test, Reseau; import Reseau: Sockets, EventLoops; include(\"test/alpn_tests.jl\")'` passed.

### [x] ITEM-002 (P1) Modernize trust evaluation path to current Security API guidance
- Description: Custom trust validation path uses deprecated `SecTrustEvaluate`.
- Desired outcome: Trust validation uses `SecTrustEvaluateWithError` and preserves current decision semantics (`trusted` vs `not trusted`) with better diagnostic logging.
- Affected files: `src/sockets/apple/secure_transport_tls_handler.jl`, `test/tls_tests_impl.jl`
- Implementation notes:
  - Replace `SecTrustEvaluate` branch with `SecTrustEvaluateWithError`.
  - Release returned `CFErrorRef` to avoid leaks.
  - Preserve existing trust success semantics and error mapping behavior.
  - Add/adjust tests to ensure Apple custom trust path behavior remains stable.
- Verification:
  - `RESEAU_RUN_TLS_TESTS=1 julia --project=. test/tls_tests.jl`
- Assumptions:
  - Supported macOS runtime baseline in this project includes `SecTrustEvaluateWithError`.
- Execution notes (2026-02-28):
  - Use `SecTrustEvaluateWithError` directly in the SecureTransport custom trust path and log `CFError` descriptions when available.
- Risks:
  - Trust failure behavior differences between APIs could alter observed error paths in edge cases.
- Completion criteria:
  - No use of `SecTrustEvaluate` remains in SecureTransport trust-validation path.
  - TLS test suite with TLS enabled passes locally.
- Verification evidence:
  - 2026-02-28: `JULIA_NUM_THREADS=1 RESEAU_RUN_TLS_TESTS=1 julia --project=. -e 'using Test, Reseau; import Reseau: Threads, EventLoops, Sockets; include(\"test/test_utils.jl\"); cleanup_test_sockets!(); setup_test_keychain!(); function wait_for_pred(pred::Function; timeout_s::Float64 = 5.0); start = Base.time_ns(); timeout_ns = Int(timeout_s * 1_000_000_000); while (Base.time_ns() - start) < timeout_ns; pred() && return true; sleep(0.01); end; return false; end; try include(\"test/tls_tests.jl\") finally cleanup_test_keychain!(); cleanup_test_sockets!() end'` passed.

### [x] ITEM-003 (P1) Close key SecureTransport parity-test gaps identified in review
- Description: Current tests miss some actionable parity checks (unknown NW TLS error fallback and selected Apple PKI negative paths).
- Desired outcome: Add deterministic regression tests for these gaps so future regressions are caught.
- Affected files: `test/tls_tests_impl.jl`, `test/pki_utils_tests.jl`
- Implementation notes:
  - Add an explicit assertion for `_nw_determine_socket_error` unknown/fallback mapping.
  - Add Apple PKI negative tests for invalid keychain path and invalid PKCS#12 password.
- Verification:
  - `RESEAU_RUN_TLS_TESTS=1 julia --project=. test/pki_utils_tests.jl`
  - `RESEAU_RUN_TLS_TESTS=1 julia --project=. test/tls_tests.jl`
- Assumptions:
  - These negative-path tests are stable across local macOS environments when TLS tests are enabled.
- Execution notes (2026-02-28):
  - Add only deterministic negative-path checks that do not rely on external network state.
- Risks:
  - Keychain/path behavior can vary by host policy; tests may need robust assertions around error-type rather than exact status.
- Completion criteria:
  - New regression tests are present and passing.
- Verification evidence:
  - 2026-02-28: `RESEAU_RUN_TLS_TESTS=1 julia --project=. -e 'using Test, Reseau; import Reseau: EventLoops, Sockets; include(\"test/test_utils.jl\"); setup_test_keychain!(); try include(\"test/pki_utils_tests.jl\") finally cleanup_test_keychain!() end'` passed.
  - 2026-02-28: `JULIA_NUM_THREADS=1 RESEAU_RUN_TLS_TESTS=1 julia --project=. -e 'using Test, Reseau; import Reseau: Threads, EventLoops, Sockets; include(\"test/test_utils.jl\"); cleanup_test_sockets!(); setup_test_keychain!(); function wait_for_pred(pred::Function; timeout_s::Float64 = 5.0); start = Base.time_ns(); timeout_ns = Int(timeout_s * 1_000_000_000); while (Base.time_ns() - start) < timeout_ns; pred() && return true; sleep(0.01); end; return false; end; try include(\"test/tls_tests.jl\") finally cleanup_test_keychain!(); cleanup_test_sockets!() end'` passed.

### [ ] ITEM-004 (P0) Full validation, PR open, and CI pass on all platforms
- Description: After implementing all fixes, run full validation, open a PR, and ensure CI platform checks are green.
- Desired outcome: Clean branch with itemized commits, full local tests passing, PR opened against `main`, and all CI checks successful.
- Affected files: `secure-transport-review.md`, `secure-transport-action-items.md`, repository files changed by prior items
- Implementation notes:
  - Run full package tests.
  - Push branch and open PR with concise parity-focused summary.
  - Monitor CI runs to completion and fix failures until green.
  - Update action-item file with verification evidence and final statuses.
- Verification:
  - `julia --project=. -e 'using Pkg; Pkg.test()'`
  - `gh pr create --base main --head codex/secure-transport-review --title "..." --body "..."`
  - `gh run list --branch codex/secure-transport-review`
  - `gh run view <run-id> --log-failed`
- Assumptions:
  - GitHub CLI auth and push permissions are configured for `JuliaServices/Reseau.jl`.
- Risks:
  - CI-only platform differences may require follow-up patches after initial PR creation.
- Completion criteria:
  - PR exists with all item commits.
  - All required CI checks are passing.
