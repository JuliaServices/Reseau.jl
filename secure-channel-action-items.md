# Action Items: Secure Channel Parity Follow-Up

## Context
- Repo: Reseau
- Worktree: /Users/jacob.quinn/.julia/dev/Reseau-secure-channel-review
- Branch: codex/secure-channel-review

## Items

### [x] ITEM-001 (P0) Add modern Windows credential path (`SCH_CREDENTIALS`) with runtime selection
- Description: Reseau Windows TLS currently uses only deprecated `SCHANNEL_CRED`, which blocks min TLS 1.3 and diverges from current `aws-c-io` behavior.
- Desired outcome: Windows backend supports both credential modes, defaults to `SCH_CREDENTIALS` on eligible Windows builds, and falls back to `SCHANNEL_CRED` when required.
- Affected files: `src/sockets/windows/secure_channel_tls_handler.jl`, `src/sockets/socket/tls_channel_handler.jl`, `test/tls_tests_impl.jl`
- Implementation notes:
  - Add Julia struct/constant definitions for `SCH_CREDENTIALS` and `TLS_PARAMETERS` equivalents needed for `AcquireCredentialsHandle`.
  - Add runtime capability gate (Windows build check) and selection logic mirroring `aws-c-io` behavior.
  - Add an internal force-toggle to choose deprecated credentials path for deterministic tests.
  - Preserve existing `SCHANNEL_CRED` behavior for unsupported systems.
- Verification:
  - `julia --project=. test/tls_tests.jl`
  - `julia --project=. -e 'using Reseau; using Reseau.Sockets; println("ok")'`
- Assumptions:
  - Tests on non-Windows will only validate API/logic shape; Windows-specific execution is validated in CI.
  - Existing credential import code can be reused for both credential paths.
- Risks:
  - Win32 struct layout mistakes can cause runtime handshake failures on Windows CI.
- Completion criteria:
  - Windows backend can select modern path, and min TLS 1.3 is no longer rejected solely due deprecated credential mode.
- Verification evidence:
  - 2026-02-28: `julia --project=. test/tls_tests.jl` (pass; TLS suite correctly skipped without `RESEAU_RUN_TLS_TESTS=1`).
  - 2026-02-28: `julia --project=. -e 'using Reseau; using Reseau.Sockets; println("ok")'` (pass; output `ok`).

### [x] ITEM-002 (P1) Add ABI/selection guard tests for Windows secure channel internals
- Description: Current tests do not explicitly guard Windows credential-path selection and struct/flag assumptions.
- Desired outcome: Deterministic tests verify credential-path selection, TLS version gating behavior, and core ALPN/credential configuration invariants.
- Affected files: `test/tls_tests_impl.jl`
- Implementation notes:
  - Add windows-conditional tests for credential mode selection logic and forced fallback behavior.
  - Add assertions for protocol-mask/disabled-protocol computation behavior.
  - Add targeted tests that prevent regressions in min-TLS handling across both paths.
- Verification:
  - `julia --project=. test/tls_tests.jl`
  - `julia --project=. -e 'using Test; using Reseau; import Reseau: Sockets; @testset "secure-channel-helpers" begin ... end'`
- Assumptions:
  - Internal helper functions can be exercised directly from test code without exposing new public API.
  - Local verification runs on non-Windows will validate deterministic helper behavior; Windows CI will validate runtime credential acquisition path.
- Risks:
  - Over-coupling tests to implementation details could make refactors noisy.
- Completion criteria:
  - New tests fail if modern/deprecated path selection regresses.
- Verification evidence:
  - 2026-02-28: `julia --project=. -e 'using Test; using Reseau; import Reseau: Sockets; @testset "secure-channel-helpers" begin ... end'` (pass; `13/13`).
  - 2026-02-28: `julia --project=. test/tls_tests.jl` (pass; TLS suite entrypoint and gating confirmed).

### [ ] ITEM-003 (P1) Expand TLS network parity matrix toward aws-c-io endpoint coverage
- Description: Reseau network TLS tests cover core badssl endpoints but miss several edge-case categories covered by aws-c-io.
- Desired outcome: Reseau network-gated tests include additional endpoints/scenarios, with resilient handling for known endpoint flakiness.
- Affected files: `test/tls_tests_impl.jl`
- Implementation notes:
  - Add missing endpoint scenarios where practical: legacy protocol/cipher and uncommon cert metadata variants.
  - Keep network tests gated by existing env var and include skip logic/messages for unstable endpoints.
  - Maintain deterministic non-network test behavior.
- Verification:
  - `RESEAU_RUN_TLS_TESTS=1 RESEAU_RUN_NETWORK_TESTS=1 julia --project=. test/tls_tests.jl`
- Assumptions:
  - External endpoints may intermittently fail; tests may need soft expectations for specific transient cases.
- Risks:
  - Increased network dependence can introduce flakiness if not carefully guarded.
- Completion criteria:
  - Added scenarios are represented in the network matrix and pass in current CI environment.

### [ ] ITEM-004 (P2) Document intentional SecureTransport protocol semantics and on-error parity stance
- Description: There are intentional-but-surprising parity behaviors (e.g., TLSv1_1 mapping on SecureTransport) and API stance differences (`on_error` callback surface).
- Desired outcome: Code and tests clearly document intentional behavior and reduce ambiguity for future maintainers.
- Affected files: `src/sockets/apple/secure_transport_tls_handler.jl`, `src/sockets/socket/tls_types.jl`, `src/sockets/socket/tls_channel_handler.jl`, `test/tls_tests_impl.jl`, `secure-channel-review.md`
- Implementation notes:
  - Add concise comments/doc notes near relevant code paths.
  - Add/adjust tests to assert the intended behavior explicitly.
  - Update review report with implementation outcomes.
- Verification:
  - `julia --project=. test/tls_tests.jl`
- Assumptions:
  - No public API breaking changes are required for this item.
- Risks:
  - Over-documentation noise if comments are too verbose.
- Completion criteria:
  - Behavior is explicit in code/tests and aligned with parity decisions.
