# Secure Channel / TLS Deep Parity Review (Reseau vs aws-c-io)

Date: 2026-02-28
Worktree: `codex/secure-channel-review`
Scope: TLS "secure channel" stack in Reseau, compared against `aws-c-io` reference logic/tests, plus official platform documentation (Schannel, SecureTransport, s2n).

## Executive Summary

Reseau’s TLS implementation is broadly faithful to `aws-c-io` for core flow and backend behavior, with strong parity across:
- Shared negotiation lifecycle and timeout/statistics wiring.
- Linux `s2n` flow (including async custom private-key operations).
- macOS SecureTransport handshake/read/write/shutdown and trust-evaluation flow.
- Windows Schannel handshake/decrypt/encrypt/manual-cert-validation flow.

At initial review time, the largest parity gap was Windows TLS 1.3 capability selection:
- `aws-c-io` conditionally uses `SCH_CREDENTIALS` on newer Windows builds and falls back to deprecated `SCHANNEL_CRED`.
- Reseau currently uses only `SCHANNEL_CRED`, which hard-blocks minimum TLS 1.3.

Test parity was strong for local handshake/core lifecycle scenarios, with initial breadth gaps vs `aws-c-io`’s extended network matrix and several channel-core behaviors.

## Implementation Update (This Branch)

The following findings were addressed in `codex/secure-channel-review`:

- Finding #1 (`SCH_CREDENTIALS` parity gap): Implemented.
  - Added runtime-selected `SCH_CREDENTIALS` path with Windows build gating and fallback to `SCHANNEL_CRED`.
  - Added force-toggle support for deterministic deprecated-path testing on Windows.
- Finding #4 (network matrix breadth): Implemented.
  - Expanded badssl endpoint matrix to include legacy cipher/protocol and uncommon-cert cases, plus no-verify parity checks.
  - Verified with TLS+network-enabled run (`TLS network negotiation`: `32/32`).
- Finding #3 (SecureTransport TLSv1_1 mapping ambiguity): Documented and test-guarded.
  - Added explicit helper for SecureTransport minimum protocol mapping and tests asserting TLSv1_1 -> TLSv1_2 behavior.
- Finding #2 (`on_error` callback surface divergence): Documented parity stance.
  - Kept existing `Future` + channel-shutdown error propagation model intentionally.
  - Added inline comments and test assertions clarifying there is no `on_error` field in `TlsConnectionOptions`.

## Method

Compared source and tests directly:

- Reseau
  - `src/sockets/socket/tls_types.jl`
  - `src/sockets/socket/tls_channel_handler.jl`
  - `src/sockets/linux/s2n_tls_handler.jl`
  - `src/sockets/apple/secure_transport_tls_handler.jl`
  - `src/sockets/windows/secure_channel_tls_handler.jl`
  - `test/tls_tests.jl`, `test/tls_tests_impl.jl`
  - `test/channel_tests.jl`, `test/io_testing_channel_tests.jl`

- aws-c-io reference
  - `include/aws/io/tls_channel_handler.h`
  - `source/tls_channel_handler.c`
  - `source/tls_channel_handler_shared.c`
  - `source/s2n/s2n_tls_channel_handler.c`
  - `source/darwin/secure_transport_tls_channel_handler.c`
  - `source/windows/secure_channel_tls_handler.c`
  - `tests/tls_handler_test.c`, `tests/channel_test.c`, `tests/io_testing_channel_test.c`

- Official docs reviewed
  - Microsoft Schannel/SSPI docs (Acquire/Init/Accept/Query/Decrypt/protocol support/ALPN structures)
  - s2n docs (usage guide + doxygen)
  - Apple SecureTransport + Security docs (including archived Secure Transport programming docs and current result-code/trust docs)

## Findings (Severity-Ordered)

Status note: This section captures the initial audit snapshot; remediation status is tracked in "Implementation Update (This Branch)" above.

### 1) High: Missing `SCH_CREDENTIALS` path on Windows (TLS 1.3 capability parity gap)

- Reference behavior in `aws-c-io`:
  - Uses `SCH_CREDENTIALS` on suitable SDK/OS combinations, with runtime build checks and fallback path.
  - Files/lines: `source/windows/secure_channel_tls_handler.c:2146-2214`, `:2289-2303`.
- Reseau behavior:
  - Only builds/uses `_SCHANNEL_CRED` and rejects min TLSv1_3.
  - Files/lines: `src/sockets/windows/secure_channel_tls_handler.jl:146-161`, `:1336-1382`, `:1523-1559`.
- Impact:
  - On modern Windows systems where Schannel TLS 1.3 is available, Reseau cannot match `aws-c-io` capability.
  - Also misses the upstream split logic (new-cred vs deprecated-cred path).

### 2) Medium: Public callback/API surface diverges (`on_error` callback not exposed in Reseau TLS options)

- `aws-c-io` connection options include `on_error` callback in API surface.
  - `include/aws/io/tls_channel_handler.h:127-154`.
- Reseau `TlsConnectionOptions` includes negotiation-result future and `on_data_read`, but no `on_error` field/setter.
  - `src/sockets/socket/tls_types.jl:243-251`
  - `src/sockets/socket/tls_channel_handler.jl:1120-1172`.
- Note:
  - In the inspected `aws-c-io` backend files, `on_error` is stored but not obviously invoked in these paths.
  - This is still API parity divergence at interface level.

### 3) Medium: SecureTransport minimum TLS v1.1 maps to TLS 1.2 (inherited from reference; doc expectation mismatch risk)

- `aws-c-io` maps TLSv1_1 -> `kTLSProtocol12` in SecureTransport path.
  - `source/darwin/secure_transport_tls_channel_handler.c:922-927`.
- Reseau mirrors this exactly.
  - `src/sockets/apple/secure_transport_tls_handler.jl:1047-1050`.
- Risk:
  - This is parity-accurate with upstream, but surprising relative to expected protocol-min semantics.
  - Should be explicitly documented in code/tests so behavior is intentional and auditable.

### 4) Medium: Test breadth gap vs aws-c-io extended negotiation matrix

- `aws-c-io` runs a larger external endpoint matrix (legacy/odd cert/crypto endpoints such as `dh*`, `null`, `no-subject`, `no-common-name`, `sha*`, `rsa*`, EV, mozilla-modern, socket-closed during negotiation).
  - `tests/tls_handler_test.c:1163-1335`, `:1708-1830`.
- Reseau network matrix covers core badssl categories but not all of the above breadth.
  - `test/tls_tests_impl.jl:2703-2772`.
- Impact:
  - Reduced parity for real-world edge-case regressions that upstream currently checks.

### 5) Low (positive divergence): Reseau credential-handle teardown is safer than current aws-c-io code

- In inspected `aws-c-io` file, handler destroy uses `DeleteSecurityContext()` for both context and creds handle.
  - `source/windows/secure_channel_tls_handler.c:1902-1908`.
- Reseau uses `DeleteSecurityContext` for context and `FreeCredentialsHandle` for creds.
  - `src/sockets/windows/secure_channel_tls_handler.jl:1771-1781`.
- This appears to be a correctness improvement over current reference implementation.

## Core API/Feature Parity

### High-level parity

- Core enums/options align well:
  - TLS version/cipher enums align with current `aws-c-io` additions (`PQ_DEFAULT`, 2025 policies).
  - `src/sockets/socket/tls_types.jl:3-25` vs `include/aws/io/tls_channel_handler.h:20-58`.
- Connection/context option helpers are largely mirrored.
  - `src/sockets/socket/tls_channel_handler.jl:648-1188`.
- Client/server handler creation and negotiation startup mirrored.
  - `src/sockets/socket/tls_channel_handler.jl:1328-1416`.
- `channel_setup_client_tls` parity present.
  - `src/sockets/socket/tls_channel_handler.jl:1460-1477`
  - `include/aws/io/tls_channel_handler.h:936-939`.

### Notable API differences

- `on_error` callback surface missing in Reseau options/setters (see Finding #2).
- Reseau uses a Future-based negotiation result signal (good ergonomic replacement for callback-heavy calling pattern).

## Platform Deep Dive

## Linux (`s2n`)

### Parity status: Strong

- Negotiation drive loop and blocked-state handling follow expected `s2n_negotiate` pattern.
  - `src/sockets/linux/s2n_tls_handler.jl:486-509, 789`
  - `source/s2n/s2n_tls_channel_handler.c` flow equivalents.
- Async private-key callback path present, including completion/single-complete guard logic.
  - `src/sockets/linux/s2n_tls_handler.jl` (custom key op region)
  - aligns with upstream async pkey integration.
- Security policy mapping mirrors current upstream logic, including custom-key-op fallback policy behavior.
  - Reseau: `src/sockets/linux/s2n_tls_handler.jl:1132-1150`
  - aws-c-io: `source/s2n/s2n_tls_channel_handler.c:1478-1524`.

### Notes

- `TLS_VER_SYS_DEFAULTS` + custom key op fallback policy remains intentionally conservative (same as upstream), and should be documented as security/compat tradeoff.

## macOS (`SecureTransport`)

### Parity status: Strong (legacy API model)

- Callback I/O bridge (`SSLSetIOFuncs`, `SSLSetConnection`) and handshake state machine (`SSLHandshake`, `errSSLWouldBlock`) are mirrored.
  - Reseau: `src/sockets/apple/secure_transport_tls_handler.jl:518-607`, `:1039-1059`.
  - aws-c-io: `source/darwin/secure_transport_tls_channel_handler.c:954-955`, handshake/read/write flow.
- Custom trust store flow mirrors upstream approach:
  - break-on-auth, peer trust extraction, policy setup, anchor certs, trust evaluate.
  - Reseau: `src/sockets/apple/secure_transport_tls_handler.jl:417-476`, `:1074-1080`.

### Notes

- Reseau mirrors upstream TLSv1_1 -> TLSv1_2 mapping (Finding #3).
- Reseau currently rejects explicit TLSv1_3 in SecureTransport handler path (consistent with current macOS-focused upstream behavior/comments).

## Windows (`SecureChannel` / Schannel)

### Parity status: Good flow parity, major capability gap (TLS 1.3 path)

- Handshake and token exchange flows match upstream pattern (`AcceptSecurityContext`/`InitializeSecurityContext`, ALPN input buffer, token output handling).
  - Reseau: `src/sockets/windows/secure_channel_tls_handler.jl:722-1065`.
- Decrypt/encrypt and renegotiation handling mirrored, including `SEC_I_RENEGOTIATE` path back through `InitializeSecurityContext`.
  - Reseau: `:1073-1183`, `:1915-1933`.
- Manual peer cert verify path mirrors upstream custom-CA chain engine + SSL policy checks.
  - Reseau: `:531-693`.

### Gap

- No `SCH_CREDENTIALS` path/runtime selection (Finding #1).

## ABI / ccall Review

This was a static audit (no Windows runtime ABI smoke-run in this pass).

## Structures and signatures reviewed

- `SecHandle` / `CredHandle` / `CtxtHandle`
  - Julia: `_SecHandle` with two `UInt` fields (`uintptr_t`-sized) at `secure_channel_tls_handler.jl:106-113`.
  - Matches SSPI handle representation expectations on 64-bit builds.
- `SecBuffer`, `SecBufferDesc`
  - Julia layouts at `:119-129`, used consistently in all Schannel entrypoints.
- `SecPkgContext_ApplicationProtocol`
  - Julia layout at `:139-144` with fixed 255-byte protocol buffer.
  - Aligned with documented max protocol id size usage.
- `SCHANNEL_CRED`
  - Julia layout at `:146-161` aligns with deprecated credential structure usage.
  - Missing `SCH_CREDENTIALS` equivalent (intentional current limitation, Finding #1).
- Cert chain structs (`CERT_CHAIN_PARA`, `CERT_CHAIN_ENGINE_CONFIG`, etc.)
  - Julia definitions at `:181-256`; call sites line up with Wincrypt usage in manual verification path.

## ccall hygiene observations

- Good `GC.@preserve` usage at high-risk boundaries:
  - ALPN input buffers and output tokens around Init/Accept calls.
  - credential struct and cert arrays for AcquireCredentialsHandle.
- Return-type/signature usage is generally correct (`Int32` for `SECURITY_STATUS`/`OSStatus`, pointer/reference conventions aligned).

## Docs Conformance Review (Official Guidance)

## Schannel (Microsoft)

Validated against current Microsoft Learn docs:

- `SCH_CREDENTIALS` is the modern credential structure; `SCHANNEL_CRED` is legacy/deprecated path (matches upstream split, not yet in Reseau).
- TLS 1.3 availability for Schannel is OS/build dependent (Windows 11 / Server 2022 era onward).
- `InitializeSecurityContext` / `AcceptSecurityContext` token-loop semantics and buffer expectations match current flow in Reseau.
- `DecryptMessage` renegotiation handling (`SEC_I_RENEGOTIATE`) is implemented in Reseau consistent with docs and upstream.
- `QueryContextAttributes` usage for stream sizes, remote cert context, and negotiated ALPN is correctly patterned.

Conformance verdict:
- Flow correctness: strong.
- Capability parity: blocked by missing `SCH_CREDENTIALS` path.

## s2n

Validated against s2n usage + API docs:

- `s2n_negotiate` handshake loop and blocked-I/O driven progression matches guidance.
- Async private key callback path and completion pattern are present and aligned with expected usage.
- Policy-selection approach mirrors upstream, including conservative handling when custom key ops are enabled.

Conformance verdict:
- Strong parity.

## SecureTransport (Apple)

Validated against available Apple docs (current pages + archive docs):

- Callback I/O model and `errSSLWouldBlock` handshake/read-write behavior are correctly used.
- Trust handling via break-on-auth + trust evaluation path is consistent with documented strategy for custom trust.
- SecureTransport itself is legacy in Apple’s ecosystem; current Apple guidance prioritizes broader Security/Trust APIs and higher-level transport stacks for modern apps.

Conformance verdict:
- Correct for SecureTransport model, with the caveat that this is legacy platform surface.

## Test Coverage Parity

## What Reseau matches well

- TLS local integration scenarios:
  - echo+backpressure, shutdown-with-cached-data (including window-update variant), cert chain, multiple connections, hangup during negotiation, handler statistics integration.
  - `test/tls_tests_impl.jl:1869-2699`.
- Cert import and option coverage:
  - concurrent/duplicate/pkcs8/ecc/cipher-pref and option helper parity sets.
  - `test/tls_tests_impl.jl:277-1712`, `:1621-1712`.
- Core channel and io-testing parity exists for many baseline scenarios.
  - `test/channel_tests.jl`, `test/io_testing_channel_tests.jl`.

## Gaps vs aws-c-io test breadth

- Extended badssl/legacy endpoint matrix is narrower in Reseau.
  - Missing many named legacy/uncommon endpoint scenarios present in upstream tests.
- Socket-closed-during-negotiation external scenario from upstream is not directly mirrored.
- Some channel-core scenarios in upstream (`refcount_delays_cleanup`, multi-host timeout fallback, ELG-liveness) are not matched 1:1 in Reseau focused suites.

## Gating note

- Reseau TLS/network suites are env-gated (`RESEAU_RUN_TLS_TESTS`, `RESEAU_RUN_NETWORK_TESTS`), but CI currently enables both on Linux/Windows/macOS.
  - `.github/workflows/ci.yml:12-33`
  - `test/tls_tests.jl:12-16`.

## Recommendations

1. Add `SCH_CREDENTIALS` support in Reseau SecureChannel backend.
- Include OS/build gate logic similar to upstream and fallback to `SCHANNEL_CRED` where required.
- Add explicit tests for both credential paths (including a forced fallback toggle for deterministic testability).

2. Expand network parity matrix toward upstream badssl coverage.
- Add missing endpoint classes (legacy protocol/cipher, uncommon cert subjects, rsa/sha variants, etc.) with stability handling (allow skip for transient endpoint instability, but keep scenario coverage).

3. Decide and document the `on_error` callback parity stance.
- Either add an explicit equivalent API in Reseau, or document why the Future+shutdown model is intentionally preferred and what telemetry substitutes it.

4. Add ABI guard tests for Windows struct assumptions.
- Lightweight runtime checks on Windows CI for key struct sizes/offset assumptions and selected ccall smoke tests.

5. Document intentional SecureTransport semantics.
- Especially TLSv1_1->TLSv1_2 mapping and explicit TLS 1.3 limitations.

## Reference Links (Official Docs)

- Microsoft Learn (Schannel/SSPI)
  - SCH_CREDENTIALS: https://learn.microsoft.com/en-us/windows/win32/api/schannel/ns-schannel-sch_credentials
  - InitializeSecurityContext (Schannel): https://learn.microsoft.com/en-us/windows/win32/secauthn/initializesecuritycontext--schannel
  - AcceptSecurityContext (Schannel): https://learn.microsoft.com/en-us/windows/win32/secauthn/acceptsecuritycontext--schannel
  - QueryContextAttributes (Schannel): https://learn.microsoft.com/en-us/windows/win32/secauthn/querycontextattributes--schannel
  - AcquireCredentialsHandle (Schannel): https://learn.microsoft.com/en-us/windows/win32/secauthn/acquirecredentialshandle--schannel
  - DecryptMessage (Schannel): https://learn.microsoft.com/en-us/windows/win32/secauthn/decryptmessage--schannel
  - SecPkgContext_ApplicationProtocol: https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secpkgcontext_applicationprotocol
  - SecBuffer: https://learn.microsoft.com/en-us/windows/win32/api/sspi/ns-sspi-secbuffer
  - Protocols in TLS/SSL (Schannel SSP): https://learn.microsoft.com/en-us/windows/win32/secauthn/protocols-in-tls-ssl--schannel-ssp-

- s2n
  - API docs: https://aws.github.io/s2n-tls/doxygen/s2n_8h.html
  - Security policies guide: https://aws.github.io/s2n-tls/usage-guide/ch05-security-policies.html
  - I/O usage guide: https://aws.github.io/s2n-tls/usage-guide/ch07-io.html

- Apple
  - Secure Transport result codes: https://developer.apple.com/documentation/security/secure-transport-result-codes
  - Secure Transport overview page: https://developer.apple.com/documentation/security/secure-transport
  - SSLSetTrustedRoots: https://developer.apple.com/documentation/security/sslsettrustedroots(_:_:)
  - Networking/Secure Transport archived guide: https://developer.apple.com/library/archive/documentation/Security/Conceptual/securetransportconcepts/Introduction.html
