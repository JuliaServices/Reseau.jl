# s2n Review: Reseau vs aws-c-io + Official s2n docs

Date: 2026-02-28
Branch/worktree used: `codex/s2n-review` in `/Users/jacob.quinn/.julia/dev/Reseau-s2n-review`

## Executive Summary

Reseau's Linux s2n implementation is very close to `aws-c-io` in logic flow and feature coverage. The core TLS state machine, async private key operations, delayed shutdown/blinding, trust-store setup paths, and ALPN parsing behavior mostly match the C reference implementation.

The biggest functional parity gap I found is OCSP setup error handling: Reseau currently ignores non-success from `s2n_config_set_check_stapled_ocsp_response(...)`, while `aws-c-io` only ignores `S2N_ERR_T_USAGE` and treats other failures as errors.

Test coverage is broad and strong, but it is not fully parity-complete with `aws-c-io` for network matrix breadth and some PKCS#11 edge-case assertions.

## Scope and Method

I reviewed:
- Reseau implementation (`src/sockets/linux/s2n_tls_handler.jl`, `src/sockets/socket/tls_channel_handler.jl`, `src/sockets/socket/pkcs11.jl`, `src/sockets/socket/tls_types.jl`, `src/sockets/socket/pki_utils.jl`)
- Reseau tests (`test/tls_tests_impl.jl`, `test/pkcs11_tests.jl`, `test/pki_utils_tests.jl`)
- `aws-c-io` reference implementation (`source/s2n/s2n_tls_channel_handler.c`, `source/tls_channel_handler.c`, `include/aws/io/tls_channel_handler.h`, `tests/tls_handler_test.c`, `tests/pkcs11_test.c`, `source/pkcs11/v2.40/pkcs11.h`)
- Official/up-to-date s2n documentation (API reference and usage guide)

I also validated PKCS#11 struct sizes at runtime (Julia vs C): all checked sizes matched.

## Implementation Parity (Reseau vs aws-c-io)

### High-confidence parity areas

1. Static s2n init/cleanup lifecycle
- Reseau: `src/sockets/linux/s2n_tls_handler.jl:165-217`, `:220-236`
- C ref: `aws-c-io/source/s2n/s2n_tls_channel_handler.c:203-260`, `:1250-1276`
- Notes: `s2n_disable_atexit`, `s2n_init`, thread cleanup hooks all present and aligned.

2. Handshake/read/write/shutdown state machine
- Reseau: `src/sockets/linux/s2n_tls_handler.jl:478-947`
- C ref: `aws-c-io/source/s2n/s2n_tls_channel_handler.c:407-1170`
- Notes: blocking/error handling flow and delayed shutdown behavior are closely ported.

3. Delayed shutdown and self-service blinding flow
- Reseau: `src/sockets/linux/s2n_tls_handler.jl:560-585`, `:1439-1442`
- C ref: `aws-c-io/source/s2n/s2n_tls_channel_handler.c:999-1018`, `:1330`

4. Async private key operations and callback flow
- Reseau: `src/sockets/linux/s2n_tls_handler.jl:949-1088`, `src/sockets/socket/tls_channel_handler.jl:521-629`
- C ref: `aws-c-io/source/s2n/s2n_tls_channel_handler.c:700-997`
- Notes: op-type mapping, signature/hash mapping, completion scheduling, and single-complete guard all present.

5. Trust store override/default logic
- Reseau: `src/sockets/linux/s2n_tls_handler.jl:1279-1316`
- C ref: `aws-c-io/source/s2n/s2n_tls_channel_handler.c:1653-1705`

6. ALPN list parsing cap behavior
- Reseau: `src/sockets/linux/s2n_tls_handler.jl:588-595`
- C ref: `aws-c-io/source/s2n/s2n_tls_channel_handler.c:1198-1235`
- Notes: both cap to 4 protocols.

7. PKCS#11 struct layout parity (v2.40)
- Reseau defs: `src/sockets/socket/pkcs11.jl:67-190`
- C ref defs: `aws-c-io/source/pkcs11/v2.40/pkcs11.h:882-963`, `:1693-1763`
- Runtime size verification (Julia and C both):
  - `CK_VERSION=2`
  - `CK_INFO=88`
  - `CK_TOKEN_INFO=208`
  - `CK_ATTRIBUTE=24`
  - `CK_MECHANISM=24`
  - `CK_C_INITIALIZE_ARGS=48`
  - `CK_FUNCTION_LIST=552`

### Gaps / divergences

1. OCSP setup error handling divergence (important)
- Reseau: `src/sockets/linux/s2n_tls_handler.jl:1270-1277`
- C ref: `aws-c-io/source/s2n/s2n_tls_channel_handler.c:1638-1650`
- Behavior difference:
  - C: if OCSP setup fails, ignores only `S2N_ERR_T_USAGE`; otherwise errors out.
  - Reseau: silently ignores all failures of `s2n_config_set_check_stapled_ocsp_response`.
- Risk: hides misconfiguration/runtime issues where C would fail fast.

2. s2n allocator callback integration missing (parity gap)
- Reseau init path does not call `s2n_mem_set_callbacks`.
- C ref does: `aws-c-io/source/s2n/s2n_tls_channel_handler.c:224-229`.
- Impact: behavior differs for allocation routing/diagnostics. Not necessarily wrong for Julia, but not parity.

3. Missing security warning log when peer verification is disabled
- C ref logs explicit warning: `aws-c-io/source/s2n/s2n_tls_channel_handler.c:1713-1717`
- Reseau disables verification without equivalent warning: `src/sockets/linux/s2n_tls_handler.jl:1325-1327`
- Impact: observability and safer-default signaling gap.

## FFI / ccall Audit Against Official s2n API

Official API reference checked: `https://aws.github.io/s2n-tls/doxygen/s2n_8h.html`

### Correctly aligned examples
- `s2n_connection_set_blinding`, `s2n_connection_get_delay`
- `s2n_config_set_async_pkey_callback`
- `s2n_config_wipe_trust_store`, `s2n_config_set_verification_ca_location`, `s2n_config_add_pem_to_trust_store`

### Signature mismatches to fix

1. `s2n_async_pkey_op_set_output`
- Official: `int s2n_async_pkey_op_set_output(struct s2n_async_pkey_op *op, const uint8_t *data, uint32_t data_len)`
- Reseau: `(Ptr{Cvoid}, Ptr{UInt8}, Csize_t)` at `src/sockets/socket/tls_channel_handler.jl:595-601`
- Issue: `Csize_t` vs `uint32_t`.

2. `s2n_send` / `s2n_recv`
- Official: `ssize_t s2n_send(..., ssize_t size, s2n_blocked_status *blocked)`, same pattern for `s2n_recv`
- Reseau: uses `Int` return with `Csize_t` length at `src/sockets/linux/s2n_tls_handler.jl:763-771` and `:858-866`
- Issue: length should ideally be `Cssize_t` and return type `Cssize_t` for exact ABI intent.

3. `s2n_cert_chain_and_key_load_public_pem_bytes`
- Official docs list length as `uint32_t`.
- Reseau uses `Csize_t`: `src/sockets/linux/s2n_tls_handler.jl:1250-1254`
- Issue: width mismatch and potential truncation/semantic mismatch for large lengths.

Note: these mismatches are often non-fatal on mainstream ABIs for small values, but they are still correctness/portability risks and should be cleaned up.

## Test Coverage Parity Review

### Raw count snapshot
- `aws-c-io` TLS tests (`AWS_TEST_CASE` in `tls_handler_test.c`): **57**
- `aws-c-io` PKCS#11 tests (`AWS_TEST_CASE` in `pkcs11_test.c`): **22**
- Reseau TLS `@testset` occurrences (`test/tls_tests_impl.jl`): **43**
- Reseau PKCS#11 `@testset` occurrences (`test/pkcs11_tests.jl`): **20**

Count-only comparison is imperfect, but Reseau is slightly below C test breadth and has a few high-value missing scenarios.

### Where Reseau is strong
- Local TLS handshake flows and state transitions are well covered.
- Coverage exists for timeout behavior, concurrent cert import, duplicate cert import, PKCS8 import, ECC import, cipher preferences, backpressure, cached shutdown, and statistics integration.
- PKCS#11 suite covers library/session/login/find/decrypt/sign and TLS negotiation integration (RSA/EC).

### Coverage gaps vs `aws-c-io`

1. Network badssl matrix breadth is narrower in Reseau
- C covers many additional hosts/cases (for example: `dh480`, `dh512`, `dh1024`, `null`, `tls-v1-0`, `tls-v1-1`, `dh2048`, `no-subject`, `no-common-name`, plus more positive cases like `sha256`, `rsa2048`, `extended-validation`, `mozilla-modern`).
- Reseau network set currently includes a smaller subset (`ecc256`, `ecc384`, `expired`, `wrong.host`, `self-signed`, `untrusted-root`, `rc4`, `rc4-md5`, and `www.amazon.com`).
- References:
  - C: `aws-c-io/tests/tls_handler_test.c:1163-1268`, `:1721-1830`
  - Reseau: `test/tls_tests_impl.jl:2702-2772`

2. mTLS TLS1.3 MQTT/ALPN scenario missing
- C has `tls_client_channel_negotiation_success_mtls_tls1_3` with explicit `x-amzn-mqtt-ca` checks.
- Reference: `aws-c-io/tests/tls_handler_test.c:1497-1564`, `:1631-1638`
- Reseau has no equivalent external mTLS+ALPN parity case.

3. External "socket closed during negotiation" scenario is not mirrored 1:1
- C test intentionally negotiates TLS on port 80 and verifies `AWS_IO_SOCKET_CLOSED` path.
- Reference: `aws-c-io/tests/tls_handler_test.c:1270-1335`
- Reseau has local server-hangup behavior coverage, but not this external wrong-port socket-close pattern.
- Reference: `test/tls_tests_impl.jl:1978-2086`

4. PKCS#11 strict initialize/finalize expected behavior mismatch
- C strict behavior test expects second strict init to fail with `CKR_CRYPTOKI_ALREADY_INITIALIZED`.
- Reference: `aws-c-io/tests/pkcs11_test.c:538-553`
- Reseau strict test currently expects second strict init to succeed.
- Reference: `test/pkcs11_tests.jl:625-637`

5. PKCS#11 signing edge-case assertions are lighter in Reseau
- C checks invalid-session and invalid-key failures for sign operations and performs EC DER/signature verification.
- Reference: `aws-c-io/tests/pkcs11_test.c:1231-1253`, `:1411-1474`
- Reseau RSA/EC sign tests currently check success + unsupported key type, but not full invalid session/key matrix or EC signature structural verification.
- Reference: `test/pkcs11_tests.jl:953-1033`

## Official s2n Usage Guidance Checks

Sources:
- API reference: `https://aws.github.io/s2n-tls/doxygen/s2n_8h.html`
- Usage guide: `https://aws.github.io/s2n-tls/usage-guide/`

Findings:
1. Init/cleanup model alignment is good
- Reseau uses `s2n_disable_atexit`, `s2n_init`, and thread cleanup hooks, matching expected lifecycle guidance.

2. Custom I/O callback style is aligned
- s2n callback contracts allow partial reads/writes and blocked signaling; Reseau's generic read/write callbacks mirror the C design.

3. Security policy handling is parity with aws-c-io, but policy names are time-versioned
- Reseau mirrors aws-c-io's policy mapping exactly (`AWS-CRT-SDK-*` and legacy `CloudFront/ELB` names).
- This is parity-correct, but should be periodically revalidated against latest s2n policy recommendations.

4. Verify-peer disabled warning from C is missing in Reseau
- This is a best-practice observability gap vs documented security posture expectations.

## Prioritized Recommendations

### P0 (fix first)
1. Match C OCSP error handling exactly
- Implement the C behavior: if OCSP enabling fails, ignore only `S2N_ERR_T_USAGE`; otherwise fail context creation.

2. Correct strict PKCS#11 test semantics
- Update `pkcs11 lib behavior strict initialize/finalize` test to match C expected failure on second strict init.

### P1
1. Tighten s2n `ccall` signatures to documented widths
- `s2n_async_pkey_op_set_output`: use `UInt32` length.
- `s2n_send` / `s2n_recv`: prefer `Cssize_t` len/return.
- `s2n_cert_chain_and_key_load_public_pem_bytes`: align length type with API expectation.

2. Add PKCS#11 sign negative-matrix assertions
- Invalid session handle and invalid key handle checks for RSA and EC sign paths.
- Add EC signature structure/verification assertions analogous to C.

### P2
1. Expand network parity matrix in TLS tests
- Add missing badssl and edge hosts present in C where feasible.
- Add mTLS TLS1.3 `x-amzn-mqtt-ca` parity scenario (or explicit rationale if not feasible in CI).

2. Add warning log when client verification is disabled
- Mirror C warning text intent.

3. Decide explicitly on allocator-callback parity
- Either add `s2n_mem_set_callbacks` integration for parity, or document why Julia intentionally relies on s2n defaults.

## Bottom Line

- **Implementation logic parity with aws-c-io:** strong, with one notable behavior bug (OCSP error handling) and a few ABI signature cleanups needed.
- **Test parity:** good but not fully equivalent; several high-value network and PKCS#11 edge cases are missing or behaviorally divergent.
- **Docs alignment:** mostly good; no major architecture violations found, but a few recommended hardening/observability items are missing.
