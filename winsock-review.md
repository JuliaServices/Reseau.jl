# Winsock Deep Review (Reseau)

Date: 2026-02-28  
Author: Codex (static audit)

## Scope

Requested review areas:

1. Parity of Reseau's Windows/Winsock implementation against `aws-c-io` (reference logic flow + feature surface).
2. Parity of test coverage for Windows core paths (winsock/iocp/socket/pipe/event-loop behavior).
3. Deep documentation audit against current official Microsoft docs for:
   - `ccall` signatures and return types
   - struct layouts
   - argument semantics and sequencing requirements
   - known gotchas/recommended usage

Codebases compared:

- Reseau worktree: `/Users/jacob.quinn/.julia/dev/Reseau-winsock-deep-review`
- Reference C lib: `/Users/jacob.quinn/.julia/dev/aws-c-io`

## Executive Summary

### 1) Implementation parity vs `aws-c-io`

Overall: **strong functional port coverage**, but **not full parity**.

From the parity matrix review:

- `covered = 5`
- `divergent = 8`
- `missing = 1`

Core winsock/IOCP flows are present (init, ConnectEx/AcceptEx, IOCP loop, readable/write flows, pipe backend), but there are meaningful behavioral divergences (especially around callback threading and close semantics), plus one missing public-equivalent helper.

### 2) Test parity vs `aws-c-io`

Overall: **not yet at parity for Windows core coverage**.

Scenario-level snapshot (Windows-relevant core scenarios):

- `equivalent = 6`
- `partial = 3`
- `missing = 1`

Biggest concrete gap: no direct equivalent to `aws-c-io`'s `event_loop_completion_events` callback-argument parity test.

### 3) Official docs compliance (latest Microsoft docs)

- Most `ccall` signatures and low-level layout mappings are correct and carefully handled.
- A few **logic-flow/documentation mismatches** are high-risk:
  1. AcceptEx address parsing does not use `GetAcceptExSockaddrs`.
  2. `SO_UPDATE_ACCEPT_CONTEXT` is not applied on accepted sockets.
  3. UDP readability uses overlapped `WSARecv` with `MSG_PEEK` while docs say `MSG_PEEK` is valid only for nonoverlapped sockets.

These are partly inherited from `aws-c-io` behavior, but they still represent docs-level risk and portability concerns.

## Methodology

- Static code inspection of Reseau Windows files:
  - `src/sockets/windows/winsock_init.jl`
  - `src/sockets/windows/winsock_socket.jl`
  - `src/sockets/windows/winsock_socket_types.jl`
  - `src/sockets/windows/iocp_pipe.jl`
  - `src/eventloops/windows/iocp_event_loop.jl`
- Static comparison to `aws-c-io` Windows reference files:
  - `source/windows/winsock_init.c`
  - `source/windows/iocp/socket.c`
  - `source/windows/iocp/pipe.c`
  - `source/windows/iocp/iocp_event_loop.c`
  - `source/windows/host_resolver.c`
- Scenario-level test inventory comparison across:
  - `aws-c-io/tests/socket_test.c`, `event_loop_test.c`, `pipe_test.c`
  - `Reseau/test/socket_tests.jl`, `event_loop_tests.jl`, `pipe_tests.jl`
- Docs cross-check done against current Microsoft Learn pages (latest update dates included in Sources).

## Detailed Findings

## High Severity

### H1. AcceptEx address parsing does not follow documented buffer parsing contract

Reseau currently parses accepted endpoint directly from start of `accept_buffer`:

- `src/sockets/windows/winsock_socket.jl:1108-1123`

Docs for `AcceptEx`/`GetAcceptExSockaddrs` specify that local and remote addresses are packed into internal format and should be parsed via `GetAcceptExSockaddrs`, with address lengths including extra 16 bytes.

Impact:

- Risk of parsing wrong address/port or relying on undocumented layout assumptions.
- Potential wrong remote endpoint reporting.

Reference parity note:

- `aws-c-io` appears to do similar direct parsing (`source/windows/iocp/socket.c:1975-1999`), so this is likely an inherited behavior.

Recommendation:

- Parse with `GetAcceptExSockaddrs` using the same lengths passed to `AcceptEx`.
- Add regression test asserting accepted `remote_endpoint` correctness (port + address family + address value).

### H2. Missing `SO_UPDATE_ACCEPT_CONTEXT` after AcceptEx completion

Reseau applies `SO_UPDATE_CONNECT_CONTEXT` for ConnectEx success (`winsock_socket.jl:516-525`) but does not set `SO_UPDATE_ACCEPT_CONTEXT` on accepted sockets in accept path.

Docs indicate accepted socket context should be updated before calling certain socket APIs (`getsockname`, `getpeername`, `getsockopt`, `setsockopt`, `shutdown`).

Impact:

- APIs on accepted sockets can fail or behave unexpectedly on some stacks/providers.
- Current flow sets socket options on accepted socket before any accept-context update.

Reference parity note:

- `aws-c-io` appears to have same omission in the winsock accept flow.

Recommendation:

- After successful `AcceptEx`, call `setsockopt(SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, ...)` using listener socket handle context.
- Add acceptance test that exercises post-accept `getsockopt/getsockname/shutdown` behavior.

## Medium Severity

### M1. UDP readable subscription uses overlapped `WSARecv(MSG_PEEK)` despite docs caveat

Reseau path:

- `src/sockets/windows/winsock_socket.jl:1688-1703`
- `src/sockets/windows/winsock_socket.jl:1752-1767`

This mirrors `aws-c-io` (`source/windows/iocp/socket.c:2874-2889`, `3166-3171`).

Docs state `MSG_PEEK` flag is valid only for nonoverlapped sockets.

Impact:

- Potential provider/version-specific incompatibility.
- Could fail on stricter providers even if it currently works.

Recommendation:

- Validate behavior across supported Windows versions/providers.
- Consider alternate UDP readability strategy if strict compliance is required.
- At minimum, add targeted Windows regression test for this path.

### M2. Cross-thread close semantics diverge from `aws-c-io`

`aws-c-io` listener close path blocks/hops to owner loop thread (`s_wait_on_close`, listener-only guard):

- `source/windows/iocp/socket.c:2510-2562`

Reseau closes directly in `socket_close_impl`:

- `src/sockets/windows/winsock_socket.jl:1518-1574`

Impact:

- Potential lifecycle races during close from non-owner thread (especially listener and in-flight IO paths).

Recommendation:

- Decide whether to match aws semantics (for parity + safety) or keep current model.
- If keeping current model, add dedicated cross-thread close stress tests.

### M3. Connect-path option handling diverges from reference

Differences found:

- Reseau treats `SO_REUSEADDR` in TCP connect as best-effort (`winsock_socket.jl:641-652`), while `aws-c-io` treats failure as connect failure (`socket.c:1012-1022`).
- Reseau UDP/local connect success path does not re-run option processing equivalent to aws's `s_process_tcp_sock_options` invocation pattern (`socket.c:1267`, `1376`).

Impact:

- Observable behavioral drift under option failure conditions.

Recommendation:

- Align behavior intentionally (documented divergence or parity update).
- Add tests for `setsockopt` failure handling in connect paths.

### M4. Windows host resolver initialization parity gap

`aws-c-io` Windows host resolver explicitly calls winsock init:

- `source/windows/host_resolver.c:26`

Reseau host resolver path uses `getaddrinfo` but does not call `winsock_check_and_init!` in that flow.

Impact:

- If winsock is not already initialized by process/runtime, resolver behavior can be environment-dependent.

Recommendation:

- Decide if resolver should explicitly initialize winsock for strict parity and robustness.

## Low Severity

### L1. `SockaddrIn.sin_family` uses `Cshort` (signed) instead of `Cushort`

Definition:

- `src/sockets/linux/posix_socket_impl.jl:678-683`

Windows docs define `sin_family` as `ADDRESS_FAMILY` (`USHORT`). Size matches, so this is likely benign, but unsigned type is more faithful.

Recommendation:

- Consider changing to `Cushort` for strict ABI readability consistency.

### L2. `WinsockSocketWriteRequest.detached` appears unused

- Set during close: `winsock_socket.jl:1552-1555`
- Not consumed in write completion callback path.

Recommendation:

- Remove dead field or wire intended behavior.

### L3. Pipe API parity differences (non-critical)

- Unique-name collision retry behavior differs.
- Public `pipe_get_unique_name` equivalent is not exposed (private helper only).

Recommendation:

- Only fix if you want strict API-surface parity with `aws-c-io`.

### L4. `WSAStartup` negotiation/cleanup contract is only partially implemented

Current Reseau init flow correctly calls `WSAStartup(2.2)` and caches extension pointers, but does not validate negotiated version fields in `WSADATA` and does not call `WSACleanup` in process lifetime.

Docs note:

- `wVersion` should be checked by caller.
- A successful `WSAStartup` should be paired with `WSACleanup` when done.

Impact:

- Typically low for long-lived process-lifetime networking stacks, but this is a strict docs-contract gap.

Recommendation:

- Keep current behavior if intentionally process-lifetime, but document rationale.
- Optionally validate `wVersion` and log explicit warning/error if mismatch.

## Implementation Parity Matrix (Reseau vs aws-c-io)

| Area | Status | Notes |
|---|---|---|
| Winsock init + extension fn loading | Covered | Same core flow (`WSAStartup` + `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)`). |
| Winsock init synchronization model | Divergent | Reseau adds lock + PID-aware reinit; aws uses simple static guard. |
| IOCP loop lifecycle | Covered | Strong parity in create/run/dispatch/schedule flow. |
| IOCP stop/finalization mechanics | Divergent | Detached foreign-thread model differs from aws thread join model. |
| IOCP handle association/unsubscribe | Covered | `CreateIoCompletionPort` + `NtSetInformationFile(FileReplaceCompletionInformation)` parity. |
| Socket API surface (init/connect/bind/listen/accept/read/write) | Covered | Broad functional parity. |
| Connect-path option handling | Divergent | `SO_REUSEADDR`/option-reapply behavior differences. |
| `on_accept_start` callback dispatch timing | Divergent | aws schedules task to loop; Reseau invokes inline. |
| Cross-thread close behavior | Divergent | aws listener-only guarded/hop behavior not mirrored. |
| IOCP pipe core flow | Covered | Same named-pipe async model. |
| Pipe unique-name collision retry | Divergent | aws retries; Reseau single UUID attempt. |
| Public `pipe_get_unique_name` equivalent | Missing | Not exposed in Reseau public API. |

## Test Parity Review (Windows core)

### Equivalent scenarios

- winsock backend init/selection (`socket_winsock_creation` equivalent coverage exists)
- local named-pipe connect/accept race
- local communication path
- outgoing local error mapping
- connect-timeout cancellation
- pipe behavior suite on Windows backend

### Partial or missing scenarios

1. **Missing:** IOCP completion callback argument parity (`aws event_loop_completion_events`)
2. **Partial:** IOCP creation contract parity (`aws event_loop_iocp_creation` equivalent not explicit)
3. **Partial:** wrong-thread read/write failure test is skipped on Windows in Reseau
4. **Partial:** Windows interface-name behavior tests are mostly bypassed/skipped in Reseau

### Direct evidence (selected)

- aws tests:
  - `tests/event_loop_test.c:284` (`event_loop_completion_events`)
  - `tests/event_loop_test.c:1041` (`event_loop_iocp_creation`)
  - `tests/socket_test.c:1694` (`wrong_thread_read_write_fails`)
  - `tests/socket_test.c:851`, `:872` (interface-name behavior)
- Reseau tests:
  - `test/event_loop_tests.jl:2171`, `:2181` (layout + rerun tests)
  - `test/socket_tests.jl:2106` (wrong-thread test skipped on Windows)
  - `test/socket_tests.jl:630` (invalid-interface test skipped on Windows)

Conclusion on test ask:

- **No**, Reseau does not yet have at least as much Windows core test parity as `aws-c-io` across key scenarios.

## `ccall` / ABI Audit

## Mostly correct mappings

The following are correctly mapped in type shape and calling usage:

- `WSAStartup(WORD, LPWSADATA)`
- `WSAIoctl(...)` for extension lookup and keepalive vals
- `ConnectEx` pointer signature
- `AcceptEx` pointer signature
- `CreateIoCompletionPort`
- `PostQueuedCompletionStatus`
- `GetQueuedCompletionStatusEx`
- `SetFileCompletionNotificationModes`
- `CancelIo`, `CancelIoEx`
- `ReadFile`, `WriteFile`, `PeekNamedPipe`, `ConnectNamedPipe`
- `WSABUF` layout (`ULONG len; CHAR* buf`)
- `OVERLAPPED_ENTRY` layout (with explicit size/offset assertions in tests)

## Struct layout checks

Good:

- `OverlappedEntry` layout checks are explicit and correct in code/tests.
- `IocpOverlappedHeader` puts `OVERLAPPED` first, matching pointer-cast assumptions.
- `GUID`, `WSADATA`, `FILE_COMPLETION_INFORMATION`, `IO_STATUS_BLOCK` fields are shape-compatible.

Potentially improve:

- `SockaddrIn.sin_family` signedness (`Cshort` vs `USHORT`/`ADDRESS_FAMILY`).

## Logic-flow checks against docs

### Compliant patterns

- ConnectEx pre-bind requirement is followed (socket bound before `ConnectEx`).
- Local named-pipe `ERROR_PIPE_CONNECTED` race handling is implemented (explicit task path).
- `CancelIo` usage in pipe unsubscribe is done on event-loop thread (matches thread-scoped semantics).

### Non-compliant/risky patterns

- AcceptEx address parsing not using documented parser helper.
- Missing `SO_UPDATE_ACCEPT_CONTEXT` update step.
- Overlapped `WSARecv(MSG_PEEK)` doc caveat.

## Recommended Action Plan (Priority Ordered)

1. **Fix AcceptEx post-processing**
   - Use `GetAcceptExSockaddrs` for endpoint parsing.
   - Apply `SO_UPDATE_ACCEPT_CONTEXT` before accepted-socket option operations.
2. **Close test parity gaps**
   - Add IOCP completion callback argument parity test.
   - Add Windows wrong-thread read/write failure test (unskip/adapt).
   - Add explicit IOCP creation parity test.
   - Add Windows interface-name behavior contract test.
3. **Decide and document intentional divergences from aws-c-io**
   - `SO_REUSEADDR` failure policy.
   - `on_accept_start` callback threading semantics.
   - cross-thread close behavior.
4. **Optional hardening**
   - Explicit winsock init in host resolver path on Windows.
   - Align `SockaddrIn.sin_family` to `Cushort`.
   - Remove/implement `detached` write-request flag.

## Notes and Limitations

- This was a static analysis; no Windows runtime execution was performed in this review.
- Some docs-risk findings are inherited from `aws-c-io`; parity and doc-compliance are not always the same objective.

## Sources (Official docs)

- ConnectEx (`LPFN_CONNECTEX`) - Microsoft Learn (updated 2024-11-20): https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_connectex
- AcceptEx - Microsoft Learn (updated 2024-11-20): https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nf-mswsock-acceptex
- GetAcceptExSockaddrs - Microsoft Learn (updated 2024-11-20): https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nf-mswsock-getacceptexsockaddrs
- WSAStartup - Microsoft Learn (updated 2025-04-09): https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsastartup
- WSAIoctl - Microsoft Learn (updated 2025-01-15): https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsaioctl
- Winsock IOCTLs (`SIO_GET_EXTENSION_FUNCTION_POINTER`, `SIO_KEEPALIVE_VALS`) - Microsoft Learn (updated 2022-11-02): https://learn.microsoft.com/en-us/windows/win32/winsock/winsock-ioctls
- GetQueuedCompletionStatusEx - Microsoft Learn (updated 2024-02-22): https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getqueuedcompletionstatusex
- OVERLAPPED_ENTRY - Microsoft Learn (updated 2024-02-22): https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-overlapped_entry
- CreateIoCompletionPort - Microsoft Learn (updated 2024-02-22): https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-createiocompletionport
- PostQueuedCompletionStatus - Microsoft Learn (updated 2024-02-22): https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-postqueuedcompletionstatus
- SetFileCompletionNotificationModes - Microsoft Learn (updated 2024-02-22): https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfilecompletionnotificationmodes
- CancelIo - Microsoft Learn (updated 2024-02-22): https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelio
- CancelIoEx - Microsoft Learn (updated 2024-02-22): https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex
- ConnectNamedPipe - Microsoft Learn (updated 2024-02-06): https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe
- WSARecv - Microsoft Learn (updated 2024-02-22): https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsarecv
- sockaddr_in - Microsoft Learn (updated 2024-02-22): https://learn.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-sockaddr_in
- SOCKADDR_IN6_LH - Microsoft Learn (updated 2024-02-22): https://learn.microsoft.com/en-us/windows/win32/api/ws2ipdef/ns-ws2ipdef-sockaddr_in6_lh
- WSABUF - Microsoft Learn (updated 2024-02-22): https://learn.microsoft.com/en-us/windows/win32/api/ws2def/ns-ws2def-wsabuf
- SOL_SOCKET options - Microsoft Learn (updated 2024-10-25): https://learn.microsoft.com/en-us/windows/win32/winsock/sol-socket-socket-options
- IPPROTO_TCP options - Microsoft Learn (updated 2024-10-25): https://learn.microsoft.com/en-us/windows/win32/winsock/ipproto-tcp-socket-options
- Using SO_REUSEADDR and SO_EXCLUSIVEADDRUSE - Microsoft Learn (updated 2022-11-02): https://learn.microsoft.com/en-us/windows/win32/winsock/using-so-reuseaddr-and-so-exclusiveaddruse
