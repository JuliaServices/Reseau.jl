# IOCP Review: Reseau vs aws-c-io and Microsoft Docs

Date: 2026-02-28

## Scope and Method

This review covered three angles:

1. **Implementation parity** between Reseau and `~/aws-c-io` (treated as reference implementation).
2. **Test parity/coverage** for IOCP core and Windows-specific behavior.
3. **Conformance to current Microsoft IOCP/WinSock docs**, including API usage, ABI/layout, argument/return handling, and common gotchas.

Reviewed repositories/files:

- Reseau (worktree): `/Users/jacob.quinn/.julia/dev/Reseau-iocp-review`
- aws-c-io (reference): `/Users/jacob.quinn/aws-c-io`

Primary Reseau files:

- `src/eventloops/windows/iocp_event_loop.jl`
- `src/eventloops/windows/iocp_event_loop_types.jl`
- `src/sockets/windows/winsock_init.jl`
- `src/sockets/windows/winsock_socket.jl`
- `src/sockets/windows/winsock_socket_types.jl`
- `src/sockets/windows/iocp_pipe.jl`
- `test/event_loop_tests.jl`
- `test/socket_tests.jl`
- `test/pipe_tests.jl`

Primary aws-c-io reference files:

- `source/windows/iocp/iocp_event_loop.c`
- `source/windows/iocp/socket.c`
- `source/windows/iocp/pipe.c`
- `source/windows/winsock_init.c`
- `tests/event_loop_test.c`
- `tests/socket_test.c`

## Executive Summary

**Bottom line:** Reseau is close to aws-c-io parity and in some places exceeds it, but it is **not yet full parity**.

High-priority findings:

1. **Critical docs-conformance issue**: IOCP completion status in Reseau is read from `OVERLAPPED_ENTRY.Internal` (`src/eventloops/windows/iocp_event_loop.jl:424-426`), but Microsoft documents that field as reserved. Status should come from the `OVERLAPPED` structure (`Internal`), not the entry's reserved field.
2. **Functional parity gap**: pipe unique-name creation retries in aws-c-io (`PIPE_UNIQUE_NAME_MAX_TRIES`) are not implemented in Reseau (single UUID attempt).
3. **Test parity gap**: aws-c-io has a dedicated IOCP completion-argument test (`event_loop_completion_events`), but Reseau has no direct equivalent. This is likely why issue #1 was not caught.

Additional doc-driven risks:

- `AcceptEx` path does not call `SO_UPDATE_ACCEPT_CONTEXT` (same in aws-c-io), and manually parses the raw accept buffer rather than using `GetAcceptExSockaddrs`.

Areas where Reseau is stronger than aws-c-io:

- Uses `CancelIoEx` in stop-accept (`src/sockets/windows/winsock_socket.jl:1273`) where aws uses `CancelIo` (`source/windows/iocp/socket.c:2218`), reducing thread-affinity cancellation pitfalls.
- Has extra IOCP robustness tests (rerun/failed-wake latch rollback) not present in aws-c-io (`test/event_loop_tests.jl:2181`, `2226`, `2268`).

## Implementation Parity Matrix

| Area | Parity vs aws-c-io | Notes |
|---|---|---|
| IOCP event-loop lifecycle/run/stop/wake | Mostly parity | Core flow ports cleanly (`iocp_event_loop.jl` vs `iocp_event_loop.c`). |
| IOCP handle association/unassociation | Parity | `CreateIoCompletionPort`, Win7 `ERROR_INVALID_PARAMETER` handling, `NtSetInformationFile` unsubscription all mirrored (`iocp_event_loop.jl:721-744`, `282-299`). |
| Completion dispatch status extraction | **Diverges / risky** | Reseau uses `entry.Internal` (`iocp_event_loop.jl:424-426`); aws uses `overlapped->overlapped.Internal` (`iocp_event_loop.c:772-776`). Microsoft docs mark entry field reserved. |
| Winsock init and extension loading | Parity | `WSAStartup`, `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)`, ConnectEx/AcceptEx pointer acquisition aligned (`winsock_init.jl:89-151`). |
| TCP ConnectEx flow | Parity | Bind-before-connect, pending/immediate handling, timeout scheduling, completion callback handling all aligned (`winsock_socket.jl:630-716`). |
| TCP AcceptEx flow | Mostly parity | Retry on `WSAECONNRESET`, overlapped usage and loop behavior align (`winsock_socket.jl:1163-1220`, `socket.c:1856-2031`). |
| LOCAL (named-pipe) accept/connect flow | Parity | `ConnectNamedPipe` + `ERROR_PIPE_CONNECTED` handling mirrored (`winsock_socket.jl:1460-1511`, `socket.c:2247-2343`). |
| Pipe read/write/subscribe state machine | Parity | Zero-byte overlapped read monitoring model closely follows aws-c-io (`iocp_pipe.jl:198-314`, `pipe.c:415-552`). |
| Pipe unique-name collision handling | **Gap** | aws retries up to 10 attempts (`pipe.c:220-253`); Reseau attempts once (`iocp_pipe.jl:101-107`, `106-127`). |
| Accept stop cancellation | Better than parity | Reseau uses `CancelIoEx` (`winsock_socket.jl:1273`) vs aws `CancelIo` (`socket.c:2218`). |

## Test Parity Matrix

### Event loop / IOCP-specific

| aws-c-io test | Reseau equivalent | Parity |
|---|---|---|
| `event_loop_completion_events` (`tests/event_loop_test.c:284-337`) | No direct equivalent | **Gap** |
| `event_loop_iocp_creation` (`tests/event_loop_test.c:1041-1050`) | Covered by generic event-loop construction and Windows IOCP paths | Partial |
| Non-IOCP subscribe/unsubscribe family under `#else !AWS_ENABLE_IO_COMPLETION_PORTS` (`tests/event_loop_test.c:890-999`) | Present but intentionally skipped on Windows (`test/event_loop_tests.jl:294`, `406`, `483`, `549`, `628`, `732`) | Intentional divergence |

### Socket/pipe core coverage (Windows relevant)

aws-c-io coverage for socket communication/error/cleanup/race cases is broadly matched in Reseau and in some areas expanded:

- Matched examples:
  - `connect_timeout`, `connect_timeout_cancelation` → `test/socket_tests.jl:1282`, `1331`
  - `cleanup_before_connect_or_timeout_doesnt_explode` → `1381`
  - `cleanup_in_accept_doesnt_explode` → `1443`
  - `cleanup_in_write_cb_doesnt_explode` → `1525`
  - `local_socket_pipe_connected_race` → `local socket connect before accept` (`1803`)
  - UDP communication + bind/connect flows → `1885`, `1994`

- Extra in Reseau:
  - IOCP-specific wake/latch regression tests (`event_loop_tests.jl:2226`, `2268`)
  - IOCP `OVERLAPPED_ENTRY` layout assertion (`2171`)

**Coverage conclusion:** overall substantial, but **not strictly at parity for IOCP core correctness**, because the dedicated completion-argument/status test is missing.

## ABI/`ccall` and Layout Audit vs Microsoft Docs

### Verified as correct/aligned

- `CreateIoCompletionPort`: signature/usage match (`iocp_event_loop.jl:242-257`).
- `PostQueuedCompletionStatus`: signature/usage match (`iocp_event_loop.jl:225-239`).
- `GetQueuedCompletionStatusEx`: signature/usage match (`iocp_event_loop.jl:394-401`).
- `SetFileCompletionNotificationModes`: `UCHAR` flags mapped to `UInt8` (`iocp_event_loop.jl:259-267`).
- `FILE_COMPLETION_INFORMATION` and `IO_STATUS_BLOCK` pointer-size layouts are ABI-compatible (`iocp_event_loop.jl:269-277`).
- `NtSetInformationFile(..., FileReplaceCompletionInformation=0x3D)` flow matches aws-c-io (`iocp_event_loop.jl:279-299`; `iocp_event_loop.c:663-675`).
- `WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER)` for ConnectEx/AcceptEx pointer retrieval is properly typed (`winsock_init.jl:107-145`).
- `AcceptEx`, `ConnectEx`, `ConnectNamedPipe`, `ReadFile`, `WriteFile`, `WSARecv` calls all have compatible signatures and expected pending/success handling.

### Docs-sensitive or risky behaviors

1. `OVERLAPPED_ENTRY.Internal` used as operation status in dispatch path.
2. `AcceptEx` post-accept context update (`SO_UPDATE_ACCEPT_CONTEXT`) missing.
3. Accept buffer parsed manually instead of using `GetAcceptExSockaddrs` helper.
4. ConnectEx context update (`SO_UPDATE_CONNECT_CONTEXT`) occurs after endpoint update/other checks (parity with aws-c-io but doc-sensitive ordering).

## Findings (Ordered by Severity)

### 1. Critical: Completion status sourced from reserved `OVERLAPPED_ENTRY.Internal`

- Reseau: `src/eventloops/windows/iocp_event_loop.jl:424-426`
- aws-c-io reference behavior: `source/windows/iocp/iocp_event_loop.c:772-776`

Why this matters:

- Microsoft documents `OVERLAPPED_ENTRY.Internal` as reserved.
- Status for a completed operation should be read from the operation's `OVERLAPPED` (`Internal`) associated with `lpOverlapped`.
- Using a reserved field is a correctness risk across Windows versions/providers.

Recommendation:

- In completion dispatch, load status from the `Win32OVERLAPPED` embedded in the overlapped object (`op.storage[].overlapped.Internal`) and normalize from that.
- Keep `OVERLAPPED_ENTRY.Internal` unused for logic.

### 2. High: Pipe unique-name retry logic not ported

- Reseau: single attempt (`src/sockets/windows/iocp_pipe.jl:101-107`, `106-127`)
- aws-c-io: retries up to `PIPE_UNIQUE_NAME_MAX_TRIES=10` (`source/windows/iocp/pipe.c:119`, `220-253`)

Why this matters:

- Rare, but collision/retry paths are intentionally handled in aws-c-io.
- Current Reseau behavior can fail earlier than reference under contention/collision scenarios.

Recommendation:

- Port retry loop with bounded attempts and existing error propagation.

### 3. Medium: Missing direct equivalent of aws `event_loop_completion_events` test

- aws test verifies completion callback args, including status code (`tests/event_loop_test.c:284-337`)
- Reseau has no direct counterpart (only IOCP layout + wake/rerun tests: `test/event_loop_tests.jl:2171+`)

Why this matters:

- This test would likely have caught finding #1.

Recommendation:

- Add a Windows-only integration test that:
  - opens overlapped-capable pipe,
  - associates handle with IOCP loop,
  - issues overlapped write,
  - asserts callback receives expected event loop pointer, overlapped object, bytes, and **status source correctness**.

### 4. Medium: `AcceptEx` conformance gaps (context + address parsing)

- No `SO_UPDATE_ACCEPT_CONTEXT` call after successful `AcceptEx` in current flow.
- Raw accept buffer parsing used (`winsock_socket.jl:1108-1123`), not `GetAcceptExSockaddrs`.

Notes:

- This is parity-neutral (aws-c-io currently behaves similarly), but diverges from Microsoft-recommended post-accept flow.

Recommendation:

- After accept success, call `setsockopt(SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT, ...)` on accepted socket.
- Prefer `GetAcceptExSockaddrs` for robust local/remote address extraction.

### 5. Low: ConnectEx context update ordering is doc-sensitive

- Reseau performs socket checks/endpoint update before `SO_UPDATE_CONNECT_CONTEXT` (`winsock_socket.jl:492-516`), matching aws pattern.

Recommendation:

- Validate desired ordering against current Microsoft guidance and move context update earlier if needed.

## Common IOCP Gotchas Checklist (Reseau Status)

- One `OVERLAPPED` per in-flight operation: **handled**.
- Zero/reset `OVERLAPPED` before reuse: **handled** (`iocp_overlapped_reset!`).
- Handle both immediate success and `ERROR_IO_PENDING`: **handled**.
- Handle cancellation completion statuses (`ERROR_OPERATION_ABORTED`/NTSTATUS cancel): **handled** in socket/pipe flows.
- Thread-safe cancellation semantics (`CancelIo` vs `CancelIoEx`): **generally good**, with Reseau improvement in stop-accept.
- Reserved-field dependence in completion entries: **not handled** (finding #1).

## Documentation References

- IOCP overview: <https://learn.microsoft.com/en-us/windows/win32/fileio/i-o-completion-ports>
- CreateIoCompletionPort: <https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-createiocompletionport>
- GetQueuedCompletionStatusEx: <https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-getqueuedcompletionstatusex>
- PostQueuedCompletionStatus: <https://learn.microsoft.com/en-us/windows/win32/fileio/postqueuedcompletionstatus>
- OVERLAPPED: <https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-overlapped>
- OVERLAPPED_ENTRY: <https://learn.microsoft.com/en-us/windows/win32/api/minwinbase/ns-minwinbase-overlapped_entry>
- AcceptEx: <https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-acceptex>
- ConnectEx: <https://learn.microsoft.com/en-us/windows/win32/api/mswsock/nc-mswsock-lpfn_connectex>
- ConnectNamedPipe: <https://learn.microsoft.com/en-us/windows/win32/api/namedpipeapi/nf-namedpipeapi-connectnamedpipe>
- ReadFile: <https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile>
- WriteFile: <https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile>
- WSARecv: <https://learn.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsarecv>
- CancelIo: <https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelio>
- CancelIoEx: <https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-cancelioex>
- SetFileCompletionNotificationModes: <https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-setfilecompletionnotificationmodes>
- FILE_COMPLETION_INFORMATION: <https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_completion_information>

## Recommended Next Steps (Priority Order)

1. Fix completion status source in IOCP dispatch (finding #1).
2. Add dedicated Windows completion-argument parity test (finding #3).
3. Port pipe unique-name retry loop (finding #2).
4. Decide and implement `AcceptEx` conformance improvements (`SO_UPDATE_ACCEPT_CONTEXT` + `GetAcceptExSockaddrs`) and validate behavior on Windows CI.

