# POSIX Socket Review: Reseau vs aws-c-io

Date: February 28, 2026  
Authoring context: deep parity + standards audit requested for Reseau POSIX socket path, using `~/aws-c-io` as behavioral reference.

## Scope and Method

This review covered:

- Reseau implementation:
  - `src/sockets/linux/posix_socket_impl.jl`
  - `src/sockets/linux/posix_socket_types.jl`
  - `src/sockets/socket/socket.jl`
- aws-c-io reference implementation:
  - `source/posix/socket.c`
  - `source/socket.c`
  - `include/aws/io/socket.h`
  - `include/aws/io/private/socket_impl.h`
- Test parity:
  - Reseau: `test/socket_tests.jl`, `test/socket_handler_tests.jl`, `test/channel_tests.jl`, `test/channel_bootstrap_tests.jl`, `test/io_testing_channel_tests.jl`, `test/sockets_compat_tests.jl`, `test/statistics_tests.jl`, `test/pipe_tests.jl`
  - aws-c-io: `tests/socket_test.c`, `tests/socket_handler_test.c`, `tests/channel_test.c`, `tests/io_testing_channel_test.c`
- Standards/docs audit:
  - POSIX Issue 8 pages that were retrievable
  - Linux man-pages 6.16 (2025-05-17) for platform-specific behavior
  - Additional local ABI size check on Darwin for type/layout portability signals

## Executive Summary

- Core logic parity with `aws-c-io` is generally strong for connect/bind/listen/accept/read/write/state transitions and error mapping.
- Reseau has several intentional improvements (task-based race hardening, event-loop handoff safety, explicit `FD_CLOEXEC` handling).
- There are meaningful API/behavior deltas and a few correctness risks:
  - two high-risk nullable-callback/default argument paths in public API wrappers;
  - portability/ABI hazards around `nfds_t` use and Unix domain path-length validation on Apple;
  - possible Linux VSOCK struct layout mismatch risk.
- Test coverage is broad and deep, but not strictly at parity with aws-c-io in socket-handler/channel regression scenarios.

## 1) Implementation Parity vs aws-c-io

### 1.1 Public API surface parity

Status summary:

- Implemented with close parity:
  - `socket_cleanup!`, `socket_bind`, `socket_listen`, `socket_stop_accept`, `socket_shutdown_dir`, `socket_set_options`, `socket_get_error`, `socket_is_open`, port validators, bound-address getter.
- Implemented with behavior differences:
  - `socket_init` (no `impl_type` override equivalent to C)
  - `socket_connect` (nullable/default API shape differs)
  - `socket_start_accept` (nullable callback default differs)
  - `socket_close` (broader cross-thread marshaling behavior)
  - `socket_assign_to_event_loop` and readable subscription (extra poll/recheck logic)
  - parse helpers (`parse_ipv4_address`, `parse_ipv6_address!`) are manual instead of `inet_pton`-based.
- Missing API parity (public helpers in aws-c-io with no Julia equivalent):
  - `aws_socket_get_event_loop`
  - `aws_socket_get_default_impl_type`

### 1.2 Data-model/lifetime parity

Expected divergences (acceptable by design):

- Julia does not mimic C field-for-field object layout (`vtable`, allocator/user-data pointer fields, refcount internals).
- Callback context is closure-based instead of explicit `void *user_data`.
- Write request queue representation differs but preserves flow intent.

Important divergence to track:

- State model encoding is not bit-identical (`TIMEDOUT/CLOSED` differences), though operational behavior mostly aligns.

## 2) High-Value Correctness Findings (Code-Level)

### High severity

1. `socket_connect` public default allows `event_loop = nothing`, but POSIX connect flow assumes a loop and can fail unexpectedly.
   - Reseau references:  
     `src/sockets/socket/socket.jl:193`, `:196`  
     `src/sockets/linux/posix_socket_impl.jl:928`, `:949`
   - C reference behavior: asserts non-null event loop before connect flow.
   - Recommendation: make `event_loop` required for POSIX path or early-throw with explicit `ERROR_INVALID_ARGUMENT`.

2. `socket_start_accept` public default allows `on_accept_result = nothing`, but accept event path expects callback presence.
   - Reseau references:  
     `src/sockets/socket/socket.jl:229`, `:232`  
     `src/sockets/linux/posix_socket_impl.jl:2272`
   - C reference behavior: explicit callback expectation/assert.
   - Recommendation: make callback required (API) or guard + deterministic no-op/error branch.

### Medium severity

3. `_update_local_endpoint!` handles `getsockname()` failure softly and callers do not always branch on failure.
   - Reseau references: `src/sockets/linux/posix_socket_impl.jl:1172`, `:1385`
   - C reference path raises/propagates failure.
   - Recommendation: propagate hard failure where endpoint correctness is required (post-connect/bind update paths).

4. Unix domain path max validation uses global `ADDRESS_MAX_LEN = 108` for non-Windows, but Darwin `sockaddr_un.sun_path` is 104 bytes.
   - Reseau references: `src/sockets/socket/socket.jl:56`, `:77`; path copy in `src/sockets/linux/posix_socket_impl.jl:872`.
   - Local Darwin ABI check:
     - `sizeof(sockaddr_un.sun_path)=104`
     - `offsetof(sun_path)=2`
     - `sizeof(struct sockaddr_un)=106`
   - Recommendation: make endpoint max-path validation platform-specific (`104` on Apple/BSD, `108` Linux where applicable), and fail-fast before copy.

5. `poll` ccall currently uses `Culong` for `nfds_t` argument.
   - Reseau reference: `src/sockets/linux/posix_socket_impl.jl:991`, `:1007`
   - Linux man-pages document `nfds_t` as an implementation-defined unsigned integer type; Darwin local check showed `sizeof(nfds_t)=4`.
   - Recommendation: use an explicit platform `nfds_t` alias (or `Base`/`Libc` type if available), not fixed `Culong`.

### Low severity

6. Manual IPv6 parser may diverge from libc `inet_pton` edge acceptance/rejection in obscure forms.
   - Reseau reference: `src/sockets/socket/socket.jl:439`
   - C reference uses `inet_pton`.
   - Recommendation: either add exhaustive conformance tests vs `inet_pton` or route parsing through libc for strict parity.

## 3) ccall and ABI Review Against POSIX/Platform Docs

### 3.1 ccall signature audit

Primary socket syscalls appear correctly typed for mainstream libc targets:

- `socket`, `connect`, `bind`, `listen`, `accept`, `getsockopt`, `getsockname`, `getpeername`, `send`, `recv`, `shutdown`, `close`, `inet_pton`, `inet_ntop`, `if_nametoindex`.
- `socklen_t`-style lengths are represented as `Cuint` in socket APIs; local Darwin check confirms 4-byte `socklen_t`.

Watchlist:

- `poll` second argument (`nfds_t`) should be a dedicated alias, not hard-coded to `Culong`.

### 3.2 Struct/layout review

- `PollFd` layout (`Cint`, `Cshort`, `Cshort`) is consistent with typical `struct pollfd`.
- `SockaddrIn` / `SockaddrIn6` / `SockaddrUn` Julia structs are not the primary path for kernel calls; most code uses byte-buffer assembly.
- `SockAddrVM` in Julia uses:
  - `svm_family::Cushort`
  - `svm_reserved1::Cushort`
  - `svm_port::UInt32`
  - `svm_cid::UInt32`
  - `svm_zero::NTuple{8, UInt8}`

Potential VSOCK mismatch:

- Linux `vsock(7)` documents `sockaddr_vm.svm_zero` as a computed pad based on `sizeof(struct sockaddr)` and field sizes; on typical Linux this may be smaller than 8.
- Recommendation: validate `sizeof(SockAddrVM)` against a C probe on Linux CI; if mismatch, adjust definition to match actual header layout.

### 3.3 Logic-flow alignment with docs

Positive alignment:

- Nonblocking connect flow tracks expected `EINPROGRESS` handling + completion via writable readiness and `SO_ERROR` confirmation.
- `SO_NOSIGPIPE` (Apple) vs `MSG_NOSIGNAL` (Linux) split is aligned with platform practice.
- Keepalive and interface-binding option flow follows expected `setsockopt` patterns.

Potentially improvable:

- Listener accept path currently does post-accept flag setup; Linux offers `accept4(..., SOCK_NONBLOCK|SOCK_CLOEXEC)` for atomicity and race reduction.

## 4) Test Coverage Parity Review

## 4.1 Where parity is strong

Reseau has strong coverage for:

- port validation;
- IPv4/IPv6 parse validation;
- core connect/bind/listen/accept/read/write across TCP/LOCAL/UDP;
- VSOCK loopback path;
- timeout + cancellation;
- key race/cleanup regressions;
- io-testing-channel behavior;
- channel task/shutdown semantics;
- statistics integration.

## 4.2 Notable aws-c-io tests without direct Reseau equivalent

Highest-value missing/partial areas:

1. Socket-handler EOF-after-peer-hangup regressions (LOCAL/IPv4/IPv6 variants).
2. Socket-handler large multi-frame payload correctness/backpressure.
3. Pinned event loop callback-affinity regressions (success + DNS-failure variants).
4. Channel refcount/hold-delayed cleanup regression.
5. Multi-host timeout/fallback integration and event-loop-group liveness regression.
6. Socket-handler close propagation/error-code expectation scenario.

## 4.3 Reseau-only added coverage (beyond scoped aws-c-io parity set)

Reseau includes additional tests not mirrored in the aws-c-io files compared:

- sockets compat suite including optional TLS echo paths;
- broad pipe behavior matrix;
- extra channel concurrency/shutdown scheduling scenarios;
- bootstrap mismatch/destroy callback wait behavior;
- implementation-selection/stub/nonblocking behavior checks.

## 5) Priority Action List

1. Fix API safety contract mismatches (`socket_connect` and `socket_start_accept` nullable defaults).
2. Fix platform ABI portability issues:
   - `nfds_t` type alias for `poll`.
   - platform-specific Unix path max validation (`sun_path` limits).
3. Add missing high-value regression tests (socket-handler EOF/multiframe/pinned loop + channel hold/liveness/multi-host fallback).
4. Harden endpoint update error propagation (`getsockname` failure paths).
5. Add Linux CI check/probe for `SockAddrVM` size parity with system headers.

## 6) Source References

### POSIX / Open Group

- Socket (Issue 8): https://pubs.opengroup.org/onlinepubs/9799919799/functions/socket.html
- Bind (Issue 8): https://pubs.opengroup.org/onlinepubs/9799919799/functions/bind.html
- Listen (Issue 8): https://pubs.opengroup.org/onlinepubs/9799919799/functions/listen.html
- Send (Issue 8): https://pubs.opengroup.org/onlinepubs/9799919799/functions/send.html
- Recv (Issue 8): https://pubs.opengroup.org/onlinepubs/9799919799/functions/recv.html
- `<sys/socket.h>` (Issue 8, 2024 edition): https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/basedefs/sys_socket.h.html

### Linux man-pages (6.16, 2025-05-17)

- connect(2): https://man7.org/linux/man-pages/man2/connect.2.html
- accept(2): https://man7.org/linux/man-pages/man2/accept.2.html
- getsockopt(2): https://man7.org/linux/man-pages/man2/getsockopt.2.html
- poll(2): https://man7.org/linux/man-pages/man2/poll.2.html
- fcntl(2): https://man7.org/linux/man-pages/man2/fcntl.2.html
- getsockname(2): https://man7.org/linux/man-pages/man2/getsockname.2.html
- getpeername(2): https://man7.org/linux/man-pages/man2/getpeername.2.html
- socket(7): https://man7.org/linux/man-pages/man7/socket.7.html
- vsock(7): https://man7.org/linux/man-pages/man7/vsock.7.html
- if_nametoindex(3p): https://man7.org/linux/man-pages/man3/if_nametoindex.3p.html

## 7) Notes and Limitations

- A subset of Open Group Issue 8 function pages intermittently returned HTTP 403 during retrieval; where that occurred, Linux man-pages and retrievable Issue 8 pages were used to cross-check call semantics.
- The VSOCK struct layout risk is flagged from docs and code inspection; it should be confirmed with a Linux-side compile-time probe.
