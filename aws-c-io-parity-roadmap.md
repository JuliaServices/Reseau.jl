# AwsIO vs aws-c-io Parity Roadmap

Goal: reach functional and behavioral parity with aws-c-io across Linux, macOS (including Apple-specific backends), and Windows. This roadmap assumes:
- Pure Julia implementation wherever possible.
- No refcounting APIs (use GC/finalizers; avoid RefCounted).
- TLS/ALPN must be fully implemented (no MbedTLS/OpenSSL). Use LibAwsCal only for crypto primitives.
- Full platform parity (epoll, kqueue, dispatch queue, IOCP; POSIX, Apple Network Framework, and Winsock/IOCP sockets; platform TLS backends as needed).
- File/URI shim headers are explicitly out-of-scope (no `file_utils`/`uri` shims).
- For each section/item, complete the implementation, ensure there are tests to cover new code, ensure tests are passing, and commit changes (code and tests).

Legend:
- [ ] Not started
- [~] In progress (fill manually when begun)
- [x] Done

---

## 0) Parity definition (checklist anchor)

### 0.1 Surface areas to match
- [ ] Core IO + error registry + logging subjects (aws-c-io/include/aws/io/io.h, logging.h)
- [ ] Event loop + event loop group (event_loop.h) for all platforms
- [ ] Sockets (socket.h) for all platforms and impl types
- [ ] Channel pipeline + handler lifecycle (channel.h)
- [ ] Socket channel handler (socket_channel_handler.h)
- [ ] Channel bootstrap (channel_bootstrap.h)
- [ ] Host resolver (host_resolver.h)
- [ ] Retry strategies (retry_strategy.h) including no-retry
- [ ] Async stream (async_stream.h)
- [x] Future (future.h) feature parity (callbacks, waiting, error/result semantics)
- [x] Stream (stream.h) feature parity (input stream vtables and constructors)
- [x] Message pool + memory pool (message_pool.h)
- [x] PEM utilities (pem.h)
- [x] Shared library (shared_library.h)
- [x] Statistics (statistics.h)
- [ ] PKCS#11 support (pkcs11.h + pkcs11_tls_op_handler.c)
- [ ] TLS channel handler (tls_channel_handler.h + tls_channel_handler_shared.c)
- [x] ALPN handler (alpn_handler.c)
- [ ] Tracing hooks (private/tracing.h)

### 0.2 Explicitly out of scope
- [ ] File/URI shim headers (file_utils.h, uri.h) NOT REQUIRED

---

## 1) Core IO, errors, logging, registry

### 1.1 IO init/cleanup
- [x] Match aws-c-io `aws_io_library_init()` and `aws_io_library_clean_up()` semantics, refcount-free
- [x] Ensure idempotent init/cleanup across modules
- [x] Confirm all error ranges and messages are registered with `aws-c-io` parity
- [x] Verify log subject list matches aws-c-io (names, ids)

### 1.2 Error code parity
- [x] Validate complete error list vs `aws/io/io.h` (including PKCS#11 and TLS errors)
- [~] Ensure error raise/translate paths are consistent with aws-c-io for socket + event loop + TLS
  - [x] Socket errno mapping parity (`s_determine_socket_error`)
  - [~] Event loop error propagation parity
    - [x] Unsubscribe without subscription reports `ERROR_IO_NOT_SUBSCRIBED`
    - [x] Syscall failure mapping parity (kevent/epoll)
  - [ ] TLS error translation parity

### 1.3 IO handle parity
- [~] Match `aws_io_handle` semantics, including platform data and set_queue hooks
  - [x] Dispatch queue `set_queue` hook behavior
  - [x] `additional_data` lifecycle on subscribe/unsubscribe
  - [ ] Network Framework + IOCP handle metadata parity

---

## 2) Event loops (platform parity)

### 2.1 Common event loop semantics
- [x] API parity for schedule/cancel/serialized scheduling semantics (order-of-execution guarantees)
- [x] Match task cancellation semantics (may execute off-thread) with aws-c-io
- [x] `event_loop_current_clock_time()` parity and clock override support
- [x] `event_loop_group_acquire_from_event_loop()` semantics
- [x] Load factor sampling + best-of-two selection parity
- [x] Event loop local objects parity (get/set/remove)
- [x] Thread ownership check `event_loop_thread_is_callers_thread()` parity
- [x] Shutdown callback user_data support (event loop group)

### 2.2 Linux: epoll
- [x] Reconcile epoll implementation with aws-c-io (edge-triggered behavior, task pre-queue)
- [x] Support `eventfd` path and pipe fallback behavior as aws-c-io
- [x] Cancellation semantics and wake-up logic parity
- [ ] Stress tests matching `tests/vcc/*` in aws-c-io

### 2.3 BSD/macOS: kqueue
- [x] Match aws-c-io kqueue event loop semantics (user events, trigger behavior, timer handling)
- [x] Validate cross-thread scheduling wakeups parity
- [x] Stress tests similar to aws-c-io vcc suite

### 2.4 macOS/iOS: dispatch queue event loop
- [x] Implement dispatch-queue event loop backend (source/darwin/dispatch_queue_event_loop.c)
- [x] Provide lifecycle + task scheduling parity
- [x] Integrate with `aws_io_handle.set_queue`
- [x] Tests covering schedule/cancel/subscribe/unsubscribe and timing

### 2.5 Windows: IOCP
- [ ] Implement IOCP event loop backend (source/windows/iocp/iocp_event_loop.c)
- [ ] Implement connect-to-IOCP and IO handle association
- [ ] Integrate socket and pipe with IOCP
- [ ] Windows event loop tests analogous to aws-c-io event_loop_test.c and vcc suite

### 2.6 Threading constraints
- [x] Document required Julia startup flags for parity behavior
- [x] Pin event-loop tasks to non-main interactive threads (sticky) to avoid main-thread blocking
- [x] Verify multi-loop scheduling guarantees with Julia tasks

---

## 3) Sockets (platform parity)

### 3.1 Socket API parity
- [ ] Implement all socket options from aws-c-io (keepalive, interface binding, connect timeout, etc.)
- [ ] Domain parity: IPv4, IPv6, LOCAL, VSOCK
- [ ] Socket impl type parity: POSIX, Winsock, Apple Network Framework, PLATFORM_DEFAULT
- [ ] All socket lifecycle methods (connect/bind/listen/accept/assign/reassign/close/cleanup)

### 3.2 POSIX sockets (Linux/BSD/macOS)
- [x] Confirm non-blocking and CLOEXEC handling parity
- [x] Implement network interface binding (SO_BINDTODEVICE / IP_BOUND_IF) where supported
- [ ] VSOCK support on Linux
- [ ] Edge-triggered behavior and read/write semantics parity

### 3.3 Apple Network Framework sockets
- [ ] Implement NW socket (source/darwin/nw_socket.c)
- [ ] Support TLS-in-socket behavior (SecItem-based TLS in NW)
- [ ] Integrate with dispatch queue event loop and io_handle.set_queue
- [ ] Lifecycle and shutdown semantics parity

### 3.4 Windows sockets
- [ ] Implement winsock init/cleanup (source/windows/winsock_init.c)
- [ ] Implement IOCP socket backend (source/windows/iocp/socket.c)
- [ ] Socket options parity and error mapping
- [ ] Accept/connect/read/write parity with IOCP

### 3.5 Pipes
- [ ] POSIX pipe parity (source/posix/pipe.c)
- [ ] Windows IOCP pipe backend (source/windows/iocp/pipe.c)

---

## 4) Channel pipeline + handlers

### 4.1 Channel core
- [x] Implement channel options parity (enable_read_back_pressure)
- [x] Implement channel holds/lifecycle semantics without refcount (GC/finalizers + explicit shutdown)
- [x] Max fragment size handling parity (`g_aws_channel_max_fragment_size` equivalent)
- [x] Window management + read back pressure parity
- [x] Cross-thread task scheduling semantics parity
- [x] Shutdown sequencing parity (left-to-right read, right-to-left write)

### 4.2 Channel task API
- [x] Implement channel task wrapper parity (`aws_channel_task_init`, task_fn signature)
- [x] Ensure task execution semantics match aws-c-io (including cancellation)

### 4.3 Socket channel handler
- [x] Validate read/write flow-control and fragmenting behavior parity
- [x] Ensure trigger_read behavior matches aws-c-io semantics
- [x] Implement statistics hooks (see Statistics section)

### 4.4 ALPN handler
- [x] Implement ALPN channel handler (source/alpn_handler.c)
- [x] Inject negotiated protocol message handling
- [x] Integrate with channel bootstrap `on_protocol_negotiated` callback
- [x] Implement error paths: missing/unknown ALPN message

---

## 5) Channel bootstrap (client + server)

### 5.1 Client bootstrap
- [ ] Implement full aws-c-io client bootstrap options (host resolution config, protocol negotiation callback)
- [x] Support requested event loop and event loop group constraints
- [x] TLS integration: add TLS handler at setup and block setup completion until negotiated
- [x] Provide creation/setup/shutdown callbacks parity

### 5.2 Server bootstrap
- [x] Listener setup callbacks (async listener for Apple Network Framework)
- [x] Accept channel setup/shutdown callbacks parity
- [x] TLS integration on accepted sockets
- [ ] Shutdown semantics parity (listener teardown + inflight channels)

---

## 6) Host resolver

### 6.1 Default resolver parity
- [ ] Implement full aws-c-io default resolver behavior (cache, TTL rules, refresh frequency)
- [ ] Connection failure tracking and load-balancing influence
- [x] Purge cache API + purge host API + callbacks
- [x] `get_host_address_count` parity

### 6.2 Custom resolver vtable
- [ ] Support custom `resolve_host` implementation callbacks
- [ ] Blocking resolution handling parity
- [ ] Threading model parity (background resolver thread)

### 6.3 Tests
- [ ] Port `default_host_resolver_test.c` scenarios
- [ ] Port mock DNS resolver tests
- [ ] Add stress tests for background refresh + TTL behavior

---

## 7) Retry strategies

### 7.1 Exponential backoff
- [x] Ensure backoff formula + jitter modes parity
- [x] Token acquire/release semantics parity
- [x] Schedule timing on event loops parity
- [x] Tests matching `exponential_backoff_retry_test.c`
- [x] Basic max-retry + client-error behavior tests

### 7.2 Standard retry (token bucket)
- [x] Capacity refill and cost semantics parity
- [x] Retry token scheduling parity
- [x] Tests matching `standard_retry_test.c`

### 7.3 No-retry strategy
- [x] Implement no-retry strategy (always denies permission)
- [x] Tests matching `no_retry_strategy_test.c`

### 7.3 No-retry strategy
- [ ] Implement `no_retry_strategy` parity (source/no_retry_strategy.c)
- [ ] Tests matching `no_retry_strategy_test.c`

---

## 8) Async streams

### 8.1 Async input stream API
- [x] Full vtable parity (read semantics, no double-read, buffer constraints)
- [x] `read_to_fill` logic parity
- [x] Ensure async completion semantics and thread behavior parity
- [x] Tests analogous to `async_stream_test.c`

---

## 9) Futures

### 9.1 Future behavior parity
- [~] Register callback (single callback only) behavior parity
- [x] Register-if-not-done semantics (avoid sync callbacks)
- [x] Event loop callback scheduling parity
- [x] Channel callback scheduling parity
- [x] Wait with timeout semantics parity

### 9.2 Result/move semantics
- [ ] Support move semantics for types with cleanup (e.g., ByteBuffer)
- [ ] Error + result handling parity for all future types

### 9.3 Tests
- [x] Port `future_test.c`

---

## 10) Streams (input stream)

### 10.1 Input stream API parity
- [ ] Vtable parity: seek, read, get_status, get_length
- [ ] Acquire/release hooks (no refcount, but API compatibility)
- [ ] Constructors: from cursor, from file, from open file
- [ ] Error and status semantics parity

### 10.2 Tests
- [ ] Port `stream_test.c`

---

## 11) Message pool + memory pool

### 11.1 Memory pool
- [x] `aws_memory_pool_*` semantics parity (acquire/release/segment sizing)
- [x] Align allocation and release behavior with aws-c-io

### 11.2 Message pool
- [x] Message pool acquire/release semantics parity
- [x] Application data vs small block pool behavior parity
- [x] Tests parity with `io_lib_test.c` and `socket_test.c` message pool scenarios

---

## 12) TLS + ALPN (full implementation)

### 12.1 TLS context/options API parity
- [ ] Implement `tls_ctx` and `tls_ctx_options` parity (min version, cipher prefs, trust store)
- [ ] Support `tls_connection_options` parity (server_name, ALPN list, callbacks, timeout)
- [ ] Support `advertise_alpn_message` semantics

### 12.2 TLS protocol support
- [ ] TLS 1.2 full handshake (client + server)
- [ ] TLS 1.3 full handshake (client + server)
- [ ] Session resumption (tickets/PSK)
- [ ] Key update and renegotiation semantics where applicable
- [ ] TLS alert handling parity (graceful vs abortive)

### 12.3 Cryptographic primitives (LibAwsCal)
- [ ] Confirm LibAwsCal exposes all required primitives
- [ ] Implement wrappers for missing primitives (ECDHE, RSA, ECDSA, X25519, AES-GCM, CHACHA20-POLY1305, HKDF)
- [ ] Implement constant-time operations for MAC/verify where required

### 12.4 X.509 and certificate validation
- [ ] Certificate parsing (DER/PEM) and chain building
- [ ] Trust store: system store + custom CA bundles
- [ ] Hostname verification (SAN/CN rules) parity
- [ ] Expiry and revocation handling parity (where aws-c-io checks)
- [ ] Error mapping to aws-c-io error codes

### 12.5 TLS channel handler integration
- [ ] Implement tls_channel_handler_shared semantics
- [ ] Channel handler state machine parity
- [ ] Ensure callbacks fire on correct thread
- [ ] Integrate ALPN handler and TLS negotiated protocol message

### 12.6 TLS backends parity (platform)
- [ ] Linux/Unix: s2n parity behavior (even if implemented in Julia)
- [ ] macOS/iOS: Secure Transport/SecItem semantics parity where required
- [ ] Windows: Schannel behavior parity

### 12.7 Tests
- [ ] Port `tls_handler_test.c` scenarios
- [ ] Port `byo_crypto_test.c`
- [ ] Port TLS server tests (use provided test certs/resources)
- [x] Add ALPN test coverage (`alpn_handler_test.c`)

---

## 13) PKCS#11

### 13.1 Core PKCS#11 API
- [ ] Implement PKCS#11 library loading + session management
- [ ] Error mapping for CKR_* to aws-c-io error codes
- [ ] Support configuration loading (module path, token label, etc.)

### 13.2 TLS private key operations
- [ ] Implement `pkcs11_tls_op_handler` parity
- [ ] Integrate with TLS handshake for mTLS

### 13.3 Tests
- [ ] Port `pkcs11_test.c`

---

## 14) PKI utilities

### 14.1 PKI utils
- [ ] Implement certificate + key loading helpers (pki_utils)
- [ ] Platform-specific helpers (darwin_pki_utils, windows_pki_utils)

### 14.2 Tests
- [ ] Add PKI-focused tests (use aws-c-io test resources)

---

## 15) Statistics

### 15.1 Stats structures
- [x] Implement socket statistics record
- [x] Implement TLS statistics record (handshake start/end, status)

### 15.2 Stats integration
- [x] `handler_reset_statistics` and `handler_gather_statistics` parity in channel handlers
- [x] Channel aggregation of handler stats

### 15.3 Tests
- [x] Port `statistics_handler_test.c`

---

## 16) Shared library

### 16.1 API parity
- [x] Ensure `shared_library_*` matches aws-c-io error behavior and Windows parity
- [x] Add tests matching `shared_library_test.c`

---

## 17) PEM utilities

### 17.1 PEM support parity
- [x] Implement full PEM type enum set and mapping
- [x] Validate parsing edge cases (CRLF, multiple objects)
- [x] Tests matching `pem_test.c`

---

## 18) Tracing

### 18.1 Tracing hooks
- [ ] Implement tracing API stubs or full integration
- [ ] Ensure no behavior regressions when tracing is enabled

---

## 19) Platform coverage summary (backend parity)

### 19.1 Linux
- [ ] epoll event loop parity
- [ ] POSIX socket parity (TCP/UDP/LOCAL/VSOCK)
- [ ] POSIX shared library parity
- [ ] Host resolver parity
- [ ] TLS parity (s2n-like behavior)

### 19.2 macOS/iOS
- [ ] kqueue event loop parity
- [ ] dispatch queue event loop parity
- [ ] Apple Network Framework socket parity
- [ ] Secure Transport TLS parity
- [ ] PKI utils parity

### 19.3 Windows
- [ ] Winsock init/cleanup parity
- [ ] IOCP event loop parity
- [ ] Winsock socket parity
- [ ] IOCP pipe parity
- [ ] Schannel TLS parity
- [ ] Windows host resolver parity

---

## 20) Test parity matrix (aws-c-io tests -> AwsIO tests)

- [ ] `event_loop_test.c` -> `test/event_loop_tests.jl` (extend)
- [ ] `socket_test.c` -> `test/socket_tests.jl` (extend)
- [x] `socket_handler_test.c` -> new `test/socket_handler_tests.jl`
- [x] `channel_test.c` -> new `test/channel_tests.jl`
- [ ] `io_testing_channel_test.c` -> new `test/io_testing_channel_tests.jl`
- [ ] `pipe_test.c` -> new `test/pipe_tests.jl`
- [x] `shared_library_test.c` -> new `test/shared_library_tests.jl`
- [x] `pem_test.c` -> new `test/pem_tests.jl`
- [ ] `future_test.c` -> new `test/future_tests.jl`
- [ ] `stream_test.c` -> new `test/stream_tests.jl`
- [ ] `async_stream_test.c` -> `test/async_stream_tests.jl` (extend)
- [ ] `exponential_backoff_retry_test.c` -> new `test/retry_strategy_tests.jl`
- [ ] `standard_retry_test.c` -> new `test/retry_strategy_tests.jl`
- [x] `no_retry_strategy_test.c` -> new `test/retry_strategy_tests.jl`
- [x] `statistics_handler_test.c` -> new `test/statistics_tests.jl`
- [x] `alpn_handler_test.c` -> new `test/alpn_tests.jl`
- [ ] `tls_handler_test.c` -> `test/tls_tests.jl` (extend)
- [ ] `byo_crypto_test.c` -> new `test/crypto_tests.jl`
- [ ] `pkcs11_test.c` -> new `test/pkcs11_tests.jl`
- [ ] vcc suite (`tests/vcc/*`) -> new stress tests (schedule, cancel, subscribe, etc.)

---

## 21) Acceptance criteria for parity

- [ ] All aws-c-io modules listed in Section 0 implemented (excluding file/uri shims)
- [ ] All platform backends implemented and covered by tests
- [ ] TLS/ALPN fully functional (TLS 1.2 + 1.3, cert validation, ALPN, mTLS, PKCS#11)
- [ ] All mapped aws-c-io tests have AwsIO equivalents with matching behavior
- [ ] Performance regressions are documented and tested (event loop throughput, socket IO)
- [ ] Documentation includes platform-specific requirements and Julia startup requirements

---

## 22) Suggested work phases (optional sequencing)

Phase 1 (Core parity)
- [ ] Event loop semantics parity (epoll/kqueue)
- [ ] Channel + socket channel handler parity
- [ ] Host resolver parity
- [ ] Retry strategies (including no-retry)
- [ ] Future + async stream + stream parity
- [ ] Message pool parity
- [ ] Tests for above

Phase 2 (TLS/ALPN + PKI)
- [ ] TLS full implementation
- [ ] ALPN handler
- [ ] PKI utilities + cert validation
- [ ] TLS/ALPN tests

Phase 3 (Platform backends)
- [ ] Dispatch queue event loop
- [ ] Apple Network Framework sockets
- [ ] Secure Transport TLS parity
- [ ] IOCP event loop + Winsock sockets + pipe
- [ ] Schannel TLS parity
- [ ] Platform tests

Phase 4 (PKCS#11 + stats + tracing)
- [ ] PKCS#11 support
- [ ] Statistics subsystem
- [ ] Tracing hooks
- [ ] Tests
