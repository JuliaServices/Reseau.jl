# Codex Review: Reseau.jl

Date: 2026-02-08  
Repo: `/Users/jacob.quinn/.julia/dev/Reseau`  
Branch: `sockets-files-parity`  
Commit: `ab376bedf526a2fce2bb4671c63f21246dd7d3ab` (`ab376be`)

Reference implementations consulted (local checkouts):
- `~/aws-c-common`
- `~/aws-c-io`
- `~/julia` (Base + stdlib, especially `Sockets` and `Base.Filesystem`)

## Scope And Method

I reviewed:
- `src/` (all files, including `src/common/unused/*` even though they are not currently included)
- `ext/` (extensions)
- `test/` (behavior/spec + coverage signals)
- `README.md`, `PORTING_PATTERNS.md`, and other top-level docs as they relate to user-facing APIs

Review dimensions:
- Correctness (logic, state machines, edge cases, error handling)
- Robustness (thread-safety, shutdown/cancellation, invariants)
- Security (memory safety, TLS/PKI behavior, temp-path safety, dynamic library loading)
- Performance (Julia type stability, dynamic dispatch, allocations, O(n) queues in hot paths)
- Ergonomics (API shape, exports, Julia-idiomatic convenience)

Notes:
- This review was performed on macOS (Apple Network.framework socket backend is relevant).
- Windows-specific paths (Winsock + IOCP) were reviewed statically only.

## Test Matrix (Executed Locally)

All tests were run from the repo root.

1. Default tests (no TLS/network): PASS
```sh
cd "$(git rev-parse --show-toplevel)"
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```

2. Network-enabled tests: PASS
```sh
cd "$(git rev-parse --show-toplevel)"
RESEAU_RUN_NETWORK_TESTS=1 JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```

3. TLS-enabled tests: FAIL (macOS, at time of review; fixed)
```sh
cd "$(git rev-parse --show-toplevel)"
RESEAU_RUN_TLS_TESTS=1 JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```
Failure details:
- `test/tls_tests_impl.jl:1860-1889` expects a non-zero port immediately after constructing `ServerBootstrap(... port=0 ...)`.
- Under the Apple Network.framework backend (`src/io/apple_nw_socket_impl.jl`), a listener bound to port 0 can report port 0 until the listener reaches READY; Reseau explicitly polls for a non-zero port and delays `on_accept_started` in `_nw_listener_poll_port_until_ready!`.
- Result: `socket_get_bound_address(listener)` can legitimately return port 0 until the accept-start callback has fired, causing the TLS test to fail.

Evidence:
- Test assumes immediate port availability: `test/tls_tests_impl.jl:1884-1889`.
- Reseau delays readiness/port publication: `src/io/apple_nw_socket_impl.jl:1337-1449`.
- Reseau tries an early read but does not guarantee it: `src/io/apple_nw_socket_impl.jl:1861-1867`.

Recommendation:
- Fix the TLS test (and/or document low-level bootstrap semantics) to wait for `on_listener_setup` before reading `socket_get_bound_address()` when using NWSocket.
- Alternatively/additionally: provide a synchronous "listener ready" helper for bootstrap that waits/polls until the effective bound port is known.

Status: ADDRESSED (TLS tests now wait for `on_listener_setup` before reading the bound port when using Apple Network.framework).

### Test Coverage Caveat: `Threads.nthreads(:interactive)` Skips

Many tests are gated behind `Threads.nthreads(:interactive) > 1` (and some require `> 2`). With `JULIA_NUM_THREADS=1`, large portions of concurrency coverage are skipped. This is intentional for determinism, but it means race-y code paths may not be exercised by the recommended "single-thread" test command.

## CI Coverage Notes

GitHub Actions currently runs only the default test suite (no TLS, no network) via `julia-actions/julia-runtest` (`.github/workflows/ci.yml`). This means:
- The macOS TLS failure described above is not caught by CI.
- Network-dependent resolver behaviors are not covered by CI.

If TLS/network coverage is desired in CI, consider adding at least one job or a scheduled workflow that sets:
- `RESEAU_RUN_TLS_TESTS=1`
- `RESEAU_RUN_NETWORK_TESTS=1`

## Test Hygiene Notes

- Tests print some `FATAL_ASSERT:` messages intentionally while validating error paths (observed during the network-enabled run). They are noisy but not failures.
- Multiple test files re-`include(...)` helpers, which can produce \"Method definition ... overwritten\" warnings. This is noisy but not a functional problem; consider reorganizing test helpers to avoid repeated includes.
- Tests leave behind `testsock*.sock` unix sockets in the repo root on macOS. Consider deleting them in `test/test_utils.jl` or an `atexit` hook.

## Executive Summary

Reseau is an ambitious "aws-c-io shaped" IO stack in pure Julia: custom event loops, socket backends (POSIX, Apple Network.framework, Winsock), a channel pipeline, TLS (SecureTransport on Apple, s2n on Linux), host resolver, retry strategies, futures, and a libuv-free `Reseau.Sockets` and `Reseau.Files` surface.

The strongest parts:
- The subsystem decomposition mirrors aws-c-common/aws-c-io closely, which makes parity review feasible.
- Tests cover a wide surface area (event loops, sockets, channels, resolver, files, crypto primitives), and network tests passed.
- The Apple Network.framework integration explicitly handles an important real-world edge case (port 0 temporarily reporting as 0).

The biggest correctness/robustness risks:
- Several "ported" helpers are currently broken at runtime due to incorrect `MemoryRef{UInt8}` usage (`date_time.jl`, `uuid.jl`).
- There is a critical memory-safety issue: `byte_buf_from_c_str(::AbstractString)` returns a *mutable* `ByteBuffer` view into immutable `String` storage, which is undefined behavior in Julia.
- Multiple thread-safety hazards exist because invariants are enforced only by `debug_assert()` (disabled by default), and global registries (`SmallRegistry`, `_BUFFER_VIEW_REGISTRY`) are mutated without synchronization.

Overall: the architectural direction is sound and tests are substantial, but there are several P0 issues that will bite downstream users as soon as the affected functions are used in production or under multi-threaded load.

## High-Priority Findings (P0)

### P0.1 `date_time` parsing is broken (invalid `MemoryRef{UInt8}` access)

Status: ADDRESSED (fixed `MemoryRef` indexing; added date parsing tests in `test/common_tests.jl`).

Impact:
- Any call path that uses RFC 822 / ISO 8601 parsing helpers can throw `MethodError` or misbehave.
- This is "dead" until used, but it is a correctness cliff.

Evidence:
- `src/common/date_time.jl:219-222`:
  - `ptr = unsafe_load(date_str_cursor).ptr` where `ptr::MemoryRef{UInt8}`.
  - `unsafe_load(ptr + index)` will throw `MethodError` (Base `unsafe_load` is defined for `Ptr`, not `MemoryRef`).
- `src/common/date_time.jl:341-357`:
  - `_read_n_digits()` uses `unsafe_load(str[].ptr + i)` where `str[].ptr::MemoryRef{UInt8}`.
- `src/common/date_time.jl:363-392`:
  - Uses `str[].ptr[1]` and `str[].ptr[i]`, but `MemoryRef` does not support `getindex(::MemoryRef, ::Int)`; the idiom is `ref[]` for the current element and `memoryref(ref, i)[]` for offsets.

Suggested fix:
- Replace the incorrect `unsafe_load(...)`/`ptr[...]` uses with `MemoryRef`-compatible access:
  - Example pattern used elsewhere: `memoryref(to_encode.ptr, i)[]` in `src/common/encoding.jl:69-75`.
  - Concretely:
    - `unsafe_load(ptr + index)` with `index` in `0:(len-1)` -> `memoryref(ptr, index + 1)[]`
    - `str[].ptr[1]` -> `str[].ptr[]`
    - `str[].ptr[i]` -> `memoryref(str[].ptr, i)[]`

Test gap:
- No tests cover date parsing (`rg date_time test/` finds none).

### P0.2 `uuid_init_from_str()` is broken (invalid `MemoryRef` arithmetic + wrong hex decode call)

Status: ADDRESSED (fixed `MemoryRef` indexing, corrected hex decode usage, and added `uuid_init_from_str` tests in `test/common_tests.jl`).

Impact:
- `uuid_init_from_str()` cannot work as written.

Evidence:
- `src/common/uuid.jl:44-83`:
  - `unsafe_load(str_val.ptr + pos)` where `str_val.ptr::MemoryRef{UInt8}`.
  - Calls `_hex_decode_char_to_int(hex_digits[...], high_val)` but `_hex_decode_char_to_int` returns a `(status, value)` tuple and takes 1 argument (`src/common/encoding.jl:80-91`).

Suggested fix:
- Use `memoryref(str_val.ptr, pos + 1)[]` instead of pointer arithmetic.
- Decode via `status, v = _hex_decode_char_to_int(ch)`.

Test gap:
- UUID tests exist (`test/common_tests.jl` reports UUID pass), but they do not cover `uuid_init_from_str()`.

### P0.3 `get_temp_directory()` and `get_home_directory()` can throw unexpectedly

Status: ADDRESSED (removed `something(...)` throw hazards, fixed Windows fallback string literal, and added env-fallback tests in `test/common_tests.jl`).

Impact:
- Instead of returning a fallback directory (or raising a controlled Reseau error), these functions can throw `ArgumentError("No value arguments present")` when environment variables are unset.

Evidence:
- `src/common/file.jl:176-193` uses `something(...)` on Windows without a non-`nothing` fallback.
- `src/common/file.jl:194-209` uses `something(..., nothing)` (still throws if all values are `nothing`).

Also:
- Windows fallback string is double-escaped: `"C:\\\\Windows\\\\Temp"` (`src/common/file.jl:201`).

Suggested fix:
- Use `get(ENV, ..., default)` or explicit `if` chains instead of `something(..., nothing)`.
- Ensure Windows temp fallback string literal is `"C:\\Windows\\Temp"`.

### P0.4 Undefined behavior: `byte_buf_from_c_str(::AbstractString)` returns a mutable view into `String` storage

Status: ADDRESSED (now copies into owned `Memory{UInt8}` to avoid mutable views into immutable `String` storage).

Impact:
- Julia `String` storage is immutable. Returning a mutable `Memory{UInt8}` view that can be written through is undefined behavior and can corrupt memory or crash.
- Even if most call-sites treat it read-only, the type is `ByteBuffer` (mutable-by-design), so the API is unsafe.

Evidence:
- `src/common/byte_buf.jl:500-508`:
  - `mem = unsafe_wrap(Memory{UInt8}, pointer(c_str), len; own = false)`
  - `return ByteBuffer(mem, Csize_t(len))`

Suggested fix options:
1. Make `byte_buf_from_c_str(::AbstractString)` copy into owned `Memory{UInt8}` (safe, slightly more allocations).
2. Remove/rename it to `byte_cursor_from_c_str(::AbstractString)` and return `ByteCursor` for string-backed views.
3. If you keep a buffer view, enforce read-only by API (hard in Julia) or by storing an internal marker and preventing mutating ops.

## Robustness And Concurrency Findings (P1)

### P1.1 "Thread-local" error state is not thread-safe and not truly thread-local

Status: ADDRESSED (replaced `SmallRegistry` globals with lock-protected `Dict`s in `src/common/error.jl`, fixed `thread_current_thread_id()` to return unique ids for non-Reseau threads in `src/threads/thread.jl`, and added a Julia-thread isolation test in `test/common_tests.jl`).

Impact:
- `last_error()` and per-thread error handlers can be corrupted or behave incorrectly under concurrency.
- Errors from different threads can overwrite each other.

Evidence:
- Global registries keyed by `thread_current_thread_id()`:
  - `src/common/error.jl:99-187` uses `SmallRegistry{UInt64,Int}` and `SmallRegistry{UInt64,Function}`.
- Registry implementation is not synchronized:
  - `src/common/registry.jl:1-82` performs resizes and swaps buffers without locks/atomics.
- Thread IDs collapse for non-Reseau-managed threads:
  - `src/common/thread.jl:152-161` returns a single `_main_thread_id[]` for any thread without a TLS handle.

Upstream comparison:
- aws-c-common uses true TLS storage for `aws_last_error()`; no global mutable registry is required.

Suggested fix:
- Use `Threads.threadid()` (or a fixed thread-index mapping) and store per-thread state in a pre-sized `Vector{T}`.
- If you must use a map, use `Dict` guarded by a lock (or `ReentrantLock`) and ensure thread IDs are unique.
- Prefer `ScopedValues.jl` for per-task/per-thread context if that is the intended model.

### P1.2 Thread-affinity is enforced only via `debug_assert()` (disabled by default)

Status: ADDRESSED (enforced thread-affinity in release builds for event-loop unsubscribe and scheduled `socket_close` onto the correct event loop when called off-thread).

Impact:
- Many operations that must run on the event-loop thread (unsubscribe, cancellation, handler teardown) can be called from the wrong thread in release builds.
- This creates real risk of UAF-like patterns via `unsafe_pointer_to_objref` if `additional_ref` is cleared while the event-loop thread is still processing events.

Evidence:
- `debug_assert()` is conditional on `DEBUG_BUILD[]`, which defaults to `false` (`src/common/assert.jl:23-28`, `src/Reseau.jl:7-8`).
- `event_loop_unsubscribe_from_io_events!` uses only `debug_assert`:
  - epoll: `src/io/epoll_event_loop.jl:377-419`
  - kqueue: `src/io/kqueue_event_loop.jl:551-598`

User-facing trigger:
- `Reseau.Sockets.TCPSocket.close` calls `socket_close(io.socket)` directly (`src/sockets/tcp.jl:722-731`).
- POSIX socket close unsubscribes immediately via `event_loop_unsubscribe_from_io_events!` if subscribed (`src/io/posix_socket_impl.jl:1217-1230`).

Upstream comparison:
- aws-c-io blocks or errors when closing from the wrong thread (listener-only allowed): `~/aws-c-io/source/posix/socket.c:1554-1602`.

Suggested fix:
- Enforce thread-affinity even in release builds for unsafe operations.
  - Either return `ErrorResult(ERROR_IO_EVENT_LOOP_THREAD_ONLY)`.
  - Or schedule the operation onto the event loop (and optionally block/wait for completion for synchronous APIs like `close`).

### P1.3 Non-atomic "once" initialization patterns (data races)

Status: ADDRESSED (removed racy double-checked init patterns; now always checks inside the lock).

Impact:
- Benign on x86 most of the time, but technically racy and can fail on weak memory models.

Evidence:
- Device random init check reads `_device_random_initialized[]` outside the lock:
  - `src/common/device_random.jl:43-55`.
- TLS CAL init does the same:
  - `src/io/tls_channel_handler.jl:509-518`.

Upstream comparison:
- aws-c-common uses `aws_thread_call_once()` for device random init.

Suggested fix:
- Use an atomic flag with acquire/release semantics, or a `Once`-like primitive.

### P1.4 `AsyncInputStream` read-in-progress gate is not atomic (TOCTOU)

Status: ADDRESSED (made the gate a CAS using `@atomicreplace`).

Impact:
- Two concurrent callers can pass `if @atomic stream.read_in_progress` and both set it true.

Evidence:
- `src/io/async_stream.jl:39-44`.

Suggested fix:
- Use `@atomicreplace` (CAS) or a lock.

### P1.5 Global counters and registries are not concurrency-safe

Status: ADDRESSED (made channel id counter atomic; added locking around `_BUFFER_VIEW_REGISTRY` and the static string cache).

Evidence:
- `_channel_id_counter::Ref{UInt64}` increments without atomics (`src/io/channel.jl:253-259`).
- `_BUFFER_VIEW_REGISTRY::WeakKeyDict` is mutated without a lock (`src/common/byte_buf.jl:37-38`, multiple constructors). `WeakKeyDict` is not safe for concurrent mutation.
- `_static_string_cache::SmallRegistry` is mutated without a lock (`src/common/string.jl:6`, `src/common/string.jl:245-260`).

Suggested fix:
- Either document single-thread assumptions clearly, or add locking/atomics.

## Correctness And Parity Divergences (P2)

### P2.1 Task scheduler fairness differs from aws-c-common

Status: ADDRESSED (implemented the upstream "swap into running list" semantics; added tests).

Impact:
- In aws-c-common, tasks scheduled during a `run_all` tick are not executed until the next tick.
- In Reseau, tasks scheduled while draining `scheduler.asap` can run in the same tick, increasing risk of starvation or unbounded work per tick.

Evidence:
- Reseau drains `asap` directly until empty: `src/common/task_scheduler.jl:118-124`.
- aws-c-common explicitly swaps `asap_list` into a separate `running_list` before executing: `~/aws-c-common/source/task_scheduler.c:193-201`.

Suggested fix:
- Implement the upstream swap behavior (e.g., keep `asap` and `running` vectors and swap references before draining).

### P2.2 kqueue default kevent timeout is much smaller than aws-c-io

Status: ADDRESSED (now matches aws-c-io: `DEFAULT_TIMEOUT_SEC = 100`).

Impact:
- Potentially higher wakeup rate and CPU usage on idle event loops.

Evidence:
- Reseau: `src/io/kqueue_event_loop_types.jl` sets `DEFAULT_TIMEOUT_SEC = 100`.
- aws-c-io: `~/aws-c-io/source/bsd/kqueue_event_loop.c:126-129` sets `DEFAULT_TIMEOUT_SEC = 100`.

Suggested fix:
- Consider matching upstream (100s) and rely on cross-thread wakeups for responsiveness.
- If keeping 1s for forward progress, document the rationale and measure idle CPU.

### P2.3 `Reseau.Files` deviates from Base semantics in multiple places

Status: DEFERRED (Files-related; pending separate PR/branch).

Evidence:
- `Reseau.Files.readlink()` POSIX implementation can return truncated results:
  - It only retries on `ERANGE/ENAMETOOLONG`, but `readlink(2)` truncates silently when the buffer is too small.
  - `src/files/fsops.jl:572-590`.
- `Reseau.Files.cp(...; preserve=true)` ignores `preserve`:
  - `_ = preserve` and no preservation logic.
  - `src/files/fsops.jl:988-1010`.
- `Reseau.Files.tempname()` is predictable and does not check for collisions:
  - Uses `time_ns()` + counter (`src/files/fsops.jl:233-240`).
  - Base uses randomness and checks for path existence: `~/julia/base/file.jl:736-820`.
- `FileHandle.readbytes!(::AbstractVector{UInt8})` assumes contiguous storage:
  - Uses `pointer(b)` with no `Base.iscontiguous` check, unsafe for strided `SubArray`.
  - `src/files/filehandle.jl:120-145`.

Suggested fixes:
- For `readlink()`: retry if `rc == length(buf)`.
- For `cp(preserve=true)`: implement mode/mtime/uid/gid preservation (platform-specific) or remove the keyword.
- For `tempname()`: use randomness + collision check, and document that `tempname()` alone is not safe for creating files.
- For `readbytes!`: restrict to contiguous vectors or copy into a contiguous temp buffer.

### P2.4 Apple Network.framework semantics: listener readiness is async

Status: ADDRESSED (fixed TLS tests to wait for `on_listener_setup` before reading `socket_get_bound_address(listener)` when binding port 0 on Apple Network.framework; added test socket cleanup).

Impact:
- Code that assumes synchronous listen/bind readiness (especially port 0 assignment) will be flaky.

Evidence:
- Port polling and delayed `on_accept_started`: `src/io/apple_nw_socket_impl.jl:1337-1449`.
- TLS test assumption fails: `test/tls_tests_impl.jl:1884-1889`.

Suggested fix:
- Document that `ServerBootstrap(...)` is async on Apple Network.framework and that callers must use `on_listener_setup`.

### P2.5 Host resolver default DNS result ordering differs from aws-c-io

Status: ADDRESSED (default DNS resolution now preserves `getaddrinfo()` ordering for parity with aws-c-io).

Impact:
- Code that assumes the OS `getaddrinfo()` ordering (or aws-c-io's ordering) may observe different address ordering from Reseau.
- This can affect connection attempt ordering (IPv6 vs IPv4 preference) and load balancing behavior.

Evidence:
- Reseau interleaves IPv6/IPv4 results when `max_addresses > 0` to keep both families represented, and otherwise appends IPv6 then IPv4 (`src/io/host_resolver.jl:403-438`).
- aws-c-io's `aws_default_dns_resolve()` pushes results in the order returned by `getaddrinfo()` (`~/aws-c-io/source/posix/host_resolver.c:20-90`).

Recommendation:
- Decide whether this divergence is intentional.
  - If intentional, document it as a stability improvement and ensure tests cover the ordering contract.
  - If parity is the goal, preserve `getaddrinfo()` order and enforce max-address limits at a higher layer.

## Security Review

### Memory Safety

- P0: `byte_buf_from_c_str(::AbstractString)` returns a mutable buffer view into immutable string storage (`src/common/byte_buf.jl:500-508`). This is undefined behavior in Julia.
- Any code that uses `unsafe_pointer_to_objref()` must ensure the object is kept alive (usually via `additional_ref`) and that lifecycle transitions are thread-safe. With thread-affinity enforced only by `debug_assert`, there are real UAF-style risks (see P1.2).

### Temp Path Safety

- `Reseau.Files.tempname()` is predictable (`src/files/fsops.jl:233-240`). `mktemp()` is safe because it uses `O_EXCL` (`src/files/fsops.jl:242-257`), but `tempname()` alone is guessable and should not be used for security-sensitive paths.

Status: DEFERRED (Files-related; pending separate PR/branch).

### TLS/PKI Defaults And Footguns

- `tls_context_new_client()` defaults `verify_peer=true` (`src/io/tls_channel_handler.jl:1336-1357`). This is good.
- However, `TlsConnectionOptions.server_name` is optional (`src/io/tls_channel_handler.jl:1381-1415`). Many TLS stacks require a server name for full hostname verification (and for SNI). Ensure high-level APIs set it by default when connecting by hostname.
- SecureTransport logs a clear warning when verification is disabled (`src/io/tls/secure_transport_tls_handler.jl:1112-1119`). Good.

Status: ADDRESSED (high-level `Reseau.Sockets` APIs default `server_name` to the hostname when `tls=true`; low-level APIs remain explicit).

### Dynamic Library Loading

- `shared_library_load(path)` uses `dlopen`/`LoadLibraryW` without constraining search paths (`src/io/shared_library.jl:30-83`). If callers pass relative paths or untrusted paths on Windows, this can enable DLL hijacking.
- The `ReseauS2NExt` extension registers the s2n handle from the JLL (`ext/ReseauS2NExt.jl:6-26`), which is the safer pattern.

Status: ADDRESSED (documented the footgun at the `shared_library_load` call-site).

### Secure Erase

- `byte_buf_clean_up_secure()` and friends should be treated as best-effort; Julia and/or underlying libc/compiler behavior can undermine "guaranteed" zeroization. The implementation should be documented accordingly.

Status: ADDRESSED (added explicit best-effort documentation to `secure_zero`).

## Performance Review (Julia Type Stability And Hot Paths)

### Quick Metrics

From grep counts under `src/`:
- `Base.invokelatest`: 71 occurrences
- Explicit `::Any` annotations: 90 occurrences
- `Function` occurrences: 136
- `@atomic`: 145

These are not intrinsically bad, but several of them sit on high-frequency paths (event dispatch, task scheduling, socket IO callbacks).

### Hot-Path Dynamic Dispatch

Key sources:
- Task scheduler: `TaskFn(f::Any, ctx::Any)` + `invokelatest` per task (`src/common/task_scheduler.jl:13-19`).
- Event loops: IO callbacks are invoked via `invokelatest` in epoll/kqueue paths (e.g., `src/io/epoll_event_loop.jl` event dispatch).
- `EventLoop.clock::Function` is called multiple times per loop tick (`src/io/event_loop.jl:72,142-224`).

Recommendations:
- Restrict `invokelatest` usage to truly user-provided callbacks where world-age is required.
- In internal callbacks, prefer concrete callable structs and parametric storage (per `PORTING_PATTERNS.md`).
- Make `EventLoop` parametric over the clock function type, or store a small set of known clocks.

Status: DEFERRED (requires deeper performance refactor; `invokelatest` is currently relied on for correctness on adopted OS threads).

### O(n) Queues

- `TaskScheduler.asap` uses `popfirst!` (O(n)) (`src/common/task_scheduler.jl:118-124`).
- Many other queues (`written_queue`, backend threadpool queue, etc.) also use `popfirst!`.

Recommendation:
- Replace with a ring buffer/deque structure for amortized O(1) push/pop.

Status: PARTIALLY ADDRESSED (TaskScheduler fairness was fixed and no longer drains via `popfirst!`; broader queue refactors deferred).

### Logging Overhead

- Many hot paths call `logf(...)` with computed arguments. Even if logs are filtered, the arguments are still evaluated.
- The repo already has logging macros (`@LOGF_*` in `src/common/logging.jl`) that can avoid that cost.

Recommendation:
- Use macros in hot paths (event loop ticks, per-packet socket callbacks, per-message channel flow).

Status: DEFERRED (no functional bugs; can be tackled as a perf-only follow-up).

## User-Facing API Ergonomics

### Exports And Module Surfaces

- `Reseau` top-level exports essentially nothing from the IO/core layer; user-facing exports are under submodules:
  - `Reseau.EventLoops` exports event loop group APIs (`src/EventLoops.jl`).
  - `Reseau.Sockets` exports a stdlib-like sockets surface (`src/Sockets.jl` + `src/sockets/*`).
  - `Reseau.Files` exports filesystem APIs (`src/Files.jl` + `src/files/*`).
  - `Reseau.Threads` exports thread/runtime utilities (`src/Threads.jl`).

Documentation mismatch:
- `README.md` examples use unqualified identifiers like `EventLoopGroup(...)` and `DefaultHostResolver(elg)` which are not defined/exported at top-level.
  - `DefaultHostResolver` does not exist (`rg DefaultHostResolver src` returns none).
  - The threading requirements described in the README do not match the implementation (no such checks exist in `src/io/event_loop.jl`).

Recommendation:
- Either update README examples to use `using Reseau.EventLoops` / `using Reseau` with qualified names, or re-export a curated surface from `Reseau`.

Status: ADDRESSED (README examples now use `Reseau.*`-qualified names; removed incorrect threading requirements section).

### Indexing Footguns

- `event_loop_group_get_loop_at(elg, index)` uses 0-based indexing (`src/io/event_loop.jl:371-377`).

Recommendation:
- Provide a 1-based convenience wrapper (or rename the 0-based method to make it obvious).

Status: ADDRESSED (added `Base.getindex` + `Base.length` for `EventLoopGroup`, with tests).

## File-By-File Notes

This section is intentionally exhaustive (every `src/` + `ext/` + `test/` file). For large files, notes focus on the most important invariants and any discrepancies found.

### Top-Level

- `src/Reseau.jl`
  - Includes all common + io code, then public submodules.
  - `__init__()` initializes the OS-thread entrypoint and calls `io_library_init()`.
  - Note: `DEBUG_BUILD` defaults false (disables `debug_assert`). Consider documenting how to enable debug assertions.

Status: ADDRESSED (documented `Reseau.DEBUG_BUILD[]` in README).

- `src/EventLoops.jl`
  - Thin re-export wrapper for event loop APIs.
  - Exposes 0-based `event_loop_group_get_loop_at` without a Julia-idiomatic alternative.

- `src/sockets/sockets.jl`
  - Declares the `Reseau.Sockets` module and includes the underlying IO implementation plus `ipaddr`, `dns`, and `tcp` surfaces.

- `src/Files.jl`
  - Declares the `Reseau.Files` module and includes `src/files/files.jl`.
  - Status: DEFERRED (Files surface is pending separate PR/branch).

- `src/threads/threads.jl`
  - Declares `Reseau.Threads` and re-exports `Base.Threads` bindings plus Reseau thread utilities.
  - This is a pragmatic workaround for internal `Threads.X` references, but it is unusual; document it prominently.

Status: ADDRESSED (documented the `Reseau.Threads` vs `Base.Threads` naming in README).

### `src/common/*`

- `src/common/platform.jl`
  - Platform flags and low-level constants. No major issues noted.

- `src/common/macros.jl`
  - Helper macros. No major issues noted.

- `src/common/registry.jl`
  - `SmallRegistry` and `SmallList` implementations.
  - Not thread-safe; this matters for any global state built atop it (see `error.jl`, `string.jl`, `logging.jl`).

- `src/common/assert.jl`
  - `debug_assert()` gated by `DEBUG_BUILD[]`. In release builds, thread-affinity checks become no-ops.

- `src/common/error.jl`
  - Error registry + `last_error()` implementation.
  - Uses `SmallRegistry` keyed by `thread_current_thread_id()`; not thread-safe and not truly thread-local on Julia threads (P1.1).

- `src/common/shutdown_types.jl`
  - Shutdown callback option structs. No major issues noted.

- `src/common/logging_types.jl`
  - Log level/subjects types. No major issues noted.

- `src/common/log_writer.jl`
  - Log writer interface. No major issues noted.

- `src/common/log_channel.jl`
  - Log channel interface. No major issues noted.

- `src/common/log_formatter.jl`
  - Log formatting helpers. No major issues noted.

- `src/common/logging.jl`
  - Logger pipeline and subject registry.
  - Uses `SmallRegistry` for subject registry; likely fine at init-time but not safe if mutated concurrently.
  - Performance: prefer macros for hot-path logging.

- `src/common/math.jl`
  - Integer math helpers (checked add/mul, saturating ops). No major issues noted.

- `src/common/zero.jl`
  - Best-effort secure zero. Document limitations.

- `src/common/priority_queue.jl`
  - `PriorityQueue` on `Memory{T}`. Looks correct; used by task scheduler.

- `src/common/byte_buf.jl`
  - ByteBuffer/ByteCursor core.
  - P0: `byte_buf_from_c_str(::AbstractString)` unsafe (mutable buffer view into immutable String).
  - Robustness: `_BUFFER_VIEW_REGISTRY::WeakKeyDict` is globally mutated without a lock.

- `src/common/file.jl`
  - File utilities; `get_home_directory()` and `get_temp_directory()` have `something(..., nothing)` throw hazards (P0.3).

- `src/common/string.jl`
  - `ByteString` type and string utilities.
  - `_static_string_cache::SmallRegistry` is not concurrency-safe.

- `src/common/cache.jl`
  - Cache interfaces. No major issues noted.

- `src/common/lru_cache.jl`
  - LRU cache implementation. Tests cover host resolver caching; no major issues observed.

- `src/common/clock.jl`
  - Clock and timestamp conversions. No major issues noted.

- `src/common/time.jl`
  - Time helpers. No major issues noted.

- `src/common/date_time.jl`
  - P0: date parsing has incorrect `MemoryRef` arithmetic (P0.1).
  - Also includes Ptr-based helpers that appear correct.

- `src/common/statistics.jl`
  - Basic statistics container. No major issues noted.

- `src/common/device_random.jl`
  - Device RNG implementation.
  - P1: initialization uses racy double-checked pattern (P1.3).

- `src/common/encoding.jl`
  - Hex/base64 encoding helpers.
  - `_hex_decode_char_to_int` signature is tuple-returning; uuid parsing code is not updated accordingly (P0.2).

- `src/common/system_info.jl`
  - CPU group helpers. No major issues noted.

- `src/common/uuid.jl`
  - UUID generation + string formatting.
  - P0: `uuid_init_from_str` broken (P0.2).

- `src/common/condition_variable.jl`
  - Condition variable wrapper. No major issues noted.

- `src/common/thread.jl`
  - OS thread launch/join, TLS handle management.
  - Thread-id behavior for non-adopted threads collapses to a single `_main_thread_id` (P1.1).

- `src/common/thread_shared.jl`
  - Managed-thread join tracking. Appears sound; uses locks.

- `src/common/task_scheduler.jl`
  - Task scheduler.
  - Performance: `TaskFn` uses `Any` and `invokelatest` per task.
  - Parity: fairness semantics differ from aws-c-common (P2.1).

- `src/common/common.jl`
  - Registers common errors and log subjects. No major issues noted.

### `src/common/unused/*` (Not Included Today)

These files are present but are not included from `src/Reseau.jl` and therefore are not part of the built package today. Treat them as dead code: they can rot silently and become dangerous if re-enabled without tests.

- `src/common/unused/array_list.jl`
- `src/common/unused/byte_order.jl`
- `src/common/unused/cbor.jl`
- `src/common/unused/command_line_parser.jl`
- `src/common/unused/cpuid.jl`
- `src/common/unused/cross_process_lock.jl`
- `src/common/unused/environment.jl`
- `src/common/unused/fifo_cache.jl`
- `src/common/unused/hash_table.jl`
- `src/common/unused/host_utils.jl`
- `src/common/unused/json.jl`
- `src/common/unused/lifo_cache.jl`
- `src/common/unused/linked_hash_table.jl`
- `src/common/unused/linked_list.jl`
- `src/common/unused/mutex.jl`
- `src/common/unused/posix_common.jl`
- `src/common/unused/process.jl`
- `src/common/unused/ring_buffer.jl`
- `src/common/unused/rw_lock.jl`
- `src/common/unused/system_resource_util.jl`
- `src/common/unused/thread_scheduler.jl`
- `src/common/unused/uri.jl`
- `src/common/unused/xml_parser.jl`

Recommendation:
- Either delete these (if truly unused) or add explicit tests + include them.

Status: ADDRESSED (kept as reference; added `src/common/unused/README.md` clarifying non-included status).

### `src/io/*`

- `src/io/io.jl`
  - Defines IO error codes, log subjects, `IoHandle`, and shared IO types.

- `src/io/tracing.jl`
  - Tracing hooks. Tests cover basic hook behavior.

- `src/io/event_loop_types.jl`
  - Event loop shared types; `OnEventCallback = Function` is dynamic dispatch.

- `src/io/kqueue_event_loop_types.jl`
  - kqueue types.
  - Default timeout matches aws-c-io (P2.2).

- `src/io/epoll_event_loop_types.jl`
  - epoll types.

- `src/io/iocp_event_loop_types.jl`
  - IOCP types.

- `src/io/event_loop.jl`
  - EventLoop abstraction and EventLoopGroup.
  - `EventLoop.clock::Function` is a dynamic-dispatch hot path.
  - `event_loop_group_get_loop_at` uses 0-based indexing (footgun).

- `src/io/kqueue_event_loop.jl`
  - kqueue backend.
  - Thread-affinity checks for unsubscribe rely on `debug_assert` (P1.2).

- `src/sockets/io/epoll_event_loop.jl`
  - epoll backend.
  - `event_loop_run!` lacks an explicit "already running" guard (unlike kqueue/iocp state checks).
  - `event_loop_complete_destroy!` drains `task_pre_queue` without holding `task_pre_queue_mutex` (possible race if callers schedule during destroy).

Status: ADDRESSED (added an `event_loop.running` guard and lock-safe pre-queue draining during destroy).

- `src/io/iocp_event_loop.jl`
  - IOCP backend. On non-Windows, much is effectively dead code.

- `src/io/message_pool.jl`
  - Message pooling for channels. Tests cover basic behavior.

- `src/io/posix_socket_types.jl`
  - POSIX socket types.

- `src/io/apple_nw_socket_types.jl`
  - Apple Network.framework socket types.

- `src/io/winsock_socket_types.jl`
  - Winsock socket types.

- `src/io/socket.jl`
  - Cross-platform `Socket` wrapper with `impl::Union{...}` and many `Function` fields.
  - This is convenient but leads to dynamic dispatch and complicates invariants.

- `src/io/posix_socket_impl.jl`
  - POSIX socket implementation.
  - Major robustness risk: `socket_close_impl` does not enforce event-loop-thread semantics (P1.2), unlike aws-c-io.

- `src/io/winsock_socket.jl`
  - Windows socket implementation (static review only).
  - High complexity; should be validated on Windows CI.

- `src/io/winsock_init.jl`
  - Winsock init logic.

- `src/io/blocks_abi.jl`
  - Apple blocks ABI helpers.

- `src/io/apple_nw_socket_impl.jl`
  - Apple Network.framework socket implementation.
  - Correctly recognizes async port assignment behavior for port 0 and implements polling.
  - This async readiness must be reflected in higher-level tests and docs (TLS test failure).

- `src/io/channel.jl`
  - Channel pipeline.
  - Concurrency: `_channel_id_counter` is non-atomic (P1.5).
  - Lifecycle: `channel_destroy!` is a no-op if called before shutdown completes (`src/io/channel.jl:1297-1303`). This mirrors aws-c-io but is a common footgun in Julia APIs.

- `src/io/statistics.jl`
  - Channel statistics handler.

- `src/io/socket_channel_handler.jl`
  - Channel handler for sockets.

- `src/io/host_resolver.jl`
  - Default host resolver with caching, background threads.
  - Behavior matches aws-c-io shape (per-host threads).
  - API mismatch vs README: type is `HostResolver`, no `DefaultHostResolver`.

- `src/io/retry_strategy.jl`
  - Retry strategies (no-retry, exponential backoff, standard).
  - Uses abstract strategy types and function-typed callbacks; likely OK, but not type-stable.

- `src/io/stream.jl`
  - Stream abstractions and implementations (cursor, byte buffer, file).
  - Uses finalizers for cleanup; update `PORTING_PATTERNS.md` or align.

- `src/io/pem.jl`
  - PEM parsing/encoding.

- `src/io/shared_library.jl`
  - Shared library loading.
  - Security: callers must avoid untrusted relative paths.

- `src/io/pkcs11.jl`
  - PKCS#11 helpers. Tests cover error mapping and many helpers.

- `src/io/pki_utils.jl`
  - PKI path selection and Apple/Linux helpers.
  - Uses finalizers; review thread-safety of finalizers.

- `src/io/pipe.jl`
  - Pipe implementation and wrappers.

- `src/io/iocp_pipe.jl`
  - IOCP pipe stubs on non-Windows.

- `src/io/future.jl`
  - Future/Promise abstraction.
  - Only one completion callback allowed; enforced via `fatal_assert`.

- `src/io/channel_bootstrap.jl`
  - ClientBootstrap/ServerBootstrap.
  - On Apple Network.framework, listener readiness is async; callers must use `on_listener_setup`.

- `src/io/aws_byte_helpers.jl`
  - Bridging helpers for aws_byte types.

- `src/io/crypto_primitives.jl`
  - Crypto primitives wrappers. Tests cover HKDF/AES-GCM/RSA/ECC operations.

- `src/io/async_stream.jl`
  - Async input stream.
  - P1: `read_in_progress` gate is not CAS (TOCTOU).

- `src/io/tls_channel_handler.jl`
  - TLS high-level API and backend selection.
  - P1: non-atomic init once pattern.

- `src/io/alpn_handler.jl`
  - ALPN protocol negotiation handler.

- `src/sockets/io/unused/dispatch_queue_event_loop.jl`
  - Exists in tree but is not included by `src/Reseau.jl`.
  - Treat as dead code unless re-enabled and tested.

Status: ADDRESSED (moved under an explicit `unused/` directory to reduce accidental reliance).

### `src/io/tls/*`

- `src/io/tls/s2n_tls_handler.jl`
  - Linux TLS backend using s2n.
  - Requires a default trust store when `verify_peer=true` (errors if missing).

- `src/io/tls/secure_transport_tls_handler.jl`
  - Apple TLS backend using SecureTransport.
  - Warns on `verify_peer=false`.

### `src/files/*` (`Reseau.Files`)

- `src/files/files.jl`
  - Module glue and exports.

- `src/files/constants.jl`
  - Base.Filesystem constant parity.

- `src/files/win32.jl`
  - Windows stubs/helpers.

- `src/files/filehandle.jl`
  - File descriptor-backed `FileHandle` with `read`, `write`, `seek`, etc.
  - Bug: `readbytes!` assumes contiguous buffers (P2.3).

- `src/files/stat.jl`
  - stat/lstat/fstat wrappers.

- `src/files/fsops.jl`
  - Filesystem ops (temp, copy, links, realpath, walkdir, etc).
  - Bugs/oddities: `readlink` truncation, `cp(preserve=true)` ignored, predictable `tempname` (P2.3).

- `src/files/backend.jl`
  - Threadpool backend.
  - Threads are created and never shut down automatically for `default_backend()`; consider `atexit` shutdown.

- `src/files/async.jl`
  - Async wrappers around file operations using the backend.

- `src/files/watching.jl`
  - File watching (inotify/kqueue/polling).
  - Integrates with Reseau event loops.

- `src/files/locking.jl`
  - File locking support.
  - Uses finalizer to ensure locks close.

### `src/sockets/*` (`Reseau.Sockets`)

- `src/sockets/ipaddr.jl`
  - IP address types and parsing.

- `src/sockets/dns.jl`
  - libuv-free DNS helpers (`getaddrinfo`, `getnameinfo`, etc).

- `src/sockets/tcp.jl`
  - `TCPSocket`/`TCPServer` surface.
  - Close path calls `socket_close` directly; thread-affinity concerns apply (P1.2).
  - `listen(port)` binds to `127.0.0.1` by default, matching Julia stdlib (`~/julia/stdlib/Sockets/src/Sockets.jl:628-651`).

### `ext/*`

- `ext/ReseauS2NExt.jl`
  - Registers s2n library handle from `s2n_tls_jll` (safe pattern, avoids fragile path lookup).

### Top-Level Non-Code Files

- `README.md`
  - Out of sync with the actual exported API surface (uses `using Reseau` + unqualified names, references `DefaultHostResolver` which does not exist).
  - Threading requirements described in README do not match the current implementation in `src/io/event_loop.jl`.

- `PORTING_PATTERNS.md`
  - Captures useful intent (parametric callable storage, avoid abstract fields in hot paths), but it is not consistently followed in the current codebase:
    - Many structs store `Function` and `Any` in fields that sit on hot paths.
    - Multiple finalizers exist (`rg finalizer src/` lists several), despite \"No finalizers\" guidance.
    - Core structures use `Vector`/`Dict`/`IdDict` in multiple places.
  - Recommendation: either update the doc to reflect reality or refactor code to match the doc, because this document reads like a hard contract.

- `AGENTS.md`
  - Good operational guidance for running tests and understanding optional suites.

- `.github/workflows/ci.yml`
  - CI runs only default tests (no TLS/network); see \"CI Coverage Notes\" above.

- `.github/workflows/TagBot.yml`
  - TagBot configuration for release automation. Ensure the bot has the minimal permissions needed (especially if future workflows publish artifacts).

- `Project.toml` / `Manifest-v1.12.toml`
  - `Project.toml` defines the supported Julia compatibility and the dependency surface that downstream users inherit.
  - `Manifest-v1.12.toml` is useful for reproducible local/dev runs, but it is not used by package users; avoid relying on Manifest-only behavior in docs/tests.

- `LICENSE.md`
  - Ensure any vendored test resources (notably `aws-c-io/tests/resources/*`) are compatible with the repo's license and are clearly test-only.

- `todo/common-usage.md`
  - Appears to be an internal inventory/usage analysis of `src/common/`. It is currently out of sync with this branch's actual `include(...)` graph (it references actively-used `linked_list.jl`/`hash_table.jl`/etc, which are currently under `src/common/unused/` and not included).
  - Recommendation: either regenerate it from the current include graph or move it under `todo/` so it is clearly non-authoritative.

Status: ADDRESSED (moved under `todo/` and added a non-authoritative note).

- `todo/*.md`
  - Design notes and parity targets (sockets/files/libuv-replacements, etc.). Useful context, but treat as aspirational unless referenced by the code/tests.

- `aws-c-io/tests/resources/*`
  - Contains test certificates and private keys copied from aws-c-io. Ensure they are only used for tests and not shipped/loaded by production code paths.

### Tests (`test/*`)

- `test/runtests.jl`
  - Includes all test suites and configures a temporary keychain on macOS.

- `test/common_tests.jl`
  - Covers basic common-layer behavior (buffers, UUID init/to_str, etc). Does not cover `uuid_init_from_str`.

- `test/event_loop_tests.jl`
  - Extensive event loop tests, many gated on interactive thread counts.

- `test/socket_tests.jl`, `test/socket_handler_tests.jl`
  - Covers core socket behaviors (connect/read/write/timeouts, local sockets, UDP).

- `test/channel_tests.jl`, `test/io_testing_channel_tests.jl`, `test/channel_bootstrap_tests.jl`
  - Covers channel pipeline and bootstraps.

- `test/tls_tests.jl`, `test/tls_tests_impl.jl`
  - TLS tests; currently failing on macOS due to port 0 readiness assumptions.

- `test/host_resolver_tests.jl`
  - Covers host resolver cache behavior and network resolution when enabled.

- `test/files_tests.jl`
  - Covers Files surface.

- Remaining test files (`*_tests.jl`)
  - Cover crypto primitives, PKCS11 mapping, shared library loading, tracing, retry strategies, vsock parsing, sockets compat.

Test hygiene note:
- The repo root contains many leftover `testsock*.sock` unix sockets created during tests. Consider cleaning them up in `test/test_utils.jl` or at `atexit`.

## Concrete Recommendations (Prioritized)

1. Fix P0 runtime breakages:
   - `src/common/date_time.jl` MemoryRef indexing.
   - `src/common/uuid.jl` uuid_init_from_str.
   - `src/common/file.jl` env var handling for home/temp.
   - `src/common/byte_buf.jl` string-backed ByteBuffer UB.

Status: ADDRESSED.

2. Enforce thread-affinity for unsafe operations in release builds:
   - `event_loop_unsubscribe_from_io_events!` and socket/channel teardown paths.
   - Make `Reseau.Sockets.close` schedule close onto the correct event loop (and optionally block until complete).
   - Align with aws-c-io close semantics (`~/aws-c-io/source/posix/socket.c:1554-1602`).

Status: ADDRESSED.

3. Reduce dynamic dispatch on hot paths:
   - Replace `Any`/`Function` fields in event loops and schedulers with parametric types where practical.
   - Keep `invokelatest` limited to user callbacks.

Status: DEFERRED (non-trivial refactor; `invokelatest` is currently required for correctness due to world-age behavior on adopted OS threads).

4. Bring `Reseau.Files` closer to Base parity:
   - Fix `readlink` truncation.
   - Implement `cp(...; preserve=true)` or remove/disable keyword.
   - Make `tempname` random and collision-checked.
   - Tighten `readbytes!` buffer requirements.

Status: DEFERRED (Files-related; pending separate PR/branch).

5. Documentation alignment:
   - Update `README.md` to reflect actual public APIs (`Reseau.EventLoops`, `Reseau.HostResolver`, etc).
   - Update or remove mismatched rules in `PORTING_PATTERNS.md` (finalizers, abstract fields, etc) or refactor code to match.

Status: ADDRESSED (README updated; `PORTING_PATTERNS.md` guidelines relaxed to match current codebase reality).
