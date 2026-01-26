# AwsIO Pure Julia aws-c-io PRD

Date: 2026-01-26

## 1. Summary
Build a pure-Julia implementation of the aws-c-io library (macOS + Linux only) that avoids libuv and its global I/O lock. The implementation will run on Julia-managed threads and use direct OS syscalls for sockets and event loops. The public API will be a "hybrid" C-like surface that closely matches aws-c-io names and behavior, but **without the `aws_` prefix**. TLS support is in MVP using `MbedTLS`. ALPN is deferred. Full host resolver behavior (cache + TTL + background refresh) is included. `async_stream` is included in MVP.

This repo (`AwsIO/`) is fully under our control, no backwards compatibility constraints.

## 2. Goals
- Pure Julia implementation of aws-c-io concepts and behavior on macOS + Linux.
- Avoid libuv and Base I/O paths to bypass the global I/O lock.
- Use Julia-managed threads (no `pthread_create`, no `jl_adopt_thread`).
- API names and shapes match aws-c-io closely, but without the `aws_` prefix.
- Support TLS channel handler in MVP via `MbedTLS`.
- Implement `async_stream` in MVP.
- Full host resolver (cache, TTL, background refresh) in MVP.
- Minimize dependency on `LibAwsCommon`; reimplement data structures in Julia where feasible.

## 3. Non-Goals (Initial)
- Windows IOCP and Apple Network Framework / dispatch queue event loops.
- ALPN handler (may be added later).
- Strict ABI compatibility with C aws-c-io.
- Maintaining any current API/behavior in this repo.

## 4. Users / Consumers
- Julia packages that want AWS CRT-style IO without libuv.
- Internal AWS Julia runtime ports that currently rely on aws-c-io.

## 5. Constraints & Principles
Aligned with `Runtime/src/aws/old_do_not_consider/PORTING_PATTERNS.md`.
- **No libuv**: do not use `Base.Sockets`, `Base.PipeEndpoint`, `Base.TCPSocket`, or other Base I/O that goes through libuv.
- Use OS syscalls via `@ccall` for sockets, epoll/kqueue, pipe/eventfd, getaddrinfo, etc.
- **No abstract-typed fields**: use parametric types so fields are concrete and dispatch is compile-time.
- **No `Function`-typed fields**: store callbacks as parametric callable fields.
- **No finalizers**: all resources are explicitly closed/destroyed (`close!`, `destroy!`, `clean_up!`).
- **No refcounting**: rely on explicit lifecycle + GC for memory (no `ref_count` module).
- Use `@atomic` for atomic fields; **do not use `Atomic{T}`**.
- Use Julia primitives for synchronization: `ReentrantLock`, `Threads.Condition`, `Threads.SpinLock` where appropriate.
- **No `Vector`/`Dict` in core data structures**: use `Memory{T}` and custom containers (ArrayList, HashTable, PriorityQueue).
- **No Julia Logging**: use custom logging interfaces/macros as in porting patterns.
- Use EnumX for scoped enums and ScopedValues for global context.
- Reuse Runtime `old_do_not_consider` implementations as starting points, adjusting to the rules above.

## 6. API Surface (Hybrid, no `aws_` prefix)
Naming follows aws-c-io but without the `aws_` prefix. All functions are Julia functions; mutating functions end with `!`.

### 6.1 Core Types
- `EventLoop`, `EventLoopGroup`, `EventLoopOptions`, `EventLoopGroupOptions`
- `Channel`, `ChannelSlot`, `ChannelHandler`, `ChannelHandlerVTable` (or multiple dispatch interface)
- `IoHandle`, `IoMessage`
- `Socket`, `SocketOptions`, `SocketEndpoint`, `SocketConnectOptions`, `SocketListenerOptions`
- `Future`, `Promise`
- `MessagePool`
- `AsyncStream` (with `AsyncInputStream`, `AsyncOutputStream`)
- `TlsConnectionOptions`, `TlsContext` (thin wrappers around MbedTLS)

### 6.2 Function Naming Examples
- `event_loop_new`, `event_loop_run!`, `event_loop_stop!`, `event_loop_schedule_task_now!`
- `event_loop_group_new`, `event_loop_group_destroy!`, `event_loop_group_get_next_loop`
- `channel_new`, `channel_destroy!`, `channel_shutdown!`, `channel_slot_new`, `channel_slot_insert_end!`
- `socket_new`, `socket_connect!`, `socket_write!`, `socket_read!`, `socket_shutdown!`
- `host_resolver_new`, `host_resolver_resolve_host!`, `host_resolver_purge_cache!`

### 6.3 Error Handling
- Port the aws-c-io error codes as `const` integers (`ERROR_IO_*`) in `io/errors.jl`.
- Provide `io_error_code_is_retryable` and `retry_error_type_from_io_error` helpers.
- Map `errno` to IO error codes for socket/file ops.
- Errors return `Union{T, ErrorResult}` or `Union{T, Nothing}` (no exception flow in hot paths).

## 7. Architecture Overview

### 7.0 Porting Pattern Guidance (Applied)
- Vtables become abstract types + multiple dispatch (no function pointers stored in structs).
- Callbacks are stored as parametric callables (no `Function` fields).
- Options/configs are immutable structs with concrete fields and keyword constructors.
- Opaque handles use explicit lifecycle (`init!`/`destroy!` or `open!`/`close!`).
- Error handling uses `ErrorResult(code)` sentinel values in union returns.
- OS-specific implementations live in OS-specific files/modules; dispatch uses `Sys.islinux()`/`Sys.isapple()`.

### 7.1 Module Layout
```
src/
  AwsIO.jl                # main module, includes submodules
  common/                 # aws-c-common analogs (subset)
    byte_buf.jl
    array_list.jl
    linked_list.jl
    hash_table.jl
    priority_queue.jl
    clock.jl
    error.jl
    thread.jl             # Julia thread helpers (no pthread)
    mutex.jl
    condition_variable.jl
    task_scheduler.jl
    logging.jl            # custom logging interfaces/macros
    scoped_context.jl     # ScopedValues context (logger, etc)
  io/
    io.jl                 # error codes, IoHandle, IoMessage
    event_loop.jl
    epoll_event_loop.jl   # Linux only
    kqueue_event_loop.jl  # macOS/BSD
    channel.jl
    channel_bootstrap.jl
    socket.jl
    posix_socket.jl       # socket impl for Linux/macOS
    socket_channel_handler.jl
    host_resolver.jl
    future.jl
    message_pool.jl
    stream.jl
    async_stream.jl
    retry_strategy.jl
    pem.jl
    pipe.jl
    shared_library.jl
    tls_channel_handler.jl
```

### 7.2 Data Structure Strategy
- **Byte buffers**: use Runtime `ByteBuffer` / `ByteCursor` port as baseline; store owned data in `Memory{UInt8}`.
- **ArrayList**: use a `Memory{T}`-backed container (not `Vector`) with explicit length/capacity.
- **Linked list**: reuse Runtime linked-list implementation for intrusive lists (or `Memory` + index-based nodes).
- **Hash table**: reuse Runtime `HashTable` (Memory-backed) for resolver cache and event loop local storage.
- **PriorityQueue**: Memory-backed implementation for schedulers and timed queues.
- **Task scheduler**: reuse Runtime `TaskScheduler` pattern (Memory-based containers).
- **No allocator interface**: do not port `aws_allocator`; memory relies on GC and `Memory{T}`.

## 8. Threading Model
- Event loop threads are Julia tasks launched via `Threads.@spawn` (or explicit `Task` + `schedule`).
- Each event loop runs on one Julia thread and **does not yield** inside the loop except via blocking syscalls (`kevent`/`epoll_wait`), which keeps it effectively pinned.
- Store `running_thread_id` in `EventLoop` to implement `event_loop_thread_is_callers_thread`.
- No `pthread_create` and no `jl_adopt_thread`.

### 8.1 Cross-Thread Scheduling
- Event loop maintains a lock-protected task queue and a wakeup fd (eventfd on Linux, pipe or `EVFILT_USER` on macOS/kqueue).
- `event_loop_schedule_task_now!` from any thread enqueues and signals wakeup fd.
- Event loop drains the task queue on wakeup.

## 9. Event Loop Design

### 9.1 Linux (epoll)
- Based on Runtime `old_do_not_consider/io/epoll_event_loop.jl`.
- Use `epoll_create`, `epoll_ctl`, `epoll_wait` via `@ccall`.
- Use `eventfd` for cross-thread wakeups; fallback to pipe if unavailable.

### 9.2 macOS (kqueue)
- Based on Runtime `old_do_not_consider/io/kqueue_event_loop.jl`.
- Use `kqueue`, `kevent` syscalls via `@ccall`.
- Use `EVFILT_USER` or pipe for wakeups.

### 9.3 Event Loop Group
- Create N event loops in a group and run each on its own Julia thread task.
- Load balancing uses “best-of-two” random selection based on load factor (as in aws-c-io).
- **No refcounting**: `event_loop_group_acquire`/`event_loop_group_release` may exist for API symmetry but are no-ops; explicit `event_loop_group_destroy!` is required to stop loops and free resources.

## 10. Channel Pipeline
- Port Runtime `channel.jl` with the same semantics:
  - Slots form a doubly-linked chain.
  - Read direction flows toward application; write direction toward socket.
  - Backpressure via windowing; `increment_read_window` propagates.
- Tasks are executed on the event loop thread.
- Support `channel_task` equivalents for scheduling actions on the event loop.

## 11. Socket Layer
- Port Runtime `socket.jl` and `posix_socket.jl`.
- Use OS syscalls: `socket`, `connect`, `read`, `write`, `shutdown`, `setsockopt`, `fcntl`.
- `SocketChannelHandler` binds socket read/write to channel messages.
- Expose low-level socket APIs (connect/accept/read/write) with callback-based completions.

## 12. TLS Channel Handler (MVP)
- Implement `TlsChannelHandler` in Julia.
- Use `MbedTLS` for TLS configuration and I/O operations.
- Provide `TlsConnectionOptions` and `TlsContext` wrappers.
- Flow:
  - TLS handler wraps the socket handler in the channel pipeline.
  - On read: decrypt incoming bytes -> emit application `IoMessage`.
  - On write: encrypt application data -> write to socket handler.
- ALPN: parsing/support deferred (optional no-op for now).

## 13. Async Stream (MVP)
- Implement `AsyncInputStream` and `AsyncOutputStream` similar to aws-c-io `async_stream`.
- Support async read/write with callbacks and future/promise integration.
- Use event-loop scheduling for callback dispatch.

## 14. Host Resolver (Full)
- Port Runtime `host_resolver.jl` with full cache semantics:
  - Cache entries per hostname.
  - TTL honoring with periodic refresh.
  - Background refresh thread/task per active host.
  - Failover tracking (connection failure counts).
- Use `getaddrinfo` via `@ccall` for resolution.
- Resolver work runs on a Julia thread task (not libuv).

## 15. Retry Strategy
- Port `retry_strategy.jl` from Runtime.
- Expose `RetryStrategy`, `ExponentialBackoffConfig`, and helpers.

## 16. Logging & Statistics
- Do **not** use Julia `Logging` stdlib in core code.
- Provide custom logging interfaces/macros (compile-time gated) as per porting patterns.
- Minimal statistics in MVP; expand only as needed by TLS/channel/socket paths.

## 17. Dependencies
- `LibAwsCommon`: keep as dependency, but prefer pure-Julia equivalents. Use only when required for CRT interop.
- `LibAwsCal`: optional for future CRT parity; not used in MVP.
- `MbedTLS`: used for TLS operations.
- `EnumX`: scoped enums.
- `ScopedValues`: scoped global context (logger, etc.).

## 18. Testing
- Port Runtime tests from `old_do_not_consider/test/io/io_tests.jl`.
- Add tests for:
  - Event loop scheduling and cross-thread wakeup.
  - Socket connect/read/write on localhost.
  - TLS handshake against local TLS server (integration test).
  - Host resolver caching and TTL behavior.
  - Async stream callbacks.

## 19. Risks & Mitigations
- **Task migration**: event loop tasks must not yield; ensure event loop loop body uses blocking syscalls and no Julia waits.
- **GC safety**: ensure buffers passed to `@ccall` are preserved with `GC.@preserve`.
- **TLS integration complexity**: start with minimal TLS data path; avoid ALPN.
- **DNS blocking**: always run resolver in separate Julia task/thread.
- **Explicit lifecycle**: without finalizers/refcount, ensure all OS handles are closed via `close!`/`destroy!`; provide `with_*` helpers.

## 20. Milestones
1. [x] **Foundation**: port common + io core types; set module layout.
2. [x] **Event loops**: epoll + kqueue loops, cross-thread scheduling.
3. [x] **Channel + socket**: channel pipeline, socket handler, message pool.
4. [x] **TLS handler**: TLS channel handler using MbedTLS.
5. [x] **Host resolver**: full resolver with cache + TTL.
6. [x] **Async stream**: async read/write streams.
7. [x] **Tests + docs**: port/author tests, add usage docs.

## 21. Open Questions (None)
All user choices are finalized:
- macOS + Linux only.
- Julia-managed threads.
- Hybrid API without `aws_` prefix.
- TLS handler in MVP; ALPN deferred.
- Full resolver in MVP.
