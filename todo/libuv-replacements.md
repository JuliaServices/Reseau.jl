# Libuv Replacements (Reseau/AwsHTTP/HTTP)

Goal: make `Reseau`, `AwsHTTP`, and `HTTP` avoid libuv for the network/IO stack (directly or via Base/stdlib helpers).

Hard requirement: `HTTP` package source (`src/`) must not import or depend on the `Sockets` stdlib.

Current scope: we are OK (for now) with Julia task/sync primitives that may drive libuv internally:
`Threads.@spawn`, `Threads.Event`, `Threads.Condition`, `wait`/`notify`, `@async`, `Channel`, and `ReentrantLock`.
The replacement work below focuses on libuv-backed *timers/clocks/filesystem helpers* and any `Sockets` stdlib usage.

This document has 2 parts:
1. What touched libuv pre-fix (exact call sites; kept for provenance).
2. The replacement surface implemented so the stack can run without using the libuv-backed APIs in scope.

Implementation note:
- We can reintroduce code from `src/common/unused/` where it helps (some functionality was moved there as dead/unused).
- When re-implementing behavior, treat the C implementations in `~/aws-c-common` as the reference for semantics/edge cases.

## Status (2026-02-07)

Completed the replacement surface and updated all call sites in `Reseau`, `AwsHTTP`, and `HTTP`.

Local verification (macOS):
- `Reseau` tests pass
- `AwsHTTP` tests pass
- `HTTP` tests pass

CI verification:
- `Reseau` PR #1 CI is green on macOS/Linux/Windows (last checked 2026-02-07).

Invariant checks:
- `Reseau/src/` has no `sleep(` / `time_ns` / `Base.timedwait` / `stat(` call sites (comments/docstrings may still mention them).
- `AwsHTTP/src/` has no `time_ns(` call sites.
- `HTTP/src/` has no `Sockets` usage and no `sleep(` call sites.

Quick checks:
```sh
cd /Users/jacob.quinn/.julia/dev/Reseau && rg -n "\\bsleep\\(|\\btime_ns\\b|Base\\.timedwait|\\bstat\\(" -S src
cd /Users/jacob.quinn/.julia/dev/AwsHTTP && rg -n "\\btime_ns\\(" -S src
cd /Users/jacob.quinn/.julia/dev/HTTP && rg -n "\\b(using|import)\\s+Sockets\\b|\\bSockets\\.|\\bsleep\\(" -S src
```

Test-only `Sockets` in HTTP:
- `Sockets` is allowed in `HTTP/test/` and is declared in `HTTP/Project.toml` under `[extras]` + `[targets].test`.

## Julia Source Proof Points (Why These Hit libuv)

These are the key Base/stdlib APIs that invoke libuv under the hood:

1. `sleep`, `Timer`, `timedwait`:
   - `~/julia/base/asyncevent.jl`: `sleep(sec)` is implemented as `wait(Timer(sec))`.
   - `~/julia/base/asyncevent.jl`: `Timer` uses `uv_timer_*` callbacks.
   - `~/julia/base/asyncevent.jl`: `timedwait` uses a repeating `Timer(...)`.

2. Task scheduler blocking (`wait`, `yield`, `Threads.Condition`, `Threads.Event`, `Channel`, `ReentrantLock` slow paths):
   - `~/julia/base/task.jl`: `yield()` calls `wait()`.
   - `~/julia/base/task.jl`: `wait()` calls `process_events()` each time it runs.
   - `~/julia/base/libuv.jl`: `process_events()` is `ccall(:jl_process_events, ...)` which drives the libuv event loop.
   - `~/julia/base/lock.jl`: `ReentrantLock` slow path calls `Base.yield()` and parks via `wait()` (thus `process_events()`).
   - `~/julia/base/lock.jl`: `Threads.Event` is built on `Threads.Condition` + `wait`/`notify`.
   - Accepted for now; not planning to replace these primitives yet.

3. Monotonic clock:
   - `~/julia/base/Base_compiler.jl`: `time_ns() = ccall(:jl_hrtime, ...)`.
   - `~/julia/src/sys.c`: `jl_hrtime()` returns `uv_hrtime()`.

4. Filesystem operations:
   - `~/julia/base/filesystem.jl`: `Filesystem.open(path, flags, ...)` uses `ccall(:uv_fs_open, ...)`.
   - `~/julia/base/stat.jl` + `~/julia/src/sys.c`: `stat(...)` uses `jl_stat(...)` which calls `uv_fs_stat(...)`.
   - `~/julia/base/path.jl`: `homedir()` calls `uv_os_homedir`.
   - `~/julia/base/file.jl`: `tempdir()` calls `uv_os_tmpdir`.

5. `Sockets` stdlib:
   - `~/julia/stdlib/Sockets/src/*`: uses `ccall(:uv_...)` for sockets + DNS (`uv_tcp_*`, `uv_getaddrinfo`, etc).

## Former libuv Touchpoints (Pre-Fix Call Sites)

The call site lists in this section were intentionally exhaustive for the *pre-fix* working trees.
They are kept for provenance; see the Status section above for how to verify the current state.

### Reseau (`/Users/jacob.quinn/.julia/dev/Reseau`)

#### Definite libuv calls (always enter libuv)

1. `sleep(...)` (libuv `Timer`):
   - `src/common/thread.jl:167`
   - `src/io/epoll_event_loop.jl:161`
   - `src/io/kqueue_event_loop.jl:241`
   - `src/io/iocp_event_loop.jl:384`
   - `src/io/future.jl:89`
   - `src/io/future.jl:187`
   - `src/io/future.jl:363`

2. `Base.timedwait(...)` (libuv `Timer`):
   - `src/common/condition_variable.jl:107`

3. `time_ns()` (libuv `uv_hrtime`):
   - `src/io/epoll_event_loop.jl:156`
   - `src/io/epoll_event_loop.jl:158`
   - `src/io/kqueue_event_loop.jl:236`
   - `src/io/kqueue_event_loop.jl:238`
   - `src/io/iocp_event_loop.jl:379`
   - `src/io/iocp_event_loop.jl:381`

4. Filesystem via Base (libuv `uv_fs_*` / `uv_os_*`):
   - `open(path, "a+")`:
     - `src/common/log_writer.jl:29`
   - `stat(...)`:
     - `src/common/file.jl:72`
     - `src/io/stream.jl:324`
   - `homedir()`:
     - `src/common/file.jl:153`

5. StdIO via Base libuv streams (TTY/LibuvStream):
   - `write(Base.stderr, ...)`:
     - `src/common/assert.jl:2`
     - `src/common/assert.jl:8`
   - `stdout`/`stderr` log writers:
     - `src/common/log_writer.jl:21`
     - `src/common/log_writer.jl:25`

#### Libuv via Base task scheduler (accepted for now)

These can reach `Base.wait()`/`Base.yield()`, which calls `process_events()` and drives libuv internally.
We are explicitly OK with these for now; no replacement work is planned yet.

1. `Threads.@spawn`:
   - `src/common/thread_scheduler.jl:83`
   - `src/io/event_loop.jl:343`

2. `@async` + `Channel{...}` (Base):
   - `src/common/log_channel.jl:6`
   - `src/common/log_channel.jl:11`
   - `src/common/log_channel.jl:12`

3. Waiting on task/conditions/events:
   - `wait(cond.cond)`:
     - `src/common/condition_variable.jl:63`
   - `wait(channel.task)`:
     - `src/common/log_channel.jl:36`
   - `wait(scheduler.worker)`:
     - `src/common/thread_scheduler.jl:94`
   - Blocking IO facades (no libuv, but uses Base task waiting/notification):
     - `src/sockets/tcp.jl`
     - `src/files/watching.jl`

4. `Threads.Condition` fields/constructors:
   - `src/common/condition_variable.jl:2`
   - `src/common/condition_variable.jl:6`
   - `src/sockets/tcp.jl`
   - `src/files/watching.jl`

5. `Threads.Event` fields/constructors:
   - `src/sockets/tcp.jl`
   - `src/files/watching.jl`

6. `notify(...)` on those conditions/events (pairs with the waits above):
   - `src/common/condition_variable.jl:21`
   - `src/common/condition_variable.jl:36`
   - `src/sockets/tcp.jl`
   - `src/files/watching.jl`

7. `ReentrantLock` usage (contention path calls `yield`/`wait`):
   - `src/common/device_random.jl:10`
   - `src/common/thread_scheduler.jl:5`
   - `src/common/thread_scheduler.jl:78`
   - `src/common/thread_shared.jl:1`
   - `src/common/condition_variable.jl:53`
   - `src/common/condition_variable.jl:76`
   - `src/common/condition_variable.jl:85`
   - `src/common/condition_variable.jl:119`
   - `src/io/dispatch_queue_event_loop.jl:28`
   - `src/io/dispatch_queue_event_loop.jl:39`
   - `src/io/apple_nw_socket_types.jl:97`
   - `src/io/apple_nw_socket_types.jl:100`
   - `src/io/apple_nw_socket_types.jl:133`
   - `src/io/apple_nw_socket_types.jl:136`
   - `src/io/kqueue_event_loop_types.jl:113`
   - `src/io/kqueue_event_loop_types.jl:121`
   - `src/io/host_resolver.jl:135`
   - `src/io/host_resolver.jl:154`
   - `src/io/host_resolver.jl:165`
   - `src/io/host_resolver.jl:204`
   - `src/io/epoll_event_loop_types.jl:79`
   - `src/io/epoll_event_loop_types.jl:98`
   - `src/io/channel.jl:243`
   - `src/io/channel.jl:245`
   - `src/io/channel.jl:252`
   - `src/io/channel.jl:297`
   - `src/io/channel.jl:299`
   - `src/io/channel.jl:305`
   - `src/io/pki_utils.jl:96`
   - `src/io/pki_utils.jl:1044`
   - `src/io/tls_channel_handler.jl:211`
   - `src/io/tls_channel_handler.jl:296`
   - `src/io/tls_channel_handler.jl:464`
   - `src/io/tls/s2n_tls_handler.jl:23`
   - `src/io/tls/s2n_tls_handler.jl:85`
   - `src/io/iocp_event_loop_types.jl:14`
   - `src/io/iocp_event_loop_types.jl:22`
   - `src/io/winsock_init.jl:8`
   - `src/io/retry_strategy.jl:51`
   - `src/io/retry_strategy.jl:219`
   - `src/io/retry_strategy.jl:509`
   - `src/io/retry_strategy.jl:513`
   - `src/io/retry_strategy.jl:522`
   - `src/io/retry_strategy.jl:540`
   - `src/io/retry_strategy.jl:556`
   - `src/io/retry_strategy.jl:609`
   - `src/io/apple_nw_socket_impl.jl:54`
   - `src/io/apple_nw_socket_impl.jl:57`
   - `src/io/future.jl:27`
   - `src/io/future.jl:37`

### AwsHTTP (`/Users/jacob.quinn/.julia/dev/AwsHTTP`)

#### Definite libuv calls

1. `time_ns()` (libuv `uv_hrtime`):
   - `src/connection_manager.jl:195`
   - `src/connection_manager.jl:218`
   - `src/connection_manager.jl:326`
   - `src/connection_manager.jl:377`
   - `src/connection_monitor.jl:74`
   - `src/connection_monitor.jl:108`
   - `src/h2_connection.jl:496`
   - `src/h2_connection.jl:543`
   - `src/h1_connection.jl:434`
   - `src/h1_connection.jl:570`
   - `src/h1_connection.jl:624`
   - `src/h1_connection.jl:955`
   - `src/h1_connection.jl:975`

#### Libuv via Base task scheduler (accepted for now)

1. `Threads.@spawn`:
   - `src/connection.jl:54`

2. `Threads.Event` + `wait`/`notify`:
   - `src/server.jl:87`
   - `src/server.jl:288`
   - `src/server.jl:291`
   - `src/server.jl:246`
   - `src/server.jl:301`
   - `src/server.jl:312`

3. `ReentrantLock` usage:
   - `src/server.jl:79`
   - `src/server.jl:280`

### HTTP (`/Users/jacob.quinn/.julia/dev/HTTP`)

#### Definite libuv calls

1. `Sockets` stdlib usage (libuv sockets + DNS) (hard requirement: remove from `HTTP` `src/`):
   - `src/HTTP.jl:3` (`using ... Sockets`)
   - `src/HTTP.jl:82` (`Sockets.getalladdrinfo("localhost")`)
   - `src/cookies.jl:36` (`using Dates, Sockets`)
   - `src/client/retry.jl:23` (`Sockets.DNSError`, `Base.UV_EAI_AGAIN`)
   - `src/server.jl:320` (`Sockets.BACKLOG_DEFAULT`)
   - `src/server.jl:342` (`Sockets.BACKLOG_DEFAULT`)

2. `sleep(...)` (libuv `Timer`):
   - `src/client/stream.jl:764`
   - `src/client/stream.jl:852`
   - `src/client/retry.jl:227`
   - `src/server.jl:678`
   - `src/websockets.jl:615`

3. Base filesystem helpers (libuv `uv_os_*` / `uv_fs_*` / `stat`):
   - `tempdir()`:
     - `src/download.jl:34`
   - `isdir(...)`:
     - `src/download.jl:37`
   - `tempname()`:
     - `src/download.jl:41`
   - `Base.open(file, "w")`:
     - `src/download.jl:105`

#### Libuv via Base task scheduler (accepted for now)

1. `Threads.@spawn`:
   - `src/client/stream.jl:763`
   - `src/client/stream.jl:851`
   - `src/server.jl:176`
   - `src/server.jl:216`
   - `src/websockets.jl:77`
   - `src/websockets.jl:248`
   - `src/websockets.jl:255`
   - `src/websockets.jl:290`
   - `src/websockets.jl:318`
   - `src/websockets.jl:367`
   - `src/websockets.jl:412`
   - `src/websockets.jl:799`

2. `Threads.Event`:
   - `src/client/stream.jl:16`
   - `src/client/stream.jl:42`
   - `src/server.jl:61`
   - `src/server.jl:76`
   - `src/server.jl:382`
   - `src/server.jl:389`

3. `Threads.Condition`:
   - `src/utils.jl:301`
   - `src/utils.jl:304`

4. `wait`/`notify` on `Threads.Event` / `Threads.Condition`:
   - `src/client/stream.jl:407`
   - `src/client/stream.jl:416`
   - `src/server.jl:530`
   - `src/server.jl:537`
   - `src/server.jl:648`
   - `src/utils.jl:318`
   - plus many `wait(...)`/`notify(...)` call sites for `Future` and stream futures:
     - `src/client/stream.jl` (multiple)
     - `src/client/retry.jl` (multiple)
     - `src/client/connection.jl` (multiple)
     - `src/server.jl` (multiple)
     - `src/websockets.jl` (multiple)
     - `src/utils.jl:309` (`Base.wait(f::Future)`)
     - `src/utils.jl:326` (`Base.notify(f::Future, ...)`)
     - `src/utils.jl:339` (`Base.notify(f::Future, err::Exception)`)

5. `ReentrantLock` usage:
   - `src/client/client.jl:8`
   - `src/client/client.jl:425`
   - `src/client/client.jl:432`
   - `src/server.jl:36`
   - `src/server.jl:42`
   - `src/server.jl:59`
   - `src/server.jl:74`
   - `src/server.jl:380`
   - `src/websockets.jl:54`
   - `src/websockets.jl:58`
   - `src/websockets.jl:154`
   - `src/websockets.jl:155`
   - `src/websockets.jl:181`
   - `src/websockets.jl:182`
   - `src/cookiejar.jl:14`
   - `src/cookiejar.jl:19`

## Replacement Surface (Minimal, Purpose-Built)

Implement these in `Reseau` to allow `Reseau`/`AwsHTTP`/`HTTP` to stop using the libuv-backed Base/stdlib APIs in scope above.

### 1. Monotonic Clock (Replace `time_ns()`)

Status: implemented in `Reseau/src/common/clock.jl` and call sites updated in `Reseau/src/io/*` + `AwsHTTP/src/*`.

Provide:
- `Reseau.monotonic_time_ns()::UInt64` in common/clock.jl

Implementation:
- Wrap existing `high_res_clock_get_ticks(::Ref{UInt64})` from `src/common/clock.jl` and return the value.

Replace call sites:
- All `time_ns()` usage in `Reseau` event loops and in `AwsHTTP` timestamping/culling/RTT calculations.

### 2. Sleep/Delay (Replace `sleep(...)` Without Blocking Julia Threads)

Status: implemented in `Reseau/src/common/clock.jl` (thread sleep) and `Reseau/src/io/event_loop.jl` (task sleep), with call sites updated in `Reseau` + `HTTP`.

Provide:
- `Reseau.thread_sleep_ns(ns::Integer)::Nothing`  in common/clock.jl (blocking; for dedicated threads only)
- `Reseau.thread_sleep_s(seconds::Real)::Nothing` (thin wrapper)  in common/clock.jl
- `Reseau.task_sleep_ns(event_loop::EventLoop, ns::Integer)::Nothing`  (non-blocking; parks the *task*, not the thread)
- `Reseau.task_sleep_s(event_loop::EventLoop, seconds::Real)::Nothing` (thin wrapper)

Why two APIs:
- A straight replacement of Base `sleep(...)` with OS-level `nanosleep`/`Sleep` **blocks the Julia thread**.
  That is not equivalent to Julia's current `sleep`, which parks the *task* and lets other tasks run on that thread.
  Blocking a thread can reduce throughput and can deadlock if the work that completes the wait needs time on that thread.
- For libuv replacement, we want to avoid libuv-backed `Timer` usage, but we still want *task-friendly* sleeps for
  timeout/backoff logic in `HTTP`, `AwsHTTP`, and `Reseau` user-facing blocking APIs.

Implementation:
- `thread_sleep_*` (blocking):
  - POSIX: `nanosleep` (or `clock_nanosleep`) via `@ccall gc_safe=true ...`.
  - Windows: `Sleep(ms)` or a waitable timer for sub-ms.
- `task_sleep_*` (non-blocking):
  - Use `event_loop_schedule_task_future!(event_loop, ScheduledTask(...), run_at_nanos)` to schedule a wake-up.
  - Park the current task on a `Threads.Event`/`Threads.Condition` and `wait(...)` until the scheduled task fires.
  - This avoids libuv `Timer` while keeping "sleep parks tasks, not threads" semantics.

Replace call sites:
- Prefer removing polling sleeps entirely where possible:
  - `Reseau` event loop startup: signal readiness with an event/condition (avoid `sleep(0.001)` polling loop).
  - `Reseau` `Future` waits: use wait/notify (avoid `yield` + `sleep` polling loops).
- Where a delay is truly needed:
  - Use `task_sleep_*` for timeouts/backoffs in `HTTP`/`AwsHTTP` (and any user-facing blocking APIs).
  - Reserve `thread_sleep_*` for dedicated low-level worker threads that run no other Julia tasks.


### 3. Replace `Base.timedwait(...)` (Avoid libuv `Timer`)

Status: implemented in `Reseau/src/common/clock.jl` + `Reseau/src/common/condition_variable.jl`.

Provide:
- `Reseau.timedwait_poll(testcb, timeout_s; poll_s=...) -> (:ok | :timed_out)`  in common/clock.jl

Implementation:
- Use `Reseau.monotonic_time_ns()` + `Reseau.thread_sleep_ns(...)` and poll `testcb()` without `Timer`.

Replace call sites:
- `Reseau` `src/common/condition_variable.jl` (uses `Base.timedwait`)

### 4. Non-libuv Filesystem Helpers (Replace `open`, `stat`, `homedir`, `tempdir`, `tempname`, `isdir`) in common/file.jl

Status: implemented in `Reseau/src/common/file.jl` (libc wrappers) + `Reseau/src/common/log_writer.jl` (no `Base.open`), with call sites updated in `HTTP/src/download.jl`.

Provide:
- `Reseau.fs_open_*` wrappers for file open/append without `Base.Filesystem.open`
- `Reseau.fs_fstat_size(fd)::Int64` or `Reseau.fs_file_length(file_ptr)::Int64` without `Base.stat`
- `Reseau.get_home_directory()` without `homedir()`:
  - POSIX: `getenv("HOME")` or `getpwuid_r`
  - Windows: `SHGetKnownFolderPath(FOLDERID_Profile)` or env fallbacks
- `Reseau.get_temp_directory()` without `tempdir()`:
  - POSIX: env fallbacks + default `/tmp`
  - Windows: `GetTempPathW`
- `Reseau.tempname(dir)` without `ispath/stat` loops (use random + `open(O_EXCL)` if you need atomicity)

Replace call sites:
- `Reseau` `src/common/file.jl` (`stat`, `homedir`)
- `Reseau` `src/io/stream.jl` (`stat`)
- `Reseau` `src/common/log_writer.jl` (`open`)
- `HTTP` `src/download.jl` (`tempdir`, `isdir`, `tempname`, `Base.open`)

### 5. Hard Requirement: Remove `Sockets` From HTTP

Status: implemented. `HTTP/src/` has no `Sockets` usage; `Sockets` is used in `HTTP/test/` only.

Provide (either in `Reseau` or in `HTTP` without importing `Sockets`):
- Minimal IP parser for cookie domain checks:
  - `HTTP.parse_ipaddr(host)::Union{Nothing, ...}` (or `Reseau.IPAddress`)
  - aws-c-common should have some functionality for this
- DNS error type and retry classifications not tied to `Sockets.DNSError` / `Base.UV_EAI_*`:
  - `Reseau.DNSError` (or reuse Reseau error codes from host resolver)
  - can live in host_resolver.jl
- Replace `Sockets.getalladdrinfo("localhost")` precompile probe with:
  - `Reseau._native_getaddrinfo("localhost")` (already exists in `Reseau` host resolver); rename to `Reseau.getalladdrinfo
- Remove `Sockets.BACKLOG_DEFAULT` usage from `HTTP` entirely; no backwards compat necessary

Success criteria:
- No `Sockets` import or reference in `HTTP` package source (`src/`):
  - `rg -n '\\b(using|import)\\s+Sockets\\b|\\bSockets\\.' src` returns no matches.
- Replace `Sockets.DNSError` and `Base.UV_EAI_*` usage with `Reseau`/`AwsHTTP`-native error types/codes.

Replace call sites:
- `HTTP` `src/HTTP.jl`
- `HTTP` `src/cookies.jl`
- `HTTP` `src/client/retry.jl`
- `HTTP` `src/server.jl`
