# Files Submodule PRD (Reseau.Files)

Goal: implement a `Reseau.Files` submodule that provides a production-ready, libuv-free filesystem + file IO + file watching stack, integrated with the Reseau event loop.

Hard requirements (v1 decisions locked):
- Works on Linux/macOS/Windows in CI.
- Avoids Base/stdlib APIs that route to libuv for filesystem + timers + file watching.
- Provides non-blocking primitives that integrate with `Reseau.EventLoop` (never block the event-loop thread).
- Provides (as close as practical) one-to-one API coverage of Base Julia "file IO" and `FileWatching` stdlib.
- Exception-first API (Base-like throwing surface).
- Windows core uses Win32 `HANDLE` APIs (not CRT `FILE*`) for core functionality and async.
- Buffering strategy: `Reseau.Files.FileHandle <: IO` directly (unbuffered syscalls) plus Base's generic `IO` helpers. No `BufferIO` dependency.
- v1 scope includes pidfile locks, file locking, and atomic write helpers.

This doc has 3 parts:
1. Inventory/deep-dive: what Julia provides today, and what calls libuv vs OS syscalls vs pure Julia.
2. Inventory/deep-dive: libuv file IO + file watching surface and how it works internally.
3. PRD: `Reseau.Files` design (API, architecture, per-platform backends, testing plan, and phased rollout).

## Status (2026-02-08)

`Reseau.Files` is now implemented as a public submodule with a libuv-free filesystem + file IO + watching surface:
- Code: `src/Files.jl` + `src/files/*`
- Core IO type: `Reseau.Files.FileHandle <: IO` (`src/files/filehandle.jl`)
- Filesystem ops (`pwd`, `cd`, `mkdir`, `mkpath`, `rm`, `mv`, `cp`, `readdir`, `walkdir`, `mktemp*`, `tempdir`, `touch`, etc): `src/files/fsops.jl`
- Stat + predicates: `src/files/stat.jl`
- Async backend (threadpool-based; IOCP integration where available): `src/files/backend.jl`, `src/files/async.jl`
- File watching (no libuv; inotify on Linux, kqueue vnode on macOS/BSD, polling fallback on Windows v1): `src/files/watching.jl`
- Locking + pidfile locks + atomic write: `src/files/locking.jl`
- Tests: `test/files_tests.jl` (sync IO, fs ops, locking, async ops, watching smoke, `poll_fd` on POSIX)

---

## 1) Inventory: Julia File IO Surface (Base + stdlibs)

### A. Core "file IO" types in Base

#### 1. `Base.IOStream` (buffered stream; what `open("path")` usually returns)

Public API:
- `open(path; read/write/create/truncate/append, lock=true) -> IOStream` (and mode-string form)
- `read`, `read!`, `readbytes!`, `write`, `seek`, `position`, `truncate`, `flush`, `close`, `fd`, etc.

Implementation:
- Defined in `~/julia/base/iostream.jl`.
- Backed by `ccall(:ios_file, ...)`, `ccall(:ios_readall, ...)`, `ccall(:ios_write, ...)`, etc.
- Implemented in C in `~/julia/src/support/ios.c`.

Where libuv is used vs not:
- POSIX: `ios_file` uses OS syscalls directly (`open`, `read`, `write`, `lseek`, `ftruncate`, etc). See `~/julia/src/support/ios.c` `open_cloexec()` + `ios_file()`.
- Windows: `ios_file` uses `_wopen` and converts UTF-8 path to UTF-16 using libuv WTF-8 helpers `uv_wtf8_length_as_utf16` / `uv_wtf8_to_utf16`. See `~/julia/src/support/ios.c` `ios_file()`.
  - Important nuance: this is "libuv for encoding utilities", not "libuv fs APIs" (`uv_fs_*`).

Takeaway:
- The most common "read/write file bytes" path in Base Julia is largely not libuv-based (aside from Windows path conversion helpers).

#### 2. `Base.Filesystem.File` (unbuffered IO; libuv `uv_fs_*` wrappers)

Public API:
- `Base.Filesystem.open(path, flags, mode=0) -> Base.Filesystem.File`
- Implements `IO` methods (`read`, `write`, `close`, `truncate`, etc) using libuv fs wrappers.

Implementation:
- Defined in `~/julia/base/filesystem.jl` (module `Filesystem`).
- Uses `ccall(:uv_fs_open, ...)` for `Filesystem.open`.
- Uses `ccall(:jl_fs_read, ...)`, `ccall(:jl_fs_write, ...)`, `ccall(:jl_fs_close, ...)` for ops on `File`.
  - Wrappers are in `~/julia/src/jl_uv.c`, and call `uv_fs_*`.

Takeaway:
- Base contains a second "file handle IO type" which is explicitly libuv-based.

#### 3. Constants for open flags and permission bits (Base.Filesystem)

`~/julia/base/filesystem.jl` defines and exports:
- `JL_O_*` open flags (documented as corresponding to libuv's file-open constants)
- `S_IF*` and `S_I*` mode bits (POSIX-style)

Takeaway:
- For one-to-one parity, `Reseau.Files` should provide compatible constants (implemented without libuv).

### B. Base filesystem operations (mostly libuv)

The majority of "filesystem operations" in Base (directory ops, metadata, path resolution, etc) are implemented with libuv:

Primary sources:
- `~/julia/base/filesystem.jl` includes:
  - `~/julia/base/path.jl`
  - `~/julia/base/stat.jl`
  - `~/julia/base/file.jl`

These implement and export:
- `pwd`, `cd`, `mkdir`, `mkpath`, `rm`, `unlink`, `rename`, `cp`, `cptree`, `mv`
- `readdir`, `walkdir`
- `tempdir`, `tempname`, `mktemp`, `mktempdir`
- `readlink`, `symlink`, `hardlink`, `realpath`, `samefile`
- `chmod`, `chown`, `touch`, `futime`, `diskstat` (statfs)
- `stat`, `lstat`, `fstat` and convenience predicates `isfile`, `isdir`, `islink`, `ispath`, etc
- permission helpers derived from `mode`: `operm`, `gperm`, `uperm`

Where libuv shows up:
- `~/julia/base/file.jl` calls `uv_cwd`, `uv_chdir`, and many `uv_fs_*` functions (`uv_fs_mkdir`, `uv_fs_rmdir`, `uv_fs_scandir`, `uv_fs_readlink`, `uv_fs_statfs`, `uv_os_tmpdir`, etc).
- `~/julia/base/stat.jl` uses `ccall(:jl_stat, ...)` / `jl_lstat` / `jl_fstat` which are implemented in `~/julia/src/sys.c` by calling `uv_fs_stat` / `uv_fs_lstat` / `uv_fs_fstat`.
- `~/julia/base/path.jl` uses libuv for OS helpers like `uv_os_homedir` and `uv_fs_realpath`.

Takeaway:
- Base filesystem operations are intentionally centralized around libuv.

### C. `FileWatching` stdlib (libuv-heavy)

Public surface (`~/julia/stdlib/FileWatching/src/FileWatching.jl`):
- One-shot API:
  - `watch_file(path)` / `watch_folder(path)` / `unwatch_folder(...)`
  - `poll_file(path, interval)` (stat-based)
  - `poll_fd(fd, readable|writable; timeout)`
- Continuous API:
  - `FileMonitor`, `FolderMonitor`, `PollingFileWatcher`, `FDWatcher`
- pidfile helpers:
  - `mkpidlock`, `trymkpidlock`

Implementation:
- All watchers are built on libuv handles and the Base libuv event loop:
  - `uv_fs_event_init/start` for file/folder events
  - `uv_fs_poll_*` + `uv_fs_stat` (async callback form) for polling watcher
  - `uv_poll_*` for file descriptor polling
  - `Timer(...)` for periodic scheduling (which itself is `uv_timer_*` under the hood)

Takeaway:
- Replacing `FileWatching` without libuv requires reimplementing watcher machinery plus a timer/scheduler that does not rely on `Timer`/`sleep`.

### D. `Mmap` stdlib (OS syscalls; not libuv)

`~/julia/stdlib/Mmap/src/Mmap.jl`:
- POSIX: uses `ccall(:jl_mmap, ...)` which calls `mmap` (see `~/julia/src/sys.c`).
- Windows: uses `CreateFileMappingW` / `MapViewOfFile`.

Takeaway:
- Julia already has precedent for cross-platform file IO features implemented without libuv.

---

## 2) Inventory: libuv FS + Watching Surface (what Julia uses today)

### A. libuv FS surface (uv.h)

See `~/libuv/include/uv.h`:
- `uv_fs_*`: open/close/read/write, copyfile, mkdir/rmdir, scandir/opendir/readdir/closedir,
  stat/lstat/fstat, rename, fsync/fdatasync, ftruncate, sendfile, access,
  chmod/chown, utime/futime/lutime, link/symlink/readlink/realpath, statfs, mkstemp/mkdtemp, etc.
- `uv_fs_event_*`: filesystem change notifications
- `uv_fs_poll_*`: stat-based polling watcher
- `uv_poll_*`: fd readability/writability watcher

### B. libuv async model for fs ops (threadpool)

See `~/libuv/src/unix/fs.c`:
- Each `uv_fs_*` request can run:
  - synchronously (if `cb == NULL`): call `uv__fs_work(...)` inline and return `req->result`.
  - asynchronously (if `cb != NULL`): submit to the libuv threadpool via `uv__work_submit`, then invoke `uv__fs_done` on the libuv loop thread.

Why this matters for Reseau:
- "Non-blocking" fs in libuv is largely "blocking syscalls on worker threads + completion on the event loop".
- For regular disk files on POSIX, readiness-based nonblocking IO is not portable; a threadpool backend is the baseline portable design.

### C. File watching in libuv

High-level:
- Linux: inotify-based
- macOS: FSEvents and/or kqueue-based, depending on the watcher type
- BSD: kqueue-based
- Windows: ReadDirectoryChangesW-based

Takeaway:
- A Reseau replacement should plan for OS-specific watcher backends plus a polling fallback.

---

## 3) Inventory: What Reseau Already Has

### A. Current synchronous file utilities (Reseau)

Key files:
- `src/common/file.jl`
  - `byte_buf_init_from_file` uses `fopen` + `fread` into `Reseau.ByteBuffer` (grows as needed).
  - home dir and temp dir are env-var based (`HOME`, `TMPDIR`, `TEMP`, etc).
  - `fs_open_write`, `fs_open_append`, `fs_write(::FILE, ...)`, `fs_flush(::FILE)`.
  - `fs_isdir` uses `opendir`/`closedir` (POSIX) or `GetFileAttributesW` (Windows).
- `src/io/stream.jl`
  - `FileInputStream <: AbstractInputStream` (sync) using `fopen`/`fread`.
  - seek/tell use `fseeko`/`ftello` on POSIX and `fseek`/`ftell` on Windows for CRT compatibility.

Constraints already discovered:
- Windows CRT mixing hazard: `src/common/file.jl` explicitly avoids some CRT calls on `FILE*` due to potential crashes when mixing CRTs.
  - This strongly suggests Win32 HANDLE-based file IO for `Reseau.Files` v1.

### B. Event loop integration primitives (Reseau)

Reseau provides:
- Cross-platform event loops (`src/io/epoll_event_loop.jl`, `src/io/kqueue_event_loop.jl`, `src/io/iocp_event_loop.jl`) with:
  - `event_loop_schedule_task_now!` and `event_loop_schedule_task_future!` (libuv-free timers via the Reseau scheduler).
  - `event_loop_subscribe_to_io_events!` for fd readability/writability on Linux/macOS/BSD.
  - IOCP completion processing on Windows for overlapped IO (`src/io/iocp_event_loop.jl` `IocpOverlapped`).
- A `Future{T}` abstraction (`src/io/future.jl`) and helpers to schedule future callbacks onto an event loop.
- `AsyncInputStream` abstraction (`src/io/async_stream.jl`) which is a natural integration point for async file reads.
- (Historical) Reseau previously had BufferIO-backed channel adapters; those were removed in favor of implementing blocking `IO` facades directly where needed (e.g. `Reseau.Sockets.TCPSocket`).

### C. AWS CRT reference implementations (semantic references)

Key sources:
- `~/aws-c-common/include/aws/common/file.h` (+ `source/*/file.c`)
  - directory traverse/iterator, path exists, home directory, file delete/move, file length, reading from offset (including direct IO on Linux), path separator normalization, etc.
- `~/aws-c-io/source/stream.c`:
  - file-based `aws_input_stream` exists (sync), no general async filesystem.

Takeaway:
- We can treat aws-c-common as a portable behavior reference when Base semantics are ambiguous.

---

## PRD: `Reseau.Files`

### Problem Statement

We want a filesystem + file IO + file watching stack that:
- does not depend on libuv filesystem and watcher APIs,
- integrates with the Reseau event loop and scheduling model, and
- offers Base-like ergonomics and semantics (one-to-one where feasible).

### Goals

1. API coverage
   - Provide Base-equivalent filesystem operations and file IO operations in `Reseau.Files`.
   - Provide `FileWatching`-equivalent APIs integrated with Reseau.
2. Async-first, event-loop integrated
   - Provide non-blocking primitives: async variants return `Future{T}` and execute on a worker backend (threadpool or platform async).
   - Never block the Reseau event-loop thread on disk IO.
3. Cross-platform
   - Linux/macOS/Windows support in CI from day one (some features may start as fallbacks).
4. Interop
   - Reseau `ByteBuffer` as the primary byte container.
   - `Files.FileHandle <: IO` as the primary IO surface (no `BufferIO` dependency).

### Non-goals (for the initial implementation)

- Replacing Julia's task scheduler or `wait()` semantics (which may still drive libuv internally).
- Reproducing Base's exact `IOStream` C buffering internals byte-for-byte.
- Implementing "true async disk IO" on all platforms in v1; we will design for it but start with the portable backend.

---

## Module Structure

Proposed layout (names are illustrative):

- `Reseau.Files`
  - `Files.open`, `Files.read`, `Files.write`, `Files.close`, `Files.seek`, `Files.truncate`, ...
  - constants for parity: `JL_O_*`, `S_IF*`, `S_I*` (mode bits)
  - `Files.stat`, `Files.lstat`, `Files.fstat`, and predicate helpers (`isfile`, `isdir`, ...).
  - `Files.readdir`, `Files.walkdir`, `Files.mkdir`, `Files.mkpath`, `Files.rm`, `Files.cp`, `Files.mv`, ...
  - `Files.tempdir`, `Files.tempname`, `Files.mktemp`, `Files.mktempdir`, `Files.homedir`, `Files.pwd`, `Files.cd`, ...
  - `Files.Locking` (v1 extensions):
    - `mkpidlock`, `trymkpidlock`
    - file locks (`flock`/`LockFileEx`-style)
    - `atomic_write` helpers
  - `Files.Watching`:
    - `watch_file`, `watch_folder`, `unwatch_folder`, `poll_file`, `poll_fd`
    - `FileMonitor`, `FolderMonitor`, `PollingFileWatcher`, `FDWatcher`
  - `Files.Async`
    - async counterparts (`open_async`, `read_async`, `write_async`, `stat_async`, ...)
  - `Files.Backend`
    - worker pool + platform-specific optimized implementations

---

## API Spec (Synchronous + Async)

### A. Types

1. `Files.FileHandle <: IO` (unbuffered, minimal allocation)
   - Holds OS handle:
     - POSIX: `RawFD`
     - Windows: `HANDLE` (`Ptr{Cvoid}`)
   - Implements:
     - `Base.close`, `Base.isopen`
     - `Base.unsafe_read`, `Base.unsafe_write`
     - `Base.position`/`Base.seek` (if supported), `Base.truncate`
2. `Files.AsyncFile`
   - Associates a `FileHandle` with:
     - `event_loop::Reseau.EventLoop`
     - `backend` (threadpool or platform-native)
     - per-handle queue/serialization state (see below)
3. `Files.StatStruct`
   - Mirrors Base's public `StatStruct` fields (size, mode, mtime, ctime, etc) as closely as practical.
4. Watcher types (mirroring `FileWatching`):
   - `Files.FileMonitor`, `Files.FolderMonitor`, `Files.PollingFileWatcher`, `Files.FDWatcher`
   - `Files.FileEvent`, `Files.FDEvent`
5. Locking types:
   - `Files.PidLock`
   - `Files.FileLock`

### B. Synchronous API: one-to-one with Base (namespaced)

Intent: every Base function in "filesystem + file IO" has a `Reseau.Files.<name>` equivalent, with the same signature when possible.

Baseline list (from `~/julia/base/file.jl` + `~/julia/base/stat.jl` + `~/julia/base/iostream.jl` + `FileWatching`):
- File IO:
  - `open`, `close`, `closewrite`, `flush`, `read`, `read!`, `readbytes!`, `write`, `seek`, `seekend`, `seekstart`, `skip`, `position`, `truncate`, `eof`, `fd`
- Metadata/stat:
  - `stat`, `lstat`, `fstat`, `filesize`, `filemode`, `mtime`, `ctime`
  - permissions: `operm`, `gperm`, `uperm`
  - predicates: `ispath`, `isfile`, `isdir`, `islink`, `ismount`, `issetuid`, `issetgid`, `issticky`, `isfifo`, `issocket`, `isblockdev`, `ischardev`
- Filesystem operations:
  - `pwd`, `cd`, `mkdir`, `mkpath`, `rm`, `unlink`, `rename`, `mv`, `cp`, `cptree`, `sendfile`
  - `hardlink`, `symlink`, `readlink`, `realpath`, `samefile`
  - `readdir`, `walkdir`
  - `tempdir`, `tempname`, `mktemp`, `mktempdir`, `touch`
  - `chmod`, `chown`, `futime`, `diskstat`
- File watching:
  - `watch_file`, `watch_folder`, `unwatch_folder`, `poll_file`, `poll_fd`
- pidfile locks:
  - `mkpidlock`, `trymkpidlock`
- file locking + atomic writes (v1 extensions):
  - `lock_file`, `unlock_file`, `with_file_lock`
  - `atomic_write`
- Constants (Base.Filesystem parity; v1):
  - `JL_O_*` (open flags), `S_IF*` and `S_I*` (mode bits)

### C. Async API: event-loop integrated

Key design: async operations return `Future{T}` and never block the event-loop thread.

Proposed surface (examples):
- `Files.open_async(event_loop, path; read/write/create/truncate/append, buffered=false) -> Future{AsyncFile}`
- `Files.read_async(file::AsyncFile, dest::ByteBuffer; nbytes, offset=nothing) -> Future{Int}`
- `Files.write_async(file::AsyncFile, src; offset=nothing) -> Future{Int}`
- `Files.stat_async(event_loop, path) -> Future{Files.StatStruct}`
- `Files.readdir_async(event_loop, path) -> Future{Vector{String}}`
- `Files.cp_async(event_loop, src, dst; force=false, follow_symlinks=false, preserve=true) -> Future{Nothing}`

Integration points:
- Provide `Files.async_input_stream(file::AsyncFile; chunk_size=...) -> AsyncInputStream`
  - This makes async file reads pluggable into existing Reseau streaming APIs.

---

## Architecture

### A. Backend model

We need a backend abstraction because:
- POSIX async filesystem is not generally event-driven.
- Windows has a first-class async story via IOCP + overlapped IO (and Reseau already has IOCP plumbing).

Proposed backend interface:
- `AbstractFilesBackend`
  - `submit(job)::Nothing` where job contains:
    - operation (open/read/write/stat/readdir/...)
    - inputs (path/fd/buffers)
    - completion `Future`
    - `event_loop` for scheduling completions
    - cancellation token (best-effort)

Backends:
1. `ThreadPoolBackend` (default cross-platform)
   - A bounded worker pool (N threads) that executes blocking syscalls.
   - Completion is scheduled onto `event_loop` via `event_loop_schedule_task_now!`.
   - Mirrors libuv's fs model (see `~/libuv/src/unix/fs.c`).
2. `WindowsIocpBackend` (high value)
   - Use overlapped IO for file reads/writes and directory watching.
   - Use existing `IocpOverlapped` to deliver completion on the IOCP event loop thread.
3. `LinuxIoUringBackend` (future)
   - Integrate io_uring for true async disk IO; keep threadpool fallback.

### B. Operation serialization and seek semantics

Disk file IO has implicit state (the file pointer) unless using pread/pwrite style operations.

Semantics for async usage:
- Default: serialize operations per file handle (a queue) to mimic `IOStream` and avoid races.
- Allow advanced usage:
  - `read_async(...; offset=...)` and `write_async(...; offset=...)` which use `pread/pwrite` (POSIX) or overlapped offsets (Windows) and therefore can be concurrent without affecting the shared pointer.
- `seek` in async context:
  - either serialize `seek` as an operation in the per-handle queue, or
  - disallow `seek` on `AsyncFile` unless `serialize=true` is explicitly enabled.

### C. Cancellation + timeouts

Cancellation semantics:
- Threadpool backend:
  - can cancel jobs that have not started,
  - cannot reliably interrupt an in-flight blocking syscall; best-effort only.
- Windows IOCP backend:
  - can use `CancelIoEx` to attempt cancellation of in-flight overlapped IO.

Timeouts:
- Implement timeouts by scheduling a deadline task on the event loop.
- If the deadline fires first, fail/cancel the Future and discard late completions safely.

### D. Buffering

We should expose file IO in forms that match how Reseau code already handles bytes:
- Primary buffer type: `Reseau.ByteBuffer`.
- Also accept/return `Vector{UInt8}` and `AbstractVector{UInt8}` where appropriate.

Implementation decision:
- `Files.FileHandle` implements the core `IO` methods directly (`unsafe_read`, `unsafe_write`, `seek`, `truncate`, etc).
- Higher-level helpers (`read`, `read!`, `write(::AbstractString)`, etc) come from Base's generic IO methods.
- If we later need buffered behavior for performance, prefer an explicit `BufferedFile <: IO` wrapper layered on `FileHandle`, rather than trying to clone `Base.IOStream`.

### E. Error model

Decision (v1):
- `Reseau.Files` is exception-first. Public APIs throw `IOError` / `SystemError` / `ArgumentError` like Base.
- Internal helpers may use `ErrorResult` when it materially reduces overhead, but these are not the primary surface.

---

## File Watching Design (Reseau replacement for FileWatching)

We want near-parity with `FileWatching`:
- efficient watch for small number of paths (`watch_file`)
- efficient directory watch for large number of files (`watch_folder`)
- polling fallback (`poll_file`)
- fd watcher (`poll_fd`)

### A. Linux (inotify)

Backend:
- Create inotify fd (`inotify_init1(IN_NONBLOCK|IN_CLOEXEC)`).
- `event_loop_subscribe_to_io_events!(..., IoEventType.READABLE, ...)` on the inotify fd.
- Read and parse `inotify_event` records into:
  - `Files.FileEvent(renamed/changed/timedout)`
  - for folders: emit `(relative_name => FileEvent)` into a queue/channel.

Notes:
- Handle overflow (`IN_Q_OVERFLOW`) and coalescing semantics.
- Provide `recursive=true` by managing child watches, or clearly document limitations.

### B. macOS/BSD (kqueue vnode) without modifying the Reseau kqueue backend

Constraint:
- Reseau's main kqueue loop is wired for `EVFILT_READ/WRITE` subscriptions only.

Proposed approach:
- Create a dedicated kqueue fd for filesystem vnode events.
- Register that kqueue fd for readability on the Reseau event loop (`EVFILT_READ` on the kqueue fd itself).
  - kqueue fds become readable when events are queued.
- When readable:
  - call `kevent(kq_fs, NULL, 0, events, ...)` to drain vnode events
  - translate NOTE_* flags (NOTE_WRITE, NOTE_RENAME, NOTE_DELETE, etc) into `Files.FileEvent`.

Tradeoffs:
- Requires one open fd per watched path (typical for vnode watchers).
- Semantics differ from FSEvents (more fd-oriented, less path-oriented).

### C. Windows (ReadDirectoryChangesW + IOCP)

Best path (production):
- Watch directories (not individual files) with `ReadDirectoryChangesW`.
- Associate directory handle with the Reseau IOCP event loop:
  - `event_loop_connect_to_io_completion_port!(event_loop, IoHandle(handle=dir_handle))`
- Issue overlapped `ReadDirectoryChangesW` calls using `IocpOverlapped`.
- On completion:
  - parse `FILE_NOTIFY_INFORMATION` entries
  - map rename/change events into `Files.FileEvent` and emit to consumers
  - re-arm the watch immediately

Fallback path:
- Polling watcher based on stat + event-loop scheduling when privileges/APIs are unavailable.

---

## Pidfile Locks, File Locking, and Atomic Writes (v1 extensions)

These features are in-scope for v1 even though Base does not have a single unified cross-platform "file locking" API.

### A. Pidfile locks (`mkpidlock`, `trymkpidlock`)

Mirror `FileWatching` stdlib pidfile helpers at a minimum:
- `mkpidlock(path; ...)` create/open a pidfile and hold an exclusive lock until released.
- `trymkpidlock(path; ...)` non-throwing variant that fails if already locked.

Implementation strategy:
- Use file locking primitives below as the underlying mechanism.
- Write the current PID to the pidfile and validate stale locks similarly to stdlib semantics.

### B. File locks (cross-platform surface)

Provide an explicit, minimal lock API:
- `lock_file(path; shared=false, blocking=true)` -> lock token/handle
- `unlock_file(lock)` -> `nothing`
- `with_file_lock(f, path; ...)` helper

Backend mapping:
- POSIX: `flock(2)` where available, otherwise `fcntl(F_SETLK/F_SETLKW)`.
- Windows: `LockFileEx` / `UnlockFileEx`.

Semantics notes:
- Document advisory-vs-mandatory behavior and limitations per OS.
- Define what is guaranteed for intra-process vs inter-process behavior.

### C. Atomic write helpers

Provide a first-class helper:
- `atomic_write(path, data; mode=nothing, tmpdir=nothing, fsync=false, fsync_dir=false, replace=true)`

Core algorithm:
1. Create temp file in same directory (default; required for atomic rename semantics).
2. Write data (and metadata if requested).
3. Optionally `fsync` the temp file.
4. Rename temp -> destination (atomic on POSIX when same filesystem; Windows uses `MoveFileExW` flags).
5. Optionally `fsync` the parent directory (platform-dependent).

Failure handling:
- Best-effort cleanup of temp file.
- Never leave partially-written destination if atomicity preconditions are met.

---

## Platform Semantics and Compatibility Notes

### A. Path encoding and normalization

Windows:
- Must support Unicode paths and long paths.
- Prefer Win32 wide-char APIs (`CreateFileW`, `GetFileAttributesExW`, etc) over CRT `fopen`.
- Provide a single internal UTF-8 -> UTF-16 conversion helper without calling libuv.

POSIX:
- Treat paths as opaque byte strings; operate on `String` assuming UTF-8.

### B. Implementation Map (No libuv)

Concrete "how we do it without libuv" mapping:

| Feature | POSIX (Linux/macOS/BSD) | Windows | Notes |
| --- | --- | --- | --- |
| Open/close | `open(2)` / `close(2)` | `CreateFileW` / `CloseHandle` | Core handle type. |
| Read/write (sequential) | `read(2)` / `write(2)` | `ReadFile` / `WriteFile` | On Windows, allow both sync and overlapped. |
| Read/write (offset) | `pread(2)` / `pwrite(2)` | `ReadFile`/`WriteFile` with `OVERLAPPED.Offset*` | Enables concurrency without shared file pointer races. |
| Seek/position | `lseek(2)` | `SetFilePointerEx` | For async, prefer offset-based IO instead of seek. |
| Truncate | `ftruncate(2)` | `SetEndOfFile` (+ `SetFilePointerEx`) | Base semantics: grow fills with `\\0`. |
| Sync | `fsync(2)` / `fdatasync(2)` | `FlushFileBuffers` | macOS durability nuance: consider `F_FULLFSYNC` as libuv does. |
| Stat/lstat/fstat | `stat(2)`/`lstat(2)`/`fstat(2)` | `GetFileAttributesExW` + `GetFileInformationByHandle(Ex)` | Need consistent `mode`/`mtime`/`ctime` mapping. |
| Access checks | `access(2)` | `GetFileAttributesExW` | Match Base behavior for non-existent paths. |
| Mkdir/rmdir | `mkdir(2)` / `rmdir(2)` | `CreateDirectoryW` / `RemoveDirectoryW` | `mkpath` recursion is pure Julia. |
| Unlink/rm | `unlink(2)` | `DeleteFileW` | Recursive `rm` handles directories. |
| Rename | `rename(2)` | `MoveFileExW(MOVEFILE_REPLACE_EXISTING|...)` | Document Windows differences like Base does. |
| Readdir | `opendir`/`readdir`/`closedir` | `FindFirstFileW`/`FindNextFileW` | Return `Vector{String}` like Base. |
| Walkdir | build on `readdir` + `isdir`/`islink` | same | Match Base `topdown`/`follow_symlinks`/`onerror` semantics. |
| Realpath | `realpath(3)` | `GetFinalPathNameByHandleW` (or `GetFullPathNameW` fallback) | Windows `\\\\?\\` prefix handling required. |
| Readlink | `readlink(2)` | (reparse points) | Likely later; may require `DeviceIoControl(FSCTL_GET_REPARSE_POINT)`. |
| Symlink/hardlink | `symlink(2)`/`link(2)` | `CreateSymbolicLinkW` / `CreateHardLinkW` | Symlink requires privileges/dev mode; fallback behavior needed. |
| chmod/chown | `chmod(2)` / `chown(2)` | limited/unsupported | Match Base: `chown` unsupported on Windows; `chmod` best-effort. |
| utime/touch | `utimensat(2)` / `futimens(2)` | `SetFileTime` | Support "touch create" like Base. |
| diskstat/statfs | `statvfs`/`statfs` | `GetDiskFreeSpaceExW` | Expose fields similar to Base `diskstat`. |
| tempdir/tempname | env + `/tmp` fallback | `GetTempPathW` fallback to env | Avoid `uv_os_tmpdir`. |
| homedir | `getpwuid_r` fallback to env | `SHGetKnownFolderPath(FOLDERID_Profile)` fallback to env | Avoid `uv_os_homedir`. |
| File locks | `flock` or `fcntl` | `LockFileEx` | Used by pidlocks and `with_file_lock`. |

Implementation guideline:
- Prefer OS handles/FDs as the truth, and build adapters above it.
- Where Base behavior is unclear, treat Base source + `~/aws-c-common` as the semantic references.

### C. Permissions and file modes

Base exposes POSIX-like mode bits even on Windows, but semantics vary.
`Reseau.Files` should:
- match Base where possible,
- clearly document platform differences (e.g. `chown` unsupported on Windows).

### D. Atomicity and durability

Define explicit APIs for:
- `fsync` / `fdatasync`
- atomic write patterns (write temp + rename) as a first-class v1 feature (with explicit durability knobs).

---

## Testing Strategy

### A. Unit tests (platform-independent)

Create tests for:
- open/read/write/seek/truncate correctness (including EOF, partial reads, small/large buffers)
- metadata (`stat`, `filesize`, `mtime`, `ctime`) and predicates (`isfile`, `isdir`, ...)
- mkdir/mkpath/rm (recursive), rename/mv, copy/cptree
- tempdir/tempname/mktemp/mktempdir behavior
- links (`symlink`, `hardlink`) guarded behind platform capability checks
- pidlocks, file locks, and `atomic_write`

### B. Async tests

Verify:
- async operations do not run on the event-loop thread (assert via `event_loop_thread_is_callers_thread`).
- serialization semantics: ordering of queued operations.
- offset-based IO can run concurrently and preserves correctness.
- timeout/cancellation behavior is consistent and does not leak resources.

### C. File watching tests

Watcher tests are timing-sensitive; plan:
- keep some behind an env var initially,
- have a minimal "smoke watch" test always on if stable:
  - create temp file, start watch, write to file, assert event arrives within bounded time.

### D. CI matrix

Target CI:
- Linux: validate inotify backend.
- macOS: validate kqueue-vnode backend.
- Windows: validate polling watcher backend in v1; IOCP watcher backend in v2.

---

## Phased Delivery Plan

Phase 1: Foundation (sync, no libuv)
- `Files.StatStruct` and `stat/lstat/fstat` implemented via OS calls (no Base `stat`).
- Basic filesystem ops: `mkdir`, `mkpath`, `rm`, `unlink`, `rename`, `readdir`, `walkdir`.
- temp/home/pwd/cd implemented without libuv helpers.
- `FileHandle` with sync read/write/seek/truncate using OS syscalls.

Phase 2: Async core (threadpool backend)
- Implement `ThreadPoolBackend` and async wrappers returning `Future{T}`.
- Add `AsyncFile` + queued operations + offset IO.
- Add `AsyncInputStream` adapter for file reads.

Phase 3: Parity coverage + v1 extensions
- Implement remaining Base-equivalent ops: `chmod/chown/futime/touch`, links, `diskstat`, `samefile`, `sendfile` (fallback copy if not available).
- Implement `cp/cptree` and `mv` with Base-like semantics and options.
- Implement v1 extensions:
  - pidfile locks (`mkpidlock`, `trymkpidlock`)
  - file locking primitives + `with_file_lock`
  - `atomic_write` helpers (with durability options)

Phase 4: File watching
- Linux inotify backend
- macOS/BSD kqueue-vnode backend (dedicated kqueue fd strategy)
- Windows backend:
  - v1: polling fallback for CI stability
  - v2: ReadDirectoryChangesW + IOCP integration

Phase 5: Optimized backends (optional)
- Windows IOCP file reads/writes (true async)
- Linux io_uring backend

---

## Risks / Unknowns

- Regular file IO "non-blocking" portability: threadpool is the only universal baseline; true async is platform-specific.
- Cancellation: best-effort only for threadpool backend.
- Windows path handling and long-path quirks: must be handled carefully; likely requires Win32 APIs.
- Watcher semantics differ across platforms; exact Base/FileWatching parity may not be possible in all edge cases.
- Performance: a naive async wrapper can allocate heavily; design buffer ownership and job structs carefully.

---

## Decisions (Locked for v1)

- Exception-first API (Base-like throwing surface).
- Core file type is an OS `FileHandle <: IO` (no separate IOStream reimplementation in v1).
- Windows uses Win32 `HANDLE` APIs (not CRT `FILE*`) for core functionality and async IO.
- v1 scope includes:
  - pidfile locks (`mkpidlock`, `trymkpidlock`)
  - file locking (e.g. `flock` / `LockFileEx` style APIs)
  - atomic write helpers (write temp + rename, with durability options)

---

## Definition of Done (v1)

Implementation is done for v1 when:
- `Reseau.Files` provides the sync API surface listed above, and all tests pass on Linux/macOS/Windows.
- `Reseau.Files.Async` provides async `open/read/write/stat/readdir/rm/mkdir/rename` at minimum, and no async op blocks an event-loop thread.
- `Reseau.Files` provides v1 extensions:
  - pidfile locks (`mkpidlock`, `trymkpidlock`)
  - file locking APIs (cross-platform surface; best-effort semantics documented per OS)
  - atomic write helpers (write temp + rename; optional `fsync`/durability knobs)
- `Reseau.Files` file-watching has:
  - Linux: inotify backend working in CI
  - macOS: kqueue-vnode backend working in CI
  - Windows: polling backend working in CI (IOCP watcher backend can be v2, but must be planned)
- Explicit "no libuv" invariants for the implementation:
  - No calls to Base `stat`, `tempdir`, `homedir`, `realpath`, or any `FileWatching` API from `Reseau.Files` implementation code.
  - No reliance on Base `Timer`/`sleep` for polling watchers (use `event_loop_schedule_task_future!`).
