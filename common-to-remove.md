# `src/common/` Removal Checklist (Base/Stdlib Parity Plan)

Goal: delete as much of `Reseau/src/common/` as possible by replacing functionality with Julia Base/stdlib, while keeping ~95% of current downstream behavior across:
- Reseau
- AwsHTTP
- HTTP

Constraint: Logging stays on the existing `logf` + `LoggerPipeline` stack, but timestamp formatting should no longer depend on `src/common/time.jl` or `src/common/date_time.jl` (use `Dates` instead).

Implementation approach: tackle items in order, keep tests green after each item.

---

## Action Items (Do In This Order)

### 1) Logging Timestamp Stack (Dates)
- [x] Replace `src/common/log_formatter.jl` timestamp generation with `Dates` (UTC).
- [x] Remove `include("common/time.jl")` and `include("common/date_time.jl")` from `src/Reseau.jl`.
- [x] Delete `src/common/time.jl` and `src/common/date_time.jl`.
- [x] Remove/update `test/common_tests.jl` date-time parsing tests (they only existed to validate `date_time.jl`).
- [x] Run Reseau tests.

Notes:
- Base/stdlib reference: `Dates.now(Dates.UTC)` + `Dates.format`.
- Keep log output shape: `[LEVEL] [timestamp] [thread] [subject] - message`.

### 2) UUID + Device RNG (UUIDs/Random)
- [x] Replace internal UUID usage (socket/pipe naming, TLS keychain labels) with `UUIDs.uuid4()` and `string(uuid4())`.
- [x] Delete `src/common/uuid.jl` and `src/common/device_random.jl`.
- [x] Remove/update UUID tests in `test/common_tests.jl`.
- [x] Run Reseau tests.

Notes:
- Stdlib reference: `UUIDs` for UUIDs; `Random` (if we need random bytes, but likely we won’t once uuid code is gone).

### 3) Encoding Helpers (Remove `encoding.jl`)
- [x] Replace `text_is_utf8(...)` call sites in TLS handlers with a tiny local helper:
  - accept UTF-8 BOM prefix, else require ASCII (`all(<(0x80), bytes)`).
- [x] Delete `src/common/encoding.jl`.
- [x] Run Reseau tests (TLS tests are optional locally unless enabled, but at least compile passes).

### 4) File I/O Helpers (Remove `file.jl`)
- [x] Replace uses of `byte_buf_init_from_file(...)` in Reseau with Base `read(path)` + `ByteBuffer` population (or direct `Vector{UInt8}` usage).
- [x] Delete `src/common/file.jl`.
- [x] Update Reseau tests that touched `get_home_directory/get_temp_directory/tempname/fs_*`.
- [x] Update `HTTP/src/download.jl` to use Base:
  - `tempdir()`, `tempname()`, `isdir`, `open`, `write`
- [x] Run Reseau tests + HTTP tests.

### 5) Remove `ByteString` (`string.jl`)
- [x] Delete `src/common/string.jl` (it is only used by `file.jl` and dead code).
- [x] Run Reseau tests (should be mostly a compile check after #4).

### 6) Replace `SmallRegistry` (`registry.jl`) With `Dict`
- [x] Replace `_log_subject_registry::SmallRegistry` with a `Dict{LogSubject, LogSubjectInfo}` (and a lock if needed).
- [x] Update `src/common/logging.jl`, `src/sockets/io/io.jl`, and `src/common/common.jl` call sites (`registry_get!/registry_set!` etc).
- [x] Delete `src/common/registry.jl`.
- [x] Run Reseau tests + AwsHTTP tests (AwsHTTP asserts log subject ranges).

### 7) System Info Helpers (`system_info.jl`)
- [x] Replace `get_cpu_count_for_group/get_cpu_ids_for_group` with direct `Sys.CPU_THREADS` logic in the few call sites.
- [x] Delete `src/common/system_info.jl`.
- [x] Run Reseau tests.

### 8) Common Init/Registration (`common.jl`)
- [x] Re-home common error definitions registration to `src/common/error.jl` (or a new core/init file).
- [x] Re-home common log subject registration to logging init (or `src/sockets/io/io.jl`).
- [x] Remove `_common_init/_common_cleanup` indirection by calling thread-management init/cleanup directly from `src/sockets/io/io.jl`.
- [x] Delete `src/common/common.jl`.
- [x] Run Reseau tests + AwsHTTP + HTTP tests.

### 9) Shrink `platform.jl` (Optional, After Deletions)
- [x] Remove pthread init/size constants that are only used by `src/common/unused/*` (not included).
- [x] Keep: `_PLATFORM_*`, `_IS_LITTLE_ENDIAN`, `_CLOCK_*` (if still needed), `_fcntl`.

### 10) Re-home Remaining “Common” Code (Optional)
If we still have a `src/common/` directory at the end, move the remaining kept pieces into more specific locations (e.g. `src/core/`), then update `src/Reseau.jl` includes.

---

## Test Commands

Reseau (recommended):
```sh
cd "$(git rev-parse --show-toplevel)"
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```

AwsHTTP:
```sh
cd /Users/jacob.quinn/.julia/dev/AwsHTTP
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```

HTTP:
```sh
cd /Users/jacob.quinn/.julia/dev/HTTP
JULIA_NUM_THREADS=1 julia --project=. --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); Pkg.test(; coverage=false)'
```
