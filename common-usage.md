# Reseau `src/common/` Inventory & Usage Report

## 1. DEAD FILES — Not Included in Module (17 files)

These exist on disk but are **never `include()`d** in `Reseau.jl`. Safe to delete entirely.

| File | What it defines |
|------|----------------|
| `cbor.jl` | CBOR encode/decode |
| `command_line_parser.jl` | CLI argument parsing |
| `cpuid.jl` | CPU feature detection |
| `cross_process_lock.jl` | Cross-process file locking |
| `environment.jl` | Environment variable get/set |
| `fifo_cache.jl` | FIFOCache (FIFO eviction) |
| `host_utils.jl` | Hostname/IP utilities |
| `json.jl` | JSON parser |
| `lifo_cache.jl` | LIFOCache (LIFO eviction) |
| `linked_hash_table.jl` | Ordered hash table |
| `posix_common.jl` | POSIX errno utilities |
| `process.jl` | Process management |
| `ring_buffer.jl` | Ring buffer |
| `rw_lock.jl` | Read-write lock |
| `system_resource_util.jl` | System resource checking |
| `uri.jl` | URI parsing |
| `xml_parser.jl` | XML parser |

## 2. INCLUDED BUT UNUSED ANYWHERE (9 files)

These are included in `Reseau.jl` but their symbols are not referenced by any `src/io/`, AwsHTTP, or HTTP code:

| File | What it defines | Notes |
|------|----------------|-------|
| `thread_scheduler.jl` | `ThreadScheduler` (task-loop-on-a-Julia-Task) | Never instantiated anywhere |
| `mutex.jl` | `Mutex` wrapper around `ReentrantLock` | `src/io/` uses `ReentrantLock` directly |
| `date_time.jl` | Date/time parsing & formatting | Completely unused |
| `device_random.jl` | Cryptographic random bytes | Completely unused |
| `file.jl` | File I/O utilities | Completely unused |
| `log_channel.jl` | Log channel abstraction | Unused — logging goes through `logf()` |
| `log_formatter.jl` | Log formatting functions | Unused |
| `log_writer.jl` | Log writer abstraction | Unused |
| `math.jl` | `round_up`, `is_power_of_two`, etc. | Unused |

## 3. INCLUDED AND ACTIVELY USED — By Tier

### Tier 1: Foundational (used by virtually every file)

| File | Key Symbols | src/io/ | AwsHTTP | HTTP |
|------|------------|---------|---------|------|
| **`error.jl`** | `ErrorResult`, `raise_error`, `last_error`, `OP_SUCCESS/ERR`, all `ERROR_*` | All files | 5 files | via Reseau constants |
| **`logging_types.jl`** | `LogLevel`, `LogSubject`, `LogSubjectInfo` | All files | 5 files | 1 file |
| **`logging.jl`** | `logf`, `set_log_level!`, `logger_get` | 8+ files | 4 files | 1 file |
| **`assert.jl`** | `@aws_assert`, `@aws_precondition`, `fatal_assert` | 8 files | — | — |
| **`common.jl`** | `_common_init/_cleanup`, error/log registration | `io.jl` init path | — | — |

### Tier 2: Core Data Structures (heavily used)

| File | Key Symbols | src/io/ consumers | AwsHTTP | HTTP |
|------|------------|------------------|---------|------|
| **`linked_list.jl`** | **`Deque`** (the deque impl), `linked_list_*` compat API | **9 files** — all event loops, channel, tls, pipe, host_resolver, apple_nw_socket | — | — |
| **`byte_buf.jl`** | `ByteBuffer`, `byte_buffer_as_string/vector` | **18 files** — most widespread type | 4 files | 2 files |
| **`hash_table.jl`** | `HashTable`, `hash_table_put!/get/remove!` | event_loop, host_resolver, apple_nw_socket, pkcs11, pem | — | — |
| **`array_list.jl`** | `ArrayList`, `push_back!`, `erase!` | event_loop (ELG), message_pool | — | `push_back!` in HTTP |
| **`task_scheduler.jl`** | `TaskScheduler`, `ScheduledTask`, scheduling fns | All event loops, channel, host_resolver | 2 files (h1/h2_connection) | — |
| **`priority_queue.jl`** | `PriorityQueue` | **Indirectly via TaskScheduler** (its `timed` field) | — | — |
| **`string.jl`** | `ByteCursor`, string view utilities | 13 files | — | — |

### Tier 3: Threading & Synchronization

| File | Key Symbols | src/io/ consumers |
|------|------------|------------------|
| **`thread.jl`** | `ThreadHandle`, `ThreadOptions`, `_spawn_os_thread`, `thread_launch` | All event loops (5), channel |
| **`thread_shared.jl`** | `thread_join_all_managed`, managed thread counting | Via `common.jl` init |
| **`condition_variable.jl`** | `ConditionVariable`, `condition_variable_wait_*` | host_resolver, dispatch_queue_event_loop |

### Tier 4: Targeted Utilities

| File | Key Symbols | src/io/ consumers | Notes |
|------|------------|------------------|-------|
| **`clock.jl`** | `sys_clock_get_ticks`, `high_res_clock_get_ticks` | 12 files | Timing for all event loops |
| **`time.jl`** | Time conversion constants (`TIMESTAMP_NANOS` etc.) | Via clock/scheduler | |
| **`shutdown_types.jl`** | `ShutdownCallbackOptions` | event_loop, retry_strategy | |
| **`platform.jl`** | `_PLATFORM_*` constants | Thread, event loop conditionals | |
| **`macros.jl`** | Utility macros | Used by other common files | |
| **`registry.jl`** | `SmallRegistry` | kqueue, tls, apple_nw_socket, io.jl | |
| **`statistics.jl`** | `CQPStatCategory`, stat tracking | tls, channel, socket_channel_handler, io.jl | |
| **`zero.jl`** | `iszero` overrides | kqueue, posix_socket, socket, pkcs11, shared_library | |
| **`encoding.jl`** | `base64_encode/decode`, `hex_encode/decode` | pem.jl only | AwsHTTP uses Julia's `Base64` instead |
| **`uuid.jl`** | `UUID`, `uuid_init`, `uuid_to_str` | dispatch_queue, tls, socket | |
| **`system_info.jl`** | `get_cpu_count_for_group` | event_loop.jl only | |
| **`byte_order.jl`** | `hton`/`ntoh` wrappers | posix_socket, apple_nw_socket | |
| **`cache.jl`** | `AbstractCache` base type | Defines interface for LRUCache | |
| **`lru_cache.jl`** | `LRUCache` | host_resolver.jl only | |

## 4. AwsHTTP's Common Dependency Surface (via Reseau)

AwsHTTP uses Reseau's **io-layer types** which internally use common types. The common symbols it touches directly:
- **Error codes**: `OP_SUCCESS`, `OP_ERR`, `ErrorResult`, `raise_error()`, `last_error()`, `ERROR_INVALID_*`
- **Logging**: `logf()`, `LogLevel.*`, `LogSubject`
- **ByteBuffer**: `byte_buffer_as_string()`, `byte_buffer_as_vector()`
- **Scheduling**: `ScheduledTask`, `TaskStatus.RUN_READY`, `ChannelTask`
- **Channel handler interface**: `AbstractChannelHandler`, 8 handler callback methods

## 5. HTTP.jl's Dependency Surface

HTTP.jl references Reseau in **9 source files** (heaviest: server.jl=99 refs, client.jl=65). Uses:
- Types: `ArrayList`, `Channel`, `ChannelSlot`, `IoMessage`, `ErrorResult`, `LogLevel`
- Functions: `push_back!`, `channel_*` operations, `byte_buffer_as_*`, bootstrap constructors
- Constants: `OP_SUCCESS`, `ERROR_IO_*` error codes

## 6. Summary Counts

| Category | Count |
|----------|-------|
| Dead files (not included) | **17** |
| Included but entirely unused | **9** |
| Included and actively used | **28** |
| **Total files in src/common/** | **54** |

**~48% of `src/common/` files are dead or unused.**
