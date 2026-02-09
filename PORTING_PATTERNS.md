# Porting C Interface Patterns to Julia (Runtime Style Guide)

This document is a prescriptive guide: it describes how we translate aws-c-common C patterns into Julia, with
zero-copy and explicit ownership preserved where possible. Each section includes a concrete recipe and examples.

## Global Guidelines (Prefer, With Exceptions)
- Prefer concrete field types (often via parametric structs) on hot paths. We still use `Any`/`Function` in some places to
  control specialization/compile-time, especially when storing heterogeneous callbacks.
- Prefer `Memory{T}` for low-level storage and aws-c-* parity types. We still use `Vector`, `Dict`, `IdDict`, etc. where it
  keeps the implementation simpler and the performance impact is negligible.
- Prefer explicit cleanup (C-style lifetime). Finalizers are used sparingly as a safety net in a few places.
- Use EnumX.jl for scoped enums. Enum types are referenced as `MyEnum.T`.
- Use ScopedValues.jl for global or thread-local context.
- Prefer `@atomic` fields and `@atomic` operations. `Threads.Atomic` may still be used for a small number of global counters.
- Errors return Union{T, Nothing} or Union{T, ErrorResult}. No Result type.
- Prefer `logf(...)` and the `@LOGF_*` macros for logging. Julia Logging is used rarely (e.g. for truly fatal internal errors).
- OS-specific code lives in OS-specific modules and dispatches on `abstract type OS end`.
- Channel handlers that store a channel slot should implement `setchannelslot!(handler, slot)`;
  the channel pipeline will call this hook when installing a handler.

## Dependencies
- EnumX.jl
- ScopedValues.jl

## Pattern P1: Vtables -> Abstract Types + Dispatch

### C shape
Vtable struct plus base struct with `vtable*` and `impl*` (logging, log_writer, log_formatter, log_channel,
statistics handler, cache interface).

### Julia porting recipe
- Define `abstract type` for the interface.
- Define required methods that serve as the interface contract.
- Use parametric concrete types and store components with concrete field types.

### Example: Logger pipeline
```julia
using EnumX

@enumx LogLevel::UInt8 begin
    NONE=0; FATAL=1; ERROR=2; WARN=3; INFO=4; DEBUG=5; TRACE=6
end

abstract type AbstractLogger end
abstract type AbstractLogFormatter end
abstract type AbstractLogWriter end
abstract type AbstractLogChannel end

log_level(::AbstractLogger, ::UInt32) = LogLevel.INFO
log!(::AbstractLogger, ::LogLevel.T, ::UInt32, ::AbstractString, args...) = nothing
close!(::AbstractLogger) = nothing

mutable struct LoggerPipeline{F<:AbstractLogFormatter,C<:AbstractLogChannel,W<:AbstractLogWriter} <: AbstractLogger
    formatter::F
    channel::C
    writer::W
    @atomic level::Int
end

function log!(l::LoggerPipeline, level::LogLevel.T, subject::UInt32, fmt::AbstractString, args...)
    level_int = @atomic l.level
    level_int < Int(level) && return nothing
    line = format_line(l.formatter, level, subject, fmt, args...)
    send!(l.channel, l.writer, line)
    return nothing
end
```

### Example: Cache base interface
```julia
abstract type AbstractCache{K,V} end

get!(::AbstractCache{K,V}, key::K, default::V) where {K,V} = default
put!(::AbstractCache{K,V}, key::K, value::V) where {K,V} = nothing
remove!(::AbstractCache{K,V}, key::K) where {K,V} = nothing
```

## Pattern P2: Impl Sub-Vtables -> Subtype Methods

### C shape
Base interface plus an extra impl vtable (LRU cache adds `use_lru` and `get_mru`).

### Julia porting recipe
- Extend the interface via additional methods on the subtype.
- Keep the base interface minimal and let subtypes add capabilities.

### Example: LRU cache capabilities
```julia
abstract type AbstractCache{K,V} end
use_lru!(::AbstractCache) = nothing
mru(::AbstractCache) = nothing

abstract type AbstractLinkedHashTable{K,V} end

struct LRUCache{K,V,T<:AbstractLinkedHashTable{K,V}} <: AbstractCache{K,V}
    table::T
end

use_lru!(c::LRUCache) = lru_pop_and_refresh!(c.table)
mru(c::LRUCache) = lru_mru_value(c.table)
```

## Pattern P3: Callback + user_data -> Callable Fields

### C shape
Function pointer callbacks with `void *user_data` (hash/eq/destroy, comparator, task fn, XML callback,
CLI dispatch, error handler, condition predicate, file traversal).

### Julia porting recipe
- Store callables as parametric fields (no `Function` fields).
- Use callable structs for hot paths to keep dispatch concrete.

### Example: Hash table strategy
```julia
struct HashEq{H,Eq}
    hash::H
    eq::Eq
end

struct HashTable{K,V,HE,OnKeyDestroy,OnValDestroy}
    hash_eq::HE
    on_key_destroy::OnKeyDestroy
    on_val_destroy::OnValDestroy
    slots::Memory{UInt64}
    entries::Memory{Ptr{Cvoid}}
end

hash_key(ht::HashTable, k) = ht.hash_eq.hash(k)
keys_equal(ht::HashTable, a, b) = ht.hash_eq.eq(a, b)
```

### Example: Task callback
```julia
struct TaskFn{F,Ctx}
    f::F
    ctx::Ctx
end

(task::TaskFn)(status) = task.f(task.ctx, status)
```

## Pattern P4: Allocator Interface + OwnedPtr

### C shape
`aws_allocator` with `mem_acquire`, `mem_release`, `mem_realloc`, `mem_calloc`.

### Julia porting recipe
- Define `AbstractAllocator` and concrete allocators.
- Use `OwnedPtr` for explicit ownership, release explicitly.
- No finalizers.

### Example
```julia
abstract type AbstractAllocator end

struct SystemAllocator <: AbstractAllocator end
alloc(::SystemAllocator, n::Integer) = Ptr{UInt8}(Libc.malloc(n))
free(::SystemAllocator, p::Ptr{UInt8}) = Libc.free(p)

struct OwnedPtr{A<:AbstractAllocator,T}
    ptr::Ptr{T}
    alloc::A
end

alloc_owned(alloc::A, ::Type{T}, n::Integer) where {A<:AbstractAllocator,T} =
    OwnedPtr{A,T}(Ptr{T}(alloc(alloc, n*sizeof(T))), alloc)

release!(p::OwnedPtr) = (free(p.alloc, Ptr{UInt8}(p.ptr)); nothing)
```

## Pattern P5: ByteBuffer/ByteCursor + Lifetime Registry

### C shape
Owning `aws_byte_buf` and non-owning `aws_byte_cursor`.

### Julia porting recipe
- Use `Memory{UInt8}` for ownership.
- `ByteCursor` stores pointer and length only.
- Use a `WeakKeyDict` to tie unsafe views to owners (global registry).

### Example
```julia
struct ByteBuffer{A<:AbstractAllocator}
    mem::Memory{UInt8}
    len::Int
    alloc::A
end

struct ByteCursor
    ptr::Ptr{UInt8}
    len::Int
end

const VIEW_REGISTRY = WeakKeyDict{Array, Any}()

function unsafe_view(ptr::Ptr{UInt8}, len::Int, owner)
    view = unsafe_wrap(Array, ptr, len; own=false)
    VIEW_REGISTRY[view] = owner
    return view
end

cursor(buf::ByteBuffer) = ByteCursor(Ptr{UInt8}(pointer(buf.mem)), buf.len)
```

## Pattern P6: Intrusive Containers

### C shape
Embedded nodes + container_of for parent pointer recovery.

### Julia porting recipe
- Use indices into `Memory` instead of pointer arithmetic.
- Store a node index in each struct that participates in an intrusive list.

### Example
```julia
struct ListNode
    next::Int
    prev::Int
end

struct IntrusiveList{T}
    nodes::Memory{ListNode}
    values::Memory{T}
    head::Int
    tail::Int
end
```

## Pattern P7: Manual Containers on Memory

### C shape
`aws_array_list`, `aws_hash_table`, `aws_priority_queue` with explicit buffers and item sizes.

### Julia porting recipe
- Implement each container on top of `Memory{T}`.
- Store `length`, `capacity`, and other invariants explicitly.

### Example: ArrayList
```julia
struct ArrayList{T}
    data::Memory{T}
    length::Int
    capacity::Int
end

function push_back!(list::ArrayList{T}, value::T) where {T}
    list.length == list.capacity && return ErrorResult(AWS_ERROR_NO_SPACE)
    unsafe_store!(pointer(list.data) + list.length, value)
    list.length += 1
    return nothing
end
```

### Example: PriorityQueue
```julia
struct PriorityQueue{T,Less}
    data::Memory{T}
    length::Int
    capacity::Int
    less::Less
end
```

## Pattern P8: Opaque Handles + Explicit Lifecycle

### C shape
`*_init` / `*_clean_up` or `*_new` / `*_destroy`.

### Julia porting recipe
- Provide `init!`, `destroy!`, or `close!` functions explicitly.
- Offer `with_resource` helpers for safe use.

### Example
```julia
struct CrossProcessLock{O<:OS}
    handle::Ptr{Cvoid}
end

function acquire_lock(os::O, nonce) where {O<:OS}
    # OS-specific logic
end

release!(lock::CrossProcessLock) = nothing

with_lock(os, nonce, f) = begin
    lock = acquire_lock(os, nonce)
    lock isa ErrorResult && return lock
    try f(lock) finally release!(lock) end
end
```

## Pattern P9: Tagged Enums -> EnumX Scoped Enums

### C shape
Enums used for RTTI and flags (log levels, file types, task status, subjects).

### Julia porting recipe
- Use `@enumx` from EnumX.
- Refer to values as `EnumName.VALUE` and types as `EnumName.T`.

### Example
```julia
using EnumX

@enumx FileType::UInt8 begin
    FILE=1
    SYM_LINK=2
    DIRECTORY=4
end

is_dir(t::FileType.T) = t == FileType.DIRECTORY
```

## Pattern P10: Errors -> Sentinel ErrorResult

### C shape
Return code + `aws_last_error()`.

### Julia porting recipe
- Use `ErrorResult(code)` as a sentinel in union returns.
- Use `Union{T, Nothing}` for optional returns without error context.

### Example
```julia
struct ErrorResult
    code::Int
end

function open_file(path)::Union{FileHandle,ErrorResult}
    # return ErrorResult(code) on failure
end
```

## Pattern P11: Global Context -> ScopedValues

### C shape
Globals for logger, error handlers, registries.

### Julia porting recipe
- Encapsulate all state in a `RuntimeContext`.
- Use ScopedValues for scoped overrides.

### Example
```julia
using ScopedValues

struct RuntimeContext{L<:AbstractLogger,A<:AbstractAllocator}
    logger::L
    allocator::A
end

const CTX = ScopedValue{RuntimeContext}(RuntimeContext(NullLogger(), SystemAllocator()))

with_context(ctx, f) = @with CTX => ctx f()
current_logger() = CTX[].logger
```

## Pattern P12: Options/Config Structs

### C shape
Options structs (log writer, formatter, thread options, uri builder, shutdown callback).

### Julia porting recipe
- Use small parametric immutable structs with keyword constructors.
- Keep all fields concrete via type parameters.

### Example
```julia
Base.@kwdef struct LogWriterOptions{S<:AbstractString}
    filename::Union{S,Nothing} = nothing
end
```

## Pattern P13: Debug Macros + Log Gating

### C shape
`AWS_LOGF_*`, `AWS_ASSERT`, `AWS_STATIC_LOG_LEVEL`.

### Julia porting recipe
- Custom logging macros that short-circuit at compile time.
- Assertions are explicit and do not depend on Julia Logging.

### Example
```julia
const STATIC_LOG_LEVEL = LogLevel.INFO

macro AWS_LOGF_INFO(subject, msg)
    return :(STATIC_LOG_LEVEL >= LogLevel.INFO ? log!(current_logger(), LogLevel.INFO, $subject, $msg) : nothing)
end
```

## Pattern P14: OS-Specific Modules

### C shape
`#ifdef _WIN32` vs POSIX branches.

### Julia porting recipe
- Define OS hierarchy and dispatch on it.
- Implement OS-specific modules.

### Example
```julia
abstract type OS end
struct Windows <: OS end
struct Posix <: OS end

current_os() = Sys.iswindows() ? Windows() : Posix()

module CrossProcessLockOS
    export acquire_lock
    acquire_lock(::Windows, nonce) = windows_acquire(nonce)
    acquire_lock(::Posix, nonce) = posix_acquire(nonce)
end
```

## Pattern P15: Refcounting with @atomic

### C shape
Refcount struct with atomic count and on-zero callback.

### Julia porting recipe
- Use `@atomic` field in a mutable struct.
- Call cleanup explicitly when count reaches zero.

### Example
```julia
mutable struct RefCounted{T,OnZero}
    @atomic count::Int
    value::T
    on_zero::OnZero
end

acquire!(r::RefCounted) = (@atomic r.count += 1; r.value)

function release!(r::RefCounted)
    new = (@atomic r.count -= 1)
    new == 0 && r.on_zero(r.value)
    return new
end
```

## Pattern P16: Atomics + Lock-Free Structures

### C shape
`aws_atomic_var` and lock-free ring buffer.

### Julia porting recipe
- Use `@atomic` fields and `@atomic` ops.
- Preserve SPSC semantics explicitly.

### Example
```julia
mutable struct SpscRingBuffer
    data::Memory{UInt8}
    @atomic head::Int
    @atomic tail::Int
end

function rb_is_empty(rb::SpscRingBuffer)
    return (@atomic rb.head) == (@atomic rb.tail)
end
```

## Coverage Map (src)
- `src/aws/common/logging.jl`, `log_writer.jl`, `log_formatter.jl`, `log_channel.jl`: P1, P12, P13
- `src/aws/common/cache.jl`, `lru_cache.jl`, `fifo_cache.jl`, `lifo_cache.jl`: P1, P2, P6
- `src/aws/common/allocator.jl`: P4
- `src/aws/common/byte_buf.jl`, `string.jl`: P5
- `src/aws/common/linked_list.jl`, `linked_hash_table.jl`: P6
- `src/aws/common/array_list.jl`, `hash_table.jl`, `priority_queue.jl`: P7
- `src/aws/common/thread_scheduler.jl`, `thread.jl`, `mutex.jl`, `condition_variable.jl`, `rw_lock.jl`, `cross_process_lock.jl`: P8, P14, P15
- `src/aws/common/statistics.jl`, `logging_types.jl`: P9
- `src/aws/common/error.jl`, `common.jl`: P10, P11
- `src/aws/common/macros.jl`, `assert.jl`, `zero.jl`: P13
- `src/aws/common/atomics.jl`, `ring_buffer.jl`: P16
- `src/aws/common/uri.jl`, `process.jl`, `file.jl`, `xml_parser.jl`, `command_line_parser.jl`: P3, P5, P12
