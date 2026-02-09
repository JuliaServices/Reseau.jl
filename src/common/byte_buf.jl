# ByteBuffer and ByteCursor - Memory-based byte buffer management
#
# Design principles:
# - ByteBuffer owns a Memory{UInt8} with a length
# - ByteCursor is a view into memory via MemoryRef{UInt8} with a length
# - All operations use Memory/MemoryRef indexing, no pointer arithmetic
# - Ptr{UInt8} is only used at true C FFI boundaries (OS calls, etc.)

mutable struct ByteBuffer
    mem::Memory{UInt8}
    len::Csize_t
end

ByteBuffer(mem::Memory{UInt8}, len::Integer) = ByteBuffer(mem, Csize_t(len))

# Convenience constructor that allocates memory
function ByteBuffer(capacity::Integer)
    cap = Int(capacity)
    if cap == 0
        return ByteBuffer(Memory{UInt8}(undef, 0), Csize_t(0))
    end
    mem = Memory{UInt8}(undef, cap)
    return ByteBuffer(mem, Csize_t(0))
end

# Sentinel memory for null cursors - must have at least 1 byte for valid MemoryRef
const _null_cursor_mem = let m = Memory{UInt8}(undef, 1)
    m[1] = 0x00
    m
end

struct ByteCursor
    len::Csize_t
    ptr::MemoryRef{UInt8}
end

# Registry to prevent GC of underlying data for wrapped cursors/buffers
const _BUFFER_VIEW_REGISTRY = WeakKeyDict{Any, Any}()
const _BUFFER_VIEW_REGISTRY_LOCK = ReentrantLock()

@inline function _buffer_view_registry_set!(key, value)::Nothing
    lock(_BUFFER_VIEW_REGISTRY_LOCK)
    try
        _BUFFER_VIEW_REGISTRY[key] = value
    finally
        unlock(_BUFFER_VIEW_REGISTRY_LOCK)
    end
    return nothing
end

#==========================================================================
  ByteCursor Constructors
==========================================================================#

function ByteCursor(s::AbstractString)
    len = ncodeunits(s)
    if len == 0
        return ByteCursor(Csize_t(0), memoryref(_null_cursor_mem))
    end
    mem = unsafe_wrap(Memory{UInt8}, pointer(s), len; own = false)
    _buffer_view_registry_set!(mem, s)
    return ByteCursor(Csize_t(len), memoryref(mem))
end

function ByteCursor(mem::Memory{UInt8}, len::Integer = length(mem))
    if len == 0
        return ByteCursor(Csize_t(0), memoryref(_null_cursor_mem))
    end
    return ByteCursor(Csize_t(len), memoryref(mem))
end

function ByteCursor(mem::Memory{UInt8}, offset::Integer, len::Integer)
    if len == 0
        return ByteCursor(Csize_t(0), memoryref(_null_cursor_mem))
    end
    return ByteCursor(Csize_t(len), memoryref(mem, offset + 1))  # +1 for 1-based indexing
end

function ByteCursor(ref::MemoryRef{UInt8}, len::Integer)
    if len == 0
        return ByteCursor(Csize_t(0), memoryref(_null_cursor_mem))
    end
    return ByteCursor(Csize_t(len), ref)
end

function ByteCursor(vec::Vector{UInt8}, len::Integer = length(vec))
    len < 0 && throw(ArgumentError("len must be >= 0"))
    if len == 0 || isempty(vec)
        return ByteCursor(Csize_t(0), memoryref(_null_cursor_mem))
    end
    actual_len = len > length(vec) ? length(vec) : Int(len)
    mem = unsafe_wrap(Memory{UInt8}, pointer(vec), actual_len; own = false)
    _buffer_view_registry_set!(mem, vec)
    return ByteCursor(Csize_t(actual_len), memoryref(mem))
end

#==========================================================================
  Null Constructors
==========================================================================#

function null_buffer()
    return ByteBuffer(Memory{UInt8}(undef, 0), 0)
end

function null_cursor()
    return ByteCursor(Csize_t(0), memoryref(_null_cursor_mem))
end

#==========================================================================
  ByteBuffer Properties
==========================================================================#

@inline capacity(buf::ByteBuffer) = Csize_t(length(buf.mem))
@inline byte_buf_available(buf::ByteBuffer) = capacity(buf) - buf.len
@inline byte_buf_remaining_capacity(buf::ByteBuffer) = capacity(buf) - buf.len

function Base.getproperty(buf::ByteBuffer, name::Symbol)
    if name === :capacity
        return Csize_t(length(getfield(buf, :mem)))
    end
    return getfield(buf, name)
end

function Base.propertynames(::ByteBuffer; private::Bool = false)
    return (:mem, :len, :capacity)
end

#==========================================================================
  Memory Access Helpers
==========================================================================#

# Get byte at index i (1-based) from a ByteCursor
@inline function cursor_getbyte(cursor::ByteCursor, i::Integer)
    return memoryref(cursor.ptr, i)[]
end

# Get byte at index i (1-based) from a MemoryRef
@inline function memref_getbyte(ref::MemoryRef{UInt8}, i::Integer)
    return memoryref(ref, i)[]
end

# Get the parent Memory from a MemoryRef
@inline memref_parent(ref::MemoryRef{UInt8}) = parent(ref)

# Get the 1-based offset of a MemoryRef in its parent Memory
@inline memref_offset(ref::MemoryRef{UInt8}) = Base.memoryrefoffset(ref)

# Create a new MemoryRef advanced by n bytes (n=0 stays at same position)
@inline function memref_advance(ref::MemoryRef{UInt8}, n::Integer)
    start = memref_offset(ref)
    return memoryref(memref_parent(ref), start + Int(n))
end

# Create a new MemoryRef advanced by 1 byte
@inline memref_next(ref::MemoryRef{UInt8}) = memref_advance(ref, 1)

# Alias to match expected naming in ported code
@inline memref_getnext(ref::MemoryRef{UInt8}) = memref_next(ref)

# Check if cursor is effectively null
@inline cursor_is_null(cursor::ByteCursor) = cursor.len == 0

#==========================================================================
  Validation
==========================================================================#

const _SIZE_MAX_HALF = (typemax(Csize_t) >> 1)

function byte_buf_is_valid(buf::ByteBuffer)
    cap = capacity(buf)
    if cap == 0 && buf.len == 0
        return true
    end
    return cap > 0 && buf.len <= cap
end

function byte_buf_is_valid(buf::Base.RefValue{ByteBuffer})
    return byte_buf_is_valid(buf[])
end

function byte_cursor_is_valid(cursor::ByteCursor)
    return true  # MemoryRef is always valid by construction
end

function byte_cursor_is_valid(cursor::Base.RefValue{ByteCursor})
    return true
end

#==========================================================================
  Array Comparison (Memory-based)
==========================================================================#

function mem_eq(a::Memory{UInt8}, a_start::Int, a_len::Int, b::Memory{UInt8}, b_start::Int, b_len::Int)
    if a_len != b_len
        return false
    end
    if a_len == 0
        return true
    end
    @inbounds for i in 1:a_len
        if a[a_start + i - 1] != b[b_start + i - 1]
            return false
        end
    end
    return true
end

function memref_eq(a::MemoryRef{UInt8}, a_len::Integer, b::MemoryRef{UInt8}, b_len::Integer)
    if a_len != b_len
        return false
    end
    if a_len == 0
        return true
    end
    @inbounds for i in 1:Int(a_len)
        if memoryref(a, i)[] != memoryref(b, i)[]
            return false
        end
    end
    return true
end

function cursor_eq(a::ByteCursor, b::ByteCursor)
    return memref_eq(a.ptr, a.len, b.ptr, b.len)
end

@inline function _ascii_tolower(b::UInt8)
    if b >= 0x41 && b <= 0x5a
        return b + 0x20
    end
    return b
end

function memref_eq_ignore_case(a::MemoryRef{UInt8}, a_len::Integer, b::MemoryRef{UInt8}, b_len::Integer)
    if a_len != b_len
        return false
    end
    if a_len == 0
        return true
    end
    @inbounds for i in 1:Int(a_len)
        av = _ascii_tolower(memoryref(a, i)[])
        bv = _ascii_tolower(memoryref(b, i)[])
        if av != bv
            return false
        end
    end
    return true
end

function cursor_eq_ignore_case(a::ByteCursor, b::ByteCursor)
    return memref_eq_ignore_case(a.ptr, a.len, b.ptr, b.len)
end

# Compare a Ptr{UInt8} with a MemoryRef{UInt8}
function ptr_memref_eq(ptr::Ptr{UInt8}, ptr_len::Integer, memref::MemoryRef{UInt8}, memref_len::Integer)
    if ptr_len != memref_len
        return false
    end
    if ptr_len == 0
        return true
    end
    @inbounds for i in 1:Int(ptr_len)
        if unsafe_load(ptr, i) != memoryref(memref, i)[]
            return false
        end
    end
    return true
end

function ptr_memref_eq_ignore_case(ptr::Ptr{UInt8}, ptr_len::Integer, memref::MemoryRef{UInt8}, memref_len::Integer)
    if ptr_len != memref_len
        return false
    end
    if ptr_len == 0
        return true
    end
    @inbounds for i in 1:Int(ptr_len)
        av = _ascii_tolower(unsafe_load(ptr, i))
        bv = _ascii_tolower(memoryref(memref, i)[])
        if av != bv
            return false
        end
    end
    return true
end

# Compare cursor to a Julia string
function cursor_eq_string(cursor::ByteCursor, s::AbstractString)
    len = ncodeunits(s)
    if cursor.len != len
        return false
    end
    if len == 0
        return true
    end
    bytes = codeunits(s)
    @inbounds for i in 1:len
        if memoryref(cursor.ptr, i)[] != bytes[i]
            return false
        end
    end
    return true
end

function cursor_eq_string_ignore_case(cursor::ByteCursor, s::AbstractString)
    len = ncodeunits(s)
    if cursor.len != len
        return false
    end
    if len == 0
        return true
    end
    bytes = codeunits(s)
    @inbounds for i in 1:len
        if _ascii_tolower(memoryref(cursor.ptr, i)[]) != _ascii_tolower(bytes[i])
            return false
        end
    end
    return true
end

#==========================================================================
  Lookup Tables
==========================================================================#

const _tolower_table = let
    table = Memory{UInt8}(undef, 256)
    for i in 0:255
        table[i + 1] = _ascii_tolower(UInt8(i))
    end
    table
end

function lookup_table_to_lower_get()
    return _tolower_table
end

const _hex_to_num_table = let
    table = Memory{UInt8}(undef, 256)
    fill!(table, UInt8(255))
    for i in 0:9
        table[UInt8('0') + i + 1] = UInt8(i)
    end
    for i in 0:5
        table[UInt8('A') + i + 1] = UInt8(0x0A + i)
        table[UInt8('a') + i + 1] = UInt8(0x0A + i)
    end
    table
end

function lookup_table_hex_to_num_get()
    return _hex_to_num_table
end

#==========================================================================
  ByteBuffer Initialization
==========================================================================#

function byte_buf_init(buf::Base.RefValue{ByteBuffer}, capacity::Integer)
    cap = Int(capacity)
    if cap == 0
        buf[] = ByteBuffer(Memory{UInt8}(undef, 0), Csize_t(0))
        return OP_SUCCESS
    end
    mem = Memory{UInt8}(undef, cap)
    buf[] = ByteBuffer(mem, Csize_t(0))
    return OP_SUCCESS
end

function byte_buf_init_copy(dest::Base.RefValue{ByteBuffer}, src::ByteBuffer)
    if length(src.mem) == 0
        dest[] = ByteBuffer(Memory{UInt8}(undef, 0), Csize_t(0))
        return OP_SUCCESS
    end
    new_mem = Memory{UInt8}(undef, length(src.mem))
    if src.len > 0
        unsafe_copyto!(new_mem, 1, src.mem, 1, Int(src.len))
    end
    dest[] = ByteBuffer(new_mem, src.len)
    return OP_SUCCESS
end

function byte_buf_init_copy(dest::Base.RefValue{ByteBuffer}, src::Base.RefValue{ByteBuffer})
    return byte_buf_init_copy(dest, src[])
end

function byte_buf_init_copy_from_cursor(dest::Base.RefValue{ByteBuffer}, src::ByteCursor)
    if src.len == 0
        dest[] = ByteBuffer(Memory{UInt8}(undef, 0), Csize_t(0))
        return OP_SUCCESS
    end
    new_mem = Memory{UInt8}(undef, Int(src.len))
    src_mem = parent(src.ptr)
    src_start = memref_offset(src.ptr)
    unsafe_copyto!(new_mem, 1, src_mem, src_start, Int(src.len))
    dest[] = ByteBuffer(new_mem, src.len)
    return OP_SUCCESS
end

function byte_buf_init_cache_and_update_cursors(dest::Base.RefValue{ByteBuffer}, cursors...)
    total = Csize_t(0)
    for cursor in cursors
        cursor === nothing && break
        cur = cursor isa Base.RefValue ? cursor[] : cursor
        !byte_cursor_is_valid(cur) && break
        tmp = Ref{Csize_t}(0)
        if add_size_checked(total, cur.len, tmp) != OP_SUCCESS
            return OP_ERR
        end
        total = tmp[]
    end
    if byte_buf_init(dest, total) != OP_SUCCESS
        return OP_ERR
    end
    for cursor in cursors
        cursor === nothing && break
        cur_ref = cursor isa Base.RefValue ? cursor : Ref(cursor)
        byte_buf_append_and_update(dest, cur_ref)
    end
    return OP_SUCCESS
end

#==========================================================================
  ByteBuffer Operations
==========================================================================#

function byte_buf_reset(buf::Base.RefValue{ByteBuffer}, zero_contents::Bool)
    b = buf[]
    if zero_contents && length(b.mem) > 0
        fill!(b.mem, UInt8(0))
    end
    buf[] = ByteBuffer(b.mem, Csize_t(0))
    return nothing
end

function byte_buf_secure_zero(buf::Base.RefValue{ByteBuffer})
    b = buf[]
    if length(b.mem) > 0
        secure_zero(b.mem)
    end
    buf[] = ByteBuffer(b.mem, Csize_t(0))
    return nothing
end

function byte_buf_clean_up(buf::Base.RefValue{ByteBuffer})
    # Note: We don't need to explicitly free Memory in Julia - GC handles it
    buf[] = ByteBuffer(Memory{UInt8}(undef, 0), Csize_t(0))
    return nothing
end

function byte_buf_clean_up_secure(buf::Base.RefValue{ByteBuffer})
    byte_buf_secure_zero(buf)
    byte_buf_clean_up(buf)
    return nothing
end

#==========================================================================
  ByteBuffer Comparison
==========================================================================#

function byte_buf_eq(a::ByteBuffer, b::ByteBuffer)
    return mem_eq(a.mem, 1, Int(a.len), b.mem, 1, Int(b.len))
end

function byte_buf_eq(a::Base.RefValue{ByteBuffer}, b::Base.RefValue{ByteBuffer})
    return byte_buf_eq(a[], b[])
end

function byte_buf_eq_ignore_case(a::ByteBuffer, b::ByteBuffer)
    if a.len != b.len
        return false
    end
    if a.len == 0
        return true
    end
    @inbounds for i in 1:Int(a.len)
        av = _ascii_tolower(a.mem[i])
        bv = _ascii_tolower(b.mem[i])
        if av != bv
            return false
        end
    end
    return true
end

function byte_buf_eq_ignore_case(a::Base.RefValue{ByteBuffer}, b::Base.RefValue{ByteBuffer})
    return byte_buf_eq_ignore_case(a[], b[])
end

function byte_buf_eq_c_str(buf::ByteBuffer, c_str::AbstractString)
    return cursor_eq_string(byte_cursor_from_buf(buf), c_str)
end

function byte_buf_eq_c_str(buf::Base.RefValue{ByteBuffer}, c_str::AbstractString)
    return byte_buf_eq_c_str(buf[], c_str)
end

function byte_buf_eq_c_str_ignore_case(buf::ByteBuffer, c_str::AbstractString)
    return cursor_eq_string_ignore_case(byte_cursor_from_buf(buf), c_str)
end

function byte_buf_eq_c_str_ignore_case(buf::Base.RefValue{ByteBuffer}, c_str::AbstractString)
    return byte_buf_eq_c_str_ignore_case(buf[], c_str)
end

#==========================================================================
  ByteBuffer/ByteCursor Creation from Data
==========================================================================#

function byte_buf_from_c_str(c_str::AbstractString)
    len = ncodeunits(c_str)
    if len == 0
        return ByteBuffer(Memory{UInt8}(undef, 0), 0)
    end
    mem = Memory{UInt8}(undef, len)
    bytes = codeunits(c_str)
    GC.@preserve bytes begin
        Base.unsafe_copyto!(pointer(mem), pointer(bytes), len)
    end
    return ByteBuffer(mem, Csize_t(len))
end

function byte_buf_from_array(bytes::Memory{UInt8}, len::Integer = length(bytes))
    cap = min(Int(len), length(bytes))
    if cap == 0
        return ByteBuffer(Memory{UInt8}(undef, 0), 0)
    end
    return ByteBuffer(bytes, Csize_t(cap))
end

function byte_buf_from_array(bytes::AbstractVector{UInt8}, len::Integer = length(bytes))
    len < 0 && throw(ArgumentError("len must be >= 0"))
    bytes isa SubArray && !Base.iscontiguous(bytes) &&
        throw(ArgumentError("byte_buf_from_array requires a contiguous array"))
    cap = len > length(bytes) ? length(bytes) : Int(len)
    if cap == 0
        return ByteBuffer(Memory{UInt8}(undef, 0), 0)
    end
    mem = unsafe_wrap(Memory{UInt8}, pointer(bytes), cap; own = false)
    _buffer_view_registry_set!(mem, bytes)
    return ByteBuffer(mem, Csize_t(cap))
end

function byte_buf_from_empty_array(bytes::AbstractVector{UInt8}, len::Integer = length(bytes))
    len < 0 && throw(ArgumentError("len must be >= 0"))
    bytes isa SubArray && !Base.iscontiguous(bytes) &&
        throw(ArgumentError("byte_buf_from_empty_array requires a contiguous array"))
    cap = len > length(bytes) ? length(bytes) : Int(len)
    if cap == 0
        return ByteBuffer(Memory{UInt8}(undef, 0), 0)
    end
    mem = unsafe_wrap(Memory{UInt8}, pointer(bytes), cap; own = false)
    _buffer_view_registry_set!(mem, bytes)
    return ByteBuffer(mem, Csize_t(0))
end

function byte_cursor_from_array(bytes::Memory{UInt8}, len::Integer = length(bytes))
    if len == 0 || length(bytes) == 0
        return null_cursor()
    end
    return ByteCursor(Csize_t(len), memoryref(bytes))
end

function byte_cursor_from_array(ref::MemoryRef{UInt8}, len::Integer)
    if len == 0
        return null_cursor()
    end
    return ByteCursor(Csize_t(len), ref)
end

function byte_cursor_from_array(bytes::AbstractVector{UInt8}, len::Integer = length(bytes))
    if len == 0 || length(bytes) == 0
        return null_cursor()
    end
    len < 0 && throw(ArgumentError("len must be >= 0"))
    bytes isa SubArray && !Base.iscontiguous(bytes) &&
        throw(ArgumentError("byte_cursor_from_array requires a contiguous array"))
    actual_len = len > length(bytes) ? length(bytes) : Int(len)
    actual_len == 0 && return null_cursor()
    mem = unsafe_wrap(Memory{UInt8}, pointer(bytes), actual_len; own = false)
    _buffer_view_registry_set!(mem, bytes)
    return ByteCursor(Csize_t(actual_len), memoryref(mem))
end

function byte_cursor_from_array(bytes::AbstractVector{UInt8}, offset::Integer, len::Integer)
    if len == 0 || length(bytes) == 0
        return null_cursor()
    end
    len < 0 && throw(ArgumentError("len must be >= 0"))
    bytes isa SubArray && !Base.iscontiguous(bytes) &&
        throw(ArgumentError("byte_cursor_from_array requires a contiguous array"))
    start = Int(offset)
    start < 0 && return null_cursor()
    start >= length(bytes) && return null_cursor()
    max_len = length(bytes) - start
    actual_len = len > max_len ? max_len : Int(len)
    actual_len == 0 && return null_cursor()
    mem = unsafe_wrap(Memory{UInt8}, pointer(bytes), length(bytes); own = false)
    _buffer_view_registry_set!(mem, bytes)
    return ByteCursor(Csize_t(actual_len), memoryref(mem, start + 1))
end

function byte_cursor_from_c_str(c_str::AbstractString)
    len = ncodeunits(c_str)
    if len == 0
        return null_cursor()
    end
    mem = unsafe_wrap(Memory{UInt8}, pointer(c_str), len; own = false)
    _buffer_view_registry_set!(mem, c_str)
    return ByteCursor(Csize_t(len), memoryref(mem))
end

function byte_cursor_from_buf(buf::ByteBuffer)
    if buf.len == 0
        return null_cursor()
    end
    return ByteCursor(buf.len, memoryref(buf.mem))
end

function byte_cursor_from_buf(buf::Base.RefValue{ByteBuffer})
    return byte_cursor_from_buf(buf[])
end

#==========================================================================
  Hash Functions
==========================================================================#

function hash_array_ignore_case(cursor::ByteCursor)
    FNV_OFFSET = UInt64(0xcbf29ce484222325)
    FNV_PRIME = UInt64(0x00000100000001b3)
    hash = FNV_OFFSET
    if cursor.len == 0
        return hash
    end
    @inbounds for i in 1:Int(cursor.len)
        b = memoryref(cursor.ptr, i)[]
        b = _tolower_table[Int(b) + 1]
        hash ⊻= UInt64(b)
        hash *= FNV_PRIME
    end
    return hash
end

function hash_array_ignore_case(mem::Memory{UInt8}, len::Integer)
    return hash_array_ignore_case(ByteCursor(mem, len))
end

#==========================================================================
  Byte Cursor Navigation
==========================================================================#

function nospec_mask(index::Csize_t, bound::Csize_t)
    limit = _SIZE_MAX_HALF
    if bound > limit || index > limit || index >= bound
        return Csize_t(0)
    end
    return typemax(Csize_t)
end

function byte_cursor_advance(cursor::Base.RefValue{ByteCursor}, len::Integer)
    cur = cursor[]
    adv = Csize_t(len)
    if cur.len > _SIZE_MAX_HALF || adv > _SIZE_MAX_HALF || adv > cur.len
        return null_cursor()
    end
    # Return cursor pointing to current position with length = adv
    rv = ByteCursor(adv, cur.ptr)
    # Advance the stored cursor's position
    if cur.len == adv
        cursor[] = null_cursor()
    else
        new_ref = memref_advance(cur.ptr, Int(adv))
        cursor[] = ByteCursor(cur.len - adv, new_ref)
    end
    return rv
end

function byte_cursor_advance(cursor::ByteCursor, len::Integer)
    ref = Ref(cursor)
    return byte_cursor_advance(ref, len)
end

function byte_cursor_advance_nospec(cursor::Base.RefValue{ByteCursor}, len::Integer)
    cur = cursor[]
    adv = Csize_t(len)
    if adv <= cur.len && adv <= _SIZE_MAX_HALF && cur.len <= _SIZE_MAX_HALF
        mask = nospec_mask(adv, cur.len + 1)
        adv = adv & mask
        len_val = cur.len & mask
        rv = adv > 0 ? ByteCursor(adv & mask, cur.ptr) : null_cursor()
        if len_val == adv
            cursor[] = null_cursor()
        elseif adv > 0
            new_ref = memref_advance(cur.ptr, Int(adv))
            cursor[] = ByteCursor(len_val - adv, new_ref)
        end
        return rv
    end
    return null_cursor()
end

#==========================================================================
  Byte Cursor Read Operations
==========================================================================#

function byte_cursor_read(cur::Base.RefValue{ByteCursor}, dest::Memory{UInt8}, dest_offset::Int, len::Integer)
    precondition(byte_cursor_is_valid(cur))
    if len == 0
        return true
    end
    slice = byte_cursor_advance_nospec(cur, len)
    if slice.len > 0
        src_mem = parent(slice.ptr)
        src_start = memref_offset(slice.ptr)
        unsafe_copyto!(dest, dest_offset, src_mem, src_start, Int(len))
        return true
    end
    return false
end

function byte_cursor_read(cur::Base.RefValue{ByteCursor}, dest::AbstractVector{UInt8}, len::Integer)
    if len == 0
        return true
    end
    slice = byte_cursor_advance_nospec(cur, len)
    if slice.len > 0
        src_mem = parent(slice.ptr)
        src_start = memref_offset(slice.ptr)
        @inbounds for i in 1:Int(len)
            dest[i] = src_mem[src_start + i - 1]
        end
        return true
    end
    return false
end

function byte_cursor_read_and_fill_buffer(cur::Base.RefValue{ByteCursor}, dest::Base.RefValue{ByteBuffer})
    d = dest[]
    cap = capacity(d)
    if cap == 0
        return true
    end
    if byte_cursor_read(cur, d.mem, 1, cap)
        dest[] = ByteBuffer(d.mem, cap)
        return true
    end
    return false
end

function byte_cursor_read_u8(cur::Base.RefValue{ByteCursor}, var::Base.RefValue{UInt8})
    c = cur[]
    if c.len < 1
        return false
    end
    var[] = memoryref(c.ptr, 1)[]
    if c.len == 1
        cur[] = null_cursor()
    else
        cur[] = ByteCursor(c.len - 1, memref_advance(c.ptr, 1))
    end
    return true
end

function byte_cursor_read_be16(cur::Base.RefValue{ByteCursor}, var::Base.RefValue{UInt16})
    c = cur[]
    if c.len < 2
        return false
    end
    b1 = UInt16(memoryref(c.ptr, 1)[])
    b2 = UInt16(memoryref(c.ptr, 2)[])
    var[] = (b1 << 8) | b2
    if c.len == 2
        cur[] = null_cursor()
    else
        cur[] = ByteCursor(c.len - 2, memref_advance(c.ptr, 2))
    end
    return true
end

function byte_cursor_read_be24(cur::Base.RefValue{ByteCursor}, var::Base.RefValue{UInt32})
    c = cur[]
    if c.len < 3
        return false
    end
    b1 = UInt32(memoryref(c.ptr, 1)[])
    b2 = UInt32(memoryref(c.ptr, 2)[])
    b3 = UInt32(memoryref(c.ptr, 3)[])
    var[] = (b1 << 16) | (b2 << 8) | b3
    if c.len == 3
        cur[] = null_cursor()
    else
        cur[] = ByteCursor(c.len - 3, memref_advance(c.ptr, 3))
    end
    return true
end

function byte_cursor_read_be32(cur::Base.RefValue{ByteCursor}, var::Base.RefValue{UInt32})
    c = cur[]
    if c.len < 4
        return false
    end
    b1 = UInt32(memoryref(c.ptr, 1)[])
    b2 = UInt32(memoryref(c.ptr, 2)[])
    b3 = UInt32(memoryref(c.ptr, 3)[])
    b4 = UInt32(memoryref(c.ptr, 4)[])
    var[] = (b1 << 24) | (b2 << 16) | (b3 << 8) | b4
    if c.len == 4
        cur[] = null_cursor()
    else
        cur[] = ByteCursor(c.len - 4, memref_advance(c.ptr, 4))
    end
    return true
end

function byte_cursor_read_be64(cur::Base.RefValue{ByteCursor}, var::Base.RefValue{UInt64})
    c = cur[]
    if c.len < 8
        return false
    end
    val = UInt64(0)
    @inbounds for i in 1:8
        val = (val << 8) | UInt64(memoryref(c.ptr, i)[])
    end
    var[] = val
    if c.len == 8
        cur[] = null_cursor()
    else
        cur[] = ByteCursor(c.len - 8, memref_advance(c.ptr, 8))
    end
    return true
end

function byte_cursor_read_float_be32(cur::Base.RefValue{ByteCursor}, var::Base.RefValue{Float32})
    tmp = Ref{UInt32}(0)
    if !byte_cursor_read_be32(cur, tmp)
        return false
    end
    var[] = reinterpret(Float32, ntoh(hton(tmp[])))
    return true
end

function byte_cursor_read_float_be64(cur::Base.RefValue{ByteCursor}, var::Base.RefValue{Float64})
    tmp = Ref{UInt64}(0)
    if !byte_cursor_read_be64(cur, tmp)
        return false
    end
    var[] = reinterpret(Float64, ntoh(hton(tmp[])))
    return true
end

function byte_cursor_read_hex_u8(cur::Base.RefValue{ByteCursor}, var::Base.RefValue{UInt8})
    c = cur[]
    if c.len < 2
        return false
    end
    hi = _hex_to_num_table[Int(memoryref(c.ptr, 1)[]) + 1]
    lo = _hex_to_num_table[Int(memoryref(c.ptr, 2)[]) + 1]
    if hi == 255 || lo == 255
        return false
    end
    var[] = (hi << 4) | lo
    if c.len == 2
        cur[] = null_cursor()
    else
        cur[] = ByteCursor(c.len - 2, memref_advance(c.ptr, 2))
    end
    return true
end

#==========================================================================
  ByteBuffer Write Operations
==========================================================================#

function byte_buf_write(buf::Base.RefValue{ByteBuffer}, src::Memory{UInt8}, src_offset::Int, len::Integer)
    if len == 0
        return true
    end
    b = buf[]
    cap = capacity(b)
    if b.len > _SIZE_MAX_HALF || len > _SIZE_MAX_HALF || b.len + Csize_t(len) > cap
        return false
    end
    unsafe_copyto!(b.mem, Int(b.len) + 1, src, src_offset, Int(len))
    buf[] = ByteBuffer(b.mem, b.len + Csize_t(len))
    return true
end

function byte_buf_write(buf::Base.RefValue{ByteBuffer}, src::AbstractVector{UInt8}, len::Integer = length(src))
    if len == 0
        return true
    end
    b = buf[]
    cap = capacity(b)
    if b.len > _SIZE_MAX_HALF || len > _SIZE_MAX_HALF || b.len + Csize_t(len) > cap
        return false
    end
    @inbounds for i in 1:Int(len)
        b.mem[Int(b.len) + i] = src[i]
    end
    buf[] = ByteBuffer(b.mem, b.len + Csize_t(len))
    return true
end

function byte_buf_write(buf::Base.RefValue{ByteBuffer}, src::Ptr{UInt8}, len::Integer)
    if len == 0
        return true
    end
    b = buf[]
    cap = capacity(b)
    if b.len > _SIZE_MAX_HALF || len > _SIZE_MAX_HALF || b.len + Csize_t(len) > cap
        return false
    end
    @inbounds for i in 1:Int(len)
        b.mem[Int(b.len) + i] = unsafe_load(src, i)
    end
    buf[] = ByteBuffer(b.mem, b.len + Csize_t(len))
    return true
end

function byte_buf_write_from_whole_buffer(buf::Base.RefValue{ByteBuffer}, src::ByteBuffer)
    return byte_buf_write(buf, src.mem, 1, Int(src.len))
end

function byte_buf_write_from_whole_buffer(buf::Base.RefValue{ByteBuffer}, src::Base.RefValue{ByteBuffer})
    return byte_buf_write_from_whole_buffer(buf, src[])
end

function byte_buf_write_from_whole_cursor(buf::Base.RefValue{ByteBuffer}, src::ByteCursor)
    if src.len == 0
        return true
    end
    src_mem = parent(src.ptr)
    src_start = memref_offset(src.ptr)
    return byte_buf_write(buf, src_mem, src_start, Int(src.len))
end

function byte_buf_write_from_whole_cursor(buf::Base.RefValue{ByteBuffer}, src::Base.RefValue{ByteCursor})
    return byte_buf_write_from_whole_cursor(buf, src[])
end

function byte_buf_write_to_capacity(buf::Base.RefValue{ByteBuffer}, advancing_cursor::Base.RefValue{ByteCursor})
    b = buf[]
    cur = advancing_cursor[]
    available = capacity(b) - b.len
    write_size = min(available, cur.len)
    write_cursor = byte_cursor_advance(advancing_cursor, write_size)
    byte_buf_write_from_whole_cursor(buf, write_cursor)
    return write_cursor
end

function byte_buf_write_u8(buf::Base.RefValue{ByteBuffer}, c::UInt8)
    b = buf[]
    cap = capacity(b)
    if b.len >= cap
        return false
    end
    b.mem[Int(b.len) + 1] = c
    buf[] = ByteBuffer(b.mem, b.len + 1)
    return true
end

function byte_buf_write_u8_n(buf::Base.RefValue{ByteBuffer}, c::UInt8, count::Integer)
    b = buf[]
    cap = capacity(b)
    if b.len > _SIZE_MAX_HALF || count > _SIZE_MAX_HALF || b.len + count > cap
        return false
    end
    if count > 0
        @inbounds for i in 1:Int(count)
            b.mem[Int(b.len) + i] = c
        end
        buf[] = ByteBuffer(b.mem, b.len + Csize_t(count))
    end
    return true
end

function byte_buf_write_be16(buf::Base.RefValue{ByteBuffer}, x::UInt16)
    b = buf[]
    cap = capacity(b)
    if b.len + 2 > cap
        return false
    end
    b.mem[Int(b.len) + 1] = UInt8((x >> 8) & 0xff)
    b.mem[Int(b.len) + 2] = UInt8(x & 0xff)
    buf[] = ByteBuffer(b.mem, b.len + 2)
    return true
end

function byte_buf_write_be24(buf::Base.RefValue{ByteBuffer}, x::UInt32)
    b = buf[]
    cap = capacity(b)
    if b.len + 3 > cap
        return false
    end
    b.mem[Int(b.len) + 1] = UInt8((x >> 16) & 0xff)
    b.mem[Int(b.len) + 2] = UInt8((x >> 8) & 0xff)
    b.mem[Int(b.len) + 3] = UInt8(x & 0xff)
    buf[] = ByteBuffer(b.mem, b.len + 3)
    return true
end

function byte_buf_write_be32(buf::Base.RefValue{ByteBuffer}, x::UInt32)
    b = buf[]
    cap = capacity(b)
    if b.len + 4 > cap
        return false
    end
    b.mem[Int(b.len) + 1] = UInt8((x >> 24) & 0xff)
    b.mem[Int(b.len) + 2] = UInt8((x >> 16) & 0xff)
    b.mem[Int(b.len) + 3] = UInt8((x >> 8) & 0xff)
    b.mem[Int(b.len) + 4] = UInt8(x & 0xff)
    buf[] = ByteBuffer(b.mem, b.len + 4)
    return true
end

function byte_buf_write_be64(buf::Base.RefValue{ByteBuffer}, x::UInt64)
    b = buf[]
    cap = capacity(b)
    if b.len + 8 > cap
        return false
    end
    @inbounds for i in 0:7
        b.mem[Int(b.len) + 8 - i] = UInt8((x >> (i * 8)) & 0xff)
    end
    buf[] = ByteBuffer(b.mem, b.len + 8)
    return true
end

function byte_buf_write_float_be32(buf::Base.RefValue{ByteBuffer}, x::Float32)
    return byte_buf_write_be32(buf, reinterpret(UInt32, x))
end

function byte_buf_write_float_be64(buf::Base.RefValue{ByteBuffer}, x::Float64)
    return byte_buf_write_be64(buf, reinterpret(UInt64, x))
end

#==========================================================================
  ByteBuffer Append Operations
==========================================================================#

function byte_buf_append(to::Base.RefValue{ByteBuffer}, from::ByteCursor)
    t = to[]
    cap = capacity(t)
    if cap - t.len < from.len
        return raise_error(ERROR_DEST_COPY_TOO_SMALL)
    end
    if from.len > 0
        src_mem = parent(from.ptr)
        src_start = memref_offset(from.ptr)
        unsafe_copyto!(t.mem, Int(t.len) + 1, src_mem, src_start, Int(from.len))
    end
    to[] = ByteBuffer(t.mem, t.len + from.len)
    return OP_SUCCESS
end

function byte_buf_append(to::Base.RefValue{ByteBuffer}, from::Base.RefValue{ByteCursor})
    return byte_buf_append(to, from[])
end

function byte_buf_append_with_lookup(to::Base.RefValue{ByteBuffer}, from::ByteCursor, lookup_table::Memory{UInt8})
    t = to[]
    cap = capacity(t)
    if cap - t.len < from.len
        return raise_error(ERROR_DEST_COPY_TOO_SMALL)
    end
    if from.len > 0
        @inbounds for i in 1:Int(from.len)
            byte = memoryref(from.ptr, i)[]
            t.mem[Int(t.len) + i] = lookup_table[Int(byte) + 1]
        end
    end
    tmp = Ref{Csize_t}(0)
    if add_size_checked(t.len, from.len, tmp) != OP_SUCCESS
        return OP_ERR
    end
    to[] = ByteBuffer(t.mem, tmp[])
    return OP_SUCCESS
end

function byte_buf_append_with_lookup(to::Base.RefValue{ByteBuffer}, from::Base.RefValue{ByteCursor}, lookup_table::Memory{UInt8})
    return byte_buf_append_with_lookup(to, from[], lookup_table)
end

function _byte_buf_append_dynamic(to::Base.RefValue{ByteBuffer}, from::ByteCursor, clear_released_memory::Bool)
    t = to[]
    cap = capacity(t)
    if cap - t.len < from.len
        missing = from.len - (cap - t.len)
        required = Ref{Csize_t}(0)
        if add_size_checked(cap, missing, required) != OP_SUCCESS
            return OP_ERR
        end
        growth = add_size_saturating(cap, cap)
        new_capacity = required[] < growth ? growth : required[]
        new_mem = Memory{UInt8}(undef, Int(new_capacity))
        if t.len > 0
            unsafe_copyto!(new_mem, 1, t.mem, 1, Int(t.len))
        end
        if from.len > 0
            src_mem = parent(from.ptr)
            src_start = memref_offset(from.ptr)
            unsafe_copyto!(new_mem, Int(t.len) + 1, src_mem, src_start, Int(from.len))
        end
        if clear_released_memory && length(t.mem) > 0
            secure_zero(t.mem)
        end
        to[] = ByteBuffer(new_mem, t.len + from.len)
    else
        if from.len > 0
            src_mem = parent(from.ptr)
            src_start = memref_offset(from.ptr)
            unsafe_copyto!(t.mem, Int(t.len) + 1, src_mem, src_start, Int(from.len))
        end
        to[] = ByteBuffer(t.mem, t.len + from.len)
    end
    return OP_SUCCESS
end

function byte_buf_append_dynamic(to::Base.RefValue{ByteBuffer}, from::ByteCursor)
    return _byte_buf_append_dynamic(to, from, false)
end

function byte_buf_append_dynamic(to::Base.RefValue{ByteBuffer}, from::Base.RefValue{ByteCursor})
    return _byte_buf_append_dynamic(to, from[], false)
end

function byte_buf_append_dynamic_secure(to::Base.RefValue{ByteBuffer}, from::ByteCursor)
    return _byte_buf_append_dynamic(to, from, true)
end

function byte_buf_append_dynamic_secure(to::Base.RefValue{ByteBuffer}, from::Base.RefValue{ByteCursor})
    return _byte_buf_append_dynamic(to, from[], true)
end

function byte_buf_append_byte_dynamic(buf::Base.RefValue{ByteBuffer}, value::UInt8)
    single = Memory{UInt8}(undef, 1)
    single[1] = value
    return _byte_buf_append_dynamic(buf, ByteCursor(single, 1), false)
end

function byte_buf_append_byte_dynamic_secure(buf::Base.RefValue{ByteBuffer}, value::UInt8)
    single = Memory{UInt8}(undef, 1)
    single[1] = value
    return _byte_buf_append_dynamic(buf, ByteCursor(single, 1), true)
end

#==========================================================================
  ByteBuffer Reserve Operations
==========================================================================#

function byte_buf_reserve(buf::Base.RefValue{ByteBuffer}, requested_capacity::Integer)
    b = buf[]
    req = Csize_t(requested_capacity)
    cap = capacity(b)
    if req <= cap
        return OP_SUCCESS
    end
    if length(b.mem) == 0
        return byte_buf_init(buf, req)
    end
    new_mem = Memory{UInt8}(undef, Int(req))
    if b.len > 0
        unsafe_copyto!(new_mem, 1, b.mem, 1, Int(b.len))
    end
    buf[] = ByteBuffer(new_mem, b.len)
    return OP_SUCCESS
end

function byte_buf_reserve_relative(buf::Base.RefValue{ByteBuffer}, additional_length::Integer)
    b = buf[]
    req = Ref{Csize_t}(0)
    if add_size_checked(b.len, Csize_t(additional_length), req) != OP_SUCCESS
        return OP_ERR
    end
    return byte_buf_reserve(buf, req[])
end

function byte_buf_reserve_smart(buf::Base.RefValue{ByteBuffer}, requested_capacity::Integer)
    b = buf[]
    req = Csize_t(requested_capacity)
    cap = capacity(b)
    if req <= cap
        return OP_SUCCESS
    end
    double_capacity = add_size_saturating(cap, cap)
    new_capacity = max_size(req, double_capacity)
    return byte_buf_reserve(buf, new_capacity)
end

function byte_buf_reserve_smart_relative(buf::Base.RefValue{ByteBuffer}, additional_length::Integer)
    b = buf[]
    req = Ref{Csize_t}(0)
    if add_size_checked(b.len, Csize_t(additional_length), req) != OP_SUCCESS
        return OP_ERR
    end
    return byte_buf_reserve_smart(buf, req[])
end

#==========================================================================
  ByteBuffer Advance
==========================================================================#

function byte_buf_advance(buffer::Base.RefValue{ByteBuffer}, output::Base.RefValue{ByteBuffer}, len::Integer)
    b = buffer[]
    cap = capacity(b)
    if cap - b.len >= Csize_t(len)
        # Create output buffer as view into remaining space
        if len == 0 || length(b.mem) == 0
            output[] = null_buffer()
        else
            # The output buffer is a view into buffer's memory starting at len position
            output_mem = unsafe_wrap(Memory{UInt8}, pointer(b.mem, Int(b.len) + 1), Int(len); own = false)
            _buffer_view_registry_set!(output_mem, b.mem)
            output[] = ByteBuffer(output_mem, Csize_t(0))
        end
        buffer[] = ByteBuffer(b.mem, b.len + Csize_t(len))
        return true
    end
    output[] = null_buffer()
    return false
end

#==========================================================================
  ByteBuffer Cat
==========================================================================#

function byte_buf_cat(dest::Base.RefValue{ByteBuffer}, bufs::Vararg{Union{ByteBuffer, Base.RefValue{ByteBuffer}}})
    for buf in bufs
        b = buf isa Base.RefValue ? buf[] : buf
        cursor = byte_cursor_from_buf(b)
        if byte_buf_append(dest, cursor) != OP_SUCCESS
            return OP_ERR
        end
    end
    return OP_SUCCESS
end

#==========================================================================
  ByteBuffer Append and Update
==========================================================================#

function byte_buf_append_and_update(to::Base.RefValue{ByteBuffer}, from_and_update::Base.RefValue{ByteCursor})
    if byte_buf_append(to, from_and_update) != OP_SUCCESS
        return OP_ERR
    end
    t = to[]
    from = from_and_update[]
    if from.len == 0 || t.len == 0
        from_and_update[] = null_cursor()
    else
        # Update cursor to point into destination buffer's memory
        offset = t.len - from.len
        new_ref = memoryref(t.mem, Int(offset) + 1)
        from_and_update[] = ByteCursor(from.len, new_ref)
    end
    return OP_SUCCESS
end

#==========================================================================
  Null Terminator
==========================================================================#

const _null_terminator_storage = let storage = Memory{UInt8}(undef, 1)
    storage[1] = 0x00
    storage
end

const _null_terminator_cursor = byte_cursor_from_array(_null_terminator_storage, 1)

function byte_buf_append_null_terminator(buf::Base.RefValue{ByteBuffer})
    return byte_buf_append_dynamic(buf, _null_terminator_cursor)
end

#==========================================================================
  Cursor Trim Operations
==========================================================================#

function byte_cursor_right_trim_pred(source::ByteCursor, predicate::Function)
    trimmed_len = source.len
    if trimmed_len == 0
        return null_cursor()
    end
    while trimmed_len > 0
        last_byte = memoryref(source.ptr, Int(trimmed_len))[]
        if predicate(last_byte)
            trimmed_len -= 1
        else
            break
        end
    end
    if trimmed_len == 0
        return null_cursor()
    end
    return ByteCursor(trimmed_len, source.ptr)
end

function byte_cursor_right_trim_pred(source::Base.RefValue{ByteCursor}, predicate::Function)
    return byte_cursor_right_trim_pred(source[], predicate)
end

function byte_cursor_left_trim_pred(source::ByteCursor, predicate::Function)
    total_len = source.len
    if total_len == 0
        return null_cursor()
    end
    skipped = Csize_t(0)
    while skipped < total_len
        first_byte = memoryref(source.ptr, Int(skipped) + 1)[]
        if predicate(first_byte)
            skipped += 1
        else
            break
        end
    end
    new_len = total_len - skipped
    if new_len == 0
        return null_cursor()
    end
    new_ref = memref_advance(source.ptr, Int(skipped))
    return ByteCursor(new_len, new_ref)
end

function byte_cursor_left_trim_pred(source::Base.RefValue{ByteCursor}, predicate::Function)
    return byte_cursor_left_trim_pred(source[], predicate)
end

function byte_cursor_trim_pred(source::ByteCursor, predicate::Function)
    left_trimmed = byte_cursor_left_trim_pred(source, predicate)
    return byte_cursor_right_trim_pred(left_trimmed, predicate)
end

function byte_cursor_trim_pred(source::Base.RefValue{ByteCursor}, predicate::Function)
    return byte_cursor_trim_pred(source[], predicate)
end

function byte_cursor_satisfies_pred(source::ByteCursor, predicate::Function)
    trimmed = byte_cursor_left_trim_pred(source, predicate)
    return trimmed.len == 0
end

function byte_cursor_satisfies_pred(source::Base.RefValue{ByteCursor}, predicate::Function)
    return byte_cursor_satisfies_pred(source[], predicate)
end

#==========================================================================
  Cursor Compare Operations
==========================================================================#

function byte_cursor_compare_lexical(lhs::ByteCursor, rhs::ByteCursor)
    comparison_length = min(lhs.len, rhs.len)
    if comparison_length > 0
        @inbounds for i in 1:Int(comparison_length)
            l = memoryref(lhs.ptr, i)[]
            r = memoryref(rhs.ptr, i)[]
            if l != r
                return l < r ? -1 : 1
            end
        end
    end
    if lhs.len == rhs.len
        return 0
    end
    return lhs.len == comparison_length ? -1 : 1
end

function byte_cursor_compare_lexical(lhs::Base.RefValue{ByteCursor}, rhs::Base.RefValue{ByteCursor})
    return byte_cursor_compare_lexical(lhs[], rhs[])
end

function byte_cursor_compare_lookup(lhs::ByteCursor, rhs::ByteCursor, lookup_table::Memory{UInt8})
    if lhs.len == 0 && rhs.len == 0
        return 0
    elseif lhs.len == 0
        return -1
    elseif rhs.len == 0
        return 1
    end
    lhs_idx = 1
    rhs_idx = 1
    while lhs_idx <= Int(lhs.len) && rhs_idx <= Int(rhs.len)
        lhc = lookup_table[Int(memoryref(lhs.ptr, lhs_idx)[]) + 1]
        rhc = lookup_table[Int(memoryref(rhs.ptr, rhs_idx)[]) + 1]
        if lhc < rhc
            return -1
        elseif lhc > rhc
            return 1
        end
        lhs_idx += 1
        rhs_idx += 1
    end
    if lhs_idx <= Int(lhs.len)
        return 1
    elseif rhs_idx <= Int(rhs.len)
        return -1
    end
    return 0
end

function byte_cursor_compare_lookup(lhs::Base.RefValue{ByteCursor}, rhs::Base.RefValue{ByteCursor}, lookup_table::Memory{UInt8})
    return byte_cursor_compare_lookup(lhs[], rhs[], lookup_table)
end

#==========================================================================
  Cursor Equality Operations
==========================================================================#

function byte_cursor_eq(a::ByteCursor, b::ByteCursor)
    return cursor_eq(a, b)
end

function byte_cursor_eq(a::Base.RefValue{ByteCursor}, b::Base.RefValue{ByteCursor})
    return cursor_eq(a[], b[])
end

function byte_cursor_eq_ignore_case(a::ByteCursor, b::ByteCursor)
    return cursor_eq_ignore_case(a, b)
end

function byte_cursor_eq_ignore_case(a::Base.RefValue{ByteCursor}, b::Base.RefValue{ByteCursor})
    return cursor_eq_ignore_case(a[], b[])
end

function byte_cursor_eq_byte_buf(a::ByteCursor, b::ByteBuffer)
    if a.len != b.len
        return false
    end
    if a.len == 0
        return true
    end
    @inbounds for i in 1:Int(a.len)
        if memoryref(a.ptr, i)[] != b.mem[i]
            return false
        end
    end
    return true
end

function byte_cursor_eq_byte_buf(a::Base.RefValue{ByteCursor}, b::Base.RefValue{ByteBuffer})
    return byte_cursor_eq_byte_buf(a[], b[])
end

function byte_cursor_eq_byte_buf_ignore_case(a::ByteCursor, b::ByteBuffer)
    if a.len != b.len
        return false
    end
    if a.len == 0
        return true
    end
    @inbounds for i in 1:Int(a.len)
        av = _ascii_tolower(memoryref(a.ptr, i)[])
        bv = _ascii_tolower(b.mem[i])
        if av != bv
            return false
        end
    end
    return true
end

function byte_cursor_eq_byte_buf_ignore_case(a::Base.RefValue{ByteCursor}, b::Base.RefValue{ByteBuffer})
    return byte_cursor_eq_byte_buf_ignore_case(a[], b[])
end

function byte_cursor_eq_c_str(cursor::ByteCursor, c_str::AbstractString)
    return cursor_eq_string(cursor, c_str)
end

function byte_cursor_eq_c_str(cursor::Base.RefValue{ByteCursor}, c_str::AbstractString)
    return cursor_eq_string(cursor[], c_str)
end

function byte_cursor_eq_c_str_ignore_case(cursor::ByteCursor, c_str::AbstractString)
    return cursor_eq_string_ignore_case(cursor, c_str)
end

function byte_cursor_eq_c_str_ignore_case(cursor::Base.RefValue{ByteCursor}, c_str::AbstractString)
    return cursor_eq_string_ignore_case(cursor[], c_str)
end

#==========================================================================
  Cursor Starts With
==========================================================================#

function byte_cursor_starts_with(input::ByteCursor, prefix::ByteCursor)
    if input.len < prefix.len
        return false
    end
    if prefix.len == 0
        return true
    end
    @inbounds for i in 1:Int(prefix.len)
        if memoryref(input.ptr, i)[] != memoryref(prefix.ptr, i)[]
            return false
        end
    end
    return true
end

function byte_cursor_starts_with(input::Base.RefValue{ByteCursor}, prefix::Base.RefValue{ByteCursor})
    return byte_cursor_starts_with(input[], prefix[])
end

function byte_cursor_starts_with_ignore_case(input::ByteCursor, prefix::ByteCursor)
    if input.len < prefix.len
        return false
    end
    if prefix.len == 0
        return true
    end
    @inbounds for i in 1:Int(prefix.len)
        iv = _ascii_tolower(memoryref(input.ptr, i)[])
        pv = _ascii_tolower(memoryref(prefix.ptr, i)[])
        if iv != pv
            return false
        end
    end
    return true
end

function byte_cursor_starts_with_ignore_case(input::Base.RefValue{ByteCursor}, prefix::Base.RefValue{ByteCursor})
    return byte_cursor_starts_with_ignore_case(input[], prefix[])
end

#==========================================================================
  Cursor Find Operations
==========================================================================#

# Find byte in cursor, returns offset (0-based) or -1 if not found
function _memchr_offset(cursor::ByteCursor, value::UInt8)
    if cursor.len == 0
        return -1
    end
    @inbounds for i in 1:Int(cursor.len)
        if memoryref(cursor.ptr, i)[] == value
            return i - 1  # 0-based offset
        end
    end
    return -1
end

# Check if this is the first run of split (pointing to null sentinel)
function _is_first_split_run(substr::ByteCursor)
    return pointer(substr.ptr) === pointer(memoryref(_null_cursor_mem))
end

function byte_cursor_next_split(input_str::ByteCursor, split_on::UInt8, substr::Base.RefValue{ByteCursor})
    substr_val = substr[]
    first_run = _is_first_split_run(substr_val)

    if !first_run && substr_val.len == 0 &&
            pointer(substr_val.ptr) === pointer(memoryref(_null_terminator_storage))
        substr[] = null_cursor()
        return false
    end

    # Handle empty input
    if input_str.len == 0
        if first_run
            substr[] = ByteCursor(Csize_t(0), memoryref(_null_terminator_storage))
            return true
        end
        substr[] = null_cursor()
        return false
    end

    if first_run
        # First run: start at beginning of input
        substr[] = input_str
    else
        # Subsequent runs: advance past previous split
        # Calculate new position using memory offsets
        input_mem = parent(input_str.ptr)
        input_start = memref_offset(input_str.ptr)
        substr_mem = parent(substr_val.ptr)
        substr_start = memref_offset(substr_val.ptr)

        # New position is after substr + split character
        new_start = substr_start + Int(substr_val.len) + 1
        input_end = input_start + Int(input_str.len)

        if new_start > input_end || new_start < input_start
            substr[] = null_cursor()
            return false
        end

        new_len = input_end - new_start
        if new_len < 0
            substr[] = null_cursor()
            return false
        end
        if new_len == 0
            substr[] = ByteCursor(Csize_t(0), memoryref(_null_terminator_storage))
            return true
        end
        new_ref = memoryref(input_mem, new_start)
        substr[] = ByteCursor(Csize_t(new_len), new_ref)
    end

    # Find next split character
    substr_val = substr[]
    split_offset = _memchr_offset(substr_val, split_on)
    if split_offset >= 0
        # Truncate to position before split character
        substr[] = ByteCursor(Csize_t(split_offset), substr_val.ptr)
    end
    return true
end

function byte_cursor_next_split(input_str::Base.RefValue{ByteCursor}, split_on::UInt8, substr::Base.RefValue{ByteCursor})
    return byte_cursor_next_split(input_str[], split_on, substr)
end

function byte_cursor_next_split(input_str, split_on::Char, substr)
    return byte_cursor_next_split(input_str, UInt8(split_on), substr)
end

function byte_cursor_split_on_char_n(input_str::ByteCursor, split_on::UInt8, n::Integer, output)
    output_list = output isa Base.RefValue ? output[] : output
    output_list === nothing && return OP_ERR
    max_splits = n > 0 ? n : typemax(Int)
    split_count = 0
    substr_ref = Ref{ByteCursor}(null_cursor())
    while split_count <= max_splits && byte_cursor_next_split(input_str, split_on, substr_ref)
        if split_count == max_splits
            # For last split, include everything remaining
            substr_val = substr_ref[]
            input_mem = parent(input_str.ptr)
            if parent(substr_val.ptr) === input_mem
                input_start = memref_offset(input_str.ptr)
                substr_start = memref_offset(substr_val.ptr)
                new_len = input_str.len - Csize_t(substr_start - input_start)
                substr_ref[] = ByteCursor(new_len, substr_val.ptr)
            end
        end
        try
            push!(output_list, substr_ref[])
        catch
            return OP_ERR
        end
        split_count += 1
    end
    return OP_SUCCESS
end

function byte_cursor_split_on_char_n(input_str::Base.RefValue{ByteCursor}, split_on::UInt8, n::Integer, output)
    return byte_cursor_split_on_char_n(input_str[], split_on, n, output)
end

function byte_cursor_split_on_char_n(input_str, split_on::Char, n::Integer, output)
    return byte_cursor_split_on_char_n(input_str, UInt8(split_on), n, output)
end

function byte_cursor_split_on_char(input_str, split_on::UInt8, output)
    return byte_cursor_split_on_char_n(input_str, split_on, 0, output)
end

function byte_cursor_split_on_char(input_str, split_on::Char, output)
    return byte_cursor_split_on_char_n(input_str, UInt8(split_on), 0, output)
end

function byte_cursor_find_exact(input_str::ByteCursor, to_find::ByteCursor, first_find::Base.RefValue{ByteCursor})
    if to_find.len > input_str.len
        return raise_error(ERROR_STRING_MATCH_NOT_FOUND)
    end
    if to_find.len < 1
        return raise_error(ERROR_SHORT_BUFFER)
    end

    first_char = memoryref(to_find.ptr, 1)[]
    working_len = input_str.len
    offset_from_start = 0

    while working_len > 0
        # Find first character
        found = false
        local_idx = 0
        @inbounds for i in 1:Int(working_len)
            if memoryref(input_str.ptr, offset_from_start + i)[] == first_char
                found = true
                local_idx = i - 1
                break
            end
        end
        if !found
            return raise_error(ERROR_STRING_MATCH_NOT_FOUND)
        end

        offset_from_start += local_idx
        working_len -= Csize_t(local_idx)

        if working_len < to_find.len
            return raise_error(ERROR_STRING_MATCH_NOT_FOUND)
        end

        # Check if we have a match
        match = true
        @inbounds for i in 1:Int(to_find.len)
            if memoryref(input_str.ptr, offset_from_start + i)[] != memoryref(to_find.ptr, i)[]
                match = false
                break
            end
        end

        if match
            result_ref = memref_advance(input_str.ptr, offset_from_start)
            first_find[] = ByteCursor(working_len, result_ref)
            return OP_SUCCESS
        end

        offset_from_start += 1
        working_len -= 1
    end
    return raise_error(ERROR_STRING_MATCH_NOT_FOUND)
end

function byte_cursor_find_exact(input_str::Base.RefValue{ByteCursor}, to_find::Base.RefValue{ByteCursor}, first_find::Base.RefValue{ByteCursor})
    return byte_cursor_find_exact(input_str[], to_find[], first_find)
end

#==========================================================================
  Cursor UTF-8 Parse Operations
==========================================================================#

function s_read_unsigned(cursor::ByteCursor, dst::Base.RefValue{UInt64}, base::UInt8)
    val = UInt64(0)
    dst[] = 0
    if cursor.len == 0
        return raise_error(ERROR_INVALID_ARGUMENT)
    end
    table = lookup_table_hex_to_num_get()
    @inbounds for i in 1:Int(cursor.len)
        c = memoryref(cursor.ptr, i)[]
        cval = table[Int(c) + 1]
        if cval >= base
            return raise_error(ERROR_INVALID_ARGUMENT)
        end
        tmp = Ref{UInt64}(0)
        if mul_u64_checked(val, UInt64(base), tmp) != OP_SUCCESS
            return raise_error(ERROR_OVERFLOW_DETECTED)
        end
        val = tmp[]
        if add_u64_checked(val, UInt64(cval), tmp) != OP_SUCCESS
            return raise_error(ERROR_OVERFLOW_DETECTED)
        end
        val = tmp[]
    end
    dst[] = val
    return OP_SUCCESS
end

function byte_cursor_utf8_parse_u64(cursor::ByteCursor, dst::Base.RefValue{UInt64})
    return s_read_unsigned(cursor, dst, UInt8(10))
end

function byte_cursor_utf8_parse_u64_hex(cursor::ByteCursor, dst::Base.RefValue{UInt64})
    return s_read_unsigned(cursor, dst, UInt8(16))
end

#==========================================================================
  Character Classification
==========================================================================#

function isalnum(ch::UInt8)
    return (ch >= UInt8('a') && ch <= UInt8('z')) ||
        (ch >= UInt8('A') && ch <= UInt8('Z')) ||
        (ch >= UInt8('0') && ch <= UInt8('9'))
end

function isalpha(ch::UInt8)
    return (ch >= UInt8('a') && ch <= UInt8('z')) ||
        (ch >= UInt8('A') && ch <= UInt8('Z'))
end

function isdigit(ch::UInt8)
    return ch >= UInt8('0') && ch <= UInt8('9')
end

function isxdigit(ch::UInt8)
    return (ch >= UInt8('0') && ch <= UInt8('9')) ||
        (ch >= UInt8('a') && ch <= UInt8('f')) ||
        (ch >= UInt8('A') && ch <= UInt8('F'))
end

function is_space(ch::UInt8)
    return ch == 0x20 || ch == 0x09 || ch == 0x0a || ch == 0x0b || ch == 0x0c || ch == 0x0d
end

#==========================================================================
  ByteBuffer to Vector Conversion
==========================================================================#

function byte_buffer_as_vector(buf::ByteBuffer)::Vector{UInt8}
    n = Int(buf.len)
    if n == 0
        return UInt8[]
    end
    vec = Vector{UInt8}(undef, n)
    @inbounds for i in 1:n
        vec[i] = buf.mem[i]
    end
    return vec
end

function byte_buffer_as_string(buf::ByteBuffer)::String
    n = Int(buf.len)
    if n == 0
        return ""
    end
    return unsafe_string(pointer(buf.mem), n)
end

#==========================================================================
  Cursor to String Conversion
==========================================================================#

function cursor_to_string(cursor::ByteCursor)
    if cursor.len == 0
        return ""
    end
    mem = parent(cursor.ptr)
    start = memref_offset(cursor.ptr)
    return unsafe_string(pointer(mem, start), Int(cursor.len))
end

Base.String(cursor::ByteCursor) = cursor_to_string(cursor)
