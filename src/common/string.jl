struct ByteString
    mem::Memory{UInt8}
    len::Int
end

const _static_string_cache = SmallRegistry{String, ByteString}()

@inline function string_len(str::ByteString)
    return str.len
end

@inline function string_bytes(str::ByteString)
    length(str.mem) == 0 && return Ptr{UInt8}(0)
    return pointer(str.mem)
end

@inline string_c_str(str::ByteString) = string_bytes(str)

function string_is_valid(str::ByteString)
    len = str.len
    len < 0 && return false
    len + 1 > length(str.mem) && return false
    ptr = string_bytes(str)
    ptr == Ptr{UInt8}(0) && return false
    return unsafe_load(ptr + len) == 0x00
end

function string_is_valid(::Nothing)
    return false
end

function c_string_is_valid(str::Ptr{UInt8})
    return str != C_NULL
end

function c_string_is_valid(str::AbstractString)
    return str !== nothing
end

function char_is_space(c::UInt8)
    return is_space(c)
end

function string_eq(a::Union{ByteString, Nothing}, b::Union{ByteString, Nothing})
    a === nothing && return b === nothing
    b === nothing && return false
    return memref_eq(memoryref(a.mem), a.len, memoryref(b.mem), b.len)
end

function string_eq_ignore_case(a::Union{ByteString, Nothing}, b::Union{ByteString, Nothing})
    a === nothing && return b === nothing
    b === nothing && return false
    return memref_eq_ignore_case(memoryref(a.mem), a.len, memoryref(b.mem), b.len)
end

function string_eq_byte_cursor(str::Union{ByteString, Nothing}, cur::ByteCursor)
    str === nothing && return cur.len == 0
    return memref_eq(memoryref(str.mem), str.len, cur.ptr, cur.len)
end

function string_eq_byte_cursor_ignore_case(str::Union{ByteString, Nothing}, cur::ByteCursor)
    str === nothing && return cur.len == 0
    return memref_eq_ignore_case(memoryref(str.mem), str.len, cur.ptr, cur.len)
end

function string_eq_byte_buf(str::Union{ByteString, Nothing}, buf::ByteBuffer)
    str === nothing && return buf.len == 0
    return memref_eq(memoryref(str.mem), str.len, memoryref(buf.mem), buf.len)
end

function string_eq_byte_buf_ignore_case(str::Union{ByteString, Nothing}, buf::ByteBuffer)
    str === nothing && return buf.len == 0
    return memref_eq_ignore_case(memoryref(str.mem), str.len, memoryref(buf.mem), buf.len)
end

function string_eq_c_str(str::Union{ByteString, Nothing}, c_str::Ptr{UInt8})
    str === nothing && return c_str == C_NULL
    c_str_len = c_str == C_NULL ? 0 : ccall(:strlen, Csize_t, (Ptr{UInt8},), c_str)
    return ptr_memref_eq(c_str, c_str_len, memoryref(str.mem), str.len)
end

function string_eq_c_str_ignore_case(str::Union{ByteString, Nothing}, c_str::Ptr{UInt8})
    str === nothing && return c_str == C_NULL
    c_str_len = c_str == C_NULL ? 0 : ccall(:strlen, Csize_t, (Ptr{UInt8},), c_str)
    return ptr_memref_eq_ignore_case(c_str, c_str_len, memoryref(str.mem), str.len)
end

function string_eq_c_str(str::Union{ByteString, Nothing}, c_str::AbstractString)
    c_str_ref = Base.cconvert(Cstring, c_str)
    GC.@preserve c_str_ref begin
        c_str_ptr = Base.unsafe_convert(Ptr{UInt8}, c_str_ref)
        return string_eq_c_str(str, c_str_ptr)
    end
end

function string_eq_c_str_ignore_case(str::Union{ByteString, Nothing}, c_str::AbstractString)
    c_str_ref = Base.cconvert(Cstring, c_str)
    GC.@preserve c_str_ref begin
        c_str_ptr = Base.unsafe_convert(Ptr{UInt8}, c_str_ref)
        return string_eq_c_str_ignore_case(str, c_str_ptr)
    end
end

function _string_memory(len::Int)
    total = len + 1
    return Memory{UInt8}(undef, total)
end

function string_new_from_array(bytes::Ptr{UInt8}, len::Integer)
    len_int = Int(len)
    mem = _string_memory(len_int)
    if len_int > 0
        Base.unsafe_copyto!(pointer(mem), bytes, len_int)
    end
    unsafe_store!(pointer(mem) + len_int, 0x00)
    return ByteString(mem, len_int)
end

function string_new_from_array(bytes::AbstractVector{UInt8}, len::Integer = length(bytes))
    GC.@preserve bytes begin
        return string_new_from_array(pointer(bytes), len)
    end
end

function string_new_from_c_str(c_str::Ptr{UInt8})
    precondition(c_str != C_NULL)
    len = ccall(:strlen, Csize_t, (Ptr{UInt8},), c_str)
    return string_new_from_array(c_str, len)
end

function string_new_from_c_str(c_str::AbstractString)
    bytes = codeunits(c_str)
    GC.@preserve bytes begin
        return string_new_from_array(pointer(bytes), length(bytes))
    end
end

function string_new_from_string(str::Union{ByteString, Nothing})
    str === nothing && return nothing
    return string_new_from_array(string_bytes(str), string_len(str))
end

function string_new_from_cursor(cursor::ByteCursor)
    if cursor.len == 0
        return string_new_from_array(Ptr{UInt8}(0), Csize_t(0))
    end
    return string_new_from_array(Ptr{UInt8}(pointer(cursor.ptr)), cursor.len)
end

function string_new_from_buf(buf::ByteBuffer)
    buf.len == 0 && return string_new_from_array(Ptr{UInt8}(0), Csize_t(0))
    return string_new_from_array(pointer(buf.mem), buf.len)
end

# string_destroy is now a no-op - Julia GC handles memory
function string_destroy(str::Union{ByteString, Nothing})
    return nothing
end

function string_destroy_secure(str::Union{ByteString, Nothing})
    str === nothing && return nothing
    ptr = string_bytes(str)
    ptr == Ptr{UInt8}(0) && return nothing
    secure_zero(ptr, string_len(str))
    return nothing
end

function string_compare(a::Union{ByteString, Nothing}, b::Union{ByteString, Nothing})
    a === b && return 0
    a === nothing && return -1
    b === nothing && return 1
    len_a = string_len(a)
    len_b = string_len(b)
    min_len = len_a < len_b ? len_a : len_b
    if min_len > 0
        for i in 0:(min_len - 1)
            ab = unsafe_load(string_bytes(a) + i)
            bb = unsafe_load(string_bytes(b) + i)
            if ab != bb
                return ab < bb ? -1 : 1
            end
        end
    end
    len_a == len_b && return 0
    return len_a > len_b ? 1 : -1
end

function array_list_comparator_string(a::ByteString, b::ByteString)
    return string_compare(a, b) < 0
end

function byte_buf_write_from_whole_string(buf, src::Union{ByteString, Nothing})
    src === nothing && return false
    return byte_buf_write(buf, string_bytes(src), string_len(src))
end

function byte_cursor_from_string(src::Union{ByteString, Nothing})
    src === nothing && return null_cursor()
    src.len == 0 && return null_cursor()
    return ByteCursor(Csize_t(src.len), memoryref(src.mem))
end

function byte_cursor_from_string(src::AbstractString)
    mem = Memory{UInt8}(codeunits(src))
    return ByteCursor(Csize_t(length(mem)), memoryref(mem))
end

function string_clone_or_reuse(str::Union{ByteString, Nothing})
    str === nothing && return nothing
    # In the new simplified model, we just return the same string
    # since Julia GC manages memory
    return str
end

function secure_strlen(str::Ptr{UInt8}, max_len::Integer, out_len::Base.RefValue{Csize_t})
    if str == C_NULL || out_len === nothing
        return raise_error(ERROR_INVALID_ARGUMENT)
    end
    limit = Csize_t(max_len)
    for i in 0:(limit - 1)
        if unsafe_load(str + i) == 0x00
            out_len[] = Csize_t(i)
            return OP_SUCCESS
        end
    end
    return raise_error(ERROR_C_STRING_BUFFER_NOT_NULL_TERMINATED)
end

function secure_strlen(str::AbstractString, max_len::Integer, out_len::Base.RefValue{Csize_t})
    bytes = codeunits(str)
    limit = min(length(bytes), max_len)
    for i in 1:limit
        if bytes[i] == 0x00
            out_len[] = Csize_t(i - 1)
            return OP_SUCCESS
        end
    end
    if limit < max_len
        out_len[] = Csize_t(limit)
        return OP_SUCCESS
    end
    return raise_error(ERROR_C_STRING_BUFFER_NOT_NULL_TERMINATED)
end

function _static_string_value(literal::AbstractString)
    return get(
        () -> begin
            bytes = codeunits(literal)
            len = length(bytes)
            mem = Memory{UInt8}(undef, len + 1)
            if len > 0
                GC.@preserve bytes begin
                    Base.unsafe_copyto!(pointer(mem), pointer(bytes), len)
                end
            end
            unsafe_store!(pointer(mem) + len, 0x00)
            return ByteString(mem, len)
        end, _static_string_cache, String(literal)
    )
end

function static_string_from_literal(literal::AbstractString)
    return _static_string_value(literal)
end
