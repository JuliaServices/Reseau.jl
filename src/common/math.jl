const SIZE_BITS = Sys.WORD_SIZE
const SIZE_MAX = typemax(Csize_t)
const SIZE_MAX_POWER_OF_TWO = UInt(1) << (SIZE_BITS - 1)

function mul_u64_saturating(a::UInt64, b::UInt64)
    r, overflow = Base.mul_with_overflow(a, b)
    return overflow ? typemax(UInt64) : r
end

function mul_u64_checked(a::UInt64, b::UInt64, r::Base.RefValue{UInt64})
    val, overflow = Base.mul_with_overflow(a, b)
    if overflow
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    r[] = val
    return OP_SUCCESS
end

function mul_u32_saturating(a::UInt32, b::UInt32)
    r, overflow = Base.mul_with_overflow(a, b)
    return overflow ? typemax(UInt32) : r
end

function mul_u32_checked(a::UInt32, b::UInt32, r::Base.RefValue{UInt32})
    val, overflow = Base.mul_with_overflow(a, b)
    if overflow
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    r[] = val
    return OP_SUCCESS
end

function add_u64_saturating(a::UInt64, b::UInt64)
    r, overflow = Base.add_with_overflow(a, b)
    return overflow ? typemax(UInt64) : r
end

function add_u64_checked(a::UInt64, b::UInt64, r::Base.RefValue{UInt64})
    val, overflow = Base.add_with_overflow(a, b)
    if overflow
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    r[] = val
    return OP_SUCCESS
end

function add_u32_saturating(a::UInt32, b::UInt32)
    r, overflow = Base.add_with_overflow(a, b)
    return overflow ? typemax(UInt32) : r
end

function add_u32_checked(a::UInt32, b::UInt32, r::Base.RefValue{UInt32})
    val, overflow = Base.add_with_overflow(a, b)
    if overflow
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    r[] = val
    return OP_SUCCESS
end

function sub_u64_saturating(a::UInt64, b::UInt64)
    r, overflow = Base.sub_with_overflow(a, b)
    return overflow ? UInt64(0) : r
end

function sub_u64_checked(a::UInt64, b::UInt64, r::Base.RefValue{UInt64})
    val, overflow = Base.sub_with_overflow(a, b)
    if overflow
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    r[] = val
    return OP_SUCCESS
end

function sub_u32_saturating(a::UInt32, b::UInt32)
    r, overflow = Base.sub_with_overflow(a, b)
    return overflow ? UInt32(0) : r
end

function sub_u32_checked(a::UInt32, b::UInt32, r::Base.RefValue{UInt32})
    val, overflow = Base.sub_with_overflow(a, b)
    if overflow
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    r[] = val
    return OP_SUCCESS
end

function mul_size_saturating(a::Csize_t, b::Csize_t)
    r, overflow = Base.mul_with_overflow(a, b)
    return overflow ? typemax(Csize_t) : r
end

function mul_size_checked(a::Csize_t, b::Csize_t, r::Base.RefValue{Csize_t})
    val, overflow = Base.mul_with_overflow(a, b)
    if overflow
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    r[] = val
    return OP_SUCCESS
end

function add_size_saturating(a::Csize_t, b::Csize_t)
    r, overflow = Base.add_with_overflow(a, b)
    return overflow ? typemax(Csize_t) : r
end

function add_size_checked(a::Csize_t, b::Csize_t, r::Base.RefValue{Csize_t})
    val, overflow = Base.add_with_overflow(a, b)
    if overflow
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    r[] = val
    return OP_SUCCESS
end

function add_size_checked_varargs(num::Integer, r::Base.RefValue{Csize_t}, args...)
    total = Csize_t(0)
    if length(args) != num
        return OP_ERR
    end
    for val in args
        tmp = Ref{Csize_t}(0)
        if add_size_checked(total, Csize_t(val), tmp) != OP_SUCCESS
            return OP_ERR
        end
        total = tmp[]
    end
    r[] = total
    return OP_SUCCESS
end

function sub_size_saturating(a::Csize_t, b::Csize_t)
    r, overflow = Base.sub_with_overflow(a, b)
    return overflow ? Csize_t(0) : r
end

function sub_size_checked(a::Csize_t, b::Csize_t, r::Base.RefValue{Csize_t})
    val, overflow = Base.sub_with_overflow(a, b)
    if overflow
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    r[] = val
    return OP_SUCCESS
end

function is_power_of_two(x::Csize_t)
    return x != 0 && (x & (x - 1)) == 0
end

function round_up_to_power_of_two(n::Csize_t, result::Base.RefValue{Csize_t})
    if n == 0
        result[] = 1
        return OP_SUCCESS
    end
    if n > SIZE_MAX_POWER_OF_TWO
        return raise_error(ERROR_OVERFLOW_DETECTED)
    end
    value = Csize_t(1)
    while value < n
        value <<= 1
    end
    result[] = value
    return OP_SUCCESS
end

clz_u32(n::UInt32) = n == 0 ? 32 : leading_zeros(n)
clz_i32(n::Int32) = clz_u32(reinterpret(UInt32, n))
clz_u64(n::UInt64) = n == 0 ? 64 : leading_zeros(n)
clz_i64(n::Int64) = clz_u64(reinterpret(UInt64, n))
clz_size(n::Csize_t) = n == 0 ? Sys.WORD_SIZE : leading_zeros(n)

ctz_u32(n::UInt32) = n == 0 ? 32 : trailing_zeros(n)
ctz_i32(n::Int32) = ctz_u32(reinterpret(UInt32, n))
ctz_u64(n::UInt64) = n == 0 ? 64 : trailing_zeros(n)
ctz_i64(n::Int64) = ctz_u64(reinterpret(UInt64, n))
ctz_size(n::Csize_t) = n == 0 ? Sys.WORD_SIZE : trailing_zeros(n)

min_u8(a::UInt8, b::UInt8) = min(a, b)
max_u8(a::UInt8, b::UInt8) = max(a, b)
min_i8(a::Int8, b::Int8) = min(a, b)
max_i8(a::Int8, b::Int8) = max(a, b)
min_u16(a::UInt16, b::UInt16) = min(a, b)
max_u16(a::UInt16, b::UInt16) = max(a, b)
min_i16(a::Int16, b::Int16) = min(a, b)
max_i16(a::Int16, b::Int16) = max(a, b)
min_u32(a::UInt32, b::UInt32) = min(a, b)
max_u32(a::UInt32, b::UInt32) = max(a, b)
min_i32(a::Int32, b::Int32) = min(a, b)
max_i32(a::Int32, b::Int32) = max(a, b)
min_u64(a::UInt64, b::UInt64) = min(a, b)
max_u64(a::UInt64, b::UInt64) = max(a, b)
min_i64(a::Int64, b::Int64) = min(a, b)
max_i64(a::Int64, b::Int64) = max(a, b)
min_size(a::Csize_t, b::Csize_t) = min(a, b)
max_size(a::Csize_t, b::Csize_t) = max(a, b)
min_int(a::Int, b::Int) = min(a, b)
max_int(a::Int, b::Int) = max(a, b)
min_float(a::Float32, b::Float32) = min(a, b)
max_float(a::Float32, b::Float32) = max(a, b)
min_double(a::Float64, b::Float64) = min(a, b)
max_double(a::Float64, b::Float64) = max(a, b)
