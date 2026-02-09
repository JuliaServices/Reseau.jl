const SIZE_MAX = typemax(Csize_t)

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

function mul_size_saturating(a::Csize_t, b::Csize_t)
    r, overflow = Base.mul_with_overflow(a, b)
    return overflow ? typemax(Csize_t) : r
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

function sub_size_saturating(a::Csize_t, b::Csize_t)
    r, overflow = Base.sub_with_overflow(a, b)
    return overflow ? Csize_t(0) : r
end

