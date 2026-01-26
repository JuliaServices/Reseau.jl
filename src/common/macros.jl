LIKELY(x) = x
UNLIKELY(x) = x

function align_round_up(value::Integer, alignment::Integer)
    alignment <= 0 && return value
    return (value + (alignment - 1)) & ~(alignment - 1)
end
