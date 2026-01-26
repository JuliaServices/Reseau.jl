mutable struct RefCounted{T,OnZero}
    @atomic count::Int
    value::T
    on_zero::OnZero
end

function RefCounted(value::T, on_zero::OnZero) where {T,OnZero}
    return RefCounted{T,OnZero}(1, value, on_zero)
end

@inline function acquire!(ref::RefCounted)
    @atomic ref.count += 1
    return ref.value
end

function release!(ref::RefCounted)
    new = (@atomic ref.count -= 1)
    new == 0 && ref.on_zero(ref.value)
    return new
end
