"""
    secure_zero(x)

Best-effort zeroization helper used by Reseau's "secure" cleanup paths.

This is not a cryptographic guarantee: copies made by user code, Julia's runtime,
or the underlying libc/compiler can undermine "guaranteed" erasure. Prefer to
minimize secret lifetimes and avoid unnecessary copies.
"""
function secure_zero(ptr::Ptr{UInt8}, len::Integer)
    if ptr == C_NULL || len <= 0
        return nothing
    end
    ccall(:memset, Ptr{Cvoid}, (Ptr{Cvoid}, Cint, Csize_t), ptr, 0, Csize_t(len))
    return nothing
end

function secure_zero(buf::Vector{UInt8})
    fill!(buf, 0x00)
    return nothing
end

function secure_zero(buf::Memory{UInt8})
    fill!(buf, 0x00)
    return nothing
end

function is_mem_zeroed(buf::Ptr{UInt8}, bufsize::Integer)
    if bufsize <= 0
        return true
    end
    if buf == C_NULL
        return false
    end
    for i in 0:(bufsize - 1)
        if unsafe_load(buf + i) != 0x00
            return false
        end
    end
    return true
end

function _zero_value(T)
    if T <: Ptr
        return T(0)
    end
    if T <: Memory
        return Memory{eltype(T)}(undef, 0)
    end
    if T <: MemoryRef
        # Return a memoryref pointing to the null cursor sentinel
        return memoryref(_null_cursor_mem)
    end
    if T <: Number
        return zero(T)
    end
    if T <: Tuple
        return ntuple(i -> _zero_value(fieldtype(T, i)), fieldcount(T))
    end
    if T isa Union && (Nothing in Base.uniontypes(T))
        return nothing
    end
    if T == Any
        return nothing
    end
    if isstructtype(T)
        field_vals = ntuple(i -> _zero_value(fieldtype(T, i)), fieldcount(T))
        return T(field_vals...)
    end
    try
        return zero(T)
    catch
    end
    try
        return T()
    catch
    end
    return nothing
end

function zero_struct!(obj)
    if obj === nothing
        return nothing
    end
    if ismutable(obj)
        T = typeof(obj)
        for i in 1:fieldcount(T)
            value = _zero_value(fieldtype(T, i))
            try
                setfield!(obj, i, value)
            catch
            end
        end
    end
    return obj
end

function zero_struct!(obj::Base.RefValue{T}) where {T}
    unsafe_store!(Base.unsafe_convert(Ptr{T}, obj), _zero_value(T))
    return obj
end

function zero_struct!(obj::Ptr{T}) where {T}
    if obj == C_NULL
        return nothing
    end
    unsafe_store!(obj, _zero_value(T))
    return nothing
end

function is_zeroed(obj)
    if obj === nothing
        return true
    end
    if ismutable(obj)
        T = typeof(obj)
        for i in 1:fieldcount(T)
            field_val = getfield(obj, i)
            zero_val = _zero_value(fieldtype(T, i))
            if field_val != zero_val
                return false
            end
        end
        return true
    end
    return obj == _zero_value(typeof(obj))
end

function is_zeroed(obj::Base.RefValue{T}) where {T}
    return unsafe_load(Base.unsafe_convert(Ptr{T}, obj)) == _zero_value(T)
end

function is_zeroed(obj::Ptr{T}) where {T}
    if obj == C_NULL
        return true
    end
    return unsafe_load(obj) == _zero_value(T)
end

function zero_array!(arr)
    if arr === nothing
        return nothing
    end
    fill!(arr, zero(eltype(arr)))
    return arr
end
