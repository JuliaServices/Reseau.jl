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
