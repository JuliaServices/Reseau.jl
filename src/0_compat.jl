# Compat helpers for byte buffers on Julia versions before `Memory` exists.

if VERSION < v"1.11"
    const ByteMemory = Vector{UInt8}
    bytememory(n::Integer)::ByteMemory = Vector{UInt8}(undef, Int(n))
else
    const ByteMemory = Memory{UInt8}
    bytememory(n::Integer)::ByteMemory = Memory{UInt8}(undef, Int(n))
end

# Compat wrapper for `@ccall gc_safe = true` on Julia versions that do not
# understand the native syntax yet.

const HAS_CCALL_GCSAFE = VERSION >= v"1.13.0-DEV.70" || v"1.12-DEV.2029" <= VERSION < v"1.13-"

"""
    @gcsafe_ccall ...

Call a foreign function like `@ccall`, but mark it safe for the GC to run.

On Julia versions with native `gc_safe = true` support this lowers directly to
the built-in form. On older Julia versions it wraps the inner `ccall` with
`jl_gc_safe_enter` / `jl_gc_safe_leave`.
"""
macro gcsafe_ccall end

if HAS_CCALL_GCSAFE
    macro gcsafe_ccall(expr)
        exprs = Any[:(gc_safe = true), expr]
        return Base.ccall_macro_lower((:ccall), Base.ccall_macro_parse(exprs)...)
    end
else
    function _gcsafe_ccall_macro_lower(func, rettype, types, args, nreq)
        _ = nreq

        cconvert_exprs = Any[]
        cconvert_args = Any[]
        for (typ, arg) in zip(types, args)
            var = gensym("$(func)_cconvert")
            push!(cconvert_args, var)
            push!(cconvert_exprs, :($var = Base.cconvert($(esc(typ)), $(esc(arg)))))
        end

        unsafe_convert_exprs = Any[]
        unsafe_convert_args = Any[]
        for (typ, arg) in zip(types, cconvert_args)
            var = gensym("$(func)_unsafe_convert")
            push!(unsafe_convert_args, var)
            push!(unsafe_convert_exprs, :($var = Base.unsafe_convert($(esc(typ)), $arg)))
        end

        call = quote
            $(unsafe_convert_exprs...)

            gc_state = @ccall(jl_gc_safe_enter()::Int8)
            ret = ccall(
                $(esc(func)), $(esc(rettype)), $(Expr(:tuple, map(esc, types)...)),
                $(unsafe_convert_args...)
            )
            @ccall(jl_gc_safe_leave(gc_state::Int8)::Cvoid)
            ret
        end

        return quote
            @inline
            $(cconvert_exprs...)
            GC.@preserve $(cconvert_args...) $(call)
        end
    end

    macro gcsafe_ccall(expr)
        return _gcsafe_ccall_macro_lower(Base.ccall_macro_parse(expr)...)
    end
end
