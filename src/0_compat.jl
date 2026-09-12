# Compat helpers for byte buffers on Julia versions before `Memory` exists.

if VERSION < v"1.11"
    const ByteMemory = Vector{UInt8}
    const MutableByteBuffer = Union{
        Vector{UInt8},
        Base.FastContiguousSubArray{UInt8,1,<:Array},
    }
    bytememory(n::Integer)::ByteMemory = Vector{UInt8}(undef, Int(n))
else
    const ByteMemory = Memory{UInt8}
    const MutableByteBuffer = Union{
        Vector{UInt8},
        ByteMemory,
        Base.FastContiguousSubArray{UInt8,1,<:Array},
        Base.FastContiguousSubArray{UInt8,1,<:Memory},
    }
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

"""
    @stdcall_ccall f(args...)::RetType
    @gcsafe_stdcall_ccall f(args...)::RetType

Call a Win32 API function with `@ccall` syntax under the `stdcall` convention.

Win32 exports (kernel32, ws2_32, mswsock, iphlpapi) are `WINAPI`, which is
`stdcall` on i686; a default-convention call there corrupts the stack on
return. Julia honors `stdcall` only when targeting i686 and ignores it
everywhere else, so every Win32 call site can carry the annotation
unconditionally. The macros lower to the classic `ccall` form, which is the
only one that can express a convention.

Function specs: `"Lib".f` or `Lib.f` for a library and symbol, bare `f` for
the process, and `\$ptr` for a function pointer.

`@gcsafe_stdcall_ccall` additionally brackets the call with
`jl_gc_safe_enter` / `jl_gc_safe_leave`, the same transition native
`gc_safe = true` inlines, exactly like [`@gcsafe_ccall`](@ref).
"""
macro stdcall_ccall end
macro gcsafe_stdcall_ccall end

function _parse_win32_ccall(ex)
    Meta.isexpr(ex, :(::), 2) || throw(ArgumentError("expected `f(args...)::RetType`"))
    call, rettype = ex.args[1], ex.args[2]
    Meta.isexpr(call, :call) || throw(ArgumentError("expected a function call"))
    f = call.args[1]
    func = Meta.isexpr(f, :.) ? Expr(:tuple, f.args[2], f.args[1]) :
           Meta.isexpr(f, :$) ? f.args[1] :
           f isa Symbol ? QuoteNode(f) :
           throw(ArgumentError("bad function spec `$f`"))
    types, args = Any[], Any[]
    for a in call.args[2:end]
        Meta.isexpr(a, :(::), 2) || throw(ArgumentError("argument `$a` needs a type"))
        push!(args, a.args[1])
        push!(types, a.args[2])
    end
    return func, rettype, types, args
end

function _emit_win32_ccall(ex, gcsafe::Bool)
    func, rettype, types, args = _parse_win32_ccall(ex)
    roots = [gensym(:root) for _ in args]
    ptrs = [gensym(:ptr) for _ in args]
    pre = [:($(roots[i]) = Base.cconvert($(esc(types[i])), $(esc(args[i])))) for i in eachindex(args)]
    conv = [:($(ptrs[i]) = Base.unsafe_convert($(esc(types[i])), $(roots[i]))) for i in eachindex(args)]
    # `stdcall` must be escaped: hygiene would otherwise rename it and lowering
    # would read the return type as the convention.
    call = Expr(:call, :ccall, esc(func), esc(:stdcall), esc(rettype),
                Expr(:tuple, map(esc, types)...), ptrs...)
    # Nothing between enter and leave may allocate, throw, or yield; every
    # conversion (including the Cstring NUL scan, which throws) is hoisted above.
    body = gcsafe ? quote
        $(conv...)
        gc_state = ccall(:jl_gc_safe_enter, Int8, ())
        ret = $call
        ccall(:jl_gc_safe_leave, Cvoid, (Int8,), gc_state)
        ret
    end : quote
        $(conv...)
        $call
    end
    return quote
        @inline
        $(pre...)
        GC.@preserve $(roots...) $body
    end
end

macro stdcall_ccall(ex)
    return _emit_win32_ccall(ex, false)
end

macro gcsafe_stdcall_ccall(ex)
    return _emit_win32_ccall(ex, true)
end
