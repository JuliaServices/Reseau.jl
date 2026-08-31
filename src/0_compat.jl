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

# The calling convention for Win32/Winsock entry points.
#
# On 32-bit Windows every Win32 function is `__stdcall`: the callee pops the
# arguments before it returns. Julia's default `ccall` convention is cdecl,
# where the caller pops them instead, so a plain `ccall` into Win32 leaves the
# stack skewed by the argument size on every single call. The damage accumulates
# and surfaces as an access violation somewhere unrelated, which makes it look
# like a Julia bug rather than an ABI mismatch.
#
# On 64-bit Windows, and on every other supported platform, there is only one
# calling convention, so this resolves to the default and nothing changes.
const WIN32_CCONV = (Sys.iswindows() && Sys.WORD_SIZE == 32) ? :stdcall : :cdecl

"""
    @win32_cconv ccall((:Func, "Ws2_32"), Ret, (ArgTypes...), args...)

Apply [`WIN32_CCONV`](@ref) to a `ccall` written in positional form.

Julia requires the calling convention to be a literal in the `ccall` surface
syntax, so it cannot be supplied by a constant at the call site. This macro
splices it in at macro-expansion time, leaving the wrapped expression otherwise
untouched. Use it for every Win32/Winsock call that is not already going
through [`@gcsafe_win32_ccall`](@ref).
"""
macro win32_cconv(expr)
    (Meta.isexpr(expr, :call) && expr.args[1] === :ccall) ||
        throw(ArgumentError("@win32_cconv expects a positional `ccall(...)` expression"))
    args = copy(expr.args)
    # ccall(target, [cconv,] rettype, (argtypes...), args...)
    insert!(args, 3, WIN32_CCONV)
    return esc(Expr(:call, args...))
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

"""
    @gcsafe_win32_ccall ...

[`@gcsafe_ccall`](@ref) for Win32/Winsock entry points: identical, except that
the call is made with [`WIN32_CCONV`](@ref) instead of the platform default.

Safe to use on shared code paths that call the same symbol on other platforms
(`inet_pton`, for instance) — off 32-bit Windows the convention is the default
one, so those callers are unaffected.
"""
macro gcsafe_win32_ccall end

if HAS_CCALL_GCSAFE
    function _gcsafe_ccall_lower(convention, expr)
        exprs = Any[:(gc_safe = true), expr]
        return Base.ccall_macro_lower(convention, Base.ccall_macro_parse(exprs)...)
    end
else
    function _gcsafe_ccall_macro_lower(convention, func, rettype, types, args, nreq)
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

        # `convention === nothing` keeps the platform default by omitting the
        # argument entirely, which is what every non-Win32 caller wants.
        #
        # Otherwise the convention goes in as a bare symbol in the `ccall`
        # surface syntax, escaped so that it survives macro hygiene: the
        # expression this macro returns is otherwise unescaped, and an
        # unescaped symbol here would come out qualified as `Reseau.stdcall`,
        # which lowering does not recognise as a convention and instead reads
        # as the return type.
        #
        # The `Expr(:cconv, convention, nreq)` node that
        # `Base.ccall_macro_lower` emits is deliberately not used: on Julia
        # 1.10 and 1.11 that node only accepts the `:ccall` marker, and any
        # other convention fails to lower ("expected QuoteNode, got a value of
        # type Expr"). Escaped surface syntax works on every supported version.
        inner_ccall = if convention === nothing
            :(ccall(
                $(esc(func)), $(esc(rettype)), $(Expr(:tuple, map(esc, types)...)),
                $(unsafe_convert_args...)
            ))
        else
            Expr(
                :call, :ccall, esc(func), esc(convention),
                esc(rettype), Expr(:tuple, map(esc, types)...),
                unsafe_convert_args...,
            )
        end

        call = quote
            $(unsafe_convert_exprs...)

            gc_state = @ccall(jl_gc_safe_enter()::Int8)
            ret = $inner_ccall
            @ccall(jl_gc_safe_leave(gc_state::Int8)::Cvoid)
            ret
        end

        return quote
            @inline
            $(cconvert_exprs...)
            GC.@preserve $(cconvert_args...) $(call)
        end
    end

    function _gcsafe_ccall_lower(convention, expr)
        return _gcsafe_ccall_macro_lower(convention, Base.ccall_macro_parse(expr)...)
    end
end

macro gcsafe_ccall(expr)
    return _gcsafe_ccall_lower(HAS_CCALL_GCSAFE ? :ccall : nothing, expr)
end

macro gcsafe_win32_ccall(expr)
    return _gcsafe_ccall_lower(WIN32_CCONV, expr)
end
