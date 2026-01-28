# AWS IO Library - PKCS#11 (stub)

@enumx Pkcs11LibBehavior::UInt8 begin
    DEFAULT_BEHAVIOR = 0
    OMIT_INITIALIZE = 1
    STRICT_INITIALIZE_FINALIZE = 2
end

const Pcks11LibBehavior = Pkcs11LibBehavior

struct Pkcs11LibOptions
    filename::ByteCursor
    initialize_finalize_behavior::Pkcs11LibBehavior.T
end

function Pkcs11LibOptions(;
        filename = nothing,
        initialize_finalize_behavior::Pkcs11LibBehavior.T = Pkcs11LibBehavior.DEFAULT_BEHAVIOR,
    )
    cursor = filename === nothing ?
        null_cursor() :
        (filename isa ByteCursor ? filename : ByteCursor(filename))
    return Pkcs11LibOptions(cursor, initialize_finalize_behavior)
end

mutable struct Pkcs11Lib
    options::Pkcs11LibOptions
    shared_lib::SharedLibrary
    function_list::Ptr{Cvoid}
end

Pkcs11Lib(options::Pkcs11LibOptions) = Pkcs11Lib(options, SharedLibrary(), C_NULL)

const _pkcs11_ckr_map = Ref{Dict{UInt64, Int}}(Dict{UInt64, Int}())
const _pkcs11_ckr_loaded = Ref(false)

function _pkcs11_load_ckr_map!()
    _pkcs11_ckr_loaded[] && return nothing
    _pkcs11_ckr_loaded[] = true

    root = normpath(joinpath(@__DIR__, "..", ".."))
    header_path = joinpath(root, "aws-c-io", "source", "pkcs11", "v2.40", "pkcs11.h")
    isfile(header_path) || return nothing

    names = Set(_pkcs11_ckr_names)
    rx = r"^#define\s+CKR_([A-Z0-9_]+)\s+(0x[0-9A-Fa-f]+|[0-9]+)[uUlL]*"
    for line in eachline(header_path)
        m = match(rx, strip(line))
        m === nothing && continue
        name = m.captures[1]
        name in names || continue
        val_str = m.captures[2]
        value = startswith(val_str, "0x") ? parse(UInt64, val_str) : parse(UInt64, val_str)
        code = getfield(@__MODULE__, Symbol("ERROR_IO_PKCS11_CKR_", name))
        _pkcs11_ckr_map[][value] = code
    end
    return nothing
end

function pkcs11_error_from_ckr(rv::Integer)::Int
    _pkcs11_load_ckr_map!()
    code = get(_pkcs11_ckr_map[], UInt64(rv), 0)
    return code == 0 ? ERROR_IO_PKCS11_UNKNOWN_CRYPTOKI_RETURN_VALUE : code
end

function pkcs11_lib_new(options::Pkcs11LibOptions)::Union{Pkcs11Lib, ErrorResult}
    behavior = options.initialize_finalize_behavior
    if behavior != Pkcs11LibBehavior.DEFAULT_BEHAVIOR &&
        behavior != Pkcs11LibBehavior.OMIT_INITIALIZE &&
        behavior != Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end

    lib = Pkcs11Lib(options)
    loaded = if options.filename.len == 0
        shared_library_load_default()
    else
        shared_library_load(String(options.filename))
    end
    loaded isa ErrorResult && return loaded

    lib.shared_lib = loaded

    sym = shared_library_find_symbol(lib.shared_lib, "C_GetFunctionList")
    sym isa ErrorResult && return sym

    fn_list = Ref{Ptr{Cvoid}}(C_NULL)
    rv = ccall(sym, Culong, (Ref{Ptr{Cvoid}},), fn_list)
    if rv != 0
        code = pkcs11_error_from_ckr(rv)
        raise_error(code)
        return ErrorResult(code)
    end
    lib.function_list = fn_list[]
    return lib
end

pkcs11_lib_acquire(lib::Pkcs11Lib) = lib
function pkcs11_lib_release(lib::Pkcs11Lib)
    _ = shared_library_clean_up!(lib.shared_lib)
    return nothing
end
