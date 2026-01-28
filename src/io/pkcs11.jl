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
end

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
    _ = options
    raise_error(ERROR_UNIMPLEMENTED)
    return ErrorResult(ERROR_UNIMPLEMENTED)
end

pkcs11_lib_acquire(lib::Pkcs11Lib) = lib
pkcs11_lib_release(::Pkcs11Lib) = nothing
