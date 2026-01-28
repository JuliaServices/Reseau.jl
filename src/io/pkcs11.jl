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

function pkcs11_lib_new(options::Pkcs11LibOptions)::Union{Pkcs11Lib, ErrorResult}
    _ = options
    raise_error(ERROR_UNIMPLEMENTED)
    return ErrorResult(ERROR_UNIMPLEMENTED)
end

pkcs11_lib_acquire(lib::Pkcs11Lib) = lib
pkcs11_lib_release(::Pkcs11Lib) = nothing
