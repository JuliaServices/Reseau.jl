# AWS IO Library - PKCS#11 (stub)

@enumx Pkcs11LibBehavior::UInt8 begin
    DEFAULT_BEHAVIOR = 0
    OMIT_INITIALIZE = 1
    STRICT_INITIALIZE_FINALIZE = 2
end

const Pcks11LibBehavior = Pkcs11LibBehavior

const CK_RV = Culong
const CK_ULONG = Culong
const CK_FLAGS = CK_ULONG
const CK_BBOOL = UInt8
const CK_SLOT_ID = CK_ULONG
const CK_SESSION_HANDLE = CK_ULONG
const CK_OBJECT_HANDLE = CK_ULONG
const CK_OBJECT_CLASS = CK_ULONG
const CK_KEY_TYPE = CK_ULONG
const CK_ATTRIBUTE_TYPE = CK_ULONG
const CK_MECHANISM_TYPE = CK_ULONG

const CKR_OK = CK_RV(0)
const CKR_CRYPTOKI_ALREADY_INITIALIZED = CK_RV(0x00000191)
const CKR_FUNCTION_NOT_SUPPORTED = CK_RV(0x00000054)
const CKR_USER_ALREADY_LOGGED_IN = CK_RV(0x00000100)
const CKU_USER = CK_ULONG(0x1)
const CKU_SO = CK_ULONG(0x0)
const CKF_OS_LOCKING_OK = CK_FLAGS(0x00000002)
const CKF_SERIAL_SESSION = CK_FLAGS(0x00000004)
const CKF_RW_SESSION = CK_FLAGS(0x00000002)
const CKF_TOKEN_INITIALIZED = CK_FLAGS(0x00000400)
const CK_TRUE = CK_BBOOL(1)
const CK_FALSE = CK_BBOOL(0)
const CK_INVALID_HANDLE = CK_OBJECT_HANDLE(0)
const CKO_PRIVATE_KEY = CK_OBJECT_CLASS(0x00000003)
const CKA_CLASS = CK_ATTRIBUTE_TYPE(0x00000000)
const CKA_SIGN = CK_ATTRIBUTE_TYPE(0x00000108)
const CKA_VERIFY = CK_ATTRIBUTE_TYPE(0x00000105)
const CKA_MODULUS_BITS = CK_ATTRIBUTE_TYPE(0x00000120)
const CKA_LABEL = CK_ATTRIBUTE_TYPE(0x00000003)
const CKA_ID = CK_ATTRIBUTE_TYPE(0x00000102)
const CKA_EC_PARAMS = CK_ATTRIBUTE_TYPE(0x00000180)
const CKA_EXTRACTABLE = CK_ATTRIBUTE_TYPE(0x00000162)
const CKA_KEY_TYPE = CK_ATTRIBUTE_TYPE(0x00000100)
const CKK_RSA = CK_KEY_TYPE(0x00000000)
const CKK_EC = CK_KEY_TYPE(0x00000003)
const CKK_GENERIC_SECRET = CK_KEY_TYPE(0x00000010)
const CKM_RSA_PKCS = CK_MECHANISM_TYPE(0x00000001)
const CKM_RSA_PKCS_KEY_PAIR_GEN = CK_MECHANISM_TYPE(0x00000000)
const CKM_EC_KEY_PAIR_GEN = CK_MECHANISM_TYPE(0x00001040)
const CKM_ECDSA = CK_MECHANISM_TYPE(0x00001041)

const TLS_HASH_SHA1 = UInt8(1)
const TLS_HASH_SHA224 = UInt8(2)
const TLS_HASH_SHA256 = UInt8(3)
const TLS_HASH_SHA384 = UInt8(4)
const TLS_HASH_SHA512 = UInt8(5)
const TLS_SIGNATURE_RSA = UInt8(1)
const TLS_SIGNATURE_ECDSA = UInt8(2)

const AWS_SUPPORTED_CRYPTOKI_VERSION_MAJOR = UInt8(2)
const AWS_MIN_SUPPORTED_CRYPTOKI_VERSION_MINOR = UInt8(20)

struct CK_VERSION
    major::UInt8
    minor::UInt8
end

struct CK_INFO
    cryptokiVersion::CK_VERSION
    manufacturerID::NTuple{32, UInt8}
    flags::CK_FLAGS
    libraryDescription::NTuple{32, UInt8}
    libraryVersion::CK_VERSION
end

struct CK_TOKEN_INFO
    label::NTuple{32, UInt8}
    manufacturerID::NTuple{32, UInt8}
    model::NTuple{16, UInt8}
    serialNumber::NTuple{16, UInt8}
    flags::CK_FLAGS
    ulMaxSessionCount::CK_ULONG
    ulSessionCount::CK_ULONG
    ulMaxRwSessionCount::CK_ULONG
    ulRwSessionCount::CK_ULONG
    ulMaxPinLen::CK_ULONG
    ulMinPinLen::CK_ULONG
    ulTotalPublicMemory::CK_ULONG
    ulFreePublicMemory::CK_ULONG
    ulTotalPrivateMemory::CK_ULONG
    ulFreePrivateMemory::CK_ULONG
    hardwareVersion::CK_VERSION
    firmwareVersion::CK_VERSION
    utcTime::NTuple{16, UInt8}
end

struct CK_ATTRIBUTE
    type::CK_ATTRIBUTE_TYPE
    pValue::Ptr{Cvoid}
    ulValueLen::CK_ULONG
end

struct CK_MECHANISM
    mechanism::CK_MECHANISM_TYPE
    pParameter::Ptr{Cvoid}
    ulParameterLen::CK_ULONG
end

struct CK_C_INITIALIZE_ARGS
    CreateMutex::Ptr{Cvoid}
    DestroyMutex::Ptr{Cvoid}
    LockMutex::Ptr{Cvoid}
    UnlockMutex::Ptr{Cvoid}
    flags::CK_FLAGS
    pReserved::Ptr{Cvoid}
end

struct CK_FUNCTION_LIST
    version::CK_VERSION
    C_Initialize::Ptr{Cvoid}
    C_Finalize::Ptr{Cvoid}
    C_GetInfo::Ptr{Cvoid}
    C_GetFunctionList::Ptr{Cvoid}
    C_GetSlotList::Ptr{Cvoid}
    C_GetSlotInfo::Ptr{Cvoid}
    C_GetTokenInfo::Ptr{Cvoid}
    C_GetMechanismList::Ptr{Cvoid}
    C_GetMechanismInfo::Ptr{Cvoid}
    C_InitToken::Ptr{Cvoid}
    C_InitPIN::Ptr{Cvoid}
    C_SetPIN::Ptr{Cvoid}
    C_OpenSession::Ptr{Cvoid}
    C_CloseSession::Ptr{Cvoid}
    C_CloseAllSessions::Ptr{Cvoid}
    C_GetSessionInfo::Ptr{Cvoid}
    C_GetOperationState::Ptr{Cvoid}
    C_SetOperationState::Ptr{Cvoid}
    C_Login::Ptr{Cvoid}
    C_Logout::Ptr{Cvoid}
    C_CreateObject::Ptr{Cvoid}
    C_CopyObject::Ptr{Cvoid}
    C_DestroyObject::Ptr{Cvoid}
    C_GetObjectSize::Ptr{Cvoid}
    C_GetAttributeValue::Ptr{Cvoid}
    C_SetAttributeValue::Ptr{Cvoid}
    C_FindObjectsInit::Ptr{Cvoid}
    C_FindObjects::Ptr{Cvoid}
    C_FindObjectsFinal::Ptr{Cvoid}
    C_EncryptInit::Ptr{Cvoid}
    C_Encrypt::Ptr{Cvoid}
    C_EncryptUpdate::Ptr{Cvoid}
    C_EncryptFinal::Ptr{Cvoid}
    C_DecryptInit::Ptr{Cvoid}
    C_Decrypt::Ptr{Cvoid}
    C_DecryptUpdate::Ptr{Cvoid}
    C_DecryptFinal::Ptr{Cvoid}
    C_DigestInit::Ptr{Cvoid}
    C_Digest::Ptr{Cvoid}
    C_DigestUpdate::Ptr{Cvoid}
    C_DigestKey::Ptr{Cvoid}
    C_DigestFinal::Ptr{Cvoid}
    C_SignInit::Ptr{Cvoid}
    C_Sign::Ptr{Cvoid}
    C_SignUpdate::Ptr{Cvoid}
    C_SignFinal::Ptr{Cvoid}
    C_SignRecoverInit::Ptr{Cvoid}
    C_SignRecover::Ptr{Cvoid}
    C_VerifyInit::Ptr{Cvoid}
    C_Verify::Ptr{Cvoid}
    C_VerifyUpdate::Ptr{Cvoid}
    C_VerifyFinal::Ptr{Cvoid}
    C_VerifyRecoverInit::Ptr{Cvoid}
    C_VerifyRecover::Ptr{Cvoid}
    C_DigestEncryptUpdate::Ptr{Cvoid}
    C_DecryptDigestUpdate::Ptr{Cvoid}
    C_SignEncryptUpdate::Ptr{Cvoid}
    C_DecryptVerifyUpdate::Ptr{Cvoid}
    C_GenerateKey::Ptr{Cvoid}
    C_GenerateKeyPair::Ptr{Cvoid}
    C_WrapKey::Ptr{Cvoid}
    C_UnwrapKey::Ptr{Cvoid}
    C_DeriveKey::Ptr{Cvoid}
    C_SeedRandom::Ptr{Cvoid}
    C_GenerateRandom::Ptr{Cvoid}
    C_GetFunctionStatus::Ptr{Cvoid}
    C_CancelFunction::Ptr{Cvoid}
    C_WaitForSlotEvent::Ptr{Cvoid}
end

function _pkcs11_function_list_stub(;
        version = CK_VERSION(AWS_SUPPORTED_CRYPTOKI_VERSION_MAJOR, AWS_MIN_SUPPORTED_CRYPTOKI_VERSION_MINOR),
        C_Initialize::Ptr{Cvoid} = C_NULL,
        C_Finalize::Ptr{Cvoid} = C_NULL,
        C_GetInfo::Ptr{Cvoid} = C_NULL,
        C_GetFunctionList::Ptr{Cvoid} = C_NULL,
        C_GetSlotList::Ptr{Cvoid} = C_NULL,
        C_GetTokenInfo::Ptr{Cvoid} = C_NULL,
        C_OpenSession::Ptr{Cvoid} = C_NULL,
        C_CloseSession::Ptr{Cvoid} = C_NULL,
        C_Login::Ptr{Cvoid} = C_NULL,
        C_GetAttributeValue::Ptr{Cvoid} = C_NULL,
        C_FindObjectsInit::Ptr{Cvoid} = C_NULL,
        C_FindObjects::Ptr{Cvoid} = C_NULL,
        C_FindObjectsFinal::Ptr{Cvoid} = C_NULL,
        C_DecryptInit::Ptr{Cvoid} = C_NULL,
        C_Decrypt::Ptr{Cvoid} = C_NULL,
        C_SignInit::Ptr{Cvoid} = C_NULL,
        C_Sign::Ptr{Cvoid} = C_NULL,
    )
    return CK_FUNCTION_LIST(
        version,
        C_Initialize,
        C_Finalize,
        C_GetInfo,
        C_GetFunctionList,
        C_GetSlotList,
        C_NULL,
        C_GetTokenInfo,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_OpenSession,
        C_CloseSession,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_Login,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_GetAttributeValue,
        C_NULL,
        C_FindObjectsInit,
        C_FindObjects,
        C_FindObjectsFinal,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_DecryptInit,
        C_Decrypt,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_SignInit,
        C_Sign,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
        C_NULL,
    )
end

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
    finalize_on_cleanup::Bool
end

Pkcs11Lib(options::Pkcs11LibOptions) = Pkcs11Lib(options, SharedLibrary(), C_NULL, false)

const _pkcs11_ckr_map = Ref{Dict{UInt64, Int}}(Dict{UInt64, Int}())
const _pkcs11_ckr_loaded = Ref(false)

const _SHA1_PREFIX_TO_RSA_SIG = Memory{UInt8}([
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
])
const _SHA224_PREFIX_TO_RSA_SIG = Memory{UInt8}([
    0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c,
])
const _SHA256_PREFIX_TO_RSA_SIG = Memory{UInt8}([
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
])
const _SHA384_PREFIX_TO_RSA_SIG = Memory{UInt8}([
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30,
])
const _SHA512_PREFIX_TO_RSA_SIG = Memory{UInt8}([
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40,
])

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

function pkcs11_ckr_str(rv::Integer)::String
    if rv == CKR_OK
        return "CKR_OK"
    end
    code = pkcs11_error_from_ckr(rv)
    name = pkcs11_error_code_str(code)
    return name === nothing ? "CKR_UNKNOWN" : name
end

function get_prefix_to_rsa_sig(digest_alg)::Union{ByteCursor, ErrorResult}
    digest_val = try
        Int(digest_alg)
    catch
        raise_error(ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED)
        return ErrorResult(ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED)
    end
    if digest_val == TLS_HASH_SHA1
        return byte_cursor_from_array(_SHA1_PREFIX_TO_RSA_SIG)
    elseif digest_val == TLS_HASH_SHA224
        return byte_cursor_from_array(_SHA224_PREFIX_TO_RSA_SIG)
    elseif digest_val == TLS_HASH_SHA256
        return byte_cursor_from_array(_SHA256_PREFIX_TO_RSA_SIG)
    elseif digest_val == TLS_HASH_SHA384
        return byte_cursor_from_array(_SHA384_PREFIX_TO_RSA_SIG)
    elseif digest_val == TLS_HASH_SHA512
        return byte_cursor_from_array(_SHA512_PREFIX_TO_RSA_SIG)
    end
    raise_error(ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED)
    return ErrorResult(ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED)
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

    init_res = _pkcs11_init_with_function_list!(lib)
    init_res isa ErrorResult && return init_res

    return lib
end

pkcs11_lib_acquire(lib::Pkcs11Lib) = lib
function pkcs11_lib_release(lib::Pkcs11Lib)
    if lib.finalize_on_cleanup && lib.function_list != C_NULL
        fl = unsafe_load(Ptr{CK_FUNCTION_LIST}(lib.function_list))
        finalize_ptr = fl.C_Finalize
        if finalize_ptr != C_NULL
            rv = ccall(finalize_ptr, CK_RV, (Ptr{Cvoid},), C_NULL)
            if rv != CKR_OK
                logf(
                    LogLevel.ERROR,
                    LS_IO_PKCS11,
                    "PKCS11 finalize failed: $(pkcs11_error_code_str(pkcs11_error_from_ckr(rv)))",
                )
            end
        end
    end
    _ = shared_library_clean_up!(lib.shared_lib)
    return nothing
end

function pkcs11_lib_get_function_list(lib::Pkcs11Lib)::Ptr{CK_FUNCTION_LIST}
    if lib.function_list == C_NULL
        return Ptr{CK_FUNCTION_LIST}(C_NULL)
    end
    return Ptr{CK_FUNCTION_LIST}(lib.function_list)
end

function _pkcs11_init_with_function_list!(lib::Pkcs11Lib)::Union{Nothing, ErrorResult}
    if lib.function_list == C_NULL
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end

    fl = unsafe_load(Ptr{CK_FUNCTION_LIST}(lib.function_list))
    version = fl.version
    if version.major != AWS_SUPPORTED_CRYPTOKI_VERSION_MAJOR ||
        version.minor < AWS_MIN_SUPPORTED_CRYPTOKI_VERSION_MINOR
        raise_error(ERROR_IO_PKCS11_VERSION_UNSUPPORTED)
        return ErrorResult(ERROR_IO_PKCS11_VERSION_UNSUPPORTED)
    end

    behavior = lib.options.initialize_finalize_behavior
    if behavior != Pkcs11LibBehavior.OMIT_INITIALIZE
        init_ptr = fl.C_Initialize
        if init_ptr == C_NULL
            raise_error(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
            return ErrorResult(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
        end
        init_args = CK_C_INITIALIZE_ARGS(C_NULL, C_NULL, C_NULL, C_NULL, CKF_OS_LOCKING_OK, C_NULL)
        rv = ccall(init_ptr, CK_RV, (Ref{CK_C_INITIALIZE_ARGS},), Ref(init_args))
        if rv != CKR_OK
            if rv != CKR_CRYPTOKI_ALREADY_INITIALIZED ||
                behavior == Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE
                code = pkcs11_error_from_ckr(rv)
                raise_error(code)
                return ErrorResult(code)
            end
        end
        if behavior == Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE
            lib.finalize_on_cleanup = true
        end
    end

    info_ptr = fl.C_GetInfo
    if info_ptr != C_NULL
        info = Ref(CK_INFO(CK_VERSION(0, 0), ntuple(_ -> UInt8(0x20), 32), 0, ntuple(_ -> UInt8(0x20), 32), CK_VERSION(0, 0)))
        rv = ccall(info_ptr, CK_RV, (Ref{CK_INFO},), info)
        if rv != CKR_OK
            code = pkcs11_error_from_ckr(rv)
            raise_error(code)
            return ErrorResult(code)
        end
    end

    return nothing
end

function _pkcs11_trim_ascii(bytes::NTuple{N, UInt8}) where {N}
    buf = collect(bytes)
    while !isempty(buf)
        b = buf[end]
        if b == 0x20 || b == 0x00
            pop!(buf)
        else
            break
        end
    end
    return String(buf)
end

function _pkcs11_label_matches(label_bytes::NTuple{32, UInt8}, cursor::ByteCursor)::Bool
    return _pkcs11_trim_ascii(label_bytes) == String(cursor)
end

function pkcs11_lib_find_slot_with_token(
        lib::Pkcs11Lib,
        match_slot_id::Union{UInt64, Nothing},
        match_token_label::Union{ByteCursor, Nothing},
    )::Union{UInt64, ErrorResult}
    match_slot = match_slot_id === nothing ? nothing : CK_SLOT_ID(match_slot_id)
    if lib.function_list == C_NULL
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end
    fl = unsafe_load(Ptr{CK_FUNCTION_LIST}(lib.function_list))
    get_slot_list = fl.C_GetSlotList
    if get_slot_list == C_NULL
        raise_error(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
        return ErrorResult(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
    end

    count_ref = Ref{CK_ULONG}(0)
    rv = ccall(get_slot_list, CK_RV, (CK_BBOOL, Ptr{CK_SLOT_ID}, Ptr{CK_ULONG}), CK_TRUE, C_NULL, count_ref)
    if rv != CKR_OK
        code = pkcs11_error_from_ckr(rv)
        raise_error(code)
        return ErrorResult(code)
    end

    count = Int(count_ref[])
    if count == 0
        raise_error(ERROR_IO_PKCS11_TOKEN_NOT_FOUND)
        return ErrorResult(ERROR_IO_PKCS11_TOKEN_NOT_FOUND)
    end

    slots = Vector{CK_SLOT_ID}(undef, count)
    rv = ccall(get_slot_list, CK_RV, (CK_BBOOL, Ptr{CK_SLOT_ID}, Ptr{CK_ULONG}), CK_TRUE, slots, count_ref)
    if rv != CKR_OK
        code = pkcs11_error_from_ckr(rv)
        raise_error(code)
        return ErrorResult(code)
    end

    found_slot::Union{CK_SLOT_ID, Nothing} = nothing
    found_count = 0
    for slot_id in slots
        if match_slot !== nothing && slot_id != match_slot
            continue
        end
        if match_token_label !== nothing
            get_token_info = fl.C_GetTokenInfo
            if get_token_info == C_NULL
                raise_error(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
                return ErrorResult(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
            end
            info_ref = Ref(
                CK_TOKEN_INFO(
                    ntuple(_ -> UInt8(0x20), 32),
                    ntuple(_ -> UInt8(0x20), 32),
                    ntuple(_ -> UInt8(0x20), 16),
                    ntuple(_ -> UInt8(0x20), 16),
                    CK_ULONG(0),
                    CK_ULONG(0),
                    CK_ULONG(0),
                    CK_ULONG(0),
                    CK_ULONG(0),
                    CK_ULONG(0),
                    CK_ULONG(0),
                    CK_ULONG(0),
                    CK_ULONG(0),
                    CK_ULONG(0),
                    CK_ULONG(0),
                    CK_VERSION(0, 0),
                    CK_VERSION(0, 0),
                    ntuple(_ -> UInt8(0x20), 16),
                ),
            )
            rv = ccall(get_token_info, CK_RV, (CK_SLOT_ID, Ptr{CK_TOKEN_INFO}), slot_id, info_ref)
            if rv != CKR_OK
                code = pkcs11_error_from_ckr(rv)
                raise_error(code)
                return ErrorResult(code)
            end
            if !_pkcs11_label_matches(info_ref[].label, match_token_label)
                continue
            end
        end

        found_count += 1
        found_slot = slot_id
    end

    if found_count != 1 || found_slot === nothing
        raise_error(ERROR_IO_PKCS11_TOKEN_NOT_FOUND)
        return ErrorResult(ERROR_IO_PKCS11_TOKEN_NOT_FOUND)
    end

    return UInt64(found_slot)
end

function pkcs11_lib_open_session(
        lib::Pkcs11Lib,
        slot_id::UInt64,
    )::Union{CK_SESSION_HANDLE, ErrorResult}
    if lib.function_list == C_NULL
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end
    fl = unsafe_load(Ptr{CK_FUNCTION_LIST}(lib.function_list))
    open_ptr = fl.C_OpenSession
    if open_ptr == C_NULL
        raise_error(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
        return ErrorResult(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
    end

    session_ref = Ref{CK_SESSION_HANDLE}(0)
    rv = ccall(
        open_ptr,
        CK_RV,
        (CK_SLOT_ID, CK_FLAGS, Ptr{Cvoid}, Ptr{Cvoid}, Ref{CK_SESSION_HANDLE}),
        CK_SLOT_ID(slot_id),
        CKF_SERIAL_SESSION,
        C_NULL,
        C_NULL,
        session_ref,
    )
    if rv != CKR_OK
        code = pkcs11_error_from_ckr(rv)
        raise_error(code)
        return ErrorResult(code)
    end
    return session_ref[]
end

function pkcs11_lib_close_session(lib::Pkcs11Lib, session_handle::CK_SESSION_HANDLE)::Union{Nothing, ErrorResult}
    if lib.function_list == C_NULL
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end
    fl = unsafe_load(Ptr{CK_FUNCTION_LIST}(lib.function_list))
    close_ptr = fl.C_CloseSession
    if close_ptr == C_NULL
        raise_error(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
        return ErrorResult(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
    end
    rv = ccall(close_ptr, CK_RV, (CK_SESSION_HANDLE,), session_handle)
    if rv != CKR_OK
        code = pkcs11_error_from_ckr(rv)
        raise_error(code)
        return ErrorResult(code)
    end
    return nothing
end

function pkcs11_lib_login_user(
        lib::Pkcs11Lib,
        session_handle::CK_SESSION_HANDLE,
        user_pin::Union{ByteCursor, Nothing},
    )::Union{Nothing, ErrorResult}
    if lib.function_list == C_NULL
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end
    fl = unsafe_load(Ptr{CK_FUNCTION_LIST}(lib.function_list))
    login_ptr = fl.C_Login
    if login_ptr == C_NULL
        raise_error(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
        return ErrorResult(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
    end

    pin_ptr = Ptr{UInt8}(C_NULL)
    pin_len = CK_ULONG(0)
    if user_pin !== nothing && user_pin.len > 0
        pin_len = CK_ULONG(user_pin.len)
        pin_ptr = Ptr{UInt8}(pointer(user_pin.ptr))
    end
    rv = ccall(login_ptr, CK_RV, (CK_SESSION_HANDLE, CK_ULONG, Ptr{UInt8}, CK_ULONG), session_handle, CKU_USER, pin_ptr, pin_len)
    if rv != CKR_OK && rv != CKR_USER_ALREADY_LOGGED_IN
        code = pkcs11_error_from_ckr(rv)
        raise_error(code)
        return ErrorResult(code)
    end
    return nothing
end

function pkcs11_lib_find_private_key(
        lib::Pkcs11Lib,
        session_handle::CK_SESSION_HANDLE,
        match_label::Union{ByteCursor, Nothing},
    )::Union{Tuple{CK_OBJECT_HANDLE, CK_KEY_TYPE}, ErrorResult}
    if lib.function_list == C_NULL
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end
    fl = unsafe_load(Ptr{CK_FUNCTION_LIST}(lib.function_list))
    find_init = fl.C_FindObjectsInit
    find_objects = fl.C_FindObjects
    find_final = fl.C_FindObjectsFinal
    get_attr = fl.C_GetAttributeValue
    if find_init == C_NULL || find_objects == C_NULL || find_final == C_NULL || get_attr == C_NULL
        raise_error(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
        return ErrorResult(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
    end

    use_label = match_label !== nothing && match_label.len > 0
    if use_label && UInt64(match_label.len) > UInt64(typemax(CK_ULONG))
        logf(LogLevel.ERROR, LS_IO_PKCS11, "PKCS11: private key label is too long")
        raise_error(ERROR_IO_PKCS11_KEY_NOT_FOUND)
        return ErrorResult(ERROR_IO_PKCS11_KEY_NOT_FOUND)
    end

    key_class_ref = Ref{CK_OBJECT_CLASS}(CKO_PRIVATE_KEY)
    attrs = Memory{CK_ATTRIBUTE}(undef, use_label ? 2 : 1)
    attrs[1] = CK_ATTRIBUTE(
        CKA_CLASS,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{CK_OBJECT_CLASS}, key_class_ref)),
        CK_ULONG(sizeof(CK_OBJECT_CLASS)),
    )
    if use_label
        label_ptr = Ptr{UInt8}(pointer(match_label.ptr))
        attrs[2] = CK_ATTRIBUTE(CKA_LABEL, Ptr{Cvoid}(label_ptr), CK_ULONG(match_label.len))
    end

    must_finalize = false
    success = false
    result::Union{Tuple{CK_OBJECT_HANDLE, CK_KEY_TYPE}, ErrorResult} = ErrorResult(ERROR_IO_PKCS11_KEY_NOT_FOUND)

    while true
        GC.@preserve key_class_ref match_label attrs begin
            rv = ccall(
                find_init,
                CK_RV,
                (CK_SESSION_HANDLE, Ptr{CK_ATTRIBUTE}, CK_ULONG),
                session_handle,
                attrs,
                CK_ULONG(length(attrs)),
            )
        end
        if rv != CKR_OK
            code = pkcs11_error_from_ckr(rv)
            raise_error(code)
            result = ErrorResult(code)
            break
        end

        must_finalize = true

        found_objects = Memory{CK_OBJECT_HANDLE}(undef, 2)
        num_found_ref = Ref{CK_ULONG}(0)
        rv = ccall(
            find_objects,
            CK_RV,
            (CK_SESSION_HANDLE, Ptr{CK_OBJECT_HANDLE}, CK_ULONG, Ptr{CK_ULONG}),
            session_handle,
            found_objects,
            CK_ULONG(2),
            num_found_ref,
        )
        if rv != CKR_OK
            code = pkcs11_error_from_ckr(rv)
            raise_error(code)
            result = ErrorResult(code)
            break
        end

        num_found = Int(num_found_ref[])
        if num_found == 0 || found_objects[1] == CK_INVALID_HANDLE
            logf(LogLevel.ERROR, LS_IO_PKCS11, "PKCS11: Failed to find private key")
            raise_error(ERROR_IO_PKCS11_KEY_NOT_FOUND)
            result = ErrorResult(ERROR_IO_PKCS11_KEY_NOT_FOUND)
            break
        end
        if num_found > 1
            logf(LogLevel.ERROR, LS_IO_PKCS11, "PKCS11: Multiple private keys matched")
            raise_error(ERROR_IO_PKCS11_KEY_NOT_FOUND)
            result = ErrorResult(ERROR_IO_PKCS11_KEY_NOT_FOUND)
            break
        end

        key_handle = found_objects[1]
        key_type_ref = Ref{CK_KEY_TYPE}(0)
        key_attrs = Memory{CK_ATTRIBUTE}(undef, 1)
        key_attrs[1] = CK_ATTRIBUTE(
            CKA_KEY_TYPE,
            Ptr{Cvoid}(Base.unsafe_convert(Ptr{CK_KEY_TYPE}, key_type_ref)),
            CK_ULONG(sizeof(CK_KEY_TYPE)),
        )
        rv = ccall(
            get_attr,
            CK_RV,
            (CK_SESSION_HANDLE, CK_OBJECT_HANDLE, Ptr{CK_ATTRIBUTE}, CK_ULONG),
            session_handle,
            key_handle,
            key_attrs,
            CK_ULONG(1),
        )
        if rv != CKR_OK
            code = pkcs11_error_from_ckr(rv)
            raise_error(code)
            result = ErrorResult(code)
            break
        end

        key_type = key_type_ref[]
        if key_type != CKK_RSA && key_type != CKK_EC
            logf(
                LogLevel.ERROR,
                LS_IO_PKCS11,
                "PKCS11: Unsupported private key type 0x$(string(UInt64(key_type), base = 16))",
            )
            raise_error(ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED)
            result = ErrorResult(ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED)
            break
        end

        result = (key_handle, key_type)
        success = true
        break
    end

    if must_finalize
        rv = ccall(find_final, CK_RV, (CK_SESSION_HANDLE,), session_handle)
        if rv != CKR_OK && success
            code = pkcs11_error_from_ckr(rv)
            raise_error(code)
            result = ErrorResult(code)
        end
    end

    return result
end

function pkcs11_lib_decrypt(
        lib::Pkcs11Lib,
        session_handle::CK_SESSION_HANDLE,
        key_handle::CK_OBJECT_HANDLE,
        key_type::CK_KEY_TYPE,
        encrypted_data::ByteCursor,
    )::Union{ByteBuffer, ErrorResult}
    if lib.function_list == C_NULL
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end
    if key_type != CKK_RSA
        raise_error(ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED)
        return ErrorResult(ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED)
    end

    fl = unsafe_load(Ptr{CK_FUNCTION_LIST}(lib.function_list))
    decrypt_init = fl.C_DecryptInit
    decrypt = fl.C_Decrypt
    if decrypt_init == C_NULL || decrypt == C_NULL
        raise_error(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
        return ErrorResult(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
    end

    mechanism = CK_MECHANISM(CKM_RSA_PKCS, C_NULL, CK_ULONG(0))
    rv = ccall(decrypt_init, CK_RV, (CK_SESSION_HANDLE, Ref{CK_MECHANISM}, CK_OBJECT_HANDLE), session_handle, Ref(mechanism), key_handle)
    if rv != CKR_OK
        code = pkcs11_error_from_ckr(rv)
        raise_error(code)
        return ErrorResult(code)
    end

    data_len_ref = Ref{CK_ULONG}(0)
    input_ptr = encrypted_data.len > 0 ? Ptr{UInt8}(pointer(encrypted_data.ptr)) : Ptr{UInt8}(C_NULL)
    rv = ccall(
        decrypt,
        CK_RV,
        (CK_SESSION_HANDLE, Ptr{UInt8}, CK_ULONG, Ptr{UInt8}, Ptr{CK_ULONG}),
        session_handle,
        input_ptr,
        CK_ULONG(encrypted_data.len),
        C_NULL,
        data_len_ref,
    )
    if rv != CKR_OK
        code = pkcs11_error_from_ckr(rv)
        raise_error(code)
        return ErrorResult(code)
    end

    out_buf = ByteBuffer(Int(data_len_ref[]))
    output_ptr = data_len_ref[] > 0 ? Ptr{UInt8}(pointer(out_buf.mem)) : Ptr{UInt8}(C_NULL)
    rv = ccall(
        decrypt,
        CK_RV,
        (CK_SESSION_HANDLE, Ptr{UInt8}, CK_ULONG, Ptr{UInt8}, Ptr{CK_ULONG}),
        session_handle,
        input_ptr,
        CK_ULONG(encrypted_data.len),
        output_ptr,
        data_len_ref,
    )
    if rv != CKR_OK
        code = pkcs11_error_from_ckr(rv)
        raise_error(code)
        byte_buf_clean_up(Ref(out_buf))
        return ErrorResult(code)
    end

    out_buf.len = Csize_t(data_len_ref[])
    return out_buf
end

function _pkcs11_sign_helper(
        lib::Pkcs11Lib,
        session_handle::CK_SESSION_HANDLE,
        key_handle::CK_OBJECT_HANDLE,
        mechanism::CK_MECHANISM,
        input_data::ByteCursor,
    )::Union{ByteBuffer, ErrorResult}
    fl = unsafe_load(Ptr{CK_FUNCTION_LIST}(lib.function_list))
    sign_init = fl.C_SignInit
    sign = fl.C_Sign
    if sign_init == C_NULL || sign == C_NULL
        raise_error(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
        return ErrorResult(ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED)
    end

    rv = ccall(sign_init, CK_RV, (CK_SESSION_HANDLE, Ref{CK_MECHANISM}, CK_OBJECT_HANDLE), session_handle, Ref(mechanism), key_handle)
    if rv != CKR_OK
        code = pkcs11_error_from_ckr(rv)
        raise_error(code)
        return ErrorResult(code)
    end

    sig_len_ref = Ref{CK_ULONG}(0)
    input_ptr = input_data.len > 0 ? Ptr{UInt8}(pointer(input_data.ptr)) : Ptr{UInt8}(C_NULL)
    rv = ccall(
        sign,
        CK_RV,
        (CK_SESSION_HANDLE, Ptr{UInt8}, CK_ULONG, Ptr{UInt8}, Ptr{CK_ULONG}),
        session_handle,
        input_ptr,
        CK_ULONG(input_data.len),
        C_NULL,
        sig_len_ref,
    )
    if rv != CKR_OK
        code = pkcs11_error_from_ckr(rv)
        raise_error(code)
        return ErrorResult(code)
    end

    signature = ByteBuffer(Int(sig_len_ref[]))
    sig_ptr = sig_len_ref[] > 0 ? Ptr{UInt8}(pointer(signature.mem)) : Ptr{UInt8}(C_NULL)
    rv = ccall(
        sign,
        CK_RV,
        (CK_SESSION_HANDLE, Ptr{UInt8}, CK_ULONG, Ptr{UInt8}, Ptr{CK_ULONG}),
        session_handle,
        input_ptr,
        CK_ULONG(input_data.len),
        sig_ptr,
        sig_len_ref,
    )
    if rv != CKR_OK
        code = pkcs11_error_from_ckr(rv)
        raise_error(code)
        byte_buf_clean_up(Ref(signature))
        return ErrorResult(code)
    end

    signature.len = Csize_t(sig_len_ref[])
    return signature
end

function _pkcs11_sign_rsa(
        lib::Pkcs11Lib,
        session_handle::CK_SESSION_HANDLE,
        key_handle::CK_OBJECT_HANDLE,
        digest_data::ByteCursor,
        digest_alg,
        signature_alg,
    )::Union{ByteBuffer, ErrorResult}
    sig_val = try
        Int(signature_alg)
    catch
        raise_error(ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED)
        return ErrorResult(ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED)
    end
    if sig_val != TLS_SIGNATURE_RSA
        logf(
            LogLevel.ERROR,
            LS_IO_PKCS11,
            "PKCS11: Signature algorithm unsupported for RSA key",
        )
        raise_error(ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED)
        return ErrorResult(ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED)
    end

    prefix = get_prefix_to_rsa_sig(digest_alg)
    prefix isa ErrorResult && return prefix

    prefixed_ref = Ref(ByteBuffer(Int(prefix.len + digest_data.len)))
    ok = byte_buf_write_from_whole_cursor(prefixed_ref, prefix)
    ok = ok && byte_buf_write_from_whole_cursor(prefixed_ref, digest_data)
    if !ok
        raise_error(ERROR_IO_PKCS11_ENCODING_ERROR)
        return ErrorResult(ERROR_IO_PKCS11_ENCODING_ERROR)
    end

    mechanism = CK_MECHANISM(CKM_RSA_PKCS, C_NULL, CK_ULONG(0))
    signature = _pkcs11_sign_helper(
        lib,
        session_handle,
        key_handle,
        mechanism,
        byte_cursor_from_buf(prefixed_ref),
    )
    return signature
end

function _pkcs11_asn1_enc_prefix(buffer::Base.RefValue{ByteBuffer}, identifier::UInt8, length::Integer)::Union{Nothing, ErrorResult}
    if (identifier & 0x1f) == 0x1f || length > 0x7f
        logf(LogLevel.ERROR, LS_IO_PKCS11, "PKCS11: Unable to encode ASN.1 header")
        raise_error(ERROR_IO_PKCS11_ENCODING_ERROR)
        return ErrorResult(ERROR_IO_PKCS11_ENCODING_ERROR)
    end
    if !byte_buf_write_u8(buffer, identifier) || !byte_buf_write_u8(buffer, UInt8(length))
        logf(LogLevel.ERROR, LS_IO_PKCS11, "PKCS11: Unable to encode ASN.1 header")
        raise_error(ERROR_IO_PKCS11_ENCODING_ERROR)
        return ErrorResult(ERROR_IO_PKCS11_ENCODING_ERROR)
    end
    return nothing
end

function pkcs11_asn1_enc_ubigint(
        buffer::Base.RefValue{ByteBuffer},
        bigint::ByteCursor,
    )::Union{Nothing, ErrorResult}
    cur = bigint
    while cur.len > 0 && cursor_getbyte(cur, 1) == 0
        if cur.len == 1
            cur = null_cursor()
        else
            cur = ByteCursor(cur.len - 1, memref_advance(cur.ptr, 1))
        end
    end
    add_leading_zero = cur.len == 0 || (cursor_getbyte(cur, 1) & 0x80) != 0
    actual_len = Int(cur.len) + (add_leading_zero ? 1 : 0)

    prefix_res = _pkcs11_asn1_enc_prefix(buffer, 0x02, actual_len)
    prefix_res isa ErrorResult && return prefix_res

    if add_leading_zero
        if !byte_buf_write_u8(buffer, 0x00)
            logf(LogLevel.ERROR, LS_IO_PKCS11, "PKCS11: Insufficient buffer for ASN.1 bigint")
            raise_error(ERROR_IO_PKCS11_ENCODING_ERROR)
            return ErrorResult(ERROR_IO_PKCS11_ENCODING_ERROR)
        end
    end
    if cur.len > 0
        if !byte_buf_write_from_whole_cursor(buffer, cur)
            logf(LogLevel.ERROR, LS_IO_PKCS11, "PKCS11: Insufficient buffer for ASN.1 bigint")
            raise_error(ERROR_IO_PKCS11_ENCODING_ERROR)
            return ErrorResult(ERROR_IO_PKCS11_ENCODING_ERROR)
        end
    end
    return nothing
end

function _pkcs11_sign_ecdsa(
        lib::Pkcs11Lib,
        session_handle::CK_SESSION_HANDLE,
        key_handle::CK_OBJECT_HANDLE,
        digest_data::ByteCursor,
        signature_alg,
    )::Union{ByteBuffer, ErrorResult}
    sig_val = try
        Int(signature_alg)
    catch
        raise_error(ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED)
        return ErrorResult(ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED)
    end
    if sig_val != TLS_SIGNATURE_ECDSA
        logf(
            LogLevel.ERROR,
            LS_IO_PKCS11,
            "PKCS11: Signature algorithm unsupported for EC key",
        )
        raise_error(ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED)
        return ErrorResult(ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED)
    end

    mechanism = CK_MECHANISM(CKM_ECDSA, C_NULL, CK_ULONG(0))
    part_signature = _pkcs11_sign_helper(
        lib,
        session_handle,
        key_handle,
        mechanism,
        digest_data,
    )
    part_signature isa ErrorResult && return part_signature

    if part_signature.len == 0 || (Int(part_signature.len) % 2) != 0
        logf(LogLevel.ERROR, LS_IO_PKCS11, "PKCS11: Invalid ECDSA signature length")
        raise_error(ERROR_IO_PKCS11_ENCODING_ERROR)
        return ErrorResult(ERROR_IO_PKCS11_ENCODING_ERROR)
    end

    num_bytes = Int(part_signature.len) ÷ 2
    r_part_ref = Ref(ByteBuffer(num_bytes + 4))
    s_part_ref = Ref(ByteBuffer(num_bytes + 4))

    r_cursor = byte_cursor_from_array(part_signature.mem, num_bytes)
    s_cursor = byte_cursor_from_array(part_signature.mem, num_bytes, num_bytes)

    res = pkcs11_asn1_enc_ubigint(r_part_ref, r_cursor)
    res isa ErrorResult && return res
    res = pkcs11_asn1_enc_ubigint(s_part_ref, s_cursor)
    res isa ErrorResult && return res

    r_part = r_part_ref[]
    s_part = s_part_ref[]
    pair_len = Int(r_part.len + s_part.len)
    out_signature_ref = Ref(ByteBuffer(pair_len + 2))
    res = _pkcs11_asn1_enc_prefix(out_signature_ref, 0x30, pair_len)
    res isa ErrorResult && return res
    if !byte_buf_write_from_whole_buffer(out_signature_ref, r_part)
        raise_error(ERROR_IO_PKCS11_ENCODING_ERROR)
        return ErrorResult(ERROR_IO_PKCS11_ENCODING_ERROR)
    end
    if !byte_buf_write_from_whole_buffer(out_signature_ref, s_part)
        raise_error(ERROR_IO_PKCS11_ENCODING_ERROR)
        return ErrorResult(ERROR_IO_PKCS11_ENCODING_ERROR)
    end

    return out_signature_ref[]
end

function pkcs11_lib_sign(
        lib::Pkcs11Lib,
        session_handle::CK_SESSION_HANDLE,
        key_handle::CK_OBJECT_HANDLE,
        key_type::CK_KEY_TYPE,
        digest_data::ByteCursor,
        digest_alg,
        signature_alg,
    )::Union{ByteBuffer, ErrorResult}
    if key_type == CKK_RSA
        return _pkcs11_sign_rsa(
            lib,
            session_handle,
            key_handle,
            digest_data,
            digest_alg,
            signature_alg,
        )
    elseif key_type == CKK_EC
        return _pkcs11_sign_ecdsa(
            lib,
            session_handle,
            key_handle,
            digest_data,
            signature_alg,
        )
    end
    raise_error(ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED)
    return ErrorResult(ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED)
end
