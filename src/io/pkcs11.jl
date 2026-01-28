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

const CKR_OK = CK_RV(0)
const CKR_CRYPTOKI_ALREADY_INITIALIZED = CK_RV(0x00000191)
const CKR_FUNCTION_NOT_SUPPORTED = CK_RV(0x00000054)
const CKR_USER_ALREADY_LOGGED_IN = CK_RV(0x00000100)
const CKU_USER = CK_ULONG(0x1)
const CKF_OS_LOCKING_OK = CK_FLAGS(0x00000002)
const CKF_SERIAL_SESSION = CK_FLAGS(0x00000004)
const CK_TRUE = CK_BBOOL(1)

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
