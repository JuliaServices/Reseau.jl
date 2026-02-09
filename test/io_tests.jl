using Test
using Reseau

const _pkcs11_test_init_rv = Ref{Sockets.CK_RV}(Sockets.CKR_OK)
const _pkcs11_test_finalize_called = Ref(false)
const _pkcs11_test_get_info_called = Ref(false)
const _pkcs11_test_slots = Ref{Vector{Sockets.CK_SLOT_ID}}(Sockets.CK_SLOT_ID[])
const _pkcs11_test_token_labels = Ref{Dict{Sockets.CK_SLOT_ID, String}}(Dict{Sockets.CK_SLOT_ID, String}())
const _pkcs11_test_open_session_rv = Ref{Sockets.CK_RV}(Sockets.CKR_OK)
const _pkcs11_test_close_session_rv = Ref{Sockets.CK_RV}(Sockets.CKR_OK)
const _pkcs11_test_login_rv = Ref{Sockets.CK_RV}(Sockets.CKR_OK)
const _pkcs11_test_session_handle = Ref{Sockets.CK_SESSION_HANDLE}(Sockets.CK_SESSION_HANDLE(0x1234))
const _pkcs11_test_find_init_rv = Ref{Sockets.CK_RV}(Sockets.CKR_OK)
const _pkcs11_test_find_rv = Ref{Sockets.CK_RV}(Sockets.CKR_OK)
const _pkcs11_test_find_final_rv = Ref{Sockets.CK_RV}(Sockets.CKR_OK)
const _pkcs11_test_get_attr_rv = Ref{Sockets.CK_RV}(Sockets.CKR_OK)
const _pkcs11_test_find_objects = Ref{Vector{Sockets.CK_OBJECT_HANDLE}}(Sockets.CK_OBJECT_HANDLE[])
const _pkcs11_test_key_type = Ref{Sockets.CK_KEY_TYPE}(Sockets.CKK_RSA)
const _pkcs11_test_decrypt_init_rv = Ref{Sockets.CK_RV}(Sockets.CKR_OK)
const _pkcs11_test_decrypt_rv = Ref{Sockets.CK_RV}(Sockets.CKR_OK)
const _pkcs11_test_decrypt_output = Ref{Vector{UInt8}}(UInt8[])
const _pkcs11_test_sign_init_rv = Ref{Sockets.CK_RV}(Sockets.CKR_OK)
const _pkcs11_test_sign_rv = Ref{Sockets.CK_RV}(Sockets.CKR_OK)
const _pkcs11_test_sign_output = Ref{Vector{UInt8}}(UInt8[])
const _pkcs11_test_sign_input = Ref{Vector{UInt8}}(UInt8[])

function _pkcs11_test_fake_initialize(::Ptr{Sockets.CK_C_INITIALIZE_ARGS})::Sockets.CK_RV
    return _pkcs11_test_init_rv[]
end

function _pkcs11_test_fake_finalize(::Ptr{Cvoid})::Sockets.CK_RV
    _pkcs11_test_finalize_called[] = true
    return Sockets.CKR_OK
end

function _pkcs11_test_fake_get_info(info_ptr::Ptr{Sockets.CK_INFO})::Sockets.CK_RV
    _pkcs11_test_get_info_called[] = true
    info = Sockets.CK_INFO(
        Sockets.CK_VERSION(2, 20),
        ntuple(_ -> UInt8(0x20), 32),
        0,
        ntuple(_ -> UInt8(0x20), 32),
        Sockets.CK_VERSION(1, 0),
    )
    unsafe_store!(info_ptr, info)
    return Sockets.CKR_OK
end

function _pkcs11_test_label_bytes(label::AbstractString)
    bytes = fill(UInt8(0x20), 32)
    data = codeunits(label)
    n = min(length(data), length(bytes))
    for i in 1:n
        bytes[i] = data[i]
    end
    return Tuple(bytes)
end

function _pkcs11_test_fake_get_slot_list(
        ::Sockets.CK_BBOOL,
        slot_list::Ptr{Sockets.CK_SLOT_ID},
        count_ptr::Ptr{Sockets.CK_ULONG},
    )::Sockets.CK_RV
    slots = _pkcs11_test_slots[]
    unsafe_store!(count_ptr, Sockets.CK_ULONG(length(slots)))
    if slot_list != C_NULL
        for i in 1:length(slots)
            unsafe_store!(slot_list, slots[i], i)
        end
    end
    return Sockets.CKR_OK
end

function _pkcs11_test_fake_get_token_info(
        slot_id::Sockets.CK_SLOT_ID,
        info_ptr::Ptr{Sockets.CK_TOKEN_INFO},
    )::Sockets.CK_RV
    label = get(_pkcs11_test_token_labels[], slot_id, "")
    info = Sockets.CK_TOKEN_INFO(
        _pkcs11_test_label_bytes(label),
        ntuple(_ -> UInt8(0x20), 32),
        ntuple(_ -> UInt8(0x20), 16),
        ntuple(_ -> UInt8(0x20), 16),
        Sockets.CK_ULONG(0),
        Sockets.CK_ULONG(0),
        Sockets.CK_ULONG(0),
        Sockets.CK_ULONG(0),
        Sockets.CK_ULONG(0),
        Sockets.CK_ULONG(0),
        Sockets.CK_ULONG(0),
        Sockets.CK_ULONG(0),
        Sockets.CK_ULONG(0),
        Sockets.CK_ULONG(0),
        Sockets.CK_ULONG(0),
        Sockets.CK_VERSION(0, 0),
        Sockets.CK_VERSION(0, 0),
        ntuple(_ -> UInt8(0x20), 16),
    )
    unsafe_store!(info_ptr, info)
    return Sockets.CKR_OK
end

function _pkcs11_test_fake_open_session(
        ::Sockets.CK_SLOT_ID,
        ::Sockets.CK_FLAGS,
        ::Ptr{Cvoid},
        ::Ptr{Cvoid},
        session_ptr::Ptr{Sockets.CK_SESSION_HANDLE},
    )::Sockets.CK_RV
    unsafe_store!(session_ptr, _pkcs11_test_session_handle[])
    return _pkcs11_test_open_session_rv[]
end

function _pkcs11_test_fake_close_session(::Sockets.CK_SESSION_HANDLE)::Sockets.CK_RV
    return _pkcs11_test_close_session_rv[]
end

function _pkcs11_test_fake_login(
        ::Sockets.CK_SESSION_HANDLE,
        ::Sockets.CK_ULONG,
        ::Ptr{UInt8},
        ::Sockets.CK_ULONG,
    )::Sockets.CK_RV
    return _pkcs11_test_login_rv[]
end

function _pkcs11_test_fake_find_objects_init(
        ::Sockets.CK_SESSION_HANDLE,
        ::Ptr{Sockets.CK_ATTRIBUTE},
        ::Sockets.CK_ULONG,
    )::Sockets.CK_RV
    return _pkcs11_test_find_init_rv[]
end

function _pkcs11_test_fake_find_objects(
        ::Sockets.CK_SESSION_HANDLE,
        objects_ptr::Ptr{Sockets.CK_OBJECT_HANDLE},
        max_objects::Sockets.CK_ULONG,
        count_ptr::Ptr{Sockets.CK_ULONG},
    )::Sockets.CK_RV
    handles = _pkcs11_test_find_objects[]
    count = min(length(handles), Int(max_objects))
    unsafe_store!(count_ptr, Sockets.CK_ULONG(count))
    if objects_ptr != C_NULL
        for i in 1:count
            unsafe_store!(objects_ptr, handles[i], i)
        end
    end
    return _pkcs11_test_find_rv[]
end

function _pkcs11_test_fake_find_objects_final(::Sockets.CK_SESSION_HANDLE)::Sockets.CK_RV
    return _pkcs11_test_find_final_rv[]
end

function _pkcs11_test_fake_get_attribute_value(
        ::Sockets.CK_SESSION_HANDLE,
        ::Sockets.CK_OBJECT_HANDLE,
        attrs_ptr::Ptr{Sockets.CK_ATTRIBUTE},
        attr_count::Sockets.CK_ULONG,
    )::Sockets.CK_RV
    if attrs_ptr != C_NULL && attr_count > 0
        attr = unsafe_load(attrs_ptr)
        if attr.type == Sockets.CKA_KEY_TYPE && attr.pValue != C_NULL
            unsafe_store!(Ptr{Sockets.CK_KEY_TYPE}(attr.pValue), _pkcs11_test_key_type[])
        end
    end
    return _pkcs11_test_get_attr_rv[]
end

function _pkcs11_test_fake_decrypt_init(
        ::Sockets.CK_SESSION_HANDLE,
        ::Ptr{Sockets.CK_MECHANISM},
        ::Sockets.CK_OBJECT_HANDLE,
    )::Sockets.CK_RV
    return _pkcs11_test_decrypt_init_rv[]
end

function _pkcs11_test_fake_decrypt(
        ::Sockets.CK_SESSION_HANDLE,
        ::Ptr{UInt8},
        ::Sockets.CK_ULONG,
        out_ptr::Ptr{UInt8},
        out_len_ptr::Ptr{Sockets.CK_ULONG},
    )::Sockets.CK_RV
    data = _pkcs11_test_decrypt_output[]
    unsafe_store!(out_len_ptr, Sockets.CK_ULONG(length(data)))
    if out_ptr != C_NULL
        for i in 1:length(data)
            unsafe_store!(out_ptr, data[i], i)
        end
    end
    return _pkcs11_test_decrypt_rv[]
end

function _pkcs11_test_fake_sign_init(
        ::Sockets.CK_SESSION_HANDLE,
        ::Ptr{Sockets.CK_MECHANISM},
        ::Sockets.CK_OBJECT_HANDLE,
    )::Sockets.CK_RV
    return _pkcs11_test_sign_init_rv[]
end

function _pkcs11_test_fake_sign(
        ::Sockets.CK_SESSION_HANDLE,
        input_ptr::Ptr{UInt8},
        input_len::Sockets.CK_ULONG,
        sig_ptr::Ptr{UInt8},
        sig_len_ptr::Ptr{Sockets.CK_ULONG},
    )::Sockets.CK_RV
    if input_ptr == C_NULL || input_len == 0
        _pkcs11_test_sign_input[] = UInt8[]
    else
        data = Vector{UInt8}(undef, Int(input_len))
        for i in 1:Int(input_len)
            data[i] = unsafe_load(input_ptr, i)
        end
        _pkcs11_test_sign_input[] = data
    end
    sig = _pkcs11_test_sign_output[]
    unsafe_store!(sig_len_ptr, Sockets.CK_ULONG(length(sig)))
    if sig_ptr != C_NULL
        for i in 1:length(sig)
            unsafe_store!(sig_ptr, sig[i], i)
        end
    end
    return _pkcs11_test_sign_rv[]
end

@testset "IO error and log subject registry" begin
    @test Reseau.error_name(EventLoops.ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT) ==
        "ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT"
    @test Reseau.error_str(EventLoops.ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT) ==
        "Channel cannot accept input"
    @test Reseau.error_str(EventLoops.ERROR_IO_PKCS11_CKR_CANCEL) ==
        "A PKCS#11 (Cryptoki) library function failed with return value CKR_CANCEL"
    @test Reseau.error_str(EventLoops.ERROR_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND) ==
        "Default TLS trust store not found on this system. Trusted CA certificates must be installed, or \"override default trust store\" must be used while creating the TLS context."

    @test Reseau.log_subject_name(EventLoops.LS_IO_GENERAL) == "aws-c-io"
    @test Reseau.log_subject_description(EventLoops.LS_IO_GENERAL) ==
        "Subject for IO logging that doesn't belong to any particular category"
    @test Reseau.log_subject_name(EventLoops.LS_IO_TLS) == "tls-handler"

    @test EventLoops.io_error_code_is_retryable(EventLoops.ERROR_IO_SOCKET_TIMEOUT)
    @test !EventLoops.io_error_code_is_retryable(EventLoops.ERROR_IO_SOCKET_NO_ROUTE_TO_HOST)
end

@testset "PKCS11 error code string" begin
    @test Sockets.pkcs11_error_code_str(EventLoops.ERROR_IO_PKCS11_CKR_CANCEL) == "CKR_CANCEL"
    @test Sockets.pkcs11_error_code_str(EventLoops.ERROR_IO_PKCS11_CKR_FUNCTION_REJECTED) ==
          "CKR_FUNCTION_REJECTED"
    @test Sockets.pkcs11_error_code_str(0) === nothing
    @test Sockets.pkcs11_ckr_str(Sockets.CKR_OK) == "CKR_OK"
    @test Sockets.pkcs11_ckr_str(0xffff) == "CKR_UNKNOWN"
end

@testset "PKCS11 lib stubs" begin
    temp_dir = mktempdir()
    missing_path = joinpath(temp_dir, "missing_pkcs11_lib")
    opts = Sockets.Pkcs11LibOptions(; filename = missing_path)
    lib = Sockets.pkcs11_lib_new(opts)
    @test lib isa Reseau.ErrorResult
    if lib isa Reseau.ErrorResult
        @test lib.code == EventLoops.ERROR_IO_SHARED_LIBRARY_LOAD_FAILURE
    end
end

@testset "PKCS11 CKR mapping" begin
    root = dirname(@__DIR__)
    header_path = joinpath(root, "aws-c-io", "source", "pkcs11", "v2.40", "pkcs11.h")
    if !isfile(header_path)
        @test true
    else
        rv_cancel = nothing
        rx = r"^#define\s+CKR_CANCEL\s+(0x[0-9A-Fa-f]+|[0-9]+)[uUlL]*"
        for line in eachline(header_path)
            m = match(rx, strip(line))
            m === nothing && continue
            val = m.captures[1]
            rv_cancel = startswith(val, "0x") ? parse(UInt64, val) : parse(UInt64, val)
            break
        end
        @test rv_cancel !== nothing
        if rv_cancel !== nothing
            @test Sockets.pkcs11_error_from_ckr(rv_cancel) == EventLoops.ERROR_IO_PKCS11_CKR_CANCEL
        end
        @test Sockets.pkcs11_error_from_ckr(0xffffffffffffffff) ==
            EventLoops.ERROR_IO_PKCS11_UNKNOWN_CRYPTOKI_RETURN_VALUE
    end
end

@testset "PKCS11 init behavior" begin
    init_fn = @cfunction(_pkcs11_test_fake_initialize, Sockets.CK_RV, (Ptr{Sockets.CK_C_INITIALIZE_ARGS},))
    finalize_fn = @cfunction(_pkcs11_test_fake_finalize, Sockets.CK_RV, (Ptr{Cvoid},))
    get_info_fn = @cfunction(_pkcs11_test_fake_get_info, Sockets.CK_RV, (Ptr{Sockets.CK_INFO},))

    fl = Sockets._pkcs11_function_list_stub(
        C_Initialize = init_fn,
        C_Finalize = finalize_fn,
        C_GetInfo = get_info_fn,
    )
    fl_ref = Ref(fl)

    function build_lib(behavior)
        lib = Sockets.Pkcs11Lib(
            Sockets.Pkcs11LibOptions(
                filename = nothing,
                initialize_finalize_behavior = behavior,
            ),
        )
        lib.function_list = Base.unsafe_convert(Ptr{Cvoid}, fl_ref)
        return lib
    end

    GC.@preserve fl_ref begin
        _pkcs11_test_init_rv[] = Sockets.CKR_CRYPTOKI_ALREADY_INITIALIZED
        _pkcs11_test_get_info_called[] = false
        lib_default = build_lib(Sockets.Pkcs11LibBehavior.DEFAULT_BEHAVIOR)
        res_default = Sockets._pkcs11_init_with_function_list!(lib_default)
        @test res_default === nothing
        @test _pkcs11_test_get_info_called[]
        @test !lib_default.finalize_on_cleanup

        _pkcs11_test_init_rv[] = Sockets.CKR_CRYPTOKI_ALREADY_INITIALIZED
        lib_strict = build_lib(Sockets.Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE)
        res_strict = Sockets._pkcs11_init_with_function_list!(lib_strict)
        @test res_strict isa Reseau.ErrorResult
        if res_strict isa Reseau.ErrorResult
            @test res_strict.code == EventLoops.ERROR_IO_PKCS11_CKR_CRYPTOKI_ALREADY_INITIALIZED
        end

        _pkcs11_test_init_rv[] = Sockets.CKR_OK
        _pkcs11_test_finalize_called[] = false
        lib_finalize = build_lib(Sockets.Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE)
        res_finalize = Sockets._pkcs11_init_with_function_list!(lib_finalize)
        @test res_finalize === nothing
        @test lib_finalize.finalize_on_cleanup
        Sockets.pkcs11_lib_release(lib_finalize)
        @test _pkcs11_test_finalize_called[]
    end
end

@testset "PKCS11 slot/session helpers" begin
    get_slot_fn = @cfunction(
        _pkcs11_test_fake_get_slot_list,
        Sockets.CK_RV,
        (Sockets.CK_BBOOL, Ptr{Sockets.CK_SLOT_ID}, Ptr{Sockets.CK_ULONG}),
    )
    get_token_fn = @cfunction(
        _pkcs11_test_fake_get_token_info,
        Sockets.CK_RV,
        (Sockets.CK_SLOT_ID, Ptr{Sockets.CK_TOKEN_INFO}),
    )
    open_fn = @cfunction(
        _pkcs11_test_fake_open_session,
        Sockets.CK_RV,
        (Sockets.CK_SLOT_ID, Sockets.CK_FLAGS, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Sockets.CK_SESSION_HANDLE}),
    )
    close_fn = @cfunction(
        _pkcs11_test_fake_close_session,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE,),
    )
    login_fn = @cfunction(
        _pkcs11_test_fake_login,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Sockets.CK_ULONG, Ptr{UInt8}, Sockets.CK_ULONG),
    )

    fl = Sockets._pkcs11_function_list_stub(
        C_GetSlotList = get_slot_fn,
        C_GetTokenInfo = get_token_fn,
        C_OpenSession = open_fn,
        C_CloseSession = close_fn,
        C_Login = login_fn,
    )
    fl_ref = Ref(fl)

    lib = Sockets.Pkcs11Lib(Sockets.Pkcs11LibOptions(filename = nothing))
    lib.function_list = Base.unsafe_convert(Ptr{Cvoid}, fl_ref)

    GC.@preserve fl_ref begin
        _pkcs11_test_slots[] = Sockets.CK_SLOT_ID[]
        res_empty = Sockets.pkcs11_lib_find_slot_with_token(lib, nothing, nothing)
        @test res_empty isa Reseau.ErrorResult
        if res_empty isa Reseau.ErrorResult
            @test res_empty.code == EventLoops.ERROR_IO_PKCS11_TOKEN_NOT_FOUND
        end

        _pkcs11_test_slots[] = Sockets.CK_SLOT_ID[1, 2]
        res_multi = Sockets.pkcs11_lib_find_slot_with_token(lib, nothing, nothing)
        @test res_multi isa Reseau.ErrorResult
        if res_multi isa Reseau.ErrorResult
            @test res_multi.code == EventLoops.ERROR_IO_PKCS11_TOKEN_NOT_FOUND
        end

        res_match = Sockets.pkcs11_lib_find_slot_with_token(lib, UInt64(2), nothing)
        @test res_match == 2

        _pkcs11_test_token_labels[] = Dict{Sockets.CK_SLOT_ID, String}(1 => "alpha", 2 => "beta")
        res_label = Sockets.pkcs11_lib_find_slot_with_token(lib, nothing, Reseau.ByteCursor("beta"))
        @test res_label == 2

        _pkcs11_test_open_session_rv[] = Sockets.CKR_OK
        _pkcs11_test_session_handle[] = Sockets.CK_SESSION_HANDLE(0x55)
        session = Sockets.pkcs11_lib_open_session(lib, UInt64(1))
        @test session == Sockets.CK_SESSION_HANDLE(0x55)

        _pkcs11_test_open_session_rv[] = Sockets.CKR_FUNCTION_NOT_SUPPORTED
        bad_session = Sockets.pkcs11_lib_open_session(lib, UInt64(1))
        @test bad_session isa Reseau.ErrorResult
        if bad_session isa Reseau.ErrorResult
            @test bad_session.code == EventLoops.ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED
        end

        _pkcs11_test_close_session_rv[] = Sockets.CKR_OK
        @test Sockets.pkcs11_lib_close_session(lib, Sockets.CK_SESSION_HANDLE(0x55)) === nothing

        _pkcs11_test_close_session_rv[] = Sockets.CKR_FUNCTION_NOT_SUPPORTED
        bad_close = Sockets.pkcs11_lib_close_session(lib, Sockets.CK_SESSION_HANDLE(0x55))
        @test bad_close isa Reseau.ErrorResult
        if bad_close isa Reseau.ErrorResult
            @test bad_close.code == EventLoops.ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED
        end

        _pkcs11_test_login_rv[] = Sockets.CKR_USER_ALREADY_LOGGED_IN
        @test Sockets.pkcs11_lib_login_user(lib, Sockets.CK_SESSION_HANDLE(0x55), Reseau.ByteCursor("1234")) ===
              nothing

        _pkcs11_test_login_rv[] = Sockets.CKR_FUNCTION_NOT_SUPPORTED
        bad_login = Sockets.pkcs11_lib_login_user(lib, Sockets.CK_SESSION_HANDLE(0x55), Reseau.ByteCursor("1234"))
        @test bad_login isa Reseau.ErrorResult
        if bad_login isa Reseau.ErrorResult
            @test bad_login.code == EventLoops.ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED
        end
    end
end

@testset "PKCS11 private key operations" begin
    find_init_fn = @cfunction(
        _pkcs11_test_fake_find_objects_init,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Ptr{Sockets.CK_ATTRIBUTE}, Sockets.CK_ULONG),
    )
    find_fn = @cfunction(
        _pkcs11_test_fake_find_objects,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Ptr{Sockets.CK_OBJECT_HANDLE}, Sockets.CK_ULONG, Ptr{Sockets.CK_ULONG}),
    )
    find_final_fn = @cfunction(
        _pkcs11_test_fake_find_objects_final,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE,),
    )
    get_attr_fn = @cfunction(
        _pkcs11_test_fake_get_attribute_value,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Sockets.CK_OBJECT_HANDLE, Ptr{Sockets.CK_ATTRIBUTE}, Sockets.CK_ULONG),
    )
    decrypt_init_fn = @cfunction(
        _pkcs11_test_fake_decrypt_init,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Ptr{Sockets.CK_MECHANISM}, Sockets.CK_OBJECT_HANDLE),
    )
    decrypt_fn = @cfunction(
        _pkcs11_test_fake_decrypt,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Ptr{UInt8}, Sockets.CK_ULONG, Ptr{UInt8}, Ptr{Sockets.CK_ULONG}),
    )
    sign_init_fn = @cfunction(
        _pkcs11_test_fake_sign_init,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Ptr{Sockets.CK_MECHANISM}, Sockets.CK_OBJECT_HANDLE),
    )
    sign_fn = @cfunction(
        _pkcs11_test_fake_sign,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Ptr{UInt8}, Sockets.CK_ULONG, Ptr{UInt8}, Ptr{Sockets.CK_ULONG}),
    )

    fl = Sockets._pkcs11_function_list_stub(
        C_FindObjectsInit = find_init_fn,
        C_FindObjects = find_fn,
        C_FindObjectsFinal = find_final_fn,
        C_GetAttributeValue = get_attr_fn,
        C_DecryptInit = decrypt_init_fn,
        C_Decrypt = decrypt_fn,
        C_SignInit = sign_init_fn,
        C_Sign = sign_fn,
    )
    fl_ref = Ref(fl)

    lib = Sockets.Pkcs11Lib(Sockets.Pkcs11LibOptions(filename = nothing))
    lib.function_list = Base.unsafe_convert(Ptr{Cvoid}, fl_ref)

    GC.@preserve fl_ref begin
        _pkcs11_test_find_objects[] = Sockets.CK_OBJECT_HANDLE[]
        res_none = Sockets.pkcs11_lib_find_private_key(lib, Sockets.CK_SESSION_HANDLE(1), nothing)
        @test res_none isa Reseau.ErrorResult
        if res_none isa Reseau.ErrorResult
            @test res_none.code == EventLoops.ERROR_IO_PKCS11_KEY_NOT_FOUND
        end

        _pkcs11_test_find_objects[] = Sockets.CK_OBJECT_HANDLE[1, 2]
        res_multi = Sockets.pkcs11_lib_find_private_key(lib, Sockets.CK_SESSION_HANDLE(1), nothing)
        @test res_multi isa Reseau.ErrorResult
        if res_multi isa Reseau.ErrorResult
            @test res_multi.code == EventLoops.ERROR_IO_PKCS11_KEY_NOT_FOUND
        end

        _pkcs11_test_find_objects[] = Sockets.CK_OBJECT_HANDLE[3]
        _pkcs11_test_key_type[] = Sockets.CK_KEY_TYPE(0xdead)
        res_bad_type = Sockets.pkcs11_lib_find_private_key(lib, Sockets.CK_SESSION_HANDLE(1), nothing)
        @test res_bad_type isa Reseau.ErrorResult
        if res_bad_type isa Reseau.ErrorResult
            @test res_bad_type.code == EventLoops.ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED
        end

        _pkcs11_test_key_type[] = Sockets.CKK_RSA
        res_ok = Sockets.pkcs11_lib_find_private_key(lib, Sockets.CK_SESSION_HANDLE(1), Reseau.ByteCursor("key"))
        @test res_ok == (Sockets.CK_OBJECT_HANDLE(3), Sockets.CKK_RSA)

        _pkcs11_test_decrypt_output[] = UInt8[0x01, 0x02, 0x03]
        _pkcs11_test_decrypt_rv[] = Sockets.CKR_OK
        dec = Sockets.pkcs11_lib_decrypt(
            lib,
            Sockets.CK_SESSION_HANDLE(1),
            Sockets.CK_OBJECT_HANDLE(3),
            Sockets.CKK_RSA,
            Reseau.ByteCursor("cipher"),
        )
        @test dec isa Reseau.ByteBuffer
        if dec isa Reseau.ByteBuffer
            @test collect(dec.mem[1:Int(dec.len)]) == _pkcs11_test_decrypt_output[]
        end

        bad_dec = Sockets.pkcs11_lib_decrypt(
            lib,
            Sockets.CK_SESSION_HANDLE(1),
            Sockets.CK_OBJECT_HANDLE(3),
            Sockets.CKK_EC,
            Reseau.ByteCursor("cipher"),
        )
        @test bad_dec isa Reseau.ErrorResult
        if bad_dec isa Reseau.ErrorResult
            @test bad_dec.code == EventLoops.ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED
        end

        _pkcs11_test_decrypt_rv[] = Sockets.CKR_FUNCTION_NOT_SUPPORTED
        bad_dec_rv = Sockets.pkcs11_lib_decrypt(
            lib,
            Sockets.CK_SESSION_HANDLE(1),
            Sockets.CK_OBJECT_HANDLE(3),
            Sockets.CKK_RSA,
            Reseau.ByteCursor("cipher"),
        )
        @test bad_dec_rv isa Reseau.ErrorResult
        if bad_dec_rv isa Reseau.ErrorResult
            @test bad_dec_rv.code == EventLoops.ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED
        end
        _pkcs11_test_decrypt_rv[] = Sockets.CKR_OK

        rsa_prefix = UInt8[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            0x05, 0x00, 0x04, 0x20,
        ]
        digest = UInt8[0xaa, 0xbb]
        _pkcs11_test_sign_output[] = UInt8[0x11, 0x22]
        _pkcs11_test_sign_rv[] = Sockets.CKR_OK
        _pkcs11_test_sign_input[] = UInt8[]
        sig = Sockets.pkcs11_lib_sign(
            lib,
            Sockets.CK_SESSION_HANDLE(1),
            Sockets.CK_OBJECT_HANDLE(3),
            Sockets.CKK_RSA,
            Reseau.ByteCursor(digest),
            Sockets.TlsHashAlgorithm.SHA256,
            Sockets.TlsSignatureAlgorithm.RSA,
        )
        @test sig isa Reseau.ByteBuffer
        if sig isa Reseau.ByteBuffer
            @test collect(sig.mem[1:Int(sig.len)]) == _pkcs11_test_sign_output[]
        end
        @test _pkcs11_test_sign_input[] == vcat(rsa_prefix, digest)

        bad_sig_alg = Sockets.pkcs11_lib_sign(
            lib,
            Sockets.CK_SESSION_HANDLE(1),
            Sockets.CK_OBJECT_HANDLE(3),
            Sockets.CKK_RSA,
            Reseau.ByteCursor(digest),
            Sockets.TlsHashAlgorithm.SHA256,
            Sockets.TlsSignatureAlgorithm.ECDSA,
        )
        @test bad_sig_alg isa Reseau.ErrorResult
        if bad_sig_alg isa Reseau.ErrorResult
            @test bad_sig_alg.code == EventLoops.ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED
        end

        bad_digest = Sockets.pkcs11_lib_sign(
            lib,
            Sockets.CK_SESSION_HANDLE(1),
            Sockets.CK_OBJECT_HANDLE(3),
            Sockets.CKK_RSA,
            Reseau.ByteCursor(digest),
            Sockets.TlsHashAlgorithm.UNKNOWN,
            Sockets.TlsSignatureAlgorithm.RSA,
        )
        @test bad_digest isa Reseau.ErrorResult
        if bad_digest isa Reseau.ErrorResult
            @test bad_digest.code == EventLoops.ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED
        end

        _pkcs11_test_sign_output[] = UInt8[0x01, 0x02, 0x03, 0x04]
        sig_ec = Sockets.pkcs11_lib_sign(
            lib,
            Sockets.CK_SESSION_HANDLE(1),
            Sockets.CK_OBJECT_HANDLE(3),
            Sockets.CKK_EC,
            Reseau.ByteCursor(digest),
            Sockets.TlsHashAlgorithm.SHA256,
            Sockets.TlsSignatureAlgorithm.ECDSA,
        )
        @test sig_ec isa Reseau.ByteBuffer
        if sig_ec isa Reseau.ByteBuffer
            @test collect(sig_ec.mem[1:Int(sig_ec.len)]) ==
                  UInt8[0x30, 0x08, 0x02, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x04]
        end

        bad_ec_sig_alg = Sockets.pkcs11_lib_sign(
            lib,
            Sockets.CK_SESSION_HANDLE(1),
            Sockets.CK_OBJECT_HANDLE(3),
            Sockets.CKK_EC,
            Reseau.ByteCursor(digest),
            Sockets.TlsHashAlgorithm.SHA256,
            Sockets.TlsSignatureAlgorithm.RSA,
        )
        @test bad_ec_sig_alg isa Reseau.ErrorResult
        if bad_ec_sig_alg isa Reseau.ErrorResult
            @test bad_ec_sig_alg.code == EventLoops.ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED
        end

        bad_key = Sockets.pkcs11_lib_sign(
            lib,
            Sockets.CK_SESSION_HANDLE(1),
            Sockets.CK_OBJECT_HANDLE(3),
            Sockets.CK_KEY_TYPE(0xdead),
            Reseau.ByteCursor(digest),
            Sockets.TlsHashAlgorithm.SHA256,
            Sockets.TlsSignatureAlgorithm.RSA,
        )
        @test bad_key isa Reseau.ErrorResult
        if bad_key isa Reseau.ErrorResult
            @test bad_key.code == EventLoops.ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED
        end
    end
end

@testset "PKCS11 TLS op handler" begin
    get_slot_fn = @cfunction(
        _pkcs11_test_fake_get_slot_list,
        Sockets.CK_RV,
        (Sockets.CK_BBOOL, Ptr{Sockets.CK_SLOT_ID}, Ptr{Sockets.CK_ULONG}),
    )
    get_token_fn = @cfunction(
        _pkcs11_test_fake_get_token_info,
        Sockets.CK_RV,
        (Sockets.CK_SLOT_ID, Ptr{Sockets.CK_TOKEN_INFO}),
    )
    open_fn = @cfunction(
        _pkcs11_test_fake_open_session,
        Sockets.CK_RV,
        (Sockets.CK_SLOT_ID, Sockets.CK_FLAGS, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Sockets.CK_SESSION_HANDLE}),
    )
    close_fn = @cfunction(
        _pkcs11_test_fake_close_session,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE,),
    )
    login_fn = @cfunction(
        _pkcs11_test_fake_login,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Sockets.CK_ULONG, Ptr{UInt8}, Sockets.CK_ULONG),
    )
    find_init_fn = @cfunction(
        _pkcs11_test_fake_find_objects_init,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Ptr{Sockets.CK_ATTRIBUTE}, Sockets.CK_ULONG),
    )
    find_fn = @cfunction(
        _pkcs11_test_fake_find_objects,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Ptr{Sockets.CK_OBJECT_HANDLE}, Sockets.CK_ULONG, Ptr{Sockets.CK_ULONG}),
    )
    find_final_fn = @cfunction(
        _pkcs11_test_fake_find_objects_final,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE,),
    )
    get_attr_fn = @cfunction(
        _pkcs11_test_fake_get_attribute_value,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Sockets.CK_OBJECT_HANDLE, Ptr{Sockets.CK_ATTRIBUTE}, Sockets.CK_ULONG),
    )
    decrypt_init_fn = @cfunction(
        _pkcs11_test_fake_decrypt_init,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Ptr{Sockets.CK_MECHANISM}, Sockets.CK_OBJECT_HANDLE),
    )
    decrypt_fn = @cfunction(
        _pkcs11_test_fake_decrypt,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Ptr{UInt8}, Sockets.CK_ULONG, Ptr{UInt8}, Ptr{Sockets.CK_ULONG}),
    )
    sign_init_fn = @cfunction(
        _pkcs11_test_fake_sign_init,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Ptr{Sockets.CK_MECHANISM}, Sockets.CK_OBJECT_HANDLE),
    )
    sign_fn = @cfunction(
        _pkcs11_test_fake_sign,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Ptr{UInt8}, Sockets.CK_ULONG, Ptr{UInt8}, Ptr{Sockets.CK_ULONG}),
    )

    fl = Sockets._pkcs11_function_list_stub(
        C_GetSlotList = get_slot_fn,
        C_GetTokenInfo = get_token_fn,
        C_OpenSession = open_fn,
        C_CloseSession = close_fn,
        C_Login = login_fn,
        C_FindObjectsInit = find_init_fn,
        C_FindObjects = find_fn,
        C_FindObjectsFinal = find_final_fn,
        C_GetAttributeValue = get_attr_fn,
        C_DecryptInit = decrypt_init_fn,
        C_Decrypt = decrypt_fn,
        C_SignInit = sign_init_fn,
        C_Sign = sign_fn,
    )
    fl_ref = Ref(fl)

    lib = Sockets.Pkcs11Lib(Sockets.Pkcs11LibOptions(filename = nothing))
    lib.function_list = Base.unsafe_convert(Ptr{Cvoid}, fl_ref)

    GC.@preserve fl_ref begin
        _pkcs11_test_slots[] = Sockets.CK_SLOT_ID[1]
        _pkcs11_test_open_session_rv[] = Sockets.CKR_OK
        _pkcs11_test_session_handle[] = Sockets.CK_SESSION_HANDLE(0x99)
        _pkcs11_test_login_rv[] = Sockets.CKR_OK
        _pkcs11_test_find_objects[] = Sockets.CK_OBJECT_HANDLE[0x55]
        _pkcs11_test_key_type[] = Sockets.CKK_RSA

        handler = Sockets.pkcs11_tls_op_handler_new(
            lib,
            Reseau.ByteCursor("1234"),
            Reseau.null_cursor(),
            Reseau.null_cursor(),
            UInt64(1),
        )
        @test handler isa Sockets.CustomKeyOpHandler

        _pkcs11_test_decrypt_output[] = UInt8[0x0a, 0x0b]
        op_dec = Sockets.TlsKeyOperation(
            Reseau.ByteCursor("cipher");
            operation_type = Sockets.TlsKeyOperationType.DECRYPT,
        )
        Sockets.custom_key_op_handler_perform_operation(handler, op_dec)
        @test op_dec.completed
        @test op_dec.error_code == Reseau.AWS_OP_SUCCESS
        @test collect(op_dec.output.mem[1:Int(op_dec.output.len)]) == _pkcs11_test_decrypt_output[]

        _pkcs11_test_sign_output[] = UInt8[0x55]
        op_sig = Sockets.TlsKeyOperation(
            Reseau.ByteCursor(UInt8[0x01, 0x02]);
            operation_type = Sockets.TlsKeyOperationType.SIGN,
            signature_algorithm = Sockets.TlsSignatureAlgorithm.RSA,
            digest_algorithm = Sockets.TlsHashAlgorithm.SHA256,
        )
        Sockets.custom_key_op_handler_perform_operation(handler, op_sig)
        @test op_sig.completed
        @test op_sig.error_code == Reseau.AWS_OP_SUCCESS
        @test collect(op_sig.output.mem[1:Int(op_sig.output.len)]) == _pkcs11_test_sign_output[]

        Sockets.custom_key_op_handler_release(handler)
    end
end

@testset "IO error parity" begin
    root = dirname(@__DIR__)
    header_path = joinpath(root, "aws-c-io", "include", "aws", "io", "io.h")

    if !isfile(header_path)
        @test true
    else
        function parse_aws_io_errors(path::AbstractString)
            names = String[]
            inside_enum = false
            for line in eachline(path)
                if occursin("enum aws_io_errors", line)
                    inside_enum = true
                    continue
                end
                if !inside_enum
                    continue
                end
                if occursin("};", line)
                    break
                end
                line = split(line, "//"; limit = 2)[1]
                line = split(line, "/*"; limit = 2)[1]
                line = strip(line)
                isempty(line) && continue
                line = replace(line, "," => "")
                name = strip(first(split(line, "="; limit = 2)))
                if startswith(name, "AWS_") || startswith(name, "DEPRECATED_")
                    push!(names, name)
                end
            end
            return names
        end

        function map_aws_error_name(name::AbstractString)
            if name == "AWS_IO_CHANNEL_ERROR_ERROR_CANT_ACCEPT_INPUT"
                return "ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT"
            elseif name == "DEPRECATED_AWS_IO_INVALID_FILE_HANDLE"
                return "ERROR_IO_INVALID_FILE_HANDLE_DEPRECATED"
            elseif name == "AWS_IO_ERROR_END_RANGE"
                return "ERROR_IO_END_RANGE"
            elseif startswith(name, "AWS_ERROR_IO_")
                return "ERROR_" * name[11:end]
            elseif startswith(name, "AWS_IO_")
                return "ERROR_" * name[5:end]
            elseif startswith(name, "AWS_ERROR_")
                return "ERROR_IO_" * name[11:end]
            else
                return "ERROR_" * String(name)
            end
        end

        missing = String[]
        for name in parse_aws_io_errors(header_path)
            mapped = Symbol(map_aws_error_name(name))
            if !isdefined(EventLoops, mapped)
                push!(missing, String(mapped))
            end
        end

        @test isempty(missing)
    end
end

@testset "Socket errno mapping parity" begin
    if Sys.iswindows()
        @test true
    else
        @test Sockets.determine_socket_error(Sockets.ECONNREFUSED) ==
            EventLoops.ERROR_IO_SOCKET_CONNECTION_REFUSED
        @test Sockets.determine_socket_error(Sockets.ECONNRESET) ==
            EventLoops.ERROR_IO_SOCKET_CLOSED
        @test Sockets.determine_socket_error(Sockets.ETIMEDOUT) ==
            EventLoops.ERROR_IO_SOCKET_TIMEOUT
        @test Sockets.determine_socket_error(Sockets.EHOSTUNREACH) ==
            EventLoops.ERROR_IO_SOCKET_NO_ROUTE_TO_HOST
        @test Sockets.determine_socket_error(Sockets.ENETUNREACH) ==
            EventLoops.ERROR_IO_SOCKET_NO_ROUTE_TO_HOST
        @test Sockets.determine_socket_error(Sockets.EADDRNOTAVAIL) ==
            EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
        @test Sockets.determine_socket_error(Sockets.ENETDOWN) ==
            EventLoops.ERROR_IO_SOCKET_NETWORK_DOWN
        @test Sockets.determine_socket_error(Sockets.ECONNABORTED) ==
            EventLoops.ERROR_IO_SOCKET_CONNECT_ABORTED
        @test Sockets.determine_socket_error(Sockets.EADDRINUSE) ==
            EventLoops.ERROR_IO_SOCKET_ADDRESS_IN_USE
        @test Sockets.determine_socket_error(Sockets.ENOBUFS) ==
            Reseau.ERROR_OOM
        @test Sockets.determine_socket_error(Sockets.ENOMEM) ==
            Reseau.ERROR_OOM
        @test Sockets.determine_socket_error(Sockets.EAGAIN) ==
            EventLoops.ERROR_IO_READ_WOULD_BLOCK
        @test Sockets.determine_socket_error(Sockets.EWOULDBLOCK) ==
            EventLoops.ERROR_IO_READ_WOULD_BLOCK
        @test Sockets.determine_socket_error(Sockets.EMFILE) ==
            Reseau.ERROR_MAX_FDS_EXCEEDED
        @test Sockets.determine_socket_error(Sockets.ENFILE) ==
            Reseau.ERROR_MAX_FDS_EXCEEDED
        @test Sockets.determine_socket_error(Sockets.ENOENT) ==
            Reseau.ERROR_FILE_INVALID_PATH
        @test Sockets.determine_socket_error(Sockets.EINVAL) ==
            Reseau.ERROR_FILE_INVALID_PATH
        @test Sockets.determine_socket_error(Sockets.EAFNOSUPPORT) ==
            EventLoops.ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY
        @test Sockets.determine_socket_error(Sockets.EACCES) ==
            Reseau.ERROR_NO_PERMISSION
        @test Sockets.determine_socket_error(9999) ==
            EventLoops.ERROR_IO_SOCKET_NOT_CONNECTED
    end
end
