using Test
using AwsIO

const _pkcs11_test_init_rv = Ref{AwsIO.CK_RV}(AwsIO.CKR_OK)
const _pkcs11_test_finalize_called = Ref(false)
const _pkcs11_test_get_info_called = Ref(false)
const _pkcs11_test_slots = Ref{Vector{AwsIO.CK_SLOT_ID}}(AwsIO.CK_SLOT_ID[])
const _pkcs11_test_token_labels = Ref{Dict{AwsIO.CK_SLOT_ID, String}}(Dict{AwsIO.CK_SLOT_ID, String}())
const _pkcs11_test_open_session_rv = Ref{AwsIO.CK_RV}(AwsIO.CKR_OK)
const _pkcs11_test_close_session_rv = Ref{AwsIO.CK_RV}(AwsIO.CKR_OK)
const _pkcs11_test_login_rv = Ref{AwsIO.CK_RV}(AwsIO.CKR_OK)
const _pkcs11_test_session_handle = Ref{AwsIO.CK_SESSION_HANDLE}(AwsIO.CK_SESSION_HANDLE(0x1234))
const _pkcs11_test_find_init_rv = Ref{AwsIO.CK_RV}(AwsIO.CKR_OK)
const _pkcs11_test_find_rv = Ref{AwsIO.CK_RV}(AwsIO.CKR_OK)
const _pkcs11_test_find_final_rv = Ref{AwsIO.CK_RV}(AwsIO.CKR_OK)
const _pkcs11_test_get_attr_rv = Ref{AwsIO.CK_RV}(AwsIO.CKR_OK)
const _pkcs11_test_find_objects = Ref{Vector{AwsIO.CK_OBJECT_HANDLE}}(AwsIO.CK_OBJECT_HANDLE[])
const _pkcs11_test_key_type = Ref{AwsIO.CK_KEY_TYPE}(AwsIO.CKK_RSA)
const _pkcs11_test_decrypt_init_rv = Ref{AwsIO.CK_RV}(AwsIO.CKR_OK)
const _pkcs11_test_decrypt_rv = Ref{AwsIO.CK_RV}(AwsIO.CKR_OK)
const _pkcs11_test_decrypt_output = Ref{Vector{UInt8}}(UInt8[])
const _pkcs11_test_sign_init_rv = Ref{AwsIO.CK_RV}(AwsIO.CKR_OK)
const _pkcs11_test_sign_rv = Ref{AwsIO.CK_RV}(AwsIO.CKR_OK)
const _pkcs11_test_sign_output = Ref{Vector{UInt8}}(UInt8[])
const _pkcs11_test_sign_input = Ref{Vector{UInt8}}(UInt8[])

function _pkcs11_test_fake_initialize(::Ptr{AwsIO.CK_C_INITIALIZE_ARGS})::AwsIO.CK_RV
    return _pkcs11_test_init_rv[]
end

function _pkcs11_test_fake_finalize(::Ptr{Cvoid})::AwsIO.CK_RV
    _pkcs11_test_finalize_called[] = true
    return AwsIO.CKR_OK
end

function _pkcs11_test_fake_get_info(info_ptr::Ptr{AwsIO.CK_INFO})::AwsIO.CK_RV
    _pkcs11_test_get_info_called[] = true
    info = AwsIO.CK_INFO(
        AwsIO.CK_VERSION(2, 20),
        ntuple(_ -> UInt8(0x20), 32),
        0,
        ntuple(_ -> UInt8(0x20), 32),
        AwsIO.CK_VERSION(1, 0),
    )
    unsafe_store!(info_ptr, info)
    return AwsIO.CKR_OK
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
        ::AwsIO.CK_BBOOL,
        slot_list::Ptr{AwsIO.CK_SLOT_ID},
        count_ptr::Ptr{AwsIO.CK_ULONG},
    )::AwsIO.CK_RV
    slots = _pkcs11_test_slots[]
    unsafe_store!(count_ptr, AwsIO.CK_ULONG(length(slots)))
    if slot_list != C_NULL
        for i in 1:length(slots)
            unsafe_store!(slot_list, slots[i], i)
        end
    end
    return AwsIO.CKR_OK
end

function _pkcs11_test_fake_get_token_info(
        slot_id::AwsIO.CK_SLOT_ID,
        info_ptr::Ptr{AwsIO.CK_TOKEN_INFO},
    )::AwsIO.CK_RV
    label = get(_pkcs11_test_token_labels[], slot_id, "")
    info = AwsIO.CK_TOKEN_INFO(
        _pkcs11_test_label_bytes(label),
        ntuple(_ -> UInt8(0x20), 32),
        ntuple(_ -> UInt8(0x20), 16),
        ntuple(_ -> UInt8(0x20), 16),
        AwsIO.CK_ULONG(0),
        AwsIO.CK_ULONG(0),
        AwsIO.CK_ULONG(0),
        AwsIO.CK_ULONG(0),
        AwsIO.CK_ULONG(0),
        AwsIO.CK_ULONG(0),
        AwsIO.CK_ULONG(0),
        AwsIO.CK_ULONG(0),
        AwsIO.CK_ULONG(0),
        AwsIO.CK_ULONG(0),
        AwsIO.CK_ULONG(0),
        AwsIO.CK_VERSION(0, 0),
        AwsIO.CK_VERSION(0, 0),
        ntuple(_ -> UInt8(0x20), 16),
    )
    unsafe_store!(info_ptr, info)
    return AwsIO.CKR_OK
end

function _pkcs11_test_fake_open_session(
        ::AwsIO.CK_SLOT_ID,
        ::AwsIO.CK_FLAGS,
        ::Ptr{Cvoid},
        ::Ptr{Cvoid},
        session_ptr::Ptr{AwsIO.CK_SESSION_HANDLE},
    )::AwsIO.CK_RV
    unsafe_store!(session_ptr, _pkcs11_test_session_handle[])
    return _pkcs11_test_open_session_rv[]
end

function _pkcs11_test_fake_close_session(::AwsIO.CK_SESSION_HANDLE)::AwsIO.CK_RV
    return _pkcs11_test_close_session_rv[]
end

function _pkcs11_test_fake_login(
        ::AwsIO.CK_SESSION_HANDLE,
        ::AwsIO.CK_ULONG,
        ::Ptr{UInt8},
        ::AwsIO.CK_ULONG,
    )::AwsIO.CK_RV
    return _pkcs11_test_login_rv[]
end

function _pkcs11_test_fake_find_objects_init(
        ::AwsIO.CK_SESSION_HANDLE,
        ::Ptr{AwsIO.CK_ATTRIBUTE},
        ::AwsIO.CK_ULONG,
    )::AwsIO.CK_RV
    return _pkcs11_test_find_init_rv[]
end

function _pkcs11_test_fake_find_objects(
        ::AwsIO.CK_SESSION_HANDLE,
        objects_ptr::Ptr{AwsIO.CK_OBJECT_HANDLE},
        max_objects::AwsIO.CK_ULONG,
        count_ptr::Ptr{AwsIO.CK_ULONG},
    )::AwsIO.CK_RV
    handles = _pkcs11_test_find_objects[]
    count = min(length(handles), Int(max_objects))
    unsafe_store!(count_ptr, AwsIO.CK_ULONG(count))
    if objects_ptr != C_NULL
        for i in 1:count
            unsafe_store!(objects_ptr, handles[i], i)
        end
    end
    return _pkcs11_test_find_rv[]
end

function _pkcs11_test_fake_find_objects_final(::AwsIO.CK_SESSION_HANDLE)::AwsIO.CK_RV
    return _pkcs11_test_find_final_rv[]
end

function _pkcs11_test_fake_get_attribute_value(
        ::AwsIO.CK_SESSION_HANDLE,
        ::AwsIO.CK_OBJECT_HANDLE,
        attrs_ptr::Ptr{AwsIO.CK_ATTRIBUTE},
        attr_count::AwsIO.CK_ULONG,
    )::AwsIO.CK_RV
    if attrs_ptr != C_NULL && attr_count > 0
        attr = unsafe_load(attrs_ptr)
        if attr.type == AwsIO.CKA_KEY_TYPE && attr.pValue != C_NULL
            unsafe_store!(Ptr{AwsIO.CK_KEY_TYPE}(attr.pValue), _pkcs11_test_key_type[])
        end
    end
    return _pkcs11_test_get_attr_rv[]
end

function _pkcs11_test_fake_decrypt_init(
        ::AwsIO.CK_SESSION_HANDLE,
        ::Ptr{AwsIO.CK_MECHANISM},
        ::AwsIO.CK_OBJECT_HANDLE,
    )::AwsIO.CK_RV
    return _pkcs11_test_decrypt_init_rv[]
end

function _pkcs11_test_fake_decrypt(
        ::AwsIO.CK_SESSION_HANDLE,
        ::Ptr{UInt8},
        ::AwsIO.CK_ULONG,
        out_ptr::Ptr{UInt8},
        out_len_ptr::Ptr{AwsIO.CK_ULONG},
    )::AwsIO.CK_RV
    data = _pkcs11_test_decrypt_output[]
    unsafe_store!(out_len_ptr, AwsIO.CK_ULONG(length(data)))
    if out_ptr != C_NULL
        for i in 1:length(data)
            unsafe_store!(out_ptr, data[i], i)
        end
    end
    return _pkcs11_test_decrypt_rv[]
end

function _pkcs11_test_fake_sign_init(
        ::AwsIO.CK_SESSION_HANDLE,
        ::Ptr{AwsIO.CK_MECHANISM},
        ::AwsIO.CK_OBJECT_HANDLE,
    )::AwsIO.CK_RV
    return _pkcs11_test_sign_init_rv[]
end

function _pkcs11_test_fake_sign(
        ::AwsIO.CK_SESSION_HANDLE,
        input_ptr::Ptr{UInt8},
        input_len::AwsIO.CK_ULONG,
        sig_ptr::Ptr{UInt8},
        sig_len_ptr::Ptr{AwsIO.CK_ULONG},
    )::AwsIO.CK_RV
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
    unsafe_store!(sig_len_ptr, AwsIO.CK_ULONG(length(sig)))
    if sig_ptr != C_NULL
        for i in 1:length(sig)
            unsafe_store!(sig_ptr, sig[i], i)
        end
    end
    return _pkcs11_test_sign_rv[]
end

@testset "IO library init/cleanup" begin
    AwsIO.io_library_init()
    AwsIO.io_library_init()
    AwsIO.io_fatal_assert_library_initialized()

    @test unsafe_string(AwsIO.error_name(AwsIO.ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)) ==
        "ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT"
    @test unsafe_string(AwsIO.error_str(AwsIO.ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)) ==
        "Channel cannot accept input"
    @test unsafe_string(AwsIO.error_str(AwsIO.ERROR_IO_PKCS11_CKR_CANCEL)) ==
        "A PKCS#11 (Cryptoki) library function failed with return value CKR_CANCEL"
    @test unsafe_string(AwsIO.error_str(AwsIO.ERROR_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND)) ==
        "Default TLS trust store not found on this system. Trusted CA certificates must be installed, or \"override default trust store\" must be used while creating the TLS context."

    @test AwsIO.log_subject_name(AwsIO.LS_IO_GENERAL) == "aws-c-io"
    @test AwsIO.log_subject_description(AwsIO.LS_IO_GENERAL) ==
        "Subject for IO logging that doesn't belong to any particular category"
    @test AwsIO.log_subject_name(AwsIO.LS_IO_TLS) == "tls-handler"

    @test AwsIO.io_error_code_is_retryable(AwsIO.ERROR_IO_SOCKET_TIMEOUT)
    @test !AwsIO.io_error_code_is_retryable(AwsIO.ERROR_IO_SOCKET_NO_ROUTE_TO_HOST)

    AwsIO.io_library_clean_up()
    AwsIO.io_library_clean_up()
    @test_throws ErrorException AwsIO.io_fatal_assert_library_initialized()
end

@testset "PKCS11 error code string" begin
    @test AwsIO.pkcs11_error_code_str(AwsIO.ERROR_IO_PKCS11_CKR_CANCEL) == "CKR_CANCEL"
    @test AwsIO.pkcs11_error_code_str(AwsIO.ERROR_IO_PKCS11_CKR_FUNCTION_REJECTED) ==
          "CKR_FUNCTION_REJECTED"
    @test AwsIO.pkcs11_error_code_str(0) === nothing
    @test AwsIO.pkcs11_ckr_str(AwsIO.CKR_OK) == "CKR_OK"
    @test AwsIO.pkcs11_ckr_str(0xffff) == "CKR_UNKNOWN"
end

@testset "PKCS11 lib stubs" begin
    temp_dir = mktempdir()
    missing_path = joinpath(temp_dir, "missing_pkcs11_lib")
    opts = AwsIO.Pkcs11LibOptions(; filename = missing_path)
    lib = AwsIO.pkcs11_lib_new(opts)
    @test lib isa AwsIO.ErrorResult
    if lib isa AwsIO.ErrorResult
        @test lib.code == AwsIO.ERROR_IO_SHARED_LIBRARY_LOAD_FAILURE
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
            @test AwsIO.pkcs11_error_from_ckr(rv_cancel) == AwsIO.ERROR_IO_PKCS11_CKR_CANCEL
        end
        @test AwsIO.pkcs11_error_from_ckr(0xffffffffffffffff) ==
            AwsIO.ERROR_IO_PKCS11_UNKNOWN_CRYPTOKI_RETURN_VALUE
    end
end

@testset "PKCS11 init behavior" begin
    init_fn = @cfunction(_pkcs11_test_fake_initialize, AwsIO.CK_RV, (Ptr{AwsIO.CK_C_INITIALIZE_ARGS},))
    finalize_fn = @cfunction(_pkcs11_test_fake_finalize, AwsIO.CK_RV, (Ptr{Cvoid},))
    get_info_fn = @cfunction(_pkcs11_test_fake_get_info, AwsIO.CK_RV, (Ptr{AwsIO.CK_INFO},))

    fl = AwsIO._pkcs11_function_list_stub(
        C_Initialize = init_fn,
        C_Finalize = finalize_fn,
        C_GetInfo = get_info_fn,
    )
    fl_ref = Ref(fl)

    function build_lib(behavior)
        lib = AwsIO.Pkcs11Lib(
            AwsIO.Pkcs11LibOptions(
                filename = nothing,
                initialize_finalize_behavior = behavior,
            ),
        )
        lib.function_list = Base.unsafe_convert(Ptr{Cvoid}, fl_ref)
        return lib
    end

    GC.@preserve fl_ref begin
        _pkcs11_test_init_rv[] = AwsIO.CKR_CRYPTOKI_ALREADY_INITIALIZED
        _pkcs11_test_get_info_called[] = false
        lib_default = build_lib(AwsIO.Pkcs11LibBehavior.DEFAULT_BEHAVIOR)
        res_default = AwsIO._pkcs11_init_with_function_list!(lib_default)
        @test res_default === nothing
        @test _pkcs11_test_get_info_called[]
        @test !lib_default.finalize_on_cleanup

        _pkcs11_test_init_rv[] = AwsIO.CKR_CRYPTOKI_ALREADY_INITIALIZED
        lib_strict = build_lib(AwsIO.Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE)
        res_strict = AwsIO._pkcs11_init_with_function_list!(lib_strict)
        @test res_strict isa AwsIO.ErrorResult
        if res_strict isa AwsIO.ErrorResult
            @test res_strict.code == AwsIO.ERROR_IO_PKCS11_CKR_CRYPTOKI_ALREADY_INITIALIZED
        end

        _pkcs11_test_init_rv[] = AwsIO.CKR_OK
        _pkcs11_test_finalize_called[] = false
        lib_finalize = build_lib(AwsIO.Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE)
        res_finalize = AwsIO._pkcs11_init_with_function_list!(lib_finalize)
        @test res_finalize === nothing
        @test lib_finalize.finalize_on_cleanup
        AwsIO.pkcs11_lib_release(lib_finalize)
        @test _pkcs11_test_finalize_called[]
    end
end

@testset "PKCS11 slot/session helpers" begin
    get_slot_fn = @cfunction(
        _pkcs11_test_fake_get_slot_list,
        AwsIO.CK_RV,
        (AwsIO.CK_BBOOL, Ptr{AwsIO.CK_SLOT_ID}, Ptr{AwsIO.CK_ULONG}),
    )
    get_token_fn = @cfunction(
        _pkcs11_test_fake_get_token_info,
        AwsIO.CK_RV,
        (AwsIO.CK_SLOT_ID, Ptr{AwsIO.CK_TOKEN_INFO}),
    )
    open_fn = @cfunction(
        _pkcs11_test_fake_open_session,
        AwsIO.CK_RV,
        (AwsIO.CK_SLOT_ID, AwsIO.CK_FLAGS, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{AwsIO.CK_SESSION_HANDLE}),
    )
    close_fn = @cfunction(
        _pkcs11_test_fake_close_session,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE,),
    )
    login_fn = @cfunction(
        _pkcs11_test_fake_login,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, AwsIO.CK_ULONG, Ptr{UInt8}, AwsIO.CK_ULONG),
    )

    fl = AwsIO._pkcs11_function_list_stub(
        C_GetSlotList = get_slot_fn,
        C_GetTokenInfo = get_token_fn,
        C_OpenSession = open_fn,
        C_CloseSession = close_fn,
        C_Login = login_fn,
    )
    fl_ref = Ref(fl)

    lib = AwsIO.Pkcs11Lib(AwsIO.Pkcs11LibOptions(filename = nothing))
    lib.function_list = Base.unsafe_convert(Ptr{Cvoid}, fl_ref)

    GC.@preserve fl_ref begin
        _pkcs11_test_slots[] = AwsIO.CK_SLOT_ID[]
        res_empty = AwsIO.pkcs11_lib_find_slot_with_token(lib, nothing, nothing)
        @test res_empty isa AwsIO.ErrorResult
        if res_empty isa AwsIO.ErrorResult
            @test res_empty.code == AwsIO.ERROR_IO_PKCS11_TOKEN_NOT_FOUND
        end

        _pkcs11_test_slots[] = AwsIO.CK_SLOT_ID[1, 2]
        res_multi = AwsIO.pkcs11_lib_find_slot_with_token(lib, nothing, nothing)
        @test res_multi isa AwsIO.ErrorResult
        if res_multi isa AwsIO.ErrorResult
            @test res_multi.code == AwsIO.ERROR_IO_PKCS11_TOKEN_NOT_FOUND
        end

        res_match = AwsIO.pkcs11_lib_find_slot_with_token(lib, UInt64(2), nothing)
        @test res_match == 2

        _pkcs11_test_token_labels[] = Dict{AwsIO.CK_SLOT_ID, String}(1 => "alpha", 2 => "beta")
        res_label = AwsIO.pkcs11_lib_find_slot_with_token(lib, nothing, AwsIO.ByteCursor("beta"))
        @test res_label == 2

        _pkcs11_test_open_session_rv[] = AwsIO.CKR_OK
        _pkcs11_test_session_handle[] = AwsIO.CK_SESSION_HANDLE(0x55)
        session = AwsIO.pkcs11_lib_open_session(lib, UInt64(1))
        @test session == AwsIO.CK_SESSION_HANDLE(0x55)

        _pkcs11_test_open_session_rv[] = AwsIO.CKR_FUNCTION_NOT_SUPPORTED
        bad_session = AwsIO.pkcs11_lib_open_session(lib, UInt64(1))
        @test bad_session isa AwsIO.ErrorResult
        if bad_session isa AwsIO.ErrorResult
            @test bad_session.code == AwsIO.ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED
        end

        _pkcs11_test_close_session_rv[] = AwsIO.CKR_OK
        @test AwsIO.pkcs11_lib_close_session(lib, AwsIO.CK_SESSION_HANDLE(0x55)) === nothing

        _pkcs11_test_close_session_rv[] = AwsIO.CKR_FUNCTION_NOT_SUPPORTED
        bad_close = AwsIO.pkcs11_lib_close_session(lib, AwsIO.CK_SESSION_HANDLE(0x55))
        @test bad_close isa AwsIO.ErrorResult
        if bad_close isa AwsIO.ErrorResult
            @test bad_close.code == AwsIO.ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED
        end

        _pkcs11_test_login_rv[] = AwsIO.CKR_USER_ALREADY_LOGGED_IN
        @test AwsIO.pkcs11_lib_login_user(lib, AwsIO.CK_SESSION_HANDLE(0x55), AwsIO.ByteCursor("1234")) ===
              nothing

        _pkcs11_test_login_rv[] = AwsIO.CKR_FUNCTION_NOT_SUPPORTED
        bad_login = AwsIO.pkcs11_lib_login_user(lib, AwsIO.CK_SESSION_HANDLE(0x55), AwsIO.ByteCursor("1234"))
        @test bad_login isa AwsIO.ErrorResult
        if bad_login isa AwsIO.ErrorResult
            @test bad_login.code == AwsIO.ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED
        end
    end
end

@testset "PKCS11 private key operations" begin
    find_init_fn = @cfunction(
        _pkcs11_test_fake_find_objects_init,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, Ptr{AwsIO.CK_ATTRIBUTE}, AwsIO.CK_ULONG),
    )
    find_fn = @cfunction(
        _pkcs11_test_fake_find_objects,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, Ptr{AwsIO.CK_OBJECT_HANDLE}, AwsIO.CK_ULONG, Ptr{AwsIO.CK_ULONG}),
    )
    find_final_fn = @cfunction(
        _pkcs11_test_fake_find_objects_final,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE,),
    )
    get_attr_fn = @cfunction(
        _pkcs11_test_fake_get_attribute_value,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, AwsIO.CK_OBJECT_HANDLE, Ptr{AwsIO.CK_ATTRIBUTE}, AwsIO.CK_ULONG),
    )
    decrypt_init_fn = @cfunction(
        _pkcs11_test_fake_decrypt_init,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, Ptr{AwsIO.CK_MECHANISM}, AwsIO.CK_OBJECT_HANDLE),
    )
    decrypt_fn = @cfunction(
        _pkcs11_test_fake_decrypt,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, Ptr{UInt8}, AwsIO.CK_ULONG, Ptr{UInt8}, Ptr{AwsIO.CK_ULONG}),
    )
    sign_init_fn = @cfunction(
        _pkcs11_test_fake_sign_init,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, Ptr{AwsIO.CK_MECHANISM}, AwsIO.CK_OBJECT_HANDLE),
    )
    sign_fn = @cfunction(
        _pkcs11_test_fake_sign,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, Ptr{UInt8}, AwsIO.CK_ULONG, Ptr{UInt8}, Ptr{AwsIO.CK_ULONG}),
    )

    fl = AwsIO._pkcs11_function_list_stub(
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

    lib = AwsIO.Pkcs11Lib(AwsIO.Pkcs11LibOptions(filename = nothing))
    lib.function_list = Base.unsafe_convert(Ptr{Cvoid}, fl_ref)

    GC.@preserve fl_ref begin
        _pkcs11_test_find_objects[] = AwsIO.CK_OBJECT_HANDLE[]
        res_none = AwsIO.pkcs11_lib_find_private_key(lib, AwsIO.CK_SESSION_HANDLE(1), nothing)
        @test res_none isa AwsIO.ErrorResult
        if res_none isa AwsIO.ErrorResult
            @test res_none.code == AwsIO.ERROR_IO_PKCS11_KEY_NOT_FOUND
        end

        _pkcs11_test_find_objects[] = AwsIO.CK_OBJECT_HANDLE[1, 2]
        res_multi = AwsIO.pkcs11_lib_find_private_key(lib, AwsIO.CK_SESSION_HANDLE(1), nothing)
        @test res_multi isa AwsIO.ErrorResult
        if res_multi isa AwsIO.ErrorResult
            @test res_multi.code == AwsIO.ERROR_IO_PKCS11_KEY_NOT_FOUND
        end

        _pkcs11_test_find_objects[] = AwsIO.CK_OBJECT_HANDLE[3]
        _pkcs11_test_key_type[] = AwsIO.CK_KEY_TYPE(0xdead)
        res_bad_type = AwsIO.pkcs11_lib_find_private_key(lib, AwsIO.CK_SESSION_HANDLE(1), nothing)
        @test res_bad_type isa AwsIO.ErrorResult
        if res_bad_type isa AwsIO.ErrorResult
            @test res_bad_type.code == AwsIO.ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED
        end

        _pkcs11_test_key_type[] = AwsIO.CKK_RSA
        res_ok = AwsIO.pkcs11_lib_find_private_key(lib, AwsIO.CK_SESSION_HANDLE(1), AwsIO.ByteCursor("key"))
        @test res_ok == (AwsIO.CK_OBJECT_HANDLE(3), AwsIO.CKK_RSA)

        _pkcs11_test_decrypt_output[] = UInt8[0x01, 0x02, 0x03]
        _pkcs11_test_decrypt_rv[] = AwsIO.CKR_OK
        dec = AwsIO.pkcs11_lib_decrypt(
            lib,
            AwsIO.CK_SESSION_HANDLE(1),
            AwsIO.CK_OBJECT_HANDLE(3),
            AwsIO.CKK_RSA,
            AwsIO.ByteCursor("cipher"),
        )
        @test dec isa AwsIO.ByteBuffer
        if dec isa AwsIO.ByteBuffer
            @test collect(dec.mem[1:Int(dec.len)]) == _pkcs11_test_decrypt_output[]
        end

        bad_dec = AwsIO.pkcs11_lib_decrypt(
            lib,
            AwsIO.CK_SESSION_HANDLE(1),
            AwsIO.CK_OBJECT_HANDLE(3),
            AwsIO.CKK_EC,
            AwsIO.ByteCursor("cipher"),
        )
        @test bad_dec isa AwsIO.ErrorResult
        if bad_dec isa AwsIO.ErrorResult
            @test bad_dec.code == AwsIO.ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED
        end

        _pkcs11_test_decrypt_rv[] = AwsIO.CKR_FUNCTION_NOT_SUPPORTED
        bad_dec_rv = AwsIO.pkcs11_lib_decrypt(
            lib,
            AwsIO.CK_SESSION_HANDLE(1),
            AwsIO.CK_OBJECT_HANDLE(3),
            AwsIO.CKK_RSA,
            AwsIO.ByteCursor("cipher"),
        )
        @test bad_dec_rv isa AwsIO.ErrorResult
        if bad_dec_rv isa AwsIO.ErrorResult
            @test bad_dec_rv.code == AwsIO.ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED
        end
        _pkcs11_test_decrypt_rv[] = AwsIO.CKR_OK

        rsa_prefix = UInt8[
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
            0x05, 0x00, 0x04, 0x20,
        ]
        digest = UInt8[0xaa, 0xbb]
        _pkcs11_test_sign_output[] = UInt8[0x11, 0x22]
        _pkcs11_test_sign_rv[] = AwsIO.CKR_OK
        _pkcs11_test_sign_input[] = UInt8[]
        sig = AwsIO.pkcs11_lib_sign(
            lib,
            AwsIO.CK_SESSION_HANDLE(1),
            AwsIO.CK_OBJECT_HANDLE(3),
            AwsIO.CKK_RSA,
            AwsIO.ByteCursor(digest),
            AwsIO.TlsHashAlgorithm.SHA256,
            AwsIO.TlsSignatureAlgorithm.RSA,
        )
        @test sig isa AwsIO.ByteBuffer
        if sig isa AwsIO.ByteBuffer
            @test collect(sig.mem[1:Int(sig.len)]) == _pkcs11_test_sign_output[]
        end
        @test _pkcs11_test_sign_input[] == vcat(rsa_prefix, digest)

        bad_sig_alg = AwsIO.pkcs11_lib_sign(
            lib,
            AwsIO.CK_SESSION_HANDLE(1),
            AwsIO.CK_OBJECT_HANDLE(3),
            AwsIO.CKK_RSA,
            AwsIO.ByteCursor(digest),
            AwsIO.TlsHashAlgorithm.SHA256,
            AwsIO.TlsSignatureAlgorithm.ECDSA,
        )
        @test bad_sig_alg isa AwsIO.ErrorResult
        if bad_sig_alg isa AwsIO.ErrorResult
            @test bad_sig_alg.code == AwsIO.ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED
        end

        bad_digest = AwsIO.pkcs11_lib_sign(
            lib,
            AwsIO.CK_SESSION_HANDLE(1),
            AwsIO.CK_OBJECT_HANDLE(3),
            AwsIO.CKK_RSA,
            AwsIO.ByteCursor(digest),
            AwsIO.TlsHashAlgorithm.UNKNOWN,
            AwsIO.TlsSignatureAlgorithm.RSA,
        )
        @test bad_digest isa AwsIO.ErrorResult
        if bad_digest isa AwsIO.ErrorResult
            @test bad_digest.code == AwsIO.ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED
        end

        _pkcs11_test_sign_output[] = UInt8[0x01, 0x02, 0x03, 0x04]
        sig_ec = AwsIO.pkcs11_lib_sign(
            lib,
            AwsIO.CK_SESSION_HANDLE(1),
            AwsIO.CK_OBJECT_HANDLE(3),
            AwsIO.CKK_EC,
            AwsIO.ByteCursor(digest),
            AwsIO.TlsHashAlgorithm.SHA256,
            AwsIO.TlsSignatureAlgorithm.ECDSA,
        )
        @test sig_ec isa AwsIO.ByteBuffer
        if sig_ec isa AwsIO.ByteBuffer
            @test collect(sig_ec.mem[1:Int(sig_ec.len)]) ==
                  UInt8[0x30, 0x08, 0x02, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03, 0x04]
        end

        bad_ec_sig_alg = AwsIO.pkcs11_lib_sign(
            lib,
            AwsIO.CK_SESSION_HANDLE(1),
            AwsIO.CK_OBJECT_HANDLE(3),
            AwsIO.CKK_EC,
            AwsIO.ByteCursor(digest),
            AwsIO.TlsHashAlgorithm.SHA256,
            AwsIO.TlsSignatureAlgorithm.RSA,
        )
        @test bad_ec_sig_alg isa AwsIO.ErrorResult
        if bad_ec_sig_alg isa AwsIO.ErrorResult
            @test bad_ec_sig_alg.code == AwsIO.ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED
        end

        bad_key = AwsIO.pkcs11_lib_sign(
            lib,
            AwsIO.CK_SESSION_HANDLE(1),
            AwsIO.CK_OBJECT_HANDLE(3),
            AwsIO.CK_KEY_TYPE(0xdead),
            AwsIO.ByteCursor(digest),
            AwsIO.TlsHashAlgorithm.SHA256,
            AwsIO.TlsSignatureAlgorithm.RSA,
        )
        @test bad_key isa AwsIO.ErrorResult
        if bad_key isa AwsIO.ErrorResult
            @test bad_key.code == AwsIO.ERROR_IO_PKCS11_KEY_TYPE_UNSUPPORTED
        end
    end
end

@testset "PKCS11 TLS op handler" begin
    get_slot_fn = @cfunction(
        _pkcs11_test_fake_get_slot_list,
        AwsIO.CK_RV,
        (AwsIO.CK_BBOOL, Ptr{AwsIO.CK_SLOT_ID}, Ptr{AwsIO.CK_ULONG}),
    )
    get_token_fn = @cfunction(
        _pkcs11_test_fake_get_token_info,
        AwsIO.CK_RV,
        (AwsIO.CK_SLOT_ID, Ptr{AwsIO.CK_TOKEN_INFO}),
    )
    open_fn = @cfunction(
        _pkcs11_test_fake_open_session,
        AwsIO.CK_RV,
        (AwsIO.CK_SLOT_ID, AwsIO.CK_FLAGS, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{AwsIO.CK_SESSION_HANDLE}),
    )
    close_fn = @cfunction(
        _pkcs11_test_fake_close_session,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE,),
    )
    login_fn = @cfunction(
        _pkcs11_test_fake_login,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, AwsIO.CK_ULONG, Ptr{UInt8}, AwsIO.CK_ULONG),
    )
    find_init_fn = @cfunction(
        _pkcs11_test_fake_find_objects_init,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, Ptr{AwsIO.CK_ATTRIBUTE}, AwsIO.CK_ULONG),
    )
    find_fn = @cfunction(
        _pkcs11_test_fake_find_objects,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, Ptr{AwsIO.CK_OBJECT_HANDLE}, AwsIO.CK_ULONG, Ptr{AwsIO.CK_ULONG}),
    )
    find_final_fn = @cfunction(
        _pkcs11_test_fake_find_objects_final,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE,),
    )
    get_attr_fn = @cfunction(
        _pkcs11_test_fake_get_attribute_value,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, AwsIO.CK_OBJECT_HANDLE, Ptr{AwsIO.CK_ATTRIBUTE}, AwsIO.CK_ULONG),
    )
    decrypt_init_fn = @cfunction(
        _pkcs11_test_fake_decrypt_init,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, Ptr{AwsIO.CK_MECHANISM}, AwsIO.CK_OBJECT_HANDLE),
    )
    decrypt_fn = @cfunction(
        _pkcs11_test_fake_decrypt,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, Ptr{UInt8}, AwsIO.CK_ULONG, Ptr{UInt8}, Ptr{AwsIO.CK_ULONG}),
    )
    sign_init_fn = @cfunction(
        _pkcs11_test_fake_sign_init,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, Ptr{AwsIO.CK_MECHANISM}, AwsIO.CK_OBJECT_HANDLE),
    )
    sign_fn = @cfunction(
        _pkcs11_test_fake_sign,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, Ptr{UInt8}, AwsIO.CK_ULONG, Ptr{UInt8}, Ptr{AwsIO.CK_ULONG}),
    )

    fl = AwsIO._pkcs11_function_list_stub(
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

    lib = AwsIO.Pkcs11Lib(AwsIO.Pkcs11LibOptions(filename = nothing))
    lib.function_list = Base.unsafe_convert(Ptr{Cvoid}, fl_ref)

    GC.@preserve fl_ref begin
        _pkcs11_test_slots[] = AwsIO.CK_SLOT_ID[1]
        _pkcs11_test_open_session_rv[] = AwsIO.CKR_OK
        _pkcs11_test_session_handle[] = AwsIO.CK_SESSION_HANDLE(0x99)
        _pkcs11_test_login_rv[] = AwsIO.CKR_OK
        _pkcs11_test_find_objects[] = AwsIO.CK_OBJECT_HANDLE[0x55]
        _pkcs11_test_key_type[] = AwsIO.CKK_RSA

        handler = AwsIO.pkcs11_tls_op_handler_new(
            lib,
            AwsIO.ByteCursor("1234"),
            AwsIO.null_cursor(),
            AwsIO.null_cursor(),
            UInt64(1),
        )
        @test handler isa AwsIO.CustomKeyOpHandler

        _pkcs11_test_decrypt_output[] = UInt8[0x0a, 0x0b]
        op_dec = AwsIO.TlsKeyOperation(
            AwsIO.ByteCursor("cipher");
            operation_type = AwsIO.TlsKeyOperationType.DECRYPT,
        )
        AwsIO.custom_key_op_handler_perform_operation(handler, op_dec)
        @test op_dec.completed
        @test op_dec.error_code == AwsIO.AWS_OP_SUCCESS
        @test collect(op_dec.output.mem[1:Int(op_dec.output.len)]) == _pkcs11_test_decrypt_output[]

        _pkcs11_test_sign_output[] = UInt8[0x55]
        op_sig = AwsIO.TlsKeyOperation(
            AwsIO.ByteCursor(UInt8[0x01, 0x02]);
            operation_type = AwsIO.TlsKeyOperationType.SIGN,
            signature_algorithm = AwsIO.TlsSignatureAlgorithm.RSA,
            digest_algorithm = AwsIO.TlsHashAlgorithm.SHA256,
        )
        AwsIO.custom_key_op_handler_perform_operation(handler, op_sig)
        @test op_sig.completed
        @test op_sig.error_code == AwsIO.AWS_OP_SUCCESS
        @test collect(op_sig.output.mem[1:Int(op_sig.output.len)]) == _pkcs11_test_sign_output[]

        AwsIO.custom_key_op_handler_release(handler)
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
            if !isdefined(AwsIO, mapped)
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
        @test AwsIO.determine_socket_error(AwsIO.ECONNREFUSED) ==
            AwsIO.ERROR_IO_SOCKET_CONNECTION_REFUSED
        @test AwsIO.determine_socket_error(AwsIO.ECONNRESET) ==
            AwsIO.ERROR_IO_SOCKET_CLOSED
        @test AwsIO.determine_socket_error(AwsIO.ETIMEDOUT) ==
            AwsIO.ERROR_IO_SOCKET_TIMEOUT
        @test AwsIO.determine_socket_error(AwsIO.EHOSTUNREACH) ==
            AwsIO.ERROR_IO_SOCKET_NO_ROUTE_TO_HOST
        @test AwsIO.determine_socket_error(AwsIO.ENETUNREACH) ==
            AwsIO.ERROR_IO_SOCKET_NO_ROUTE_TO_HOST
        @test AwsIO.determine_socket_error(AwsIO.EADDRNOTAVAIL) ==
            AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS
        @test AwsIO.determine_socket_error(AwsIO.ENETDOWN) ==
            AwsIO.ERROR_IO_SOCKET_NETWORK_DOWN
        @test AwsIO.determine_socket_error(AwsIO.ECONNABORTED) ==
            AwsIO.ERROR_IO_SOCKET_CONNECT_ABORTED
        @test AwsIO.determine_socket_error(AwsIO.EADDRINUSE) ==
            AwsIO.ERROR_IO_SOCKET_ADDRESS_IN_USE
        @test AwsIO.determine_socket_error(AwsIO.ENOBUFS) ==
            AwsIO.ERROR_OOM
        @test AwsIO.determine_socket_error(AwsIO.ENOMEM) ==
            AwsIO.ERROR_OOM
        @test AwsIO.determine_socket_error(AwsIO.EAGAIN) ==
            AwsIO.ERROR_IO_READ_WOULD_BLOCK
        @test AwsIO.determine_socket_error(AwsIO.EWOULDBLOCK) ==
            AwsIO.ERROR_IO_READ_WOULD_BLOCK
        @test AwsIO.determine_socket_error(AwsIO.EMFILE) ==
            AwsIO.ERROR_MAX_FDS_EXCEEDED
        @test AwsIO.determine_socket_error(AwsIO.ENFILE) ==
            AwsIO.ERROR_MAX_FDS_EXCEEDED
        @test AwsIO.determine_socket_error(AwsIO.ENOENT) ==
            AwsIO.ERROR_FILE_INVALID_PATH
        @test AwsIO.determine_socket_error(AwsIO.EINVAL) ==
            AwsIO.ERROR_FILE_INVALID_PATH
        @test AwsIO.determine_socket_error(AwsIO.EAFNOSUPPORT) ==
            AwsIO.ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY
        @test AwsIO.determine_socket_error(AwsIO.EACCES) ==
            AwsIO.ERROR_NO_PERMISSION
        @test AwsIO.determine_socket_error(9999) ==
            AwsIO.ERROR_IO_SOCKET_NOT_CONNECTED
    end
end
