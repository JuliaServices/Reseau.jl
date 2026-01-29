using Test
using AwsIO
using Random

const PKCS11_ENV_LIB = "TEST_PKCS11_LIB"
const PKCS11_ENV_TOKEN_DIR = "TEST_PKCS11_TOKEN_DIR"

const TOKEN_LABEL = "my-token"
const TOKEN_LABEL_RSA = "my-rsa-token"
const TOKEN_LABEL_EC = "my-ec-token"
const SO_PIN = "1111"
const USER_PIN = "0000"
const DEFAULT_KEY_LABEL = "my-key"
const DEFAULT_KEY_ID = "AABBCCDD"

const TIMEOUT_SEC = 10.0

@testset "PKCS11 error mapping" begin
    @test AwsIO.pkcs11_error_from_ckr(AwsIO.CKR_FUNCTION_NOT_SUPPORTED) ==
        AwsIO.ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED
    @test AwsIO.pkcs11_error_from_ckr(0xdeadbeef) ==
        AwsIO.ERROR_IO_PKCS11_UNKNOWN_CRYPTOKI_RETURN_VALUE
    @test AwsIO.pkcs11_ckr_str(AwsIO.CKR_FUNCTION_NOT_SUPPORTED) == "CKR_FUNCTION_NOT_SUPPORTED"
    @test AwsIO.pkcs11_ckr_str(0xdeadbeef) == "CKR_UNKNOWN"
end

mutable struct Pkcs11Tester
    lib_path::String
    token_dir::String
    lib::Union{AwsIO.Pkcs11Lib, Nothing}
end

function pkcs11_env_ready()
    lib_path = get(ENV, PKCS11_ENV_LIB, "")
    token_dir = get(ENV, PKCS11_ENV_TOKEN_DIR, "")
    return !isempty(lib_path) && !isempty(token_dir) && Sys.which("softhsm2-util") !== nothing
end

function pkcs11_clear_softhsm!(tester::Pkcs11Tester)
    if !isempty(tester.token_dir)
        rm(tester.token_dir; recursive = true, force = true)
        mkpath(tester.token_dir)
    end
    return nothing
end

function pkcs11_tester_init_without_load!(tester::Pkcs11Tester)
    AwsIO.io_library_init()
    tester.lib_path = get(ENV, PKCS11_ENV_LIB, "")
    tester.token_dir = get(ENV, PKCS11_ENV_TOKEN_DIR, "")
    pkcs11_clear_softhsm!(tester)
    tester.lib = nothing
    return nothing
end

function pkcs11_tester_init!(
        tester::Pkcs11Tester;
        behavior::AwsIO.Pkcs11LibBehavior.T = AwsIO.Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE,
    )
    pkcs11_tester_init_without_load!(tester)
    opts = AwsIO.Pkcs11LibOptions(;
        filename = tester.lib_path,
        initialize_finalize_behavior = behavior,
    )
    lib = AwsIO.pkcs11_lib_new(opts)
    @test lib isa AwsIO.Pkcs11Lib
    tester.lib = lib isa AwsIO.Pkcs11Lib ? lib : nothing
    return tester.lib
end

function pkcs11_tester_cleanup!(tester::Pkcs11Tester)
    if tester.lib !== nothing
        AwsIO.pkcs11_lib_release(tester.lib)
        tester.lib = nothing
    end
    pkcs11_clear_softhsm!(tester)
    AwsIO.io_library_clean_up()
    tester.lib_path = ""
    tester.token_dir = ""
    return nothing
end

function pkcs11_reload_hsm!(tester::Pkcs11Tester)
    if tester.lib !== nothing
        AwsIO.pkcs11_lib_release(tester.lib)
        tester.lib = nothing
    end
    opts = AwsIO.Pkcs11LibOptions(;
        filename = tester.lib_path,
        initialize_finalize_behavior = AwsIO.Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE,
    )
    lib = AwsIO.pkcs11_lib_new(opts)
    @test lib isa AwsIO.Pkcs11Lib
    tester.lib = lib isa AwsIO.Pkcs11Lib ? lib : nothing
    return tester.lib
end

function pkcs11_empty_token_info()
    return AwsIO.CK_TOKEN_INFO(
        ntuple(_ -> UInt8(0x20), 32),
        ntuple(_ -> UInt8(0x20), 32),
        ntuple(_ -> UInt8(0x20), 16),
        ntuple(_ -> UInt8(0x20), 16),
        AwsIO.CK_FLAGS(0),
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
end

function pkcs11_find_slot(tester::Pkcs11Tester, token_info::Union{AwsIO.CK_TOKEN_INFO, Nothing})
    @test tester.lib !== nothing
    fl_ptr = AwsIO.pkcs11_lib_get_function_list(tester.lib::AwsIO.Pkcs11Lib)
    @test fl_ptr != C_NULL
    fl = unsafe_load(fl_ptr)

    slot_count = Ref{AwsIO.CK_ULONG}(0)
    rv = ccall(
        fl.C_GetSlotList,
        AwsIO.CK_RV,
        (AwsIO.CK_BBOOL, Ptr{AwsIO.CK_SLOT_ID}, Ptr{AwsIO.CK_ULONG}),
        AwsIO.CK_TRUE,
        C_NULL,
        slot_count,
    )
    @test rv == AwsIO.CKR_OK

    count = Int(slot_count[])
    slots = Memory{AwsIO.CK_SLOT_ID}(undef, count)
    rv = GC.@preserve slots begin
        ccall(
            fl.C_GetSlotList,
            AwsIO.CK_RV,
            (AwsIO.CK_BBOOL, Ptr{AwsIO.CK_SLOT_ID}, Ptr{AwsIO.CK_ULONG}),
            AwsIO.CK_FALSE,
            pointer(slots),
            slot_count,
        )
    end
    @test rv == AwsIO.CKR_OK

    found_slot = AwsIO.CK_SLOT_ID(0)
    matches = 0
    for i in 1:count
        info_ref = Ref(pkcs11_empty_token_info())
        rv = ccall(
            fl.C_GetTokenInfo,
            AwsIO.CK_RV,
            (AwsIO.CK_SLOT_ID, Ptr{AwsIO.CK_TOKEN_INFO}),
            slots[i],
            info_ref,
        )
        @test rv == AwsIO.CKR_OK
        info = info_ref[]
        if token_info === nothing
            if (info.flags & AwsIO.CKF_TOKEN_INITIALIZED) == 0
                found_slot = slots[i]
                matches += 1
            end
        else
            if info.serialNumber == token_info.serialNumber && info.label == token_info.label
                found_slot = slots[i]
                matches += 1
            end
        end
    end

    @test matches == 1
    return found_slot
end

function pkcs11_find_free_slot(tester::Pkcs11Tester)
    return pkcs11_find_slot(tester, nothing)
end

function pkcs11_softhsm_create_slot(
        tester::Pkcs11Tester,
        token_name::AbstractString,
        so_pin::AbstractString,
        user_pin::AbstractString,
    )
    @test tester.lib !== nothing
    fl = unsafe_load(AwsIO.pkcs11_lib_get_function_list(tester.lib::AwsIO.Pkcs11Lib))

    label_buf = Memory{UInt8}(undef, 32)
    fill!(label_buf, UInt8(' '))
    name_bytes = Vector{UInt8}(codeunits(token_name))
    copyto!(label_buf, 1, name_bytes, 1, min(length(name_bytes), 32))

    slot_id = pkcs11_find_free_slot(tester)

    so_bytes = Vector{UInt8}(codeunits(so_pin))
    user_bytes = Vector{UInt8}(codeunits(user_pin))

    GC.@preserve label_buf so_bytes user_bytes begin
        rv = ccall(
            fl.C_InitToken,
            AwsIO.CK_RV,
            (AwsIO.CK_SLOT_ID, Ptr{UInt8}, AwsIO.CK_ULONG, Ptr{UInt8}),
            slot_id,
            pointer(so_bytes),
            AwsIO.CK_ULONG(length(so_bytes)),
            pointer(label_buf),
        )
        @test rv == AwsIO.CKR_OK

        session_ref = Ref{AwsIO.CK_SESSION_HANDLE}(0)
        rv = ccall(
            fl.C_OpenSession,
            AwsIO.CK_RV,
            (AwsIO.CK_SLOT_ID, AwsIO.CK_FLAGS, Ptr{Cvoid}, Ptr{Cvoid}, Ref{AwsIO.CK_SESSION_HANDLE}),
            slot_id,
            AwsIO.CKF_SERIAL_SESSION | AwsIO.CKF_RW_SESSION,
            C_NULL,
            C_NULL,
            session_ref,
        )
        @test rv == AwsIO.CKR_OK
        session = session_ref[]

        rv = ccall(
            fl.C_Login,
            AwsIO.CK_RV,
            (AwsIO.CK_SESSION_HANDLE, AwsIO.CK_ULONG, Ptr{UInt8}, AwsIO.CK_ULONG),
            session,
            AwsIO.CKU_SO,
            pointer(so_bytes),
            AwsIO.CK_ULONG(length(so_bytes)),
        )
        @test rv == AwsIO.CKR_OK

        rv = ccall(
            fl.C_InitPIN,
            AwsIO.CK_RV,
            (AwsIO.CK_SESSION_HANDLE, Ptr{UInt8}, AwsIO.CK_ULONG),
            session,
            pointer(user_bytes),
            AwsIO.CK_ULONG(length(user_bytes)),
        )
        @test rv == AwsIO.CKR_OK
    end

    info_ref = Ref(pkcs11_empty_token_info())
    rv = ccall(
        fl.C_GetTokenInfo,
        AwsIO.CK_RV,
        (AwsIO.CK_SLOT_ID, Ptr{AwsIO.CK_TOKEN_INFO}),
        slot_id,
        info_ref,
    )
    @test rv == AwsIO.CKR_OK

    @test pkcs11_reload_hsm!(tester) isa AwsIO.Pkcs11Lib
    new_slot = pkcs11_find_slot(tester, info_ref[])
    return new_slot
end

function pkcs11_tester_init_with_session_login!(
        tester::Pkcs11Tester,
        token_label::AbstractString,
    )
    @test pkcs11_tester_init!(tester) isa AwsIO.Pkcs11Lib
    slot = pkcs11_softhsm_create_slot(tester, token_label, SO_PIN, USER_PIN)
    session = AwsIO.pkcs11_lib_open_session(tester.lib::AwsIO.Pkcs11Lib, UInt64(slot))
    @test session isa AwsIO.CK_SESSION_HANDLE

    login_res = AwsIO.pkcs11_lib_login_user(tester.lib::AwsIO.Pkcs11Lib, session, AwsIO.ByteCursor(USER_PIN))
    @test login_res === nothing
    return slot, session
end

function pkcs11_rsa_encrypt(
        tester::Pkcs11Tester,
        message::AwsIO.ByteCursor,
        session::AwsIO.CK_SESSION_HANDLE,
        public_key::AwsIO.CK_OBJECT_HANDLE,
    )
    fl = unsafe_load(AwsIO.pkcs11_lib_get_function_list(tester.lib::AwsIO.Pkcs11Lib))
    mechanism = AwsIO.CK_MECHANISM(AwsIO.CKM_RSA_PKCS, C_NULL, AwsIO.CK_ULONG(0))
    rv = ccall(
        fl.C_EncryptInit,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, Ref{AwsIO.CK_MECHANISM}, AwsIO.CK_OBJECT_HANDLE),
        session,
        Ref(mechanism),
        public_key,
    )
    @test rv == AwsIO.CKR_OK

    cipher_len = Ref{AwsIO.CK_ULONG}(0)
    GC.@preserve message begin
        msg_ptr = message.len > 0 ? Ptr{UInt8}(pointer(message.ptr)) : Ptr{UInt8}(C_NULL)
        rv = ccall(
            fl.C_Encrypt,
            AwsIO.CK_RV,
            (AwsIO.CK_SESSION_HANDLE, Ptr{UInt8}, AwsIO.CK_ULONG, Ptr{UInt8}, Ptr{AwsIO.CK_ULONG}),
            session,
            msg_ptr,
            AwsIO.CK_ULONG(message.len),
            C_NULL,
            cipher_len,
        )
    end
    @test rv == AwsIO.CKR_OK

    output = AwsIO.ByteBuffer(Int(cipher_len[]))
    GC.@preserve message output begin
        msg_ptr = message.len > 0 ? Ptr{UInt8}(pointer(message.ptr)) : Ptr{UInt8}(C_NULL)
        out_ptr = cipher_len[] > 0 ? Ptr{UInt8}(pointer(output.mem)) : Ptr{UInt8}(C_NULL)
        rv = ccall(
            fl.C_Encrypt,
            AwsIO.CK_RV,
            (AwsIO.CK_SESSION_HANDLE, Ptr{UInt8}, AwsIO.CK_ULONG, Ptr{UInt8}, Ptr{AwsIO.CK_ULONG}),
            session,
            msg_ptr,
            AwsIO.CK_ULONG(message.len),
            out_ptr,
            cipher_len,
        )
    end
    @test rv == AwsIO.CKR_OK
    output.len = Csize_t(cipher_len[])
    return output
end

function pkcs11_verify_signature(
        tester::Pkcs11Tester,
        message::AwsIO.ByteCursor,
        signature::AwsIO.ByteBuffer,
        session::AwsIO.CK_SESSION_HANDLE,
        public_key::AwsIO.CK_OBJECT_HANDLE,
        mechanism_type::AwsIO.CK_MECHANISM_TYPE,
    )
    fl = unsafe_load(AwsIO.pkcs11_lib_get_function_list(tester.lib::AwsIO.Pkcs11Lib))
    mechanism = AwsIO.CK_MECHANISM(mechanism_type, C_NULL, AwsIO.CK_ULONG(0))
    rv = ccall(
        fl.C_VerifyInit,
        AwsIO.CK_RV,
        (AwsIO.CK_SESSION_HANDLE, Ref{AwsIO.CK_MECHANISM}, AwsIO.CK_OBJECT_HANDLE),
        session,
        Ref(mechanism),
        public_key,
    )
    @test rv == AwsIO.CKR_OK

    GC.@preserve message signature begin
        msg_ptr = message.len > 0 ? Ptr{UInt8}(pointer(message.ptr)) : Ptr{UInt8}(C_NULL)
        sig_ptr = signature.len > 0 ? Ptr{UInt8}(pointer(signature.mem)) : Ptr{UInt8}(C_NULL)
        rv = ccall(
            fl.C_Verify,
            AwsIO.CK_RV,
            (AwsIO.CK_SESSION_HANDLE, Ptr{UInt8}, AwsIO.CK_ULONG, Ptr{UInt8}, AwsIO.CK_ULONG),
            session,
            msg_ptr,
            AwsIO.CK_ULONG(message.len),
            sig_ptr,
            AwsIO.CK_ULONG(signature.len),
        )
    end
    @test rv == AwsIO.CKR_OK
    return nothing
end

function pkcs11_create_rsa_key(
        tester::Pkcs11Tester,
        session::AwsIO.CK_SESSION_HANDLE,
        key_label::AbstractString,
        key_id::AbstractString,
        key_length::Integer,
    )
    fl = unsafe_load(AwsIO.pkcs11_lib_get_function_list(tester.lib::AwsIO.Pkcs11Lib))

    smech = AwsIO.CK_MECHANISM(AwsIO.CKM_RSA_PKCS_KEY_PAIR_GEN, C_NULL, AwsIO.CK_ULONG(0))
    trueval = Ref{AwsIO.CK_BBOOL}(AwsIO.CK_TRUE)
    falseval = Ref{AwsIO.CK_BBOOL}(AwsIO.CK_FALSE)
    modulus = Ref{AwsIO.CK_ULONG}(AwsIO.CK_ULONG(key_length))

    public_attrs = Memory{AwsIO.CK_ATTRIBUTE}(undef, 2)
    public_attrs[1] = AwsIO.CK_ATTRIBUTE(
        AwsIO.CKA_VERIFY,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{AwsIO.CK_BBOOL}, trueval)),
        AwsIO.CK_ULONG(sizeof(AwsIO.CK_BBOOL)),
    )
    public_attrs[2] = AwsIO.CK_ATTRIBUTE(
        AwsIO.CKA_MODULUS_BITS,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{AwsIO.CK_ULONG}, modulus)),
        AwsIO.CK_ULONG(sizeof(AwsIO.CK_ULONG)),
    )

    label_bytes = Vector{UInt8}(codeunits(key_label))
    id_bytes = Vector{UInt8}(codeunits(key_id))
    private_attrs = Memory{AwsIO.CK_ATTRIBUTE}(undef, 4)
    private_attrs[1] = AwsIO.CK_ATTRIBUTE(
        AwsIO.CKA_LABEL,
        Ptr{Cvoid}(pointer(label_bytes)),
        AwsIO.CK_ULONG(length(label_bytes)),
    )
    private_attrs[2] = AwsIO.CK_ATTRIBUTE(
        AwsIO.CKA_ID,
        Ptr{Cvoid}(pointer(id_bytes)),
        AwsIO.CK_ULONG(length(id_bytes)),
    )
    private_attrs[3] = AwsIO.CK_ATTRIBUTE(
        AwsIO.CKA_SIGN,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{AwsIO.CK_BBOOL}, trueval)),
        AwsIO.CK_ULONG(sizeof(AwsIO.CK_BBOOL)),
    )
    private_attrs[4] = AwsIO.CK_ATTRIBUTE(
        AwsIO.CKA_EXTRACTABLE,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{AwsIO.CK_BBOOL}, falseval)),
        AwsIO.CK_ULONG(sizeof(AwsIO.CK_BBOOL)),
    )

    priv_ref = Ref{AwsIO.CK_OBJECT_HANDLE}(AwsIO.CK_INVALID_HANDLE)
    pub_ref = Ref{AwsIO.CK_OBJECT_HANDLE}(AwsIO.CK_INVALID_HANDLE)

    GC.@preserve public_attrs private_attrs label_bytes id_bytes trueval falseval modulus begin
        rv = ccall(
            fl.C_GenerateKeyPair,
            AwsIO.CK_RV,
            (AwsIO.CK_SESSION_HANDLE, Ref{AwsIO.CK_MECHANISM}, Ptr{AwsIO.CK_ATTRIBUTE}, AwsIO.CK_ULONG,
             Ptr{AwsIO.CK_ATTRIBUTE}, AwsIO.CK_ULONG, Ref{AwsIO.CK_OBJECT_HANDLE}, Ref{AwsIO.CK_OBJECT_HANDLE}),
            session,
            Ref(smech),
            pointer(public_attrs),
            AwsIO.CK_ULONG(length(public_attrs)),
            pointer(private_attrs),
            AwsIO.CK_ULONG(length(private_attrs)),
            pub_ref,
            priv_ref,
        )
        @test rv == AwsIO.CKR_OK
    end

    return priv_ref[], pub_ref[]
end

const EC_P256_PARAMS = Memory{UInt8}([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])

function pkcs11_create_ec_key(
        tester::Pkcs11Tester,
        session::AwsIO.CK_SESSION_HANDLE,
        key_label::AbstractString,
        key_id::AbstractString,
    )
    fl = unsafe_load(AwsIO.pkcs11_lib_get_function_list(tester.lib::AwsIO.Pkcs11Lib))
    smech = AwsIO.CK_MECHANISM(AwsIO.CKM_EC_KEY_PAIR_GEN, C_NULL, AwsIO.CK_ULONG(0))

    trueval = Ref{AwsIO.CK_BBOOL}(AwsIO.CK_TRUE)
    falseval = Ref{AwsIO.CK_BBOOL}(AwsIO.CK_FALSE)

    public_attrs = Memory{AwsIO.CK_ATTRIBUTE}(undef, 2)
    public_attrs[1] = AwsIO.CK_ATTRIBUTE(
        AwsIO.CKA_EC_PARAMS,
        Ptr{Cvoid}(pointer(EC_P256_PARAMS)),
        AwsIO.CK_ULONG(length(EC_P256_PARAMS)),
    )
    public_attrs[2] = AwsIO.CK_ATTRIBUTE(
        AwsIO.CKA_VERIFY,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{AwsIO.CK_BBOOL}, trueval)),
        AwsIO.CK_ULONG(sizeof(AwsIO.CK_BBOOL)),
    )

    label_bytes = Vector{UInt8}(codeunits(key_label))
    id_bytes = Vector{UInt8}(codeunits(key_id))
    private_attrs = Memory{AwsIO.CK_ATTRIBUTE}(undef, 4)
    private_attrs[1] = AwsIO.CK_ATTRIBUTE(
        AwsIO.CKA_LABEL,
        Ptr{Cvoid}(pointer(label_bytes)),
        AwsIO.CK_ULONG(length(label_bytes)),
    )
    private_attrs[2] = AwsIO.CK_ATTRIBUTE(
        AwsIO.CKA_ID,
        Ptr{Cvoid}(pointer(id_bytes)),
        AwsIO.CK_ULONG(length(id_bytes)),
    )
    private_attrs[3] = AwsIO.CK_ATTRIBUTE(
        AwsIO.CKA_SIGN,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{AwsIO.CK_BBOOL}, trueval)),
        AwsIO.CK_ULONG(sizeof(AwsIO.CK_BBOOL)),
    )
    private_attrs[4] = AwsIO.CK_ATTRIBUTE(
        AwsIO.CKA_EXTRACTABLE,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{AwsIO.CK_BBOOL}, falseval)),
        AwsIO.CK_ULONG(sizeof(AwsIO.CK_BBOOL)),
    )

    priv_ref = Ref{AwsIO.CK_OBJECT_HANDLE}(AwsIO.CK_INVALID_HANDLE)
    pub_ref = Ref{AwsIO.CK_OBJECT_HANDLE}(AwsIO.CK_INVALID_HANDLE)

    GC.@preserve public_attrs private_attrs label_bytes id_bytes trueval falseval EC_P256_PARAMS begin
        rv = ccall(
            fl.C_GenerateKeyPair,
            AwsIO.CK_RV,
            (AwsIO.CK_SESSION_HANDLE, Ref{AwsIO.CK_MECHANISM}, Ptr{AwsIO.CK_ATTRIBUTE}, AwsIO.CK_ULONG,
             Ptr{AwsIO.CK_ATTRIBUTE}, AwsIO.CK_ULONG, Ref{AwsIO.CK_OBJECT_HANDLE}, Ref{AwsIO.CK_OBJECT_HANDLE}),
            session,
            Ref(smech),
            pointer(public_attrs),
            AwsIO.CK_ULONG(length(public_attrs)),
            pointer(private_attrs),
            AwsIO.CK_ULONG(length(private_attrs)),
            pub_ref,
            priv_ref,
        )
        @test rv == AwsIO.CKR_OK
    end

    return priv_ref[], pub_ref[]
end

function pkcs11_run_cmd(cmd::Cmd)
    run(cmd)
    return nothing
end

@testset "PKCS11 ASN1 bigint" begin
    function verify_bigint(input::AbstractVector{UInt8}, expected::AbstractVector{UInt8})
        buf_ref = Ref(AwsIO.ByteBuffer(length(input) + 4))
        res = AwsIO.pkcs11_asn1_enc_ubigint(buf_ref, AwsIO.ByteCursor(input))
        @test res === nothing
        buf = buf_ref[]
        @test buf.len == length(expected)
        out = Vector{UInt8}(undef, Int(buf.len))
        copyto!(out, 1, buf.mem, 1, Int(buf.len))
        @test out == expected
        AwsIO.byte_buf_clean_up(buf_ref)
    end

    verify_bigint(UInt8[0x12, 0x34, 0x56, 0x78], UInt8[0x02, 0x04, 0x12, 0x34, 0x56, 0x78])
    verify_bigint(UInt8[0x00, 0x34, 0x56, 0x78], UInt8[0x02, 0x03, 0x34, 0x56, 0x78])
    verify_bigint(UInt8[0x00, 0x00, 0x56, 0x78], UInt8[0x02, 0x02, 0x56, 0x78])
    verify_bigint(UInt8[0x00, 0x00, 0x00, 0x78], UInt8[0x02, 0x01, 0x78])
    verify_bigint(UInt8[0x00, 0x00, 0x00, 0x00], UInt8[0x02, 0x01, 0x00])
    verify_bigint(UInt8[], UInt8[0x02, 0x01, 0x00])
    verify_bigint(UInt8[0x00, 0x84, 0x56, 0x78], UInt8[0x02, 0x04, 0x00, 0x84, 0x56, 0x78])
    verify_bigint(UInt8[0x82, 0x34, 0x56, 0x78], UInt8[0x02, 0x05, 0x00, 0x82, 0x34, 0x56, 0x78])
end

@testset "PKCS11 (SoftHSM)" begin
    if !pkcs11_env_ready()
        @info "Skipping PKCS11 tests (set TEST_PKCS11_LIB/TEST_PKCS11_TOKEN_DIR and install softhsm2-util)"
        return
    end

    @testset "pkcs11 lib sanity check" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa AwsIO.Pkcs11Lib
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 lib behavior default" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            pkcs11_tester_init_without_load!(tester)
            opts = AwsIO.Pkcs11LibOptions(;
                filename = tester.lib_path,
                initialize_finalize_behavior = AwsIO.Pkcs11LibBehavior.DEFAULT_BEHAVIOR,
            )
            lib1 = AwsIO.pkcs11_lib_new(opts)
            @test lib1 isa AwsIO.Pkcs11Lib
            lib2 = AwsIO.pkcs11_lib_new(opts)
            @test lib2 isa AwsIO.Pkcs11Lib
            AwsIO.pkcs11_lib_release(lib1::AwsIO.Pkcs11Lib)
            info = Ref(AwsIO.CK_INFO(AwsIO.CK_VERSION(0, 0), ntuple(_ -> UInt8(0x20), 32), 0,
                ntuple(_ -> UInt8(0x20), 32), AwsIO.CK_VERSION(0, 0)))
            fl = unsafe_load(AwsIO.pkcs11_lib_get_function_list(lib2::AwsIO.Pkcs11Lib))
            rv = ccall(fl.C_GetInfo, AwsIO.CK_RV, (Ref{AwsIO.CK_INFO},), info)
            @test rv == AwsIO.CKR_OK
            AwsIO.pkcs11_lib_release(lib2::AwsIO.Pkcs11Lib)
            lib3 = AwsIO.pkcs11_lib_new(opts)
            @test lib3 isa AwsIO.Pkcs11Lib
            AwsIO.pkcs11_lib_release(lib3::AwsIO.Pkcs11Lib)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 lib behavior omit initialize" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            pkcs11_tester_init_without_load!(tester)
            opts = AwsIO.Pkcs11LibOptions(;
                filename = tester.lib_path,
                initialize_finalize_behavior = AwsIO.Pkcs11LibBehavior.OMIT_INITIALIZE,
            )
            lib_fail = AwsIO.pkcs11_lib_new(opts)
            @test lib_fail isa AwsIO.ErrorResult
            if lib_fail isa AwsIO.ErrorResult
                @test lib_fail.code == AwsIO.ERROR_IO_PKCS11_CKR_CRYPTOKI_NOT_INITIALIZED
            end

            opts_strict = AwsIO.Pkcs11LibOptions(;
                filename = tester.lib_path,
                initialize_finalize_behavior = AwsIO.Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE,
            )
            lib1 = AwsIO.pkcs11_lib_new(opts_strict)
            @test lib1 isa AwsIO.Pkcs11Lib

            lib2 = AwsIO.pkcs11_lib_new(opts)
            @test lib2 isa AwsIO.Pkcs11Lib
            if lib2 isa AwsIO.Pkcs11Lib
                AwsIO.pkcs11_lib_release(lib2)
            end
            if lib1 isa AwsIO.Pkcs11Lib
                AwsIO.pkcs11_lib_release(lib1)
            end
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 lib behavior strict initialize/finalize" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            pkcs11_tester_init_without_load!(tester)
            opts = AwsIO.Pkcs11LibOptions(;
                filename = tester.lib_path,
                initialize_finalize_behavior = AwsIO.Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE,
            )
            lib1 = AwsIO.pkcs11_lib_new(opts)
            @test lib1 isa AwsIO.Pkcs11Lib
            lib2 = AwsIO.pkcs11_lib_new(opts)
            @test lib2 isa AwsIO.Pkcs11Lib
            AwsIO.pkcs11_lib_release(lib1::AwsIO.Pkcs11Lib)
            AwsIO.pkcs11_lib_release(lib2::AwsIO.Pkcs11Lib)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 session tests" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa AwsIO.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL, SO_PIN, USER_PIN)

            invalid = AwsIO.pkcs11_lib_open_session(tester.lib::AwsIO.Pkcs11Lib, UInt64(9999))
            @test invalid isa AwsIO.ErrorResult

            session1 = AwsIO.pkcs11_lib_open_session(tester.lib::AwsIO.Pkcs11Lib, UInt64(slot))
            @test session1 isa AwsIO.CK_SESSION_HANDLE
            session2 = AwsIO.pkcs11_lib_open_session(tester.lib::AwsIO.Pkcs11Lib, UInt64(slot))
            @test session2 isa AwsIO.CK_SESSION_HANDLE
            @test session1 != session2

            AwsIO.pkcs11_lib_close_session(tester.lib::AwsIO.Pkcs11Lib, session1)
            AwsIO.pkcs11_lib_close_session(tester.lib::AwsIO.Pkcs11Lib, session2)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 login tests" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa AwsIO.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL, SO_PIN, USER_PIN)

            bad_login = AwsIO.pkcs11_lib_login_user(
                tester.lib::AwsIO.Pkcs11Lib,
                AwsIO.CK_SESSION_HANDLE(1),
                AwsIO.ByteCursor(USER_PIN),
            )
            @test bad_login isa AwsIO.ErrorResult

            session = AwsIO.pkcs11_lib_open_session(tester.lib::AwsIO.Pkcs11Lib, UInt64(slot))
            @test session isa AwsIO.CK_SESSION_HANDLE

            invalid_pin = AwsIO.pkcs11_lib_login_user(
                tester.lib::AwsIO.Pkcs11Lib,
                session,
                AwsIO.ByteCursor("INVALID_PIN"),
            )
            @test invalid_pin isa AwsIO.ErrorResult

            @test AwsIO.pkcs11_lib_login_user(tester.lib::AwsIO.Pkcs11Lib, session, AwsIO.ByteCursor(USER_PIN)) === nothing
            @test AwsIO.pkcs11_lib_login_user(tester.lib::AwsIO.Pkcs11Lib, session, AwsIO.ByteCursor(USER_PIN)) === nothing

            session2 = AwsIO.pkcs11_lib_open_session(tester.lib::AwsIO.Pkcs11Lib, UInt64(slot))
            @test AwsIO.pkcs11_lib_login_user(tester.lib::AwsIO.Pkcs11Lib, session2, AwsIO.ByteCursor(USER_PIN)) === nothing

            AwsIO.pkcs11_lib_close_session(tester.lib::AwsIO.Pkcs11Lib, session)
            @test AwsIO.pkcs11_lib_login_user(tester.lib::AwsIO.Pkcs11Lib, session2, AwsIO.ByteCursor(USER_PIN)) === nothing
            AwsIO.pkcs11_lib_close_session(tester.lib::AwsIO.Pkcs11Lib, session2)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find private key for different rsa types" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa AwsIO.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL_RSA, SO_PIN, USER_PIN)

            session_access = AwsIO.pkcs11_lib_open_session(tester.lib::AwsIO.Pkcs11Lib, UInt64(slot))
            session_create = AwsIO.pkcs11_lib_open_session(tester.lib::AwsIO.Pkcs11Lib, UInt64(slot))
            @test AwsIO.pkcs11_lib_login_user(tester.lib::AwsIO.Pkcs11Lib, session_access, AwsIO.ByteCursor(USER_PIN)) === nothing

            k1, _ = pkcs11_create_rsa_key(tester, session_create, "1024_Key", "1024_id", 1024)
            res1 = AwsIO.pkcs11_lib_find_private_key(
                tester.lib::AwsIO.Pkcs11Lib,
                session_access,
                AwsIO.ByteCursor("1024_Key"),
            )
            @test res1 isa Tuple
            if res1 isa Tuple
                @test res1[1] == k1
                @test res1[2] == AwsIO.CKK_RSA
            end

            k2, _ = pkcs11_create_rsa_key(tester, session_create, "2048_Key", "2048_id", 2048)
            res2 = AwsIO.pkcs11_lib_find_private_key(
                tester.lib::AwsIO.Pkcs11Lib,
                session_access,
                AwsIO.ByteCursor("2048_Key"),
            )
            @test res2 isa Tuple
            if res2 isa Tuple
                @test res2[1] == k2
                @test res2[2] == AwsIO.CKK_RSA
            end

            k3, _ = pkcs11_create_rsa_key(tester, session_create, "4096_Key", "4096_id", 4096)
            res3 = AwsIO.pkcs11_lib_find_private_key(
                tester.lib::AwsIO.Pkcs11Lib,
                session_access,
                AwsIO.ByteCursor("4096_Key"),
            )
            @test res3 isa Tuple
            if res3 isa Tuple
                @test res3[1] == k3
                @test res3[2] == AwsIO.CKK_RSA
            end
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find private key for ec" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa AwsIO.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL, SO_PIN, USER_PIN)

            session_access = AwsIO.pkcs11_lib_open_session(tester.lib::AwsIO.Pkcs11Lib, UInt64(slot))
            session_create = AwsIO.pkcs11_lib_open_session(tester.lib::AwsIO.Pkcs11Lib, UInt64(slot))
            @test AwsIO.pkcs11_lib_login_user(tester.lib::AwsIO.Pkcs11Lib, session_access, AwsIO.ByteCursor(USER_PIN)) === nothing

            k1, _ = pkcs11_create_ec_key(tester, session_create, "EC_256_Key", "EC_256_id")
            res = AwsIO.pkcs11_lib_find_private_key(
                tester.lib::AwsIO.Pkcs11Lib,
                session_access,
                AwsIO.ByteCursor("EC_256_Key"),
            )
            @test res isa Tuple
            if res isa Tuple
                @test res[1] == k1
                @test res[2] == AwsIO.CKK_EC
            end
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find multiple private key" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa AwsIO.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL, SO_PIN, USER_PIN)

            session_access = AwsIO.pkcs11_lib_open_session(tester.lib::AwsIO.Pkcs11Lib, UInt64(slot))
            session_create1 = AwsIO.pkcs11_lib_open_session(tester.lib::AwsIO.Pkcs11Lib, UInt64(slot))
            session_create2 = AwsIO.pkcs11_lib_open_session(tester.lib::AwsIO.Pkcs11Lib, UInt64(slot))
            @test AwsIO.pkcs11_lib_login_user(tester.lib::AwsIO.Pkcs11Lib, session_access, AwsIO.ByteCursor(USER_PIN)) === nothing

            k1, _ = pkcs11_create_rsa_key(tester, session_create1, "RSA_KEY", "BEEFCAFE", 1024)
            k2, _ = pkcs11_create_rsa_key(tester, session_create2, "DES_KEY_2", "BEEFCAFEDEAD", 1024)

            res = AwsIO.pkcs11_lib_find_private_key(tester.lib::AwsIO.Pkcs11Lib, session_access, nothing)
            @test res isa AwsIO.ErrorResult

            res1 = AwsIO.pkcs11_lib_find_private_key(
                tester.lib::AwsIO.Pkcs11Lib,
                session_access,
                AwsIO.ByteCursor("RSA_KEY"),
            )
            @test res1 isa Tuple
            if res1 isa Tuple
                @test res1[1] == k1
                @test res1[2] == AwsIO.CKK_RSA
            end

            res2 = AwsIO.pkcs11_lib_find_private_key(
                tester.lib::AwsIO.Pkcs11Lib,
                session_access,
                AwsIO.ByteCursor("DES_KEY_2"),
            )
            @test res2 isa Tuple
            if res2 isa Tuple
                @test res2[1] == k2
                @test res2[2] == AwsIO.CKK_RSA
            end

            AwsIO.pkcs11_lib_close_session(tester.lib::AwsIO.Pkcs11Lib, session_access)
            AwsIO.pkcs11_lib_close_session(tester.lib::AwsIO.Pkcs11Lib, session_create1)
            AwsIO.pkcs11_lib_close_session(tester.lib::AwsIO.Pkcs11Lib, session_create2)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find private key" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa AwsIO.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL, SO_PIN, USER_PIN)

            session_access = AwsIO.pkcs11_lib_open_session(tester.lib::AwsIO.Pkcs11Lib, UInt64(slot))
            session_create = AwsIO.pkcs11_lib_open_session(tester.lib::AwsIO.Pkcs11Lib, UInt64(slot))
            @test AwsIO.pkcs11_lib_login_user(tester.lib::AwsIO.Pkcs11Lib, session_access, AwsIO.ByteCursor(USER_PIN)) === nothing

            k1, _ = pkcs11_create_rsa_key(tester, session_create, "RSA_KEY", "BEEFCAFE", 1024)
            res1 = AwsIO.pkcs11_lib_find_private_key(
                tester.lib::AwsIO.Pkcs11Lib,
                session_access,
                AwsIO.ByteCursor("RSA_KEY"),
            )
            @test res1 isa Tuple
            if res1 isa Tuple
                @test res1[1] == k1
                @test res1[2] == AwsIO.CKK_RSA
            end

            res_none = AwsIO.pkcs11_lib_find_private_key(
                tester.lib::AwsIO.Pkcs11Lib,
                session_access,
                AwsIO.ByteCursor("NON_EXISTENT"),
            )
            @test res_none isa AwsIO.ErrorResult
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find slot" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa AwsIO.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, "label!@#", SO_PIN, USER_PIN)

            found = AwsIO.pkcs11_lib_find_slot_with_token(tester.lib::AwsIO.Pkcs11Lib, nothing, nothing)
            @test found isa UInt64

            match_slot = UInt64(slot)
            found_slot = AwsIO.pkcs11_lib_find_slot_with_token(tester.lib::AwsIO.Pkcs11Lib, match_slot, nothing)
            @test found_slot == match_slot

            label = AwsIO.ByteCursor("label!@#")
            found_label = AwsIO.pkcs11_lib_find_slot_with_token(tester.lib::AwsIO.Pkcs11Lib, nothing, label)
            @test found_label == match_slot
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find slot many tokens" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa AwsIO.Pkcs11Lib
            slot1 = pkcs11_softhsm_create_slot(tester, "token_one", SO_PIN, USER_PIN)
            slot2 = pkcs11_softhsm_create_slot(tester, "token_two", SO_PIN, USER_PIN)

            found1 = AwsIO.pkcs11_lib_find_slot_with_token(tester.lib::AwsIO.Pkcs11Lib, UInt64(slot1), nothing)
            @test found1 == UInt64(slot1)
            found2 = AwsIO.pkcs11_lib_find_slot_with_token(tester.lib::AwsIO.Pkcs11Lib, UInt64(slot2), nothing)
            @test found2 == UInt64(slot2)

            label1 = AwsIO.ByteCursor("token_one")
            found_label1 = AwsIO.pkcs11_lib_find_slot_with_token(tester.lib::AwsIO.Pkcs11Lib, nothing, label1)
            @test found_label1 == UInt64(slot1)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 rsa decrypt" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            slot, session = pkcs11_tester_init_with_session_login!(tester, TOKEN_LABEL_RSA)
            priv, pub = pkcs11_create_rsa_key(tester, session, DEFAULT_KEY_LABEL, DEFAULT_KEY_ID, 2048)

            input_cursor = AwsIO.ByteCursor("ABCDEFGHIJKL")
            cipher_buf = pkcs11_rsa_encrypt(tester, input_cursor, session, pub)
            cipher_cur = AwsIO.byte_cursor_from_buf(cipher_buf)

            decrypted = AwsIO.pkcs11_lib_decrypt(
                tester.lib::AwsIO.Pkcs11Lib,
                session,
                priv,
                AwsIO.CKK_RSA,
                cipher_cur,
            )
            @test decrypted isa AwsIO.ByteBuffer
            if decrypted isa AwsIO.ByteBuffer
                out = Vector{UInt8}(undef, Int(decrypted.len))
                copyto!(out, 1, decrypted.mem, 1, Int(decrypted.len))
                @test out == Vector{UInt8}(codeunits("ABCDEFGHIJKL"))
            end

            unsupported = AwsIO.pkcs11_lib_decrypt(
                tester.lib::AwsIO.Pkcs11Lib,
                session,
                priv,
                AwsIO.CKK_GENERIC_SECRET,
                cipher_cur,
            )
            @test unsupported isa AwsIO.ErrorResult

            bad_session = AwsIO.pkcs11_lib_decrypt(
                tester.lib::AwsIO.Pkcs11Lib,
                AwsIO.CK_SESSION_HANDLE(0),
                priv,
                AwsIO.CKK_RSA,
                cipher_cur,
            )
            @test bad_session isa AwsIO.ErrorResult

            bad_key = AwsIO.pkcs11_lib_decrypt(
                tester.lib::AwsIO.Pkcs11Lib,
                session,
                AwsIO.CK_INVALID_HANDLE,
                AwsIO.CKK_RSA,
                cipher_cur,
            )
            @test bad_key isa AwsIO.ErrorResult

            empty = AwsIO.pkcs11_lib_decrypt(
                tester.lib::AwsIO.Pkcs11Lib,
                session,
                priv,
                AwsIO.CKK_RSA,
                AwsIO.ByteCursor(""),
            )
            @test empty isa AwsIO.ErrorResult
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 sign rsa" begin
        function sign_rsa(digest_alg)
            tester = Pkcs11Tester("", "", nothing)
            try
                slot, session = pkcs11_tester_init_with_session_login!(tester, TOKEN_LABEL_RSA)
                priv, pub = pkcs11_create_rsa_key(tester, session, DEFAULT_KEY_LABEL, DEFAULT_KEY_ID, 2048)

                message = AwsIO.ByteCursor("ABCDEFGHIJKL")
                signature = AwsIO.pkcs11_lib_sign(
                    tester.lib::AwsIO.Pkcs11Lib,
                    session,
                    priv,
                    AwsIO.CKK_RSA,
                    message,
                    digest_alg,
                    AwsIO.TlsSignatureAlgorithm.RSA,
                )
                @test signature isa AwsIO.ByteBuffer
                if signature isa AwsIO.ByteBuffer
                    prefix = AwsIO.get_prefix_to_rsa_sig(digest_alg)
                    @test prefix isa AwsIO.ByteCursor
                    if prefix isa AwsIO.ByteCursor
                        prefixed = AwsIO.ByteBuffer(Int(prefix.len + message.len))
                        pref_ref = Ref(prefixed)
                        @test AwsIO.byte_buf_write_from_whole_cursor(pref_ref, prefix)
                        @test AwsIO.byte_buf_write_from_whole_cursor(pref_ref, message)
                        prefixed = pref_ref[]
                        pkcs11_verify_signature(
                            tester,
                            AwsIO.byte_cursor_from_buf(prefixed),
                            signature,
                            session,
                            pub,
                            AwsIO.CKM_RSA_PKCS,
                        )
                    end
                end

                unsupported = AwsIO.pkcs11_lib_sign(
                    tester.lib::AwsIO.Pkcs11Lib,
                    session,
                    priv,
                    AwsIO.CKK_GENERIC_SECRET,
                    message,
                    digest_alg,
                    AwsIO.TlsSignatureAlgorithm.RSA,
                )
                @test unsupported isa AwsIO.ErrorResult
            finally
                pkcs11_tester_cleanup!(tester)
            end
        end
        sign_rsa(AwsIO.TlsHashAlgorithm.SHA1)
        sign_rsa(AwsIO.TlsHashAlgorithm.SHA512)
        sign_rsa(AwsIO.TlsHashAlgorithm.SHA384)
        sign_rsa(AwsIO.TlsHashAlgorithm.SHA256)
        sign_rsa(AwsIO.TlsHashAlgorithm.SHA224)
    end

    @testset "pkcs11 sign ec 256" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            slot, session = pkcs11_tester_init_with_session_login!(tester, TOKEN_LABEL_EC)
            priv, pub = pkcs11_create_ec_key(tester, session, DEFAULT_KEY_LABEL, DEFAULT_KEY_ID)

            message = AwsIO.ByteCursor("ABCDEFGHIJKL")
            signature = AwsIO.pkcs11_lib_sign(
                tester.lib::AwsIO.Pkcs11Lib,
                session,
                priv,
                AwsIO.CKK_EC,
                message,
                AwsIO.TlsHashAlgorithm.UNKNOWN,
                AwsIO.TlsSignatureAlgorithm.ECDSA,
            )
            @test signature isa AwsIO.ByteBuffer

            unsupported = AwsIO.pkcs11_lib_sign(
                tester.lib::AwsIO.Pkcs11Lib,
                session,
                priv,
                AwsIO.CKK_GENERIC_SECRET,
                message,
                AwsIO.TlsHashAlgorithm.UNKNOWN,
                AwsIO.TlsSignatureAlgorithm.ECDSA,
            )
            @test unsupported isa AwsIO.ErrorResult
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 tls negotiation succeeds (rsa)" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa AwsIO.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL_RSA, SO_PIN, USER_PIN)
            AwsIO.pkcs11_lib_release(tester.lib::AwsIO.Pkcs11Lib)
            tester.lib = nothing

            root = normpath(joinpath(@__DIR__, ".."))
            rsa_p8 = joinpath(root, "aws-c-io", "tests", "resources", "unittests.p8")
            cert_path = joinpath(root, "aws-c-io", "tests", "resources", "unittests.crt")
            key_path = joinpath(root, "aws-c-io", "tests", "resources", "unittests.key")
            @test isfile(rsa_p8)
            @test isfile(cert_path)
            @test isfile(key_path)

            cmd = `softhsm2-util --import $(rsa_p8) --module $(tester.lib_path) --slot $(slot) --label $(DEFAULT_KEY_LABEL) --id $(DEFAULT_KEY_ID) --pin $(USER_PIN)`
            pkcs11_run_cmd(cmd)

            @test pkcs11_reload_hsm!(tester) isa AwsIO.Pkcs11Lib

            elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
            resolver = AwsIO.DefaultHostResolver(elg)

            server_tls_opts = AwsIO.tls_ctx_options_init_default_server_from_path(cert_path, key_path)
            @test server_tls_opts isa AwsIO.TlsContextOptions
            if server_tls_opts isa AwsIO.TlsContextOptions
                _ = AwsIO.tls_ctx_options_override_default_trust_store_from_path(
                    server_tls_opts;
                    ca_file = cert_path,
                )
                AwsIO.tls_ctx_options_set_verify_peer(server_tls_opts, true)
            end
            server_ctx = AwsIO.tls_context_new(server_tls_opts)
            @test server_ctx isa AwsIO.TlsContext

            server_ready = Ref(false)
            server_shutdown = Ref(false)

            server_bootstrap = AwsIO.ServerBootstrap(AwsIO.ServerBootstrapOptions(
                event_loop_group = elg,
                host = "127.0.0.1",
                port = 0,
                tls_connection_options = AwsIO.TlsConnectionOptions(server_ctx),
                on_incoming_channel_setup = (bs, err, channel, ud) -> begin
                    server_ready[] = err == AwsIO.AWS_OP_SUCCESS
                    return nothing
                end,
                on_incoming_channel_shutdown = (bs, err, channel, ud) -> begin
                    server_shutdown[] = true
                    return nothing
                end,
            ))
            listener = server_bootstrap.listener_socket
            @test listener !== nothing
            bound = AwsIO.socket_get_bound_address(listener)
            port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
            @test port != 0

            client_opts = AwsIO.TlsCtxPkcs11Options(
                pkcs11_lib = tester.lib,
                token_label = TOKEN_LABEL_RSA,
                user_pin = USER_PIN,
                private_key_object_label = DEFAULT_KEY_LABEL,
                cert_file_path = cert_path,
            )
            client_tls_opts = AwsIO.tls_ctx_options_init_client_mtls_with_pkcs11(client_opts)
            @test client_tls_opts isa AwsIO.TlsContextOptions
            client_ctx = AwsIO.tls_context_new(client_tls_opts)
            @test client_ctx isa AwsIO.TlsContext

            client_ready = Ref(false)
            client_shutdown = Ref(false)
            client_bootstrap = AwsIO.ClientBootstrap(AwsIO.ClientBootstrapOptions(
                event_loop_group = elg,
                host_resolver = resolver,
            ))
            @test AwsIO.client_bootstrap_connect!(
                client_bootstrap,
                "127.0.0.1",
                port;
                tls_connection_options = AwsIO.TlsConnectionOptions(client_ctx; server_name = "localhost"),
                on_setup = (bs, err, channel, ud) -> begin
                    client_ready[] = err == AwsIO.AWS_OP_SUCCESS
                    if err == AwsIO.AWS_OP_SUCCESS
                        AwsIO.channel_shutdown!(channel, AwsIO.AWS_OP_SUCCESS)
                    end
                    return nothing
                end,
                on_shutdown = (bs, err, channel, ud) -> begin
                    client_shutdown[] = true
                    return nothing
                end,
            ) === nothing

            wait_start = time()
            while !(client_ready[] && server_ready[] && client_shutdown[] && server_shutdown[])
                if (time() - wait_start) > TIMEOUT_SEC
                    break
                end
                sleep(0.05)
            end
            @test client_ready[]
            @test server_ready[]
            @test client_shutdown[]
            @test server_shutdown[]

            AwsIO.server_bootstrap_shutdown!(server_bootstrap)
            AwsIO.host_resolver_shutdown!(resolver)
            AwsIO.event_loop_group_destroy!(elg)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 tls negotiation succeeds (ec)" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa AwsIO.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL_EC, SO_PIN, USER_PIN)
            AwsIO.pkcs11_lib_release(tester.lib::AwsIO.Pkcs11Lib)
            tester.lib = nothing

            root = normpath(joinpath(@__DIR__, ".."))
            ec_p8 = joinpath(root, "aws-c-io", "tests", "resources", "ec_unittests.p8")
            cert_path = joinpath(root, "aws-c-io", "tests", "resources", "ec_unittests.crt")
            key_path = joinpath(root, "aws-c-io", "tests", "resources", "ec_unittests.key")
            @test isfile(ec_p8)
            @test isfile(cert_path)
            @test isfile(key_path)

            cmd = `softhsm2-util --import $(ec_p8) --module $(tester.lib_path) --slot $(slot) --label $(DEFAULT_KEY_LABEL) --id $(DEFAULT_KEY_ID) --pin $(USER_PIN)`
            pkcs11_run_cmd(cmd)

            @test pkcs11_reload_hsm!(tester) isa AwsIO.Pkcs11Lib

            elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
            resolver = AwsIO.DefaultHostResolver(elg)

            server_tls_opts = AwsIO.tls_ctx_options_init_default_server_from_path(cert_path, key_path)
            @test server_tls_opts isa AwsIO.TlsContextOptions
            if server_tls_opts isa AwsIO.TlsContextOptions
                _ = AwsIO.tls_ctx_options_override_default_trust_store_from_path(
                    server_tls_opts;
                    ca_file = cert_path,
                )
                AwsIO.tls_ctx_options_set_verify_peer(server_tls_opts, true)
            end
            server_ctx = AwsIO.tls_context_new(server_tls_opts)
            @test server_ctx isa AwsIO.TlsContext

            server_ready = Ref(false)
            server_shutdown = Ref(false)

            server_bootstrap = AwsIO.ServerBootstrap(AwsIO.ServerBootstrapOptions(
                event_loop_group = elg,
                host = "127.0.0.1",
                port = 0,
                tls_connection_options = AwsIO.TlsConnectionOptions(server_ctx),
                on_incoming_channel_setup = (bs, err, channel, ud) -> begin
                    server_ready[] = err == AwsIO.AWS_OP_SUCCESS
                    return nothing
                end,
                on_incoming_channel_shutdown = (bs, err, channel, ud) -> begin
                    server_shutdown[] = true
                    return nothing
                end,
            ))
            listener = server_bootstrap.listener_socket
            @test listener !== nothing
            bound = AwsIO.socket_get_bound_address(listener)
            port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
            @test port != 0

            client_opts = AwsIO.TlsCtxPkcs11Options(
                pkcs11_lib = tester.lib,
                token_label = TOKEN_LABEL_EC,
                user_pin = USER_PIN,
                private_key_object_label = DEFAULT_KEY_LABEL,
                cert_file_path = cert_path,
            )
            client_tls_opts = AwsIO.tls_ctx_options_init_client_mtls_with_pkcs11(client_opts)
            @test client_tls_opts isa AwsIO.TlsContextOptions
            client_ctx = AwsIO.tls_context_new(client_tls_opts)
            @test client_ctx isa AwsIO.TlsContext

            client_ready = Ref(false)
            client_shutdown = Ref(false)
            client_bootstrap = AwsIO.ClientBootstrap(AwsIO.ClientBootstrapOptions(
                event_loop_group = elg,
                host_resolver = resolver,
            ))
            @test AwsIO.client_bootstrap_connect!(
                client_bootstrap,
                "127.0.0.1",
                port;
                tls_connection_options = AwsIO.TlsConnectionOptions(client_ctx; server_name = "localhost"),
                on_setup = (bs, err, channel, ud) -> begin
                    client_ready[] = err == AwsIO.AWS_OP_SUCCESS
                    if err == AwsIO.AWS_OP_SUCCESS
                        AwsIO.channel_shutdown!(channel, AwsIO.AWS_OP_SUCCESS)
                    end
                    return nothing
                end,
                on_shutdown = (bs, err, channel, ud) -> begin
                    client_shutdown[] = true
                    return nothing
                end,
            ) === nothing

            wait_start = time()
            while !(client_ready[] && server_ready[] && client_shutdown[] && server_shutdown[])
                if (time() - wait_start) > TIMEOUT_SEC
                    break
                end
                sleep(0.05)
            end
            @test client_ready[]
            @test server_ready[]
            @test client_shutdown[]
            @test server_shutdown[]

            AwsIO.server_bootstrap_shutdown!(server_bootstrap)
            AwsIO.host_resolver_shutdown!(resolver)
            AwsIO.event_loop_group_destroy!(elg)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end
end
