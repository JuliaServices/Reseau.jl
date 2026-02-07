using Test
using Reseau
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
    @test Reseau.pkcs11_error_from_ckr(Reseau.CKR_FUNCTION_NOT_SUPPORTED) ==
        Reseau.ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED
    @test Reseau.pkcs11_error_from_ckr(0xdeadbeef) ==
        Reseau.ERROR_IO_PKCS11_UNKNOWN_CRYPTOKI_RETURN_VALUE
    @test Reseau.pkcs11_ckr_str(Reseau.CKR_FUNCTION_NOT_SUPPORTED) == "CKR_FUNCTION_NOT_SUPPORTED"
    @test Reseau.pkcs11_ckr_str(0xdeadbeef) == "CKR_UNKNOWN"
end

mutable struct Pkcs11Tester
    lib_path::String
    token_dir::String
    lib::Union{Reseau.Pkcs11Lib, Nothing}
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
    Reseau.io_library_init()
    tester.lib_path = get(ENV, PKCS11_ENV_LIB, "")
    tester.token_dir = get(ENV, PKCS11_ENV_TOKEN_DIR, "")
    pkcs11_clear_softhsm!(tester)
    tester.lib = nothing
    return nothing
end

function pkcs11_tester_init!(
        tester::Pkcs11Tester;
        behavior::Reseau.Pkcs11LibBehavior.T = Reseau.Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE,
    )
    pkcs11_tester_init_without_load!(tester)
    opts = Reseau.Pkcs11LibOptions(;
        filename = tester.lib_path,
        initialize_finalize_behavior = behavior,
    )
    lib = Reseau.pkcs11_lib_new(opts)
    @test lib isa Reseau.Pkcs11Lib
    tester.lib = lib isa Reseau.Pkcs11Lib ? lib : nothing
    return tester.lib
end

function pkcs11_tester_cleanup!(tester::Pkcs11Tester)
    if tester.lib !== nothing
        Reseau.pkcs11_lib_release(tester.lib)
        tester.lib = nothing
    end
    pkcs11_clear_softhsm!(tester)
    Reseau.io_library_clean_up()
    tester.lib_path = ""
    tester.token_dir = ""
    return nothing
end

function pkcs11_reload_hsm!(tester::Pkcs11Tester)
    if tester.lib !== nothing
        Reseau.pkcs11_lib_release(tester.lib)
        tester.lib = nothing
    end
    opts = Reseau.Pkcs11LibOptions(;
        filename = tester.lib_path,
        initialize_finalize_behavior = Reseau.Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE,
    )
    lib = Reseau.pkcs11_lib_new(opts)
    @test lib isa Reseau.Pkcs11Lib
    tester.lib = lib isa Reseau.Pkcs11Lib ? lib : nothing
    return tester.lib
end

function pkcs11_empty_token_info()
    return Reseau.CK_TOKEN_INFO(
        ntuple(_ -> UInt8(0x20), 32),
        ntuple(_ -> UInt8(0x20), 32),
        ntuple(_ -> UInt8(0x20), 16),
        ntuple(_ -> UInt8(0x20), 16),
        Reseau.CK_FLAGS(0),
        Reseau.CK_ULONG(0),
        Reseau.CK_ULONG(0),
        Reseau.CK_ULONG(0),
        Reseau.CK_ULONG(0),
        Reseau.CK_ULONG(0),
        Reseau.CK_ULONG(0),
        Reseau.CK_ULONG(0),
        Reseau.CK_ULONG(0),
        Reseau.CK_ULONG(0),
        Reseau.CK_ULONG(0),
        Reseau.CK_VERSION(0, 0),
        Reseau.CK_VERSION(0, 0),
        ntuple(_ -> UInt8(0x20), 16),
    )
end

function pkcs11_find_slot(tester::Pkcs11Tester, token_info::Union{Reseau.CK_TOKEN_INFO, Nothing})
    @test tester.lib !== nothing
    fl_ptr = Reseau.pkcs11_lib_get_function_list(tester.lib::Reseau.Pkcs11Lib)
    @test fl_ptr != C_NULL
    fl = unsafe_load(fl_ptr)

    slot_count = Ref{Reseau.CK_ULONG}(0)
    rv = ccall(
        fl.C_GetSlotList,
        Reseau.CK_RV,
        (Reseau.CK_BBOOL, Ptr{Reseau.CK_SLOT_ID}, Ptr{Reseau.CK_ULONG}),
        Reseau.CK_TRUE,
        C_NULL,
        slot_count,
    )
    @test rv == Reseau.CKR_OK

    count = Int(slot_count[])
    slots = Memory{Reseau.CK_SLOT_ID}(undef, count)
    rv = GC.@preserve slots begin
        ccall(
            fl.C_GetSlotList,
            Reseau.CK_RV,
            (Reseau.CK_BBOOL, Ptr{Reseau.CK_SLOT_ID}, Ptr{Reseau.CK_ULONG}),
            Reseau.CK_FALSE,
            pointer(slots),
            slot_count,
        )
    end
    @test rv == Reseau.CKR_OK

    found_slot = Reseau.CK_SLOT_ID(0)
    matches = 0
    for i in 1:count
        info_ref = Ref(pkcs11_empty_token_info())
        rv = ccall(
            fl.C_GetTokenInfo,
            Reseau.CK_RV,
            (Reseau.CK_SLOT_ID, Ptr{Reseau.CK_TOKEN_INFO}),
            slots[i],
            info_ref,
        )
        @test rv == Reseau.CKR_OK
        info = info_ref[]
        if token_info === nothing
            if (info.flags & Reseau.CKF_TOKEN_INITIALIZED) == 0
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
    fl = unsafe_load(Reseau.pkcs11_lib_get_function_list(tester.lib::Reseau.Pkcs11Lib))

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
            Reseau.CK_RV,
            (Reseau.CK_SLOT_ID, Ptr{UInt8}, Reseau.CK_ULONG, Ptr{UInt8}),
            slot_id,
            pointer(so_bytes),
            Reseau.CK_ULONG(length(so_bytes)),
            pointer(label_buf),
        )
        @test rv == Reseau.CKR_OK

        session_ref = Ref{Reseau.CK_SESSION_HANDLE}(0)
        rv = ccall(
            fl.C_OpenSession,
            Reseau.CK_RV,
            (Reseau.CK_SLOT_ID, Reseau.CK_FLAGS, Ptr{Cvoid}, Ptr{Cvoid}, Ref{Reseau.CK_SESSION_HANDLE}),
            slot_id,
            Reseau.CKF_SERIAL_SESSION | Reseau.CKF_RW_SESSION,
            C_NULL,
            C_NULL,
            session_ref,
        )
        @test rv == Reseau.CKR_OK
        session = session_ref[]

        rv = ccall(
            fl.C_Login,
            Reseau.CK_RV,
            (Reseau.CK_SESSION_HANDLE, Reseau.CK_ULONG, Ptr{UInt8}, Reseau.CK_ULONG),
            session,
            Reseau.CKU_SO,
            pointer(so_bytes),
            Reseau.CK_ULONG(length(so_bytes)),
        )
        @test rv == Reseau.CKR_OK

        rv = ccall(
            fl.C_InitPIN,
            Reseau.CK_RV,
            (Reseau.CK_SESSION_HANDLE, Ptr{UInt8}, Reseau.CK_ULONG),
            session,
            pointer(user_bytes),
            Reseau.CK_ULONG(length(user_bytes)),
        )
        @test rv == Reseau.CKR_OK
    end

    info_ref = Ref(pkcs11_empty_token_info())
    rv = ccall(
        fl.C_GetTokenInfo,
        Reseau.CK_RV,
        (Reseau.CK_SLOT_ID, Ptr{Reseau.CK_TOKEN_INFO}),
        slot_id,
        info_ref,
    )
    @test rv == Reseau.CKR_OK

    @test pkcs11_reload_hsm!(tester) isa Reseau.Pkcs11Lib
    new_slot = pkcs11_find_slot(tester, info_ref[])
    return new_slot
end

function pkcs11_tester_init_with_session_login!(
        tester::Pkcs11Tester,
        token_label::AbstractString,
    )
    @test pkcs11_tester_init!(tester) isa Reseau.Pkcs11Lib
    slot = pkcs11_softhsm_create_slot(tester, token_label, SO_PIN, USER_PIN)
    session = Reseau.pkcs11_lib_open_session(tester.lib::Reseau.Pkcs11Lib, UInt64(slot))
    @test session isa Reseau.CK_SESSION_HANDLE

    login_res = Reseau.pkcs11_lib_login_user(tester.lib::Reseau.Pkcs11Lib, session, Reseau.ByteCursor(USER_PIN))
    @test login_res === nothing
    return slot, session
end

function pkcs11_rsa_encrypt(
        tester::Pkcs11Tester,
        message::Reseau.ByteCursor,
        session::Reseau.CK_SESSION_HANDLE,
        public_key::Reseau.CK_OBJECT_HANDLE,
    )
    fl = unsafe_load(Reseau.pkcs11_lib_get_function_list(tester.lib::Reseau.Pkcs11Lib))
    mechanism = Reseau.CK_MECHANISM(Reseau.CKM_RSA_PKCS, C_NULL, Reseau.CK_ULONG(0))
    rv = ccall(
        fl.C_EncryptInit,
        Reseau.CK_RV,
        (Reseau.CK_SESSION_HANDLE, Ref{Reseau.CK_MECHANISM}, Reseau.CK_OBJECT_HANDLE),
        session,
        Ref(mechanism),
        public_key,
    )
    @test rv == Reseau.CKR_OK

    cipher_len = Ref{Reseau.CK_ULONG}(0)
    GC.@preserve message begin
        msg_ptr = message.len > 0 ? Ptr{UInt8}(pointer(message.ptr)) : Ptr{UInt8}(C_NULL)
        rv = ccall(
            fl.C_Encrypt,
            Reseau.CK_RV,
            (Reseau.CK_SESSION_HANDLE, Ptr{UInt8}, Reseau.CK_ULONG, Ptr{UInt8}, Ptr{Reseau.CK_ULONG}),
            session,
            msg_ptr,
            Reseau.CK_ULONG(message.len),
            C_NULL,
            cipher_len,
        )
    end
    @test rv == Reseau.CKR_OK

    output = Reseau.ByteBuffer(Int(cipher_len[]))
    GC.@preserve message output begin
        msg_ptr = message.len > 0 ? Ptr{UInt8}(pointer(message.ptr)) : Ptr{UInt8}(C_NULL)
        out_ptr = cipher_len[] > 0 ? Ptr{UInt8}(pointer(output.mem)) : Ptr{UInt8}(C_NULL)
        rv = ccall(
            fl.C_Encrypt,
            Reseau.CK_RV,
            (Reseau.CK_SESSION_HANDLE, Ptr{UInt8}, Reseau.CK_ULONG, Ptr{UInt8}, Ptr{Reseau.CK_ULONG}),
            session,
            msg_ptr,
            Reseau.CK_ULONG(message.len),
            out_ptr,
            cipher_len,
        )
    end
    @test rv == Reseau.CKR_OK
    output.len = Csize_t(cipher_len[])
    return output
end

function pkcs11_verify_signature(
        tester::Pkcs11Tester,
        message::Reseau.ByteCursor,
        signature::Reseau.ByteBuffer,
        session::Reseau.CK_SESSION_HANDLE,
        public_key::Reseau.CK_OBJECT_HANDLE,
        mechanism_type::Reseau.CK_MECHANISM_TYPE,
    )
    fl = unsafe_load(Reseau.pkcs11_lib_get_function_list(tester.lib::Reseau.Pkcs11Lib))
    mechanism = Reseau.CK_MECHANISM(mechanism_type, C_NULL, Reseau.CK_ULONG(0))
    rv = ccall(
        fl.C_VerifyInit,
        Reseau.CK_RV,
        (Reseau.CK_SESSION_HANDLE, Ref{Reseau.CK_MECHANISM}, Reseau.CK_OBJECT_HANDLE),
        session,
        Ref(mechanism),
        public_key,
    )
    @test rv == Reseau.CKR_OK

    GC.@preserve message signature begin
        msg_ptr = message.len > 0 ? Ptr{UInt8}(pointer(message.ptr)) : Ptr{UInt8}(C_NULL)
        sig_ptr = signature.len > 0 ? Ptr{UInt8}(pointer(signature.mem)) : Ptr{UInt8}(C_NULL)
        rv = ccall(
            fl.C_Verify,
            Reseau.CK_RV,
            (Reseau.CK_SESSION_HANDLE, Ptr{UInt8}, Reseau.CK_ULONG, Ptr{UInt8}, Reseau.CK_ULONG),
            session,
            msg_ptr,
            Reseau.CK_ULONG(message.len),
            sig_ptr,
            Reseau.CK_ULONG(signature.len),
        )
    end
    @test rv == Reseau.CKR_OK
    return nothing
end

function pkcs11_create_rsa_key(
        tester::Pkcs11Tester,
        session::Reseau.CK_SESSION_HANDLE,
        key_label::AbstractString,
        key_id::AbstractString,
        key_length::Integer,
    )
    fl = unsafe_load(Reseau.pkcs11_lib_get_function_list(tester.lib::Reseau.Pkcs11Lib))

    smech = Reseau.CK_MECHANISM(Reseau.CKM_RSA_PKCS_KEY_PAIR_GEN, C_NULL, Reseau.CK_ULONG(0))
    trueval = Ref{Reseau.CK_BBOOL}(Reseau.CK_TRUE)
    falseval = Ref{Reseau.CK_BBOOL}(Reseau.CK_FALSE)
    modulus = Ref{Reseau.CK_ULONG}(Reseau.CK_ULONG(key_length))

    public_attrs = Memory{Reseau.CK_ATTRIBUTE}(undef, 2)
    public_attrs[1] = Reseau.CK_ATTRIBUTE(
        Reseau.CKA_VERIFY,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{Reseau.CK_BBOOL}, trueval)),
        Reseau.CK_ULONG(sizeof(Reseau.CK_BBOOL)),
    )
    public_attrs[2] = Reseau.CK_ATTRIBUTE(
        Reseau.CKA_MODULUS_BITS,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{Reseau.CK_ULONG}, modulus)),
        Reseau.CK_ULONG(sizeof(Reseau.CK_ULONG)),
    )

    label_bytes = Vector{UInt8}(codeunits(key_label))
    id_bytes = Vector{UInt8}(codeunits(key_id))
    private_attrs = Memory{Reseau.CK_ATTRIBUTE}(undef, 4)
    private_attrs[1] = Reseau.CK_ATTRIBUTE(
        Reseau.CKA_LABEL,
        Ptr{Cvoid}(pointer(label_bytes)),
        Reseau.CK_ULONG(length(label_bytes)),
    )
    private_attrs[2] = Reseau.CK_ATTRIBUTE(
        Reseau.CKA_ID,
        Ptr{Cvoid}(pointer(id_bytes)),
        Reseau.CK_ULONG(length(id_bytes)),
    )
    private_attrs[3] = Reseau.CK_ATTRIBUTE(
        Reseau.CKA_SIGN,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{Reseau.CK_BBOOL}, trueval)),
        Reseau.CK_ULONG(sizeof(Reseau.CK_BBOOL)),
    )
    private_attrs[4] = Reseau.CK_ATTRIBUTE(
        Reseau.CKA_EXTRACTABLE,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{Reseau.CK_BBOOL}, falseval)),
        Reseau.CK_ULONG(sizeof(Reseau.CK_BBOOL)),
    )

    priv_ref = Ref{Reseau.CK_OBJECT_HANDLE}(Reseau.CK_INVALID_HANDLE)
    pub_ref = Ref{Reseau.CK_OBJECT_HANDLE}(Reseau.CK_INVALID_HANDLE)

    GC.@preserve public_attrs private_attrs label_bytes id_bytes trueval falseval modulus begin
        rv = ccall(
            fl.C_GenerateKeyPair,
            Reseau.CK_RV,
            (Reseau.CK_SESSION_HANDLE, Ref{Reseau.CK_MECHANISM}, Ptr{Reseau.CK_ATTRIBUTE}, Reseau.CK_ULONG,
             Ptr{Reseau.CK_ATTRIBUTE}, Reseau.CK_ULONG, Ref{Reseau.CK_OBJECT_HANDLE}, Ref{Reseau.CK_OBJECT_HANDLE}),
            session,
            Ref(smech),
            pointer(public_attrs),
            Reseau.CK_ULONG(length(public_attrs)),
            pointer(private_attrs),
            Reseau.CK_ULONG(length(private_attrs)),
            pub_ref,
            priv_ref,
        )
        @test rv == Reseau.CKR_OK
    end

    return priv_ref[], pub_ref[]
end

const EC_P256_PARAMS = Memory{UInt8}([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])

function pkcs11_create_ec_key(
        tester::Pkcs11Tester,
        session::Reseau.CK_SESSION_HANDLE,
        key_label::AbstractString,
        key_id::AbstractString,
    )
    fl = unsafe_load(Reseau.pkcs11_lib_get_function_list(tester.lib::Reseau.Pkcs11Lib))
    smech = Reseau.CK_MECHANISM(Reseau.CKM_EC_KEY_PAIR_GEN, C_NULL, Reseau.CK_ULONG(0))

    trueval = Ref{Reseau.CK_BBOOL}(Reseau.CK_TRUE)
    falseval = Ref{Reseau.CK_BBOOL}(Reseau.CK_FALSE)

    public_attrs = Memory{Reseau.CK_ATTRIBUTE}(undef, 2)
    public_attrs[1] = Reseau.CK_ATTRIBUTE(
        Reseau.CKA_EC_PARAMS,
        Ptr{Cvoid}(pointer(EC_P256_PARAMS)),
        Reseau.CK_ULONG(length(EC_P256_PARAMS)),
    )
    public_attrs[2] = Reseau.CK_ATTRIBUTE(
        Reseau.CKA_VERIFY,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{Reseau.CK_BBOOL}, trueval)),
        Reseau.CK_ULONG(sizeof(Reseau.CK_BBOOL)),
    )

    label_bytes = Vector{UInt8}(codeunits(key_label))
    id_bytes = Vector{UInt8}(codeunits(key_id))
    private_attrs = Memory{Reseau.CK_ATTRIBUTE}(undef, 4)
    private_attrs[1] = Reseau.CK_ATTRIBUTE(
        Reseau.CKA_LABEL,
        Ptr{Cvoid}(pointer(label_bytes)),
        Reseau.CK_ULONG(length(label_bytes)),
    )
    private_attrs[2] = Reseau.CK_ATTRIBUTE(
        Reseau.CKA_ID,
        Ptr{Cvoid}(pointer(id_bytes)),
        Reseau.CK_ULONG(length(id_bytes)),
    )
    private_attrs[3] = Reseau.CK_ATTRIBUTE(
        Reseau.CKA_SIGN,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{Reseau.CK_BBOOL}, trueval)),
        Reseau.CK_ULONG(sizeof(Reseau.CK_BBOOL)),
    )
    private_attrs[4] = Reseau.CK_ATTRIBUTE(
        Reseau.CKA_EXTRACTABLE,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{Reseau.CK_BBOOL}, falseval)),
        Reseau.CK_ULONG(sizeof(Reseau.CK_BBOOL)),
    )

    priv_ref = Ref{Reseau.CK_OBJECT_HANDLE}(Reseau.CK_INVALID_HANDLE)
    pub_ref = Ref{Reseau.CK_OBJECT_HANDLE}(Reseau.CK_INVALID_HANDLE)

    GC.@preserve public_attrs private_attrs label_bytes id_bytes trueval falseval EC_P256_PARAMS begin
        rv = ccall(
            fl.C_GenerateKeyPair,
            Reseau.CK_RV,
            (Reseau.CK_SESSION_HANDLE, Ref{Reseau.CK_MECHANISM}, Ptr{Reseau.CK_ATTRIBUTE}, Reseau.CK_ULONG,
             Ptr{Reseau.CK_ATTRIBUTE}, Reseau.CK_ULONG, Ref{Reseau.CK_OBJECT_HANDLE}, Ref{Reseau.CK_OBJECT_HANDLE}),
            session,
            Ref(smech),
            pointer(public_attrs),
            Reseau.CK_ULONG(length(public_attrs)),
            pointer(private_attrs),
            Reseau.CK_ULONG(length(private_attrs)),
            pub_ref,
            priv_ref,
        )
        @test rv == Reseau.CKR_OK
    end

    return priv_ref[], pub_ref[]
end

function pkcs11_run_cmd(cmd::Cmd)
    run(cmd)
    return nothing
end

@testset "PKCS11 ASN1 bigint" begin
    function verify_bigint(input::AbstractVector{UInt8}, expected::AbstractVector{UInt8})
        buf_ref = Ref(Reseau.ByteBuffer(length(input) + 4))
        res = Reseau.pkcs11_asn1_enc_ubigint(buf_ref, Reseau.ByteCursor(input))
        @test res === nothing
        buf = buf_ref[]
        @test buf.len == length(expected)
        out = Vector{UInt8}(undef, Int(buf.len))
        copyto!(out, 1, buf.mem, 1, Int(buf.len))
        @test out == expected
        Reseau.byte_buf_clean_up(buf_ref)
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
            @test pkcs11_tester_init!(tester) isa Reseau.Pkcs11Lib
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 lib behavior default" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            pkcs11_tester_init_without_load!(tester)
            opts = Reseau.Pkcs11LibOptions(;
                filename = tester.lib_path,
                initialize_finalize_behavior = Reseau.Pkcs11LibBehavior.DEFAULT_BEHAVIOR,
            )
            lib1 = Reseau.pkcs11_lib_new(opts)
            @test lib1 isa Reseau.Pkcs11Lib
            lib2 = Reseau.pkcs11_lib_new(opts)
            @test lib2 isa Reseau.Pkcs11Lib
            Reseau.pkcs11_lib_release(lib1::Reseau.Pkcs11Lib)
            info = Ref(Reseau.CK_INFO(Reseau.CK_VERSION(0, 0), ntuple(_ -> UInt8(0x20), 32), 0,
                ntuple(_ -> UInt8(0x20), 32), Reseau.CK_VERSION(0, 0)))
            fl = unsafe_load(Reseau.pkcs11_lib_get_function_list(lib2::Reseau.Pkcs11Lib))
            rv = ccall(fl.C_GetInfo, Reseau.CK_RV, (Ref{Reseau.CK_INFO},), info)
            @test rv == Reseau.CKR_OK
            Reseau.pkcs11_lib_release(lib2::Reseau.Pkcs11Lib)
            lib3 = Reseau.pkcs11_lib_new(opts)
            @test lib3 isa Reseau.Pkcs11Lib
            Reseau.pkcs11_lib_release(lib3::Reseau.Pkcs11Lib)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 lib behavior omit initialize" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            pkcs11_tester_init_without_load!(tester)
            opts = Reseau.Pkcs11LibOptions(;
                filename = tester.lib_path,
                initialize_finalize_behavior = Reseau.Pkcs11LibBehavior.OMIT_INITIALIZE,
            )
            lib_fail = Reseau.pkcs11_lib_new(opts)
            @test lib_fail isa Reseau.ErrorResult
            if lib_fail isa Reseau.ErrorResult
                @test lib_fail.code == Reseau.ERROR_IO_PKCS11_CKR_CRYPTOKI_NOT_INITIALIZED
            end

            opts_strict = Reseau.Pkcs11LibOptions(;
                filename = tester.lib_path,
                initialize_finalize_behavior = Reseau.Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE,
            )
            lib1 = Reseau.pkcs11_lib_new(opts_strict)
            @test lib1 isa Reseau.Pkcs11Lib

            lib2 = Reseau.pkcs11_lib_new(opts)
            @test lib2 isa Reseau.Pkcs11Lib
            if lib2 isa Reseau.Pkcs11Lib
                Reseau.pkcs11_lib_release(lib2)
            end
            if lib1 isa Reseau.Pkcs11Lib
                Reseau.pkcs11_lib_release(lib1)
            end
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 lib behavior strict initialize/finalize" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            pkcs11_tester_init_without_load!(tester)
            opts = Reseau.Pkcs11LibOptions(;
                filename = tester.lib_path,
                initialize_finalize_behavior = Reseau.Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE,
            )
            lib1 = Reseau.pkcs11_lib_new(opts)
            @test lib1 isa Reseau.Pkcs11Lib
            lib2 = Reseau.pkcs11_lib_new(opts)
            @test lib2 isa Reseau.Pkcs11Lib
            Reseau.pkcs11_lib_release(lib1::Reseau.Pkcs11Lib)
            Reseau.pkcs11_lib_release(lib2::Reseau.Pkcs11Lib)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 session tests" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Reseau.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL, SO_PIN, USER_PIN)

            invalid = Reseau.pkcs11_lib_open_session(tester.lib::Reseau.Pkcs11Lib, UInt64(9999))
            @test invalid isa Reseau.ErrorResult

            session1 = Reseau.pkcs11_lib_open_session(tester.lib::Reseau.Pkcs11Lib, UInt64(slot))
            @test session1 isa Reseau.CK_SESSION_HANDLE
            session2 = Reseau.pkcs11_lib_open_session(tester.lib::Reseau.Pkcs11Lib, UInt64(slot))
            @test session2 isa Reseau.CK_SESSION_HANDLE
            @test session1 != session2

            Reseau.pkcs11_lib_close_session(tester.lib::Reseau.Pkcs11Lib, session1)
            Reseau.pkcs11_lib_close_session(tester.lib::Reseau.Pkcs11Lib, session2)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 login tests" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Reseau.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL, SO_PIN, USER_PIN)

            bad_login = Reseau.pkcs11_lib_login_user(
                tester.lib::Reseau.Pkcs11Lib,
                Reseau.CK_SESSION_HANDLE(1),
                Reseau.ByteCursor(USER_PIN),
            )
            @test bad_login isa Reseau.ErrorResult

            session = Reseau.pkcs11_lib_open_session(tester.lib::Reseau.Pkcs11Lib, UInt64(slot))
            @test session isa Reseau.CK_SESSION_HANDLE

            invalid_pin = Reseau.pkcs11_lib_login_user(
                tester.lib::Reseau.Pkcs11Lib,
                session,
                Reseau.ByteCursor("INVALID_PIN"),
            )
            @test invalid_pin isa Reseau.ErrorResult

            @test Reseau.pkcs11_lib_login_user(tester.lib::Reseau.Pkcs11Lib, session, Reseau.ByteCursor(USER_PIN)) === nothing
            @test Reseau.pkcs11_lib_login_user(tester.lib::Reseau.Pkcs11Lib, session, Reseau.ByteCursor(USER_PIN)) === nothing

            session2 = Reseau.pkcs11_lib_open_session(tester.lib::Reseau.Pkcs11Lib, UInt64(slot))
            @test Reseau.pkcs11_lib_login_user(tester.lib::Reseau.Pkcs11Lib, session2, Reseau.ByteCursor(USER_PIN)) === nothing

            Reseau.pkcs11_lib_close_session(tester.lib::Reseau.Pkcs11Lib, session)
            @test Reseau.pkcs11_lib_login_user(tester.lib::Reseau.Pkcs11Lib, session2, Reseau.ByteCursor(USER_PIN)) === nothing
            Reseau.pkcs11_lib_close_session(tester.lib::Reseau.Pkcs11Lib, session2)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find private key for different rsa types" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Reseau.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL_RSA, SO_PIN, USER_PIN)

            session_access = Reseau.pkcs11_lib_open_session(tester.lib::Reseau.Pkcs11Lib, UInt64(slot))
            session_create = Reseau.pkcs11_lib_open_session(tester.lib::Reseau.Pkcs11Lib, UInt64(slot))
            @test Reseau.pkcs11_lib_login_user(tester.lib::Reseau.Pkcs11Lib, session_access, Reseau.ByteCursor(USER_PIN)) === nothing

            k1, _ = pkcs11_create_rsa_key(tester, session_create, "1024_Key", "1024_id", 1024)
            res1 = Reseau.pkcs11_lib_find_private_key(
                tester.lib::Reseau.Pkcs11Lib,
                session_access,
                Reseau.ByteCursor("1024_Key"),
            )
            @test res1 isa Tuple
            if res1 isa Tuple
                @test res1[1] == k1
                @test res1[2] == Reseau.CKK_RSA
            end

            k2, _ = pkcs11_create_rsa_key(tester, session_create, "2048_Key", "2048_id", 2048)
            res2 = Reseau.pkcs11_lib_find_private_key(
                tester.lib::Reseau.Pkcs11Lib,
                session_access,
                Reseau.ByteCursor("2048_Key"),
            )
            @test res2 isa Tuple
            if res2 isa Tuple
                @test res2[1] == k2
                @test res2[2] == Reseau.CKK_RSA
            end

            k3, _ = pkcs11_create_rsa_key(tester, session_create, "4096_Key", "4096_id", 4096)
            res3 = Reseau.pkcs11_lib_find_private_key(
                tester.lib::Reseau.Pkcs11Lib,
                session_access,
                Reseau.ByteCursor("4096_Key"),
            )
            @test res3 isa Tuple
            if res3 isa Tuple
                @test res3[1] == k3
                @test res3[2] == Reseau.CKK_RSA
            end
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find private key for ec" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Reseau.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL, SO_PIN, USER_PIN)

            session_access = Reseau.pkcs11_lib_open_session(tester.lib::Reseau.Pkcs11Lib, UInt64(slot))
            session_create = Reseau.pkcs11_lib_open_session(tester.lib::Reseau.Pkcs11Lib, UInt64(slot))
            @test Reseau.pkcs11_lib_login_user(tester.lib::Reseau.Pkcs11Lib, session_access, Reseau.ByteCursor(USER_PIN)) === nothing

            k1, _ = pkcs11_create_ec_key(tester, session_create, "EC_256_Key", "EC_256_id")
            res = Reseau.pkcs11_lib_find_private_key(
                tester.lib::Reseau.Pkcs11Lib,
                session_access,
                Reseau.ByteCursor("EC_256_Key"),
            )
            @test res isa Tuple
            if res isa Tuple
                @test res[1] == k1
                @test res[2] == Reseau.CKK_EC
            end
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find multiple private key" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Reseau.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL, SO_PIN, USER_PIN)

            session_access = Reseau.pkcs11_lib_open_session(tester.lib::Reseau.Pkcs11Lib, UInt64(slot))
            session_create1 = Reseau.pkcs11_lib_open_session(tester.lib::Reseau.Pkcs11Lib, UInt64(slot))
            session_create2 = Reseau.pkcs11_lib_open_session(tester.lib::Reseau.Pkcs11Lib, UInt64(slot))
            @test Reseau.pkcs11_lib_login_user(tester.lib::Reseau.Pkcs11Lib, session_access, Reseau.ByteCursor(USER_PIN)) === nothing

            k1, _ = pkcs11_create_rsa_key(tester, session_create1, "RSA_KEY", "BEEFCAFE", 1024)
            k2, _ = pkcs11_create_rsa_key(tester, session_create2, "DES_KEY_2", "BEEFCAFEDEAD", 1024)

            res = Reseau.pkcs11_lib_find_private_key(tester.lib::Reseau.Pkcs11Lib, session_access, nothing)
            @test res isa Reseau.ErrorResult

            res1 = Reseau.pkcs11_lib_find_private_key(
                tester.lib::Reseau.Pkcs11Lib,
                session_access,
                Reseau.ByteCursor("RSA_KEY"),
            )
            @test res1 isa Tuple
            if res1 isa Tuple
                @test res1[1] == k1
                @test res1[2] == Reseau.CKK_RSA
            end

            res2 = Reseau.pkcs11_lib_find_private_key(
                tester.lib::Reseau.Pkcs11Lib,
                session_access,
                Reseau.ByteCursor("DES_KEY_2"),
            )
            @test res2 isa Tuple
            if res2 isa Tuple
                @test res2[1] == k2
                @test res2[2] == Reseau.CKK_RSA
            end

            Reseau.pkcs11_lib_close_session(tester.lib::Reseau.Pkcs11Lib, session_access)
            Reseau.pkcs11_lib_close_session(tester.lib::Reseau.Pkcs11Lib, session_create1)
            Reseau.pkcs11_lib_close_session(tester.lib::Reseau.Pkcs11Lib, session_create2)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find private key" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Reseau.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL, SO_PIN, USER_PIN)

            session_access = Reseau.pkcs11_lib_open_session(tester.lib::Reseau.Pkcs11Lib, UInt64(slot))
            session_create = Reseau.pkcs11_lib_open_session(tester.lib::Reseau.Pkcs11Lib, UInt64(slot))
            @test Reseau.pkcs11_lib_login_user(tester.lib::Reseau.Pkcs11Lib, session_access, Reseau.ByteCursor(USER_PIN)) === nothing

            k1, _ = pkcs11_create_rsa_key(tester, session_create, "RSA_KEY", "BEEFCAFE", 1024)
            res1 = Reseau.pkcs11_lib_find_private_key(
                tester.lib::Reseau.Pkcs11Lib,
                session_access,
                Reseau.ByteCursor("RSA_KEY"),
            )
            @test res1 isa Tuple
            if res1 isa Tuple
                @test res1[1] == k1
                @test res1[2] == Reseau.CKK_RSA
            end

            res_none = Reseau.pkcs11_lib_find_private_key(
                tester.lib::Reseau.Pkcs11Lib,
                session_access,
                Reseau.ByteCursor("NON_EXISTENT"),
            )
            @test res_none isa Reseau.ErrorResult
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find slot" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Reseau.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, "label!@#", SO_PIN, USER_PIN)

            found = Reseau.pkcs11_lib_find_slot_with_token(tester.lib::Reseau.Pkcs11Lib, nothing, nothing)
            @test found isa UInt64

            match_slot = UInt64(slot)
            found_slot = Reseau.pkcs11_lib_find_slot_with_token(tester.lib::Reseau.Pkcs11Lib, match_slot, nothing)
            @test found_slot == match_slot

            label = Reseau.ByteCursor("label!@#")
            found_label = Reseau.pkcs11_lib_find_slot_with_token(tester.lib::Reseau.Pkcs11Lib, nothing, label)
            @test found_label == match_slot
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find slot many tokens" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Reseau.Pkcs11Lib
            slot1 = pkcs11_softhsm_create_slot(tester, "token_one", SO_PIN, USER_PIN)
            slot2 = pkcs11_softhsm_create_slot(tester, "token_two", SO_PIN, USER_PIN)

            found1 = Reseau.pkcs11_lib_find_slot_with_token(tester.lib::Reseau.Pkcs11Lib, UInt64(slot1), nothing)
            @test found1 == UInt64(slot1)
            found2 = Reseau.pkcs11_lib_find_slot_with_token(tester.lib::Reseau.Pkcs11Lib, UInt64(slot2), nothing)
            @test found2 == UInt64(slot2)

            label1 = Reseau.ByteCursor("token_one")
            found_label1 = Reseau.pkcs11_lib_find_slot_with_token(tester.lib::Reseau.Pkcs11Lib, nothing, label1)
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

            input_cursor = Reseau.ByteCursor("ABCDEFGHIJKL")
            cipher_buf = pkcs11_rsa_encrypt(tester, input_cursor, session, pub)
            cipher_cur = Reseau.byte_cursor_from_buf(cipher_buf)

            decrypted = Reseau.pkcs11_lib_decrypt(
                tester.lib::Reseau.Pkcs11Lib,
                session,
                priv,
                Reseau.CKK_RSA,
                cipher_cur,
            )
            @test decrypted isa Reseau.ByteBuffer
            if decrypted isa Reseau.ByteBuffer
                out = Vector{UInt8}(undef, Int(decrypted.len))
                copyto!(out, 1, decrypted.mem, 1, Int(decrypted.len))
                @test out == Vector{UInt8}(codeunits("ABCDEFGHIJKL"))
            end

            unsupported = Reseau.pkcs11_lib_decrypt(
                tester.lib::Reseau.Pkcs11Lib,
                session,
                priv,
                Reseau.CKK_GENERIC_SECRET,
                cipher_cur,
            )
            @test unsupported isa Reseau.ErrorResult

            bad_session = Reseau.pkcs11_lib_decrypt(
                tester.lib::Reseau.Pkcs11Lib,
                Reseau.CK_SESSION_HANDLE(0),
                priv,
                Reseau.CKK_RSA,
                cipher_cur,
            )
            @test bad_session isa Reseau.ErrorResult

            bad_key = Reseau.pkcs11_lib_decrypt(
                tester.lib::Reseau.Pkcs11Lib,
                session,
                Reseau.CK_INVALID_HANDLE,
                Reseau.CKK_RSA,
                cipher_cur,
            )
            @test bad_key isa Reseau.ErrorResult

            empty = Reseau.pkcs11_lib_decrypt(
                tester.lib::Reseau.Pkcs11Lib,
                session,
                priv,
                Reseau.CKK_RSA,
                Reseau.ByteCursor(""),
            )
            @test empty isa Reseau.ErrorResult
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

                message = Reseau.ByteCursor("ABCDEFGHIJKL")
                signature = Reseau.pkcs11_lib_sign(
                    tester.lib::Reseau.Pkcs11Lib,
                    session,
                    priv,
                    Reseau.CKK_RSA,
                    message,
                    digest_alg,
                    Reseau.TlsSignatureAlgorithm.RSA,
                )
                @test signature isa Reseau.ByteBuffer
                if signature isa Reseau.ByteBuffer
                    prefix = Reseau.get_prefix_to_rsa_sig(digest_alg)
                    @test prefix isa Reseau.ByteCursor
                    if prefix isa Reseau.ByteCursor
                        prefixed = Reseau.ByteBuffer(Int(prefix.len + message.len))
                        pref_ref = Ref(prefixed)
                        @test Reseau.byte_buf_write_from_whole_cursor(pref_ref, prefix)
                        @test Reseau.byte_buf_write_from_whole_cursor(pref_ref, message)
                        prefixed = pref_ref[]
                        pkcs11_verify_signature(
                            tester,
                            Reseau.byte_cursor_from_buf(prefixed),
                            signature,
                            session,
                            pub,
                            Reseau.CKM_RSA_PKCS,
                        )
                    end
                end

                unsupported = Reseau.pkcs11_lib_sign(
                    tester.lib::Reseau.Pkcs11Lib,
                    session,
                    priv,
                    Reseau.CKK_GENERIC_SECRET,
                    message,
                    digest_alg,
                    Reseau.TlsSignatureAlgorithm.RSA,
                )
                @test unsupported isa Reseau.ErrorResult
            finally
                pkcs11_tester_cleanup!(tester)
            end
        end
        sign_rsa(Reseau.TlsHashAlgorithm.SHA1)
        sign_rsa(Reseau.TlsHashAlgorithm.SHA512)
        sign_rsa(Reseau.TlsHashAlgorithm.SHA384)
        sign_rsa(Reseau.TlsHashAlgorithm.SHA256)
        sign_rsa(Reseau.TlsHashAlgorithm.SHA224)
    end

    @testset "pkcs11 sign ec 256" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            slot, session = pkcs11_tester_init_with_session_login!(tester, TOKEN_LABEL_EC)
            priv, pub = pkcs11_create_ec_key(tester, session, DEFAULT_KEY_LABEL, DEFAULT_KEY_ID)

            message = Reseau.ByteCursor("ABCDEFGHIJKL")
            signature = Reseau.pkcs11_lib_sign(
                tester.lib::Reseau.Pkcs11Lib,
                session,
                priv,
                Reseau.CKK_EC,
                message,
                Reseau.TlsHashAlgorithm.UNKNOWN,
                Reseau.TlsSignatureAlgorithm.ECDSA,
            )
            @test signature isa Reseau.ByteBuffer

            unsupported = Reseau.pkcs11_lib_sign(
                tester.lib::Reseau.Pkcs11Lib,
                session,
                priv,
                Reseau.CKK_GENERIC_SECRET,
                message,
                Reseau.TlsHashAlgorithm.UNKNOWN,
                Reseau.TlsSignatureAlgorithm.ECDSA,
            )
            @test unsupported isa Reseau.ErrorResult
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 tls negotiation succeeds (rsa)" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Reseau.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL_RSA, SO_PIN, USER_PIN)
            Reseau.pkcs11_lib_release(tester.lib::Reseau.Pkcs11Lib)
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

            @test pkcs11_reload_hsm!(tester) isa Reseau.Pkcs11Lib

            elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
            resolver = Reseau.DefaultHostResolver(elg)

            server_tls_opts = Reseau.tls_ctx_options_init_default_server_from_path(cert_path, key_path)
            maybe_apply_test_keychain!(server_tls_opts)
            @test server_tls_opts isa Reseau.TlsContextOptions
            if server_tls_opts isa Reseau.TlsContextOptions
                _ = Reseau.tls_ctx_options_override_default_trust_store_from_path(
                    server_tls_opts;
                    ca_file = cert_path,
                )
                Reseau.tls_ctx_options_set_verify_peer(server_tls_opts, true)
            end
            server_ctx = Reseau.tls_context_new(server_tls_opts)
            @test server_ctx isa Reseau.TlsContext

            server_ready = Ref(false)
            server_shutdown = Ref(false)

            server_bootstrap = Reseau.ServerBootstrap(Reseau.ServerBootstrapOptions(
                event_loop_group = elg,
                host = "127.0.0.1",
                port = 0,
                tls_connection_options = Reseau.TlsConnectionOptions(server_ctx),
                on_incoming_channel_setup = (bs, err, channel, ud) -> begin
                    server_ready[] = err == Reseau.AWS_OP_SUCCESS
                    return nothing
                end,
                on_incoming_channel_shutdown = (bs, err, channel, ud) -> begin
                    server_shutdown[] = true
                    return nothing
                end,
            ))
            listener = server_bootstrap.listener_socket
            @test listener !== nothing
            bound = Reseau.socket_get_bound_address(listener)
            port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
            @test port != 0

            client_opts = Reseau.TlsCtxPkcs11Options(
                pkcs11_lib = tester.lib,
                token_label = TOKEN_LABEL_RSA,
                user_pin = USER_PIN,
                private_key_object_label = DEFAULT_KEY_LABEL,
                cert_file_path = cert_path,
            )
            client_tls_opts = Reseau.tls_ctx_options_init_client_mtls_with_pkcs11(client_opts)
            @test client_tls_opts isa Reseau.TlsContextOptions
            client_ctx = Reseau.tls_context_new(client_tls_opts)
            @test client_ctx isa Reseau.TlsContext

            client_ready = Ref(false)
            client_shutdown = Ref(false)
            client_bootstrap = Reseau.ClientBootstrap(Reseau.ClientBootstrapOptions(
                event_loop_group = elg,
                host_resolver = resolver,
            ))
            @test Reseau.client_bootstrap_connect!(
                client_bootstrap,
                "127.0.0.1",
                port;
                tls_connection_options = Reseau.TlsConnectionOptions(client_ctx; server_name = "localhost"),
                on_setup = (bs, err, channel, ud) -> begin
                    client_ready[] = err == Reseau.AWS_OP_SUCCESS
                    if err == Reseau.AWS_OP_SUCCESS
                        Reseau.channel_shutdown!(channel, Reseau.AWS_OP_SUCCESS)
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

            Reseau.server_bootstrap_shutdown!(server_bootstrap)
            Reseau.host_resolver_shutdown!(resolver)
            Reseau.event_loop_group_destroy!(elg)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 tls negotiation succeeds (ec)" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Reseau.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL_EC, SO_PIN, USER_PIN)
            Reseau.pkcs11_lib_release(tester.lib::Reseau.Pkcs11Lib)
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

            @test pkcs11_reload_hsm!(tester) isa Reseau.Pkcs11Lib

            elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
            resolver = Reseau.DefaultHostResolver(elg)

            server_tls_opts = Reseau.tls_ctx_options_init_default_server_from_path(cert_path, key_path)
            maybe_apply_test_keychain!(server_tls_opts)
            @test server_tls_opts isa Reseau.TlsContextOptions
            if server_tls_opts isa Reseau.TlsContextOptions
                _ = Reseau.tls_ctx_options_override_default_trust_store_from_path(
                    server_tls_opts;
                    ca_file = cert_path,
                )
                Reseau.tls_ctx_options_set_verify_peer(server_tls_opts, true)
            end
            server_ctx = Reseau.tls_context_new(server_tls_opts)
            @test server_ctx isa Reseau.TlsContext

            server_ready = Ref(false)
            server_shutdown = Ref(false)

            server_bootstrap = Reseau.ServerBootstrap(Reseau.ServerBootstrapOptions(
                event_loop_group = elg,
                host = "127.0.0.1",
                port = 0,
                tls_connection_options = Reseau.TlsConnectionOptions(server_ctx),
                on_incoming_channel_setup = (bs, err, channel, ud) -> begin
                    server_ready[] = err == Reseau.AWS_OP_SUCCESS
                    return nothing
                end,
                on_incoming_channel_shutdown = (bs, err, channel, ud) -> begin
                    server_shutdown[] = true
                    return nothing
                end,
            ))
            listener = server_bootstrap.listener_socket
            @test listener !== nothing
            bound = Reseau.socket_get_bound_address(listener)
            port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
            @test port != 0

            client_opts = Reseau.TlsCtxPkcs11Options(
                pkcs11_lib = tester.lib,
                token_label = TOKEN_LABEL_EC,
                user_pin = USER_PIN,
                private_key_object_label = DEFAULT_KEY_LABEL,
                cert_file_path = cert_path,
            )
            client_tls_opts = Reseau.tls_ctx_options_init_client_mtls_with_pkcs11(client_opts)
            @test client_tls_opts isa Reseau.TlsContextOptions
            client_ctx = Reseau.tls_context_new(client_tls_opts)
            @test client_ctx isa Reseau.TlsContext

            client_ready = Ref(false)
            client_shutdown = Ref(false)
            client_bootstrap = Reseau.ClientBootstrap(Reseau.ClientBootstrapOptions(
                event_loop_group = elg,
                host_resolver = resolver,
            ))
            @test Reseau.client_bootstrap_connect!(
                client_bootstrap,
                "127.0.0.1",
                port;
                tls_connection_options = Reseau.TlsConnectionOptions(client_ctx; server_name = "localhost"),
                on_setup = (bs, err, channel, ud) -> begin
                    client_ready[] = err == Reseau.AWS_OP_SUCCESS
                    if err == Reseau.AWS_OP_SUCCESS
                        Reseau.channel_shutdown!(channel, Reseau.AWS_OP_SUCCESS)
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

            Reseau.server_bootstrap_shutdown!(server_bootstrap)
            Reseau.host_resolver_shutdown!(resolver)
            Reseau.event_loop_group_destroy!(elg)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end
end
