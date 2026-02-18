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
    @test Sockets.pkcs11_error_from_ckr(Sockets.CKR_FUNCTION_NOT_SUPPORTED) ==
        EventLoops.ERROR_IO_PKCS11_CKR_FUNCTION_NOT_SUPPORTED
    @test Sockets.pkcs11_error_from_ckr(0xdeadbeef) ==
        EventLoops.ERROR_IO_PKCS11_UNKNOWN_CRYPTOKI_RETURN_VALUE
    @test Sockets.pkcs11_ckr_str(Sockets.CKR_FUNCTION_NOT_SUPPORTED) == "CKR_FUNCTION_NOT_SUPPORTED"
    @test Sockets.pkcs11_ckr_str(0xdeadbeef) == "CKR_UNKNOWN"
end

mutable struct Pkcs11Tester
    lib_path::String
    token_dir::String
    lib::Union{Sockets.Pkcs11Lib, Nothing}
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
    Sockets.io_library_init()
    tester.lib_path = get(ENV, PKCS11_ENV_LIB, "")
    tester.token_dir = get(ENV, PKCS11_ENV_TOKEN_DIR, "")
    pkcs11_clear_softhsm!(tester)
    tester.lib = nothing
    return nothing
end

function pkcs11_tester_init!(
        tester::Pkcs11Tester;
        behavior::Sockets.Pkcs11LibBehavior.T = Sockets.Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE,
    )
    pkcs11_tester_init_without_load!(tester)
    opts = Sockets.Pkcs11LibOptions(;
        filename = tester.lib_path,
        initialize_finalize_behavior = behavior,
    )
    lib = Sockets.pkcs11_lib_new(opts)
    @test lib isa Sockets.Pkcs11Lib
    tester.lib = lib
    return tester.lib
end

function pkcs11_tester_cleanup!(tester::Pkcs11Tester)
    if tester.lib !== nothing
        Sockets.pkcs11_lib_release(tester.lib)
        tester.lib = nothing
    end
    pkcs11_clear_softhsm!(tester)
    Sockets.io_library_clean_up()
    tester.lib_path = ""
    tester.token_dir = ""
    return nothing
end

function pkcs11_reload_hsm!(tester::Pkcs11Tester)
    if tester.lib !== nothing
        Sockets.pkcs11_lib_release(tester.lib)
        tester.lib = nothing
    end
    opts = Sockets.Pkcs11LibOptions(;
        filename = tester.lib_path,
        initialize_finalize_behavior = Sockets.Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE,
    )
    lib = Sockets.pkcs11_lib_new(opts)
    @test lib isa Sockets.Pkcs11Lib
    tester.lib = lib
    return tester.lib
end

function pkcs11_empty_token_info()
    return Sockets.CK_TOKEN_INFO(
        ntuple(_ -> UInt8(0x20), 32),
        ntuple(_ -> UInt8(0x20), 32),
        ntuple(_ -> UInt8(0x20), 16),
        ntuple(_ -> UInt8(0x20), 16),
        Sockets.CK_FLAGS(0),
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
end

function pkcs11_find_slot(tester::Pkcs11Tester, token_info::Union{Sockets.CK_TOKEN_INFO, Nothing})
    @test tester.lib !== nothing
    fl_ptr = Sockets.pkcs11_lib_get_function_list(tester.lib::Sockets.Pkcs11Lib)
    @test fl_ptr != C_NULL
    fl = unsafe_load(fl_ptr)

    slot_count = Ref{Sockets.CK_ULONG}(0)
    rv = ccall(
        fl.C_GetSlotList,
        Sockets.CK_RV,
        (Sockets.CK_BBOOL, Ptr{Sockets.CK_SLOT_ID}, Ptr{Sockets.CK_ULONG}),
        Sockets.CK_TRUE,
        C_NULL,
        slot_count,
    )
    @test rv == Sockets.CKR_OK

    count = Int(slot_count[])
    slots = Memory{Sockets.CK_SLOT_ID}(undef, count)
    rv = GC.@preserve slots begin
        ccall(
            fl.C_GetSlotList,
            Sockets.CK_RV,
            (Sockets.CK_BBOOL, Ptr{Sockets.CK_SLOT_ID}, Ptr{Sockets.CK_ULONG}),
            Sockets.CK_FALSE,
            pointer(slots),
            slot_count,
        )
    end
    @test rv == Sockets.CKR_OK

    found_slot = Sockets.CK_SLOT_ID(0)
    matches = 0
    for i in 1:count
        info_ref = Ref(pkcs11_empty_token_info())
        rv = ccall(
            fl.C_GetTokenInfo,
            Sockets.CK_RV,
            (Sockets.CK_SLOT_ID, Ptr{Sockets.CK_TOKEN_INFO}),
            slots[i],
            info_ref,
        )
        @test rv == Sockets.CKR_OK
        info = info_ref[]
        if token_info === nothing
            if (info.flags & Sockets.CKF_TOKEN_INITIALIZED) == 0
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
    fl = unsafe_load(Sockets.pkcs11_lib_get_function_list(tester.lib::Sockets.Pkcs11Lib))

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
            Sockets.CK_RV,
            (Sockets.CK_SLOT_ID, Ptr{UInt8}, Sockets.CK_ULONG, Ptr{UInt8}),
            slot_id,
            pointer(so_bytes),
            Sockets.CK_ULONG(length(so_bytes)),
            pointer(label_buf),
        )
        @test rv == Sockets.CKR_OK

        session_ref = Ref{Sockets.CK_SESSION_HANDLE}(0)
        rv = ccall(
            fl.C_OpenSession,
            Sockets.CK_RV,
            (Sockets.CK_SLOT_ID, Sockets.CK_FLAGS, Ptr{Cvoid}, Ptr{Cvoid}, Ref{Sockets.CK_SESSION_HANDLE}),
            slot_id,
            Sockets.CKF_SERIAL_SESSION | Sockets.CKF_RW_SESSION,
            C_NULL,
            C_NULL,
            session_ref,
        )
        @test rv == Sockets.CKR_OK
        session = session_ref[]

        rv = ccall(
            fl.C_Login,
            Sockets.CK_RV,
            (Sockets.CK_SESSION_HANDLE, Sockets.CK_ULONG, Ptr{UInt8}, Sockets.CK_ULONG),
            session,
            Sockets.CKU_SO,
            pointer(so_bytes),
            Sockets.CK_ULONG(length(so_bytes)),
        )
        @test rv == Sockets.CKR_OK

        rv = ccall(
            fl.C_InitPIN,
            Sockets.CK_RV,
            (Sockets.CK_SESSION_HANDLE, Ptr{UInt8}, Sockets.CK_ULONG),
            session,
            pointer(user_bytes),
            Sockets.CK_ULONG(length(user_bytes)),
        )
        @test rv == Sockets.CKR_OK
    end

    info_ref = Ref(pkcs11_empty_token_info())
    rv = ccall(
        fl.C_GetTokenInfo,
        Sockets.CK_RV,
        (Sockets.CK_SLOT_ID, Ptr{Sockets.CK_TOKEN_INFO}),
        slot_id,
        info_ref,
    )
    @test rv == Sockets.CKR_OK

    @test pkcs11_reload_hsm!(tester) isa Sockets.Pkcs11Lib
    new_slot = pkcs11_find_slot(tester, info_ref[])
    return new_slot
end

function pkcs11_tester_init_with_session_login!(
        tester::Pkcs11Tester,
        token_label::AbstractString,
    )
    @test pkcs11_tester_init!(tester) isa Sockets.Pkcs11Lib
    slot = pkcs11_softhsm_create_slot(tester, token_label, SO_PIN, USER_PIN)
    session = Sockets.pkcs11_lib_open_session(tester.lib::Sockets.Pkcs11Lib, UInt64(slot))
    @test session isa Sockets.CK_SESSION_HANDLE

    login_res = Sockets.pkcs11_lib_login_user(tester.lib::Sockets.Pkcs11Lib, session, Reseau.ByteCursor(USER_PIN))
    @test login_res === nothing
    return slot, session
end

function pkcs11_rsa_encrypt(
        tester::Pkcs11Tester,
        message::Reseau.ByteCursor,
        session::Sockets.CK_SESSION_HANDLE,
        public_key::Sockets.CK_OBJECT_HANDLE,
    )
    fl = unsafe_load(Sockets.pkcs11_lib_get_function_list(tester.lib::Sockets.Pkcs11Lib))
    mechanism = Sockets.CK_MECHANISM(Sockets.CKM_RSA_PKCS, C_NULL, Sockets.CK_ULONG(0))
    rv = ccall(
        fl.C_EncryptInit,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Ref{Sockets.CK_MECHANISM}, Sockets.CK_OBJECT_HANDLE),
        session,
        Ref(mechanism),
        public_key,
    )
    @test rv == Sockets.CKR_OK

    cipher_len = Ref{Sockets.CK_ULONG}(0)
    GC.@preserve message begin
        msg_ptr = message.len > 0 ? Ptr{UInt8}(pointer(message.ptr)) : Ptr{UInt8}(C_NULL)
        rv = ccall(
            fl.C_Encrypt,
            Sockets.CK_RV,
            (Sockets.CK_SESSION_HANDLE, Ptr{UInt8}, Sockets.CK_ULONG, Ptr{UInt8}, Ptr{Sockets.CK_ULONG}),
            session,
            msg_ptr,
            Sockets.CK_ULONG(message.len),
            C_NULL,
            cipher_len,
        )
    end
    @test rv == Sockets.CKR_OK

    output = Reseau.ByteBuffer(Int(cipher_len[]))
    GC.@preserve message output begin
        msg_ptr = message.len > 0 ? Ptr{UInt8}(pointer(message.ptr)) : Ptr{UInt8}(C_NULL)
        out_ptr = cipher_len[] > 0 ? Ptr{UInt8}(pointer(output.mem)) : Ptr{UInt8}(C_NULL)
        rv = ccall(
            fl.C_Encrypt,
            Sockets.CK_RV,
            (Sockets.CK_SESSION_HANDLE, Ptr{UInt8}, Sockets.CK_ULONG, Ptr{UInt8}, Ptr{Sockets.CK_ULONG}),
            session,
            msg_ptr,
            Sockets.CK_ULONG(message.len),
            out_ptr,
            cipher_len,
        )
    end
    @test rv == Sockets.CKR_OK
    output.len = Csize_t(cipher_len[])
    return output
end

function pkcs11_verify_signature(
        tester::Pkcs11Tester,
        message::Reseau.ByteCursor,
        signature::Reseau.ByteBuffer,
        session::Sockets.CK_SESSION_HANDLE,
        public_key::Sockets.CK_OBJECT_HANDLE,
        mechanism_type::Sockets.CK_MECHANISM_TYPE,
    )
    fl = unsafe_load(Sockets.pkcs11_lib_get_function_list(tester.lib::Sockets.Pkcs11Lib))
    mechanism = Sockets.CK_MECHANISM(mechanism_type, C_NULL, Sockets.CK_ULONG(0))
    rv = ccall(
        fl.C_VerifyInit,
        Sockets.CK_RV,
        (Sockets.CK_SESSION_HANDLE, Ref{Sockets.CK_MECHANISM}, Sockets.CK_OBJECT_HANDLE),
        session,
        Ref(mechanism),
        public_key,
    )
    @test rv == Sockets.CKR_OK

    GC.@preserve message signature begin
        msg_ptr = message.len > 0 ? Ptr{UInt8}(pointer(message.ptr)) : Ptr{UInt8}(C_NULL)
        sig_ptr = signature.len > 0 ? Ptr{UInt8}(pointer(signature.mem)) : Ptr{UInt8}(C_NULL)
        rv = ccall(
            fl.C_Verify,
            Sockets.CK_RV,
            (Sockets.CK_SESSION_HANDLE, Ptr{UInt8}, Sockets.CK_ULONG, Ptr{UInt8}, Sockets.CK_ULONG),
            session,
            msg_ptr,
            Sockets.CK_ULONG(message.len),
            sig_ptr,
            Sockets.CK_ULONG(signature.len),
        )
    end
    @test rv == Sockets.CKR_OK
    return nothing
end

function pkcs11_create_rsa_key(
        tester::Pkcs11Tester,
        session::Sockets.CK_SESSION_HANDLE,
        key_label::AbstractString,
        key_id::AbstractString,
        key_length::Integer,
    )
    fl = unsafe_load(Sockets.pkcs11_lib_get_function_list(tester.lib::Sockets.Pkcs11Lib))

    smech = Sockets.CK_MECHANISM(Sockets.CKM_RSA_PKCS_KEY_PAIR_GEN, C_NULL, Sockets.CK_ULONG(0))
    trueval = Ref{Sockets.CK_BBOOL}(Sockets.CK_TRUE)
    falseval = Ref{Sockets.CK_BBOOL}(Sockets.CK_FALSE)
    modulus = Ref{Sockets.CK_ULONG}(Sockets.CK_ULONG(key_length))

    public_attrs = Memory{Sockets.CK_ATTRIBUTE}(undef, 2)
    public_attrs[1] = Sockets.CK_ATTRIBUTE(
        Sockets.CKA_VERIFY,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{Sockets.CK_BBOOL}, trueval)),
        Sockets.CK_ULONG(sizeof(Sockets.CK_BBOOL)),
    )
    public_attrs[2] = Sockets.CK_ATTRIBUTE(
        Sockets.CKA_MODULUS_BITS,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{Sockets.CK_ULONG}, modulus)),
        Sockets.CK_ULONG(sizeof(Sockets.CK_ULONG)),
    )

    label_bytes = Vector{UInt8}(codeunits(key_label))
    id_bytes = Vector{UInt8}(codeunits(key_id))
    private_attrs = Memory{Sockets.CK_ATTRIBUTE}(undef, 4)
    private_attrs[1] = Sockets.CK_ATTRIBUTE(
        Sockets.CKA_LABEL,
        Ptr{Cvoid}(pointer(label_bytes)),
        Sockets.CK_ULONG(length(label_bytes)),
    )
    private_attrs[2] = Sockets.CK_ATTRIBUTE(
        Sockets.CKA_ID,
        Ptr{Cvoid}(pointer(id_bytes)),
        Sockets.CK_ULONG(length(id_bytes)),
    )
    private_attrs[3] = Sockets.CK_ATTRIBUTE(
        Sockets.CKA_SIGN,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{Sockets.CK_BBOOL}, trueval)),
        Sockets.CK_ULONG(sizeof(Sockets.CK_BBOOL)),
    )
    private_attrs[4] = Sockets.CK_ATTRIBUTE(
        Sockets.CKA_EXTRACTABLE,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{Sockets.CK_BBOOL}, falseval)),
        Sockets.CK_ULONG(sizeof(Sockets.CK_BBOOL)),
    )

    priv_ref = Ref{Sockets.CK_OBJECT_HANDLE}(Sockets.CK_INVALID_HANDLE)
    pub_ref = Ref{Sockets.CK_OBJECT_HANDLE}(Sockets.CK_INVALID_HANDLE)

    GC.@preserve public_attrs private_attrs label_bytes id_bytes trueval falseval modulus begin
        rv = ccall(
            fl.C_GenerateKeyPair,
            Sockets.CK_RV,
            (Sockets.CK_SESSION_HANDLE, Ref{Sockets.CK_MECHANISM}, Ptr{Sockets.CK_ATTRIBUTE}, Sockets.CK_ULONG,
             Ptr{Sockets.CK_ATTRIBUTE}, Sockets.CK_ULONG, Ref{Sockets.CK_OBJECT_HANDLE}, Ref{Sockets.CK_OBJECT_HANDLE}),
            session,
            Ref(smech),
            pointer(public_attrs),
            Sockets.CK_ULONG(length(public_attrs)),
            pointer(private_attrs),
            Sockets.CK_ULONG(length(private_attrs)),
            pub_ref,
            priv_ref,
        )
        @test rv == Sockets.CKR_OK
    end

    return priv_ref[], pub_ref[]
end

const EC_P256_PARAMS = Memory{UInt8}([0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07])

function pkcs11_create_ec_key(
        tester::Pkcs11Tester,
        session::Sockets.CK_SESSION_HANDLE,
        key_label::AbstractString,
        key_id::AbstractString,
    )
    fl = unsafe_load(Sockets.pkcs11_lib_get_function_list(tester.lib::Sockets.Pkcs11Lib))
    smech = Sockets.CK_MECHANISM(Sockets.CKM_EC_KEY_PAIR_GEN, C_NULL, Sockets.CK_ULONG(0))

    trueval = Ref{Sockets.CK_BBOOL}(Sockets.CK_TRUE)
    falseval = Ref{Sockets.CK_BBOOL}(Sockets.CK_FALSE)

    public_attrs = Memory{Sockets.CK_ATTRIBUTE}(undef, 2)
    public_attrs[1] = Sockets.CK_ATTRIBUTE(
        Sockets.CKA_EC_PARAMS,
        Ptr{Cvoid}(pointer(EC_P256_PARAMS)),
        Sockets.CK_ULONG(length(EC_P256_PARAMS)),
    )
    public_attrs[2] = Sockets.CK_ATTRIBUTE(
        Sockets.CKA_VERIFY,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{Sockets.CK_BBOOL}, trueval)),
        Sockets.CK_ULONG(sizeof(Sockets.CK_BBOOL)),
    )

    label_bytes = Vector{UInt8}(codeunits(key_label))
    id_bytes = Vector{UInt8}(codeunits(key_id))
    private_attrs = Memory{Sockets.CK_ATTRIBUTE}(undef, 4)
    private_attrs[1] = Sockets.CK_ATTRIBUTE(
        Sockets.CKA_LABEL,
        Ptr{Cvoid}(pointer(label_bytes)),
        Sockets.CK_ULONG(length(label_bytes)),
    )
    private_attrs[2] = Sockets.CK_ATTRIBUTE(
        Sockets.CKA_ID,
        Ptr{Cvoid}(pointer(id_bytes)),
        Sockets.CK_ULONG(length(id_bytes)),
    )
    private_attrs[3] = Sockets.CK_ATTRIBUTE(
        Sockets.CKA_SIGN,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{Sockets.CK_BBOOL}, trueval)),
        Sockets.CK_ULONG(sizeof(Sockets.CK_BBOOL)),
    )
    private_attrs[4] = Sockets.CK_ATTRIBUTE(
        Sockets.CKA_EXTRACTABLE,
        Ptr{Cvoid}(Base.unsafe_convert(Ptr{Sockets.CK_BBOOL}, falseval)),
        Sockets.CK_ULONG(sizeof(Sockets.CK_BBOOL)),
    )

    priv_ref = Ref{Sockets.CK_OBJECT_HANDLE}(Sockets.CK_INVALID_HANDLE)
    pub_ref = Ref{Sockets.CK_OBJECT_HANDLE}(Sockets.CK_INVALID_HANDLE)

    GC.@preserve public_attrs private_attrs label_bytes id_bytes trueval falseval EC_P256_PARAMS begin
        rv = ccall(
            fl.C_GenerateKeyPair,
            Sockets.CK_RV,
            (Sockets.CK_SESSION_HANDLE, Ref{Sockets.CK_MECHANISM}, Ptr{Sockets.CK_ATTRIBUTE}, Sockets.CK_ULONG,
             Ptr{Sockets.CK_ATTRIBUTE}, Sockets.CK_ULONG, Ref{Sockets.CK_OBJECT_HANDLE}, Ref{Sockets.CK_OBJECT_HANDLE}),
            session,
            Ref(smech),
            pointer(public_attrs),
            Sockets.CK_ULONG(length(public_attrs)),
            pointer(private_attrs),
            Sockets.CK_ULONG(length(private_attrs)),
            pub_ref,
            priv_ref,
        )
        @test rv == Sockets.CKR_OK
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
        res = Sockets.pkcs11_asn1_enc_ubigint(buf_ref, Reseau.ByteCursor(input))
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
            @test pkcs11_tester_init!(tester) isa Sockets.Pkcs11Lib
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 lib behavior default" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            pkcs11_tester_init_without_load!(tester)
            opts = Sockets.Pkcs11LibOptions(;
                filename = tester.lib_path,
                initialize_finalize_behavior = Sockets.Pkcs11LibBehavior.DEFAULT_BEHAVIOR,
            )
            lib1 = Sockets.pkcs11_lib_new(opts)
            @test lib1 isa Sockets.Pkcs11Lib
            lib2 = Sockets.pkcs11_lib_new(opts)
            @test lib2 isa Sockets.Pkcs11Lib
            Sockets.pkcs11_lib_release(lib1::Sockets.Pkcs11Lib)
            info = Ref(Sockets.CK_INFO(Sockets.CK_VERSION(0, 0), ntuple(_ -> UInt8(0x20), 32), 0,
                ntuple(_ -> UInt8(0x20), 32), Sockets.CK_VERSION(0, 0)))
            fl = unsafe_load(Sockets.pkcs11_lib_get_function_list(lib2::Sockets.Pkcs11Lib))
            rv = ccall(fl.C_GetInfo, Sockets.CK_RV, (Ref{Sockets.CK_INFO},), info)
            @test rv == Sockets.CKR_OK
            Sockets.pkcs11_lib_release(lib2::Sockets.Pkcs11Lib)
            lib3 = Sockets.pkcs11_lib_new(opts)
            @test lib3 isa Sockets.Pkcs11Lib
            Sockets.pkcs11_lib_release(lib3::Sockets.Pkcs11Lib)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 lib behavior omit initialize" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            pkcs11_tester_init_without_load!(tester)
            opts = Sockets.Pkcs11LibOptions(;
                filename = tester.lib_path,
                initialize_finalize_behavior = Sockets.Pkcs11LibBehavior.OMIT_INITIALIZE,
            )
            err = try
                Sockets.pkcs11_lib_new(opts)
                nothing
            catch e
                e
            end
            @test err isa Reseau.ReseauError
            @test err.code == EventLoops.ERROR_IO_PKCS11_CKR_CRYPTOKI_NOT_INITIALIZED

            opts_strict = Sockets.Pkcs11LibOptions(;
                filename = tester.lib_path,
                initialize_finalize_behavior = Sockets.Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE,
            )
            lib1 = Sockets.pkcs11_lib_new(opts_strict)
            @test lib1 isa Sockets.Pkcs11Lib

            lib2 = Sockets.pkcs11_lib_new(opts)
            @test lib2 isa Sockets.Pkcs11Lib
            Sockets.pkcs11_lib_release(lib2)
            Sockets.pkcs11_lib_release(lib1)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 lib behavior strict initialize/finalize" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            pkcs11_tester_init_without_load!(tester)
            opts = Sockets.Pkcs11LibOptions(;
                filename = tester.lib_path,
                initialize_finalize_behavior = Sockets.Pkcs11LibBehavior.STRICT_INITIALIZE_FINALIZE,
            )
            lib1 = Sockets.pkcs11_lib_new(opts)
            @test lib1 isa Sockets.Pkcs11Lib
            lib2 = Sockets.pkcs11_lib_new(opts)
            @test lib2 isa Sockets.Pkcs11Lib
            Sockets.pkcs11_lib_release(lib1::Sockets.Pkcs11Lib)
            Sockets.pkcs11_lib_release(lib2::Sockets.Pkcs11Lib)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 session tests" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Sockets.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL, SO_PIN, USER_PIN)

            @test_throws Reseau.ReseauError Sockets.pkcs11_lib_open_session(tester.lib::Sockets.Pkcs11Lib, UInt64(9999))

            session1 = Sockets.pkcs11_lib_open_session(tester.lib::Sockets.Pkcs11Lib, UInt64(slot))
            @test session1 isa Sockets.CK_SESSION_HANDLE
            session2 = Sockets.pkcs11_lib_open_session(tester.lib::Sockets.Pkcs11Lib, UInt64(slot))
            @test session2 isa Sockets.CK_SESSION_HANDLE
            @test session1 != session2

            Sockets.pkcs11_lib_close_session(tester.lib::Sockets.Pkcs11Lib, session1)
            Sockets.pkcs11_lib_close_session(tester.lib::Sockets.Pkcs11Lib, session2)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 login tests" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Sockets.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL, SO_PIN, USER_PIN)

            @test_throws Reseau.ReseauError Sockets.pkcs11_lib_login_user(
                tester.lib::Sockets.Pkcs11Lib,
                Sockets.CK_SESSION_HANDLE(1),
                Reseau.ByteCursor(USER_PIN),
            )

            session = Sockets.pkcs11_lib_open_session(tester.lib::Sockets.Pkcs11Lib, UInt64(slot))
            @test session isa Sockets.CK_SESSION_HANDLE

            @test_throws Reseau.ReseauError Sockets.pkcs11_lib_login_user(
                tester.lib::Sockets.Pkcs11Lib,
                session,
                Reseau.ByteCursor("INVALID_PIN"),
            )

            @test Sockets.pkcs11_lib_login_user(tester.lib::Sockets.Pkcs11Lib, session, Reseau.ByteCursor(USER_PIN)) === nothing
            @test Sockets.pkcs11_lib_login_user(tester.lib::Sockets.Pkcs11Lib, session, Reseau.ByteCursor(USER_PIN)) === nothing

            session2 = Sockets.pkcs11_lib_open_session(tester.lib::Sockets.Pkcs11Lib, UInt64(slot))
            @test Sockets.pkcs11_lib_login_user(tester.lib::Sockets.Pkcs11Lib, session2, Reseau.ByteCursor(USER_PIN)) === nothing

            Sockets.pkcs11_lib_close_session(tester.lib::Sockets.Pkcs11Lib, session)
            @test Sockets.pkcs11_lib_login_user(tester.lib::Sockets.Pkcs11Lib, session2, Reseau.ByteCursor(USER_PIN)) === nothing
            Sockets.pkcs11_lib_close_session(tester.lib::Sockets.Pkcs11Lib, session2)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find private key for different rsa types" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Sockets.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL_RSA, SO_PIN, USER_PIN)

            session_access = Sockets.pkcs11_lib_open_session(tester.lib::Sockets.Pkcs11Lib, UInt64(slot))
            session_create = Sockets.pkcs11_lib_open_session(tester.lib::Sockets.Pkcs11Lib, UInt64(slot))
            @test Sockets.pkcs11_lib_login_user(tester.lib::Sockets.Pkcs11Lib, session_access, Reseau.ByteCursor(USER_PIN)) === nothing

            k1, _ = pkcs11_create_rsa_key(tester, session_create, "1024_Key", "1024_id", 1024)
            res1 = Sockets.pkcs11_lib_find_private_key(
                tester.lib::Sockets.Pkcs11Lib,
                session_access,
                Reseau.ByteCursor("1024_Key"),
            )
            @test res1 isa Tuple
            if res1 isa Tuple
                @test res1[1] == k1
                @test res1[2] == Sockets.CKK_RSA
            end

            k2, _ = pkcs11_create_rsa_key(tester, session_create, "2048_Key", "2048_id", 2048)
            res2 = Sockets.pkcs11_lib_find_private_key(
                tester.lib::Sockets.Pkcs11Lib,
                session_access,
                Reseau.ByteCursor("2048_Key"),
            )
            @test res2 isa Tuple
            if res2 isa Tuple
                @test res2[1] == k2
                @test res2[2] == Sockets.CKK_RSA
            end

            k3, _ = pkcs11_create_rsa_key(tester, session_create, "4096_Key", "4096_id", 4096)
            res3 = Sockets.pkcs11_lib_find_private_key(
                tester.lib::Sockets.Pkcs11Lib,
                session_access,
                Reseau.ByteCursor("4096_Key"),
            )
            @test res3 isa Tuple
            if res3 isa Tuple
                @test res3[1] == k3
                @test res3[2] == Sockets.CKK_RSA
            end
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find private key for ec" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Sockets.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL, SO_PIN, USER_PIN)

            session_access = Sockets.pkcs11_lib_open_session(tester.lib::Sockets.Pkcs11Lib, UInt64(slot))
            session_create = Sockets.pkcs11_lib_open_session(tester.lib::Sockets.Pkcs11Lib, UInt64(slot))
            @test Sockets.pkcs11_lib_login_user(tester.lib::Sockets.Pkcs11Lib, session_access, Reseau.ByteCursor(USER_PIN)) === nothing

            k1, _ = pkcs11_create_ec_key(tester, session_create, "EC_256_Key", "EC_256_id")
            res = Sockets.pkcs11_lib_find_private_key(
                tester.lib::Sockets.Pkcs11Lib,
                session_access,
                Reseau.ByteCursor("EC_256_Key"),
            )
            @test res isa Tuple
            if res isa Tuple
                @test res[1] == k1
                @test res[2] == Sockets.CKK_EC
            end
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find multiple private key" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Sockets.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL, SO_PIN, USER_PIN)

            session_access = Sockets.pkcs11_lib_open_session(tester.lib::Sockets.Pkcs11Lib, UInt64(slot))
            session_create1 = Sockets.pkcs11_lib_open_session(tester.lib::Sockets.Pkcs11Lib, UInt64(slot))
            session_create2 = Sockets.pkcs11_lib_open_session(tester.lib::Sockets.Pkcs11Lib, UInt64(slot))
            @test Sockets.pkcs11_lib_login_user(tester.lib::Sockets.Pkcs11Lib, session_access, Reseau.ByteCursor(USER_PIN)) === nothing

            k1, _ = pkcs11_create_rsa_key(tester, session_create1, "RSA_KEY", "BEEFCAFE", 1024)
            k2, _ = pkcs11_create_rsa_key(tester, session_create2, "DES_KEY_2", "BEEFCAFEDEAD", 1024)

            @test_throws Reseau.ReseauError Sockets.pkcs11_lib_find_private_key(tester.lib::Sockets.Pkcs11Lib, session_access, nothing)

            res1 = Sockets.pkcs11_lib_find_private_key(
                tester.lib::Sockets.Pkcs11Lib,
                session_access,
                Reseau.ByteCursor("RSA_KEY"),
            )
            @test res1 isa Tuple
            if res1 isa Tuple
                @test res1[1] == k1
                @test res1[2] == Sockets.CKK_RSA
            end

            res2 = Sockets.pkcs11_lib_find_private_key(
                tester.lib::Sockets.Pkcs11Lib,
                session_access,
                Reseau.ByteCursor("DES_KEY_2"),
            )
            @test res2 isa Tuple
            if res2 isa Tuple
                @test res2[1] == k2
                @test res2[2] == Sockets.CKK_RSA
            end

            Sockets.pkcs11_lib_close_session(tester.lib::Sockets.Pkcs11Lib, session_access)
            Sockets.pkcs11_lib_close_session(tester.lib::Sockets.Pkcs11Lib, session_create1)
            Sockets.pkcs11_lib_close_session(tester.lib::Sockets.Pkcs11Lib, session_create2)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find private key" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Sockets.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL, SO_PIN, USER_PIN)

            session_access = Sockets.pkcs11_lib_open_session(tester.lib::Sockets.Pkcs11Lib, UInt64(slot))
            session_create = Sockets.pkcs11_lib_open_session(tester.lib::Sockets.Pkcs11Lib, UInt64(slot))
            @test Sockets.pkcs11_lib_login_user(tester.lib::Sockets.Pkcs11Lib, session_access, Reseau.ByteCursor(USER_PIN)) === nothing

            k1, _ = pkcs11_create_rsa_key(tester, session_create, "RSA_KEY", "BEEFCAFE", 1024)
            res1 = Sockets.pkcs11_lib_find_private_key(
                tester.lib::Sockets.Pkcs11Lib,
                session_access,
                Reseau.ByteCursor("RSA_KEY"),
            )
            @test res1 isa Tuple
            if res1 isa Tuple
                @test res1[1] == k1
                @test res1[2] == Sockets.CKK_RSA
            end

            @test_throws Reseau.ReseauError Sockets.pkcs11_lib_find_private_key(
                tester.lib::Sockets.Pkcs11Lib,
                session_access,
                Reseau.ByteCursor("NON_EXISTENT"),
            )
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find slot" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Sockets.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, "label!@#", SO_PIN, USER_PIN)

            found = Sockets.pkcs11_lib_find_slot_with_token(tester.lib::Sockets.Pkcs11Lib, nothing, nothing)
            @test found isa UInt64

            match_slot = UInt64(slot)
            found_slot = Sockets.pkcs11_lib_find_slot_with_token(tester.lib::Sockets.Pkcs11Lib, match_slot, nothing)
            @test found_slot == match_slot

            label = Reseau.ByteCursor("label!@#")
            found_label = Sockets.pkcs11_lib_find_slot_with_token(tester.lib::Sockets.Pkcs11Lib, nothing, label)
            @test found_label == match_slot
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 find slot many tokens" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Sockets.Pkcs11Lib
            slot1 = pkcs11_softhsm_create_slot(tester, "token_one", SO_PIN, USER_PIN)
            slot2 = pkcs11_softhsm_create_slot(tester, "token_two", SO_PIN, USER_PIN)

            found1 = Sockets.pkcs11_lib_find_slot_with_token(tester.lib::Sockets.Pkcs11Lib, UInt64(slot1), nothing)
            @test found1 == UInt64(slot1)
            found2 = Sockets.pkcs11_lib_find_slot_with_token(tester.lib::Sockets.Pkcs11Lib, UInt64(slot2), nothing)
            @test found2 == UInt64(slot2)

            label1 = Reseau.ByteCursor("token_one")
            found_label1 = Sockets.pkcs11_lib_find_slot_with_token(tester.lib::Sockets.Pkcs11Lib, nothing, label1)
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

            decrypted = Sockets.pkcs11_lib_decrypt(
                tester.lib::Sockets.Pkcs11Lib,
                session,
                priv,
                Sockets.CKK_RSA,
                cipher_cur,
            )
            @test decrypted isa Reseau.ByteBuffer
            out = Vector{UInt8}(undef, Int(decrypted.len))
            copyto!(out, 1, decrypted.mem, 1, Int(decrypted.len))
            @test out == Vector{UInt8}(codeunits("ABCDEFGHIJKL"))

            @test_throws Reseau.ReseauError Sockets.pkcs11_lib_decrypt(
                tester.lib::Sockets.Pkcs11Lib,
                session,
                priv,
                Sockets.CKK_GENERIC_SECRET,
                cipher_cur,
            )

            @test_throws Reseau.ReseauError Sockets.pkcs11_lib_decrypt(
                tester.lib::Sockets.Pkcs11Lib,
                Sockets.CK_SESSION_HANDLE(0),
                priv,
                Sockets.CKK_RSA,
                cipher_cur,
            )

            @test_throws Reseau.ReseauError Sockets.pkcs11_lib_decrypt(
                tester.lib::Sockets.Pkcs11Lib,
                session,
                Sockets.CK_INVALID_HANDLE,
                Sockets.CKK_RSA,
                cipher_cur,
            )

            @test_throws Reseau.ReseauError Sockets.pkcs11_lib_decrypt(
                tester.lib::Sockets.Pkcs11Lib,
                session,
                priv,
                Sockets.CKK_RSA,
                Reseau.ByteCursor(""),
            )
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
                signature = Sockets.pkcs11_lib_sign(
                    tester.lib::Sockets.Pkcs11Lib,
                    session,
                    priv,
                    Sockets.CKK_RSA,
                    message,
                    digest_alg,
                    Sockets.TlsSignatureAlgorithm.RSA,
                )
                @test signature isa Reseau.ByteBuffer
                prefix = Sockets.get_prefix_to_rsa_sig(digest_alg)
                @test prefix isa Reseau.ByteCursor
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
                    Sockets.CKM_RSA_PKCS,
                )

                @test_throws Reseau.ReseauError Sockets.pkcs11_lib_sign(
                    tester.lib::Sockets.Pkcs11Lib,
                    session,
                    priv,
                    Sockets.CKK_GENERIC_SECRET,
                    message,
                    digest_alg,
                    Sockets.TlsSignatureAlgorithm.RSA,
                )
            finally
                pkcs11_tester_cleanup!(tester)
            end
        end
        sign_rsa(Sockets.TlsHashAlgorithm.SHA1)
        sign_rsa(Sockets.TlsHashAlgorithm.SHA512)
        sign_rsa(Sockets.TlsHashAlgorithm.SHA384)
        sign_rsa(Sockets.TlsHashAlgorithm.SHA256)
        sign_rsa(Sockets.TlsHashAlgorithm.SHA224)
    end

    @testset "pkcs11 sign ec 256" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            slot, session = pkcs11_tester_init_with_session_login!(tester, TOKEN_LABEL_EC)
            priv, pub = pkcs11_create_ec_key(tester, session, DEFAULT_KEY_LABEL, DEFAULT_KEY_ID)

            message = Reseau.ByteCursor("ABCDEFGHIJKL")
            signature = Sockets.pkcs11_lib_sign(
                tester.lib::Sockets.Pkcs11Lib,
                session,
                priv,
                Sockets.CKK_EC,
                message,
                Sockets.TlsHashAlgorithm.UNKNOWN,
                Sockets.TlsSignatureAlgorithm.ECDSA,
            )
            @test signature isa Reseau.ByteBuffer

            @test_throws Reseau.ReseauError Sockets.pkcs11_lib_sign(
                tester.lib::Sockets.Pkcs11Lib,
                session,
                priv,
                Sockets.CKK_GENERIC_SECRET,
                message,
                Sockets.TlsHashAlgorithm.UNKNOWN,
                Sockets.TlsSignatureAlgorithm.ECDSA,
            )
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 tls negotiation succeeds (rsa)" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Sockets.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL_RSA, SO_PIN, USER_PIN)
            Sockets.pkcs11_lib_release(tester.lib::Sockets.Pkcs11Lib)
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

            @test pkcs11_reload_hsm!(tester) isa Sockets.Pkcs11Lib

            elg = EventLoops.EventLoopGroup(; loop_count = 1)
            resolver = Sockets.HostResolver()

            server_tls_opts = Sockets.tls_ctx_options_init_default_server_from_path(cert_path, key_path)
            maybe_apply_test_keychain!(server_tls_opts)
            @test server_tls_opts isa Sockets.TlsContextOptions
            if server_tls_opts isa Sockets.TlsContextOptions
                _ = Sockets.tls_ctx_options_override_default_trust_store_from_path(
                    server_tls_opts;
                    ca_file = cert_path,
                )
                Sockets.tls_ctx_options_set_verify_peer(server_tls_opts, true)
            end
            server_ctx = Sockets.tls_context_new(server_tls_opts)
            @test server_ctx isa Sockets.TlsContext

            server_ready = Ref(false)
            server_shutdown = Ref(false)

            server_bootstrap = Sockets.ServerBootstrap(Sockets.ServerBootstrapOptions(
                event_loop_group = elg,
                host = "127.0.0.1",
                port = 0,
                tls_connection_options = Sockets.TlsConnectionOptions(server_ctx),
                on_incoming_channel_setup = (bs, err, channel, ud) -> begin
                    server_ready[] = err == Reseau.OP_SUCCESS
                    return nothing
                end,
                on_incoming_channel_shutdown = (bs, err, channel, ud) -> begin
                    server_shutdown[] = true
                    return nothing
                end,
            ))
            listener = server_bootstrap.listener_socket
            @test listener !== nothing
            bound = Sockets.socket_get_bound_address(listener)
            port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
            @test port != 0

            client_opts = Sockets.TlsCtxPkcs11Options(
                pkcs11_lib = tester.lib,
                token_label = TOKEN_LABEL_RSA,
                user_pin = USER_PIN,
                private_key_object_label = DEFAULT_KEY_LABEL,
                cert_file_path = cert_path,
            )
            client_tls_opts = Sockets.tls_ctx_options_init_client_mtls_with_pkcs11(client_opts)
            @test client_tls_opts isa Sockets.TlsContextOptions
            client_ctx = Sockets.tls_context_new(client_tls_opts)
            @test client_ctx isa Sockets.TlsContext

            client_ready = Ref(false)
            client_bootstrap = Sockets.ClientBootstrap()
            client_channel = Sockets.client_bootstrap_connect!(
                client_bootstrap,
                "127.0.0.1",
                port,
                client_bootstrap.socket_options,
                Sockets.TlsConnectionOptions(client_ctx; server_name = "localhost"),
                client_bootstrap.on_protocol_negotiated,
                false,
                nothing,
                nothing,
            )
            client_ready[] = true
            Sockets.channel_shutdown!(client_channel, Reseau.OP_SUCCESS)

            wait_start = time()
            while !(client_ready[] && server_ready[] && server_shutdown[])
                if (time() - wait_start) > TIMEOUT_SEC
                    break
                end
                sleep(0.05)
            end
            @test client_ready[]
            @test server_ready[]
            @test server_shutdown[]

            Sockets.server_bootstrap_shutdown!(server_bootstrap)
            Sockets.close(resolver)
            close(elg)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end

    @testset "pkcs11 tls negotiation succeeds (ec)" begin
        tester = Pkcs11Tester("", "", nothing)
        try
            @test pkcs11_tester_init!(tester) isa Sockets.Pkcs11Lib
            slot = pkcs11_softhsm_create_slot(tester, TOKEN_LABEL_EC, SO_PIN, USER_PIN)
            Sockets.pkcs11_lib_release(tester.lib::Sockets.Pkcs11Lib)
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

            @test pkcs11_reload_hsm!(tester) isa Sockets.Pkcs11Lib

            elg = EventLoops.EventLoopGroup(; loop_count = 1)
            resolver = Sockets.HostResolver()

            server_tls_opts = Sockets.tls_ctx_options_init_default_server_from_path(cert_path, key_path)
            maybe_apply_test_keychain!(server_tls_opts)
            @test server_tls_opts isa Sockets.TlsContextOptions
            if server_tls_opts isa Sockets.TlsContextOptions
                _ = Sockets.tls_ctx_options_override_default_trust_store_from_path(
                    server_tls_opts;
                    ca_file = cert_path,
                )
                Sockets.tls_ctx_options_set_verify_peer(server_tls_opts, true)
            end
            server_ctx = Sockets.tls_context_new(server_tls_opts)
            @test server_ctx isa Sockets.TlsContext

            server_ready = Ref(false)
            server_shutdown = Ref(false)

            server_bootstrap = Sockets.ServerBootstrap(Sockets.ServerBootstrapOptions(
                event_loop_group = elg,
                host = "127.0.0.1",
                port = 0,
                tls_connection_options = Sockets.TlsConnectionOptions(server_ctx),
                on_incoming_channel_setup = (bs, err, channel, ud) -> begin
                    server_ready[] = err == Reseau.OP_SUCCESS
                    return nothing
                end,
                on_incoming_channel_shutdown = (bs, err, channel, ud) -> begin
                    server_shutdown[] = true
                    return nothing
                end,
            ))
            listener = server_bootstrap.listener_socket
            @test listener !== nothing
            bound = Sockets.socket_get_bound_address(listener)
            port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
            @test port != 0

            client_opts = Sockets.TlsCtxPkcs11Options(
                pkcs11_lib = tester.lib,
                token_label = TOKEN_LABEL_EC,
                user_pin = USER_PIN,
                private_key_object_label = DEFAULT_KEY_LABEL,
                cert_file_path = cert_path,
            )
            client_tls_opts = Sockets.tls_ctx_options_init_client_mtls_with_pkcs11(client_opts)
            @test client_tls_opts isa Sockets.TlsContextOptions
            client_ctx = Sockets.tls_context_new(client_tls_opts)
            @test client_ctx isa Sockets.TlsContext

            client_ready = Ref(false)
            client_bootstrap = Sockets.ClientBootstrap()
            client_channel = Sockets.client_bootstrap_connect!(
                client_bootstrap,
                "127.0.0.1",
                port,
                client_bootstrap.socket_options,
                Sockets.TlsConnectionOptions(client_ctx; server_name = "localhost"),
                client_bootstrap.on_protocol_negotiated,
                false,
                nothing,
                nothing,
            )
            client_ready[] = true
            Sockets.channel_shutdown!(client_channel, Reseau.OP_SUCCESS)

            wait_start = time()
            while !(client_ready[] && server_ready[] && server_shutdown[])
                if (time() - wait_start) > TIMEOUT_SEC
                    break
                end
                sleep(0.05)
            end
            @test client_ready[]
            @test server_ready[]
            @test server_shutdown[]

            Sockets.server_bootstrap_shutdown!(server_bootstrap)
            Sockets.close(resolver)
            close(elg)
        finally
            pkcs11_tester_cleanup!(tester)
        end
    end
end
