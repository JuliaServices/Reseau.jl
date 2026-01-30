# AWS IO Library - TLS Channel Handler

using LibAwsCal
using LibAwsCommon
using Libdl

const TlsOnNegotiationResultFn = Function  # (handler, slot, error_code, user_data) -> nothing
const TlsOnDataReadFn = Function           # (handler, slot, buffer, user_data) -> nothing
const TlsOnErrorFn = Function              # (handler, slot, error_code, message, user_data) -> nothing

const TLS_DEFAULT_TIMEOUT_MS = 10_000
const TLS_MAX_RECORD_SIZE = 16 * 1024
const TLS_EST_RECORD_OVERHEAD = 53
const TLS_EST_HANDSHAKE_SIZE = 7 * 1024

@enumx TlsVersion::UInt8 begin
    SSLv3 = 0
    TLSv1 = 1
    TLSv1_1 = 2
    TLSv1_2 = 3
    TLSv1_3 = 4
    TLS_VER_SYS_DEFAULTS = 128
end

@enumx TlsCipherPref::UInt16 begin
    TLS_CIPHER_PREF_SYSTEM_DEFAULT = 0
    TLS_CIPHER_PREF_KMS_PQ_TLSv1_0_2019_06 = 1
    TLS_CIPHER_PREF_KMS_PQ_SIKE_TLSv1_0_2019_11 = 2
    TLS_CIPHER_PREF_KMS_PQ_TLSv1_0_2020_02 = 3
    TLS_CIPHER_PREF_KMS_PQ_SIKE_TLSv1_0_2020_02 = 4
    TLS_CIPHER_PREF_KMS_PQ_TLSv1_0_2020_07 = 5
    TLS_CIPHER_PREF_PQ_TLSv1_0_2021_05 = 6
    TLS_CIPHER_PREF_PQ_TLSV1_2_2024_10 = 7
    TLS_CIPHER_PREF_PQ_DEFAULT = 8
    TLS_CIPHER_PREF_TLSV1_2_2025_07 = 9
    TLS_CIPHER_PREF_TLSV1_0_2023_06 = 10
    TLS_CIPHER_PREF_END_RANGE = 0xffff
end

@enumx TlsNegotiationState::UInt8 begin
    ONGOING = 0
    FAILED = 1
    SUCCEEDED = 2
end

@enumx TlsHashAlgorithm::UInt8 begin
    UNKNOWN = 0
    SHA1 = 1
    SHA224 = 2
    SHA256 = 3
    SHA384 = 4
    SHA512 = 5
end

@enumx TlsSignatureAlgorithm::UInt8 begin
    UNKNOWN = 0
    RSA = 1
    ECDSA = 2
end

@enumx TlsKeyOperationType::UInt8 begin
    UNKNOWN = 0
    SIGN = 1
    DECRYPT = 2
end

@enumx TlsHandlerReadState::UInt8 begin
    OPEN = 0
    SHUTTING_DOWN = 1
    SHUT_DOWN_COMPLETE = 2
end

mutable struct CustomKeyOpHandler{F, UD}
    on_key_operation::F
    user_data::UD
end

function CustomKeyOpHandler(on_key_operation; user_data = nothing)
    return CustomKeyOpHandler(on_key_operation, user_data)
end

custom_key_op_handler_acquire(handler::CustomKeyOpHandler) = handler
function custom_key_op_handler_release(handler::CustomKeyOpHandler)
    if handler.user_data isa Pkcs11KeyOpState
        _pkcs11_key_op_state_close!(handler.user_data)
    end
    return nothing
end
custom_key_op_handler_release(::Nothing) = nothing

function custom_key_op_handler_perform_operation(handler::CustomKeyOpHandler, operation)
    if handler.on_key_operation !== nothing
        Base.invokelatest(handler.on_key_operation, handler, operation)
    end
    return nothing
end

mutable struct TlsByoCryptoSetupOptions{NewFn, StartFn, UD}
    new_handler_fn::NewFn
    start_negotiation_fn::StartFn
    user_data::UD
end

function TlsByoCryptoSetupOptions(;
        new_handler_fn,
        start_negotiation_fn = nothing,
        user_data = nothing,
    )
    return TlsByoCryptoSetupOptions(new_handler_fn, start_negotiation_fn, user_data)
end

const _tls_byo_client_setup = Ref{Union{TlsByoCryptoSetupOptions, Nothing}}(nothing)
const _tls_byo_server_setup = Ref{Union{TlsByoCryptoSetupOptions, Nothing}}(nothing)

function _tls_byo_new_handler(
        setup::TlsByoCryptoSetupOptions,
        options,
        slot::ChannelSlot,
    )::Union{AbstractChannelHandler, ErrorResult}
    handler = setup.new_handler_fn(options, slot, setup.user_data)
    if handler isa ErrorResult
        return handler
    end
    if !(handler isa AbstractChannelHandler)
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end
    set_res = channel_slot_set_handler!(slot, handler)
    if set_res isa ErrorResult
        return set_res
    end
    return handler
end

function _tls_byo_start_negotiation(
        setup::TlsByoCryptoSetupOptions,
        handler::AbstractChannelHandler,
    )::Union{Nothing, ErrorResult}
    if setup.start_negotiation_fn === nothing
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end
    res = setup.start_negotiation_fn(handler, setup.user_data)
    if res isa ErrorResult
        return res
    end
    if res isa Integer && res != AWS_OP_SUCCESS
        raise_error(Int(res))
        return ErrorResult(Int(res))
    end
    return nothing
end

function tls_byo_crypto_set_client_setup_options(options::TlsByoCryptoSetupOptions)
    if options.new_handler_fn === nothing || options.start_negotiation_fn === nothing
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end
    _tls_byo_client_setup[] = options
    return nothing
end

function tls_byo_crypto_set_server_setup_options(options::TlsByoCryptoSetupOptions)
    if options.new_handler_fn === nothing
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end
    _tls_byo_server_setup[] = options
    return nothing
end

struct SecItemOptions
    cert_label::Union{String, Nothing}
    key_label::Union{String, Nothing}
end

struct TlsCtxPkcs11Options
    pkcs11_lib::Any
    user_pin::ByteCursor
    slot_id::Union{UInt64, Nothing}
    token_label::ByteCursor
    private_key_object_label::ByteCursor
    cert_file_path::ByteCursor
    cert_file_contents::ByteCursor
end

mutable struct Pkcs11KeyOpState
    pkcs11_lib::Any
    user_pin::ByteCursor
    slot_id::UInt64
    token_label::ByteCursor
    private_key_object_label::ByteCursor
    session_handle::CK_SESSION_HANDLE
    private_key_handle::CK_OBJECT_HANDLE
    private_key_type::CK_KEY_TYPE
    lock::ReentrantLock
    closed::Bool
end

function _pkcs11_key_op_state_close!(state::Pkcs11KeyOpState)
    state.closed && return nothing
    state.closed = true
    if state.session_handle != CK_SESSION_HANDLE(0)
        _ = pkcs11_lib_close_session(state.pkcs11_lib, state.session_handle)
    end
    pkcs11_lib_release(state.pkcs11_lib)
    state.session_handle = CK_SESSION_HANDLE(0)
    return nothing
end

function _tls_pkcs11_cursor(value)::ByteCursor
    if value === nothing
        return null_cursor()
    elseif value isa ByteCursor
        return value
    elseif value isa AbstractString || value isa AbstractVector{UInt8}
        return ByteCursor(value)
    else
        return null_cursor()
    end
end

function pkcs11_tls_op_handler_new(
        pkcs11_lib,
        user_pin::ByteCursor,
        token_label::ByteCursor,
        private_key_object_label::ByteCursor,
        slot_id::Union{UInt64, Nothing},
    )::Union{CustomKeyOpHandler, ErrorResult}
    if pkcs11_lib === nothing
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end
    if !(pkcs11_lib isa Pkcs11Lib)
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end

    lib = pkcs11_lib_acquire(pkcs11_lib)

    match_label = token_label.len > 0 ? token_label : nothing
    slot_res = pkcs11_lib_find_slot_with_token(lib, slot_id, match_label)
    if slot_res isa ErrorResult
        pkcs11_lib_release(lib)
        return slot_res
    end
    selected_slot = slot_res

    session_res = pkcs11_lib_open_session(lib, selected_slot)
    if session_res isa ErrorResult
        pkcs11_lib_release(lib)
        return session_res
    end

    pin_cursor = user_pin.len > 0 ? user_pin : nothing
    login_res = pkcs11_lib_login_user(lib, session_res, pin_cursor)
    if login_res isa ErrorResult
        _ = pkcs11_lib_close_session(lib, session_res)
        pkcs11_lib_release(lib)
        return login_res
    end

    key_label = private_key_object_label.len > 0 ? private_key_object_label : nothing
    key_res = pkcs11_lib_find_private_key(lib, session_res, key_label)
    if key_res isa ErrorResult
        _ = pkcs11_lib_close_session(lib, session_res)
        pkcs11_lib_release(lib)
        return key_res
    end
    key_handle, key_type = key_res

    state = Pkcs11KeyOpState(
        lib,
        user_pin,
        UInt64(selected_slot),
        token_label,
        private_key_object_label,
        session_res,
        key_handle,
        key_type,
        ReentrantLock(),
        false,
    )
    finalizer(state) do s
        _pkcs11_key_op_state_close!(s)
    end

    on_op = (handler, operation) -> begin
        _ = handler
        if state.closed
            tls_key_operation_complete_with_error!(operation, ERROR_INVALID_STATE)
            return
        end
        lock(state.lock) do
            op_type = tls_key_operation_get_type(operation)
            if op_type == TlsKeyOperationType.DECRYPT
                input = tls_key_operation_get_input(operation)
                res = pkcs11_lib_decrypt(
                    state.pkcs11_lib,
                    state.session_handle,
                    state.private_key_handle,
                    state.private_key_type,
                    input,
                )
                if res isa ErrorResult
                    tls_key_operation_complete_with_error!(operation, res.code)
                else
                    tls_key_operation_complete!(operation, byte_cursor_from_buf(res))
                end
            elseif op_type == TlsKeyOperationType.SIGN
                input = tls_key_operation_get_input(operation)
                digest_alg = tls_key_operation_get_digest_algorithm(operation)
                sig_alg = tls_key_operation_get_signature_algorithm(operation)
                res = pkcs11_lib_sign(
                    state.pkcs11_lib,
                    state.session_handle,
                    state.private_key_handle,
                    state.private_key_type,
                    input,
                    digest_alg,
                    sig_alg,
                )
                if res isa ErrorResult
                    tls_key_operation_complete_with_error!(operation, res.code)
                else
                    tls_key_operation_complete!(operation, byte_cursor_from_buf(res))
                end
            else
                tls_key_operation_complete_with_error!(operation, ERROR_UNIMPLEMENTED)
            end
        end
    end
    return CustomKeyOpHandler(on_op; user_data = state)
end

function TlsCtxPkcs11Options(;
        pkcs11_lib,
        user_pin = nothing,
        slot_id::Union{UInt64, Nothing} = nothing,
        token_label = nothing,
        private_key_object_label = nothing,
        cert_file_path = nothing,
        cert_file_contents = nothing,
    )
    return TlsCtxPkcs11Options(
        pkcs11_lib,
        _tls_pkcs11_cursor(user_pin),
        slot_id,
        _tls_pkcs11_cursor(token_label),
        _tls_pkcs11_cursor(private_key_object_label),
        _tls_pkcs11_cursor(cert_file_path),
        _tls_pkcs11_cursor(cert_file_contents),
    )
end

mutable struct TlsContextOptions
    is_server::Bool
    minimum_tls_version::TlsVersion.T
    cipher_pref::TlsCipherPref.T
    ca_file::ByteBuffer
    ca_file_set::Bool
    ca_path::Union{String, Nothing}
    alpn_list::Union{String, Nothing}
    certificate::ByteBuffer
    certificate_set::Bool
    private_key::ByteBuffer
    private_key_set::Bool
    system_certificate_path::Union{String, Nothing}
    pkcs12::ByteBuffer
    pkcs12_set::Bool
    pkcs12_password::ByteBuffer
    pkcs12_password_set::Bool
    secitem_options::Union{SecItemOptions, Nothing}
    keychain_path::Union{String, Nothing}
    max_fragment_size::Csize_t
    verify_peer::Bool
    ctx_options_extension::Any
    custom_key_op_handler::Union{CustomKeyOpHandler, Nothing}
end

function TlsContextOptions(;
        is_server::Bool = false,
        minimum_tls_version::TlsVersion.T = TlsVersion.TLS_VER_SYS_DEFAULTS,
        cipher_pref::TlsCipherPref.T = TlsCipherPref.TLS_CIPHER_PREF_SYSTEM_DEFAULT,
        ca_file::Union{ByteBuffer, Nothing} = nothing,
        ca_file_set::Union{Bool, Nothing} = nothing,
        ca_path::Union{String, Nothing} = nothing,
        alpn_list::Union{String, Nothing} = nothing,
        certificate::Union{ByteBuffer, Nothing} = nothing,
        certificate_set::Union{Bool, Nothing} = nothing,
        private_key::Union{ByteBuffer, Nothing} = nothing,
        private_key_set::Union{Bool, Nothing} = nothing,
        system_certificate_path::Union{String, Nothing} = nothing,
        pkcs12::Union{ByteBuffer, Nothing} = nothing,
        pkcs12_set::Union{Bool, Nothing} = nothing,
        pkcs12_password::Union{ByteBuffer, Nothing} = nothing,
        pkcs12_password_set::Union{Bool, Nothing} = nothing,
        secitem_options::Union{SecItemOptions, Nothing} = nothing,
        keychain_path::Union{String, Nothing} = nothing,
        max_fragment_size::Integer = g_aws_channel_max_fragment_size[],
        verify_peer::Union{Bool, Nothing} = nothing,
        ctx_options_extension = nothing,
        custom_key_op_handler = nothing,
    )
    verify_peer_final = verify_peer === nothing ? !is_server : verify_peer
    ca_file_set_final = ca_file_set === nothing ? (ca_file !== nothing) : ca_file_set
    certificate_set_final = certificate_set === nothing ? (certificate !== nothing) : certificate_set
    private_key_set_final = private_key_set === nothing ? (private_key !== nothing) : private_key_set
    pkcs12_set_final = pkcs12_set === nothing ? (pkcs12 !== nothing) : pkcs12_set
    pkcs12_password_set_final = pkcs12_password_set === nothing ? (pkcs12_password !== nothing) : pkcs12_password_set
    ca_file_buf = ca_file === nothing ? null_buffer() : ca_file
    certificate_buf = certificate === nothing ? null_buffer() : certificate
    private_key_buf = private_key === nothing ? null_buffer() : private_key
    pkcs12_buf = pkcs12 === nothing ? null_buffer() : pkcs12
    pkcs12_password_buf = pkcs12_password === nothing ? null_buffer() : pkcs12_password
    return TlsContextOptions(
        is_server,
        minimum_tls_version,
        cipher_pref,
        ca_file_buf,
        ca_file_set_final,
        ca_path,
        alpn_list,
        certificate_buf,
        certificate_set_final,
        private_key_buf,
        private_key_set_final,
        system_certificate_path,
        pkcs12_buf,
        pkcs12_set_final,
        pkcs12_password_buf,
        pkcs12_password_set_final,
        secitem_options,
        keychain_path,
        Csize_t(max_fragment_size),
        verify_peer_final,
        ctx_options_extension,
        custom_key_op_handler,
    )
end

mutable struct TlsContext{Impl}
    options::TlsContextOptions
    impl::Impl
    closed::Bool
end

const _tls_cal_init_lock = ReentrantLock()
const _tls_cal_initialized = Ref(false)
const _tls_use_secitem = Ref(false)

function _tls_set_use_secitem_from_env()
    @static if Sys.isapple()
        # aws-c-io enables SecItem via compile-time AWS_USE_SECITEM (typically iOS-only).
        # On macOS we default to SecureTransport and ignore runtime toggles.
        val = lowercase(get(ENV, "AWSIO_USE_SECITEM", ""))
        if !isempty(val) && (val == "1" || val == "true" || val == "yes" || val == "y" || val == "on")
            logf(
                LogLevel.WARN,
                LS_IO_TLS,
                "AWSIO_USE_SECITEM is ignored on macOS; SecItem requires AWS_USE_SECITEM at build time.",
            )
        end
        _tls_use_secitem[] = false
    else
        _tls_use_secitem[] = false
    end
    return nothing
end

function _tls_cal_init_once()
    _tls_cal_initialized[] && return nothing
    lock(_tls_cal_init_lock) do
        if !_tls_cal_initialized[]
            _cal_init()
            _tls_cal_initialized[] = true
        end
    end
    return nothing
end

function tls_init_static_state()
    _tls_cal_init_once()
    _tls_set_use_secitem_from_env()
    return _tls_backend_init()
end

function tls_clean_up_static_state()
    return _tls_backend_cleanup()
end

is_using_secitem() = _tls_use_secitem[]

@inline _tls_options_buf_is_set(is_set::Bool)::Bool = is_set

function _tls_buf_copy_from(value)::Union{ByteBuffer, ErrorResult}
    if value === nothing
        return null_buffer()
    end

    cursor = if value isa ByteBuffer
        byte_cursor_from_buf(value)
    elseif value isa ByteCursor
        value
    elseif value isa AbstractVector{UInt8}
        ByteCursor(value)
    elseif value isa AbstractString
        ByteCursor(value)
    else
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end

    dest_ref = Ref(null_buffer())
    if byte_buf_init_copy_from_cursor(dest_ref, cursor) != OP_SUCCESS
        return ErrorResult(last_error())
    end
    return dest_ref[]
end

function _tls_buf_from_file(path::AbstractString)::Union{ByteBuffer, ErrorResult}
    dest_ref = Ref(null_buffer())
    if byte_buf_init_from_file(dest_ref, path) != OP_SUCCESS
        return ErrorResult(last_error())
    end
    return dest_ref[]
end

function _tls_validate_pem(buf::ByteBuffer)::Union{Nothing, ErrorResult}
    if buf.len == 0
        raise_error(ERROR_IO_PEM_MALFORMED)
        return ErrorResult(ERROR_IO_PEM_MALFORMED)
    end
    data = Memory{UInt8}(undef, Int(buf.len))
    unsafe_copyto!(pointer(data), pointer(buf.mem), Int(buf.len))
    parsed = pem_parse(data)
    if parsed isa ErrorResult
        return ErrorResult(last_error())
    end
    return nothing
end

function tls_context_new(options::TlsContextOptions)::Union{TlsContext, ErrorResult}
    _tls_cal_init_once()
    return _tls_context_new_impl(options)
end

tls_ctx_acquire(ctx::TlsContext) = ctx
tls_ctx_acquire(::Nothing) = nothing
tls_ctx_release(ctx::TlsContext) = _tls_context_release_impl(ctx)
tls_ctx_release(::Nothing) = nothing

function _tls_ctx_options_copy(
        options::TlsContextOptions;
        is_server_override::Union{Bool, Nothing} = nothing,
    )::Union{TlsContextOptions, ErrorResult}
    ca_buf = _tls_buf_copy_from(options.ca_file)
    ca_buf isa ErrorResult && return ca_buf
    cert_buf = _tls_buf_copy_from(options.certificate)
    if cert_buf isa ErrorResult
        byte_buf_clean_up_secure(Ref(ca_buf))
        return cert_buf
    end
    key_buf = _tls_buf_copy_from(options.private_key)
    if key_buf isa ErrorResult
        byte_buf_clean_up_secure(Ref(ca_buf))
        byte_buf_clean_up_secure(Ref(cert_buf))
        return key_buf
    end
    pkcs_buf = _tls_buf_copy_from(options.pkcs12)
    if pkcs_buf isa ErrorResult
        byte_buf_clean_up_secure(Ref(ca_buf))
        byte_buf_clean_up_secure(Ref(cert_buf))
        byte_buf_clean_up_secure(Ref(key_buf))
        return pkcs_buf
    end
    pkcs_pwd_buf = _tls_buf_copy_from(options.pkcs12_password)
    if pkcs_pwd_buf isa ErrorResult
        byte_buf_clean_up_secure(Ref(ca_buf))
        byte_buf_clean_up_secure(Ref(cert_buf))
        byte_buf_clean_up_secure(Ref(key_buf))
        byte_buf_clean_up_secure(Ref(pkcs_buf))
        return pkcs_pwd_buf
    end

    secitem_copy = options.secitem_options === nothing ?
        nothing :
        SecItemOptions(options.secitem_options.cert_label, options.secitem_options.key_label)

    return TlsContextOptions(
        is_server = is_server_override === nothing ? options.is_server : is_server_override,
        minimum_tls_version = options.minimum_tls_version,
        cipher_pref = options.cipher_pref,
        ca_file = ca_buf,
        ca_file_set = options.ca_file_set,
        ca_path = options.ca_path,
        alpn_list = options.alpn_list,
        certificate = cert_buf,
        certificate_set = options.certificate_set,
        private_key = key_buf,
        private_key_set = options.private_key_set,
        system_certificate_path = options.system_certificate_path,
        pkcs12 = pkcs_buf,
        pkcs12_set = options.pkcs12_set,
        pkcs12_password = pkcs_pwd_buf,
        pkcs12_password_set = options.pkcs12_password_set,
        secitem_options = secitem_copy,
        keychain_path = options.keychain_path,
        max_fragment_size = options.max_fragment_size,
        verify_peer = options.verify_peer,
        ctx_options_extension = options.ctx_options_extension,
        custom_key_op_handler = options.custom_key_op_handler,
    )
end

function tls_client_ctx_new(options::TlsContextOptions)::Union{TlsContext, ErrorResult}
    if !tls_is_cipher_pref_supported(options.cipher_pref)
        raise_error(ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED)
        return ErrorResult(ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED)
    end
    opts_copy = _tls_ctx_options_copy(options; is_server_override = false)
    opts_copy isa ErrorResult && return opts_copy
    return tls_context_new(opts_copy)
end

function tls_server_ctx_new(options::TlsContextOptions)::Union{TlsContext, ErrorResult}
    if !tls_is_cipher_pref_supported(options.cipher_pref)
        raise_error(ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED)
        return ErrorResult(ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED)
    end
    opts_copy = _tls_ctx_options_copy(options; is_server_override = true)
    opts_copy isa ErrorResult && return opts_copy
    return tls_context_new(opts_copy)
end

function tls_hash_algorithm_str(hash::TlsHashAlgorithm.T)::String
    return hash == TlsHashAlgorithm.SHA1 ? "SHA1" :
        hash == TlsHashAlgorithm.SHA224 ? "SHA224" :
        hash == TlsHashAlgorithm.SHA256 ? "SHA256" :
        hash == TlsHashAlgorithm.SHA384 ? "SHA384" :
        hash == TlsHashAlgorithm.SHA512 ? "SHA512" :
        "UNKNOWN"
end

function tls_signature_algorithm_str(sig::TlsSignatureAlgorithm.T)::String
    return sig == TlsSignatureAlgorithm.RSA ? "RSA" :
        sig == TlsSignatureAlgorithm.ECDSA ? "ECDSA" :
        "UNKNOWN"
end

function tls_key_operation_type_str(op::TlsKeyOperationType.T)::String
    return op == TlsKeyOperationType.SIGN ? "SIGN" :
        op == TlsKeyOperationType.DECRYPT ? "DECRYPT" :
        "UNKNOWN"
end

mutable struct TlsKeyOperation{F, UD, Handler}
    input::ByteCursor
    input_buf::Union{ByteBuffer, Nothing}
    operation_type::TlsKeyOperationType.T
    signature_algorithm::TlsSignatureAlgorithm.T
    digest_algorithm::TlsHashAlgorithm.T
    on_complete::F
    user_data::UD
    completed::Bool
    error_code::Int
    output::ByteBuffer
    s2n_op::Ptr{Cvoid}
    s2n_handler::Handler
    completion_task::ChannelTask
    completion_error_code::Int
    @atomic complete_count::UInt32
end

function TlsKeyOperation(
        input::ByteCursor;
        operation_type::TlsKeyOperationType.T = TlsKeyOperationType.UNKNOWN,
        signature_algorithm::TlsSignatureAlgorithm.T = TlsSignatureAlgorithm.UNKNOWN,
        digest_algorithm::TlsHashAlgorithm.T = TlsHashAlgorithm.UNKNOWN,
        on_complete = nothing,
        user_data = nothing,
    )
    return TlsKeyOperation{typeof(on_complete), typeof(user_data), typeof(nothing)}(
        input,
        nothing,
        operation_type,
        signature_algorithm,
        digest_algorithm,
        on_complete,
        user_data,
        false,
        0,
        null_buffer(),
        C_NULL,
        nothing,
        ChannelTask(),
        0,
        UInt32(0),
    )
end

function _tls_key_operation_destroy!(operation::TlsKeyOperation)
    if operation.s2n_op != C_NULL
        lib = _s2n_lib_handle()
        if !(lib isa ErrorResult)
            _ = ccall(_s2n_symbol(:s2n_async_pkey_op_free), Cint, (Ptr{Cvoid},), operation.s2n_op)
        end
        operation.s2n_op = C_NULL
    end
    operation.s2n_handler = nothing
    operation.input_buf = nothing
    return nothing
end

function _tls_key_operation_completion_task(task::ChannelTask, operation::TlsKeyOperation, status::TaskStatus.T)
    _ = task
    if status != TaskStatus.RUN_READY
        _tls_key_operation_destroy!(operation)
        return nothing
    end

    handler = operation.s2n_handler
    if handler === nothing || !(handler isa S2nTlsHandler)
        _tls_key_operation_destroy!(operation)
        return nothing
    end

    if handler.state != TlsNegotiationState.ONGOING
        _tls_key_operation_destroy!(operation)
        return nothing
    end

    if operation.completion_error_code == 0
        lib = _s2n_lib_handle()
        if lib isa ErrorResult
            operation.completion_error_code = ERROR_INVALID_STATE
        else
            if ccall(_s2n_symbol(:s2n_async_pkey_op_apply), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), operation.s2n_op, handler.connection) !=
                    S2N_SUCCESS
                logf(LogLevel.ERROR, LS_IO_TLS, "Failed applying s2n async pkey op")
                operation.completion_error_code = ERROR_INVALID_STATE
            end
        end
    end

    if operation.completion_error_code == 0
        _ = _s2n_drive_negotiation(handler)
    else
        slot = handler.slot
        if slot !== nothing && slot.channel !== nothing
            channel_shutdown!(slot.channel, operation.completion_error_code)
        end
    end

    _tls_key_operation_destroy!(operation)
    return nothing
end

function _tls_key_operation_complete_common(
        operation::TlsKeyOperation,
        error_code::Int,
        output::Union{ByteCursor, Nothing},
    )
    new_count = @atomic operation.complete_count += UInt32(1)
    if new_count != UInt32(1)
        logf(LogLevel.ERROR, LS_IO_TLS, "TLS key operation completed multiple times.")
        return nothing
    end

    operation.output = null_buffer()
    local out_buf::Union{ByteBuffer, ErrorResult} = null_buffer()
    if output !== nothing
        out_buf = _tls_buf_copy_from(output)
        if out_buf isa ErrorResult
            error_code = out_buf.code
        end
    end

    if !(out_buf isa ErrorResult)
        operation.output = out_buf
    end

    if output !== nothing && !(out_buf isa ErrorResult) && operation.s2n_op != C_NULL
        lib = _s2n_lib_handle()
        if lib isa ErrorResult
            error_code = ERROR_INVALID_STATE
        else
            if ccall(
                    _s2n_symbol(:s2n_async_pkey_op_set_output),
                    Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
                    operation.s2n_op,
                    pointer(operation.output.mem),
                    operation.output.len,
                ) != S2N_SUCCESS
                logf(LogLevel.ERROR, LS_IO_TLS, "Failed setting output on s2n async pkey op")
                error_code = ERROR_INVALID_STATE
            end
        end
    end

    operation.completed = true
    operation.error_code = error_code
    operation.completion_error_code = error_code

    if operation.s2n_op != C_NULL && operation.s2n_handler !== nothing
        handler = operation.s2n_handler
        if handler isa S2nTlsHandler && handler.slot !== nothing && handler.slot.channel !== nothing
            channel_task_init!(
                operation.completion_task,
                _tls_key_operation_completion_task,
                operation,
                "tls_key_operation_completion_task",
            )
            channel_schedule_task_now!(handler.slot.channel, operation.completion_task)
        end
    end

    if operation.on_complete !== nothing
        operation.on_complete(operation, error_code, operation.user_data)
    end

    return nothing
end

function tls_key_operation_complete!(operation::TlsKeyOperation, output::ByteCursor)
    return _tls_key_operation_complete_common(operation, AWS_OP_SUCCESS, output)
end

function tls_key_operation_complete_with_error!(operation::TlsKeyOperation, error_code::Int)
    if error_code == 0
        error_code = ERROR_UNKNOWN
        logf(LogLevel.ERROR, LS_IO_TLS, "TLS key operation completed with error, but no error-code set.")
    end
    return _tls_key_operation_complete_common(operation, error_code, nothing)
end

tls_key_operation_get_input(operation::TlsKeyOperation) = operation.input
tls_key_operation_get_type(operation::TlsKeyOperation) = operation.operation_type
tls_key_operation_get_signature_algorithm(operation::TlsKeyOperation) = operation.signature_algorithm
tls_key_operation_get_digest_algorithm(operation::TlsKeyOperation) = operation.digest_algorithm

function tls_ctx_options_init_default_client(;
        verify_peer::Bool = true,
        ca_file::Union{ByteBuffer, Nothing} = nothing,
        ca_path::Union{String, Nothing} = nothing,
        alpn_list::Union{String, Nothing} = nothing,
        minimum_tls_version::TlsVersion.T = TlsVersion.TLS_VER_SYS_DEFAULTS,
        cipher_pref::TlsCipherPref.T = TlsCipherPref.TLS_CIPHER_PREF_SYSTEM_DEFAULT,
        max_fragment_size::Integer = g_aws_channel_max_fragment_size[],
    )
    @static if Sys.isapple()
        _tls_set_use_secitem_from_env()
    end
    secitem_options = (Sys.isapple() && is_using_secitem()) ?
        SecItemOptions("aws-crt-default-certificate-label", "aws-crt-default-key-label") : nothing
    return TlsContextOptions(;
        is_server = false,
        verify_peer = verify_peer,
        ca_file = ca_file,
        ca_path = ca_path,
        alpn_list = alpn_list,
        minimum_tls_version = minimum_tls_version,
        cipher_pref = cipher_pref,
        max_fragment_size = max_fragment_size,
        secitem_options = secitem_options,
    )
end

function tls_ctx_options_clean_up!(options::TlsContextOptions)
    byte_buf_clean_up(Ref(options.ca_file))
    byte_buf_clean_up(Ref(options.certificate))
    byte_buf_clean_up_secure(Ref(options.private_key))

    byte_buf_clean_up_secure(Ref(options.pkcs12))
    byte_buf_clean_up_secure(Ref(options.pkcs12_password))
    options.ca_file_set = false
    options.certificate_set = false
    options.private_key_set = false
    options.pkcs12_set = false
    options.pkcs12_password_set = false
    options.keychain_path = nothing
    options.secitem_options = nothing

    options.ca_path = nothing
    options.alpn_list = nothing
    options.system_certificate_path = nothing
    options.ctx_options_extension = nothing
    if options.custom_key_op_handler !== nothing
        custom_key_op_handler_release(options.custom_key_op_handler)
    end
    options.custom_key_op_handler = nothing
    return nothing
end

function tls_ctx_options_set_alpn_list!(options::TlsContextOptions, alpn_list::Union{String, Nothing})
    options.alpn_list = alpn_list
    return nothing
end

function tls_ctx_options_set_verify_peer!(options::TlsContextOptions, verify_peer::Bool)
    options.verify_peer = verify_peer
    return nothing
end

function tls_ctx_options_set_tls_cipher_preference!(options::TlsContextOptions, cipher_pref::TlsCipherPref.T)
    options.cipher_pref = cipher_pref
    return nothing
end

function tls_ctx_options_set_minimum_tls_version!(options::TlsContextOptions, minimum_tls_version::TlsVersion.T)
    options.minimum_tls_version = minimum_tls_version
    return nothing
end

function tls_ctx_options_set_max_fragment_size!(options::TlsContextOptions, max_fragment_size::Integer)
    options.max_fragment_size = Csize_t(max_fragment_size)
    return nothing
end

function tls_ctx_options_override_default_trust_store!(
        options::TlsContextOptions,
        ca_file,
    )::Union{Nothing, ErrorResult}
    if options.ca_file_set
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end
    ca_buf = _tls_buf_copy_from(ca_file)
    if ca_buf isa ErrorResult
        return ca_buf
    end
    pem_res = _tls_validate_pem(ca_buf)
    if pem_res isa ErrorResult
        byte_buf_clean_up_secure(Ref(ca_buf))
        return pem_res
    end
    options.ca_file = ca_buf
    options.ca_file_set = true
    return nothing
end

function tls_ctx_options_override_default_trust_store_from_path!(
        options::TlsContextOptions;
        ca_path::Union{String, Nothing} = nothing,
        ca_file::Union{String, Nothing} = nothing,
    )::Union{Nothing, ErrorResult}
    if ca_path !== nothing && options.ca_path !== nothing
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end
    if ca_file !== nothing && options.ca_file_set
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end

    if ca_path !== nothing
        options.ca_path = ca_path
    end

    if ca_file !== nothing
        ca_buf = _tls_buf_from_file(ca_file)
        if ca_buf isa ErrorResult
            return ca_buf
        end
        pem_res = _tls_validate_pem(ca_buf)
        if pem_res isa ErrorResult
            byte_buf_clean_up_secure(Ref(ca_buf))
            return pem_res
        end
        options.ca_file = ca_buf
        options.ca_file_set = true
    end

    return nothing
end

function tls_ctx_options_set_extension_data!(options::TlsContextOptions, extension_data)
    options.ctx_options_extension = extension_data
    return nothing
end

function tls_ctx_options_init_client_mtls(cert, pkey)::Union{TlsContextOptions, ErrorResult}
    opts = tls_ctx_options_init_default_client()

    cert_buf = _tls_buf_copy_from(cert)
    cert_buf isa ErrorResult && return cert_buf
    opts.certificate = cert_buf
    opts.certificate_set = true
    pem_res = _tls_validate_pem(cert_buf)
    if pem_res isa ErrorResult
        tls_ctx_options_clean_up!(opts)
        return pem_res
    end

    key_buf = _tls_buf_copy_from(pkey)
    if key_buf isa ErrorResult
        tls_ctx_options_clean_up!(opts)
        return key_buf
    end
    opts.private_key = key_buf
    opts.private_key_set = true
    pem_res = _tls_validate_pem(key_buf)
    if pem_res isa ErrorResult
        tls_ctx_options_clean_up!(opts)
        return pem_res
    end

    return opts
end

function tls_ctx_options_init_client_mtls_from_path(
        cert_path::AbstractString,
        pkey_path::AbstractString,
    )::Union{TlsContextOptions, ErrorResult}
    opts = tls_ctx_options_init_default_client()

    cert_buf = _tls_buf_from_file(cert_path)
    cert_buf isa ErrorResult && return cert_buf
    opts.certificate = cert_buf
    opts.certificate_set = true
    pem_res = _tls_validate_pem(cert_buf)
    if pem_res isa ErrorResult
        tls_ctx_options_clean_up!(opts)
        return pem_res
    end

    key_buf = _tls_buf_from_file(pkey_path)
    if key_buf isa ErrorResult
        tls_ctx_options_clean_up!(opts)
        return key_buf
    end
    opts.private_key = key_buf
    opts.private_key_set = true
    pem_res = _tls_validate_pem(key_buf)
    if pem_res isa ErrorResult
        tls_ctx_options_clean_up!(opts)
        return pem_res
    end

    return opts
end

function tls_ctx_options_init_client_mtls_from_system_path(
        cert_reg_path::AbstractString,
    )::Union{TlsContextOptions, ErrorResult}
    if !Sys.iswindows()
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end
    opts = tls_ctx_options_init_default_client()
    opts.system_certificate_path = cert_reg_path
    return opts
end

function tls_ctx_options_init_default_server(
        cert,
        pkey;
        alpn_list::Union{String, Nothing} = nothing,
    )::Union{TlsContextOptions, ErrorResult}
    opts = tls_ctx_options_init_client_mtls(cert, pkey)
    if opts isa ErrorResult
        return opts
    end
    opts.is_server = true
    opts.verify_peer = false
    opts.alpn_list = alpn_list
    return opts
end

function tls_ctx_options_init_default_server_from_path(
        cert_path::AbstractString,
        pkey_path::AbstractString;
        alpn_list::Union{String, Nothing} = nothing,
    )::Union{TlsContextOptions, ErrorResult}
    opts = tls_ctx_options_init_client_mtls_from_path(cert_path, pkey_path)
    if opts isa ErrorResult
        return opts
    end
    opts.is_server = true
    opts.verify_peer = false
    opts.alpn_list = alpn_list
    return opts
end

function tls_ctx_options_init_default_server_from_system_path(
        cert_reg_path::AbstractString,
    )::Union{TlsContextOptions, ErrorResult}
    opts = tls_ctx_options_init_client_mtls_from_system_path(cert_reg_path)
    if opts isa ErrorResult
        return opts
    end
    opts.is_server = true
    opts.verify_peer = false
    return opts
end

function tls_ctx_options_init_client_mtls_pkcs12_from_path(
        pkcs12_path::AbstractString,
        pkcs_password,
    )::Union{TlsContextOptions, ErrorResult}
    if !Sys.isapple()
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end
    opts = tls_ctx_options_init_default_client()
    pkcs_buf = _tls_buf_from_file(pkcs12_path)
    pkcs_buf isa ErrorResult && return pkcs_buf
    pwd_buf = _tls_buf_copy_from(pkcs_password)
    if pwd_buf isa ErrorResult
        tls_ctx_options_clean_up!(opts)
        return pwd_buf
    end
    opts.pkcs12 = pkcs_buf
    opts.pkcs12_password = pwd_buf
    opts.pkcs12_set = true
    opts.pkcs12_password_set = true
    return opts
end

function tls_ctx_options_init_client_mtls_pkcs12(
        pkcs12,
        pkcs_password,
    )::Union{TlsContextOptions, ErrorResult}
    if !Sys.isapple()
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end
    opts = tls_ctx_options_init_default_client()
    pkcs_buf = _tls_buf_copy_from(pkcs12)
    pkcs_buf isa ErrorResult && return pkcs_buf
    pwd_buf = _tls_buf_copy_from(pkcs_password)
    if pwd_buf isa ErrorResult
        tls_ctx_options_clean_up!(opts)
        return pwd_buf
    end
    opts.pkcs12 = pkcs_buf
    opts.pkcs12_password = pwd_buf
    opts.pkcs12_set = true
    opts.pkcs12_password_set = true
    return opts
end

function tls_ctx_options_init_server_pkcs12_from_path(
        pkcs12_path::AbstractString,
        pkcs_password,
    )::Union{TlsContextOptions, ErrorResult}
    opts = tls_ctx_options_init_client_mtls_pkcs12_from_path(pkcs12_path, pkcs_password)
    if opts isa ErrorResult
        return opts
    end
    opts.is_server = true
    opts.verify_peer = false
    return opts
end

function tls_ctx_options_init_server_pkcs12(
        pkcs12,
        pkcs_password,
    )::Union{TlsContextOptions, ErrorResult}
    opts = tls_ctx_options_init_client_mtls_pkcs12(pkcs12, pkcs_password)
    if opts isa ErrorResult
        return opts
    end
    opts.is_server = true
    opts.verify_peer = false
    return opts
end

function tls_ctx_options_set_keychain_path!(
        options::TlsContextOptions,
        keychain_path::AbstractString,
    )::Union{Nothing, ErrorResult}
    if !Sys.isapple()
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end
    if is_using_secitem()
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end
    options.keychain_path = keychain_path
    return nothing
end

function tls_ctx_options_set_secitem_options!(
        options::TlsContextOptions,
        secitem_options::SecItemOptions,
    )::Union{Nothing, ErrorResult}
    if !Sys.isapple()
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end
    if !is_using_secitem()
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end
    options.secitem_options = SecItemOptions(secitem_options.cert_label, secitem_options.key_label)
    return nothing
end

# Non-bang API aliases for aws-c-io parity.
tls_ctx_options_clean_up(options::TlsContextOptions) = tls_ctx_options_clean_up!(options)
tls_ctx_options_set_alpn_list(options::TlsContextOptions, alpn_list::Union{String, Nothing}) =
    tls_ctx_options_set_alpn_list!(options, alpn_list)
tls_ctx_options_set_verify_peer(options::TlsContextOptions, verify_peer::Bool) =
    tls_ctx_options_set_verify_peer!(options, verify_peer)
tls_ctx_options_set_tls_cipher_preference(options::TlsContextOptions, cipher_pref::TlsCipherPref.T) =
    tls_ctx_options_set_tls_cipher_preference!(options, cipher_pref)
tls_ctx_options_set_minimum_tls_version(options::TlsContextOptions, minimum_tls_version::TlsVersion.T) =
    tls_ctx_options_set_minimum_tls_version!(options, minimum_tls_version)
tls_ctx_options_set_max_fragment_size(options::TlsContextOptions, max_fragment_size::Integer) =
    tls_ctx_options_set_max_fragment_size!(options, max_fragment_size)
tls_ctx_options_override_default_trust_store(options::TlsContextOptions, ca_file) =
    tls_ctx_options_override_default_trust_store!(options, ca_file)
function tls_ctx_options_override_default_trust_store_from_path(
        options::TlsContextOptions;
        ca_path::Union{String, Nothing} = nothing,
        ca_file::Union{String, Nothing} = nothing,
    )
    return tls_ctx_options_override_default_trust_store_from_path!(options; ca_path = ca_path, ca_file = ca_file)
end
tls_ctx_options_set_extension_data(options::TlsContextOptions, extension_data) =
    tls_ctx_options_set_extension_data!(options, extension_data)
tls_ctx_options_set_keychain_path(options::TlsContextOptions, keychain_path::AbstractString) =
    tls_ctx_options_set_keychain_path!(options, keychain_path)
tls_ctx_options_set_secitem_options(options::TlsContextOptions, secitem_options::SecItemOptions) =
    tls_ctx_options_set_secitem_options!(options, secitem_options)
tls_secitem_options_clean_up(::SecItemOptions) = nothing

function tls_ctx_options_init_client_mtls_with_custom_key_operations(
        custom_key_op_handler,
        cert,
    )::Union{TlsContextOptions, ErrorResult}
    if custom_key_op_handler === nothing
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end
    handler = custom_key_op_handler
    if !(handler isa CustomKeyOpHandler) || handler.on_key_operation === nothing
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end

    opts = tls_ctx_options_init_default_client()
    cert_buf = _tls_buf_copy_from(cert)
    cert_buf isa ErrorResult && return cert_buf
    opts.certificate = cert_buf
    opts.certificate_set = true
    pem_res = _tls_validate_pem(cert_buf)
    if pem_res isa ErrorResult
        tls_ctx_options_clean_up!(opts)
        return pem_res
    end

    opts.custom_key_op_handler = custom_key_op_handler_acquire(handler)
    return opts
end

function tls_ctx_options_init_client_mtls_with_pkcs11(
        pkcs11_options::TlsCtxPkcs11Options,
    )::Union{TlsContextOptions, ErrorResult}
    if pkcs11_options.pkcs11_lib === nothing
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end
    if pkcs11_options.cert_file_path.len > 0 && pkcs11_options.cert_file_contents.len > 0
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end

    handler = pkcs11_tls_op_handler_new(
        pkcs11_options.pkcs11_lib,
        pkcs11_options.user_pin,
        pkcs11_options.token_label,
        pkcs11_options.private_key_object_label,
        pkcs11_options.slot_id,
    )
    handler isa ErrorResult && return handler

    if pkcs11_options.cert_file_contents.len > 0
        return tls_ctx_options_init_client_mtls_with_custom_key_operations(
            handler,
            pkcs11_options.cert_file_contents,
        )
    end

    cert_path = String(pkcs11_options.cert_file_path)
    cert_buf = _tls_buf_from_file(cert_path)
    cert_buf isa ErrorResult && return cert_buf

    cert_cursor = byte_cursor_from_buf(cert_buf)
    opts = tls_ctx_options_init_client_mtls_with_custom_key_operations(handler, cert_cursor)
    byte_buf_clean_up_secure(Ref(cert_buf))
    return opts
end

function tls_context_new_client(;
        verify_peer::Bool = true,
        ca_file::Union{String, Nothing} = nothing,
        ca_path::Union{String, Nothing} = nothing,
        alpn_list::Union{String, Nothing} = nothing,
        minimum_tls_version::TlsVersion.T = TlsVersion.TLS_VER_SYS_DEFAULTS,
        cipher_pref::TlsCipherPref.T = TlsCipherPref.TLS_CIPHER_PREF_SYSTEM_DEFAULT,
        max_fragment_size::Integer = g_aws_channel_max_fragment_size[],
    )
    opts = tls_ctx_options_init_default_client(;
        verify_peer = verify_peer,
        alpn_list = alpn_list,
        minimum_tls_version = minimum_tls_version,
        cipher_pref = cipher_pref,
        max_fragment_size = max_fragment_size,
    )
    if ca_file !== nothing || ca_path !== nothing
        res = tls_ctx_options_override_default_trust_store_from_path!(opts; ca_path = ca_path, ca_file = ca_file)
        res isa ErrorResult && return res
    end
    return tls_context_new(opts)
end

function tls_context_new_server(;
        certificate,
        private_key,
        alpn_list::Union{String, Nothing} = nothing,
        minimum_tls_version::TlsVersion.T = TlsVersion.TLS_VER_SYS_DEFAULTS,
        cipher_pref::TlsCipherPref.T = TlsCipherPref.TLS_CIPHER_PREF_SYSTEM_DEFAULT,
        max_fragment_size::Integer = g_aws_channel_max_fragment_size[],
    )
    opts = tls_ctx_options_init_default_server(
        certificate,
        private_key;
        alpn_list = alpn_list,
    )
    if opts isa ErrorResult
        return opts
    end
    opts.minimum_tls_version = minimum_tls_version
    opts.cipher_pref = cipher_pref
    opts.max_fragment_size = Csize_t(max_fragment_size)
    return tls_context_new(opts)
end

mutable struct TlsConnectionOptions <: AbstractTlsConnectionOptions
    ctx::TlsContext
    server_name::Union{String, Nothing}
    alpn_list::Union{String, Nothing}
    advertise_alpn_message::Bool
    on_negotiation_result::Union{TlsOnNegotiationResultFn, Nothing}
    on_data_read::Union{TlsOnDataReadFn, Nothing}
    on_error::Union{TlsOnErrorFn, Nothing}
    user_data::Any
    timeout_ms::UInt32
end

function TlsConnectionOptions(
        ctx::TlsContext;
        server_name::Union{String, Nothing} = nothing,
        alpn_list::Union{String, Nothing} = ctx.options.alpn_list,
        advertise_alpn_message::Bool = false,
        on_negotiation_result::Union{TlsOnNegotiationResultFn, Nothing} = nothing,
        on_data_read::Union{TlsOnDataReadFn, Nothing} = nothing,
        on_error::Union{TlsOnErrorFn, Nothing} = nothing,
        user_data = nothing,
        timeout_ms::Integer = TLS_DEFAULT_TIMEOUT_MS,
    )
    return TlsConnectionOptions(
        ctx,
        server_name,
        alpn_list,
        advertise_alpn_message,
        on_negotiation_result,
        on_data_read,
        on_error,
        user_data,
        UInt32(timeout_ms),
    )
end


tls_connection_options_clean_up!(::TlsConnectionOptions) = nothing

function tls_connection_options_copy(options::TlsConnectionOptions)
    return TlsConnectionOptions(
        options.ctx;
        server_name = options.server_name,
        alpn_list = options.alpn_list,
        advertise_alpn_message = options.advertise_alpn_message,
        on_negotiation_result = options.on_negotiation_result,
        on_data_read = options.on_data_read,
        on_error = options.on_error,
        user_data = options.user_data,
        timeout_ms = options.timeout_ms,
    )
end

function tls_connection_options_set_callbacks!(
        options::TlsConnectionOptions,
        on_negotiation_result::Union{TlsOnNegotiationResultFn, Nothing},
        on_data_read::Union{TlsOnDataReadFn, Nothing},
        on_error::Union{TlsOnErrorFn, Nothing},
        user_data = options.user_data,
    )
    options.on_negotiation_result = on_negotiation_result
    options.on_data_read = on_data_read
    options.on_error = on_error
    options.user_data = user_data
    return nothing
end

function tls_connection_options_set_server_name!(options::TlsConnectionOptions, server_name::Union{String, Nothing})
    options.server_name = server_name
    return nothing
end

function tls_connection_options_set_alpn_list!(options::TlsConnectionOptions, alpn_list::Union{String, Nothing})
    options.alpn_list = alpn_list
    return nothing
end

function tls_connection_options_set_timeout_ms!(options::TlsConnectionOptions, timeout_ms::Integer)
    options.timeout_ms = UInt32(timeout_ms)
    return nothing
end

function tls_connection_options_set_advertise_alpn_message!(options::TlsConnectionOptions, advertise::Bool)
    options.advertise_alpn_message = advertise
    return nothing
end

tls_connection_options_init_from_ctx(ctx::TlsContext) = TlsConnectionOptions(ctx)
tls_connection_options_clean_up(options::TlsConnectionOptions) = tls_connection_options_clean_up!(options)
function tls_connection_options_set_callbacks(
        options::TlsConnectionOptions,
        on_negotiation_result::Union{TlsOnNegotiationResultFn, Nothing},
        on_data_read::Union{TlsOnDataReadFn, Nothing},
        on_error::Union{TlsOnErrorFn, Nothing},
        user_data = options.user_data,
    )
    return tls_connection_options_set_callbacks!(
        options,
        on_negotiation_result,
        on_data_read,
        on_error,
        user_data,
    )
end
tls_connection_options_set_server_name(options::TlsConnectionOptions, server_name::Union{String, Nothing}) =
    tls_connection_options_set_server_name!(options, server_name)
tls_connection_options_set_alpn_list(options::TlsConnectionOptions, alpn_list::Union{String, Nothing}) =
    tls_connection_options_set_alpn_list!(options, alpn_list)
tls_connection_options_set_timeout_ms(options::TlsConnectionOptions, timeout_ms::Integer) =
    tls_connection_options_set_timeout_ms!(options, timeout_ms)
tls_connection_options_set_advertise_alpn_message(options::TlsConnectionOptions, advertise::Bool) =
    tls_connection_options_set_advertise_alpn_message!(options, advertise)

struct TlsNegotiatedProtocolMessage
    protocol::ByteBuffer
end

# TLS handler shared state (ported from tls_channel_handler_shared.c)
mutable struct TlsHandlerShared{H}
    handler::H
    tls_timeout_ms::UInt32
    stats::TlsHandlerStatistics
    timeout_task::ChannelTask
end

function _tls_timeout_task(task::ChannelTask, shared::TlsHandlerShared, status::TaskStatus.T)
    _ = task
    status == TaskStatus.RUN_READY || return nothing
    shared.stats.handshake_status == TlsNegotiationStatus.ONGOING || return nothing
    handler = shared.handler
    if handler === nothing || !(handler isa TlsChannelHandler)
        return nothing
    end
    slot = handler.slot
    slot === nothing && return nothing
    channel = slot.channel
    channel === nothing && return nothing
    channel_shutdown!(channel, ERROR_IO_TLS_NEGOTIATION_TIMEOUT)
    return nothing
end

function tls_handler_shared_init!(shared::TlsHandlerShared, handler, options::TlsConnectionOptions)
    shared.handler = handler
    shared.tls_timeout_ms = options.timeout_ms
    crt_statistics_tls_init!(shared.stats)
    channel_task_init!(shared.timeout_task, _tls_timeout_task, shared, "tls_timeout")
    return nothing
end

tls_handler_shared_clean_up!(::TlsHandlerShared) = nothing

function tls_on_drive_negotiation(shared::TlsHandlerShared)
    if shared.stats.handshake_status == TlsNegotiationStatus.NONE
        shared.stats.handshake_status = TlsNegotiationStatus.ONGOING
        handler = shared.handler
        handler === nothing && return nothing
        slot = handler.slot
        slot === nothing && return nothing
        channel = slot.channel
        channel === nothing && return nothing
        now = channel_current_clock_time(channel)
        now isa ErrorResult && return nothing
        shared.stats.handshake_start_ns = now

        if shared.tls_timeout_ms > 0
            timeout_ns = now + timestamp_convert(shared.tls_timeout_ms, TIMESTAMP_MILLIS, TIMESTAMP_NANOS, nothing)
            channel_schedule_task_future!(channel, shared.timeout_task, timeout_ns)
        end
    end
    return nothing
end

function tls_on_negotiation_completed(shared::TlsHandlerShared, error_code::Int)
    shared.stats.handshake_status =
        error_code == AWS_OP_SUCCESS ? TlsNegotiationStatus.SUCCESS : TlsNegotiationStatus.FAILURE
    handler = shared.handler
    handler === nothing && return nothing
    slot = handler.slot
    slot === nothing && return nothing
    channel = slot.channel
    channel === nothing && return nothing
    now = channel_current_clock_time(channel)
    now isa ErrorResult && return nothing
    shared.stats.handshake_end_ns = now
    return nothing
end

# TLS handler base type
abstract type TlsChannelHandler <: AbstractChannelHandler end

# Backend registration (s2n extension on Linux)
const _s2n_lib = Ref{Union{Nothing, String, Ptr{Cvoid}}}(nothing)
const _s2n_available = Ref(false)

function _register_s2n_lib!(lib)
    _s2n_lib[] = lib
    _s2n_available[] = true
    return nothing
end

@inline function _s2n_lib_handle()
    lib = _s2n_lib[]
    if lib === nothing
        return ErrorResult(raise_error(ERROR_IO_TLS_CTX_ERROR))
    end
    return lib
end

const _s2n_symbol_cache = Dict{Symbol, Ptr{Cvoid}}()
const _s2n_symbol_lock = ReentrantLock()

function _s2n_symbol(sym::Symbol)::Ptr{Cvoid}
    lib = _s2n_lib_handle()
    lib isa ErrorResult && return C_NULL
    return lock(_s2n_symbol_lock) do
        get!(_s2n_symbol_cache, sym) do
            try
                return Libdl.dlsym(lib, sym)
            catch
                return C_NULL
            end
        end
    end
end

function _tls_backend_init()
    @static if Sys.isapple()
        return _secure_transport_init()
    elseif Sys.islinux()
        return _s2n_init_once()
    else
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end
end

function _tls_backend_cleanup()
    @static if Sys.isapple()
        return _secure_transport_cleanup()
    elseif Sys.islinux()
        return _s2n_cleanup()
    else
        return nothing
    end
end

# === s2n TLS backend (Linux) ===
const S2N_SUCCESS = 0
const S2N_FAILURE = -1
const S2N_SERVER = 0
const S2N_CLIENT = 1
const S2N_NOT_BLOCKED = 0
const S2N_BLOCKED_ON_READ = 1
const S2N_BLOCKED_ON_WRITE = 2
const S2N_BLOCKED_ON_APPLICATION_INPUT = 3
const S2N_BLOCKED_ON_EARLY_DATA = 4

const S2N_ERR_T_OK = 0
const S2N_ERR_T_IO = 1
const S2N_ERR_T_BLOCKED = 2
const S2N_ERR_T_ALERT = 3
const S2N_ERR_T_PROTO = 4
const S2N_ERR_T_INTERNAL = 5
const S2N_ERR_T_USAGE = 6

const S2N_CERT_AUTH_NONE = 0
const S2N_CERT_AUTH_REQUIRED = 1
const S2N_CERT_AUTH_OPTIONAL = 2

const S2N_SELF_SERVICE_BLINDING = 1
const S2N_STATUS_REQUEST_OCSP = 1

const S2N_TLS_MAX_FRAG_LEN_512 = 1
const S2N_TLS_MAX_FRAG_LEN_1024 = 2
const S2N_TLS_MAX_FRAG_LEN_2048 = 3
const S2N_TLS_MAX_FRAG_LEN_4096 = 4

const S2N_ASYNC_SIGN = 1
const S2N_ASYNC_DECRYPT = 2

const S2N_TLS_SIGNATURE_RSA = 1
const S2N_TLS_SIGNATURE_ECDSA = 3

const S2N_TLS_HASH_SHA1 = 2
const S2N_TLS_HASH_SHA224 = 3
const S2N_TLS_HASH_SHA256 = 4
const S2N_TLS_HASH_SHA384 = 5
const S2N_TLS_HASH_SHA512 = 6

const _s2n_initialized = Ref(false)
const _s2n_initialized_externally = Ref(false)
const _s2n_init_lock = ReentrantLock()
const _s2n_default_ca_dir = Ref{Union{Nothing, String}}(nothing)
const _s2n_default_ca_file = Ref{Union{Nothing, String}}(nothing)

@inline function _s2n_errno()
    ptr = _s2n_symbol(:s2n_errno)
    ptr == C_NULL && return 0
    return unsafe_load(Ptr{Cint}(ptr))
end

@inline function _s2n_strerror(err::Int)
    fptr = _s2n_symbol(:s2n_strerror)
    fptr == C_NULL && return "<s2n unavailable>"
    return unsafe_string(ccall(fptr, Cstring, (Cint, Cstring), err, "EN"))
end

@inline function _s2n_strerror_debug(err::Int)
    fptr = _s2n_symbol(:s2n_strerror_debug)
    fptr == C_NULL && return "<s2n unavailable>"
    return unsafe_string(ccall(fptr, Cstring, (Cint, Cstring), err, "EN"))
end

@inline function _s2n_error_get_type(err::Int)::Cint
    fptr = _s2n_symbol(:s2n_error_get_type)
    fptr == C_NULL && return Cint(S2N_ERR_T_INTERNAL)
    return ccall(fptr, Cint, (Cint,), err)
end

function _s2n_init_once()
    @static if !Sys.islinux()
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end
    !_s2n_available[] && return ErrorResult(raise_error(ERROR_IO_TLS_CTX_ERROR))
    _s2n_initialized[] && return nothing
    lock(_s2n_init_lock) do
        if !_s2n_initialized[]
            lib = _s2n_lib_handle()
            if lib isa ErrorResult
                return lib
            end
            res = ccall(_s2n_symbol(:s2n_disable_atexit), Cint, ())
            if res != 0
                _s2n_initialized_externally[] = true
            else
                _s2n_initialized_externally[] = false
                if ccall(_s2n_symbol(:s2n_init), Cint, ()) != 0
                    logf(LogLevel.ERROR, LS_IO_TLS, "s2n_init failed: $(_s2n_strerror(_s2n_errno()))")
                    raise_error(ERROR_IO_TLS_CTX_ERROR)
                    return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
                end
            end
            _s2n_default_ca_dir[] = determine_default_pki_dir()
            _s2n_default_ca_file[] = determine_default_pki_ca_file()
            _s2n_initialized[] = true
        end
    end
    return nothing
end

function _s2n_cleanup()
    @static if Sys.islinux()
        if _s2n_initialized[] && !_s2n_initialized_externally[]
            lib = _s2n_lib_handle()
            if !(lib isa ErrorResult)
                _ = ccall(_s2n_symbol(:s2n_cleanup_final), Cint, ())
            end
        end
    end
    return nothing
end

function _s2n_cleanup_thread()
    @static if Sys.islinux()
        lib = _s2n_lib_handle()
        if !(lib isa ErrorResult)
            _ = ccall(_s2n_symbol(:s2n_cleanup_thread), Cint, ())
        end
    end
    return nothing
end

function _s2n_wall_clock_time_nanoseconds(context::Ptr{Cvoid}, time_in_ns::Ptr{UInt64})::Cint
    _ = context
    if sys_clock_get_ticks(time_in_ns) != OP_SUCCESS
        unsafe_store!(time_in_ns, UInt64(0))
        return Cint(-1)
    end
    return Cint(0)
end

function _s2n_monotonic_clock_time_nanoseconds(context::Ptr{Cvoid}, time_in_ns::Ptr{UInt64})::Cint
    _ = context
    if high_res_clock_get_ticks(time_in_ns) != OP_SUCCESS
        unsafe_store!(time_in_ns, UInt64(0))
        return Cint(-1)
    end
    return Cint(0)
end

const _s2n_wall_clock_time_nanoseconds_c =
    @cfunction(_s2n_wall_clock_time_nanoseconds, Cint, (Ptr{Cvoid}, Ptr{UInt64}))
const _s2n_monotonic_clock_time_nanoseconds_c =
    @cfunction(_s2n_monotonic_clock_time_nanoseconds, Cint, (Ptr{Cvoid}, Ptr{UInt64}))

const _s2n_tls_cleanup_key = Ref{UInt8}(0)
const _s2n_tls_cleanup_key_ptr = pointer_from_objref(_s2n_tls_cleanup_key)

function _s2n_schedule_thread_cleanup(slot::ChannelSlot)
    channel = slot.channel
    channel === nothing && return ErrorResult(raise_error(ERROR_INVALID_STATE))
    existing = channel_fetch_local_object(channel, _s2n_tls_cleanup_key_ptr)
    if existing isa ErrorResult
        reset_error()
        local_obj = EventLoopLocalObject(_s2n_tls_cleanup_key_ptr, nothing)
        put_res = channel_put_local_object!(channel, local_obj)
        put_res isa ErrorResult && return put_res
        _ = thread_current_at_exit(_s2n_cleanup_thread)
    end
    return nothing
end

mutable struct S2nTlsCtx
    config::Ptr{Cvoid}
    custom_cert_chain_and_key::Ptr{Cvoid}
    custom_key_handler::Union{CustomKeyOpHandler, Nothing}
end

S2nTlsCtx() = S2nTlsCtx(C_NULL, C_NULL, nothing)

mutable struct S2nTlsHandler{SlotRef <: Union{ChannelSlot, Nothing}} <: TlsChannelHandler
    slot::SlotRef
    shared::TlsHandlerShared{Any}
    connection::Ptr{Cvoid}
    ctx::Union{TlsContext, Nothing}
    s2n_ctx::Union{S2nTlsCtx, Nothing}
    input_queue::Deque{IoMessage}
    protocol::ByteBuffer
    server_name::ByteBuffer
    latest_message_on_completion::Any
    latest_message_completion_user_data::Any
    on_negotiation_result::Union{TlsOnNegotiationResultFn, Nothing}
    on_data_read::Union{TlsOnDataReadFn, Nothing}
    on_error::Union{TlsOnErrorFn, Nothing}
    user_data::Any
    advertise_alpn_message::Bool
    state::TlsNegotiationState.T
    read_task::ChannelTask
    read_task_pending::Bool
    read_state::TlsHandlerReadState.T
    shutdown_error_code::Int
    delayed_shutdown_task::ChannelTask
    negotiation_task::ChannelTask
end

function _byte_buf_from_c_str(ptr::Ptr{Cchar})::ByteBuffer
    ptr == C_NULL && return null_buffer()
    len = ccall(:strlen, Csize_t, (Cstring,), ptr)
    if len == 0
        return null_buffer()
    end
    buf = ByteBuffer(Int(len))
    unsafe_copyto!(pointer(buf.mem), Ptr{UInt8}(ptr), Int(len))
    setfield!(buf, :len, len)
    return buf
end

function _byte_buf_from_string(value::AbstractString)::ByteBuffer
    bytes = codeunits(value)
    if isempty(bytes)
        return null_buffer()
    end
    buf = ByteBuffer(length(bytes))
    copyto!(buf.mem, 1, bytes, 1, length(bytes))
    setfield!(buf, :len, Csize_t(length(bytes)))
    return buf
end

function _s2n_generic_read(handler::S2nTlsHandler, buf_ptr::Ptr{UInt8}, len::UInt32)::Cint
    written = 0
    queue = handler.input_queue
    while !linked_list_empty(queue) && written < len
        message = linked_list_pop_front(queue)
        message === nothing && break
        msg = message::IoMessage
        remaining_message_len = Int(msg.message_data.len) - Int(msg.copy_mark)
        remaining_buf_len = Int(len) - written
        to_write = remaining_message_len < remaining_buf_len ? remaining_message_len : remaining_buf_len

        if to_write > 0
            src_ptr = pointer(msg.message_data.mem) + Int(msg.copy_mark)
            unsafe_copyto!(buf_ptr + written, src_ptr, to_write)
            written += to_write
            msg.copy_mark += Csize_t(to_write)
        end

        if msg.copy_mark == msg.message_data.len
            if msg.owning_channel isa Channel
                channel_release_message_to_pool!(msg.owning_channel, msg)
            end
        else
            linked_list_push_front(queue, msg)
        end
    end

    if written > 0
        return Cint(written)
    end

    Base.Libc.errno(Base.Libc.EAGAIN)
    return Cint(-1)
end

function _s2n_generic_send(handler::S2nTlsHandler, buf_ptr::Ptr{UInt8}, len::UInt32)::Cint
    channel = handler.slot === nothing ? nothing : handler.slot.channel
    channel === nothing && return Cint(-1)
    processed = 0

    while processed < len
        overhead = channel_slot_upstream_message_overhead(handler.slot)
        message_size_hint = Csize_t(len - processed) + overhead
        message = channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, message_size_hint)
        message === nothing && return Cint(-1)

        if message.message_data.capacity <= overhead
            channel_release_message_to_pool!(channel, message)
            Base.Libc.errno(Base.Libc.ENOMEM)
            return Cint(-1)
        end

        available = Int(message.message_data.capacity - overhead)
        to_write = min(available, Int(len) - processed)

        mem = unsafe_wrap(Memory{UInt8}, buf_ptr + processed, to_write; own = false)
        chunk = ByteCursor(mem, to_write)
        buf_ref = Ref(message.message_data)
        if byte_buf_append(buf_ref, chunk) != AWS_OP_SUCCESS
            channel_release_message_to_pool!(channel, message)
            return Cint(-1)
        end
        message.message_data = buf_ref[]
        processed += Int(message.message_data.len)

        if processed == len
            message.on_completion = handler.latest_message_on_completion
            message.user_data = handler.latest_message_completion_user_data
            handler.latest_message_on_completion = nothing
            handler.latest_message_completion_user_data = nothing
        end

        send_res = channel_slot_send_message(handler.slot, message, ChannelDirection.WRITE)
        if send_res isa ErrorResult
            channel_release_message_to_pool!(channel, message)
            Base.Libc.errno(Base.Libc.EPIPE)
            return Cint(-1)
        end
    end

    if processed > 0
        return Cint(processed)
    end

    Base.Libc.errno(Base.Libc.EAGAIN)
    return Cint(-1)
end

function _s2n_handler_recv(io_context::Ptr{Cvoid}, buf::Ptr{UInt8}, len::UInt32)::Cint
    handler = unsafe_pointer_to_objref(io_context)::S2nTlsHandler
    return _s2n_generic_read(handler, buf, len)
end

function _s2n_handler_send(io_context::Ptr{Cvoid}, buf::Ptr{UInt8}, len::UInt32)::Cint
    handler = unsafe_pointer_to_objref(io_context)::S2nTlsHandler
    return _s2n_generic_send(handler, buf, len)
end

const _s2n_handler_recv_c = @cfunction(_s2n_handler_recv, Cint, (Ptr{Cvoid}, Ptr{UInt8}, UInt32))
const _s2n_handler_send_c = @cfunction(_s2n_handler_send, Cint, (Ptr{Cvoid}, Ptr{UInt8}, UInt32))

function _s2n_on_negotiation_result(handler::S2nTlsHandler, slot::ChannelSlot, error_code::Int)
    tls_on_negotiation_completed(handler.shared, error_code)
    if handler.on_negotiation_result !== nothing
        Base.invokelatest(handler.on_negotiation_result, handler, slot, error_code, handler.user_data)
    end
    return nothing
end

function _s2n_send_alpn_message(handler::S2nTlsHandler)
    slot = handler.slot
    slot === nothing && return nothing
    slot.adj_right === nothing && return nothing
    handler.advertise_alpn_message || return nothing
    handler.protocol.len == 0 && return nothing
    channel = slot.channel
    channel === nothing && return nothing

    message = channel_acquire_message_from_pool(
        channel,
        IoMessageType.APPLICATION_DATA,
        sizeof(TlsNegotiatedProtocolMessage),
    )
    message === nothing && return nothing
    message.message_tag = TLS_NEGOTIATED_PROTOCOL_MESSAGE
    message.user_data = TlsNegotiatedProtocolMessage(handler.protocol)
    setfield!(message.message_data, :len, Csize_t(sizeof(TlsNegotiatedProtocolMessage)))
    send_res = channel_slot_send_message(slot, message, ChannelDirection.READ)
    if send_res isa ErrorResult
        channel_release_message_to_pool!(channel, message)
        channel_shutdown!(channel, send_res.code)
    end
    return nothing
end

function _s2n_drive_negotiation(handler::S2nTlsHandler)
    handler.state == TlsNegotiationState.ONGOING || return nothing
    tls_on_drive_negotiation(handler.shared)

    lib = _s2n_lib_handle()
    lib isa ErrorResult && return lib

    blocked = Ref{Cint}(S2N_NOT_BLOCKED)
    while true
        negotiation_code = ccall(_s2n_symbol(:s2n_negotiate), Cint, (Ptr{Cvoid}, Ptr{Cint}), handler.connection, blocked)
        s2n_error = _s2n_errno()

        if negotiation_code == S2N_SUCCESS
            handler.state = TlsNegotiationState.SUCCEEDED
            protocol_ptr = ccall(_s2n_symbol(:s2n_get_application_protocol), Ptr{Cchar}, (Ptr{Cvoid},), handler.connection)
            if protocol_ptr != C_NULL
                handler.protocol = _byte_buf_from_c_str(protocol_ptr)
            end
            server_name_ptr = ccall(_s2n_symbol(:s2n_get_server_name), Ptr{Cchar}, (Ptr{Cvoid},), handler.connection)
            if server_name_ptr != C_NULL
                handler.server_name = _byte_buf_from_c_str(server_name_ptr)
            end
            _s2n_send_alpn_message(handler)
            _s2n_on_negotiation_result(handler, handler.slot, AWS_OP_SUCCESS)
            return nothing
        end

        if _s2n_error_get_type(s2n_error) != S2N_ERR_T_BLOCKED
            if _s2n_error_get_type(s2n_error) == S2N_ERR_T_ALERT
                alert_code = ccall(_s2n_symbol(:s2n_connection_get_alert), Cint, (Ptr{Cvoid},), handler.connection)
                logf(LogLevel.DEBUG, LS_IO_TLS, "s2n alert code $alert_code")
            end
            logf(
                LogLevel.WARN,
                LS_IO_TLS,
                "s2n negotiate failed: $(_s2n_strerror(s2n_error)) ($(_s2n_strerror_debug(s2n_error)))",
            )
            handler.state = TlsNegotiationState.FAILED
            _s2n_on_negotiation_result(handler, handler.slot, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
            raise_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
            return ErrorResult(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
        end

        if blocked[] != S2N_NOT_BLOCKED
            return nothing
        end
    end
end

function _s2n_negotiation_task(task::ChannelTask, handler::S2nTlsHandler, status::TaskStatus.T)
    _ = task
    status == TaskStatus.RUN_READY || return nothing
    handler.state == TlsNegotiationState.ONGOING || return nothing
    _s2n_drive_negotiation(handler)
    return nothing
end

function _s2n_delayed_shutdown_task(task::ChannelTask, handler::S2nTlsHandler, status::TaskStatus.T)
    _ = task
    lib = _s2n_lib_handle()
    if status == TaskStatus.RUN_READY && !(lib isa ErrorResult)
        blocked = Ref{Cint}(S2N_NOT_BLOCKED)
        _ = ccall(_s2n_symbol(:s2n_shutdown), Cint, (Ptr{Cvoid}, Ptr{Cint}), handler.connection, blocked)
    end
    slot = handler.slot
    slot === nothing && return nothing
    channel_slot_on_handler_shutdown_complete!(
        slot,
        ChannelDirection.WRITE,
        handler.shutdown_error_code,
        false,
    )
    return nothing
end

function _s2n_read_task(task::ChannelTask, handler::S2nTlsHandler, status::TaskStatus.T)
    _ = task
    status == TaskStatus.RUN_READY || return nothing
    handler.read_task_pending = false
    if handler.slot !== nothing
        handler_process_read_message(handler, handler.slot, nothing)
    end
    return nothing
end

function _s2n_initialize_read_delay_shutdown(handler::S2nTlsHandler, slot::ChannelSlot, error_code::Int)
    logf(
        LogLevel.DEBUG,
        LS_IO_TLS,
        "TLS handler pending data during shutdown, waiting for downstream read window.",
    )
    if channel_slot_downstream_read_window(slot) == 0
        logf(
            LogLevel.WARN,
            LS_IO_TLS,
            "TLS shutdown delayed; pending data cannot be processed until read window opens.",
        )
    end
    handler.read_state = TlsHandlerReadState.SHUTTING_DOWN
    handler.shutdown_error_code = error_code
    if !handler.read_task_pending
        handler.read_task_pending = true
        channel_task_init!(handler.read_task, _s2n_read_task, handler, "s2n_read_on_delay_shutdown")
        channel_schedule_task_now!(slot.channel, handler.read_task)
    end
    return nothing
end

function _s2n_do_delayed_shutdown(handler::S2nTlsHandler, slot::ChannelSlot, error_code::Int)
    handler.shutdown_error_code = error_code
    lib = _s2n_lib_handle()
    lib isa ErrorResult && return lib
    delay = ccall(_s2n_symbol(:s2n_connection_get_delay), UInt64, (Ptr{Cvoid},), handler.connection)
    now = channel_current_clock_time(slot.channel)
    now isa ErrorResult && return now
    channel_schedule_task_future!(slot.channel, handler.delayed_shutdown_task, now + delay)
    return nothing
end

function _parse_alpn_list(alpn_list::String)::Union{Vector{String}, ErrorResult}
    parts = split(alpn_list, ';'; keepempty = false)
    isempty(parts) && return ErrorResult(raise_error(ERROR_IO_TLS_CTX_ERROR))
    if length(parts) > 4
        parts = parts[1:4]
    end
    return parts
end

function _s2n_set_protocol_preferences_config(config::Ptr{Cvoid}, alpn_list::String)::Union{Nothing, ErrorResult}
    protocols = _parse_alpn_list(alpn_list)
    protocols isa ErrorResult && return protocols
    lib = _s2n_lib_handle()
    lib isa ErrorResult && return lib

    count = length(protocols)
    ptrs = Memory{Ptr{UInt8}}(undef, count)
    buffers = Vector{Memory{UInt8}}(undef, count)
    for (i, proto) in enumerate(protocols)
        bytes = codeunits(proto)
        mem = Memory{UInt8}(undef, length(bytes) + 1)
        if !isempty(bytes)
            copyto!(mem, 1, bytes, 1, length(bytes))
        end
        mem[length(bytes) + 1] = 0x00
        buffers[i] = mem
        ptrs[i] = pointer(mem)
    end

    res = GC.@preserve buffers ptrs begin
        ccall(
            _s2n_symbol(:s2n_config_set_protocol_preferences),
            Cint,
            (Ptr{Cvoid}, Ptr{Ptr{UInt8}}, Cint),
            config,
            pointer(ptrs),
            Cint(count),
        )
    end

    if res != S2N_SUCCESS
        raise_error(ERROR_IO_TLS_CTX_ERROR)
        return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
    end
    return nothing
end

function _s2n_set_protocol_preferences_connection(conn::Ptr{Cvoid}, alpn_list::String)::Union{Nothing, ErrorResult}
    protocols = _parse_alpn_list(alpn_list)
    protocols isa ErrorResult && return protocols
    lib = _s2n_lib_handle()
    lib isa ErrorResult && return lib

    count = length(protocols)
    ptrs = Memory{Ptr{UInt8}}(undef, count)
    buffers = Vector{Memory{UInt8}}(undef, count)
    for (i, proto) in enumerate(protocols)
        bytes = codeunits(proto)
        mem = Memory{UInt8}(undef, length(bytes) + 1)
        if !isempty(bytes)
            copyto!(mem, 1, bytes, 1, length(bytes))
        end
        mem[length(bytes) + 1] = 0x00
        buffers[i] = mem
        ptrs[i] = pointer(mem)
    end

    res = GC.@preserve buffers ptrs begin
        ccall(
            _s2n_symbol(:s2n_connection_set_protocol_preferences),
            Cint,
            (Ptr{Cvoid}, Ptr{Ptr{UInt8}}, Cint),
            conn,
            pointer(ptrs),
            Cint(count),
        )
    end

    if res != S2N_SUCCESS
        raise_error(ERROR_IO_TLS_CTX_ERROR)
        return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
    end
    return nothing
end

# S2N handler interface implementations
function handler_initial_window_size(handler::S2nTlsHandler)::Csize_t
    _ = handler
    return Csize_t(TLS_EST_HANDSHAKE_SIZE)
end

function handler_message_overhead(handler::S2nTlsHandler)::Csize_t
    _ = handler
    return Csize_t(TLS_EST_RECORD_OVERHEAD)
end

function handler_destroy(handler::S2nTlsHandler)::Nothing
    tls_handler_shared_clean_up!(handler.shared)
    while !linked_list_empty(handler.input_queue)
        msg = linked_list_pop_front(handler.input_queue)
        if msg isa IoMessage && msg.owning_channel isa Channel
            channel_release_message_to_pool!(msg.owning_channel, msg)
        end
    end
    if handler.connection != C_NULL
        lib = _s2n_lib_handle()
        if !(lib isa ErrorResult)
            _ = ccall(_s2n_symbol(:s2n_connection_free), Cint, (Ptr{Cvoid},), handler.connection)
        end
        handler.connection = C_NULL
    end
    handler.protocol = null_buffer()
    handler.server_name = null_buffer()
    handler.slot = nothing
    return nothing
end

function handler_reset_statistics(handler::S2nTlsHandler)::Nothing
    crt_statistics_tls_reset!(handler.shared.stats)
    return nothing
end

function handler_gather_statistics(handler::S2nTlsHandler)
    return handler.shared.stats
end

function handler_process_read_message(
        handler::S2nTlsHandler,
        slot::ChannelSlot,
        message::Union{IoMessage, Nothing},
    )::Union{Nothing, ErrorResult}
    if handler.read_state == TlsHandlerReadState.SHUT_DOWN_COMPLETE
        message !== nothing && message.owning_channel isa Channel && channel_release_message_to_pool!(message.owning_channel, message)
        return nothing
    end

    if handler.state == TlsNegotiationState.FAILED
        raise_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
        return ErrorResult(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
    end

    if message !== nothing
        linked_list_push_back(handler.input_queue, message)

        if handler.state == TlsNegotiationState.ONGOING
            message_len = message.message_data.len
            res = _s2n_drive_negotiation(handler)
            if res isa ErrorResult
                channel_shutdown!(slot.channel, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
            else
                channel_slot_increment_read_window!(slot, message_len)
            end
            return nothing
        end
    end

    lib = _s2n_lib_handle()
    lib isa ErrorResult && return lib

    if slot.adj_right === nothing
        downstream_window = SIZE_MAX
    else
        downstream_window = channel_slot_downstream_read_window(slot)
    end
    processed = Csize_t(0)
    shutdown_error_code = 0
    force_shutdown = false

    while processed < downstream_window
        outgoing = channel_acquire_message_from_pool(
            slot.channel,
            IoMessageType.APPLICATION_DATA,
            downstream_window - processed,
        )
        outgoing === nothing && break

        blocked = Ref{Cint}(S2N_NOT_BLOCKED)
        read_val = ccall(
            _s2n_symbol(:s2n_recv),
            Int,
            (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{Cint}),
            handler.connection,
            pointer(outgoing.message_data.mem),
            outgoing.message_data.capacity,
            blocked,
        )

        if read_val == 0
            channel_release_message_to_pool!(slot.channel, outgoing)
            force_shutdown = true
            break
        end

        if read_val < 0
            channel_release_message_to_pool!(slot.channel, outgoing)
            err_type = _s2n_error_get_type(_s2n_errno())
            if err_type == S2N_ERR_T_BLOCKED
                if handler.read_state == TlsHandlerReadState.SHUTTING_DOWN
                    break
                end
                break
            end
            logf(
                LogLevel.ERROR,
                LS_IO_TLS,
                "s2n recv failed: $(_s2n_strerror(_s2n_errno())) ($(_s2n_strerror_debug(_s2n_errno())))",
            )
            shutdown_error_code = ERROR_IO_TLS_ERROR_READ_FAILURE
            break
        end

        processed += Csize_t(read_val)
        setfield!(outgoing.message_data, :len, Csize_t(read_val))

        if handler.on_data_read !== nothing
            Base.invokelatest(handler.on_data_read, handler, slot, outgoing.message_data, handler.user_data)
        end

        if slot.adj_right !== nothing
            send_res = channel_slot_send_message(slot, outgoing, ChannelDirection.READ)
            if send_res isa ErrorResult
                channel_release_message_to_pool!(slot.channel, outgoing)
                shutdown_error_code = send_res.code
                break
            end
        else
            channel_release_message_to_pool!(slot.channel, outgoing)
        end
    end

    if force_shutdown || shutdown_error_code != 0 ||
            (handler.read_state == TlsHandlerReadState.SHUTTING_DOWN && processed < downstream_window)
        if handler.read_state == TlsHandlerReadState.SHUTTING_DOWN
            if handler.shutdown_error_code != 0
                shutdown_error_code = handler.shutdown_error_code
            end
            handler.read_state = TlsHandlerReadState.SHUT_DOWN_COMPLETE
            channel_slot_on_handler_shutdown_complete!(
                slot,
                ChannelDirection.READ,
                shutdown_error_code,
                false,
            )
        else
            channel_shutdown!(slot.channel, shutdown_error_code)
        end
    end

    return nothing
end

function handler_process_read_message(handler::S2nTlsHandler, slot::ChannelSlot, message::IoMessage)
    return invoke(
        handler_process_read_message,
        Tuple{S2nTlsHandler, ChannelSlot, Union{IoMessage, Nothing}},
        handler,
        slot,
        message,
    )
end

function handler_process_write_message(
        handler::S2nTlsHandler,
        slot::ChannelSlot,
        message::IoMessage,
    )::Union{Nothing, ErrorResult}
    _ = slot
    if handler.state != TlsNegotiationState.SUCCEEDED
        raise_error(ERROR_IO_TLS_ERROR_NOT_NEGOTIATED)
        return ErrorResult(ERROR_IO_TLS_ERROR_NOT_NEGOTIATED)
    end

    handler.latest_message_on_completion = message.on_completion
    handler.latest_message_completion_user_data = message.user_data

    lib = _s2n_lib_handle()
    lib isa ErrorResult && return lib
    blocked = Ref{Cint}(S2N_NOT_BLOCKED)
    write_val = ccall(
        _s2n_symbol(:s2n_send),
        Int,
        (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{Cint}),
        handler.connection,
        pointer(message.message_data.mem),
        message.message_data.len,
        blocked,
    )

    if write_val < Int(message.message_data.len)
        raise_error(ERROR_IO_TLS_ERROR_WRITE_FAILURE)
        return ErrorResult(ERROR_IO_TLS_ERROR_WRITE_FAILURE)
    end

    channel_release_message_to_pool!(slot.channel, message)
    return nothing
end

function handler_shutdown(
        handler::S2nTlsHandler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Union{Nothing, ErrorResult}
    abort_immediately = free_scarce_resources_immediately

    if direction == ChannelDirection.READ
        if handler.state == TlsNegotiationState.ONGOING
            handler.state = TlsNegotiationState.FAILED
        end
        if !abort_immediately &&
                handler.state == TlsNegotiationState.SUCCEEDED &&
                !linked_list_empty(handler.input_queue) &&
                slot.adj_right !== nothing
            _s2n_initialize_read_delay_shutdown(handler, slot, error_code)
            return nothing
        end
        handler.read_state = TlsHandlerReadState.SHUT_DOWN_COMPLETE
    else
        if !abort_immediately && error_code != ERROR_IO_SOCKET_CLOSED
            _s2n_do_delayed_shutdown(handler, slot, error_code)
            return nothing
        end
    end

    while !linked_list_empty(handler.input_queue)
        msg = linked_list_pop_front(handler.input_queue)
        if msg isa IoMessage && msg.owning_channel isa Channel
            channel_release_message_to_pool!(msg.owning_channel, msg)
        end
    end
    channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, abort_immediately)
    return nothing
end

function handler_increment_read_window(
        handler::S2nTlsHandler,
        slot::ChannelSlot,
        size::Csize_t,
    )::Union{Nothing, ErrorResult}
    _ = size
    if handler.read_state == TlsHandlerReadState.SHUT_DOWN_COMPLETE
        return nothing
    end

    downstream_size = channel_slot_downstream_read_window(slot)
    current_window = slot.window_size
    record_size = Csize_t(TLS_MAX_RECORD_SIZE)
    likely_records = downstream_size == 0 ? Csize_t(0) : Csize_t(ceil(downstream_size / record_size))
    offset_size = mul_size_saturating(likely_records, Csize_t(TLS_EST_RECORD_OVERHEAD))
    total_desired = add_size_saturating(offset_size, downstream_size)

    if total_desired > current_window
        update_size = total_desired - current_window
        channel_slot_increment_read_window!(slot, update_size)
    end

    if handler.state == TlsNegotiationState.SUCCEEDED && !handler.read_task_pending
        handler.read_task_pending = true
        channel_task_init!(handler.read_task, _s2n_read_task, handler, "s2n_read_on_window_increment")
        channel_schedule_task_now!(slot.channel, handler.read_task)
    end

    return nothing
end

function _s2n_to_tls_signature_algorithm(s2n_alg::Cint)::TlsSignatureAlgorithm.T
    return s2n_alg == S2N_TLS_SIGNATURE_RSA ? TlsSignatureAlgorithm.RSA :
        s2n_alg == S2N_TLS_SIGNATURE_ECDSA ? TlsSignatureAlgorithm.ECDSA :
        TlsSignatureAlgorithm.UNKNOWN
end

function _s2n_to_tls_hash_algorithm(s2n_alg::Cint)::TlsHashAlgorithm.T
    return s2n_alg == S2N_TLS_HASH_SHA1 ? TlsHashAlgorithm.SHA1 :
        s2n_alg == S2N_TLS_HASH_SHA224 ? TlsHashAlgorithm.SHA224 :
        s2n_alg == S2N_TLS_HASH_SHA256 ? TlsHashAlgorithm.SHA256 :
        s2n_alg == S2N_TLS_HASH_SHA384 ? TlsHashAlgorithm.SHA384 :
        s2n_alg == S2N_TLS_HASH_SHA512 ? TlsHashAlgorithm.SHA512 :
        TlsHashAlgorithm.UNKNOWN
end

function _s2n_tls_key_operation_new(
        handler::S2nTlsHandler,
        s2n_op::Ptr{Cvoid},
    )::Union{TlsKeyOperation, ErrorResult}
    lib = _s2n_lib_handle()
    lib isa ErrorResult && return lib

    input_size = Ref{UInt32}(0)
    if ccall(_s2n_symbol(:s2n_async_pkey_op_get_input_size), Cint, (Ptr{Cvoid}, Ref{UInt32}), s2n_op, input_size) !=
            S2N_SUCCESS
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end

    input_buf = ByteBuffer(Int(input_size[]))
    if input_size[] > 0
        if ccall(
                _s2n_symbol(:s2n_async_pkey_op_get_input),
                Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, UInt32),
                s2n_op,
                pointer(input_buf.mem),
                input_size[],
            ) != S2N_SUCCESS
            raise_error(ERROR_INVALID_STATE)
            return ErrorResult(ERROR_INVALID_STATE)
        end
        setfield!(input_buf, :len, Csize_t(input_size[]))
    end

    op_type = Ref{Cint}(0)
    if ccall(_s2n_symbol(:s2n_async_pkey_op_get_op_type), Cint, (Ptr{Cvoid}, Ref{Cint}), s2n_op, op_type) != S2N_SUCCESS
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end

    operation_type = TlsKeyOperationType.UNKNOWN
    signature_algorithm = TlsSignatureAlgorithm.UNKNOWN
    digest_algorithm = TlsHashAlgorithm.UNKNOWN

    if op_type[] == S2N_ASYNC_SIGN
        operation_type = TlsKeyOperationType.SIGN
        sig_alg = Ref{Cint}(0)
        if ccall(
                _s2n_symbol(:s2n_connection_get_selected_client_cert_signature_algorithm),
                Cint,
                (Ptr{Cvoid}, Ref{Cint}),
                handler.connection,
                sig_alg,
            ) != S2N_SUCCESS
            raise_error(ERROR_INVALID_STATE)
            return ErrorResult(ERROR_INVALID_STATE)
        end
        signature_algorithm = _s2n_to_tls_signature_algorithm(sig_alg[])
        if signature_algorithm == TlsSignatureAlgorithm.UNKNOWN
            raise_error(ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED)
            return ErrorResult(ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED)
        end

        hash_alg = Ref{Cint}(0)
        if ccall(
                _s2n_symbol(:s2n_connection_get_selected_client_cert_digest_algorithm),
                Cint,
                (Ptr{Cvoid}, Ref{Cint}),
                handler.connection,
                hash_alg,
            ) != S2N_SUCCESS
            raise_error(ERROR_INVALID_STATE)
            return ErrorResult(ERROR_INVALID_STATE)
        end
        digest_algorithm = _s2n_to_tls_hash_algorithm(hash_alg[])
        if digest_algorithm == TlsHashAlgorithm.UNKNOWN
            raise_error(ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED)
            return ErrorResult(ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED)
        end
    elseif op_type[] == S2N_ASYNC_DECRYPT
        operation_type = TlsKeyOperationType.DECRYPT
    else
        raise_error(ERROR_INVALID_STATE)
        return ErrorResult(ERROR_INVALID_STATE)
    end

    operation = TlsKeyOperation(
        byte_cursor_from_buf(input_buf);
        operation_type = operation_type,
        signature_algorithm = signature_algorithm,
        digest_algorithm = digest_algorithm,
    )
    operation.input_buf = input_buf
    operation.s2n_op = s2n_op
    operation.s2n_handler = handler
    operation.complete_count = UInt32(0)

    return operation
end

function _s2n_async_pkey_callback(conn::Ptr{Cvoid}, s2n_op::Ptr{Cvoid})::Cint
    lib = _s2n_lib_handle()
    lib isa ErrorResult && return Cint(S2N_FAILURE)
    handler_ptr = ccall(_s2n_symbol(:s2n_connection_get_ctx), Ptr{Cvoid}, (Ptr{Cvoid},), conn)
    handler_ptr == C_NULL && return Cint(S2N_FAILURE)
    handler = unsafe_pointer_to_objref(handler_ptr)::S2nTlsHandler

    operation = _s2n_tls_key_operation_new(handler, s2n_op)
    if operation isa ErrorResult
        _ = ccall(_s2n_symbol(:s2n_async_pkey_op_free), Cint, (Ptr{Cvoid},), s2n_op)
        return Cint(S2N_FAILURE)
    end

    logf(
        LogLevel.DEBUG,
        LS_IO_TLS,
        "Begin TLS key operation. type=$(tls_key_operation_type_str(operation.operation_type)) input_len=$(operation.input.len) signature=$(tls_signature_algorithm_str(operation.signature_algorithm)) digest=$(tls_hash_algorithm_str(operation.digest_algorithm))",
    )

    if handler.s2n_ctx !== nothing && handler.s2n_ctx.custom_key_handler !== nothing
        custom_key_op_handler_perform_operation(handler.s2n_ctx.custom_key_handler, operation)
    end

    return Cint(S2N_SUCCESS)
end

const _s2n_async_pkey_callback_c = @cfunction(_s2n_async_pkey_callback, Cint, (Ptr{Cvoid}, Ptr{Cvoid}))

function _s2n_ctx_destroy!(ctx::S2nTlsCtx)
    lib = _s2n_lib_handle()
    lib isa ErrorResult && return nothing
    if ctx.config != C_NULL
        _ = ccall(_s2n_symbol(:s2n_config_free), Cint, (Ptr{Cvoid},), ctx.config)
        ctx.config = C_NULL
    end
    if ctx.custom_cert_chain_and_key != C_NULL
        _ = ccall(_s2n_symbol(:s2n_cert_chain_and_key_free), Cint, (Ptr{Cvoid},), ctx.custom_cert_chain_and_key)
        ctx.custom_cert_chain_and_key = C_NULL
    end
    if ctx.custom_key_handler !== nothing
        custom_key_op_handler_release(ctx.custom_key_handler)
        ctx.custom_key_handler = nothing
    end
    return nothing
end

function _s2n_security_policy(options::TlsContextOptions)::Union{String, ErrorResult}
    if options.custom_key_op_handler !== nothing
        return options.minimum_tls_version == TlsVersion.SSLv3 ? "CloudFront-SSL-v-3" :
            options.minimum_tls_version == TlsVersion.TLSv1 ? "CloudFront-TLS-1-0-2014" :
            options.minimum_tls_version == TlsVersion.TLSv1_1 ? "ELBSecurityPolicy-TLS-1-1-2017-01" :
            options.minimum_tls_version == TlsVersion.TLSv1_2 ? "ELBSecurityPolicy-TLS-1-2-Ext-2018-06" :
            options.minimum_tls_version == TlsVersion.TLSv1_3 ? begin
                logf(LogLevel.ERROR, LS_IO_TLS, "TLS 1.3 with PKCS#11 is not supported yet.")
                ErrorResult(raise_error(ERROR_IO_TLS_VERSION_UNSUPPORTED))
            end :
                "ELBSecurityPolicy-TLS-1-1-2017-01"
    end

    return options.minimum_tls_version == TlsVersion.SSLv3 ? "AWS-CRT-SDK-SSLv3.0-2023" :
        options.minimum_tls_version == TlsVersion.TLSv1 ? "AWS-CRT-SDK-TLSv1.0-2023" :
        options.minimum_tls_version == TlsVersion.TLSv1_1 ? "AWS-CRT-SDK-TLSv1.1-2023" :
        options.minimum_tls_version == TlsVersion.TLSv1_2 ? "AWS-CRT-SDK-TLSv1.2-2025-PQ" :
        options.minimum_tls_version == TlsVersion.TLSv1_3 ? "AWS-CRT-SDK-TLSv1.3-2025-PQ" :
        "AWS-CRT-SDK-TLSv1.0-2025-PQ"
end

function _s2n_context_new(options::TlsContextOptions)::Union{TlsContext, ErrorResult}
    io_fatal_assert_library_initialized()
    init_res = _s2n_init_once()
    init_res isa ErrorResult && return init_res

    lib = _s2n_lib_handle()
    lib isa ErrorResult && return lib

    ctx_impl = S2nTlsCtx()
    ctx_impl.config = ccall(_s2n_symbol(:s2n_config_new), Ptr{Cvoid}, ())
    if ctx_impl.config == C_NULL
        raise_error(ERROR_IO_TLS_CTX_ERROR)
        return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
    end

    if ccall(
            _s2n_symbol(:s2n_config_set_wall_clock),
            Cint,
            (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            ctx_impl.config,
            _s2n_wall_clock_time_nanoseconds_c,
            C_NULL,
        ) != S2N_SUCCESS
        logf(LogLevel.ERROR, LS_IO_TLS, "s2n: failed to set wall clock callback")
        _s2n_ctx_destroy!(ctx_impl)
        raise_error(ERROR_IO_TLS_CTX_ERROR)
        return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
    end

    if ccall(
            _s2n_symbol(:s2n_config_set_monotonic_clock),
            Cint,
            (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            ctx_impl.config,
            _s2n_monotonic_clock_time_nanoseconds_c,
            C_NULL,
        ) != S2N_SUCCESS
        logf(LogLevel.ERROR, LS_IO_TLS, "s2n: failed to set monotonic clock callback")
        _s2n_ctx_destroy!(ctx_impl)
        raise_error(ERROR_IO_TLS_CTX_ERROR)
        return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
    end

    policy = _s2n_security_policy(options)
    policy isa ErrorResult && return policy

    if options.cipher_pref == TlsCipherPref.TLS_CIPHER_PREF_PQ_DEFAULT
        policy = "AWS-CRT-SDK-TLSv1.2-2025-PQ"
    elseif options.cipher_pref == TlsCipherPref.TLS_CIPHER_PREF_PQ_TLSV1_2_2024_10
        policy = "AWS-CRT-SDK-TLSv1.2-2023-PQ"
    elseif options.cipher_pref == TlsCipherPref.TLS_CIPHER_PREF_TLSV1_2_2025_07
        policy = "AWS-CRT-SDK-TLSv1.2-2025"
    elseif options.cipher_pref == TlsCipherPref.TLS_CIPHER_PREF_TLSV1_0_2023_06
        policy = "AWS-CRT-SDK-TLSv1.0-2023"
    elseif options.cipher_pref != TlsCipherPref.TLS_CIPHER_PREF_SYSTEM_DEFAULT
        _s2n_ctx_destroy!(ctx_impl)
        raise_error(ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED)
        return ErrorResult(ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED)
    end

    if ccall(_s2n_symbol(:s2n_config_set_cipher_preferences), Cint, (Ptr{Cvoid}, Cstring), ctx_impl.config, policy) !=
            S2N_SUCCESS
        logf(
            LogLevel.ERROR,
            LS_IO_TLS,
            "s2n: failed to set security policy '$policy': $(_s2n_strerror(_s2n_errno()))",
        )
        _s2n_ctx_destroy!(ctx_impl)
        raise_error(ERROR_IO_TLS_CTX_ERROR)
        return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
    end

    if options.certificate_set && options.private_key_set
        cert_cur = byte_cursor_from_buf(options.certificate)
        key_cur = byte_cursor_from_buf(options.private_key)
        if !text_is_utf8(cert_cur) || !text_is_utf8(key_cur)
            _s2n_ctx_destroy!(ctx_impl)
            raise_error(ERROR_IO_FILE_VALIDATION_FAILURE)
            return ErrorResult(ERROR_IO_FILE_VALIDATION_FAILURE)
        end
        cert_str = String(cert_cur)
        key_str = String(key_cur)
        if ccall(_s2n_symbol(:s2n_config_add_cert_chain_and_key), Cint, (Ptr{Cvoid}, Cstring, Cstring), ctx_impl.config, cert_str, key_str) !=
                S2N_SUCCESS
            _s2n_ctx_destroy!(ctx_impl)
            raise_error(ERROR_IO_TLS_CTX_ERROR)
            return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
        end
        if !options.is_server
            _ = ccall(_s2n_symbol(:s2n_config_set_client_auth_type), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, S2N_CERT_AUTH_REQUIRED)
        end
    elseif options.custom_key_op_handler !== nothing
        ctx_impl.custom_key_handler = custom_key_op_handler_acquire(options.custom_key_op_handler)
        if ccall(_s2n_symbol(:s2n_config_set_async_pkey_callback), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), ctx_impl.config, _s2n_async_pkey_callback_c) !=
                S2N_SUCCESS
            _s2n_ctx_destroy!(ctx_impl)
            raise_error(ERROR_IO_TLS_CTX_ERROR)
            return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
        end

        ctx_impl.custom_cert_chain_and_key = ccall(_s2n_symbol(:s2n_cert_chain_and_key_new), Ptr{Cvoid}, ())
        if ctx_impl.custom_cert_chain_and_key == C_NULL
            _s2n_ctx_destroy!(ctx_impl)
            raise_error(ERROR_IO_TLS_CTX_ERROR)
            return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
        end

        cert_ptr = pointer(options.certificate.mem)
        cert_len = options.certificate.len
        if ccall(_s2n_symbol(:s2n_cert_chain_and_key_load_public_pem_bytes), Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
                ctx_impl.custom_cert_chain_and_key,
                cert_ptr,
                cert_len) != S2N_SUCCESS
            _s2n_ctx_destroy!(ctx_impl)
            raise_error(ERROR_IO_TLS_CTX_ERROR)
            return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
        end

        if ccall(_s2n_symbol(:s2n_config_add_cert_chain_and_key_to_store), Cint, (Ptr{Cvoid}, Ptr{Cvoid}),
                ctx_impl.config, ctx_impl.custom_cert_chain_and_key) != S2N_SUCCESS
            _s2n_ctx_destroy!(ctx_impl)
            raise_error(ERROR_IO_TLS_CTX_ERROR)
            return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
        end

        if !options.is_server
            _ = ccall(_s2n_symbol(:s2n_config_set_client_auth_type), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, S2N_CERT_AUTH_REQUIRED)
        end
    end

    if options.verify_peer
        if ccall(_s2n_symbol(:s2n_config_set_check_stapled_ocsp_response), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, 1) == S2N_SUCCESS
            if ccall(_s2n_symbol(:s2n_config_set_status_request_type), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, S2N_STATUS_REQUEST_OCSP) !=
                    S2N_SUCCESS
                _s2n_ctx_destroy!(ctx_impl)
                raise_error(ERROR_IO_TLS_CTX_ERROR)
                return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
            end
        end

        if options.ca_path !== nothing || options.ca_file_set
            if ccall(_s2n_symbol(:s2n_config_wipe_trust_store), Cint, (Ptr{Cvoid},), ctx_impl.config) != S2N_SUCCESS
                _s2n_ctx_destroy!(ctx_impl)
                raise_error(ERROR_IO_TLS_CTX_ERROR)
                return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
            end
            if options.ca_path !== nothing
                if ccall(_s2n_symbol(:s2n_config_set_verification_ca_location), Cint,
                        (Ptr{Cvoid}, Cstring, Cstring),
                        ctx_impl.config,
                        C_NULL,
                        options.ca_path) != S2N_SUCCESS
                    _s2n_ctx_destroy!(ctx_impl)
                    raise_error(ERROR_IO_TLS_CTX_ERROR)
                    return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
                end
            end
            if options.ca_file_set
                ca_str = String(byte_cursor_from_buf(options.ca_file))
                if ccall(_s2n_symbol(:s2n_config_add_pem_to_trust_store), Cint, (Ptr{Cvoid}, Cstring), ctx_impl.config, ca_str) !=
                        S2N_SUCCESS
                    _s2n_ctx_destroy!(ctx_impl)
                    raise_error(ERROR_IO_TLS_CTX_ERROR)
                    return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
                end
            end
        elseif _s2n_default_ca_file[] !== nothing || _s2n_default_ca_dir[] !== nothing
            ca_file = _s2n_default_ca_file[] === nothing ? C_NULL : _s2n_default_ca_file[]
            ca_dir = _s2n_default_ca_dir[] === nothing ? C_NULL : _s2n_default_ca_dir[]
            if ccall(_s2n_symbol(:s2n_config_set_verification_ca_location), Cint,
                    (Ptr{Cvoid}, Cstring, Cstring),
                    ctx_impl.config,
                    ca_file,
                    ca_dir) != S2N_SUCCESS
                _s2n_ctx_destroy!(ctx_impl)
                raise_error(ERROR_IO_TLS_CTX_ERROR)
                return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
            end
        else
            _s2n_ctx_destroy!(ctx_impl)
            raise_error(ERROR_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND)
            return ErrorResult(ERROR_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND)
        end

        if options.is_server
            if ccall(_s2n_symbol(:s2n_config_set_client_auth_type), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, S2N_CERT_AUTH_REQUIRED) !=
                    S2N_SUCCESS
                _s2n_ctx_destroy!(ctx_impl)
                raise_error(ERROR_IO_TLS_CTX_ERROR)
                return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
            end
        end
    elseif !options.is_server
        _ = ccall(_s2n_symbol(:s2n_config_disable_x509_verification), Cint, (Ptr{Cvoid},), ctx_impl.config)
    end

    if options.alpn_list !== nothing
        alpn_res = _s2n_set_protocol_preferences_config(ctx_impl.config, options.alpn_list)
        alpn_res isa ErrorResult && return alpn_res
    end

    if options.max_fragment_size == 512
        _ = ccall(_s2n_symbol(:s2n_config_send_max_fragment_length), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, S2N_TLS_MAX_FRAG_LEN_512)
    elseif options.max_fragment_size == 1024
        _ = ccall(_s2n_symbol(:s2n_config_send_max_fragment_length), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, S2N_TLS_MAX_FRAG_LEN_1024)
    elseif options.max_fragment_size == 2048
        _ = ccall(_s2n_symbol(:s2n_config_send_max_fragment_length), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, S2N_TLS_MAX_FRAG_LEN_2048)
    elseif options.max_fragment_size == 4096
        _ = ccall(_s2n_symbol(:s2n_config_send_max_fragment_length), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, S2N_TLS_MAX_FRAG_LEN_4096)
    end

    ctx = TlsContext(options, ctx_impl, false)
    finalizer(ctx) do c
        c.closed && return
        c.closed = true
        if c.impl isa S2nTlsCtx
            _s2n_ctx_destroy!(c.impl)
        end
    end
    return ctx
end

function _s2n_handler_new(
        options::TlsConnectionOptions,
        slot::ChannelSlot,
        mode::Cint,
    )::Union{S2nTlsHandler, ErrorResult}
    lib = _s2n_lib_handle()
    lib isa ErrorResult && return lib

    ctx = options.ctx
    if ctx.impl isa ErrorResult
        return ctx.impl
    end
    s2n_ctx = ctx.impl isa S2nTlsCtx ? ctx.impl : nothing
    s2n_ctx === nothing && return ErrorResult(raise_error(ERROR_IO_TLS_CTX_ERROR))

    shared = TlsHandlerShared{Any}(nothing, UInt32(0), TlsHandlerStatistics(), ChannelTask())
    handler = S2nTlsHandler{Union{ChannelSlot, Nothing}}(
        slot,
        shared,
        C_NULL,
        ctx,
        s2n_ctx,
        linked_list_init(IoMessage),
        null_buffer(),
        null_buffer(),
        nothing,
        nothing,
        options.on_negotiation_result,
        options.on_data_read,
        options.on_error,
        options.user_data,
        options.advertise_alpn_message,
        TlsNegotiationState.ONGOING,
        ChannelTask(),
        false,
        TlsHandlerReadState.OPEN,
        0,
        ChannelTask(),
        ChannelTask(),
    )

    tls_handler_shared_init!(handler.shared, handler, options)

    handler.connection = ccall(_s2n_symbol(:s2n_connection_new), Ptr{Cvoid}, (Cint,), mode)
    handler.connection == C_NULL && return ErrorResult(raise_error(ERROR_IO_TLS_CTX_ERROR))

    if options.server_name !== nothing
        if ccall(_s2n_symbol(:s2n_set_server_name), Cint, (Ptr{Cvoid}, Cstring), handler.connection, options.server_name) !=
                S2N_SUCCESS
            raise_error(ERROR_IO_TLS_CTX_ERROR)
            return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
        end
    end

    _ = ccall(_s2n_symbol(:s2n_connection_set_recv_cb), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), handler.connection, _s2n_handler_recv_c)
    _ = ccall(_s2n_symbol(:s2n_connection_set_recv_ctx), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), handler.connection, pointer_from_objref(handler))
    _ = ccall(_s2n_symbol(:s2n_connection_set_send_cb), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), handler.connection, _s2n_handler_send_c)
    _ = ccall(_s2n_symbol(:s2n_connection_set_send_ctx), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), handler.connection, pointer_from_objref(handler))
    _ = ccall(_s2n_symbol(:s2n_connection_set_ctx), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), handler.connection, pointer_from_objref(handler))
    _ = ccall(_s2n_symbol(:s2n_connection_set_blinding), Cint, (Ptr{Cvoid}, Cint), handler.connection, S2N_SELF_SERVICE_BLINDING)

    if options.alpn_list !== nothing
        alpn_res = _s2n_set_protocol_preferences_connection(handler.connection, options.alpn_list)
        alpn_res isa ErrorResult && return alpn_res
    end

    if ccall(_s2n_symbol(:s2n_connection_set_config), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), handler.connection, s2n_ctx.config) !=
            S2N_SUCCESS
        raise_error(ERROR_IO_TLS_CTX_ERROR)
        return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
    end

    channel_task_init!(handler.delayed_shutdown_task, _s2n_delayed_shutdown_task, handler, "s2n_delayed_shutdown")
    _ = _s2n_schedule_thread_cleanup(slot)
    return handler
end

# === SecureTransport backend (macOS) ===
const CFTypeRef = Ptr{Cvoid}
const CFAllocatorRef = Ptr{Cvoid}
const CFStringRef = Ptr{Cvoid}
const CFDataRef = Ptr{Cvoid}
const CFArrayRef = Ptr{Cvoid}
const CFMutableArrayRef = Ptr{Cvoid}
const CFDictionaryRef = Ptr{Cvoid}
const CFMutableDictionaryRef = Ptr{Cvoid}
const SecKeychainRef = Ptr{Cvoid}
const SecCertificateRef = Ptr{Cvoid}
const SecIdentityRef = Ptr{Cvoid}
const SecTrustRef = Ptr{Cvoid}
const SecPolicyRef = Ptr{Cvoid}
const SSLContextRef = Ptr{Cvoid}
const SSLConnectionRef = Ptr{Cvoid}

const OSStatus = Int32
const SSLProtocolSide = Cint
const SSLConnectionType = Cint

const _SECURITY_LIB = "/System/Library/Frameworks/Security.framework/Security"
const _COREFOUNDATION_LIB = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

const _ssl_set_alpn_protocols = Ref{Ptr{Cvoid}}(C_NULL)
const _ssl_copy_alpn_protocols = Ref{Ptr{Cvoid}}(C_NULL)
const _secure_transport_security_handle = Ref{Any}(nothing)
const _secure_transport_handler_registry = IdDict{Any, Nothing}()

const _kCFStringEncodingASCII = UInt32(0x0600)
const _kCFStringEncodingUTF8 = UInt32(0x08000100)

const _kSSLProtocolUnknown = Cint(0)
const _kSSLProtocol3 = Cint(2)
const _kTLSProtocol1 = Cint(4)
const _kTLSProtocol11 = Cint(7)
const _kTLSProtocol12 = Cint(8)
const _kTLSProtocol13 = Cint(10)

const _kSSLServerSide = Cint(0)
const _kSSLClientSide = Cint(1)
const _kSSLStreamType = Cint(0)

const _kSSLSessionOptionBreakOnServerAuth = Cint(0)
const _kSSLSessionOptionBreakOnClientAuth = Cint(2)

const _errSSLWouldBlock = OSStatus(-9803)
const _errSSLClosedGraceful = OSStatus(-9805)
const _errSSLPeerAuthCompleted = OSStatus(-9841)
const _errSSLClosedNoNotify = OSStatus(-9816)
const _errSecBufferTooSmall = OSStatus(-25301)
const _errSecMemoryError = OSStatus(-67672)
const _errSecSuccess = OSStatus(0)
const _errSecDuplicateItem = OSStatus(-25299)
const _errSecUnsupportedFormat = OSStatus(-25256)
const _errSecUnknownFormat = OSStatus(-25257)

const _kSecTrustResultProceed = Cint(1)
const _kSecTrustResultUnspecified = Cint(4)

const _kSecFormatUnknown = UInt32(0)
const _kSecFormatOpenSSL = UInt32(1)
const _kSecFormatWrappedPKCS8 = UInt32(5)
const _kSecFormatX509Cert = UInt32(9)
const _kSecItemTypePrivateKey = UInt32(1)
const _kSecItemTypeCertificate = UInt32(4)

@static if Sys.isapple()
    const _kCFTypeArrayCallBacks = cglobal((:kCFTypeArrayCallBacks, _COREFOUNDATION_LIB), Cvoid)
    const _kSecImportExportPassphrase = unsafe_load(cglobal((:kSecImportExportPassphrase, _SECURITY_LIB), Ptr{Cvoid}))
    const _kSecImportItemIdentity = unsafe_load(cglobal((:kSecImportItemIdentity, _SECURITY_LIB), Ptr{Cvoid}))
else
    const _kCFTypeArrayCallBacks = C_NULL
    const _kSecImportExportPassphrase = C_NULL
    const _kSecImportItemIdentity = C_NULL
end

struct CFRange
    location::Clong
    length::Clong
end

mutable struct SecureTransportCtx
    minimum_tls_version::TlsVersion.T
    alpn_list::Union{String, Nothing}
    verify_peer::Bool
    ca_cert::Ptr{Cvoid}
    certs::Ptr{Cvoid}
    secitem_identity::Ptr{Cvoid}
end

mutable struct SecureTransportTlsHandler{SlotRef <: Union{ChannelSlot, Nothing}} <: TlsChannelHandler
    slot::SlotRef
    shared::TlsHandlerShared{Any}
    ctx::SSLContextRef
    ctx_obj::Union{TlsContext, Nothing}
    input_queue::Deque{IoMessage}
    protocol::ByteBuffer
    server_name::ByteBuffer
    latest_message_on_completion::Any
    latest_message_completion_user_data::Any
    ca_certs::CFArrayRef
    on_negotiation_result::Union{TlsOnNegotiationResultFn, Nothing}
    on_data_read::Union{TlsOnDataReadFn, Nothing}
    on_error::Union{TlsOnErrorFn, Nothing}
    user_data::Any
    advertise_alpn_message::Bool
    negotiation_finished::Bool
    verify_peer::Bool
    read_task::ChannelTask
    read_task_pending::Bool
    read_state::TlsHandlerReadState.T
    delay_shutdown_error_code::Int
    negotiation_task::ChannelTask
end

@inline function _cf_release(obj::Ptr{Cvoid})
    @static if Sys.isapple()
        obj == C_NULL && return nothing
        ccall((:CFRelease, _COREFOUNDATION_LIB), Cvoid, (Ptr{Cvoid},), obj)
    end
    return nothing
end

@inline function _cf_retain(obj::Ptr{Cvoid})
    @static if Sys.isapple()
        obj == C_NULL && return nothing
        ccall((:CFRetain, _COREFOUNDATION_LIB), Cvoid, (Ptr{Cvoid},), obj)
    end
    return nothing
end

@inline function _cf_data_create(bytes::Ptr{UInt8}, len::Csize_t)::CFDataRef
    @static if Sys.isapple()
        return ccall((:CFDataCreate, _COREFOUNDATION_LIB), CFDataRef, (CFAllocatorRef, Ptr{UInt8}, Csize_t), C_NULL, bytes, len)
    else
        return C_NULL
    end
end

@inline function _cf_string_create(bytes::Ptr{UInt8}, len::Csize_t, encoding::UInt32)::CFStringRef
    @static if Sys.isapple()
        return ccall(
            (:CFStringCreateWithBytes, _COREFOUNDATION_LIB),
            CFStringRef,
            (CFAllocatorRef, Ptr{UInt8}, Csize_t, UInt32, UInt8),
            C_NULL,
            bytes,
            len,
            encoding,
            0,
        )
    else
        return C_NULL
    end
end

function _cf_string_from_cursor(cursor::ByteCursor, encoding::UInt32)
    if cursor.len == 0
        return _cf_string_create(C_NULL, 0, encoding)
    end
    return GC.@preserve cursor _cf_string_create(_cursor_ptr(cursor), cursor.len, encoding)
end

function _cf_string_to_bytebuffer(str::CFStringRef)::ByteBuffer
    @static if !Sys.isapple()
        return null_buffer()
    end
    str == C_NULL && return null_buffer()
    len = ccall((:CFStringGetLength, _COREFOUNDATION_LIB), Clong, (CFStringRef,), str)
    if len == 0
        return null_buffer()
    end
    max_size = ccall(
        (:CFStringGetMaximumSizeForEncoding, _COREFOUNDATION_LIB),
        Clong,
        (Clong, UInt32),
        len,
        _kCFStringEncodingASCII,
    )
    buf = ByteBuffer(Int(max_size + 1))
    ok = ccall(
        (:CFStringGetCString, _COREFOUNDATION_LIB),
        UInt8,
        (CFStringRef, Ptr{UInt8}, Clong, UInt32),
        str,
        pointer(buf.mem),
        max_size + 1,
        _kCFStringEncodingASCII,
    )
    if ok == 0
        return null_buffer()
    end
    actual = ccall(:strlen, Csize_t, (Cstring,), pointer(buf.mem))
    setfield!(buf, :len, actual)
    return buf
end

function _secure_transport_init()
    @static if !Sys.isapple()
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    handle = _secure_transport_security_handle[]
    if handle === nothing
        handle = Libdl.dlopen(_SECURITY_LIB)
        _secure_transport_security_handle[] = handle
    end
    _ssl_set_alpn_protocols[] = Libdl.dlsym(handle, :SSLSetALPNProtocols; throw_error = false)
    _ssl_copy_alpn_protocols[] = Libdl.dlsym(handle, :SSLCopyALPNProtocols; throw_error = false)
    _secure_transport_init_callbacks()

    if is_using_secitem()
        logf(LogLevel.INFO, LS_IO_TLS, "static: initializing TLS implementation as Apple SecItem.")
    else
        logf(LogLevel.INFO, LS_IO_TLS, "static: initializing TLS implementation as Apple SecureTransport.")
    end

    if _ssl_set_alpn_protocols[] != C_NULL
        logf(LogLevel.INFO, LS_IO_TLS, "static: ALPN support detected.")
    else
        logf(LogLevel.WARN, LS_IO_TLS, "static: ALPN isn't supported on this apple device.")
    end
    return nothing
end

function _secure_transport_cleanup()
    return nothing
end

function _secure_transport_set_protocols(handler::SecureTransportTlsHandler, alpn_list::String)
    @static if !Sys.isapple()
        return nothing
    end
    _ssl_set_alpn_protocols[] == C_NULL && return nothing

    protocols = split(alpn_list, ';'; keepempty = false)
    isempty(protocols) && return nothing

    alpn_array = ccall(
        (:CFArrayCreateMutable, _COREFOUNDATION_LIB),
        CFMutableArrayRef,
        (CFAllocatorRef, Clong, Ptr{Cvoid}),
        C_NULL,
        length(protocols),
        _kCFTypeArrayCallBacks,
    )
    alpn_array == C_NULL && return nothing

    for proto in protocols
        proto_cursor = ByteCursor(proto)
        str_ref = GC.@preserve proto_cursor _cf_string_create(_cursor_ptr(proto_cursor), proto_cursor.len, _kCFStringEncodingASCII)
        if str_ref == C_NULL
            _cf_release(alpn_array)
            return nothing
        end
        ccall((:CFArrayAppendValue, _COREFOUNDATION_LIB), Cvoid, (CFMutableArrayRef, Ptr{Cvoid}), alpn_array, str_ref)
        _cf_release(str_ref)
    end

    _ = ccall(
        _ssl_set_alpn_protocols[],
        OSStatus,
        (SSLContextRef, CFArrayRef),
        handler.ctx,
        alpn_array,
    )

    _cf_release(alpn_array)
    return nothing
end

function _secure_transport_get_protocol(handler::SecureTransportTlsHandler)::ByteBuffer
    @static if !Sys.isapple()
        return null_buffer()
    end
    _ssl_copy_alpn_protocols[] == C_NULL && return null_buffer()

    protocols_ref = Ref{CFArrayRef}(C_NULL)
    status = ccall(
        _ssl_copy_alpn_protocols[],
        OSStatus,
        (SSLContextRef, Ref{CFArrayRef}),
        handler.ctx,
        protocols_ref,
    )
    status != _errSecSuccess && return null_buffer()
    protocols_ref[] == C_NULL && return null_buffer()

    count = ccall((:CFArrayGetCount, _COREFOUNDATION_LIB), Clong, (CFArrayRef,), protocols_ref[])
    if count <= 0
        _cf_release(protocols_ref[])
        return null_buffer()
    end

    protocol_ref = ccall(
        (:CFArrayGetValueAtIndex, _COREFOUNDATION_LIB),
        CFTypeRef,
        (CFArrayRef, Clong),
        protocols_ref[],
        0,
    )
    _cf_retain(protocol_ref)
    _cf_release(protocols_ref[])
    buf = _cf_string_to_bytebuffer(protocol_ref)
    _cf_release(protocol_ref)
    return buf
end

function _secure_transport_on_negotiation_result(handler::SecureTransportTlsHandler, error_code::Int)
    tls_on_negotiation_completed(handler.shared, error_code)
    if handler.on_negotiation_result !== nothing && handler.slot !== nothing
        Base.invokelatest(handler.on_negotiation_result, handler, handler.slot, error_code, handler.user_data)
    end
    return nothing
end

function _secure_transport_send_alpn_message(handler::SecureTransportTlsHandler)
    slot = handler.slot
    slot === nothing && return nothing
    slot.adj_right === nothing && return nothing
    handler.advertise_alpn_message || return nothing
    handler.protocol.len == 0 && return nothing
    channel = slot.channel
    channel === nothing && return nothing

    message = channel_acquire_message_from_pool(
        channel,
        IoMessageType.APPLICATION_DATA,
        sizeof(TlsNegotiatedProtocolMessage),
    )
    message === nothing && return nothing
    message.message_tag = TLS_NEGOTIATED_PROTOCOL_MESSAGE
    message.user_data = TlsNegotiatedProtocolMessage(handler.protocol)
    setfield!(message.message_data, :len, Csize_t(sizeof(TlsNegotiatedProtocolMessage)))
    send_res = channel_slot_send_message(slot, message, ChannelDirection.READ)
    if send_res isa ErrorResult
        channel_release_message_to_pool!(channel, message)
        channel_shutdown!(channel, send_res.code)
    end
    return nothing
end

function _secure_transport_drive_negotiation(handler::SecureTransportTlsHandler)
    @static if !Sys.isapple()
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    tls_on_drive_negotiation(handler.shared)

    status = ccall((:SSLHandshake, _SECURITY_LIB), OSStatus, (SSLContextRef,), handler.ctx)
    if status == _errSecSuccess
        logf(
            LogLevel.DEBUG,
            LS_IO_TLS,
            "SecureTransport SSLHandshake success",
        )
        handler.negotiation_finished = true
        handler.protocol = _secure_transport_get_protocol(handler)
        if handler.protocol.len > 0
            logf(LogLevel.DEBUG, LS_IO_TLS, "negotiated protocol: $(String(byte_cursor_from_buf(handler.protocol)))")
        end
        _secure_transport_send_alpn_message(handler)
        _secure_transport_on_negotiation_result(handler, AWS_OP_SUCCESS)
        return nothing
    elseif status == _errSSLPeerAuthCompleted
        logf(
            LogLevel.DEBUG,
            LS_IO_TLS,
            "SecureTransport SSLHandshake peer auth completed",
        )
        if handler.verify_peer
            if handler.ca_certs == C_NULL
                _secure_transport_on_negotiation_result(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                raise_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                return ErrorResult(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
            end
            trust_ref = Ref{SecTrustRef}(C_NULL)
            if ccall((:SSLCopyPeerTrust, _SECURITY_LIB), OSStatus, (SSLContextRef, Ref{SecTrustRef}), handler.ctx, trust_ref) !=
                    _errSecSuccess
                _secure_transport_on_negotiation_result(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                raise_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                return ErrorResult(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
            end

            policy = if handler.server_name.len > 0
                name_str = String(byte_cursor_from_buf(handler.server_name))
                name_cursor = ByteCursor(name_str)
                name_ref = GC.@preserve name_cursor _cf_string_create(_cursor_ptr(name_cursor), name_cursor.len, _kCFStringEncodingUTF8)
                policy_ref = ccall((:SecPolicyCreateSSL, _SECURITY_LIB), SecPolicyRef, (UInt8, CFStringRef), 1, name_ref)
                _cf_release(name_ref)
                policy_ref
            else
                ccall((:SecPolicyCreateBasicX509, _SECURITY_LIB), SecPolicyRef, ())
            end

            if ccall((:SecTrustSetPolicies, _SECURITY_LIB), OSStatus, (SecTrustRef, SecPolicyRef), trust_ref[], policy) !=
                    _errSecSuccess
                _cf_release(policy)
                _cf_release(trust_ref[])
                _secure_transport_on_negotiation_result(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                raise_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                return ErrorResult(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
            end
            _cf_release(policy)

            if handler.ca_certs != C_NULL
                if ccall(
                        (:SecTrustSetAnchorCertificates, _SECURITY_LIB),
                        OSStatus,
                        (SecTrustRef, CFArrayRef),
                        trust_ref[],
                        handler.ca_certs,
                    ) != _errSecSuccess
                    _cf_release(trust_ref[])
                    _secure_transport_on_negotiation_result(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                    raise_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                    return ErrorResult(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                end

                if ccall(
                        (:SecTrustSetAnchorCertificatesOnly, _SECURITY_LIB),
                        OSStatus,
                        (SecTrustRef, UInt8),
                        trust_ref[],
                        1,
                    ) != _errSecSuccess
                    _cf_release(trust_ref[])
                    _secure_transport_on_negotiation_result(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                    raise_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                    return ErrorResult(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                end
            end

            trust_eval = Ref{Cint}(0)
            status = ccall((:SecTrustEvaluate, _SECURITY_LIB), OSStatus, (SecTrustRef, Ref{Cint}), trust_ref[], trust_eval)
            _cf_release(trust_ref[])

            if status == _errSecSuccess &&
                    (trust_eval[] == _kSecTrustResultProceed || trust_eval[] == _kSecTrustResultUnspecified)
                return _secure_transport_drive_negotiation(handler)
            end

            logf(
                LogLevel.WARN,
                LS_IO_TLS,
                "SecureTransport custom CA validation failed with OSStatus $status and Trust Eval $(trust_eval[])",
            )
            raise_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
            return ErrorResult(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
        end

        return _secure_transport_drive_negotiation(handler)
    elseif status == _errSSLWouldBlock
        return nothing
    else
        logf(
            LogLevel.WARN,
            LS_IO_TLS,
            "SecureTransport SSLHandshake failed with OSStatus $status",
        )
        handler.negotiation_finished = false
        _secure_transport_on_negotiation_result(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
        raise_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
        return ErrorResult(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
    end
end

function _secure_transport_negotiation_task(task::ChannelTask, handler::SecureTransportTlsHandler, status::TaskStatus.T)
    _ = task
    status == TaskStatus.RUN_READY || return nothing
    _ = _secure_transport_drive_negotiation(handler)
    return nothing
end

function _secure_transport_read_cb(conn::SSLConnectionRef, data::Ptr{UInt8}, len_ptr::Ptr{Csize_t})::OSStatus
    handler = unsafe_pointer_to_objref(conn)::SecureTransportTlsHandler
    requested = unsafe_load(len_ptr)
    written = Csize_t(0)
    queue = handler.input_queue
    while !linked_list_empty(queue) && written < requested
        message = linked_list_pop_front(queue)
        message === nothing && break
        msg = message::IoMessage
        remaining_message_len = Int(msg.message_data.len) - Int(msg.copy_mark)
        remaining_buf_len = Int(requested) - Int(written)
        to_write = remaining_message_len < remaining_buf_len ? remaining_message_len : remaining_buf_len

        if to_write > 0
            src_ptr = pointer(msg.message_data.mem) + Int(msg.copy_mark)
            unsafe_copyto!(data + Int(written), src_ptr, to_write)
            written += Csize_t(to_write)
            msg.copy_mark += Csize_t(to_write)
        end

        if msg.copy_mark == msg.message_data.len
            if msg.owning_channel isa Channel
                channel_release_message_to_pool!(msg.owning_channel, msg)
            end
        else
            linked_list_push_front(queue, msg)
        end
    end

    unsafe_store!(len_ptr, written)
    if written == requested
        return _errSecSuccess
    end
    return _errSSLWouldBlock
end

function _secure_transport_write_cb(conn::SSLConnectionRef, data::Ptr{UInt8}, len_ptr::Ptr{Csize_t})::OSStatus
    handler = unsafe_pointer_to_objref(conn)::SecureTransportTlsHandler
    requested = unsafe_load(len_ptr)
    channel = handler.slot === nothing ? nothing : handler.slot.channel
    channel === nothing && return _errSSLClosedNoNotify

    processed = Csize_t(0)
    while processed < requested
        overhead = channel_slot_upstream_message_overhead(handler.slot)
        message_size_hint = Csize_t(requested - processed) + overhead
        message = channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, message_size_hint)
        message === nothing && return _errSSLClosedNoNotify

        if message.message_data.capacity <= overhead
            channel_release_message_to_pool!(channel, message)
            return _errSecMemoryError
        end

        available = Int(message.message_data.capacity - overhead)
        to_write = min(available, Int(requested - processed))

        mem = unsafe_wrap(Memory{UInt8}, data + Int(processed), to_write; own = false)
        chunk = ByteCursor(mem, to_write)
        buf_ref = Ref(message.message_data)
        if byte_buf_append(buf_ref, chunk) != AWS_OP_SUCCESS
            channel_release_message_to_pool!(channel, message)
            return _errSecBufferTooSmall
        end
        message.message_data = buf_ref[]
        processed += Csize_t(message.message_data.len)

        if processed == requested
            message.on_completion = handler.latest_message_on_completion
            message.user_data = handler.latest_message_completion_user_data
            handler.latest_message_on_completion = nothing
            handler.latest_message_completion_user_data = nothing
        end

        send_res = channel_slot_send_message(handler.slot, message, ChannelDirection.WRITE)
        if send_res isa ErrorResult
            channel_release_message_to_pool!(channel, message)
            return _errSSLClosedNoNotify
        end
    end

    unsafe_store!(len_ptr, processed)
    if processed == requested
        return _errSecSuccess
    end
    return _errSSLWouldBlock
end

function _secure_transport_init_callbacks()
    @static if !Sys.isapple()
        return nothing
    end
    if _secure_transport_read_cb_c[] == C_NULL
        _secure_transport_read_cb_c[] = @cfunction(
            _secure_transport_read_cb,
            OSStatus,
            (SSLConnectionRef, Ptr{UInt8}, Ptr{Csize_t}),
        )
    end
    if _secure_transport_write_cb_c[] == C_NULL
        _secure_transport_write_cb_c[] = @cfunction(
            _secure_transport_write_cb,
            OSStatus,
            (SSLConnectionRef, Ptr{UInt8}, Ptr{Csize_t}),
        )
    end
    return nothing
end

const _secure_transport_read_cb_c = Ref{Ptr{Cvoid}}(C_NULL)
const _secure_transport_write_cb_c = Ref{Ptr{Cvoid}}(C_NULL)

function _secure_transport_read_task(task::ChannelTask, handler::SecureTransportTlsHandler, status::TaskStatus.T)
    _ = task
    status == TaskStatus.RUN_READY || return nothing
    handler.read_task_pending = false
    if handler.slot !== nothing
        handler_process_read_message(handler, handler.slot, nothing)
    end
    return nothing
end

function _secure_transport_initialize_read_delay_shutdown(handler::SecureTransportTlsHandler, slot::ChannelSlot, error_code::Int)
    logf(
        LogLevel.DEBUG,
        LS_IO_TLS,
        "TLS handler pending data during shutdown, waiting for downstream read window.",
    )
    if channel_slot_downstream_read_window(slot) == 0
        logf(
            LogLevel.WARN,
            LS_IO_TLS,
            "TLS shutdown delayed; pending data cannot be processed until read window opens.",
        )
    end
    handler.read_state = TlsHandlerReadState.SHUTTING_DOWN
    handler.delay_shutdown_error_code = error_code
    if !handler.read_task_pending
        handler.read_task_pending = true
        channel_task_init!(handler.read_task, _secure_transport_read_task, handler, "secure_transport_read_on_delay_shutdown")
        channel_schedule_task_now!(slot.channel, handler.read_task)
    end
    return nothing
end

function handler_initial_window_size(handler::SecureTransportTlsHandler)::Csize_t
    _ = handler
    return Csize_t(TLS_EST_HANDSHAKE_SIZE)
end

function handler_message_overhead(handler::SecureTransportTlsHandler)::Csize_t
    _ = handler
    return Csize_t(TLS_EST_RECORD_OVERHEAD)
end

function handler_destroy(handler::SecureTransportTlsHandler)::Nothing
    delete!(_secure_transport_handler_registry, handler)
    tls_handler_shared_clean_up!(handler.shared)
    while !linked_list_empty(handler.input_queue)
        msg = linked_list_pop_front(handler.input_queue)
        if msg isa IoMessage && msg.owning_channel isa Channel
            channel_release_message_to_pool!(msg.owning_channel, msg)
        end
    end
    if handler.ctx != C_NULL
        _ = ccall((:CFRelease, _COREFOUNDATION_LIB), Cvoid, (Ptr{Cvoid},), handler.ctx)
        handler.ctx = C_NULL
    end
    handler.protocol = null_buffer()
    handler.server_name = null_buffer()
    handler.slot = nothing
    handler.ctx_obj = nothing
    return nothing
end

function handler_reset_statistics(handler::SecureTransportTlsHandler)::Nothing
    crt_statistics_tls_reset!(handler.shared.stats)
    return nothing
end

function handler_gather_statistics(handler::SecureTransportTlsHandler)
    return handler.shared.stats
end

function handler_process_read_message(
        handler::SecureTransportTlsHandler,
        slot::ChannelSlot,
        message::Union{IoMessage, Nothing},
    )::Union{Nothing, ErrorResult}
    if handler.read_state == TlsHandlerReadState.SHUT_DOWN_COMPLETE
        message !== nothing && message.owning_channel isa Channel && channel_release_message_to_pool!(message.owning_channel, message)
        return nothing
    end

    if message !== nothing
        linked_list_push_back(handler.input_queue, message)

        if !handler.negotiation_finished
            message_len = message.message_data.len
            res = _secure_transport_drive_negotiation(handler)
            if res isa ErrorResult
                channel_shutdown!(slot.channel, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
            else
                channel_slot_increment_read_window!(slot, message_len)
            end
            return nothing
        end
    end

    if slot.adj_right === nothing
        downstream_window = SIZE_MAX
    else
        downstream_window = channel_slot_downstream_read_window(slot)
    end
    processed = Csize_t(0)
    shutdown_error_code = 0
    force_shutdown = false

    while processed < downstream_window
        outgoing = channel_acquire_message_from_pool(
            slot.channel,
            IoMessageType.APPLICATION_DATA,
            downstream_window - processed,
        )
        outgoing === nothing && break

        read_size = Ref{Csize_t}(0)
        status = ccall(
            (:SSLRead, _SECURITY_LIB),
            OSStatus,
            (SSLContextRef, Ptr{UInt8}, Csize_t, Ref{Csize_t}),
            handler.ctx,
            pointer(outgoing.message_data.mem),
            outgoing.message_data.capacity,
            read_size,
        )

        if read_size[] > 0
            processed += read_size[]
            setfield!(outgoing.message_data, :len, Csize_t(read_size[]))

            if handler.on_data_read !== nothing
                Base.invokelatest(handler.on_data_read, handler, slot, outgoing.message_data, handler.user_data)
            end

            if slot.adj_right !== nothing
                send_res = channel_slot_send_message(slot, outgoing, ChannelDirection.READ)
                if send_res isa ErrorResult
                    channel_release_message_to_pool!(slot.channel, outgoing)
                    shutdown_error_code = send_res.code
                    break
                end
            else
                channel_release_message_to_pool!(slot.channel, outgoing)
            end
        else
            channel_release_message_to_pool!(slot.channel, outgoing)
        end

        if status == _errSSLWouldBlock
            if handler.read_state == TlsHandlerReadState.SHUTTING_DOWN
                break
            end
            break
        elseif status == _errSSLClosedGraceful
            force_shutdown = true
            break
        elseif status == _errSecSuccess
            continue
        else
            logf(
                LogLevel.ERROR,
                LS_IO_TLS,
                "SecureTransport SSLRead failed with OSStatus $status",
            )
            raise_error(ERROR_IO_TLS_ERROR_READ_FAILURE)
            shutdown_error_code = ERROR_IO_TLS_ERROR_READ_FAILURE
            break
        end
    end

    if force_shutdown || shutdown_error_code != 0 ||
            (handler.read_state == TlsHandlerReadState.SHUTTING_DOWN && processed < downstream_window)
        if handler.read_state == TlsHandlerReadState.SHUTTING_DOWN
            if handler.delay_shutdown_error_code != 0
                shutdown_error_code = handler.delay_shutdown_error_code
            end
            handler.read_state = TlsHandlerReadState.SHUT_DOWN_COMPLETE
            channel_slot_on_handler_shutdown_complete!(
                slot,
                ChannelDirection.READ,
                shutdown_error_code,
                false,
            )
        else
            channel_shutdown!(slot.channel, shutdown_error_code)
        end
    end

    return nothing
end

function handler_process_read_message(handler::SecureTransportTlsHandler, slot::ChannelSlot, message::IoMessage)
    return invoke(
        handler_process_read_message,
        Tuple{SecureTransportTlsHandler, ChannelSlot, Union{IoMessage, Nothing}},
        handler,
        slot,
        message,
    )
end

function handler_process_write_message(
        handler::SecureTransportTlsHandler,
        slot::ChannelSlot,
        message::IoMessage,
    )::Union{Nothing, ErrorResult}
    _ = slot
    if !handler.negotiation_finished
        raise_error(ERROR_IO_TLS_ERROR_NOT_NEGOTIATED)
        return ErrorResult(ERROR_IO_TLS_ERROR_NOT_NEGOTIATED)
    end

    handler.latest_message_on_completion = message.on_completion
    handler.latest_message_completion_user_data = message.user_data

    processed = Ref{Csize_t}(0)
    status = ccall(
        (:SSLWrite, _SECURITY_LIB),
        OSStatus,
        (SSLContextRef, Ptr{UInt8}, Csize_t, Ref{Csize_t}),
        handler.ctx,
        pointer(message.message_data.mem),
        message.message_data.len,
        processed,
    )

    if status != _errSecSuccess
        raise_error(ERROR_IO_TLS_ERROR_WRITE_FAILURE)
        return ErrorResult(ERROR_IO_TLS_ERROR_WRITE_FAILURE)
    end

    channel_release_message_to_pool!(slot.channel, message)
    return nothing
end

function handler_shutdown(
        handler::SecureTransportTlsHandler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Union{Nothing, ErrorResult}
    abort_immediately = free_scarce_resources_immediately

    if direction == ChannelDirection.READ
        if !abort_immediately &&
                handler.negotiation_finished &&
                !linked_list_empty(handler.input_queue) &&
                slot.adj_right !== nothing
            _secure_transport_initialize_read_delay_shutdown(handler, slot, error_code)
            return nothing
        end
        handler.read_state = TlsHandlerReadState.SHUT_DOWN_COMPLETE
    else
        if !abort_immediately && error_code != ERROR_IO_SOCKET_CLOSED
            _ = ccall((:SSLClose, _SECURITY_LIB), OSStatus, (SSLContextRef,), handler.ctx)
        end
    end

    while !linked_list_empty(handler.input_queue)
        msg = linked_list_pop_front(handler.input_queue)
        if msg isa IoMessage && msg.owning_channel isa Channel
            channel_release_message_to_pool!(msg.owning_channel, msg)
        end
    end
    channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, abort_immediately)
    return nothing
end

function handler_increment_read_window(
        handler::SecureTransportTlsHandler,
        slot::ChannelSlot,
        size::Csize_t,
    )::Union{Nothing, ErrorResult}
    _ = size
    if handler.read_state == TlsHandlerReadState.SHUT_DOWN_COMPLETE
        return nothing
    end

    downstream_size = channel_slot_downstream_read_window(slot)
    current_window = slot.window_size
    record_size = Csize_t(TLS_MAX_RECORD_SIZE)
    likely_records = downstream_size == 0 ? Csize_t(0) : Csize_t(ceil(downstream_size / record_size))
    offset_size = mul_size_saturating(likely_records, Csize_t(TLS_EST_RECORD_OVERHEAD))
    total_desired = add_size_saturating(offset_size, downstream_size)

    if total_desired > current_window
        update_size = total_desired - current_window
        channel_slot_increment_read_window!(slot, update_size)
    end

    if handler.negotiation_finished && !handler.read_task_pending
        handler.read_task_pending = true
        channel_task_init!(handler.read_task, _secure_transport_read_task, handler, "secure_transport_read_on_window_increment")
        channel_schedule_task_now!(slot.channel, handler.read_task)
    end

    return nothing
end

function _secure_transport_ctx_destroy!(ctx::SecureTransportCtx)
    if ctx.certs != C_NULL
        _cf_release(ctx.certs)
        ctx.certs = C_NULL
    end
    if ctx.ca_cert != C_NULL
        _cf_release(ctx.ca_cert)
        ctx.ca_cert = C_NULL
    end
    if ctx.secitem_identity != C_NULL
        _cf_release(ctx.secitem_identity)
        ctx.secitem_identity = C_NULL
    end
    ctx.alpn_list = nothing
    return nothing
end

function _secure_transport_context_new(options::TlsContextOptions)::Union{TlsContext, ErrorResult}
    if !tls_is_cipher_pref_supported(options.cipher_pref)
        raise_error(ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED)
        return ErrorResult(ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED)
    end

    ctx_impl = SecureTransportCtx(options.minimum_tls_version, options.alpn_list, options.verify_peer, C_NULL, C_NULL, C_NULL)

    if options.certificate_set && options.private_key_set
        cert_cursor = byte_cursor_from_buf(options.certificate)
        key_cursor = byte_cursor_from_buf(options.private_key)
        if !text_is_utf8(cert_cursor) || !text_is_utf8(key_cursor)
            raise_error(ERROR_IO_FILE_VALIDATION_FAILURE)
            return ErrorResult(ERROR_IO_FILE_VALIDATION_FAILURE)
        end
        if is_using_secitem()
            if options.secitem_options === nothing ||
                    options.secitem_options.cert_label === nothing ||
                    options.secitem_options.key_label === nothing
                raise_error(ERROR_INVALID_ARGUMENT)
                return ErrorResult(ERROR_INVALID_ARGUMENT)
            end
            res = secitem_import_cert_and_key(
                cert_cursor,
                key_cursor;
                cert_label = options.secitem_options.cert_label,
                key_label = options.secitem_options.key_label,
            )
            if res isa ErrorResult
                return res
            end
            ctx_impl.secitem_identity = res
        else
            res = import_public_and_private_keys_to_identity(cert_cursor, key_cursor; keychain_path = options.keychain_path)
            if res isa ErrorResult
                return res
            end
            ctx_impl.certs = res
        end
    elseif options.pkcs12_set
        pkcs_cursor = byte_cursor_from_buf(options.pkcs12)
        pwd_cursor = byte_cursor_from_buf(options.pkcs12_password)
        if is_using_secitem()
            res = secitem_import_pkcs12(pkcs_cursor, pwd_cursor)
            if res isa ErrorResult
                return res
            end
            ctx_impl.secitem_identity = res
        else
            res = import_pkcs12_to_identity(pkcs_cursor, pwd_cursor)
            if res isa ErrorResult
                return res
            end
            ctx_impl.certs = res
        end
    end

    if options.ca_file_set
        ca_cursor = byte_cursor_from_buf(options.ca_file)
        res = import_trusted_certificates(ca_cursor)
        if res isa ErrorResult
            return res
        end
        ctx_impl.ca_cert = res
    end

    ctx = TlsContext(options, ctx_impl, false)
    finalizer(ctx) do c
        c.closed && return
        c.closed = true
        if c.impl isa SecureTransportCtx
            _secure_transport_ctx_destroy!(c.impl)
        end
    end
    return ctx
end

function _secure_transport_handler_new(
        options::TlsConnectionOptions,
        slot::ChannelSlot,
        protocol_side::SSLProtocolSide,
    )::Union{SecureTransportTlsHandler, ErrorResult}
    @static if !Sys.isapple()
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    ctx = options.ctx
    ctx.impl isa ErrorResult && return ctx.impl
    st_ctx = ctx.impl isa SecureTransportCtx ? ctx.impl : nothing
    st_ctx === nothing && return ErrorResult(raise_error(ERROR_IO_TLS_CTX_ERROR))

    handler = SecureTransportTlsHandler{Union{ChannelSlot, Nothing}}(
        slot,
        TlsHandlerShared{Any}(nothing, UInt32(0), TlsHandlerStatistics(), ChannelTask()),
        C_NULL,
        ctx,
        linked_list_init(IoMessage),
        null_buffer(),
        null_buffer(),
        nothing,
        nothing,
        C_NULL,
        options.on_negotiation_result,
        options.on_data_read,
        options.on_error,
        options.user_data,
        options.advertise_alpn_message,
        false,
        options.ctx.options.verify_peer,
        ChannelTask(),
        false,
        TlsHandlerReadState.OPEN,
        0,
        ChannelTask(),
    )

    tls_handler_shared_init!(handler.shared, handler, options)
    _secure_transport_handler_registry[handler] = nothing

    handler.ctx = ccall((:SSLCreateContext, _SECURITY_LIB), SSLContextRef, (CFAllocatorRef, SSLProtocolSide, SSLConnectionType), C_NULL, protocol_side, _kSSLStreamType)
    handler.ctx == C_NULL && return ErrorResult(raise_error(ERROR_IO_TLS_CTX_ERROR))
    _secure_transport_init_callbacks()

    if options.ctx.options.minimum_tls_version == TlsVersion.SSLv3
        _ = ccall((:SSLSetProtocolVersionMin, _SECURITY_LIB), OSStatus, (SSLContextRef, Cint), handler.ctx, _kSSLProtocol3)
    elseif options.ctx.options.minimum_tls_version == TlsVersion.TLSv1
        _ = ccall((:SSLSetProtocolVersionMin, _SECURITY_LIB), OSStatus, (SSLContextRef, Cint), handler.ctx, _kTLSProtocol1)
    elseif options.ctx.options.minimum_tls_version == TlsVersion.TLSv1_1
        _ = ccall((:SSLSetProtocolVersionMin, _SECURITY_LIB), OSStatus, (SSLContextRef, Cint), handler.ctx, _kTLSProtocol12)
    elseif options.ctx.options.minimum_tls_version == TlsVersion.TLSv1_2
        _ = ccall((:SSLSetProtocolVersionMin, _SECURITY_LIB), OSStatus, (SSLContextRef, Cint), handler.ctx, _kTLSProtocol12)
    elseif options.ctx.options.minimum_tls_version == TlsVersion.TLSv1_3
        raise_error(ERROR_IO_TLS_CTX_ERROR)
        return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
    else
        _ = ccall((:SSLSetProtocolVersionMin, _SECURITY_LIB), OSStatus, (SSLContextRef, Cint), handler.ctx, _kSSLProtocolUnknown)
    end

    if ccall((:SSLSetIOFuncs, _SECURITY_LIB), OSStatus, (SSLContextRef, Ptr{Cvoid}, Ptr{Cvoid}), handler.ctx, _secure_transport_read_cb_c[], _secure_transport_write_cb_c[]) != _errSecSuccess ||
            ccall((:SSLSetConnection, _SECURITY_LIB), OSStatus, (SSLContextRef, SSLConnectionRef), handler.ctx, pointer_from_objref(handler)) != _errSecSuccess
        raise_error(ERROR_IO_TLS_CTX_ERROR)
        return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
    end

    handler.verify_peer = st_ctx.verify_peer

    if !st_ctx.verify_peer && protocol_side == _kSSLClientSide
        _ = ccall((:SSLSetSessionOption, _SECURITY_LIB), OSStatus, (SSLContextRef, Cint, UInt8), handler.ctx, _kSSLSessionOptionBreakOnServerAuth, 1)
    end

    if st_ctx.certs != C_NULL
        _ = ccall((:SSLSetCertificate, _SECURITY_LIB), OSStatus, (SSLContextRef, CFArrayRef), handler.ctx, st_ctx.certs)
    end

    handler.ca_certs = st_ctx.ca_cert
    if handler.ca_certs != C_NULL
        if protocol_side == _kSSLServerSide && st_ctx.verify_peer
            _ = ccall((:SSLSetSessionOption, _SECURITY_LIB), OSStatus, (SSLContextRef, Cint, UInt8), handler.ctx, _kSSLSessionOptionBreakOnClientAuth, 1)
        elseif st_ctx.verify_peer
            _ = ccall((:SSLSetSessionOption, _SECURITY_LIB), OSStatus, (SSLContextRef, Cint, UInt8), handler.ctx, _kSSLSessionOptionBreakOnServerAuth, 1)
        end
    end

    if options.server_name !== nothing
        handler.server_name = _byte_buf_from_string(options.server_name)
        _ = ccall((:SSLSetPeerDomainName, _SECURITY_LIB), OSStatus, (SSLContextRef, Cstring, Csize_t), handler.ctx, options.server_name, ncodeunits(options.server_name))
    end

    if options.alpn_list !== nothing
        _secure_transport_set_protocols(handler, options.alpn_list)
    elseif st_ctx.alpn_list !== nothing
        _secure_transport_set_protocols(handler, st_ctx.alpn_list)
    end

    return handler
end

# === Generic TLS API ===

function tls_is_alpn_available()::Bool
    @static if Sys.isapple()
        return _ssl_copy_alpn_protocols[] != C_NULL
    elseif Sys.islinux()
        return _s2n_available[]
    else
        return false
    end
end

function tls_is_cipher_pref_supported(pref::TlsCipherPref.T)::Bool
    @static if Sys.isapple()
        return pref == TlsCipherPref.TLS_CIPHER_PREF_SYSTEM_DEFAULT
    elseif Sys.islinux()
        return pref == TlsCipherPref.TLS_CIPHER_PREF_SYSTEM_DEFAULT ||
            pref == TlsCipherPref.TLS_CIPHER_PREF_PQ_DEFAULT ||
            pref == TlsCipherPref.TLS_CIPHER_PREF_PQ_TLSV1_2_2024_10 ||
            pref == TlsCipherPref.TLS_CIPHER_PREF_TLSV1_2_2025_07 ||
            pref == TlsCipherPref.TLS_CIPHER_PREF_TLSV1_0_2023_06
    else
        return false
    end
end

function _tls_context_new_impl(options::TlsContextOptions)::Union{TlsContext, ErrorResult}
    @static if Sys.islinux()
        return _s2n_context_new(options)
    elseif Sys.isapple()
        return _secure_transport_context_new(options)
    else
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end
end

function _tls_context_release_impl(ctx::TlsContext)
    ctx.closed && return nothing
    ctx.closed = true
    if ctx.impl isa S2nTlsCtx
        _s2n_ctx_destroy!(ctx.impl)
    elseif ctx.impl isa SecureTransportCtx
        _secure_transport_ctx_destroy!(ctx.impl)
    end
    return nothing
end

function tls_client_handler_new(
        options::TlsConnectionOptions,
        slot::ChannelSlot,
    )::Union{AbstractChannelHandler, ErrorResult}
    if options.ctx.options.is_server
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end

    if _tls_byo_client_setup[] !== nothing
        return _tls_byo_new_handler(_tls_byo_client_setup[], options, slot)
    end

    @static if Sys.islinux()
        return _s2n_handler_new(options, slot, S2N_CLIENT)
    elseif Sys.isapple()
        return _secure_transport_handler_new(options, slot, _kSSLClientSide)
    else
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end
end

function tls_server_handler_new(
        options::TlsConnectionOptions,
        slot::ChannelSlot,
    )::Union{AbstractChannelHandler, ErrorResult}
    if !options.ctx.options.is_server
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end

    if _tls_byo_server_setup[] !== nothing
        return _tls_byo_new_handler(_tls_byo_server_setup[], options, slot)
    end

    @static if Sys.islinux()
        return _s2n_handler_new(options, slot, S2N_SERVER)
    elseif Sys.isapple()
        return _secure_transport_handler_new(options, slot, _kSSLServerSide)
    else
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end
end

function tls_client_handler_start_negotiation(handler::AbstractChannelHandler)
    if _tls_byo_client_setup[] !== nothing
        return _tls_byo_start_negotiation(_tls_byo_client_setup[], handler)
    end

    @static if Sys.islinux()
        if !(handler isa S2nTlsHandler)
            raise_error(ERROR_INVALID_STATE)
            return ErrorResult(ERROR_INVALID_STATE)
        end
        if handler.slot !== nothing && handler.slot.channel !== nothing && channel_thread_is_callers_thread(handler.slot.channel)
            _ = _s2n_drive_negotiation(handler)
            return nothing
        end
        channel_task_init!(handler.negotiation_task, _s2n_negotiation_task, handler, "s2n_channel_handler_negotiation")
        channel_schedule_task_now!(handler.slot.channel, handler.negotiation_task)
        return nothing
    elseif Sys.isapple()
        if !(handler isa SecureTransportTlsHandler)
            raise_error(ERROR_INVALID_STATE)
            return ErrorResult(ERROR_INVALID_STATE)
        end
        if handler.slot !== nothing && handler.slot.channel !== nothing && channel_thread_is_callers_thread(handler.slot.channel)
            return _secure_transport_drive_negotiation(handler)
        end
        channel_task_init!(handler.negotiation_task, _secure_transport_negotiation_task, handler, "secure_transport_channel_handler_start_negotiation")
        channel_schedule_task_now!(handler.slot.channel, handler.negotiation_task)
        return nothing
    else
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end
end

function tls_handler_protocol(handler::TlsChannelHandler)::ByteBuffer
    if handler isa S2nTlsHandler
        return handler.protocol
    elseif handler isa SecureTransportTlsHandler
        return handler.protocol
    else
        return null_buffer()
    end
end

function tls_handler_server_name(handler::TlsChannelHandler)::ByteBuffer
    if handler isa S2nTlsHandler
        return handler.server_name
    elseif handler isa SecureTransportTlsHandler
        return handler.server_name
    else
        return null_buffer()
    end
end

function tls_channel_handler_new!(
        channel::Channel,
        options::TlsConnectionOptions,
    )::Union{AbstractChannelHandler, ErrorResult}
    channel.last === nothing && return ErrorResult(raise_error(ERROR_INVALID_STATE))

    tls_slot = ChannelSlot()
    tls_slot.channel = channel

    handler = options.ctx.options.is_server ?
        tls_server_handler_new(options, tls_slot) :
        tls_client_handler_new(options, tls_slot)
    handler isa ErrorResult && return handler

    channel_slot_insert_right!(channel.last, tls_slot)
    set_res = channel_slot_set_handler!(tls_slot, handler)
    set_res isa ErrorResult && return set_res

    return handler
end

function channel_setup_client_tls(
        right_of_slot::ChannelSlot,
        options::TlsConnectionOptions,
    )::Union{AbstractChannelHandler, ErrorResult}
    channel = right_of_slot.channel
    channel === nothing && return ErrorResult(raise_error(ERROR_INVALID_STATE))

    tls_slot = ChannelSlot()
    tls_slot.channel = channel

    handler = tls_client_handler_new(options, tls_slot)
    handler isa ErrorResult && return handler

    channel_slot_insert_right!(right_of_slot, tls_slot)
    set_res = channel_slot_set_handler!(tls_slot, handler)
    set_res isa ErrorResult && return set_res

    start_res = tls_client_handler_start_negotiation(handler)
    start_res isa ErrorResult && return start_res

    return handler
end
