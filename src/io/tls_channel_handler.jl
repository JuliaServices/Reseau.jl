# AWS IO Library - TLS Channel Handler (LibAwsCal-backed)

using LibAwsCal
using LibAwsCommon

const TlsOnNegotiationResultFn = Function  # (handler, slot, error_code, user_data) -> nothing
const TlsOnDataReadFn = Function           # (handler, slot, buffer, user_data) -> nothing
const TlsOnErrorFn = Function              # (handler, slot, error_code, message, user_data) -> nothing

const TLS_HANDSHAKE_CLIENT_HELLO = 0x01
const TLS_HANDSHAKE_SERVER_HELLO = 0x02
const TLS_RECORD_APPLICATION = 0x03
const TLS_RECORD_ALERT = 0x15
const TLS_RECORD_HEADER_LEN = 5
const TLS_DEFAULT_TIMEOUT_MS = 10_000
const TLS_NONCE_LEN = 32
const TLS_MAC_LEN = 32
const TLS_SESSION_KEY_LEN = 32
const TLS_ALERT_LEVEL_WARNING = 0x01
const TLS_ALERT_LEVEL_FATAL = 0x02
const TLS_ALERT_CLOSE_NOTIFY = 0x00

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

function tls_is_cipher_pref_supported(pref::TlsCipherPref.T)::Bool
    return pref != TlsCipherPref.TLS_CIPHER_PREF_END_RANGE
end

tls_is_alpn_available() = true

@enumx TlsHandshakeState::UInt8 begin
    INIT = 0
    CLIENT_HELLO_SENT = 1
    NEGOTIATED = 2
    FAILED = 3
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
    ca_path::Union{String, Nothing}
    alpn_list::Union{String, Nothing}
    certificate::ByteBuffer
    private_key::ByteBuffer
    system_certificate_path::Union{String, Nothing}
    pkcs12::ByteBuffer
    pkcs12_password::ByteBuffer
    secitem_options::Union{SecItemOptions, Nothing}
    keychain_path::Union{String, Nothing}
    max_fragment_size::Csize_t
    verify_peer::Bool
    ctx_options_extension::Any
    custom_key_op_handler::Any
end

function TlsContextOptions(;
        is_server::Bool = false,
        minimum_tls_version::TlsVersion.T = TlsVersion.TLS_VER_SYS_DEFAULTS,
        cipher_pref::TlsCipherPref.T = TlsCipherPref.TLS_CIPHER_PREF_SYSTEM_DEFAULT,
        ca_file::Union{ByteBuffer, Nothing} = nothing,
        ca_path::Union{String, Nothing} = nothing,
        alpn_list::Union{String, Nothing} = nothing,
        certificate::Union{ByteBuffer, Nothing} = nothing,
        private_key::Union{ByteBuffer, Nothing} = nothing,
        system_certificate_path::Union{String, Nothing} = nothing,
        pkcs12::Union{ByteBuffer, Nothing} = nothing,
        pkcs12_password::Union{ByteBuffer, Nothing} = nothing,
        secitem_options::Union{SecItemOptions, Nothing} = nothing,
        keychain_path::Union{String, Nothing} = nothing,
        max_fragment_size::Integer = g_aws_channel_max_fragment_size[],
        verify_peer::Union{Bool, Nothing} = nothing,
        ctx_options_extension = nothing,
        custom_key_op_handler = nothing,
    )
    verify_peer_final = verify_peer === nothing ? !is_server : verify_peer
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
        ca_path,
        alpn_list,
        certificate_buf,
        private_key_buf,
        system_certificate_path,
        pkcs12_buf,
        pkcs12_password_buf,
        secitem_options,
        keychain_path,
        Csize_t(max_fragment_size),
        verify_peer_final,
        ctx_options_extension,
        custom_key_op_handler,
    )
end

mutable struct TlsContext
    options::TlsContextOptions
end

const _tls_cal_init_lock = ReentrantLock()
const _tls_cal_initialized = Ref(false)
const _tls_use_secitem = Ref(false)

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
    return nothing
end

function tls_clean_up_static_state()
    return nothing
end

is_using_secitem() = _tls_use_secitem[]

@inline function _tls_options_buf_is_set(buf::ByteBuffer)::Bool
    return buf.len > 0
end

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
    data = Vector{UInt8}(undef, Int(buf.len))
    copyto!(data, 1, buf.mem, 1, Int(buf.len))
    parsed = pem_parse(data)
    if parsed isa ErrorResult
        return ErrorResult(last_error())
    end
    return nothing
end

function tls_context_new(options::TlsContextOptions)::Union{TlsContext, ErrorResult}
    _tls_cal_init_once()
    return TlsContext(options)
end

tls_ctx_acquire(ctx::TlsContext) = ctx
tls_ctx_acquire(::Nothing) = nothing
tls_ctx_release(::TlsContext) = nothing
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
        ca_path = options.ca_path,
        alpn_list = options.alpn_list,
        certificate = cert_buf,
        private_key = key_buf,
        system_certificate_path = options.system_certificate_path,
        pkcs12 = pkcs_buf,
        pkcs12_password = pkcs_pwd_buf,
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

mutable struct TlsKeyOperation{F, UD}
    input::ByteCursor
    operation_type::TlsKeyOperationType.T
    signature_algorithm::TlsSignatureAlgorithm.T
    digest_algorithm::TlsHashAlgorithm.T
    on_complete::F
    user_data::UD
    completed::Bool
    error_code::Int
    output::ByteBuffer
end

function TlsKeyOperation(
        input::ByteCursor;
        operation_type::TlsKeyOperationType.T = TlsKeyOperationType.UNKNOWN,
        signature_algorithm::TlsSignatureAlgorithm.T = TlsSignatureAlgorithm.UNKNOWN,
        digest_algorithm::TlsHashAlgorithm.T = TlsHashAlgorithm.UNKNOWN,
        on_complete = nothing,
        user_data = nothing,
    )
    return TlsKeyOperation(
        input,
        operation_type,
        signature_algorithm,
        digest_algorithm,
        on_complete,
        user_data,
        false,
        0,
        null_buffer(),
    )
end

function tls_key_operation_complete!(operation::TlsKeyOperation, output::ByteCursor)
    operation.output = null_buffer()
    buf = _tls_buf_copy_from(output)
    if buf isa ErrorResult
        return buf
    end
    operation.output = buf
    operation.completed = true
    operation.error_code = AWS_OP_SUCCESS
    if operation.on_complete !== nothing
        operation.on_complete(operation, AWS_OP_SUCCESS, operation.user_data)
    end
    return nothing
end

function tls_key_operation_complete_with_error!(operation::TlsKeyOperation, error_code::Int)
    operation.completed = true
    operation.error_code = error_code
    if operation.on_complete !== nothing
        operation.on_complete(operation, error_code, operation.user_data)
    end
    return nothing
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
    return TlsContextOptions(;
        is_server = false,
        verify_peer = verify_peer,
        ca_file = ca_file,
        ca_path = ca_path,
        alpn_list = alpn_list,
        minimum_tls_version = minimum_tls_version,
        cipher_pref = cipher_pref,
        max_fragment_size = max_fragment_size,
    )
end

function tls_ctx_options_clean_up!(options::TlsContextOptions)
    byte_buf_clean_up(Ref(options.ca_file))
    byte_buf_clean_up(Ref(options.certificate))
    byte_buf_clean_up_secure(Ref(options.private_key))

    byte_buf_clean_up_secure(Ref(options.pkcs12))
    byte_buf_clean_up_secure(Ref(options.pkcs12_password))
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
    if _tls_options_buf_is_set(options.ca_file)
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
    if ca_file !== nothing && _tls_options_buf_is_set(options.ca_file)
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

mutable struct PendingWrite
    message::IoMessage
    offset::Int
end

mutable struct TlsChannelHandler{SlotRef <: Union{ChannelSlot, Nothing}} <: AbstractChannelHandler
    slot::SlotRef
    negotiation_completed::Bool
    pending_writes::Vector{PendingWrite}
    max_read_size::Csize_t
    options::TlsConnectionOptions
    state::TlsHandshakeState.T
    read_state::TlsHandlerReadState.T
    stats::TlsHandlerStatistics
    timeout_task::ChannelTask
    protocol::ByteBuffer
    server_name::ByteBuffer
    client_random::Memory{UInt8}
    server_random::Memory{UInt8}
    session_key::Memory{UInt8}
    inbound_buf::Vector{UInt8}
    inbound_offset::Int
end

function TlsChannelHandler(
        options::TlsConnectionOptions;
        max_read_size::Integer = 16384,
    )
    server_name_buf = options.server_name === nothing ? null_buffer() : byte_buf_from_c_str(options.server_name)
    return TlsChannelHandler{Union{ChannelSlot, Nothing}}(
        nothing,
        false,
        PendingWrite[],
        Csize_t(max_read_size),
        options,
        TlsHandshakeState.INIT,
        TlsHandlerReadState.OPEN,
        TlsHandlerStatistics(),
        ChannelTask(),
        null_buffer(),
        server_name_buf,
        Memory{UInt8}(undef, 0),
        Memory{UInt8}(undef, 0),
        Memory{UInt8}(undef, 0),
        UInt8[],
        0,
    )
end

tls_handler_protocol(handler::TlsChannelHandler) = handler.protocol
tls_handler_server_name(handler::TlsChannelHandler) = handler.server_name

function tls_channel_handler_new!(channel::Channel, options::TlsConnectionOptions; max_read_size::Integer = 16384)
    slot = channel_slot_new!(channel)

    handler = if options.ctx.options.is_server
        tls_server_handler_new(options, slot; max_read_size = max_read_size)
    else
        tls_client_handler_new(options, slot; max_read_size = max_read_size)
    end

    handler isa ErrorResult && return handler

    if channel.first !== slot
        channel_slot_insert_end!(channel, slot)
    end

    if !options.ctx.options.is_server
        start_res = tls_client_handler_start_negotiation(handler)
        start_res isa ErrorResult && return start_res
    end

    return handler
end

function tls_client_handler_new(
        options::TlsConnectionOptions,
        slot::ChannelSlot;
        max_read_size::Integer = 16384,
    )
    if options.ctx.options.is_server
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end
    byo_setup = _tls_byo_client_setup[]
    if byo_setup !== nothing
        return _tls_byo_new_handler(byo_setup, options, slot)
    end

    handler = TlsChannelHandler(tls_connection_options_copy(options); max_read_size = max_read_size)
    handler.slot = slot
    set_res = channel_slot_set_handler!(slot, handler)
    set_res isa ErrorResult && return set_res
    return handler
end

function tls_server_handler_new(
        options::TlsConnectionOptions,
        slot::ChannelSlot;
        max_read_size::Integer = 16384,
    )
    if !options.ctx.options.is_server
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end
    byo_setup = _tls_byo_server_setup[]
    if byo_setup !== nothing
        return _tls_byo_new_handler(byo_setup, options, slot)
    end

    handler = TlsChannelHandler(tls_connection_options_copy(options); max_read_size = max_read_size)
    handler.slot = slot
    set_res = channel_slot_set_handler!(slot, handler)
    set_res isa ErrorResult && return set_res
    return handler
end

function _tls_start_negotiation_task(task::ChannelTask, handler::TlsChannelHandler, status::TaskStatus.T)
    _ = task
    status == TaskStatus.RUN_READY || return nothing
    tls_channel_handler_start_negotiation!(handler)
    return nothing
end

function tls_client_handler_start_negotiation(handler::AbstractChannelHandler)
    if handler isa TlsChannelHandler
        if handler.options.ctx.options.is_server
            raise_error(ERROR_INVALID_ARGUMENT)
            return ErrorResult(ERROR_INVALID_ARGUMENT)
        end
        slot = handler.slot
        channel = slot === nothing ? nothing : slot.channel
        if channel === nothing
            raise_error(ERROR_INVALID_STATE)
            return ErrorResult(ERROR_INVALID_STATE)
        end
        if channel_thread_is_callers_thread(channel)
            tls_channel_handler_start_negotiation!(handler)
            return nothing
        end
        task = ChannelTask()
        channel_task_init!(task, _tls_start_negotiation_task, handler, "tls_start_negotiation")
        channel_schedule_task_now!(channel, task)
        return nothing
    end

    byo_setup = _tls_byo_client_setup[]
    if byo_setup !== nothing
        return _tls_byo_start_negotiation(byo_setup, handler)
    end

    raise_error(ERROR_INVALID_ARGUMENT)
    return ErrorResult(ERROR_INVALID_ARGUMENT)
end

function channel_setup_client_tls!(right_of_slot::ChannelSlot, options::TlsConnectionOptions)
    channel = right_of_slot.channel
    if channel === nothing
        raise_error(ERROR_INVALID_ARGUMENT)
        return ErrorResult(ERROR_INVALID_ARGUMENT)
    end

    slot = channel_slot_new!(channel)
    handler = tls_client_handler_new(options, slot)
    handler isa ErrorResult && return handler

    channel_slot_insert_right!(right_of_slot, slot)
    start_res = tls_client_handler_start_negotiation(handler)
    start_res isa ErrorResult && return start_res
    return handler
end

channel_setup_client_tls(right_of_slot::ChannelSlot, options::TlsConnectionOptions) =
    channel_setup_client_tls!(right_of_slot, options)

function tls_channel_handler_start_negotiation!(handler::TlsChannelHandler)
    handler.state == TlsHandshakeState.INIT || return nothing
    _tls_mark_handshake_start!(handler)
    if handler.slot !== nothing && handler.slot.adj_left !== nothing
        left_handler = handler.slot.adj_left.handler
        if left_handler isa SocketChannelHandler
            _socket_handler_trigger_read(left_handler)
        end
    end

    if !handler.options.ctx.options.is_server
        _tls_send_client_hello!(handler)
    end
    return nothing
end

function _aws_byte_cursor_from_vec(vec::AbstractVector{UInt8})
    if isempty(vec)
        return LibAwsCommon.aws_byte_cursor(Csize_t(0), Ptr{UInt8}(C_NULL))
    end
    return LibAwsCommon.aws_byte_cursor(Csize_t(length(vec)), pointer(vec))
end

function _aws_byte_buf_from_vec(vec::AbstractVector{UInt8})
    return LibAwsCommon.aws_byte_buf(Csize_t(0), pointer(vec), Csize_t(length(vec)), Ptr{LibAwsCommon.aws_allocator}(C_NULL))
end

function _derive_session_key(client_random::AbstractVector{UInt8}, server_random::AbstractVector{UInt8})
    _tls_cal_init_once()

    psk = Memory{UInt8}(codeunits("awsio-tls-psk"))
    ikm = _aws_byte_cursor_from_vec(psk)
    salt = _aws_byte_cursor_from_vec(vcat(client_random, server_random))
    info = _aws_byte_cursor_from_vec(Memory{UInt8}(codeunits("awsio-tls")))

    out = Memory{UInt8}(undef, TLS_SESSION_KEY_LEN)
    out_buf = _aws_byte_buf_from_vec(out)
    allocator = LibAwsCommon.default_aws_allocator()

    rv = LibAwsCal.aws_hkdf_derive(
        allocator,
        LibAwsCal.HKDF_HMAC_SHA512,
        ikm,
        salt,
        info,
        Ref(out_buf),
        Csize_t(TLS_SESSION_KEY_LEN),
    )
    if rv != 0
        return Memory{UInt8}(undef, 0)
    end
    return out
end

function _hmac_sha256(key::AbstractVector{UInt8}, data::AbstractVector{UInt8})
    _tls_cal_init_once()
    allocator = LibAwsCommon.default_aws_allocator()
    key_cur = _aws_byte_cursor_from_vec(key)
    data_cur = _aws_byte_cursor_from_vec(data)

    hmac = LibAwsCal.aws_sha256_hmac_new(allocator, Ref(key_cur))
    if hmac == C_NULL
        return Memory{UInt8}(undef, 0)
    end

    if LibAwsCal.aws_hmac_update(hmac, Ref(data_cur)) != 0
        LibAwsCal.aws_hmac_destroy(hmac)
        return Memory{UInt8}(undef, 0)
    end

    out = Memory{UInt8}(undef, TLS_MAC_LEN)
    out_buf = _aws_byte_buf_from_vec(out)
    if LibAwsCal.aws_hmac_finalize(hmac, Ref(out_buf), Csize_t(0)) != 0
        LibAwsCal.aws_hmac_destroy(hmac)
        return Memory{UInt8}(undef, 0)
    end

    LibAwsCal.aws_hmac_destroy(hmac)
    return out
end

function _xor_with_key(data::AbstractVector{UInt8}, key::AbstractVector{UInt8})
    out = Memory{UInt8}(undef, length(data))
    key_len = length(key)
    key_len == 0 && return data
    for i in eachindex(data)
        out[i] = data[i] ⊻ key[1 + ((i - 1) % key_len)]
    end
    return out
end

function _const_time_eq(a::AbstractVector{UInt8}, b::AbstractVector{UInt8})
    length(a) == length(b) || return false
    acc = UInt8(0)
    for i in eachindex(a)
        acc |= a[i] ⊻ b[i]
    end
    return acc == 0x00
end

function _tls_callback_task(task::ChannelTask, arg, status::TaskStatus.T)
    _ = task
    status == TaskStatus.RUN_READY || return nothing
    fn, args = arg
    Base.invokelatest(fn, args...)
    return nothing
end

function _tls_invoke_on_event_loop(handler::TlsChannelHandler, fn, args...)
    if fn === nothing
        return nothing
    end
    slot = handler.slot
    channel = slot === nothing ? nothing : slot.channel
    if channel === nothing || channel_thread_is_callers_thread(channel)
        Base.invokelatest(fn, args...)
        return nothing
    end
    task = ChannelTask()
    channel_task_init!(task, _tls_callback_task, (fn, args), "tls_callback")
    channel_schedule_task_now!(channel, task)
    return nothing
end

function _tls_report_error!(handler::TlsChannelHandler, error_code::Int, message::AbstractString)
    if !handler.negotiation_completed
        handler.state = TlsHandshakeState.FAILED
        _tls_mark_handshake_end!(handler, TlsNegotiationStatus.FAILURE)
        if handler.options.on_negotiation_result !== nothing && handler.slot !== nothing
            _tls_invoke_on_event_loop(
                handler,
                handler.options.on_negotiation_result,
                handler,
                handler.slot,
                error_code,
                handler.options.user_data,
            )
        end
    else
        if handler.options.on_error !== nothing && handler.slot !== nothing
            _tls_invoke_on_event_loop(
                handler,
                handler.options.on_error,
                handler,
                handler.slot,
                error_code,
                message,
                handler.options.user_data,
            )
        end
    end

    if handler.slot !== nothing && handler.slot.channel !== nothing
        channel_shutdown!(handler.slot.channel, error_code)
    end

    return nothing
end

function _tls_timeout_task(task::ChannelTask, handler::TlsChannelHandler, status::TaskStatus.T)
    _ = task
    status == TaskStatus.RUN_READY || return nothing
    handler.stats.handshake_status == TlsNegotiationStatus.ONGOING || return nothing
    if handler.slot !== nothing && handler.slot.channel !== nothing
        channel_shutdown!(handler.slot.channel, ERROR_IO_TLS_NEGOTIATION_TIMEOUT)
    end
    return nothing
end

function _tls_mark_handshake_start!(handler::TlsChannelHandler)
    handler.stats.handshake_status == TlsNegotiationStatus.NONE || return nothing
    handler.stats.handshake_status = TlsNegotiationStatus.ONGOING

    if handler.slot === nothing || handler.slot.channel === nothing
        return nothing
    end

    now = channel_current_clock_time(handler.slot.channel)
    if !(now isa ErrorResult)
        handler.stats.handshake_start_ns = now
        if handler.options.timeout_ms > 0
            timeout_ns = timestamp_convert(handler.options.timeout_ms, TIMESTAMP_MILLIS, TIMESTAMP_NANOS, nothing)
            channel_task_init!(handler.timeout_task, _tls_timeout_task, handler, "tls_timeout")
            channel_schedule_task_future!(handler.slot.channel, handler.timeout_task, now + timeout_ns)
        end
    end

    return nothing
end

function _tls_mark_handshake_end!(handler::TlsChannelHandler, status::TlsNegotiationStatus.T)
    if handler.slot !== nothing && handler.slot.channel !== nothing
        now = channel_current_clock_time(handler.slot.channel)
        if !(now isa ErrorResult)
            handler.stats.handshake_end_ns = now
        end
    end
    handler.stats.handshake_status = status
    return nothing
end

function _tls_select_alpn_protocol(options::TlsConnectionOptions)
    list = options.alpn_list
    if list === nothing || isempty(list)
        return null_buffer()
    end
    for token in split(list, ';')
        proto = strip(token)
        if !isempty(proto)
            return byte_buf_from_c_str(proto)
        end
    end
    return null_buffer()
end

function _tls_send_alpn_message!(handler::TlsChannelHandler)::Bool
    if !handler.options.advertise_alpn_message
        return true
    end
    slot = handler.slot
    if slot === nothing || slot.channel === nothing
        return true
    end
    if slot.adj_right === nothing
        return true
    end
    if handler.protocol.len == 0
        return true
    end

    channel = slot.channel
    msg = channel_acquire_message_from_pool(
        channel,
        IoMessageType.APPLICATION_DATA,
        sizeof(TlsNegotiatedProtocolMessage),
    )
    if msg === nothing
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_WRITE_FAILURE, "ALPN message alloc failed")
        return false
    end

    msg.message_tag = TLS_NEGOTIATED_PROTOCOL_MESSAGE
    msg.user_data = TlsNegotiatedProtocolMessage(handler.protocol)
    msg.message_data.len = Csize_t(sizeof(TlsNegotiatedProtocolMessage))

    send_result = channel_slot_send_message(slot, msg, ChannelDirection.READ)
    if send_result isa ErrorResult
        channel_release_message_to_pool!(channel, msg)
        channel_shutdown!(channel, send_result.code)
        return false
    end

    return true
end

function _tls_send_record!(handler::TlsChannelHandler, record_type::UInt8, payload::AbstractVector{UInt8})
    slot = handler.slot
    if slot === nothing || slot.channel === nothing
        return nothing
    end

    channel = slot.channel
    total_len = TLS_RECORD_HEADER_LEN + length(payload)
    msg = channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, total_len)
    if msg === nothing
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_WRITE_FAILURE, "TLS output alloc failed")
        return nothing
    end

    buf_ref = Ref(msg.message_data)
    byte_buf_reserve(buf_ref, total_len)
    msg.message_data = buf_ref[]
    buf = msg.message_data

    GC.@preserve buf begin
        ptr = pointer(getfield(buf, :mem))
        unsafe_store!(ptr, record_type)
        len = UInt32(length(payload))
        unsafe_store!(ptr + 1, UInt8((len >> 24) & 0xFF))
        unsafe_store!(ptr + 2, UInt8((len >> 16) & 0xFF))
        unsafe_store!(ptr + 3, UInt8((len >> 8) & 0xFF))
        unsafe_store!(ptr + 4, UInt8(len & 0xFF))
        if !isempty(payload)
            unsafe_copyto!(ptr + TLS_RECORD_HEADER_LEN, pointer(payload), length(payload))
        end
    end
    setfield!(buf, :len, Csize_t(total_len))

    send_result = channel_slot_send_message(slot, msg, ChannelDirection.WRITE)
    if send_result isa ErrorResult
        channel_release_message_to_pool!(channel, msg)
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_WRITE_FAILURE, "TLS output send failed")
        return nothing
    end

    return nothing
end

function _tls_send_client_hello!(handler::TlsChannelHandler)
    handler.state == TlsHandshakeState.INIT || return nothing
    rnd_buf = ByteBuffer(TLS_NONCE_LEN)
    device_random_buffer_append(Ref(rnd_buf), Csize_t(TLS_NONCE_LEN))
    client_random = Memory{UInt8}(undef, TLS_NONCE_LEN)
    unsafe_copyto!(pointer(client_random), pointer(getfield(rnd_buf, :mem)), TLS_NONCE_LEN)
    handler.client_random = client_random
    handler.state = TlsHandshakeState.CLIENT_HELLO_SENT
    _tls_send_record!(handler, TLS_HANDSHAKE_CLIENT_HELLO, client_random)
    return nothing
end

function _tls_send_server_hello!(handler::TlsChannelHandler)
    rnd_buf = ByteBuffer(TLS_NONCE_LEN)
    device_random_buffer_append(Ref(rnd_buf), Csize_t(TLS_NONCE_LEN))
    server_random = Memory{UInt8}(undef, TLS_NONCE_LEN)
    unsafe_copyto!(pointer(server_random), pointer(getfield(rnd_buf, :mem)), TLS_NONCE_LEN)
    handler.server_random = server_random
    _tls_send_record!(handler, TLS_HANDSHAKE_SERVER_HELLO, server_random)
    return nothing
end

function _tls_mark_negotiated!(handler::TlsChannelHandler)
    handler.negotiation_completed = true
    handler.state = TlsHandshakeState.NEGOTIATED
    _tls_mark_handshake_end!(handler, TlsNegotiationStatus.SUCCESS)
    handler.protocol = _tls_select_alpn_protocol(handler.options)
    if !_tls_send_alpn_message!(handler)
        return nothing
    end
    if handler.options.on_negotiation_result !== nothing && handler.slot !== nothing
        _tls_invoke_on_event_loop(
            handler,
            handler.options.on_negotiation_result,
            handler,
            handler.slot,
            AWS_OP_SUCCESS,
            handler.options.user_data,
        )
    end
    _tls_flush_pending_writes!(handler)
    return nothing
end

function _tls_handle_handshake!(handler::TlsChannelHandler, record_type::UInt8, payload::AbstractVector{UInt8})
    if record_type == TLS_HANDSHAKE_CLIENT_HELLO
        if !handler.options.ctx.options.is_server || handler.state != TlsHandshakeState.INIT
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE, "Unexpected client hello")
            return nothing
        end
        _tls_mark_handshake_start!(handler)
        if length(payload) != TLS_NONCE_LEN
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE, "Invalid client hello size")
            return nothing
        end
        handler.client_random = Memory{UInt8}(payload)
        _tls_send_server_hello!(handler)
        handler.session_key = _derive_session_key(handler.client_random, handler.server_random)
        if isempty(handler.session_key)
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE, "Session key derivation failed")
            return nothing
        end
        _tls_mark_negotiated!(handler)
        return nothing
    end

    if record_type == TLS_HANDSHAKE_SERVER_HELLO
        if handler.options.ctx.options.is_server || handler.state != TlsHandshakeState.CLIENT_HELLO_SENT
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE, "Unexpected server hello")
            return nothing
        end
        if length(payload) != TLS_NONCE_LEN
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE, "Invalid server hello size")
            return nothing
        end
        handler.server_random = Memory{UInt8}(payload)
        handler.session_key = _derive_session_key(handler.client_random, handler.server_random)
        if isempty(handler.session_key)
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE, "Session key derivation failed")
            return nothing
        end
        _tls_mark_negotiated!(handler)
        return nothing
    end

    _tls_report_error!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE, "Unknown handshake message")
    return nothing
end

function _tls_handle_application!(handler::TlsChannelHandler, payload::AbstractVector{UInt8})
    if !handler.negotiation_completed
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_READ_FAILURE, "Application data before negotiation")
        return nothing
    end

    if length(payload) < TLS_MAC_LEN
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_READ_FAILURE, "Invalid TLS record size")
        return nothing
    end

    mac = payload[1:TLS_MAC_LEN]
    cipher = payload[(TLS_MAC_LEN + 1):end]
    plaintext = _xor_with_key(cipher, handler.session_key)
    calc_mac = _hmac_sha256(handler.session_key, plaintext)

    if isempty(calc_mac) || !_const_time_eq(mac, calc_mac)
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_READ_FAILURE, "TLS record MAC mismatch")
        return nothing
    end

    slot = handler.slot
    if slot === nothing || slot.channel === nothing
        return nothing
    end

    channel = slot.channel
    msg = channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, length(plaintext))
    if msg === nothing
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_READ_FAILURE, "TLS read alloc failed")
        return nothing
    end

    buf_ref = Ref(msg.message_data)
    byte_buf_reserve(buf_ref, length(plaintext))
    msg.message_data = buf_ref[]
    buf = msg.message_data

    GC.@preserve buf begin
        unsafe_copyto!(pointer(getfield(buf, :mem)), pointer(plaintext), length(plaintext))
    end
    setfield!(buf, :len, Csize_t(length(plaintext)))

    if handler.options.on_data_read !== nothing
        _tls_invoke_on_event_loop(handler, handler.options.on_data_read, handler, slot, buf, handler.options.user_data)
    end

    if slot.adj_right !== nothing
        send_result = channel_slot_send_message(slot, msg, ChannelDirection.READ)
        if send_result isa ErrorResult
            channel_release_message_to_pool!(channel, msg)
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_READ_FAILURE, "TLS read send failed")
            return nothing
        end
    else
        channel_release_message_to_pool!(channel, msg)
    end

    return nothing
end

function _tls_handle_alert!(handler::TlsChannelHandler, payload::AbstractVector{UInt8})
    if length(payload) < 2
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_ALERT_RECEIVED, "TLS alert received")
        return nothing
    end
    level = payload[1]
    description = payload[2]
    if level == TLS_ALERT_LEVEL_WARNING && description == TLS_ALERT_CLOSE_NOTIFY
        _tls_report_error!(handler, ERROR_IO_TLS_CLOSED_GRACEFUL, "TLS close notify")
        return nothing
    end
    _tls_report_error!(handler, ERROR_IO_TLS_ALERT_NOT_GRACEFUL, "TLS alert")
    return nothing
end

function _tls_process_inbound!(handler::TlsChannelHandler)
    buf = handler.inbound_buf
    while true
        available = length(buf) - handler.inbound_offset
        if available < TLS_RECORD_HEADER_LEN
            break
        end

        idx = handler.inbound_offset + 1
        record_type = buf[idx]
        len = (UInt32(buf[idx + 1]) << 24) |
            (UInt32(buf[idx + 2]) << 16) |
            (UInt32(buf[idx + 3]) << 8) |
            UInt32(buf[idx + 4])
        total_len = TLS_RECORD_HEADER_LEN + Int(len)
        if available < total_len
            break
        end

        payload_start = idx + TLS_RECORD_HEADER_LEN
        payload_end = payload_start + Int(len) - 1
        payload = Int(len) == 0 ? UInt8[] : Vector{UInt8}(view(buf, payload_start:payload_end))
        handler.inbound_offset += total_len

        if record_type == TLS_RECORD_APPLICATION
            _tls_handle_application!(handler, payload)
        elseif record_type == TLS_RECORD_ALERT
            _tls_handle_alert!(handler, payload)
        else
            _tls_handle_handshake!(handler, record_type, payload)
        end
    end

    if handler.inbound_offset > 0
        if handler.inbound_offset >= length(buf)
            empty!(buf)
            handler.inbound_offset = 0
        elseif handler.inbound_offset > 4096
            handler.inbound_buf = buf[(handler.inbound_offset + 1):end]
            handler.inbound_offset = 0
        end
    end

    return nothing
end

function _tls_encrypt_message(handler::TlsChannelHandler, message::IoMessage)
    slot = handler.slot
    if slot === nothing || slot.channel === nothing
        return nothing
    end

    channel = slot.channel
    buf = message.message_data
    total = Int(buf.len)
    if total == 0
        channel_release_message_to_pool!(channel, message)
        return nothing
    end

    plaintext = Memory{UInt8}(undef, total)
    GC.@preserve buf begin
        unsafe_copyto!(pointer(plaintext), pointer(getfield(buf, :mem)), total)
    end

    mac = _hmac_sha256(handler.session_key, plaintext)
    if isempty(mac)
        channel_release_message_to_pool!(channel, message)
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_WRITE_FAILURE, "TLS HMAC failed")
        return nothing
    end

    cipher = _xor_with_key(plaintext, handler.session_key)
    record_payload = vcat(mac, cipher)
    _tls_send_record!(handler, TLS_RECORD_APPLICATION, record_payload)
    channel_release_message_to_pool!(channel, message)
    return nothing
end

function _tls_flush_pending_writes!(handler::TlsChannelHandler)
    if isempty(handler.pending_writes)
        return nothing
    end

    for pending in handler.pending_writes
        _tls_encrypt_message(handler, pending.message)
    end
    empty!(handler.pending_writes)
    return nothing
end

function handler_process_read_message(handler::TlsChannelHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    channel = slot.channel
    if handler.read_state == TlsHandlerReadState.SHUT_DOWN_COMPLETE
        if channel !== nothing
            channel_release_message_to_pool!(channel, message)
        end
        return nothing
    end
    buf = message.message_data
    data_len = Int(buf.len)

    if data_len > 0
        start = length(handler.inbound_buf) + 1
        resize!(handler.inbound_buf, length(handler.inbound_buf) + data_len)
        GC.@preserve buf begin
            unsafe_copyto!(pointer(handler.inbound_buf, start), pointer(getfield(buf, :mem)), data_len)
        end
    end

    if channel !== nothing
        channel_release_message_to_pool!(channel, message)
    end

    _tls_process_inbound!(handler)
    return nothing
end

function handler_process_write_message(handler::TlsChannelHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    if handler.state == TlsHandshakeState.FAILED
        if slot.channel !== nothing
            channel_release_message_to_pool!(slot.channel, message)
        end
        raise_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
        return ErrorResult(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
    end
    if !handler.negotiation_completed
        push!(handler.pending_writes, PendingWrite(message, 0))
        return nothing
    end

    _tls_encrypt_message(handler, message)
    return nothing
end

function handler_increment_read_window(handler::TlsChannelHandler, slot::ChannelSlot, size::Csize_t)::Union{Nothing, ErrorResult}
    return channel_slot_increment_read_window!(slot, size)
end

function handler_shutdown(
        handler::TlsChannelHandler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Union{Nothing, ErrorResult}
    if direction == ChannelDirection.READ && handler.read_state != TlsHandlerReadState.SHUT_DOWN_COMPLETE
        handler.read_state = TlsHandlerReadState.SHUT_DOWN_COMPLETE
    end
    if !isempty(handler.pending_writes)
        channel = slot.channel
        if channel !== nothing
            for pending in handler.pending_writes
                channel_release_message_to_pool!(channel, pending.message)
            end
        end
        empty!(handler.pending_writes)
    end
    if !handler.negotiation_completed && handler.options.on_negotiation_result !== nothing
        _tls_invoke_on_event_loop(
            handler,
            handler.options.on_negotiation_result,
            handler,
            slot,
            error_code,
            handler.options.user_data,
        )
    end
    channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    return nothing
end

function handler_initial_window_size(handler::TlsChannelHandler)::Csize_t
    return SIZE_MAX
end

function handler_message_overhead(handler::TlsChannelHandler)::Csize_t
    return Csize_t(0)
end

function handler_destroy(handler::TlsChannelHandler)::Nothing
    return nothing
end

function handler_reset_statistics(handler::TlsChannelHandler)::Nothing
    crt_statistics_tls_reset!(handler.stats)
    return nothing
end

function handler_gather_statistics(handler::TlsChannelHandler)::TlsHandlerStatistics
    return handler.stats
end

function handler_trigger_write(handler::TlsChannelHandler)::Nothing
    _tls_flush_pending_writes!(handler)
    return nothing
end
