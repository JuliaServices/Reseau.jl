# AWS IO Library - TLS Channel Handler

using LibAwsCal
using LibAwsCommon
using Libdl

# TLS callback types — closures capture context for trim-safe dispatch
# on_negotiation_result: (handler, slot, error_code) -> nothing
# on_data_read: (handler, slot, buffer) -> nothing
# on_error: (handler, slot, error_code, message) -> nothing

const TLS_DEFAULT_TIMEOUT_MS = 10_000
const TLS_MAX_RECORD_SIZE = 16 * 1024
const TLS_EST_RECORD_OVERHEAD = 53
const TLS_EST_HANDSHAKE_SIZE = 7 * 1024

# The TLS backends and PKI utilities currently assume PEM-like text content.
# Historically, `text_is_utf8()` in `src/common/encoding.jl` only accepted ASCII,
# plus a UTF-8 BOM prefix. Keep that exact behavior here so we can delete the
# broader encoding helpers.
function _tls_text_is_ascii_or_utf8_bom(cursor::ByteCursor)::Bool
    n = Int(cursor.len)
    if n >= 3
        @inbounds begin
            b0 = memoryref(cursor.ptr, 1)[]
            b1 = memoryref(cursor.ptr, 2)[]
            b2 = memoryref(cursor.ptr, 3)[]
        end
        if b0 == 0xef && b1 == 0xbb && b2 == 0xbf
            return true
        end
    end
    @inbounds for i in 1:n
        if (memoryref(cursor.ptr, i)[] & 0x80) != 0
            return false
        end
    end
    return true
end

struct TlsCtxPkcs11Options
    pkcs11_lib::Pkcs11Lib
    user_pin::ByteCursor
    slot_id::Union{UInt64, Nothing}
    token_label::ByteCursor
    private_key_object_label::ByteCursor
    cert_file_path::ByteCursor
    cert_file_contents::ByteCursor
end

mutable struct Pkcs11KeyOpState <: AbstractPkcs11KeyOpState
    pkcs11_lib::Pkcs11Lib
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

function _pkcs11_key_op_state_close!(state::Pkcs11KeyOpState)::Nothing
    state.closed && return nothing
    state.closed = true
    if state.session_handle != CK_SESSION_HANDLE(0)
        try; pkcs11_lib_close_session(state.pkcs11_lib, state.session_handle); catch; end
    end
    pkcs11_lib_release(state.pkcs11_lib)
    state.session_handle = CK_SESSION_HANDLE(0)
    return nothing
end

@inline function custom_key_op_handler_release(handler::CustomKeyOpHandler{Pkcs11KeyOpState})::Nothing
    _pkcs11_key_op_state_close!(handler.pkcs11_state)
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
    )::CustomKeyOpHandler
    if pkcs11_lib === nothing
        throw_error(ERROR_INVALID_ARGUMENT)
    end
    if !(pkcs11_lib isa Pkcs11Lib)
        throw_error(ERROR_INVALID_ARGUMENT)
    end

    lib = pkcs11_lib_acquire(pkcs11_lib)

    match_label = token_label.len > 0 ? token_label : nothing
    local selected_slot::UInt64
    try
        selected_slot = pkcs11_lib_find_slot_with_token(lib, slot_id, match_label)
    catch
        pkcs11_lib_release(lib)
        rethrow()
    end

    local session_handle::CK_SESSION_HANDLE
    try
        session_handle = pkcs11_lib_open_session(lib, selected_slot)
    catch
        pkcs11_lib_release(lib)
        rethrow()
    end

    pin_cursor = user_pin.len > 0 ? user_pin : nothing
    try
        pkcs11_lib_login_user(lib, session_handle, pin_cursor)
    catch
        try; pkcs11_lib_close_session(lib, session_handle); catch; end
        pkcs11_lib_release(lib)
        rethrow()
    end

    key_label = private_key_object_label.len > 0 ? private_key_object_label : nothing
    local key_handle::CK_OBJECT_HANDLE
    local key_type::CK_KEY_TYPE
    try
        key_handle, key_type = pkcs11_lib_find_private_key(lib, session_handle, key_label)
    catch
        try; pkcs11_lib_close_session(lib, session_handle); catch; end
        pkcs11_lib_release(lib)
        rethrow()
    end

    state = Pkcs11KeyOpState(
        lib,
        user_pin,
        UInt64(selected_slot),
        token_label,
        private_key_object_label,
        session_handle,
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
                try
                    res = pkcs11_lib_decrypt(
                        state.pkcs11_lib,
                        state.session_handle,
                        state.private_key_handle,
                        state.private_key_type,
                        input,
                    )
                    tls_key_operation_complete!(operation, byte_cursor_from_buf(res))
                catch e
                    code = e isa ReseauError ? e.code : ERROR_UNKNOWN
                    tls_key_operation_complete_with_error!(operation, code)
                end
            elseif op_type == TlsKeyOperationType.SIGN
                input = tls_key_operation_get_input(operation)
                digest_alg = tls_key_operation_get_digest_algorithm(operation)
                sig_alg = tls_key_operation_get_signature_algorithm(operation)
                try
                    res = pkcs11_lib_sign(
                        state.pkcs11_lib,
                        state.session_handle,
                        state.private_key_handle,
                        state.private_key_type,
                        input,
                        digest_alg,
                        sig_alg,
                    )
                    tls_key_operation_complete!(operation, byte_cursor_from_buf(res))
                catch e
                    code = e isa ReseauError ? e.code : ERROR_UNKNOWN
                    tls_key_operation_complete_with_error!(operation, code)
                end
            else
                tls_key_operation_complete_with_error!(operation, ERROR_UNIMPLEMENTED)
            end
        end
    end
    return CustomKeyOpHandler(on_op; pkcs11_state = state)
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

const _tls_cal_init_lock = ReentrantLock()
const _tls_cal_initialized = Ref(false)
const _tls_use_secitem = Ref(false)
const _tls_use_secitem_override = Ref{Union{Bool, Nothing}}(nothing)

@inline function _env_truthy(val::AbstractString)::Bool
    isempty(val) && return false
    return val == "1" || val == "true" || val == "yes" || val == "y" || val == "on"
end

function _tls_set_use_secitem_from_env()
    @static if Sys.isapple()
        if _tls_use_secitem_override[] !== nothing
            _tls_use_secitem[] = _tls_use_secitem_override[]
            return nothing
        end
        val = lowercase(get(ENV, "RESEAU_USE_SECITEM", ""))
        enabled = if !isempty(val)
            _env_truthy(val)
        else
            false
        end
        _tls_use_secitem[] = enabled
        if enabled
            logf(LogLevel.INFO, LS_IO_TLS, "SecItem support enabled on Apple platforms.")
        end
    else
        _tls_use_secitem[] = false
    end
    return nothing
end

function tls_set_use_secitem!(flag::Bool)::Nothing
    @static if Sys.isapple()
        _tls_use_secitem_override[] = flag
        _tls_use_secitem[] = flag
        if flag
            logf(LogLevel.INFO, LS_IO_TLS, "SecItem support enabled on Apple platforms.")
        end
    else
        _tls_use_secitem[] = false
    end
    return nothing
end

function _tls_cal_init_once()
    lock(_tls_cal_init_lock)
    try
        _tls_cal_initialized[] && return nothing
        _cal_init()
        _tls_cal_initialized[] = true
    finally
        unlock(_tls_cal_init_lock)
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

function _tls_buf_copy_from(value)::ByteBuffer
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
        throw_error(ERROR_INVALID_ARGUMENT)
    end

    dest_ref = Ref(null_buffer())
    if byte_buf_init_copy_from_cursor(dest_ref, cursor) != OP_SUCCESS
        throw(ReseauError(last_error()))
    end
    return dest_ref[]
end

function _tls_buf_from_file(path::AbstractString)::ByteBuffer
    bytes = try
        read(path)
    catch e
        if e isa SystemError
            translate_and_raise_io_error_or(e.errnum, ERROR_FILE_READ_FAILURE)
        else
            raise_error(ERROR_FILE_READ_FAILURE)
        end
        throw(ReseauError(last_error()))
    end

    dest_ref = Ref(null_buffer())
    if byte_buf_init_copy_from_cursor(dest_ref, ByteCursor(bytes)) != OP_SUCCESS
        throw(ReseauError(last_error()))
    end
    return dest_ref[]
end

function _tls_validate_pem(buf::ByteBuffer)::Nothing
    if buf.len == 0
        throw_error(ERROR_IO_PEM_MALFORMED)
    end
    data = Memory{UInt8}(undef, Int(buf.len))
    unsafe_copyto!(pointer(data), pointer(buf.mem), Int(buf.len))
    pem_parse(data)
    return nothing
end

function tls_context_new(options::TlsContextOptions)::TlsContext
    tls_init_static_state()
    return _tls_context_new_impl(options)
end

tls_ctx_acquire(ctx::TlsContext) = ctx
tls_ctx_acquire(::Nothing) = nothing
tls_ctx_release(ctx::TlsContext) = _tls_context_release_impl(ctx)
tls_ctx_release(::Nothing) = nothing

function _tls_ctx_options_copy(
        options::TlsContextOptions;
        is_server_override::Union{Bool, Nothing} = nothing,
    )::TlsContextOptions
    ca_buf = _tls_buf_copy_from(options.ca_file)
    cert_buf = try
        _tls_buf_copy_from(options.certificate)
    catch
        byte_buf_clean_up_secure(Ref(ca_buf))
        rethrow()
    end
    key_buf = try
        _tls_buf_copy_from(options.private_key)
    catch
        byte_buf_clean_up_secure(Ref(ca_buf))
        byte_buf_clean_up_secure(Ref(cert_buf))
        rethrow()
    end
    pkcs_buf = try
        _tls_buf_copy_from(options.pkcs12)
    catch
        byte_buf_clean_up_secure(Ref(ca_buf))
        byte_buf_clean_up_secure(Ref(cert_buf))
        byte_buf_clean_up_secure(Ref(key_buf))
        rethrow()
    end
    pkcs_pwd_buf = try
        _tls_buf_copy_from(options.pkcs12_password)
    catch
        byte_buf_clean_up_secure(Ref(ca_buf))
        byte_buf_clean_up_secure(Ref(cert_buf))
        byte_buf_clean_up_secure(Ref(key_buf))
        byte_buf_clean_up_secure(Ref(pkcs_buf))
        rethrow()
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

function tls_client_ctx_new(options::TlsContextOptions)::TlsContext
    if !tls_is_cipher_pref_supported(options.cipher_pref)
        throw_error(ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED)
    end
    opts_copy = _tls_ctx_options_copy(options; is_server_override = false)
    return tls_context_new(opts_copy)
end

function tls_server_ctx_new(options::TlsContextOptions)::TlsContext
    if !tls_is_cipher_pref_supported(options.cipher_pref)
        throw_error(ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED)
    end
    opts_copy = _tls_ctx_options_copy(options; is_server_override = true)
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
        try
            lib = _s2n_lib_handle()
            _ = ccall(_s2n_symbol(:s2n_async_pkey_op_free), Cint, (Ptr{Cvoid},), operation.s2n_op)
        catch
        end
        operation.s2n_op = C_NULL
    end
    operation.s2n_handler = nothing
    operation.input_buf = nothing
    return nothing
end

function _tls_key_operation_completion_task(operation::TlsKeyOperation, status::TaskStatus.T)
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
        try
            lib = _s2n_lib_handle()
            if ccall(_s2n_symbol(:s2n_async_pkey_op_apply), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), operation.s2n_op, handler.connection) !=
                    S2N_SUCCESS
                logf(LogLevel.ERROR, LS_IO_TLS, "Failed applying s2n async pkey op")
                operation.completion_error_code = ERROR_INVALID_STATE
            end
        catch
            operation.completion_error_code = ERROR_INVALID_STATE
        end
    end

    if operation.completion_error_code == 0
        _ = _s2n_drive_negotiation(handler)
    else
        slot = handler.slot
        if slot !== nothing && channel_slot_is_attached(slot)
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
    local out_buf::ByteBuffer = null_buffer()
    local out_buf_failed::Bool = false
    if output !== nothing
        try
            out_buf = _tls_buf_copy_from(output)
        catch e
            error_code = e isa ReseauError ? e.code : ERROR_UNKNOWN
            out_buf_failed = true
        end
    end

    if !out_buf_failed
        operation.output = out_buf
    end

    if output !== nothing && !out_buf_failed && operation.s2n_op != C_NULL
        try
            lib = _s2n_lib_handle()
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
        catch
            error_code = ERROR_INVALID_STATE
        end
    end

    operation.completed = true
    operation.error_code = error_code
    operation.completion_error_code = error_code

    if operation.s2n_op != C_NULL && operation.s2n_handler !== nothing
        handler = operation.s2n_handler
        if handler isa S2nTlsHandler && handler.slot !== nothing && channel_slot_is_attached(handler.slot)
            channel_task_init!(
                operation.completion_task,
                EventCallable(s -> _tls_key_operation_completion_task(operation, _coerce_task_status(s))),
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
    return _tls_key_operation_complete_common(operation, OP_SUCCESS, output)
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
        max_fragment_size::Integer = g_channel_max_fragment_size[],
    )
    @static if Sys.isapple()
        _tls_set_use_secitem_from_env()
    end
    secitem_options = (Sys.isapple() && is_using_secitem()) ?
        SecItemOptions("aws-crt-default-certificate-label", "aws-crt-default-key-label") : nothing
    ca_file_buf = ca_file === nothing ? null_buffer() : ca_file
    ca_file_set = ca_file !== nothing
    return TlsContextOptions(
        false, # is_server
        minimum_tls_version,
        cipher_pref,
        ca_file_buf,
        ca_file_set,
        ca_path,
        alpn_list,
        null_buffer(), # certificate
        false,         # certificate_set
        null_buffer(), # private_key
        false,         # private_key_set
        nothing,       # system_certificate_path
        null_buffer(), # pkcs12
        false,         # pkcs12_set
        null_buffer(), # pkcs12_password
        false,         # pkcs12_password_set
        secitem_options,
        nothing, # keychain_path
        Csize_t(max_fragment_size),
        verify_peer,
        nothing, # ctx_options_extension
        nothing, # custom_key_op_handler
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
    )::Nothing
    if options.ca_file_set
        throw_error(ERROR_INVALID_STATE)
    end
    ca_buf = _tls_buf_copy_from(ca_file)
    try
        _tls_validate_pem(ca_buf)
    catch
        byte_buf_clean_up_secure(Ref(ca_buf))
        rethrow()
    end
    options.ca_file = ca_buf
    options.ca_file_set = true
    return nothing
end

function tls_ctx_options_override_default_trust_store_from_path!(
        options::TlsContextOptions;
        ca_path::Union{String, Nothing} = nothing,
        ca_file::Union{String, Nothing} = nothing,
    )::Nothing
    if ca_path !== nothing && options.ca_path !== nothing
        throw_error(ERROR_INVALID_STATE)
    end
    if ca_file !== nothing && options.ca_file_set
        throw_error(ERROR_INVALID_STATE)
    end

    if ca_path !== nothing
        options.ca_path = ca_path
    end

    if ca_file !== nothing
        ca_buf = _tls_buf_from_file(ca_file)
        try
            _tls_validate_pem(ca_buf)
        catch
            byte_buf_clean_up_secure(Ref(ca_buf))
            rethrow()
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

function tls_ctx_options_init_client_mtls(cert, pkey)::TlsContextOptions
    opts = tls_ctx_options_init_default_client()
    try
        cert_buf = _tls_buf_copy_from(cert)
        opts.certificate = cert_buf
        opts.certificate_set = true
        _tls_validate_pem(cert_buf)

        key_buf = _tls_buf_copy_from(pkey)
        opts.private_key = key_buf
        opts.private_key_set = true
        _tls_validate_pem(key_buf)
    catch
        tls_ctx_options_clean_up!(opts)
        rethrow()
    end

    return opts
end

function tls_ctx_options_init_client_mtls_from_path(
        cert_path::AbstractString,
        pkey_path::AbstractString,
    )::TlsContextOptions
    opts = tls_ctx_options_init_default_client()
    try
        cert_buf = _tls_buf_from_file(cert_path)
        opts.certificate = cert_buf
        opts.certificate_set = true
        _tls_validate_pem(cert_buf)

        key_buf = _tls_buf_from_file(pkey_path)
        opts.private_key = key_buf
        opts.private_key_set = true
        _tls_validate_pem(key_buf)
    catch
        tls_ctx_options_clean_up!(opts)
        rethrow()
    end

    return opts
end

function tls_ctx_options_init_client_mtls_from_system_path(
        cert_reg_path::AbstractString,
    )::TlsContextOptions
    if !Sys.iswindows()
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end
    opts = tls_ctx_options_init_default_client()
    opts.system_certificate_path = cert_reg_path
    return opts
end

function tls_ctx_options_init_default_server(
        cert,
        pkey;
        alpn_list::Union{String, Nothing} = nothing,
    )::TlsContextOptions
    opts = tls_ctx_options_init_client_mtls(cert, pkey)
    opts.is_server = true
    opts.verify_peer = false
    opts.alpn_list = alpn_list
    return opts
end

function tls_ctx_options_init_default_server_from_path(
        cert_path::AbstractString,
        pkey_path::AbstractString;
        alpn_list::Union{String, Nothing} = nothing,
    )::TlsContextOptions
    opts = tls_ctx_options_init_client_mtls_from_path(cert_path, pkey_path)
    opts.is_server = true
    opts.verify_peer = false
    opts.alpn_list = alpn_list
    return opts
end

function tls_ctx_options_init_default_server_from_system_path(
        cert_reg_path::AbstractString,
    )::TlsContextOptions
    opts = tls_ctx_options_init_client_mtls_from_system_path(cert_reg_path)
    opts.is_server = true
    opts.verify_peer = false
    return opts
end

function tls_ctx_options_init_client_mtls_pkcs12_from_path(
        pkcs12_path::AbstractString,
        pkcs_password,
    )::TlsContextOptions
    if !Sys.isapple()
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end
    opts = tls_ctx_options_init_default_client()
    try
        pkcs_buf = _tls_buf_from_file(pkcs12_path)
        opts.pkcs12 = pkcs_buf
        pwd_buf = _tls_buf_copy_from(pkcs_password)
        opts.pkcs12_password = pwd_buf
    catch
        tls_ctx_options_clean_up!(opts)
        rethrow()
    end
    opts.pkcs12_set = true
    opts.pkcs12_password_set = true
    return opts
end

function tls_ctx_options_init_client_mtls_pkcs12(
        pkcs12,
        pkcs_password,
    )::TlsContextOptions
    if !Sys.isapple()
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end
    opts = tls_ctx_options_init_default_client()
    try
        pkcs_buf = _tls_buf_copy_from(pkcs12)
        opts.pkcs12 = pkcs_buf
        pwd_buf = _tls_buf_copy_from(pkcs_password)
        opts.pkcs12_password = pwd_buf
    catch
        tls_ctx_options_clean_up!(opts)
        rethrow()
    end
    opts.pkcs12_set = true
    opts.pkcs12_password_set = true
    return opts
end

function tls_ctx_options_init_server_pkcs12_from_path(
        pkcs12_path::AbstractString,
        pkcs_password,
    )::TlsContextOptions
    opts = tls_ctx_options_init_client_mtls_pkcs12_from_path(pkcs12_path, pkcs_password)
    opts.is_server = true
    opts.verify_peer = false
    return opts
end

function tls_ctx_options_init_server_pkcs12(
        pkcs12,
        pkcs_password,
    )::TlsContextOptions
    opts = tls_ctx_options_init_client_mtls_pkcs12(pkcs12, pkcs_password)
    opts.is_server = true
    opts.verify_peer = false
    return opts
end

function tls_ctx_options_set_keychain_path!(
        options::TlsContextOptions,
        keychain_path::AbstractString,
    )::Nothing
    if !Sys.isapple()
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end
    if is_using_secitem()
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end
    options.keychain_path = keychain_path
    return nothing
end

function tls_ctx_options_set_secitem_options!(
        options::TlsContextOptions,
        secitem_options::SecItemOptions,
    )::Nothing
    if !Sys.isapple()
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end
    if !is_using_secitem()
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
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
    )::TlsContextOptions
    if custom_key_op_handler === nothing
        throw_error(ERROR_INVALID_ARGUMENT)
    end
    handler = custom_key_op_handler
    if !(handler isa CustomKeyOpHandler) || handler.on_key_operation === nothing
        throw_error(ERROR_INVALID_ARGUMENT)
    end

    opts = tls_ctx_options_init_default_client()
    try
        cert_buf = _tls_buf_copy_from(cert)
        opts.certificate = cert_buf
        opts.certificate_set = true
        _tls_validate_pem(cert_buf)
    catch
        tls_ctx_options_clean_up!(opts)
        rethrow()
    end

    opts.custom_key_op_handler = custom_key_op_handler_acquire(handler)
    return opts
end

function tls_ctx_options_init_client_mtls_with_pkcs11(
        pkcs11_options::TlsCtxPkcs11Options,
    )::TlsContextOptions
    if pkcs11_options.pkcs11_lib === nothing
        throw_error(ERROR_INVALID_ARGUMENT)
    end
    if pkcs11_options.cert_file_path.len > 0 && pkcs11_options.cert_file_contents.len > 0
        throw_error(ERROR_INVALID_ARGUMENT)
    end

    handler = pkcs11_tls_op_handler_new(
        pkcs11_options.pkcs11_lib,
        pkcs11_options.user_pin,
        pkcs11_options.token_label,
        pkcs11_options.private_key_object_label,
        pkcs11_options.slot_id,
    )

    if pkcs11_options.cert_file_contents.len > 0
        return tls_ctx_options_init_client_mtls_with_custom_key_operations(
            handler,
            pkcs11_options.cert_file_contents,
        )
    end

    cert_path = String(pkcs11_options.cert_file_path)
    cert_buf = _tls_buf_from_file(cert_path)

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
        max_fragment_size::Integer = g_channel_max_fragment_size[],
    )
    opts = tls_ctx_options_init_default_client(;
        verify_peer = verify_peer,
        alpn_list = alpn_list,
        minimum_tls_version = minimum_tls_version,
        cipher_pref = cipher_pref,
        max_fragment_size = max_fragment_size,
    )
    if ca_file !== nothing || ca_path !== nothing
        tls_ctx_options_override_default_trust_store_from_path!(opts; ca_path = ca_path, ca_file = ca_file)
    end
    return tls_context_new(opts)
end

function tls_context_new_server(;
        certificate,
        private_key,
        alpn_list::Union{String, Nothing} = nothing,
        minimum_tls_version::TlsVersion.T = TlsVersion.TLS_VER_SYS_DEFAULTS,
        cipher_pref::TlsCipherPref.T = TlsCipherPref.TLS_CIPHER_PREF_SYSTEM_DEFAULT,
        max_fragment_size::Integer = g_channel_max_fragment_size[],
    )
    opts = tls_ctx_options_init_default_server(
        certificate,
        private_key;
        alpn_list = alpn_list,
    )
    opts.minimum_tls_version = minimum_tls_version
    opts.cipher_pref = cipher_pref
    opts.max_fragment_size = Csize_t(max_fragment_size)
    return tls_context_new(opts)
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
        timeout_ms = options.timeout_ms,
    )
end

function tls_connection_options_set_callbacks!(
        options::TlsConnectionOptions,
        on_negotiation_result = nothing,
        on_data_read = nothing,
        on_error = nothing,
    )
    options.on_negotiation_result = _tls_negotiation_result_callback(on_negotiation_result)
    options.on_data_read = _tls_data_read_callback(on_data_read)
    options.on_error = _tls_error_callback(on_error)
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
        on_negotiation_result = nothing,
        on_data_read = nothing,
        on_error = nothing,
    )
    return tls_connection_options_set_callbacks!(
        options,
        on_negotiation_result,
        on_data_read,
        on_error,
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

function _tls_timeout_task(handler, status::TaskStatus.T)
    status == TaskStatus.RUN_READY || return nothing
    handler isa TlsChannelHandler || return nothing
    handler.stats.handshake_status == TlsNegotiationStatus.ONGOING || return nothing
    slot = handler.slot
    slot === nothing && return nothing
    channel_slot_is_attached(slot) || return nothing
    channel = slot.channel
    channel_shutdown!(channel, ERROR_IO_TLS_NEGOTIATION_TIMEOUT)
    return nothing
end

function tls_on_drive_negotiation(handler::TlsChannelHandler)
    if handler.stats.handshake_status == TlsNegotiationStatus.NONE
        handler.stats.handshake_status = TlsNegotiationStatus.ONGOING
        slot = handler.slot
        slot === nothing && return nothing
        channel_slot_is_attached(slot) || return nothing
        channel = slot.channel
        now = channel_current_clock_time(channel)
        handler.stats.handshake_start_ns = now

        if handler.tls_timeout_ms > 0
            timeout_ns = now + timestamp_convert(handler.tls_timeout_ms, TIMESTAMP_MILLIS, TIMESTAMP_NANOS, nothing)
            channel_schedule_task_future!(channel, handler.timeout_task, timeout_ns)
        end
    end
    return nothing
end

function tls_on_negotiation_completed(handler::TlsChannelHandler, error_code::Int)
    handler.stats.handshake_status =
        error_code == OP_SUCCESS ? TlsNegotiationStatus.SUCCESS : TlsNegotiationStatus.FAILURE
    slot = handler.slot
    slot === nothing && return nothing
    channel_slot_is_attached(slot) || return nothing
    channel = slot.channel
    now = channel_current_clock_time(channel)
    handler.stats.handshake_end_ns = now
    return nothing
end

function _tls_backend_init()
    @static if Sys.isapple()
        return _secure_transport_init()
    elseif Sys.islinux()
        return _s2n_init_once()
    else
        return nothing
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

# Backend implementations
include("tls/s2n_tls_handler.jl")
include("tls/secure_transport_tls_handler.jl")

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

function _tls_context_new_impl(options::TlsContextOptions)::TlsContext
    @static if Sys.islinux()
        return _s2n_context_new(options)
    elseif Sys.isapple()
        return _secure_transport_context_new(options)
    else
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
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
    )
    if options.ctx.options.is_server
        throw_error(ERROR_INVALID_ARGUMENT)
    end

    @static if Sys.islinux()
        return _s2n_handler_new(options, slot, S2N_CLIENT)
    elseif Sys.isapple()
        return _secure_transport_handler_new(options, slot, _kSSLClientSide)
    else
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end
end

function tls_server_handler_new(
        options::TlsConnectionOptions,
        slot::ChannelSlot,
    )
    if !options.ctx.options.is_server
        throw_error(ERROR_INVALID_ARGUMENT)
    end

    @static if Sys.islinux()
        return _s2n_handler_new(options, slot, S2N_SERVER)
    elseif Sys.isapple()
        return _secure_transport_handler_new(options, slot, _kSSLServerSide)
    else
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end
end

function tls_client_handler_start_negotiation(handler)::Nothing
    @static if Sys.islinux()
        if !(handler isa S2nTlsHandler)
            throw_error(ERROR_INVALID_STATE)
        end
        slot = handler.slot
        slot !== nothing || throw_error(ERROR_INVALID_STATE)
        channel_slot_is_attached(slot) || throw_error(ERROR_INVALID_STATE)
        if channel_thread_is_callers_thread(slot.channel)
            _ = _s2n_drive_negotiation(handler)
            return nothing
        end
        channel_task_init!(handler.negotiation_task, EventCallable(s -> _s2n_negotiation_task(handler, _coerce_task_status(s))), "s2n_channel_handler_negotiation")
        channel_schedule_task_now!(slot.channel, handler.negotiation_task)
        return nothing
    elseif Sys.isapple()
        if !(handler isa SecureTransportTlsHandler)
            throw_error(ERROR_INVALID_STATE)
        end
        slot = handler.slot
        slot !== nothing || throw_error(ERROR_INVALID_STATE)
        channel_slot_is_attached(slot) || throw_error(ERROR_INVALID_STATE)
        if channel_thread_is_callers_thread(slot.channel)
            _secure_transport_drive_negotiation(handler)
            return nothing
        end
        channel_task_init!(handler.negotiation_task, EventCallable(s -> _secure_transport_negotiation_task(handler, _coerce_task_status(s))), "secure_transport_channel_handler_start_negotiation")
        channel_schedule_task_now!(slot.channel, handler.negotiation_task)
        return nothing
    else
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
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
    )
    channel.last === nothing && throw_error(ERROR_INVALID_STATE)

    tls_slot = channel_slot_new!(channel)

    handler = options.ctx.options.is_server ?
        tls_server_handler_new(options, tls_slot) :
        tls_client_handler_new(options, tls_slot)

    channel_slot_insert_right!(channel.last, tls_slot)
    channel_slot_set_handler!(tls_slot, handler)

    return handler
end

function channel_setup_client_tls(
        right_of_slot::ChannelSlot,
        options::TlsConnectionOptions,
    )
    channel_slot_is_attached(right_of_slot) || throw_error(ERROR_INVALID_STATE)
    channel = right_of_slot.channel

    tls_slot = channel_slot_new!(channel)

    handler = tls_client_handler_new(options, tls_slot)

    channel_slot_insert_right!(right_of_slot, tls_slot)
    channel_slot_set_handler!(tls_slot, handler)

    tls_client_handler_start_negotiation(handler)

    return handler
end
