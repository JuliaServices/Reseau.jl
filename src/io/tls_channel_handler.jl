# AWS IO Library - TLS Channel Handler (LibAwsCal-backed)

using LibAwsCal
using LibAwsCommon

const TlsOnNegotiationResultFn = Function  # (handler, slot, error_code, user_data) -> nothing
const TlsOnDataReadFn = Function           # (handler, slot, buffer, user_data) -> nothing
const TlsOnErrorFn = Function              # (handler, slot, error_code, message, user_data) -> nothing

const TLS_HANDSHAKE_CLIENT_HELLO = 0x01
const TLS_HANDSHAKE_SERVER_HELLO = 0x02
const TLS_RECORD_APPLICATION = 0x03
const TLS_RECORD_HEADER_LEN = 5
const TLS_NONCE_LEN = 32
const TLS_MAC_LEN = 32
const TLS_SESSION_KEY_LEN = 32

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

@enumx TlsHandshakeState::UInt8 begin
    INIT = 0
    CLIENT_HELLO_SENT = 1
    NEGOTIATED = 2
    FAILED = 3
end

struct SecItemOptions
    cert_label::Union{String, Nothing}
    key_label::Union{String, Nothing}
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
    key_buf isa ErrorResult && return key_buf
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
    key_buf isa ErrorResult && return key_buf
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
    pwd_buf isa ErrorResult && return pwd_buf
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
    pwd_buf isa ErrorResult && return pwd_buf
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

function tls_ctx_options_init_client_mtls_with_custom_key_operations(
        custom_key_op_handler,
        cert,
    )::Union{TlsContextOptions, ErrorResult}
    _ = custom_key_op_handler
    _ = cert
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
end

function tls_ctx_options_init_client_mtls_with_pkcs11(
        pkcs11_options,
    )::Union{TlsContextOptions, ErrorResult}
    _ = pkcs11_options
    raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
    return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
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
        timeout_ms::Integer = 0,
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

tls_connection_options_init_from_ctx(ctx::TlsContext) = TlsConnectionOptions(ctx)

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
    stats::TlsHandlerStatistics
    protocol::ByteBuffer
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
    return TlsChannelHandler{Union{ChannelSlot, Nothing}}(
        nothing,
        false,
        PendingWrite[],
        Csize_t(max_read_size),
        options,
        TlsHandshakeState.INIT,
        TlsHandlerStatistics(),
        null_buffer(),
        Memory{UInt8}(undef, 0),
        Memory{UInt8}(undef, 0),
        Memory{UInt8}(undef, 0),
        UInt8[],
        0,
    )
end

function tls_channel_handler_new!(channel::Channel, options::TlsConnectionOptions; max_read_size::Integer = 16384)
    handler = TlsChannelHandler(options; max_read_size = max_read_size)
    slot = channel_slot_new!(channel)
    handler.slot = slot
    channel_slot_set_handler!(slot, handler)

    if channel.first !== slot
        channel_slot_insert_end!(channel, slot)
    end

    tls_channel_handler_start_negotiation!(handler)

    return handler
end

function tls_channel_handler_start_negotiation!(handler::TlsChannelHandler)
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

function _tls_report_error!(handler::TlsChannelHandler, error_code::Int, message::AbstractString)
    if !handler.negotiation_completed
        handler.state = TlsHandshakeState.FAILED
        _tls_mark_handshake_end!(handler, TlsNegotiationStatus.FAILURE)
        if handler.options.on_negotiation_result !== nothing && handler.slot !== nothing
            Base.invokelatest(
                handler.options.on_negotiation_result,
                handler,
                handler.slot,
                error_code,
                handler.options.user_data,
            )
        end
    else
        if handler.options.on_error !== nothing && handler.slot !== nothing
            Base.invokelatest(
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

function _tls_mark_handshake_start!(handler::TlsChannelHandler)
    if handler.stats.handshake_start_ns == 0
        ts = Ref{UInt64}()
        if high_res_clock_get_ticks(ts) == OP_SUCCESS
            handler.stats.handshake_start_ns = ts[]
        end
    end
    handler.stats.handshake_status = TlsNegotiationStatus.ONGOING
    return nothing
end

function _tls_mark_handshake_end!(handler::TlsChannelHandler, status::TlsNegotiationStatus.T)
    if handler.stats.handshake_end_ns == 0
        ts = Ref{UInt64}()
        if high_res_clock_get_ticks(ts) == OP_SUCCESS
            handler.stats.handshake_end_ns = ts[]
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
        Base.invokelatest(
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
        Base.invokelatest(handler.options.on_data_read, handler, slot, buf, handler.options.user_data)
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
    if !handler.negotiation_completed && handler.options.on_negotiation_result !== nothing
        Base.invokelatest(handler.options.on_negotiation_result, handler, slot, error_code, handler.options.user_data)
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
