# AWS IO Library - TLS Core Types

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

# TLS handler base type (implemented by backend-specific handlers)
abstract type TlsChannelHandler end

abstract type AbstractPkcs11KeyOpState end

mutable struct CustomKeyOpHandler{S <: Union{AbstractPkcs11KeyOpState, Nothing}}
    on_key_operation::Union{Function, Nothing}
    pkcs11_state::S
end

function CustomKeyOpHandler(
        on_key_operation;
        pkcs11_state::Union{AbstractPkcs11KeyOpState, Nothing} = nothing,
    )
    return CustomKeyOpHandler{typeof(pkcs11_state)}(on_key_operation, pkcs11_state)
end

custom_key_op_handler_acquire(handler::CustomKeyOpHandler) = handler
@inline function custom_key_op_handler_release(handler::Union{Nothing, CustomKeyOpHandler})::Nothing
    return _custom_key_op_handler_release(handler)
end

@inline _custom_key_op_handler_release(::Nothing)::Nothing = nothing
@inline _custom_key_op_handler_release(::CustomKeyOpHandler{Nothing})::Nothing = nothing
@inline function _custom_key_op_handler_release(handler::CustomKeyOpHandler{S})::Nothing where {S <: AbstractPkcs11KeyOpState}
    _pkcs11_key_op_state_close!(handler.pkcs11_state)
    return nothing
end

function custom_key_op_handler_perform_operation(handler::CustomKeyOpHandler, operation)
    if handler.on_key_operation !== nothing
        handler.on_key_operation(handler, operation)
    end
    return nothing
end

struct SecItemOptions
    cert_label::Union{String, Nothing}
    key_label::Union{String, Nothing}
end

function _tls_generate_secitem_labels()::SecItemOptions
    uuid_str = string(UUIDs.uuid4())
    return SecItemOptions("reseau-cert-$uuid_str", "reseau-key-$uuid_str")
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
    # late-init: starts nothing, mutated to extension data or CustomKeyOpHandler
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
        max_fragment_size::Integer = g_channel_max_fragment_size[],
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

@inline tls_context_alpn_list(ctx::TlsContext)::Union{String, Nothing} = ctx.options.alpn_list
@inline tls_context_impl(ctx::TlsContext) = ctx.impl
@inline tls_context_minimum_tls_version_code(ctx::TlsContext)::UInt8 = UInt8(ctx.options.minimum_tls_version)
@inline tls_context_verify_peer(ctx::TlsContext)::Bool = ctx.options.verify_peer
@inline tls_context_ca_cert(ctx::TlsContext)::Ptr{Cvoid} = C_NULL
@inline tls_context_certs(ctx::TlsContext)::Ptr{Cvoid} = C_NULL
@inline tls_context_secitem_identity(ctx::TlsContext)::Ptr{Cvoid} = C_NULL

mutable struct TlsConnectionOptions
    ctx::TlsContext
    server_name::Union{String, Nothing}
    alpn_list::Union{String, Nothing}
    advertise_alpn_message::Bool
    on_negotiation_result::Union{TlsNegotiationResultCallback, Nothing}
    on_data_read::Union{TlsDataReadCallback, Nothing}
    on_error::Union{TlsErrorCallback, Nothing}
    timeout_ms::UInt32
end

@inline tls_connection_options_server_name(options::TlsConnectionOptions)::Union{String, Nothing} = options.server_name
@inline tls_connection_options_alpn_list(options::TlsConnectionOptions)::Union{String, Nothing} = options.alpn_list
@inline tls_connection_options_context(options::TlsConnectionOptions)::Union{TlsContext, Nothing} = options.ctx

@inline _tls_negotiation_result_callback(::Nothing) = nothing
@inline _tls_negotiation_result_callback(callback::TlsNegotiationResultCallback) = callback
@inline _tls_negotiation_result_callback(callback) = TlsNegotiationResultCallback(callback)

@inline _tls_data_read_callback(::Nothing) = nothing
@inline _tls_data_read_callback(callback::TlsDataReadCallback) = callback
@inline _tls_data_read_callback(callback) = TlsDataReadCallback(callback)

@inline _tls_error_callback(::Nothing) = nothing
@inline _tls_error_callback(callback::TlsErrorCallback) = callback
@inline _tls_error_callback(callback) = TlsErrorCallback(callback)

function TlsConnectionOptions(
        ctx::TlsContext;
        server_name::Union{String, Nothing} = nothing,
        alpn_list::Union{String, Nothing} = ctx.options.alpn_list,
        advertise_alpn_message::Bool = false,
        on_negotiation_result = nothing,
        on_data_read = nothing,
        on_error = nothing,
        timeout_ms::Integer = 10_000,
    )
    return TlsConnectionOptions(
        ctx,
        server_name,
        alpn_list,
        advertise_alpn_message,
        _tls_negotiation_result_callback(on_negotiation_result),
        _tls_data_read_callback(on_data_read),
        _tls_error_callback(on_error),
        UInt32(timeout_ms),
    )
end

@inline function _tls_connection_options_with_negotiation(
        options::TlsConnectionOptions,
        advertise_alpn_message::Bool,
        on_negotiation_result::Union{TlsNegotiationResultCallback, Nothing},
    )::TlsConnectionOptions
    return TlsConnectionOptions(
        options.ctx,
        options.server_name,
        options.alpn_list,
        options.advertise_alpn_message || advertise_alpn_message,
        on_negotiation_result,
        options.on_data_read,
        options.on_error,
        options.timeout_ms,
    )
end

const MaybeTlsConnectionOptions = Union{TlsConnectionOptions, Nothing}
