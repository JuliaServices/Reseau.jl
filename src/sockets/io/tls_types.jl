# AWS IO Library - TLS Core Type Stubs

# Defined early so non-TLS files (socket/bootstrap) can avoid `Any` fields while
# `TlsConnectionOptions` is implemented later in tls_channel_handler.jl.

abstract type AbstractTlsContext end
abstract type AbstractTlsConnectionOptions end

const MaybeTlsConnectionOptions = Union{AbstractTlsConnectionOptions, Nothing}

# Lightweight TLS interface hooks so non-TLS files can stay concretely typed
# without depending on concrete TLS backend structs.
@inline tls_connection_options_server_name(::AbstractTlsConnectionOptions)::Union{String, Nothing} = nothing
@inline tls_connection_options_alpn_list(::AbstractTlsConnectionOptions)::Union{String, Nothing} = nothing
@inline tls_connection_options_context(::AbstractTlsConnectionOptions)::Union{AbstractTlsContext, Nothing} = nothing
@inline tls_context_alpn_list(::AbstractTlsContext)::Union{String, Nothing} = nothing
@inline tls_context_impl(::AbstractTlsContext) = nothing
@inline tls_context_minimum_tls_version_code(::AbstractTlsContext)::UInt8 = UInt8(0x80)
@inline tls_context_verify_peer(::AbstractTlsContext)::Bool = true
@inline tls_context_ca_cert(::AbstractTlsContext)::Ptr{Cvoid} = C_NULL
@inline tls_context_certs(::AbstractTlsContext)::Ptr{Cvoid} = C_NULL
@inline tls_context_secitem_identity(::AbstractTlsContext)::Ptr{Cvoid} = C_NULL
