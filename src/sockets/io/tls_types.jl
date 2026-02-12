# AWS IO Library - TLS Core Type Stubs

# Defined early so non-TLS files (socket/bootstrap) can avoid `Any` fields while
# `TlsConnectionOptions` is implemented later in tls_channel_handler.jl.

abstract type AbstractTlsContext end
abstract type AbstractTlsConnectionOptions end

const MaybeTlsConnectionOptions = Union{AbstractTlsConnectionOptions, Nothing}
