"""
    TLS

TLS client/server layer built on OpenSSL and `TCP` connections.
"""
module TLS

using OpenSSL_jll
using NetworkOptions
using EnumX: @enumx
using ..Reseau.IOPoll
using ..Reseau.TCP
using ..Reseau.HostResolvers

const _LIBSSL = OpenSSL_jll.libssl
const _LIBCRYPTO = OpenSSL_jll.libcrypto

const _SSL_VERIFY_NONE = Cint(0)
const _SSL_VERIFY_PEER = Cint(1)
const _SSL_VERIFY_FAIL_IF_NO_PEER_CERT = Cint(2)
const _SSL_FILETYPE_PEM = Cint(1)

const _SSL_ERROR_NONE = Cint(0)
const _SSL_ERROR_SSL = Cint(1)
const _SSL_ERROR_WANT_READ = Cint(2)
const _SSL_ERROR_WANT_WRITE = Cint(3)
const _SSL_ERROR_SYSCALL = Cint(5)
const _SSL_ERROR_ZERO_RETURN = Cint(6)
const _SSL_SELECT_NEXT_NEGOTIATED = Cint(1)
const _SSL_TLSEXT_ERR_OK = Cint(0)
const _SSL_TLSEXT_ERR_NOACK = Cint(3)
const _HAS_SSL_SET1_IP_ASC = Ref(false)
const _HAS_SSL_CTX_SET_MIN_PROTO_VERSION = Ref(false)
const _HAS_SSL_CTX_SET_MAX_PROTO_VERSION = Ref(false)
const _VERIFY_ALLOW_ALL_CB = Ref{Ptr{Cvoid}}(C_NULL)
const _ALPN_SELECT_CB = Ref{Ptr{Cvoid}}(C_NULL)
const _SSL_CTRL_SET_TLSEXT_HOSTNAME = Cint(55)
const _TLSEXT_NAMETYPE_HOST_NAME = Clong(0)
const _ERRNO_EAGAIN = Int32(Base.Libc.EAGAIN)
const _ERRNO_EWOULDBLOCK = _ERRNO_EAGAIN

const _SSL_OP_NO_TLSv1 = Culong(0x04000000)
const _SSL_OP_NO_TLSv1_1 = Culong(0x10000000)
const _SSL_OP_NO_TLSv1_2 = Culong(0x08000000)
const _SSL_OP_NO_TLSv1_3 = Culong(0x20000000)

const TLS1_0_VERSION = UInt16(0x0301)
const TLS1_1_VERSION = UInt16(0x0302)
const TLS1_2_VERSION = UInt16(0x0303)
const TLS1_3_VERSION = UInt16(0x0304)

@enumx ClientAuthMode::UInt8 begin
    NoClientCert = 0
    RequestClientCert = 1
    RequireAnyClientCert = 2
    VerifyClientCertIfGiven = 3
    RequireAndVerifyClientCert = 4
end

"""
    ConfigError

Raised when TLS configuration is invalid.
"""
struct ConfigError <: Exception
    message::String
end

"""
    TLSError

Raised when TLS handshake/read/write/close operations fail.
"""
struct TLSError <: Exception
    op::String
    code::Int32
    message::String
    cause::Union{Nothing, Exception}
end

"""
    TLSHandshakeTimeoutError

Raised when handshake exceeds the configured timeout.
"""
struct TLSHandshakeTimeoutError <: Exception
    timeout_ns::Int64
end

function Base.showerror(io::IO, err::ConfigError)
    print(io, "tls config error: ", err.message)
    return nothing
end

function Base.showerror(io::IO, err::TLSError)
    print(io, "tls ", err.op, " failed")
    err.code != 0 && print(io, " (code=", err.code, ")")
    !isempty(err.message) && print(io, ": ", err.message)
    if err.cause !== nothing
        print(io, " [")
        showerror(io, err.cause::Exception)
        print(io, "]")
    end
    return nothing
end

function Base.showerror(io::IO, err::TLSHandshakeTimeoutError)
    print(io, "tls handshake timed out after ", err.timeout_ns, " ns")
    return nothing
end

"""
    Config(; ...)

Go-style TLS configuration for client/server TLS sessions.
"""
struct Config
    server_name::Union{Nothing, String}
    verify_peer::Bool
    client_auth::ClientAuthMode.T
    cert_file::Union{Nothing, String}
    key_file::Union{Nothing, String}
    ca_file::Union{Nothing, String}
    client_ca_file::Union{Nothing, String}
    alpn_protocols::Vector{String}
    handshake_timeout_ns::Int64
    min_version::Union{Nothing, UInt16}
    max_version::Union{Nothing, UInt16}
end

struct _SSLContextKey
    is_server::Bool
    verify_peer::Bool
    client_auth::ClientAuthMode.T
    cert_file::Union{Nothing, String}
    key_file::Union{Nothing, String}
    ca_file::Union{Nothing, String}
    client_ca_file::Union{Nothing, String}
    alpn_protocols_key::String
    min_version::Union{Nothing, UInt16}
    max_version::Union{Nothing, UInt16}
end

mutable struct _ALPNServerData
    wire::Vector{UInt8}
end

const _CTX_CACHE_LOCK = ReentrantLock()
const _CTX_CACHE = Dict{_SSLContextKey, Ptr{Cvoid}}()
const _CTX_CACHE_ORDER = _SSLContextKey[]
const _CTX_CACHE_MAX = Ref(128)
const _CTX_SERVER_ALPN = Dict{Ptr{Cvoid}, _ALPNServerData}()

function Config(;
        server_name::Union{Nothing, AbstractString} = nothing,
        verify_peer::Bool = true,
        client_auth::ClientAuthMode.T = ClientAuthMode.NoClientCert,
        cert_file::Union{Nothing, AbstractString} = nothing,
        key_file::Union{Nothing, AbstractString} = nothing,
        ca_file::Union{Nothing, AbstractString} = nothing,
        client_ca_file::Union{Nothing, AbstractString} = nothing,
        alpn_protocols::Vector{String} = String[],
        handshake_timeout_ns::Integer = Int64(0),
        min_version::Union{Nothing, UInt16} = TLS1_2_VERSION,
        max_version::Union{Nothing, UInt16} = nothing,
    )
    server_name_s = server_name === nothing ? nothing : String(server_name)
    cert_file_s = cert_file === nothing ? nothing : String(cert_file)
    key_file_s = key_file === nothing ? nothing : String(key_file)
    ca_file_s = ca_file === nothing ? nothing : String(ca_file)
    client_ca_file_s = client_ca_file === nothing ? nothing : String(client_ca_file)
    has_cert = cert_file_s !== nothing
    has_key = key_file_s !== nothing
    has_cert == has_key || throw(ConfigError("both `cert_file` and `key_file` must be set together"))
    handshake_timeout_ns < 0 && throw(ConfigError("handshake_timeout_ns must be >= 0"))
    return Config(
        server_name_s,
        verify_peer,
        client_auth,
        cert_file_s,
        key_file_s,
        ca_file_s,
        client_ca_file_s,
        copy(alpn_protocols),
        Int64(handshake_timeout_ns),
        min_version,
        max_version,
    )
end

@inline function _default_ca_file_path()::Union{Nothing, String}
    ca_path = try
        NetworkOptions.ca_roots_path()
    catch
        nothing
    end
    ca_path === nothing && return nothing
    ca_path_s = String(ca_path)
    isempty(ca_path_s) && return nothing
    isfile(ca_path_s) || return nothing
    return ca_path_s
end

@inline function _effective_ca_file(config::Config; is_server::Bool)::Union{Nothing, String}
    if is_server
        return config.client_ca_file
    end
    config.ca_file !== nothing && return config.ca_file::String
    return _default_ca_file_path()
end

"""
    ConnectionState

Snapshot of negotiated TLS connection state.
"""
struct ConnectionState
    handshake_complete::Bool
    version::String
    alpn_protocol::Union{Nothing, String}
end

"""
    Conn

TLS stream wrapper over one `TCP.Conn`.
"""
mutable struct Conn
    tcp::TCP.Conn
    ssl_ctx::Ptr{Cvoid}
    ssl::Ptr{Cvoid}
    is_server::Bool
    config::Config
    handshake_lock::ReentrantLock
    read_lock::ReentrantLock
    write_lock::ReentrantLock
    @atomic handshake_complete::Bool
    @atomic closed::Bool
    write_permanent_error::Union{Nothing, TLSError}
end

"""
    Listener

TLS listener wrapper over `TCP.Listener`.
"""
struct Listener
    listener::TCP.Listener
    config::Config
end

"""
    Connector

TLS connector using a `HostResolvers.HostResolver` for the underlying TCP connect.
"""
struct Connector
    host_resolver::HostResolvers.HostResolver
    config::Config
end

function Connector(;
        host_resolver::HostResolvers.HostResolver = HostResolvers.HostResolver(),
        config::Config = Config(),
    )
    return Connector(host_resolver, config)
end

@inline function _verify_allow_all_cb(_preverify_ok::Cint, _store_ctx::Ptr{Cvoid})::Cint
    return Cint(1)
end

function _ssl_alpn_select_cb(
        _ssl::Ptr{Cvoid},
        out::Ptr{Ptr{UInt8}},
        outlen::Ptr{UInt8},
        in::Ptr{UInt8},
        inlen::Cuint,
        arg::Ptr{Cvoid},
    )::Cint
    arg == C_NULL && return _SSL_TLSEXT_ERR_NOACK
    data = unsafe_pointer_to_objref(arg)::_ALPNServerData
    wire = data.wire
    isempty(wire) && return _SSL_TLSEXT_ERR_NOACK
    selected = Ref{Ptr{UInt8}}(C_NULL)
    selected_len = Ref{UInt8}(0)
    rc = GC.@preserve wire ccall(
        (:SSL_select_next_proto, _LIBSSL),
        Cint,
        (Ref{Ptr{UInt8}}, Ref{UInt8}, Ptr{UInt8}, Cuint, Ptr{UInt8}, Cuint),
        selected,
        selected_len,
        pointer(wire),
        Cuint(length(wire)),
        in,
        inlen,
    )
    rc == _SSL_SELECT_NEXT_NEGOTIATED || return _SSL_TLSEXT_ERR_NOACK
    unsafe_store!(out, selected[])
    unsafe_store!(outlen, selected_len[])
    return _SSL_TLSEXT_ERR_OK
end

function __init__()
    _ = ccall((:OPENSSL_init_ssl, _LIBSSL), Cint, (Culong, Ptr{Cvoid}), Culong(0), C_NULL)
    handle = Base.Libc.Libdl.dlopen(_LIBSSL)
    _VERIFY_ALLOW_ALL_CB[] = @cfunction(_verify_allow_all_cb, Cint, (Cint, Ptr{Cvoid}))
    _ALPN_SELECT_CB[] = @cfunction(_ssl_alpn_select_cb, Cint, (Ptr{Cvoid}, Ptr{Ptr{UInt8}}, Ptr{UInt8}, Ptr{UInt8}, Cuint, Ptr{Cvoid}))
    _HAS_SSL_SET1_IP_ASC[] = Base.Libc.Libdl.dlsym_e(handle, :SSL_set1_ip_asc) != C_NULL
    _HAS_SSL_CTX_SET_MIN_PROTO_VERSION[] = Base.Libc.Libdl.dlsym_e(handle, :SSL_CTX_set_min_proto_version) != C_NULL
    _HAS_SSL_CTX_SET_MAX_PROTO_VERSION[] = Base.Libc.Libdl.dlsym_e(handle, :SSL_CTX_set_max_proto_version) != C_NULL
    atexit(_free_ssl_ctx_cache!)
    return nothing
end

@inline function _as_exception(err)::Exception
    return err::Exception
end

@inline function _is_socket_would_block(errno::Int32)::Bool
    return errno == _ERRNO_EAGAIN || errno == _ERRNO_EWOULDBLOCK
end

@inline function _normalize_peer_name(host::AbstractString)::String
    h = String(host)
    if length(h) >= 2 && h[firstindex(h)] == '[' && h[lastindex(h)] == ']'
        h = h[nextind(h, firstindex(h)):prevind(h, lastindex(h))]
    end
    i = findlast(==('%'), h)
    if i !== nothing && i > firstindex(h)
        h = h[firstindex(h):prevind(h, i)]
    end
    while !isempty(h) && h[lastindex(h)] == '.'
        h = h[firstindex(h):prevind(h, lastindex(h))]
    end
    return h
end

@inline function _is_ip_literal_name(name::AbstractString)::Bool
    normalized = _normalize_peer_name(name)
    return HostResolvers._literal_host_addr(normalized) !== nothing
end

@inline function _hostname_in_sni(name::AbstractString)::String
    _is_ip_literal_name(name) && return ""
    return _normalize_peer_name(name)
end

@inline function _verify_name(name::AbstractString)::String
    return _normalize_peer_name(name)
end

@inline function _verify_ip(name::AbstractString)::String
    return _normalize_peer_name(name)
end

function _apply_client_server_name!(ssl::Ptr{Cvoid}, config::Config)
    config.server_name === nothing && return nothing
    configured = config.server_name::String
    verify_name = _verify_name(configured)
    isempty(verify_name) && return nothing
    sni_name = _hostname_in_sni(configured)
    if !isempty(sni_name)
        ok = ccall(
            (:SSL_ctrl, _LIBSSL),
            Clong,
            (Ptr{Cvoid}, Cint, Clong, Cstring),
            ssl,
            _SSL_CTRL_SET_TLSEXT_HOSTNAME,
            _TLSEXT_NAMETYPE_HOST_NAME,
            sni_name,
        )
        ok == 1 || throw(_make_tls_error("SSL_ctrl(SNI)", Int32(ok)))
    end
    if config.verify_peer
        if _is_ip_literal_name(configured)
            ip_verify = _verify_ip(configured)
            if _HAS_SSL_SET1_IP_ASC[]
                ok = ccall(
                    (:SSL_set1_ip_asc, _LIBSSL),
                    Cint,
                    (Ptr{Cvoid}, Cstring),
                    ssl,
                    ip_verify,
                )
                ok == 1 || throw(_make_tls_error("SSL_set1_ip_asc", Int32(ok)))
            else
                ok = ccall(
                    (:SSL_set1_host, _LIBSSL),
                    Cint,
                    (Ptr{Cvoid}, Cstring),
                    ssl,
                    ip_verify,
                )
                ok == 1 || throw(_make_tls_error("SSL_set1_host", Int32(ok)))
            end
        else
            ok = ccall(
                (:SSL_set1_host, _LIBSSL),
                Cint,
                (Ptr{Cvoid}, Cstring),
                ssl,
                verify_name,
            )
            ok == 1 || throw(_make_tls_error("SSL_set1_host", Int32(ok)))
        end
    end
    return nothing
end

function _config_with_server_name(config::Config, server_name::String)::Config
    return Config(
        server_name = server_name,
        verify_peer = config.verify_peer,
        client_auth = config.client_auth,
        cert_file = config.cert_file,
        key_file = config.key_file,
        ca_file = config.ca_file,
        client_ca_file = config.client_ca_file,
        alpn_protocols = config.alpn_protocols,
        handshake_timeout_ns = config.handshake_timeout_ns,
        min_version = config.min_version,
        max_version = config.max_version,
    )
end

function _openssl_error_message()::String
    err_code = ccall((:ERR_get_error, _LIBCRYPTO), Culong, ())
    err_code == Culong(0) && return "OpenSSL error queue is empty"
    buf = Vector{UInt8}(undef, 256)
    GC.@preserve buf begin
        ccall(
            (:ERR_error_string_n, _LIBCRYPTO),
            Cvoid,
            (Culong, Ptr{UInt8}, Csize_t),
            err_code,
            pointer(buf),
            Csize_t(length(buf)),
        )
    end
    nul = findfirst(==(0x00), buf)
    msg_len = nul === nothing ? length(buf) : (nul - 1)
    return String(buf[1:msg_len])
end

function _make_tls_error(op::AbstractString, code::Int32)::TLSError
    return TLSError(String(op), code, _openssl_error_message(), nothing)
end

function _wrap_tls_exception(op::AbstractString, err::Exception)::TLSError
    return TLSError(String(op), Int32(0), "unexpected TLS failure", err)
end

function _encode_alpn_protocols(protocols::Vector{String})::Vector{UInt8}
    out = UInt8[]
    for proto in protocols
        bytes = collect(codeunits(proto))
        isempty(bytes) && throw(ConfigError("ALPN protocol names cannot be empty"))
        length(bytes) > 255 && throw(ConfigError("ALPN protocol names must be at most 255 bytes"))
        push!(out, UInt8(length(bytes)))
        append!(out, bytes)
    end
    return out
end

function _validate_config(config::Config; is_server::Bool)
    has_cert = config.cert_file !== nothing
    has_key = config.key_file !== nothing
    has_cert == has_key || throw(ConfigError("both `cert_file` and `key_file` must be set together"))
    if is_server
        has_cert || throw(ConfigError("server TLS requires `cert_file` and `key_file`"))
        cert_path = config.cert_file::String
        key_path = config.key_file::String
        isfile(cert_path) || throw(ConfigError("certificate file not found: $cert_path"))
        isfile(key_path) || throw(ConfigError("private key file not found: $key_path"))
    else
        if config.verify_peer && (config.server_name === nothing || isempty(config.server_name::String))
            throw(ConfigError("client TLS with `verify_peer=true` requires `server_name`"))
        end
    end
    if config.ca_file !== nothing
        ca_path = config.ca_file::String
        isfile(ca_path) || throw(ConfigError("CA file not found: $ca_path"))
    end
    if config.client_ca_file !== nothing
        client_ca_path = config.client_ca_file::String
        isfile(client_ca_path) || throw(ConfigError("client CA file not found: $client_ca_path"))
    end
    if config.min_version !== nothing && config.max_version !== nothing
        (config.min_version::UInt16) <= (config.max_version::UInt16) || throw(ConfigError("min_version must be <= max_version"))
    end
    return nothing
end

@inline function _server_verify_mode(config::Config)::Cint
    mode = config.client_auth
    mode == ClientAuthMode.NoClientCert && return _SSL_VERIFY_NONE
    mode == ClientAuthMode.RequestClientCert && return _SSL_VERIFY_PEER
    mode == ClientAuthMode.VerifyClientCertIfGiven && return _SSL_VERIFY_PEER
    mode == ClientAuthMode.RequireAnyClientCert && return _SSL_VERIFY_PEER | _SSL_VERIFY_FAIL_IF_NO_PEER_CERT
    mode == ClientAuthMode.RequireAndVerifyClientCert && return _SSL_VERIFY_PEER | _SSL_VERIFY_FAIL_IF_NO_PEER_CERT
    throw(ConfigError("unsupported client auth mode: $mode"))
end

@inline function _server_verify_callback(config::Config)::Ptr{Cvoid}
    mode = config.client_auth
    if mode == ClientAuthMode.RequestClientCert || mode == ClientAuthMode.RequireAnyClientCert
        cb = _VERIFY_ALLOW_ALL_CB[]
        cb == C_NULL && throw(ConfigError("verify callback is not initialized"))
        return cb
    end
    return C_NULL
end

function _free_ssl_ctx_cache!()
    lock(_CTX_CACHE_LOCK)
    try
        for ctx in values(_CTX_CACHE)
            ctx == C_NULL && continue
            ccall((:SSL_CTX_free, _LIBSSL), Cvoid, (Ptr{Cvoid},), ctx)
        end
        empty!(_CTX_CACHE)
        empty!(_CTX_CACHE_ORDER)
        empty!(_CTX_SERVER_ALPN)
    finally
        unlock(_CTX_CACHE_LOCK)
    end
    return nothing
end

function _evict_ssl_ctx_locked!()
    max_entries = _CTX_CACHE_MAX[]
    max_entries < 1 && (max_entries = 1)
    while length(_CTX_CACHE_ORDER) > max_entries
        old_key = popfirst!(_CTX_CACHE_ORDER)
        haskey(_CTX_CACHE, old_key) || continue
        ctx = pop!(_CTX_CACHE, old_key)
        delete!(_CTX_SERVER_ALPN, ctx)
        ctx == C_NULL && continue
        ccall((:SSL_CTX_free, _LIBSSL), Cvoid, (Ptr{Cvoid},), ctx)
    end
    return nothing
end

@inline function _ctx_set_options!(ctx::Ptr{Cvoid}, opts::Culong)
    ccall((:SSL_CTX_set_options, _LIBSSL), Culong, (Ptr{Cvoid}, Culong), ctx, opts)
    return nothing
end

function _set_ctx_min_version!(ctx::Ptr{Cvoid}, version::UInt16)
    if _HAS_SSL_CTX_SET_MIN_PROTO_VERSION[]
        ok = ccall((:SSL_CTX_set_min_proto_version, _LIBSSL), Cint, (Ptr{Cvoid}, Cint), ctx, Cint(version))
        ok == 1 || throw(_make_tls_error("SSL_CTX_set_min_proto_version", Int32(ok)))
        return nothing
    end
    if version <= TLS1_0_VERSION
        return nothing
    elseif version == TLS1_1_VERSION
        _ctx_set_options!(ctx, _SSL_OP_NO_TLSv1)
        return nothing
    elseif version == TLS1_2_VERSION
        _ctx_set_options!(ctx, _SSL_OP_NO_TLSv1 | _SSL_OP_NO_TLSv1_1)
        return nothing
    elseif version == TLS1_3_VERSION
        _ctx_set_options!(ctx, _SSL_OP_NO_TLSv1 | _SSL_OP_NO_TLSv1_1 | _SSL_OP_NO_TLSv1_2)
        return nothing
    end
    throw(ConfigError("unsupported min_version for this TLS backend: $(Int(version))"))
end

function _set_ctx_max_version!(ctx::Ptr{Cvoid}, version::UInt16)
    if _HAS_SSL_CTX_SET_MAX_PROTO_VERSION[]
        ok = ccall((:SSL_CTX_set_max_proto_version, _LIBSSL), Cint, (Ptr{Cvoid}, Cint), ctx, Cint(version))
        ok == 1 || throw(_make_tls_error("SSL_CTX_set_max_proto_version", Int32(ok)))
        return nothing
    end
    if version >= TLS1_3_VERSION
        return nothing
    elseif version == TLS1_2_VERSION
        _ctx_set_options!(ctx, _SSL_OP_NO_TLSv1_3)
        return nothing
    elseif version == TLS1_1_VERSION
        _ctx_set_options!(ctx, _SSL_OP_NO_TLSv1_2 | _SSL_OP_NO_TLSv1_3)
        return nothing
    elseif version <= TLS1_0_VERSION
        _ctx_set_options!(ctx, _SSL_OP_NO_TLSv1_1 | _SSL_OP_NO_TLSv1_2 | _SSL_OP_NO_TLSv1_3)
        return nothing
    end
    throw(ConfigError("unsupported max_version for this TLS backend: $(Int(version))"))
end

function _ssl_ctx_new(config::Config; is_server::Bool)::Ptr{Cvoid}
    _validate_config(config; is_server = is_server)
    method = ccall((:TLS_method, _LIBSSL), Ptr{Cvoid}, ())
    method == C_NULL && throw(_make_tls_error("TLS_method", Int32(0)))
    ctx = ccall((:SSL_CTX_new, _LIBSSL), Ptr{Cvoid}, (Ptr{Cvoid},), method)
    ctx == C_NULL && throw(_make_tls_error("SSL_CTX_new", Int32(0)))
    try
        verify_mode = if is_server
            _server_verify_mode(config)
        else
            config.verify_peer ? _SSL_VERIFY_PEER : _SSL_VERIFY_NONE
        end
        verify_cb = if is_server
            _server_verify_callback(config)
        else
            C_NULL
        end
        ccall((:SSL_CTX_set_verify, _LIBSSL), Cvoid, (Ptr{Cvoid}, Cint, Ptr{Cvoid}), ctx, verify_mode, verify_cb)
        if config.min_version !== nothing
            _set_ctx_min_version!(ctx, config.min_version::UInt16)
        end
        if config.max_version !== nothing
            _set_ctx_max_version!(ctx, config.max_version::UInt16)
        end
        need_verify_paths = if is_server
            config.client_auth != ClientAuthMode.NoClientCert
        else
            config.verify_peer
        end
        if need_verify_paths
            ca_path = _effective_ca_file(config; is_server = is_server)
            if ca_path === nothing
                ok = ccall((:SSL_CTX_set_default_verify_paths, _LIBSSL), Cint, (Ptr{Cvoid},), ctx)
                ok == 1 || throw(_make_tls_error("SSL_CTX_set_default_verify_paths", Int32(ok)))
            else
                ok = ccall((:SSL_CTX_load_verify_locations, _LIBSSL), Cint, (Ptr{Cvoid}, Cstring, Cstring), ctx, ca_path, C_NULL)
                ok == 1 || throw(_make_tls_error("SSL_CTX_load_verify_locations", Int32(ok)))
            end
        end
        if is_server
            cert_file = config.cert_file::String
            key_file = config.key_file::String
            ok = ccall((:SSL_CTX_use_certificate_chain_file, _LIBSSL), Cint, (Ptr{Cvoid}, Cstring), ctx, cert_file)
            ok == 1 || throw(_make_tls_error("SSL_CTX_use_certificate_chain_file", Int32(ok)))
            ok = ccall((:SSL_CTX_use_PrivateKey_file, _LIBSSL), Cint, (Ptr{Cvoid}, Cstring, Cint), ctx, key_file, _SSL_FILETYPE_PEM)
            ok == 1 || throw(_make_tls_error("SSL_CTX_use_PrivateKey_file", Int32(ok)))
            ok = ccall((:SSL_CTX_check_private_key, _LIBSSL), Cint, (Ptr{Cvoid},), ctx)
            ok == 1 || throw(_make_tls_error("SSL_CTX_check_private_key", Int32(ok)))
            if !isempty(config.alpn_protocols)
                cb = _ALPN_SELECT_CB[]
                cb == C_NULL && throw(ConfigError("ALPN select callback is not initialized"))
                alpn_data = _ALPNServerData(_encode_alpn_protocols(config.alpn_protocols))
                ccall(
                    (:SSL_CTX_set_alpn_select_cb, _LIBSSL),
                    Cvoid,
                    (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                    ctx,
                    cb,
                    pointer_from_objref(alpn_data),
                )
                _CTX_SERVER_ALPN[ctx] = alpn_data
            end
        else
            if !isempty(config.alpn_protocols)
                alpn_wire = _encode_alpn_protocols(config.alpn_protocols)
                ok = GC.@preserve alpn_wire ccall(
                    (:SSL_CTX_set_alpn_protos, _LIBSSL),
                    Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Cuint),
                    ctx,
                    pointer(alpn_wire),
                    Cuint(length(alpn_wire)),
                )
                ok == 0 || throw(_make_tls_error("SSL_CTX_set_alpn_protos", Int32(ok)))
            end
            if config.cert_file !== nothing
                cert_file = config.cert_file::String
                key_file = config.key_file::String
                ok = ccall((:SSL_CTX_use_certificate_chain_file, _LIBSSL), Cint, (Ptr{Cvoid}, Cstring), ctx, cert_file)
                ok == 1 || throw(_make_tls_error("SSL_CTX_use_certificate_chain_file", Int32(ok)))
                ok = ccall((:SSL_CTX_use_PrivateKey_file, _LIBSSL), Cint, (Ptr{Cvoid}, Cstring, Cint), ctx, key_file, _SSL_FILETYPE_PEM)
                ok == 1 || throw(_make_tls_error("SSL_CTX_use_PrivateKey_file", Int32(ok)))
                ok = ccall((:SSL_CTX_check_private_key, _LIBSSL), Cint, (Ptr{Cvoid},), ctx)
                ok == 1 || throw(_make_tls_error("SSL_CTX_check_private_key", Int32(ok)))
            end
        end
        return ctx
    catch
        ccall((:SSL_CTX_free, _LIBSSL), Cvoid, (Ptr{Cvoid},), ctx)
        rethrow()
    end
end

@inline function _ssl_context_key(config::Config; is_server::Bool)::_SSLContextKey
    alpn_key = isempty(config.alpn_protocols) ? "" : join(config.alpn_protocols, '\0')
    ca_file_key = if is_server
        config.ca_file
    else
        _effective_ca_file(config; is_server = false)
    end
    return _SSLContextKey(
        is_server,
        config.verify_peer,
        config.client_auth,
        config.cert_file,
        config.key_file,
        ca_file_key,
        config.client_ca_file,
        alpn_key,
        config.min_version,
        config.max_version,
    )
end

function _shared_ssl_ctx(config::Config; is_server::Bool)::Ptr{Cvoid}
    key = _ssl_context_key(config; is_server = is_server)
    lock(_CTX_CACHE_LOCK)
    try
        existing = get(() -> C_NULL, _CTX_CACHE, key)
        existing != C_NULL && return existing
        ctx = _ssl_ctx_new(config; is_server = is_server)
        _CTX_CACHE[key] = ctx
        push!(_CTX_CACHE_ORDER, key)
        _evict_ssl_ctx_locked!()
        return _CTX_CACHE[key]
    finally
        unlock(_CTX_CACHE_LOCK)
    end
end

function _ssl_new(ctx::Ptr{Cvoid}, tcp::TCP.Conn, config::Config; is_server::Bool)::Ptr{Cvoid}
    ssl = ccall((:SSL_new, _LIBSSL), Ptr{Cvoid}, (Ptr{Cvoid},), ctx)
    ssl == C_NULL && throw(_make_tls_error("SSL_new", Int32(0)))
    try
        ok = ccall((:SSL_set_fd, _LIBSSL), Cint, (Ptr{Cvoid}, Cint), ssl, tcp.fd.pfd.sysfd)
        ok == 1 || throw(_make_tls_error("SSL_set_fd", Int32(ok)))
        if is_server
            ccall((:SSL_set_accept_state, _LIBSSL), Cvoid, (Ptr{Cvoid},), ssl)
        else
            ccall((:SSL_set_connect_state, _LIBSSL), Cvoid, (Ptr{Cvoid},), ssl)
            _apply_client_server_name!(ssl, config)
        end
        return ssl
    catch
        ccall((:SSL_free, _LIBSSL), Cvoid, (Ptr{Cvoid},), ssl)
        rethrow()
    end
end

function _new_conn(tcp::TCP.Conn, config::Config; is_server::Bool)::Conn
    ctx = _shared_ssl_ctx(config; is_server = is_server)
    ssl = _ssl_new(ctx, tcp, config; is_server = is_server)
    return Conn(tcp, ctx, ssl, is_server, config, ReentrantLock(), ReentrantLock(), ReentrantLock(), false, false, nothing)
end

function client(tcp::TCP.Conn, config::Config)::Conn
    return _new_conn(tcp, config; is_server = false)
end

function server(tcp::TCP.Conn, config::Config)::Conn
    return _new_conn(tcp, config; is_server = true)
end

function _free_native_handles!(conn::Conn)
    if conn.ssl != C_NULL
        ccall((:SSL_free, _LIBSSL), Cvoid, (Ptr{Cvoid},), conn.ssl)
        conn.ssl = C_NULL
    end
    conn.ssl_ctx = C_NULL
    return nothing
end

function _mark_closed!(conn::Conn)::Bool
    while true
        current = @atomic :acquire conn.closed
        current && return false
        _, ok = @atomicreplace(conn.closed, current => true)
        ok && return true
    end
end

function _set_handshake_complete!(conn::Conn)
    @atomic :release conn.handshake_complete = true
    return nothing
end

@inline function _handshake_complete(conn::Conn)::Bool
    return @atomic :acquire conn.handshake_complete
end

@inline function _is_closed(conn::Conn)::Bool
    return @atomic :acquire conn.closed
end

function _closed_error(op::AbstractString, cause::Union{Nothing, Exception} = nothing)
    return TLSError(String(op), Int32(0), "connection is closed", cause)
end

function _ensure_open!(conn::Conn, op::AbstractString)
    _is_closed(conn) && throw(_closed_error(op))
    conn.ssl == C_NULL && throw(_closed_error(op))
    return nothing
end

function _wait_ssl_ready!(conn::Conn, ssl_err::Cint, op::AbstractString)
    if ssl_err == _SSL_ERROR_WANT_READ
        IOPoll.wait_read!(conn.tcp.fd.pfd.pd)
        return true
    end
    if ssl_err == _SSL_ERROR_WANT_WRITE
        IOPoll.wait_write!(conn.tcp.fd.pfd.pd)
        return true
    end
    if ssl_err == _SSL_ERROR_SYSCALL
        errno = Int32(Base.Libc.errno())
        if _is_socket_would_block(errno)
            IOPoll.wait_read!(conn.tcp.fd.pfd.pd)
            return true
        end
        if errno == Int32(0)
            throw(TLSError(String(op), ssl_err, "unexpected EOF", nothing))
        end
        throw(TLSError(String(op), ssl_err, "syscall errno=$(errno)", nothing))
    end
    return false
end

@inline function _handshake_effective_deadline(old_ns::Int64, handshake_ns::Int64)::Int64
    old_ns < 0 && return old_ns
    old_ns == 0 && return handshake_ns
    return min(old_ns, handshake_ns)
end

function _with_handshake_deadline(f::F, conn::Conn) where {F}
    timeout_ns = conn.config.handshake_timeout_ns
    if timeout_ns <= 0
        return f()
    end
    pfd = conn.tcp.fd.pfd
    pd = pfd.pd
    old_read_ns = @atomic :acquire pd.rd_ns
    old_write_ns = @atomic :acquire pd.wd_ns
    handshake_deadline_ns = Int64(time_ns()) + timeout_ns
    read_deadline_ns = _handshake_effective_deadline(old_read_ns, handshake_deadline_ns)
    write_deadline_ns = _handshake_effective_deadline(old_write_ns, handshake_deadline_ns)
    IOPoll.set_read_deadline!(pfd, read_deadline_ns)
    IOPoll.set_write_deadline!(pfd, write_deadline_ns)
    try
        return f()
    finally
        try
            IOPoll.set_read_deadline!(pfd, old_read_ns)
        catch
        end
        try
            IOPoll.set_write_deadline!(pfd, old_write_ns)
        catch
        end
    end
end

function _with_temporary_deadline_cap(f::F, conn::Conn, deadline_ns::Int64) where {F}
    deadline_ns == 0 && return f()
    pfd = conn.tcp.fd.pfd
    pd = pfd.pd
    old_read_ns = @atomic :acquire pd.rd_ns
    old_write_ns = @atomic :acquire pd.wd_ns
    read_deadline_ns = _handshake_effective_deadline(old_read_ns, deadline_ns)
    write_deadline_ns = _handshake_effective_deadline(old_write_ns, deadline_ns)
    IOPoll.set_read_deadline!(pfd, read_deadline_ns)
    IOPoll.set_write_deadline!(pfd, write_deadline_ns)
    try
        return f()
    finally
        try
            IOPoll.set_read_deadline!(pfd, old_read_ns)
        catch
        end
        try
            IOPoll.set_write_deadline!(pfd, old_write_ns)
        catch
        end
    end
end

function handshake!(conn::Conn)
    _ensure_open!(conn, "handshake")
    _handshake_complete(conn) && return nothing
    lock(conn.handshake_lock)
    try
        _ensure_open!(conn, "handshake")
        _handshake_complete(conn) && return nothing
        try
            _with_handshake_deadline(conn) do
                while true
                    _ensure_open!(conn, "handshake")
                    ret = ccall((:SSL_do_handshake, _LIBSSL), Cint, (Ptr{Cvoid},), conn.ssl)
                    if ret == 1
                        _set_handshake_complete!(conn)
                        return nothing
                    end
                    ssl_err = ccall((:SSL_get_error, _LIBSSL), Cint, (Ptr{Cvoid}, Cint), conn.ssl, ret)
                    _wait_ssl_ready!(conn, ssl_err, "handshake") && continue
                    ssl_err == _SSL_ERROR_ZERO_RETURN && throw(EOFError())
                    throw(_make_tls_error("handshake", ssl_err))
                end
            end
        catch err
            ex = _as_exception(err)
            if ex isa IOPoll.DeadlineExceededError
                if conn.config.handshake_timeout_ns > 0
                    throw(TLSHandshakeTimeoutError(conn.config.handshake_timeout_ns))
                end
                throw(TLSError("handshake", Int32(0), "i/o timeout", ex))
            end
            ex isa TLSError && rethrow()
            if ex isa IOPoll.NetClosingError || _is_closed(conn)
                throw(_closed_error("handshake", ex))
            end
            throw(_wrap_tls_exception("handshake", ex))
        end
    finally
        unlock(conn.handshake_lock)
    end
end

@inline function _ensure_handshake!(conn::Conn)
    _handshake_complete(conn) || handshake!(conn)
    return nothing
end

function Base.read!(conn::Conn, buf::Vector{UInt8})::Int
    length(buf) == 0 && return 0
    _ensure_open!(conn, "read")
    _ensure_handshake!(conn)
    lock(conn.read_lock)
    try
        _ensure_open!(conn, "read")
        while true
            ret = GC.@preserve buf ccall(
                (:SSL_read, _LIBSSL),
                Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Cint),
                conn.ssl,
                pointer(buf),
                Cint(length(buf)),
            )
            if ret > 0
                return Int(ret)
            end
            ssl_err = ccall((:SSL_get_error, _LIBSSL), Cint, (Ptr{Cvoid}, Cint), conn.ssl, ret)
            _wait_ssl_ready!(conn, ssl_err, "read") && continue
            ssl_err == _SSL_ERROR_ZERO_RETURN && return 0
            throw(_make_tls_error("read", ssl_err))
        end
    catch err
        ex = _as_exception(err)
        ex isa TLSError && rethrow()
        if ex isa IOPoll.NetClosingError || _is_closed(conn)
            throw(_closed_error("read", ex))
        end
        throw(_wrap_tls_exception("read", ex))
    finally
        unlock(conn.read_lock)
    end
end

function Base.write(conn::Conn, buf::Vector{UInt8})::Int
    return _write!(conn, buf, length(buf))
end

function Base.write(conn::Conn, buf::Memory{UInt8}, nbytes::Integer)::Int
    return _write!(conn, buf, nbytes)
end

function _write!(conn::Conn, buf, nbytes::Integer)::Int
    nbytes_int = Int(nbytes)
    nbytes_int < 0 && throw(ArgumentError("nbytes must be >= 0"))
    nbytes_int <= length(buf) || throw(ArgumentError("nbytes exceeds buffer length"))
    nbytes_int == 0 && return 0
    _ensure_open!(conn, "write")
    _ensure_handshake!(conn)
    lock(conn.write_lock)
    try
        _ensure_open!(conn, "write")
        conn.write_permanent_error === nothing || throw(conn.write_permanent_error::TLSError)
        total = 0
        GC.@preserve buf begin
            base_ptr = pointer(buf)
            while total < nbytes_int
                chunk_len = nbytes_int - total
                wrote = ccall(
                    (:SSL_write, _LIBSSL),
                    Cint,
                    (Ptr{Cvoid}, Ptr{UInt8}, Cint),
                    conn.ssl,
                    base_ptr + total,
                    Cint(chunk_len),
                )
                if wrote > 0
                    total += Int(wrote)
                    continue
                end
                ssl_err = ccall((:SSL_get_error, _LIBSSL), Cint, (Ptr{Cvoid}, Cint), conn.ssl, wrote)
                _wait_ssl_ready!(conn, ssl_err, "write") && continue
                throw(_make_tls_error("write", ssl_err))
            end
        end
        return total
    catch err
        ex = _as_exception(err)
        if ex isa IOPoll.DeadlineExceededError
            timeout_err = TLSError("write", Int32(0), "i/o timeout", ex)
            if conn.write_permanent_error === nothing
                conn.write_permanent_error = timeout_err
            end
            throw(conn.write_permanent_error::TLSError)
        end
        ex isa TLSError && rethrow()
        if ex isa IOPoll.NetClosingError || _is_closed(conn)
            throw(_closed_error("write", ex))
        end
        throw(_wrap_tls_exception("write", ex))
    finally
        unlock(conn.write_lock)
    end
end

function _ssl_shutdown!(conn::Conn)
    try
        TCP.set_write_deadline!(conn.tcp, Int64(time_ns()) + Int64(5_000_000_000))
    catch
    end
    for _ in 1:4
        ret = ccall((:SSL_shutdown, _LIBSSL), Cint, (Ptr{Cvoid},), conn.ssl)
        if ret == 1 || ret == 0
            return nothing
        end
        ssl_err = ccall((:SSL_get_error, _LIBSSL), Cint, (Ptr{Cvoid}, Cint), conn.ssl, ret)
        _wait_ssl_ready!(conn, ssl_err, "shutdown") && continue
        return nothing
    end
    try
        TCP.set_write_deadline!(conn.tcp, Int64(time_ns()))
    catch
    end
    return nothing
end

@inline function _try_lock_close_path!(conn::Conn)::Bool
    trylock(conn.handshake_lock) || return false
    if !trylock(conn.read_lock)
        unlock(conn.handshake_lock)
        return false
    end
    if !trylock(conn.write_lock)
        unlock(conn.read_lock)
        unlock(conn.handshake_lock)
        return false
    end
    return true
end

@inline function _unlock_close_path!(conn::Conn)
    unlock(conn.write_lock)
    unlock(conn.read_lock)
    unlock(conn.handshake_lock)
    return nothing
end

function close!(conn::Conn)
    _mark_closed!(conn) || return nothing
    if _handshake_complete(conn) && conn.ssl != C_NULL
        if _try_lock_close_path!(conn)
            try
                _ssl_shutdown!(conn)
            catch
            finally
                _unlock_close_path!(conn)
            end
        end
    end
    try
        # Close the transport first to unblock any in-flight waits.
        TCP.close!(conn.tcp)
    catch
    end
    lock(conn.handshake_lock)
    lock(conn.read_lock)
    lock(conn.write_lock)
    try
        _free_native_handles!(conn)
    finally
        unlock(conn.write_lock)
        unlock(conn.read_lock)
        unlock(conn.handshake_lock)
    end
    return nothing
end

function close_write!(conn::Conn)
    _ensure_open!(conn, "close_write")
    _handshake_complete(conn) || throw(TLSError("close_write", Int32(0), "close_write before handshake complete", nothing))
    lock(conn.write_lock)
    try
        _ensure_open!(conn, "close_write")
        _ssl_shutdown!(conn)
        conn.write_permanent_error === nothing && (conn.write_permanent_error = TLSError("write", Int32(0), "tls: protocol is shutdown", nothing))
        return nothing
    catch err
        ex = _as_exception(err)
        ex isa TLSError && rethrow()
        if ex isa IOPoll.NetClosingError || _is_closed(conn)
            throw(_closed_error("close_write", ex))
        end
        throw(_wrap_tls_exception("close_write", ex))
    finally
        unlock(conn.write_lock)
    end
end

function Base.close(conn::Conn)
    close!(conn)
    return nothing
end

function set_deadline!(conn::Conn, deadline_ns::Integer)
    TCP.set_deadline!(conn.tcp, deadline_ns)
    return nothing
end

function set_read_deadline!(conn::Conn, deadline_ns::Integer)
    TCP.set_read_deadline!(conn.tcp, deadline_ns)
    return nothing
end

function set_write_deadline!(conn::Conn, deadline_ns::Integer)
    TCP.set_write_deadline!(conn.tcp, deadline_ns)
    return nothing
end

function local_addr(conn::Conn)
    return TCP.local_addr(conn.tcp)
end

function remote_addr(conn::Conn)
    return TCP.remote_addr(conn.tcp)
end

function net_conn(conn::Conn)::TCP.Conn
    return conn.tcp
end

function _ssl_version(conn::Conn)::String
    ptr = ccall((:SSL_get_version, _LIBSSL), Cstring, (Ptr{Cvoid},), conn.ssl)
    ptr == C_NULL && return ""
    return unsafe_string(ptr)
end

function _ssl_alpn_protocol(conn::Conn)::Union{Nothing, String}
    data_ref = Ref{Ptr{UInt8}}(C_NULL)
    len_ref = Ref{Cuint}(0)
    ccall(
        (:SSL_get0_alpn_selected, _LIBSSL),
        Cvoid,
        (Ptr{Cvoid}, Ref{Ptr{UInt8}}, Ref{Cuint}),
        conn.ssl,
        data_ref,
        len_ref,
    )
    data = data_ref[]
    len = Int(len_ref[])
    (data == C_NULL || len == 0) && return nothing
    return unsafe_string(Ptr{Cchar}(data), len)
end

function connection_state(conn::Conn)::ConnectionState
    return ConnectionState(
        _handshake_complete(conn),
        _ssl_version(conn),
        _ssl_alpn_protocol(conn),
    )
end

function listen(
        network::AbstractString,
        address::AbstractString,
        config::Config;
        backlog::Integer = 128,
        reuseaddr::Bool = true,
    )::Listener
    _validate_config(config; is_server = true)
    listener = HostResolvers.listen(network, address; backlog = backlog, reuseaddr = reuseaddr)
    return Listener(listener, config)
end

function accept!(listener::Listener)::Conn
    tcp = TCP.accept!(listener.listener)
    return server(tcp, listener.config)
end

function close!(listener::Listener)
    TCP.close!(listener.listener)
    return nothing
end

function Base.close(listener::Listener)
    close!(listener)
    return nothing
end

function addr(listener::Listener)
    return TCP.addr(listener.listener)
end

function _prepare_connect_config(config::Config, address::AbstractString)::Config
    if config.server_name !== nothing
        return config
    end
    host = ""
    try
        host, _ = HostResolvers.split_host_port(address)
    catch
        return config
    end
    host = _normalize_peer_name(host)
    if isempty(host)
        return config
    end
    return _config_with_server_name(config, host)
end

function connect_with_resolver(
        host_resolver::HostResolvers.HostResolver,
        network::AbstractString,
        address::AbstractString,
        config::Config = Config(),
    )::Conn
    tls_config = _prepare_connect_config(config, address)
    connect_deadline_ns = HostResolvers._connect_deadline_ns(host_resolver)
    tcp = HostResolvers.connect(host_resolver, network, address)
    tls_conn = nothing
    try
        tls_conn = client(tcp, tls_config)
        _with_temporary_deadline_cap(tls_conn, connect_deadline_ns) do
            handshake!(tls_conn)
        end
        return tls_conn
    catch err
        ex = _as_exception(err)
        if tls_conn !== nothing
            try
                close!(tls_conn)
            catch
            end
        else
            try
                TCP.close!(tcp)
            catch
            end
        end
        ex isa Exception && rethrow()
    end
end

function connect(connector::Connector, network::AbstractString, address::AbstractString)::Conn
    return connect_with_resolver(connector.host_resolver, network, address, connector.config)
end

function connect(network::AbstractString, address::AbstractString, config::Config = Config())::Conn
    return connect_with_resolver(HostResolvers.HostResolver(), network, address, config)
end

end
