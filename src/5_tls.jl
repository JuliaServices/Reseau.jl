"""
    TLS

TLS client/server layer built on OpenSSL and `TCP` connections.

This layer provides:
- reusable `Config` objects for client and server policy
- `Conn` wrappers that can handshake eagerly or lazily on first I/O
- deadline handling delegated to the wrapped transport so TLS retries follow
  the same timeout model as plain TCP
- transport timeout handling is available as `TLS.DeadlineExceededError`
"""
module TLS

using OpenSSL_jll
using NetworkOptions
using Random
using ..Reseau: ByteMemory, MutableByteBuffer
using ..Reseau: @gcsafe_ccall
using ..Reseau.IOPoll
using ..Reseau.SocketOps
using ..Reseau.TCP
using ..Reseau.HostResolvers

"""
    DeadlineExceededError

Alias for the transport deadline timeout type used by `TLS`.

Catch `TLS.DeadlineExceededError` for direct listener `accept` timeouts and when
inspecting `TLSError.cause`. Higher-level TLS operations may wrap deadline
expiry in `TLSError` or `TLSHandshakeTimeoutError` so callers can keep
operation-specific handling.
"""
const DeadlineExceededError = IOPoll.DeadlineExceededError

# Use bundled string paths instead of LazyLibrary operands so trim-compiled apps
# avoid the dynamic `dlopen(::LazyLibrary)` callback path at runtime.
_LIBSSL_PATH::String = string(OpenSSL_jll.libssl_path)
_LIBCRYPTO_PATH::String = string(OpenSSL_jll.libcrypto_path)

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
const _VERIFY_ALLOW_ALL_CB = Ref{Ptr{Cvoid}}(C_NULL)
const _ALPN_SELECT_CB = Ref{Ptr{Cvoid}}(C_NULL)
const _SSL_CTRL_SET_TLSEXT_HOSTNAME = Cint(55)
const _SSL_CTRL_SET_MIN_PROTO_VERSION = Cint(123)
const _SSL_CTRL_SET_MAX_PROTO_VERSION = Cint(124)
const _SSL_CTRL_GET_MIN_PROTO_VERSION = Cint(130)
const _SSL_CTRL_GET_MAX_PROTO_VERSION = Cint(131)
const _TLSEXT_NAMETYPE_HOST_NAME = Clong(0)
const _ERRNO_EAGAIN = Int32(Base.Libc.EAGAIN)
const _ERRNO_EWOULDBLOCK = _ERRNO_EAGAIN

const TLS1_0_VERSION = UInt16(0x0301)
const TLS1_1_VERSION = UInt16(0x0302)
const TLS1_2_VERSION = UInt16(0x0303)
const TLS1_3_VERSION = UInt16(0x0304)

include("tls/crypto.jl")
include("tls/openssl_crypto.jl")
include("tls/handshake_messages.jl")
include("tls/handshake_client_tls13.jl")
include("tls/record_tls13.jl")

module ClientAuthMode
Base.@enum T::UInt8 begin
    NoClientCert = 0
    RequestClientCert = 1
    RequireAnyClientCert = 2
    VerifyClientCertIfGiven = 3
    RequireAndVerifyClientCert = 4
end
end

"""
    ConfigError

Raised when TLS configuration is invalid.

This is thrown before any network I/O starts, typically while normalizing a `Config`
or constructing an `SSL_CTX`.
"""
struct ConfigError <: Exception
    message::String
end

"""
    TLSError

Raised when TLS handshake/read/write/close operations fail.

`code` is usually an OpenSSL `SSL_get_error` result, though wrapper paths may set it to
`0` when the failure is higher-level than one OpenSSL call. `cause` preserves the
underlying Julia-side exception when the failure originated in the transport/poller
layer instead of OpenSSL itself.
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

This is kept separate from `TLSError` because handshake timeouts are often configured
and handled distinctly from generic TLS failures.
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

Reusable TLS configuration for client and server sessions.

Keyword arguments:
- `server_name`: hostname or IP literal used for certificate verification. For clients,
  this also drives SNI when it is a hostname. If omitted, `connect` will try to derive
  it from the dial target.
- `verify_peer`: whether to validate the remote certificate chain and peer name.
- `client_auth`: server-side client certificate policy.
- `cert_file` / `key_file`: PEM-encoded certificate chain and private key. Servers must
  provide both; clients may provide both for mutual TLS.
- `ca_file`: CA bundle or hashed CA directory used to verify remote servers. When omitted,
  client verification uses `NetworkOptions.ca_roots_path()`.
- `client_ca_file`: CA bundle or hashed CA directory used by servers to verify client
  certificates. This is required for server configs that verify presented client certs.
- `alpn_protocols`: ordered ALPN protocol preference list.
- `handshake_timeout_ns`: optional cap, in monotonic nanoseconds, applied only while the
  handshake is running. Existing transport deadlines still win if they are earlier.
- `min_version` / `max_version`: TLS protocol version bounds. `nothing` leaves the bound
  unset.

Returns a reusable immutable `Config`.

Throws `ConfigError` if the keyword combination is internally inconsistent.
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
    session_tickets_disabled::Bool
    _client_session_cache::_TLS13ClientSessionCache
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
const _TLS_CONN_MODE_OPENSSL = UInt8(0)
const _TLS_CONN_MODE_NATIVE_TLS13_CLIENT = UInt8(1)

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
        session_tickets_disabled::Bool = false,
        session_cache_capacity::Integer = 64,
    )
    # Normalize to owned `String` storage so shared configs do not depend on caller-owned
    # string buffers or views.
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
        session_tickets_disabled,
        _TLS13ClientSessionCache(session_cache_capacity),
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
    ispath(ca_path_s) || return nothing
    return ca_path_s
end

@inline function _server_needs_verified_client_ca(config::Config)::Bool
    mode = config.client_auth
    return mode == ClientAuthMode.VerifyClientCertIfGiven || mode == ClientAuthMode.RequireAndVerifyClientCert
end

@inline function _effective_ca_file(config::Config; is_server::Bool)::Union{Nothing, String}
    if is_server
        return _server_needs_verified_client_ca(config) ? config.client_ca_file : nothing
    end
    config.ca_file !== nothing && return config.ca_file::String
    return _default_ca_file_path()
end

function _load_verify_locations!(ctx::Ptr{Cvoid}, ca_path::String)
    ok = if isdir(ca_path)
        @gcsafe_ccall _LIBSSL_PATH.SSL_CTX_load_verify_locations(
            ctx::Ptr{Cvoid},
            C_NULL::Cstring,
            ca_path::Cstring,
        )::Cint
    else
        @gcsafe_ccall _LIBSSL_PATH.SSL_CTX_load_verify_locations(
            ctx::Ptr{Cvoid},
            ca_path::Cstring,
            C_NULL::Cstring,
        )::Cint
    end
    ok == 1 || throw(_make_tls_error("SSL_CTX_load_verify_locations", Int32(ok)))
    return nothing
end

"""
    ConnectionState

Snapshot of negotiated TLS connection state.

Fields:
- `handshake_complete`: whether the TLS handshake has finished successfully.
- `version`: negotiated TLS protocol version string as reported by OpenSSL.
- `alpn_protocol`: negotiated ALPN protocol, or `nothing` if ALPN was not used.
"""
struct ConnectionState
    handshake_complete::Bool
    version::String
    alpn_protocol::Union{Nothing, String}
end

"""
    Conn

TLS stream wrapper over one `TCP.Conn`.

`Conn` is safe for one concurrent reader and one concurrent writer. Handshake,
read, and write all have separate locks so lazy handshakes and shutdown can
coordinate without corrupting the OpenSSL state machine. Because `Conn <: IO`,
standard Base stream helpers like `read`, `read!`, `readbytes!`, `eof`, and
`write` apply directly to decrypted application data.
"""
mutable struct Conn <: IO
    tcp::TCP.Conn
    ssl_ctx::Ptr{Cvoid}
    ssl::Ptr{Cvoid}
    mode::UInt8
    is_server::Bool
    config::Config
    native_state::Union{Nothing, _TLS13NativeClientState}
    handshake_lock::ReentrantLock
    read_lock::ReentrantLock
    write_lock::ReentrantLock
    @atomic handshake_complete::Bool
    @atomic closed::Bool
    write_permanent_error::Union{Nothing, TLSError}
    negotiated_version::String
    negotiated_alpn::Union{Nothing, String}
end

"""
    Listener

TLS listener wrapper over `TCP.Listener`.

Accepted connections are wrapped in server-side TLS state but are not handshaken until
`handshake!` or the first read/write call.
"""
struct Listener
    listener::TCP.Listener
    config::Config
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
    # OpenSSL stores the callback argument as an opaque pointer. We root the actual Julia
    # object in `_CTX_SERVER_ALPN`, then recover it here so the ALPN preference bytes stay
    # alive for as long as the shared `SSL_CTX` remains cached.
    arg == C_NULL && return _SSL_TLSEXT_ERR_NOACK
    data = unsafe_pointer_to_objref(arg)::_ALPNServerData
    wire = data.wire
    isempty(wire) && return _SSL_TLSEXT_ERR_NOACK
    selected = Ref{Ptr{UInt8}}(C_NULL)
    selected_len = Ref{UInt8}(0)
    rc = GC.@preserve wire ccall(
        (:SSL_select_next_proto, _LIBSSL_PATH),
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
    # Module initialization roots the callback trampolines and ensures OpenSSL is
    # initialized once before any contexts are created.
    global _LIBCRYPTO_PATH = OpenSSL_jll.libcrypto_path
    global _LIBSSL_PATH = OpenSSL_jll.libssl_path
    _ = @gcsafe_ccall _LIBSSL_PATH.OPENSSL_init_ssl(
        Culong(0)::Culong,
        C_NULL::Ptr{Cvoid},
    )::Cint
    _init_x25519_pkey_id!()
    _init_p256_group_nid!()
    _VERIFY_ALLOW_ALL_CB[] = @cfunction(_verify_allow_all_cb, Cint, (Cint, Ptr{Cvoid}))
    _ALPN_SELECT_CB[] = @cfunction(_ssl_alpn_select_cb, Cint, (Ptr{Cvoid}, Ptr{Ptr{UInt8}}, Ptr{UInt8}, Ptr{UInt8}, Cuint, Ptr{Cvoid}))
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
    percent_index = nothing
    if !isempty(h)
        i = lastindex(h)
        start = firstindex(h)
        while true
            if h[i] == '%'
                percent_index = i
                break
            end
            i == start && break
            i = prevind(h, i)
        end
    end
    if percent_index !== nothing && percent_index > firstindex(h)
        h = h[firstindex(h):prevind(h, percent_index)]
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
    # SNI is sent only for hostnames, while peer verification still supports
    # both DNS names and IP literals.
    config.server_name === nothing && return nothing
    configured = config.server_name::String
    verify_name = _verify_name(configured)
    isempty(verify_name) && return nothing
    sni_name = _hostname_in_sni(configured)
    if !isempty(sni_name)
        ok = ccall(
            (:SSL_ctrl, _LIBSSL_PATH),
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
            param = ccall((:SSL_get0_param, _LIBSSL_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), ssl)
            param == C_NULL && throw(_make_tls_error("SSL_get0_param", Int32(0)))
            ok = ccall(
                (:X509_VERIFY_PARAM_set1_ip_asc, _LIBCRYPTO_PATH),
                Cint,
                (Ptr{Cvoid}, Cstring),
                param,
                ip_verify,
            )
            ok == 1 || throw(_make_tls_error("X509_VERIFY_PARAM_set1_ip_asc", Int32(ok)))
        else
            ok = ccall(
                (:SSL_set1_host, _LIBSSL_PATH),
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
        server_name,
        config.verify_peer,
        config.client_auth,
        config.cert_file,
        config.key_file,
        config.ca_file,
        config.client_ca_file,
        copy(config.alpn_protocols),
        config.handshake_timeout_ns,
        config.min_version,
        config.max_version,
        config.session_tickets_disabled,
        config._client_session_cache,
    )
end

function _openssl_error_message()::String
    err_code = ccall((:ERR_get_error, _LIBCRYPTO_PATH), Culong, ())
    err_code == Culong(0) && return "OpenSSL error queue is empty"
    buf = Vector{UInt8}(undef, 256)
    GC.@preserve buf begin
        ccall(
            (:ERR_error_string_n, _LIBCRYPTO_PATH),
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

function _append_session_context_string!(out::Vector{UInt8}, value::Union{Nothing, String})::Nothing
    if value === nothing
        _append_u32!(out, 0x00000000)
        return nothing
    end
    bytes = codeunits(value::String)
    _append_u32!(out, UInt32(length(bytes)))
    append!(out, bytes)
    return nothing
end

function _server_session_id_context(config::Config)::Vector{UInt8}
    material = UInt8[]
    _append_session_context_string!(material, config.cert_file)
    _append_session_context_string!(material, config.key_file)
    _append_session_context_string!(material, config.client_ca_file)
    push!(material, Base.Enums.bitcast(UInt8, config.client_auth))
    _append_u32!(material, UInt32(length(config.alpn_protocols)))
    for proto in config.alpn_protocols
        proto_bytes = codeunits(proto)
        _append_u32!(material, UInt32(length(proto_bytes)))
        append!(material, proto_bytes)
    end
    _append_u16!(material, config.min_version === nothing ? 0x0000 : config.min_version::UInt16)
    _append_u16!(material, config.max_version === nothing ? 0x0000 : config.max_version::UInt16)
    return SHA.sha256(material)
end

function _validate_config(config::Config; is_server::Bool)
    # Keep validation centralized so callers can rely on `Config` being cheap to construct
    # while the expensive filesystem/OpenSSL checks happen only when a context is needed.
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
        ispath(ca_path) || throw(ConfigError("CA roots path not found: $ca_path"))
    end
    if config.client_ca_file !== nothing
        client_ca_path = config.client_ca_file::String
        ispath(client_ca_path) || throw(ConfigError("client CA roots path not found: $client_ca_path"))
    elseif is_server && _server_needs_verified_client_ca(config)
        throw(ConfigError("server TLS with verified client auth requires `client_ca_file`"))
    end
    if !is_server && config.verify_peer && config.ca_file === nothing
        _default_ca_file_path() === nothing && throw(ConfigError("client TLS verification requires a CA roots path from NetworkOptions.ca_roots_path()"))
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
            ccall((:SSL_CTX_free, _LIBSSL_PATH), Cvoid, (Ptr{Cvoid},), ctx)
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
        ccall((:SSL_CTX_free, _LIBSSL_PATH), Cvoid, (Ptr{Cvoid},), ctx)
    end
    return nothing
end

@inline function _ctx_ctrl!(ctx::Ptr{Cvoid}, cmd::Cint, version::UInt16, opname::AbstractString)
    ok = ccall(
        (:SSL_CTX_ctrl, _LIBSSL_PATH),
        Clong,
        (Ptr{Cvoid}, Cint, Clong, Ptr{Cvoid}),
        ctx,
        cmd,
        Clong(version),
        C_NULL,
    )
    ok == 1 || throw(_make_tls_error(opname, Int32(ok)))
    return nothing
end

function _set_ctx_min_version!(ctx::Ptr{Cvoid}, version::UInt16)
    _ctx_ctrl!(ctx, _SSL_CTRL_SET_MIN_PROTO_VERSION, version, "SSL_CTX_set_min_proto_version")
    return nothing
end

function _set_ctx_max_version!(ctx::Ptr{Cvoid}, version::UInt16)
    _ctx_ctrl!(ctx, _SSL_CTRL_SET_MAX_PROTO_VERSION, version, "SSL_CTX_set_max_proto_version")
    return nothing
end

function _ssl_ctx_new(config::Config; is_server::Bool)::Ptr{Cvoid}
    # `SSL_CTX` is the expensive, shareable part of OpenSSL configuration, so
    # it is fully configured up front and then reused across many live `Conn`s.
    _validate_config(config; is_server = is_server)
    method = ccall((:TLS_method, _LIBSSL_PATH), Ptr{Cvoid}, ())
    method == C_NULL && throw(_make_tls_error("TLS_method", Int32(0)))
    ctx = ccall((:SSL_CTX_new, _LIBSSL_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), method)
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
        # Verification mode lives on the context so every connection built from it starts
        # with the same authentication policy.
        ccall((:SSL_CTX_set_verify, _LIBSSL_PATH), Cvoid, (Ptr{Cvoid}, Cint, Ptr{Cvoid}), ctx, verify_mode, verify_cb)
        if config.min_version !== nothing
            _set_ctx_min_version!(ctx, config.min_version::UInt16)
        end
        if config.max_version !== nothing
            _set_ctx_max_version!(ctx, config.max_version::UInt16)
        end
        need_verify_paths = if is_server
            _server_needs_verified_client_ca(config)
        else
            config.verify_peer
        end
        if need_verify_paths
            ca_path = _effective_ca_file(config; is_server = is_server)
            ca_path === nothing && throw(ConfigError("no CA roots path available for TLS verification"))
            _load_verify_locations!(ctx, ca_path::String)
        end
        if is_server
            cert_file = config.cert_file::String
            key_file = config.key_file::String
            ok = @gcsafe_ccall _LIBSSL_PATH.SSL_CTX_use_certificate_chain_file(
                ctx::Ptr{Cvoid},
                cert_file::Cstring,
            )::Cint
            ok == 1 || throw(_make_tls_error("SSL_CTX_use_certificate_chain_file", Int32(ok)))
            ok = @gcsafe_ccall _LIBSSL_PATH.SSL_CTX_use_PrivateKey_file(
                ctx::Ptr{Cvoid},
                key_file::Cstring,
                _SSL_FILETYPE_PEM::Cint,
            )::Cint
            ok == 1 || throw(_make_tls_error("SSL_CTX_use_PrivateKey_file", Int32(ok)))
            ok = ccall((:SSL_CTX_check_private_key, _LIBSSL_PATH), Cint, (Ptr{Cvoid},), ctx)
            ok == 1 || throw(_make_tls_error("SSL_CTX_check_private_key", Int32(ok)))
            session_id_context = _server_session_id_context(config)
            ok = GC.@preserve session_id_context ccall(
                (:SSL_CTX_set_session_id_context, _LIBSSL_PATH),
                Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Cuint),
                ctx,
                pointer(session_id_context),
                Cuint(length(session_id_context)),
            )
            ok == 1 || throw(_make_tls_error("SSL_CTX_set_session_id_context", Int32(ok)))
            if !isempty(config.alpn_protocols)
                cb = _ALPN_SELECT_CB[]
                cb == C_NULL && throw(ConfigError("ALPN select callback is not initialized"))
                alpn_data = _ALPNServerData(_encode_alpn_protocols(config.alpn_protocols))
                # The callback receives an opaque pointer, so cache the Julia owner next to
                # the shared context to keep the ALPN wire bytes rooted.
                ccall(
                    (:SSL_CTX_set_alpn_select_cb, _LIBSSL_PATH),
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
                    (:SSL_CTX_set_alpn_protos, _LIBSSL_PATH),
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
                ok = @gcsafe_ccall _LIBSSL_PATH.SSL_CTX_use_certificate_chain_file(
                    ctx::Ptr{Cvoid},
                    cert_file::Cstring,
                )::Cint
                ok == 1 || throw(_make_tls_error("SSL_CTX_use_certificate_chain_file", Int32(ok)))
                ok = @gcsafe_ccall _LIBSSL_PATH.SSL_CTX_use_PrivateKey_file(
                    ctx::Ptr{Cvoid},
                    key_file::Cstring,
                    _SSL_FILETYPE_PEM::Cint,
                )::Cint
                ok == 1 || throw(_make_tls_error("SSL_CTX_use_PrivateKey_file", Int32(ok)))
                ok = ccall((:SSL_CTX_check_private_key, _LIBSSL_PATH), Cint, (Ptr{Cvoid},), ctx)
                ok == 1 || throw(_make_tls_error("SSL_CTX_check_private_key", Int32(ok)))
            end
        end
        return ctx
    catch
        ccall((:SSL_CTX_free, _LIBSSL_PATH), Cvoid, (Ptr{Cvoid},), ctx)
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
    # Context reuse matters for throughput-oriented clients/servers because parsing PEM
    # files, loading CA bundles, and allocating OpenSSL tables per connection would be
    # needlessly expensive.
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
    # `SSL_new` creates the per-connection state machine. The shared `SSL_CTX` contributes
    # configuration; the resulting `SSL*` binds that policy to one live socket.
    ssl = ccall((:SSL_new, _LIBSSL_PATH), Ptr{Cvoid}, (Ptr{Cvoid},), ctx)
    ssl == C_NULL && throw(_make_tls_error("SSL_new", Int32(0)))
    try
        ok = ccall((:SSL_set_fd, _LIBSSL_PATH), Cint, (Ptr{Cvoid}, Cint), ssl, tcp.fd.pfd.sysfd)
        ok == 1 || throw(_make_tls_error("SSL_set_fd", Int32(ok)))
        if is_server
            ccall((:SSL_set_accept_state, _LIBSSL_PATH), Cvoid, (Ptr{Cvoid},), ssl)
        else
            ccall((:SSL_set_connect_state, _LIBSSL_PATH), Cvoid, (Ptr{Cvoid},), ssl)
            _apply_client_server_name!(ssl, config)
        end
        return ssl
    catch
        ccall((:SSL_free, _LIBSSL_PATH), Cvoid, (Ptr{Cvoid},), ssl)
        rethrow()
    end
end

@inline function _native_tls13_client_enabled(config::Config)::Bool
    return config.cert_file === nothing &&
        config.key_file === nothing &&
        config.min_version == TLS1_3_VERSION &&
        (config.max_version === nothing || config.max_version == TLS1_3_VERSION)
end

function _tls13_client_hello(config::Config)::_ClientHelloMsg
    rng = Random.RandomDevice()
    hello = _ClientHelloMsg()
    hello.vers = TLS1_2_VERSION
    hello.random = rand(rng, UInt8, 32)
    hello.session_id = rand(rng, UInt8, 32)
    hello.cipher_suites = UInt16[
        _TLS13_AES_128_GCM_SHA256_ID,
        _TLS13_CHACHA20_POLY1305_SHA256_ID,
        _TLS13_AES_256_GCM_SHA384_ID,
    ]
    hello.compression_methods = UInt8[_TLS_COMPRESSION_NONE]
    hello.server_name = config.server_name === nothing ? "" : String(config.server_name)
    hello.ocsp_stapling = true
    hello.ticket_supported = true
    hello.alpn_protocols = copy(config.alpn_protocols)
    hello.supported_points = UInt8[0x00]
    hello.supported_versions = UInt16[TLS1_3_VERSION]
    hello.supported_curves = UInt16[_TLS_GROUP_X25519, _TLS_GROUP_SECP256R1]
    hello.supported_signature_algorithms = UInt16[
        _TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
        _TLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
        _TLS_SIGNATURE_ED25519,
        _TLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
        _TLS_SIGNATURE_RSA_PSS_RSAE_SHA512,
        _TLS_SIGNATURE_RSA_PSS_PSS_SHA256,
        _TLS_SIGNATURE_RSA_PSS_PSS_SHA384,
        _TLS_SIGNATURE_RSA_PSS_PSS_SHA512,
        _TLS_SIGNATURE_ECDSA_SECP384R1_SHA384,
        _TLS_SIGNATURE_ECDSA_SECP521R1_SHA512,
    ]
    hello.supported_signature_algorithms_cert = UInt16[
        _TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
        _TLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
        _TLS_SIGNATURE_ED25519,
        _TLS_SIGNATURE_RSA_PSS_RSAE_SHA384,
        _TLS_SIGNATURE_RSA_PSS_RSAE_SHA512,
        _TLS_SIGNATURE_RSA_PKCS1_SHA256,
        _TLS_SIGNATURE_RSA_PKCS1_SHA384,
        _TLS_SIGNATURE_RSA_PKCS1_SHA512,
        _TLS_SIGNATURE_ECDSA_SECP384R1_SHA384,
        _TLS_SIGNATURE_ECDSA_SECP521R1_SHA512,
    ]
    hello.secure_renegotiation_supported = true
    hello.extended_master_secret = true
    hello.scts = true
    return hello
end

function _native_tls13_certificate_verifier(config::Config)::_TLS13OpenSSLCertificateVerifier
    return _TLS13OpenSSLCertificateVerifier(
        verify_peer = config.verify_peer,
        ca_file = config.verify_peer ? _effective_ca_file(config; is_server = false) : nothing,
    )
end

@inline function _tls13_client_session_cache_key(config::Config, tcp::TCP.Conn)::String
    if config.server_name !== nothing && !isempty(config.server_name::String)
        return config.server_name::String
    end
    raddr = TCP.remote_addr(tcp)
    raddr === nothing && return ""
    if raddr isa TCP.SocketAddrV4
        return string(raddr::TCP.SocketAddrV4)
    end
    return string(raddr::TCP.SocketAddrV6)
end

function _tls13_try_load_client_session(config::Config, cache_key::AbstractString, hello::_ClientHelloMsg)::Union{Nothing, _TLS13ClientSession}
    config.session_tickets_disabled && return nothing
    isempty(cache_key) && return nothing
    session = _tls13_session_cache_get(config._client_session_cache, cache_key)
    session === nothing && return nothing
    now_s = UInt64(floor(time()))
    if session.version != TLS1_3_VERSION || now_s > session.use_by_s
        _tls13_session_cache_put!(config._client_session_cache, cache_key, nothing)
        _securezero_tls13_client_session!(session)
        return nothing
    end
    session_spec = _tls13_cipher_spec(session.cipher_suite)
    if session_spec === nothing
        _tls13_session_cache_put!(config._client_session_cache, cache_key, nothing)
        _securezero_tls13_client_session!(session)
        return nothing
    end
    offered_ok = false
    for offered_suite in hello.cipher_suites
        offered_spec = _tls13_cipher_spec(offered_suite)
        offered_spec === nothing && continue
        if offered_spec.hash_kind == session_spec.hash_kind
            offered_ok = true
            break
        end
    end
    if !offered_ok
        _securezero_tls13_client_session!(session)
        return nothing
    end
    if config.verify_peer
        pkey = Ptr{Cvoid}(C_NULL)
        try
            pkey = _tls13_verify_server_certificate_chain(
                session.certificates,
                config.server_name === nothing ? "" : config.server_name::String;
                verify_peer = true,
                ca_file = _effective_ca_file(config; is_server = false),
            )
        catch
            _tls13_session_cache_put!(config._client_session_cache, cache_key, nothing)
            _securezero_tls13_client_session!(session)
            return nothing
        finally
            _free_evp_pkey!(pkey)
        end
    end
    ticket_age_ms = floor(UInt64, max(0.0, time() - Float64(session.created_at_s)) * 1000.0)
    hello.psk_modes = UInt8[_TLS_PSK_MODE_DHE]
    hello.psk_identities = [_TLSPSKIdentity(copy(session.ticket), UInt32(mod(ticket_age_ms + UInt64(session.age_add), UInt64(1) << 32)))]
    hello.psk_binders = [zeros(UInt8, _hash_len(session_spec.hash_kind))]
    return session
end

function _new_native_tls13_client_conn(tcp::TCP.Conn, config::Config)::Conn
    _validate_config(config; is_server = false)
    return Conn(
        tcp,
        C_NULL,
        C_NULL,
        _TLS_CONN_MODE_NATIVE_TLS13_CLIENT,
        false,
        config,
        _TLS13NativeClientState(),
        ReentrantLock(),
        ReentrantLock(),
        ReentrantLock(),
        false,
        false,
        nothing,
        "",
        nothing,
    )
end

function _new_openssl_conn(tcp::TCP.Conn, config::Config; is_server::Bool)::Conn
    ctx = _shared_ssl_ctx(config; is_server = is_server)
    ssl = _ssl_new(ctx, tcp, config; is_server = is_server)
    return Conn(
        tcp,
        ctx,
        ssl,
        _TLS_CONN_MODE_OPENSSL,
        is_server,
        config,
        nothing,
        ReentrantLock(),
        ReentrantLock(),
        ReentrantLock(),
        false,
        false,
        nothing,
        "",
        nothing,
    )
end

"""
    client(tcp, config) -> Conn

Wrap an established `TCP.Conn` in client-side TLS state.

The handshake is deferred until `handshake!` or the first read/write operation.

Throws `ConfigError` or `TLSError` if the TLS state cannot be initialized.
"""
function client(tcp::TCP.Conn, config::Config)::Conn
    if _native_tls13_client_enabled(config)
        return _new_native_tls13_client_conn(tcp, config)
    end
    return _new_openssl_conn(tcp, config; is_server = false)
end

"""
    server(tcp, config) -> Conn

Wrap an established `TCP.Conn` in server-side TLS state.

The handshake is deferred until `handshake!` or the first read/write operation.

Throws `ConfigError` or `TLSError` if the TLS state cannot be initialized.
"""
function server(tcp::TCP.Conn, config::Config)::Conn
    return _new_openssl_conn(tcp, config; is_server = true)
end

function _free_native_handles!(conn::Conn)
    if conn.mode == _TLS_CONN_MODE_NATIVE_TLS13_CLIENT
        if conn.native_state !== nothing
            _securezero_tls13_native_client_state!(conn.native_state::_TLS13NativeClientState)
            conn.native_state = nothing
        end
        conn.ssl = C_NULL
        conn.ssl_ctx = C_NULL
        return nothing
    end
    if conn.ssl != C_NULL
        ccall((:SSL_free, _LIBSSL_PATH), Cvoid, (Ptr{Cvoid},), conn.ssl)
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
    conn.negotiated_version = _ssl_version(conn)
    conn.negotiated_alpn = _ssl_alpn_protocol(conn)
    @atomic :release conn.handshake_complete = true
    return nothing
end

function _set_handshake_complete!(conn::Conn, negotiated_version::String, negotiated_alpn::Union{Nothing, String})
    conn.negotiated_version = negotiated_version
    conn.negotiated_alpn = negotiated_alpn
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

@inline function _native_tls13_state(conn::Conn)::_TLS13NativeClientState
    state = conn.native_state
    state === nothing && throw(_closed_error("tls13"))
    return state::_TLS13NativeClientState
end

function _ensure_open!(conn::Conn, op::AbstractString)
    _is_closed(conn) && throw(_closed_error(op))
    if conn.mode == _TLS_CONN_MODE_NATIVE_TLS13_CLIENT
        conn.native_state === nothing && throw(_closed_error(op))
        return nothing
    end
    conn.ssl == C_NULL && throw(_closed_error(op))
    return nothing
end

function _wait_ssl_ready!(conn::Conn, ssl_err::Cint, op::AbstractString)
    # OpenSSL signals retryable progress via read/write readiness on the
    # underlying socket.
    if ssl_err == _SSL_ERROR_WANT_READ
        IOPoll.waitread(conn.tcp.fd.pfd.pd)
        return true
    end
    if ssl_err == _SSL_ERROR_WANT_WRITE
        IOPoll.waitwrite(conn.tcp.fd.pfd.pd)
        return true
    end
    if ssl_err == _SSL_ERROR_SYSCALL
        errno = SocketOps.last_error()
        if _is_socket_would_block(errno)
            IOPoll.waitread(conn.tcp.fd.pfd.pd)
            return true
        end
        if errno == Int32(0)
            throw(TLSError(String(op), ssl_err, "unexpected EOF", nothing))
        end
        throw(TLSError(String(op), ssl_err, "syscall errno=$(errno)", nothing))
    end
    return false
end

function _native_tls13_handshake!(conn::Conn)::Nothing
    cache_key = _tls13_client_session_cache_key(conn.config, conn.tcp)
    client_hello = _tls13_client_hello(conn.config)
    session = _tls13_try_load_client_session(conn.config, cache_key, client_hello)
    state = _TLS13ClientHandshakeState(
        client_hello,
        _TLS13OpenSSLKeyShareProvider(),
        _native_tls13_certificate_verifier(conn.config),
        session,
    )
    native_state = _native_tls13_state(conn)
    io = _TLS13HandshakeRecordIO(conn.tcp, native_state)
    try
        _client_handshake_tls13!(state, io)
        negotiated_alpn = isempty(state.client_protocol) ? nothing : state.client_protocol
        _securezero!(native_state.resumption_secret)
        for cert in native_state.session_certificates
            _securezero!(cert)
        end
        empty!(native_state.resumption_secret)
        empty!(native_state.session_certificates)
        native_state.resumption_secret = _tls13_derive_secret(
            state.cipher_spec.hash_kind,
            state.master_secret,
            "res master",
            _tls13_selected_transcript(state),
        )
        if state.using_psk && state.resumption_session !== nothing
            native_state.session_certificates = [copy(cert) for cert in (state.resumption_session::_TLS13ClientSession).certificates]
        else
            native_state.session_certificates = [copy(cert) for cert in state.server_certificate.certificates]
        end
        native_state.session_cipher_suite = state.cipher_suite
        native_state.session_cache_key = cache_key
        native_state.session_alpn = negotiated_alpn === nothing ? "" : negotiated_alpn::String
        native_state.did_resume = state.using_psk
        native_state.did_hello_retry_request = state.did_hello_retry_request
        native_state.curve_id = state.server_hello.server_share === nothing ? UInt16(0) : (state.server_hello.server_share::_TLSKeyShare).group
        _set_handshake_complete!(conn, "TLSv1.3", negotiated_alpn)
    finally
        _securezero_tls13_client_handshake_state!(state)
    end
    return nothing
end

@inline function _handshake_effective_deadline(old_ns::Int64, handshake_ns::Int64)::Int64
    old_ns < 0 && return old_ns
    old_ns == 0 && return handshake_ns
    return min(old_ns, handshake_ns)
end

function _with_handshake_deadline(f::F, conn::Conn) where {F}
    # Go overlays handshake timeouts onto the transport deadline rather than inventing a
    # separate timer path. We do the same by temporarily tightening the read/write
    # deadlines on the underlying poll descriptor, then restoring the prior values.
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
    # Used when the outer dial path already computed an overall connect deadline. TLS
    # should respect that cap during the initial handshake without permanently mutating
    # the caller's long-lived socket deadlines.
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

"""
    handshake!(conn)

Run the TLS handshake to completion if it has not already finished.

This method is idempotent. Concurrent callers serialize through `handshake_lock`, so
only one task drives OpenSSL while the others observe the completed state afterward.

Returns `nothing`.

Throws:
- `TLSHandshakeTimeoutError` when `config.handshake_timeout_ns` expires
- `TLSError` for OpenSSL or transport failures
- `EOFError` if the peer closes cleanly during the handshake
"""
function handshake!(conn::Conn)
    _ensure_open!(conn, "handshake")
    _handshake_complete(conn) && return nothing
    lock(conn.handshake_lock)
    try
        _ensure_open!(conn, "handshake")
        _handshake_complete(conn) && return nothing
        try
            _with_handshake_deadline(conn) do
                if conn.mode == _TLS_CONN_MODE_NATIVE_TLS13_CLIENT
                    _native_tls13_handshake!(conn)
                    return nothing
                end
                while true
                    _ensure_open!(conn, "handshake")
                    ret = @gcsafe_ccall _LIBSSL_PATH.SSL_do_handshake(
                        conn.ssl::Ptr{Cvoid},
                    )::Cint
                    if ret == 1
                        _set_handshake_complete!(conn)
                        return nothing
                    end
                    ssl_err = ccall((:SSL_get_error, _LIBSSL_PATH), Cint, (Ptr{Cvoid}, Cint), conn.ssl, ret)
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

@inline function _native_tls13_pending_plaintext(conn::Conn)::Int
    state = _native_tls13_state(conn)
    return _tls13_buffer_available(state.plaintext_buffer, state.plaintext_buffer_pos)
end

function _native_tls13_fill_plaintext!(conn::Conn)::Nothing
    state = _native_tls13_state(conn)
    while true
        _tls13_handle_post_handshake_messages!(conn, state)
        _tls13_buffer_available(state.plaintext_buffer, state.plaintext_buffer_pos) > 0 && return nothing
        state.peer_close_notify && throw(EOFError())
        _tls13_read_record!(conn.tcp, state)
    end
end

function _native_tls13_take_plaintext!(conn::Conn, ptr::Ptr{UInt8}, nbytes::Int)::Int
    nbytes == 0 && return 0
    _native_tls13_fill_plaintext!(conn)
    state = _native_tls13_state(conn)
    available = _tls13_buffer_available(state.plaintext_buffer, state.plaintext_buffer_pos)
    n = min(nbytes, available)
    unsafe_copyto!(ptr, pointer(state.plaintext_buffer, state.plaintext_buffer_pos), n)
    state.plaintext_buffer_pos += n
    state.plaintext_buffer_pos = _tls13_compact_buffer!(state.plaintext_buffer, state.plaintext_buffer_pos)
    return n
end

@inline function _pending_plaintext(conn::Conn)::Int
    conn.mode == _TLS_CONN_MODE_NATIVE_TLS13_CLIENT && return _native_tls13_pending_plaintext(conn)
    conn.ssl == C_NULL && return 0
    return Int(ccall((:SSL_pending, _LIBSSL_PATH), Cint, (Ptr{Cvoid},), conn.ssl))
end

@inline function _read_some!(conn::Conn, buf::MutableByteBuffer)::Int
    GC.@preserve buf begin
        return _read_some!(conn, pointer(buf), length(buf))
    end
end

function _read_some!(conn::Conn, ptr::Ptr{UInt8}, nbytes::Int)::Int
    nbytes == 0 && return 0
    _ensure_open!(conn, "read")
    _ensure_handshake!(conn)
    lock(conn.read_lock)
    try
        _ensure_open!(conn, "read")
        if conn.mode == _TLS_CONN_MODE_NATIVE_TLS13_CLIENT
            return _native_tls13_take_plaintext!(conn, ptr, nbytes)
        end
        while true
            chunk_len = min(nbytes, typemax(Cint))
            ret = @gcsafe_ccall _LIBSSL_PATH.SSL_read(
                conn.ssl::Ptr{Cvoid},
                ptr::Ptr{UInt8},
                Cint(chunk_len)::Cint,
            )::Cint
            if ret > 0
                return Int(ret)
            end
            ssl_err = ccall((:SSL_get_error, _LIBSSL_PATH), Cint, (Ptr{Cvoid}, Cint), conn.ssl, ret)
            _wait_ssl_ready!(conn, ssl_err, "read") && continue
            ssl_err == _SSL_ERROR_ZERO_RETURN && throw(EOFError())
            throw(_make_tls_error("read", ssl_err))
        end
    catch err
        ex = _as_exception(err)
        ex isa EOFError && rethrow()
        ex isa TLSError && rethrow()
        if ex isa IOPoll.NetClosingError || _is_closed(conn)
            throw(_closed_error("read", ex))
        end
        throw(_wrap_tls_exception("read", ex))
    finally
        unlock(conn.read_lock)
    end
end

function _grow_readbytes_target!(buf::Vector{UInt8}, current::Int, nb::Int)::Int
    newlen = if current == 0
        min(nb, 1024)
    else
        min(nb, current * 2)
    end
    resize!(buf, newlen)
    return newlen
end

function _peek_eof(conn::Conn)::Bool
    _ensure_open!(conn, "peek")
    _ensure_handshake!(conn)
    lock(conn.read_lock)
    try
        _ensure_open!(conn, "peek")
        if conn.mode == _TLS_CONN_MODE_NATIVE_TLS13_CLIENT
            state = _native_tls13_state(conn)
            while true
                _tls13_handle_post_handshake_messages!(conn, state)
                _tls13_buffer_available(state.plaintext_buffer, state.plaintext_buffer_pos) > 0 && return false
                state.peer_close_notify && return true
                _tls13_read_record!(conn.tcp, state)
            end
        end
        _pending_plaintext(conn) > 0 && return false
        pref = Ref{UInt8}(0x00)
        while true
            ret = GC.@preserve pref @gcsafe_ccall _LIBSSL_PATH.SSL_peek(
                conn.ssl::Ptr{Cvoid},
                Base.unsafe_convert(Ptr{UInt8}, pref)::Ptr{UInt8},
                Cint(1)::Cint,
            )::Cint
            if ret > 0
                return false
            end
            ssl_err = ccall((:SSL_get_error, _LIBSSL_PATH), Cint, (Ptr{Cvoid}, Cint), conn.ssl, ret)
            _wait_ssl_ready!(conn, ssl_err, "peek") && continue
            ssl_err == _SSL_ERROR_ZERO_RETURN && return true
            throw(_make_tls_error("peek", ssl_err))
        end
    catch err
        ex = _as_exception(err)
        ex isa TLSError && rethrow()
        if ex isa IOPoll.NetClosingError || _is_closed(conn)
            throw(_closed_error("peek", ex))
        end
        throw(_wrap_tls_exception("peek", ex))
    finally
        unlock(conn.read_lock)
    end
end

"""
    unsafe_read(conn, ptr, nbytes)

Read exactly `nbytes` of decrypted application data or throw `EOFError`.
"""
function Base.unsafe_read(conn::Conn, ptr::Ptr{UInt8}, nbytes::UInt)
    remaining = Int(nbytes)
    offset = 0
    while remaining > 0
        n = _read_some!(conn, ptr + offset, remaining)
        offset += n
        remaining -= n
    end
    return nothing
end

function _readbytes_all!(conn::Conn, buf::Vector{UInt8}, requested::Int)::Int
    original_len = length(buf)
    current_len = original_len
    bytes_read = 0
    while bytes_read < requested
        if current_len == 0 || bytes_read == current_len
            current_len = _grow_readbytes_target!(buf, current_len, requested)
        end
        chunk_capacity = min(current_len - bytes_read, requested - bytes_read)
        n = try
            GC.@preserve buf _read_some!(conn, pointer(buf, bytes_read + 1), chunk_capacity)
        catch err
            ex = err::Exception
            ex isa EOFError || rethrow(ex)
            break
        end
        bytes_read += n
    end
    if current_len > original_len && current_len > bytes_read
        resize!(buf, max(original_len, bytes_read))
    end
    return bytes_read
end

function _readbytes_some!(conn::Conn, buf::Vector{UInt8}, requested::Int)::Int
    original_len = length(buf)
    requested > original_len && resize!(buf, requested)
    bytes_read = try
        GC.@preserve buf _read_some!(conn, pointer(buf), requested)
    catch err
        ex = err::Exception
        ex isa EOFError || rethrow(ex)
        0
    end
    current_len = length(buf)
    if current_len > original_len && current_len > bytes_read
        resize!(buf, max(original_len, bytes_read))
    end
    return bytes_read
end

function _readbytes_all!(conn::Conn, buf::MutableByteBuffer, requested::Int)::Int
    requested <= length(buf) || throw(ArgumentError("nb exceeds fixed-size buffer length"))
    bytes_read = 0
    while bytes_read < requested
        n = try
            GC.@preserve buf _read_some!(conn, pointer(buf, bytes_read + 1), requested - bytes_read)
        catch err
            ex = err::Exception
            ex isa EOFError || rethrow(ex)
            break
        end
        bytes_read += n
    end
    return bytes_read
end

function _readbytes_some!(conn::Conn, buf::MutableByteBuffer, requested::Int)::Int
    requested <= length(buf) || throw(ArgumentError("nb exceeds fixed-size buffer length"))
    return try
        GC.@preserve buf _read_some!(conn, pointer(buf), requested)
    catch err
        ex = err::Exception
        ex isa EOFError || rethrow(ex)
        0
    end
end

"""
    read!(conn, buf) -> buf

Read exactly `length(buf)` decrypted bytes into `buf` or throw `EOFError`.

Because `Conn <: IO`, Base's generic `read!` implementation already supports
mutable byte views like `@view bytes[2:5]` in addition to plain vectors.

Use `readbytes!` or `readavailable` when you want a count-returning read that
may stop early.
"""
Base.read!(conn::Conn, buf)

"""
    readbytes!(conn, buf, nb=length(buf); all::Bool=true) -> Int

Read up to `nb` decrypted bytes into `buf`, returning the byte count.

If `all` is `true` (the default), the call keeps reading until `nb` bytes have
been transferred, EOF is reached, or an error occurs. If `all` is `false`, at
most one underlying TLS read is performed.

Resizable `Vector{UInt8}` buffers grow when needed, matching Julia's standard
`readbytes!` behavior. Fixed-size contiguous byte views must satisfy
`nb <= length(buf)`.
"""
function Base.readbytes!(conn::Conn, buf::MutableByteBuffer, nb::Integer = length(buf); all::Bool = true)::Int
    Base.require_one_based_indexing(buf)
    requested = Int(nb)
    requested < 0 && throw(ArgumentError("nb must be >= 0"))
    requested == 0 && return 0
    return all ? _readbytes_all!(conn, buf, requested) : _readbytes_some!(conn, buf, requested)
end

"""
    read(conn, nb::Integer; all::Bool=true) -> Vector{UInt8}

Read and return up to `nb` decrypted bytes from `conn`.

If `all` is `true` (the default), the call keeps reading until `nb` bytes have
been transferred, EOF is reached, or an error occurs. If `all` is `false`, at
most one underlying TLS read is performed.
"""
function Base.read(conn::Conn, nb::Integer; all::Bool = true)::Vector{UInt8}
    requested = Int(nb)
    requested < 0 && throw(ArgumentError("nb must be >= 0"))
    buf = Vector{UInt8}(undef, all && requested == typemax(Int) ? 1024 : requested)
    n = readbytes!(conn, buf, requested; all = all)
    return resize!(buf, n)
end

"""
    readavailable(conn) -> Vector{UInt8}

Read and return decrypted plaintext that is ready without requiring a
full-buffer exact read.
"""
function Base.readavailable(conn::Conn)::Vector{UInt8}
    _ensure_open!(conn, "read")
    if _handshake_complete(conn)
        pending = _pending_plaintext(conn)
        if pending > 0
            buf = Vector{UInt8}(undef, pending)
            n = _read_some!(conn, buf)
            return resize!(buf, n)
        end
    end
    buf = Vector{UInt8}(undef, Base.SZ_UNBUFFERED_IO)
    n = try
        _read_some!(conn, buf)
    catch err
        ex = err::Exception
        ex isa EOFError || rethrow(ex)
        return UInt8[]
    end
    return resize!(buf, n)
end

function Base.read(conn::Conn, ::Type{UInt8})::UInt8
    ref = Ref{UInt8}(0x00)
    Base.unsafe_read(conn, ref, 1)
    return ref[]
end

"""
    eof(conn) -> Bool

Report whether the peer has cleanly finished the TLS stream.
"""
function Base.eof(conn::Conn)::Bool
    isopen(conn) || return true
    return _peek_eof(conn)
end

"""
    isopen(conn) -> Bool

Return `true` while both the TLS state and underlying TCP transport remain open.
"""
function Base.isopen(conn::Conn)::Bool
    if conn.mode == _TLS_CONN_MODE_NATIVE_TLS13_CLIENT
        return !_is_closed(conn) && conn.native_state !== nothing && isopen(conn.tcp)
    end
    return !_is_closed(conn) && conn.ssl != C_NULL && isopen(conn.tcp)
end

function Base.flush(::Conn)
    return nothing
end

"""
    write(conn, buf) -> Int
    write(conn, buf, nbytes) -> Int

Write plaintext application bytes through the TLS connection.

`write(conn, buf)` attempts to write the entire buffer. The fixed-size
byte-buffer overload allows callers to cap the write at `nbytes`.
"""
Base.write(conn::Conn, buf::AbstractVector{UInt8})

function _write_buffer(buf::AbstractVector{UInt8}, nbytes::Int)
    if buf isa StridedVector{UInt8} && stride(buf, 1) == 1
        return buf
    end
    copied = Vector{UInt8}(undef, nbytes)
    copyto!(copied, 1, buf, 1, nbytes)
    return copied
end

_write_buffer(buf::ByteMemory, nbytes::Int) = buf

function _native_tls13_write_alert!(conn::Conn, alert_desc::UInt8)::Nothing
    state = _native_tls13_state(conn)
    state.sent_close_notify && return nothing
    _tls13_write_record!(conn.tcp, state.write_cipher, _TLS_RECORD_TYPE_ALERT, UInt8[_TLS_ALERT_LEVEL_WARNING, alert_desc])
    if alert_desc == _TLS_ALERT_CLOSE_NOTIFY
        state.sent_close_notify = true
    end
    return nothing
end

function _native_tls13_write_application!(conn::Conn, ptr::Ptr{UInt8}, nbytes::Int)::Int
    state = _native_tls13_state(conn)
    total = 0
    while total < nbytes
        chunk_len = min(nbytes - total, _TLS13_MAX_PLAINTEXT)
        chunk = unsafe_wrap(Vector{UInt8}, ptr + total, chunk_len; own = false)
        _tls13_write_record!(conn.tcp, state.write_cipher, _TLS_RECORD_TYPE_APPLICATION_DATA, chunk)
        total += chunk_len
    end
    return total
end

function Base.unsafe_write(conn::Conn, ptr::Ptr{UInt8}, nbytes::UInt)
    nbytes_int = Int(nbytes)
    nbytes_int == 0 && return 0
    _ensure_open!(conn, "write")
    _ensure_handshake!(conn)
    lock(conn.write_lock)
    try
        _ensure_open!(conn, "write")
        conn.write_permanent_error === nothing || throw(conn.write_permanent_error::TLSError)
        if conn.mode == _TLS_CONN_MODE_NATIVE_TLS13_CLIENT
            return _native_tls13_write_application!(conn, ptr, nbytes_int)
        end
        total = 0
        while total < nbytes_int
            chunk_len = min(nbytes_int - total, typemax(Cint))
            wrote = @gcsafe_ccall _LIBSSL_PATH.SSL_write(
                conn.ssl::Ptr{Cvoid},
                (ptr + total)::Ptr{UInt8},
                Cint(chunk_len)::Cint,
            )::Cint
            if wrote > 0
                total += Int(wrote)
                continue
            end
            ssl_err = ccall((:SSL_get_error, _LIBSSL_PATH), Cint, (Ptr{Cvoid}, Cint), conn.ssl, wrote)
            _wait_ssl_ready!(conn, ssl_err, "write") && continue
            throw(_make_tls_error("write", ssl_err))
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

function Base.write(conn::Conn, byte::UInt8)::Int
    ref = Ref{UInt8}(byte)
    GC.@preserve ref begin
        return Int(Base.unsafe_write(conn, Base.unsafe_convert(Ptr{UInt8}, ref), UInt(1)))
    end
end

function Base.write(conn::Conn, buf::Vector{UInt8})::Int
    GC.@preserve buf begin
        return Int(Base.unsafe_write(conn, pointer(buf), UInt(length(buf))))
    end
end

function Base.write(conn::Conn, buf::StridedVector{UInt8})::Int
    if stride(buf, 1) == 1
        return GC.@preserve buf Int(Base.unsafe_write(conn, pointer(buf), UInt(length(buf))))
    end
    data = Vector{UInt8}(buf)
    GC.@preserve data begin
        return Int(Base.unsafe_write(conn, pointer(data), UInt(length(data))))
    end
end

function Base.write(conn::Conn, buf::Base.CodeUnits{UInt8,<:AbstractString})::Int
    return write(conn, buf.s)
end

function Base.write(conn::Conn, buf::AbstractVector{UInt8})::Int
    data = Vector{UInt8}(buf)
    GC.@preserve data begin
        return Int(Base.unsafe_write(conn, pointer(data), UInt(length(data))))
    end
end

function Base.write(conn::Conn, buf::ByteMemory, nbytes::Integer)::Int
    n = Int(nbytes)
    n < 0 && throw(ArgumentError("nbytes must be >= 0"))
    n <= length(buf) || throw(ArgumentError("nbytes exceeds buffer length"))
    GC.@preserve buf begin
        return Int(Base.unsafe_write(conn, pointer(buf), UInt(n)))
    end
end

function _ssl_shutdown!(conn::Conn)
    # `SSL_shutdown` may need multiple rounds because a close-notify alert can require
    # additional socket readiness before OpenSSL considers the shutdown complete. We cap
    # the write side so close does not hang forever on an unresponsive peer.
    try
        TCP.set_write_deadline!(conn.tcp, Int64(time_ns()) + Int64(5_000_000_000))
    catch
    end
    for _ in 1:4
        ret = @gcsafe_ccall _LIBSSL_PATH.SSL_shutdown(
            conn.ssl::Ptr{Cvoid},
        )::Cint
        if ret == 1 || ret == 0
            return nothing
        end
        ssl_err = ccall((:SSL_get_error, _LIBSSL_PATH), Cint, (Ptr{Cvoid}, Cint), conn.ssl, ret)
        _wait_ssl_ready!(conn, ssl_err, "shutdown") && continue
        return nothing
    end
    try
        TCP.set_write_deadline!(conn.tcp, Int64(time_ns()))
    catch
    end
    return nothing
end

function _native_tls13_shutdown!(conn::Conn)::Nothing
    _native_tls13_write_alert!(conn, _TLS_ALERT_CLOSE_NOTIFY)
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

"""
    close(conn)

Close the TLS connection and the underlying TCP transport.

If the handshake completed, this best-effort sends a TLS `close_notify` alert before
closing the socket. The method is idempotent and returns `nothing`.
"""
function Base.close(conn::Conn)
    _mark_closed!(conn) || return nothing
    if _handshake_complete(conn) && (conn.mode == _TLS_CONN_MODE_NATIVE_TLS13_CLIENT || conn.ssl != C_NULL)
        if _try_lock_close_path!(conn)
            try
                if conn.mode == _TLS_CONN_MODE_NATIVE_TLS13_CLIENT
                    _native_tls13_shutdown!(conn)
                else
                    _ssl_shutdown!(conn)
                end
            catch
            finally
                _unlock_close_path!(conn)
            end
        end
    end
    try
        # Close the transport first to unblock any in-flight waits.
        close(conn.tcp)
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

"""
    closewrite(conn)

Send TLS shutdown on the write side and mark future writes as permanently failed.

This is the TLS analogue of half-closing a TCP socket. It requires the handshake to
have completed because the TLS close-notify alert is itself a TLS record.

Returns `nothing`.

Throws `TLSError` if the TLS shutdown path fails.
"""
function Base.closewrite(conn::Conn)
    _ensure_open!(conn, "closewrite")
    _handshake_complete(conn) || throw(TLSError("closewrite", Int32(0), "closewrite before handshake complete", nothing))
    lock(conn.write_lock)
    try
        _ensure_open!(conn, "closewrite")
        if conn.mode == _TLS_CONN_MODE_NATIVE_TLS13_CLIENT
            _native_tls13_shutdown!(conn)
        else
            _ssl_shutdown!(conn)
        end
        conn.write_permanent_error === nothing && (conn.write_permanent_error = TLSError("write", Int32(0), "tls: protocol is shutdown", nothing))
        return nothing
    catch err
        ex = _as_exception(err)
        ex isa TLSError && rethrow()
        if ex isa IOPoll.NetClosingError || _is_closed(conn)
            throw(_closed_error("closewrite", ex))
        end
        throw(_wrap_tls_exception("closewrite", ex))
    finally
        unlock(conn.write_lock)
    end
end

"""
    set_deadline!(conn, deadline_ns)

Set both read and write deadlines on the underlying transport.

`deadline_ns` is interpreted using the same monotonic-clock convention as `TCP` and
`IOPoll`: `0` clears the deadline, negative values mean the deadline has already
expired, and positive values are absolute `time_ns()` values.
"""
function set_deadline!(conn::Conn, deadline_ns::Integer)
    TCP.set_deadline!(conn.tcp, deadline_ns)
    return nothing
end

"""
    set_deadline!(listener, deadline_ns)

Set the accept deadline on the underlying TCP listener.

This affects `accept(listener)` only. The returned `Conn` still uses its own
connection and handshake deadlines afterward. Expired accept waits throw
`DeadlineExceededError`.
"""
function set_deadline!(listener::Listener, deadline_ns::Integer)
    TCP.set_deadline!(listener.listener, deadline_ns)
    return nothing
end

"""
    set_read_deadline!(conn, deadline_ns)

Set the read deadline on the underlying transport. See `set_deadline!` for the timestamp
convention.
"""
function set_read_deadline!(conn::Conn, deadline_ns::Integer)
    TCP.set_read_deadline!(conn.tcp, deadline_ns)
    return nothing
end

"""
    set_write_deadline!(conn, deadline_ns)

Set the write deadline on the underlying transport. See `set_deadline!` for the
timestamp convention.
"""
function set_write_deadline!(conn::Conn, deadline_ns::Integer)
    TCP.set_write_deadline!(conn.tcp, deadline_ns)
    return nothing
end

"""
    local_addr(conn)

Return the local `TCP.SocketAddr` for the wrapped transport.
"""
function local_addr(conn::Conn)
    return TCP.local_addr(conn.tcp)
end

"""
    local_addr(listener)

Return the local listening address for the wrapped TCP listener.

This is an alias for `addr(listener)`.
"""
function local_addr(listener::Listener)
    return addr(listener)
end

"""
    remote_addr(conn)

Return the remote `TCP.SocketAddr` for the wrapped transport.
"""
function remote_addr(conn::Conn)
    return TCP.remote_addr(conn.tcp)
end

"""
    net_conn(conn) -> TCP.Conn

Expose the underlying TCP connection.

Callers that need transport-level inspection can reach through the TLS wrapper
without reconstructing the socket state.
"""
function net_conn(conn::Conn)::TCP.Conn
    return conn.tcp
end

function _ssl_version(conn::Conn)::String
    ptr = ccall((:SSL_get_version, _LIBSSL_PATH), Cstring, (Ptr{Cvoid},), conn.ssl)
    ptr == C_NULL && return ""
    return unsafe_string(ptr)
end

function _ssl_alpn_protocol(conn::Conn)::Union{Nothing, String}
    data_ref = Ref{Ptr{UInt8}}(C_NULL)
    len_ref = Ref{Cuint}(0)
    ccall(
        (:SSL_get0_alpn_selected, _LIBSSL_PATH),
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

"""
    connection_state(conn) -> ConnectionState

Return a snapshot of the currently negotiated TLS state.

This does not force a handshake; if the handshake has not yet run, the returned
`ConnectionState` reports `handshake_complete=false`.
"""
function connection_state(conn::Conn)::ConnectionState
    return ConnectionState(
        _handshake_complete(conn),
        conn.negotiated_version,
        conn.negotiated_alpn,
    )
end

"""
    listen(network, address, config; backlog=128, reuseaddr=true) -> Listener

Create a TLS listener by first creating a TCP listener and then associating a server
`Config` with accepted connections.

Accepted `Conn`s are returned in lazy-handshake form.

Throws `ConfigError` if the server config is invalid and propagates any listener creation
errors from `TCP.listen`.
"""
function listen(
        network::AbstractString,
        address::AbstractString,
        config::Config;
        backlog::Integer = 128,
        reuseaddr::Bool = true,
    )::Listener
    _validate_config(config; is_server = true)
    listener = TCP.listen(network, address; backlog = backlog, reuseaddr = reuseaddr)
    return Listener(listener, config)
end

"""
    accept(listener) -> Conn

Accept one inbound TCP connection and wrap it in server-side TLS state.

The returned `Conn` has not handshaken yet. If the listener deadline expires,
`accept(listener)` throws `DeadlineExceededError`.
"""
function accept(listener::Listener)::Conn
    tcp = TCP.accept(listener.listener)
    return server(tcp, listener.config)
end

"""
    isopen(listener) -> Bool

Return `true` while the wrapped TCP listener remains open.
"""
function Base.isopen(listener::Listener)::Bool
    return isopen(listener.listener)
end

"""
    close(listener)

Close the underlying TCP listener. Repeated closes are treated as no-ops.
"""
function Base.close(listener::Listener)
    close(listener.listener)
    return nothing
end

"""
    addr(listener)

Return the local listening address for the wrapped TCP listener.
"""
function addr(listener::Listener)
    return TCP.addr(listener.listener)
end

@inline function _show_endpoint(io::IO, endpoint::Union{Nothing, TCP.SocketAddr})
    if endpoint === nothing
        print(io, "?")
    else
        show(io, endpoint)
    end
    return nothing
end

@inline _show_role(conn::Conn) = conn.is_server ? "server" : "client"
@inline _show_state(listener::Listener) = listener.listener.fd.pfd.sysfd >= 0 ? "active" : "closed"
@inline _show_closed(conn::Conn) = _is_closed(conn) || conn.ssl == C_NULL || conn.tcp.fd.pfd.sysfd < 0

function Base.show(io::IO, conn::Conn)
    print(io, "TLS.Conn(")
    _show_endpoint(io, local_addr(conn))
    print(io, " => ")
    _show_endpoint(io, remote_addr(conn))
    print(io, ", ", _show_role(conn))
    if _show_closed(conn)
        print(io, ", closed")
    elseif !_handshake_complete(conn)
        print(io, ", handshake pending")
    else
        if isempty(conn.negotiated_version)
            print(io, ", handshake complete")
        else
            print(io, ", ", conn.negotiated_version)
        end
        conn.negotiated_alpn === nothing || print(io, ", ", conn.negotiated_alpn)
    end
    print(io, ")")
    return nothing
end

function Base.show(io::IO, listener::Listener)
    print(io, "TLS.Listener(")
    _show_endpoint(io, addr(listener))
    print(io, ", ", _show_state(listener), ")")
    return nothing
end

function _prepare_connect_config(config::Config, address::AbstractString)::Config
    # Match the ergonomic Go behavior where client TLS verification can infer the peer
    # name from the dial target unless the caller explicitly overrides it.
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

function _prepare_connect_config(config::Config, remote_addr::TCP.SocketAddr)::Config
    config.server_name !== nothing && return config
    host = try
        hostport = sprint(show, remote_addr)
        parsed_host, _ = HostResolvers.split_host_port(hostport)
        _normalize_peer_name(parsed_host)
    catch
        ""
    end
    isempty(host) && return config
    return _config_with_server_name(config, host)
end

function _connect_client(tcp::TCP.Conn, config::Config, deadline_ns::Int64 = Int64(0))::Conn
    tls_conn = try
        client(tcp, config)
    catch err
        ex = _as_exception(err)
        try
            close(tcp)
        catch
        end
        ex isa Exception && rethrow()
    end
    try
        if deadline_ns != 0
            _with_temporary_deadline_cap(tls_conn, deadline_ns) do
                handshake!(tls_conn)
            end
        else
            handshake!(tls_conn)
        end
        return tls_conn
    catch err
        ex = _as_exception(err)
        try
            close(tls_conn)
        catch
        end
        ex isa Exception && rethrow()
    end
end

function _connect(
        host_resolver::HostResolvers.HostResolver,
        network::AbstractString,
        address::AbstractString,
        config::Config,
    )::Conn
    tls_config = _prepare_connect_config(config, address)
    connect_deadline_ns = HostResolvers._connect_deadline_ns(host_resolver)
    tcp = TCP.connect(host_resolver, network, address)
    return _connect_client(tcp, tls_config, connect_deadline_ns)
end

function _connect(
        remote_addr::TCP.SocketAddr,
        local_addr::Union{Nothing, TCP.SocketAddr},
        config::Config,
    )::Conn
    tls_config = _prepare_connect_config(config, remote_addr)
    tcp = TCP.connect(remote_addr, local_addr)
    return _connect_client(tcp, tls_config)
end

"""
    connect(remote_addr; kwargs...) -> Conn
    connect(remote_addr, local_addr; kwargs...) -> Conn

Connect to a concrete `TCP.SocketAddr`, negotiate TLS, and return a fully
handshaken client connection.

This is the direct-address counterpart to the string-address `connect(network,
address; ...)` overloads. The underlying socket setup is delegated to
`TCP.connect`, after which the returned transport is wrapped in TLS and
handshaken immediately.

TLS keyword arguments are forwarded to `Config`. If `server_name` is omitted, it
is inferred from the concrete remote address when possible so peer verification
and SNI can follow the same rules as the string-address client path.
"""
function connect(remote_addr::TCP.SocketAddr; kw...)::Conn
    return _connect(remote_addr, nothing, Config(; kw...))
end

function connect(remote_addr::TCP.SocketAddr, config::Config)::Conn
    return _connect(remote_addr, nothing, config)
end

function connect(remote_addr::TCP.SocketAddr, local_addr::Union{Nothing, TCP.SocketAddr}; kw...)::Conn
    return _connect(remote_addr, local_addr, Config(; kw...))
end

function connect(remote_addr::TCP.SocketAddr, local_addr::Union{Nothing, TCP.SocketAddr}, config::Config)::Conn
    return _connect(remote_addr, local_addr, config)
end

"""
    connect(network, address; kwargs...) -> Conn

Connect to `address`, negotiate TLS, and return a fully handshaken client
connection.

Network-resolution keyword arguments are:
- `timeout_ns`
- `deadline_ns`
- `local_addr`
- `fallback_delay_ns`
- `resolver`
- `policy`

TLS keyword arguments are forwarded to `Config`:
- `server_name`
- `verify_peer`
- `client_auth`
- `cert_file`
- `key_file`
- `ca_file`
- `client_ca_file`
- `alpn_protocols`
- `handshake_timeout_ns`
- `min_version`
- `max_version`

If `server_name` is omitted, it is derived from `address` when possible so SNI
and peer verification use the dial target's host name automatically.
"""
function connect(
        network::AbstractString,
        address::AbstractString;
        timeout_ns::Integer = Int64(0),
        deadline_ns::Integer = Int64(0),
        local_addr::Union{Nothing, TCP.SocketEndpoint} = nothing,
        fallback_delay_ns::Integer = Int64(300_000_000),
        resolver::HostResolvers.AbstractResolver = HostResolvers.DEFAULT_RESOLVER,
        policy::HostResolvers.ResolverPolicy = HostResolvers.ResolverPolicy(),
        kw...
    )::Conn
    host_resolver = HostResolvers.HostResolver(; timeout_ns, deadline_ns, local_addr, fallback_delay_ns, resolver, policy)
    return _connect(host_resolver, network, address, Config(; kw...))
end

function connect(
        network::AbstractString,
        address::AbstractString,
        config::Config;
        timeout_ns::Integer = Int64(0),
        deadline_ns::Integer = Int64(0),
        local_addr::Union{Nothing, TCP.SocketEndpoint} = nothing,
        fallback_delay_ns::Integer = Int64(300_000_000),
        resolver::HostResolvers.AbstractResolver = HostResolvers.DEFAULT_RESOLVER,
        policy::HostResolvers.ResolverPolicy = HostResolvers.ResolverPolicy(),
    )::Conn
    host_resolver = HostResolvers.HostResolver(; timeout_ns, deadline_ns, local_addr, fallback_delay_ns, resolver, policy)
    return _connect(host_resolver, network, address, config)
end

"""
    connect(address; kwargs...) -> Conn

Convenience shorthand for `connect("tcp", address; kwargs...)`.
"""
function connect(address::AbstractString; kwargs...)::Conn
    return connect("tcp", address; kwargs...)
end

function connect(address::AbstractString, config::Config)::Conn
    return connect("tcp", address, config)
end

"""
    listen(local_addr, config; backlog=128, reuseaddr=true) -> Listener

Create a TLS listener from a concrete local `TCP.SocketAddr`.

This is the direct-address counterpart to `listen(network, address, config;
...)`. The underlying TCP listener is created with `TCP.listen`, then accepted
connections are wrapped in lazy-handshake TLS state.
"""
function listen(
        local_addr::TCP.SocketAddr,
        config::Config;
        backlog::Integer = 128,
        reuseaddr::Bool = true,
    )::Listener
    _validate_config(config; is_server = true)
    listener = TCP.listen(local_addr; backlog = backlog, reuseaddr = reuseaddr)
    return Listener(listener, config)
end

end
