"""
    TLS

TLS client/server layer built on native TLS 1.2/1.3 machinery, OpenSSL-backed
crypto/X.509 helpers, and `TCP` connections.

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

const TLS1_2_VERSION = UInt16(0x0303)
const TLS1_3_VERSION = UInt16(0x0304)
const _TLS_LEGACY_RECORD_VERSION = UInt16(0x0301)

include("tls/crypto.jl")
include("tls/record_common.jl")
include("tls/session_cache.jl")
include("tls/openssl_crypto.jl")
include("tls/handshake_messages.jl")
include("tls/handshake_common.jl")
include("tls/handshake_client_tls13.jl")
include("tls/record_tls13.jl")
include("tls/x509.jl")
include("tls/record_tls12.jl")
include("tls/handshake_client_tls12.jl")
include("tls/handshake_server_tls13.jl")
include("tls/handshake_server_tls12.jl")

const X25519 = _TLS_GROUP_X25519
const P256 = _TLS_GROUP_SECP256R1

"""
    ClientAuthMode

Server-side client certificate policy for native TLS handshakes.

The values intentionally mirror Go's client-auth policy surface: callers pick a
policy up front in `Config`, then the TLS 1.2/1.3 server handshakes interpret
that policy consistently when deciding whether to request, require, and verify
client certificates.
"""
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
or preparing a TLS connection/listener.
"""
struct ConfigError <: Exception
    message::String
end

"""
    TLSError

Raised when TLS handshake/read/write/close operations fail.

`code` is `0` for pure Julia-side failures and may be nonzero when the
OpenSSL-backed primitive layer reports a backend error. `cause` preserves the
underlying Julia-side exception when the failure originated in the
transport/poller layer or a higher-level TLS check.
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
- `verify_peer`: whether to validate the remote certificate chain against trusted roots.
- `verify_hostname`: whether to validate the remote peer name against the presented
  leaf certificate. This defaults to `verify_peer`, but can be enabled separately.
- `client_auth`: server-side client certificate policy.
- `cert_file` / `key_file`: PEM-encoded certificate chain and private key. Servers must
  provide both; clients may provide both for mutual TLS.
- `ca_file`: CA bundle or hashed CA directory used to verify remote servers. When omitted,
  client verification uses `NetworkOptions.ca_roots_path()`.
- `client_ca_file`: CA bundle or hashed CA directory used by servers to verify client
  certificates. This is required for server configs that verify presented client certs.
- `alpn_protocols`: ordered ALPN protocol preference list.
- `curve_preferences`: ordered native ECDHE group preferences for TLS 1.2/1.3.
  When empty, native TLS 1.3 and mixed-mode handshakes default to `[TLS.X25519, TLS.P256]`,
  while exact native TLS 1.2 defaults to `[TLS.P256]`.
- `handshake_timeout_ns`: optional cap, in monotonic nanoseconds, applied only while the
  handshake is running. Existing transport deadlines still win if they are earlier.
- `min_version` / `max_version`: TLS protocol version bounds. Only TLS 1.2 and TLS 1.3
  are supported; `nothing` leaves the bound unset.

Returns a reusable immutable `Config`.

Throws `ConfigError` if the keyword combination is internally inconsistent.
"""
struct Config
    server_name::Union{Nothing, String}
    verify_peer::Bool
    verify_hostname::Bool
    client_auth::ClientAuthMode.T
    cert_file::Union{Nothing, String}
    key_file::Union{Nothing, String}
    ca_file::Union{Nothing, String}
    client_ca_file::Union{Nothing, String}
    alpn_protocols::Vector{String}
    curve_preferences::Vector{UInt16}
    handshake_timeout_ns::Int64
    min_version::Union{Nothing, UInt16}
    max_version::Union{Nothing, UInt16}
    session_tickets_disabled::Bool
    _session_ticket_keys::_TLSSessionTicketKeyState
    _client_session_cache::_TLSSessionCache{_TLS13ClientSession}
    _server_session_cache::_TLSSessionCache{_TLS13ServerSession}
    _client_session_cache12::_TLSSessionCache{_TLS12ClientSession}
    _server_session_cache12::_TLSSessionCache{_TLS12ServerSession}
end

# `policy` records which native handshake lane a `Conn` should enter before the
# protocol version is known. Exact TLS 1.2 / TLS 1.3 configs use a fixed lane,
# while `_TLS_POLICY_AUTO` means "emit a mixed ClientHello/accept both versions
# and then commit to the negotiated native state machine".
const _TLS_POLICY_TLS13 = UInt8(1)
const _TLS_POLICY_TLS12 = UInt8(2)
const _TLS_POLICY_AUTO = UInt8(3)

@inline _is_tls13_policy(policy::UInt8) = policy == _TLS_POLICY_TLS13
@inline _is_tls12_policy(policy::UInt8) = policy == _TLS_POLICY_TLS12
@inline _is_tls_auto_policy(policy::UInt8) = policy == _TLS_POLICY_AUTO

function Config(;
        server_name::Union{Nothing, AbstractString} = nothing,
        verify_peer::Bool = true,
        verify_hostname::Bool = verify_peer,
        client_auth::ClientAuthMode.T = ClientAuthMode.NoClientCert,
        cert_file::Union{Nothing, AbstractString} = nothing,
        key_file::Union{Nothing, AbstractString} = nothing,
        ca_file::Union{Nothing, AbstractString} = nothing,
        client_ca_file::Union{Nothing, AbstractString} = nothing,
        alpn_protocols::Vector{String} = String[],
        curve_preferences::Vector{UInt16} = UInt16[],
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
    min_version !== nothing && _require_supported_tls_version!("min_version", min_version::UInt16)
    max_version !== nothing && _require_supported_tls_version!("max_version", max_version::UInt16)
    if min_version !== nothing && max_version !== nothing
        (min_version::UInt16) <= (max_version::UInt16) || throw(ConfigError("min_version must be <= max_version"))
    end
    return Config(
        server_name_s,
        verify_peer,
        verify_hostname,
        client_auth,
        cert_file_s,
        key_file_s,
        ca_file_s,
        client_ca_file_s,
        copy(alpn_protocols),
        copy(curve_preferences),
        Int64(handshake_timeout_ns),
        min_version,
        max_version,
        session_tickets_disabled,
        _TLSSessionTicketKeyState(),
        _TLSSessionCache(_TLS13ClientSession, session_cache_capacity),
        _TLSSessionCache(_TLS13ServerSession, session_cache_capacity),
        _TLSSessionCache(_TLS12ClientSession, session_cache_capacity),
        _TLSSessionCache(_TLS12ServerSession, session_cache_capacity),
    )
end

const _NATIVE_DEFAULT_CURVE_PREFERENCES = (_TLS_GROUP_X25519, _TLS_GROUP_SECP256R1)

@inline _supported_tls_version(version::UInt16)::Bool = version == TLS1_2_VERSION || version == TLS1_3_VERSION
@inline _tls_version_hex(version::UInt16)::String = "0x" * string(version, base = 16, pad = 4)

function _require_supported_tls_version!(field_name::AbstractString, version::UInt16)::Nothing
    _supported_tls_version(version) && return nothing
    throw(ConfigError("`$field_name` must be TLS 1.2 or TLS 1.3, got $(_tls_version_hex(version))"))
end

@inline function _native_curve_supported(group::UInt16)::Bool
    return group == _TLS_GROUP_X25519 || group == _TLS_GROUP_SECP256R1
end

@inline _curve_preference_name(group::UInt16) = "0x" * string(group, base = 16, pad = 4)

function _native_curve_preferences(config::Config)::Vector{UInt16}
    requested = config.curve_preferences
    isempty(requested) && return UInt16[_NATIVE_DEFAULT_CURVE_PREFERENCES...]
    out = UInt16[]
    for group in requested
        _native_curve_supported(group) || throw(ConfigError("unsupported curve preference: $(_curve_preference_name(group))"))
        in(group, out) || push!(out, group)
    end
    isempty(out) && throw(ConfigError("curve_preferences must include at least one supported native TLS group"))
    return out
end

function _tls12_curve_preferences(config::Config)::Vector{UInt16}
    isempty(config.curve_preferences) && return UInt16[_TLS_GROUP_SECP256R1]
    return _native_curve_preferences(config)
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

"""
    ConnectionState

Snapshot of negotiated TLS connection state.

Fields:
- `handshake_complete`: whether the TLS handshake has finished successfully.
- `version`: negotiated TLS protocol version string.
- `alpn_protocol`: negotiated ALPN protocol, or `nothing` if ALPN was not used.
- `cipher_suite`: negotiated cipher suite name, or `nothing` if it is not available.
- `using_native_tls13`: whether the connection is using the native TLS 1.3 path.
- `did_resume`: whether the connection resumed a previously cached TLS session.
- `did_hello_retry_request`: whether the handshake observed a TLS 1.3 HelloRetryRequest.
- `has_resumable_session`: whether this connection currently has a cached resumable native TLS session.
- `curve`: negotiated native TLS key share group name, or `nothing` if it is not available.
"""
struct ConnectionState
    handshake_complete::Bool
    version::String
    alpn_protocol::Union{Nothing, String}
    cipher_suite::Union{Nothing, String}
    using_native_tls13::Bool
    did_resume::Bool
    did_hello_retry_request::Bool
    has_resumable_session::Bool
    curve::Union{Nothing, String}
end

"""
    Conn

TLS stream wrapper over one `TCP.Conn`.

`Conn` is safe for one concurrent reader and one concurrent writer. Handshake,
read, and write all have separate locks so lazy handshakes and shutdown can
coordinate cleanly across the native TLS state machine. Because `Conn <: IO`,
standard Base stream helpers like `read`, `read!`, `readbytes!`, `eof`, and
`write` apply directly to decrypted application data.
"""
mutable struct Conn <: IO
    tcp::TCP.Conn
    policy::UInt8
    is_server::Bool
    config::Config
    native_state::Union{Nothing, _TLS13NativeClientState, _TLS12NativeState}
    handshake_lock::ReentrantLock
    read_lock::ReentrantLock
    write_lock::ReentrantLock
    @atomic handshake_complete::Bool
    @atomic closed::Bool
    @atomic active_version::UInt16
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

function __init__()
    # Module initialization ensures OpenSSL-backed primitive helpers are ready
    # before any TLS handshake or record code reaches into EVP/X509 routines.
    global _LIBCRYPTO_PATH = OpenSSL_jll.libcrypto_path
    global _LIBSSL_PATH = OpenSSL_jll.libssl_path
    _ = @gcsafe_ccall _LIBSSL_PATH.OPENSSL_init_ssl(
        Culong(0)::Culong,
        C_NULL::Ptr{Cvoid},
    )::Cint
    _init_x25519_pkey_id!()
    _init_p256_group_nid!()
    _init_p384_group_nid!()
    _init_p521_group_nid!()
    return nothing
end

@inline function _as_exception(err)::Exception
    return err::Exception
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

function _config_with_server_name(config::Config, server_name::String)::Config
    return Config(
        server_name,
        config.verify_peer,
        config.verify_hostname,
        config.client_auth,
        config.cert_file,
        config.key_file,
        config.ca_file,
        config.client_ca_file,
        copy(config.alpn_protocols),
        copy(config.curve_preferences),
        config.handshake_timeout_ns,
        config.min_version,
        config.max_version,
        config.session_tickets_disabled,
        config._session_ticket_keys,
        config._client_session_cache,
        config._server_session_cache,
        config._client_session_cache12,
        config._server_session_cache12,
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

# Validation is deliberately separated from `Config` construction: building a
# config should stay cheap and pure, while path existence checks and policy
# coherence checks only happen when a client/server context is actually needed.
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
        if (config.verify_peer || config.verify_hostname) &&
           (config.server_name === nothing || isempty(config.server_name::String))
            throw(ConfigError("client TLS with `verify_peer=true` or `verify_hostname=true` requires `server_name`"))
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
    config.min_version !== nothing && _require_supported_tls_version!("min_version", config.min_version::UInt16)
    config.max_version !== nothing && _require_supported_tls_version!("max_version", config.max_version::UInt16)
    if config.min_version !== nothing && config.max_version !== nothing
        (config.min_version::UInt16) <= (config.max_version::UInt16) || throw(ConfigError("min_version must be <= max_version"))
    end
    if !isempty(config.curve_preferences)
        _native_curve_preferences(config)
    end
    return nothing
end

@inline function _native_tls13_only(config::Config)::Bool
    return _config_allows_tls_version(config, TLS1_3_VERSION) &&
        !_config_allows_tls_version(config, TLS1_2_VERSION)
end

@inline function _native_tls12_only(config::Config)::Bool
    return _config_allows_tls_version(config, TLS1_2_VERSION) &&
        !_config_allows_tls_version(config, TLS1_3_VERSION)
end

@inline function _config_allows_tls_version(config::Config, version::UInt16)::Bool
    if config.min_version !== nothing && version < (config.min_version::UInt16)
        return false
    end
    if config.max_version !== nothing && version > (config.max_version::UInt16)
        return false
    end
    return true
end

function _native_supported_versions(config::Config)::Vector{UInt16}
    versions = UInt16[]
    _config_allows_tls_version(config, TLS1_3_VERSION) && push!(versions, TLS1_3_VERSION)
    _config_allows_tls_version(config, TLS1_2_VERSION) && push!(versions, TLS1_2_VERSION)
    return versions
end

@inline function _native_tls_mixed_versions(config::Config)::Bool
    return _config_allows_tls_version(config, TLS1_2_VERSION) &&
        _config_allows_tls_version(config, TLS1_3_VERSION)
end

@inline function _native_tls_auto_client_enabled(config::Config)::Bool
    return _native_tls_mixed_versions(config)
end

@inline function _native_tls_auto_server_enabled(config::Config)::Bool
    return _native_tls_mixed_versions(config) &&
        config.cert_file !== nothing &&
        config.key_file !== nothing
end

# Client/server policy selection answers a single question: which native
# handshake engine should this connection enter before any bytes are exchanged?
# The answer is exact TLS 1.2, exact TLS 1.3, or mixed-version auto negotiation.
@inline function _tls_client_policy(config::Config)::UInt8
    if _native_tls13_only(config)
        return _TLS_POLICY_TLS13
    end
    if _native_tls12_only(config)
        return _TLS_POLICY_TLS12
    end
    if _native_tls_auto_client_enabled(config)
        return _TLS_POLICY_AUTO
    end
    throw(ConfigError("unsupported client TLS config"))
end

@inline function _tls_server_policy(config::Config)::UInt8
    if _native_tls13_server_enabled(config)
        return _TLS_POLICY_TLS13
    end
    if _native_tls12_server_enabled(config)
        return _TLS_POLICY_TLS12
    end
    if _native_tls_auto_server_enabled(config)
        return _TLS_POLICY_AUTO
    end
    throw(ConfigError("unsupported server TLS config"))
end

function _tls_supported_versions_from_max(max_version::UInt16)::Vector{UInt16}
    versions = UInt16[]
    max_version >= TLS1_3_VERSION && push!(versions, TLS1_3_VERSION)
    max_version >= TLS1_2_VERSION && push!(versions, TLS1_2_VERSION)
    return versions
end

function _tls_client_hello_supported_versions(client_hello::_ClientHelloMsg)::Vector{UInt16}
    versions = client_hello.supported_versions
    if isempty(versions)
        if client_hello.vers >= TLS1_3_VERSION
            return UInt16[TLS1_2_VERSION]
        end
        return _tls_supported_versions_from_max(client_hello.vers)
    end
    return versions
end

function _tls_mutual_supported_version(config::Config, peer_versions::AbstractVector{UInt16})::UInt16
    for version in _native_supported_versions(config)
        in(version, peer_versions) && return version
    end
    _tls_fail(_TLS_ALERT_PROTOCOL_VERSION, "tls: peer offered only unsupported native TLS versions")
end

function _tls_pick_client_version(config::Config, server_hello::_ServerHelloMsg)::UInt16
    peer_version = server_hello.supported_version == UInt16(0) ? server_hello.vers : server_hello.supported_version
    in(peer_version, _native_supported_versions(config)) ||
        _tls_fail(_TLS_ALERT_PROTOCOL_VERSION, "tls: server negotiated an unsupported TLS version")
    if peer_version != TLS1_3_VERSION && server_hello.supported_version != UInt16(0)
        _tls_fail(_TLS_ALERT_PROTOCOL_VERSION, "tls: server sent supported_versions for a pre-TLS 1.3 handshake")
    end
    if _config_allows_tls_version(config, TLS1_3_VERSION) && peer_version <= TLS1_2_VERSION
        random_tail = @view server_hello.random[25:32]
        (random_tail == _TLS13_DOWNGRADE_CANARY_TLS12 || random_tail == _TLS13_DOWNGRADE_CANARY_TLS11) &&
            _tls_fail(_TLS_ALERT_ILLEGAL_PARAMETER, "tls: downgrade attempt detected")
    end
    return peer_version
end

# These helpers construct the native ClientHello variants that front the exact
# TLS 1.3, exact TLS 1.2, and mixed-version native paths. Once the hello is on
# the wire, the corresponding handshake state machine owns all subsequent flow.
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
    hello.ticket_supported = !config.session_tickets_disabled
    hello.alpn_protocols = copy(config.alpn_protocols)
    hello.supported_points = UInt8[0x00]
    hello.supported_versions = UInt16[TLS1_3_VERSION]
    hello.supported_curves = _native_curve_preferences(config)
    hello.psk_modes = UInt8[_TLS_PSK_MODE_DHE]
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

function _tls_auto_client_hello(config::Config)::_ClientHelloMsg
    hello = _tls13_client_hello(config)
    hello.supported_versions = UInt16[TLS1_3_VERSION, TLS1_2_VERSION]
    hello.cipher_suites = UInt16[
        _TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_ID,
        _TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_ID,
        _TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256_ID,
        _TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384_ID,
        _TLS13_AES_128_GCM_SHA256_ID,
        _TLS13_CHACHA20_POLY1305_SHA256_ID,
        _TLS13_AES_256_GCM_SHA384_ID,
    ]
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
        _TLS_SIGNATURE_RSA_PKCS1_SHA256,
        _TLS_SIGNATURE_RSA_PKCS1_SHA384,
        _TLS_SIGNATURE_RSA_PKCS1_SHA512,
    ]
    hello.supported_signature_algorithms_cert = copy(hello.supported_signature_algorithms)
    return hello
end

function _native_tls13_certificate_verifier(config::Config)::_TLS13OpenSSLCertificateVerifier
    return _TLS13OpenSSLCertificateVerifier(
        verify_peer = config.verify_peer,
        verify_hostname = config.verify_hostname,
        ca_file = config.verify_peer ? _effective_ca_file(config; is_server = false) : nothing,
    )
end

function _native_tls13_client_identity(config::Config)::Tuple{Vector{Vector{UInt8}}, Ptr{Cvoid}}
    config.cert_file === nothing && return Vector{Vector{UInt8}}(), C_NULL
    cert_pem = _read_tls_file_bytes(config.cert_file::String)
    key_pem = _read_tls_file_bytes(config.key_file::String)
    try
        return _tls13_load_x509_pem_chain(cert_pem), _tls13_load_private_key_pem(key_pem)
    finally
        _securezero!(key_pem)
    end
end

# Session cache lookups validate cached material before the handshake consumes
# it. That keeps `connection_state` / resumption probes cheap while ensuring
# handshakes never proceed with expired, mismatched, or now-untrusted sessions.
function _tls12_try_load_client_session(config::Config, cache_key::AbstractString, hello::_ClientHelloMsg)::Union{Nothing, _TLS12ClientSession}
    config.session_tickets_disabled && return nothing
    isempty(cache_key) && return nothing
    session = _tls_session_cache_get(config._client_session_cache12, cache_key)
    session === nothing && return nothing
    keep_session = false
    try
        session.version == TLS1_2_VERSION || return nothing
        _tls12_cipher_spec(session.cipher_suite) === nothing && return nothing
        UInt64(floor(time())) <= session.use_by_s || return nothing
        in(session.cipher_suite, hello.cipher_suites) || return nothing
        if config.verify_peer || config.verify_hostname
            try
                _tls13_verify_server_certificate_chain(
                    session.certificates,
                    config.server_name === nothing ? "" : config.server_name::String;
                    verify_peer = config.verify_peer,
                    verify_hostname = config.verify_hostname,
                    ca_file = config.verify_peer ? _effective_ca_file(config; is_server = false) : nothing,
                )
            catch
                _tls_session_cache_put!(config._client_session_cache12, cache_key, nothing, _securezero_tls12_client_session!)
                return nothing
            end
        end
        hello.ticket_supported = true
        hello.session_ticket = copy(session.ticket)
        keep_session = true
        return session
    finally
        keep_session || _securezero_tls12_client_session!(session::_TLS12ClientSession)
    end
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
    session = _tls_session_cache_get(config._client_session_cache, cache_key)
    session === nothing && return nothing
    now_s = UInt64(floor(time()))
    if session.version != TLS1_3_VERSION || now_s > session.use_by_s
        _tls_session_cache_put!(config._client_session_cache, cache_key, nothing, _securezero_tls13_client_session!)
        _securezero_tls13_client_session!(session)
        return nothing
    end
    session_spec = _tls13_cipher_spec(session.cipher_suite)
    if session_spec === nothing
        _tls_session_cache_put!(config._client_session_cache, cache_key, nothing, _securezero_tls13_client_session!)
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
    if config.verify_peer || config.verify_hostname
        try
            _tls13_verify_server_certificate_chain(
                session.certificates,
                config.server_name === nothing ? "" : config.server_name::String;
                verify_peer = config.verify_peer,
                verify_hostname = config.verify_hostname,
                ca_file = config.verify_peer ? _effective_ca_file(config; is_server = false) : nothing,
            )
        catch
            _tls_session_cache_put!(config._client_session_cache, cache_key, nothing, _securezero_tls13_client_session!)
            _securezero_tls13_client_session!(session)
            return nothing
        end
    end
    ticket_age_ms = floor(UInt64, max(0.0, time() - Float64(session.created_at_s)) * 1000.0)
    hello.psk_modes = UInt8[_TLS_PSK_MODE_DHE]
    hello.psk_identities = [_TLSPSKIdentity(copy(session.ticket), UInt32(mod(ticket_age_ms + UInt64(session.age_add), UInt64(1) << 32)))]
    hello.psk_binders = [zeros(UInt8, _hash_len(session_spec.hash_kind))]
    return session
end

# `Conn` always starts with a version-appropriate native state allocation so the
# public wrapper can exist before any handshake bytes move. Mixed-mode starts in
# the TLS 1.3-shaped state because the first record/hello path is TLS 1.3-style;
# exact TLS 1.2 and post-negotiation mixed-mode then transition to the TLS 1.2
# native state container when required.
function _new_native_conn(tcp::TCP.Conn, config::Config, policy::UInt8, native_state; is_server::Bool)::Conn
    return Conn(
        tcp,
        policy,
        is_server,
        config,
        native_state,
        ReentrantLock(),
        ReentrantLock(),
        ReentrantLock(),
        false,
        false,
        UInt16(0),
        nothing,
        "",
        nothing,
    )
end

function _new_native_tls13_conn(tcp::TCP.Conn, config::Config; is_server::Bool)::Conn
    return _new_native_conn(tcp, config, _TLS_POLICY_TLS13, _TLS13NativeClientState(); is_server)
end

function _new_native_tls13_client_conn(tcp::TCP.Conn, config::Config)::Conn
    _validate_config(config; is_server = false)
    return _new_native_tls13_conn(tcp, config; is_server = false)
end

function _new_native_tls12_conn(tcp::TCP.Conn, config::Config; is_server::Bool)::Conn
    return _new_native_conn(tcp, config, _TLS_POLICY_TLS12, _TLS12NativeState(); is_server)
end

function _new_native_tls12_client_conn(tcp::TCP.Conn, config::Config)::Conn
    _validate_config(config; is_server = false)
    return _new_native_tls12_conn(tcp, config; is_server = false)
end

function _new_native_tls12_server_conn(tcp::TCP.Conn, config::Config)::Conn
    _validate_config(config; is_server = true)
    return _new_native_tls12_conn(tcp, config; is_server = true)
end

function _new_native_tls13_server_conn(tcp::TCP.Conn, config::Config)::Conn
    _validate_config(config; is_server = true)
    return _new_native_tls13_conn(tcp, config; is_server = true)
end

function _new_native_tls_auto_conn(tcp::TCP.Conn, config::Config; is_server::Bool)::Conn
    return _new_native_conn(tcp, config, _TLS_POLICY_AUTO, _TLS13NativeClientState(); is_server)
end

function _new_native_tls_auto_client_conn(tcp::TCP.Conn, config::Config)::Conn
    _validate_config(config; is_server = false)
    return _new_native_tls_auto_conn(tcp, config; is_server = false)
end

function _new_native_tls_auto_server_conn(tcp::TCP.Conn, config::Config)::Conn
    _validate_config(config; is_server = true)
    return _new_native_tls_auto_conn(tcp, config; is_server = true)
end

"""
    client(tcp, config) -> Conn

Wrap an established `TCP.Conn` in client-side TLS state.

The handshake is deferred until `handshake!` or the first read/write operation.

Throws `ConfigError` or `TLSError` if the TLS state cannot be initialized.
"""
function client(tcp::TCP.Conn, config::Config)::Conn
    policy = _tls_client_policy(config)
    if policy == _TLS_POLICY_TLS13
        return _new_native_tls13_client_conn(tcp, config)
    end
    if policy == _TLS_POLICY_TLS12
        return _new_native_tls12_client_conn(tcp, config)
    end
    if policy == _TLS_POLICY_AUTO
        return _new_native_tls_auto_client_conn(tcp, config)
    end
    throw(ConfigError("unsupported client TLS config"))
end

"""
    server(tcp, config) -> Conn

Wrap an established `TCP.Conn` in server-side TLS state.

The handshake is deferred until `handshake!` or the first read/write operation.

Throws `ConfigError` or `TLSError` if the TLS state cannot be initialized.
"""
function server(tcp::TCP.Conn, config::Config)::Conn
    policy = _tls_server_policy(config)
    if policy == _TLS_POLICY_TLS13
        return _new_native_tls13_server_conn(tcp, config)
    end
    if policy == _TLS_POLICY_TLS12
        return _new_native_tls12_server_conn(tcp, config)
    end
    if policy == _TLS_POLICY_AUTO
        return _new_native_tls_auto_server_conn(tcp, config)
    end
    throw(ConfigError("unsupported server TLS config"))
end

function _free_native_handles!(conn::Conn)
    state = conn.native_state
    state === nothing && return nothing
    if state isa _TLS13NativeClientState
        _securezero_tls13_native_client_state!(state)
        conn.native_state = nothing
        return nothing
    end
    if state isa _TLS12NativeState
        _securezero_tls12_native_state!(state)
        conn.native_state = nothing
        return nothing
    end
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

function _set_handshake_complete!(conn::Conn, active_version::UInt16, negotiated_version::String, negotiated_alpn::Union{Nothing, String})
    @atomic :release conn.active_version = active_version
    conn.negotiated_version = negotiated_version
    conn.negotiated_alpn = negotiated_alpn
    @atomic :release conn.handshake_complete = true
    return nothing
end

@inline function _handshake_complete(conn::Conn)::Bool
    return @atomic :acquire conn.handshake_complete
end

@inline function _active_tls_version(conn::Conn)::UInt16
    return @atomic :acquire conn.active_version
end

@inline _active_tls13(conn::Conn)::Bool = _active_tls_version(conn) == TLS1_3_VERSION
@inline _active_tls12(conn::Conn)::Bool = _active_tls_version(conn) == TLS1_2_VERSION

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

@inline function _native_tls12_state(conn::Conn)::_TLS12NativeState
    state = conn.native_state
    state === nothing && throw(_closed_error("tls12"))
    return state::_TLS12NativeState
end

# Mixed-version handshakes reuse the bytes buffered during the initial TLS 1.3-
# style record/hello exchange. When the negotiated version downgrades to TLS
# 1.2, we copy that shared transport state into the TLS 1.2 native container so
# the exact TLS 1.2 record/handshake code can continue from the same stream.
function _tls12_copy_initial_state(state13::_TLS13NativeClientState)::_TLS12NativeState
    state12 = _TLS12NativeState()
    state12.handshake_buffer = copy(state13.handshake_buffer)
    state12.handshake_buffer_pos = state13.handshake_buffer_pos
    state12.plaintext_buffer = copy(state13.plaintext_buffer)
    state12.plaintext_buffer_pos = state13.plaintext_buffer_pos
    state12.peer_close_notify = state13.peer_close_notify
    state12.sent_close_notify = state13.sent_close_notify
    return state12
end

function _ensure_open!(conn::Conn, op::AbstractString)
    _is_closed(conn) && throw(_closed_error(op))
    conn.native_state === nothing && throw(_closed_error(op))
    return nothing
end

function _native_tls13_client_handshake!(conn::Conn)::Nothing
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
    client_certificate_chain = Vector{Vector{UInt8}}()
    client_private_key = Ptr{Cvoid}(C_NULL)
    try
        client_certificate_chain, client_private_key = _native_tls13_client_identity(conn.config)
        state.client_certificate_chain = client_certificate_chain
        state.client_private_key = client_private_key
        _client_handshake_tls13!(state, io)
        _finish_native_tls13_client_handshake!(conn, state, cache_key)
    finally
        _securezero_tls13_client_handshake_state!(state)
    end
    return nothing
end

function _native_tls12_client_handshake!(conn::Conn)::Nothing
    cache_key = _tls13_client_session_cache_key(conn.config, conn.tcp)
    client_hello = _tls12_client_hello(conn.config)
    session = _tls12_try_load_client_session(conn.config, cache_key, client_hello)
    state = _TLS12ClientHandshakeState(client_hello, session)
    native_state = _native_tls12_state(conn)
    io = _TLS12HandshakeRecordIO(conn.tcp, native_state)
    try
        _client_handshake_tls12!(state, io, conn.config)
        _finish_native_tls12_client_handshake!(conn, state)
    finally
        _securezero_tls12_client_handshake_state!(state)
    end
    return nothing
end

function _finish_native_tls13_client_handshake!(conn::Conn, state::_TLS13ClientHandshakeState, cache_key::String)::Nothing
    native_state = _native_tls13_state(conn)
    if state.using_psk
        _tls_session_cache_put!(conn.config._client_session_cache, cache_key, nothing, _securezero_tls13_client_session!)
    end
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
    _set_handshake_complete!(conn, TLS1_3_VERSION, "TLSv1.3", negotiated_alpn)
    return nothing
end

function _finish_native_tls12_client_handshake!(conn::Conn, state::_TLS12ClientHandshakeState)::Nothing
    native_state = _native_tls12_state(conn)
    native_state.did_resume = state.did_resume
    native_state.curve_id = state.curve_id
    native_state.cipher_suite = state.cipher_suite
    _set_handshake_complete!(conn, TLS1_2_VERSION, "TLSv1.2", isempty(state.client_protocol) ? nothing : state.client_protocol)
    return nothing
end

function _finish_native_tls13_server_handshake!(conn::Conn, state::_TLS13ServerHandshakeState)::Nothing
    native_state = _native_tls13_state(conn)
    native_state.session_cipher_suite = state.cipher_suite
    native_state.session_alpn = state.selected_alpn
    native_state.did_resume = state.using_psk
    native_state.did_hello_retry_request = state.did_hello_retry_request
    native_state.curve_id = state.selected_group
    _set_handshake_complete!(conn, TLS1_3_VERSION, "TLSv1.3", isempty(state.selected_alpn) ? nothing : state.selected_alpn)
    return nothing
end

function _finish_native_tls12_server_handshake!(conn::Conn, state::_TLS12ServerHandshakeState)::Nothing
    native_state = _native_tls12_state(conn)
    native_state.did_resume = state.using_resumption
    native_state.curve_id = state.curve_id
    native_state.cipher_suite = state.cipher_suite
    _set_handshake_complete!(conn, TLS1_2_VERSION, "TLSv1.2", isempty(state.selected_alpn) ? nothing : state.selected_alpn)
    return nothing
end

# Mixed-mode client flow owns only the first flight/version selection. Once the
# peer commits to TLS 1.2 or TLS 1.3, we hand the buffered transcript and record
# state to the exact-version implementation and let it finish the handshake.
function _native_tls_auto_client_handshake!(conn::Conn)::Nothing
    cache_key = _tls13_client_session_cache_key(conn.config, conn.tcp)
    client_hello = _tls_auto_client_hello(conn.config)
    session13 = _tls13_try_load_client_session(conn.config, cache_key, client_hello)
    session12 = _tls12_try_load_client_session(conn.config, cache_key, client_hello)
    state13 = _TLS13ClientHandshakeState(
        client_hello,
        _TLS13OpenSSLKeyShareProvider(),
        _native_tls13_certificate_verifier(conn.config),
        session13,
    )
    native_state13 = _native_tls13_state(conn)
    io13 = _TLS13HandshakeRecordIO(conn.tcp, native_state13)
    try
        _write_client_hello!(state13, io13)
        raw_server_hello = _read_handshake_bytes!(io13)
        server_hello = _unmarshal_server_hello(raw_server_hello)
        server_hello === nothing && _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: native mixed-version client expected ServerHello")
        state13.server_hello_raw = raw_server_hello
        state13.server_hello = server_hello
        state13.have_server_hello = true
        negotiated_version = _tls_pick_client_version(conn.config, state13.server_hello)
        if negotiated_version == TLS1_3_VERSION
            _check_server_hello_or_hrr!(state13)
            _client_handshake_tls13_after_server_hello!(state13, io13)
            _finish_native_tls13_client_handshake!(conn, state13, cache_key)
            return nothing
        end
        # TLS 1.2 reuses the already-written mixed ClientHello and the received
        # ServerHello so the exact TLS 1.2 client state machine can continue
        # without re-reading the transport.
        raw_client_hello = copy(state13.client_hello_raw)
        raw_server_hello = copy(state13.server_hello_raw)
        client_hello12 = _unmarshal_client_hello(raw_client_hello)
        client_hello12 === nothing && throw(ArgumentError("tls: malformed native mixed-version ClientHello"))
        state12 = _TLS12ClientHandshakeState(client_hello12, session12)
        state12_native = _tls12_copy_initial_state(native_state13)
        io12 = _TLS12HandshakeRecordIO(conn.tcp, state12_native)
        installed_state12 = false
        try
            _tls12_set_server_hello!(state12, raw_server_hello)
            _client_handshake_tls12_after_server_hello!(state12, io12, conn.config, raw_client_hello, raw_server_hello, cache_key)
            conn.native_state = state12_native
            installed_state12 = true
            _securezero_tls13_native_client_state!(native_state13)
            _finish_native_tls12_client_handshake!(conn, state12)
        finally
            installed_state12 || _securezero_tls12_native_state!(state12_native)
            _securezero_tls12_client_handshake_state!(state12)
        end
    finally
        _securezero_tls13_client_handshake_state!(state13)
    end
    return nothing
end

# Mixed-mode server flow mirrors the client side: parse one ClientHello, pick a
# mutual version, then hand the live buffered state to the exact-version server
# handshake implementation that owns the remainder of the protocol.
function _native_tls_auto_server_handshake!(conn::Conn)::Nothing
    native_state13 = _native_tls13_state(conn)
    io13 = _TLS13HandshakeRecordIO(conn.tcp, native_state13)
    raw_client_hello = _read_handshake_bytes!(io13)
    client_hello = _unmarshal_client_hello(raw_client_hello)
    client_hello === nothing && _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, "tls: native mixed-version server expected ClientHello")
    negotiated_version = _tls_mutual_supported_version(conn.config, _tls_client_hello_supported_versions(client_hello))
    if negotiated_version == TLS1_3_VERSION
        state13 = _TLS13ServerHandshakeState(conn.config)
        try
            _tls13_set_client_hello!(state13, raw_client_hello)
            _server_handshake_tls13_after_client_hello!(state13, io13, conn.config)
            _finish_native_tls13_server_handshake!(conn, state13)
        finally
            _securezero_tls13_server_handshake_state!(state13)
        end
        return nothing
    end
    state12_native = _tls12_copy_initial_state(native_state13)
    io12 = _TLS12HandshakeRecordIO(conn.tcp, state12_native)
    state12 = _TLS12ServerHandshakeState(conn.config)
    installed_state12 = false
    try
        state12.send_downgrade_canary = true
        _tls12_set_client_hello!(state12, raw_client_hello)
        _server_handshake_tls12_after_client_hello!(state12, io12, conn.config, raw_client_hello)
        conn.native_state = state12_native
        installed_state12 = true
        _securezero_tls13_native_client_state!(native_state13)
        _finish_native_tls12_server_handshake!(conn, state12)
    finally
        installed_state12 || _securezero_tls12_native_state!(state12_native)
        _securezero_tls12_server_handshake_state!(state12)
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
only one task drives the native TLS state machine while the others observe the
completed state afterward.

Returns `nothing`.

Throws:
- `TLSHandshakeTimeoutError` when `config.handshake_timeout_ns` expires
- `TLSError` for TLS or transport failures
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
                if _is_tls13_policy(conn.policy)
                    if conn.is_server
                        _native_tls13_server_handshake!(conn)
                    else
                        _native_tls13_client_handshake!(conn)
                    end
                    return nothing
                end
                if _is_tls12_policy(conn.policy)
                    if conn.is_server
                        _native_tls12_server_handshake!(conn)
                    else
                        _native_tls12_client_handshake!(conn)
                    end
                    return nothing
                end
                if _is_tls_auto_policy(conn.policy)
                    if conn.is_server
                        _native_tls_auto_server_handshake!(conn)
                    else
                        _native_tls_auto_client_handshake!(conn)
                    end
                    return nothing
                end
                throw(ArgumentError("tls: unsupported connection mode"))
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
            if ex isa _TLSAlertError
                tls13_err = ex::_TLSAlertError
                if _is_tls13_policy(conn.policy) && !tls13_err.from_peer
                    _native_tls13_try_write_fatal_alert!(conn, tls13_err.alert)
                elseif _is_tls12_policy(conn.policy) && !tls13_err.from_peer
                    _native_tls12_try_write_fatal_alert!(conn, tls13_err.alert)
                elseif _is_tls_auto_policy(conn.policy) && !tls13_err.from_peer
                    _native_auto_try_write_fatal_alert!(conn, tls13_err.alert)
                end
                throw(TLSError("handshake", Int32(0), tls13_err.message, tls13_err))
            end
            if ex isa ArgumentError
                if _is_tls13_policy(conn.policy)
                    _native_tls13_try_write_fatal_alert!(conn, _TLS_ALERT_INTERNAL_ERROR)
                elseif _is_tls12_policy(conn.policy)
                    _native_tls12_try_write_fatal_alert!(conn, _TLS_ALERT_INTERNAL_ERROR)
                elseif _is_tls_auto_policy(conn.policy)
                    _native_auto_try_write_fatal_alert!(conn, _TLS_ALERT_INTERNAL_ERROR)
                end
                throw(TLSError("handshake", Int32(0), (ex::ArgumentError).msg::String, ex))
            end
            throw(TLSError("handshake", Int32(0), "unexpected TLS failure", ex))
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
    return _tls_buffer_available(state.plaintext_buffer, state.plaintext_buffer_pos)
end

@inline function _native_tls12_pending_plaintext(conn::Conn)::Int
    state = _native_tls12_state(conn)
    return _tls_buffer_available(state.plaintext_buffer, state.plaintext_buffer_pos)
end

# Read paths all follow the same pattern:
# 1. ensure the handshake completed,
# 2. drain any buffered plaintext,
# 3. if necessary read more TLS records,
# 4. translate protocol/transport failures into `TLSError`.
function _native_tls13_fill_plaintext!(conn::Conn)::Nothing
    state = _native_tls13_state(conn)
    while true
        _tls13_handle_post_handshake_messages!(conn, state)
        _tls_buffer_available(state.plaintext_buffer, state.plaintext_buffer_pos) > 0 && return nothing
        state.peer_close_notify && throw(EOFError())
        _tls13_read_record!(conn.tcp, state)
    end
end

function _native_tls12_fill_plaintext!(conn::Conn)::Nothing
    state = _native_tls12_state(conn)
    while true
        _tls_buffer_available(state.plaintext_buffer, state.plaintext_buffer_pos) > 0 && return nothing
        state.peer_close_notify && throw(EOFError())
        _tls12_read_record!(conn.tcp, state)
    end
end

function _native_tls13_take_plaintext!(conn::Conn, ptr::Ptr{UInt8}, nbytes::Int)::Int
    nbytes == 0 && return 0
    _native_tls13_fill_plaintext!(conn)
    state = _native_tls13_state(conn)
    available = _tls_buffer_available(state.plaintext_buffer, state.plaintext_buffer_pos)
    n = min(nbytes, available)
    unsafe_copyto!(ptr, pointer(state.plaintext_buffer, state.plaintext_buffer_pos), n)
    state.plaintext_buffer_pos += n
    state.plaintext_buffer_pos = _tls_compact_buffer!(state.plaintext_buffer, state.plaintext_buffer_pos)
    return n
end

function _native_tls12_take_plaintext!(conn::Conn, ptr::Ptr{UInt8}, nbytes::Int)::Int
    nbytes == 0 && return 0
    _native_tls12_fill_plaintext!(conn)
    state = _native_tls12_state(conn)
    available = _tls_buffer_available(state.plaintext_buffer, state.plaintext_buffer_pos)
    n = min(nbytes, available)
    unsafe_copyto!(ptr, pointer(state.plaintext_buffer, state.plaintext_buffer_pos), n)
    state.plaintext_buffer_pos += n
    state.plaintext_buffer_pos = _tls_compact_buffer!(state.plaintext_buffer, state.plaintext_buffer_pos)
    return n
end

@inline function _pending_plaintext(conn::Conn)::Int
    _active_tls13(conn) && return _native_tls13_pending_plaintext(conn)
    _active_tls12(conn) && return _native_tls12_pending_plaintext(conn)
    return 0
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
        if _active_tls13(conn)
            return _native_tls13_take_plaintext!(conn, ptr, nbytes)
        end
        if _active_tls12(conn)
            return _native_tls12_take_plaintext!(conn, ptr, nbytes)
        end
        throw(ArgumentError("tls: unsupported connection mode"))
    catch err
        ex = _as_exception(err)
        ex isa EOFError && rethrow()
        ex isa TLSError && rethrow()
        if ex isa IOPoll.NetClosingError || _is_closed(conn)
            throw(_closed_error("read", ex))
        end
        if ex isa _TLSAlertError
            tls13_err = ex::_TLSAlertError
            if _active_tls13(conn) && !tls13_err.from_peer
                _native_tls13_try_write_fatal_alert!(conn, tls13_err.alert)
            elseif _active_tls12(conn) && !tls13_err.from_peer
                _native_tls12_try_write_fatal_alert!(conn, tls13_err.alert)
            end
            throw(TLSError("read", Int32(0), tls13_err.message, tls13_err))
        end
        if ex isa ArgumentError
            if _active_tls13(conn)
                _native_tls13_try_write_fatal_alert!(conn, _TLS_ALERT_INTERNAL_ERROR)
            elseif _active_tls12(conn)
                _native_tls12_try_write_fatal_alert!(conn, _TLS_ALERT_INTERNAL_ERROR)
            end
            throw(TLSError("read", Int32(0), (ex::ArgumentError).msg::String, ex))
        end
        throw(TLSError("read", Int32(0), "unexpected TLS failure", ex))
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
        if _active_tls13(conn)
            state = _native_tls13_state(conn)
            while true
                _tls13_handle_post_handshake_messages!(conn, state)
                _tls_buffer_available(state.plaintext_buffer, state.plaintext_buffer_pos) > 0 && return false
                state.peer_close_notify && return true
                _tls13_read_record!(conn.tcp, state)
            end
        end
        if _active_tls12(conn)
            state = _native_tls12_state(conn)
            while true
                _tls_buffer_available(state.plaintext_buffer, state.plaintext_buffer_pos) > 0 && return false
                state.peer_close_notify && return true
                _tls12_read_record!(conn.tcp, state)
            end
        end
        throw(ArgumentError("tls: unsupported connection mode"))
    catch err
        ex = _as_exception(err)
        ex isa TLSError && rethrow()
        if ex isa IOPoll.NetClosingError || _is_closed(conn)
            throw(_closed_error("peek", ex))
        end
        if ex isa _TLSAlertError
            tls13_err = ex::_TLSAlertError
            if _active_tls13(conn) && !tls13_err.from_peer
                _native_tls13_try_write_fatal_alert!(conn, tls13_err.alert)
            elseif _active_tls12(conn) && !tls13_err.from_peer
                _native_tls12_try_write_fatal_alert!(conn, tls13_err.alert)
            end
            throw(TLSError("peek", Int32(0), tls13_err.message, tls13_err))
        end
        if ex isa ArgumentError
            if _active_tls13(conn)
                _native_tls13_try_write_fatal_alert!(conn, _TLS_ALERT_INTERNAL_ERROR)
            elseif _active_tls12(conn)
                _native_tls12_try_write_fatal_alert!(conn, _TLS_ALERT_INTERNAL_ERROR)
            end
            throw(TLSError("peek", Int32(0), (ex::ArgumentError).msg::String, ex))
        end
        throw(TLSError("peek", Int32(0), "unexpected TLS failure", ex))
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
    return !_is_closed(conn) && conn.native_state !== nothing && isopen(conn.tcp)
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

# Alert helpers are intentionally version-specific because the record encoders,
# cipher state, and shutdown rules differ across TLS 1.2 and TLS 1.3 even
# though `handshake!` / `read` / `write` surface them through a single `Conn`.
function _native_tls13_write_alert!(conn::Conn, alert_level::UInt8, alert_desc::UInt8)::Nothing
    state = _native_tls13_state(conn)
    state.sent_close_notify && return nothing
    _tls13_write_record!(conn.tcp, state.write_cipher, _TLS_RECORD_TYPE_ALERT, UInt8[alert_level, alert_desc])
    if alert_desc == _TLS_ALERT_CLOSE_NOTIFY
        state.sent_close_notify = true
    end
    return nothing
end

function _native_tls13_try_write_fatal_alert!(conn::Conn, alert_desc::UInt8)::Nothing
    _is_closed(conn) && return nothing
    !(conn.native_state isa _TLS13NativeClientState) && return nothing
    try
        _native_tls13_write_alert!(conn, _TLS_ALERT_LEVEL_FATAL, alert_desc)
    catch
    end
    return nothing
end

function _native_tls12_write_alert!(conn::Conn, alert_level::UInt8, alert_desc::UInt8)::Nothing
    state = _native_tls12_state(conn)
    state.sent_close_notify && return nothing
    _tls12_write_record!(conn.tcp, state.write_cipher, _TLS_RECORD_TYPE_ALERT, UInt8[alert_level, alert_desc])
    if alert_desc == _TLS_ALERT_CLOSE_NOTIFY
        state.sent_close_notify = true
    end
    return nothing
end

function _native_tls12_try_write_fatal_alert!(conn::Conn, alert_desc::UInt8)::Nothing
    _is_closed(conn) && return nothing
    !(conn.native_state isa _TLS12NativeState) && return nothing
    try
        _native_tls12_write_alert!(conn, _TLS_ALERT_LEVEL_FATAL, alert_desc)
    catch
    end
    return nothing
end

function _native_auto_try_write_fatal_alert!(conn::Conn, alert_desc::UInt8)::Nothing
    _is_closed(conn) && return nothing
    !_is_tls_auto_policy(conn.policy) && return nothing
    conn.native_state === nothing && return nothing
    try
        _tls_write_tls_plaintext!(conn.tcp, _TLS_RECORD_TYPE_ALERT, UInt8[_TLS_ALERT_LEVEL_FATAL, alert_desc], TLS1_2_VERSION)
    catch
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

function _native_tls12_write_application!(conn::Conn, ptr::Ptr{UInt8}, nbytes::Int)::Int
    state = _native_tls12_state(conn)
    total = 0
    while total < nbytes
        chunk_len = min(nbytes - total, _TLS12_MAX_PLAINTEXT)
        chunk = unsafe_wrap(Vector{UInt8}, ptr + total, chunk_len; own = false)
        _tls12_write_record!(conn.tcp, state.write_cipher, _TLS_RECORD_TYPE_APPLICATION_DATA, chunk)
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
        if _active_tls13(conn)
            return _native_tls13_write_application!(conn, ptr, nbytes_int)
        end
        if _active_tls12(conn)
            return _native_tls12_write_application!(conn, ptr, nbytes_int)
        end
        throw(ArgumentError("tls: unsupported connection mode"))
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
        if ex isa _TLSAlertError
            tls13_err = ex::_TLSAlertError
            if _active_tls13(conn) && !tls13_err.from_peer
                _native_tls13_try_write_fatal_alert!(conn, tls13_err.alert)
            elseif _active_tls12(conn) && !tls13_err.from_peer
                _native_tls12_try_write_fatal_alert!(conn, tls13_err.alert)
            end
            throw(TLSError("write", Int32(0), tls13_err.message, tls13_err))
        end
        if ex isa ArgumentError
            if _active_tls13(conn)
                _native_tls13_try_write_fatal_alert!(conn, _TLS_ALERT_INTERNAL_ERROR)
            elseif _active_tls12(conn)
                _native_tls12_try_write_fatal_alert!(conn, _TLS_ALERT_INTERNAL_ERROR)
            end
            throw(TLSError("write", Int32(0), (ex::ArgumentError).msg::String, ex))
        end
        throw(TLSError("write", Int32(0), "unexpected TLS failure", ex))
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

# `close` and `closewrite` cap the alert write deadline so a peer that never
# drains close-notify does not stall teardown forever. That mirrors Go's "best
# effort shutdown, then tear down the transport" behavior.
function _with_close_write_deadline_cap(f::F, conn::Conn) where {F}
    pfd = conn.tcp.fd.pfd
    pd = pfd.pd
    old_write_ns = @atomic :acquire pd.wd_ns
    close_deadline_ns = Int64(time_ns()) + Int64(5_000_000_000)
    write_deadline_ns = _handshake_effective_deadline(old_write_ns, close_deadline_ns)
    IOPoll.set_write_deadline!(pfd, write_deadline_ns)
    try
        return f()
    finally
        try
            IOPoll.set_write_deadline!(pfd, old_write_ns)
        catch
        end
    end
end

function _native_tls13_shutdown!(conn::Conn)::Nothing
    _with_close_write_deadline_cap(conn) do
        _native_tls13_write_alert!(conn, _TLS_ALERT_LEVEL_WARNING, _TLS_ALERT_CLOSE_NOTIFY)
    end
    return nothing
end

function _native_tls12_shutdown!(conn::Conn)::Nothing
    _with_close_write_deadline_cap(conn) do
        _native_tls12_write_alert!(conn, _TLS_ALERT_LEVEL_WARNING, _TLS_ALERT_CLOSE_NOTIFY)
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

"""
    close(conn)

Close the TLS connection and the underlying TCP transport.

If the handshake completed, this best-effort sends a TLS `close_notify` alert before
closing the socket. The method is idempotent and returns `nothing`.
"""
function Base.close(conn::Conn)
    _mark_closed!(conn) || return nothing
    if _handshake_complete(conn)
        if _try_lock_close_path!(conn)
            try
                if _active_tls13(conn)
                    _native_tls13_shutdown!(conn)
                elseif _active_tls12(conn)
                    _native_tls12_shutdown!(conn)
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
        if _active_tls13(conn)
            _native_tls13_shutdown!(conn)
        elseif _active_tls12(conn)
            _native_tls12_shutdown!(conn)
        end
        conn.write_permanent_error === nothing && (conn.write_permanent_error = TLSError("write", Int32(0), "tls: protocol is shutdown", nothing))
        return nothing
    catch err
        ex = _as_exception(err)
        ex isa TLSError && rethrow()
        if ex isa IOPoll.NetClosingError || _is_closed(conn)
            throw(_closed_error("closewrite", ex))
        end
        if ex isa ArgumentError
            throw(TLSError("closewrite", Int32(0), (ex::ArgumentError).msg::String, ex))
        end
        throw(TLSError("closewrite", Int32(0), "unexpected TLS failure", ex))
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

@inline function _tls13_cipher_suite_name(cipher_suite::UInt16)::Union{Nothing, String}
    cipher_suite == _TLS13_AES_128_GCM_SHA256_ID && return "TLS_AES_128_GCM_SHA256"
    cipher_suite == _TLS13_AES_256_GCM_SHA384_ID && return "TLS_AES_256_GCM_SHA384"
    cipher_suite == _TLS13_CHACHA20_POLY1305_SHA256_ID && return "TLS_CHACHA20_POLY1305_SHA256"
    return nothing
end

@inline function _tls12_cipher_suite_name(cipher_suite::UInt16)::Union{Nothing, String}
    cipher_suite == _TLS12_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256_ID && return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
    cipher_suite == _TLS12_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384_ID && return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
    cipher_suite == _TLS12_ECDHE_RSA_WITH_AES_128_GCM_SHA256_ID && return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
    cipher_suite == _TLS12_ECDHE_RSA_WITH_AES_256_GCM_SHA384_ID && return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"
    return nothing
end

@inline function _tls_group_name(group::UInt16)::Union{Nothing, String}
    group == _TLS_GROUP_X25519 && return "X25519"
    group == _TLS_GROUP_SECP256R1 && return "P-256"
    return nothing
end

function _tls13_has_resumable_session(config::Config, tcp::TCP.Conn)::Bool
    config.session_tickets_disabled && return false
    cache_key = _tls13_client_session_cache_key(config, tcp)
    isempty(cache_key) && return false
    session = _tls_session_cache_peek(config._client_session_cache, cache_key)
    session === nothing && return false
    try
        session.version == TLS1_3_VERSION || return false
        _tls13_cipher_spec(session.cipher_suite) === nothing && return false
        return UInt64(floor(time())) <= session.use_by_s
    finally
        _securezero_tls13_client_session!(session)
    end
end

function _tls12_has_resumable_session(config::Config, tcp::TCP.Conn)::Bool
    config.session_tickets_disabled && return false
    cache_key = _tls13_client_session_cache_key(config, tcp)
    isempty(cache_key) && return false
    session = _tls_session_cache_peek(config._client_session_cache12, cache_key)
    session === nothing && return false
    try
        session.version == TLS1_2_VERSION || return false
        _tls12_cipher_spec(session.cipher_suite) === nothing && return false
        return UInt64(floor(time())) <= session.use_by_s
    finally
        _securezero_tls12_client_session!(session)
    end
end

"""
    connection_state(conn) -> ConnectionState

Return a snapshot of the currently negotiated TLS state.

This does not force a handshake; if the handshake has not yet run, the returned
`ConnectionState` reports `handshake_complete=false`.
"""
function connection_state(conn::Conn)::ConnectionState
    if !_handshake_complete(conn) && _is_tls_auto_policy(conn.policy)
        resumable = conn.is_server ? false : (_tls13_has_resumable_session(conn.config, conn.tcp) || _tls12_has_resumable_session(conn.config, conn.tcp))
        return ConnectionState(
            _handshake_complete(conn),
            conn.negotiated_version,
            conn.negotiated_alpn,
            nothing,
            false,
            false,
            false,
            resumable,
            nothing,
        )
    end
    if _active_tls13(conn) || (_is_tls13_policy(conn.policy) && !_handshake_complete(conn))
        resumed = false
        did_hrr = false
        resumable = false
        cipher_suite = nothing
        curve = nothing
        if conn.native_state !== nothing
            native_state = conn.native_state::_TLS13NativeClientState
            resumed = native_state.did_resume
            did_hrr = native_state.did_hello_retry_request
            resumable = conn.is_server ? false : _tls13_has_resumable_session(conn.config, conn.tcp)
            cipher_suite = native_state.session_cipher_suite == UInt16(0) ? nothing : _tls13_cipher_suite_name(native_state.session_cipher_suite)
            curve = native_state.curve_id == UInt16(0) ? nothing : _tls_group_name(native_state.curve_id)
        end
        return ConnectionState(
            _handshake_complete(conn),
            conn.negotiated_version,
            conn.negotiated_alpn,
            cipher_suite,
            true,
            resumed,
            did_hrr,
            resumable,
            curve,
        )
    end
    if _active_tls12(conn) || (_is_tls12_policy(conn.policy) && !_handshake_complete(conn))
        resumed = false
        resumable = false
        cipher_suite = nothing
        curve = nothing
        if conn.native_state !== nothing
            native_state = conn.native_state::_TLS12NativeState
            resumed = native_state.did_resume
            resumable = conn.is_server ? false : _tls12_has_resumable_session(conn.config, conn.tcp)
            cipher_suite = native_state.cipher_suite == UInt16(0) ? nothing : _tls12_cipher_suite_name(native_state.cipher_suite)
            curve = native_state.curve_id == UInt16(0) ? nothing : _tls_group_name(native_state.curve_id)
        end
        return ConnectionState(
            _handshake_complete(conn),
            conn.negotiated_version,
            conn.negotiated_alpn,
            cipher_suite,
            false,
            resumed,
            false,
            resumable,
            curve,
        )
    end
    throw(ArgumentError("tls: unsupported connection mode"))
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
@inline _show_closed(conn::Conn) = _is_closed(conn) || conn.native_state === nothing || conn.tcp.fd.pfd.sysfd < 0

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

# The public connect helpers derive `server_name` from the dial target when the
# caller did not set one explicitly, then force the handshake eagerly so
# `connect(...)` returns a ready-to-use TLS stream just like Go's `tls.Dial`.
function _connect_client(tcp::TCP.Conn, config::Config, deadline_ns::Int64 = Int64(0))::Conn
    tls_conn = try
        client(tcp, config)
    catch err
        try
            close(tcp)
        catch
        end
        rethrow()
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
        try
            close(tls_conn)
        catch
        end
        rethrow()
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
