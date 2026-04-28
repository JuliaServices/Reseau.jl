const _RESEAU_TLS_TEST_UTILS_LOADED = true

const TL = Reseau.TLS
const NC = Reseau.TCP
const ND = Reseau.HostResolvers
const IP = Reseau.IOPoll

const _TLS_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")
const _TLS_NATIVE_CA_PATH = joinpath(@__DIR__, "resources", "native_tls_ca.crt")
const _TLS_NATIVE_SERVER_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server.crt")
const _TLS_NATIVE_SERVER_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_server.key")
const _TLS_NATIVE_CLIENT_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_client.crt")
const _TLS_NATIVE_CLIENT_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_client.key")

function _tls_wait_task_done(task::Task, timeout_s::Float64 = 2.0)
    return IP.timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
end

function _tls_close_quiet!(x)
    x === nothing && return nothing
    try
        if x isa TL.Conn || x isa TL.Listener
            close(x)
        elseif x isa NC.Conn || x isa NC.Listener
            close(x)
        end
    catch
    end
    return nothing
end

@inline function _tls_handshake_connect_error(ex)
    return ex isa TL.TLSError || ex isa TL.TLSHandshakeTimeoutError
end

function _tls_server_config(;
    handshake_timeout_ns::Int64 = 0,
    cert_file::String = _TLS_CERT_PATH,
    key_file::String = _TLS_KEY_PATH,
    client_auth::TL.ClientAuthMode.T = TL.ClientAuthMode.NoClientCert,
    client_ca_file::Union{Nothing, String} = nothing,
    min_version::Union{Nothing, UInt16} = TL.TLS1_2_VERSION,
    max_version::Union{Nothing, UInt16} = nothing,
    curve_preferences::Vector{UInt16} = UInt16[],
)
    return TL.Config(
        verify_peer = false,
        cert_file = cert_file,
        key_file = key_file,
        client_auth = client_auth,
        client_ca_file = client_ca_file,
        handshake_timeout_ns = handshake_timeout_ns,
        min_version = min_version,
        max_version = max_version,
        curve_preferences = copy(curve_preferences),
    )
end

function _tls_connect(
        network::AbstractString,
        address::AbstractString,
        config::TL.Config = TL.Config();
        timeout_ns::Integer = Int64(0),
        deadline_ns::Integer = Int64(0),
        local_addr::Union{Nothing, NC.SocketEndpoint} = nothing,
        fallback_delay_ns::Integer = Int64(300_000_000),
        resolver::ND.AbstractResolver = ND.DEFAULT_RESOLVER,
        policy::ND.ResolverPolicy = ND.ResolverPolicy(),
    )::TL.Conn
    return TL.connect(
        network,
        address,
        config;
        timeout_ns = timeout_ns,
        deadline_ns = deadline_ns,
        local_addr = local_addr,
        fallback_delay_ns = fallback_delay_ns,
        resolver = resolver,
        policy = policy,
    )
end
