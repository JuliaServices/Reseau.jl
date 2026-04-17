using Reseau

const TL = Reseau.TLS
const NC = Reseau.TCP
const IP = Reseau.IOPoll

const _TLS_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")
const _TLS_NATIVE_CA_PATH = joinpath(@__DIR__, "resources", "native_tls_ca.crt")
const _TLS_NATIVE_SERVER_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server.crt")
const _TLS_NATIVE_SERVER_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_server.key")
const _TLS_NATIVE_CLIENT_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_client.crt")
const _TLS_NATIVE_CLIENT_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_client.key")
const _TLS_NATIVE_ECDSA_CERT_PATH = joinpath(@__DIR__, "resources", "native_tls_server_ecdsa.crt")
const _TLS_NATIVE_ECDSA_KEY_PATH = joinpath(@__DIR__, "resources", "native_tls_server_ecdsa.key")
const _TLS_MIXED_SERVER_CONFIG = TL.Config(
    verify_peer = false,
    cert_file = _TLS_CERT_PATH,
    key_file = _TLS_KEY_PATH,
    handshake_timeout_ns = 10_000_000_000,
    min_version = TL.TLS1_2_VERSION,
)
const _TLS_EXACT_TLS12_SERVER_CONFIG = TL.Config(
    verify_peer = false,
    cert_file = _TLS_CERT_PATH,
    key_file = _TLS_KEY_PATH,
    handshake_timeout_ns = 10_000_000_000,
    min_version = TL.TLS1_2_VERSION,
    max_version = TL.TLS1_2_VERSION,
)
const _TLS_SERVER_LISTENER = Ref{Union{Nothing, TL.Listener}}(nothing)

function _close_quiet!(x)
    x === nothing && return nothing
    try
        close(x)
    catch
    end
    return nothing
end

function _tls_server_config(;
    cert_file::String = _TLS_CERT_PATH,
    key_file::String = _TLS_KEY_PATH,
    client_auth::TL.ClientAuthMode.T = TL.ClientAuthMode.NoClientCert,
    client_ca_file::Union{Nothing, String} = nothing,
    min_version::UInt16 = TL.TLS1_2_VERSION,
    max_version::Union{Nothing, UInt16} = nothing,
    curve_preferences::Vector{UInt16} = UInt16[],
)::TL.Config
    return TL.Config(
        verify_peer = false,
        cert_file = cert_file,
        key_file = key_file,
        client_auth = client_auth,
        client_ca_file = client_ca_file,
        handshake_timeout_ns = 10_000_000_000,
        min_version = min_version,
        max_version = max_version,
        curve_preferences = copy(curve_preferences),
    )
end

function _tls_client_config(;
    ca_file::String = _TLS_CERT_PATH,
    cert_file::Union{Nothing, String} = nothing,
    key_file::Union{Nothing, String} = nothing,
    max_version::Union{Nothing, UInt16} = nothing,
    curve_preferences::Vector{UInt16} = UInt16[],
)::TL.Config
    return TL.Config(
        server_name = "localhost",
        verify_peer = true,
        ca_file = ca_file,
        cert_file = cert_file,
        key_file = key_file,
        handshake_timeout_ns = 10_000_000_000,
        min_version = TL.TLS1_2_VERSION,
        max_version = max_version,
        curve_preferences = copy(curve_preferences),
    )
end

function _tls_server_task_entry()::TL.ConnectionState
    listener = _TLS_SERVER_LISTENER[]::TL.Listener
    conn = TL.accept(listener)
    try
        TL.handshake!(conn)
        state = TL.connection_state(conn)
        write(conn, UInt8[0x11])
        read(conn, 1) == UInt8[0x21] || error("unexpected TLS trim client ack")
        return state
    finally
        _close_quiet!(conn)
    end
end

Base.Experimental.entrypoint(_tls_server_task_entry, ())

function _tls_expect_state(
    state::TL.ConnectionState,
    expected_version::String,
    expect_native_tls13::Bool,
    expect_resume::Union{Nothing, Bool} = nothing,
    expect_resumable::Union{Nothing, Bool} = nothing,
    expected_curve::Union{Nothing, String} = nothing,
)::Nothing
    state.handshake_complete || error("handshake incomplete")
    state.version == expected_version || error("unexpected TLS version")
    state.using_native_tls13 == expect_native_tls13 || error("unexpected native TLS mode")
    expect_resume === nothing || state.did_resume == expect_resume || error("unexpected TLS resumed state")
    expect_resumable === nothing || state.has_resumable_session == expect_resumable || error("unexpected TLS resumable-session state")
    if expect_native_tls13
        state.cipher_suite in (
            "TLS_AES_128_GCM_SHA256",
            "TLS_AES_256_GCM_SHA384",
            "TLS_CHACHA20_POLY1305_SHA256",
        ) || error("unexpected TLS 1.3 cipher suite")
        if expected_curve === nothing
            state.curve in ("X25519", "P-256") || error("unexpected TLS 1.3 curve")
        else
            state.curve == expected_curve || error("unexpected TLS curve")
        end
    else
        state.cipher_suite in (
            "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
            "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
            "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
        ) || error("unexpected TLS 1.2 cipher suite")
        if expected_curve === nothing
            state.curve in ("X25519", "P-256") || error("unexpected TLS 1.2 curve")
        else
            state.curve == expected_curve || error("unexpected TLS curve")
        end
    end
    return nothing
end

function _run_tls_roundtrip_states!(
    server_config::TL.Config,
    client_config::TL.Config,
)::Tuple{TL.ConnectionState, TL.ConnectionState}
    listener::Union{Nothing, TL.Listener} = nothing
    client::Union{Nothing, TL.Conn} = nothing
    server_task::Union{Nothing, Task} = nothing
    try
        listener = TL.listen(NC.loopback_addr(0), server_config; backlog = 8)
        _TLS_SERVER_LISTENER[] = listener
        laddr = TL.addr(listener)::NC.SocketAddrV4
        server_task = Task(_tls_server_task_entry)
        schedule(server_task)
        client = TL.connect(NC.loopback_addr(Int(laddr.port)), client_config)
        read(client, 1) == UInt8[0x11] || error("expected TLS server byte")
        write(client, UInt8[0x21]) == 1 || error("expected TLS client ack write")
        eof(client) || error("expected TLS EOF")
        client_state = TL.connection_state(client)
        status = IP.timedwait(() -> istaskdone(server_task::Task), 10.0; pollint = 0.001)
        status == :timed_out && error("timed out waiting for TLS server task")
        return client_state, fetch(server_task::Task)::TL.ConnectionState
    finally
        _TLS_SERVER_LISTENER[] = nothing
        _close_quiet!(client)
        _close_quiet!(listener)
    end
end

function _run_tls_roundtrip!(
    server_config::TL.Config,
    client_config::TL.Config,
    expected_version::String,
    expect_native_tls13::Bool,
    expect_client_resume::Union{Nothing, Bool} = nothing,
    expect_client_resumable::Union{Nothing, Bool} = nothing,
    expect_server_resume::Union{Nothing, Bool} = nothing,
    expected_curve::Union{Nothing, String} = nothing,
)::Nothing
    client_state, server_state = _run_tls_roundtrip_states!(server_config, client_config)
    _tls_expect_state(client_state, expected_version, expect_native_tls13, expect_client_resume, expect_client_resumable, expected_curve)
    _tls_expect_state(server_state, expected_version, expect_native_tls13, expect_server_resume, false, expected_curve)
    return nothing
end

function run_tls_trim_sample()::Nothing
    _run_tls_roundtrip!(_TLS_MIXED_SERVER_CONFIG, _tls_client_config(), "TLSv1.3", true)
    _run_tls_roundtrip!(_TLS_EXACT_TLS12_SERVER_CONFIG, _tls_client_config(), "TLSv1.2", false)
    _run_tls_roundtrip!(_TLS_MIXED_SERVER_CONFIG, _tls_client_config(max_version = TL.TLS1_2_VERSION), "TLSv1.2", false)
    _run_tls_roundtrip!(
        _tls_server_config(
            max_version = TL.TLS1_2_VERSION,
            curve_preferences = UInt16[TL.X25519],
        ),
        _tls_client_config(
            max_version = TL.TLS1_2_VERSION,
            curve_preferences = UInt16[TL.X25519],
        ),
        "TLSv1.2",
        false,
        nothing,
        nothing,
        nothing,
        "X25519",
    )
    _run_tls_roundtrip!(
        _tls_server_config(
            max_version = TL.TLS1_2_VERSION,
            curve_preferences = UInt16[TL.X25519],
        ),
        _tls_client_config(
            curve_preferences = UInt16[TL.X25519],
        ),
        "TLSv1.2",
        false,
        nothing,
        nothing,
        nothing,
        "X25519",
    )
    tls12_mtls_server = _tls_server_config(
        cert_file = _TLS_NATIVE_SERVER_CERT_PATH,
        key_file = _TLS_NATIVE_SERVER_KEY_PATH,
        client_auth = TL.ClientAuthMode.RequireAndVerifyClientCert,
        client_ca_file = _TLS_NATIVE_CA_PATH,
        max_version = TL.TLS1_2_VERSION,
    )
    tls12_mtls_client = _tls_client_config(
        ca_file = _TLS_NATIVE_CA_PATH,
        cert_file = _TLS_NATIVE_CLIENT_CERT_PATH,
        key_file = _TLS_NATIVE_CLIENT_KEY_PATH,
        max_version = TL.TLS1_2_VERSION,
    )
    _run_tls_roundtrip!(tls12_mtls_server, tls12_mtls_client, "TLSv1.2", false, false, true, false)
    _run_tls_roundtrip!(tls12_mtls_server, tls12_mtls_client, "TLSv1.2", false, true, true, true)
    _run_tls_roundtrip!(
        _tls_server_config(
            cert_file = _TLS_NATIVE_ECDSA_CERT_PATH,
            key_file = _TLS_NATIVE_ECDSA_KEY_PATH,
            max_version = TL.TLS1_2_VERSION,
        ),
        _tls_client_config(
            ca_file = _TLS_NATIVE_ECDSA_CERT_PATH,
            max_version = TL.TLS1_2_VERSION,
        ),
        "TLSv1.2",
        false,
    )
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_tls_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
