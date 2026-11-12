using Test
using Reseau

# Interop between Reseau's QUICConn and Go's crypto/tls QUICConn, through the
# helper in quic_interop/. The self-tests in tls_quic_tests.jl cannot catch a
# mistake both Reseau sides share, such as a wrong extension encoding or a
# message sent at the wrong encryption level; Go's implementation can. Runs when
# a Go 1.22+ toolchain is on PATH.

const TLG = Reseau.TLS
const QELG = TLG.QUICEncryptionLevel
const QEKG = TLG.QUICEventKind

const _GO_INTEROP_DIR = joinpath(@__DIR__, "quic_interop")
const _GO_INTEROP_CA = joinpath(@__DIR__, "resources", "native_tls_ca.crt")
const _GO_INTEROP_CERT = joinpath(@__DIR__, "resources", "native_tls_server.crt")
const _GO_INTEROP_KEY = joinpath(@__DIR__, "resources", "native_tls_server.key")
const _GO_INTEROP_JULIA_PARAMS = Vector{UInt8}(codeunits("reseau params"))
const _GO_INTEROP_GO_PARAMS = Vector{UInt8}(codeunits("go params"))

# What one side of a handshake reported.
mutable struct _GoInteropSide
    read_secret::Dict{UInt8, Tuple{UInt16, Vector{UInt8}}}
    write_secret::Dict{UInt8, Tuple{UInt16, Vector{UInt8}}}
    got_params::Union{Nothing, Vector{UInt8}}
    done::Bool
    did_resume::Bool
    alpn::String
    alert::Union{Nothing, UInt8}
    error_message::String
end

_GoInteropSide() = _GoInteropSide(
    Dict{UInt8, Tuple{UInt16, Vector{UInt8}}}(),
    Dict{UInt8, Tuple{UInt16, Vector{UInt8}}}(),
    nothing,
    false,
    false,
    "",
    nothing,
    "",
)

function _go_interop_version_ok(go::String)::Bool
    version = try
        readchomp(`$go env GOVERSION`)
    catch
        return false
    end
    m = match(r"^go(\d+)\.(\d+)", version)
    m === nothing && return false
    return (parse(Int, m[1]), parse(Int, m[2])) >= (1, 22)
end

function _go_interop_build(go::String, dir::String)::String
    bin = joinpath(dir, Sys.iswindows() ? "quic_interop.exe" : "quic_interop")
    cmd = addenv(Cmd(`$go build -o $bin .`; dir = _GO_INTEROP_DIR), "GOTOOLCHAIN" => "local", "CGO_ENABLED" => "0")
    run(cmd)
    return bin
end

function _go_interop_write_frame(io::IO, kind::Char, level::Integer, payload::AbstractVector{UInt8} = UInt8[])
    n = length(payload)
    write(io, UInt8[UInt8(kind), UInt8(level), UInt8((n >> 24) & 0xff), UInt8((n >> 16) & 0xff), UInt8((n >> 8) & 0xff), UInt8(n & 0xff)])
    write(io, payload)
    return nothing
end

function _go_interop_read_frame(io::IO)::Tuple{Char, UInt8, Vector{UInt8}}
    header = read(io, 6)
    length(header) == 6 || error("Go QUIC helper exited mid-handshake")
    n = (Int(header[3]) << 24) | (Int(header[4]) << 16) | (Int(header[5]) << 8) | Int(header[6])
    payload = read(io, n)
    length(payload) == n || error("Go QUIC helper exited mid-frame")
    return Char(header[1]), header[2], payload
end

_go_interop_secret(payload::Vector{UInt8}) = ((UInt16(payload[1]) << 8) | UInt16(payload[2]), payload[3:end])

# Reads the helper's turn, delivering its CRYPTO data to `q`. Returns how many
# data frames arrived.
function _go_interop_go_turn!(proc, q::TLG.QUICConn, go::_GoInteropSide, jl::_GoInteropSide)::Int
    delivered = 0
    while true
        kind, level, payload = _go_interop_read_frame(proc)
        kind == 'I' && return delivered
        if kind == 'D'
            delivered += 1
            jl.alert === nothing || continue
            try
                TLG.handle_data!(q, QELG.T(level), payload)
            catch ex
                ex isa TLG.TLSError || rethrow()
                jl.alert = TLG.alert_code(ex)
                jl.error_message = sprint(showerror, ex)
            end
        elseif kind == 'R'
            go.read_secret[level] = _go_interop_secret(payload)
        elseif kind == 'W'
            go.write_secret[level] = _go_interop_secret(payload)
        elseif kind == 'P'
            go.got_params = payload
        elseif kind == 'H'
            go.done = true
            go.did_resume = payload[1] == 0x01
            go.alpn = String(payload[2:end])
        elseif kind == 'E'
            go.alert = payload[1]
            go.error_message = String(payload[2:end])
        else
            error("unexpected frame $(repr(kind)) from the Go QUIC helper")
        end
    end
end

# Sends `q`'s pending events to the helper and ends the turn. Returns how many
# data frames went out.
function _go_interop_julia_turn!(proc, q::TLG.QUICConn, jl::_GoInteropSide)::Int
    sent = 0
    while true
        e = TLG.next_event!(q)
        e.kind == QEKG.NoEvent && break
        if e.kind == QEKG.WriteData
            _go_interop_write_frame(proc, 'D', UInt8(e.level), e.data)
            sent += 1
        elseif e.kind == QEKG.SetReadSecret
            jl.read_secret[UInt8(e.level)] = (e.suite, e.data)
        elseif e.kind == QEKG.SetWriteSecret
            jl.write_secret[UInt8(e.level)] = (e.suite, e.data)
        elseif e.kind == QEKG.TransportParameters
            jl.got_params = e.data
        elseif e.kind == QEKG.HandshakeDone
            jl.done = true
            q.is_server && TLG.send_session_ticket!(q)
        elseif e.kind == QEKG.Error
            err = e.err::TLG.TLSError
            if jl.alert === nothing
                jl.alert = TLG.alert_code(err)
                jl.error_message = sprint(showerror, err)
            end
        else
            error("unexpected Reseau QUIC event $(e.kind)")
        end
    end
    _go_interop_write_frame(proc, 'I', 0)
    flush(proc)
    return sent
end

# Runs one handshake between `q` and the helper's current connection. The
# helper has already taken its first turn's worth of setup; on return it is
# waiting for the next frame from us.
function _go_interop_handshake!(proc, q::TLG.QUICConn)
    jl = _GoInteropSide()
    go = _GoInteropSide()
    TLG.set_transport_parameters!(q, _GO_INTEROP_JULIA_PARAMS)
    TLG.start!(q)
    sent = -1
    for _ in 1:64
        delivered = _go_interop_go_turn!(proc, q, go, jl)
        failed = jl.alert !== nothing || go.alert !== nothing
        settled = jl.done && go.done && delivered == 0 && sent == 0
        (failed && sent >= 0) && return jl, go
        settled && return jl, go
        sent = _go_interop_julia_turn!(proc, q, jl)
    end
    error("Reseau/Go QUIC handshake did not settle")
end

# Starts the helper, runs `length(configs)` handshakes against it on one
# process (so the second can resume the first), and returns each side's report.
function _go_interop_run(bin::String, julia_is_server::Bool, julia_configs::Vector{TLG.Config}, go_args::Vector{String})
    stderr_path = tempname()
    role = julia_is_server ? "client" : "server"
    cmd = `$bin -role $role -cert $_GO_INTEROP_CERT -key $_GO_INTEROP_KEY -ca $_GO_INTEROP_CA -params $(String(copy(_GO_INTEROP_GO_PARAMS))) $go_args`
    proc = open(pipeline(cmd; stderr = stderr_path), "r+")
    results = Tuple{_GoInteropSide, _GoInteropSide, TLG.ConnectionState}[]
    try
        for (i, config) in enumerate(julia_configs)
            q = julia_is_server ? TLG.quic_server(config) : TLG.quic_client(config)
            try
                jl, go = _go_interop_handshake!(proc, q)
                push!(results, (jl, go, TLG.connection_state(q)))
            finally
                close(q)
            end
            _go_interop_write_frame(proc, i == length(julia_configs) ? 'Q' : 'N', 0)
            flush(proc)
        end
        close(proc.in)
        wait(proc)
    catch
        kill(proc)
        isfile(stderr_path) && print(stderr, read(stderr_path, String))
        rethrow()
    finally
        rm(stderr_path; force = true)
    end
    return results
end

function _go_interop_check_handshake(jl::_GoInteropSide, go::_GoInteropSide, state::TLG.ConnectionState)
    @test jl.alert === nothing
    @test go.alert === nothing
    jl.alert === nothing || @info "Reseau side failed" jl.error_message
    go.alert === nothing || @info "Go side failed" go.error_message
    @test jl.done
    @test go.done
    for level in (UInt8(QELG.Handshake), UInt8(QELG.Application))
        @test haskey(jl.read_secret, level)
        @test haskey(jl.write_secret, level)
        # Different defaults, so a secret missing on both sides still fails.
        @test isequal(get(jl.read_secret, level, nothing), get(go.write_secret, level, missing))
        @test isequal(get(jl.write_secret, level, nothing), get(go.read_secret, level, missing))
    end
    @test jl.got_params == _GO_INTEROP_GO_PARAMS
    @test go.got_params == _GO_INTEROP_JULIA_PARAMS
    @test go.alpn == "h3"
    @test state.alpn_protocol == "h3"
    @test state.handshake_complete
    @test state.did_resume == go.did_resume
    return nothing
end

function _go_interop_client_config(; alpn_protocols = ["h3"], curve_preferences = UInt16[])
    return TLG.Config(;
        server_name = "localhost",
        verify_peer = true,
        ca_file = _GO_INTEROP_CA,
        alpn_protocols,
        curve_preferences,
    )
end

function _go_interop_server_config(; alpn_protocols = ["h3"], curve_preferences = UInt16[])
    return TLG.Config(;
        verify_peer = false,
        cert_file = _GO_INTEROP_CERT,
        key_file = _GO_INTEROP_KEY,
        alpn_protocols,
        curve_preferences,
    )
end

const _GO_INTEROP_GO = Sys.which("go")

@testset "TLS QUIC Go interop" begin
    if _GO_INTEROP_GO === nothing || !_go_interop_version_ok(_GO_INTEROP_GO)
        @info "Skipping Reseau/Go QUIC interop: no Go 1.22+ toolchain on PATH"
        @test_skip false
    else
        mktempdir() do dir
            bin = _go_interop_build(_GO_INTEROP_GO, dir)

            @testset "Reseau client, Go server, then resumption" begin
                config = _go_interop_client_config()
                results = _go_interop_run(bin, false, [config, config], String[])
                @test length(results) == 2
                for (jl, go, state) in results
                    _go_interop_check_handshake(jl, go, state)
                end
                @test !results[1][3].did_resume
                @test results[2][3].did_resume
            end

            @testset "Go client, Reseau server, then resumption" begin
                config = _go_interop_server_config()
                results = _go_interop_run(bin, true, [config, config], String[])
                @test length(results) == 2
                for (jl, go, state) in results
                    _go_interop_check_handshake(jl, go, state)
                end
                @test !results[1][2].did_resume
                @test results[2][2].did_resume
            end

            @testset "HelloRetryRequest in both directions" begin
                # Reseau's client leads with an X25519 share that Go's server refuses.
                client = _go_interop_client_config(curve_preferences = [TLG.X25519, TLG.P256])
                ((jl, go, state),) = _go_interop_run(bin, false, [client], ["-curves", "P256"])
                _go_interop_check_handshake(jl, go, state)
                @test state.did_hello_retry_request
                @test state.curve == "P-256"

                # Go's client leads with X25519; Reseau's server insists on P-256.
                server = _go_interop_server_config(curve_preferences = [TLG.P256])
                ((jl, go, state),) = _go_interop_run(bin, true, [server], ["-curves", "X25519,P256"])
                _go_interop_check_handshake(jl, go, state)
                @test state.did_hello_retry_request
                @test state.curve == "P-256"
            end

            @testset "ALPN mismatch fails with no_application_protocol" begin
                ((jl, go, state),) = _go_interop_run(bin, false, [_go_interop_client_config()], ["-alpn", "h3-29"])
                @test go.alert == 0x78
                @test !state.handshake_complete

                ((jl, go, state),) = _go_interop_run(bin, true, [_go_interop_server_config()], ["-alpn", "h3-29"])
                @test jl.alert == 0x78
                @test !state.handshake_complete
            end
        end
    end
end
