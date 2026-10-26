using Test
using Reseau

# Interop with quic-go over loopback UDP, through the helper in
# quic_go_interop/: a Reseau client against a quic-go server, and a quic-go
# client against a Reseau server, moving data on bidirectional and
# unidirectional streams. quic-go starts a key update after 100 packets, so
# these transfers also cover key updates. Runs when a Go 1.22+ toolchain is on
# PATH and the quic-go module is cached or can be downloaded.

const QGI = Reseau.QUIC
const TLGI = Reseau.TLS
const UDGI = Reseau.UDP

const _QGI_DIR = joinpath(@__DIR__, "quic_go_interop")
const _QGI_CERT = joinpath(@__DIR__, "resources", "unittests.crt")
const _QGI_KEY = joinpath(@__DIR__, "resources", "unittests.key")
const _QGI_ALPN = "reseau-interop"
const _QGI_STREAMS = 4
const _QGI_SIZE = 256 * 1024

function _qgi_go()::Union{Nothing, String}
    go = Sys.which("go")
    go === nothing && return nothing
    version = try
        readchomp(addenv(`$go env GOVERSION`, "GOTOOLCHAIN" => "local"))
    catch
        return nothing
    end
    m = match(r"^go(\d+)\.(\d+)", version)
    m === nothing && return nothing
    return (parse(Int, m[1]), parse(Int, m[2])) >= (1, 22) ? go : nothing
end

# Builds the helper, or returns `nothing` when quic-go cannot be fetched.
function _qgi_build(go::String, dir::String)::Union{Nothing, String}
    bin = joinpath(dir, Sys.iswindows() ? "quic_go_interop.exe" : "quic_go_interop")
    log = joinpath(dir, "build.log")
    cmd = addenv(Cmd(`$go build -o $bin .`; dir = _QGI_DIR), "GOTOOLCHAIN" => "local", "CGO_ENABLED" => "0")
    if !success(pipeline(cmd; stdout = log, stderr = log))
        @info "Skipping quic-go interop: the helper did not build" log = read(log, String)
        return nothing
    end
    return bin
end

_qgi_data(n) = rand(UInt8, n)

# quic-go warns when it cannot enlarge the socket buffers; the transfers here are small.
_qgi_cmd(cmd) = addenv(cmd, "QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING" => "true")

# A Reseau client opens `_QGI_STREAMS` bidirectional streams and one
# unidirectional stream to the quic-go server, and checks what comes back.
mutable struct _QgiClientApp
    sent::Dict{UInt64, Vector{UInt8}}
    got::Dict{UInt64, Vector{UInt8}}
    done::Set{UInt64}
    uni_sent::Vector{UInt8}
    uni_reply::Union{Nothing, UInt64}
    started::Bool
end

_QgiClientApp() = _QgiClientApp(Dict{UInt64, Vector{UInt8}}(), Dict{UInt64, Vector{UInt8}}(), Set{UInt64}(), UInt8[], nothing, false)

function _qgi_client_step!(conn, app::_QgiClientApp)::Bool
    QGI._handshake_complete(conn) || return false
    if !app.started
        app.started = true
        for _ in 1:_QGI_STREAMS
            id = QGI._open_stream!(conn)::UInt64
            app.sent[id] = _qgi_data(_QGI_SIZE)
            app.got[id] = UInt8[]
            QGI._stream_write!(conn, id, app.sent[id]; fin = true)
        end
        uni = QGI._open_stream!(conn; bidi = false)::UInt64
        app.uni_sent = _qgi_data(_QGI_SIZE)
        QGI._stream_write!(conn, uni, app.uni_sent; fin = true)
    end
    if app.uni_reply === nothing
        id = QGI._accept_stream!(conn)
        if id !== nothing
            app.uni_reply = id
            app.got[id] = UInt8[]
        end
    end
    for (id, got) in app.got
        id in app.done && continue
        r = QGI._stream_read!(conn, id)
        append!(got, r.data)
        r.fin && push!(app.done, id)
    end
    return length(app.done) == _QGI_STREAMS + 1
end

# The Reseau server echoes bidirectional streams and answers each
# unidirectional stream with one of its own carrying the same bytes, as the
# quic-go server does.
mutable struct _QgiServerApp
    open::Vector{UInt64}
    uni_data::Dict{UInt64, Vector{UInt8}}
    echoed::Int
end

_QgiServerApp() = _QgiServerApp(UInt64[], Dict{UInt64, Vector{UInt8}}(), 0)

function _qgi_server_step!(conn, app::_QgiServerApp)::Bool
    while (id = QGI._accept_stream!(conn)) !== nothing
        push!(app.open, id)
        QGI._is_bidi(id) || (app.uni_data[id] = UInt8[])
    end
    for id in copy(app.open)
        r = QGI._stream_read!(conn, id)
        if QGI._is_bidi(id)
            QGI._stream_write!(conn, id, r.data; fin = r.fin)
        else
            append!(app.uni_data[id], r.data)
            if r.fin
                reply = QGI._open_stream!(conn; bidi = false)::UInt64
                QGI._stream_write!(conn, reply, app.uni_data[id]; fin = true)
            end
        end
        if r.fin
            filter!(!=(id), app.open)
            app.echoed += 1
        end
    end
    # The quic-go client closes the connection once it has checked everything.
    return conn.peer_error !== nothing
end

_qgi_closed(conn) = conn.state == QGI._ConnState.Closed || conn.state == QGI._ConnState.Draining

@testset "QUIC interop with quic-go" begin
    go = _qgi_go()
    if go === nothing
        @info "Skipping quic-go interop: no Go 1.22+ toolchain on PATH"
        return
    end
    mktempdir() do dir
        bin = _qgi_build(go, dir)
        bin === nothing && return

        @testset "Reseau client, quic-go server" begin
            stdin_pipe = Pipe()
            stdout_pipe = Pipe()
            stderr_log = joinpath(dir, "server.log")
            proc = run(pipeline(_qgi_cmd(`$bin server -cert $_QGI_CERT -key $_QGI_KEY -addr 127.0.0.1:0`);
                stdin = stdin_pipe, stdout = stdout_pipe, stderr = stderr_log); wait = false)
            close(stdout_pipe.in)
            sock = nothing
            try
                line = readline(stdout_pipe)
                m = match(r"^ADDR 127\.0\.0\.1:(\d+)$", line)
                @test m !== nothing
                port = parse(Int, m[1])
                sock = UDGI.connect(UDGI.loopback_addr(port))
                deadline = Int64(time_ns()) + 60_000_000_000
                config = TLGI.Config(verify_peer = false, server_name = "localhost", alpn_protocols = [_QGI_ALPN])
                client = QGI._client_connection(config, Int64(time_ns()))
                app = _QgiClientApp()
                @test QGI._drive_connection!(client, sock, nothing, c -> _qgi_client_step!(c, app); deadline_ns = deadline)
                for (id, sent) in app.sent
                    @test app.got[id] == sent
                end
                @test app.uni_reply !== nothing && app.got[app.uni_reply] == app.uni_sent
                @test client.error === nothing && client.peer_error === nothing
                @test client.key_updates >= 1
                QGI._close_connection!(client, UInt64(0), "done", Int64(time_ns()))
                QGI._drive_connection!(client, sock, nothing, _qgi_closed; deadline_ns = Int64(time_ns()) + 5_000_000_000)
            finally
                sock === nothing || close(sock)
                close(stdin_pipe)
                wait(proc)
            end
            log = read(stderr_log, String)
            isempty(log) || @info "quic-go server log" log
        end

        @testset "quic-go client, Reseau server" begin
            sock = UDGI.listen(UDGI.loopback_addr(0))
            out_log = joinpath(dir, "client.out")
            err_log = joinpath(dir, "client.log")
            try
                port = UDGI.local_addr(sock).port
                proc = run(pipeline(_qgi_cmd(`$bin client -addr 127.0.0.1:$port -size $_QGI_SIZE -streams $_QGI_STREAMS`);
                    stdout = out_log, stderr = err_log); wait = false)
                deadline = Int64(time_ns()) + 60_000_000_000
                config = TLGI.Config(verify_peer = false, cert_file = _QGI_CERT, key_file = _QGI_KEY, alpn_protocols = [_QGI_ALPN])
                accepted = QGI._accept_over_udp(config, sock; deadline_ns = deadline)
                @test accepted !== nothing
                if accepted !== nothing
                    server, peer = accepted
                    app = _QgiServerApp()
                    @test QGI._drive_connection!(server, sock, peer, c -> _qgi_server_step!(c, app); deadline_ns = deadline)
                    @test app.echoed == _QGI_STREAMS + 1
                    @test server.error === nothing
                    err = server.peer_error
                    @test err !== nothing && err.app && err.code == 0
                    @test server.key_updates >= 1
                end
                wait(proc)
                @test success(proc)
                @test strip(read(out_log, String)) == "OK"
            finally
                close(sock)
            end
            log = read(err_log, String)
            isempty(log) || @info "quic-go client log" log
        end
    end
end
