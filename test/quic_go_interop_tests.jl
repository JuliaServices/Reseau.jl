using Test
using Reseau

# Interop with quic-go over loopback UDP, through the helper in
# quic_go_interop/: a Reseau client against a quic-go server, and a quic-go
# client against a Reseau server, moving data on bidirectional and
# unidirectional streams through the public endpoint API, and resuming TLS
# sessions both ways. quic-go starts a key update after 100 packets, so these
# transfers also cover key updates. Runs when a Go 1.22+ toolchain is on PATH
# and the quic-go module is cached or can be downloaded.

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

# Reads `f(conn)` for a connection's internal state under its endpoint's lock.
_qgi_state(f, c::QGI.Connection) = lock(() -> f(c.slot.conn), c.ep.lock)

# A Reseau client opens `_QGI_STREAMS` bidirectional streams and one
# unidirectional stream to the quic-go server, each from its own task, and
# returns what it sent and what came back on each, keyed by stream ID. The
# reply to the unidirectional stream is under `uni_reply`.
function _qgi_client_transfer(conn::QGI.Connection, deadline::Int64)
    sent = Dict{UInt64, Vector{UInt8}}()
    got = Dict{UInt64, Vector{UInt8}}()
    tasks = Task[]
    for _ in 1:_QGI_STREAMS
        s = QGI.open_stream(conn; deadline_ns = deadline)
        data = _qgi_data(_QGI_SIZE)
        sent[QGI.stream_id(s)] = data
        QGI.set_read_deadline!(s, deadline)
        QGI.set_write_deadline!(s, deadline)
        push!(tasks, Threads.@spawn begin
            writer = Threads.@spawn (write(s, data); closewrite(s))
            echoed = read(s)
            wait(writer)
            QGI.stream_id(s) => echoed
        end)
    end
    uni = QGI.open_stream(conn; bidi = false, deadline_ns = deadline)
    uni_sent = _qgi_data(_QGI_SIZE)
    QGI.set_write_deadline!(uni, deadline)
    uni_writer = Threads.@spawn (write(uni, uni_sent); closewrite(uni))
    reply = QGI.accept_stream(conn; deadline_ns = deadline)
    QGI.set_read_deadline!(reply, deadline)
    uni_reply = QGI.stream_id(reply)
    got[uni_reply] = read(reply)
    wait(uni_writer)
    for t in tasks
        id, echoed = fetch(t)
        got[id] = echoed
    end
    return (; sent, got, uni_sent, uni_reply, reply_bidi = QGI.isbidi(reply))
end

# The Reseau server echoes bidirectional streams and answers each
# unidirectional stream with one of its own carrying the same bytes, as the
# quic-go server does, until the peer closes the connection. Returns how many
# streams it finished and the error that ended the connection.
function _qgi_serve(conn::QGI.Connection)
    tasks = Task[]
    err = try
        while true
            s = QGI.accept_stream(conn)
            push!(tasks, Threads.@spawn begin
                data = read(s)
                if QGI.isbidi(s)
                    write(s, data)
                    closewrite(s)
                else
                    reply = QGI.open_stream(conn; bidi = false)
                    write(reply, data)
                    closewrite(reply)
                end
                true
            end)
        end
    catch ex
        ex isa QGI.ConnectionError || rethrow()
        ex
    end
    # The quic-go client closes the connection only once it has checked
    # everything, so every stream has finished by now.
    return count(fetch, tasks), err
end

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
            client = nothing
            try
                line = readline(stdout_pipe)
                m = match(r"^ADDR 127\.0\.0\.1:(\d+)$", line)
                @test m !== nothing
                port = parse(Int, m[1])
                deadline = Int64(time_ns()) + 60_000_000_000
                config = TLGI.Config(verify_peer = false, server_name = "localhost", alpn_protocols = [_QGI_ALPN])
                client = QGI.connect(UDGI.loopback_addr(port), config; deadline_ns = deadline)
                @test QGI.alpn_protocol(client) == _QGI_ALPN
                r = _qgi_client_transfer(client, deadline)
                @test length(r.sent) == _QGI_STREAMS
                for (id, sent) in r.sent
                    @test r.got[id] == sent
                end
                @test !r.reply_bidi && r.got[r.uni_reply] == r.uni_sent
                @test _qgi_state(c -> c.error === nothing && c.peer_error === nothing, client)
                @test _qgi_state(c -> c.key_updates, client) >= 1
                # quic-go sent its session ticket with HANDSHAKE_DONE.
                @test _qgi_state(c -> !TLGI.connection_state(c.tls).did_resume, client)
                @test _qgi_state(c -> TLGI.connection_state(c.tls).has_resumable_session, client)
                close(client; code = 0, reason = "done")
                # Wait out the closing period, so quic-go sees the close.
                QGI._wait_endpoint_done(client.ep, Int64(time_ns()) + 5_000_000_000)

                # A second connection with the same config resumes.
                client = QGI.connect(UDGI.loopback_addr(port), config; deadline_ns = deadline)
                @test _qgi_state(c -> TLGI.connection_state(c.tls).did_resume, client)
                close(client; code = 0, reason = "done")
                QGI._wait_endpoint_done(client.ep, Int64(time_ns()) + 5_000_000_000)
            finally
                client === nothing || close(client)
                close(stdin_pipe)
                wait(proc)
            end
            log = read(stderr_log, String)
            isempty(log) || @info "quic-go server log" log
        end

        @testset "quic-go client, Reseau server" begin
            config = TLGI.Config(verify_peer = false, cert_file = _QGI_CERT, key_file = _QGI_KEY, alpn_protocols = [_QGI_ALPN])
            listener = QGI.listen(UDGI.loopback_addr(0), config)
            out_log = joinpath(dir, "client.out")
            err_log = joinpath(dir, "client.log")
            server = nothing
            try
                port = QGI.local_addr(listener).port
                proc = run(pipeline(_qgi_cmd(`$bin client -addr 127.0.0.1:$port -size $_QGI_SIZE -streams $_QGI_STREAMS`);
                    stdout = out_log, stderr = err_log); wait = false)
                deadline = Int64(time_ns()) + 60_000_000_000
                server = QGI.accept(listener; deadline_ns = deadline)
                @test QGI.alpn_protocol(server) == _QGI_ALPN
                echoed, err = _qgi_serve(server)
                @test echoed == _QGI_STREAMS + 1
                @test err.remote && err.app && err.code == 0
                @test _qgi_state(c -> c.error === nothing, server)
                @test _qgi_state(c -> c.key_updates, server) >= 1
                wait(proc)
                @test success(proc)
                @test strip(read(out_log, String)) == "OK"
            finally
                server === nothing || close(server)
                close(listener)
            end
            log = read(err_log, String)
            isempty(log) || @info "quic-go client log" log
        end

        @testset "quic-go client resumes against a Reseau server" begin
            config = TLGI.Config(verify_peer = false, cert_file = _QGI_CERT, key_file = _QGI_KEY, alpn_protocols = [_QGI_ALPN])
            listener = QGI.listen(UDGI.loopback_addr(0), config)
            out_log = joinpath(dir, "resume.out")
            err_log = joinpath(dir, "resume.log")
            try
                port = QGI.local_addr(listener).port
                proc = run(pipeline(_qgi_cmd(`$bin resume -addr 127.0.0.1:$port`); stdout = out_log, stderr = err_log); wait = false)
                deadline = Int64(time_ns()) + 60_000_000_000
                # The client echoes once on each connection, then closes it.
                for resumed in (false, true)
                    server = QGI.accept(listener; deadline_ns = deadline)
                    @test _qgi_state(c -> TLGI.connection_state(c.tls).did_resume, server) == resumed
                    s = QGI.accept_stream(server; deadline_ns = deadline)
                    @test String(read(s)) == "ping"
                    write(s, "ping")
                    closewrite(s)
                    err = try
                        QGI.accept_stream(server; deadline_ns = deadline)
                        nothing
                    catch ex
                        ex
                    end
                    @test err isa QGI.ConnectionError && err.remote && err.app && err.code == 0
                end
                wait(proc)
                @test success(proc)
                @test strip(read(out_log, String)) == "OK"
            finally
                close(listener)
            end
            log = read(err_log, String)
            isempty(log) || @info "quic-go client log" log
        end
    end
end
