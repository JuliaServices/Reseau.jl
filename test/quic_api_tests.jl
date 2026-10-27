using Test
using Reseau

# The public QUIC API: connections and listeners driven by their own receive
# task, with streams used from any task as `IO`.

const QA = Reseau.QUIC
const TLA = Reseau.TLS
const UDA = Reseau.UDP

const _QA_CERT = joinpath(@__DIR__, "resources", "unittests.crt")
const _QA_KEY = joinpath(@__DIR__, "resources", "unittests.key")
const _QA_ALPN = "reseau-api"

_qa_deadline(seconds::Real = 30) = Int64(time_ns()) + round(Int64, seconds * 1e9)

_qa_server_config() = TLA.Config(verify_peer = false, cert_file = _QA_CERT, key_file = _QA_KEY, alpn_protocols = [_QA_ALPN])
_qa_client_config() = TLA.Config(verify_peer = false, server_name = "localhost", alpn_protocols = [_QA_ALPN])

# A listener and a connected client/server pair over IPv4 loopback.
function _qa_pair(; server_kw = (;), client_kw = (;))
    listener = QA.listen(UDA.loopback_addr(0), _qa_server_config(); server_kw...)
    port = QA.local_addr(listener).port
    accepted = Threads.@spawn QA.accept(listener; deadline_ns = _qa_deadline())
    client = QA.connect(UDA.loopback_addr(port), _qa_client_config(); deadline_ns = _qa_deadline(), client_kw...)
    server = fetch(accepted)
    return listener, client, server
end

function _qa_close_all(listener, conns...)
    for c in conns
        close(c)
    end
    close(listener)
    return nothing
end

# Echoes every bidirectional stream the peer opens until the connection ends.
function _qa_echo_server(conn::QA.Connection)
    return errormonitor(Threads.@spawn begin
        tasks = Task[]
        try
            while true
                s = QA.accept_stream(conn)
                push!(tasks, errormonitor(Threads.@spawn begin
                    data = read(s)
                    write(s, data)
                    closewrite(s)
                end))
            end
        catch ex
            ex isa QA.ConnectionError || rethrow()
        end
        foreach(wait, tasks)
    end)
end

# The TLS state of a connection, read under its endpoint's lock.
function _qa_tls_state(c::QA.Connection)
    lock(c.ep.lock)
    try
        return TLA.connection_state(c.slot.conn.tls)
    finally
        unlock(c.ep.lock)
    end
end

@testset "QUIC API" begin
    @testset "handshake and a request-response stream" begin
        listener, client, server = _qa_pair()
        try
            @test QA.alpn_protocol(client) == _QA_ALPN
            @test QA.alpn_protocol(server) == _QA_ALPN
            @test isopen(client) && isopen(server)
            s = QA.open_stream(client)
            @test QA.isbidi(s) && QA.stream_id(s) == 0
            write(s, "hello")
            closewrite(s)
            peer = QA.accept_stream(server)
            @test QA.stream_id(peer) == 0
            @test String(read(peer)) == "hello"
            @test eof(peer)
            write(peer, "HELLO")
            closewrite(peer)
            @test String(read(s, 2)) == "HE"
            @test read(s, UInt8) == UInt8('L')
            @test String(read(s)) == "LO"
            @test eof(s)
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "many concurrent streams from many tasks" begin
        listener, client, server = _qa_pair()
        try
            echo = _qa_echo_server(server)
            tasks = map(1:16) do i
                Threads.@spawn begin
                    s = QA.open_stream(client)
                    data = rand(UInt8, 100_000 + i)
                    writer = Threads.@spawn (write(s, data); closewrite(s))
                    got = read(s)
                    wait(writer)
                    got == data
                end
            end
            @test all(fetch, tasks)
            close(client)
            wait(echo)
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "a large transfer with backpressure" begin
        listener, client, server =
            _qa_pair(server_kw = (; max_stream_data = 64 * 1024, max_data = 128 * 1024))
        try
            echo = _qa_echo_server(server)
            s = QA.open_stream(client)
            data = rand(UInt8, 8 * 1024 * 1024)
            writer = Threads.@spawn (write(s, data); closewrite(s))
            @test read(s) == data
            wait(writer)
            close(client)
            wait(echo)
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "a large transfer with one send per datagram" begin
        # Platforms without UDP segmentation offload, or a kernel that turns
        # it down, send datagrams one at a time.
        listener, client, server = _qa_pair()
        try
            lock(() -> (client.ep.gso = false), client.ep.lock)
            lock(() -> (server.ep.gso = false), server.ep.lock)
            echo = _qa_echo_server(server)
            s = QA.open_stream(client)
            data = rand(UInt8, 4 * 1024 * 1024)
            writer = Threads.@spawn (write(s, data); closewrite(s))
            @test read(s) == data
            wait(writer)
            close(client)
            wait(echo)
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "path MTU discovery finds each side's datagram size" begin
        # A connected socket's route MTU sets the client's ceiling (loopback's
        # is large); a listener cannot ask, so it stays at the default.
        listener, client, server = _qa_pair()
        try
            echo = _qa_echo_server(server)
            s = QA.open_stream(client)
            data = rand(UInt8, 2 * 1024 * 1024)
            writer = Threads.@spawn (write(s, data); closewrite(s))
            @test read(s) == data
            wait(writer)
            sizes = lock(client.ep.lock) do
                (client.slot.conn.max_datagram_size, server.slot.conn.max_datagram_size)
            end
            if Sys.islinux()
                @test sizes == (QA._PMTU_MAX_CEILING, QA._PMTU_DEFAULT_CEILING)
            else
                @test sizes[2] == QA._PMTU_DEFAULT_CEILING
            end
            close(client)
            wait(echo)
        finally
            _qa_close_all(listener, client, server)
        end
        # Either side may set its own ceiling.
        listener, client, server = _qa_pair(server_kw = (; max_datagram_size = 1300), client_kw = (; max_datagram_size = 1250))
        try
            echo = _qa_echo_server(server)
            s = QA.open_stream(client)
            data = rand(UInt8, 1024 * 1024)
            writer = Threads.@spawn (write(s, data); closewrite(s))
            @test read(s) == data
            wait(writer)
            @test lock(() -> client.slot.conn.max_datagram_size, client.ep.lock) == 1250
            @test lock(() -> server.slot.conn.max_datagram_size, server.ep.lock) == 1300
            close(client)
            wait(echo)
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "writes wait for buffer space, up to the write deadline" begin
        listener, client, server = _qa_pair(server_kw = (; max_stream_data = 64 * 1024))
        try
            s = QA.open_stream(client)
            QA.set_write_deadline!(s, _qa_deadline(0.3))
            # The server never reads, so only 64 KiB can leave and the rest
            # stays buffered until the limit stops the writer.
            @test_throws UDA.DeadlineExceededError write(s, zeros(UInt8, 4 * QA._SEND_BUFFER_LIMIT))
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "unidirectional streams both ways" begin
        listener, client, server = _qa_pair()
        try
            u = QA.open_stream(client; bidi = false)
            @test !QA.isbidi(u)
            write(u, "ping")
            closewrite(u)
            pu = QA.accept_stream(server)
            @test !QA.isbidi(pu)
            @test String(read(pu)) == "ping"
            back = QA.open_stream(server; bidi = false)
            write(back, "pong")
            closewrite(back)
            cu = QA.accept_stream(client)
            @test QA.stream_id(cu) == QA.stream_id(back)
            @test String(read(cu)) == "pong"
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "the peer's reset ends reads with StreamResetError" begin
        listener, client, server = _qa_pair()
        try
            s = QA.open_stream(client)
            write(s, "request")
            peer = QA.accept_stream(server)
            @test String(read(peer, 7)) == "request"
            write(peer, "partial")
            QA.reset_stream!(peer, 0x10c)
            err = try
                read(s)
                nothing
            catch ex
                ex
            end
            @test err isa QA.StreamResetError
            @test err.code == 0x10c && err.stream_id == QA.stream_id(s) && err.remote
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "the peer's STOP_SENDING fails writes with StreamStoppedError" begin
        listener, client, server = _qa_pair()
        try
            s = QA.open_stream(client)
            write(s, "x")
            peer = QA.accept_stream(server)
            @test read(peer, 1) == UInt8[UInt8('x')]
            QA.stop_sending!(peer, 0x10b)
            chunk = zeros(UInt8, 1024)
            err = nothing
            for _ in 1:100_000
                try
                    write(s, chunk)
                catch ex
                    err = ex
                    break
                end
                yield()
            end
            @test err isa QA.StreamStoppedError
            @test err.code == 0x10b && err.remote
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "STOP_SENDING is reported to writes even after both sides finished" begin
        listener, client, server = _qa_pair()
        try
            s = QA.open_stream(client)
            write(s, "x")
            peer = QA.accept_stream(server)
            @test read(peer, 1) == UInt8[UInt8('x')]
            write(peer, "done")
            closewrite(peer)
            QA.stop_sending!(peer, 0x10b)
            @test String(read(s)) == "done"
            # Wait until the reset that answers the STOP_SENDING is
            # acknowledged, when the stream would otherwise be forgotten.
            ep = client.ep
            acked() = lock(ep.lock) do
                st = get(client.slot.conn.streams, QA.stream_id(s), nothing)
                st === nothing || st.reset_acked
            end
            while !acked()
                yield()
            end
            err = try
                write(s, "more")
                nothing
            catch ex
                ex
            end
            @test err isa QA.StreamStoppedError
            @test err.code == 0x10b && err.remote
            # Once seen, the stream is freed.
            @test !isopen(s)
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "abandoning a stream locally fails its blocked reads and later writes" begin
        listener, client, server = _qa_pair()
        try
            s = QA.open_stream(client)
            write(s, "x")
            peer = QA.accept_stream(server)
            @test read(peer, 1) == UInt8[UInt8('x')]
            reader = Threads.@spawn try
                read(s)
                nothing
            catch ex
                ex
            end
            QA.stop_sending!(s, 0x10c)
            err = fetch(reader)
            @test err isa QA.StreamStoppedError
            @test err.code == 0x10c && !err.remote
            QA.reset_stream!(s, 0x10d)
            err = try
                write(s, "more")
                nothing
            catch ex
                ex
            end
            @test err isa QA.StreamResetError
            @test err.code == 0x10d && !err.remote
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "readbytes! with all = false returns what has arrived" begin
        listener, client, server = _qa_pair()
        try
            s = QA.open_stream(client)
            write(s, "abc")
            peer = QA.accept_stream(server)
            buf = zeros(UInt8, 100)
            n = 0
            while n < 3
                k = readbytes!(peer, view(buf, (n + 1):100), 100 - n; all = false)
                @test k > 0
                n += k
            end
            @test String(buf[1:3]) == "abc"
            closewrite(s)
            @test readbytes!(peer, buf, 10; all = false) == 0
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "closing a connection fails the peer's blocked reads" begin
        listener, client, server = _qa_pair()
        try
            s = QA.open_stream(client)
            write(s, "hi")
            peer = QA.accept_stream(server)
            @test read(peer, 2) == codeunits("hi")
            reader = Threads.@spawn try
                read(s)
                nothing
            catch ex
                ex
            end
            close(server; code = 0x100, reason = "bye")
            err = fetch(reader)
            @test err isa QA.ConnectionError
            @test err.code == 0x100 && err.app && err.remote && err.reason == "bye"
            @test !isopen(client)
            local_err = try
                write(peer, "late")
                nothing
            catch ex
                ex
            end
            @test local_err isa QA.ConnectionError
            @test local_err.code == 0x100 && !local_err.remote
            @test_throws QA.ConnectionError QA.open_stream(client)
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "read deadlines" begin
        listener, client, server = _qa_pair()
        try
            s = QA.open_stream(client)
            write(s, "x")
            peer = QA.accept_stream(server)
            @test read(peer, 1) == UInt8[UInt8('x')]
            QA.set_read_deadline!(peer, Int64(time_ns()) - 1)
            @test_throws UDA.DeadlineExceededError read(peer, 1)
            QA.set_read_deadline!(peer, _qa_deadline(0.2))
            @test_throws UDA.DeadlineExceededError eof(peer)
            QA.set_read_deadline!(peer, 0)
            write(s, "y")
            @test read(peer, 1) == UInt8[UInt8('y')]
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "open_stream waits for the peer's stream limit" begin
        listener, client, server = _qa_pair(server_kw = (; max_streams_bidi = 1))
        try
            first_stream = QA.open_stream(client)
            @test_throws UDA.DeadlineExceededError QA.open_stream(client; deadline_ns = _qa_deadline(0.2))
            write(first_stream, "a")
            closewrite(first_stream)
            peer = QA.accept_stream(server)
            @test String(read(peer)) == "a"
            closewrite(peer)
            @test eof(first_stream)
            second = QA.open_stream(client; deadline_ns = _qa_deadline())
            @test QA.stream_id(second) == 4
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "connect gives up at its deadline when nobody answers" begin
        silent = UDA.listen(UDA.loopback_addr(0))
        try
            addr = UDA.local_addr(silent)
            @test_throws UDA.DeadlineExceededError QA.connect(addr, _qa_client_config(); deadline_ns = _qa_deadline(0.3))
        finally
            close(silent)
        end
    end

    @testset "an unreachable port is retried until the deadline, not fatal" begin
        # A connected socket hears ICMP port unreachable as ECONNREFUSED; that
        # is lost packets, as on an unconnected socket, not the end.
        probe = UDA.listen(UDA.loopback_addr(0))
        addr = UDA.local_addr(probe)
        close(probe)
        @test_throws UDA.DeadlineExceededError QA.connect(addr, _qa_client_config(); deadline_ns = _qa_deadline(0.5))
    end

    @testset "a closed connection releases its TLS state" begin
        listener, client, server = _qa_pair()
        close(client)
        @test QA._wait_endpoint_done(client.ep, _qa_deadline())
        @test client.slot.conn.tls.closed
        close(listener)
        @test QA._wait_endpoint_done(server.ep, _qa_deadline())
        @test server.slot.conn.tls.closed
    end

    @testset "rejects new connection attempts if the accept queue is full" begin
        # quic-go v0.48.2 server_test.go: protocol.MaxAcceptQueueSize = 32
        # handshaken connections wait to be accepted; more are refused.
        listener = QA.listen(UDA.loopback_addr(0), _qa_server_config())
        port = QA.local_addr(listener).port
        clients = QA.Connection[]
        try
            for _ in 1:32
                push!(clients, QA.connect(UDA.loopback_addr(port), _qa_client_config(); deadline_ns = _qa_deadline()))
            end
            err = try
                c = QA.connect(UDA.loopback_addr(port), _qa_client_config(); deadline_ns = _qa_deadline())
                push!(clients, c)
                QA.accept_stream(c; deadline_ns = _qa_deadline(10))
                nothing
            catch ex
                ex
            end
            @test err isa QA.ConnectionError && err.code == 0x02 && err.remote && !err.app
            # Accepting one makes room for another.
            QA.accept(listener; deadline_ns = _qa_deadline())
            push!(clients, QA.connect(UDA.loopback_addr(port), _qa_client_config(); deadline_ns = _qa_deadline()))
            @test QA.accept(listener; deadline_ns = _qa_deadline()) isa QA.Connection
        finally
            foreach(close, clients)
            close(listener)
        end
    end

    @testset "application error codes must fit a varint" begin
        listener, client, server = _qa_pair()
        try
            s = QA.open_stream(client)
            write(s, "x")
            too_big = UInt64(1) << 62
            @test_throws ArgumentError QA.reset_stream!(s, too_big)
            @test_throws ArgumentError QA.stop_sending!(s, too_big)
            @test_throws ArgumentError close(client; code = too_big)
            # Nothing broke: the connection and its endpoint still work.
            peer = QA.accept_stream(server; deadline_ns = _qa_deadline())
            @test read(peer, 1) == UInt8[UInt8('x')]
            QA.reset_stream!(s, too_big - 1)
            close(client; code = too_big - 1)
            err = try
                QA.accept_stream(server; deadline_ns = _qa_deadline())
                nothing
            catch ex
                ex
            end
            @test err isa QA.ConnectionError && err.code == too_big - 1 && err.app
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "listen checks the server's TLS config" begin
        no_cert = TLA.Config(verify_peer = false, alpn_protocols = [_QA_ALPN])
        @test_throws TLA.ConfigError QA.listen(UDA.loopback_addr(0), no_cert)
        tls12 = TLA.Config(verify_peer = false, cert_file = _QA_CERT, key_file = _QA_KEY,
            alpn_protocols = [_QA_ALPN], max_version = TLA.TLS1_2_VERSION)
        @test_throws TLA.ConfigError QA.listen(UDA.loopback_addr(0), tls12)
    end

    @testset "a connection that closes while waiting to be accepted is not handed out" begin
        listener = QA.listen(UDA.loopback_addr(0), _qa_server_config())
        port = QA.local_addr(listener).port
        try
            c = QA.connect(UDA.loopback_addr(port), _qa_client_config(); deadline_ns = _qa_deadline())
            ep = listener.ep
            queued() = lock(() -> length(ep.accept_queue), ep.lock)
            @test timedwait(() -> queued() == 1, 10) == :ok
            close(c)
            # Once the server has finished closing it, it leaves the queue.
            @test timedwait(() -> queued() == 0, 10) == :ok
            @test_throws UDA.DeadlineExceededError QA.accept(listener; deadline_ns = _qa_deadline(0.2))
        finally
            close(listener)
        end
    end

    @testset "connecting does not pin the calling task to a thread" begin
        # Scheduling a sticky task makes the scheduling task sticky too.
        if Threads.threadpoolsize() > 1
            listener = QA.listen(UDA.loopback_addr(0), _qa_server_config())
            port = QA.local_addr(listener).port
            try
                t = Threads.@spawn begin
                    c = QA.connect(UDA.loopback_addr(port), _qa_client_config(); deadline_ns = _qa_deadline())
                    sticky = current_task().sticky
                    close(c)
                    sticky
                end
                @test !fetch(t)
            finally
                close(listener)
            end
        end
    end

    @testset "a closed listener accepts no more, but its connections go on" begin
        listener, client, server = _qa_pair()
        try
            close(listener)
            @test_throws ArgumentError QA.accept(listener)
            s = QA.open_stream(client)
            write(s, "still here")
            closewrite(s)
            @test String(read(QA.accept_stream(server))) == "still here"
        finally
            _qa_close_all(listener, client, server)
        end
    end

    @testset "accept gives up at its deadline" begin
        listener = QA.listen(UDA.loopback_addr(0), _qa_server_config())
        try
            @test_throws UDA.DeadlineExceededError QA.accept(listener; deadline_ns = _qa_deadline(0.2))
        finally
            close(listener)
        end
    end

    # quic-go v0.48.2 integrationtests/self/resumption_test.go, "uses session
    # resumption": the second connection with the same client config resumes.
    @testset "uses session resumption" begin
        client_config = _qa_client_config()
        listener = QA.listen(UDA.loopback_addr(0), _qa_server_config())
        try
            addr = UDA.loopback_addr(QA.local_addr(listener).port)
            for resumed in (false, true)
                accepted = Threads.@spawn QA.accept(listener; deadline_ns = _qa_deadline())
                client = QA.connect(addr, client_config; deadline_ns = _qa_deadline())
                server = fetch(accepted)
                try
                    @test _qa_tls_state(client).did_resume == resumed
                    @test _qa_tls_state(server).did_resume == resumed
                    # The server queued its ticket when the handshake
                    # completed, ahead of any stream data, so on loopback it
                    # has arrived once a reply has.
                    s = QA.open_stream(client)
                    write(s, "ping")
                    closewrite(s)
                    peer = QA.accept_stream(server)
                    write(peer, read(peer))
                    closewrite(peer)
                    @test String(read(s)) == "ping"
                    @test _qa_tls_state(client).has_resumable_session
                finally
                    close(client)
                    close(server)
                end
            end
        finally
            close(listener)
        end
    end
end
