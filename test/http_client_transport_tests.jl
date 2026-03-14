using Test
using Reseau
using CodecZlib

const HT = Reseau.HTTP
const NC = Reseau.TCP
const ND = Reseau.HostResolvers

function _read_all_body_bytes(body::HT.AbstractBody)::Vector{UInt8}
    out = UInt8[]
    buf = Vector{UInt8}(undef, 32)
    while true
        n = HT.body_read!(body, buf)
        n == 0 && break
        append!(out, @view(buf[1:n]))
    end
    return out
end

function _write_all_tcp!(conn::NC.Conn, bytes::Vector{UInt8})::Nothing
    total = 0
    while total < length(bytes)
        n = write(conn, bytes[(total + 1):end])
        n > 0 || error("expected write progress")
        total += n
    end
    return nothing
end

function _write_response_to_conn!(conn::NC.Conn, request::HT.Request; body_text::String, close_conn::Bool = false)::Nothing
    payload = collect(codeunits(body_text))
    return _write_response_bytes_to_conn!(conn, request; body_bytes = payload, close_conn = close_conn)
end

function _write_response_bytes_to_conn!(conn::NC.Conn, request::HT.Request; body_bytes::Vector{UInt8}, headers::HT.Headers = HT.Headers(), close_conn::Bool = false)::Nothing
    headers_copy = copy(headers)
    close_conn && HT.setheader(headers_copy, "Connection", "close")
    response = HT.Response(
        200;
        reason = "OK",
        headers = headers_copy,
        body = HT.BytesBody(body_bytes),
        content_length = length(body_bytes),
        close = close_conn,
        request = request,
    )
    io = IOBuffer()
    HT.write_response!(io, response)
    _write_all_tcp!(conn, take!(io))
    return nothing
end

function _gzip_bytes_transport(text::String)::Vector{UInt8}
    return transcode(CodecZlib.GzipCompressor, collect(codeunits(text)))
end

function _wait_task!(task::Task; timeout_s::Float64 = 5.0)
    status = timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
    status == :timed_out && error("timed out waiting for server task")
    fetch(task)
    return nothing
end

function _transport_debug(msg::AbstractString)
    _ = msg
    return nothing
end

mutable struct _ChunkReadConn
    payload::Vector{UInt8}
    idx::Int
    max_chunk::Int
    reads::Int
end

function _ChunkReadConn(payload::Vector{UInt8}; max_chunk::Integer = 8)
    max_chunk > 0 || throw(ArgumentError("max_chunk must be > 0"))
    return _ChunkReadConn(payload, 1, Int(max_chunk), 0)
end

function Base.read!(conn::_ChunkReadConn, dst::Vector{UInt8})::Int
    conn.reads += 1
    conn.idx > length(conn.payload) && return 0
    n = min(length(dst), conn.max_chunk, length(conn.payload) - conn.idx + 1)
    copyto!(dst, 1, conn.payload, conn.idx, n)
    conn.idx += n
    return n
end

mutable struct _CountingResolverTransport <: ND.AbstractResolver
    delay_s::Float64
    addrs::Vector{NC.SocketEndpoint}
    lock::ReentrantLock
    calls::Int
end

function _CountingResolverTransport(delay_s::Float64, addrs::Vector{NC.SocketEndpoint})
    return _CountingResolverTransport(delay_s, addrs, ReentrantLock(), 0)
end

function ND.resolve_tcp_addrs(
        resolver::_CountingResolverTransport,
        network::AbstractString,
        address::AbstractString;
        op::Symbol = :connect,
        policy::ND.ResolverPolicy = ND.ResolverPolicy(),
    )::Vector{NC.SocketEndpoint}
    _ = network
    _ = address
    _ = op
    _ = policy
    lock(resolver.lock)
    try
        resolver.calls += 1
    finally
        unlock(resolver.lock)
    end
    sleep(resolver.delay_s)
    return copy(resolver.addrs)
end

@testset "_read_all_response_bytes caps eager preallocation" begin
    payload = collect(codeunits("ok"))
    body = HT.BytesBody(payload)
    bytes = HT._read_all_response_bytes(body; content_length_hint = HT._MAX_EAGER_RESPONSE_PREALLOC + 1)
    @test bytes == payload
end

@testset "HTTP transport constructor validates max_conns_per_host" begin
    @test_throws ArgumentError HT.Transport(max_conns_per_host = -1)
end

@testset "HTTP client transport coalesces duplicate concurrent lookups" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("same.test", Int(laddr.port))
    resolver = _CountingResolverTransport(0.05, NC.SocketEndpoint[NC.loopback_addr(Int(laddr.port))])
    singleflight = ND.SingleflightResolver(resolver)
    host_resolver = ND.HostResolver(resolver = singleflight, timeout_ns = 1_000_000_000, fallback_delay_ns = -1)
    server_task = errormonitor(Threads.@spawn begin
        for _ in 1:2
            conn = NC.accept!(listener)
            try
                request = HT.read_request(HT._ConnReader(conn))
                _read_all_body_bytes(request.body)
                _write_response_to_conn!(conn, request; body_text = "ok", close_conn = true)
            finally
                try
                    NC.close!(conn)
                catch
                end
            end
        end
        return nothing
    end)
    transport = HT.Transport(host_resolver = host_resolver, max_idle_per_host = 4, max_idle_total = 4)
    try
        req1 = HT.Request("GET", "/one"; host = address, body = HT.EmptyBody(), content_length = 0)
        req2 = HT.Request("GET", "/two"; host = address, body = HT.EmptyBody(), content_length = 0)
        task1 = errormonitor(Threads.@spawn HT.roundtrip!(transport, address, req1))
        task2 = errormonitor(Threads.@spawn HT.roundtrip!(transport, address, req2))
        @test _wait_task!(task1) === nothing
        @test _wait_task!(task2) === nothing
        res1 = fetch(task1)
        res2 = fetch(task2)
        @test String(_read_all_body_bytes(res1.body)) == "ok"
        @test String(_read_all_body_bytes(res2.body)) == "ok"
        _wait_task!(server_task)
        @test resolver.calls == 1
        @test (@atomic :acquire singleflight.actual_lookups) == 1
        @test (@atomic :acquire singleflight.shared_hits) == 1
    finally
        close(transport)
        try
            NC.close!(listener)
        catch
        end
    end
end

@testset "_ConnReader uses buffered reads for HTTP/1 parsing" begin
    raw = collect(codeunits("POST /upload HTTP/1.1\r\nHost: example.test\r\nContent-Length: 5\r\n\r\nhello"))
    conn = _ChunkReadConn(raw; max_chunk = 8)
    reader = HT._ConnReader(conn; buffer_bytes = 32)
    request = HT.read_request(reader)
    @test request.method == "POST"
    @test request.target == "/upload"
    @test request.content_length == 5
    @test String(_read_all_body_bytes(request.body)) == "hello"
    @test conn.reads <= cld(length(raw), conn.max_chunk) + 2
end

@testset "HTTP client transport keep-alive reuse" begin
    _transport_debug("keep-alive reuse: start")
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    lock_obj = ReentrantLock()
    accept_count = Ref(0)
    paths = String[]
    server_task = errormonitor(Threads.@spawn begin
        _transport_debug("keep-alive reuse: server waiting accept")
        conn = NC.accept!(listener)
        _transport_debug("keep-alive reuse: server accepted")
        lock(lock_obj)
        try
            accept_count[] += 1
        finally
            unlock(lock_obj)
        end
        try
            for _ in 1:2
                _transport_debug("keep-alive reuse: server read_request begin")
                request = HT.read_request(HT._ConnReader(conn))
                _transport_debug("keep-alive reuse: server read_request done")
                push!(paths, request.target)
                _read_all_body_bytes(request.body)
                _write_response_to_conn!(conn, request; body_text = "ok")
                _transport_debug("keep-alive reuse: server response written")
            end
        finally
            try
                NC.close!(conn)
            catch
            end
        end
        return nothing
    end)
    transport = HT.Transport(max_idle_per_host = 4, max_idle_total = 4)
    try
        _transport_debug("keep-alive reuse: client req1 begin")
        _transport_debug("keep-alive reuse: client req1 build request")
        req1 = HT.Request("GET", "/one"; host = address, body = HT.EmptyBody(), content_length = 0)
        _transport_debug("keep-alive reuse: client req1 build done")
        _transport_debug("keep-alive reuse: client req1 roundtrip call")
        res1 = HT.roundtrip!(transport, address, req1)
        _transport_debug("keep-alive reuse: client req1 roundtrip done")
        @test String(_read_all_body_bytes(res1.body)) == "ok"
        _transport_debug("keep-alive reuse: client req2 begin")
        req2 = HT.Request("GET", "/two"; host = address, body = HT.EmptyBody(), content_length = 0)
        res2 = HT.roundtrip!(transport, address, req2)
        _transport_debug("keep-alive reuse: client req2 roundtrip done")
        @test String(_read_all_body_bytes(res2.body)) == "ok"
        _transport_debug("keep-alive reuse: waiting server task")
        _wait_task!(server_task)
        _transport_debug("keep-alive reuse: server task done")
        @test accept_count[] == 1
        @test paths == ["/one", "/two"]
        @test HT.idle_connection_count(transport; key = "http://$address") == 1
        HT.close_idle_connections!(transport)
        @test HT.idle_connection_count(transport) == 0
    finally
        close(transport)
        try
            NC.close!(listener)
        catch
        end
    end
end

@testset "HTTP client transport no reuse on Connection close" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    lock_obj = ReentrantLock()
    accept_count = Ref(0)
    server_task = errormonitor(Threads.@spawn begin
        for _ in 1:2
            conn = NC.accept!(listener)
            lock(lock_obj)
            try
                accept_count[] += 1
            finally
                unlock(lock_obj)
            end
            try
                request = HT.read_request(HT._ConnReader(conn))
                _read_all_body_bytes(request.body)
                _write_response_to_conn!(conn, request; body_text = "bye", close_conn = true)
            finally
                try
                    NC.close!(conn)
                catch
                end
            end
        end
        return nothing
    end)
    transport = HT.Transport(max_idle_per_host = 4, max_idle_total = 4)
    try
        req1 = HT.Request("GET", "/a"; host = address, body = HT.EmptyBody(), content_length = 0)
        res1 = HT.roundtrip!(transport, address, req1)
        @test String(_read_all_body_bytes(res1.body)) == "bye"
        req2 = HT.Request("GET", "/b"; host = address, body = HT.EmptyBody(), content_length = 0)
        res2 = HT.roundtrip!(transport, address, req2)
        @test String(_read_all_body_bytes(res2.body)) == "bye"
        _wait_task!(server_task)
        @test accept_count[] == 2
        @test HT.idle_connection_count(transport) == 0
    finally
        close(transport)
        try
            NC.close!(listener)
        catch
        end
    end
end

@testset "HTTP client transport keep-alive reuse with gzip decompression" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    base_url = "http://$(address)"
    accept_count = Ref(0)
    paths = String[]
    server_task = errormonitor(Threads.@spawn begin
        conn = NC.accept!(listener)
        accept_count[] += 1
        try
            for _ in 1:2
                request = HT.read_request(HT._ConnReader(conn))
                push!(paths, request.target)
                _read_all_body_bytes(request.body)
                headers = HT.Headers()
                HT.setheader(headers, "Content-Encoding", "gzip")
                _write_response_bytes_to_conn!(
                    conn,
                    request;
                    body_bytes = _gzip_bytes_transport("gzip-ok"),
                    headers = headers,
                )
            end
        finally
            try
                NC.close!(conn)
            catch
            end
        end
        return nothing
    end)
    transport = HT.Transport(max_idle_per_host = 4, max_idle_total = 4)
    client = HT.Client(transport = transport)
    try
        res1 = HT.get("$(base_url)/one"; client = client)
        @test String(res1.body) == "gzip-ok"
        res2 = HT.get("$(base_url)/two"; client = client)
        @test String(res2.body) == "gzip-ok"
        _wait_task!(server_task)
        @test accept_count[] == 1
        @test paths == ["/one", "/two"]
        @test HT.idle_connection_count(transport; key = "http://$address") == 1
    finally
        close(client)
        try
            NC.close!(listener)
        catch
        end
    end
end

@testset "HTTP client transport hands off waiting acquire under host cap" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    accept_count = Ref(0)
    paths = String[]
    server_task = errormonitor(Threads.@spawn begin
        conn = NC.accept!(listener)
        accept_count[] += 1
        try
            req1 = HT.read_request(HT._ConnReader(conn))
            push!(paths, req1.target)
            _read_all_body_bytes(req1.body)
            _write_response_to_conn!(conn, req1; body_text = "first")
            req2 = HT.read_request(HT._ConnReader(conn))
            push!(paths, req2.target)
            _read_all_body_bytes(req2.body)
            _write_response_to_conn!(conn, req2; body_text = "second", close_conn = true)
        finally
            try
                NC.close!(conn)
            catch
            end
        end
        return nothing
    end)
    transport = HT.Transport(max_idle_per_host = 1, max_idle_total = 1, max_conns_per_host = 1)
    try
        req1 = HT.Request("GET", "/one"; host = address, body = HT.EmptyBody(), content_length = 0)
        res1 = HT.roundtrip!(transport, address, req1)
        @test res1.status_code == 200

        req2 = HT.Request("GET", "/two"; host = address, body = HT.EmptyBody(), content_length = 0)
        res2_task = errormonitor(Threads.@spawn HT.roundtrip!(transport, address, req2))
        @test timedwait(() -> istaskdone(res2_task), 0.05; pollint = 0.001) == :timed_out

        @test String(_read_all_body_bytes(res1.body)) == "first"

        res2 = fetch(res2_task)
        @test res2.status_code == 200
        @test String(_read_all_body_bytes(res2.body)) == "second"
        _wait_task!(server_task)
        @test accept_count[] == 1
        @test paths == ["/one", "/two"]
        @test HT.idle_connection_count(transport) == 0
    finally
        close(transport)
        try
            NC.close!(listener)
        catch
        end
    end
end

@testset "HTTP client transport wakes waiter to redial after early close under host cap" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    accept_count = Ref(0)
    same_conn_second_request = Ref(false)
    server_task = errormonitor(Threads.@spawn begin
        conn1 = NC.accept!(listener)
        accept_count[] += 1
        try
            req1 = HT.read_request(HT._ConnReader(conn1))
            _read_all_body_bytes(req1.body)
            _write_response_to_conn!(conn1, req1; body_text = "first-response")
            NC.set_read_deadline!(conn1, Int64(time_ns()) + 300_000_000)
            try
                req_maybe = HT.read_request(HT._ConnReader(conn1))
                same_conn_second_request[] = true
                _read_all_body_bytes(req_maybe.body)
                _write_response_to_conn!(conn1, req_maybe; body_text = "unexpected")
            catch err
                if !(err isa EOFError || err isa SystemError || err isa Reseau.IOPoll.DeadlineExceededError || err isa Reseau.IOPoll.NetClosingError || err isa HT.ParseError || err isa HT.ProtocolError)
                    rethrow(err)
                end
            end
        finally
            try
                NC.close!(conn1)
            catch
            end
        end
        conn2 = NC.accept!(listener)
        accept_count[] += 1
        try
            req2 = HT.read_request(HT._ConnReader(conn2))
            _read_all_body_bytes(req2.body)
            _write_response_to_conn!(conn2, req2; body_text = "second-response", close_conn = true)
        finally
            try
                NC.close!(conn2)
            catch
            end
        end
        return nothing
    end)
    transport = HT.Transport(max_idle_per_host = 1, max_idle_total = 1, max_conns_per_host = 1)
    try
        req1 = HT.Request("GET", "/one"; host = address, body = HT.EmptyBody(), content_length = 0)
        res1 = HT.roundtrip!(transport, address, req1)
        @test res1.status_code == 200

        req2 = HT.Request("GET", "/two"; host = address, body = HT.EmptyBody(), content_length = 0)
        res2_task = errormonitor(Threads.@spawn HT.roundtrip!(transport, address, req2))
        @test timedwait(() -> istaskdone(res2_task), 0.05; pollint = 0.001) == :timed_out

        first_byte = Vector{UInt8}(undef, 1)
        @test HT.body_read!(res1.body, first_byte) == 1
        HT.body_close!(res1.body)

        res2 = fetch(res2_task)
        @test res2.status_code == 200
        @test String(_read_all_body_bytes(res2.body)) == "second-response"
        _wait_task!(server_task)
        @test accept_count[] == 2
        @test !same_conn_second_request[]
        @test HT.idle_connection_count(transport) == 0
    finally
        close(transport)
        try
            NC.close!(listener)
        catch
        end
    end
end

@testset "HTTP client transport waiter honors request deadline under host cap" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    accept_count = Ref(0)
    second_request_seen = Ref(false)
    server_task = errormonitor(Threads.@spawn begin
        conn = NC.accept!(listener)
        accept_count[] += 1
        try
            req1 = HT.read_request(HT._ConnReader(conn))
            _read_all_body_bytes(req1.body)
            _write_response_to_conn!(conn, req1; body_text = "first")
            NC.set_read_deadline!(conn, Int64(time_ns()) + 300_000_000)
            try
                req2 = HT.read_request(HT._ConnReader(conn))
                second_request_seen[] = true
                _read_all_body_bytes(req2.body)
            catch err
                if !(err isa EOFError || err isa SystemError || err isa Reseau.IOPoll.DeadlineExceededError || err isa Reseau.IOPoll.NetClosingError || err isa HT.ParseError || err isa HT.ProtocolError)
                    rethrow(err)
                end
            end
        finally
            try
                NC.close!(conn)
            catch
            end
        end
        return nothing
    end)
    transport = HT.Transport(max_idle_per_host = 1, max_idle_total = 1, max_conns_per_host = 1)
    try
        req1 = HT.Request("GET", "/one"; host = address, body = HT.EmptyBody(), content_length = 0)
        res1 = HT.roundtrip!(transport, address, req1)
        @test res1.status_code == 200

        req2 = HT.Request("GET", "/two"; host = address, body = HT.EmptyBody(), content_length = 0)
        HT.set_deadline!(req2.context, Int64(time_ns()) + 50_000_000)
        err = try
            HT.roundtrip!(transport, address, req2)
            nothing
        catch caught
            caught
        end
        @test err isa Reseau.IOPoll.DeadlineExceededError

        HT.body_close!(res1.body)
        _wait_task!(server_task)
        @test accept_count[] == 1
        @test !second_request_seen[]
        @test HT.idle_connection_count(transport) == 0
    finally
        close(transport)
        try
            NC.close!(listener)
        catch
        end
    end
end

@testset "HTTP client transport skips interim 1xx responses" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    server_task = errormonitor(Threads.@spawn begin
        conn = NC.accept!(listener)
        try
            request = HT.read_request(HT._ConnReader(conn))
            _read_all_body_bytes(request.body)
            payload = collect(codeunits("HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"))
            _write_all_tcp!(conn, payload)
        finally
            try
                NC.close!(conn)
            catch
            end
        end
        return nothing
    end)
    transport = HT.Transport(max_idle_per_host = 4, max_idle_total = 4)
    try
        req = HT.Request("POST", "/one"; host = address, body = HT.BytesBody(UInt8[0x78]), content_length = 1)
        res = HT.roundtrip!(transport, address, req)
        @test res.status_code == 200
        @test String(_read_all_body_bytes(res.body)) == "ok"
        _wait_task!(server_task)
    finally
        close(transport)
        try
            NC.close!(listener)
        catch
        end
    end
end

@testset "HTTP client transport closes request body after send" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    body_data = collect(codeunits("ping"))
    body_index = Ref(1)
    close_count = Ref(0)
    callback_body = HT.CallbackBody(
        dst -> begin
            idx = body_index[]
            idx > length(body_data) && return 0
            n = min(length(dst), length(body_data) - idx + 1)
            copyto!(dst, 1, body_data, idx, n)
            body_index[] += n
            return n
        end,
        () -> begin
            close_count[] += 1
            return nothing
        end,
    )
    server_task = errormonitor(Threads.@spawn begin
        conn = NC.accept!(listener)
        try
            request = HT.read_request(HT._ConnReader(conn))
            @test String(_read_all_body_bytes(request.body)) == "ping"
            _write_response_to_conn!(conn, request; body_text = "done", close_conn = true)
        finally
            try
                NC.close!(conn)
            catch
            end
        end
        return nothing
    end)
    transport = HT.Transport(max_idle_per_host = 4, max_idle_total = 4)
    try
        req = HT.Request("POST", "/close"; host = address, body = callback_body, content_length = 4)
        res = HT.roundtrip!(transport, address, req)
        @test res.status_code == 200
        @test String(_read_all_body_bytes(res.body)) == "done"
        _wait_task!(server_task)
        @test close_count[] == 1
    finally
        close(transport)
        try
            NC.close!(listener)
        catch
        end
    end
end

@testset "HTTP client transport does not reuse conn after early response close" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    accept_count = Ref(0)
    same_conn_second_request = Ref(false)
    server_task = errormonitor(Threads.@spawn begin
        conn1 = NC.accept!(listener)
        accept_count[] += 1
        try
            req1 = HT.read_request(HT._ConnReader(conn1))
            _read_all_body_bytes(req1.body)
            _write_response_to_conn!(conn1, req1; body_text = "first-response")
            NC.set_read_deadline!(conn1, Int64(time_ns()) + 300_000_000)
            try
                req_maybe = HT.read_request(HT._ConnReader(conn1))
                same_conn_second_request[] = true
                _read_all_body_bytes(req_maybe.body)
                _write_response_to_conn!(conn1, req_maybe; body_text = "unexpected")
            catch err
                if !(err isa EOFError || err isa SystemError || err isa Reseau.IOPoll.DeadlineExceededError || err isa Reseau.IOPoll.NetClosingError || err isa HT.ParseError || err isa HT.ProtocolError)
                    rethrow(err)
                end
            end
        finally
            try
                NC.close!(conn1)
            catch
            end
        end
        conn2 = NC.accept!(listener)
        accept_count[] += 1
        try
            req2 = HT.read_request(HT._ConnReader(conn2))
            _read_all_body_bytes(req2.body)
            _write_response_to_conn!(conn2, req2; body_text = "second-response", close_conn = true)
        finally
            try
                NC.close!(conn2)
            catch
            end
        end
        return nothing
    end)
    transport = HT.Transport(max_idle_per_host = 4, max_idle_total = 4)
    try
        req1 = HT.Request("GET", "/one"; host = address, body = HT.EmptyBody(), content_length = 0)
        res1 = HT.roundtrip!(transport, address, req1)
        first_byte = Vector{UInt8}(undef, 1)
        @test HT.body_read!(res1.body, first_byte) == 1
        HT.body_close!(res1.body)
        @test HT.idle_connection_count(transport) == 0

        req2 = HT.Request("GET", "/two"; host = address, body = HT.EmptyBody(), content_length = 0)
        res2 = HT.roundtrip!(transport, address, req2)
        @test res2.status_code == 200
        @test String(_read_all_body_bytes(res2.body)) == "second-response"
        _wait_task!(server_task)
        @test accept_count[] == 2
        @test !same_conn_second_request[]
    finally
        close(transport)
        try
            NC.close!(listener)
        catch
        end
    end
end

@testset "HTTP client transport retries idempotent request on stale reused conn" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    accept_count = Ref(0)
    paths = String[]
    server_task = errormonitor(Threads.@spawn begin
        conn1 = NC.accept!(listener)
        accept_count[] += 1
        try
            req1 = HT.read_request(HT._ConnReader(conn1))
            push!(paths, req1.target)
            _read_all_body_bytes(req1.body)
            _write_response_to_conn!(conn1, req1; body_text = "warmup")
            sleep(0.15)
        finally
            try
                NC.close!(conn1)
            catch
            end
        end
        conn2 = NC.accept!(listener)
        accept_count[] += 1
        try
            req2 = HT.read_request(HT._ConnReader(conn2))
            push!(paths, req2.target)
            _read_all_body_bytes(req2.body)
            _write_response_to_conn!(conn2, req2; body_text = "retried", close_conn = true)
        finally
            try
                NC.close!(conn2)
            catch
            end
        end
        return nothing
    end)
    transport = HT.Transport(max_idle_per_host = 4, max_idle_total = 4)
    try
        req1 = HT.Request("GET", "/warmup"; host = address, body = HT.EmptyBody(), content_length = 0)
        res1 = HT.roundtrip!(transport, address, req1)
        @test String(_read_all_body_bytes(res1.body)) == "warmup"
        sleep(0.20)
        req2 = HT.Request("GET", "/retry"; host = address, body = HT.EmptyBody(), content_length = 0)
        res2 = HT.roundtrip!(transport, address, req2)
        @test res2.status_code == 200
        @test String(_read_all_body_bytes(res2.body)) == "retried"
        _wait_task!(server_task)
        @test accept_count[] == 2
        @test paths == ["/warmup", "/retry"]
    finally
        close(transport)
        try
            NC.close!(listener)
        catch
        end
    end
end

@testset "HTTP client transport treats not-pollable reused errors as retryable" begin
    @test HT._retryable_reused_conn_error(Reseau.IOPoll.NotPollableError())
end
