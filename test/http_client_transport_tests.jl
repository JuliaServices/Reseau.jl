using Test
using Reseau

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
    headers = HT.Headers()
    close_conn && HT.set_header!(headers, "Connection", "close")
    payload = collect(codeunits(body_text))
    response = HT.Response(
        200;
        reason = "OK",
        headers = headers,
        body = HT.BytesBody(payload),
        content_length = length(payload),
        close = close_conn,
        request = request,
    )
    io = IOBuffer()
    HT.write_response!(io, response)
    _write_all_tcp!(conn, take!(io))
    return nothing
end

function _wait_task!(task::Task; timeout_s::Float64 = 5.0)
    status = timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
    status == :timed_out && error("timed out waiting for server task")
    fetch(task)
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
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    lock_obj = ReentrantLock()
    accept_count = Ref(0)
    paths = String[]
    server_task = errormonitor(Threads.@spawn begin
        conn = NC.accept!(listener)
        lock(lock_obj)
        try
            accept_count[] += 1
        finally
            unlock(lock_obj)
        end
        try
            for _ in 1:2
                request = HT.read_request(HT._ConnReader(conn))
                push!(paths, request.target)
                _read_all_body_bytes(request.body)
                _write_response_to_conn!(conn, request; body_text = "ok")
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
        req1 = HT.Request("GET", "/one"; host = address, body = HT.EmptyBody(), content_length = 0)
        res1 = HT.roundtrip!(transport, address, req1)
        @test String(_read_all_body_bytes(res1.body)) == "ok"
        req2 = HT.Request("GET", "/two"; host = address, body = HT.EmptyBody(), content_length = 0)
        res2 = HT.roundtrip!(transport, address, req2)
        @test String(_read_all_body_bytes(res2.body)) == "ok"
        _wait_task!(server_task)
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
