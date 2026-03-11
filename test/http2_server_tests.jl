using Test
using Reseau

const HT = Reseau.HTTP
const ND = Reseau.HostResolvers
const NC = Reseau.TCP

function _wait_http_server_addr(server::HT.Server; timeout_s::Float64 = 5.0)::String
    deadline = time() + timeout_s
    while time() < deadline
        try
            return HT.server_addr(server)
        catch
            sleep(0.01)
        end
    end
    error("timed out waiting for server address")
end

function _read_all_h2_server(body::HT.AbstractBody)::Vector{UInt8}
    out = UInt8[]
    buf = Vector{UInt8}(undef, 64)
    while true
        n = HT.body_read!(body, buf)
        n == 0 && break
        append!(out, @view(buf[1:n]))
    end
    return out
end

function _write_all_h2_server_raw!(conn::NC.Conn, bytes::Vector{UInt8})
    total = 0
    while total < length(bytes)
        n = write(conn, bytes[(total + 1):end])
        n > 0 || error("expected write progress")
        total += n
    end
    return nothing
end

function _write_frame_h2_server_raw!(conn::NC.Conn, frame::HT.AbstractFrame)
    io = IOBuffer()
    framer = HT.Framer(io)
    HT.write_frame!(framer, frame)
    _write_all_h2_server_raw!(conn, take!(io))
    return nothing
end

@testset "HTTP/2 server request handling" begin
    server = HT.serve!("127.0.0.1", 0; listenany = true) do request
            payload = collect(codeunits("h2:" * request.target))
            return HT.Response(200; body = HT.BytesBody(payload), content_length = length(payload), proto_major = 2, proto_minor = 0)
        end
    address = _wait_http_server_addr(server)
    conn = HT.connect_h2!(address; secure = false)
    try
        req1 = HT.Request("GET", "/one"; host = address, body = HT.EmptyBody(), content_length = 0, proto_major = 2, proto_minor = 0)
        req2 = HT.Request("GET", "/two"; host = address, body = HT.EmptyBody(), content_length = 0, proto_major = 2, proto_minor = 0)
        res1 = HT.h2_roundtrip!(conn, req1)
        res2 = HT.h2_roundtrip!(conn, req2)
        @test res1.status_code == 200
        @test res2.status_code == 200
        @test String(_read_all_h2_server(res1.body)) == "h2:/one"
        @test String(_read_all_h2_server(res2.body)) == "h2:/two"
    finally
        close(conn)
        HT.forceclose(server)
        _ = timedwait(() -> istaskdone(server.serve_task::Task), 3.0; pollint = 0.001)
    end
end

@testset "HTTP/2 server stream handlers work and suppress HEAD bodies" begin
    server = HT.listen!("127.0.0.1", 0; listenany = true) do stream
            request = HT.startread(stream)
            body = String(read(stream))
            HT.setstatus(stream, 200)
            HT.setheader(stream, "Content-Type", "text/plain")
            HT.startwrite(stream)
            write(stream, isempty(body) ? "ok" : body)
            return nothing
        end
    address = _wait_http_server_addr(server)
    conn = HT.connect_h2!(address; secure = false)
    try
        get_req = HT.Request("GET", "/stream"; host = address, body = HT.EmptyBody(), content_length = 0, proto_major = 2, proto_minor = 0)
        get_res = HT.h2_roundtrip!(conn, get_req)
        @test get_res.status_code == 200
        @test String(_read_all_h2_server(get_res.body)) == "ok"

        post_payload = collect(codeunits("echo"))
        post_req = HT.Request("POST", "/echo"; host = address, body = HT.BytesBody(post_payload), content_length = length(post_payload), proto_major = 2, proto_minor = 0)
        post_res = HT.h2_roundtrip!(conn, post_req)
        @test post_res.status_code == 200
        @test String(_read_all_h2_server(post_res.body)) == "echo"

        head_req = HT.Request("HEAD", "/head"; host = address, body = HT.EmptyBody(), content_length = 0, proto_major = 2, proto_minor = 0)
        head_res = HT.h2_roundtrip!(conn, head_req)
        @test head_res.status_code == 200
        @test isempty(_read_all_h2_server(head_res.body))
    finally
        close(conn)
        HT.forceclose(server)
        _ = timedwait(() -> istaskdone(server.serve_task::Task), 3.0; pollint = 0.001)
    end
end

@testset "HTTP/2 server request flow control for large uploads" begin
    server = HT.serve!("127.0.0.1", 0; listenany = true) do request
            total = 0
            buf = Vector{UInt8}(undef, 16 * 1024)
            while true
                n = HT.body_read!(request.body, buf)
                n == 0 && break
                total += n
            end
            payload = collect(codeunits(string(total)))
            return HT.Response(200; body = HT.BytesBody(payload), content_length = length(payload), proto_major = 2, proto_minor = 0)
        end
    address = _wait_http_server_addr(server)
    conn = HT.connect_h2!(address; secure = false)
    try
        payload = fill(UInt8('u'), 70_000)
        req = HT.Request("POST", "/upload"; host = address, body = HT.BytesBody(payload), content_length = length(payload), proto_major = 2, proto_minor = 0)
        res = HT.h2_roundtrip!(conn, req)
        @test res.status_code == 200
        @test String(_read_all_h2_server(res.body)) == "70000"
    finally
        close(conn)
        HT.forceclose(server)
        _ = timedwait(() -> istaskdone(server.serve_task::Task), 3.0; pollint = 0.001)
    end
end

@testset "HTTP/2 server shutdown closes listener" begin
    server = HT.serve!("127.0.0.1", 0; listenany = true) do request
            _ = request
            return HT.Response(200; body = HT.BytesBody(UInt8[0x6f, 0x6b]), content_length = 2, proto_major = 2, proto_minor = 0)
        end
    address = _wait_http_server_addr(server)
    conn = HT.connect_h2!(address; secure = false)
    try
        req = HT.Request("GET", "/ok"; host = address, body = HT.EmptyBody(), content_length = 0, proto_major = 2, proto_minor = 0)
        res = HT.h2_roundtrip!(conn, req)
        @test res.status_code == 200
    finally
        close(conn)
    end
    HT.forceclose(server)
    _ = timedwait(() -> istaskdone(server.serve_task::Task), 3.0; pollint = 0.001)
    fail_fast_resolver = ND.HostResolver(timeout_ns = Int64(1_000_000_000))
    @test_throws Exception HT.connect_h2!(address; secure = false, host_resolver = fail_fast_resolver)
end

@testset "HTTP/2 server splits large response bodies into valid DATA frames" begin
    large_payload = fill(UInt8('z'), 70_000)
    server = HT.serve!("127.0.0.1", 0; listenany = true) do request
            _ = request
            return HT.Response(200; body = HT.BytesBody(large_payload), content_length = length(large_payload), proto_major = 2, proto_minor = 0)
        end
    address = _wait_http_server_addr(server)
    conn = HT.connect_h2!(address; secure = false)
    try
        req = HT.Request("GET", "/large"; host = address, body = HT.EmptyBody(), content_length = 0, proto_major = 2, proto_minor = 0)
        res = HT.h2_roundtrip!(conn, req)
        @test res.status_code == 200
        body = _read_all_h2_server(res.body)
        @test length(body) == 70_000
        @test body == large_payload
    finally
        close(conn)
        HT.forceclose(server)
        _ = timedwait(() -> istaskdone(server.serve_task::Task), 3.0; pollint = 0.001)
    end
end

@testset "HTTP/2 server suppresses bodies for 204 and 304 responses" begin
    server = HT.serve!("127.0.0.1", 0; listenany = true) do request
            payload = collect(codeunits("oops"))
            if request.target == "/nocontent"
                return HT.Response(204; body = HT.BytesBody(payload), content_length = length(payload), proto_major = 2, proto_minor = 0)
            end
            return HT.Response(304; body = HT.BytesBody(payload), content_length = length(payload), proto_major = 2, proto_minor = 0)
        end
    address = _wait_http_server_addr(server)
    conn = HT.connect_h2!(address; secure = false)
    try
        no_content_req = HT.Request("GET", "/nocontent"; host = address, body = HT.EmptyBody(), content_length = 0, proto_major = 2, proto_minor = 0)
        no_content_res = HT.h2_roundtrip!(conn, no_content_req)
        @test no_content_res.status_code == 204
        @test isempty(_read_all_h2_server(no_content_res.body))

        not_modified_req = HT.Request("GET", "/not-modified"; host = address, body = HT.EmptyBody(), content_length = 0, proto_major = 2, proto_minor = 0)
        not_modified_res = HT.h2_roundtrip!(conn, not_modified_req)
        @test not_modified_res.status_code == 304
        @test isempty(_read_all_h2_server(not_modified_res.body))
    finally
        close(conn)
        HT.forceclose(server)
        _ = timedwait(() -> istaskdone(server.serve_task::Task), 3.0; pollint = 0.001)
    end
end

@testset "HTTP/2 server rejects invalid continuation sequencing" begin
    server = HT.serve!("127.0.0.1", 0; listenany = true) do request
            _ = request
            return HT.Response(200; body = HT.BytesBody(UInt8[0x6f, 0x6b]), content_length = 2, proto_major = 2, proto_minor = 0)
        end
    address = _wait_http_server_addr(server)
    conn = ND.connect("tcp", address)
    reader = HT.Framer(HT._ConnReader(conn))
    try
        _write_all_h2_server_raw!(conn, HT._H2_PREFACE)
        _write_frame_h2_server_raw!(conn, HT.SettingsFrame(false, Pair{UInt16, UInt32}[]))
        _ = HT.read_frame!(reader)
        _ = HT.read_frame!(reader)
        encoder = HT.Encoder()
        header_block = HT.encode_header_block(
            encoder,
            HT.HeaderField[
                HT.HeaderField(":method", "GET", false),
                HT.HeaderField(":scheme", "http", false),
                HT.HeaderField(":authority", address, false),
                HT.HeaderField(":path", "/bad", false),
            ],
        )
        split_idx = max(1, length(header_block) ÷ 2)
        _write_frame_h2_server_raw!(conn, HT.HeadersFrame(UInt32(1), false, false, header_block[1:split_idx]))
        _write_frame_h2_server_raw!(conn, HT.DataFrame(UInt32(1), true, UInt8[]))
        NC.set_deadline!(conn, Int64(time_ns() + 1_000_000_000))
        @test_throws Exception HT.read_frame!(reader)
    finally
        try
            NC.close!(conn)
        catch
        end
        HT.forceclose(server)
        _ = timedwait(() -> istaskdone(server.serve_task::Task), 3.0; pollint = 0.001)
    end
end
