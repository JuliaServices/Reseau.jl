using Test
using Reseau

const HT = Reseau.HTTP

function _read_all_body_bytes(body::HT.AbstractBody)::Vector{UInt8}
    out = UInt8[]
    buf = Vector{UInt8}(undef, 8)
    while true
        n = HT.body_read!(body, buf)
        n == 0 && break
        append!(out, @view(buf[1:n]))
    end
    return out
end

@testset "HTTP/1 request parse/write" begin
    raw = "POST /upload HTTP/1.1\r\nHost: example.com\r\nContent-Length: 5\r\nX-Test: one\r\nX-Test: two\r\n\r\nhello"
    req = HT.read_request(IOBuffer(codeunits(raw)))
    @test req.method == "POST"
    @test req.target == "/upload"
    @test req.host == "example.com"
    @test req.content_length == 5
    @test HT.get_headers(req.headers, "X-Test") == ["one", "two"]
    @test _read_all_body_bytes(req.body) == collect(codeunits("hello"))
    headers = HT.Headers()
    HT.set_header!(headers, "host", "example.com")
    body = HT.BytesBody(collect(codeunits("ping")))
    outbound = HT.Request("PUT", "/v1"; headers = headers, body = body, content_length = 4)
    io = IOBuffer()
    HT.write_request!(io, outbound)
    parsed = HT.read_request(IOBuffer(take!(io)))
    @test parsed.method == "PUT"
    @test parsed.target == "/v1"
    @test parsed.content_length == 4
    @test _read_all_body_bytes(parsed.body) == collect(codeunits("ping"))
end

@testset "HTTP/1 response parse/write chunked" begin
    raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\nX-Trailer: done\r\n\r\n"
    resp = HT._read_response(IOBuffer(codeunits(raw)))
    @test resp.status_code == 200
    @test HT.get_header(resp.headers, "Transfer-Encoding") == "chunked"
    @test _read_all_body_bytes(resp.body) == collect(codeunits("Wikipedia"))
    @test HT.get_header(resp.trailers, "X-Trailer") == "done"
    headers = HT.Headers()
    HT.set_header!(headers, "Transfer-Encoding", "chunked")
    trailers = HT.Headers()
    HT.set_header!(trailers, "X-Checksum", "abc123")
    resp_out = HT.Response(200; reason = "OK", headers = headers, trailers = trailers, body = HT.BytesBody(collect(codeunits("chunked-body"))), content_length = -1)
    io = IOBuffer()
    HT.write_response!(io, resp_out)
    resp_in = HT._read_response(IOBuffer(take!(io)))
    @test resp_in.status_code == 200
    @test _read_all_body_bytes(resp_in.body) == collect(codeunits("chunked-body"))
    @test HT.get_header(resp_in.trailers, "X-Checksum") == "abc123"
end

@testset "HTTP/1 parse and framing errors" begin
    bad_header = "GET / HTTP/1.1\r\nHost example.com\r\n\r\n"
    @test_throws HT.ParseError HT.read_request(IOBuffer(codeunits(bad_header)))
    bad_cl = "POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello"
    @test_throws HT.ProtocolError HT.read_request(IOBuffer(codeunits(bad_cl)))
    bad_chunk = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nX\r\nabc\r\n0\r\n\r\n"
    bad_resp = HT._read_response(IOBuffer(codeunits(bad_chunk)))
    @test_throws HT.ParseError _read_all_body_bytes(bad_resp.body)
end

@testset "HTTP/1 response body suppression" begin
    raw = "HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\nhello"
    resp = HT._read_response(IOBuffer(codeunits(raw)))
    @test resp.status_code == 204
    @test _read_all_body_bytes(resp.body) == UInt8[]
end

@testset "HTTP/1 status line reason phrase handling" begin
    response = HT.Response(200; body = HT.EmptyBody(), content_length = 0)
    io = IOBuffer()
    HT.write_response!(io, response)
    bytes = take!(io)
    text = String(copy(bytes))
    @test startswith(text, "HTTP/1.1 200 OK\r\n")

    parsed = HT._read_response(IOBuffer(bytes))
    @test parsed.status_code == 200
    @test parsed.reason == "OK"

    # Parser accepts empty reason phrases from peers.
    raw = "HTTP/1.1 299 \r\nContent-Length: 0\r\n\r\n"
    parsed_raw = HT._read_response(IOBuffer(codeunits(raw)))
    @test parsed_raw.status_code == 299
    @test parsed_raw.reason == ""
end
