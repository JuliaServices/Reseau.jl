using Test
using Reseau

const HT = Reseau.HTTP

@testset "HTTP core headers" begin
    @test HT.canonical_header_key("content-type") == "Content-Type"
    @test HT.canonical_header_key("X-CUSTOM-HEADER") == "X-Custom-Header"
    @test HT.canonical_header_key("x-forwarded-for") == "X-Forwarded-For"
    headers = HT.Headers()
    HT.set_header!(headers, "content-type", "application/json")
    HT.add_header!(headers, "x-forwarded-for", "127.0.0.1")
    HT.add_header!(headers, "x-forwarded-for", "127.0.0.2")
    @test HT.has_header(headers, "Content-Type")
    @test HT.get_header(headers, "content-type") == "application/json"
    @test HT.get_headers(headers, "x-forwarded-for") == ["127.0.0.1", "127.0.0.2"]
    @test HT.header_keys(headers) == ["Content-Type", "X-Forwarded-For"]
    copied = HT.get_headers(headers, "x-forwarded-for")
    push!(copied, "127.0.0.3")
    @test HT.get_headers(headers, "x-forwarded-for") == ["127.0.0.1", "127.0.0.2"]
    HT.set_header!(headers, "x-forwarded-for", "127.0.0.9")
    @test HT.get_headers(headers, "x-forwarded-for") == ["127.0.0.9"]
    HT.delete_header!(headers, "x-forwarded-for")
    @test !HT.has_header(headers, "x-forwarded-for")
end

@testset "HTTP core header tokens" begin
    headers = HT.Headers()
    HT.set_header!(headers, "Connection", "keep-alive, Upgrade")
    HT.add_header!(headers, "Connection", " close")
    @test HT.has_header_token(headers, "connection", "upgrade")
    @test HT.has_header_token(headers, "connection", "keep-alive")
    @test HT.has_header_token(headers, "connection", "close")
    @test !HT.has_header_token(headers, "connection", "te")
end

@testset "HTTP core request context" begin
    ctx = HT.RequestContext()
    @test !HT.canceled(ctx)
    @test !HT.expired(ctx)
    HT.set_deadline!(ctx, time_ns() + 50_000_000)
    @test !HT.expired(ctx)
    HT.set_deadline!(ctx, 1)
    @test HT.expired(ctx)
    HT.cancel!(ctx; message = "manual")
    @test HT.canceled(ctx)
end

@testset "HTTP core bodies" begin
    body = HT.BytesBody(UInt8[0x41, 0x42, 0x43])
    dst = Vector{UInt8}(undef, 2)
    n = HT.body_read!(body, dst)
    @test n == 2
    @test dst == UInt8[0x41, 0x42]
    n = HT.body_read!(body, dst)
    @test n == 1
    @test dst[1] == 0x43
    n = HT.body_read!(body, dst)
    @test n == 0
    HT.body_close!(body)
    @test HT.body_closed(body)
    cb_closed = Ref(false)
    cb_reads = Ref(0)
    cb = HT.CallbackBody(
        dst_buf -> begin
            cb_reads[] += 1
            isempty(dst_buf) && return 0
            dst_buf[1] = 0x5a
            return 1
        end,
        () -> begin
            cb_closed[] = true
            return nothing
        end,
    )
    cb_buf = Vector{UInt8}(undef, 1)
    @test HT.body_read!(cb, cb_buf) == 1
    @test cb_buf[1] == 0x5a
    HT.body_close!(cb)
    HT.body_close!(cb)
    @test HT.body_closed(cb)
    @test cb_closed[]
    @test cb_reads[] == 1
end

@testset "HTTP core request/response construction" begin
    headers = HT.Headers()
    HT.set_header!(headers, "content-type", "text/plain")
    req = HT.Request("POST", "/upload"; headers = headers, content_length = 4, host = "localhost")
    res = HT.Response(201; reason = "Created", headers = headers, request = req)
    @test req.method == "POST"
    @test req.target == "/upload"
    @test req.content_length == 4
    @test req.host == "localhost"
    @test HT.get_header(req.headers, "content-type") == "text/plain"
    @test res.status_code == 201
    @test res.reason == "Created"
    @test res.request === req
    HT.set_header!(headers, "content-type", "application/json")
    @test HT.get_header(req.headers, "content-type") == "text/plain"
    @test HT.get_header(res.headers, "content-type") == "text/plain"
end
