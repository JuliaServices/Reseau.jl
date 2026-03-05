using Test
using Reseau

const HT = Reseau.HTTP

function _read_all_server_bytes(body::HT.AbstractBody)::Vector{UInt8}
    out = UInt8[]
    buf = Vector{UInt8}(undef, 32)
    while true
        n = HT.body_read!(body, buf)
        n == 0 && break
        append!(out, @view(buf[1:n]))
    end
    return out
end

function _wait_server_addr(server::HT.Server; timeout_s::Float64 = 5.0)::String
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

function _wait_task_done(task::Task; timeout_s::Float64 = 5.0)
    status = timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
    status == :timed_out && error("timed out waiting for task")
    return fetch(task)
end

@testset "HTTP server basic request handling" begin
    seen_targets = String[]
    server = HT.Server(
        address = "127.0.0.1:0",
        handler = request -> begin
            push!(seen_targets, request.target)
            payload = collect(codeunits("echo:" * request.target))
            return HT.Response(200; reason = "OK", body = HT.BytesBody(payload), content_length = length(payload))
        end,
        idle_timeout_ns = 1_000_000_000,
    )
    task = HT.start!(server)
    address = _wait_server_addr(server)
    client = HT.Client(transport = HT.Transport(max_idle_per_host = 4, max_idle_total = 4))
    try
        response1 = HT.get!(client, address, "/one")
        @test response1.status_code == 200
        @test String(_read_all_server_bytes(response1.body)) == "echo:/one"
        response2 = HT.get!(client, address, "/two")
        @test response2.status_code == 200
        @test String(_read_all_server_bytes(response2.body)) == "echo:/two"
        @test seen_targets == ["/one", "/two"]
    finally
        close(client.transport)
        HT.shutdown!(server; force = true)
        _wait_task_done(task)
    end
end

@testset "HTTP server shutdown rejects new requests" begin
    server = HT.Server(
        address = "127.0.0.1:0",
        handler = request -> begin
            _ = request
            return HT.Response(200; reason = "OK", body = HT.BytesBody(UInt8[0x6f, 0x6b]), content_length = 2)
        end,
    )
    task = HT.start!(server)
    address = _wait_server_addr(server)
    client = HT.Client(transport = HT.Transport(max_idle_per_host = 4, max_idle_total = 4))
    try
        response = HT.get!(client, address, "/live")
        @test response.status_code == 200
        @test String(_read_all_server_bytes(response.body)) == "ok"
        HT.shutdown!(server; force = true)
        _wait_task_done(task)
        @test_throws Exception HT.get!(client, address, "/after-shutdown")
    finally
        close(client.transport)
    end
end

@testset "HTTP server closes keep-alive when request body is unread" begin
    server = HT.Server(
        address = "127.0.0.1:0",
        handler = request -> begin
            payload = collect(codeunits("ok:" * request.target))
            return HT.Response(200; reason = "OK", body = HT.BytesBody(payload), content_length = length(payload))
        end,
    )
    task = HT.start!(server)
    address = _wait_server_addr(server)
    client = HT.Client(transport = HT.Transport(max_idle_per_host = 4, max_idle_total = 4))
    try
        req1 = HT.Request("POST", "/one"; host = address, body = HT.BytesBody(collect(codeunits("abc"))), content_length = 3)
        response1 = HT.do!(client, address, req1)
        @test response1.status_code == 200
        @test response1.close
        @test String(_read_all_server_bytes(response1.body)) == "ok:/one"
        @test HT.idle_connection_count(client.transport) == 0

        response2 = HT.get!(client, address, "/two")
        @test response2.status_code == 200
        @test String(_read_all_server_bytes(response2.body)) == "ok:/two"
    finally
        close(client.transport)
        HT.shutdown!(server; force = true)
        _wait_task_done(task)
    end
end
