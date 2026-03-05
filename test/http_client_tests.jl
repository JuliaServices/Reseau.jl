using Test
using Reseau

const HT = Reseau.HTTP
const NC = Reseau.TCP
const ND = Reseau.HostResolvers

function _read_all_body_bytes_client(body::HT.AbstractBody)::Vector{UInt8}
    out = UInt8[]
    buf = Vector{UInt8}(undef, 32)
    while true
        n = HT.body_read!(body, buf)
        n == 0 && break
        append!(out, @view(buf[1:n]))
    end
    return out
end

function _write_all_tcp_client!(conn::NC.Conn, bytes::Vector{UInt8})::Nothing
    total = 0
    while total < length(bytes)
        n = write(conn, bytes[(total + 1):end])
        n > 0 || error("expected write progress")
        total += n
    end
    return nothing
end

function _send_response_client!(conn::NC.Conn, request::HT.Request; status::Int = 200, reason::String = "OK", body_text::String = "", headers::HT.Headers = HT.Headers(), close_conn::Bool = false)::Nothing
    payload = collect(codeunits(body_text))
    response = HT.Response(
        status;
        reason = reason,
        headers = headers,
        body = HT.BytesBody(payload),
        content_length = length(payload),
        close = close_conn,
        request = request,
    )
    io = IOBuffer()
    HT.write_response!(io, response)
    _write_all_tcp_client!(conn, take!(io))
    return nothing
end

function _wait_task_client!(task::Task; timeout_s::Float64 = 5.0)
    status = timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
    status == :timed_out && error("timed out waiting for server task")
    fetch(task)
    return nothing
end

@testset "HTTP client redirect rewrites method" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    seen_methods = String[]
    seen_targets = String[]
    redirected_content_type = Ref{Union{Nothing, String}}(nothing)
    server_task = errormonitor(Threads.@spawn begin
        conn1 = NC.accept!(listener)
        try
            req1 = HT.read_request(HT._ConnReader(conn1))
            push!(seen_methods, req1.method)
            push!(seen_targets, req1.target)
            headers1 = HT.Headers()
            HT.set_header!(headers1, "Location", "/final")
            HT.set_header!(headers1, "Connection", "close")
            _send_response_client!(conn1, req1; status = 302, reason = "Found", headers = headers1, close_conn = true)
        finally
            try
                NC.close!(conn1)
            catch
            end
        end
        conn2 = NC.accept!(listener)
        try
            req2 = HT.read_request(HT._ConnReader(conn2))
            push!(seen_methods, req2.method)
            push!(seen_targets, req2.target)
            redirected_content_type[] = HT.get_header(req2.headers, "Content-Type")
            _send_response_client!(conn2, req2; body_text = "final")
        finally
            try
                NC.close!(conn2)
            catch
            end
        end
        return nothing
    end)
    client = HT.Client(transport = HT.Transport(max_idle_per_host = 4, max_idle_total = 4))
    try
        headers = HT.Headers()
        HT.set_header!(headers, "Content-Type", "application/json")
        req = HT.Request("POST", "/start"; host = address, headers = headers, body = HT.BytesBody(collect(codeunits("abc"))), content_length = 3)
        resp = HT.do!(client, address, req)
        @test resp.status_code == 200
        @test String(_read_all_body_bytes_client(resp.body)) == "final"
        _wait_task_client!(server_task)
        @test seen_methods == ["POST", "GET"]
        @test seen_targets == ["/start", "/final"]
        @test redirected_content_type[] === nothing
    finally
        close(client.transport)
        try
            NC.close!(listener)
        catch
        end
    end
end

@testset "HTTP client 307 does not follow non-replayable body redirect" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    callback_body = HT.CallbackBody(
        dst -> begin
            isempty(dst) && return 0
            dst[1] = UInt8('x')
            return 1
        end,
        () -> nothing,
    )
    seen_methods = String[]
    server_task = errormonitor(Threads.@spawn begin
        conn = NC.accept!(listener)
        try
            req = HT.read_request(HT._ConnReader(conn))
            push!(seen_methods, req.method)
            _ = _read_all_body_bytes_client(req.body)
            headers = HT.Headers()
            HT.set_header!(headers, "Location", "/final")
            HT.set_header!(headers, "Connection", "close")
            _send_response_client!(conn, req; status = 307, reason = "Temporary Redirect", headers = headers, body_text = "redirect", close_conn = true)
        finally
            try
                NC.close!(conn)
            catch
            end
        end
        return nothing
    end)
    client = HT.Client(transport = HT.Transport(max_idle_per_host = 4, max_idle_total = 4))
    try
        req = HT.Request("POST", "/start"; host = address, body = callback_body, content_length = 1)
        resp = HT.do!(client, address, req)
        @test resp.status_code == 307
        @test String(_read_all_body_bytes_client(resp.body)) == "redirect"
        _wait_task_client!(server_task)
        @test seen_methods == ["POST"]
    finally
        close(client.transport)
        try
            NC.close!(listener)
        catch
        end
    end
end

@testset "HTTP client redirect referer behavior" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    seen_referer = Ref{Union{Nothing, String}}(nothing)
    server_task = errormonitor(Threads.@spawn begin
        conn1 = NC.accept!(listener)
        try
            req1 = HT.read_request(HT._ConnReader(conn1))
            headers1 = HT.Headers()
            HT.set_header!(headers1, "Location", "/next")
            HT.set_header!(headers1, "Connection", "close")
            _send_response_client!(conn1, req1; status = 302, reason = "Found", headers = headers1, close_conn = true)
        finally
            try
                NC.close!(conn1)
            catch
            end
        end
        conn2 = NC.accept!(listener)
        try
            req2 = HT.read_request(HT._ConnReader(conn2))
            seen_referer[] = HT.get_header(req2.headers, "Referer")
            _send_response_client!(conn2, req2; body_text = "ok", close_conn = true)
        finally
            try
                NC.close!(conn2)
            catch
            end
        end
        return nothing
    end)
    client = HT.Client(transport = HT.Transport(max_idle_per_host = 4, max_idle_total = 4))
    try
        req = HT.Request("GET", "/start"; host = address, body = HT.EmptyBody(), content_length = 0)
        resp = HT.do!(client, address, req)
        @test resp.status_code == 200
        @test String(_read_all_body_bytes_client(resp.body)) == "ok"
        _wait_task_client!(server_task)
        @test seen_referer[] == "http://$(address)/start"
    finally
        close(client.transport)
        try
            NC.close!(listener)
        catch
        end
    end
    @test HT._redirect_referer(true, "example.com:443", "/secure", false, nothing) === nothing
    @test HT._redirect_referer(false, "example.com:80", "/plain", false, "custom-ref") == "custom-ref"
end

@testset "HTTP client redirect strips sensitive headers for untrusted hosts" begin
    listener1 = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    listener2 = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr1 = NC.addr(listener1)::NC.SocketAddrV4
    laddr2 = NC.addr(listener2)::NC.SocketAddrV4
    address1 = ND.join_host_port("127.0.0.1", Int(laddr1.port))
    address2 = ND.join_host_port("localhost", Int(laddr2.port))
    seen_auth_hop1 = Ref{Union{Nothing, String}}(nothing)
    seen_cookie_hop1 = Ref{Union{Nothing, String}}(nothing)
    seen_auth_hop2 = Ref{Union{Nothing, String}}(nothing)
    seen_cookie_hop2 = Ref{Union{Nothing, String}}(nothing)
    server_task1 = errormonitor(Threads.@spawn begin
        conn = NC.accept!(listener1)
        try
            req = HT.read_request(HT._ConnReader(conn))
            seen_auth_hop1[] = HT.get_header(req.headers, "Authorization")
            seen_cookie_hop1[] = HT.get_header(req.headers, "Cookie")
            headers = HT.Headers()
            HT.set_header!(headers, "Location", "http://$(address2)/final")
            HT.set_header!(headers, "Connection", "close")
            _send_response_client!(conn, req; status = 302, reason = "Found", headers = headers, close_conn = true)
        finally
            try
                NC.close!(conn)
            catch
            end
        end
        return nothing
    end)
    server_task2 = errormonitor(Threads.@spawn begin
        conn = NC.accept!(listener2)
        try
            req = HT.read_request(HT._ConnReader(conn))
            seen_auth_hop2[] = HT.get_header(req.headers, "Authorization")
            seen_cookie_hop2[] = HT.get_header(req.headers, "Cookie")
            _send_response_client!(conn, req; body_text = "ok", close_conn = true)
        finally
            try
                NC.close!(conn)
            catch
            end
        end
        return nothing
    end)
    client = HT.Client(transport = HT.Transport(max_idle_per_host = 4, max_idle_total = 4), jar = nothing)
    try
        headers = HT.Headers()
        HT.set_header!(headers, "Authorization", "Bearer abc")
        HT.set_header!(headers, "Cookie", "session=abc")
        req = HT.Request("GET", "/start"; host = address1, headers = headers, body = HT.EmptyBody(), content_length = 0)
        response = HT.do!(client, address1, req)
        @test response.status_code == 200
        @test String(_read_all_body_bytes_client(response.body)) == "ok"
        _wait_task_client!(server_task1)
        _wait_task_client!(server_task2)
        @test seen_auth_hop1[] == "Bearer abc"
        @test seen_cookie_hop1[] == "session=abc"
        @test seen_auth_hop2[] === nothing
        @test seen_cookie_hop2[] === nothing
    finally
        close(client.transport)
        try
            NC.close!(listener1)
        catch
        end
        try
            NC.close!(listener2)
        catch
        end
    end
end

@testset "HTTP client redirect trusted host matching helper" begin
    @test HT._should_copy_sensitive_headers_on_redirect("foo.com:80", "foo.com:443")
    @test HT._should_copy_sensitive_headers_on_redirect("foo.com:80", "sub.foo.com:443")
    @test !HT._should_copy_sensitive_headers_on_redirect("foo.com:80", "bar.com:443")
end

@testset "HTTP client redirect absolute location default ports" begin
    address_h2, secure_h2, target_h2 = HT._resolve_redirect_target("origin.com:443", true, "https://www.google.com/search", "/")
    @test address_h2 == "www.google.com:443"
    @test secure_h2
    @test target_h2 == "/search"

    address_h1, secure_h1, target_h1 = HT._resolve_redirect_target("origin.com:80", false, "http://example.com/next", "/")
    @test address_h1 == "example.com:80"
    @test !secure_h1
    @test target_h1 == "/next"

    address_rel, secure_rel, target_rel = HT._resolve_redirect_target("origin.com:443", true, "//cdn.example.com/assets", "/")
    @test address_rel == "cdn.example.com:443"
    @test secure_rel
    @test target_rel == "/assets"
end

@testset "HTTP client cookie jar round-trip" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    cookie_header_seen = Ref{Union{Nothing, String}}(nothing)
    server_task = errormonitor(Threads.@spawn begin
        conn1 = NC.accept!(listener)
        try
            req1 = HT.read_request(HT._ConnReader(conn1))
            _ = req1
            headers1 = HT.Headers()
            HT.add_header!(headers1, "Set-Cookie", "session=abc; Path=/")
            HT.set_header!(headers1, "Connection", "close")
            _send_response_client!(conn1, req1; body_text = "set", headers = headers1, close_conn = true)
        finally
            try
                NC.close!(conn1)
            catch
            end
        end
        conn2 = NC.accept!(listener)
        try
            req2 = HT.read_request(HT._ConnReader(conn2))
            cookie_header_seen[] = HT.get_header(req2.headers, "Cookie")
            _send_response_client!(conn2, req2; body_text = "ok")
        finally
            try
                NC.close!(conn2)
            catch
            end
        end
        return nothing
    end)
    client = HT.Client(transport = HT.Transport(max_idle_per_host = 4, max_idle_total = 4), jar = HT.MemoryCookieJar())
    try
        r1 = HT.get!(client, address, "/set")
        @test String(_read_all_body_bytes_client(r1.body)) == "set"
        r2 = HT.get!(client, address, "/check")
        @test String(_read_all_body_bytes_client(r2.body)) == "ok"
        _wait_task_client!(server_task)
        @test cookie_header_seen[] == "session=abc"
    finally
        close(client.transport)
        try
            NC.close!(listener)
        catch
        end
    end
end

@testset "HTTP client trace callbacks" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    server_task = errormonitor(Threads.@spawn begin
        conn = NC.accept!(listener)
        try
            req = HT.read_request(HT._ConnReader(conn))
            _send_response_client!(conn, req; body_text = "trace")
        finally
            try
                NC.close!(conn)
            catch
            end
        end
        return nothing
    end)
    events = Symbol[]
    trace = HT.ClientTrace(
        on_get_conn = (address, secure) -> begin
            _ = (address, secure)
            push!(events, :get_conn)
            return nothing
        end,
        on_got_conn = (address, secure) -> begin
            _ = (address, secure)
            push!(events, :got_conn)
            return nothing
        end,
        on_wrote_request = (method, target) -> begin
            _ = (method, target)
            push!(events, :wrote_request)
            return nothing
        end,
        on_got_first_response_byte = status -> begin
            _ = status
            push!(events, :got_first_response_byte)
            return nothing
        end,
    )
    client = HT.Client(transport = HT.Transport(max_idle_per_host = 4, max_idle_total = 4), trace = trace)
    try
        response = HT.get!(client, address, "/trace")
        @test response.status_code == 200
        @test String(_read_all_body_bytes_client(response.body)) == "trace"
        _wait_task_client!(server_task)
        @test events == [:get_conn, :got_conn, :wrote_request, :got_first_response_byte]
    finally
        close(client.transport)
        try
            NC.close!(listener)
        catch
        end
    end
end

@testset "HTTP high-level request interface" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    base_url = "http://$(address)"
    seen_targets = String[]
    seen_header = Ref{Union{Nothing, String}}(nothing)
    seen_auth = Ref{Union{Nothing, String}}(nothing)
    server_task = errormonitor(Threads.@spawn begin
        for _ in 1:7
            conn = NC.accept!(listener)
            try
                req = HT.read_request(HT._ConnReader(conn))
                push!(seen_targets, req.target)
                if req.target == "/hello"
                    _send_response_client!(conn, req; body_text = "hello", close_conn = true)
                elseif startswith(req.target, "/query?")
                    _send_response_client!(conn, req; body_text = req.target, close_conn = true)
                elseif req.target == "/echo"
                    seen_header[] = HT.get_header(req.headers, "X-Token")
                    payload = String(_read_all_body_bytes_client(req.body))
                    _send_response_client!(conn, req; body_text = payload, close_conn = true)
                elseif startswith(req.target, "/encoded?")
                    _send_response_client!(conn, req; body_text = req.target, close_conn = true)
                elseif req.target == "/auth"
                    seen_auth[] = HT.get_header(req.headers, "Authorization")
                    _send_response_client!(conn, req; body_text = "auth-ok", close_conn = true)
                elseif req.target == "/missing"
                    _send_response_client!(conn, req; status = 404, reason = "Not Found", body_text = "missing", close_conn = true)
                else
                    _send_response_client!(conn, req; status = 500, reason = "Unexpected", body_text = req.target, close_conn = true)
                end
            finally
                try
                    NC.close!(conn)
                catch
                end
            end
        end
        return nothing
    end)
    try
        resp_hello = HT.get("$(base_url)/hello")
        @test resp_hello.status == 200
        @test String(resp_hello.body) == "hello"

        resp_query = HT.get("$(base_url)/query"; query = Dict("a" => 1, "b" => 2))
        @test resp_query.status == 200
        @test String(resp_query.body) == "/query?a=1&b=2"

        resp_encoded = HT.get("$(base_url)/encoded"; query = Dict("a b" => "c+d", "slash" => "/x"))
        @test resp_encoded.status == 200
        @test String(resp_encoded.body) == "/encoded?a%20b=c%2Bd&slash=%2Fx"

        resp_echo = HT.post("$(base_url)/echo", ["X-Token" => "abc123"], "payload")
        @test resp_echo.status == 200
        @test String(resp_echo.body) == "payload"
        @test seen_header[] == "abc123"

        resp_auth = HT.get("http://alice:secret@$(address)/auth")
        @test resp_auth.status == 200
        @test String(resp_auth.body) == "auth-ok"
        @test seen_auth[] == "Basic YWxpY2U6c2VjcmV0"

        resp_missing = HT.get("$(base_url)/missing"; status_exception = false)
        @test resp_missing.status == 404
        @test String(resp_missing.body) == "missing"

        status_err = try
            HT.get("$(base_url)/missing")
            nothing
        catch err
            err
        end
        @test status_err isa HT.StatusError
        if status_err isa HT.StatusError
            @test status_err.response.status == 404
            @test status_err.response.url == "$(base_url)/missing"
        end

        _wait_task_client!(server_task)
        @test "/hello" in seen_targets
        @test "/echo" in seen_targets
        @test "/query?a=1&b=2" in seen_targets
        @test "/encoded?a%20b=c%2Bd&slash=%2Fx" in seen_targets
        @test "/auth" in seen_targets
    finally
        try
            NC.close!(listener)
        catch
        end
    end
end

@testset "HTTP high-level readtimeout" begin
    listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
    laddr = NC.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    base_url = "http://$(address)"
    server_task = errormonitor(Threads.@spawn begin
        conn = NC.accept!(listener)
        try
            req = HT.read_request(HT._ConnReader(conn))
            _ = req
            sleep(0.20)
        finally
            try
                NC.close!(conn)
            catch
            end
        end
        return nothing
    end)
    try
        err = try
            HT.get("$(base_url)/slow"; readtimeout = 0.05)
            nothing
        catch ex
            ex
        end
        @test err isa Reseau.IOPoll.DeadlineExceededError
        _wait_task_client!(server_task)
    finally
        try
            NC.close!(listener)
        catch
        end
    end
end
