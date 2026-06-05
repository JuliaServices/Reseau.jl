using Test
using Reseau

const SK = Reseau.SOCKS
const NC = Reseau.TCP
const IP = Reseau.IOPoll

struct _SocksRequest
    atyp::UInt8
    host::String
    port::UInt16
end

function _socks_close_quiet!(x)
    x === nothing && return nothing
    try
        close(x)
    catch
    end
    return nothing
end

function _socks_wait_task!(task::Task; timeout_s::Float64 = 2.0)
    status = timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
    status == :timed_out && error("timed out waiting for SOCKS test task")
    fetch(task)
    return nothing
end

function _socks_read_exact!(conn::NC.Conn, n::Integer)::Vector{UInt8}
    count = Int(n)
    buf = Vector{UInt8}(undef, count)
    got = readbytes!(conn, buf, count; all = true)
    got == count || throw(EOFError())
    return buf
end

function _socks_read_greeting!(conn::NC.Conn)::Vector{UInt8}
    header = _socks_read_exact!(conn, 2)
    @test header[1] == 0x05
    nmethods = Int(header[2])
    return _socks_read_exact!(conn, nmethods)
end

function _socks_read_connect_request!(conn::NC.Conn)::_SocksRequest
    prefix = _socks_read_exact!(conn, 4)
    @test prefix[1:3] == UInt8[0x05, 0x01, 0x00]
    atyp = prefix[4]
    if atyp == 0x01
        data = _socks_read_exact!(conn, 6)
        host = string(data[1], ".", data[2], ".", data[3], ".", data[4])
        port = (UInt16(data[5]) << 8) | UInt16(data[6])
        return _SocksRequest(atyp, host, port)
    elseif atyp == 0x03
        len = Int(_socks_read_exact!(conn, 1)[1])
        data = _socks_read_exact!(conn, len + 2)
        host = String(data[1:len])
        port = (UInt16(data[len + 1]) << 8) | UInt16(data[len + 2])
        return _SocksRequest(atyp, host, port)
    elseif atyp == 0x04
        data = _socks_read_exact!(conn, 18)
        ip = (
            data[1], data[2], data[3], data[4],
            data[5], data[6], data[7], data[8],
            data[9], data[10], data[11], data[12],
            data[13], data[14], data[15], data[16],
        )
        port = (UInt16(data[17]) << 8) | UInt16(data[18])
        return _SocksRequest(atyp, NC._format_ipv6(ip), port)
    end
    error("unexpected SOCKS address type $(Int(atyp))")
end

function _socks_write_success!(conn::NC.Conn)::Nothing
    write(conn, UInt8[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    return nothing
end

function _socks_write_success!(conn::NC.Conn, atyp::UInt8, bound_payload::Vector{UInt8})::Nothing
    reply = UInt8[0x05, 0x00, 0x00, atyp]
    append!(reply, bound_payload)
    write(conn, reply)
    return nothing
end

function _socks_with_proxy(server_handler::Function, client_handler::Function)
    IP.shutdown!()
    listener = nothing
    client = nothing
    server_task = nothing
    try
        listener = NC.listen(NC.loopback_addr(0); backlog = 8)
        laddr = NC.addr(listener)::NC.SocketAddrV4
        server_task = errormonitor(Threads.@spawn begin
            conn = NC.accept(listener)
            try
                server_handler(conn)
            finally
                _socks_close_quiet!(conn)
            end
            return nothing
        end)
        client = NC.connect(NC.loopback_addr(Int(laddr.port)))
        client_handler(client)
        _socks_wait_task!(server_task)
    finally
        _socks_close_quiet!(client)
        _socks_close_quiet!(listener)
        if server_task !== nothing && !istaskdone(server_task)
            _socks_wait_task!(server_task; timeout_s = 2.0)
        end
        IP.shutdown!()
    end
    return nothing
end

function _socks_expect_no_proxy_bytes(target::String)::Nothing
    IP.shutdown!()
    listener = nothing
    client = nothing
    server_task = nothing
    try
        listener = NC.listen(NC.loopback_addr(0); backlog = 8)
        laddr = NC.addr(listener)::NC.SocketAddrV4
        server_task = errormonitor(Threads.@spawn begin
            conn = NC.accept(listener)
            try
                NC.set_read_deadline!(conn, Int64(time_ns()) + 50_000_000)
                try
                    read(conn, UInt8)
                    return :saw_byte
                catch err
                    ex = err::Exception
                    ex isa NC.DeadlineExceededError || rethrow(ex)
                    return :no_bytes
                end
            finally
                _socks_close_quiet!(conn)
            end
        end)
        client = NC.connect(NC.loopback_addr(Int(laddr.port)))
        @test_throws SK.TargetAddressError SK.connect!(client, target)
        _socks_wait_task!(server_task)
        @test fetch(server_task) == :no_bytes
    finally
        _socks_close_quiet!(client)
        _socks_close_quiet!(listener)
        if server_task !== nothing && !istaskdone(server_task)
            _socks_wait_task!(server_task; timeout_s = 2.0)
        end
        IP.shutdown!()
    end
    return nothing
end

@testset "SOCKS5 no-auth FQDN connect leaves stream open" begin
    seen = Channel{_SocksRequest}(1)
    _socks_with_proxy(
        conn -> begin
            @test _socks_read_greeting!(conn) == UInt8[0x00]
            write(conn, UInt8[0x05, 0x00])
            req = _socks_read_connect_request!(conn)
            put!(seen, req)
            _socks_write_success!(conn)
            @test String(_socks_read_exact!(conn, 4)) == "ping"
            write(conn, codeunits("pong"))
        end,
        conn -> begin
            bound = SK.connect!(conn, "example.com:443")
            @test string(bound) == "0.0.0.0:0"
            @test write(conn, codeunits("ping")) == 4
            @test String(_socks_read_exact!(conn, 4)) == "pong"
        end,
    )
    req = take!(seen)
    @test req.atyp == 0x03
    @test req.host == "example.com"
    @test req.port == UInt16(443)
end

@testset "SOCKS5 connect encodes IP targets" begin
    for (target, expected_atyp, expected_host, expected_port) in (
            ("127.0.0.1:80", UInt8(0x01), "127.0.0.1", UInt16(80)),
            ("[::1]:443", UInt8(0x04), "::1", UInt16(443)),
        )
        seen = Channel{_SocksRequest}(1)
        _socks_with_proxy(
            conn -> begin
                @test _socks_read_greeting!(conn) == UInt8[0x00]
                write(conn, UInt8[0x05, 0x00])
                put!(seen, _socks_read_connect_request!(conn))
                _socks_write_success!(conn)
            end,
            conn -> begin
                bound = SK.connect!(conn, target)
                @test string(bound) == "0.0.0.0:0"
            end,
        )
        req = take!(seen)
        @test req.atyp == expected_atyp
        @test req.host == expected_host
        @test req.port == expected_port
    end
end

@testset "SOCKS5 username/password authentication" begin
    seen = Channel{_SocksRequest}(1)
    _socks_with_proxy(
        conn -> begin
            @test _socks_read_greeting!(conn) == UInt8[0x00, 0x02]
            write(conn, UInt8[0x05, 0x02])
            auth_header = _socks_read_exact!(conn, 2)
            @test auth_header == UInt8[0x01, 0x04]
            @test String(_socks_read_exact!(conn, 4)) == "user"
            @test _socks_read_exact!(conn, 1) == UInt8[0x04]
            @test String(_socks_read_exact!(conn, 4)) == "pass"
            write(conn, UInt8[0x01, 0x00])
            put!(seen, _socks_read_connect_request!(conn))
            _socks_write_success!(conn)
        end,
        conn -> begin
            bound = SK.connect!(conn, "secure.local:8443"; username = "user", password = "pass")
            @test string(bound) == "0.0.0.0:0"
        end,
    )
    req = take!(seen)
    @test req.atyp == 0x03
    @test req.host == "secure.local"
    @test req.port == UInt16(8443)
end

@testset "SOCKS5 parses bound reply addresses" begin
    cases = (
        (UInt8(0x03), UInt8[0x0b, codeunits("bound.local")..., 0x1f, 0x90], "bound.local:8080"),
        (UInt8(0x04), UInt8[
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x01,
                0x00, 0x35,
            ], "[::1]:53"),
    )
    for (atyp, payload, expected) in cases
        _socks_with_proxy(
            conn -> begin
                @test _socks_read_greeting!(conn) == UInt8[0x00]
                write(conn, UInt8[0x05, 0x00])
                _socks_read_connect_request!(conn)
                _socks_write_success!(conn, atyp, payload)
            end,
            conn -> begin
                bound = SK.connect!(conn, "example.com:80")
                @test string(bound) == expected
            end,
        )
    end
end

@testset "SOCKS5 authentication and reply failures surface typed errors" begin
    _socks_with_proxy(
        conn -> begin
            @test _socks_read_greeting!(conn) == UInt8[0x00]
            write(conn, UInt8[0x05, 0xff])
        end,
        conn -> begin
            @test_throws SK.AuthenticationError SK.connect!(conn, "example.com:80")
        end,
    )

    _socks_with_proxy(
        conn -> begin
            @test _socks_read_greeting!(conn) == UInt8[0x00]
            write(conn, UInt8[0x05, 0x00])
            _socks_read_connect_request!(conn)
            write(conn, UInt8[0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
        end,
        conn -> begin
            err = try
                SK.connect!(conn, "example.com:80")
                nothing
            catch ex
                ex
            end
            @test err isa SK.ReplyError
            if err isa SK.ReplyError
                @test err.code == 0x05
                @test err.message == "connection refused"
            end
        end,
    )
end

@testset "SOCKS5 validates target before proxy I/O" begin
    _socks_expect_no_proxy_bytes("example.com")
    long_host = repeat("a", 256)
    _socks_expect_no_proxy_bytes("$long_host:80")
end

@testset "SOCKS5 handshake observes connection deadline" begin
    _socks_with_proxy(
        conn -> begin
            sleep(0.2)
        end,
        conn -> begin
            deadline_ns = Int64(time_ns()) + 50_000_000
            @test_throws NC.DeadlineExceededError SK.connect!(conn, "example.com:80"; deadline_ns)
        end,
    )
end
