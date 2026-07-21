using Test
using Reseau

const NC = Reseau.TCP
const IP = Reseau.IOPoll
const SO = Reseau.SocketOps

function _nc_wait_task_done(task::Task, timeout_s::Float64 = 2.0)
    return IP.timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
end

function _read_exact!(conn::NC.Conn, buf::Vector{UInt8})::Int
    read!(conn, buf)
    return length(buf)
end

function _close_quiet!(x)
    x === nothing && return nothing
    try
        close(x)
    catch
    end
    return nothing
end

function _fake_dial_conn(; self_connect::Bool)::NC.Conn
    fd = NC._new_netfd(SO.INVALID_SOCKET)
    fd.laddr = NC.loopback_addr(self_connect ? 5000 : 5001)
    fd.raddr = NC.loopback_addr(5000)
    return NC.Conn(fd)
end

function _readavailable_until_quiet(conn::NC.Conn; timeout_s::Float64 = 2.0, quiet_timeout_s::Float64 = 0.1)::Vector{UInt8}
    out = UInt8[]
    deadline_ns = Int64(time_ns()) + round(Int64, timeout_s * 1.0e9)
    saw_bytes = false
    while true
        remaining_ns = deadline_ns - Int64(time_ns())
        remaining_ns <= 0 && break
        read_timeout_s = saw_bytes ? min(quiet_timeout_s, remaining_ns / 1.0e9) : (remaining_ns / 1.0e9)
        NC.set_read_deadline!(conn, Int64(time_ns()) + round(Int64, read_timeout_s * 1.0e9))
        chunk = try
            readavailable(conn)
        catch err
            ex = err::Exception
            (ex isa IP.DeadlineExceededError || ex isa EOFError) || rethrow(ex)
            break
        end
        isempty(chunk) && break
        append!(out, chunk)
        saw_bytes = true
    end
    return out
end

@testset "TCP phase 4" begin
        @test NC.Conn <: IO
        @test NC.DeadlineExceededError === IP.DeadlineExceededError
        @testset "connect/listen/accept and address snapshots" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            accept_task = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 32)
                laddr = NC.addr(listener)
                @test laddr isa NC.SocketAddrV4
                @test (laddr::NC.SocketAddrV4).port > 0
                accept_task = errormonitor(@async NC.accept(listener))
                pre = _nc_wait_task_done(accept_task, 0.05)
                @test pre == :timed_out
                client = NC.connect(NC.loopback_addr(Int((laddr::NC.SocketAddrV4).port)))
                status = _nc_wait_task_done(accept_task, 2.0)
                @test status != :timed_out
                if status != :timed_out
                    server = fetch(accept_task)
                end
                @test server isa NC.Conn
                local_client = NC.local_addr(client)
                remote_client = NC.remote_addr(client)
                local_server = NC.local_addr(server)
                remote_server = NC.remote_addr(server)
                @test local_client isa NC.SocketAddrV4
                @test remote_client isa NC.SocketAddrV4
                @test local_server isa NC.SocketAddrV4
                @test remote_server isa NC.SocketAddrV4
                @test (remote_client::NC.SocketAddrV4).port == (laddr::NC.SocketAddrV4).port
                @test (local_server::NC.SocketAddrV4).port == (laddr::NC.SocketAddrV4).port
                @test (remote_server::NC.SocketAddrV4).port == (local_client::NC.SocketAddrV4).port
                payload = UInt8[0x61, 0x62, 0x63, 0x64]
                nw = write(client, payload)
                @test nw == length(payload)
                recv_buf = Vector{UInt8}(undef, length(payload))
                nr = _read_exact!(server, recv_buf)
                @test nr == length(payload)
                @test recv_buf == payload
                payload_view = @view payload[2:4]
                @test write(client, payload_view) == length(payload_view)
                recv_view_buf = Vector{UInt8}(undef, length(payload_view))
                @test _read_exact!(server, recv_view_buf) == length(payload_view)
                @test recv_view_buf == collect(payload_view)
                @test write(client, "ok") == 2
                string_buf = Vector{UInt8}(undef, 2)
                @test read!(server, string_buf) === string_buf
                @test String(string_buf) == "ok"
                @test write(client, codeunits("hi")) == 2
                codeunits_buf = Vector{UInt8}(undef, 2)
                @test read!(server, codeunits_buf) === codeunits_buf
                @test String(codeunits_buf) == "hi"
                @test write(client, UInt8[0x6a, 0x6b, 0x6c]) == 3
                view_backing = fill(UInt8(0x00), 5)
                view_buf = @view view_backing[2:4]
                @test read!(server, view_buf) === view_buf
                @test view_backing == UInt8[0x00, 0x6a, 0x6b, 0x6c, 0x00]
                @test write(client, UInt8[0x31, 0x32, 0x33]) == 3
                short_buf = UInt8[]
                @test readbytes!(server, short_buf, 3) == 3
                @test short_buf == UInt8[0x31, 0x32, 0x33]
            finally
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "dial owns Go self-connect and EADDRNOTAVAIL retries" begin
            remote_addr = NC.loopback_addr(5000)

            no_local_calls = Ref(0)
            no_local = NC._dial_socketaddr_with(
                remote_addr,
                nothing,
                Int64(0),
                nothing,
                :tcp,
            ) do _remote, _local, _deadline, _cancel, network
                no_local_calls[] += 1
                @test network === :tcp
                return _fake_dial_conn(; self_connect = no_local_calls[] < 3)
            end
            @test no_local_calls[] == 3
            @test !NC._is_self_connect(no_local)
            close(no_local)

            port_zero_calls = Ref(0)
            port_zero = NC._dial_socketaddr_with(
                remote_addr,
                NC.loopback_addr(0),
                Int64(0),
                nothing,
                :tcp4,
            ) do _remote, _local, _deadline, _cancel, network
                port_zero_calls[] += 1
                @test network === :tcp4
                return _fake_dial_conn(; self_connect = port_zero_calls[] == 1)
            end
            @test port_zero_calls[] == 2
            @test !NC._is_self_connect(port_zero)
            close(port_zero)

            fixed_port_calls = Ref(0)
            fixed_port = NC._dial_socketaddr_with(
                remote_addr,
                NC.loopback_addr(4000),
                Int64(0),
                nothing,
                :tcp,
            ) do _remote, _local, _deadline, _cancel, _network
                fixed_port_calls[] += 1
                return _fake_dial_conn(; self_connect = true)
            end
            @test fixed_port_calls[] == 1
            @test NC._is_self_connect(fixed_port)
            close(fixed_port)

            not_available_calls = Ref(0)
            recovered = NC._dial_socketaddr_with(
                remote_addr,
                nothing,
                Int64(0),
                nothing,
                :tcp,
            ) do _remote, _local, _deadline, _cancel, _network
                not_available_calls[] += 1
                not_available_calls[] < 3 && throw(SystemError("connect", Int(Base.Libc.EADDRNOTAVAIL)))
                return _fake_dial_conn(; self_connect = false)
            end
            @test not_available_calls[] == 3
            close(recovered)
        end
        @testset "connect honors explicit local address binding" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = NC.listen("tcp", "127.0.0.1:0"; backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(@async NC.accept(listener))
                client = NC.connect("tcp", "127.0.0.1:$(Int(laddr.port))"; local_addr = NC.loopback_addr(0))
                @test _nc_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)
                client_local = NC.local_addr(client)::NC.SocketAddrV4
                @test client_local.ip == NC.loopback_addr(0).ip
                @test client_local.port > 0
                mismatch_err = try
                    NC.connect("tcp", "127.0.0.1:$(Int(laddr.port))"; local_addr = NC.loopback_addr6(0))
                    nothing
                catch ex
                    ex
                end
                @test mismatch_err isa Reseau.HostResolvers.OpError
                if mismatch_err isa Reseau.HostResolvers.OpError
                    @test mismatch_err.err isa ArgumentError
                end
            finally
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "readbytes! and read support single-read mode" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(@async NC.accept(listener))
                client = NC.connect(NC.loopback_addr(Int(laddr.port)))
                @test _nc_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)

                first_payload = UInt8[0x41, 0x42]
                @test write(client, first_payload) == length(first_payload)
                first_buf = Vector{UInt8}(undef, 4)
                @test readbytes!(server, first_buf, 4; all = false) == length(first_payload)
                @test first_buf[1:2] == first_payload

                second_payload = UInt8[0x43, 0x44]
                @test write(client, second_payload) == length(second_payload)
                @test read(server, 4; all = false) == second_payload

                third_payload = UInt8[0x45, 0x46]
                @test write(client, third_payload) == length(third_payload)
                grown_buf = fill(UInt8(0x00), 3)
                @test readbytes!(server, grown_buf, 5; all = false) == length(third_payload)
                @test grown_buf[1:2] == third_payload
                @test length(grown_buf) == 3

                fourth_payload = UInt8[0x47, 0x48]
                @test write(client, fourth_payload) == length(fourth_payload)
                view_backing = fill(UInt8(0x00), 5)
                view_buf = @view view_backing[2:4]
                @test readbytes!(server, view_buf, 3; all = false) == length(fourth_payload)
                @test view_backing == UInt8[0x00, 0x47, 0x48, 0x00, 0x00]
            finally
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "read observes data before peer close" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server_task = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                payload = collect(codeunits("HTTP/1.1 302 Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"))
                server_task = errormonitor(@async begin
                    server = NC.accept(listener)
                    try
                        write(server, payload)
                    finally
                        _close_quiet!(server)
                    end
                    return nothing
                end)
                client = NC.connect(NC.loopback_addr(Int(laddr.port)))
                buf = Vector{UInt8}(undef, length(payload))
                @test readbytes!(client, buf, length(buf); all = true) == length(payload)
                @test buf == payload
                @test _nc_wait_task_done(server_task, 2.0) != :timed_out
                wait(server_task)
            finally
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "readavailable observes response after peer half-close" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server_task = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                request = collect(codeunits("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
                response_parts = [
                    collect(codeunits("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")),
                    collect(codeunits("5\r\nhello\r\n")),
                    collect(codeunits("0\r\nX-Trailer: ok\r\n\r\n")),
                ]
                expected = reduce(vcat, response_parts)
                server_task = errormonitor(@async begin
                    server = NC.accept(listener)
                    try
                        buf = Vector{UInt8}(undef, length(request))
                        @test readbytes!(server, buf, length(buf); all = true) == length(request)
                        @test buf == request
                        for part in response_parts
                            @test write(server, part) == length(part)
                        end
                    finally
                        _close_quiet!(server)
                    end
                    return nothing
                end)
                client = NC.connect(NC.loopback_addr(Int(laddr.port)))
                @test write(client, request) == length(request)
                closewrite(client)
                @test _readavailable_until_quiet(client; timeout_s = 2.0, quiet_timeout_s = 0.1) == expected
                @test _nc_wait_task_done(server_task, 2.0) != :timed_out
                wait(server_task)
            finally
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "short read observes data before peer half-close EOF" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server_task = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                request = collect(codeunits("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
                server_task = errormonitor(@async begin
                    server = NC.accept(listener)
                    try
                        buf = Vector{UInt8}(undef, length(request))
                        n = readbytes!(server, buf, length(buf); all = false)
                        @test n == length(request)
                        @test buf[1:n] == request
                        @test eof(server)
                    finally
                        _close_quiet!(server)
                    end
                    return nothing
                end)
                client = NC.connect(NC.loopback_addr(Int(laddr.port)))
                @test write(client, request) == length(request)
                closewrite(client)
                @test _nc_wait_task_done(server_task, 2.0) != :timed_out
                wait(server_task)
            finally
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "repeated half-close requests observe close-delimited responses" begin
            IP.shutdown!()
            listener = nothing
            server_task = nothing
            iterations = Sys.iswindows() ? 120 : 20
            request = collect(codeunits("HEAD /head HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"))
            response = collect(codeunits("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n"))
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 32)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                server_task = errormonitor(@async begin
                    for _ in 1:iterations
                        server = NC.accept(listener)
                        try
                            raw_request = _readavailable_until_quiet(server; timeout_s = 2.0, quiet_timeout_s = 0.02)
                            @test raw_request == request
                            @test write(server, response) == length(response)
                        finally
                            _close_quiet!(server)
                        end
                    end
                    return nothing
                end)
                for _ in 1:iterations
                    client = nothing
                    try
                        client = NC.connect(NC.loopback_addr(Int(laddr.port)))
                        @test write(client, request) == length(request)
                        closewrite(client)
                        @test _readavailable_until_quiet(client; timeout_s = 2.0, quiet_timeout_s = 0.02) == response
                    finally
                        _close_quiet!(client)
                    end
                end
                @test _nc_wait_task_done(server_task, 2.0) != :timed_out
                wait(server_task)
            finally
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "repeated fixed-body requests observe responses before close" begin
            IP.shutdown!()
            listener = nothing
            server_task = nothing
            iterations = Sys.iswindows() ? 120 : 20
            request = collect(codeunits("POST /echo HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\nConnection: close\r\n\r\necho"))
            response = collect(codeunits("HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\necho"))
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 32)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                server_task = errormonitor(@async begin
                    for _ in 1:iterations
                        server = NC.accept(listener)
                        try
                            buf = Vector{UInt8}(undef, length(request))
                            @test readbytes!(server, buf, length(buf); all = true) == length(request)
                            @test buf == request
                            @test write(server, response) == length(response)
                        finally
                            _close_quiet!(server)
                        end
                    end
                    return nothing
                end)
                for _ in 1:iterations
                    client = nothing
                    try
                        client = NC.connect(NC.loopback_addr(Int(laddr.port)))
                        @test write(client, request) == length(request)
                        @test _readavailable_until_quiet(client; timeout_s = 2.0, quiet_timeout_s = 0.02) == response
                    finally
                        _close_quiet!(client)
                    end
                end
                @test _nc_wait_task_done(server_task, 2.0) != :timed_out
                wait(server_task)
            finally
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "show methods summarize TCP endpoints" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)
                accept_task = errormonitor(@async NC.accept(listener))
                client = NC.connect(NC.loopback_addr(Int((laddr::NC.SocketAddrV4).port)))
                @test _nc_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)

                client_local = NC.local_addr(client)
                client_remote = NC.remote_addr(client)
                server_local = NC.local_addr(server)
                server_remote = NC.remote_addr(server)

                @test repr(listener) == "TCP.Listener($(repr(laddr)), active)"
                @test repr(client) == "TCP.Conn($(repr(client_local)) => $(repr(client_remote)), open)"
                @test repr(server) == "TCP.Conn($(repr(server_local)) => $(repr(server_remote)), open)"

                close(client)
                close(server)
                close(listener)

                @test repr(client) == "TCP.Conn($(repr(client_local)) => $(repr(client_remote)), closed)"
                @test repr(server) == "TCP.Conn($(repr(server_local)) => $(repr(server_remote)), closed)"
                @test repr(listener) == "TCP.Listener($(repr(laddr)), closed)"
            finally
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "connected sockets set TCP_NODELAY and SO_KEEPALIVE defaults" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(@async NC.accept(listener))
                client = NC.connect(NC.loopback_addr(Int(laddr.port)))
                @test _nc_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)
                @test SO.get_sockopt_int(client.fd.pfd.sysfd, SO.IPPROTO_TCP, SO.TCP_NODELAY) != 0
                @test SO.get_sockopt_int(server.fd.pfd.sysfd, SO.IPPROTO_TCP, SO.TCP_NODELAY) != 0
                @test SO.get_sockopt_int(client.fd.pfd.sysfd, SO.SOL_SOCKET, SO.SO_KEEPALIVE) != 0
                @test SO.get_sockopt_int(server.fd.pfd.sysfd, SO.SOL_SOCKET, SO.SO_KEEPALIVE) != 0
            finally
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "refused connect surfaces connect syscall error" begin
            IP.shutdown!()
            listener = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)
                port = Int((laddr::NC.SocketAddrV4).port)
                close(listener)
                listener = nothing
                err = try
                    NC.connect(NC.loopback_addr(port))
                    nothing
                catch ex
                    ex
                end
                @test err isa SystemError
                if err isa SystemError
                    @test err.errnum == Int(Base.Libc.ECONNREFUSED) || err.errnum == Int(Base.Libc.ETIMEDOUT)
                end
            finally
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "accept unblocks on listener close" begin
            IP.shutdown!()
            listener = nothing
            accept_task = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                accept_task = errormonitor(Threads.@spawn begin
                    try
                        NC.accept(listener)
                        return :ok
                    catch err
                        return err
                    end
                end)
                pre = _nc_wait_task_done(accept_task, 0.05)
                @test pre == :timed_out
                close(listener)
                listener = nothing
                status = _nc_wait_task_done(accept_task, 2.0)
                @test status != :timed_out
                if status != :timed_out
                    err = fetch(accept_task)
                    @test err isa IP.NetClosingError
                end
            finally
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "read deadline timeout and reset through Conn" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)
                accept_task = errormonitor(@async NC.accept(listener))
                client = NC.connect(NC.loopback_addr(Int((laddr::NC.SocketAddrV4).port)))
                status = _nc_wait_task_done(accept_task, 2.0)
                @test status != :timed_out
                server = fetch(accept_task)
                NC.set_read_deadline!(server, time_ns() + 30_000_000)
                @test_throws NC.DeadlineExceededError read!(server, Vector{UInt8}(undef, 1))
                NC.set_read_deadline!(server, Int64(0))
                @test write(client, UInt8[0x77]) == 1
                recv_buf = Vector{UInt8}(undef, 1)
                @test read!(server, recv_buf) === recv_buf
                @test recv_buf[1] == 0x77
            finally
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "combined deadline applies to both read and write state" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(@async NC.accept(listener))
                client = NC.connect(NC.loopback_addr(Int(laddr.port)))
                @test _nc_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)
                pfd = server.fd.pfd
                future_deadline = Int64(time_ns()) + Int64(5_000_000_000)
                NC.set_deadline!(server, future_deadline)
                @test (@atomic :acquire pfd.pd.rd_ns) == future_deadline
                @test (@atomic :acquire pfd.pd.wd_ns) == future_deadline
                NC.set_deadline!(server, Int64(time_ns()) + Int64(30_000_000))
                rseq = @atomic :acquire pfd.pd.rseq
                wseq = @atomic :acquire pfd.pd.wseq
                IP.deadline_fire!(pfd.pd, IP.PollMode.READWRITE, rseq, wseq)
                @test IP._check_error(pfd.pd, IP.PollMode.READ) == Int32(2)
                @test IP._check_error(pfd.pd, IP.PollMode.WRITE) == Int32(2)
                NC.set_deadline!(server, Int64(0))
                @test IP._check_error(pfd.pd, IP.PollMode.READ) == Int32(0)
                @test IP._check_error(pfd.pd, IP.PollMode.WRITE) == Int32(0)
            finally
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "listener deadline, open state, and local_addr alias" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                @test isopen(listener)
                @test NC.local_addr(listener) == laddr

                NC.set_deadline!(listener, Int64(time_ns()) - Int64(1))
                @test_throws NC.DeadlineExceededError NC.accept(listener)

                NC.set_deadline!(listener, Int64(0))
                accept_task = errormonitor(@async begin
                    try
                        return NC.accept(listener)
                    catch err
                        return err
                    end
                end)
                @test _nc_wait_task_done(accept_task, 0.05) == :timed_out
                client = NC.connect(NC.loopback_addr(Int(laddr.port)))
                @test _nc_wait_task_done(accept_task, 2.0) != :timed_out
                server_result = fetch(accept_task)
                server_result isa Exception && throw(server_result)
                server = server_result
                @test server isa NC.Conn

                @test close(listener) === nothing
                @test !isopen(listener)
                @test close(listener) === nothing
            finally
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "blocked read unblocks on conn close and close stays idempotent" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            read_task = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)
                accept_task = errormonitor(@async NC.accept(listener))
                client = NC.connect(NC.loopback_addr(Int((laddr::NC.SocketAddrV4).port)))
                status = _nc_wait_task_done(accept_task, 2.0)
                @test status != :timed_out
                server = fetch(accept_task)
                read_task = errormonitor(Threads.@spawn begin
                    try
                        read!(server, Vector{UInt8}(undef, 1))
                        return :ok
                    catch err
                        return err
                    end
                end)
                pre = _nc_wait_task_done(read_task, 0.05)
                @test pre == :timed_out
                @test close(server) === nothing
                @test close(server) === nothing
                done = _nc_wait_task_done(read_task, 2.0)
                @test done != :timed_out
                if done != :timed_out
                    err = fetch(read_task)
                    @test err isa IP.NetClosingError
                end
                @test close(listener) === nothing
                @test close(listener) === nothing
            finally
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "EOF and empty reads participate in FD read ownership" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            eof_task = nothing
            read_lock_held = false
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(@async NC.accept(listener))
                client = NC.connect(NC.loopback_addr(Int(laddr.port)))
                @test _nc_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)

                empty = UInt8[]
                @test read!(server, empty) === empty
                @test readbytes!(server, empty, 0) == 0

                IP._fd_read_lock!(server.fd.pfd)
                read_lock_held = true
                eof_task = errormonitor(Threads.@spawn begin
                    try
                        return eof(server)
                    catch err
                        return err
                    end
                end)
                @test _nc_wait_task_done(eof_task, 0.05) == :timed_out
                @test write(client, UInt8[0x5a]) == 1
                IP._fd_read_unlock!(server.fd.pfd)
                read_lock_held = false
                @test _nc_wait_task_done(eof_task, 2.0) != :timed_out
                @test fetch(eof_task) === false

                close(server)
                @test_throws IP.NetClosingError read!(server, UInt8[])
                @test_throws IP.NetClosingError readbytes!(server, UInt8[], 0)
            finally
                read_lock_held && IP._fd_read_unlock!(server.fd.pfd)
                eof_task isa Task && !istaskdone(eof_task) && wait(eof_task)
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "close state publishes before descriptor destruction" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            close_task = nothing
            read_lock_held = false
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(@async NC.accept(listener))
                client = NC.connect(NC.loopback_addr(Int(laddr.port)))
                @test _nc_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)

                IP._fd_read_lock!(server.fd.pfd)
                read_lock_held = true
                close_task = errormonitor(Threads.@spawn close(server))
                @test IP.timedwait(
                    () -> IP._fdlock_closing(server.fd.pfd.fdlock),
                    2.0;
                    pollint = 0.001,
                ) != :timed_out
                @test !isopen(server)
                @test IP._is_valid_fd(server.fd.pfd.sysfd)
                @test _nc_wait_task_done(close_task, 0.05) == :timed_out

                IP._fd_read_unlock!(server.fd.pfd)
                read_lock_held = false
                @test _nc_wait_task_done(close_task, 2.0) != :timed_out
                @test fetch(close_task) === nothing
                @test server.fd.pfd.sysfd == IP.INVALID_FD
            finally
                read_lock_held && IP._fd_read_unlock!(server.fd.pfd)
                close_task isa Task && !istaskdone(close_task) && wait(close_task)
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "concurrent EOF and read operations serialize" begin
            iterations = Threads.nthreads() > 1 ? 64 : 8
            for _ in 1:iterations
                IP.shutdown!()
                listener = nothing
                client = nothing
                server = nothing
                eof_task = nothing
                read_task = nothing
                try
                    listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                    laddr = NC.addr(listener)::NC.SocketAddrV4
                    accept_task = errormonitor(@async NC.accept(listener))
                    client = NC.connect(NC.loopback_addr(Int(laddr.port)))
                    @test _nc_wait_task_done(accept_task, 2.0) != :timed_out
                    server = fetch(accept_task)

                    eof_task = errormonitor(Threads.@spawn eof(server))
                    read_task = errormonitor(Threads.@spawn begin
                        byte = Vector{UInt8}(undef, 1)
                        read!(server, byte)
                        return byte[1]
                    end)
                    @test write(client, UInt8[0xa5]) == 1
                    closewrite(client)
                    @test _nc_wait_task_done(eof_task, 2.0) != :timed_out
                    @test _nc_wait_task_done(read_task, 2.0) != :timed_out
                    @test fetch(eof_task) isa Bool
                    @test fetch(read_task) == 0xa5
                finally
                    eof_task isa Task && !istaskdone(eof_task) && wait(eof_task)
                    read_task isa Task && !istaskdone(read_task) && wait(read_task)
                    _close_quiet!(server)
                    _close_quiet!(client)
                    _close_quiet!(listener)
                    IP.shutdown!()
                end
            end
        end
        @testset "FD lifecycle uses explicit close" begin
            IP.shutdown!()
            fd = nothing
            try
                fd = NC.open_tcp_fd!()
                @test IP._is_valid_fd(fd.pfd.sysfd)
                sysfd_before = fd.pfd.sysfd
                finalize(fd)
                @test fd.pfd.sysfd == sysfd_before
                close(fd)
                @test fd.pfd.sysfd == IP.INVALID_FD
            finally
                _close_quiet!(fd)
                IP.shutdown!()
            end
        end
        @testset "TCP half-close and tuning controls" begin
            IP.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(@async NC.accept(listener))
                client = NC.connect(NC.loopback_addr(Int(laddr.port)))
                @test _nc_wait_task_done(accept_task, 2.0) != :timed_out
                server = fetch(accept_task)
                NC.set_nodelay!(client, false)
                @test SO.get_sockopt_int(client.fd.pfd.sysfd, SO.IPPROTO_TCP, SO.TCP_NODELAY) == 0
                NC.set_nodelay!(client, true)
                @test SO.get_sockopt_int(client.fd.pfd.sysfd, SO.IPPROTO_TCP, SO.TCP_NODELAY) != 0
                NC.set_keepalive!(client, false)
                @test SO.get_sockopt_int(client.fd.pfd.sysfd, SO.SOL_SOCKET, SO.SO_KEEPALIVE) == 0
                NC.set_keepalive!(client, true)
                @test SO.get_sockopt_int(client.fd.pfd.sysfd, SO.SOL_SOCKET, SO.SO_KEEPALIVE) != 0
                @test NC.closeread(client) === nothing
                closewrite(client)
                NC.set_read_deadline!(server, time_ns() + 1_000_000_000)
                @test eof(server)
                @test_throws EOFError read!(server, Vector{UInt8}(undef, 1))

                close(client)
                @test_throws IP.NetClosingError NC.set_nodelay!(client, true)
                @test_throws IP.NetClosingError NC.set_keepalive!(client, true)
                @test_throws IP.NetClosingError NC.closeread(client)
                @test_throws IP.NetClosingError closewrite(client)
            finally
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "TCP controls race close without raw-descriptor errors" begin
            for _ in 1:16
                IP.shutdown!()
                listener = nothing
                client = nothing
                server = nothing
                control_tasks = Task[]
                close_task = nothing
                try
                    listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                    laddr = NC.addr(listener)::NC.SocketAddrV4
                    accept_task = errormonitor(@async NC.accept(listener))
                    client = NC.connect(NC.loopback_addr(Int(laddr.port)))
                    @test _nc_wait_task_done(accept_task, 2.0) != :timed_out
                    server = fetch(accept_task)

                    controls = (
                        () -> NC.set_nodelay!(client, false),
                        () -> NC.set_keepalive!(client, false),
                        () -> NC.closeread(client),
                        () -> closewrite(client),
                    )
                    for control in controls
                        push!(control_tasks, errormonitor(Threads.@spawn begin
                            try
                                control()
                                return nothing
                            catch err
                                return err::Exception
                            end
                        end))
                    end
                    close_task = errormonitor(Threads.@spawn close(client))

                    for task in control_tasks
                        @test _nc_wait_task_done(task, 2.0) != :timed_out
                        result = fetch(task)
                        # Go's internal/poll Shutdown and SetsockoptInt take
                        # shared lifetime references, but do not serialize
                        # control syscalls with each other. The kernel may
                        # therefore reject a control racing a half-close (for
                        # example, Darwin returns EINVAL for SO_KEEPALIVE), and
                        # Go propagates that syscall error. The lifetime
                        # contract here is specifically that close cannot
                        # invalidate and recycle the descriptor underneath the
                        # control operation.
                        if result isa SystemError
                            @test result.errnum != Int(Base.Libc.EBADF)
                        else
                            @test result === nothing || result isa IP.NetClosingError
                        end
                    end
                    @test _nc_wait_task_done(close_task, 2.0) != :timed_out
                    @test fetch(close_task) === nothing
                    @test client.fd.pfd.sysfd == IP.INVALID_FD
                finally
                    for task in control_tasks
                        istaskdone(task) || wait(task)
                    end
                    close_task isa Task && !istaskdone(close_task) && wait(close_task)
                    _close_quiet!(server)
                    _close_quiet!(client)
                    _close_quiet!(listener)
                    IP.shutdown!()
                end
            end
        end
        @testset "IPv6 show output uses compressed form" begin
            @test string(NC.loopback_addr(80)) == "127.0.0.1:80"
            @test repr(NC.loopback_addr(80)) == "127.0.0.1:80"
            @test string(NC.any_addr(0)) == "0.0.0.0:0"
            @test repr(NC.loopback_addr6(443)) == "[::1]:443"
            @test string(NC.loopback_addr6(443)) == "[::1]:443"
            @test repr(NC.any_addr6(0)) == "[::]:0"
            @test string(NC.any_addr6(0)) == "[::]:0"
            doc_addr = NC.SocketAddrV6((
                    0x20, 0x01, 0x0d, 0xb8,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x01,
                ),
                8443,
            )
            @test repr(doc_addr) == "[2001:db8::1]:8443"
            @test string(doc_addr) == "[2001:db8::1]:8443"
            scoped = NC.SocketAddrV6(NC.loopback_addr6(1).ip, 1; scope_id = 7)
            @test repr(scoped) == "[::1%7]:1"
            @test string(scoped) == "[::1%7]:1"
        end
    end
