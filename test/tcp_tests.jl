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

@testset "TCP phase 4" begin
        @test NC.Conn <: IO
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
                NC.set_read_deadline!(server, time_ns() + 250_000_000)
                first_buf = Vector{UInt8}(undef, 4)
                @test readbytes!(server, first_buf, 4; all = false) == length(first_payload)
                @test first_buf[1:2] == first_payload
                NC.set_read_deadline!(server, Int64(0))

                second_payload = UInt8[0x43, 0x44]
                @test write(client, second_payload) == length(second_payload)
                NC.set_read_deadline!(server, time_ns() + 250_000_000)
                @test read(server, 4; all = false) == second_payload
                NC.set_read_deadline!(server, Int64(0))

                third_payload = UInt8[0x45, 0x46]
                @test write(client, third_payload) == length(third_payload)
                NC.set_read_deadline!(server, time_ns() + 250_000_000)
                grown_buf = fill(UInt8(0x00), 3)
                @test readbytes!(server, grown_buf, 5; all = false) == length(third_payload)
                @test grown_buf[1:2] == third_payload
                @test length(grown_buf) == 3
                NC.set_read_deadline!(server, Int64(0))

                fourth_payload = UInt8[0x47, 0x48]
                @test write(client, fourth_payload) == length(fourth_payload)
                NC.set_read_deadline!(server, time_ns() + 250_000_000)
                view_backing = fill(UInt8(0x00), 5)
                view_buf = @view view_backing[2:4]
                @test readbytes!(server, view_buf, 3; all = false) == length(fourth_payload)
                @test view_backing == UInt8[0x00, 0x47, 0x48, 0x00, 0x00]
                NC.set_read_deadline!(server, Int64(0))
            finally
                _close_quiet!(server)
                _close_quiet!(client)
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
                @test_throws IP.DeadlineExceededError read!(server, Vector{UInt8}(undef, 1))
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
                IP.sleep(0.06)
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
        @testset "blocked read unblocks on conn close and repeated close errors" begin
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
                close(server)
                @test_throws IP.NetClosingError close(server)
                done = _nc_wait_task_done(read_task, 2.0)
                @test done != :timed_out
                if done != :timed_out
                    err = fetch(read_task)
                    @test err isa IP.NetClosingError
                end
                close(listener)
                @test_throws IP.NetClosingError close(listener)
            finally
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "FD lifecycle uses explicit close" begin
            IP.shutdown!()
            fd = nothing
            try
                fd = NC.open_tcp_fd!()
                @test fd.pfd.sysfd >= 0
                sysfd_before = fd.pfd.sysfd
                finalize(fd)
                @test fd.pfd.sysfd == sysfd_before
                close(fd)
                @test fd.pfd.sysfd == Cint(-1)
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
            finally
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                IP.shutdown!()
            end
        end
        @testset "IPv6 show output uses compressed form" begin
            @test repr(NC.loopback_addr6(443)) == "[::1]:443"
            @test repr(NC.any_addr6(0)) == "[::]:0"
            doc_addr = NC.SocketAddrV6((
                    0x20, 0x01, 0x0d, 0xb8,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x01,
                ),
                8443,
            )
            @test repr(doc_addr) == "[2001:db8::1]:8443"
            scoped = NC.SocketAddrV6(NC.loopback_addr6(1).ip, 1; scope_id = 7)
            @test repr(scoped) == "[::1%7]:1"
        end
    end
