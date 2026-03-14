using Test
using Reseau

const EL = Reseau.EventLoops
const NC = Reseau.TCP
const IP = Reseau.IOPoll
const SO = Reseau.SocketOps

function _nc_wait_task_done(task::Task, timeout_s::Float64 = 2.0)
    return EL.timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
end

function _read_exact!(conn::NC.Conn, buf::Vector{UInt8})::Int
    offset = 0
    while offset < length(buf)
        chunk = Vector{UInt8}(undef, length(buf) - offset)
        n = read!(conn, chunk)
        n > 0 || throw(EOFError())
        copyto!(buf, offset + 1, chunk, 1, n)
        offset += n
    end
    return offset
end

function _close_quiet!(x)
    x === nothing && return nothing
    try
        NC.close!(x)
    catch
    end
    return nothing
end

if !(Sys.isapple() || Sys.islinux())
    @testset "TCP (macOS/Linux only)" begin
        @test true
    end
else
    @testset "TCP phase 4" begin
        @testset "connect/listen/accept and address snapshots" begin
            EL.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            accept_task = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 32)
                laddr = NC.addr(listener)
                @test laddr isa NC.SocketAddrV4
                @test (laddr::NC.SocketAddrV4).port > 0
                accept_task = errormonitor(Threads.@spawn NC.accept!(listener))
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
            finally
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "connected sockets set TCP_NODELAY and SO_KEEPALIVE defaults" begin
            EL.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn NC.accept!(listener))
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
                EL.shutdown!()
            end
        end
        @testset "refused connect surfaces connect syscall error" begin
            EL.shutdown!()
            listener = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)
                port = Int((laddr::NC.SocketAddrV4).port)
                NC.close!(listener)
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
                EL.shutdown!()
            end
        end
        @testset "accept unblocks on listener close" begin
            EL.shutdown!()
            listener = nothing
            accept_task = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                accept_task = errormonitor(Threads.@spawn begin
                    try
                        NC.accept!(listener)
                        return :ok
                    catch err
                        return err
                    end
                end)
                pre = _nc_wait_task_done(accept_task, 0.05)
                @test pre == :timed_out
                NC.close!(listener)
                listener = nothing
                status = _nc_wait_task_done(accept_task, 2.0)
                @test status != :timed_out
                if status != :timed_out
                    err = fetch(accept_task)
                    @test err isa IP.NetClosingError
                end
            finally
                _close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "read deadline timeout and reset through Conn" begin
            EL.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)
                accept_task = errormonitor(Threads.@spawn NC.accept!(listener))
                client = NC.connect(NC.loopback_addr(Int((laddr::NC.SocketAddrV4).port)))
                status = _nc_wait_task_done(accept_task, 2.0)
                @test status != :timed_out
                server = fetch(accept_task)
                NC.set_read_deadline!(server, time_ns() + 30_000_000)
                @test_throws IP.DeadlineExceededError read!(server, Vector{UInt8}(undef, 1))
                NC.set_read_deadline!(server, Int64(0))
                @test write(client, UInt8[0x77]) == 1
                recv_buf = Vector{UInt8}(undef, 1)
                @test read!(server, recv_buf) == 1
                @test recv_buf[1] == 0x77
            finally
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "blocked read unblocks on conn close and repeated close errors" begin
            EL.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            read_task = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)
                accept_task = errormonitor(Threads.@spawn NC.accept!(listener))
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
                NC.close!(server)
                @test_throws IP.NetClosingError NC.close!(server)
                done = _nc_wait_task_done(read_task, 2.0)
                @test done != :timed_out
                if done != :timed_out
                    err = fetch(read_task)
                    @test err isa IP.NetClosingError
                end
                NC.close!(listener)
                @test_throws IP.NetClosingError NC.close!(listener)
            finally
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                EL.shutdown!()
            end
        end
        @testset "FD lifecycle uses explicit close" begin
            EL.shutdown!()
            fd = nothing
            try
                fd = NC.open_tcp_fd!()
                @test fd.pfd.sysfd >= 0
                sysfd_before = fd.pfd.sysfd
                finalize(fd)
                @test fd.pfd.sysfd == sysfd_before
                NC.close!(fd)
                @test fd.pfd.sysfd == Cint(-1)
            finally
                _close_quiet!(fd)
                EL.shutdown!()
            end
        end
        @testset "TCP half-close and tuning controls" begin
            EL.shutdown!()
            listener = nothing
            client = nothing
            server = nothing
            try
                listener = NC.listen(NC.loopback_addr(0); backlog = 8)
                laddr = NC.addr(listener)::NC.SocketAddrV4
                accept_task = errormonitor(Threads.@spawn NC.accept!(listener))
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
                @test NC.close_read!(client) === nothing
                NC.close_write!(client)
                NC.set_read_deadline!(server, time_ns() + 1_000_000_000)
                @test_throws EOFError read!(server, Vector{UInt8}(undef, 1))
            finally
                _close_quiet!(server)
                _close_quiet!(client)
                _close_quiet!(listener)
                EL.shutdown!()
            end
        end
    end
end
