using Test
using Reseau

const EL = Reseau.EventLoops
const SO = Reseau.SocketOps

function _socketpair(sotype::Cint = SO.SOCK_STREAM)::Tuple{Cint, Cint}
    fds = Vector{Cint}(undef, 2)
    ret = @ccall socketpair(SO.AF_UNIX::Cint, sotype::Cint, Cint(0)::Cint, pointer(fds)::Ptr{Cint})::Cint
    ret == 0 || throw(SystemError("socketpair", Int(Base.Libc.errno())))
    return fds[1], fds[2]
end

function _close_fd_raw(fd::Cint)
    fd < 0 && return nothing
    @ccall close(fd::Cint)::Cint
    return nothing
end

function _accept_with_retry(listener::Cint)::Tuple{Cint, SO.AcceptPeer}
    for _ in 1:5000
        accepted, peer, errno = SO.try_accept_socket(listener)
        accepted != -1 && return accepted, peer
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == Int32(Base.Libc.EWOULDBLOCK) && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("accept", Int(errno)))
    end
    throw(ArgumentError("timed out waiting for accepted socket"))
end

function _wait_connect_ready!(fd::Cint)
    registration = EL.register!(fd; mode = EL.PollMode.WRITE)
    try
        EL.pollwait!(registration.write_waiter)
    finally
        EL.deregister!(fd)
    end
    return nothing
end

if !(Sys.isapple() || Sys.islinux())
    @testset "SocketOps (macOS/Linux only)" begin
        @test true
    end
else
    @testset "SocketOps phase 3" begin
        @testset "open sets cloexec and nonblocking" begin
            fd = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
            try
                @test SO.fd_is_cloexec(fd)
                @test SO.fd_is_nonblocking(fd)
            finally
                SO.close_socket_nothrow(fd)
            end
        end
        @testset "close reports only invalid descriptor errors" begin
            @test SO.close_socket_nothrow(Cint(-1)) == Int32(Base.Libc.EBADF)
            @test_throws SystemError SO.close_socket(Cint(-1))
        end
        @testset "read/write and recv/send wrappers" begin
            fd0, fd1 = _socketpair(SO.SOCK_STREAM)
            d0 = Cint(-1)
            d1 = Cint(-1)
            try
                d0 = fd0
                d1 = fd1
                SO.set_nonblocking!(d0, false)
                SO.set_nonblocking!(d1, false)
                payload = UInt8[0x61, 0x62, 0x63]
                nw = GC.@preserve payload SO.write_once!(d0, pointer(payload), Csize_t(length(payload)))
                @test nw == Cssize_t(length(payload))
                recv_buf = Vector{UInt8}(undef, 3)
                nr = GC.@preserve recv_buf SO.read_once!(d1, pointer(recv_buf), Csize_t(length(recv_buf)))
                @test nr == Cssize_t(3)
                @test recv_buf == payload
                iov = Ref(SO.IOVec(pointer(payload), Csize_t(length(payload))))
                send_hdr = Ref(SO.MsgHdr(C_NULL, SO.SockLen(0), Base.unsafe_convert(Ptr{SO.IOVec}, iov), Cint(1), C_NULL, SO.SockLen(0), Cint(0)))
                sent = GC.@preserve payload iov send_hdr SO.send_msg!(d0, send_hdr)
                @test sent == Cssize_t(length(payload))
                recv_msg_buf = Vector{UInt8}(undef, 3)
                recv_iov = Ref(SO.IOVec(pointer(recv_msg_buf), Csize_t(length(recv_msg_buf))))
                recv_hdr = Ref(SO.MsgHdr(C_NULL, SO.SockLen(0), Base.unsafe_convert(Ptr{SO.IOVec}, recv_iov), Cint(1), C_NULL, SO.SockLen(0), Cint(0)))
                recvd = GC.@preserve recv_msg_buf recv_iov recv_hdr SO.recv_msg!(d1, recv_hdr)
                @test recvd == Cssize_t(length(payload))
                @test recv_msg_buf == payload
            finally
                _close_fd_raw(d0)
                _close_fd_raw(d1)
            end
            fd2, fd3 = _socketpair(SO.SOCK_DGRAM)
            d2 = Cint(-1)
            d3 = Cint(-1)
            try
                d2 = fd2
                d3 = fd3
                SO.set_nonblocking!(d2, false)
                SO.set_nonblocking!(d3, false)
                msg = UInt8[0x41, 0x42]
                sn = GC.@preserve msg SO.send_to!(d2, pointer(msg), Csize_t(length(msg)), Cint(0), C_NULL, SO.SockLen(0))
                @test sn == Cssize_t(length(msg))
                got = Vector{UInt8}(undef, 2)
                rn = GC.@preserve got SO.recv_from!(d3, pointer(got), Csize_t(length(got)))
                @test rn == Cssize_t(length(msg))
                @test got == msg
            finally
                _close_fd_raw(d2)
                _close_fd_raw(d3)
            end
        end
        @testset "connect completion and accept flags" begin
            EL.shutdown!()
            listener = Cint(-1)
            client = Cint(-1)
            accepted = Cint(-1)
            try
                listener = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
                SO.set_sockopt_int(listener, SO.SOL_SOCKET, SO.SO_REUSEADDR, 1)
                SO.bind_socket(listener, SO.sockaddr_in_loopback(0))
                SO.listen_socket(listener, 32)
                bound = SO.get_socket_name_in(listener)
                port = Int(SO.sockaddr_in_port(bound))
                client = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
                err = SO.connect_socket(client, SO.sockaddr_in_loopback(port))
                if err != Int32(0) && err != Int32(Base.Libc.EISCONN)
                    @test err == Int32(Base.Libc.EINPROGRESS) || err == Int32(Base.Libc.EALREADY) || err == Int32(Base.Libc.EINTR)
                    _wait_connect_ready!(client)
                    @test SO.get_socket_error(client) == Int32(0)
                end
                accepted, peer = _accept_with_retry(listener)
                @test SO.fd_is_cloexec(accepted)
                @test SO.fd_is_nonblocking(accepted)
                @test peer !== nothing
                @test peer isa SO.SockAddrIn || peer isa SO.SockAddrIn6
            finally
                accepted >= 0 && SO.close_socket_nothrow(accepted)
                client >= 0 && SO.close_socket_nothrow(client)
                listener >= 0 && SO.close_socket_nothrow(listener)
                EL.shutdown!()
            end
        end
    end
end
