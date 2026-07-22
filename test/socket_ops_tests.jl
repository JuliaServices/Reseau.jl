using Test
using Reseau

const IP = Reseau.IOPoll
const SO = Reseau.SocketOps
const _SO_EWOULDBLOCK = @static isdefined(Base.Libc, :EWOULDBLOCK) ? Int32(getfield(Base.Libc, :EWOULDBLOCK)) : Int32(Base.Libc.EAGAIN)

function _close_fd_raw(fd::SO.SocketFD)
    SO.is_valid_socket(fd) || return nothing
    SO.close_socket_nothrow(fd)
    return nothing
end

function _accept_with_retry(listener::SO.SocketFD)::Tuple{SO.SocketFD, SO.AcceptPeer}
    for _ in 1:5000
        accepted, peer, errno = SO.try_accept_socket(listener)
        SO.is_valid_socket(accepted) && return accepted, peer
        errno == Int32(Base.Libc.EAGAIN) && (yield(); continue)
        errno == _SO_EWOULDBLOCK && (yield(); continue)
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("accept", Int(errno)))
    end
    throw(ArgumentError("timed out waiting for accepted socket"))
end

function _wait_connect_ready!(fd::SO.SocketFD)
    registration = IP.register!(fd; mode = IP.PollMode.WRITE)
    try
        IP.arm_waiter!(registration, IP.PollMode.WRITE)
        IP.pollwait!(registration.write_waiter)
    finally
        IP.deregister!(fd)
    end
    return nothing
end

function _stream_pair()::Tuple{SO.SocketFD, SO.SocketFD}
    listener = SO.INVALID_SOCKET
    client = SO.INVALID_SOCKET
    accepted = SO.INVALID_SOCKET
    try
        listener = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        SO.set_sockopt_int(listener, SO.SOL_SOCKET, SO.SO_REUSEADDR, 1)
        SO.bind_socket(listener, SO.sockaddr_in_loopback(0))
        SO.listen_socket(listener, 32)
        bound = SO.get_socket_name_in(listener)
        port = Int(SO.sockaddr_in_port(bound))
        client = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        SO.set_nonblocking!(client, false)
        try
            err = SO.connect_socket(client, SO.sockaddr_in_loopback(port))
            err == Int32(0) || err == Int32(Base.Libc.EISCONN) || throw(SystemError("connect", Int(err)))
        finally
            SO.set_nonblocking!(client, true)
        end
        accepted, _ = _accept_with_retry(listener)
        stream_client = client
        stream_server = accepted
        client = SO.INVALID_SOCKET
        accepted = SO.INVALID_SOCKET
        return stream_client, stream_server
    finally
        SO.is_valid_socket(accepted) && SO.close_socket_nothrow(accepted)
        SO.is_valid_socket(client) && SO.close_socket_nothrow(client)
        SO.is_valid_socket(listener) && SO.close_socket_nothrow(listener)
    end
end

function _dgram_pair()::Tuple{SO.SocketFD, SO.SocketFD, SO.SockAddrIn, SO.SockAddrIn}
    fd0 = SO.INVALID_SOCKET
    fd1 = SO.INVALID_SOCKET
    try
        fd0 = SO.open_socket(SO.AF_INET, SO.SOCK_DGRAM)
        fd1 = SO.open_socket(SO.AF_INET, SO.SOCK_DGRAM)
        SO.bind_socket(fd0, SO.sockaddr_in_loopback(0))
        SO.bind_socket(fd1, SO.sockaddr_in_loopback(0))
        addr0 = SO.get_socket_name_in(fd0)
        addr1 = SO.get_socket_name_in(fd1)
        return fd0, fd1, addr0, addr1
    catch
        SO.is_valid_socket(fd1) && SO.close_socket_nothrow(fd1)
        SO.is_valid_socket(fd0) && SO.close_socket_nothrow(fd0)
        rethrow()
    end
end

@testset "SocketOps phase 3" begin
        @static if Sys.iswindows()
            @testset "pointer-sized WinSock handles" begin
                @test SO.SocketFD === UInt
                @test IP.SysFD === UInt
                high_handle = (UInt(1) << 40) | UInt(0x1234)
                @test high_handle > UInt(typemax(UInt32))
                @test SO.is_valid_socket(high_handle)
                @test SO._socket_value(high_handle) == high_handle
                pollstate = IP.PollState(high_handle, UInt64(7))
                @test pollstate.sysfd == high_handle
                registration = IP.Registration(
                    high_handle,
                    UInt64(7),
                    IP.PollMode.READWRITE,
                    IP.PollWaiter(),
                    IP.PollWaiter(),
                    false,
                )
                poller = IP.Poller()
                poller.registrations[high_handle] = registration
                @test poller.registrations[high_handle].fd == high_handle
                iocp_registration = IP._new_iocp_registration(high_handle, UInt64(7))
                @test iocp_registration.fd == high_handle
            end
        end
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
            @test SO.close_socket_nothrow(SO.INVALID_SOCKET) == Int32(Base.Libc.EBADF)
            @test_throws SystemError SO.close_socket(SO.INVALID_SOCKET)
        end
        @testset "read/write and recv/send wrappers" begin
            fd0, fd1 = _stream_pair()
            d0 = SO.INVALID_SOCKET
            d1 = SO.INVALID_SOCKET
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
                recv_msg_buf = Vector{UInt8}(undef, 3)
                recv_iov = Ref(SO.IOVec(pointer(recv_msg_buf), Csize_t(length(recv_msg_buf))))
                recv_hdr = Ref(SO.MsgHdr(C_NULL, SO.SockLen(0), Base.unsafe_convert(Ptr{SO.IOVec}, recv_iov), Cint(1), C_NULL, SO.SockLen(0), Cint(0)))
                sent = GC.@preserve payload iov send_hdr SO.send_msg!(d0, send_hdr)
                @test sent == Cssize_t(length(payload))
                recvd = GC.@preserve recv_msg_buf recv_iov recv_hdr SO.recv_msg!(d1, recv_hdr)
                @test recvd == Cssize_t(length(payload))
                @test recv_msg_buf == payload
            finally
                _close_fd_raw(d0)
                _close_fd_raw(d1)
            end
            fd2, fd3, addr2, addr3 = _dgram_pair()
            d2 = SO.INVALID_SOCKET
            d3 = SO.INVALID_SOCKET
            try
                d2 = fd2
                d3 = fd3
                SO.set_nonblocking!(d2, false)
                SO.set_nonblocking!(d3, false)
                msg = UInt8[0x41, 0x42]
                addr3_ref = Ref(addr3)
                sn = GC.@preserve msg addr3_ref SO.send_to!(
                    d2,
                    pointer(msg),
                    Csize_t(length(msg)),
                    Cint(0),
                    Base.unsafe_convert(Ptr{Cvoid}, addr3_ref),
                    SO.SockLen(sizeof(SO.SockAddrIn)),
                )
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
            IP.shutdown!()
            listener = SO.INVALID_SOCKET
            client = SO.INVALID_SOCKET
            accepted = SO.INVALID_SOCKET
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
                SO.is_valid_socket(accepted) && SO.close_socket_nothrow(accepted)
                SO.is_valid_socket(client) && SO.close_socket_nothrow(client)
                SO.is_valid_socket(listener) && SO.close_socket_nothrow(listener)
                IP.shutdown!()
            end
        end
    end
