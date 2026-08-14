# UDP transport tests.
#
# Determinism rules (test/README.md): no clocks, no sleeps, no timing
# assertions. Datagram tests keep counts small and always park the receiver
# logic after the sends are already queued in the loopback socket buffer, or
# rely on blocking recv calls that complete exactly when the datagram arrives.

function _udp_pair()
    a = UDP.listen(UDP.loopback_addr(0))
    b = UDP.connect(UDP.local_addr(a))
    return a, b
end

@testset "UDP" begin
    @testset "listen binds an ephemeral port" begin
        a = UDP.listen(UDP.loopback_addr(0))
        addr = UDP.local_addr(a)
        @test addr isa UDP.SocketAddrV4
        @test addr.port != 0
        @test UDP.remote_addr(a) === nothing
        @test isopen(a)
        @test occursin("UDP.Conn(", repr(a))
        @test occursin("open", repr(a))
        close(a)
        @test !isopen(a)
        @test occursin("closed", repr(a))
        close(a)
    end

    @testset "connected round trip" begin
        a, b = _udp_pair()
        @test UDP.remote_addr(b) == UDP.local_addr(a)
        UDP.send(b, "hello")
        buf = zeros(UInt8, 16)
        n, from = UDP.recvfrom!(a, buf)
        @test n == 5
        @test buf[1:5] == b"hello"
        @test from == UDP.local_addr(b)
        UDP.sendto(a, "world!", from)
        @test String(UDP.recv(b)) == "world!"
        close(a)
        close(b)
    end

    @testset "unconnected sendto/recvfrom both directions" begin
        a = UDP.listen(UDP.loopback_addr(0))
        b = UDP.listen(UDP.loopback_addr(0))
        UDP.sendto(a, b"ping", UDP.local_addr(b))
        data, from = UDP.recvfrom(b)
        @test data == b"ping"
        @test from == UDP.local_addr(a)
        UDP.sendto(b, b"pong", from)
        data2, from2 = UDP.recvfrom(a)
        @test data2 == b"pong"
        @test from2 == UDP.local_addr(b)
        close(a)
        close(b)
    end

    @testset "connected/unconnected guards" begin
        a, b = _udp_pair()
        @test_throws ArgumentError UDP.sendto(b, "x", UDP.local_addr(a))
        @test_throws ArgumentError UDP.send(a, "x")
        @test_throws ArgumentError UDP.sendto(a, "x", UDP.loopback_addr6(1))
        close(a)
        close(b)
    end

    @testset "empty datagram is data, not EOF" begin
        a, b = _udp_pair()
        UDP.send(b, UInt8[])
        buf = zeros(UInt8, 4)
        n, from = UDP.recvfrom!(a, buf)
        @test n == 0
        @test from == UDP.local_addr(b)
        UDP.send(b, "after")
        @test String(UDP.recv(a)) == "after"
        close(a)
        close(b)
    end

    @testset "payload types and buffer views" begin
        a, b = _udp_pair()
        UDP.send(b, "str")
        UDP.send(b, codeunits("cu?"))
        UDP.send(b, view(collect(b"viewpay"), 1:4))
        backing = zeros(UInt8, 12)
        n = UDP.recv!(a, view(backing, 5:8))
        @test n == 3
        @test backing[5:7] == b"str"
        @test String(UDP.recv(a)) == "cu?"
        @test UDP.recv(a) == b"view"
        close(a)
        close(b)
    end

    @testset "truncation policy" begin
        a, b = _udp_pair()
        UDP.send(b, "0123456789")
        buf = zeros(UInt8, 4)
        err = try
            UDP.recv!(a, buf)
            nothing
        catch e
            e
        end
        @test err isa UDP.TruncatedDatagramError
        @test err.nread == 4
        @test occursin("allow_truncate", sprint(showerror, err))
        # The truncated prefix was delivered and the rest of the datagram
        # dropped; the socket stays usable (a Sockets stdlib invariant worth
        # keeping).
        UDP.send(b, "0123456789")
        @test UDP.recv!(a, buf; allow_truncate = true) == 4
        @test buf == b"0123"
        UDP.send(b, "ok")
        @test String(UDP.recv(a)) == "ok"
        # Allocating forms honor maxsize the same way.
        UDP.send(b, "0123456789")
        @test_throws UDP.TruncatedDatagramError UDP.recv(a; maxsize = 4)
        UDP.send(b, "fits")
        @test String(UDP.recv(a; maxsize = 4)) == "fits"
        close(a)
        close(b)
    end

    @testset "datagram boundaries and FIFO order" begin
        a, b = _udp_pair()
        for i in 1:8
            UDP.send(b, "msg-$(i)")
        end
        for i in 1:8
            @test String(UDP.recv(a)) == "msg-$(i)"
        end
        close(a)
        close(b)
    end

    @testset "oversized send surfaces EMSGSIZE and keeps the socket" begin
        a, b = _udp_pair()
        # 64 KiB exceeds the UDP maximum payload everywhere.
        err = try
            UDP.send(b, zeros(UInt8, 64 * 1024))
            nothing
        catch e
            e
        end
        @test err isa Union{ArgumentError, SystemError}
        UDP.send(b, "still works")
        @test String(UDP.recv(a)) == "still works"
        close(a)
        close(b)
    end

    @testset "read deadline" begin
        a, b = _udp_pair()
        UDP.set_read_deadline!(a, Int64(1))
        @test_throws UDP.DeadlineExceededError UDP.recv!(a, zeros(UInt8, 4))
        UDP.set_read_deadline!(a, 0)
        UDP.send(b, "post-clear")
        @test String(UDP.recv(a)) == "post-clear"
        close(a)
        close(b)
    end

    @testset "write deadline" begin
        a, b = _udp_pair()
        UDP.set_write_deadline!(b, Int64(1))
        @test_throws UDP.DeadlineExceededError UDP.send(b, "never")
        UDP.set_write_deadline!(b, 0)
        UDP.send(b, "sent")
        @test String(UDP.recv(a)) == "sent"
        UDP.set_deadline!(b, Int64(1))
        @test_throws UDP.DeadlineExceededError UDP.send(b, "never")
        close(a)
        close(b)
    end

    @testset "close wakes and rejects operations" begin
        a, b = _udp_pair()
        close(a)
        @test_throws Reseau.IOPoll.NetClosingError UDP.recv!(a, zeros(UInt8, 4))
        close(b)
        @test_throws Reseau.IOPoll.NetClosingError UDP.send(b, "x")
        close(a)
        close(b)
    end

    @testset "ipv6 loopback round trip" begin
        a = UDP.listen(UDP.loopback_addr6(0))
        addr = UDP.local_addr(a)
        @test addr isa UDP.SocketAddrV6
        b = UDP.connect(addr)
        UDP.send(b, "v6 datagram")
        data, from = UDP.recvfrom(a)
        @test String(data) == "v6 datagram"
        @test from == UDP.local_addr(b)
        close(a)
        close(b)
    end

    @testset "reuseaddr and reuseport" begin
        a = UDP.listen(UDP.loopback_addr(0); reuseaddr = true)
        @test isopen(a)
        close(a)
        @static if Sys.iswindows()
            @test_throws ArgumentError UDP.listen(UDP.loopback_addr(0); reuseport = true)
        else
            l1 = UDP.listen(UDP.loopback_addr(0); reuseport = true)
            port = Int(UDP.local_addr(l1).port)
            l2 = UDP.listen(UDP.loopback_addr(port); reuseport = true)
            @test Int(UDP.local_addr(l2).port) == port
            close(l1)
            close(l2)
        end
    end

    @testset "socket options" begin
        a = UDP.listen(UDP.loopback_addr(0))
        # Broadcast defaults on (Go setDefaultSockopts parity).
        @test Reseau.SocketOps.get_sockopt_int(
            a.fd.pfd.sysfd,
            Reseau.SocketOps.SOL_SOCKET,
            Reseau.SocketOps.SO_BROADCAST,
        ) != 0
        UDP.set_broadcast!(a, false)
        @test Reseau.SocketOps.get_sockopt_int(
            a.fd.pfd.sysfd,
            Reseau.SocketOps.SOL_SOCKET,
            Reseau.SocketOps.SO_BROADCAST,
        ) == 0
        UDP.set_broadcast!(a, true)
        UDP.set_read_buffer!(a, 64 * 1024)
        @test Reseau.SocketOps.get_sockopt_int(
            a.fd.pfd.sysfd,
            Reseau.SocketOps.SOL_SOCKET,
            Reseau.SocketOps.SO_RCVBUF,
        ) >= 64 * 1024
        UDP.set_write_buffer!(a, 64 * 1024)
        @test Reseau.SocketOps.get_sockopt_int(
            a.fd.pfd.sysfd,
            Reseau.SocketOps.SOL_SOCKET,
            Reseau.SocketOps.SO_SNDBUF,
        ) >= 64 * 1024
        @test_throws ArgumentError UDP.set_read_buffer!(a, 0)
        @test_throws ArgumentError UDP.set_write_buffer!(a, 0)
        UDP.set_ttl!(a, 3)
        @test Reseau.SocketOps.get_sockopt_int(
            a.fd.pfd.sysfd,
            Reseau.SocketOps.IPPROTO_IP,
            Reseau.SocketOps.IP_TTL,
        ) == 3
        @test_throws ArgumentError UDP.set_ttl!(a, 300)
        v6 = UDP.listen(UDP.loopback_addr6(0))
        UDP.set_ttl!(v6, 5)
        @test Reseau.SocketOps.get_sockopt_int(
            v6.fd.pfd.sysfd,
            Reseau.SocketOps.IPPROTO_IPV6,
            Reseau.SocketOps.IPV6_UNICAST_HOPS,
        ) == 5
        close(a)
        close(v6)
    end

    @testset "dual-stack address coercion" begin
        four = UDP.listen(UDP.loopback_addr(0))
        four_addr = UDP.local_addr(four)

        # An IPv4 destination on an AF_INET6 socket becomes IPv4-mapped.
        six = UDP.listen(UDP.any_addr6(0))
        UDP.sendto(six, "mapped", four_addr)
        data, _ = UDP.recvfrom(four)
        @test String(data) == "mapped"

        # An IPv4-mapped IPv6 destination on an AF_INET socket collapses.
        mapped = UDP.SocketAddrV6(
            (0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01),
            Int(four_addr.port),
        )
        sender4 = UDP.listen(UDP.loopback_addr(0))
        UDP.sendto(sender4, "collapsed", mapped)
        data, _ = UDP.recvfrom(four)
        @test String(data) == "collapsed"

        # connect with a v6 local and a v4 remote opens an AF_INET6 socket
        # and carries the remote as IPv4-mapped (Go favoriteAddrFamily).
        mixed = UDP.connect(four_addr; local_addr = UDP.any_addr6(0))
        @test UDP.remote_addr(mixed) isa UDP.SocketAddrV6
        UDP.send(mixed, "mixed families")
        data, _ = UDP.recvfrom(four)
        @test String(data) == "mixed families"

        # A wildcard dial destination means the local system (Go
        # internetSocket parity; rewritten to loopback where kernels
        # reject it).
        wild = UDP.connect(UDP.any_addr(Int(four_addr.port)))
        UDP.send(wild, "wildcard dial")
        data, _ = UDP.recvfrom(four)
        @test String(data) == "wildcard dial"

        foreach(close, (four, six, sender4, mixed, wild))
    end

    @testset "string-address entrypoints" begin
        a = UDP.listen("udp4", "127.0.0.1:0")
        @test UDP.local_addr(a) isa UDP.SocketAddrV4
        b = UDP.connect("127.0.0.1:$(Int(UDP.local_addr(a).port))")
        UDP.send(b, "resolved")
        @test String(UDP.recv(a)) == "resolved"
        close(a)
        close(b)

        wild = UDP.listen(":0")
        @test UDP.local_addr(wild) !== nothing
        close(wild)

        v6 = UDP.listen("udp6", "[::1]:0")
        @test UDP.local_addr(v6) isa UDP.SocketAddrV6
        close(v6)

        err = try
            UDP.connect("nope", "127.0.0.1:1")
            nothing
        catch e
            e
        end
        @test err isa Reseau.HostResolvers.OpError
        @test err.err isa Reseau.HostResolvers.UnknownNetworkError

        err = try
            TCP.connect("udp", "127.0.0.1:1")
            nothing
        catch e
            e
        end
        @test err isa Reseau.HostResolvers.OpError
        @test err.err isa Reseau.HostResolvers.UnknownNetworkError
    end
end
