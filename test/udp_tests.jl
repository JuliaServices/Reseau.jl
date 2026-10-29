# UDP transport tests.
#
# Determinism rules (test/README.md): no clocks, no sleeps, no timing
# assertions. Datagram tests keep counts small and always park the receiver
# logic after the sends are already queued in the loopback socket buffer, or
# rely on blocking recv calls that complete exactly when the datagram arrives.

# Bytes allocated by one call; results go into preallocated `Ref`s so the
# measurement sees only the call itself.
function _udp_recv_allocs(conn, maxsize = 65535)
    out = Ref{Vector{UInt8}}()
    allocs = @allocated(out[] = UDP.recv(conn; maxsize))
    return out[], allocs
end

# Waits, without consuming it, until a datagram is queued on `conn`, so a
# measured receive does not park. The peek buffer is larger than the test
# datagrams: Windows fails a truncated peek with WSAEMSGSIZE.
function _udp_wait_queued(conn)
    peek = zeros(UInt8, 16)
    while GC.@preserve(peek, Reseau.SocketOps.recv_from!(
        conn.fd.pfd.sysfd, pointer(peek), Csize_t(length(peek)), Reseau.SocketOps.MSG_PEEK,
    )) < 0
        yield()
    end
    return nothing
end

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

    @testset "allocating receives keep only the datagram's bytes" begin
        a, b = _udp_pair()
        UDP.send(b, "tiny")
        data = UDP.recv(a)
        UDP.sendto(a, "tiny", UDP.local_addr(b))
        data2, _ = UDP.recvfrom(b)
        @test data == data2 == b"tiny"
        @static if VERSION >= v"1.11"
            # Not the 64 KiB receive buffer shrunk with `resize!`.
            @test length(data.ref.mem) == length(data2.ref.mem) == 4
        end
        close(a)
        close(b)
    end

    @testset "allocating receives reuse the socket's buffer" begin
        a, b = _udp_pair()
        UDP.send(b, "warm")
        @test UDP.recv(a) == b"warm"
        scratch = @atomic a.fd.recv_scratch
        @test scratch isa Vector{UInt8}
        reused_allocs = typemax(Int)
        fresh_allocs = typemax(Int)
        # Compare the same receive API with a reusable buffer and a request one
        # byte larger, which requires a fresh buffer. recv! follows a different
        # compiled path and its small allocation overhead need not match recv.
        # Queue each datagram first; the minimum drops compilation and unrelated
        # allocations without requiring byte-exact platform-specific overhead.
        for _ in 1:5
            UDP.send(b, "abc")
            _udp_wait_queued(a)
            data, allocs = _udp_recv_allocs(a, length(scratch))
            @test data == b"abc"
            @test (@atomic a.fd.recv_scratch) === scratch
            reused_allocs = min(reused_allocs, allocs)
            UDP.send(b, "xyz")
            _udp_wait_queued(a)
            data, allocs = _udp_recv_allocs(a, length(scratch) + 1)
            @test data == b"xyz"
            fresh_allocs = min(fresh_allocs, allocs)
        end
        # Reuse must save at least the full scratch buffer's payload allocation.
        @test reused_allocs + length(scratch) <= fresh_allocs
        close(a)
        close(b)
    end

    @testset "concurrent allocating receives never share the buffer" begin
        a, b = _udp_pair()
        UDP.send(b, "warm")
        @test UDP.recv(a) == b"warm"
        @test a.fd.recv_scratch isa Vector{UInt8}
        first = errormonitor(@async UDP.recv(a))
        waiter = Reseau.IOPoll.current_registration(a.fd.pfd.pd).read_waiter
        while !istaskdone(first) && !((@atomic :acquire waiter.state) isa Task)
            yield()
        end
        # The parked receive owns the buffer, so this one must use its own.
        @test a.fd.recv_scratch === nothing
        second = errormonitor(@async UDP.recv(a))
        UDP.send(b, "one")
        @test fetch(first) == b"one"
        UDP.send(b, "two")
        @test fetch(second) == b"two"
        @test a.fd.recv_scratch isa Vector{UInt8}
        close(a)
        close(b)
        # Closing drops the buffer.
        @test a.fd.recv_scratch === nothing
        @test_throws ArgumentError UDP.recv(a; maxsize = -1)
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

@static if !Sys.iswindows()
@testset "UDP failed listen and connect leave no finalizer that closes a reused descriptor" begin
    SO = Reseau.SocketOps
    holder = UDP.listen(UDP.loopback_addr(0))
    port = Int(UDP.local_addr(holder).port)
    try
        for attempt in (
                () -> UDP.listen(UDP.loopback_addr(port)),
                () -> UDP.connect(UDP.loopback_addr(9); local_addr = UDP.loopback_addr(port)),
            )
            @test_throws SystemError attempt()
            # Descriptor numbers are reused lowest-first, so one of these takes
            # the number the failed call released.
            victims = [SO.open_socket(SO.AF_INET, SO.SOCK_STREAM) for _ in 1:32]
            try
                GC.gc(true)  # runs the failed socket's finalizer
                for _ in 1:100
                    yield()  # and any close task it scheduled
                end
                @test all(v -> ccall(:fcntl, Cint, (Cint, Cint), v, Cint(1)) != -1, victims)
            finally
                foreach(SO.close_socket_nothrow, victims)
            end
        end
    finally
        close(holder)
    end
end
end

@testset "UDP draining receives never wait" begin
    receiver = UDP.listen(UDP.loopback_addr(0))
    sender = UDP.connect(UDP.local_addr(receiver)::UDP.SocketAddrV4)
    try
        buf = Vector{UInt8}(undef, 64)
        @test UDP._try_recvfrom!(receiver, buf) == (-1, nothing)
        UDP.send(sender, UInt8[0x01])
        UDP.send(sender, UInt8[0x02, 0x03])
        # A blocking receive returns the first, and the rest drain without waiting.
        n, from = UDP.recvfrom!(receiver, buf)
        @test buf[1:n] == UInt8[0x01]
        got = Int[]
        @static if Sys.iswindows()
            # Receives complete through IOCP, so nothing drains.
            @test UDP._try_recvfrom!(receiver, buf) == (-1, nothing)
        else
            k, peer = UDP._try_recvfrom!(receiver, buf)
            @test buf[1:k] == UInt8[0x02, 0x03]
            @test peer == from
            @test UDP._try_recvfrom!(receiver, buf) == (-1, nothing)
        end
        UDP.send(sender, zeros(UInt8, 100))
        @static if !Sys.iswindows()
            # Wait for it to queue, then a short buffer reports truncation.
            UDP.set_read_deadline!(receiver, 0)
            while true
                try
                    UDP._try_recvfrom!(receiver, buf)[1] < 0 || error("expected truncation")
                    yield()
                catch err
                    @test err isa UDP.TruncatedDatagramError
                    break
                end
            end
        end
    finally
        close(sender)
        close(receiver)
    end
    @test_throws Exception UDP._try_recvfrom!(receiver, Vector{UInt8}(undef, 8))
end

@testset "UDP don't-fragment and path MTU" begin
    supported = Sys.islinux() || Sys.isapple()
    # Whether Don't Fragment can be set for IPv4 datagrams on `sock` itself.
    function v4_dont_fragment(sock)
        supported || return false
        try
            @static if Sys.islinux()
                Reseau.SocketOps.set_sockopt_int(sock.fd.pfd.sysfd, Reseau.SocketOps.IPPROTO_IP, UDP._IP_MTU_DISCOVER, UDP._PMTUDISC_PROBE)
            else
                Reseau.SocketOps.set_sockopt_int(sock.fd.pfd.sysfd, Reseau.SocketOps.IPPROTO_IP, UDP._IP_DONTFRAG, 1)
            end
            return true
        catch
            return false
        end
    end
    # Bound to a wildcard, an IPv6 listener is dual-stack; bound to ::1 it is
    # IPv6-only.
    for addr in (UDP.loopback_addr(0), UDP.any_addr6(0))
        receiver = try
            UDP.listen(addr)
        catch
            continue  # no IPv6
        end
        sender = UDP.connect(UDP.local_addr(receiver))
        v6only = UDP.listen(UDP.loopback_addr6(0); v6only = true)
        try
            v4 = addr isa UDP.SocketAddrV4
            # The listener is IPv4 or dual-stack; the IPv6 sockets connected
            # to an IPv6 peer, or IPv6-only, send no IPv4.
            @test UDP._carries_ipv4(receiver)
            @test UDP._carries_ipv4(sender) == v4
            @test !UDP._carries_ipv4(v6only)
            @test UDP._set_dont_fragment!(sender) == supported
            @test UDP._set_dont_fragment!(v6only) == supported
            # A dual-stack socket counts only where IPv4 datagrams get it too,
            # which macOS refuses.
            @test UDP._set_dont_fragment!(receiver) == (v4 ? supported : v4_dont_fragment(receiver))
            Sys.islinux() && @test UDP._set_dont_fragment!(receiver)
            if Sys.islinux()
                # The connected socket knows its route's MTU; loopback's is large.
                @test UDP._path_mtu(sender) >= 1500
                # An unconnected socket has no route to ask about.
                @test UDP._path_mtu(receiver) == 0
            else
                @test UDP._path_mtu(sender) == 0
            end
        finally
            close(sender)
            close(receiver)
            close(v6only)
        end
    end
    # An IPv6 socket connected to an IPv4 peer sends IPv4 datagrams.
    receiver = UDP.listen(UDP.loopback_addr(0))
    mapped = try
        UDP.connect(UDP.local_addr(receiver); local_addr = UDP.any_addr6(0))
    catch
        nothing  # no IPv6
    end
    try
        if mapped !== nothing
            @test mapped.fd.family == Reseau.SocketOps.AF_INET6
            @test UDP._carries_ipv4(mapped)
            @test UDP._set_dont_fragment!(mapped) == v4_dont_fragment(mapped)
        end
    finally
        mapped === nothing || close(mapped)
        close(receiver)
    end
end
