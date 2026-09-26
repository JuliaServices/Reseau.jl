using Test
using Reseau

const _UX = Reseau.Unix
const _UX_IP = Reseau.IOPoll
const _UX_SO = Reseau.SocketOps

@testset "Unix filesystem stream clients" begin
    @test isconcretetype(_UX.Conn)
    @test isconcretetype(Reseau.TCP.Conn)
    @test fieldtypes(Reseau.TCP.Conn) == (Reseau.NetCommon.FD,)
    @test _UX.Conn <: IO
    @test _UX.DeadlineExceededError === _UX_IP.DeadlineExceededError
    @test _UX.NetClosingError === _UX_IP.NetClosingError
    @test Reseau.TCP._read_some! === Reseau.NetCommon._read_some!
    @test Reseau.TCP._tryread! === Reseau.NetCommon._tryread!

    @testset "connect budget arithmetic" begin
        deadline(a, b, c) = _UX._connect_deadline_ns(Int64(a), Int64(b), Int64(c))
        @test deadline(0, 0, 100) == 0
        @test deadline(10, 0, 100) == 110
        @test deadline(0, 120, 100) == 120
        @test deadline(10, 120, 100) == 110
        @test deadline(30, 120, 100) == 120
        @test deadline(30, -10, 100) == -10
        @test deadline(-1, 0, 100) < 100
        @test deadline(-100, 0, 100) < 0
        @test deadline(typemax(Int64), 0, 100) == typemax(Int64)
        @test deadline(typemax(Int64), 120, 100) == 120
    end

    @static if Sys.islinux() || Sys.isapple() || Sys.isfreebsd()
        @testset "pathname validation and native errors" begin
            @test_throws ArgumentError _UX.connect("")
            @test_throws ArgumentError _UX.connect("bad\0path")
            cap = _UX_SO._UNIX_PATH_CAPACITY
            @test_throws ArgumentError _UX.connect(repeat("x", cap))
            @test_throws ArgumentError _UX.connect(repeat("é", cap ÷ 2))
            @test sizeof(_UX_SO.SockAddrUn) == cap + 2
            @test fieldoffset(_UX_SO.SockAddrUn, fieldcount(_UX_SO.SockAddrUn)) == 2
            addr = _UX_SO.sockaddr_un("é")
            @test addr.sun_path[1:3] == (0xc3, 0xa9, 0x00)
            @static if !Sys.islinux()
                @test addr.sun_len == 5
            end
            mktempdir("/tmp"; prefix = "reseau-unix-") do dir
                missing = joinpath(dir, "missing")
                err = try _UX.connect(missing); nothing catch e; e end
                @test err isa SystemError
                @test err.errnum == Base.Libc.ENOENT
                @test_throws _UX.DeadlineExceededError _UX.connect(missing; deadline_ns = 1)
                @test_throws _UX.DeadlineExceededError _UX.connect(missing; timeout_ns = -1)
                @test_throws InexactError _UX.connect(missing; timeout_ns = big(typemax(Int64)) + 1)
                @test_throws InexactError _UX.connect(missing; deadline_ns = big(typemax(Int64)) + 1)
                plain = joinpath(dir, "file")
                write(plain, "ordinary file")
                @test_throws SystemError _UX.connect(plain)
                stale = joinpath(dir, "stale")
                listening = UnixTestHelpers.listener(stale)
                close(listening)
                @test ispath(stale)
                @test_throws SystemError _UX.connect(stale)

                longest = joinpath(dir, repeat("x", cap - 2 - sizeof(dir)))
                @test sizeof(longest) == cap - 1
                UnixTestHelpers.with_pair(longest; timeout_ns = typemax(Int64)) do client, server
                    @test write(client, "ok") == 2
                    @test read(server, 2) == codeunits("ok")
                    @test (@atomic client.fd.pfd.pd.wd_ns) == 0
                end
                @test ispath(longest)
                cd(dir) do
                    UnixTestHelpers.with_pair("@é.sock"; deadline_ns = typemax(Int64)) do client, server
                        @test client.path == "@é.sock"
                        @test write(client, 0x61) == 1
                        @test read(server, UInt8) == 0x61
                    end
                    @test ispath("@é.sock")
                end
            end
        end

        @testset "Base stream IO and ownership" begin
            UnixTestHelpers.with_pair() do client, server
                @test isopen(client)
                @test _UX_SO.fd_is_cloexec(client.fd.pfd.sysfd)
                @test _UX_SO.fd_is_nonblocking(client.fd.pfd.sysfd)
                @test _UX.tryread!(server, zeros(UInt8, 1)) === nothing
                @test_throws ArgumentError _UX.tryread!(server, UInt8[])
                @test write(client, UInt8[]) == 0
                @test read(client, 0) == UInt8[]
                @test readbytes!(client, UInt8[], 0) == 0
                @test flush(client) === nothing
                payload = collect(UInt8, 0:31)
                @test write(client, @view(payload[2:2:20])) == 10
                owned = read(server, 10)
                @test owned == payload[2:2:20]
                @test write(client, "abcd") == 4
                buffer = fill(0xff, 8)
                destination = @view(buffer[3:6])
                @test read!(server, destination) === destination
                @test destination == codeunits("abcd")
                @test buffer[[1, 2, 7, 8]] == fill(0xff, 4)
                @test owned == payload[2:2:20]
                @test write(client, codeunits("xyz")) == 3
                @test readbytes!(server, @view(buffer[2:6]), 3; all = false) == 3
                @test buffer[2:4] == codeunits("xyz")
                @test write(client, "left") == 4
                @test !eof(server)
                @test readavailable(server) == codeunits("left")
                @test write(client, 0x70) == 1
                @test _UX.tryread!(server, @view(buffer[2:3])) == 1
                @test buffer[2] == 0x70
                @test write(client, "tail") == 4
                closewrite(client)
                @test read(server, 10) == codeunits("tail")
                @test eof(server)
                @test _UX.tryread!(server, buffer) === 0
                @test write(server, "reply") == 5
                @test read(client, 5) == codeunits("reply")
                @test _UX.rawfd(client) isa RawFD
                @test occursin("open", repr(client))
                close(client)
                @test !isopen(client)
                @test close(client) === nothing
                @test occursin("closed", repr(client))
                @test _UX.tryread!(client, buffer) === 0
                @test_throws _UX.NetClosingError _UX.rawfd(client)
            end
        end

        @testset "deadline reset and shutdown" begin
            UnixTestHelpers.with_pair() do client, server
                # Exercise completion on a real connected descriptor as well
                # as immediate connect. Local kernels need not return pending.
                @test _UX._wait_connected!(client.fd) === nothing
                _UX.set_write_deadline!(client, 1)
                @test_throws _UX.DeadlineExceededError _UX._wait_connected!(client.fd)
                _UX.set_write_deadline!(client, 0)
                _UX.set_deadline!(client, 1)
                @test_throws _UX.DeadlineExceededError read(client, UInt8)
                @test_throws _UX.DeadlineExceededError write(client, 0x01)
                _UX.set_read_deadline!(client, 0)
                @test write(server, 0x02) == 1
                @test read(client, UInt8) == 0x02
                _UX.set_write_deadline!(client, 0)
                @test write(client, 0x03) == 1
                @test read(server, UInt8) == 0x03
                _UX.closeread(client)
                @test eof(client)
            end
        end

        @testset "close wakes a parked read" begin
            UnixTestHelpers.with_pair() do client, server
                task = errormonitor(Threads.@spawn try read(client, UInt8) catch e; e end)
                waiter = _UX_IP._poll_registration(client.fd.pfd.pd).read_waiter
                @test UnixTestHelpers.wait_parked(task, waiter)
                close(client)
                @test fetch(task) isa _UX.NetClosingError
            end
        end

        @testset "close wakes a backpressured write" begin
            UnixTestHelpers.with_pair() do client, server
                _UX_IP.set_sockopt_int!(client.fd.pfd, _UX_SO.SOL_SOCKET, _UX_SO.SO_SNDBUF, 4096)
                payload = zeros(UInt8, 1 << 20)
                task = errormonitor(Threads.@spawn try
                    while true
                        write(client, payload)
                    end
                catch e
                    e
                end)
                waiter = _UX_IP._poll_registration(client.fd.pfd.pd).write_waiter
                @test UnixTestHelpers.wait_parked(task, waiter)
                close(client)
                @test fetch(task) isa _UX.NetClosingError
            end
        end
    else
        @test_throws ArgumentError _UX.connect("example.sock")
        @test_throws ArgumentError _UX.connect("")
    end
end
