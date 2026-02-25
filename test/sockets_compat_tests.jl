using Test
using Random
using Reseau
using Reseau.Sockets

@testset "Sockets Compat" begin
    @testset "Addr/DNS Utils" begin
        @test parse(IPAddr, "127.0.0.1") == IPv4("127.0.0.1")
        @test parse(IPAddr, "::1") == IPv6("::1")

        addrs = getalladdrinfo("localhost")
        @test !isempty(addrs)
        @test all(a -> a isa IPAddr, addrs)

        @test getaddrinfo("localhost") isa IPAddr
        @test getaddrinfo("localhost", IPv4) isa IPv4

        # `getnameinfo` should return either a real name or a numeric fallback.
        @test !isempty(getnameinfo(IPv4("127.0.0.1")))

        # `getipaddrs` should always be able to return loopback addresses.
        local_addrs = getipaddrs(IPAddr; loopback = true)
        @test !isempty(local_addrs)

        @test islinklocaladdr(IPv4("169.254.1.2"))
        @test islinklocaladdr(IPv6("fe80::1"))
        @test !islinklocaladdr(IPv4("8.8.8.8"))
    end

    @testset "TCP Echo" begin
        port, server = listenany(0)
        msg = Vector{UInt8}(codeunits("hello"))

        server_task = @async begin
            client = accept(server)
            data = read(client, length(msg))
            write(client, data)
            write(client, Vector{UInt8}(codeunits("abc")))
            flush(client)
            close(client)
        end

        sock = connect("127.0.0.1", port)

        @test getpeername(sock)[1] == IPv4("127.0.0.1")
        @test getsockname(sock)[2] > 0

        write(sock, msg)
        resp = read(sock, length(msg))
        @test resp == msg

        @test peek(sock, UInt8) == UInt8('a')
        @test read(sock, UInt8) == UInt8('a')
        @test readavailable(sock) == Vector{UInt8}(codeunits("bc"))

        close(sock)
        close(server)
        wait(server_task)
    end

    @testset "LOCAL Echo" begin
        # Use a unique path to avoid collisions/leaks if a prior test run crashed.
        name = string("reseau-sock-", string(rand(UInt128); base = 16))
        # Keep Unix socket paths short enough for platform sockaddr_un limits.
        path = Sys.iswindows() ? string("\\\\.\\pipe\\", name) : string(name, ".sock")

        server = listen(path)
        msg = Vector{UInt8}(codeunits("ping"))

        server_task = @async begin
            client = accept(server)
            data = read(client, length(msg))
            write(client, data)
            flush(client)
            close(client)
        end

        sock = connect(path)
        write(sock, msg)
        resp = read(sock, length(msg))
        @test resp == msg
        close(sock)
        close(server)
        wait(server_task)

        if !Sys.iswindows()
            # Best-effort cleanup of the unix domain socket file.
            ispath(path) && rm(path; force = true)
        end
    end

    if get(ENV, "RESEAU_RUN_TLS_TESTS", "0") == "1"
        @testset "TLS Echo" begin
            resource_root = joinpath(dirname(@__DIR__), "aws-c-io", "tests", "resources")
            cert_path = joinpath(resource_root, "unittests.crt")
            key_path = joinpath(resource_root, "unittests.key")
            event_loop_group = Reseau.EventLoops.EventLoopGroup(; loop_count = 1)
            host_resolver = Sockets.HostResolver()
            msg = Vector{UInt8}(codeunits("tls"))

            server = nothing
            sock = nothing
            server_task = nothing

            try
                port, server_val = listenany(
                    0;
                    tls = true,
                    ssl_cert = cert_path,
                    ssl_key = key_path,
                    event_loop_group = event_loop_group,
                )
                server = server_val

                server_task = @async begin
                    client = accept(server_val)
                    data = read(client, length(msg))
                    write(client, data)
                    flush(client)
                    close(client)
                end

                sock = connect(
                    "127.0.0.1",
                    port;
                    tls = true,
                    ssl_cacert = cert_path,
                    server_name = "localhost",
                    event_loop_group = event_loop_group,
                    host_resolver = host_resolver,
                )
                write(sock, msg)
                resp = read(sock, length(msg))
                @test resp == msg
            finally
                sock !== nothing && close(sock)
                server !== nothing && close(server)
                server_task !== nothing && wait(server_task)
                close(host_resolver)
                close(event_loop_group)
            end
        end
    end
end
