using Test
using Reseau

function wait_for_flag(flag; timeout_s::Float64 = 5.0)
    start = Base.time_ns()
    timeout_ns = Int(timeout_s * 1_000_000_000)
    while (Base.time_ns() - start) < timeout_ns
        if flag[]
            return true
        end
        sleep(0.01)
    end
    return false
end

function _mem_from_bytes(bytes::NTuple{16, UInt8})
    mem = Memory{UInt8}(undef, 16)
    for i in 1:16
        mem[i] = bytes[i]
    end
    return mem
end

function _is_allowed_connect_error(code::Int)
    return code == Reseau.ERROR_IO_SOCKET_TIMEOUT ||
        code == Reseau.ERROR_IO_SOCKET_NO_ROUTE_TO_HOST ||
        code == Reseau.ERROR_IO_SOCKET_NETWORK_DOWN ||
        code == Reseau.ERROR_IO_SOCKET_CONNECTION_REFUSED
end

@testset "socket validate port" begin
    @test Reseau.socket_validate_port_for_connect(80, Reseau.SocketDomain.IPV4) === nothing
    @test Reseau.socket_validate_port_for_bind(80, Reseau.SocketDomain.IPV4) === nothing

    res = Reseau.socket_validate_port_for_connect(0, Reseau.SocketDomain.IPV4)
    @test res isa Reseau.ErrorResult
    res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS
    @test Reseau.socket_validate_port_for_bind(0, Reseau.SocketDomain.IPV4) === nothing

    res = Reseau.socket_validate_port_for_connect(0xFFFFFFFF, Reseau.SocketDomain.IPV4)
    @test res isa Reseau.ErrorResult
    res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS

    res = Reseau.socket_validate_port_for_bind(0xFFFFFFFF, Reseau.SocketDomain.IPV4)
    @test res isa Reseau.ErrorResult
    res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS

    @test Reseau.socket_validate_port_for_connect(80, Reseau.SocketDomain.IPV6) === nothing
    @test Reseau.socket_validate_port_for_bind(80, Reseau.SocketDomain.IPV6) === nothing

    res = Reseau.socket_validate_port_for_connect(0, Reseau.SocketDomain.IPV6)
    @test res isa Reseau.ErrorResult
    res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS
    @test Reseau.socket_validate_port_for_bind(0, Reseau.SocketDomain.IPV6) === nothing

    res = Reseau.socket_validate_port_for_connect(0xFFFFFFFF, Reseau.SocketDomain.IPV6)
    @test res isa Reseau.ErrorResult
    res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS

    res = Reseau.socket_validate_port_for_bind(0xFFFFFFFF, Reseau.SocketDomain.IPV6)
    @test res isa Reseau.ErrorResult
    res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS

    @test Reseau.socket_validate_port_for_connect(80, Reseau.SocketDomain.VSOCK) === nothing
    @test Reseau.socket_validate_port_for_bind(80, Reseau.SocketDomain.VSOCK) === nothing
    @test Reseau.socket_validate_port_for_connect(0, Reseau.SocketDomain.VSOCK) === nothing
    @test Reseau.socket_validate_port_for_bind(0, Reseau.SocketDomain.VSOCK) === nothing
    @test Reseau.socket_validate_port_for_connect(0x7FFFFFFF, Reseau.SocketDomain.VSOCK) === nothing
    @test Reseau.socket_validate_port_for_bind(0x7FFFFFFF, Reseau.SocketDomain.VSOCK) === nothing

    res = Reseau.socket_validate_port_for_connect(-1, Reseau.SocketDomain.VSOCK)
    @test res isa Reseau.ErrorResult
    res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS
    @test Reseau.socket_validate_port_for_bind(-1, Reseau.SocketDomain.VSOCK) === nothing

    @test Reseau.socket_validate_port_for_connect(0, Reseau.SocketDomain.LOCAL) === nothing
    @test Reseau.socket_validate_port_for_bind(0, Reseau.SocketDomain.LOCAL) === nothing
    @test Reseau.socket_validate_port_for_connect(80, Reseau.SocketDomain.LOCAL) === nothing
    @test Reseau.socket_validate_port_for_bind(80, Reseau.SocketDomain.LOCAL) === nothing
    @test Reseau.socket_validate_port_for_connect(-1, Reseau.SocketDomain.LOCAL) === nothing
    @test Reseau.socket_validate_port_for_bind(-1, Reseau.SocketDomain.LOCAL) === nothing

    bad_domain = Base.bitcast(Reseau.SocketDomain.T, UInt8(0xff))
    res = Reseau.socket_validate_port_for_connect(80, bad_domain)
    @test res isa Reseau.ErrorResult
    res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS
    res = Reseau.socket_validate_port_for_bind(80, bad_domain)
    @test res isa Reseau.ErrorResult
    res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS
end

@testset "parse ipv4 valid addresses" begin
    cases = [
        ("127.0.0.1", UInt32(0x7f000001)),
        ("0.0.0.0", UInt32(0x00000000)),
        ("255.255.255.255", UInt32(0xffffffff)),
        ("192.168.1.1", UInt32(0xc0a80101)),
        ("10.0.0.1", UInt32(0x0a000001)),
        ("172.16.0.1", UInt32(0xac100001)),
        ("8.8.8.8", UInt32(0x08080808)),
        ("1.2.3.4", UInt32(0x01020304)),
    ]

    for (input, expected) in cases
        res = Reseau.parse_ipv4_address(input)
        @test res isa UInt32
        res isa UInt32 && @test res == expected
    end
end

@testset "parse ipv4 invalid addresses" begin
    invalid = [
        "",
        "256.1.1.1",
        "1.1.1",
        "1.1.1.1.1",
        "1.1.1.a",
        "1..1.1",
        "192.168.1.-1",
        "not.an.ip.address",
        "2001:db8::1",
    ]

    for input in invalid
        res = Reseau.parse_ipv4_address(input)
        @test res isa Reseau.ErrorResult
        res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS
    end
end

@testset "parse ipv6 valid addresses" begin
    cases = [
        ("::", (0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)),
        ("2001:db8:85a3::8a2e:370:7334",
            (0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x2e, 0x03, 0x70, 0x73, 0x34)),
        ("::ffff:192.168.1.1",
            (0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x01, 0x01)),
        ("fe80::1",
            (0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01)),
    ]

    for (input, bytes) in cases
        buf = Reseau.ByteBuffer(16)
        res = Reseau.parse_ipv6_address!(input, buf)
        @test res === nothing
        expected = _mem_from_bytes(bytes)
        cursor = Reseau.ByteCursor(expected)
        @test Reseau.byte_cursor_eq_byte_buf(cursor, buf)
    end
end

@testset "parse ipv6 invalid addresses" begin
    invalid = [
        "",
        ":::",
        "2001:db8:85a3::8a2e::7334",
        "2001:db8:85a3:0000:0000:8a2e:0370:7334:extra",
        "2001:db8:85a3:0000:0000:8a2e:0370:733g",
        "192.168.1.1",
        "not:an:ipv6:address",
        "gggg::1",
    ]

    for input in invalid
        buf = Reseau.ByteBuffer(16)
        res = Reseau.parse_ipv6_address!(input, buf)
        @test res isa Reseau.ErrorResult
        res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS
    end
end

function _mem_from_bytes(bytes::NTuple{16, UInt8})
    mem = Memory{UInt8}(undef, 16)
    for i in 1:16
        mem[i] = bytes[i]
    end
    return mem
end

@testset "message pool" begin
    args = Reseau.MessagePoolCreationArgs(
        application_data_msg_data_size = 128,
        application_data_msg_count = 2,
        small_block_msg_data_size = 16,
        small_block_msg_count = 2,
    )
    pool = Reseau.MessagePool(args)
    @test pool isa Reseau.MessagePool
    @test length(pool.application_data_pool) == 2
    @test length(pool.small_block_pool) == 2

    msg = Reseau.message_pool_acquire(pool, Reseau.IoMessageType.APPLICATION_DATA, 8)
    @test msg isa Reseau.IoMessage
    @test length(pool.small_block_pool) == 1
    @test Reseau.capacity(msg.message_data) == Csize_t(8)

    Reseau.message_pool_release!(pool, msg)
    @test length(pool.small_block_pool) == 2
end

@testset "memory pool" begin
    pool = Reseau.MemoryPool(2, 32)
    @test length(pool) == 2

    seg1 = Reseau.memory_pool_acquire(pool)
    seg2 = Reseau.memory_pool_acquire(pool)
    @test length(pool) == 0
    @test length(seg1) == 32
    @test length(seg2) == 32

    seg3 = Reseau.memory_pool_acquire(pool)
    @test length(pool) == 0
    @test length(seg3) == 32

    Reseau.memory_pool_release!(pool, seg1)
    @test length(pool) == 1
    Reseau.memory_pool_release!(pool, seg2)
    @test length(pool) == 2
    Reseau.memory_pool_release!(pool, seg3)
    @test length(pool) == 2
end

@testset "socket interface options" begin
    if Sys.iswindows()
        @test !Reseau.is_network_interface_name_valid("lo")
    else
        long_name = repeat("a", Reseau.NETWORK_INTERFACE_NAME_MAX)
        @test !Reseau.is_network_interface_name_valid(long_name)
        @test !Reseau.is_network_interface_name_valid("definitely_not_an_iface")

        opts = Reseau.SocketOptions(;
            type = Reseau.SocketType.STREAM,
            domain = Reseau.SocketDomain.IPV4,
            network_interface_name = long_name,
        )
        res = Reseau.socket_init(opts)
        @test res isa Reseau.ErrorResult
        if res isa Reseau.ErrorResult
            # POSIX path returns INVALID_OPTIONS for bad interface name length;
            # NW path (macOS IPV4/IPV6) returns PLATFORM_NOT_SUPPORTED for any interface name
            @test res.code == Reseau.ERROR_IO_SOCKET_INVALID_OPTIONS || res.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
        end
    end
end

@testset "socket bind to interface" begin
    if Sys.iswindows()
        @test true
    else
        iface = Sys.islinux() ? "lo" : (Sys.isapple() ? "lo0" : "")
        if isempty(iface)
            @test true
            return
        end
        if !Reseau.is_network_interface_name_valid(iface)
            @test true
            return
        end

        # IPv4 stream
        el = Reseau.event_loop_new(Reseau.EventLoopOptions())
        el_val = el isa Reseau.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test Reseau.event_loop_run!(el_val) === nothing

        opts = Reseau.SocketOptions(;
            type = Reseau.SocketType.STREAM,
            domain = Reseau.SocketDomain.IPV4,
            connect_timeout_ms = 3000,
            keepalive = true,
            keep_alive_interval_sec = 1000,
            keep_alive_timeout_sec = 60000,
            network_interface_name = iface,
        )

        server = Reseau.socket_init(opts)
        server_socket = server isa Reseau.Socket ? server : nothing
        if server isa Reseau.ErrorResult
            @test server.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED ||
                server.code == Reseau.ERROR_IO_SOCKET_INVALID_OPTIONS
            Reseau.event_loop_destroy!(el_val)
            return
        end

        client_socket = nothing
        accepted = Ref{Any}(nothing)

        try
            bind_opts = Reseau.SocketBindOptions(Reseau.SocketEndpoint("127.0.0.1", 0))
            bind_res = Reseau.socket_bind(server_socket, bind_opts)
            if bind_res isa Reseau.ErrorResult
                @test bind_res.code == Reseau.ERROR_IO_SOCKET_INVALID_OPTIONS ||
                    bind_res.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
                return
            end
            listen_res = Reseau.socket_listen(server_socket, 1024)
            if listen_res isa Reseau.ErrorResult
                @test listen_res.code == Reseau.ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY ||
                    listen_res.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
                return
            end

            bound = Reseau.socket_get_bound_address(server_socket)
            @test bound isa Reseau.SocketEndpoint
            port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                return
            end

            accept_err = Ref{Int}(0)
            read_err = Ref{Int}(0)
            payload = Ref{String}("")
            read_done = Threads.Atomic{Bool}(false)

            connect_err = Ref{Int}(0)
            connect_done = Threads.Atomic{Bool}(false)
            write_err = Ref{Int}(0)
            write_done = Threads.Atomic{Bool}(false)

            on_accept = (listener, err, new_sock, ud) -> begin
                accept_err[] = err
                accepted[] = new_sock
                if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
                    read_done[] = true
                    return nothing
                end

                assign_res = Reseau.socket_assign_to_event_loop(new_sock, el_val)
                if assign_res isa Reseau.ErrorResult
                    read_err[] = assign_res.code
                    read_done[] = true
                    return nothing
                end

                sub_res = Reseau.socket_subscribe_to_readable_events(
                    new_sock, (sock, err, ud) -> begin
                        read_err[] = err
                        if err != Reseau.AWS_OP_SUCCESS
                            read_done[] = true
                            return nothing
                        end

                        buf = Reseau.ByteBuffer(64)
                        read_res = Reseau.socket_read(sock, buf)
                        if read_res isa Reseau.ErrorResult
                            read_err[] = read_res.code
                        else
                            payload[] = String(Reseau.byte_cursor_from_buf(buf))
                        end
                        read_done[] = true
                        return nothing
                    end, nothing
                )

                if sub_res isa Reseau.ErrorResult
                    read_err[] = sub_res.code
                    read_done[] = true
                end
                return nothing
            end

            accept_opts = Reseau.SocketListenerOptions(on_accept_result = on_accept)
            @test Reseau.socket_start_accept(server_socket, el_val, accept_opts) === nothing

            client = Reseau.socket_init(opts)
            client_socket = client isa Reseau.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            connect_opts = Reseau.SocketConnectOptions(
                Reseau.SocketEndpoint("127.0.0.1", port);
                event_loop = el_val,
                on_connection_result = (sock, err, ud) -> begin
                    connect_err[] = err
                    connect_done[] = true
                    if err != Reseau.AWS_OP_SUCCESS
                        return nothing
                    end

                    cursor = Reseau.ByteCursor("ping")
                    write_res = Reseau.socket_write(
                        sock, cursor, (s, err, bytes, ud) -> begin
                            write_err[] = err
                            write_done[] = true
                            return nothing
                        end, nothing
                    )

                    if write_res isa Reseau.ErrorResult
                        write_err[] = write_res.code
                        write_done[] = true
                    end
                    return nothing
                end,
            )

            @test Reseau.socket_connect(client_socket, connect_opts) === nothing
            @test wait_for_flag(connect_done)
            @test connect_err[] == Reseau.AWS_OP_SUCCESS
            @test wait_for_flag(write_done)
            @test write_err[] == Reseau.AWS_OP_SUCCESS
            @test wait_for_flag(read_done)
            @test accept_err[] == Reseau.AWS_OP_SUCCESS
            @test read_err[] == Reseau.AWS_OP_SUCCESS
            @test payload[] == "ping"
        finally
            if client_socket !== nothing
                Reseau.socket_cleanup!(client_socket)
            end
            if accepted[] !== nothing
                Reseau.socket_cleanup!(accepted[])
            end
            Reseau.socket_cleanup!(server_socket)
            Reseau.event_loop_destroy!(el_val)
        end

        # IPv4 UDP
        el = Reseau.event_loop_new(Reseau.EventLoopOptions())
        el_val = el isa Reseau.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test Reseau.event_loop_run!(el_val) === nothing

        opts_udp = Reseau.SocketOptions(;
            type = Reseau.SocketType.DGRAM,
            domain = Reseau.SocketDomain.IPV4,
            connect_timeout_ms = 3000,
            network_interface_name = iface,
        )

        server = Reseau.socket_init(opts_udp)
        server_socket = server isa Reseau.Socket ? server : nothing
        if server isa Reseau.ErrorResult
            @test server.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED ||
                server.code == Reseau.ERROR_IO_SOCKET_INVALID_OPTIONS
            Reseau.event_loop_destroy!(el_val)
            return
        end

        client_socket = nothing
        try
            bind_opts = Reseau.SocketBindOptions(Reseau.SocketEndpoint("127.0.0.1", 0))
            bind_res = Reseau.socket_bind(server_socket, bind_opts)
            if bind_res isa Reseau.ErrorResult
                @test bind_res.code == Reseau.ERROR_IO_SOCKET_INVALID_OPTIONS ||
                    bind_res.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
                return
            end

            bound = Reseau.socket_get_bound_address(server_socket)
            @test bound isa Reseau.SocketEndpoint
            port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                return
            end

            client = Reseau.socket_init(opts_udp)
            client_socket = client isa Reseau.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            connect_opts = Reseau.SocketConnectOptions(
                Reseau.SocketEndpoint("127.0.0.1", port);
                event_loop = el_val,
                on_connection_result = (sock, err, ud) -> nothing,
            )

            @test Reseau.socket_connect(client_socket, connect_opts) === nothing
        finally
            if client_socket !== nothing
                Reseau.socket_cleanup!(client_socket)
            end
            Reseau.socket_cleanup!(server_socket)
            Reseau.event_loop_destroy!(el_val)
        end

        # IPv6 stream
        el = Reseau.event_loop_new(Reseau.EventLoopOptions())
        el_val = el isa Reseau.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test Reseau.event_loop_run!(el_val) === nothing

        opts6 = Reseau.SocketOptions(;
            type = Reseau.SocketType.STREAM,
            domain = Reseau.SocketDomain.IPV6,
            connect_timeout_ms = 3000,
            network_interface_name = iface,
        )

        server = Reseau.socket_init(opts6)
        server_socket = server isa Reseau.Socket ? server : nothing
        if server isa Reseau.ErrorResult
            @test server.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED ||
                server.code == Reseau.ERROR_IO_SOCKET_INVALID_OPTIONS
            Reseau.event_loop_destroy!(el_val)
            return
        end

        client_socket = nothing
        accepted = Ref{Any}(nothing)

        try
            bind_opts = Reseau.SocketBindOptions(Reseau.SocketEndpoint("::1", 0))
            bind_res = Reseau.socket_bind(server_socket, bind_opts)
            if bind_res isa Reseau.ErrorResult
                @test bind_res.code == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS
                return
            end
            @test Reseau.socket_listen(server_socket, 1024) === nothing

            bound = Reseau.socket_get_bound_address(server_socket)
            @test bound isa Reseau.SocketEndpoint
            port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                return
            end

            accept_err = Ref{Int}(0)
            connect_err = Ref{Int}(0)
            connect_done = Threads.Atomic{Bool}(false)

            on_accept = (listener, err, new_sock, ud) -> begin
                accept_err[] = err
                accepted[] = new_sock
                return nothing
            end

            accept_opts = Reseau.SocketListenerOptions(on_accept_result = on_accept)
            @test Reseau.socket_start_accept(server_socket, el_val, accept_opts) === nothing

            client = Reseau.socket_init(opts6)
            client_socket = client isa Reseau.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            connect_opts = Reseau.SocketConnectOptions(
                Reseau.SocketEndpoint("::1", port);
                event_loop = el_val,
                on_connection_result = (sock, err, ud) -> begin
                    connect_err[] = err
                    connect_done[] = true
                    return nothing
                end,
            )

            @test Reseau.socket_connect(client_socket, connect_opts) === nothing
            @test wait_for_flag(connect_done)
            @test connect_err[] == Reseau.AWS_OP_SUCCESS
            @test accept_err[] == Reseau.AWS_OP_SUCCESS
        finally
            if client_socket !== nothing
                Reseau.socket_cleanup!(client_socket)
            end
            if accepted[] !== nothing
                Reseau.socket_cleanup!(accepted[])
            end
            Reseau.socket_cleanup!(server_socket)
            Reseau.event_loop_destroy!(el_val)
        end
    end
end

@testset "socket bind to invalid interface" begin
    if Sys.iswindows()
        @test true
    else
        opts = Reseau.SocketOptions(;
            type = Reseau.SocketType.STREAM,
            domain = Reseau.SocketDomain.IPV4,
            connect_timeout_ms = 3000,
            keepalive = true,
            keep_alive_interval_sec = 1000,
            keep_alive_timeout_sec = 60000,
            network_interface_name = "invalid",
        )

        res = Reseau.socket_init(opts)
        @test res isa Reseau.ErrorResult
        if res isa Reseau.ErrorResult
            @test res.code == Reseau.ERROR_IO_SOCKET_INVALID_OPTIONS ||
                res.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
        end
    end
end

@testset "vsock loopback socket communication" begin
    if !Sys.islinux()
        @test true
    else
        el = Reseau.event_loop_new(Reseau.EventLoopOptions())
        el_val = el isa Reseau.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test Reseau.event_loop_run!(el_val) === nothing

        opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.VSOCK, connect_timeout_ms = 3000)
        server = Reseau.socket_init(opts)
        server_socket = server isa Reseau.Socket ? server : nothing
        if server isa Reseau.ErrorResult
            @test server.code == Reseau.ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY ||
                server.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED ||
                server.code == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS
            Reseau.event_loop_destroy!(el_val)
            return
        end

        client_socket = nothing
        accepted = Ref{Any}(nothing)

        try
            bind_opts = Reseau.SocketBindOptions(Reseau.SocketEndpoint("1", 0))
            bind_res = Reseau.socket_bind(server_socket, bind_opts)
            if bind_res isa Reseau.ErrorResult
                @test bind_res.code == Reseau.ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY ||
                    bind_res.code == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS
                return
            end
            @test Reseau.socket_listen(server_socket, 1024) === nothing

            bound = Reseau.socket_get_bound_address(server_socket)
            @test bound isa Reseau.SocketEndpoint
            port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                return
            end

            accept_err = Ref{Int}(0)
            connect_err = Ref{Int}(0)
            connect_done = Threads.Atomic{Bool}(false)

            on_accept = (listener, err, new_sock, ud) -> begin
                accept_err[] = err
                accepted[] = new_sock
                return nothing
            end

            accept_opts = Reseau.SocketListenerOptions(on_accept_result = on_accept)
            @test Reseau.socket_start_accept(server_socket, el_val, accept_opts) === nothing

            client = Reseau.socket_init(opts)
            client_socket = client isa Reseau.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            connect_opts = Reseau.SocketConnectOptions(
                Reseau.SocketEndpoint("1", port);
                event_loop = el_val,
                on_connection_result = (sock, err, ud) -> begin
                    connect_err[] = err
                    connect_done[] = true
                    return nothing
                end,
            )

            connect_res = Reseau.socket_connect(client_socket, connect_opts)
            if connect_res isa Reseau.ErrorResult
                @test _is_allowed_connect_error(connect_res.code) ||
                    connect_res.code == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS ||
                    connect_res.code == Reseau.ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY
                return
            end
            @test wait_for_flag(connect_done)
            if connect_err[] != Reseau.AWS_OP_SUCCESS
                @test _is_allowed_connect_error(connect_err[]) ||
                    connect_err[] == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS
            else
                @test accept_err[] == Reseau.AWS_OP_SUCCESS
            end
        finally
            if client_socket !== nothing
                Reseau.socket_cleanup!(client_socket)
            end
            if accepted[] !== nothing
                Reseau.socket_cleanup!(accepted[])
            end
            Reseau.socket_cleanup!(server_socket)
            Reseau.event_loop_destroy!(el_val)
        end
    end
end

@testset "socket init domain-based selection" begin
    # IPV4 socket
    opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4)
    sock = Reseau.socket_init(opts)
    @test sock isa Reseau.Socket
    if sock isa Reseau.Socket
        @static if Sys.isapple()
            @test sock.impl isa Reseau.NWSocket
        elseif Sys.iswindows()
            @test sock.impl isa Reseau.WinsockSocket
        else
            @test sock.impl isa Reseau.PosixSocket
        end
        Reseau.socket_close(sock)
    end

    # LOCAL domain
    local_opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.LOCAL)
    local_sock = Reseau.socket_init(local_opts)
    @test local_sock isa Reseau.Socket
    if local_sock isa Reseau.Socket
        @static if Sys.iswindows()
            @test local_sock.impl isa Reseau.WinsockSocket
        else
            @test local_sock.impl isa Reseau.PosixSocket
        end
        Reseau.socket_close(local_sock)
    end
end

@testset "winsock stubs" begin
    res = Reseau.winsock_check_and_init!()
    if Sys.iswindows()
        @test res isa Reseau.ErrorResult || res === nothing
    else
        @test res isa Reseau.ErrorResult
        res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
    end

    res = Reseau.winsock_get_connectex_fn()
    @test res isa Reseau.ErrorResult || res isa Ptr
    res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED

    res = Reseau.winsock_get_acceptex_fn()
    @test res isa Reseau.ErrorResult || res isa Ptr
    res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
end

@testset "socket nonblocking cloexec" begin
    if Sys.iswindows()
        @test true
    else
        opts = Reseau.SocketOptions(;
            type = Reseau.SocketType.STREAM,
            domain = Reseau.SocketDomain.IPV4,
        )
        sock = Reseau.socket_init(opts)
        @test sock isa Reseau.Socket
        if sock isa Reseau.Socket
            fd = sock.io_handle.fd
            flags = Reseau._fcntl(fd, Reseau.F_GETFL)
            @test (flags & Reseau.O_NONBLOCK) != 0
            fd_flags = Reseau._fcntl(fd, Reseau.F_GETFD)
            @test (fd_flags & Reseau.FD_CLOEXEC) != 0
            Reseau.socket_close(sock)
        end
    end
end

@testset "socket connect read write" begin
    el = Reseau.event_loop_new(Reseau.EventLoopOptions())
    el_val = el isa Reseau.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test Reseau.event_loop_run!(el_val) === nothing
    # Use LOCAL domain to ensure POSIX path (standalone event loop, no ELG)
    opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.LOCAL)
    server = Reseau.socket_init(opts)
    server_socket = server isa Reseau.Socket ? server : nothing
    @test server_socket !== nothing

    client_socket = nothing
    accepted = Ref{Any}(nothing)

    local_endpoint = Reseau.SocketEndpoint()
    Reseau.socket_endpoint_init_local_address_for_test!(local_endpoint)

    try
        if server_socket === nothing
            return
        end

        bind_opts = Reseau.SocketBindOptions(local_endpoint)
        @test Reseau.socket_bind(server_socket, bind_opts) === nothing
        @test Reseau.socket_listen(server_socket, 8) === nothing

        accept_err = Ref{Int}(0)
        read_err = Ref{Int}(0)
        payload = Ref{String}("")
        read_done = Threads.Atomic{Bool}(false)

        connect_err = Ref{Int}(0)
        connect_done = Threads.Atomic{Bool}(false)
        write_err = Ref{Int}(0)
        write_done = Threads.Atomic{Bool}(false)

        on_accept = (listener, err, new_sock, ud) -> begin
            accept_err[] = err
            accepted[] = new_sock
            if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
                read_done[] = true
                return nothing
            end

            assign_res = Reseau.socket_assign_to_event_loop(new_sock, el_val)
            if assign_res isa Reseau.ErrorResult
                read_err[] = assign_res.code
                read_done[] = true
                return nothing
            end

            sub_res = Reseau.socket_subscribe_to_readable_events(
                new_sock, (sock, err, ud) -> begin
                    read_err[] = err
                    if err != Reseau.AWS_OP_SUCCESS
                        read_done[] = true
                        return nothing
                    end

                    buf = Reseau.ByteBuffer(64)
                    read_res = Reseau.socket_read(sock, buf)
                    if read_res isa Reseau.ErrorResult
                        read_err[] = read_res.code
                    else
                        payload[] = String(Reseau.byte_cursor_from_buf(buf))
                    end
                    read_done[] = true
                    return nothing
                end, nothing
            )

            if sub_res isa Reseau.ErrorResult
                read_err[] = sub_res.code
                read_done[] = true
            end
            return nothing
        end

        accept_opts = Reseau.SocketListenerOptions(on_accept_result = on_accept)
        @test Reseau.socket_start_accept(server_socket, el_val, accept_opts) === nothing

        client = Reseau.socket_init(opts)
        client_socket = client isa Reseau.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end
        connect_opts = Reseau.SocketConnectOptions(
            local_endpoint;
            event_loop = el_val,
            on_connection_result = (sock, err, ud) -> begin
                connect_err[] = err
                connect_done[] = true
                if err != Reseau.AWS_OP_SUCCESS
                    return nothing
                end

                cursor = Reseau.ByteCursor("ping")
                write_res = Reseau.socket_write(
                    sock, cursor, (s, err, bytes, ud) -> begin
                        write_err[] = err
                        write_done[] = true
                        return nothing
                    end, nothing
                )

                if write_res isa Reseau.ErrorResult
                    write_err[] = write_res.code
                    write_done[] = true
                end

                return nothing
            end,
        )

        @test Reseau.socket_connect(client_socket, connect_opts) === nothing
        @test wait_for_flag(connect_done)
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag(write_done)
        @test write_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag(read_done)
        @test accept_err[] == Reseau.AWS_OP_SUCCESS
        @test read_err[] == Reseau.AWS_OP_SUCCESS
        @test payload[] == "ping"
    finally
        if client_socket !== nothing
            Reseau.socket_close(client_socket)
        end
        if accepted[] !== nothing
            Reseau.socket_close(accepted[])
        end
        if server_socket !== nothing
            Reseau.socket_close(server_socket)
        end
        Reseau.event_loop_destroy!(el_val)
        # Clean up Unix domain socket file (Windows LOCAL uses named pipes, not a filesystem path).
        @static if !Sys.iswindows()
            sock_path = Reseau.get_address(local_endpoint)
            isfile(sock_path) && rm(sock_path; force=true)
        end
    end
end

@testset "nw socket connect read write" begin
    @static if !Sys.isapple()
        @test true
        return
    end

    elg = Reseau.event_loop_group_new(Reseau.EventLoopGroupOptions(;
        loop_count = 1,
    ))
    elg_val = elg isa Reseau.EventLoopGroup ? elg : nothing
    @test elg_val !== nothing
    if elg_val === nothing
        return
    end
    el_val = Reseau.event_loop_group_get_next_loop(elg_val)
    @test el_val isa Reseau.EventLoop
    if !(el_val isa Reseau.EventLoop)
        Reseau.event_loop_group_destroy!(elg_val)
        return
    end

    opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4)
    server = Reseau.socket_init(opts)
    server_socket = server isa Reseau.Socket ? server : nothing
    @test server_socket !== nothing

    client_socket = nothing
    accepted = Ref{Any}(nothing)

    accept_err = Ref{Int}(0)
    read_err = Ref{Int}(0)
    payload = Ref{String}("")
    read_done = Threads.Atomic{Bool}(false)

    connect_err = Ref{Int}(0)
    connect_done = Threads.Atomic{Bool}(false)
    write_err = Ref{Int}(0)
    write_done = Threads.Atomic{Bool}(false)

    port_ref = Ref{Int}(0)
    accept_started = Threads.Atomic{Bool}(false)

    try
        if server_socket === nothing
            return
        end

        bind_opts = Reseau.SocketBindOptions(Reseau.SocketEndpoint("127.0.0.1", 0))
        @test Reseau.socket_bind(server_socket, bind_opts) === nothing
        @test Reseau.socket_listen(server_socket, 8) === nothing

        on_accept_started = (listener, err, ud) -> begin
            accept_started[] = true
            if err == Reseau.AWS_OP_SUCCESS && listener !== nothing
                bound = Reseau.socket_get_bound_address(listener)
                if bound isa Reseau.SocketEndpoint
                    port_ref[] = Int(bound.port)
                end
            end
            return nothing
        end

        on_accept = (listener, err, new_sock, ud) -> begin
            accept_err[] = err
            accepted[] = new_sock
            if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
                read_done[] = true
                return nothing
            end

            assign_res = Reseau.socket_assign_to_event_loop(new_sock, el_val)
            if assign_res isa Reseau.ErrorResult
                read_err[] = assign_res.code
                read_done[] = true
                return nothing
            end

            sub_res = Reseau.socket_subscribe_to_readable_events(
                new_sock, (sock, err, ud) -> begin
                    read_err[] = err
                    if err != Reseau.AWS_OP_SUCCESS
                        read_done[] = true
                        return nothing
                    end

                    buf = Reseau.ByteBuffer(64)
                    read_res = Reseau.socket_read(sock, buf)
                    if read_res isa Reseau.ErrorResult
                        read_err[] = read_res.code
                    else
                        payload[] = String(Reseau.byte_cursor_from_buf(buf))
                    end
                    read_done[] = true
                    return nothing
                end, nothing
            )

            if sub_res isa Reseau.ErrorResult
                read_err[] = sub_res.code
                read_done[] = true
            end
            return nothing
        end

        accept_opts = Reseau.SocketListenerOptions(
            on_accept_result = on_accept,
            on_accept_start = on_accept_started,
        )
        @test Reseau.socket_start_accept(server_socket, el_val, accept_opts) === nothing

        @test wait_for_flag(accept_started)
        @test port_ref[] != 0

        client = Reseau.socket_init(opts)
        client_socket = client isa Reseau.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end

        connect_opts = Reseau.SocketConnectOptions(
            Reseau.SocketEndpoint("127.0.0.1", port_ref[]);
            event_loop = el_val,
            on_connection_result = (sock, err, ud) -> begin
                connect_err[] = err
                connect_done[] = true
                if err != Reseau.AWS_OP_SUCCESS
                    return nothing
                end

                cursor = Reseau.ByteCursor("ping")
                write_res = Reseau.socket_write(
                    sock, cursor, (s, err, bytes, ud) -> begin
                        write_err[] = err
                        write_done[] = true
                        return nothing
                    end, nothing
                )

                if write_res isa Reseau.ErrorResult
                    write_err[] = write_res.code
                    write_done[] = true
                end
                return nothing
            end,
        )

        @test Reseau.socket_connect(client_socket, connect_opts) === nothing
        @test wait_for_flag(connect_done)
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag(write_done)
        @test write_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag(read_done)
        @test accept_err[] == Reseau.AWS_OP_SUCCESS
        @test read_err[] == Reseau.AWS_OP_SUCCESS
        @test payload[] == "ping"
    finally
        if client_socket !== nothing
            Reseau.socket_close(client_socket)
        end
        if accepted[] !== nothing
            Reseau.socket_close(accepted[])
        end
        if server_socket !== nothing
            Reseau.socket_close(server_socket)
        end
        Reseau.event_loop_destroy!(el_val)
    end
end

@testset "sock write cb is async" begin
    el = Reseau.event_loop_new(Reseau.EventLoopOptions())
    el_val = el isa Reseau.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test Reseau.event_loop_run!(el_val) === nothing

    opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4)
    server = Reseau.socket_init(opts)
    server_socket = server isa Reseau.Socket ? server : nothing
    @test server_socket !== nothing

    client_socket = nothing
    accepted = Ref{Any}(nothing)

    try
        if server_socket === nothing
            return
        end

        bind_opts = Reseau.SocketBindOptions(Reseau.SocketEndpoint("127.0.0.1", 0))
        @test Reseau.socket_bind(server_socket, bind_opts) === nothing
        @test Reseau.socket_listen(server_socket, 8) === nothing

        bound = Reseau.socket_get_bound_address(server_socket)
        @test bound isa Reseau.SocketEndpoint
        port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
        if port == 0
            return
        end

        accept_done = Threads.Atomic{Bool}(false)
        on_accept = (listener, err, new_sock, ud) -> begin
            accepted[] = new_sock
            accept_done[] = true
            if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
                return nothing
            end
            assign_res = Reseau.socket_assign_to_event_loop(new_sock, el_val)
            if assign_res isa Reseau.ErrorResult
                return nothing
            end
            _ = Reseau.socket_subscribe_to_readable_events(
                new_sock, (sock, err, ud) -> begin
                    if err != Reseau.AWS_OP_SUCCESS
                        return nothing
                    end
                    buf = Reseau.ByteBuffer(64)
                    _ = Reseau.socket_read(sock, buf)
                    return nothing
                end, nothing
            )
            return nothing
        end

        accept_opts = Reseau.SocketListenerOptions(on_accept_result = on_accept)
        @test Reseau.socket_start_accept(server_socket, el_val, accept_opts) === nothing

        client = Reseau.socket_init(opts)
        client_socket = client isa Reseau.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end

        connect_done = Threads.Atomic{Bool}(false)
        write_started = Threads.Atomic{Bool}(false)
        write_cb_invoked = Threads.Atomic{Bool}(false)
        write_cb_sync = Threads.Atomic{Bool}(false)
        write_err = Ref{Int}(0)

        connect_opts = Reseau.SocketConnectOptions(
            Reseau.SocketEndpoint("127.0.0.1", port);
            event_loop = el_val,
            on_connection_result = (sock, err, ud) -> begin
                connect_done[] = true
                if err != Reseau.AWS_OP_SUCCESS
                    write_started[] = true
                    return nothing
                end
                cursor = Reseau.ByteCursor("ping")
                write_cb_invoked[] = false
                write_cb_sync[] = false
                write_res = Reseau.socket_write(
                    sock, cursor, (s, err, bytes, ud) -> begin
                        write_err[] = err
                        write_cb_invoked[] = true
                        return nothing
                    end, nothing
                )
                if write_res isa Reseau.ErrorResult
                    write_err[] = write_res.code
                    write_cb_invoked[] = true
                end
                if write_cb_invoked[]
                    write_cb_sync[] = true
                end
                write_started[] = true
                return nothing
            end,
        )

        @test Reseau.socket_connect(client_socket, connect_opts) === nothing
        @test wait_for_flag(connect_done)
        @test wait_for_flag(accept_done)
        @test wait_for_flag(write_started)
        @test wait_for_flag(write_cb_invoked)
        @test !write_cb_sync[]
        @test write_err[] == Reseau.AWS_OP_SUCCESS
    finally
        if client_socket !== nothing
            Reseau.socket_close(client_socket)
        end
        if accepted[] !== nothing
            Reseau.socket_close(accepted[])
        end
        if server_socket !== nothing
            Reseau.socket_close(server_socket)
        end
        Reseau.event_loop_destroy!(el_val)
    end
end

@testset "connect timeout" begin
    elg = Reseau.event_loop_group_new(Reseau.EventLoopGroupOptions(; loop_count = 1))
    elg_val = elg isa Reseau.EventLoopGroup ? elg : nothing
    @test elg_val !== nothing
    if elg_val === nothing
        return
    end
    el_val = Reseau.event_loop_group_get_next_loop(elg_val)
    @test el_val isa Reseau.EventLoop
    if !(el_val isa Reseau.EventLoop)
        Reseau.event_loop_group_destroy!(elg_val)
        return
    end

    opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4, connect_timeout_ms = 200)
    sock = Reseau.socket_init(opts)
    socket_val = sock isa Reseau.Socket ? sock : nothing
    @test socket_val !== nothing
    if socket_val === nothing
        Reseau.event_loop_group_destroy!(elg_val)
        return
    end

    connect_done = Threads.Atomic{Bool}(false)
    connect_err = Ref{Int}(0)
    endpoint = Reseau.SocketEndpoint("10.255.255.1", 81)
    connect_opts = Reseau.SocketConnectOptions(
        endpoint;
        event_loop = el_val,
        on_connection_result = (sock, err, ud) -> begin
            connect_err[] = err
            connect_done[] = true
            return nothing
        end,
    )

    try
        res = Reseau.socket_connect(socket_val, connect_opts)
        if res isa Reseau.ErrorResult
            @test _is_allowed_connect_error(res.code)
        else
            @test wait_for_flag(connect_done; timeout_s = 3.0)
            @test _is_allowed_connect_error(connect_err[])
        end
    finally
        Reseau.socket_cleanup!(socket_val)
        Reseau.event_loop_group_destroy!(elg_val)
    end
end

@testset "connect timeout cancellation" begin
    elg = Reseau.event_loop_group_new(Reseau.EventLoopGroupOptions(; loop_count = 1))
    elg_val = elg isa Reseau.EventLoopGroup ? elg : nothing
    @test elg_val !== nothing
    if elg_val === nothing
        return
    end
    el_val = Reseau.event_loop_group_get_next_loop(elg_val)
    @test el_val isa Reseau.EventLoop
    if !(el_val isa Reseau.EventLoop)
        Reseau.event_loop_group_destroy!(elg_val)
        return
    end

    opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4, connect_timeout_ms = 10_000)
    sock = Reseau.socket_init(opts)
    socket_val = sock isa Reseau.Socket ? sock : nothing
    @test socket_val !== nothing
    if socket_val === nothing
        Reseau.event_loop_group_destroy!(elg_val)
        return
    end

    connect_done = Threads.Atomic{Bool}(false)
    connect_err = Ref{Int}(0)
    endpoint = Reseau.SocketEndpoint("10.255.255.1", 81)
    connect_opts = Reseau.SocketConnectOptions(
        endpoint;
        event_loop = el_val,
        on_connection_result = (sock, err, ud) -> begin
            connect_err[] = err
            connect_done[] = true
            return nothing
        end,
    )

    try
        res = Reseau.socket_connect(socket_val, connect_opts)
        if res isa Reseau.ErrorResult
            @test _is_allowed_connect_error(res.code)
        else
            Reseau.event_loop_group_destroy!(elg_val)
            @test connect_done[]
            @test connect_err[] == Reseau.ERROR_IO_EVENT_LOOP_SHUTDOWN ||
                _is_allowed_connect_error(connect_err[])
        end
    finally
        Reseau.socket_cleanup!(socket_val)
    end
end

@testset "cleanup before connect or timeout" begin
    elg = Reseau.event_loop_group_new(Reseau.EventLoopGroupOptions(; loop_count = 1))
        elg_val = elg isa Reseau.EventLoopGroup ? elg : nothing
        @test elg_val !== nothing
        if elg_val === nothing
            return
        end
        el_val = Reseau.event_loop_group_get_next_loop(elg_val)
        @test el_val isa Reseau.EventLoop
        if !(el_val isa Reseau.EventLoop)
            Reseau.event_loop_group_destroy!(elg_val)
            return
        end

        opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4, connect_timeout_ms = 1000)
        sock = Reseau.socket_init(opts)
        socket_val = sock isa Reseau.Socket ? sock : nothing
        @test socket_val !== nothing
        if socket_val === nothing
            Reseau.event_loop_group_destroy!(elg_val)
            return
        end

        connect_done = Threads.Atomic{Bool}(false)
        connect_err = Ref{Int}(0)
        cleanup_done = Threads.Atomic{Bool}(false)
        endpoint = Reseau.SocketEndpoint("10.255.255.1", 81)
        connect_opts = Reseau.SocketConnectOptions(
            endpoint;
            event_loop = el_val,
            on_connection_result = (sock, err, ud) -> begin
                connect_err[] = err
                connect_done[] = true
                return nothing
            end,
        )

        cleanup_task = Reseau.ScheduledTask((ctx, status) -> begin
            Reseau.socket_cleanup!(socket_val)
            cleanup_done[] = true
            return nothing
        end, nothing; type_tag = "socket_cleanup_before_connect")

        try
            res = Reseau.socket_connect(socket_val, connect_opts)
            if res isa Reseau.ErrorResult
                @test _is_allowed_connect_error(res.code)
            else
                Reseau.event_loop_schedule_task_now!(el_val, cleanup_task)
                @test wait_for_flag(cleanup_done)
                sleep(0.05)
                if connect_done[]
                    @test _is_allowed_connect_error(connect_err[])
                else
                    @test true
                end
            end
        finally
            Reseau.socket_cleanup!(socket_val)
            Reseau.event_loop_group_destroy!(elg_val)
        end
end

@testset "cleanup in accept doesn't explode" begin
    el = Reseau.event_loop_new(Reseau.EventLoopOptions())
    el_val = el isa Reseau.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test Reseau.event_loop_run!(el_val) === nothing

    opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4)
    listener = Reseau.socket_init(opts)
    listener_socket = listener isa Reseau.Socket ? listener : nothing
    @test listener_socket !== nothing
    if listener_socket === nothing
        Reseau.event_loop_destroy!(el_val)
        return
    end

    incoming = Ref{Any}(nothing)
    accept_done = Threads.Atomic{Bool}(false)
    accept_err = Ref{Int}(0)
    connect_done = Threads.Atomic{Bool}(false)
    connect_err = Ref{Int}(0)
    client_socket = nothing

    try
        bind_opts = Reseau.SocketBindOptions(Reseau.SocketEndpoint("127.0.0.1", 0))
        @test Reseau.socket_bind(listener_socket, bind_opts) === nothing
        @test Reseau.socket_listen(listener_socket, 1024) === nothing

        bound = Reseau.socket_get_bound_address(listener_socket)
        @test bound isa Reseau.SocketEndpoint
        port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
        if port == 0
            return
        end

        on_accept = (sock, err, new_sock, ud) -> begin
            accept_err[] = err
            incoming[] = new_sock
            accept_done[] = true
            if sock !== nothing
                Reseau.socket_cleanup!(sock)
            end
            return nothing
        end

        accept_opts = Reseau.SocketListenerOptions(on_accept_result = on_accept)
        @test Reseau.socket_start_accept(listener_socket, el_val, accept_opts) === nothing

        client = Reseau.socket_init(opts)
        client_socket = client isa Reseau.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end

        connect_opts = Reseau.SocketConnectOptions(
            Reseau.SocketEndpoint("127.0.0.1", port);
            event_loop = el_val,
            on_connection_result = (sock, err, ud) -> begin
                connect_err[] = err
                connect_done[] = true
                return nothing
            end,
        )

        @test Reseau.socket_connect(client_socket, connect_opts) === nothing
        @test wait_for_flag(accept_done)
        @test wait_for_flag(connect_done)
        @test accept_err[] == Reseau.AWS_OP_SUCCESS
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
    finally
        if client_socket !== nothing
            Reseau.socket_cleanup!(client_socket)
        end
        if incoming[] !== nothing
            Reseau.socket_cleanup!(incoming[])
        end
        Reseau.socket_cleanup!(listener_socket)
        Reseau.event_loop_destroy!(el_val)
    end
end

@testset "cleanup in write cb doesn't explode" begin
    el = Reseau.event_loop_new(Reseau.EventLoopOptions())
    el_val = el isa Reseau.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test Reseau.event_loop_run!(el_val) === nothing

    opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4)
    listener = Reseau.socket_init(opts)
    listener_socket = listener isa Reseau.Socket ? listener : nothing
    @test listener_socket !== nothing
    if listener_socket === nothing
        Reseau.event_loop_destroy!(el_val)
        return
    end

    accepted = Ref{Any}(nothing)
    accept_done = Threads.Atomic{Bool}(false)
    connect_done = Threads.Atomic{Bool}(false)
    client_socket = nothing

    try
        bind_opts = Reseau.SocketBindOptions(Reseau.SocketEndpoint("127.0.0.1", 0))
        @test Reseau.socket_bind(listener_socket, bind_opts) === nothing
        @test Reseau.socket_listen(listener_socket, 1024) === nothing

        bound = Reseau.socket_get_bound_address(listener_socket)
        @test bound isa Reseau.SocketEndpoint
        port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
        if port == 0
            return
        end

        on_accept = (sock, err, new_sock, ud) -> begin
            accepted[] = new_sock
            accept_done[] = true
            return nothing
        end

        accept_opts = Reseau.SocketListenerOptions(on_accept_result = on_accept)
        @test Reseau.socket_start_accept(listener_socket, el_val, accept_opts) === nothing

        client = Reseau.socket_init(opts)
        client_socket = client isa Reseau.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end

        connect_opts = Reseau.SocketConnectOptions(
            Reseau.SocketEndpoint("127.0.0.1", port);
            event_loop = el_val,
            on_connection_result = (sock, err, ud) -> begin
                connect_done[] = true
                return nothing
            end,
        )

        @test Reseau.socket_connect(client_socket, connect_opts) === nothing
        @test wait_for_flag(accept_done)
        @test wait_for_flag(connect_done)

        server_sock = accepted[]
        @test server_sock !== nothing
        if server_sock === nothing
            return
        end

        assign_res = Reseau.socket_assign_to_event_loop(server_sock, el_val)
        @test !(assign_res isa Reseau.ErrorResult)

        write_done_client = Threads.Atomic{Bool}(false)
        write_err_client = Ref{Int}(0)
        write_done_server = Threads.Atomic{Bool}(false)
        write_err_server = Ref{Int}(0)

        write_task_client = Reseau.ScheduledTask((ctx, status) -> begin
            cursor = Reseau.ByteCursor("teapot")
            res = Reseau.socket_write(
                client_socket,
                cursor,
                (s, err, bytes, ud) -> begin
                    write_err_client[] = err
                    Reseau.socket_cleanup!(client_socket)
                    write_done_client[] = true
                    return nothing
                end,
                nothing,
            )
            if res isa Reseau.ErrorResult
                write_err_client[] = res.code
                Reseau.socket_cleanup!(client_socket)
                write_done_client[] = true
            end
            return nothing
        end, nothing; type_tag = "socket_write_cleanup_client")

        write_task_server = Reseau.ScheduledTask((ctx, status) -> begin
            cursor = Reseau.ByteCursor("spout")
            res = Reseau.socket_write(
                server_sock,
                cursor,
                (s, err, bytes, ud) -> begin
                    write_err_server[] = err
                    Reseau.socket_cleanup!(server_sock)
                    write_done_server[] = true
                    return nothing
                end,
                nothing,
            )
            if res isa Reseau.ErrorResult
                write_err_server[] = res.code
                Reseau.socket_cleanup!(server_sock)
                write_done_server[] = true
            end
            return nothing
        end, nothing; type_tag = "socket_write_cleanup_server")

        Reseau.event_loop_schedule_task_now!(el_val, write_task_client)
        @test wait_for_flag(write_done_client)
        Reseau.event_loop_schedule_task_now!(el_val, write_task_server)
        @test wait_for_flag(write_done_server)
        @test write_err_client[] == Reseau.AWS_OP_SUCCESS
        @test write_err_server[] == Reseau.AWS_OP_SUCCESS
    finally
        if client_socket !== nothing
            Reseau.socket_cleanup!(client_socket)
        end
        if accepted[] !== nothing
            Reseau.socket_cleanup!(accepted[])
        end
        Reseau.socket_cleanup!(listener_socket)
        Reseau.event_loop_destroy!(el_val)
    end
end

@testset "local socket communication" begin
    el = Reseau.event_loop_new(Reseau.EventLoopOptions())
    el_val = el isa Reseau.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test Reseau.event_loop_run!(el_val) === nothing

    opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.LOCAL)
    server = Reseau.socket_init(opts)
    server_socket = server isa Reseau.Socket ? server : nothing
    @test server_socket !== nothing

    client_socket = nothing
    accepted = Ref{Any}(nothing)
    endpoint = Reseau.SocketEndpoint()
    Reseau.socket_endpoint_init_local_address_for_test!(endpoint)
    local_path = Reseau.get_address(endpoint)

    try
        if server_socket === nothing
            return
        end

        bind_opts = Reseau.SocketBindOptions(endpoint)
        @test Reseau.socket_bind(server_socket, bind_opts) === nothing
        @test Reseau.socket_listen(server_socket, 8) === nothing

        accept_err = Ref{Int}(0)
        read_err = Ref{Int}(0)
        payload = Ref{String}("")
        read_done = Threads.Atomic{Bool}(false)

        connect_err = Ref{Int}(0)
        connect_done = Threads.Atomic{Bool}(false)
        write_err = Ref{Int}(0)
        write_done = Threads.Atomic{Bool}(false)

        on_accept = (listener, err, new_sock, ud) -> begin
            accept_err[] = err
            accepted[] = new_sock
            if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
                read_done[] = true
                return nothing
            end

            assign_res = Reseau.socket_assign_to_event_loop(new_sock, el_val)
            if assign_res isa Reseau.ErrorResult
                read_err[] = assign_res.code
                read_done[] = true
                return nothing
            end

            sub_res = Reseau.socket_subscribe_to_readable_events(
                new_sock, (sock, err, ud) -> begin
                    read_err[] = err
                    if err != Reseau.AWS_OP_SUCCESS
                        read_done[] = true
                        return nothing
                    end

                    buf = Reseau.ByteBuffer(64)
                    read_res = Reseau.socket_read(sock, buf)
                    if read_res isa Reseau.ErrorResult
                        read_err[] = read_res.code
                    else
                        payload[] = String(Reseau.byte_cursor_from_buf(buf))
                    end
                    read_done[] = true
                    return nothing
                end, nothing
            )

            if sub_res isa Reseau.ErrorResult
                read_err[] = sub_res.code
                read_done[] = true
            end
            return nothing
        end

        accept_opts = Reseau.SocketListenerOptions(on_accept_result = on_accept)
        @test Reseau.socket_start_accept(server_socket, el_val, accept_opts) === nothing

        client = Reseau.socket_init(opts)
        client_socket = client isa Reseau.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end

        connect_opts = Reseau.SocketConnectOptions(
            endpoint;
            event_loop = el_val,
            on_connection_result = (sock, err, ud) -> begin
                connect_err[] = err
                connect_done[] = true
                if err != Reseau.AWS_OP_SUCCESS
                    return nothing
                end

                cursor = Reseau.ByteCursor("ping")
                write_res = Reseau.socket_write(
                    sock, cursor, (s, err, bytes, ud) -> begin
                        write_err[] = err
                        write_done[] = true
                        return nothing
                    end, nothing
                )

                if write_res isa Reseau.ErrorResult
                    write_err[] = write_res.code
                    write_done[] = true
                end
                return nothing
            end,
        )

        @test Reseau.socket_connect(client_socket, connect_opts) === nothing
        @test wait_for_flag(connect_done)
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag(write_done)
        @test write_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag(read_done)
        @test accept_err[] == Reseau.AWS_OP_SUCCESS
        @test read_err[] == Reseau.AWS_OP_SUCCESS
        @test payload[] == "ping"
    finally
        if client_socket !== nothing
            Reseau.socket_close(client_socket)
        end
        if accepted[] !== nothing
            Reseau.socket_close(accepted[])
        end
        if server_socket !== nothing
            Reseau.socket_close(server_socket)
        end
        Reseau.event_loop_destroy!(el_val)
        if !isempty(local_path) && isfile(local_path)
            rm(local_path; force = true)
        end
    end
end

@testset "local socket connect before accept" begin
    el = Reseau.event_loop_new(Reseau.EventLoopOptions())
    el_val = el isa Reseau.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test Reseau.event_loop_run!(el_val) === nothing

    opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.LOCAL)
    server = Reseau.socket_init(opts)
    server_socket = server isa Reseau.Socket ? server : nothing
    @test server_socket !== nothing

    client_socket = nothing
    accepted = Ref{Any}(nothing)
    endpoint = Reseau.SocketEndpoint()
    Reseau.socket_endpoint_init_local_address_for_test!(endpoint)
    local_path = Reseau.get_address(endpoint)

    try
        if server_socket === nothing
            return
        end

        bind_opts = Reseau.SocketBindOptions(endpoint)
        @test Reseau.socket_bind(server_socket, bind_opts) === nothing
        @test Reseau.socket_listen(server_socket, 1024) === nothing

        accept_err = Ref{Int}(0)
        accept_done = Threads.Atomic{Bool}(false)
        connect_err = Ref{Int}(0)
        connect_done = Threads.Atomic{Bool}(false)

        client = Reseau.socket_init(opts)
        client_socket = client isa Reseau.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end

        connect_opts = Reseau.SocketConnectOptions(
            endpoint;
            event_loop = el_val,
            on_connection_result = (sock, err, ud) -> begin
                connect_err[] = err
                connect_done[] = true
                return nothing
            end,
        )

        @test Reseau.socket_connect(client_socket, connect_opts) === nothing

        on_accept = (listener, err, new_sock, ud) -> begin
            accept_err[] = err
            accepted[] = new_sock
            accept_done[] = true
            return nothing
        end

        accept_opts = Reseau.SocketListenerOptions(on_accept_result = on_accept)
        @test Reseau.socket_start_accept(server_socket, el_val, accept_opts) === nothing

        @test wait_for_flag(connect_done)
        @test wait_for_flag(accept_done)
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
        @test accept_err[] == Reseau.AWS_OP_SUCCESS
    finally
        if client_socket !== nothing
            Reseau.socket_cleanup!(client_socket)
        end
        if accepted[] !== nothing
            Reseau.socket_cleanup!(accepted[])
        end
        if server_socket !== nothing
            Reseau.socket_cleanup!(server_socket)
        end
        Reseau.event_loop_destroy!(el_val)
        if !isempty(local_path) && isfile(local_path)
            rm(local_path; force = true)
        end
    end
end

@testset "udp socket communication" begin
    el = Reseau.event_loop_new(Reseau.EventLoopOptions())
    el_val = el isa Reseau.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test Reseau.event_loop_run!(el_val) === nothing

    opts = Reseau.SocketOptions(; type = Reseau.SocketType.DGRAM, domain = Reseau.SocketDomain.IPV4)
    server = Reseau.socket_init(opts)
    server_socket = server isa Reseau.Socket ? server : nothing
    @test server_socket !== nothing

    client_socket = nothing
    try
        if server_socket === nothing
            return
        end

        bind_opts = Reseau.SocketBindOptions(Reseau.SocketEndpoint("127.0.0.1", 0))
        @test Reseau.socket_bind(server_socket, bind_opts) === nothing

        bound = Reseau.socket_get_bound_address(server_socket)
        @test bound isa Reseau.SocketEndpoint
        port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
        if port == 0
            return
        end

        assign_res = Reseau.socket_assign_to_event_loop(server_socket, el_val)
        @test !(assign_res isa Reseau.ErrorResult)

        read_err = Ref{Int}(0)
        read_done = Threads.Atomic{Bool}(false)
        payload = Ref{String}("")
        sub_res = Reseau.socket_subscribe_to_readable_events(
            server_socket, (sock, err, ud) -> begin
                read_err[] = err
                if err != Reseau.AWS_OP_SUCCESS
                    read_done[] = true
                    return nothing
                end
                    buf = Reseau.ByteBuffer(64)
                    read_res = Reseau.socket_read(sock, buf)
                    if read_res isa Reseau.ErrorResult
                        read_err[] = read_res.code
                    else
                        payload[] = String(Reseau.byte_cursor_from_buf(buf))
                    end
                    read_done[] = true
                    return nothing
            end, nothing
        )
        @test !(sub_res isa Reseau.ErrorResult)

        client = Reseau.socket_init(opts)
        client_socket = client isa Reseau.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end

        connect_err = Ref{Int}(0)
        connect_done = Threads.Atomic{Bool}(false)
        write_err = Ref{Int}(0)
        write_done = Threads.Atomic{Bool}(false)

        connect_opts = Reseau.SocketConnectOptions(
            Reseau.SocketEndpoint("127.0.0.1", port);
            event_loop = el_val,
            on_connection_result = (sock, err, ud) -> begin
                connect_err[] = err
                connect_done[] = true
                if err != Reseau.AWS_OP_SUCCESS
                    return nothing
                end
                cursor = Reseau.ByteCursor("ping")
                write_res = Reseau.socket_write(
                    sock, cursor, (s, err, bytes, ud) -> begin
                        write_err[] = err
                        write_done[] = true
                        return nothing
                    end, nothing
                )
                if write_res isa Reseau.ErrorResult
                    write_err[] = write_res.code
                    write_done[] = true
                end
                return nothing
            end,
        )

        @test Reseau.socket_connect(client_socket, connect_opts) === nothing
        @test wait_for_flag(connect_done)
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag(write_done)
        @test write_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag(read_done)
        @test read_err[] == Reseau.AWS_OP_SUCCESS
        @test payload[] == "ping"
    finally
        if client_socket !== nothing
            Reseau.socket_close(client_socket)
        end
        if server_socket !== nothing
            Reseau.socket_close(server_socket)
        end
        Reseau.event_loop_destroy!(el_val)
    end
end

@testset "udp bind connect communication" begin
    el = Reseau.event_loop_new(Reseau.EventLoopOptions())
    el_val = el isa Reseau.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test Reseau.event_loop_run!(el_val) === nothing

    opts = Reseau.SocketOptions(; type = Reseau.SocketType.DGRAM, domain = Reseau.SocketDomain.IPV4)
    server = Reseau.socket_init(opts)
    server_socket = server isa Reseau.Socket ? server : nothing
    @test server_socket !== nothing

    client_socket = nothing
    try
        if server_socket === nothing
            return
        end

        bind_opts = Reseau.SocketBindOptions(Reseau.SocketEndpoint("127.0.0.1", 0))
        @test Reseau.socket_bind(server_socket, bind_opts) === nothing

        bound = Reseau.socket_get_bound_address(server_socket)
        @test bound isa Reseau.SocketEndpoint
        port = bound isa Reseau.SocketEndpoint ? Int(bound.port) : 0
        if port == 0
            return
        end

        assign_res = Reseau.socket_assign_to_event_loop(server_socket, el_val)
        @test !(assign_res isa Reseau.ErrorResult)

        read_err = Ref{Int}(0)
        read_done = Threads.Atomic{Bool}(false)
        payload = Ref{String}("")
        sub_res = Reseau.socket_subscribe_to_readable_events(
            server_socket, (sock, err, ud) -> begin
                read_err[] = err
                if err != Reseau.AWS_OP_SUCCESS
                    read_done[] = true
                    return nothing
                end
                buf = Reseau.ByteBuffer(64)
                read_res = Reseau.socket_read(sock, buf)
                if read_res isa Reseau.ErrorResult
                    read_err[] = read_res.code
                else
                    payload[] = String(Reseau.byte_cursor_from_buf(buf))
                end
                read_done[] = true
                return nothing
            end, nothing
        )
        @test !(sub_res isa Reseau.ErrorResult)

        client = Reseau.socket_init(opts)
        client_socket = client isa Reseau.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end

        local_bind = Reseau.SocketBindOptions(Reseau.SocketEndpoint("127.0.0.1", 0))
        @test Reseau.socket_bind(client_socket, local_bind) === nothing

        connect_err = Ref{Int}(0)
        connect_done = Threads.Atomic{Bool}(false)
        write_err = Ref{Int}(0)
        write_done = Threads.Atomic{Bool}(false)

        connect_opts = Reseau.SocketConnectOptions(
            Reseau.SocketEndpoint("127.0.0.1", port);
            event_loop = el_val,
            on_connection_result = (sock, err, ud) -> begin
                connect_err[] = err
                connect_done[] = true
                if err != Reseau.AWS_OP_SUCCESS
                    return nothing
                end
                cursor = Reseau.ByteCursor("ping")
                write_res = Reseau.socket_write(
                    sock, cursor, (s, err, bytes, ud) -> begin
                        write_err[] = err
                        write_done[] = true
                        return nothing
                    end, nothing
                )
                if write_res isa Reseau.ErrorResult
                    write_err[] = write_res.code
                    write_done[] = true
                end
                return nothing
            end,
        )

        @test Reseau.socket_connect(client_socket, connect_opts) === nothing
        @test wait_for_flag(connect_done)
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag(write_done)
        @test write_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag(read_done)
        @test read_err[] == Reseau.AWS_OP_SUCCESS
        @test payload[] == "ping"
    finally
        if client_socket !== nothing
            Reseau.socket_close(client_socket)
        end
        if server_socket !== nothing
            Reseau.socket_close(server_socket)
        end
        Reseau.event_loop_destroy!(el_val)
    end
end

@testset "wrong thread read write fails" begin
    if Sys.iswindows()
        @test true
    else
        el = Reseau.event_loop_new(Reseau.EventLoopOptions())
        el_val = el isa Reseau.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test Reseau.event_loop_run!(el_val) === nothing

        # Use LOCAL domain (POSIX path on all platforms) since this test
        # exercises POSIX-specific bind/assign/read/write/close flow
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.DGRAM, domain = Reseau.SocketDomain.LOCAL)
        sock = Reseau.socket_init(opts)
        socket_val = sock isa Reseau.Socket ? sock : nothing
        @test socket_val !== nothing
        if socket_val === nothing
            Reseau.event_loop_destroy!(el_val)
            return
        end

        try
            endpoint = Reseau.SocketEndpoint()
            Reseau.socket_endpoint_init_local_address_for_test!(endpoint)
            bind_opts = Reseau.SocketBindOptions(endpoint)
            @test Reseau.socket_bind(socket_val, bind_opts) === nothing
            @test Reseau.socket_assign_to_event_loop(socket_val, el_val) === nothing
            sub_res = Reseau.socket_subscribe_to_readable_events(socket_val, (sock, err, ud) -> nothing, nothing)
            @test !(sub_res isa Reseau.ErrorResult)

            buf = Reseau.ByteBuffer(4)
            read_res = Reseau.socket_read(socket_val, buf)
            @test read_res isa Reseau.ErrorResult
            read_res isa Reseau.ErrorResult && @test read_res.code == Reseau.ERROR_IO_EVENT_LOOP_THREAD_ONLY

            write_res = Reseau.socket_write(socket_val, Reseau.ByteCursor("noop"), (s, err, bytes, ud) -> nothing, nothing)
            @test write_res isa Reseau.ErrorResult
            write_res isa Reseau.ErrorResult && @test write_res.code == Reseau.ERROR_IO_EVENT_LOOP_THREAD_ONLY

            close_done = Threads.Atomic{Bool}(false)
            close_task = Reseau.ScheduledTask((ctx, status) -> begin
                Reseau.socket_close(socket_val)
                close_done[] = true
                return nothing
            end, nothing; type_tag = "socket_close_wrong_thread")
            Reseau.event_loop_schedule_task_now!(el_val, close_task)
            @test wait_for_flag(close_done)
        finally
            Reseau.event_loop_destroy!(el_val)
        end
    end
end

@testset "bind on zero port tcp ipv4" begin
    # Use LOCAL domain on macOS to get a POSIX socket (IPV4 → NW on macOS,
    # which doesn't expose resolved port from socket_get_bound_address)
    @static if Sys.isapple()
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.LOCAL)
    else
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4)
    end
    sock = Reseau.socket_init(opts)
    socket_val = sock isa Reseau.Socket ? sock : nothing
    @test socket_val !== nothing
    if socket_val === nothing
        return
    end

    res = Reseau.socket_get_bound_address(socket_val)
    @test res isa Reseau.ErrorResult

    @static if Sys.isapple()
        endpoint = Reseau.SocketEndpoint()
        Reseau.socket_endpoint_init_local_address_for_test!(endpoint)
    else
        endpoint = Reseau.SocketEndpoint("127.0.0.1", 0)
    end
    @test Reseau.socket_bind(socket_val, Reseau.SocketBindOptions(endpoint)) === nothing
    @test Reseau.socket_listen(socket_val, 1024) === nothing

    bound = Reseau.socket_get_bound_address(socket_val)
    @test bound isa Reseau.SocketEndpoint
    @static if !Sys.isapple()
        # Port resolution only testable on POSIX with IPV4
        if bound isa Reseau.SocketEndpoint
            @test bound.port > 0
            @test Reseau.get_address(bound) == "127.0.0.1"
        end

        bound2 = Reseau.socket_get_bound_address(socket_val)
        @test bound2 isa Reseau.SocketEndpoint
        if bound2 isa Reseau.SocketEndpoint && bound isa Reseau.SocketEndpoint
            @test bound2.port == bound.port
            @test Reseau.get_address(bound2) == Reseau.get_address(bound)
        end
    end

    Reseau.socket_close(socket_val)
end

@testset "bind on zero port udp ipv4" begin
    @static if Sys.isapple()
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.DGRAM, domain = Reseau.SocketDomain.LOCAL)
    else
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.DGRAM, domain = Reseau.SocketDomain.IPV4)
    end
    sock = Reseau.socket_init(opts)
    socket_val = sock isa Reseau.Socket ? sock : nothing
    @test socket_val !== nothing
    if socket_val === nothing
        return
    end

    res = Reseau.socket_get_bound_address(socket_val)
    @test res isa Reseau.ErrorResult

    @static if Sys.isapple()
        endpoint = Reseau.SocketEndpoint()
        Reseau.socket_endpoint_init_local_address_for_test!(endpoint)
    else
        endpoint = Reseau.SocketEndpoint("127.0.0.1", 0)
    end
    @test Reseau.socket_bind(socket_val, Reseau.SocketBindOptions(endpoint)) === nothing

    bound = Reseau.socket_get_bound_address(socket_val)
    @test bound isa Reseau.SocketEndpoint
    @static if !Sys.isapple()
        if bound isa Reseau.SocketEndpoint
            @test bound.port > 0
            @test Reseau.get_address(bound) == "127.0.0.1"
        end

        bound2 = Reseau.socket_get_bound_address(socket_val)
        @test bound2 isa Reseau.SocketEndpoint
        if bound2 isa Reseau.SocketEndpoint && bound isa Reseau.SocketEndpoint
            @test bound2.port == bound.port
            @test Reseau.get_address(bound2) == Reseau.get_address(bound)
        end
    end

    Reseau.socket_close(socket_val)
end

@testset "incoming duplicate tcp bind errors" begin
    # Use LOCAL on macOS since IPV4 → NW sockets, which don't expose
    # resolved port or enforce POSIX duplicate-bind semantics
    @static if Sys.isapple()
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.LOCAL)
    else
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4)
    end
    sock1 = Reseau.socket_init(opts)
    sock1_val = sock1 isa Reseau.Socket ? sock1 : nothing
    @test sock1_val !== nothing
    if sock1_val === nothing
        return
    end

    sock2 = Reseau.socket_init(opts)
    sock2_val = sock2 isa Reseau.Socket ? sock2 : nothing
    @test sock2_val !== nothing

    try
        @static if Sys.isapple()
            endpoint = Reseau.SocketEndpoint()
            Reseau.socket_endpoint_init_local_address_for_test!(endpoint)
            bind_opts = Reseau.SocketBindOptions(endpoint)
        else
            bind_opts = Reseau.SocketBindOptions(Reseau.SocketEndpoint("127.0.0.1", 0))
        end
        @test Reseau.socket_bind(sock1_val, bind_opts) === nothing
        @test Reseau.socket_listen(sock1_val, 1024) === nothing

        @static if Sys.isapple()
            # On macOS LOCAL: duplicate bind on the same path
            if sock2_val !== nothing
                res = Reseau.socket_bind(sock2_val, bind_opts)
                @test res isa Reseau.ErrorResult
                res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_SOCKET_ADDRESS_IN_USE
            end
        else
            bound = Reseau.socket_get_bound_address(sock1_val)
            @test bound isa Reseau.SocketEndpoint
            if bound isa Reseau.SocketEndpoint && sock2_val !== nothing
                dup_endpoint = Reseau.SocketEndpoint("127.0.0.1", Int(bound.port))
                res = Reseau.socket_bind(sock2_val, Reseau.SocketBindOptions(dup_endpoint))
                @test res isa Reseau.ErrorResult
                res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_SOCKET_ADDRESS_IN_USE
            end
        end
    finally
        sock2_val !== nothing && Reseau.socket_close(sock2_val)
        Reseau.socket_close(sock1_val)
    end
end

@testset "incoming tcp socket errors" begin
    # Use LOCAL on macOS to test POSIX bind error paths
    @static if Sys.isapple()
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.LOCAL)
    else
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4)
    end
    sock = Reseau.socket_init(opts)
    sock_val = sock isa Reseau.Socket ? sock : nothing
    @test sock_val !== nothing
    if sock_val === nothing
        return
    end

    @static if Sys.isapple()
        # Test bind to a path in a non-existent directory
        endpoint = Reseau.SocketEndpoint("/nonexistent_dir_xxxxx/sock", 0)
        res = Reseau.socket_bind(sock_val, Reseau.SocketBindOptions(endpoint))
        @test res isa Reseau.ErrorResult
    else
        endpoint = Reseau.SocketEndpoint("127.0.0.1", 80)
        res = Reseau.socket_bind(sock_val, Reseau.SocketBindOptions(endpoint))
        if res === nothing
            # likely running with elevated privileges; skip assertion
            @test true
        else
            @static if Sys.iswindows()
                @test res.code == Reseau.ERROR_NO_PERMISSION ||
                    res.code == Reseau.ERROR_IO_SOCKET_ADDRESS_IN_USE
            else
                @test res.code == Reseau.ERROR_NO_PERMISSION
            end
        end
    end
    Reseau.socket_close(sock_val)
end

@testset "incoming udp socket errors" begin
    @static if Sys.isapple()
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.DGRAM, domain = Reseau.SocketDomain.LOCAL)
    else
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.DGRAM, domain = Reseau.SocketDomain.IPV4)
    end
    sock = Reseau.socket_init(opts)
    sock_val = sock isa Reseau.Socket ? sock : nothing
    @test sock_val !== nothing
    if sock_val === nothing
        return
    end

    @static if Sys.isapple()
        # Test bind to an invalid/non-existent path
        endpoint = Reseau.SocketEndpoint("/nonexistent_dir_xxxxx/sock", 0)
        res = Reseau.socket_bind(sock_val, Reseau.SocketBindOptions(endpoint))
        @test res isa Reseau.ErrorResult
    else
        endpoint = Reseau.SocketEndpoint("127.0", 80)
        res = Reseau.socket_bind(sock_val, Reseau.SocketBindOptions(endpoint))
        @test res isa Reseau.ErrorResult
        res isa Reseau.ErrorResult && @test res.code == Reseau.ERROR_IO_SOCKET_INVALID_ADDRESS
    end
    Reseau.socket_close(sock_val)
end

@testset "outgoing local socket errors" begin
    el = Reseau.event_loop_new(Reseau.EventLoopOptions())
    el_val = el isa Reseau.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test Reseau.event_loop_run!(el_val) === nothing

    opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.LOCAL)
    sock = Reseau.socket_init(opts)
    sock_val = sock isa Reseau.Socket ? sock : nothing
    @test sock_val !== nothing
    if sock_val === nothing
        Reseau.event_loop_destroy!(el_val)
        return
    end

    endpoint = Reseau.SocketEndpoint()
    Reseau.socket_endpoint_init_local_address_for_test!(endpoint)
    # Ensure path does not exist
    local_path = Reseau.get_address(endpoint)
    isfile(local_path) && rm(local_path; force = true)

    err_code = Ref{Int}(0)
    done = Threads.Atomic{Bool}(false)
    connect_opts = Reseau.SocketConnectOptions(
        endpoint;
        event_loop = el_val,
        on_connection_result = (sock, err, ud) -> begin
            err_code[] = err
            done[] = true
            return nothing
        end,
    )

    res = Reseau.socket_connect(sock_val, connect_opts)
    if res isa Reseau.ErrorResult
        err_code[] = res.code
        done[] = true
    end

    @test wait_for_flag(done)
    @static if Sys.iswindows()
        @test err_code[] == Reseau.ERROR_IO_SOCKET_CONNECTION_REFUSED ||
            err_code[] == Reseau.ERROR_FILE_INVALID_PATH ||
            err_code[] == Reseau.ERROR_IO_SOCKET_NOT_CONNECTED
    else
        @test err_code[] == Reseau.ERROR_IO_SOCKET_CONNECTION_REFUSED ||
            err_code[] == Reseau.ERROR_FILE_INVALID_PATH
    end

    Reseau.socket_close(sock_val)
    Reseau.event_loop_destroy!(el_val)
end

@testset "outgoing tcp socket error" begin
    el = Reseau.event_loop_new(Reseau.EventLoopOptions())
    el_val = el isa Reseau.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test Reseau.event_loop_run!(el_val) === nothing

    @static if Sys.isapple()
        # On macOS, use LOCAL domain (POSIX path) with a nonexistent socket
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.LOCAL)
        endpoint = Reseau.SocketEndpoint()
        Reseau.socket_endpoint_init_local_address_for_test!(endpoint)
        # Don't actually create a listener — the path won't exist
        connect_endpoint = endpoint
    else
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4)
        temp = Reseau.socket_init(opts)
        temp_val = temp isa Reseau.Socket ? temp : nothing
        @test temp_val !== nothing
        if temp_val === nothing
            Reseau.event_loop_destroy!(el_val)
            return
        end

        port = 0
        try
            @test Reseau.socket_bind(temp_val, Reseau.SocketBindOptions(Reseau.SocketEndpoint("127.0.0.1", 0))) === nothing
            bound = Reseau.socket_get_bound_address(temp_val)
            if bound isa Reseau.SocketEndpoint
                port = Int(bound.port)
            end
        finally
            Reseau.socket_close(temp_val)
        end

        if port == 0
            Reseau.event_loop_destroy!(el_val)
            return
        end
        connect_endpoint = Reseau.SocketEndpoint("127.0.0.1", port)
    end

    sock = Reseau.socket_init(opts)
    sock_val = sock isa Reseau.Socket ? sock : nothing
    @test sock_val !== nothing
    if sock_val === nothing
        Reseau.event_loop_destroy!(el_val)
        return
    end

    err_code = Ref{Int}(0)
    done = Threads.Atomic{Bool}(false)
    connect_opts = Reseau.SocketConnectOptions(
        connect_endpoint;
        event_loop = el_val,
        on_connection_result = (sock, err, ud) -> begin
            err_code[] = err
            done[] = true
            return nothing
        end,
    )

    res = Reseau.socket_connect(sock_val, connect_opts)
    if res isa Reseau.ErrorResult
        err_code[] = res.code
        done[] = true
    end

    @test wait_for_flag(done)
    @test err_code[] == Reseau.ERROR_IO_SOCKET_CONNECTION_REFUSED ||
        err_code[] == Reseau.ERROR_FILE_INVALID_PATH

    Reseau.socket_close(sock_val)
    Reseau.event_loop_destroy!(el_val)
end
