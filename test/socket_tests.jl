using Test
using AwsIO

function wait_for_flag(flag::Base.RefValue{Bool}; timeout_s::Float64 = 5.0)
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
    return code == AwsIO.ERROR_IO_SOCKET_TIMEOUT ||
        code == AwsIO.ERROR_IO_SOCKET_NO_ROUTE_TO_HOST ||
        code == AwsIO.ERROR_IO_SOCKET_NETWORK_DOWN ||
        code == AwsIO.ERROR_IO_SOCKET_CONNECTION_REFUSED
end

@testset "socket validate port" begin
    @test AwsIO.socket_validate_port_for_connect(80, AwsIO.SocketDomain.IPV4) === nothing
    @test AwsIO.socket_validate_port_for_bind(80, AwsIO.SocketDomain.IPV4) === nothing

    res = AwsIO.socket_validate_port_for_connect(0, AwsIO.SocketDomain.IPV4)
    @test res isa AwsIO.ErrorResult
    res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS
    @test AwsIO.socket_validate_port_for_bind(0, AwsIO.SocketDomain.IPV4) === nothing

    res = AwsIO.socket_validate_port_for_connect(0xFFFFFFFF, AwsIO.SocketDomain.IPV4)
    @test res isa AwsIO.ErrorResult
    res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS

    res = AwsIO.socket_validate_port_for_bind(0xFFFFFFFF, AwsIO.SocketDomain.IPV4)
    @test res isa AwsIO.ErrorResult
    res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS

    @test AwsIO.socket_validate_port_for_connect(80, AwsIO.SocketDomain.IPV6) === nothing
    @test AwsIO.socket_validate_port_for_bind(80, AwsIO.SocketDomain.IPV6) === nothing

    res = AwsIO.socket_validate_port_for_connect(0, AwsIO.SocketDomain.IPV6)
    @test res isa AwsIO.ErrorResult
    res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS
    @test AwsIO.socket_validate_port_for_bind(0, AwsIO.SocketDomain.IPV6) === nothing

    res = AwsIO.socket_validate_port_for_connect(0xFFFFFFFF, AwsIO.SocketDomain.IPV6)
    @test res isa AwsIO.ErrorResult
    res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS

    res = AwsIO.socket_validate_port_for_bind(0xFFFFFFFF, AwsIO.SocketDomain.IPV6)
    @test res isa AwsIO.ErrorResult
    res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS

    @test AwsIO.socket_validate_port_for_connect(80, AwsIO.SocketDomain.VSOCK) === nothing
    @test AwsIO.socket_validate_port_for_bind(80, AwsIO.SocketDomain.VSOCK) === nothing
    @test AwsIO.socket_validate_port_for_connect(0, AwsIO.SocketDomain.VSOCK) === nothing
    @test AwsIO.socket_validate_port_for_bind(0, AwsIO.SocketDomain.VSOCK) === nothing
    @test AwsIO.socket_validate_port_for_connect(0x7FFFFFFF, AwsIO.SocketDomain.VSOCK) === nothing
    @test AwsIO.socket_validate_port_for_bind(0x7FFFFFFF, AwsIO.SocketDomain.VSOCK) === nothing

    res = AwsIO.socket_validate_port_for_connect(-1, AwsIO.SocketDomain.VSOCK)
    @test res isa AwsIO.ErrorResult
    res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS
    @test AwsIO.socket_validate_port_for_bind(-1, AwsIO.SocketDomain.VSOCK) === nothing

    @test AwsIO.socket_validate_port_for_connect(0, AwsIO.SocketDomain.LOCAL) === nothing
    @test AwsIO.socket_validate_port_for_bind(0, AwsIO.SocketDomain.LOCAL) === nothing
    @test AwsIO.socket_validate_port_for_connect(80, AwsIO.SocketDomain.LOCAL) === nothing
    @test AwsIO.socket_validate_port_for_bind(80, AwsIO.SocketDomain.LOCAL) === nothing
    @test AwsIO.socket_validate_port_for_connect(-1, AwsIO.SocketDomain.LOCAL) === nothing
    @test AwsIO.socket_validate_port_for_bind(-1, AwsIO.SocketDomain.LOCAL) === nothing

    bad_domain = Base.bitcast(AwsIO.SocketDomain.T, UInt8(0xff))
    res = AwsIO.socket_validate_port_for_connect(80, bad_domain)
    @test res isa AwsIO.ErrorResult
    res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS
    res = AwsIO.socket_validate_port_for_bind(80, bad_domain)
    @test res isa AwsIO.ErrorResult
    res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS
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
        res = AwsIO.parse_ipv4_address(input)
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
        res = AwsIO.parse_ipv4_address(input)
        @test res isa AwsIO.ErrorResult
        res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS
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
        buf = AwsIO.ByteBuffer(16)
        res = AwsIO.parse_ipv6_address!(input, buf)
        @test res === nothing
        expected = _mem_from_bytes(bytes)
        cursor = AwsIO.ByteCursor(expected)
        @test AwsIO.byte_cursor_eq_byte_buf(cursor, buf)
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
        buf = AwsIO.ByteBuffer(16)
        res = AwsIO.parse_ipv6_address!(input, buf)
        @test res isa AwsIO.ErrorResult
        res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS
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
    args = AwsIO.MessagePoolCreationArgs(
        application_data_msg_data_size = 128,
        application_data_msg_count = 2,
        small_block_msg_data_size = 16,
        small_block_msg_count = 2,
    )
    pool = AwsIO.MessagePool(args)
    @test pool isa AwsIO.MessagePool
    @test length(pool.application_data_pool) == 2
    @test length(pool.small_block_pool) == 2

    msg = AwsIO.message_pool_acquire(pool, AwsIO.IoMessageType.APPLICATION_DATA, 8)
    @test msg isa AwsIO.IoMessage
    @test length(pool.small_block_pool) == 1
    @test AwsIO.capacity(msg.message_data) == Csize_t(8)

    AwsIO.message_pool_release!(pool, msg)
    @test length(pool.small_block_pool) == 2
end

@testset "memory pool" begin
    pool = AwsIO.MemoryPool(2, 32)
    @test length(pool) == 2

    seg1 = AwsIO.memory_pool_acquire(pool)
    seg2 = AwsIO.memory_pool_acquire(pool)
    @test length(pool) == 0
    @test length(seg1) == 32
    @test length(seg2) == 32

    seg3 = AwsIO.memory_pool_acquire(pool)
    @test length(pool) == 0
    @test length(seg3) == 32

    AwsIO.memory_pool_release!(pool, seg1)
    @test length(pool) == 1
    AwsIO.memory_pool_release!(pool, seg2)
    @test length(pool) == 2
    AwsIO.memory_pool_release!(pool, seg3)
    @test length(pool) == 2
end

@testset "socket interface options" begin
    if Sys.iswindows()
        @test !AwsIO.is_network_interface_name_valid("lo")
    else
        long_name = repeat("a", AwsIO.NETWORK_INTERFACE_NAME_MAX)
        @test !AwsIO.is_network_interface_name_valid(long_name)
        @test !AwsIO.is_network_interface_name_valid("definitely_not_an_iface")

        opts = AwsIO.SocketOptions(;
            type = AwsIO.SocketType.STREAM,
            domain = AwsIO.SocketDomain.IPV4,
            network_interface_name = long_name,
        )
        res = AwsIO.socket_init(opts)
        @test res isa AwsIO.ErrorResult
        res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_SOCKET_INVALID_OPTIONS
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
        if !AwsIO.is_network_interface_name_valid(iface)
            @test true
            return
        end

        # IPv4 stream
        el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
        el_val = el isa AwsIO.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test AwsIO.event_loop_run!(el_val) === nothing

        opts = AwsIO.SocketOptions(;
            type = AwsIO.SocketType.STREAM,
            domain = AwsIO.SocketDomain.IPV4,
            connect_timeout_ms = 3000,
            keepalive = true,
            keep_alive_interval_sec = 1000,
            keep_alive_timeout_sec = 60000,
            network_interface_name = iface,
        )

        server = AwsIO.socket_init(opts)
        server_socket = server isa AwsIO.Socket ? server : nothing
        if server isa AwsIO.ErrorResult
            @test server.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED ||
                server.code == AwsIO.ERROR_IO_SOCKET_INVALID_OPTIONS
            AwsIO.event_loop_destroy!(el_val)
            return
        end

        client_socket = nothing
        accepted = Ref{Any}(nothing)

        try
            bind_opts = AwsIO.SocketBindOptions(AwsIO.SocketEndpoint("127.0.0.1", 0))
            bind_res = AwsIO.socket_bind(server_socket, bind_opts)
            if bind_res isa AwsIO.ErrorResult
                @test bind_res.code == AwsIO.ERROR_IO_SOCKET_INVALID_OPTIONS ||
                    bind_res.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED
                return
            end
            listen_res = AwsIO.socket_listen(server_socket, 1024)
            if listen_res isa AwsIO.ErrorResult
                @test listen_res.code == AwsIO.ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY ||
                    listen_res.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED
                return
            end

            bound = AwsIO.socket_get_bound_address(server_socket)
            @test bound isa AwsIO.SocketEndpoint
            port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                return
            end

            accept_err = Ref{Int}(0)
            read_err = Ref{Int}(0)
            payload = Ref{String}("")
            read_done = Ref{Bool}(false)

            connect_err = Ref{Int}(0)
            connect_done = Ref{Bool}(false)
            write_err = Ref{Int}(0)
            write_done = Ref{Bool}(false)

            on_accept = (listener, err, new_sock, ud) -> begin
                accept_err[] = err
                accepted[] = new_sock
                if err != AwsIO.AWS_OP_SUCCESS || new_sock === nothing
                    read_done[] = true
                    return nothing
                end

                assign_res = AwsIO.socket_assign_to_event_loop(new_sock, el_val)
                if assign_res isa AwsIO.ErrorResult
                    read_err[] = assign_res.code
                    read_done[] = true
                    return nothing
                end

                sub_res = AwsIO.socket_subscribe_to_readable_events(
                    new_sock, (sock, err, ud) -> begin
                        read_err[] = err
                        if err != AwsIO.AWS_OP_SUCCESS
                            read_done[] = true
                            return nothing
                        end

                        buf = AwsIO.ByteBuffer(64)
                        read_res = AwsIO.socket_read(sock, buf)
                        if read_res isa AwsIO.ErrorResult
                            read_err[] = read_res.code
                        else
                            payload[] = String(AwsIO.byte_cursor_from_buf(buf))
                        end
                        read_done[] = true
                        return nothing
                    end, nothing
                )

                if sub_res isa AwsIO.ErrorResult
                    read_err[] = sub_res.code
                    read_done[] = true
                end
                return nothing
            end

            accept_opts = AwsIO.SocketListenerOptions(on_accept_result = on_accept)
            @test AwsIO.socket_start_accept(server_socket, el_val, accept_opts) === nothing

            client = AwsIO.socket_init(opts)
            client_socket = client isa AwsIO.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            connect_opts = AwsIO.SocketConnectOptions(
                AwsIO.SocketEndpoint("127.0.0.1", port);
                event_loop = el_val,
                on_connection_result = (sock, err, ud) -> begin
                    connect_err[] = err
                    connect_done[] = true
                    if err != AwsIO.AWS_OP_SUCCESS
                        return nothing
                    end

                    cursor = AwsIO.ByteCursor("ping")
                    write_res = AwsIO.socket_write(
                        sock, cursor, (s, err, bytes, ud) -> begin
                            write_err[] = err
                            write_done[] = true
                            return nothing
                        end, nothing
                    )

                    if write_res isa AwsIO.ErrorResult
                        write_err[] = write_res.code
                        write_done[] = true
                    end
                    return nothing
                end,
            )

            @test AwsIO.socket_connect(client_socket, connect_opts) === nothing
            @test wait_for_flag(connect_done)
            @test connect_err[] == AwsIO.AWS_OP_SUCCESS
            @test wait_for_flag(write_done)
            @test write_err[] == AwsIO.AWS_OP_SUCCESS
            @test wait_for_flag(read_done)
            @test accept_err[] == AwsIO.AWS_OP_SUCCESS
            @test read_err[] == AwsIO.AWS_OP_SUCCESS
            @test payload[] == "ping"
        finally
            if client_socket !== nothing
                AwsIO.socket_cleanup!(client_socket)
            end
            if accepted[] !== nothing
                AwsIO.socket_cleanup!(accepted[])
            end
            AwsIO.socket_cleanup!(server_socket)
            AwsIO.event_loop_destroy!(el_val)
        end

        # IPv4 UDP
        el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
        el_val = el isa AwsIO.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test AwsIO.event_loop_run!(el_val) === nothing

        opts_udp = AwsIO.SocketOptions(;
            type = AwsIO.SocketType.DGRAM,
            domain = AwsIO.SocketDomain.IPV4,
            connect_timeout_ms = 3000,
            network_interface_name = iface,
        )

        server = AwsIO.socket_init(opts_udp)
        server_socket = server isa AwsIO.Socket ? server : nothing
        if server isa AwsIO.ErrorResult
            @test server.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED ||
                server.code == AwsIO.ERROR_IO_SOCKET_INVALID_OPTIONS
            AwsIO.event_loop_destroy!(el_val)
            return
        end

        client_socket = nothing
        try
            bind_opts = AwsIO.SocketBindOptions(AwsIO.SocketEndpoint("127.0.0.1", 0))
            bind_res = AwsIO.socket_bind(server_socket, bind_opts)
            if bind_res isa AwsIO.ErrorResult
                @test bind_res.code == AwsIO.ERROR_IO_SOCKET_INVALID_OPTIONS ||
                    bind_res.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED
                return
            end

            bound = AwsIO.socket_get_bound_address(server_socket)
            @test bound isa AwsIO.SocketEndpoint
            port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                return
            end

            client = AwsIO.socket_init(opts_udp)
            client_socket = client isa AwsIO.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            connect_opts = AwsIO.SocketConnectOptions(
                AwsIO.SocketEndpoint("127.0.0.1", port);
                event_loop = el_val,
                on_connection_result = (sock, err, ud) -> nothing,
            )

            @test AwsIO.socket_connect(client_socket, connect_opts) === nothing
        finally
            if client_socket !== nothing
                AwsIO.socket_cleanup!(client_socket)
            end
            AwsIO.socket_cleanup!(server_socket)
            AwsIO.event_loop_destroy!(el_val)
        end

        # IPv6 stream
        el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
        el_val = el isa AwsIO.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test AwsIO.event_loop_run!(el_val) === nothing

        opts6 = AwsIO.SocketOptions(;
            type = AwsIO.SocketType.STREAM,
            domain = AwsIO.SocketDomain.IPV6,
            connect_timeout_ms = 3000,
            network_interface_name = iface,
        )

        server = AwsIO.socket_init(opts6)
        server_socket = server isa AwsIO.Socket ? server : nothing
        if server isa AwsIO.ErrorResult
            @test server.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED ||
                server.code == AwsIO.ERROR_IO_SOCKET_INVALID_OPTIONS
            AwsIO.event_loop_destroy!(el_val)
            return
        end

        client_socket = nothing
        accepted = Ref{Any}(nothing)

        try
            bind_opts = AwsIO.SocketBindOptions(AwsIO.SocketEndpoint("::1", 0))
            bind_res = AwsIO.socket_bind(server_socket, bind_opts)
            if bind_res isa AwsIO.ErrorResult
                @test bind_res.code == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS
                return
            end
            @test AwsIO.socket_listen(server_socket, 1024) === nothing

            bound = AwsIO.socket_get_bound_address(server_socket)
            @test bound isa AwsIO.SocketEndpoint
            port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                return
            end

            accept_err = Ref{Int}(0)
            connect_err = Ref{Int}(0)
            connect_done = Ref{Bool}(false)

            on_accept = (listener, err, new_sock, ud) -> begin
                accept_err[] = err
                accepted[] = new_sock
                return nothing
            end

            accept_opts = AwsIO.SocketListenerOptions(on_accept_result = on_accept)
            @test AwsIO.socket_start_accept(server_socket, el_val, accept_opts) === nothing

            client = AwsIO.socket_init(opts6)
            client_socket = client isa AwsIO.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            connect_opts = AwsIO.SocketConnectOptions(
                AwsIO.SocketEndpoint("::1", port);
                event_loop = el_val,
                on_connection_result = (sock, err, ud) -> begin
                    connect_err[] = err
                    connect_done[] = true
                    return nothing
                end,
            )

            @test AwsIO.socket_connect(client_socket, connect_opts) === nothing
            @test wait_for_flag(connect_done)
            @test connect_err[] == AwsIO.AWS_OP_SUCCESS
            @test accept_err[] == AwsIO.AWS_OP_SUCCESS
        finally
            if client_socket !== nothing
                AwsIO.socket_cleanup!(client_socket)
            end
            if accepted[] !== nothing
                AwsIO.socket_cleanup!(accepted[])
            end
            AwsIO.socket_cleanup!(server_socket)
            AwsIO.event_loop_destroy!(el_val)
        end
    end
end

@testset "socket bind to invalid interface" begin
    if Sys.iswindows()
        @test true
    else
        opts = AwsIO.SocketOptions(;
            type = AwsIO.SocketType.STREAM,
            domain = AwsIO.SocketDomain.IPV4,
            connect_timeout_ms = 3000,
            keepalive = true,
            keep_alive_interval_sec = 1000,
            keep_alive_timeout_sec = 60000,
            network_interface_name = "invalid",
        )

        res = AwsIO.socket_init(opts)
        @test res isa AwsIO.ErrorResult
        if res isa AwsIO.ErrorResult
            @test res.code == AwsIO.ERROR_IO_SOCKET_INVALID_OPTIONS ||
                res.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED
        end
    end
end

@testset "vsock loopback socket communication" begin
    if !Sys.islinux()
        @test true
    else
        el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
        el_val = el isa AwsIO.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test AwsIO.event_loop_run!(el_val) === nothing

        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.VSOCK, connect_timeout_ms = 3000)
        server = AwsIO.socket_init(opts)
        server_socket = server isa AwsIO.Socket ? server : nothing
        if server isa AwsIO.ErrorResult
            @test server.code == AwsIO.ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY ||
                server.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED ||
                server.code == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS
            AwsIO.event_loop_destroy!(el_val)
            return
        end

        client_socket = nothing
        accepted = Ref{Any}(nothing)

        try
            bind_opts = AwsIO.SocketBindOptions(AwsIO.SocketEndpoint("1", 0))
            bind_res = AwsIO.socket_bind(server_socket, bind_opts)
            if bind_res isa AwsIO.ErrorResult
                @test bind_res.code == AwsIO.ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY ||
                    bind_res.code == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS
                return
            end
            @test AwsIO.socket_listen(server_socket, 1024) === nothing

            bound = AwsIO.socket_get_bound_address(server_socket)
            @test bound isa AwsIO.SocketEndpoint
            port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                return
            end

            accept_err = Ref{Int}(0)
            connect_err = Ref{Int}(0)
            connect_done = Ref{Bool}(false)

            on_accept = (listener, err, new_sock, ud) -> begin
                accept_err[] = err
                accepted[] = new_sock
                return nothing
            end

            accept_opts = AwsIO.SocketListenerOptions(on_accept_result = on_accept)
            @test AwsIO.socket_start_accept(server_socket, el_val, accept_opts) === nothing

            client = AwsIO.socket_init(opts)
            client_socket = client isa AwsIO.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            connect_opts = AwsIO.SocketConnectOptions(
                AwsIO.SocketEndpoint("1", port);
                event_loop = el_val,
                on_connection_result = (sock, err, ud) -> begin
                    connect_err[] = err
                    connect_done[] = true
                    return nothing
                end,
            )

            connect_res = AwsIO.socket_connect(client_socket, connect_opts)
            if connect_res isa AwsIO.ErrorResult
                @test _is_allowed_connect_error(connect_res.code) ||
                    connect_res.code == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS ||
                    connect_res.code == AwsIO.ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY
                return
            end
            @test wait_for_flag(connect_done)
            if connect_err[] != AwsIO.AWS_OP_SUCCESS
                @test _is_allowed_connect_error(connect_err[]) ||
                    connect_err[] == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS
            else
                @test accept_err[] == AwsIO.AWS_OP_SUCCESS
            end
        finally
            if client_socket !== nothing
                AwsIO.socket_cleanup!(client_socket)
            end
            if accepted[] !== nothing
                AwsIO.socket_cleanup!(accepted[])
            end
            AwsIO.socket_cleanup!(server_socket)
            AwsIO.event_loop_destroy!(el_val)
        end
    end
end

@testset "socket init impl type" begin
    opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4)
    sock = AwsIO.socket_init(opts)
    @test sock isa AwsIO.Socket
    sock isa AwsIO.Socket && AwsIO.socket_close(sock)

    @static if !Sys.iswindows()
        win_opts = AwsIO.SocketOptions(; impl_type = AwsIO.SocketImplType.WINSOCK)
        win_sock = AwsIO.socket_init(win_opts)
        @test win_sock isa AwsIO.ErrorResult
        win_sock isa AwsIO.ErrorResult && @test win_sock.code == AwsIO.ERROR_PLATFORM_NOT_SUPPORTED
    end
end

@testset "socket nonblocking cloexec" begin
    if Sys.iswindows()
        @test true
    else
        opts = AwsIO.SocketOptions(;
            type = AwsIO.SocketType.STREAM,
            domain = AwsIO.SocketDomain.IPV4,
        )
        sock = AwsIO.socket_init(opts)
        @test sock isa AwsIO.Socket
        if sock isa AwsIO.Socket
            fd = sock.io_handle.fd
            flags = AwsIO._fcntl(fd, AwsIO.F_GETFL)
            @test (flags & AwsIO.O_NONBLOCK) != 0
            fd_flags = AwsIO._fcntl(fd, AwsIO.F_GETFD)
            @test (fd_flags & AwsIO.FD_CLOEXEC) != 0
            AwsIO.socket_close(sock)
        end
    end
end

@testset "socket connect read write" begin
    el_type = AwsIO.event_loop_get_default_type()
    el = AwsIO.event_loop_new(AwsIO.EventLoopOptions(; type = el_type))
    el_val = el isa AwsIO.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test AwsIO.event_loop_run!(el_val) === nothing
    opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4)
    server = AwsIO.socket_init(opts)
    server_socket = server isa AwsIO.Socket ? server : nothing
    @test server_socket !== nothing

    client_socket = nothing
    accepted = Ref{Any}(nothing)

    try
        if server_socket === nothing
            return
        end

        bind_opts = AwsIO.SocketBindOptions(AwsIO.SocketEndpoint("127.0.0.1", 0))
        @test AwsIO.socket_bind(server_socket, bind_opts) === nothing
        @test AwsIO.socket_listen(server_socket, 8) === nothing

        bound = AwsIO.socket_get_bound_address(server_socket)
        @test bound isa AwsIO.SocketEndpoint
        port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
        if !(bound isa AwsIO.SocketEndpoint)
            return
        end

        accept_err = Ref{Int}(0)
        read_err = Ref{Int}(0)
        payload = Ref{String}("")
        read_done = Ref{Bool}(false)

        connect_err = Ref{Int}(0)
        connect_done = Ref{Bool}(false)
        write_err = Ref{Int}(0)
        write_done = Ref{Bool}(false)

        on_accept = (listener, err, new_sock, ud) -> begin
            accept_err[] = err
            accepted[] = new_sock
            if err != AwsIO.AWS_OP_SUCCESS || new_sock === nothing
                read_done[] = true
                return nothing
            end

            assign_res = AwsIO.socket_assign_to_event_loop(new_sock, el_val)
            if assign_res isa AwsIO.ErrorResult
                read_err[] = assign_res.code
                read_done[] = true
                return nothing
            end

            sub_res = AwsIO.socket_subscribe_to_readable_events(
                new_sock, (sock, err, ud) -> begin
                    read_err[] = err
                    if err != AwsIO.AWS_OP_SUCCESS
                        read_done[] = true
                        return nothing
                    end

                    buf = AwsIO.ByteBuffer(64)
                    read_res = AwsIO.socket_read(sock, buf)
                    if read_res isa AwsIO.ErrorResult
                        read_err[] = read_res.code
                    else
                        payload[] = String(AwsIO.byte_cursor_from_buf(buf))
                    end
                    read_done[] = true
                    return nothing
                end, nothing
            )

            if sub_res isa AwsIO.ErrorResult
                read_err[] = sub_res.code
                read_done[] = true
            end
            return nothing
        end

        accept_opts = AwsIO.SocketListenerOptions(on_accept_result = on_accept)
        @test AwsIO.socket_start_accept(server_socket, el_val, accept_opts) === nothing

        client = AwsIO.socket_init(opts)
        client_socket = client isa AwsIO.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end
        connect_opts = AwsIO.SocketConnectOptions(
            AwsIO.SocketEndpoint("127.0.0.1", port);
            event_loop = el_val,
            on_connection_result = (sock, err, ud) -> begin
                connect_err[] = err
                connect_done[] = true
                if err != AwsIO.AWS_OP_SUCCESS
                    return nothing
                end

                cursor = AwsIO.ByteCursor("ping")
                write_res = AwsIO.socket_write(
                    sock, cursor, (s, err, bytes, ud) -> begin
                        write_err[] = err
                        write_done[] = true
                        return nothing
                    end, nothing
                )

                if write_res isa AwsIO.ErrorResult
                    write_err[] = write_res.code
                    write_done[] = true
                end

                return nothing
            end,
        )

        @test AwsIO.socket_connect(client_socket, connect_opts) === nothing
        @test wait_for_flag(connect_done)
        @test connect_err[] == AwsIO.AWS_OP_SUCCESS
        @test wait_for_flag(write_done)
        @test write_err[] == AwsIO.AWS_OP_SUCCESS
        @test wait_for_flag(read_done)
        @test accept_err[] == AwsIO.AWS_OP_SUCCESS
        @test read_err[] == AwsIO.AWS_OP_SUCCESS
        @test payload[] == "ping"
    finally
        if client_socket !== nothing
            AwsIO.socket_close(client_socket)
        end
        if accepted[] !== nothing
            AwsIO.socket_close(accepted[])
        end
        if server_socket !== nothing
            AwsIO.socket_close(server_socket)
        end
        AwsIO.event_loop_destroy!(el_val)
    end
end

@testset "sock write cb is async" begin
    if Sys.iswindows()
        @test true
    else
        el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
        el_val = el isa AwsIO.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test AwsIO.event_loop_run!(el_val) === nothing

        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4)
        server = AwsIO.socket_init(opts)
        server_socket = server isa AwsIO.Socket ? server : nothing
        @test server_socket !== nothing

        client_socket = nothing
        accepted = Ref{Any}(nothing)

        try
            if server_socket === nothing
                return
            end

            bind_opts = AwsIO.SocketBindOptions(AwsIO.SocketEndpoint("127.0.0.1", 0))
            @test AwsIO.socket_bind(server_socket, bind_opts) === nothing
            @test AwsIO.socket_listen(server_socket, 8) === nothing

            bound = AwsIO.socket_get_bound_address(server_socket)
            @test bound isa AwsIO.SocketEndpoint
            port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                return
            end

            accept_done = Ref(false)
            on_accept = (listener, err, new_sock, ud) -> begin
                accepted[] = new_sock
                accept_done[] = true
                if err != AwsIO.AWS_OP_SUCCESS || new_sock === nothing
                    return nothing
                end
                assign_res = AwsIO.socket_assign_to_event_loop(new_sock, el_val)
                if assign_res isa AwsIO.ErrorResult
                    return nothing
                end
                _ = AwsIO.socket_subscribe_to_readable_events(
                    new_sock, (sock, err, ud) -> begin
                        if err != AwsIO.AWS_OP_SUCCESS
                            return nothing
                        end
                        buf = AwsIO.ByteBuffer(64)
                        _ = AwsIO.socket_read(sock, buf)
                        return nothing
                    end, nothing
                )
                return nothing
            end

            accept_opts = AwsIO.SocketListenerOptions(on_accept_result = on_accept)
            @test AwsIO.socket_start_accept(server_socket, el_val, accept_opts) === nothing

            client = AwsIO.socket_init(opts)
            client_socket = client isa AwsIO.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            connect_done = Ref(false)
            write_started = Ref(false)
            write_cb_invoked = Ref(false)
            write_cb_sync = Ref(false)
            write_err = Ref{Int}(0)

            connect_opts = AwsIO.SocketConnectOptions(
                AwsIO.SocketEndpoint("127.0.0.1", port);
                event_loop = el_val,
                on_connection_result = (sock, err, ud) -> begin
                    connect_done[] = true
                    if err != AwsIO.AWS_OP_SUCCESS
                        write_started[] = true
                        return nothing
                    end
                    cursor = AwsIO.ByteCursor("ping")
                    write_cb_invoked[] = false
                    write_cb_sync[] = false
                    write_res = AwsIO.socket_write(
                        sock, cursor, (s, err, bytes, ud) -> begin
                            write_err[] = err
                            write_cb_invoked[] = true
                            return nothing
                        end, nothing
                    )
                    if write_res isa AwsIO.ErrorResult
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

            @test AwsIO.socket_connect(client_socket, connect_opts) === nothing
            @test wait_for_flag(connect_done)
            @test wait_for_flag(accept_done)
            @test wait_for_flag(write_started)
            @test wait_for_flag(write_cb_invoked)
            @test !write_cb_sync[]
            @test write_err[] == AwsIO.AWS_OP_SUCCESS
        finally
            if client_socket !== nothing
                AwsIO.socket_close(client_socket)
            end
            if accepted[] !== nothing
                AwsIO.socket_close(accepted[])
            end
            if server_socket !== nothing
                AwsIO.socket_close(server_socket)
            end
            AwsIO.event_loop_destroy!(el_val)
        end
    end
end

@testset "connect timeout" begin
    if Sys.iswindows()
        @test true
    else
        el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
        el_val = el isa AwsIO.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test AwsIO.event_loop_run!(el_val) === nothing

        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4, connect_timeout_ms = 200)
        sock = AwsIO.socket_init(opts)
        socket_val = sock isa AwsIO.Socket ? sock : nothing
        @test socket_val !== nothing
        if socket_val === nothing
            AwsIO.event_loop_destroy!(el_val)
            return
        end

        connect_done = Ref(false)
        connect_err = Ref{Int}(0)
        endpoint = AwsIO.SocketEndpoint("10.255.255.1", 81)
        connect_opts = AwsIO.SocketConnectOptions(
            endpoint;
            event_loop = el_val,
            on_connection_result = (sock, err, ud) -> begin
                connect_err[] = err
                connect_done[] = true
                return nothing
            end,
        )

        try
            res = AwsIO.socket_connect(socket_val, connect_opts)
            if res isa AwsIO.ErrorResult
                @test _is_allowed_connect_error(res.code)
            else
                @test wait_for_flag(connect_done; timeout_s = 3.0)
                @test _is_allowed_connect_error(connect_err[])
            end
        finally
            AwsIO.socket_cleanup!(socket_val)
            AwsIO.event_loop_destroy!(el_val)
        end
    end
end

@testset "connect timeout cancellation" begin
    if Sys.iswindows()
        @test true
    else
        el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
        el_val = el isa AwsIO.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test AwsIO.event_loop_run!(el_val) === nothing

        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4, connect_timeout_ms = 10_000)
        sock = AwsIO.socket_init(opts)
        socket_val = sock isa AwsIO.Socket ? sock : nothing
        @test socket_val !== nothing
        if socket_val === nothing
            AwsIO.event_loop_destroy!(el_val)
            return
        end

        connect_done = Ref(false)
        connect_err = Ref{Int}(0)
        endpoint = AwsIO.SocketEndpoint("10.255.255.1", 81)
        connect_opts = AwsIO.SocketConnectOptions(
            endpoint;
            event_loop = el_val,
            on_connection_result = (sock, err, ud) -> begin
                connect_err[] = err
                connect_done[] = true
                return nothing
            end,
        )

        destroyed = false
        try
            res = AwsIO.socket_connect(socket_val, connect_opts)
            if res isa AwsIO.ErrorResult
                @test _is_allowed_connect_error(res.code)
            else
                AwsIO.event_loop_destroy!(el_val)
                destroyed = true
                @test connect_done[]
                @test connect_err[] == AwsIO.ERROR_IO_EVENT_LOOP_SHUTDOWN ||
                    _is_allowed_connect_error(connect_err[])
            end
        finally
            if !destroyed
                AwsIO.event_loop_destroy!(el_val)
            end
            AwsIO.socket_cleanup!(socket_val)
        end
    end
end

@testset "cleanup before connect or timeout" begin
    if Sys.iswindows()
        @test true
    else
        el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
        el_val = el isa AwsIO.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test AwsIO.event_loop_run!(el_val) === nothing

        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4, connect_timeout_ms = 1000)
        sock = AwsIO.socket_init(opts)
        socket_val = sock isa AwsIO.Socket ? sock : nothing
        @test socket_val !== nothing
        if socket_val === nothing
            AwsIO.event_loop_destroy!(el_val)
            return
        end

        connect_done = Ref(false)
        connect_err = Ref{Int}(0)
        cleanup_done = Ref(false)
        endpoint = AwsIO.SocketEndpoint("10.255.255.1", 81)
        connect_opts = AwsIO.SocketConnectOptions(
            endpoint;
            event_loop = el_val,
            on_connection_result = (sock, err, ud) -> begin
                connect_err[] = err
                connect_done[] = true
                return nothing
            end,
        )

        cleanup_task = AwsIO.ScheduledTask((ctx, status) -> begin
            AwsIO.socket_cleanup!(socket_val)
            cleanup_done[] = true
            return nothing
        end, nothing; type_tag = "socket_cleanup_before_connect")

        try
            res = AwsIO.socket_connect(socket_val, connect_opts)
            if res isa AwsIO.ErrorResult
                @test _is_allowed_connect_error(res.code)
            else
                AwsIO.event_loop_schedule_task_now!(el_val, cleanup_task)
                @test wait_for_flag(cleanup_done)
                sleep(0.05)
                if connect_done[]
                    @test _is_allowed_connect_error(connect_err[])
                else
                    @test true
                end
            end
        finally
            AwsIO.socket_cleanup!(socket_val)
            AwsIO.event_loop_destroy!(el_val)
        end
    end
end

@testset "cleanup in accept doesn't explode" begin
    if Sys.iswindows()
        @test true
    else
        el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
        el_val = el isa AwsIO.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test AwsIO.event_loop_run!(el_val) === nothing

        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4)
        listener = AwsIO.socket_init(opts)
        listener_socket = listener isa AwsIO.Socket ? listener : nothing
        @test listener_socket !== nothing
        if listener_socket === nothing
            AwsIO.event_loop_destroy!(el_val)
            return
        end

        incoming = Ref{Any}(nothing)
        accept_done = Ref(false)
        accept_err = Ref{Int}(0)
        connect_done = Ref(false)
        connect_err = Ref{Int}(0)
        client_socket = nothing

        try
            bind_opts = AwsIO.SocketBindOptions(AwsIO.SocketEndpoint("127.0.0.1", 0))
            @test AwsIO.socket_bind(listener_socket, bind_opts) === nothing
            @test AwsIO.socket_listen(listener_socket, 1024) === nothing

            bound = AwsIO.socket_get_bound_address(listener_socket)
            @test bound isa AwsIO.SocketEndpoint
            port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                return
            end

            on_accept = (sock, err, new_sock, ud) -> begin
                accept_err[] = err
                incoming[] = new_sock
                accept_done[] = true
                if sock !== nothing
                    AwsIO.socket_cleanup!(sock)
                end
                return nothing
            end

            accept_opts = AwsIO.SocketListenerOptions(on_accept_result = on_accept)
            @test AwsIO.socket_start_accept(listener_socket, el_val, accept_opts) === nothing

            client = AwsIO.socket_init(opts)
            client_socket = client isa AwsIO.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            connect_opts = AwsIO.SocketConnectOptions(
                AwsIO.SocketEndpoint("127.0.0.1", port);
                event_loop = el_val,
                on_connection_result = (sock, err, ud) -> begin
                    connect_err[] = err
                    connect_done[] = true
                    return nothing
                end,
            )

            @test AwsIO.socket_connect(client_socket, connect_opts) === nothing
            @test wait_for_flag(accept_done)
            @test wait_for_flag(connect_done)
            @test accept_err[] == AwsIO.AWS_OP_SUCCESS
            @test connect_err[] == AwsIO.AWS_OP_SUCCESS
        finally
            if client_socket !== nothing
                AwsIO.socket_cleanup!(client_socket)
            end
            if incoming[] !== nothing
                AwsIO.socket_cleanup!(incoming[])
            end
            AwsIO.socket_cleanup!(listener_socket)
            AwsIO.event_loop_destroy!(el_val)
        end
    end
end

@testset "cleanup in write cb doesn't explode" begin
    if Sys.iswindows()
        @test true
    else
        el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
        el_val = el isa AwsIO.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test AwsIO.event_loop_run!(el_val) === nothing

        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4)
        listener = AwsIO.socket_init(opts)
        listener_socket = listener isa AwsIO.Socket ? listener : nothing
        @test listener_socket !== nothing
        if listener_socket === nothing
            AwsIO.event_loop_destroy!(el_val)
            return
        end

        accepted = Ref{Any}(nothing)
        accept_done = Ref(false)
        connect_done = Ref(false)
        client_socket = nothing

        try
            bind_opts = AwsIO.SocketBindOptions(AwsIO.SocketEndpoint("127.0.0.1", 0))
            @test AwsIO.socket_bind(listener_socket, bind_opts) === nothing
            @test AwsIO.socket_listen(listener_socket, 1024) === nothing

            bound = AwsIO.socket_get_bound_address(listener_socket)
            @test bound isa AwsIO.SocketEndpoint
            port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                return
            end

            on_accept = (sock, err, new_sock, ud) -> begin
                accepted[] = new_sock
                accept_done[] = true
                return nothing
            end

            accept_opts = AwsIO.SocketListenerOptions(on_accept_result = on_accept)
            @test AwsIO.socket_start_accept(listener_socket, el_val, accept_opts) === nothing

            client = AwsIO.socket_init(opts)
            client_socket = client isa AwsIO.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            connect_opts = AwsIO.SocketConnectOptions(
                AwsIO.SocketEndpoint("127.0.0.1", port);
                event_loop = el_val,
                on_connection_result = (sock, err, ud) -> begin
                    connect_done[] = true
                    return nothing
                end,
            )

            @test AwsIO.socket_connect(client_socket, connect_opts) === nothing
            @test wait_for_flag(accept_done)
            @test wait_for_flag(connect_done)

            server_sock = accepted[]
            @test server_sock !== nothing
            if server_sock === nothing
                return
            end

            assign_res = AwsIO.socket_assign_to_event_loop(server_sock, el_val)
            @test !(assign_res isa AwsIO.ErrorResult)

            write_done_client = Ref(false)
            write_err_client = Ref{Int}(0)
            write_done_server = Ref(false)
            write_err_server = Ref{Int}(0)

            write_task_client = AwsIO.ScheduledTask((ctx, status) -> begin
                cursor = AwsIO.ByteCursor("teapot")
                res = AwsIO.socket_write(
                    client_socket,
                    cursor,
                    (s, err, bytes, ud) -> begin
                        write_err_client[] = err
                        AwsIO.socket_cleanup!(client_socket)
                        write_done_client[] = true
                        return nothing
                    end,
                    nothing,
                )
                if res isa AwsIO.ErrorResult
                    write_err_client[] = res.code
                    AwsIO.socket_cleanup!(client_socket)
                    write_done_client[] = true
                end
                return nothing
            end, nothing; type_tag = "socket_write_cleanup_client")

            write_task_server = AwsIO.ScheduledTask((ctx, status) -> begin
                cursor = AwsIO.ByteCursor("spout")
                res = AwsIO.socket_write(
                    server_sock,
                    cursor,
                    (s, err, bytes, ud) -> begin
                        write_err_server[] = err
                        AwsIO.socket_cleanup!(server_sock)
                        write_done_server[] = true
                        return nothing
                    end,
                    nothing,
                )
                if res isa AwsIO.ErrorResult
                    write_err_server[] = res.code
                    AwsIO.socket_cleanup!(server_sock)
                    write_done_server[] = true
                end
                return nothing
            end, nothing; type_tag = "socket_write_cleanup_server")

            AwsIO.event_loop_schedule_task_now!(el_val, write_task_client)
            @test wait_for_flag(write_done_client)
            AwsIO.event_loop_schedule_task_now!(el_val, write_task_server)
            @test wait_for_flag(write_done_server)
            @test write_err_client[] == AwsIO.AWS_OP_SUCCESS
            @test write_err_server[] == AwsIO.AWS_OP_SUCCESS
        finally
            if client_socket !== nothing
                AwsIO.socket_cleanup!(client_socket)
            end
            if accepted[] !== nothing
                AwsIO.socket_cleanup!(accepted[])
            end
            AwsIO.socket_cleanup!(listener_socket)
            AwsIO.event_loop_destroy!(el_val)
        end
    end
end

@testset "local socket communication" begin
    if Sys.iswindows()
        @test true
    else
        el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
        el_val = el isa AwsIO.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test AwsIO.event_loop_run!(el_val) === nothing

        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.LOCAL)
        server = AwsIO.socket_init(opts)
        server_socket = server isa AwsIO.Socket ? server : nothing
        @test server_socket !== nothing

        client_socket = nothing
        accepted = Ref{Any}(nothing)
        endpoint = AwsIO.SocketEndpoint()
        AwsIO.socket_endpoint_init_local_address_for_test!(endpoint)
        local_path = AwsIO.get_address(endpoint)

        try
            if server_socket === nothing
                return
            end

            bind_opts = AwsIO.SocketBindOptions(endpoint)
            @test AwsIO.socket_bind(server_socket, bind_opts) === nothing
            @test AwsIO.socket_listen(server_socket, 8) === nothing

            accept_err = Ref{Int}(0)
            read_err = Ref{Int}(0)
            payload = Ref{String}("")
            read_done = Ref{Bool}(false)

            connect_err = Ref{Int}(0)
            connect_done = Ref{Bool}(false)
            write_err = Ref{Int}(0)
            write_done = Ref{Bool}(false)

            on_accept = (listener, err, new_sock, ud) -> begin
                accept_err[] = err
                accepted[] = new_sock
                if err != AwsIO.AWS_OP_SUCCESS || new_sock === nothing
                    read_done[] = true
                    return nothing
                end

                assign_res = AwsIO.socket_assign_to_event_loop(new_sock, el_val)
                if assign_res isa AwsIO.ErrorResult
                    read_err[] = assign_res.code
                    read_done[] = true
                    return nothing
                end

                sub_res = AwsIO.socket_subscribe_to_readable_events(
                    new_sock, (sock, err, ud) -> begin
                        read_err[] = err
                        if err != AwsIO.AWS_OP_SUCCESS
                            read_done[] = true
                            return nothing
                        end

                        buf = AwsIO.ByteBuffer(64)
                        read_res = AwsIO.socket_read(sock, buf)
                        if read_res isa AwsIO.ErrorResult
                            read_err[] = read_res.code
                        else
                            payload[] = String(AwsIO.byte_cursor_from_buf(buf))
                        end
                        read_done[] = true
                        return nothing
                    end, nothing
                )

                if sub_res isa AwsIO.ErrorResult
                    read_err[] = sub_res.code
                    read_done[] = true
                end
                return nothing
            end

            accept_opts = AwsIO.SocketListenerOptions(on_accept_result = on_accept)
            @test AwsIO.socket_start_accept(server_socket, el_val, accept_opts) === nothing

            client = AwsIO.socket_init(opts)
            client_socket = client isa AwsIO.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            connect_opts = AwsIO.SocketConnectOptions(
                endpoint;
                event_loop = el_val,
                on_connection_result = (sock, err, ud) -> begin
                    connect_err[] = err
                    connect_done[] = true
                    if err != AwsIO.AWS_OP_SUCCESS
                        return nothing
                    end

                    cursor = AwsIO.ByteCursor("ping")
                    write_res = AwsIO.socket_write(
                        sock, cursor, (s, err, bytes, ud) -> begin
                            write_err[] = err
                            write_done[] = true
                            return nothing
                        end, nothing
                    )

                    if write_res isa AwsIO.ErrorResult
                        write_err[] = write_res.code
                        write_done[] = true
                    end
                    return nothing
                end,
            )

            @test AwsIO.socket_connect(client_socket, connect_opts) === nothing
            @test wait_for_flag(connect_done)
            @test connect_err[] == AwsIO.AWS_OP_SUCCESS
            @test wait_for_flag(write_done)
            @test write_err[] == AwsIO.AWS_OP_SUCCESS
            @test wait_for_flag(read_done)
            @test accept_err[] == AwsIO.AWS_OP_SUCCESS
            @test read_err[] == AwsIO.AWS_OP_SUCCESS
            @test payload[] == "ping"
        finally
            if client_socket !== nothing
                AwsIO.socket_close(client_socket)
            end
            if accepted[] !== nothing
                AwsIO.socket_close(accepted[])
            end
            if server_socket !== nothing
                AwsIO.socket_close(server_socket)
            end
            AwsIO.event_loop_destroy!(el_val)
            if !isempty(local_path) && isfile(local_path)
                rm(local_path; force = true)
            end
        end
    end
end

@testset "udp socket communication" begin
    if Sys.iswindows()
        @test true
    else
        el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
        el_val = el isa AwsIO.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test AwsIO.event_loop_run!(el_val) === nothing

        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.DGRAM, domain = AwsIO.SocketDomain.IPV4)
        server = AwsIO.socket_init(opts)
        server_socket = server isa AwsIO.Socket ? server : nothing
        @test server_socket !== nothing

        client_socket = nothing
        try
            if server_socket === nothing
                return
            end

            bind_opts = AwsIO.SocketBindOptions(AwsIO.SocketEndpoint("127.0.0.1", 0))
            @test AwsIO.socket_bind(server_socket, bind_opts) === nothing

            bound = AwsIO.socket_get_bound_address(server_socket)
            @test bound isa AwsIO.SocketEndpoint
            port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                return
            end

            assign_res = AwsIO.socket_assign_to_event_loop(server_socket, el_val)
            @test !(assign_res isa AwsIO.ErrorResult)

            read_err = Ref{Int}(0)
            read_done = Ref{Bool}(false)
            payload = Ref{String}("")
            sub_res = AwsIO.socket_subscribe_to_readable_events(
                server_socket, (sock, err, ud) -> begin
                    read_err[] = err
                    if err != AwsIO.AWS_OP_SUCCESS
                        read_done[] = true
                        return nothing
                    end
                    buf = AwsIO.ByteBuffer(64)
                    read_res = AwsIO.socket_read(sock, buf)
                    if read_res isa AwsIO.ErrorResult
                        read_err[] = read_res.code
                    else
                        payload[] = String(AwsIO.byte_cursor_from_buf(buf))
                    end
                    read_done[] = true
                    return nothing
                end, nothing
            )
            @test !(sub_res isa AwsIO.ErrorResult)

            client = AwsIO.socket_init(opts)
            client_socket = client isa AwsIO.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            connect_err = Ref{Int}(0)
            connect_done = Ref{Bool}(false)
            write_err = Ref{Int}(0)
            write_done = Ref{Bool}(false)

            connect_opts = AwsIO.SocketConnectOptions(
                AwsIO.SocketEndpoint("127.0.0.1", port);
                event_loop = el_val,
                on_connection_result = (sock, err, ud) -> begin
                    connect_err[] = err
                    connect_done[] = true
                    if err != AwsIO.AWS_OP_SUCCESS
                        return nothing
                    end
                    cursor = AwsIO.ByteCursor("ping")
                    write_res = AwsIO.socket_write(
                        sock, cursor, (s, err, bytes, ud) -> begin
                            write_err[] = err
                            write_done[] = true
                            return nothing
                        end, nothing
                    )
                    if write_res isa AwsIO.ErrorResult
                        write_err[] = write_res.code
                        write_done[] = true
                    end
                    return nothing
                end,
            )

            @test AwsIO.socket_connect(client_socket, connect_opts) === nothing
            @test wait_for_flag(connect_done)
            @test connect_err[] == AwsIO.AWS_OP_SUCCESS
            @test wait_for_flag(write_done)
            @test write_err[] == AwsIO.AWS_OP_SUCCESS
            @test wait_for_flag(read_done)
            @test read_err[] == AwsIO.AWS_OP_SUCCESS
            @test payload[] == "ping"
        finally
            if client_socket !== nothing
                AwsIO.socket_close(client_socket)
            end
            if server_socket !== nothing
                AwsIO.socket_close(server_socket)
            end
            AwsIO.event_loop_destroy!(el_val)
        end
    end
end

@testset "udp bind connect communication" begin
    if Sys.iswindows()
        @test true
    else
        el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
        el_val = el isa AwsIO.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test AwsIO.event_loop_run!(el_val) === nothing

        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.DGRAM, domain = AwsIO.SocketDomain.IPV4)
        server = AwsIO.socket_init(opts)
        server_socket = server isa AwsIO.Socket ? server : nothing
        @test server_socket !== nothing

        client_socket = nothing
        try
            if server_socket === nothing
                return
            end

            bind_opts = AwsIO.SocketBindOptions(AwsIO.SocketEndpoint("127.0.0.1", 0))
            @test AwsIO.socket_bind(server_socket, bind_opts) === nothing

            bound = AwsIO.socket_get_bound_address(server_socket)
            @test bound isa AwsIO.SocketEndpoint
            port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                return
            end

            assign_res = AwsIO.socket_assign_to_event_loop(server_socket, el_val)
            @test !(assign_res isa AwsIO.ErrorResult)

            read_err = Ref{Int}(0)
            read_done = Ref{Bool}(false)
            payload = Ref{String}("")
            sub_res = AwsIO.socket_subscribe_to_readable_events(
                server_socket, (sock, err, ud) -> begin
                    read_err[] = err
                    if err != AwsIO.AWS_OP_SUCCESS
                        read_done[] = true
                        return nothing
                    end
                    buf = AwsIO.ByteBuffer(64)
                    read_res = AwsIO.socket_read(sock, buf)
                    if read_res isa AwsIO.ErrorResult
                        read_err[] = read_res.code
                    else
                        payload[] = String(AwsIO.byte_cursor_from_buf(buf))
                    end
                    read_done[] = true
                    return nothing
                end, nothing
            )
            @test !(sub_res isa AwsIO.ErrorResult)

            client = AwsIO.socket_init(opts)
            client_socket = client isa AwsIO.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            local_bind = AwsIO.SocketBindOptions(AwsIO.SocketEndpoint("127.0.0.1", 0))
            @test AwsIO.socket_bind(client_socket, local_bind) === nothing

            connect_err = Ref{Int}(0)
            connect_done = Ref{Bool}(false)
            write_err = Ref{Int}(0)
            write_done = Ref{Bool}(false)

            connect_opts = AwsIO.SocketConnectOptions(
                AwsIO.SocketEndpoint("127.0.0.1", port);
                event_loop = el_val,
                on_connection_result = (sock, err, ud) -> begin
                    connect_err[] = err
                    connect_done[] = true
                    if err != AwsIO.AWS_OP_SUCCESS
                        return nothing
                    end
                    cursor = AwsIO.ByteCursor("ping")
                    write_res = AwsIO.socket_write(
                        sock, cursor, (s, err, bytes, ud) -> begin
                            write_err[] = err
                            write_done[] = true
                            return nothing
                        end, nothing
                    )
                    if write_res isa AwsIO.ErrorResult
                        write_err[] = write_res.code
                        write_done[] = true
                    end
                    return nothing
                end,
            )

            @test AwsIO.socket_connect(client_socket, connect_opts) === nothing
            @test wait_for_flag(connect_done)
            @test connect_err[] == AwsIO.AWS_OP_SUCCESS
            @test wait_for_flag(write_done)
            @test write_err[] == AwsIO.AWS_OP_SUCCESS
            @test wait_for_flag(read_done)
            @test read_err[] == AwsIO.AWS_OP_SUCCESS
            @test payload[] == "ping"
        finally
            if client_socket !== nothing
                AwsIO.socket_close(client_socket)
            end
            if server_socket !== nothing
                AwsIO.socket_close(server_socket)
            end
            AwsIO.event_loop_destroy!(el_val)
        end
    end
end

@testset "wrong thread read write fails" begin
    if Sys.iswindows()
        @test true
    else
        el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
        el_val = el isa AwsIO.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test AwsIO.event_loop_run!(el_val) === nothing

        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.DGRAM, domain = AwsIO.SocketDomain.IPV4)
        sock = AwsIO.socket_init(opts)
        socket_val = sock isa AwsIO.Socket ? sock : nothing
        @test socket_val !== nothing
        if socket_val === nothing
            AwsIO.event_loop_destroy!(el_val)
            return
        end

        try
            bind_opts = AwsIO.SocketBindOptions(AwsIO.SocketEndpoint("127.0.0.1", 0))
            @test AwsIO.socket_bind(socket_val, bind_opts) === nothing
            @test AwsIO.socket_assign_to_event_loop(socket_val, el_val) === nothing
            sub_res = AwsIO.socket_subscribe_to_readable_events(socket_val, (sock, err, ud) -> nothing, nothing)
            @test !(sub_res isa AwsIO.ErrorResult)

            buf = AwsIO.ByteBuffer(4)
            read_res = AwsIO.socket_read(socket_val, buf)
            @test read_res isa AwsIO.ErrorResult
            read_res isa AwsIO.ErrorResult && @test read_res.code == AwsIO.ERROR_IO_EVENT_LOOP_THREAD_ONLY

            write_res = AwsIO.socket_write(socket_val, AwsIO.ByteCursor("noop"), (s, err, bytes, ud) -> nothing, nothing)
            @test write_res isa AwsIO.ErrorResult
            write_res isa AwsIO.ErrorResult && @test write_res.code == AwsIO.ERROR_IO_EVENT_LOOP_THREAD_ONLY

            close_done = Ref(false)
            close_task = AwsIO.ScheduledTask((ctx, status) -> begin
                AwsIO.socket_close(socket_val)
                close_done[] = true
                return nothing
            end, nothing; type_tag = "socket_close_wrong_thread")
            AwsIO.event_loop_schedule_task_now!(el_val, close_task)
            @test wait_for_flag(close_done)
        finally
            AwsIO.event_loop_destroy!(el_val)
        end
    end
end

@testset "bind on zero port tcp ipv4" begin
    if Sys.iswindows()
        @test true
    else
        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4)
        sock = AwsIO.socket_init(opts)
        socket_val = sock isa AwsIO.Socket ? sock : nothing
        @test socket_val !== nothing
        if socket_val === nothing
            return
        end

        res = AwsIO.socket_get_bound_address(socket_val)
        @test res isa AwsIO.ErrorResult

        endpoint = AwsIO.SocketEndpoint("127.0.0.1", 0)
        @test AwsIO.socket_bind(socket_val, AwsIO.SocketBindOptions(endpoint)) === nothing
        @test AwsIO.socket_listen(socket_val, 1024) === nothing

        bound = AwsIO.socket_get_bound_address(socket_val)
        @test bound isa AwsIO.SocketEndpoint
        if bound isa AwsIO.SocketEndpoint
            @test bound.port > 0
            @test AwsIO.get_address(bound) == "127.0.0.1"
        end

        bound2 = AwsIO.socket_get_bound_address(socket_val)
        @test bound2 isa AwsIO.SocketEndpoint
        if bound2 isa AwsIO.SocketEndpoint && bound isa AwsIO.SocketEndpoint
            @test bound2.port == bound.port
            @test AwsIO.get_address(bound2) == AwsIO.get_address(bound)
        end

        AwsIO.socket_close(socket_val)
    end
end

@testset "bind on zero port udp ipv4" begin
    if Sys.iswindows()
        @test true
    else
        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.DGRAM, domain = AwsIO.SocketDomain.IPV4)
        sock = AwsIO.socket_init(opts)
        socket_val = sock isa AwsIO.Socket ? sock : nothing
        @test socket_val !== nothing
        if socket_val === nothing
            return
        end

        res = AwsIO.socket_get_bound_address(socket_val)
        @test res isa AwsIO.ErrorResult

        endpoint = AwsIO.SocketEndpoint("127.0.0.1", 0)
        @test AwsIO.socket_bind(socket_val, AwsIO.SocketBindOptions(endpoint)) === nothing

        bound = AwsIO.socket_get_bound_address(socket_val)
        @test bound isa AwsIO.SocketEndpoint
        if bound isa AwsIO.SocketEndpoint
            @test bound.port > 0
            @test AwsIO.get_address(bound) == "127.0.0.1"
        end

        bound2 = AwsIO.socket_get_bound_address(socket_val)
        @test bound2 isa AwsIO.SocketEndpoint
        if bound2 isa AwsIO.SocketEndpoint && bound isa AwsIO.SocketEndpoint
            @test bound2.port == bound.port
            @test AwsIO.get_address(bound2) == AwsIO.get_address(bound)
        end

        AwsIO.socket_close(socket_val)
    end
end

@testset "incoming duplicate tcp bind errors" begin
    if Sys.iswindows()
        @test true
    else
        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4)
        sock1 = AwsIO.socket_init(opts)
        sock1_val = sock1 isa AwsIO.Socket ? sock1 : nothing
        @test sock1_val !== nothing
        if sock1_val === nothing
            return
        end

        sock2 = AwsIO.socket_init(opts)
        sock2_val = sock2 isa AwsIO.Socket ? sock2 : nothing
        @test sock2_val !== nothing

        try
            bind_opts = AwsIO.SocketBindOptions(AwsIO.SocketEndpoint("127.0.0.1", 0))
            @test AwsIO.socket_bind(sock1_val, bind_opts) === nothing
            @test AwsIO.socket_listen(sock1_val, 1024) === nothing

            bound = AwsIO.socket_get_bound_address(sock1_val)
            @test bound isa AwsIO.SocketEndpoint
            if bound isa AwsIO.SocketEndpoint && sock2_val !== nothing
                dup_endpoint = AwsIO.SocketEndpoint("127.0.0.1", Int(bound.port))
                res = AwsIO.socket_bind(sock2_val, AwsIO.SocketBindOptions(dup_endpoint))
                @test res isa AwsIO.ErrorResult
                res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_SOCKET_ADDRESS_IN_USE
            end
        finally
            sock2_val !== nothing && AwsIO.socket_close(sock2_val)
            AwsIO.socket_close(sock1_val)
        end
    end
end

@testset "incoming tcp socket errors" begin
    if Sys.iswindows()
        @test true
    else
        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4)
        sock = AwsIO.socket_init(opts)
        sock_val = sock isa AwsIO.Socket ? sock : nothing
        @test sock_val !== nothing
        if sock_val === nothing
            return
        end

        endpoint = AwsIO.SocketEndpoint("127.0.0.1", 80)
        res = AwsIO.socket_bind(sock_val, AwsIO.SocketBindOptions(endpoint))
        if res === nothing
            # likely running with elevated privileges; skip assertion
            @test true
        else
            @test res.code == AwsIO.ERROR_NO_PERMISSION
        end
        AwsIO.socket_close(sock_val)
    end
end

@testset "incoming udp socket errors" begin
    if Sys.iswindows()
        @test true
    else
        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.DGRAM, domain = AwsIO.SocketDomain.IPV4)
        sock = AwsIO.socket_init(opts)
        sock_val = sock isa AwsIO.Socket ? sock : nothing
        @test sock_val !== nothing
        if sock_val === nothing
            return
        end

        endpoint = AwsIO.SocketEndpoint("127.0", 80)
        res = AwsIO.socket_bind(sock_val, AwsIO.SocketBindOptions(endpoint))
        @test res isa AwsIO.ErrorResult
        res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_SOCKET_INVALID_ADDRESS
        AwsIO.socket_close(sock_val)
    end
end

@testset "outgoing local socket errors" begin
    if Sys.iswindows()
        @test true
    else
        el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
        el_val = el isa AwsIO.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test AwsIO.event_loop_run!(el_val) === nothing

        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.LOCAL)
        sock = AwsIO.socket_init(opts)
        sock_val = sock isa AwsIO.Socket ? sock : nothing
        @test sock_val !== nothing
        if sock_val === nothing
            AwsIO.event_loop_destroy!(el_val)
            return
        end

        endpoint = AwsIO.SocketEndpoint()
        AwsIO.socket_endpoint_init_local_address_for_test!(endpoint)
        # Ensure path does not exist
        local_path = AwsIO.get_address(endpoint)
        isfile(local_path) && rm(local_path; force = true)

        err_code = Ref{Int}(0)
        done = Ref{Bool}(false)
        connect_opts = AwsIO.SocketConnectOptions(
            endpoint;
            event_loop = el_val,
            on_connection_result = (sock, err, ud) -> begin
                err_code[] = err
                done[] = true
                return nothing
            end,
        )

        res = AwsIO.socket_connect(sock_val, connect_opts)
        if res isa AwsIO.ErrorResult
            err_code[] = res.code
            done[] = true
        end

        @test wait_for_flag(done)
        @test err_code[] == AwsIO.ERROR_IO_SOCKET_CONNECTION_REFUSED ||
            err_code[] == AwsIO.ERROR_FILE_INVALID_PATH

        AwsIO.socket_close(sock_val)
        AwsIO.event_loop_destroy!(el_val)
    end
end

@testset "outgoing tcp socket error" begin
    if Sys.iswindows()
        @test true
    else
        el = AwsIO.event_loop_new(AwsIO.EventLoopOptions())
        el_val = el isa AwsIO.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test AwsIO.event_loop_run!(el_val) === nothing

        opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4)
        temp = AwsIO.socket_init(opts)
        temp_val = temp isa AwsIO.Socket ? temp : nothing
        @test temp_val !== nothing
        if temp_val === nothing
            AwsIO.event_loop_destroy!(el_val)
            return
        end

        port = 0
        try
            @test AwsIO.socket_bind(temp_val, AwsIO.SocketBindOptions(AwsIO.SocketEndpoint("127.0.0.1", 0))) === nothing
            bound = AwsIO.socket_get_bound_address(temp_val)
            if bound isa AwsIO.SocketEndpoint
                port = Int(bound.port)
            end
        finally
            AwsIO.socket_close(temp_val)
        end

        if port == 0
            AwsIO.event_loop_destroy!(el_val)
            return
        end

        sock = AwsIO.socket_init(opts)
        sock_val = sock isa AwsIO.Socket ? sock : nothing
        @test sock_val !== nothing
        if sock_val === nothing
            AwsIO.event_loop_destroy!(el_val)
            return
        end

        err_code = Ref{Int}(0)
        done = Ref{Bool}(false)
        connect_opts = AwsIO.SocketConnectOptions(
            AwsIO.SocketEndpoint("127.0.0.1", port);
            event_loop = el_val,
            on_connection_result = (sock, err, ud) -> begin
                err_code[] = err
                done[] = true
                return nothing
            end,
        )

        res = AwsIO.socket_connect(sock_val, connect_opts)
        if res isa AwsIO.ErrorResult
            err_code[] = res.code
            done[] = true
        end

        @test wait_for_flag(done)
        @test err_code[] == AwsIO.ERROR_IO_SOCKET_CONNECTION_REFUSED

        AwsIO.socket_close(sock_val)
        AwsIO.event_loop_destroy!(el_val)
    end
end
