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
