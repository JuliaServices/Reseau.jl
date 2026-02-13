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

const _SOCKET_BIND_INTERFACE_DEBUG = get(ENV, "RESEAU_SOCKET_BIND_INTERFACE_DEBUG", "") == "1"

function _wait_for_flag_debug(flag::Ref{Bool}, label::AbstractString; timeout_s::Float64 = 5.0)
    ok = wait_for_flag(flag; timeout_s = timeout_s)
    if !ok && _SOCKET_BIND_INTERFACE_DEBUG
        println("[socket-bind-iface] timeout waiting for ", label)
    end
    return ok
end

function _socket_bind_interface_dump(
    label::AbstractString,
    server::Sockets.Socket,
    client::Union{Sockets.Socket, Nothing} = nothing,
    accepted::Union{Sockets.Socket, Nothing} = nothing,
)
    _SOCKET_BIND_INTERFACE_DEBUG || return nothing
    server_state = Int(server.state)
    server_fd = server.io_handle.fd
    client_state = client === nothing ? "none" : string(Int(client.state))
    client_fd = client === nothing ? "none" : string(client.io_handle.fd)
    accepted_fd = accepted === nothing ? "none" : string(accepted.io_handle.fd)
    accepted_state = accepted === nothing ? "none" : string(Int(accepted.state))
    println(
        "[socket-bind-iface] ",
        label,
        " server(fd=",
        server_fd,
        ", state=",
        server_state,
        ") client(fd=",
        client_fd,
        ", state=",
        client_state,
        ") accepted(fd=",
        accepted_fd,
        ", state=",
        accepted_state,
        ") thread=",
        Base.Threads.threadid(),
    )
    return nothing
end

function _mem_from_bytes(bytes::NTuple{16, UInt8})
    mem = Memory{UInt8}(undef, 16)
    for i in 1:16
        mem[i] = bytes[i]
    end
    return mem
end

function _is_allowed_connect_error(code::Int)
    return code == EventLoops.ERROR_IO_SOCKET_TIMEOUT ||
        code == EventLoops.ERROR_IO_SOCKET_NO_ROUTE_TO_HOST ||
        code == EventLoops.ERROR_IO_SOCKET_NETWORK_DOWN ||
        code == EventLoops.ERROR_IO_SOCKET_CONNECTION_REFUSED
end

const _SOCKET_TEST_TRACE = get(ENV, "RESEAU_SOCKET_TEST_TRACE", "") == "1"
const _SOCKET_TEST_TRACE_LIMIT = begin
    try
        parse(Int, get(ENV, "RESEAU_SOCKET_TEST_TRACE_LIMIT", "0"))
    catch
        0
    end
end
const _SOCKET_TEST_TRACE_START = begin
    try
        parse(Int, get(ENV, "RESEAU_SOCKET_TEST_TRACE_START", "1"))
    catch
        1
    end
end
const _SOCKET_TEST_TRACE_COUNT = Ref(0)

macro trace_socket_testset(test_name, body)
    return esc(
        quote
            local _run = true
            if _SOCKET_TEST_TRACE_LIMIT > 0
                _SOCKET_TEST_TRACE_COUNT[] += 1
                local _idx = _SOCKET_TEST_TRACE_COUNT[]
                if _idx < _SOCKET_TEST_TRACE_START || _idx > _SOCKET_TEST_TRACE_LIMIT
                    _run = false
                end
            end

            if _run
                _SOCKET_TEST_TRACE && println("[socket-test] ", $(test_name))
                @testset $(test_name) $(body)
            else
                _SOCKET_TEST_TRACE && println("[socket-test-skip] ", $(test_name))
            end
        end,
    )
end

@trace_socket_testset "socket validate port" begin
    @test Sockets.socket_validate_port_for_connect(80, Sockets.SocketDomain.IPV4) === nothing
    @test Sockets.socket_validate_port_for_bind(80, Sockets.SocketDomain.IPV4) === nothing

    try
        Sockets.socket_validate_port_for_connect(0, Sockets.SocketDomain.IPV4)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
    end
    @test Sockets.socket_validate_port_for_bind(0, Sockets.SocketDomain.IPV4) === nothing

    try
        Sockets.socket_validate_port_for_connect(0xFFFFFFFF, Sockets.SocketDomain.IPV4)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
    end

    try
        Sockets.socket_validate_port_for_bind(0xFFFFFFFF, Sockets.SocketDomain.IPV4)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
    end

    @test Sockets.socket_validate_port_for_connect(80, Sockets.SocketDomain.IPV6) === nothing
    @test Sockets.socket_validate_port_for_bind(80, Sockets.SocketDomain.IPV6) === nothing

    try
        Sockets.socket_validate_port_for_connect(0, Sockets.SocketDomain.IPV6)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
    end
    @test Sockets.socket_validate_port_for_bind(0, Sockets.SocketDomain.IPV6) === nothing

    try
        Sockets.socket_validate_port_for_connect(0xFFFFFFFF, Sockets.SocketDomain.IPV6)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
    end

    try
        Sockets.socket_validate_port_for_bind(0xFFFFFFFF, Sockets.SocketDomain.IPV6)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
    end

    @test Sockets.socket_validate_port_for_connect(80, Sockets.SocketDomain.VSOCK) === nothing
    @test Sockets.socket_validate_port_for_bind(80, Sockets.SocketDomain.VSOCK) === nothing
    @test Sockets.socket_validate_port_for_connect(0, Sockets.SocketDomain.VSOCK) === nothing
    @test Sockets.socket_validate_port_for_bind(0, Sockets.SocketDomain.VSOCK) === nothing
    @test Sockets.socket_validate_port_for_connect(0x7FFFFFFF, Sockets.SocketDomain.VSOCK) === nothing
    @test Sockets.socket_validate_port_for_bind(0x7FFFFFFF, Sockets.SocketDomain.VSOCK) === nothing

    try
        Sockets.socket_validate_port_for_connect(-1, Sockets.SocketDomain.VSOCK)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
    end
    @test Sockets.socket_validate_port_for_bind(-1, Sockets.SocketDomain.VSOCK) === nothing

    @test Sockets.socket_validate_port_for_connect(0, Sockets.SocketDomain.LOCAL) === nothing
    @test Sockets.socket_validate_port_for_bind(0, Sockets.SocketDomain.LOCAL) === nothing
    @test Sockets.socket_validate_port_for_connect(80, Sockets.SocketDomain.LOCAL) === nothing
    @test Sockets.socket_validate_port_for_bind(80, Sockets.SocketDomain.LOCAL) === nothing
    @test Sockets.socket_validate_port_for_connect(-1, Sockets.SocketDomain.LOCAL) === nothing
    @test Sockets.socket_validate_port_for_bind(-1, Sockets.SocketDomain.LOCAL) === nothing

    bad_domain = Base.bitcast(Sockets.SocketDomain.T, UInt8(0xff))
    try
        Sockets.socket_validate_port_for_connect(80, bad_domain)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
    end
    try
        Sockets.socket_validate_port_for_bind(80, bad_domain)
        @test false
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
    end
end

@trace_socket_testset "parse ipv4 valid addresses" begin
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
        res = Sockets.parse_ipv4_address(input)
        @test res == expected
    end
end

@trace_socket_testset "parse ipv4 invalid addresses" begin
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
        try
            Sockets.parse_ipv4_address(input)
            @test false
        catch e
            @test e isa Reseau.ReseauError
            @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
        end
    end
end

@trace_socket_testset "parse ipv6 valid addresses" begin
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
        res = Sockets.parse_ipv6_address!(input, buf)
        @test res === nothing
        expected = _mem_from_bytes(bytes)
        cursor = Reseau.ByteCursor(expected)
        @test Reseau.byte_cursor_eq_byte_buf(cursor, buf)
    end
end

@trace_socket_testset "parse ipv6 invalid addresses" begin
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
        try
            Sockets.parse_ipv6_address!(input, buf)
            @test false
        catch e
            @test e isa Reseau.ReseauError
            @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
        end
    end
end

function _mem_from_bytes(bytes::NTuple{16, UInt8})
    mem = Memory{UInt8}(undef, 16)
    for i in 1:16
        mem[i] = bytes[i]
    end
    return mem
end

@trace_socket_testset "message pool" begin
    args = Sockets.MessagePoolCreationArgs(
        application_data_msg_data_size = 128,
        application_data_msg_count = 2,
        small_block_msg_data_size = 16,
        small_block_msg_count = 2,
    )
    pool = Sockets.MessagePool(args)
    @test pool isa Sockets.MessagePool
    @test length(pool.application_data_pool) == 2
    @test length(pool.small_block_pool) == 2

    msg = Sockets.message_pool_acquire(pool, EventLoops.IoMessageType.APPLICATION_DATA, 8)
    @test msg isa EventLoops.IoMessage
    @test length(pool.small_block_pool) == 1
    @test Reseau.capacity(msg.message_data) == Csize_t(8)

    Sockets.message_pool_release!(pool, msg)
    @test length(pool.small_block_pool) == 2
end

@trace_socket_testset "memory pool" begin
    pool = Sockets.MemoryPool(2, 32)
    @test length(pool) == 2

    seg1 = Sockets.memory_pool_acquire(pool)
    seg2 = Sockets.memory_pool_acquire(pool)
    @test length(pool) == 0
    @test length(seg1) == 32
    @test length(seg2) == 32

    seg3 = Sockets.memory_pool_acquire(pool)
    @test length(pool) == 0
    @test length(seg3) == 32

    Sockets.memory_pool_release!(pool, seg1)
    @test length(pool) == 1
    Sockets.memory_pool_release!(pool, seg2)
    @test length(pool) == 2
    Sockets.memory_pool_release!(pool, seg3)
    @test length(pool) == 2
end

@trace_socket_testset "socket interface options" begin
    if Sys.iswindows()
        @test !Sockets.is_network_interface_name_valid("lo")
    else
        long_name = repeat("a", Sockets.NETWORK_INTERFACE_NAME_MAX)
        @test !Sockets.is_network_interface_name_valid(long_name)
        @test !Sockets.is_network_interface_name_valid("definitely_not_an_iface")

        opts = Sockets.SocketOptions(;
            type = Sockets.SocketType.STREAM,
            domain = Sockets.SocketDomain.IPV4,
            network_interface_name = long_name,
        )
        try
            Sockets.socket_init(opts)
            @test false
        catch e
            @test e isa Reseau.ReseauError
            # POSIX path returns INVALID_OPTIONS for bad interface name length;
            # NW path (macOS IPV4/IPV6) returns PLATFORM_NOT_SUPPORTED for any interface name
            @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_OPTIONS || e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
        end
    end
end

@trace_socket_testset "socket bind to interface" begin
    if Sys.iswindows()
        @test true
    else
        iface = Sys.islinux() ? "lo" : (Sys.isapple() ? "lo0" : "")
        if isempty(iface)
            @test true
            return
        end
        if !Sockets.is_network_interface_name_valid(iface)
            @test true
            return
        end

        # IPv4 stream
        el = EventLoops.event_loop_new()
        el_val = el isa EventLoops.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test EventLoops.event_loop_run!(el_val) === nothing

        opts = Sockets.SocketOptions(;
            type = Sockets.SocketType.STREAM,
            domain = Sockets.SocketDomain.IPV4,
            connect_timeout_ms = 3000,
            keepalive = true,
            keep_alive_interval_sec = 1000,
            keep_alive_timeout_sec = 60000,
            network_interface_name = iface,
        )

        local server_socket
        try
            server_socket = Sockets.socket_init(opts)
        catch e
            @test e isa Reseau.ReseauError
            @test e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED ||
                e.code == EventLoops.ERROR_IO_SOCKET_INVALID_OPTIONS
            EventLoops.event_loop_destroy!(el_val)
            return
        end

        client_socket = nothing
        accepted = Ref{Any}(nothing)

        try
            bind_opts = Sockets.SocketBindOptions(Sockets.SocketEndpoint("127.0.0.1", 0))
            try
                Sockets.socket_bind(server_socket, bind_opts)
            catch e
                @test e isa Reseau.ReseauError
                @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_OPTIONS ||
                    e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
                return
            end
            try
                Sockets.socket_listen(server_socket, 1024)
            catch e
                @test e isa Reseau.ReseauError
                @test e.code == EventLoops.ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY ||
                    e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
                return
            end

            bound = Sockets.socket_get_bound_address(server_socket)
            @test bound isa Sockets.SocketEndpoint
            port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
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

            on_accept = Reseau.ChannelCallable((err, new_sock) -> begin
                accept_err[] = err
                accepted[] = new_sock
                if _SOCKET_BIND_INTERFACE_DEBUG
                    println(
                        "[socket-bind-iface] accept callback err=",
                        accept_err[],
                        " thread=",
                        Base.Threads.threadid(),
                    )
                    _socket_bind_interface_dump("accept callback", server_socket, client_socket, accepted[])
                end
                if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
                    read_done[] = true
                    return nothing
                end

                try
                    Sockets.socket_assign_to_event_loop(new_sock, el_val)
                catch e
                    read_err[] = e isa Reseau.ReseauError ? e.code : -1
                    read_done[] = true
                    return nothing
                end

                try
                    Sockets.socket_subscribe_to_readable_events(
                        new_sock, Reseau.EventCallable(err -> begin
                            read_err[] = err
                            if _SOCKET_BIND_INTERFACE_DEBUG
                                println(
                                    "[socket-bind-iface] read callback err=",
                                    read_err[],
                                    " thread=",
                                    Base.Threads.threadid(),
                                )
                            end
                            if err != Reseau.AWS_OP_SUCCESS
                                read_done[] = true
                                return nothing
                            end

                            buf = Reseau.ByteBuffer(64)
                            try
                                Sockets.socket_read(new_sock, buf)
                                payload[] = String(Reseau.byte_cursor_from_buf(buf))
                            catch e
                                read_err[] = e isa Reseau.ReseauError ? e.code : -1
                            end
                            read_done[] = true
                            if _SOCKET_BIND_INTERFACE_DEBUG
                                println("[socket-bind-iface] read payload='", payload[], "'")
                                _socket_bind_interface_dump("read callback", server_socket, client_socket, accepted[])
                            end
                            return nothing
                        end)
                    )
                catch e
                    read_err[] = e isa Reseau.ReseauError ? e.code : -1
                    read_done[] = true
                    _SOCKET_BIND_INTERFACE_DEBUG && println(
                        "[socket-bind-iface] readable subscribe error=",
                        read_err[],
                    )
                end
                return nothing
            end)

            accept_opts = Sockets.SocketListenerOptions(on_accept_result = on_accept)
            @test Sockets.socket_start_accept(server_socket, el_val, accept_opts) === nothing

            client = Sockets.socket_init(opts)
            client_socket = client isa Sockets.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end
            _socket_bind_interface_dump("prepared client", server_socket, client_socket, accepted[])

            connect_opts = Sockets.SocketConnectOptions(
                Sockets.SocketEndpoint("127.0.0.1", port);
                event_loop = el_val,
                on_connection_result = Reseau.EventCallable(err -> begin
                    connect_err[] = err
                    connect_done[] = true
                    if _SOCKET_BIND_INTERFACE_DEBUG
                        println(
                            "[socket-bind-iface] connect callback err=",
                            connect_err[],
                            " thread=",
                            Base.Threads.threadid(),
                        )
                        _socket_bind_interface_dump("connect callback", server_socket, client_socket, accepted[])
                    end
                    if err != Reseau.AWS_OP_SUCCESS
                        return nothing
                    end

                    cursor = Reseau.ByteCursor("ping")
                    try
                        Sockets.socket_write(
                            client_socket, cursor, Reseau.WriteCallable((err, bytes) -> begin
                                write_err[] = err
                                write_done[] = true
                                if _SOCKET_BIND_INTERFACE_DEBUG
                                    println(
                                        "[socket-bind-iface] write callback err=",
                                        write_err[],
                                        " bytes=",
                                        bytes,
                                        " thread=",
                                        Base.Threads.threadid(),
                                    )
                                    _socket_bind_interface_dump("write callback", server_socket, client_socket, accepted[])
                                end
                                return nothing
                            end)
                        )
                    catch e
                        write_err[] = e isa Reseau.ReseauError ? e.code : -1
                        write_done[] = true
                        _SOCKET_BIND_INTERFACE_DEBUG && println(
                            "[socket-bind-iface] socket_write threw ",
                            write_err[],
                        )
                    end
                    return nothing
                end),
            )

            @test Sockets.socket_connect(client_socket, connect_opts) === nothing
            if _SOCKET_BIND_INTERFACE_DEBUG
                _socket_bind_interface_dump("before wait connect", server_socket, client_socket, accepted[])
            end
            @test _wait_for_flag_debug(connect_done, "connect_done")
            @test connect_err[] == Reseau.AWS_OP_SUCCESS
            if _SOCKET_BIND_INTERFACE_DEBUG
                _socket_bind_interface_dump("before wait write", server_socket, client_socket, accepted[])
            end
            @test _wait_for_flag_debug(write_done, "write_done")
            @test write_err[] == Reseau.AWS_OP_SUCCESS
            if _SOCKET_BIND_INTERFACE_DEBUG
                _socket_bind_interface_dump("before wait read", server_socket, client_socket, accepted[])
            end
            @test _wait_for_flag_debug(read_done, "read_done")
            @test accept_err[] == Reseau.AWS_OP_SUCCESS
            @test read_err[] == Reseau.AWS_OP_SUCCESS
            @test payload[] == "ping"
            if _SOCKET_BIND_INTERFACE_DEBUG
                _socket_bind_interface_dump("done", server_socket, client_socket, accepted[])
            end
        finally
            if client_socket !== nothing
                Sockets.socket_cleanup!(client_socket)
            end
            if accepted[] !== nothing
                Sockets.socket_cleanup!(accepted[])
            end
            Sockets.socket_cleanup!(server_socket)
            EventLoops.event_loop_destroy!(el_val)
        end

        # IPv4 UDP
        el = EventLoops.event_loop_new()
        el_val = el isa EventLoops.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test EventLoops.event_loop_run!(el_val) === nothing

        opts_udp = Sockets.SocketOptions(;
            type = Sockets.SocketType.DGRAM,
            domain = Sockets.SocketDomain.IPV4,
            connect_timeout_ms = 3000,
            network_interface_name = iface,
        )

        local server_socket
        try
            server_socket = Sockets.socket_init(opts_udp)
        catch e
            @test e isa Reseau.ReseauError
            @test e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED ||
                e.code == EventLoops.ERROR_IO_SOCKET_INVALID_OPTIONS
            EventLoops.event_loop_destroy!(el_val)
            return
        end

        client_socket = nothing
        try
            bind_opts = Sockets.SocketBindOptions(Sockets.SocketEndpoint("127.0.0.1", 0))
            try
                Sockets.socket_bind(server_socket, bind_opts)
            catch e
                @test e isa Reseau.ReseauError
                @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_OPTIONS ||
                    e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
                return
            end

            bound = Sockets.socket_get_bound_address(server_socket)
            @test bound isa Sockets.SocketEndpoint
            port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                return
            end

            client = Sockets.socket_init(opts_udp)
            client_socket = client isa Sockets.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            connect_opts = Sockets.SocketConnectOptions(
                Sockets.SocketEndpoint("127.0.0.1", port);
                event_loop = el_val,
                on_connection_result = Reseau.EventCallable(err -> nothing),
            )

            @test Sockets.socket_connect(client_socket, connect_opts) === nothing
        finally
            if client_socket !== nothing
                Sockets.socket_cleanup!(client_socket)
            end
            Sockets.socket_cleanup!(server_socket)
            EventLoops.event_loop_destroy!(el_val)
        end

        # IPv6 stream
        el = EventLoops.event_loop_new()
        el_val = el isa EventLoops.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test EventLoops.event_loop_run!(el_val) === nothing

        opts6 = Sockets.SocketOptions(;
            type = Sockets.SocketType.STREAM,
            domain = Sockets.SocketDomain.IPV6,
            connect_timeout_ms = 3000,
            network_interface_name = iface,
        )

        local server_socket
        try
            server_socket = Sockets.socket_init(opts6)
        catch e
            @test e isa Reseau.ReseauError
            @test e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED ||
                e.code == EventLoops.ERROR_IO_SOCKET_INVALID_OPTIONS
            EventLoops.event_loop_destroy!(el_val)
            return
        end

        client_socket = nothing
        accepted = Ref{Any}(nothing)

        try
            bind_opts = Sockets.SocketBindOptions(Sockets.SocketEndpoint("::1", 0))
            try
                Sockets.socket_bind(server_socket, bind_opts)
            catch e
                @test e isa Reseau.ReseauError
                @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
                return
            end
            @test Sockets.socket_listen(server_socket, 1024) === nothing

            bound = Sockets.socket_get_bound_address(server_socket)
            @test bound isa Sockets.SocketEndpoint
            port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                return
            end

            accept_err = Ref{Int}(0)
            connect_err = Ref{Int}(0)
            connect_done = Threads.Atomic{Bool}(false)

            on_accept = Reseau.ChannelCallable((err, new_sock) -> begin
                accept_err[] = err
                accepted[] = new_sock
                return nothing
            end)

            accept_opts = Sockets.SocketListenerOptions(on_accept_result = on_accept)
            @test Sockets.socket_start_accept(server_socket, el_val, accept_opts) === nothing

            client = Sockets.socket_init(opts6)
            client_socket = client isa Sockets.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            connect_opts = Sockets.SocketConnectOptions(
                Sockets.SocketEndpoint("::1", port);
                event_loop = el_val,
                on_connection_result = Reseau.EventCallable(err -> begin
                    connect_err[] = err
                    connect_done[] = true
                    return nothing
                end),
            )

            @test Sockets.socket_connect(client_socket, connect_opts) === nothing
            @test wait_for_flag(connect_done)
            @test connect_err[] == Reseau.AWS_OP_SUCCESS
            @test accept_err[] == Reseau.AWS_OP_SUCCESS
        finally
            if client_socket !== nothing
                Sockets.socket_cleanup!(client_socket)
            end
            if accepted[] !== nothing
                Sockets.socket_cleanup!(accepted[])
            end
            Sockets.socket_cleanup!(server_socket)
            EventLoops.event_loop_destroy!(el_val)
        end
    end
end

@trace_socket_testset "socket bind to invalid interface" begin
    if Sys.iswindows()
        @test true
    else
        opts = Sockets.SocketOptions(;
            type = Sockets.SocketType.STREAM,
            domain = Sockets.SocketDomain.IPV4,
            connect_timeout_ms = 3000,
            keepalive = true,
            keep_alive_interval_sec = 1000,
            keep_alive_timeout_sec = 60000,
            network_interface_name = "invalid",
        )

        try
            Sockets.socket_init(opts)
            @test false
        catch e
            @test e isa Reseau.ReseauError
            @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_OPTIONS ||
                e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
        end
    end
end

@trace_socket_testset "vsock loopback socket communication" begin
    if !Sys.islinux()
        @test true
    else
        el = EventLoops.event_loop_new()
        el_val = el isa EventLoops.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test EventLoops.event_loop_run!(el_val) === nothing

        opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.VSOCK, connect_timeout_ms = 3000)
        local server_socket
        try
            server_socket = Sockets.socket_init(opts)
        catch e
            @test e isa Reseau.ReseauError
            @test e.code == EventLoops.ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY ||
                e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED ||
                e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
            EventLoops.event_loop_destroy!(el_val)
            return
        end

        client_socket = nothing
        accepted = Ref{Any}(nothing)

        try
            bind_opts = Sockets.SocketBindOptions(Sockets.SocketEndpoint("1", 0))
            try
                Sockets.socket_bind(server_socket, bind_opts)
            catch e
                @test e isa Reseau.ReseauError
                @test e.code == EventLoops.ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY ||
                    e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED ||
                    e.code == Reseau.ERROR_NO_PERMISSION ||
                    e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
                return
            end
            @test Sockets.socket_listen(server_socket, 1024) === nothing

            bound = Sockets.socket_get_bound_address(server_socket)
            @test bound isa Sockets.SocketEndpoint
            port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                return
            end

            accept_err = Ref{Int}(0)
            connect_err = Ref{Int}(0)
            connect_done = Threads.Atomic{Bool}(false)

            on_accept = Reseau.ChannelCallable((err, new_sock) -> begin
                accept_err[] = err
                accepted[] = new_sock
                return nothing
            end)

            accept_opts = Sockets.SocketListenerOptions(on_accept_result = on_accept)
            @test Sockets.socket_start_accept(server_socket, el_val, accept_opts) === nothing

            client = Sockets.socket_init(opts)
            client_socket = client isa Sockets.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            connect_opts = Sockets.SocketConnectOptions(
                Sockets.SocketEndpoint("1", port);
                event_loop = el_val,
                on_connection_result = Reseau.EventCallable(err -> begin
                    connect_err[] = err
                    connect_done[] = true
                    return nothing
                end),
            )

            try
                Sockets.socket_connect(client_socket, connect_opts)
            catch e
                @test e isa Reseau.ReseauError
                @test _is_allowed_connect_error(e.code) ||
                    e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS ||
                    e.code == EventLoops.ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY
                return
            end
            @test wait_for_flag(connect_done)
            if connect_err[] != Reseau.AWS_OP_SUCCESS
                @test _is_allowed_connect_error(connect_err[]) ||
                    connect_err[] == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
            else
                @test accept_err[] == Reseau.AWS_OP_SUCCESS
            end
        finally
            if client_socket !== nothing
                Sockets.socket_cleanup!(client_socket)
            end
            if accepted[] !== nothing
                Sockets.socket_cleanup!(accepted[])
            end
            Sockets.socket_cleanup!(server_socket)
            EventLoops.event_loop_destroy!(el_val)
        end
    end
end

@trace_socket_testset "socket init domain-based selection" begin
    # IPV4 socket
    opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    sock = Sockets.socket_init(opts)
    @test sock isa Sockets.Socket
    if sock isa Sockets.Socket
        @static if Sys.isapple()
            @test sock.impl isa Sockets.NWSocket
        elseif Sys.iswindows()
            @test sock.impl isa Sockets.WinsockSocket
        else
            @test sock.impl isa Sockets.PosixSocket
        end
        Sockets.socket_close(sock)
    end

    # LOCAL domain
    local_opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.LOCAL)
    local_sock = Sockets.socket_init(local_opts)
    @test local_sock isa Sockets.Socket
    if local_sock isa Sockets.Socket
        @static if Sys.iswindows()
            @test local_sock.impl isa Sockets.WinsockSocket
        else
            @test local_sock.impl isa Sockets.PosixSocket
        end
        Sockets.socket_close(local_sock)
    end
end

@trace_socket_testset "winsock stubs" begin
    if Sys.iswindows()
        @test Sockets.winsock_check_and_init!() === nothing
    else
        try
            Sockets.winsock_check_and_init!()
            @test false
        catch e
            @test e isa Reseau.ReseauError
            @test e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
        end
    end

    try
        res = Sockets.winsock_get_connectex_fn()
        @test res isa Ptr
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
    end

    try
        res = Sockets.winsock_get_acceptex_fn()
        @test res isa Ptr
    catch e
        @test e isa Reseau.ReseauError
        @test e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
    end
end

@trace_socket_testset "socket nonblocking cloexec" begin
    if Sys.iswindows()
        @test true
    else
        opts = Sockets.SocketOptions(;
            type = Sockets.SocketType.STREAM,
            domain = Sockets.SocketDomain.IPV4,
        )
        sock = Sockets.socket_init(opts)
        @test sock isa Sockets.Socket
	        if sock isa Sockets.Socket
	            fd = sock.io_handle.fd
	            flags = Reseau._fcntl(fd, Sockets.F_GETFL)
	            @test (flags & Sockets.O_NONBLOCK) != 0
	            fd_flags = Reseau._fcntl(fd, Sockets.F_GETFD)
	            @test (fd_flags & Sockets.FD_CLOEXEC) != 0
	            Sockets.socket_close(sock)
	        end
	    end
end

@trace_socket_testset "socket connect read write" begin
    el = EventLoops.event_loop_new()
    el_val = el isa EventLoops.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test EventLoops.event_loop_run!(el_val) === nothing
    # Use LOCAL domain to ensure POSIX path (standalone event loop, no ELG)
    opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.LOCAL)
    server = Sockets.socket_init(opts)
    server_socket = server isa Sockets.Socket ? server : nothing
    @test server_socket !== nothing

    client_socket = nothing
    accepted = Ref{Any}(nothing)

    local_endpoint = Sockets.SocketEndpoint()
    Sockets.socket_endpoint_init_local_address_for_test!(local_endpoint)

    try
        if server_socket === nothing
            return
        end

        bind_opts = Sockets.SocketBindOptions(local_endpoint)
        @test Sockets.socket_bind(server_socket, bind_opts) === nothing
        @test Sockets.socket_listen(server_socket, 8) === nothing

        accept_err = Ref{Int}(0)
        read_err = Ref{Int}(0)
        payload = Ref{String}("")
        read_done = Threads.Atomic{Bool}(false)

        connect_err = Ref{Int}(0)
        connect_done = Threads.Atomic{Bool}(false)
        write_err = Ref{Int}(0)
        write_done = Threads.Atomic{Bool}(false)

        on_accept = Reseau.ChannelCallable((err, new_sock) -> begin
            accept_err[] = err
            accepted[] = new_sock
            if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
                read_done[] = true
                return nothing
            end

            try
                Sockets.socket_assign_to_event_loop(new_sock, el_val)
            catch e
                read_err[] = e isa Reseau.ReseauError ? e.code : -1
                read_done[] = true
                return nothing
            end

            try
                Sockets.socket_subscribe_to_readable_events(
                    new_sock, Reseau.EventCallable(err -> begin
                        read_err[] = err
                        if err != Reseau.AWS_OP_SUCCESS
                            read_done[] = true
                            return nothing
                        end

                        buf = Reseau.ByteBuffer(64)
                        try
                            Sockets.socket_read(new_sock, buf)
                            payload[] = String(Reseau.byte_cursor_from_buf(buf))
                        catch e
                            read_err[] = e isa Reseau.ReseauError ? e.code : -1
                        end
                        read_done[] = true
                        return nothing
                    end)
                )
            catch e
                read_err[] = e isa Reseau.ReseauError ? e.code : -1
                read_done[] = true
            end
            return nothing
        end)

        accept_opts = Sockets.SocketListenerOptions(on_accept_result = on_accept)
        @test Sockets.socket_start_accept(server_socket, el_val, accept_opts) === nothing

        client = Sockets.socket_init(opts)
        client_socket = client isa Sockets.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end
        connect_opts = Sockets.SocketConnectOptions(
            local_endpoint;
            event_loop = el_val,
            on_connection_result = Reseau.EventCallable(err -> begin
                connect_err[] = err
                connect_done[] = true
                if err != Reseau.AWS_OP_SUCCESS
                    return nothing
                end

                cursor = Reseau.ByteCursor("ping")
                try
                    Sockets.socket_write(
                        client_socket, cursor, Reseau.WriteCallable((err, bytes) -> begin
                            write_err[] = err
                            write_done[] = true
                            return nothing
                        end)
                    )
                catch e
                    write_err[] = e isa Reseau.ReseauError ? e.code : -1
                    write_done[] = true
                end

                return nothing
            end),
        )

        @test Sockets.socket_connect(client_socket, connect_opts) === nothing
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
            Sockets.socket_close(client_socket)
        end
        if accepted[] !== nothing
            Sockets.socket_close(accepted[])
        end
        if server_socket !== nothing
            Sockets.socket_close(server_socket)
        end
        EventLoops.event_loop_destroy!(el_val)
        # Clean up Unix domain socket file (Windows LOCAL uses named pipes, not a filesystem path).
        @static if !Sys.iswindows()
            sock_path = Sockets.get_address(local_endpoint)
            isfile(sock_path) && rm(sock_path; force=true)
        end
    end
end

@trace_socket_testset "nw socket connect read write" begin
    @static if !Sys.isapple()
        @test true
        return
    end

    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    elg_val = elg isa EventLoops.EventLoopGroup ? elg : nothing
    @test elg_val !== nothing
    if elg_val === nothing
        return
    end
    el_val = EventLoops.event_loop_group_get_next_loop(elg_val)
    @test el_val isa EventLoops.EventLoop
    if !(el_val isa EventLoops.EventLoop)
        EventLoops.event_loop_group_destroy!(elg_val)
        return
    end

    opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    server = Sockets.socket_init(opts)
    server_socket = server isa Sockets.Socket ? server : nothing
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

        bind_opts = Sockets.SocketBindOptions(Sockets.SocketEndpoint("127.0.0.1", 0))
        @test Sockets.socket_bind(server_socket, bind_opts) === nothing
        @test Sockets.socket_listen(server_socket, 8) === nothing

        on_accept_started = Reseau.EventCallable(err -> begin
            accept_started[] = true
            if err == Reseau.AWS_OP_SUCCESS && server_socket !== nothing
                bound = Sockets.socket_get_bound_address(server_socket)
                if bound isa Sockets.SocketEndpoint
                    port_ref[] = Int(bound.port)
                end
            end
            return nothing
        end)

        on_accept = Reseau.ChannelCallable((err, new_sock) -> begin
            accept_err[] = err
            accepted[] = new_sock
            if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
                read_done[] = true
                return nothing
            end

            try
                Sockets.socket_assign_to_event_loop(new_sock, el_val)
            catch e
                read_err[] = e isa Reseau.ReseauError ? e.code : -1
                read_done[] = true
                return nothing
            end

            try
                Sockets.socket_subscribe_to_readable_events(
                    new_sock, Reseau.EventCallable(err -> begin
                        read_err[] = err
                        if err != Reseau.AWS_OP_SUCCESS
                            read_done[] = true
                            return nothing
                        end

                        buf = Reseau.ByteBuffer(64)
                        try
                            Sockets.socket_read(new_sock, buf)
                            payload[] = String(Reseau.byte_cursor_from_buf(buf))
                        catch e
                            read_err[] = e isa Reseau.ReseauError ? e.code : -1
                        end
                        read_done[] = true
                        return nothing
                    end)
                )
            catch e
                read_err[] = e isa Reseau.ReseauError ? e.code : -1
                read_done[] = true
            end
            return nothing
        end)

        accept_opts = Sockets.SocketListenerOptions(
            on_accept_result = on_accept,
            on_accept_start = on_accept_started,
        )
        @test Sockets.socket_start_accept(server_socket, el_val, accept_opts) === nothing

        @test wait_for_flag(accept_started)
        @test port_ref[] != 0

        client = Sockets.socket_init(opts)
        client_socket = client isa Sockets.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end

        connect_opts = Sockets.SocketConnectOptions(
            Sockets.SocketEndpoint("127.0.0.1", port_ref[]);
            event_loop = el_val,
            on_connection_result = Reseau.EventCallable(err -> begin
                connect_err[] = err
                connect_done[] = true
                if err != Reseau.AWS_OP_SUCCESS
                    return nothing
                end

                cursor = Reseau.ByteCursor("ping")
                try
                    Sockets.socket_write(
                        client_socket, cursor, Reseau.WriteCallable((err, bytes) -> begin
                            write_err[] = err
                            write_done[] = true
                            return nothing
                        end)
                    )
                catch e
                    write_err[] = e isa Reseau.ReseauError ? e.code : -1
                    write_done[] = true
                end
                return nothing
            end),
        )

        @test Sockets.socket_connect(client_socket, connect_opts) === nothing
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
            Sockets.socket_close(client_socket)
        end
        if accepted[] !== nothing
            Sockets.socket_close(accepted[])
        end
        if server_socket !== nothing
            Sockets.socket_close(server_socket)
        end
        EventLoops.event_loop_destroy!(el_val)
    end
end

@trace_socket_testset "sock write cb is async" begin
    el = EventLoops.event_loop_new()
    el_val = el isa EventLoops.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test EventLoops.event_loop_run!(el_val) === nothing

    opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    server = Sockets.socket_init(opts)
    server_socket = server isa Sockets.Socket ? server : nothing
    @test server_socket !== nothing

    client_socket = nothing
    accepted = Ref{Any}(nothing)

    try
        if server_socket === nothing
            return
        end

        bind_opts = Sockets.SocketBindOptions(Sockets.SocketEndpoint("127.0.0.1", 0))
        @test Sockets.socket_bind(server_socket, bind_opts) === nothing
        @test Sockets.socket_listen(server_socket, 8) === nothing

        bound = Sockets.socket_get_bound_address(server_socket)
        @test bound isa Sockets.SocketEndpoint
        port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
        if port == 0
            return
        end

        accept_done = Threads.Atomic{Bool}(false)
        on_accept = Reseau.ChannelCallable((err, new_sock) -> begin
            accepted[] = new_sock
            accept_done[] = true
            if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
                return nothing
            end
            try
                Sockets.socket_assign_to_event_loop(new_sock, el_val)
            catch
                return nothing
            end
            _ = Sockets.socket_subscribe_to_readable_events(
                new_sock, Reseau.EventCallable(err -> begin
                    if err != Reseau.AWS_OP_SUCCESS
                        return nothing
                    end
                    buf = Reseau.ByteBuffer(64)
                    _ = Sockets.socket_read(new_sock, buf)
                    return nothing
                end)
            )
            return nothing
        end)

        accept_opts = Sockets.SocketListenerOptions(on_accept_result = on_accept)
        @test Sockets.socket_start_accept(server_socket, el_val, accept_opts) === nothing

        client = Sockets.socket_init(opts)
        client_socket = client isa Sockets.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end

        connect_done = Threads.Atomic{Bool}(false)
        write_started = Threads.Atomic{Bool}(false)
        write_cb_invoked = Threads.Atomic{Bool}(false)
        write_cb_sync = Threads.Atomic{Bool}(false)
        write_err = Ref{Int}(0)

        connect_opts = Sockets.SocketConnectOptions(
            Sockets.SocketEndpoint("127.0.0.1", port);
            event_loop = el_val,
            on_connection_result = Reseau.EventCallable(err -> begin
                connect_done[] = true
                if err != Reseau.AWS_OP_SUCCESS
                    write_started[] = true
                    return nothing
                end
                cursor = Reseau.ByteCursor("ping")
                write_cb_invoked[] = false
                write_cb_sync[] = false
                try
                    Sockets.socket_write(
                        client_socket, cursor, Reseau.WriteCallable((err, bytes) -> begin
                            write_err[] = err
                            write_cb_invoked[] = true
                            return nothing
                        end)
                    )
                catch e
                    write_err[] = e isa Reseau.ReseauError ? e.code : -1
                    write_cb_invoked[] = true
                end
                if write_cb_invoked[]
                    write_cb_sync[] = true
                end
                write_started[] = true
                return nothing
            end),
        )

        @test Sockets.socket_connect(client_socket, connect_opts) === nothing
        @test wait_for_flag(connect_done)
        @test wait_for_flag(accept_done)
        @test wait_for_flag(write_started)
        @test wait_for_flag(write_cb_invoked)
        @test !write_cb_sync[]
        @test write_err[] == Reseau.AWS_OP_SUCCESS
    finally
        if client_socket !== nothing
            Sockets.socket_close(client_socket)
        end
        if accepted[] !== nothing
            Sockets.socket_close(accepted[])
        end
        if server_socket !== nothing
            Sockets.socket_close(server_socket)
        end
        EventLoops.event_loop_destroy!(el_val)
    end
end

@trace_socket_testset "connect timeout" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    elg_val = elg isa EventLoops.EventLoopGroup ? elg : nothing
    @test elg_val !== nothing
    if elg_val === nothing
        return
    end
    el_val = EventLoops.event_loop_group_get_next_loop(elg_val)
    @test el_val isa EventLoops.EventLoop
    if !(el_val isa EventLoops.EventLoop)
        EventLoops.event_loop_group_destroy!(elg_val)
        return
    end

    opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4, connect_timeout_ms = 200)
    sock = Sockets.socket_init(opts)
    socket_val = sock isa Sockets.Socket ? sock : nothing
    @test socket_val !== nothing
    if socket_val === nothing
        EventLoops.event_loop_group_destroy!(elg_val)
        return
    end

    connect_done = Threads.Atomic{Bool}(false)
    connect_err = Ref{Int}(0)
    endpoint = Sockets.SocketEndpoint("10.255.255.1", 81)
    connect_opts = Sockets.SocketConnectOptions(
        endpoint;
        event_loop = el_val,
        on_connection_result = Reseau.EventCallable(err -> begin
            connect_err[] = err
            connect_done[] = true
            return nothing
        end),
    )

    try
        try
            Sockets.socket_connect(socket_val, connect_opts)
            @test wait_for_flag(connect_done; timeout_s = 3.0)
            @test _is_allowed_connect_error(connect_err[])
        catch e
            @test e isa Reseau.ReseauError
            @test _is_allowed_connect_error(e.code)
        end
    finally
        Sockets.socket_cleanup!(socket_val)
        EventLoops.event_loop_group_destroy!(elg_val)
    end
end

@trace_socket_testset "connect timeout cancellation" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    elg_val = elg isa EventLoops.EventLoopGroup ? elg : nothing
    @test elg_val !== nothing
    if elg_val === nothing
        return
    end
    el_val = EventLoops.event_loop_group_get_next_loop(elg_val)
    @test el_val isa EventLoops.EventLoop
    if !(el_val isa EventLoops.EventLoop)
        EventLoops.event_loop_group_destroy!(elg_val)
        return
    end

    opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4, connect_timeout_ms = 10_000)
    sock = Sockets.socket_init(opts)
    socket_val = sock isa Sockets.Socket ? sock : nothing
    @test socket_val !== nothing
    if socket_val === nothing
        EventLoops.event_loop_group_destroy!(elg_val)
        return
    end

    connect_done = Threads.Atomic{Bool}(false)
    connect_err = Ref{Int}(0)
    endpoint = Sockets.SocketEndpoint("10.255.255.1", 81)
    connect_opts = Sockets.SocketConnectOptions(
        endpoint;
        event_loop = el_val,
        on_connection_result = Reseau.EventCallable(err -> begin
            connect_err[] = err
            connect_done[] = true
            return nothing
        end),
    )

    try
        try
            Sockets.socket_connect(socket_val, connect_opts)
            EventLoops.event_loop_group_destroy!(elg_val)
            @test connect_done[]
            @test connect_err[] == EventLoops.ERROR_IO_EVENT_LOOP_SHUTDOWN ||
                _is_allowed_connect_error(connect_err[])
        catch e
            @test e isa Reseau.ReseauError
            @test _is_allowed_connect_error(e.code)
        end
    finally
        Sockets.socket_cleanup!(socket_val)
    end
end

@trace_socket_testset "cleanup before connect or timeout" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
        elg_val = elg isa EventLoops.EventLoopGroup ? elg : nothing
        @test elg_val !== nothing
        if elg_val === nothing
            return
        end
        el_val = EventLoops.event_loop_group_get_next_loop(elg_val)
        @test el_val isa EventLoops.EventLoop
        if !(el_val isa EventLoops.EventLoop)
            EventLoops.event_loop_group_destroy!(elg_val)
            return
        end

        opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4, connect_timeout_ms = 1000)
        sock = Sockets.socket_init(opts)
        socket_val = sock isa Sockets.Socket ? sock : nothing
        @test socket_val !== nothing
        if socket_val === nothing
            EventLoops.event_loop_group_destroy!(elg_val)
            return
        end

        connect_done = Threads.Atomic{Bool}(false)
        connect_err = Ref{Int}(0)
        cleanup_done = Threads.Atomic{Bool}(false)
        endpoint = Sockets.SocketEndpoint("10.255.255.1", 81)
        connect_opts = Sockets.SocketConnectOptions(
            endpoint;
            event_loop = el_val,
            on_connection_result = Reseau.EventCallable(err -> begin
                connect_err[] = err
                connect_done[] = true
                return nothing
            end),
        )

        cleanup_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
            Sockets.socket_cleanup!(socket_val)
            cleanup_done[] = true
            return nothing
        end); type_tag = "socket_cleanup_before_connect")

        try
            try
                Sockets.socket_connect(socket_val, connect_opts)
                EventLoops.event_loop_schedule_task_now!(el_val, cleanup_task)
                @test wait_for_flag(cleanup_done)
                sleep(0.05)
                if connect_done[]
                    @test _is_allowed_connect_error(connect_err[])
                else
                    @test true
                end
            catch e
                @test e isa Reseau.ReseauError
                @test _is_allowed_connect_error(e.code)
            end
        finally
            Sockets.socket_cleanup!(socket_val)
            EventLoops.event_loop_group_destroy!(elg_val)
        end
end

@trace_socket_testset "cleanup in accept doesn't explode" begin
    el = EventLoops.event_loop_new()
    el_val = el isa EventLoops.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test EventLoops.event_loop_run!(el_val) === nothing

    opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    listener = Sockets.socket_init(opts)
    listener_socket = listener isa Sockets.Socket ? listener : nothing
    @test listener_socket !== nothing
    if listener_socket === nothing
        EventLoops.event_loop_destroy!(el_val)
        return
    end

    incoming = Ref{Any}(nothing)
    accept_done = Threads.Atomic{Bool}(false)
    accept_err = Ref{Int}(0)
    connect_done = Threads.Atomic{Bool}(false)
    connect_err = Ref{Int}(0)
    client_socket = nothing

    try
        bind_opts = Sockets.SocketBindOptions(Sockets.SocketEndpoint("127.0.0.1", 0))
        @test Sockets.socket_bind(listener_socket, bind_opts) === nothing
        @test Sockets.socket_listen(listener_socket, 1024) === nothing

        bound = Sockets.socket_get_bound_address(listener_socket)
        @test bound isa Sockets.SocketEndpoint
        port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
        if port == 0
            return
        end

        on_accept = Reseau.ChannelCallable((err, new_sock) -> begin
            accept_err[] = err
            incoming[] = new_sock
            accept_done[] = true
            if new_sock !== nothing
                Sockets.socket_cleanup!(new_sock)
            end
            return nothing
        end)

        accept_opts = Sockets.SocketListenerOptions(on_accept_result = on_accept)
        @test Sockets.socket_start_accept(listener_socket, el_val, accept_opts) === nothing

        client = Sockets.socket_init(opts)
        client_socket = client isa Sockets.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end

        connect_opts = Sockets.SocketConnectOptions(
            Sockets.SocketEndpoint("127.0.0.1", port);
            event_loop = el_val,
            on_connection_result = Reseau.EventCallable(err -> begin
                connect_err[] = err
                connect_done[] = true
                return nothing
            end),
        )

        @test Sockets.socket_connect(client_socket, connect_opts) === nothing
        @test wait_for_flag(accept_done)
        @test wait_for_flag(connect_done)
        @test accept_err[] == Reseau.AWS_OP_SUCCESS
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
    finally
        if client_socket !== nothing
            Sockets.socket_cleanup!(client_socket)
        end
        if incoming[] !== nothing
            Sockets.socket_cleanup!(incoming[])
        end
        Sockets.socket_cleanup!(listener_socket)
        EventLoops.event_loop_destroy!(el_val)
    end
end

@trace_socket_testset "cleanup in write cb doesn't explode" begin
    el = EventLoops.event_loop_new()
    el_val = el isa EventLoops.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test EventLoops.event_loop_run!(el_val) === nothing

    opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    listener = Sockets.socket_init(opts)
    listener_socket = listener isa Sockets.Socket ? listener : nothing
    @test listener_socket !== nothing
    if listener_socket === nothing
        EventLoops.event_loop_destroy!(el_val)
        return
    end

    accepted = Ref{Any}(nothing)
    accept_done = Threads.Atomic{Bool}(false)
    connect_done = Threads.Atomic{Bool}(false)
    client_socket = nothing

    try
        bind_opts = Sockets.SocketBindOptions(Sockets.SocketEndpoint("127.0.0.1", 0))
        @test Sockets.socket_bind(listener_socket, bind_opts) === nothing
        @test Sockets.socket_listen(listener_socket, 1024) === nothing

        bound = Sockets.socket_get_bound_address(listener_socket)
        @test bound isa Sockets.SocketEndpoint
        port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
        if port == 0
            return
        end

        on_accept = Reseau.ChannelCallable((err, new_sock) -> begin
            accepted[] = new_sock
            accept_done[] = true
            return nothing
        end)

        accept_opts = Sockets.SocketListenerOptions(on_accept_result = on_accept)
        @test Sockets.socket_start_accept(listener_socket, el_val, accept_opts) === nothing

        client = Sockets.socket_init(opts)
        client_socket = client isa Sockets.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end

        connect_opts = Sockets.SocketConnectOptions(
            Sockets.SocketEndpoint("127.0.0.1", port);
            event_loop = el_val,
            on_connection_result = Reseau.EventCallable(err -> begin
                connect_done[] = true
                return nothing
            end),
        )

        @test Sockets.socket_connect(client_socket, connect_opts) === nothing
        @test wait_for_flag(accept_done)
        @test wait_for_flag(connect_done)

        server_sock = accepted[]
        @test server_sock !== nothing
        if server_sock === nothing
            return
        end

        Sockets.socket_assign_to_event_loop(server_sock, el_val)

        write_done_client = Threads.Atomic{Bool}(false)
        write_err_client = Ref{Int}(0)
        write_done_server = Threads.Atomic{Bool}(false)
        write_err_server = Ref{Int}(0)

        write_task_client = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
            cursor = Reseau.ByteCursor("teapot")
            try
                Sockets.socket_write(
                    client_socket,
                    cursor,
                    Reseau.WriteCallable((err, bytes) -> begin
                        write_err_client[] = err
                        Sockets.socket_cleanup!(client_socket)
                        write_done_client[] = true
                        return nothing
                    end),
                )
            catch e
                write_err_client[] = e isa Reseau.ReseauError ? e.code : -1
                Sockets.socket_cleanup!(client_socket)
                write_done_client[] = true
            end
            return nothing
        end); type_tag = "socket_write_cleanup_client")

        write_task_server = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
            cursor = Reseau.ByteCursor("spout")
            try
                Sockets.socket_write(
                    server_sock,
                    cursor,
                    Reseau.WriteCallable((err, bytes) -> begin
                        write_err_server[] = err
                        Sockets.socket_cleanup!(server_sock)
                        write_done_server[] = true
                        return nothing
                    end),
                )
            catch e
                write_err_server[] = e isa Reseau.ReseauError ? e.code : -1
                Sockets.socket_cleanup!(server_sock)
                write_done_server[] = true
            end
            return nothing
        end); type_tag = "socket_write_cleanup_server")

        EventLoops.event_loop_schedule_task_now!(el_val, write_task_client)
        @test wait_for_flag(write_done_client)
        EventLoops.event_loop_schedule_task_now!(el_val, write_task_server)
        @test wait_for_flag(write_done_server)
        @test write_err_client[] == Reseau.AWS_OP_SUCCESS
        @test write_err_server[] == Reseau.AWS_OP_SUCCESS
    finally
        if client_socket !== nothing
            Sockets.socket_cleanup!(client_socket)
        end
        if accepted[] !== nothing
            Sockets.socket_cleanup!(accepted[])
        end
        Sockets.socket_cleanup!(listener_socket)
        EventLoops.event_loop_destroy!(el_val)
    end
end

@trace_socket_testset "local socket communication" begin
    el = EventLoops.event_loop_new()
    el_val = el isa EventLoops.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test EventLoops.event_loop_run!(el_val) === nothing

    opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.LOCAL)
    server = Sockets.socket_init(opts)
    server_socket = server isa Sockets.Socket ? server : nothing
    @test server_socket !== nothing

    client_socket = nothing
    accepted = Ref{Any}(nothing)
    endpoint = Sockets.SocketEndpoint()
    Sockets.socket_endpoint_init_local_address_for_test!(endpoint)
    local_path = Sockets.get_address(endpoint)

    try
        if server_socket === nothing
            return
        end

        bind_opts = Sockets.SocketBindOptions(endpoint)
        @test Sockets.socket_bind(server_socket, bind_opts) === nothing
        @test Sockets.socket_listen(server_socket, 8) === nothing

        accept_err = Ref{Int}(0)
        read_err = Ref{Int}(0)
        payload = Ref{String}("")
        read_done = Threads.Atomic{Bool}(false)

        connect_err = Ref{Int}(0)
        connect_done = Threads.Atomic{Bool}(false)
        write_err = Ref{Int}(0)
        write_done = Threads.Atomic{Bool}(false)

        on_accept = Reseau.ChannelCallable((err, new_sock) -> begin
            accept_err[] = err
            accepted[] = new_sock
            if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
                read_done[] = true
                return nothing
            end

            try
                Sockets.socket_assign_to_event_loop(new_sock, el_val)
            catch e
                read_err[] = e isa Reseau.ReseauError ? e.code : -1
                read_done[] = true
                return nothing
            end

            try
                Sockets.socket_subscribe_to_readable_events(
                    new_sock, Reseau.EventCallable(err -> begin
                        read_err[] = err
                        if err != Reseau.AWS_OP_SUCCESS
                            read_done[] = true
                            return nothing
                        end

                        buf = Reseau.ByteBuffer(64)
                        try
                            Sockets.socket_read(new_sock, buf)
                            payload[] = String(Reseau.byte_cursor_from_buf(buf))
                        catch e
                            read_err[] = e isa Reseau.ReseauError ? e.code : -1
                        end
                        read_done[] = true
                        return nothing
                    end)
                )
            catch e
                read_err[] = e isa Reseau.ReseauError ? e.code : -1
                read_done[] = true
            end
            return nothing
        end)

        accept_opts = Sockets.SocketListenerOptions(on_accept_result = on_accept)
        @test Sockets.socket_start_accept(server_socket, el_val, accept_opts) === nothing

        client = Sockets.socket_init(opts)
        client_socket = client isa Sockets.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end

        connect_opts = Sockets.SocketConnectOptions(
            endpoint;
            event_loop = el_val,
            on_connection_result = Reseau.EventCallable(err -> begin
                connect_err[] = err
                connect_done[] = true
                if err != Reseau.AWS_OP_SUCCESS
                    return nothing
                end

                cursor = Reseau.ByteCursor("ping")
                try
                    Sockets.socket_write(
                        client_socket, cursor, Reseau.WriteCallable((err, bytes) -> begin
                            write_err[] = err
                            write_done[] = true
                            return nothing
                        end)
                    )
                catch e
                    write_err[] = e isa Reseau.ReseauError ? e.code : -1
                    write_done[] = true
                end
                return nothing
            end),
        )

        @test Sockets.socket_connect(client_socket, connect_opts) === nothing
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
            Sockets.socket_close(client_socket)
        end
        if accepted[] !== nothing
            Sockets.socket_close(accepted[])
        end
        if server_socket !== nothing
            Sockets.socket_close(server_socket)
        end
        EventLoops.event_loop_destroy!(el_val)
        if !isempty(local_path) && isfile(local_path)
            rm(local_path; force = true)
        end
    end
end

@trace_socket_testset "local socket connect before accept" begin
    el = EventLoops.event_loop_new()
    el_val = el isa EventLoops.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test EventLoops.event_loop_run!(el_val) === nothing

    opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.LOCAL)
    server = Sockets.socket_init(opts)
    server_socket = server isa Sockets.Socket ? server : nothing
    @test server_socket !== nothing

    client_socket = nothing
    accepted = Ref{Any}(nothing)
    endpoint = Sockets.SocketEndpoint()
    Sockets.socket_endpoint_init_local_address_for_test!(endpoint)
    local_path = Sockets.get_address(endpoint)

    try
        if server_socket === nothing
            return
        end

        bind_opts = Sockets.SocketBindOptions(endpoint)
        @test Sockets.socket_bind(server_socket, bind_opts) === nothing
        @test Sockets.socket_listen(server_socket, 1024) === nothing

        accept_err = Ref{Int}(0)
        accept_done = Threads.Atomic{Bool}(false)
        connect_err = Ref{Int}(0)
        connect_done = Threads.Atomic{Bool}(false)

        client = Sockets.socket_init(opts)
        client_socket = client isa Sockets.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end

        connect_opts = Sockets.SocketConnectOptions(
            endpoint;
            event_loop = el_val,
            on_connection_result = Reseau.EventCallable(err -> begin
                connect_err[] = err
                connect_done[] = true
                return nothing
            end),
        )

        @test Sockets.socket_connect(client_socket, connect_opts) === nothing

        on_accept = Reseau.ChannelCallable((err, new_sock) -> begin
            accept_err[] = err
            accepted[] = new_sock
            accept_done[] = true
            return nothing
        end)

        accept_opts = Sockets.SocketListenerOptions(on_accept_result = on_accept)
        @test Sockets.socket_start_accept(server_socket, el_val, accept_opts) === nothing

        @test wait_for_flag(connect_done)
        @test wait_for_flag(accept_done)
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
        @test accept_err[] == Reseau.AWS_OP_SUCCESS
    finally
        if client_socket !== nothing
            Sockets.socket_cleanup!(client_socket)
        end
        if accepted[] !== nothing
            Sockets.socket_cleanup!(accepted[])
        end
        if server_socket !== nothing
            Sockets.socket_cleanup!(server_socket)
        end
        EventLoops.event_loop_destroy!(el_val)
        if !isempty(local_path) && isfile(local_path)
            rm(local_path; force = true)
        end
    end
end

@trace_socket_testset "udp socket communication" begin
    el = EventLoops.event_loop_new()
    el_val = el isa EventLoops.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test EventLoops.event_loop_run!(el_val) === nothing

    opts = Sockets.SocketOptions(; type = Sockets.SocketType.DGRAM, domain = Sockets.SocketDomain.IPV4)
    server = Sockets.socket_init(opts)
    server_socket = server isa Sockets.Socket ? server : nothing
    @test server_socket !== nothing

    client_socket = nothing
    try
        if server_socket === nothing
            return
        end

        bind_opts = Sockets.SocketBindOptions(Sockets.SocketEndpoint("127.0.0.1", 0))
        @test Sockets.socket_bind(server_socket, bind_opts) === nothing

        bound = Sockets.socket_get_bound_address(server_socket)
        @test bound isa Sockets.SocketEndpoint
        port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
        if port == 0
            return
        end

        Sockets.socket_assign_to_event_loop(server_socket, el_val)

        read_err = Ref{Int}(0)
        read_done = Threads.Atomic{Bool}(false)
        payload = Ref{String}("")
        Sockets.socket_subscribe_to_readable_events(
            server_socket, Reseau.EventCallable(err -> begin
                read_err[] = err
                if err != Reseau.AWS_OP_SUCCESS
                    read_done[] = true
                    return nothing
                end
                    buf = Reseau.ByteBuffer(64)
                    try
                        Sockets.socket_read(server_socket, buf)
                        payload[] = String(Reseau.byte_cursor_from_buf(buf))
                    catch e
                        read_err[] = e isa Reseau.ReseauError ? e.code : -1
                    end
                    read_done[] = true
                    return nothing
            end)
        )

        client = Sockets.socket_init(opts)
        client_socket = client isa Sockets.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end

        connect_err = Ref{Int}(0)
        connect_done = Threads.Atomic{Bool}(false)
        write_err = Ref{Int}(0)
        write_done = Threads.Atomic{Bool}(false)

        connect_opts = Sockets.SocketConnectOptions(
            Sockets.SocketEndpoint("127.0.0.1", port);
            event_loop = el_val,
            on_connection_result = Reseau.EventCallable(err -> begin
                connect_err[] = err
                connect_done[] = true
                if err != Reseau.AWS_OP_SUCCESS
                    return nothing
                end
                cursor = Reseau.ByteCursor("ping")
                try
                    Sockets.socket_write(
                        client_socket, cursor, Reseau.WriteCallable((err, bytes) -> begin
                            write_err[] = err
                            write_done[] = true
                            return nothing
                        end)
                    )
                catch e
                    write_err[] = e isa Reseau.ReseauError ? e.code : -1
                    write_done[] = true
                end
                return nothing
            end),
        )

        @test Sockets.socket_connect(client_socket, connect_opts) === nothing
        @test wait_for_flag(connect_done)
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag(write_done)
        @test write_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag(read_done)
        @test read_err[] == Reseau.AWS_OP_SUCCESS
        @test payload[] == "ping"
    finally
        if client_socket !== nothing
            Sockets.socket_close(client_socket)
        end
        if server_socket !== nothing
            Sockets.socket_close(server_socket)
        end
        EventLoops.event_loop_destroy!(el_val)
    end
end

@trace_socket_testset "udp bind connect communication" begin
    el = EventLoops.event_loop_new()
    el_val = el isa EventLoops.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test EventLoops.event_loop_run!(el_val) === nothing

    opts = Sockets.SocketOptions(; type = Sockets.SocketType.DGRAM, domain = Sockets.SocketDomain.IPV4)
    server = Sockets.socket_init(opts)
    server_socket = server isa Sockets.Socket ? server : nothing
    @test server_socket !== nothing

    client_socket = nothing
    try
        if server_socket === nothing
            return
        end

        bind_opts = Sockets.SocketBindOptions(Sockets.SocketEndpoint("127.0.0.1", 0))
        @test Sockets.socket_bind(server_socket, bind_opts) === nothing

        bound = Sockets.socket_get_bound_address(server_socket)
        @test bound isa Sockets.SocketEndpoint
        port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
        if port == 0
            return
        end

        Sockets.socket_assign_to_event_loop(server_socket, el_val)

        read_err = Ref{Int}(0)
        read_done = Threads.Atomic{Bool}(false)
        payload = Ref{String}("")
        Sockets.socket_subscribe_to_readable_events(
            server_socket, Reseau.EventCallable(err -> begin
                read_err[] = err
                if err != Reseau.AWS_OP_SUCCESS
                    read_done[] = true
                    return nothing
                end
                buf = Reseau.ByteBuffer(64)
                try
                    Sockets.socket_read(server_socket, buf)
                    payload[] = String(Reseau.byte_cursor_from_buf(buf))
                catch e
                    read_err[] = e isa Reseau.ReseauError ? e.code : -1
                end
                read_done[] = true
                return nothing
            end)
        )

        client = Sockets.socket_init(opts)
        client_socket = client isa Sockets.Socket ? client : nothing
        @test client_socket !== nothing
        if client_socket === nothing
            return
        end

        local_bind = Sockets.SocketBindOptions(Sockets.SocketEndpoint("127.0.0.1", 0))
        @test Sockets.socket_bind(client_socket, local_bind) === nothing

        connect_err = Ref{Int}(0)
        connect_done = Threads.Atomic{Bool}(false)
        write_err = Ref{Int}(0)
        write_done = Threads.Atomic{Bool}(false)

        connect_opts = Sockets.SocketConnectOptions(
            Sockets.SocketEndpoint("127.0.0.1", port);
            event_loop = el_val,
            on_connection_result = Reseau.EventCallable(err -> begin
                connect_err[] = err
                connect_done[] = true
                if err != Reseau.AWS_OP_SUCCESS
                    return nothing
                end
                cursor = Reseau.ByteCursor("ping")
                try
                    Sockets.socket_write(
                        client_socket, cursor, Reseau.WriteCallable((err, bytes) -> begin
                            write_err[] = err
                            write_done[] = true
                            return nothing
                        end)
                    )
                catch e
                    write_err[] = e isa Reseau.ReseauError ? e.code : -1
                    write_done[] = true
                end
                return nothing
            end),
        )

        @test Sockets.socket_connect(client_socket, connect_opts) === nothing
        @test wait_for_flag(connect_done)
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag(write_done)
        @test write_err[] == Reseau.AWS_OP_SUCCESS
        @test wait_for_flag(read_done)
        @test read_err[] == Reseau.AWS_OP_SUCCESS
        @test payload[] == "ping"
    finally
        if client_socket !== nothing
            Sockets.socket_close(client_socket)
        end
        if server_socket !== nothing
            Sockets.socket_close(server_socket)
        end
        EventLoops.event_loop_destroy!(el_val)
    end
end

@trace_socket_testset "wrong thread read write fails" begin
    if Sys.iswindows()
        @test true
    else
        el = EventLoops.event_loop_new()
        el_val = el isa EventLoops.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            return
        end
        @test EventLoops.event_loop_run!(el_val) === nothing

        # Use LOCAL domain (POSIX path on all platforms) since this test
        # exercises POSIX-specific bind/assign/read/write/close flow
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.DGRAM, domain = Sockets.SocketDomain.LOCAL)
        sock = Sockets.socket_init(opts)
        socket_val = sock isa Sockets.Socket ? sock : nothing
        @test socket_val !== nothing
        if socket_val === nothing
            EventLoops.event_loop_destroy!(el_val)
            return
        end

        try
            endpoint = Sockets.SocketEndpoint()
            Sockets.socket_endpoint_init_local_address_for_test!(endpoint)
            bind_opts = Sockets.SocketBindOptions(endpoint)
            @test Sockets.socket_bind(socket_val, bind_opts) === nothing
            @test Sockets.socket_assign_to_event_loop(socket_val, el_val) === nothing
            Sockets.socket_subscribe_to_readable_events(socket_val, Reseau.EventCallable(err -> nothing))

            buf = Reseau.ByteBuffer(4)
            try
                Sockets.socket_read(socket_val, buf)
                @test false
            catch e
                @test e isa Reseau.ReseauError
                @test e.code == EventLoops.ERROR_IO_EVENT_LOOP_THREAD_ONLY
            end

            try
                Sockets.socket_write(socket_val, Reseau.ByteCursor("noop"), Reseau.WriteCallable((err, bytes) -> nothing))
                @test false
            catch e
                @test e isa Reseau.ReseauError
                @test e.code == EventLoops.ERROR_IO_EVENT_LOOP_THREAD_ONLY
            end

            close_done = Threads.Atomic{Bool}(false)
            close_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
                Sockets.socket_close(socket_val)
                close_done[] = true
                return nothing
            end); type_tag = "socket_close_wrong_thread")
            EventLoops.event_loop_schedule_task_now!(el_val, close_task)
            @test wait_for_flag(close_done)
        finally
            EventLoops.event_loop_destroy!(el_val)
        end
    end
end

@trace_socket_testset "socket_close while event loop is stopping returns promptly" begin
    if Threads.nthreads(:interactive) <= 1
        @test true
    else
        el = EventLoops.event_loop_new()
        el_val = el isa EventLoops.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            @test true
        else
            @test EventLoops.event_loop_run!(el_val) === nothing

            @static if Sys.isapple()
                opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.LOCAL)
            else
                opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
            end
            sock = Sockets.socket_init(opts)
            socket_val = sock isa Sockets.Socket ? sock : nothing
            @test socket_val !== nothing
            if socket_val === nothing
                EventLoops.event_loop_destroy!(el_val)
                @test true
            else
                close_done = Channel{Any}(1)
                try
                    if Sys.isapple()
                        endpoint = Sockets.SocketEndpoint()
                        Sockets.socket_endpoint_init_local_address_for_test!(endpoint)
                    else
                        endpoint = Sockets.SocketEndpoint("127.0.0.1", 0)
                    end

                    @test Sockets.socket_bind(socket_val, Sockets.SocketBindOptions(endpoint)) === nothing
                    @test Sockets.socket_assign_to_event_loop(socket_val, el_val) === nothing
                    @test Sockets.socket_listen(socket_val, 1) === nothing

                    EventLoops.event_loop_stop!(el_val)

                    Threads.@spawn begin
                        try
                            Sockets.socket_close(socket_val)
                            put!(close_done, :ok)
                        catch e
                            put!(close_done, e)
                        end
                    end

                    deadline = Base.time_ns() + 2_000_000_000
                    while !isready(close_done) && Base.time_ns() < deadline
                        sleep(0.01)
                    end
                    @test isready(close_done)
                    close_result = take!(close_done)
                    @test close_result === :ok
                finally
                    if @atomic el_val.running
                        EventLoops.event_loop_wait_for_stop_completion!(el_val)
                    end
                    EventLoops.event_loop_destroy!(el_val)
                end
            end
        end
    end
end

@trace_socket_testset "socket_close after event loop thread crash returns promptly" begin
    if !Sys.islinux() || Threads.nthreads(:interactive) <= 1
        @test true
    else
        el = EventLoops.event_loop_new()
        el_val = el isa EventLoops.EventLoop ? el : nothing
        @test el_val !== nothing
        if el_val === nothing
            @test true
        else
            @test EventLoops.event_loop_run!(el_val) === nothing

            if Sys.isapple()
                endpoint = Sockets.SocketEndpoint()
                Sockets.socket_endpoint_init_local_address_for_test!(endpoint)
                domain = Sockets.SocketDomain.LOCAL
            else
                endpoint = Sockets.SocketEndpoint("127.0.0.1", 0)
                domain = Sockets.SocketDomain.IPV4
            end
            opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = domain)
            sock = Sockets.socket_init(opts)
            socket_val = sock isa Sockets.Socket ? sock : nothing
            @test socket_val !== nothing

            if socket_val === nothing
                EventLoops.event_loop_destroy!(el_val)
                @test true
            else
                impl = el_val.impl_data
                crash_done = Channel{Any}(1)
                close_done = Channel{Any}(1)
                close_call_completed = false
                try
                    @test Sockets.socket_bind(socket_val, Sockets.SocketBindOptions(endpoint)) === nothing
                    @test Sockets.socket_assign_to_event_loop(socket_val, el_val) === nothing
                    @test Sockets.socket_listen(socket_val, 1) === nothing

                    EventLoops.event_loop_schedule_task_now!(
                        el_val,
                        Reseau.ScheduledTask(
                            Reseau.TaskFn(status -> begin
                                put!(crash_done, :triggered)
                                throw(ErrorException("forced event-loop crash for socket close regression test"))
                            end);
                            type_tag = "socket_close_regression_crash_task",
                        ),
                    )

                    crash_wait_deadline = Base.time_ns() + 2_000_000_000
                    while !isready(crash_done) && Base.time_ns() < crash_wait_deadline
                        sleep(0.01)
                    end
                    @test isready(crash_done)

                    wait(impl.completion_event)
                    @test isready(crash_done)

                    Threads.@spawn begin
                        try
                            Sockets.socket_close(socket_val)
                            put!(close_done, :ok)
                        catch e
                            put!(close_done, e)
                        end
                    end

                    deadline = Base.time_ns() + 5_000_000_000
                    while !isready(close_done) && Base.time_ns() < deadline
                        sleep(0.01)
                    end
                    @test isready(close_done)
                    close_result = take!(close_done)
                    close_call_completed = true
                    @test close_result === :ok
                finally
                    if !close_call_completed
                        try
                            Sockets.socket_close(socket_val)
                        catch
                            # ignore close failure from crash-path test cleanup
                        end
                    end
                    if @atomic el_val.running
                        EventLoops.event_loop_wait_for_stop_completion!(el_val)
                    end
                    EventLoops.event_loop_destroy!(el_val)
                end
            end
        end
    end
end

@trace_socket_testset "bind on zero port tcp ipv4" begin
    # Use LOCAL domain on macOS to get a POSIX socket (IPV4 → NW on macOS,
    # which doesn't expose resolved port from socket_get_bound_address)
    @static if Sys.isapple()
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.LOCAL)
    else
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    end
    sock = Sockets.socket_init(opts)
    socket_val = sock isa Sockets.Socket ? sock : nothing
    @test socket_val !== nothing
    if socket_val === nothing
        return
    end

    try
        Sockets.socket_get_bound_address(socket_val)
        @test false
    catch e
        @test e isa Reseau.ReseauError
    end

    @static if Sys.isapple()
        endpoint = Sockets.SocketEndpoint()
        Sockets.socket_endpoint_init_local_address_for_test!(endpoint)
    else
        endpoint = Sockets.SocketEndpoint("127.0.0.1", 0)
    end
    @test Sockets.socket_bind(socket_val, Sockets.SocketBindOptions(endpoint)) === nothing
    @test Sockets.socket_listen(socket_val, 1024) === nothing

    bound = Sockets.socket_get_bound_address(socket_val)
    @test bound isa Sockets.SocketEndpoint
    @static if !Sys.isapple()
        # Port resolution only testable on POSIX with IPV4
        @test bound.port > 0
        @test Sockets.get_address(bound) == "127.0.0.1"

        bound2 = Sockets.socket_get_bound_address(socket_val)
        @test bound2 isa Sockets.SocketEndpoint
        @test bound2.port == bound.port
        @test Sockets.get_address(bound2) == Sockets.get_address(bound)
    end

    Sockets.socket_close(socket_val)
end

@trace_socket_testset "bind on zero port udp ipv4" begin
    @static if Sys.isapple()
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.DGRAM, domain = Sockets.SocketDomain.LOCAL)
    else
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.DGRAM, domain = Sockets.SocketDomain.IPV4)
    end
    sock = Sockets.socket_init(opts)
    socket_val = sock isa Sockets.Socket ? sock : nothing
    @test socket_val !== nothing
    if socket_val === nothing
        return
    end

    try
        Sockets.socket_get_bound_address(socket_val)
        @test false
    catch e
        @test e isa Reseau.ReseauError
    end

    @static if Sys.isapple()
        endpoint = Sockets.SocketEndpoint()
        Sockets.socket_endpoint_init_local_address_for_test!(endpoint)
    else
        endpoint = Sockets.SocketEndpoint("127.0.0.1", 0)
    end
    @test Sockets.socket_bind(socket_val, Sockets.SocketBindOptions(endpoint)) === nothing

    bound = Sockets.socket_get_bound_address(socket_val)
    @test bound isa Sockets.SocketEndpoint
    @static if !Sys.isapple()
        @test bound.port > 0
        @test Sockets.get_address(bound) == "127.0.0.1"

        bound2 = Sockets.socket_get_bound_address(socket_val)
        @test bound2 isa Sockets.SocketEndpoint
        @test bound2.port == bound.port
        @test Sockets.get_address(bound2) == Sockets.get_address(bound)
    end

    Sockets.socket_close(socket_val)
end

@trace_socket_testset "incoming duplicate tcp bind errors" begin
    # Use LOCAL on macOS since IPV4 → NW sockets, which don't expose
    # resolved port or enforce POSIX duplicate-bind semantics
    @static if Sys.isapple()
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.LOCAL)
    else
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    end
    sock1 = Sockets.socket_init(opts)
    sock1_val = sock1 isa Sockets.Socket ? sock1 : nothing
    @test sock1_val !== nothing
    if sock1_val === nothing
        return
    end

    sock2 = Sockets.socket_init(opts)
    sock2_val = sock2 isa Sockets.Socket ? sock2 : nothing
    @test sock2_val !== nothing

    try
        @static if Sys.isapple()
            endpoint = Sockets.SocketEndpoint()
            Sockets.socket_endpoint_init_local_address_for_test!(endpoint)
            bind_opts = Sockets.SocketBindOptions(endpoint)
        else
            bind_opts = Sockets.SocketBindOptions(Sockets.SocketEndpoint("127.0.0.1", 0))
        end
        @test Sockets.socket_bind(sock1_val, bind_opts) === nothing
        @test Sockets.socket_listen(sock1_val, 1024) === nothing

        @static if Sys.isapple()
            # On macOS LOCAL: duplicate bind on the same path
            if sock2_val !== nothing
                try
                    Sockets.socket_bind(sock2_val, bind_opts)
                    @test false
                catch e
                    @test e isa Reseau.ReseauError
                    @test e.code == EventLoops.ERROR_IO_SOCKET_ADDRESS_IN_USE
                end
            end
        else
            bound = Sockets.socket_get_bound_address(sock1_val)
            @test bound isa Sockets.SocketEndpoint
            if sock2_val !== nothing
                dup_endpoint = Sockets.SocketEndpoint("127.0.0.1", Int(bound.port))
                try
                    Sockets.socket_bind(sock2_val, Sockets.SocketBindOptions(dup_endpoint))
                    @test false
                catch e
                    @test e isa Reseau.ReseauError
                    @test e.code == EventLoops.ERROR_IO_SOCKET_ADDRESS_IN_USE
                end
            end
        end
    finally
        sock2_val !== nothing && Sockets.socket_close(sock2_val)
        Sockets.socket_close(sock1_val)
    end
end

@trace_socket_testset "incoming tcp socket errors" begin
    # Use LOCAL on macOS to test POSIX bind error paths
    @static if Sys.isapple()
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.LOCAL)
    else
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    end
    sock = Sockets.socket_init(opts)
    sock_val = sock isa Sockets.Socket ? sock : nothing
    @test sock_val !== nothing
    if sock_val === nothing
        return
    end

    @static if Sys.isapple()
        # Test bind to a path in a non-existent directory
        endpoint = Sockets.SocketEndpoint("/nonexistent_dir_xxxxx/sock", 0)
        try
            Sockets.socket_bind(sock_val, Sockets.SocketBindOptions(endpoint))
            @test false
        catch e
            @test e isa Reseau.ReseauError
        end
    else
        endpoint = Sockets.SocketEndpoint("127.0.0.1", 80)
        try
            Sockets.socket_bind(sock_val, Sockets.SocketBindOptions(endpoint))
            # likely running with elevated privileges; skip assertion
            @test true
        catch e
            @test e isa Reseau.ReseauError
            @static if Sys.iswindows()
                @test e.code == Reseau.ERROR_NO_PERMISSION ||
                    e.code == EventLoops.ERROR_IO_SOCKET_ADDRESS_IN_USE
            else
                @test e.code == Reseau.ERROR_NO_PERMISSION
            end
        end
    end
    Sockets.socket_close(sock_val)
end

@trace_socket_testset "incoming udp socket errors" begin
    @static if Sys.isapple()
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.DGRAM, domain = Sockets.SocketDomain.LOCAL)
    else
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.DGRAM, domain = Sockets.SocketDomain.IPV4)
    end
    sock = Sockets.socket_init(opts)
    sock_val = sock isa Sockets.Socket ? sock : nothing
    @test sock_val !== nothing
    if sock_val === nothing
        return
    end

    @static if Sys.isapple()
        # Test bind to an invalid/non-existent path
        endpoint = Sockets.SocketEndpoint("/nonexistent_dir_xxxxx/sock", 0)
        try
            Sockets.socket_bind(sock_val, Sockets.SocketBindOptions(endpoint))
            @test false
        catch e
            @test e isa Reseau.ReseauError
        end
    else
        endpoint = Sockets.SocketEndpoint("127.0", 80)
        try
            Sockets.socket_bind(sock_val, Sockets.SocketBindOptions(endpoint))
            @test false
        catch e
            @test e isa Reseau.ReseauError
            @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
        end
    end
    Sockets.socket_close(sock_val)
end

@trace_socket_testset "outgoing local socket errors" begin
    el = EventLoops.event_loop_new()
    el_val = el isa EventLoops.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test EventLoops.event_loop_run!(el_val) === nothing

    opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.LOCAL)
    sock = Sockets.socket_init(opts)
    sock_val = sock isa Sockets.Socket ? sock : nothing
    @test sock_val !== nothing
    if sock_val === nothing
        EventLoops.event_loop_destroy!(el_val)
        return
    end

    endpoint = Sockets.SocketEndpoint()
    Sockets.socket_endpoint_init_local_address_for_test!(endpoint)
    # Ensure path does not exist
    local_path = Sockets.get_address(endpoint)
    isfile(local_path) && rm(local_path; force = true)

    err_code = Ref{Int}(0)
    done = Threads.Atomic{Bool}(false)
    connect_opts = Sockets.SocketConnectOptions(
        endpoint;
        event_loop = el_val,
        on_connection_result = Reseau.EventCallable(err -> begin
            err_code[] = err
            done[] = true
            return nothing
        end),
    )

    try
        Sockets.socket_connect(sock_val, connect_opts)
    catch e
        err_code[] = e isa Reseau.ReseauError ? e.code : -1
        done[] = true
    end

    @test wait_for_flag(done)
    @static if Sys.iswindows()
        @test err_code[] == EventLoops.ERROR_IO_SOCKET_CONNECTION_REFUSED ||
            err_code[] == Reseau.ERROR_FILE_INVALID_PATH ||
            err_code[] == EventLoops.ERROR_IO_SOCKET_NOT_CONNECTED
    else
        @test err_code[] == EventLoops.ERROR_IO_SOCKET_CONNECTION_REFUSED ||
            err_code[] == Reseau.ERROR_FILE_INVALID_PATH
    end

    Sockets.socket_close(sock_val)
    EventLoops.event_loop_destroy!(el_val)
end

@trace_socket_testset "outgoing tcp socket error" begin
    el = EventLoops.event_loop_new()
    el_val = el isa EventLoops.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test EventLoops.event_loop_run!(el_val) === nothing

    @static if Sys.isapple()
        # On macOS, use LOCAL domain (POSIX path) with a nonexistent socket
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.LOCAL)
        endpoint = Sockets.SocketEndpoint()
        Sockets.socket_endpoint_init_local_address_for_test!(endpoint)
        # Don't actually create a listener — the path won't exist
        connect_endpoint = endpoint
    else
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
        temp = Sockets.socket_init(opts)
        temp_val = temp isa Sockets.Socket ? temp : nothing
        @test temp_val !== nothing
        if temp_val === nothing
            EventLoops.event_loop_destroy!(el_val)
            return
        end

        port = 0
        try
            @test Sockets.socket_bind(temp_val, Sockets.SocketBindOptions(Sockets.SocketEndpoint("127.0.0.1", 0))) === nothing
            bound = Sockets.socket_get_bound_address(temp_val)
            if bound isa Sockets.SocketEndpoint
                port = Int(bound.port)
            end
        finally
            Sockets.socket_close(temp_val)
        end

        if port == 0
            EventLoops.event_loop_destroy!(el_val)
            return
        end
        connect_endpoint = Sockets.SocketEndpoint("127.0.0.1", port)
    end

    sock = Sockets.socket_init(opts)
    sock_val = sock isa Sockets.Socket ? sock : nothing
    @test sock_val !== nothing
    if sock_val === nothing
        EventLoops.event_loop_destroy!(el_val)
        return
    end

    err_code = Ref{Int}(0)
    done = Threads.Atomic{Bool}(false)
    connect_opts = Sockets.SocketConnectOptions(
        connect_endpoint;
        event_loop = el_val,
        on_connection_result = Reseau.EventCallable(err -> begin
            err_code[] = err
            done[] = true
            return nothing
        end),
    )

    try
        Sockets.socket_connect(sock_val, connect_opts)
    catch e
        err_code[] = e isa Reseau.ReseauError ? e.code : -1
        done[] = true
    end

    @test wait_for_flag(done)
    @test err_code[] == EventLoops.ERROR_IO_SOCKET_CONNECTION_REFUSED ||
        err_code[] == Reseau.ERROR_FILE_INVALID_PATH

    Sockets.socket_close(sock_val)
    EventLoops.event_loop_destroy!(el_val)
end
