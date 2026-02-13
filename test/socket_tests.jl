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

function ci_debug_log(msg::AbstractString)
    println("[CI DEBUG] $(msg)")
    flush(stdout)
end

function ci_with_timeout(label::AbstractString, f::Function; timeout_s::Float64 = 1.0)
    done = Threads.Atomic{Bool}(false)
    @async begin
        try
            f()
        catch e
            ci_debug_log("$(label) threw: $(e)")
        finally
            done[] = true
        end
    end

    if wait_for_flag(done; timeout_s)
        ci_debug_log("$(label) done")
        return true
    end
    ci_debug_log("$(label) timed out after $(timeout_s)s")
    return false
end

function ci_wait_for_flag(label::AbstractString, flag; timeout_s::Float64 = 5.0)
    ci_debug_log("$(label) waiting")
    if wait_for_flag(flag; timeout_s)
        ci_debug_log("$(label) complete")
        return true
    end
    ci_debug_log("$(label) timed out after $(timeout_s)s")
    return false
end

function ci_debug_event_loop_state(label::AbstractString, event_loop::EventLoops.EventLoop)
    ci_debug_log("$(label): running=$(@atomic event_loop.running) should_stop=$(@atomic event_loop.should_stop)")
    @static if Sys.islinux()
        impl = event_loop.impl_data
        scheduler = impl.scheduler
        ci_debug_log(
            "$(label): running_thread_id=$(@atomic impl.running_thread_id) caller_thread=$(Threads.threadid()) is_event_loop_thread=$(EventLoops.event_loop_thread_is_callers_thread(event_loop)) should_process_task_pre_queue=$(impl.should_process_task_pre_queue) should_continue=$(impl.should_continue) read_fd=$(impl.read_task_handle.fd) write_fd=$(impl.write_task_handle.fd) stop_task_scheduled=$(@atomic impl.stop_task_scheduled)"
        )
        ci_debug_log(
            "$(label): pre_queue=$(length(impl.task_pre_queue)), running_tasks=$(length(scheduler.running)), asap=$(length(scheduler.asap)), timed=$(length(scheduler.timed)), should_continue=$(impl.should_continue), stop_task_scheduled=$(@atomic impl.stop_task_scheduled)"
        )
        if !isempty(scheduler.asap)
            for i in 1:min(length(scheduler.asap), 4)
                ci_debug_log(
                    "$(label): asap[$i]=type=$(scheduler.asap[i].type_tag), scheduled=$(scheduler.asap[i].scheduled), timestamp=$(scheduler.asap[i].timestamp)"
                )
            end
        end
        if !isempty(scheduler.timed)
            next_timed_task = Reseau.peek(scheduler.timed)
            if next_timed_task !== nothing
                ci_debug_log(
                    "$(label): timed_next=type=$(next_timed_task.type_tag), scheduled=$(next_timed_task.scheduled), timestamp=$(next_timed_task.timestamp)"
                )
            end
        end
        if !isempty(scheduler.running)
            for i in 1:min(length(scheduler.running), 4)
                ci_debug_log(
                    "$(label): running[$i]=type=$(scheduler.running[i].type_tag), scheduled=$(scheduler.running[i].scheduled), timestamp=$(scheduler.running[i].timestamp)"
                )
            end
        end
        if !isempty(impl.task_pre_queue)
            for i in 1:min(length(impl.task_pre_queue), 4)
                ci_debug_log(
                    "$(label): pre_queue[$i]=type=$(impl.task_pre_queue[i].type_tag), scheduled=$(impl.task_pre_queue[i].scheduled), timestamp=$(impl.task_pre_queue[i].timestamp)"
                )
            end
        end
    end
end

function ci_debug_socket_state(label::AbstractString, socket::Union{Sockets.Socket, Nothing})
    socket === nothing && return
    ci_debug_log(
        "$(label): fd=$(socket.io_handle.fd), state=$(socket.state), event_loop=$(socket.event_loop === nothing ? "none" : "set")"
    )
    impl = socket.impl
    impl === nothing && return
    @static if Sys.islinux()
        try
            ci_debug_log(
                "$(label): currently_subscribed=$(impl.currently_subscribed), close_happened=$((impl.close_happened === nothing) ? "none" : "set"), connect_args=$(impl.connect_args === nothing ? "none" : "set"), written_task_scheduled=$(impl.written_task_scheduled)"
            )
        catch
            ci_debug_log("$(label): failed to read platform socket impl internals")
        end
    end
end

function ci_debug_cleanup_context(label::AbstractString, event_loop::EventLoops.EventLoop, sockets::Union{Sockets.Socket, Nothing}...)
    ci_debug_event_loop_state("$(label): pre-cleanup", event_loop)
    for i in eachindex(sockets)
        ci_debug_socket_state("$(label): pre-cleanup socket[$i]", sockets[i])
    end
end

function ci_debug_task_state(label::AbstractString, task::Union{Reseau.ScheduledTask, Nothing})
    task === nothing && return
    ci_debug_log(
        "$(label): type=$(task.type_tag), scheduled=$(task.scheduled), timestamp=$(task.timestamp), objectid=$(objectid(task))"
    )
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

@testset "socket validate port" begin
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
        res = Sockets.parse_ipv4_address(input)
        @test res == expected
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
        try
            Sockets.parse_ipv4_address(input)
            @test false
        catch e
            @test e isa Reseau.ReseauError
            @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
        end
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
        res = Sockets.parse_ipv6_address!(input, buf)
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

@testset "message pool" begin
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

@testset "memory pool" begin
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

@testset "socket interface options" begin
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

@testset "socket bind to interface" begin
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
        ci_debug_log("ipv4 stream: event loop running")

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
            ci_debug_log("ipv4 stream: socket_init(server) start")
            server_socket = Sockets.socket_init(opts)
            ci_debug_log("ipv4 stream: socket_init(server) done")
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
                ci_debug_log("ipv4 stream: socket_bind(server) start")
                Sockets.socket_bind(server_socket, bind_opts)
                ci_debug_log("ipv4 stream: socket_bind(server) done")
            catch e
                @test e isa Reseau.ReseauError
                @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_OPTIONS ||
                    e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
                return
            end
            try
                ci_debug_log("ipv4 stream: socket_listen(server) start")
                Sockets.socket_listen(server_socket, 1024)
                ci_debug_log("ipv4 stream: socket_listen(server) done")
            catch e
                @test e isa Reseau.ReseauError
                @test e.code == EventLoops.ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY ||
                    e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
                return
            end

            ci_debug_log("ipv4 stream: get_bound_address(server) start")
            bound = Sockets.socket_get_bound_address(server_socket)
            ci_debug_log("ipv4 stream: get_bound_address(server) done")
            @test bound isa Sockets.SocketEndpoint
            port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                ci_debug_log("ipv4 stream: bound port is 0, aborting subtest")
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

            ci_debug_log("ipv4 stream: socket_connect(start)")
            @test Sockets.socket_connect(client_socket, connect_opts) === nothing
            ci_debug_log("ipv4 stream: waiting connect_done")
            @test wait_for_flag(connect_done)
            ci_debug_log("ipv4 stream: wait connect_done complete")
            @test connect_err[] == Reseau.AWS_OP_SUCCESS
            ci_debug_log("ipv4 stream: waiting write_done")
            @test wait_for_flag(write_done)
            ci_debug_log("ipv4 stream: wait write_done complete")
            @test write_err[] == Reseau.AWS_OP_SUCCESS
            ci_debug_log("ipv4 stream: waiting read_done")
            @test wait_for_flag(read_done)
            ci_debug_log("ipv4 stream: wait read_done complete")
            @test accept_err[] == Reseau.AWS_OP_SUCCESS
            @test read_err[] == Reseau.AWS_OP_SUCCESS
            @test payload[] == "ping"
        finally
            ci_debug_log("ipv4 stream: cleanup start")
            ci_debug_cleanup_context("ipv4 stream", el_val, client_socket, accepted[], server_socket)
            if client_socket !== nothing
                ci_debug_log("ipv4 stream: cleanup client_socket")
                if !ci_with_timeout("ipv4 stream: socket_cleanup!(client_socket)", () -> Sockets.socket_cleanup!(client_socket); timeout_s=1.0)
                    ci_debug_log("ipv4 stream: cleanup client_socket fallback close")
                    if !ci_with_timeout("ipv4 stream: socket_close(client_socket)", () -> Sockets.socket_close(client_socket); timeout_s=1.0)
                        ci_debug_log("ipv4 stream: socket_close(client_socket) timed out")
                    end
                end
            end
            if accepted[] !== nothing
                ci_debug_log("ipv4 stream: cleanup accepted")
                ci_with_timeout("ipv4 stream: socket_cleanup!(accepted[])", () -> Sockets.socket_cleanup!(accepted[]); timeout_s=1.0)
            end
            ci_debug_log("ipv4 stream: cleanup server_socket")
            ci_with_timeout("ipv4 stream: socket_cleanup!(server_socket)", () -> Sockets.socket_cleanup!(server_socket); timeout_s=1.0)
            ci_debug_log("ipv4 stream: event_loop_destroy start")
            if !ci_with_timeout(
                "ipv4 stream: event_loop_destroy!",
                () -> EventLoops.event_loop_destroy!(el_val);
                timeout_s=1.0,
            )
                ci_debug_log("ipv4 stream: event_loop_destroy timed out")
            end
            ci_debug_log("ipv4 stream: event_loop_destroy done")
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
            ci_debug_log("ipv4 udp: socket_init(server) start")
            server_socket = Sockets.socket_init(opts_udp)
            ci_debug_log("ipv4 udp: socket_init(server) done")
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
                ci_debug_log("ipv4 udp: socket_bind(server) start")
                Sockets.socket_bind(server_socket, bind_opts)
                ci_debug_log("ipv4 udp: socket_bind(server) done")
            catch e
                @test e isa Reseau.ReseauError
                @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_OPTIONS ||
                    e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED
                return
            end

            ci_debug_log("ipv4 udp: get_bound_address(server) start")
            bound = Sockets.socket_get_bound_address(server_socket)
            ci_debug_log("ipv4 udp: get_bound_address(server) done")
            @test bound isa Sockets.SocketEndpoint
            port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                ci_debug_log("ipv4 udp: bound port is 0, aborting subtest")
                return
            end

            ci_debug_log("ipv4 udp: socket_init(client) start")
            client = Sockets.socket_init(opts_udp)
            client_socket = client isa Sockets.Socket ? client : nothing
            @test client_socket !== nothing
            if client_socket === nothing
                return
            end

            ci_debug_log("ipv4 udp: socket_connect(client) start")
            connect_opts = Sockets.SocketConnectOptions(
                Sockets.SocketEndpoint("127.0.0.1", port);
                event_loop = el_val,
                on_connection_result = Reseau.EventCallable(err -> nothing),
            )

            ci_debug_log("ipv4 udp: socket_connect call")
            @test Sockets.socket_connect(client_socket, connect_opts) === nothing
        finally
            ci_debug_log("ipv4 udp: cleanup start")
            ci_debug_cleanup_context("ipv4 udp", el_val, client_socket, server_socket)
            if client_socket !== nothing
                ci_debug_log("ipv4 udp: cleanup client_socket")
                if !ci_with_timeout(
                    "ipv4 udp: socket_cleanup!(client_socket)",
                    () -> Sockets.socket_cleanup!(client_socket);
                    timeout_s=1.0,
                )
                    ci_debug_log("ipv4 udp: cleanup client_socket timed out")
                end
                ci_debug_log("ipv4 udp: cleanup client_socket done")
            end
            ci_debug_log("ipv4 udp: cleanup server_socket")
            ci_with_timeout(
                "ipv4 udp: socket_cleanup!(server_socket)",
                () -> Sockets.socket_cleanup!(server_socket);
                timeout_s=1.0,
            )
            ci_debug_log("ipv4 udp: cleanup server_socket done")
            ci_debug_log("ipv4 udp: event_loop_destroy start")
            if !ci_with_timeout(
                "ipv4 udp: event_loop_destroy!",
                () -> EventLoops.event_loop_destroy!(el_val);
                timeout_s=1.0,
            )
                ci_debug_log("ipv4 udp: event_loop_destroy timed out")
            end
            ci_debug_log("ipv4 udp: event_loop_destroy done")
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
            ci_debug_log("ipv6 stream: socket_init(server) start")
            server_socket = Sockets.socket_init(opts6)
            ci_debug_log("ipv6 stream: socket_init(server) done")
        catch e
            @test e isa Reseau.ReseauError
            @test e.code == Reseau.ERROR_PLATFORM_NOT_SUPPORTED ||
                e.code == EventLoops.ERROR_IO_SOCKET_INVALID_OPTIONS
            ci_with_timeout(
                "ipv6 stream: event_loop_destroy!",
                () -> EventLoops.event_loop_destroy!(el_val);
                timeout_s=1.0,
            )
            return
        end

        client_socket = nothing
        accepted = Ref{Any}(nothing)

        try
            bind_opts = Sockets.SocketBindOptions(Sockets.SocketEndpoint("::1", 0))
            try
                ci_debug_log("ipv6 stream: socket_bind(server) start")
                Sockets.socket_bind(server_socket, bind_opts)
                ci_debug_log("ipv6 stream: socket_bind(server) done")
            catch e
                @test e isa Reseau.ReseauError
                @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_ADDRESS
                return
            end
            ci_debug_log("ipv6 stream: socket_listen(server) start")
            @test Sockets.socket_listen(server_socket, 1024) === nothing
            ci_debug_log("ipv6 stream: socket_listen(server) done")

            ci_debug_log("ipv6 stream: get_bound_address(server) start")
            bound = Sockets.socket_get_bound_address(server_socket)
            ci_debug_log("ipv6 stream: get_bound_address(server) done")
            @test bound isa Sockets.SocketEndpoint
            port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
            if port == 0
                ci_debug_log("ipv6 stream: bound port is 0, aborting subtest")
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

            ci_debug_log("ipv6 stream: socket_connect(start)")
            @test Sockets.socket_connect(client_socket, connect_opts) === nothing
            ci_debug_log("ipv6 stream: waiting connect_done")
            @test wait_for_flag(connect_done)
            ci_debug_log("ipv6 stream: wait connect_done complete")
            @test connect_err[] == Reseau.AWS_OP_SUCCESS
            @test accept_err[] == Reseau.AWS_OP_SUCCESS
        finally
            ci_debug_log("ipv6 stream: cleanup start")
            ci_debug_cleanup_context("ipv6 stream", el_val, client_socket, accepted[], server_socket)
            if client_socket !== nothing
                ci_debug_log("ipv6 stream: cleanup client_socket")
                ci_with_timeout(
                    "ipv6 stream: socket_cleanup!(client_socket)",
                    () -> Sockets.socket_cleanup!(client_socket);
                    timeout_s=1.0,
                )
                ci_debug_log("ipv6 stream: cleanup client_socket done")
            end
            if accepted[] !== nothing
                ci_debug_log("ipv6 stream: cleanup accepted")
                ci_with_timeout(
                    "ipv6 stream: socket_cleanup!(accepted[])",
                    () -> Sockets.socket_cleanup!(accepted[]);
                    timeout_s=1.0,
                )
                ci_debug_log("ipv6 stream: cleanup accepted done")
            end
            ci_debug_log("ipv6 stream: cleanup server_socket")
            ci_with_timeout(
                "ipv6 stream: socket_cleanup!(server_socket)",
                () -> Sockets.socket_cleanup!(server_socket);
                timeout_s=1.0,
            )
            ci_debug_log("ipv6 stream: cleanup server_socket done")
            ci_debug_log("ipv6 stream: event_loop_destroy start")
            if !ci_with_timeout(
                "ipv6 stream: event_loop_destroy!",
                () -> EventLoops.event_loop_destroy!(el_val);
                timeout_s=1.0,
            )
                ci_debug_log("ipv6 stream: event_loop_destroy timed out")
            end
            ci_debug_log("ipv6 stream: event_loop_destroy done")
        end
    end
end

@testset "socket bind to invalid interface" begin
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

@testset "vsock loopback socket communication" begin
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

@testset "socket init domain-based selection" begin
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

@testset "winsock stubs" begin
    ci_debug_log("socket_tests: winsock stubs start")
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

@testset "socket nonblocking cloexec" begin
    ci_debug_log("socket_tests: socket nonblocking cloexec start")
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

@testset "socket connect read write" begin
    ci_debug_log("socket_tests: socket connect read write start")
    el = EventLoops.event_loop_new()
    el_val = el isa EventLoops.EventLoop ? el : nothing
    ci_debug_log("socket connect read write: event_loop_new")
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    ci_debug_log("socket connect read write: event_loop_run!")
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
        ci_debug_log("socket connect read write: socket_bind")
        @test Sockets.socket_bind(server_socket, bind_opts) === nothing
        ci_debug_log("socket connect read write: socket_listen")
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
            ci_debug_log("socket connect read write: on_accept")
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
                        ci_debug_log("socket connect read write: on_read")
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
        ci_debug_log("socket connect read write: socket_start_accept")
        @test ci_with_timeout(
            "socket connect read write: socket_start_accept",
            () -> Sockets.socket_start_accept(server_socket, el_val, accept_opts) === nothing;
            timeout_s = 1.0,
        )

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
                ci_debug_log("socket connect read write: on_connection_result")
                connect_err[] = err
                connect_done[] = true
                if err != Reseau.AWS_OP_SUCCESS
                    return nothing
                end

                cursor = Reseau.ByteCursor("ping")
                try
                    Sockets.socket_write(
                        client_socket, cursor, Reseau.WriteCallable((err, bytes) -> begin
                            ci_debug_log("socket connect read write: on_write")
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

        ci_debug_log("socket connect read write: socket_connect")
        @test ci_with_timeout(
            "socket connect read write: socket_connect",
            () -> Sockets.socket_connect(client_socket, connect_opts) === nothing;
            timeout_s = 1.0,
        )
        ci_debug_log("socket connect read write: socket_connect done")
        @test ci_wait_for_flag("socket connect read write: wait connect_done", connect_done)
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
        @test ci_wait_for_flag("socket connect read write: wait write_done", write_done)
        @test write_err[] == Reseau.AWS_OP_SUCCESS
        @test ci_wait_for_flag("socket connect read write: wait read_done", read_done)
        @test accept_err[] == Reseau.AWS_OP_SUCCESS
        @test read_err[] == Reseau.AWS_OP_SUCCESS
        @test payload[] == "ping"
    finally
        ci_debug_log("socket connect read write: cleanup start")
        ci_debug_cleanup_context("socket connect read write", el_val, client_socket, accepted[], server_socket)
        if client_socket !== nothing
            ci_with_timeout("socket connect read write: socket_cleanup!(client_socket)", () -> Sockets.socket_cleanup!(client_socket))
            if !ci_with_timeout("socket connect read write: socket_close(client_socket)", () -> Sockets.socket_close(client_socket))
                ci_debug_log("socket connect read write: fallback socket_close(client_socket) timed out")
            end
        end
        if accepted[] !== nothing
            ci_with_timeout("socket connect read write: socket_cleanup!(accepted[])", () -> Sockets.socket_cleanup!(accepted[]))
            if !ci_with_timeout("socket connect read write: socket_close(accepted[])", () -> Sockets.socket_close(accepted[]))
                ci_debug_log("socket connect read write: fallback socket_close(accepted[]) timed out")
            end
        end
        if server_socket !== nothing
            ci_with_timeout("socket connect read write: socket_cleanup!(server_socket)", () -> Sockets.socket_cleanup!(server_socket))
            if !ci_with_timeout("socket connect read write: socket_close(server_socket)", () -> Sockets.socket_close(server_socket))
                ci_debug_log("socket connect read write: fallback socket_close(server_socket) timed out")
            end
        end
        ci_with_timeout("socket connect read write: event_loop_destroy!", () -> EventLoops.event_loop_destroy!(el_val))
        # Clean up Unix domain socket file (Windows LOCAL uses named pipes, not a filesystem path).
        @static if !Sys.iswindows()
            sock_path = Sockets.get_address(local_endpoint)
            isfile(sock_path) && rm(sock_path; force=true)
        end
    end
end

@testset "nw socket connect read write" begin
    ci_debug_log("socket_tests: nw socket connect read write start")
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
    ci_debug_log("nw socket connect read write: server socket init")
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
        ci_debug_log("nw socket connect read write: socket_bind")
        @test Sockets.socket_bind(server_socket, bind_opts) === nothing
        ci_debug_log("nw socket connect read write: socket_listen")
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
            ci_debug_log("nw socket connect read write: on_accept")
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
        ci_debug_log("nw socket connect read write: socket_start_accept")
        @test ci_with_timeout(
            "nw socket connect read write: socket_start_accept",
            () -> Sockets.socket_start_accept(server_socket, el_val, accept_opts) === nothing;
            timeout_s = 1.0,
        )

        @test ci_wait_for_flag("nw socket connect read write: wait accept_started", accept_started)
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
                ci_debug_log("nw socket connect read write: on_connection_result")
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

        ci_debug_log("nw socket connect read write: socket_connect")
        @test ci_with_timeout(
            "nw socket connect read write: socket_connect",
            () -> Sockets.socket_connect(client_socket, connect_opts) === nothing;
            timeout_s = 1.0,
        )
        ci_debug_log("nw socket connect read write: socket_connect done")
        @test ci_wait_for_flag("nw socket connect read write: wait connect_done", connect_done)
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
        @test ci_wait_for_flag("nw socket connect read write: wait write_done", write_done)
        @test write_err[] == Reseau.AWS_OP_SUCCESS
        @test ci_wait_for_flag("nw socket connect read write: wait read_done", read_done)
        @test accept_err[] == Reseau.AWS_OP_SUCCESS
        @test read_err[] == Reseau.AWS_OP_SUCCESS
        @test payload[] == "ping"
    finally
        ci_debug_log("nw socket connect read write: cleanup start")
        if client_socket !== nothing
            ci_with_timeout("nw socket connect read write: socket_cleanup!(client_socket)", () -> Sockets.socket_cleanup!(client_socket))
            if !ci_with_timeout("nw socket connect read write: socket_close(client_socket)", () -> Sockets.socket_close(client_socket))
                ci_debug_log("nw socket connect read write: fallback socket_close(client_socket) timed out")
            end
        end
        if accepted[] !== nothing
            ci_with_timeout("nw socket connect read write: socket_cleanup!(accepted[])", () -> Sockets.socket_cleanup!(accepted[]))
            if !ci_with_timeout("nw socket connect read write: socket_close(accepted[])", () -> Sockets.socket_close(accepted[]))
                ci_debug_log("nw socket connect read write: fallback socket_close(accepted[]) timed out")
            end
        end
        if server_socket !== nothing
            ci_with_timeout("nw socket connect read write: socket_cleanup!(server_socket)", () -> Sockets.socket_cleanup!(server_socket))
            if !ci_with_timeout("nw socket connect read write: socket_close(server_socket)", () -> Sockets.socket_close(server_socket))
                ci_debug_log("nw socket connect read write: fallback socket_close(server_socket) timed out")
            end
        end
        ci_with_timeout("nw socket connect read write: event_loop_destroy!", () -> EventLoops.event_loop_destroy!(el_val))
    end
end

@testset "sock write cb is async" begin
    ci_debug_log("socket_tests: sock write cb is async start")
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
        ci_debug_log("sock write cb is async: socket_start_accept")
        @test ci_with_timeout(
            "sock write cb is async: socket_start_accept",
            () -> Sockets.socket_start_accept(server_socket, el_val, accept_opts) === nothing;
            timeout_s = 1.0,
        )

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
                ci_debug_log("sock write cb is async: on_connection_result")
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

        ci_debug_log("sock write cb is async: socket_connect")
        @test ci_with_timeout(
            "sock write cb is async: socket_connect",
            () -> Sockets.socket_connect(client_socket, connect_opts) === nothing;
            timeout_s = 1.0,
        )
        ci_debug_log("sock write cb is async: socket_connect done")
        @test ci_wait_for_flag("sock write cb is async: wait connect_done", connect_done)
        @test ci_wait_for_flag("sock write cb is async: wait accept_done", accept_done)
        @test ci_wait_for_flag("sock write cb is async: wait write_started", write_started)
        @test ci_wait_for_flag("sock write cb is async: wait write_cb_invoked", write_cb_invoked)
        @test !write_cb_sync[]
        @test write_err[] == Reseau.AWS_OP_SUCCESS
    finally
        ci_debug_log("sock write cb is async: cleanup start")
        if client_socket !== nothing
            ci_with_timeout("sock write cb is async: socket_cleanup!(client_socket)", () -> Sockets.socket_cleanup!(client_socket))
            if !ci_with_timeout("sock write cb is async: socket_close(client_socket)", () -> Sockets.socket_close(client_socket))
                ci_debug_log("sock write cb is async: fallback socket_close(client_socket) timed out")
            end
        end
        if accepted[] !== nothing
            ci_with_timeout("sock write cb is async: socket_cleanup!(accepted[])", () -> Sockets.socket_cleanup!(accepted[]))
            if !ci_with_timeout("sock write cb is async: socket_close(accepted[])", () -> Sockets.socket_close(accepted[]))
                ci_debug_log("sock write cb is async: fallback socket_close(accepted[]) timed out")
            end
        end
        if server_socket !== nothing
            ci_with_timeout("sock write cb is async: socket_cleanup!(server_socket)", () -> Sockets.socket_cleanup!(server_socket))
            if !ci_with_timeout("sock write cb is async: socket_close(server_socket)", () -> Sockets.socket_close(server_socket))
                ci_debug_log("sock write cb is async: fallback socket_close(server_socket) timed out")
            end
        end
        ci_with_timeout("sock write cb is async: event_loop_destroy!", () -> EventLoops.event_loop_destroy!(el_val))
    end
end

@testset "connect timeout" begin
    ci_debug_log("socket_tests: connect timeout start")
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
            ci_debug_log("connect timeout: socket_connect")
            @test ci_with_timeout(
                "connect timeout: socket_connect",
                () -> Sockets.socket_connect(socket_val, connect_opts),
                timeout_s = 1.0,
            )
            @test ci_wait_for_flag("connect timeout: wait connect_done", connect_done; timeout_s = 3.0)
            @test _is_allowed_connect_error(connect_err[])
        catch e
            @test e isa Reseau.ReseauError
            @test _is_allowed_connect_error(e.code)
        end
    finally
        ci_with_timeout("connect timeout: socket_cleanup!(socket_val)", () -> Sockets.socket_cleanup!(socket_val))
        if !ci_with_timeout("connect timeout: socket_close(socket_val)", () -> Sockets.socket_close(socket_val))
            ci_debug_log("connect timeout: fallback socket_close(socket_val) timed out")
        end
        ci_with_timeout("connect timeout: event_loop_group_destroy!", () -> EventLoops.event_loop_group_destroy!(elg_val))
    end
end

@testset "connect timeout cancellation" begin
    ci_debug_log("socket_tests: connect timeout cancellation start")
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
            ci_debug_log("connect timeout cancellation: socket_connect")
            @test ci_with_timeout(
                "connect timeout cancellation: socket_connect",
                () -> Sockets.socket_connect(socket_val, connect_opts),
                timeout_s = 1.0,
            )
            if !ci_with_timeout(
                "connect timeout cancellation: event_loop_group_destroy!",
                () -> EventLoops.event_loop_group_destroy!(elg_val),
                timeout_s = 5.0,
            )
                ci_debug_log(
                    "connect timeout cancellation: event_loop_group_destroy! timed out before callback completed"
                )
            end
            @test ci_wait_for_flag("connect timeout cancellation: wait connect_done", connect_done; timeout_s = 5.0)
            @test connect_err[] == EventLoops.ERROR_IO_EVENT_LOOP_SHUTDOWN ||
                _is_allowed_connect_error(connect_err[])
        catch e
            if e isa Reseau.ReseauError
                @test _is_allowed_connect_error(e.code)
            else
                rethrow()
            end
        end
    finally
        ci_with_timeout("connect timeout cancellation: socket_cleanup!(socket_val)", () -> Sockets.socket_cleanup!(socket_val))
        if !ci_with_timeout("connect timeout cancellation: socket_close(socket_val)", () -> Sockets.socket_close(socket_val))
            ci_debug_log("connect timeout cancellation: fallback socket_close(socket_val) timed out")
        end
    end
end

@testset "cleanup before connect or timeout" begin
    ci_debug_log("socket_tests: cleanup before connect or timeout start")
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
                ci_debug_log("cleanup before connect or timeout: socket_connect")
                @test ci_with_timeout(
                    "cleanup before connect or timeout: socket_connect",
                    () -> Sockets.socket_connect(socket_val, connect_opts),
                    timeout_s = 1.0,
                )
                EventLoops.event_loop_schedule_task_now!(el_val, cleanup_task)
                if !ci_wait_for_flag(
                    "cleanup before connect or timeout: wait cleanup_done",
                    cleanup_done;
                    timeout_s = 10.0,
                )
                    ci_debug_log(
                        "cleanup before connect or timeout: cleanup_done timed out; continuing"
                    )
                end
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
            ci_with_timeout("cleanup before connect or timeout: socket_cleanup!(socket_val)", () -> Sockets.socket_cleanup!(socket_val))
            if !ci_with_timeout("cleanup before connect or timeout: socket_close(socket_val)", () -> Sockets.socket_close(socket_val))
                ci_debug_log("cleanup before connect or timeout: fallback socket_close(socket_val) timed out")
            end
            ci_with_timeout("cleanup before connect or timeout: event_loop_group_destroy!", () -> EventLoops.event_loop_group_destroy!(elg_val))
        end
end

@testset "cleanup in accept doesn't explode" begin
    ci_debug_log("socket_tests: cleanup in accept doesn't explode start")
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
        ci_debug_log("cleanup in accept doesn't explode: socket_start_accept")
        @test ci_with_timeout(
            "cleanup in accept doesn't explode: socket_start_accept",
            () -> Sockets.socket_start_accept(listener_socket, el_val, accept_opts) === nothing;
            timeout_s = 1.0,
        )

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
                ci_debug_log("cleanup in accept doesn't explode: on_connection_result")
                connect_err[] = err
                connect_done[] = true
                return nothing
            end),
        )

        ci_debug_log("cleanup in accept doesn't explode: socket_connect")
        @test ci_with_timeout(
            "cleanup in accept doesn't explode: socket_connect",
            () -> Sockets.socket_connect(client_socket, connect_opts) === nothing,
            timeout_s = 1.0,
        )
        @test ci_wait_for_flag("cleanup in accept doesn't explode: wait accept_done", accept_done)
        @test ci_wait_for_flag("cleanup in accept doesn't explode: wait connect_done", connect_done)
        @test accept_err[] == Reseau.AWS_OP_SUCCESS
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
    finally
        ci_debug_log("cleanup in accept doesn't explode: cleanup start")
        if client_socket !== nothing
            ci_with_timeout("cleanup in accept doesn't explode: socket_cleanup!(client_socket)", () -> Sockets.socket_cleanup!(client_socket))
            if !ci_with_timeout("cleanup in accept doesn't explode: socket_close(client_socket)", () -> Sockets.socket_close(client_socket))
                ci_debug_log("cleanup in accept doesn't explode: fallback socket_close(client_socket) timed out")
            end
        end
        if incoming[] !== nothing
            ci_with_timeout("cleanup in accept doesn't explode: socket_cleanup!(incoming[])", () -> Sockets.socket_cleanup!(incoming[]))
            if !ci_with_timeout("cleanup in accept doesn't explode: socket_close(incoming[])", () -> Sockets.socket_close(incoming[]))
                ci_debug_log("cleanup in accept doesn't explode: fallback socket_close(incoming[]) timed out")
            end
        end
        ci_with_timeout("cleanup in accept doesn't explode: socket_cleanup!(listener_socket)", () -> Sockets.socket_cleanup!(listener_socket))
        if !ci_with_timeout("cleanup in accept doesn't explode: socket_close(listener_socket)", () -> Sockets.socket_close(listener_socket))
            ci_debug_log("cleanup in accept doesn't explode: fallback socket_close(listener_socket) timed out")
        end
        ci_with_timeout("cleanup in accept doesn't explode: event_loop_destroy!", () -> EventLoops.event_loop_destroy!(el_val))
    end
end

@testset "cleanup in write cb doesn't explode" begin
    ci_debug_log("socket_tests: cleanup in write cb doesn't explode start")
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
        ci_debug_log("cleanup in write cb doesn't explode: socket_start_accept")
        @test ci_with_timeout(
            "cleanup in write cb doesn't explode: socket_start_accept",
            () -> Sockets.socket_start_accept(listener_socket, el_val, accept_opts) === nothing;
            timeout_s = 1.0,
        )

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
                ci_debug_log("cleanup in write cb doesn't explode: on_connection_result")
                connect_done[] = true
                return nothing
            end),
        )

        ci_debug_log("cleanup in write cb doesn't explode: socket_connect")
        @test ci_with_timeout(
            "cleanup in write cb doesn't explode: socket_connect",
            () -> Sockets.socket_connect(client_socket, connect_opts) === nothing,
            timeout_s = 1.0,
        )
        @test ci_wait_for_flag("cleanup in write cb doesn't explode: wait accept_done", accept_done)
        @test ci_wait_for_flag("cleanup in write cb doesn't explode: wait connect_done", connect_done)

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
        write_done_client_cb_err = Ref{Any}(nothing)
        write_done_server_cb_err = Ref{Any}(nothing)

        write_task_client = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
            ci_debug_log("cleanup in write cb doesn't explode: write_task_client running")
            ci_debug_log("cleanup in write cb doesn't explode: write_task_client status=$(status)")
            cursor = Reseau.ByteCursor("teapot")
            try
                Sockets.socket_write(
                    client_socket,
                    cursor,
                    Reseau.WriteCallable((err, bytes) -> begin
                        write_err_client[] = err
                        try
                            Sockets.socket_cleanup!(client_socket)
                        catch e
                            write_done_client_cb_err[] = e
                            ci_debug_log(
                                "cleanup in write cb doesn't explode: client write callback cleanup threw $(e)"
                            )
                        end
                        write_done_client[] = true
                        return nothing
                    end),
                )
            catch e
                write_err_client[] = e isa Reseau.ReseauError ? e.code : -1
                try
                    Sockets.socket_cleanup!(client_socket)
                catch cleanup_err
                    write_done_client_cb_err[] = cleanup_err
                    ci_debug_log(
                        "cleanup in write cb doesn't explode: client write task cleanup threw $(cleanup_err)"
                    )
                end
                write_done_client[] = true
            end
                ci_debug_log("cleanup in write cb doesn't explode: write_task_client complete")
            return nothing
        end); type_tag = "socket_write_cleanup_client")

        write_task_server = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
            ci_debug_log("cleanup in write cb doesn't explode: write_task_server running")
            ci_debug_log("cleanup in write cb doesn't explode: write_task_server status=$(status)")
            cursor = Reseau.ByteCursor("spout")
            try
                Sockets.socket_write(
                    server_sock,
                    cursor,
                    Reseau.WriteCallable((err, bytes) -> begin
                        write_err_server[] = err
                        try
                            Sockets.socket_cleanup!(server_sock)
                        catch e
                            write_done_server_cb_err[] = e
                            ci_debug_log(
                                "cleanup in write cb doesn't explode: server write callback cleanup threw $(e)"
                            )
                        end
                        write_done_server[] = true
                        return nothing
                    end),
                )
            catch e
                write_err_server[] = e isa Reseau.ReseauError ? e.code : -1
                try
                    Sockets.socket_cleanup!(server_sock)
                catch cleanup_err
                    write_done_server_cb_err[] = cleanup_err
                    ci_debug_log(
                        "cleanup in write cb doesn't explode: server write task cleanup threw $(cleanup_err)"
                    )
                end
                write_done_server[] = true
            end
            ci_debug_log("cleanup in write cb doesn't explode: write_task_server complete")
            return nothing
        end); type_tag = "socket_write_cleanup_server")

        ci_debug_task_state("cleanup in write cb doesn't explode: write_task_client initial", write_task_client)
        ci_debug_task_state("cleanup in write cb doesn't explode: write_task_server initial", write_task_server)
        ci_debug_event_loop_state(
            "cleanup in write cb doesn't explode: state before client schedule",
            el_val,
        )
        EventLoops.event_loop_schedule_task_now!(el_val, write_task_client)
        ci_debug_task_state("cleanup in write cb doesn't explode: write_task_client after schedule", write_task_client)
        ci_debug_event_loop_state(
            "cleanup in write cb doesn't explode: state after client schedule",
            el_val,
        )
        if !ci_wait_for_flag(
            "cleanup in write cb doesn't explode: wait write_done_client",
            write_done_client;
            timeout_s = 10.0,
        )
            ci_debug_log("cleanup in write cb doesn't explode: write_done_client timed out")
            ci_debug_event_loop_state(
                "cleanup in write cb doesn't explode: state at client timeout",
                el_val,
            )
            ci_debug_task_state(
                "cleanup in write cb doesn't explode: write_task_client at client timeout",
                write_task_client,
            )
            ci_debug_task_state(
                "cleanup in write cb doesn't explode: write_task_server at client timeout",
                write_task_server,
            )
            ci_debug_socket_state("cleanup in write cb doesn't explode: client socket at client timeout", client_socket)
            ci_debug_socket_state("cleanup in write cb doesn't explode: server socket at client timeout", server_sock)
            ci_debug_socket_state("cleanup in write cb doesn't explode: listener socket at client timeout", listener_socket)
        end
        @test write_done_client[] == true
        ci_debug_task_state(
            "cleanup in write cb doesn't explode: write_task_client at client completion",
            write_task_client,
        )
        ci_debug_task_state(
            "cleanup in write cb doesn't explode: write_task_server at client completion",
            write_task_server,
        )
        EventLoops.event_loop_schedule_task_now!(el_val, write_task_server)
        ci_debug_task_state("cleanup in write cb doesn't explode: write_task_server after schedule", write_task_server)
        ci_debug_event_loop_state(
            "cleanup in write cb doesn't explode: state after server schedule",
            el_val,
        )
        if !ci_wait_for_flag(
            "cleanup in write cb doesn't explode: wait write_done_server",
            write_done_server;
            timeout_s = 10.0,
        )
            ci_debug_log("cleanup in write cb doesn't explode: write_done_server timed out")
            ci_debug_event_loop_state(
                "cleanup in write cb doesn't explode: state at server timeout",
                el_val,
            )
            ci_debug_task_state(
                "cleanup in write cb doesn't explode: write_task_server at server timeout",
                write_task_server,
            )
            ci_debug_task_state(
                "cleanup in write cb doesn't explode: write_task_client at server timeout",
                write_task_client,
            )
            ci_debug_socket_state("cleanup in write cb doesn't explode: client socket at server timeout", client_socket)
            ci_debug_socket_state("cleanup in write cb doesn't explode: server socket at server timeout", server_sock)
            ci_debug_socket_state("cleanup in write cb doesn't explode: listener socket at server timeout", listener_socket)
        end
        @test write_done_server[] == true
        ci_debug_event_loop_state(
            "cleanup in write cb doesn't explode: state at completion",
            el_val,
        )
        ci_debug_task_state(
            "cleanup in write cb doesn't explode: write_task_client at server completion",
            write_task_client,
        )
        ci_debug_task_state(
            "cleanup in write cb doesn't explode: write_task_server at server completion",
            write_task_server,
        )
        @test write_err_client[] == Reseau.AWS_OP_SUCCESS
        @test write_err_server[] == Reseau.AWS_OP_SUCCESS
        @test write_done_client_cb_err[] === nothing
        @test write_done_server_cb_err[] === nothing
    finally
        ci_debug_log("cleanup in write cb doesn't explode: cleanup start")
        if client_socket !== nothing
            ci_with_timeout("cleanup in write cb doesn't explode: socket_cleanup!(client_socket)", () -> Sockets.socket_cleanup!(client_socket))
            if !ci_with_timeout("cleanup in write cb doesn't explode: socket_close(client_socket)", () -> Sockets.socket_close(client_socket))
                ci_debug_log("cleanup in write cb doesn't explode: fallback socket_close(client_socket) timed out")
            end
        end
        if accepted[] !== nothing
            ci_with_timeout("cleanup in write cb doesn't explode: socket_cleanup!(accepted[])", () -> Sockets.socket_cleanup!(accepted[]))
            if !ci_with_timeout("cleanup in write cb doesn't explode: socket_close(accepted[])", () -> Sockets.socket_close(accepted[]))
                ci_debug_log("cleanup in write cb doesn't explode: fallback socket_close(accepted[]) timed out")
            end
        end
        ci_with_timeout("cleanup in write cb doesn't explode: socket_cleanup!(listener_socket)", () -> Sockets.socket_cleanup!(listener_socket))
        if !ci_with_timeout("cleanup in write cb doesn't explode: socket_close(listener_socket)", () -> Sockets.socket_close(listener_socket))
            ci_debug_log("cleanup in write cb doesn't explode: fallback socket_close(listener_socket) timed out")
        end
        ci_with_timeout("cleanup in write cb doesn't explode: event_loop_destroy!", () -> EventLoops.event_loop_destroy!(el_val))
    end
end

@testset "local socket communication" begin
    ci_debug_log("socket_tests: local socket communication start")
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
        ci_debug_log("local socket communication: socket_start_accept")
        @test ci_with_timeout(
            "local socket communication: socket_start_accept",
            () -> Sockets.socket_start_accept(server_socket, el_val, accept_opts) === nothing;
            timeout_s = 1.0,
        )

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
                ci_debug_log("local socket communication: on_connection_result")
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

        ci_debug_log("local socket communication: socket_connect")
        @test ci_with_timeout(
            "local socket communication: socket_connect",
            () -> Sockets.socket_connect(client_socket, connect_opts) === nothing;
            timeout_s = 1.0,
        )
        ci_debug_log("local socket communication: socket_connect done")
        @test ci_wait_for_flag("local socket communication: wait connect_done", connect_done)
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
        @test ci_wait_for_flag("local socket communication: wait write_done", write_done)
        @test write_err[] == Reseau.AWS_OP_SUCCESS
        @test ci_wait_for_flag("local socket communication: wait read_done", read_done)
        @test accept_err[] == Reseau.AWS_OP_SUCCESS
        @test read_err[] == Reseau.AWS_OP_SUCCESS
        @test payload[] == "ping"
    finally
        ci_debug_log("local socket communication: cleanup start")
        if client_socket !== nothing
            ci_with_timeout("local socket communication: socket_cleanup!(client_socket)", () -> Sockets.socket_cleanup!(client_socket))
            if !ci_with_timeout("local socket communication: socket_close(client_socket)", () -> Sockets.socket_close(client_socket))
                ci_debug_log("local socket communication: fallback socket_close(client_socket) timed out")
            end
        end
        if accepted[] !== nothing
            ci_with_timeout("local socket communication: socket_cleanup!(accepted[])", () -> Sockets.socket_cleanup!(accepted[]))
            if !ci_with_timeout("local socket communication: socket_close(accepted[])", () -> Sockets.socket_close(accepted[]))
                ci_debug_log("local socket communication: fallback socket_close(accepted[]) timed out")
            end
        end
        if server_socket !== nothing
            ci_with_timeout("local socket communication: socket_cleanup!(server_socket)", () -> Sockets.socket_cleanup!(server_socket))
            if !ci_with_timeout("local socket communication: socket_close(server_socket)", () -> Sockets.socket_close(server_socket))
                ci_debug_log("local socket communication: fallback socket_close(server_socket) timed out")
            end
        end
        ci_with_timeout("local socket communication: event_loop_destroy!", () -> EventLoops.event_loop_destroy!(el_val))
        if !isempty(local_path) && isfile(local_path)
            rm(local_path; force = true)
        end
    end
end

@testset "local socket connect before accept" begin
    ci_debug_log("socket_tests: local socket connect before accept start")
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
                ci_debug_log("local socket connect before accept: on_connection_result")
                connect_err[] = err
                connect_done[] = true
                return nothing
            end),
        )

        ci_debug_log("local socket connect before accept: socket_connect")
        @test ci_with_timeout(
            "local socket connect before accept: socket_connect",
            () -> Sockets.socket_connect(client_socket, connect_opts) === nothing;
            timeout_s = 1.0,
        )

        on_accept = Reseau.ChannelCallable((err, new_sock) -> begin
            ci_debug_log("local socket connect before accept: on_accept")
            accept_err[] = err
            accepted[] = new_sock
            accept_done[] = true
            return nothing
        end)

        accept_opts = Sockets.SocketListenerOptions(on_accept_result = on_accept)
        ci_debug_log("local socket connect before accept: socket_start_accept")
        @test ci_with_timeout(
            "local socket connect before accept: socket_start_accept",
            () -> Sockets.socket_start_accept(server_socket, el_val, accept_opts) === nothing;
            timeout_s = 1.0,
        )

        @test ci_wait_for_flag("local socket connect before accept: wait connect_done", connect_done)
        @test ci_wait_for_flag("local socket connect before accept: wait accept_done", accept_done)
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
        @test accept_err[] == Reseau.AWS_OP_SUCCESS
    finally
        ci_debug_log("local socket connect before accept: cleanup start")
        if client_socket !== nothing
            ci_with_timeout("local socket connect before accept: socket_cleanup!(client_socket)", () -> Sockets.socket_cleanup!(client_socket))
            if !ci_with_timeout("local socket connect before accept: socket_close(client_socket)", () -> Sockets.socket_close(client_socket))
                ci_debug_log("local socket connect before accept: fallback socket_close(client_socket) timed out")
            end
        end
        if accepted[] !== nothing
            ci_with_timeout("local socket connect before accept: socket_cleanup!(accepted[])", () -> Sockets.socket_cleanup!(accepted[]))
            if !ci_with_timeout("local socket connect before accept: socket_close(accepted[])", () -> Sockets.socket_close(accepted[]))
                ci_debug_log("local socket connect before accept: fallback socket_close(accepted[]) timed out")
            end
        end
        if server_socket !== nothing
            ci_with_timeout("local socket connect before accept: socket_cleanup!(server_socket)", () -> Sockets.socket_cleanup!(server_socket))
            if !ci_with_timeout("local socket connect before accept: socket_close(server_socket)", () -> Sockets.socket_close(server_socket))
                ci_debug_log("local socket connect before accept: fallback socket_close(server_socket) timed out")
            end
        end
        ci_with_timeout("local socket connect before accept: event_loop_destroy!", () -> EventLoops.event_loop_destroy!(el_val))
        if !isempty(local_path) && isfile(local_path)
            rm(local_path; force = true)
        end
    end
end

@testset "udp socket communication" begin
    ci_debug_log("socket_tests: udp socket communication start")
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
                ci_debug_log("udp socket communication: on_connection_result")
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

        ci_debug_log("udp socket communication: socket_connect")
        @test ci_with_timeout(
            "udp socket communication: socket_connect",
            () -> Sockets.socket_connect(client_socket, connect_opts) === nothing;
            timeout_s = 1.0,
        )
        @test ci_wait_for_flag("udp socket communication: wait connect_done", connect_done)
        @test connect_err[] == Reseau.AWS_OP_SUCCESS
        @test ci_wait_for_flag("udp socket communication: wait write_done", write_done)
        @test write_err[] == Reseau.AWS_OP_SUCCESS
        @test ci_wait_for_flag("udp socket communication: wait read_done", read_done)
        @test read_err[] == Reseau.AWS_OP_SUCCESS
        @test payload[] == "ping"
    finally
        ci_debug_log("udp socket communication: cleanup start")
        if client_socket !== nothing
            ci_with_timeout("udp socket communication: socket_cleanup!(client_socket)", () -> Sockets.socket_cleanup!(client_socket))
            if !ci_with_timeout("udp socket communication: socket_close(client_socket)", () -> Sockets.socket_close(client_socket))
                ci_debug_log("udp socket communication: fallback socket_close(client_socket) timed out")
            end
        end
        if server_socket !== nothing
            ci_with_timeout("udp socket communication: socket_cleanup!(server_socket)", () -> Sockets.socket_cleanup!(server_socket))
            if !ci_with_timeout("udp socket communication: socket_close(server_socket)", () -> Sockets.socket_close(server_socket))
                ci_debug_log("udp socket communication: fallback socket_close(server_socket) timed out")
            end
        end
        ci_with_timeout("udp socket communication: event_loop_destroy!", () -> EventLoops.event_loop_destroy!(el_val))
    end
end

@testset "udp bind connect communication" begin
    ci_debug_log("socket_tests: udp bind connect communication start")
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

@testset "wrong thread read write fails" begin
    ci_debug_log("socket_tests: wrong thread read write fails start")
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

@testset "bind on zero port tcp ipv4" begin
    ci_debug_log("socket_tests: bind on zero port tcp ipv4 start")
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

@testset "bind on zero port udp ipv4" begin
    ci_debug_log("socket_tests: bind on zero port udp ipv4 start")
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

@testset "incoming duplicate tcp bind errors" begin
    ci_debug_log("socket_tests: incoming duplicate tcp bind errors start")
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

@testset "incoming tcp socket errors" begin
    ci_debug_log("socket_tests: incoming tcp socket errors start")
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

@testset "incoming udp socket errors" begin
    ci_debug_log("socket_tests: incoming udp socket errors start")
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

@testset "outgoing local socket errors" begin
    ci_debug_log("socket_tests: outgoing local socket errors start")
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

@testset "outgoing tcp socket error" begin
    ci_debug_log("socket_tests: outgoing tcp socket error start")
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
