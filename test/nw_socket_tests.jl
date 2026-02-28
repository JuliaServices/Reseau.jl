using Test
using Reseau
import Reseau: Threads, EventLoops, Sockets

function wait_for_flag_nw(flag; timeout_s::Float64 = 5.0)
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

@testset "NW Socket Targeted Coverage" begin
    @testset "send path with connected udp sockets" begin
        if Sys.isapple()
            el = EventLoops.EventLoop()
            el_val = el isa EventLoops.EventLoop ? el : nothing
            @test el_val !== nothing
            if el_val === nothing
                return
            end
            @test EventLoops.run!(el_val) === nothing

            opts = Sockets.SocketOptions(; type = Sockets.SocketType.DGRAM, domain = Sockets.SocketDomain.IPV4)
            server = Sockets.socket_init(opts)
            server_socket = server isa Sockets.Socket ? server : nothing
            @test server_socket !== nothing
            if server_socket === nothing
                close(el_val)
                return
            end

            client_socket = nothing
            try
                bind_opts = (; local_endpoint = Sockets.SocketEndpoint("127.0.0.1", 0))
                @test Sockets.socket_bind(server_socket; bind_opts...) === nothing
                bound = Sockets.socket_get_bound_address(server_socket)
                @test bound isa Sockets.SocketEndpoint
                port = bound isa Sockets.SocketEndpoint ? Int(bound.port) : 0
                if port == 0
                    return
                end

                @test Sockets.socket_assign_to_event_loop(server_socket, el_val) === nothing

                read_err = Ref{Int}(0)
                read_done = Threads.Atomic{Bool}(false)
                payload = Ref{String}("")
                Sockets.socket_subscribe_to_readable_events(
                    server_socket,
                    Reseau.EventCallable(err -> begin
                        read_err[] = err
                        if err != Reseau.OP_SUCCESS
                            read_done[] = true
                            return nothing
                        end
                        buf = Reseau.ByteBuffer(64)
                        try
                            Sockets.socket_read(server_socket, buf)
                            payload[] = String(Reseau.byte_cursor_from_buf(buf))
                        catch e
                            read_err[] = e isa Reseau.ReseauError ? e.code : Reseau.ERROR_UNKNOWN
                        end
                        read_done[] = true
                        return nothing
                    end),
                )

                client = Sockets.socket_init(opts)
                client_socket = client isa Sockets.Socket ? client : nothing
                @test client_socket !== nothing
                if client_socket === nothing
                    return
                end

                @test Sockets.socket_bind(client_socket; local_endpoint = Sockets.SocketEndpoint("127.0.0.1", 0)) === nothing

                connect_err = Ref{Int}(0)
                connect_done = Threads.Atomic{Bool}(false)
                write_err = Ref{Int}(0)
                write_done = Threads.Atomic{Bool}(false)
                connect_opts = (
                    remote_endpoint = Sockets.SocketEndpoint("127.0.0.1", port),
                    event_loop = el_val,
                    on_connection_result = Reseau.EventCallable(err -> begin
                        connect_err[] = err
                        connect_done[] = true
                        if err != Reseau.OP_SUCCESS
                            return nothing
                        end
                        cursor = Reseau.ByteCursor("ping")
                        try
                            Sockets.socket_write(
                                client_socket,
                                cursor,
                                Reseau.WriteCallable((err, bytes) -> begin
                                    _ = bytes
                                    write_err[] = err
                                    write_done[] = true
                                    return nothing
                                end),
                            )
                        catch e
                            write_err[] = e isa Reseau.ReseauError ? e.code : Reseau.ERROR_UNKNOWN
                            write_done[] = true
                        end
                        return nothing
                    end),
                )

                @test Sockets.socket_connect(client_socket; connect_opts...) === nothing
                @test wait_for_flag_nw(connect_done)
                @test connect_err[] == Reseau.OP_SUCCESS
                @test wait_for_flag_nw(write_done)
                @test write_err[] == Reseau.OP_SUCCESS
                @test wait_for_flag_nw(read_done)
                @test read_err[] == Reseau.OP_SUCCESS
                @test payload[] == "ping"
            finally
                client_socket !== nothing && Sockets.socket_close(client_socket)
                Sockets.socket_close(server_socket)
                close(el_val)
            end
        else
            @test true
        end
    end

    @testset "stop_accept state transitions" begin
        if Sys.isapple()
            opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
            sock = Sockets.socket_init(opts)
            socket_val = sock isa Sockets.Socket ? sock : nothing
            @test socket_val !== nothing
            if socket_val === nothing
                return
            end

            try
                @test Sockets.socket_bind(socket_val; local_endpoint = Sockets.SocketEndpoint("127.0.0.1", 0)) === nothing
                @test Sockets.socket_listen(socket_val, 8) === nothing
                @test Sockets.socket_stop_accept(socket_val) === nothing

                try
                    Sockets.socket_stop_accept(socket_val)
                    @test false
                catch e
                    @test e isa Reseau.ReseauError
                    @test e.code == EventLoops.ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE
                end
            finally
                Sockets.socket_close(socket_val)
            end
        else
            @test true
        end
    end

    @testset "set_options validates domain and type" begin
        if Sys.isapple()
            opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
            sock = Sockets.socket_init(opts)
            socket_val = sock isa Sockets.Socket ? sock : nothing
            @test socket_val !== nothing
            if socket_val === nothing
                return
            end

            try
                updated = copy(socket_val.options)
                updated.connect_timeout_ms = UInt32(1234)
                @test Sockets.socket_set_options(socket_val, updated) === nothing
                @test socket_val.options.connect_timeout_ms == UInt32(1234)

                bad_domain = copy(updated)
                bad_domain.domain = Sockets.SocketDomain.LOCAL
                try
                    Sockets.socket_set_options(socket_val, bad_domain)
                    @test false
                catch e
                    @test e isa Reseau.ReseauError
                    @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_OPTIONS
                end

                bad_type = copy(updated)
                bad_type.type = Sockets.SocketType.DGRAM
                try
                    Sockets.socket_set_options(socket_val, bad_type)
                    @test false
                catch e
                    @test e isa Reseau.ReseauError
                    @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_OPTIONS
                end
            finally
                Sockets.socket_close(socket_val)
            end
        else
            @test true
        end
    end

    @testset "shutdown dir unsupported" begin
        if Sys.isapple()
            opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
            sock = Sockets.socket_init(opts)
            socket_val = sock isa Sockets.Socket ? sock : nothing
            @test socket_val !== nothing
            if socket_val === nothing
                return
            end

            try
                for dir in (Sockets.ChannelDirection.READ, Sockets.ChannelDirection.WRITE)
                    try
                        Sockets.socket_shutdown_dir(socket_val, dir)
                        @test false
                    catch e
                        @test e isa Reseau.ReseauError
                        @test e.code == EventLoops.ERROR_IO_SOCKET_INVALID_OPERATION_FOR_TYPE
                    end
                end
            finally
                Sockets.socket_close(socket_val)
            end
        else
            @test true
        end
    end

    @testset "protocol and server name getters" begin
        if Sys.isapple()
            opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
            sock = Sockets.socket_init(opts)
            socket_val = sock isa Sockets.Socket ? sock : nothing
            @test socket_val !== nothing
            if socket_val === nothing
                return
            end

            client_opts = Sockets.tls_ctx_options_init_default_client()
            ctx = Sockets.tls_context_new(client_opts)

            try
                @test Sockets.socket_get_protocol(socket_val).len == 0
                @test Sockets.socket_get_server_name(socket_val).len == 0

                tls_opts = Sockets.TlsConnectionOptions(ctx; server_name = "example.org")
                try
                    Sockets.socket_connect(
                        socket_val;
                        remote_endpoint = Sockets.SocketEndpoint("127.0.0.1", 443),
                        tls_connection_options = tls_opts,
                    )
                    @test false
                catch e
                    @test e isa Reseau.ReseauError
                    @test e.code == EventLoops.ERROR_IO_SOCKET_MISSING_EVENT_LOOP
                end

                server_name = String(Reseau.byte_cursor_from_buf(Sockets.socket_get_server_name(socket_val)))
                @test server_name == "example.org"
                @test Sockets.socket_get_protocol(socket_val).len == 0
            finally
                Sockets.socket_close(socket_val)
                Sockets.tls_ctx_release(ctx)
            end
        else
            @test true
        end
    end

    @testset "wrong thread read write fails on nw ipv4" begin
        if Sys.isapple()
            el = EventLoops.EventLoop()
            el_val = el isa EventLoops.EventLoop ? el : nothing
            @test el_val !== nothing
            if el_val === nothing
                return
            end
            @test EventLoops.run!(el_val) === nothing

            opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
            sock = Sockets.socket_init(opts)
            socket_val = sock isa Sockets.Socket ? sock : nothing
            @test socket_val !== nothing
            if socket_val === nothing
                close(el_val)
                return
            end

            try
                connect_opts = (
                    remote_endpoint = Sockets.SocketEndpoint("127.0.0.1", 9),
                    event_loop = el_val,
                    on_connection_result = Reseau.EventCallable(err -> nothing),
                )
                try
                    @test Sockets.socket_connect(socket_val; connect_opts...) === nothing
                catch e
                    @test e isa Reseau.ReseauError
                end

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
                end); type_tag = "socket_close_wrong_thread_nw")
                EventLoops.schedule_task_now!(el_val, close_task)
                @test wait_for_flag_nw(close_done)
            finally
                close(el_val)
            end
        else
            @test true
        end
    end
end
