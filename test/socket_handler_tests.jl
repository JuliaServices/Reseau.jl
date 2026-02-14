using Test
using Reseau

function wait_for(predicate; timeout_s::Float64 = 5.0)
    start = Base.time_ns()
    timeout_ns = Int(timeout_s * 1_000_000_000)
    while (Base.time_ns() - start) < timeout_ns
        if predicate()
            return true
        end
        sleep(0.01)
    end
    return false
end

@testset "socket handler read backpressure" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    # Use LOCAL on macOS (IPV4 → NW sockets, which don't expose resolved port)
    @static if Sys.isapple()
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.LOCAL)
    else
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    end
    server = Sockets.socket_init(opts)
    @test server isa Sockets.Socket

    @static if Sys.isapple()
        bind_endpoint = Sockets.SocketEndpoint()
        Sockets.socket_endpoint_init_local_address_for_test!(bind_endpoint)
        connect_endpoint = bind_endpoint
    else
        bind_endpoint = Sockets.SocketEndpoint("127.0.0.1", 0)
    end
    bind_opts = Sockets.SocketBindOptions(bind_endpoint)
    @test Sockets.socket_bind(server, bind_opts) === nothing
    @test Sockets.socket_listen(server, 8) === nothing
    @static if !Sys.isapple()
        bound = Sockets.socket_get_bound_address(server)
        @test bound isa Sockets.SocketEndpoint
        port = bound isa Sockets.SocketEndpoint ? bound.port : 0
        @test port > 0
        connect_endpoint = Sockets.SocketEndpoint("127.0.0.1", port)
    end

    accept_done = Ref(false)
    accept_err = Ref(0)
    accepted_socket = Ref{Any}(nothing)
    pipeline_ref = Ref{Any}(nothing)

    received = UInt8[]
    received_lock = ReentrantLock()

    on_accept = Reseau.ChannelCallable((err, new_sock) -> begin
        accept_err[] = err
        if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
            accept_done[] = true
            return nothing
        end
        Sockets.socket_assign_to_event_loop(new_sock, event_loop)

        ps = Sockets.PipelineState(event_loop; enable_read_back_pressure = true)
        ps.message_pool = EventLoops.MessagePool(EventLoops.MessagePoolCreationArgs())

        try
            Sockets.socket_pipeline_init!(new_sock, ps; max_read_size = 4)
        catch
            accept_done[] = true
            return nothing
        end

        # For non-TLS with backpressure, propagate window updates to socket
        ps.window_update_fn = function(size::Csize_t)
            new_sock.downstream_window = Reseau.add_size_saturating(new_sock.downstream_window, size)
            Sockets._socket_handler_trigger_read(new_sock)
        end

        # Install closure-based read handler
        ps.downstream_read_setter(msg -> begin
            chunk = String(Reseau.byte_cursor_from_buf(msg.message_data))
            lock(received_lock) do
                append!(received, codeunits(chunk))
            end
            Sockets.pipeline_release_message_to_pool!(ps, msg)
            return nothing
        end)

        # Ensure deterministic window size for backpressure checks
        if ps.window_update_task.wrapper_task.scheduled
            EventLoops.event_loop_cancel_task!(event_loop, ps.window_update_task.wrapper_task)
        end
        ps.window_update_scheduled = false
        new_sock.downstream_window = Csize_t(4)
        ps.downstream_window = Csize_t(4)
        ps.window_update_batch = Csize_t(0)

        accepted_socket[] = new_sock
        pipeline_ref[] = ps
        accept_done[] = true
        return nothing
    end)

    accept_opts = Sockets.SocketListenerOptions(on_accept_result = on_accept)
    @test Sockets.socket_start_accept(server, event_loop, accept_opts) === nothing

    client = Sockets.socket_init(opts)
    @test client isa Sockets.Socket

    connect_done = Ref(false)
    connect_err = Ref(0)
    connect_opts = Sockets.SocketConnectOptions(
        connect_endpoint;
        event_loop = event_loop,
        on_connection_result = Reseau.EventCallable(err -> begin
            connect_err[] = err
            connect_done[] = true
            return nothing
        end),
    )
    @test Sockets.socket_connect(client, connect_opts) === nothing
    @test wait_for(() -> connect_done[] && accept_done[])
    @test connect_err[] == Reseau.AWS_OP_SUCCESS
    @test accept_err[] == Reseau.AWS_OP_SUCCESS

    ps = pipeline_ref[]
    @test ps isa Sockets.PipelineState
    if !(ps isa Sockets.PipelineState)
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    write_done = Ref(false)
    write_err = Ref(Reseau.AWS_OP_SUCCESS)
    write_bytes = Ref(0)

    payload = "abcdefghij"
    cursor = Reseau.ByteCursor(payload)

    write_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
        Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return nothing
        try
            Sockets.socket_write(client, cursor, Reseau.WriteCallable((err, num_bytes) -> begin
                write_err[] = err
                write_bytes[] = Int(num_bytes)
                write_done[] = true
                return nothing
            end))
        catch e
            write_err[] = e isa Reseau.ReseauError ? e.code : Reseau.ERROR_UNKNOWN
            write_done[] = true
        end
        return nothing
    end); type_tag = "client_write")
    EventLoops.event_loop_schedule_task_now!(event_loop, write_task)

    @test wait_for(() -> write_done[])
    @test write_err[] == Reseau.AWS_OP_SUCCESS
    @test write_bytes[] == ncodeunits(payload)

    # Trigger read on the accepted socket
    trigger_done = Ref(false)
    trigger_task = Sockets.ChannelTask(Reseau.EventCallable(status -> begin
        Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return nothing
        Sockets._socket_handler_trigger_read(accepted_socket[]::Sockets.Socket)
        trigger_done[] = true
        return nothing
    end), "socket_handler_trigger_read")
    Sockets.pipeline_schedule_task_now!(ps::Sockets.PipelineState, trigger_task)
    @test wait_for(() -> trigger_done[])

    received_len() = lock(received_lock) do; length(received); end

    @test wait_for(() -> received_len() >= 4)
    @test received_len() == 4

    # Increment window to allow remaining bytes
    update_done = Ref(false)
    update_task = Sockets.ChannelTask(Reseau.EventCallable(status -> begin
        Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return nothing
        Sockets.pipeline_increment_read_window!(ps::Sockets.PipelineState, Csize_t(6))
        update_done[] = true
        return nothing
    end), "window_update")
    Sockets.pipeline_schedule_task_now!(ps::Sockets.PipelineState, update_task)
    @test wait_for(() -> update_done[])

    @test wait_for(() -> received_len() == 10)

    if accepted_socket[] isa Sockets.Socket
        Sockets.socket_close(accepted_socket[])
    end
    Sockets.socket_close(client)
    Sockets.socket_close(server)
    EventLoops.event_loop_group_destroy!(elg)
end

@testset "socket handler write completion" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    @static if Sys.isapple()
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.LOCAL)
    else
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    end
    server = Sockets.socket_init(opts)
    @test server isa Sockets.Socket

    @static if Sys.isapple()
        bind_endpoint = Sockets.SocketEndpoint()
        Sockets.socket_endpoint_init_local_address_for_test!(bind_endpoint)
        connect_endpoint = bind_endpoint
    else
        bind_endpoint = Sockets.SocketEndpoint("127.0.0.1", 0)
    end
    bind_opts = Sockets.SocketBindOptions(bind_endpoint)
    @test Sockets.socket_bind(server, bind_opts) === nothing
    @test Sockets.socket_listen(server, 8) === nothing
    @static if !Sys.isapple()
        bound = Sockets.socket_get_bound_address(server)
        @test bound isa Sockets.SocketEndpoint
        port = bound isa Sockets.SocketEndpoint ? bound.port : 0
        @test port > 0
        connect_endpoint = Sockets.SocketEndpoint("127.0.0.1", port)
    end

    accept_done = Ref(false)
    accept_err = Ref(0)
    accepted_socket = Ref{Any}(nothing)
    pipeline_ref = Ref{Any}(nothing)

    on_accept = Reseau.ChannelCallable((err, new_sock) -> begin
        accept_err[] = err
        if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
            accept_done[] = true
            return nothing
        end
        Sockets.socket_assign_to_event_loop(new_sock, event_loop)

        ps = Sockets.PipelineState(event_loop)
        ps.message_pool = EventLoops.MessagePool(EventLoops.MessagePoolCreationArgs())

        try
            Sockets.socket_pipeline_init!(new_sock, ps)
        catch
            accept_done[] = true
            return nothing
        end

        # For non-TLS, route writes directly to the OS socket
        new_sock.write_fn = msg -> Sockets._socket_write_message(new_sock, msg)

        # Install a dummy read handler (this test only tests writes)
        ps.downstream_read_setter(msg -> begin
            Sockets.pipeline_release_message_to_pool!(ps, msg)
            return nothing
        end)

        accepted_socket[] = new_sock
        pipeline_ref[] = ps
        accept_done[] = true
        return nothing
    end)

    accept_opts = Sockets.SocketListenerOptions(on_accept_result = on_accept)
    @test Sockets.socket_start_accept(server, event_loop, accept_opts) === nothing

    client = Sockets.socket_init(opts)
    @test client isa Sockets.Socket

    connect_done = Ref(false)
    connect_err = Ref(0)
    connect_opts = Sockets.SocketConnectOptions(
        connect_endpoint;
        event_loop = event_loop,
        on_connection_result = Reseau.EventCallable(err -> begin
            connect_err[] = err
            connect_done[] = true
            return nothing
        end),
    )
    @test Sockets.socket_connect(client, connect_opts) === nothing
    @test wait_for(() -> connect_done[] && accept_done[])
    @test connect_err[] == Reseau.AWS_OP_SUCCESS
    @test accept_err[] == Reseau.AWS_OP_SUCCESS

    read_done = Ref(false)
    read_err = Ref(0)
    read_payload = Ref("")
    subscribe_done = Ref(false)
    subscribe_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
        Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return nothing
        try
            Sockets.socket_subscribe_to_readable_events(client, Reseau.EventCallable(err -> begin
                read_err[] = err
                if err != Reseau.AWS_OP_SUCCESS
                    read_done[] = true
                    return nothing
                end
                buf = Reseau.ByteBuffer(64)
                try
                    Sockets.socket_read(client, buf)
                    read_payload[] = String(Reseau.byte_cursor_from_buf(buf))
                catch e
                    read_err[] = e isa Reseau.ReseauError ? e.code : Reseau.ERROR_UNKNOWN
                end
                read_done[] = true
                return nothing
            end))
        catch e
            read_err[] = e isa Reseau.ReseauError ? e.code : Reseau.ERROR_UNKNOWN
            read_done[] = true
        end
        subscribe_done[] = true
        return nothing
    end); type_tag = "client_subscribe")
    EventLoops.event_loop_schedule_task_now!(event_loop, subscribe_task)
    @test wait_for(() -> subscribe_done[])

    ps = pipeline_ref[]
    @test ps isa Sockets.PipelineState
    if !(ps isa Sockets.PipelineState)
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    send_done = Ref(false)
    send_err = Ref(0)
    payload = "hello"
    send_task = Sockets.ChannelTask(Reseau.EventCallable(status -> begin
        Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return nothing
        msg = Sockets.pipeline_acquire_message_from_pool(ps::Sockets.PipelineState, EventLoops.IoMessageType.APPLICATION_DATA, length(payload))
        if msg === nothing
            send_err[] = Reseau.ERROR_OOM
            send_done[] = true
            return nothing
        end
        msg_ref = Ref(msg.message_data)
        ok = Reseau.byte_buf_write_from_whole_cursor(msg_ref, Reseau.ByteCursor(payload))
        msg.message_data = msg_ref[]
        if !ok || msg.message_data.len != Csize_t(length(payload))
            send_err[] = EventLoops.ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT
            send_done[] = true
            return nothing
        end
        msg.on_completion = Reseau.EventCallable(err -> begin
            send_err[] = err
            send_done[] = true
            return nothing
        end)
        try
            Sockets._socket_write_message(accepted_socket[]::Sockets.Socket, msg)
        catch e
            send_err[] = e isa Reseau.ReseauError ? e.code : Reseau.ERROR_UNKNOWN
            send_done[] = true
        end
        return nothing
    end), "socket_handler_send")
    Sockets.pipeline_schedule_task_now!(ps::Sockets.PipelineState, send_task)

    @test wait_for(() -> send_done[])
    @test send_err[] == Reseau.AWS_OP_SUCCESS
    @test wait_for(() -> read_done[])
    @test read_err[] == Reseau.AWS_OP_SUCCESS
    @test read_payload[] == payload

    if accepted_socket[] isa Sockets.Socket
        Sockets.socket_close(accepted_socket[])
    end
    Sockets.socket_close(client)
    Sockets.socket_close(server)
    EventLoops.event_loop_group_destroy!(elg)
end

@testset "socket handler pending read before downstream setup" begin
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    @static if Sys.isapple()
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.LOCAL)
    else
        opts = Sockets.SocketOptions(; type = Sockets.SocketType.STREAM, domain = Sockets.SocketDomain.IPV4)
    end
    server = Sockets.socket_init(opts)
    @test server isa Sockets.Socket

    @static if Sys.isapple()
        bind_endpoint = Sockets.SocketEndpoint()
        Sockets.socket_endpoint_init_local_address_for_test!(bind_endpoint)
        connect_endpoint = bind_endpoint
    else
        bind_endpoint = Sockets.SocketEndpoint("127.0.0.1", 0)
    end
    bind_opts = Sockets.SocketBindOptions(bind_endpoint)
    @test Sockets.socket_bind(server, bind_opts) === nothing
    @test Sockets.socket_listen(server, 8) === nothing
    @static if !Sys.isapple()
        bound = Sockets.socket_get_bound_address(server)
        @test bound isa Sockets.SocketEndpoint
        port = bound isa Sockets.SocketEndpoint ? bound.port : 0
        @test port > 0
        connect_endpoint = Sockets.SocketEndpoint("127.0.0.1", port)
    end

    accept_done = Ref(false)
    accept_err = Ref(0)
    accepted_socket = Ref{Any}(nothing)
    pipeline_ref = Ref{Any}(nothing)

    on_accept = Reseau.ChannelCallable((err, new_sock) -> begin
        accept_err[] = err
        if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
            accept_done[] = true
            return nothing
        end
        Sockets.socket_assign_to_event_loop(new_sock, event_loop)

        ps = Sockets.PipelineState(event_loop)
        ps.message_pool = EventLoops.MessagePool(EventLoops.MessagePoolCreationArgs())

        try
            Sockets.socket_pipeline_init!(new_sock, ps; max_read_size = 16)
        catch
            accept_done[] = true
            return nothing
        end

        # Do NOT install read handler yet — leave socket.read_fn as nothing
        accepted_socket[] = new_sock
        pipeline_ref[] = ps
        accept_done[] = true
        return nothing
    end)

    accept_opts = Sockets.SocketListenerOptions(on_accept_result = on_accept)
    @test Sockets.socket_start_accept(server, event_loop, accept_opts) === nothing

    client = Sockets.socket_init(opts)
    @test client isa Sockets.Socket

    connect_done = Ref(false)
    connect_err = Ref(0)
    connect_opts = Sockets.SocketConnectOptions(
        connect_endpoint;
        event_loop = event_loop,
        on_connection_result = Reseau.EventCallable(err -> begin
            connect_err[] = err
            connect_done[] = true
            return nothing
        end),
    )
    @test Sockets.socket_connect(client, connect_opts) === nothing
    @test wait_for(() -> connect_done[] && accept_done[])
    @test connect_err[] == Reseau.AWS_OP_SUCCESS
    @test accept_err[] == Reseau.AWS_OP_SUCCESS

    sock = accepted_socket[]
    @test sock isa Sockets.Socket
    if !(sock isa Sockets.Socket)
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    write_done = Ref(false)
    write_err = Ref(Reseau.AWS_OP_SUCCESS)

    payload = "pending"
    cursor = Reseau.ByteCursor(payload)

    write_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
        Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return nothing
        try
            Sockets.socket_write(client, cursor, Reseau.WriteCallable((err, num_bytes) -> begin
                write_err[] = err
                write_done[] = true
                return nothing
            end))
        catch e
            write_err[] = e isa Reseau.ReseauError ? e.code : Reseau.ERROR_UNKNOWN
            write_done[] = true
        end
        return nothing
    end); type_tag = "client_write_pending")
    EventLoops.event_loop_schedule_task_now!(event_loop, write_task)

    @test wait_for(() -> write_done[])
    @test write_err[] == Reseau.AWS_OP_SUCCESS

    # Wait for pending_read flag — data arrived but no read handler installed
    @test wait_for(() -> (sock::Sockets.Socket).pending_read)

    ps = pipeline_ref[]
    @test ps isa Sockets.PipelineState
    if !(ps isa Sockets.PipelineState)
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    received = UInt8[]
    received_lock = ReentrantLock()

    # Install read handler and trigger read on event loop thread
    setup_done = Ref(false)
    setup_task = Sockets.ChannelTask(Reseau.EventCallable(status -> begin
        Reseau.TaskStatus.T(status) == Reseau.TaskStatus.RUN_READY || return nothing
        (ps::Sockets.PipelineState).downstream_read_setter(msg -> begin
            data = String(Reseau.byte_cursor_from_buf(msg.message_data))
            lock(received_lock) do
                append!(received, codeunits(data))
            end
            Sockets.pipeline_release_message_to_pool!(ps::Sockets.PipelineState, msg)
            return nothing
        end)
        Sockets._socket_handler_trigger_read(sock::Sockets.Socket)
        setup_done[] = true
        return nothing
    end), "setup_downstream")
    Sockets.pipeline_schedule_task_now!(ps::Sockets.PipelineState, setup_task)

    @test wait_for(() -> setup_done[])

    received_string() = lock(received_lock) do; String(received); end
    @test wait_for(() -> received_string() == payload)

    if client isa Sockets.Socket
        Sockets.socket_close(client)
    end
    if accepted_socket[] !== nothing
        Sockets.socket_close(accepted_socket[])
    end
    if server isa Sockets.Socket
        Sockets.socket_close(server)
    end
    EventLoops.event_loop_group_destroy!(elg)
end
