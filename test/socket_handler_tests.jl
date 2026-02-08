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

mutable struct TestReadHandler <: Reseau.AbstractChannelHandler
    slot::Union{Reseau.ChannelSlot, Nothing}
    received::Vector{UInt8}
    lock::ReentrantLock
    auto_increment::Bool
    initial_window_size::Csize_t
end

function TestReadHandler(initial_window_size::Integer; auto_increment::Bool = false)
    return TestReadHandler(nothing, UInt8[], ReentrantLock(), auto_increment, Csize_t(initial_window_size))
end

function Reseau.handler_process_read_message(handler::TestReadHandler, slot::Reseau.ChannelSlot, message::Reseau.IoMessage)
    payload = String(Reseau.byte_cursor_from_buf(message.message_data))
    # Handlers run on event-loop threads; tests may read `received` from the main thread.
    lock(handler.lock) do
        append!(handler.received, codeunits(payload))
    end

    if handler.auto_increment
        Reseau.channel_slot_increment_read_window!(slot, message.message_data.len)
    end

    if slot.channel !== nothing
        Reseau.channel_release_message_to_pool!(slot.channel, message)
    end
    return nothing
end

function Reseau.handler_process_write_message(handler::TestReadHandler, slot::Reseau.ChannelSlot, message::Reseau.IoMessage)
    return Reseau.channel_slot_send_message(slot, message, Reseau.ChannelDirection.WRITE)
end

function _received_len(handler::TestReadHandler)::Int
    return lock(handler.lock) do
        length(handler.received)
    end
end

function _received_string(handler::TestReadHandler)::String
    return lock(handler.lock) do
        String(handler.received)
    end
end

function Reseau.handler_increment_read_window(handler::TestReadHandler, slot::Reseau.ChannelSlot, size::Csize_t)
    return Reseau.channel_slot_increment_read_window!(slot, size)
end

function Reseau.handler_shutdown(
        handler::TestReadHandler,
        slot::Reseau.ChannelSlot,
        direction::Reseau.ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )
    Reseau.channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    return nothing
end

Reseau.handler_initial_window_size(handler::TestReadHandler) = handler.initial_window_size
Reseau.handler_message_overhead(::TestReadHandler) = Csize_t(0)
Reseau.handler_destroy(::TestReadHandler) = nothing

@testset "socket handler read backpressure" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    # Use LOCAL on macOS (IPV4 → NW sockets, which don't expose resolved port)
    @static if Sys.isapple()
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.LOCAL)
    else
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4)
    end
    server = Reseau.socket_init(opts)
    @test server isa Reseau.Socket
    if server isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    @static if Sys.isapple()
        bind_endpoint = Reseau.SocketEndpoint()
        Reseau.socket_endpoint_init_local_address_for_test!(bind_endpoint)
        connect_endpoint = bind_endpoint
    else
        bind_endpoint = Reseau.SocketEndpoint("127.0.0.1", 0)
    end
    bind_opts = Reseau.SocketBindOptions(bind_endpoint)
    @test Reseau.socket_bind(server, bind_opts) === nothing
    @test Reseau.socket_listen(server, 8) === nothing
    @static if !Sys.isapple()
        bound = Reseau.socket_get_bound_address(server)
        @test bound isa Reseau.SocketEndpoint
        port = bound isa Reseau.SocketEndpoint ? bound.port : 0
        @test port > 0
        connect_endpoint = Reseau.SocketEndpoint("127.0.0.1", port)
    end

    accept_done = Ref(false)
    accept_err = Ref(0)
    accepted_socket = Ref{Any}(nothing)
    channel_ref = Ref{Any}(nothing)
    socket_handler_ref = Ref{Any}(nothing)
    app_handler_ref = Ref{Any}(nothing)

    on_accept = (listener, err, new_sock, ud) -> begin
        accept_err[] = err
        if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
            accept_done[] = true
            return nothing
        end
        Reseau.socket_assign_to_event_loop(new_sock, event_loop)
        channel = Reseau.Channel(event_loop; enable_read_back_pressure = true)
        handler = Reseau.socket_channel_handler_new!(channel, new_sock; max_read_size = 4)
        if handler isa Reseau.ErrorResult
            accept_done[] = true
            return nothing
        end

        app_handler = TestReadHandler(4; auto_increment = false)
        app_slot = Reseau.channel_slot_new!(channel)
        if Reseau.channel_first_slot(channel) !== app_slot
            Reseau.channel_slot_insert_end!(channel, app_slot)
        end
        Reseau.channel_slot_set_handler!(app_slot, app_handler)
        app_handler.slot = app_slot

        Reseau.channel_setup_complete!(channel)

        # Ensure deterministic window size for backpressure checks
        if channel.window_update_task.wrapper_task.scheduled
            Reseau.event_loop_cancel_task!(event_loop, channel.window_update_task.wrapper_task)
        end
        channel.window_update_scheduled = false
        app_slot.window_size = Csize_t(4)
        app_slot.current_window_update_batch_size = Csize_t(0)

        accepted_socket[] = new_sock
        channel_ref[] = channel
        socket_handler_ref[] = handler
        app_handler_ref[] = app_handler
        accept_done[] = true
        return nothing
    end

    accept_opts = Reseau.SocketListenerOptions(on_accept_result = on_accept)
    @test Reseau.socket_start_accept(server, event_loop, accept_opts) === nothing

    client = Reseau.socket_init(opts)
    @test client isa Reseau.Socket
    if client isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    connect_done = Ref(false)
    connect_err = Ref(0)
    connect_opts = Reseau.SocketConnectOptions(
        connect_endpoint;
        event_loop = event_loop,
        on_connection_result = (sock, err, ud) -> begin
            connect_err[] = err
            connect_done[] = true
            return nothing
        end,
    )
    @test Reseau.socket_connect(client, connect_opts) === nothing
    @test wait_for(() -> connect_done[] && accept_done[])
    @test connect_err[] == Reseau.AWS_OP_SUCCESS
    @test accept_err[] == Reseau.AWS_OP_SUCCESS

    app_handler = app_handler_ref[]
    @test app_handler isa TestReadHandler
    if !(app_handler isa TestReadHandler)
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    write_done = Ref(false)
    write_err = Ref(Reseau.AWS_OP_SUCCESS)
    write_bytes = Ref(0)

    payload = "abcdefghij"
    cursor = Reseau.ByteCursor(payload)

    write_task = Reseau.ScheduledTask((ctx, status) -> begin
        status == Reseau.TaskStatus.RUN_READY || return nothing
        res = Reseau.socket_write(client, cursor, (sock, err, num_bytes, ud) -> begin
            write_err[] = err
            write_bytes[] = Int(num_bytes)
            write_done[] = true
            return nothing
        end, nothing)
        if res isa Reseau.ErrorResult
            write_err[] = res.code
            write_done[] = true
        end
        return nothing
    end, nothing; type_tag = "client_write")
    Reseau.event_loop_schedule_task_now!(event_loop, write_task)

    @test wait_for(() -> write_done[])
    @test write_err[] == Reseau.AWS_OP_SUCCESS
    @test write_bytes[] == ncodeunits(payload)

    channel = channel_ref[]
    socket_handler = socket_handler_ref[]
    @test channel isa Reseau.Channel
    @test socket_handler isa Reseau.SocketChannelHandler
    if !(channel isa Reseau.Channel && socket_handler isa Reseau.SocketChannelHandler)
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    trigger_done = Ref(false)
    trigger_task = Reseau.ChannelTask((task, arg, status) -> begin
        status == Reseau.TaskStatus.RUN_READY || return nothing
        Reseau.channel_trigger_read(channel)
        trigger_done[] = true
        return nothing
    end, nothing, "socket_handler_trigger_read")
    Reseau.channel_schedule_task_now!(channel, trigger_task)
    @test wait_for(() -> trigger_done[])

    @test wait_for(() -> _received_len(app_handler) >= 4)
    @test _received_len(app_handler) == 4

    update_done = Ref(false)
    update_task = Reseau.ChannelTask((task, arg, status) -> begin
        status == Reseau.TaskStatus.RUN_READY || return nothing
        app_handler.slot.window_size = app_handler.slot.window_size + Csize_t(6)
        Reseau.handler_increment_read_window(socket_handler, socket_handler.slot, Csize_t(6))
        update_done[] = true
        return nothing
    end, nothing, "window_update")
    Reseau.channel_schedule_task_now!(channel, update_task)
    @test wait_for(() -> update_done[])

    @test wait_for(() -> _received_len(app_handler) == 10)

    if accepted_socket[] isa Reseau.Socket
        Reseau.socket_close(accepted_socket[])
    end
    Reseau.socket_close(client)
    Reseau.socket_close(server)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "socket handler write completion" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    @static if Sys.isapple()
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.LOCAL)
    else
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4)
    end
    server = Reseau.socket_init(opts)
    @test server isa Reseau.Socket
    if server isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    @static if Sys.isapple()
        bind_endpoint = Reseau.SocketEndpoint()
        Reseau.socket_endpoint_init_local_address_for_test!(bind_endpoint)
        connect_endpoint = bind_endpoint
    else
        bind_endpoint = Reseau.SocketEndpoint("127.0.0.1", 0)
    end
    bind_opts = Reseau.SocketBindOptions(bind_endpoint)
    @test Reseau.socket_bind(server, bind_opts) === nothing
    @test Reseau.socket_listen(server, 8) === nothing
    @static if !Sys.isapple()
        bound = Reseau.socket_get_bound_address(server)
        @test bound isa Reseau.SocketEndpoint
        port = bound isa Reseau.SocketEndpoint ? bound.port : 0
        @test port > 0
        connect_endpoint = Reseau.SocketEndpoint("127.0.0.1", port)
    end

    accept_done = Ref(false)
    accept_err = Ref(0)
    accepted_socket = Ref{Any}(nothing)
    channel_ref = Ref{Any}(nothing)
    app_slot_ref = Ref{Any}(nothing)
    socket_handler_ref = Ref{Any}(nothing)

    on_accept = (listener, err, new_sock, ud) -> begin
        accept_err[] = err
        if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
            accept_done[] = true
            return nothing
        end
        Reseau.socket_assign_to_event_loop(new_sock, event_loop)
        channel = Reseau.Channel(event_loop; enable_read_back_pressure = false)
        socket_handler = Reseau.socket_channel_handler_new!(channel, new_sock)
        if socket_handler isa Reseau.ErrorResult
            accept_done[] = true
            return nothing
        end

        app_slot = Reseau.channel_slot_new!(channel)
        if Reseau.channel_first_slot(channel) !== app_slot
            Reseau.channel_slot_insert_end!(channel, app_slot)
        end
        Reseau.channel_slot_set_handler!(app_slot, Reseau.PassthroughHandler())

        Reseau.channel_setup_complete!(channel)

        accepted_socket[] = new_sock
        channel_ref[] = channel
        app_slot_ref[] = app_slot
        socket_handler_ref[] = socket_handler
        accept_done[] = true
        return nothing
    end

    accept_opts = Reseau.SocketListenerOptions(on_accept_result = on_accept)
    @test Reseau.socket_start_accept(server, event_loop, accept_opts) === nothing

    client = Reseau.socket_init(opts)
    @test client isa Reseau.Socket
    if client isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    connect_done = Ref(false)
    connect_err = Ref(0)
    connect_opts = Reseau.SocketConnectOptions(
        connect_endpoint;
        event_loop = event_loop,
        on_connection_result = (sock, err, ud) -> begin
            connect_err[] = err
            connect_done[] = true
            return nothing
        end,
    )
    @test Reseau.socket_connect(client, connect_opts) === nothing
    @test wait_for(() -> connect_done[] && accept_done[])
    @test connect_err[] == Reseau.AWS_OP_SUCCESS
    @test accept_err[] == Reseau.AWS_OP_SUCCESS

    read_done = Ref(false)
    read_err = Ref(0)
    read_payload = Ref("")
    subscribe_done = Ref(false)
    subscribe_task = Reseau.ScheduledTask((ctx, status) -> begin
        status == Reseau.TaskStatus.RUN_READY || return nothing
        res = Reseau.socket_subscribe_to_readable_events(client, (sock, err, ud) -> begin
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
                read_payload[] = String(Reseau.byte_cursor_from_buf(buf))
            end
            read_done[] = true
            return nothing
        end, nothing)
        if res isa Reseau.ErrorResult
            read_err[] = res.code
            read_done[] = true
        end
        subscribe_done[] = true
        return nothing
    end, nothing; type_tag = "client_subscribe")
    Reseau.event_loop_schedule_task_now!(event_loop, subscribe_task)
    @test wait_for(() -> subscribe_done[])

    channel = channel_ref[]
    app_slot = app_slot_ref[]
    socket_handler = socket_handler_ref[]
    @test channel isa Reseau.Channel
    @test app_slot isa Reseau.ChannelSlot
    @test socket_handler isa Reseau.SocketChannelHandler
    if !(channel isa Reseau.Channel && app_slot isa Reseau.ChannelSlot && socket_handler isa Reseau.SocketChannelHandler)
        Reseau.event_loop_group_destroy!(elg)
        return
    end
    if accepted_socket[] isa Reseau.Socket
        @test socket_handler.socket === accepted_socket[]
        @test socket_handler.socket.handler === socket_handler
    end

    send_done = Ref(false)
    send_err = Ref(0)
    payload = "hello"
    send_task = Reseau.ChannelTask((task, arg, status) -> begin
        status == Reseau.TaskStatus.RUN_READY || return nothing
        msg = Reseau.channel_acquire_message_from_pool(channel, Reseau.IoMessageType.APPLICATION_DATA, length(payload))
        if msg === nothing
            send_err[] = Reseau.ERROR_OOM
            send_done[] = true
            return nothing
        end
        msg_ref = Ref(msg.message_data)
        ok = Reseau.byte_buf_write_from_whole_cursor(msg_ref, Reseau.ByteCursor(payload))
        msg.message_data = msg_ref[]
        if !ok || msg.message_data.len != Csize_t(length(payload))
            send_err[] = Reseau.ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT
            send_done[] = true
            return nothing
        end
        msg.on_completion = (ch, message, err, ud) -> begin
            send_err[] = err
            send_done[] = true
            return nothing
        end
        res = Reseau.channel_slot_send_message(app_slot, msg, Reseau.ChannelDirection.WRITE)
        if res isa Reseau.ErrorResult
            send_err[] = res.code
            send_done[] = true
        end
        return nothing
    end, nothing, "socket_handler_send")
    Reseau.channel_schedule_task_now!(channel, send_task)

    @test wait_for(() -> send_done[])
    @test send_err[] == Reseau.AWS_OP_SUCCESS
    @test wait_for(() -> read_done[])
    @test read_err[] == Reseau.AWS_OP_SUCCESS
    @test read_payload[] == payload

    if accepted_socket[] isa Reseau.Socket
        Reseau.socket_close(accepted_socket[])
    end
    Reseau.socket_close(client)
    Reseau.socket_close(server)
    Reseau.event_loop_group_destroy!(elg)
end

@testset "socket handler pending read before downstream setup" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    @static if Sys.isapple()
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.LOCAL)
    else
        opts = Reseau.SocketOptions(; type = Reseau.SocketType.STREAM, domain = Reseau.SocketDomain.IPV4)
    end
    server = Reseau.socket_init(opts)
    @test server isa Reseau.Socket
    if server isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    @static if Sys.isapple()
        bind_endpoint = Reseau.SocketEndpoint()
        Reseau.socket_endpoint_init_local_address_for_test!(bind_endpoint)
        connect_endpoint = bind_endpoint
    else
        bind_endpoint = Reseau.SocketEndpoint("127.0.0.1", 0)
    end
    bind_opts = Reseau.SocketBindOptions(bind_endpoint)
    @test Reseau.socket_bind(server, bind_opts) === nothing
    @test Reseau.socket_listen(server, 8) === nothing
    @static if !Sys.isapple()
        bound = Reseau.socket_get_bound_address(server)
        @test bound isa Reseau.SocketEndpoint
        port = bound isa Reseau.SocketEndpoint ? bound.port : 0
        @test port > 0
        connect_endpoint = Reseau.SocketEndpoint("127.0.0.1", port)
    end

    accept_done = Ref(false)
    accept_err = Ref(0)
    accepted_socket = Ref{Any}(nothing)
    channel_ref = Ref{Any}(nothing)
    socket_handler_ref = Ref{Any}(nothing)

    on_accept = (listener, err, new_sock, ud) -> begin
        accept_err[] = err
        if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
            accept_done[] = true
            return nothing
        end
        Reseau.socket_assign_to_event_loop(new_sock, event_loop)
        channel = Reseau.Channel(event_loop; enable_read_back_pressure = false)
        handler = Reseau.socket_channel_handler_new!(channel, new_sock; max_read_size = 16)
        if handler isa Reseau.ErrorResult
            accept_done[] = true
            return nothing
        end
        accepted_socket[] = new_sock
        channel_ref[] = channel
        socket_handler_ref[] = handler
        accept_done[] = true
        return nothing
    end

    accept_opts = Reseau.SocketListenerOptions(on_accept_result = on_accept)
    @test Reseau.socket_start_accept(server, event_loop, accept_opts) === nothing

    client = Reseau.socket_init(opts)
    @test client isa Reseau.Socket
    if client isa Reseau.ErrorResult
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    connect_done = Ref(false)
    connect_err = Ref(0)
    connect_opts = Reseau.SocketConnectOptions(
        connect_endpoint;
        event_loop = event_loop,
        on_connection_result = (sock, err, ud) -> begin
            connect_err[] = err
            connect_done[] = true
            return nothing
        end,
    )
    @test Reseau.socket_connect(client, connect_opts) === nothing
    @test wait_for(() -> connect_done[] && accept_done[])
    @test connect_err[] == Reseau.AWS_OP_SUCCESS
    @test accept_err[] == Reseau.AWS_OP_SUCCESS

    socket_handler = socket_handler_ref[]
    @test socket_handler isa Reseau.SocketChannelHandler
    if !(socket_handler isa Reseau.SocketChannelHandler)
        Reseau.event_loop_group_destroy!(elg)
        return
    end

    write_done = Ref(false)
    write_err = Ref(Reseau.AWS_OP_SUCCESS)

    payload = "pending"
    cursor = Reseau.ByteCursor(payload)

    write_task = Reseau.ScheduledTask((ctx, status) -> begin
        status == Reseau.TaskStatus.RUN_READY || return nothing
        res = Reseau.socket_write(client, cursor, (sock, err, num_bytes, ud) -> begin
            write_err[] = err
            write_done[] = true
            return nothing
        end, nothing)
        if res isa Reseau.ErrorResult
            write_err[] = res.code
            write_done[] = true
        end
        return nothing
    end, nothing; type_tag = "client_write_pending")
    Reseau.event_loop_schedule_task_now!(event_loop, write_task)

    @test wait_for(() -> write_done[])
    @test write_err[] == Reseau.AWS_OP_SUCCESS
    @test wait_for(() -> socket_handler.pending_read)

    channel_any = channel_ref[]
    @test channel_any isa Reseau.Channel
    if !(channel_any isa Reseau.Channel)
        Reseau.event_loop_group_destroy!(elg)
        return
    end
    channel = channel_any::Reseau.Channel

    setup_done = Ref(false)
    setup_err = Ref(0)
    app_handler_ref = Ref{Any}(nothing)

    setup_task = Reseau.ChannelTask((task, arg, status) -> begin
        status == Reseau.TaskStatus.RUN_READY || return nothing
        ch = arg::Reseau.Channel

        app_handler = TestReadHandler(64)
        app_slot = Reseau.channel_slot_new!(ch)
        if Reseau.channel_first_slot(ch) !== app_slot
            insert_res = Reseau.channel_slot_insert_end!(ch, app_slot)
            if insert_res isa Reseau.ErrorResult
                setup_err[] = insert_res.code
                setup_done[] = true
                return nothing
            end
        end

        set_res = Reseau.channel_slot_set_handler!(app_slot, app_handler)
        if set_res isa Reseau.ErrorResult
            setup_err[] = set_res.code
            setup_done[] = true
            return nothing
        end
        app_handler.slot = app_slot

        res = Reseau.channel_setup_complete!(ch)
        setup_err[] = res isa Reseau.ErrorResult ? res.code : Reseau.AWS_OP_SUCCESS
        app_handler_ref[] = app_handler
        setup_done[] = true
        return nothing
    end, channel, "setup_downstream")
    Reseau.channel_schedule_task_now!(channel, setup_task)

    @test wait_for(() -> setup_done[])
    @test setup_err[] == Reseau.AWS_OP_SUCCESS

    app_handler = app_handler_ref[]
    @test app_handler isa TestReadHandler
    if !(app_handler isa TestReadHandler)
        Reseau.event_loop_group_destroy!(elg)
        return
    end
    @test wait_for(() -> _received_string(app_handler::TestReadHandler) == payload)

    if client isa Reseau.Socket
        Reseau.socket_close(client)
    end
    if accepted_socket[] !== nothing
        Reseau.socket_close(accepted_socket[])
    end
    if server isa Reseau.Socket
        Reseau.socket_close(server)
    end
    Reseau.event_loop_group_destroy!(elg)
end
