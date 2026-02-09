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

mutable struct TestReadHandler <: Sockets.AbstractChannelHandler
    slot::Union{Sockets.ChannelSlot, Nothing}
    received::Vector{UInt8}
    lock::ReentrantLock
    auto_increment::Bool
    initial_window_size::Csize_t
end

function TestReadHandler(initial_window_size::Integer; auto_increment::Bool = false)
    return TestReadHandler(nothing, UInt8[], ReentrantLock(), auto_increment, Csize_t(initial_window_size))
end

function Sockets.handler_process_read_message(handler::TestReadHandler, slot::Sockets.ChannelSlot, message::EventLoops.IoMessage)
    payload = String(Reseau.byte_cursor_from_buf(message.message_data))
    # Handlers run on event-loop threads; tests may read `received` from the main thread.
    lock(handler.lock) do
        append!(handler.received, codeunits(payload))
    end

    if handler.auto_increment
        Sockets.channel_slot_increment_read_window!(slot, message.message_data.len)
    end

    if slot.channel !== nothing
        Sockets.channel_release_message_to_pool!(slot.channel, message)
    end
    return nothing
end

function Sockets.handler_process_write_message(handler::TestReadHandler, slot::Sockets.ChannelSlot, message::EventLoops.IoMessage)
    return Sockets.channel_slot_send_message(slot, message, Sockets.ChannelDirection.WRITE)
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

function Sockets.handler_increment_read_window(handler::TestReadHandler, slot::Sockets.ChannelSlot, size::Csize_t)
    return Sockets.channel_slot_increment_read_window!(slot, size)
end

function Sockets.handler_shutdown(
        handler::TestReadHandler,
        slot::Sockets.ChannelSlot,
        direction::Sockets.ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )
    Sockets.channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    return nothing
end

Sockets.handler_initial_window_size(handler::TestReadHandler) = handler.initial_window_size
Sockets.handler_message_overhead(::TestReadHandler) = Csize_t(0)
Sockets.handler_destroy(::TestReadHandler) = nothing

@testset "socket handler read backpressure" begin
    elg = EventLoops.EventLoopGroup(EventLoops.EventLoopGroupOptions(; loop_count = 1))
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
    if server isa Reseau.ErrorResult
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

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
    channel_ref = Ref{Any}(nothing)
    socket_handler_ref = Ref{Any}(nothing)
    app_handler_ref = Ref{Any}(nothing)

    on_accept = (listener, err, new_sock, ud) -> begin
        accept_err[] = err
        if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
            accept_done[] = true
            return nothing
        end
        Sockets.socket_assign_to_event_loop(new_sock, event_loop)
        channel = Sockets.Channel(event_loop; enable_read_back_pressure = true)
        handler = Sockets.socket_channel_handler_new!(channel, new_sock; max_read_size = 4)
        if handler isa Reseau.ErrorResult
            accept_done[] = true
            return nothing
        end

        app_handler = TestReadHandler(4; auto_increment = false)
        app_slot = Sockets.channel_slot_new!(channel)
        if Sockets.channel_first_slot(channel) !== app_slot
            Sockets.channel_slot_insert_end!(channel, app_slot)
        end
        Sockets.channel_slot_set_handler!(app_slot, app_handler)
        app_handler.slot = app_slot

        Sockets.channel_setup_complete!(channel)

        # Ensure deterministic window size for backpressure checks
        if channel.window_update_task.wrapper_task.scheduled
            EventLoops.event_loop_cancel_task!(event_loop, channel.window_update_task.wrapper_task)
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

    accept_opts = Sockets.SocketListenerOptions(on_accept_result = on_accept)
    @test Sockets.socket_start_accept(server, event_loop, accept_opts) === nothing

    client = Sockets.socket_init(opts)
    @test client isa Sockets.Socket
    if client isa Reseau.ErrorResult
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    connect_done = Ref(false)
    connect_err = Ref(0)
    connect_opts = Sockets.SocketConnectOptions(
        connect_endpoint;
        event_loop = event_loop,
        on_connection_result = (sock, err, ud) -> begin
            connect_err[] = err
            connect_done[] = true
            return nothing
        end,
    )
    @test Sockets.socket_connect(client, connect_opts) === nothing
    @test wait_for(() -> connect_done[] && accept_done[])
    @test connect_err[] == Reseau.AWS_OP_SUCCESS
    @test accept_err[] == Reseau.AWS_OP_SUCCESS

    app_handler = app_handler_ref[]
    @test app_handler isa TestReadHandler
    if !(app_handler isa TestReadHandler)
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    write_done = Ref(false)
    write_err = Ref(Reseau.AWS_OP_SUCCESS)
    write_bytes = Ref(0)

    payload = "abcdefghij"
    cursor = Reseau.ByteCursor(payload)

    write_task = Threads.ScheduledTask((ctx, status) -> begin
        status == Threads.TaskStatus.RUN_READY || return nothing
        res = Sockets.socket_write(client, cursor, (sock, err, num_bytes, ud) -> begin
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
    EventLoops.event_loop_schedule_task_now!(event_loop, write_task)

    @test wait_for(() -> write_done[])
    @test write_err[] == Reseau.AWS_OP_SUCCESS
    @test write_bytes[] == ncodeunits(payload)

    channel = channel_ref[]
    socket_handler = socket_handler_ref[]
    @test channel isa Sockets.Channel
    @test socket_handler isa Sockets.SocketChannelHandler
    if !(channel isa Sockets.Channel && socket_handler isa Sockets.SocketChannelHandler)
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    trigger_done = Ref(false)
    trigger_task = Sockets.ChannelTask((task, arg, status) -> begin
        status == Threads.TaskStatus.RUN_READY || return nothing
        Sockets.channel_trigger_read(channel)
        trigger_done[] = true
        return nothing
    end, nothing, "socket_handler_trigger_read")
    Sockets.channel_schedule_task_now!(channel, trigger_task)
    @test wait_for(() -> trigger_done[])

    @test wait_for(() -> _received_len(app_handler) >= 4)
    @test _received_len(app_handler) == 4

    update_done = Ref(false)
    update_task = Sockets.ChannelTask((task, arg, status) -> begin
        status == Threads.TaskStatus.RUN_READY || return nothing
        app_handler.slot.window_size = app_handler.slot.window_size + Csize_t(6)
        Sockets.handler_increment_read_window(socket_handler, socket_handler.slot, Csize_t(6))
        update_done[] = true
        return nothing
    end, nothing, "window_update")
    Sockets.channel_schedule_task_now!(channel, update_task)
    @test wait_for(() -> update_done[])

    @test wait_for(() -> _received_len(app_handler) == 10)

    if accepted_socket[] isa Sockets.Socket
        Sockets.socket_close(accepted_socket[])
    end
    Sockets.socket_close(client)
    Sockets.socket_close(server)
    EventLoops.event_loop_group_destroy!(elg)
end

@testset "socket handler write completion" begin
    elg = EventLoops.EventLoopGroup(EventLoops.EventLoopGroupOptions(; loop_count = 1))
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
    if server isa Reseau.ErrorResult
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

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
    channel_ref = Ref{Any}(nothing)
    app_slot_ref = Ref{Any}(nothing)
    socket_handler_ref = Ref{Any}(nothing)

    on_accept = (listener, err, new_sock, ud) -> begin
        accept_err[] = err
        if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
            accept_done[] = true
            return nothing
        end
        Sockets.socket_assign_to_event_loop(new_sock, event_loop)
        channel = Sockets.Channel(event_loop; enable_read_back_pressure = false)
        socket_handler = Sockets.socket_channel_handler_new!(channel, new_sock)
        if socket_handler isa Reseau.ErrorResult
            accept_done[] = true
            return nothing
        end

        app_slot = Sockets.channel_slot_new!(channel)
        if Sockets.channel_first_slot(channel) !== app_slot
            Sockets.channel_slot_insert_end!(channel, app_slot)
        end
        Sockets.channel_slot_set_handler!(app_slot, Sockets.PassthroughHandler())

        Sockets.channel_setup_complete!(channel)

        accepted_socket[] = new_sock
        channel_ref[] = channel
        app_slot_ref[] = app_slot
        socket_handler_ref[] = socket_handler
        accept_done[] = true
        return nothing
    end

    accept_opts = Sockets.SocketListenerOptions(on_accept_result = on_accept)
    @test Sockets.socket_start_accept(server, event_loop, accept_opts) === nothing

    client = Sockets.socket_init(opts)
    @test client isa Sockets.Socket
    if client isa Reseau.ErrorResult
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    connect_done = Ref(false)
    connect_err = Ref(0)
    connect_opts = Sockets.SocketConnectOptions(
        connect_endpoint;
        event_loop = event_loop,
        on_connection_result = (sock, err, ud) -> begin
            connect_err[] = err
            connect_done[] = true
            return nothing
        end,
    )
    @test Sockets.socket_connect(client, connect_opts) === nothing
    @test wait_for(() -> connect_done[] && accept_done[])
    @test connect_err[] == Reseau.AWS_OP_SUCCESS
    @test accept_err[] == Reseau.AWS_OP_SUCCESS

    read_done = Ref(false)
    read_err = Ref(0)
    read_payload = Ref("")
    subscribe_done = Ref(false)
    subscribe_task = Threads.ScheduledTask((ctx, status) -> begin
        status == Threads.TaskStatus.RUN_READY || return nothing
        res = Sockets.socket_subscribe_to_readable_events(client, (sock, err, ud) -> begin
            read_err[] = err
            if err != Reseau.AWS_OP_SUCCESS
                read_done[] = true
                return nothing
            end
            buf = Reseau.ByteBuffer(64)
            read_res = Sockets.socket_read(sock, buf)
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
    EventLoops.event_loop_schedule_task_now!(event_loop, subscribe_task)
    @test wait_for(() -> subscribe_done[])

    channel = channel_ref[]
    app_slot = app_slot_ref[]
    socket_handler = socket_handler_ref[]
    @test channel isa Sockets.Channel
    @test app_slot isa Sockets.ChannelSlot
    @test socket_handler isa Sockets.SocketChannelHandler
    if !(channel isa Sockets.Channel && app_slot isa Sockets.ChannelSlot && socket_handler isa Sockets.SocketChannelHandler)
        EventLoops.event_loop_group_destroy!(elg)
        return
    end
    if accepted_socket[] isa Sockets.Socket
        @test socket_handler.socket === accepted_socket[]
        @test socket_handler.socket.handler === socket_handler
    end

    send_done = Ref(false)
    send_err = Ref(0)
    payload = "hello"
    send_task = Sockets.ChannelTask((task, arg, status) -> begin
        status == Threads.TaskStatus.RUN_READY || return nothing
        msg = Sockets.channel_acquire_message_from_pool(channel, EventLoops.IoMessageType.APPLICATION_DATA, length(payload))
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
        msg.on_completion = (ch, message, err, ud) -> begin
            send_err[] = err
            send_done[] = true
            return nothing
        end
        res = Sockets.channel_slot_send_message(app_slot, msg, Sockets.ChannelDirection.WRITE)
        if res isa Reseau.ErrorResult
            send_err[] = res.code
            send_done[] = true
        end
        return nothing
    end, nothing, "socket_handler_send")
    Sockets.channel_schedule_task_now!(channel, send_task)

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
    elg = EventLoops.EventLoopGroup(EventLoops.EventLoopGroupOptions(; loop_count = 1))
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
    if server isa Reseau.ErrorResult
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

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
    channel_ref = Ref{Any}(nothing)
    socket_handler_ref = Ref{Any}(nothing)

    on_accept = (listener, err, new_sock, ud) -> begin
        accept_err[] = err
        if err != Reseau.AWS_OP_SUCCESS || new_sock === nothing
            accept_done[] = true
            return nothing
        end
        Sockets.socket_assign_to_event_loop(new_sock, event_loop)
        channel = Sockets.Channel(event_loop; enable_read_back_pressure = false)
        handler = Sockets.socket_channel_handler_new!(channel, new_sock; max_read_size = 16)
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

    accept_opts = Sockets.SocketListenerOptions(on_accept_result = on_accept)
    @test Sockets.socket_start_accept(server, event_loop, accept_opts) === nothing

    client = Sockets.socket_init(opts)
    @test client isa Sockets.Socket
    if client isa Reseau.ErrorResult
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    connect_done = Ref(false)
    connect_err = Ref(0)
    connect_opts = Sockets.SocketConnectOptions(
        connect_endpoint;
        event_loop = event_loop,
        on_connection_result = (sock, err, ud) -> begin
            connect_err[] = err
            connect_done[] = true
            return nothing
        end,
    )
    @test Sockets.socket_connect(client, connect_opts) === nothing
    @test wait_for(() -> connect_done[] && accept_done[])
    @test connect_err[] == Reseau.AWS_OP_SUCCESS
    @test accept_err[] == Reseau.AWS_OP_SUCCESS

    socket_handler = socket_handler_ref[]
    @test socket_handler isa Sockets.SocketChannelHandler
    if !(socket_handler isa Sockets.SocketChannelHandler)
        EventLoops.event_loop_group_destroy!(elg)
        return
    end

    write_done = Ref(false)
    write_err = Ref(Reseau.AWS_OP_SUCCESS)

    payload = "pending"
    cursor = Reseau.ByteCursor(payload)

    write_task = Threads.ScheduledTask((ctx, status) -> begin
        status == Threads.TaskStatus.RUN_READY || return nothing
        res = Sockets.socket_write(client, cursor, (sock, err, num_bytes, ud) -> begin
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
    EventLoops.event_loop_schedule_task_now!(event_loop, write_task)

    @test wait_for(() -> write_done[])
    @test write_err[] == Reseau.AWS_OP_SUCCESS
    @test wait_for(() -> socket_handler.pending_read)

    channel_any = channel_ref[]
    @test channel_any isa Sockets.Channel
    if !(channel_any isa Sockets.Channel)
        EventLoops.event_loop_group_destroy!(elg)
        return
    end
    channel = channel_any::Sockets.Channel

    setup_done = Ref(false)
    setup_err = Ref(0)
    app_handler_ref = Ref{Any}(nothing)

    setup_task = Sockets.ChannelTask((task, arg, status) -> begin
        status == Threads.TaskStatus.RUN_READY || return nothing
        ch = arg::Sockets.Channel

        app_handler = TestReadHandler(64)
        app_slot = Sockets.channel_slot_new!(ch)
        if Sockets.channel_first_slot(ch) !== app_slot
            insert_res = Sockets.channel_slot_insert_end!(ch, app_slot)
            if insert_res isa Reseau.ErrorResult
                setup_err[] = insert_res.code
                setup_done[] = true
                return nothing
            end
        end

        set_res = Sockets.channel_slot_set_handler!(app_slot, app_handler)
        if set_res isa Reseau.ErrorResult
            setup_err[] = set_res.code
            setup_done[] = true
            return nothing
        end
        app_handler.slot = app_slot

        res = Sockets.channel_setup_complete!(ch)
        setup_err[] = res isa Reseau.ErrorResult ? res.code : Reseau.AWS_OP_SUCCESS
        app_handler_ref[] = app_handler
        setup_done[] = true
        return nothing
    end, channel, "setup_downstream")
    Sockets.channel_schedule_task_now!(channel, setup_task)

    @test wait_for(() -> setup_done[])
    @test setup_err[] == Reseau.AWS_OP_SUCCESS

    app_handler = app_handler_ref[]
    @test app_handler isa TestReadHandler
    if !(app_handler isa TestReadHandler)
        EventLoops.event_loop_group_destroy!(elg)
        return
    end
    @test wait_for(() -> _received_string(app_handler::TestReadHandler) == payload)

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
