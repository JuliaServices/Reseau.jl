using Test
using AwsIO

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

mutable struct TestReadHandler <: AwsIO.AbstractChannelHandler
    slot::Union{AwsIO.ChannelSlot, Nothing}
    received::Vector{UInt8}
    auto_increment::Bool
    initial_window_size::Csize_t
end

function TestReadHandler(initial_window_size::Integer; auto_increment::Bool = false)
    return TestReadHandler(nothing, UInt8[], auto_increment, Csize_t(initial_window_size))
end

function AwsIO.handler_process_read_message(handler::TestReadHandler, slot::AwsIO.ChannelSlot, message::AwsIO.IoMessage)
    payload = String(AwsIO.byte_cursor_from_buf(message.message_data))
    append!(handler.received, codeunits(payload))

    if handler.auto_increment
        AwsIO.channel_slot_increment_read_window!(slot, message.message_data.len)
    end

    if slot.channel !== nothing
        AwsIO.channel_release_message_to_pool!(slot.channel, message)
    end
    return nothing
end

function AwsIO.handler_process_write_message(handler::TestReadHandler, slot::AwsIO.ChannelSlot, message::AwsIO.IoMessage)
    return AwsIO.channel_slot_send_message(slot, message, AwsIO.ChannelDirection.WRITE)
end

function AwsIO.handler_increment_read_window(handler::TestReadHandler, slot::AwsIO.ChannelSlot, size::Csize_t)
    return AwsIO.channel_slot_increment_read_window!(slot, size)
end

function AwsIO.handler_shutdown(
        handler::TestReadHandler,
        slot::AwsIO.ChannelSlot,
        direction::AwsIO.ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )
    AwsIO.channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    return nothing
end

AwsIO.handler_initial_window_size(handler::TestReadHandler) = handler.initial_window_size
AwsIO.handler_message_overhead(::TestReadHandler) = Csize_t(0)
AwsIO.handler_destroy(::TestReadHandler) = nothing

@testset "socket handler read backpressure" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4)
    server = AwsIO.socket_init(opts)
    @test server isa AwsIO.Socket
    if server isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    bind_opts = AwsIO.SocketBindOptions(AwsIO.SocketEndpoint("127.0.0.1", 0))
    @test AwsIO.socket_bind(server, bind_opts) === nothing
    @test AwsIO.socket_listen(server, 8) === nothing
    bound = AwsIO.socket_get_bound_address(server)
    @test bound isa AwsIO.SocketEndpoint
    port = bound isa AwsIO.SocketEndpoint ? bound.port : 0
    @test port > 0

    accept_done = Ref(false)
    accept_err = Ref(0)
    accepted_socket = Ref{Any}(nothing)
    channel_ref = Ref{Any}(nothing)
    socket_handler_ref = Ref{Any}(nothing)
    app_handler_ref = Ref{Any}(nothing)

    on_accept = (listener, err, new_sock, ud) -> begin
        accept_err[] = err
        if err != AwsIO.AWS_OP_SUCCESS || new_sock === nothing
            accept_done[] = true
            return nothing
        end
        AwsIO.socket_assign_to_event_loop(new_sock, event_loop)
        channel = AwsIO.Channel(event_loop; enable_read_back_pressure = true)
        handler = AwsIO.socket_channel_handler_new!(channel, new_sock; max_read_size = 4)
        if handler isa AwsIO.ErrorResult
            accept_done[] = true
            return nothing
        end

        app_handler = TestReadHandler(4; auto_increment = false)
        app_slot = AwsIO.channel_slot_new!(channel)
        if AwsIO.channel_first_slot(channel) !== app_slot
            AwsIO.channel_slot_insert_end!(channel, app_slot)
        end
        AwsIO.channel_slot_set_handler!(app_slot, app_handler)
        app_handler.slot = app_slot

        AwsIO.channel_setup_complete!(channel)

        # Ensure deterministic window size for backpressure checks
        if channel.window_update_task.wrapper_task.scheduled
            AwsIO.event_loop_cancel_task!(event_loop, channel.window_update_task.wrapper_task)
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

    accept_opts = AwsIO.SocketListenerOptions(on_accept_result = on_accept)
    @test AwsIO.socket_start_accept(server, event_loop, accept_opts) === nothing

    client = AwsIO.socket_init(opts)
    @test client isa AwsIO.Socket
    if client isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    connect_done = Ref(false)
    connect_err = Ref(0)
    connect_opts = AwsIO.SocketConnectOptions(
        AwsIO.SocketEndpoint("127.0.0.1", port);
        event_loop = event_loop,
        on_connection_result = (sock, err, ud) -> begin
            connect_err[] = err
            connect_done[] = true
            return nothing
        end,
    )
    @test AwsIO.socket_connect(client, connect_opts) === nothing
    @test wait_for(() -> connect_done[] && accept_done[])
    @test connect_err[] == AwsIO.AWS_OP_SUCCESS
    @test accept_err[] == AwsIO.AWS_OP_SUCCESS

    app_handler = app_handler_ref[]
    @test app_handler isa TestReadHandler
    if !(app_handler isa TestReadHandler)
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    write_err = Ref(0)
    payload = "abcdefghij"
    bytes = Vector{UInt8}(codeunits(payload))
    offset = 0
    while offset < length(bytes)
        sent = ccall(
            :send, Cssize_t, (Cint, Ptr{UInt8}, Csize_t, Cint),
            client.io_handle.fd, pointer(bytes, offset + 1), length(bytes) - offset, AwsIO.NO_SIGNAL_SEND
        )
        if sent < 0
            errno_val = AwsIO.get_errno()
            if errno_val == AwsIO.EAGAIN || errno_val == AwsIO.EWOULDBLOCK
                sleep(0.01)
                continue
            end
            write_err[] = AwsIO.determine_socket_error(errno_val)
            break
        end
        offset += sent
    end
    @test write_err[] == AwsIO.AWS_OP_SUCCESS

    channel = channel_ref[]
    socket_handler = socket_handler_ref[]
    @test channel isa AwsIO.Channel
    @test socket_handler isa AwsIO.SocketChannelHandler
    if !(channel isa AwsIO.Channel && socket_handler isa AwsIO.SocketChannelHandler)
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    trigger_done = Ref(false)
    trigger_task = AwsIO.ChannelTask((task, arg, status) -> begin
        status == AwsIO.TaskStatus.RUN_READY || return nothing
        AwsIO.channel_trigger_read(channel)
        trigger_done[] = true
        return nothing
    end, nothing, "socket_handler_trigger_read")
    AwsIO.channel_schedule_task_now!(channel, trigger_task)
    @test wait_for(() -> trigger_done[])

    @test wait_for(() -> length(app_handler.received) >= 4)
    @test length(app_handler.received) == 4

    update_done = Ref(false)
    update_task = AwsIO.ChannelTask((task, arg, status) -> begin
        status == AwsIO.TaskStatus.RUN_READY || return nothing
        app_handler.slot.window_size = app_handler.slot.window_size + Csize_t(6)
        AwsIO.handler_increment_read_window(socket_handler, socket_handler.slot, Csize_t(6))
        update_done[] = true
        return nothing
    end, nothing, "window_update")
    AwsIO.channel_schedule_task_now!(channel, update_task)
    @test wait_for(() -> update_done[])

    @test wait_for(() -> length(app_handler.received) == 10)

    if accepted_socket[] isa AwsIO.Socket
        AwsIO.socket_close(accepted_socket[])
    end
    AwsIO.socket_close(client)
    AwsIO.socket_close(server)
    AwsIO.event_loop_group_destroy!(elg)
end

@testset "socket handler write completion" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    event_loop = AwsIO.event_loop_group_get_next_loop(elg)
    @test event_loop !== nothing
    if event_loop === nothing
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4)
    server = AwsIO.socket_init(opts)
    @test server isa AwsIO.Socket
    if server isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    bind_opts = AwsIO.SocketBindOptions(AwsIO.SocketEndpoint("127.0.0.1", 0))
    @test AwsIO.socket_bind(server, bind_opts) === nothing
    @test AwsIO.socket_listen(server, 8) === nothing
    bound = AwsIO.socket_get_bound_address(server)
    @test bound isa AwsIO.SocketEndpoint
    port = bound isa AwsIO.SocketEndpoint ? bound.port : 0
    @test port > 0

    accept_done = Ref(false)
    accept_err = Ref(0)
    accepted_socket = Ref{Any}(nothing)
    channel_ref = Ref{Any}(nothing)
    app_slot_ref = Ref{Any}(nothing)
    socket_handler_ref = Ref{Any}(nothing)

    on_accept = (listener, err, new_sock, ud) -> begin
        accept_err[] = err
        if err != AwsIO.AWS_OP_SUCCESS || new_sock === nothing
            accept_done[] = true
            return nothing
        end
        AwsIO.socket_assign_to_event_loop(new_sock, event_loop)
        channel = AwsIO.Channel(event_loop; enable_read_back_pressure = false)
        socket_handler = AwsIO.socket_channel_handler_new!(channel, new_sock)
        if socket_handler isa AwsIO.ErrorResult
            accept_done[] = true
            return nothing
        end

        app_slot = AwsIO.channel_slot_new!(channel)
        if AwsIO.channel_first_slot(channel) !== app_slot
            AwsIO.channel_slot_insert_end!(channel, app_slot)
        end
        AwsIO.channel_slot_set_handler!(app_slot, AwsIO.PassthroughHandler())

        AwsIO.channel_setup_complete!(channel)

        accepted_socket[] = new_sock
        channel_ref[] = channel
        app_slot_ref[] = app_slot
        socket_handler_ref[] = socket_handler
        accept_done[] = true
        return nothing
    end

    accept_opts = AwsIO.SocketListenerOptions(on_accept_result = on_accept)
    @test AwsIO.socket_start_accept(server, event_loop, accept_opts) === nothing

    client = AwsIO.socket_init(opts)
    @test client isa AwsIO.Socket
    if client isa AwsIO.ErrorResult
        AwsIO.event_loop_group_destroy!(elg)
        return
    end

    connect_done = Ref(false)
    connect_err = Ref(0)
    connect_opts = AwsIO.SocketConnectOptions(
        AwsIO.SocketEndpoint("127.0.0.1", port);
        event_loop = event_loop,
        on_connection_result = (sock, err, ud) -> begin
            connect_err[] = err
            connect_done[] = true
            return nothing
        end,
    )
    @test AwsIO.socket_connect(client, connect_opts) === nothing
    @test wait_for(() -> connect_done[] && accept_done[])
    @test connect_err[] == AwsIO.AWS_OP_SUCCESS
    @test accept_err[] == AwsIO.AWS_OP_SUCCESS

    read_done = Ref(false)
    read_err = Ref(0)
    read_payload = Ref("")
    subscribe_done = Ref(false)
    subscribe_task = AwsIO.ScheduledTask((ctx, status) -> begin
        status == AwsIO.TaskStatus.RUN_READY || return nothing
        res = AwsIO.socket_subscribe_to_readable_events(client, (sock, err, ud) -> begin
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
                read_payload[] = String(AwsIO.byte_cursor_from_buf(buf))
            end
            read_done[] = true
            return nothing
        end, nothing)
        if res isa AwsIO.ErrorResult
            read_err[] = res.code
            read_done[] = true
        end
        subscribe_done[] = true
        return nothing
    end, nothing; type_tag = "client_subscribe")
    AwsIO.event_loop_schedule_task_now!(event_loop, subscribe_task)
    @test wait_for(() -> subscribe_done[])

    channel = channel_ref[]
    app_slot = app_slot_ref[]
    socket_handler = socket_handler_ref[]
    @test channel isa AwsIO.Channel
    @test app_slot isa AwsIO.ChannelSlot
    @test socket_handler isa AwsIO.SocketChannelHandler
    if !(channel isa AwsIO.Channel && app_slot isa AwsIO.ChannelSlot && socket_handler isa AwsIO.SocketChannelHandler)
        AwsIO.event_loop_group_destroy!(elg)
        return
    end
    if accepted_socket[] isa AwsIO.Socket
        @test socket_handler.socket === accepted_socket[]
        @test socket_handler.socket.handler === socket_handler
    end

    send_done = Ref(false)
    send_err = Ref(0)
    payload = "hello"
    send_task = AwsIO.ChannelTask((task, arg, status) -> begin
        status == AwsIO.TaskStatus.RUN_READY || return nothing
        msg = AwsIO.channel_acquire_message_from_pool(channel, AwsIO.IoMessageType.APPLICATION_DATA, length(payload))
        if msg === nothing
            send_err[] = AwsIO.ERROR_OOM
            send_done[] = true
            return nothing
        end
        msg_ref = Ref(msg.message_data)
        ok = AwsIO.byte_buf_write_from_whole_cursor(msg_ref, AwsIO.ByteCursor(payload))
        msg.message_data = msg_ref[]
        if !ok || msg.message_data.len != Csize_t(length(payload))
            send_err[] = AwsIO.ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT
            send_done[] = true
            return nothing
        end
        msg.on_completion = (ch, message, err, ud) -> begin
            send_err[] = err
            send_done[] = true
            return nothing
        end
        res = AwsIO.channel_slot_send_message(app_slot, msg, AwsIO.ChannelDirection.WRITE)
        if res isa AwsIO.ErrorResult
            send_err[] = res.code
            send_done[] = true
        end
        return nothing
    end, nothing, "socket_handler_send")
    AwsIO.channel_schedule_task_now!(channel, send_task)

    @test wait_for(() -> send_done[])
    @test send_err[] == AwsIO.AWS_OP_SUCCESS
    @test wait_for(() -> read_done[])
    @test read_err[] == AwsIO.AWS_OP_SUCCESS
    @test read_payload[] == payload

    if accepted_socket[] isa AwsIO.Socket
        AwsIO.socket_close(accepted_socket[])
    end
    AwsIO.socket_close(client)
    AwsIO.socket_close(server)
    AwsIO.event_loop_group_destroy!(elg)
end
