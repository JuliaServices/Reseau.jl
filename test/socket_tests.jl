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
    server = AwsIO.socket_init_posix(opts)
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

        client = AwsIO.socket_init_posix(opts)
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
