using Test
using AwsIO
using MbedTLS
using Sockets

function wait_for_flag_tls(flag::Base.RefValue{Bool}; timeout_s::Float64 = 5.0)
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

@testset "tls handler" begin
    cert_path = joinpath(@__DIR__, "..", "aws-c-io", "tests", "resources", "unittests.crt")
    key_path = joinpath(@__DIR__, "..", "aws-c-io", "tests", "resources", "unittests.key")
    @test isfile(cert_path)
    @test isfile(key_path)

    server = Sockets.listen(ip"127.0.0.1", 0)
    port = Sockets.getsockname(server)[2]
    server_error = Ref{Any}(nothing)

    server_task = @async begin
        try
            sock = accept(server)
            conf = MbedTLS.SSLConfig()
            MbedTLS.config_defaults!(conf; endpoint = MbedTLS.MBEDTLS_SSL_IS_SERVER)
            entropy = MbedTLS.Entropy()
            rng = MbedTLS.CtrDrbg()
            MbedTLS.seed!(rng, entropy)
            MbedTLS.rng!(conf, rng)
            cert = MbedTLS.crt_parse_file(cert_path)
            key = MbedTLS.parse_keyfile(key_path)
            MbedTLS.own_cert!(conf, cert, key)
            ctx = MbedTLS.SSLContext()
            MbedTLS.setup!(ctx, conf)
            MbedTLS.set_bio!(ctx, sock)
            MbedTLS.handshake!(ctx)
            _ = read(ctx, 4)
            write(ctx, "pong")
            close(ctx)
            close(sock)
        catch err
            server_error[] = err
        finally
            close(server)
        end
    end

    el_type = AwsIO.event_loop_get_default_type()
    el = AwsIO.event_loop_new(AwsIO.EventLoopOptions(; type = el_type))
    el_val = el isa AwsIO.EventLoop ? el : nothing
    @test el_val !== nothing
    if el_val === nothing
        return
    end
    @test AwsIO.event_loop_run!(el_val) === nothing

    opts = AwsIO.SocketOptions(; type = AwsIO.SocketType.STREAM, domain = AwsIO.SocketDomain.IPV4)
    sock = AwsIO.socket_init_posix(opts)
    sock_val = sock isa AwsIO.Socket ? sock : nothing
    @test sock_val !== nothing
    if sock_val === nothing
        AwsIO.event_loop_destroy!(el_val)
        return
    end

    negotiated = Ref(false)
    connect_err = Ref{Int}(0)
    read_done = Ref(false)
    read_payload = Ref("")
    tls_error = Ref{Int}(0)

    on_data_read = (handler, slot, buf, ud) -> begin
        read_payload[] = String(AwsIO.byte_cursor_from_buf(buf))
        read_done[] = true
        return nothing
    end

    on_negotiation = (handler, slot, err, ud) -> begin
        connect_err[] = err
        negotiated[] = true
        if err != AwsIO.AWS_OP_SUCCESS
            return nothing
        end

        msg = AwsIO.IoMessage(4)
        buf_ref = Ref(msg.message_data)
        AwsIO.byte_buf_write_from_whole_cursor(buf_ref, AwsIO.ByteCursor("ping"))
        msg.message_data = buf_ref[]
        AwsIO.handler_process_write_message(handler, slot, msg)
        return nothing
    end

    on_error = (handler, slot, err, msg, ud) -> begin
        tls_error[] = err
        return nothing
    end

    connect_opts = AwsIO.SocketConnectOptions(
        AwsIO.SocketEndpoint("127.0.0.1", port);
        event_loop = el_val,
        on_connection_result = (sock_obj, err, ud) -> begin
            if err != AwsIO.AWS_OP_SUCCESS
                connect_err[] = err
                negotiated[] = true
                return nothing
            end

            channel = AwsIO.Channel(el_val, nothing)
            AwsIO.socket_channel_handler_new!(channel, sock_obj)

            ctx = AwsIO.tls_context_new_client(; verify_peer = false)
            if ctx isa AwsIO.ErrorResult
                connect_err[] = ctx.code
                negotiated[] = true
                return nothing
            end

            tls_opts = AwsIO.TlsConnectionOptions(
                ctx;
                server_name = "localhost",
                on_negotiation_result = on_negotiation,
                on_data_read = on_data_read,
                on_error = on_error,
            )

            AwsIO.tls_channel_handler_new!(channel, tls_opts)
            AwsIO.channel_setup_complete!(channel)
            return nothing
        end,
    )

    @test AwsIO.socket_connect(sock_val, connect_opts) === nothing

    @test wait_for_flag_tls(negotiated)
    @test connect_err[] == AwsIO.AWS_OP_SUCCESS
    @test wait_for_flag_tls(read_done)
    @test read_payload[] == "pong"
    @test tls_error[] == 0

    AwsIO.socket_close(sock_val)
    AwsIO.event_loop_destroy!(el_val)
    wait(server_task)
    @test server_error[] === nothing
end
