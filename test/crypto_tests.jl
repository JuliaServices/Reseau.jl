begin

using Test
using AwsIO

include("read_write_test_handler.jl")

if !tls_tests_enabled()
    @info "Skipping TLS crypto tests (set AWSIO_RUN_TLS_TESTS=1 to enable)"
    return
end

function wait_for_pred(pred::Function; timeout_s::Float64 = 5.0)
    start = Base.time_ns()
    timeout_ns = Int(timeout_s * 1_000_000_000)
    while (Base.time_ns() - start) < timeout_ns
        pred() && return true
        sleep(0.01)
    end
    return false
end

mutable struct ByoCryptoTestArgs
    lock::ReentrantLock
    channel::Any
    rw_handler::ReadWriteTestHandler
    tls_ctx::AwsIO.TlsContext
    tls_options::AwsIO.TlsConnectionOptions
    negotiation_result_fn::Any
    cb_data::Any
    error_code::Int
    shutdown_invoked::Bool
    listener_destroyed::Bool
    setup_completed::Bool
    negotiated::Bool
end

mutable struct ByoCryptoRwArgs
    lock::ReentrantLock
    received_message::AwsIO.ByteBuffer
    invocation_happened::Bool
    test_args::Union{ByoCryptoTestArgs, Nothing}
end

function _buf_from_string(str::AbstractString)
    buf_ref = Ref(AwsIO.ByteBuffer(length(str)))
    AwsIO.byte_buf_write_from_whole_cursor(buf_ref, AwsIO.ByteCursor(str))
    return buf_ref[]
end

function _byo_handle_read(handler, slot, data_read, rw_args::ByoCryptoRwArgs)
    lock(rw_args.lock) do
        buf_ref = Ref(rw_args.received_message)
        AwsIO.byte_buf_write_from_whole_buffer(buf_ref, data_read)
        rw_args.received_message = buf_ref[]
        rw_args.invocation_happened = true
    end
    if rw_args.test_args !== nothing && rw_args.test_args.negotiation_result_fn !== nothing
        rw_args.test_args.negotiation_result_fn(
            handler,
            slot,
            AwsIO.AWS_OP_SUCCESS,
            rw_args.test_args.cb_data,
        )
        rw_args.test_args.negotiation_result_fn = nothing
    end
    return rw_args.received_message
end

function _byo_handle_write(handler, slot, data_read, user_data)
    _ = handler
    _ = slot
    _ = data_read
    _ = user_data
    return AwsIO.null_buffer()
end

const _BYO_WRITE_TAG = "I'm a big teapot"
const _BYO_READ_TAG = "I'm a little teapot."

function _byo_start_negotiation(handler::ReadWriteTestHandler, test_args::ByoCryptoTestArgs)
    write_buf = _buf_from_string(_BYO_WRITE_TAG)
    res = rw_handler_write(handler, handler.slot, write_buf)
    res isa AwsIO.ErrorResult && return res
    if test_args.negotiation_result_fn !== nothing
        test_args.negotiation_result_fn(
            handler,
            handler.slot,
            AwsIO.AWS_OP_SUCCESS,
            test_args.cb_data,
        )
        test_args.negotiation_result_fn = nothing
    end
    return AwsIO.AWS_OP_SUCCESS
end

function _byo_tls_handler_new(options, slot, test_args::ByoCryptoTestArgs)
    _ = slot
    test_args.negotiation_result_fn = options.on_negotiation_result
    test_args.cb_data = options.user_data
    return test_args.rw_handler
end

@testset "BYO crypto handler integration" begin
    elg = AwsIO.EventLoopGroup(AwsIO.EventLoopGroupOptions(; loop_count = 1))
    resolver = AwsIO.DefaultHostResolver(elg)

    incoming_rw_args = ByoCryptoRwArgs(ReentrantLock(), AwsIO.ByteBuffer(128), false, nothing)
    outgoing_rw_args = ByoCryptoRwArgs(ReentrantLock(), AwsIO.ByteBuffer(128), false, nothing)

    incoming_rw_handler = rw_handler_new(
        _byo_handle_read,
        _byo_handle_write,
        true,
        128,
        incoming_rw_args,
    )
    outgoing_rw_handler = rw_handler_new(
        _byo_handle_read,
        _byo_handle_write,
        true,
        128,
        outgoing_rw_args,
    )

    server_ctx = AwsIO.tls_context_new(AwsIO.TlsContextOptions(; is_server = true, verify_peer = false))
    @test server_ctx isa AwsIO.TlsContext
    client_ctx = AwsIO.tls_context_new(AwsIO.TlsContextOptions(; is_server = false, verify_peer = false))
    @test client_ctx isa AwsIO.TlsContext

    incoming_args = ByoCryptoTestArgs(
        ReentrantLock(),
        nothing,
        incoming_rw_handler,
        server_ctx,
        AwsIO.TlsConnectionOptions(
            server_ctx;
            on_negotiation_result = (handler, slot, err, ud) -> begin
                _ = handler
                _ = slot
                _ = ud
                incoming_args.negotiated = true
                return nothing
            end,
        ),
        nothing,
        nothing,
        AwsIO.AWS_OP_SUCCESS,
        false,
        false,
        false,
        false,
    )
    outgoing_args = ByoCryptoTestArgs(
        ReentrantLock(),
        nothing,
        outgoing_rw_handler,
        client_ctx,
        AwsIO.TlsConnectionOptions(
            client_ctx;
            on_negotiation_result = (handler, slot, err, ud) -> begin
                _ = handler
                _ = slot
                _ = ud
                outgoing_args.negotiated = true
                return nothing
            end,
        ),
        nothing,
        nothing,
        AwsIO.AWS_OP_SUCCESS,
        false,
        false,
        false,
        false,
    )

    incoming_rw_args.test_args = incoming_args
    outgoing_rw_args.test_args = outgoing_args

    client_setup = AwsIO.TlsByoCryptoSetupOptions(
        new_handler_fn = _byo_tls_handler_new,
        start_negotiation_fn = _byo_start_negotiation,
        user_data = outgoing_args,
    )
    @test AwsIO.tls_byo_crypto_set_client_setup_options(client_setup) === nothing

    server_setup = AwsIO.TlsByoCryptoSetupOptions(
        new_handler_fn = _byo_tls_handler_new,
        user_data = incoming_args,
    )
    @test AwsIO.tls_byo_crypto_set_server_setup_options(server_setup) === nothing

    server_bootstrap = AwsIO.ServerBootstrap(AwsIO.ServerBootstrapOptions(
        event_loop_group = elg,
        host = "127.0.0.1",
        port = 0,
        tls_connection_options = incoming_args.tls_options,
        enable_read_back_pressure = true,
        on_incoming_channel_setup = (bs, err, channel, ud) -> begin
            _ = bs
            _ = ud
            lock(incoming_args.lock) do
                incoming_args.channel = channel
                incoming_args.setup_completed = true
            end
            return nothing
        end,
        on_incoming_channel_shutdown = (bs, err, channel, ud) -> begin
            _ = bs
            _ = channel
            _ = ud
            lock(incoming_args.lock) do
                incoming_args.shutdown_invoked = true
                incoming_args.error_code = err
            end
            return nothing
        end,
        on_listener_destroy = (bs, ud) -> begin
            _ = bs
            _ = ud
            lock(incoming_args.lock) do
                incoming_args.listener_destroyed = true
            end
            return nothing
        end,
    ))

    listener = server_bootstrap.listener_socket
    @test listener !== nothing
    bound = AwsIO.socket_get_bound_address(listener)
    @test bound isa AwsIO.SocketEndpoint
    port = bound isa AwsIO.SocketEndpoint ? Int(bound.port) : 0
    @test port != 0

    client_bootstrap = AwsIO.ClientBootstrap(AwsIO.ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
    ))

    resolution_config = AwsIO.HostResolutionConfig(impl = (host, impl_data) -> begin
        _ = impl_data
        return [AwsIO.HostAddress("127.0.0.1", AwsIO.HostAddressType.A, host, UInt64(0))]
    end)

    @test AwsIO.client_bootstrap_connect!(
        client_bootstrap,
        "127.0.0.1",
        port;
        host_resolution_config = resolution_config,
        tls_connection_options = outgoing_args.tls_options,
        enable_read_back_pressure = false,
        on_setup = (bs, err, channel, ud) -> begin
            _ = bs
            _ = ud
            lock(outgoing_args.lock) do
                outgoing_args.channel = channel
                outgoing_args.setup_completed = true
            end
            return nothing
        end,
        on_shutdown = (bs, err, channel, ud) -> begin
            _ = bs
            _ = channel
            _ = ud
            lock(outgoing_args.lock) do
                outgoing_args.shutdown_invoked = true
                outgoing_args.error_code = err
            end
            return nothing
        end,
    ) === nothing

    @test wait_for_pred(() -> incoming_args.setup_completed)
    @test wait_for_pred(() -> outgoing_args.setup_completed)
    @test wait_for_pred(() -> incoming_rw_args.invocation_happened)

    read_buf = _buf_from_string(_BYO_READ_TAG)
    @test rw_handler_write(incoming_args.rw_handler, incoming_args.rw_handler.slot, read_buf) === nothing
    @test wait_for_pred(() -> outgoing_rw_args.invocation_happened)

    @test String(AwsIO.byte_cursor_from_buf(incoming_rw_args.received_message)) == _BYO_WRITE_TAG
    @test String(AwsIO.byte_cursor_from_buf(outgoing_rw_args.received_message)) == _BYO_READ_TAG
    @test incoming_args.negotiated
    @test outgoing_args.negotiated

    if incoming_args.channel !== nothing
        AwsIO.channel_shutdown!(incoming_args.channel, AwsIO.AWS_OP_SUCCESS)
    end
    if outgoing_args.channel !== nothing
        AwsIO.channel_shutdown!(outgoing_args.channel, AwsIO.AWS_OP_SUCCESS)
    end

    @test wait_for_pred(() -> incoming_args.shutdown_invoked)
    @test wait_for_pred(() -> outgoing_args.shutdown_invoked)

    AwsIO.server_bootstrap_shutdown!(server_bootstrap)
    @test wait_for_pred(() -> incoming_args.listener_destroyed)

    AwsIO.host_resolver_shutdown!(resolver)
    AwsIO.event_loop_group_destroy!(elg)
end

end # begin
