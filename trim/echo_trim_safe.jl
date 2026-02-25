using Reseau

const RS = Reseau.Sockets
const EL = Reseau.EventLoops

function run_echo()::Nothing
    server::Union{RS.TCPServer, Nothing} = nothing
    client::Union{RS.TCPSocket, Nothing} = nothing
    peer::Union{RS.TCPSocket, Nothing} = nothing
    try
        RS.io_library_init()

        port_u16, server = RS.listenany(0)
        client = RS.connect(Int(port_u16))

        write(client, "hello")
        flush(client)

        peer = RS.accept(server)
        req = String(read(peer, 5))
        req == "hello" || error("server expected \"hello\", got $(repr(req))")

        write(peer, "hello")
        flush(peer)
        close(peer)
        peer = nothing

        resp = String(read(client, 5))
        resp == "hello" || error("client expected \"hello\", got $(repr(resp))")

        close(client)
        client = nothing
        close(server)
        server = nothing
    finally
        peer !== nothing && close(peer)
        client !== nothing && close(client)
        server !== nothing && close(server)
    end
    return nothing
end

@inline function _expect_success(code::Int, what::AbstractString)::Nothing
    code == Reseau.OP_SUCCESS || error("$what failed with error code $code")
    return nothing
end

function _wait_retry_future!(f::EL.Future{Int}, what::AbstractString)::Nothing
    _expect_success(wait(f), what)
    return nothing
end

function run_retry_samples()::Nothing
    RS.io_library_init()

    event_loop_group = EL.EventLoopGroup(; loop_count = 1)
    try
        exp_strategy = RS.ExponentialBackoffRetryStrategy(
            event_loop_group,
            ;
            backoff_scale_factor_ms = 1,
            max_backoff_secs = 1,
            max_retries = 1,
            jitter_mode = :none,
        )
        exp_acquired = EL.Future{Int}()
        exp_ready = EL.Future{Int}()
        try
            on_ready = function (token, code)
                notify(exp_ready, code)
                if code == Reseau.OP_SUCCESS
                    RS.retry_token_record_success(token)
                end
                RS.retry_token_release!(token)
                return nothing
            end

            on_acquired = function (token, code)
                notify(exp_acquired, code)
                if code != Reseau.OP_SUCCESS || token === nothing
                    notify(exp_ready, code)
                    return nothing
                end
                RS.retry_token_schedule_retry(token, RS.RetryErrorType.TRANSIENT, on_ready)
                return nothing
            end

            RS.retry_strategy_acquire_token!(exp_strategy, on_acquired)
            _wait_retry_future!(exp_acquired, "trim exponential retry token acquire")
            _wait_retry_future!(exp_ready, "trim exponential retry ready")
        finally
            RS.retry_strategy_shutdown!(exp_strategy)
        end

        std_strategy = RS.StandardRetryStrategy(
            event_loop_group,
            ;
            initial_bucket_capacity = 10,
            backoff_scale_factor_ms = 1,
            max_backoff_secs = 1,
            max_retries = 1,
            jitter_mode = :none,
        )
        std_acquired = EL.Future{Int}()
        std_ready = EL.Future{Int}()
        try
            on_ready = function (token, code)
                notify(std_ready, code)
                if code == Reseau.OP_SUCCESS
                    RS.retry_token_record_success(token)
                end
                RS.retry_token_release!(token)
                return nothing
            end

            on_acquired = function (token, code)
                notify(std_acquired, code)
                if code != Reseau.OP_SUCCESS || token === nothing
                    notify(std_ready, code)
                    return nothing
                end
                RS.retry_token_schedule_retry(token, RS.RetryErrorType.SERVER_ERROR, on_ready)
                return nothing
            end

            RS.retry_strategy_acquire_token!(std_strategy, "trim", on_acquired, 0)
            _wait_retry_future!(std_acquired, "trim standard retry token acquire")
            _wait_retry_future!(std_ready, "trim standard retry ready")
        finally
            RS.retry_strategy_shutdown!(std_strategy)
        end
    finally
        close(event_loop_group)
    end

    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_echo()
    run_retry_samples()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
