const _PC_FOREIGN_THREAD_ENTRY_C = Ref{Ptr{Cvoid}}(C_NULL)
const _PC_FOREIGN_THREAD_LOCK = ReentrantLock()

ForeignThreads.@wrap_thread_fn function _pc_foreign_thread_entry(started::Base.Threads.Event)
    try
        notify(started)
    finally
        ForeignThreads.managed_thread_finished!()
    end
end

function _pc_init_foreign_thread_entry!()::Nothing
    _PC_FOREIGN_THREAD_ENTRY_C[] != C_NULL && return nothing
    lock(_PC_FOREIGN_THREAD_LOCK)
    try
        _PC_FOREIGN_THREAD_ENTRY_C[] == C_NULL || return nothing
        _PC_FOREIGN_THREAD_ENTRY_C[] = @cfunction(
            _pc_foreign_thread_entry,
            Ptr{Cvoid},
            (Ptr{Cvoid},),
        )
    finally
        unlock(_PC_FOREIGN_THREAD_LOCK)
    end
    return nothing
end

@inline function _pc_close_default_event_loop_group!()::Nothing
    isdefined(EventLoops, :EVENT_LOOP_GROUP) || return nothing
    once = EventLoops.EVENT_LOOP_GROUP
    if getfield(once, :state) != 0
        value = getfield(once, :value)
        value === nothing || close(value)
    end
    return nothing
end

@inline function _pc_close_default_host_resolver!()::Nothing
    isdefined(Sockets, :HOST_RESOLVER) || return nothing
    once = Sockets.HOST_RESOLVER
    if getfield(once, :state) != 0
        value = getfield(once, :value)
        value === nothing || close(value)
    end
    return nothing
end

@inline function _pc_yield!(rounds::Int = 128)::Nothing
    for _ in 1:rounds
        yield()
    end
    return nothing
end

@inline function _pc_expect_success(code::Int, what::AbstractString)::Nothing
    code == OP_SUCCESS || error("$what failed with error code $code")
    return nothing
end

function _pc_wait_retry_future!(f::EventLoops.Future{Int}, what::AbstractString)::Nothing
    _pc_expect_success(wait(f), what)
    return nothing
end

function _pc_run_retry_workload!(event_loop_group::EventLoops.EventLoopGroup)::Nothing
    exp_strategy = Sockets.ExponentialBackoffRetryStrategy(
        event_loop_group,
        ;
        backoff_scale_factor_ms = 1,
        max_backoff_secs = 1,
        max_retries = 1,
        jitter_mode = :none,
    )

    exp_acquired = EventLoops.Future{Int}()
    exp_ready = EventLoops.Future{Int}()
    try
        on_ready = function (token, code)
            notify(exp_ready, code)
            if code == OP_SUCCESS
                Sockets.retry_token_record_success(token)
            end
            Sockets.retry_token_release!(token)
            return nothing
        end

        on_acquired = function (token, code)
            notify(exp_acquired, code)
            if code != OP_SUCCESS || token === nothing
                notify(exp_ready, code)
                return nothing
            end
            try
                Sockets.retry_token_schedule_retry(token, Sockets.RetryErrorType.TRANSIENT, on_ready)
            catch e
                if e isa ReseauError
                    notify(exp_ready, e.code)
                    Sockets.retry_token_release!(token)
                    return nothing
                end
                rethrow()
            end
            return nothing
        end

        Sockets.retry_strategy_acquire_token!(exp_strategy, on_acquired)
        _pc_wait_retry_future!(exp_acquired, "exponential retry token acquire")
        _pc_wait_retry_future!(exp_ready, "exponential retry ready")
    finally
        Sockets.retry_strategy_shutdown!(exp_strategy)
    end

    std_strategy = Sockets.StandardRetryStrategy(
        event_loop_group,
        ;
        initial_bucket_capacity = 10,
        backoff_scale_factor_ms = 1,
        max_backoff_secs = 1,
        max_retries = 1,
        jitter_mode = :none,
    )

    std_acquired = EventLoops.Future{Int}()
    std_ready = EventLoops.Future{Int}()
    try
        on_ready = function (token, code)
            notify(std_ready, code)
            if code == OP_SUCCESS
                Sockets.retry_token_record_success(token)
            end
            Sockets.retry_token_release!(token)
            return nothing
        end

        on_acquired = function (token, code)
            notify(std_acquired, code)
            if code != OP_SUCCESS || token === nothing
                notify(std_ready, code)
                return nothing
            end
            try
                Sockets.retry_token_schedule_retry(token, Sockets.RetryErrorType.SERVER_ERROR, on_ready)
            catch e
                if e isa ReseauError
                    notify(std_ready, e.code)
                    Sockets.retry_token_release!(token)
                    return nothing
                end
                rethrow()
            end
            return nothing
        end

        Sockets.retry_strategy_acquire_token!(std_strategy, "precompile", on_acquired, 0)
        _pc_wait_retry_future!(std_acquired, "standard retry token acquire")
        _pc_wait_retry_future!(std_ready, "standard retry ready")
    finally
        Sockets.retry_strategy_shutdown!(std_strategy)
    end

    return nothing
end

function _pc_cleanup_runtime!()::Nothing
    _pc_close_default_host_resolver!()
    _pc_close_default_event_loop_group!()
    Sockets.io_library_clean_up()
    EventLoops._cal_cleanup()
    ForeignThreads.join_all_managed()
    GC.gc(true)
    GC.gc()
    return nothing
end

function _pc_run_echo_workload!()::Nothing
    _pc_init_foreign_thread_entry!()

    started = Base.Threads.Event()
    _ = ForeignThreads.ForeignThread(
        "ReseauPrecompile",
        _PC_FOREIGN_THREAD_ENTRY_C,
        started;
        join_strategy = ForeignThreads.ThreadJoinStrategy.MANAGED,
    )
    wait(started)
    ForeignThreads.join_all_managed()

    event_loop_group = EventLoops.EventLoopGroup(; loop_count = 1)
    host_resolver = Sockets.HostResolver()

    server::Union{Sockets.TCPServer,Nothing} = nothing
    client::Union{Sockets.TCPSocket,Nothing} = nothing
    peer::Union{Sockets.TCPSocket,Nothing} = nothing

    try
        port_u16, server = Sockets.listenany(0; event_loop_group = event_loop_group)
        client = Sockets.connect(Int(port_u16); event_loop_group = event_loop_group, host_resolver = host_resolver)
        peer = Sockets.accept(server)

        write(client, "hello")
        flush(client)

        request = String(read(peer, 5))
        request == "hello" || error("server expected hello, got $(repr(request))")

        write(peer, "hello")
        flush(peer)
        close(peer)
        peer = nothing

        response = String(read(client, 5))
        response == "hello" || error("client expected hello, got $(repr(response))")

        _pc_run_retry_workload!(event_loop_group)

        close(client)
        client = nothing

        close(server)
        server = nothing
    finally
        peer === nothing || close(peer)
        client === nothing || close(client)
        server === nothing || close(server)
        close(host_resolver)
        _pc_yield!()
        close(event_loop_group)
        _pc_yield!()
        ForeignThreads.join_all_managed()
    end

    return nothing
end

try
    @setup_workload begin
        try
            ForeignThreads.__init__()
            EventLoops.__init__()
            Sockets.io_library_init()
            @compile_workload begin
                _pc_run_echo_workload!()
            end
        finally
            _pc_cleanup_runtime!()
        end
    end
catch e
    @info "Ignoring an error that occurred during the precompilation workload" exception = (e, catch_backtrace())
end
