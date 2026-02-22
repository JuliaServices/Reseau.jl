const _PRECOMPILE_STAGE = let
    stage_env = get(ENV, "RESEAU_PRECOMPILE_STAGE", "6")
    parsed = try
        parse(Int, stage_env)
    catch
        6
    end
    max(parsed, 0)
end
function _pc_debug(msg::AbstractString)::Nothing
    _ = msg
    return nothing
end

@inline function _pc_try(f)::Nothing
    try
        f()
    catch
    end
    return nothing
end

function _pc_init_all!()::Bool
    _pc_debug("init start")
    ok = true

    try
        ForeignThreads.__init__()
    catch e
        _pc_debug("ForeignThreads.__init__ failed: $(repr(e))")
        ok = false
    end

    try
        EventLoops.__init__()
    catch e
        _pc_debug("EventLoops.__init__ failed: $(repr(e))")
        ok = false
    end

    try
        Sockets.io_library_init()
    catch e
        _pc_debug("Sockets.io_library_init failed: $(repr(e))")
        ok = false
    end

    _pc_debug(ok ? "init done" : "init partial")
    return ok
end

function _pc_close_default_event_loop_group!()::Nothing
    if !isdefined(EventLoops, :EVENT_LOOP_GROUP)
        return nothing
    end
    once = EventLoops.EVENT_LOOP_GROUP
    if getfield(once, :state) != 0
        value = getfield(once, :value)
        value !== nothing && close(value)
    end
    return nothing
end

function _pc_close_default_host_resolver!()::Nothing
    if !isdefined(Sockets, :HOST_RESOLVER)
        return nothing
    end
    once = Sockets.HOST_RESOLVER
    if getfield(once, :state) != 0
        value = getfield(once, :value)
        value !== nothing && close(value)
    end
    return nothing
end

function _pc_cleanup_all!()::Nothing
    _pc_debug("cleanup start")

    _pc_try(_pc_close_default_host_resolver!)
    _pc_try(_pc_close_default_event_loop_group!)
    _pc_try(Sockets.io_library_clean_up)
    _pc_try(EventLoops._cal_cleanup)
    _pc_try(ForeignThreads.join_all_managed)
    _pc_try(() -> GC.gc(true))
    _pc_try(GC.gc)

    _pc_debug("cleanup done")
    return nothing
end

const _PC_FOREIGN_THREAD_ENTRY_C = Ref{Ptr{Cvoid}}(C_NULL)
const _PC_FOREIGN_THREAD_LOCK = ReentrantLock()

ForeignThreads.@wrap_thread_fn function _pc_foreign_thread_entry(started::Base.Threads.Event)
    try
        notify(started)
    finally
        ForeignThreads.managed_thread_finished!()
    end
end

function _pc_init_cfunctions!()::Nothing
    _PC_FOREIGN_THREAD_ENTRY_C[] != C_NULL && return nothing
    lock(_PC_FOREIGN_THREAD_LOCK)
    try
        _PC_FOREIGN_THREAD_ENTRY_C[] != C_NULL && return nothing
        _PC_FOREIGN_THREAD_ENTRY_C[] = @cfunction(_pc_foreign_thread_entry, Ptr{Cvoid}, (Ptr{Cvoid},))
    finally
        unlock(_PC_FOREIGN_THREAD_LOCK)
    end
    return nothing
end

function _pc_stage_1_foreign_thread!()::Nothing
    _pc_debug("stage 1 start: foreign thread")
    _pc_init_cfunctions!()

    started = Base.Threads.Event()
    _ = ForeignThreads.ForeignThread(
        "ReseauPrecompileStage1",
        _PC_FOREIGN_THREAD_ENTRY_C,
        started;
        join_strategy = ForeignThreads.ThreadJoinStrategy.MANAGED,
    )

    wait(started)
    ForeignThreads.join_all_managed()
    _pc_debug("stage 1 done")
    return nothing
end

function _pc_stage_2_event_loop_task!()::Nothing
    _pc_debug("stage 2 start: event loop group + scheduled task")
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    ran = Base.Threads.Event()

    try
        loop = elg.event_loops[1]
        EventLoops.schedule_task_now!(loop; type_tag = "precompile_stage2_task") do _
            _pc_try(() -> notify(ran))
            return nothing
        end
        wait(ran)
    finally
        close(elg)
        yield()
    end

    _pc_debug("stage 2 done")
    return nothing
end

function _pc_stage_3_host_resolver!()::Nothing
    _pc_debug("stage 3 start: host resolver")
    resolver = Sockets.HostResolver()

    try
        addresses = Sockets.host_resolver_resolve!(resolver, "127.0.0.1")
        isempty(addresses) && error("host resolver returned no addresses for 127.0.0.1")
    finally
        close(resolver)
        ForeignThreads.join_all_managed()
    end

    _pc_debug("stage 3 done")
    return nothing
end

@inline function _pc_close_socket_safe!(sock)::Nothing
    _pc_try(() -> Sockets.socket_close(sock))
    _pc_try(() -> Sockets.socket_cleanup!(sock))
    return nothing
end

@inline function _pc_close_server_safe!(server)::Nothing
    _pc_try(() -> begin
        lock(server.state.cond)
        try
            if !server.state.closed
                server.state.closed = true
                server.state.close_error = ERROR_IO_SOCKET_CLOSED
                notify(server.state.cond)
            end
        finally
            unlock(server.state.cond)
        end
        Sockets.server_bootstrap_shutdown!(server.bootstrap)
    end)
    return nothing
end

@inline function _pc_close_pending_server_accepts!(server)::Nothing
    pending = []
    lock(server.state.cond)
    try
        while !isempty(server.state.accept_queue)
            push!(pending, popfirst!(server.state.accept_queue))
        end
    finally
        unlock(server.state.cond)
    end
    for sock in pending
        _pc_try(() -> close(sock))
    end
    return nothing
end

@inline function _pc_drain_yields!(rounds::Int = 512)::Nothing
    for _ in 1:rounds
        yield()
    end
    return nothing
end

function _pc_stage_4_tcp_listener!()::Nothing
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    server::Union{Sockets.TCPServer, Nothing} = nothing
    try
        server = Sockets.listen("127.0.0.1", 0; event_loop_group = elg)
        close(server)
        server = nothing
    finally
        server !== nothing && _pc_close_server_safe!(server)
        _pc_drain_yields!()
        close(elg)
        _pc_drain_yields!()
    end
    return nothing
end

function _pc_echo_exchange!(client, peer)::Nothing
    write(client, "hello")
    flush(client)

    request = String(read(peer, 5))
    request == "hello" || error("server expected hello, got $(repr(request))")

    write(peer, "hello")
    flush(peer)
    close(peer)

    response = String(read(client, 5))
    response == "hello" || error("client expected hello, got $(repr(response))")

    close(client)
    return nothing
end

function _pc_stage_5_tcp_echo!()::Nothing
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    connect_opts = Sockets.SocketOptions(connect_timeout_ms = UInt32(1000))
    resolve_as_address = Sockets.HostResolutionConfig(resolve_host_as_address = true)

    server::Union{Sockets.TCPServer, Nothing} = nothing
    client::Union{Sockets.TCPSocket, Nothing} = nothing
    peer::Union{Sockets.TCPSocket, Nothing} = nothing

    try
        server = Sockets.listen("127.0.0.1", 0; event_loop_group = elg)
        _, port_u16 = Sockets.getsockname(server)

        client = Sockets.connect(
            "127.0.0.1",
            Int(port_u16);
            event_loop_group = elg,
            socket_options = connect_opts,
            host_resolution_config = resolve_as_address,
        )

        peer = Sockets.accept(server)

        _pc_echo_exchange!(client, peer)

        peer = nothing
        client = nothing

        _pc_close_server_safe!(server)
        server = nothing
    finally
        peer !== nothing && close(peer)
        client !== nothing && close(client)
        if server !== nothing
            _pc_close_pending_server_accepts!(server)
            _pc_close_server_safe!(server)
            _pc_close_pending_server_accepts!(server)
        end

        _pc_drain_yields!()
        server !== nothing && _pc_close_pending_server_accepts!(server)
        close(elg)
        _pc_drain_yields!()
    end
    return nothing
end

function _pc_stage_6_trim_echo!()::Nothing
    elg = EventLoops.EventLoopGroup(; loop_count = 1)
    resolver = Sockets.HostResolver()
    server::Union{Sockets.TCPServer, Nothing} = nothing
    client::Union{Sockets.TCPSocket, Nothing} = nothing
    peer::Union{Sockets.TCPSocket, Nothing} = nothing

    try
        # Mirror trim/echo_trim_safe.jl to root the exact high-level API path.
        Sockets.io_library_init()

        port_u16, server = Sockets.listenany(0; event_loop_group = elg)

        client = Sockets.connect(Int(port_u16); event_loop_group = elg, host_resolver = resolver)

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

        close(client)
        client = nothing
        _pc_close_server_safe!(server)
        server = nothing
    finally
        peer !== nothing && close(peer)
        client !== nothing && close(client)
        if server !== nothing
            _pc_close_pending_server_accepts!(server)
            _pc_close_server_safe!(server)
            _pc_close_pending_server_accepts!(server)
        end
        close(resolver)
        _pc_drain_yields!()
        server !== nothing && _pc_close_pending_server_accepts!(server)
        close(elg)
        _pc_drain_yields!()
    end
    return nothing
end

function _pc_run_upto_stage!(stage::Int)::Nothing
    stage <= 0 && return nothing

    stage >= 1 && _pc_stage_1_foreign_thread!()
    stage >= 2 && _pc_stage_2_event_loop_task!()
    stage >= 3 && _pc_stage_3_host_resolver!()
    stage >= 4 && _pc_stage_4_tcp_listener!()
    stage >= 5 && _pc_stage_5_tcp_echo!()
    stage >= 6 && _pc_stage_6_trim_echo!()

    return nothing
end

try
    @setup_workload begin
        init_ok = _pc_init_all!()
        try
            @compile_workload begin
                if init_ok
                    _pc_debug("compile workload start (stage=$(_PRECOMPILE_STAGE))")
                    _pc_run_upto_stage!(_PRECOMPILE_STAGE)
                    _pc_debug("compile workload done")
                else
                    _pc_debug("compile workload skipped (init failed)")
                end
            end
        finally
            _pc_cleanup_all!()
        end
    end
catch e
    @info "Ignoring error that occurred during precompilation workload" exception = (e, catch_backtrace())
end
