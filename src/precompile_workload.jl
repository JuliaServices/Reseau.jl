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
