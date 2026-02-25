export
    TCPSocket,
    TCPServer,
    accept,
    connect,
    listen,
    listenany,
    getsockname,
    getpeername,
    tlsupgrade!

mutable struct TCPSocket <: IO
    channel::Union{Channel, Nothing}
    slot::Union{ChannelSlot{Channel}, Nothing}
    socket::Union{Socket, Nothing}
    host::String
    port::Int
    is_local::Bool
    tls_enabled::Bool
    event_loop_group::Union{EventLoopGroup, Nothing}
    host_resolver::Union{HostResolver, Nothing}
    owns_event_loop_group::Bool
    owns_host_resolver::Bool
    buffer::Vector{UInt8}
    read_pos::Int
    write_pos::Int
    cond::Base.Threads.Condition
    closed::Bool
    shutdown_error::Int
    pending_writes::Int
    write_error::Int
    enable_read_back_pressure::Bool
    initial_window_size::Int
end

mutable struct _TCPSocketHandler
    slot::Union{ChannelSlot{Channel}, Nothing}
    io::TCPSocket
end

_TCPSocketHandler(io::TCPSocket) = _TCPSocketHandler(nothing, io)

mutable struct _WriteCtx
    io::TCPSocket
    remaining::Int
    error_code::Int
end

@inline function _buffered_len(io::TCPSocket)::Int
    return io.write_pos - io.read_pos
end

function _ensure_capacity!(io::TCPSocket, needed::Int)::Nothing
    needed <= 0 && return nothing
    cap = length(io.buffer)
    available = cap - io.write_pos + 1
    if available >= needed
        return nothing
    end
    unread = _buffered_len(io)
    if unread > 0 && io.read_pos > 1
        copyto!(io.buffer, 1, io.buffer, io.read_pos, unread)
    end
    io.read_pos = 1
    io.write_pos = unread + 1
    cap = length(io.buffer)
    available = cap - io.write_pos + 1
    if available >= needed
        return nothing
    end
    new_cap = max(cap * 2, io.write_pos + needed - 1)
    resize!(io.buffer, new_cap)
    return nothing
end

function _new_unconnected_socket(;
        read_buffer_capacity::Integer,
        enable_read_back_pressure::Bool,
        initial_window_size::Union{Integer, Nothing},
    )::TCPSocket
    read_buffer_capacity < 0 && throw(ArgumentError("read_buffer_capacity must be >= 0"))
    initial_window = initial_window_size === nothing ? Int(read_buffer_capacity) : Int(initial_window_size)
    buffer = read_buffer_capacity > 0 ? Vector{UInt8}(undef, Int(read_buffer_capacity)) : UInt8[]
    return TCPSocket(
        nothing,
        nothing,
        nothing,
        "",
        0,
        false,
        false,
        nothing,
        nothing,
        false,
        false,
        buffer,
        1,
        1,
        Base.Threads.Condition(),
        false,
        OP_SUCCESS,
        0,
        OP_SUCCESS,
        enable_read_back_pressure,
        initial_window,
    )
end

function _mark_closed!(io::TCPSocket, error_code::Int)::Nothing
    lock(io.cond)
    try
        io.closed = true
        io.shutdown_error = error_code
        notify(io.cond)
    finally
        unlock(io.cond)
    end
    return nothing
end

function _install_handler!(io::TCPSocket, channel::Channel)::Nothing
    handler = _TCPSocketHandler(io)
    slot = channel_slot_new!(channel)
    channel.last !== slot && channel_slot_insert_end!(channel, slot)
    channel_slot_set_handler!(slot, handler)
    io.channel = channel
    io.slot = slot
    io.socket = channel.socket
    channel.channel_state == ChannelState.ACTIVE && channel_trigger_read(channel)
    return nothing
end

function _install_handler_for_connected_channel!(io::TCPSocket, channel::Channel)::Nothing
    if channel_thread_is_callers_thread(channel)
        _install_handler!(io, channel)
        return nothing
    end
    install_future = Future{Nothing}()
    task = ChannelTask(
        EventCallable(s -> begin
            _coerce_task_status(s) == TaskStatus.RUN_READY || return nothing
            try
                _install_handler!(io, channel)
                notify(install_future, nothing)
            catch e
                if e isa Exception
                    @inline notify_exception!(install_future, e)
                else
                    @inline notify_exception!(install_future, ReseauError(ERROR_UNKNOWN))
                end
            end
            return nothing
        end),
        "tcpsocket_install_handler",
    )
    channel_schedule_task_now!(channel, task)
    wait(install_future)
    return nothing
end

function _tls_client_context(;
        ssl_cert::Union{String, Nothing},
        ssl_key::Union{String, Nothing},
        ssl_cacert::Union{String, Nothing},
        ssl_capath::Union{String, Nothing},
        ssl_insecure::Bool,
    )::TlsContext
    opts = if ssl_cert !== nothing || ssl_key !== nothing
        (ssl_cert === nothing || ssl_key === nothing) && error("Both ssl_cert and ssl_key must be provided for client TLS")
        mtls_opts = tls_ctx_options_init_client_mtls_from_path(ssl_cert, ssl_key)
        tls_ctx_options_set_verify_peer!(mtls_opts, !ssl_insecure)
        mtls_opts
    else
        tls_ctx_options_init_default_client(verify_peer = !ssl_insecure)
    end
    if ssl_cacert !== nothing || ssl_capath !== nothing
        tls_ctx_options_override_default_trust_store_from_path!(
            opts;
            ca_path = ssl_capath,
            ca_file = ssl_cacert,
        )
    end
    ctx = tls_context_new(opts)
    return ctx
end

function _tls_server_context(;
        ssl_cert::Union{String, Nothing},
        ssl_key::Union{String, Nothing},
        alpn_list::Union{String, Nothing},
    )::TlsContext
    (ssl_cert === nothing || ssl_key === nothing) && error("Both ssl_cert and ssl_key are required for server TLS")
    opts = tls_ctx_options_init_default_server_from_path(ssl_cert, ssl_key; alpn_list = alpn_list)
    ctx = tls_context_new(opts)
    return ctx
end

function TCPSocket(
        host::AbstractString,
        port::Integer;
        tls::Bool = false,
        tls_options::Union{TlsConnectionOptions, Nothing} = nothing,
        enable_read_back_pressure::Bool = false,
        connect_timeout_ms::Integer = 3000,
        read_buffer_capacity::Integer = 65536,
        initial_window_size::Union{Integer, Nothing} = nothing,
        server_name::Union{String, Nothing} = nothing,
        ssl_cert::Union{String, Nothing} = nothing,
        ssl_key::Union{String, Nothing} = nothing,
        ssl_cacert::Union{String, Nothing} = nothing,
        ssl_capath::Union{String, Nothing} = nothing,
        ssl_insecure::Bool = false,
        alpn_list::Union{String, Nothing} = nothing,
        timeout_ms::Integer = 3000,
        event_loop_group = nothing,
        host_resolver = nothing,
        socket_options::SocketOptions = SocketOptions(connect_timeout_ms = connect_timeout_ms),
        host_resolution_config::Union{HostResolutionConfig, Nothing} = nothing,
    )
    read_buffer_capacity < 0 && throw(ArgumentError("read_buffer_capacity must be >= 0"))
    initial_window = initial_window_size === nothing ? Int(read_buffer_capacity) : Int(initial_window_size)
    elg = event_loop_group
    resolver = host_resolver
    owns_elg = false
    owns_resolver = false
    if elg === nothing
        elg = EventLoops.get_event_loop_group()
        resolver = get_host_resolver()
    else
        if resolver === nothing
            resolver = HostResolver()
            owns_resolver = true
        end
    end

    tls_conn = tls_options
    if tls_conn === nothing && tls
        ctx = _tls_client_context(
            ssl_cert = ssl_cert,
            ssl_key = ssl_key,
            ssl_cacert = ssl_cacert,
            ssl_capath = ssl_capath,
            ssl_insecure = ssl_insecure,
        )
        tls_conn = TlsConnectionOptions(
            ctx;
            server_name = server_name === nothing ? String(host) : server_name,
            alpn_list = alpn_list,
            timeout_ms = timeout_ms,
        )
    end

    io = _new_unconnected_socket(
        read_buffer_capacity = read_buffer_capacity,
        enable_read_back_pressure = enable_read_back_pressure,
        initial_window_size = initial_window_size,
    )
    io.host = String(host)
    io.port = Int(port)
    io.is_local = socket_options.domain == SocketDomain.LOCAL
    io.event_loop_group = elg
    io.host_resolver = resolver
    io.owns_event_loop_group = owns_elg
    io.owns_host_resolver = owns_resolver

    channel = client_bootstrap_connect!(
        (_error_code, _channel) -> nothing,
        host,
        port;
        socket_options,
        tls_connection_options = tls_conn,
        enable_read_back_pressure,
        requested_event_loop = nothing,
        host_resolution_config,
        event_loop_group = elg::EventLoopGroup,
        host_resolver = resolver::HostResolver,
    )
    _install_handler_for_connected_channel!(io, channel)
    io.tls_enabled = tls_conn !== nothing
    return io
end

# Public constructors
connect(port::Integer; kws...) = connect("127.0.0.1", port; kws...)

function connect(host::AbstractString, port::Integer;
        tls::Bool = false,
        tls_options::Union{TlsConnectionOptions, Nothing} = nothing,
        socket_options::SocketOptions = SocketOptions(connect_timeout_ms = 3000),
        kwargs...,
    )
    return TCPSocket(host, port; tls = tls, tls_options = tls_options, socket_options = socket_options, kwargs...)
end

function connect(addr::IPAddr, port::Integer; kwargs...)
    return connect(string(addr), port; kwargs...)
end

connect(addr::InetAddr; kwargs...) = connect(addr.host, addr.port; kwargs...)

# LOCAL sockets / named pipes
function connect(path::AbstractString;
        socket_options::SocketOptions = SocketOptions(domain = SocketDomain.LOCAL, type = SocketType.STREAM),
        kwargs...,
    )
    # Bypass DNS for local socket paths and treat the path as the resolved address.
    config = HostResolutionConfig(;
        resolve_host_as_address = true,
    )
    return TCPSocket(path, 0; socket_options = socket_options, host_resolution_config = config, kwargs...)
end

mutable struct _TCPServerState
    accept_queue::Vector{TCPSocket}
    cond::Base.Threads.Condition
    closed::Bool
    close_error::Int
    listen_event::Base.Threads.Event
    close_event::Base.Threads.Event
    listen_error::Int
    read_buffer_capacity::Int
    enable_read_back_pressure::Bool
    initial_window_size::Union{Int, Nothing}
    is_local::Bool
end

mutable struct TCPServer{B <: ServerBootstrap}
    bootstrap::B
    state::_TCPServerState
end

function Base.isopen(server::TCPServer)::Bool
    return !server.state.closed
end

function Base.close(server::TCPServer)::Nothing
    server.state.closed && return nothing
    lock(server.state.cond)
    try
        server.state.closed = true
        server.state.close_error = ERROR_IO_SOCKET_CLOSED
        notify(server.state.cond)
    finally
        unlock(server.state.cond)
    end
    server_bootstrap_shutdown!(server.bootstrap)
    listener_loop = server.bootstrap.listener_event_loop
    if listener_loop !== nothing && event_loop_thread_is_callers_thread(listener_loop)
        return nothing
    end
    wait(server.state.close_event)
    return nothing
end

function _server_on_incoming_setup(state::_TCPServerState, error_code::Int, channel::Channel)
    if error_code != OP_SUCCESS
        return nothing
    end
    io = _new_unconnected_socket(
        read_buffer_capacity = state.read_buffer_capacity,
        enable_read_back_pressure = state.enable_read_back_pressure,
        initial_window_size = state.initial_window_size,
    )
    io.is_local = state.is_local
    # Install the read-buffering handler and only then publish to accept queue.
    if channel_thread_is_callers_thread(channel)
        _install_handler!(io, channel)
        lock(state.cond)
        try
            push!(state.accept_queue, io)
            notify(state.cond)
        finally
            unlock(state.cond)
        end
    else
        task = ChannelTask(
            EventCallable(s -> begin
                _coerce_task_status(s) == TaskStatus.RUN_READY || return nothing
                _install_handler!(io, channel)
                lock(state.cond)
                try
                    push!(state.accept_queue, io)
                    notify(state.cond)
                finally
                    unlock(state.cond)
                end
                return nothing
            end),
            "tcpserver_install_handler",
        )
        channel_schedule_task_now!(channel, task)
    end
    return nothing
end

function listen(host::IPAddr, port::Integer; backlog::Integer = 511, tls::Bool = false, tls_options::Union{TlsConnectionOptions, Nothing} = nothing, ssl_cert=nothing, ssl_key=nothing, alpn_list=nothing, event_loop_group=nothing, socket_options::SocketOptions = SocketOptions(), kwargs...)
    domain = host isa IPv6 ? SocketDomain.IPV6 : SocketDomain.IPV4
    sockopts = copy(socket_options)
    sockopts.domain = domain
    return listen(string(host), port; backlog = backlog, tls = tls, tls_options = tls_options, ssl_cert = ssl_cert, ssl_key = ssl_key, alpn_list = alpn_list, event_loop_group = event_loop_group, socket_options = sockopts, kwargs...)
end

listen(port::Integer; backlog::Integer = 511, kwargs...) = listen(IPv4(0x7F000001), port; backlog = backlog, kwargs...)

function listen(addr::InetAddr; backlog::Integer = 511, kwargs...)
    return listen(addr.host, addr.port; backlog = backlog, kwargs...)
end

struct _TCPServerOnListenerSetup
    state::_TCPServerState
end

@inline function (cb::_TCPServerOnListenerSetup)(error_code::Int)::Nothing
    st = cb.state
    st.listen_error = error_code
    notify(st.listen_event)
    return nothing
end

struct _TCPServerOnIncomingSetup
    state::_TCPServerState
end

@inline function (cb::_TCPServerOnIncomingSetup)(error_code::Int, channel)::Nothing
    if error_code != OP_SUCCESS || !(channel isa Channel)
        return nothing
    end
    _server_on_incoming_setup(cb.state, error_code, channel::Channel)
    return nothing
end

struct _TCPServerOnListenerDestroy
    state::_TCPServerState
end

@inline function (cb::_TCPServerOnListenerDestroy)(_error_code::Int)::Nothing
    st = cb.state
    st.close_error = OP_SUCCESS
    notify(st.close_event)
    return nothing
end

function listen(host::AbstractString, port::Integer;
        backlog::Integer = 511,
        tls::Bool = false,
        tls_options::Union{TlsConnectionOptions, Nothing} = nothing,
        ssl_cert::Union{String, Nothing} = nothing,
        ssl_key::Union{String, Nothing} = nothing,
        alpn_list::Union{String, Nothing} = nothing,
        enable_read_back_pressure::Bool = false,
        read_buffer_capacity::Integer = 65536,
        initial_window_size::Union{Integer, Nothing} = nothing,
        event_loop_group = nothing,
        socket_options::SocketOptions = SocketOptions(),
    )
    elg = event_loop_group === nothing ? EventLoops.get_event_loop_group() : event_loop_group

    tls_conn = tls_options
    if tls_conn === nothing && tls
        ctx = _tls_server_context(ssl_cert = ssl_cert, ssl_key = ssl_key, alpn_list = alpn_list)
        tls_conn = TlsConnectionOptions(ctx; alpn_list = alpn_list)
    end

    state = _TCPServerState(
        TCPSocket[],
        Base.Threads.Condition(),
        false,
        OP_SUCCESS,
        Base.Threads.Event(),
        Base.Threads.Event(),
        OP_SUCCESS,
        Int(read_buffer_capacity),
        enable_read_back_pressure,
        initial_window_size === nothing ? nothing : Int(initial_window_size),
        socket_options.domain == SocketDomain.LOCAL,
    )

    bootstrap = ServerBootstrap(;
        event_loop_group = elg,
        socket_options = socket_options,
        host = host,
        port = port,
        backlog = backlog,
        tls_connection_options = tls_conn,
        on_listener_setup = _TCPServerOnListenerSetup(state),
        on_incoming_channel_setup = _TCPServerOnIncomingSetup(state),
        on_listener_destroy = _TCPServerOnListenerDestroy(state),
        enable_read_back_pressure = enable_read_back_pressure,
    )
    wait(state.listen_event)
    state.listen_error == OP_SUCCESS || error("listen failed: $(state.listen_error)")
    return TCPServer(bootstrap, state)
end

function listen(path::AbstractString; backlog::Integer = 511, kwargs...)
    sockopts = SocketOptions(domain = SocketDomain.LOCAL, type = SocketType.STREAM)
    return listen(path, 0; backlog = backlog, socket_options = sockopts, kwargs...)
end

function accept(server::TCPServer)::TCPSocket
    lock(server.state.cond)
    try
        while isempty(server.state.accept_queue) && !server.state.closed
            wait(server.state.cond)
        end
        if server.state.closed && isempty(server.state.accept_queue)
            throw(EOFError())
        end
        return popfirst!(server.state.accept_queue)
    finally
        unlock(server.state.cond)
    end
end

function accept(callback, server::TCPServer)
    task = @async begin
        while true
            client = accept(server)
            callback(client)
        end
    end
    return task
end

function listenany(host::IPAddr, port_hint; backlog::Integer = 511, kwargs...)
    default_port = UInt16(port_hint)
    addr = InetAddr(host, default_port)
    while true
        try
            server = listen(addr; backlog = backlog, kwargs...)
            if default_port == 0
                endpoint = socket_get_bound_address(server.bootstrap.listener_socket)
                return (UInt16(endpoint.port), server)
            end
            return (addr.port, server)
        catch
        end
        addr = InetAddr(addr.host, addr.port + UInt16(1))
        if addr.port == default_port
            error("no ports available")
        end
    end
end

listenany(port_hint; backlog::Integer = 511, kwargs...) = listenany(IPv4(0x7F000001), port_hint; backlog = backlog, kwargs...)

function getsockname(sock::TCPSocket)
    sock.socket === nothing && error("socket not connected")
    ep = socket_get_bound_address(sock.socket)
    if sock.is_local
        return (get_address(ep), UInt16(0))
    end
    return (parse(IPAddr, get_address(ep)), UInt16(ep.port))
end

function getsockname(server::TCPServer)
    listener = server.bootstrap.listener_socket
    listener === nothing && error("server is not listening")
    ep = socket_get_bound_address(listener)
    if server.state.is_local
        return (get_address(ep), UInt16(0))
    end
    return (parse(IPAddr, get_address(ep)), UInt16(ep.port))
end

function getpeername(sock::TCPSocket)
    sock.socket === nothing && error("socket not connected")
    ep = sock.socket.remote_endpoint::SocketEndpoint
    if sock.is_local
        return (get_address(ep), UInt16(0))
    end
    return (parse(IPAddr, get_address(ep)), UInt16(ep.port))
end

function tlsupgrade!(
        io::TCPSocket;
        ssl_cert::Union{String, Nothing} = nothing,
        ssl_key::Union{String, Nothing} = nothing,
        ssl_cacert::Union{String, Nothing} = nothing,
        ssl_capath::Union{String, Nothing} = nothing,
        ssl_insecure::Bool = false,
        server_name::Union{String, Nothing} = io.host,
        timeout_ms::Integer = TLS_DEFAULT_TIMEOUT_MS,
    )::Nothing
    io.tls_enabled && return nothing
    channel = io.channel
    channel === nothing && error("TCPSocket is not connected")
    socket_slot = channel_first_slot(channel)
    socket_slot === nothing && error("TCPSocket has no socket slot")

    ctx = _tls_client_context(
        ssl_cert = ssl_cert,
        ssl_key = ssl_key,
        ssl_cacert = ssl_cacert,
        ssl_capath = ssl_capath,
        ssl_insecure = ssl_insecure,
    )

    negotiation_error = Ref(OP_SUCCESS)
    negotiation_event = Base.Threads.Event()
    on_negotiation = (handler, slot, err, ud) -> begin
        _ = handler
        _ = ud
        negotiation_error[] = err
        if err == OP_SUCCESS && slot !== nothing && channel_slot_is_attached(slot)
            channel_trigger_read(slot.channel)
        end
        notify(negotiation_event)
        return nothing
    end

    tls_options = TlsConnectionOptions(
        ctx;
        server_name = server_name,
        on_negotiation_result = on_negotiation,
        timeout_ms = timeout_ms,
    )

    setup_result = Ref{Any}(nothing)
    if channel_thread_is_callers_thread(channel)
        setup_result[] = channel_setup_client_tls(socket_slot, tls_options)
    else
        task = ChannelTask(
            EventCallable(s -> begin
                _coerce_task_status(s) == TaskStatus.RUN_READY || return nothing
                setup_result[] = channel_setup_client_tls(socket_slot, tls_options)
                return nothing
            end),
            "tcpsocket_tls_setup",
        )
        channel_schedule_task_now!(channel, task)
    end

    wait(negotiation_event)
    negotiation_error[] == OP_SUCCESS || error("TLS negotiation failed: $(negotiation_error[])")
    io.tls_enabled = true
    return nothing
end

# --- Base IO methods ---

function Base.isopen(io::TCPSocket)::Bool
    return !io.closed
end

function Base.close(io::TCPSocket)::Nothing
    io.closed && return nothing
    _mark_closed!(io, ERROR_IO_SOCKET_CLOSED)
    channel = io.channel
    channel !== nothing && channel_shutdown!(channel, ERROR_IO_SOCKET_CLOSED)
    io.socket !== nothing && socket_close(io.socket)
    io.owns_host_resolver && io.host_resolver !== nothing && close(io.host_resolver)
    io.owns_event_loop_group && io.event_loop_group !== nothing && close(io.event_loop_group)
    return nothing
end

function Base.eof(io::TCPSocket)::Bool
    lock(io.cond)
    try
        while _buffered_len(io) == 0 && !io.closed
            wait(io.cond)
        end
        return io.closed && _buffered_len(io) == 0
    finally
        unlock(io.cond)
    end
end

function Base.bytesavailable(io::TCPSocket)::Int
    lock(io.cond)
    try
        return _buffered_len(io)
    finally
        unlock(io.cond)
    end
end

function _consume!(io::TCPSocket, nbytes::Int)::Nothing
    io.read_pos += nbytes
    if io.read_pos == io.write_pos
        io.read_pos = 1
        io.write_pos = 1
    end
    if io.enable_read_back_pressure && io.slot !== nothing
        channel_slot_increment_read_window!(io.slot, Csize_t(nbytes))
    end
    return nothing
end

function Base.unsafe_read(io::TCPSocket, p::Ptr{UInt8}, n::UInt)
    nbytes = Int(n)
    nbytes == 0 && return nothing
    lock(io.cond)
    try
        while _buffered_len(io) < nbytes && !io.closed
            wait(io.cond)
        end
        if _buffered_len(io) < nbytes && io.closed
            throw(EOFError())
        end
        buf = io.buffer
        GC.@preserve buf begin
            unsafe_copyto!(p, pointer(buf, io.read_pos), nbytes)
        end
        _consume!(io, nbytes)
    finally
        unlock(io.cond)
    end
    return nothing
end

function Base.read!(io::TCPSocket, buf::StridedVector{UInt8})
    bytes = buf isa Vector{UInt8} ? buf : Vector{UInt8}(buf)
    GC.@preserve bytes begin
        unsafe_read(io, pointer(bytes), UInt(length(bytes)))
    end
    buf === bytes || copyto!(buf, 1, bytes, 1, length(bytes))
    return buf
end

function Base.read!(io::TCPSocket, buf::AbstractVector{UInt8})
    tmp = Vector{UInt8}(undef, length(buf))
    GC.@preserve tmp begin
        unsafe_read(io, pointer(tmp), UInt(length(tmp)))
    end
    copyto!(buf, 1, tmp, 1, length(tmp))
    return buf
end

function Base.read(io::TCPSocket, n::Integer)
    nbytes = Int(n)
    nbytes < 0 && throw(ArgumentError("read length must be >= 0"))
    buf = Vector{UInt8}(undef, nbytes)
    read!(io, buf)
    return buf
end

function Base.read(io::TCPSocket, ::Type{UInt8})
    buf = Vector{UInt8}(undef, 1)
    read!(io, buf)
    return buf[1]
end

function Base.peek(io::TCPSocket, ::Type{UInt8})
    lock(io.cond)
    try
        while _buffered_len(io) == 0 && !io.closed
            wait(io.cond)
        end
        _buffered_len(io) == 0 && throw(EOFError())
        return io.buffer[io.read_pos]
    finally
        unlock(io.cond)
    end
end

function Base.readavailable(io::TCPSocket)
    lock(io.cond)
    try
        n = _buffered_len(io)
        n == 0 && return UInt8[]
        out = Vector{UInt8}(undef, n)
        copyto!(out, 1, io.buffer, io.read_pos, n)
        _consume!(io, n)
        return out
    finally
        unlock(io.cond)
    end
end

function Base.skip(io::TCPSocket, n::Integer)
    nbytes = Int(n)
    nbytes < 0 && throw(ArgumentError("skip length must be >= 0"))
    nbytes == 0 && return nothing
    tmp = Vector{UInt8}(undef, min(nbytes, 8192))
    remaining = nbytes
    while remaining > 0
        chunk = min(remaining, length(tmp))
        GC.@preserve tmp begin
            unsafe_read(io, pointer(tmp), UInt(chunk))
        end
        remaining -= chunk
    end
    return nothing
end

function _begin_write!(io::TCPSocket)::_WriteCtx
    lock(io.cond)
    try
        io.pending_writes += 1
    finally
        unlock(io.cond)
    end
    return _WriteCtx(io, 0, OP_SUCCESS)
end

function _finish_write!(ctx::_WriteCtx)::Nothing
    io = ctx.io
    lock(io.cond)
    try
        io.pending_writes -= 1
        io.pending_writes < 0 && (io.pending_writes = 0)
        if ctx.error_code != OP_SUCCESS && io.write_error == OP_SUCCESS
            io.write_error = ctx.error_code
        end
        notify(io.cond)
    finally
        unlock(io.cond)
    end
    return nothing
end

function _write_fail!(ctx::_WriteCtx, error_code::Int)::Int
    ctx.error_code == OP_SUCCESS && (ctx.error_code = error_code)
    ctx.remaining == 0 && _finish_write!(ctx)
    return error_code
end

function _make_write_completion(ctx::_WriteCtx)::EventCallable
    return EventCallable(error_code -> begin
        error_code != OP_SUCCESS && ctx.error_code == OP_SUCCESS && (ctx.error_code = error_code)
        ctx.remaining -= 1
        if ctx.remaining <= 0
            _finish_write!(ctx)
        end
        return nothing
    end)
end

function _write_now(io::TCPSocket, data::Vector{UInt8}, ctx::_WriteCtx)::Int
    channel = io.channel
    slot = io.slot
    channel === nothing && return _write_fail!(ctx, ERROR_IO_SOCKET_NOT_CONNECTED)
    slot === nothing && return _write_fail!(ctx, ERROR_IO_SOCKET_NOT_CONNECTED)
    remaining = length(data)
    cursor_ref = Ref(ByteCursor(data))
    completion = _make_write_completion(ctx)
    while remaining > 0
        msg = channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, remaining)
        msg === nothing && return _write_fail!(ctx, ERROR_OOM)
        chunk_size = min(remaining, Int(capacity(msg.message_data) - msg.message_data.len))
        chunk_cursor = byte_cursor_advance(cursor_ref, chunk_size)
        msg_ref = Ref(msg.message_data)
        byte_buf_write_from_whole_cursor(msg_ref, chunk_cursor)
        msg.message_data = msg_ref[]
        ctx.remaining += 1
        msg.on_completion = completion
        try
            channel_slot_send_message(slot, msg, ChannelDirection.WRITE)
        catch e
            e isa ReseauError || rethrow()
            ctx.remaining -= 1
            channel_release_message_to_pool!(channel, msg)
            return _write_fail!(ctx, e.code)
        end
        remaining -= chunk_size
    end
    return OP_SUCCESS
end

function _write(io::TCPSocket, data::Vector{UInt8})::Nothing
    io.closed && throw(EOFError())
    channel = io.channel
    channel === nothing && throw(EOFError())
    isempty(data) && return nothing
    ctx = _begin_write!(io)
    if channel_thread_is_callers_thread(channel)
        res = _write_now(io, data, ctx)
        if res != OP_SUCCESS
            error("TCPSocket write failed: $res")
        end
        return nothing
    end
    task = ChannelTask(
        EventCallable(s -> begin
            _coerce_task_status(s) == TaskStatus.RUN_READY || return nothing
            _ = _write_now(io, data, ctx)
            return nothing
        end),
        "tcpsocket_write",
    )
    channel_schedule_task_now!(channel, task)
    return nothing
end

function Base.write(io::TCPSocket, data::StridedVector{UInt8})
    bytes = data isa Vector{UInt8} ? data : Vector{UInt8}(data)
    _write(io, bytes)
    return length(bytes)
end

function Base.write(io::TCPSocket, data::AbstractVector{UInt8})
    bytes = Vector{UInt8}(data)
    _write(io, bytes)
    return length(bytes)
end

function Base.write(io::TCPSocket, data::Union{String, SubString{String}})
    bytes = Vector{UInt8}(codeunits(data))
    _write(io, bytes)
    return length(bytes)
end

function Base.write(io::TCPSocket, data::AbstractString)
    bytes = Vector{UInt8}(codeunits(data))
    _write(io, bytes)
    return length(bytes)
end

function Base.write(io::TCPSocket, b::UInt8)
    _write(io, UInt8[b])
    return 1
end

function Base.flush(io::TCPSocket)
    io.closed && return nothing
    channel = io.channel
    channel === nothing && return nothing
    channel_thread_is_callers_thread(channel) && return nothing
    lock(io.cond)
    try
        while io.pending_writes > 0 && !io.closed
            wait(io.cond)
        end
        io.write_error == OP_SUCCESS || error("TCPSocket write failed: $(io.write_error)")
    finally
        unlock(io.cond)
    end
    return nothing
end

function Base.unsafe_write(io::TCPSocket, p::Ptr{UInt8}, n::UInt)
    nbytes = Int(n)
    nbytes == 0 && return 0
    data = Vector{UInt8}(undef, nbytes)
    GC.@preserve data begin
        unsafe_copyto!(pointer(data), p, nbytes)
    end
    _write(io, data)
    return nbytes
end

function setchannelslot!(handler::_TCPSocketHandler, slot::ChannelSlot)::Nothing
    handler.slot = slot
    return nothing
end

@inline function (::_ChannelSlotReadCallWrapper)(
        f::_ChannelHandlerReadDispatch{_TCPSocketHandler},
        slot_ptr::Ptr{Cvoid},
        message_ptr::Ptr{Cvoid},
    )::Nothing
    slot = _callback_ptr_to_obj(slot_ptr)::ChannelSlot{Channel}
    message = _callback_ptr_to_obj(message_ptr)::IoMessage
    _tcpsocket_handler_process_read_message_impl(f.handler, slot, message)::Nothing
    return nothing
end

@inline function (::_ChannelSlotWriteCallWrapper)(
        f::_ChannelHandlerWriteDispatch{_TCPSocketHandler},
        slot_ptr::Ptr{Cvoid},
        message_ptr::Ptr{Cvoid},
    )::Nothing
    slot = _callback_ptr_to_obj(slot_ptr)::ChannelSlot{Channel}
    message = _callback_ptr_to_obj(message_ptr)::IoMessage
    _tcpsocket_handler_process_write_message_impl(f.handler, slot, message)::Nothing
    return nothing
end

@inline function (::_ChannelSlotIncrementWindowCallWrapper)(
        f::_ChannelHandlerIncrementWindowDispatch{_TCPSocketHandler},
        slot_ptr::Ptr{Cvoid},
        size::Csize_t,
    )::Nothing
    slot = _callback_ptr_to_obj(slot_ptr)::ChannelSlot{Channel}
    _tcpsocket_handler_increment_read_window_impl(f.handler, slot, size)::Nothing
    return nothing
end

@inline function (::_ChannelSlotShutdownCallWrapper)(
        f::_ChannelHandlerShutdownDispatch{_TCPSocketHandler},
        slot_ptr::Ptr{Cvoid},
        direction::UInt8,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Nothing
    slot = _callback_ptr_to_obj(slot_ptr)::ChannelSlot{Channel}
    _tcpsocket_handler_shutdown_impl(
        f.handler,
        slot,
        ChannelDirection.T(direction),
        error_code,
        free_scarce_resources_immediately,
    )::Nothing
    return nothing
end

@inline function _channel_handler_read_dispatch(
        handler::_TCPSocketHandler,
        slot::ChannelSlot,
        message::IoMessage,
    )::Nothing
    _tcpsocket_handler_process_read_message_impl(handler, slot, message)::Nothing
    return nothing
end

@inline function _channel_handler_write_dispatch(
        handler::_TCPSocketHandler,
        slot::ChannelSlot,
        message::IoMessage,
    )::Nothing
    _tcpsocket_handler_process_write_message_impl(handler, slot, message)::Nothing
    return nothing
end

@inline function _channel_handler_increment_window_dispatch(
        handler::_TCPSocketHandler,
        slot::ChannelSlot,
        size::Csize_t,
    )::Nothing
    _tcpsocket_handler_increment_read_window_impl(handler, slot, size)::Nothing
    return nothing
end

@inline function _channel_handler_shutdown_dispatch(
        handler::_TCPSocketHandler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Nothing
    _tcpsocket_handler_shutdown_impl(
        handler,
        slot,
        direction,
        error_code,
        free_scarce_resources_immediately,
    )::Nothing
    return nothing
end

function _tcpsocket_handler_process_read_message_impl(
        handler::_TCPSocketHandler,
        slot::ChannelSlot,
        message::IoMessage,
    )::Nothing
    io = handler.io
    data_len = Int(message.message_data.len)
    if data_len > 0
        lock(io.cond)
        try
            _ensure_capacity!(io, data_len)
            copyto!(io.buffer, io.write_pos, message.message_data.mem, 1, data_len)
            io.write_pos += data_len
            notify(io.cond)
        finally
            unlock(io.cond)
        end
    end
    channel_slot_is_attached(slot) && channel_release_message_to_pool!(slot.channel, message)
    return nothing
end

function _tcpsocket_handler_process_write_message_impl(
        handler::_TCPSocketHandler,
        slot::ChannelSlot,
        message::IoMessage,
    )::Nothing
    _ = handler
    _ = slot
    _ = message
    throw_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
end

function _tcpsocket_handler_increment_read_window_impl(
        handler::_TCPSocketHandler,
        slot::ChannelSlot,
        size::Csize_t,
    )::Nothing
    _ = handler
    channel_slot_increment_read_window!(slot, size)
    return nothing
end

function _tcpsocket_handler_shutdown_impl(
        handler::_TCPSocketHandler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Nothing
    _mark_closed!(handler.io, error_code)
    channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
    return nothing
end

function handler_process_read_message(handler::_TCPSocketHandler, slot::ChannelSlot, message::IoMessage)::Nothing
    return _tcpsocket_handler_process_read_message_impl(handler, slot, message)
end

function handler_process_write_message(handler::_TCPSocketHandler, slot::ChannelSlot, message::IoMessage)::Nothing
    return _tcpsocket_handler_process_write_message_impl(handler, slot, message)
end

function handler_increment_read_window(handler::_TCPSocketHandler, slot::ChannelSlot, size::Csize_t)::Nothing
    return _tcpsocket_handler_increment_read_window_impl(handler, slot, size)
end

function handler_shutdown(handler::_TCPSocketHandler, slot::ChannelSlot, direction::ChannelDirection.T, error_code::Int, free_scarce_resources_immediately::Bool)::Nothing
    return _tcpsocket_handler_shutdown_impl(handler, slot, direction, error_code, free_scarce_resources_immediately)
end

function handler_initial_window_size(handler::_TCPSocketHandler)::Csize_t
    return Csize_t(handler.io.initial_window_size)
end

function handler_message_overhead(handler::_TCPSocketHandler)::Csize_t
    _ = handler
    return Csize_t(0)
end

function handler_destroy(handler::_TCPSocketHandler)::Nothing
    _ = handler
    return nothing
end
