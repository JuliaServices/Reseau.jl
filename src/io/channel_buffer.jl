# ChannelBuffer - IO adapter for Reseau channels

mutable struct ChannelBuffer <: IO
    channel::Union{Channel, Nothing}
    slot::Union{ChannelSlot, Nothing}
    socket::Union{Socket, Nothing}
    handler::Union{AbstractChannelHandler, Nothing}
    host::String
    port::Int
    tls_enabled::Bool
    event_loop_group::EventLoopGroup
    host_resolver::DefaultHostResolver
    bootstrap::ClientBootstrap
    owns_event_loop_group::Bool
    owns_host_resolver::Bool
    buffer::Vector{UInt8}
    read_pos::Int
    write_pos::Int
    cond::Threads.Condition
    closed::Bool
    shutdown_error::Int
    pending_writes::Int
    write_error::Int
    enable_read_back_pressure::Bool
    initial_window_size::Int
    connect_event::Threads.Event
    connect_error::Int
end

const _CHANNELBUFFER_DEFAULT_LOCK = ReentrantLock()
const _CHANNELBUFFER_DEFAULT_ELG = Ref{Union{EventLoopGroup, Nothing}}(nothing)
const _CHANNELBUFFER_DEFAULT_RESOLVER = Ref{Union{DefaultHostResolver, Nothing}}(nothing)

function _channelbuffer_default_resources()
    lock(_CHANNELBUFFER_DEFAULT_LOCK)
    try
        if _CHANNELBUFFER_DEFAULT_ELG[] === nothing
            elg = EventLoopGroup(EventLoopGroupOptions(; loop_count = 1))
            elg isa ErrorResult && error("Failed to create EventLoopGroup: $(elg.code)")
            resolver = DefaultHostResolver(elg)
            _CHANNELBUFFER_DEFAULT_ELG[] = elg
            _CHANNELBUFFER_DEFAULT_RESOLVER[] = resolver
        end
        return _CHANNELBUFFER_DEFAULT_ELG[]::EventLoopGroup, _CHANNELBUFFER_DEFAULT_RESOLVER[]::DefaultHostResolver
    finally
        unlock(_CHANNELBUFFER_DEFAULT_LOCK)
    end
end

mutable struct ChannelBufferHandler <: AbstractChannelHandler
    slot::Union{ChannelSlot, Nothing}
    io::ChannelBuffer
end

function ChannelBufferHandler(io::ChannelBuffer)
    return ChannelBufferHandler(nothing, io)
end

mutable struct ChannelBufferWriteContext
    io::ChannelBuffer
    remaining::Int
    error_code::Int
end

@inline function _buffered_len(io::ChannelBuffer)::Int
    return io.write_pos - io.read_pos
end

function _ensure_capacity!(io::ChannelBuffer, needed::Int)::Nothing
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

function _channelbuffer_mark_closed!(io::ChannelBuffer, error_code::Int)::Nothing
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

function _channelbuffer_install_handler!(io::ChannelBuffer, channel::Channel)::Nothing
    handler = ChannelBufferHandler(io)
    slot = channel_slot_new!(channel)
    channel.last !== slot && channel_slot_insert_end!(channel, slot)
    channel_slot_set_handler!(slot, handler)
    io.channel = channel
    io.slot = slot
    io.handler = handler
    first_slot = channel_first_slot(channel)
    if first_slot !== nothing && first_slot.handler isa SocketChannelHandler
        io.socket = socket_channel_handler_get_socket(first_slot.handler)
    end
    channel.channel_state == ChannelState.ACTIVE && channel_trigger_read(channel)
    return nothing
end

function _channelbuffer_on_setup(bootstrap, error_code::Int, channel, io::ChannelBuffer)
    _ = bootstrap
    if error_code != AWS_OP_SUCCESS || channel === nothing
        io.connect_error = error_code
        _channelbuffer_mark_closed!(io, error_code)
        notify(io.connect_event)
        return nothing
    end
    if channel_thread_is_callers_thread(channel)
        _channelbuffer_install_handler!(io, channel)
        io.connect_error = AWS_OP_SUCCESS
        notify(io.connect_event)
        return nothing
    end
    task = ChannelTask(
        (t, ctx, status) -> begin
            _ = t
            status == TaskStatus.RUN_READY || return nothing
            _channelbuffer_install_handler!(ctx.io, ctx.channel)
            ctx.io.connect_error = AWS_OP_SUCCESS
            notify(ctx.io.connect_event)
            return nothing
        end,
        (io = io, channel = channel),
        "channelbuffer_install_handler",
    )
    channel_schedule_task_now!(channel, task)
    return nothing
end

function _channelbuffer_on_shutdown(bootstrap, error_code::Int, channel, io::ChannelBuffer)
    _ = bootstrap
    _ = channel
    _channelbuffer_mark_closed!(io, error_code)
    return nothing
end

function ChannelBuffer(
        host::AbstractString,
        port::Integer;
        tls::Bool = false,
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
        event_loop_group = nothing,
        host_resolver = nothing,
        socket_options::SocketOptions = SocketOptions(connect_timeout_ms = connect_timeout_ms),
    )
    initial_window = initial_window_size === nothing ? Int(read_buffer_capacity) : Int(initial_window_size)
    elg = event_loop_group
    resolver = host_resolver
    owns_elg = false
    owns_resolver = false
    if elg === nothing
        elg, resolver = _channelbuffer_default_resources()
    else
        if resolver === nothing
            resolver = DefaultHostResolver(elg)
            owns_resolver = true
        end
    end
    bootstrap = ClientBootstrap(ClientBootstrapOptions(
        event_loop_group = elg,
        host_resolver = resolver,
        socket_options = socket_options,
    ))
    buffer = read_buffer_capacity > 0 ? Vector{UInt8}(undef, Int(read_buffer_capacity)) : UInt8[]
    io = ChannelBuffer(
        nothing,
        nothing,
        nothing,
        nothing,
        String(host),
        Int(port),
        false,
        elg,
        resolver,
        bootstrap,
        owns_elg,
        owns_resolver,
        buffer,
        1,
        1,
        Threads.Condition(),
        false,
        AWS_OP_SUCCESS,
        0,
        AWS_OP_SUCCESS,
        enable_read_back_pressure,
        initial_window,
        Threads.Event(),
        ERROR_IO_SOCKET_NOT_CONNECTED,
    )
    result = client_bootstrap_connect!(
        bootstrap,
        host,
        port;
        socket_options = socket_options,
        tls_connection_options = nothing,
        on_setup = _channelbuffer_on_setup,
        on_shutdown = _channelbuffer_on_shutdown,
        user_data = io,
        enable_read_back_pressure = enable_read_back_pressure,
    )
    result isa ErrorResult && error("ChannelBuffer connect failed: $(result.code)")
    wait(io.connect_event)
    io.connect_error == AWS_OP_SUCCESS || error("ChannelBuffer connect failed: $(io.connect_error)")
    if tls
        tlsupgrade!(
            io;
            ssl_cert = ssl_cert,
            ssl_key = ssl_key,
            ssl_cacert = ssl_cacert,
            ssl_capath = ssl_capath,
            ssl_insecure = ssl_insecure,
            server_name = server_name === nothing ? io.host : server_name,
        )
    end
    return io
end

function Base.isopen(io::ChannelBuffer)::Bool
    return !io.closed
end

function Base.close(io::ChannelBuffer)::Nothing
    io.closed && return nothing
    _channelbuffer_mark_closed!(io, ERROR_IO_SOCKET_CLOSED)
    channel = io.channel
    channel !== nothing && channel_shutdown!(channel, ERROR_IO_SOCKET_CLOSED)
    io.socket !== nothing && socket_close(io.socket)
    io.owns_host_resolver && host_resolver_shutdown!(io.host_resolver)
    io.owns_event_loop_group && event_loop_group_release!(io.event_loop_group)
    return nothing
end

function Base.eof(io::ChannelBuffer)::Bool
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

function Base.bytesavailable(io::ChannelBuffer)::Int
    lock(io.cond)
    try
        return _buffered_len(io)
    finally
        unlock(io.cond)
    end
end

function _channelbuffer_consume!(io::ChannelBuffer, nbytes::Int)::Nothing
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

function Base.unsafe_read(io::ChannelBuffer, p::Ptr{UInt8}, n::UInt)
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
        _channelbuffer_consume!(io, nbytes)
    finally
        unlock(io.cond)
    end
    return nothing
end

function Base.read!(io::ChannelBuffer, buf::StridedVector{UInt8})
    bytes = buf isa Vector{UInt8} ? buf : Vector{UInt8}(buf)
    GC.@preserve bytes begin
        unsafe_read(io, pointer(bytes), UInt(length(bytes)))
    end
    buf === bytes || copyto!(buf, 1, bytes, 1, length(bytes))
    return buf
end

function Base.read!(io::ChannelBuffer, buf::AbstractVector{UInt8})
    tmp = Vector{UInt8}(undef, length(buf))
    GC.@preserve tmp begin
        unsafe_read(io, pointer(tmp), UInt(length(tmp)))
    end
    copyto!(buf, 1, tmp, 1, length(tmp))
    return buf
end

function Base.read(io::ChannelBuffer, n::Integer)
    nbytes = Int(n)
    nbytes < 0 && throw(ArgumentError("read length must be >= 0"))
    buf = Vector{UInt8}(undef, nbytes)
    read!(io, buf)
    return buf
end

function Base.read(io::ChannelBuffer, ::Type{UInt8})
    buf = Vector{UInt8}(undef, 1)
    read!(io, buf)
    return buf[1]
end

function Base.skip(io::ChannelBuffer, n::Integer)
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

function _channelbuffer_tls_context(;
        ssl_cert::Union{String, Nothing},
        ssl_key::Union{String, Nothing},
        ssl_cacert::Union{String, Nothing},
        ssl_capath::Union{String, Nothing},
        ssl_insecure::Bool,
    )::TlsContext
    opts = if ssl_cert !== nothing || ssl_key !== nothing
        (ssl_cert === nothing || ssl_key === nothing) && error("Both ssl_cert and ssl_key must be provided for client TLS")
        mtls_opts = tls_ctx_options_init_client_mtls_from_path(ssl_cert, ssl_key)
        mtls_opts isa ErrorResult && error("TLS mTLS init failed: $(mtls_opts.code)")
        tls_ctx_options_set_verify_peer!(mtls_opts, !ssl_insecure)
        mtls_opts
    else
        tls_ctx_options_init_default_client(verify_peer = !ssl_insecure)
    end

    if ssl_cacert !== nothing || ssl_capath !== nothing
        res = tls_ctx_options_override_default_trust_store_from_path!(
            opts;
            ca_path = ssl_capath,
            ca_file = ssl_cacert,
        )
        res isa ErrorResult && error("TLS trust store override failed: $(res.code)")
    end

    ctx = tls_context_new(opts)
    ctx isa ErrorResult && error("TLS context creation failed: $(ctx.code)")
    return ctx
end

function tlsupgrade!(
        io::ChannelBuffer;
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
    channel === nothing && error("ChannelBuffer is not connected")
    socket_slot = channel_first_slot(channel)
    socket_slot === nothing && error("ChannelBuffer has no socket slot")

    ctx = _channelbuffer_tls_context(
        ssl_cert = ssl_cert,
        ssl_key = ssl_key,
        ssl_cacert = ssl_cacert,
        ssl_capath = ssl_capath,
        ssl_insecure = ssl_insecure,
    )

    negotiation_error = Ref(AWS_OP_SUCCESS)
    negotiation_event = Threads.Event()
    on_negotiation = (handler, slot, err, ud) -> begin
        _ = handler
        _ = ud
        negotiation_error[] = err
        if err == AWS_OP_SUCCESS && slot !== nothing && slot.channel !== nothing
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
            (t, ctx2, status) -> begin
                _ = t
                status == TaskStatus.RUN_READY || return nothing
                ctx2.result[] = channel_setup_client_tls(ctx2.socket_slot, ctx2.tls_options)
                return nothing
            end,
            (socket_slot = socket_slot, tls_options = tls_options, result = setup_result),
            "channelbuffer_tls_setup",
        )
        channel_schedule_task_now!(channel, task)
    end

    if setup_result[] isa ErrorResult
        negotiation_error[] = setup_result[].code
        notify(negotiation_event)
    end

    wait(negotiation_event)
    negotiation_error[] == AWS_OP_SUCCESS || error("TLS negotiation failed: $(negotiation_error[])")
    io.tls_enabled = true
    return nothing
end

function _channelbuffer_begin_write!(io::ChannelBuffer)::ChannelBufferWriteContext
    lock(io.cond)
    try
        io.pending_writes += 1
    finally
        unlock(io.cond)
    end
    return ChannelBufferWriteContext(io, 0, AWS_OP_SUCCESS)
end

function _channelbuffer_finish_write!(ctx::ChannelBufferWriteContext)::Nothing
    io = ctx.io
    lock(io.cond)
    try
        io.pending_writes -= 1
        io.pending_writes < 0 && (io.pending_writes = 0)
        if ctx.error_code != AWS_OP_SUCCESS && io.write_error == AWS_OP_SUCCESS
            io.write_error = ctx.error_code
        end
        notify(io.cond)
    finally
        unlock(io.cond)
    end
    return nothing
end

function _channelbuffer_write_fail!(ctx::ChannelBufferWriteContext, error_code::Int)::ErrorResult
    ctx.error_code == AWS_OP_SUCCESS && (ctx.error_code = error_code)
    ctx.remaining == 0 && _channelbuffer_finish_write!(ctx)
    return ErrorResult(error_code)
end

function _channelbuffer_on_write_complete(channel, message::IoMessage, error_code::Int, user_data)::Nothing
    _ = channel
    _ = message
    ctx = user_data::ChannelBufferWriteContext
    error_code != AWS_OP_SUCCESS && ctx.error_code == AWS_OP_SUCCESS && (ctx.error_code = error_code)
    ctx.remaining -= 1
    if ctx.remaining <= 0
        _channelbuffer_finish_write!(ctx)
    end
    return nothing
end

function _channelbuffer_write_now(io::ChannelBuffer, data::Vector{UInt8}, ctx::ChannelBufferWriteContext)
    channel = io.channel
    slot = io.slot
    channel === nothing && return _channelbuffer_write_fail!(ctx, ERROR_IO_SOCKET_NOT_CONNECTED)
    slot === nothing && return _channelbuffer_write_fail!(ctx, ERROR_IO_SOCKET_NOT_CONNECTED)
    remaining = length(data)
    cursor_ref = Ref(ByteCursor(data))
    while remaining > 0
        msg = channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, remaining)
        msg === nothing && return _channelbuffer_write_fail!(ctx, ERROR_OOM)
        chunk_size = min(remaining, Int(capacity(msg.message_data) - msg.message_data.len))
        chunk_cursor = byte_cursor_advance(cursor_ref, chunk_size)
        msg_ref = Ref(msg.message_data)
        byte_buf_write_from_whole_cursor(msg_ref, chunk_cursor)
        msg.message_data = msg_ref[]
        ctx.remaining += 1
        msg.on_completion = _channelbuffer_on_write_complete
        msg.user_data = ctx
        send_res = channel_slot_send_message(slot, msg, ChannelDirection.WRITE)
        if send_res isa ErrorResult
            ctx.remaining -= 1
            channel_release_message_to_pool!(channel, msg)
            return _channelbuffer_write_fail!(ctx, send_res.code)
        end
        remaining -= chunk_size
    end
    return nothing
end

function _channelbuffer_write(io::ChannelBuffer, data::Vector{UInt8})::Nothing
    io.closed && throw(EOFError())
    channel = io.channel
    channel === nothing && throw(EOFError())
    isempty(data) && return nothing
    ctx = _channelbuffer_begin_write!(io)
    if channel_thread_is_callers_thread(channel)
        res = _channelbuffer_write_now(io, data, ctx)
        if res isa ErrorResult
            error("ChannelBuffer write failed: $(res.code)")
        end
        return nothing
    end
    task = ChannelTask(
        (t, ctx, status) -> begin
            _ = t
            status == TaskStatus.RUN_READY || return nothing
            _ = _channelbuffer_write_now(ctx.io, ctx.data, ctx.write_ctx)
            return nothing
        end,
        (io = io, data = data, write_ctx = ctx),
        "channelbuffer_write",
    )
    channel_schedule_task_now!(channel, task)
    return nothing
end

function Base.write(io::ChannelBuffer, data::StridedVector{UInt8})
    bytes = data isa Vector{UInt8} ? data : Vector{UInt8}(data)
    _channelbuffer_write(io, bytes)
    return length(bytes)
end

function Base.write(io::ChannelBuffer, data::AbstractVector{UInt8})
    bytes = Vector{UInt8}(data)
    _channelbuffer_write(io, bytes)
    return length(bytes)
end

function Base.write(io::ChannelBuffer, data::Union{String, SubString{String}})
    bytes = Vector{UInt8}(codeunits(data))
    _channelbuffer_write(io, bytes)
    return length(bytes)
end

function Base.write(io::ChannelBuffer, data::AbstractString)
    bytes = Vector{UInt8}(codeunits(data))
    _channelbuffer_write(io, bytes)
    return length(bytes)
end

function Base.write(io::ChannelBuffer, b::UInt8)
    _channelbuffer_write(io, UInt8[b])
    return 1
end

function Base.flush(io::ChannelBuffer)
    io.closed && return nothing
    channel = io.channel
    channel === nothing && return nothing
    channel_thread_is_callers_thread(channel) && return nothing
    lock(io.cond)
    try
        while io.pending_writes > 0 && !io.closed
            wait(io.cond)
        end
        io.write_error == AWS_OP_SUCCESS || error("ChannelBuffer write failed: $(io.write_error)")
    finally
        unlock(io.cond)
    end
    return nothing
end

function Base.unsafe_write(io::ChannelBuffer, p::Ptr{UInt8}, n::UInt)
    nbytes = Int(n)
    nbytes == 0 && return 0
    data = Vector{UInt8}(undef, nbytes)
    GC.@preserve data begin
        unsafe_copyto!(pointer(data), p, nbytes)
    end
    _channelbuffer_write(io, data)
    return nbytes
end

function Reseau.setchannelslot!(handler::ChannelBufferHandler, slot::ChannelSlot)::Nothing
    handler.slot = slot
    return nothing
end

function Reseau.handler_process_read_message(
        handler::ChannelBufferHandler,
        slot::ChannelSlot,
        message::IoMessage,
    )::Union{Nothing, ErrorResult}
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
    slot.channel !== nothing && channel_release_message_to_pool!(slot.channel, message)
    return nothing
end

function Reseau.handler_process_write_message(
        handler::ChannelBufferHandler,
        slot::ChannelSlot,
        message::IoMessage,
    )::Union{Nothing, ErrorResult}
    _ = handler
    _ = slot
    _ = message
    raise_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
    return ErrorResult(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
end

function Reseau.handler_increment_read_window(
        handler::ChannelBufferHandler,
        slot::ChannelSlot,
        size::Csize_t,
    )::Union{Nothing, ErrorResult}
    _ = handler
    return channel_slot_increment_read_window!(slot, size)
end

function Reseau.handler_shutdown(
        handler::ChannelBufferHandler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Union{Nothing, ErrorResult}
    _channelbuffer_mark_closed!(handler.io, error_code)
    return channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
end

function Reseau.handler_initial_window_size(handler::ChannelBufferHandler)::Csize_t
    return Csize_t(handler.io.initial_window_size)
end

function Reseau.handler_message_overhead(handler::ChannelBufferHandler)::Csize_t
    _ = handler
    return Csize_t(0)
end

function Reseau.handler_destroy(handler::ChannelBufferHandler)::Nothing
    _ = handler
    return nothing
end
