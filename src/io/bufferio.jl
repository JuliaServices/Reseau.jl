# BufferIOChannel - BufferIO adapter for AwsIO channels

import BufferIO
using BufferIO: AbstractBufReader, AbstractBufWriter, ImmutableMemoryView, MemoryView, MutableMemoryView, IOError, IOErrorKinds, IOReader, IOWriter

mutable struct BufferIOChannel <: IO
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
    read_segments::Vector{Vector{UInt8}}
    read_head::Int
    read_segment_pos::Int
    read_available::Int
    write_buffer::Vector{UInt8}
    write_len::Int
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

struct BufferIOChannelReader <: AbstractBufReader
    io::BufferIOChannel
end

struct BufferIOChannelWriter <: AbstractBufWriter
    io::BufferIOChannel
end

const _BUFFERIOCHANNEL_DEFAULT_LOCK = ReentrantLock()
const _BUFFERIOCHANNEL_DEFAULT_ELG = Ref{Union{EventLoopGroup, Nothing}}(nothing)
const _BUFFERIOCHANNEL_DEFAULT_RESOLVER = Ref{Union{DefaultHostResolver, Nothing}}(nothing)

function _bufferiochannel_default_resources()
    lock(_BUFFERIOCHANNEL_DEFAULT_LOCK)
    try
        if _BUFFERIOCHANNEL_DEFAULT_ELG[] === nothing
            elg = EventLoopGroup(EventLoopGroupOptions(; loop_count = 1))
            elg isa ErrorResult && error("Failed to create EventLoopGroup: $(elg.code)")
            resolver = DefaultHostResolver(elg)
            _BUFFERIOCHANNEL_DEFAULT_ELG[] = elg
            _BUFFERIOCHANNEL_DEFAULT_RESOLVER[] = resolver
        end
        return _BUFFERIOCHANNEL_DEFAULT_ELG[]::EventLoopGroup, _BUFFERIOCHANNEL_DEFAULT_RESOLVER[]::DefaultHostResolver
    finally
        unlock(_BUFFERIOCHANNEL_DEFAULT_LOCK)
    end
end

mutable struct BufferIOChannelHandler <: AbstractChannelHandler
    slot::Union{ChannelSlot, Nothing}
    io::BufferIOChannel
end

function BufferIOChannelHandler(io::BufferIOChannel)
    return BufferIOChannelHandler(nothing, io)
end

mutable struct BufferIOChannelWriteContext
    io::BufferIOChannel
    remaining::Int
    error_code::Int
end

@inline function bufferio_reader(io::BufferIOChannel)::BufferIOChannelReader
    return BufferIOChannelReader(io)
end

@inline function bufferio_writer(io::BufferIOChannel)::BufferIOChannelWriter
    return BufferIOChannelWriter(io)
end

@inline function _bufferio_ioreader(io::BufferIOChannel)
    return IOReader(bufferio_reader(io))
end

@inline function _bufferiochannel_require_open(io::BufferIOChannel)::Nothing
    io.closed && throw(IOError(IOErrorKinds.ClosedIO))
    return nothing
end

function _bufferiochannel_compact_segments!(io::BufferIOChannel)::Nothing
    io.read_head <= 32 && return nothing
    io.read_head <= (length(io.read_segments) ÷ 2) && return nothing
    io.read_segments = copy(io.read_segments[io.read_head:end])
    io.read_head = 1
    return nothing
end

function _bufferiochannel_mark_closed!(io::BufferIOChannel, error_code::Int)::Nothing
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

function _bufferiochannel_install_handler!(io::BufferIOChannel, channel::Channel)::Nothing
    handler = BufferIOChannelHandler(io)
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

function _bufferiochannel_on_setup(bootstrap, error_code::Int, channel, io::BufferIOChannel)
    _ = bootstrap
    if error_code != AWS_OP_SUCCESS || channel === nothing
        io.connect_error = error_code
        _bufferiochannel_mark_closed!(io, error_code)
        notify(io.connect_event)
        return nothing
    end
    if channel_thread_is_callers_thread(channel)
        _bufferiochannel_install_handler!(io, channel)
        io.connect_error = AWS_OP_SUCCESS
        notify(io.connect_event)
        return nothing
    end
    task = ChannelTask(
        (t, ctx, status) -> begin
            _ = t
            status == TaskStatus.RUN_READY || return nothing
            _bufferiochannel_install_handler!(ctx.io, ctx.channel)
            ctx.io.connect_error = AWS_OP_SUCCESS
            notify(ctx.io.connect_event)
            return nothing
        end,
        (io = io, channel = channel),
        "bufferiochannel_install_handler",
    )
    channel_schedule_task_now!(channel, task)
    return nothing
end

function _bufferiochannel_on_shutdown(bootstrap, error_code::Int, channel, io::BufferIOChannel)
    _ = bootstrap
    _ = channel
    _bufferiochannel_mark_closed!(io, error_code)
    return nothing
end

function BufferIOChannel(
        host::AbstractString,
        port::Integer;
        tls::Bool = false,
        enable_read_back_pressure::Bool = false,
        connect_timeout_ms::Integer = 3000,
        read_buffer_capacity::Integer = 65536,
        write_buffer_capacity::Integer = 4096,
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
    read_buffer_capacity < 1 && throw(ArgumentError("read_buffer_capacity must be >= 1"))
    write_buffer_capacity < 1 && throw(ArgumentError("write_buffer_capacity must be >= 1"))
    initial_window = initial_window_size === nothing ? Int(read_buffer_capacity) : Int(initial_window_size)
    elg = event_loop_group
    resolver = host_resolver
    owns_elg = false
    owns_resolver = false
    if elg === nothing
        elg, resolver = _bufferiochannel_default_resources()
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
    io = BufferIOChannel(
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
        Vector{UInt8}[],
        1,
        1,
        0,
        Vector{UInt8}(undef, Int(write_buffer_capacity)),
        0,
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
        on_setup = _bufferiochannel_on_setup,
        on_shutdown = _bufferiochannel_on_shutdown,
        user_data = io,
        enable_read_back_pressure = enable_read_back_pressure,
    )
    result isa ErrorResult && error("BufferIOChannel connect failed: $(result.code)")
    wait(io.connect_event)
    io.connect_error == AWS_OP_SUCCESS || error("BufferIOChannel connect failed: $(io.connect_error)")
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

function Base.isopen(io::BufferIOChannel)::Bool
    return !io.closed
end

function Base.close(io::BufferIOChannel)::Nothing
    io.closed && return nothing
    _bufferiochannel_mark_closed!(io, ERROR_IO_SOCKET_CLOSED)
    channel = io.channel
    channel !== nothing && channel_shutdown!(channel, ERROR_IO_SOCKET_CLOSED)
    io.socket !== nothing && socket_close(io.socket)
    io.owns_host_resolver && host_resolver_shutdown!(io.host_resolver)
    io.owns_event_loop_group && event_loop_group_release!(io.event_loop_group)
    return nothing
end

function Base.bytesavailable(io::BufferIOChannel)::Int
    lock(io.cond)
    try
        return io.read_available
    finally
        unlock(io.cond)
    end
end

function BufferIO.get_buffer(reader::BufferIOChannelReader)::ImmutableMemoryView{UInt8}
    io = reader.io
    lock(io.cond)
    try
        io.read_available == 0 && return ImmutableMemoryView(UInt8[])
        io.read_head > length(io.read_segments) && return ImmutableMemoryView(UInt8[])
        segment = io.read_segments[io.read_head]
        view = @inbounds ImmutableMemoryView(segment)[io.read_segment_pos:end]
        return view
    finally
        unlock(io.cond)
    end
end

function BufferIO.fill_buffer(reader::BufferIOChannelReader)::Int
    io = reader.io
    lock(io.cond)
    try
        io.read_available > 0 && return 0
        while io.read_available == 0 && !io.closed
            wait(io.cond)
        end
        io.read_available == 0 && return 0
        return io.read_available
    finally
        unlock(io.cond)
    end
end

function BufferIO.consume(reader::BufferIOChannelReader, n::Int)::Nothing
    io = reader.io
    n < 0 && throw(IOError(IOErrorKinds.ConsumeBufferError))
    lock(io.cond)
    try
        n > io.read_available && throw(IOError(IOErrorKinds.ConsumeBufferError))
        remaining = n
        while remaining > 0
            segment = io.read_segments[io.read_head]
            seg_remaining = length(segment) - io.read_segment_pos + 1
            if remaining < seg_remaining
                io.read_segment_pos += remaining
                io.read_available -= remaining
                remaining = 0
            else
                io.read_available -= seg_remaining
                io.read_head += 1
                io.read_segment_pos = 1
                remaining -= seg_remaining
            end
        end
        if io.read_available == 0
            empty!(io.read_segments)
            io.read_head = 1
            io.read_segment_pos = 1
        else
            _bufferiochannel_compact_segments!(io)
        end
        if io.enable_read_back_pressure && io.slot !== nothing && n > 0
            channel_slot_increment_read_window!(io.slot, Csize_t(n))
        end
    finally
        unlock(io.cond)
    end
    return nothing
end

function Base.bytesavailable(reader::BufferIOChannelReader)::Int
    io = reader.io
    lock(io.cond)
    try
        return io.read_available
    finally
        unlock(io.cond)
    end
end

function Base.close(reader::BufferIOChannelReader)::Nothing
    close(reader.io)
    return nothing
end

function BufferIO.get_buffer(writer::BufferIOChannelWriter)::MutableMemoryView{UInt8}
    io = writer.io
    _bufferiochannel_require_open(io)
    return @inbounds MemoryView(io.write_buffer)[(io.write_len + 1):end]
end

function BufferIO.get_unflushed(writer::BufferIOChannelWriter)::MutableMemoryView{UInt8}
    io = writer.io
    return @inbounds MemoryView(io.write_buffer)[1:(io.write_len)]
end

function BufferIO.consume(writer::BufferIOChannelWriter, n::Int)::Nothing
    io = writer.io
    _bufferiochannel_require_open(io)
    n < 0 && throw(IOError(IOErrorKinds.ConsumeBufferError))
    (io.write_len + n) > length(io.write_buffer) && throw(IOError(IOErrorKinds.ConsumeBufferError))
    io.write_len += n
    return nothing
end

function BufferIO.shallow_flush(writer::BufferIOChannelWriter)::Int
    io = writer.io
    _bufferiochannel_require_open(io)
    io.write_len == 0 && return 0
    data = Vector{UInt8}(undef, io.write_len)
    copyto!(data, 1, io.write_buffer, 1, io.write_len)
    io.write_len = 0
    _bufferiochannel_write(io, data)
    return length(data)
end

function BufferIO.grow_buffer(writer::BufferIOChannelWriter)::Int
    io = writer.io
    _bufferiochannel_require_open(io)
    io.write_len > 0 && return BufferIO.shallow_flush(writer)
    old_size = length(io.write_buffer)
    new_size = max(old_size * 2, 1)
    resize!(io.write_buffer, new_size)
    return new_size - old_size
end

function Base.flush(writer::BufferIOChannelWriter)::Nothing
    _ = BufferIO.shallow_flush(writer)
    _bufferiochannel_wait_writes(writer.io)
    return nothing
end

function Base.close(writer::BufferIOChannelWriter)::Nothing
    io = writer.io
    io.closed && return nothing
    flush(writer)
    close(io)
    return nothing
end

function Base.unsafe_read(io::BufferIOChannel, p::Ptr{UInt8}, n::UInt)
    return unsafe_read(_bufferio_ioreader(io), p, n)
end

function Base.read!(io::BufferIOChannel, A::AbstractArray{UInt8})
    return read!(_bufferio_ioreader(io), A)
end

function Base.readbytes!(io::BufferIOChannel, b::AbstractVector{UInt8}, nb::Integer = length(b))
    return readbytes!(_bufferio_ioreader(io), b, nb)
end

function Base.read(io::BufferIOChannel, n::Integer)
    return read(_bufferio_ioreader(io), n)
end

function Base.read(io::BufferIOChannel, ::Type{UInt8})
    return read(_bufferio_ioreader(io), UInt8)
end

function Base.read(io::BufferIOChannel, ::Type{String})
    return read(_bufferio_ioreader(io), String)
end

function Base.readavailable(io::BufferIOChannel)
    return readavailable(_bufferio_ioreader(io))
end

function Base.peek(io::BufferIOChannel, ::Type{UInt8})
    return peek(_bufferio_ioreader(io), UInt8)
end

function Base.eof(io::BufferIOChannel)::Bool
    return eof(bufferio_reader(io))
end

function Base.skip(io::BufferIOChannel, n::Integer)
    return skip(bufferio_reader(io), n)
end

function Base.write(io::BufferIOChannel, data::StridedVector{UInt8})
    bytes = data isa Vector{UInt8} ? data : Vector{UInt8}(data)
    return write(bufferio_writer(io), bytes)
end

function Base.write(io::BufferIOChannel, data::AbstractVector{UInt8})
    bytes = Vector{UInt8}(data)
    return write(bufferio_writer(io), bytes)
end

function Base.write(io::BufferIOChannel, data::Union{String, SubString{String}})
    return write(bufferio_writer(io), data)
end

function Base.write(io::BufferIOChannel, data::AbstractString)
    return write(bufferio_writer(io), data)
end

function Base.write(io::BufferIOChannel, b::UInt8)
    return write(bufferio_writer(io), b)
end

function Base.unsafe_write(io::BufferIOChannel, p::Ptr{UInt8}, n::UInt)
    return unsafe_write(bufferio_writer(io), p, n)
end

function Base.flush(io::BufferIOChannel)::Nothing
    flush(bufferio_writer(io))
    return nothing
end

function _bufferiochannel_tls_context(; ssl_cert::Union{String, Nothing}, ssl_key::Union{String, Nothing}, ssl_cacert::Union{String, Nothing}, ssl_capath::Union{String, Nothing}, ssl_insecure::Bool)::TlsContext
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
        io::BufferIOChannel;
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
    channel === nothing && error("BufferIOChannel is not connected")
    socket_slot = channel_first_slot(channel)
    socket_slot === nothing && error("BufferIOChannel has no socket slot")
    ctx = _bufferiochannel_tls_context(
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
            "bufferiochannel_tls_setup",
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

function _bufferiochannel_begin_write!(io::BufferIOChannel)::BufferIOChannelWriteContext
    lock(io.cond)
    try
        io.pending_writes += 1
    finally
        unlock(io.cond)
    end
    return BufferIOChannelWriteContext(io, 0, AWS_OP_SUCCESS)
end

function _bufferiochannel_finish_write!(ctx::BufferIOChannelWriteContext)::Nothing
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

function _bufferiochannel_write_fail!(ctx::BufferIOChannelWriteContext, error_code::Int)::ErrorResult
    ctx.error_code == AWS_OP_SUCCESS && (ctx.error_code = error_code)
    ctx.remaining == 0 && _bufferiochannel_finish_write!(ctx)
    return ErrorResult(error_code)
end

function _bufferiochannel_on_write_complete(channel, message::IoMessage, error_code::Int, user_data)::Nothing
    _ = channel
    _ = message
    ctx = user_data::BufferIOChannelWriteContext
    error_code != AWS_OP_SUCCESS && ctx.error_code == AWS_OP_SUCCESS && (ctx.error_code = error_code)
    ctx.remaining -= 1
    if ctx.remaining <= 0
        _bufferiochannel_finish_write!(ctx)
    end
    return nothing
end

function _bufferiochannel_write_now(io::BufferIOChannel, data::Vector{UInt8}, ctx::BufferIOChannelWriteContext)
    channel = io.channel
    slot = io.slot
    channel === nothing && return _bufferiochannel_write_fail!(ctx, ERROR_IO_SOCKET_NOT_CONNECTED)
    slot === nothing && return _bufferiochannel_write_fail!(ctx, ERROR_IO_SOCKET_NOT_CONNECTED)
    remaining = length(data)
    cursor_ref = Ref(ByteCursor(data))
    while remaining > 0
        msg = channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, remaining)
        msg === nothing && return _bufferiochannel_write_fail!(ctx, ERROR_OOM)
        chunk_size = min(remaining, Int(capacity(msg.message_data) - msg.message_data.len))
        chunk_cursor = byte_cursor_advance(cursor_ref, chunk_size)
        msg_ref = Ref(msg.message_data)
        byte_buf_write_from_whole_cursor(msg_ref, chunk_cursor)
        msg.message_data = msg_ref[]
        ctx.remaining += 1
        msg.on_completion = _bufferiochannel_on_write_complete
        msg.user_data = ctx
        send_res = channel_slot_send_message(slot, msg, ChannelDirection.WRITE)
        if send_res isa ErrorResult
            ctx.remaining -= 1
            channel_release_message_to_pool!(channel, msg)
            return _bufferiochannel_write_fail!(ctx, send_res.code)
        end
        remaining -= chunk_size
    end
    return nothing
end

function _bufferiochannel_write(io::BufferIOChannel, data::Vector{UInt8})::Nothing
    io.closed && throw(EOFError())
    channel = io.channel
    channel === nothing && throw(EOFError())
    isempty(data) && return nothing
    ctx = _bufferiochannel_begin_write!(io)
    if channel_thread_is_callers_thread(channel)
        res = _bufferiochannel_write_now(io, data, ctx)
        if res isa ErrorResult
            error("BufferIOChannel write failed: $(res.code)")
        end
        return nothing
    end
    task = ChannelTask(
        (t, ctx, status) -> begin
            _ = t
            status == TaskStatus.RUN_READY || return nothing
            _ = _bufferiochannel_write_now(ctx.io, ctx.data, ctx.write_ctx)
            return nothing
        end,
        (io = io, data = data, write_ctx = ctx),
        "bufferiochannel_write",
    )
    channel_schedule_task_now!(channel, task)
    return nothing
end

function _bufferiochannel_wait_writes(io::BufferIOChannel)::Nothing
    lock(io.cond)
    try
        while io.pending_writes > 0 && !io.closed
            wait(io.cond)
        end
        io.write_error == AWS_OP_SUCCESS || error("BufferIOChannel write failed: $(io.write_error)")
    finally
        unlock(io.cond)
    end
    return nothing
end

function AwsIO.setchannelslot!(handler::BufferIOChannelHandler, slot::ChannelSlot)::Nothing
    handler.slot = slot
    return nothing
end

function AwsIO.handler_process_read_message(handler::BufferIOChannelHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    io = handler.io
    data_len = Int(message.message_data.len)
    if data_len > 0
        data = Vector{UInt8}(undef, data_len)
        copyto!(data, 1, message.message_data.mem, 1, data_len)
        lock(io.cond)
        try
            push!(io.read_segments, data)
            io.read_available += data_len
            notify(io.cond)
        finally
            unlock(io.cond)
        end
    end
    slot.channel !== nothing && channel_release_message_to_pool!(slot.channel, message)
    return nothing
end

function AwsIO.handler_process_write_message(handler::BufferIOChannelHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    _ = handler
    _ = slot
    _ = message
    raise_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
    return ErrorResult(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
end

function AwsIO.handler_increment_read_window(handler::BufferIOChannelHandler, slot::ChannelSlot, size::Csize_t)::Union{Nothing, ErrorResult}
    _ = handler
    return channel_slot_increment_read_window!(slot, size)
end

function AwsIO.handler_shutdown(handler::BufferIOChannelHandler, slot::ChannelSlot, direction::ChannelDirection.T, error_code::Int, free_scarce_resources_immediately::Bool)::Union{Nothing, ErrorResult}
    _bufferiochannel_mark_closed!(handler.io, error_code)
    return channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
end

function AwsIO.handler_initial_window_size(handler::BufferIOChannelHandler)::Csize_t
    return Csize_t(handler.io.initial_window_size)
end

function AwsIO.handler_message_overhead(handler::BufferIOChannelHandler)::Csize_t
    _ = handler
    return Csize_t(0)
end

function AwsIO.handler_destroy(handler::BufferIOChannelHandler)::Nothing
    _ = handler
    return nothing
end
