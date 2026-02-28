# s2n TLS backend (Linux)
# Included by src/sockets/socket/tls_channel_handler.jl

# Backend registration (s2n extension on Linux)
#
# On Linux, s2n is provided by s2n_tls_jll. JLLWrappers exports `libs2n` as a String path,
# and also provides `libs2n_handle` as a dlopen() handle. We accept either, but always
# convert to a handle for dlsym()/ccall().
const _s2n_lib = Ref{Union{Nothing, String, Ptr{Cvoid}}}(nothing)
const _s2n_available = Ref(false)

function _register_s2n_lib!(lib)
    if lib isa Ptr{Cvoid}
        _s2n_lib[] = lib
        _s2n_available[] = lib != C_NULL
    elseif lib isa AbstractString
        lib_str = String(lib)
        _s2n_lib[] = lib_str
        _s2n_available[] = !isempty(lib_str)
    else
        # Best-effort: allow passing a library product-like object.
        try
            handle = Base.unsafe_convert(Ptr{Cvoid}, lib)
            _s2n_lib[] = handle
            _s2n_available[] = handle != C_NULL
        catch
            _s2n_lib[] = nothing
            _s2n_available[] = false
        end
    end

    # The library may change from path -> handle; drop any cached symbols.
    lock(_s2n_symbol_lock) do
        empty!(_s2n_symbol_cache)
    end

    return nothing
end

@inline function _s2n_lib_handle()::Ptr{Cvoid}
    lib = _s2n_lib[]
    if lib === nothing
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end

    if lib isa Ptr{Cvoid}
        lib == C_NULL && throw_error(ERROR_IO_TLS_CTX_ERROR)
        return lib
    end

    # `s2n_tls_jll.libs2n` is a path String on Julia >= 1.6 (JLLWrappers).
    isempty(lib) && throw_error(ERROR_IO_TLS_CTX_ERROR)

    flags = @static isdefined(Libdl, :RTLD_DEEPBIND) ? (Libdl.RTLD_LAZY | Libdl.RTLD_DEEPBIND) : Libdl.RTLD_LAZY
    try
        handle = Libdl.dlopen(lib, flags)
        _s2n_lib[] = handle
        lock(_s2n_symbol_lock) do
            empty!(_s2n_symbol_cache)
        end
        return handle
    catch
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end
end

const _s2n_symbol_cache = Dict{Symbol, Ptr{Cvoid}}()
const _s2n_symbol_lock = ReentrantLock()

function _s2n_symbol(sym::Symbol)::Ptr{Cvoid}
    lib = try
        _s2n_lib_handle()
    catch
        return C_NULL
    end
    return lock(_s2n_symbol_lock) do
        get!(_s2n_symbol_cache, sym) do
            try
                return Libdl.dlsym(lib, sym)
            catch
                return C_NULL
            end
        end
    end
end


# === s2n TLS backend (Linux) ===
const S2N_SUCCESS = 0
const S2N_FAILURE = -1
const S2N_SERVER = 0
const S2N_CLIENT = 1
const S2N_NOT_BLOCKED = 0
const S2N_BLOCKED_ON_READ = 1
const S2N_BLOCKED_ON_WRITE = 2
const S2N_BLOCKED_ON_APPLICATION_INPUT = 3
const S2N_BLOCKED_ON_EARLY_DATA = 4

const S2N_ERR_T_OK = 0
const S2N_ERR_T_IO = 1
const S2N_ERR_T_BLOCKED = 2
const S2N_ERR_T_ALERT = 3
const S2N_ERR_T_PROTO = 4
const S2N_ERR_T_INTERNAL = 5
const S2N_ERR_T_USAGE = 6

const S2N_CERT_AUTH_NONE = 0
const S2N_CERT_AUTH_REQUIRED = 1
const S2N_CERT_AUTH_OPTIONAL = 2

const S2N_SELF_SERVICE_BLINDING = 1
const S2N_STATUS_REQUEST_OCSP = 1

const S2N_TLS_MAX_FRAG_LEN_512 = 1
const S2N_TLS_MAX_FRAG_LEN_1024 = 2
const S2N_TLS_MAX_FRAG_LEN_2048 = 3
const S2N_TLS_MAX_FRAG_LEN_4096 = 4

const S2N_ASYNC_SIGN = 1
const S2N_ASYNC_DECRYPT = 2

const S2N_TLS_SIGNATURE_RSA = 1
const S2N_TLS_SIGNATURE_ECDSA = 3

const S2N_TLS_HASH_SHA1 = 2
const S2N_TLS_HASH_SHA224 = 3
const S2N_TLS_HASH_SHA256 = 4
const S2N_TLS_HASH_SHA384 = 5
const S2N_TLS_HASH_SHA512 = 6

const S2N_OCSP_ACTION_ENABLE = 1
const S2N_OCSP_ACTION_IGNORE = 2
const S2N_OCSP_ACTION_FAIL = 3

const _s2n_initialized = Ref(false)
const _s2n_initialized_externally = Ref(false)
const _s2n_init_lock = ReentrantLock()
const _s2n_default_ca_dir = Ref{Union{Nothing, String}}(nothing)
const _s2n_default_ca_file = Ref{Union{Nothing, String}}(nothing)

@inline function _s2n_errno()
    ptr = _s2n_symbol(:s2n_errno)
    ptr == C_NULL && return 0
    return unsafe_load(Ptr{Cint}(ptr))
end

@inline function _s2n_strerror(err::Int)
    fptr = _s2n_symbol(:s2n_strerror)
    fptr == C_NULL && return "<s2n unavailable>"
    msg_ptr = ccall(fptr, Cstring, (Cint, Cstring), err, "EN")
    msg_ptr == C_NULL && return "<s2n null error string>"
    return unsafe_string(msg_ptr)
end

@inline function _s2n_strerror_debug(err::Int)
    fptr = _s2n_symbol(:s2n_strerror_debug)
    fptr == C_NULL && return "<s2n unavailable>"
    msg_ptr = ccall(fptr, Cstring, (Cint, Cstring), err, "EN")
    msg_ptr == C_NULL && return "<s2n null debug string>"
    return unsafe_string(msg_ptr)
end

@inline function _s2n_error_get_type(err::Int)::Cint
    fptr = _s2n_symbol(:s2n_error_get_type)
    fptr == C_NULL && return Cint(S2N_ERR_T_INTERNAL)
    return ccall(fptr, Cint, (Cint,), err)
end

function _s2n_init_once()
    @static if !Sys.islinux()
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end
    !_s2n_available[] && return nothing
    _s2n_initialized[] && return nothing

    lock(_s2n_init_lock) do
        _s2n_initialized[] && return nothing

        _s2n_lib_handle()
        _s2n_init_callbacks()

        disable_atexit = _s2n_symbol(:s2n_disable_atexit)
        disable_atexit == C_NULL && throw_error(ERROR_IO_TLS_CTX_ERROR)
        rc = ccall(disable_atexit, Cint, ())

        if rc != 0
            _s2n_initialized_externally[] = true
        else
            _s2n_initialized_externally[] = false

            s2n_init = _s2n_symbol(:s2n_init)
            s2n_init == C_NULL && throw_error(ERROR_IO_TLS_CTX_ERROR)
            if ccall(s2n_init, Cint, ()) != 0
                logf(LogLevel.ERROR, LS_IO_TLS, "s2n_init failed: $(_s2n_strerror(_s2n_errno()))")
                throw_error(ERROR_IO_TLS_CTX_ERROR)
            end
        end

        _s2n_default_ca_dir[] = determine_default_pki_dir()
        _s2n_default_ca_file[] = determine_default_pki_ca_file()
        _s2n_initialized[] = true
        return nothing
    end

    return nothing
end

function _s2n_cleanup()
    @static if Sys.islinux()
        if _s2n_initialized[] && !_s2n_initialized_externally[]
            try
                _s2n_lib_handle()
                cleanup_final = _s2n_symbol(:s2n_cleanup_final)
                cleanup_final != C_NULL && (_ = ccall(cleanup_final, Cint, ()))
            catch
            end
            _s2n_initialized[] = false
        end
    end
    return nothing
end

@static if Sys.islinux()
function EventLoops.event_loop_thread_exit_s2n_cleanup!(::EventLoops.EventLoop)::Nothing
    _s2n_cleanup_thread()
    return nothing
end
end

function _s2n_cleanup_thread()
    @static if Sys.islinux()
        try
            _s2n_lib_handle()
            cleanup_thread = _s2n_symbol(:s2n_cleanup_thread)
            cleanup_thread != C_NULL && (_ = ccall(cleanup_thread, Cint, ()))
        catch
        end
    end
    return nothing
end

function _s2n_wall_clock_time_nanoseconds(context::Ptr{Cvoid}, time_in_ns::Ptr{UInt64})::Cint
    _ = context
    if sys_clock_get_ticks(time_in_ns) != OP_SUCCESS
        unsafe_store!(time_in_ns, UInt64(0))
        return Cint(-1)
    end
    return Cint(0)
end

function _s2n_monotonic_clock_time_nanoseconds(context::Ptr{Cvoid}, time_in_ns::Ptr{UInt64})::Cint
    _ = context
    if high_res_clock_get_ticks(time_in_ns) != OP_SUCCESS
        unsafe_store!(time_in_ns, UInt64(0))
        return Cint(-1)
    end
    return Cint(0)
end

const _s2n_wall_clock_time_nanoseconds_c = Ref{Ptr{Cvoid}}(C_NULL)
const _s2n_monotonic_clock_time_nanoseconds_c = Ref{Ptr{Cvoid}}(C_NULL)

mutable struct S2nTlsCtx
    config::Ptr{Cvoid}
    custom_cert_chain_and_key::Ptr{Cvoid}
    custom_key_handler::Union{CustomKeyOpHandler, Nothing}
end

S2nTlsCtx() = S2nTlsCtx(C_NULL, C_NULL, nothing)

mutable struct S2nTlsHandler <: TlsChannelHandler
    slot::Union{ChannelSlot{Channel}, Nothing}
    tls_timeout_ms::UInt32
    stats::TlsHandlerStatistics
    timeout_task::ChannelTask{Channel}
    connection::Ptr{Cvoid}
    ctx::Union{TlsContext, Nothing}
    s2n_ctx::Union{S2nTlsCtx, Nothing}
    input_queue::Vector{IoMessage}
    protocol::ByteBuffer
    server_name::ByteBuffer
    latest_message_on_completion::Union{EventCallable, Nothing}
    tls_negotiation_result::Future{Cint}
    on_data_read::Union{TlsDataReadCallback, Nothing}
    advertise_alpn_message::Bool
    state::TlsNegotiationState.T
    read_task::ChannelTask{Channel}
    read_task_pending::Bool
    read_state::TlsHandlerReadState.T
    shutdown_error_code::Int
    delayed_shutdown_task::ChannelTask{Channel}
    negotiation_task::ChannelTask{Channel}
end

function setchannelslot!(handler::S2nTlsHandler, slot::ChannelSlot{Channel})::Nothing
    handler.slot = slot
    return nothing
end

function _byte_buf_from_c_str(ptr::Ptr{Cchar})::ByteBuffer
    ptr == C_NULL && return null_buffer()
    len = ccall(:strlen, Csize_t, (Cstring,), ptr)
    if len == 0
        return null_buffer()
    end
    buf = ByteBuffer(Int(len))
    unsafe_copyto!(pointer(buf.mem), Ptr{UInt8}(ptr), Int(len))
    setfield!(buf, :len, len)
    return buf
end

function _byte_buf_from_string(value::AbstractString)::ByteBuffer
    bytes = codeunits(value)
    if isempty(bytes)
        return null_buffer()
    end
    buf = ByteBuffer(length(bytes))
    copyto!(buf.mem, 1, bytes, 1, length(bytes))
    setfield!(buf, :len, Csize_t(length(bytes)))
    return buf
end

function _s2n_generic_read(handler::S2nTlsHandler, buf_ptr::Ptr{UInt8}, len::UInt32)::Cint
    written = 0
    queue = handler.input_queue
    while !isempty(queue) && written < len
        message = popfirst!(queue)
        message === nothing && break
        msg = message::IoMessage
        remaining_message_len = Int(msg.message_data.len) - Int(msg.copy_mark)
        remaining_buf_len = Int(len) - written
        to_write = remaining_message_len < remaining_buf_len ? remaining_message_len : remaining_buf_len

        if to_write > 0
            src_ptr = pointer(msg.message_data.mem) + Int(msg.copy_mark)
            unsafe_copyto!(buf_ptr + written, src_ptr, to_write)
            written += to_write
            msg.copy_mark += Csize_t(to_write)
        end

        if msg.copy_mark == msg.message_data.len
            if msg.owning_channel isa Channel
                channel_release_message_to_pool!(msg.owning_channel, msg)
            end
        else
            pushfirst!(queue, msg)
        end
    end

    if written > 0
        return Cint(written)
    end

    Base.Libc.errno(Base.Libc.EAGAIN)
    return Cint(-1)
end

function _s2n_generic_send(handler::S2nTlsHandler, buf_ptr::Ptr{UInt8}, len::UInt32)::Cint
    slot = handler.slot
    slot === nothing && return Cint(-1)
    channel_slot_is_attached(slot) || return Cint(-1)
    channel = slot.channel
    processed = 0

    while processed < len
        overhead = channel_slot_upstream_message_overhead(slot)
        message_size_hint = Csize_t(len - processed) + overhead
        message = channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, message_size_hint)
        message === nothing && return Cint(-1)

        if message.message_data.capacity <= overhead
            channel_release_message_to_pool!(channel, message)
            Base.Libc.errno(Base.Libc.ENOMEM)
            return Cint(-1)
        end

        available = Int(message.message_data.capacity - overhead)
        to_write = min(available, Int(len) - processed)

        mem = unsafe_wrap(Memory{UInt8}, buf_ptr + processed, to_write; own = false)
        chunk = ByteCursor(mem, to_write)
        buf_ref = Ref(message.message_data)
        if byte_buf_append(buf_ref, chunk) != OP_SUCCESS
            channel_release_message_to_pool!(channel, message)
            return Cint(-1)
        end
        message.message_data = buf_ref[]
        processed += Int(message.message_data.len)

        if processed == len
            message.on_completion = handler.latest_message_on_completion
            handler.latest_message_on_completion = nothing
        end

        try
            channel_slot_send_message(slot, message, ChannelDirection.WRITE)
        catch e
            channel_release_message_to_pool!(channel, message)
            if e isa ReseauError
                Base.Libc.errno(Base.Libc.EPIPE)
            else
                Base.Libc.errno(Base.Libc.EIO)
            end
            return Cint(-1)
        end
    end

    if processed > 0
        return Cint(processed)
    end

    Base.Libc.errno(Base.Libc.EAGAIN)
    return Cint(-1)
end

function _s2n_handler_recv(io_context::Ptr{Cvoid}, buf::Ptr{UInt8}, len::UInt32)::Cint
    try
        handler = unsafe_pointer_to_objref(io_context)::S2nTlsHandler
        return _s2n_generic_read(handler, buf, len)
    catch
        Base.Libc.errno(Base.Libc.EIO)
        return Cint(-1)
    end
end

function _s2n_handler_send(io_context::Ptr{Cvoid}, buf::Ptr{UInt8}, len::UInt32)::Cint
    try
        handler = unsafe_pointer_to_objref(io_context)::S2nTlsHandler
        return _s2n_generic_send(handler, buf, len)
    catch
        Base.Libc.errno(Base.Libc.EIO)
        return Cint(-1)
    end
end

const _s2n_handler_recv_c = Ref{Ptr{Cvoid}}(C_NULL)
const _s2n_handler_send_c = Ref{Ptr{Cvoid}}(C_NULL)

function _s2n_finish_negotiation(handler::S2nTlsHandler, error_code::Int)
    tls_on_negotiation_completed(handler, error_code)
    _complete_setup!(error_code, handler.slot.channel)
    return nothing
end

@inline function _s2n_fail_pending_negotiation!(handler::S2nTlsHandler, error_code::Int)::Nothing
    if handler.state == TlsNegotiationState.ONGOING
        handler.state = TlsNegotiationState.FAILED
        err = error_code == OP_SUCCESS ? ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE : error_code
        _s2n_finish_negotiation(handler, err)
    end
    return nothing
end

function _s2n_send_alpn_message(handler::S2nTlsHandler)
    slot = handler.slot
    slot === nothing && return nothing
    channel_slot_is_attached(slot) || return nothing
    slot.adj_right === nothing && return nothing
    handler.advertise_alpn_message || return nothing
    handler.protocol.len == 0 && return nothing
    channel = slot.channel

    message = channel_acquire_message_from_pool(
        channel,
        IoMessageType.APPLICATION_DATA,
        sizeof(TlsNegotiatedProtocolMessage),
    )
    message === nothing && return nothing
    message.message_tag = TLS_NEGOTIATED_PROTOCOL_MESSAGE
    message.negotiated_protocol = byte_buffer_as_string(handler.protocol)
    setfield!(message.message_data, :len, Csize_t(sizeof(TlsNegotiatedProtocolMessage)))
    try
        channel_slot_send_message(slot, message, ChannelDirection.READ)
    catch e
        e isa ReseauError || rethrow()
        channel_release_message_to_pool!(channel, message)
        channel_shutdown!(channel, e.code)
    end
    return nothing
end

function _s2n_drive_negotiation(handler::S2nTlsHandler)::Nothing
    handler.state == TlsNegotiationState.ONGOING || return nothing
    tls_on_drive_negotiation(handler)

    _s2n_lib_handle()

    blocked = Ref{Cint}(S2N_NOT_BLOCKED)
    while true
        negotiation_code = ccall(_s2n_symbol(:s2n_negotiate), Cint, (Ptr{Cvoid}, Ptr{Cint}), handler.connection, blocked)

        if negotiation_code == S2N_SUCCESS
            handler.state = TlsNegotiationState.SUCCEEDED
            protocol_ptr = ccall(_s2n_symbol(:s2n_get_application_protocol), Ptr{Cchar}, (Ptr{Cvoid},), handler.connection)
            if protocol_ptr != C_NULL
                handler.protocol = _byte_buf_from_c_str(protocol_ptr)
            end
            server_name_ptr = ccall(_s2n_symbol(:s2n_get_server_name), Ptr{Cchar}, (Ptr{Cvoid},), handler.connection)
            if server_name_ptr != C_NULL
                handler.server_name = _byte_buf_from_c_str(server_name_ptr)
            end
            _s2n_send_alpn_message(handler)
            _s2n_finish_negotiation(handler, OP_SUCCESS)
            return nothing
        end

        # Trust the blocked out-param first; when blocked, negotiation needs another I/O tick.
        if blocked[] != S2N_NOT_BLOCKED
            return nothing
        end

        s2n_error = _s2n_errno()
        if _s2n_error_get_type(s2n_error) != S2N_ERR_T_BLOCKED
            if _s2n_error_get_type(s2n_error) == S2N_ERR_T_ALERT
                alert_code = ccall(_s2n_symbol(:s2n_connection_get_alert), Cint, (Ptr{Cvoid},), handler.connection)
                logf(LogLevel.DEBUG, LS_IO_TLS, "s2n alert code $alert_code")
            end
            logf(
                LogLevel.WARN,
                LS_IO_TLS,string("s2n negotiate failed: $(_s2n_strerror(s2n_error)) ($(_s2n_strerror_debug(s2n_error)))", " ", ))
            handler.state = TlsNegotiationState.FAILED
            _s2n_finish_negotiation(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
            throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
        end
    end
end

function _s2n_negotiation_task(handler::S2nTlsHandler, status::TaskStatus.T)
    status == TaskStatus.RUN_READY || return nothing
    handler.state == TlsNegotiationState.ONGOING || return nothing
    _s2n_drive_negotiation(handler)
    return nothing
end

function _s2n_delayed_shutdown_task(handler::S2nTlsHandler, status::TaskStatus.T)
    if status == TaskStatus.RUN_READY
        try
            _s2n_lib_handle()
            blocked = Ref{Cint}(S2N_NOT_BLOCKED)
            _ = ccall(_s2n_symbol(:s2n_shutdown), Cint, (Ptr{Cvoid}, Ptr{Cint}), handler.connection, blocked)
        catch
        end
    end
    slot = handler.slot
    slot === nothing && return nothing
    channel_slot_on_handler_shutdown_complete!(
        slot,
        ChannelDirection.WRITE,
        handler.shutdown_error_code,
        false,
    )
    return nothing
end

function _s2n_read_task(handler::S2nTlsHandler, status::TaskStatus.T)
    status == TaskStatus.RUN_READY || return nothing
    handler.read_task_pending = false
    if handler.slot !== nothing
        handler_process_read_message(handler, handler.slot, nothing)
    end
    return nothing
end

function _s2n_initialize_read_delay_shutdown(handler::S2nTlsHandler, slot::ChannelSlot, error_code::Int)
    logf(
        LogLevel.DEBUG,
        LS_IO_TLS,string("TLS handler pending data during shutdown, waiting for downstream read window.", " ", ))
    if channel_slot_downstream_read_window(slot) == 0
        logf(
            LogLevel.WARN,
            LS_IO_TLS,string("TLS shutdown delayed; pending data cannot be processed until read window opens.", " ", ))
    end
    handler.read_state = TlsHandlerReadState.SHUTTING_DOWN
    handler.shutdown_error_code = error_code
    if !handler.read_task_pending
        handler.read_task_pending = true
        channel_task_init!(handler.read_task, EventCallable(s -> _s2n_read_task(handler, _coerce_task_status(s))), "s2n_read_on_delay_shutdown")
        channel_schedule_task_now!(slot.channel, handler.read_task)
    end
    return nothing
end

function _s2n_do_delayed_shutdown(handler::S2nTlsHandler, slot::ChannelSlot, error_code::Int)::Nothing
    handler.shutdown_error_code = error_code
    _s2n_lib_handle()
    delay = ccall(_s2n_symbol(:s2n_connection_get_delay), UInt64, (Ptr{Cvoid},), handler.connection)
    now = channel_current_clock_time(slot.channel)
    channel_schedule_task_future!(slot.channel, handler.delayed_shutdown_task, now + delay)
    return nothing
end

function _parse_alpn_list(alpn_list::String)::Vector{String}
    parts = split(alpn_list, ';'; keepempty = false)
    isempty(parts) && throw_error(ERROR_IO_TLS_CTX_ERROR)
    if length(parts) > 4
        parts = parts[1:4]
    end
    return String.(parts)
end

function _s2n_set_protocol_preferences_config(config::Ptr{Cvoid}, alpn_list::String)::Nothing
    protocols = _parse_alpn_list(alpn_list)
    _s2n_lib_handle()

    count = length(protocols)
    ptrs = Memory{Ptr{UInt8}}(undef, count)
    buffers = Vector{Memory{UInt8}}(undef, count)
    for (i, proto) in enumerate(protocols)
        bytes = codeunits(proto)
        mem = Memory{UInt8}(undef, length(bytes) + 1)
        if !isempty(bytes)
            copyto!(mem, 1, bytes, 1, length(bytes))
        end
        mem[length(bytes) + 1] = 0x00
        buffers[i] = mem
        ptrs[i] = pointer(mem)
    end

    res = GC.@preserve buffers ptrs begin
        ccall(
            _s2n_symbol(:s2n_config_set_protocol_preferences),
            Cint,
            (Ptr{Cvoid}, Ptr{Ptr{UInt8}}, Cint),
            config,
            pointer(ptrs),
            Cint(count),
        )
    end

    if res != S2N_SUCCESS
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end
    return nothing
end

function _s2n_set_protocol_preferences_connection(conn::Ptr{Cvoid}, alpn_list::String)::Nothing
    protocols = _parse_alpn_list(alpn_list)
    _s2n_lib_handle()

    count = length(protocols)
    ptrs = Memory{Ptr{UInt8}}(undef, count)
    buffers = Vector{Memory{UInt8}}(undef, count)
    for (i, proto) in enumerate(protocols)
        bytes = codeunits(proto)
        mem = Memory{UInt8}(undef, length(bytes) + 1)
        if !isempty(bytes)
            copyto!(mem, 1, bytes, 1, length(bytes))
        end
        mem[length(bytes) + 1] = 0x00
        buffers[i] = mem
        ptrs[i] = pointer(mem)
    end

    res = GC.@preserve buffers ptrs begin
        ccall(
            _s2n_symbol(:s2n_connection_set_protocol_preferences),
            Cint,
            (Ptr{Cvoid}, Ptr{Ptr{UInt8}}, Cint),
            conn,
            pointer(ptrs),
            Cint(count),
        )
    end

    if res != S2N_SUCCESS
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end
    return nothing
end

# S2N handler interface implementations
function handler_initial_window_size(handler::S2nTlsHandler)::Csize_t
    _ = handler
    return Csize_t(TLS_EST_HANDSHAKE_SIZE)
end

function handler_message_overhead(handler::S2nTlsHandler)::Csize_t
    _ = handler
    return Csize_t(TLS_EST_RECORD_OVERHEAD)
end

function handler_destroy(handler::S2nTlsHandler)::Nothing
    while !isempty(handler.input_queue)
        msg = popfirst!(handler.input_queue)
        if msg isa IoMessage && msg.owning_channel isa Channel
            channel_release_message_to_pool!(msg.owning_channel, msg)
        end
    end
    if handler.connection != C_NULL
        try
            _s2n_lib_handle()
            _ = ccall(_s2n_symbol(:s2n_connection_free), Cint, (Ptr{Cvoid},), handler.connection)
        catch
        end
        handler.connection = C_NULL
    end
    handler.protocol = null_buffer()
    handler.server_name = null_buffer()
    handler.slot = nothing
    handler.ctx = nothing
    handler.s2n_ctx = nothing
    return nothing
end

function handler_reset_statistics(handler::S2nTlsHandler)::Nothing
    crt_statistics_tls_reset!(handler.stats)
    return nothing
end

function handler_gather_statistics(handler::S2nTlsHandler)
    return handler.stats
end

function handler_process_read_message(
        handler::S2nTlsHandler,
        slot::ChannelSlot,
        message::Union{IoMessage, Nothing},
    )::Nothing
    if handler.read_state == TlsHandlerReadState.SHUT_DOWN_COMPLETE
        message !== nothing && message.owning_channel isa Channel && channel_release_message_to_pool!(message.owning_channel, message)
        return nothing
    end

    if handler.state == TlsNegotiationState.FAILED
        throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
    end

    if message !== nothing
        push!(handler.input_queue, message)

        if handler.state == TlsNegotiationState.ONGOING
            message_len = message.message_data.len
            try
                _s2n_drive_negotiation(handler)
            catch e
                e isa ReseauError || rethrow()
                channel_shutdown!(slot.channel, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                return nothing
            end
            channel_slot_increment_read_window!(slot, message_len)
            if handler.state == TlsNegotiationState.ONGOING
                return nothing
            end
        end
    end

    _s2n_lib_handle()

    if slot.adj_right === nothing
        downstream_window = SIZE_MAX
    else
        downstream_window = channel_slot_downstream_read_window(slot)
    end
    processed = Csize_t(0)
    shutdown_error_code = 0
    force_shutdown = false

    while processed < downstream_window
        outgoing = channel_acquire_message_from_pool(
            slot.channel,
            IoMessageType.APPLICATION_DATA,
            downstream_window - processed,
        )
        outgoing === nothing && break

        blocked = Ref{Cint}(S2N_NOT_BLOCKED)
        read_val = ccall(
            _s2n_symbol(:s2n_recv),
            Int,
            (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{Cint}),
            handler.connection,
            pointer(outgoing.message_data.mem),
            outgoing.message_data.capacity,
            blocked,
        )

        if read_val == 0
            channel_release_message_to_pool!(slot.channel, outgoing)
            force_shutdown = true
            break
        end

        if read_val < 0
            channel_release_message_to_pool!(slot.channel, outgoing)
            if blocked[] != S2N_NOT_BLOCKED
                if handler.read_state == TlsHandlerReadState.SHUTTING_DOWN
                    break
                end
                break
            end
            s2n_err = _s2n_errno()
            err_type = _s2n_error_get_type(s2n_err)
            if err_type == S2N_ERR_T_BLOCKED
                if handler.read_state == TlsHandlerReadState.SHUTTING_DOWN
                    break
                end
                break
            end
            logf(
                LogLevel.ERROR,
                LS_IO_TLS,string("s2n recv failed: $(_s2n_strerror(s2n_err)) ($(_s2n_strerror_debug(s2n_err)))", " ", ))
            shutdown_error_code = ERROR_IO_TLS_ERROR_READ_FAILURE
            break
        end

        processed += Csize_t(read_val)
        setfield!(outgoing.message_data, :len, Csize_t(read_val))

        if handler.on_data_read !== nothing
            handler.on_data_read(handler, slot, outgoing.message_data)
        end

        if slot.adj_right !== nothing
            try
                channel_slot_send_message(slot, outgoing, ChannelDirection.READ)
            catch e
                e isa ReseauError || rethrow()
                channel_release_message_to_pool!(slot.channel, outgoing)
                shutdown_error_code = e.code
                break
            end
        else
            channel_release_message_to_pool!(slot.channel, outgoing)
        end
    end

    if force_shutdown || shutdown_error_code != 0 ||
            (handler.read_state == TlsHandlerReadState.SHUTTING_DOWN && processed < downstream_window)
        if handler.read_state == TlsHandlerReadState.SHUTTING_DOWN
            if handler.shutdown_error_code != 0
                shutdown_error_code = handler.shutdown_error_code
            end
            handler.read_state = TlsHandlerReadState.SHUT_DOWN_COMPLETE
            channel_slot_on_handler_shutdown_complete!(
                slot,
                ChannelDirection.READ,
                shutdown_error_code,
                false,
            )
        else
            channel_shutdown!(slot.channel, shutdown_error_code)
        end
    end

    return nothing
end

function handler_process_write_message(
        handler::S2nTlsHandler,
        slot::ChannelSlot,
        message::IoMessage,
    )::Nothing
    _ = slot
    if handler.state != TlsNegotiationState.SUCCEEDED
        throw_error(ERROR_IO_TLS_ERROR_NOT_NEGOTIATED)
    end

    handler.latest_message_on_completion = message.on_completion

    _s2n_lib_handle()
    blocked = Ref{Cint}(S2N_NOT_BLOCKED)
    write_val = ccall(
        _s2n_symbol(:s2n_send),
        Int,
        (Ptr{Cvoid}, Ptr{UInt8}, Csize_t, Ptr{Cint}),
        handler.connection,
        pointer(message.message_data.mem),
        message.message_data.len,
        blocked,
    )

    if write_val < Int(message.message_data.len)
        throw_error(ERROR_IO_TLS_ERROR_WRITE_FAILURE)
    end

    channel_release_message_to_pool!(slot.channel, message)
    return nothing
end

function handler_shutdown(
        handler::S2nTlsHandler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Nothing
    abort_immediately = free_scarce_resources_immediately

    if direction == ChannelDirection.READ
        _s2n_fail_pending_negotiation!(handler, error_code)
        if !abort_immediately &&
                handler.state == TlsNegotiationState.SUCCEEDED &&
                !isempty(handler.input_queue) &&
                slot.adj_right !== nothing
            _s2n_initialize_read_delay_shutdown(handler, slot, error_code)
            return nothing
        end
        handler.read_state = TlsHandlerReadState.SHUT_DOWN_COMPLETE
    else
        if !abort_immediately &&
                error_code != ERROR_IO_SOCKET_CLOSED &&
                slot.channel.channel_state == ChannelState.ACTIVE
            try
                _s2n_do_delayed_shutdown(handler, slot, error_code)
                return nothing
            catch
                # If delayed shutdown scheduling fails, fall through to immediate shutdown completion.
            end
        end
    end

    while !isempty(handler.input_queue)
        msg = popfirst!(handler.input_queue)
        if msg isa IoMessage && msg.owning_channel isa Channel
            channel_release_message_to_pool!(msg.owning_channel, msg)
        end
    end
    channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, abort_immediately)
    return nothing
end

function handler_increment_read_window(
        handler::S2nTlsHandler,
        slot::ChannelSlot,
        size::Csize_t,
    )::Nothing
    _ = size
    if handler.read_state == TlsHandlerReadState.SHUT_DOWN_COMPLETE
        return nothing
    end

    downstream_size = channel_slot_downstream_read_window(slot)
    current_window = slot.window_size
    record_size = Csize_t(TLS_MAX_RECORD_SIZE)
    likely_records = downstream_size == 0 ? Csize_t(0) : Csize_t(ceil(downstream_size / record_size))
    offset_size = mul_size_saturating(likely_records, Csize_t(TLS_EST_RECORD_OVERHEAD))
    total_desired = add_size_saturating(offset_size, downstream_size)

    if total_desired > current_window
        update_size = total_desired - current_window
        channel_slot_increment_read_window!(slot, update_size)
    end

    if handler.state == TlsNegotiationState.SUCCEEDED && !handler.read_task_pending
        handler.read_task_pending = true
        channel_task_init!(handler.read_task, EventCallable(s -> _s2n_read_task(handler, _coerce_task_status(s))), "s2n_read_on_window_increment")
        channel_schedule_task_now!(slot.channel, handler.read_task)
    end

    return nothing
end

function _s2n_to_tls_signature_algorithm(s2n_alg::Cint)::TlsSignatureAlgorithm.T
    return s2n_alg == S2N_TLS_SIGNATURE_RSA ? TlsSignatureAlgorithm.RSA :
        s2n_alg == S2N_TLS_SIGNATURE_ECDSA ? TlsSignatureAlgorithm.ECDSA :
        TlsSignatureAlgorithm.UNKNOWN
end

function _s2n_to_tls_hash_algorithm(s2n_alg::Cint)::TlsHashAlgorithm.T
    return s2n_alg == S2N_TLS_HASH_SHA1 ? TlsHashAlgorithm.SHA1 :
        s2n_alg == S2N_TLS_HASH_SHA224 ? TlsHashAlgorithm.SHA224 :
        s2n_alg == S2N_TLS_HASH_SHA256 ? TlsHashAlgorithm.SHA256 :
        s2n_alg == S2N_TLS_HASH_SHA384 ? TlsHashAlgorithm.SHA384 :
        s2n_alg == S2N_TLS_HASH_SHA512 ? TlsHashAlgorithm.SHA512 :
        TlsHashAlgorithm.UNKNOWN
end

@inline function _s2n_ocsp_action(set_check_rc::Cint, err_type::Cint)::Cint
    if set_check_rc == S2N_SUCCESS
        return Cint(S2N_OCSP_ACTION_ENABLE)
    end
    if err_type == S2N_ERR_T_USAGE
        return Cint(S2N_OCSP_ACTION_IGNORE)
    end
    return Cint(S2N_OCSP_ACTION_FAIL)
end

function _s2n_tls_key_operation_new(
        handler::S2nTlsHandler,
        s2n_op::Ptr{Cvoid},
    )::TlsKeyOperation
    _s2n_lib_handle()

    input_size = Ref{UInt32}(0)
    if ccall(_s2n_symbol(:s2n_async_pkey_op_get_input_size), Cint, (Ptr{Cvoid}, Ref{UInt32}), s2n_op, input_size) !=
            S2N_SUCCESS
        throw_error(ERROR_INVALID_STATE)
    end

    input_buf = ByteBuffer(Int(input_size[]))
    if input_size[] > 0
        if ccall(
                _s2n_symbol(:s2n_async_pkey_op_get_input),
                Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, UInt32),
                s2n_op,
                pointer(input_buf.mem),
                input_size[],
            ) != S2N_SUCCESS
            throw_error(ERROR_INVALID_STATE)
        end
        setfield!(input_buf, :len, Csize_t(input_size[]))
    end

    op_type = Ref{Cint}(0)
    if ccall(_s2n_symbol(:s2n_async_pkey_op_get_op_type), Cint, (Ptr{Cvoid}, Ref{Cint}), s2n_op, op_type) != S2N_SUCCESS
        throw_error(ERROR_INVALID_STATE)
    end

    operation_type = TlsKeyOperationType.UNKNOWN
    signature_algorithm = TlsSignatureAlgorithm.UNKNOWN
    digest_algorithm = TlsHashAlgorithm.UNKNOWN

    if op_type[] == S2N_ASYNC_SIGN
        operation_type = TlsKeyOperationType.SIGN
        sig_alg = Ref{Cint}(0)
        if ccall(
                _s2n_symbol(:s2n_connection_get_selected_client_cert_signature_algorithm),
                Cint,
                (Ptr{Cvoid}, Ref{Cint}),
                handler.connection,
                sig_alg,
            ) != S2N_SUCCESS
            throw_error(ERROR_INVALID_STATE)
        end
        signature_algorithm = _s2n_to_tls_signature_algorithm(sig_alg[])
        if signature_algorithm == TlsSignatureAlgorithm.UNKNOWN
            throw_error(ERROR_IO_TLS_SIGNATURE_ALGORITHM_UNSUPPORTED)
        end

        hash_alg = Ref{Cint}(0)
        if ccall(
                _s2n_symbol(:s2n_connection_get_selected_client_cert_digest_algorithm),
                Cint,
                (Ptr{Cvoid}, Ref{Cint}),
                handler.connection,
                hash_alg,
            ) != S2N_SUCCESS
            throw_error(ERROR_INVALID_STATE)
        end
        digest_algorithm = _s2n_to_tls_hash_algorithm(hash_alg[])
        if digest_algorithm == TlsHashAlgorithm.UNKNOWN
            throw_error(ERROR_IO_TLS_DIGEST_ALGORITHM_UNSUPPORTED)
        end
    elseif op_type[] == S2N_ASYNC_DECRYPT
        operation_type = TlsKeyOperationType.DECRYPT
    else
        throw_error(ERROR_INVALID_STATE)
    end

    operation = TlsKeyOperation(
        byte_cursor_from_buf(input_buf);
        operation_type = operation_type,
        signature_algorithm = signature_algorithm,
        digest_algorithm = digest_algorithm,
    )
    operation.input_buf = input_buf
    operation.s2n_op = s2n_op
    operation.s2n_handler = handler
    operation.complete_count = UInt32(0)

    return operation
end

function _s2n_async_pkey_callback(conn::Ptr{Cvoid}, s2n_op::Ptr{Cvoid})::Cint
    try
        _s2n_lib_handle()
    catch
        return Cint(S2N_FAILURE)
    end
    handler_ptr = ccall(_s2n_symbol(:s2n_connection_get_ctx), Ptr{Cvoid}, (Ptr{Cvoid},), conn)
    handler_ptr == C_NULL && return Cint(S2N_FAILURE)
    handler = unsafe_pointer_to_objref(handler_ptr)::S2nTlsHandler

    operation = try
        _s2n_tls_key_operation_new(handler, s2n_op)
    catch
        _ = ccall(_s2n_symbol(:s2n_async_pkey_op_free), Cint, (Ptr{Cvoid},), s2n_op)
        return Cint(S2N_FAILURE)
    end

    logf(
        LogLevel.DEBUG,
        LS_IO_TLS,string("Begin TLS key operation. type=$(tls_key_operation_type_str(operation.operation_type)) input_len=$(operation.input.len) signature=$(tls_signature_algorithm_str(operation.signature_algorithm)) digest=$(tls_hash_algorithm_str(operation.digest_algorithm))", " ", ))

    ctx = handler.s2n_ctx
    if ctx === nothing
        _tls_key_operation_destroy!(operation)
        return Cint(S2N_FAILURE)
    end

    custom_key_handler = ctx.custom_key_handler
    if !(custom_key_handler isa CustomKeyOpHandler)
        _tls_key_operation_destroy!(operation)
        return Cint(S2N_FAILURE)
    end
    custom_key_op_handler_perform_operation(custom_key_handler::CustomKeyOpHandler, operation)

    return Cint(S2N_SUCCESS)
end

const _s2n_async_pkey_callback_c = Ref{Ptr{Cvoid}}(C_NULL)

function _s2n_init_callbacks()::Nothing
    if _s2n_wall_clock_time_nanoseconds_c[] == C_NULL
        _s2n_wall_clock_time_nanoseconds_c[] =
            @cfunction(_s2n_wall_clock_time_nanoseconds, Cint, (Ptr{Cvoid}, Ptr{UInt64}))
    end
    if _s2n_monotonic_clock_time_nanoseconds_c[] == C_NULL
        _s2n_monotonic_clock_time_nanoseconds_c[] =
            @cfunction(_s2n_monotonic_clock_time_nanoseconds, Cint, (Ptr{Cvoid}, Ptr{UInt64}))
    end
    if _s2n_handler_recv_c[] == C_NULL
        _s2n_handler_recv_c[] = @cfunction(_s2n_handler_recv, Cint, (Ptr{Cvoid}, Ptr{UInt8}, UInt32))
    end
    if _s2n_handler_send_c[] == C_NULL
        _s2n_handler_send_c[] = @cfunction(_s2n_handler_send, Cint, (Ptr{Cvoid}, Ptr{UInt8}, UInt32))
    end
    return nothing
end

function _s2n_ctx_destroy!(ctx::S2nTlsCtx)
    try
        _s2n_lib_handle()
    catch
        return nothing
    end
    if ctx.config != C_NULL
        _ = ccall(_s2n_symbol(:s2n_config_free), Cint, (Ptr{Cvoid},), ctx.config)
        ctx.config = C_NULL
    end
    if ctx.custom_cert_chain_and_key != C_NULL
        _ = ccall(_s2n_symbol(:s2n_cert_chain_and_key_free), Cint, (Ptr{Cvoid},), ctx.custom_cert_chain_and_key)
        ctx.custom_cert_chain_and_key = C_NULL
    end
    custom_key_handler = ctx.custom_key_handler
    if custom_key_handler isa CustomKeyOpHandler && custom_key_handler.pkcs11_state isa Pkcs11KeyOpState
        _pkcs11_key_op_state_close!(custom_key_handler.pkcs11_state)
    end
    if custom_key_handler !== nothing
        ctx.custom_key_handler = nothing
    end
    return nothing
end

function _s2n_security_policy(options::TlsContextOptions)::String
    if options.custom_key_op_handler !== nothing
        if options.minimum_tls_version == TlsVersion.TLSv1_3
            logf(LogLevel.ERROR, LS_IO_TLS, "TLS 1.3 with PKCS#11 is not supported yet.")
            throw_error(ERROR_IO_TLS_VERSION_UNSUPPORTED)
        end
        return options.minimum_tls_version == TlsVersion.SSLv3 ? "CloudFront-SSL-v-3" :
            options.minimum_tls_version == TlsVersion.TLSv1 ? "CloudFront-TLS-1-0-2014" :
            options.minimum_tls_version == TlsVersion.TLSv1_1 ? "ELBSecurityPolicy-TLS-1-1-2017-01" :
            options.minimum_tls_version == TlsVersion.TLSv1_2 ? "ELBSecurityPolicy-TLS-1-2-Ext-2018-06" :
                "ELBSecurityPolicy-TLS-1-1-2017-01"
    end

    return options.minimum_tls_version == TlsVersion.SSLv3 ? "AWS-CRT-SDK-SSLv3.0-2023" :
        options.minimum_tls_version == TlsVersion.TLSv1 ? "AWS-CRT-SDK-TLSv1.0-2023" :
        options.minimum_tls_version == TlsVersion.TLSv1_1 ? "AWS-CRT-SDK-TLSv1.1-2023" :
        options.minimum_tls_version == TlsVersion.TLSv1_2 ? "AWS-CRT-SDK-TLSv1.2-2025-PQ" :
        options.minimum_tls_version == TlsVersion.TLSv1_3 ? "AWS-CRT-SDK-TLSv1.3-2025-PQ" :
        "AWS-CRT-SDK-TLSv1.0-2025-PQ"
end

function _s2n_context_new(options::TlsContextOptions)::TlsContext
    _s2n_init_once()
    _s2n_lib_handle()

    ctx_impl = S2nTlsCtx()
    ctx_impl.config = ccall(_s2n_symbol(:s2n_config_new), Ptr{Cvoid}, ())
    if ctx_impl.config == C_NULL
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end

    if ccall(
            _s2n_symbol(:s2n_config_set_wall_clock),
            Cint,
            (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            ctx_impl.config,
            _s2n_wall_clock_time_nanoseconds_c[],
            C_NULL,
        ) != S2N_SUCCESS
        logf(LogLevel.ERROR, LS_IO_TLS, "s2n: failed to set wall clock callback")
        _s2n_ctx_destroy!(ctx_impl)
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end

    if ccall(
            _s2n_symbol(:s2n_config_set_monotonic_clock),
            Cint,
            (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
            ctx_impl.config,
            _s2n_monotonic_clock_time_nanoseconds_c[],
            C_NULL,
        ) != S2N_SUCCESS
        logf(LogLevel.ERROR, LS_IO_TLS, "s2n: failed to set monotonic clock callback")
        _s2n_ctx_destroy!(ctx_impl)
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end

    policy = _s2n_security_policy(options)

    if options.cipher_pref == TlsCipherPref.TLS_CIPHER_PREF_PQ_DEFAULT
        policy = "AWS-CRT-SDK-TLSv1.2-2025-PQ"
    elseif options.cipher_pref == TlsCipherPref.TLS_CIPHER_PREF_PQ_TLSV1_2_2024_10
        policy = "AWS-CRT-SDK-TLSv1.2-2023-PQ"
    elseif options.cipher_pref == TlsCipherPref.TLS_CIPHER_PREF_TLSV1_2_2025_07
        policy = "AWS-CRT-SDK-TLSv1.2-2025"
    elseif options.cipher_pref == TlsCipherPref.TLS_CIPHER_PREF_TLSV1_0_2023_06
        policy = "AWS-CRT-SDK-TLSv1.0-2023"
    elseif options.cipher_pref != TlsCipherPref.TLS_CIPHER_PREF_SYSTEM_DEFAULT
        _s2n_ctx_destroy!(ctx_impl)
        throw_error(ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED)
    end

    if ccall(_s2n_symbol(:s2n_config_set_cipher_preferences), Cint, (Ptr{Cvoid}, Cstring), ctx_impl.config, policy) !=
            S2N_SUCCESS
        logf(
            LogLevel.ERROR,
            LS_IO_TLS,string("s2n: failed to set security policy '$policy': $(_s2n_strerror(_s2n_errno()))", " ", ))
        _s2n_ctx_destroy!(ctx_impl)
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end

    if options.certificate_set && options.private_key_set
        cert_cur = byte_cursor_from_buf(options.certificate)
        key_cur = byte_cursor_from_buf(options.private_key)
        if !_tls_text_is_ascii_or_utf8_bom(cert_cur) || !_tls_text_is_ascii_or_utf8_bom(key_cur)
            _s2n_ctx_destroy!(ctx_impl)
            throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)
        end
        cert_str = String(cert_cur)
        key_str = String(key_cur)
        if ccall(_s2n_symbol(:s2n_config_add_cert_chain_and_key), Cint, (Ptr{Cvoid}, Cstring, Cstring), ctx_impl.config, cert_str, key_str) !=
                S2N_SUCCESS
            _s2n_ctx_destroy!(ctx_impl)
            throw_error(ERROR_IO_TLS_CTX_ERROR)
        end
        if !options.is_server
            _ = ccall(_s2n_symbol(:s2n_config_set_client_auth_type), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, S2N_CERT_AUTH_REQUIRED)
        end
    elseif options.custom_key_op_handler !== nothing
        ctx_impl.custom_key_handler = custom_key_op_handler_acquire(options.custom_key_op_handler)
        if _s2n_async_pkey_callback_c[] == C_NULL
            _s2n_async_pkey_callback_c[] =
                @cfunction(_s2n_async_pkey_callback, Cint, (Ptr{Cvoid}, Ptr{Cvoid}))
        end
        if ccall(_s2n_symbol(:s2n_config_set_async_pkey_callback), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), ctx_impl.config, _s2n_async_pkey_callback_c[]) !=
                S2N_SUCCESS
            _s2n_ctx_destroy!(ctx_impl)
            throw_error(ERROR_IO_TLS_CTX_ERROR)
        end

        ctx_impl.custom_cert_chain_and_key = ccall(_s2n_symbol(:s2n_cert_chain_and_key_new), Ptr{Cvoid}, ())
        if ctx_impl.custom_cert_chain_and_key == C_NULL
            _s2n_ctx_destroy!(ctx_impl)
            throw_error(ERROR_IO_TLS_CTX_ERROR)
        end

        cert_ptr = pointer(options.certificate.mem)
        cert_len = options.certificate.len
        if ccall(_s2n_symbol(:s2n_cert_chain_and_key_load_public_pem_bytes), Cint,
                (Ptr{Cvoid}, Ptr{UInt8}, Csize_t),
                ctx_impl.custom_cert_chain_and_key,
                cert_ptr,
                cert_len) != S2N_SUCCESS
            _s2n_ctx_destroy!(ctx_impl)
            throw_error(ERROR_IO_TLS_CTX_ERROR)
        end

        if ccall(_s2n_symbol(:s2n_config_add_cert_chain_and_key_to_store), Cint, (Ptr{Cvoid}, Ptr{Cvoid}),
                ctx_impl.config, ctx_impl.custom_cert_chain_and_key) != S2N_SUCCESS
            _s2n_ctx_destroy!(ctx_impl)
            throw_error(ERROR_IO_TLS_CTX_ERROR)
        end

        if !options.is_server
            _ = ccall(_s2n_symbol(:s2n_config_set_client_auth_type), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, S2N_CERT_AUTH_REQUIRED)
        end
    end

    if options.verify_peer
        ocsp_rc = ccall(_s2n_symbol(:s2n_config_set_check_stapled_ocsp_response), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, 1)
        ocsp_err_type = ocsp_rc == S2N_SUCCESS ? Cint(S2N_ERR_T_OK) : _s2n_error_get_type(_s2n_errno())
        ocsp_action = _s2n_ocsp_action(ocsp_rc, ocsp_err_type)
        if ocsp_action == Cint(S2N_OCSP_ACTION_ENABLE)
            if ccall(_s2n_symbol(:s2n_config_set_status_request_type), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, S2N_STATUS_REQUEST_OCSP) !=
                    S2N_SUCCESS
                _s2n_ctx_destroy!(ctx_impl)
                throw_error(ERROR_IO_TLS_CTX_ERROR)
            end
        elseif ocsp_action == Cint(S2N_OCSP_ACTION_IGNORE)
            logf(LogLevel.INFO, LS_IO_TLS, "ctx: cannot enable ocsp stapling due to usage constraints")
        else
            _s2n_ctx_destroy!(ctx_impl)
            throw_error(ERROR_IO_TLS_CTX_ERROR)
        end

        if options.ca_path !== nothing || options.ca_file_set
            if ccall(_s2n_symbol(:s2n_config_wipe_trust_store), Cint, (Ptr{Cvoid},), ctx_impl.config) != S2N_SUCCESS
                _s2n_ctx_destroy!(ctx_impl)
                throw_error(ERROR_IO_TLS_CTX_ERROR)
            end
            if options.ca_path !== nothing
                if ccall(_s2n_symbol(:s2n_config_set_verification_ca_location), Cint,
                        (Ptr{Cvoid}, Cstring, Cstring),
                        ctx_impl.config,
                        C_NULL,
                        options.ca_path) != S2N_SUCCESS
                    _s2n_ctx_destroy!(ctx_impl)
                    throw_error(ERROR_IO_TLS_CTX_ERROR)
                end
            end
            if options.ca_file_set
                ca_str = String(byte_cursor_from_buf(options.ca_file))
                if ccall(_s2n_symbol(:s2n_config_add_pem_to_trust_store), Cint, (Ptr{Cvoid}, Cstring), ctx_impl.config, ca_str) !=
                        S2N_SUCCESS
                    _s2n_ctx_destroy!(ctx_impl)
                    throw_error(ERROR_IO_TLS_CTX_ERROR)
                end
            end
        elseif _s2n_default_ca_file[] !== nothing || _s2n_default_ca_dir[] !== nothing
            ca_file = _s2n_default_ca_file[] === nothing ? C_NULL : _s2n_default_ca_file[]
            ca_dir = _s2n_default_ca_dir[] === nothing ? C_NULL : _s2n_default_ca_dir[]
            if ccall(_s2n_symbol(:s2n_config_set_verification_ca_location), Cint,
                    (Ptr{Cvoid}, Cstring, Cstring),
                    ctx_impl.config,
                    ca_file,
                    ca_dir) != S2N_SUCCESS
                _s2n_ctx_destroy!(ctx_impl)
                throw_error(ERROR_IO_TLS_CTX_ERROR)
            end
        else
            _s2n_ctx_destroy!(ctx_impl)
            throw_error(ERROR_IO_TLS_ERROR_DEFAULT_TRUST_STORE_NOT_FOUND)
        end

        if options.is_server
            if ccall(_s2n_symbol(:s2n_config_set_client_auth_type), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, S2N_CERT_AUTH_REQUIRED) !=
                    S2N_SUCCESS
                _s2n_ctx_destroy!(ctx_impl)
                throw_error(ERROR_IO_TLS_CTX_ERROR)
            end
        end
    elseif !options.is_server
        _ = ccall(_s2n_symbol(:s2n_config_disable_x509_verification), Cint, (Ptr{Cvoid},), ctx_impl.config)
    end

    if options.alpn_list !== nothing
        _s2n_set_protocol_preferences_config(ctx_impl.config, options.alpn_list)
    end

    if options.max_fragment_size == 512
        _ = ccall(_s2n_symbol(:s2n_config_send_max_fragment_length), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, S2N_TLS_MAX_FRAG_LEN_512)
    elseif options.max_fragment_size == 1024
        _ = ccall(_s2n_symbol(:s2n_config_send_max_fragment_length), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, S2N_TLS_MAX_FRAG_LEN_1024)
    elseif options.max_fragment_size == 2048
        _ = ccall(_s2n_symbol(:s2n_config_send_max_fragment_length), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, S2N_TLS_MAX_FRAG_LEN_2048)
    elseif options.max_fragment_size == 4096
        _ = ccall(_s2n_symbol(:s2n_config_send_max_fragment_length), Cint, (Ptr{Cvoid}, Cint), ctx_impl.config, S2N_TLS_MAX_FRAG_LEN_4096)
    end

    ctx = TlsContext(options, ctx_impl, false)
    finalizer(ctx) do c
        c.closed && return
        c.closed = true
        if c.impl isa S2nTlsCtx
            _s2n_ctx_destroy!(c.impl)
        end
    end
    return ctx
end

function _s2n_handler_new(
        options::TlsConnectionOptions,
        slot::ChannelSlot,
        mode::Integer,
    )::S2nTlsHandler
    _s2n_lib_handle()
    _s2n_init_callbacks()

    ctx = options.ctx
    ctx.impl isa S2nTlsCtx || throw_error(ERROR_IO_TLS_CTX_ERROR)
    s2n_ctx = ctx.impl::S2nTlsCtx

    handler = S2nTlsHandler(
        slot,
        options.timeout_ms,
        TlsHandlerStatistics(),
        ChannelTask(),
        C_NULL,
        ctx,
        s2n_ctx,
        IoMessage[],
        null_buffer(),
        null_buffer(),
        nothing,
        options.tls_negotiation_result,
        options.on_data_read,
        options.advertise_alpn_message,
        TlsNegotiationState.ONGOING,
        ChannelTask(),
        false,
        TlsHandlerReadState.OPEN,
        0,
        ChannelTask(),
        ChannelTask(),
    )

    crt_statistics_tls_init!(handler.stats)
    channel_task_init!(handler.timeout_task, EventCallable(s -> _tls_timeout_task(handler, _coerce_task_status(s))), "tls_timeout")

    handler.connection = ccall(_s2n_symbol(:s2n_connection_new), Ptr{Cvoid}, (Cint,), Cint(mode))
    handler.connection == C_NULL && throw_error(ERROR_IO_TLS_CTX_ERROR)

    if options.server_name !== nothing
        handler.server_name = _byte_buf_from_string(options.server_name)
        if ccall(_s2n_symbol(:s2n_set_server_name), Cint, (Ptr{Cvoid}, Cstring), handler.connection, options.server_name) !=
                S2N_SUCCESS
            throw_error(ERROR_IO_TLS_CTX_ERROR)
        end
    end

    if ccall(_s2n_symbol(:s2n_connection_set_recv_cb), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), handler.connection, _s2n_handler_recv_c[]) !=
            S2N_SUCCESS
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end
    if ccall(
            _s2n_symbol(:s2n_connection_set_recv_ctx),
            Cint,
            (Ptr{Cvoid}, Ptr{Cvoid}),
            handler.connection,
            pointer_from_objref(handler),
        ) != S2N_SUCCESS
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end
    if ccall(_s2n_symbol(:s2n_connection_set_send_cb), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), handler.connection, _s2n_handler_send_c[]) !=
            S2N_SUCCESS
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end
    if ccall(
            _s2n_symbol(:s2n_connection_set_send_ctx),
            Cint,
            (Ptr{Cvoid}, Ptr{Cvoid}),
            handler.connection,
            pointer_from_objref(handler),
        ) != S2N_SUCCESS
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end
    if ccall(
            _s2n_symbol(:s2n_connection_set_ctx),
            Cint,
            (Ptr{Cvoid}, Ptr{Cvoid}),
            handler.connection,
            pointer_from_objref(handler),
        ) != S2N_SUCCESS
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end
    if ccall(_s2n_symbol(:s2n_connection_set_blinding), Cint, (Ptr{Cvoid}, Cint), handler.connection, S2N_SELF_SERVICE_BLINDING) !=
            S2N_SUCCESS
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end

    if options.alpn_list !== nothing
        _s2n_set_protocol_preferences_connection(handler.connection, options.alpn_list)
    end

    if ccall(_s2n_symbol(:s2n_connection_set_config), Cint, (Ptr{Cvoid}, Ptr{Cvoid}), handler.connection, s2n_ctx.config) !=
            S2N_SUCCESS
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end

    channel_task_init!(handler.delayed_shutdown_task, EventCallable(s -> _s2n_delayed_shutdown_task(handler, _coerce_task_status(s))), "s2n_delayed_shutdown")
    return handler
end
