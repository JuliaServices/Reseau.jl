# TLS channel handler (MVP)

using MbedTLS

const TlsOnNegotiationResultFn = Function  # (handler, slot, error_code, user_data) -> nothing
const TlsOnDataReadFn = Function           # (handler, slot, buffer, user_data) -> nothing
const TlsOnErrorFn = Function              # (handler, slot, error_code, message, user_data) -> nothing

struct TlsContextOptions
    is_server::Bool
    verify_peer::Bool
    ca_file::Union{String, Nothing}
    ca_data::Union{String, Nothing}
    certificate::Union{String, Nothing}
    private_key::Union{String, Nothing}
end

function TlsContextOptions(;
        is_server::Bool = false,
        verify_peer::Bool = true,
        ca_file::Union{String, Nothing} = nothing,
        ca_data::Union{String, Nothing} = nothing,
        certificate::Union{String, Nothing} = nothing,
        private_key::Union{String, Nothing} = nothing,
    )
    return TlsContextOptions(
        is_server,
        verify_peer,
        ca_file,
        ca_data,
        certificate,
        private_key,
    )
end

mutable struct TlsContext
    config::MbedTLS.SSLConfig
    is_server::Bool
end

function tls_context_new(options::TlsContextOptions)::Union{TlsContext, ErrorResult}
    conf = MbedTLS.SSLConfig()
    entropy = MbedTLS.Entropy()
    rng = MbedTLS.CtrDrbg()

    try
        endpoint = options.is_server ? MbedTLS.MBEDTLS_SSL_IS_SERVER : MbedTLS.MBEDTLS_SSL_IS_CLIENT
        MbedTLS.config_defaults!(conf; endpoint = endpoint)
        MbedTLS.seed!(rng, entropy)
        MbedTLS.rng!(conf, rng)

        if options.is_server
            if options.certificate === nothing || options.private_key === nothing
                raise_error(ERROR_IO_TLS_CTX_ERROR)
                return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
            end

            cert = isfile(options.certificate) ? MbedTLS.crt_parse_file(options.certificate) :
                MbedTLS.crt_parse(options.certificate)
            key = isfile(options.private_key) ? MbedTLS.parse_keyfile(options.private_key) :
                MbedTLS.parse_key(options.private_key)

            MbedTLS.own_cert!(conf, cert, key)
        else
            MbedTLS.authmode!(conf, options.verify_peer ? MbedTLS.MBEDTLS_SSL_VERIFY_REQUIRED : MbedTLS.MBEDTLS_SSL_VERIFY_NONE)

            if options.ca_data !== nothing
                chain = MbedTLS.crt_parse(options.ca_data)
                MbedTLS.ca_chain!(conf, chain)
            elseif options.ca_file !== nothing
                chain = MbedTLS.crt_parse_file(options.ca_file)
                MbedTLS.ca_chain!(conf, chain)
            else
                MbedTLS.ca_chain!(conf)
            end
        end
    catch err
        logf(LogLevel.ERROR, LS_IO_TLS, "TLS context init failed: $err")
        raise_error(ERROR_IO_TLS_CTX_ERROR)
        return ErrorResult(ERROR_IO_TLS_CTX_ERROR)
    end

    return TlsContext(conf, options.is_server)
end

function tls_context_new_client(;
        verify_peer::Bool = true,
        ca_file::Union{String, Nothing} = nothing,
        ca_data::Union{String, Nothing} = nothing,
    )
    return tls_context_new(
        TlsContextOptions(;
            is_server = false,
            verify_peer = verify_peer,
            ca_file = ca_file,
            ca_data = ca_data,
        )
    )
end

function tls_context_new_server(;
        certificate::String,
        private_key::String,
    )
    return tls_context_new(
        TlsContextOptions(;
            is_server = true,
            verify_peer = false,
            certificate = certificate,
            private_key = private_key,
        )
    )
end

struct TlsConnectionOptions{C <: TlsContext, FNR <: Union{TlsOnNegotiationResultFn, Nothing}, FDR <: Union{TlsOnDataReadFn, Nothing}, FER <: Union{TlsOnErrorFn, Nothing}, U}
    ctx::C
    server_name::Union{String, Nothing}
    on_negotiation_result::FNR
    on_data_read::FDR
    on_error::FER
    user_data::U
    timeout_ms::UInt32
end

function TlsConnectionOptions(
        ctx::TlsContext;
        server_name::Union{String, Nothing} = nothing,
        on_negotiation_result::Union{TlsOnNegotiationResultFn, Nothing} = nothing,
        on_data_read::Union{TlsOnDataReadFn, Nothing} = nothing,
        on_error::Union{TlsOnErrorFn, Nothing} = nothing,
        user_data = nothing,
        timeout_ms::Integer = 0,
    )
    return TlsConnectionOptions(
        ctx,
        server_name,
        on_negotiation_result,
        on_data_read,
        on_error,
        user_data,
        UInt32(timeout_ms),
    )
end

mutable struct TlsBio <: IO
    status::Int
    in_buf::Vector{UInt8}
    in_offset::Int
    out_buf::Vector{UInt8}
    out_offset::Int
    open::Bool
end

function TlsBio()
    return TlsBio(Base.StatusOpen, UInt8[], 0, UInt8[], 0, true)
end

Base.isopen(bio::TlsBio) = bio.open
Base.isreadable(bio::TlsBio) = bio.open
Base.bytesavailable(bio::TlsBio) = max(0, length(bio.in_buf) - bio.in_offset)
Base.eof(bio::TlsBio) = !bio.open && Base.bytesavailable(bio) == 0

function Base.close(bio::TlsBio)
    bio.open = false
    bio.status = Base.StatusClosing
    return nothing
end

function Base.unsafe_read(bio::TlsBio, buf::Ptr{UInt8}, nbytes::UInt)
    available = length(bio.in_buf) - bio.in_offset
    if available <= 0
        return 0
    end

    n = min(Int(nbytes), available)
    unsafe_copyto!(buf, pointer(bio.in_buf, bio.in_offset + 1), n)
    bio.in_offset += n

    if bio.in_offset >= length(bio.in_buf)
        empty!(bio.in_buf)
        bio.in_offset = 0
    end

    return n
end

function Base.unsafe_write(bio::TlsBio, buf::Ptr{UInt8}, nbytes::UInt)
    n = Int(nbytes)
    if n == 0
        return 0
    end

    old_len = length(bio.out_buf)
    resize!(bio.out_buf, old_len + n)
    unsafe_copyto!(pointer(bio.out_buf, old_len + 1), buf, n)
    return n
end

function _bio_append_input!(bio::TlsBio, ptr::Ptr{UInt8}, len::Int)
    if len <= 0
        return nothing
    end

    old_len = length(bio.in_buf)
    resize!(bio.in_buf, old_len + len)
    unsafe_copyto!(pointer(bio.in_buf, old_len + 1), ptr, len)
    return nothing
end

function _bio_pending_output(bio::TlsBio)::Int
    return max(0, length(bio.out_buf) - bio.out_offset)
end

function _bio_take_output!(bio::TlsBio, ptr::Ptr{UInt8}, len::Int)::Int
    available = _bio_pending_output(bio)
    if available <= 0
        return 0
    end

    n = min(len, available)
    unsafe_copyto!(ptr, pointer(bio.out_buf, bio.out_offset + 1), n)
    bio.out_offset += n

    if bio.out_offset >= length(bio.out_buf)
        empty!(bio.out_buf)
        bio.out_offset = 0
    end

    return n
end

mutable struct PendingWrite
    message::IoMessage
    offset::Int
end

mutable struct TlsChannelHandler{FNR <: Union{TlsOnNegotiationResultFn, Nothing}, FDR <: Union{TlsOnDataReadFn, Nothing}, FER <: Union{TlsOnErrorFn, Nothing}, U} <: AbstractChannelHandler
    slot::Union{ChannelSlot, Nothing}
    ctx::MbedTLS.SSLContext
    bio::TlsBio
    negotiation_completed::Bool
    pending_writes::Vector{PendingWrite}
    max_read_size::Csize_t
    options::TlsConnectionOptions{TlsContext, FNR, FDR, FER, U}
end

function TlsChannelHandler(
        options::TlsConnectionOptions;
        max_read_size::Integer = 16384,
    )
    ssl_ctx = MbedTLS.SSLContext()
    MbedTLS.setup!(ssl_ctx, options.ctx.config)

    if options.server_name !== nothing && !options.ctx.is_server
        MbedTLS.hostname!(ssl_ctx, options.server_name)
    end

    bio = TlsBio()
    MbedTLS.set_bio!(ssl_ctx, bio)

    return TlsChannelHandler(
        nothing,
        ssl_ctx,
        bio,
        false,
        PendingWrite[],
        Csize_t(max_read_size),
        options,
    )
end

function tls_channel_handler_new!(channel::Channel, options::TlsConnectionOptions; max_read_size::Integer = 16384)
    handler = TlsChannelHandler(options; max_read_size = max_read_size)
    slot = channel_slot_new!(channel)
    handler.slot = slot
    channel_slot_set_handler!(slot, handler)

    if channel.last === nothing
        channel_slot_insert_end!(channel, slot)
    else
        channel_slot_insert_left!(slot, channel.last)
    end

    tls_channel_handler_start_negotiation!(handler)

    return handler
end

function tls_channel_handler_start_negotiation!(handler::TlsChannelHandler)
    if handler.slot !== nothing && handler.slot.adj_right !== nothing
        right_handler = handler.slot.adj_right.handler
        if right_handler isa SocketChannelHandler
            _socket_handler_trigger_read(right_handler)
        end
    end
    _tls_drive_negotiation!(handler)
    return nothing
end

function _tls_drive_negotiation!(handler::TlsChannelHandler)
    if handler.negotiation_completed
        return nothing
    end

    while true
        result = MbedTLS.ssl_handshake(handler.ctx)

        if result == 0
            handler.negotiation_completed = true
            _tls_flush_output!(handler)
            if handler.options.on_negotiation_result !== nothing && handler.slot !== nothing
                Base.invokelatest(
                    handler.options.on_negotiation_result,
                    handler,
                    handler.slot,
                    AWS_OP_SUCCESS,
                    handler.options.user_data,
                )
            end
            _tls_flush_pending_writes!(handler)
            return nothing
        end

        if result == MbedTLS.MBEDTLS_ERR_SSL_WANT_READ || result == MbedTLS.MBEDTLS_ERR_SSL_WANT_WRITE
            _tls_flush_output!(handler)
            return nothing
        end

        _tls_flush_output!(handler)
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE, "TLS handshake failed")
        return nothing
    end
    return
end

function _tls_report_error!(handler::TlsChannelHandler, error_code::Int, message::AbstractString)
    if handler.options.on_error !== nothing && handler.slot !== nothing
        Base.invokelatest(
            handler.options.on_error,
            handler,
            handler.slot,
            error_code,
            message,
            handler.options.user_data,
        )
    end

    if handler.slot !== nothing && handler.slot.channel !== nothing
        channel_shutdown!(handler.slot.channel, ChannelDirection.READ, error_code)
    end

    return nothing
end

function _tls_flush_output!(handler::TlsChannelHandler)
    slot = handler.slot
    if slot === nothing || slot.channel === nothing
        return nothing
    end

    channel = slot.channel
    while true
        pending = _bio_pending_output(handler.bio)
        if pending <= 0
            break
        end

        msg = channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, pending)
        if msg === nothing
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_WRITE_FAILURE, "TLS output alloc failed")
            return nothing
        end

        buf_ref = Ref(msg.message_data)
        byte_buf_reserve(buf_ref, pending)
        msg.message_data = buf_ref[]
        buf = msg.message_data

        GC.@preserve buf begin
            wrote = _bio_take_output!(handler.bio, pointer(getfield(buf, :mem)), pending)
            setfield!(buf, :len, Csize_t(wrote))
        end

        send_result = channel_slot_send_message(slot, msg, ChannelDirection.WRITE)
        if send_result isa ErrorResult
            channel_release_message_to_pool!(channel, msg)
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_WRITE_FAILURE, "TLS output send failed")
            return nothing
        end
    end

    return nothing
end

function _tls_flush_pending_writes!(handler::TlsChannelHandler)
    if isempty(handler.pending_writes)
        return nothing
    end

    idx = 1
    while idx <= length(handler.pending_writes)
        pending = handler.pending_writes[idx]
        done = _tls_encrypt_from_offset!(handler, pending)
        if done
            deleteat!(handler.pending_writes, idx)
        else
            return nothing
        end
    end

    return nothing
end

function _tls_encrypt_from_offset!(handler::TlsChannelHandler, pending::PendingWrite)::Bool
    slot = handler.slot
    if slot === nothing || slot.channel === nothing
        return true
    end

    channel = slot.channel
    message = pending.message
    buf = message.message_data
    total = Int(buf.len)
    offset = pending.offset

    if offset >= total
        channel_release_message_to_pool!(channel, message)
        return true
    end

    GC.@preserve buf begin
        ptr = pointer(getfield(buf, :mem)) + offset
        while offset < total
            remaining = total - offset
            result = MbedTLS.ssl_write(handler.ctx, ptr, remaining)

            if result > 0
                offset += result
                ptr += result
                pending.offset = offset
                _tls_flush_output!(handler)
                continue
            end

            if result == MbedTLS.MBEDTLS_ERR_SSL_WANT_READ || result == MbedTLS.MBEDTLS_ERR_SSL_WANT_WRITE
                _tls_flush_output!(handler)
                pending.offset = offset
                return false
            end

            channel_release_message_to_pool!(channel, message)
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_WRITE_FAILURE, "TLS write failed")
            return true
        end
    end

    channel_release_message_to_pool!(channel, message)
    return true
end

function _tls_read_available!(handler::TlsChannelHandler)
    slot = handler.slot
    if slot === nothing || slot.channel === nothing
        return nothing
    end

    channel = slot.channel
    while true
        msg = channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, handler.max_read_size)
        if msg === nothing
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_READ_FAILURE, "TLS read alloc failed")
            return nothing
        end

        buf_ref = Ref(msg.message_data)
        byte_buf_reserve(buf_ref, handler.max_read_size)
        msg.message_data = buf_ref[]
        buf = msg.message_data

        result = 0
        GC.@preserve buf begin
            result = MbedTLS.ssl_read(handler.ctx, pointer(getfield(buf, :mem)), handler.max_read_size)
        end

        if result > 0
            setfield!(buf, :len, Csize_t(result))
            if handler.options.on_data_read !== nothing && slot.adj_left === nothing
                Base.invokelatest(handler.options.on_data_read, handler, slot, buf, handler.options.user_data)
                channel_release_message_to_pool!(channel, msg)
            else
                send_result = channel_slot_send_message(slot, msg, ChannelDirection.READ)
                if send_result isa ErrorResult
                    channel_release_message_to_pool!(channel, msg)
                    _tls_report_error!(handler, ERROR_IO_TLS_ERROR_READ_FAILURE, "TLS read send failed")
                    return nothing
                end
            end
            continue
        end

        channel_release_message_to_pool!(channel, msg)

        if result == 0 || result == MbedTLS.MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY
            _tls_report_error!(handler, ERROR_IO_TLS_CLOSED_GRACEFUL, "TLS peer closed")
            return nothing
        end

        if result == MbedTLS.MBEDTLS_ERR_SSL_WANT_READ || result == MbedTLS.MBEDTLS_ERR_SSL_WANT_WRITE
            return nothing
        end

        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_READ_FAILURE, "TLS read failed")
        return nothing
    end
    return
end

function handler_process_read_message(handler::TlsChannelHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    channel = slot.channel
    buf = message.message_data
    data_len = Int(buf.len)

    if data_len > 0
        GC.@preserve buf begin
            _bio_append_input!(handler.bio, pointer(getfield(buf, :mem)), data_len)
        end
    end

    if channel !== nothing
        channel_release_message_to_pool!(channel, message)
    end

    if !handler.negotiation_completed
        _tls_drive_negotiation!(handler)
        if !handler.negotiation_completed
            return nothing
        end
    end

    _tls_read_available!(handler)
    _tls_flush_pending_writes!(handler)
    return nothing
end

function handler_process_write_message(handler::TlsChannelHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    if !handler.negotiation_completed
        push!(handler.pending_writes, PendingWrite(message, 0))
        _tls_drive_negotiation!(handler)
        return nothing
    end

    pending = PendingWrite(message, 0)
    done = _tls_encrypt_from_offset!(handler, pending)
    if !done
        push!(handler.pending_writes, pending)
    end
    return nothing
end

function handler_increment_read_window(handler::TlsChannelHandler, slot::ChannelSlot, size::Csize_t)::Union{Nothing, ErrorResult}
    return channel_slot_increment_read_window!(slot, size)
end

function handler_shutdown(handler::TlsChannelHandler, slot::ChannelSlot, direction::ChannelDirection.T, error_code::Int)::Union{Nothing, ErrorResult}
    if !handler.negotiation_completed
        if handler.options.on_negotiation_result !== nothing
            Base.invokelatest(handler.options.on_negotiation_result, handler, slot, error_code, handler.options.user_data)
        end
    end

    Base.close(handler.bio)
    channel_slot_on_handler_shutdown_complete!(slot, direction, false, true)
    return nothing
end

function handler_initial_window_size(handler::TlsChannelHandler)::Csize_t
    return SIZE_MAX
end

function handler_message_overhead(handler::TlsChannelHandler)::Csize_t
    return Csize_t(0)
end

function handler_destroy(handler::TlsChannelHandler)::Nothing
    Base.close(handler.bio)
    return nothing
end

function handler_trigger_write(handler::TlsChannelHandler)::Nothing
    _tls_flush_pending_writes!(handler)
    _tls_flush_output!(handler)
    return nothing
end
