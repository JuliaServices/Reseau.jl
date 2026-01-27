# AWS IO Library - ALPN Handler
# Port of aws-c-io/source/alpn_handler.c

mutable struct AlpnHandler{F <: Union{ChannelOnProtocolNegotiatedFn, Nothing}, U, SlotRef <: Union{ChannelSlot, Nothing}} <: AbstractChannelHandler
    slot::SlotRef
    on_protocol_negotiated::F
    user_data::U
end

function AlpnHandler(on_protocol_negotiated::F, user_data) where {F}
    return AlpnHandler{F, typeof(user_data), Union{ChannelSlot, Nothing}}(nothing, on_protocol_negotiated, user_data)
end

function tls_alpn_handler_new(on_protocol_negotiated::ChannelOnProtocolNegotiatedFn, user_data = nothing)
    return AlpnHandler(on_protocol_negotiated, user_data)
end

function _alpn_extract_protocol(message::IoMessage)::Union{ByteBuffer, Nothing}
    if message.user_data isa TlsNegotiatedProtocolMessage
        return (message.user_data::TlsNegotiatedProtocolMessage).protocol
    end
    return nothing
end

function handler_process_read_message(handler::AlpnHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    if message.message_tag != TLS_NEGOTIATED_PROTOCOL_MESSAGE
        raise_error(ERROR_IO_MISSING_ALPN_MESSAGE)
        return ErrorResult(ERROR_IO_MISSING_ALPN_MESSAGE)
    end

    protocol = _alpn_extract_protocol(message)
    if protocol === nothing
        raise_error(ERROR_IO_MISSING_ALPN_MESSAGE)
        return ErrorResult(ERROR_IO_MISSING_ALPN_MESSAGE)
    end

    channel = slot.channel
    if channel === nothing
        raise_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
        return ErrorResult(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
    end

    new_slot = channel_slot_new!(channel)
    new_handler = handler.on_protocol_negotiated(new_slot, protocol, handler.user_data)

    if new_handler === nothing
        channel_release_message_to_pool!(channel, message)
        raise_error(ERROR_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE)
        return ErrorResult(ERROR_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE)
    end

    channel_slot_replace!(slot, new_slot)
    channel_slot_set_handler!(new_slot, new_handler)
    if hasproperty(new_handler, :slot)
        try
            setfield!(new_handler, :slot, new_slot)
        catch
        end
    end
    _channel_calculate_message_overheads!(channel)
    channel_release_message_to_pool!(channel, message)
    return nothing
end

function handler_process_write_message(handler::AlpnHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    logf(LogLevel.ERROR, LS_IO_ALPN, "ALPN handler received unexpected write message")
    raise_error(ERROR_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE)
    return ErrorResult(ERROR_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE)
end

function handler_increment_read_window(handler::AlpnHandler, slot::ChannelSlot, size::Csize_t)::Union{Nothing, ErrorResult}
    logf(LogLevel.ERROR, LS_IO_ALPN, "ALPN handler does not accept window increments")
    raise_error(ERROR_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE)
    return ErrorResult(ERROR_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE)
end

function handler_shutdown(handler::AlpnHandler, slot::ChannelSlot, direction::ChannelDirection.T, error_code::Int)::Union{Nothing, ErrorResult}
    channel_slot_on_handler_shutdown_complete!(slot, direction, false, true)
    return nothing
end

function handler_initial_window_size(handler::AlpnHandler)::Csize_t
    return Csize_t(sizeof(TlsNegotiatedProtocolMessage))
end

function handler_message_overhead(handler::AlpnHandler)::Csize_t
    return Csize_t(0)
end

function handler_destroy(handler::AlpnHandler)::Nothing
    handler.slot = nothing
    return nothing
end
