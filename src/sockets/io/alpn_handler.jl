# AWS IO Library - ALPN Handler
# Port of aws-c-io/source/alpn_handler.c

mutable struct AlpnHandler
    slot::Union{ChannelSlot, Nothing}
    on_protocol_negotiated::Union{ProtocolNegotiatedCallable, Nothing}
end

@inline _alpn_protocol_negotiated_callback(::Nothing) = nothing
@inline _alpn_protocol_negotiated_callback(callback::ProtocolNegotiatedCallable) = callback
@inline _alpn_protocol_negotiated_callback(callback) = ProtocolNegotiatedCallable(callback)

function _alpn_protocol_negotiated_callback_or_throw(callback)
    callback === nothing && throw_error(ERROR_INVALID_ARGUMENT)
    return callback
end

function tls_alpn_handler_new(on_protocol_negotiated)
    callback = _alpn_protocol_negotiated_callback(on_protocol_negotiated)
    return AlpnHandler(nothing, _alpn_protocol_negotiated_callback_or_throw(callback))
end

function setchannelslot!(handler::AlpnHandler, slot::ChannelSlot)::Nothing
    handler.slot = slot
    return nothing
end

function _alpn_extract_protocol(message::IoMessage)::Union{ByteBuffer, Nothing}
    if message.user_data isa TlsNegotiatedProtocolMessage
        return (message.user_data::TlsNegotiatedProtocolMessage).protocol
    end
    return nothing
end

function handler_process_read_message(handler::AlpnHandler, slot::ChannelSlot, message::IoMessage)::Nothing
    if message.message_tag != TLS_NEGOTIATED_PROTOCOL_MESSAGE
        throw_error(ERROR_IO_MISSING_ALPN_MESSAGE)
    end

    protocol = _alpn_extract_protocol(message)
    if protocol === nothing
        throw_error(ERROR_IO_MISSING_ALPN_MESSAGE)
    end
    protocol_str = byte_buffer_as_string(protocol)
    chan = slot_channel_or_nothing(slot)
    chan_id = chan === nothing ? -1 : chan.channel_id
    logf(
        LogLevel.DEBUG,
        LS_IO_ALPN,string("ALPN negotiated protocol: %s (channel %d)", " ", string(isempty(protocol_str) ? "<empty>" : protocol_str), " ", string(chan_id), " ", ))

    channel = slot_channel_or_nothing(slot)
    if channel === nothing
        throw_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
    end

    new_slot = channel_slot_new!(channel)
    callback = handler.on_protocol_negotiated
    callback === nothing && throw_error(ERROR_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE)
    new_handler = callback(new_slot, protocol)

    if new_handler === nothing
        channel_release_message_to_pool!(channel, message)
        throw_error(ERROR_IO_UNHANDLED_ALPN_PROTOCOL_MESSAGE)
    end

    channel_slot_replace!(slot, new_slot)
    channel_slot_set_handler!(new_slot, new_handler)
    _channel_calculate_message_overheads!(channel)
    channel_release_message_to_pool!(channel, message)
    return nothing
end

function handler_process_write_message(handler::AlpnHandler, slot::ChannelSlot, message::IoMessage)::Nothing
    logf(LogLevel.ERROR, LS_IO_ALPN, "ALPN handler received unexpected write message")
    throw_error(ERROR_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE)
end

function handler_increment_read_window(handler::AlpnHandler, slot::ChannelSlot, size::Csize_t)::Nothing
    logf(LogLevel.ERROR, LS_IO_ALPN, "ALPN handler does not accept window increments")
    throw_error(ERROR_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE)
end

function handler_shutdown(
        handler::AlpnHandler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Nothing
    channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, free_scarce_resources_immediately)
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
