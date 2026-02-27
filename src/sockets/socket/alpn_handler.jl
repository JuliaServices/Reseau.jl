# AWS IO Library - ALPN Handler
# Port of aws-c-io/source/alpn_handler.c

mutable struct AlpnHandler
    slot::Union{ChannelSlot, Nothing}
end

tls_alpn_handler_new() = AlpnHandler(nothing)

function setchannelslot!(handler::AlpnHandler, slot::ChannelSlot)::Nothing
    handler.slot = slot
    return nothing
end

function handler_process_read_message(
        handler::AlpnHandler,
        slot::ChannelSlot,
        message::IoMessage,
    )::Nothing
    if message.message_tag != TLS_NEGOTIATED_PROTOCOL_MESSAGE
        throw_error(ERROR_IO_MISSING_ALPN_MESSAGE)
    end

    protocol = message.negotiated_protocol
    if protocol === nothing
        throw_error(ERROR_IO_MISSING_ALPN_MESSAGE)
    end
    chan_id = channel_slot_is_attached(slot) ? slot.channel.channel_id : -1
    logf(
        LogLevel.DEBUG, LS_IO_ALPN,
        string("ALPN negotiated protocol: %s (channel %d)", " ", string(isempty(protocol) ? "<empty>" : protocol), " ", string(chan_id), " ", )
    )

    if !channel_slot_is_attached(slot)
        throw_error(ERROR_IO_CHANNEL_ERROR_CANT_ACCEPT_INPUT)
    end
    channel = slot.channel
    channel.negotiated_protocol = protocol
    _channel_calculate_message_overheads!(channel)
    channel_release_message_to_pool!(channel, message)
    return nothing
end

function handler_process_write_message(
        handler::AlpnHandler,
        slot::ChannelSlot,
        message::IoMessage,
    )::Nothing
    logf(LogLevel.ERROR, LS_IO_ALPN, "ALPN handler received unexpected write message")
    throw_error(ERROR_IO_CHANNEL_UNKNOWN_MESSAGE_TYPE)
end

function handler_increment_read_window(
        handler::AlpnHandler,
        slot::ChannelSlot,
        size::Csize_t,
    )::Nothing
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
