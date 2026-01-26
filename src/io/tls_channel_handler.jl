# AWS IO Library - TLS Channel Handler (LibAwsCal-backed)

using LibAwsCal
using LibAwsCommon

const TlsOnNegotiationResultFn = Function  # (handler, slot, error_code, user_data) -> nothing
const TlsOnDataReadFn = Function           # (handler, slot, buffer, user_data) -> nothing
const TlsOnErrorFn = Function              # (handler, slot, error_code, message, user_data) -> nothing

const TLS_HANDSHAKE_CLIENT_HELLO = 0x01
const TLS_HANDSHAKE_SERVER_HELLO = 0x02
const TLS_RECORD_APPLICATION = 0x03
const TLS_RECORD_HEADER_LEN = 5
const TLS_NONCE_LEN = 32
const TLS_MAC_LEN = 32
const TLS_SESSION_KEY_LEN = 32

@enumx TlsHandshakeState::UInt8 begin
    INIT = 0
    CLIENT_HELLO_SENT = 1
    NEGOTIATED = 2
    FAILED = 3
end

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
    options::TlsContextOptions
end

const _tls_cal_init_lock = ReentrantLock()
const _tls_cal_initialized = Ref(false)

function _tls_cal_init_once()
    _tls_cal_initialized[] && return nothing
    lock(_tls_cal_init_lock) do
        if !_tls_cal_initialized[]
            LibAwsCal.init()
            _tls_cal_initialized[] = true
        end
    end
    return nothing
end

function tls_context_new(options::TlsContextOptions)::Union{TlsContext, ErrorResult}
    _tls_cal_init_once()
    return TlsContext(options)
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

mutable struct PendingWrite
    message::IoMessage
    offset::Int
end

mutable struct TlsChannelHandler{FNR <: Union{TlsOnNegotiationResultFn, Nothing}, FDR <: Union{TlsOnDataReadFn, Nothing}, FER <: Union{TlsOnErrorFn, Nothing}, U} <: AbstractChannelHandler
    slot::Union{ChannelSlot, Nothing}
    negotiation_completed::Bool
    pending_writes::Vector{PendingWrite}
    max_read_size::Csize_t
    options::TlsConnectionOptions{TlsContext, FNR, FDR, FER, U}
    state::TlsHandshakeState.T
    client_random::Vector{UInt8}
    server_random::Vector{UInt8}
    session_key::Vector{UInt8}
    inbound_buf::Vector{UInt8}
    inbound_offset::Int
end

function TlsChannelHandler(
        options::TlsConnectionOptions;
        max_read_size::Integer = 16384,
    )
    return TlsChannelHandler(
        nothing,
        false,
        PendingWrite[],
        Csize_t(max_read_size),
        options,
        TlsHandshakeState.INIT,
        UInt8[],
        UInt8[],
        UInt8[],
        UInt8[],
        0,
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

    if !handler.options.ctx.options.is_server
        _tls_send_client_hello!(handler)
    end
    return nothing
end

function _aws_byte_cursor_from_vec(vec::Vector{UInt8})
    if isempty(vec)
        return LibAwsCommon.aws_byte_cursor(Csize_t(0), Ptr{UInt8}(C_NULL))
    end
    return LibAwsCommon.aws_byte_cursor(Csize_t(length(vec)), pointer(vec))
end

function _aws_byte_buf_from_vec(vec::Vector{UInt8})
    return LibAwsCommon.aws_byte_buf(Csize_t(0), pointer(vec), Csize_t(length(vec)), Ptr{LibAwsCommon.aws_allocator}(C_NULL))
end

function _derive_session_key(client_random::Vector{UInt8}, server_random::Vector{UInt8})
    _tls_cal_init_once()

    psk = Vector{UInt8}(codeunits("awsio-tls-psk"))
    ikm = _aws_byte_cursor_from_vec(psk)
    salt = _aws_byte_cursor_from_vec(vcat(client_random, server_random))
    info = _aws_byte_cursor_from_vec(Vector{UInt8}(codeunits("awsio-tls")))

    out = Vector{UInt8}(undef, TLS_SESSION_KEY_LEN)
    out_buf = _aws_byte_buf_from_vec(out)
    allocator = LibAwsCommon.default_aws_allocator()

    rv = LibAwsCal.aws_hkdf_derive(
        allocator,
        LibAwsCal.HKDF_HMAC_SHA512,
        ikm,
        salt,
        info,
        Ref(out_buf),
        Csize_t(TLS_SESSION_KEY_LEN),
    )
    if rv != 0
        return UInt8[]
    end
    return out
end

function _hmac_sha256(key::Vector{UInt8}, data::Vector{UInt8})
    _tls_cal_init_once()
    allocator = LibAwsCommon.default_aws_allocator()
    key_cur = _aws_byte_cursor_from_vec(key)
    data_cur = _aws_byte_cursor_from_vec(data)

    hmac = LibAwsCal.aws_sha256_hmac_new(allocator, Ref(key_cur))
    if hmac == C_NULL
        return UInt8[]
    end

    if LibAwsCal.aws_hmac_update(hmac, Ref(data_cur)) != 0
        LibAwsCal.aws_hmac_destroy(hmac)
        return UInt8[]
    end

    out = Vector{UInt8}(undef, TLS_MAC_LEN)
    out_buf = _aws_byte_buf_from_vec(out)
    if LibAwsCal.aws_hmac_finalize(hmac, Ref(out_buf), Csize_t(0)) != 0
        LibAwsCal.aws_hmac_destroy(hmac)
        return UInt8[]
    end

    LibAwsCal.aws_hmac_destroy(hmac)
    return out
end

function _xor_with_key(data::Vector{UInt8}, key::Vector{UInt8})
    out = Vector{UInt8}(undef, length(data))
    key_len = length(key)
    key_len == 0 && return data
    for i in eachindex(data)
        out[i] = data[i] ⊻ key[1 + ((i - 1) % key_len)]
    end
    return out
end

function _const_time_eq(a::Vector{UInt8}, b::Vector{UInt8})
    length(a) == length(b) || return false
    acc = UInt8(0)
    for i in eachindex(a)
        acc |= a[i] ⊻ b[i]
    end
    return acc == 0x00
end

function _tls_report_error!(handler::TlsChannelHandler, error_code::Int, message::AbstractString)
    if !handler.negotiation_completed
        handler.state = TlsHandshakeState.FAILED
        if handler.options.on_negotiation_result !== nothing && handler.slot !== nothing
            Base.invokelatest(
                handler.options.on_negotiation_result,
                handler,
                handler.slot,
                error_code,
                handler.options.user_data,
            )
        end
    else
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
    end

    if handler.slot !== nothing && handler.slot.channel !== nothing
        channel_shutdown!(handler.slot.channel, ChannelDirection.READ, error_code)
    end

    return nothing
end

function _tls_send_record!(handler::TlsChannelHandler, record_type::UInt8, payload::Vector{UInt8})
    slot = handler.slot
    if slot === nothing || slot.channel === nothing
        return nothing
    end

    channel = slot.channel
    total_len = TLS_RECORD_HEADER_LEN + length(payload)
    msg = channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, total_len)
    if msg === nothing
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_WRITE_FAILURE, "TLS output alloc failed")
        return nothing
    end

    buf_ref = Ref(msg.message_data)
    byte_buf_reserve(buf_ref, total_len)
    msg.message_data = buf_ref[]
    buf = msg.message_data

    GC.@preserve buf begin
        ptr = pointer(getfield(buf, :mem))
        unsafe_store!(ptr, record_type)
        len = UInt32(length(payload))
        unsafe_store!(ptr + 1, UInt8((len >> 24) & 0xFF))
        unsafe_store!(ptr + 2, UInt8((len >> 16) & 0xFF))
        unsafe_store!(ptr + 3, UInt8((len >> 8) & 0xFF))
        unsafe_store!(ptr + 4, UInt8(len & 0xFF))
        if !isempty(payload)
            unsafe_copyto!(ptr + TLS_RECORD_HEADER_LEN, pointer(payload), length(payload))
        end
    end
    setfield!(buf, :len, Csize_t(total_len))

    send_result = channel_slot_send_message(slot, msg, ChannelDirection.WRITE)
    if send_result isa ErrorResult
        channel_release_message_to_pool!(channel, msg)
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_WRITE_FAILURE, "TLS output send failed")
        return nothing
    end

    return nothing
end

function _tls_send_client_hello!(handler::TlsChannelHandler)
    handler.state == TlsHandshakeState.INIT || return nothing
    rnd_buf = ByteBuffer(TLS_NONCE_LEN)
    device_random_buffer_append(Ref(rnd_buf), Csize_t(TLS_NONCE_LEN))
    client_random = Vector{UInt8}(undef, TLS_NONCE_LEN)
    unsafe_copyto!(pointer(client_random), pointer(getfield(rnd_buf, :mem)), TLS_NONCE_LEN)
    handler.client_random = client_random
    handler.state = TlsHandshakeState.CLIENT_HELLO_SENT
    _tls_send_record!(handler, TLS_HANDSHAKE_CLIENT_HELLO, client_random)
    return nothing
end

function _tls_send_server_hello!(handler::TlsChannelHandler)
    rnd_buf = ByteBuffer(TLS_NONCE_LEN)
    device_random_buffer_append(Ref(rnd_buf), Csize_t(TLS_NONCE_LEN))
    server_random = Vector{UInt8}(undef, TLS_NONCE_LEN)
    unsafe_copyto!(pointer(server_random), pointer(getfield(rnd_buf, :mem)), TLS_NONCE_LEN)
    handler.server_random = server_random
    _tls_send_record!(handler, TLS_HANDSHAKE_SERVER_HELLO, server_random)
    return nothing
end

function _tls_mark_negotiated!(handler::TlsChannelHandler)
    handler.negotiation_completed = true
    handler.state = TlsHandshakeState.NEGOTIATED
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

function _tls_handle_handshake!(handler::TlsChannelHandler, record_type::UInt8, payload::Vector{UInt8})
    if record_type == TLS_HANDSHAKE_CLIENT_HELLO
        if !handler.options.ctx.options.is_server || handler.state != TlsHandshakeState.INIT
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE, "Unexpected client hello")
            return nothing
        end
        if length(payload) != TLS_NONCE_LEN
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE, "Invalid client hello size")
            return nothing
        end
        handler.client_random = copy(payload)
        _tls_send_server_hello!(handler)
        handler.session_key = _derive_session_key(handler.client_random, handler.server_random)
        if isempty(handler.session_key)
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE, "Session key derivation failed")
            return nothing
        end
        _tls_mark_negotiated!(handler)
        return nothing
    end

    if record_type == TLS_HANDSHAKE_SERVER_HELLO
        if handler.options.ctx.options.is_server || handler.state != TlsHandshakeState.CLIENT_HELLO_SENT
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE, "Unexpected server hello")
            return nothing
        end
        if length(payload) != TLS_NONCE_LEN
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE, "Invalid server hello size")
            return nothing
        end
        handler.server_random = copy(payload)
        handler.session_key = _derive_session_key(handler.client_random, handler.server_random)
        if isempty(handler.session_key)
            _tls_report_error!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE, "Session key derivation failed")
            return nothing
        end
        _tls_mark_negotiated!(handler)
        return nothing
    end

    _tls_report_error!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE, "Unknown handshake message")
    return nothing
end

function _tls_handle_application!(handler::TlsChannelHandler, payload::Vector{UInt8})
    if !handler.negotiation_completed
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_READ_FAILURE, "Application data before negotiation")
        return nothing
    end

    if length(payload) < TLS_MAC_LEN
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_READ_FAILURE, "Invalid TLS record size")
        return nothing
    end

    mac = payload[1:TLS_MAC_LEN]
    cipher = payload[(TLS_MAC_LEN + 1):end]
    plaintext = _xor_with_key(cipher, handler.session_key)
    calc_mac = _hmac_sha256(handler.session_key, plaintext)

    if isempty(calc_mac) || !_const_time_eq(mac, calc_mac)
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_READ_FAILURE, "TLS record MAC mismatch")
        return nothing
    end

    slot = handler.slot
    if slot === nothing || slot.channel === nothing
        return nothing
    end

    channel = slot.channel
    msg = channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, length(plaintext))
    if msg === nothing
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_READ_FAILURE, "TLS read alloc failed")
        return nothing
    end

    buf_ref = Ref(msg.message_data)
    byte_buf_reserve(buf_ref, length(plaintext))
    msg.message_data = buf_ref[]
    buf = msg.message_data

    GC.@preserve buf begin
        unsafe_copyto!(pointer(getfield(buf, :mem)), pointer(plaintext), length(plaintext))
    end
    setfield!(buf, :len, Csize_t(length(plaintext)))

    if handler.options.on_data_read !== nothing && slot.adj_left === nothing
        Base.invokelatest(handler.options.on_data_read, handler, slot, buf, handler.options.user_data)
        channel_release_message_to_pool!(channel, msg)
        return nothing
    end

    send_result = channel_slot_send_message(slot, msg, ChannelDirection.READ)
    if send_result isa ErrorResult
        channel_release_message_to_pool!(channel, msg)
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_READ_FAILURE, "TLS read send failed")
        return nothing
    end

    return nothing
end

function _tls_process_inbound!(handler::TlsChannelHandler)
    buf = handler.inbound_buf
    while true
        available = length(buf) - handler.inbound_offset
        if available < TLS_RECORD_HEADER_LEN
            break
        end

        idx = handler.inbound_offset + 1
        record_type = buf[idx]
        len = (UInt32(buf[idx + 1]) << 24) |
            (UInt32(buf[idx + 2]) << 16) |
            (UInt32(buf[idx + 3]) << 8) |
            UInt32(buf[idx + 4])
        total_len = TLS_RECORD_HEADER_LEN + Int(len)
        if available < total_len
            break
        end

        payload_start = idx + TLS_RECORD_HEADER_LEN
        payload_end = payload_start + Int(len) - 1
        payload = Int(len) == 0 ? UInt8[] : Vector{UInt8}(view(buf, payload_start:payload_end))
        handler.inbound_offset += total_len

        if record_type == TLS_RECORD_APPLICATION
            _tls_handle_application!(handler, payload)
        else
            _tls_handle_handshake!(handler, record_type, payload)
        end
    end

    if handler.inbound_offset > 0
        if handler.inbound_offset >= length(buf)
            empty!(buf)
            handler.inbound_offset = 0
        elseif handler.inbound_offset > 4096
            handler.inbound_buf = buf[(handler.inbound_offset + 1):end]
            handler.inbound_offset = 0
        end
    end

    return nothing
end

function _tls_encrypt_message(handler::TlsChannelHandler, message::IoMessage)
    slot = handler.slot
    if slot === nothing || slot.channel === nothing
        return nothing
    end

    channel = slot.channel
    buf = message.message_data
    total = Int(buf.len)
    if total == 0
        channel_release_message_to_pool!(channel, message)
        return nothing
    end

    plaintext = Vector{UInt8}(undef, total)
    GC.@preserve buf begin
        unsafe_copyto!(pointer(plaintext), pointer(getfield(buf, :mem)), total)
    end

    mac = _hmac_sha256(handler.session_key, plaintext)
    if isempty(mac)
        channel_release_message_to_pool!(channel, message)
        _tls_report_error!(handler, ERROR_IO_TLS_ERROR_WRITE_FAILURE, "TLS HMAC failed")
        return nothing
    end

    cipher = _xor_with_key(plaintext, handler.session_key)
    record_payload = vcat(mac, cipher)
    _tls_send_record!(handler, TLS_RECORD_APPLICATION, record_payload)
    channel_release_message_to_pool!(channel, message)
    return nothing
end

function _tls_flush_pending_writes!(handler::TlsChannelHandler)
    if isempty(handler.pending_writes)
        return nothing
    end

    for pending in handler.pending_writes
        _tls_encrypt_message(handler, pending.message)
    end
    empty!(handler.pending_writes)
    return nothing
end

function handler_process_read_message(handler::TlsChannelHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    channel = slot.channel
    buf = message.message_data
    data_len = Int(buf.len)

    if data_len > 0
        start = length(handler.inbound_buf) + 1
        resize!(handler.inbound_buf, length(handler.inbound_buf) + data_len)
        GC.@preserve buf begin
            unsafe_copyto!(pointer(handler.inbound_buf, start), pointer(getfield(buf, :mem)), data_len)
        end
    end

    if channel !== nothing
        channel_release_message_to_pool!(channel, message)
    end

    _tls_process_inbound!(handler)
    return nothing
end

function handler_process_write_message(handler::TlsChannelHandler, slot::ChannelSlot, message::IoMessage)::Union{Nothing, ErrorResult}
    if !handler.negotiation_completed
        push!(handler.pending_writes, PendingWrite(message, 0))
        return nothing
    end

    _tls_encrypt_message(handler, message)
    return nothing
end

function handler_increment_read_window(handler::TlsChannelHandler, slot::ChannelSlot, size::Csize_t)::Union{Nothing, ErrorResult}
    return channel_slot_increment_read_window!(slot, size)
end

function handler_shutdown(handler::TlsChannelHandler, slot::ChannelSlot, direction::ChannelDirection.T, error_code::Int)::Union{Nothing, ErrorResult}
    if !handler.negotiation_completed && handler.options.on_negotiation_result !== nothing
        Base.invokelatest(handler.options.on_negotiation_result, handler, slot, error_code, handler.options.user_data)
    end
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
    return nothing
end

function handler_trigger_write(handler::TlsChannelHandler)::Nothing
    _tls_flush_pending_writes!(handler)
    return nothing
end
