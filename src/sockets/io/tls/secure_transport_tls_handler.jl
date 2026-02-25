# SecureTransport TLS backend (macOS)
# Included by src/sockets/io/tls_channel_handler.jl

# === SecureTransport backend (macOS) ===
const CFTypeRef = Ptr{Cvoid}
const CFAllocatorRef = Ptr{Cvoid}
const CFStringRef = Ptr{Cvoid}
const CFDataRef = Ptr{Cvoid}
const CFArrayRef = Ptr{Cvoid}
const CFMutableArrayRef = Ptr{Cvoid}
const CFDictionaryRef = Ptr{Cvoid}
const CFMutableDictionaryRef = Ptr{Cvoid}
const SecKeychainRef = Ptr{Cvoid}
const SecCertificateRef = Ptr{Cvoid}
const SecIdentityRef = Ptr{Cvoid}
const SecTrustRef = Ptr{Cvoid}
const SecPolicyRef = Ptr{Cvoid}
const SSLContextRef = Ptr{Cvoid}
const SSLConnectionRef = Ptr{Cvoid}

const OSStatus = Int32
const SSLProtocolSide = Cint
const SSLConnectionType = Cint

const _SECURITY_LIB = "/System/Library/Frameworks/Security.framework/Security"
const _COREFOUNDATION_LIB = "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"

const _ssl_set_alpn_protocols = Ref{Ptr{Cvoid}}(C_NULL)
const _ssl_copy_alpn_protocols = Ref{Ptr{Cvoid}}(C_NULL)
const _secure_transport_security_handle = Ref{Union{Ptr{Nothing}, Nothing}}(nothing)
const _secure_transport_handler_registry = IdDict{Any, Nothing}()

const _kCFStringEncodingASCII = UInt32(0x0600)
const _kCFStringEncodingUTF8 = UInt32(0x08000100)

const _kSSLProtocolUnknown = Cint(0)
const _kSSLProtocol3 = Cint(2)
const _kTLSProtocol1 = Cint(4)
const _kTLSProtocol11 = Cint(7)
const _kTLSProtocol12 = Cint(8)
const _kTLSProtocol13 = Cint(10)

const _kSSLServerSide = Cint(0)
const _kSSLClientSide = Cint(1)
const _kSSLStreamType = Cint(0)

const _kSSLSessionOptionBreakOnServerAuth = Cint(0)
const _kSSLSessionOptionBreakOnClientAuth = Cint(2)

const _kSSLIdle = Cint(0)
const _kSSLHandshake = Cint(1)
const _kSSLConnected = Cint(2)
const _kSSLClosed = Cint(3)
const _kSSLAborted = Cint(4)

const _errSSLWouldBlock = OSStatus(-9803)
const _errSSLClosedGraceful = OSStatus(-9805)
const _errSSLPeerAuthCompleted = OSStatus(-9841)
const _errSSLClosedNoNotify = OSStatus(-9816)
const _errSecBufferTooSmall = OSStatus(-25301)
const _errSecMemoryError = OSStatus(-67672)
const _errSecSuccess = OSStatus(0)
const _errSecDuplicateItem = OSStatus(-25299)
const _errSecUnsupportedFormat = OSStatus(-25256)
const _errSecUnknownFormat = OSStatus(-25257)

const _kSecTrustResultProceed = Cint(1)
const _kSecTrustResultUnspecified = Cint(4)

const _kSecFormatUnknown = UInt32(0)
const _kSecFormatOpenSSL = UInt32(1)
const _kSecFormatWrappedPKCS8 = UInt32(5)
const _kSecFormatX509Cert = UInt32(9)
const _kSecItemTypePrivateKey = UInt32(1)
const _kSecItemTypeCertificate = UInt32(4)

@static if Sys.isapple()
    const _kCFTypeArrayCallBacks = cglobal((:kCFTypeArrayCallBacks, _COREFOUNDATION_LIB), Cvoid)
    const _kSecImportExportPassphrase = unsafe_load(cglobal((:kSecImportExportPassphrase, _SECURITY_LIB), Ptr{Cvoid}))
    const _kSecImportItemIdentity = unsafe_load(cglobal((:kSecImportItemIdentity, _SECURITY_LIB), Ptr{Cvoid}))
    const _kSecImportItemCertChain = unsafe_load(cglobal((:kSecImportItemCertChain, _SECURITY_LIB), Ptr{Cvoid}))
else
    const _kCFTypeArrayCallBacks = C_NULL
    const _kSecImportExportPassphrase = C_NULL
    const _kSecImportItemIdentity = C_NULL
    const _kSecImportItemCertChain = C_NULL
end

struct CFRange
    location::Clong
    length::Clong
end

mutable struct SecureTransportCtx
    minimum_tls_version::TlsVersion.T
    alpn_list::Union{String, Nothing}
    verify_peer::Bool
    ca_cert::Ptr{Cvoid}
    certs::Ptr{Cvoid}
    secitem_identity::Ptr{Cvoid}
end

mutable struct SecureTransportTlsHandler <: TlsChannelHandler
    slot::Union{ChannelSlot{Channel}, Nothing}
    tls_timeout_ms::UInt32
    stats::TlsHandlerStatistics
    timeout_task::ChannelTask
    ctx::SSLContextRef
    ctx_obj::Union{TlsContext, Nothing}
    input_queue::Vector{IoMessage}
    protocol::ByteBuffer
    server_name::ByteBuffer
    alpn_list::Union{String, Nothing}
    latest_message_on_completion::Union{EventCallable, Nothing}
    ca_certs::CFArrayRef
    on_negotiation_result::Union{TlsNegotiationResultCallback, Nothing}
    on_data_read::Union{TlsDataReadCallback, Nothing}
    on_error::Union{TlsErrorCallback, Nothing}
    advertise_alpn_message::Bool
    negotiation_finished::Bool
    verify_peer::Bool
    read_task::ChannelTask
    read_task_pending::Bool
    read_state::TlsHandlerReadState.T
    delay_shutdown_error_code::Int
    negotiation_task::ChannelTask
end

function setchannelslot!(handler::SecureTransportTlsHandler, slot::ChannelSlot{Channel})::Nothing
    handler.slot = slot
    return nothing
end

@inline tls_context_ca_cert(ctx::TlsContext{SecureTransportCtx})::Ptr{Cvoid} = ctx.impl.ca_cert
@inline tls_context_certs(ctx::TlsContext{SecureTransportCtx})::Ptr{Cvoid} = ctx.impl.certs
@inline tls_context_secitem_identity(ctx::TlsContext{SecureTransportCtx})::Ptr{Cvoid} = ctx.impl.secitem_identity

@inline function _cf_release(obj::Ptr{Cvoid})
    @static if Sys.isapple()
        obj == C_NULL && return nothing
        ccall((:CFRelease, _COREFOUNDATION_LIB), Cvoid, (Ptr{Cvoid},), obj)
    end
    return nothing
end

@inline function _cf_retain(obj::Ptr{Cvoid})
    @static if Sys.isapple()
        obj == C_NULL && return nothing
        ccall((:CFRetain, _COREFOUNDATION_LIB), Cvoid, (Ptr{Cvoid},), obj)
    end
    return nothing
end

@inline function _cf_data_create(bytes::Ptr{UInt8}, len::Csize_t)::CFDataRef
    @static if Sys.isapple()
        return ccall((:CFDataCreate, _COREFOUNDATION_LIB), CFDataRef, (CFAllocatorRef, Ptr{UInt8}, Csize_t), C_NULL, bytes, len)
    else
        return C_NULL
    end
end

@inline function _cf_string_create(bytes::Ptr{UInt8}, len::Csize_t, encoding::UInt32)::CFStringRef
    @static if Sys.isapple()
        return ccall(
            (:CFStringCreateWithBytes, _COREFOUNDATION_LIB),
            CFStringRef,
            (CFAllocatorRef, Ptr{UInt8}, Csize_t, UInt32, UInt8),
            C_NULL,
            bytes,
            len,
            encoding,
            0,
        )
    else
        return C_NULL
    end
end

function _cf_string_from_cursor(cursor::ByteCursor, encoding::UInt32)
    if cursor.len == 0
        return _cf_string_create(C_NULL, 0, encoding)
    end
    return GC.@preserve cursor _cf_string_create(_cursor_ptr(cursor), cursor.len, encoding)
end

function _cf_string_to_bytebuffer(str::CFStringRef)::ByteBuffer
    @static if !Sys.isapple()
        return null_buffer()
    end
    str == C_NULL && return null_buffer()
    len = ccall((:CFStringGetLength, _COREFOUNDATION_LIB), Clong, (CFStringRef,), str)
    if len == 0
        return null_buffer()
    end
    max_size = ccall(
        (:CFStringGetMaximumSizeForEncoding, _COREFOUNDATION_LIB),
        Clong,
        (Clong, UInt32),
        len,
        _kCFStringEncodingASCII,
    )
    buf = ByteBuffer(Int(max_size + 1))
    ok = ccall(
        (:CFStringGetCString, _COREFOUNDATION_LIB),
        UInt8,
        (CFStringRef, Ptr{UInt8}, Clong, UInt32),
        str,
        pointer(buf.mem),
        max_size + 1,
        _kCFStringEncodingASCII,
    )
    if ok == 0
        return null_buffer()
    end
    actual = ccall(:strlen, Csize_t, (Cstring,), pointer(buf.mem))
    setfield!(buf, :len, actual)
    return buf
end

function _secure_transport_init()
    @static if !Sys.isapple()
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    handle = _secure_transport_security_handle[]
    if handle === nothing
        handle = Libdl.dlopen(_SECURITY_LIB)::Ptr{Nothing}
        _secure_transport_security_handle[] = handle
    end
    _ssl_set_alpn_protocols[] = Libdl.dlsym(handle, :SSLSetALPNProtocols; throw_error = false)
    _ssl_copy_alpn_protocols[] = Libdl.dlsym(handle, :SSLCopyALPNProtocols; throw_error = false)
    _secure_transport_init_callbacks()

    if is_using_secitem()
        logf(LogLevel.INFO, LS_IO_TLS, "static: initializing TLS implementation as Apple SecItem.")
    else
        logf(LogLevel.INFO, LS_IO_TLS, "static: initializing TLS implementation as Apple SecureTransport.")
    end

    if _ssl_set_alpn_protocols[] != C_NULL
        logf(LogLevel.INFO, LS_IO_TLS, "static: ALPN support detected.")
    else
        logf(LogLevel.WARN, LS_IO_TLS, "static: ALPN isn't supported on this apple device.")
    end
    return nothing
end

function _secure_transport_cleanup()
    return nothing
end

function _secure_transport_set_protocols(handler::SecureTransportTlsHandler, alpn_list::String)
    @static if !Sys.isapple()
        return nothing
    end
    _ssl_set_alpn_protocols[] == C_NULL && return nothing

    protocols = split(alpn_list, ';'; keepempty = false)
    isempty(protocols) && return nothing

    alpn_array = ccall(
        (:CFArrayCreateMutable, _COREFOUNDATION_LIB),
        CFMutableArrayRef,
        (CFAllocatorRef, Clong, Ptr{Cvoid}),
        C_NULL,
        length(protocols),
        _kCFTypeArrayCallBacks,
    )
    alpn_array == C_NULL && return nothing

    for proto in protocols
        proto_cursor = ByteCursor(proto)
        str_ref = GC.@preserve proto_cursor _cf_string_create(_cursor_ptr(proto_cursor), proto_cursor.len, _kCFStringEncodingASCII)
        if str_ref == C_NULL
            _cf_release(alpn_array)
            return nothing
        end
        ccall((:CFArrayAppendValue, _COREFOUNDATION_LIB), Cvoid, (CFMutableArrayRef, Ptr{Cvoid}), alpn_array, str_ref)
        _cf_release(str_ref)
    end

    status = ccall(
        _ssl_set_alpn_protocols[],
        OSStatus,
        (SSLContextRef, CFArrayRef),
        handler.ctx,
        alpn_array,
    )
    if status != _errSecSuccess
        logf(LogLevel.WARN, LS_IO_TLS, "SecureTransport SSLSetALPNProtocols failed with OSStatus $status")
    end

    _cf_release(alpn_array)
    return nothing
end

function _secure_transport_get_protocol(handler::SecureTransportTlsHandler)::ByteBuffer
    @static if !Sys.isapple()
        return null_buffer()
    end
    _ssl_copy_alpn_protocols[] == C_NULL && return null_buffer()

    protocols_ref = Ref{CFArrayRef}(C_NULL)
    status = ccall(
        _ssl_copy_alpn_protocols[],
        OSStatus,
        (SSLContextRef, Ref{CFArrayRef}),
        handler.ctx,
        protocols_ref,
    )
    if protocols_ref[] == C_NULL
        is_server = handler.ctx_obj !== nothing && handler.ctx_obj.options.is_server
        logf(
            LogLevel.DEBUG,
            LS_IO_TLS,string("SecureTransport SSLCopyALPNProtocols unavailable (server=%s status=%d)", " ", string(is_server ? "true" : "false"), " ", string(status), " ", ))
        return null_buffer()
    end

    count = ccall((:CFArrayGetCount, _COREFOUNDATION_LIB), Clong, (CFArrayRef,), protocols_ref[])
    if count <= 0
        _cf_release(protocols_ref[])
        return null_buffer()
    end

    protocol_ref = ccall(
        (:CFArrayGetValueAtIndex, _COREFOUNDATION_LIB),
        CFTypeRef,
        (CFArrayRef, Clong),
        protocols_ref[],
        0,
    )
    _cf_retain(protocol_ref)
    buf = _cf_string_to_bytebuffer(protocol_ref)
    _cf_release(protocol_ref)
    _cf_release(protocols_ref[])
    return buf
end

function _secure_transport_on_negotiation_result(handler::SecureTransportTlsHandler, error_code::Int)
    tls_on_negotiation_completed(handler, error_code)
    _complete_setup!(error_code, handler.slot.channel)
    return nothing
end

@inline function _secure_transport_fail_pending_negotiation!(
        handler::SecureTransportTlsHandler,
        error_code::Int,
    )::Nothing
    status = handler.stats.handshake_status
    if status == TlsNegotiationStatus.ONGOING || status == TlsNegotiationStatus.NONE
        handler.negotiation_finished = false
        err = error_code == OP_SUCCESS ? ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE : error_code
        _secure_transport_on_negotiation_result(handler, err)
    end
    return nothing
end

function _secure_transport_send_alpn_message(handler::SecureTransportTlsHandler)
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
    message.user_data = TlsNegotiatedProtocolMessage(handler.protocol)
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

function _secure_transport_handle_would_block(handler::SecureTransportTlsHandler, is_server::Bool)
    _ = handler
    logf(
        LogLevel.DEBUG,
        LS_IO_TLS,string("SecureTransport SSLHandshake would block (server=%s)", " ", string(is_server ? "true" : "false"), " ", ))
    return nothing
end

function _secure_transport_drive_negotiation(handler::SecureTransportTlsHandler)::Nothing
    @static if !Sys.isapple()
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    tls_on_drive_negotiation(handler)

    is_server = handler.ctx_obj !== nothing && handler.ctx_obj.options.is_server
    status = ccall((:SSLHandshake, _SECURITY_LIB), OSStatus, (SSLContextRef,), handler.ctx)
    if status == _errSecSuccess
        logf(
            LogLevel.DEBUG,
            LS_IO_TLS,string("SecureTransport SSLHandshake success (server=%s)", " ", string(is_server ? "true" : "false"), " ", ))
        handler.negotiation_finished = true
        handler.protocol = _secure_transport_get_protocol(handler)
        if handler.protocol.len > 0
            logf(LogLevel.DEBUG, LS_IO_TLS, "negotiated protocol: $(String(byte_cursor_from_buf(handler.protocol)))")
        end
        _secure_transport_send_alpn_message(handler)
        _secure_transport_on_negotiation_result(handler, OP_SUCCESS)
        return nothing
    elseif status == _errSSLPeerAuthCompleted
        logf(
            LogLevel.DEBUG,
            LS_IO_TLS,string("SecureTransport SSLHandshake peer auth completed", " ", ))
        if handler.verify_peer
            if handler.ca_certs == C_NULL
                throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
            end
            trust_ref = Ref{SecTrustRef}(C_NULL)
            if ccall((:SSLCopyPeerTrust, _SECURITY_LIB), OSStatus, (SSLContextRef, Ref{SecTrustRef}), handler.ctx, trust_ref) !=
                    _errSecSuccess
                throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
            end

            policy = if handler.server_name.len > 0
                name_str = String(byte_cursor_from_buf(handler.server_name))
                name_cursor = ByteCursor(name_str)
                name_ref = GC.@preserve name_cursor _cf_string_create(_cursor_ptr(name_cursor), name_cursor.len, _kCFStringEncodingUTF8)
                policy_ref = ccall((:SecPolicyCreateSSL, _SECURITY_LIB), SecPolicyRef, (UInt8, CFStringRef), 1, name_ref)
                _cf_release(name_ref)
                policy_ref
            else
                ccall((:SecPolicyCreateBasicX509, _SECURITY_LIB), SecPolicyRef, ())
            end

            if ccall((:SecTrustSetPolicies, _SECURITY_LIB), OSStatus, (SecTrustRef, SecPolicyRef), trust_ref[], policy) !=
                    _errSecSuccess
                _cf_release(policy)
                _cf_release(trust_ref[])
                throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
            end
            _cf_release(policy)

            if handler.ca_certs != C_NULL
                if ccall(
                        (:SecTrustSetAnchorCertificates, _SECURITY_LIB),
                        OSStatus,
                        (SecTrustRef, CFArrayRef),
                        trust_ref[],
                        handler.ca_certs,
                    ) != _errSecSuccess
                    _cf_release(trust_ref[])
                    throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                end

                if ccall(
                        (:SecTrustSetAnchorCertificatesOnly, _SECURITY_LIB),
                        OSStatus,
                        (SecTrustRef, UInt8),
                        trust_ref[],
                        1,
                    ) != _errSecSuccess
                    _cf_release(trust_ref[])
                    throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                end
            end

            trust_eval = Ref{Cint}(0)
            status = ccall((:SecTrustEvaluate, _SECURITY_LIB), OSStatus, (SecTrustRef, Ref{Cint}), trust_ref[], trust_eval)
            _cf_release(trust_ref[])

            if status == _errSecSuccess &&
                    (trust_eval[] == _kSecTrustResultProceed || trust_eval[] == _kSecTrustResultUnspecified)
                return _secure_transport_drive_negotiation(handler)
            end

            logf(
                LogLevel.WARN,
                LS_IO_TLS,string("SecureTransport custom CA validation failed with OSStatus $status and Trust Eval $(trust_eval[])", " ", ))
            handler.negotiation_finished = false
            throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
        end

        return _secure_transport_drive_negotiation(handler)
    elseif status == _errSSLWouldBlock
        _secure_transport_handle_would_block(handler, is_server)
        return nothing
    else
        logf(
            LogLevel.WARN,
            LS_IO_TLS,string("SecureTransport SSLHandshake failed with OSStatus $status", " ", ))
        handler.negotiation_finished = false
        throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
    end
end

function _secure_transport_negotiation_task(handler::SecureTransportTlsHandler, status::TaskStatus.T)
    status == TaskStatus.RUN_READY || return nothing
    try
        _secure_transport_drive_negotiation(handler)
    catch
        _secure_transport_fail_pending_negotiation!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
    end
    return nothing
end

function _tls_pending_input_bytes(queue::Vector{IoMessage})::Int
    total = 0
    for msg in queue
        total += Int(msg.message_data.len) - Int(msg.copy_mark)
    end
    return total
end

function _secure_transport_read_cb(conn::SSLConnectionRef, data::Ptr{UInt8}, len_ptr::Ptr{Csize_t})::OSStatus
    handler = unsafe_pointer_to_objref(conn)::SecureTransportTlsHandler
    requested = unsafe_load(len_ptr)
    written = Csize_t(0)
    queue = handler.input_queue
    while !isempty(queue) && written < requested
        message = popfirst!(queue)
        message === nothing && break
        msg = message::IoMessage
        remaining_message_len = Int(msg.message_data.len) - Int(msg.copy_mark)
        remaining_buf_len = Int(requested) - Int(written)
        to_write = remaining_message_len < remaining_buf_len ? remaining_message_len : remaining_buf_len

        if to_write > 0
            src_ptr = pointer(msg.message_data.mem) + Int(msg.copy_mark)
            unsafe_copyto!(data + Int(written), src_ptr, to_write)
            written += Csize_t(to_write)
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

    unsafe_store!(len_ptr, written)
    if written == requested
        return _errSecSuccess
    end
    return _errSSLWouldBlock
end

function _secure_transport_write_cb(conn::SSLConnectionRef, data::Ptr{UInt8}, len_ptr::Ptr{Csize_t})::OSStatus
    handler = unsafe_pointer_to_objref(conn)::SecureTransportTlsHandler
    requested = unsafe_load(len_ptr)
    slot_any = handler.slot
    slot_any === nothing && return _errSSLClosedNoNotify
    slot = slot_any::ChannelSlot{Channel}
    channel_slot_is_attached(slot) || return _errSSLClosedNoNotify
    channel = slot.channel

    processed = Csize_t(0)
    while processed < requested
        overhead = channel_slot_upstream_message_overhead(slot)
        message_size_hint = Csize_t(requested - processed) + overhead
        message = channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, message_size_hint)
        message === nothing && return _errSSLClosedNoNotify

        if message.message_data.capacity <= overhead
            channel_release_message_to_pool!(channel, message)
            return _errSecMemoryError
        end

        available = Int(message.message_data.capacity - overhead)
        to_write = min(available, Int(requested - processed))

        mem = unsafe_wrap(Memory{UInt8}, data + Int(processed), to_write; own = false)
        chunk = ByteCursor(mem, to_write)
        buf_ref = Ref(message.message_data)
        if byte_buf_append(buf_ref, chunk) != OP_SUCCESS
            channel_release_message_to_pool!(channel, message)
            return _errSecBufferTooSmall
        end
        message.message_data = buf_ref[]
        processed += Csize_t(message.message_data.len)

        if processed == requested
            message.on_completion = handler.latest_message_on_completion
            handler.latest_message_on_completion = nothing
        end

        try
            channel_slot_send_message(slot, message, ChannelDirection.WRITE)
        catch e
            e isa ReseauError || rethrow()
            channel_release_message_to_pool!(channel, message)
            return _errSSLClosedNoNotify
        end
    end

    unsafe_store!(len_ptr, processed)
    if processed == requested
        return _errSecSuccess
    end
    return _errSSLWouldBlock
end

function _secure_transport_init_callbacks()
    @static if !Sys.isapple()
        return nothing
    end
    if _secure_transport_read_cb_c[] == C_NULL
        _secure_transport_read_cb_c[] = @cfunction(
            _secure_transport_read_cb,
            OSStatus,
            (SSLConnectionRef, Ptr{UInt8}, Ptr{Csize_t}),
        )
    end
    if _secure_transport_write_cb_c[] == C_NULL
        _secure_transport_write_cb_c[] = @cfunction(
            _secure_transport_write_cb,
            OSStatus,
            (SSLConnectionRef, Ptr{UInt8}, Ptr{Csize_t}),
        )
    end
    return nothing
end

const _secure_transport_read_cb_c = Ref{Ptr{Cvoid}}(C_NULL)
const _secure_transport_write_cb_c = Ref{Ptr{Cvoid}}(C_NULL)

function _secure_transport_read_task(handler::SecureTransportTlsHandler, status::TaskStatus.T)
    status == TaskStatus.RUN_READY || return nothing
    handler.read_task_pending = false
    if handler.slot !== nothing
        handler_process_read_message(handler, handler.slot, nothing)
    end
    return nothing
end

function _secure_transport_initialize_read_delay_shutdown(handler::SecureTransportTlsHandler, slot::ChannelSlot, error_code::Int)
    logf(
        LogLevel.DEBUG,
        LS_IO_TLS,string("TLS handler pending data during shutdown, waiting for downstream read window.", " ", ))
    if channel_slot_downstream_read_window(slot) == 0
        logf(
            LogLevel.WARN,
            LS_IO_TLS,string("TLS shutdown delayed; pending data cannot be processed until read window opens.", " ", ))
    end
    handler.read_state = TlsHandlerReadState.SHUTTING_DOWN
    handler.delay_shutdown_error_code = error_code
    if !handler.read_task_pending
        handler.read_task_pending = true
        channel_task_init!(handler.read_task, EventCallable(s -> _secure_transport_read_task(handler, _coerce_task_status(s))), "secure_transport_read_on_delay_shutdown")
        channel_schedule_task_now!(slot.channel, handler.read_task)
    end
    return nothing
end

function handler_initial_window_size(handler::SecureTransportTlsHandler)::Csize_t
    _ = handler
    return Csize_t(TLS_EST_HANDSHAKE_SIZE)
end

function handler_message_overhead(handler::SecureTransportTlsHandler)::Csize_t
    _ = handler
    return Csize_t(TLS_EST_RECORD_OVERHEAD)
end

function handler_destroy(handler::SecureTransportTlsHandler)::Nothing
    delete!(_secure_transport_handler_registry, handler)
    while !isempty(handler.input_queue)
        msg = popfirst!(handler.input_queue)
        if msg isa IoMessage && msg.owning_channel isa Channel
            channel_release_message_to_pool!(msg.owning_channel, msg)
        end
    end
    if handler.ctx != C_NULL
        _ = ccall((:CFRelease, _COREFOUNDATION_LIB), Cvoid, (Ptr{Cvoid},), handler.ctx)
        handler.ctx = C_NULL
    end
    handler.protocol = null_buffer()
    handler.server_name = null_buffer()
    handler.slot = nothing
    handler.ctx_obj = nothing
    return nothing
end

function handler_reset_statistics(handler::SecureTransportTlsHandler)::Nothing
    crt_statistics_tls_reset!(handler.stats)
    return nothing
end

function handler_gather_statistics(handler::SecureTransportTlsHandler)
    return handler.stats
end

function handler_process_read_message(
        handler::SecureTransportTlsHandler,
        slot::ChannelSlot,
        message::Union{IoMessage, Nothing},
    )::Nothing
    if handler.read_state == TlsHandlerReadState.SHUT_DOWN_COMPLETE
        message !== nothing && message.owning_channel isa Channel && channel_release_message_to_pool!(message.owning_channel, message)
        return nothing
    end

    if message !== nothing
        push!(handler.input_queue, message)

        if !handler.negotiation_finished
            message_len = message.message_data.len
            negotiation_failed = false
            try
                _secure_transport_drive_negotiation(handler)
            catch
                negotiation_failed = true
            end
            if negotiation_failed
                _secure_transport_fail_pending_negotiation!(handler, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                channel_shutdown!(slot.channel, ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                return nothing
            end
            channel_slot_increment_read_window!(slot, message_len)
            if !handler.negotiation_finished
                return nothing
            end
        end
    end

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

        read_size = Ref{Csize_t}(0)
        status = ccall(
            (:SSLRead, _SECURITY_LIB),
            OSStatus,
            (SSLContextRef, Ptr{UInt8}, Csize_t, Ref{Csize_t}),
            handler.ctx,
            pointer(outgoing.message_data.mem),
            outgoing.message_data.capacity,
            read_size,
        )

        if read_size[] > 0
            processed += read_size[]
            setfield!(outgoing.message_data, :len, Csize_t(read_size[]))

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
        else
            channel_release_message_to_pool!(slot.channel, outgoing)
        end

        if status == _errSSLWouldBlock
            if handler.read_state == TlsHandlerReadState.SHUTTING_DOWN
                break
            end
            break
        elseif status == _errSSLClosedGraceful
            force_shutdown = true
            break
        elseif status == _errSecSuccess
            continue
        else
            logf(
                LogLevel.ERROR,
                LS_IO_TLS,string("SecureTransport SSLRead failed with OSStatus $status", " ", ))
            shutdown_error_code = ERROR_IO_TLS_ERROR_READ_FAILURE
            break
        end
    end

    if force_shutdown || shutdown_error_code != 0 ||
            (handler.read_state == TlsHandlerReadState.SHUTTING_DOWN && processed < downstream_window)
        if handler.read_state == TlsHandlerReadState.SHUTTING_DOWN
            if handler.delay_shutdown_error_code != 0
                shutdown_error_code = handler.delay_shutdown_error_code
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

function handler_process_read_message(handler::SecureTransportTlsHandler, slot::ChannelSlot, message::IoMessage)::Nothing
    invoke(
        handler_process_read_message,
        Tuple{SecureTransportTlsHandler, ChannelSlot, Union{IoMessage, Nothing}},
        handler,
        slot,
        message,
    )
    return nothing
end

function handler_process_write_message(
        handler::SecureTransportTlsHandler,
        slot::ChannelSlot,
        message::IoMessage,
    )::Nothing
    _ = slot
    if !handler.negotiation_finished
        throw_error(ERROR_IO_TLS_ERROR_NOT_NEGOTIATED)
    end

    handler.latest_message_on_completion = message.on_completion

    processed = Ref{Csize_t}(0)
    status = ccall(
        (:SSLWrite, _SECURITY_LIB),
        OSStatus,
        (SSLContextRef, Ptr{UInt8}, Csize_t, Ref{Csize_t}),
        handler.ctx,
        pointer(message.message_data.mem),
        message.message_data.len,
        processed,
    )

    if status != _errSecSuccess
        throw_error(ERROR_IO_TLS_ERROR_WRITE_FAILURE)
    end

    channel_release_message_to_pool!(slot.channel, message)
    return nothing
end

function handler_shutdown(
        handler::SecureTransportTlsHandler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Nothing
    abort_immediately = free_scarce_resources_immediately

    if direction == ChannelDirection.READ
        if !handler.negotiation_finished
            _secure_transport_fail_pending_negotiation!(handler, error_code)
        end
        if !abort_immediately &&
                handler.negotiation_finished &&
                !isempty(handler.input_queue) &&
                slot.adj_right !== nothing
            _secure_transport_initialize_read_delay_shutdown(handler, slot, error_code)
            return nothing
        end
        handler.read_state = TlsHandlerReadState.SHUT_DOWN_COMPLETE
    else
        if !abort_immediately && error_code != ERROR_IO_SOCKET_CLOSED
            _ = ccall((:SSLClose, _SECURITY_LIB), OSStatus, (SSLContextRef,), handler.ctx)
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
        handler::SecureTransportTlsHandler,
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

    if handler.negotiation_finished && !handler.read_task_pending
        handler.read_task_pending = true
        channel_task_init!(handler.read_task, EventCallable(s -> _secure_transport_read_task(handler, _coerce_task_status(s))), "secure_transport_read_on_window_increment")
        channel_schedule_task_now!(slot.channel, handler.read_task)
    end

    return nothing
end

function _secure_transport_ctx_destroy!(ctx::SecureTransportCtx)
    if ctx.certs != C_NULL
        _cf_release(ctx.certs)
        ctx.certs = C_NULL
    end
    if ctx.ca_cert != C_NULL
        _cf_release(ctx.ca_cert)
        ctx.ca_cert = C_NULL
    end
    if ctx.secitem_identity != C_NULL
        _cf_release(ctx.secitem_identity)
        ctx.secitem_identity = C_NULL
    end
    ctx.alpn_list = nothing
    return nothing
end

function _secure_transport_context_new(options::TlsContextOptions)::TlsContext
    if !tls_is_cipher_pref_supported(options.cipher_pref)
        throw_error(ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED)
    end

    ctx_impl = SecureTransportCtx(options.minimum_tls_version, options.alpn_list, options.verify_peer, C_NULL, C_NULL, C_NULL)

    if options.certificate_set && options.private_key_set
        cert_cursor = byte_cursor_from_buf(options.certificate)
        key_cursor = byte_cursor_from_buf(options.private_key)
        if !_tls_text_is_ascii_or_utf8_bom(cert_cursor) || !_tls_text_is_ascii_or_utf8_bom(key_cursor)
            throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)
        end
        if is_using_secitem()
            secitem_opts = options.secitem_options
            if secitem_opts === nothing ||
                    secitem_opts.cert_label === nothing ||
                    secitem_opts.key_label === nothing
                secitem_opts = _tls_generate_secitem_labels()
                options.secitem_options = secitem_opts
            end
            ctx_impl.secitem_identity = secitem_import_cert_and_key(
                cert_cursor,
                key_cursor;
                cert_label = secitem_opts.cert_label,
                key_label = secitem_opts.key_label,
            )
        else
            ctx_impl.certs = import_public_and_private_keys_to_identity(cert_cursor, key_cursor; keychain_path = options.keychain_path)
        end
    elseif options.pkcs12_set
        pkcs_cursor = byte_cursor_from_buf(options.pkcs12)
        pwd_cursor = byte_cursor_from_buf(options.pkcs12_password)
        if is_using_secitem()
            ctx_impl.secitem_identity = secitem_import_pkcs12(pkcs_cursor, pwd_cursor)
        else
            ctx_impl.certs = import_pkcs12_to_identity(pkcs_cursor, pwd_cursor)
        end
    end

    if options.ca_file_set
        ca_cursor = byte_cursor_from_buf(options.ca_file)
        ctx_impl.ca_cert = import_trusted_certificates(ca_cursor)
    end

    ctx = TlsContext(options, ctx_impl, false)
    finalizer(ctx) do c
        c.closed && return
        c.closed = true
        if c.impl isa SecureTransportCtx
            _secure_transport_ctx_destroy!(c.impl)
        end
    end
    return ctx
end

function _secure_transport_handler_new(
        options::TlsConnectionOptions,
        slot::ChannelSlot,
        protocol_side::SSLProtocolSide,
    )::SecureTransportTlsHandler
    @static if !Sys.isapple()
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    ctx = options.ctx
    st_ctx = ctx.impl isa SecureTransportCtx ? (ctx.impl::SecureTransportCtx) : nothing
    st_ctx === nothing && throw_error(ERROR_IO_TLS_CTX_ERROR)
    st_ctx = st_ctx::SecureTransportCtx

    handler = SecureTransportTlsHandler(
        slot,
        options.timeout_ms,
        TlsHandlerStatistics(),
        ChannelTask(),
        C_NULL,
        ctx,
        IoMessage[],
        null_buffer(),
        null_buffer(),
        options.alpn_list === nothing ? st_ctx.alpn_list : options.alpn_list,
        nothing,
        C_NULL,
        options.on_negotiation_result,
        options.on_data_read,
        options.on_error,
        options.advertise_alpn_message,
        false,
        options.ctx.options.verify_peer,
        ChannelTask(),
        false,
        TlsHandlerReadState.OPEN,
        0,
        ChannelTask(),
    )

    crt_statistics_tls_init!(handler.stats)
    channel_task_init!(handler.timeout_task, EventCallable(s -> _tls_timeout_task(handler, _coerce_task_status(s))), "tls_timeout")
    _secure_transport_handler_registry[handler] = nothing

    handler.ctx = ccall((:SSLCreateContext, _SECURITY_LIB), SSLContextRef, (CFAllocatorRef, SSLProtocolSide, SSLConnectionType), C_NULL, protocol_side, _kSSLStreamType)
    handler.ctx == C_NULL && throw_error(ERROR_IO_TLS_CTX_ERROR)
    _secure_transport_init_callbacks()

    if options.ctx.options.minimum_tls_version == TlsVersion.SSLv3
        _ = ccall((:SSLSetProtocolVersionMin, _SECURITY_LIB), OSStatus, (SSLContextRef, Cint), handler.ctx, _kSSLProtocol3)
    elseif options.ctx.options.minimum_tls_version == TlsVersion.TLSv1
        _ = ccall((:SSLSetProtocolVersionMin, _SECURITY_LIB), OSStatus, (SSLContextRef, Cint), handler.ctx, _kTLSProtocol1)
    elseif options.ctx.options.minimum_tls_version == TlsVersion.TLSv1_1
        _ = ccall((:SSLSetProtocolVersionMin, _SECURITY_LIB), OSStatus, (SSLContextRef, Cint), handler.ctx, _kTLSProtocol12)
    elseif options.ctx.options.minimum_tls_version == TlsVersion.TLSv1_2
        _ = ccall((:SSLSetProtocolVersionMin, _SECURITY_LIB), OSStatus, (SSLContextRef, Cint), handler.ctx, _kTLSProtocol12)
    elseif options.ctx.options.minimum_tls_version == TlsVersion.TLSv1_3
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    else
        _ = ccall((:SSLSetProtocolVersionMin, _SECURITY_LIB), OSStatus, (SSLContextRef, Cint), handler.ctx, _kSSLProtocolUnknown)
    end
    if ccall((:SSLSetIOFuncs, _SECURITY_LIB), OSStatus, (SSLContextRef, Ptr{Cvoid}, Ptr{Cvoid}), handler.ctx, _secure_transport_read_cb_c[], _secure_transport_write_cb_c[]) != _errSecSuccess ||
            ccall((:SSLSetConnection, _SECURITY_LIB), OSStatus, (SSLContextRef, SSLConnectionRef), handler.ctx, pointer_from_objref(handler)) != _errSecSuccess
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end

    handler.verify_peer = st_ctx.verify_peer

    if !st_ctx.verify_peer && protocol_side == _kSSLClientSide
        logf(
            LogLevel.WARN,
            LS_IO_TLS,string("x.509 validation has been disabled. This is unsafe outside of test environments.", " ", ))
        _ = ccall((:SSLSetSessionOption, _SECURITY_LIB), OSStatus, (SSLContextRef, Cint, UInt8), handler.ctx, _kSSLSessionOptionBreakOnServerAuth, 1)
    end

    if st_ctx.certs != C_NULL
        _ = ccall((:SSLSetCertificate, _SECURITY_LIB), OSStatus, (SSLContextRef, CFArrayRef), handler.ctx, st_ctx.certs)
    end

    handler.ca_certs = st_ctx.ca_cert
    if handler.ca_certs != C_NULL
        if protocol_side == _kSSLServerSide && st_ctx.verify_peer
            _ = ccall((:SSLSetSessionOption, _SECURITY_LIB), OSStatus, (SSLContextRef, Cint, UInt8), handler.ctx, _kSSLSessionOptionBreakOnClientAuth, 1)
        elseif st_ctx.verify_peer
            _ = ccall((:SSLSetSessionOption, _SECURITY_LIB), OSStatus, (SSLContextRef, Cint, UInt8), handler.ctx, _kSSLSessionOptionBreakOnServerAuth, 1)
        end
    end

    if options.server_name !== nothing
        handler.server_name = _byte_buf_from_string(options.server_name)
        _ = ccall((:SSLSetPeerDomainName, _SECURITY_LIB), OSStatus, (SSLContextRef, Cstring, Csize_t), handler.ctx, options.server_name, ncodeunits(options.server_name))
    end

    if options.alpn_list !== nothing
        _secure_transport_set_protocols(handler, options.alpn_list)
    elseif st_ctx.alpn_list !== nothing
        _secure_transport_set_protocols(handler, st_ctx.alpn_list)
    end

    return handler
end
