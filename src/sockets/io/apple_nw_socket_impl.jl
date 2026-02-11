# AWS IO Library - Apple Network Framework sockets
# Port of aws-c-io/source/darwin/nw_socket.c

# Type definitions (NWSocket, NWSendContext, enums, type aliases, library paths)
# are in apple_nw_socket_types.jl — included before socket.jl for type ordering.

@static if Sys.isapple()
    # Network.framework exports some "constants" (e.g. NW_PARAMETERS_DISABLE_PROTOCOL) as
    # globals whose value is already a pointer type. We must load the pointer value from
    # the global's storage (i.e. dereference `cglobal`).
    @noinline function _nw_global_ptr(sym::Symbol)::Ptr{Cvoid}
        return unsafe_load(cglobal((sym, _NW_NETWORK_LIB), Ptr{Cvoid}))
    end

    const _NW_DISABLE_PROTOCOL_BLOCK = Ref{Ptr{Cvoid}}(C_NULL)
    const _NW_DEFAULT_MESSAGE_CONTEXT = Ref{nw_content_context_t}(C_NULL)

    function _nw_ensure_globals!()
        if _NW_DISABLE_PROTOCOL_BLOCK[] == C_NULL
            _NW_DISABLE_PROTOCOL_BLOCK[] = _nw_global_ptr(:_nw_parameters_configure_protocol_disable)
        end
        if _NW_DEFAULT_MESSAGE_CONTEXT[] == C_NULL
            _NW_DEFAULT_MESSAGE_CONTEXT[] = nw_content_context_t(_nw_global_ptr(:_nw_content_context_default_message))
        end
        return nothing
    end

    # OSStatus TLS errors (Security.framework)
    const errSSLUnknownRootCert = -9812
    const errSSLNoRootCert = -9813
    const errSSLCertExpired = -9814
    const errSSLCertNotYetValid = -9815
    const errSSLPeerHandshakeFail = -9824
    const errSSLBadCert = -9808
    const errSSLPeerCertExpired = -9828
    const errSSLPeerBadCert = -9825
    const errSSLPeerCertRevoked = -9827
    const errSSLPeerCertUnknown = -9829
    const errSSLInternal = -9810
    const errSSLClosedGraceful = -9805
    const errSSLClosedAbort = -9806
    const errSSLXCertChainInvalid = -9807
    const errSSLHostNameMismatch = -9843
    const errSSLPeerProtocolVersion = -9836
    const errSecNotTrusted = -67843

    const kSecTrustResultProceed = Cint(1)
    const kSecTrustResultUnspecified = Cint(4)

    const tls_protocol_version_TLSv12 = UInt16(0x0303)
    const tls_protocol_version_TLSv13 = UInt16(0x0304)

    const _nw_socket_registry = Dict{Ptr{Cvoid}, NWSocket}()
    const _nw_socket_registry_lock = ReentrantLock()

    const _nw_send_registry = Dict{Ptr{Cvoid}, NWSendContext}()
    const _nw_send_registry_lock = ReentrantLock()

    function _nw_register_socket!(sock::NWSocket)
        key = pointer_from_objref(sock)
        lock(_nw_socket_registry_lock)
        _nw_socket_registry[key] = sock
        unlock(_nw_socket_registry_lock)
        sock.registry_key = key
        return key
    end

    function _nw_unregister_socket!(sock::NWSocket)
        key = sock.registry_key
        if key != C_NULL
            lock(_nw_socket_registry_lock)
            delete!(_nw_socket_registry, key)
            unlock(_nw_socket_registry_lock)
            sock.registry_key = C_NULL
        end
        return nothing
    end

    function _nw_register_send!(ctx::NWSendContext)::Ptr{Cvoid}
        key = pointer_from_objref(ctx)
        lock(_nw_send_registry_lock)
        _nw_send_registry[key] = ctx
        unlock(_nw_send_registry_lock)
        return key
    end

    function _nw_unregister_send!(ctx::NWSendContext)
        key = pointer_from_objref(ctx)
        lock(_nw_send_registry_lock)
        delete!(_nw_send_registry, key)
        unlock(_nw_send_registry_lock)
        return nothing
    end

    function _nw_lookup_socket(ctx::Ptr{Cvoid})::Union{NWSocket, Nothing}
        ctx == C_NULL && return nothing
        lock(_nw_socket_registry_lock)
        sock = get(_nw_socket_registry, ctx, nothing)
        unlock(_nw_socket_registry_lock)
        return sock
    end

    function _nw_lookup_send(ctx::Ptr{Cvoid})::Union{NWSendContext, Nothing}
        ctx == C_NULL && return nothing
        lock(_nw_send_registry_lock)
        send_ctx = get(_nw_send_registry, ctx, nothing)
        unlock(_nw_send_registry_lock)
        return send_ctx
    end

    @inline _nw_lock_synced(sock::NWSocket) = lock(sock.synced_lock)
    @inline _nw_unlock_synced(sock::NWSocket) = unlock(sock.synced_lock)
    @inline _nw_lock_base(sock::NWSocket) = lock(sock.base_socket_lock)
    @inline _nw_unlock_base(sock::NWSocket) = unlock(sock.base_socket_lock)
    @inline function _nw_socket_ptr(sock::NWSocket)::Ptr{Cvoid}
        key = sock.registry_key
        return key == C_NULL ? pointer_from_objref(sock) : key
    end

    function _nw_validate_event_loop(event_loop::Union{EventLoop, Nothing})::Bool
        return event_loop !== nothing
    end

    function _nw_set_event_loop!(socket::Socket, event_loop::EventLoop)::Union{Nothing, ErrorResult}
        socket.event_loop = event_loop
        nw_socket = socket.impl::NWSocket
        nw_socket.event_loop !== nothing && return ErrorResult(raise_error(ERROR_INVALID_STATE))
        if event_loop_group_acquire_from_event_loop(event_loop) === nothing
            logf(LogLevel.ERROR, LS_IO_SOCKET, "nw_socket=%p: failed to acquire event loop group.", _nw_socket_ptr(nw_socket))
            return ErrorResult(raise_error(ERROR_INVALID_STATE))
        end
        nw_socket.event_loop = event_loop
        return nothing
    end

    function _nw_release_event_loop!(nw_socket::NWSocket)
        if nw_socket.event_loop !== nothing
            event_loop_group_release_from_event_loop!(nw_socket.event_loop)
            nw_socket.event_loop = nothing
        end
        return nothing
    end

    @inline function _nw_state_mask(state::NWSocketState.T)
        return UInt16(state)
    end

    function _nw_state_string(state::UInt16)::String
        if state == _nw_state_mask(NWSocketState.INIT)
            return "INIT"
        elseif state == _nw_state_mask(NWSocketState.INVALID)
            return "INVALID"
        elseif state == _nw_state_mask(NWSocketState.CONNECTING)
            return "CONNECTING"
        elseif state == _nw_state_mask(NWSocketState.CONNECTED_READ)
            return "CONNECTED_READ"
        elseif state == _nw_state_mask(NWSocketState.CONNECTED_WRITE)
            return "CONNECTED_WRITE"
        elseif state == _nw_state_mask(NWSocketState.BOUND)
            return "BOUND"
        elseif state == _nw_state_mask(NWSocketState.LISTENING)
            return "LISTENING"
        elseif state == _nw_state_mask(NWSocketState.STOPPED)
            return "STOPPED"
        elseif state == _nw_state_mask(NWSocketState.ERROR)
            return "ERROR"
        elseif state == _nw_state_mask(NWSocketState.CLOSING)
            return "CLOSING"
        elseif state == _nw_state_mask(NWSocketState.CLOSED)
            return "CLOSED"
        elseif state == (_nw_state_mask(NWSocketState.CONNECTED_WRITE) | _nw_state_mask(NWSocketState.CONNECTED_READ))
            return "CONNECTED_WRITE | CONNECTED_READ"
        elseif state == (_nw_state_mask(NWSocketState.CLOSING) | _nw_state_mask(NWSocketState.CONNECTED_READ))
            return "CLOSING | CONNECTED_READ"
        elseif state == UInt16((~Int(_nw_state_mask(NWSocketState.CONNECTED_READ))) & 0xFFFF)
            return "~CONNECTED_READ"
        elseif state == UInt16((~Int(_nw_state_mask(NWSocketState.CONNECTED_WRITE))) & 0xFFFF)
            return "~CONNECTED_WRITE"
        else
            return "UNKNOWN"
        end
    end

    function _nw_set_socket_state!(nw_socket::NWSocket, state::Integer)
        state_masked = UInt16(state & 0xFFFF)
        logf(
            LogLevel.DEBUG,
            LS_IO_SOCKET,
            "nw_socket=%p: set state from %s to %s",
            _nw_socket_ptr(nw_socket),
            _nw_state_string(nw_socket.state),
            _nw_state_string(state_masked),
        )

        current = nw_socket.state
        read_write_bits = state_masked & (_nw_state_mask(NWSocketState.CONNECTED_WRITE) | _nw_state_mask(NWSocketState.CONNECTED_READ))
        result_state = current & ~_nw_state_mask(NWSocketState.CONNECTED_WRITE) & ~_nw_state_mask(NWSocketState.CONNECTED_READ)

        if state == ~Int(_nw_state_mask(NWSocketState.CONNECTED_WRITE)) ||
                state == ~Int(_nw_state_mask(NWSocketState.CONNECTED_READ))
            state = Int(NWSocketState.INVALID)
        end

        state_u = UInt16(state & 0xFFFF)
        if result_state < state_u ||
                (state_u == _nw_state_mask(NWSocketState.LISTENING) && result_state == _nw_state_mask(NWSocketState.STOPPED))
            result_state = state_u
        end

        result_state |= read_write_bits
        nw_socket.state = result_state

        logf(
            LogLevel.DEBUG,
            LS_IO_SOCKET,
            "nw_socket=%p: state now %s",
            _nw_socket_ptr(nw_socket),
            _nw_state_string(nw_socket.state),
        )
        return nothing
    end

    function _nw_determine_socket_error(err::Integer)::Int
        if err == errSSLUnknownRootCert
            return ERROR_IO_TLS_UNKNOWN_ROOT_CERTIFICATE
        elseif err == errSSLNoRootCert
            return ERROR_IO_TLS_NO_ROOT_CERTIFICATE_FOUND
        elseif err == errSSLCertExpired
            return ERROR_IO_TLS_CERTIFICATE_EXPIRED
        elseif err == errSSLCertNotYetValid
            return ERROR_IO_TLS_CERTIFICATE_NOT_YET_VALID
        elseif err == errSSLPeerHandshakeFail
            return ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE
        elseif err == errSSLBadCert
            return ERROR_IO_TLS_BAD_CERTIFICATE
        elseif err == errSSLPeerCertExpired
            return ERROR_IO_TLS_PEER_CERTIFICATE_EXPIRED
        elseif err == errSSLPeerBadCert
            return ERROR_IO_TLS_BAD_PEER_CERTIFICATE
        elseif err == errSSLPeerCertRevoked
            return ERROR_IO_TLS_PEER_CERTIFICATE_REVOKED
        elseif err == errSSLPeerCertUnknown
            return ERROR_IO_TLS_PEER_CERTIFICATE_UNKNOWN
        elseif err == errSSLInternal
            return ERROR_IO_TLS_INTERNAL_ERROR
        elseif err == errSSLClosedGraceful
            return ERROR_IO_TLS_CLOSED_GRACEFUL
        elseif err == errSSLClosedAbort
            return ERROR_IO_TLS_CLOSED_ABORT
        elseif err == errSSLXCertChainInvalid
            return ERROR_IO_TLS_INVALID_CERTIFICATE_CHAIN
        elseif err == errSSLHostNameMismatch
            return ERROR_IO_TLS_HOST_NAME_MISMATCH
        elseif err == errSecNotTrusted || err == errSSLPeerProtocolVersion
            return ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE
        elseif err == Libc.ECONNREFUSED
            return ERROR_IO_SOCKET_CONNECTION_REFUSED
        elseif err == Libc.ETIMEDOUT
            return ERROR_IO_SOCKET_TIMEOUT
        elseif err == Libc.EHOSTUNREACH || err == Libc.ENETUNREACH
            return ERROR_IO_SOCKET_NO_ROUTE_TO_HOST
        elseif err == Libc.EADDRNOTAVAIL
            return ERROR_IO_SOCKET_INVALID_ADDRESS
        elseif err == Libc.ENETDOWN
            return ERROR_IO_SOCKET_NETWORK_DOWN
        elseif err == Libc.ECONNABORTED
            return ERROR_IO_SOCKET_CONNECT_ABORTED
        elseif err == Libc.EADDRINUSE
            return ERROR_IO_SOCKET_ADDRESS_IN_USE
        elseif err == Libc.ENOBUFS || err == Libc.ENOMEM
            return ERROR_OOM
        elseif err == Libc.EAGAIN
            return ERROR_IO_READ_WOULD_BLOCK
        elseif err == Libc.EMFILE || err == Libc.ENFILE
            return ERROR_MAX_FDS_EXCEEDED
        elseif err == Libc.ENOENT || err == Libc.EINVAL
            return ERROR_FILE_INVALID_PATH
        elseif err == Libc.EAFNOSUPPORT
            return ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY
        elseif err == Libc.EACCES
            return ERROR_NO_PERMISSION
        else
            return ERROR_IO_SOCKET_NOT_CONNECTED
        end
    end

    function _nw_convert_nw_error(nw_error::nw_error_t)::Int
        nw_error == C_NULL && return 0
        err_code = ccall((:nw_error_get_error_code, _NW_NETWORK_LIB), Cint, (nw_error_t,), nw_error)
        return _nw_determine_socket_error(Int(err_code))
    end

    function _nw_convert_pton_error(pton_code::Integer)::Int
        if pton_code == 0
            return ERROR_IO_SOCKET_INVALID_ADDRESS
        end
        return _nw_determine_socket_error(Int(Libc.errno()))
    end

    function _nw_error_description(error::CFErrorRef)::String
        error == C_NULL && return "No error provided"
        desc = ccall((:CFErrorCopyDescription, _COREFOUNDATION_LIB), CFStringRef, (CFErrorRef,), error)
        desc == C_NULL && return "Unable to retrieve error description"
        buf = Memory{UInt8}(undef, 256)
        ok = ccall(
            (:CFStringGetCString, _COREFOUNDATION_LIB),
            UInt8,
            (CFStringRef, Ptr{UInt8}, Clong, UInt32),
            desc,
            pointer(buf),
            Clong(length(buf)),
            UInt32(0x08000100), # kCFStringEncodingUTF8
        )
        ccall((:CFRelease, _COREFOUNDATION_LIB), Cvoid, (CFTypeRef,), desc)
        if ok == 0
            return "Unable to retrieve error description"
        end
        len = findfirst(==(UInt8(0)), buf)
        len = len === nothing ? length(buf) : len - 1
        return String(Vector{UInt8}(buf[1:len]))
    end

    function _nw_byte_buf_write!(buf::ByteBuffer, src::Ptr{UInt8}, len::Int)::Bool
        len == 0 && return true
        cap = capacity(buf)
        if buf.len > _SIZE_MAX_HALF || len > _SIZE_MAX_HALF || buf.len + Csize_t(len) > cap
            return false
        end
        @inbounds for i in 1:len
            buf.mem[Int(buf.len) + i] = unsafe_load(src, i)
        end
        buf.len += Csize_t(len)
        return true
    end

    function _nw_read_queue_node_destroy!(node::ReadQueueNode)
        node.data != C_NULL && ccall((:dispatch_release, _NW_DISPATCH_LIB), Cvoid, (dispatch_data_t,), node.data)
        node.data = C_NULL
        return nothing
    end

    function _nw_create_dispatch_data(cursor::ByteCursor)::dispatch_data_t
        return ccall(
            (:dispatch_data_create, _NW_DISPATCH_LIB),
            dispatch_data_t,
            (Ptr{Cvoid}, Csize_t, dispatch_queue_t, Ptr{Cvoid}),
            cursor.ptr,
            cursor.len,
            C_NULL,
            C_NULL,
        )
    end

    function _nw_dispatch_data_size(data::dispatch_data_t)::Csize_t
        return ccall((:dispatch_data_get_size, _NW_DISPATCH_LIB), Csize_t, (dispatch_data_t,), data)
    end

    function _nw_dispatch_data_map(data::dispatch_data_t)
        buf_ref = Ref{Ptr{Cvoid}}(C_NULL)
        size_ref = Ref{Csize_t}(0)
        map_data = ccall(
            (:dispatch_data_create_map, _NW_DISPATCH_LIB),
            dispatch_data_t,
            (dispatch_data_t, Ref{Ptr{Cvoid}}, Ref{Csize_t}),
            data,
            buf_ref,
            size_ref,
        )
        return map_data, buf_ref[], size_ref[]
    end

    function _nw_tls_verify_block(
            nw_socket::NWSocket,
            metadata::sec_protocol_metadata_t,
            trust::sec_trust_t,
        )::Bool
        _ = metadata
        transport_ctx = nw_socket.tls_ctx === nothing ? nothing : nw_socket.tls_ctx.impl
        transport_ctx === nothing && return false

        if !transport_ctx.verify_peer
            logf(
                LogLevel.WARN,
                LS_IO_TLS,
                "nw_socket=%p: x.509 validation has been disabled. If this is not running in a test environment, this is likely a security vulnerability.",
                _nw_socket_ptr(nw_socket),
            )
            return true
        end

        trust_ref = ccall((:sec_trust_copy_ref, _NW_SECURITY_LIB), SecTrustRef, (sec_trust_t,), trust)
        trust_ref == C_NULL && return false

        if transport_ctx.ca_cert != C_NULL
            status = ccall(
                (:SecTrustSetAnchorCertificates, _NW_SECURITY_LIB),
                OSStatus,
                (SecTrustRef, CFArrayRef),
                trust_ref,
                transport_ctx.ca_cert,
            )
            if status != 0
                logf(
                    LogLevel.ERROR,
                    LS_IO_TLS,
                    "nw_socket=%p: SecTrustSetAnchorCertificates failed with OSStatus %d",
                    _nw_socket_ptr(nw_socket),
                    Int(status),
                )
                raise_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                ccall((:CFRelease, _COREFOUNDATION_LIB), Cvoid, (CFTypeRef,), trust_ref)
                return false
            end
        end

        policy = if nw_socket.host_name !== nothing
            name_ref = ccall(
                (:CFStringCreateWithCString, _COREFOUNDATION_LIB),
                CFStringRef,
                (Ptr{Cvoid}, Cstring, UInt32),
                Ptr{Cvoid}(C_NULL),
                nw_socket.host_name,
                UInt32(0x08000100),
            )
            policy_ref = ccall((:SecPolicyCreateSSL, _NW_SECURITY_LIB), SecPolicyRef, (UInt8, CFStringRef), 1, name_ref)
            name_ref != C_NULL && ccall((:CFRelease, _COREFOUNDATION_LIB), Cvoid, (CFTypeRef,), name_ref)
            policy_ref
        else
            ccall((:SecPolicyCreateBasicX509, _NW_SECURITY_LIB), SecPolicyRef, ())
        end

        if policy != C_NULL
            status = ccall(
                (:SecTrustSetPolicies, _NW_SECURITY_LIB),
                OSStatus,
                (SecTrustRef, SecPolicyRef),
                trust_ref,
                policy,
            )
            if status != 0
                logf(LogLevel.ERROR, LS_IO_TLS, "nw_socket=%p: SecTrustSetPolicies failed %d", _nw_socket_ptr(nw_socket), Int(status))
                raise_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
                ccall((:CFRelease, _COREFOUNDATION_LIB), Cvoid, (CFTypeRef,), policy)
                ccall((:CFRelease, _COREFOUNDATION_LIB), Cvoid, (CFTypeRef,), trust_ref)
                return false
            end
        end

        error_ref = Ref{CFErrorRef}(C_NULL)
        success = ccall(
            (:SecTrustEvaluateWithError, _NW_SECURITY_LIB),
            UInt8,
            (SecTrustRef, Ref{CFErrorRef}),
            trust_ref,
            error_ref,
        )

        verified = false
        if success != 0
            trust_result = Ref{Cint}(0)
            status = ccall(
                (:SecTrustGetTrustResult, _NW_SECURITY_LIB),
                OSStatus,
                (SecTrustRef, Ref{Cint}),
                trust_ref,
                trust_result,
            )
            if status == 0 && (trust_result[] == kSecTrustResultProceed || trust_result[] == kSecTrustResultUnspecified)
                verified = true
            end
        else
            err_desc = _nw_error_description(error_ref[])
            err_code = error_ref[] == C_NULL ? 0 :
                Int(ccall((:CFErrorGetCode, _COREFOUNDATION_LIB), Clong, (CFErrorRef,), error_ref[]))
            crt_error = _nw_determine_socket_error(err_code)
            logf(
                LogLevel.DEBUG,
                LS_IO_TLS,
                "nw_socket=%p: SecTrustEvaluateWithError failed with crt error %d: %s (CF error %d: %s)",
                _nw_socket_ptr(nw_socket),
                crt_error,
                error_name(crt_error),
                err_code,
                err_desc,
            )
        end

        policy != C_NULL && ccall((:CFRelease, _COREFOUNDATION_LIB), Cvoid, (CFTypeRef,), policy)
        trust_ref != C_NULL && ccall((:CFRelease, _COREFOUNDATION_LIB), Cvoid, (CFTypeRef,), trust_ref)
        error_ref[] != C_NULL && ccall((:CFRelease, _COREFOUNDATION_LIB), Cvoid, (CFTypeRef,), error_ref[])
        return verified
    end

    function _nw_setup_tls_options!(tls_options::nw_protocol_options_t, nw_socket::NWSocket)
        sec_options = ccall(
            (:nw_tls_copy_sec_protocol_options, _NW_NETWORK_LIB),
            sec_protocol_options_t,
            (nw_protocol_options_t,),
            tls_options,
        )
        sec_options == C_NULL && return nothing

        transport_ctx = nw_socket.tls_ctx === nothing ? nothing : nw_socket.tls_ctx.impl
        transport_ctx === nothing && return nothing

        local_identity = transport_ctx.secitem_identity
        if local_identity == C_NULL && transport_ctx.certs != C_NULL
            local_identity = ccall(
                (:CFArrayGetValueAtIndex, _COREFOUNDATION_LIB),
                Ptr{Cvoid},
                (Ptr{Cvoid}, Clong),
                transport_ctx.certs,
                0,
            )
        end
        if local_identity != C_NULL
            ccall(
                (:sec_protocol_options_set_local_identity, _NW_SECURITY_LIB),
                Cvoid,
                (sec_protocol_options_t, SecIdentityRef),
                sec_options,
                local_identity,
            )
        end

        if transport_ctx.minimum_tls_version == TlsVersion.TLSv1_2
            ccall(
                (:sec_protocol_options_set_min_tls_protocol_version, _NW_SECURITY_LIB),
                Cvoid,
                (sec_protocol_options_t, UInt16),
                sec_options,
                tls_protocol_version_TLSv12,
            )
        elseif transport_ctx.minimum_tls_version == TlsVersion.TLSv1_3
            ccall(
                (:sec_protocol_options_set_min_tls_protocol_version, _NW_SECURITY_LIB),
                Cvoid,
                (sec_protocol_options_t, UInt16),
                sec_options,
                tls_protocol_version_TLSv13,
            )
        else
            # system defaults
        end

        ccall(
            (:sec_protocol_options_set_peer_authentication_required, _NW_SECURITY_LIB),
            Cvoid,
            (sec_protocol_options_t, UInt8),
            sec_options,
            transport_ctx.verify_peer ? 1 : 0,
        )

        if nw_socket.host_name !== nothing
            ccall(
                (:sec_protocol_options_set_tls_server_name, _NW_SECURITY_LIB),
                Cvoid,
                (sec_protocol_options_t, Cstring),
                sec_options,
                nw_socket.host_name,
            )
        end

        if nw_socket.alpn_list !== nothing
            for proto in split(nw_socket.alpn_list, ';'; keepempty = false)
                ccall(
                    (:sec_protocol_options_add_tls_application_protocol, _NW_SECURITY_LIB),
                    Cvoid,
                    (sec_protocol_options_t, Cstring),
                    sec_options,
                    proto,
                )
            end
        end

        if nw_socket.event_loop === nothing
            logf(
                LogLevel.ERROR,
                LS_IO_TLS,
                "nw_socket=%p: TLS verify block requires event loop with dispatch queue",
                _nw_socket_ptr(nw_socket),
            )
        else
            _nw_ensure_callbacks!()
            dispatch_queue = nw_socket.event_loop.impl_data.dispatch_queue
            verify_ctx = pointer_from_objref(nw_socket)
            blk = BlocksABI.make_stack_block_ctx(_nw_tls_verify_cb[], verify_ctx)
            try
                ccall(
                    (:sec_protocol_options_set_verify_block, _NW_SECURITY_LIB),
                    Cvoid,
                    (sec_protocol_options_t, Ptr{Cvoid}, dispatch_queue_t),
                    sec_options,
                    blk.ptr,
                    dispatch_queue,
                )
            finally
                BlocksABI.free!(blk)
            end
        end

        ccall((:nw_release, _NW_NETWORK_LIB), Cvoid, (Ptr{Cvoid},), sec_options)
        return nothing
    end

    function _nw_setup_tcp_options!(tcp_options::nw_protocol_options_t, options::SocketOptions)
        if options.domain == SocketDomain.LOCAL
            return nothing
        end

        if options.connect_timeout_ms != 0
            timeout_sec = UInt32(options.connect_timeout_ms ÷ 1000)
            ccall(
                (:nw_tcp_options_set_connection_timeout, _NW_NETWORK_LIB),
                Cvoid,
                (nw_protocol_options_t, UInt32),
                tcp_options,
                timeout_sec,
            )
        end

        if options.keepalive && options.keep_alive_interval_sec != 0 && options.keep_alive_timeout_sec != 0
            ccall(
                (:nw_tcp_options_set_enable_keepalive, _NW_NETWORK_LIB),
                Cvoid,
                (nw_protocol_options_t, UInt8),
                tcp_options,
                options.keepalive ? 1 : 0,
            )
            ccall(
                (:nw_tcp_options_set_keepalive_idle_time, _NW_NETWORK_LIB),
                Cvoid,
                (nw_protocol_options_t, UInt32),
                tcp_options,
                options.keep_alive_interval_sec,
            )
            ccall(
                (:nw_tcp_options_set_keepalive_interval, _NW_NETWORK_LIB),
                Cvoid,
                (nw_protocol_options_t, UInt32),
                tcp_options,
                options.keep_alive_timeout_sec,
            )
        end

        if options.keep_alive_max_failed_probes != 0
            ccall(
                (:nw_tcp_options_set_keepalive_count, _NW_NETWORK_LIB),
                Cvoid,
                (nw_protocol_options_t, UInt32),
                tcp_options,
                options.keep_alive_max_failed_probes,
            )
        end

        if g_aws_channel_max_fragment_size[] < KB_16
            ccall(
                (:nw_tcp_options_set_maximum_segment_size, _NW_NETWORK_LIB),
                Cvoid,
                (nw_protocol_options_t, UInt32),
                tcp_options,
                UInt32(g_aws_channel_max_fragment_size[]),
            )
        end
        return nothing
    end

    function _nw_setup_socket_params!(nw_socket::NWSocket, options::SocketOptions)::Union{Nothing, ErrorResult}
        _nw_ensure_callbacks!()
        _nw_ensure_globals!()
        if nw_socket.parameters != C_NULL
            ccall((:nw_release, _NW_NETWORK_LIB), Cvoid, (Ptr{Cvoid},), nw_socket.parameters)
            nw_socket.parameters = C_NULL
            nw_socket.parameters_context = nothing
        end

        setup_tls = false
        if is_using_secitem() && nw_socket.tls_ctx !== nothing
            setup_tls = true
        end

        if options.type == SocketType.STREAM
            if setup_tls
                nw_socket.event_loop === nothing && return ErrorResult(raise_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP))
                transport_ctx = nw_socket.tls_ctx.impl
                if transport_ctx.minimum_tls_version == TlsVersion.SSLv3 ||
                        transport_ctx.minimum_tls_version == TlsVersion.TLSv1 ||
                        transport_ctx.minimum_tls_version == TlsVersion.TLSv1_1
                    raise_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
                    return ErrorResult(ERROR_IO_SOCKET_INVALID_OPTIONS)
                end

                if options.domain == SocketDomain.IPV4 || options.domain == SocketDomain.IPV6 || options.domain == SocketDomain.LOCAL
                    ctx = NWParametersContext(nw_socket, options)
                    nw_socket.parameters_context = ctx
                    ctx_ptr = pointer_from_objref(ctx)
                    tls_blk = BlocksABI.make_stack_block_ctx(_nw_tls_options_cb[], ctx_ptr)
                    tcp_blk = BlocksABI.make_stack_block_ctx(_nw_tcp_options_cb[], ctx_ptr)
                    try
                        params = GC.@preserve ctx ccall(
                            (:nw_parameters_create_secure_tcp, _NW_NETWORK_LIB),
                            nw_parameters_t,
                            (Ptr{Cvoid}, Ptr{Cvoid}),
                            tls_blk.ptr,
                            tcp_blk.ptr,
                        )
                        nw_socket.parameters = params
                    finally
                        BlocksABI.free!(tls_blk)
                        BlocksABI.free!(tcp_blk)
                    end
                else
                    raise_error(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
                    return ErrorResult(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
                end
            else
                if options.domain == SocketDomain.IPV4 || options.domain == SocketDomain.IPV6 || options.domain == SocketDomain.LOCAL
                    ctx = NWParametersContext(nw_socket, options)
                    nw_socket.parameters_context = ctx
                    ctx_ptr = pointer_from_objref(ctx)
                    tcp_blk = BlocksABI.make_stack_block_ctx(_nw_tcp_options_cb[], ctx_ptr)
                    try
                        params = GC.@preserve ctx ccall(
                            (:nw_parameters_create_secure_tcp, _NW_NETWORK_LIB),
                            nw_parameters_t,
                            (Ptr{Cvoid}, Ptr{Cvoid}),
                            _NW_DISABLE_PROTOCOL_BLOCK[],
                            tcp_blk.ptr,
                        )
                        nw_socket.parameters = params
                    finally
                        BlocksABI.free!(tcp_blk)
                    end
                else
                    raise_error(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
                    return ErrorResult(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
                end
            end

            if options.domain == SocketDomain.LOCAL && nw_socket.parameters != C_NULL
                ccall(
                    (:nw_parameters_set_reuse_local_address, _NW_NETWORK_LIB),
                    Cvoid,
                    (nw_parameters_t, UInt8),
                    nw_socket.parameters,
                    1,
                )
            end
        elseif options.type == SocketType.DGRAM
            if setup_tls
                raise_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
                return ErrorResult(ERROR_IO_SOCKET_INVALID_OPTIONS)
            end
            ctx = NWParametersContext(nw_socket, options)
            nw_socket.parameters_context = ctx
            ctx_ptr = pointer_from_objref(ctx)
            udp_blk = BlocksABI.make_stack_block_ctx(_nw_tcp_options_cb[], ctx_ptr)
            try
                params = GC.@preserve ctx ccall(
                    (:nw_parameters_create_secure_udp, _NW_NETWORK_LIB),
                    nw_parameters_t,
                    (Ptr{Cvoid}, Ptr{Cvoid}),
                    _NW_DISABLE_PROTOCOL_BLOCK[],
                    udp_blk.ptr,
                )
                nw_socket.parameters = params
            finally
                BlocksABI.free!(udp_blk)
            end
        end

        if nw_socket.parameters == C_NULL
            raise_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_OPTIONS)
        end
        return nothing
    end

    function _nw_socket_state_changed(ctx::Ptr{Cvoid}, state::Cint, error::nw_error_t)
        nw_socket = _nw_lookup_socket(ctx)
        nw_socket === nothing && return nothing
        _nw_handle_connection_state_changed(nw_socket, state, error)
        return nothing
    end

    function _nw_listener_state_changed(ctx::Ptr{Cvoid}, state::Cint, error::nw_error_t)
        nw_socket = _nw_lookup_socket(ctx)
        nw_socket === nothing && return nothing
        _nw_handle_listener_state_changed(nw_socket, state, error)
        return nothing
    end

    function _nw_listener_new_connection(ctx::Ptr{Cvoid}, connection::nw_connection_t)
        nw_socket = _nw_lookup_socket(ctx)
        nw_socket === nothing && return nothing
        _nw_handle_listener_new_connection(nw_socket, connection)
        return nothing
    end

    function _nw_receive_completion(
            ctx::Ptr{Cvoid},
            data::dispatch_data_t,
            context::nw_content_context_t,
            is_complete::UInt8,
            error::nw_error_t,
        )
        nw_socket = _nw_lookup_socket(ctx)
        nw_socket === nothing && return nothing
        _nw_handle_receive_completion(nw_socket, data, context, is_complete != 0, error)
        return nothing
    end

    function _nw_send_completion(ctx::Ptr{Cvoid}, error::nw_error_t, data::dispatch_data_t)
        send_ctx = _nw_lookup_send(ctx)
        send_ctx === nothing && return nothing
        _nw_unregister_send!(send_ctx)
        _nw_handle_send_completion(send_ctx.socket, error, data, send_ctx.written_fn, send_ctx.user_data)
        return nothing
    end

    function _nw_tls_verify_callback(
            ctx::Ptr{Cvoid},
            metadata::sec_protocol_metadata_t,
            trust::sec_trust_t,
        )::UInt8
        nw_socket = _nw_lookup_socket(ctx)
        nw_socket === nothing && return UInt8(0)
        return _nw_tls_verify_block(nw_socket, metadata, trust) ? UInt8(1) : UInt8(0)
    end

    function _nw_tls_options_callback(ctx::Ptr{Cvoid}, options::nw_protocol_options_t)
        context = unsafe_pointer_to_objref(ctx)::NWParametersContext
        _nw_setup_tls_options!(options, context.socket)
        return nothing
    end

    function _nw_tcp_options_callback(ctx::Ptr{Cvoid}, options::nw_protocol_options_t)
        context = unsafe_pointer_to_objref(ctx)::NWParametersContext
        _nw_setup_tcp_options!(options, context.options)
        return nothing
    end

    # --- Clang Blocks ABI invokers (no C shim) ---
    #
    # Network.framework APIs accept blocks, where the invoke function receives
    # the block pointer as its first argument. We capture our callback context
    # pointer in the block, extract it here, and then call the existing handlers.

    function _nw_connection_state_changed_invoke(block_ptr::Ptr{Cvoid}, state::Cint, error::nw_error_t)::Cvoid
        try
            ctx = BlocksABI.captured_ctx(block_ptr)
            _nw_socket_state_changed(ctx, state, error)
        catch ex
            try
                @error "Fatal error in nw_connection state handler" exception = (ex, catch_backtrace())
            catch
            end
        end
        return
    end

    function _nw_listener_state_changed_invoke(block_ptr::Ptr{Cvoid}, state::Cint, error::nw_error_t)::Cvoid
        try
            ctx = BlocksABI.captured_ctx(block_ptr)
            _nw_listener_state_changed(ctx, state, error)
        catch ex
            try
                @error "Fatal error in nw_listener state handler" exception = (ex, catch_backtrace())
            catch
            end
        end
        return
    end

    function _nw_listener_new_connection_invoke(block_ptr::Ptr{Cvoid}, connection::nw_connection_t)::Cvoid
        try
            ctx = BlocksABI.captured_ctx(block_ptr)
            _nw_listener_new_connection(ctx, connection)
        catch ex
            try
                @error "Fatal error in nw_listener new connection handler" exception = (ex, catch_backtrace())
            catch
            end
        end
        return
    end

    function _nw_receive_completion_invoke(
            block_ptr::Ptr{Cvoid},
            data::dispatch_data_t,
            context::nw_content_context_t,
            is_complete::UInt8,
            error::nw_error_t,
        )::Cvoid
        try
            ctx = BlocksABI.captured_ctx(block_ptr)
            _nw_receive_completion(ctx, data, context, is_complete, error)
        catch ex
            try
                @error "Fatal error in nw_connection receive completion" exception = (ex, catch_backtrace())
            catch
            end
        end
        return
    end

    function _nw_send_completion_invoke(block_ptr::Ptr{Cvoid}, error::nw_error_t)::Cvoid
        ctx_mem = BlocksABI.captured_ctx(block_ptr)
        try
            ctx_u8 = Ptr{UInt8}(ctx_mem)
            send_ctx_ptr = unsafe_load(Ptr{Ptr{Cvoid}}(ctx_u8))
            data = dispatch_data_t(unsafe_load(Ptr{Ptr{Cvoid}}(ctx_u8 + sizeof(Ptr{Cvoid}))))
            _nw_send_completion(send_ctx_ptr, error, data)
        catch ex
            try
                @error "Fatal error in nw_connection send completion" exception = (ex, catch_backtrace())
            catch
            end
        finally
            ctx_mem != C_NULL && Base.Libc.free(ctx_mem)
        end
        return
    end

    function _nw_tls_verify_invoke(
            block_ptr::Ptr{Cvoid},
            metadata::sec_protocol_metadata_t,
            trust::sec_trust_t,
            complete::Ptr{Cvoid},
        )::Cvoid
        verified = false
        try
            ctx = BlocksABI.captured_ctx(block_ptr)
            verified = _nw_tls_verify_callback(ctx, metadata, trust) != 0
        catch ex
            try
                @error "Fatal error in sec_protocol verify callback" exception = (ex, catch_backtrace())
            catch
            end
            verified = false
        end

        # Always call `complete(...)` or the handshake can stall.
        try
            complete != C_NULL && BlocksABI.call_block_void_bool(complete, verified)
        catch ex
            try
                @error "Fatal error calling sec_protocol verify completion block" exception = (ex, catch_backtrace())
            catch
            end
        end
        return
    end

    function _nw_tls_options_invoke(block_ptr::Ptr{Cvoid}, options::nw_protocol_options_t)::Cvoid
        try
            ctx = BlocksABI.captured_ctx(block_ptr)
            _nw_tls_options_callback(ctx, options)
        catch ex
            try
                @error "Fatal error in nw_parameters TLS options block" exception = (ex, catch_backtrace())
            catch
            end
        end
        return
    end

    function _nw_tcp_options_invoke(block_ptr::Ptr{Cvoid}, options::nw_protocol_options_t)::Cvoid
        try
            ctx = BlocksABI.captured_ctx(block_ptr)
            _nw_tcp_options_callback(ctx, options)
        catch ex
            try
                @error "Fatal error in nw_parameters TCP/UDP options block" exception = (ex, catch_backtrace())
            catch
            end
        end
        return
    end

    function _nw_client_set_queue(handle_ptr::Ptr{IoHandle}, queue::Ptr{Cvoid})
        handle = unsafe_load(handle_ptr)
        ccall((:nw_connection_set_queue, _NW_NETWORK_LIB), Cvoid, (nw_connection_t, dispatch_queue_t), handle.handle, queue)
        return nothing
    end

    function _nw_listener_set_queue(handle_ptr::Ptr{IoHandle}, queue::Ptr{Cvoid})
        handle = unsafe_load(handle_ptr)
        ccall((:nw_listener_set_queue, _NW_NETWORK_LIB), Cvoid, (nw_listener_t, dispatch_queue_t), handle.handle, queue)
        return nothing
    end

    const _nw_state_changed_cb = Ref{Ptr{Cvoid}}(C_NULL)
    const _nw_listener_state_changed_cb = Ref{Ptr{Cvoid}}(C_NULL)
    const _nw_listener_new_conn_cb = Ref{Ptr{Cvoid}}(C_NULL)
    const _nw_receive_cb = Ref{Ptr{Cvoid}}(C_NULL)
    const _nw_send_cb = Ref{Ptr{Cvoid}}(C_NULL)
    const _nw_tls_verify_cb = Ref{Ptr{Cvoid}}(C_NULL)
    const _nw_tls_options_cb = Ref{Ptr{Cvoid}}(C_NULL)
    const _nw_tcp_options_cb = Ref{Ptr{Cvoid}}(C_NULL)
    const _nw_client_set_queue_c = Ref{Ptr{Cvoid}}(C_NULL)
    const _nw_listener_set_queue_c = Ref{Ptr{Cvoid}}(C_NULL)

    function _nw_ensure_callbacks!()
        _nw_state_changed_cb[] != C_NULL && return nothing
        _nw_state_changed_cb[] = @cfunction(_nw_connection_state_changed_invoke, Cvoid, (Ptr{Cvoid}, Cint, nw_error_t))
        _nw_listener_state_changed_cb[] = @cfunction(_nw_listener_state_changed_invoke, Cvoid, (Ptr{Cvoid}, Cint, nw_error_t))
        _nw_listener_new_conn_cb[] = @cfunction(_nw_listener_new_connection_invoke, Cvoid, (Ptr{Cvoid}, nw_connection_t))
        _nw_receive_cb[] = @cfunction(_nw_receive_completion_invoke, Cvoid, (Ptr{Cvoid}, dispatch_data_t, nw_content_context_t, UInt8, nw_error_t))
        _nw_send_cb[] = @cfunction(_nw_send_completion_invoke, Cvoid, (Ptr{Cvoid}, nw_error_t))
        _nw_tls_verify_cb[] = @cfunction(_nw_tls_verify_invoke, Cvoid, (Ptr{Cvoid}, sec_protocol_metadata_t, sec_trust_t, Ptr{Cvoid}))
        _nw_tls_options_cb[] = @cfunction(_nw_tls_options_invoke, Cvoid, (Ptr{Cvoid}, nw_protocol_options_t))
        _nw_tcp_options_cb[] = @cfunction(_nw_tcp_options_invoke, Cvoid, (Ptr{Cvoid}, nw_protocol_options_t))
        _nw_client_set_queue_c[] = @cfunction(_nw_client_set_queue, Cvoid, (Ptr{IoHandle}, Ptr{Cvoid}))
        _nw_listener_set_queue_c[] = @cfunction(_nw_listener_set_queue, Cvoid, (Ptr{IoHandle}, Ptr{Cvoid}))
        return nothing
    end

    function _nw_schedule_next_read!(nw_socket::NWSocket)::Union{Nothing, ErrorResult}
        _nw_lock_synced(nw_socket)
        if nw_socket.read_scheduled
            _nw_unlock_synced(nw_socket)
            return nothing
        end
        if (nw_socket.state & _nw_state_mask(NWSocketState.CLOSING)) != 0 ||
                (nw_socket.state & _nw_state_mask(NWSocketState.CONNECTED_READ)) == 0
            _nw_unlock_synced(nw_socket)
            return nothing
        end

        nw_socket.read_scheduled = true
        connection = nw_socket.connection
        _nw_unlock_synced(nw_socket)

        if connection == C_NULL
            return ErrorResult(raise_error(ERROR_IO_SOCKET_NOT_CONNECTED))
        end

        _nw_ensure_callbacks!()
        recv_ctx = pointer_from_objref(nw_socket)
        blk = BlocksABI.make_stack_block_ctx(_nw_receive_cb[], recv_ctx)
        try
            ccall(
                (:nw_connection_receive, _NW_NETWORK_LIB),
                Cvoid,
                (nw_connection_t, UInt32, UInt32, Ptr{Cvoid}),
                connection,
                UInt32(1),
                UInt32(KB_16),
                blk.ptr,
            )
        finally
            BlocksABI.free!(blk)
        end
        return nothing
    end

    function _nw_handle_incoming_data(
            nw_socket::NWSocket,
            error_code::Int,
            data::dispatch_data_t,
            is_complete::Bool,
        )
        nw_socket.event_loop === nothing && return nothing

        if data != C_NULL
            ccall((:dispatch_retain, _NW_DISPATCH_LIB), Cvoid, (dispatch_data_t,), data)
        end

        task = ScheduledTask(
            TaskFn(function(status)
                try
                    if data != C_NULL
                        node = ReadQueueNode(data, 0)
                        push!(nw_socket.read_queue, node)
                    end

                    if nw_socket.base_socket !== nothing
                        socket = nw_socket.base_socket
                        if socket.options.type != SocketType.DGRAM && is_complete
                            _nw_lock_synced(nw_socket)
                            _nw_set_socket_state!(nw_socket, ~Int(_nw_state_mask(NWSocketState.CONNECTED_READ)))
                            _nw_unlock_synced(nw_socket)
                        end
                        if nw_socket.on_readable !== nothing
                            nw_socket.on_readable(socket, error_code, nw_socket.on_readable_user_data)
                        end
                    end
                catch e
                    Core.println("nw_readable_task task errored: $e")
                end
                return nothing
            end);
            type_tag = "nw_readable_task",
        )
        event_loop_schedule_task_now!(nw_socket.event_loop, task)
        return nothing
    end

    function _nw_handle_receive_completion(
            nw_socket::NWSocket,
            data::dispatch_data_t,
            context::nw_content_context_t,
            is_complete::Bool,
            error::nw_error_t,
        )
        _nw_lock_synced(nw_socket)
        nw_socket.read_scheduled = false
        _nw_unlock_synced(nw_socket)

        err_code = _nw_convert_nw_error(error)
        complete = false
        if is_complete
            complete = ccall((:nw_content_context_get_is_final, _NW_NETWORK_LIB), UInt8, (nw_content_context_t,), context) != 0
        end

        if nw_socket.base_socket !== nothing
            logf(
                LogLevel.TRACE,
                LS_IO_SOCKET,
                "NW receive complete: is_complete=%d is_final=%d err=%d",
                is_complete ? 1 : 0,
                complete ? 1 : 0,
                err_code,
            )
        end

        _nw_handle_incoming_data(nw_socket, err_code, data, complete)
        _nw_schedule_next_read!(nw_socket)
        return nothing
    end

    function _nw_handle_write_result(
            nw_socket::NWSocket,
            error_code::Int,
            bytes_written::Csize_t,
            written_fn::Union{SocketOnWriteCompletedFn, Nothing},
            user_data,
        )
        nw_socket.event_loop === nothing && return nothing
        task = ScheduledTask(
            TaskFn(function(status)
                try
                    if TaskStatus.T(status) != TaskStatus.CANCELED && written_fn !== nothing
                        _nw_lock_base(nw_socket)
                        socket = nw_socket.base_socket
                        written_fn(socket, error_code, bytes_written, user_data)
                        _nw_unlock_base(nw_socket)
                    end
                catch e
                    Core.println("nw_written_task task errored: $e")
                end
                return nothing
            end);
            type_tag = "nw_written_task",
        )
        event_loop_schedule_task_now!(nw_socket.event_loop, task)
        return nothing
    end

    function _nw_handle_send_completion(
            nw_socket::NWSocket,
            error::nw_error_t,
            data::dispatch_data_t,
            written_fn::SocketOnWriteCompletedFn,
            user_data,
        )
        err_code = _nw_convert_nw_error(error)
        if err_code != 0
            nw_socket.last_error = err_code
        end
        size_written = data == C_NULL ? Csize_t(0) : _nw_dispatch_data_size(data)

        _nw_handle_write_result(nw_socket, err_code, size_written, written_fn, user_data)

        if data != C_NULL
            ccall((:dispatch_release, _NW_DISPATCH_LIB), Cvoid, (dispatch_data_t,), data)
        end

        _nw_lock_synced(nw_socket)
        if nw_socket.pending_writes > 0
            nw_socket.pending_writes -= 1
        end
        should_cancel = (nw_socket.state & _nw_state_mask(NWSocketState.CLOSING)) != 0 && nw_socket.pending_writes == 0
        _nw_unlock_synced(nw_socket)

        should_cancel && _nw_cancel_socket!(nw_socket)
        return nothing
    end

    function _nw_connection_ready!(nw_socket::NWSocket, connection::nw_connection_t)
        _nw_lock_base(nw_socket)
        socket = nw_socket.base_socket
        if socket !== nothing
            path = ccall((:nw_connection_copy_current_path, _NW_NETWORK_LIB), nw_path_t, (nw_connection_t,), connection)
            endpoint = ccall((:nw_path_copy_effective_local_endpoint, _NW_NETWORK_LIB), nw_endpoint_t, (nw_path_t,), path)
            path != C_NULL && ccall((:nw_release, _NW_NETWORK_LIB), Cvoid, (Ptr{Cvoid},), path)
            hostname = ccall((:nw_endpoint_get_hostname, _NW_NETWORK_LIB), Cstring, (nw_endpoint_t,), endpoint)
            port = ccall((:nw_endpoint_get_port, _NW_NETWORK_LIB), UInt16, (nw_endpoint_t,), endpoint)
            endpoint != C_NULL && ccall((:nw_release, _NW_NETWORK_LIB), Cvoid, (Ptr{Cvoid},), endpoint)
            if hostname != C_NULL
                host_str = unsafe_string(hostname)
                set_address!(socket.local_endpoint, host_str)
                socket.local_endpoint.port = port
            end

            tls_def = ccall((:nw_protocol_copy_tls_definition, _NW_NETWORK_LIB), nw_protocol_definition_t, ())
            metadata = ccall(
                (:nw_connection_copy_protocol_metadata, _NW_NETWORK_LIB),
                nw_protocol_metadata_t,
                (nw_connection_t, nw_protocol_definition_t),
                connection,
                tls_def,
            )
            tls_def != C_NULL && ccall((:nw_release, _NW_NETWORK_LIB), Cvoid, (Ptr{Cvoid},), tls_def)
            if metadata != C_NULL
                negotiated = ccall(
                    (:sec_protocol_metadata_get_negotiated_protocol, _NW_SECURITY_LIB),
                    Cstring,
                    (sec_protocol_metadata_t,),
                    metadata,
                )
                if negotiated != C_NULL
                    nw_socket.protocol_buf = byte_buf_from_c_str(unsafe_string(negotiated))
                end
                ccall((:nw_release, _NW_NETWORK_LIB), Cvoid, (Ptr{Cvoid},), metadata)
            end
        end
        _nw_unlock_base(nw_socket)

        _nw_lock_synced(nw_socket)
        _nw_set_socket_state!(nw_socket, Int(_nw_state_mask(NWSocketState.CONNECTED_WRITE)) | Int(_nw_state_mask(NWSocketState.CONNECTED_READ)))
        _nw_unlock_synced(nw_socket)

        nw_socket.connection_setup = true
        if nw_socket.timeout_task !== nothing && nw_socket.event_loop !== nothing
            event_loop_cancel_task!(nw_socket.event_loop, nw_socket.timeout_task)
        end

        if nw_socket.on_connection_result !== nothing
            _nw_lock_base(nw_socket)
            socket = nw_socket.base_socket
            nw_socket.on_connection_result(socket, 0, nw_socket.connect_result_user_data)
            _nw_unlock_base(nw_socket)
        else
            logf(
                LogLevel.TRACE,
                LS_IO_SOCKET,
                "nw_socket=%p: connection ready but no connect callback set",
                _nw_socket_ptr(nw_socket),
            )
        end
        return nothing
    end

    function _nw_handle_connection_state_changed(nw_socket::NWSocket, state::Cint, error::nw_error_t)
        err_code = _nw_convert_nw_error(error)
        if nw_socket.event_loop === nothing
            return nothing
        end

        raw_code = error == C_NULL ? 0 : ccall((:nw_error_get_error_code, _NW_NETWORK_LIB), Cint, (nw_error_t,), error)
        raw_domain = error == C_NULL ? 0 : ccall((:nw_error_get_error_domain, _NW_NETWORK_LIB), Cint, (nw_error_t,), error)

        task = ScheduledTask(
            TaskFn(function(status)
                try
                    if TaskStatus.T(status) == TaskStatus.CANCELED
                        return nothing
                    end

                    if state == 5 # nw_connection_state_cancelled
                        _nw_lock_synced(nw_socket)
                        _nw_set_socket_state!(nw_socket, Int(_nw_state_mask(NWSocketState.CLOSED)))
                        _nw_unlock_synced(nw_socket)
                        if nw_socket.on_close_complete !== nothing
                            nw_socket.on_close_complete(nw_socket.close_user_data)
                        end
                        if nw_socket.connection != C_NULL
                            ccall((:nw_release, _NW_NETWORK_LIB), Cvoid, (Ptr{Cvoid},), nw_socket.connection)
                            nw_socket.connection = C_NULL
                        end
                        _nw_release_event_loop!(nw_socket)
                        _nw_unregister_socket!(nw_socket)
                        if nw_socket.cleanup_requested
                            _nw_destroy_socket!(nw_socket)
                        end
                    elseif state == 3 # nw_connection_state_ready
                        _nw_connection_ready!(nw_socket, nw_socket.connection)
                    end

                    if err_code != 0
                        logf(
                            LogLevel.ERROR,
                            LS_IO_SOCKET,
                            "nw_connection error (domain=%d raw=%d mapped=%d)",
                            Int(raw_domain),
                            Int(raw_code),
                            err_code,
                        )
                        nw_socket.last_error = err_code
                        _nw_lock_synced(nw_socket)
                        _nw_set_socket_state!(nw_socket, Int(_nw_state_mask(NWSocketState.ERROR)))
                        _nw_unlock_synced(nw_socket)

                        if !nw_socket.connection_setup
                            if nw_socket.on_connection_result !== nothing
                                _nw_lock_base(nw_socket)
                                socket = nw_socket.base_socket
                                nw_socket.on_connection_result(socket, err_code, nw_socket.connect_result_user_data)
                                _nw_unlock_base(nw_socket)
                            end
                            nw_socket.connection_setup = true
                            if nw_socket.timeout_task !== nothing && nw_socket.event_loop !== nothing
                                event_loop_cancel_task!(nw_socket.event_loop, nw_socket.timeout_task)
                            end
                        else
                            _nw_handle_incoming_data(nw_socket, err_code, C_NULL, false)
                        end
                    end
                catch e
                    Core.println("nw_conn_state task errored: $e")
                end
                return nothing
            end);
            type_tag = "nw_conn_state",
        )
        event_loop_schedule_task_now!(nw_socket.event_loop, task)
        return nothing
    end

    function _nw_handle_listener_state_changed(nw_socket::NWSocket, state::Cint, error::nw_error_t)
        err_code = _nw_convert_nw_error(error)
        nw_socket.event_loop === nothing && return nothing

        raw_code = error == C_NULL ? 0 : ccall((:nw_error_get_error_code, _NW_NETWORK_LIB), Cint, (nw_error_t,), error)
        raw_domain = error == C_NULL ? 0 : ccall((:nw_error_get_error_domain, _NW_NETWORK_LIB), Cint, (nw_error_t,), error)

        task = ScheduledTask(
            TaskFn(function(status)
                try
                    if TaskStatus.T(status) == TaskStatus.CANCELED
                        return nothing
                    end

                    if state == 2 # nw_listener_state_ready
                        # Network.framework may report port 0 briefly even after READY when binding
                        # to port 0. Delay the accept-started callback until we can observe a
                        # non-zero port (or time out and proceed with 0).
                        _nw_listener_poll_port_until_ready!(nw_socket)
                    elseif state == 3 # nw_listener_state_failed
                        logf(
                            LogLevel.ERROR,
                            LS_IO_SOCKET,
                            "nw_listener failed (domain=%d raw=%d mapped=%d)",
                            Int(raw_domain),
                            Int(raw_code),
                            err_code,
                        )
                        _nw_lock_synced(nw_socket)
                        _nw_set_socket_state!(nw_socket, Int(_nw_state_mask(NWSocketState.ERROR)))
                        _nw_unlock_synced(nw_socket)
                        _nw_lock_base(nw_socket)
                        if nw_socket.on_accept_started !== nothing && nw_socket.base_socket !== nothing
                            nw_socket.on_accept_started(nw_socket.base_socket, err_code, nw_socket.listen_accept_started_user_data)
                        end
                        _nw_unlock_base(nw_socket)
                    elseif state == 4 # nw_listener_state_cancelled
                        _nw_lock_synced(nw_socket)
                        _nw_set_socket_state!(nw_socket, Int(_nw_state_mask(NWSocketState.CLOSED)))
                        _nw_unlock_synced(nw_socket)
                        if nw_socket.on_close_complete !== nothing
                            nw_socket.on_close_complete(nw_socket.close_user_data)
                        end
                        if nw_socket.listener != C_NULL
                            ccall((:nw_release, _NW_NETWORK_LIB), Cvoid, (Ptr{Cvoid},), nw_socket.listener)
                            nw_socket.listener = C_NULL
                        end
                        _nw_release_event_loop!(nw_socket)
                        _nw_unregister_socket!(nw_socket)
                        if nw_socket.cleanup_requested
                            _nw_destroy_socket!(nw_socket)
                        end
                    end
                catch e
                    Core.println("nw_listener_state task errored: $e")
                end
                return nothing
            end);
            type_tag = "nw_listener_state",
        )
        event_loop_schedule_task_now!(nw_socket.event_loop, task)
        return nothing
    end

    function _nw_listener_poll_port_until_ready!(nw_socket::NWSocket)::Nothing
        # Called on the socket's event-loop thread.
        nw_socket.event_loop === nothing && return nothing

        deadline_ns = time_ns() + 2_000_000_000

        function try_finish!()::Bool
            _nw_lock_base(nw_socket)
            try
                sock = nw_socket.base_socket
                cb = nw_socket.on_accept_started
                sock === nothing && return true
                cb === nothing && return true
                port = ccall((:nw_listener_get_port, _NW_NETWORK_LIB), UInt16, (nw_listener_t,), nw_socket.listener)
                if port != 0
                    sock.local_endpoint.port = port
                    nw_socket.on_accept_started = nothing
                    cb(sock, 0, nw_socket.listen_accept_started_user_data)
                    return true
                end
                return false
            finally
                _nw_unlock_base(nw_socket)
            end
        end

        # Fast path: finish immediately if the port is already known.
        try_finish!() && return nothing

        task = ScheduledTask(
            TaskFn(function(status)
                try
                    TaskStatus.T(status) == TaskStatus.RUN_READY || return nothing

                    try_finish!() && return nothing
                    if time_ns() >= deadline_ns
                        # Timed out waiting for a non-zero port; proceed anyway to avoid hanging
                        # listener setup in callers.
                        _nw_lock_base(nw_socket)
                        try
                            sock = nw_socket.base_socket
                            cb = nw_socket.on_accept_started
                            if sock !== nothing && cb !== nothing
                                nw_socket.on_accept_started = nothing
                                cb(sock, 0, nw_socket.listen_accept_started_user_data)
                            end
                        finally
                            _nw_unlock_base(nw_socket)
                        end
                        return nothing
                    end

                    now = event_loop_current_clock_time(nw_socket.event_loop)
                    run_at = now isa ErrorResult ? UInt64(time_ns()) + 1_000_000 : now + 1_000_000
                    event_loop_schedule_task_future!(nw_socket.event_loop, task, run_at)
                catch e
                    Core.println("nw_listener_port_poll task errored: $e")
                end
                return nothing
            end);
            type_tag = "nw_listener_port_poll",
        )

        now = event_loop_current_clock_time(nw_socket.event_loop)
        run_at = now isa ErrorResult ? UInt64(time_ns()) + 1_000_000 : now + 1_000_000
        event_loop_schedule_task_future!(nw_socket.event_loop, task, run_at)
        return nothing
    end

    function _nw_handle_listener_new_connection(nw_socket::NWSocket, connection::nw_connection_t)
        nw_socket.event_loop === nothing && return nothing
        if connection == C_NULL
            return nothing
        end

        ccall((:nw_retain, _NW_NETWORK_LIB), Cvoid, (Ptr{Cvoid},), connection)
        task = ScheduledTask(
            TaskFn(function(status)
                try
                    if TaskStatus.T(status) == TaskStatus.CANCELED
                        ccall((:nw_release, _NW_NETWORK_LIB), Cvoid, (Ptr{Cvoid},), connection)
                        return nothing
                    end
                    _nw_lock_base(nw_socket)
                    listener = nw_socket.base_socket
                    if listener === nothing || listener.accept_result_fn === nothing
                        _nw_unlock_base(nw_socket)
                        ccall((:nw_release, _NW_NETWORK_LIB), Cvoid, (Ptr{Cvoid},), connection)
                        return nothing
                    end

                    options = copy(listener.options)
                    new_socket = socket_init_apple_nw(options)
                    if new_socket isa ErrorResult
                        listener.accept_result_fn(listener, new_socket.code, nothing, listener.connect_accept_user_data)
                        _nw_unlock_base(nw_socket)
                        ccall((:nw_release, _NW_NETWORK_LIB), Cvoid, (Ptr{Cvoid},), connection)
                        return nothing
                    end

                    endpoint = ccall((:nw_connection_copy_endpoint, _NW_NETWORK_LIB), nw_endpoint_t, (nw_connection_t,), connection)
                    hostname = ccall((:nw_endpoint_get_hostname, _NW_NETWORK_LIB), Cstring, (nw_endpoint_t,), endpoint)
                    port = ccall((:nw_endpoint_get_port, _NW_NETWORK_LIB), UInt16, (nw_endpoint_t,), endpoint)
                    endpoint != C_NULL && ccall((:nw_release, _NW_NETWORK_LIB), Cvoid, (Ptr{Cvoid},), endpoint)
                    if hostname != C_NULL
                        set_address!(new_socket.remote_endpoint, unsafe_string(hostname))
                        new_socket.remote_endpoint.port = port
                    end

                    new_socket.io_handle.handle = connection
                    new_socket.io_handle.set_queue = _nw_client_set_queue_c[]
                    new_nw_socket = new_socket.impl::NWSocket
                    new_nw_socket.tls_ctx = nw_socket.tls_ctx
                    new_nw_socket.host_name = nw_socket.host_name
                    new_nw_socket.alpn_list = nw_socket.alpn_list
                    new_nw_socket.connection = connection
                    new_nw_socket.connection_setup = true
                    _nw_set_socket_state!(new_nw_socket, Int(_nw_state_mask(NWSocketState.CONNECTED_READ)) | Int(_nw_state_mask(NWSocketState.CONNECTED_WRITE)))

                    _nw_ensure_callbacks!()
                    st_ctx = pointer_from_objref(new_nw_socket)
                    st_blk = BlocksABI.make_stack_block_ctx(_nw_state_changed_cb[], st_ctx)
                    try
                        ccall(
                            (:nw_connection_set_state_changed_handler, _NW_NETWORK_LIB),
                            Cvoid,
                            (nw_connection_t, Ptr{Cvoid}),
                            connection,
                            st_blk.ptr,
                        )
                    finally
                        BlocksABI.free!(st_blk)
                    end

                    listener.accept_result_fn(listener, 0, new_socket, listener.connect_accept_user_data)
                    _nw_unlock_base(nw_socket)
                catch e
                    Core.println("nw_listener_accept task errored: $e")
                end
                return nothing
            end);
            type_tag = "nw_listener_accept",
        )
        event_loop_schedule_task_now!(nw_socket.event_loop, task)
        return nothing
    end

    function _nw_cancel_socket!(nw_socket::NWSocket)
        nw_socket.event_loop === nothing && return nothing

        task = ScheduledTask(
            TaskFn(function(status)
                try
                    if nw_socket.mode == NWSocketMode.CONNECTION && nw_socket.timeout_task !== nothing && !nw_socket.connection_setup
                        event_loop_cancel_task!(nw_socket.event_loop, nw_socket.timeout_task)
                    end
                    if nw_socket.mode == NWSocketMode.LISTENER && nw_socket.listener != C_NULL
                        ccall((:nw_listener_cancel, _NW_NETWORK_LIB), Cvoid, (nw_listener_t,), nw_socket.listener)
                    elseif nw_socket.mode == NWSocketMode.CONNECTION && nw_socket.connection != C_NULL
                        ccall((:nw_connection_cancel, _NW_NETWORK_LIB), Cvoid, (nw_connection_t,), nw_socket.connection)
                    end
                catch e
                    Core.println("nw_cancel task errored: $e")
                end
                return nothing
            end);
            type_tag = "nw_cancel",
        )
        event_loop_schedule_task_now!(nw_socket.event_loop, task)
        return nothing
    end

    function _nw_destroy_socket!(nw_socket::NWSocket)
        while !isempty(nw_socket.read_queue)
            node = popfirst!(nw_socket.read_queue)
            node === nothing && break
            _nw_read_queue_node_destroy!(node)
        end

        if nw_socket.parameters != C_NULL
            ccall((:nw_release, _NW_NETWORK_LIB), Cvoid, (Ptr{Cvoid},), nw_socket.parameters)
            nw_socket.parameters = C_NULL
            nw_socket.parameters_context = nothing
        end

        nw_socket.protocol_buf = null_buffer()
        nw_socket.tls_ctx = nothing
        nw_socket.host_name = nothing
        nw_socket.alpn_list = nothing

        cleanup_fn = nw_socket.on_cleanup_complete
        cleanup_ud = nw_socket.cleanup_user_data

        nw_socket.on_cleanup_complete = nothing
        nw_socket.cleanup_user_data = nothing

        cleanup_fn !== nothing && cleanup_fn(cleanup_ud)
        return nothing
    end

    function _nw_setup_tls_from_connection_options!(nw_socket::NWSocket, options::Union{Any, Nothing})
        if nw_socket.tls_ctx !== nothing || nw_socket.host_name !== nothing || nw_socket.alpn_list !== nothing
            raise_error(ERROR_INVALID_STATE)
            return ErrorResult(ERROR_INVALID_STATE)
        end
        options === nothing && return nothing

        if options.server_name !== nothing
            nw_socket.host_name = String(options.server_name)
        end

        alpn_list = options.alpn_list
        if options.ctx !== nothing
            nw_socket.tls_ctx = options.ctx
            if alpn_list === nothing
                alpn_list = options.ctx.options.alpn_list
            end
        end

        if alpn_list !== nothing
            nw_socket.alpn_list = String(alpn_list)
        end
        return nothing
    end

    function socket_init_apple_nw(options::SocketOptions)::Union{Socket, ErrorResult}
        if options.network_interface_name[1] != 0
            raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
            return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
        end

        _nw_ensure_callbacks!()
        nw_socket = NWSocket()
        _nw_register_socket!(nw_socket)

        sock = Socket(
            SocketEndpoint(),
            SocketEndpoint(),
            copy(options),
            IoHandle(),
            nothing,
            nothing,
            SocketState.INIT,
            nothing,
            nothing,
            nothing,
            nothing,
            nothing,
            nw_socket,
        )

        nw_socket.base_socket = sock
        return sock
    end

    function socket_cleanup_impl(::NWSocket, socket::Socket)
        nw_socket = socket.impl
        nw_socket === nothing && return nothing

        if socket_is_open(socket)
            socket_close(socket)
        end

        if _nw_validate_event_loop(socket.event_loop) && !event_loop_thread_is_callers_thread(socket.event_loop)
            _nw_lock_base(nw_socket)
            nw_socket.base_socket = nothing
            _nw_unlock_base(nw_socket)
        else
            nw_socket.base_socket = nothing
        end

        nw_socket.cleanup_requested = true
        if nw_socket.connection == C_NULL && nw_socket.listener == C_NULL
            _nw_unregister_socket!(nw_socket)
            _nw_destroy_socket!(nw_socket)
        end

        socket.impl = nothing
        return nothing
    end

    function socket_connect_impl(
            ::NWSocket,
            socket::Socket,
            options::SocketConnectOptions,
        )::Union{Nothing, ErrorResult}
        nw_socket = socket.impl
        if socket.event_loop !== nothing
            raise_error(ERROR_IO_EVENT_LOOP_ALREADY_ASSIGNED)
            return ErrorResult(ERROR_IO_EVENT_LOOP_ALREADY_ASSIGNED)
        end

        tls_res = _nw_setup_tls_from_connection_options!(nw_socket, options.tls_connection_options)
        tls_res isa ErrorResult && return tls_res

        event_loop = options.event_loop
        event_loop === nothing && return ErrorResult(raise_error(ERROR_IO_SOCKET_MISSING_EVENT_LOOP))

        set_el = _nw_set_event_loop!(socket, event_loop)
        set_el isa ErrorResult && return set_el

        setup_params = _nw_setup_socket_params!(nw_socket, socket.options)
        setup_params isa ErrorResult && return setup_params

	        _nw_lock_synced(nw_socket)
	        if nw_socket.state != _nw_state_mask(NWSocketState.INIT)
	            _nw_unlock_synced(nw_socket)
	            raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
	            return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
	        end

	        # Mirror the POSIX/Winsock implementations: record the requested remote endpoint.
	        copy!(socket.remote_endpoint, options.remote_endpoint)

	        endpoint = _nw_endpoint_from_socket_endpoint(options.remote_endpoint, socket.options.domain)
	        if endpoint isa ErrorResult
	            _nw_unlock_synced(nw_socket)
	            return endpoint
	        end

        connection = ccall(
            (:nw_connection_create, _NW_NETWORK_LIB),
            nw_connection_t,
            (nw_endpoint_t, nw_parameters_t),
            endpoint,
            nw_socket.parameters,
        )
        ccall((:nw_release, _NW_NETWORK_LIB), Cvoid, (Ptr{Cvoid},), endpoint)

        if connection == C_NULL
            _nw_unlock_synced(nw_socket)
            raise_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_OPTIONS)
        end

        socket.io_handle.handle = connection
        socket.io_handle.set_queue = _nw_client_set_queue_c[]
        nw_socket.connection = connection
        nw_socket.mode = NWSocketMode.CONNECTION

        _nw_ensure_callbacks!()
        st_ctx = pointer_from_objref(nw_socket)
        st_blk = BlocksABI.make_stack_block_ctx(_nw_state_changed_cb[], st_ctx)
        try
            ccall(
                (:nw_connection_set_state_changed_handler, _NW_NETWORK_LIB),
                Cvoid,
                (nw_connection_t, Ptr{Cvoid}),
                connection,
                st_blk.ptr,
            )
        finally
            BlocksABI.free!(st_blk)
        end

        _nw_set_socket_state!(nw_socket, Int(_nw_state_mask(NWSocketState.CONNECTING)))
        _nw_unlock_synced(nw_socket)

        if options.on_connection_result !== nothing
            nw_socket.on_connection_result = options.on_connection_result
            nw_socket.connect_result_user_data = options.user_data
            logf(
                LogLevel.TRACE,
                LS_IO_SOCKET,
                "nw_socket=%p: connect callback set",
                _nw_socket_ptr(nw_socket),
            )
        else
            logf(
                LogLevel.TRACE,
                LS_IO_SOCKET,
                "nw_socket=%p: connect callback missing",
                _nw_socket_ptr(nw_socket),
            )
        end

        if event_loop_connect_to_io_completion_port!(event_loop, socket.io_handle) isa ErrorResult
            raise_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_OPTIONS)
        end

        ccall((:nw_connection_start, _NW_NETWORK_LIB), Cvoid, (nw_connection_t,), connection)

        if socket.options.connect_timeout_ms > 0
            now = event_loop_current_clock_time(event_loop)
            if now isa ErrorResult
                return now
            end
            timeout = UInt64(socket.options.connect_timeout_ms) * 1_000_000 + now
            nw_socket.timeout_task = ScheduledTask(
                TaskFn(function(status)
                    try
                        _nw_lock_base(nw_socket)
                        if !nw_socket.connection_setup && nw_socket.base_socket !== nothing
                            err = ERROR_IO_SOCKET_TIMEOUT
                            nw_socket.connection_setup = true
                            socket_close(nw_socket.base_socket)
                            if nw_socket.on_connection_result !== nothing
                                nw_socket.on_connection_result(nw_socket.base_socket, err, nw_socket.connect_result_user_data)
                            end
                        end
                        _nw_unlock_base(nw_socket)
                    catch e
                        Core.println("nw_timeout task errored: $e")
                    end
                    return nothing
                end);
                type_tag = "nw_timeout",
            )
            event_loop_schedule_task_future!(event_loop, nw_socket.timeout_task, timeout)
        end

        return nothing
    end

    function socket_bind_impl(
            ::NWSocket,
            socket::Socket,
            options::SocketBindOptions,
        )::Union{Nothing, ErrorResult}
        nw_socket = socket.impl

        _nw_lock_synced(nw_socket)
        if nw_socket.state != _nw_state_mask(NWSocketState.INIT)
            _nw_unlock_synced(nw_socket)
            raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
            return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
        end

        socket.local_endpoint.address = options.local_endpoint.address
        socket.local_endpoint.port = options.local_endpoint.port

        if nw_socket.parameters == C_NULL
            tls_res = _nw_setup_tls_from_connection_options!(nw_socket, options.tls_connection_options)
            tls_res isa ErrorResult && ( _nw_unlock_synced(nw_socket); return tls_res )

            if options.event_loop !== nothing
                nw_socket.event_loop = options.event_loop
            end
            setup_params = _nw_setup_socket_params!(nw_socket, socket.options)
            nw_socket.event_loop = nothing
            setup_params isa ErrorResult && ( _nw_unlock_synced(nw_socket); return setup_params )
        end

        endpoint = _nw_endpoint_from_socket_endpoint(options.local_endpoint, socket.options.domain)
        if endpoint isa ErrorResult
            _nw_unlock_synced(nw_socket)
            return endpoint
        end

        ccall(
            (:nw_parameters_set_local_endpoint, _NW_NETWORK_LIB),
            Cvoid,
            (nw_parameters_t, nw_endpoint_t),
            nw_socket.parameters,
            endpoint,
        )
        ccall((:nw_release, _NW_NETWORK_LIB), Cvoid, (Ptr{Cvoid},), endpoint)

        _nw_set_socket_state!(nw_socket, Int(_nw_state_mask(NWSocketState.BOUND)))
        _nw_unlock_synced(nw_socket)
        return nothing
    end

    function socket_listen_impl(
            ::NWSocket,
            socket::Socket,
            backlog_size::Integer,
        )::Union{Nothing, ErrorResult}
        _ = backlog_size
        nw_socket = socket.impl
        _nw_lock_synced(nw_socket)
        if nw_socket.state != _nw_state_mask(NWSocketState.BOUND)
            _nw_unlock_synced(nw_socket)
            raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
            return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
        end
        if nw_socket.parameters == C_NULL
            _nw_unlock_synced(nw_socket)
            raise_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_OPTIONS)
        end

        listener = ccall((:nw_listener_create, _NW_NETWORK_LIB), nw_listener_t, (nw_parameters_t,), nw_socket.parameters)
        if listener == C_NULL
            _nw_unlock_synced(nw_socket)
            raise_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_OPTIONS)
        end

        # When binding to port 0, Network.framework may already have chosen an ephemeral port
        # at listener creation time. Grab it early so `socket_get_bound_address()` reflects it
        # before `socket_start_accept()` transitions to READY.
        port = ccall((:nw_listener_get_port, _NW_NETWORK_LIB), UInt16, (nw_listener_t,), listener)
        if port != 0
            socket.local_endpoint.port = port
        end

        socket.io_handle.handle = listener
        socket.io_handle.set_queue = _nw_listener_set_queue_c[]
        nw_socket.listener = listener
        nw_socket.mode = NWSocketMode.LISTENER
        _nw_set_socket_state!(nw_socket, Int(_nw_state_mask(NWSocketState.LISTENING)))
        _nw_unlock_synced(nw_socket)
        return nothing
    end

	    function socket_start_accept_impl(
	            ::NWSocket,
	            socket::Socket,
	            accept_loop::EventLoop,
	            options::SocketListenerOptions,
	        )::Union{Nothing, ErrorResult}
        nw_socket = socket.impl
        _nw_lock_synced(nw_socket)
        if nw_socket.state != _nw_state_mask(NWSocketState.LISTENING)
            _nw_unlock_synced(nw_socket)
            raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
            return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
        end

        nw_socket.on_accept_started = options.on_accept_start
        nw_socket.listen_accept_started_user_data = options.on_accept_start_user_data
        socket.accept_result_fn = options.on_accept_result
        socket.connect_accept_user_data = options.on_accept_result_user_data

        set_el = _nw_set_event_loop!(socket, accept_loop)
        if set_el isa ErrorResult
            _nw_unlock_synced(nw_socket)
            return set_el
        end

        if event_loop_connect_to_io_completion_port!(accept_loop, socket.io_handle) isa ErrorResult
            _nw_unlock_synced(nw_socket)
            raise_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_OPTIONS)
        end

        _nw_ensure_callbacks!()
        lctx = pointer_from_objref(nw_socket)
        state_blk = BlocksABI.make_stack_block_ctx(_nw_listener_state_changed_cb[], lctx)
        conn_blk = BlocksABI.make_stack_block_ctx(_nw_listener_new_conn_cb[], lctx)
	        try
	            ccall(
	                (:nw_listener_set_state_changed_handler, _NW_NETWORK_LIB),
	                Cvoid,
	                (nw_listener_t, Ptr{Cvoid}),
	                nw_socket.listener,
	                state_blk.ptr,
	            )
	            ccall(
	                (:nw_listener_set_new_connection_handler, _NW_NETWORK_LIB),
	                Cvoid,
	                (nw_listener_t, Ptr{Cvoid}),
	                nw_socket.listener,
	                conn_blk.ptr,
	            )
	        finally
	            BlocksABI.free!(state_blk)
	            BlocksABI.free!(conn_blk)
	        end

	        ccall((:nw_listener_start, _NW_NETWORK_LIB), Cvoid, (nw_listener_t,), nw_socket.listener)
	        _nw_unlock_synced(nw_socket)
	        return nothing
	    end

    function socket_stop_accept_impl(::NWSocket, socket::Socket)::Union{Nothing, ErrorResult}
        nw_socket = socket.impl
        _nw_lock_synced(nw_socket)
        if nw_socket.state != _nw_state_mask(NWSocketState.LISTENING)
            _nw_unlock_synced(nw_socket)
            raise_error(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
            return ErrorResult(ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE)
        end
        ccall((:nw_listener_cancel, _NW_NETWORK_LIB), Cvoid, (nw_listener_t,), nw_socket.listener)
        _nw_set_socket_state!(nw_socket, Int(_nw_state_mask(NWSocketState.STOPPED)))
        _nw_unlock_synced(nw_socket)
        return nothing
    end

    function socket_close_impl(::NWSocket, socket::Socket)::Union{Nothing, ErrorResult}
        nw_socket = socket.impl
        _nw_lock_synced(nw_socket)
        if nw_socket.state < _nw_state_mask(NWSocketState.CLOSING)
            _nw_set_socket_state!(nw_socket, Int(_nw_state_mask(NWSocketState.CLOSING)) | Int(_nw_state_mask(NWSocketState.CONNECTED_READ)))
            if nw_socket.pending_writes == 0
                _nw_unlock_synced(nw_socket)
                _nw_cancel_socket!(nw_socket)
                return nothing
            end
        end
        _nw_unlock_synced(nw_socket)
        return nothing
    end

    function socket_shutdown_dir_impl(::NWSocket, socket::Socket, dir::ChannelDirection.T)::Union{Nothing, ErrorResult}
        _ = dir
        raise_error(ERROR_IO_SOCKET_INVALID_OPERATION_FOR_TYPE)
        return ErrorResult(ERROR_IO_SOCKET_INVALID_OPERATION_FOR_TYPE)
    end

    function socket_set_options_impl(
            ::NWSocket,
            socket::Socket,
            options::SocketOptions,
        )::Union{Nothing, ErrorResult}
        if socket.options.domain != options.domain || socket.options.type != options.type
            raise_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_OPTIONS)
        end
        socket.options = copy(options)
        nw_socket = socket.impl
        return _nw_setup_socket_params!(nw_socket, options)
    end

    function socket_assign_to_event_loop_impl(
            ::NWSocket,
            socket::Socket,
            event_loop::EventLoop,
        )::Union{Nothing, ErrorResult}
        nw_socket = socket.impl
        if socket.event_loop !== nothing
            raise_error(ERROR_IO_EVENT_LOOP_ALREADY_ASSIGNED)
            return ErrorResult(ERROR_IO_EVENT_LOOP_ALREADY_ASSIGNED)
        end

        set_el = _nw_set_event_loop!(socket, event_loop)
        set_el isa ErrorResult && return set_el

        if event_loop_connect_to_io_completion_port!(event_loop, socket.io_handle) isa ErrorResult
            raise_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_OPTIONS)
        end

        if nw_socket.mode == NWSocketMode.CONNECTION && socket.io_handle.handle != C_NULL
            ccall((:nw_connection_start, _NW_NETWORK_LIB), Cvoid, (nw_connection_t,), socket.io_handle.handle)
        end
        return nothing
    end

    function socket_subscribe_to_readable_events_impl(
            ::NWSocket,
            socket::Socket,
            on_readable::SocketOnReadableFn,
            user_data,
        )::Union{Nothing, ErrorResult}
        nw_socket = socket.impl
        if nw_socket.mode == NWSocketMode.LISTENER
            raise_error(ERROR_IO_SOCKET_INVALID_OPERATION_FOR_TYPE)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_OPERATION_FOR_TYPE)
        end
        nw_socket.on_readable = on_readable
        nw_socket.on_readable_user_data = user_data
        return _nw_schedule_next_read!(nw_socket)
    end

    function socket_read_impl(
            ::NWSocket,
            socket::Socket,
            buffer::ByteBuffer,
        )::Union{Tuple{Nothing, Csize_t}, ErrorResult}
        nw_socket = socket.impl
        if socket.event_loop === nothing || !event_loop_thread_is_callers_thread(socket.event_loop)
            raise_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
            return ErrorResult(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
        end

        max_to_read = buffer.capacity - buffer.len
        if isempty(nw_socket.read_queue)
            _nw_lock_synced(nw_socket)
            if (nw_socket.state & _nw_state_mask(NWSocketState.CONNECTED_READ)) == 0
                _nw_unlock_synced(nw_socket)
                raise_error(ERROR_IO_SOCKET_CLOSED)
                return ErrorResult(ERROR_IO_SOCKET_CLOSED)
            end
            _nw_unlock_synced(nw_socket)
            _nw_schedule_next_read!(nw_socket)
            raise_error(ERROR_IO_READ_WOULD_BLOCK)
            return ErrorResult(ERROR_IO_READ_WOULD_BLOCK)
        end

        amount_read = Csize_t(0)
        while !isempty(nw_socket.read_queue) && max_to_read > 0
            node = first(nw_socket.read_queue)
            node === nothing && break

            map_data, buf_ptr, size = _nw_dispatch_data_map(node.data)
            if map_data == C_NULL
                break
            end

            to_copy = min(max_to_read, size - node.offset)
            if to_copy > 0
                src_ptr = Ptr{UInt8}(buf_ptr) + node.offset
                _nw_byte_buf_write!(buffer, src_ptr, Int(to_copy))
                amount_read += to_copy
                max_to_read -= to_copy
                node.offset += to_copy
            end

            ccall((:dispatch_release, _NW_DISPATCH_LIB), Cvoid, (dispatch_data_t,), map_data)

            if node.offset >= size
                popfirst!(nw_socket.read_queue)
                _nw_read_queue_node_destroy!(node)
            end
        end

        return (nothing, amount_read)
    end

    function socket_write_impl(
            ::NWSocket,
            socket::Socket,
            cursor::ByteCursor,
            written_fn::Union{SocketOnWriteCompletedFn, Nothing},
            user_data,
        )::Union{Nothing, ErrorResult}
        nw_socket = socket.impl
        if socket.event_loop === nothing || !event_loop_thread_is_callers_thread(socket.event_loop)
            raise_error(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
            return ErrorResult(ERROR_IO_EVENT_LOOP_THREAD_ONLY)
        end
        if written_fn === nothing
            raise_error(ERROR_INVALID_ARGUMENT)
            return ErrorResult(ERROR_INVALID_ARGUMENT)
        end

        _nw_lock_synced(nw_socket)
        if (nw_socket.state & _nw_state_mask(NWSocketState.CONNECTED_WRITE)) == 0
            _nw_unlock_synced(nw_socket)
            raise_error(ERROR_IO_SOCKET_NOT_CONNECTED)
            return ErrorResult(ERROR_IO_SOCKET_NOT_CONNECTED)
        end

        data = _nw_create_dispatch_data(cursor)
        if data == C_NULL
            _nw_unlock_synced(nw_socket)
            raise_error(ERROR_IO_SOCKET_INVALID_OPTIONS)
            return ErrorResult(ERROR_IO_SOCKET_INVALID_OPTIONS)
        end

        nw_socket.pending_writes += 1
        _nw_unlock_synced(nw_socket)

        send_ctx = NWSendContext(nw_socket, written_fn, user_data)
        send_ctx_ptr = _nw_register_send!(send_ctx)
        _nw_ensure_callbacks!()
        _nw_ensure_globals!()

        # The NW send completion block only receives `nw_error_t`. Capture both the
        # send ctx pointer and the dispatch_data_t in a malloc'd context.
        send_block_ctx = Base.Libc.malloc(Csize_t(2 * sizeof(Ptr{Cvoid})))
        send_block_ctx == C_NULL && error("malloc failed for send block ctx")
        send_block_ctx_u8 = Ptr{UInt8}(send_block_ctx)
        unsafe_store!(Ptr{Ptr{Cvoid}}(send_block_ctx_u8), send_ctx_ptr)
        unsafe_store!(Ptr{Ptr{Cvoid}}(send_block_ctx_u8 + sizeof(Ptr{Cvoid})), Ptr{Cvoid}(data))

        blk = BlocksABI.make_stack_block_ctx(_nw_send_cb[], Ptr{Cvoid}(send_block_ctx))
        try
            ccall(
                (:nw_connection_send, _NW_NETWORK_LIB),
                Cvoid,
                (nw_connection_t, dispatch_data_t, nw_content_context_t, UInt8, Ptr{Cvoid}),
                socket.io_handle.handle,
                data,
                _NW_DEFAULT_MESSAGE_CONTEXT[],
                UInt8(1),
                blk.ptr,
            )
        finally
            BlocksABI.free!(blk)
        end
        return nothing
    end

    function socket_get_error_impl(::NWSocket, socket::Socket)::Int
        return socket.impl.last_error
    end

    function socket_is_open_impl(::NWSocket, socket::Socket)::Bool
        nw_socket = socket.impl
        _nw_lock_synced(nw_socket)
        is_open = nw_socket.state < _nw_state_mask(NWSocketState.CLOSING)
        _nw_unlock_synced(nw_socket)
        return is_open
    end

    function socket_set_close_callback_impl(
            ::NWSocket,
            socket::Socket,
            fn::SocketOnShutdownCompleteFn,
            user_data,
        )::Union{Nothing, ErrorResult}
        nw_socket = socket.impl
        nw_socket.on_close_complete = fn
        nw_socket.close_user_data = user_data
        return nothing
    end

    function socket_set_cleanup_callback_impl(
            ::NWSocket,
            socket::Socket,
            fn::SocketOnShutdownCompleteFn,
            user_data,
        )::Union{Nothing, ErrorResult}
        nw_socket = socket.impl
        nw_socket.on_cleanup_complete = fn
        nw_socket.cleanup_user_data = user_data
        return nothing
    end

    function socket_get_protocol_impl(::NWSocket, socket::Socket)::ByteBuffer
        return socket.impl.protocol_buf
    end

    function socket_get_server_name_impl(::NWSocket, socket::Socket)::ByteBuffer
        name = socket.impl.host_name
        name === nothing && return null_buffer()
        return byte_buf_from_c_str(name)
    end

    function _nw_endpoint_from_socket_endpoint(
            endpoint::SocketEndpoint,
            domain::SocketDomain.T,
        )::Union{nw_endpoint_t, ErrorResult}
        addr = get_address(endpoint)
        port = Int(endpoint.port)

        sockaddr_buf = Memory{UInt8}(undef, 128)
        fill!(sockaddr_buf, 0x00)

        pton_err = 1
        if domain == SocketDomain.IPV4
            _set_sockaddr_family!(sockaddr_buf, AF_INET, 16)
            pton_err = ccall(:inet_pton, Cint, (Cint, Cstring, Ptr{Cvoid}), AF_INET, addr, pointer(sockaddr_buf) + 4)
            sockaddr_buf[3:4] .= reinterpret(UInt8, [htons(port)])
        elseif domain == SocketDomain.IPV6
            _set_sockaddr_family!(sockaddr_buf, AF_INET6, 28)
            pton_err = ccall(:inet_pton, Cint, (Cint, Cstring, Ptr{Cvoid}), AF_INET6, addr, pointer(sockaddr_buf) + 8)
            sockaddr_buf[3:4] .= reinterpret(UInt8, [htons(port)])
        elseif domain == SocketDomain.LOCAL
            _set_sockaddr_family!(sockaddr_buf, AF_UNIX, 110)
            addr_bytes = codeunits(addr)
            len = min(length(addr_bytes), ADDRESS_MAX_LEN - 1)
            for i in 1:len
                sockaddr_buf[2 + i] = addr_bytes[i]
            end
        else
            raise_error(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
            return ErrorResult(ERROR_IO_SOCKET_UNSUPPORTED_ADDRESS_FAMILY)
        end

        if pton_err != 1
            raise_error(_nw_convert_pton_error(pton_err))
            return ErrorResult(_nw_convert_pton_error(pton_err))
        end

        endpoint_ptr = ccall(
            (:nw_endpoint_create_address, _NW_NETWORK_LIB),
            nw_endpoint_t,
            (Ptr{UInt8},),
            pointer(sockaddr_buf),
        )

        endpoint_ptr == C_NULL && return ErrorResult(raise_error(ERROR_IO_SOCKET_INVALID_ADDRESS))
        return endpoint_ptr
    end

else
    function socket_init_apple_nw(options::SocketOptions)::Union{Socket, ErrorResult}
        _ = options
        raise_error(ERROR_PLATFORM_NOT_SUPPORTED)
        return ErrorResult(ERROR_PLATFORM_NOT_SUPPORTED)
    end
end
