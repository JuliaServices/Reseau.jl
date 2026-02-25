# SecureChannel TLS backend (Windows)
# Included by src/sockets/io/tls_channel_handler.jl

# === SecureChannel backend (Windows) ===

const _SECUR32_LIB = "secur32.dll"
const _CRYPT32_LIB = "crypt32.dll"
const _KERNEL32_LIB = "kernel32.dll"

const _SCHANNEL_READ_OUT_SIZE = 16 * 1024
const _SCHANNEL_READ_IN_SIZE = _SCHANNEL_READ_OUT_SIZE
const _SCHANNEL_EXTRA_HEADROOM = 1024
const _SCHANNEL_MAX_HOST_LENGTH = 255

const _UNISP_NAME = "Microsoft Unified Security Protocol Provider"

const _SECBUFFER_VERSION = UInt32(0)
const _SECBUFFER_EMPTY = UInt32(0)
const _SECBUFFER_DATA = UInt32(1)
const _SECBUFFER_TOKEN = UInt32(2)
const _SECBUFFER_EXTRA = UInt32(5)
const _SECBUFFER_STREAM_TRAILER = UInt32(6)
const _SECBUFFER_STREAM_HEADER = UInt32(7)
const _SECBUFFER_ALERT = UInt32(17)
const _SECBUFFER_APPLICATION_PROTOCOLS = UInt32(18)

const _SEC_E_OK = Int32(0x00000000)
const _SEC_I_CONTINUE_NEEDED = Int32(0x00090312)
const _SEC_I_CONTEXT_EXPIRED = Int32(0x00090317)
const _SEC_E_INCOMPLETE_MESSAGE = reinterpret(Int32, UInt32(0x80090318))
const _SEC_I_RENEGOTIATE = Int32(0x00090321)
const _SEC_E_INSUFFICIENT_MEMORY = reinterpret(Int32, UInt32(0x80090300))
const _SEC_E_WRONG_PRINCIPAL = reinterpret(Int32, UInt32(0x80090322))

const _ISC_REQ_SEQUENCE_DETECT = UInt32(0x00000008)
const _ISC_REQ_REPLAY_DETECT = UInt32(0x00000004)
const _ISC_REQ_CONFIDENTIALITY = UInt32(0x00000010)
const _ISC_REQ_ALLOCATE_MEMORY = UInt32(0x00000100)
const _ISC_REQ_STREAM = UInt32(0x00008000)

const _ASC_REQ_MUTUAL_AUTH = UInt32(0x00000002)
const _ASC_REQ_SEQUENCE_DETECT = UInt32(0x00000008)
const _ASC_REQ_REPLAY_DETECT = UInt32(0x00000004)
const _ASC_REQ_CONFIDENTIALITY = UInt32(0x00000010)
const _ASC_REQ_ALLOCATE_MEMORY = UInt32(0x00000100)
const _ASC_REQ_STREAM = UInt32(0x00010000)

const _SECPKG_CRED_INBOUND = UInt32(1)
const _SECPKG_CRED_OUTBOUND = UInt32(2)

const _SECPKG_ATTR_STREAM_SIZES = UInt32(4)
const _SECPKG_ATTR_APPLICATION_PROTOCOL = UInt32(35)
const _SECPKG_ATTR_REMOTE_CERT_CONTEXT = UInt32(0x53)

const _SECPROT_SSL3_SERVER = UInt32(0x00000010)
const _SECPROT_SSL3_CLIENT = UInt32(0x00000020)
const _SECPROT_TLS1_0_SERVER = UInt32(0x00000040)
const _SECPROT_TLS1_0_CLIENT = UInt32(0x00000080)
const _SECPROT_TLS1_1_SERVER = UInt32(0x00000100)
const _SECPROT_TLS1_1_CLIENT = UInt32(0x00000200)
const _SECPROT_TLS1_2_SERVER = UInt32(0x00000400)
const _SECPROT_TLS1_2_CLIENT = UInt32(0x00000800)

const _SCHANNEL_CRED_VERSION = UInt32(0x00000004)
const _SCH_CRED_NO_SERVERNAME_CHECK = UInt32(0x00000004)
const _SCH_CRED_MANUAL_CRED_VALIDATION = UInt32(0x00000008)
const _SCH_CRED_NO_DEFAULT_CREDS = UInt32(0x00000010)
const _SCH_CRED_AUTO_CRED_VALIDATION = UInt32(0x00000020)
const _SCH_CRED_REVOCATION_CHECK_CHAIN = UInt32(0x00000200)
const _SCH_CRED_IGNORE_NO_REVOCATION_CHECK = UInt32(0x00000800)
const _SCH_CRED_IGNORE_REVOCATION_OFFLINE = UInt32(0x00001000)
const _SCH_USE_STRONG_CRYPTO = UInt32(0x00400000)

const _SCHANNEL_SHUTDOWN = UInt32(1)

const _X509_ASN_ENCODING = UInt32(0x00000001)
const _PKCS_7_ASN_ENCODING = UInt32(0x00010000)
const _ENCODING_FLAGS = _X509_ASN_ENCODING | _PKCS_7_ASN_ENCODING
const _CERT_STORE_PROV_MEMORY = Ptr{UInt8}(2)
const _CERT_STORE_CREATE_NEW_FLAG = UInt32(0x00002000)
const _CERT_STORE_ADD_ALWAYS = UInt32(4)

const _CERT_CHAIN_POLICY_SSL = Ptr{UInt8}(4)
const _AUTHTYPE_SERVER = UInt32(2)
const _CERT_TRUST_IS_NOT_TIME_NESTED = UInt32(0x00000002)
const _USAGE_MATCH_TYPE_OR = UInt32(0x00000001)

const _SEC_APP_PROTO_NEGOTIATION_EXT_ALPN = UInt32(2)
const _SEC_APP_PROTO_NEGOTIATION_STATUS_SUCCESS = UInt32(1)

const _CP_UTF8 = UInt32(65001)
const _MB_ERR_INVALID_CHARS = UInt32(0x00000008)

const _OID_SERVER_AUTH = "1.3.6.1.5.5.7.3.1"
const _OID_SERVER_GATED_CRYPTO = "1.3.6.1.4.1.311.10.3.3"
const _OID_SGC_NETSCAPE = "2.16.840.1.113730.4.1"

@enumx _SecureChannelConnectionState::UInt8 begin
    CLIENT_NEGOTIATION_STEP_1 = 1
    CLIENT_NEGOTIATION_STEP_2 = 2
    SERVER_NEGOTIATION_STEP_1 = 3
    SERVER_NEGOTIATION_STEP_2 = 4
    APPLICATION_DECRYPT = 5
end

struct _SecHandle
    dwLower::UInt
    dwUpper::UInt
end

const _CredHandle = _SecHandle
const _CtxtHandle = _SecHandle

struct _TimeStamp
    LowPart::UInt32
    HighPart::Int32
end

struct _SecBuffer
    cbBuffer::UInt32
    BufferType::UInt32
    pvBuffer::Ptr{Cvoid}
end

struct _SecBufferDesc
    ulVersion::UInt32
    cBuffers::UInt32
    pBuffers::Ptr{_SecBuffer}
end

struct _SecPkgContextStreamSizes
    cbHeader::UInt32
    cbTrailer::UInt32
    cbMaximumMessage::UInt32
    cBuffers::UInt32
    cbBlockSize::UInt32
end

struct _SecPkgContextApplicationProtocol
    ProtoNegoStatus::UInt32
    ProtoNegoExt::UInt32
    ProtocolIdSize::UInt8
    ProtocolId::NTuple{255, UInt8}
end

struct _SCHANNEL_CRED
    dwVersion::UInt32
    cCreds::UInt32
    paCred::Ptr{Ptr{Cvoid}}
    hRootStore::Ptr{Cvoid}
    cMappers::UInt32
    aphMappers::Ptr{Ptr{Cvoid}}
    cSupportedAlgs::UInt32
    palgSupportedAlgs::Ptr{UInt32}
    grbitEnabledProtocols::UInt32
    dwMinimumCipherStrength::UInt32
    dwMaximumCipherStrength::UInt32
    dwSessionLifespan::UInt32
    dwFlags::UInt32
    dwCredFormat::UInt32
end

struct _CERT_CONTEXT
    dwCertEncodingType::UInt32
    pbCertEncoded::Ptr{UInt8}
    cbCertEncoded::UInt32
    pCertInfo::Ptr{Cvoid}
    hCertStore::Ptr{Cvoid}
end

struct _CERT_ENHKEY_USAGE
    cUsageIdentifier::UInt32
    rgpszUsageIdentifier::Ptr{Cstring}
end

struct _CERT_USAGE_MATCH
    dwType::UInt32
    Usage::_CERT_ENHKEY_USAGE
end

struct _CERT_CHAIN_PARA
    cbSize::UInt32
    RequestedUsage::_CERT_USAGE_MATCH
    RequestedIssuancePolicy::_CERT_USAGE_MATCH
    dwUrlRetrievalTimeout::UInt32
    fCheckRevocationFreshnessTime::Int32
    dwRevocationFreshnessTime::UInt32
    pftCacheResync::Ptr{Cvoid}
    pStrongSignPara::Ptr{Cvoid}
    dwStrongSignFlags::UInt32
end

struct _CERT_CHAIN_ENGINE_CONFIG
    cbSize::UInt32
    hRestrictedRoot::Ptr{Cvoid}
    hRestrictedTrust::Ptr{Cvoid}
    hRestrictedOther::Ptr{Cvoid}
    cAdditionalStore::UInt32
    rghAdditionalStore::Ptr{Ptr{Cvoid}}
    dwFlags::UInt32
    dwUrlRetrievalTimeout::UInt32
    MaximumCachedCertificates::UInt32
    CycleDetectionModulus::UInt32
    hExclusiveRoot::Ptr{Cvoid}
    hExclusiveTrustedPeople::Ptr{Cvoid}
    dwExclusiveFlags::UInt32
end

struct _CERT_TRUST_STATUS
    dwErrorStatus::UInt32
    dwInfoStatus::UInt32
end

struct _CERT_SIMPLE_CHAIN
    cbSize::UInt32
    TrustStatus::_CERT_TRUST_STATUS
    cElement::UInt32
    rgpElement::Ptr{Ptr{Cvoid}}
    pTrustListInfo::Ptr{Cvoid}
    fHasRevocationFreshnessTime::Int32
    dwRevocationFreshnessTime::UInt32
end

struct _CERT_CHAIN_CONTEXT
    cbSize::UInt32
    TrustStatus::_CERT_TRUST_STATUS
    cChain::UInt32
    rgpChain::Ptr{Ptr{_CERT_SIMPLE_CHAIN}}
    cLowerQualityChainContext::UInt32
    rgpLowerQualityChainContext::Ptr{Ptr{Cvoid}}
    fHasRevocationFreshnessTime::Int32
    dwRevocationFreshnessTime::UInt32
    dwCreateFlags::UInt32
    ChainId::NTuple{16, UInt8}
end

struct _HTTPSPolicyCallbackData
    cbSize::UInt32
    dwAuthType::UInt32
    fdwChecks::UInt32
    pwszServerName::Ptr{UInt16}
end

struct _CERT_CHAIN_POLICY_PARA
    cbSize::UInt32
    dwFlags::UInt32
    pvExtraPolicyPara::Ptr{Cvoid}
end

struct _CERT_CHAIN_POLICY_STATUS
    cbSize::UInt32
    dwError::UInt32
    lChainIndex::Int32
    lElementIndex::Int32
    pvExtraPolicyStatus::Ptr{Cvoid}
end

@inline _zero_sechandle() = _SecHandle(0, 0)
@inline _sechandle_is_set(h::_SecHandle) = h.dwLower != 0 || h.dwUpper != 0

function _secure_channel_byte_buf_from_string(value::AbstractString)::ByteBuffer
    bytes = codeunits(value)
    isempty(bytes) && return null_buffer()
    buf = ByteBuffer(length(bytes))
    copyto!(buf.mem, 1, bytes, 1, length(bytes))
    setfield!(buf, :len, Csize_t(length(bytes)))
    return buf
end

function _secure_channel_determine_sspi_error(sspi_status::Int32)::Int
    if sspi_status == _SEC_E_INSUFFICIENT_MEMORY
        return ERROR_OOM
    elseif sspi_status == _SEC_I_CONTEXT_EXPIRED || sspi_status == _SEC_E_WRONG_PRINCIPAL
        return ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE
    else
        return ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE
    end
end

@inline function _secure_channel_error_code_from_exception(e, location::AbstractString)::Int
    _ = location
    if e isa ReseauError
        return e.code
    end
    return ERROR_UNKNOWN
end

function _secure_channel_memmove!(dest::Ptr{UInt8}, src::Ptr{UInt8}, len::Csize_t)::Nothing
    len == 0 && return nothing
    ccall(:memmove, Ptr{Cvoid}, (Ptr{Cvoid}, Ptr{Cvoid}, Csize_t), dest, src, len)
    return nothing
end

function _secure_channel_query_stream_sizes!(handler)
    handler.stream_sizes.cbMaximumMessage != 0 && return true
    sizes_ref = Ref(handler.stream_sizes)
    status = ccall(
        (:QueryContextAttributesW, _SECUR32_LIB),
        Int32,
        (Ref{_CtxtHandle}, UInt32, Ptr{Cvoid}),
        handler.sec_handle,
        _SECPKG_ATTR_STREAM_SIZES,
        Base.unsafe_convert(Ptr{Cvoid}, sizes_ref),
    )
    if status == _SEC_E_OK
        handler.stream_sizes = sizes_ref[]
        return true
    end
    return false
end

function _secure_channel_protocol_from_context(handler)::ByteBuffer
    result = Ref(_SecPkgContextApplicationProtocol(0, 0, 0x00, ntuple(_ -> UInt8(0x00), Val(255))))
    status = ccall(
        (:QueryContextAttributesW, _SECUR32_LIB),
        Int32,
        (Ref{_CtxtHandle}, UInt32, Ptr{Cvoid}),
        handler.sec_handle,
        _SECPKG_ATTR_APPLICATION_PROTOCOL,
        Base.unsafe_convert(Ptr{Cvoid}, result),
    )
    status == _SEC_E_OK || throw_error(_secure_channel_determine_sspi_error(status))
    proto = result[]
    if proto.ProtoNegoStatus != _SEC_APP_PROTO_NEGOTIATION_STATUS_SUCCESS || proto.ProtocolIdSize == 0x00
        return null_buffer()
    end
    proto_len = Int(proto.ProtocolIdSize)
    out = ByteBuffer(proto_len)
    @inbounds for i in 1:proto_len
        out.mem[i] = proto.ProtocolId[i]
    end
    setfield!(out, :len, Csize_t(proto_len))
    return out
end

function _secure_channel_send_token_message(
        handler,
        token_ptr::Ptr{Cvoid},
        token_len::UInt32,
    )::Nothing
    token_ptr == C_NULL && return nothing
    token_len == 0 && return nothing

    slot = handler.slot
    slot === nothing && return nothing
    channel_slot_is_attached(slot) || return nothing
    channel = slot.channel

    msg = channel_acquire_message_from_pool(channel, IoMessageType.APPLICATION_DATA, token_len)
    if msg === nothing
        throw_error(ERROR_OOM)
    end
    if msg.message_data.capacity < token_len
        channel_release_message_to_pool!(channel, msg)
        throw_error(ERROR_IO_TLS_ERROR_WRITE_FAILURE)
    end

    try
        unsafe_copyto!(pointer(msg.message_data.mem), Ptr{UInt8}(token_ptr), Int(token_len))
        setfield!(msg.message_data, :len, Csize_t(token_len))
        channel_slot_send_message(slot, msg, ChannelDirection.WRITE)
    catch
        channel_release_message_to_pool!(channel, msg)
        rethrow()
    end

    return nothing
end

function _secure_channel_free_output_buffers!(buffers::Vector{_SecBuffer})::Nothing
    for i in eachindex(buffers)
        ptr = buffers[i].pvBuffer
        ptr == C_NULL && continue
        _ = ccall((:FreeContextBuffer, _SECUR32_LIB), Int32, (Ptr{Cvoid},), ptr)
        buffers[i] = _SecBuffer(0, _SECBUFFER_EMPTY, C_NULL)
    end
    return nothing
end

function _secure_channel_parse_alpn_list(alpn_list::String)::Vector{String}
    parts = split(alpn_list, ';'; keepempty = false)
    isempty(parts) && throw_error(ERROR_IO_TLS_CTX_ERROR)
    if length(parts) > 4
        throw_error(ERROR_IO_TLS_CTX_ERROR)
    end
    return String.(parts)
end

function _secure_channel_fill_alpn_data!(handler, alpn_data::Memory{UInt8})::Csize_t
    handler.alpn_list === nothing && return Csize_t(0)
    protocols = _secure_channel_parse_alpn_list(handler.alpn_list)
    isempty(protocols) && return Csize_t(0)

    fill!(alpn_data, 0x00)
    max_len = length(alpn_data)
    idx = 1

    function ensure_len(required::Int)
        if required > max_len
            throw_error(ERROR_SHORT_BUFFER)
        end
    end

    ensure_len(idx + 4 - 1)
    ext_len_ptr = Ptr{UInt32}(pointer(alpn_data, idx))
    unsafe_store!(ext_len_ptr, UInt32(0))
    idx += 4

    ensure_len(idx + 4 - 1)
    ext_name_ptr = Ptr{UInt32}(pointer(alpn_data, idx))
    unsafe_store!(ext_name_ptr, _SEC_APP_PROTO_NEGOTIATION_EXT_ALPN)
    idx += 4

    ensure_len(idx + 2 - 1)
    protos_len_ptr = Ptr{UInt16}(pointer(alpn_data, idx))
    unsafe_store!(protos_len_ptr, UInt16(0))
    idx += 2

    ext_len = UInt32(4 + 2)
    protos_len = UInt16(0)

    for proto in protocols
        bytes = codeunits(proto)
        plen = length(bytes)
        plen == 0 && continue
        plen > 255 && throw_error(ERROR_IO_TLS_CTX_ERROR)

        ext_len += UInt32(plen + 1)
        protos_len = UInt16(protos_len + UInt16(plen + 1))

        ensure_len(idx)
        alpn_data[idx] = UInt8(plen)
        idx += 1

        ensure_len(idx + plen - 1)
        for j in 1:plen
            alpn_data[idx + j - 1] = bytes[j]
        end
        idx += plen
    end

    unsafe_store!(ext_len_ptr, ext_len)
    unsafe_store!(protos_len_ptr, protos_len)

    return Csize_t(ext_len + UInt32(4))
end

function _secure_channel_on_negotiation_result(handler, error_code::Int)
    tls_on_negotiation_completed(handler, error_code)
    slot = handler.slot
    slot === nothing && return nothing
    channel_slot_is_attached(slot) || return nothing
    _complete_setup!(error_code, slot.channel)
    return nothing
end

function _secure_channel_send_alpn_message(handler)
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

function _secure_channel_invoke_negotiation_error(handler, err::Int)
    logf(
        LogLevel.ERROR,
        LS_IO_TLS,
        "secure_channel: negotiation error code=$(err), state=$(Int(handler.connection_state)), is_client=$(handler.is_client_mode)",
    )
    handler.negotiation_failed = true
    _secure_channel_on_negotiation_result(handler, err)
    return nothing
end

function _secure_channel_on_negotiation_success(handler)
    handler.negotiation_failed = false
    _secure_channel_send_alpn_message(handler)
    _secure_channel_on_negotiation_result(handler, OP_SUCCESS)
    return nothing
end

@inline function _secure_channel_fail_pending_negotiation!(
        handler,
        error_code::Int,
    )::Nothing
    status = handler.stats.handshake_status
    if status == TlsNegotiationStatus.ONGOING || status == TlsNegotiationStatus.NONE
        handler.negotiation_finished = false
        handler.negotiation_failed = true
        err = error_code == OP_SUCCESS ? ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE : error_code
        _secure_channel_on_negotiation_result(handler, err)
    end
    return nothing
end

function _secure_channel_server_name_cstring(handler)::Vector{UInt8}
    if handler.server_name.len == 0
        return UInt8[0x00]
    end
    cur = byte_cursor_from_buf(handler.server_name)
    name = String(cur)
    bytes = Vector{UInt8}(codeunits(name))
    push!(bytes, 0x00)
    return bytes
end

function _secure_channel_manual_verify_peer_cert(handler)::Nothing
    handler.custom_ca_store == C_NULL && return nothing

    peer_cert_ref = Ref{Ptr{Cvoid}}(C_NULL)
    status = ccall(
        (:QueryContextAttributesW, _SECUR32_LIB),
        Int32,
        (Ref{_CtxtHandle}, UInt32, Ptr{Cvoid}),
        handler.sec_handle,
        _SECPKG_ATTR_REMOTE_CERT_CONTEXT,
        Base.unsafe_convert(Ptr{Cvoid}, peer_cert_ref),
    )
    if status != _SEC_E_OK || peer_cert_ref[] == C_NULL
        throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
    end

    engine_ref = Ref{Ptr{Cvoid}}(C_NULL)
    chain_ctx_ref = Ref{Ptr{Cvoid}}(C_NULL)

    try
        engine_cfg = _CERT_CHAIN_ENGINE_CONFIG(
            UInt32(sizeof(_CERT_CHAIN_ENGINE_CONFIG)),
            C_NULL,
            C_NULL,
            C_NULL,
            0,
            C_NULL,
            0,
            0,
            0,
            0,
            handler.custom_ca_store,
            C_NULL,
            0,
        )

        ok = ccall(
            (:CertCreateCertificateChainEngine, _CRYPT32_LIB),
            Int32,
            (Ref{_CERT_CHAIN_ENGINE_CONFIG}, Ref{Ptr{Cvoid}}),
            engine_cfg,
            engine_ref,
        )
        ok == 0 && throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)

        usage_oids = [_OID_SERVER_AUTH, _OID_SERVER_GATED_CRYPTO, _OID_SGC_NETSCAPE]
        usage_ptrs = Vector{Cstring}(undef, length(usage_oids))
        for i in eachindex(usage_oids)
            usage_ptrs[i] = Base.unsafe_convert(Cstring, usage_oids[i])
        end

        requested_usage = GC.@preserve usage_oids usage_ptrs begin
            _CERT_USAGE_MATCH(
                _USAGE_MATCH_TYPE_OR,
                _CERT_ENHKEY_USAGE(UInt32(length(usage_ptrs)), pointer(usage_ptrs)),
            )
        end

        chain_para = _CERT_CHAIN_PARA(
            UInt32(sizeof(_CERT_CHAIN_PARA)),
            requested_usage,
            _CERT_USAGE_MATCH(0, _CERT_ENHKEY_USAGE(0, C_NULL)),
            0,
            0,
            0,
            C_NULL,
            C_NULL,
            0,
        )

        peer_cert = unsafe_load(Ptr{_CERT_CONTEXT}(peer_cert_ref[]))

        ok = GC.@preserve usage_oids usage_ptrs chain_para begin
            ccall(
                (:CertGetCertificateChain, _CRYPT32_LIB),
                Int32,
                (Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ref{_CERT_CHAIN_PARA}, UInt32, Ptr{Cvoid}, Ref{Ptr{Cvoid}}),
                engine_ref[],
                peer_cert_ref[],
                C_NULL,
                peer_cert.hCertStore,
                chain_para,
                0,
                C_NULL,
                chain_ctx_ref,
            )
        end
        ok == 0 && throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)

        host_wstr = Vector{UInt16}(undef, _SCHANNEL_MAX_HOST_LENGTH + 1)
        fill!(host_wstr, 0x0000)
        host_ptr = pointer(host_wstr)

        if handler.server_name.len > 0
            host = String(byte_cursor_from_buf(handler.server_name))
            converted = ccall(
                (:MultiByteToWideChar, _KERNEL32_LIB),
                Int32,
                (UInt32, UInt32, Cstring, Int32, Ptr{UInt16}, Int32),
                _CP_UTF8,
                _MB_ERR_INVALID_CHARS,
                host,
                Int32(ncodeunits(host)),
                pointer(host_wstr),
                Int32(length(host_wstr)),
            )
            if converted != ncodeunits(host)
                throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
            end
            host_wstr[converted + 1] = 0x0000
            host_ptr = pointer(host_wstr)
        end

        ssl_policy = _HTTPSPolicyCallbackData(
            UInt32(sizeof(_HTTPSPolicyCallbackData)),
            _AUTHTYPE_SERVER,
            0,
            host_ptr,
        )

        ssl_policy_ref = Ref(ssl_policy)
        policy_para = _CERT_CHAIN_POLICY_PARA(
            UInt32(sizeof(_CERT_CHAIN_POLICY_PARA)),
            0,
            Base.unsafe_convert(Ptr{Cvoid}, ssl_policy_ref),
        )

        policy_status = Ref(_CERT_CHAIN_POLICY_STATUS(UInt32(sizeof(_CERT_CHAIN_POLICY_STATUS)), 0, 0, 0, C_NULL))

        ok = GC.@preserve host_wstr ssl_policy_ref policy_para policy_status begin
            ccall(
                (:CertVerifyCertificateChainPolicy, _CRYPT32_LIB),
                Int32,
                (Ptr{UInt8}, Ptr{Cvoid}, Ref{_CERT_CHAIN_POLICY_PARA}, Ref{_CERT_CHAIN_POLICY_STATUS}),
                _CERT_CHAIN_POLICY_SSL,
                chain_ctx_ref[],
                policy_para,
                policy_status,
            )
        end
        ok == 0 && throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
        policy_status[].dwError == 0 || throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)

        chain_ctx = unsafe_load(Ptr{_CERT_CHAIN_CONTEXT}(chain_ctx_ref[]))
        if chain_ctx.cChain > 0 && chain_ctx.rgpChain != C_NULL
            simple_chain_ptr = unsafe_load(chain_ctx.rgpChain)
            if simple_chain_ptr != C_NULL
                simple_chain = unsafe_load(simple_chain_ptr)
                trust_mask = simple_chain.TrustStatus.dwErrorStatus & ~_CERT_TRUST_IS_NOT_TIME_NESTED
                trust_mask == 0 || throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
            end
        end
    finally
        if chain_ctx_ref[] != C_NULL
            ccall((:CertFreeCertificateChain, _CRYPT32_LIB), Cvoid, (Ptr{Cvoid},), chain_ctx_ref[])
        end
        if engine_ref[] != C_NULL
            ccall((:CertFreeCertificateChainEngine, _CRYPT32_LIB), Cvoid, (Ptr{Cvoid},), engine_ref[])
        end
        if peer_cert_ref[] != C_NULL
            _ = ccall((:CertFreeCertificateContext, _CRYPT32_LIB), Int32, (Ptr{Cvoid},), peer_cert_ref[])
        end
    end

    return nothing
end

function _secure_channel_run_state(handler)::Nothing
    state = handler.connection_state
    if state == _SecureChannelConnectionState.CLIENT_NEGOTIATION_STEP_1
        _secure_channel_do_client_negotiation_step_1(handler)
    elseif state == _SecureChannelConnectionState.CLIENT_NEGOTIATION_STEP_2
        _secure_channel_do_client_negotiation_step_2(handler)
    elseif state == _SecureChannelConnectionState.SERVER_NEGOTIATION_STEP_1
        _secure_channel_do_server_negotiation_step_1(handler)
    elseif state == _SecureChannelConnectionState.SERVER_NEGOTIATION_STEP_2
        _secure_channel_do_server_negotiation_step_2(handler)
    elseif state == _SecureChannelConnectionState.APPLICATION_DECRYPT
        _secure_channel_do_application_data_decrypt(handler)
    else
        throw_error(ERROR_INVALID_STATE)
    end
    return nothing
end

function _secure_channel_do_server_negotiation_step_1(handler)::Nothing
    tls_on_drive_negotiation(handler)

    aws_error = 0
    alpn_data = Memory{UInt8}(undef, 128)

    input_buffers = _SecBuffer[
        _SecBuffer(UInt32(handler.buffered_read_in.len), _SECBUFFER_TOKEN, pointer(handler.buffered_read_in.mem)),
        _SecBuffer(0, _SECBUFFER_EMPTY, C_NULL),
    ]

    if handler.alpn_list !== nothing && tls_is_alpn_available()
        written = _secure_channel_fill_alpn_data!(handler, alpn_data)
        input_buffers[2] = _SecBuffer(UInt32(written), _SECBUFFER_APPLICATION_PROTOCOLS, pointer(alpn_data))
    end

    output_ref = Ref(_SecBuffer(0, _SECBUFFER_TOKEN, C_NULL))
    input_desc = Ref(_SecBufferDesc(_SECBUFFER_VERSION, UInt32(length(input_buffers)), pointer(input_buffers)))
    output_desc = Ref(_SecBufferDesc(_SECBUFFER_VERSION, UInt32(1), Base.unsafe_convert(Ptr{_SecBuffer}, output_ref)))

    handler.ctx_req = _ASC_REQ_SEQUENCE_DETECT | _ASC_REQ_REPLAY_DETECT | _ASC_REQ_CONFIDENTIALITY |
        _ASC_REQ_ALLOCATE_MEMORY | _ASC_REQ_STREAM
    if handler.verify_peer
        handler.ctx_req |= _ASC_REQ_MUTUAL_AUTH
    end

    creds_ref = Ref(handler.creds)
    sec_ref = Ref(handler.sec_handle)
    ctx_ret_ref = Ref(handler.ctx_ret_flags)
    status = GC.@preserve input_buffers output_ref input_desc output_desc alpn_data ctx_ret_ref begin
        ccall(
            (:AcceptSecurityContext, _SECUR32_LIB),
            Int32,
            (Ref{_CredHandle}, Ptr{_CtxtHandle}, Ref{_SecBufferDesc}, UInt32, UInt32, Ref{_CtxtHandle}, Ref{_SecBufferDesc}, Ref{UInt32}, Ptr{Cvoid}),
            creds_ref,
            C_NULL,
            input_desc,
            handler.ctx_req,
            0,
            sec_ref,
            output_desc,
            ctx_ret_ref,
            C_NULL,
        )
    end
    handler.sec_handle = sec_ref[]
    handler.ctx_ret_flags = ctx_ret_ref[]
    output_buffer = output_ref[]

    if status != _SEC_I_CONTINUE_NEEDED && status != _SEC_E_OK
        logf(
            LogLevel.ERROR,
            LS_IO_TLS,
            "secure_channel: server step1 AcceptSecurityContext failed, status=0x$(uppercase(string(reinterpret(UInt32, status), base=16)))",
        )
        aws_error = _secure_channel_determine_sspi_error(status)
    else
        try
            _secure_channel_send_token_message(handler, output_buffer.pvBuffer, output_buffer.cbBuffer)
            handler.connection_state = _SecureChannelConnectionState.SERVER_NEGOTIATION_STEP_2
        catch e
            aws_error = _secure_channel_error_code_from_exception(e, "server_negotiation_step_1")
        end
    end

    if output_buffer.pvBuffer != C_NULL
        _ = ccall((:FreeContextBuffer, _SECUR32_LIB), Int32, (Ptr{Cvoid},), output_buffer.pvBuffer)
    end

    if aws_error != 0
        _secure_channel_invoke_negotiation_error(handler, aws_error)
        throw_error(aws_error)
    end

    return nothing
end

function _secure_channel_do_server_negotiation_step_2(handler)::Nothing
    aws_error = 0

    input_buffers = _SecBuffer[
        _SecBuffer(UInt32(handler.buffered_read_in.len), _SECBUFFER_TOKEN, pointer(handler.buffered_read_in.mem)),
        _SecBuffer(0, _SECBUFFER_EMPTY, C_NULL),
    ]

    output_buffers = _SecBuffer[
        _SecBuffer(0, _SECBUFFER_TOKEN, C_NULL),
        _SecBuffer(0, _SECBUFFER_ALERT, C_NULL),
        _SecBuffer(0, _SECBUFFER_EMPTY, C_NULL),
    ]

    input_desc = Ref(_SecBufferDesc(_SECBUFFER_VERSION, UInt32(length(input_buffers)), pointer(input_buffers)))
    output_desc = Ref(_SecBufferDesc(_SECBUFFER_VERSION, UInt32(length(output_buffers)), pointer(output_buffers)))

    handler.read_extra = 0
    handler.estimated_incomplete_size = 0

    creds_ref = Ref(handler.creds)
    sec_ref = Ref(handler.sec_handle)
    ts_ref = Ref(handler.sspi_timestamp)
    ctx_ret_ref = Ref(handler.ctx_ret_flags)

    status = GC.@preserve input_buffers output_buffers input_desc output_desc ts_ref ctx_ret_ref begin
        ccall(
            (:AcceptSecurityContext, _SECUR32_LIB),
            Int32,
            (Ref{_CredHandle}, Ref{_CtxtHandle}, Ref{_SecBufferDesc}, UInt32, UInt32, Ptr{_CtxtHandle}, Ref{_SecBufferDesc}, Ref{UInt32}, Ref{_TimeStamp}),
            creds_ref,
            sec_ref,
            input_desc,
            handler.ctx_req,
            0,
            C_NULL,
            output_desc,
            ctx_ret_ref,
            ts_ref,
        )
    end
    handler.sspi_timestamp = ts_ref[]
    handler.ctx_ret_flags = ctx_ret_ref[]

    if status != _SEC_E_INCOMPLETE_MESSAGE && status != _SEC_I_CONTINUE_NEEDED && status != _SEC_E_OK
        logf(
            LogLevel.ERROR,
            LS_IO_TLS,
            "secure_channel: server step2 AcceptSecurityContext failed, status=0x$(uppercase(string(reinterpret(UInt32, status), base=16)))",
        )
        aws_error = _secure_channel_determine_sspi_error(status)
    elseif status == _SEC_E_INCOMPLETE_MESSAGE
        handler.estimated_incomplete_size = Csize_t(input_buffers[2].cbBuffer)
        aws_error = ERROR_IO_READ_WOULD_BLOCK
    else
        try
            for i in eachindex(output_buffers)
                buf = output_buffers[i]
                if buf.BufferType == _SECBUFFER_TOKEN && buf.cbBuffer > 0
                    _secure_channel_send_token_message(handler, buf.pvBuffer, buf.cbBuffer)
                end
            end

            if input_buffers[2].BufferType == _SECBUFFER_EXTRA && input_buffers[2].cbBuffer > 0
                handler.read_extra = Csize_t(input_buffers[2].cbBuffer)
            end

            if status == _SEC_E_OK
                if handler.custom_ca_store != C_NULL
                    _secure_channel_manual_verify_peer_cert(handler)
                end

                handler.negotiation_finished = true
                _secure_channel_query_stream_sizes!(handler)
                if handler.alpn_list !== nothing && tls_is_alpn_available()
                    handler.protocol = _secure_channel_protocol_from_context(handler)
                end

                handler.connection_state = _SecureChannelConnectionState.APPLICATION_DECRYPT
                _secure_channel_on_negotiation_success(handler)
            end
        catch e
            aws_error = _secure_channel_error_code_from_exception(e, "server_negotiation_step_2")
        end
    end

    _secure_channel_free_output_buffers!(output_buffers)

    if aws_error != 0
        if aws_error != ERROR_IO_READ_WOULD_BLOCK
            _secure_channel_invoke_negotiation_error(handler, aws_error)
        end
        throw_error(aws_error)
    end

    return nothing
end

function _secure_channel_do_client_negotiation_step_1(handler)::Nothing
    tls_on_drive_negotiation(handler)

    aws_error = 0

    alpn_data = Memory{UInt8}(undef, 128)
    alpn_buffers = _SecBuffer[_SecBuffer(0, _SECBUFFER_EMPTY, C_NULL)]
    alpn_desc = Ref(_SecBufferDesc(_SECBUFFER_VERSION, UInt32(1), pointer(alpn_buffers)))
    alpn_desc_ptr = Ptr{_SecBufferDesc}(C_NULL)

    if handler.alpn_list !== nothing && tls_is_alpn_available()
        written = _secure_channel_fill_alpn_data!(handler, alpn_data)
        alpn_buffers[1] = _SecBuffer(UInt32(written), _SECBUFFER_APPLICATION_PROTOCOLS, pointer(alpn_data))
        alpn_desc_ptr = Base.unsafe_convert(Ptr{_SecBufferDesc}, alpn_desc)
    end

    output_ref = Ref(_SecBuffer(0, _SECBUFFER_TOKEN, C_NULL))
    output_desc = Ref(_SecBufferDesc(_SECBUFFER_VERSION, UInt32(1), Base.unsafe_convert(Ptr{_SecBuffer}, output_ref)))

    handler.ctx_req = _ISC_REQ_SEQUENCE_DETECT | _ISC_REQ_REPLAY_DETECT | _ISC_REQ_CONFIDENTIALITY |
        _ISC_REQ_ALLOCATE_MEMORY | _ISC_REQ_STREAM

    server_name_cstr = _secure_channel_server_name_cstring(handler)

    creds_ref = Ref(handler.creds)
    sec_ref = Ref(handler.sec_handle)
    ts_ref = Ref(handler.sspi_timestamp)
    ctx_ret_ref = Ref(handler.ctx_ret_flags)
    status = GC.@preserve output_ref output_desc server_name_cstr alpn_buffers alpn_desc alpn_data ts_ref ctx_ret_ref begin
        ccall(
            (:InitializeSecurityContextA, _SECUR32_LIB),
            Int32,
            (Ref{_CredHandle}, Ptr{_CtxtHandle}, Cstring, UInt32, UInt32, UInt32, Ptr{_SecBufferDesc}, UInt32, Ref{_CtxtHandle}, Ref{_SecBufferDesc}, Ref{UInt32}, Ref{_TimeStamp}),
            creds_ref,
            C_NULL,
            pointer(server_name_cstr),
            handler.ctx_req,
            0,
            0,
            alpn_desc_ptr,
            0,
            sec_ref,
            output_desc,
            ctx_ret_ref,
            ts_ref,
        )
    end
    handler.sec_handle = sec_ref[]
    handler.sspi_timestamp = ts_ref[]
    handler.ctx_ret_flags = ctx_ret_ref[]
    output_buffer = output_ref[]

    if status != _SEC_I_CONTINUE_NEEDED
        logf(
            LogLevel.ERROR,
            LS_IO_TLS,
            "secure_channel: client step1 InitializeSecurityContext failed, status=0x$(uppercase(string(reinterpret(UInt32, status), base=16)))",
        )
        aws_error = _secure_channel_determine_sspi_error(status)
    else
        try
            _secure_channel_send_token_message(handler, output_buffer.pvBuffer, output_buffer.cbBuffer)
            handler.connection_state = _SecureChannelConnectionState.CLIENT_NEGOTIATION_STEP_2
        catch e
            aws_error = _secure_channel_error_code_from_exception(e, "client_negotiation_step_1")
        end
    end

    if output_buffer.pvBuffer != C_NULL
        _ = ccall((:FreeContextBuffer, _SECUR32_LIB), Int32, (Ptr{Cvoid},), output_buffer.pvBuffer)
    end

    if aws_error != 0
        _secure_channel_invoke_negotiation_error(handler, aws_error)
        throw_error(aws_error)
    end

    return nothing
end

function _secure_channel_do_client_negotiation_step_2(handler)::Nothing
    aws_error = 0

    input_buffers = _SecBuffer[
        _SecBuffer(UInt32(handler.buffered_read_in.len), _SECBUFFER_TOKEN, pointer(handler.buffered_read_in.mem)),
        _SecBuffer(0, _SECBUFFER_EMPTY, C_NULL),
    ]

    output_buffers = _SecBuffer[
        _SecBuffer(0, _SECBUFFER_TOKEN, C_NULL),
        _SecBuffer(0, _SECBUFFER_ALERT, C_NULL),
        _SecBuffer(0, _SECBUFFER_EMPTY, C_NULL),
    ]

    input_desc = Ref(_SecBufferDesc(_SECBUFFER_VERSION, UInt32(length(input_buffers)), pointer(input_buffers)))
    output_desc = Ref(_SecBufferDesc(_SECBUFFER_VERSION, UInt32(length(output_buffers)), pointer(output_buffers)))

    handler.read_extra = 0
    handler.estimated_incomplete_size = 0

    server_name_cstr = _secure_channel_server_name_cstring(handler)

    creds_ref = Ref(handler.creds)
    sec_ref = Ref(handler.sec_handle)
    ts_ref = Ref(handler.sspi_timestamp)
    ctx_ret_ref = Ref(handler.ctx_ret_flags)
    status = GC.@preserve input_buffers output_buffers input_desc output_desc server_name_cstr ts_ref ctx_ret_ref begin
        ccall(
            (:InitializeSecurityContextA, _SECUR32_LIB),
            Int32,
            (Ref{_CredHandle}, Ref{_CtxtHandle}, Cstring, UInt32, UInt32, UInt32, Ref{_SecBufferDesc}, UInt32, Ptr{_CtxtHandle}, Ref{_SecBufferDesc}, Ref{UInt32}, Ref{_TimeStamp}),
            creds_ref,
            sec_ref,
            pointer(server_name_cstr),
            handler.ctx_req,
            0,
            0,
            input_desc,
            0,
            C_NULL,
            output_desc,
            ctx_ret_ref,
            ts_ref,
        )
    end
    handler.sspi_timestamp = ts_ref[]
    handler.ctx_ret_flags = ctx_ret_ref[]

    if status != _SEC_E_INCOMPLETE_MESSAGE && status != _SEC_I_CONTINUE_NEEDED && status != _SEC_E_OK
        logf(
            LogLevel.ERROR,
            LS_IO_TLS,
            "secure_channel: client step2 InitializeSecurityContext failed, status=0x$(uppercase(string(reinterpret(UInt32, status), base=16)))",
        )
        aws_error = _secure_channel_determine_sspi_error(status)
    elseif status == _SEC_E_INCOMPLETE_MESSAGE
        handler.estimated_incomplete_size = Csize_t(input_buffers[2].cbBuffer)
        aws_error = ERROR_IO_READ_WOULD_BLOCK
    else
        try
            for i in eachindex(output_buffers)
                buf = output_buffers[i]
                if buf.BufferType == _SECBUFFER_TOKEN && buf.cbBuffer > 0
                    _secure_channel_send_token_message(handler, buf.pvBuffer, buf.cbBuffer)
                end
            end

            if input_buffers[2].BufferType == _SECBUFFER_EXTRA && input_buffers[2].cbBuffer > 0
                handler.read_extra = Csize_t(input_buffers[2].cbBuffer)
            end

            if status == _SEC_E_OK
                if handler.custom_ca_store != C_NULL
                    _secure_channel_manual_verify_peer_cert(handler)
                end

                handler.negotiation_finished = true
                _secure_channel_query_stream_sizes!(handler)
                if handler.alpn_list !== nothing && tls_is_alpn_available()
                    handler.protocol = _secure_channel_protocol_from_context(handler)
                end

                handler.connection_state = _SecureChannelConnectionState.APPLICATION_DECRYPT
                _secure_channel_on_negotiation_success(handler)
            end
        catch e
            aws_error = _secure_channel_error_code_from_exception(e, "client_negotiation_step_2")
        end
    end

    _secure_channel_free_output_buffers!(output_buffers)

    if aws_error != 0
        if aws_error != ERROR_IO_READ_WOULD_BLOCK
            _secure_channel_invoke_negotiation_error(handler, aws_error)
        end
        throw_error(aws_error)
    end

    return nothing
end

function _secure_channel_do_application_data_decrypt(handler)::Nothing
    while true
        read_len = handler.read_extra > 0 ? handler.read_extra : Csize_t(handler.buffered_read_in.len)
        offset = handler.read_extra > 0 ? Csize_t(handler.buffered_read_in.len - handler.read_extra) : Csize_t(0)
        handler.read_extra = 0

        input_buffers = _SecBuffer[
            _SecBuffer(UInt32(read_len), _SECBUFFER_DATA, pointer(handler.buffered_read_in.mem) + Int(offset)),
            _SecBuffer(0, _SECBUFFER_EMPTY, C_NULL),
            _SecBuffer(0, _SECBUFFER_EMPTY, C_NULL),
            _SecBuffer(0, _SECBUFFER_EMPTY, C_NULL),
        ]

        desc = Ref(_SecBufferDesc(_SECBUFFER_VERSION, UInt32(length(input_buffers)), pointer(input_buffers)))

        sec_ref = Ref(handler.sec_handle)
        status = GC.@preserve input_buffers desc begin
            ccall(
                (:DecryptMessage, _SECUR32_LIB),
                Int32,
                (Ref{_CtxtHandle}, Ref{_SecBufferDesc}, UInt32, Ptr{UInt32}),
                sec_ref,
                desc,
                0,
                C_NULL,
            )
        end

        if status == _SEC_E_OK
            if input_buffers[2].BufferType == _SECBUFFER_DATA
                decrypted_len = Int(input_buffers[2].cbBuffer)
                if decrypted_len > 0
                    cursor = ByteCursor(unsafe_wrap(Memory{UInt8}, Ptr{UInt8}(input_buffers[2].pvBuffer), decrypted_len; own = false), decrypted_len)
                    out_ref = Ref(handler.buffered_read_out)
                    if byte_buf_append(out_ref, cursor) != OP_SUCCESS
                        throw_error(ERROR_OOM)
                    end
                    handler.buffered_read_out = out_ref[]
                end

                if input_buffers[4].BufferType == _SECBUFFER_EXTRA && input_buffers[4].cbBuffer > 0
                    handler.read_extra = Csize_t(input_buffers[4].cbBuffer)
                else
                    setfield!(handler.buffered_read_in, :len, Csize_t(0))
                end
            end
        elseif status == _SEC_I_RENEGOTIATE
            if input_buffers[2].BufferType == _SECBUFFER_DATA
                decrypted_len = Int(input_buffers[2].cbBuffer)
                if decrypted_len > 0
                    cursor = ByteCursor(unsafe_wrap(Memory{UInt8}, Ptr{UInt8}(input_buffers[2].pvBuffer), decrypted_len; own = false), decrypted_len)
                    out_ref = Ref(handler.buffered_read_out)
                    if byte_buf_append(out_ref, cursor) != OP_SUCCESS
                        throw_error(ERROR_OOM)
                    end
                    handler.buffered_read_out = out_ref[]
                end
            end

            extra_data_offset = Int(offset)
            if input_buffers[4].BufferType == _SECBUFFER_EXTRA &&
                    input_buffers[4].cbBuffer > 0 &&
                    input_buffers[4].cbBuffer < read_len
                extra_data_offset = Int(offset + read_len - Csize_t(input_buffers[4].cbBuffer))
            end

            input2 = _SecBuffer[
                _SecBuffer(
                    UInt32(handler.buffered_read_in.len - extra_data_offset),
                    _SECBUFFER_TOKEN,
                    pointer(handler.buffered_read_in.mem) + extra_data_offset,
                ),
                _SecBuffer(0, _SECBUFFER_EMPTY, C_NULL),
            ]
            input2_desc = Ref(_SecBufferDesc(_SECBUFFER_VERSION, UInt32(length(input2)), pointer(input2)))

            output2 = _SecBuffer[
                _SecBuffer(0, _SECBUFFER_TOKEN, C_NULL),
                _SecBuffer(0, _SECBUFFER_ALERT, C_NULL),
                _SecBuffer(0, _SECBUFFER_EMPTY, C_NULL),
            ]
            output2_desc = Ref(_SecBufferDesc(_SECBUFFER_VERSION, UInt32(length(output2)), pointer(output2)))

            server_name_cstr = _secure_channel_server_name_cstring(handler)
            creds_ref = Ref(handler.creds)
            sec2_ref = Ref(handler.sec_handle)
            ctx_ret_ref = Ref(handler.ctx_ret_flags)
            reneg_status = GC.@preserve input2 input2_desc output2 output2_desc server_name_cstr ctx_ret_ref begin
                ccall(
                    (:InitializeSecurityContextA, _SECUR32_LIB),
                    Int32,
                    (Ref{_CredHandle}, Ref{_CtxtHandle}, Cstring, UInt32, UInt32, UInt32, Ref{_SecBufferDesc}, UInt32, Ptr{_CtxtHandle}, Ref{_SecBufferDesc}, Ref{UInt32}, Ptr{Cvoid}),
                    creds_ref,
                    sec2_ref,
                    pointer(server_name_cstr),
                    handler.ctx_req,
                    0,
                    0,
                    input2_desc,
                    0,
                    C_NULL,
                    output2_desc,
                    ctx_ret_ref,
                    C_NULL,
                )
            end
            handler.ctx_ret_flags = ctx_ret_ref[]

            if reneg_status == _SEC_E_OK
                if input2[2].BufferType == _SECBUFFER_EXTRA
                    handler.read_extra = Csize_t(input2[2].cbBuffer)
                end
            else
                _secure_channel_free_output_buffers!(output2)
                throw_error(ERROR_IO_TLS_ERROR_READ_FAILURE)
            end

            _secure_channel_free_output_buffers!(output2)
        elseif status == _SEC_E_INCOMPLETE_MESSAGE
            handler.estimated_incomplete_size = Csize_t(input_buffers[2].cbBuffer)
            src = pointer(handler.buffered_read_in.mem) + Int(offset)
            dest = pointer(handler.buffered_read_in.mem)
            _secure_channel_memmove!(dest, src, read_len)
            setfield!(handler.buffered_read_in, :len, read_len)
            throw_error(ERROR_IO_READ_WOULD_BLOCK)
        elseif status == _SEC_I_CONTEXT_EXPIRED
            slot = handler.slot
            slot !== nothing && channel_slot_is_attached(slot) && channel_shutdown!(slot.channel, OP_SUCCESS)
            return nothing
        else
            throw_error(ERROR_IO_TLS_ERROR_READ_FAILURE)
        end

        handler.read_extra == 0 && break
    end

    return nothing
end

mutable struct SecureChannelCtx
    minimum_tls_version::TlsVersion.T
    alpn_list::Union{String, Nothing}
    verify_peer::Bool
    credential_flags::UInt32
    cert_context::Ptr{Cvoid}
    cert_store::Ptr{Cvoid}
    custom_trust_store::Ptr{Cvoid}
    disable_tls13::Bool
    should_free_cert_context::Bool
end

mutable struct SecureChannelTlsHandler <: TlsChannelHandler
    slot::Union{ChannelSlot{Channel}, Nothing}
    tls_timeout_ms::UInt32
    stats::TlsHandlerStatistics
    timeout_task::ChannelTask
    sec_handle::_CtxtHandle
    creds::_CredHandle
    stream_sizes::_SecPkgContextStreamSizes
    ctx_req::UInt32
    ctx_ret_flags::UInt32
    protocol::ByteBuffer
    server_name::ByteBuffer
    sspi_timestamp::_TimeStamp
    connection_state::_SecureChannelConnectionState.T
    buffered_read_in::ByteBuffer
    estimated_incomplete_size::Csize_t
    read_extra::Csize_t
    buffered_read_out::ByteBuffer
    tls_negotiation_result::Future{Cint}
    on_data_read::Union{TlsDataReadCallback, Nothing}
    alpn_list::Union{String, Nothing}
    advertise_alpn_message::Bool
    negotiation_finished::Bool
    negotiation_failed::Bool
    verify_peer::Bool
    read_task::ChannelTask
    read_task_pending::Bool
    read_state::TlsHandlerReadState.T
    shutdown_error_code::Int
    negotiation_task::ChannelTask
    ctx_obj::Union{TlsContext, Nothing}
    custom_ca_store::Ptr{Cvoid}
    is_client_mode::Bool
    cert_contexts::Union{Memory{Ptr{Cvoid}}, Nothing}
end

function setchannelslot!(handler::SecureChannelTlsHandler, slot::ChannelSlot{Channel})::Nothing
    handler.slot = slot
    return nothing
end

function _secure_channel_init()
    @static if Sys.iswindows()
        logf(LogLevel.INFO, LS_IO_TLS, "static: Initializing TLS using SecureChannel (SSPI).")
        return nothing
    else
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end
end

function _secure_channel_cleanup()
    return nothing
end

function _secure_channel_open_memory_cert_store()::Ptr{Cvoid}
    return ccall(
        (:CertOpenStore, _CRYPT32_LIB),
        Ptr{Cvoid},
        (Ptr{UInt8}, UInt32, Ptr{Cvoid}, UInt32, Ptr{Cvoid}),
        _CERT_STORE_PROV_MEMORY,
        _ENCODING_FLAGS,
        C_NULL,
        _CERT_STORE_CREATE_NEW_FLAG,
        C_NULL,
    )
end

function _secure_channel_close_cert_store(store::Ptr{Cvoid})::Nothing
    store == C_NULL && return nothing
    _ = ccall((:CertCloseStore, _CRYPT32_LIB), Int32, (Ptr{Cvoid}, UInt32), store, 0)
    return nothing
end

function _secure_channel_import_trusted_certificates(cert_blob::ByteCursor)::Ptr{Cvoid}
    store = _secure_channel_open_memory_cert_store()
    store == C_NULL && throw_error(ERROR_IO_TLS_CTX_ERROR)

    success = false
    try
        objs = pem_parse(_cursor_to_memory(cert_blob))
        certs = pem_filter_certificates(objs)
        isempty(certs) && throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)

        for obj in certs
            der = obj.data
            cert_ctx_ref = Ref{Ptr{Cvoid}}(C_NULL)
            ok = ccall(
                (:CertAddEncodedCertificateToStore, _CRYPT32_LIB),
                Int32,
                (Ptr{Cvoid}, UInt32, Ptr{UInt8}, UInt32, UInt32, Ref{Ptr{Cvoid}}),
                store,
                _ENCODING_FLAGS,
                pointer(der.mem),
                UInt32(der.len),
                _CERT_STORE_ADD_ALWAYS,
                cert_ctx_ref,
            )
            ok == 0 && throw_error(ERROR_IO_TLS_CTX_ERROR)
            if cert_ctx_ref[] != C_NULL
                _ = ccall((:CertFreeCertificateContext, _CRYPT32_LIB), Int32, (Ptr{Cvoid},), cert_ctx_ref[])
            end
        end

        success = true
        return store
    finally
        if !success
            _secure_channel_close_cert_store(store)
        end
    end
end

function _secure_channel_get_enabled_protocols(minimum_tls_version::TlsVersion.T, is_client_mode::Bool)::UInt32
    enabled = UInt32(0)
    if is_client_mode
        if minimum_tls_version == TlsVersion.SSLv3
            enabled |= _SECPROT_SSL3_CLIENT
            enabled |= _SECPROT_TLS1_0_CLIENT
            enabled |= _SECPROT_TLS1_1_CLIENT
            enabled |= _SECPROT_TLS1_2_CLIENT
        elseif minimum_tls_version == TlsVersion.TLSv1
            enabled |= _SECPROT_TLS1_0_CLIENT
            enabled |= _SECPROT_TLS1_1_CLIENT
            enabled |= _SECPROT_TLS1_2_CLIENT
        elseif minimum_tls_version == TlsVersion.TLSv1_1
            enabled |= _SECPROT_TLS1_1_CLIENT
            enabled |= _SECPROT_TLS1_2_CLIENT
        elseif minimum_tls_version == TlsVersion.TLSv1_2
            enabled |= _SECPROT_TLS1_2_CLIENT
        elseif minimum_tls_version == TlsVersion.TLSv1_3
            # SCHANNEL_CRED path cannot request TLS1.3 explicitly.
            throw_error(ERROR_IO_TLS_VERSION_UNSUPPORTED)
        else
            enabled = UInt32(0)
        end
    else
        if minimum_tls_version == TlsVersion.SSLv3
            enabled |= _SECPROT_SSL3_SERVER
            enabled |= _SECPROT_TLS1_0_SERVER
            enabled |= _SECPROT_TLS1_1_SERVER
            enabled |= _SECPROT_TLS1_2_SERVER
        elseif minimum_tls_version == TlsVersion.TLSv1
            enabled |= _SECPROT_TLS1_0_SERVER
            enabled |= _SECPROT_TLS1_1_SERVER
            enabled |= _SECPROT_TLS1_2_SERVER
        elseif minimum_tls_version == TlsVersion.TLSv1_1
            enabled |= _SECPROT_TLS1_1_SERVER
            enabled |= _SECPROT_TLS1_2_SERVER
        elseif minimum_tls_version == TlsVersion.TLSv1_2
            enabled |= _SECPROT_TLS1_2_SERVER
        elseif minimum_tls_version == TlsVersion.TLSv1_3
            throw_error(ERROR_IO_TLS_VERSION_UNSUPPORTED)
        else
            enabled = UInt32(0)
        end
    end

    return enabled
end

function _secure_channel_context_new(options::TlsContextOptions)::TlsContext
    @static if !Sys.iswindows()
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    if !tls_is_cipher_pref_supported(options.cipher_pref)
        throw_error(ERROR_IO_TLS_CIPHER_PREF_UNSUPPORTED)
    end

    ctx_impl = SecureChannelCtx(
        options.minimum_tls_version,
        options.alpn_list,
        options.verify_peer,
        UInt32(0),
        C_NULL,
        C_NULL,
        C_NULL,
        false,
        true,
    )

    success = false
    try
        flags = UInt32(0)

        if options.verify_peer && options.ca_file_set
            flags |= _SCH_CRED_MANUAL_CRED_VALIDATION
            ca_cursor = byte_cursor_from_buf(options.ca_file)
            ctx_impl.custom_trust_store = _secure_channel_import_trusted_certificates(ca_cursor)
        elseif !options.is_server
            flags |= _SCH_CRED_AUTO_CRED_VALIDATION
        end

        if !options.is_server && !options.verify_peer
            logf(
                LogLevel.WARN,
                LS_IO_TLS,
                "static: x.509 validation has been disabled. If this is not running in a test environment, this is likely a security vulnerability.",
            )
            flags &= ~_SCH_CRED_AUTO_CRED_VALIDATION
            flags |= _SCH_CRED_NO_SERVERNAME_CHECK
            flags |= _SCH_CRED_IGNORE_NO_REVOCATION_CHECK
            flags |= _SCH_CRED_IGNORE_REVOCATION_OFFLINE
            flags |= _SCH_CRED_MANUAL_CRED_VALIDATION
        elseif !options.is_server
            flags |= _SCH_CRED_REVOCATION_CHECK_CHAIN
            flags |= _SCH_CRED_IGNORE_REVOCATION_OFFLINE
        end

        flags |= _SCH_USE_STRONG_CRYPTO
        flags |= _SCH_CRED_NO_DEFAULT_CREDS

        # Certificate loading on Windows currently follows existing PKI helper behavior.
        if options.system_certificate_path !== nothing
            ctx_impl.cert_context = load_cert_from_system_cert_store(options.system_certificate_path)
            # `load_cert_from_system_cert_store()` binds cert-context -> store for later close.
            ctx_impl.cert_store = ctx_impl.cert_context
            ctx_impl.should_free_cert_context = true
        elseif options.certificate_set && options.private_key_set
            cert_cursor = byte_cursor_from_buf(options.certificate)
            key_cursor = byte_cursor_from_buf(options.private_key)
            if !_tls_text_is_ascii_or_utf8_bom(cert_cursor) || !_tls_text_is_ascii_or_utf8_bom(key_cursor)
                throw_error(ERROR_IO_FILE_VALIDATION_FAILURE)
            end
            ctx_impl.cert_context = import_key_pair_to_cert_context(cert_cursor, key_cursor; is_client_mode = !options.is_server)
            # `import_key_pair_to_cert_context()` binds cert-context -> store for later close.
            ctx_impl.cert_store = ctx_impl.cert_context
            # Windows key-container teardown can release the bound context; match aws-c-io
            # ownership and let store/key-handle cleanup own final release.
            ctx_impl.should_free_cert_context = false
        end

        ctx_impl.credential_flags = flags

        ctx = TlsContext(options, ctx_impl, false)
        finalizer(ctx) do c
            c.closed && return
            c.closed = true
            if c.impl isa SecureChannelCtx
                _secure_channel_ctx_destroy!(c.impl)
            end
        end

        success = true
        return ctx
    finally
        if !success
            try
                _secure_channel_ctx_destroy!(ctx_impl)
            catch
            end
        end
    end
end

function _secure_channel_ctx_destroy!(ctx::SecureChannelCtx)
    if ctx.custom_trust_store != C_NULL
        _secure_channel_close_cert_store(ctx.custom_trust_store)
        ctx.custom_trust_store = C_NULL
    end

    if ctx.cert_context != C_NULL && ctx.should_free_cert_context
        _ = ccall((:CertFreeCertificateContext, _CRYPT32_LIB), Int32, (Ptr{Cvoid},), ctx.cert_context)
        ctx.cert_context = C_NULL
    end

    if ctx.cert_store != C_NULL
        close_cert_store(ctx.cert_store)
        ctx.cert_store = C_NULL
    end
    ctx.cert_context = C_NULL

    ctx.alpn_list = nothing
    return nothing
end

function _secure_channel_handler_new(
        options::TlsConnectionOptions,
        slot::ChannelSlot,
        is_client_mode::Bool,
    )::SecureChannelTlsHandler
    @static if !Sys.iswindows()
        throw_error(ERROR_PLATFORM_NOT_SUPPORTED)
    end

    ctx = options.ctx
    sc_ctx = ctx.impl isa SecureChannelCtx ? (ctx.impl::SecureChannelCtx) : nothing
    sc_ctx === nothing && throw_error(ERROR_IO_TLS_CTX_ERROR)

    cert_contexts = nothing
    pa_cred = Ptr{Ptr{Cvoid}}(C_NULL)
    c_creds = UInt32(0)
    if sc_ctx.cert_context != C_NULL
        cert_contexts = Memory{Ptr{Cvoid}}(undef, 1)
        cert_contexts[1] = sc_ctx.cert_context
        pa_cred = pointer(cert_contexts)
        c_creds = UInt32(1)
    end

    creds_struct = _SCHANNEL_CRED(
        _SCHANNEL_CRED_VERSION,
        c_creds,
        pa_cred,
        C_NULL,
        0,
        C_NULL,
        0,
        C_NULL,
        _secure_channel_get_enabled_protocols(sc_ctx.minimum_tls_version, is_client_mode),
        0,
        0,
        0,
        sc_ctx.credential_flags,
        0,
    )

    cred_handle_ref = Ref(_zero_sechandle())
    ts_ref = Ref(_TimeStamp(0, 0))
    creds_struct_ref = Ref(creds_struct)

    cred_use = is_client_mode ? _SECPKG_CRED_OUTBOUND : _SECPKG_CRED_INBOUND
    status = GC.@preserve creds_struct_ref cert_contexts begin
        ccall(
            (:AcquireCredentialsHandleA, _SECUR32_LIB),
            Int32,
            (Cstring, Cstring, UInt32, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}, Ref{_CredHandle}, Ref{_TimeStamp}),
            C_NULL,
            _UNISP_NAME,
            cred_use,
            C_NULL,
            Base.unsafe_convert(Ptr{Cvoid}, creds_struct_ref),
            C_NULL,
            C_NULL,
            cred_handle_ref,
            ts_ref,
        )
    end
    if status != _SEC_E_OK
        throw_error(_secure_channel_determine_sspi_error(status))
    end

    handler = SecureChannelTlsHandler(
        slot,
        options.timeout_ms,
        TlsHandlerStatistics(),
        ChannelTask(),
        _zero_sechandle(),
        cred_handle_ref[],
        _SecPkgContextStreamSizes(0, 0, 0, 0, 0),
        0,
        0,
        null_buffer(),
        null_buffer(),
        ts_ref[],
        is_client_mode ? _SecureChannelConnectionState.CLIENT_NEGOTIATION_STEP_1 : _SecureChannelConnectionState.SERVER_NEGOTIATION_STEP_1,
        ByteBuffer(_SCHANNEL_READ_IN_SIZE + _SCHANNEL_EXTRA_HEADROOM),
        0,
        0,
        ByteBuffer(_SCHANNEL_READ_OUT_SIZE + _SCHANNEL_EXTRA_HEADROOM),
        options.tls_negotiation_result,
        options.on_data_read,
        options.alpn_list === nothing ? sc_ctx.alpn_list : options.alpn_list,
        options.advertise_alpn_message,
        false,
        false,
        sc_ctx.verify_peer,
        ChannelTask(),
        false,
        TlsHandlerReadState.OPEN,
        0,
        ChannelTask(),
        ctx,
        sc_ctx.custom_trust_store,
        is_client_mode,
        cert_contexts,
    )

    setfield!(handler.buffered_read_in, :len, Csize_t(0))
    setfield!(handler.buffered_read_out, :len, Csize_t(0))

    if options.server_name !== nothing
        handler.server_name = _secure_channel_byte_buf_from_string(options.server_name)
    end

    crt_statistics_tls_init!(handler.stats)
    channel_task_init!(handler.timeout_task, EventCallable(s -> _tls_timeout_task(handler, _coerce_task_status(s))), "tls_timeout")

    return handler
end

function _secure_channel_drive_negotiation(handler::SecureChannelTlsHandler)::Nothing
    _secure_channel_run_state(handler)
    return nothing
end

function _secure_channel_negotiation_task(handler::SecureChannelTlsHandler, status::TaskStatus.T)
    status == TaskStatus.RUN_READY || return nothing
    try
        _secure_channel_drive_negotiation(handler)
    catch e
        err = _secure_channel_error_code_from_exception(e, "negotiation_task")
        slot = handler.slot
        if slot !== nothing && channel_slot_is_attached(slot)
            channel_shutdown!(slot.channel, err)
        end
    end
    return nothing
end

function _secure_channel_process_pending_output_messages(handler::SecureChannelTlsHandler)::Nothing
    if handler.read_state == TlsHandlerReadState.SHUT_DOWN_COMPLETE
        return nothing
    end

    slot = handler.slot
    slot === nothing && return nothing
    channel_slot_is_attached(slot) || return nothing

    downstream_window = slot.adj_right === nothing ? SIZE_MAX : channel_slot_downstream_read_window(slot)
    error_code = 0

    while handler.buffered_read_out.len > 0 && downstream_window > 0
        requested = downstream_window == SIZE_MAX ?
            handler.buffered_read_out.len :
            min(handler.buffered_read_out.len, downstream_window)

        if slot.adj_right !== nothing
            read_out_msg = channel_acquire_message_from_pool(slot.channel, IoMessageType.APPLICATION_DATA, requested)
            read_out_msg === nothing && throw_error(ERROR_OOM)

            copy_size = min(Int(read_out_msg.message_data.capacity), Int(requested))
            unsafe_copyto!(pointer(read_out_msg.message_data.mem), pointer(handler.buffered_read_out.mem), copy_size)
            setfield!(read_out_msg.message_data, :len, Csize_t(copy_size))

            remaining = Int(handler.buffered_read_out.len) - copy_size
            if remaining > 0
                _secure_channel_memmove!(
                    pointer(handler.buffered_read_out.mem),
                    pointer(handler.buffered_read_out.mem) + copy_size,
                    Csize_t(remaining),
                )
            end
            setfield!(handler.buffered_read_out, :len, Csize_t(max(remaining, 0)))

            if handler.on_data_read !== nothing
                try
                    handler.on_data_read(handler, slot, read_out_msg.message_data)
                catch e
                    channel_release_message_to_pool!(slot.channel, read_out_msg)
                    error_code = _secure_channel_error_code_from_exception(e, "process_pending_output_on_data_read")
                    break
                end
            end

            try
                channel_slot_send_message(slot, read_out_msg, ChannelDirection.READ)
            catch e
                e isa ReseauError || rethrow()
                channel_release_message_to_pool!(slot.channel, read_out_msg)
                error_code = e.code
                break
            end

            downstream_window = slot.adj_right === nothing ? SIZE_MAX : channel_slot_downstream_read_window(slot)
        else
            if handler.on_data_read !== nothing
                try
                    handler.on_data_read(handler, slot, handler.buffered_read_out)
                catch e
                    error_code = _secure_channel_error_code_from_exception(e, "process_pending_output_terminal_on_data_read")
                    break
                end
            end
            setfield!(handler.buffered_read_out, :len, Csize_t(0))
        end
    end

    if handler.buffered_read_out.len == 0 && handler.read_state == TlsHandlerReadState.SHUTTING_DOWN
        handler.read_state = TlsHandlerReadState.SHUT_DOWN_COMPLETE
        shutdown_error = handler.shutdown_error_code != 0 ? handler.shutdown_error_code : error_code
        channel_slot_on_handler_shutdown_complete!(slot, ChannelDirection.READ, shutdown_error, false)
    end

    error_code != 0 && throw_error(error_code)

    return nothing
end

function _secure_channel_read_task(handler::SecureChannelTlsHandler, status::TaskStatus.T)
    status == TaskStatus.RUN_READY || return nothing
    handler.read_task_pending = false
    slot = handler.slot
    if slot !== nothing
        try
            _secure_channel_process_pending_output_messages(handler)
        catch e
            err = _secure_channel_error_code_from_exception(e, "read_task")
            channel_shutdown!(slot.channel, err)
        end
    end
    return nothing
end

function _secure_channel_initialize_read_delay_shutdown(handler::SecureChannelTlsHandler, slot::ChannelSlot, error_code::Int)
    logf(
        LogLevel.DEBUG,
        LS_IO_TLS,
        "TLS handler pending data during shutdown, waiting for downstream read window.",
    )
    if channel_slot_downstream_read_window(slot) == 0
        logf(
            LogLevel.WARN,
            LS_IO_TLS,
            "TLS shutdown delayed; pending data cannot be processed until read window opens.",
        )
    end

    handler.read_state = TlsHandlerReadState.SHUTTING_DOWN
    handler.shutdown_error_code = error_code

    if !handler.read_task_pending
        handler.read_task_pending = true
        channel_task_init!(handler.read_task, EventCallable(s -> _secure_channel_read_task(handler, _coerce_task_status(s))), "secure_channel_read_on_delay_shutdown")
        try
            channel_schedule_task_now!(slot.channel, handler.read_task)
        catch e
            handler.read_task_pending = false
            handler.read_state = TlsHandlerReadState.SHUT_DOWN_COMPLETE
            schedule_err = _secure_channel_error_code_from_exception(e, "initialize_read_delay_shutdown_schedule")
            shutdown_error = error_code != 0 ? error_code : schedule_err
            channel_slot_on_handler_shutdown_complete!(slot, ChannelDirection.READ, shutdown_error, false)
        end
    end

    return nothing
end

function handler_initial_window_size(handler::SecureChannelTlsHandler)::Csize_t
    _ = handler
    return Csize_t(TLS_EST_HANDSHAKE_SIZE)
end

function handler_message_overhead(handler::SecureChannelTlsHandler)::Csize_t
    _secure_channel_query_stream_sizes!(handler) || return Csize_t(TLS_EST_RECORD_OVERHEAD)
    return Csize_t(handler.stream_sizes.cbTrailer + handler.stream_sizes.cbHeader)
end

function handler_destroy(handler::SecureChannelTlsHandler)::Nothing
    if _sechandle_is_set(handler.sec_handle)
        sec_ref = Ref(handler.sec_handle)
        _ = ccall((:DeleteSecurityContext, _SECUR32_LIB), Int32, (Ref{_CtxtHandle},), sec_ref)
        handler.sec_handle = _zero_sechandle()
    end

    if _sechandle_is_set(handler.creds)
        creds_ref = Ref(handler.creds)
        _ = ccall((:FreeCredentialsHandle, _SECUR32_LIB), Int32, (Ref{_CredHandle},), creds_ref)
        handler.creds = _zero_sechandle()
    end

    handler.protocol = null_buffer()
    handler.server_name = null_buffer()
    handler.slot = nothing
    handler.ctx_obj = nothing
    handler.cert_contexts = nothing

    return nothing
end

function handler_reset_statistics(handler::SecureChannelTlsHandler)::Nothing
    crt_statistics_tls_reset!(handler.stats)
    return nothing
end

function handler_gather_statistics(handler::SecureChannelTlsHandler)
    return handler.stats
end

function handler_process_read_message(
        handler::SecureChannelTlsHandler,
        slot::ChannelSlot,
        message::Union{IoMessage, Nothing},
    )::Nothing
    if handler.read_state == TlsHandlerReadState.SHUT_DOWN_COMPLETE
        if message !== nothing && message.owning_channel isa Channel
            channel_release_message_to_pool!(message.owning_channel, message)
        end
        return nothing
    end

    if message === nothing
        _secure_channel_process_pending_output_messages(handler)
        return nothing
    end

    if handler.negotiation_failed
        throw_error(ERROR_IO_TLS_ERROR_NEGOTIATION_FAILURE)
    end

    msg = message
    cursor_ref = Ref(byte_cursor_from_buf(msg.message_data))

    while cursor_ref[].len > 0
        in_ref = Ref(handler.buffered_read_in)
        byte_buf_write_to_capacity(in_ref, cursor_ref)
        handler.buffered_read_in = in_ref[]

        record_incomplete = false
        try
            _secure_channel_run_state(handler)
        catch e
            e isa ReseauError || rethrow()
            if e.code == ERROR_IO_READ_WOULD_BLOCK
                record_incomplete = true
            else
                throw(e)
            end
        end

        if handler.buffered_read_out.len > 0
            _secure_channel_process_pending_output_messages(handler)
        end

        if record_incomplete
            if handler.buffered_read_in.len == handler.buffered_read_in.capacity
                throw_error(ERROR_IO_TLS_ERROR_WRITE_FAILURE)
            end

            downstream_window = slot.adj_right === nothing ? SIZE_MAX : channel_slot_downstream_read_window(slot)
            if downstream_window > 0 && slot.window_size == 0
                channel_slot_increment_read_window!(slot, handler.estimated_incomplete_size)
            end
        else
            if handler.read_extra > 0
                move_pos = handler.buffered_read_in.len - handler.read_extra
                _secure_channel_memmove!(
                    pointer(handler.buffered_read_in.mem),
                    pointer(handler.buffered_read_in.mem) + Int(move_pos),
                    handler.read_extra,
                )
                setfield!(handler.buffered_read_in, :len, handler.read_extra)
                handler.read_extra = 0
            else
                setfield!(handler.buffered_read_in, :len, Csize_t(0))
            end
        end
    end

    channel_release_message_to_pool!(slot.channel, msg)
    return nothing
end

function handler_process_read_message(handler::SecureChannelTlsHandler, slot::ChannelSlot, message::IoMessage)::Nothing
    try
        invoke(
            handler_process_read_message,
            Tuple{SecureChannelTlsHandler, ChannelSlot, Union{IoMessage, Nothing}},
            handler,
            slot,
            message,
        )
    catch e
        err = _secure_channel_error_code_from_exception(e, "handler_process_read_message")
        channel_shutdown!(slot.channel, err)
    end
    return nothing
end

function handler_process_write_message(
        handler::SecureChannelTlsHandler,
        slot::ChannelSlot,
        message::IoMessage,
    )::Nothing
    handler.negotiation_finished || throw_error(ERROR_IO_TLS_ERROR_NOT_NEGOTIATED)
    _secure_channel_query_stream_sizes!(handler) || throw_error(ERROR_IO_TLS_ERROR_WRITE_FAILURE)

    cursor_ref = Ref(byte_cursor_from_buf(message.message_data))

    while cursor_ref[].len > 0
        upstream_overhead = channel_slot_upstream_message_overhead(slot) +
            Csize_t(handler.stream_sizes.cbHeader + handler.stream_sizes.cbTrailer)

        requested = Int(cursor_ref[].len) + Int(upstream_overhead)
        to_write = handler.stream_sizes.cbMaximumMessage < requested ?
            Int(handler.stream_sizes.cbMaximumMessage) :
            requested

        outgoing = channel_acquire_message_from_pool(slot.channel, IoMessageType.APPLICATION_DATA, to_write)
        outgoing === nothing && throw_error(ERROR_OOM)

        if outgoing.message_data.capacity <= upstream_overhead
            channel_release_message_to_pool!(slot.channel, outgoing)
            throw_error(ERROR_INVALID_STATE)
        end

        fragment_len = min(Int(outgoing.message_data.capacity - upstream_overhead), Int(cursor_ref[].len))

        unsafe_copyto!(
            pointer(outgoing.message_data.mem) + Int(handler.stream_sizes.cbHeader),
            _cursor_ptr(cursor_ref[]),
            fragment_len,
        )

        if fragment_len == Int(cursor_ref[].len)
            outgoing.on_completion = message.on_completion
        end

        sec_buffers = _SecBuffer[
            _SecBuffer(handler.stream_sizes.cbHeader, _SECBUFFER_STREAM_HEADER, pointer(outgoing.message_data.mem)),
            _SecBuffer(UInt32(fragment_len), _SECBUFFER_DATA, pointer(outgoing.message_data.mem) + Int(handler.stream_sizes.cbHeader)),
            _SecBuffer(
                handler.stream_sizes.cbTrailer,
                _SECBUFFER_STREAM_TRAILER,
                pointer(outgoing.message_data.mem) + Int(handler.stream_sizes.cbHeader) + fragment_len,
            ),
            _SecBuffer(0, _SECBUFFER_EMPTY, C_NULL),
        ]

        sec_desc = Ref(_SecBufferDesc(_SECBUFFER_VERSION, UInt32(length(sec_buffers)), pointer(sec_buffers)))

        sec_ref = Ref(handler.sec_handle)
        status = GC.@preserve sec_buffers sec_desc begin
            ccall(
                (:EncryptMessage, _SECUR32_LIB),
                Int32,
                (Ref{_CtxtHandle}, UInt32, Ref{_SecBufferDesc}, UInt32),
                sec_ref,
                0,
                sec_desc,
                0,
            )
        end

        if status != _SEC_E_OK
            channel_release_message_to_pool!(slot.channel, outgoing)
            throw_error(ERROR_IO_TLS_ERROR_WRITE_FAILURE)
        end

        total_len = sec_buffers[1].cbBuffer + sec_buffers[2].cbBuffer + sec_buffers[3].cbBuffer
        setfield!(outgoing.message_data, :len, Csize_t(total_len))

        try
            channel_slot_send_message(slot, outgoing, ChannelDirection.WRITE)
        catch e
            e isa ReseauError || rethrow()
            channel_release_message_to_pool!(slot.channel, outgoing)
            throw(e)
        end

        _ = byte_cursor_advance(cursor_ref, fragment_len)
    end

    channel_release_message_to_pool!(slot.channel, message)
    return nothing
end

function handler_increment_read_window(
        handler::SecureChannelTlsHandler,
        slot::ChannelSlot,
        size::Csize_t,
    )::Nothing
    if handler.read_state == TlsHandlerReadState.SHUT_DOWN_COMPLETE
        return nothing
    end

    if handler.negotiation_finished && handler.stream_sizes.cbMaximumMessage == 0
        if !_secure_channel_query_stream_sizes!(handler)
            channel_shutdown!(slot.channel, ERROR_SYS_CALL_FAILURE)
            throw_error(ERROR_SYS_CALL_FAILURE)
        end
    end

    total_desired = size
    downstream_size = channel_slot_downstream_read_window(slot)
    current_window = slot.window_size

    if handler.stream_sizes.cbMaximumMessage > 0
        likely_records = downstream_size == 0 ? Csize_t(0) : Csize_t(ceil(downstream_size / Csize_t(_SCHANNEL_READ_IN_SIZE)))
        offset_size = mul_size_saturating(likely_records, Csize_t(handler.stream_sizes.cbTrailer + handler.stream_sizes.cbHeader))
        total_desired = add_size_saturating(offset_size, downstream_size)
    end

    if total_desired > current_window
        channel_slot_increment_read_window!(slot, total_desired - current_window)
    end

    if handler.negotiation_finished && !handler.read_task_pending
        handler.read_task_pending = true
        channel_task_init!(handler.read_task, EventCallable(s -> _secure_channel_read_task(handler, _coerce_task_status(s))), "secure_channel_process_pending_output_on_window_increment")
        channel_schedule_task_now!(slot.channel, handler.read_task)
    end

    return nothing
end

function handler_shutdown(
        handler::SecureChannelTlsHandler,
        slot::ChannelSlot,
        direction::ChannelDirection.T,
        error_code::Int,
        free_scarce_resources_immediately::Bool,
    )::Nothing
    abort_immediately = free_scarce_resources_immediately

    if direction == ChannelDirection.READ
        if !handler.negotiation_finished
            _secure_channel_fail_pending_negotiation!(handler, error_code)
        end
        if !abort_immediately &&
                handler.negotiation_finished &&
                handler.buffered_read_out.len > 0 &&
                slot.adj_right !== nothing
            _secure_channel_initialize_read_delay_shutdown(handler, slot, error_code)
            return nothing
        end
        handler.read_state = TlsHandlerReadState.SHUT_DOWN_COMPLETE
    else
        if !abort_immediately && error_code != ERROR_IO_SOCKET_CLOSED
            shutdown_code = Ref{UInt32}(_SCHANNEL_SHUTDOWN)
            shutdown_ref = Ref(_SecBuffer(UInt32(sizeof(UInt32)), _SECBUFFER_TOKEN, Base.unsafe_convert(Ptr{Cvoid}, shutdown_code)))
            shutdown_desc = Ref(_SecBufferDesc(_SECBUFFER_VERSION, UInt32(1), Base.unsafe_convert(Ptr{_SecBuffer}, shutdown_ref)))

            sec_ref = Ref(handler.sec_handle)
            status = ccall(
                (:ApplyControlToken, _SECUR32_LIB),
                Int32,
                (Ref{_CtxtHandle}, Ref{_SecBufferDesc}),
                sec_ref,
                shutdown_desc,
            )

            if status != _SEC_E_OK
                error_code = ERROR_SYS_CALL_FAILURE
            else
                output_ref = Ref(_SecBuffer(0, _SECBUFFER_TOKEN, C_NULL))
                output_desc = Ref(_SecBufferDesc(_SECBUFFER_VERSION, UInt32(1), Base.unsafe_convert(Ptr{_SecBuffer}, output_ref)))

                server_name_cstr = _secure_channel_server_name_cstring(handler)
                creds_ref = Ref(handler.creds)
                ctx_ret_ref = Ref(handler.ctx_ret_flags)

                status = GC.@preserve output_ref output_desc server_name_cstr ctx_ret_ref begin
                    ccall(
                        (:InitializeSecurityContextA, _SECUR32_LIB),
                        Int32,
                        (Ref{_CredHandle}, Ref{_CtxtHandle}, Cstring, UInt32, UInt32, UInt32, Ptr{_SecBufferDesc}, UInt32, Ptr{_CtxtHandle}, Ref{_SecBufferDesc}, Ref{UInt32}, Ptr{Cvoid}),
                        creds_ref,
                        sec_ref,
                        pointer(server_name_cstr),
                        handler.ctx_req,
                        0,
                        0,
                        C_NULL,
                        0,
                        C_NULL,
                        output_desc,
                        ctx_ret_ref,
                        C_NULL,
                    )
                end
                handler.ctx_ret_flags = ctx_ret_ref[]
                output_buffer = output_ref[]

                if status == _SEC_E_OK || status == _SEC_I_CONTEXT_EXPIRED
                    try
                        _secure_channel_send_token_message(handler, output_buffer.pvBuffer, output_buffer.cbBuffer)
                    catch
                        # best effort; ignore alert-send failures
                    end
                end

                if output_buffer.pvBuffer != C_NULL
                    _ = ccall((:FreeContextBuffer, _SECUR32_LIB), Int32, (Ptr{Cvoid},), output_buffer.pvBuffer)
                end
            end
        end
    end

    channel_slot_on_handler_shutdown_complete!(slot, direction, error_code, abort_immediately)
    return nothing
end

function _secure_channel_is_alpn_available()::Bool
    @static if Sys.iswindows()
        # ALPN on SChannel requires Windows 8.1+/Server 2012 R2+.
        if isdefined(Sys, :windows_version)
            v = Sys.windows_version()
            return (v.major > 6) || (v.major == 6 && v.minor >= 3)
        end
        return true
    else
        return false
    end
end
