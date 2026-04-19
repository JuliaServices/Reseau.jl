const _TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC = UInt8(20)
const _TLS_RECORD_TYPE_ALERT = UInt8(21)
const _TLS_RECORD_TYPE_HANDSHAKE = UInt8(22)
const _TLS_RECORD_TYPE_APPLICATION_DATA = UInt8(23)

const _TLS_ALERT_LEVEL_WARNING = UInt8(1)
const _TLS_ALERT_LEVEL_FATAL = UInt8(2)
const _TLS_ALERT_CLOSE_NOTIFY = UInt8(0)
const _TLS_ALERT_UNEXPECTED_MESSAGE = UInt8(10)
const _TLS_ALERT_BAD_RECORD_MAC = UInt8(20)
const _TLS_ALERT_HANDSHAKE_FAILURE = UInt8(40)
const _TLS_ALERT_BAD_CERTIFICATE = UInt8(42)
const _TLS_ALERT_ILLEGAL_PARAMETER = UInt8(47)
const _TLS_ALERT_DECODE_ERROR = UInt8(50)
const _TLS_ALERT_DECRYPT_ERROR = UInt8(51)
const _TLS_ALERT_PROTOCOL_VERSION = UInt8(70)
const _TLS_ALERT_INTERNAL_ERROR = UInt8(80)
const _TLS_ALERT_CERTIFICATE_REQUIRED = UInt8(116)

"""
    _TLSAlertError

Internal protocol-error carrier used by the native record and handshake layers.

`alert` is the wire alert description that should be emitted or has already been
observed, and `from_peer` distinguishes locally-detected protocol violations
from alerts received off the wire.
"""
struct _TLSAlertError <: Exception
    message::String
    alert::UInt8
    from_peer::Bool
end

Base.showerror(io::IO, err::_TLSAlertError) = print(io, err.message)

@inline _tls_protocol_error(alert::UInt8, message::AbstractString) = _TLSAlertError(String(message), alert, false)
@inline _tls_peer_alert_error(alert::UInt8, message::AbstractString) = _TLSAlertError(String(message), alert, true)
@inline _tls_fail(alert::UInt8, message::AbstractString)::Union{} = throw(_tls_protocol_error(alert, message))

@inline function _tls_buffer_available(buf::Vector{UInt8}, pos::Int)::Int
    return max(0, length(buf) - pos + 1)
end

# Both TLS 1.2 and TLS 1.3 use simple owned vectors for buffered handshake and
# plaintext bytes. Compacting in place keeps the hot path allocation-light while
# still giving the protocol code view-like semantics over "remaining bytes".
function _tls_compact_buffer!(buf::Vector{UInt8}, pos::Int)::Int
    pos <= 1 && return 1
    if pos > length(buf)
        empty!(buf)
        return 1
    end
    remaining = length(buf) - pos + 1
    copyto!(buf, 1, buf, pos, remaining)
    resize!(buf, remaining)
    return 1
end

# Used only before a record cipher is installed or for compatibility records
# like TLS 1.2 ChangeCipherSpec. Once handshake/application keys are live, the
# version-specific record files own framing and AEAD processing.
function _tls_write_tls_plaintext!(tcp::TCP.Conn, content_type::UInt8, payload::AbstractVector{UInt8}, record_version::UInt16 = _TLS_LEGACY_RECORD_VERSION)::Nothing
    header = UInt8[
        content_type,
        UInt8(record_version >> 8),
        UInt8(record_version & 0xff),
        UInt8(length(payload) >> 8),
        UInt8(length(payload) & 0xff),
    ]
    try
        write(tcp, header)
        isempty(payload) || write(tcp, payload)
    finally
        _securezero!(header)
    end
    return nothing
end
