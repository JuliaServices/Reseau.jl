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
const _TLS_ALERT_NO_APPLICATION_PROTOCOL = UInt8(120)
const _TLS_ALERT_CERTIFICATE_REQUIRED = UInt8(116)

# Symbolic names for TLS alert descriptions (RFC 8446 §6, RFC 5246 §7.2).
# Used when surfacing peer alerts so error messages name the alert instead of
# leaving callers to decode raw numerics.
@inline function _tls_alert_name(alert::UInt8)::String
    alert == 0   && return "close_notify"
    alert == 10  && return "unexpected_message"
    alert == 20  && return "bad_record_mac"
    alert == 21  && return "decryption_failed"
    alert == 22  && return "record_overflow"
    alert == 30  && return "decompression_failure"
    alert == 40  && return "handshake_failure"
    alert == 41  && return "no_certificate"
    alert == 42  && return "bad_certificate"
    alert == 43  && return "unsupported_certificate"
    alert == 44  && return "certificate_revoked"
    alert == 45  && return "certificate_expired"
    alert == 46  && return "certificate_unknown"
    alert == 47  && return "illegal_parameter"
    alert == 48  && return "unknown_ca"
    alert == 49  && return "access_denied"
    alert == 50  && return "decode_error"
    alert == 51  && return "decrypt_error"
    alert == 60  && return "export_restriction"
    alert == 70  && return "protocol_version"
    alert == 71  && return "insufficient_security"
    alert == 80  && return "internal_error"
    alert == 86  && return "inappropriate_fallback"
    alert == 90  && return "user_canceled"
    alert == 100 && return "no_renegotiation"
    alert == 109 && return "missing_extension"
    alert == 110 && return "unsupported_extension"
    alert == 112 && return "unrecognized_name"
    alert == 113 && return "bad_certificate_status_response"
    alert == 115 && return "unknown_psk_identity"
    alert == 116 && return "certificate_required"
    alert == 120 && return "no_application_protocol"
    return "unknown"
end

const _TLS_MAX_USELESS_RECORDS = 16

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

@inline function _tls_reset_useless_record_count!(state)::Nothing
    state.useless_record_count = 0
    return nothing
end

@inline function _tls_note_useless_record!(state, message::AbstractString)::Nothing
    state.useless_record_count += 1
    state.useless_record_count <= _TLS_MAX_USELESS_RECORDS ||
        _tls_fail(_TLS_ALERT_UNEXPECTED_MESSAGE, message)
    return nothing
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

function _tls_read_wire_record!(tcp::TCP.Conn, record_buffer::Vector{UInt8}, max_ciphertext::Int)::Int
    resize!(record_buffer, 5)
    GC.@preserve record_buffer Base.unsafe_read(tcp, pointer(record_buffer), UInt(5))
    payload_len = (Int(record_buffer[4]) << 8) | Int(record_buffer[5])
    payload_len <= max_ciphertext || _tls_fail(_TLS_ALERT_DECODE_ERROR, "tls: received oversized TLS record")
    resize!(record_buffer, 5 + payload_len)
    if payload_len != 0
        GC.@preserve record_buffer Base.unsafe_read(tcp, pointer(record_buffer, 6), UInt(payload_len))
    end
    return payload_len
end
