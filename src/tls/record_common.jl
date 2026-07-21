const _TLS_RECORD_TYPE_CHANGE_CIPHER_SPEC = UInt8(20)
const _TLS_RECORD_TYPE_ALERT = UInt8(21)
const _TLS_RECORD_TYPE_HANDSHAKE = UInt8(22)
const _TLS_RECORD_TYPE_APPLICATION_DATA = UInt8(23)

const _TLS_ALERT_LEVEL_WARNING = UInt8(1)
const _TLS_ALERT_LEVEL_FATAL = UInt8(2)
const _TLS_ALERT_CLOSE_NOTIFY = UInt8(0)
const _TLS_ALERT_UNEXPECTED_MESSAGE = UInt8(10)
const _TLS_ALERT_BAD_RECORD_MAC = UInt8(20)
const _TLS_ALERT_RECORD_OVERFLOW = UInt8(22)
const _TLS_ALERT_HANDSHAKE_FAILURE = UInt8(40)
const _TLS_ALERT_BAD_CERTIFICATE = UInt8(42)
const _TLS_ALERT_ILLEGAL_PARAMETER = UInt8(47)
const _TLS_ALERT_DECODE_ERROR = UInt8(50)
const _TLS_ALERT_DECRYPT_ERROR = UInt8(51)
const _TLS_ALERT_PROTOCOL_VERSION = UInt8(70)
const _TLS_ALERT_INTERNAL_ERROR = UInt8(80)
const _TLS_ALERT_INAPPROPRIATE_FALLBACK = UInt8(86)
const _TLS_ALERT_USER_CANCELED = UInt8(90)
const _TLS_ALERT_UNSUPPORTED_EXTENSION = UInt8(110)
const _TLS_ALERT_NO_APPLICATION_PROTOCOL = UInt8(120)
const _TLS_ALERT_CERTIFICATE_REQUIRED = UInt8(116)

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

# A transport EOF is compatible with Go's TLS behavior only before any bytes of
# a new record have arrived. Once a header or announced payload is partial, the
# peer truncated the TLS framing and callers must not mistake that for a clean
# record-boundary close.
struct _TLSUnexpectedEOFError <: Exception end

Base.showerror(io::IO, ::_TLSUnexpectedEOFError) = print(io, "unexpected EOF")

# The first record can fail Go's pre-negotiation plausibility checks without
# generating a TLS alert, because the bytes might not be TLS at all. Keep that
# distinct from negotiated protocol violations, which do emit an alert.
struct _TLSRecordHeaderError <: Exception
    message::String
end

Base.showerror(io::IO, err::_TLSRecordHeaderError) = print(io, err.message)

const _TLS_IO_READ = UInt8(1)
const _TLS_IO_WRITE = UInt8(2)

struct _TLSTransportDeadlineError <: Exception
    direction::UInt8
    cause::IOPoll.DeadlineExceededError
end

Base.showerror(io::IO, err::_TLSTransportDeadlineError) = showerror(io, err.cause)

struct _TLSHandshakeDeadlineError <: Exception
    handshake_owned::Bool
    cause::IOPoll.DeadlineExceededError
end

Base.showerror(io::IO, err::_TLSHandshakeDeadlineError) = showerror(io, err.cause)

@inline _tls_protocol_error(alert::UInt8, message::AbstractString) = _TLSAlertError(String(message), alert, false)
@inline _tls_peer_alert_error(alert::UInt8, message::AbstractString) = _TLSAlertError(String(message), alert, true)
@inline _tls_fail(alert::UInt8, message::AbstractString)::Union{} = throw(_tls_protocol_error(alert, message))

# Detached handshake-state tests and alternate handshake adapters intentionally
# do not own a wire record layer. Concrete TCP record adapters specialize this
# hook to record the selected protocol version.
@inline _tls_set_negotiated_record_version!(io, ::UInt16)::Nothing = nothing

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
        _tls_write_transport!(tcp, header)
        isempty(payload) || _tls_write_transport!(tcp, payload)
    finally
        _securezero!(header)
    end
    return nothing
end

function _tls_write_transport!(tcp::TCP.Conn, payload::AbstractVector{UInt8})::Nothing
    try
        write(tcp, payload)
    catch err
        err isa IOPoll.DeadlineExceededError &&
            throw(_TLSTransportDeadlineError(_TLS_IO_WRITE, err))
        rethrow()
    end
    return nothing
end

function _tls_read_record_bytes!(
        tcp::TCP.Conn,
        ptr::Ptr{UInt8},
        nbytes::Int,
        allow_boundary_eof::Bool,
    )::Nothing
    offset = 0
    while offset < nbytes
        n = try
            TCP._read_some!(tcp, ptr + offset, nbytes - offset)
        catch err
            err isa IOPoll.DeadlineExceededError &&
                throw(_TLSTransportDeadlineError(_TLS_IO_READ, err))
            if err isa EOFError
                allow_boundary_eof && offset == 0 && rethrow()
                throw(_TLSUnexpectedEOFError())
            end
            rethrow()
        end
        # Stream TCP reads throw EOFError for a zero-byte peer close, but keep
        # this helper correct for any future transport with Reader-like zero
        # progress semantics.
        if n == 0
            allow_boundary_eof && offset == 0 && throw(EOFError())
            throw(_TLSUnexpectedEOFError())
        end
        offset += n
    end
    return nothing
end

@inline function _tls_wire_record_version(negotiated_version::UInt16)::UInt16
    negotiated_version == UInt16(0) && return _TLS_LEGACY_RECORD_VERSION
    negotiated_version == TLS1_3_VERSION && return TLS1_2_VERSION
    return negotiated_version
end

function _tls_validate_record_header!(record_buffer::Vector{UInt8}, negotiated_version::UInt16)::Nothing
    content_type = record_buffer[1]
    record_version = (UInt16(record_buffer[2]) << 8) | UInt16(record_buffer[3])
    if negotiated_version == UInt16(0)
        content_type == 0x80 && _tls_fail(_TLS_ALERT_PROTOCOL_VERSION, "tls: unsupported SSLv2 handshake received")
        if (content_type != _TLS_RECORD_TYPE_ALERT && content_type != _TLS_RECORD_TYPE_HANDSHAKE) ||
           record_version >= UInt16(0x1000)
            throw(_TLSRecordHeaderError("tls: first record does not look like a TLS handshake"))
        end
        return nothing
    end
    expected_version = _tls_wire_record_version(negotiated_version)
    record_version == expected_version || _tls_fail(
        _TLS_ALERT_PROTOCOL_VERSION,
        "tls: received record with version $(string(record_version; base = 16)) when expecting version $(string(expected_version; base = 16))",
    )
    return nothing
end

function _tls_read_wire_record!(
        tcp::TCP.Conn,
        record_buffer::Vector{UInt8},
        max_ciphertext::Int,
        negotiated_version::UInt16,
    )::Int
    resize!(record_buffer, 5)
    GC.@preserve record_buffer _tls_read_record_bytes!(tcp, pointer(record_buffer), 5, true)
    _tls_validate_record_header!(record_buffer, negotiated_version)
    payload_len = (Int(record_buffer[4]) << 8) | Int(record_buffer[5])
    payload_len <= max_ciphertext || _tls_fail(_TLS_ALERT_RECORD_OVERFLOW, "tls: received oversized TLS record")
    resize!(record_buffer, 5 + payload_len)
    if payload_len != 0
        GC.@preserve record_buffer _tls_read_record_bytes!(tcp, pointer(record_buffer, 6), payload_len, false)
    end
    return payload_len
end
