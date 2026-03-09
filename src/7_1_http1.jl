# HTTP/1.1 parser and serializer primitives used by client and server stacks.
export read_request
export write_request!
export write_response!
export trailers
export FixedLengthBody
export ChunkedBody
export EOFBody

const _HTTP1_DEFAULT_MAX_LINE_BYTES = 8 * 1024
const _HTTP1_DEFAULT_MAX_HEADER_BYTES = 1 * 1024 * 1024

"""
    FixedLengthBody

HTTP/1 body reader for a known `Content-Length`.

Reads are bounded strictly by `remaining`; once the counter reaches zero the
body reports EOF even if more bytes are available on the underlying stream.
"""
mutable struct FixedLengthBody{I <: IO} <: AbstractBody
    io::I
    remaining::Int64
    @atomic closed::Bool
end

"""
    ChunkedBody

HTTP/1 body reader for `Transfer-Encoding: chunked`.

This reader owns the chunk parser state. It lazily advances from chunk-size
line to chunk payload to trailing CRLF, and after the terminal zero-sized chunk
it parses trailer headers into `trailers`.
"""
mutable struct ChunkedBody{I <: IO} <: AbstractBody
    io::I
    chunk_remaining::Int64
    done::Bool
    trailers::Headers
    max_line_bytes::Int
    max_header_bytes::Int
    @atomic closed::Bool
end

"""
    EOFBody

HTTP/1 body reader that consumes until EOF (typically response bodies without
length/chunk framing on non-keepalive connections).

Because EOF is the framing signal, these bodies generally imply that the
connection cannot be safely reused afterwards.
"""
mutable struct EOFBody{I <: IO} <: AbstractBody
    io::I
    @atomic closed::Bool
end

"""
    FixedLengthBody(io, remaining)

Create a fixed-length HTTP/1 body reader with `remaining` bytes available.
"""
function FixedLengthBody(io::I, remaining::Integer) where {I <: IO}
    remaining < 0 && throw(ArgumentError("remaining must be >= 0"))
    return FixedLengthBody(io, Int64(remaining), false)
end

"""
    ChunkedBody(io; max_line_bytes=..., max_header_bytes=...)

Create a chunked body reader with parser limits.

Throws `ArgumentError` when either limit is non-positive. The returned reader
converts malformed chunk syntax and trailer overflows into `ParseError` or
`ProtocolError`.
"""
function ChunkedBody(io::I; max_line_bytes::Integer = _HTTP1_DEFAULT_MAX_LINE_BYTES, max_header_bytes::Integer = _HTTP1_DEFAULT_MAX_HEADER_BYTES) where {I <: IO}
    max_line_bytes <= 0 && throw(ArgumentError("max_line_bytes must be > 0"))
    max_header_bytes <= 0 && throw(ArgumentError("max_header_bytes must be > 0"))
    return ChunkedBody(io, 0, false, Headers(), Int(max_line_bytes), Int(max_header_bytes), false)
end

"""
    EOFBody(io)

Create an EOF-terminated body reader.
"""
function EOFBody(io::I) where {I <: IO}
    return EOFBody(io, false)
end

function body_closed(body::FixedLengthBody)::Bool
    return @atomic :acquire body.closed
end

function body_closed(body::ChunkedBody)::Bool
    return @atomic :acquire body.closed
end

function body_closed(body::EOFBody)::Bool
    return @atomic :acquire body.closed
end

function body_close!(body::FixedLengthBody)
    @atomic :release body.closed = true
    return nothing
end

function body_close!(body::ChunkedBody)
    @atomic :release body.closed = true
    return nothing
end

function body_close!(body::EOFBody)
    @atomic :release body.closed = true
    return nothing
end

"""
    trailers(body)

Return parsed trailer headers for a chunked body; empty headers for other body
types.

The returned `Headers` object is copied so callers can inspect or mutate it
without racing the body reader.
"""
function trailers(body::ChunkedBody)::Headers
    return copy(body.trailers)
end

function trailers(::AbstractBody)::Headers
    return Headers()
end

@inline function _read_u8(io::IO)::UInt8
    try
        return read(io, UInt8)
    catch err
        err isa EOFError && throw(ParseError("unexpected EOF while reading HTTP/1 data"))
        rethrow(err)
    end
end

function _readline_crlf(io::IO, max_line_bytes::Integer)::String
    max_line_bytes <= 0 && throw(ArgumentError("max_line_bytes must be > 0"))
    bytes = UInt8[]
    while true
        b = _read_u8(io)
        push!(bytes, b)
        length(bytes) > max_line_bytes && throw(ProtocolError("HTTP/1 line exceeds configured max_line_bytes"))
        n = length(bytes)
        if n >= 2 && bytes[n - 1] == 0x0d && bytes[n] == 0x0a
            resize!(bytes, n - 2)
            return String(bytes)
        end
    end
end

"""
Approximate number of header keys available in the current buffered chunk.
Specialized readers can override this to enable better preallocation.
"""
function _upcoming_header_keys(io::IO)::Int
    _ = io
    return 0
end

function _read_headers(io::IO, max_line_bytes::Integer, max_header_bytes::Integer)::Headers
    max_header_bytes <= 0 && throw(ArgumentError("max_header_bytes must be > 0"))
    headers = Headers(_upcoming_header_keys(io))
    consumed = 0
    while true
        line = _readline_crlf(io, max_line_bytes)
        consumed += ncodeunits(line) + 2
        consumed > max_header_bytes && throw(ProtocolError("HTTP/1 headers exceed configured max_header_bytes"))
        isempty(line) && return headers
        sep = findfirst(':', line)
        sep === nothing && throw(ParseError("malformed HTTP/1 header line (missing ':'): $(repr(line))"))
        key = String(SubString(line, firstindex(line), prevind(line, sep)))
        isempty(_trim_http_ows(key)) && throw(ParseError("malformed HTTP/1 header line (empty key)"))
        value = _trim_http_ows(SubString(line, nextind(line, sep), lastindex(line)))
        add_header!(headers, key, value)
    end
end

function _parse_http_version(version::AbstractString)::Tuple{UInt8, UInt8}
    startswith(version, "HTTP/") || throw(ParseError("invalid HTTP version token: $(repr(version))"))
    parts = split(String(SubString(version, 6)), '.'; limit = 2)
    length(parts) == 2 || throw(ParseError("invalid HTTP version token: $(repr(version))"))
    major = try
        parse(Int, parts[1])
    catch
        throw(ParseError("invalid HTTP major version: $(repr(version))"))
    end
    minor = try
        parse(Int, parts[2])
    catch
        throw(ParseError("invalid HTTP minor version: $(repr(version))"))
    end
    (major < 0 || major > typemax(UInt8)) && throw(ParseError("invalid HTTP major version: $(repr(version))"))
    (minor < 0 || minor > typemax(UInt8)) && throw(ParseError("invalid HTTP minor version: $(repr(version))"))
    return UInt8(major), UInt8(minor)
end

function _parse_content_length(headers::Headers)::Int64
    values = get_headers(headers, "Content-Length")
    isempty(values) && return Int64(-1)
    parsed = Int64(-1)
    for value in values
        trimmed = _trim_http_ows(value)
        isempty(trimmed) && throw(ParseError("empty Content-Length header value"))
        n = try
            parse(Int64, trimmed)
        catch
            throw(ParseError("invalid Content-Length header value: $(repr(value))"))
        end
        n < 0 && throw(ParseError("negative Content-Length header value"))
        if parsed == Int64(-1)
            parsed = n
            continue
        end
        parsed == n || throw(ProtocolError("mismatched Content-Length header values"))
    end
    return parsed
end

function _should_close_connection(headers::Headers, proto_major::UInt8, proto_minor::UInt8)::Bool
    if proto_major == UInt8(1) && proto_minor == UInt8(0)
        return !has_header_token(headers, "Connection", "keep-alive")
    end
    return has_header_token(headers, "Connection", "close")
end

function _body_allowed_for_status(status_code::Integer)::Bool
    status_code < 100 && return true
    (100 <= status_code < 200) && return false
    status_code == 204 && return false
    status_code == 304 && return false
    return true
end

function _read_exact!(io::IO, dst::Vector{UInt8}, nbytes::Integer)::Int
    nbytes < 0 && throw(ArgumentError("nbytes must be >= 0"))
    nbytes == 0 && return 0
    nbytes <= length(dst) || throw(ArgumentError("nbytes must be <= destination length"))
    try
        n = readbytes!(io, dst, Int(nbytes))
        return n
    catch err
        err isa EOFError && throw(ParseError("unexpected EOF while reading HTTP/1 body"))
        rethrow(err)
    end
end

function _consume_crlf(io::IO)
    b1 = _read_u8(io)
    b2 = _read_u8(io)
    (b1 == 0x0d && b2 == 0x0a) || throw(ParseError("expected CRLF terminator in chunked body"))
    return nothing
end

function _parse_chunk_size(line::AbstractString)::Int64
    trimmed = _trim_http_ows(line)
    isempty(trimmed) && throw(ParseError("empty chunk size line"))
    semi = findfirst(';', trimmed)
    token = semi === nothing ? trimmed : String(SubString(trimmed, firstindex(trimmed), prevind(trimmed, semi)))
    token = _trim_http_ows(token)
    isempty(token) && throw(ParseError("empty chunk size"))
    size = try
        parse(Int64, token; base = 16)
    catch
        throw(ParseError("invalid chunk size: $(repr(line))"))
    end
    size < 0 && throw(ParseError("negative chunk size"))
    return size
end

function _read_next_chunk!(body::ChunkedBody)
    body.done && return nothing
    # Chunked framing is a tiny state machine: parse the next size line, switch
    # into payload-reading mode, and after a zero-sized chunk parse trailers
    # instead of more body bytes.
    line = _readline_crlf(body.io, body.max_line_bytes)
    size = _parse_chunk_size(line)
    if size == 0
        # Terminal chunk: trailing header block is parsed as trailers.
        parsed_trailers = _read_headers(body.io, body.max_line_bytes, body.max_header_bytes)
        empty!(body.trailers)
        for key in header_keys(parsed_trailers)
            values = get_headers(parsed_trailers, key)
            for value in values
                add_header!(body.trailers, key, value)
            end
        end
        body.done = true
        body.chunk_remaining = 0
        return nothing
    end
    body.chunk_remaining = size
    return nothing
end

function body_read!(body::FixedLengthBody, dst::Vector{UInt8})::Int
    body_closed(body) && return 0
    isempty(dst) && return 0
    body.remaining <= 0 && return 0
    to_read = min(Int64(length(dst)), body.remaining)
    n = _read_exact!(body.io, dst, to_read)
    n == to_read || throw(ParseError("truncated fixed-length HTTP/1 body"))
    body.remaining -= n
    return n
end

function body_read!(body::EOFBody, dst::Vector{UInt8})::Int
    body_closed(body) && return 0
    isempty(dst) && return 0
    try
        return readbytes!(body.io, dst, length(dst))
    catch err
        err isa EOFError && return 0
        rethrow(err)
    end
end

function body_read!(body::ChunkedBody, dst::Vector{UInt8})::Int
    body_closed(body) && return 0
    isempty(dst) && return 0
    body.done && return 0
    body.chunk_remaining == 0 && _read_next_chunk!(body)
    body.done && return 0
    to_read = min(Int64(length(dst)), body.chunk_remaining)
    n = _read_exact!(body.io, dst, to_read)
    n == to_read || throw(ParseError("truncated chunked HTTP/1 body"))
    body.chunk_remaining -= n
    if body.chunk_remaining == 0
        _consume_crlf(body.io)
    end
    return n
end

function _write_start_line!(io::IO, request::Request; wire_target::Union{Nothing, AbstractString} = nothing)
    target = wire_target === nothing ? request.target : String(wire_target)
    print(io, request.method, ' ', target, " HTTP/", Int(request.proto_major), '.', Int(request.proto_minor), "\r\n")
    return nothing
end

function _status_text(status_code::Integer)::String
    status_code == 100 && return "Continue"
    status_code == 101 && return "Switching Protocols"
    status_code == 102 && return "Processing"
    status_code == 103 && return "Early Hints"
    status_code == 200 && return "OK"
    status_code == 201 && return "Created"
    status_code == 202 && return "Accepted"
    status_code == 203 && return "Non-Authoritative Information"
    status_code == 204 && return "No Content"
    status_code == 205 && return "Reset Content"
    status_code == 206 && return "Partial Content"
    status_code == 207 && return "Multi-Status"
    status_code == 208 && return "Already Reported"
    status_code == 226 && return "IM Used"
    status_code == 300 && return "Multiple Choices"
    status_code == 301 && return "Moved Permanently"
    status_code == 302 && return "Found"
    status_code == 303 && return "See Other"
    status_code == 304 && return "Not Modified"
    status_code == 305 && return "Use Proxy"
    status_code == 307 && return "Temporary Redirect"
    status_code == 308 && return "Permanent Redirect"
    status_code == 400 && return "Bad Request"
    status_code == 401 && return "Unauthorized"
    status_code == 402 && return "Payment Required"
    status_code == 403 && return "Forbidden"
    status_code == 404 && return "Not Found"
    status_code == 405 && return "Method Not Allowed"
    status_code == 406 && return "Not Acceptable"
    status_code == 407 && return "Proxy Authentication Required"
    status_code == 408 && return "Request Timeout"
    status_code == 409 && return "Conflict"
    status_code == 410 && return "Gone"
    status_code == 411 && return "Length Required"
    status_code == 412 && return "Precondition Failed"
    status_code == 413 && return "Content Too Large"
    status_code == 414 && return "URI Too Long"
    status_code == 415 && return "Unsupported Media Type"
    status_code == 416 && return "Range Not Satisfiable"
    status_code == 417 && return "Expectation Failed"
    status_code == 418 && return "I'm a teapot"
    status_code == 421 && return "Misdirected Request"
    status_code == 422 && return "Unprocessable Entity"
    status_code == 423 && return "Locked"
    status_code == 424 && return "Failed Dependency"
    status_code == 425 && return "Too Early"
    status_code == 426 && return "Upgrade Required"
    status_code == 428 && return "Precondition Required"
    status_code == 429 && return "Too Many Requests"
    status_code == 431 && return "Request Header Fields Too Large"
    status_code == 451 && return "Unavailable For Legal Reasons"
    status_code == 500 && return "Internal Server Error"
    status_code == 501 && return "Not Implemented"
    status_code == 502 && return "Bad Gateway"
    status_code == 503 && return "Service Unavailable"
    status_code == 504 && return "Gateway Timeout"
    status_code == 505 && return "HTTP Version Not Supported"
    status_code == 506 && return "Variant Also Negotiates"
    status_code == 507 && return "Insufficient Storage"
    status_code == 508 && return "Loop Detected"
    status_code == 510 && return "Not Extended"
    status_code == 511 && return "Network Authentication Required"
    return ""
end

function _write_status_line!(io::IO, response::Response)
    reason = isempty(response.reason) ? _status_text(response.status_code) : response.reason
    print(io, "HTTP/", Int(response.proto_major), '.', Int(response.proto_minor), ' ', response.status_code, ' ', reason, "\r\n")
    return nothing
end

function _write_headers!(io::IO, headers::Headers)
    for key in header_keys(headers)
        values = get_headers(headers, key)
        for value in values
            print(io, key, ": ", value, "\r\n")
        end
    end
    return nothing
end

function _prepare_trailer_header!(headers::Headers, trailer_values::Headers)
    isempty(trailer_values) && return nothing
    has_header(headers, "Trailer") && return nothing
    names = header_keys(trailer_values)
    isempty(names) && return nothing
    set_header!(headers, "Trailer", join(names, ", "))
    return nothing
end

function _write_exact_body!(io::IO, body::B, expected_len::Int64) where {B <: AbstractBody}
    expected_len < 0 && throw(ArgumentError("expected_len must be >= 0"))
    expected_len == 0 && return nothing
    remaining = expected_len
    while remaining > 0
        to_read = Int(min(Int64(16 * 1024), remaining))
        buf = Vector{UInt8}(undef, to_read)
        n = body_read!(body, buf)
        n > 0 || throw(ProtocolError("body ended before expected Content-Length bytes were written"))
        write(io, n == length(buf) ? buf : @view(buf[1:n]))
        remaining -= n
    end
    return nothing
end

@noinline function _unsupported_serialized_body(body::AbstractBody)
    throw(ProtocolError("unsupported serialized body type $(typeof(body))"))
end

function _write_exact_body_dispatch!(io::IO, body::AbstractBody, expected_len::Int64)
    return _unsupported_serialized_body(body)
end

function _write_exact_body_dispatch!(io::IO, body::EmptyBody, expected_len::Int64)
    return _write_exact_body!(io, body, expected_len)
end

function _write_exact_body_dispatch!(io::IO, body::BytesBody, expected_len::Int64)
    return _write_exact_body!(io, body, expected_len)
end

function _write_exact_body_dispatch!(io::IO, body::CallbackBody, expected_len::Int64)
    return _write_exact_body!(io, body, expected_len)
end

function _write_exact_body_dispatch!(io::IO, body::FixedLengthBody, expected_len::Int64)
    return _write_exact_body!(io, body, expected_len)
end

function _write_exact_body_dispatch!(io::IO, body::ChunkedBody, expected_len::Int64)
    return _write_exact_body!(io, body, expected_len)
end

function _write_exact_body_dispatch!(io::IO, body::EOFBody, expected_len::Int64)
    return _write_exact_body!(io, body, expected_len)
end

function _write_chunked_body!(io::IO, body::B, trailer_values::Headers) where {B <: AbstractBody}
    buf = Vector{UInt8}(undef, 16 * 1024)
    while true
        n = body_read!(body, buf)
        n == 0 && break
        print(io, string(n, base = 16), "\r\n")
        write(io, @view(buf[1:n]))
        write(io, "\r\n")
    end
    write(io, "0\r\n")
    _write_headers!(io, trailer_values)
    write(io, "\r\n")
    return nothing
end

function _write_chunked_body_dispatch!(io::IO, body::AbstractBody, trailer_values::Headers)
    return _unsupported_serialized_body(body)
end

function _write_chunked_body_dispatch!(io::IO, body::EmptyBody, trailer_values::Headers)
    return _write_chunked_body!(io, body, trailer_values)
end

function _write_chunked_body_dispatch!(io::IO, body::BytesBody, trailer_values::Headers)
    return _write_chunked_body!(io, body, trailer_values)
end

function _write_chunked_body_dispatch!(io::IO, body::CallbackBody, trailer_values::Headers)
    return _write_chunked_body!(io, body, trailer_values)
end

function _write_chunked_body_dispatch!(io::IO, body::FixedLengthBody, trailer_values::Headers)
    return _write_chunked_body!(io, body, trailer_values)
end

function _write_chunked_body_dispatch!(io::IO, body::ChunkedBody, trailer_values::Headers)
    return _write_chunked_body!(io, body, trailer_values)
end

function _write_chunked_body_dispatch!(io::IO, body::EOFBody, trailer_values::Headers)
    return _write_chunked_body!(io, body, trailer_values)
end

function _request_has_body(request::Request)::Bool
    request.body isa EmptyBody && return false
    request.content_length == 0 && return false
    return true
end

function _response_has_body(response::Response)::Bool
    _body_allowed_for_status(response.status_code) || return false
    response.body isa EmptyBody && return false
    response.content_length == 0 && return false
    return true
end

"""
    write_request!(io, request)

Serialize an HTTP/1 request to `io`, including body framing.

Behavior:
- injects `Host` from `request.host` when missing
- normalizes connection-close signaling
- chooses between `Content-Length` and chunked transfer-coding
- serializes trailers only for chunked bodies

Returns `nothing`. May throw `ProtocolError` for inconsistent framing or
propagate exceptions from `io` and the request body.
"""
function write_request!(
        io::IO,
        request::Request{B};
        wire_target::Union{Nothing, AbstractString} = nothing,
        proxy_authorization::Union{Nothing, AbstractString} = nothing,
    ) where {B <: AbstractBody}
    headers = copy(request.headers)
    if proxy_authorization !== nothing && !has_header(headers, "Proxy-Authorization")
        set_header!(headers, "Proxy-Authorization", String(proxy_authorization))
    end
    has_host = has_header(headers, "Host")
    if !has_host && request.host !== nothing
        set_header!(headers, "Host", request.host::String)
    end
    request_close = request.close || _should_close_connection(headers, request.proto_major, request.proto_minor)
    request_close && set_header!(headers, "Connection", "close")
    use_chunked = has_header_token(headers, "Transfer-Encoding", "chunked")
    if !use_chunked
        if request.content_length >= 0
            set_header!(headers, "Content-Length", string(request.content_length))
        elseif _request_has_body(request)
            use_chunked = true
            set_header!(headers, "Transfer-Encoding", "chunked")
            delete_header!(headers, "Content-Length")
        else
            set_header!(headers, "Content-Length", "0")
        end
    end
    use_chunked && _prepare_trailer_header!(headers, request.trailers)
    _write_start_line!(io, request; wire_target = wire_target)
    _write_headers!(io, headers)
    write(io, "\r\n")
    if use_chunked
        _write_chunked_body!(io, request.body, request.trailers)
        return nothing
    end
    request.content_length < 0 && return nothing
    _write_exact_body!(io, request.body, request.content_length)
    return nothing
end

"""
    write_response!(io, response)

Serialize an HTTP/1 response to `io`, including body framing.

Body suppression rules for status codes like `1xx`, `204`, and `304` are
enforced here so callers can hand the function a regular `Response` object and
let the serializer apply wire-level HTTP/1 rules.
"""
function write_response!(io::IO, response::Response{B}) where {B <: AbstractBody}
    headers = copy(response.headers)
    response_close = response.close || _should_close_connection(headers, response.proto_major, response.proto_minor)
    response_close && set_header!(headers, "Connection", "close")
    allows_body = _body_allowed_for_status(response.status_code)
    use_chunked = allows_body && has_header_token(headers, "Transfer-Encoding", "chunked")
    if !allows_body
        delete_header!(headers, "Content-Length")
        delete_header!(headers, "Transfer-Encoding")
    elseif !use_chunked
        if response.content_length >= 0
            set_header!(headers, "Content-Length", string(response.content_length))
        elseif _response_has_body(response)
            use_chunked = true
            set_header!(headers, "Transfer-Encoding", "chunked")
            delete_header!(headers, "Content-Length")
        else
            set_header!(headers, "Content-Length", "0")
        end
    end
    use_chunked && _prepare_trailer_header!(headers, response.trailers)
    _write_status_line!(io, response)
    _write_headers!(io, headers)
    write(io, "\r\n")
    allows_body || return nothing
    if use_chunked
        _write_chunked_body_dispatch!(io, response.body, response.trailers)
        return nothing
    end
    response.content_length < 0 && return nothing
    _write_exact_body_dispatch!(io, response.body, response.content_length)
    return nothing
end

function _parse_request_line(line::AbstractString)::Tuple{String, String, UInt8, UInt8}
    first_space = findfirst(isequal(' '), line)
    first_space === nothing && throw(ParseError("malformed HTTP/1 request line: $(repr(line))"))
    second_space = findnext(isequal(' '), line, nextind(line, first_space))
    second_space === nothing && throw(ParseError("malformed HTTP/1 request line: $(repr(line))"))
    method = String(SubString(line, firstindex(line), prevind(line, first_space)))
    target = String(SubString(line, nextind(line, first_space), prevind(line, second_space)))
    version = String(SubString(line, nextind(line, second_space), lastindex(line)))
    isempty(method) && throw(ParseError("empty HTTP method in request line"))
    isempty(target) && throw(ParseError("empty HTTP target in request line"))
    major, minor = _parse_http_version(version)
    return method, target, major, minor
end

function _parse_status_line(line::AbstractString)::Tuple{UInt8, UInt8, Int, String}
    first_space = findfirst(isequal(' '), line)
    first_space === nothing && throw(ParseError("malformed HTTP/1 status line: $(repr(line))"))
    version = String(SubString(line, firstindex(line), prevind(line, first_space)))
    major, minor = _parse_http_version(version)
    rest_start = nextind(line, first_space)
    rest_start > lastindex(line) && throw(ParseError("malformed HTTP/1 status line: missing status code"))
    second_space = findnext(isequal(' '), line, rest_start)
    code_token = if second_space === nothing
        String(SubString(line, rest_start, lastindex(line)))
    else
        String(SubString(line, rest_start, prevind(line, second_space)))
    end
    status_code = try
        parse(Int, code_token)
    catch
        throw(ParseError("invalid HTTP status code in status line: $(repr(line))"))
    end
    status_code < 0 && throw(ParseError("invalid HTTP status code in status line: $(repr(line))"))
    if second_space === nothing || second_space == lastindex(line)
        reason = ""
    else
        reason = String(SubString(line, nextind(line, second_space), lastindex(line)))
    end
    return major, minor, status_code, reason
end

@inline function _new_parsed_request(
        method::String,
        target::String,
        headers::Headers,
        trailers::Headers,
        body::B,
        host::Union{Nothing, String},
        content_length::Int64,
        proto_major::UInt8,
        proto_minor::UInt8,
        close::Bool,
    )::Request{B} where {B <: AbstractBody}
    return Request{B}(
        method,
        target,
        headers,
        trailers,
        body,
        host,
        content_length,
        proto_major,
        proto_minor,
        close,
        RequestContext(),
    )
end

@inline function _new_parsed_incoming_response(
        status_code::Int,
        reason::String,
        headers::Headers,
        trailers::Headers,
        body::B,
        content_length::Int64,
        proto_major::UInt8,
        proto_minor::UInt8,
        close::Bool,
        request::Union{Nothing, Request},
    )::_IncomingResponse{B} where {B <: AbstractBody}
    return _IncomingResponse(
        _IncomingResponseHead(
            status_code,
            reason,
            headers,
            trailers,
            content_length,
            proto_major,
            proto_minor,
            close,
            request,
            nothing,
            nothing,
            0,
        ),
        body,
    )
end

@inline function _new_parsed_response(
        status_code::Int,
        reason::String,
        headers::Headers,
        trailers::Headers,
        body::B,
        content_length::Int64,
        proto_major::UInt8,
        proto_minor::UInt8,
        close::Bool,
        request::Union{Nothing, Request},
    )::Response{B} where {B <: AbstractBody}
    response = Response{B}(
        status_code,
        reason,
        headers,
        trailers,
        body,
        content_length,
        proto_major,
        proto_minor,
        close,
        request,
        nothing,
        nothing,
        0,
    )
    response.trailers = trailers
    return response
end

"""
    read_request(io; max_line_bytes=..., max_header_bytes=...)

Parse one HTTP/1 request from `io`.

Returns a `Request` whose body is one of `EmptyBody`, `FixedLengthBody`, or
`ChunkedBody` depending on the incoming framing headers.

Throws:
- `ArgumentError` for invalid parser limits
- `ParseError` for malformed syntax or truncated framed bodies
- `ProtocolError` for invalid semantic combinations such as conflicting length
  metadata
- any exception propagated by the underlying `IO`
"""
function read_request(io::IO; max_line_bytes::Integer = _HTTP1_DEFAULT_MAX_LINE_BYTES, max_header_bytes::Integer = _HTTP1_DEFAULT_MAX_HEADER_BYTES)
    line = _readline_crlf(io, max_line_bytes)
    method, target, proto_major, proto_minor = _parse_request_line(line)
    headers = _read_headers(io, max_line_bytes, max_header_bytes)
    content_length = _parse_content_length(headers)
    host = get_header(headers, "Host")
    close = _should_close_connection(headers, proto_major, proto_minor)
    if has_header_token(headers, "Transfer-Encoding", "chunked")
        body = ChunkedBody(io; max_line_bytes = Int(max_line_bytes), max_header_bytes = Int(max_header_bytes))
        request = _new_parsed_request(
            method,
            target,
            headers,
            body.trailers,
            body,
            host,
            Int64(-1),
            UInt8(proto_major),
            UInt8(proto_minor),
            close,
        )
        request.trailers = body.trailers
        return request
    end
    if content_length > 0
        body = FixedLengthBody(io, content_length)
        request = _new_parsed_request(
            method,
            target,
            headers,
            Headers(),
            body,
            host,
            content_length,
            UInt8(proto_major),
            UInt8(proto_minor),
            close,
        )
        return request
    end
    request = _new_parsed_request(
        method,
        target,
        headers,
        Headers(),
        EmptyBody(),
        host,
        Int64(0),
        UInt8(proto_major),
        UInt8(proto_minor),
        close,
    )
    return request
end

"""
    _read_response(io, request=nothing; max_line_bytes=..., max_header_bytes=...)

Parse one HTTP/1 response from `io`.
`request` is optional but allows HEAD/no-body response handling parity.

Returns a `Response` whose body is one of `EmptyBody`, `FixedLengthBody`,
`ChunkedBody`, or `EOFBody` depending on the status code and framing headers.
Exception behavior mirrors `read_request`.
"""
function _read_incoming_response(
        io::IO,
        request::Union{Nothing, Request} = nothing;
        max_line_bytes::Integer = _HTTP1_DEFAULT_MAX_LINE_BYTES,
        max_header_bytes::Integer = _HTTP1_DEFAULT_MAX_HEADER_BYTES,
    )
    line = _readline_crlf(io, max_line_bytes)
    proto_major, proto_minor, status_code, reason = _parse_status_line(line)
    headers = _read_headers(io, max_line_bytes, max_header_bytes)
    content_length = _parse_content_length(headers)
    close = _should_close_connection(headers, proto_major, proto_minor)
    request_is_head = request !== nothing && request.method == "HEAD"
    request_is_connect_tunnel = request !== nothing && request.method == "CONNECT" && status_code >= 200 && status_code < 300
    if !_body_allowed_for_status(status_code) || request_is_head || request_is_connect_tunnel
        return _new_parsed_incoming_response(
            Int(status_code),
            reason,
            headers,
            Headers(),
            EmptyBody(),
            Int64(0),
            UInt8(proto_major),
            UInt8(proto_minor),
            close,
            request,
        )
    end
    if has_header_token(headers, "Transfer-Encoding", "chunked")
        body = ChunkedBody(io; max_line_bytes = Int(max_line_bytes), max_header_bytes = Int(max_header_bytes))
        response = _new_parsed_incoming_response(
            Int(status_code),
            reason,
            headers,
            body.trailers,
            body,
            Int64(-1),
            UInt8(proto_major),
            UInt8(proto_minor),
            close,
            request,
        )
        return response
    end
    if content_length > 0
        body = FixedLengthBody(io, content_length)
        return _new_parsed_incoming_response(
            Int(status_code),
            reason,
            headers,
            Headers(),
            body,
            content_length,
            UInt8(proto_major),
            UInt8(proto_minor),
            close,
            request,
        )
    end
    if content_length == 0
        return _new_parsed_incoming_response(
            Int(status_code),
            reason,
            headers,
            Headers(),
            EmptyBody(),
            Int64(0),
            UInt8(proto_major),
            UInt8(proto_minor),
            close,
            request,
        )
    end
    body = EOFBody(io)
    return _new_parsed_incoming_response(
        Int(status_code),
        reason,
        headers,
        Headers(),
        body,
        Int64(-1),
        UInt8(proto_major),
        UInt8(proto_minor),
        close,
        request,
    )
end

function _read_response(
        io::IO,
        request::Union{Nothing, Request} = nothing;
        max_line_bytes::Integer = _HTTP1_DEFAULT_MAX_LINE_BYTES,
        max_header_bytes::Integer = _HTTP1_DEFAULT_MAX_HEADER_BYTES,
    )
    line = _readline_crlf(io, max_line_bytes)
    proto_major, proto_minor, status_code, reason = _parse_status_line(line)
    headers = _read_headers(io, max_line_bytes, max_header_bytes)
    content_length = _parse_content_length(headers)
    close = _should_close_connection(headers, proto_major, proto_minor)
    request_is_head = request !== nothing && request.method == "HEAD"
    request_is_connect_tunnel = request !== nothing && request.method == "CONNECT" && status_code >= 200 && status_code < 300
    if !_body_allowed_for_status(status_code) || request_is_head || request_is_connect_tunnel
        return _new_parsed_response(
            Int(status_code),
            reason,
            headers,
            Headers(),
            EmptyBody(),
            Int64(0),
            UInt8(proto_major),
            UInt8(proto_minor),
            close,
            request,
        )
    end
    if has_header_token(headers, "Transfer-Encoding", "chunked")
        body = ChunkedBody(io; max_line_bytes = Int(max_line_bytes), max_header_bytes = Int(max_header_bytes))
        return _new_parsed_response(
            Int(status_code),
            reason,
            headers,
            body.trailers,
            body,
            Int64(-1),
            UInt8(proto_major),
            UInt8(proto_minor),
            close,
            request,
        )
    end
    if content_length > 0
        body = FixedLengthBody(io, content_length)
        return _new_parsed_response(
            Int(status_code),
            reason,
            headers,
            Headers(),
            body,
            content_length,
            UInt8(proto_major),
            UInt8(proto_minor),
            close,
            request,
        )
    end
    if content_length == 0
        return _new_parsed_response(
            Int(status_code),
            reason,
            headers,
            Headers(),
            EmptyBody(),
            Int64(0),
            UInt8(proto_major),
            UInt8(proto_minor),
            close,
            request,
        )
    end
    body = EOFBody(io)
    return _new_parsed_response(
        Int(status_code),
        reason,
        headers,
        Headers(),
        body,
        Int64(-1),
        UInt8(proto_major),
        UInt8(proto_minor),
        close,
        request,
    )
end
