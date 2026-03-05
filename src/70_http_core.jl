# Core HTTP request/response/header/body types and errors.
export Headers
export Request
export Response
export RequestContext
export AbstractBody
export EmptyBody
export BytesBody
export CallbackBody
export ParseError
export ProtocolError
export CanceledError
export HTTPTimeoutError
export canonical_header_key
export has_header
export get_header
export get_headers
export header_keys
export set_header!
export add_header!
export delete_header!
export has_header_token
export body_read!
export body_close!
export body_closed
export set_deadline!
export cancel!
export canceled
export expired

"""Raised for malformed HTTP syntax during parsing."""
struct ParseError <: Exception
    message::String
end

"""Raised for semantic HTTP protocol violations."""
struct ProtocolError <: Exception
    message::String
end

"""Raised when request processing is explicitly canceled."""
struct CanceledError <: Exception
    message::String
end

"""Raised when a timeout/deadline expires for an HTTP operation."""
struct HTTPTimeoutError <: Exception
    operation::String
    timeout_ns::Int64
end

function Base.showerror(io::IO, err::ParseError)
    print(io, "http parse error: ", err.message)
    return nothing
end

function Base.showerror(io::IO, err::ProtocolError)
    print(io, "http protocol error: ", err.message)
    return nothing
end

function Base.showerror(io::IO, err::CanceledError)
    print(io, "http canceled: ", err.message)
    return nothing
end

function Base.showerror(io::IO, err::HTTPTimeoutError)
    print(io, "http timeout during ", err.operation, " after ", err.timeout_ns, " ns")
    return nothing
end

@inline function _is_ascii_upper(c::Char)::Bool
    return 'A' <= c <= 'Z'
end

@inline function _is_ascii_lower(c::Char)::Bool
    return 'a' <= c <= 'z'
end

@inline function _to_ascii_upper(c::Char)::Char
    _is_ascii_lower(c) || return c
    return Char(UInt32(c) - 0x20)
end

@inline function _to_ascii_lower(c::Char)::Char
    _is_ascii_upper(c) || return c
    return Char(UInt32(c) + 0x20)
end

const _COMMON_CANONICAL_HEADER_KEYS = let headers = (
        "Accept",
        "Accept-Charset",
        "Accept-Encoding",
        "Accept-Language",
        "Accept-Ranges",
        "Cache-Control",
        "Connection",
        "Content-Encoding",
        "Content-Language",
        "Content-Length",
        "Content-Type",
        "Cookie",
        "Date",
        "Host",
        "Location",
        "Referer",
        "Server",
        "Set-Cookie",
        "Transfer-Encoding",
        "Trailer",
        "User-Agent",
    )
    dict = Dict{String, String}()
    sizehint!(dict, length(headers))
    for header in headers
        dict[header] = header
    end
    dict
end

"""
    canonical_header_key(key)

Canonicalize header keys using Go-like MIME canonicalization rules.
"""
function canonical_header_key(key::AbstractString)::String
    isempty(key) && return ""
    key_s = String(key)
    upper_next = true
    canonical = true
    @inbounds for b in codeunits(key_s)
        if upper_next
            if 0x61 <= b <= 0x7a
                canonical = false
                break
            end
        else
            if 0x41 <= b <= 0x5a
                canonical = false
                break
            end
        end
        upper_next = (b == 0x2d)
    end
    if canonical
        return get(() -> key_s, _COMMON_CANONICAL_HEADER_KEYS, key_s)
    end
    chars = Vector{Char}(undef, ncodeunits(key_s))
    upper_next = true
    i = 1
    for c in key_s
        if upper_next
            chars[i] = _to_ascii_upper(c)
        else
            chars[i] = _to_ascii_lower(c)
        end
        upper_next = chars[i] == '-'
        i += 1
    end
    canon = String(chars[1:(i - 1)])
    return get(() -> canon, _COMMON_CANONICAL_HEADER_KEYS, canon)
end

"""
    Headers

Ordered, case-canonicalized HTTP header map.
"""
mutable struct Headers
    order::Vector{String}
    values::Dict{String, Vector{String}}
end

"""Create an empty ordered header collection."""
function Headers()
    return Headers(String[], Dict{String, Vector{String}}())
end

"""Create an empty ordered header collection with preallocation hint."""
function Headers(hint::Integer)
    hint < 0 && throw(ArgumentError("hint must be >= 0"))
    order = String[]
    values = Dict{String, Vector{String}}()
    sizehint!(order, Int(hint))
    sizehint!(values, Int(hint))
    return Headers(order, values)
end

"""Deep copy constructor for header collections."""
function Headers(headers::Headers)
    copied = Dict{String, Vector{String}}()
    for key in headers.order
        copied[key] = copy(headers.values[key])
    end
    return Headers(copy(headers.order), copied)
end

function Base.copy(headers::Headers)
    return Headers(headers)
end

function Base.length(headers::Headers)
    return length(headers.order)
end

function Base.isempty(headers::Headers)
    return isempty(headers.order)
end

function Base.empty!(headers::Headers)
    empty!(headers.order)
    empty!(headers.values)
    return headers
end

"""Return header keys in insertion order."""
function header_keys(headers::Headers)::Vector{String}
    return copy(headers.order)
end

"""Check whether a header key exists."""
function has_header(headers::Headers, key::AbstractString)::Bool
    canon = canonical_header_key(key)
    return haskey(headers.values, canon)
end

"""Return all values for a header key."""
function get_headers(headers::Headers, key::AbstractString)::Vector{String}
    canon = canonical_header_key(key)
    values = get(() -> nothing, headers.values, canon)
    values === nothing && return String[]
    return copy(values::Vector{String})
end

"""Return first header value for a key, or `nothing`."""
function get_header(headers::Headers, key::AbstractString)::Union{Nothing, String}
    canon = canonical_header_key(key)
    values = get(() -> nothing, headers.values, canon)
    values === nothing && return nothing
    isempty(values::Vector{String}) && return nothing
    return values[1]
end

"""Replace header key with a single value."""
function set_header!(headers::Headers, key::AbstractString, value::AbstractString)
    canon = canonical_header_key(key)
    if haskey(headers.values, canon)
        headers.values[canon] = String[String(value)]
        return headers
    end
    headers.values[canon] = String[String(value)]
    push!(headers.order, canon)
    return headers
end

"""Append one value for a header key."""
function add_header!(headers::Headers, key::AbstractString, value::AbstractString)
    canon = canonical_header_key(key)
    values = get(() -> nothing, headers.values, canon)
    if values === nothing
        headers.values[canon] = String[String(value)]
        push!(headers.order, canon)
        return headers
    end
    push!(values::Vector{String}, String(value))
    return headers
end

"""Delete a header key and all associated values."""
function delete_header!(headers::Headers, key::AbstractString)
    canon = canonical_header_key(key)
    haskey(headers.values, canon) || return headers
    delete!(headers.values, canon)
    idx = findfirst(isequal(canon), headers.order)
    idx === nothing || deleteat!(headers.order, idx)
    return headers
end

@inline function _ascii_lowercase_string(s::AbstractString)::String
    chars = Vector{Char}(undef, ncodeunits(s))
    i = 1
    for c in s
        chars[i] = _to_ascii_lower(c)
        i += 1
    end
    return String(chars[1:(i - 1)])
end

@inline function _trim_http_ows(s::AbstractString)::String
    lo = firstindex(s)
    hi = lastindex(s)
    while lo <= hi
        c = s[lo]
        if c == ' ' || c == '\t'
            lo = nextind(s, lo)
            continue
        end
        break
    end
    while hi >= lo
        c = s[hi]
        if c == ' ' || c == '\t'
            hi = prevind(s, hi)
            continue
        end
        break
    end
    hi < lo && return ""
    return String(SubString(s, lo, hi))
end

"""
    has_header_token(headers, key, token)

Return `true` when a comma-separated header value contains `token`
case-insensitively (e.g. `Connection: close`).
"""
function has_header_token(headers::Headers, key::AbstractString, token::AbstractString)::Bool
    needle = _ascii_lowercase_string(_trim_http_ows(token))
    isempty(needle) && return false
    values = get_headers(headers, key)
    for value in values
        start = firstindex(value)
        idx = start
        stop = lastindex(value)
        while idx <= stop
            while idx <= stop
                c = value[idx]
                if c == ','
                    idx = nextind(value, idx)
                    continue
                end
                break
            end
            idx > stop && break
            token_start = idx
            while idx <= stop && value[idx] != ','
                idx = nextind(value, idx)
            end
            token_end = prevind(value, idx)
            candidate = _ascii_lowercase_string(_trim_http_ows(SubString(value, token_start, token_end)))
            candidate == needle && return true
            idx <= stop && (idx = nextind(value, idx))
        end
    end
    return false
end

"""
    RequestContext(; deadline_ns=0)

Per-request cancellation and deadline metadata.
"""
mutable struct RequestContext
    deadline_ns::Int64
    @atomic canceled_flag::Bool
    cancel_message::Union{Nothing, String}
end

"""Create a request context with optional absolute deadline (ns)."""
function RequestContext(; deadline_ns::Integer = Int64(0))
    deadline_ns < 0 && throw(ArgumentError("deadline_ns must be >= 0"))
    return RequestContext(Int64(deadline_ns), false, nothing)
end

"""Set absolute deadline timestamp in nanoseconds."""
function set_deadline!(ctx::RequestContext, deadline_ns::Integer)
    deadline_ns < 0 && throw(ArgumentError("deadline_ns must be >= 0"))
    ctx.deadline_ns = Int64(deadline_ns)
    return ctx
end

"""Mark context canceled with an optional message."""
function cancel!(ctx::RequestContext; message::AbstractString = "request canceled")
    @atomic :release ctx.canceled_flag = true
    ctx.cancel_message = String(message)
    return ctx
end

"""Return whether context has been canceled."""
function canceled(ctx::RequestContext)::Bool
    return @atomic :acquire ctx.canceled_flag
end

"""Return whether context deadline has passed."""
function expired(ctx::RequestContext, now_ns::Integer = time_ns())::Bool
    deadline = ctx.deadline_ns
    deadline <= 0 && return false
    return Int64(now_ns) >= deadline
end

abstract type AbstractBody end

"""Empty body implementation."""
struct EmptyBody <: AbstractBody
end

"""In-memory byte-backed body implementation."""
mutable struct BytesBody <: AbstractBody
    data::Vector{UInt8}
    next_index::Int
    @atomic closed::Bool
end

"""Create a byte body from a vector-like input."""
function BytesBody(data::AbstractVector{UInt8})
    return BytesBody(copy(data), 1, false)
end

"""Callback-driven streaming body implementation."""
mutable struct CallbackBody{R, C} <: AbstractBody
    read_cb::R
    close_cb::C
    @atomic closed::Bool
end

"""Create a callback body from read and close callbacks."""
function CallbackBody(read_cb::R, close_cb::C) where {R, C}
    return CallbackBody{R, C}(read_cb, close_cb, false)
end

function body_closed(::EmptyBody)::Bool
    return false
end

function body_closed(body::BytesBody)::Bool
    return @atomic :acquire body.closed
end

function body_closed(body::CallbackBody)::Bool
    return @atomic :acquire body.closed
end

"""Generic body read API (returns bytes read, `0` on EOF)."""
function body_read!(::EmptyBody, dst::Vector{UInt8})::Int
    _ = dst
    return 0
end

function body_read!(body::BytesBody, dst::Vector{UInt8})::Int
    body_closed(body) && return 0
    isempty(dst) && return 0
    available = (length(body.data) - body.next_index) + 1
    available <= 0 && return 0
    n = min(length(dst), available)
    copyto!(dst, 1, body.data, body.next_index, n)
    body.next_index += n
    return n
end

function body_read!(body::CallbackBody, dst::Vector{UInt8})::Int
    body_closed(body) && return 0
    n = Int(body.read_cb(dst))
    n < 0 && throw(ProtocolError("body read callback returned negative byte count"))
    n <= length(dst) || throw(ProtocolError("body read callback exceeded destination buffer length"))
    return n
end

"""Generic body close API."""
function body_close!(::EmptyBody)
    return nothing
end

function body_close!(body::BytesBody)
    @atomic :release body.closed = true
    return nothing
end

function body_close!(body::CallbackBody)
    was_closed = body_closed(body)
    was_closed && return nothing
    @atomic :release body.closed = true
    body.close_cb()
    return nothing
end

"""
    Request(method, target; ...)

HTTP request object used across client and server stacks.
"""
mutable struct Request{B <: AbstractBody}
    method::String
    target::String
    headers::Headers
    trailers::Headers
    body::B
    host::Union{Nothing, String}
    content_length::Int64
    proto_major::UInt8
    proto_minor::UInt8
    close::Bool
    context::RequestContext
end

"""Construct a `Request` with validated metadata and copied headers."""
function Request(
        method::AbstractString,
        target::AbstractString;
        headers::Headers = Headers(),
        trailers::Headers = Headers(),
        body::B = EmptyBody(),
        host::Union{Nothing, AbstractString} = nothing,
        content_length::Integer = Int64(-1),
        proto_major::Integer = 1,
        proto_minor::Integer = 1,
        close::Bool = false,
        context::RequestContext = RequestContext(),
    ) where {B <: AbstractBody}
    isempty(method) && throw(ArgumentError("method must not be empty"))
    isempty(target) && throw(ArgumentError("target must not be empty"))
    content_length < -1 && throw(ArgumentError("content_length must be >= -1"))
    (proto_major < 0 || proto_major > typemax(UInt8)) && throw(ArgumentError("proto_major must fit in UInt8"))
    (proto_minor < 0 || proto_minor > typemax(UInt8)) && throw(ArgumentError("proto_minor must fit in UInt8"))
    host_s = host === nothing ? nothing : String(host)
    return Request{B}(
        String(method),
        String(target),
        copy(headers),
        copy(trailers),
        body,
        host_s,
        Int64(content_length),
        UInt8(proto_major),
        UInt8(proto_minor),
        close,
        context,
    )
end

"""
    Response(status_code; ...)

HTTP response object used across client and server stacks.
"""
mutable struct Response{B <: AbstractBody}
    status_code::Int
    reason::String
    headers::Headers
    trailers::Headers
    body::B
    content_length::Int64
    proto_major::UInt8
    proto_minor::UInt8
    close::Bool
    request::Union{Nothing, Request}
end

"""Construct a `Response` with validated metadata and copied headers."""
function Response(
        status_code::Integer;
        reason::AbstractString = "",
        headers::Headers = Headers(),
        trailers::Headers = Headers(),
        body::B = EmptyBody(),
        content_length::Integer = Int64(-1),
        proto_major::Integer = 1,
        proto_minor::Integer = 1,
        close::Bool = false,
        request::Union{Nothing, Request} = nothing,
    ) where {B <: AbstractBody}
    status_code < 0 && throw(ArgumentError("status_code must be >= 0"))
    content_length < -1 && throw(ArgumentError("content_length must be >= -1"))
    (proto_major < 0 || proto_major > typemax(UInt8)) && throw(ArgumentError("proto_major must fit in UInt8"))
    (proto_minor < 0 || proto_minor > typemax(UInt8)) && throw(ArgumentError("proto_minor must fit in UInt8"))
    return Response{B}(
        Int(status_code),
        String(reason),
        copy(headers),
        copy(trailers),
        body,
        Int64(content_length),
        UInt8(proto_major),
        UInt8(proto_minor),
        close,
        request,
    )
end
