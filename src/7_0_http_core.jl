# Core HTTP request/response/header/body types and errors.
export Headers
export Request
export Response
export RequestContext
export AbstractBody
export EmptyBody
export BytesBody
export CallbackBody
export nobody
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

"""
    ParseError

Raised when byte-level HTTP syntax cannot be parsed. This is used for malformed
request/status lines, invalid header syntax, truncated framed bodies, and other
wire-format failures where the peer did not send valid HTTP.
"""
struct ParseError <: Exception
    message::String
end

"""
    ProtocolError

Raised when the bytes are syntactically valid but violate higher-level HTTP
rules. Examples include mismatched `Content-Length` values, impossible frame
ordering, or unsupported control-flow states in the client/server stacks.
"""
struct ProtocolError <: Exception
    message::String
end

"""
    CanceledError

Raised when request processing is canceled explicitly through `RequestContext`.
Unlike `ParseError` and `ProtocolError`, this usually reflects local control
flow rather than a bad peer.
"""
struct CanceledError <: Exception
    message::String
end

"""
    HTTPTimeoutError

Raised when an HTTP-layer deadline expires. This is intentionally separate from
lower-level socket timeout exceptions so higher layers can distinguish "request
context expired" from transport-specific readiness or handshake failures.
"""
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

"""Shared empty byte-vector payload used for responses with no buffered body."""
const nobody = UInt8[]

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
    canonical_header_key(key) -> String

Canonicalize a header field name using the same "MIME canonical form" used by
Go's `textproto.CanonicalMIMEHeaderKey`: the first character and every
character after `-` is uppercased; other ASCII letters are lowercased.

Returns a newly owned `String` unless `key` is already in canonical form, in
which case a cached common-header string may be reused. This function does not
validate that `key` is a legal HTTP token; callers are still responsible for
protocol validation where needed.
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

`Headers` deliberately preserves insertion order for keys while storing one
vector of values per canonicalized name. That mirrors the parts of Go's
`http.Header` behavior that are useful to higher layers:
- key lookups are case-insensitive after canonicalization
- repeated headers preserve value order
- header iteration is stable and reflects the original append/replace pattern
"""
mutable struct Headers
    order::Vector{String}
    values::Dict{String, Vector{String}}
end

"""Create and return an empty `Headers` collection."""
function Headers()
    return Headers(String[], Dict{String, Vector{String}}())
end

"""
    Headers(hint)

Create an empty `Headers` collection and use `hint` as a preallocation hint for
both the key-order vector and backing dictionary. Throws `ArgumentError` when
`hint < 0`.
"""
function Headers(hint::Integer)
    hint < 0 && throw(ArgumentError("hint must be >= 0"))
    order = String[]
    values = Dict{String, Vector{String}}()
    sizehint!(order, Int(hint))
    sizehint!(values, Int(hint))
    return Headers(order, values)
end

"""
    Headers(headers)

Deep-copy constructor for header collections. Both the ordered key list and
every value vector are copied, so mutating the result does not affect the
source.
"""
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

"""Return a newly allocated `Vector{String}` of header keys in insertion order."""
function header_keys(headers::Headers)::Vector{String}
    return copy(headers.order)
end

"""Return `true` when `headers` contains at least one value for `key`."""
function has_header(headers::Headers, key::AbstractString)::Bool
    canon = canonical_header_key(key)
    return haskey(headers.values, canon)
end

"""
    get_headers(headers, key) -> Vector{String}

Return a freshly allocated vector containing all values for `key` in stored
order. Returns `String[]` when the header is absent.
"""
function get_headers(headers::Headers, key::AbstractString)::Vector{String}
    canon = canonical_header_key(key)
    values = get(() -> nothing, headers.values, canon)
    values === nothing && return String[]
    return copy(values::Vector{String})
end

"""Return the first value for `key`, or `nothing` if the header is absent."""
function get_header(headers::Headers, key::AbstractString)::Union{Nothing, String}
    canon = canonical_header_key(key)
    values = get(() -> nothing, headers.values, canon)
    values === nothing && return nothing
    isempty(values::Vector{String}) && return nothing
    return values[1]
end

"""
    set_header!(headers, key, value) -> Headers

Replace all existing values for `key` with a single `value`, preserving the
original key position if the key already exists and appending it otherwise.
Returns the mutated `headers`.
"""
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

"""Append one additional value for `key` and return the mutated `headers`."""
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

"""Delete `key` and all associated values, then return the mutated `headers`."""
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
    has_header_token(headers, key, token) -> Bool

Return `true` when a comma-separated header field contains `token`
case-insensitively after trimming optional whitespace.

This is the helper used for semantics like `Connection: close` and
`Transfer-Encoding: chunked`, where RFCs define one header line as a list of
tokens rather than one opaque string.
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

Per-request cancellation and deadline metadata shared across the HTTP client and
server layers.

Arguments:
- `deadline_ns`: absolute monotonic deadline in nanoseconds, or `0` to disable
  deadline tracking.

The context itself does not schedule timers; it is a passive state container
that transport code consults before or during blocking operations.
"""
mutable struct RequestContext
    deadline_ns::Int64
    @atomic canceled_flag::Bool
    cancel_message::Union{Nothing, String}
end

"""Construct a `RequestContext`; throws `ArgumentError` when `deadline_ns < 0`."""
function RequestContext(; deadline_ns::Integer = Int64(0))
    deadline_ns < 0 && throw(ArgumentError("deadline_ns must be >= 0"))
    return RequestContext(Int64(deadline_ns), false, nothing)
end

"""
    set_deadline!(ctx, deadline_ns) -> RequestContext

Set an absolute monotonic deadline in nanoseconds. Passing `0` clears any
deadline. Throws `ArgumentError` when `deadline_ns < 0`.
"""
function set_deadline!(ctx::RequestContext, deadline_ns::Integer)
    deadline_ns < 0 && throw(ArgumentError("deadline_ns must be >= 0"))
    ctx.deadline_ns = Int64(deadline_ns)
    return ctx
end

"""
    cancel!(ctx; message="request canceled") -> RequestContext

Mark `ctx` canceled and store a human-readable message for higher layers. This
does not throw on its own; callers typically check `canceled(ctx)` or turn the
state into a `CanceledError`.
"""
function cancel!(ctx::RequestContext; message::AbstractString = "request canceled")
    @atomic :release ctx.canceled_flag = true
    ctx.cancel_message = String(message)
    return ctx
end

"""Return `true` once `cancel!` has been called for `ctx`."""
function canceled(ctx::RequestContext)::Bool
    return @atomic :acquire ctx.canceled_flag
end

"""
    expired(ctx, now_ns=time_ns()) -> Bool

Return `true` when `ctx.deadline_ns` is non-zero and less than or equal to
`now_ns`. `now_ns` is injectable so tests and higher-level schedulers can reuse
an already-sampled monotonic timestamp.
"""
function expired(ctx::RequestContext, now_ns::Integer = time_ns())::Bool
    deadline = ctx.deadline_ns
    deadline <= 0 && return false
    return Int64(now_ns) >= deadline
end

"""
    AbstractBody

Abstract streaming body interface used throughout the HTTP stack.

Concrete subtypes are expected to implement:
- `body_read!(body, dst)::Int`
- `body_close!(body)`
- `body_closed(body)::Bool`

`body_read!` must return the number of bytes written into `dst`, with `0`
signaling EOF. Implementations may throw transport-specific exceptions.
"""
abstract type AbstractBody end

"""Zero-length body that immediately reports EOF and ignores close requests."""
struct EmptyBody <: AbstractBody
end

"""
    BytesBody(data)

Simple in-memory body backed by a copied `Vector{UInt8}`. Reads advance an
internal cursor until EOF; closing marks the body closed but does not free or
truncate the stored bytes.
"""
mutable struct BytesBody <: AbstractBody
    data::Vector{UInt8}
    next_index::Int
    @atomic closed::Bool
end

"""Copy `data` into a new `BytesBody` and reset the read cursor to the start."""
function BytesBody(data::AbstractVector{UInt8})
    return BytesBody(copy(data), 1, false)
end

"""
    CallbackBody(read_cb, close_cb)

Callback-driven streaming body. `read_cb(dst)` must return the number of bytes
written into `dst`, and `close_cb()` is invoked once when the body is closed.
This is the escape hatch for non-buffered request or response bodies.
"""
mutable struct CallbackBody{R, C} <: AbstractBody
    read_cb::R
    close_cb::C
    @atomic closed::Bool
end

"""Construct a `CallbackBody` from read and close callbacks."""
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

"""
    body_read!(body, dst) -> Int

Read up to `length(dst)` bytes into `dst`. Returns `0` on EOF.

Concrete body types may throw `ProtocolError`, transport errors, or body-
specific exceptions if the stream is malformed or the backing connection fails.
"""
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

"""
    body_close!(body)

Release any resources held by `body`. Implementations should be idempotent so
callers can safely close in `finally` blocks.
"""
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
    Request(method, target; headers=Headers(), trailers=Headers(), body=EmptyBody(), host=nothing,
            content_length=-1, proto_major=1, proto_minor=1, close=false,
            context=RequestContext())

HTTP request object shared by the client and server stacks.

Keyword arguments:
- `headers`, `trailers`: copied into the request.
- `body`: any `AbstractBody`; ownership stays with the request.
- `host`: optional authority used for HTTP/1 `Host` and HTTP/2 `:authority`.
- `content_length`: exact byte length, or `-1` when unknown.
- `proto_major`, `proto_minor`: protocol version metadata.
- `close`: request/connection-close hint.
- `context`: cancellation/deadline metadata consulted by higher layers.

Returns a new `Request{B}` where `B` is the concrete body type. Throws
`ArgumentError` for invalid protocol numbers, empty method/target, or
`content_length < -1`.
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
    Response(status_code; reason="", headers=Headers(), trailers=Headers(), body=EmptyBody(),
             content_length=-1, proto_major=1, proto_minor=1, close=false,
             request=nothing)

HTTP response object shared by the client and server stacks.

Keyword arguments mirror `Request` closely. `request` optionally links the
response back to the originating request, which is especially useful in client
redirect flows and server handler pipelines.

    Returns a new `Response{B}` where `B` is the body field type chosen for the
    public response object. For `AbstractBody` inputs, the constructor widens
    the field to `AbstractBody` so server handlers can swap in another streaming
    body later without rebuilding the whole response object. Fully materialized
    high-level payloads like `Vector{UInt8}` keep their concrete body type.
    `request_url` is optional client metadata used by high-level request
    helpers.

    Throws `ArgumentError` for invalid status or protocol metadata.
"""
mutable struct Response{B}
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
    request_url::Union{Nothing, String}
end

struct _IncomingResponseHead
    status_code::Int
    reason::String
    headers::Headers
    trailers::Headers
    content_length::Int64
    proto_major::UInt8
    proto_minor::UInt8
    close::Bool
    request::Union{Nothing, Request}
end

struct _IncomingResponse{B <: AbstractBody}
    head::_IncomingResponseHead
    rawbody::B
end

@inline _public_response_body_type(::Type{B}) where {B <: AbstractBody} = AbstractBody
@inline _public_response_body_type(::Type{B}) where {B} = B

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
        request_url::Union{Nothing, AbstractString} = nothing,
    ) where {B}
    status_code < 0 && throw(ArgumentError("status_code must be >= 0"))
    content_length < -1 && throw(ArgumentError("content_length must be >= -1"))
    (proto_major < 0 || proto_major > typemax(UInt8)) && throw(ArgumentError("proto_major must fit in UInt8"))
    (proto_minor < 0 || proto_minor > typemax(UInt8)) && throw(ArgumentError("proto_minor must fit in UInt8"))
    BodyT = _public_response_body_type(B)
    return Response{BodyT}(
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
        request_url === nothing ? nothing : String(request_url),
    )
end

function Base.getproperty(response::Response, field::Symbol)
    field === :status && return getfield(response, :status_code)
    field === :url && return getfield(response, :request_url)
    return getfield(response, field)
end

function _streaming_response(incoming::_IncomingResponse)
    head = incoming.head
    response = Response{typeof(incoming.rawbody)}(
        head.status_code,
        head.reason,
        head.headers,
        head.trailers,
        incoming.rawbody,
        head.content_length,
        head.proto_major,
        head.proto_minor,
        head.close,
        head.request,
        nothing,
    )
    response.trailers = head.trailers
    return response
end
