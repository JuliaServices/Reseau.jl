module WebSockets

using Random

import Base: close, iterate

import ..Headers
import ..HostResolvers
import ..Request
import ..Response
import ..EmptyBody
import ..ProtocolError
import ..TooManyRedirectsError
import ..Client
import ..ClientConn
import ..Cookie
import ..CookieJar
import ..COOKIEJAR
import .._ConnReader
import .._USE_TRANSPORT_PROXY
import .._close_conn!
import .._client_for_request
import .._conn_reader_available
import .._conn_stream
import .._copy_request
import .._copy_request_for_send
import .._cookie_header
import .._effective_cookiejar
import .._host_for_sni
import .._host_path_from_request
import .._normalize_cookies_input
import .._normalize_headers_input
import .._parse_http_url
import .._prepare_request_for_redirect
import .._proxy_config_for_request
import .._proxy_plan
import .._ProxyPlanMode
import .._ProxyTarget
import .._read_incoming_response
import .._redirect_policy
import .._redirect_referer
import .._request_deadline_ns
import .._request_url
import .._resolve_redirect_target
import .._should_copy_sensitive_headers_on_redirect
import .._store_set_cookies!
import .._strip_sensitive_redirect_headers!
import .._streaming_response
import .._validate_request_extra_kwargs
import .._apply_conn_deadline!
import .._new_conn!
import .._is_redirect_status
import ..get_header
import ..get_headers
import ..has_header
import ..set_header!
import ..delete_header!
import ..body_close!
import ..write_request!
import ..WsOpcode
import ..WsDecodedFrame
import ..WsConnection
import ..ws_connection_new
import ..ws_send_frame!
import ..ws_send_ping!
import ..ws_send_pong!
import ..ws_close!
import ..ws_on_incoming_data!
import ..ws_get_outgoing_data!
import ..ws_random_handshake_key
import ..ws_compute_accept_key
import ..ws_decode_close_payload
import ..ws_is_valid_close_status
import ..ws_select_subprotocol
import ..ws_is_websocket_request
import ..WebSocketProtocolError
import ..WebSocketInvalidPayloadError

export WebSocket
export WebSocketError
export CloseFrameBody
export send
export receive
export ping
export pong

const DEFAULT_MAX_FRAG = 1024
const DEFAULT_READ_BUFFER_BYTES = 16 * 1024

struct CloseFrameBody
    code::Int
    reason::String
end

struct WebSocketError <: Exception
    message::CloseFrameBody
end

isok(err::WebSocketError) = return err.message.code in (1000, 1001, 1005)
isok(_) = return false

function Base.showerror(io::IO, err::WebSocketError)
    print(io, "websocket closed with status ", err.message.code)
    isempty(err.message.reason) || print(io, ": ", err.message.reason)
    return nothing
end

mutable struct WebSocket{S, C, W <: WsConnection}
    id::String
    host::String
    path::String
    subprotocol::Union{Nothing, String}
    stream::S
    close_transport!::C
    codec::W
    maxframesize::Int
    maxfragmentation::Int
    is_client::Bool
    readchannel::Channel{Union{String, Vector{UInt8}, WebSocketError}}
    readtask::Union{Nothing, Task}
    readclosed::Bool
    writeclosed::Bool
    closelock::ReentrantLock
    sendlock::ReentrantLock
    handshake_request::Union{Nothing, Request}
    handshake_response::Union{Nothing, Response}
    fragment_opcode::Union{Nothing, UInt8}
    fragment_payload::Vector{UInt8}
    fragment_count::Int
    closebody::Union{Nothing, CloseFrameBody}
end

function WebSocket(
        stream::S,
        close_transport!::C,
        host::AbstractString,
        path::AbstractString;
        subprotocol::Union{Nothing, AbstractString} = nothing,
        maxframesize::Integer = typemax(Int),
        maxfragmentation::Integer = DEFAULT_MAX_FRAG,
        is_client::Bool = true,
    ) where {S, C}
    maxframesize > 0 || throw(ArgumentError("maxframesize must be > 0"))
    maxfragmentation > 0 || throw(ArgumentError("maxfragmentation must be > 0"))
    channel = Channel{Union{String, Vector{UInt8}, WebSocketError}}(Inf)
    codec = ws_connection_new(is_client = is_client)
    ws = WebSocket(
        string(rand(UInt32); base = 58),
        String(host),
        String(path),
        subprotocol === nothing ? nothing : String(subprotocol),
        stream,
        close_transport!,
        codec,
        Int(maxframesize),
        Int(maxfragmentation),
        is_client,
        channel,
        nothing,
        false,
        false,
        ReentrantLock(),
        ReentrantLock(),
        nothing,
        nothing,
        nothing,
        UInt8[],
        0,
        nothing,
    )
    return ws
end

struct _ClientHandshake
    conn::Union{Nothing, ClientConn}
    response::Response
    buffered::Vector{UInt8}
    request::Request
end

isbinary(x) = return x isa AbstractVector{UInt8}
istext(x) = return x isa AbstractString
opcode(x) = return isbinary(x) ? WsOpcode.BINARY : WsOpcode.TEXT
_to_bytes(x::AbstractVector{UInt8}) = return x
_to_bytes(x::AbstractString) = return codeunits(String(x))
_to_bytes(x) = return codeunits(string(x))

function getresponse(ws::WebSocket)
    return ws.handshake_response
end

function isclosed(ws::WebSocket)::Bool
    return ws.readclosed && ws.writeclosed
end

function isupgrade(message::Request)::Bool
    return ws_is_websocket_request(message)
end

function isupgrade(message::Response)::Bool
    message.status_code == 101 || return false
    _response_has_token(message.headers, "Upgrade", "websocket") || return false
    _response_has_token(message.headers, "Connection", "upgrade") || return false
    return true
end

function _response_has_token(headers::Headers, name::AbstractString, token::AbstractString)::Bool
    values = get_headers(headers, name)
    isempty(values) && return false
    lower_token = lowercase(token)
    for value in values
        for part in eachsplit(value, ',')
            lowercase(strip(part)) == lower_token && return true
        end
    end
    return false
end

function _queue_close!(ws::WebSocket, body::CloseFrameBody)::Nothing
    ws.closebody = body
    ws.readclosed = true
    if isopen(ws.readchannel)
        try
            put!(ws.readchannel, WebSocketError(body))
        catch
        end
        close(ws.readchannel)
    end
    return nothing
end

function _close_channel!(ws::WebSocket)::Nothing
    isopen(ws.readchannel) && close(ws.readchannel)
    return nothing
end

function _enqueue_message!(ws::WebSocket, msg)::Nothing
    if isopen(ws.readchannel)
        try
            put!(ws.readchannel, msg)
        catch
        end
    end
    return nothing
end

function _valid_close_status(code::Int)::Bool
    code < 0 && return false
    code > typemax(UInt16) && return false
    return ws_is_valid_close_status(UInt16(code))
end

function _take_conn_reader_buffer!(reader::_ConnReader)::Vector{UInt8}
    available = _conn_reader_available(reader)
    available == 0 && return UInt8[]
    buffered = Vector{UInt8}(undef, available)
    copyto!(buffered, 1, reader.buf, reader.next, available)
    reader.next = reader.stop + 1
    return buffered
end

function _flush_ws_output_locked!(ws::WebSocket)::Nothing
    outgoing = ws_get_outgoing_data!(ws.codec)
    isempty(outgoing) && return nothing
    write(ws.stream, outgoing)
    return nothing
end

function _flush_ws_output!(ws::WebSocket)::Nothing
    @lock ws.sendlock begin
        _flush_ws_output_locked!(ws)
    end
    return nothing
end

function _process_incoming_frame!(ws::WebSocket, frame::WsDecodedFrame)::Nothing
    frame.payload_length <= ws.maxframesize || begin
        close_body = CloseFrameBody(1009, "frame too large")
        _queue_close!(ws, close_body)
        return nothing
    end
    op = frame.opcode
    fin = frame.fin
    frame_payload = copy(frame.payload)
    if op == UInt8(WsOpcode.PING) || op == UInt8(WsOpcode.PONG)
        return nothing
    end
    if op == UInt8(WsOpcode.CLOSE)
        close_body = if length(frame_payload) >= 2
            code, reason = ws_decode_close_payload(frame_payload)
            _valid_close_status(Int(code)) || begin
                _queue_close!(ws, CloseFrameBody(1002, "invalid close status code"))
                return nothing
            end
            CloseFrameBody(Int(code), isempty(reason) ? "" : String(reason))
        else
            CloseFrameBody(1005, "")
        end
        ws.writeclosed = true
        _queue_close!(ws, close_body)
        return nothing
    end
    if op == UInt8(WsOpcode.CONTINUATION)
        ws.fragment_opcode === nothing && begin
            _queue_close!(ws, CloseFrameBody(1002, "unexpected continuation"))
            return nothing
        end
        ws.fragment_count += 1
        if ws.fragment_count > ws.maxfragmentation
            _queue_close!(ws, CloseFrameBody(1009, "message too large"))
            return nothing
        end
        append!(ws.fragment_payload, frame_payload)
        if fin
            msg_opcode = ws.fragment_opcode::UInt8
            data = copy(ws.fragment_payload)
            ws.fragment_opcode = nothing
            empty!(ws.fragment_payload)
            ws.fragment_count = 0
            if msg_opcode == UInt8(WsOpcode.TEXT)
                _enqueue_message!(ws, String(data))
            else
                _enqueue_message!(ws, data)
            end
        end
        return nothing
    end
    if op == UInt8(WsOpcode.TEXT) || op == UInt8(WsOpcode.BINARY)
        ws.fragment_opcode === nothing || begin
            _queue_close!(ws, CloseFrameBody(1002, "unexpected new data frame"))
            return nothing
        end
        if fin
            if op == UInt8(WsOpcode.TEXT)
                _enqueue_message!(ws, String(frame_payload))
            else
                _enqueue_message!(ws, frame_payload)
            end
            ws.fragment_count = 0
        else
            ws.fragment_opcode = op
            ws.fragment_payload = frame_payload
            ws.fragment_count = 1
            if ws.fragment_count > ws.maxfragmentation
                _queue_close!(ws, CloseFrameBody(1009, "message too large"))
            end
        end
    end
    return nothing
end

function _ws_read_loop!(ws::WebSocket; buffer_bytes::Int = DEFAULT_READ_BUFFER_BYTES)::Nothing
    buffer_bytes > 0 || throw(ArgumentError("buffer_bytes must be > 0"))
    buf = Vector{UInt8}(undef, buffer_bytes)
    try
        while true
            n = read!(ws.stream, buf)
            n == 0 && break
            frames = ws_on_incoming_data!(ws.codec, @view buf[1:n])
            for frame in frames
                _process_incoming_frame!(ws, frame)
            end
            _flush_ws_output!(ws)
            ws.readclosed && break
        end
        if !ws.readclosed
            _queue_close!(ws, CloseFrameBody(1006, ""))
        end
    catch err
        close_body = if err isa WebSocketInvalidPayloadError
            CloseFrameBody(1007, "invalid websocket payload")
        elseif err isa WebSocketProtocolError
            CloseFrameBody(1002, "websocket protocol error")
        else
            CloseFrameBody(1006, "")
        end
        if !ws.readclosed
            _queue_close!(ws, close_body)
        end
        if !ws.writeclosed && close_body.code != 1006
            try
                close(ws, close_body)
            catch
            end
        end
    finally
        if ws.readclosed && ws.writeclosed
            try
                ws.close_transport!()
            catch
            end
        end
    end
    return nothing
end

function _start_read_task!(ws::WebSocket)::Nothing
    ws.readtask !== nothing && return nothing
    ws.readtask = errormonitor(Threads.@spawn _ws_read_loop!(ws))
    return nothing
end

function writeframe(ws::WebSocket, fin::Bool, op::WsOpcode.T, payload::AbstractVector{UInt8})::Int
    @lock ws.sendlock begin
        ws.writeclosed && throw(WebSocketError(CloseFrameBody(1006, "websocket is closed")))
        ws_send_frame!(ws.codec, UInt8(op), payload; fin = fin)
        _flush_ws_output_locked!(ws)
    end
    return length(payload)
end

function send(ws::WebSocket, x)
    @lock ws.sendlock begin
        ws.writeclosed && throw(WebSocketError(CloseFrameBody(1006, "websocket is closed")))
        if !isbinary(x) && !istext(x)
            first = true
            total = 0
            state = iterate(x)
            if state === nothing
                ws_send_frame!(ws.codec, UInt8(WsOpcode.TEXT), UInt8[]; fin = true)
                _flush_ws_output_locked!(ws)
                return 0
            end
            item, st = state
            next_state = iterate(x, st)
            while true
                total += length(_to_bytes(item))
                ws_send_frame!(ws.codec, UInt8(first ? opcode(item) : WsOpcode.CONTINUATION), _to_bytes(item); fin = next_state === nothing)
                first = false
                next_state === nothing && break
                item, st = next_state
                next_state = iterate(x, st)
            end
            _flush_ws_output_locked!(ws)
            return total
        end
        bytes = _to_bytes(x)
        ws_send_frame!(ws.codec, UInt8(opcode(x)), bytes; fin = true)
        _flush_ws_output_locked!(ws)
        return length(bytes)
    end
end

function ping(ws::WebSocket, data = UInt8[])
    @lock ws.sendlock begin
        ws.writeclosed && throw(WebSocketError(CloseFrameBody(1006, "websocket is closed")))
        ws_send_ping!(ws.codec, _to_bytes(data))
        _flush_ws_output_locked!(ws)
    end
    return nothing
end

function pong(ws::WebSocket, data = UInt8[])
    @lock ws.sendlock begin
        ws.writeclosed && throw(WebSocketError(CloseFrameBody(1006, "websocket is closed")))
        ws_send_pong!(ws.codec, _to_bytes(data))
        _flush_ws_output_locked!(ws)
    end
    return nothing
end

function receive(ws::WebSocket)
    if isready(ws.readchannel)
        msg = take!(ws.readchannel)
        msg isa WebSocketError && throw(msg)
        return msg
    end
    if ws.readclosed || !isopen(ws.readchannel)
        throw(WebSocketError(ws.closebody === nothing ? CloseFrameBody(1006, "") : ws.closebody::CloseFrameBody))
    end
    msg = take!(ws.readchannel)
    msg isa WebSocketError && throw(msg)
    return msg
end

function Base.iterate(ws::WebSocket, st = nothing)
    isclosed(ws) && return nothing
    try
        return receive(ws), nothing
    catch err
        isok(err) && return nothing
        rethrow(err)
    end
end

function close(ws::WebSocket, body::Union{Nothing, CloseFrameBody} = nothing)
    @lock ws.closelock begin
        if !ws.writeclosed
            ws.writeclosed = true
            if body !== nothing
                if !_valid_close_status(body.code)
                    body = CloseFrameBody(1002, "invalid close status code")
                end
                try
                    @lock ws.sendlock begin
                        ws_close!(ws.codec; status_code = UInt16(body.code), reason = codeunits(body.reason))
                        _flush_ws_output_locked!(ws)
                    end
                catch
                end
            else
                try
                    @lock ws.sendlock begin
                        ws_close!(ws.codec; status_code = UInt16(1000), reason = UInt8[])
                        _flush_ws_output_locked!(ws)
                    end
                catch
                end
            end
        end
    end
    if !ws.readclosed
        deadline = time() + 5.0
        while time() < deadline
            ws.readclosed && break
            sleep(0.05)
        end
        ws.readclosed = true
    end
    try
        ws.close_transport!()
    catch
    end
    _close_channel!(ws)
    return nothing
end

function _apply_websocket_request_headers!(
        headers::Headers,
        key::String;
        subprotocols::AbstractVector{<:AbstractString} = String[],
    )::Nothing
    set_header!(headers, "Upgrade", "websocket")
    set_header!(headers, "Connection", "Upgrade")
    set_header!(headers, "Sec-WebSocket-Key", key)
    set_header!(headers, "Sec-WebSocket-Version", "13")
    if isempty(subprotocols)
        delete_header!(headers, "Sec-WebSocket-Protocol")
    else
        set_header!(headers, "Sec-WebSocket-Protocol", join(String.(subprotocols), ", "))
    end
    return nothing
end

function _parse_websocket_url(url::AbstractString; query = nothing)
    text = String(url)
    lower = lowercase(text)
    if startswith(lower, "ws://")
        return _parse_http_url("http://" * text[6:end]; query = query)
    elseif startswith(lower, "wss://")
        return _parse_http_url("https://" * text[7:end]; query = query)
    elseif startswith(lower, "http://") || startswith(lower, "https://")
        return _parse_http_url(text; query = query)
    end
    throw(ArgumentError("websocket URL must use ws://, wss://, http://, or https://"))
end

function _normalize_websocket_redirect_location(location::AbstractString)::String
    text = String(location)
    lower = lowercase(text)
    if startswith(lower, "ws://")
        return "http://" * text[6:end]
    elseif startswith(lower, "wss://")
        return "https://" * text[7:end]
    end
    return text
end

function _validate_websocket_upgrade!(
        response::Response,
        expected_accept::String,
        requested_subprotocols::AbstractVector{<:AbstractString},
    )::Union{Nothing, String}
    isupgrade(response) || throw(WebSocketError(CloseFrameBody(1002, "websocket handshake failed")))
    accept = get_header(response.headers, "Sec-WebSocket-Accept")
    accept == expected_accept || throw(WebSocketError(CloseFrameBody(1002, "websocket handshake accept mismatch")))
    subprotocol = get_header(response.headers, "Sec-WebSocket-Protocol")
    subprotocol === nothing && return nothing
    normalized = strip(subprotocol)
    isempty(normalized) && return nothing
    if isempty(requested_subprotocols)
        throw(WebSocketError(CloseFrameBody(1002, "unexpected websocket subprotocol in response")))
    end
    normalized in String.(requested_subprotocols) || throw(WebSocketError(CloseFrameBody(1002, "unrequested websocket subprotocol in response")))
    return normalized
end

function _websocket_roundtrip!(
        client::Client,
        address::String,
        request::Request;
        secure::Bool,
        server_name::String,
        proxy_config,
    )::_ClientHandshake
    deadline_ns = _request_deadline_ns(request)
    plan = _proxy_plan(proxy_config, secure, address)
    conn = _new_conn!(client.transport, plan, address; secure = secure, server_name = server_name, deadline_ns = deadline_ns)
    try
        _apply_conn_deadline!(conn, deadline_ns)
        request_io = conn.request_buf
        truncate(request_io, 0)
        seekstart(request_io)
        wire_target = plan.mode == _ProxyPlanMode.HTTP_FORWARD ? _request_url(secure, address, request.target) : nothing
        proxy_auth = plan.mode == _ProxyPlanMode.HTTP_FORWARD && plan.proxy !== nothing ? (plan.proxy::_ProxyTarget).authorization : nothing
        write_request!(request_io, request; wire_target = wire_target, proxy_authorization = proxy_auth)
        stream = _conn_stream(conn)
        nbytes = request_io.size
        wrote = write(stream, request_io.data, nbytes)
        wrote == nbytes || throw(ProtocolError("transport short write"))
        response = _read_incoming_response(conn.reader, request)
        try
            body_close!(response.rawbody)
        catch
        end
        buffered = response.head.status_code == 101 ? _take_conn_reader_buffer!(conn.reader) : UInt8[]
        public_response = _streaming_response(response)
        if response.head.status_code != 101
            _close_conn!(conn)
            return _ClientHandshake(nothing, public_response, UInt8[], request)
        end
        return _ClientHandshake(conn, public_response, buffered, request)
    catch
        _close_conn!(conn)
        rethrow()
    end
end

function _open_client_websocket(
        url::AbstractString;
        headers = Pair{String, String}[],
        maxframesize::Integer = typemax(Int),
        maxfragmentation::Integer = DEFAULT_MAX_FRAG,
        subprotocols::AbstractVector{<:AbstractString} = String[],
        query = nothing,
        client::Union{Nothing, Client} = nothing,
        redirect::Bool = true,
        redirect_limit::Union{Nothing, Integer} = nothing,
        redirect_method = nothing,
        forwardheaders::Bool = true,
        cookies = true,
        cookiejar::Union{Nothing, CookieJar} = nothing,
        proxy = _USE_TRANSPORT_PROXY,
        connect_timeout::Real = 0,
        require_ssl_verification::Bool = true,
        kwargs...,
    )::Tuple{WebSocket, Client, Bool}
    _validate_request_extra_kwargs(kwargs)
    parsed = _parse_websocket_url(url; query = query)
    req_headers = _normalize_headers_input(headers)
    normalized_cookies = _normalize_cookies_input(cookies)
    if parsed.authorization !== nothing && !has_header(req_headers, "Authorization")
        set_header!(req_headers, "Authorization", parsed.authorization::String)
    end
    key = ws_random_handshake_key()
    _apply_websocket_request_headers!(req_headers, key; subprotocols = subprotocols)
    request = Request("GET", parsed.target; headers = req_headers, host = parsed.address, body = EmptyBody(), content_length = 0)
    req_client, owns_client = _client_for_request(client; connect_timeout = connect_timeout, require_ssl_verification = require_ssl_verification)
    client === nothing || proxy === _USE_TRANSPORT_PROXY || throw(ArgumentError("proxy override is not supported when passing an explicit Client"))
    proxy_config = _proxy_config_for_request(req_client, proxy)
    effective_cookiejar = _effective_cookiejar(client, cookiejar)
    redirect_policy = _redirect_policy(
        req_client;
        redirect_limit = redirect ? redirect_limit : 0,
        redirect_method = redirect_method,
        forwardheaders = forwardheaders,
    )
    current_address = parsed.address
    current_secure = parsed.secure
    current_server_name = parsed.server_name
    current_request = request
    initial_address = current_address
    for redirect_count in 0:redirect_policy.max_redirects
        send_request = _copy_request(current_request)
        host, path = _host_path_from_request(current_address, current_request)
        cookie_value = _cookie_header(effective_cookiejar, normalized_cookies, current_secure, host, path)
        cookie_value === nothing || set_header!(send_request.headers, "Cookie", cookie_value)
        expected_accept = ws_compute_accept_key(get_header(send_request.headers, "Sec-WebSocket-Key")::String)
        attempt = _websocket_roundtrip!(
            req_client,
            current_address,
            send_request;
            secure = current_secure,
            server_name = current_server_name,
            proxy_config = proxy_config,
        )
        _store_set_cookies!(effective_cookiejar, normalized_cookies, current_secure, host, path, attempt.response.headers)
        response = attempt.response
        if response.status_code == 101
            negotiated = try
                _validate_websocket_upgrade!(response, expected_accept, subprotocols)
            catch
                attempt.conn === nothing || _close_conn!(attempt.conn::ClientConn)
                owns_client && close(req_client)
                rethrow()
            end
            conn = attempt.conn
            conn === nothing && begin
                owns_client && close(req_client)
                throw(ProtocolError("websocket upgrade succeeded without an active connection"))
            end
            close_transport! = let conn = conn::ClientConn, owned_client = owns_client, local_client = req_client
                () -> begin
                    _close_conn!(conn)
                    owned_client && close(local_client)
                    return nothing
                end
            end
            host_name, _ = HostResolvers.split_host_port(current_address)
            ws = WebSocket(
                _conn_stream(conn),
                close_transport!,
                host_name,
                current_request.target;
                subprotocol = negotiated,
                maxframesize = maxframesize,
                maxfragmentation = maxfragmentation,
                is_client = true,
            )
            ws.handshake_request = send_request
            ws.handshake_response = response
            if !isempty(attempt.buffered)
                frames = ws_on_incoming_data!(ws.codec, attempt.buffered)
                for frame in frames
                    _process_incoming_frame!(ws, frame)
                end
                _flush_ws_output!(ws)
            end
            _start_read_task!(ws)
            return ws, req_client, owns_client
        end
        if !_is_redirect_status(response.status_code) || redirect_policy.max_redirects == 0
            owns_client && close(req_client)
            throw(WebSocketError(CloseFrameBody(1002, "websocket handshake failed: status $(response.status_code)")))
        end
        location = get_header(response.headers, "Location")
        (location === nothing || isempty(location::String)) && begin
            owns_client && close(req_client)
            throw(WebSocketError(CloseFrameBody(1002, "websocket handshake failed: status $(response.status_code)")))
        end
        redirect_count == redirect_policy.max_redirects && begin
            owns_client && close(req_client)
            throw(TooManyRedirectsError(redirect_policy.max_redirects, response))
        end
        previous_secure = current_secure
        previous_address = current_address
        previous_target = current_request.target
        current_address, current_secure, next_target = _resolve_redirect_target(
            current_address,
            current_secure,
            _normalize_websocket_redirect_location(location::String),
            current_request.target,
        )
        current_server_name = _host_for_sni(current_address)
        current_request = _prepare_request_for_redirect(current_request, response.status_code, next_target, redirect_policy)
        key = ws_random_handshake_key()
        _apply_websocket_request_headers!(current_request.headers, key; subprotocols = subprotocols)
        current_request.host = current_address
        next_ref = _redirect_referer(previous_secure, previous_address, previous_target, current_secure, get_header(current_request.headers, "Referer"))
        if next_ref === nothing
            delete_header!(current_request.headers, "Referer")
        else
            set_header!(current_request.headers, "Referer", next_ref::String)
        end
        if !_should_copy_sensitive_headers_on_redirect(initial_address, current_address)
            _strip_sensitive_redirect_headers!(current_request.headers)
            _apply_websocket_request_headers!(current_request.headers, key; subprotocols = subprotocols)
        end
    end
    owns_client && close(req_client)
    throw(ProtocolError("unexpected websocket redirect loop termination"))
end

function open(
        url::AbstractString;
        suppress_close_error::Bool = false,
        headers = Pair{String, String}[],
        maxframesize::Integer = typemax(Int),
        maxfragmentation::Integer = DEFAULT_MAX_FRAG,
        subprotocols::AbstractVector{<:AbstractString} = String[],
        query = nothing,
        client::Union{Nothing, Client} = nothing,
        redirect::Bool = true,
        redirect_limit::Union{Nothing, Integer} = nothing,
        redirect_method = nothing,
        forwardheaders::Bool = true,
        cookies = true,
        cookiejar::Union{Nothing, CookieJar} = nothing,
        proxy = _USE_TRANSPORT_PROXY,
        connect_timeout::Real = 0,
        require_ssl_verification::Bool = true,
        kwargs...,
    )
    ws, _, _ = _open_client_websocket(
        url;
        headers = headers,
        maxframesize = maxframesize,
        maxfragmentation = maxfragmentation,
        subprotocols = subprotocols,
        query = query,
        client = client,
        redirect = redirect,
        redirect_limit = redirect_limit,
        redirect_method = redirect_method,
        forwardheaders = forwardheaders,
        cookies = cookies,
        cookiejar = cookiejar,
        proxy = proxy,
        connect_timeout = connect_timeout,
        require_ssl_verification = require_ssl_verification,
        kwargs...,
    )
    return ws
end

function open(
        f::Function,
        url::AbstractString;
        suppress_close_error::Bool = false,
        kwargs...,
    )
    ws = open(url; suppress_close_error = suppress_close_error, kwargs...)
    try
        return f(ws)
    catch err
        if err isa WebSocketError && isok(err)
            return nothing
        end
        rethrow(err)
    finally
        if !isclosed(ws)
            try
                close(ws, CloseFrameBody(1000, ""))
            catch err
                if !(suppress_close_error && err isa WebSocketError)
                    rethrow(err)
                end
            end
        end
    end
end

end
