# HTTP/2 server implementation using shared HTTP core request/response types.
export H2Server
export h2_server_addr
export start_h2_server!
export shutdown_h2_server!

using ..Reseau.TCP
using ..Reseau.HostResolvers
using ..Reseau.IOPoll

mutable struct H2Server{F}
    network::String
    address::String
    handler::F
    lock::ReentrantLock
    listener::Union{Nothing, TCP.Listener}
    serve_task::Union{Nothing, Task}
    active_conns::Set{TCP.Conn}
    bound_address::Union{Nothing, String}
    @atomic shutting_down::Bool
end

"""
    H2Server(; network="tcp", address="127.0.0.1:0", handler)

Create an HTTP/2 server configured with a request handler.
"""
function H2Server(; network::AbstractString = "tcp", address::AbstractString = "127.0.0.1:0", handler)
    return H2Server{typeof(handler)}(
        String(network),
        String(address),
        handler,
        ReentrantLock(),
        nothing,
        nothing,
        Set{TCP.Conn}(),
        nothing,
        false,
    )
end

@inline function _h2_server_shutting_down(server::H2Server)::Bool
    return @atomic :acquire server.shutting_down
end

"""
    h2_server_addr(server)

Return the bound `host:port` after the server starts listening.
"""
function h2_server_addr(server::H2Server)::String
    lock(server.lock)
    try
        server.bound_address === nothing && throw(ProtocolError("h2 server is not listening"))
        return server.bound_address::String
    finally
        unlock(server.lock)
    end
end

function _write_all_h2_server!(conn::TCP.Conn, bytes::Vector{UInt8})
    total = 0
    while total < length(bytes)
        n = write(conn, bytes[(total + 1):end])
        n > 0 || throw(ProtocolError("h2 server write made no progress"))
        total += n
    end
    return nothing
end

function _write_frame_h2_server!(conn::TCP.Conn, frame::AbstractFrame)
    io = IOBuffer()
    framer = Framer(io)
    write_frame!(framer, frame)
    _write_all_h2_server!(conn, take!(io))
    return nothing
end

const _H2_MAX_DATA_FRAME_SIZE = 16_384

function _write_data_frames_h2_server!(conn::TCP.Conn, stream_id::UInt32, data::Vector{UInt8}; end_stream::Bool)
    isempty(data) && return nothing
    offset = 1
    total_len = length(data)
    while offset <= total_len
        remaining = total_len - offset + 1
        chunk_len = min(_H2_MAX_DATA_FRAME_SIZE, remaining)
        chunk = Vector{UInt8}(undef, chunk_len)
        copyto!(chunk, 1, data, offset, chunk_len)
        final_chunk = (offset + chunk_len - 1) == total_len
        _write_frame_h2_server!(conn, DataFrame(stream_id, end_stream && final_chunk, chunk))
        offset += chunk_len
    end
    return nothing
end

function _read_exact_h2_server!(conn::TCP.Conn, n::Int)::Vector{UInt8}
    out = Vector{UInt8}(undef, n)
    offset = 0
    while offset < n
        chunk = Vector{UInt8}(undef, n - offset)
        nr = read!(conn, chunk)
        nr > 0 || throw(EOFError())
        copyto!(out, offset + 1, chunk, 1, nr)
        offset += nr
    end
    return out
end

function _decode_h2_request(headers::Vector{HeaderField}, body::Vector{UInt8})::Request
    method = "GET"
    path = "/"
    host = nothing
    out_headers = Headers()
    for header in headers
        if header.name == ":method"
            method = header.value
            continue
        end
        if header.name == ":path"
            path = header.value
            continue
        end
        if header.name == ":authority"
            host = header.value
            continue
        end
        add_header!(out_headers, header.name, header.value)
    end
    return Request(
        method,
        path;
        headers = out_headers,
        body = BytesBody(body),
        host = host,
        content_length = length(body),
        proto_major = 2,
        proto_minor = 0,
    )
end

function _encode_h2_response_headers(response::Response)::Vector{UInt8}
    header_fields = HeaderField[HeaderField(":status", string(response.status_code), false)]
    for key in header_keys(response.headers)
        values = get_headers(response.headers, key)
        for value in values
            push!(header_fields, HeaderField(lowercase(key), value, false))
        end
    end
    encoder = Encoder()
    return encode_header_block(encoder, header_fields)
end

function _write_response_body_h2_server!(conn::TCP.Conn, stream_id::UInt32, response::Response)
    response.body isa EmptyBody && return nothing
    buf = Vector{UInt8}(undef, 16 * 1024)
    pending = UInt8[]
    have_pending = false
    try
        while true
            n = body_read!(response.body, buf)
            if n == 0
                if have_pending
                    _write_data_frames_h2_server!(conn, stream_id, pending; end_stream = true)
                else
                    _write_frame_h2_server!(conn, DataFrame(stream_id, true, UInt8[]))
                end
                return nothing
            end
            current = Vector{UInt8}(undef, n)
            copyto!(current, 1, buf, 1, n)
            if have_pending
                _write_data_frames_h2_server!(conn, stream_id, pending; end_stream = false)
            end
            pending = current
            have_pending = true
        end
    finally
        try
            body_close!(response.body)
        catch
        end
    end
end

function _handle_h2_stream!(server::H2Server, conn::TCP.Conn, stream_id::UInt32, header_block::Vector{UInt8}, body::Vector{UInt8}, decoder::Decoder)
    decoded_headers = decode_header_block(decoder, header_block)
    request = _decode_h2_request(decoded_headers, body)
    response = server.handler(request)
    response isa Response || throw(ProtocolError("h2 server handler must return HTTP.Response"))
    response_obj = response::Response
    response_obj.request = request
    response_header_block = _encode_h2_response_headers(response_obj)
    end_stream = response_obj.body isa EmptyBody
    _write_frame_h2_server!(conn, HeadersFrame(stream_id, end_stream, true, response_header_block))
    end_stream || _write_response_body_h2_server!(conn, stream_id, response_obj)
    return nothing
end

function _serve_h2_conn!(server::H2Server, conn::TCP.Conn)
    lock(server.lock)
    try
        push!(server.active_conns, conn)
    finally
        unlock(server.lock)
    end
    reader = Framer(_ConnReader(conn))
    decoder = Decoder()
    try
        preface = _read_exact_h2_server!(conn, length(_H2_PREFACE))
        preface == _H2_PREFACE || throw(ProtocolError("invalid h2 client preface"))
        client_settings = read_frame!(reader)
        client_settings isa SettingsFrame || throw(ProtocolError("expected initial h2 SETTINGS frame"))
        _write_frame_h2_server!(conn, SettingsFrame(false, Pair{UInt16, UInt32}[]))
        _write_frame_h2_server!(conn, SettingsFrame(true, Pair{UInt16, UInt32}[]))
        # Simple per-stream aggregation: collect HEADERS/CONTINUATION and DATA until
        # both header and body sides complete, then dispatch to the handler.
        headers_block = Dict{UInt32, Vector{UInt8}}()
        body_block = Dict{UInt32, Vector{UInt8}}()
        headers_done = Dict{UInt32, Bool}()
        body_done = Dict{UInt32, Bool}()
        continuation_stream = UInt32(0)
        max_stream_id = UInt32(0)
        while !_h2_server_shutting_down(server)
            frame = try
                read_frame!(reader)
            catch err
                if err isa EOFError || err isa IOPoll.NetClosingError || err isa ParseError
                    return nothing
                end
                rethrow(err)
            end
            if continuation_stream != UInt32(0)
                if !(frame isa ContinuationFrame && (frame::ContinuationFrame).stream_id == continuation_stream)
                    throw(ProtocolError("expected CONTINUATION for stream $(continuation_stream)"))
                end
            elseif frame isa ContinuationFrame
                throw(ProtocolError("unexpected CONTINUATION frame"))
            end
            if frame isa SettingsFrame
                sf = frame::SettingsFrame
                sf.ack || _write_frame_h2_server!(conn, SettingsFrame(true, Pair{UInt16, UInt32}[]))
                continue
            end
            if frame isa PingFrame
                ping = frame::PingFrame
                ping.ack || _write_frame_h2_server!(conn, PingFrame(true, ping.opaque_data))
                continue
            end
            if frame isa HeadersFrame
                hf = frame::HeadersFrame
                hf.stream_id == UInt32(0) && throw(ProtocolError("HEADERS stream id must be non-zero"))
                iseven(hf.stream_id) && throw(ProtocolError("HEADERS stream id must be odd for client-initiated streams"))
                if hf.stream_id < max_stream_id && !haskey(headers_block, hf.stream_id)
                    throw(ProtocolError("HEADERS stream id must increase monotonically"))
                end
                hf.stream_id > max_stream_id && (max_stream_id = hf.stream_id)
                headers_block[hf.stream_id] = get(() -> UInt8[], headers_block, hf.stream_id)
                append!(headers_block[hf.stream_id], hf.header_block_fragment)
                headers_done[hf.stream_id] = hf.end_headers
                !hf.end_headers && (continuation_stream = hf.stream_id)
                body_done[hf.stream_id] = hf.end_stream
                if get(() -> false, headers_done, hf.stream_id) && get(() -> false, body_done, hf.stream_id)
                    _handle_h2_stream!(server, conn, hf.stream_id, headers_block[hf.stream_id], get(() -> UInt8[], body_block, hf.stream_id), decoder)
                    delete!(headers_block, hf.stream_id)
                    delete!(headers_done, hf.stream_id)
                    haskey(body_block, hf.stream_id) && delete!(body_block, hf.stream_id)
                    haskey(body_done, hf.stream_id) && delete!(body_done, hf.stream_id)
                end
                continue
            end
            if frame isa ContinuationFrame
                cf = frame::ContinuationFrame
                cf.stream_id == UInt32(0) && throw(ProtocolError("CONTINUATION stream id must be non-zero"))
                existing = get(() -> UInt8[], headers_block, cf.stream_id)
                append!(existing, cf.header_block_fragment)
                headers_block[cf.stream_id] = existing
                headers_done[cf.stream_id] = cf.end_headers
                continuation_stream = cf.end_headers ? UInt32(0) : cf.stream_id
                if get(() -> false, headers_done, cf.stream_id) && get(() -> false, body_done, cf.stream_id)
                    _handle_h2_stream!(server, conn, cf.stream_id, headers_block[cf.stream_id], get(() -> UInt8[], body_block, cf.stream_id), decoder)
                    delete!(headers_block, cf.stream_id)
                    delete!(headers_done, cf.stream_id)
                    haskey(body_block, cf.stream_id) && delete!(body_block, cf.stream_id)
                    haskey(body_done, cf.stream_id) && delete!(body_done, cf.stream_id)
                end
                continue
            end
            if frame isa DataFrame
                df = frame::DataFrame
                df.stream_id == UInt32(0) && throw(ProtocolError("DATA stream id must be non-zero"))
                iseven(df.stream_id) && throw(ProtocolError("DATA stream id must be odd for client-initiated streams"))
                haskey(headers_block, df.stream_id) || throw(ProtocolError("DATA frame received before HEADERS"))
                existing = get(() -> UInt8[], body_block, df.stream_id)
                append!(existing, df.data)
                body_block[df.stream_id] = existing
                _write_frame_h2_server!(conn, WindowUpdateFrame(UInt32(0), UInt32(length(df.data))))
                _write_frame_h2_server!(conn, WindowUpdateFrame(df.stream_id, UInt32(length(df.data))))
                body_done[df.stream_id] = df.end_stream
                if get(() -> false, headers_done, df.stream_id) && get(() -> false, body_done, df.stream_id)
                    _handle_h2_stream!(server, conn, df.stream_id, headers_block[df.stream_id], body_block[df.stream_id], decoder)
                    delete!(headers_block, df.stream_id)
                    delete!(headers_done, df.stream_id)
                    delete!(body_block, df.stream_id)
                    delete!(body_done, df.stream_id)
                end
                continue
            end
        end
    catch err
        if err isa ProtocolError || err isa ParseError || err isa EOFError || err isa IOPoll.NetClosingError
            return nothing
        end
        rethrow(err)
    finally
        lock(server.lock)
        try
            delete!(server.active_conns, conn)
        finally
            unlock(server.lock)
        end
        try
            TCP.close!(conn)
        catch
        end
    end
    return nothing
end

function _serve_h2_listener!(server::H2Server, listener::TCP.Listener)
    while !_h2_server_shutting_down(server)
        conn = try
            TCP.accept!(listener)
        catch err
            if _h2_server_shutting_down(server) || err isa IOPoll.NetClosingError
                return nothing
            end
            rethrow(err)
        end
        errormonitor(Threads.@spawn _serve_h2_conn!(server, conn))
    end
    return nothing
end

"""
    start_h2_server!(server)

Start accepting HTTP/2 connections on a background task.
"""
function start_h2_server!(server::H2Server)::Task
    listener = HostResolvers.listen(server.network, server.address; backlog = 128)
    lock(server.lock)
    try
        server.listener = listener
        laddr = TCP.addr(listener)
        if laddr isa TCP.SocketAddrV4
            server.bound_address = HostResolvers.join_host_port("127.0.0.1", Int((laddr::TCP.SocketAddrV4).port))
        elseif laddr isa TCP.SocketAddrV6
            server.bound_address = HostResolvers.join_host_port("::1", Int((laddr::TCP.SocketAddrV6).port))
        end
    finally
        unlock(server.lock)
    end
    task = errormonitor(Threads.@spawn _serve_h2_listener!(server, listener))
    lock(server.lock)
    try
        server.serve_task = task
    finally
        unlock(server.lock)
    end
    return task
end

"""
    shutdown_h2_server!(server; force=true)

Stop listener accept loop and optionally close active connections.
"""
function shutdown_h2_server!(server::H2Server; force::Bool = true)
    @atomic :release server.shutting_down = true
    listener = nothing
    conns = TCP.Conn[]
    lock(server.lock)
    try
        listener = server.listener
        server.listener = nothing
        append!(conns, server.active_conns)
    finally
        unlock(server.lock)
    end
    if listener !== nothing
        try
            TCP.close!(listener::TCP.Listener)
        catch
        end
    end
    if force
        for conn in conns
            try
                TCP.close!(conn)
            catch
            end
        end
    end
    task = nothing
    lock(server.lock)
    try
        task = server.serve_task
    finally
        unlock(server.lock)
    end
    task === nothing || timedwait(() -> istaskdone(task::Task), 3.0; pollint = 0.001)
    return nothing
end
