# Production precompile workload. Helpers exercise real code paths (not stubs)
# so precompile artifacts track runtime behavior closely.
using PrecompileTools: @compile_workload, @setup_workload

const EL = EventLoops
const IP = IOPoll
const SO = SocketOps
const NC = TCP
const ND = HostResolvers
const TL = TLS
const HT = HTTP
const _PC_TLS_CERT_PATH = joinpath(dirname(dirname(@__FILE__)), "test", "resources", "unittests.crt")
const _PC_TLS_KEY_PATH = joinpath(dirname(dirname(@__FILE__)), "test", "resources", "unittests.key")

@inline function _pc_is_generating_output()::Bool
    return ccall(:jl_generating_output, Cint, ()) == 1
end

@inline function _pc_runtime_supported()::Bool
    return Sys.isapple() || Sys.islinux()
end

function _pc_socketpair_stream()
    fds = Vector{Cint}(undef, 2)
    ret = ccall(:socketpair, Cint, (Cint, Cint, Cint, Ptr{Cint}), Cint(1), Cint(1), Cint(0), pointer(fds))
    ret == 0 || throw(SystemError("socketpair", Int(Base.Libc.errno())))
    return fds[1], fds[2]
end

function _pc_close_fd(fd::Cint)
    fd < 0 && return nothing
    ccall(:close, Cint, (Cint,), fd)
    return nothing
end

function _pc_write_byte(fd::Cint, b::UInt8)
    buf = Ref{UInt8}(b)
    n = ccall(:write, Cssize_t, (Cint, Ptr{UInt8}, Csize_t), fd, buf, Csize_t(1))
    n == Cssize_t(1) || throw(SystemError("write", Int(Base.Libc.errno())))
    return nothing
end

mutable struct _PCHTTPChunkConn
    payload::Vector{UInt8}
    idx::Int
    max_chunk::Int
end

function _PCHTTPChunkConn(payload::Vector{UInt8}; max_chunk::Integer = 8)
    max_chunk > 0 || throw(ArgumentError("max_chunk must be > 0"))
    return _PCHTTPChunkConn(payload, 1, Int(max_chunk))
end

function Base.read!(conn::_PCHTTPChunkConn, dst::Vector{UInt8})::Int
    conn.idx > length(conn.payload) && return 0
    n = min(length(dst), conn.max_chunk, length(conn.payload) - conn.idx + 1)
    copyto!(dst, 1, conn.payload, conn.idx, n)
    conn.idx += n
    return n
end

"""
Run a minimal event-loop workload that touches registration, polling, and wakeup.
"""
function _pc_run_eventloops_workload!()
    EL.__init__()
    @assert isassigned(EL.POLLER)
    waiter = EL.PollWaiter()
    EL.pollnotify!(waiter)
    EL.pollwait!(waiter)
    _pc_runtime_supported() || return nothing
    state = EL.Poller()
    fd0 = Cint(-1)
    fd1 = Cint(-1)
    backend_open = false
    try
        errno = EL._backend_init!(state)
        errno == Int32(0) || throw(SystemError("event loop kqueue init", Int(errno)))
        backend_open = true
        fd0, fd1 = _pc_socketpair_stream()
        token = UInt64(1)
        registration = EL.Registration(fd0, token, EL.PollMode.READWRITE, EL.PollWaiter(), EL.PollWaiter(), false)
        state.registrations[fd0] = registration
        state.registrations_by_token[token] = registration
        errno = EL._backend_open_fd!(state, fd0, EL.PollMode.READWRITE, token)
        errno == Int32(0) || throw(SystemError("event loop open fd", Int(errno)))
        _pc_write_byte(fd1, 0x31)
        errno = EL._backend_poll_once!(state, Int64(0))
        errno == Int32(0) || throw(SystemError("event loop poll once", Int(errno)))
        EL.pollwait!(registration.read_waiter)
        errno = EL._backend_close_fd!(state, fd0)
        errno == Int32(0) || throw(SystemError("event loop close fd", Int(errno)))
    finally
        _pc_close_fd(fd0)
        _pc_close_fd(fd1)
        backend_open && EL._backend_close!(state)
    end
    return nothing
end

"""
Run a minimal internal poll workload including deadline wait and readable wake-up.
"""
function _pc_run_internal_poll_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    fd0, fd1 = _pc_socketpair_stream()
    ipfd = IP.FD(fd0)
    fd0 = Cint(-1)
    try
        IP._set_nonblocking!(ipfd.sysfd)
        IP.init!(ipfd)
        IP.set_read_deadline!(ipfd, time_ns() + 8_000_000)
        try
            IP.read!(ipfd, Vector{UInt8}(undef, 1))
        catch err
            err isa IP.DeadlineExceededError || rethrow(err)
        end
        IP.set_read_deadline!(ipfd, Int64(0))
        _pc_write_byte(fd1, 0x66)
        n = IP.read!(ipfd, Vector{UInt8}(undef, 1))
        n == 1 || error("internal poll workload expected one-byte read")
    finally
        ipfd.sysfd >= 0 && IP.close!(ipfd)
        _pc_close_fd(fd1)
    end
    return nothing
end

function _pc_wait_connect_ready!(fd::Cint)
    registration = EL.register!(fd; mode = EL.PollMode.WRITE)
    try
        EL.pollwait!(registration.write_waiter)
    finally
        EL.deregister!(fd)
    end
    return nothing
end

function _pc_accept_with_retry!(listener::Cint)::Cint
    for _ in 1:5000
        accepted, _, errno = SO.try_accept_socket(listener)
        accepted != -1 && return accepted
        if errno == Int32(Base.Libc.EAGAIN) || errno == Int32(Base.Libc.EWOULDBLOCK)
            yield()
            continue
        end
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("accept", Int(errno)))
    end
    throw(ArgumentError("timed out waiting for accepted socket"))
end

function _pc_run_socket_ops_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    listener = Cint(-1)
    client = Cint(-1)
    accepted = Cint(-1)
    try
        listener = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        SO.set_sockopt_int(listener, SO.SOL_SOCKET, SO.SO_REUSEADDR, 1)
        SO.bind_socket(listener, SO.sockaddr_in_loopback(0))
        SO.listen_socket(listener, 16)
        bound = SO.get_socket_name_in(listener)
        port = Int(SO.sockaddr_in_port(bound))
        client = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        errno = SO.connect_socket(client, SO.sockaddr_in_loopback(port))
        if errno != Int32(0) && errno != Int32(Base.Libc.EISCONN)
            if errno != Int32(Base.Libc.EINPROGRESS) && errno != Int32(Base.Libc.EALREADY) && errno != Int32(Base.Libc.EINTR)
                throw(SystemError("connect", Int(errno)))
            end
            _pc_wait_connect_ready!(client)
            so_error = SO.get_socket_error(client)
            so_error == Int32(0) || throw(SystemError("connect(SO_ERROR)", Int(so_error)))
        end
        accepted = _pc_accept_with_retry!(listener)
        payload = UInt8[0x31, 0x32]
        nw = GC.@preserve payload SO.write_once!(client, pointer(payload), Csize_t(length(payload)))
        nw == Cssize_t(length(payload)) || throw(ArgumentError("socket ops workload expected 2-byte write"))
        recv_buf = Vector{UInt8}(undef, 2)
        nr = GC.@preserve recv_buf SO.read_once!(accepted, pointer(recv_buf), Csize_t(length(recv_buf)))
        nr == Cssize_t(length(recv_buf)) || throw(ArgumentError("socket ops workload expected 2-byte read"))
    finally
        accepted >= 0 && SO.close_socket_nothrow(accepted)
        client >= 0 && SO.close_socket_nothrow(client)
        listener >= 0 && SO.close_socket_nothrow(listener)
    end
    return nothing
end

function _pc_run_tcp_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    listener = nothing
    client = nothing
    server = nothing
    try
        listener = NC.listen(NC.loopback_addr(0); backlog = 16)
        laddr = NC.addr(listener)
        accept_task = errormonitor(Threads.@spawn NC.accept!(listener))
        client = NC.connect(NC.loopback_addr(Int((laddr::NC.SocketAddrV4).port)))
        server = fetch(accept_task)
        payload = UInt8[0x41, 0x42, 0x43]
        written = write(client, payload)
        written == length(payload) || throw(ArgumentError("net core workload expected 3-byte write"))
        recv_buf = Vector{UInt8}(undef, length(payload))
        offset = 0
        while offset < length(recv_buf)
            recv_tmp = Vector{UInt8}(undef, length(recv_buf) - offset)
            read_count = read!(server, recv_tmp)
            read_count > 0 || throw(EOFError())
            copyto!(recv_buf, offset + 1, recv_tmp, 1, read_count)
            offset += read_count
        end
    finally
        try
            server === nothing || NC.close!(server)
        catch
        end
        try
            client === nothing || NC.close!(client)
        catch
        end
        try
            listener === nothing || NC.close!(listener)
        catch
        end
    end
    return nothing
end

function _pc_run_host_resolvers_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    listener = nothing
    client = nothing
    server = nothing
    try
        listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 16)
        laddr = NC.addr(listener)
        client = ND.connect("tcp", ND.join_host_port("127.0.0.1", Int((laddr::NC.SocketAddrV4).port)))
        server = NC.accept!(listener)
        payload = UInt8[0x51, 0x52]
        written = write(client, payload)
        written == length(payload) || throw(ArgumentError("host resolver workload expected 2-byte write"))
        recv_buf = Vector{UInt8}(undef, length(payload))
        offset = 0
        while offset < length(recv_buf)
            recv_tmp = Vector{UInt8}(undef, length(recv_buf) - offset)
            read_count = read!(server, recv_tmp)
            read_count > 0 || throw(EOFError())
            copyto!(recv_buf, offset + 1, recv_tmp, 1, read_count)
            offset += read_count
        end
    finally
        try
            server === nothing || NC.close!(server)
        catch
        end
        try
            client === nothing || NC.close!(client)
        catch
        end
        try
            listener === nothing || NC.close!(listener)
        catch
        end
    end
    return nothing
end

function _pc_tls_resource_file(name::AbstractString)::Union{Nothing, String}
    pkg_root = normpath(joinpath(@__DIR__, ".."))
    candidates = (
        joinpath(pkg_root, "test", "resources", name),
        joinpath(pkg_root, "test_old", "resources", name),
    )
    for path in candidates
        if isfile(path)
            return path
        end
    end
    return nothing
end

function _pc_run_tls_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    cert_path = _pc_tls_resource_file("unittests.crt")
    key_path = _pc_tls_resource_file("unittests.key")
    (cert_path === nothing || key_path === nothing) && return nothing
    listener = nothing
    client = nothing
    server = nothing
    try
        server_cfg = TL.Config(
            verify_peer = false,
            cert_file = cert_path::String,
            key_file = key_path::String,
            handshake_timeout_ns = 1_000_000_000,
        )
        listener = TL.listen("tcp", "127.0.0.1:0", server_cfg; backlog = 8)
        laddr = TL.addr(listener)::NC.SocketAddrV4
        accept_task = errormonitor(Threads.@spawn begin
            conn = TL.accept!(listener::TL.Listener)
            TL.handshake!(conn)
            return conn
        end)
        client_cfg = TL.Config(
            verify_peer = false,
            server_name = "localhost",
            handshake_timeout_ns = 1_000_000_000,
        )
        client = TL.connect(
            "tcp",
            "127.0.0.1:$(Int(laddr.port))";
            server_name = client_cfg.server_name,
            verify_peer = client_cfg.verify_peer,
            client_auth = client_cfg.client_auth,
            cert_file = client_cfg.cert_file,
            key_file = client_cfg.key_file,
            ca_file = client_cfg.ca_file,
            client_ca_file = client_cfg.client_ca_file,
            alpn_protocols = copy(client_cfg.alpn_protocols),
            handshake_timeout_ns = client_cfg.handshake_timeout_ns,
            min_version = client_cfg.min_version,
            max_version = client_cfg.max_version,
        )
        status = EL.timedwait(() -> istaskdone(accept_task), 2.0; pollint = 0.001)
        status == :timed_out && throw(ArgumentError("TLS precompile workload timed out during accept"))
        server = fetch(accept_task)
        payload = UInt8[0x54, 0x4c, 0x53]
        recv_buf = Vector{UInt8}(undef, 3)
        written = write(client, payload)
        written == 3 || throw(ArgumentError("TLS precompile workload expected 3-byte write"))
        read_count = read!(server, recv_buf)
        read_count == 3 || throw(ArgumentError("TLS precompile workload expected 3-byte read"))
    finally
        try
            server === nothing || TL.close!(server)
        catch
        end
        try
            client === nothing || TL.close!(client)
        catch
        end
        try
            listener === nothing || TL.close!(listener)
        catch
        end
        EL.shutdown!()
    end
    return nothing
end

function _pc_run_http_core_workload!()
    headers = HT.Headers()
    HT.set_header!(headers, "content-type", "application/json")
    HT.add_header!(headers, "x-test", "a")
    HT.add_header!(headers, "x-test", "b")
    request = HT.Request("GET", "/status"; headers = headers, host = "localhost")
    response = HT.Response(200; reason = "OK", headers = headers, request = request)
    _ = response
    body = HT.BytesBody(UInt8[0x68, 0x74, 0x74, 0x70])
    buf = Vector{UInt8}(undef, 4)
    n = HT.body_read!(body, buf)
    n == 4 || throw(ArgumentError("HTTP precompile workload expected 4-byte read"))
    HT.body_close!(body)
    request_io = IOBuffer()
    request_out = HT.Request("GET", "/ready"; headers = headers, body = HT.EmptyBody(), content_length = 0)
    HT.write_request!(request_io, request_out)
    request_in = HT.read_request(IOBuffer(take!(request_io)))
    request_in.method == "GET" || throw(ArgumentError("HTTP precompile workload expected GET request"))
    response_io = IOBuffer()
    response_headers = HT.Headers()
    HT.set_header!(response_headers, "Transfer-Encoding", "chunked")
    response_out = HT.Response(
        200;
        reason = "OK",
        headers = response_headers,
        trailers = headers,
        body = HT.BytesBody(UInt8[0x6f, 0x6b]),
        content_length = -1,
        request = request_in,
    )
    HT.write_response!(response_io, response_out)
    response_in = HT._read_response(IOBuffer(take!(response_io)), request_in)
    response_in.status_code == 200 || throw(ArgumentError("HTTP precompile workload expected 200 status"))
    chunked_bytes = codeunits("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nok\r\n0\r\n\r\n")
    chunk_reader = HT._ConnReader(_PCHTTPChunkConn(Vector{UInt8}(chunked_bytes); max_chunk = 3); buffer_bytes = 16)
    response_chunked = HT._read_response(chunk_reader, request_in)
    read_buf = Vector{UInt8}(undef, 2)
    HT.body_read!(response_chunked.body, read_buf) == 2 || throw(ArgumentError("HTTP precompile workload expected chunked read"))
    h2_io = IOBuffer()
    h2_writer = HT.Framer(h2_io)
    HT.write_frame!(h2_writer, HT.PingFrame(false, (UInt8(1), UInt8(2), UInt8(3), UInt8(4), UInt8(5), UInt8(6), UInt8(7), UInt8(8))))
    h2_reader = HT.Framer(HT._ConnReader(_PCHTTPChunkConn(take!(h2_io); max_chunk = 2); buffer_bytes = 8))
    h2_frame = HT.read_frame!(h2_reader)
    h2_frame isa HT.PingFrame || throw(ArgumentError("HTTP precompile workload expected PING frame"))
    return nothing
end

function _pc_run_http_transport_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    listener = nothing
    accepted = nothing
    server_task = nothing
    transport = nothing
    try
        listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
        laddr = NC.addr(listener)::NC.SocketAddrV4
        address = ND.join_host_port("127.0.0.1", Int(laddr.port))
        server_task = errormonitor(Threads.@spawn begin
            accepted = NC.accept!(listener::NC.Listener)
            request = HT.read_request(HT._ConnReader(accepted::NC.Conn))
            _ = request
            response = HT.Response(200; reason = "OK", body = HT.BytesBody(UInt8[0x6f, 0x6b]), content_length = 2)
            io = IOBuffer()
            HT.write_response!(io, response)
            payload = take!(io)
            n = write(accepted::NC.Conn, payload)
            n == length(payload) || throw(ArgumentError("HTTP transport precompile workload expected full write"))
            return accepted
        end)
        transport = HT.Transport(max_idle_per_host = 2, max_idle_total = 4)
        request = HT.Request("GET", "/ready"; host = address, body = HT.EmptyBody(), content_length = 0)
        response = HT.roundtrip!(transport::HT.Transport, address, request)
        body_buf = Vector{UInt8}(undef, 2)
        read_n = HT.body_read!(response.body, body_buf)
        read_n == 2 || throw(ArgumentError("HTTP transport precompile workload expected two-byte response body"))
        status = EL.timedwait(() -> istaskdone(server_task::Task), 2.0; pollint = 0.001)
        status == :timed_out && throw(ArgumentError("HTTP transport precompile workload timed out waiting for server task"))
        accepted = fetch(server_task::Task)
    finally
        try
            accepted === nothing || NC.close!(accepted::NC.Conn)
        catch
        end
        try
            transport === nothing || close(transport::HT.Transport)
        catch
        end
        try
            listener === nothing || NC.close!(listener::NC.Listener)
        catch
        end
    end
    return nothing
end

function _pc_run_http_client_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    listener = nothing
    server_task = nothing
    client = nothing
    try
        listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
        laddr = NC.addr(listener)::NC.SocketAddrV4
        address = ND.join_host_port("127.0.0.1", Int(laddr.port))
        server_task = errormonitor(Threads.@spawn begin
            conn = NC.accept!(listener::NC.Listener)
            try
                request = HT.read_request(HT._ConnReader(conn::NC.Conn))
                _ = request
                response = HT.Response(200; reason = "OK", body = HT.BytesBody(UInt8[0x6f, 0x6b]), content_length = 2)
                io = IOBuffer()
                HT.write_response!(io, response)
                payload = take!(io)
                n = write(conn::NC.Conn, payload)
                n == length(payload) || throw(ArgumentError("HTTP client precompile workload expected full write"))
            finally
                try
                    NC.close!(conn::NC.Conn)
                catch
                end
            end
            return nothing
        end)
        client = HT.Client(transport = HT.Transport(max_idle_per_host = 2, max_idle_total = 4))
        response = HT.get!(client::HT.Client, address, "/ready")
        body_buf = Vector{UInt8}(undef, 2)
        read_n = HT.body_read!(response.body, body_buf)
        read_n == 2 || throw(ArgumentError("HTTP client precompile workload expected two-byte response body"))
        status = EL.timedwait(() -> istaskdone(server_task::Task), 2.0; pollint = 0.001)
        status == :timed_out && throw(ArgumentError("HTTP client precompile workload timed out waiting for server task"))
        fetch(server_task::Task)
    finally
        try
            client === nothing || close(client.transport)
        catch
        end
        try
            listener === nothing || NC.close!(listener::NC.Listener)
        catch
        end
    end
    return nothing
end

function _pc_wait_http_server_addr(server::HT.Server; timeout_s::Float64 = 2.0)::String
    deadline = time() + timeout_s
    while time() < deadline
        try
            return HT.server_addr(server)
        catch
            EL.sleep(0.01)
        end
    end
    throw(ArgumentError("HTTP server precompile workload timed out waiting for address"))
end

function _pc_run_http_server_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    server = HT.serve!("127.0.0.1", 0; listenany = true) do request
            _ = request
            return HT.Response(200; reason = "OK", body = HT.BytesBody(UInt8[0x6f, 0x6b]), content_length = 2)
        end
    client = nothing
    try
        address = _pc_wait_http_server_addr(server)
        client = HT.Client(transport = HT.Transport(max_idle_per_host = 2, max_idle_total = 4))
        response = HT.get!(client::HT.Client, address::String, "/ready")
        body_buf = Vector{UInt8}(undef, 2)
        read_n = HT.body_read!(response.body, body_buf)
        read_n == 2 || throw(ArgumentError("HTTP server precompile workload expected two-byte response body"))
    finally
        try
            HT.forceclose(server)
        catch
        end
        try
            client === nothing || close(client.transport)
        catch
        end
        try
            wait(server)
        catch
        end
    end
    return nothing
end

function _pc_run_https_server_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    listener = TL.listen(
        "tcp",
        "127.0.0.1:0",
        TL.Config(
            verify_peer = false,
            cert_file = _PC_TLS_CERT_PATH,
            key_file = _PC_TLS_KEY_PATH,
            alpn_protocols = ["http/1.1"],
        );
        backlog = 8,
    )
    laddr = TL.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    server = HT.serve!(listener) do request
            _ = request
            return HT.Response(200; body = HT.BytesBody(UInt8[0x74, 0x6c, 0x73]), content_length = 3)
        end
    client = HT.Client(
        transport = HT.Transport(
            tls_config = TL.Config(verify_peer = false, server_name = "localhost", alpn_protocols = ["http/1.1"]),
            max_idle_per_host = 2,
            max_idle_total = 4,
        ),
        prefer_http2 = true,
    )
    try
        response = HT.get!(client, address, "/secure-h1"; secure = true, protocol = :auto)
        body_buf = Vector{UInt8}(undef, 3)
        read_n = HT.body_read!(response.body, body_buf)
        read_n == 3 || throw(ArgumentError("HTTPS server precompile workload expected three-byte response body"))
    finally
        try
            close(client)
        catch
        end
        try
            HT.forceclose(server)
        catch
        end
        try
            wait(server)
        catch
        end
    end
    return nothing
end

function _pc_run_http2_workload!()
    encoder = HT.Encoder()
    decoder = HT.Decoder()
    headers = HT.HeaderField[
        HT.HeaderField(":method", "GET", false),
        HT.HeaderField(":path", "/", false),
        HT.HeaderField("x-precompile", "1", false),
    ]
    block = HT.encode_header_block(encoder, headers)
    decoded = HT.decode_header_block(decoder, block)
    length(decoded) == length(headers) || throw(ArgumentError("HTTP/2 precompile workload expected decoded header count match"))
    io = IOBuffer()
    writer = HT.Framer(io)
    HT.write_frame!(writer, HT.SettingsFrame(false, [UInt16(0x4) => UInt32(65535)]))
    HT.write_frame!(writer, HT.DataFrame(UInt32(1), true, UInt8[0x6f, 0x6b]))
    reader = HT.Framer(IOBuffer(take!(io)))
    frame1 = HT.read_frame!(reader)
    frame2 = HT.read_frame!(reader)
    frame1 isa HT.SettingsFrame || throw(ArgumentError("HTTP/2 precompile workload expected SETTINGS frame"))
    frame2 isa HT.DataFrame || throw(ArgumentError("HTTP/2 precompile workload expected DATA frame"))
    return nothing
end

function _pc_run_http2_client_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    listener = nothing
    server_task = nothing
    conn = nothing
    try
        listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 8)
        laddr = NC.addr(listener)::NC.SocketAddrV4
        address = ND.join_host_port("127.0.0.1", Int(laddr.port))
        server_task = errormonitor(Threads.@spawn begin
            accepted = NC.accept!(listener::NC.Listener)
            reader = HT.Framer(HT._ConnReader(accepted::NC.Conn))
            try
                preface = Vector{UInt8}(undef, length(HT._H2_PREFACE))
                offset = 0
                while offset < length(preface)
                    chunk = Vector{UInt8}(undef, length(preface) - offset)
                    n = read!(accepted::NC.Conn, chunk)
                    n > 0 || throw(EOFError())
                    copyto!(preface, offset + 1, chunk, 1, n)
                    offset += n
                end
                preface == HT._H2_PREFACE || throw(ArgumentError("HTTP/2 client precompile workload invalid preface"))
                _ = HT.read_frame!(reader)
                io = IOBuffer()
                fw = HT.Framer(io)
                HT.write_frame!(fw, HT.SettingsFrame(false, Pair{UInt16, UInt32}[]))
                payload = take!(io)
                n = write(accepted::NC.Conn, payload)
                n == length(payload) || throw(ArgumentError("HTTP/2 client precompile workload expected full settings write"))
                _ = HT.read_frame!(reader)
                request_headers = HT.read_frame!(reader)
                request_headers isa HT.HeadersFrame || throw(ArgumentError("HTTP/2 client precompile workload expected headers frame"))
                encoder = HT.Encoder()
                response_headers = HT.encode_header_block(encoder, HT.HeaderField[HT.HeaderField(":status", "200", false)])
                io2 = IOBuffer()
                fw2 = HT.Framer(io2)
                hdr = request_headers::HT.HeadersFrame
                HT.write_frame!(fw2, HT.HeadersFrame(hdr.stream_id, false, true, response_headers))
                HT.write_frame!(fw2, HT.DataFrame(hdr.stream_id, true, UInt8[0x6f, 0x6b]))
                payload2 = take!(io2)
                nw = write(accepted::NC.Conn, payload2)
                nw == length(payload2) || throw(ArgumentError("HTTP/2 client precompile workload expected full response write"))
            finally
                try
                    NC.close!(accepted::NC.Conn)
                catch
                end
            end
            return nothing
        end)
        conn = HT.connect_h2!(address; secure = false)
        request = HT.Request("GET", "/ready"; host = address, body = HT.EmptyBody(), content_length = 0)
        response = HT.h2_roundtrip!(conn::HT.H2Connection, request)
        response.status_code == 200 || throw(ArgumentError("HTTP/2 client precompile workload expected status 200"))
        status = EL.timedwait(() -> istaskdone(server_task::Task), 2.0; pollint = 0.001)
        status == :timed_out && throw(ArgumentError("HTTP/2 client precompile workload timed out waiting for server task"))
        fetch(server_task::Task)
    finally
        try
            conn === nothing || close(conn::HT.H2Connection)
        catch
        end
        try
            listener === nothing || NC.close!(listener::NC.Listener)
        catch
        end
    end
    return nothing
end

function _pc_run_http2_server_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    server = HT.serve!("127.0.0.1", 0; listenany = true) do request
            _ = request
            return HT.Response(200; body = HT.BytesBody(UInt8[0x6f, 0x6b]), content_length = 2, proto_major = 2, proto_minor = 0)
        end
    conn = nothing
    try
        address = _pc_wait_http_server_addr(server)
        conn = HT.connect_h2!(address::String; secure = false)
        request = HT.Request("GET", "/ready"; host = address::String, body = HT.EmptyBody(), content_length = 0, proto_major = 2, proto_minor = 0)
        response = HT.h2_roundtrip!(conn::HT.H2Connection, request)
        response.status_code == 200 || throw(ArgumentError("HTTP/2 unified server precompile workload expected status 200"))
    finally
        try
            conn === nothing || close(conn::HT.H2Connection)
        catch
        end
        try
            HT.forceclose(server)
        catch
        end
        try
            wait(server)
        catch
        end
    end
    return nothing
end

function _pc_run_https_h2_server_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    listener = TL.listen(
        "tcp",
        "127.0.0.1:0",
        TL.Config(
            verify_peer = false,
            cert_file = _PC_TLS_CERT_PATH,
            key_file = _PC_TLS_KEY_PATH,
            alpn_protocols = ["h2"],
        );
        backlog = 8,
    )
    laddr = TL.addr(listener)::NC.SocketAddrV4
    address = ND.join_host_port("127.0.0.1", Int(laddr.port))
    server = HT.serve!(listener) do request
            _ = request
            return HT.Response(200; body = HT.BytesBody(UInt8[0x68, 0x32]), content_length = 2, proto_major = 2, proto_minor = 0)
        end
    client = HT.Client(
        transport = HT.Transport(
            tls_config = TL.Config(verify_peer = false, server_name = "localhost", alpn_protocols = ["h2"]),
            max_idle_per_host = 2,
            max_idle_total = 4,
        ),
        prefer_http2 = true,
    )
    try
        response = HT.get!(client, address, "/secure-h2"; secure = true, protocol = :h2)
        body_buf = Vector{UInt8}(undef, 2)
        read_n = HT.body_read!(response.body, body_buf)
        read_n == 2 || throw(ArgumentError("HTTPS h2 server precompile workload expected two-byte response body"))
    finally
        try
            close(client)
        catch
        end
        try
            HT.forceclose(server)
        catch
        end
        try
            wait(server)
        catch
        end
    end
    return nothing
end

"""
Run end-to-end HTTP/1 + HTTP/2 client/server requests through top-level APIs.
"""
function _pc_run_http_unified_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    h1_server = HT.serve!("127.0.0.1", 0; listenany = true) do request
            _ = request
            return HT.Response(200; body = HT.BytesBody(UInt8[0x68, 0x31]), content_length = 2)
        end
    h1_client = nothing
    h2_server = nothing
    h2_client = nothing
    try
        h1_address = _pc_wait_http_server_addr(h1_server)
        h1_client = HT.Client(transport = HT.Transport(max_idle_per_host = 2, max_idle_total = 4), prefer_http2 = true)
        _ = HT.get!(h1_client::HT.Client, h1_address::String, "/auto"; protocol = :auto)
        h2_server = HT.serve!("127.0.0.1", 0; listenany = true) do request
                _ = request
                return HT.Response(200; body = HT.BytesBody(UInt8[0x68, 0x32]), content_length = 2, proto_major = 2, proto_minor = 0)
            end
        h2_address = _pc_wait_http_server_addr(h2_server)
        h2_client = HT.Client(transport = HT.Transport(max_idle_per_host = 2, max_idle_total = 4), prefer_http2 = true)
        _ = HT.get!(h2_client::HT.Client, h2_address::String, "/h2"; protocol = :h2)
    finally
        try
            h1_client === nothing || close(h1_client::HT.Client)
        catch
        end
        try
            HT.forceclose(h1_server)
        catch
        end
        try
            wait(h1_server)
        catch
        end
        try
            h2_client === nothing || close(h2_client::HT.Client)
        catch
        end
        if h2_server !== nothing
            try
                HT.forceclose(h2_server)
            catch
            end
        end
        if h2_server !== nothing
            try
                wait(h2_server)
            catch
            end
        end
    end
    return nothing
end

try
    @setup_workload begin
        EL.__init__()
        @assert isassigned(EL.POLLER)
        # Keep all compile-time samples concrete and side-effectful so `--trim=safe`
        # builds have compiled coverage for the same paths used in tests and benchmarks.
        @compile_workload begin
            _pc_run_eventloops_workload!()
            _pc_run_internal_poll_workload!()
            _pc_run_socket_ops_workload!()
            _pc_run_tcp_workload!()
            _pc_run_host_resolvers_workload!()
            _pc_run_tls_workload!()
            _pc_run_http_core_workload!()
            _pc_run_http_transport_workload!()
            _pc_run_http_client_workload!()
            _pc_run_http_server_workload!()
            _pc_run_https_server_workload!()
            _pc_run_http2_workload!()
            _pc_run_http2_client_workload!()
            _pc_run_http2_server_workload!()
            _pc_run_https_h2_server_workload!()
            _pc_run_http_unified_workload!()
        end
    end
catch err
    @info "Ignoring an error that occurred during the precompilation workload" exception = (err, catch_backtrace())
end
