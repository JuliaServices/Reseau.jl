using Reseau

const TL = Reseau.TLS
const NC = Reseau.TCP
const IP = Reseau.IOPoll
const SO = Reseau.SocketOps
const _LIBSSL = TL._LIBSSL
const _SSL_ERROR_WANT_READ = TL._SSL_ERROR_WANT_READ
const _SSL_ERROR_WANT_WRITE = TL._SSL_ERROR_WANT_WRITE
const _SSL_ERROR_SYSCALL = TL._SSL_ERROR_SYSCALL
const _tls_make_tls_error = TL._make_tls_error
const _tls_set_handshake_complete! = TL._set_handshake_complete!
const _tls_handshake_complete = TL._handshake_complete
const _tls_socket_would_block = TL._is_socket_would_block

const _TLS_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")

function _close_quiet!(x)
    x === nothing && return nothing
    try
        close(x)
    catch
    end
    return nothing
end

function _read_exact!(conn::TL.Conn, buf::Vector{UInt8})::Nothing
    read!(conn, buf)
    return nothing
end

function _handshake_step!(conn::TL.Conn)::Bool
    _tls_handshake_complete(conn) && return true
    ret = ccall((:SSL_do_handshake, _LIBSSL), Cint, (Ptr{Cvoid},), conn.ssl)
    if ret == 1
        _tls_set_handshake_complete!(conn)
        return true
    end
    ssl_err = ccall((:SSL_get_error, _LIBSSL), Cint, (Ptr{Cvoid}, Cint), conn.ssl, ret)
    if ssl_err == _SSL_ERROR_WANT_READ || ssl_err == _SSL_ERROR_WANT_WRITE
        return false
    end
    if ssl_err == _SSL_ERROR_SYSCALL
        errno = SO.last_error()
        _tls_socket_would_block(errno) && return false
        errno == Int32(0) && throw(TL.TLSError("handshake", ssl_err, "unexpected EOF", nothing))
        throw(TL.TLSError("handshake", ssl_err, "syscall errno=$(errno)", nothing))
    end
    throw(_tls_make_tls_error("handshake", Int32(ssl_err)))
end

function _handshake_pair!(client::TL.Conn, server::TL.Conn; max_iters::Int = 10_000)::Nothing
    client_done = _tls_handshake_complete(client)
    server_done = _tls_handshake_complete(server)
    for _ in 1:max_iters
        client_done || (client_done = _handshake_step!(client))
        server_done || (server_done = _handshake_step!(server))
        client_done && server_done && return nothing
        yield()
    end
    error("timed out driving TLS handshake pair")
end

function run_tls_trim_sample()::Nothing
    listener::Union{Nothing, TL.Listener} = nothing
    client_tcp::Union{Nothing, NC.Conn} = nothing
    client::Union{Nothing, TL.Conn} = nothing
    server::Union{Nothing, TL.Conn} = nothing
    try
        server_cfg = TL.Config(
            verify_peer = false,
            cert_file = _TLS_CERT_PATH,
            key_file = _TLS_KEY_PATH,
            handshake_timeout_ns = 10_000_000_000,
        )
        listener = TL.listen(NC.loopback_addr(0), server_cfg; backlog = 8)
        laddr = TL.addr(listener)::NC.SocketAddrV4
        client_tcp = NC.connect(NC.loopback_addr(Int(laddr.port)))
        server = TL.accept(listener)
        client = TL.client(
            client_tcp,
            TL.Config(
                verify_peer = false,
                server_name = "localhost",
                handshake_timeout_ns = 10_000_000_000,
            ),
        )
        client_tcp = nothing
        _handshake_pair!(client, server)
        TL.connection_state(client).handshake_complete || error("client handshake incomplete")
        TL.connection_state(server).handshake_complete || error("server handshake incomplete")
        payload = UInt8[0x54, 0x4c, 0x53]
        write(client, payload) == length(payload) || error("expected TLS payload write")
        recv_buf = Vector{UInt8}(undef, length(payload))
        _read_exact!(server, recv_buf)
        recv_buf == payload || error("TLS payload mismatch")
    finally
        _close_quiet!(server)
        _close_quiet!(client)
        _close_quiet!(client_tcp)
        _close_quiet!(listener)
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_tls_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
