using Reseau

const TL = Reseau.TLS
const NC = Reseau.TCP
const IP = Reseau.IOPoll
const SO = Reseau.SocketOps

const _TLS_CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _TLS_KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")

function _raw_connected_client(port::Int)::NC.Conn
    sysfd = Cint(-1)
    try
        sysfd = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        SO.set_nonblocking!(sysfd, false)
        try
            errno = SO.connect_socket(sysfd, SO.sockaddr_in_loopback(port))
            errno == Int32(0) || errno == Int32(Base.Libc.EISCONN) || throw(SystemError("connect", Int(errno)))
        finally
            SO.set_nonblocking!(sysfd, true)
        end
        fd = NC._new_netfd(sysfd; family = SO.AF_INET, sotype = SO.SOCK_STREAM, net = :tcp, is_connected = true)
        sysfd = Cint(-1)
        IP.register!(fd.pfd)
        NC._apply_default_tcp_opts!(fd)
        NC._finalize_connected_addrs!(fd, NC.loopback_addr(port))
        return NC.Conn(fd)
    catch
        sysfd >= 0 && SO.close_socket_nothrow(sysfd)
        rethrow()
    end
end

function run_tls_trim_sample()::Nothing
    listener::Union{Nothing, NC.Listener} = nothing
    client_tcp::Union{Nothing, NC.Conn} = nothing
    server_tcp::Union{Nothing, NC.Conn} = nothing
    client_tls::Union{Nothing, TL.Conn} = nothing
    server_tls::Union{Nothing, TL.Conn} = nothing
    try
        listener = NC.listen(NC.loopback_addr(0); backlog = 8)
        laddr = NC.addr(listener)::NC.SocketAddrV4
        client_tcp = _raw_connected_client(Int(laddr.port))
        IP.set_read_deadline!(listener.fd.pfd, time_ns() + 5_000_000_000)
        try
            server_tcp = NC.accept(listener)
        finally
            IP.set_read_deadline!(listener.fd.pfd, Int64(0))
        end
        client_cfg = TL.Config(verify_peer = false, server_name = "localhost", handshake_timeout_ns = 10_000_000_000)
        server_cfg = TL.Config(
            verify_peer = false,
            cert_file = _TLS_CERT_PATH,
            key_file = _TLS_KEY_PATH,
            handshake_timeout_ns = 10_000_000_000,
        )
        client_tls = TL.client(client_tcp, client_cfg)
        server_tls = TL.server(server_tcp, server_cfg)
        _ = TL.connection_state(client_tls)
        _ = TL.connection_state(server_tls)
    finally
        if server_tls !== nothing
            try
                close(server_tls::TL.Conn)
            catch
            end
        elseif server_tcp !== nothing
            try
                close(server_tcp::NC.Conn)
            catch
            end
        end
        if client_tls !== nothing
            try
                close(client_tls::TL.Conn)
            catch
            end
        elseif client_tcp !== nothing
            try
                close(client_tcp::NC.Conn)
            catch
            end
        end
        if listener !== nothing
            try
                close(listener::NC.Listener)
            catch
            end
        end
        IP.shutdown!()
    end
    return nothing
end

function @main(args::Vector{String})::Cint
    _ = args
    run_tls_trim_sample()
    return 0
end

Base.Experimental.entrypoint(main, (Vector{String},))
