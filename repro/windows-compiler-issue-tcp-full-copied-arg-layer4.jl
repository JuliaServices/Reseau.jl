using Reseau
const TCP = Reseau.TCP
const IOPoll = Reseau.IOPoll
const SocketOps = Reseau.SocketOps
const ADDR_FAMILY = getfield(TCP, Symbol("_addr_family"))
const APPLY_DEFAULT_TCP_OPTS! = getfield(TCP, Symbol("_apply_default_tcp_opts!"))
const BIND_CONNECTEX_LOCAL! = getfield(TCP, Symbol("_bind_connectex_local!"))
const WAIT_CONNECT_COMPLETE! = getfield(TCP, Symbol("_wait_connect_complete!"))

function connect_like(remote_addr::TCP.SocketAddr)::TCP.FD
    family = ADDR_FAMILY(remote_addr)
    fd = TCP.open_tcp_fd!(; family = family)
    try
        BIND_CONNECTEX_LOCAL!(fd, family)
        SocketOps.set_nonblocking!(fd.pfd.sysfd, true)
        IOPoll.init!(fd.pfd; net = :tcp, pollable = true)
        WAIT_CONNECT_COMPLETE!(fd, remote_addr)
        APPLY_DEFAULT_TCP_OPTS!(fd)
        return fd
    catch
        TCP.close!(fd)
        rethrow()
    end
end

Base.return_types(connect_like, Tuple{TCP.SocketAddrV4})
