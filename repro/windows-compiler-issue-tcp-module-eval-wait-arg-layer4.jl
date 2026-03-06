using Reseau
const TCP = Reseau.TCP

Core.eval(TCP, quote
    function compiler_repro_wait_arg(remote_addr::SocketAddr)::FD
        family = _addr_family(remote_addr)
        fd = open_tcp_fd!(; family = family)
        try
            _bind_connectex_local!(fd, family)
            SocketOps.set_nonblocking!(fd.pfd.sysfd, true)
            IOPoll.init!(fd.pfd; net = :tcp, pollable = true)
            _wait_connect_complete!(fd, remote_addr)
            _apply_default_tcp_opts!(fd)
            return fd
        catch
            close!(fd)
            rethrow()
        end
    end
end)

Base.return_types(TCP.compiler_repro_wait_arg, Tuple{TCP.SocketAddrV4})
