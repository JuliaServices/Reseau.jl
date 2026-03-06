using Reseau
const TCP = Reseau.TCP

Core.eval(TCP, quote
    function compiler_repro_bind_init_catch()::FD
        fd = open_tcp_fd!(; family = SocketOps.AF_INET)
        try
            _bind_connectex_local!(fd, SocketOps.AF_INET)
            SocketOps.set_nonblocking!(fd.pfd.sysfd, true)
            IOPoll.init!(fd.pfd; net = :tcp, pollable = true)
            return fd
        catch
            close!(fd)
            rethrow()
        end
    end
end)

Base.return_types(TCP.compiler_repro_bind_init_catch, Tuple{})
