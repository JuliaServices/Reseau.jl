using Reseau
const TCP = Reseau.TCP

Core.eval(TCP, quote
    const compiler_repro_const_addr = SocketAddrV4((UInt8(127), UInt8(0), UInt8(0), UInt8(1)), 8080)

    function compiler_repro_const_deadtail_emptytryfinally()::FD
        family = _addr_family(compiler_repro_const_addr)
        fd = open_tcp_fd!(; family = family)
        try
            _bind_connectex_local!(fd, family)
            SocketOps.set_nonblocking!(fd.pfd.sysfd, true)
            @static if Sys.iswindows()
                IOPoll.init!(fd.pfd; net = :tcp, pollable = true)
                _wait_connect_complete!(fd, compiler_repro_const_addr)
                _apply_default_tcp_opts!(fd)
                return fd
            end
            try
                nothing
            finally
                nothing
            end
            return fd
        catch
            close!(fd)
            rethrow()
        end
    end
end)

Base.return_types(TCP.compiler_repro_const_deadtail_emptytryfinally, Tuple{})
