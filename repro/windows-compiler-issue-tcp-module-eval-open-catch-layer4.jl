using Reseau
const TCP = Reseau.TCP

Core.eval(TCP, quote
    function compiler_repro_open_catch()::FD
        fd = open_tcp_fd!(; family = SocketOps.AF_INET)
        try
            return fd
        catch
            close!(fd)
            rethrow()
        end
    end
end)

Base.return_types(TCP.compiler_repro_open_catch, Tuple{})
