using Reseau
const TCP = Reseau.TCP
const IOPoll = Reseau.IOPoll
const SocketOps = Reseau.SocketOps
const BIND_CONNECTEX_LOCAL! = getfield(TCP, Symbol("_bind_connectex_local!"))

function trigger()
    fd = TCP.open_tcp_fd!(; family = SocketOps.AF_INET)
    try
        BIND_CONNECTEX_LOCAL!(fd, SocketOps.AF_INET)
        SocketOps.set_nonblocking!(fd.pfd.sysfd, true)
        IOPoll.init!(fd.pfd; net = :tcp, pollable = true)
        return fd
    catch
        TCP.close!(fd)
        rethrow()
    end
end

Base.return_types(trigger, Tuple{})
