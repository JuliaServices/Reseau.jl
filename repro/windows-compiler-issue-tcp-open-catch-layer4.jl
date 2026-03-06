using Reseau
const TCP = Reseau.TCP
const SocketOps = Reseau.SocketOps

function trigger()
    fd = TCP.open_tcp_fd!(; family = SocketOps.AF_INET)
    try
        return fd
    catch
        TCP.close!(fd)
        rethrow()
    end
end

Base.return_types(trigger, Tuple{})
