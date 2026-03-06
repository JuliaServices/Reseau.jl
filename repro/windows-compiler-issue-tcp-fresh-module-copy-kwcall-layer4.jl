using Reseau

module FreshTCPCompilerReproKw
using ..Reseau

const TCP = Reseau.TCP
const IOPoll = Reseau.IOPoll
const SocketOps = Reseau.SocketOps
const SocketAddr = TCP.SocketAddr
const SocketAddrV4 = TCP.SocketAddrV4
const FD = TCP.FD
const _addr_family = TCP._addr_family
const _apply_default_tcp_opts! = TCP._apply_default_tcp_opts!
const _bind_connectex_local! = TCP._bind_connectex_local!
const _to_sockaddr = TCP._to_sockaddr
const _wait_connect_complete! = TCP._wait_connect_complete!
const close! = TCP.close!
const open_tcp_fd! = TCP.open_tcp_fd!

function connect_like(
        remote_addr::SocketAddr;
        local_addr::Union{Nothing, SocketAddr} = nothing,
        connect_deadline_ns::Integer = Int64(0),
        cancel_state = nothing,
    )::FD
    family = _addr_family(remote_addr)
    if local_addr !== nothing && _addr_family(local_addr) != family
        throw(ArgumentError("local and remote address families must match"))
    end
    fd = open_tcp_fd!(; family = family)
    try
        if local_addr !== nothing
            SocketOps.bind_socket(fd.pfd.sysfd, _to_sockaddr(local_addr))
        else
            _bind_connectex_local!(fd, family)
        end
        SocketOps.set_nonblocking!(fd.pfd.sysfd, true)
        IOPoll.init!(fd.pfd; net = :tcp, pollable = true)
        if connect_deadline_ns != 0
            IOPoll.set_write_deadline!(fd.pfd, connect_deadline_ns)
        end
        try
            _wait_connect_complete!(fd, remote_addr; cancel_state = cancel_state)
        finally
            if connect_deadline_ns != 0
                try
                    IOPoll.set_write_deadline!(fd.pfd, Int64(0))
                catch
                end
            end
        end
        _apply_default_tcp_opts!(fd)
        return fd
    catch
        close!(fd)
        rethrow()
    end
end

end

const KW = NamedTuple{(:local_addr, :connect_deadline_ns, :cancel_state), Tuple{Nothing, Int64, Nothing}}
Base.return_types(Core.kwcall, Tuple{KW, typeof(FreshTCPCompilerReproKw.connect_like), FreshTCPCompilerReproKw.SocketAddrV4})
