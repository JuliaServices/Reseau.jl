using Reseau
const TCP = Reseau.TCP
const IOPoll = Reseau.IOPoll
const SocketOps = Reseau.SocketOps
const ADDR_FAMILY = getfield(TCP, Symbol("_addr_family"))
const APPLY_DEFAULT_TCP_OPTS! = getfield(TCP, Symbol("_apply_default_tcp_opts!"))
const BIND_CONNECTEX_LOCAL! = getfield(TCP, Symbol("_bind_connectex_local!"))
const TO_SOCKADDR = getfield(TCP, Symbol("_to_sockaddr"))
const WAIT_CONNECT_COMPLETE! = getfield(TCP, Symbol("_wait_connect_complete!"))
const KW = NamedTuple{(:local_addr, :connect_deadline_ns, :cancel_state), Tuple{Nothing, Int64, Nothing}}

function connect_like(
        remote_addr::TCP.SocketAddr;
        local_addr::Union{Nothing, TCP.SocketAddr} = nothing,
        connect_deadline_ns::Integer = Int64(0),
        cancel_state = nothing,
    )::TCP.FD
    family = ADDR_FAMILY(remote_addr)
    if local_addr !== nothing && ADDR_FAMILY(local_addr) != family
        throw(ArgumentError("local and remote address families must match"))
    end
    fd = TCP.open_tcp_fd!(; family = family)
    try
        if local_addr !== nothing
            SocketOps.bind_socket(fd.pfd.sysfd, TO_SOCKADDR(local_addr))
        else
            BIND_CONNECTEX_LOCAL!(fd, family)
        end
        SocketOps.set_nonblocking!(fd.pfd.sysfd, true)
        IOPoll.init!(fd.pfd; net = :tcp, pollable = true)
        if connect_deadline_ns != 0
            IOPoll.set_write_deadline!(fd.pfd, connect_deadline_ns)
        end
        try
            WAIT_CONNECT_COMPLETE!(fd, remote_addr; cancel_state = cancel_state)
        finally
            if connect_deadline_ns != 0
                try
                    IOPoll.set_write_deadline!(fd.pfd, Int64(0))
                catch
                end
            end
        end
        APPLY_DEFAULT_TCP_OPTS!(fd)
        return fd
    catch
        TCP.close!(fd)
        rethrow()
    end
end

Base.return_types(Core.kwcall, Tuple{KW, typeof(connect_like), TCP.SocketAddrV4})
