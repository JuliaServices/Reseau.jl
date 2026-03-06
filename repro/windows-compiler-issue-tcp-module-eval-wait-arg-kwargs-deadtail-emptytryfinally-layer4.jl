using Reseau
const TCP = Reseau.TCP

Core.eval(TCP, quote
    function compiler_repro_wait_arg_kwargs_deadtail_emptytryfinally(
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
            elseif Sys.iswindows()
                _bind_connectex_local!(fd, family)
            end
            SocketOps.set_nonblocking!(fd.pfd.sysfd, true)
            @static if Sys.iswindows()
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

const KW = NamedTuple{(:local_addr, :connect_deadline_ns, :cancel_state), Tuple{Nothing, Int64, Nothing}}
Base.return_types(Core.kwcall, Tuple{KW, typeof(TCP.compiler_repro_wait_arg_kwargs_deadtail_emptytryfinally), TCP.SocketAddrV4})
