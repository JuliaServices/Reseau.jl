using Reseau
const TCP = Reseau.TCP

Core.eval(TCP, quote
    const compiler_repro_alias_addr_family = _addr_family
    const compiler_repro_alias_apply_default_tcp_opts! = _apply_default_tcp_opts!
    const compiler_repro_alias_bind_connectex_local! = _bind_connectex_local!
    const compiler_repro_alias_close! = close!
    const compiler_repro_alias_open_tcp_fd! = open_tcp_fd!
    const compiler_repro_alias_to_sockaddr = _to_sockaddr
    const compiler_repro_alias_wait_connect_complete! = _wait_connect_complete!

    function compiler_repro_connect_alias(
            remote_addr::SocketAddr;
            local_addr::Union{Nothing, SocketAddr} = nothing,
            connect_deadline_ns::Integer = Int64(0),
            cancel_state = nothing,
        )::FD
        family = compiler_repro_alias_addr_family(remote_addr)
        if local_addr !== nothing && compiler_repro_alias_addr_family(local_addr) != family
            throw(ArgumentError("local and remote address families must match"))
        end
        fd = compiler_repro_alias_open_tcp_fd!(; family = family)
        try
            if local_addr !== nothing
                SocketOps.bind_socket(fd.pfd.sysfd, compiler_repro_alias_to_sockaddr(local_addr))
            elseif Sys.iswindows()
                compiler_repro_alias_bind_connectex_local!(fd, family)
            end
            SocketOps.set_nonblocking!(fd.pfd.sysfd, true)
            @static if Sys.iswindows()
                IOPoll.init!(fd.pfd; net = :tcp, pollable = true)
                if connect_deadline_ns != 0
                    IOPoll.set_write_deadline!(fd.pfd, connect_deadline_ns)
                end
                try
                    compiler_repro_alias_wait_connect_complete!(
                        fd,
                        remote_addr;
                        cancel_state = cancel_state,
                    )
                finally
                    if connect_deadline_ns != 0
                        try
                            IOPoll.set_write_deadline!(fd.pfd, Int64(0))
                        catch
                        end
                    end
                end
                compiler_repro_alias_apply_default_tcp_opts!(fd)
                return fd
            end
            errno = SocketOps.connect_socket(fd.pfd.sysfd, compiler_repro_alias_to_sockaddr(remote_addr))
            if errno == Int32(0) || errno == Int32(Base.Libc.EISCONN)
                IOPoll.init!(fd.pfd; net = :tcp, pollable = true)
                _finalize_connected_addrs!(fd, remote_addr)
                compiler_repro_alias_apply_default_tcp_opts!(fd)
                return fd
            end
            _is_connect_pending_errno(errno) || throw(SystemError("connect", Int(errno)))
            IOPoll.init!(fd.pfd; net = :tcp, pollable = true)
            if connect_deadline_ns != 0
                IOPoll.set_write_deadline!(fd.pfd, connect_deadline_ns)
            end
            try
                compiler_repro_alias_wait_connect_complete!(
                    fd,
                    remote_addr;
                    cancel_state = cancel_state,
                )
            finally
                if connect_deadline_ns != 0
                    try
                        IOPoll.set_write_deadline!(fd.pfd, Int64(0))
                    catch
                    end
                end
            end
            compiler_repro_alias_apply_default_tcp_opts!(fd)
            return fd
        catch
            compiler_repro_alias_close!(fd)
            rethrow()
        end
    end
end)

Base.return_types(TCP.compiler_repro_connect_alias, Tuple{TCP.SocketAddrV4})
