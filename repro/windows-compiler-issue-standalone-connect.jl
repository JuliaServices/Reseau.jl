module WindowsCompilerStandaloneConnect

module SocketOps
const AF_INET = Int32(2)
const AF_INET6 = Int32(23)
const SOCK_STREAM = Int32(1)
const SOL_SOCKET = Int32(0xffff)
const SO_KEEPALIVE = Int32(0x0008)
const SO_REUSEADDR = Int32(0x0004)
const IPPROTO_TCP = Int32(6)
const TCP_NODELAY = Int32(0x01)
struct SockAddrIn end
sockaddr_in_any(port::Integer) = port
sockaddr_in6_any(port::Integer) = port
bind_socket(args...) = nothing
set_nonblocking!(args...) = nothing
set_sockopt_int(args...) = nothing
open_socket(args...) = 1
end

module IOPoll
export FD, DeadlineExceededError, init!, connect!, set_write_deadline!, close!
struct DeadlineExceededError <: Exception end
mutable struct FD
    sysfd::Int
end
init!(args...; kwargs...) = nothing
connect!(args...) = nothing
set_write_deadline!(args...) = nothing
close!(args...) = nothing
end

abstract type SocketAddr end
struct SocketAddrV4 <: SocketAddr end
struct SocketAddrV6 <: SocketAddr end
struct ConnectCanceledError <: Exception end

struct FD
    pfd::IOPoll.FD
end

_addr_family(::SocketAddrV4) = SocketOps.AF_INET
_addr_family(::SocketAddrV6) = SocketOps.AF_INET6
_to_sockaddr(::SocketAddrV4) = SocketOps.SockAddrIn()
_to_sockaddr(::SocketAddrV6) = SocketOps.SockAddrIn()
_apply_default_tcp_opts!(fd::FD) = begin
    try
        SocketOps.set_sockopt_int(fd.pfd.sysfd, SocketOps.IPPROTO_TCP, SocketOps.TCP_NODELAY, 1)
    catch
    end
    try
        SocketOps.set_sockopt_int(fd.pfd.sysfd, SocketOps.SOL_SOCKET, SocketOps.SO_KEEPALIVE, 1)
    catch
    end
    return nothing
end
_finalize_connected_addrs!(fd::FD, remote_addr::SocketAddr) = nothing
_connect_wait_register!(cancel_state, fd) = nothing
_connect_wait_unregister!(cancel_state, fd) = nothing
_connect_canceled(cancel_state) = false

function _wait_connect_complete!(
        fd::FD,
        remote_addr::SocketAddr;
        cancel_state = nothing,
    )
    _connect_wait_register!(cancel_state, fd)
    try
        @static if Sys.iswindows()
            sockaddr = _to_sockaddr(remote_addr)
            addrbuf = UInt8[]
            addrlen = Int32(sizeof(typeof(sockaddr)))
            while true
                if _connect_canceled(cancel_state)
                    throw(ConnectCanceledError())
                end
                try
                    IOPoll.connect!(fd.pfd, addrbuf, addrlen)
                catch err
                    ex = err::Exception
                    if ex isa IOPoll.DeadlineExceededError && _connect_canceled(cancel_state)
                        throw(ConnectCanceledError())
                    end
                    rethrow(ex)
                end
                _finalize_connected_addrs!(fd, remote_addr)
                return nothing
            end
        end
        return nothing
    finally
        _connect_wait_unregister!(cancel_state, fd)
    end
end

_bind_connectex_local!(fd::FD, family::Int32) = begin
    if family == SocketOps.AF_INET6
        SocketOps.bind_socket(fd.pfd.sysfd, SocketOps.sockaddr_in6_any(0))
        return nothing
    end
    SocketOps.bind_socket(fd.pfd.sysfd, SocketOps.sockaddr_in_any(0))
    return nothing
end

open_tcp_fd!(; family::Int32 = SocketOps.AF_INET) = FD(IOPoll.FD(SocketOps.open_socket(family, SocketOps.SOCK_STREAM)))
close!(fd::FD) = IOPoll.close!(fd.pfd)

function connect_tcp_fd!(
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
                _wait_connect_complete!(
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
            _apply_default_tcp_opts!(fd)
            return fd
        end
        return fd
    catch
        close!(fd)
        rethrow()
    end
end

const KW = NamedTuple{(:local_addr, :connect_deadline_ns, :cancel_state), Tuple{Nothing, Int64, Nothing}}
Base.return_types(Core.kwcall, Tuple{KW, typeof(connect_tcp_fd!), SocketAddrV4})

end
