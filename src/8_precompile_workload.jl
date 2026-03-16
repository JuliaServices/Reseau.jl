# Production precompile workload. Helpers exercise real Reseau code paths so
# precompile artifacts stay aligned with the transport/runtime stack we ship.
using PrecompileTools: @compile_workload, @setup_workload

const EL = EventLoops
const IP = IOPoll
const SO = SocketOps
const NC = TCP
const ND = HostResolvers
const TL = TLS

@inline function _pc_is_generating_output()::Bool
    return ccall(:jl_generating_output, Cint, ()) == 1
end

@inline function _pc_runtime_supported()::Bool
    return Sys.isapple() || Sys.islinux()
end

function _pc_socketpair_stream()
    fds = Vector{Cint}(undef, 2)
    ret = ccall(:socketpair, Cint, (Cint, Cint, Cint, Ptr{Cint}), Cint(1), Cint(1), Cint(0), pointer(fds))
    ret == 0 || throw(SystemError("socketpair", Int(Base.Libc.errno())))
    return fds[1], fds[2]
end

function _pc_close_fd(fd::Cint)
    fd < 0 && return nothing
    ccall(:close, Cint, (Cint,), fd)
    return nothing
end

function _pc_write_byte(fd::Cint, b::UInt8)
    buf = Ref{UInt8}(b)
    n = ccall(:write, Cssize_t, (Cint, Ptr{UInt8}, Csize_t), fd, buf, Csize_t(1))
    n == Cssize_t(1) || throw(SystemError("write", Int(Base.Libc.errno())))
    return nothing
end

function _pc_read_exact!(conn::NC.Conn, buf::Vector{UInt8})::Int
    offset = 0
    while offset < length(buf)
        chunk = Vector{UInt8}(undef, length(buf) - offset)
        n = read!(conn, chunk)
        n > 0 || throw(EOFError())
        copyto!(buf, offset + 1, chunk, 1, n)
        offset += n
    end
    return offset
end

function _pc_wait_connect_ready!(fd::Cint)
    registration = EL.register!(fd; mode = EL.PollMode.WRITE)
    try
        EL.pollwait!(registration.write_waiter)
    finally
        EL.deregister!(fd)
    end
    return nothing
end

function _pc_accept_with_retry!(listener::Cint)::Cint
    for _ in 1:5000
        accepted, _, errno = SO.try_accept_socket(listener)
        accepted != -1 && return accepted
        if errno == Int32(Base.Libc.EAGAIN) || errno == Int32(Base.Libc.EWOULDBLOCK)
            yield()
            continue
        end
        errno == Int32(Base.Libc.EINTR) && continue
        throw(SystemError("accept", Int(errno)))
    end
    throw(ArgumentError("timed out waiting for accepted socket"))
end

function _pc_run_eventloops_workload!()
    EL.__init__()
    @assert isassigned(EL.POLLER)
    waiter = EL.PollWaiter()
    EL.pollnotify!(waiter)
    EL.pollwait!(waiter)
    _pc_runtime_supported() || return nothing
    state = EL.Poller()
    fd0 = Cint(-1)
    fd1 = Cint(-1)
    backend_open = false
    try
        errno = EL._backend_init!(state)
        errno == Int32(0) || throw(SystemError("event loop backend init", Int(errno)))
        backend_open = true
        fd0, fd1 = _pc_socketpair_stream()
        token = UInt64(1)
        registration = EL.Registration(fd0, token, EL.PollMode.READWRITE, EL.PollWaiter(), EL.PollWaiter(), false)
        state.registrations[fd0] = registration
        state.registrations_by_token[token] = registration
        errno = EL._backend_open_fd!(state, fd0, EL.PollMode.READWRITE, token)
        errno == Int32(0) || throw(SystemError("event loop open fd", Int(errno)))
        _pc_write_byte(fd1, 0x31)
        errno = EL._backend_poll_once!(state, Int64(0))
        errno == Int32(0) || throw(SystemError("event loop poll once", Int(errno)))
        EL.pollwait!(registration.read_waiter)
        errno = EL._backend_close_fd!(state, fd0)
        errno == Int32(0) || throw(SystemError("event loop close fd", Int(errno)))
    finally
        _pc_close_fd(fd0)
        _pc_close_fd(fd1)
        backend_open && EL._backend_close!(state)
    end
    return nothing
end

function _pc_run_internal_poll_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    fd0, fd1 = _pc_socketpair_stream()
    ipfd = IP.FD(fd0)
    fd0 = Cint(-1)
    try
        IP._set_nonblocking!(ipfd.sysfd)
        IP.init!(ipfd)
        IP.set_read_deadline!(ipfd, time_ns() + 8_000_000)
        try
            IP.read!(ipfd, Vector{UInt8}(undef, 1))
        catch err
            err isa IP.DeadlineExceededError || rethrow(err)
        end
        IP.set_read_deadline!(ipfd, Int64(0))
        _pc_write_byte(fd1, 0x66)
        n = IP.read!(ipfd, Vector{UInt8}(undef, 1))
        n == 1 || error("internal poll workload expected one-byte read")
    finally
        ipfd.sysfd >= 0 && close(ipfd)
        _pc_close_fd(fd1)
    end
    return nothing
end

function _pc_run_socket_ops_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    listener = Cint(-1)
    client = Cint(-1)
    accepted = Cint(-1)
    try
        listener = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        SO.set_sockopt_int(listener, SO.SOL_SOCKET, SO.SO_REUSEADDR, 1)
        SO.bind_socket(listener, SO.sockaddr_in_loopback(0))
        SO.listen_socket(listener, 16)
        bound = SO.get_socket_name_in(listener)
        port = Int(SO.sockaddr_in_port(bound))
        client = SO.open_socket(SO.AF_INET, SO.SOCK_STREAM)
        errno = SO.connect_socket(client, SO.sockaddr_in_loopback(port))
        if errno != Int32(0) && errno != Int32(Base.Libc.EISCONN)
            if errno != Int32(Base.Libc.EINPROGRESS) && errno != Int32(Base.Libc.EALREADY) && errno != Int32(Base.Libc.EINTR)
                throw(SystemError("connect", Int(errno)))
            end
            _pc_wait_connect_ready!(client)
            so_error = SO.get_socket_error(client)
            so_error == Int32(0) || throw(SystemError("connect(SO_ERROR)", Int(so_error)))
        end
        accepted = _pc_accept_with_retry!(listener)
        payload = UInt8[0x31, 0x32]
        nw = GC.@preserve payload SO.write_once!(client, pointer(payload), Csize_t(length(payload)))
        nw == Cssize_t(length(payload)) || throw(ArgumentError("socket ops workload expected 2-byte write"))
        recv_buf = Vector{UInt8}(undef, 2)
        nr = GC.@preserve recv_buf SO.read_once!(accepted, pointer(recv_buf), Csize_t(length(recv_buf)))
        nr == Cssize_t(length(recv_buf)) || throw(ArgumentError("socket ops workload expected 2-byte read"))
    finally
        accepted >= 0 && SO.close_socket_nothrow(accepted)
        client >= 0 && SO.close_socket_nothrow(client)
        listener >= 0 && SO.close_socket_nothrow(listener)
    end
    return nothing
end

function _pc_run_tcp_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    listener = nothing
    client = nothing
    server = nothing
    try
        listener = NC.listen(NC.loopback_addr(0); backlog = 16)
        laddr = NC.addr(listener)
        accept_task = errormonitor(Threads.@spawn NC.accept(listener))
        client = NC.connect(NC.loopback_addr(Int((laddr::NC.SocketAddrV4).port)))
        server = fetch(accept_task)
        payload = UInt8[0x41, 0x42, 0x43]
        written = write(client, payload)
        written == length(payload) || throw(ArgumentError("tcp workload expected 3-byte write"))
        recv_buf = Vector{UInt8}(undef, length(payload))
        _pc_read_exact!(server, recv_buf) == length(payload) || throw(EOFError())
    finally
        try
            server === nothing || close(server)
        catch
        end
        try
            client === nothing || close(client)
        catch
        end
        try
            listener === nothing || close(listener)
        catch
        end
    end
    return nothing
end

function _pc_run_host_resolvers_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    listener = nothing
    client = nothing
    server = nothing
    try
        listener = ND.listen("tcp", "127.0.0.1:0"; backlog = 16)
        laddr = NC.addr(listener)
        client = ND.connect("tcp", ND.join_host_port("127.0.0.1", Int((laddr::NC.SocketAddrV4).port)))
        server = NC.accept(listener)
        payload = UInt8[0x51, 0x52]
        written = write(client, payload)
        written == length(payload) || throw(ArgumentError("host resolver workload expected 2-byte write"))
        recv_buf = Vector{UInt8}(undef, length(payload))
        _pc_read_exact!(server, recv_buf) == length(payload) || throw(EOFError())
    finally
        try
            server === nothing || close(server)
        catch
        end
        try
            client === nothing || close(client)
        catch
        end
        try
            listener === nothing || close(listener)
        catch
        end
    end
    return nothing
end

function _pc_tls_resource_file(name::AbstractString)::Union{Nothing, String}
    pkg_root = normpath(joinpath(@__DIR__, ".."))
    path = joinpath(pkg_root, "test", "resources", name)
    return isfile(path) ? path : nothing
end

function _pc_run_tls_workload!()
    _pc_is_generating_output() && return nothing
    _pc_runtime_supported() || return nothing
    cert_path = _pc_tls_resource_file("unittests.crt")
    key_path = _pc_tls_resource_file("unittests.key")
    (cert_path === nothing || key_path === nothing) && return nothing
    listener = nothing
    client = nothing
    server = nothing
    try
        server_cfg = TL.Config(
            verify_peer = false,
            cert_file = cert_path::String,
            key_file = key_path::String,
            handshake_timeout_ns = 1_000_000_000,
        )
        listener = TL.listen("tcp", "127.0.0.1:0", server_cfg; backlog = 8)
        laddr = TL.addr(listener)::NC.SocketAddrV4
        accept_task = errormonitor(Threads.@spawn begin
            conn = TL.accept(listener::TL.Listener)
            TL.handshake!(conn)
            return conn
        end)
        client_cfg = TL.Config(
            verify_peer = false,
            server_name = "localhost",
            handshake_timeout_ns = 1_000_000_000,
        )
        client = TL.connect(
            "tcp",
            "127.0.0.1:$(Int(laddr.port))";
            server_name = client_cfg.server_name,
            verify_peer = client_cfg.verify_peer,
            client_auth = client_cfg.client_auth,
            cert_file = client_cfg.cert_file,
            key_file = client_cfg.key_file,
            ca_file = client_cfg.ca_file,
            client_ca_file = client_cfg.client_ca_file,
            alpn_protocols = copy(client_cfg.alpn_protocols),
            handshake_timeout_ns = client_cfg.handshake_timeout_ns,
            min_version = client_cfg.min_version,
            max_version = client_cfg.max_version,
        )
        status = EL.timedwait(() -> istaskdone(accept_task), 2.0; pollint = 0.001)
        status == :timed_out && throw(ArgumentError("TLS precompile workload timed out during accept"))
        server = fetch(accept_task)
        payload = UInt8[0x54, 0x4c, 0x53]
        recv_buf = Vector{UInt8}(undef, 3)
        written = write(client, payload)
        written == 3 || throw(ArgumentError("TLS precompile workload expected 3-byte write"))
        read_count = read!(server, recv_buf)
        read_count == 3 || throw(ArgumentError("TLS precompile workload expected 3-byte read"))
    finally
        try
            server === nothing || close(server)
        catch
        end
        try
            client === nothing || close(client)
        catch
        end
        try
            listener === nothing || close(listener)
        catch
        end
        EL.shutdown!()
    end
    return nothing
end

try
    @setup_workload begin
        EL.__init__()
        @assert isassigned(EL.POLLER)
        @compile_workload begin
            _pc_run_eventloops_workload!()
            _pc_run_internal_poll_workload!()
            _pc_run_socket_ops_workload!()
            _pc_run_tcp_workload!()
            _pc_run_host_resolvers_workload!()
            _pc_run_tls_workload!()
        end
    end
catch err
    @info "Ignoring an error that occurred during the precompilation workload" exception = (err, catch_backtrace())
end
