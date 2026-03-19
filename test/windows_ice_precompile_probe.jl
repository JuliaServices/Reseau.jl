using Reseau

const TL = Reseau.TLS
const NC = Reseau.TCP
const ND = Reseau.HostResolvers
const IP = Reseau.IOPoll

const _CERT_PATH = joinpath(@__DIR__, "resources", "unittests.crt")
const _KEY_PATH = joinpath(@__DIR__, "resources", "unittests.key")

function _trace(label::AbstractString)
    println("[windows-ice-probe] ", label)
    flush(stdout)
    return nothing
end

function _close_quiet!(x)
    x === nothing && return nothing
    try
        close(x)
    catch
    end
    return nothing
end

function _wait_task_done(task::Task, timeout_s::Float64 = 2.0)
    return IP.timedwait(() -> istaskdone(task), timeout_s; pollint = 0.001)
end

function _ipv6_supported()::Bool
    listener = nothing
    try
        listener = NC.listen("tcp6", "[::1]:0"; backlog = 1)
        return true
    catch
        return false
    finally
        _close_quiet!(listener)
        IP.shutdown!()
    end
end

function _write_and_readback!(client, server)
    payload = UInt8[0x52, 0x45, 0x53]
    write(client, payload)
    recv_buf = Vector{UInt8}(undef, length(payload))
    read!(server, recv_buf)
    return nothing
end

function _tcp_server_pair(f::F) where {F}
    listener = nothing
    client = nothing
    server = nothing
    accept_task = nothing
    try
        listener = NC.listen("tcp", "127.0.0.1:0"; backlog = 4)
        port = Int((NC.addr(listener)::NC.SocketAddrV4).port)
        accept_task = errormonitor(@async NC.accept(listener))
        client = f(port)
        status = _wait_task_done(accept_task)
        status == :timed_out && error("timed out waiting for TCP accept")
        server = fetch(accept_task)
        _write_and_readback!(client, server)
    finally
        _close_quiet!(server)
        _close_quiet!(client)
        _close_quiet!(listener)
        IP.shutdown!()
    end
    return nothing
end

function _tcp6_server_pair(f::F) where {F}
    !_ipv6_supported() && return :skipped
    listener = nothing
    client = nothing
    server = nothing
    accept_task = nothing
    try
        listener = NC.listen("tcp6", "[::1]:0"; backlog = 4)
        port = Int((NC.addr(listener)::NC.SocketAddrV6).port)
        accept_task = errormonitor(@async NC.accept(listener))
        client = f(port)
        status = _wait_task_done(accept_task)
        status == :timed_out && error("timed out waiting for TCP6 accept")
        server = fetch(accept_task)
        _write_and_readback!(client, server)
    finally
        _close_quiet!(server)
        _close_quiet!(client)
        _close_quiet!(listener)
        IP.shutdown!()
    end
    return nothing
end

function _tls_server_pair(f::F) where {F}
    listener = nothing
    client = nothing
    server = nothing
    accept_task = nothing
    try
        server_cfg = TL.Config(
            verify_peer = false,
            cert_file = _CERT_PATH,
            key_file = _KEY_PATH,
            handshake_timeout_ns = 1_000_000_000,
        )
        listener = TL.listen(NC.loopback_addr(0), server_cfg; backlog = 4)
        port = Int((TL.addr(listener)::NC.SocketAddrV4).port)
        accept_task = errormonitor(@async begin
            conn = TL.accept(listener)
            TL.handshake!(conn)
            return conn
        end)
        client = f(port)
        status = _wait_task_done(accept_task, 3.0)
        status == :timed_out && error("timed out waiting for TLS accept")
        server = fetch(accept_task)
        _write_and_readback!(client, server)
    finally
        _close_quiet!(server)
        _close_quiet!(client)
        _close_quiet!(listener)
        IP.shutdown!()
    end
    return nothing
end

function probe_tcp_direct_v4()
    return _tcp_server_pair() do port
        NC.connect(NC.loopback_addr(port))
    end
end

function probe_tcp_kw_local_v4()
    return _tcp_server_pair() do port
        NC.connect("tcp", "127.0.0.1:$port"; local_addr = NC.loopback_addr(0))
    end
end

function probe_tcp_kw_local_v6()
    return _tcp6_server_pair() do port
        NC.connect("tcp6", ND.join_host_port("::1", port); local_addr = NC.loopback_addr6(0))
    end
end

function probe_tcp_kw_resolver()
    return _tcp_server_pair() do port
        resolver = ND.StaticResolver(hosts = Dict(
            "probe.test" => NC.SocketEndpoint[NC.loopback_addr(port)],
        ))
        NC.connect(
            "tcp",
            "probe.test:$port";
            resolver = resolver,
            timeout_ns = 1_000_000_000,
            fallback_delay_ns = -1,
        )
    end
end

function probe_tcp_deadline_error()
    err = try
        NC.connect("tcp", "127.0.0.1:1"; deadline_ns = time_ns() - 1)
        nothing
    catch ex
        ex
    end
    err === nothing && error("expected deadline failure")
    return nothing
end

function probe_tls_string()
    return _tls_server_pair() do port
        TL.connect(
            "tcp",
            "127.0.0.1:$port";
            server_name = "localhost",
            verify_peer = false,
            handshake_timeout_ns = 1_000_000_000,
        )
    end
end

function probe_tls_socketaddr()
    return _tls_server_pair() do port
        TL.connect(
            NC.loopback_addr(port),
            NC.loopback_addr(0);
            server_name = "localhost",
            verify_peer = false,
            handshake_timeout_ns = 1_000_000_000,
        )
    end
end

const PROBES = [
    ("tcp_direct_v4", probe_tcp_direct_v4),
    ("tcp_kw_local_v4", probe_tcp_kw_local_v4),
    ("tcp_kw_local_v6", probe_tcp_kw_local_v6),
    ("tcp_kw_resolver", probe_tcp_kw_resolver),
    ("tcp_deadline_error", probe_tcp_deadline_error),
    ("tls_string", probe_tls_string),
    ("tls_socketaddr", probe_tls_socketaddr),
]

for pass in 1:2
    _trace("pass=$pass begin")
    for (name, probe) in PROBES
        _trace("pass=$pass probe=$name start")
        outcome = try
            probe()
            "ok"
        catch err
            sprint(showerror, err, catch_backtrace())
        end
        _trace("pass=$pass probe=$name done outcome=$(replace(outcome, '\n' => ' '))")
    end
end
