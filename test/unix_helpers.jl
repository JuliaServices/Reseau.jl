module UnixTestHelpers

using Reseau
const U = Reseau.Unix
const NC = Reseau.NetCommon
const IP = Reseau.IOPoll
const SO = Reseau.SocketOps

# The feature is client-only. Test listeners use the native socket layer,
# keeping the public entrypoint under test Unix.connect.
function listener(path::String; backlog::Int = 16)
    fd = NC.open_net_fd!(; family = SO.AF_UNIX, net = :unix)
    try
        addr = Ref(SO.sockaddr_un(path))
        GC.@preserve addr SO.bind_socket(fd.pfd.sysfd,
            Base.unsafe_convert(Ptr{Cvoid}, addr), SO.SockLen(3 + sizeof(path)))
        SO.listen_socket(fd.pfd.sysfd, backlog)
        IP.register!(fd.pfd)
        return fd
    catch
        close(fd)
        rethrow()
    end
end

function accept(fd::NC.FD, path::String)
    sysfd, _ = IP.accept!(fd.pfd, fd.family, fd.sotype)
    child = NC._new_netfd(sysfd; family = SO.AF_UNIX, net = :unix, is_connected = true)
    try
        IP.register!(child.pfd)
        return U.Conn(child, path)
    catch
        close(child)
        rethrow()
    end
end

function with_pair(f::F, path::String; kwargs...) where {F}
    listening = listener(path)
    client = nothing
    server = nothing
    try
        client = U.connect(path; kwargs...)
        server = accept(listening, path)
        return f(client, server)
    finally
        server === nothing || close(server)
        client === nothing || close(client)
        close(listening)
    end
end

function with_pair(f::F; kwargs...) where {F}
    return mktempdir("/tmp"; prefix = "reseau-unix-") do dir
        with_pair(f, joinpath(dir, "s"); kwargs...)
    end
end

function wait_parked(task::Task, waiter::IP.PollWaiter)
    while !((@atomic :acquire waiter.state) isa Task) && !istaskdone(task)
        yield()
    end
    return !istaskdone(task)
end

end
