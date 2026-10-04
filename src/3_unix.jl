"""
    Unix

Filesystem Unix-domain stream clients on Linux, macOS and FreeBSD.

Use `Reseau.Unix.connect(path)` to open a poll-driven `IO` connection. Reads,
writes, half-close and deadlines follow the same stream contracts as `TCP`.
The client owns its descriptor and never removes the server's socket path.
"""
module Unix

using ..Reseau.IOPoll
using ..Reseau.SocketOps
using ..Reseau.NetCommon: FD, _StreamConn, open_net_fd!, _is_temporary_unconnected
import ..Reseau.NetCommon: tryread!, closeread, rawfd,
    set_deadline!, set_read_deadline!, set_write_deadline!

"""
    Conn <: IO

A connected filesystem Unix-domain byte stream. Use [`connect`](@ref) to
create one. `close` releases the descriptor, wakes pending operations, and
leaves the server's filesystem path intact.
"""
struct Conn <: _StreamConn
    fd::FD
    path::String
end

"""
    DeadlineExceededError

Raised when a Unix connect, read or write exceeds its active deadline.
"""
const DeadlineExceededError = IOPoll.DeadlineExceededError

"""
    NetClosingError

Raised when an operation encounters a locally closed Unix connection,
including a pending operation woken by `close` from another task.
"""
const NetClosingError = IOPoll.NetClosingError

@inline function _connect_deadline_ns(timeout_ns::Int64, deadline_ns::Int64, now_ns::Int64)::Int64
    timeout_ns < 0 && return Int64(-1)
    timeout_deadline = timeout_ns == 0 ? Int64(0) : IOPoll._saturating_add_ns(now_ns, timeout_ns)
    timeout_deadline == 0 && return deadline_ns
    deadline_ns == 0 && return timeout_deadline
    return min(timeout_deadline, deadline_ns)
end

@inline function _check_connect_deadline(deadline_ns::Int64)
    deadline_ns != 0 && Int64(time_ns()) >= deadline_ns && throw(DeadlineExceededError())
    return nothing
end

@static if Sys.islinux() || Sys.isapple() || Sys.isfreebsd()
    @inline function _connect_pending(errno::Int32)::Bool
        return errno == Int32(Base.Libc.EINPROGRESS) || errno == Int32(Base.Libc.EALREADY) || errno == Int32(Base.Libc.EINTR)
    end

    function _wait_connected!(fd::FD)
        while true
            IOPoll.waitwrite(fd.pfd.pd)
            errno = SocketOps.get_socket_error(fd.pfd.sysfd)
            _connect_pending(errno) && continue
            errno == Int32(Base.Libc.EISCONN) && return nothing
            errno == 0 || throw(SystemError("connect", Int(errno)))
            try
                # Readiness may be spurious; SO_ERROR=0 alone is not proof of
                # a connected socket. This follows Go's netFD.connect check.
                SocketOps.check_peer_name_un(fd.pfd.sysfd)
                return nothing
            catch err
                err isa SystemError && _is_temporary_unconnected(err) && continue
                rethrow()
            end
        end
    end

    function _connect(path::String, timeout_ns::Int64, deadline_ns::Int64)::Conn
        addr = SocketOps.sockaddr_un(path)
        deadline = _connect_deadline_ns(timeout_ns, deadline_ns, Int64(time_ns()))
        _check_connect_deadline(deadline)
        fd = open_net_fd!(; family = SocketOps.AF_UNIX, sotype = SocketOps.SOCK_STREAM, net = :unix)
        try
            errno = SocketOps.connect_socket(fd.pfd.sysfd, addr, sizeof(path))
            if errno != 0 && errno != Int32(Base.Libc.EISCONN)
                _connect_pending(errno) || throw(SystemError("connect", Int(errno)))
                IOPoll.register!(fd.pfd)
                deadline != 0 && IOPoll.set_write_deadline!(fd.pfd, deadline)
                _wait_connected!(fd)
                _check_connect_deadline(deadline)
                deadline != 0 && IOPoll.set_write_deadline!(fd.pfd, Int64(0))
            else
                IOPoll.register!(fd.pfd)
            end
            # Include registration and deadline cleanup in the connect budget,
            # even when the kernel completes connect immediately.
            _check_connect_deadline(deadline)
            @atomic :release fd.is_connected = true
            return Conn(fd, path)
        catch
            try
                close(fd)
            catch
                # Preserve the original connection failure.
            end
            rethrow()
        end
    end
end

"""
    connect(path::AbstractString; timeout_ns=0, deadline_ns=0) -> Conn

Connect to a filesystem Unix-domain stream socket on Linux, macOS or FreeBSD.
The path is used as given, including relative paths. Empty paths, embedded NUL
and paths exceeding the platform's byte limit are rejected before opening a
socket. Linux abstract names and Windows named pipes are not supported.

`timeout_ns` is a relative connect budget in nanoseconds. `deadline_ns` is an
absolute monotonic timestamp on the `time_ns()` clock. Zero disables either
limit; when both are set, the earlier deadline applies. Relative addition
saturates at `typemax(Int64)`. Negative budgets and elapsed deadlines fail with
`DeadlineExceededError`. Both inputs must fit in `Int64`.

The connect deadline is cleared on success. Use `set_read_deadline!`,
`set_write_deadline!` or `set_deadline!` for subsequent operations. Native
connection failures throw `SystemError` with the original OS error code.
Unsupported platforms throw `ArgumentError` without opening a descriptor.
"""
function connect(path::AbstractString; timeout_ns::Integer = 0, deadline_ns::Integer = 0)::Conn
    @static if Sys.islinux() || Sys.isapple() || Sys.isfreebsd()
        return _connect(String(path), Int64(timeout_ns), Int64(deadline_ns))
    else
        throw(ArgumentError("filesystem Unix socket clients are supported on Linux, macOS and FreeBSD"))
    end
end

function Base.show(io::IO, conn::Conn)
    print(io, "Unix.Conn(")
    show(io, conn.path)
    print(io, ", ", isopen(conn) ? "open" : "closed", ")")
    return nothing
end

end
