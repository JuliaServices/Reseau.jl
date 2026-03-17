"""
    IOPoll

Internal readiness polling and deadline management for network descriptors.

`IOPoll` owns:
- one dedicated native poller thread plus the platform backend integration
- descriptor registration and readiness waiters
- read/write deadlines and poller-managed timers
- the low-level `FD` wrapper used by higher transport layers

Higher layers call `register!`, `prepare_*`, `wait_*`, and timer helpers
instead of interacting with backend-specific handles directly.
"""
module IOPoll

using ..Reseau: ByteMemory, @gcsafe_ccall
using ..Reseau.SocketOps

include("3_iopoll_types.jl")
include("3_iopoll_errors.jl")
include("3_iopoll_runtime.jl")
include("3_iopoll_timers.jl")
include("3_iopoll_fdlock.jl")
include("3_iopoll_fd.jl")

@static if Sys.isapple()
    include("3_iopoll_backend_kqueue.jl")
elseif Sys.islinux()
    include("3_iopoll_backend_epoll.jl")
elseif Sys.iswindows()
    include("3_iopoll_backend_iocp.jl")
else
    include("3_iopoll_backend_kqueue.jl")
end

end
