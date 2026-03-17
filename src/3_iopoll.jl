"""
    IOPoll

Go-style polling and runtime netpoll layer for network descriptors.

This merged module now spans both of the Go-inspired layers that used to be
split between `runtime/netpoll`-like machinery and `internal/poll`-like fd
operations:
- one dedicated native poller thread blocks in the platform poll syscall
- registrations own one read waiter and one write waiter per descriptor
- deadlines and timers live inside the shared poller heap
- higher transport layers call `register!`, `prepare_*`, `wait_*`, and fd/timer
  helpers instead of talking to backend-specific handles directly
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
