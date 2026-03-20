"""
    IOPoll

Internal readiness polling and deadline management for network descriptors.

`IOPoll` owns:
- one dedicated native poller thread plus the platform backend integration
- descriptor registration and readiness waiters
- read/write deadlines and poller-managed timers
- the low-level `FD` wrapper used by higher transport layers

Higher layers call `register!`, `prepareread`, `preparewrite`, `waitread`,
`waitwrite`, and timer helpers instead of interacting with backend-specific
handles directly.
"""
module IOPoll

using ..Reseau: ByteMemory, MutableByteBuffer, @gcsafe_ccall
using ..Reseau.SocketOps

include("iopoll/types.jl")
include("iopoll/errors.jl")
include("iopoll/runtime.jl")
include("iopoll/timers.jl")
include("iopoll/fdlock.jl")
include("iopoll/fd.jl")

@static if Sys.isapple()
    include("iopoll/kqueue.jl")
elseif Sys.islinux()
    include("iopoll/epoll.jl")
elseif Sys.iswindows()
    include("iopoll/iocp.jl")
else
    include("iopoll/kqueue.jl")
end

end
