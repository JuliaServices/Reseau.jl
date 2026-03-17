"""
    IOPoll

Go-style poll descriptor layer built on `EventLoops`.
Provides deadline-aware readiness waiting for network descriptors.

Conceptually this sits where Go's `internal/poll` package sits:
- `EventLoops` is the runtime-facing readiness engine
- `IOPoll` turns readiness and deadlines into descriptor-centric operations
- higher transport layers call `prepare_*`, `wait_*`, and deadline helpers
  instead of talking to the event loop directly
"""
module IOPoll

using EnumX
using ..Reseau: ByteMemory
using ..Reseau.EventLoops
using ..Reseau.SocketOps
import ..Reseau.EventLoops: deadline_fire!

const PollState = EventLoops.PollState

include("3_iopoll_errors.jl")
include("3_iopoll_fdlock.jl")
include("3_iopoll_fd.jl")

end
