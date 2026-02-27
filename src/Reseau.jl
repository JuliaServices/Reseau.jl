module Reseau

using EnumX
using PrecompileTools: @compile_workload, @setup_workload
using ScopedValues
import UUIDs

# Debug flag for internal asserts
const DEBUG_BUILD = Ref(false)

# --- shared runtime ---
include("error.jl")
include("utils.jl")
include("logging.jl")
include("byte_buf.jl")
include("clock.jl")

# --- public submodules (native implementations) ---
include("foreign_threads.jl")
include("task_scheduler.jl")
include("eventloops/eventloops.jl")
include("retry_strategy.jl")
include("sockets/sockets.jl")
include("precompile_workload.jl")

function __init__()
    ForeignThreads.__init__()
    EventLoops.__init__()
    Sockets.io_library_init()
end

end # module Reseau
