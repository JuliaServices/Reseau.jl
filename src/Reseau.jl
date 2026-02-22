module Reseau

using EnumX
using PrecompileTools: @compile_workload, @setup_workload
using ScopedValues
import UUIDs

# Debug flag for internal asserts
const DEBUG_BUILD = Ref(false)

# --- common ---
include("common/platform.jl")
include("common/assert.jl")
include("common/error.jl")
include("common/logging_types.jl")
include("common/log_writer.jl")
include("common/log_channel.jl")
include("common/math.jl")
include("common/zero.jl")
include("common/priority_queue.jl")
include("common/byte_buf.jl")
include("common/lru_cache.jl")
include("common/clock.jl")
include("common/log_formatter.jl")
include("common/logging.jl")
include("common/statistics.jl")

# --- public submodules (native implementations) ---
include("foreign_threads.jl")
include("task_scheduler.jl")
include("eventloops/eventloops.jl")
include("sockets/sockets.jl")
include("precompile_workload.jl")

function __init__()
    ForeignThreads.__init__()
    EventLoops.__init__()
    Sockets.io_library_init()
end

end # module Reseau
