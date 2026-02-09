module Reseau

using EnumX
using ScopedValues
import UUIDs

# Debug flag for internal asserts
const DEBUG_BUILD = Ref(false)

# --- common ---
include("common/platform.jl")
include("common/assert.jl")
include("common/error.jl")
include("common/shutdown_types.jl")
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
include("threads/threads.jl")
include("eventloops/eventloops.jl")
include("sockets/sockets.jl")

function __init__()
    Threads._init_os_thread_cfunc!()
    Sockets.io_library_init()
end

end # module Reseau
