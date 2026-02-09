module Reseau

using EnumX
using ScopedValues
import UUIDs

# Debug flag for internal asserts
const DEBUG_BUILD = Ref(false)

	# --- common ---
	include("common/platform.jl")
	include("common/macros.jl")
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
	include("common/cache.jl")
	include("common/lru_cache.jl")
	include("common/clock.jl")
	include("common/log_formatter.jl")
	include("common/logging.jl")
	include("common/statistics.jl")

	# --- public submodules (native implementations) ---
	include("threads/threads.jl")
include("sockets/sockets.jl")

# Re-alias moved bindings back into the parent module so existing call-sites
# (including downstream packages) can keep referencing `Reseau.*`.
function _alias_module_bindings!(src_mod::Module)::Nothing
    for name in names(src_mod; all = true, imported = false)
        str = String(name)
        startswith(str, "@") && continue
        startswith(str, "#") && continue
        if isdefined(@__MODULE__, name)
            # Allow overwriting Base/Core imports (we want the moved implementation
            # bindings), but never clobber bindings defined by this module.
            owner = Base.binding_module(@__MODULE__, name)
            owner === (@__MODULE__) && continue
            (owner === Base || owner === Core) || continue
        end
        val = getfield(src_mod, name)
        @eval const $(name) = $src_mod.$(name)
    end
    return nothing
end

_alias_module_bindings!(Threads)
_alias_module_bindings!(Sockets)

# --- thin wrappers / grouped surfaces ---
include("EventLoops.jl")

function __init__()
    Threads._init_os_thread_cfunc!()
    io_library_init()
end

end # module Reseau
