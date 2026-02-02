module AwsIO

using EnumX
using ScopedValues

# Debug flag for internal asserts
const DEBUG_BUILD = Ref(false)

const _deps_path = joinpath(@__DIR__, "..", "deps", "deps.jl")
if isfile(_deps_path)
    include(_deps_path)
else
    const libawsio_nw_shim = ""
end

# --- common ---
include("common/platform.jl")
include("common/macros.jl")
include("common/registry.jl")
include("common/assert.jl")
include("common/error.jl")
include("common/shutdown_types.jl")
include("common/logging_types.jl")
include("common/log_writer.jl")
include("common/log_channel.jl")
include("common/math.jl")
include("common/byte_order.jl")
include("common/zero.jl")
include("common/array_list.jl")
include("common/linked_list.jl")
include("common/priority_queue.jl")
include("common/byte_buf.jl")
include("common/file.jl")
include("common/string.jl")
include("common/hash_table.jl")
include("common/cache.jl")
include("common/lru_cache.jl")
include("common/clock.jl")
include("common/time.jl")
include("common/date_time.jl")
include("common/log_formatter.jl")
include("common/logging.jl")
include("common/statistics.jl")
include("common/device_random.jl")
include("common/encoding.jl")
include("common/system_info.jl")
include("common/uuid.jl")
include("common/mutex.jl")
include("common/condition_variable.jl")
include("common/thread.jl")
include("common/thread_shared.jl")
include("common/task_scheduler.jl")
include("common/thread_scheduler.jl")
include("common/common.jl")

# --- io ---
include("io/io.jl")
include("io/aws_byte_helpers.jl")
include("io/crypto_primitives.jl")
include("io/async_stream.jl")
include("io/tls_channel_handler.jl")
include("io/alpn_handler.jl")

end # module AwsIO
