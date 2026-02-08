module Reseau

using EnumX
using ScopedValues

# Debug flag for internal asserts
const DEBUG_BUILD = Ref(false)

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
include("common/zero.jl")
include("common/priority_queue.jl")
include("common/byte_buf.jl")
include("common/file.jl")
include("common/string.jl")
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
include("common/condition_variable.jl")
include("common/thread.jl")
include("common/thread_shared.jl")
include("common/task_scheduler.jl")
include("common/common.jl")

# --- io ---
include("io/io.jl")

# Previously included from src/io/io.jl (same order preserved)
include("io/tracing.jl")
include("io/event_loop_types.jl")
include("io/kqueue_event_loop_types.jl")
include("io/epoll_event_loop_types.jl")
include("io/iocp_event_loop_types.jl")
include("io/event_loop.jl")
include("io/kqueue_event_loop.jl")
include("io/epoll_event_loop.jl")
include("io/iocp_event_loop.jl")
include("io/message_pool.jl")
include("io/posix_socket_types.jl")
include("io/apple_nw_socket_types.jl")
include("io/winsock_socket_types.jl")
include("io/socket.jl")
include("io/posix_socket_impl.jl")
include("io/winsock_socket.jl")
include("io/winsock_init.jl")
include("io/blocks_abi.jl")
include("io/apple_nw_socket_impl.jl")
include("io/channel.jl")
include("io/statistics.jl")
include("io/socket_channel_handler.jl")
include("io/host_resolver.jl")
include("io/retry_strategy.jl")
include("io/stream.jl")
include("io/pem.jl")
include("io/shared_library.jl")
include("io/pkcs11.jl")
include("io/pki_utils.jl")
include("io/pipe.jl")
include("io/iocp_pipe.jl")
include("io/future.jl")
include("io/channel_bootstrap.jl")

# Previously included directly from src/Reseau.jl
include("io/aws_byte_helpers.jl")
include("io/crypto_primitives.jl")
include("io/async_stream.jl")
include("io/tls_channel_handler.jl")
include("io/alpn_handler.jl")

# --- public submodules (thin wrappers / new surfaces) ---
include("EventLoops.jl")
include("Sockets.jl")
include("Files.jl")
# Must be last: defining `Reseau.Threads` shadows `Base.Threads` within this module.
include("Threads.jl")

function __init__()
    _init_os_thread_cfunc!()
    io_library_init()
end

end # module Reseau
