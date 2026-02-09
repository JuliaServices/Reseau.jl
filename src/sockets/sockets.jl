module Sockets

# Reseau's libuv-free sockets surface.
#
# This module now also houses the underlying event-loop + channel + socket + TLS
# implementation that used to live under `src/io/*`.

using EnumX
import UUIDs

# Bring parent-module bindings (common utilities, error codes, logging, etc.)
# into this module so the moved `io/*` implementation can remain largely
# unchanged (it historically lived in the parent module).
const _PARENT = parentmodule(@__MODULE__)
for name in names(_PARENT; all = true, imported = false)
    str = String(name)
    startswith(str, "@") && continue
    # Do not shadow stdlib `Threads` inside this module (IO code uses `Threads.*`).
    name === :Threads && continue
    # Avoid self-aliasing.
    name === :Sockets && continue
    if isdefined(@__MODULE__, name)
        owner = Base.binding_module(@__MODULE__, name)
        owner === (@__MODULE__) && continue
        (owner === Base || owner === Core) || continue
    end
    val = getfield(_PARENT, name)
    @eval const $(name) = $(_PARENT).$(name)
end

# Similarly, pull in thread/runtime primitives from the sibling `Reseau.Threads`
# module so the IO stack can keep referring to them unqualified.
const _THREADS = getfield(_PARENT, :Threads)
for name in names(_THREADS; all = true, imported = false)
    str = String(name)
    startswith(str, "@") && continue
    name === :Threads && continue
    if isdefined(@__MODULE__, name)
        owner = Base.binding_module(@__MODULE__, name)
        owner === (@__MODULE__) && continue
        (owner === Base || owner === Core) || continue
    end
    val = getfield(_THREADS, name)
    @eval const $(name) = $(_THREADS).$(name)
end

# --- IO implementation (moved from `src/io/*`) ---
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
include("io/channel_bootstrap.jl")
include("io/future_integration.jl")

# Previously included directly from src/Reseau.jl
include("io/aws_byte_helpers.jl")
include("io/crypto_primitives.jl")
include("io/async_stream.jl")
include("io/tls_channel_handler.jl")
include("io/alpn_handler.jl")

# --- Public surface (stdlib-like TCP + LOCAL subset) ---
include("ipaddr.jl")
include("dns.jl")
include("tcp.jl")

end # module Sockets
