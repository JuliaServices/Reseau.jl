module Sockets

# Reseau's libuv-free sockets surface.
#
# This module houses the channel + socket + TLS implementation that used to live
# under `src/io/*` (event-loops have moved to `Reseau.EventLoops`).

using EnumX
import UUIDs
using LibAwsCal
using LibAwsCommon

# Bring parent-module bindings (common utilities, error codes, logging, etc.)
# into this module so the moved `io/*` implementation can remain largely
# unchanged (it historically lived in the parent module).
const _PARENT = parentmodule(@__MODULE__)
for name in names(_PARENT; all = true, imported = false)
    str = String(name)
    startswith(str, "@") && continue
    # Do not shadow stdlib `Threads` inside this module (IO code uses `Threads.*`).
    name === :Threads && continue
    # Do not shadow Base.put!/Base.take! (lru_cache.jl defines Reseau.put! which would mask them).
    name === :put! && continue
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

# Similarly, pull in thread/runtime primitives from the sibling `Reseau.ForeignThreads`
# module so the IO stack can keep referring to them unqualified.
const _THREADS = getfield(_PARENT, :ForeignThreads)
for name in names(_THREADS; all = true, imported = false)
    str = String(name)
    startswith(str, "@") && continue
    name === :ForeignThreads && continue
    name === :__init__ && continue
    if isdefined(@__MODULE__, name)
        owner = Base.binding_module(@__MODULE__, name)
        owner === (@__MODULE__) && continue
        (owner === Base || owner === Core) || continue
    end
    val = getfield(_THREADS, name)
    @eval const $(name) = $(_THREADS).$(name)
end
# Macros are skipped by the name-loop above; import them explicitly.
using ..ForeignThreads: @wrap_thread_fn

# Pull in event-loop + core IO definitions from the sibling `Reseau.EventLoops`
# module so the socket stack can keep referring to them unqualified.
const _EVENT_LOOPS = getfield(_PARENT, :EventLoops)
for name in names(_EVENT_LOOPS; all = true, imported = false)
    str = String(name)
    startswith(str, "@") && continue
    name === :EventLoops && continue
    if isdefined(@__MODULE__, name)
        owner = Base.binding_module(@__MODULE__, name)
        owner === (@__MODULE__) && continue
        (owner === Base || owner === Core) || continue
    end
    val = getfield(_EVENT_LOOPS, name)
    @eval const $(name) = $(_EVENT_LOOPS).$(name)
end

const _io_library_initialized = Ref{Bool}(false)

function io_library_init()
    _io_library_initialized[] && return nothing
    _io_library_initialized[] = true
    _cal_init()
    tls_init_static_state()
    io_tracing_init()
    _host_resolver_init_cfunctions!()
    return nothing
end

function io_library_clean_up()
    !_io_library_initialized[] && return nothing
    _io_library_initialized[] = false
    tls_clean_up_static_state()
    join_all_managed()
    return nothing
end

# --- IO implementation (moved from `src/io/*`) ---
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

# Previously included directly from src/Reseau.jl
include("io/aws_byte_helpers.jl")
include("io/crypto_primitives.jl")
include("io/tls_channel_handler.jl")
include("io/alpn_handler.jl")

# --- Public surface (stdlib-like TCP + LOCAL subset) ---
include("ipaddr.jl")
include("dns.jl")
include("tcp.jl")

end # module Sockets
