"""
    Reseau

Root module for the rewritten Go-parity networking stack.

The package is organized in layers:
- low-level eventing/polling and socket ops
- TCP core primitives + host resolution/connection orchestration
- TLS transport
- HTTP/1 + HTTP/2 client/server stacks
"""
module Reseau

const _REPRO_MAX_LAYER = something(tryparse(Int, get(ENV, "RESEAU_REPRO_MAX_LAYER", "8")), 8)

_REPRO_MAX_LAYER >= 1 && include("1_eventloops.jl")
_REPRO_MAX_LAYER >= 2 && include("2_socket_ops.jl")
_REPRO_MAX_LAYER >= 3 && include("3_internal_poll.jl")
_REPRO_MAX_LAYER >= 4 && include("4_tcp.jl")
_REPRO_MAX_LAYER >= 5 && include("5_host_resolvers.jl")
_REPRO_MAX_LAYER >= 6 && include("6_tls.jl")
_REPRO_MAX_LAYER >= 7 && include("7_http.jl")
_REPRO_MAX_LAYER >= 8 && include("8_precompile_workload.jl")

end
