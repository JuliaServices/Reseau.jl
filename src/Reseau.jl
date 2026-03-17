"""
    Reseau

Root module for the rewritten Go-parity networking stack.

The package is organized in layers:
- low-level eventing/polling and socket ops
- TCP core primitives + host resolution/connection orchestration
- TLS transport
"""
module Reseau

export TCP, TLS

include("0_compat.jl")
include("2_socket_ops.jl")
include("3_iopoll.jl")
include("4_tcp.jl")
include("5_host_resolvers.jl")
include("6_tls.jl")
include("8_precompile_workload.jl")

end
