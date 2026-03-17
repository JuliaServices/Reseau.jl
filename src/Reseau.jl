"""
    Reseau

Root module for Reseau's networking transport stack.

The primary public entrypoints are `TCP` and `TLS`.
"""
module Reseau

export TCP, TLS

include("0_compat.jl")
include("1_socket_ops.jl")
include("2_iopoll.jl")
include("3_tcp.jl")
include("4_host_resolvers.jl")
include("5_tls.jl")
include("6_precompile_workload.jl")

end
