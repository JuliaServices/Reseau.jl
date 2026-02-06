const _deps_file = joinpath(@__DIR__, "deps.jl")

# As of AwsIO v1.1.1, we no longer build a Network.framework Blocks shim
# (formerly `libawsio_nw_shim`). Network/Security blocks are implemented directly
# in Julia (see `src/io/blocks_abi.jl` and `src/io/apple_nw_socket.jl`).
open(_deps_file, "w") do io
    println(io, "const libawsio_nw_shim = \"\"")
end
