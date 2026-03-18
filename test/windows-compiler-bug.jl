using Test
using Reseau

println("[windows-compiler-bug] loaded Reseau")
println("[windows-compiler-bug] julia threads: $(Threads.nthreads())")

@test Reseau.TCP === TCP
@test Reseau.TLS === TLS
@test true
