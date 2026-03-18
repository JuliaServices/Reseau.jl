using Test
using Reseau

const NC = Reseau.TCP

println("[windows-compiler-bug] loaded Reseau")
println("[windows-compiler-bug] julia threads: $(Threads.nthreads())")

function _probe(f, label::AbstractString)
    println("[windows-compiler-bug] probe start: $(label)")
    try
        f()
        println("[windows-compiler-bug] probe done: $(label)")
    catch ex
        println("[windows-compiler-bug] probe error ($(label)): $(typeof(ex))")
    end
    return nothing
end

@test Reseau.TCP === TCP
@test Reseau.TLS === TLS

_probe("tcp kwcall local_addr v4") do
    NC.connect("tcp", "127.0.0.1:1"; local_addr = NC.loopback_addr(0))
end

_probe("tcp kwcall local_addr v6 mismatch") do
    NC.connect("tcp", "127.0.0.1:1"; local_addr = NC.loopback_addr6(0))
end

@test true
