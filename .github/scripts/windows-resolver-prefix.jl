using Test

function progress(message)
    println(message)
    flush(stdout)
end

progress("[runtests] loading Reseau")
using Reseau
progress("[runtests] loaded Reseau")
progress("[runtests] julia threads: $(Threads.nthreads())")

@test TCP === Reseau.TCP
@test UDP === Reseau.UDP
@test TLS === Reseau.TLS

# Preserve the original ordering and shared process through the resolver tests.
test_files = [
    "timing_semantics_tests.jl",
    "iopoll_runtime_tests.jl",
    "internal_poll_tests.jl",
    "deadline_heap_tests.jl",
    "socket_ops_tests.jl",
    "tcp_tests.jl",
    "udp_tests.jl",
    "host_resolvers_tests.jl",
]
subject = only(ARGS)
original = read(joinpath(subject, "test", "runtests.jl"), String)
ordered_files = [m.captures[1] for m in eachmatch(r"\"([^\"]+_tests\.jl)\"", original)]
@assert ordered_files[1:length(test_files)] == test_files "subject test ordering changed"
for file in test_files
    progress("[runtests] include START: $file")
    include(joinpath(subject, "test", file))
    progress("[runtests] include DONE: $file")
end
