using Test

function _log_test_progress(msg::AbstractString)
    println(msg)
    flush(stdout)
    return nothing
end

_log_test_progress("[runtests] loading Reseau")
using Reseau
_log_test_progress("[runtests] loaded Reseau")
_log_test_progress("[runtests] julia threads: $(Threads.nthreads())")

@test TCP === Reseau.TCP
@test TLS === Reseau.TLS

function _include_with_progress(path::AbstractString)
    _log_test_progress("[runtests] include START: $(path)")
    include(path)
    _log_test_progress("[runtests] include DONE: $(path)")
    return nothing
end

test_files = [
    "iopoll_runtime_tests.jl",
    "internal_poll_tests.jl",
    "socket_ops_tests.jl",
    "tcp_tests.jl",
    "host_resolvers_tests.jl",
    "tls_tests.jl",
    "trim_compile_tests.jl",
]

only_test = strip(get(ENV, "RESEAU_TEST_ONLY", ""))
if !isempty(only_test)
    test_files = filter(==(only_test), test_files)
    isempty(test_files) && error("unknown RESEAU_TEST_ONLY test file: $(only_test)")
end

for test_file in test_files
    _include_with_progress(test_file)
end
