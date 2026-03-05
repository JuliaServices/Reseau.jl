using Test

function _log_test_progress(msg::AbstractString)
    println(msg)
    flush(stdout)
    return nothing
end

_log_test_progress("[runtests] loading Reseau")
using Reseau
_log_test_progress("[runtests] loaded Reseau")

function _include_with_progress(path::AbstractString)
    _log_test_progress("[runtests] include START: $(path)")
    include(path)
    _log_test_progress("[runtests] include DONE: $(path)")
    return nothing
end

_include_with_progress("eventloops_tests.jl")
_include_with_progress("internal_poll_tests.jl")
_include_with_progress("socket_ops_tests.jl")
_include_with_progress("tcp_tests.jl")
_include_with_progress("host_resolvers_tests.jl")
_include_with_progress("tls_tests.jl")
_include_with_progress("http_core_tests.jl")
_include_with_progress("http1_wire_tests.jl")
_include_with_progress("http_client_transport_tests.jl")
_include_with_progress("http_client_tests.jl")
_include_with_progress("http_server_http1_tests.jl")
_include_with_progress("hpack_tests.jl")
_include_with_progress("http2_frame_tests.jl")
_include_with_progress("http2_client_tests.jl")
_include_with_progress("http2_server_tests.jl")
_include_with_progress("http_integration_tests.jl")
_include_with_progress("http_parity_tests.jl")
_include_with_progress("trim_compile_tests.jl")
