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

function _include_with_progress(path::AbstractString)
    _log_test_progress("[runtests] include START: $(path)")
    include(path)
    _log_test_progress("[runtests] include DONE: $(path)")
    return nothing
end

test_files = [
    "eventloops_tests.jl",
    "internal_poll_tests.jl",
    "socket_ops_tests.jl",
    "tcp_tests.jl",
    "host_resolvers_tests.jl",
    "tls_tests.jl",
    "http_core_tests.jl",
    "http1_wire_tests.jl",
    "http_cookie_tests.jl",
    "http_forms_tests.jl",
    "http_websocket_codec_tests.jl",
    "http_websocket_client_tests.jl",
    "http_websocket_server_tests.jl",
    "http_websocket_integration_tests.jl",
    "http_client_transport_tests.jl",
    "http_client_proxy_tests.jl",
    "http_client_tests.jl",
    "http_server_http1_tests.jl",
    "hpack_tests.jl",
    "http2_frame_tests.jl",
    "http2_client_tests.jl",
    "http2_server_tests.jl",
    "http_integration_tests.jl",
    "http_parity_tests.jl",
    "trim_compile_tests.jl",
]

const _WINDOWS_COMPILER_ISSUE_TESTS = Set([
    "http_client_transport_tests.jl",
    "http_client_proxy_tests.jl",
    "http_client_tests.jl",
    "http_server_http1_tests.jl",
    "http_integration_tests.jl",
    "http_parity_tests.jl",
])

only_test = strip(get(ENV, "RESEAU_TEST_ONLY", ""))
if !isempty(only_test)
    test_files = filter(==(only_test), test_files)
    isempty(test_files) && error("unknown RESEAU_TEST_ONLY test file: $(only_test)")
end

for test_file in test_files
    if Sys.iswindows() && in(test_file, _WINDOWS_COMPILER_ISSUE_TESTS)
        _log_test_progress("[runtests] include SKIP: $(test_file) (temporary Windows compiler issue)")
        continue
    end
    _include_with_progress(test_file)
end

if get(ENV, "RESEAU_RUN_WEBSOCKET_AUTOBAHN", "") == "1"
    _include_with_progress("http_websocket_autobahn.jl")
end
