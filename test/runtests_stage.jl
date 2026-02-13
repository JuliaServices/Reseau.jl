using Test
using Reseau
import Reseau: Threads, EventLoops, Sockets

function _include_stage(file_name::AbstractString)
    file_path = joinpath(@__DIR__, string(file_name, ".jl"))
    isfile(file_path) || throw(ArgumentError("Unknown test file: $file_name"))
    include(file_path)
    return nothing
end

const _test_file = get(ENV, "RESEAU_TEST_FILE", "")
if _test_file == ""
    error("RESEAU_TEST_FILE is required for this runner")
end

const _LOG_TEST_STAGE = get(ENV, "RESEAU_TEST_STAGE_LOG", "") == "1"
_LOG_TEST_STAGE && println("[test-stage-drill] start ", _test_file)

include("test_utils.jl")
cleanup_test_sockets!()
atexit(cleanup_test_sockets!)
setup_test_keychain!()
atexit(setup_test_keychain!)

if Sys.islinux()
    using aws_lc_jll
    using s2n_tls_jll
end

const _allowed_stage_files = Set([
    "common_tests",
    "event_loop_tests",
    "socket_tests",
    "socket_handler_tests",
    "channel_tests",
    "io_testing_channel_tests",
    "channel_bootstrap_tests",
    "pipe_tests",
    "tls_tests",
    "pkcs11_tests",
    "alpn_tests",
    "host_resolver_tests",
    "io_tests",
    "future_tests",
    "stream_tests",
    "pem_tests",
    "pki_utils_tests",
    "crypto_primitives_tests",
    "crypto_tests",
    "statistics_tests",
    "retry_strategy_tests",
    "vsock_tests",
    "tracing_tests",
    "sockets_compat_tests",
])
(_test_file in _allowed_stage_files) || error("Unsupported RESEAU_TEST_FILE: ", _test_file)

_include_stage(_test_file)
_LOG_TEST_STAGE && println("[test-stage-drill] done ", _test_file)
