using Test
using Reseau

include(joinpath(@__DIR__, "test_utils.jl"))

cleanup_test_sockets!()
atexit(cleanup_test_sockets!)

setup_test_keychain!()
atexit(cleanup_test_keychain!)

if Sys.islinux()
    using aws_lc_jll
    using s2n_tls_jll
end

const _trace_enabled = get(ENV, "RESEAU_EVENT_LOOP_TEST_TRACE", "") == "1"
if _trace_enabled
    println("[ci-drill] test mode: ", "event_loop_ci_drill")
    println(
        "[ci-drill] trace-window=",
        get(ENV, "RESEAU_EVENT_LOOP_TEST_TRACE_START", "1"),
        ":",
        get(ENV, "RESEAU_EVENT_LOOP_TEST_TRACE_LIMIT", "0"),
    )
end

include("event_loop_tests.jl")
