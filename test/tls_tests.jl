using Test
using AwsIO

# `Pkg.test` includes `test/test_utils.jl` from `test/runtests.jl` before including this file.
# But when someone includes `test/tls_tests.jl` directly, these helpers don't exist yet.
if !isdefined(@__MODULE__, :tls_tests_enabled)
    include("test_utils.jl")
    setup_test_keychain!()
    atexit(cleanup_test_keychain!)
end

if !tls_tests_enabled()
    @info "Skipping TLS tests (set AWSIO_RUN_TLS_TESTS=1 to enable)"
else
    include("tls_tests_impl.jl")
end

