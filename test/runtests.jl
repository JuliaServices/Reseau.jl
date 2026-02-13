using Test
using Reseau
import Reseau: Threads, EventLoops, Sockets

const _TEST_STAGE_LOG = get(ENV, "RESEAU_TEST_STAGE_LOG", "") == "1"
_log_stage(name::AbstractString) = _TEST_STAGE_LOG && println("[test-stage] ", name)

include("test_utils.jl")
cleanup_test_sockets!()
atexit(cleanup_test_sockets!)
setup_test_keychain!()
atexit(cleanup_test_keychain!)

if Sys.islinux()
    using aws_lc_jll
    using s2n_tls_jll
end

if Sys.islinux()
    @testset "ReseauS2N extension hooks" begin
        @testset "ReseauS2N extension loaded" begin
            @test Base.get_extension(Reseau, :ReseauS2NExt) !== nothing
        end
        @testset "s2n registration symbol available" begin
            @test isdefined(Reseau, :_register_s2n_lib!) || isdefined(Reseau.Sockets, :_register_s2n_lib!)
        end
    end
end

_log_stage("start common_tests")
include("common_tests.jl")
_log_stage("done common_tests")
_log_stage("start event_loop_tests")
include("event_loop_tests.jl")
_log_stage("done event_loop_tests")
_log_stage("start socket_tests")
include("socket_tests.jl")
_log_stage("done socket_tests")
_log_stage("start socket_handler_tests")
include("socket_handler_tests.jl")
_log_stage("done socket_handler_tests")
_log_stage("start channel_tests")
include("channel_tests.jl")
_log_stage("done channel_tests")
_log_stage("start io_testing_channel_tests")
include("io_testing_channel_tests.jl")
_log_stage("done io_testing_channel_tests")
_log_stage("start channel_bootstrap_tests")
include("channel_bootstrap_tests.jl")
_log_stage("done channel_bootstrap_tests")
_log_stage("start pipe_tests")
include("pipe_tests.jl")
_log_stage("done pipe_tests")
_log_stage("start tls_tests")
include("tls_tests.jl")
_log_stage("done tls_tests")
_log_stage("start pkcs11_tests")
include("pkcs11_tests.jl")
_log_stage("done pkcs11_tests")
_log_stage("start alpn_tests")
include("alpn_tests.jl")
_log_stage("done alpn_tests")
_log_stage("start host_resolver_tests")
include("host_resolver_tests.jl")
_log_stage("done host_resolver_tests")
_log_stage("start io_tests")
include("io_tests.jl")
_log_stage("done io_tests")
_log_stage("start future_tests")
include("future_tests.jl")
_log_stage("done future_tests")
_log_stage("start stream_tests")
include("stream_tests.jl")
_log_stage("done stream_tests")
_log_stage("start pem_tests")
include("pem_tests.jl")
_log_stage("done pem_tests")
_log_stage("start pki_utils_tests")
include("pki_utils_tests.jl")
_log_stage("done pki_utils_tests")
_log_stage("start crypto_primitives_tests")
include("crypto_primitives_tests.jl")
_log_stage("done crypto_primitives_tests")
_log_stage("start crypto_tests")
include("crypto_tests.jl")
_log_stage("done crypto_tests")
_log_stage("start statistics_tests")
include("statistics_tests.jl")
_log_stage("done statistics_tests")
_log_stage("start retry_strategy_tests")
include("retry_strategy_tests.jl")
_log_stage("done retry_strategy_tests")
_log_stage("start vsock_tests")
include("vsock_tests.jl")
_log_stage("done vsock_tests")
_log_stage("start tracing_tests")
include("tracing_tests.jl")
_log_stage("done tracing_tests")
_log_stage("start sockets_compat_tests")
include("sockets_compat_tests.jl")
_log_stage("done sockets_compat_tests")
