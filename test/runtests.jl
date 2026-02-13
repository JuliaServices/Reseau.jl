using Test
using Reseau
import Reseau: Threads, EventLoops, Sockets

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

include("common_tests.jl")
include("event_loop_tests.jl")
include("socket_tests.jl")
include("socket_handler_tests.jl")
include("channel_tests.jl")
include("io_testing_channel_tests.jl")
include("channel_bootstrap_tests.jl")
include("pipe_tests.jl")
include("tls_tests.jl")
include("pkcs11_tests.jl")
include("alpn_tests.jl")
include("host_resolver_tests.jl")
include("io_tests.jl")
include("future_tests.jl")
include("stream_tests.jl")
include("pem_tests.jl")
include("pki_utils_tests.jl")
include("crypto_primitives_tests.jl")
include("crypto_tests.jl")
include("statistics_tests.jl")
include("retry_strategy_tests.jl")
include("vsock_tests.jl")
include("tracing_tests.jl")
include("sockets_compat_tests.jl")
