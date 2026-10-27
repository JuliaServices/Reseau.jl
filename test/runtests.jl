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
@test UDP === Reseau.UDP
@test TLS === Reseau.TLS

@static if Sys.islinux() || Sys.isapple() || Sys.isfreebsd()
    include("unix_helpers.jl")
end

function _include_with_progress(path::AbstractString)
    _log_test_progress("[runtests] include START: $(path)")
    include(path)
    _log_test_progress("[runtests] include DONE: $(path)")
    return nothing
end

test_files = [
    "timing_semantics_tests.jl",
    "iopoll_runtime_tests.jl",
    "internal_poll_tests.jl",
    "deadline_heap_tests.jl",
    "socket_ops_tests.jl",
    "tcp_tests.jl",
    "unix_tests.jl",
    "udp_tests.jl",
    "host_resolvers_tests.jl",
    "socks_tests.jl",
    "tls_crypto_tests.jl",
    "tls_x509_tests.jl",
    "tls_distrust_tests.jl",
    "tls_handshake_messages_tests.jl",
    "tls_handshake_client_tls12_tests.jl",
    "tls_handshake_client_tls13_tests.jl",
    "tls_native_tls12_tests.jl",
    "tls_native_tls13_tests.jl",
    "tls_quic_tests.jl",
    "tls_quic_go_interop_tests.jl",
    "quic_packet_protection_tests.jl",
    "quic_packet_tests.jl",
    "quic_frame_tests.jl",
    "quic_transport_parameters_tests.jl",
    "quic_go_wire_frames_tests.jl",
    "quic_go_wire_header_tests.jl",
    "quic_go_wire_transport_parameters_tests.jl",
    "quic_buffers_tests.jl",
    "quic_connection_tests.jl",
    "quic_stream_tests.jl",
    "quic_congestion_tests.jl",
    "quic_go_congestion_tests.jl",
    "quic_go_flowcontrol_tests.jl",
    "quic_pmtu_tests.jl",
    "quic_udp_tests.jl",
    "quic_api_tests.jl",
    "quic_go_handshake_tests.jl",
    "quic_go_ackhandler_tests.jl",
    "quic_go_streams_tests.jl",
    "quic_go_interop_tests.jl",
    "tls_config_tests.jl",
    "tls_ca_sources_tests.jl",
    "tls_precompile_time_tests.jl",
    "precompile_workload_tests.jl",
    "tls_public_api_tests.jl",
    "tryread_tests.jl",
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
