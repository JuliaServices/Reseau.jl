using Test
using Reseau

# Ports of quic-go v0.48.2 internal/wire/transport_parameter_test.go
# (github.com/quic-go/quic-go@v0.48.2/internal/wire). Testset names are the Go
# test names. quic-go's TransportParameters.Marshal maps to
# `_encode_transport_parameters`; Unmarshal(data, perspective) maps to
# `_decode_transport_parameters(data; from_server)` plus, for the checks quic-go
# makes in Unmarshal but we make once the handshake hands the parameters over
# (missing original_destination_connection_id / initial_source_connection_id),
# `_check_peer_transport_parameters`. Every quic-go error here is a
# TRANSPORT_PARAMETER_ERROR; we check that code rather than the message.
#
# Not ported (N/A):
# - TestTransportParametersStringRepresentation,
#   TestTransportParametersStringRepresentationWithoutOptionalFields: Go String().
# - TestMarshalAdditionalTransportParameters: no hook for extra parameters.
# - TestTransportParametersFromSessionTicket, TestSessionTicketInvalidTransportParameters,
#   TestSessionTicketTransportParameterVersionMismatch, TestTransportParametersValidFor0RTT,
#   TestTransportParametersValidAfter0RTT: no session resumption / 0-RTT.
# - max_datagram_frame_size (RFC 9221) fields in the round trip: no DATAGRAM support.
# - BenchmarkTransportParameters.

const QGWP = Reseau.QUIC

@isdefined(_QcnHarness) || include("quic_harness.jl")

_qgwp_v(v::Integer) = (b = UInt8[]; QGWP._append_varint!(b, UInt64(v)); b)
_qgwp_b(s::AbstractString) = Vector{UInt8}(codeunits(s))
_qgwp_param(id::Integer, value::AbstractVector{UInt8}) = vcat(_qgwp_v(id), _qgwp_v(length(value)), value)
_qgwp_varint_param(id::Integer, v::Integer) = vcat(_qgwp_v(id), _qgwp_v(QGWP._varint_length(UInt64(v))), _qgwp_v(v))
# appendInitialSourceConnectionID
_qgwp_iscid(b::Vector{UInt8}) = vcat(b, _qgwp_param(QGWP._TP_INITIAL_SOURCE_CONNECTION_ID, _qgwp_b("foobar")))

# getRandomValueUpTo
function _qgwp_rand_upto(max::Integer)
    m = rand((typemax(UInt8) ÷ 4, typemax(UInt16) ÷ 4, typemax(UInt32) ÷ 4, typemax(UInt64) ÷ 4))
    m = min(UInt64(m), UInt64(max))
    return rand(UInt64(0):(m - 1))
end
_qgwp_rand() = _qgwp_rand_upto(QGWP._MAX_VARINT)

_qgwp_decode(bytes; from_server::Bool) = QGWP._decode_transport_parameters(bytes; from_server)

# quic-go's Unmarshal: decode, then the presence checks a receiving endpoint
# makes. The connection's own IDs are set to whatever the parameters carry,
# so only a missing parameter fails.
function _qgwp_unmarshal(bytes; from_server::Bool)
    p = _qgwp_decode(bytes; from_server)
    p isa QGWP._TransportError && return p
    conn = QGWP._client_connection(_qcn_client_config(), Int64(0))
    conn.is_server = !from_server
    p.initial_source_connection_id === nothing || (conn.peer_cid = copy(p.initial_source_connection_id))
    p.original_destination_connection_id === nothing || (conn.original_dcid = copy(p.original_destination_connection_id))
    err = QGWP._check_peer_transport_parameters(conn, p)
    return err === nothing ? p : err
end

_qgwp_tp_error(result) = result isa QGWP._TransportError && result.code == QGWP._TRANSPORT_PARAMETER_ERROR

# A preferred_address value (RFC 9000 Section 18.2).
function _qgwp_preferred_address(ipv4, port4, ipv6, port6, cid, token)
    return vcat(UInt8.(collect(ipv4)), UInt8[port4 >> 8, port4 & 0xff], UInt8.(collect(ipv6)), UInt8[port6 >> 8, port6 & 0xff],
                UInt8[length(cid)], cid, token)
end

@testset "quic-go internal/wire transport parameters" begin
    @testset "TestMarshalAndUnmarshalTransportParameters" begin
        token = rand(UInt8, 16)
        rcid = UInt8[0xde, 0xad, 0xc0, 0xde]
        params = QGWP._TransportParameters(
            initial_max_stream_data_bidi_local = _qgwp_rand(),
            initial_max_stream_data_bidi_remote = _qgwp_rand(),
            initial_max_stream_data_uni = _qgwp_rand(),
            initial_max_data = _qgwp_rand(),
            max_idle_timeout_ms = UInt64(0xcafe) * 1000,
            initial_max_streams_bidi = _qgwp_rand_upto(QGWP._MAX_STREAMS_LIMIT),
            initial_max_streams_uni = _qgwp_rand_upto(QGWP._MAX_STREAMS_LIMIT),
            disable_active_migration = true,
            stateless_reset_token = token,
            original_destination_connection_id = UInt8[0xde, 0xad, 0xbe, 0xef],
            initial_source_connection_id = UInt8[0xde, 0xca, 0xfb, 0xad],
            retry_source_connection_id = rcid,
            ack_delay_exponent = UInt64(13),
            max_ack_delay_ms = UInt64(42),
            active_connection_id_limit = 2 + _qgwp_rand_upto(QGWP._MAX_VARINT - 2),
            max_udp_payload_size = 1200 + _qgwp_rand_upto(QGWP._MAX_VARINT - 1200),
        )
        data = QGWP._encode_transport_parameters(params)
        p = _qgwp_decode(data; from_server = true)
        @test p isa QGWP._TransportParameters
        @test p.initial_max_stream_data_bidi_local == params.initial_max_stream_data_bidi_local
        @test p.initial_max_stream_data_bidi_remote == params.initial_max_stream_data_bidi_remote
        @test p.initial_max_stream_data_uni == params.initial_max_stream_data_uni
        @test p.initial_max_data == params.initial_max_data
        @test p.initial_max_streams_uni == params.initial_max_streams_uni
        @test p.initial_max_streams_bidi == params.initial_max_streams_bidi
        @test p.max_idle_timeout_ms == params.max_idle_timeout_ms
        @test p.disable_active_migration == params.disable_active_migration
        @test p.stateless_reset_token == params.stateless_reset_token
        @test p.original_destination_connection_id == UInt8[0xde, 0xad, 0xbe, 0xef]
        @test p.initial_source_connection_id == UInt8[0xde, 0xca, 0xfb, 0xad]
        @test p.retry_source_connection_id == rcid
        @test p.ack_delay_exponent == 13
        @test p.max_ack_delay_ms == 42
        @test p.active_connection_id_limit == params.active_connection_id_limit
        @test p.max_udp_payload_size == params.max_udp_payload_size
    end

    @testset "TestMarshalWithoutRetrySourceConnectionID" begin
        data = QGWP._encode_transport_parameters(QGWP._TransportParameters(
            stateless_reset_token = zeros(UInt8, 16), active_connection_id_limit = UInt64(2)))
        p = _qgwp_decode(data; from_server = true)
        @test p isa QGWP._TransportParameters
        @test p.retry_source_connection_id === nothing
    end

    @testset "TestMarshalZeroLengthRetrySourceConnectionID" begin
        data = QGWP._encode_transport_parameters(QGWP._TransportParameters(
            retry_source_connection_id = UInt8[], stateless_reset_token = zeros(UInt8, 16),
            active_connection_id_limit = UInt64(2)))
        p = _qgwp_decode(data; from_server = true)
        @test p isa QGWP._TransportParameters
        @test p.retry_source_connection_id !== nothing
        @test isempty(p.retry_source_connection_id)
    end

    @testset "TestTransportParameterNoMaxAckDelayIfDefault" begin
        default_max_ack_delay = QGWP._DEFAULT_TRANSPORT_PARAMETERS.max_ack_delay_ms
        max_ack_delay = default_max_ack_delay + 1
        data_default = QGWP._encode_transport_parameters(QGWP._TransportParameters(
            max_ack_delay_ms = default_max_ack_delay, stateless_reset_token = zeros(UInt8, 16)))
        data = QGWP._encode_transport_parameters(QGWP._TransportParameters(
            max_ack_delay_ms = max_ack_delay, stateless_reset_token = zeros(UInt8, 16)))
        # (quic-go's entryLen uses the ack_delay_exponent ID; both IDs are 1 byte.)
        entry_len = QGWP._varint_length(QGWP._TP_ACK_DELAY_EXPONENT) +
                    QGWP._varint_length(UInt64(QGWP._varint_length(max_ack_delay))) +
                    QGWP._varint_length(max_ack_delay)
        @test abs(length(data_default) + entry_len - length(data)) <= 1
    end

    @testset "TestTransportParameterNoAckDelayExponentIfDefault" begin
        default_exponent = QGWP._DEFAULT_TRANSPORT_PARAMETERS.ack_delay_exponent
        data_default = QGWP._encode_transport_parameters(QGWP._TransportParameters(
            ack_delay_exponent = default_exponent, stateless_reset_token = zeros(UInt8, 16)))
        data = QGWP._encode_transport_parameters(QGWP._TransportParameters(
            ack_delay_exponent = default_exponent + 1, stateless_reset_token = zeros(UInt8, 16)))
        entry_len = QGWP._varint_length(QGWP._TP_ACK_DELAY_EXPONENT) +
                    QGWP._varint_length(UInt64(QGWP._varint_length(default_exponent + 1))) +
                    QGWP._varint_length(default_exponent + 1)
        @test abs(length(data_default) + entry_len - length(data)) <= 1
    end

    @testset "TestTransportParameterSetsDefaultValuesWhenNotSent" begin
        d = QGWP._DEFAULT_TRANSPORT_PARAMETERS
        data = QGWP._encode_transport_parameters(QGWP._TransportParameters(
            ack_delay_exponent = d.ack_delay_exponent, stateless_reset_token = zeros(UInt8, 16),
            active_connection_id_limit = d.active_connection_id_limit))
        p = _qgwp_decode(data; from_server = true)
        @test p isa QGWP._TransportParameters
        @test p.ack_delay_exponent == 3
        @test p.active_connection_id_limit == 2
    end

    @testset "TestTransportParameterErrors" begin
        reset_token = zeros(UInt8, 16)
        max_stream_count = QGWP._MAX_STREAMS_LIMIT
        cases = [
            ("invalid stateless reset token length",
             _qgwp_param(QGWP._TP_STATELESS_RESET_TOKEN, zeros(UInt8, 15)), true),
            ("small max UDP payload size",
             _qgwp_varint_param(QGWP._TP_MAX_UDP_PAYLOAD_SIZE, 1199), true),
            ("active connection ID limit too small",
             QGWP._encode_transport_parameters(QGWP._TransportParameters(
                 active_connection_id_limit = UInt64(1), stateless_reset_token = reset_token)), true),
            ("ack delay exponent too large",
             QGWP._encode_transport_parameters(QGWP._TransportParameters(
                 ack_delay_exponent = UInt64(21), stateless_reset_token = reset_token)), true),
            ("disable active migration has content",
             _qgwp_param(QGWP._TP_DISABLE_ACTIVE_MIGRATION, _qgwp_b("foobar")), true),
            ("server doesn't set original destination connection ID",
             _qgwp_iscid(_qgwp_param(QGWP._TP_STATELESS_RESET_TOKEN, zeros(UInt8, 16))), true),
            ("initial source connection ID is missing", UInt8[], false),
            ("max ack delay is too large",
             QGWP._encode_transport_parameters(QGWP._TransportParameters(
                 max_ack_delay_ms = UInt64(1) << 14, stateless_reset_token = reset_token)), true),
            ("varint value has wrong length",
             _qgwp_iscid(vcat(_qgwp_v(QGWP._TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL), _qgwp_v(2), _qgwp_v(0xdeadbeef))), true),
            ("initial max streams bidi is too large",
             _qgwp_iscid(_qgwp_varint_param(QGWP._TP_INITIAL_MAX_STREAMS_BIDI, max_stream_count + 1)), true),
            ("initial max streams uni is too large",
             _qgwp_iscid(_qgwp_varint_param(QGWP._TP_INITIAL_MAX_STREAMS_UNI, max_stream_count + 1)), true),
            ("not enough data to read",
             vcat(_qgwp_v(0x42), _qgwp_v(7), _qgwp_b("foobar")), true),
            ("client sent stateless reset token",
             vcat(_qgwp_v(QGWP._TP_STATELESS_RESET_TOKEN), _qgwp_v(QGWP._varint_length(UInt64(16))), zeros(UInt8, 16)), false),
            ("client sent original destination connection ID",
             _qgwp_param(QGWP._TP_ORIGINAL_DESTINATION_CONNECTION_ID, _qgwp_b("foobar")), false),
            ("huge max ack delay value",
             _qgwp_iscid(_qgwp_varint_param(QGWP._TP_MAX_ACK_DELAY, typemax(UInt64) ÷ 5)), false),
        ]
        for (name, data, from_server) in cases
            @testset "$name" begin
                @test _qgwp_tp_error(_qgwp_unmarshal(data; from_server))
            end
        end
    end

    @testset "TestTransportParameterUnknownParameters" begin
        b = vcat(_qgwp_varint_param(QGWP._TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 0x1337),
                 vcat(_qgwp_v(0x42), _qgwp_v(6), _qgwp_b("foobar")),
                 _qgwp_varint_param(QGWP._TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 0x42))
        b = _qgwp_iscid(b)
        p = _qgwp_unmarshal(b; from_server = false)
        @test p isa QGWP._TransportParameters
        @test p.initial_max_stream_data_bidi_local == 0x1337
        @test p.initial_max_stream_data_bidi_remote == 0x42
    end

    @testset "TestTransportParameterRejectsDuplicateParameters" begin
        b = vcat(_qgwp_varint_param(QGWP._TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 0x1337),
                 _qgwp_varint_param(QGWP._TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 0x42),
                 _qgwp_varint_param(QGWP._TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, 0x1337))
        b = _qgwp_iscid(b)
        @test _qgwp_tp_error(_qgwp_unmarshal(b; from_server = false))
    end

    pa_ipv4 = (127, 0, 0, 1)
    pa_ipv6 = 1:16
    pa_token = UInt8.(16:-1:1)

    @testset "TestPreferredAddressMarshalAndUnmarshal" begin
        cid = UInt8[0xde, 0xad, 0xbe, 0xef]
        pa = _qgwp_preferred_address(pa_ipv4, 42, pa_ipv6, 13, cid, pa_token)
        data = QGWP._encode_transport_parameters(QGWP._TransportParameters(
            preferred_address = pa, stateless_reset_token = zeros(UInt8, 16), active_connection_id_limit = UInt64(2)))
        p = _qgwp_decode(data; from_server = true)
        @test p isa QGWP._TransportParameters
        # We keep preferred_address as its validated encoding.
        got = p.preferred_address
        @test got == pa
        @test got[1:4] == UInt8[127, 0, 0, 1] && got[5:6] == UInt8[0, 42]       # IPv4
        @test got[7:22] == UInt8.(1:16) && got[23:24] == UInt8[0, 13]           # IPv6
        @test got[25] == 4 && got[26:29] == cid                                  # connection ID
        @test got[30:45] == pa_token                                             # stateless reset token
    end

    @testset "TestPreferredAddressFromClient" begin
        b = _qgwp_param(QGWP._TP_PREFERRED_ADDRESS, _qgwp_b("foobar"))
        @test _qgwp_tp_error(_qgwp_decode(b; from_server = false))  # "client sent a preferred_address"
    end

    @testset "TestPreferredAddressZeroLengthConnectionID" begin
        pa = _qgwp_preferred_address(pa_ipv4, 42, pa_ipv6, 13, UInt8[], pa_token)
        data = QGWP._encode_transport_parameters(QGWP._TransportParameters(
            preferred_address = pa, stateless_reset_token = zeros(UInt8, 16)))
        @test _qgwp_tp_error(_qgwp_decode(data; from_server = true))  # "invalid connection ID length: 0"
    end

    @testset "TestPreferredAddressErrorOnEOF" begin
        raw = vcat(UInt8[127, 0, 0, 1], UInt8[0, 42], UInt8.(1:16), UInt8[13, 37], UInt8[4],
                   UInt8[0xde, 0xad, 0xbe, 0xef], UInt8.(16:-1:1))
        for i in 1:(length(raw) - 1)
            # As in Go, the value follows the ID with no length field.
            b = vcat(_qgwp_v(QGWP._TP_PREFERRED_ADDRESS), raw[1:i])
            @test _qgwp_tp_error(_qgwp_decode(b; from_server = true))
        end
    end
end
