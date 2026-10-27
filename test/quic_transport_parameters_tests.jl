using Test
using Reseau

# QUIC transport parameters (RFC 9000 Section 18).

const QTP = Reseau.QUIC

function _qtp_param(id::Integer, value::AbstractVector{UInt8})
    buf = UInt8[]
    QTP._append_varint!(buf, UInt64(id))
    QTP._append_varint!(buf, UInt64(length(value)))
    append!(buf, value)
    return buf
end

function _qtp_varint_param(id::Integer, value::Integer)
    v = UInt8[]
    QTP._append_varint!(v, UInt64(value))
    return _qtp_param(id, v)
end

_qtp_decode(bytes; from_server::Bool = true) = QTP._decode_transport_parameters(bytes; from_server)

function _qtp_error(bytes; from_server::Bool = true)
    result = _qtp_decode(bytes; from_server)
    return result isa QTP._TransportError && result.code == QTP._TRANSPORT_PARAMETER_ERROR
end

@testset "QUIC transport parameters" begin
    @testset "defaults" begin
        p = QTP._TransportParameters()
        @test p.max_idle_timeout_ms == 0
        @test p.max_udp_payload_size == 65527
        @test p.initial_max_data == 0
        @test p.ack_delay_exponent == 3
        @test p.max_ack_delay_ms == 25
        @test !p.disable_active_migration
        @test p.active_connection_id_limit == 2
        @test p.original_destination_connection_id === nothing
        @test p.initial_source_connection_id === nothing
        # Defaults are not sent, and an empty list decodes to the defaults.
        @test QTP._encode_transport_parameters(p) == UInt8[]
        @test _qtp_decode(UInt8[]) == p
    end

    @testset "round trip" begin
        p = QTP._TransportParameters(
            original_destination_connection_id = rand(UInt8, 8),
            max_idle_timeout_ms = UInt64(30_000),
            stateless_reset_token = rand(UInt8, 16),
            max_udp_payload_size = UInt64(1452),
            initial_max_data = UInt64(1) << 20,
            initial_max_stream_data_bidi_local = UInt64(65536),
            initial_max_stream_data_bidi_remote = UInt64(65537),
            initial_max_stream_data_uni = UInt64(65538),
            initial_max_streams_bidi = UInt64(100),
            initial_max_streams_uni = UInt64(3),
            ack_delay_exponent = UInt64(4),
            max_ack_delay_ms = UInt64(40),
            disable_active_migration = true,
            active_connection_id_limit = UInt64(8),
            initial_source_connection_id = rand(UInt8, 8),
            retry_source_connection_id = rand(UInt8, 5),
        )
        @test _qtp_decode(QTP._encode_transport_parameters(p)) == p
        # Zero-length connection IDs are present, not absent.
        q = QTP._TransportParameters(initial_source_connection_id = UInt8[])
        @test _qtp_decode(QTP._encode_transport_parameters(q); from_server = false).initial_source_connection_id == UInt8[]
    end

    @testset "preferred_address" begin
        cid = rand(UInt8, 8)
        value = vcat(UInt8[127, 0, 0, 1, 0x11, 0x5c], zeros(UInt8, 16), UInt8[0x11, 0x5d], UInt8[length(cid)], cid, rand(UInt8, 16))
        p = _qtp_decode(_qtp_param(0x0d, value))
        @test p.preferred_address == value
        @test QTP._encode_transport_parameters(p) == _qtp_param(0x0d, value)
        # A server must not offer a zero-length connection ID there.
        bad = vcat(UInt8[127, 0, 0, 1, 0x11, 0x5c], zeros(UInt8, 16), UInt8[0x11, 0x5d, 0x00], rand(UInt8, 16))
        @test _qtp_error(_qtp_param(0x0d, bad))
        @test _qtp_error(_qtp_param(0x0d, value[1:(end - 1)]))
    end

    @testset "unknown and reserved parameters are ignored" begin
        # 31 * N + 27 are reserved for greasing (Section 18.1).
        bytes = vcat(_qtp_param(27, rand(UInt8, 5)), _qtp_param(31 * 1000 + 27, UInt8[]), _qtp_varint_param(0x04, 99), _qtp_param(0x4000, UInt8[0x01]))
        p = _qtp_decode(bytes)
        @test p.initial_max_data == 99
    end

    @testset "malformed lists are TRANSPORT_PARAMETER_ERROR" begin
        @test _qtp_error(vcat(_qtp_varint_param(0x04, 1), _qtp_varint_param(0x04, 2)))  # duplicate
        @test _qtp_error(_qtp_varint_param(0x04, 1)[1:(end - 1)])                          # truncated value
        @test _qtp_error(UInt8[0x04])                                                      # no length
        @test _qtp_error(_qtp_param(0x04, UInt8[0x01, 0x02]))                              # integer with trailing bytes
        @test _qtp_error(_qtp_param(0x04, UInt8[]))                                        # integer with no value
        @test _qtp_error(_qtp_param(0x0c, UInt8[0x01]))                                    # disable_active_migration has no value
        @test _qtp_error(_qtp_param(0x02, rand(UInt8, 15)))                                # reset token is 16 bytes
        @test _qtp_error(_qtp_param(0x0f, rand(UInt8, 21)))                                # connection IDs are at most 20 bytes
        # Value limits (Section 18.2).
        @test _qtp_error(_qtp_varint_param(0x03, 1199))
        @test _qtp_decode(_qtp_varint_param(0x03, 1200)).max_udp_payload_size == 1200
        @test _qtp_error(_qtp_varint_param(0x0a, 21))
        @test _qtp_decode(_qtp_varint_param(0x0a, 20)).ack_delay_exponent == 20
        @test _qtp_error(_qtp_varint_param(0x0b, 1 << 14))
        @test _qtp_error(_qtp_varint_param(0x0e, 1))
        @test _qtp_error(_qtp_varint_param(0x08, (1 << 60) + 1))
        @test _qtp_error(_qtp_varint_param(0x09, (1 << 60) + 1))
    end

    @testset "clients cannot send server-only parameters" begin
        for (id, value) in ((0x00, rand(UInt8, 8)), (0x02, rand(UInt8, 16)), (0x10, rand(UInt8, 8)))
            bytes = _qtp_param(id, value)
            @test _qtp_decode(bytes; from_server = true) isa QTP._TransportParameters
            @test _qtp_error(bytes; from_server = false)
        end
        cid = rand(UInt8, 8)
        preferred = vcat(zeros(UInt8, 24), UInt8[length(cid)], cid, rand(UInt8, 16))
        @test _qtp_error(_qtp_param(0x0d, preferred); from_server = false)
    end
end
