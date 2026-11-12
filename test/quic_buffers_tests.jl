using Test
using Reseau
using Random

# Bookkeeping for QUIC connections: range sets (received packet numbers,
# acknowledged CRYPTO bytes), CRYPTO stream send and receive buffers, and
# stream send and receive buffers.

const QBF = Reseau.QUIC

_qbf_set(ranges...) = (s = QBF._RangeSet(); foreach(r -> push!(s, Int64(r.start):Int64(r.stop)), ranges); s)
_qbf_ranges(s) = [r for r in s]
_qbf_receive!(rb, offset, data) = QBF._crypto_receive!(rb, UInt64(offset), data)
_qbf_buffered(rb) = sum((length(f[2]) for f in rb.fragments); init = 0)
_qbf_insert!(rb, offset, data; fin = false) = QBF._recv_insert!(rb, Int64(offset), data, fin)

@testset "QUIC buffers" begin
    @testset "range sets agree with a plain set under random edits" begin
        rng = Random.Xoshiro(9000)
        for _ in 1:200
            s = QBF._RangeSet()
            ref = Set{Int64}()
            for _ in 1:40
                a = Int64(rand(rng, 0:200))
                r = a:(a + Int64(rand(rng, -1:30)))
                if rand(rng, Bool)
                    push!(s, r)
                    union!(ref, r)
                else
                    delete!(s, r)
                    setdiff!(ref, r)
                end
                # Sorted, disjoint, non-adjacent, and holding exactly `ref`.
                @test all(i -> last(s.ranges[i]) + 1 < first(s.ranges[i + 1]), 1:(length(s.ranges) - 1))
                @test all(!isempty, s.ranges)
                @test Set{Int64}(Iterators.flatten(s.ranges)) == ref
            end
        end
    end

    @testset "range sets" begin
        s = QBF._RangeSet()
        @test isempty(s)
        push!(s, Int64(10):Int64(12))
        push!(s, Int64(1):Int64(3))
        push!(s, Int64(20):Int64(20))
        @test _qbf_ranges(s) == [1:3, 10:12, 20:20]
        @test length(s) == 3
        push!(s, Int64(4):Int64(5))       # adjacent: merges
        @test _qbf_ranges(s) == [1:5, 10:12, 20:20]
        push!(s, Int64(11):Int64(19))     # overlapping and adjacent
        @test _qbf_ranges(s) == [1:5, 10:20]
        push!(s, Int64(2):Int64(3))       # already covered
        @test _qbf_ranges(s) == [1:5, 10:20]
        push!(s, Int64(0):Int64(30))      # covers everything
        @test _qbf_ranges(s) == [0:30]
        @test 15 in s
        @test !(31 in s)
        @test QBF._range_set_max(s) == 30

        s = _qbf_set(1:10, 20:30)
        delete!(s, Int64(4):Int64(6))     # splits
        @test _qbf_ranges(s) == [1:3, 7:10, 20:30]
        delete!(s, Int64(8):Int64(25))    # spans a gap
        @test _qbf_ranges(s) == [1:3, 7:7, 26:30]
        delete!(s, Int64(0):Int64(100))
        @test isempty(s)

        # ACK frames list ranges largest first, and only the most recent ones are kept.
        s = _qbf_set(1:2, 5:5, 9:12)
        @test QBF._descending_ranges(s) == [UInt64(9):UInt64(12), UInt64(5):UInt64(5), UInt64(1):UInt64(2)]
        QBF._keep_largest_ranges!(s, 2)
        @test _qbf_ranges(s) == [5:5, 9:12]
    end

    @testset "CRYPTO reassembly" begin
        rb = QBF._Reassembly()
        data = rand(UInt8, 100)
        @test _qbf_receive!(rb, 0, data[1:10]) == data[1:10]
        # Out of order: held until the gap is filled.
        @test _qbf_receive!(rb, 30, data[31:40]) == UInt8[]
        @test _qbf_receive!(rb, 50, data[51:60]) == UInt8[]
        @test _qbf_receive!(rb, 10, data[11:31]) == data[11:40]  # overlaps the held fragment
        # Already delivered: ignored; partly delivered: trimmed.
        @test _qbf_receive!(rb, 0, data[1:20]) == UInt8[]
        @test _qbf_receive!(rb, 35, data[36:55]) == data[41:60]
        @test rb.delivered == 60
        @test isempty(rb.fragments)
        # A peer may not run more than the buffer limit ahead (RFC 9000 Section 7.5).
        err = _qbf_receive!(rb, 60 + QBF._CRYPTO_BUFFER_LIMIT, UInt8[0x01])
        @test err isa QBF._TransportError
        @test err.code == QBF._CRYPTO_BUFFER_EXCEEDED
        @test _qbf_receive!(rb, 60 + QBF._CRYPTO_BUFFER_LIMIT - 1, UInt8[0x01]) == UInt8[]
    end

    @testset "CRYPTO send buffer" begin
        sb = QBF._CryptoSendBuffer()
        @test !QBF._crypto_has_pending(sb)
        data = rand(UInt8, 100)
        QBF._crypto_queue!(sb, data)
        @test QBF._crypto_has_pending(sb)
        @test QBF._crypto_next_chunk!(sb, 30) == 0:29
        @test QBF._crypto_next_chunk!(sb, 30) == 30:59
        @test QBF._crypto_bytes(sb, Int64(30):Int64(59)) == data[31:60]
        QBF._crypto_on_acked!(sb, Int64(40):Int64(49))
        # Losing 30:59 resends only what was not acknowledged meanwhile.
        QBF._crypto_on_lost!(sb, Int64(30):Int64(59))
        @test QBF._crypto_next_chunk!(sb, 30) == 30:39
        # The resent 50:59 joins the never-sent 60:99 into one run.
        @test QBF._crypto_next_chunk!(sb, 30) == 50:79
        @test QBF._crypto_next_chunk!(sb, 100) == 80:99
        @test QBF._crypto_next_chunk!(sb, 100) === nothing
        # More data queued later continues at the next offset.
        QBF._crypto_queue!(sb, UInt8[0x01, 0x02])
        @test QBF._crypto_next_chunk!(sb, 100) == 100:101
        # Acknowledged data is never resent.
        QBF._crypto_on_acked!(sb, Int64(0):Int64(101))
        QBF._crypto_on_lost!(sb, Int64(0):Int64(101))
        @test !QBF._crypto_has_pending(sb)
    end

    @testset "reassembly holds each out-of-order byte once" begin
        rb = QBF._Reassembly()
        data = rand(UInt8, 100)
        # The same fragment, again and again, is stored once.
        for _ in 1:50
            @test _qbf_receive!(rb, 40, data[41:50]) == UInt8[]
        end
        @test _qbf_buffered(rb) == 10
        # Overlapping fragments store only the bytes not already held.
        @test _qbf_receive!(rb, 30, data[31:60]) == UInt8[]
        @test _qbf_buffered(rb) == 30
        @test _qbf_receive!(rb, 20, data[21:35]) == UInt8[]
        @test _qbf_buffered(rb) == 40
        @test _qbf_receive!(rb, 0, data[1:20]) == data[1:60]
        @test isempty(rb.fragments)
    end

    @testset "stream send buffer" begin
        sb = QBF._StreamSendBuffer()
        @test !QBF._send_has_pending(sb)
        data = rand(UInt8, 1000)
        QBF._send_write!(sb, data)
        @test QBF._send_end(sb) == 1000
        @test QBF._send_has_pending(sb)
        # Flow control: nothing at or past `limit` is sent for the first time.
        @test QBF._send_next_chunk!(sb, 300, Int64(200)) == (Int64(0):Int64(199), false)
        @test QBF._send_next_chunk!(sb, 300, Int64(200)) === nothing
        @test sb.max_sent == 200
        @test QBF._send_next_chunk!(sb, 300, Int64(1000)) == (Int64(200):Int64(499), false)
        @test QBF._send_bytes(sb, Int64(200):Int64(499)) == data[201:500]
        # A lost range below the limit is resent even when the limit has not grown.
        QBF._send_on_acked!(sb, Int64(0):Int64(99), false)
        QBF._send_on_lost!(sb, Int64(0):Int64(199), false)
        @test QBF._send_next_chunk!(sb, 300, Int64(200)) == (Int64(100):Int64(199), false)
        @test sb.max_sent == 500
        # Finishing marks the last chunk with FIN.
        QBF._send_finish!(sb)
        @test_throws ArgumentError QBF._send_write!(sb, UInt8[0x01])
        @test QBF._send_next_chunk!(sb, 1000, Int64(1000)) == (Int64(500):Int64(999), true)
        @test !QBF._send_has_pending(sb)
        # Acknowledged prefixes are released.
        QBF._send_on_acked!(sb, Int64(100):Int64(599), false)
        @test sb.base == 600
        @test QBF._send_bytes(sb, Int64(600):Int64(609)) == data[601:610]
        @test !QBF._send_all_acked(sb)
        # A lost FIN is resent; once acknowledged, nothing remains.
        QBF._send_on_lost!(sb, Int64(500):Int64(999), true)
        @test QBF._send_next_chunk!(sb, 1000, Int64(1000)) == (Int64(600):Int64(999), true)
        QBF._send_on_acked!(sb, Int64(600):Int64(999), true)
        @test QBF._send_all_acked(sb)
        @test sb.base == 1000
        QBF._send_on_lost!(sb, Int64(0):Int64(999), true)
        @test !QBF._send_has_pending(sb)

        # A FIN with no data left to send goes out alone, even at the flow-control limit.
        sb = QBF._StreamSendBuffer()
        QBF._send_write!(sb, UInt8[1, 2, 3])
        @test QBF._send_next_chunk!(sb, 100, Int64(3)) == (Int64(0):Int64(2), false)
        QBF._send_finish!(sb)
        @test QBF._send_next_chunk!(sb, 100, Int64(3)) == (Int64(3):Int64(2), true)
        @test QBF._send_next_chunk!(sb, 100, Int64(3)) === nothing
        # Only the chunk that reaches the end carries the FIN.
        sb = QBF._StreamSendBuffer()
        QBF._send_write!(sb, data)
        QBF._send_finish!(sb)
        @test QBF._send_next_chunk!(sb, 600, Int64(1000)) == (Int64(0):Int64(599), false)
        @test QBF._send_next_chunk!(sb, 600, Int64(1000)) == (Int64(600):Int64(999), true)
        # An empty stream finishes with a lone FIN at offset 0.
        sb = QBF._StreamSendBuffer()
        QBF._send_finish!(sb)
        @test QBF._send_next_chunk!(sb, 100, Int64(0)) == (Int64(0):Int64(-1), true)
    end

    @testset "stream receive buffer" begin
        rb = QBF._StreamReceiveBuffer()
        data = rand(UInt8, 100)
        @test _qbf_insert!(rb, 50, data[51:60]) === nothing
        @test rb.max_received == 60
        @test QBF._recv_readable(rb) == 0
        @test _qbf_insert!(rb, 0, data[1:50]) === nothing
        @test QBF._recv_readable(rb) == 60
        @test QBF._recv_read!(rb, 25) == data[1:25]
        @test QBF._recv_read!(rb, 100) == data[26:60]
        @test QBF._recv_read!(rb, 100) == UInt8[]
        @test !QBF._recv_finished(rb)
        @test _qbf_insert!(rb, 60, data[61:100]; fin = true) === nothing
        @test rb.final_size == 100
        @test QBF._recv_read!(rb, 100) == data[61:100]
        @test QBF._recv_finished(rb)

        # Final size rules (RFC 9000 Section 4.5).
        rb = QBF._StreamReceiveBuffer()
        @test _qbf_insert!(rb, 0, data[1:20]) === nothing
        @test _qbf_insert!(rb, 0, data[1:10]; fin = true) == QBF._FINAL_SIZE_ERROR  # below data received
        rb = QBF._StreamReceiveBuffer()
        @test _qbf_insert!(rb, 0, data[1:20]; fin = true) === nothing
        @test _qbf_insert!(rb, 0, data[1:20]; fin = true) === nothing  # repeated, same size
        @test _qbf_insert!(rb, 20, UInt8[0x01]) == QBF._FINAL_SIZE_ERROR  # past the final size
        @test _qbf_insert!(rb, 0, data[1:21]; fin = true) == QBF._FINAL_SIZE_ERROR  # a different final size
        @test _qbf_insert!(rb, 0, data[1:10]; fin = true) == QBF._FINAL_SIZE_ERROR  # a smaller one
        @test QBF._recv_set_final_size!(rb, Int64(20)) === nothing  # RESET_STREAM agreeing with it
        @test QBF._recv_set_final_size!(rb, Int64(19)) == QBF._FINAL_SIZE_ERROR
        rb = QBF._StreamReceiveBuffer()
        @test _qbf_insert!(rb, 0, data[1:30]) === nothing
        @test QBF._recv_set_final_size!(rb, Int64(29)) == QBF._FINAL_SIZE_ERROR
        @test QBF._recv_set_final_size!(rb, Int64(40)) === nothing
        @test rb.max_received == 40  # the final size counts against flow control
        # A FIN without data on an empty stream finishes it.
        rb = QBF._StreamReceiveBuffer()
        @test _qbf_insert!(rb, 0, UInt8[]; fin = true) === nothing
        @test QBF._recv_finished(rb)
    end
end
