using Test
using Reseau
import Reseau: Sockets

# Test the abstract StatisticsHandler interface
mutable struct TestStatisticsHandler <: Reseau.StatisticsHandler
    report_ms::UInt64
    results::Channel{Tuple{Reseau.StatisticsSampleInterval, Vector{Any}}}
end

Reseau.report_interval_ms(handler::TestStatisticsHandler) = handler.report_ms
Reseau.close!(::TestStatisticsHandler) = nothing

function Reseau.process_statistics(
        handler::TestStatisticsHandler,
        interval::Reseau.StatisticsSampleInterval,
        stats_list::AbstractVector,
    )
    stats = Vector{Any}(undef, length(stats_list))
    for i in 1:length(stats_list)
        entry = stats_list[i]
        if entry isa Sockets.SocketHandlerStatistics
            copy_entry = Sockets.SocketHandlerStatistics()
            copy_entry.category = entry.category
            copy_entry.bytes_read = entry.bytes_read
            copy_entry.bytes_written = entry.bytes_written
            stats[i] = copy_entry
        else
            stats[i] = entry
        end
    end
    put!(handler.results, (interval, stats))
    return nothing
end

@testset "StatisticsHandler abstract interface" begin
    results = Channel{Tuple{Reseau.StatisticsSampleInterval, Vector{Any}}}(1)
    handler = TestStatisticsHandler(UInt64(100), results)

    @test Reseau.report_interval_ms(handler) == UInt64(100)
    @test Reseau.close!(handler) === nothing

    interval = Reseau.StatisticsSampleInterval(UInt64(0), UInt64(100))
    stat = Sockets.SocketHandlerStatistics()
    stat.bytes_read = 42
    stat.bytes_written = 84
    Reseau.process_statistics(handler, interval, [stat])

    @test isready(results)
    recv_interval, recv_stats = take!(results)
    @test recv_interval.begin_time_ms == UInt64(0)
    @test recv_interval.end_time_ms == UInt64(100)
    @test length(recv_stats) == 1
    @test recv_stats[1] isa Sockets.SocketHandlerStatistics
    @test recv_stats[1].bytes_read == 42
    @test recv_stats[1].bytes_written == 84
end

@testset "SocketHandlerStatistics struct operations" begin
    @testset "default construction" begin
        stats = Sockets.SocketHandlerStatistics()
        @test stats.bytes_read == 0
        @test stats.bytes_written == 0
        @test stats.category == Sockets.STAT_CAT_SOCKET
    end

    @testset "init!" begin
        stats = Sockets.SocketHandlerStatistics()
        stats.bytes_read = 100
        stats.bytes_written = 200
        Sockets.crt_statistics_socket_init!(stats)
        @test stats.bytes_read == 0
        @test stats.bytes_written == 0
        @test stats.category == Sockets.STAT_CAT_SOCKET
    end

    @testset "set values and reset!" begin
        stats = Sockets.SocketHandlerStatistics()
        stats.bytes_read = 111
        stats.bytes_written = 222
        @test stats.bytes_read == 111
        @test stats.bytes_written == 222

        Sockets.crt_statistics_socket_reset!(stats)
        @test stats.bytes_read == 0
        @test stats.bytes_written == 0
        # category should be unchanged after reset
        @test stats.category == Sockets.STAT_CAT_SOCKET
    end

    @testset "cleanup!" begin
        stats = Sockets.SocketHandlerStatistics()
        stats.bytes_read = 50
        # cleanup is a no-op but should not error
        Sockets.crt_statistics_socket_cleanup!(stats)
        @test true
    end
end
