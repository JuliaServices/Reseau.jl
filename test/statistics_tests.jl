using Test
using AwsIO

function _wait_ready_stats(ch::Channel; timeout_ns::Integer = 5_000_000_000)
    deadline = Base.time_ns() + timeout_ns
    while !isready(ch) && Base.time_ns() < deadline
        yield()
    end
    return isready(ch)
end

mutable struct TestStatsChannelHandler <: AwsIO.AbstractChannelHandler
    stats::AwsIO.SocketHandlerStatistics
end

TestStatsChannelHandler() = TestStatsChannelHandler(AwsIO.SocketHandlerStatistics())

AwsIO.handler_process_read_message(
    ::TestStatsChannelHandler,
    ::AwsIO.ChannelSlot,
    ::AwsIO.IoMessage,
) = nothing

AwsIO.handler_process_write_message(
    ::TestStatsChannelHandler,
    ::AwsIO.ChannelSlot,
    ::AwsIO.IoMessage,
) = nothing

AwsIO.handler_increment_read_window(
    ::TestStatsChannelHandler,
    ::AwsIO.ChannelSlot,
    ::Csize_t,
) = nothing

function AwsIO.handler_shutdown(
        ::TestStatsChannelHandler,
        slot::AwsIO.ChannelSlot,
        direction::AwsIO.ChannelDirection.T,
        _error_code::Int,
    )
    AwsIO.channel_slot_on_handler_shutdown_complete!(slot, direction, false, true)
    return nothing
end

AwsIO.handler_initial_window_size(::TestStatsChannelHandler) = Csize_t(0)
AwsIO.handler_message_overhead(::TestStatsChannelHandler) = Csize_t(0)
AwsIO.handler_destroy(::TestStatsChannelHandler) = nothing
AwsIO.handler_trigger_write(::TestStatsChannelHandler) = nothing

function AwsIO.handler_reset_statistics(handler::TestStatsChannelHandler)::Nothing
    AwsIO.crt_statistics_socket_reset!(handler.stats)
    return nothing
end

AwsIO.handler_gather_statistics(handler::TestStatsChannelHandler) = handler.stats

mutable struct TestStatisticsHandler <: AwsIO.StatisticsHandler
    report_ms::UInt64
    results::Channel{Tuple{AwsIO.StatisticsSampleInterval, Vector{Any}}}
end

AwsIO.report_interval_ms(handler::TestStatisticsHandler) = handler.report_ms
AwsIO.close!(::TestStatisticsHandler) = nothing

function AwsIO.process_statistics(
        handler::TestStatisticsHandler,
        interval::AwsIO.StatisticsSampleInterval,
        stats_list::AwsIO.ArrayList,
    )
    stats = Vector{Any}(undef, length(stats_list))
    for i in 1:length(stats_list)
        entry = stats_list.data[i]
        if entry isa AwsIO.SocketHandlerStatistics
            copy_entry = AwsIO.SocketHandlerStatistics()
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

@testset "channel statistics handler integration" begin
    if Threads.nthreads(:interactive) <= 1
        @test true
    else
        AwsIO.io_library_init()

        elg_opts = AwsIO.EventLoopGroupOptions(; loop_count = 1)
        elg = AwsIO.event_loop_group_new(elg_opts)
        @test !(elg isa AwsIO.ErrorResult)
        elg isa AwsIO.ErrorResult && return

        event_loop = AwsIO.event_loop_group_get_next_loop(elg)
        @test event_loop !== nothing
        event_loop === nothing && return

        channel = AwsIO.Channel(event_loop, nothing)
        handler = TestStatsChannelHandler()
        slot = AwsIO.channel_slot_new!(channel)
        AwsIO.channel_slot_set_handler!(slot, handler)
        if AwsIO.channel_first_slot(channel) !== slot
            AwsIO.channel_slot_insert_end!(channel, slot)
        end

        results = Channel{Tuple{AwsIO.StatisticsSampleInterval, Vector{Any}}}(1)
        stats_handler = TestStatisticsHandler(UInt64(50), results)

        set_task = AwsIO.ScheduledTask(
            (ch, _status) -> AwsIO.channel_set_statistics_handler!(ch, stats_handler),
            channel;
            type_tag = "set_stats_handler",
        )
        AwsIO.event_loop_schedule_task_now!(event_loop, set_task)

        update_task = AwsIO.ScheduledTask(
            (h, _status) -> begin
                h.stats.bytes_read = 111
                h.stats.bytes_written = 222
                return nothing
            end,
            handler;
            type_tag = "update_stats",
        )
        AwsIO.event_loop_schedule_task_now!(event_loop, update_task)

        @test _wait_ready_stats(results; timeout_ns = 5_000_000_000)
        interval, stats_vec = take!(results)
        @test interval.end_time_ms >= interval.begin_time_ms
        @test length(stats_vec) == 1
        stats = stats_vec[1]
        @test stats isa AwsIO.SocketHandlerStatistics
        @test stats.bytes_read == 111
        @test stats.bytes_written == 222

        @test handler.stats.bytes_read == 0
        @test handler.stats.bytes_written == 0

        clear_task = AwsIO.ScheduledTask(
            (ch, _status) -> AwsIO.channel_set_statistics_handler!(ch, nothing),
            channel;
            type_tag = "clear_stats_handler",
        )
        AwsIO.event_loop_schedule_task_now!(event_loop, clear_task)

        AwsIO.event_loop_group_destroy!(elg)
        AwsIO.io_library_clean_up()
    end
end
