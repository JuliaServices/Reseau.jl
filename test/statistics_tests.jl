using Test
using Reseau

function _wait_ready_stats(ch::Channel; timeout_ns::Integer = 5_000_000_000)
    deadline = Base.time_ns() + timeout_ns
    while !isready(ch) && Base.time_ns() < deadline
        yield()
    end
    return isready(ch)
end

mutable struct TestStatsChannelHandler <: Reseau.AbstractChannelHandler
    stats::Reseau.SocketHandlerStatistics
end

TestStatsChannelHandler() = TestStatsChannelHandler(Reseau.SocketHandlerStatistics())

Reseau.handler_process_read_message(
    ::TestStatsChannelHandler,
    ::Reseau.ChannelSlot,
    ::Reseau.IoMessage,
) = nothing

Reseau.handler_process_write_message(
    ::TestStatsChannelHandler,
    ::Reseau.ChannelSlot,
    ::Reseau.IoMessage,
) = nothing

Reseau.handler_increment_read_window(
    ::TestStatsChannelHandler,
    ::Reseau.ChannelSlot,
    ::Csize_t,
) = nothing

function Reseau.handler_shutdown(
        ::TestStatsChannelHandler,
        slot::Reseau.ChannelSlot,
        direction::Reseau.ChannelDirection.T,
        _error_code::Int,
    )
    Reseau.channel_slot_on_handler_shutdown_complete!(slot, direction, false, true)
    return nothing
end

Reseau.handler_initial_window_size(::TestStatsChannelHandler) = Csize_t(0)
Reseau.handler_message_overhead(::TestStatsChannelHandler) = Csize_t(0)
Reseau.handler_destroy(::TestStatsChannelHandler) = nothing
Reseau.handler_trigger_write(::TestStatsChannelHandler) = nothing

function Reseau.handler_reset_statistics(handler::TestStatsChannelHandler)::Nothing
    Reseau.crt_statistics_socket_reset!(handler.stats)
    return nothing
end

Reseau.handler_gather_statistics(handler::TestStatsChannelHandler) = handler.stats

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
        if entry isa Reseau.SocketHandlerStatistics
            copy_entry = Reseau.SocketHandlerStatistics()
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
        Reseau.io_library_init()

        elg_opts = Reseau.EventLoopGroupOptions(; loop_count = 1)
        elg = Reseau.event_loop_group_new(elg_opts)
        @test !(elg isa Reseau.ErrorResult)
        elg isa Reseau.ErrorResult && return

        event_loop = Reseau.event_loop_group_get_next_loop(elg)
        @test event_loop !== nothing
        event_loop === nothing && return

        channel = Reseau.Channel(event_loop, nothing)
        handler = TestStatsChannelHandler()
        slot = Reseau.channel_slot_new!(channel)
        Reseau.channel_slot_set_handler!(slot, handler)
        if Reseau.channel_first_slot(channel) !== slot
            Reseau.channel_slot_insert_end!(channel, slot)
        end

        results = Channel{Tuple{Reseau.StatisticsSampleInterval, Vector{Any}}}(1)
        stats_handler = TestStatisticsHandler(UInt64(50), results)

        set_task = Reseau.ScheduledTask(
            (ch, _status) -> Reseau.channel_set_statistics_handler!(ch, stats_handler),
            channel;
            type_tag = "set_stats_handler",
        )
        Reseau.event_loop_schedule_task_now!(event_loop, set_task)

        update_task = Reseau.ScheduledTask(
            (h, _status) -> begin
                h.stats.bytes_read = 111
                h.stats.bytes_written = 222
                return nothing
            end,
            handler;
            type_tag = "update_stats",
        )
        Reseau.event_loop_schedule_task_now!(event_loop, update_task)

        @test _wait_ready_stats(results; timeout_ns = 5_000_000_000)
        interval, stats_vec = take!(results)
        @test interval.end_time_ms >= interval.begin_time_ms
        @test length(stats_vec) == 1
        stats = stats_vec[1]
        @test stats isa Reseau.SocketHandlerStatistics
        @test stats.bytes_read == 111
        @test stats.bytes_written == 222

        @test handler.stats.bytes_read == 0
        @test handler.stats.bytes_written == 0

        clear_task = Reseau.ScheduledTask(
            (ch, _status) -> Reseau.channel_set_statistics_handler!(ch, nothing),
            channel;
            type_tag = "clear_stats_handler",
        )
        Reseau.event_loop_schedule_task_now!(event_loop, clear_task)

        Reseau.event_loop_group_destroy!(elg)
        Reseau.io_library_clean_up()
    end
end
