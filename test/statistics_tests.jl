using Test
using Reseau
import Reseau: EventLoops, Sockets, Threads

function _wait_ready_stats(ch::Channel; timeout_ns::Integer = 5_000_000_000)
    deadline = Base.time_ns() + timeout_ns
    while !isready(ch) && Base.time_ns() < deadline
        yield()
    end
    return isready(ch)
end

mutable struct TestStatsChannelHandler <: Sockets.AbstractChannelHandler
    stats::Sockets.SocketHandlerStatistics
end

TestStatsChannelHandler() = TestStatsChannelHandler(Sockets.SocketHandlerStatistics())

Sockets.handler_process_read_message(
    ::TestStatsChannelHandler,
    ::Sockets.ChannelSlot,
    ::EventLoops.IoMessage,
) = nothing

Sockets.handler_process_write_message(
    ::TestStatsChannelHandler,
    ::Sockets.ChannelSlot,
    ::EventLoops.IoMessage,
) = nothing

Sockets.handler_increment_read_window(
    ::TestStatsChannelHandler,
    ::Sockets.ChannelSlot,
    ::Csize_t,
) = nothing

function Sockets.handler_shutdown(
        ::TestStatsChannelHandler,
        slot::Sockets.ChannelSlot,
        direction::Sockets.ChannelDirection.T,
        _error_code::Int,
    )
    Sockets.channel_slot_on_handler_shutdown_complete!(slot, direction, false, true)
    return nothing
end

Sockets.handler_initial_window_size(::TestStatsChannelHandler) = Csize_t(0)
Sockets.handler_message_overhead(::TestStatsChannelHandler) = Csize_t(0)
Sockets.handler_destroy(::TestStatsChannelHandler) = nothing
Sockets.handler_trigger_write(::TestStatsChannelHandler) = nothing

function Sockets.handler_reset_statistics(handler::TestStatsChannelHandler)::Nothing
    Sockets.crt_statistics_socket_reset!(handler.stats)
    return nothing
end

Sockets.handler_gather_statistics(handler::TestStatsChannelHandler) = handler.stats

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

@testset "channel statistics handler integration" begin
    if Base.Threads.nthreads(:interactive) <= 1
        @test true
    else
        Sockets.io_library_init()

        elg_opts = EventLoops.EventLoopGroupOptions(; loop_count = 1)
        elg = EventLoops.EventLoopGroup(elg_opts)
        @test !(elg isa Reseau.ErrorResult)
        elg isa Reseau.ErrorResult && return

        event_loop = EventLoops.event_loop_group_get_next_loop(elg)
        @test event_loop !== nothing
        event_loop === nothing && return

        channel = Sockets.Channel(event_loop, nothing)
        handler = TestStatsChannelHandler()
        slot = Sockets.channel_slot_new!(channel)
        Sockets.channel_slot_set_handler!(slot, handler)
        if Sockets.channel_first_slot(channel) !== slot
            Sockets.channel_slot_insert_end!(channel, slot)
        end

        results = Channel{Tuple{Reseau.StatisticsSampleInterval, Vector{Any}}}(1)
        stats_handler = TestStatisticsHandler(UInt64(50), results)

        set_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
            Sockets.channel_set_statistics_handler!(channel, stats_handler)
        end); type_tag = "set_stats_handler")
        EventLoops.event_loop_schedule_task_now!(event_loop, set_task)

        update_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
            handler.stats.bytes_read = 111
            handler.stats.bytes_written = 222
            return nothing
        end); type_tag = "update_stats")
        EventLoops.event_loop_schedule_task_now!(event_loop, update_task)

        @test _wait_ready_stats(results; timeout_ns = 5_000_000_000)
        interval, stats_vec = take!(results)
        @test interval.end_time_ms >= interval.begin_time_ms
        @test length(stats_vec) == 1
        stats = stats_vec[1]
        @test stats isa Sockets.SocketHandlerStatistics
        @test stats.bytes_read == 111
        @test stats.bytes_written == 222

        @test handler.stats.bytes_read == 0
        @test handler.stats.bytes_written == 0

        clear_task = Reseau.ScheduledTask(Reseau.TaskFn(status -> begin
            Sockets.channel_set_statistics_handler!(channel, nothing)
        end); type_tag = "clear_stats_handler")
        EventLoops.event_loop_schedule_task_now!(event_loop, clear_task)

        EventLoops.event_loop_group_release!(elg)
        Sockets.io_library_clean_up()
    end
end
