using Test
using Reseau
import Reseau: EventLoops

@testset "tracing hooks" begin
    EventLoops.io_tracing_init()
    EventLoops.tracing_task_begin(EventLoops.tracing_input_stream_read)
    EventLoops.tracing_task_end(EventLoops.tracing_input_stream_read)
    @test true
end
