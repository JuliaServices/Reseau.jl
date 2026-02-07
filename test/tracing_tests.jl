using Test
using Reseau

@testset "tracing hooks" begin
    Reseau.io_tracing_init()
    Reseau.tracing_task_begin(Reseau.tracing_input_stream_read)
    Reseau.tracing_task_end(Reseau.tracing_input_stream_read)
    @test true
end
