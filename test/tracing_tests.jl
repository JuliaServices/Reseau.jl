using Test
using AwsIO

@testset "tracing hooks" begin
    AwsIO.io_tracing_init()
    AwsIO.tracing_task_begin(AwsIO.tracing_input_stream_read)
    AwsIO.tracing_task_end(AwsIO.tracing_input_stream_read)
    @test true
end
