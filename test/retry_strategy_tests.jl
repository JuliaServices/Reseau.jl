using Test
using AwsIO

@testset "no retry strategy" begin
    AwsIO.io_library_init()

    strategy = AwsIO.NoRetryStrategy()
    res = AwsIO.retry_strategy_acquire_token!(strategy, (token, code, ud) -> nothing, nothing)
    @test res isa AwsIO.ErrorResult
    res isa AwsIO.ErrorResult && @test res.code == AwsIO.ERROR_IO_RETRY_PERMISSION_DENIED

    AwsIO.retry_strategy_shutdown!(strategy)
    AwsIO.io_library_clean_up()
end
