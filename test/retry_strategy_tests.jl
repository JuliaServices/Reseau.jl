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

@testset "exponential backoff max retries" begin
    if Threads.nthreads(:interactive) <= 1
        @test true
    else
        AwsIO.io_library_init()

        elg_opts = AwsIO.EventLoopGroupOptions(; loop_count = 1)
        elg = AwsIO.event_loop_group_new(elg_opts)
        @test !(elg isa AwsIO.ErrorResult)
        elg isa AwsIO.ErrorResult && return

        config = AwsIO.ExponentialBackoffConfig(;
            backoff_scale_factor_ms = 1,
            max_backoff_secs = 1,
            max_retries = 3,
            jitter_mode = :none,
        )
        strategy = AwsIO.ExponentialBackoffRetryStrategy(elg, config)

        mtx = ReentrantLock()
        retry_count = Ref(0)
        done_ch = Channel{Int}(1)

        on_ready = function (token, code, ud)
            lock(mtx) do
                retry_count[] += 1
            end
            res = AwsIO.retry_token_schedule_retry(token, AwsIO.RetryErrorType.SERVER_ERROR, on_ready, ud)
            if res isa AwsIO.ErrorResult
                put!(done_ch, res.code)
                AwsIO.retry_token_release!(token)
            end
            return nothing
        end

        on_acquired = function (token, code, ud)
            res = AwsIO.retry_token_schedule_retry(token, AwsIO.RetryErrorType.SERVER_ERROR, on_ready, ud)
            if res isa AwsIO.ErrorResult
                put!(done_ch, res.code)
                AwsIO.retry_token_release!(token)
            end
            return nothing
        end

        _ = AwsIO.retry_strategy_acquire_token!(strategy, on_acquired, nothing)

        deadline = Base.time_ns() + 5_000_000_000
        while !isready(done_ch) && Base.time_ns() < deadline
            yield()
        end

        @test isready(done_ch)
        if isready(done_ch)
            code = take!(done_ch)
            @test code == AwsIO.ERROR_IO_MAX_RETRIES_EXCEEDED
        end

        lock(mtx) do
            @test retry_count[] == Int(config.max_retries)
        end

        AwsIO.retry_strategy_shutdown!(strategy)
        AwsIO.event_loop_group_destroy!(elg)
        AwsIO.io_library_clean_up()
    end
end

@testset "exponential backoff client errors do not count" begin
    if Threads.nthreads(:interactive) <= 1
        @test true
    else
        AwsIO.io_library_init()

        elg_opts = AwsIO.EventLoopGroupOptions(; loop_count = 1)
        elg = AwsIO.event_loop_group_new(elg_opts)
        @test !(elg isa AwsIO.ErrorResult)
        elg isa AwsIO.ErrorResult && return

        config = AwsIO.ExponentialBackoffConfig(;
            backoff_scale_factor_ms = 1,
            max_backoff_secs = 1,
            max_retries = 3,
            jitter_mode = :none,
        )
        strategy = AwsIO.ExponentialBackoffRetryStrategy(elg, config)

        mtx = ReentrantLock()
        retry_count = Ref(0)
        client_errors = Ref(2)
        done_ch = Channel{Int}(1)

        on_ready = function (token, code, ud)
            lock(mtx) do
                retry_count[] += 1
            end
            err_type = AwsIO.RetryErrorType.SERVER_ERROR
            lock(mtx) do
                if client_errors[] > 0
                    client_errors[] -= 1
                    err_type = AwsIO.RetryErrorType.CLIENT_ERROR
                end
            end
            res = AwsIO.retry_token_schedule_retry(token, err_type, on_ready, ud)
            if res isa AwsIO.ErrorResult
                put!(done_ch, res.code)
                AwsIO.retry_token_release!(token)
            end
            return nothing
        end

        on_acquired = function (token, code, ud)
            res = AwsIO.retry_token_schedule_retry(token, AwsIO.RetryErrorType.SERVER_ERROR, on_ready, ud)
            if res isa AwsIO.ErrorResult
                put!(done_ch, res.code)
                AwsIO.retry_token_release!(token)
            end
            return nothing
        end

        _ = AwsIO.retry_strategy_acquire_token!(strategy, on_acquired, nothing)

        deadline = Base.time_ns() + 5_000_000_000
        while !isready(done_ch) && Base.time_ns() < deadline
            yield()
        end

        @test isready(done_ch)
        if isready(done_ch)
            code = take!(done_ch)
            @test code == AwsIO.ERROR_IO_MAX_RETRIES_EXCEEDED
        end

        lock(mtx) do
            @test retry_count[] == Int(config.max_retries) + 2
        end

        AwsIO.retry_strategy_shutdown!(strategy)
        AwsIO.event_loop_group_destroy!(elg)
        AwsIO.io_library_clean_up()
    end
end
