using Test
using Reseau
import Reseau: EventLoops, Sockets

function _wait_ready(ch::Channel; timeout_ns::Integer = 5_000_000_000)
    deadline = Base.time_ns() + timeout_ns
    while !isready(ch) && Base.time_ns() < deadline
        yield()
    end
    return isready(ch)
end

@testset "no retry strategy" begin
    Sockets.io_library_init()

    strategy = Sockets.NoRetryStrategy()
    res = Sockets.retry_strategy_acquire_token!(strategy, (token, code, ud) -> nothing, nothing)
    @test res isa Reseau.ErrorResult
    res isa Reseau.ErrorResult && @test res.code == EventLoops.ERROR_IO_RETRY_PERMISSION_DENIED

    Sockets.retry_strategy_shutdown!(strategy)
    Sockets.io_library_clean_up()
end

@testset "exponential backoff max retries" begin
    if Base.Threads.nthreads(:interactive) <= 1
        @test true
    else
        for jitter_mode in (:none, :full, :decorrelated, :default)
            @testset "jitter $(jitter_mode)" begin
                Sockets.io_library_init()

                elg = EventLoops.EventLoopGroup(EventLoops.EventLoopGroupOptions(; loop_count = 1))
                @test !(elg isa Reseau.ErrorResult)
                elg isa Reseau.ErrorResult && return

                config = Sockets.ExponentialBackoffConfig(;
                    backoff_scale_factor_ms = 1,
                    max_backoff_secs = 1,
                    max_retries = 3,
                    jitter_mode = jitter_mode,
                )
                strategy = Sockets.ExponentialBackoffRetryStrategy(elg, config)
                @test !(strategy isa Reseau.ErrorResult)
                if strategy isa Reseau.ErrorResult
                    EventLoops.event_loop_group_release!(elg)
                    Sockets.io_library_clean_up()
                    return
                end

                mtx = ReentrantLock()
                retry_count = Ref(0)
                done_ch = Channel{Int}(1)

                on_ready = function (token, code, ud)
                    lock(mtx) do
                        retry_count[] += 1
                    end
                    res = Sockets.retry_token_schedule_retry(token, Sockets.RetryErrorType.SERVER_ERROR, on_ready, ud)
                    if res isa Reseau.ErrorResult
                        put!(done_ch, res.code)
                        Sockets.retry_token_release!(token)
                    end
                    return nothing
                end

                on_acquired = function (token, code, ud)
                    res = Sockets.retry_token_schedule_retry(token, Sockets.RetryErrorType.SERVER_ERROR, on_ready, ud)
                    if res isa Reseau.ErrorResult
                        put!(done_ch, res.code)
                        Sockets.retry_token_release!(token)
                    end
                    return nothing
                end

                _ = Sockets.retry_strategy_acquire_token!(strategy, on_acquired, nothing)

                deadline = Base.time_ns() + 5_000_000_000
                while !isready(done_ch) && Base.time_ns() < deadline
                    yield()
                end

                @test isready(done_ch)
                if isready(done_ch)
                    code = take!(done_ch)
                    @test code == EventLoops.ERROR_IO_MAX_RETRIES_EXCEEDED
                end

                lock(mtx) do
                    @test retry_count[] == Int(config.max_retries)
                end

                Sockets.retry_strategy_shutdown!(strategy)
                EventLoops.event_loop_group_release!(elg)
                Sockets.io_library_clean_up()
            end
        end
    end
end

@testset "exponential backoff client errors do not count" begin
    if Base.Threads.nthreads(:interactive) <= 1
        @test true
    else
        Sockets.io_library_init()

        elg = EventLoops.EventLoopGroup(EventLoops.EventLoopGroupOptions(; loop_count = 1))
        @test !(elg isa Reseau.ErrorResult)
        elg isa Reseau.ErrorResult && return

        config = Sockets.ExponentialBackoffConfig(;
            backoff_scale_factor_ms = 1,
            max_backoff_secs = 1,
            max_retries = 3,
            jitter_mode = :none,
        )
        strategy = Sockets.ExponentialBackoffRetryStrategy(elg, config)
        @test !(strategy isa Reseau.ErrorResult)
        if strategy isa Reseau.ErrorResult
            EventLoops.event_loop_group_release!(elg)
            Sockets.io_library_clean_up()
            return
        end

        mtx = ReentrantLock()
        retry_count = Ref(0)
        client_errors = Ref(2)
        done_ch = Channel{Int}(1)

        on_ready = function (token, code, ud)
            lock(mtx) do
                retry_count[] += 1
            end
            err_type = Reseau.RetryErrorType.SERVER_ERROR
            lock(mtx) do
                if client_errors[] > 0
                    client_errors[] -= 1
                    err_type = Sockets.RetryErrorType.CLIENT_ERROR
                end
            end
            res = Sockets.retry_token_schedule_retry(token, err_type, on_ready, ud)
            if res isa Reseau.ErrorResult
                put!(done_ch, res.code)
                Sockets.retry_token_release!(token)
            end
            return nothing
        end

        on_acquired = function (token, code, ud)
            res = Sockets.retry_token_schedule_retry(token, Sockets.RetryErrorType.SERVER_ERROR, on_ready, ud)
            if res isa Reseau.ErrorResult
                put!(done_ch, res.code)
                Sockets.retry_token_release!(token)
            end
            return nothing
        end

        _ = Sockets.retry_strategy_acquire_token!(strategy, on_acquired, nothing)

        deadline = Base.time_ns() + 5_000_000_000
        while !isready(done_ch) && Base.time_ns() < deadline
            yield()
        end

        @test isready(done_ch)
        if isready(done_ch)
            code = take!(done_ch)
            @test code == EventLoops.ERROR_IO_MAX_RETRIES_EXCEEDED
        end

        lock(mtx) do
            @test retry_count[] == Int(config.max_retries) + 2
        end

        Sockets.retry_strategy_shutdown!(strategy)
        EventLoops.event_loop_group_release!(elg)
        Sockets.io_library_clean_up()
    end
end

@testset "exponential backoff no jitter time taken" begin
    if Base.Threads.nthreads(:interactive) <= 1
        @test true
    else
        Sockets.io_library_init()

        elg = EventLoops.EventLoopGroup(EventLoops.EventLoopGroupOptions(; loop_count = 1))
        @test !(elg isa Reseau.ErrorResult)
        elg isa Reseau.ErrorResult && return

        config = Sockets.ExponentialBackoffConfig(;
            backoff_scale_factor_ms = 5,
            max_backoff_secs = 10,
            max_retries = 3,
            jitter_mode = :none,
        )
        strategy = Sockets.ExponentialBackoffRetryStrategy(elg, config)
        @test !(strategy isa Reseau.ErrorResult)
        if strategy isa Reseau.ErrorResult
            EventLoops.event_loop_group_release!(elg)
            Sockets.io_library_clean_up()
            return
        end

        mtx = ReentrantLock()
        retry_count = Ref(0)
        done_ch = Channel{Int}(1)

        on_ready = function (token, code, ud)
            lock(mtx) do
                retry_count[] += 1
            end
            res = Sockets.retry_token_schedule_retry(token, Sockets.RetryErrorType.SERVER_ERROR, on_ready, ud)
            if res isa Reseau.ErrorResult
                put!(done_ch, res.code)
                Sockets.retry_token_release!(token)
            end
            return nothing
        end

        on_acquired = function (token, code, ud)
            res = Sockets.retry_token_schedule_retry(token, Sockets.RetryErrorType.SERVER_ERROR, on_ready, ud)
            if res isa Reseau.ErrorResult
                put!(done_ch, res.code)
                Sockets.retry_token_release!(token)
            end
            return nothing
        end

        before = Ref{UInt64}()
        @test Reseau.high_res_clock_get_ticks(before) == Reseau.OP_SUCCESS

        _ = Sockets.retry_strategy_acquire_token!(strategy, on_acquired, nothing)

        deadline = Base.time_ns() + 10_000_000_000
        while !isready(done_ch) && Base.time_ns() < deadline
            yield()
        end

        after = Ref{UInt64}()
        @test Reseau.high_res_clock_get_ticks(after) == Reseau.OP_SUCCESS

        @test isready(done_ch)
        if isready(done_ch)
            code = take!(done_ch)
            @test code == EventLoops.ERROR_IO_MAX_RETRIES_EXCEEDED
        end

        scale_ns = config.backoff_scale_factor_ms * UInt64(1_000_000)
        expected_interval = scale_ns * UInt64(7)
        @test expected_interval <= after[] - before[]

        lock(mtx) do
            @test retry_count[] == Int(config.max_retries)
        end

        Sockets.retry_strategy_shutdown!(strategy)
        EventLoops.event_loop_group_release!(elg)
        Sockets.io_library_clean_up()
    end
end

@testset "exponential backoff max backoff cap" begin
    if Base.Threads.nthreads(:interactive) <= 1
        @test true
    else
        Sockets.io_library_init()

        elg = EventLoops.EventLoopGroup(EventLoops.EventLoopGroupOptions(; loop_count = 1))
        @test !(elg isa Reseau.ErrorResult)
        elg isa Reseau.ErrorResult && return

        config = Sockets.ExponentialBackoffConfig(;
            backoff_scale_factor_ms = 400,
            max_backoff_secs = 1,
            max_retries = 3,
            jitter_mode = :none,
        )
        strategy = Sockets.ExponentialBackoffRetryStrategy(elg, config)
        @test !(strategy isa Reseau.ErrorResult)
        if strategy isa Reseau.ErrorResult
            EventLoops.event_loop_group_release!(elg)
            Sockets.io_library_clean_up()
            return
        end

        mtx = ReentrantLock()
        retry_count = Ref(0)
        done_ch = Channel{Int}(1)

        on_ready = function (token, code, ud)
            lock(mtx) do
                retry_count[] += 1
            end
            res = Sockets.retry_token_schedule_retry(token, Sockets.RetryErrorType.SERVER_ERROR, on_ready, ud)
            if res isa Reseau.ErrorResult
                put!(done_ch, res.code)
                Sockets.retry_token_release!(token)
            end
            return nothing
        end

        on_acquired = function (token, code, ud)
            res = Sockets.retry_token_schedule_retry(token, Sockets.RetryErrorType.SERVER_ERROR, on_ready, ud)
            if res isa Reseau.ErrorResult
                put!(done_ch, res.code)
                Sockets.retry_token_release!(token)
            end
            return nothing
        end

        before = Ref{UInt64}()
        @test Reseau.high_res_clock_get_ticks(before) == Reseau.OP_SUCCESS

        _ = Sockets.retry_strategy_acquire_token!(strategy, on_acquired, nothing)

        deadline = Base.time_ns() + 15_000_000_000
        while !isready(done_ch) && Base.time_ns() < deadline
            yield()
        end

        after = Ref{UInt64}()
        @test Reseau.high_res_clock_get_ticks(after) == Reseau.OP_SUCCESS

        @test isready(done_ch)
        if isready(done_ch)
            code = take!(done_ch)
            @test code == EventLoops.ERROR_IO_MAX_RETRIES_EXCEEDED
        end

        scale_ns = config.backoff_scale_factor_ms * UInt64(1_000_000)
        max_backoff_ns = config.max_backoff_secs * UInt64(1_000_000_000)
        expected_interval =
            min(max_backoff_ns, scale_ns) +
            min(max_backoff_ns, scale_ns * UInt64(2)) +
            min(max_backoff_ns, scale_ns * UInt64(4))
        @test expected_interval <= after[] - before[]

        lock(mtx) do
            @test retry_count[] == Int(config.max_retries)
        end

        Sockets.retry_strategy_shutdown!(strategy)
        EventLoops.event_loop_group_release!(elg)
        Sockets.io_library_clean_up()
    end
end

@testset "exponential backoff invalid options" begin
    Sockets.io_library_init()

    elg = EventLoops.EventLoopGroup(EventLoops.EventLoopGroupOptions(; loop_count = 1))
    @test !(elg isa Reseau.ErrorResult)
    elg isa Reseau.ErrorResult && return

    config = Sockets.ExponentialBackoffConfig(;
        max_retries = 64,
    )
    strategy = Sockets.ExponentialBackoffRetryStrategy(elg, config)
    @test strategy isa Reseau.ErrorResult
    if strategy isa Reseau.ErrorResult
        @test strategy.code == Reseau.ERROR_INVALID_ARGUMENT
    end

    EventLoops.event_loop_group_release!(elg)
    Sockets.io_library_clean_up()
end

@testset "standard retry failure exhausts bucket" begin
    if Base.Threads.nthreads(:interactive) <= 1
        @test true
    else
        Sockets.io_library_init()

        elg = EventLoops.EventLoopGroup(EventLoops.EventLoopGroupOptions(; loop_count = 1))
        @test !(elg isa Reseau.ErrorResult)
        elg isa Reseau.ErrorResult && return

        backoff_config = Sockets.ExponentialBackoffConfig(;
            backoff_scale_factor_ms = 1,
            max_backoff_secs = 1,
            max_retries = 3,
            jitter_mode = :none,
        )
        config = Sockets.StandardRetryConfig(;
            initial_bucket_capacity = 15,
            backoff_config = backoff_config,
        )
        strategy = Sockets.StandardRetryStrategy(elg, config)
        @test !(strategy isa Reseau.ErrorResult)
        if strategy isa Reseau.ErrorResult
            EventLoops.event_loop_group_release!(elg)
            Sockets.io_library_clean_up()
            return
        end

        partition = "us-east-1:super-badly-named-aws-service"

        acquired_ch = Channel{Tuple{Any, Int}}(1)
        on_acquired = (token, code, ud) -> put!(acquired_ch, (token, code))
        _ = Sockets.retry_strategy_acquire_token!(strategy, partition, on_acquired, nothing, 0)
        @test _wait_ready(acquired_ch)
        token1, code1 = take!(acquired_ch)
        @test code1 == Reseau.AWS_OP_SUCCESS

        acquired_ch2 = Channel{Tuple{Any, Int}}(1)
        on_acquired2 = (token, code, ud) -> put!(acquired_ch2, (token, code))
        _ = Sockets.retry_strategy_acquire_token!(strategy, partition, on_acquired2, nothing, 0)
        @test _wait_ready(acquired_ch2)
        token2, code2 = take!(acquired_ch2)
        @test code2 == Reseau.AWS_OP_SUCCESS

        ready_ch = Channel{Tuple{Any, Int}}(1)
        on_ready = (token, code, ud) -> put!(ready_ch, (token, code))
        res = Sockets.retry_token_schedule_retry(token1, Sockets.RetryErrorType.TRANSIENT, on_ready, nothing)
        @test !(res isa Reseau.ErrorResult)
        @test _wait_ready(ready_ch)
        ready_token, ready_code = take!(ready_ch)
        @test ready_token === token1
        @test ready_code == Reseau.AWS_OP_SUCCESS

        ready_ch2 = Channel{Tuple{Any, Int}}(1)
        on_ready2 = (token, code, ud) -> put!(ready_ch2, (token, code))
        res = Sockets.retry_token_schedule_retry(token2, Sockets.RetryErrorType.SERVER_ERROR, on_ready2, nothing)
        @test !(res isa Reseau.ErrorResult)
        @test _wait_ready(ready_ch2)
        ready_token2, ready_code2 = take!(ready_ch2)
        @test ready_token2 === token2
        @test ready_code2 == Reseau.AWS_OP_SUCCESS

        res = Sockets.retry_token_schedule_retry(
            token1,
            Sockets.RetryErrorType.SERVER_ERROR,
            on_ready,
            nothing,
        )
        @test res isa Reseau.ErrorResult
        res isa Reseau.ErrorResult && @test res.code == EventLoops.ERROR_IO_RETRY_PERMISSION_DENIED

        res = Sockets.retry_token_schedule_retry(
            token2,
            Sockets.RetryErrorType.SERVER_ERROR,
            on_ready2,
            nothing,
        )
        @test res isa Reseau.ErrorResult
        res isa Reseau.ErrorResult && @test res.code == EventLoops.ERROR_IO_RETRY_PERMISSION_DENIED

        Sockets.retry_token_release!(token1)
        Sockets.retry_token_release!(token2)

        acquired_ch3 = Channel{Tuple{Any, Int}}(1)
        on_acquired3 = (token, code, ud) -> put!(acquired_ch3, (token, code))
        _ = Sockets.retry_strategy_acquire_token!(strategy, nothing, on_acquired3, nothing, 0)
        @test _wait_ready(acquired_ch3)
        token3, code3 = take!(acquired_ch3)
        @test code3 == Reseau.AWS_OP_SUCCESS

        ready_ch3 = Channel{Tuple{Any, Int}}(1)
        on_ready3 = (token, code, ud) -> put!(ready_ch3, (token, code))
        res = Sockets.retry_token_schedule_retry(token3, Sockets.RetryErrorType.SERVER_ERROR, on_ready3, nothing)
        @test !(res isa Reseau.ErrorResult)
        @test _wait_ready(ready_ch3)
        ready_token3, ready_code3 = take!(ready_ch3)
        @test ready_token3 === token3
        @test ready_code3 == Reseau.AWS_OP_SUCCESS

        Sockets.retry_token_release!(token3)

        Sockets.retry_strategy_shutdown!(strategy)
        EventLoops.event_loop_group_release!(elg)
        Sockets.io_library_clean_up()
    end
end

@testset "standard retry failure recovers capacity" begin
    if Base.Threads.nthreads(:interactive) <= 1
        @test true
    else
        Sockets.io_library_init()

        elg = EventLoops.EventLoopGroup(EventLoops.EventLoopGroupOptions(; loop_count = 1))
        @test !(elg isa Reseau.ErrorResult)
        elg isa Reseau.ErrorResult && return

        backoff_config = Sockets.ExponentialBackoffConfig(;
            backoff_scale_factor_ms = 1,
            max_backoff_secs = 1,
            max_retries = 3,
            jitter_mode = :none,
        )
        config = Sockets.StandardRetryConfig(;
            initial_bucket_capacity = 15,
            backoff_config = backoff_config,
        )
        strategy = Sockets.StandardRetryStrategy(elg, config)
        @test !(strategy isa Reseau.ErrorResult)
        if strategy isa Reseau.ErrorResult
            EventLoops.event_loop_group_release!(elg)
            Sockets.io_library_clean_up()
            return
        end

        partition = "us-west-2:elastic-something-something-manager-manager"

        acquired_ch = Channel{Tuple{Any, Int}}(1)
        on_acquired = (token, code, ud) -> put!(acquired_ch, (token, code))
        _ = Sockets.retry_strategy_acquire_token!(strategy, partition, on_acquired, nothing, 0)
        @test _wait_ready(acquired_ch)
        token, code = take!(acquired_ch)
        @test code == Reseau.AWS_OP_SUCCESS

        ready_ch = Channel{Tuple{Any, Int}}(1)
        on_ready = (token, code, ud) -> put!(ready_ch, (token, code))
        res = Sockets.retry_token_schedule_retry(token, Sockets.RetryErrorType.TRANSIENT, on_ready, nothing)
        @test !(res isa Reseau.ErrorResult)
        @test _wait_ready(ready_ch)
        _ = take!(ready_ch)

        ready_ch2 = Channel{Tuple{Any, Int}}(1)
        on_ready2 = (token, code, ud) -> put!(ready_ch2, (token, code))
        res = Sockets.retry_token_schedule_retry(token, Sockets.RetryErrorType.SERVER_ERROR, on_ready2, nothing)
        @test !(res isa Reseau.ErrorResult)
        @test _wait_ready(ready_ch2)
        _ = take!(ready_ch2)

        res = Sockets.retry_token_schedule_retry(token, Sockets.RetryErrorType.SERVER_ERROR, on_ready, nothing)
        @test res isa Reseau.ErrorResult
        res isa Reseau.ErrorResult && @test res.code == EventLoops.ERROR_IO_RETRY_PERMISSION_DENIED

        Sockets.retry_token_release!(token)

        for _ in 1:5
            acquired_ch = Channel{Tuple{Any, Int}}(1)
            on_acquired = (token, code, ud) -> put!(acquired_ch, (token, code))
            _ = Sockets.retry_strategy_acquire_token!(strategy, partition, on_acquired, nothing, 0)
            @test _wait_ready(acquired_ch)
            token, code = take!(acquired_ch)
            @test code == Reseau.AWS_OP_SUCCESS
            Sockets.retry_token_record_success(token)
            Sockets.retry_token_release!(token)
        end

        acquired_ch = Channel{Tuple{Any, Int}}(1)
        on_acquired = (token, code, ud) -> put!(acquired_ch, (token, code))
        _ = Sockets.retry_strategy_acquire_token!(strategy, partition, on_acquired, nothing, 0)
        @test _wait_ready(acquired_ch)
        token, code = take!(acquired_ch)
        @test code == Reseau.AWS_OP_SUCCESS

        ready_ch = Channel{Tuple{Any, Int}}(1)
        on_ready = (token, code, ud) -> put!(ready_ch, (token, code))
        res = Sockets.retry_token_schedule_retry(token, Sockets.RetryErrorType.SERVER_ERROR, on_ready, nothing)
        @test !(res isa Reseau.ErrorResult)
        @test _wait_ready(ready_ch)
        _ = take!(ready_ch)

        res = Sockets.retry_token_schedule_retry(token, Sockets.RetryErrorType.SERVER_ERROR, on_ready, nothing)
        @test res isa Reseau.ErrorResult
        res isa Reseau.ErrorResult && @test res.code == EventLoops.ERROR_IO_RETRY_PERMISSION_DENIED

        Sockets.retry_token_release!(token)

        Sockets.retry_strategy_shutdown!(strategy)
        EventLoops.event_loop_group_release!(elg)
        Sockets.io_library_clean_up()
    end
end
