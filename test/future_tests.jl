using Test
using Reseau

function _wait_for_pred(pred::Function; timeout_s::Float64 = 5.0)
    start = Base.time_ns()
    timeout_ns = Int(timeout_s * 1_000_000_000)
    while (Base.time_ns() - start) < timeout_ns
        if pred()
            return true
        end
        sleep(0.01)
    end
    return false
end

@testset "Future basics" begin
    future = Reseau.Future{Int}()

    @test !Reseau.future_is_done(future)
    @test !Reseau.future_is_success(future)
    @test !Reseau.future_is_failed(future)
    @test !Reseau.future_is_cancelled(future)

    on_done = Ref(false)
    Reseau.future_on_complete!(future, (f, ud) -> (ud[] = true), on_done)

    @test Reseau.future_complete!(future, 42) === nothing
    @test Reseau.future_is_done(future)
    @test Reseau.future_is_success(future)
    @test Reseau.future_get_result(future) == 42
    @test on_done[]

    immediate = Ref(false)
    Reseau.future_on_complete!(future, (f, ud) -> (ud[] = true), immediate)
    @test immediate[]

    err = Reseau.future_complete!(future, 7)
    @test err isa Reseau.ErrorResult
    @test err.code == Reseau.ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE
end

@testset "Future fail/cancel" begin
    failed = Reseau.Future{Int}()
    @test Reseau.future_fail!(failed, Reseau.ERROR_IO_SOCKET_TIMEOUT) === nothing
    @test Reseau.future_is_failed(failed)
    @test Reseau.future_get_error(failed) == Reseau.ERROR_IO_SOCKET_TIMEOUT

    cancelled = Reseau.Future{Int}()
    @test Reseau.future_cancel!(cancelled) === nothing
    @test Reseau.future_is_cancelled(cancelled)
    @test Reseau.future_get_error(cancelled) == Reseau.ERROR_IO_OPERATION_CANCELLED

    noop = Reseau.future_cancel!(cancelled)
    @test noop === nothing
end

@testset "Future wait/any/all" begin
    pending = Reseau.Future{Int}()
    @test !Reseau.future_wait(pending; timeout_ms = 1)

    done = Reseau.Future{Int}()
    @test Reseau.future_complete!(done, 5) === nothing
    @test Reseau.future_wait(done; timeout_ms = 1)

    f1 = Reseau.Future{Int}()
    f2 = Reseau.Future{Int}()
    Reseau.future_complete!(f2, 9)
    @test Reseau.future_any([f1, f2]; timeout_ms = 10) == 2

    f3 = Reseau.Future{Int}()
    Reseau.future_complete!(f1, 1)
    Reseau.future_complete!(f3, 3)
    @test Reseau.future_all([f1, f2, f3])
end

@testset "Future chaining" begin
    base = Reseau.Future{Int}()
    chained = Reseau.future_then(base, x -> x + 1)
    Reseau.future_complete!(base, 41)
    @test Reseau.future_is_success(chained)
    @test Reseau.future_get_result(chained) == 42

    base_fail = Reseau.Future{Int}()
    chained_fail = Reseau.future_then(base_fail, x -> x + 1)
    Reseau.future_fail!(base_fail, Reseau.ERROR_IO_SOCKET_TIMEOUT)
    @test Reseau.future_is_failed(chained_fail)
    @test Reseau.future_get_error(chained_fail) == Reseau.ERROR_IO_SOCKET_TIMEOUT

    base_throw = Reseau.Future{Int}()
    chained_throw = Reseau.future_then(base_throw, x -> error("boom"))
    Reseau.future_complete!(base_throw, 1)
    @test Reseau.future_is_failed(chained_throw)
    @test Reseau.future_get_error(chained_throw) == Reseau.ERROR_UNKNOWN
end

@testset "Promise" begin
    promise = Reseau.Promise{Int}()
    future = Reseau.promise_get_future(promise)
    @test Reseau.promise_complete!(promise, 99) === nothing
    @test Reseau.future_is_success(future)
    @test Reseau.future_get_result(future) == 99

    p_fail = Reseau.Promise{Int}()
    f_fail = Reseau.promise_get_future(p_fail)
    @test Reseau.promise_fail!(p_fail, Reseau.ERROR_IO_SOCKET_TIMEOUT) === nothing
    @test Reseau.future_is_failed(f_fail)
    @test Reseau.future_get_error(f_fail) == Reseau.ERROR_IO_SOCKET_TIMEOUT
end

@testset "Future callback registration" begin
    pending = Reseau.Future{Bool}()
    called = Ref(false)
    @test Reseau.future_on_complete_if_not_done!(pending, (f, ud) -> (ud[] = true), called)
    @test_throws ErrorException Reseau.future_on_complete!(pending, (f, ud) -> nothing, nothing)
    @test_throws ErrorException Reseau.future_on_complete_if_not_done!(pending, (f, ud) -> nothing, nothing)
    Reseau.future_complete!(pending, true)
    @test called[]

    done = Reseau.Future{Bool}()
    Reseau.future_complete!(done, true)
    called2 = Ref(false)
    @test !Reseau.future_on_complete_if_not_done!(done, (f, ud) -> (ud[] = true), called2)
    @test !called2[]
end

@testset "Future event loop callback" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    future = Reseau.Future{Int}()
    called = Ref(false)
    Reseau.future_on_event_loop!(future, event_loop, (f, ud) -> (ud[] = true), called)
    Reseau.future_complete!(future, 1)
    @test _wait_for_pred(() -> called[])

    done = Reseau.Future{Int}()
    Reseau.future_complete!(done, 2)
    called2 = Ref(false)
    Reseau.future_on_event_loop!(done, event_loop, (f, ud) -> (ud[] = true), called2)
    @test _wait_for_pred(() -> called2[])

    Reseau.event_loop_group_destroy!(elg)
end

@testset "Future channel callback" begin
    elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
    event_loop = Reseau.event_loop_group_get_next_loop(elg)
    channel = Reseau.Channel(event_loop, nothing)

    future = Reseau.Future{Int}()
    called = Ref(false)
    Reseau.future_on_channel!(future, channel, (f, ud) -> (ud[] = true), called)
    Reseau.future_complete!(future, 1)
    @test _wait_for_pred(() -> called[])

    done = Reseau.Future{Int}()
    Reseau.future_complete!(done, 2)
    called2 = Ref(false)
    Reseau.future_on_channel!(done, channel, (f, ud) -> (ud[] = true), called2)
    @test _wait_for_pred(() -> called2[])

    Reseau.event_loop_group_destroy!(elg)
end

@testset "Future wait ns" begin
    pending = Reseau.Future{Bool}()
    @test !Reseau.future_wait_ns(pending; timeout_ns = 1_000_000)

    done = Reseau.Future{Bool}()
    Reseau.future_complete!(done, true)
    @test Reseau.future_wait_ns(done; timeout_ns = 1_000_000)
end

@testset "Future move semantics" begin
    future = Reseau.Future{Int}()
    Reseau.future_complete!(future, 10)
    @test Reseau.future_get_result_by_move!(future) == 10
    @test_throws ErrorException Reseau.future_get_result(future)
    @test_throws ErrorException Reseau.future_get_result_by_move!(future)
end
