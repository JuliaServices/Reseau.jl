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
    future = EventLoops.Future{Int}()

    @test !EventLoops.future_is_done(future)
    @test !EventLoops.future_is_success(future)
    @test !EventLoops.future_is_failed(future)
    @test !EventLoops.future_is_cancelled(future)

    on_done = Ref(false)
    EventLoops.future_on_complete!(future, (f, ud) -> (ud[] = true), on_done)

    @test EventLoops.future_complete!(future, 42) === nothing
    @test EventLoops.future_is_done(future)
    @test EventLoops.future_is_success(future)
    @test EventLoops.future_get_result(future) == 42
    @test on_done[]

    immediate = Ref(false)
    EventLoops.future_on_complete!(future, (f, ud) -> (ud[] = true), immediate)
    @test immediate[]

    err = EventLoops.future_complete!(future, 7)
    @test err isa Reseau.ErrorResult
    @test err.code == EventLoops.ERROR_IO_SOCKET_ILLEGAL_OPERATION_FOR_STATE
end

@testset "Future fail/cancel" begin
    failed = EventLoops.Future{Int}()
    @test EventLoops.future_fail!(failed, EventLoops.ERROR_IO_SOCKET_TIMEOUT) === nothing
    @test EventLoops.future_is_failed(failed)
    @test EventLoops.future_get_error(failed) == EventLoops.ERROR_IO_SOCKET_TIMEOUT

    cancelled = EventLoops.Future{Int}()
    @test EventLoops.future_cancel!(cancelled) === nothing
    @test EventLoops.future_is_cancelled(cancelled)
    @test EventLoops.future_get_error(cancelled) == EventLoops.ERROR_IO_OPERATION_CANCELLED

    noop = EventLoops.future_cancel!(cancelled)
    @test noop === nothing
end

@testset "Future wait/any/all" begin
    pending = EventLoops.Future{Int}()
    @test !EventLoops.future_wait(pending; timeout_ms = 1)

    done = EventLoops.Future{Int}()
    @test EventLoops.future_complete!(done, 5) === nothing
    @test EventLoops.future_wait(done; timeout_ms = 1)

    f1 = EventLoops.Future{Int}()
    f2 = EventLoops.Future{Int}()
    EventLoops.future_complete!(f2, 9)
    @test EventLoops.future_any([f1, f2]; timeout_ms = 10) == 2

    f3 = EventLoops.Future{Int}()
    EventLoops.future_complete!(f1, 1)
    EventLoops.future_complete!(f3, 3)
    @test EventLoops.future_all([f1, f2, f3])
end

@testset "Future chaining" begin
    base = EventLoops.Future{Int}()
    chained = EventLoops.future_then(base, x -> x + 1)
    EventLoops.future_complete!(base, 41)
    @test EventLoops.future_is_success(chained)
    @test EventLoops.future_get_result(chained) == 42

    base_fail = EventLoops.Future{Int}()
    chained_fail = EventLoops.future_then(base_fail, x -> x + 1)
    EventLoops.future_fail!(base_fail, EventLoops.ERROR_IO_SOCKET_TIMEOUT)
    @test EventLoops.future_is_failed(chained_fail)
    @test EventLoops.future_get_error(chained_fail) == EventLoops.ERROR_IO_SOCKET_TIMEOUT

    base_throw = EventLoops.Future{Int}()
    chained_throw = EventLoops.future_then(base_throw, x -> error("boom"))
    EventLoops.future_complete!(base_throw, 1)
    @test EventLoops.future_is_failed(chained_throw)
    @test EventLoops.future_get_error(chained_throw) == Reseau.ERROR_UNKNOWN
end

@testset "Promise" begin
    promise = EventLoops.Promise{Int}()
    future = EventLoops.promise_get_future(promise)
    @test EventLoops.promise_complete!(promise, 99) === nothing
    @test EventLoops.future_is_success(future)
    @test EventLoops.future_get_result(future) == 99

    p_fail = EventLoops.Promise{Int}()
    f_fail = EventLoops.promise_get_future(p_fail)
    @test EventLoops.promise_fail!(p_fail, EventLoops.ERROR_IO_SOCKET_TIMEOUT) === nothing
    @test EventLoops.future_is_failed(f_fail)
    @test EventLoops.future_get_error(f_fail) == EventLoops.ERROR_IO_SOCKET_TIMEOUT
end

@testset "Future callback registration" begin
    pending = EventLoops.Future{Bool}()
    called = Ref(false)
    @test EventLoops.future_on_complete_if_not_done!(pending, (f, ud) -> (ud[] = true), called)
    @test_throws ErrorException EventLoops.future_on_complete!(pending, (f, ud) -> nothing, nothing)
    @test_throws ErrorException EventLoops.future_on_complete_if_not_done!(pending, (f, ud) -> nothing, nothing)
    EventLoops.future_complete!(pending, true)
    @test called[]

    done = EventLoops.Future{Bool}()
    EventLoops.future_complete!(done, true)
    called2 = Ref(false)
    @test !EventLoops.future_on_complete_if_not_done!(done, (f, ud) -> (ud[] = true), called2)
    @test !called2[]
end

@testset "Future event loop callback" begin
    elg = EventLoops.EventLoopGroup(EventLoops.EventLoopGroupOptions(; loop_count = 1))
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    future = EventLoops.Future{Int}()
    called = Ref(false)
    EventLoops.future_on_event_loop!(future, event_loop, (f, ud) -> (ud[] = true), called)
    EventLoops.future_complete!(future, 1)
    @test _wait_for_pred(() -> called[])

    done = EventLoops.Future{Int}()
    EventLoops.future_complete!(done, 2)
    called2 = Ref(false)
    EventLoops.future_on_event_loop!(done, event_loop, (f, ud) -> (ud[] = true), called2)
    @test _wait_for_pred(() -> called2[])

    EventLoops.event_loop_group_destroy!(elg)
end

@testset "Future channel callback" begin
    elg = EventLoops.EventLoopGroup(EventLoops.EventLoopGroupOptions(; loop_count = 1))
    event_loop = EventLoops.event_loop_group_get_next_loop(elg)
    channel = Sockets.Channel(event_loop, nothing)

    future = EventLoops.Future{Int}()
    called = Ref(false)
    EventLoops.future_on_channel!(future, channel, (f, ud) -> (ud[] = true), called)
    EventLoops.future_complete!(future, 1)
    @test _wait_for_pred(() -> called[])

    done = EventLoops.Future{Int}()
    EventLoops.future_complete!(done, 2)
    called2 = Ref(false)
    EventLoops.future_on_channel!(done, channel, (f, ud) -> (ud[] = true), called2)
    @test _wait_for_pred(() -> called2[])

    EventLoops.event_loop_group_destroy!(elg)
end

@testset "Future wait ns" begin
    pending = EventLoops.Future{Bool}()
    @test !EventLoops.future_wait_ns(pending; timeout_ns = 1_000_000)

    done = EventLoops.Future{Bool}()
    EventLoops.future_complete!(done, true)
    @test EventLoops.future_wait_ns(done; timeout_ns = 1_000_000)
end

@testset "Future move semantics" begin
    future = EventLoops.Future{Int}()
    EventLoops.future_complete!(future, 10)
    @test EventLoops.future_get_result_by_move!(future) == 10
    @test_throws ErrorException EventLoops.future_get_result(future)
    @test_throws ErrorException EventLoops.future_get_result_by_move!(future)
end
