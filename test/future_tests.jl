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

    # Not yet set
    @test (@atomic future.set) == Int8(0)

    # Complete with value
    notify(future, 42)
    @test (@atomic future.set) == Int8(1)
    @test wait(future) == 42

    # Completing again is a no-op (not an error)
    notify(future, 7)
    @test wait(future) == 42
end

@testset "Future failure" begin
    failed = EventLoops.Future{Int}()
    notify(failed, Reseau.ReseauError(EventLoops.ERROR_IO_SOCKET_TIMEOUT))
    @test_throws Reseau.ReseauError wait(failed)

    cancelled = EventLoops.Future{Int}()
    EventLoops.cancel!(cancelled)
    @test_throws Reseau.ReseauError wait(cancelled)
end

@testset "Future wait with timeout" begin
    done = EventLoops.Future{Int}()
    notify(done, 5)
    @test wait(done) == 5
end

@testset "Future{Nothing}" begin
    f = EventLoops.Future{Nothing}()
    notify(f)
    @test wait(f) === nothing

    f2 = EventLoops.Future()
    notify(f2)
    @test wait(f2) === nothing
end

@testset "Future pointer round-trip" begin
    f = EventLoops.Future{Int}()
    ptr = Base.pointer(f)
    f2 = EventLoops.Future{Int}(ptr)
    @test f === f2
end

@testset "Future cross-thread notify" begin
    f = EventLoops.Future{Int}()
    Threads.@spawn begin
        sleep(0.01)
        notify(f, 99)
    end
    @test wait(f) == 99
end
