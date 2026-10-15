using Test
using Reseau

@testset "Precompile workloads" begin
    # Precompilation only warns when a workload fails, so run them strictly here.
    @test Reseau._pc_run_selected_workloads!() === nothing
end
