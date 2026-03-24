using Test
using Reseau

function _pc_capture_command(cmd::Cmd)
    output_path = tempname()
    out = open(output_path, "w")
    exit_code = -1
    output = ""
    try
        proc = run(pipeline(ignorestatus(cmd), stdout = out, stderr = out); wait = true)
        exit_code = something(proc.exitcode, -1)
    finally
        close(out)
        output = try
            read(output_path, String)
        catch
            ""
        finally
            rm(output_path; force = true)
        end
    end
    return exit_code, output
end

function _pc_using_reseau_exit_code()::Tuple{Int, String}
    julia_exe = joinpath(Sys.BINDIR, Base.julia_exename())
    project_path = normpath(joinpath(@__DIR__, ".."))
    return mktempdir() do depot_path
        depots = [depot_path; Base.DEPOT_PATH]
        depot_expr = repr(depots)
        code = string(
            "empty!(DEPOT_PATH); append!(DEPOT_PATH, ",
            depot_expr,
            "); using Pkg; Pkg.instantiate(); using Reseau",
        )
        env = Dict("JULIA_PKG_PRECOMPILE_AUTO" => "0")
        cmd = setenv(
            `$julia_exe --project=$project_path --startup-file=no --history-file=no -e $code`,
            env,
        )
        return _pc_capture_command(cmd)
    end
end

@testset "Precompile workload" begin
    @testset "direct strict runner succeeds" begin
        @test Reseau._run_precompile_workloads_for_tests() === nothing
    end

    @testset "fresh package precompile succeeds" begin
        exit_code, output = _pc_using_reseau_exit_code()
        exit_code == 0 || println(output)
        @test exit_code == 0
    end
end
