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

function _pc_strict_using_reseau_exit_code()::Tuple{Int, String}
    julia_exe = joinpath(Sys.BINDIR, Base.julia_exename())
    project_path = normpath(joinpath(@__DIR__, ".."))
    return mktempdir() do depot_path
        env = Dict(
            "JULIA_DEPOT_PATH" => string(depot_path, Base.Filesystem.path_separator, join(Base.DEPOT_PATH, Base.Filesystem.path_separator)),
            "JULIA_PKG_PRECOMPILE_AUTO" => "0",
            "RESEAU_PRECOMPILE_STRICT" => "1",
        )
        cmd = setenv(
            `$julia_exe --project=$project_path --startup-file=no --history-file=no -e 'using Pkg; Pkg.instantiate(); using Reseau'`,
            env,
        )
        return _pc_capture_command(cmd)
    end
end

@testset "Precompile workload" begin
    @testset "direct strict runner succeeds" begin
        @test Reseau._run_precompile_workloads_for_tests() === nothing
    end

    @testset "fresh package precompile succeeds in strict mode" begin
        exit_code, output = _pc_strict_using_reseau_exit_code()
        exit_code == 0 || println(output)
        @test exit_code == 0
        @test !occursin("Ignoring an error that occurred during the precompilation workload", output)
    end
end
