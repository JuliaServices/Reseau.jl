using Test

const _TRIM_SAFE_ERROR_BUDGET = @static if Sys.isapple()
    0
elseif Sys.iswindows()
    0
elseif Sys.islinux()
    0
else
    typemax(Int)
end

function _run_trim_compile(project_path::String, script_path::String, output_name::String)
    julia_exe = joinpath(Sys.BINDIR, Base.julia_exename())
    cmd = `$julia_exe --startup-file=no --history-file=no --code-coverage=none --project=$project_path -e "using JuliaC; JuliaC.main(ARGS)" -- --output-exe $output_name --project=$project_path --experimental --trim=safe $script_path`
    io = IOBuffer()
    proc = run(pipeline(ignorestatus(cmd), stdout = io, stderr = io))
    return proc.exitcode, String(take!(io))
end

function _parse_trim_verify_totals(output::String)
    m = match(r"Trim verify finished with\s+(\d+)\s+errors,\s+(\d+)\s+warnings\.", output)
    m === nothing && return nothing
    return parse(Int, m.captures[1]), parse(Int, m.captures[2])
end

@testset "Trim compile" begin
    project_path = normpath(joinpath(@__DIR__, ".."))
    trim_workloads = [
        ("eventloops_trim_safe.jl", "eventloops_trim_safe"),
        ("socket_ops_trim_safe.jl", "socket_ops_trim_safe"),
        ("tcp_trim_safe.jl", "tcp_trim_safe"),
        ("host_resolvers_trim_safe.jl", "host_resolvers_trim_safe"),
        ("tls_trim_safe.jl", "tls_trim_safe"),
        ("http_trim_safe.jl", "http_trim_safe"),
    ]
    for (script_file, output_name) in trim_workloads
        script_path = joinpath(@__DIR__, script_file)
        @test isfile(script_path)
        mktempdir() do tmpdir
            cd(tmpdir) do
                exit_code, output = _run_trim_compile(project_path, script_path, output_name)
                totals = _parse_trim_verify_totals(output)
                trim_errors, trim_warnings = if totals === nothing
                    exit_code == 0 ? (0, 0) : error("failed to parse trim verifier summary:\n$output")
                else
                    totals
                end
                if get(ENV, "RESEAU_TRIM_PRINT_OUTPUT", "0") == "1" || trim_errors > 0
                    println("---- trim compile output ($(script_file)) ----")
                    println(output)
                    println("---- end trim compile output ----")
                end
                @test trim_errors <= _TRIM_SAFE_ERROR_BUDGET
                @test trim_warnings >= 0
                output_path = Sys.iswindows() ? "$(output_name).exe" : output_name
                if trim_errors == 0
                    @test exit_code == 0
                    @test isfile(output_path)
                    run_io = IOBuffer()
                    run_cmd = Sys.iswindows() ? `$output_path` : `./$output_path`
                    run_proc = run(pipeline(ignorestatus(run_cmd), stdout = run_io, stderr = run_io))
                    run_output = String(take!(run_io))
                    if run_proc.exitcode != 0
                        println("---- trim executable output ($(script_file)) ----")
                        println(run_output)
                        println("---- end trim executable output ----")
                    end
                    @test run_proc.exitcode == 0
                else
                    @test exit_code != 0
                end
            end
        end
    end
end
