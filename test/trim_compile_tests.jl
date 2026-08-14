using Test

const _TRIM_SAFE_ERROR_BUDGET = 0

const _TRIM_SUPPORTED = VERSION >= v"1.12.0-rc1"
const _TRIM_PRE_RELEASE = !isempty(VERSION.prerelease)
const _JULIAC_ENTRYPOINT_EXPR = "using JuliaC; if isdefined(JuliaC, :main); JuliaC.main(ARGS); else JuliaC._main_cli(ARGS); end"

function _run_trim_compile(project_path::String, script_path::String, output_name::String; bundle_dir::Union{Nothing, String} = nothing)
    julia_exe = joinpath(Sys.BINDIR, Base.julia_exename())
    cmd = if bundle_dir === nothing
        `$julia_exe --startup-file=no --history-file=no --code-coverage=none --project=$project_path -e $(_JULIAC_ENTRYPOINT_EXPR) -- --output-exe $output_name --project=$project_path --experimental --trim=safe $script_path`
    else
        `$julia_exe --startup-file=no --history-file=no --code-coverage=none --project=$project_path -e $(_JULIAC_ENTRYPOINT_EXPR) -- --output-exe $output_name --bundle $bundle_dir --project=$project_path --experimental --trim=safe $script_path`
    end
    return _run_trim_command(cmd)
end

function _run_trim_executable(run_cmd)
    return _run_trim_command(run_cmd)
end

# Runs to completion: a hung juliac or executable surfaces as a suite hang
# and the CI job timeout is the final guard.
function _run_trim_command(cmd::Cmd)
    output_path = tempname()
    out = open(output_path, "w")
    exit_code = -1
    try
        proc = run(pipeline(ignorestatus(cmd), stdout = out, stderr = out))
        exit_code = something(proc.exitcode, -1)
    finally
        close(out)
    end
    output = try
        read(output_path, String)
    finally
        rm(output_path; force = true)
    end
    return exit_code, output
end

function _maybe_print_output(header::String, output::String)
    isempty(output) && return nothing
    println(header)
    println(output)
    println("---- end output ----")
    return nothing
end

function _trim_selected_workloads(workloads::Vector{Tuple{String, String}})::Vector{Tuple{String, String}}
    only = strip(get(ENV, "RESEAU_TRIM_ONLY", ""))
    isempty(only) && return workloads
    selected = Tuple{String, String}[]
    for workload in workloads
        workload[1] == only && push!(selected, workload)
    end
    isempty(selected) && throw(ArgumentError("unknown RESEAU_TRIM_ONLY workload: $(only)"))
    return selected
end

function _trim_use_bundle()::Bool
    default = "1"
    return get(ENV, "RESEAU_TRIM_BUNDLE", default) == "1"
end

function _trim_compiler_available()::Bool
    julia_cc = strip(get(ENV, "JULIA_CC", ""))
    !isempty(julia_cc) && return true
    @static if Sys.iswindows()
        return true
    else
        return Sys.which("gcc") !== nothing || Sys.which("clang") !== nothing
    end
end

function _trim_output_path(dir::String, output_name::String)::String
    path = joinpath(dir, output_name)
    isfile(path) && return path
    exe_path = joinpath(dir, "$(output_name).exe")
    isfile(exe_path) && return exe_path
    return path
end

function _run_trim_case(project_path::String, script_file::String, output_name::String)
    script_path = joinpath(@__DIR__, script_file)
    @test isfile(script_path)
    println("[trim] compile START $(script_file)")
    mktempdir() do tmpdir
        cd(tmpdir) do
            bundle_dir = _trim_use_bundle() ? joinpath(tmpdir, "bundle") : nothing
            exit_code, output = _run_trim_compile(project_path, script_path, output_name; bundle_dir = bundle_dir)
            totals = _parse_trim_verify_totals(output)
            trim_errors, trim_warnings = if totals === nothing
                exit_code == 0 ? (0, 0) : error("failed to parse trim verifier summary:\n$output")
            else
                totals
            end
            if get(ENV, "RESEAU_TRIM_PRINT_OUTPUT", "0") == "1" || trim_errors > 0
                _maybe_print_output("---- trim compile output ($(script_file)) ----", output)
            end
            @test trim_errors <= _TRIM_SAFE_ERROR_BUDGET
            @test trim_warnings >= 0
            if trim_errors == 0
                run_dir = bundle_dir === nothing ? pwd() : joinpath(bundle_dir, "bin")
                run_path = _trim_output_path(run_dir, output_name)
                @test exit_code == 0
                @test isfile(run_path)
                helper_julia = joinpath(Sys.BINDIR, Base.julia_exename())
                run_cmd = setenv(`$(abspath(run_path))`, "RESEAU_TRIM_HELPER_JULIA" => helper_julia)
                run_exit, run_output = _run_trim_executable(run_cmd)
                if run_exit != 0
                    _maybe_print_output("---- trim executable output ($(script_file)) ----", run_output)
                end
                @test run_exit == 0
            else
                @test exit_code != 0
            end
        end
    end
    println("[trim] compile DONE $(script_file)")
    return nothing
end

function _parse_trim_verify_totals(output::String)
    m = match(r"Trim verify finished with\s+(\d+)\s+errors,\s+(\d+)\s+warnings\.", output)
    m === nothing && return nothing
    return parse(Int, m.captures[1]), parse(Int, m.captures[2])
end

@testset "Trim compile" begin
    if !Base.get_bool_env("RESEAU_RUN_TRIM_TESTS", true)
        println("[trim] skip RESEAU_RUN_TRIM_TESTS=false: user requested to skip trim compilation tests")
        @test true
    elseif !_TRIM_SUPPORTED
        println("[trim] skip Julia < 1.12: JuliaC trim compilation is unavailable")
        @test true
    elseif _TRIM_PRE_RELEASE
        println("[trim] skip prerelease Julia: trim verifier behavior is not stable yet")
        @test true
    elseif !_trim_compiler_available()
        @warn "Reseau trim compile tests are being skipped." reason = "no C compiler found" action = "install gcc/clang or set JULIA_CC to run trim compilation tests"
        @test true
    else
        project_path = normpath(joinpath(@__DIR__, ".."))
        trim_workloads = [
            ("iopoll_runtime_trim_safe.jl", "iopoll_runtime_trim_safe"),
            ("socket_ops_trim_safe.jl", "socket_ops_trim_safe"),
            ("tcp_trim_safe.jl", "tcp_trim_safe"),
            ("udp_trim_safe.jl", "udp_trim_safe"),
            ("socks_trim_safe.jl", "socks_trim_safe"),
            ("host_resolvers_trim_safe.jl", "host_resolvers_trim_safe"),
            ("host_resolvers_system_trim_safe.jl", "host_resolvers_system_trim_safe"),
            ("tls_trim_safe.jl", "tls_trim_safe"),
        ]
        trim_workloads = _trim_selected_workloads(trim_workloads)
        for (script_file, output_name) in trim_workloads
            _run_trim_case(project_path, script_file, output_name)
        end
    end
end
