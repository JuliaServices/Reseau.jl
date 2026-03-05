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

function _run_trim_compile(project_path::String, script_path::String, output_name::String; timeout_s::Float64 = 120.0, bundle_dir::Union{Nothing, String} = nothing)
    julia_exe = joinpath(Sys.BINDIR, Base.julia_exename())
    cmd = if bundle_dir === nothing
        `$julia_exe --startup-file=no --history-file=no --code-coverage=none --project=$project_path -e "using JuliaC; JuliaC.main(ARGS)" -- --output-exe $output_name --project=$project_path --experimental --trim=safe $script_path`
    else
        `$julia_exe --startup-file=no --history-file=no --code-coverage=none --project=$project_path -e "using JuliaC; JuliaC.main(ARGS)" -- --output-exe $output_name --bundle $bundle_dir --project=$project_path --experimental --trim=safe $script_path`
    end
    return _run_command_with_timeout(cmd; timeout_s = timeout_s, log_label = "compile")
end

function _run_trim_executable(run_cmd; timeout_s::Float64 = 30.0)
    return _run_command_with_timeout(run_cmd; timeout_s = timeout_s, log_label = "run")
end

function _run_command_with_timeout(cmd::Cmd; timeout_s::Float64, log_label::String)
    output_path = tempname()
    out = open(output_path, "w")
    exit_code = -1
    timed_out = false
    try
        proc = run(pipeline(ignorestatus(cmd), stdout = out, stderr = out); wait = false)
        timed_out = _wait_process_with_timeout!(proc; timeout_s = timeout_s, log_label = log_label)
        exit_code = something(proc.exitcode, -1)
    finally
        close(out)
    end
    output = try
        read(output_path, String)
    catch
        ""
    finally
        rm(output_path; force = true)
    end
    return exit_code, output, timed_out
end

function _wait_process_with_timeout!(proc::Base.Process; timeout_s::Float64, log_label::String)
    started_at = time()
    next_log_at = started_at + 10.0
    timed_out = false
    while Base.process_running(proc)
        now = time()
        if now - started_at >= timeout_s
            timed_out = true
            try
                kill(proc)
            catch
            end
            break
        end
        if now >= next_log_at
            elapsed = round(now - started_at; digits = 1)
            println("[trim] $(log_label) WAIT $(elapsed)s")
            flush(stdout)
            next_log_at = now + 10.0
        end
        sleep(0.1)
    end
    try
        wait(proc)
    catch
    end
    return timed_out
end

function _trim_timeout_error(kind::String, script_file::String, output::String = "")
    msg = "trim $kind timed out for $(script_file)"
    if !isempty(output)
        msg = string(msg, "\n---- captured output ----\n", output, "\n---- end captured output ----")
    end
    throw(ArgumentError(msg))
end

function _maybe_print_output(header::String, output::String)
    isempty(output) && return nothing
    println(header)
    println(output)
    println("---- end output ----")
    return nothing
end

function _trim_executable_timeout_s()::Float64
    default = Sys.iswindows() ? "120.0" : "30.0"
    return parse(Float64, get(ENV, "RESEAU_TRIM_EXE_TIMEOUT_S", default))
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
    default = Sys.iswindows() ? "1" : "0"
    return get(ENV, "RESEAU_TRIM_BUNDLE", default) == "1"
end

function _run_trim_case(project_path::String, script_file::String, output_name::String)
    script_path = joinpath(@__DIR__, script_file)
    @test isfile(script_path)
    println("[trim] compile START $(script_file)")
    start_t = time()
    mktempdir() do tmpdir
        cd(tmpdir) do
            bundle_dir = _trim_use_bundle() ? joinpath(tmpdir, "bundle") : nothing
            exit_code, output, timed_out = _run_trim_compile(project_path, script_path, output_name; bundle_dir = bundle_dir)
            timed_out && _trim_timeout_error("compile", script_file, output)
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
            output_path = Sys.iswindows() ? "$(output_name).exe" : output_name
            if trim_errors == 0
                run_path = bundle_dir === nothing ? output_path : joinpath(bundle_dir, "bin", output_path)
                @test exit_code == 0
                @test isfile(run_path)
                run_cmd = Sys.iswindows() ? `$(abspath(run_path))` : `$(abspath(run_path))`
                run_timeout_s = _trim_executable_timeout_s()
                run_exit, run_output, run_timed_out = _run_trim_executable(run_cmd; timeout_s = run_timeout_s)
                run_timed_out && _trim_timeout_error("executable run", script_file, run_output)
                if run_exit != 0
                    _maybe_print_output("---- trim executable output ($(script_file)) ----", run_output)
                end
                @test run_exit == 0
            else
                @test exit_code != 0
            end
        end
    end
    println("[trim] compile DONE $(script_file) ($(round(time() - start_t; digits = 2))s)")
    return nothing
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
    trim_workloads = _trim_selected_workloads(trim_workloads)
    for (script_file, output_name) in trim_workloads
        _run_trim_case(project_path, script_file, output_name)
    end
end
