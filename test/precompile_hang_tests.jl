using Test

# Regression coverage for the Windows precompile hang where a downstream
# `@compile_workload` that performs same-process loopback I/O lazily started the
# runtime poller thread, and that detached thread then blocked the precompile
# worker process from terminating. The worker never exited, so `Pkg.precompile()`
# hung forever (no per-request timeout could break it, because the poller thread
# that services both completions and deadlines was the thing that was stranded).
#
# The fix makes Reseau register an `atexit` hook during output generation that
# stops the poller thread, so any downstream workload tears the thread down
# automatically. This test drives a real `Pkg.precompile()` of a tiny package
# whose workload opens a loopback connection, and asserts it finishes instead of
# hanging.

function _precompile_hang_kill_tree!(proc::Base.Process)
    @static if Sys.iswindows()
        try
            pid = getpid(proc)
            pid > 0 && run(pipeline(ignorestatus(`taskkill /T /F /PID $pid`); stdout = devnull, stderr = devnull))
        catch
        end
    end
    try
        kill(proc)
    catch
    end
    return nothing
end

function _precompile_hang_run(cmd::Cmd; timeout_s::Float64)
    output_path = tempname()
    out = open(output_path, "w")
    exit_code = -1
    timed_out = false
    try
        proc = run(pipeline(ignorestatus(cmd); stdout = out, stderr = out); wait = false)
        started_at = time()
        while Base.process_running(proc)
            if time() - started_at >= timeout_s
                timed_out = true
                _precompile_hang_kill_tree!(proc)
                break
            end
            sleep(0.1)
        end
        try
            wait(proc)
        catch
        end
        exit_code = something(proc.exitcode, -1)
    finally
        close(out)
    end
    output = try
        read(output_path, String)
    catch
        ""
    finally
        try
            rm(output_path; force = true)
        catch
        end
    end
    return exit_code, output, timed_out
end

function _write_loopback_precompile_pkg(dir::String)
    pkg_dir = joinpath(dir, "LoopbackPrecompilePkg")
    mkpath(joinpath(pkg_dir, "src"))
    write(joinpath(pkg_dir, "Project.toml"), """
    name = "LoopbackPrecompilePkg"
    uuid = "5f8b9c1a-2d3e-4f5a-9b8c-7d6e5f4a3b2c"
    version = "0.1.0"

    [deps]
    Reseau = "802f3686-a58f-41ce-bb0c-3c43c75bba36"
    PrecompileTools = "aea7be01-6a6a-4083-8856-8a6e6704d82a"
    """)
    # The workload deliberately does not call any Reseau shutdown API: the point
    # of the regression is that an arbitrary downstream workload performing
    # loopback I/O must still precompile cleanly.
    write(joinpath(pkg_dir, "src", "LoopbackPrecompilePkg.jl"), """
    module LoopbackPrecompilePkg

    using Reseau
    using PrecompileTools
    const TCP = Reseau.TCP
    const IP = Reseau.IOPoll

    function _loopback_roundtrip()
        listener = TCP.listen(TCP.loopback_addr(0); backlog = 16)
        laddr = TCP.addr(listener)
        port = Int((laddr::TCP.SocketAddrV4).port)
        client = TCP.connect(TCP.loopback_addr(port))
        server = TCP.accept(listener)
        # Schedule the write only after the read has begun, forcing the read to
        # complete through an asynchronous completion serviced by the poller
        # thread (the exact path that stranded during output generation).
        writer = @async begin
            IP.sleep(0.1)
            write(server, UInt8[0x41, 0x42, 0x43])
        end
        buf = Vector{UInt8}(undef, 3)
        read!(client, buf)
        wait(writer)
        close(client)
        close(server)
        close(listener)
        return buf
    end

    @compile_workload begin
        _loopback_roundtrip()
    end

    end
    """)
    return pkg_dir
end

@testset "Precompile loopback workload does not hang" begin
    if !Base.get_bool_env("RESEAU_RUN_PRECOMPILE_HANG_TEST", true)
        println("[precompile-hang] skip RESEAU_RUN_PRECOMPILE_HANG_TEST=false")
        @test true
    else
        reseau_path = normpath(joinpath(@__DIR__, ".."))
        timeout_s = parse(Float64, get(ENV, "RESEAU_PRECOMPILE_HANG_TIMEOUT_S", "180.0"))
        mktempdir() do tmpdir
            pkg_dir = _write_loopback_precompile_pkg(tmpdir)
            env_dir = joinpath(tmpdir, "env")
            mkpath(env_dir)
            driver = """
            import Pkg
            Pkg.activate(raw"$(escape_string(env_dir))")
            Pkg.develop(path = raw"$(escape_string(reseau_path))")
            Pkg.develop(path = raw"$(escape_string(pkg_dir))")
            Pkg.precompile("LoopbackPrecompilePkg")
            println("PRECOMPILE_DONE")
            """
            julia_exe = joinpath(Sys.BINDIR, Base.julia_exename())
            cmd = `$julia_exe --startup-file=no --history-file=no -e $driver`
            exit_code, output, timed_out = _precompile_hang_run(cmd; timeout_s = timeout_s)
            if timed_out || exit_code != 0 || !occursin("PRECOMPILE_DONE", output)
                println("---- precompile-hang output ----")
                println(output)
                println("---- end output ----")
            end
            @test !timed_out
            @test exit_code == 0
            @test occursin("PRECOMPILE_DONE", output)
        end
    end
end
