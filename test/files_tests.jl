using Test
using Reseau
using Reseau.Files
using Reseau.Files.Async
using Reseau.Files.Watching
using Reseau.Files.Locking

const _FILES_TEST_TIMEOUT_NS = 5_000_000_000

function _wait_task_done(t::Task; timeout_ns::Int = _FILES_TEST_TIMEOUT_NS)
    deadline = Base.time_ns() + timeout_ns
    while !istaskdone(t) && Base.time_ns() < deadline
        yield()
    end
    return istaskdone(t)
end

@testset "Files" begin
    @testset "Sync FileHandle IO" begin
        dir = Files.mktempdir()
        path = joinpath(dir, "hello.txt")
        io = Files.open(path, "w+")
        try
            @test isopen(io)
            @test write(io, "abcdef") == 6
            flush(io)
            @test position(io) == 6
            seekstart(io)
            @test read(io, 3) == Vector{UInt8}(codeunits("abc"))
            @test position(io) == 3
            truncate(io, 4)
            seekstart(io)
            @test read(io, 4) == Vector{UInt8}(codeunits("abcd"))
        finally
            close(io)
            Files.rm(dir; recursive = true, force = true)
        end
    end

    @testset "Stat + Predicates" begin
        dir = Files.mktempdir()
        path = joinpath(dir, "f.txt")
        Files.open(path, "w") do io
            write(io, "x")
        end
        @test Files.ispath(path)
        @test Files.isfile(path)
        @test !Files.isdir(path)
        @test Files.filesize(path) == 1
        @test Files.filemode(path) != 0
        @test Files.uperm(path) isa UInt8
        @test Files.gperm(path) isa UInt8
        @test Files.operm(path) isa UInt8
        Files.rm(dir; recursive = true, force = true)
    end

    @testset "Filesystem Ops" begin
        dir = Files.mktempdir()
        a = joinpath(dir, "a")
        b = joinpath(dir, "b")
        Files.mkpath(a)
        Files.open(joinpath(a, "x.txt"), "w") do io
            write(io, "x")
        end
        Files.cp(a, b; force = true, follow_symlinks = true)
        @test Files.isfile(joinpath(b, "x.txt"))
        Files.mv(joinpath(b, "x.txt"), joinpath(b, "y.txt"); force = true)
        @test Files.isfile(joinpath(b, "y.txt"))
        Files.rm(dir; recursive = true, force = true)
    end

    @testset "Locking + Atomic Write" begin
        dir = Files.mktempdir()
        path = joinpath(dir, "atomic.txt")
        atomic_write(path, "one"; replace = true)
        Files.open(path, "r") do io
            @test read(io, 3) == Vector{UInt8}(codeunits("one"))
        end
        atomic_write(path, "two"; replace = true)
        Files.open(path, "r") do io
            @test read(io, 3) == Vector{UInt8}(codeunits("two"))
        end
        @test_throws ArgumentError atomic_write(path, "no"; replace = false)

        lockpath = joinpath(dir, "pid.lock")
        lock = mkpidlock(lockpath; wait = true, poll_interval = 0.05)
        try
            @test trymkpidlock(lockpath; poll_interval = 0.05) == false
        finally
            close(lock)
        end
        lock2 = mkpidlock(lockpath; wait = true, poll_interval = 0.05)
        close(lock2)

        filelock_path = joinpath(dir, "file.lock")
        l = lock_file(filelock_path; blocking = true)
        try
            @test_throws Exception lock_file(filelock_path; blocking = false)
        finally
            unlock_file(l)
        end
        Files.rm(dir; recursive = true, force = true)
    end

    @testset "Async Ops" begin
        elg = Reseau.EventLoopGroup(Reseau.EventLoopGroupOptions(; loop_count = 1))
        event_loop = Reseau.event_loop_group_get_next_loop(elg)

        dir = Files.mktempdir()
        path = joinpath(dir, "async.txt")

        f_open = open_async(event_loop, path; write = true, create = true, truncate = true)
        @test Reseau.future_wait(f_open; timeout_ms = 2000)
        file = Reseau.future_get_result(f_open)

        t_on_loop = Ref(false)
        cb_ran = Ref(false)
        f_write1 = write_async(file, "abc")
        Reseau.future_on_event_loop!(
            f_write1,
            event_loop,
            (_f, ud) -> begin
                ud.t_on_loop[] = Reseau.event_loop_thread_is_callers_thread(event_loop)
                ud.cb_ran[] = true
                return nothing
            end,
            (t_on_loop = t_on_loop, cb_ran = cb_ran),
        )
        @test Reseau.future_wait(f_write1; timeout_ms = 2000)
        deadline = Base.time_ns() + 2_000_000_000
        while !cb_ran[] && Base.time_ns() < deadline
            yield()
        end
        @test cb_ran[]
        @test t_on_loop[]
        @test Reseau.future_get_result(f_write1) == 3

        f_write2 = write_async(file, "def")
        @test Reseau.future_wait(f_write2; timeout_ms = 2000)

        # Read back via async read into ByteBuffer.
        Files.open(path, "r") do io
            close(io)
        end
        f_open_r = open_async(event_loop, path; read = true)
        @test Reseau.future_wait(f_open_r; timeout_ms = 2000)
        file_r = Reseau.future_get_result(f_open_r)
        buf = Reseau.ByteBuffer(16)
        f_read = read_async(file_r, buf; nbytes = 6)
        @test Reseau.future_wait(f_read; timeout_ms = 2000)
        @test Reseau.future_get_result(f_read) == 6
        got = String(copy(collect(buf.mem[1:Int(buf.len)])))
        @test got == "abcdef"

        Files.rm(dir; recursive = true, force = true)
        Reseau.event_loop_group_destroy!(elg)
    end

    @testset "Watching Smoke" begin
        dir = Files.mktempdir()
        path = joinpath(dir, "watch.txt")
        Files.open(path, "w") do io
            write(io, "a")
        end

        fm = FileMonitor(path)
        t = @async wait(fm)
        Files.open(path, "w") do io
            write(io, "b")
        end
        @test _wait_task_done(t)
        ev = fetch(t)
        @test ev.changed || ev.renamed
        close(fm)

        folder = FolderMonitor(dir)
        t2 = @async wait(folder)
        Files.open(joinpath(dir, "newfile.txt"), "w") do io
            write(io, "x")
        end
        @test _wait_task_done(t2)
        p = fetch(t2)
        @test p.second.changed || p.second.renamed
        close(folder)

        tpf = @async poll_file(path, 0.05, 2.0)
        # Ensure the watcher has a chance to capture the initial stat.
        for _ in 1:50
            yield()
        end
        Files.open(path, "w") do io
            write(io, "c")
        end
        @test _wait_task_done(tpf)
        prev, cur = fetch(tpf)
        @test prev isa Files.StatStruct
        @test cur isa Files.StatStruct

        @static if !Sys.iswindows()
            pipe_res = Reseau.open_nonblocking_posix_pipe()
            @test !(pipe_res isa Reseau.ErrorResult)
            if !(pipe_res isa Reseau.ErrorResult)
                read_fd, write_fd = pipe_res
                try
                    t3 = @async poll_fd(Base.RawFD(read_fd), 2.0; readable = true)
                    payload = Vector{UInt8}(codeunits("x"))
                    GC.@preserve payload begin
                        _ = @ccall write(write_fd::Cint, pointer(payload)::Ptr{Cvoid}, Csize_t(1)::Csize_t)::Cssize_t
                    end
                    @test _wait_task_done(t3)
                    fev = fetch(t3)
                    @test fev.readable
                finally
                    @ccall close(read_fd::Cint)::Cint
                    @ccall close(write_fd::Cint)::Cint
                end
            end
        end

        Files.rm(dir; recursive = true, force = true)
    end
end
