using Libdl
using InteractiveUtils

@assert VERSION == v"1.13.1"
@assert Sys.iswindows()
@assert Threads.nthreads() == 1
const SHOULD_THROW = ARGS[2] == "exception"
@assert ARGS[2] in ("exception", "no-exception")

function progress(message)
    println(message)
    flush(stdout)
end

@noinline function nested_throw(depth)
    depth == 0 && throw(ErrorException("native thread unwind control"))
    return nested_throw(depth - 1)
end

function native_callback(iterations::Csize_t)::Cint
    for _ in 1:iterations
        if SHOULD_THROW
            try
                nested_throw(8)
            catch err
                err isa ErrorException || return 1
            end
        end
    end
    return 0
end

versioninfo()
const CALLBACK = @cfunction(native_callback, Cint, (Csize_t,))
@assert ccall(CALLBACK, Cint, (Csize_t,), 1) == 0
const LIBRARY = Libdl.dlopen(ARGS[1])
const START = Libdl.dlsym(LIBRARY, :start_workers)
const EXITED = Libdl.dlsym(LIBRARY, :workers_exited)
const FINISH = Libdl.dlsym(LIBRARY, :finish_workers)

progress("[runtime] mode=$(ARGS[2]) word_size=$(Sys.WORD_SIZE) threads=4 rounds=64 START")
for round in 1:64
    progress("[runtime] round=$round START")
    @assert ccall(START, UInt32, (Ptr{Cvoid},), CALLBACK) == 0
    while true
        status = ccall(EXITED, UInt32, ())
        status == 0 && break
        @assert status == 0x102 # WAIT_TIMEOUT: the owned native threads have not exited yet.
        sleep(0.001)
    end
    @assert ccall(FINISH, Cint, ()) == 1
    progress("[runtime] round=$round DONE callbacks=4 threads_exited=4")
end
progress("[runtime] COMPLETE callbacks=256 threads_exited=256")
