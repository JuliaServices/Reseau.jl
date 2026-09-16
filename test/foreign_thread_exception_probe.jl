# Diagnostic only: isolate the profile/stack-walk lock order during exceptions.
const completed = Threads.Atomic{Int}(0)
const profile_guard = get(ENV, "PROBE_PROFILE_GUARD", "false") == "true"
const failure = ErrorException("foreign thread backtrace probe")
function callback(::Ptr{Cvoid})::Cvoid
    profile_guard && ccall(:jl_lock_profile, Cvoid, ())
    try
        throw(failure)
    catch
    finally
        profile_guard && ccall(:jl_unlock_profile, Cvoid, ())
    end
    Threads.atomic_add!(completed, 1)
    return nothing
end
const entry = @cfunction(callback, Cvoid, (Ptr{Cvoid},))
function run_probe()
    callback(C_NULL)
    completed[] = 0
    for iteration in 1:100
        println("iteration $iteration: create, profile guard=$profile_guard")
        flush(stdout)
        handles = [Ref{UInt}(0) for _ in 1:4]
        for handle in handles
            ret = @ccall uv_thread_create(handle::Ref{UInt}, entry::Ptr{Cvoid}, C_NULL::Ptr{Cvoid})::Cint
            ret == 0 || error("uv_thread_create: $ret")
        end
        for handle in handles
            ret = @ccall gc_safe=true uv_thread_join(handle::Ref{UInt})::Cint
            ret == 0 || error("uv_thread_join: $ret")
        end
        GC.gc()
        println("iteration $iteration: completed=$(completed[])")
        flush(stdout)
    end
    @assert completed[] == 400
end
run_probe()
