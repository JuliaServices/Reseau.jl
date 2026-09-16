# Standalone runtime probe: no Reseau import, sockets, channels, or locks.
const completed = Threads.Atomic{Int}(0)
function callback(::Ptr{Cvoid})::Cvoid
    Threads.atomic_add!(completed, 1)
    return nothing
end
const entry = @cfunction(callback, Cvoid, (Ptr{Cvoid},))
function mark(message)
    println(message)
    flush(stdout)
end
for iteration in 1:100
    mark("iteration $iteration: create")
    handles = [Ref{Ptr{Cvoid}}(C_NULL) for _ in 1:4]
    for handle in handles
        ret = ccall(:uv_thread_create, Cint,
            (Ref{Ptr{Cvoid}}, Ptr{Cvoid}, Ptr{Cvoid}), handle, entry, C_NULL)
        ret == 0 || error("uv_thread_create: $ret")
    end
    mark("iteration $iteration: join")
    for handle in handles
        ret = @ccall gc_safe=true uv_thread_join(handle::Ref{Ptr{Cvoid}})::Cint
        ret == 0 || error("uv_thread_join: $ret")
    end
    mark("iteration $iteration: completed=$(completed[]), GC start")
    GC.gc()
    mark("iteration $iteration: GC complete")
end
completed[] == 400 || error("missing callbacks")
