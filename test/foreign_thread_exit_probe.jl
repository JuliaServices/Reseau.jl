# Standalone runtime probe: no Reseau import or sockets.
const completed = Threads.Atomic{Int}(0)
function callback(arg::Ptr{Cvoid})::Cvoid
    if arg != C_NULL
        queue = unsafe_pointer_to_objref(arg)::Channel{Int}
        for item in queue
            item == 1 || error("unexpected item")
        end
    end
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
    queue = Channel{Int}(64)
    handles = [Ref{Ptr{Cvoid}}(C_NULL) for _ in 1:4]
    for handle in handles
        ret = ccall(:uv_thread_create, Cint,
            (Ref{Ptr{Cvoid}}, Ptr{Cvoid}, Ptr{Cvoid}), handle, entry, pointer_from_objref(queue))
        ret == 0 || error("uv_thread_create: $ret")
    end
    mark("iteration $iteration: close queue")
    put!(queue, 1)
    close(queue)
    mark("iteration $iteration: join")
    GC.@preserve queue for handle in handles
        ret = @ccall gc_safe=true uv_thread_join(handle::Ref{Ptr{Cvoid}})::Cint
        ret == 0 || error("uv_thread_join: $ret")
    end
    mark("iteration $iteration: completed=$(completed[]), GC start")
    GC.gc()
    mark("iteration $iteration: GC complete")
end
completed[] == 400 || error("missing callbacks")
