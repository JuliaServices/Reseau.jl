
        const entered = Threads.Atomic{Int}(0)
        const completed = Threads.Atomic{Int}(0)
        function callback(arg::Ptr{Cvoid})::Cvoid
            queue = unsafe_pointer_to_objref(arg)::Channel{Int}
            Threads.atomic_add!(entered, 1)
            for _ in queue
            end
            Threads.atomic_add!(completed, 1)
            return nothing
        end
        const entry = @cfunction(callback, Cvoid, (Ptr{Cvoid},))
        function run_close_probe()
            for iteration in 1:100
                queue = Channel{Int}(64)
                handles = [Ref{UInt}(0) for _ in 1:4]
                GC.@preserve queue begin
                    for handle in handles
                        arg = pointer_from_objref(queue)
                        ret = @ccall uv_thread_create(handle::Ref{UInt}, entry::Ptr{Cvoid}, arg::Ptr{Cvoid})::Cint
                        ret == 0 || Base.uv_error("uv_thread_create", ret)
                    end
                    while entered[] < 4 * iteration
                        yield()
                    end
                    close(queue)
                    for handle in handles
                        ret = @ccall gc_safe=true uv_thread_join(handle::Ref{UInt})::Cint
                        ret == 0 || Base.uv_error("uv_thread_join", ret)
                    end
                end
                GC.gc()
            end
            @assert completed[] == 400
        end
        run_close_probe()
        