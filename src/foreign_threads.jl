module ForeignThreads

# Reseau foreign thread/runtime utilities.
#
# Launches OS threads via pthread_create / CreateThread with automatic
# Julia runtime adoption (via @cfunction trampoline). All threads are
# detached at creation — synchronization is the caller's responsibility
# (use Events, atomic flags, etc. in your thread function body).
#
# For managed threads, call `managed_thread_finished!()` in your thread
# function's `finally` block and `join_all_managed()` at shutdown.

using EnumX

@enumx ThreadJoinStrategy::UInt8 begin
    MANUAL = 0
    MANAGED = 1
end

@static if Sys.iswindows()
    const thread_id_t = UInt32
else
    const thread_id_t = UInt64
end

const pthread_t = UInt  # pointer-sized: opaque ptr on macOS, unsigned long on Linux

@inline function _foreign_thread_report_error(thread_id::thread_id_t, exc::Any, bt)
    Core.println("[foreign-thread-err] id=", thread_id)
    io = stderr
    try
        Base.showerror(io, exc)
        Base.show_backtrace(io, bt)
    catch
        Core.println("[foreign-thread-err] failed to print full backtrace")
    end
    return nothing
end

mutable struct ThreadIdState
    @atomic next_id::UInt64
end

const _thread_id_state = ThreadIdState(UInt64(0))

@inline function _thread_next_id()
    return thread_id_t(@atomic _thread_id_state.next_id += 1)
end

mutable struct ForeignThread
    id::thread_id_t
    name::String
    managed::Bool
end

# ── Managed thread tracking ──────────────────────────────────────────

mutable struct ManagedThreadCount
    @atomic count::Int
end

const _managed_count = ManagedThreadCount(0)
const _managed_done = Base.Threads.Event()

function managed_thread_started!()
    @atomic _managed_count.count += 1
    return nothing
end

function managed_thread_finished!()
    val = @atomic _managed_count.count -= 1
    if val == 0
        notify(_managed_done)
    end
    return nothing
end

function join_all_managed()
    while (@atomic _managed_count.count) > 0
        wait(_managed_done)
        reset(_managed_done)
    end
    return nothing
end

# ── Thread creation ──────────────────────────────────────────────────

function ForeignThread(name::String, thread_fn::Ref{Ptr{Cvoid}};
        join_strategy::ThreadJoinStrategy.T = ThreadJoinStrategy.MANAGED)
    managed = join_strategy == ThreadJoinStrategy.MANAGED
    id = _thread_next_id()
    if managed
        managed_thread_started!()
    end
    try
        @static if Sys.iswindows()
            ret = ccall(
                (:CreateThread, "kernel32"), Ptr{Cvoid},
                (Ptr{Cvoid}, Csize_t, Ptr{Cvoid}, Ptr{Cvoid}, UInt32, Ptr{UInt32}),
                C_NULL, Csize_t(0), thread_fn[], Ptr{Cvoid}(UInt(id)), UInt32(0), C_NULL,
            )
            ret == C_NULL && throw(ArgumentError("error creating OS thread for ForeignThread"))
            # Close handle — thread keeps running, OS auto-cleans on exit
            ccall((:CloseHandle, "kernel32"), Int32, (Ptr{Cvoid},), ret)
        else
            pthread_ref = Ref{pthread_t}(0)
            ret = ccall(
                :pthread_create, Cint,
                (Ref{pthread_t}, Ptr{Cvoid}, Ptr{Cvoid}, Ptr{Cvoid}),
                pthread_ref, C_NULL, thread_fn[], Ptr{Cvoid}(id),
            )
            ret != 0 && throw(ArgumentError("error creating OS thread for ForeignThread"))
            ccall(:pthread_detach, Cint, (pthread_t,), pthread_ref[])
        end
        return ForeignThread(id, name, managed)
    catch
        if managed
            managed_thread_finished!()
        end
        rethrow()
    end
end

# ── @wrap_thread_fn macro ────────────────────────────────────────────

# Transform a zero-arg function definition into an OS thread entry point.
# The output function takes `(::Ptr{Cvoid})::Ptr{Cvoid}` and runs the
# body on the adopted foreign thread (@cfunction trampoline).
#
# Usage:
#   @wrap_thread_fn function my_worker()
#       try
#           # ... do work ...
#       finally
#           managed_thread_finished!()   # if managed
#       end
#   end
#   const MY_WORKER_C = Ref{Ptr{Cvoid}}(C_NULL)
#   # in __init__:
#   MY_WORKER_C[] = @cfunction(my_worker, Ptr{Cvoid}, (Ptr{Cvoid},))
#   ForeignThread("worker", MY_WORKER_C)
macro wrap_thread_fn(fndef)
    Meta.isexpr(fndef, :function) || error("@wrap_thread_fn requires a function definition")
    sig = fndef.args[1]
    body = fndef.args[2]
    Meta.isexpr(sig, :call) || error("@wrap_thread_fn: expected `function name() ... end`")
    name = sig.args[1]
    length(sig.args) == 1 || error("@wrap_thread_fn: function must take zero arguments")
    return quote
    function $(esc(name))(arg::Ptr{Cvoid})::Ptr{Cvoid}
        thread_id = UInt64(UInt(arg))
        try
            _ = thread_id
            $(esc(body))
        catch e
            bt = catch_backtrace()
            _foreign_thread_report_error(UInt64(thread_id), e, bt)
        end
        return C_NULL
    end
    end
end

# ── @wrap_task_fn macro ──────────────────────────────────────────────

# Transform a zero-arg function definition into a scheduled task callback.
# The output function takes `(status::UInt8)::Nothing` — if status is
# CANCELED (0x01), the body is skipped. Exceptions are caught to prevent
# them from crossing the C boundary when called via ccall.
#
# Usage:
#   @wrap_task_fn function on_connected()
#       # ... only runs for RUN_READY ...
#   end
#   const ON_CONNECTED_C = Ref{Ptr{Cvoid}}(C_NULL)
#   # in __init__:
#   ON_CONNECTED_C[] = @cfunction(on_connected, Cvoid, (UInt8,))
#   task = ScheduledTask(ON_CONNECTED_C[]; type_tag="on_connected")
#
# For manual status handling, skip the macro and define directly:
#   function my_task(status::UInt8)::Nothing
#       ...
#   end
macro wrap_task_fn(fndef)
    Meta.isexpr(fndef, :function) || error("@wrap_task_fn requires a function definition")
    sig = fndef.args[1]
    body = fndef.args[2]
    Meta.isexpr(sig, :call) || error("@wrap_task_fn: expected `function name() ... end`")
    name = sig.args[1]
    length(sig.args) == 1 || error("@wrap_task_fn: function must take zero arguments")
    return quote
        function $(esc(name))(status::UInt8)::Nothing
            status == 0x00 || return nothing  # only run for RUN_READY
            try
                $(esc(body))
            catch e
                Core.println("task ($($(string(name)))) errored")
            end
            return nothing
        end
    end
end

function __init__()
    return nothing
end

end # module ForeignThreads
